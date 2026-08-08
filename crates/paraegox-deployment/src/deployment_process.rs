//! Exact one-shot process facade for the reference DeploymentController vertical.
//!
//! The facade deliberately exposes no daemon loop, retry policy, reset path, or
//! caller-constructed Planner candidate. `initialize-reference-v1` consumes the
//! exact installer manifest once; normal Controller operations subsequently use
//! only the immutable manifest pin recovered from the Controller journal.

use core::fmt;

/// Opaque, non-sensitive failure returned by `paraegox-deploymentd`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeploymentdProcessError {
    kind: ProcessErrorKind,
}

impl DeploymentdProcessError {
    const fn new(kind: ProcessErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Debug for DeploymentdProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentdProcessError")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for DeploymentdProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (code, stage) = match self.kind {
            #[cfg(not(unix))]
            ProcessErrorKind::UnsupportedPlatform => ("PXDC-PLATFORM-UNSUPPORTED", "start_process"),
            ProcessErrorKind::Arguments => ("PXDC-ARGUMENTS-INVALID", "parse_arguments"),
            ProcessErrorKind::ServiceIdentity => {
                ("PXDC-SERVICE-IDENTITY-REJECTED", "validate_identity")
            }
            ProcessErrorKind::Path => ("PXDC-PATH-REJECTED", "validate_path"),
            ProcessErrorKind::Manifest => ("PXDC-MANIFEST-REJECTED", "load_manifest"),
            ProcessErrorKind::Key => ("PXDC-KEY-REJECTED", "load_request_auth_key"),
            ProcessErrorKind::Provisioning => {
                ("PXDC-PROVISIONING-REJECTED", "build_controller_identity")
            }
            ProcessErrorKind::Initialization => {
                ("PXDC-INITIALIZATION-FAILED", "initialize_controller")
            }
            ProcessErrorKind::Store => ("PXDC-STORE-FAILED-CLOSED", "operate_controller_store"),
            ProcessErrorKind::Migration => {
                ("PXDC-MIGRATION-FAILED-CLOSED", "migrate_controller_store")
            }
            ProcessErrorKind::Planning => ("PXDC-PLANNING-REJECTED", "compile_reference_plan"),
            ProcessErrorKind::Commit => ("PXDC-COMMIT-FAILED-CLOSED", "commit_reference_plan"),
            ProcessErrorKind::Tenure => ("PXDC-TENURE-FAILED-CLOSED", "acquire_tenure"),
            ProcessErrorKind::Bootstrap => ("PXDC-BOOTSTRAP-FAILED-CLOSED", "bootstrap_runtime"),
            ProcessErrorKind::ServingObservation => (
                "PXDC-SERVING-OBSERVATION-FAILED-CLOSED",
                "observe_managed_serving",
            ),
            ProcessErrorKind::AgentStack => (
                "PXDC-AGENT-STACK-FAILED-CLOSED",
                "operate_managed_agent_stack",
            ),
            ProcessErrorKind::NodeDiscovery => (
                "PXDC-NODE-DISCOVERY-FAILED-CLOSED",
                "observe_distributed_nodes_once",
            ),
            ProcessErrorKind::DistributedApply => (
                "PXDC-DISTRIBUTED-APPLY-FAILED-CLOSED",
                "apply_distributed_agent_stack_once",
            ),
            ProcessErrorKind::Apply => ("PXDC-APPLY-FAILED-CLOSED", "apply_reference"),
            ProcessErrorKind::Reconcile => {
                ("PXDC-RECONCILE-FAILED-CLOSED", "reconcile_reference_once")
            }
            ProcessErrorKind::Output => ("PXDC-OUTPUT-FAILED", "write_receipt"),
        };
        write!(
            formatter,
            "paraegox-deploymentd failed closed; code={code} stage={stage}"
        )
    }
}

impl std::error::Error for DeploymentdProcessError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessErrorKind {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    Arguments,
    ServiceIdentity,
    Path,
    Manifest,
    Key,
    Provisioning,
    Initialization,
    Store,
    Migration,
    Planning,
    Commit,
    Tenure,
    Bootstrap,
    ServingObservation,
    AgentStack,
    NodeDiscovery,
    DistributedApply,
    Apply,
    Reconcile,
    Output,
}

/// Parses and executes exactly one versioned DeploymentController operation.
pub fn run_deploymentd_process() -> Result<(), DeploymentdProcessError> {
    platform::run()
}

#[cfg(unix)]
pub use platform::{
    DeveloperDeploymentEnrollmentFactsFieldsV1, DeveloperDeploymentEnrollmentFactsV1,
    DeveloperDeploymentErrorV1,
    DeveloperDeploymentOwnerV1, DeveloperDeploymentStartFieldsV1,
    DeveloperDeploymentStartInputV1, DeveloperDeploymentStartModeV1,
    DeveloperDeploymentReadyV1, DeveloperDeploymentStartOutcomeV1,
    start_developer_deployment_v1,
};

#[cfg(unix)]
pub(crate) use platform::{
    DistributedAgentStackOwnerApplyErrorV1, DistributedAgentStackOwnerApplyOutcomeV1,
    DistributedAgentStackOwnerConnectorInputV1, DistributedAgentStackOwnerNodeInputFieldsV1,
    DistributedAgentStackOwnerNodeInputV1, DistributedAgentStackOwnerTargetInputV1,
    DistributedCoordinatorContextV1, run_developer_local_distributed_agent_stack_owner_v1,
    verify_distributed_coordinator_context_v1,
};

#[cfg(not(unix))]
mod platform {
    use super::{DeploymentdProcessError, ProcessErrorKind};

    pub(super) fn run() -> Result<(), DeploymentdProcessError> {
        Err(DeploymentdProcessError::new(
            ProcessErrorKind::UnsupportedPlatform,
        ))
    }
}

#[cfg(unix)]
mod platform {
    use core::fmt;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, Metadata};
    use std::io::{Read, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};
    use std::time::{Duration, Instant as MonotonicInstant, SystemTime, UNIX_EPOCH};

    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    use nix::unistd::{getegid, geteuid};
    use paraegox_fabric::{
        ResolvedRemoteMtlsIdentityFiles, RestrictedNodeControlClientConfigV1,
        RestrictedNodeControlClientV1, RestrictedRuntimeControlClientConfigV1,
        RestrictedRuntimeControlClientV1,
    };
    use paraegox_kernel::digest::{Digest32, Digest32Builder};
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::apply::{
        ApplyOperationId, PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
        TenureProofAuthority,
    };
    use paraegox_runtime_contracts::assignment::BindingId;
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        DistributedAgentStackTerminalOutcomeV1, DistributedFabricTopologyV1,
        MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES,
        MAX_RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_BYTES,
        RestrictedRuntimeApplyCarrierBindingFieldsV1, RestrictedRuntimeApplyCarrierBindingV1,
        RestrictedRuntimeApplyTransportProfileV1,
    };
    use paraegox_runtime_contracts::installation::{
        MAX_INSTALLED_RUNTIME_MANIFEST_BYTES, VerifiedRuntimeManifestIngressV1,
    };
    use paraegox_runtime_contracts::provenance::SourceScopeRef;
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentIngressLimitsV1, ManagedAgentPortPlanV1, ManagedAgentProviderRefV1,
        ManagedAgentProviderSelectionV1, ManagedAgentSecretRefV1, ManagedAgentSemanticLimitsV1,
        ManagedAgentServicePlanV1, ManagedAgentStackTargetModeV1,
    };
    use paraegox_runtime_contracts::managed_service::{
        ManagedServiceId, ManagedServiceLifecycleBudgetsV1, ManagedServiceSpecV1,
    };
    use paraegox_runtime_contracts::reference_control::{
        MAX_REFERENCE_QUERY_RESPONSE_BYTES, ReferenceAdmissionPolicyInputV1,
        ReferenceApplyTerminalHeadV1, ReferenceApplyTerminalLifecycleEffectV1,
        ReferenceApplyTerminalOutcomeV1, ReferenceBootstrapChannelPolicyInputV1,
        ReferenceBootstrapResponseV1, ReferenceBootstrapServingIdentityV1, ReferenceQueryIdV1,
        ReferenceQueryRequestDraftV1, ReferenceQueryRequestV1, ReferenceQueryResponseV1,
        ReferenceQuerySelectorV1,
        ValidatedReferenceLifecycleBudgetsV1,
        ed25519_control_key_fingerprint, reference_admission_policy_fingerprint_v1,
        reference_bootstrap_channel_policy_fingerprint_v1,
    };
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
    };
    use tokio::runtime::Builder as RuntimeBuilder;
    use zeroize::Zeroizing;

    use crate::controller_apply::{
        ControllerAppliedReferenceV1, ControllerApplyProvisioningV1, FreshControllerApplyRequestV1,
        PreparedControllerApplyAttemptV1, apply_reference_once_v1, prepare_reference_apply_v1,
        replay_prepared_reference_apply_v1,
    };
    use crate::controller_bootstrap::{
        ControllerBootstrapProvisioningV1, ControllerBootstrapReceiptV1,
        FreshControllerBootstrapRequestV1, bootstrap_runtime_v1,
    };
    use crate::controller_initializer::{
        ControllerInitializationInput, ControllerInitializationReceipt,
        initialize_controller_store, initialize_controller_store_developer_local,
    };
    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerJournalError, ControllerJournalSnapshot,
        ControllerOperationId, ControllerOwnerIdentityFingerprint,
        ControllerRemoteConnectorAttemptPhaseV1, ControllerRemoteConnectorRestartRequirementV1,
        ControllerRemoteConnectorStepV1, ControllerRequestAuthPin,
        ControllerTenureAuthorityDomainFingerprint, ControllerTenureTransaction,
    };
    use crate::controller_query::ControllerQueryProvisioningV1;
    use crate::controller_reconcile::{ControllerReconcileOutcomeV1, reconcile_reference_once_v1};
    use crate::controller_store::ControllerStoreOpenError;
    use crate::controller_store::{
        ClaimedControllerRemoteConnectorAttemptV1, ControllerDistributedAgentStackOwnerStateV1,
        ControllerStore,
        ControllerStoreMigrationDisposition, DistributedRuntimeObservationCommitDispositionV1,
    };
    use crate::controller_tenure::{ControllerAcquiredTenure, acquire_tenure_once};
    use crate::deck::{
        CardDefinitionVersionRequirement, CardUseKey, DeckCardConfig, DeckCardRole, DeckCardSpec,
        DeckCompiler, DeckExportRef, DeckKey, DeckLifetimeRequest, DeckOwnershipRequest,
        DeckResolverSnapshot, DeckSpec, ResolvedCardArtifact, ResolvedCardDefinition,
    };
    use crate::distributed_agent_stack_apply::DistributedAgentStackApplyJournalV1;
    use crate::distributed_agent_stack_node_reconcile::{
        DistributedAgentStackNodeDiscoveryStateV1, DistributedAgentStackNodeTargetV1,
        DistributedAgentStackRuntimeQueryInputV1, DistributedAgentStackRuntimeQueryPhaseV1,
        FreshRemoteNodeControlRequestV1, NodeObservationProcessGenerationV1,
        ReadyDistributedAgentStackRuntimeEndpointV1, RemoteNodeControlAdapterV1,
        RemoteNodeControlTransportErrorV1, RemoteNodeControlTransportPinV1,
        RemoteNodeMtlsExchangeSuccessV1, TransportAuthenticatedNodeResponseV1,
        TrustedLocalNodeClientErrorV1, TrustedLocalNodeEndpointV1,
        TrustedLocalRuntimeObservationEndpointV1,
    };
    use crate::distributed_agent_stack_producer::{
        DistributedAgentStackRolloutIdV1, DistributedAgentStackTargetRolloutInputV1,
        FreshDistributedAgentStackApplyV1, VerifiedDistributedAgentStackPredecessorV1,
        produce_distributed_agent_stack_rollout_v1, validate_predecessor_pair,
    };
    use crate::distributed_agent_stack_store::{
        DistributedAgentStackRolloutStatusV1, DistributedAgentStackStoreError,
    };
    use crate::managed_agent_stack_apply::{
        ManagedAgentStackApplyJournalV1, ManagedAgentStackTerminalCommitV1,
    };
    use crate::managed_agent_stack_producer::{
        FreshManagedAgentStackApplyV1, ManagedAgentStackActivationV1,
    };
    use crate::managed_fabric_apply::{
        ManagedFabricApplyControllerError, ManagedFabricApplyJournalV1,
    };
    use crate::managed_fabric_producer::{
        ManagedFabricControllerIdentityV1, ManagedFabricControllerProvisioningV1,
        ManagedFabricRemoteControllerProvisioningV1, ManagedFabricRuntimeChannelPinV1,
        ManagedFabricServiceAccountsV1, ManagedFabricTenureAuthorityPinV1,
        VerifiedManagedFabricProducerContextV1,
    };
    use crate::managed_fabric_store::{
        ManagedAgentStackDurableStoreV1, ManagedFabricSuccessorStoreV1,
    };
    use crate::managed_serving_client::{
        FreshManagedServingBootstrapV1, ManagedServingBootstrapPhaseV1,
        ManagedServingDescribeIngressV1, ManagedServingDescribeReconcilePhaseV1,
        ManagedServingDescribeVerifierV1,
        RuntimeManagedServingDescribeMtlsExchangeSuccessV1,
        RuntimeManagedServingDescribeTransportErrorV1,
        RuntimeManagedServingMtlsExchangeSuccessV1, RuntimeManagedServingTransportErrorV1,
        VerifiedManagedServingPinV1,
    };
    use crate::manifest_ingress::ControllerInstalledManifestPin;
    use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
    use crate::planner::{
        AllocationState, DeploymentPlanCandidate, DeploymentPlanner, PlannerDesired, PlannerInput,
        PlannerOutcome, PreviousTargetEligibility, StableAllocationSnapshot, TargetIntent,
        ValidatedReferenceLifecycleBudgets,
    };
    use crate::runtime_control_client::{
        RuntimeApplyResponseVerifier, RuntimeControlSocketAcl,
        RuntimeManagedAgentStackResponseVerifier, RuntimeManagedServingResponseVerifier,
        PreparedRuntimeQueryRequest, RuntimeQueryExchangeError, RuntimeQueryResponseVerifier,
        RuntimeUnixCredentials, UnixRuntimeApplyClient, UnixRuntimeControlEndpoint,
        UnixRuntimeManagedAgentStackClient, UnixRuntimeManagedServingClient,
        UnixRuntimeQueryClient,
    };
    use crate::tenure_client::{
        AcquireTenureRequestToSign, AuthorityProofVerifier, AuthoritySocketAcl,
        PreparedAcquireTenureRequest, UnixAuthorityEndpoint, UnixCredentials,
        UnixTenureAuthorityClient,
    };
    use crate::tenure_protocol::{
        ACQUIRE_TENURE_ED25519_ALGORITHM, ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };
    use paraegox_node::observation::{
        MAX_RUNTIME_OBSERVATION_CHALLENGE_NANOS, RuntimeObservationAuthorityV1,
        RuntimeObservationEndpointRefV1, RuntimeObservationRequestInputV1,
        RuntimeObservationRequestV1, derive_runtime_observation_query_nonce_v1,
    };
    use paraegox_node::protocol::{
        NodeControlObservationChallengeFieldsV1, NodeControlObservationChallengeV1,
        NodeManagementRequestV1, NodeManagementTargetV1,
    };
    use paraegox_node::{
        MAX_NODE_STATUS_FRESHNESS_NANOS, NodeId, NodeIncarnation,
        NodeManagementEndpointRefV1, RuntimeApplyEndpointDescriptorV1,
        RuntimeApplyEndpointRefV1,
    };

    use crate::developer_local_tenure_authority::{
        DeveloperLocalTenureAuthorityConfigV1, DeveloperLocalTenureAuthorityV1,
    };

    use super::{DeploymentdProcessError, ProcessErrorKind};

    const ED25519_ALGORITHM: u16 = 1;
    const ED25519_ALGORITHM_VERSION: u16 = 1;
    const INITIAL_AUTH_ROTATION_GENERATION: u64 = 1;
    const CONTROLLER_OWNER_IDENTITY_DOMAIN: &[u8] =
        b"paraegox.deployment.controller.process-owner.sha256.v1";
    const COMMIT_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
        b"paraegox.deployment.controller.commit-snapshot.sha256.v1";
    const COMMIT_RECEIPT_DIGEST_DOMAIN: &[u8] =
        b"paraegox.deployment.controller.commit-receipt.sha256.v1";
    const COMMIT_RECEIPT_MAGIC: &[u8] = b"PXDCOMMIT\0";
    const COMMIT_RECEIPT_VERSION: u16 = 1;
    const EMPTY_COMMIT_RECEIPT_DIGEST_DOMAIN: &[u8] =
        b"paraegox.deployment.controller.commit-empty-receipt.sha256.v1";
    const EMPTY_COMMIT_RECEIPT_MAGIC: &[u8] = b"PXDCEMPTY\0";
    const EMPTY_COMMIT_RECEIPT_VERSION: u16 = 1;
    const MAX_ARGUMENTS: usize = 49;
    const PUBLIC_KEY_BYTES: usize = 32;
    const BOOTSTRAP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const BOOTSTRAP_ENTROPY_BYTES: usize = 48;
    const TENURE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const TENURE_ENTROPY_BYTES: usize = 48;
    const APPLY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const APPLY_ENTROPY_BYTES: usize = 64;
    const QUERY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const MANAGED_SERVING_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const MANAGED_SERVING_ENTROPY_BYTES: usize = 48;
    const MANAGED_AGENT_STACK_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const MANAGED_AGENT_STACK_ENTROPY_BYTES: usize = 64;
    const DISTRIBUTED_NODE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const DISTRIBUTED_ROLLOUT_ENTROPY_BYTES: usize = 144;
    const DISTRIBUTED_OBSERVATION_ENTROPY_BYTES: usize = 48;
    const DISTRIBUTED_RUNTIME_QUERY_ENTROPY_BYTES: usize = 32;
    const DISTRIBUTED_CAPABILITY_MAGIC: &[u8; 4] = b"PXNC";
    const DISTRIBUTED_CAPABILITY_VERSION_V1: u16 = 1;
    const DISTRIBUTED_CAPABILITY_VERSION_V2: u16 = 2;
    const DISTRIBUTED_CAPABILITY_HEADER_BYTES: usize = 32;
    const DISTRIBUTED_CAPABILITY_CHECKSUM_BYTES: usize = 32;
    const MAX_DISTRIBUTED_CAPABILITY_BYTES: usize = 256 * 1024;
    const MAX_DISTRIBUTED_CAPABILITY_PATH_BYTES: usize = 1024;
    const DISTRIBUTED_CAPABILITY_CHECKSUM_DOMAIN: &[u8] =
        b"paraegox.deployment.distributed-local-node-capability.sha256.v1";
    const DISTRIBUTED_CARRIER_BINDING_DOMAIN: &[u8] =
        b"paraegox.deployment.distributed-local-node-carrier.sha256.v1";
    const DISTRIBUTED_OWNER_ANCHOR_DOMAIN: &[u8] =
        b"paraegox.deployment.distributed-agent-stack.owner-anchor.sha256.v1";
    const DEVELOPER_DEPLOYMENT_PLAN_DOMAIN: &[u8] =
        b"paraegox.deployment.developer-enrollment.plan.sha256.v1";
    const DEVELOPER_DEPLOYMENT_MANAGED_READY_DOMAIN: &[u8] =
        b"paraegox.deployment.developer-managed-ready.sha256.v1";

    /// Typed projection of one already SHA-pinned, decoded, signature-verified
    /// and cross-pinned PXEA. Deployment never receives the PXEA file bytes.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct DeveloperDeploymentEnrollmentFactsV1 {
        configuration_digest: Digest32,
        verified_manifest: VerifiedRuntimeManifestIngressV1,
        runtime_transport_profile_ref: [u8; 16],
        runtime_transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        runtime_carrier: RestrictedRuntimeApplyCarrierBindingV1,
        runtime_response_public_key: [u8; 32],
        expected_node_target: NodeManagementTargetV1,
        expected_node_principal: PrincipalRef,
        node_route: Box<str>,
        node_route_config_digest: Digest32,
        observation_endpoint_ref: RuntimeObservationEndpointRefV1,
        source_scope: SourceScopeRef,
        writer: PlanWriterRef,
        authority_principal: PrincipalRef,
        authority_ref: TenureAuthorityRef,
        authority_key_ref: TenureKeyRef,
        authority_verification_key: [u8; 32],
    }

    /// Named public facts copied only from a verified PXEA token. This bundle
    /// keeps field provenance reviewable without a positional constructor.
    pub struct DeveloperDeploymentEnrollmentFactsFieldsV1 {
        pub configuration_digest: Digest32,
        pub verified_manifest: VerifiedRuntimeManifestIngressV1,
        pub runtime_transport_profile_ref: [u8; 16],
        pub runtime_transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        pub runtime_carrier: RestrictedRuntimeApplyCarrierBindingV1,
        pub runtime_response_public_key: [u8; 32],
        pub expected_node_target: NodeManagementTargetV1,
        pub expected_node_principal: PrincipalRef,
        pub node_route: String,
        pub node_route_config_digest: Digest32,
        pub observation_endpoint_ref: RuntimeObservationEndpointRefV1,
        pub source_scope: SourceScopeRef,
        pub writer: PlanWriterRef,
        pub authority_principal: PrincipalRef,
        pub authority_ref: TenureAuthorityRef,
        pub authority_key_ref: TenureKeyRef,
        pub authority_verification_key: [u8; 32],
    }

    impl DeveloperDeploymentEnrollmentFactsV1 {
        pub fn try_new(
            fields: DeveloperDeploymentEnrollmentFactsFieldsV1,
        ) -> Result<Self, DeveloperDeploymentErrorV1> {
            let DeveloperDeploymentEnrollmentFactsFieldsV1 {
                configuration_digest,
                verified_manifest,
                runtime_transport_profile_ref,
                runtime_transport_profile,
                runtime_carrier,
                runtime_response_public_key,
                expected_node_target,
                expected_node_principal,
                node_route,
                node_route_config_digest,
                observation_endpoint_ref,
                source_scope,
                writer,
                authority_principal,
                authority_ref,
                authority_key_ref,
                authority_verification_key,
            } = fields;
            let runtime_response_key = VerifyingKey::from_bytes(&runtime_response_public_key)
                .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
            let authority_key = VerifyingKey::from_bytes(&authority_verification_key)
                .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
            if configuration_digest.as_bytes().iter().all(|byte| *byte == 0)
                || runtime_transport_profile_ref.iter().all(|byte| *byte == 0)
                || verified_manifest.target() != runtime_transport_profile.target()
                || verified_manifest.target() != runtime_carrier.target()
                || runtime_transport_profile
                    .validate_carrier_binding(runtime_transport_profile_ref, &runtime_carrier)
                    .is_err()
                || expected_node_principal.as_bytes().iter().all(|byte| *byte == 0)
                || node_route.is_empty()
                || node_route_config_digest
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == 0)
                || source_scope.as_bytes().iter().all(|byte| *byte == 0)
                || writer.as_bytes().iter().all(|byte| *byte == 0)
                || authority_principal.as_bytes().iter().all(|byte| *byte == 0)
                || authority_ref.as_bytes().iter().all(|byte| *byte == 0)
                || authority_key_ref.as_bytes().iter().all(|byte| *byte == 0)
                || runtime_response_key.is_weak()
                || authority_key.is_weak()
            {
                return Err(DeveloperDeploymentErrorV1::InvalidEnrollmentFacts);
            }
            Ok(Self {
                configuration_digest,
                verified_manifest,
                runtime_transport_profile_ref,
                runtime_transport_profile,
                runtime_carrier,
                runtime_response_public_key,
                expected_node_target,
                expected_node_principal,
                node_route: node_route.into_boxed_str(),
                node_route_config_digest,
                observation_endpoint_ref,
                source_scope,
                writer,
                authority_principal,
                authority_ref,
                authority_key_ref,
                authority_verification_key,
            })
        }
    }

    /// Complete secret-bearing start request. Seeds remain zeroizing until
    /// their respective Controller and Authority signing owners consume them.
    pub struct DeveloperDeploymentStartInputV1 {
        mode: DeveloperDeploymentStartModeV1,
        controller_store_directory: PathBuf,
        successor_store_directory: PathBuf,
        enrollment: DeveloperDeploymentEnrollmentFactsV1,
        controller_seed: Zeroizing<[u8; 32]>,
        authority: DeveloperLocalTenureAuthorityConfigV1,
        runtime_client: RestrictedRuntimeControlClientConfigV1,
        node_client: RestrictedNodeControlClientConfigV1,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum DeveloperDeploymentStartModeV1 {
        Fresh,
        Resume,
    }

    pub struct DeveloperDeploymentStartFieldsV1 {
        pub mode: DeveloperDeploymentStartModeV1,
        pub controller_store_directory: PathBuf,
        pub successor_store_directory: PathBuf,
        pub enrollment: DeveloperDeploymentEnrollmentFactsV1,
        pub controller_seed: Zeroizing<[u8; 32]>,
        pub authority: DeveloperLocalTenureAuthorityConfigV1,
        pub runtime_client: RestrictedRuntimeControlClientConfigV1,
        pub node_client: RestrictedNodeControlClientConfigV1,
    }

    impl fmt::Debug for DeveloperDeploymentStartInputV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DeveloperDeploymentStartInputV1")
                .field("mode", &self.mode)
                .field("controller_store_directory", &self.controller_store_directory)
                .field("successor_store_directory", &self.successor_store_directory)
                .field("enrollment", &self.enrollment)
                .field("controller_seed", &"<redacted>")
                .field("authority", &"<redacted>")
                .field("runtime_client", &"<redacted>")
                .field("node_client", &"<redacted>")
                .finish()
        }
    }

    impl DeveloperDeploymentStartInputV1 {
        pub fn try_new(
            fields: DeveloperDeploymentStartFieldsV1,
        ) -> Result<Self, DeveloperDeploymentErrorV1> {
            let DeveloperDeploymentStartFieldsV1 {
                mode,
                controller_store_directory,
                successor_store_directory,
                enrollment,
                controller_seed,
                authority,
                runtime_client,
                node_client,
            } = fields;
            let controller_key = SigningKey::from_bytes(&controller_seed)
                .verifying_key()
                .to_bytes();
            let controller_fingerprint = ed25519_control_key_fingerprint(&controller_key)
                .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
            if !controller_store_directory.is_absolute()
                || !successor_store_directory.is_absolute()
                || controller_store_directory == successor_store_directory
                || controller_seed.iter().all(|byte| *byte == 0)
                || controller_fingerprint
                    != enrollment
                        .runtime_carrier
                        .controller_request_key_fingerprint()
                || runtime_client.route() != enrollment.runtime_transport_profile.route()
                || !node_client.matches_transport_pins(
                    &enrollment.node_route,
                    enrollment.expected_node_principal,
                    enrollment.node_route_config_digest,
                )
            {
                return Err(DeveloperDeploymentErrorV1::InvalidConfiguration);
            }
            Ok(Self {
                mode,
                controller_store_directory,
                successor_store_directory,
                enrollment,
                controller_seed,
                authority,
                runtime_client,
                node_client,
            })
        }
    }

    /// The real owner graph after PXFS and terminal PXFR are durable. It is
    /// deliberately not reported Ready until a later durable ManagedReady
    /// Describe reconciliation seam exists.
    pub struct DeveloperDeploymentOwnerV1 {
        authority: Option<DeveloperLocalTenureAuthorityV1>,
        node_client: Option<RestrictedNodeControlClientV1>,
        runtime_client: Option<RestrictedRuntimeControlClientV1>,
        successor_store: Option<ManagedFabricSuccessorStoreV1>,
    }

    impl fmt::Debug for DeveloperDeploymentOwnerV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DeveloperDeploymentOwnerV1")
                .field("authority_running", &self.authority.is_some())
                .field("node_connector_running", &self.node_client.is_some())
                .field("runtime_connector_running", &self.runtime_client.is_some())
                .field("pxfs_owned", &self.successor_store.is_some())
                .finish()
        }
    }

    impl DeveloperDeploymentOwnerV1 {
        /// Bounded supervision poll. It never waits for a connector or joins a
        /// live thread; `true` means the Authority owner has already exited.
        pub fn try_poll_exit(&mut self) -> Result<bool, DeveloperDeploymentErrorV1> {
            self.authority.as_mut().map_or(Ok(true), |authority| {
                authority
                    .try_poll_exit()
                    .map_err(|_| DeveloperDeploymentErrorV1::AuthorityFailed)
            })
        }

        /// Waits for owner death for no longer than the caller's explicit
        /// bound. `false` is a clean timeout, not an owner failure.
        pub async fn wait_for_exit(
            &mut self,
            max_wait: Duration,
        ) -> Result<bool, DeveloperDeploymentErrorV1> {
            if max_wait.is_zero() || max_wait > Duration::from_secs(60) {
                return Err(DeveloperDeploymentErrorV1::InvalidConfiguration);
            }
            let deadline = tokio::time::Instant::now()
                .checked_add(max_wait)
                .ok_or(DeveloperDeploymentErrorV1::InvalidConfiguration)?;
            loop {
                if self.try_poll_exit()? {
                    return Ok(true);
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Ok(false);
                }
                tokio::time::sleep(
                    Duration::from_millis(20).min(deadline.saturating_duration_since(now)),
                )
                .await;
            }
        }

        /// Shuts both connector sessions and always joins the Authority owner.
        pub async fn shutdown_and_join(mut self) -> Result<(), DeveloperDeploymentErrorV1> {
            let mut failed = false;
            if let Some(client) = self.node_client.take() {
                failed |= client.shutdown().await.is_err();
            }
            if let Some(client) = self.runtime_client.take() {
                failed |= client.shutdown().await.is_err();
            }
            self.successor_store.take();
            if let Some(authority) = self.authority.take() {
                failed |= authority.shutdown().is_err();
            }
            if failed {
                Err(DeveloperDeploymentErrorV1::JoinedShutdownFailed)
            } else {
                Ok(())
            }
        }
    }

    /// Non-secret, post-persistence proof that the fresh successor Describe
    /// reached ManagedReady. Construction remains inside the owner facade.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct DeveloperDeploymentReadyV1 {
        target: paraegox_kernel::identity::RuntimeHostId,
        runtime_store_instance_id: [u8; 32],
        snapshot_sequence: u64,
        runtime_host_epoch: u64,
        managed_ready_digest: Digest32,
    }

    impl DeveloperDeploymentReadyV1 {
        #[must_use]
        pub const fn target(&self) -> paraegox_kernel::identity::RuntimeHostId {
            self.target
        }

        #[must_use]
        pub const fn runtime_store_instance_id(&self) -> [u8; 32] {
            self.runtime_store_instance_id
        }

        #[must_use]
        pub const fn snapshot_sequence(&self) -> u64 {
            self.snapshot_sequence
        }

        #[must_use]
        pub const fn runtime_host_epoch(&self) -> u64 {
            self.runtime_host_epoch
        }

        #[must_use]
        pub const fn managed_ready_digest(&self) -> Digest32 {
            self.managed_ready_digest
        }
    }

    /// Only `Ready` may authorize Local to publish a readiness marker.
    #[derive(Debug)]
    #[must_use]
    pub enum DeveloperDeploymentStartOutcomeV1 {
        Ready {
            owner: DeveloperDeploymentOwnerV1,
            ready: DeveloperDeploymentReadyV1,
        },
        ReconcileRequired(DeveloperDeploymentOwnerV1),
    }

    enum DeveloperDeploymentPipelineOutcomeV1 {
        Ready {
            store: ManagedFabricSuccessorStoreV1,
            ready: DeveloperDeploymentReadyV1,
        },
        ReconcileRequired(ManagedFabricSuccessorStoreV1),
    }

    /// Stable non-sensitive failure for the developer deployment boundary.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[non_exhaustive]
    pub enum DeveloperDeploymentErrorV1 {
        InvalidEnrollmentFacts,
        InvalidConfiguration,
        AuthorityFailed,
        ControllerStoreFailed,
        RestartRequiresExplicitRecovery,
        NodeExchangeFailed,
        RuntimeExchangeFailed,
        PxfsCutoverFailed,
        ManagedServingFailed,
        JoinedShutdownFailed,
    }

    impl fmt::Display for DeveloperDeploymentErrorV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "developer deployment failed closed: {self:?}")
        }
    }

    impl std::error::Error for DeveloperDeploymentErrorV1 {}

    /// Starts the real developer Deployment owner graph and performs one
    /// non-retrying remote enrollment/cutover attempt.
    pub async fn start_developer_deployment_v1(
        input: DeveloperDeploymentStartInputV1,
    ) -> Result<DeveloperDeploymentStartOutcomeV1, DeveloperDeploymentErrorV1> {
        let DeveloperDeploymentStartInputV1 {
            mode,
            controller_store_directory,
            successor_store_directory,
            enrollment,
            controller_seed,
            authority,
            runtime_client,
            node_client,
        } = input;
        let authority = DeveloperLocalTenureAuthorityV1::start(authority)
            .map_err(|_| DeveloperDeploymentErrorV1::AuthorityFailed)?;
        let mut runtime_client = match RestrictedRuntimeControlClientV1::start(runtime_client).await {
            Ok(client) => client,
            Err(_) => {
                let _ = authority.shutdown();
                return Err(DeveloperDeploymentErrorV1::RuntimeExchangeFailed);
            }
        };
        let mut node_client = match RestrictedNodeControlClientV1::start(node_client).await {
            Ok(client) => client,
            Err(_) => {
                let _ = runtime_client.shutdown().await;
                let _ = authority.shutdown();
                return Err(DeveloperDeploymentErrorV1::NodeExchangeFailed);
            }
        };
        let controller_signer = SigningKey::from_bytes(&controller_seed);
        drop(controller_seed);
        let result = enroll_and_cutover_developer_deployment_v1(
            mode,
            &controller_store_directory,
            &successor_store_directory,
            &enrollment,
            &controller_signer,
            authority.facts(),
            &mut node_client,
            &mut runtime_client,
        )
        .await;
        match result {
            Ok(DeveloperDeploymentPipelineOutcomeV1::Ready { store, ready }) => {
                Ok(DeveloperDeploymentStartOutcomeV1::Ready {
                    owner: DeveloperDeploymentOwnerV1 {
                        authority: Some(authority),
                        node_client: Some(node_client),
                        runtime_client: Some(runtime_client),
                        successor_store: Some(store),
                    },
                    ready,
                })
            }
            Ok(DeveloperDeploymentPipelineOutcomeV1::ReconcileRequired(store)) => {
                Ok(DeveloperDeploymentStartOutcomeV1::ReconcileRequired(
                    DeveloperDeploymentOwnerV1 {
                        authority: Some(authority),
                        node_client: Some(node_client),
                        runtime_client: Some(runtime_client),
                        successor_store: Some(store),
                    },
                ))
            }
            Err(error) => {
                let _ = node_client.shutdown().await;
                let _ = runtime_client.shutdown().await;
                let _ = authority.shutdown();
                Err(error)
            }
        }
    }

    async fn enroll_and_cutover_developer_deployment_v1(
        mode: DeveloperDeploymentStartModeV1,
        controller_store_directory: &Path,
        successor_store_directory: &Path,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        controller_signer: &SigningKey,
        authority_facts: &crate::developer_local_tenure_authority::DeveloperLocalTenureAuthorityFactsV1,
        node_client: &mut RestrictedNodeControlClientV1,
        runtime_client: &mut RestrictedRuntimeControlClientV1,
    ) -> Result<DeveloperDeploymentPipelineOutcomeV1, DeveloperDeploymentErrorV1> {
        validate_authority_cross_pins(enrollment, controller_signer, authority_facts)?;
        enrollment
            .runtime_transport_profile
            .validate_carrier_binding(
                enrollment.runtime_transport_profile_ref,
                &enrollment.runtime_carrier,
            )
            .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        if !runtime_client.matches_restricted_target(
            enrollment.runtime_transport_profile.target(),
            enrollment.runtime_transport_profile.route(),
            enrollment.runtime_transport_profile.runtime_principal(),
            enrollment.runtime_carrier.binding_digest(),
        ) {
            return Err(DeveloperDeploymentErrorV1::InvalidConfiguration);
        }
        let controller = ManagedFabricControllerIdentityV1::try_new(
            enrollment.runtime_carrier.controller_principal(),
            DeploymentWriterRef::from_bytes(*enrollment.writer.as_bytes()),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        let authority = ManagedFabricTenureAuthorityPinV1::try_new(
            enrollment.authority_principal,
            authority_facts.peer().uid(),
            authority_facts.peer().gid(),
            enrollment.authority_ref,
            enrollment.authority_key_ref,
            authority_facts.authority_verification_key(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        let describe = ManagedServingDescribeVerifierV1::try_new(
            enrollment.runtime_transport_profile.target(),
            enrollment.runtime_carrier.clone(),
            controller_signer.verifying_key().to_bytes(),
            enrollment.runtime_response_public_key,
            enrollment.verified_manifest.manifest_digest(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        let provisioning =
            ManagedFabricRemoteControllerProvisioningV1::new(controller, authority, describe);
        let owner_identity = ControllerOwnerIdentityFingerprint::from_stored(
            authority_facts.owner_identity_fingerprint(),
        );
        let request_auth = ControllerRequestAuthPin::try_new(
            enrollment.runtime_carrier.controller_request_key(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?,
            ED25519_ALGORITHM_VERSION,
            ControllerAuthKeyFingerprint::from_stored(
                enrollment
                    .runtime_carrier
                    .controller_request_key_fingerprint(),
            ),
            INITIAL_AUTH_ROTATION_GENERATION,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        if mode == DeveloperDeploymentStartModeV1::Resume {
            return resume_developer_deployment_v1(
                controller_store_directory,
                successor_store_directory,
                enrollment,
                controller_signer,
                authority_facts,
                owner_identity,
                request_auth,
                &provisioning,
                runtime_client,
            )
            .await;
        }
        let allocation = StableAllocationSnapshot::try_new(
            enrollment.runtime_transport_profile.target(),
            0,
            0,
            Vec::new(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        let initialization = ControllerInitializationInput::try_new(
            DeploymentScopeId::from_bytes(*enrollment.source_scope.as_bytes()),
            DeploymentId::from_bytes(derived_developer_plan_id(enrollment.configuration_digest)?),
            allocation,
            ControllerInstalledManifestPin::from_verified_manifest(
                enrollment.verified_manifest.clone(),
            ),
            request_auth,
            owner_identity,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        let receipt = initialize_controller_store_developer_local(
            controller_store_directory,
            initialization,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        let mut store = ControllerStore::open_developer_local(
            controller_store_directory,
            *receipt.store_instance_id(),
            owner_identity,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        acquire_developer_tenure_once(
            &mut store,
            DeveloperTenurePinsV1::from_enrollment(enrollment),
            controller_signer,
            authority_facts,
        )
        .await?;
        if store
            .remote_connector_restart_requirement()
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?
            != ControllerRemoteConnectorRestartRequirementV1::None
        {
            return Err(DeveloperDeploymentErrorV1::RestartRequiresExplicitRecovery);
        }
        let successor_store_instance_id = nonzero_system_entropy::<32>()?;
        store
            .initialize_remote_connector(
                enrollment.configuration_digest,
                enrollment.runtime_transport_profile.target(),
                successor_store_instance_id,
                authority_facts.store_instance_id(),
            )
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;

        let node_transport = RemoteNodeControlTransportPinV1::try_new(
            enrollment.expected_node_principal,
            enrollment.node_route_config_digest,
            enrollment.runtime_carrier.controller_principal(),
            enrollment.runtime_carrier.controller_request_key(),
            enrollment
                .runtime_carrier
                .controller_request_key_fingerprint(),
            controller_signer.verifying_key().to_bytes(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        let mut node = RemoteNodeControlAdapterV1::new(node_transport);
        let target = node_describe_exchange(
            &mut store,
            node_client,
            &mut node,
            controller_signer,
            enrollment,
        )
        .await?;
        if target != enrollment.expected_node_target {
            return Err(DeveloperDeploymentErrorV1::NodeExchangeFailed);
        }
        let ingress = runtime_describe_exchange(
            &mut store,
            runtime_client,
            provisioning.describe(),
            controller_signer,
            enrollment,
        )
        .await?;
        if ingress.phase()
            != paraegox_runtime_contracts::managed_serving_bootstrap::RuntimeControlDescribeReadyPhaseV1::LegacyReady
        {
            return Err(DeveloperDeploymentErrorV1::RuntimeExchangeFailed);
        }
        let runtime_authority = runtime_observation_authority(enrollment, &ingress)?;
        let challenge = node_challenge_exchange(
            &mut store,
            node_client,
            &node,
            controller_signer,
            enrollment,
            &runtime_authority,
        )
        .await?;
        let verified_query = runtime_query_exchange(
            &mut store,
            runtime_client,
            provisioning.describe(),
            controller_signer,
            enrollment,
            &ingress,
            challenge,
        )
        .await?;
        let observation = RuntimeObservationRequestV1::try_new(RuntimeObservationRequestInputV1 {
            intended_status_sequence: challenge.intended_status_sequence(),
            freshness_budget_nanos: challenge.freshness_budget_nanos(),
            runtime_host_id: challenge.runtime_host_id(),
            authority_digest: challenge.authority_digest(),
            challenge_issued_at_unix_nanos: challenge.issued_at_unix_nanos(),
            challenge_expires_at_unix_nanos: challenge.expires_at_unix_nanos(),
            query_request: verified_query.0,
            query_response: verified_query.1,
        })
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        node_publish_exchange(
            &mut store,
            node_client,
            &node,
            controller_signer,
            enrollment,
            observation,
        )
        .await?;
        node_latest_exchange(
            &mut store,
            node_client,
            &node,
            controller_signer,
            enrollment,
            target,
        )
        .await?;
        store
            .revalidate_remote_connector_cutover_ready()
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        let mut successor = ManagedFabricSuccessorStoreV1::cutover_from_remote_connector_developer_local(
            store,
            controller_store_directory,
            successor_store_directory,
            owner_identity,
            controller_signer,
            &provisioning,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::PxfsCutoverFailed)?;
        let ready = persist_remote_managed_serving_terminal(
            &mut successor,
            runtime_client,
            &provisioning,
            &ingress,
            controller_signer,
            enrollment,
        )
        .await?;
        Ok(match ready {
            Some(ready) => DeveloperDeploymentPipelineOutcomeV1::Ready {
                store: successor,
                ready,
            },
            None => DeveloperDeploymentPipelineOutcomeV1::ReconcileRequired(successor),
        })
    }

    async fn resume_developer_deployment_v1(
        controller_store_directory: &Path,
        successor_store_directory: &Path,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        controller_signer: &SigningKey,
        authority_facts: &crate::developer_local_tenure_authority::DeveloperLocalTenureAuthorityFactsV1,
        owner_identity: ControllerOwnerIdentityFingerprint,
        request_auth: ControllerRequestAuthPin,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        runtime_client: &mut RestrictedRuntimeControlClientV1,
    ) -> Result<DeveloperDeploymentPipelineOutcomeV1, DeveloperDeploymentErrorV1> {
        if let Ok(mut successor) =
            ManagedFabricSuccessorStoreV1::resume_from_remote_connector_cutover_marker_developer_local(
                controller_store_directory,
                successor_store_directory,
                owner_identity,
                controller_signer,
                provisioning,
            )
        {
            validate_resumed_controller_snapshot(
                successor.state().legacy_snapshot(),
                enrollment,
                authority_facts,
                request_auth,
            )?;
            let ingress = remote_describe_ingress_from_successor(&successor, provisioning)?;
            let ready = persist_remote_managed_serving_terminal(
                &mut successor,
                runtime_client,
                provisioning,
                &ingress,
                controller_signer,
                enrollment,
            )
            .await?;
            return Ok(match ready {
                Some(ready) => DeveloperDeploymentPipelineOutcomeV1::Ready {
                    store: successor,
                    ready,
                },
                None => DeveloperDeploymentPipelineOutcomeV1::ReconcileRequired(successor),
            });
        }

        let store = ControllerStore::open_developer_local_observed_identity(
            controller_store_directory,
            owner_identity,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RestartRequiresExplicitRecovery)?;
        let snapshot = store
            .snapshot()
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        validate_resumed_controller_snapshot(
            snapshot,
            enrollment,
            authority_facts,
            request_auth,
        )?;
        let facts = snapshot
            .remote_connector_cutover_ready_facts()
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?
            .ok_or(DeveloperDeploymentErrorV1::RestartRequiresExplicitRecovery)?;
        let ingress = ManagedServingDescribeIngressV1::try_accept(
            provisioning.describe(),
            None,
            facts.runtime_describe_request().clone(),
            facts.runtime_describe_response().canonical_wire(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let mut successor =
            ManagedFabricSuccessorStoreV1::cutover_from_remote_connector_developer_local(
                store,
                controller_store_directory,
                successor_store_directory,
                owner_identity,
                controller_signer,
                provisioning,
            )
            .map_err(|_| DeveloperDeploymentErrorV1::PxfsCutoverFailed)?;
        let ready = persist_remote_managed_serving_terminal(
            &mut successor,
            runtime_client,
            provisioning,
            &ingress,
            controller_signer,
            enrollment,
        )
        .await?;
        Ok(match ready {
            Some(ready) => DeveloperDeploymentPipelineOutcomeV1::Ready {
                store: successor,
                ready,
            },
            None => DeveloperDeploymentPipelineOutcomeV1::ReconcileRequired(successor),
        })
    }

    fn validate_resumed_controller_snapshot(
        snapshot: &ControllerJournalSnapshot,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        authority_facts: &crate::developer_local_tenure_authority::DeveloperLocalTenureAuthorityFactsV1,
        request_auth: ControllerRequestAuthPin,
    ) -> Result<(), DeveloperDeploymentErrorV1> {
        let state = snapshot.state();
        if state.scope() != DeploymentScopeId::from_bytes(*enrollment.source_scope.as_bytes())
            || state.plan_lineage()
                != DeploymentId::from_bytes(derived_developer_plan_id(
                    enrollment.configuration_digest,
                )?)
            || state.request_auth() != request_auth
            || state.installed_manifest().verified_manifest() != &enrollment.verified_manifest
        {
            return Err(DeveloperDeploymentErrorV1::InvalidEnrollmentFacts);
        }
        let facts = snapshot
            .remote_connector_cutover_ready_facts()
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?
            .ok_or(DeveloperDeploymentErrorV1::RestartRequiresExplicitRecovery)?;
        if facts.configuration_digest() != enrollment.configuration_digest
            || facts.target() != enrollment.runtime_transport_profile.target()
            || facts.node_target() != enrollment.expected_node_target
            || facts.authority_store_instance_id() != authority_facts.store_instance_id()
        {
            return Err(DeveloperDeploymentErrorV1::InvalidEnrollmentFacts);
        }
        Ok(())
    }

    fn remote_describe_ingress_from_successor(
        successor: &ManagedFabricSuccessorStoreV1,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
    ) -> Result<ManagedServingDescribeIngressV1, DeveloperDeploymentErrorV1> {
        let facts = successor
            .state()
            .legacy_snapshot()
            .remote_connector_cutover_ready_facts()
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?
            .ok_or(DeveloperDeploymentErrorV1::RestartRequiresExplicitRecovery)?;
        ManagedServingDescribeIngressV1::try_accept(
            provisioning.describe(),
            None,
            facts.runtime_describe_request().clone(),
            facts.runtime_describe_response().canonical_wire(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)
    }

    #[derive(Clone, Copy)]
    struct DeveloperTenurePinsV1 {
        source_scope: SourceScopeRef,
        writer: PlanWriterRef,
        authority_ref: TenureAuthorityRef,
        authority_key_ref: TenureKeyRef,
        controller_principal: PrincipalRef,
        controller_key: ApplyAuthKeyRef,
    }

    impl DeveloperTenurePinsV1 {
        const fn from_enrollment(enrollment: &DeveloperDeploymentEnrollmentFactsV1) -> Self {
            Self {
                source_scope: enrollment.source_scope,
                writer: enrollment.writer,
                authority_ref: enrollment.authority_ref,
                authority_key_ref: enrollment.authority_key_ref,
                controller_principal: enrollment.runtime_carrier.controller_principal(),
                controller_key: enrollment.runtime_carrier.controller_request_key(),
            }
        }
    }

    async fn acquire_developer_tenure_once(
        store: &mut ControllerStore,
        pins: DeveloperTenurePinsV1,
        signer: &SigningKey,
        authority: &crate::developer_local_tenure_authority::DeveloperLocalTenureAuthorityFactsV1,
    ) -> Result<(), DeveloperDeploymentErrorV1> {
        let proof_authority = TenureProofAuthority::try_new(
            pins.authority_ref,
            pins.authority_key_ref,
            TenureProofAlgorithm::try_new(ACQUIRE_TENURE_ED25519_ALGORITHM)
                .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?,
            ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        let peer = authority.peer();
        let endpoint = UnixAuthorityEndpoint::try_new(
            authority.socket_path().to_path_buf(),
            AuthoritySocketAcl::new(peer.uid(), peer.gid()),
            UnixCredentials::new(peer.uid(), peer.gid()),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::AuthorityFailed)?;
        let verifier = AuthorityProofVerifier::try_new(
            proof_authority,
            VerifyingKey::from_bytes(&authority.authority_verification_key())
                .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::AuthorityFailed)?;
        let client = UnixTenureAuthorityClient::try_new(endpoint, verifier, TENURE_EXCHANGE_TIMEOUT)
            .map_err(|_| DeveloperDeploymentErrorV1::AuthorityFailed)?;
        let profile = TenureRequestProfile {
            scope: DeploymentScopeId::from_bytes(*pins.source_scope.as_bytes()),
            writer: DeploymentWriterRef::from_bytes(*pins.writer.as_bytes()),
            controller_principal: pins.controller_principal,
            controller_key: ControllerAcquireKeyRef::from_bytes(*pins.controller_key.as_bytes()),
            controller_public_key_fingerprint: ControllerPublicKeyFingerprint::for_ed25519_key(
                &signer.verifying_key().to_bytes(),
            )
            .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?,
            max_response_payload_bytes: u32::try_from(
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
            )
            .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?,
        };
        let prepared = fresh_tenure_request(&profile, signer)
            .map_err(|_| DeveloperDeploymentErrorV1::AuthorityFailed)?;
        acquire_tenure_once(store, &client, &prepared)
            .await
            .map(|_| ())
            .map_err(|_| DeveloperDeploymentErrorV1::AuthorityFailed)
    }

    fn validate_authority_cross_pins(
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        controller_signer: &SigningKey,
        authority: &crate::developer_local_tenure_authority::DeveloperLocalTenureAuthorityFactsV1,
    ) -> Result<(), DeveloperDeploymentErrorV1> {
        let identities = authority.identities();
        let controller_public_key_fingerprint = ControllerPublicKeyFingerprint::for_ed25519_key(
            &controller_signer.verifying_key().to_bytes(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        if identities.source_scope != *enrollment.source_scope.as_bytes()
            || identities.writer != *enrollment.writer.as_bytes()
            || identities.authority != *enrollment.authority_ref.as_bytes()
            || identities.authority_key != *enrollment.authority_key_ref.as_bytes()
            || identities.service_principal != *enrollment.authority_principal.as_bytes()
            || identities.controller_principal
                != *enrollment.runtime_carrier.controller_principal().as_bytes()
            || identities.controller_key
                != *enrollment
                    .runtime_carrier
                    .controller_request_key()
                    .as_bytes()
            || authority.controller_public_key_fingerprint()
                != *controller_public_key_fingerprint.as_bytes()
            || authority.authority_verification_key() != enrollment.authority_verification_key
            || controller_signer.verifying_key().to_bytes()
                == authority.authority_verification_key()
        {
            return Err(DeveloperDeploymentErrorV1::InvalidEnrollmentFacts);
        }
        Ok(())
    }

    fn derived_developer_plan_id(
        configuration_digest: Digest32,
    ) -> Result<[u8; 16], DeveloperDeploymentErrorV1> {
        let mut builder = Digest32Builder::try_new(DEVELOPER_DEPLOYMENT_PLAN_DOMAIN)
            .map_err(|_| DeveloperDeploymentErrorV1::InvalidConfiguration)?;
        builder
            .field_digest(&configuration_digest)
            .map_err(|_| DeveloperDeploymentErrorV1::InvalidConfiguration)?;
        let digest = builder.finish();
        let mut value = [0; 16];
        value.copy_from_slice(&digest.as_bytes()[..16]);
        if value == [0; 16] {
            return Err(DeveloperDeploymentErrorV1::InvalidConfiguration);
        }
        Ok(value)
    }

    fn nonzero_system_entropy<const N: usize>() -> Result<[u8; N], DeveloperDeploymentErrorV1> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidConfiguration)?;
        let mut source = File::from(owned);
        let mut value = [0; N];
        source
            .read_exact(&mut value)
            .map_err(|_| DeveloperDeploymentErrorV1::InvalidConfiguration)?;
        if value.iter().all(|byte| *byte == 0) {
            return Err(DeveloperDeploymentErrorV1::InvalidConfiguration);
        }
        Ok(value)
    }

    fn fresh_remote_node_request(
    ) -> Result<FreshRemoteNodeControlRequestV1, DeveloperDeploymentErrorV1> {
        FreshRemoteNodeControlRequestV1::try_new(
            nonzero_system_entropy::<16>()?,
            nonzero_system_entropy::<32>()?,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::NodeExchangeFailed)
    }

    fn fresh_remote_runtime_request(
    ) -> Result<FreshManagedServingBootstrapV1, DeveloperDeploymentErrorV1> {
        FreshManagedServingBootstrapV1::try_new(
            nonzero_system_entropy::<16>()?,
            nonzero_system_entropy::<32>()?,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)
    }

    struct PendingRemoteResponseV1 {
        claim: ClaimedControllerRemoteConnectorAttemptV1,
        response: Box<[u8]>,
    }

    async fn send_node_wire_once(
        store: &mut ControllerStore,
        client: &mut RestrictedNodeControlClientV1,
        step: ControllerRemoteConnectorStepV1,
        request_wire: Box<[u8]>,
    ) -> Result<PendingRemoteResponseV1, DeveloperDeploymentErrorV1> {
        store
            .prepare_remote_connector_request(step, &request_wire)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        let preflight = client
            .preflight(request_wire.into_vec())
            .await
            .map_err(|_| DeveloperDeploymentErrorV1::NodeExchangeFailed)?;
        let claim = store
            .claim_remote_connector_attempt(step)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        let response = match preflight.send_once().await {
            Ok(response) => response,
            Err(_) => {
                store
                    .close_remote_connector_attempt(
                        claim,
                        ControllerRemoteConnectorAttemptPhaseV1::Uncertain,
                    )
                    .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
                return Err(DeveloperDeploymentErrorV1::NodeExchangeFailed);
            }
        };
        Ok(PendingRemoteResponseV1 { claim, response })
    }

    async fn send_runtime_wire_once(
        store: &mut ControllerStore,
        client: &mut RestrictedRuntimeControlClientV1,
        step: ControllerRemoteConnectorStepV1,
        request_wire: Box<[u8]>,
    ) -> Result<PendingRemoteResponseV1, DeveloperDeploymentErrorV1> {
        store
            .prepare_remote_connector_request(step, &request_wire)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        let preflight = client
            .preflight(request_wire.into_vec())
            .await
            .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let claim = store
            .claim_remote_connector_attempt(step)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        let response = match preflight.send_once().await {
            Ok(response) => response,
            Err(_) => {
                store
                    .close_remote_connector_attempt(
                        claim,
                        ControllerRemoteConnectorAttemptPhaseV1::Uncertain,
                    )
                    .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
                return Err(DeveloperDeploymentErrorV1::RuntimeExchangeFailed);
            }
        };
        Ok(PendingRemoteResponseV1 { claim, response })
    }

    async fn node_describe_exchange(
        store: &mut ControllerStore,
        client: &mut RestrictedNodeControlClientV1,
        node: &mut RemoteNodeControlAdapterV1,
        signer: &SigningKey,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
    ) -> Result<NodeManagementTargetV1, DeveloperDeploymentErrorV1> {
        let mut boundary_error = None;
        let mut pending = None;
        let result = node
            .describe_once(fresh_remote_node_request()?, signer, |wire| async {
                match send_node_wire_once(
                    store,
                    client,
                    ControllerRemoteConnectorStepV1::NodeDescribe,
                    wire,
                )
                .await
                {
                    Ok(response) => {
                        let raw = response.response.clone();
                        pending = Some(response);
                        RemoteNodeMtlsExchangeSuccessV1::try_new(
                            enrollment.expected_node_principal,
                            enrollment.node_route_config_digest,
                            raw,
                        )
                        .map_err(|_| RemoteNodeControlTransportErrorV1::Rejected)
                    }
                    Err(error) => {
                        boundary_error = Some(error);
                        Err(RemoteNodeControlTransportErrorV1::Rejected)
                    }
                }
            })
            .await;
        if let Some(error) = boundary_error {
            return Err(error);
        }
        let target = match result {
            Ok(target) => target,
            Err(_) => {
                if let Some(pending) = pending.take() {
                    let _ = store.close_remote_connector_attempt(
                        pending.claim,
                        ControllerRemoteConnectorAttemptPhaseV1::Rejected,
                    );
                }
                return Err(DeveloperDeploymentErrorV1::NodeExchangeFailed);
            }
        };
        let pending = pending.ok_or(DeveloperDeploymentErrorV1::NodeExchangeFailed)?;
        store
            .commit_remote_connector_response(pending.claim, &pending.response)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        Ok(target)
    }

    async fn runtime_describe_exchange(
        store: &mut ControllerStore,
        client: &mut RestrictedRuntimeControlClientV1,
        verifier: &ManagedServingDescribeVerifierV1,
        signer: &SigningKey,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
    ) -> Result<ManagedServingDescribeIngressV1, DeveloperDeploymentErrorV1> {
        let request = verifier
            .try_build_request(None, fresh_remote_runtime_request()?, signer)
            .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let pending = send_runtime_wire_once(
            store,
            client,
            ControllerRemoteConnectorStepV1::RuntimeDescribe,
            request.canonical_wire().into(),
        )
        .await?;
        let ingress = match ManagedServingDescribeIngressV1::try_accept(
            verifier,
            None,
            request,
            &pending.response,
        ) {
            Ok(ingress) => ingress,
            Err(_) => {
                let _ = store.close_remote_connector_attempt(
                    pending.claim,
                    ControllerRemoteConnectorAttemptPhaseV1::Rejected,
                );
                return Err(DeveloperDeploymentErrorV1::RuntimeExchangeFailed);
            }
        };
        store
            .commit_remote_connector_response(pending.claim, &pending.response)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        Ok(ingress)
    }

    fn runtime_observation_authority(
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        ingress: &ManagedServingDescribeIngressV1,
    ) -> Result<RuntimeObservationAuthorityV1, DeveloperDeploymentErrorV1> {
        let facts = ingress.serving_facts();
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            facts.target(),
            facts.runtime_store_instance_id(),
            facts.snapshot_sequence(),
            facts.runtime_host_epoch(),
            facts.clock_domain(),
            facts.clock_generation(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes(
                enrollment.runtime_transport_profile.endpoint_ref(),
            )
            .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?,
            enrollment.runtime_transport_profile.target(),
            enrollment.runtime_transport_profile.endpoint_generation(),
            enrollment.runtime_transport_profile.route(),
            *enrollment.runtime_carrier.runtime_response_key().as_bytes(),
            enrollment.runtime_response_public_key,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)?;
        RuntimeObservationAuthorityV1::try_new(
            enrollment.runtime_carrier.runtime_principal(),
            ingress.channel(),
            serving,
            endpoint,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::InvalidEnrollmentFacts)
    }

    async fn node_challenge_exchange(
        store: &mut ControllerStore,
        client: &mut RestrictedNodeControlClientV1,
        node: &RemoteNodeControlAdapterV1,
        signer: &SigningKey,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        authority: &RuntimeObservationAuthorityV1,
    ) -> Result<NodeControlObservationChallengeV1, DeveloperDeploymentErrorV1> {
        let mut boundary_error = None;
        let mut pending = None;
        let result = node
            .observation_challenge_once(
                fresh_remote_node_request()?,
                signer,
                authority,
                enrollment.observation_endpoint_ref,
                MAX_RUNTIME_OBSERVATION_CHALLENGE_NANOS.min(MAX_NODE_STATUS_FRESHNESS_NANOS),
                |wire| async {
                    match send_node_wire_once(
                        store,
                        client,
                        ControllerRemoteConnectorStepV1::NodeChallenge,
                        wire,
                    )
                    .await
                    {
                        Ok(response) => {
                            let raw = response.response.clone();
                            pending = Some(response);
                            RemoteNodeMtlsExchangeSuccessV1::try_new(
                                enrollment.expected_node_principal,
                                enrollment.node_route_config_digest,
                                raw,
                            )
                            .map_err(|_| RemoteNodeControlTransportErrorV1::Rejected)
                        }
                        Err(error) => {
                            boundary_error = Some(error);
                            Err(RemoteNodeControlTransportErrorV1::Rejected)
                        }
                    }
                },
            )
            .await;
        if let Some(error) = boundary_error {
            return Err(error);
        }
        let challenge = match result {
            Ok(challenge) => challenge,
            Err(_) => {
                if let Some(pending) = pending.take() {
                    let _ = store.close_remote_connector_attempt(
                        pending.claim,
                        ControllerRemoteConnectorAttemptPhaseV1::Rejected,
                    );
                }
                return Err(DeveloperDeploymentErrorV1::NodeExchangeFailed);
            }
        };
        let pending = pending.ok_or(DeveloperDeploymentErrorV1::NodeExchangeFailed)?;
        store
            .commit_remote_connector_response(pending.claim, &pending.response)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        Ok(challenge)
    }

    async fn runtime_query_exchange(
        store: &mut ControllerStore,
        client: &mut RestrictedRuntimeControlClientV1,
        verifier: &ManagedServingDescribeVerifierV1,
        signer: &SigningKey,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        ingress: &ManagedServingDescribeIngressV1,
        challenge: NodeControlObservationChallengeV1,
    ) -> Result<(ReferenceQueryRequestV1, ReferenceQueryResponseV1), DeveloperDeploymentErrorV1>
    {
        let query_id = ReferenceQueryIdV1::from_bytes(nonzero_system_entropy::<16>()?);
        let selector = ReferenceQuerySelectorV1::try_new(
            query_id,
            enrollment.runtime_transport_profile.target(),
            enrollment.source_scope,
            ingress.serving_facts().runtime_store_instance_id(),
            ApplyOperationId::from_bytes(nonzero_system_entropy::<16>()?),
            None,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let claim = ApplyRequestAuthClaim::try_new(
            enrollment.runtime_carrier.controller_principal(),
            enrollment.runtime_carrier.controller_request_key(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?,
            ED25519_ALGORITHM_VERSION,
            challenge.query_nonce().as_bytes(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let draft = ReferenceQueryRequestDraftV1::try_new(
            selector,
            claim,
            u32::try_from(MAX_REFERENCE_QUERY_RESPONSE_BYTES)
                .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let signature = signer.sign(
            draft
                .signing_transcript()
                .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?
                .as_bytes(),
        );
        let request = draft
            .finalize(&signature.to_bytes())
            .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let facts = ingress.serving_facts();
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            facts.target(),
            facts.runtime_store_instance_id(),
            facts.snapshot_sequence(),
            facts.runtime_host_epoch(),
            facts.clock_domain(),
            facts.clock_generation(),
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let prepared = PreparedRuntimeQueryRequest::try_new(
            request.clone(),
            ingress.channel(),
            enrollment.runtime_carrier.runtime_response_key(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?,
            ED25519_ALGORITHM_VERSION,
            serving,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let action = verifier
            .try_build_reference_query(
                ingress,
                fresh_remote_runtime_request()?,
                signer,
                prepared,
            )
            .map_err(|_| DeveloperDeploymentErrorV1::RuntimeExchangeFailed)?;
        let pending = send_runtime_wire_once(
            store,
            client,
            ControllerRemoteConnectorStepV1::RuntimeQuery,
            action.carrier_request().canonical_wire().into(),
        )
        .await?;
        let verified = match verifier.try_accept_reference_query_response(
                ingress,
                action.carrier_request(),
                action.prepared(),
                enrollment.runtime_carrier.runtime_principal(),
                enrollment.runtime_carrier.binding_digest(),
                &pending.response,
            ) {
            Ok(verified) => verified,
            Err(_) => {
                let _ = store.close_remote_connector_attempt(
                    pending.claim,
                    ControllerRemoteConnectorAttemptPhaseV1::Rejected,
                );
                return Err(DeveloperDeploymentErrorV1::RuntimeExchangeFailed);
            }
        };
        store
            .commit_remote_connector_response(pending.claim, &pending.response)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)?;
        Ok((request, verified.into_response()))
    }

    async fn node_publish_exchange(
        store: &mut ControllerStore,
        client: &mut RestrictedNodeControlClientV1,
        node: &RemoteNodeControlAdapterV1,
        signer: &SigningKey,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        observation: RuntimeObservationRequestV1,
    ) -> Result<(), DeveloperDeploymentErrorV1> {
        let mut boundary_error = None;
        let mut pending = None;
        let result = node
            .publish_runtime_observation_once(
                fresh_remote_node_request()?,
                signer,
                observation,
                |wire| async {
                    match send_node_wire_once(
                        store,
                        client,
                        ControllerRemoteConnectorStepV1::NodePublish,
                        wire,
                    )
                    .await
                    {
                        Ok(response) => {
                            let raw = response.response.clone();
                            pending = Some(response);
                            RemoteNodeMtlsExchangeSuccessV1::try_new(
                                enrollment.expected_node_principal,
                                enrollment.node_route_config_digest,
                                raw,
                            )
                            .map_err(|_| RemoteNodeControlTransportErrorV1::Rejected)
                        }
                        Err(error) => {
                            boundary_error = Some(error);
                            Err(RemoteNodeControlTransportErrorV1::Rejected)
                        }
                    }
                },
            )
            .await;
        if let Some(error) = boundary_error {
            return Err(error);
        }
        if result.is_err() {
            if let Some(pending) = pending.take() {
                let _ = store.close_remote_connector_attempt(
                    pending.claim,
                    ControllerRemoteConnectorAttemptPhaseV1::Rejected,
                );
            }
            return Err(DeveloperDeploymentErrorV1::NodeExchangeFailed);
        }
        let pending = pending.ok_or(DeveloperDeploymentErrorV1::NodeExchangeFailed)?;
        store
            .commit_remote_connector_response(pending.claim, &pending.response)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)
    }

    async fn node_latest_exchange(
        store: &mut ControllerStore,
        client: &mut RestrictedNodeControlClientV1,
        node: &RemoteNodeControlAdapterV1,
        signer: &SigningKey,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
        target: NodeManagementTargetV1,
    ) -> Result<(), DeveloperDeploymentErrorV1> {
        let request_id = nonzero_system_entropy::<16>()?;
        let request = NodeManagementRequestV1::try_latest(request_id, target)
            .map_err(|_| DeveloperDeploymentErrorV1::NodeExchangeFailed)?;
        // The carrier request id and inner PXNS request id must be identical.
        let fresh = FreshRemoteNodeControlRequestV1::try_new(
            request_id,
            nonzero_system_entropy::<32>()?,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::NodeExchangeFailed)?;
        let process_generation = NodeObservationProcessGenerationV1::try_from_bytes(
            nonzero_system_entropy::<16>()?,
        )
        .map_err(|_| DeveloperDeploymentErrorV1::NodeExchangeFailed)?;
        let mut boundary_error = None;
        let mut pending = None;
        let result = node
            .observe_management_once(
                fresh,
                signer,
                request,
                process_generation,
                || {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .and_then(|value| u64::try_from(value.as_nanos()).ok())
                        .filter(|value| *value != 0)
                        .unwrap_or(1)
                },
                |wire| async {
                    match send_node_wire_once(
                        store,
                        client,
                        ControllerRemoteConnectorStepV1::NodeLatest,
                        wire,
                    )
                    .await
                    {
                        Ok(response) => {
                            let raw = response.response.clone();
                            pending = Some(response);
                            RemoteNodeMtlsExchangeSuccessV1::try_new(
                                enrollment.expected_node_principal,
                                enrollment.node_route_config_digest,
                                raw,
                            )
                            .map_err(|_| RemoteNodeControlTransportErrorV1::Rejected)
                        }
                        Err(error) => {
                            boundary_error = Some(error);
                            Err(RemoteNodeControlTransportErrorV1::Rejected)
                        }
                    }
                },
            )
            .await;
        if let Some(error) = boundary_error {
            return Err(error);
        }
        if result.is_err() {
            if let Some(pending) = pending.take() {
                let _ = store.close_remote_connector_attempt(
                    pending.claim,
                    ControllerRemoteConnectorAttemptPhaseV1::Rejected,
                );
            }
            return Err(DeveloperDeploymentErrorV1::NodeExchangeFailed);
        }
        let pending = pending.ok_or(DeveloperDeploymentErrorV1::NodeExchangeFailed)?;
        store
            .commit_remote_connector_response(pending.claim, &pending.response)
            .map_err(|_| DeveloperDeploymentErrorV1::ControllerStoreFailed)
    }

    async fn persist_remote_managed_serving_terminal(
        store: &mut ManagedFabricSuccessorStoreV1,
        client: &mut RestrictedRuntimeControlClientV1,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ingress: &ManagedServingDescribeIngressV1,
        signer: &SigningKey,
        enrollment: &DeveloperDeploymentEnrollmentFactsV1,
    ) -> Result<Option<DeveloperDeploymentReadyV1>, DeveloperDeploymentErrorV1> {
        let mut journal = ManagedFabricApplyJournalV1::new(store.state().clone());
        if journal.state().serving_phase() == ManagedServingBootstrapPhaseV1::AttemptInFlight {
            journal
                .close_recovered_serving_bootstrap_with(|next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                })
                .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
        }
        if matches!(
            journal.state().serving_phase(),
            ManagedServingBootstrapPhaseV1::ReadyForRequest
                | ManagedServingBootstrapPhaseV1::RequestDurable
        ) {
            let prepared = if journal.state().serving_phase()
                == ManagedServingBootstrapPhaseV1::RequestDurable
            {
                journal
                    .prepared_serving_bootstrap()
                    .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?
            } else {
                journal
                    .prepare_remote_serving_bootstrap_with(
                        signer,
                        provisioning,
                        ingress,
                        fresh_remote_runtime_request()?,
                        |next| {
                            store.commit_state(next).map_err(|_| {
                                ManagedFabricApplyControllerError::DurabilityRejected
                            })
                        },
                    )
                    .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?
            };
            let action = journal
                .claim_remote_serving_bootstrap_with(
                    prepared,
                    signer,
                    provisioning,
                    ingress,
                    fresh_remote_runtime_request()?,
                    |next| {
                        store
                            .commit_state(next)
                            .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                    },
                )
                .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
            let context = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
                journal.state().legacy_snapshot().state(),
                signer,
                provisioning,
                ingress,
            )
            .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
            let outcome = action
                .exchange_remote_once(
                    provisioning.describe(),
                    ingress,
                    &context,
                    |wire| async {
                        let preflight = client
                            .preflight(wire.into_vec())
                            .await
                            .map_err(|_| RuntimeManagedServingTransportErrorV1::NotSent)?;
                        let response = preflight
                            .send_once()
                            .await
                            .map_err(|_| RuntimeManagedServingTransportErrorV1::Uncertain)?;
                        RuntimeManagedServingMtlsExchangeSuccessV1::try_new(
                            enrollment.runtime_carrier.runtime_principal(),
                            enrollment.runtime_carrier.binding_digest(),
                            response,
                        )
                        .map_err(|_| RuntimeManagedServingTransportErrorV1::Rejected)
                    },
                )
                .await;
            let (action, response) = outcome.into_parts();
            match response {
                Ok(response) => {
                    journal
                        .consume_remote_serving_bootstrap_response_with(
                            action,
                            response,
                            signer,
                            provisioning,
                            ingress,
                            |next| {
                                store.commit_state(next).map_err(|_| {
                                    ManagedFabricApplyControllerError::DurabilityRejected
                                })
                            },
                        )
                        .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
                }
                Err(_) => {
                    journal
                        .close_serving_bootstrap_no_response_with(action, |next| {
                            store.commit_state(next).map_err(|_| {
                                ManagedFabricApplyControllerError::DurabilityRejected
                            })
                        })
                        .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
                }
            }
        }

        if journal.state().serving_describe_reconcile_phase()
            == ManagedServingDescribeReconcilePhaseV1::AttemptInFlight
        {
            journal
                .close_recovered_remote_managed_ready_describe_with(|next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                })
                .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
        }
        if journal.state().serving_describe_reconcile_phase()
            == ManagedServingDescribeReconcilePhaseV1::ResponseDurable
        {
            let ready = journal
                .current_remote_managed_ready_facts(signer, provisioning, ingress)
                .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
            if journal.state().serving_phase()
                != ManagedServingBootstrapPhaseV1::ResponseDurable
            {
                return Ok(None);
            }
            return developer_deployment_ready(&journal, &ready).map(Some);
        }
        let prepared = if journal.state().serving_describe_reconcile_phase()
            == ManagedServingDescribeReconcilePhaseV1::RequestDurable
        {
            journal
                .prepared_remote_managed_ready_describe()
                .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?
        } else {
            journal
                .prepare_remote_managed_ready_describe_with(
                    signer,
                    provisioning,
                    ingress,
                    fresh_remote_runtime_request()?,
                    |next| {
                        store
                            .commit_state(next)
                            .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                    },
                )
                .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?
        };
        let action = journal
            .claim_remote_managed_ready_describe_with(
                prepared,
                provisioning,
                ingress,
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
        let outcome = action
            .exchange_remote_once(|wire| async {
                let preflight = client
                    .preflight(wire.into_vec())
                    .await
                    .map_err(|_| RuntimeManagedServingDescribeTransportErrorV1::NotSent)?;
                let response = preflight
                    .send_once()
                    .await
                    .map_err(|_| RuntimeManagedServingDescribeTransportErrorV1::Uncertain)?;
                RuntimeManagedServingDescribeMtlsExchangeSuccessV1::try_new(
                    enrollment.runtime_carrier.runtime_principal(),
                    enrollment.runtime_carrier.binding_digest(),
                    response,
                )
                .map_err(|_| RuntimeManagedServingDescribeTransportErrorV1::Rejected)
            })
            .await;
        let (action, response) = outcome.into_parts();
        let transport = match response {
            Ok(transport) => transport,
            Err(_) => {
                journal
                    .close_remote_managed_ready_describe_no_response_with(action, |next| {
                        store.commit_state(next).map_err(|_| {
                            ManagedFabricApplyControllerError::DurabilityRejected
                        })
                    })
                    .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
                return Ok(None);
            }
        };
        if provisioning
            .describe()
            .try_accept_managed_ready_describe_response(
                ingress,
                action.request().clone(),
                &transport,
            )
            .is_err()
        {
            journal
                .close_remote_managed_ready_describe_no_response_with(action, |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                })
                .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
            return Ok(None);
        }
        journal
            .consume_remote_managed_ready_describe_response_with(
                action,
                transport,
                provisioning,
                ingress,
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
        let ready = journal
            .current_remote_managed_ready_facts(signer, provisioning, ingress)
            .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
        if journal.state().serving_phase() != ManagedServingBootstrapPhaseV1::ResponseDurable {
            return Ok(None);
        }
        developer_deployment_ready(&journal, &ready).map(Some)
    }

    fn developer_deployment_ready(
        journal: &ManagedFabricApplyJournalV1,
        ready: &crate::managed_serving_client::VerifiedManagedServingReadyV1,
    ) -> Result<DeveloperDeploymentReadyV1, DeveloperDeploymentErrorV1> {
        if journal.state().serving_phase() != ManagedServingBootstrapPhaseV1::ResponseDurable {
            return Err(DeveloperDeploymentErrorV1::RestartRequiresExplicitRecovery);
        }
        let facts = ready.serving_facts();
        let mut digest = Digest32Builder::try_new(DEVELOPER_DEPLOYMENT_MANAGED_READY_DOMAIN)
            .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
        digest
            .field_bytes(ready.response_wire())
            .map_err(|_| DeveloperDeploymentErrorV1::ManagedServingFailed)?;
        Ok(DeveloperDeploymentReadyV1 {
            target: facts.target(),
            runtime_store_instance_id: facts.runtime_store_instance_id(),
            snapshot_sequence: facts.snapshot_sequence(),
            runtime_host_epoch: facts.runtime_host_epoch(),
            managed_ready_digest: digest.finish(),
        })
    }

    pub(super) fn run() -> Result<(), DeploymentdProcessError> {
        let command = parse_arguments(std::env::args_os().skip(1))?;
        execute(command)
    }

    fn execute(command: ProcessCommand) -> Result<(), DeploymentdProcessError> {
        match command {
            ProcessCommand::Initialize(arguments) => initialize(arguments),
            ProcessCommand::MigrateControllerJournal(arguments) => {
                migrate_controller_journal(arguments)
            }
            ProcessCommand::CommitReferenceLoop(arguments) => commit_reference_loop(arguments),
            ProcessCommand::CommitReferenceEmpty(arguments) => commit_reference_empty(arguments),
            ProcessCommand::AcquireTenure(arguments) => acquire_tenure(arguments),
            ProcessCommand::BootstrapRuntime(arguments) => bootstrap_runtime(arguments),
            ProcessCommand::ObserveManagedServing(arguments) => observe_managed_serving(arguments),
            ProcessCommand::CommitAgentStack(arguments) => commit_agent_stack(*arguments),
            ProcessCommand::ApplyAgentStack(arguments) => apply_agent_stack(arguments),
            ProcessCommand::DeactivateAgentStack(arguments) => deactivate_agent_stack(arguments),
            ProcessCommand::InitializeDistributedAgentStack(capability_path) => {
                initialize_distributed_agent_stack(capability_path)
            }
            ProcessCommand::ObserveDistributedAgentStackNodesOnce(capability_path) => {
                observe_distributed_agent_stack_nodes_once(capability_path)
            }
            ProcessCommand::ApplyDistributedAgentStackOnce(capability_path) => {
                apply_distributed_agent_stack_once(capability_path)
            }
            ProcessCommand::ApplyReference(arguments) => apply_reference(arguments),
            ProcessCommand::ReconcileReferenceOnce(arguments) => reconcile_reference(arguments),
        }
    }

    fn migrate_controller_journal(
        arguments: ControllerJournalMigrationArguments,
    ) -> Result<(), DeploymentdProcessError> {
        let outcome = ControllerStore::migrate_payload_v7_offline(
            &arguments.state_directory,
            &arguments.evidence_directory,
            arguments.expected_store_id,
            ControllerOwnerIdentityFingerprint::from_stored(Digest32::from_bytes(
                arguments.expected_owner_identity,
            )),
            arguments.migration_id,
        )
        .map_err(|_| process_error(ProcessErrorKind::Migration))?;
        let disposition = match outcome.disposition {
            ControllerStoreMigrationDisposition::Migrated => b"migrated".as_slice(),
            ControllerStoreMigrationDisposition::AlreadyMigrated => b"already_migrated".as_slice(),
        };
        let receipt = outcome.receipt;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(b"controller_journal_migration_v1 disposition=")
            .and_then(|()| stdout.write_all(disposition))
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex_inline(&mut stdout, b" migration_id=", receipt.migration_id())?;
        write!(
            stdout,
            " source_payload_version={}",
            receipt.source_payload_version()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex_inline(
            &mut stdout,
            b" source_checksum=",
            receipt.source_checksum().as_bytes(),
        )?;
        write_labeled_hex_inline(
            &mut stdout,
            b" store_instance_id=",
            receipt.source_store_instance_id(),
        )?;
        write_labeled_hex_inline(
            &mut stdout,
            b" owner_identity_fingerprint=",
            receipt.source_owner_identity_fingerprint().as_bytes(),
        )?;
        write!(
            stdout,
            " source_snapshot_sequence={}",
            receipt.source_snapshot_sequence()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex_inline(&mut stdout, b" receipt=", receipt.canonical_wire())?;
        stdout
            .write_all(b"\n")
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_labeled_hex_inline(
        output: &mut impl Write,
        label: &[u8],
        bytes: &[u8],
    ) -> Result<(), DeploymentdProcessError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output
            .write_all(label)
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        let mut encoded = Vec::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            encoded.push(HEX[usize::from(byte >> 4)]);
            encoded.push(HEX[usize::from(byte & 0x0f)]);
        }
        output
            .write_all(&encoded)
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn initialize(arguments: InitializeArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_separation(&arguments.common, Some(&arguments.manifest_path))?;

        let key = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let manifest = read_pinned_file(
            &arguments.manifest_path,
            FileLengthPolicy::BoundedNonZero(MAX_INSTALLED_RUNTIME_MANIFEST_BYTES),
            FileRole::Manifest,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        if key.identity == manifest.identity {
            return Err(process_error(ProcessErrorKind::Path));
        }

        let request_auth = request_auth_pin(&arguments.common, &key.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let installed_manifest = ControllerInstalledManifestPin::try_from_persisted_manifest(
            &manifest.bytes,
            arguments.manifest_digest,
        )
        .map_err(|_| process_error(ProcessErrorKind::Manifest))?;
        let allocation =
            StableAllocationSnapshot::try_new(installed_manifest.target(), 0, 0, Vec::new())
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let input = ControllerInitializationInput::try_new(
            DeploymentScopeId::from_bytes(arguments.common.scope),
            DeploymentId::from_bytes(arguments.common.plan),
            allocation,
            installed_manifest,
            request_auth.pin,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let receipt = initialize_controller_store(&arguments.common.state_directory, input)
            .map_err(|_| process_error(ProcessErrorKind::Initialization))?;
        write_initialization_receipt(&receipt)
    }

    fn commit_reference_loop(arguments: CommitArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_separation(&arguments.common, None)?;
        let key = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &key.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;

        let scope = DeploymentScopeId::from_bytes(arguments.common.scope);
        let plan = DeploymentId::from_bytes(arguments.common.plan);
        let (candidate, operation) = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let state = snapshot.state();
            if state.scope() != scope
                || state.plan_lineage() != plan
                || state.request_auth() != request_auth.pin
                || state.current_revision() > 1
            {
                return Err(process_error(ProcessErrorKind::Provisioning));
            }
            let lifecycle = ValidatedReferenceLifecycleBudgetsV1::try_new(
                BoundedDuration::from_nanos(arguments.start_nanos),
                BoundedDuration::from_nanos(arguments.drain_nanos),
                BoundedDuration::from_nanos(arguments.cleanup_nanos),
            )
            .map_err(|_| process_error(ProcessErrorKind::Planning))?;
            let candidate = build_reference_candidate(
                state.installed_manifest(),
                arguments.deck_key,
                arguments.card_use_key,
                arguments.definition_version,
                lifecycle,
            )?;
            (
                candidate,
                ControllerOperationId::from_bytes(arguments.operation_id),
            )
        };

        // Preview both transitions before the first write. This prevents a
        // competing Prepared operation from becoming durable merely because a
        // later commit check would reject it. The same path reconstructs an
        // exact candidate after a crash at Prepared and verifies an already
        // Committed operation without asking the Planner for Loop -> Loop.
        let prepared_preview = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state()
            .prepare_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        prepared_preview
            .commit_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;

        if &prepared_preview
            != store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state()
        {
            let prepared_snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .try_successor(prepared_preview)
                .map_err(|_| process_error(ProcessErrorKind::Commit))?;
            store
                .commit(prepared_snapshot)
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
        }

        let committed_state = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state()
            .commit_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        if &committed_state
            != store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state()
        {
            let committed_snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .try_successor(committed_state)
                .map_err(|_| process_error(ProcessErrorKind::Commit))?;
            store
                .commit(committed_snapshot)
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
        }

        let committed = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?;
        if committed.state().current_revision() != 1 {
            return Err(process_error(ProcessErrorKind::Commit));
        }
        write_commit_receipt(committed, operation)
    }

    fn commit_reference_empty(
        arguments: CommitEmptyArguments,
    ) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_separation(&arguments.common, None)?;
        let key = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &key.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let operation = ControllerOperationId::from_bytes(arguments.operation_id);
        let scope = DeploymentScopeId::from_bytes(arguments.common.scope);
        let plan_lineage = DeploymentId::from_bytes(arguments.common.plan);

        let committed = commit_reference_empty_in_store(
            &mut store,
            scope,
            plan_lineage,
            request_auth.pin,
            operation,
        )?;
        write_empty_commit_receipt(&committed, operation)
    }

    fn commit_reference_empty_in_store(
        store: &mut ControllerStore,
        scope: DeploymentScopeId,
        plan_lineage: DeploymentId,
        request_auth: ControllerRequestAuthPin,
        operation: ControllerOperationId,
    ) -> Result<ControllerJournalSnapshot, DeploymentdProcessError> {
        let already_committed = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let state = snapshot.state();
            validate_empty_common_state(state, scope, plan_lineage, request_auth)?;
            state.current_revision() == 2
                && state
                    .committed_plan()
                    .is_some_and(|plan| plan.content().shape() == TargetIntent::EmptyTarget)
        };
        if already_committed {
            let committed = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            validate_committed_empty_state(committed.state(), operation)?;
            return Ok(committed.clone());
        }

        let candidate = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            build_reference_empty_candidate(snapshot.state())?
        };

        // As with the Loop commit, validate both durable transitions before
        // the first write. A competing Prepared operation therefore cannot be
        // introduced by an invocation whose eventual Empty commit must fail.
        let prepared_preview = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state()
            .prepare_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        prepared_preview
            .commit_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;

        if &prepared_preview
            != store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state()
        {
            let prepared_snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .try_successor(prepared_preview)
                .map_err(|_| process_error(ProcessErrorKind::Commit))?;
            store
                .commit(prepared_snapshot)
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
        }

        let committed_state = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state()
            .commit_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        if &committed_state
            != store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state()
        {
            let committed_snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .try_successor(committed_state)
                .map_err(|_| process_error(ProcessErrorKind::Commit))?;
            store
                .commit(committed_snapshot)
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
        }

        let committed = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?;
        validate_committed_empty_state(committed.state(), operation)?;
        Ok(committed.clone())
    }

    fn validate_empty_common_state(
        state: &crate::controller_journal::ControllerJournalState,
        scope: DeploymentScopeId,
        plan_lineage: DeploymentId,
        request_auth: ControllerRequestAuthPin,
    ) -> Result<(), DeploymentdProcessError> {
        if state.scope() != scope
            || state.plan_lineage() != plan_lineage
            || state.request_auth() != request_auth
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn build_reference_empty_candidate(
        state: &crate::controller_journal::ControllerJournalState,
    ) -> Result<DeploymentPlanCandidate, DeploymentdProcessError> {
        let plan = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let intent = state
            .current_signed_apply_intent()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let expected_active = state
            .current_active_target_slice_digest_for_plan_advance()
            .map_err(|_| process_error(ProcessErrorKind::Commit))?
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        if state.current_revision() != 1
            || plan.revision().value() != 1
            || plan.content().shape() != TargetIntent::OneSourceLoop
            || !state.current_apply_is_terminal()
            || intent.source_plan_digest() != plan.deployment_plan_digest()
            || expected_active != intent.target_slice_digest()
        {
            return Err(process_error(ProcessErrorKind::Commit));
        }

        let outcome = DeploymentPlanner::plan(&PlannerInput {
            target: state.installed_manifest().target(),
            desired: PlannerDesired::EmptyTarget,
            previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
            manifest: Some(state.installed_manifest().projection()),
            allocation: state.allocation(),
            service_dependencies: &[],
        })
        .map_err(|_| process_error(ProcessErrorKind::Planning))?;
        match outcome {
            PlannerOutcome::Candidate(candidate) => Ok(*candidate),
            PlannerOutcome::Omitted => Err(process_error(ProcessErrorKind::Planning)),
        }
    }

    fn validate_committed_empty_state(
        state: &crate::controller_journal::ControllerJournalState,
        operation: ControllerOperationId,
    ) -> Result<paraegox_runtime_contracts::provenance::TargetSliceDigest, DeploymentdProcessError>
    {
        let plan = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let expected_active = state
            .last_archived_active_target_slice_digest()
            .map_err(|_| process_error(ProcessErrorKind::Commit))?
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        if state.current_revision() != 2
            || plan.revision().value() != 2
            || plan.content().shape() != TargetIntent::EmptyTarget
            || plan.commit_operation() != operation
            || state.allocation().generation() != 2
            || state.allocation().high_water() != 1
            || state.allocation().records().len() != 1
            || state
                .allocation()
                .records()
                .iter()
                .any(|record| record.state() == AllocationState::Active)
            || state
                .last_terminal_target_slice_digest()
                .map_err(|_| process_error(ProcessErrorKind::Commit))?
                != Some(expected_active)
        {
            return Err(process_error(ProcessErrorKind::Commit));
        }
        Ok(expected_active)
    }

    fn acquire_tenure(arguments: AcquireTenureArguments) -> Result<(), DeploymentdProcessError> {
        // This S7-E command is deliberately ensure-once, not a writer-turnover
        // surface. It replays only the globally current matching transaction;
        // another writer's later committed epoch fences this invocation.
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_tenure_separation(&arguments)?;

        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        // The seed remains a pinned Controller-owned provisioning fact even on
        // replay. Durable request bytes are never re-signed, however.
        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        if controller_public.identity == authority_public.identity
            || controller_public.identity == controller_seed_file.identity
            || authority_public.identity == controller_seed_file.identity
        {
            return Err(process_error(ProcessErrorKind::Path));
        }

        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == authority_public_bytes {
            return Err(process_error(ProcessErrorKind::Key));
        }
        let mut seed = Zeroizing::new([0; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        let controller_verifying_key = controller_signer.verifying_key();
        if controller_verifying_key.to_bytes() != controller_public_bytes
            || controller_verifying_key.is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let proof_authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes(arguments.tenure_authority_ref),
            TenureKeyRef::from_bytes(arguments.tenure_key_ref),
            TenureProofAlgorithm::try_new(ACQUIRE_TENURE_ED25519_ALGORITHM)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?,
            ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let endpoint = UnixAuthorityEndpoint::try_new(
            arguments.authority_socket_path.clone(),
            AuthoritySocketAcl::new(arguments.authority_uid, arguments.common.expected_gid),
            UnixCredentials::new(arguments.authority_uid, arguments.authority_gid),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let proof_verifier = AuthorityProofVerifier::try_new(
            proof_authority,
            VerifyingKey::from_bytes(&authority_public_bytes)
                .map_err(|_| process_error(ProcessErrorKind::Key))?,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let client =
            UnixTenureAuthorityClient::try_new(endpoint, proof_verifier, TENURE_EXCHANGE_TIMEOUT)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let authority_domain_fingerprint = ControllerTenureAuthorityDomainFingerprint::from_stored(
            client.authority_domain_fingerprint(),
        );

        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let profile = tenure_request_profile(
            &arguments,
            &request_auth,
            controller_public_bytes,
            store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state(),
        )?;
        let prepared = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let unresolved = snapshot
                .state()
                .current_unresolved_tenure_transaction()
                .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
            let global_latest_committed = if unresolved.is_none() {
                snapshot
                    .state()
                    .global_latest_committed_tenure_transaction()
                    .map_err(|_| process_error(ProcessErrorKind::Tenure))?
            } else {
                None
            };
            match select_durable_tenure_request(
                unresolved.map(DurableTenureRequest::from),
                global_latest_committed.map(DurableTenureRequest::from),
                profile.writer,
                authority_domain_fingerprint,
            )? {
                Some(canonical_request) => {
                    recover_tenure_request(canonical_request, &profile, &controller_verifying_key)?
                }
                None => {
                    validate_fresh_tenure_plan(&arguments, snapshot.state())?;
                    fresh_tenure_request(&profile, &controller_signer)?
                }
            }
        };
        let operation = prepared.request().operation_id();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let acquired = runtime
            .block_on(acquire_tenure_once(&mut store, &client, &prepared))
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        write_tenure_receipt(
            store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?,
            operation,
            &acquired,
        )
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TenureRequestProfile {
        scope: DeploymentScopeId,
        writer: DeploymentWriterRef,
        controller_principal: PrincipalRef,
        controller_key: ControllerAcquireKeyRef,
        controller_public_key_fingerprint: ControllerPublicKeyFingerprint,
        max_response_payload_bytes: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DurableTenureRequest<'a> {
        canonical_request: &'a [u8],
        writer: DeploymentWriterRef,
        authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
    }

    impl<'a> From<&'a ControllerTenureTransaction> for DurableTenureRequest<'a> {
        fn from(transaction: &'a ControllerTenureTransaction) -> Self {
            Self {
                canonical_request: transaction.request().canonical_bytes(),
                writer: transaction.request().writer(),
                authority_domain_fingerprint: transaction.authority_domain_fingerprint(),
            }
        }
    }

    fn select_durable_tenure_request<'a>(
        unresolved: Option<DurableTenureRequest<'a>>,
        global_latest_committed: Option<DurableTenureRequest<'a>>,
        requested_writer: DeploymentWriterRef,
        authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
    ) -> Result<Option<&'a [u8]>, DeploymentdProcessError> {
        let selected = unresolved.or(global_latest_committed);
        let Some(selected) = selected else {
            return Ok(None);
        };
        if selected.writer != requested_writer
            || selected.authority_domain_fingerprint != authority_domain_fingerprint
        {
            return Err(process_error(ProcessErrorKind::Tenure));
        }
        Ok(Some(selected.canonical_request))
    }

    fn tenure_request_profile(
        arguments: &AcquireTenureArguments,
        request_auth: &RequestAuthProvisioning,
        controller_public_key: [u8; PUBLIC_KEY_BYTES],
        state: &crate::controller_journal::ControllerJournalState,
    ) -> Result<TenureRequestProfile, DeploymentdProcessError> {
        let scope = DeploymentScopeId::from_bytes(arguments.common.scope);
        let plan = DeploymentId::from_bytes(arguments.common.plan);
        if state.scope() != scope
            || state.plan_lineage() != plan
            || state.request_auth() != request_auth.pin
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(TenureRequestProfile {
            scope,
            writer: DeploymentWriterRef::from_bytes(arguments.writer_ref),
            controller_principal: PrincipalRef::from_bytes(arguments.controller_principal),
            controller_key: ControllerAcquireKeyRef::from_bytes(*request_auth.pin.key().as_bytes()),
            controller_public_key_fingerprint: ControllerPublicKeyFingerprint::for_ed25519_key(
                &controller_public_key,
            )
            .map_err(|_| process_error(ProcessErrorKind::Key))?,
            max_response_payload_bytes: u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?,
        })
    }

    fn validate_fresh_tenure_plan(
        arguments: &AcquireTenureArguments,
        state: &crate::controller_journal::ControllerJournalState,
    ) -> Result<(), DeploymentdProcessError> {
        let scope = DeploymentScopeId::from_bytes(arguments.common.scope);
        let plan = DeploymentId::from_bytes(arguments.common.plan);
        let committed = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Provisioning))?;
        if state.current_revision() != 1
            || committed.scope() != scope
            || committed.plan() != plan
            || committed.revision().value() != state.current_revision()
            || committed.target() != state.installed_manifest().target()
            || committed.content().target() != state.installed_manifest().target()
            || committed.content().shape() != TargetIntent::OneSourceLoop
            || committed.content().manifest_digest().value()
                != state.installed_manifest().manifest_digest()
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn recover_tenure_request(
        canonical_request: &[u8],
        profile: &TenureRequestProfile,
        controller_verifying_key: &VerifyingKey,
    ) -> Result<PreparedAcquireTenureRequest, DeploymentdProcessError> {
        let prepared =
            PreparedAcquireTenureRequest::try_from_canonical_request_bytes(canonical_request)
                .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let request = prepared.request();
        if request.scope() != profile.scope
            || request.writer() != profile.writer
            || request.controller_principal() != profile.controller_principal
            || request.controller_key() != profile.controller_key
            || request.controller_public_key_fingerprint()
                != profile.controller_public_key_fingerprint
            || request.auth_algorithm() != ACQUIRE_TENURE_ED25519_ALGORITHM
            || request.auth_algorithm_version() != ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION
            || request.max_response_payload_bytes() != profile.max_response_payload_bytes
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let signature_bytes: [u8; 64] = request
            .auth_signature()
            .try_into()
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let transcript = request
            .signing_transcript()
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        controller_verifying_key
            .verify_strict(
                transcript.as_bytes(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        Ok(prepared)
    }

    fn fresh_tenure_request(
        profile: &TenureRequestProfile,
        controller_signer: &SigningKey,
    ) -> Result<PreparedAcquireTenureRequest, DeploymentdProcessError> {
        let entropy = read_tenure_entropy()?;
        fresh_tenure_request_from_entropy(profile, controller_signer, &entropy)
    }

    fn fresh_tenure_request_from_entropy(
        profile: &TenureRequestProfile,
        controller_signer: &SigningKey,
        entropy: &[u8; TENURE_ENTROPY_BYTES],
    ) -> Result<PreparedAcquireTenureRequest, DeploymentdProcessError> {
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&entropy[..16]);
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                profile.scope,
                profile.writer,
                AcquireTenureOperationId::from_bytes(operation_id),
            ),
            profile.controller_principal,
            profile.controller_key,
            profile.controller_public_key_fingerprint,
            &entropy[16..],
            profile.max_response_payload_bytes,
        )
        .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let request = AcquireTenureRequestToSign::try_new(draft)
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let signature = controller_signer.sign(request.signing_bytes());
        request
            .finalize_ed25519(&signature.to_bytes())
            .map_err(|_| process_error(ProcessErrorKind::Tenure))
    }

    fn read_tenure_entropy() -> Result<[u8; TENURE_ENTROPY_BYTES], DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let mut source = File::from(owned);
        let mut entropy = [0; TENURE_ENTROPY_BYTES];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        Ok(entropy)
    }

    fn bootstrap_runtime(arguments: BootstrapArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_bootstrap_separation(&arguments)?;

        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let runtime_response_public = read_pinned_file(
            &arguments.runtime_response_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let runtime_response_public_bytes = exact_public_key(&runtime_response_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == runtime_response_public_bytes
            || controller_public_bytes == authority_public_bytes
            || runtime_response_public_bytes == authority_public_bytes
        {
            return Err(process_error(ProcessErrorKind::Key));
        }
        // Load the only secret last, after every public-key/path validation that
        // can fail without it. `PinnedFile` owns zeroizing storage, so all exits
        // after this point erase the original read buffer automatically.
        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let file_identities = [
            controller_public.identity,
            controller_seed_file.identity,
            runtime_response_public.identity,
            authority_public.identity,
        ];
        if file_identities
            .iter()
            .enumerate()
            .any(|(index, identity)| file_identities[index + 1..].contains(identity))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let mut seed = Zeroizing::new([0; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        if controller_signer.verifying_key().to_bytes() != controller_public_bytes
            || controller_signer.verifying_key().is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let admission_policy = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let state = snapshot.state();
            let expected_scope = DeploymentScopeId::from_bytes(arguments.common.scope);
            let expected_plan = DeploymentId::from_bytes(arguments.common.plan);
            if state.scope() != expected_scope
                || state.plan_lineage() != expected_plan
                || state.request_auth() != request_auth.pin
                || state.current_revision() != 1
                || state.committed_plan_digest().is_none()
            {
                return Err(process_error(ProcessErrorKind::Provisioning));
            }
            let target = state.installed_manifest().target();
            let source_scope = paraegox_runtime_contracts::provenance::SourceScopeRef::from_bytes(
                *state.scope().as_bytes(),
            );
            reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
                target,
                source_scope,
                writer: PlanWriterRef::from_bytes(arguments.writer_ref),
                controller_principal: PrincipalRef::from_bytes(arguments.controller_principal),
                controller_key_ref: request_auth.pin.key(),
                controller_public_key: &controller_public_bytes,
                authority_principal: PrincipalRef::from_bytes(arguments.authority_principal),
                authority_uid: arguments.authority_uid,
                authority_gid: arguments.authority_gid,
                tenure_authority_ref: TenureAuthorityRef::from_bytes(
                    arguments.tenure_authority_ref,
                ),
                tenure_key_ref: TenureKeyRef::from_bytes(arguments.tenure_key_ref),
                tenure_public_key: &authority_public_bytes,
            })
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?
        };

        let provisioning = ControllerBootstrapProvisioningV1::try_new(
            arguments.runtime_socket_path,
            PrincipalRef::from_bytes(arguments.controller_principal),
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            runtime_response_public_bytes,
            arguments.runtime_uid,
            arguments.runtime_gid,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
            admission_policy,
            BOOTSTRAP_EXCHANGE_TIMEOUT,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let fresh = fresh_bootstrap_request()?;
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::Bootstrap))?;
        let receipt = runtime
            .block_on(bootstrap_runtime_v1(
                &mut store,
                owner_identity,
                &controller_signer,
                provisioning,
                fresh,
            ))
            .map_err(|_| process_error(ProcessErrorKind::Bootstrap))?;
        write_bootstrap_receipt(&receipt)
    }

    fn observe_managed_serving(
        arguments: ManagedServingArguments,
    ) -> Result<(), DeploymentdProcessError> {
        let ManagedServingArguments {
            bootstrap: arguments,
            successor_directory,
            successor_store_id,
        } = arguments;
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_bootstrap_separation(&arguments)?;
        if successor_directory == arguments.common.state_directory
            || successor_directory.starts_with(&arguments.common.state_directory)
            || arguments
                .common
                .state_directory
                .starts_with(&successor_directory)
        {
            return Err(process_error(ProcessErrorKind::Path));
        }

        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let runtime_response_public = read_pinned_file(
            &arguments.runtime_response_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let runtime_response_public_bytes = exact_public_key(&runtime_response_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == runtime_response_public_bytes
            || controller_public_bytes == authority_public_bytes
            || runtime_response_public_bytes == authority_public_bytes
        {
            return Err(process_error(ProcessErrorKind::Key));
        }
        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let file_identities = [
            controller_public.identity,
            controller_seed_file.identity,
            runtime_response_public.identity,
            authority_public.identity,
        ];
        if file_identities
            .iter()
            .enumerate()
            .any(|(index, identity)| file_identities[index + 1..].contains(identity))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let mut seed = Zeroizing::new([0; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        if controller_signer.verifying_key().to_bytes() != controller_public_bytes
            || controller_signer.verifying_key().is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let controller = ManagedFabricControllerIdentityV1::try_new(
            PrincipalRef::from_bytes(arguments.controller_principal),
            DeploymentWriterRef::from_bytes(arguments.writer_ref),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let authority = ManagedFabricTenureAuthorityPinV1::try_new(
            PrincipalRef::from_bytes(arguments.authority_principal),
            arguments.authority_uid,
            arguments.authority_gid,
            TenureAuthorityRef::from_bytes(arguments.tenure_authority_ref),
            TenureKeyRef::from_bytes(arguments.tenure_key_ref),
            authority_public_bytes,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let accounts = ManagedFabricServiceAccountsV1::try_new(
            arguments.runtime_uid,
            arguments.runtime_gid,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_channel = ManagedFabricRuntimeChannelPinV1::try_new(
            arguments.runtime_socket_path.as_os_str().as_bytes(),
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            runtime_response_public_bytes,
            accounts,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let provisioning =
            ManagedFabricControllerProvisioningV1::new(controller, authority, runtime_channel);

        let mut store = match ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        ) {
            Ok(legacy) => ManagedFabricSuccessorStoreV1::cutover_from_legacy(
                legacy,
                &arguments.common.state_directory,
                &successor_directory,
                successor_store_id,
                owner_identity,
                &controller_signer,
                &provisioning,
            ),
            Err(ControllerStoreOpenError::Codec(ControllerJournalError::UnknownPayloadVersion)) => {
                ManagedFabricSuccessorStoreV1::resume_from_cutover_marker(
                    &arguments.common.state_directory,
                    &successor_directory,
                    successor_store_id,
                    owner_identity,
                    &controller_signer,
                    &provisioning,
                )
            }
            Err(_) => return Err(process_error(ProcessErrorKind::Store)),
        }
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let legacy_state = store.state().legacy_snapshot().state();
        if legacy_state.scope() != DeploymentScopeId::from_bytes(arguments.common.scope)
            || legacy_state.plan_lineage() != DeploymentId::from_bytes(arguments.common.plan)
            || legacy_state.request_auth() != request_auth.pin
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let target = legacy_state.installed_manifest().target();
        let endpoint = UnixRuntimeControlEndpoint::try_new(
            arguments.runtime_socket_path,
            RuntimeControlSocketAcl::new(arguments.runtime_uid, arguments.common.expected_gid),
            RuntimeUnixCredentials::new(arguments.runtime_uid, arguments.runtime_gid),
            target,
            PrincipalRef::from_bytes(arguments.runtime_principal),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_verifying_key = VerifyingKey::from_bytes(&runtime_response_public_bytes)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let runtime_key_fingerprint =
            ed25519_control_key_fingerprint(runtime_verifying_key.as_bytes())
                .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let response_verifier = RuntimeManagedServingResponseVerifier::try_new(
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            request_auth.pin.algorithm(),
            request_auth.pin.algorithm_version(),
            runtime_key_fingerprint,
            runtime_verifying_key,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let client = UnixRuntimeManagedServingClient::try_new(
            endpoint,
            response_verifier,
            MANAGED_SERVING_EXCHANGE_TIMEOUT,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let mut journal = ManagedFabricApplyJournalV1::new(store.state().clone());
        if journal.state().serving_phase() == ManagedServingBootstrapPhaseV1::AttemptInFlight {
            journal
                .close_recovered_serving_bootstrap_with(|next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                })
                .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?;
        }
        let prepared = if journal.state().serving_phase()
            == ManagedServingBootstrapPhaseV1::RequestDurable
        {
            journal
                .prepared_serving_bootstrap()
                .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?
        } else {
            let fresh = fresh_managed_serving_request()?;
            journal
                .prepare_serving_bootstrap_with(&controller_signer, &provisioning, fresh, |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                })
                .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?
        };
        let action = journal
            .claim_serving_bootstrap_with(prepared, |next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            })
            .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?;
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?;
        let outcome = runtime.block_on(client.exchange(action));
        let (action, response) = outcome.into_parts();
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                journal
                    .close_serving_bootstrap_no_response_with(action, |next| {
                        store
                            .commit_state(next)
                            .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                    })
                    .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?;
                return Err(process_error(ProcessErrorKind::ServingObservation));
            }
        };
        let pin = journal
            .consume_serving_bootstrap_response_with(
                action,
                &response,
                &controller_signer,
                &provisioning,
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?;
        write_managed_serving_receipt(&pin)
    }

    struct ManagedAgentStackProcessContext {
        store: ManagedFabricSuccessorStoreV1,
        controller_signer: SigningKey,
        provisioning: ManagedFabricControllerProvisioningV1,
        client: UnixRuntimeManagedAgentStackClient,
    }

    fn open_managed_agent_stack_context(
        managed: ManagedServingArguments,
    ) -> Result<ManagedAgentStackProcessContext, DeploymentdProcessError> {
        let ManagedServingArguments {
            bootstrap: arguments,
            successor_directory,
            successor_store_id,
        } = managed;
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_bootstrap_separation(&arguments)?;
        if successor_directory == arguments.common.state_directory
            || successor_directory.starts_with(&arguments.common.state_directory)
            || arguments
                .common
                .state_directory
                .starts_with(&successor_directory)
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let runtime_response_public = read_pinned_file(
            &arguments.runtime_response_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let identities = [
            controller_public.identity,
            controller_seed_file.identity,
            runtime_response_public.identity,
            authority_public.identity,
        ];
        if identities
            .iter()
            .enumerate()
            .any(|(index, identity)| identities[index + 1..].contains(identity))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let runtime_response_public_bytes = exact_public_key(&runtime_response_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == runtime_response_public_bytes
            || controller_public_bytes == authority_public_bytes
            || runtime_response_public_bytes == authority_public_bytes
        {
            return Err(process_error(ProcessErrorKind::Key));
        }
        let mut seed = Zeroizing::new([0; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        if controller_signer.verifying_key().to_bytes() != controller_public_bytes
            || controller_signer.verifying_key().is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }
        let controller = ManagedFabricControllerIdentityV1::try_new(
            PrincipalRef::from_bytes(arguments.controller_principal),
            DeploymentWriterRef::from_bytes(arguments.writer_ref),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let authority = ManagedFabricTenureAuthorityPinV1::try_new(
            PrincipalRef::from_bytes(arguments.authority_principal),
            arguments.authority_uid,
            arguments.authority_gid,
            TenureAuthorityRef::from_bytes(arguments.tenure_authority_ref),
            TenureKeyRef::from_bytes(arguments.tenure_key_ref),
            authority_public_bytes,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let accounts = ManagedFabricServiceAccountsV1::try_new(
            arguments.runtime_uid,
            arguments.runtime_gid,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_channel = ManagedFabricRuntimeChannelPinV1::try_new(
            arguments.runtime_socket_path.as_os_str().as_bytes(),
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            runtime_response_public_bytes,
            accounts,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let provisioning =
            ManagedFabricControllerProvisioningV1::new(controller, authority, runtime_channel);
        let store = ManagedFabricSuccessorStoreV1::resume_from_cutover_marker(
            &arguments.common.state_directory,
            &successor_directory,
            successor_store_id,
            owner_identity,
            &controller_signer,
            &provisioning,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let legacy_state = store.state().legacy_snapshot().state();
        if legacy_state.scope() != DeploymentScopeId::from_bytes(arguments.common.scope)
            || legacy_state.plan_lineage() != DeploymentId::from_bytes(arguments.common.plan)
            || legacy_state.request_auth() != request_auth.pin
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let target = legacy_state.installed_manifest().target();
        let endpoint = UnixRuntimeControlEndpoint::try_new(
            arguments.runtime_socket_path,
            RuntimeControlSocketAcl::new(arguments.runtime_uid, arguments.common.expected_gid),
            RuntimeUnixCredentials::new(arguments.runtime_uid, arguments.runtime_gid),
            target,
            PrincipalRef::from_bytes(arguments.runtime_principal),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_verifying_key = VerifyingKey::from_bytes(&runtime_response_public_bytes)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let runtime_key_fingerprint =
            ed25519_control_key_fingerprint(runtime_verifying_key.as_bytes())
                .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let response_verifier = RuntimeManagedAgentStackResponseVerifier::try_new(
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            request_auth.pin.algorithm(),
            request_auth.pin.algorithm_version(),
            runtime_key_fingerprint,
            runtime_verifying_key,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let client = UnixRuntimeManagedAgentStackClient::try_new(
            endpoint,
            response_verifier,
            MANAGED_AGENT_STACK_EXCHANGE_TIMEOUT,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        Ok(ManagedAgentStackProcessContext {
            store,
            controller_signer,
            provisioning,
            client,
        })
    }

    pub(crate) struct DistributedCoordinatorContextV1 {
        store: ControllerStore,
        owner_anchor: Digest32,
        controller_signer: SigningKey,
    }

    /// Seals an already-open Controller writer as the distributed coordinator
    /// authority. The caller cannot provide an owner anchor: it is recomputed
    /// only from the validated durable store, exact owner and Controller key.
    pub(crate) fn verify_distributed_coordinator_context_v1(
        store: ControllerStore,
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        controller_signer: SigningKey,
    ) -> Result<DistributedCoordinatorContextV1, DeploymentdProcessError> {
        let snapshot = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let request_auth = snapshot.state().request_auth();
        let controller_key = controller_signer.verifying_key();
        let controller_fingerprint = ed25519_control_key_fingerprint(controller_key.as_bytes())
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        if controller_key.is_weak()
            || snapshot.owner_identity_fingerprint() != expected_owner_identity
            || request_auth.algorithm().value() != ED25519_ALGORITHM
            || request_auth.algorithm_version() != ED25519_ALGORITHM_VERSION
            || request_auth.verification_key_fingerprint().value() != controller_fingerprint
        {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        let mut anchor = Digest32Builder::try_new(DISTRIBUTED_OWNER_ANCHOR_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        anchor
            .field_bytes(snapshot.store_instance_id())
            .and_then(|builder| builder.field_digest(&expected_owner_identity.value()))
            .and_then(|builder| builder.field_bytes(snapshot.state().scope().as_bytes()))
            .and_then(|builder| builder.field_bytes(snapshot.state().plan_lineage().as_bytes()))
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        Ok(DistributedCoordinatorContextV1 {
            store,
            owner_anchor: anchor.finish(),
            controller_signer,
        })
    }

    /// Owner-private DeveloperLocal PXNL facts for one distributed target.
    /// The bearer token remains zeroizing and never appears in Debug output.
    pub(crate) struct DistributedAgentStackOwnerNodeInputV1 {
        management_target: NodeManagementTargetV1,
        socket_path: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
        token: Zeroizing<[u8; 32]>,
        observation_endpoint_ref: RuntimeObservationEndpointRefV1,
        observation_socket_path: PathBuf,
        observation_token: Zeroizing<[u8; 32]>,
    }

    pub(crate) struct DistributedAgentStackOwnerNodeInputFieldsV1 {
        pub(crate) management_target: NodeManagementTargetV1,
        pub(crate) socket_path: PathBuf,
        pub(crate) expected_uid: u32,
        pub(crate) expected_gid: u32,
        pub(crate) token: Zeroizing<[u8; 32]>,
        pub(crate) observation_endpoint_ref: RuntimeObservationEndpointRefV1,
        pub(crate) observation_socket_path: PathBuf,
        pub(crate) observation_token: Zeroizing<[u8; 32]>,
    }

    impl DistributedAgentStackOwnerNodeInputV1 {
        pub(crate) fn new(fields: DistributedAgentStackOwnerNodeInputFieldsV1) -> Self {
            let DistributedAgentStackOwnerNodeInputFieldsV1 {
                management_target,
                socket_path,
                expected_uid,
                expected_gid,
                token,
                observation_endpoint_ref,
                observation_socket_path,
                observation_token,
            } = fields;
            Self {
                management_target,
                socket_path,
                expected_uid,
                expected_gid,
                token,
                observation_endpoint_ref,
                observation_socket_path,
                observation_token,
            }
        }
    }

    impl core::fmt::Debug for DistributedAgentStackOwnerNodeInputV1 {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("DistributedAgentStackOwnerNodeInputV1")
                .field("management_target", &self.management_target)
                .field("socket_path", &"<owner-private>")
                .field("expected_uid", &self.expected_uid)
                .field("expected_gid", &self.expected_gid)
                .field("token", &"<redacted>")
                .field("observation_endpoint_ref", &self.observation_endpoint_ref)
                .field("observation_socket_path", &"<owner-private>")
                .field("observation_token", &"<redacted>")
                .finish()
        }
    }

    /// Exact pre-start restricted Runtime carrier and its Controller connector
    /// resolution. The carrier is recomputed from durable predecessor and
    /// fresh Node facts before any send authority is created.
    pub(crate) struct DistributedAgentStackOwnerConnectorInputV1 {
        profile_ref: [u8; 16],
        transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
        root_ca_certificate_file: PathBuf,
        connector_certificate_file: PathBuf,
        connector_private_key_file: PathBuf,
    }

    impl DistributedAgentStackOwnerConnectorInputV1 {
        pub(crate) fn new(
            profile_ref: [u8; 16],
            transport_profile: RestrictedRuntimeApplyTransportProfileV1,
            expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
            root_ca_certificate_file: PathBuf,
            connector_certificate_file: PathBuf,
            connector_private_key_file: PathBuf,
        ) -> Self {
            Self {
                profile_ref,
                transport_profile,
                expected_carrier,
                root_ca_certificate_file,
                connector_certificate_file,
                connector_private_key_file,
            }
        }
    }

    pub(crate) struct DistributedAgentStackOwnerTargetInputV1 {
        topology: DistributedFabricTopologyV1,
        node: DistributedAgentStackOwnerNodeInputV1,
        connector: DistributedAgentStackOwnerConnectorInputV1,
        observation_authority: RuntimeObservationAuthorityV1,
        runtime_query_client: UnixRuntimeQueryClient,
    }

    impl DistributedAgentStackOwnerTargetInputV1 {
        pub(crate) fn new(
            topology: DistributedFabricTopologyV1,
            node: DistributedAgentStackOwnerNodeInputV1,
            connector: DistributedAgentStackOwnerConnectorInputV1,
            observation_authority: RuntimeObservationAuthorityV1,
            runtime_query_client: UnixRuntimeQueryClient,
        ) -> Self {
            Self {
                topology,
                node,
                connector,
                observation_authority,
                runtime_query_client,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum DistributedAgentStackOwnerApplyErrorV1 {
        Operation,
        PendingNotSent,
        TerminalNonReady,
        Uncertain,
        IndeterminateUncertain,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct DistributedAgentStackOwnerApplyOutcomeV1 {
        target_receipts: [Box<[u8]>; 2],
        replayed: bool,
    }

    impl DistributedAgentStackOwnerApplyOutcomeV1 {
        pub(crate) fn into_parts(self) -> ([Box<[u8]>; 2], bool) {
            (self.target_receipts, self.replayed)
        }
    }

    struct DistributedAgentStackOwnerTargetV1 {
        topology: DistributedFabricTopologyV1,
        node_target: DistributedAgentStackNodeTargetV1,
        node_endpoint: TrustedLocalNodeEndpointV1,
        connector: DistributedAgentStackOwnerConnectorInputV1,
        runtime_observation: Option<DistributedAgentStackOwnerRuntimeObservationV1>,
    }

    struct DistributedAgentStackOwnerRuntimeObservationV1 {
        authority: RuntimeObservationAuthorityV1,
        endpoint_ref: RuntimeObservationEndpointRefV1,
        endpoint: TrustedLocalRuntimeObservationEndpointV1,
        token: Zeroizing<[u8; 32]>,
        query_client: UnixRuntimeQueryClient,
    }

    struct DistributedAgentStackOwnerInputV1 {
        lifecycle: BoundedDuration,
        targets: [DistributedAgentStackOwnerTargetV1; 2],
    }

    struct DistributedAgentStackOwnerTerminalV1 {
        status: DistributedAgentStackRolloutStatusV1,
        target_receipts: [Box<[u8]>; 2],
        replayed: bool,
    }

    /// Completes the typed DeveloperLocal owner path without producing or
    /// consuming PXNC. The coordinator and predecessor tokens were sealed by
    /// Deployment during the prepare phase; only public Node carrier facts are
    /// supplied after the two Node daemons have started.
    pub(crate) fn run_developer_local_distributed_agent_stack_owner_v1(
        mut coordinator: DistributedCoordinatorContextV1,
        predecessors: [VerifiedDistributedAgentStackPredecessorV1; 2],
        lifecycle: BoundedDuration,
        targets: [DistributedAgentStackOwnerTargetInputV1; 2],
    ) -> Result<DistributedAgentStackOwnerApplyOutcomeV1, DistributedAgentStackOwnerApplyErrorV1>
    {
        validate_predecessor_pair([&predecessors[0], &predecessors[1]])
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        validate_distributed_coordinator_predecessors(&coordinator, &predecessors)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let owner_input = build_developer_local_distributed_owner_input(
            coordinator.owner_anchor,
            &predecessors,
            lifecycle,
            targets,
        )?;
        let existing =
            reopen_distributed_agent_stack_owner(&coordinator, &predecessors, &owner_input)
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if let Some(owner) = existing {
            validate_distributed_owner_configuration(&owner, &owner_input)
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        } else {
            initialize_distributed_agent_stack_owner(&mut coordinator, &predecessors, &owner_input)
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        }
        let terminal =
            apply_distributed_agent_stack_owner(coordinator, &predecessors, &owner_input)?;
        match terminal.status {
            DistributedAgentStackRolloutStatusV1::ActiveReady => {
                Ok(DistributedAgentStackOwnerApplyOutcomeV1 {
                    target_receipts: terminal.target_receipts,
                    replayed: terminal.replayed,
                })
            }
            DistributedAgentStackRolloutStatusV1::PendingNotSent => {
                Err(DistributedAgentStackOwnerApplyErrorV1::PendingNotSent)
            }
            DistributedAgentStackRolloutStatusV1::TerminalNonReady => {
                Err(DistributedAgentStackOwnerApplyErrorV1::TerminalNonReady)
            }
            DistributedAgentStackRolloutStatusV1::Uncertain => {
                Err(DistributedAgentStackOwnerApplyErrorV1::Uncertain)
            }
            DistributedAgentStackRolloutStatusV1::IndeterminateUncertain => {
                Err(DistributedAgentStackOwnerApplyErrorV1::IndeterminateUncertain)
            }
        }
    }

    fn build_developer_local_distributed_owner_input(
        owner_anchor: Digest32,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        lifecycle: BoundedDuration,
        targets: [DistributedAgentStackOwnerTargetInputV1; 2],
    ) -> Result<DistributedAgentStackOwnerInputV1, DistributedAgentStackOwnerApplyErrorV1> {
        if lifecycle.value() == 0 {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        let [first, second] = targets;
        if first.node.socket_path == first.node.observation_socket_path
            || first.node.socket_path == second.node.socket_path
            || first.node.socket_path == second.node.observation_socket_path
            || first.node.observation_socket_path == second.node.socket_path
            || first.node.observation_socket_path == second.node.observation_socket_path
            || second.node.socket_path == second.node.observation_socket_path
            || first.node.token.as_ref() == first.node.observation_token.as_ref()
            || first.node.token.as_ref() == second.node.token.as_ref()
            || first.node.token.as_ref() == second.node.observation_token.as_ref()
            || first.node.observation_token.as_ref() == second.node.token.as_ref()
            || first.node.observation_token.as_ref() == second.node.observation_token.as_ref()
            || second.node.token.as_ref() == second.node.observation_token.as_ref()
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        let targets = [
            build_developer_local_distributed_owner_target(
                owner_anchor,
                0,
                predecessors[0].target(),
                first,
            )?,
            build_developer_local_distributed_owner_target(
                owner_anchor,
                1,
                predecessors[1].target(),
                second,
            )?,
        ];
        let first_observation = targets[0]
            .runtime_observation
            .as_ref()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let second_observation = targets[1]
            .runtime_observation
            .as_ref()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if first_observation.endpoint_ref == second_observation.endpoint_ref
            || first_observation.token.as_ref() == second_observation.token.as_ref()
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        Ok(DistributedAgentStackOwnerInputV1 { lifecycle, targets })
    }

    fn build_developer_local_distributed_owner_target(
        owner_anchor: Digest32,
        index: usize,
        runtime_target: paraegox_kernel::identity::RuntimeHostId,
        input: DistributedAgentStackOwnerTargetInputV1,
    ) -> Result<DistributedAgentStackOwnerTargetV1, DistributedAgentStackOwnerApplyErrorV1> {
        let DistributedAgentStackOwnerTargetInputV1 {
            topology,
            node,
            connector,
            observation_authority,
            runtime_query_client,
        } = input;
        DistributedFabricTopologyV1::decode(runtime_target, topology.canonical_wire())
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let binding = developer_local_distributed_carrier_binding(
            owner_anchor,
            index,
            runtime_target,
            &node,
        )?;
        let node_target = DistributedAgentStackNodeTargetV1::try_new(
            runtime_target,
            node.management_target,
            binding,
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let node_endpoint = TrustedLocalNodeEndpointV1::try_new(
            node.socket_path.clone(),
            node.expected_uid,
            node.expected_gid,
            *node.token,
            binding,
            DISTRIBUTED_NODE_EXCHANGE_TIMEOUT,
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if observation_authority.runtime_host_id() != runtime_target
            || node.socket_path == node.observation_socket_path
            || node.token.as_ref() == node.observation_token.as_ref()
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        let observation_endpoint = TrustedLocalRuntimeObservationEndpointV1::try_new(
            node.observation_endpoint_ref,
            node.observation_socket_path,
            node.expected_uid,
            node.expected_gid,
            *node.observation_token,
            DISTRIBUTED_NODE_EXCHANGE_TIMEOUT,
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        Ok(DistributedAgentStackOwnerTargetV1 {
            topology,
            node_target,
            node_endpoint,
            connector,
            runtime_observation: Some(DistributedAgentStackOwnerRuntimeObservationV1 {
                authority: observation_authority,
                endpoint_ref: node.observation_endpoint_ref,
                endpoint: observation_endpoint,
                token: node.observation_token,
                query_client: runtime_query_client,
            }),
        })
    }

    fn developer_local_distributed_carrier_binding(
        owner_anchor: Digest32,
        index: usize,
        runtime_target: paraegox_kernel::identity::RuntimeHostId,
        node: &DistributedAgentStackOwnerNodeInputV1,
    ) -> Result<Digest32, DistributedAgentStackOwnerApplyErrorV1> {
        let index =
            u64::try_from(index).map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let mut builder = Digest32Builder::try_new(DISTRIBUTED_CARRIER_BINDING_DOMAIN)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        builder
            .field_digest(&owner_anchor)
            .and_then(|builder| builder.field_u64(index))
            .and_then(|builder| builder.field_bytes(runtime_target.as_bytes()))
            .and_then(|builder| builder.field_bytes(node.management_target.node_id().as_bytes()))
            .and_then(|builder| {
                builder.field_bytes(node.management_target.management_endpoint_ref().as_bytes())
            })
            .and_then(|builder| {
                builder.field_bytes(node.management_target.node_incarnation().as_bytes())
            })
            .and_then(|builder| builder.field_u64(node.management_target.registration_epoch()))
            .and_then(|builder| builder.field_bytes(node.socket_path.as_os_str().as_bytes()))
            .and_then(|builder| builder.field_u64(u64::from(node.expected_uid)))
            .and_then(|builder| builder.field_u64(u64::from(node.expected_gid)))
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        Ok(builder.finish())
    }

    enum StagedNodeObservationV1 {
        Response(Box<TransportAuthenticatedNodeResponseV1>),
        Disconnected(u64),
    }

    struct CurrentProcessObservationClockV1 {
        origin: MonotonicInstant,
        last: u64,
    }

    impl CurrentProcessObservationClockV1 {
        fn new() -> Self {
            Self {
                origin: MonotonicInstant::now(),
                last: 0,
            }
        }

        fn next(&mut self) -> u64 {
            let elapsed = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let minimum = self.last.saturating_add(1);
            let next = elapsed.max(minimum);
            self.last = next;
            next
        }
    }

    fn load_distributed_capability(
        capability_path: &Path,
    ) -> Result<DistributedLocalCapabilityV1, DeploymentdProcessError> {
        let expected_uid = geteuid().as_raw();
        let expected_gid = getegid().as_raw();
        validate_service_identity(expected_uid, expected_gid)?;
        let file = read_pinned_file(
            capability_path,
            FileLengthPolicy::BoundedNonZero(MAX_DISTRIBUTED_CAPABILITY_BYTES),
            FileRole::Capability,
            expected_uid,
            expected_gid,
        )?;
        let capability = DistributedLocalCapabilityV1::decode(&file.bytes)?;
        if capability.expected_uid != expected_uid || capability.expected_gid != expected_gid {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        Ok(capability)
    }

    fn open_distributed_coordinator(
        capability: &DistributedLocalCapabilityV1,
    ) -> Result<DistributedCoordinatorContextV1, DeploymentdProcessError> {
        let coordinator = &capability.coordinator;
        let public = read_pinned_file(
            &coordinator.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            capability.expected_uid,
            capability.expected_gid,
        )?;
        let seed_file = read_pinned_file(
            &coordinator.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            capability.expected_uid,
            capability.expected_gid,
        )?;
        if public.identity == seed_file.identity {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let public_bytes = exact_public_key(&public.bytes)?;
        let mut seed = Zeroizing::new([0_u8; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        if controller_signer.verifying_key().is_weak()
            || controller_signer.verifying_key().to_bytes() != public_bytes
        {
            return Err(process_error(ProcessErrorKind::Key));
        }
        let request_auth = request_auth_pin(&coordinator.common, &public.bytes)?;
        let owner_identity = owner_identity(&coordinator.common, request_auth.fingerprint)?;
        let store = ControllerStore::open(
            &coordinator.common.state_directory,
            coordinator.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let snapshot = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?;
        if snapshot.state().scope() != DeploymentScopeId::from_bytes(coordinator.common.scope)
            || snapshot.state().plan_lineage() != DeploymentId::from_bytes(coordinator.common.plan)
            || snapshot.state().request_auth() != request_auth.pin
        {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        let mut anchor = Digest32Builder::try_new(DISTRIBUTED_OWNER_ANCHOR_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        anchor
            .field_bytes(snapshot.store_instance_id())
            .and_then(|builder| builder.field_digest(&owner_identity.value()))
            .and_then(|builder| builder.field_bytes(coordinator.common.scope.as_slice()))
            .and_then(|builder| builder.field_bytes(coordinator.common.plan.as_slice()))
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        Ok(DistributedCoordinatorContextV1 {
            store,
            owner_anchor: anchor.finish(),
            controller_signer,
        })
    }

    fn load_verified_distributed_predecessors(
        capability: &DistributedLocalCapabilityV1,
    ) -> Result<
        (
            [VerifiedDistributedAgentStackPredecessorV1; 2],
            [DistributedFabricTopologyV1; 2],
        ),
        DeploymentdProcessError,
    > {
        let first = verify_distributed_predecessor(&capability.predecessors[0])?;
        let second = verify_distributed_predecessor(&capability.predecessors[1])?;
        validate_predecessor_pair([&first, &second])
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let first_topology = DistributedFabricTopologyV1::decode(
            first.target(),
            &capability.predecessors[0].node.topology_wire,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let second_topology = DistributedFabricTopologyV1::decode(
            second.target(),
            &capability.predecessors[1].node.topology_wire,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        Ok(([first, second], [first_topology, second_topology]))
    }

    fn validate_distributed_coordinator_predecessors(
        coordinator: &DistributedCoordinatorContextV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<(), DeploymentdProcessError> {
        let state = coordinator
            .store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state();
        let controller_verifying_key = coordinator.controller_signer.verifying_key().to_bytes();
        if predecessors.iter().any(|predecessor| {
            predecessor.source_scope().as_bytes() != state.scope().as_bytes()
                || predecessor.source_plan().as_bytes() != state.plan_lineage().as_bytes()
                || predecessor.request_key() != state.request_auth().key()
                || predecessor.controller_verifying_key() != &controller_verifying_key
        }) {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        Ok(())
    }

    fn reopen_distributed_agent_stack_owner(
        coordinator: &DistributedCoordinatorContextV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        input: &DistributedAgentStackOwnerInputV1,
    ) -> Result<Option<ControllerDistributedAgentStackOwnerStateV1>, DeploymentdProcessError> {
        let predecessor_refs = [&predecessors[0], &predecessors[1]];
        match (
            input.targets[0].runtime_observation.as_ref(),
            input.targets[1].runtime_observation.as_ref(),
        ) {
            (Some(first), Some(second)) => coordinator
                .store
                .reopen_distributed_agent_stack_with_runtime_observation(
                    coordinator.owner_anchor,
                    predecessor_refs,
                    [&first.authority, &second.authority],
                    [first.endpoint_ref, second.endpoint_ref],
                ),
            (None, None) => coordinator
                .store
                .reopen_distributed_agent_stack(coordinator.owner_anchor, predecessor_refs),
            _ => return Err(process_error(ProcessErrorKind::NodeDiscovery)),
        }
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))
    }

    fn verify_distributed_predecessor(
        capability: &DistributedPredecessorCapabilityV1,
    ) -> Result<VerifiedDistributedAgentStackPredecessorV1, DeploymentdProcessError> {
        let context = open_managed_agent_stack_context(capability.managed.clone())?;
        let base = VerifiedManagedFabricProducerContextV1::try_from_provisioning(
            context.store.state().legacy_snapshot().state(),
            &context.controller_signer,
            &context.provisioning,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let state = context
            .store
            .state()
            .agent_stack_state()
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        let predecessor =
            VerifiedDistributedAgentStackPredecessorV1::try_from_committed(&base, state)
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        if predecessor.target() != capability.expected_target {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        Ok(predecessor)
    }

    fn initialize_distributed_agent_stack_owner(
        coordinator: &mut DistributedCoordinatorContextV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        input: &DistributedAgentStackOwnerInputV1,
    ) -> Result<(), DeploymentdProcessError> {
        validate_distributed_coordinator_predecessors(coordinator, predecessors)?;
        if reopen_distributed_agent_stack_owner(coordinator, predecessors, input)?.is_some() {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        let entropy = read_exact_entropy::<DISTRIBUTED_ROLLOUT_ENTROPY_BYTES>(
            ProcessErrorKind::NodeDiscovery,
        )?;
        let rollout_id = DistributedAgentStackRolloutIdV1::try_from_bytes(
            entropy[0..16]
                .try_into()
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let first_fresh = distributed_fresh(&entropy[16..80], input.lifecycle)?;
        let second_fresh = distributed_fresh(&entropy[80..144], input.lifecycle)?;
        let predecessor_refs = [&predecessors[0], &predecessors[1]];
        let rollout = produce_distributed_agent_stack_rollout_v1(
            rollout_id,
            [
                DistributedAgentStackTargetRolloutInputV1::new(
                    predecessors[0].clone(),
                    input.targets[0].topology.clone(),
                    first_fresh,
                ),
                DistributedAgentStackTargetRolloutInputV1::new(
                    predecessors[1].clone(),
                    input.targets[1].topology.clone(),
                    second_fresh,
                ),
            ],
            &coordinator.controller_signer,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        journal
            .prepare_with(coordinator.owner_anchor, rollout, |_| Ok(()))
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let journal_wire = journal
            .durable_wire()
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        let node_state = DistributedAgentStackNodeDiscoveryStateV1::try_initialize(
            coordinator.owner_anchor,
            rollout_id,
            [
                input.targets[0].node_target.clone(),
                input.targets[1].node_target.clone(),
            ],
            predecessor_refs,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let node_wire = node_state
            .encode()
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        coordinator
            .store
            .commit_distributed_agent_stack_wires(journal_wire, &node_wire)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let expected_journal = journal_wire.to_vec();
        let reopened = reopen_distributed_agent_stack_owner(coordinator, predecessors, input)?
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        if reopened.apply_journal().durable_wire() != Some(expected_journal.as_slice())
            || reopened.node_discovery() != &node_state
        {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        validate_distributed_owner_configuration(&reopened, input)
    }

    fn validate_distributed_owner_configuration(
        owner: &ControllerDistributedAgentStackOwnerStateV1,
        input: &DistributedAgentStackOwnerInputV1,
    ) -> Result<(), DeploymentdProcessError> {
        let state = owner
            .apply_journal()
            .state()
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        let runtime_targets = owner.node_discovery().runtime_targets();
        for (index, row) in state.targets().iter().enumerate() {
            if row.target() != runtime_targets[index]
                || row.request().target_execution().topology()
                    != Some(&input.targets[index].topology)
                || row.restricted_request().is_some_and(|request| {
                    request.carrier() != &input.targets[index].connector.expected_carrier
                })
            {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
        }
        Ok(())
    }

    fn initialize_distributed_agent_stack(
        capability_path: PathBuf,
    ) -> Result<(), DeploymentdProcessError> {
        let capability = load_distributed_capability(&capability_path)?;
        let (predecessors, topologies) = load_verified_distributed_predecessors(&capability)?;
        let mut coordinator = open_distributed_coordinator(&capability)?;
        let owner_input =
            distributed_owner_input_from_capability(&capability, &predecessors, topologies)?;
        initialize_distributed_agent_stack_owner(&mut coordinator, &predecessors, &owner_input)?;
        std::io::stdout()
            .lock()
            .write_all(b"distributed_agent_stack_v1 outcome=initialized\n")
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn distributed_fresh(
        bytes: &[u8],
        lifecycle: BoundedDuration,
    ) -> Result<FreshDistributedAgentStackApplyV1, DeploymentdProcessError> {
        if bytes.len() != 64 {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        FreshDistributedAgentStackApplyV1::try_new(
            bytes[0..16]
                .try_into()
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
            bytes[16..32]
                .try_into()
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
            bytes[32..64]
                .try_into()
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
            lifecycle,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))
    }

    fn distributed_node_targets(
        capability: &DistributedLocalCapabilityV1,
    ) -> Result<[DistributedAgentStackNodeTargetV1; 2], DeploymentdProcessError> {
        Ok([
            distributed_node_target(capability, 0)?,
            distributed_node_target(capability, 1)?,
        ])
    }

    fn distributed_node_target(
        capability: &DistributedLocalCapabilityV1,
        index: usize,
    ) -> Result<DistributedAgentStackNodeTargetV1, DeploymentdProcessError> {
        let predecessor = capability
            .predecessors
            .get(index)
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        DistributedAgentStackNodeTargetV1::try_new(
            predecessor.expected_target,
            predecessor.node.management_target,
            distributed_carrier_binding(capability, index)?,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))
    }

    fn distributed_carrier_binding(
        capability: &DistributedLocalCapabilityV1,
        index: usize,
    ) -> Result<Digest32, DeploymentdProcessError> {
        let predecessor = capability
            .predecessors
            .get(index)
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        let index =
            u64::try_from(index).map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let mut builder = Digest32Builder::try_new(DISTRIBUTED_CARRIER_BINDING_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        builder
            .field_digest(&capability.checksum)
            .and_then(|builder| builder.field_u64(index))
            .and_then(|builder| builder.field_bytes(predecessor.expected_target.as_bytes()))
            .and_then(|builder| {
                builder.field_bytes(predecessor.node.management_target.node_id().as_bytes())
            })
            .and_then(|builder| {
                builder.field_bytes(
                    predecessor
                        .node
                        .management_target
                        .management_endpoint_ref()
                        .as_bytes(),
                )
            })
            .and_then(|builder| {
                builder.field_bytes(
                    predecessor
                        .node
                        .management_target
                        .node_incarnation()
                        .as_bytes(),
                )
            })
            .and_then(|builder| {
                builder.field_u64(predecessor.node.management_target.registration_epoch())
            })
            .and_then(|builder| {
                builder.field_bytes(predecessor.node.socket_path.as_os_str().as_bytes())
            })
            .and_then(|builder| builder.field_u64(u64::from(predecessor.node.expected_uid)))
            .and_then(|builder| builder.field_u64(u64::from(predecessor.node.expected_gid)))
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        Ok(builder.finish())
    }

    fn distributed_owner_input_from_capability(
        capability: &DistributedLocalCapabilityV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        topologies: [DistributedFabricTopologyV1; 2],
    ) -> Result<DistributedAgentStackOwnerInputV1, DeploymentdProcessError> {
        let [first_node_target, second_node_target] = distributed_node_targets(capability)?;
        let [first_node_endpoint, second_node_endpoint] = distributed_node_endpoints(capability)?;
        let connectors = capability.distributed_apply_connectors()?;
        let [first_topology, second_topology] = topologies;
        Ok(DistributedAgentStackOwnerInputV1 {
            lifecycle: BoundedDuration::from_nanos(capability.lifecycle_budget_nanos),
            targets: [
                DistributedAgentStackOwnerTargetV1 {
                    topology: first_topology,
                    node_target: first_node_target,
                    node_endpoint: first_node_endpoint,
                    connector: distributed_owner_connector_from_capability(
                        connectors[0],
                        &predecessors[0],
                    )?,
                    runtime_observation: None,
                },
                DistributedAgentStackOwnerTargetV1 {
                    topology: second_topology,
                    node_target: second_node_target,
                    node_endpoint: second_node_endpoint,
                    connector: distributed_owner_connector_from_capability(
                        connectors[1],
                        &predecessors[1],
                    )?,
                    runtime_observation: None,
                },
            ],
        })
    }

    fn distributed_owner_connector_from_capability(
        connector: &DistributedRestrictedControllerConnectorCapabilityV1,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    ) -> Result<DistributedAgentStackOwnerConnectorInputV1, DeploymentdProcessError> {
        let profile = &connector.transport_profile;
        if profile.target() != predecessor.target()
            || profile.controller_principal() != predecessor.controller_principal()
            || profile.runtime_principal() != predecessor.runtime_principal()
        {
            return Err(process_error(ProcessErrorKind::DistributedApply));
        }
        let expected_carrier = RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: predecessor.target(),
                runtime_principal: predecessor.runtime_principal(),
                controller_principal: predecessor.controller_principal(),
                endpoint_ref: profile.endpoint_ref(),
                endpoint_generation: profile.endpoint_generation(),
                route: profile.route(),
                controller_request_key: predecessor.request_key(),
                controller_request_key_fingerprint: ed25519_control_key_fingerprint(
                    predecessor.controller_verifying_key(),
                )
                .map_err(|_| process_error(ProcessErrorKind::DistributedApply))?,
                runtime_response_key: predecessor.runtime_response_key(),
                runtime_response_key_fingerprint: ed25519_control_key_fingerprint(
                    predecessor.runtime_response_public_key().as_bytes(),
                )
                .map_err(|_| process_error(ProcessErrorKind::DistributedApply))?,
                control_transport_profile_ref: connector.profile_ref,
                control_transport_profile_digest: profile.profile_digest(),
            },
        )
        .map_err(|_| process_error(ProcessErrorKind::DistributedApply))?;
        Ok(DistributedAgentStackOwnerConnectorInputV1 {
            profile_ref: connector.profile_ref,
            transport_profile: profile.clone(),
            expected_carrier,
            root_ca_certificate_file: connector.root_ca_certificate_file.clone(),
            connector_certificate_file: connector.connector_certificate_file.clone(),
            connector_private_key_file: connector.connector_private_key_file.clone(),
        })
    }

    fn observe_distributed_agent_stack_nodes_once(
        capability_path: PathBuf,
    ) -> Result<(), DeploymentdProcessError> {
        let capability = load_distributed_capability(&capability_path)?;
        let (predecessors, topologies) = load_verified_distributed_predecessors(&capability)?;
        let coordinator = open_distributed_coordinator(&capability)?;
        let owner_input =
            distributed_owner_input_from_capability(&capability, &predecessors, topologies)?;
        let observation = fresh_distributed_agent_stack_owner_observation(
            coordinator,
            &predecessors,
            &owner_input,
        )?;
        let outcome = if observation.ready_endpoints.is_some() {
            b"ready".as_slice()
        } else {
            b"blocked".as_slice()
        };
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(b"distributed_agent_stack_node_discovery_v1 outcome=")
            .and_then(|()| stdout.write_all(outcome))
            .and_then(|()| stdout.write_all(b"\n"))
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    struct FreshDistributedAgentStackNodeObservationV1 {
        coordinator: DistributedCoordinatorContextV1,
        owner: ControllerDistributedAgentStackOwnerStateV1,
        ready_endpoints: Option<[ReadyDistributedAgentStackRuntimeEndpointV1; 2]>,
        status_sequences: Option<[u64; 2]>,
    }

    fn fresh_distributed_agent_stack_owner_observation(
        mut coordinator: DistributedCoordinatorContextV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        input: &DistributedAgentStackOwnerInputV1,
    ) -> Result<FreshDistributedAgentStackNodeObservationV1, DeploymentdProcessError> {
        validate_distributed_coordinator_predecessors(&coordinator, predecessors)?;
        let owner = reopen_distributed_agent_stack_owner(&coordinator, predecessors, input)?
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        validate_distributed_owner_configuration(&owner, input)?;
        let journal_wire = owner
            .apply_journal()
            .durable_wire()
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?
            .to_vec();
        let durable_journal_before = journal_wire.clone();
        let entropy = read_exact_entropy::<DISTRIBUTED_OBSERVATION_ENTROPY_BYTES>(
            ProcessErrorKind::NodeDiscovery,
        )?;
        let generation = NodeObservationProcessGenerationV1::try_from_bytes(
            entropy[0..16]
                .try_into()
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let mut node_state = owner
            .node_discovery()
            .try_begin_observation_process(generation)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let targets = node_state.runtime_targets();
        let requests = [
            node_state
                .request_for(
                    targets[0],
                    entropy[16..32]
                        .try_into()
                        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
                )
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
            node_state
                .request_for(
                    targets[1],
                    entropy[32..48]
                        .try_into()
                        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
                )
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
        ];
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let mut clock = CurrentProcessObservationClockV1::new();
        let first = stage_node_observation(
            &runtime,
            &input.targets[0].node_endpoint,
            &requests[0],
            generation,
            &mut clock,
        )?;
        let second = stage_node_observation(
            &runtime,
            &input.targets[1].node_endpoint,
            &requests[1],
            generation,
            &mut clock,
        )?;
        drop(owner);

        for (target, request, staged) in [
            (targets[0], &requests[0], first),
            (targets[1], &requests[1], second),
        ] {
            node_state = match staged {
                StagedNodeObservationV1::Response(response) => {
                    node_state.try_observe_authenticated(target, request, *response)
                }
                StagedNodeObservationV1::Disconnected(observed_at_nanos) => {
                    node_state.try_observe_disconnect(target, generation, observed_at_nanos)
                }
            }
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
            let node_wire = node_state
                .encode()
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
            coordinator
                .store
                .commit_distributed_agent_stack_wires(&journal_wire, &node_wire)
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        }
        let persisted_journal = coordinator
            .store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .distributed_agent_stack_journal_wire()
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        if persisted_journal != durable_journal_before {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        let verified = reopen_distributed_agent_stack_owner(&coordinator, predecessors, input)?
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
        validate_distributed_owner_configuration(&verified, input)?;
        if verified.apply_journal().durable_wire() != Some(durable_journal_before.as_slice()) {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        let qualified = verified
            .node_discovery()
            .try_qualify_verified_reopen(&node_state)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let ready_endpoints = qualified
            .ready_endpoints(
                clock.next(),
                current_unix_nanos()?,
                [&predecessors[0], &predecessors[1]],
            )
            .ok();
        let status_sequences = match (
            qualified.current_authenticated_status_sequence(targets[0]),
            qualified.current_authenticated_status_sequence(targets[1]),
        ) {
            (Ok(first), Ok(second)) => Some([first, second]),
            _ => None,
        };
        Ok(FreshDistributedAgentStackNodeObservationV1 {
            coordinator,
            owner: verified,
            ready_endpoints,
            status_sequences,
        })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DistributedRuntimeObservationStageV1 {
        Complete,
        NotSent,
        Uncertain,
        Rejected,
    }

    /// Advances only the durable request/response/publication chain. Fresh
    /// PXQR authority exists solely between the pair commit readback and this
    /// function's two one-shot Runtime exchanges; a reopened request-only row
    /// is closed as ResidentAuthorityLost and is never reconstructed.
    fn advance_distributed_runtime_observation_chain(
        mut coordinator: DistributedCoordinatorContextV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        input: &DistributedAgentStackOwnerInputV1,
        authenticated_status_sequences: [u64; 2],
    ) -> Result<DistributedCoordinatorContextV1, DistributedAgentStackOwnerApplyErrorV1> {
        let first_observation = input.targets[0]
            .runtime_observation
            .as_ref()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::PendingNotSent)?;
        let second_observation = input.targets[1]
            .runtime_observation
            .as_ref()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::PendingNotSent)?;
        let predecessor_refs = [&predecessors[0], &predecessors[1]];
        let authority_refs = [&first_observation.authority, &second_observation.authority];
        let endpoint_refs = [
            first_observation.endpoint_ref,
            second_observation.endpoint_ref,
        ];

        let mut owner = reopen_distributed_agent_stack_owner(&coordinator, predecessors, input)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let targets = owner.node_discovery().runtime_targets();
        if let Some(phases) = owner.node_discovery().runtime_query_phases() {
            let mut resident_authority_was_lost = false;
            for index in 0..2 {
                if phases[index] == DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent
                {
                    coordinator
                        .store
                        .commit_distributed_runtime_query_closure(
                            targets[index],
                            DistributedAgentStackRuntimeQueryPhaseV1::ResidentAuthorityLost,
                            coordinator.owner_anchor,
                            predecessor_refs,
                            authority_refs,
                            endpoint_refs,
                        )
                        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
                    resident_authority_was_lost = true;
                }
            }
            if resident_authority_was_lost {
                return Err(DistributedAgentStackOwnerApplyErrorV1::PendingNotSent);
            }
            owner = reopen_distributed_agent_stack_owner(&coordinator, predecessors, input)
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?
                .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        }

        let append_fresh_pair = owner
            .node_discovery()
            .runtime_query_phases()
            .is_none_or(|phases| phases.into_iter().all(runtime_query_phase_is_closed));
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if append_fresh_pair {
            let entropy = read_exact_entropy::<DISTRIBUTED_RUNTIME_QUERY_ENTROPY_BYTES>(
                ProcessErrorKind::NodeDiscovery,
            )
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
            let issued_at = current_unix_nanos()
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
            let freshness_budget =
                MAX_RUNTIME_OBSERVATION_CHALLENGE_NANOS.min(MAX_NODE_STATUS_FRESHNESS_NANOS);
            let expires_at = issued_at
                .checked_add(freshness_budget)
                .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
            let intended_sequences = [
                authenticated_status_sequences[0]
                    .checked_add(1)
                    .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?,
                authenticated_status_sequences[1]
                    .checked_add(1)
                    .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?,
            ];
            let inputs = [
                build_distributed_runtime_query_input(DistributedRuntimeQueryBuildInputV1 {
                    signer: &coordinator.controller_signer,
                    predecessor: &predecessors[0],
                    node_target: input.targets[0].node_target.management_target(),
                    observation: first_observation,
                    intended_status_sequence: intended_sequences[0],
                    query_id: entropy[..16]
                        .try_into()
                        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?,
                    issued_at_unix_nanos: issued_at,
                    expires_at_unix_nanos: expires_at,
                    freshness_budget_nanos: freshness_budget,
                })?,
                build_distributed_runtime_query_input(DistributedRuntimeQueryBuildInputV1 {
                    signer: &coordinator.controller_signer,
                    predecessor: &predecessors[1],
                    node_target: input.targets[1].node_target.management_target(),
                    observation: second_observation,
                    intended_status_sequence: intended_sequences[1],
                    query_id: entropy[16..]
                        .try_into()
                        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?,
                    issued_at_unix_nanos: issued_at,
                    expires_at_unix_nanos: expires_at,
                    freshness_budget_nanos: freshness_budget,
                })?,
            ];
            let next = owner
                .node_discovery()
                .try_prepare_runtime_query_pair(inputs)
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
            drop(owner);
            let committed = coordinator
                .store
                .commit_distributed_runtime_query_pair(
                    &next,
                    predecessor_refs,
                    authority_refs,
                    endpoint_refs,
                )
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
            let [first_query, second_query] = coordinator
                .store
                .claim_distributed_runtime_query_pair(
                    committed,
                    coordinator.owner_anchor,
                    predecessor_refs,
                    authority_refs,
                    endpoint_refs,
                )
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
            let _first_stage = exchange_distributed_runtime_query_once(
                &runtime,
                &mut coordinator,
                predecessors,
                input,
                0,
                first_query,
            )?;
            let _second_stage = exchange_distributed_runtime_query_once(
                &runtime,
                &mut coordinator,
                predecessors,
                input,
                1,
                second_query,
            )?;
        } else {
            drop(owner);
        }

        let mut stages = [DistributedRuntimeObservationStageV1::Complete; 2];
        for (index, stage) in stages.iter_mut().enumerate() {
            let publication = advance_distributed_runtime_observation_once(
                &runtime,
                &mut coordinator,
                predecessors,
                input,
                index,
            )?;
            *stage = publication;
        }
        if stages
            .iter()
            .copied()
            .any(|stage| stage == DistributedRuntimeObservationStageV1::Uncertain)
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Uncertain);
        }
        if stages
            .iter()
            .copied()
            .any(|stage| stage != DistributedRuntimeObservationStageV1::Complete)
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::PendingNotSent);
        }
        Ok(coordinator)
    }

    fn runtime_query_phase_is_closed(phase: DistributedAgentStackRuntimeQueryPhaseV1) -> bool {
        phase == DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable
            || phase.is_terminal_failure()
    }

    fn stage_from_runtime_query_phase(
        phase: DistributedAgentStackRuntimeQueryPhaseV1,
    ) -> DistributedRuntimeObservationStageV1 {
        match phase {
            DistributedAgentStackRuntimeQueryPhaseV1::QueryUncertain
            | DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain => {
                DistributedRuntimeObservationStageV1::Uncertain
            }
            DistributedAgentStackRuntimeQueryPhaseV1::QueryRejected
            | DistributedAgentStackRuntimeQueryPhaseV1::ObservationRejected => {
                DistributedRuntimeObservationStageV1::Rejected
            }
            DistributedAgentStackRuntimeQueryPhaseV1::ResidentAuthorityLost
            | DistributedAgentStackRuntimeQueryPhaseV1::QueryNotSent
            | DistributedAgentStackRuntimeQueryPhaseV1::ObservationNotSent => {
                DistributedRuntimeObservationStageV1::NotSent
            }
            _ => DistributedRuntimeObservationStageV1::Complete,
        }
    }

    struct DistributedRuntimeQueryBuildInputV1<'a> {
        signer: &'a SigningKey,
        predecessor: &'a VerifiedDistributedAgentStackPredecessorV1,
        node_target: NodeManagementTargetV1,
        observation: &'a DistributedAgentStackOwnerRuntimeObservationV1,
        intended_status_sequence: u64,
        query_id: [u8; 16],
        issued_at_unix_nanos: u64,
        expires_at_unix_nanos: u64,
        freshness_budget_nanos: u64,
    }

    fn build_distributed_runtime_query_input(
        input: DistributedRuntimeQueryBuildInputV1<'_>,
    ) -> Result<DistributedAgentStackRuntimeQueryInputV1, DistributedAgentStackOwnerApplyErrorV1>
    {
        let DistributedRuntimeQueryBuildInputV1 {
            signer,
            predecessor,
            node_target,
            observation,
            intended_status_sequence,
            query_id,
            issued_at_unix_nanos,
            expires_at_unix_nanos,
            freshness_budget_nanos,
        } = input;
        let nonce = derive_runtime_observation_query_nonce_v1(
            &observation.token,
            node_target,
            observation.endpoint_ref,
            &observation.authority,
            intended_status_sequence,
            issued_at_unix_nanos,
            expires_at_unix_nanos,
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let challenge =
            NodeControlObservationChallengeV1::try_new(NodeControlObservationChallengeFieldsV1 {
                observation_endpoint_ref: observation.endpoint_ref,
                runtime_host_id: predecessor.target(),
                authority_digest: observation.authority.authority_digest(),
                intended_status_sequence,
                freshness_budget_nanos,
                issued_at_unix_nanos,
                expires_at_unix_nanos,
                query_nonce: nonce,
            })
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let selector = ReferenceQuerySelectorV1::try_new(
            ReferenceQueryIdV1::from_bytes(query_id),
            predecessor.target(),
            predecessor.source_scope(),
            predecessor.request().expected_runtime_store_instance_id(),
            predecessor.request().operation_id(),
            Some(predecessor.request().envelope_request_digest()),
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let claim = ApplyRequestAuthClaim::try_new(
            predecessor.controller_principal(),
            predecessor.request_key(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?,
            ED25519_ALGORITHM_VERSION,
            challenge.query_nonce().as_bytes(),
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let draft = ReferenceQueryRequestDraftV1::try_new(
            selector,
            claim,
            u32::try_from(MAX_REFERENCE_QUERY_RESPONSE_BYTES)
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?,
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let signature = signer.sign(
            draft
                .signing_transcript()
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?
                .as_bytes(),
        );
        let request = draft
            .finalize(&signature.to_bytes())
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        DistributedAgentStackRuntimeQueryInputV1::try_new(
            request,
            observation.authority.serving_baseline(),
            challenge,
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)
    }

    fn exchange_distributed_runtime_query_once(
        runtime: &tokio::runtime::Runtime,
        coordinator: &mut DistributedCoordinatorContextV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        input: &DistributedAgentStackOwnerInputV1,
        index: usize,
        prepared: crate::runtime_control_client::PreparedRuntimeQueryRequest,
    ) -> Result<DistributedRuntimeObservationStageV1, DistributedAgentStackOwnerApplyErrorV1> {
        let observation = input.targets[index]
            .runtime_observation
            .as_ref()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let other = input.targets[1 - index]
            .runtime_observation
            .as_ref()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let authorities = if index == 0 {
            [&observation.authority, &other.authority]
        } else {
            [&other.authority, &observation.authority]
        };
        let endpoint_refs = if index == 0 {
            [observation.endpoint_ref, other.endpoint_ref]
        } else {
            [other.endpoint_ref, observation.endpoint_ref]
        };
        let target = predecessors[index].target();
        match runtime.block_on(observation.query_client.exchange(prepared)) {
            Ok(validated) => {
                coordinator
                    .store
                    .commit_distributed_runtime_query_response(
                        target,
                        validated.response().clone(),
                        coordinator.owner_anchor,
                        [&predecessors[0], &predecessors[1]],
                        authorities,
                        endpoint_refs,
                    )
                    .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
                Ok(DistributedRuntimeObservationStageV1::Complete)
            }
            Err(error) => {
                let (phase, stage) = match error {
                    RuntimeQueryExchangeError::NotSent(_) => (
                        DistributedAgentStackRuntimeQueryPhaseV1::QueryNotSent,
                        DistributedRuntimeObservationStageV1::NotSent,
                    ),
                    RuntimeQueryExchangeError::Uncertain(_) => (
                        DistributedAgentStackRuntimeQueryPhaseV1::QueryUncertain,
                        DistributedRuntimeObservationStageV1::Uncertain,
                    ),
                    RuntimeQueryExchangeError::Rejected(_) => (
                        DistributedAgentStackRuntimeQueryPhaseV1::QueryRejected,
                        DistributedRuntimeObservationStageV1::Rejected,
                    ),
                };
                coordinator
                    .store
                    .commit_distributed_runtime_query_closure(
                        target,
                        phase,
                        coordinator.owner_anchor,
                        [&predecessors[0], &predecessors[1]],
                        authorities,
                        endpoint_refs,
                    )
                    .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
                Ok(stage)
            }
        }
    }

    fn advance_distributed_runtime_observation_once(
        runtime: &tokio::runtime::Runtime,
        coordinator: &mut DistributedCoordinatorContextV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        input: &DistributedAgentStackOwnerInputV1,
        index: usize,
    ) -> Result<DistributedRuntimeObservationStageV1, DistributedAgentStackOwnerApplyErrorV1> {
        let observation = input.targets[index]
            .runtime_observation
            .as_ref()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let other = input.targets[1 - index]
            .runtime_observation
            .as_ref()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let authorities = if index == 0 {
            [&observation.authority, &other.authority]
        } else {
            [&other.authority, &observation.authority]
        };
        let endpoint_refs = if index == 0 {
            [observation.endpoint_ref, other.endpoint_ref]
        } else {
            [other.endpoint_ref, observation.endpoint_ref]
        };
        let owner = reopen_distributed_agent_stack_owner(coordinator, predecessors, input)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let target = predecessors[index].target();
        let phase = owner
            .node_discovery()
            .runtime_query_phase(target)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let prepared = match phase {
            DistributedAgentStackRuntimeQueryPhaseV1::ResponseDurable => {
                let next = owner
                    .node_discovery()
                    .try_prepare_runtime_observation(target)
                    .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
                drop(owner);
                coordinator
                    .store
                    .commit_distributed_runtime_observation(
                        &next,
                        target,
                        [&predecessors[0], &predecessors[1]],
                        authorities,
                        endpoint_refs,
                    )
                    .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?
            }
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent
            | DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain => {
                drop(owner);
                coordinator
                    .store
                    .recover_distributed_runtime_observation(
                        coordinator.owner_anchor,
                        target,
                        [&predecessors[0], &predecessors[1]],
                        authorities,
                        endpoint_refs,
                    )
                    .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?
            }
            _ => return Ok(stage_from_runtime_query_phase(phase)),
        };
        let claimed = coordinator
            .store
            .claim_distributed_runtime_observation(
                prepared,
                coordinator.owner_anchor,
                [&predecessors[0], &predecessors[1]],
                authorities,
                endpoint_refs,
            )
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let completed = runtime.block_on(observation.endpoint.exchange(claimed));
        let disposition = completed
            .commit_into(
                &mut coordinator.store,
                coordinator.owner_anchor,
                [&predecessors[0], &predecessors[1]],
                authorities,
                endpoint_refs,
            )
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        Ok(match disposition {
            DistributedRuntimeObservationCommitDispositionV1::AckDurable => {
                DistributedRuntimeObservationStageV1::Complete
            }
            DistributedRuntimeObservationCommitDispositionV1::NotSent => {
                DistributedRuntimeObservationStageV1::NotSent
            }
            DistributedRuntimeObservationCommitDispositionV1::Uncertain => {
                DistributedRuntimeObservationStageV1::Uncertain
            }
            DistributedRuntimeObservationCommitDispositionV1::Rejected => {
                DistributedRuntimeObservationStageV1::Rejected
            }
        })
    }

    fn apply_distributed_agent_stack_owner(
        coordinator: DistributedCoordinatorContextV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        input: &DistributedAgentStackOwnerInputV1,
    ) -> Result<DistributedAgentStackOwnerTerminalV1, DistributedAgentStackOwnerApplyErrorV1> {
        validate_distributed_coordinator_predecessors(&coordinator, predecessors)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let owner = reopen_distributed_agent_stack_owner(&coordinator, predecessors, input)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        validate_distributed_owner_configuration(&owner, input)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        match owner.apply_journal().status() {
            Some(DistributedAgentStackRolloutStatusV1::PendingNotSent) => {}
            Some(
                DistributedAgentStackRolloutStatusV1::TerminalNonReady
                | DistributedAgentStackRolloutStatusV1::ActiveReady,
            ) => return distributed_owner_terminal_from_reopen(&owner, predecessors, input, true),
            Some(DistributedAgentStackRolloutStatusV1::Uncertain) => {
                return Err(DistributedAgentStackOwnerApplyErrorV1::Uncertain);
            }
            Some(DistributedAgentStackRolloutStatusV1::IndeterminateUncertain) => {
                return Err(DistributedAgentStackOwnerApplyErrorV1::IndeterminateUncertain);
            }
            None => return Err(DistributedAgentStackOwnerApplyErrorV1::Operation),
        }
        drop(owner);

        // Reopen through the same verified owner seam after the current-process
        // Node observation. This path never rehydrates from caller bytes.
        // The coordinator value itself is moved into the observation helper.
        let FreshDistributedAgentStackNodeObservationV1 {
            mut coordinator,
            mut owner,
            mut ready_endpoints,
            status_sequences,
        } = fresh_distributed_agent_stack_owner_observation(coordinator, predecessors, input)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if owner.apply_journal().status()
            != Some(DistributedAgentStackRolloutStatusV1::PendingNotSent)
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        if ready_endpoints.is_none()
            || !owner.node_discovery().runtime_observation_pair_is_durable()
        {
            let status_sequences =
                status_sequences.ok_or(DistributedAgentStackOwnerApplyErrorV1::PendingNotSent)?;
            drop(owner);
            coordinator = advance_distributed_runtime_observation_chain(
                coordinator,
                predecessors,
                input,
                status_sequences,
            )?;
            let refreshed =
                fresh_distributed_agent_stack_owner_observation(coordinator, predecessors, input)
                    .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
            coordinator = refreshed.coordinator;
            owner = refreshed.owner;
            ready_endpoints = refreshed.ready_endpoints;
        }
        if owner.apply_journal().status()
            != Some(DistributedAgentStackRolloutStatusV1::PendingNotSent)
            || !owner.node_discovery().runtime_observation_pair_is_durable()
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        let ready_endpoints =
            ready_endpoints.ok_or(DistributedAgentStackOwnerApplyErrorV1::PendingNotSent)?;
        let carriers = [
            distributed_owner_restricted_apply_carrier(
                &ready_endpoints[0],
                &input.targets[0].connector,
                &predecessors[0],
            )?,
            distributed_owner_restricted_apply_carrier(
                &ready_endpoints[1],
                &input.targets[1].connector,
                &predecessors[1],
            )?,
        ];
        let node_wire = owner
            .node_discovery()
            .encode()
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let targets = owner.node_discovery().runtime_targets();
        let prepared_targets = [
            owner
                .apply_journal()
                .prepared_target(targets[0])
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?,
            owner
                .apply_journal()
                .prepared_target(targets[1])
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?,
        ];
        let prepared_pair = owner
            .apply_journal()
            .prepare_restricted_pair_for_preflight(
                prepared_targets,
                carriers,
                [&predecessors[0], &predecessors[1]],
                &coordinator.controller_signer,
            )
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let connector_inputs = [
            distributed_owner_restricted_connector_input(&input.targets[0].connector)?,
            distributed_owner_restricted_connector_input(&input.targets[1].connector)?,
        ];
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let (dispatch_outcomes, cleanup_failed) = {
            let (journal, _) = owner.parts_mut();
            match runtime.block_on(journal.start_dispatch_and_shutdown_restricted_pair_with(
                prepared_pair,
                connector_inputs,
                |journal_wire| {
                    coordinator
                        .store
                        .commit_distributed_agent_stack_wires(journal_wire, &node_wire)
                        .map_err(|_| DistributedAgentStackStoreError::DurabilityRejected)
                },
            )) {
                Ok(outcomes) => (outcomes, false),
                Err(error) => match error.into_shutdown_after_dispatch_parts() {
                    Ok((outcomes, _shutdown_results)) => (outcomes, true),
                    Err(_) => return Err(DistributedAgentStackOwnerApplyErrorV1::Operation),
                },
            }
        };
        let terminal_outcomes = {
            let (journal, _) = owner.parts_mut();
            journal.consume_restricted_dispatch_pair_with(
                dispatch_outcomes,
                [&predecessors[0], &predecessors[1]],
                |_target, journal_wire| {
                    coordinator
                        .store
                        .commit_distributed_agent_stack_wires(journal_wire, &node_wire)
                        .map_err(|_| DistributedAgentStackStoreError::DurabilityRejected)
                },
            )
        };
        let [first, second] = terminal_outcomes;
        let first = first
            .into_terminal_result()
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let second = second
            .into_terminal_result()
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if first.target() != targets[0]
            || second.target() != targets[1]
            || first.rollout_status() != second.rollout_status()
            || !matches!(
                second.rollout_status(),
                DistributedAgentStackRolloutStatusV1::TerminalNonReady
                    | DistributedAgentStackRolloutStatusV1::ActiveReady
            )
            || cleanup_failed
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        drop(owner);
        let reopened = reopen_distributed_agent_stack_owner(&coordinator, predecessors, input)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        validate_distributed_owner_configuration(&reopened, input)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        distributed_owner_terminal_from_reopen(&reopened, predecessors, input, false)
    }

    fn distributed_owner_terminal_from_reopen(
        owner: &ControllerDistributedAgentStackOwnerStateV1,
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
        input: &DistributedAgentStackOwnerInputV1,
        replayed: bool,
    ) -> Result<DistributedAgentStackOwnerTerminalV1, DistributedAgentStackOwnerApplyErrorV1> {
        validate_distributed_owner_configuration(owner, input)
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let status = owner
            .apply_journal()
            .status()
            .ok_or(DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if !matches!(
            status,
            DistributedAgentStackRolloutStatusV1::TerminalNonReady
                | DistributedAgentStackRolloutStatusV1::ActiveReady
        ) || !distributed_owner_terminal_runtime_observation_is_admissible(
            status,
            owner.node_discovery().runtime_observation_pair_is_durable(),
        ) {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        let targets = owner.node_discovery().runtime_targets();
        let first = owner
            .apply_journal()
            .restricted_terminal_replay(targets[0])
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let second = owner
            .apply_journal()
            .restricted_terminal_replay(targets[1])
            .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if targets != [predecessors[0].target(), predecessors[1].target()]
            || first.target() != targets[0]
            || second.target() != targets[1]
            || first.rollout_status() != status
            || second.rollout_status() != status
            || !first.replayed_from_durable_state()
            || !second.replayed_from_durable_state()
            || status == DistributedAgentStackRolloutStatusV1::ActiveReady
                && (first.outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady
                    || second.outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady)
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        Ok(DistributedAgentStackOwnerTerminalV1 {
            status,
            target_receipts: [
                first.canonical_receipt_bytes().into(),
                second.canonical_receipt_bytes().into(),
            ],
            replayed,
        })
    }

    fn distributed_owner_terminal_runtime_observation_is_admissible(
        status: DistributedAgentStackRolloutStatusV1,
        runtime_observation_pair_is_durable: bool,
    ) -> bool {
        status != DistributedAgentStackRolloutStatusV1::ActiveReady
            || runtime_observation_pair_is_durable
    }

    fn distributed_owner_restricted_apply_carrier(
        ready: &ReadyDistributedAgentStackRuntimeEndpointV1,
        connector: &DistributedAgentStackOwnerConnectorInputV1,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    ) -> Result<RestrictedRuntimeApplyCarrierBindingV1, DistributedAgentStackOwnerApplyErrorV1>
    {
        let endpoint = ready.endpoint();
        let endpoint_ref = *endpoint.endpoint_ref().as_bytes();
        if ready.runtime_target() != predecessor.target()
            || endpoint.runtime_host_id() != predecessor.target()
            || connector.transport_profile.target() != ready.runtime_target()
            || connector.transport_profile.endpoint_ref() != endpoint_ref
            || connector.transport_profile.endpoint_generation() != endpoint.endpoint_generation()
            || connector.transport_profile.route() != ready.route()
            || connector.transport_profile.controller_principal()
                != predecessor.controller_principal()
            || connector.transport_profile.runtime_principal() != predecessor.runtime_principal()
            || ApplyAuthKeyRef::from_bytes(endpoint.runtime_response_key_ref())
                != predecessor.runtime_response_key()
        {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        let controller_request_key_fingerprint =
            ed25519_control_key_fingerprint(predecessor.controller_verifying_key())
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let runtime_response_key_fingerprint =
            ed25519_control_key_fingerprint(&endpoint.runtime_response_public_key())
                .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: ready.runtime_target(),
                runtime_principal: predecessor.runtime_principal(),
                controller_principal: predecessor.controller_principal(),
                endpoint_ref,
                endpoint_generation: endpoint.endpoint_generation(),
                route: ready.route(),
                controller_request_key: predecessor.request_key(),
                controller_request_key_fingerprint,
                runtime_response_key: predecessor.runtime_response_key(),
                runtime_response_key_fingerprint,
                control_transport_profile_ref: connector.profile_ref,
                control_transport_profile_digest: connector.transport_profile.profile_digest(),
            },
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        if carrier != connector.expected_carrier {
            return Err(DistributedAgentStackOwnerApplyErrorV1::Operation);
        }
        Ok(carrier)
    }

    fn distributed_owner_restricted_connector_input(
        connector: &DistributedAgentStackOwnerConnectorInputV1,
    ) -> Result<
        (
            [u8; 16],
            RestrictedRuntimeApplyTransportProfileV1,
            PathBuf,
            ResolvedRemoteMtlsIdentityFiles,
        ),
        DistributedAgentStackOwnerApplyErrorV1,
    > {
        let identity = ResolvedRemoteMtlsIdentityFiles::try_new(
            connector.connector_certificate_file.clone(),
            connector.connector_private_key_file.clone(),
        )
        .map_err(|_| DistributedAgentStackOwnerApplyErrorV1::Operation)?;
        Ok((
            connector.profile_ref,
            connector.transport_profile.clone(),
            connector.root_ca_certificate_file.clone(),
            identity,
        ))
    }

    fn apply_distributed_agent_stack_once(
        capability_path: PathBuf,
    ) -> Result<(), DeploymentdProcessError> {
        let capability = load_distributed_capability(&capability_path)
            .map_err(|_| process_error(ProcessErrorKind::DistributedApply))?;
        let (predecessors, topologies) = load_verified_distributed_predecessors(&capability)
            .map_err(|_| process_error(ProcessErrorKind::DistributedApply))?;
        let coordinator = open_distributed_coordinator(&capability)
            .map_err(|_| process_error(ProcessErrorKind::DistributedApply))?;
        let owner_input =
            distributed_owner_input_from_capability(&capability, &predecessors, topologies)
                .map_err(|_| process_error(ProcessErrorKind::DistributedApply))?;
        let terminal =
            apply_distributed_agent_stack_owner(coordinator, &predecessors, &owner_input)
                .map_err(|_| process_error(ProcessErrorKind::DistributedApply))?;
        write_distributed_agent_stack_apply_outcome(terminal.status, terminal.replayed)
    }

    fn write_distributed_agent_stack_apply_outcome(
        status: DistributedAgentStackRolloutStatusV1,
        replayed: bool,
    ) -> Result<(), DeploymentdProcessError> {
        let outcome = match status {
            DistributedAgentStackRolloutStatusV1::TerminalNonReady => "terminal_non_ready",
            DistributedAgentStackRolloutStatusV1::ActiveReady => "active_ready",
            _ => return Err(process_error(ProcessErrorKind::DistributedApply)),
        };
        writeln!(
            std::io::stdout().lock(),
            "distributed_agent_stack_apply_v1 outcome={outcome} replayed={replayed}"
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn distributed_node_endpoints(
        capability: &DistributedLocalCapabilityV1,
    ) -> Result<[TrustedLocalNodeEndpointV1; 2], DeploymentdProcessError> {
        Ok([
            distributed_node_endpoint(capability, 0)?,
            distributed_node_endpoint(capability, 1)?,
        ])
    }

    fn distributed_node_endpoint(
        capability: &DistributedLocalCapabilityV1,
        index: usize,
    ) -> Result<TrustedLocalNodeEndpointV1, DeploymentdProcessError> {
        let node = &capability
            .predecessors
            .get(index)
            .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?
            .node;
        TrustedLocalNodeEndpointV1::try_new(
            node.socket_path.clone(),
            node.expected_uid,
            node.expected_gid,
            *node.token,
            distributed_carrier_binding(capability, index)?,
            DISTRIBUTED_NODE_EXCHANGE_TIMEOUT,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))
    }

    fn stage_node_observation(
        runtime: &tokio::runtime::Runtime,
        endpoint: &TrustedLocalNodeEndpointV1,
        request: &NodeManagementRequestV1,
        generation: NodeObservationProcessGenerationV1,
        clock: &mut CurrentProcessObservationClockV1,
    ) -> Result<StagedNodeObservationV1, DeploymentdProcessError> {
        match runtime.block_on(endpoint.exchange(request, generation, || clock.next())) {
            Ok(response) => Ok(StagedNodeObservationV1::Response(Box::new(response))),
            Err(TrustedLocalNodeClientErrorV1::Disconnected) => {
                Ok(StagedNodeObservationV1::Disconnected(clock.next()))
            }
            Err(_) => Err(process_error(ProcessErrorKind::NodeDiscovery)),
        }
    }

    fn current_unix_nanos() -> Result<u64, DeploymentdProcessError> {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?
                .as_nanos(),
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))
    }

    fn read_exact_entropy<const N: usize>(
        kind: ProcessErrorKind,
    ) -> Result<[u8; N], DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(kind))?;
        let mut source = File::from(owned);
        let mut entropy = [0_u8; N];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(kind))?;
        Ok(entropy)
    }

    fn commit_agent_stack(
        arguments: AgentStackCommitArguments,
    ) -> Result<(), DeploymentdProcessError> {
        let agent = build_agent_service_plan(&arguments)?;
        let ManagedAgentStackProcessContext {
            mut store,
            controller_signer,
            provisioning,
            client: _,
        } = open_managed_agent_stack_context(arguments.managed)?;
        let expected_fabric = store
            .state()
            .desired()
            .ok_or_else(|| process_error(ProcessErrorKind::AgentStack))?
            .execution()
            .clone();
        let activation = ManagedAgentStackActivationV1::try_new(expected_fabric, agent)
            .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let fresh = fresh_managed_agent_stack_request()?;
        let mut journal = ManagedAgentStackApplyJournalV1::new(store.state().clone());
        {
            let mut durable = ManagedAgentStackDurableStoreV1::try_new(&mut store)
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
            journal
                .prepare_activate_with(
                    &controller_signer,
                    &provisioning,
                    &activation,
                    fresh,
                    |next| durable.commit(next),
                )
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        }
        let stack = journal
            .state()
            .agent_stack_state()
            .ok_or_else(|| process_error(ProcessErrorKind::AgentStack))?;
        write_agent_stack_prepared(stack.request().envelope_request_digest())
    }

    fn apply_agent_stack(
        arguments: ManagedServingArguments,
    ) -> Result<(), DeploymentdProcessError> {
        let ManagedAgentStackProcessContext {
            mut store,
            controller_signer,
            provisioning,
            client,
        } = open_managed_agent_stack_context(arguments)?;
        let mut journal = ManagedAgentStackApplyJournalV1::new(store.state().clone());
        if let Some(terminal) = journal
            .terminal(&controller_signer, &provisioning)
            .map_err(|_| process_error(ProcessErrorKind::AgentStack))?
        {
            if terminal.receipt().facts().request_mode()
                != ManagedAgentStackTargetModeV1::FabricAndAgent
            {
                return Err(process_error(ProcessErrorKind::AgentStack));
            }
            return write_agent_stack_terminal(&terminal);
        }
        let prepared = journal
            .prepared(&controller_signer, &provisioning)
            .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let action = {
            let mut durable = ManagedAgentStackDurableStoreV1::try_new(&mut store)
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
            journal
                .claim_send_with(prepared, &controller_signer, &provisioning, |next| {
                    durable.commit(next)
                })
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?
        };
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let outcome = runtime.block_on(client.exchange(action));
        let (action, response) = outcome.into_parts();
        let response = response.map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let terminal = {
            let mut durable = ManagedAgentStackDurableStoreV1::try_new(&mut store)
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
            journal
                .consume_pxst_with(
                    action,
                    &response,
                    &controller_signer,
                    &provisioning,
                    |next| durable.commit(next),
                )
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?
        };
        write_agent_stack_terminal(&terminal)
    }

    fn deactivate_agent_stack(
        arguments: ManagedServingArguments,
    ) -> Result<(), DeploymentdProcessError> {
        let ManagedAgentStackProcessContext {
            mut store,
            controller_signer,
            provisioning,
            client,
        } = open_managed_agent_stack_context(arguments)?;
        let mut journal = ManagedAgentStackApplyJournalV1::new(store.state().clone());
        if let Some(terminal) = journal
            .terminal(&controller_signer, &provisioning)
            .map_err(|_| process_error(ProcessErrorKind::AgentStack))?
            && terminal.receipt().facts().request_mode()
                == ManagedAgentStackTargetModeV1::EmptyDeactivate
        {
            return write_agent_stack_terminal(&terminal);
        }
        let fresh = fresh_managed_agent_stack_request()?;
        let prepared = {
            let mut durable = ManagedAgentStackDurableStoreV1::try_new(&mut store)
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
            journal
                .prepare_empty_deactivate_with(&controller_signer, &provisioning, fresh, |next| {
                    durable.commit(next)
                })
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?
        };
        let action = {
            let mut durable = ManagedAgentStackDurableStoreV1::try_new(&mut store)
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
            journal
                .claim_send_with(prepared, &controller_signer, &provisioning, |next| {
                    durable.commit(next)
                })
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?
        };
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let outcome = runtime.block_on(client.exchange(action));
        let (action, response) = outcome.into_parts();
        let response = response.map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let terminal = {
            let mut durable = ManagedAgentStackDurableStoreV1::try_new(&mut store)
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
            journal
                .consume_pxst_with(
                    action,
                    &response,
                    &controller_signer,
                    &provisioning,
                    |next| durable.commit(next),
                )
                .map_err(|_| process_error(ProcessErrorKind::AgentStack))?
        };
        write_agent_stack_terminal(&terminal)
    }

    fn build_agent_service_plan(
        arguments: &AgentStackCommitArguments,
    ) -> Result<ManagedAgentServicePlanV1, DeploymentdProcessError> {
        let lifecycle = ManagedServiceLifecycleBudgetsV1::try_new(
            BoundedDuration::from_nanos(arguments.lifecycle_budgets[0]),
            BoundedDuration::from_nanos(arguments.lifecycle_budgets[1]),
            BoundedDuration::from_nanos(arguments.lifecycle_budgets[2]),
            BoundedDuration::from_nanos(arguments.lifecycle_budgets[3]),
            BoundedDuration::from_nanos(arguments.lifecycle_budgets[4]),
        )
        .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let semantic = ManagedAgentSemanticLimitsV1::try_new(
            arguments.semantic_limits[0],
            arguments.semantic_limits[1],
            arguments.semantic_limits[2],
            arguments.semantic_limits[3],
        )
        .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let ingress = ManagedAgentIngressLimitsV1::try_new(
            arguments.ingress_max_items,
            arguments.ingress_max_bytes,
            arguments.ingress_max_frame_bytes,
            arguments.ingress_max_response_body_bytes,
            arguments.handler_timeout_nanos,
        )
        .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let port = ManagedAgentPortPlanV1::try_new(
            BindingId::from_bytes(arguments.submit_binding),
            BindingId::from_bytes(arguments.control_binding),
            &arguments.submit_key_expression,
            &arguments.control_key_expression,
            ingress,
        )
        .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let provider = match arguments.provider {
            AgentStackProviderArguments::DeterministicFixture {
                provider_ref,
                config_digest,
            } => ManagedAgentProviderSelectionV1::try_deterministic_fixture(
                ManagedAgentProviderRefV1::try_from_bytes(provider_ref)
                    .map_err(|_| process_error(ProcessErrorKind::AgentStack))?,
                Digest32::from_bytes(config_digest),
            ),
            AgentStackProviderArguments::Provisioned {
                provider_ref,
                config_digest,
                secret_ref,
            } => ManagedAgentProviderSelectionV1::try_provisioned(
                ManagedAgentProviderRefV1::try_from_bytes(provider_ref)
                    .map_err(|_| process_error(ProcessErrorKind::AgentStack))?,
                Digest32::from_bytes(config_digest),
                ManagedAgentSecretRefV1::try_from_bytes(secret_ref)
                    .map_err(|_| process_error(ProcessErrorKind::AgentStack))?,
            ),
        }
        .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        ManagedAgentServicePlanV1::try_new(
            ManagedServiceSpecV1::new(
                ManagedServiceId::from_bytes(arguments.service_id),
                lifecycle,
            ),
            semantic,
            port,
            provider,
        )
        .map_err(|_| process_error(ProcessErrorKind::AgentStack))
    }

    fn apply_reference(arguments: BootstrapArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_bootstrap_separation(&arguments)?;

        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let runtime_response_public = read_pinned_file(
            &arguments.runtime_response_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let runtime_response_public_bytes = exact_public_key(&runtime_response_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == runtime_response_public_bytes
            || controller_public_bytes == authority_public_bytes
            || runtime_response_public_bytes == authority_public_bytes
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        // Load the Controller secret only after all public files and their
        // separation have been validated. Exact durable PXAR replay never
        // re-signs with this key, but still verifies the pinned signer.
        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let file_identities = [
            controller_public.identity,
            controller_seed_file.identity,
            runtime_response_public.identity,
            authority_public.identity,
        ];
        if file_identities
            .iter()
            .enumerate()
            .any(|(index, identity)| file_identities[index + 1..].contains(identity))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let mut seed = Zeroizing::new([0; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        if controller_signer.verifying_key().to_bytes() != controller_public_bytes
            || controller_signer.verifying_key().is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let (target, provisioning) = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let state = snapshot.state();
            let expected_scope = DeploymentScopeId::from_bytes(arguments.common.scope);
            let expected_plan = DeploymentId::from_bytes(arguments.common.plan);
            if state.scope() != expected_scope
                || state.plan_lineage() != expected_plan
                || state.request_auth() != request_auth.pin
                || state.committed_plan().is_none()
                || state.target_binding().is_none()
            {
                return Err(process_error(ProcessErrorKind::Provisioning));
            }
            validate_apply_protected_policy(
                &arguments,
                state,
                &request_auth,
                &controller_public_bytes,
                &runtime_response_public_bytes,
                &authority_public_bytes,
            )?;
            let provisioning = ControllerApplyProvisioningV1::try_from_controller_state(
                state,
                &controller_signer,
                PrincipalRef::from_bytes(arguments.controller_principal),
                DeploymentWriterRef::from_bytes(arguments.writer_ref),
                PrincipalRef::from_bytes(arguments.authority_principal),
                arguments.authority_uid,
                arguments.authority_gid,
                TenureAuthorityRef::from_bytes(arguments.tenure_authority_ref),
                TenureKeyRef::from_bytes(arguments.tenure_key_ref),
                authority_public_bytes,
            )
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
            (state.installed_manifest().target(), provisioning)
        };

        let endpoint = UnixRuntimeControlEndpoint::try_new(
            arguments.runtime_socket_path,
            RuntimeControlSocketAcl::new(arguments.runtime_uid, arguments.common.expected_gid),
            RuntimeUnixCredentials::new(arguments.runtime_uid, arguments.runtime_gid),
            target,
            PrincipalRef::from_bytes(arguments.runtime_principal),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_verifying_key = VerifyingKey::from_bytes(&runtime_response_public_bytes)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let runtime_key_fingerprint =
            ed25519_control_key_fingerprint(runtime_verifying_key.as_bytes())
                .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let response_verifier = RuntimeApplyResponseVerifier::try_new(
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            request_auth.pin.algorithm(),
            request_auth.pin.algorithm_version(),
            runtime_key_fingerprint,
            runtime_verifying_key,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let client =
            UnixRuntimeApplyClient::try_new(endpoint, response_verifier, APPLY_EXCHANGE_TIMEOUT)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::Apply))?;

        let prepared = match replay_prepared_reference_apply_v1(
            &mut store,
            owner_identity,
            &controller_signer,
            &provisioning,
        )
        .map_err(|_| process_error(ProcessErrorKind::Apply))?
        {
            Some(prepared) => prepared,
            None => {
                let fresh = fresh_apply_request()?;
                prepare_reference_apply_v1(
                    &mut store,
                    owner_identity,
                    &controller_signer,
                    &provisioning,
                    fresh,
                )
                .map_err(|_| process_error(ProcessErrorKind::Apply))?
            }
        };
        let applied = runtime
            .block_on(apply_reference_once_v1(&mut store, &client, &prepared))
            .map_err(|_| process_error(ProcessErrorKind::Apply))?;
        write_apply_receipt(&prepared, &applied)
    }

    fn reconcile_reference(arguments: BootstrapArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_bootstrap_separation(&arguments)?;

        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let runtime_response_public = read_pinned_file(
            &arguments.runtime_response_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let runtime_response_public_bytes = exact_public_key(&runtime_response_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == runtime_response_public_bytes
            || controller_public_bytes == authority_public_bytes
            || runtime_response_public_bytes == authority_public_bytes
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let file_identities = [
            controller_public.identity,
            controller_seed_file.identity,
            runtime_response_public.identity,
            authority_public.identity,
        ];
        if file_identities
            .iter()
            .enumerate()
            .any(|(index, identity)| file_identities[index + 1..].contains(identity))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let mut seed = Zeroizing::new([0_u8; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        if controller_signer.verifying_key().to_bytes() != controller_public_bytes
            || controller_signer.verifying_key().is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let target = {
            let state = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state();
            if state.scope() != DeploymentScopeId::from_bytes(arguments.common.scope)
                || state.plan_lineage() != DeploymentId::from_bytes(arguments.common.plan)
                || state.request_auth() != request_auth.pin
                || state.committed_plan().is_none()
                || state.target_binding().is_none()
            {
                return Err(process_error(ProcessErrorKind::Provisioning));
            }
            validate_apply_protected_policy(
                &arguments,
                state,
                &request_auth,
                &controller_public_bytes,
                &runtime_response_public_bytes,
                &authority_public_bytes,
            )?;
            state.installed_manifest().target()
        };

        let endpoint = UnixRuntimeControlEndpoint::try_new(
            arguments.runtime_socket_path,
            RuntimeControlSocketAcl::new(arguments.runtime_uid, arguments.common.expected_gid),
            RuntimeUnixCredentials::new(arguments.runtime_uid, arguments.runtime_gid),
            target,
            PrincipalRef::from_bytes(arguments.runtime_principal),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_verifying_key = VerifyingKey::from_bytes(&runtime_response_public_bytes)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let runtime_key_fingerprint =
            ed25519_control_key_fingerprint(runtime_verifying_key.as_bytes())
                .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let response_verifier = RuntimeQueryResponseVerifier::try_new(
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            request_auth.pin.algorithm(),
            request_auth.pin.algorithm_version(),
            runtime_key_fingerprint,
            runtime_verifying_key,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let client =
            UnixRuntimeQueryClient::try_new(endpoint, response_verifier, QUERY_EXCHANGE_TIMEOUT)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let provisioning = ControllerQueryProvisioningV1::try_new(PrincipalRef::from_bytes(
            arguments.controller_principal,
        ))
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::Reconcile))?;
        let outcome = runtime
            .block_on(reconcile_reference_once_v1(
                &mut store,
                &client,
                owner_identity,
                &controller_signer,
                provisioning,
            ))
            .map_err(|_| process_error(ProcessErrorKind::Reconcile))?;
        write_reconcile_outcome(outcome)
    }

    fn validate_apply_protected_policy(
        arguments: &BootstrapArguments,
        state: &crate::controller_journal::ControllerJournalState,
        request_auth: &RequestAuthProvisioning,
        controller_public_key: &[u8; PUBLIC_KEY_BYTES],
        runtime_response_public_key: &[u8; PUBLIC_KEY_BYTES],
        authority_public_key: &[u8; PUBLIC_KEY_BYTES],
    ) -> Result<(), DeploymentdProcessError> {
        let target = state.installed_manifest().target();
        let source_scope = paraegox_runtime_contracts::provenance::SourceScopeRef::from_bytes(
            *state.scope().as_bytes(),
        );
        let admission_policy =
            reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
                target,
                source_scope,
                writer: PlanWriterRef::from_bytes(arguments.writer_ref),
                controller_principal: PrincipalRef::from_bytes(arguments.controller_principal),
                controller_key_ref: request_auth.pin.key(),
                controller_public_key,
                authority_principal: PrincipalRef::from_bytes(arguments.authority_principal),
                authority_uid: arguments.authority_uid,
                authority_gid: arguments.authority_gid,
                tenure_authority_ref: TenureAuthorityRef::from_bytes(
                    arguments.tenure_authority_ref,
                ),
                tenure_key_ref: TenureKeyRef::from_bytes(arguments.tenure_key_ref),
                tenure_public_key: authority_public_key,
            })
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let channel_policy = reference_bootstrap_channel_policy_fingerprint_v1(
            ReferenceBootstrapChannelPolicyInputV1 {
                canonical_socket_path: arguments.runtime_socket_path.as_os_str().as_bytes(),
                target,
                source_scope,
                controller_principal: PrincipalRef::from_bytes(arguments.controller_principal),
                controller_key_ref: request_auth.pin.key(),
                controller_public_key,
                runtime_uid: arguments.runtime_uid,
                runtime_gid: arguments.runtime_gid,
                controller_uid: arguments.common.expected_uid,
                controller_gid: arguments.common.expected_gid,
                runtime_principal: PrincipalRef::from_bytes(arguments.runtime_principal),
                response_key_ref: ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
                response_public_key: runtime_response_public_key,
            },
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let binding = state
            .target_binding()
            .ok_or_else(|| process_error(ProcessErrorKind::Provisioning))?;
        let response = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_auth = binding.runtime_response_auth();
        if response.facts().admission_policy_fingerprint() != admission_policy.digest()
            || binding.channel_auth_fingerprint().value() != channel_policy
            || runtime_auth.runtime_peer() != PrincipalRef::from_bytes(arguments.runtime_principal)
            || runtime_auth.key() != ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref)
            || runtime_auth.algorithm() != request_auth.pin.algorithm()
            || runtime_auth.algorithm_version() != request_auth.pin.algorithm_version()
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn fresh_apply_request() -> Result<FreshControllerApplyRequestV1, DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(ProcessErrorKind::Apply))?;
        let mut source = File::from(owned);
        let mut entropy = [0; APPLY_ENTROPY_BYTES];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(ProcessErrorKind::Apply))?;
        fresh_apply_request_from_entropy(&entropy)
    }

    fn fresh_apply_request_from_entropy(
        entropy: &[u8; APPLY_ENTROPY_BYTES],
    ) -> Result<FreshControllerApplyRequestV1, DeploymentdProcessError> {
        let mut operation = [0; 16];
        operation.copy_from_slice(&entropy[..16]);
        let mut temporal = [0; 16];
        temporal.copy_from_slice(&entropy[16..32]);
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&entropy[32..]);
        FreshControllerApplyRequestV1::try_new(operation, temporal, nonce)
            .map_err(|_| process_error(ProcessErrorKind::Apply))
    }

    fn exact_public_key(bytes: &[u8]) -> Result<[u8; 32], DeploymentdProcessError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| process_error(ProcessErrorKind::Key))?;
        if key.is_weak() {
            return Err(process_error(ProcessErrorKind::Key));
        }
        Ok(bytes)
    }

    fn fresh_bootstrap_request()
    -> Result<FreshControllerBootstrapRequestV1, DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(ProcessErrorKind::Bootstrap))?;
        let mut source = File::from(owned);
        let mut entropy = [0; BOOTSTRAP_ENTROPY_BYTES];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(ProcessErrorKind::Bootstrap))?;
        let mut request_id = [0; 16];
        request_id.copy_from_slice(&entropy[..16]);
        let mut client_nonce = [0; 32];
        client_nonce.copy_from_slice(&entropy[16..]);
        FreshControllerBootstrapRequestV1::try_new(request_id, client_nonce)
            .map_err(|_| process_error(ProcessErrorKind::Bootstrap))
    }

    fn fresh_managed_serving_request()
    -> Result<FreshManagedServingBootstrapV1, DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?;
        let mut source = File::from(owned);
        let mut entropy = [0; MANAGED_SERVING_ENTROPY_BYTES];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(ProcessErrorKind::ServingObservation))?;
        let mut request_id = [0; 16];
        request_id.copy_from_slice(&entropy[..16]);
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&entropy[16..]);
        FreshManagedServingBootstrapV1::try_new(request_id, nonce)
            .map_err(|_| process_error(ProcessErrorKind::ServingObservation))
    }

    fn fresh_managed_agent_stack_request()
    -> Result<FreshManagedAgentStackApplyV1, DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let mut source = File::from(owned);
        let mut entropy = [0; MANAGED_AGENT_STACK_ENTROPY_BYTES];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(ProcessErrorKind::AgentStack))?;
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&entropy[..16]);
        let mut temporal_constraint_id = [0; 16];
        temporal_constraint_id.copy_from_slice(&entropy[16..32]);
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&entropy[32..]);
        FreshManagedAgentStackApplyV1::try_new(operation_id, temporal_constraint_id, nonce)
            .map_err(|_| process_error(ProcessErrorKind::AgentStack))
    }

    fn build_reference_candidate(
        installed_manifest: &ControllerInstalledManifestPin,
        deck_key: [u8; 16],
        card_use_key: [u8; 16],
        definition_version: u32,
        lifecycle: ValidatedReferenceLifecycleBudgetsV1,
    ) -> Result<DeploymentPlanCandidate, DeploymentdProcessError> {
        let manifest = installed_manifest.projection();
        let definition = manifest.fixture_definition();
        let deck = DeckSpec::new(
            DeckKey::from_bytes(deck_key),
            vec![
                DeckCardSpec::new(
                    CardUseKey::from_bytes(card_use_key),
                    definition,
                    DeckCardConfig::CanonicalEmpty,
                )
                .with_role(DeckCardRole::ReferenceSubject)
                .with_requested_version(CardDefinitionVersionRequirement::exact(
                    definition_version,
                )),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DeckOwnershipRequest::Deck,
            DeckLifetimeRequest::Deck,
        );
        let resolver = DeckResolverSnapshot::new(vec![ResolvedCardDefinition::new(
            definition,
            definition_version,
            ResolvedCardArtifact::new(
                manifest.fixture_definition_digest(),
                manifest.fixture_implementation(),
                DeckExportRef::from_bytes(manifest.fixture_export()),
                manifest.fixture_artifact_digest(),
            ),
            Vec::new(),
        )]);
        let deck_lock = DeckCompiler::compile(&deck, &resolver)
            .map_err(|_| process_error(ProcessErrorKind::Planning))?;
        let empty_allocation =
            StableAllocationSnapshot::try_new(installed_manifest.target(), 0, 0, Vec::new())
                .map_err(|_| process_error(ProcessErrorKind::Planning))?;
        let outcome = DeploymentPlanner::plan(&PlannerInput {
            target: installed_manifest.target(),
            desired: PlannerDesired::OneSourceLoop {
                deck_lock: &deck_lock,
                lifecycle: ValidatedReferenceLifecycleBudgets::from_reference_contract(lifecycle),
                config_digest: manifest.canonical_empty_config_digest(),
            },
            previous: PreviousTargetEligibility::UninitializedNoneExactZero,
            manifest: Some(manifest),
            allocation: &empty_allocation,
            service_dependencies: &[],
        })
        .map_err(|_| process_error(ProcessErrorKind::Planning))?;
        match outcome {
            PlannerOutcome::Candidate(candidate) => Ok(*candidate),
            PlannerOutcome::Omitted => Err(process_error(ProcessErrorKind::Planning)),
        }
    }

    struct RequestAuthProvisioning {
        pin: ControllerRequestAuthPin,
        fingerprint: Digest32,
    }

    fn request_auth_pin(
        arguments: &CommonArguments,
        bytes: &[u8],
    ) -> Result<RequestAuthProvisioning, DeploymentdProcessError> {
        let public_key: [u8; PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        if verifying_key.is_weak() {
            return Err(process_error(ProcessErrorKind::Key));
        }
        let fingerprint = ed25519_control_key_fingerprint(&public_key)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let pin = ControllerRequestAuthPin::try_new(
            ApplyAuthKeyRef::from_bytes(arguments.request_auth_key),
            algorithm,
            ED25519_ALGORITHM_VERSION,
            ControllerAuthKeyFingerprint::from_stored(fingerprint),
            INITIAL_AUTH_ROTATION_GENERATION,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        Ok(RequestAuthProvisioning { pin, fingerprint })
    }

    fn owner_identity(
        arguments: &CommonArguments,
        request_auth_fingerprint: Digest32,
    ) -> Result<ControllerOwnerIdentityFingerprint, DeploymentdProcessError> {
        // The fields are deliberately reproducible by normal startup without
        // rereading the installer artifact. The journal itself owns the exact
        // immutable manifest pin and cross-checks every later plan against it.
        let mut builder = Digest32Builder::try_new(CONTROLLER_OWNER_IDENTITY_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        builder
            .field_bytes(arguments.state_directory.as_os_str().as_bytes())
            .and_then(|builder| builder.field_u64(u64::from(arguments.expected_uid)))
            .and_then(|builder| builder.field_u64(u64::from(arguments.expected_gid)))
            .and_then(|builder| builder.field_bytes(&arguments.scope))
            .and_then(|builder| builder.field_bytes(&arguments.plan))
            .and_then(|builder| builder.field_bytes(&arguments.request_auth_key))
            .and_then(|builder| builder.field_u16(ED25519_ALGORITHM))
            .and_then(|builder| builder.field_u16(ED25519_ALGORITHM_VERSION))
            .and_then(|builder| builder.field_digest(&request_auth_fingerprint))
            .and_then(|builder| builder.field_u64(INITIAL_AUTH_ROTATION_GENERATION))
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        Ok(ControllerOwnerIdentityFingerprint::from_stored(
            builder.finish(),
        ))
    }

    fn validate_service_identity(
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), DeploymentdProcessError> {
        if expected_uid == 0
            || expected_gid == 0
            || geteuid().as_raw() != expected_uid
            || getegid().as_raw() != expected_gid
        {
            return Err(process_error(ProcessErrorKind::ServiceIdentity));
        }
        Ok(())
    }

    fn validate_separation(
        arguments: &CommonArguments,
        manifest_path: Option<&Path>,
    ) -> Result<(), DeploymentdProcessError> {
        if arguments
            .public_key_path
            .starts_with(&arguments.state_directory)
            || manifest_path.is_some_and(|path| {
                path.starts_with(&arguments.state_directory) || path == arguments.public_key_path
            })
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        Ok(())
    }

    fn validate_bootstrap_separation(
        arguments: &BootstrapArguments,
    ) -> Result<(), DeploymentdProcessError> {
        validate_separation(&arguments.common, None)?;
        let protected_paths = [
            &arguments.common.public_key_path,
            &arguments.controller_private_seed_path,
            &arguments.runtime_response_public_key_path,
            &arguments.authority_public_key_path,
        ];
        if arguments
            .runtime_socket_path
            .starts_with(&arguments.common.state_directory)
            || protected_paths.iter().any(|path| {
                path.starts_with(&arguments.common.state_directory)
                    || *path == &arguments.runtime_socket_path
            })
            || protected_paths
                .iter()
                .enumerate()
                .any(|(index, path)| protected_paths[index + 1..].contains(path))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let principals = [
            arguments.controller_principal,
            arguments.runtime_principal,
            arguments.authority_principal,
        ];
        if principals
            .iter()
            .enumerate()
            .any(|(index, principal)| principals[index + 1..].contains(principal))
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let key_and_authority_refs = [
            arguments.common.request_auth_key,
            arguments.runtime_response_key_ref,
            arguments.tenure_key_ref,
            arguments.tenure_authority_ref,
        ];
        if key_and_authority_refs
            .iter()
            .enumerate()
            .any(|(index, reference)| key_and_authority_refs[index + 1..].contains(reference))
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let uids = [
            arguments.common.expected_uid,
            arguments.runtime_uid,
            arguments.authority_uid,
        ];
        if uids
            .iter()
            .enumerate()
            .any(|(index, uid)| uids[index + 1..].contains(uid))
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn validate_tenure_separation(
        arguments: &AcquireTenureArguments,
    ) -> Result<(), DeploymentdProcessError> {
        validate_separation(&arguments.common, None)?;
        let key_paths = [
            &arguments.common.public_key_path,
            &arguments.controller_private_seed_path,
            &arguments.authority_public_key_path,
        ];
        if arguments
            .authority_socket_path
            .starts_with(&arguments.common.state_directory)
            || key_paths.iter().any(|path| {
                path.starts_with(&arguments.common.state_directory)
                    || *path == &arguments.authority_socket_path
            })
            || key_paths
                .iter()
                .enumerate()
                .any(|(index, path)| key_paths[index + 1..].contains(path))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        if arguments.authority_uid == arguments.common.expected_uid {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let refs = [
            arguments.common.request_auth_key,
            arguments.tenure_authority_ref,
            arguments.tenure_key_ref,
        ];
        if refs
            .iter()
            .enumerate()
            .any(|(index, reference)| refs[index + 1..].contains(reference))
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn write_initialization_receipt(
        receipt: &ControllerInitializationReceipt,
    ) -> Result<(), DeploymentdProcessError> {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_initialize_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "store_instance_id",
            receipt.store_instance_id(),
        )?;
        write_labeled_hex(
            &mut output,
            "owner_identity_fingerprint",
            receipt.owner_identity_fingerprint().value().as_bytes(),
        )?;
        writeln!(output, "snapshot_sequence={}", receipt.snapshot_sequence())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "initialized_snapshot_digest",
            receipt.initialized_snapshot_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "receipt_digest",
            receipt.receipt_digest().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "receipt_bytes", receipt.canonical_bytes())?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_commit_receipt(
        snapshot: &ControllerJournalSnapshot,
        operation: ControllerOperationId,
    ) -> Result<(), DeploymentdProcessError> {
        let plan_digest = snapshot
            .state()
            .committed_plan_digest()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let manifest_digest = snapshot.state().installed_manifest().manifest_digest();
        let encoded_snapshot = snapshot
            .encode()
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        let mut snapshot_digest = Digest32Builder::try_new(COMMIT_SNAPSHOT_DIGEST_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        snapshot_digest
            .field_bytes(&encoded_snapshot)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        let snapshot_digest = snapshot_digest.finish();

        let mut receipt = Vec::new();
        receipt.extend_from_slice(COMMIT_RECEIPT_MAGIC);
        receipt.extend_from_slice(&COMMIT_RECEIPT_VERSION.to_be_bytes());
        receipt.extend_from_slice(snapshot.store_instance_id());
        receipt.extend_from_slice(&snapshot.snapshot_sequence().to_be_bytes());
        receipt.extend_from_slice(&snapshot.state().current_revision().to_be_bytes());
        receipt.extend_from_slice(operation.as_bytes());
        receipt.extend_from_slice(plan_digest.value().as_bytes());
        receipt.extend_from_slice(manifest_digest.as_bytes());
        receipt.extend_from_slice(snapshot_digest.as_bytes());
        let mut receipt_digest = Digest32Builder::try_new(COMMIT_RECEIPT_DIGEST_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        receipt_digest
            .field_bytes(&receipt)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        let receipt_digest = receipt_digest.finish();

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_commit_reference_loop_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "store_instance_id",
            snapshot.store_instance_id(),
        )?;
        writeln!(output, "snapshot_sequence={}", snapshot.snapshot_sequence())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "plan_revision={}",
            snapshot.state().current_revision()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "operation_id", operation.as_bytes())?;
        write_labeled_hex(&mut output, "plan_digest", plan_digest.value().as_bytes())?;
        write_labeled_hex(&mut output, "manifest_digest", manifest_digest.as_bytes())?;
        write_labeled_hex(&mut output, "snapshot_digest", snapshot_digest.as_bytes())?;
        write_labeled_hex(&mut output, "receipt_digest", receipt_digest.as_bytes())?;
        write_labeled_hex(&mut output, "receipt_bytes", &receipt)?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_empty_commit_receipt(
        snapshot: &ControllerJournalSnapshot,
        operation: ControllerOperationId,
    ) -> Result<(), DeploymentdProcessError> {
        let state = snapshot.state();
        let plan = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let manifest_digest = state.installed_manifest().manifest_digest();

        let (receipt, receipt_digest, expected_active) =
            build_empty_commit_receipt(snapshot, operation)?;

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_commit_reference_empty_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "controller_store_instance_id",
            snapshot.store_instance_id(),
        )?;
        write_labeled_hex(&mut output, "source_scope", state.scope().as_bytes())?;
        write_labeled_hex(&mut output, "source_plan", state.plan_lineage().as_bytes())?;
        writeln!(output, "plan_revision={}", plan.revision().value())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "operation_id", operation.as_bytes())?;
        write_labeled_hex(&mut output, "target", plan.target().as_bytes())?;
        write_labeled_hex(
            &mut output,
            "plan_digest",
            plan.deployment_plan_digest().value().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "manifest_digest", manifest_digest.as_bytes())?;
        writeln!(
            output,
            "allocation_generation={}",
            state.allocation().generation()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "expected_active_target_slice_digest",
            expected_active.value().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "receipt_digest", receipt_digest.as_bytes())?;
        write_labeled_hex(&mut output, "receipt_bytes", &receipt)?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn build_empty_commit_receipt(
        snapshot: &ControllerJournalSnapshot,
        operation: ControllerOperationId,
    ) -> Result<
        (
            Vec<u8>,
            Digest32,
            paraegox_runtime_contracts::provenance::TargetSliceDigest,
        ),
        DeploymentdProcessError,
    > {
        let state = snapshot.state();
        let expected_active = validate_committed_empty_state(state, operation)?;
        let plan = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let manifest_digest = state.installed_manifest().manifest_digest();

        // This receipt intentionally excludes the physical Controller snapshot
        // sequence and whole-snapshot digest. Bootstrap refreshes and the
        // subsequent Empty apply are legal successors, but must not change the
        // semantic result of replaying this exact committed plan operation.
        let mut receipt = Vec::new();
        receipt.extend_from_slice(EMPTY_COMMIT_RECEIPT_MAGIC);
        receipt.extend_from_slice(&EMPTY_COMMIT_RECEIPT_VERSION.to_be_bytes());
        receipt.extend_from_slice(snapshot.store_instance_id());
        receipt.extend_from_slice(state.scope().as_bytes());
        receipt.extend_from_slice(state.plan_lineage().as_bytes());
        receipt.extend_from_slice(&plan.revision().value().to_be_bytes());
        receipt.extend_from_slice(operation.as_bytes());
        receipt.extend_from_slice(plan.target().as_bytes());
        receipt.extend_from_slice(plan.deployment_plan_digest().value().as_bytes());
        receipt.extend_from_slice(manifest_digest.as_bytes());
        receipt.extend_from_slice(&state.allocation().generation().to_be_bytes());
        receipt.extend_from_slice(expected_active.value().as_bytes());
        let mut receipt_digest = Digest32Builder::try_new(EMPTY_COMMIT_RECEIPT_DIGEST_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        receipt_digest
            .field_bytes(&receipt)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        let receipt_digest = receipt_digest.finish();
        Ok((receipt, receipt_digest, expected_active))
    }

    fn write_bootstrap_receipt(
        receipt: &ControllerBootstrapReceiptV1,
    ) -> Result<(), DeploymentdProcessError> {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_bootstrap_runtime_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "controller_store_instance_id",
            receipt.controller_store_instance_id(),
        )?;
        writeln!(
            output,
            "controller_snapshot_sequence={}",
            receipt.controller_snapshot_sequence()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "target", receipt.target().as_bytes())?;
        write_labeled_hex(
            &mut output,
            "runtime_store_instance_id",
            receipt.runtime_store_instance_id(),
        )?;
        writeln!(
            output,
            "runtime_host_epoch={}",
            receipt.runtime_host_epoch()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "channel_policy_fingerprint",
            receipt.channel_policy_fingerprint().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "bootstrap_response_digest",
            receipt.bootstrap_response_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "bootstrap_response_bytes",
            receipt.bootstrap_response(),
        )?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_tenure_receipt(
        snapshot: &ControllerJournalSnapshot,
        operation: AcquireTenureOperationId,
        acquired: &ControllerAcquiredTenure,
    ) -> Result<(), DeploymentdProcessError> {
        let transaction = snapshot
            .state()
            .tenure_transaction(operation)
            .ok_or_else(|| process_error(ProcessErrorKind::Tenure))?;
        let response = transaction
            .response()
            .ok_or_else(|| process_error(ProcessErrorKind::Tenure))?;
        if response.proof() != acquired.proof()
            || response.operation_id() != operation
            || response.request_digest() != transaction.request().request_digest()
        {
            return Err(process_error(ProcessErrorKind::Tenure));
        }
        let proof = response.proof();
        let authority = proof.authority();
        let claim = proof.claim();

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_acquire_tenure_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "controller_store_instance_id",
            snapshot.store_instance_id(),
        )?;
        write_labeled_hex(
            &mut output,
            "authority_domain_fingerprint",
            transaction
                .authority_domain_fingerprint()
                .value()
                .as_bytes(),
        )?;
        write_labeled_hex(&mut output, "operation_id", operation.as_bytes())?;
        write_labeled_hex(
            &mut output,
            "request_digest",
            transaction.request().request_digest().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "source_scope", claim.source_scope().as_bytes())?;
        write_labeled_hex(&mut output, "writer_ref", claim.writer().as_bytes())?;
        writeln!(output, "writer_epoch={}", claim.epoch().value())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "supersedes_through_epoch={}",
            claim.supersedes_through_epoch().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "tenure_authority_ref",
            authority.authority().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "tenure_key_ref", authority.key().as_bytes())?;
        writeln!(output, "proof_algorithm={}", authority.algorithm().value())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "proof_algorithm_version={}",
            authority.algorithm_version()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "proof_nonce", proof.nonce())?;
        write_labeled_hex(&mut output, "proof_signature", proof.signature())?;
        write_labeled_hex(
            &mut output,
            "proof_digest",
            response.proof_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "acquire_response_digest",
            response.response_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "acquire_response_bytes",
            response.canonical_bytes(),
        )?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_apply_receipt(
        prepared: &PreparedControllerApplyAttemptV1,
        applied: &ControllerAppliedReferenceV1,
    ) -> Result<(), DeploymentdProcessError> {
        let request = prepared.request();
        let receipt = applied
            .terminal_receipt()
            .ok_or_else(|| process_error(ProcessErrorKind::Apply))?;
        let provenance = request.provenance();
        let control = request.control_commitment().control();
        let writer = control.writer_context();
        let facts = receipt.facts();
        let request_time_channel = prepared.runtime_response_expectation().channel();
        let validated_facts = receipt
            .validate_against_request(request, request_time_channel)
            .map_err(|_| process_error(ProcessErrorKind::Apply))?;
        if applied.controller_store_instance_id() != prepared.controller_store_instance_id()
            || validated_facts != facts
            || receipt.target() != request.target()
            || receipt.runtime_store_instance_id() != request.expected_runtime_store_instance_id()
            || receipt.source_scope() != provenance.source_scope()
            || receipt.operation_id() != control.operation_id()
            || receipt.request_digest() != request.envelope_request_digest()
            || receipt.authentication_channel_binding_digest()
                != request_time_channel.binding_digest()
        {
            return Err(process_error(ProcessErrorKind::Apply));
        }

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_apply_reference_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "controller_store_instance_id",
            applied.controller_store_instance_id(),
        )?;
        write_labeled_hex(&mut output, "target", request.target().as_bytes())?;
        write_labeled_hex(
            &mut output,
            "runtime_store_instance_id",
            &request.expected_runtime_store_instance_id(),
        )?;
        write_labeled_hex(
            &mut output,
            "source_scope",
            provenance.source_scope().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "source_plan",
            provenance.source_plan().as_bytes(),
        )?;
        writeln!(
            output,
            "source_plan_revision={}",
            provenance.source_revision().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "source_plan_digest",
            provenance.source_plan_digest().value().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "writer_ref", writer.writer().as_bytes())?;
        writeln!(output, "writer_epoch={}", writer.epoch().value())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "apply_operation_id",
            control.operation_id().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "target_slice_digest",
            request.target_slice_digest().value().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "apply_request_digest",
            request.envelope_request_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "request_time_channel_binding_digest",
            request_time_channel.binding_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "apply_request_bytes",
            prepared.canonical_request_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "terminal_result_ref",
            facts.terminal_result_ref().as_bytes(),
        )?;
        writeln!(
            output,
            "terminal_outcome={}",
            terminal_outcome_code(facts.outcome())
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "terminal_lifecycle_effect={}",
            terminal_lifecycle_effect_code(facts.lifecycle_effect())
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(output, "terminal_head={}", terminal_head_code(facts.head()))
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        match facts.desired_head_digest() {
            Some(digest) => write_labeled_hex(
                &mut output,
                "desired_head_digest",
                digest.value().as_bytes(),
            )?,
            None => writeln!(output, "desired_head_digest=none")
                .map_err(|_| process_error(ProcessErrorKind::Output))?,
        }
        write_labeled_hex(
            &mut output,
            "resource_census_digest",
            facts.resource_census_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "raw_outcome_digest",
            facts.raw_outcome_digest().as_bytes(),
        )?;
        writeln!(
            output,
            "completion_runtime_host_epoch={}",
            facts.completion_runtime_host_epoch()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "completion_snapshot_sequence={}",
            facts.completion_snapshot_sequence()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "selection_clock_generation={}",
            facts.selection_clock_generation().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "selection_observed_at_nanos={}",
            facts.selection_observed_at_nanos()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "runtime_peer",
            receipt.authentication_runtime_peer().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "runtime_response_key_ref",
            receipt.authentication_key().as_bytes(),
        )?;
        writeln!(
            output,
            "runtime_response_algorithm={}",
            receipt.authentication_algorithm().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "runtime_response_algorithm_version={}",
            receipt.authentication_algorithm_version()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "terminal_receipt_digest",
            receipt.receipt_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "terminal_receipt_bytes",
            receipt.canonical_wire(),
        )?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_managed_serving_receipt(
        pin: &VerifiedManagedServingPinV1,
    ) -> Result<(), DeploymentdProcessError> {
        let facts = pin.facts();
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(
            output,
            "managed_serving_observation_v1 status=recovered_ready"
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "target", facts.target().as_bytes())?;
        write_labeled_hex(
            &mut output,
            "runtime_store_instance_id",
            &facts.runtime_store_instance_id(),
        )?;
        writeln!(output, "runtime_host_epoch={}", facts.runtime_host_epoch())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(output, "snapshot_sequence={}", facts.snapshot_sequence())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "clock_domain", facts.clock_domain().as_bytes())?;
        writeln!(
            output,
            "clock_generation={}",
            facts.clock_generation().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(output, "observed_at_nanos={}", facts.observed_at_nanos())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "request_digest",
            pin.request_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "response_digest",
            pin.response_digest().as_bytes(),
        )?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_agent_stack_prepared(request_digest: Digest32) -> Result<(), DeploymentdProcessError> {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(
            output,
            "managed_agent_stack_v1 status=request_committed mode=active"
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "request_digest", request_digest.as_bytes())?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_agent_stack_terminal(
        terminal: &ManagedAgentStackTerminalCommitV1,
    ) -> Result<(), DeploymentdProcessError> {
        let receipt = terminal.receipt();
        let mode = match receipt.facts().request_mode() {
            ManagedAgentStackTargetModeV1::FabricAndAgent => "active",
            ManagedAgentStackTargetModeV1::EmptyDeactivate => "empty_exact_zero",
        };
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(
            output,
            "managed_agent_stack_v1 status=applied mode={mode} replayed={}",
            terminal.replayed_from_journal()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "request_digest",
            receipt.facts().request_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "receipt_digest",
            receipt.receipt_digest().as_bytes(),
        )?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_reconcile_outcome(
        outcome: ControllerReconcileOutcomeV1,
    ) -> Result<(), DeploymentdProcessError> {
        let (label, receipt) = match outcome {
            ControllerReconcileOutcomeV1::Prepared => (b"prepared".as_slice(), None),
            ControllerReconcileOutcomeV1::Active(receipt) => (b"active".as_slice(), Some(receipt)),
            ControllerReconcileOutcomeV1::Retired(receipt) => {
                (b"retired".as_slice(), Some(receipt))
            }
            ControllerReconcileOutcomeV1::Uncertain => (b"uncertain".as_slice(), None),
        };
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(b"controller_reconcile_v1 outcome=")
            .and_then(|()| stdout.write_all(label))
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        if let Some(receipt) = receipt {
            write_labeled_hex_inline(&mut stdout, b" receipt=", receipt.as_bytes())?;
        }
        stdout
            .write_all(b"\n")
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    const fn terminal_head_code(head: ReferenceApplyTerminalHeadV1) -> u16 {
        match head {
            ReferenceApplyTerminalHeadV1::PreservedNone => 1,
            ReferenceApplyTerminalHeadV1::PreservedExisting(_) => 2,
            ReferenceApplyTerminalHeadV1::CommittedIncoming => 3,
        }
    }

    const fn terminal_lifecycle_effect_code(
        effect: ReferenceApplyTerminalLifecycleEffectV1,
    ) -> u16 {
        match effect {
            ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted => 1,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted => 2,
        }
    }

    const fn terminal_outcome_code(outcome: ReferenceApplyTerminalOutcomeV1) -> u16 {
        match outcome {
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive => 1,
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero => 2,
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects => 3,
            ReferenceApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects => 4,
            ReferenceApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero => 5,
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero => 6,
            ReferenceApplyTerminalOutcomeV1::StopFailedButExactZero => 7,
            ReferenceApplyTerminalOutcomeV1::TimedOutButExactZero => 8,
            ReferenceApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects => 9,
            ReferenceApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero => 10,
            ReferenceApplyTerminalOutcomeV1::SupersededAfterIntentExactZero => 11,
            ReferenceApplyTerminalOutcomeV1::InterruptedButNowExactZero => 12,
        }
    }

    fn write_labeled_hex(
        output: &mut impl Write,
        label: &str,
        bytes: &[u8],
    ) -> Result<(), DeploymentdProcessError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = Vec::with_capacity(label.len() + 2 + bytes.len().saturating_mul(2));
        encoded.extend_from_slice(label.as_bytes());
        encoded.push(b'=');
        for byte in bytes {
            encoded.push(HEX[usize::from(byte >> 4)]);
            encoded.push(HEX[usize::from(byte & 0x0f)]);
        }
        encoded.push(b'\n');
        output
            .write_all(&encoded)
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    struct DistributedNodeCapabilityV1 {
        expected_target: paraegox_kernel::identity::RuntimeHostId,
        management_target: NodeManagementTargetV1,
        socket_path: PathBuf,
        token: Zeroizing<[u8; 32]>,
        expected_uid: u32,
        expected_gid: u32,
        topology_wire: Box<[u8]>,
    }

    struct DistributedCoordinatorCapabilityV1 {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        controller_private_seed_path: PathBuf,
    }

    struct DistributedPredecessorCapabilityV1 {
        expected_target: paraegox_kernel::identity::RuntimeHostId,
        managed: ManagedServingArguments,
        node: DistributedNodeCapabilityV1,
        connector: Option<DistributedRestrictedControllerConnectorCapabilityV1>,
    }

    struct DistributedRestrictedControllerConnectorCapabilityV1 {
        profile_ref: [u8; 16],
        transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        root_ca_certificate_file: PathBuf,
        connector_certificate_file: PathBuf,
        connector_private_key_file: PathBuf,
    }

    pub(crate) struct DistributedLocalCapabilityV1 {
        expected_uid: u32,
        expected_gid: u32,
        lifecycle_budget_nanos: u64,
        coordinator: DistributedCoordinatorCapabilityV1,
        predecessors: [DistributedPredecessorCapabilityV1; 2],
        checksum: Digest32,
    }

    impl core::fmt::Debug for DistributedLocalCapabilityV1 {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("DistributedLocalCapabilityV1")
                .finish_non_exhaustive()
        }
    }

    impl DistributedLocalCapabilityV1 {
        fn decode(frame: &[u8]) -> Result<Self, DeploymentdProcessError> {
            if frame.len()
                < DISTRIBUTED_CAPABILITY_HEADER_BYTES + DISTRIBUTED_CAPABILITY_CHECKSUM_BYTES
                || frame.len() > MAX_DISTRIBUTED_CAPABILITY_BYTES
            {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            let checksum_offset = frame.len() - DISTRIBUTED_CAPABILITY_CHECKSUM_BYTES;
            let checksum = Digest32::from_bytes(
                frame[checksum_offset..]
                    .try_into()
                    .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?,
            );
            if distributed_capability_checksum(&frame[..checksum_offset])? != checksum {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            let mut header =
                DistributedCapabilityCursor::new(&frame[..DISTRIBUTED_CAPABILITY_HEADER_BYTES]);
            if header.array::<4>()? != *DISTRIBUTED_CAPABILITY_MAGIC {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            let wire_version = header.u16()?;
            if !matches!(
                wire_version,
                DISTRIBUTED_CAPABILITY_VERSION_V1 | DISTRIBUTED_CAPABILITY_VERSION_V2
            ) || usize::from(header.u16()?) != DISTRIBUTED_CAPABILITY_HEADER_BYTES
                || usize::try_from(header.u32()?).ok() != Some(frame.len())
                || usize::try_from(header.u32()?).ok()
                    != Some(
                        frame.len()
                            - DISTRIBUTED_CAPABILITY_HEADER_BYTES
                            - DISTRIBUTED_CAPABILITY_CHECKSUM_BYTES,
                    )
            {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            let expected_uid = header.u32()?;
            let expected_gid = header.u32()?;
            if expected_uid == 0 || expected_gid == 0 || header.u64()? != 0 {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            header.finish()?;
            let mut cursor = DistributedCapabilityCursor::new(
                &frame[DISTRIBUTED_CAPABILITY_HEADER_BYTES..checksum_offset],
            );
            let coordinator = DistributedCoordinatorCapabilityV1 {
                common: CommonArguments {
                    state_directory: cursor.path()?,
                    scope: cursor.nonzero_array()?,
                    plan: cursor.nonzero_array()?,
                    request_auth_key: cursor.nonzero_array()?,
                    public_key_path: cursor.path()?,
                    expected_uid,
                    expected_gid,
                },
                expected_store_id: cursor.nonzero_array()?,
                controller_private_seed_path: cursor.path()?,
            };
            let lifecycle_budget_nanos = cursor.nonzero_u64()?;
            let predecessors = [
                decode_distributed_predecessor(
                    &mut cursor,
                    expected_uid,
                    expected_gid,
                    wire_version,
                )?,
                decode_distributed_predecessor(
                    &mut cursor,
                    expected_uid,
                    expected_gid,
                    wire_version,
                )?,
            ];
            cursor.finish()?;
            let capability = Self {
                expected_uid,
                expected_gid,
                lifecycle_budget_nanos,
                coordinator,
                predecessors,
                checksum,
            };
            capability.validate()?;
            if capability.encode()?.as_slice() != frame {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            Ok(capability)
        }

        fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DeploymentdProcessError> {
            self.validate()?;
            let wire_version = self.wire_version()?;
            let mut payload = Zeroizing::new(Vec::new());
            encode_path(&mut payload, &self.coordinator.common.state_directory)?;
            payload.extend_from_slice(&self.coordinator.common.scope);
            payload.extend_from_slice(&self.coordinator.common.plan);
            payload.extend_from_slice(&self.coordinator.common.request_auth_key);
            encode_path(&mut payload, &self.coordinator.common.public_key_path)?;
            payload.extend_from_slice(&self.coordinator.expected_store_id);
            encode_path(&mut payload, &self.coordinator.controller_private_seed_path)?;
            payload.extend_from_slice(&self.lifecycle_budget_nanos.to_be_bytes());
            for predecessor in &self.predecessors {
                encode_distributed_predecessor(&mut payload, predecessor, wire_version)?;
            }
            let total = DISTRIBUTED_CAPABILITY_HEADER_BYTES
                .checked_add(payload.len())
                .and_then(|value| value.checked_add(DISTRIBUTED_CAPABILITY_CHECKSUM_BYTES))
                .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
            if total > MAX_DISTRIBUTED_CAPABILITY_BYTES {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            let mut wire = Zeroizing::new(Vec::with_capacity(total));
            wire.extend_from_slice(DISTRIBUTED_CAPABILITY_MAGIC);
            wire.extend_from_slice(&wire_version.to_be_bytes());
            wire.extend_from_slice(&(DISTRIBUTED_CAPABILITY_HEADER_BYTES as u16).to_be_bytes());
            wire.extend_from_slice(
                &u32::try_from(total)
                    .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?
                    .to_be_bytes(),
            );
            wire.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?
                    .to_be_bytes(),
            );
            wire.extend_from_slice(&self.expected_uid.to_be_bytes());
            wire.extend_from_slice(&self.expected_gid.to_be_bytes());
            wire.extend_from_slice(&0_u64.to_be_bytes());
            wire.extend_from_slice(payload.as_slice());
            let checksum = distributed_capability_checksum(&wire)?;
            wire.extend_from_slice(checksum.as_bytes());
            Ok(wire)
        }

        fn wire_version(&self) -> Result<u16, DeploymentdProcessError> {
            match [
                self.predecessors[0].connector.is_some(),
                self.predecessors[1].connector.is_some(),
            ] {
                [false, false] => Ok(DISTRIBUTED_CAPABILITY_VERSION_V1),
                [true, true] => Ok(DISTRIBUTED_CAPABILITY_VERSION_V2),
                _ => Err(process_error(ProcessErrorKind::NodeDiscovery)),
            }
        }

        fn distributed_apply_connectors(
            &self,
        ) -> Result<
            [&DistributedRestrictedControllerConnectorCapabilityV1; 2],
            DeploymentdProcessError,
        > {
            Ok([
                self.predecessors[0]
                    .connector
                    .as_ref()
                    .ok_or_else(|| process_error(ProcessErrorKind::DistributedApply))?,
                self.predecessors[1]
                    .connector
                    .as_ref()
                    .ok_or_else(|| process_error(ProcessErrorKind::DistributedApply))?,
            ])
        }

        fn validate(&self) -> Result<(), DeploymentdProcessError> {
            if self.expected_uid == 0
                || self.expected_gid == 0
                || self.lifecycle_budget_nanos == 0
                || self.predecessors[0].expected_target.as_bytes()
                    >= self.predecessors[1].expected_target.as_bytes()
                || self.predecessors[0].expected_target != self.predecessors[0].node.expected_target
                || self.predecessors[1].expected_target != self.predecessors[1].node.expected_target
                || self.predecessors[0].node.management_target.node_id()
                    == self.predecessors[1].node.management_target.node_id()
            {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            for predecessor in &self.predecessors {
                if predecessor.managed.bootstrap.common.expected_uid != self.expected_uid
                    || predecessor.managed.bootstrap.common.expected_gid != self.expected_gid
                    || predecessor.node.expected_uid != self.expected_uid
                    || predecessor.node.expected_gid != self.expected_gid
                    || predecessor.node.topology_wire.is_empty()
                    || predecessor.node.topology_wire.len() > MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES
                {
                    return Err(process_error(ProcessErrorKind::NodeDiscovery));
                }
                if let Some(connector) = predecessor.connector.as_ref() {
                    connector.validate(predecessor)?;
                }
            }
            self.wire_version()?;
            if let (Some(first), Some(second)) = (
                self.predecessors[0].connector.as_ref(),
                self.predecessors[1].connector.as_ref(),
            ) && first.profile_ref == second.profile_ref
            {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            let roots = [
                &self.coordinator.common.state_directory,
                &self.predecessors[0]
                    .managed
                    .bootstrap
                    .common
                    .state_directory,
                &self.predecessors[0].managed.successor_directory,
                &self.predecessors[1]
                    .managed
                    .bootstrap
                    .common
                    .state_directory,
                &self.predecessors[1].managed.successor_directory,
            ];
            if roots.iter().enumerate().any(|(index, left)| {
                roots[index + 1..].iter().any(|right| {
                    left == right || left.starts_with(right) || right.starts_with(left)
                })
            }) {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            Ok(())
        }
    }

    impl DistributedRestrictedControllerConnectorCapabilityV1 {
        fn validate(
            &self,
            predecessor: &DistributedPredecessorCapabilityV1,
        ) -> Result<(), DeploymentdProcessError> {
            let paths = [
                &self.root_ca_certificate_file,
                &self.connector_certificate_file,
                &self.connector_private_key_file,
            ];
            if self.profile_ref.iter().all(|byte| *byte == 0)
                || self.transport_profile.target() != predecessor.expected_target
                || self.transport_profile.controller_principal()
                    != PrincipalRef::from_bytes(predecessor.managed.bootstrap.controller_principal)
                || self.transport_profile.runtime_principal()
                    != PrincipalRef::from_bytes(predecessor.managed.bootstrap.runtime_principal)
                || paths.iter().any(|path| {
                    path.as_os_str().as_bytes().len() > MAX_DISTRIBUTED_CAPABILITY_PATH_BYTES
                        || path.to_str().is_none()
                        || parse_absolute_file_path(path.as_os_str()).is_err()
                })
                || paths[0] == paths[1]
                || paths[0] == paths[2]
                || paths[1] == paths[2]
                || RestrictedRuntimeApplyTransportProfileV1::decode(
                    self.transport_profile.canonical_wire(),
                )
                .is_err()
                || ResolvedRemoteMtlsIdentityFiles::try_new(
                    self.connector_certificate_file.clone(),
                    self.connector_private_key_file.clone(),
                )
                .is_err()
            {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            Ok(())
        }
    }

    fn decode_distributed_predecessor(
        cursor: &mut DistributedCapabilityCursor<'_>,
        expected_uid: u32,
        expected_gid: u32,
        wire_version: u16,
    ) -> Result<DistributedPredecessorCapabilityV1, DeploymentdProcessError> {
        let expected_target =
            paraegox_kernel::identity::RuntimeHostId::from_bytes(cursor.nonzero_array()?);
        let bootstrap = BootstrapArguments {
            common: CommonArguments {
                state_directory: cursor.path()?,
                scope: cursor.nonzero_array()?,
                plan: cursor.nonzero_array()?,
                request_auth_key: cursor.nonzero_array()?,
                public_key_path: cursor.path()?,
                expected_uid,
                expected_gid,
            },
            expected_store_id: cursor.nonzero_array()?,
            controller_private_seed_path: cursor.path()?,
            controller_principal: cursor.nonzero_array()?,
            writer_ref: cursor.nonzero_array()?,
            authority_principal: cursor.nonzero_array()?,
            authority_uid: cursor.nonzero_u32()?,
            authority_gid: cursor.nonzero_u32()?,
            tenure_authority_ref: cursor.nonzero_array()?,
            tenure_key_ref: cursor.nonzero_array()?,
            authority_public_key_path: cursor.path()?,
            runtime_socket_path: cursor.path()?,
            runtime_principal: cursor.nonzero_array()?,
            runtime_response_key_ref: cursor.nonzero_array()?,
            runtime_response_public_key_path: cursor.path()?,
            runtime_uid: cursor.nonzero_u32()?,
            runtime_gid: cursor.nonzero_u32()?,
        };
        let successor_directory = cursor.path()?;
        let successor_store_id = cursor.nonzero_array()?;
        let node_id = NodeId::try_from_bytes(cursor.nonzero_array()?)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let management_endpoint_ref =
            NodeManagementEndpointRefV1::try_from_bytes(cursor.nonzero_array()?)
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let node_incarnation = NodeIncarnation::try_from_bytes(cursor.nonzero_array()?)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let registration_epoch = cursor.nonzero_u64()?;
        let management_target = NodeManagementTargetV1::try_new(
            node_id,
            management_endpoint_ref,
            node_incarnation,
            registration_epoch,
        )
        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        let socket_path = cursor.path()?;
        let token = Zeroizing::new(cursor.nonzero_array()?);
        let node_uid = cursor.nonzero_u32()?;
        let node_gid = cursor.nonzero_u32()?;
        let topology_length = cursor.usize_u32()?;
        if topology_length == 0 || topology_length > MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        let topology_wire = cursor.take(topology_length)?.into();
        let connector = match wire_version {
            DISTRIBUTED_CAPABILITY_VERSION_V1 => None,
            DISTRIBUTED_CAPABILITY_VERSION_V2 => {
                let profile_ref = cursor.nonzero_array()?;
                let profile_length = cursor.usize_u32()?;
                if profile_length == 0
                    || profile_length > MAX_RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_BYTES
                {
                    return Err(process_error(ProcessErrorKind::NodeDiscovery));
                }
                let transport_profile =
                    RestrictedRuntimeApplyTransportProfileV1::decode(cursor.take(profile_length)?)
                        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
                Some(DistributedRestrictedControllerConnectorCapabilityV1 {
                    profile_ref,
                    transport_profile,
                    root_ca_certificate_file: cursor.path()?,
                    connector_certificate_file: cursor.path()?,
                    connector_private_key_file: cursor.path()?,
                })
            }
            _ => return Err(process_error(ProcessErrorKind::NodeDiscovery)),
        };
        Ok(DistributedPredecessorCapabilityV1 {
            expected_target,
            managed: ManagedServingArguments {
                bootstrap,
                successor_directory,
                successor_store_id,
            },
            node: DistributedNodeCapabilityV1 {
                expected_target,
                management_target,
                socket_path,
                token,
                expected_uid: node_uid,
                expected_gid: node_gid,
                topology_wire,
            },
            connector,
        })
    }

    fn encode_distributed_predecessor(
        wire: &mut Vec<u8>,
        predecessor: &DistributedPredecessorCapabilityV1,
        wire_version: u16,
    ) -> Result<(), DeploymentdProcessError> {
        let arguments = &predecessor.managed.bootstrap;
        wire.extend_from_slice(predecessor.expected_target.as_bytes());
        encode_path(wire, &arguments.common.state_directory)?;
        wire.extend_from_slice(&arguments.common.scope);
        wire.extend_from_slice(&arguments.common.plan);
        wire.extend_from_slice(&arguments.common.request_auth_key);
        encode_path(wire, &arguments.common.public_key_path)?;
        wire.extend_from_slice(&arguments.expected_store_id);
        encode_path(wire, &arguments.controller_private_seed_path)?;
        wire.extend_from_slice(&arguments.controller_principal);
        wire.extend_from_slice(&arguments.writer_ref);
        wire.extend_from_slice(&arguments.authority_principal);
        wire.extend_from_slice(&arguments.authority_uid.to_be_bytes());
        wire.extend_from_slice(&arguments.authority_gid.to_be_bytes());
        wire.extend_from_slice(&arguments.tenure_authority_ref);
        wire.extend_from_slice(&arguments.tenure_key_ref);
        encode_path(wire, &arguments.authority_public_key_path)?;
        encode_path(wire, &arguments.runtime_socket_path)?;
        wire.extend_from_slice(&arguments.runtime_principal);
        wire.extend_from_slice(&arguments.runtime_response_key_ref);
        encode_path(wire, &arguments.runtime_response_public_key_path)?;
        wire.extend_from_slice(&arguments.runtime_uid.to_be_bytes());
        wire.extend_from_slice(&arguments.runtime_gid.to_be_bytes());
        encode_path(wire, &predecessor.managed.successor_directory)?;
        wire.extend_from_slice(&predecessor.managed.successor_store_id);
        wire.extend_from_slice(predecessor.node.management_target.node_id().as_bytes());
        wire.extend_from_slice(
            predecessor
                .node
                .management_target
                .management_endpoint_ref()
                .as_bytes(),
        );
        wire.extend_from_slice(
            predecessor
                .node
                .management_target
                .node_incarnation()
                .as_bytes(),
        );
        wire.extend_from_slice(
            &predecessor
                .node
                .management_target
                .registration_epoch()
                .to_be_bytes(),
        );
        encode_path(wire, &predecessor.node.socket_path)?;
        wire.extend_from_slice(predecessor.node.token.as_ref());
        wire.extend_from_slice(&predecessor.node.expected_uid.to_be_bytes());
        wire.extend_from_slice(&predecessor.node.expected_gid.to_be_bytes());
        wire.extend_from_slice(
            &u32::try_from(predecessor.node.topology_wire.len())
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?
                .to_be_bytes(),
        );
        wire.extend_from_slice(&predecessor.node.topology_wire);
        match (wire_version, predecessor.connector.as_ref()) {
            (DISTRIBUTED_CAPABILITY_VERSION_V1, None) => {}
            (DISTRIBUTED_CAPABILITY_VERSION_V2, Some(connector)) => {
                wire.extend_from_slice(&connector.profile_ref);
                wire.extend_from_slice(
                    &u32::try_from(connector.transport_profile.canonical_wire().len())
                        .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?
                        .to_be_bytes(),
                );
                wire.extend_from_slice(connector.transport_profile.canonical_wire());
                encode_path(wire, &connector.root_ca_certificate_file)?;
                encode_path(wire, &connector.connector_certificate_file)?;
                encode_path(wire, &connector.connector_private_key_file)?;
            }
            _ => return Err(process_error(ProcessErrorKind::NodeDiscovery)),
        }
        Ok(())
    }

    fn encode_path(wire: &mut Vec<u8>, path: &Path) -> Result<(), DeploymentdProcessError> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_DISTRIBUTED_CAPABILITY_PATH_BYTES {
            return Err(process_error(ProcessErrorKind::NodeDiscovery));
        }
        wire.extend_from_slice(
            &u16::try_from(bytes.len())
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?
                .to_be_bytes(),
        );
        wire.extend_from_slice(bytes);
        Ok(())
    }

    fn distributed_capability_checksum(bytes: &[u8]) -> Result<Digest32, DeploymentdProcessError> {
        let mut builder = Digest32Builder::try_new(DISTRIBUTED_CAPABILITY_CHECKSUM_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        builder
            .field_bytes(bytes)
            .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))?;
        Ok(builder.finish())
    }

    struct DistributedCapabilityCursor<'a> {
        bytes: &'a [u8],
        position: usize,
    }

    impl<'a> DistributedCapabilityCursor<'a> {
        const fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, position: 0 }
        }

        fn take(&mut self, length: usize) -> Result<&'a [u8], DeploymentdProcessError> {
            let end = self
                .position
                .checked_add(length)
                .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
            let value = self
                .bytes
                .get(self.position..end)
                .ok_or_else(|| process_error(ProcessErrorKind::NodeDiscovery))?;
            self.position = end;
            Ok(value)
        }

        fn array<const N: usize>(&mut self) -> Result<[u8; N], DeploymentdProcessError> {
            self.take(N)?
                .try_into()
                .map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))
        }

        fn nonzero_array<const N: usize>(&mut self) -> Result<[u8; N], DeploymentdProcessError> {
            let value = self.array()?;
            if value.iter().all(|byte| *byte == 0) {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            Ok(value)
        }

        fn u16(&mut self) -> Result<u16, DeploymentdProcessError> {
            Ok(u16::from_be_bytes(self.array()?))
        }

        fn u32(&mut self) -> Result<u32, DeploymentdProcessError> {
            Ok(u32::from_be_bytes(self.array()?))
        }

        fn u64(&mut self) -> Result<u64, DeploymentdProcessError> {
            Ok(u64::from_be_bytes(self.array()?))
        }

        fn nonzero_u32(&mut self) -> Result<u32, DeploymentdProcessError> {
            let value = self.u32()?;
            if value == 0 {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            Ok(value)
        }

        fn nonzero_u64(&mut self) -> Result<u64, DeploymentdProcessError> {
            let value = self.u64()?;
            if value == 0 {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            Ok(value)
        }

        fn usize_u32(&mut self) -> Result<usize, DeploymentdProcessError> {
            usize::try_from(self.u32()?).map_err(|_| process_error(ProcessErrorKind::NodeDiscovery))
        }

        fn path(&mut self) -> Result<PathBuf, DeploymentdProcessError> {
            let length = usize::from(self.u16()?);
            if length == 0 || length > MAX_DISTRIBUTED_CAPABILITY_PATH_BYTES {
                return Err(process_error(ProcessErrorKind::NodeDiscovery));
            }
            let path = PathBuf::from(OsString::from_vec(self.take(length)?.to_vec()));
            parse_absolute_path(path.as_os_str())
        }

        fn finish(self) -> Result<(), DeploymentdProcessError> {
            if self.position == self.bytes.len() {
                Ok(())
            } else {
                Err(process_error(ProcessErrorKind::NodeDiscovery))
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ProcessCommand {
        Initialize(InitializeArguments),
        MigrateControllerJournal(ControllerJournalMigrationArguments),
        CommitReferenceLoop(CommitArguments),
        CommitReferenceEmpty(CommitEmptyArguments),
        AcquireTenure(AcquireTenureArguments),
        BootstrapRuntime(BootstrapArguments),
        ObserveManagedServing(ManagedServingArguments),
        CommitAgentStack(Box<AgentStackCommitArguments>),
        ApplyAgentStack(ManagedServingArguments),
        DeactivateAgentStack(ManagedServingArguments),
        InitializeDistributedAgentStack(PathBuf),
        ObserveDistributedAgentStackNodesOnce(PathBuf),
        ApplyDistributedAgentStackOnce(PathBuf),
        ApplyReference(BootstrapArguments),
        ReconcileReferenceOnce(BootstrapArguments),
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ControllerJournalMigrationArguments {
        state_directory: PathBuf,
        evidence_directory: PathBuf,
        expected_store_id: [u8; 32],
        expected_owner_identity: [u8; 32],
        migration_id: [u8; 32],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CommonArguments {
        state_directory: PathBuf,
        scope: [u8; 16],
        plan: [u8; 16],
        request_auth_key: [u8; 16],
        public_key_path: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct InitializeArguments {
        common: CommonArguments,
        manifest_path: PathBuf,
        manifest_digest: Digest32,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CommitArguments {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        deck_key: [u8; 16],
        card_use_key: [u8; 16],
        definition_version: u32,
        operation_id: [u8; 16],
        start_nanos: u64,
        drain_nanos: u64,
        cleanup_nanos: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CommitEmptyArguments {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        operation_id: [u8; 16],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct AcquireTenureArguments {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        controller_private_seed_path: PathBuf,
        controller_principal: [u8; 16],
        writer_ref: [u8; 16],
        tenure_authority_ref: [u8; 16],
        tenure_key_ref: [u8; 16],
        authority_public_key_path: PathBuf,
        authority_socket_path: PathBuf,
        authority_uid: u32,
        authority_gid: u32,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct BootstrapArguments {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        controller_private_seed_path: PathBuf,
        controller_principal: [u8; 16],
        writer_ref: [u8; 16],
        authority_principal: [u8; 16],
        authority_uid: u32,
        authority_gid: u32,
        tenure_authority_ref: [u8; 16],
        tenure_key_ref: [u8; 16],
        authority_public_key_path: PathBuf,
        runtime_socket_path: PathBuf,
        runtime_principal: [u8; 16],
        runtime_response_key_ref: [u8; 16],
        runtime_response_public_key_path: PathBuf,
        runtime_uid: u32,
        runtime_gid: u32,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ManagedServingArguments {
        bootstrap: BootstrapArguments,
        successor_directory: PathBuf,
        successor_store_id: [u8; 32],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct AgentStackCommitArguments {
        managed: ManagedServingArguments,
        service_id: [u8; 16],
        lifecycle_budgets: [u64; 5],
        semantic_limits: [u16; 4],
        submit_binding: [u8; 16],
        control_binding: [u8; 16],
        submit_key_expression: String,
        control_key_expression: String,
        ingress_max_items: u32,
        ingress_max_bytes: u64,
        ingress_max_frame_bytes: u32,
        ingress_max_response_body_bytes: u32,
        handler_timeout_nanos: u64,
        provider: AgentStackProviderArguments,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum AgentStackProviderArguments {
        DeterministicFixture {
            provider_ref: [u8; 16],
            config_digest: [u8; 32],
        },
        Provisioned {
            provider_ref: [u8; 16],
            config_digest: [u8; 32],
            secret_ref: [u8; 16],
        },
    }

    fn parse_arguments(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<ProcessCommand, DeploymentdProcessError> {
        let arguments = arguments
            .into_iter()
            .take(MAX_ARGUMENTS + 1)
            .collect::<Vec<_>>();
        let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
            return Err(process_error(ProcessErrorKind::Arguments));
        };
        match command {
            "initialize-distributed-agent-stack-v1" if arguments.len() == 2 => {
                Ok(ProcessCommand::InitializeDistributedAgentStack(
                    parse_absolute_file_path(&arguments[1])?,
                ))
            }
            "observe-distributed-agent-stack-nodes-once-v1" if arguments.len() == 2 => {
                Ok(ProcessCommand::ObserveDistributedAgentStackNodesOnce(
                    parse_absolute_file_path(&arguments[1])?,
                ))
            }
            "apply-distributed-agent-stack-once-v1" if arguments.len() == 2 => {
                Ok(ProcessCommand::ApplyDistributedAgentStackOnce(
                    parse_absolute_file_path(&arguments[1])?,
                ))
            }
            "migrate-controller-journal-v7-to-v8-v1" if arguments.len() == 6 => Ok(
                ProcessCommand::MigrateControllerJournal(ControllerJournalMigrationArguments {
                    state_directory: parse_absolute_path(&arguments[1])?,
                    evidence_directory: parse_absolute_path(&arguments[2])?,
                    expected_store_id: parse_nonzero_hex(&arguments[3])?,
                    expected_owner_identity: parse_nonzero_hex(&arguments[4])?,
                    migration_id: parse_nonzero_hex(&arguments[5])?,
                }),
            ),
            "initialize-reference-v1" if arguments.len() == 10 => {
                Ok(ProcessCommand::Initialize(InitializeArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[4])?,
                        plan: parse_nonzero_hex(&arguments[5])?,
                        request_auth_key: parse_nonzero_hex(&arguments[6])?,
                        public_key_path: parse_absolute_file_path(&arguments[7])?,
                        expected_uid: parse_nonzero_u32(&arguments[8])?,
                        expected_gid: parse_nonzero_u32(&arguments[9])?,
                    },
                    manifest_path: parse_absolute_file_path(&arguments[2])?,
                    manifest_digest: Digest32::from_bytes(parse_nonzero_hex(&arguments[3])?),
                }))
            }
            "commit-reference-loop-v1" if arguments.len() == 16 => {
                Ok(ProcessCommand::CommitReferenceLoop(CommitArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[3])?,
                        plan: parse_nonzero_hex(&arguments[4])?,
                        request_auth_key: parse_nonzero_hex(&arguments[5])?,
                        public_key_path: parse_absolute_file_path(&arguments[6])?,
                        expected_uid: parse_nonzero_u32(&arguments[7])?,
                        expected_gid: parse_nonzero_u32(&arguments[8])?,
                    },
                    expected_store_id: parse_nonzero_hex(&arguments[2])?,
                    deck_key: parse_nonzero_hex(&arguments[9])?,
                    card_use_key: parse_nonzero_hex(&arguments[10])?,
                    definition_version: parse_nonzero_u32(&arguments[11])?,
                    operation_id: parse_nonzero_hex(&arguments[12])?,
                    start_nanos: parse_nonzero_u64(&arguments[13])?,
                    drain_nanos: parse_nonzero_u64(&arguments[14])?,
                    cleanup_nanos: parse_nonzero_u64(&arguments[15])?,
                }))
            }
            "commit-reference-empty-v1" if arguments.len() == 10 => {
                Ok(ProcessCommand::CommitReferenceEmpty(CommitEmptyArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[3])?,
                        plan: parse_nonzero_hex(&arguments[4])?,
                        request_auth_key: parse_nonzero_hex(&arguments[5])?,
                        public_key_path: parse_absolute_file_path(&arguments[6])?,
                        expected_uid: parse_nonzero_u32(&arguments[7])?,
                        expected_gid: parse_nonzero_u32(&arguments[8])?,
                    },
                    expected_store_id: parse_nonzero_hex(&arguments[2])?,
                    operation_id: parse_nonzero_hex(&arguments[9])?,
                }))
            }
            "acquire-tenure-v1" if arguments.len() == 18 => {
                Ok(ProcessCommand::AcquireTenure(AcquireTenureArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[3])?,
                        plan: parse_nonzero_hex(&arguments[4])?,
                        request_auth_key: parse_nonzero_hex(&arguments[5])?,
                        public_key_path: parse_absolute_file_path(&arguments[6])?,
                        expected_uid: parse_nonzero_u32(&arguments[8])?,
                        expected_gid: parse_nonzero_u32(&arguments[9])?,
                    },
                    expected_store_id: parse_nonzero_hex(&arguments[2])?,
                    controller_private_seed_path: parse_absolute_file_path(&arguments[7])?,
                    controller_principal: parse_nonzero_hex(&arguments[10])?,
                    writer_ref: parse_nonzero_hex(&arguments[11])?,
                    tenure_authority_ref: parse_nonzero_hex(&arguments[12])?,
                    tenure_key_ref: parse_nonzero_hex(&arguments[13])?,
                    authority_public_key_path: parse_absolute_file_path(&arguments[14])?,
                    authority_socket_path: parse_absolute_file_path(&arguments[15])?,
                    authority_uid: parse_nonzero_u32(&arguments[16])?,
                    authority_gid: parse_nonzero_u32(&arguments[17])?,
                }))
            }
            command @ ("bootstrap-runtime-v1"
            | "apply-reference-v1"
            | "reconcile-reference-once-v1")
                if arguments.len() == 24 =>
            {
                let parsed = BootstrapArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[3])?,
                        plan: parse_nonzero_hex(&arguments[4])?,
                        request_auth_key: parse_nonzero_hex(&arguments[5])?,
                        public_key_path: parse_absolute_file_path(&arguments[6])?,
                        expected_uid: parse_nonzero_u32(&arguments[8])?,
                        expected_gid: parse_nonzero_u32(&arguments[9])?,
                    },
                    expected_store_id: parse_nonzero_hex(&arguments[2])?,
                    controller_private_seed_path: parse_absolute_file_path(&arguments[7])?,
                    controller_principal: parse_nonzero_hex(&arguments[10])?,
                    writer_ref: parse_nonzero_hex(&arguments[11])?,
                    authority_principal: parse_nonzero_hex(&arguments[12])?,
                    authority_uid: parse_nonzero_u32(&arguments[13])?,
                    authority_gid: parse_nonzero_u32(&arguments[14])?,
                    tenure_authority_ref: parse_nonzero_hex(&arguments[15])?,
                    tenure_key_ref: parse_nonzero_hex(&arguments[16])?,
                    authority_public_key_path: parse_absolute_file_path(&arguments[17])?,
                    runtime_socket_path: parse_absolute_file_path(&arguments[18])?,
                    runtime_principal: parse_nonzero_hex(&arguments[19])?,
                    runtime_response_key_ref: parse_nonzero_hex(&arguments[20])?,
                    runtime_response_public_key_path: parse_absolute_file_path(&arguments[21])?,
                    runtime_uid: parse_nonzero_u32(&arguments[22])?,
                    runtime_gid: parse_nonzero_u32(&arguments[23])?,
                };
                if command == "bootstrap-runtime-v1" {
                    Ok(ProcessCommand::BootstrapRuntime(parsed))
                } else if command == "apply-reference-v1" {
                    Ok(ProcessCommand::ApplyReference(parsed))
                } else {
                    Ok(ProcessCommand::ReconcileReferenceOnce(parsed))
                }
            }
            "observe-managed-serving-v1" if arguments.len() == 26 => Ok(
                ProcessCommand::ObserveManagedServing(parse_managed_serving_arguments(&arguments)?),
            ),
            "apply-agent-stack-v1" if arguments.len() == 26 => Ok(ProcessCommand::ApplyAgentStack(
                parse_managed_serving_arguments(&arguments)?,
            )),
            "deactivate-agent-stack-v1" if arguments.len() == 26 => Ok(
                ProcessCommand::DeactivateAgentStack(parse_managed_serving_arguments(&arguments)?),
            ),
            "commit-agent-stack-v1" if arguments.len() == 49 => {
                Ok(ProcessCommand::CommitAgentStack(Box::new(
                    parse_agent_stack_commit_arguments(&arguments)?,
                )))
            }
            _ => Err(process_error(ProcessErrorKind::Arguments)),
        }
    }

    fn parse_managed_serving_arguments(
        arguments: &[OsString],
    ) -> Result<ManagedServingArguments, DeploymentdProcessError> {
        Ok(ManagedServingArguments {
            bootstrap: BootstrapArguments {
                common: CommonArguments {
                    state_directory: parse_absolute_path(&arguments[1])?,
                    scope: parse_nonzero_hex(&arguments[5])?,
                    plan: parse_nonzero_hex(&arguments[6])?,
                    request_auth_key: parse_nonzero_hex(&arguments[7])?,
                    public_key_path: parse_absolute_file_path(&arguments[8])?,
                    expected_uid: parse_nonzero_u32(&arguments[10])?,
                    expected_gid: parse_nonzero_u32(&arguments[11])?,
                },
                expected_store_id: parse_nonzero_hex(&arguments[3])?,
                controller_private_seed_path: parse_absolute_file_path(&arguments[9])?,
                controller_principal: parse_nonzero_hex(&arguments[12])?,
                writer_ref: parse_nonzero_hex(&arguments[13])?,
                authority_principal: parse_nonzero_hex(&arguments[14])?,
                authority_uid: parse_nonzero_u32(&arguments[15])?,
                authority_gid: parse_nonzero_u32(&arguments[16])?,
                tenure_authority_ref: parse_nonzero_hex(&arguments[17])?,
                tenure_key_ref: parse_nonzero_hex(&arguments[18])?,
                authority_public_key_path: parse_absolute_file_path(&arguments[19])?,
                runtime_socket_path: parse_absolute_file_path(&arguments[20])?,
                runtime_principal: parse_nonzero_hex(&arguments[21])?,
                runtime_response_key_ref: parse_nonzero_hex(&arguments[22])?,
                runtime_response_public_key_path: parse_absolute_file_path(&arguments[23])?,
                runtime_uid: parse_nonzero_u32(&arguments[24])?,
                runtime_gid: parse_nonzero_u32(&arguments[25])?,
            },
            successor_directory: parse_absolute_path(&arguments[2])?,
            successor_store_id: parse_nonzero_hex(&arguments[4])?,
        })
    }

    fn parse_agent_stack_commit_arguments(
        arguments: &[OsString],
    ) -> Result<AgentStackCommitArguments, DeploymentdProcessError> {
        let provider_ref = parse_nonzero_hex(&arguments[46])?;
        let config_digest = parse_nonzero_hex(&arguments[47])?;
        let profile = arguments[45]
            .to_str()
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?;
        let provider = match profile {
            "deterministic-fixture" if arguments[48] == OsStr::new("none") => {
                AgentStackProviderArguments::DeterministicFixture {
                    provider_ref,
                    config_digest,
                }
            }
            "provisioned" => AgentStackProviderArguments::Provisioned {
                provider_ref,
                config_digest,
                secret_ref: parse_nonzero_hex(&arguments[48])?,
            },
            _ => return Err(process_error(ProcessErrorKind::Arguments)),
        };
        let semantic = [
            parse_nonzero_u16(&arguments[32])?,
            parse_nonzero_u16(&arguments[33])?,
            parse_nonzero_u16(&arguments[34])?,
            parse_nonzero_u16(&arguments[35])?,
        ];
        let submit_key_expression = arguments[38]
            .to_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?
            .to_owned();
        let control_key_expression = arguments[39]
            .to_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?
            .to_owned();
        Ok(AgentStackCommitArguments {
            managed: parse_managed_serving_arguments(arguments)?,
            service_id: parse_nonzero_hex(&arguments[26])?,
            lifecycle_budgets: [
                parse_nonzero_u64(&arguments[27])?,
                parse_nonzero_u64(&arguments[28])?,
                parse_nonzero_u64(&arguments[29])?,
                parse_nonzero_u64(&arguments[30])?,
                parse_nonzero_u64(&arguments[31])?,
            ],
            semantic_limits: semantic,
            submit_binding: parse_nonzero_hex(&arguments[36])?,
            control_binding: parse_nonzero_hex(&arguments[37])?,
            submit_key_expression,
            control_key_expression,
            ingress_max_items: parse_nonzero_u32(&arguments[40])?,
            ingress_max_bytes: parse_nonzero_u64(&arguments[41])?,
            ingress_max_frame_bytes: parse_nonzero_u32(&arguments[42])?,
            ingress_max_response_body_bytes: parse_nonzero_u32(&arguments[43])?,
            handler_timeout_nanos: parse_nonzero_u64(&arguments[44])?,
            provider,
        })
    }

    fn parse_absolute_file_path(value: &OsStr) -> Result<PathBuf, DeploymentdProcessError> {
        let path = parse_absolute_path(value)?;
        if path.parent().is_none() || path.file_name().is_none() {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(path)
    }

    fn parse_absolute_path(value: &OsStr) -> Result<PathBuf, DeploymentdProcessError> {
        let path = PathBuf::from(value);
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || bytes.len() <= 1
            || bytes.first() != Some(&b'/')
            || bytes.last() == Some(&b'/')
            || bytes.contains(&0)
            || bytes.windows(2).any(|window| window == b"//")
            || bytes[1..]
                .split(|byte| *byte == b'/')
                .any(|component| component == b"." || component == b"..")
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir | Component::ParentDir | Component::Prefix(_)
                )
            })
        {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(path)
    }

    fn parse_nonzero_hex<const N: usize>(
        value: &OsStr,
    ) -> Result<[u8; N], DeploymentdProcessError> {
        let value = value
            .to_str()
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?;
        if value.len() != N.saturating_mul(2) {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        let mut decoded = [0; N];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        if decoded.iter().all(|byte| *byte == 0) {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(decoded)
    }

    fn hex_nibble(value: u8) -> Result<u8, DeploymentdProcessError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(process_error(ProcessErrorKind::Arguments)),
        }
    }

    fn parse_nonzero_u32(value: &OsStr) -> Result<u32, DeploymentdProcessError> {
        let value = parse_nonzero_u64(value)?;
        u32::try_from(value).map_err(|_| process_error(ProcessErrorKind::Arguments))
    }

    fn parse_nonzero_u16(value: &OsStr) -> Result<u16, DeploymentdProcessError> {
        let parsed = parse_nonzero_u32(value)?;
        u16::try_from(parsed).map_err(|_| process_error(ProcessErrorKind::Arguments))
    }

    fn parse_nonzero_u64(value: &OsStr) -> Result<u64, DeploymentdProcessError> {
        let value = value
            .to_str()
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?;
        if value.is_empty()
            || value == "0"
            || value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        value
            .parse()
            .map_err(|_| process_error(ProcessErrorKind::Arguments))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        length: u64,
    }

    impl FileIdentity {
        fn from_metadata(metadata: &Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
            }
        }
    }

    struct PinnedFile {
        bytes: Zeroizing<Box<[u8]>>,
        identity: FileIdentity,
    }

    #[derive(Clone, Copy)]
    enum FileRole {
        Manifest,
        PublicKey,
        PrivateSeed,
        Capability,
    }

    #[derive(Clone, Copy)]
    enum FileLengthPolicy {
        Exact(usize),
        BoundedNonZero(usize),
    }

    fn read_pinned_file(
        path: &Path,
        length_policy: FileLengthPolicy,
        role: FileRole,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<PinnedFile, DeploymentdProcessError> {
        validate_existing_path_chain(path)?;
        validate_trusted_ancestors(path, expected_uid)?;
        let before = fs::symlink_metadata(path).map_err(|_| file_error(role))?;
        let observed_length =
            validate_file_metadata(&before, length_policy, role, expected_uid, expected_gid)?;
        let owned = open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| file_error(role))?;
        let mut file = File::from(owned);
        let opened = file.metadata().map_err(|_| file_error(role))?;
        let opened_length =
            validate_file_metadata(&opened, length_policy, role, expected_uid, expected_gid)?;
        let identity = FileIdentity::from_metadata(&opened);
        if FileIdentity::from_metadata(&before) != identity || opened_length != observed_length {
            return Err(file_error(role));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(observed_length)
            .map_err(|_| file_error(role))?;
        bytes.resize(observed_length, 0);
        file.read_exact(&mut bytes).map_err(|_| file_error(role))?;
        let mut trailing = [0; 1];
        if file.read(&mut trailing).map_err(|_| file_error(role))? != 0 {
            return Err(file_error(role));
        }
        let after = file.metadata().map_err(|_| file_error(role))?;
        let after_length =
            validate_file_metadata(&after, length_policy, role, expected_uid, expected_gid)?;
        if FileIdentity::from_metadata(&after) != identity || after_length != observed_length {
            return Err(file_error(role));
        }
        Ok(PinnedFile {
            bytes: Zeroizing::new(bytes.into_boxed_slice()),
            identity,
        })
    }

    fn validate_file_metadata(
        metadata: &Metadata,
        length_policy: FileLengthPolicy,
        role: FileRole,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<usize, DeploymentdProcessError> {
        let length = usize::try_from(metadata.len()).map_err(|_| file_error(role))?;
        let valid_length = match length_policy {
            FileLengthPolicy::Exact(expected) => length == expected,
            FileLengthPolicy::BoundedNonZero(maximum) => length != 0 && length <= maximum,
        };
        let mode = metadata.mode() & 0o7777;
        let valid_mode = match role {
            FileRole::Manifest => mode == 0o600,
            FileRole::PrivateSeed | FileRole::Capability => mode == 0o400,
            FileRole::PublicKey => {
                mode & 0o400 == 0o400
                    && mode & 0o022 == 0
                    && mode & 0o111 == 0
                    && mode & 0o7000 == 0
            }
        };
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.uid() != expected_uid
            || metadata.gid() != expected_gid
            || !valid_length
            || !valid_mode
        {
            return Err(file_error(role));
        }
        Ok(length)
    }

    fn validate_existing_path_chain(path: &Path) -> Result<(), DeploymentdProcessError> {
        let mut current = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir => current.push(component.as_os_str()),
                Component::Normal(value) => {
                    current.push(value);
                    let metadata = fs::symlink_metadata(&current)
                        .map_err(|_| process_error(ProcessErrorKind::Path))?;
                    if metadata.file_type().is_symlink() {
                        return Err(process_error(ProcessErrorKind::Path));
                    }
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(process_error(ProcessErrorKind::Path));
                }
            }
        }
        Ok(())
    }

    fn validate_trusted_ancestors(
        path: &Path,
        service_uid: u32,
    ) -> Result<(), DeploymentdProcessError> {
        let parent = path
            .parent()
            .ok_or_else(|| process_error(ProcessErrorKind::Path))?;
        let mut current = PathBuf::new();
        for component in parent.components() {
            match component {
                Component::RootDir => current.push(component.as_os_str()),
                Component::Normal(value) => current.push(value),
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(process_error(ProcessErrorKind::Path));
                }
            }
            let metadata = fs::symlink_metadata(&current)
                .map_err(|_| process_error(ProcessErrorKind::Path))?;
            let owner = metadata.uid();
            let mode = metadata.mode() & 0o7777;
            let root_sticky = owner == 0 && mode & 0o1000 != 0;
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || (owner != 0 && owner != service_uid)
                || (mode & 0o022 != 0 && !root_sticky)
            {
                return Err(process_error(ProcessErrorKind::Path));
            }
        }
        Ok(())
    }

    const fn file_error(role: FileRole) -> DeploymentdProcessError {
        match role {
            FileRole::Manifest => DeploymentdProcessError::new(ProcessErrorKind::Manifest),
            FileRole::PublicKey | FileRole::PrivateSeed => {
                DeploymentdProcessError::new(ProcessErrorKind::Key)
            }
            FileRole::Capability => DeploymentdProcessError::new(ProcessErrorKind::NodeDiscovery),
        }
    }

    const fn process_error(kind: ProcessErrorKind) -> DeploymentdProcessError {
        DeploymentdProcessError::new(kind)
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::OsString;
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        use ed25519_dalek::SigningKey;
        use nix::unistd::{getegid, geteuid};
        use paraegox_kernel::digest::Digest32;
        use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
        use paraegox_kernel::time::BoundedDuration;
        use paraegox_node::protocol::NodeManagementTargetV1;
        use paraegox_node::{NodeId, NodeIncarnation, NodeManagementEndpointRefV1};
        use paraegox_runtime_contracts::distributed_agent_stack_plan::{
            DistributedFabricCredentialRefV1, DistributedFabricTrustAnchorRefV1,
            DistributedFabricTrustDomainRefV1, RestrictedRuntimeApplyTransportProfileFieldsV1,
            RestrictedRuntimeApplyTransportProfileV1,
        };
        use paraegox_runtime_contracts::reference_control::ValidatedReferenceLifecycleBudgetsV1;
        use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
        use zeroize::Zeroizing;

        use crate::controller_journal::{
            ControllerAuthKeyFingerprint, ControllerJournalError, ControllerJournalState,
            ControllerOperationId, ControllerRequestAuthPin,
            ControllerTenureAuthorityDomainFingerprint, controller_test_manifest,
            tests::{decided_snapshot, direct_active_snapshot},
        };
        use crate::controller_store::{
            ControllerCommitFailpoint, ControllerFilesystemPolicy, ControllerStore,
            create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
            open_controller_directory, publish_initial_controller_snapshot,
        };
        use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
        use crate::planner::StableAllocationSnapshot;
        use crate::tenure_protocol::{
            ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        };

        use super::{
            APPLY_ENTROPY_BYTES, BootstrapArguments, CommonArguments,
            DistributedAgentStackRolloutStatusV1, DistributedCoordinatorCapabilityV1,
            DistributedLocalCapabilityV1, DistributedNodeCapabilityV1,
            DistributedPredecessorCapabilityV1,
            DistributedRestrictedControllerConnectorCapabilityV1, DurableTenureRequest,
            FileLengthPolicy, FileRole, FreshControllerApplyRequestV1, ManagedServingArguments,
            ProcessCommand, ProcessErrorKind, TENURE_ENTROPY_BYTES, TenureRequestProfile,
            build_empty_commit_receipt, build_reference_candidate, build_reference_empty_candidate,
            commit_reference_empty_in_store,
            distributed_owner_terminal_runtime_observation_is_admissible,
            fresh_apply_request_from_entropy, fresh_tenure_request_from_entropy, parse_arguments,
            parse_nonzero_hex, read_pinned_file, recover_tenure_request,
            select_durable_tenure_request, validate_committed_empty_state,
        };

        static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(1);

        fn hex(byte: u8, length: usize) -> OsString {
            OsString::from(format!("{byte:02x}").repeat(length))
        }

        fn initialize_arguments() -> Vec<OsString> {
            vec![
                "initialize-reference-v1".into(),
                "/tmp/paraegox-controller".into(),
                "/tmp/runtime.pxcm".into(),
                hex(0x11, 32),
                hex(0x12, 16),
                hex(0x13, 16),
                hex(0x14, 16),
                "/tmp/controller.pub".into(),
                "501".into(),
                "20".into(),
            ]
        }

        fn bootstrap_arguments() -> Vec<OsString> {
            vec![
                "bootstrap-runtime-v1".into(),
                "/tmp/paraegox-controller".into(),
                hex(0x31, 32),
                hex(0x32, 16),
                hex(0x33, 16),
                hex(0x34, 16),
                "/tmp/controller.pub".into(),
                "/tmp/controller.seed".into(),
                "501".into(),
                "20".into(),
                hex(0x35, 16),
                hex(0x36, 16),
                hex(0x37, 16),
                "502".into(),
                "21".into(),
                hex(0x38, 16),
                hex(0x39, 16),
                "/tmp/authority.pub".into(),
                "/tmp/runtime.sock".into(),
                hex(0x3a, 16),
                hex(0x3b, 16),
                "/tmp/runtime-response.pub".into(),
                "503".into(),
                "22".into(),
            ]
        }

        fn managed_serving_arguments() -> Vec<OsString> {
            vec![
                "observe-managed-serving-v1".into(),
                "/tmp/paraegox-controller".into(),
                "/tmp/paraegox-managed-controller".into(),
                hex(0x31, 32),
                hex(0x30, 32),
                hex(0x32, 16),
                hex(0x33, 16),
                hex(0x34, 16),
                "/tmp/controller.pub".into(),
                "/tmp/controller.seed".into(),
                "501".into(),
                "20".into(),
                hex(0x35, 16),
                hex(0x36, 16),
                hex(0x37, 16),
                "502".into(),
                "21".into(),
                hex(0x38, 16),
                hex(0x39, 16),
                "/tmp/authority.pub".into(),
                "/tmp/runtime.sock".into(),
                hex(0x3a, 16),
                hex(0x3b, 16),
                "/tmp/runtime-response.pub".into(),
                "503".into(),
                "22".into(),
            ]
        }

        fn tenure_arguments() -> Vec<OsString> {
            vec![
                "acquire-tenure-v1".into(),
                "/tmp/paraegox-controller".into(),
                hex(0x51, 32),
                hex(0x52, 16),
                hex(0x53, 16),
                hex(0x54, 16),
                "/tmp/controller.pub".into(),
                "/tmp/controller.seed".into(),
                "501".into(),
                "20".into(),
                hex(0x55, 16),
                hex(0x56, 16),
                hex(0x57, 16),
                hex(0x58, 16),
                "/tmp/authority.pub".into(),
                "/tmp/authority.sock".into(),
                "502".into(),
                "21".into(),
            ]
        }

        fn migration_arguments() -> Vec<OsString> {
            vec![
                "migrate-controller-journal-v7-to-v8-v1".into(),
                "/tmp/paraegox-controller".into(),
                "/tmp/paraegox-controller-migration-evidence".into(),
                hex(0x61, 32),
                hex(0x62, 32),
                hex(0x63, 32),
            ]
        }

        fn distributed_capability_fixture(
            first_token: u8,
            second_token: u8,
        ) -> DistributedLocalCapabilityV1 {
            let expected_uid = geteuid().as_raw().max(1);
            let expected_gid = getegid().as_raw().max(1);
            let common = |name: &str| CommonArguments {
                state_directory: PathBuf::from(format!("/tmp/paraegox-pxnc-{name}-state")),
                scope: [0x11; 16],
                plan: [0x12; 16],
                request_auth_key: [0x13; 16],
                public_key_path: PathBuf::from(format!("/tmp/paraegox-pxnc-{name}-controller.pub")),
                expected_uid,
                expected_gid,
            };
            let predecessor = |name: &str, byte: u8, token: u8| {
                let expected_target = RuntimeHostId::from_bytes([byte; 16]);
                DistributedPredecessorCapabilityV1 {
                    expected_target,
                    managed: ManagedServingArguments {
                        bootstrap: BootstrapArguments {
                            common: common(name),
                            expected_store_id: [byte.wrapping_add(1); 32],
                            controller_private_seed_path: PathBuf::from(format!(
                                "/tmp/paraegox-pxnc-{name}-controller.seed"
                            )),
                            controller_principal: [byte.wrapping_add(2); 16],
                            writer_ref: [byte.wrapping_add(3); 16],
                            authority_principal: [byte.wrapping_add(4); 16],
                            authority_uid: expected_uid,
                            authority_gid: expected_gid,
                            tenure_authority_ref: [byte.wrapping_add(5); 16],
                            tenure_key_ref: [byte.wrapping_add(6); 16],
                            authority_public_key_path: PathBuf::from(format!(
                                "/tmp/paraegox-pxnc-{name}-authority.pub"
                            )),
                            runtime_socket_path: PathBuf::from(format!(
                                "/tmp/paraegox-pxnc-{name}-runtime.sock"
                            )),
                            runtime_principal: [byte.wrapping_add(7); 16],
                            runtime_response_key_ref: [byte.wrapping_add(8); 16],
                            runtime_response_public_key_path: PathBuf::from(format!(
                                "/tmp/paraegox-pxnc-{name}-runtime.pub"
                            )),
                            runtime_uid: expected_uid,
                            runtime_gid: expected_gid,
                        },
                        successor_directory: PathBuf::from(format!(
                            "/tmp/paraegox-pxnc-{name}-successor"
                        )),
                        successor_store_id: [byte.wrapping_add(9); 32],
                    },
                    node: DistributedNodeCapabilityV1 {
                        expected_target,
                        management_target: NodeManagementTargetV1::try_new(
                            NodeId::try_from_bytes([byte.wrapping_add(10); 16])
                                .expect("nonzero node id"),
                            NodeManagementEndpointRefV1::try_from_bytes(
                                [byte.wrapping_add(11); 16],
                            )
                            .expect("nonzero endpoint ref"),
                            NodeIncarnation::try_from_bytes([byte.wrapping_add(12); 16])
                                .expect("nonzero incarnation"),
                            u64::from(byte),
                        )
                        .expect("valid management target"),
                        socket_path: PathBuf::from(format!("/tmp/paraegox-pxnc-{name}-node.sock")),
                        token: Zeroizing::new([token; 32]),
                        expected_uid,
                        expected_gid,
                        topology_wire: vec![0xa0, byte].into_boxed_slice(),
                    },
                    connector: Some(DistributedRestrictedControllerConnectorCapabilityV1 {
                        profile_ref: [byte.wrapping_add(13); 16],
                        transport_profile: RestrictedRuntimeApplyTransportProfileV1::try_new(
                            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                                target: expected_target,
                                endpoint_ref: [byte.wrapping_add(14); 16],
                                endpoint_generation: u64::from(byte),
                                tls_listener_locator: if byte == 0x21 {
                                    "tls/192.0.2.21:7447"
                                } else {
                                    "tls/192.0.2.22:7447"
                                },
                                route: if byte == 0x21 {
                                    "paraegox/runtime-first/apply"
                                } else {
                                    "paraegox/runtime-second/apply"
                                },
                                trust_domain_ref:
                                    DistributedFabricTrustDomainRefV1::try_from_bytes(
                                        [byte.wrapping_add(15); 16],
                                    )
                                    .expect("trust domain"),
                                trust_anchor_ref:
                                    DistributedFabricTrustAnchorRefV1::try_from_bytes(
                                        [byte.wrapping_add(16); 16],
                                    )
                                    .expect("trust anchor"),
                                controller_connector_credential_ref:
                                    DistributedFabricCredentialRefV1::try_from_bytes(
                                        [byte.wrapping_add(17); 16],
                                    )
                                    .expect("Controller connector credential"),
                                runtime_listener_credential_ref:
                                    DistributedFabricCredentialRefV1::try_from_bytes(
                                        [byte.wrapping_add(18); 16],
                                    )
                                    .expect("Runtime listener credential"),
                                controller_principal: PrincipalRef::from_bytes(
                                    [byte.wrapping_add(2); 16],
                                ),
                                runtime_principal: PrincipalRef::from_bytes(
                                    [byte.wrapping_add(7); 16],
                                ),
                                operation_timeout_nanos: 5_000_000_000,
                            },
                        )
                        .expect("restricted transport profile"),
                        root_ca_certificate_file: PathBuf::from(format!(
                            "/tmp/paraegox-pxnc-{name}-root-ca.pem"
                        )),
                        connector_certificate_file: PathBuf::from(format!(
                            "/tmp/paraegox-pxnc-{name}-connector-cert.pem"
                        )),
                        connector_private_key_file: PathBuf::from(format!(
                            "/tmp/paraegox-pxnc-{name}-connector-key.pem"
                        )),
                    }),
                }
            };
            DistributedLocalCapabilityV1 {
                expected_uid,
                expected_gid,
                lifecycle_budget_nanos: 1_000_000,
                coordinator: DistributedCoordinatorCapabilityV1 {
                    common: common("coordinator"),
                    expected_store_id: [0x14; 32],
                    controller_private_seed_path: PathBuf::from(
                        "/tmp/paraegox-pxnc-coordinator-controller.seed",
                    ),
                },
                predecessors: [
                    predecessor("first", 0x21, first_token),
                    predecessor("second", 0x22, second_token),
                ],
                checksum: Digest32::from_bytes([0; 32]),
            }
        }

        #[test]
        fn legacy_active_ready_without_durable_runtime_observation_is_rejected() {
            assert!(
                !distributed_owner_terminal_runtime_observation_is_admissible(
                    DistributedAgentStackRolloutStatusV1::ActiveReady,
                    false,
                )
            );
            assert!(
                distributed_owner_terminal_runtime_observation_is_admissible(
                    DistributedAgentStackRolloutStatusV1::ActiveReady,
                    true,
                )
            );
            assert!(
                distributed_owner_terminal_runtime_observation_is_admissible(
                    DistributedAgentStackRolloutStatusV1::TerminalNonReady,
                    false,
                )
            );
        }

        #[test]
        fn distributed_capability_codec_is_canonical_and_debug_redacts_tokens() {
            let capability = distributed_capability_fixture(0xe1, 0xe2);
            let wire = capability
                .encode()
                .expect("fixture must encode with the one PXNC codec");
            assert_eq!(&wire[..6], b"PXNC\0\x02");
            let decoded = DistributedLocalCapabilityV1::decode(&wire)
                .expect("canonical PXNC must decode and revalidate");
            assert_eq!(
                decoded
                    .encode()
                    .expect("decoded PXNC must re-encode")
                    .as_slice(),
                wire.as_slice()
            );
            let mut tampered = wire.to_vec();
            tampered[64] ^= 1;
            assert!(
                DistributedLocalCapabilityV1::decode(&tampered).is_err(),
                "checksum-bound payload mutation must fail closed"
            );

            let debug = format!("{capability:?}");
            assert_eq!(debug, "DistributedLocalCapabilityV1 { .. }");
            assert!(!debug.contains(&"e1".repeat(32)));
            assert!(!debug.contains(&"e2".repeat(32)));
        }

        #[test]
        fn distributed_capability_v1_remains_canonical_but_cannot_apply() {
            let mut capability = distributed_capability_fixture(0xe1, 0xe2);
            capability.predecessors[0].connector = None;
            capability.predecessors[1].connector = None;
            let wire = capability
                .encode()
                .expect("legacy PXNC v1 remains an exact readable capability");
            assert_eq!(&wire[..6], b"PXNC\0\x01");
            let decoded = DistributedLocalCapabilityV1::decode(&wire)
                .expect("legacy PXNC v1 must still reopen canonically");
            assert_eq!(
                decoded
                    .encode()
                    .expect("legacy PXNC v1 canonical replay")
                    .as_slice(),
                wire.as_slice()
            );
            assert!(decoded.distributed_apply_connectors().is_err());
        }

        #[test]
        fn distributed_capability_rejects_partial_connector_authority() {
            let mut capability = distributed_capability_fixture(0xe1, 0xe2);
            capability.predecessors[1].connector = None;
            assert!(capability.encode().is_err());
        }

        #[test]
        fn distributed_capability_rejects_cross_target_transport_profiles() {
            let mut capability = distributed_capability_fixture(0xe1, 0xe2);
            let first = capability.predecessors[0]
                .connector
                .take()
                .expect("first connector");
            let second = capability.predecessors[1]
                .connector
                .take()
                .expect("second connector");
            capability.predecessors[0].connector = Some(second);
            capability.predecessors[1].connector = Some(first);
            assert!(capability.encode().is_err());
        }

        #[test]
        fn distributed_capability_rejects_reused_cross_target_profile_ref() {
            let mut capability = distributed_capability_fixture(0xe1, 0xe2);
            let first_profile_ref = capability.predecessors[0]
                .connector
                .as_ref()
                .expect("first connector")
                .profile_ref;
            capability.predecessors[1]
                .connector
                .as_mut()
                .expect("second connector")
                .profile_ref = first_profile_ref;
            assert!(capability.encode().is_err());
        }

        #[test]
        fn exact_versioned_positional_grammars_accept_only_complete_commands() {
            let initialize_distributed = vec![
                "initialize-distributed-agent-stack-v1".into(),
                "/tmp/paraegox-distributed.pxnc".into(),
            ];
            assert!(matches!(
                parse_arguments(initialize_distributed.clone()),
                Ok(ProcessCommand::InitializeDistributedAgentStack(_))
            ));
            let mut extra_initialize_distributed = initialize_distributed.clone();
            extra_initialize_distributed.push("unexpected".into());
            assert!(parse_arguments(extra_initialize_distributed).is_err());

            let observe_distributed = vec![
                "observe-distributed-agent-stack-nodes-once-v1".into(),
                "/tmp/paraegox-distributed.pxnc".into(),
            ];
            assert!(matches!(
                parse_arguments(observe_distributed.clone()),
                Ok(ProcessCommand::ObserveDistributedAgentStackNodesOnce(_))
            ));
            let mut missing_observe_distributed = observe_distributed;
            missing_observe_distributed.pop();
            assert!(parse_arguments(missing_observe_distributed).is_err());

            let apply_distributed = vec![
                "apply-distributed-agent-stack-once-v1".into(),
                "/tmp/paraegox-distributed.pxnc".into(),
            ];
            assert!(matches!(
                parse_arguments(apply_distributed.clone()),
                Ok(ProcessCommand::ApplyDistributedAgentStackOnce(_))
            ));
            let mut extra_apply_distributed = apply_distributed.clone();
            extra_apply_distributed.push("unexpected".into());
            assert!(parse_arguments(extra_apply_distributed).is_err());
            let mut missing_apply_distributed = apply_distributed;
            missing_apply_distributed.pop();
            assert!(parse_arguments(missing_apply_distributed).is_err());

            assert!(matches!(
                parse_arguments(migration_arguments()),
                Ok(ProcessCommand::MigrateControllerJournal(_))
            ));
            let mut missing_migration = migration_arguments();
            missing_migration.pop();
            assert!(parse_arguments(missing_migration).is_err());
            let mut extra_migration = migration_arguments();
            extra_migration.push("unexpected".into());
            assert!(parse_arguments(extra_migration).is_err());
            let mut uppercase_migration = migration_arguments();
            uppercase_migration[5] = OsString::from("AA".repeat(32));
            assert!(parse_arguments(uppercase_migration).is_err());
            let mut unversioned_migration = migration_arguments();
            unversioned_migration[0] = "migrate-controller-journal-v7-to-v8".into();
            assert!(parse_arguments(unversioned_migration).is_err());

            assert!(matches!(
                parse_arguments(initialize_arguments()),
                Ok(ProcessCommand::Initialize(_))
            ));

            let mut commit = vec![
                "commit-reference-loop-v1".into(),
                "/tmp/paraegox-controller".into(),
                hex(0x21, 32),
                hex(0x22, 16),
                hex(0x23, 16),
                hex(0x24, 16),
                "/tmp/controller.pub".into(),
                "501".into(),
                "20".into(),
                hex(0x25, 16),
                hex(0x26, 16),
                "7".into(),
                hex(0x27, 16),
                "10".into(),
                "20".into(),
                "30".into(),
            ];
            assert!(matches!(
                parse_arguments(commit.clone()),
                Ok(ProcessCommand::CommitReferenceLoop(_))
            ));
            commit.push("unexpected".into());
            assert_eq!(
                parse_arguments(commit)
                    .expect_err("extra positional value must fail")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut empty = vec![
                "commit-reference-empty-v1".into(),
                "/tmp/paraegox-controller".into(),
                hex(0x28, 32),
                hex(0x29, 16),
                hex(0x2a, 16),
                hex(0x2b, 16),
                "/tmp/controller.pub".into(),
                "501".into(),
                "20".into(),
                hex(0x2c, 16),
            ];
            assert!(matches!(
                parse_arguments(empty.clone()),
                Ok(ProcessCommand::CommitReferenceEmpty(_))
            ));
            empty.push("unexpected".into());
            assert_eq!(
                parse_arguments(empty)
                    .expect_err("Empty commit must reject extra positional values")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut tenure = tenure_arguments();
            assert!(matches!(
                parse_arguments(tenure.clone()),
                Ok(ProcessCommand::AcquireTenure(_))
            ));
            tenure.push(hex(0x59, 16));
            assert_eq!(
                parse_arguments(tenure)
                    .expect_err("tenure must reject caller operation/nonce entropy")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut missing = initialize_arguments();
            missing.pop();
            assert!(parse_arguments(missing).is_err());
            let mut unknown = initialize_arguments();
            unknown[0] = "initialize".into();
            assert!(parse_arguments(unknown).is_err());

            let mut bootstrap = bootstrap_arguments();
            assert!(matches!(
                parse_arguments(bootstrap.clone()),
                Ok(ProcessCommand::BootstrapRuntime(_))
            ));
            bootstrap.push(hex(0x40, 16));
            assert_eq!(
                parse_arguments(bootstrap)
                    .expect_err("bootstrap must reject caller entropy/extra fields")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut apply = bootstrap_arguments();
            apply[0] = "apply-reference-v1".into();
            assert!(matches!(
                parse_arguments(apply.clone()),
                Ok(ProcessCommand::ApplyReference(_))
            ));
            apply.push(hex(0x41, 16));
            assert_eq!(
                parse_arguments(apply)
                    .expect_err("apply must reject caller operation/temporal/nonce entropy")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut reconcile = bootstrap_arguments();
            reconcile[0] = "reconcile-reference-once-v1".into();
            assert!(matches!(
                parse_arguments(reconcile.clone()),
                Ok(ProcessCommand::ReconcileReferenceOnce(_))
            ));
            reconcile.push(hex(0x42, 16));
            assert_eq!(
                parse_arguments(reconcile)
                    .expect_err("reconcile must reject caller query-id/nonce entropy")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut serving = managed_serving_arguments();
            assert!(matches!(
                parse_arguments(serving.clone()),
                Ok(ProcessCommand::ObserveManagedServing(_))
            ));
            serving.push(hex(0x43, 16));
            assert_eq!(
                parse_arguments(serving)
                    .expect_err("managed serving must reject caller request-id/nonce entropy")
                    .kind,
                ProcessErrorKind::Arguments
            );
            let mut missing_serving = managed_serving_arguments();
            missing_serving.pop();
            assert!(parse_arguments(missing_serving).is_err());
        }

        #[test]
        fn identities_require_exact_nonzero_lower_hex() {
            assert_eq!(parse_nonzero_hex::<16>(&hex(0xab, 16)), Ok([0xab; 16]));
            for rejected in [
                OsString::from("00".repeat(16)),
                OsString::from("AB".repeat(16)),
                OsString::from("ab".repeat(15)),
                OsString::from("ag".repeat(16)),
            ] {
                assert!(parse_nonzero_hex::<16>(&rejected).is_err());
            }
        }

        #[test]
        fn tenure_fresh_material_and_durable_recovery_are_byte_exact() {
            let signer = SigningKey::from_bytes(&[0x61; 32]);
            let profile = TenureRequestProfile {
                scope: DeploymentScopeId::from_bytes([0x62; 16]),
                writer: DeploymentWriterRef::from_bytes([0x63; 16]),
                controller_principal: PrincipalRef::from_bytes([0x64; 16]),
                controller_key: ControllerAcquireKeyRef::from_bytes([0x65; 16]),
                controller_public_key_fingerprint: ControllerPublicKeyFingerprint::for_ed25519_key(
                    &signer.verifying_key().to_bytes(),
                )
                .expect("valid Controller public key fingerprint"),
                max_response_payload_bytes: u32::try_from(
                    MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
                )
                .expect("protocol bound fits u32"),
            };
            let mut entropy = [0x66; TENURE_ENTROPY_BYTES];
            entropy[..16].copy_from_slice(&[0x67; 16]);
            let fresh = fresh_tenure_request_from_entropy(&profile, &signer, &entropy)
                .expect("fresh request");
            assert_eq!(fresh.request().operation_id().as_bytes(), &[0x67; 16]);
            assert_eq!(fresh.request().client_nonce(), &[0x66; 32]);

            let recovered = recover_tenure_request(
                fresh.request().canonical_bytes(),
                &profile,
                &signer.verifying_key(),
            )
            .expect("durable request must recover");
            assert_eq!(recovered.request(), fresh.request());
            assert_eq!(recovered.frame_bytes(), fresh.frame_bytes());

            let mut conflicting_profile = profile;
            conflicting_profile.writer = DeploymentWriterRef::from_bytes([0x68; 16]);
            assert!(
                recover_tenure_request(
                    fresh.request().canonical_bytes(),
                    &conflicting_profile,
                    &signer.verifying_key(),
                )
                .is_err(),
                "durable request facts cannot be rebound on restart"
            );
            assert!(
                fresh_tenure_request_from_entropy(&profile, &signer, &[0; TENURE_ENTROPY_BYTES],)
                    .is_err(),
                "an all-zero operation identity must fail closed"
            );
        }

        #[test]
        fn apply_fresh_material_is_split_exactly_and_rejects_invalid_identities() {
            let mut entropy = [0x81; APPLY_ENTROPY_BYTES];
            entropy[..16].copy_from_slice(&[0x82; 16]);
            entropy[16..32].copy_from_slice(&[0x83; 16]);
            entropy[32..].copy_from_slice(&[0x84; 32]);
            let fresh = fresh_apply_request_from_entropy(&entropy)
                .expect("valid process-owned apply entropy");
            assert_eq!(
                fresh,
                FreshControllerApplyRequestV1::try_new([0x82; 16], [0x83; 16], [0x84; 32],)
                    .expect("expected split")
            );

            assert!(fresh_apply_request_from_entropy(&[0; APPLY_ENTROPY_BYTES]).is_err());
            let mut same_identities = [0x85; APPLY_ENTROPY_BYTES];
            same_identities[16..32].copy_from_slice(&[0x85; 16]);
            assert!(fresh_apply_request_from_entropy(&same_identities).is_err());
        }

        #[test]
        fn tenure_ensure_selection_fences_domain_drift_and_a_newer_other_writer() {
            let writer_a = DeploymentWriterRef::from_bytes([0x71; 16]);
            let writer_b = DeploymentWriterRef::from_bytes([0x72; 16]);
            let domain_a = ControllerTenureAuthorityDomainFingerprint::from_stored(
                Digest32::from_bytes([0x73; 32]),
            );
            let domain_b = ControllerTenureAuthorityDomainFingerprint::from_stored(
                Digest32::from_bytes([0x74; 32]),
            );
            let a1 = DurableTenureRequest {
                canonical_request: b"writer-a-epoch-1",
                writer: writer_a,
                authority_domain_fingerprint: domain_a,
            };
            let b2 = DurableTenureRequest {
                canonical_request: b"writer-b-epoch-2",
                writer: writer_b,
                authority_domain_fingerprint: domain_a,
            };

            assert_eq!(
                select_durable_tenure_request(Some(a1), None, writer_a, domain_a),
                Ok(Some(a1.canonical_request)),
                "the unique unresolved request has priority"
            );
            assert_eq!(
                select_durable_tenure_request(None, Some(a1), writer_a, domain_a),
                Ok(Some(a1.canonical_request)),
                "the matching global latest commit is ensure-once replayable"
            );
            assert_eq!(
                select_durable_tenure_request(None, None, writer_a, domain_a),
                Ok(None),
                "fresh entropy is admitted only with no durable tenure history"
            );
            assert_eq!(
                select_durable_tenure_request(Some(a1), None, writer_a, domain_b)
                    .expect_err("unresolved domain drift must fail closed")
                    .kind,
                ProcessErrorKind::Tenure
            );
            assert_eq!(
                select_durable_tenure_request(None, Some(a1), writer_a, domain_b)
                    .expect_err("committed domain drift must fail closed")
                    .kind,
                ProcessErrorKind::Tenure
            );
            assert_eq!(
                select_durable_tenure_request(None, Some(b2), writer_a, domain_a)
                    .expect_err("B2 globally fences A1; ensure A cannot replay A1")
                    .kind,
                ProcessErrorKind::Tenure
            );
        }

        #[test]
        fn noncanonical_paths_and_numbers_are_rejected_before_execution() {
            for path in [
                "relative/state",
                "/tmp/../state",
                "/tmp//state",
                "/tmp/state/",
            ] {
                let mut arguments = initialize_arguments();
                arguments[1] = path.into();
                assert!(parse_arguments(arguments).is_err(), "accepted {path}");
            }
            for value in ["0", "01", "+1", " 1", "1 "] {
                let mut arguments = initialize_arguments();
                arguments[8] = value.into();
                assert!(parse_arguments(arguments).is_err(), "accepted {value}");
            }
        }

        #[test]
        fn manifest_reads_are_actual_length_bounded_while_public_keys_are_exact() {
            let directory = TempDirectory::new();
            let manifest = directory.write("runtime.pxcm", b"manifest", 0o600);
            let observed = read_pinned_file(
                &manifest,
                FileLengthPolicy::BoundedNonZero(64),
                FileRole::Manifest,
                geteuid().as_raw(),
                getegid().as_raw(),
            )
            .expect("bounded manifest must read its actual bytes");
            assert_eq!(observed.bytes.as_ref(), b"manifest");

            let empty = directory.write("empty.pxcm", b"", 0o600);
            assert!(
                read_pinned_file(
                    &empty,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
            let oversized = directory.write("oversized.pxcm", &[0x11; 65], 0o600);
            assert!(
                read_pinned_file(
                    &oversized,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );

            let public_key = directory.write("controller.pub", &[0x22; 32], 0o600);
            assert_eq!(
                read_pinned_file(
                    &public_key,
                    FileLengthPolicy::Exact(32),
                    FileRole::PublicKey,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .expect("exact public key must read")
                .bytes
                .len(),
                32
            );
            let short_key = directory.write("short.pub", &[0x23; 31], 0o600);
            assert!(
                read_pinned_file(
                    &short_key,
                    FileLengthPolicy::Exact(32),
                    FileRole::PublicKey,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
        }

        #[test]
        fn pinned_reads_reject_symlinks_hardlinks_modes_and_wrong_owners() {
            let directory = TempDirectory::new();
            let key = directory.write("controller.pub", &[0x31; 32], 0o600);
            let hardlink = directory.path.join("controller-hardlink.pub");
            fs::hard_link(&key, &hardlink).expect("hard link fixture");
            assert!(
                read_pinned_file(
                    &key,
                    FileLengthPolicy::Exact(32),
                    FileRole::PublicKey,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
            assert!(
                read_pinned_file(
                    &hardlink,
                    FileLengthPolicy::Exact(32),
                    FileRole::PublicKey,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );

            let target = directory.write("target.pxcm", b"manifest", 0o600);
            let linked = directory.path.join("linked.pxcm");
            symlink(&target, &linked).expect("symlink fixture");
            assert!(
                read_pinned_file(
                    &linked,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
            let unsafe_mode = directory.write("unsafe.pxcm", b"manifest", 0o640);
            assert!(
                read_pinned_file(
                    &unsafe_mode,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
            assert!(
                read_pinned_file(
                    &target,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw().wrapping_add(1),
                    getegid().as_raw(),
                )
                .is_err()
            );
        }

        #[test]
        fn compiler_planner_candidate_and_controller_commit_are_exactly_idempotent() {
            let target = RuntimeHostId::from_bytes([0x41; 16]);
            let manifest = controller_test_manifest(target);
            let lifecycle = ValidatedReferenceLifecycleBudgetsV1::try_new(
                BoundedDuration::from_nanos(10),
                BoundedDuration::from_nanos(20),
                BoundedDuration::from_nanos(30),
            )
            .expect("lifecycle fixture");
            let candidate =
                build_reference_candidate(&manifest, [0x42; 16], [0x43; 16], 7, lifecycle)
                    .expect("real DeckCompiler -> Planner path must produce a candidate");
            assert_eq!(candidate.content().target(), target);
            assert_eq!(
                candidate.content().manifest_digest().value(),
                manifest.manifest_digest()
            );

            let empty = StableAllocationSnapshot::try_new(target, 0, 0, Vec::new())
                .expect("empty allocation");
            let auth = ControllerRequestAuthPin::try_new(
                ApplyAuthKeyRef::from_bytes([0x44; 16]),
                ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
                1,
                ControllerAuthKeyFingerprint::from_stored(Digest32::from_bytes([0x45; 32])),
                1,
            )
            .expect("auth pin");
            let initial = ControllerJournalState::try_initialize(
                DeploymentScopeId::from_bytes([0x46; 16]),
                DeploymentId::from_bytes([0x47; 16]),
                empty,
                manifest,
                auth,
            )
            .expect("initial state");
            let operation = ControllerOperationId::from_bytes([0x48; 16]);
            let prepared = initial
                .prepare_plan_candidate(operation, &candidate)
                .expect("prepare");
            let committed = prepared
                .commit_plan_candidate(operation, &candidate)
                .expect("commit");
            assert_eq!(committed.current_revision(), 1);
            assert_eq!(
                committed
                    .prepare_plan_candidate(operation, &candidate)
                    .expect("committed prepare retry"),
                committed
            );
            assert_eq!(
                committed
                    .commit_plan_candidate(operation, &candidate)
                    .expect("committed commit retry"),
                committed
            );

            let changed = build_reference_candidate(
                committed.installed_manifest(),
                [0x42; 16],
                [0x43; 16],
                8,
                lifecycle,
            )
            .expect("changed resolved version remains a valid candidate");
            assert_ne!(changed.content_digest(), candidate.content_digest());
            assert_eq!(
                committed.prepare_plan_candidate(operation, &changed),
                Err(ControllerJournalError::OperationConflict)
            );
            assert!(
                committed
                    .prepare_plan_candidate(
                        ControllerOperationId::from_bytes([0x49; 16]),
                        &candidate
                    )
                    .is_err(),
                "a different operation cannot implicitly plan Loop -> Loop"
            );
        }

        #[test]
        fn empty_commit_reopens_prepared_and_committed_snapshots_exactly() {
            let (terminal, _, _) = direct_active_snapshot();
            let operation = ControllerOperationId::from_bytes([0x32; 16]);
            let candidate = build_reference_empty_candidate(terminal.state())
                .expect("the real Active terminal must plan an Empty successor");
            let prepared_state = terminal
                .state()
                .prepare_plan_candidate(operation, &candidate)
                .expect("Empty candidate must prepare");
            let prepared = terminal
                .try_successor(prepared_state)
                .expect("Prepared Empty snapshot must validate");

            let directory = TempDirectory::new();
            install_controller_snapshot(&prepared, &directory);
            let store_id = *prepared.store_instance_id();
            let owner = prepared.owner_identity_fingerprint();
            let scope = prepared.state().scope();
            let plan_lineage = prepared.state().plan_lineage();
            let request_auth = prepared.state().request_auth();

            let mut store = ControllerStore::open_with_policy(
                &directory.path,
                store_id,
                owner,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("Prepared snapshot must reopen");
            let committed = commit_reference_empty_in_store(
                &mut store,
                scope,
                plan_lineage,
                request_auth,
                operation,
            )
            .expect("same operation must finish Prepared -> Committed");
            assert_eq!(
                committed.snapshot_sequence(),
                prepared.snapshot_sequence() + 1
            );
            assert_eq!(committed.state().current_revision(), 2);
            let first_receipt = build_empty_commit_receipt(&committed, operation)
                .expect("committed Empty receipt must encode");
            drop(store);

            let mut reopened = ControllerStore::open_with_policy(
                &directory.path,
                store_id,
                owner,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("Committed snapshot must reopen");
            let replay = commit_reference_empty_in_store(
                &mut reopened,
                scope,
                plan_lineage,
                request_auth,
                operation,
            )
            .expect("same committed operation must replay");
            assert_eq!(replay, committed);
            assert_eq!(
                build_empty_commit_receipt(&replay, operation)
                    .expect("replayed Empty receipt must encode"),
                first_receipt,
                "receipt bytes and digest must remain exact across reopen"
            );

            let different_operation = ControllerOperationId::from_bytes([0x33; 16]);
            assert_eq!(
                commit_reference_empty_in_store(
                    &mut reopened,
                    scope,
                    plan_lineage,
                    request_auth,
                    different_operation,
                )
                .expect_err("a different operation must fail closed")
                .kind,
                ProcessErrorKind::Commit
            );
            assert_eq!(
                reopened.snapshot().expect("store remains readable"),
                &committed,
                "rejected operation must not mutate the open store"
            );
            drop(reopened);

            let reopened_after_rejection = ControllerStore::open_with_policy(
                &directory.path,
                store_id,
                owner,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("store must reopen after a rejected operation");
            assert_eq!(
                reopened_after_rejection
                    .snapshot()
                    .expect("reopened snapshot"),
                &committed,
                "rejected operation must not mutate durable state"
            );
        }

        #[test]
        fn lost_direct_receipt_active_query_can_commit_empty() {
            let terminal = decided_snapshot();
            assert!(terminal.state().current_direct_terminal_receipt().is_none());
            let operation = ControllerOperationId::from_bytes([0x33; 16]);
            let candidate = build_reference_empty_candidate(terminal.state())
                .expect("query-derived Active must plan an Empty successor");
            let prepared = terminal
                .clone()
                .try_successor(
                    terminal
                        .state()
                        .prepare_plan_candidate(operation, &candidate)
                        .expect("query-derived Empty candidate must prepare"),
                )
                .expect("query-derived Empty prepared snapshot");
            let committed = prepared
                .clone()
                .try_successor(
                    prepared
                        .state()
                        .commit_plan_candidate(operation, &candidate)
                        .expect("query-derived Active must archive and commit Empty"),
                )
                .expect("query-derived Empty committed snapshot");
            assert_eq!(
                validate_committed_empty_state(committed.state(), operation)
                    .expect("query-derived Empty committed state"),
                terminal
                    .state()
                    .current_signed_apply_intent()
                    .expect("query-derived Active intent")
                    .target_slice_digest()
            );
        }

        fn install_controller_snapshot(
            snapshot: &crate::controller_journal::ControllerJournalSnapshot,
            directory: &TempDirectory,
        ) {
            let handle = open_controller_directory(
                &directory.path,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("fixture directory must open");
            ensure_fresh_controller_directory(&handle).expect("fixture directory must be fresh");
            let _initializer_lock = create_and_lock_controller_initializer_lock(&handle)
                .expect("fixture initializer lock");
            let encoded = snapshot.encode().expect("fixture snapshot must encode");
            publish_initial_controller_snapshot(
                &handle,
                &encoded,
                [0xd1; 16],
                ControllerCommitFailpoint::None,
            )
            .expect("fixture snapshot must publish");
        }

        struct TempDirectory {
            path: PathBuf,
        }

        impl TempDirectory {
            fn new() -> Self {
                let unique = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir()
                    .canonicalize()
                    .expect("canonical test temporary root");
                let path = root.join(format!(
                    "paraegox-deploymentd-unit-{}-{unique}",
                    std::process::id()
                ));
                fs::create_dir(&path).expect("create test directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("set test directory mode");
                Self { path }
            }

            fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
                let path = self.path.join(name);
                fs::write(&path, bytes).expect("write fixture");
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                    .expect("set fixture mode");
                path
            }
        }

        impl Drop for TempDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }
    }
}
