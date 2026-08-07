//! Developer-local composition of the real Controller protocol chain.
//!
//! This facade never substitutes in-memory receipts or direct service starts.
//! It advances the same durable Controller journals and the same authenticated
//! Unix Runtime endpoint used by the managed Fabric and Agent stack verticals.

#![cfg(unix)]

use core::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use paraegox_kernel::digest::{Digest32, Digest32Builder};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::BoundedDuration;
use paraegox_node::observation::{RuntimeObservationAuthorityV1, RuntimeObservationEndpointRefV1};
use paraegox_node::protocol::NodeManagementTargetV1;
use paraegox_node::{RuntimeApplyEndpointDescriptorV1, RuntimeApplyEndpointRefV1};
use paraegox_runtime_contracts::apply::{
    PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
};
use paraegox_runtime_contracts::assignment::BindingId;
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedFabricTopologyV1, RestrictedRuntimeApplyCarrierBindingFieldsV1,
    RestrictedRuntimeApplyCarrierBindingV1, RestrictedRuntimeApplyTransportProfileV1,
};
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentIngressLimitsV1, ManagedAgentPortPlanV1, ManagedAgentProviderProfileV1,
    ManagedAgentProviderRefV1, ManagedAgentProviderSelectionV1, ManagedAgentSemanticLimitsV1,
    ManagedAgentServicePlanV1, ManagedAgentStackTargetModeV1, ManagedAgentStackTerminalOutcomeV1,
};
use paraegox_runtime_contracts::managed_fabric_plan::{
    ManagedFabricApplyTerminalOutcomeV1, ManagedFabricListenEndpointV1,
};
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    ManagedModelAgentStackTargetModeV1, ManagedModelAgentStackTerminalOutcomeV1,
    ManagedModelServicePlanV1,
};
use paraegox_runtime_contracts::managed_service::{
    ManagedServiceId, ManagedServiceLifecycleBudgetsV1, ManagedServiceSpecV1,
};
use paraegox_runtime_contracts::provenance::SourceScopeRef;
use paraegox_runtime_contracts::reference_control::{
    ReferenceAdmissionPolicyInputV1, ReferenceBootstrapServingIdentityV1,
    ValidatedReferenceLifecycleBudgetsV1, ed25519_control_key_fingerprint,
    reference_admission_policy_fingerprint_v1,
};
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
use tokio::runtime::Builder as RuntimeBuilder;
use zeroize::Zeroizing;

use crate::controller_bootstrap::{
    ControllerBootstrapProvisioningV1, ControllerBootstrapReceiptV1,
    FreshControllerBootstrapRequestV1, bootstrap_runtime_v1,
};
use crate::controller_initializer::{
    ControllerInitializationInput, initialize_controller_store_developer_local,
};
use crate::controller_journal::{
    ControllerAuthKeyFingerprint, ControllerOperationId, ControllerOwnerIdentityFingerprint,
    ControllerRequestAuthPin, ControllerTenureAuthorityDomainFingerprint,
};
use crate::controller_store::ControllerStore;
use crate::controller_tenure::acquire_tenure_once;
use crate::deck::{
    CardDefinitionVersionRequirement, CardUseKey, DeckCardConfig, DeckCardRole, DeckCardSpec,
    DeckCompiler, DeckExportRef, DeckKey, DeckLifetimeRequest, DeckOwnershipRequest,
    DeckResolverSnapshot, DeckSpec, ResolvedCardArtifact, ResolvedCardDefinition,
};
use crate::deployment_process::{
    DistributedAgentStackOwnerApplyErrorV1, DistributedAgentStackOwnerApplyOutcomeV1,
    DistributedAgentStackOwnerConnectorInputV1, DistributedAgentStackOwnerNodeInputV1,
    DistributedAgentStackOwnerTargetInputV1, DistributedCoordinatorContextV1,
    run_developer_local_distributed_agent_stack_owner_v1,
    verify_distributed_coordinator_context_v1,
};
use crate::distributed_agent_stack_producer::VerifiedDistributedAgentStackPredecessorV1;
use crate::managed_agent_stack_apply::{
    ManagedAgentStackApplyJournalV1, ManagedAgentStackTerminalCommitV1,
};
use crate::managed_agent_stack_producer::{
    FreshManagedAgentStackApplyV1, ManagedAgentStackActivationV1,
};
use crate::managed_fabric_apply::{
    ManagedFabricApplyControllerError, ManagedFabricApplyJournalV1, ManagedFabricControllerStateV1,
    ManagedFabricTerminalCommitV1,
};
use crate::managed_fabric_producer::{
    FreshManagedFabricApplyV1, ManagedFabricControllerIdentityV1,
    ManagedFabricControllerProvisioningV1, ManagedFabricRuntimeChannelPinV1,
    ManagedFabricServiceAccountsV1, ManagedFabricTenureAuthorityPinV1,
};
use crate::managed_fabric_store::{ManagedAgentStackDurableStoreV1, ManagedFabricSuccessorStoreV1};
use crate::managed_model_agent_stack_apply::{
    ManagedModelAgentStackApplyControllerError, ManagedModelAgentStackApplyJournalV1,
    ManagedModelAgentStackTerminalCommitV1,
};
use crate::managed_model_agent_stack_producer::{
    FreshManagedModelAgentStackApplyV1, ManagedModelAgentStackActivationV1,
};
use crate::managed_serving_client::{
    FreshManagedServingBootstrapV1, ManagedServingBootstrapPhaseV1, VerifiedManagedServingPinV1,
};
use crate::manifest_ingress::ControllerInstalledManifestPin;
use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
use crate::planner::{
    DeploymentPlanCandidate, DeploymentPlanner, PlannerDesired, PlannerInput, PlannerOutcome,
    PreviousTargetEligibility, StableAllocationSnapshot, ValidatedReferenceLifecycleBudgets,
};
use crate::runtime_control_client::{
    RuntimeControlSocketAcl, RuntimeManagedAgentStackResponseVerifier,
    RuntimeManagedFabricResponseVerifier, RuntimeManagedModelAgentStackResponseVerifier,
    RuntimeManagedServingResponseVerifier, RuntimeQueryResponseVerifier, RuntimeUnixCredentials,
    UnixRuntimeControlEndpoint, UnixRuntimeManagedAgentStackClient, UnixRuntimeManagedFabricClient,
    UnixRuntimeManagedModelAgentStackClient, UnixRuntimeManagedServingClient,
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
use crate::{
    DeveloperLocalPeerIdentityV1, DeveloperLocalTenureAuthorityFactsV1,
    DeveloperLocalTenureAuthorityIdentityBytesV1,
};

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const INITIAL_AUTH_ROTATION_GENERATION: u64 = 1;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const OWNER_IDENTITY_DOMAIN: &[u8] = b"paraegox.deployment.controller.process-owner.sha256.v1";
const DERIVED_IDENTITY_DOMAIN: &[u8] =
    b"paraegox.deployment.developer-fixture-derived-identity.sha256.v1";
const SUCCESSOR_STORE_DOMAIN: &[u8] =
    b"paraegox.deployment.developer-fixture-successor-store.sha256.v1";
const MODEL_SERVICE_DOMAIN: &[u8] =
    b"paraegox.deployment.developer-fixture-model-service.sha256.v1";
const LEGACY_OPERATION_DOMAIN: &[u8] =
    b"paraegox.deployment.developer-fixture-legacy-operation.sha256.v1";

const FABRIC_LIFECYCLE_NANOS: u64 = 3_000_000_000;
const AGENT_LIFECYCLE_NANOS: u64 = 3_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureIdentitySeedV1 {
    pub manifest_instance_id: [u8; 16],
    pub controller_instance_id: [u8; 16],
    pub authority_instance_id: [u8; 16],
    pub runtime_instance_id: [u8; 16],
    pub source_scope_id: [u8; 16],
    pub source_plan_id: [u8; 16],
    pub fabric_service_id: [u8; 16],
    pub agent_service_id: [u8; 16],
    pub submit_binding_id: [u8; 16],
    pub control_binding_id: [u8; 16],
    pub provider_ref: [u8; 16],
    pub deck_run_id: [u8; 16],
    pub session_id: [u8; 16],
    pub provider_configuration_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureDerivedIdentityV1 {
    seed: DeveloperFixtureIdentitySeedV1,
    writer: [u8; 16],
    controller_key_ref: [u8; 16],
    authority_ref: [u8; 16],
    authority_key_ref: [u8; 16],
    runtime_principal: [u8; 16],
    runtime_response_key_ref: [u8; 16],
    authority_service_principal: [u8; 16],
    authority_owner: [u8; 16],
    successor_store_instance_id: [u8; 32],
    model_service_id: [u8; 16],
    legacy_plan_operation_id: [u8; 16],
}

impl DeveloperFixtureDerivedIdentityV1 {
    pub fn try_from_seed(
        seed: DeveloperFixtureIdentitySeedV1,
    ) -> Result<Self, DeveloperFixtureAgentStackError> {
        validate_seed(seed)?;
        let writer = derive16(b"writer", &seed.controller_instance_id)?;
        let controller_key_ref = derive16(b"controller-key", &seed.controller_instance_id)?;
        let authority_ref = derive16(b"authority-ref", &seed.authority_instance_id)?;
        let authority_key_ref = derive16(b"authority-key", &seed.authority_instance_id)?;
        let runtime_principal = derive16(b"runtime-principal", &seed.runtime_instance_id)?;
        let runtime_response_key_ref = derive16(b"runtime-key", &seed.runtime_instance_id)?;
        let authority_service_principal =
            derive16(b"authority-service", &seed.authority_instance_id)?;
        let authority_owner = derive16(b"authority-owner", &seed.authority_instance_id)?;
        let successor_store_instance_id = derive32(
            SUCCESSOR_STORE_DOMAIN,
            &[&seed.controller_instance_id, &seed.runtime_instance_id],
        )?;
        let model_service_id =
            derive16_with_domain(MODEL_SERVICE_DOMAIN, &[&seed.agent_service_id])?;
        let legacy_plan_operation_id = derive16_with_domain(
            LEGACY_OPERATION_DOMAIN,
            &[&seed.source_scope_id, &seed.source_plan_id],
        )?;
        let derived = Self {
            seed,
            writer,
            controller_key_ref,
            authority_ref,
            authority_key_ref,
            runtime_principal,
            runtime_response_key_ref,
            authority_service_principal,
            authority_owner,
            successor_store_instance_id,
            model_service_id,
            legacy_plan_operation_id,
        };
        validate_derived(&derived)?;
        Ok(derived)
    }

    #[must_use]
    pub const fn source_scope(self) -> [u8; 16] {
        self.seed.source_scope_id
    }

    #[must_use]
    pub const fn installation_id(self) -> [u8; 16] {
        self.seed.manifest_instance_id
    }

    #[must_use]
    pub const fn source_plan(self) -> [u8; 16] {
        self.seed.source_plan_id
    }

    #[must_use]
    pub const fn writer(self) -> [u8; 16] {
        self.writer
    }

    #[must_use]
    pub const fn controller_principal(self) -> [u8; 16] {
        self.seed.controller_instance_id
    }

    #[must_use]
    pub const fn controller_key_ref(self) -> [u8; 16] {
        self.controller_key_ref
    }

    #[must_use]
    pub const fn authority_principal(self) -> [u8; 16] {
        self.seed.authority_instance_id
    }

    #[must_use]
    pub const fn authority_ref(self) -> [u8; 16] {
        self.authority_ref
    }

    #[must_use]
    pub const fn authority_key_ref(self) -> [u8; 16] {
        self.authority_key_ref
    }

    #[must_use]
    pub const fn authority_service_principal(self) -> [u8; 16] {
        self.authority_service_principal
    }

    #[must_use]
    pub const fn authority_owner(self) -> [u8; 16] {
        self.authority_owner
    }

    #[must_use]
    pub const fn runtime_target(self) -> [u8; 16] {
        self.seed.runtime_instance_id
    }

    #[must_use]
    pub const fn runtime_principal(self) -> [u8; 16] {
        self.runtime_principal
    }

    #[must_use]
    pub const fn runtime_response_key_ref(self) -> [u8; 16] {
        self.runtime_response_key_ref
    }

    #[must_use]
    pub const fn successor_store_instance_id(self) -> [u8; 32] {
        self.successor_store_instance_id
    }

    #[must_use]
    pub const fn fabric_service_id(self) -> [u8; 16] {
        self.seed.fabric_service_id
    }

    #[must_use]
    pub const fn agent_service_id(self) -> [u8; 16] {
        self.seed.agent_service_id
    }

    #[must_use]
    pub const fn model_service_id(self) -> [u8; 16] {
        self.model_service_id
    }

    #[must_use]
    pub const fn submit_binding_id(self) -> [u8; 16] {
        self.seed.submit_binding_id
    }

    #[must_use]
    pub const fn control_binding_id(self) -> [u8; 16] {
        self.seed.control_binding_id
    }

    #[must_use]
    pub const fn provider_ref(self) -> [u8; 16] {
        self.seed.provider_ref
    }

    #[must_use]
    pub const fn provider_configuration_digest(self) -> [u8; 32] {
        self.seed.provider_configuration_digest
    }

    #[must_use]
    pub const fn deck_key(self) -> [u8; 16] {
        self.seed.deck_run_id
    }

    #[must_use]
    pub const fn card_use_key(self) -> [u8; 16] {
        self.seed.session_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixturePathsV1 {
    controller_state_directory: PathBuf,
    successor_state_directory: PathBuf,
    authority_socket_path: PathBuf,
    runtime_socket_path: PathBuf,
}

impl DeveloperFixturePathsV1 {
    pub fn try_new(
        controller_state_directory: PathBuf,
        successor_state_directory: PathBuf,
        authority_socket_path: PathBuf,
        runtime_socket_path: PathBuf,
    ) -> Result<Self, DeveloperFixtureAgentStackError> {
        for path in [
            &controller_state_directory,
            &successor_state_directory,
            &authority_socket_path,
            &runtime_socket_path,
        ] {
            validate_absolute_path(path)?;
        }
        if controller_state_directory == successor_state_directory
            || controller_state_directory.starts_with(&successor_state_directory)
            || successor_state_directory.starts_with(&controller_state_directory)
            || authority_socket_path == runtime_socket_path
            || authority_socket_path.starts_with(&controller_state_directory)
            || authority_socket_path.starts_with(&successor_state_directory)
            || runtime_socket_path.starts_with(&controller_state_directory)
            || runtime_socket_path.starts_with(&successor_state_directory)
        {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        Ok(Self {
            controller_state_directory,
            successor_state_directory,
            authority_socket_path,
            runtime_socket_path,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureRuntimePinsV1 {
    manifest_wire: Box<[u8]>,
    manifest_digest: Digest32,
    expected_runtime_store_instance_id: [u8; 32],
    runtime_response_verification_key: [u8; 32],
}

impl DeveloperFixtureRuntimePinsV1 {
    pub fn try_new(
        manifest_wire: Box<[u8]>,
        manifest_digest: [u8; 32],
        expected_runtime_store_instance_id: [u8; 32],
        runtime_response_verification_key: [u8; 32],
    ) -> Result<Self, DeveloperFixtureAgentStackError> {
        if manifest_wire.is_empty()
            || bytes_are_zero(&manifest_digest)
            || bytes_are_zero(&expected_runtime_store_instance_id)
            || bytes_are_zero(&runtime_response_verification_key)
        {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        let key = VerifyingKey::from_bytes(&runtime_response_verification_key)
            .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        if key.is_weak() {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        Ok(Self {
            manifest_wire,
            manifest_digest: Digest32::from_bytes(manifest_digest),
            expected_runtime_store_instance_id,
            runtime_response_verification_key,
        })
    }
}

pub struct DeveloperFixtureControllerCredentialsV1 {
    controller_signing_seed: Zeroizing<[u8; 32]>,
    authority_verification_key: [u8; 32],
}

impl fmt::Debug for DeveloperFixtureControllerCredentialsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperFixtureControllerCredentialsV1")
            .field("controller_signing_seed", &"<redacted>")
            .field("authority_verification_key", &"<public-key-redacted>")
            .finish()
    }
}

impl DeveloperFixtureControllerCredentialsV1 {
    pub fn try_new(
        controller_signing_seed: Zeroizing<[u8; 32]>,
        authority_verification_key: [u8; 32],
    ) -> Result<Self, DeveloperFixtureAgentStackError> {
        if controller_signing_seed.iter().all(|byte| *byte == 0)
            || bytes_are_zero(&authority_verification_key)
        {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        let authority = VerifyingKey::from_bytes(&authority_verification_key)
            .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        let controller = SigningKey::from_bytes(&controller_signing_seed).verifying_key();
        if authority.is_weak() || controller.is_weak() || authority == controller {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        Ok(Self {
            controller_signing_seed,
            authority_verification_key,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureFabricEndpointV1(ManagedFabricListenEndpointV1);

impl DeveloperFixtureFabricEndpointV1 {
    pub fn try_new(value: &str) -> Result<Self, DeveloperFixtureAgentStackError> {
        Ok(Self(
            ManagedFabricListenEndpointV1::try_new(value)
                .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?,
        ))
    }
}

pub struct DeveloperFixtureAgentStackInputV1 {
    paths: DeveloperFixturePathsV1,
    identities: DeveloperFixtureDerivedIdentityV1,
    runtime: DeveloperFixtureRuntimePinsV1,
    credentials: DeveloperFixtureControllerCredentialsV1,
    authority: DeveloperLocalTenureAuthorityFactsV1,
    fabric: DeveloperFixtureFabricEndpointV1,
}

impl fmt::Debug for DeveloperFixtureAgentStackInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperFixtureAgentStackInputV1")
            .field("paths", &self.paths)
            .field("identities", &self.identities)
            .field("runtime", &self.runtime)
            .field("credentials", &self.credentials)
            .field("fabric", &self.fabric)
            .finish()
    }
}

impl DeveloperFixtureAgentStackInputV1 {
    #[must_use]
    pub fn new(
        paths: DeveloperFixturePathsV1,
        identities: DeveloperFixtureDerivedIdentityV1,
        runtime: DeveloperFixtureRuntimePinsV1,
        credentials: DeveloperFixtureControllerCredentialsV1,
        authority: DeveloperLocalTenureAuthorityFactsV1,
        fabric: DeveloperFixtureFabricEndpointV1,
    ) -> Self {
        Self {
            paths,
            identities,
            runtime,
            credentials,
            authority,
            fabric,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureDistributedCoordinatorV1 {
    state_directory: PathBuf,
}

impl DeveloperFixtureDistributedCoordinatorV1 {
    pub fn try_new(
        state_directory: PathBuf,
    ) -> Result<Self, DeveloperFixtureDistributedAgentStackError> {
        validate_absolute_path(&state_directory)
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
        Ok(Self { state_directory })
    }
}

/// Exact pre-start restricted transport selection. The expected carrier is
/// derived by Deployment from public identity/key pins before Runtime starts,
/// retained here, and re-derived from the durable predecessor plus fresh Node
/// observation before the later distributed send.
#[derive(Clone, Eq, PartialEq)]
pub struct DeveloperFixtureDistributedTransportV1 {
    profile_ref: [u8; 16],
    transport_profile: RestrictedRuntimeApplyTransportProfileV1,
    expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
    root_ca_certificate_file: PathBuf,
    connector_certificate_file: PathBuf,
    connector_private_key_file: PathBuf,
}

impl fmt::Debug for DeveloperFixtureDistributedTransportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperFixtureDistributedTransportV1")
            .field("profile_ref", &"<redacted>")
            .field("transport_profile", &"<redacted>")
            .field("expected_carrier", &"<redacted>")
            .field("root_ca_certificate_file", &"<redacted-path>")
            .field("connector_certificate_file", &"<redacted-path>")
            .field("connector_private_key_file", &"<redacted-path>")
            .finish()
    }
}

impl DeveloperFixtureDistributedTransportV1 {
    pub fn try_new(
        identities: DeveloperFixtureDerivedIdentityV1,
        credentials: &DeveloperFixtureControllerCredentialsV1,
        runtime_response_verification_key: [u8; 32],
        profile_ref: [u8; 16],
        transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        root_ca_certificate_file: PathBuf,
        connector_certificate_file: PathBuf,
        connector_private_key_file: PathBuf,
    ) -> Result<Self, DeveloperFixtureDistributedAgentStackError> {
        for path in [
            &root_ca_certificate_file,
            &connector_certificate_file,
            &connector_private_key_file,
        ] {
            validate_absolute_path(path)
                .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
        }
        let controller_key =
            SigningKey::from_bytes(&credentials.controller_signing_seed).verifying_key();
        let runtime_key = VerifyingKey::from_bytes(&runtime_response_verification_key)
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
        if runtime_key.is_weak() || runtime_key == controller_key {
            return Err(DeveloperFixtureDistributedAgentStackError::InvalidInput);
        }
        let controller_fingerprint = ed25519_control_key_fingerprint(controller_key.as_bytes())
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
        let runtime_fingerprint = ed25519_control_key_fingerprint(runtime_key.as_bytes())
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
        let target = RuntimeHostId::from_bytes(identities.runtime_target());
        if bytes_are_zero(&profile_ref)
            || root_ca_certificate_file == connector_certificate_file
            || root_ca_certificate_file == connector_private_key_file
            || connector_certificate_file == connector_private_key_file
            || transport_profile.target() != target
            || transport_profile.controller_principal()
                != PrincipalRef::from_bytes(identities.controller_principal())
            || transport_profile.runtime_principal()
                != PrincipalRef::from_bytes(identities.runtime_principal())
        {
            return Err(DeveloperFixtureDistributedAgentStackError::InvalidInput);
        }
        let expected_carrier = RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target,
                runtime_principal: PrincipalRef::from_bytes(identities.runtime_principal()),
                controller_principal: PrincipalRef::from_bytes(identities.controller_principal()),
                endpoint_ref: transport_profile.endpoint_ref(),
                endpoint_generation: transport_profile.endpoint_generation(),
                route: transport_profile.route(),
                controller_request_key: ApplyAuthKeyRef::from_bytes(
                    identities.controller_key_ref(),
                ),
                controller_request_key_fingerprint: controller_fingerprint,
                runtime_response_key: ApplyAuthKeyRef::from_bytes(
                    identities.runtime_response_key_ref(),
                ),
                runtime_response_key_fingerprint: runtime_fingerprint,
                control_transport_profile_ref: profile_ref,
                control_transport_profile_digest: transport_profile.profile_digest(),
            },
        )
        .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
        Ok(Self {
            profile_ref,
            transport_profile,
            expected_carrier,
            root_ca_certificate_file,
            connector_certificate_file,
            connector_private_key_file,
        })
    }

    #[must_use]
    pub const fn profile_ref(&self) -> [u8; 16] {
        self.profile_ref
    }

    #[must_use]
    pub const fn transport_profile(&self) -> &RestrictedRuntimeApplyTransportProfileV1 {
        &self.transport_profile
    }

    #[must_use]
    pub const fn expected_carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        &self.expected_carrier
    }
}

pub struct DeveloperFixtureDistributedTargetV1 {
    agent_stack: DeveloperFixtureAgentStackInputV1,
    topology: DistributedFabricTopologyV1,
    transport: DeveloperFixtureDistributedTransportV1,
}

impl fmt::Debug for DeveloperFixtureDistributedTargetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperFixtureDistributedTargetV1")
            .field("agent_stack", &self.agent_stack)
            .field("topology", &"<redacted>")
            .field("transport", &self.transport)
            .finish()
    }
}

impl DeveloperFixtureDistributedTargetV1 {
    #[must_use]
    pub fn new(
        agent_stack: DeveloperFixtureAgentStackInputV1,
        topology: DistributedFabricTopologyV1,
        transport: DeveloperFixtureDistributedTransportV1,
    ) -> Self {
        Self {
            agent_stack,
            topology,
            transport,
        }
    }
}

pub struct DeveloperFixtureDistributedAgentStackInputV1 {
    coordinator: DeveloperFixtureDistributedCoordinatorV1,
    lifecycle_budget: BoundedDuration,
    targets: [DeveloperFixtureDistributedTargetV1; 2],
}

impl fmt::Debug for DeveloperFixtureDistributedAgentStackInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperFixtureDistributedAgentStackInputV1")
            .field("coordinator", &self.coordinator)
            .field("lifecycle_budget", &self.lifecycle_budget)
            .field("targets", &self.targets)
            .finish()
    }
}

impl DeveloperFixtureDistributedAgentStackInputV1 {
    #[must_use]
    pub fn new(
        coordinator: DeveloperFixtureDistributedCoordinatorV1,
        lifecycle_budget: BoundedDuration,
        targets: [DeveloperFixtureDistributedTargetV1; 2],
    ) -> Self {
        Self {
            coordinator,
            lifecycle_budget,
            targets,
        }
    }
}

pub struct DeveloperFixtureDistributedNodeV1 {
    management_target: NodeManagementTargetV1,
    socket_path: PathBuf,
    token: Zeroizing<[u8; 32]>,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    observation_socket_path: PathBuf,
    observation_token: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for DeveloperFixtureDistributedNodeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperFixtureDistributedNodeV1")
            .field("management_target", &self.management_target)
            .field("socket_path", &"<redacted-path>")
            .field("token", &"<redacted>")
            .field("observation_endpoint_ref", &"<redacted-ref>")
            .field("observation_socket_path", &"<redacted-path>")
            .field("observation_token", &"<redacted>")
            .finish()
    }
}

impl DeveloperFixtureDistributedNodeV1 {
    pub fn try_new(
        management_target: NodeManagementTargetV1,
        socket_path: PathBuf,
        token: Zeroizing<[u8; 32]>,
        observation_endpoint_ref: RuntimeObservationEndpointRefV1,
        observation_socket_path: PathBuf,
        observation_token: Zeroizing<[u8; 32]>,
    ) -> Result<Self, DeveloperFixtureDistributedAgentStackError> {
        validate_absolute_path(&socket_path)
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
        validate_absolute_path(&observation_socket_path)
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
        if bytes_are_zero(token.as_ref())
            || bytes_are_zero(observation_token.as_ref())
            || socket_path == observation_socket_path
            || token.as_ref() == observation_token.as_ref()
            || management_target.management_endpoint_ref().as_bytes()
                == observation_endpoint_ref.as_bytes()
        {
            return Err(DeveloperFixtureDistributedAgentStackError::InvalidInput);
        }
        Ok(Self {
            management_target,
            socket_path,
            token,
            observation_endpoint_ref,
            observation_socket_path,
            observation_token,
        })
    }
}

struct PreparedDeveloperFixtureDistributedTargetV1 {
    topology: DistributedFabricTopologyV1,
    connector: DistributedAgentStackOwnerConnectorInputV1,
    runtime_query_client: UnixRuntimeQueryClient,
}

/// Move-only Deployment owner token produced only after both durable single-
/// target predecessors have reached ActiveReady. It exposes just the public
/// Runtime observation authorities needed to start the two Node daemons.
pub struct PreparedDeveloperFixtureDistributedAgentStackV1 {
    coordinator: DistributedCoordinatorContextV1,
    predecessors: [VerifiedDistributedAgentStackPredecessorV1; 2],
    lifecycle_budget: BoundedDuration,
    targets: [PreparedDeveloperFixtureDistributedTargetV1; 2],
    observation_authorities: [RuntimeObservationAuthorityV1; 2],
}

impl fmt::Debug for PreparedDeveloperFixtureDistributedAgentStackV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDeveloperFixtureDistributedAgentStackV1")
            .field(
                "observation_authorities",
                &"<redacted-public-contract-pair>",
            )
            .finish_non_exhaustive()
    }
}

impl PreparedDeveloperFixtureDistributedAgentStackV1 {
    /// Exact A/B Runtime authorities in strict RuntimeHostId order. These are
    /// public Node contracts, not Deployment journal or preflight DTOs.
    #[must_use]
    pub fn runtime_observation_authorities(&self) -> [RuntimeObservationAuthorityV1; 2] {
        self.observation_authorities.clone()
    }

    #[must_use]
    pub fn runtime_targets(&self) -> [RuntimeHostId; 2] {
        [
            self.observation_authorities[0].runtime_host_id(),
            self.observation_authorities[1].runtime_host_id(),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureDistributedAgentStackOutcomeV1 {
    target_receipts: [Box<[u8]>; 2],
    replayed: bool,
}

impl DeveloperFixtureDistributedAgentStackOutcomeV1 {
    /// Exact durable PXDS v2 receipts in strict RuntimeHostId A/B order.
    #[must_use]
    pub fn target_receipts(&self) -> [&[u8]; 2] {
        [&self.target_receipts[0], &self.target_receipts[1]]
    }

    /// True only when the complete two-target ActiveReady pair existed before
    /// this completion call and both receipts were replayed from durable state.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeveloperFixtureDistributedAgentStackError {
    InvalidInput,
    TargetA(DeveloperFixtureAgentStackError),
    TargetB(DeveloperFixtureAgentStackError),
    Coordinator,
    Predecessor,
    ObservationAuthority,
    OwnerOperation,
    PendingNotSent,
    TerminalNonReady,
    Uncertain,
    IndeterminateUncertain,
}

impl fmt::Display for DeveloperFixtureDistributedAgentStackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "developer fixture distributed Agent stack failed closed: {self:?}"
        )
    }
}

impl std::error::Error for DeveloperFixtureDistributedAgentStackError {}

/// Explicit provisioned-provider developer facade input. It reuses the same
/// durable Controller chain as the fixture facade, while requiring an exact
/// Provisioned provider selection and never supplying a fallback.
pub struct DeveloperProvisionedAgentStackInputV1 {
    common: DeveloperFixtureAgentStackInputV1,
    provider: ManagedAgentProviderSelectionV1,
}

impl DeveloperProvisionedAgentStackInputV1 {
    pub fn try_new(
        common: DeveloperFixtureAgentStackInputV1,
        provider: ManagedAgentProviderSelectionV1,
    ) -> Result<Self, DeveloperFixtureAgentStackError> {
        validate_provisioned_provider_selection(common.identities, provider)?;
        Ok(Self { common, provider })
    }
}

fn validate_provisioned_provider_selection(
    identities: DeveloperFixtureDerivedIdentityV1,
    provider: ManagedAgentProviderSelectionV1,
) -> Result<(), DeveloperFixtureAgentStackError> {
    if provider.profile() != ManagedAgentProviderProfileV1::Provisioned
        || provider.provider_ref().as_bytes() != &identities.provider_ref()
        || provider.config_digest().as_bytes() != &identities.provider_configuration_digest()
    {
        return Err(DeveloperFixtureAgentStackError::InvalidInput);
    }
    Ok(())
}

impl fmt::Debug for DeveloperProvisionedAgentStackInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperProvisionedAgentStackInputV1")
            .field("common", &self.common)
            .field("provider", &self.provider)
            .finish()
    }
}

/// A2 successor input over the deterministic developer fixture provider. The
/// complete Model service plan, including its exact provider and adapter
/// binding, is caller-owned and never synthesized by Deployment.
pub struct DeveloperFixtureModelAgentStackInputV1 {
    common: DeveloperFixtureAgentStackInputV1,
    model: ManagedModelServicePlanV1,
}

impl DeveloperFixtureModelAgentStackInputV1 {
    pub fn try_new(
        common: DeveloperFixtureAgentStackInputV1,
        model: ManagedModelServicePlanV1,
    ) -> Result<Self, DeveloperFixtureModelAgentStackError> {
        let provider = deterministic_provider(common.identities)
            .map_err(DeveloperFixtureModelAgentStackError::Base)?;
        validate_model_plan(common.identities, provider, model)?;
        Ok(Self { common, model })
    }
}

impl fmt::Debug for DeveloperFixtureModelAgentStackInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperFixtureModelAgentStackInputV1")
            .field("common", &self.common)
            .field("model", &self.model)
            .finish()
    }
}

/// A2 successor input over one exact Provisioned Agent provider. Model and
/// Agent must retain the same explicit provider selection.
pub struct DeveloperProvisionedModelAgentStackInputV1 {
    common: DeveloperFixtureAgentStackInputV1,
    provider: ManagedAgentProviderSelectionV1,
    model: ManagedModelServicePlanV1,
}

impl DeveloperProvisionedModelAgentStackInputV1 {
    pub fn try_new(
        common: DeveloperProvisionedAgentStackInputV1,
        model: ManagedModelServicePlanV1,
    ) -> Result<Self, DeveloperFixtureModelAgentStackError> {
        validate_model_plan(common.common.identities, common.provider, model)?;
        Ok(Self {
            common: common.common,
            provider: common.provider,
            model,
        })
    }
}

impl fmt::Debug for DeveloperProvisionedModelAgentStackInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperProvisionedModelAgentStackInputV1")
            .field("common", &self.common)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .finish()
    }
}

fn validate_model_plan(
    identities: DeveloperFixtureDerivedIdentityV1,
    agent_provider: ManagedAgentProviderSelectionV1,
    model: ManagedModelServicePlanV1,
) -> Result<(), DeveloperFixtureModelAgentStackError> {
    let model_service_id = model.service().service_id();
    if model.provider() != agent_provider
        || model_service_id.as_bytes() != &identities.model_service_id()
        || model_service_id.as_bytes() == &identities.fabric_service_id()
        || model_service_id.as_bytes() == &identities.agent_service_id()
    {
        return Err(DeveloperFixtureModelAgentStackError::InvalidInput);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureAgentStackOutcomeV1 {
    controller_store_instance_id: [u8; 32],
    successor_store_instance_id: [u8; 32],
    runtime_store_instance_id: [u8; 32],
    serving_response_digest: Digest32,
    fabric_request_digest: Digest32,
    fabric_receipt_digest: Digest32,
    agent_request_digest: Digest32,
    agent_receipt_digest: Digest32,
    agent_terminal_receipt: Box<[u8]>,
    authority_tenure_epoch: u64,
    authority_proof_digest: Digest32,
    controller_revision: u64,
    controller_snapshot_sequence: u64,
    fabric_replayed: bool,
    agent_replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperProvisionedAgentStackOutcomeV1(DeveloperFixtureAgentStackOutcomeV1);

impl DeveloperProvisionedAgentStackOutcomeV1 {
    /// Exact authenticated PXST bytes required by the TUI-side broker claim.
    #[must_use]
    pub fn agent_terminal_receipt(&self) -> &[u8] {
        self.0.agent_terminal_receipt()
    }

    #[must_use]
    pub const fn authority_tenure_epoch(&self) -> u64 {
        self.0.authority_tenure_epoch()
    }

    #[must_use]
    pub const fn authority_proof_digest(&self) -> Digest32 {
        self.0.authority_proof_digest()
    }

    #[must_use]
    pub const fn controller_revision(&self) -> u64 {
        self.0.controller_revision()
    }

    #[must_use]
    pub const fn controller_snapshot_sequence(&self) -> u64 {
        self.0.controller_snapshot_sequence()
    }

    #[must_use]
    pub const fn agent_request_digest(&self) -> Digest32 {
        self.0.agent_request_digest()
    }

    #[must_use]
    pub const fn agent_receipt_digest(&self) -> Digest32 {
        self.0.agent_receipt_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureAgentStackDeactivationOutcomeV1 {
    agent_request_digest: Digest32,
    agent_receipt_digest: Digest32,
    agent_terminal_receipt: Box<[u8]>,
    replayed: bool,
}

impl DeveloperFixtureAgentStackDeactivationOutcomeV1 {
    #[must_use]
    pub const fn agent_request_digest(&self) -> Digest32 {
        self.agent_request_digest
    }

    #[must_use]
    pub const fn agent_receipt_digest(&self) -> Digest32 {
        self.agent_receipt_digest
    }

    /// Exact authenticated empty PXST bytes proving Runtime reached exact zero.
    #[must_use]
    pub fn agent_terminal_receipt(&self) -> &[u8] {
        &self.agent_terminal_receipt
    }

    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureModelAgentStackOutcomeV1 {
    controller_store_instance_id: [u8; 32],
    successor_store_instance_id: [u8; 32],
    runtime_store_instance_id: [u8; 32],
    serving_response_digest: Digest32,
    fabric_request_digest: Digest32,
    fabric_receipt_digest: Digest32,
    model_agent_request_digest: Digest32,
    model_agent_receipt_digest: Digest32,
    model_agent_terminal_receipt: Box<[u8]>,
    authority_tenure_epoch: u64,
    authority_proof_digest: Digest32,
    controller_revision: u64,
    controller_snapshot_sequence: u64,
    fabric_replayed: bool,
    model_agent_replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperProvisionedModelAgentStackOutcomeV1(DeveloperFixtureModelAgentStackOutcomeV1);

impl DeveloperProvisionedModelAgentStackOutcomeV1 {
    #[must_use]
    pub fn model_agent_terminal_receipt(&self) -> &[u8] {
        self.0.model_agent_terminal_receipt()
    }

    #[must_use]
    pub const fn authority_tenure_epoch(&self) -> u64 {
        self.0.authority_tenure_epoch()
    }

    #[must_use]
    pub const fn authority_proof_digest(&self) -> Digest32 {
        self.0.authority_proof_digest()
    }

    #[must_use]
    pub const fn controller_revision(&self) -> u64 {
        self.0.controller_revision()
    }

    #[must_use]
    pub const fn controller_snapshot_sequence(&self) -> u64 {
        self.0.controller_snapshot_sequence()
    }

    #[must_use]
    pub const fn model_agent_request_digest(&self) -> Digest32 {
        self.0.model_agent_request_digest()
    }

    #[must_use]
    pub const fn model_agent_receipt_digest(&self) -> Digest32 {
        self.0.model_agent_receipt_digest()
    }
}

impl DeveloperFixtureModelAgentStackOutcomeV1 {
    #[must_use]
    pub const fn controller_store_instance_id(&self) -> [u8; 32] {
        self.controller_store_instance_id
    }

    #[must_use]
    pub const fn successor_store_instance_id(&self) -> [u8; 32] {
        self.successor_store_instance_id
    }

    #[must_use]
    pub const fn runtime_store_instance_id(&self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    #[must_use]
    pub const fn serving_response_digest(&self) -> Digest32 {
        self.serving_response_digest
    }

    #[must_use]
    pub const fn fabric_request_digest(&self) -> Digest32 {
        self.fabric_request_digest
    }

    #[must_use]
    pub const fn fabric_receipt_digest(&self) -> Digest32 {
        self.fabric_receipt_digest
    }

    #[must_use]
    pub const fn model_agent_request_digest(&self) -> Digest32 {
        self.model_agent_request_digest
    }

    #[must_use]
    pub const fn model_agent_receipt_digest(&self) -> Digest32 {
        self.model_agent_receipt_digest
    }

    #[must_use]
    pub fn model_agent_terminal_receipt(&self) -> &[u8] {
        &self.model_agent_terminal_receipt
    }

    #[must_use]
    pub const fn authority_tenure_epoch(&self) -> u64 {
        self.authority_tenure_epoch
    }

    #[must_use]
    pub const fn authority_proof_digest(&self) -> Digest32 {
        self.authority_proof_digest
    }

    #[must_use]
    pub const fn controller_revision(&self) -> u64 {
        self.controller_revision
    }

    #[must_use]
    pub const fn controller_snapshot_sequence(&self) -> u64 {
        self.controller_snapshot_sequence
    }

    #[must_use]
    pub const fn fabric_replayed(&self) -> bool {
        self.fabric_replayed
    }

    #[must_use]
    pub const fn model_agent_replayed(&self) -> bool {
        self.model_agent_replayed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperFixtureModelAgentStackDeactivationOutcomeV1 {
    model_agent_request_digest: Digest32,
    model_agent_receipt_digest: Digest32,
    model_agent_terminal_receipt: Box<[u8]>,
    replayed: bool,
}

impl DeveloperFixtureModelAgentStackDeactivationOutcomeV1 {
    #[must_use]
    pub const fn model_agent_request_digest(&self) -> Digest32 {
        self.model_agent_request_digest
    }

    #[must_use]
    pub const fn model_agent_receipt_digest(&self) -> Digest32 {
        self.model_agent_receipt_digest
    }

    #[must_use]
    pub fn model_agent_terminal_receipt(&self) -> &[u8] {
        &self.model_agent_terminal_receipt
    }

    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

impl DeveloperFixtureAgentStackOutcomeV1 {
    #[must_use]
    pub const fn controller_store_instance_id(&self) -> [u8; 32] {
        self.controller_store_instance_id
    }

    #[must_use]
    pub const fn successor_store_instance_id(&self) -> [u8; 32] {
        self.successor_store_instance_id
    }

    #[must_use]
    pub const fn runtime_store_instance_id(&self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    #[must_use]
    pub const fn serving_response_digest(&self) -> Digest32 {
        self.serving_response_digest
    }

    #[must_use]
    pub const fn fabric_receipt_digest(&self) -> Digest32 {
        self.fabric_receipt_digest
    }

    #[must_use]
    pub const fn fabric_request_digest(&self) -> Digest32 {
        self.fabric_request_digest
    }

    #[must_use]
    pub const fn agent_request_digest(&self) -> Digest32 {
        self.agent_request_digest
    }

    #[must_use]
    pub const fn agent_receipt_digest(&self) -> Digest32 {
        self.agent_receipt_digest
    }

    /// Exact authenticated PXST bytes required by the TUI-side broker claim.
    #[must_use]
    pub fn agent_terminal_receipt(&self) -> &[u8] {
        &self.agent_terminal_receipt
    }

    /// Authority-issued writer epoch selected by the committed Controller state.
    #[must_use]
    pub const fn authority_tenure_epoch(&self) -> u64 {
        self.authority_tenure_epoch
    }

    /// Digest of the exact Authority-signed tenure proof retained by Controller.
    #[must_use]
    pub const fn authority_proof_digest(&self) -> Digest32 {
        self.authority_proof_digest
    }

    /// Source revision of the exact active Fabric-to-Agent desired state.
    #[must_use]
    pub const fn controller_revision(&self) -> u64 {
        self.controller_revision
    }

    /// Durable successor snapshot sequence containing the active PXST.
    #[must_use]
    pub const fn controller_snapshot_sequence(&self) -> u64 {
        self.controller_snapshot_sequence
    }

    #[must_use]
    pub const fn fabric_replayed(&self) -> bool {
        self.fabric_replayed
    }

    #[must_use]
    pub const fn agent_replayed(&self) -> bool {
        self.agent_replayed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeveloperFixtureAgentStackError {
    InvalidInput,
    Filesystem,
    Initialization,
    Planning,
    Tenure,
    Bootstrap,
    Cutover,
    ServingObservation,
    FabricApply,
    AgentApply,
    Runtime,
}

impl fmt::Display for DeveloperFixtureAgentStackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "developer fixture Agent stack failed closed: {self:?}"
        )
    }
}

impl std::error::Error for DeveloperFixtureAgentStackError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeveloperFixtureModelAgentStackError {
    InvalidInput,
    Base(DeveloperFixtureAgentStackError),
    ModelAgentApply,
}

impl From<DeveloperFixtureAgentStackError> for DeveloperFixtureModelAgentStackError {
    fn from(value: DeveloperFixtureAgentStackError) -> Self {
        Self::Base(value)
    }
}

impl fmt::Display for DeveloperFixtureModelAgentStackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "developer fixture Model+Agent successor failed closed: {self:?}"
        )
    }
}

impl std::error::Error for DeveloperFixtureModelAgentStackError {}

/// Phase one: advances and seals both durable single-target ActiveReady
/// predecessors, then returns only the public Runtime observation authorities
/// required to construct PXOB and start the two Node daemons.
pub fn prepare_developer_fixture_distributed_agent_stack_v1(
    input: DeveloperFixtureDistributedAgentStackInputV1,
) -> Result<
    PreparedDeveloperFixtureDistributedAgentStackV1,
    DeveloperFixtureDistributedAgentStackError,
> {
    let DeveloperFixtureDistributedAgentStackInputV1 {
        coordinator,
        lifecycle_budget,
        targets: [first, second],
    } = input;
    if lifecycle_budget.value() == 0
        || first.agent_stack.identities.runtime_target()
            >= second.agent_stack.identities.runtime_target()
    {
        return Err(DeveloperFixtureDistributedAgentStackError::InvalidInput);
    }
    let (first_context, first_predecessor, first_authority, first_runtime_query_client) =
        advance_developer_distributed_predecessor(
            first.agent_stack,
            &first.transport,
            DeveloperFixtureDistributedAgentStackError::TargetA,
        )?;
    let (second_context, second_predecessor, second_authority, second_runtime_query_client) =
        advance_developer_distributed_predecessor(
            second.agent_stack,
            &second.transport,
            DeveloperFixtureDistributedAgentStackError::TargetB,
        )?;
    crate::distributed_agent_stack_producer::validate_predecessor_pair([
        &first_predecessor,
        &second_predecessor,
    ])
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::Predecessor)?;
    validate_developer_distributed_context_pair(&first_context, &second_context)?;
    let coordinator = open_or_initialize_developer_distributed_coordinator(
        &first_context,
        &second_context,
        coordinator,
    )?;
    Ok(PreparedDeveloperFixtureDistributedAgentStackV1 {
        coordinator,
        predecessors: [first_predecessor, second_predecessor],
        lifecycle_budget,
        targets: [
            PreparedDeveloperFixtureDistributedTargetV1 {
                topology: first.topology,
                connector: distributed_owner_connector(first.transport),
                runtime_query_client: first_runtime_query_client,
            },
            PreparedDeveloperFixtureDistributedTargetV1 {
                topology: second.topology,
                connector: distributed_owner_connector(second.transport),
                runtime_query_client: second_runtime_query_client,
            },
        ],
        observation_authorities: [first_authority, second_authority],
    })
}

/// Phase two: after Local has used the prepared public authorities to start
/// both Node daemons, performs the typed D1D initialize/observe/restricted-
/// apply owner path and returns only exact durable ActiveReady PXDS v2 bytes.
pub fn complete_developer_fixture_distributed_agent_stack_v1(
    prepared: PreparedDeveloperFixtureDistributedAgentStackV1,
    nodes: [DeveloperFixtureDistributedNodeV1; 2],
) -> Result<
    DeveloperFixtureDistributedAgentStackOutcomeV1,
    DeveloperFixtureDistributedAgentStackError,
> {
    let PreparedDeveloperFixtureDistributedAgentStackV1 {
        coordinator,
        predecessors,
        lifecycle_budget,
        targets: [first, second],
        observation_authorities,
    } = prepared;
    let [first_authority, second_authority] = observation_authorities;
    let [first_node, second_node] = nodes;
    if first_authority.runtime_host_id() != predecessors[0].target()
        || second_authority.runtime_host_id() != predecessors[1].target()
        || first_node.management_target.node_id() == second_node.management_target.node_id()
        || first_node.socket_path == second_node.socket_path
    {
        return Err(DeveloperFixtureDistributedAgentStackError::InvalidInput);
    }
    let peer = DeveloperLocalPeerIdentityV1::current()
        .map_err(|_| DeveloperFixtureDistributedAgentStackError::InvalidInput)?;
    let outcome: DistributedAgentStackOwnerApplyOutcomeV1 =
        run_developer_local_distributed_agent_stack_owner_v1(
            coordinator,
            predecessors,
            lifecycle_budget,
            [
                DistributedAgentStackOwnerTargetInputV1::new(
                    first.topology,
                    DistributedAgentStackOwnerNodeInputV1::new(
                        first_node.management_target,
                        first_node.socket_path,
                        peer.uid(),
                        peer.gid(),
                        first_node.token,
                        first_node.observation_endpoint_ref,
                        first_node.observation_socket_path,
                        first_node.observation_token,
                    ),
                    first.connector,
                    first_authority,
                    first.runtime_query_client,
                ),
                DistributedAgentStackOwnerTargetInputV1::new(
                    second.topology,
                    DistributedAgentStackOwnerNodeInputV1::new(
                        second_node.management_target,
                        second_node.socket_path,
                        peer.uid(),
                        peer.gid(),
                        second_node.token,
                        second_node.observation_endpoint_ref,
                        second_node.observation_socket_path,
                        second_node.observation_token,
                    ),
                    second.connector,
                    second_authority,
                    second.runtime_query_client,
                ),
            ],
        )
        .map_err(map_distributed_owner_error)?;
    let (target_receipts, replayed) = outcome.into_parts();
    Ok(DeveloperFixtureDistributedAgentStackOutcomeV1 {
        target_receipts,
        replayed,
    })
}

/// Advances the real developer-local Controller path through an authenticated
/// active Fabric and Agent terminal. The caller must keep both the real
/// Authority and Runtime lifecycle handles alive for this complete call.
pub fn run_developer_fixture_agent_stack_v1(
    input: DeveloperFixtureAgentStackInputV1,
) -> Result<DeveloperFixtureAgentStackOutcomeV1, DeveloperFixtureAgentStackError> {
    let provider = deterministic_provider(input.identities)?;
    run_developer_agent_stack(input, provider)
}

/// Advances the same real developer-local Controller path with one exact
/// Provisioned selection. This facade neither accepts deterministic selection
/// nor falls back to the fixture provider.
pub fn run_developer_provisioned_agent_stack_v1(
    input: DeveloperProvisionedAgentStackInputV1,
) -> Result<DeveloperProvisionedAgentStackOutcomeV1, DeveloperFixtureAgentStackError> {
    run_developer_agent_stack(input.common, input.provider)
        .map(DeveloperProvisionedAgentStackOutcomeV1)
}

/// Activates the A2 PXAR v9 Fabric/Model/Agent sibling over the exact active
/// PXAR v6 Fabric predecessor. It never executes or upgrades a PXAR v7 root.
pub fn run_developer_fixture_model_agent_stack_v1(
    input: DeveloperFixtureModelAgentStackInputV1,
) -> Result<DeveloperFixtureModelAgentStackOutcomeV1, DeveloperFixtureModelAgentStackError> {
    let provider = deterministic_provider(input.common.identities)?;
    run_developer_model_agent_stack(input.common, provider, input.model)
}

/// Provisioned-provider A2 facade. Agent and Model use the same exact provider
/// selection while sharing the identical PXMJ/PXAR9 path with the fixture API.
pub fn run_developer_provisioned_model_agent_stack_v1(
    input: DeveloperProvisionedModelAgentStackInputV1,
) -> Result<DeveloperProvisionedModelAgentStackOutcomeV1, DeveloperFixtureModelAgentStackError> {
    run_developer_model_agent_stack(input.common, input.provider, input.model)
        .map(DeveloperProvisionedModelAgentStackOutcomeV1)
}

fn run_developer_model_agent_stack(
    input: DeveloperFixtureAgentStackInputV1,
    provider: ManagedAgentProviderSelectionV1,
    model: ManagedModelServicePlanV1,
) -> Result<DeveloperFixtureModelAgentStackOutcomeV1, DeveloperFixtureModelAgentStackError> {
    validate_model_plan(input.identities, provider, model)?;
    let context = FixtureContext::try_new(input, provider)?;
    let runtime = RuntimeBuilder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;

    let mut successor = match open_or_initialize_legacy(&context) {
        Ok(legacy) => advance_legacy_and_cutover(&context, &runtime, legacy)?,
        Err(_) => ManagedFabricSuccessorStoreV1::resume_from_cutover_marker_developer_local(
            &context.paths.controller_state_directory,
            &context.paths.successor_state_directory,
            context.identities.successor_store_instance_id(),
            context.owner_identity,
            &context.controller_signer,
            &context.fabric_provisioning,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::Cutover)?,
    };
    ensure_a2_successor_root(successor.state())?;

    let serving = advance_serving_pin(&context, &runtime, &mut successor)?;
    let fabric = advance_fabric_active(&context, &runtime, &mut successor)?;
    let model_agent = advance_model_agent_active(&context, &runtime, &mut successor, model)?;
    let final_state = successor.state();
    let authority_proof = final_state
        .legacy_snapshot()
        .state()
        .latest_committed_tenure_proof(PlanWriterRef::from_bytes(context.identities.writer()))
        .ok_or(DeveloperFixtureAgentStackError::Tenure)?;
    let authority_tenure_epoch = authority_proof.claim().epoch().value();
    let authority_proof_digest = authority_proof
        .envelope_digest()
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    let controller_revision = final_state
        .model_agent_stack_state()
        .ok_or(DeveloperFixtureModelAgentStackError::ModelAgentApply)?
        .desired()
        .revision()
        .value();
    let controller_snapshot_sequence = final_state.sequence();
    Ok(DeveloperFixtureModelAgentStackOutcomeV1 {
        controller_store_instance_id: *final_state.legacy_snapshot().store_instance_id(),
        successor_store_instance_id: context.identities.successor_store_instance_id(),
        runtime_store_instance_id: context.runtime_store_instance_id,
        serving_response_digest: serving.response_digest(),
        fabric_request_digest: fabric.receipt().request_digest(),
        fabric_receipt_digest: fabric.receipt().receipt_digest(),
        model_agent_request_digest: model_agent.receipt().facts().request_digest(),
        model_agent_receipt_digest: model_agent.receipt().receipt_digest(),
        model_agent_terminal_receipt: model_agent.receipt().canonical_wire().into(),
        authority_tenure_epoch,
        authority_proof_digest,
        controller_revision,
        controller_snapshot_sequence,
        fabric_replayed: fabric.replayed_from_journal(),
        model_agent_replayed: model_agent.replayed_from_journal(),
    })
}

fn run_developer_agent_stack(
    input: DeveloperFixtureAgentStackInputV1,
    provider: ManagedAgentProviderSelectionV1,
) -> Result<DeveloperFixtureAgentStackOutcomeV1, DeveloperFixtureAgentStackError> {
    let context = FixtureContext::try_new(input, provider)?;
    let runtime = RuntimeBuilder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;

    let mut successor = match open_or_initialize_legacy(&context) {
        Ok(legacy) => advance_legacy_and_cutover(&context, &runtime, legacy)?,
        Err(_) => ManagedFabricSuccessorStoreV1::resume_from_cutover_marker_developer_local(
            &context.paths.controller_state_directory,
            &context.paths.successor_state_directory,
            context.identities.successor_store_instance_id(),
            context.owner_identity,
            &context.controller_signer,
            &context.fabric_provisioning,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::Cutover)?,
    };

    let serving = advance_serving_pin(&context, &runtime, &mut successor)?;
    let fabric = advance_fabric_active(&context, &runtime, &mut successor)?;
    let agent = advance_agent_active(&context, &runtime, &mut successor)?;
    let final_state = successor.state();
    let authority_proof = final_state
        .legacy_snapshot()
        .state()
        .latest_committed_tenure_proof(PlanWriterRef::from_bytes(context.identities.writer()))
        .ok_or(DeveloperFixtureAgentStackError::Tenure)?;
    let authority_tenure_epoch = authority_proof.claim().epoch().value();
    let authority_proof_digest = authority_proof
        .envelope_digest()
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    let controller_revision = final_state
        .agent_stack_state()
        .ok_or(DeveloperFixtureAgentStackError::AgentApply)?
        .desired()
        .revision()
        .value();
    let controller_snapshot_sequence = final_state.sequence();
    Ok(DeveloperFixtureAgentStackOutcomeV1 {
        controller_store_instance_id: *successor.state().legacy_snapshot().store_instance_id(),
        successor_store_instance_id: context.identities.successor_store_instance_id(),
        runtime_store_instance_id: context.runtime_store_instance_id,
        serving_response_digest: serving.response_digest(),
        fabric_request_digest: fabric.receipt().request_digest(),
        fabric_receipt_digest: fabric.receipt().receipt_digest(),
        agent_request_digest: agent.receipt().facts().request_digest(),
        agent_receipt_digest: agent.receipt().receipt_digest(),
        agent_terminal_receipt: agent.receipt().canonical_wire().into(),
        authority_tenure_epoch,
        authority_proof_digest,
        controller_revision,
        controller_snapshot_sequence,
        fabric_replayed: fabric.replayed_from_journal(),
        agent_replayed: agent.replayed_from_journal(),
    })
}

fn advance_developer_distributed_predecessor(
    input: DeveloperFixtureAgentStackInputV1,
    transport: &DeveloperFixtureDistributedTransportV1,
    map_error: fn(DeveloperFixtureAgentStackError) -> DeveloperFixtureDistributedAgentStackError,
) -> Result<
    (
        FixtureContext,
        VerifiedDistributedAgentStackPredecessorV1,
        RuntimeObservationAuthorityV1,
        UnixRuntimeQueryClient,
    ),
    DeveloperFixtureDistributedAgentStackError,
> {
    let provider = deterministic_provider(input.identities).map_err(map_error)?;
    let context = FixtureContext::try_new(input, provider).map_err(map_error)?;
    let runtime = RuntimeBuilder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| map_error(DeveloperFixtureAgentStackError::Runtime))?;
    let mut successor = match open_or_initialize_legacy(&context) {
        Ok(legacy) => advance_legacy_and_cutover(&context, &runtime, legacy).map_err(map_error)?,
        Err(_) => ManagedFabricSuccessorStoreV1::resume_from_cutover_marker_developer_local(
            &context.paths.controller_state_directory,
            &context.paths.successor_state_directory,
            context.identities.successor_store_instance_id(),
            context.owner_identity,
            &context.controller_signer,
            &context.fabric_provisioning,
        )
        .map_err(|_| map_error(DeveloperFixtureAgentStackError::Cutover))?,
    };
    advance_serving_pin(&context, &runtime, &mut successor).map_err(map_error)?;
    advance_fabric_active(&context, &runtime, &mut successor).map_err(map_error)?;
    advance_agent_active(&context, &runtime, &mut successor).map_err(map_error)?;
    let state = successor.state();
    let base = state
        .verified_current_context(&context.controller_signer, &context.fabric_provisioning)
        .map_err(|_| DeveloperFixtureDistributedAgentStackError::Predecessor)?;
    let predecessor = VerifiedDistributedAgentStackPredecessorV1::try_from_committed(
        &base,
        state
            .agent_stack_state()
            .ok_or(DeveloperFixtureDistributedAgentStackError::Predecessor)?,
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::Predecessor)?;
    let authority =
        distributed_runtime_observation_authority(state, &context, &predecessor, transport)?;
    let runtime_query_client = distributed_runtime_query_client(&context, &predecessor)?;
    Ok((context, predecessor, authority, runtime_query_client))
}

fn distributed_runtime_query_client(
    context: &FixtureContext,
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
) -> Result<UnixRuntimeQueryClient, DeveloperFixtureDistributedAgentStackError> {
    if RuntimeHostId::from_bytes(context.identities.runtime_target()) != predecessor.target()
        || PrincipalRef::from_bytes(context.identities.runtime_principal())
            != predecessor.runtime_principal()
        || ApplyAuthKeyRef::from_bytes(context.identities.runtime_response_key_ref())
            != predecessor.runtime_response_key()
        || context.runtime_response_verification_key != *predecessor.runtime_response_public_key()
    {
        return Err(DeveloperFixtureDistributedAgentStackError::Predecessor);
    }
    let runtime_key_fingerprint =
        ed25519_control_key_fingerprint(predecessor.runtime_response_public_key().as_bytes())
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?;
    let response_verifier = RuntimeQueryResponseVerifier::try_new(
        predecessor.runtime_principal(),
        predecessor.runtime_response_key(),
        ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?,
        ED25519_ALGORITHM_VERSION,
        runtime_key_fingerprint,
        *predecessor.runtime_response_public_key(),
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?;
    UnixRuntimeQueryClient::try_new(
        runtime_endpoint(context)
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?,
        response_verifier,
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)
}

fn distributed_runtime_observation_authority(
    state: &ManagedFabricControllerStateV1,
    context: &FixtureContext,
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    transport: &DeveloperFixtureDistributedTransportV1,
) -> Result<RuntimeObservationAuthorityV1, DeveloperFixtureDistributedAgentStackError> {
    let journal = ManagedFabricApplyJournalV1::new(state.clone());
    let serving_pin = journal
        .current_serving_pin(&context.controller_signer, &context.fabric_provisioning)
        .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?;
    let facts = serving_pin.facts();
    let serving = ReferenceBootstrapServingIdentityV1::try_new(
        facts.target(),
        facts.runtime_store_instance_id(),
        facts.snapshot_sequence(),
        facts.runtime_host_epoch(),
        facts.clock_domain(),
        facts.clock_generation(),
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?;
    let profile = &transport.transport_profile;
    let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
        RuntimeApplyEndpointRefV1::try_from_bytes(profile.endpoint_ref())
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?,
        predecessor.target(),
        profile.endpoint_generation(),
        profile.route(),
        *predecessor.runtime_response_key().as_bytes(),
        predecessor.runtime_response_public_key().to_bytes(),
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?;
    let controller_fingerprint =
        ed25519_control_key_fingerprint(predecessor.controller_verifying_key())
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?;
    let runtime_fingerprint =
        ed25519_control_key_fingerprint(predecessor.runtime_response_public_key().as_bytes())
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)?;
    if facts.target() != predecessor.target()
        || transport.expected_carrier.target() != predecessor.target()
        || transport.expected_carrier.controller_principal() != predecessor.controller_principal()
        || transport.expected_carrier.runtime_principal() != predecessor.runtime_principal()
        || transport.expected_carrier.endpoint_ref() != profile.endpoint_ref()
        || transport.expected_carrier.endpoint_generation() != profile.endpoint_generation()
        || transport.expected_carrier.route() != profile.route()
        || transport.expected_carrier.controller_request_key() != predecessor.request_key()
        || transport
            .expected_carrier
            .controller_request_key_fingerprint()
            != controller_fingerprint
        || transport.expected_carrier.runtime_response_key() != predecessor.runtime_response_key()
        || transport
            .expected_carrier
            .runtime_response_key_fingerprint()
            != runtime_fingerprint
        || transport.expected_carrier.control_transport_profile_ref() != transport.profile_ref
        || transport
            .expected_carrier
            .control_transport_profile_digest()
            != profile.profile_digest()
    {
        return Err(DeveloperFixtureDistributedAgentStackError::ObservationAuthority);
    }
    RuntimeObservationAuthorityV1::try_new(
        predecessor.runtime_principal(),
        predecessor.runtime_channel(),
        serving,
        endpoint,
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::ObservationAuthority)
}

fn validate_developer_distributed_context_pair(
    first: &FixtureContext,
    second: &FixtureContext,
) -> Result<(), DeveloperFixtureDistributedAgentStackError> {
    if first.peer != second.peer
        || first.identities.source_scope() != second.identities.source_scope()
        || first.identities.source_plan() != second.identities.source_plan()
        || first.identities.writer() != second.identities.writer()
        || first.identities.controller_principal() != second.identities.controller_principal()
        || first.identities.controller_key_ref() != second.identities.controller_key_ref()
        || first.request_auth != second.request_auth
        || first.controller_signer.verifying_key() != second.controller_signer.verifying_key()
        || first.paths.controller_state_directory == second.paths.controller_state_directory
        || first.paths.successor_state_directory == second.paths.successor_state_directory
        || first.identities.runtime_target() >= second.identities.runtime_target()
    {
        return Err(DeveloperFixtureDistributedAgentStackError::Predecessor);
    }
    Ok(())
}

fn open_or_initialize_developer_distributed_coordinator(
    first: &FixtureContext,
    second: &FixtureContext,
    coordinator: DeveloperFixtureDistributedCoordinatorV1,
) -> Result<DistributedCoordinatorContextV1, DeveloperFixtureDistributedAgentStackError> {
    validate_private_directory(&coordinator.state_directory, first.peer)
        .map_err(|_| DeveloperFixtureDistributedAgentStackError::Coordinator)?;
    let forbidden = [
        first.paths.controller_state_directory.as_path(),
        first.paths.successor_state_directory.as_path(),
        second.paths.controller_state_directory.as_path(),
        second.paths.successor_state_directory.as_path(),
        first.authority.state_directory(),
        second.authority.state_directory(),
    ];
    if forbidden.iter().any(|path| {
        coordinator.state_directory.starts_with(path)
            || path.starts_with(&coordinator.state_directory)
    }) {
        return Err(DeveloperFixtureDistributedAgentStackError::Coordinator);
    }
    let owner_identity = controller_owner_identity(
        &coordinator.state_directory,
        first.peer,
        first.identities,
        first.request_auth.verification_key_fingerprint().value(),
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::Coordinator)?;
    let allocation =
        StableAllocationSnapshot::try_new(first.installed_manifest.target(), 0, 0, Vec::new())
            .map_err(|_| DeveloperFixtureDistributedAgentStackError::Coordinator)?;
    let initialization = ControllerInitializationInput::try_new(
        DeploymentScopeId::from_bytes(first.identities.source_scope()),
        DeploymentId::from_bytes(first.identities.source_plan()),
        allocation,
        first.installed_manifest.clone(),
        first.request_auth,
        owner_identity,
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::Coordinator)?;
    let store = match initialize_controller_store_developer_local(
        &coordinator.state_directory,
        initialization,
    ) {
        Ok(receipt) => ControllerStore::open_developer_local(
            &coordinator.state_directory,
            *receipt.store_instance_id(),
            owner_identity,
        ),
        Err(_) => ControllerStore::open_developer_local_observed_identity(
            &coordinator.state_directory,
            owner_identity,
        ),
    }
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::Coordinator)?;
    verify_distributed_coordinator_context_v1(
        store,
        owner_identity,
        SigningKey::from_bytes(&first.controller_signer.to_bytes()),
    )
    .map_err(|_| DeveloperFixtureDistributedAgentStackError::Coordinator)
}

fn distributed_owner_connector(
    transport: DeveloperFixtureDistributedTransportV1,
) -> DistributedAgentStackOwnerConnectorInputV1 {
    DistributedAgentStackOwnerConnectorInputV1::new(
        transport.profile_ref,
        transport.transport_profile,
        transport.expected_carrier,
        transport.root_ca_certificate_file,
        transport.connector_certificate_file,
        transport.connector_private_key_file,
    )
}

const fn map_distributed_owner_error(
    error: DistributedAgentStackOwnerApplyErrorV1,
) -> DeveloperFixtureDistributedAgentStackError {
    match error {
        DistributedAgentStackOwnerApplyErrorV1::Operation => {
            DeveloperFixtureDistributedAgentStackError::OwnerOperation
        }
        DistributedAgentStackOwnerApplyErrorV1::PendingNotSent => {
            DeveloperFixtureDistributedAgentStackError::PendingNotSent
        }
        DistributedAgentStackOwnerApplyErrorV1::TerminalNonReady => {
            DeveloperFixtureDistributedAgentStackError::TerminalNonReady
        }
        DistributedAgentStackOwnerApplyErrorV1::Uncertain => {
            DeveloperFixtureDistributedAgentStackError::Uncertain
        }
        DistributedAgentStackOwnerApplyErrorV1::IndeterminateUncertain => {
            DeveloperFixtureDistributedAgentStackError::IndeterminateUncertain
        }
    }
}

/// Reopens only an already active successor, applies the canonical PXAR v7
/// empty target, and returns only after an authenticated exact-zero PXST is
/// durable. This is an explicit terminal retirement operation, not the normal
/// restartable launcher shutdown path. It never initializes or reconstructs a
/// missing active stack.
pub fn deactivate_developer_fixture_agent_stack_v1(
    input: DeveloperFixtureAgentStackInputV1,
) -> Result<DeveloperFixtureAgentStackDeactivationOutcomeV1, DeveloperFixtureAgentStackError> {
    let provider = deterministic_provider(input.identities)?;
    let context = FixtureContext::try_new(input, provider)?;
    let runtime = RuntimeBuilder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let mut successor = ManagedFabricSuccessorStoreV1::resume_from_cutover_marker_developer_local(
        &context.paths.controller_state_directory,
        &context.paths.successor_state_directory,
        context.identities.successor_store_instance_id(),
        context.owner_identity,
        &context.controller_signer,
        &context.fabric_provisioning,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Cutover)?;
    advance_agent_exact_zero(&context, &runtime, &mut successor)
}

/// Explicit A2 retirement. Success is only an authenticated durable PXMT
/// `EmptyExactZero`; every other terminal classification fails closed.
pub fn deactivate_developer_fixture_model_agent_stack_v1(
    input: DeveloperFixtureModelAgentStackInputV1,
) -> Result<
    DeveloperFixtureModelAgentStackDeactivationOutcomeV1,
    DeveloperFixtureModelAgentStackError,
> {
    let provider = deterministic_provider(input.common.identities)?;
    deactivate_developer_model_agent_stack(input.common, provider, input.model)
}

/// Provisioned-provider wrapper over the same exact A2 empty transition.
pub fn deactivate_developer_provisioned_model_agent_stack_v1(
    input: DeveloperProvisionedModelAgentStackInputV1,
) -> Result<
    DeveloperFixtureModelAgentStackDeactivationOutcomeV1,
    DeveloperFixtureModelAgentStackError,
> {
    deactivate_developer_model_agent_stack(input.common, input.provider, input.model)
}

fn deactivate_developer_model_agent_stack(
    input: DeveloperFixtureAgentStackInputV1,
    provider: ManagedAgentProviderSelectionV1,
    model: ManagedModelServicePlanV1,
) -> Result<
    DeveloperFixtureModelAgentStackDeactivationOutcomeV1,
    DeveloperFixtureModelAgentStackError,
> {
    validate_model_plan(input.identities, provider, model)?;
    let context = FixtureContext::try_new(input, provider)?;
    let runtime = RuntimeBuilder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let mut successor = ManagedFabricSuccessorStoreV1::resume_from_cutover_marker_developer_local(
        &context.paths.controller_state_directory,
        &context.paths.successor_state_directory,
        context.identities.successor_store_instance_id(),
        context.owner_identity,
        &context.controller_signer,
        &context.fabric_provisioning,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Cutover)?;
    ensure_a2_successor_root(successor.state())?;
    advance_model_agent_exact_zero(&context, &runtime, &mut successor, model)
}

struct FixtureContext {
    paths: DeveloperFixturePathsV1,
    identities: DeveloperFixtureDerivedIdentityV1,
    installed_manifest: ControllerInstalledManifestPin,
    runtime_store_instance_id: [u8; 32],
    runtime_response_verification_key: VerifyingKey,
    controller_signer: SigningKey,
    request_auth: ControllerRequestAuthPin,
    owner_identity: ControllerOwnerIdentityFingerprint,
    peer: DeveloperLocalPeerIdentityV1,
    authority: DeveloperLocalTenureAuthorityFactsV1,
    fabric_endpoint: ManagedFabricListenEndpointV1,
    fabric_provisioning: ManagedFabricControllerProvisioningV1,
    provider: ManagedAgentProviderSelectionV1,
}

impl FixtureContext {
    fn try_new(
        input: DeveloperFixtureAgentStackInputV1,
        provider: ManagedAgentProviderSelectionV1,
    ) -> Result<Self, DeveloperFixtureAgentStackError> {
        if provider.provider_ref().as_bytes() != &input.identities.provider_ref()
            || provider.config_digest().as_bytes()
                != &input.identities.provider_configuration_digest()
        {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        let peer = DeveloperLocalPeerIdentityV1::current()
            .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        validate_private_directory(&input.paths.controller_state_directory, peer)?;
        validate_private_directory(&input.paths.successor_state_directory, peer)?;
        validate_absolute_path(input.authority.state_directory())?;
        if input.authority.socket_path() != input.paths.authority_socket_path
            || input.authority.peer() != peer
            || input.authority.authority_verification_key()
                != input.credentials.authority_verification_key
            || input.authority.state_directory() == input.paths.controller_state_directory.as_path()
            || input.authority.state_directory() == input.paths.successor_state_directory.as_path()
            || input
                .authority
                .state_directory()
                .starts_with(&input.paths.controller_state_directory)
            || input
                .authority
                .state_directory()
                .starts_with(&input.paths.successor_state_directory)
            || input
                .paths
                .controller_state_directory
                .starts_with(input.authority.state_directory())
            || input
                .paths
                .successor_state_directory
                .starts_with(input.authority.state_directory())
            || input
                .paths
                .runtime_socket_path
                .starts_with(input.authority.state_directory())
        {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        let expected_authority_identities = DeveloperLocalTenureAuthorityIdentityBytesV1 {
            source_scope: input.identities.source_scope(),
            writer: input.identities.writer(),
            authority: input.identities.authority_ref(),
            authority_key: input.identities.authority_key_ref(),
            controller_principal: input.identities.controller_principal(),
            controller_key: input.identities.controller_key_ref(),
            service_principal: input.identities.authority_service_principal(),
            owner: input.identities.authority_owner(),
        };
        if input.authority.identities() != expected_authority_identities {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }

        let controller_signer = SigningKey::from_bytes(&input.credentials.controller_signing_seed);
        let controller_verification_key = controller_signer.verifying_key();
        if controller_verification_key.is_weak()
            || controller_verification_key.to_bytes()
                == input.runtime.runtime_response_verification_key
            || controller_verification_key.to_bytes()
                == input.credentials.authority_verification_key
            || input.runtime.runtime_response_verification_key
                == input.credentials.authority_verification_key
            || input.runtime.expected_runtime_store_instance_id
                == input.identities.successor_store_instance_id()
            || input.runtime.expected_runtime_store_instance_id
                == input.authority.store_instance_id()
            || input.identities.successor_store_instance_id() == input.authority.store_instance_id()
        {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        let controller_fingerprint =
            ed25519_control_key_fingerprint(controller_verification_key.as_bytes())
                .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        let controller_acquire_fingerprint =
            ControllerPublicKeyFingerprint::for_ed25519_key(controller_verification_key.as_bytes())
                .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        if input.authority.controller_public_key_fingerprint()
            != *controller_acquire_fingerprint.as_bytes()
        {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        let algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
            .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        let request_auth = ControllerRequestAuthPin::try_new(
            ApplyAuthKeyRef::from_bytes(input.identities.controller_key_ref()),
            algorithm,
            ED25519_ALGORITHM_VERSION,
            ControllerAuthKeyFingerprint::from_stored(controller_fingerprint),
            INITIAL_AUTH_ROTATION_GENERATION,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        let owner_identity = controller_owner_identity(
            &input.paths.controller_state_directory,
            peer,
            input.identities,
            controller_fingerprint,
        )?;
        let installed_manifest = ControllerInstalledManifestPin::try_from_persisted_manifest(
            &input.runtime.manifest_wire,
            input.runtime.manifest_digest,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        if installed_manifest.target()
            != RuntimeHostId::from_bytes(input.identities.runtime_target())
        {
            return Err(DeveloperFixtureAgentStackError::InvalidInput);
        }
        let runtime_response_verification_key =
            VerifyingKey::from_bytes(&input.runtime.runtime_response_verification_key)
                .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        let accounts = ManagedFabricServiceAccountsV1::try_new_developer_local(
            peer.uid(),
            peer.gid(),
            peer.uid(),
            peer.gid(),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        let controller = ManagedFabricControllerIdentityV1::try_new(
            PrincipalRef::from_bytes(input.identities.controller_principal()),
            DeploymentWriterRef::from_bytes(input.identities.writer()),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        let authority_pin = ManagedFabricTenureAuthorityPinV1::try_new(
            PrincipalRef::from_bytes(input.identities.authority_principal()),
            peer.uid(),
            peer.gid(),
            TenureAuthorityRef::from_bytes(input.identities.authority_ref()),
            TenureKeyRef::from_bytes(input.identities.authority_key_ref()),
            input.credentials.authority_verification_key,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        let runtime_pin = ManagedFabricRuntimeChannelPinV1::try_new(
            input.paths.runtime_socket_path.as_os_str().as_bytes(),
            PrincipalRef::from_bytes(input.identities.runtime_principal()),
            ApplyAuthKeyRef::from_bytes(input.identities.runtime_response_key_ref()),
            input.runtime.runtime_response_verification_key,
            accounts,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
        Ok(Self {
            paths: input.paths,
            identities: input.identities,
            installed_manifest,
            runtime_store_instance_id: input.runtime.expected_runtime_store_instance_id,
            runtime_response_verification_key,
            controller_signer,
            request_auth,
            owner_identity,
            peer,
            authority: input.authority,
            fabric_endpoint: input.fabric.0,
            fabric_provisioning: ManagedFabricControllerProvisioningV1::new(
                controller,
                authority_pin,
                runtime_pin,
            ),
            provider,
        })
    }
}

fn controller_owner_identity(
    state_directory: &Path,
    peer: DeveloperLocalPeerIdentityV1,
    identities: DeveloperFixtureDerivedIdentityV1,
    request_auth_fingerprint: Digest32,
) -> Result<ControllerOwnerIdentityFingerprint, DeveloperFixtureAgentStackError> {
    let mut builder = Digest32Builder::try_new(OWNER_IDENTITY_DOMAIN)
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
    builder
        .field_bytes(state_directory.as_os_str().as_bytes())
        .and_then(|builder| builder.field_u64(u64::from(peer.uid())))
        .and_then(|builder| builder.field_u64(u64::from(peer.gid())))
        .and_then(|builder| builder.field_bytes(&identities.source_scope()))
        .and_then(|builder| builder.field_bytes(&identities.source_plan()))
        .and_then(|builder| builder.field_bytes(&identities.controller_key_ref()))
        .and_then(|builder| builder.field_u16(ED25519_ALGORITHM))
        .and_then(|builder| builder.field_u16(ED25519_ALGORITHM_VERSION))
        .and_then(|builder| builder.field_digest(&request_auth_fingerprint))
        .and_then(|builder| builder.field_u64(INITIAL_AUTH_ROTATION_GENERATION))
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
    Ok(ControllerOwnerIdentityFingerprint::from_stored(
        builder.finish(),
    ))
}

fn open_or_initialize_legacy(
    context: &FixtureContext,
) -> Result<ControllerStore, DeveloperFixtureAgentStackError> {
    let allocation =
        StableAllocationSnapshot::try_new(context.installed_manifest.target(), 0, 0, Vec::new())
            .map_err(|_| DeveloperFixtureAgentStackError::Initialization)?;
    let initialization = ControllerInitializationInput::try_new(
        DeploymentScopeId::from_bytes(context.identities.source_scope()),
        DeploymentId::from_bytes(context.identities.source_plan()),
        allocation,
        context.installed_manifest.clone(),
        context.request_auth,
        context.owner_identity,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Initialization)?;
    match initialize_controller_store_developer_local(
        &context.paths.controller_state_directory,
        initialization,
    ) {
        Ok(receipt) => ControllerStore::open_developer_local(
            &context.paths.controller_state_directory,
            *receipt.store_instance_id(),
            context.owner_identity,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::Initialization),
        Err(_) => ControllerStore::open_developer_local_observed_identity(
            &context.paths.controller_state_directory,
            context.owner_identity,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::Initialization),
    }
}

fn advance_legacy_and_cutover(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    mut legacy: ControllerStore,
) -> Result<ManagedFabricSuccessorStoreV1, DeveloperFixtureAgentStackError> {
    commit_reference_plan(context, &mut legacy)?;
    ensure_tenure(context, runtime, &mut legacy)?;
    let bootstrap = bootstrap_runtime(context, runtime, &mut legacy)?;
    if bootstrap.runtime_store_instance_id() != &context.runtime_store_instance_id {
        return Err(DeveloperFixtureAgentStackError::Bootstrap);
    }
    ManagedFabricSuccessorStoreV1::cutover_from_legacy_developer_local(
        legacy,
        &context.paths.controller_state_directory,
        &context.paths.successor_state_directory,
        context.identities.successor_store_instance_id(),
        context.owner_identity,
        &context.controller_signer,
        &context.fabric_provisioning,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Cutover)
}

fn commit_reference_plan(
    context: &FixtureContext,
    store: &mut ControllerStore,
) -> Result<(), DeveloperFixtureAgentStackError> {
    let lifecycle = ValidatedReferenceLifecycleBudgetsV1::try_new(
        BoundedDuration::from_nanos(FABRIC_LIFECYCLE_NANOS),
        BoundedDuration::from_nanos(FABRIC_LIFECYCLE_NANOS),
        BoundedDuration::from_nanos(FABRIC_LIFECYCLE_NANOS),
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
    let candidate = build_reference_candidate(
        &context.installed_manifest,
        context.identities.deck_key(),
        context.identities.card_use_key(),
        1,
        lifecycle,
    )?;
    let operation = ControllerOperationId::from_bytes(context.identities.legacy_plan_operation_id);
    let state = store
        .snapshot()
        .map_err(|_| DeveloperFixtureAgentStackError::Planning)?
        .state();
    if state.scope() != DeploymentScopeId::from_bytes(context.identities.source_scope())
        || state.plan_lineage() != DeploymentId::from_bytes(context.identities.source_plan())
        || state.request_auth() != context.request_auth
        || state.current_revision() > 1
    {
        return Err(DeveloperFixtureAgentStackError::Planning);
    }
    let prepared = state
        .prepare_plan_candidate(operation, &candidate)
        .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
    prepared
        .commit_plan_candidate(operation, &candidate)
        .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
    if &prepared != state {
        let snapshot = store
            .snapshot()
            .map_err(|_| DeveloperFixtureAgentStackError::Planning)?
            .try_successor(prepared)
            .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
        store
            .commit(snapshot)
            .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
    }
    let state = store
        .snapshot()
        .map_err(|_| DeveloperFixtureAgentStackError::Planning)?
        .state();
    let committed = state
        .commit_plan_candidate(operation, &candidate)
        .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
    if &committed != state {
        let snapshot = store
            .snapshot()
            .map_err(|_| DeveloperFixtureAgentStackError::Planning)?
            .try_successor(committed)
            .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
        store
            .commit(snapshot)
            .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
    }
    if store
        .snapshot()
        .map_err(|_| DeveloperFixtureAgentStackError::Planning)?
        .state()
        .current_revision()
        != 1
    {
        return Err(DeveloperFixtureAgentStackError::Planning);
    }
    Ok(())
}

fn build_reference_candidate(
    installed_manifest: &ControllerInstalledManifestPin,
    deck_key: [u8; 16],
    card_use_key: [u8; 16],
    definition_version: u32,
    lifecycle: ValidatedReferenceLifecycleBudgetsV1,
) -> Result<DeploymentPlanCandidate, DeveloperFixtureAgentStackError> {
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
            .with_requested_version(CardDefinitionVersionRequirement::exact(definition_version)),
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
        .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
    let empty_allocation =
        StableAllocationSnapshot::try_new(installed_manifest.target(), 0, 0, Vec::new())
            .map_err(|_| DeveloperFixtureAgentStackError::Planning)?;
    match DeploymentPlanner::plan(&PlannerInput {
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
    .map_err(|_| DeveloperFixtureAgentStackError::Planning)?
    {
        PlannerOutcome::Candidate(candidate) => Ok(*candidate),
        PlannerOutcome::Omitted => Err(DeveloperFixtureAgentStackError::Planning),
    }
}

fn ensure_tenure(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    store: &mut ControllerStore,
) -> Result<(), DeveloperFixtureAgentStackError> {
    let writer = PlanWriterRef::from_bytes(context.identities.writer());
    if store
        .snapshot()
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?
        .state()
        .latest_committed_tenure_proof(writer)
        .is_some()
    {
        return Ok(());
    }
    let proof_authority = TenureProofAuthority::try_new(
        TenureAuthorityRef::from_bytes(context.identities.authority_ref()),
        TenureKeyRef::from_bytes(context.identities.authority_key_ref()),
        TenureProofAlgorithm::try_new(ACQUIRE_TENURE_ED25519_ALGORITHM)
            .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?,
        ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    let endpoint = UnixAuthorityEndpoint::try_new(
        context.paths.authority_socket_path.clone(),
        AuthoritySocketAcl::new(context.peer.uid(), context.peer.gid()),
        UnixCredentials::new(context.peer.uid(), context.peer.gid()),
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    let proof_verifier = AuthorityProofVerifier::try_new(
        proof_authority,
        VerifyingKey::from_bytes(&context.authority.authority_verification_key())
            .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    let client = UnixTenureAuthorityClient::try_new(endpoint, proof_verifier, EXCHANGE_TIMEOUT)
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    let prepared = prepare_tenure_request(context, store, &client)?;
    runtime
        .block_on(acquire_tenure_once(store, &client, &prepared))
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    Ok(())
}

fn prepare_tenure_request(
    context: &FixtureContext,
    store: &ControllerStore,
    client: &UnixTenureAuthorityClient,
) -> Result<PreparedAcquireTenureRequest, DeveloperFixtureAgentStackError> {
    let state = store
        .snapshot()
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?
        .state();
    let unresolved = state
        .current_unresolved_tenure_transaction()
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    let prepared = if let Some(transaction) = unresolved {
        if transaction.authority_domain_fingerprint()
            != ControllerTenureAuthorityDomainFingerprint::from_stored(
                client.authority_domain_fingerprint(),
            )
        {
            return Err(DeveloperFixtureAgentStackError::Tenure);
        }
        PreparedAcquireTenureRequest::try_from_canonical_request_bytes(
            transaction.request().canonical_bytes(),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?
    } else {
        let entropy = read_entropy::<48>()?;
        let mut operation_id = [0_u8; 16];
        operation_id.copy_from_slice(&entropy[..16]);
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                DeploymentScopeId::from_bytes(context.identities.source_scope()),
                DeploymentWriterRef::from_bytes(context.identities.writer()),
                AcquireTenureOperationId::from_bytes(operation_id),
            ),
            PrincipalRef::from_bytes(context.identities.controller_principal()),
            ControllerAcquireKeyRef::from_bytes(context.identities.controller_key_ref()),
            ControllerPublicKeyFingerprint::for_ed25519_key(
                context.controller_signer.verifying_key().as_bytes(),
            )
            .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?,
            &entropy[16..],
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?,
        )
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
        let request = AcquireTenureRequestToSign::try_new(draft)
            .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
        let signature = context.controller_signer.sign(request.signing_bytes());
        request
            .finalize_ed25519(&signature.to_bytes())
            .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?
    };
    validate_tenure_request(context, &prepared)?;
    Ok(prepared)
}

fn validate_tenure_request(
    context: &FixtureContext,
    prepared: &PreparedAcquireTenureRequest,
) -> Result<(), DeveloperFixtureAgentStackError> {
    let request = prepared.request();
    let expected_fingerprint = ControllerPublicKeyFingerprint::for_ed25519_key(
        context.controller_signer.verifying_key().as_bytes(),
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    if request.scope() != DeploymentScopeId::from_bytes(context.identities.source_scope())
        || request.writer() != DeploymentWriterRef::from_bytes(context.identities.writer())
        || request.controller_principal()
            != PrincipalRef::from_bytes(context.identities.controller_principal())
        || request.controller_key()
            != ControllerAcquireKeyRef::from_bytes(context.identities.controller_key_ref())
        || request.controller_public_key_fingerprint() != expected_fingerprint
        || request.auth_algorithm() != ACQUIRE_TENURE_ED25519_ALGORITHM
        || request.auth_algorithm_version() != ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION
        || request.max_response_payload_bytes()
            != u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?
    {
        return Err(DeveloperFixtureAgentStackError::Tenure);
    }
    let signature: [u8; 64] = request
        .auth_signature()
        .try_into()
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?;
    context
        .controller_signer
        .verifying_key()
        .verify_strict(
            request
                .signing_transcript()
                .map_err(|_| DeveloperFixtureAgentStackError::Tenure)?
                .as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::Tenure)
}

fn bootstrap_runtime(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    store: &mut ControllerStore,
) -> Result<ControllerBootstrapReceiptV1, DeveloperFixtureAgentStackError> {
    let admission_policy =
        reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
            target: context.installed_manifest.target(),
            source_scope: SourceScopeRef::from_bytes(context.identities.source_scope()),
            writer: PlanWriterRef::from_bytes(context.identities.writer()),
            controller_principal: PrincipalRef::from_bytes(
                context.identities.controller_principal(),
            ),
            controller_key_ref: context.request_auth.key(),
            controller_public_key: context.controller_signer.verifying_key().as_bytes(),
            authority_principal: PrincipalRef::from_bytes(context.identities.authority_principal()),
            authority_uid: context.peer.uid(),
            authority_gid: context.peer.gid(),
            tenure_authority_ref: TenureAuthorityRef::from_bytes(
                context.identities.authority_ref(),
            ),
            tenure_key_ref: TenureKeyRef::from_bytes(context.identities.authority_key_ref()),
            tenure_public_key: &context.authority.authority_verification_key(),
        })
        .map_err(|_| DeveloperFixtureAgentStackError::Bootstrap)?;
    let provisioning = ControllerBootstrapProvisioningV1::try_new_developer_local(
        context.paths.runtime_socket_path.clone(),
        PrincipalRef::from_bytes(context.identities.controller_principal()),
        PrincipalRef::from_bytes(context.identities.runtime_principal()),
        ApplyAuthKeyRef::from_bytes(context.identities.runtime_response_key_ref()),
        context.runtime_response_verification_key.to_bytes(),
        context.peer.uid(),
        context.peer.gid(),
        context.peer.uid(),
        context.peer.gid(),
        admission_policy,
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Bootstrap)?;
    let entropy = read_entropy::<48>()?;
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&entropy[..16]);
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&entropy[16..]);
    let fresh = FreshControllerBootstrapRequestV1::try_new(request_id, nonce)
        .map_err(|_| DeveloperFixtureAgentStackError::Bootstrap)?;
    runtime
        .block_on(bootstrap_runtime_v1(
            store,
            context.owner_identity,
            &context.controller_signer,
            provisioning,
            fresh,
        ))
        .map_err(|_| DeveloperFixtureAgentStackError::Bootstrap)
}

fn runtime_endpoint(
    context: &FixtureContext,
) -> Result<UnixRuntimeControlEndpoint, DeveloperFixtureAgentStackError> {
    UnixRuntimeControlEndpoint::try_new(
        context.paths.runtime_socket_path.clone(),
        RuntimeControlSocketAcl::new(context.peer.uid(), context.peer.gid()),
        RuntimeUnixCredentials::new(context.peer.uid(), context.peer.gid()),
        RuntimeHostId::from_bytes(context.identities.runtime_target()),
        PrincipalRef::from_bytes(context.identities.runtime_principal()),
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)
}

fn runtime_response_key_fingerprint(
    context: &FixtureContext,
) -> Result<Digest32, DeveloperFixtureAgentStackError> {
    ed25519_control_key_fingerprint(context.runtime_response_verification_key.as_bytes())
        .map_err(|_| DeveloperFixtureAgentStackError::Runtime)
}

fn advance_serving_pin(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    store: &mut ManagedFabricSuccessorStoreV1,
) -> Result<VerifiedManagedServingPinV1, DeveloperFixtureAgentStackError> {
    let mut journal = ManagedFabricApplyJournalV1::new(store.state().clone());
    if journal.state().serving_phase() == ManagedServingBootstrapPhaseV1::AttemptInFlight {
        journal
            .close_recovered_serving_bootstrap_with(|next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            })
            .map_err(|_| DeveloperFixtureAgentStackError::ServingObservation)?;
    }
    if journal.state().serving_phase() == ManagedServingBootstrapPhaseV1::ResponseDurable {
        return journal
            .current_serving_pin(&context.controller_signer, &context.fabric_provisioning)
            .map_err(|_| DeveloperFixtureAgentStackError::ServingObservation);
    }
    let prepared =
        if journal.state().serving_phase() == ManagedServingBootstrapPhaseV1::RequestDurable {
            journal
                .prepared_serving_bootstrap()
                .map_err(|_| DeveloperFixtureAgentStackError::ServingObservation)?
        } else {
            let entropy = read_entropy::<48>()?;
            let mut request_id = [0_u8; 16];
            request_id.copy_from_slice(&entropy[..16]);
            let mut nonce = [0_u8; 32];
            nonce.copy_from_slice(&entropy[16..]);
            let fresh = FreshManagedServingBootstrapV1::try_new(request_id, nonce)
                .map_err(|_| DeveloperFixtureAgentStackError::ServingObservation)?;
            journal
                .prepare_serving_bootstrap_with(
                    &context.controller_signer,
                    &context.fabric_provisioning,
                    fresh,
                    |next| {
                        store
                            .commit_state(next)
                            .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                    },
                )
                .map_err(|_| DeveloperFixtureAgentStackError::ServingObservation)?
        };
    let action = journal
        .claim_serving_bootstrap_with(prepared, |next| {
            store
                .commit_state(next)
                .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
        })
        .map_err(|_| DeveloperFixtureAgentStackError::ServingObservation)?;
    let verifier = RuntimeManagedServingResponseVerifier::try_new(
        PrincipalRef::from_bytes(context.identities.runtime_principal()),
        ApplyAuthKeyRef::from_bytes(context.identities.runtime_response_key_ref()),
        context.request_auth.algorithm(),
        context.request_auth.algorithm_version(),
        runtime_response_key_fingerprint(context)?,
        context.runtime_response_verification_key,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let client = UnixRuntimeManagedServingClient::try_new(
        runtime_endpoint(context)?,
        verifier,
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let (action, response) = runtime.block_on(client.exchange(action)).into_parts();
    match response {
        Ok(wire) => journal
            .consume_serving_bootstrap_response_with(
                action,
                &wire,
                &context.controller_signer,
                &context.fabric_provisioning,
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .map_err(|_| DeveloperFixtureAgentStackError::ServingObservation),
        Err(_) => {
            journal
                .close_serving_bootstrap_no_response_with(action, |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                })
                .map_err(|_| DeveloperFixtureAgentStackError::ServingObservation)?;
            Err(DeveloperFixtureAgentStackError::ServingObservation)
        }
    }
}

fn advance_fabric_active(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    store: &mut ManagedFabricSuccessorStoreV1,
) -> Result<ManagedFabricTerminalCommitV1, DeveloperFixtureAgentStackError> {
    let mut journal = ManagedFabricApplyJournalV1::new(store.state().clone());
    if let Some(terminal) = journal
        .terminal(&context.controller_signer, &context.fabric_provisioning)
        .map_err(|_| DeveloperFixtureAgentStackError::FabricApply)?
    {
        if terminal.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady {
            return Err(DeveloperFixtureAgentStackError::FabricApply);
        }
        return Ok(terminal);
    }
    let budgets = managed_lifecycle_budgets()?;
    let service = ManagedServiceSpecV1::new(
        ManagedServiceId::from_bytes(context.identities.fabric_service_id()),
        budgets,
    );
    let fresh = fresh_managed_fabric_apply()?;
    let prepared = journal
        .prepare_activate_with(
            &context.controller_signer,
            &context.fabric_provisioning,
            service,
            context.fabric_endpoint.clone(),
            fresh,
            |next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureAgentStackError::FabricApply)?;
    let action = journal
        .claim_send_with(
            prepared,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureAgentStackError::FabricApply)?;
    let verifier = RuntimeManagedFabricResponseVerifier::try_new(
        PrincipalRef::from_bytes(context.identities.runtime_principal()),
        ApplyAuthKeyRef::from_bytes(context.identities.runtime_response_key_ref()),
        context.request_auth.algorithm(),
        context.request_auth.algorithm_version(),
        runtime_response_key_fingerprint(context)?,
        context.runtime_response_verification_key,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let client = UnixRuntimeManagedFabricClient::try_new(
        runtime_endpoint(context)?,
        verifier,
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let (action, response) = runtime.block_on(client.exchange(action)).into_parts();
    let wire = response.map_err(|_| DeveloperFixtureAgentStackError::FabricApply)?;
    let terminal = journal
        .consume_pxft_with(
            action,
            &wire,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureAgentStackError::FabricApply)?;
    if terminal.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady {
        return Err(DeveloperFixtureAgentStackError::FabricApply);
    }
    Ok(terminal)
}

fn ensure_a2_successor_root(
    state: &ManagedFabricControllerStateV1,
) -> Result<(), DeveloperFixtureModelAgentStackError> {
    if state.agent_stack_state().is_some()
        || state
            .legacy_snapshot()
            .distributed_agent_stack_journal_wire()
            .is_some()
        || state
            .legacy_snapshot()
            .distributed_agent_stack_node_discovery_wire()
            .is_some()
    {
        return Err(DeveloperFixtureModelAgentStackError::ModelAgentApply);
    }
    Ok(())
}

fn validate_stored_model_agent_plan(
    context: &FixtureContext,
    state: &ManagedFabricControllerStateV1,
    model: ManagedModelServicePlanV1,
) -> Result<(), DeveloperFixtureModelAgentStackError> {
    let Some(stack) = state.model_agent_stack_state() else {
        return Ok(());
    };
    let active_desired = stack
        .archived_active()
        .map_or(stack.desired(), |archived| archived.desired());
    if active_desired.execution().mode() != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
        || active_desired.execution().model() != Some(&model)
        || active_desired.execution().managed_agent_stack().agent()
            != Some(&developer_agent_plan(context)?)
    {
        return Err(DeveloperFixtureModelAgentStackError::ModelAgentApply);
    }
    Ok(())
}

fn advance_model_agent_active(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    successor: &mut ManagedFabricSuccessorStoreV1,
    model: ManagedModelServicePlanV1,
) -> Result<ManagedModelAgentStackTerminalCommitV1, DeveloperFixtureModelAgentStackError> {
    ensure_a2_successor_root(successor.state())?;
    validate_stored_model_agent_plan(context, successor.state(), model)?;
    let mut journal = ManagedModelAgentStackApplyJournalV1::new(successor.state().clone());
    if let Some(terminal) = journal
        .terminal(&context.controller_signer, &context.fabric_provisioning)
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?
    {
        let facts = terminal.receipt().facts();
        if facts.request_mode() != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
            || facts.state().outcome() != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
        {
            return Err(DeveloperFixtureModelAgentStackError::ModelAgentApply);
        }
        return Ok(terminal);
    }
    let expected_fabric = successor
        .state()
        .desired()
        .ok_or(DeveloperFixtureModelAgentStackError::ModelAgentApply)?
        .execution()
        .clone();
    let activation = ManagedModelAgentStackActivationV1::try_new(
        expected_fabric,
        developer_agent_plan(context)?,
        model,
    )
    .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let prepared = journal
        .prepare_activate_with(
            &context.controller_signer,
            &context.fabric_provisioning,
            &activation,
            fresh_managed_model_agent_stack_apply()?,
            |next| {
                successor
                    .commit_state(next)
                    .map_err(|_| ManagedModelAgentStackApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let action = journal
        .claim_send_with(
            prepared,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| {
                successor
                    .commit_state(next)
                    .map_err(|_| ManagedModelAgentStackApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let verifier = RuntimeManagedModelAgentStackResponseVerifier::try_new(
        PrincipalRef::from_bytes(context.identities.runtime_principal()),
        ApplyAuthKeyRef::from_bytes(context.identities.runtime_response_key_ref()),
        context.request_auth.algorithm(),
        context.request_auth.algorithm_version(),
        runtime_response_key_fingerprint(context)?,
        context.runtime_response_verification_key,
    )
    .map_err(|_| {
        DeveloperFixtureModelAgentStackError::Base(DeveloperFixtureAgentStackError::Runtime)
    })?;
    let client = UnixRuntimeManagedModelAgentStackClient::try_new(
        runtime_endpoint(context)?,
        verifier,
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| {
        DeveloperFixtureModelAgentStackError::Base(DeveloperFixtureAgentStackError::Runtime)
    })?;
    let (action, response) = runtime.block_on(client.exchange(action)).into_parts();
    let wire = response.map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let terminal = journal
        .consume_pxmt_with(
            action,
            &wire,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| {
                successor
                    .commit_state(next)
                    .map_err(|_| ManagedModelAgentStackApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let facts = terminal.receipt().facts();
    if facts.request_mode() != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
        || facts.state().outcome() != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
    {
        return Err(DeveloperFixtureModelAgentStackError::ModelAgentApply);
    }
    Ok(terminal)
}

fn advance_model_agent_exact_zero(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    successor: &mut ManagedFabricSuccessorStoreV1,
    model: ManagedModelServicePlanV1,
) -> Result<
    DeveloperFixtureModelAgentStackDeactivationOutcomeV1,
    DeveloperFixtureModelAgentStackError,
> {
    ensure_a2_successor_root(successor.state())?;
    validate_stored_model_agent_plan(context, successor.state(), model)?;
    let mut journal = ManagedModelAgentStackApplyJournalV1::new(successor.state().clone());
    if let Some(terminal) = journal
        .terminal(&context.controller_signer, &context.fabric_provisioning)
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?
    {
        let facts = terminal.receipt().facts();
        if facts.request_mode() == ManagedModelAgentStackTargetModeV1::EmptyDeactivate
            && facts.state().outcome() == ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero
        {
            return Ok(model_agent_deactivation_outcome(terminal));
        }
        if facts.request_mode() != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
            || facts.state().outcome() != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
        {
            return Err(DeveloperFixtureModelAgentStackError::ModelAgentApply);
        }
    }
    let prepared = journal
        .prepare_empty_deactivate_with(
            &context.controller_signer,
            &context.fabric_provisioning,
            fresh_managed_model_agent_stack_apply()?,
            |next| {
                successor
                    .commit_state(next)
                    .map_err(|_| ManagedModelAgentStackApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let action = journal
        .claim_send_with(
            prepared,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| {
                successor
                    .commit_state(next)
                    .map_err(|_| ManagedModelAgentStackApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let verifier = RuntimeManagedModelAgentStackResponseVerifier::try_new(
        PrincipalRef::from_bytes(context.identities.runtime_principal()),
        ApplyAuthKeyRef::from_bytes(context.identities.runtime_response_key_ref()),
        context.request_auth.algorithm(),
        context.request_auth.algorithm_version(),
        runtime_response_key_fingerprint(context)?,
        context.runtime_response_verification_key,
    )
    .map_err(|_| {
        DeveloperFixtureModelAgentStackError::Base(DeveloperFixtureAgentStackError::Runtime)
    })?;
    let client = UnixRuntimeManagedModelAgentStackClient::try_new(
        runtime_endpoint(context)?,
        verifier,
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| {
        DeveloperFixtureModelAgentStackError::Base(DeveloperFixtureAgentStackError::Runtime)
    })?;
    let (action, response) = runtime.block_on(client.exchange(action)).into_parts();
    let wire = response.map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let terminal = journal
        .consume_pxmt_with(
            action,
            &wire,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| {
                successor
                    .commit_state(next)
                    .map_err(|_| ManagedModelAgentStackApplyControllerError::DurabilityRejected)
            },
        )
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)?;
    let facts = terminal.receipt().facts();
    if facts.request_mode() != ManagedModelAgentStackTargetModeV1::EmptyDeactivate
        || facts.state().outcome() != ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero
    {
        return Err(DeveloperFixtureModelAgentStackError::ModelAgentApply);
    }
    Ok(model_agent_deactivation_outcome(terminal))
}

fn model_agent_deactivation_outcome(
    terminal: ManagedModelAgentStackTerminalCommitV1,
) -> DeveloperFixtureModelAgentStackDeactivationOutcomeV1 {
    DeveloperFixtureModelAgentStackDeactivationOutcomeV1 {
        model_agent_request_digest: terminal.receipt().facts().request_digest(),
        model_agent_receipt_digest: terminal.receipt().receipt_digest(),
        model_agent_terminal_receipt: terminal.receipt().canonical_wire().into(),
        replayed: terminal.replayed_from_journal(),
    }
}

fn advance_agent_active(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    successor: &mut ManagedFabricSuccessorStoreV1,
) -> Result<ManagedAgentStackTerminalCommitV1, DeveloperFixtureAgentStackError> {
    let mut store = ManagedAgentStackDurableStoreV1::try_new(successor)
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let mut journal = ManagedAgentStackApplyJournalV1::new(store.state().clone());
    if let Some(terminal) = journal
        .terminal(&context.controller_signer, &context.fabric_provisioning)
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?
    {
        let facts = terminal.receipt().facts();
        if facts.request_mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
            || facts.state().outcome() != ManagedAgentStackTerminalOutcomeV1::ActiveReady
        {
            return Err(DeveloperFixtureAgentStackError::AgentApply);
        }
        return Ok(terminal);
    }
    let expected_fabric = store
        .state()
        .desired()
        .ok_or(DeveloperFixtureAgentStackError::AgentApply)?
        .execution()
        .clone();
    let activation =
        ManagedAgentStackActivationV1::try_new(expected_fabric, developer_agent_plan(context)?)
            .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let prepared = journal
        .prepare_activate_with(
            &context.controller_signer,
            &context.fabric_provisioning,
            &activation,
            fresh_managed_agent_stack_apply()?,
            |next| store.commit(next),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let action = journal
        .claim_send_with(
            prepared,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| store.commit(next),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let verifier = RuntimeManagedAgentStackResponseVerifier::try_new(
        PrincipalRef::from_bytes(context.identities.runtime_principal()),
        ApplyAuthKeyRef::from_bytes(context.identities.runtime_response_key_ref()),
        context.request_auth.algorithm(),
        context.request_auth.algorithm_version(),
        runtime_response_key_fingerprint(context)?,
        context.runtime_response_verification_key,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let client = UnixRuntimeManagedAgentStackClient::try_new(
        runtime_endpoint(context)?,
        verifier,
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let (action, response) = runtime.block_on(client.exchange(action)).into_parts();
    let wire = response.map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let terminal = journal
        .consume_pxst_with(
            action,
            &wire,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| store.commit(next),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let facts = terminal.receipt().facts();
    if facts.request_mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
        || facts.state().outcome() != ManagedAgentStackTerminalOutcomeV1::ActiveReady
    {
        return Err(DeveloperFixtureAgentStackError::AgentApply);
    }
    Ok(terminal)
}

fn advance_agent_exact_zero(
    context: &FixtureContext,
    runtime: &tokio::runtime::Runtime,
    successor: &mut ManagedFabricSuccessorStoreV1,
) -> Result<DeveloperFixtureAgentStackDeactivationOutcomeV1, DeveloperFixtureAgentStackError> {
    let mut store = ManagedAgentStackDurableStoreV1::try_new(successor)
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let mut journal = ManagedAgentStackApplyJournalV1::new(store.state().clone());
    if let Some(terminal) = journal
        .terminal(&context.controller_signer, &context.fabric_provisioning)
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?
    {
        let facts = terminal.receipt().facts();
        if facts.request_mode() == ManagedAgentStackTargetModeV1::EmptyDeactivate
            && facts.state().outcome() == ManagedAgentStackTerminalOutcomeV1::EmptyExactZero
        {
            return Ok(deactivation_outcome(terminal));
        }
        if facts.request_mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
            || facts.state().outcome() != ManagedAgentStackTerminalOutcomeV1::ActiveReady
        {
            return Err(DeveloperFixtureAgentStackError::AgentApply);
        }
    }
    let prepared = journal
        .prepare_empty_deactivate_with(
            &context.controller_signer,
            &context.fabric_provisioning,
            fresh_managed_agent_stack_apply()?,
            |next| store.commit(next),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let action = journal
        .claim_send_with(
            prepared,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| store.commit(next),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let verifier = RuntimeManagedAgentStackResponseVerifier::try_new(
        PrincipalRef::from_bytes(context.identities.runtime_principal()),
        ApplyAuthKeyRef::from_bytes(context.identities.runtime_response_key_ref()),
        context.request_auth.algorithm(),
        context.request_auth.algorithm_version(),
        runtime_response_key_fingerprint(context)?,
        context.runtime_response_verification_key,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let client = UnixRuntimeManagedAgentStackClient::try_new(
        runtime_endpoint(context)?,
        verifier,
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Runtime)?;
    let (action, response) = runtime.block_on(client.exchange(action)).into_parts();
    let wire = response.map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let terminal = journal
        .consume_pxst_with(
            action,
            &wire,
            &context.controller_signer,
            &context.fabric_provisioning,
            |next| store.commit(next),
        )
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let facts = terminal.receipt().facts();
    if facts.request_mode() != ManagedAgentStackTargetModeV1::EmptyDeactivate
        || facts.state().outcome() != ManagedAgentStackTerminalOutcomeV1::EmptyExactZero
    {
        return Err(DeveloperFixtureAgentStackError::AgentApply);
    }
    Ok(deactivation_outcome(terminal))
}

fn deactivation_outcome(
    terminal: ManagedAgentStackTerminalCommitV1,
) -> DeveloperFixtureAgentStackDeactivationOutcomeV1 {
    DeveloperFixtureAgentStackDeactivationOutcomeV1 {
        agent_request_digest: terminal.receipt().facts().request_digest(),
        agent_receipt_digest: terminal.receipt().receipt_digest(),
        agent_terminal_receipt: terminal.receipt().canonical_wire().into(),
        replayed: terminal.replayed_from_journal(),
    }
}

fn managed_lifecycle_budgets()
-> Result<ManagedServiceLifecycleBudgetsV1, DeveloperFixtureAgentStackError> {
    ManagedServiceLifecycleBudgetsV1::try_new(
        BoundedDuration::from_nanos(AGENT_LIFECYCLE_NANOS),
        BoundedDuration::from_nanos(AGENT_LIFECYCLE_NANOS),
        BoundedDuration::from_nanos(AGENT_LIFECYCLE_NANOS),
        BoundedDuration::from_nanos(AGENT_LIFECYCLE_NANOS),
        BoundedDuration::from_nanos(AGENT_LIFECYCLE_NANOS),
    )
    .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)
}

fn developer_agent_plan(
    context: &FixtureContext,
) -> Result<ManagedAgentServicePlanV1, DeveloperFixtureAgentStackError> {
    let ingress =
        ManagedAgentIngressLimitsV1::try_new(8, 512 * 1024, 64 * 1024, 64 * 1024, 2_000_000_000)
            .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    let port = ManagedAgentPortPlanV1::try_new(
        BindingId::from_bytes(context.identities.submit_binding_id()),
        BindingId::from_bytes(context.identities.control_binding_id()),
        "paraegox/local/agent/v1/submit",
        "paraegox/local/agent/v1/control",
        ingress,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?;
    ManagedAgentServicePlanV1::try_new(
        ManagedServiceSpecV1::new(
            ManagedServiceId::from_bytes(context.identities.agent_service_id()),
            managed_lifecycle_budgets()?,
        ),
        ManagedAgentSemanticLimitsV1::try_new(8, 16, 16, 32)
            .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?,
        port,
        context.provider,
    )
    .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)
}

fn deterministic_provider(
    identities: DeveloperFixtureDerivedIdentityV1,
) -> Result<ManagedAgentProviderSelectionV1, DeveloperFixtureAgentStackError> {
    ManagedAgentProviderSelectionV1::try_deterministic_fixture(
        ManagedAgentProviderRefV1::try_from_bytes(identities.provider_ref())
            .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)?,
        Digest32::from_bytes(identities.provider_configuration_digest()),
    )
    .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)
}

fn fresh_managed_fabric_apply() -> Result<FreshManagedFabricApplyV1, DeveloperFixtureAgentStackError>
{
    let entropy = read_entropy::<64>()?;
    let mut operation_id = [0_u8; 16];
    operation_id.copy_from_slice(&entropy[..16]);
    let mut temporal_id = [0_u8; 16];
    temporal_id.copy_from_slice(&entropy[16..32]);
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&entropy[32..]);
    FreshManagedFabricApplyV1::try_new(operation_id, temporal_id, nonce)
        .map_err(|_| DeveloperFixtureAgentStackError::FabricApply)
}

fn fresh_managed_agent_stack_apply()
-> Result<FreshManagedAgentStackApplyV1, DeveloperFixtureAgentStackError> {
    let entropy = read_entropy::<64>()?;
    let mut operation_id = [0_u8; 16];
    operation_id.copy_from_slice(&entropy[..16]);
    let mut temporal_id = [0_u8; 16];
    temporal_id.copy_from_slice(&entropy[16..32]);
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&entropy[32..]);
    FreshManagedAgentStackApplyV1::try_new(operation_id, temporal_id, nonce)
        .map_err(|_| DeveloperFixtureAgentStackError::AgentApply)
}

fn fresh_managed_model_agent_stack_apply()
-> Result<FreshManagedModelAgentStackApplyV1, DeveloperFixtureModelAgentStackError> {
    let entropy = read_entropy::<64>()?;
    let mut operation_id = [0_u8; 16];
    operation_id.copy_from_slice(&entropy[..16]);
    let mut temporal_id = [0_u8; 16];
    temporal_id.copy_from_slice(&entropy[16..32]);
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&entropy[32..]);
    FreshManagedModelAgentStackApplyV1::try_new(operation_id, temporal_id, nonce)
        .map_err(|_| DeveloperFixtureModelAgentStackError::ModelAgentApply)
}

fn read_entropy<const N: usize>() -> Result<[u8; N], DeveloperFixtureAgentStackError> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| DeveloperFixtureAgentStackError::Filesystem)?;
    let mut source = File::from(owned);
    let mut entropy = [0_u8; N];
    source
        .read_exact(&mut entropy)
        .map_err(|_| DeveloperFixtureAgentStackError::Filesystem)?;
    if bytes_are_zero(&entropy) {
        return Err(DeveloperFixtureAgentStackError::Filesystem);
    }
    Ok(entropy)
}

fn validate_private_directory(
    path: &Path,
    peer: DeveloperLocalPeerIdentityV1,
) -> Result<(), DeveloperFixtureAgentStackError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| DeveloperFixtureAgentStackError::Filesystem)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != peer.uid()
        || metadata.gid() != peer.gid()
        || metadata.permissions().mode() & 0o7777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(DeveloperFixtureAgentStackError::Filesystem);
    }
    Ok(())
}

fn validate_seed(
    seed: DeveloperFixtureIdentitySeedV1,
) -> Result<(), DeveloperFixtureAgentStackError> {
    let identities = [
        seed.manifest_instance_id,
        seed.controller_instance_id,
        seed.authority_instance_id,
        seed.runtime_instance_id,
        seed.source_scope_id,
        seed.source_plan_id,
        seed.fabric_service_id,
        seed.agent_service_id,
        seed.submit_binding_id,
        seed.control_binding_id,
        seed.provider_ref,
        seed.deck_run_id,
        seed.session_id,
    ];
    if bytes_are_zero(&seed.provider_configuration_digest)
        || identities.iter().any(|identity| bytes_are_zero(identity))
        || identities
            .iter()
            .enumerate()
            .any(|(index, identity)| identities[index + 1..].contains(identity))
    {
        return Err(DeveloperFixtureAgentStackError::InvalidInput);
    }
    Ok(())
}

fn validate_derived(
    identities: &DeveloperFixtureDerivedIdentityV1,
) -> Result<(), DeveloperFixtureAgentStackError> {
    let values = [
        identities.installation_id(),
        identities.source_scope(),
        identities.source_plan(),
        identities.writer(),
        identities.controller_principal(),
        identities.controller_key_ref(),
        identities.authority_principal(),
        identities.authority_ref(),
        identities.authority_key_ref(),
        identities.authority_service_principal(),
        identities.authority_owner(),
        identities.runtime_target(),
        identities.runtime_principal(),
        identities.runtime_response_key_ref(),
        identities.fabric_service_id(),
        identities.agent_service_id(),
        identities.model_service_id(),
        identities.submit_binding_id(),
        identities.control_binding_id(),
        identities.provider_ref(),
        identities.deck_key(),
        identities.card_use_key(),
        identities.legacy_plan_operation_id,
    ];
    if values.iter().any(|value| bytes_are_zero(value))
        || values
            .iter()
            .enumerate()
            .any(|(index, value)| values[index + 1..].contains(value))
        || bytes_are_zero(&identities.successor_store_instance_id)
    {
        return Err(DeveloperFixtureAgentStackError::InvalidInput);
    }
    Ok(())
}

fn derive16(label: &[u8], source: &[u8; 16]) -> Result<[u8; 16], DeveloperFixtureAgentStackError> {
    derive16_with_domain(DERIVED_IDENTITY_DOMAIN, &[label, source])
}

fn derive16_with_domain(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 16], DeveloperFixtureAgentStackError> {
    let digest = derive32(domain, fields)?;
    let mut result = [0_u8; 16];
    result.copy_from_slice(&digest[..16]);
    if bytes_are_zero(&result) {
        return Err(DeveloperFixtureAgentStackError::InvalidInput);
    }
    Ok(result)
}

fn derive32(domain: &[u8], fields: &[&[u8]]) -> Result<[u8; 32], DeveloperFixtureAgentStackError> {
    let mut digest = Digest32Builder::try_new(domain)
        .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
    for field in fields {
        digest
            .field_bytes(field)
            .map_err(|_| DeveloperFixtureAgentStackError::InvalidInput)?;
    }
    let value = *digest.finish().as_bytes();
    if bytes_are_zero(&value) {
        return Err(DeveloperFixtureAgentStackError::InvalidInput);
    }
    Ok(value)
}

fn validate_absolute_path(path: &Path) -> Result<(), DeveloperFixtureAgentStackError> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(DeveloperFixtureAgentStackError::InvalidInput);
    }
    Ok(())
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_seed() -> DeveloperFixtureIdentitySeedV1 {
        DeveloperFixtureIdentitySeedV1 {
            manifest_instance_id: [0x01; 16],
            controller_instance_id: [0x02; 16],
            authority_instance_id: [0x03; 16],
            runtime_instance_id: [0x04; 16],
            source_scope_id: [0x05; 16],
            source_plan_id: [0x06; 16],
            fabric_service_id: [0x07; 16],
            agent_service_id: [0x08; 16],
            submit_binding_id: [0x09; 16],
            control_binding_id: [0x0a; 16],
            provider_ref: [0x0b; 16],
            deck_run_id: [0x0c; 16],
            session_id: [0x0d; 16],
            provider_configuration_digest: [0x0e; 32],
        }
    }

    #[test]
    fn derived_identity_is_deterministic_distinct_and_runtime_complete() {
        let first = DeveloperFixtureDerivedIdentityV1::try_from_seed(identity_seed())
            .expect("valid fixture identity");
        let second = DeveloperFixtureDerivedIdentityV1::try_from_seed(identity_seed())
            .expect("same fixture identity");
        assert_eq!(first, second);
        assert_eq!(first.installation_id(), [0x01; 16]);
        assert_eq!(first.runtime_target(), [0x04; 16]);
        assert_ne!(first.runtime_target(), first.runtime_principal());
        assert_ne!(first.controller_key_ref(), first.runtime_response_key_ref());
        assert_ne!(first.authority_ref(), first.authority_key_ref());
        assert!(!bytes_are_zero(&first.model_service_id()));
        assert_ne!(first.model_service_id(), first.fabric_service_id());
        assert_ne!(first.model_service_id(), first.agent_service_id());
        assert!(!bytes_are_zero(&first.successor_store_instance_id()));
    }

    #[test]
    fn identity_seed_rejects_zero_and_role_aliasing() {
        let mut zero = identity_seed();
        zero.source_scope_id = [0; 16];
        assert_eq!(
            DeveloperFixtureDerivedIdentityV1::try_from_seed(zero),
            Err(DeveloperFixtureAgentStackError::InvalidInput)
        );

        let mut aliased = identity_seed();
        aliased.control_binding_id = aliased.submit_binding_id;
        assert_eq!(
            DeveloperFixtureDerivedIdentityV1::try_from_seed(aliased),
            Err(DeveloperFixtureAgentStackError::InvalidInput)
        );
    }

    #[test]
    fn provisioned_facade_requires_exact_provider_identity() {
        let identities = DeveloperFixtureDerivedIdentityV1::try_from_seed(identity_seed())
            .expect("valid fixture identity");
        let provider_ref = ManagedAgentProviderRefV1::try_from_bytes(identities.provider_ref())
            .expect("test provider reference");
        let config_digest = Digest32::from_bytes(identities.provider_configuration_digest());
        let secret_ref =
            paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentSecretRefV1::try_from_bytes(
                [0x51; 16],
            )
            .expect("test Secret reference");
        let exact = ManagedAgentProviderSelectionV1::try_provisioned(
            provider_ref,
            config_digest,
            secret_ref,
        )
        .expect("exact Provisioned provider");
        assert_eq!(
            validate_provisioned_provider_selection(identities, exact),
            Ok(())
        );

        let deterministic =
            ManagedAgentProviderSelectionV1::try_deterministic_fixture(provider_ref, config_digest)
                .expect("deterministic selection");
        assert_eq!(
            validate_provisioned_provider_selection(identities, deterministic),
            Err(DeveloperFixtureAgentStackError::InvalidInput)
        );

        let wrong_provider = ManagedAgentProviderSelectionV1::try_provisioned(
            ManagedAgentProviderRefV1::try_from_bytes([0x61; 16])
                .expect("different provider reference"),
            config_digest,
            secret_ref,
        )
        .expect("different Provisioned provider");
        assert_eq!(
            validate_provisioned_provider_selection(identities, wrong_provider),
            Err(DeveloperFixtureAgentStackError::InvalidInput)
        );

        let wrong_config = ManagedAgentProviderSelectionV1::try_provisioned(
            provider_ref,
            Digest32::from_bytes([0x62; 32]),
            secret_ref,
        )
        .expect("different Provisioned config");
        assert_eq!(
            validate_provisioned_provider_selection(identities, wrong_config),
            Err(DeveloperFixtureAgentStackError::InvalidInput)
        );
    }

    fn model_plan(
        service_id: [u8; 16],
        provider: ManagedAgentProviderSelectionV1,
    ) -> ManagedModelServicePlanV1 {
        let binding = paraegox_runtime_contracts::managed_model_agent_stack_plan::ManagedModelAdapterBindingV1::try_new(
            [0x71; 16],
            paraegox_runtime_contracts::managed_model_agent_stack_plan::ManagedModelAdapterVersionV1::try_new(1)
                .expect("test adapter version"),
            paraegox_runtime_contracts::managed_model_agent_stack_plan::ManagedModelCapabilityIdV1::bounded_text_v1(),
        )
        .expect("test adapter binding");
        ManagedModelServicePlanV1::try_new(
            ManagedServiceSpecV1::new(
                ManagedServiceId::from_bytes(service_id),
                managed_lifecycle_budgets().expect("test lifecycle budgets"),
            ),
            4,
            provider,
            binding,
        )
        .expect("test Model plan")
    }

    #[test]
    fn model_facades_require_exact_model_identity_and_shared_provider() {
        let identities = DeveloperFixtureDerivedIdentityV1::try_from_seed(identity_seed())
            .expect("valid fixture identity");
        let provider = deterministic_provider(identities).expect("fixture provider");
        let exact = model_plan(identities.model_service_id(), provider);
        assert_eq!(validate_model_plan(identities, provider, exact), Ok(()));

        let wrong_provider = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([0x72; 16])
                .expect("different provider reference"),
            Digest32::from_bytes([0x73; 32]),
        )
        .expect("different provider");
        assert_eq!(
            validate_model_plan(
                identities,
                provider,
                model_plan(identities.model_service_id(), wrong_provider),
            ),
            Err(DeveloperFixtureModelAgentStackError::InvalidInput)
        );
        assert_eq!(
            validate_model_plan(identities, provider, model_plan([0x74; 16], provider)),
            Err(DeveloperFixtureModelAgentStackError::InvalidInput)
        );
    }

    #[test]
    fn paths_allow_sibling_state_and_shared_run_parent_only() {
        let valid = DeveloperFixturePathsV1::try_new(
            PathBuf::from("/tmp/paraegox/controller"),
            PathBuf::from("/tmp/paraegox/successor"),
            PathBuf::from("/tmp/paraegox/run/a.sock"),
            PathBuf::from("/tmp/paraegox/run/r.sock"),
        );
        assert!(valid.is_ok());
        assert_eq!(
            DeveloperFixturePathsV1::try_new(
                PathBuf::from("/tmp/paraegox/controller"),
                PathBuf::from("/tmp/paraegox/successor"),
                PathBuf::from("/tmp/paraegox/controller/a.sock"),
                PathBuf::from("/tmp/paraegox/run/r.sock"),
            ),
            Err(DeveloperFixtureAgentStackError::InvalidInput)
        );
    }

    #[test]
    fn controller_credentials_never_debug_key_material() {
        let authority = SigningKey::from_bytes(&[0x21; 32])
            .verifying_key()
            .to_bytes();
        let credentials =
            DeveloperFixtureControllerCredentialsV1::try_new(Zeroizing::new([0x22; 32]), authority)
                .expect("distinct non-weak developer keys");
        let rendered = format!("{credentials:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("34, 34"));
    }

    fn restricted_transport_profile(
        identities: DeveloperFixtureDerivedIdentityV1,
    ) -> RestrictedRuntimeApplyTransportProfileV1 {
        use paraegox_runtime_contracts::distributed_agent_stack_plan::{
            DistributedFabricCredentialRefV1, DistributedFabricTrustAnchorRefV1,
            DistributedFabricTrustDomainRefV1, RestrictedRuntimeApplyTransportProfileFieldsV1,
        };

        RestrictedRuntimeApplyTransportProfileV1::try_new(
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                target: RuntimeHostId::from_bytes(identities.runtime_target()),
                endpoint_ref: [0x31; 16],
                endpoint_generation: 7,
                tls_listener_locator: "tls/192.0.2.31:7447",
                route: "paraegox/runtime-a/distributed/apply",
                trust_domain_ref: DistributedFabricTrustDomainRefV1::try_from_bytes([0x32; 16])
                    .expect("trust domain"),
                trust_anchor_ref: DistributedFabricTrustAnchorRefV1::try_from_bytes([0x33; 16])
                    .expect("trust anchor"),
                controller_connector_credential_ref:
                    DistributedFabricCredentialRefV1::try_from_bytes([0x34; 16])
                        .expect("Controller credential"),
                runtime_listener_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                    [0x35; 16],
                )
                .expect("Runtime credential"),
                controller_principal: PrincipalRef::from_bytes(identities.controller_principal()),
                runtime_principal: PrincipalRef::from_bytes(identities.runtime_principal()),
                operation_timeout_nanos: 5_000_000_000,
            },
        )
        .expect("restricted transport profile")
    }

    #[test]
    fn distributed_transport_prepares_exact_carrier_before_runtime_ready_and_redacts_debug() {
        let identities = DeveloperFixtureDerivedIdentityV1::try_from_seed(identity_seed())
            .expect("valid fixture identity");
        let authority = SigningKey::from_bytes(&[0x21; 32])
            .verifying_key()
            .to_bytes();
        let credentials =
            DeveloperFixtureControllerCredentialsV1::try_new(Zeroizing::new([0x22; 32]), authority)
                .expect("Controller credentials");
        let runtime_key = SigningKey::from_bytes(&[0x23; 32])
            .verifying_key()
            .to_bytes();
        let transport = DeveloperFixtureDistributedTransportV1::try_new(
            identities,
            &credentials,
            runtime_key,
            [0x36; 16],
            restricted_transport_profile(identities),
            PathBuf::from("/tmp/paraegox-root-ca.pem"),
            PathBuf::from("/tmp/paraegox-connector.pem"),
            PathBuf::from("/tmp/paraegox-connector.key"),
        )
        .expect("pre-start distributed transport");
        assert_eq!(
            transport.expected_carrier().target(),
            RuntimeHostId::from_bytes(identities.runtime_target())
        );
        assert_eq!(
            transport.expected_carrier().runtime_response_key(),
            ApplyAuthKeyRef::from_bytes(identities.runtime_response_key_ref())
        );
        assert_eq!(
            transport.expected_carrier().control_transport_profile_ref(),
            transport.profile_ref()
        );

        let rendered = format!("{transport:?}");
        for forbidden in [
            "192.0.2.31",
            "distributed-apply",
            "paraegox-root-ca.pem",
            "paraegox-connector.pem",
            "paraegox-connector.key",
        ] {
            assert!(!rendered.contains(forbidden));
        }
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn distributed_outcome_preserves_fixed_receipt_order_and_pair_replay() {
        let outcome = DeveloperFixtureDistributedAgentStackOutcomeV1 {
            target_receipts: [
                b"target-a-pxds2".as_slice().into(),
                b"target-b-pxds2".as_slice().into(),
            ],
            replayed: true,
        };
        assert_eq!(
            outcome.target_receipts(),
            [b"target-a-pxds2".as_slice(), b"target-b-pxds2".as_slice()]
        );
        assert!(outcome.replayed());
    }
}
