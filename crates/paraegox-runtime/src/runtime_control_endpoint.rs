#![cfg(unix)]

//! Authenticated S7-E/S7-F Runtime bootstrap, query, and PXAR apply endpoint.
//!
//! One identity-bound local channel carries canonical PXBR bootstrap reads,
//! read-only PXQR operation/live queries, and canonical PXAR v5 applies. Apply
//! success is represented exclusively by the canonical PXRT v1 terminal
//! Receipt; no transport ACK or private status byte exists. The restricted
//! public Runtime-control listener additionally carries frozen PXCC v1 and the
//! independent PXAG/PXAH v1 Agent-control exchange on the same pinned route.

use core::{fmt, future::Future, time::Duration};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
#[cfg(test)]
use nix::unistd::{getegid, geteuid};
use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
    unistd::{Gid, UnlinkatFlags, chown, getpid, unlinkat},
};
use paraegox_fabric::{
    RestrictedRuntimeApplyEndpointConfigV1, RestrictedRuntimeApplyEndpointV1,
    RestrictedRuntimeApplyErrorV1, RestrictedRuntimeApplyReceiverV1,
    RestrictedRuntimeApplyRespondErrorV1, RestrictedRuntimeControlEndpointConfigV1,
    RestrictedRuntimeControlEndpointV1, RestrictedRuntimeControlInboundV1,
    RestrictedRuntimeControlReceiverV1,
};
#[cfg(test)]
use paraegox_kernel::identity::PrincipalRef;
use paraegox_kernel::{
    digest::Digest32,
    identity::RuntimeHostId,
    time::{ClockDomainRef, ClockGeneration},
};
use paraegox_runtime_contracts::{
    apply::ExpectedActive,
    distributed_agent_stack_plan::{
        ControllerAuthenticatedDistributedAgentStackApplyRequestV1,
        DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_VERSION, DistributedAgentStackApplyRequestV1,
        DistributedAgentStackPlanError, DistributedAgentStackProjectionV1,
        DistributedAgentStackRestrictedApplyRequestV1, DistributedAgentStackTerminalFactsV1,
        DistributedAgentStackTerminalOutcomeV1, DistributedAgentStackTerminalReceiptDraftV2,
        DistributedAgentStackTerminalReceiptV1, MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES,
        MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES,
        MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES,
        MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES,
        RestrictedRuntimeApplyCarrierBindingV1,
    },
    installation::{
        RuntimeCompiledInstallationFactsV1, RuntimeInstallationError,
        VerifiedRuntimeInstallationV1, VerifiedRuntimeManifestIngressV1,
        verify_immutable_manifest_ingress, verify_pinned_startup,
    },
    managed_agent_stack_plan::{
        MANAGED_AGENT_STACK_APPLY_REQUEST_VERSION, MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES,
        MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES, ManagedAgentStackApplyRequestV1,
        ManagedAgentStackPlanError, ManagedAgentStackProjectionV1,
        ManagedAgentStackTerminalReceiptV1,
    },
    managed_fabric_plan::{
        MANAGED_FABRIC_APPLY_REQUEST_VERSION, MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES,
        MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES, ManagedFabricApplyRequestV1,
        ManagedFabricApplyTerminalReceiptV1, ManagedFabricManifestProjectionV1,
        ManagedFabricPlanError,
    },
    managed_model_agent_stack_plan::{
        MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION,
        MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES,
        MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES, ManagedModelAgentStackApplyRequestV1,
        ManagedModelAgentStackPlanError, ManagedModelAgentStackProjectionV1,
    },
    managed_serving_bootstrap::{
        ControllerAuthenticatedRuntimeAgentControlRequestV1,
        ControllerAuthenticatedRuntimeControlCarrierV1,
        MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES, MAX_MANAGED_SERVING_BOOTSTRAP_RESPONSE_BYTES,
        MAX_RUNTIME_AGENT_CONTROL_RECEIPT_BYTES, MAX_RUNTIME_AGENT_CONTROL_REQUEST_BYTES,
        MAX_RUNTIME_CONTROL_CARRIER_REQUEST_BYTES,
        MAX_RUNTIME_CONTROL_DESCRIBE_READY_RESPONSE_BYTES, ManagedServingBootstrapError,
        ManagedServingBootstrapFactsV1, ManagedServingBootstrapRequestV1,
        ManagedServingBootstrapResponseAuthClaimV1, ManagedServingBootstrapResponseDraftV1,
        RUNTIME_AGENT_CONTROL_REQUEST_MAGIC, RuntimeAgentControlKindV1,
        RuntimeAgentControlReceiptDraftV1, RuntimeAgentControlRequestV1,
        RuntimeAgentControlResponseAuthClaimV1, RuntimeControlCarrierKindV1,
        RuntimeControlCarrierRequestV1, RuntimeControlDescribeReadyFactsV1,
        RuntimeControlDescribeReadyPhaseV1, RuntimeControlDescribeReadyResponseDraftV1,
    },
    provenance::{SourcePlanRevision, TargetSliceDigest},
    reference_control::{
        MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES, MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES,
        MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES, MAX_REFERENCE_QUERY_REQUEST_BYTES,
        MAX_REFERENCE_QUERY_RESPONSE_BYTES, MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES,
        ReferenceApplyRequestV1, ReferenceApplyTerminalReceiptV1, ReferenceAssemblyModeV1,
        ReferenceBootstrapCompatibilityV1, ReferenceBootstrapFactsV1, ReferenceBootstrapRequestV1,
        ReferenceBootstrapResponseAuthClaimV1, ReferenceBootstrapResponseDraftV1,
        ReferenceBootstrapServingIdentityV1, ReferenceBootstrapStateV1, ReferenceChannelBindingV1,
        ReferenceControlError, ReferenceOperationalReasonV1, ReferenceQueryDesiredHeadV1,
        ReferenceQueryDesiredStateV1, ReferenceQueryDurablePhaseV1, ReferenceQueryFactsV1,
        ReferenceQueryLiveFactsV1, ReferenceQueryLiveStateV1, ReferenceQueryOperationLookupV1,
        ReferenceQueryOperationStateV1, ReferenceQueryOwnerStateV1, ReferenceQueryRequestV1,
        ReferenceQueryResponseAuthClaimV1, ReferenceQueryResponseDraftV1,
        ReferenceTargetExecutionPlanV4, ed25519_control_key_fingerprint,
        reference_local_control_endpoint_identity_digest_v1,
        reference_runtime_peer_credentials_digest_v1, verify_reference_durable_slice_v1,
    },
    wire::ApplyAuthAlgorithm,
};
#[cfg(test)]
use paraegox_runtime_contracts::{provenance::SourceScopeRef, wire::ApplyAuthKeyRef};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

use crate::{
    admission::{ED25519_ALGORITHM, ED25519_ALGORITHM_VERSION},
    distributed_agent_stack_runtime::{
        DistributedAgentStackApplyOutcome, DistributedAgentStackEvidenceStoreConfigV1,
        DistributedAgentStackOwnerConfig, DistributedAgentStackRuntimeCore,
        DistributedAgentStackRuntimeError,
    },
    distributed_fabric_runtime::RuntimeFabricCredentialResolverV2,
    managed_agent_stack_runtime::{
        ManagedAgentStackApplyOutcome, ManagedAgentStackOwnerConfig, ManagedAgentStackRuntimeCore,
        ManagedAgentStackRuntimeError, RuntimeAgentConversationPortExportErrorV1,
        RuntimeAgentHandleBroker,
    },
    managed_fabric_runtime::{
        ManagedFabricApplyOutcome, ManagedFabricOwnerConfig, ManagedFabricRuntimeCore,
        ManagedFabricRuntimeError, transition_projection_digest,
    },
    managed_fabric_state::{ManagedFabricSnapshot, ManagedFabricStateError},
    managed_model_agent_stack_runtime::{
        ManagedModelAgentStackApplyOutcome, ManagedModelAgentStackCutoverOutcome,
        ManagedModelAgentStackOwnerConfig, ManagedModelAgentStackRuntimeCore,
        ManagedModelAgentStackRuntimeError,
    },
    managed_model_runtime::{
        RuntimeModelBackendResolverV1, UnavailableRuntimeModelBackendResolver,
    },
    runtime_agent_provider::{
        RuntimeAgentProviderResolverV1, UnavailableRuntimeAgentProviderResolver,
    },
    runtime_clock::RuntimeClock,
    runtime_control_state::{
        RuntimeControlState, RuntimeControlStateError, RuntimeJournalBootstrapReason,
        RuntimeJournalBootstrapState, RuntimeReferenceApplyPreflight,
        runtime_reference_apply::{
            RuntimeReferenceApplyClock, RuntimeReferenceApplyClockError, RuntimeReferenceApplyCore,
            RuntimeReferenceApplyError, RuntimeReferenceApplyOutcome, RuntimeReferenceApplySigner,
            RuntimeReferenceApplyStore, RuntimeReferenceMaterializationOwner,
            RuntimeRestartReassemblyError, RuntimeStoredReferenceApplyReceipt,
            run_runtime_restart_reassembly,
        },
        runtime_reference_owner::RuntimeFixedReferenceMaterializationOwner,
    },
    runtime_journal::{
        DesiredHeadKind, ExpectedActiveCas, LiveMaterialization, PreparedPhase,
        RuntimeDeadlineObservation, RuntimeJournalSnapshot, StorePinnedBuildIdentity,
    },
    runtime_provisioning::{
        RuntimeProvisioningError, RuntimeProvisioningV1, validate_canonical_absolute_path,
    },
    runtime_store::{
        ManagedFabricStore, ManagedFabricStoreError, RuntimeStore, RuntimeStoreError,
        RuntimeStoreOpenError,
    },
};

#[cfg(test)]
use crate::runtime_provisioning::CONTROL_SOCKET_DIRECTORY_MODE;

#[cfg(test)]
use crate::runtime_journal::ResourcePhase;

const ED25519_SIGNATURE_BYTES: usize = 64;
const CONTROL_FRAME_HEADER_BYTES: usize = 4;
const BOOTSTRAP_REQUEST_MAGIC: &[u8; 4] = b"PXBR";
const MANAGED_BOOTSTRAP_REQUEST_MAGIC: &[u8; 4] = b"PXFB";
const QUERY_REQUEST_MAGIC: &[u8; 4] = b"PXQR";
const APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const MODE_MASK: u32 = 0o7777;
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONTROL_REQUEST_BYTES: usize = maximum_eight([
    MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES,
    MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES,
    MAX_REFERENCE_QUERY_REQUEST_BYTES,
    MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES,
    MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES,
    MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES,
    MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES,
    MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES,
]);
const MAX_CONTROL_RESPONSE_BYTES: usize = maximum_eight([
    MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES,
    MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES,
    MAX_REFERENCE_QUERY_RESPONSE_BYTES,
    MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES,
    MAX_MANAGED_SERVING_BOOTSTRAP_RESPONSE_BYTES,
    MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES,
    MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES,
    MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES,
]);

/// Builds the scheduler used by every process owner that can host managed
/// Fabric. Zenoh requires Tokio's multi-thread scheduler; one worker keeps the
/// Runtime's bounded owner model without relying on the unsupported
/// current-thread flavor.
pub(crate) fn build_managed_fabric_owner_runtime()
-> Result<tokio::runtime::Runtime, RuntimeBootstrapEndpointError> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| RuntimeBootstrapEndpointError::Runtime)
}

fn unavailable_provider_resolver() -> Arc<dyn RuntimeAgentProviderResolverV1> {
    Arc::new(UnavailableRuntimeAgentProviderResolver)
}

fn unavailable_model_backend_resolver() -> Arc<dyn RuntimeModelBackendResolverV1> {
    Arc::new(UnavailableRuntimeModelBackendResolver)
}

/// Strict experimental V2 dependency required by the distributed Agent stack.
///
/// Live-link observation is not injectable: PXAR-v8 reads the exact
/// lifecycle-owned Fabric session through its generation fence. Composition
/// supplies one complete resolver-and-Evidence configuration or selects the
/// explicit unavailable path; partial distributed composition cannot exist.
#[derive(Clone)]
pub(crate) struct RuntimeDistributedAgentStackDependenciesV1 {
    fabric_credential_resolver: Arc<dyn RuntimeFabricCredentialResolverV2>,
    evidence_store_config: DistributedAgentStackEvidenceStoreConfigV1,
}

impl RuntimeDistributedAgentStackDependenciesV1 {
    pub(crate) fn new(
        fabric_credential_resolver: Arc<dyn RuntimeFabricCredentialResolverV2>,
        evidence_store_config: DistributedAgentStackEvidenceStoreConfigV1,
    ) -> Self {
        Self {
            fabric_credential_resolver,
            evidence_store_config,
        }
    }
}

impl fmt::Debug for RuntimeDistributedAgentStackDependenciesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDistributedAgentStackDependenciesV1")
            .field("fabric_credential_resolver", &"<injected>")
            .field("evidence_store_config", &"<composition-pinned>")
            .finish()
    }
}

/// Composition-owned restricted Runtime apply endpoint generation.
///
/// The Fabric configuration owns resolved listener/TLS mechanics while the
/// exact PXCB remains the Runtime admission correlation value. In particular,
/// `control_transport_profile_ref` and `control_transport_profile_digest` are
/// opaque composition assertions: Runtime provisioning does not resolve or
/// fabricate them. The composition root must bind them to this exact resolved
/// endpoint generation; Runtime additionally checks the route and all
/// Provisioning-owned identity/key pins before opening the listener.
#[derive(Clone)]
pub(crate) struct RuntimeRestrictedApplyEndpointDependenciesV1 {
    endpoint_config: RestrictedRuntimeEndpointConfigV1,
    expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
    protocol: RestrictedRuntimeEndpointProtocolV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestrictedRuntimeEndpointProtocolV1 {
    LegacyApply,
    RuntimeControl,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RestrictedRuntimeEndpointConfigV1 {
    LegacyApply(RestrictedRuntimeApplyEndpointConfigV1),
    RuntimeControl(RestrictedRuntimeControlEndpointConfigV1),
}

impl RestrictedRuntimeEndpointConfigV1 {
    #[cfg(test)]
    fn route(&self) -> &str {
        match self {
            Self::LegacyApply(config) => config.route(),
            Self::RuntimeControl(config) => config.route(),
        }
    }

    fn matches_restricted_carrier(&self, carrier: &RestrictedRuntimeApplyCarrierBindingV1) -> bool {
        match self {
            Self::LegacyApply(config) => config.matches_restricted_carrier(carrier),
            Self::RuntimeControl(config) => config.matches_restricted_carrier(carrier),
        }
    }

    #[cfg(test)]
    fn into_legacy_apply(self) -> RestrictedRuntimeApplyEndpointConfigV1 {
        match self {
            Self::LegacyApply(config) => config,
            Self::RuntimeControl(_) => panic!("expected legacy restricted endpoint config"),
        }
    }
}

impl RuntimeRestrictedApplyEndpointDependenciesV1 {
    pub(crate) fn new(
        endpoint_config: RestrictedRuntimeApplyEndpointConfigV1,
        expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
    ) -> Self {
        Self {
            endpoint_config: RestrictedRuntimeEndpointConfigV1::LegacyApply(endpoint_config),
            expected_carrier,
            protocol: RestrictedRuntimeEndpointProtocolV1::LegacyApply,
        }
    }

    pub(crate) fn new_runtime_control(
        endpoint_config: RestrictedRuntimeControlEndpointConfigV1,
        expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
    ) -> Self {
        Self {
            endpoint_config: RestrictedRuntimeEndpointConfigV1::RuntimeControl(endpoint_config),
            expected_carrier,
            protocol: RestrictedRuntimeEndpointProtocolV1::RuntimeControl,
        }
    }
}

impl fmt::Debug for RuntimeRestrictedApplyEndpointDependenciesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeRestrictedApplyEndpointDependenciesV1")
            .field("endpoint_config", &"<composition-pinned>")
            .field("expected_carrier", &"<composition-pinned>")
            .field("protocol", &self.protocol)
            .finish()
    }
}

/// Process-local managed-service composition dependencies.
///
/// Agent-provider and Model-backend resolution are independent non-optional
/// seams. A composition that cannot serve either seam must inject its explicit
/// rejecting resolver; Runtime never substitutes one for the other and never
/// falls back. Distributed V2 and restricted-apply capabilities remain
/// explicit optional values whose exact dependencies survive restart and
/// cutover unchanged.
#[derive(Clone)]
pub(crate) struct RuntimeManagedFabricServiceDependenciesV1 {
    agent_provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
    model_backend_resolver: Arc<dyn RuntimeModelBackendResolverV1>,
    distributed_agent_stack: Option<RuntimeDistributedAgentStackDependenciesV1>,
    restricted_runtime_apply_endpoint: Option<RuntimeRestrictedApplyEndpointDependenciesV1>,
}

impl RuntimeManagedFabricServiceDependenciesV1 {
    pub(crate) fn new(
        agent_provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
        model_backend_resolver: Arc<dyn RuntimeModelBackendResolverV1>,
        distributed_agent_stack: Option<RuntimeDistributedAgentStackDependenciesV1>,
        restricted_runtime_apply_endpoint: Option<RuntimeRestrictedApplyEndpointDependenciesV1>,
    ) -> Self {
        Self {
            agent_provider_resolver,
            model_backend_resolver,
            distributed_agent_stack,
            restricted_runtime_apply_endpoint,
        }
    }

    pub(crate) fn unavailable() -> Self {
        Self::new(
            unavailable_provider_resolver(),
            unavailable_model_backend_resolver(),
            None,
            None,
        )
    }

    fn agent_provider_resolver(&self) -> Arc<dyn RuntimeAgentProviderResolverV1> {
        Arc::clone(&self.agent_provider_resolver)
    }

    fn model_backend_resolver(&self) -> Arc<dyn RuntimeModelBackendResolverV1> {
        Arc::clone(&self.model_backend_resolver)
    }

    fn distributed_agent_stack_owner_dependencies(
        &self,
    ) -> Option<&RuntimeDistributedAgentStackDependenciesV1> {
        self.distributed_agent_stack.as_ref()
    }
}

impl fmt::Debug for RuntimeManagedFabricServiceDependenciesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeManagedFabricServiceDependenciesV1")
            .field("agent_provider_resolver", &"<injected>")
            .field("model_backend_resolver", &"<injected>")
            .field(
                "distributed_agent_stack",
                &self.distributed_agent_stack.is_some(),
            )
            .field(
                "restricted_runtime_apply_endpoint",
                &self.restricted_runtime_apply_endpoint.is_some(),
            )
            .finish()
    }
}

const fn maximum_eight(values: [usize; 8]) -> usize {
    let mut maximum = values[0];
    let mut index = 1;
    while index < values.len() {
        if values[index] > maximum {
            maximum = values[index];
        }
        index += 1;
    }
    maximum
}

fn validate_snapshot_pins(
    provisioning: &RuntimeProvisioningV1,
    snapshot: &RuntimeJournalSnapshot,
) -> Result<(), RuntimeBootstrapEndpointError> {
    provisioning.validate_runtime_credentials()?;
    let state = snapshot.state();
    if snapshot.owner_target_fingerprint() != &provisioning.owner_target_fingerprint()
        || state.host.admission_policy_fingerprint != provisioning.admission_policy_fingerprint()
        || state.host.controller_key_fingerprint != provisioning.controller_key_fingerprint()
        || state.host.channel_policy_fingerprint != provisioning.channel_policy_fingerprint()
    {
        return Err(RuntimeBootstrapEndpointError::ProvisioningPinMismatch);
    }
    Ok(())
}

fn authenticate_request(
    provisioning: &RuntimeProvisioningV1,
    request: &ReferenceBootstrapRequestV1,
) -> Result<(), RuntimeBootstrapRequestError> {
    let claim = request.authentication().claim();
    if request.target() != provisioning.target()
        || request.source_scope() != provisioning.source_scope()
        || claim.principal() != provisioning.controller_principal()
        || claim.key() != provisioning.controller_request_key_ref()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(RuntimeBootstrapRequestError::Unauthorized);
    }
    let signature = parse_signature(request.authentication().signature())?;
    let transcript = request
        .signing_transcript()
        .map_err(|_| RuntimeBootstrapRequestError::InvalidCanonicalRequest)?;
    provisioning
        .controller_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| RuntimeBootstrapRequestError::InvalidSignature)
}

fn authenticate_query_request(
    provisioning: &RuntimeProvisioningV1,
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceQueryRequestV1,
) -> Result<(), RuntimeQueryRequestError> {
    let claim = request.authentication().claim();
    if request.target() != provisioning.target()
        || request.source_scope() != provisioning.source_scope()
        || claim.principal() != provisioning.controller_principal()
        || claim.key() != provisioning.controller_request_key_ref()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(RuntimeQueryRequestError::Unauthorized);
    }
    request
        .validate_expected_store(*snapshot.store_instance_id())
        .map_err(|_| RuntimeQueryRequestError::StoreMismatch)?;
    let signature = parse_query_signature(request.authentication().signature())?;
    let transcript = request
        .signing_transcript()
        .map_err(|_| RuntimeQueryRequestError::InvalidCanonicalRequest)?;
    provisioning
        .controller_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| RuntimeQueryRequestError::InvalidSignature)
}

fn parse_signature(signature: &[u8]) -> Result<Signature, RuntimeBootstrapRequestError> {
    let bytes: &[u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| RuntimeBootstrapRequestError::InvalidSignature)?;
    Ok(Signature::from_bytes(bytes))
}

fn parse_query_signature(signature: &[u8]) -> Result<Signature, RuntimeQueryRequestError> {
    let bytes: &[u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| RuntimeQueryRequestError::InvalidSignature)?;
    Ok(Signature::from_bytes(bytes))
}

/// Store seam used to prove startup invalidation is durable before binding.
trait RuntimeBootstrapStore {
    fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeBootstrapEndpointError>;

    fn commit(&mut self, next: RuntimeJournalSnapshot)
    -> Result<(), RuntimeBootstrapEndpointError>;
}

impl RuntimeBootstrapStore for RuntimeStore {
    fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeBootstrapEndpointError> {
        self.snapshot().map_err(Into::into)
    }

    fn commit(
        &mut self,
        next: RuntimeJournalSnapshot,
    ) -> Result<(), RuntimeBootstrapEndpointError> {
        self.commit(next).map_err(Into::into)
    }
}

/// Service capability that exists only after strict startup verification and
/// the startup-invalidation snapshot commit have both succeeded.
struct StartedRuntimeBootstrapService<Store> {
    store: Store,
    #[cfg(test)]
    state: RuntimeControlState,
    clock: RuntimeClock,
    owner: RuntimeFixedReferenceMaterializationOwner,
    signer: RuntimeReferenceApplySigner,
    compiled: RuntimeCompiledInstallationFactsV1,
    compatibility: ReferenceBootstrapCompatibilityV1,
    provisioning: RuntimeProvisioningV1,
}

impl<Store> StartedRuntimeBootstrapService<Store>
where
    Store: RuntimeBootstrapStore + RuntimeReferenceApplyStore,
{
    fn try_start(
        mut store: Store,
        compiled: RuntimeCompiledInstallationFactsV1,
        provisioning: RuntimeProvisioningV1,
    ) -> Result<Self, RuntimeBootstrapEndpointError> {
        let previous = store.snapshot()?.clone();
        let installation = verify_startup_installation(&previous, provisioning.target(), compiled)?;
        validate_snapshot_pins(&provisioning, &previous)?;
        let manifest = installation.immutable_manifest_ingress()?;
        validate_startup_durable_control_state(&previous, &manifest, compiled, &provisioning)?;
        let compatibility = ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            &installation,
            compiled,
            previous.state().host.admission_policy_fingerprint,
        )?;
        let state = RuntimeControlState::try_start(&previous)?;
        let active_execution = startup_active_execution(&previous, &manifest, compiled)?;

        // Startup invalidation is the first durable boundary. Reassembly and
        // every exact-zero/quarantine successor below also finish before this
        // capability can be converted into a listener.
        store.commit(state.snapshot().clone())?;
        let journal = state.bootstrap_facts()?;
        let generation = ClockGeneration::try_new(journal.clock_generation())
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let clock = RuntimeClock::new(
            ClockDomainRef::from_bytes(journal.clock_domain()),
            generation,
            1,
        );
        let owner =
            RuntimeFixedReferenceMaterializationOwner::try_new(compiled, clock, state.snapshot())
                .map_err(|error| {
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Owner(error))
            })?;
        let signer = RuntimeReferenceApplySigner::try_new(
            provisioning.response_signer().clone(),
            provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?,
            ED25519_ALGORITHM_VERSION,
        )
        .map_err(RuntimeBootstrapEndpointError::Apply)?;
        let parts = run_runtime_restart_reassembly(
            store,
            state,
            RuntimeEndpointApplyClock { clock },
            owner,
            &signer,
            active_execution.as_ref(),
        )?;
        Ok(Self {
            store: parts.store,
            #[cfg(test)]
            state: parts.state,
            clock,
            owner: parts.owner,
            signer,
            compiled,
            compatibility,
            provisioning,
        })
    }

    #[cfg(test)]
    fn bootstrap_core(
        &self,
        channel: ReferenceChannelBindingV1,
    ) -> Result<RuntimeBootstrapCore<'_>, RuntimeBootstrapEndpointError> {
        runtime_bootstrap_core(
            &self.state,
            &self.compatibility,
            &self.provisioning,
            channel,
        )
    }
}

fn runtime_bootstrap_core<'a>(
    state: &RuntimeControlState,
    compatibility: &ReferenceBootstrapCompatibilityV1,
    provisioning: &'a RuntimeProvisioningV1,
    channel: ReferenceChannelBindingV1,
) -> Result<RuntimeBootstrapCore<'a>, RuntimeBootstrapEndpointError> {
    let journal = state.bootstrap_facts()?;
    let serving = ReferenceBootstrapServingIdentityV1::try_new(
        provisioning.target(),
        journal.store_instance_id(),
        journal.snapshot_sequence(),
        journal.runtime_host_epoch(),
        ClockDomainRef::from_bytes(journal.clock_domain()),
        ClockGeneration::try_new(journal.clock_generation())
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?,
    )?;
    let facts = ReferenceBootstrapFactsV1::try_new(
        serving,
        compatibility,
        map_bootstrap_state(journal.readiness()),
        journal.reason().map(map_bootstrap_reason),
    )?;
    Ok(RuntimeBootstrapCore {
        facts,
        channel,
        provisioning,
    })
}

#[derive(Clone, Copy, Debug)]
struct RuntimeEndpointApplyClock {
    clock: RuntimeClock,
}

impl RuntimeReferenceApplyClock for RuntimeEndpointApplyClock {
    fn observe(
        &mut self,
        expected_clock_generation: u64,
    ) -> Result<RuntimeDeadlineObservation, RuntimeReferenceApplyClockError> {
        if self.clock.generation().value() != expected_clock_generation {
            return Err(RuntimeReferenceApplyClockError::Unavailable);
        }
        let reading = self
            .clock
            .reading()
            .map_err(|_| RuntimeReferenceApplyClockError::Unavailable)?;
        let observed_at_nanos = reading.now().value();
        if observed_at_nanos == 0 {
            return Err(RuntimeReferenceApplyClockError::Unavailable);
        }
        Ok(RuntimeDeadlineObservation {
            clock_generation: reading.generation().value(),
            observed_at_nanos,
        })
    }
}

struct RuntimeControlService<Store, Owner = RuntimeFixedReferenceMaterializationOwner> {
    apply: RuntimeReferenceApplyCore<Store, RuntimeEndpointApplyClock, Owner>,
    clock: RuntimeClock,
    compiled: RuntimeCompiledInstallationFactsV1,
    compatibility: ReferenceBootstrapCompatibilityV1,
    provisioning: RuntimeProvisioningV1,
    channel: ReferenceChannelBindingV1,
}

impl<Store, Owner> RuntimeControlService<Store, Owner>
where
    Store: RuntimeReferenceApplyStore,
    Owner: RuntimeReferenceMaterializationOwner,
{
    fn handle_request(
        &mut self,
        frame: &[u8],
        live_channel: ReferenceChannelBindingV1,
    ) -> Result<Option<Box<[u8]>>, RuntimeControlRequestError> {
        if live_channel != self.channel || frame.len() < 4 {
            return Err(RuntimeControlRequestError::Rejected);
        }
        if frame.starts_with(BOOTSTRAP_REQUEST_MAGIC) {
            self.handle_bootstrap(frame).map(Some)
        } else if frame.starts_with(QUERY_REQUEST_MAGIC) {
            self.handle_query(frame).map(Some)
        } else if frame.starts_with(APPLY_REQUEST_MAGIC) {
            self.handle_apply(frame)
        } else {
            Err(RuntimeControlRequestError::Rejected)
        }
    }

    fn handle_bootstrap(&self, frame: &[u8]) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        let state = RuntimeControlState::try_from_started_snapshot(self.apply.snapshot()).map_err(
            |error| {
                RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(
                    error,
                ))
            },
        )?;
        let core = runtime_bootstrap_core(
            &state,
            &self.compatibility,
            &self.provisioning,
            self.channel,
        )
        .map_err(RuntimeControlRequestError::Internal)?;
        core.handle_request(frame).map_err(|error| match error {
            RuntimeBootstrapRequestError::InternalContract => RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::InvalidStartedState,
            ),
            _ => RuntimeControlRequestError::Rejected,
        })
    }

    fn handle_query(&self, frame: &[u8]) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if frame.is_empty() || frame.len() > MAX_REFERENCE_QUERY_REQUEST_BYTES {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = ReferenceQueryRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        validate_snapshot_pins(&self.provisioning, self.apply.snapshot())
            .map_err(RuntimeControlRequestError::Internal)?;
        RuntimeControlState::try_from_started_snapshot(self.apply.snapshot()).map_err(|error| {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
        })?;
        authenticate_query_request(&self.provisioning, self.apply.snapshot(), &request)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        let facts = runtime_query_facts(
            self.apply.snapshot(),
            &self.provisioning,
            self.clock,
            &request,
        )
        .map_err(RuntimeControlRequestError::Internal)?;
        let auth_claim = ReferenceQueryResponseAuthClaimV1::try_new(
            self.channel,
            self.provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM).map_err(|_| {
                RuntimeControlRequestError::Internal(
                    RuntimeBootstrapEndpointError::InvalidStartedState,
                )
            })?,
            ED25519_ALGORITHM_VERSION,
        )
        .map_err(|_| {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidStartedState)
        })?;
        let draft =
            ReferenceQueryResponseDraftV1::try_new(&request, facts, self.channel, auth_claim)
                .map_err(|_| {
                    RuntimeControlRequestError::Internal(
                        RuntimeBootstrapEndpointError::InvalidStartedState,
                    )
                })?;
        let signature = self
            .provisioning
            .response_signer()
            .sign(
                draft
                    .signing_transcript()
                    .map_err(|_| {
                        RuntimeControlRequestError::Internal(
                            RuntimeBootstrapEndpointError::InvalidStartedState,
                        )
                    })?
                    .as_bytes(),
            )
            .to_bytes();
        let response = draft
            .finalize(&signature)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        let wire = response.canonical_wire();
        if wire.is_empty()
            || wire.len() > MAX_REFERENCE_QUERY_RESPONSE_BYTES
            || wire.len() > request.max_response_bytes() as usize
        {
            return Err(RuntimeControlRequestError::Rejected);
        }
        Ok(wire.into())
    }

    fn handle_apply(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<Box<[u8]>>, RuntimeControlRequestError> {
        if frame.is_empty() || frame.len() > MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = ReferenceApplyRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        reference_apply_base_validation(
            &self.provisioning,
            self.compiled,
            self.apply.snapshot(),
            self.channel,
            &request,
        )?;
        match reference_terminal_match(self.apply.snapshot(), &request) {
            ReferenceTerminalMatch::Exact => {
                self.provisioning
                    .admission_policy()
                    .authenticate_reference_apply_request(&request)
                    .map_err(|_| RuntimeControlRequestError::Rejected)?;
                let replay = self
                    .apply
                    .try_exact_terminal_replay(&request)
                    .map_err(map_apply_error)?
                    .ok_or({
                        RuntimeControlRequestError::Internal(
                            RuntimeBootstrapEndpointError::InvalidStartedState,
                        )
                    })?;
                return terminal_response_wire(&replay).map(Some);
            }
            ReferenceTerminalMatch::Conflict => {
                return Err(RuntimeControlRequestError::Rejected);
            }
            ReferenceTerminalMatch::Absent => {}
        }
        let preflight = reference_apply_fresh_preflight(
            &self.provisioning,
            self.apply.snapshot(),
            self.clock,
            self.channel,
            &request,
        )?;
        let outcome = self
            .apply
            .try_apply(&request, preflight)
            .map_err(map_apply_error)?;
        match outcome {
            RuntimeReferenceApplyOutcome::Terminal(stored) => {
                terminal_response_wire(&stored).map(Some)
            }
            RuntimeReferenceApplyOutcome::TenureOnlyDurable => Ok(None),
        }
    }
}

fn runtime_query_facts(
    snapshot: &RuntimeJournalSnapshot,
    provisioning: &RuntimeProvisioningV1,
    clock: RuntimeClock,
    request: &ReferenceQueryRequestV1,
) -> Result<ReferenceQueryFactsV1, RuntimeBootstrapEndpointError> {
    let control = RuntimeControlState::try_from_started_snapshot(snapshot)?;
    let bootstrap = control.bootstrap_facts()?;
    let serving = ReferenceBootstrapServingIdentityV1::try_new(
        provisioning.target(),
        bootstrap.store_instance_id(),
        bootstrap.snapshot_sequence(),
        bootstrap.runtime_host_epoch(),
        ClockDomainRef::from_bytes(bootstrap.clock_domain()),
        ClockGeneration::try_new(bootstrap.clock_generation())
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?,
    )?;
    let reading = clock
        .reading()
        .map_err(|_| RuntimeBootstrapEndpointError::RuntimeClock)?;
    if reading.generation().value() != bootstrap.clock_generation() {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }

    let owner = query_owner_projection(bootstrap.readiness(), bootstrap.reason());
    let lookup = if let Some(reason) = owner.indeterminate_reason {
        ReferenceQueryOperationLookupV1::Indeterminate { reason }
    } else {
        query_operation_lookup(snapshot, request)?
    };
    let operation = ReferenceQueryOperationStateV1::try_new(owner.state, owner.reason, lookup)?;
    let desired = query_desired_projection(snapshot, request)?;
    let live = query_live_projection(snapshot, reading.now().value())?;
    ReferenceQueryFactsV1::try_new(serving, operation, desired, live).map_err(Into::into)
}

#[derive(Clone, Copy)]
struct QueryOwnerProjection {
    state: ReferenceQueryOwnerStateV1,
    reason: Option<ReferenceOperationalReasonV1>,
    indeterminate_reason: Option<ReferenceOperationalReasonV1>,
}

fn query_owner_projection(
    readiness: RuntimeJournalBootstrapState,
    reason: Option<RuntimeJournalBootstrapReason>,
) -> QueryOwnerProjection {
    match (readiness, reason) {
        (RuntimeJournalBootstrapState::ReadyForApply, None) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::Operational,
            reason: None,
            indeterminate_reason: None,
        },
        (
            RuntimeJournalBootstrapState::NotReadyRecovering,
            Some(RuntimeJournalBootstrapReason::Recovering),
        ) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::ApplyDisabled,
            reason: Some(ReferenceOperationalReasonV1::Recovering),
            indeterminate_reason: None,
        },
        (
            RuntimeJournalBootstrapState::RecoveryFailedNotReady,
            Some(RuntimeJournalBootstrapReason::RecoveryFailed),
        ) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::ApplyDisabled,
            reason: Some(ReferenceOperationalReasonV1::RecoveryFailed),
            indeterminate_reason: None,
        },
        (
            RuntimeJournalBootstrapState::NotReadyBusy,
            Some(RuntimeJournalBootstrapReason::RuntimeBusy),
        ) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::ApplyDisabled,
            reason: Some(ReferenceOperationalReasonV1::RuntimeBusy),
            indeterminate_reason: None,
        },
        (
            RuntimeJournalBootstrapState::ValidatedOperationalQuarantine,
            Some(RuntimeJournalBootstrapReason::OwnershipUncertain),
        ) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::OwnershipUncertain,
            reason: Some(ReferenceOperationalReasonV1::OwnershipUncertain),
            indeterminate_reason: Some(ReferenceOperationalReasonV1::OwnershipUncertain),
        },
        _ => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::OwnershipUncertain,
            reason: Some(ReferenceOperationalReasonV1::HistoryUnavailable),
            indeterminate_reason: Some(ReferenceOperationalReasonV1::HistoryUnavailable),
        },
    }
}

fn query_operation_lookup(
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceQueryRequestV1,
) -> Result<ReferenceQueryOperationLookupV1, RuntimeBootstrapEndpointError> {
    let requested_scope = *request.source_scope().as_bytes();
    let requested_operation = *request.requested_operation_id().as_bytes();
    if let Some(prepared) = snapshot.state().prepared.as_ref().filter(|prepared| {
        prepared.source_scope == requested_scope && prepared.operation_id == requested_operation
    }) {
        return Ok(query_known_or_conflict(
            request.expected_request_digest(),
            prepared.request.digest,
            query_prepared_phase(prepared.phase, prepared.retiring.is_some()),
            None,
        ));
    }
    if let Some(terminal) = snapshot
        .state()
        .terminal_operations
        .iter()
        .find(|terminal| {
            terminal.source_scope == requested_scope && terminal.operation_id == requested_operation
        })
    {
        let receipt =
            ReferenceApplyTerminalReceiptV1::decode(&terminal.canonical_response.canonical_bytes)
                .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        return Ok(query_known_or_conflict(
            request.expected_request_digest(),
            terminal.request_digest,
            ReferenceQueryDurablePhaseV1::Terminal,
            Some(receipt.facts().terminal_result_ref()),
        ));
    }
    Ok(ReferenceQueryOperationLookupV1::Unknown)
}

fn query_known_or_conflict(
    expected: Option<Digest32>,
    existing: Digest32,
    durable_phase: ReferenceQueryDurablePhaseV1,
    terminal_result: Option<
        paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1,
    >,
) -> ReferenceQueryOperationLookupV1 {
    if expected.is_some_and(|expected| expected != existing) {
        ReferenceQueryOperationLookupV1::Conflict {
            existing_request_digest: existing,
        }
    } else {
        ReferenceQueryOperationLookupV1::Known {
            request_digest: existing,
            durable_phase,
            terminal_result,
        }
    }
}

const fn query_prepared_phase(
    phase: PreparedPhase,
    is_head_first_retire: bool,
) -> ReferenceQueryDurablePhaseV1 {
    match phase {
        PreparedPhase::PreparedNoEffects
        | PreparedPhase::SupersededBeforeEffects
        | PreparedPhase::StartupExpiredNoEffects => ReferenceQueryDurablePhaseV1::PreparedNoEffects,
        PreparedPhase::FirstActionIntent => ReferenceQueryDurablePhaseV1::FirstActionIntent,
        PreparedPhase::SupersededReconcileRequired | PreparedPhase::StartupReconcileRequired => {
            if is_head_first_retire {
                ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld
            } else {
                ReferenceQueryDurablePhaseV1::FirstActionIntent
            }
        }
        PreparedPhase::HeadCommittedRetiringOld => {
            ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld
        }
    }
}

fn query_desired_projection(
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceQueryRequestV1,
) -> Result<ReferenceQueryDesiredStateV1, RuntimeBootstrapEndpointError> {
    let requested_scope = *request.source_scope().as_bytes();
    let high_water = match snapshot.state().source_revision_high_water {
        Some(high_water) if high_water.source_scope == requested_scope => high_water.revision,
        Some(_) => return Err(RuntimeBootstrapEndpointError::InvalidStartedState),
        None => 0,
    };
    let head = match snapshot.state().active_desired.as_ref() {
        Some(active) if active.source_scope != requested_scope => {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        Some(active) => {
            let facts = {
                let source_revision = SourcePlanRevision::new(active.source_revision);
                let target_slice_digest = active.slice_provenance.target_slice_digest;
                let manifest_digest = active.manifest_digest;
                (source_revision, target_slice_digest, manifest_digest)
            };
            match active.kind {
                DesiredHeadKind::OneSourceLoop => ReferenceQueryDesiredHeadV1::OneSourceLoop {
                    source_revision: facts.0,
                    target_slice_digest: facts.1,
                    manifest_digest: facts.2,
                },
                DesiredHeadKind::EmptyDeactivate => ReferenceQueryDesiredHeadV1::EmptyDeactivate {
                    source_revision: facts.0,
                    target_slice_digest: facts.1,
                    manifest_digest: facts.2,
                },
            }
        }
        None => ReferenceQueryDesiredHeadV1::None,
    };
    ReferenceQueryDesiredStateV1::try_new(head, SourcePlanRevision::new(high_water))
        .map_err(Into::into)
}

fn query_live_projection(
    snapshot: &RuntimeJournalSnapshot,
    measured_at: u64,
) -> Result<ReferenceQueryLiveFactsV1, RuntimeBootstrapEndpointError> {
    let state = snapshot.state();
    let census = snapshot
        .resource_census_digest()
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    let nonterminal_generation = state
        .owned_resources
        .iter()
        .filter(|resource| !resource.phase.is_terminal())
        .map(|resource| resource.generation)
        .max()
        .unwrap_or(0);
    let (live, generation, recorded_census) = match state.live_materialization {
        LiveMaterialization::None => (
            if state.prepared.is_some() {
                ReferenceQueryLiveStateV1::NotReady
            } else {
                ReferenceQueryLiveStateV1::ExactZero
            },
            0,
            census,
        ),
        LiveMaterialization::StartupInvalidated {
            recovery_eligibility,
            resource_census_digest,
            ..
        } => match recovery_eligibility {
            crate::runtime_journal::StartupRecoveryEligibility::NoActiveHead
            | crate::runtime_journal::StartupRecoveryEligibility::CanonicalEmptyExactZero => (
                ReferenceQueryLiveStateV1::ExactZero,
                0,
                resource_census_digest,
            ),
            crate::runtime_journal::StartupRecoveryEligibility::EligibleOneSourceLoop => (
                ReferenceQueryLiveStateV1::Recovering,
                nonterminal_generation,
                resource_census_digest,
            ),
            crate::runtime_journal::StartupRecoveryEligibility::RecoveryFailureLatched => (
                ReferenceQueryLiveStateV1::RecoveryFailedNotReady,
                0,
                resource_census_digest,
            ),
            crate::runtime_journal::StartupRecoveryEligibility::ReconcileRequired => (
                if nonterminal_generation == 0 {
                    ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
                } else {
                    ReferenceQueryLiveStateV1::Uncertain
                },
                nonterminal_generation,
                resource_census_digest,
            ),
        },
        LiveMaterialization::Recovering {
            resource_generation,
            resource_census_digest,
            ..
        } => (
            ReferenceQueryLiveStateV1::Recovering,
            resource_generation,
            resource_census_digest,
        ),
        LiveMaterialization::LiveReady {
            resource_generation,
            resource_census_digest,
            ..
        } => (
            ReferenceQueryLiveStateV1::LiveReady,
            resource_generation,
            resource_census_digest,
        ),
        LiveMaterialization::RecoveryFailedNotReady {
            resource_census_digest,
            ..
        } => (
            ReferenceQueryLiveStateV1::RecoveryFailedNotReady,
            0,
            resource_census_digest,
        ),
        LiveMaterialization::Draining {
            retiring_generation,
            resource_census_digest,
            ..
        } => (
            ReferenceQueryLiveStateV1::Draining,
            retiring_generation,
            resource_census_digest,
        ),
        LiveMaterialization::ExactZero { census_digest, .. } => {
            (ReferenceQueryLiveStateV1::ExactZero, 0, census_digest)
        }
        LiveMaterialization::Quarantined {
            resource_census_digest,
            ..
        } => (
            if nonterminal_generation == 0 {
                ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
            } else {
                ReferenceQueryLiveStateV1::Uncertain
            },
            nonterminal_generation,
            resource_census_digest,
        ),
    };
    if recorded_census != census {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }
    ReferenceQueryLiveFactsV1::try_new(live, generation, measured_at, census).map_err(Into::into)
}

fn terminal_response_wire(
    stored: &RuntimeStoredReferenceApplyReceipt,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let wire = stored.canonical_wire();
    if wire.is_empty() || wire.len() > MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    let strict = ReferenceApplyTerminalReceiptV1::decode(wire).map_err(|_| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidStartedState)
    })?;
    if strict.canonical_wire() != wire {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    Ok(wire.into())
}

fn reference_apply_base_validation(
    provisioning: &RuntimeProvisioningV1,
    compiled: RuntimeCompiledInstallationFactsV1,
    snapshot: &RuntimeJournalSnapshot,
    channel: ReferenceChannelBindingV1,
    request: &ReferenceApplyRequestV1,
) -> Result<(), RuntimeControlRequestError> {
    validate_snapshot_pins(provisioning, snapshot).map_err(RuntimeControlRequestError::Internal)?;
    RuntimeControlState::try_from_started_snapshot(snapshot).map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
    })?;
    if request.target() != provisioning.target()
        || request.provenance().source_scope() != provisioning.source_scope()
        || request.authentication().claim().principal() != provisioning.controller_principal()
        || request.authentication().claim().key() != provisioning.controller_request_key_ref()
        || channel.target() != provisioning.target()
        || channel.runtime_peer() != provisioning.runtime_principal()
    {
        return Err(RuntimeControlRequestError::Rejected);
    }
    request
        .validate_expected_store(*snapshot.store_instance_id())
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    let manifest = verify_immutable_manifest_ingress(
        &snapshot.state().host.singleton_manifest.canonical_bytes,
        snapshot.state().host.singleton_manifest.digest,
    )
    .map_err(|_| RuntimeControlRequestError::Rejected)?;
    request
        .validate_manifest(&manifest)
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    request
        .target_execution()
        .validate_compiled_fixture(compiled)
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    Ok(())
}

fn reference_apply_fresh_preflight(
    provisioning: &RuntimeProvisioningV1,
    snapshot: &RuntimeJournalSnapshot,
    clock: RuntimeClock,
    channel: ReferenceChannelBindingV1,
    request: &ReferenceApplyRequestV1,
) -> Result<RuntimeReferenceApplyPreflight, RuntimeControlRequestError> {
    let state = RuntimeControlState::try_from_started_snapshot(snapshot).map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
    })?;
    let bootstrap = state.bootstrap_facts().map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
    })?;
    if bootstrap.readiness() != RuntimeJournalBootstrapState::ReadyForApply {
        return Err(RuntimeControlRequestError::Rejected);
    }
    if !reference_apply_cas_matches(snapshot, request) {
        return Err(RuntimeControlRequestError::Rejected);
    }
    let reading = clock.reading().map_err(|_| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::RuntimeClock)
    })?;
    let verified = provisioning
        .admission_policy()
        .verify_reference_apply_request(request, reading)
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    let identities = verified.identities();
    Ok(RuntimeReferenceApplyPreflight {
        local_target: provisioning.target(),
        owner_target_fingerprint: *snapshot.owner_target_fingerprint(),
        admission_policy_fingerprint: snapshot.state().host.admission_policy_fingerprint,
        channel_policy_fingerprint: snapshot.state().host.channel_policy_fingerprint,
        controller_key_fingerprint: snapshot.state().host.controller_key_fingerprint,
        tenure_nonce_identity: identities.tenure_nonce_identity(),
        request_nonce_identity: identities.request_nonce_identity(),
        temporal_lineage_digest: identities.temporal_lineage_digest(),
        admitted_at_nanos: verified.admitted_at_nanos(),
        response_channel: channel,
    })
}

fn reference_apply_cas_matches(
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceApplyRequestV1,
) -> bool {
    let expected = request.control_commitment().control().expected_active();
    match (expected, snapshot.state().active_desired.as_ref()) {
        (ExpectedActive::None, None) => true,
        (ExpectedActive::Exact(expected), Some(active)) => {
            expected == TargetSliceDigest::new(active.slice.digest)
        }
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceTerminalMatch {
    Absent,
    Exact,
    Conflict,
}

fn reference_terminal_match(
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceApplyRequestV1,
) -> ReferenceTerminalMatch {
    let scope = request.provenance().source_scope();
    let operation = request.control_commitment().control().operation_id();
    let Some(terminal) = snapshot
        .state()
        .terminal_operations
        .iter()
        .find(|terminal| {
            terminal.source_scope == *scope.as_bytes()
                && terminal.operation_id == *operation.as_bytes()
        })
    else {
        return ReferenceTerminalMatch::Absent;
    };
    if terminal.request_digest == request.envelope_request_digest() {
        ReferenceTerminalMatch::Exact
    } else {
        ReferenceTerminalMatch::Conflict
    }
}

fn map_apply_error(error: RuntimeReferenceApplyError) -> RuntimeControlRequestError {
    match error {
        RuntimeReferenceApplyError::OperationConflict
        | RuntimeReferenceApplyError::State(RuntimeControlStateError::PreflightRejected) => {
            RuntimeControlRequestError::Rejected
        }
        other => RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::Apply(other)),
    }
}

#[derive(Debug)]
enum RuntimeControlRequestError {
    Rejected,
    Unavailable,
    Internal(RuntimeBootstrapEndpointError),
}

fn runtime_control_readiness_error(
    error: RuntimeControlRequestError,
) -> RuntimeBootstrapEndpointError {
    match error {
        RuntimeControlRequestError::Internal(error) => error,
        RuntimeControlRequestError::Rejected | RuntimeControlRequestError::Unavailable => {
            RuntimeBootstrapEndpointError::InvalidStartedState
        }
    }
}

/// Display-safe outcome of the restricted remote PXRC processing seam.
///
/// The transport owner distinguishes generic rejection, retryable owner
/// unavailability, and fatal owner failure. No variant carries request,
/// carrier, key, or signature material across the boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeRestrictedRemoteApplyErrorV1 {
    Rejected,
    Unavailable,
    Internal,
}

impl fmt::Display for RuntimeRestrictedRemoteApplyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "restricted Runtime apply rejected",
            Self::Unavailable => "restricted Runtime apply temporarily unavailable",
            Self::Internal => "restricted Runtime apply owner failed",
        })
    }
}

impl std::error::Error for RuntimeRestrictedRemoteApplyErrorV1 {}

pub(crate) struct StartedManagedFabricService {
    core: ManagedFabricRuntimeCore,
    stack: Option<ManagedAgentStackRuntimeCore>,
    stack_projection: ManagedAgentStackProjectionV1,
    model_stack: Option<ManagedModelAgentStackRuntimeCore>,
    model_stack_projection: ManagedModelAgentStackProjectionV1,
    distributed: Option<DistributedAgentStackRuntimeCore>,
    distributed_projection: DistributedAgentStackProjectionV1,
    handle_broker: RuntimeAgentHandleBroker,
    state_directory: PathBuf,
    provisioning: RuntimeProvisioningV1,
    dependencies: RuntimeManagedFabricServiceDependenciesV1,
}

impl StartedManagedFabricService {
    fn try_start(
        state_directory: &Path,
        expected_store_instance_id: [u8; 32],
        compiled: RuntimeCompiledInstallationFactsV1,
        provisioning: RuntimeProvisioningV1,
        dependencies: RuntimeManagedFabricServiceDependenciesV1,
    ) -> Result<Self, RuntimeBootstrapEndpointError> {
        let store = ManagedFabricStore::open_unbound_projection(
            state_directory,
            expected_store_instance_id,
            provisioning.owner_target_fingerprint(),
        )?;
        Self::try_start_from_store(
            state_directory,
            expected_store_instance_id,
            compiled,
            provisioning,
            store,
            dependencies,
        )
    }

    pub(crate) fn try_start_developer_local(
        state_directory: &Path,
        expected_store_instance_id: [u8; 32],
        compiled: RuntimeCompiledInstallationFactsV1,
        provisioning: RuntimeProvisioningV1,
        dependencies: RuntimeManagedFabricServiceDependenciesV1,
    ) -> Result<Self, RuntimeBootstrapEndpointError> {
        if ManagedFabricStore::cutover_present_developer_local(state_directory)? {
            let store = ManagedFabricStore::open_unbound_projection_developer_local(
                state_directory,
                expected_store_instance_id,
                provisioning.owner_target_fingerprint(),
            )?;
            return Self::try_start_from_store(
                state_directory,
                expected_store_instance_id,
                compiled,
                provisioning,
                store,
                dependencies,
            );
        }

        let legacy_store = RuntimeStore::open_developer_local(
            state_directory,
            expected_store_instance_id,
            provisioning.owner_target_fingerprint(),
        )?;
        Self::try_cutover_developer_local_from_store(
            state_directory,
            expected_store_instance_id,
            compiled,
            provisioning,
            legacy_store,
            RuntimeAgentHandleBroker::default(),
            dependencies,
        )
    }

    fn try_cutover_developer_local_from_store(
        state_directory: &Path,
        expected_store_instance_id: [u8; 32],
        compiled: RuntimeCompiledInstallationFactsV1,
        provisioning: RuntimeProvisioningV1,
        legacy_store: RuntimeStore,
        handle_broker: RuntimeAgentHandleBroker,
        dependencies: RuntimeManagedFabricServiceDependenciesV1,
    ) -> Result<Self, RuntimeBootstrapEndpointError> {
        let frozen = legacy_store.snapshot()?.clone();
        let installation = verify_startup_installation(&frozen, provisioning.target(), compiled)?;
        validate_snapshot_pins(&provisioning, &frozen)?;
        let manifest = installation.immutable_manifest_ingress()?;
        validate_startup_durable_control_state(&frozen, &manifest, compiled, &provisioning)?;
        let projection =
            ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(&manifest)?;
        let legacy_host = &frozen.state().host;
        let runtime_host_epoch = legacy_host
            .runtime_host_epoch_high_water
            .max(legacy_host.clock_generation_high_water)
            .checked_add(1)
            .ok_or(RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let generation = ClockGeneration::try_new(runtime_host_epoch)
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let clock = RuntimeClock::new(
            ClockDomainRef::from_bytes(legacy_host.clock_domain),
            generation,
            1,
        );
        let core = ManagedFabricRuntimeCore::cutover_developer_local(
            legacy_store,
            ManagedFabricOwnerConfig {
                state_directory: state_directory.to_path_buf(),
                store_instance_id: expected_store_instance_id,
                owner_target_fingerprint: provisioning.owner_target_fingerprint(),
                projection: projection.clone(),
                runtime_host_epoch,
                clock,
                response_key_ref: provisioning.runtime_response_key_ref(),
                response_signer: provisioning.response_signer().clone(),
            },
        )?;
        let stack_projection =
            ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(projection)?;
        let model_stack_projection =
            ManagedModelAgentStackProjectionV1::try_from_managed_agent_stack_projection(
                stack_projection.clone(),
            )?;
        let distributed_projection =
            DistributedAgentStackProjectionV1::try_from_managed_agent_stack_projection(
                stack_projection.clone(),
            )?;
        Ok(Self {
            core,
            stack: None,
            stack_projection,
            model_stack: None,
            model_stack_projection,
            distributed: None,
            distributed_projection,
            handle_broker,
            state_directory: state_directory.to_path_buf(),
            provisioning,
            dependencies,
        })
    }

    fn try_start_from_store(
        state_directory: &Path,
        expected_store_instance_id: [u8; 32],
        compiled: RuntimeCompiledInstallationFactsV1,
        provisioning: RuntimeProvisioningV1,
        store: ManagedFabricStore,
        dependencies: RuntimeManagedFabricServiceDependenciesV1,
    ) -> Result<Self, RuntimeBootstrapEndpointError> {
        let frozen = store.frozen_legacy_snapshot().clone();
        let installation = verify_startup_installation(&frozen, provisioning.target(), compiled)?;
        validate_snapshot_pins(&provisioning, &frozen)?;
        let manifest = installation.immutable_manifest_ingress()?;
        validate_startup_durable_control_state(&frozen, &manifest, compiled, &provisioning)?;
        let projection =
            ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(&manifest)?;
        let projection_digest =
            transition_projection_digest(&projection).map_err(ManagedFabricRuntimeError::from)?;
        if store.marker().transition_projection_digest() != projection_digest {
            return Err(RuntimeBootstrapEndpointError::ManagedFabric(
                ManagedFabricRuntimeError::ProjectionMismatch,
            ));
        }

        // Production deliberately uses one monotonically increasing value for
        // both the successor RuntimeHost epoch and its process-local clock
        // generation. Taking the maximum of both frozen legacy high-waters and
        // the previous successor epoch prevents either namespace from
        // regressing across the one-way transition or a later restart.
        let previous_successor_epoch = match store.snapshot_bytes()? {
            Some(frame) => ManagedFabricSnapshot::decode(
                frame,
                expected_store_instance_id,
                provisioning.owner_target_fingerprint(),
                projection_digest,
                &projection,
            )?
            .runtime_host_epoch(),
            None => 0,
        };
        let legacy_host = &frozen.state().host;
        let runtime_host_epoch = legacy_host
            .runtime_host_epoch_high_water
            .max(legacy_host.clock_generation_high_water)
            .max(previous_successor_epoch)
            .checked_add(1)
            .ok_or(RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let generation = ClockGeneration::try_new(runtime_host_epoch)
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let clock = RuntimeClock::new(
            ClockDomainRef::from_bytes(legacy_host.clock_domain),
            generation,
            1,
        );
        let core = ManagedFabricRuntimeCore::from_preopened_store(
            store,
            ManagedFabricOwnerConfig {
                state_directory: state_directory.to_path_buf(),
                store_instance_id: expected_store_instance_id,
                owner_target_fingerprint: provisioning.owner_target_fingerprint(),
                projection: projection.clone(),
                runtime_host_epoch,
                clock,
                response_key_ref: provisioning.runtime_response_key_ref(),
                response_signer: provisioning.response_signer().clone(),
            },
        )?;
        let stack_projection =
            ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(projection)?;
        let handle_broker = RuntimeAgentHandleBroker::default();
        let model_stack_projection =
            ManagedModelAgentStackProjectionV1::try_from_managed_agent_stack_projection(
                stack_projection.clone(),
            )?;
        let model_stack = ManagedModelAgentStackRuntimeCore::open(
            &core,
            ManagedModelAgentStackOwnerConfig {
                state_directory: state_directory.to_path_buf(),
                projection: model_stack_projection.clone(),
                runtime_host_epoch,
                clock,
                response_key_ref: provisioning.runtime_response_key_ref(),
                response_signer: provisioning.response_signer().clone(),
                handle_broker: handle_broker.clone(),
                model_backend_resolver: dependencies.model_backend_resolver(),
            },
        )?;
        let stack = ManagedAgentStackRuntimeCore::open(
            &core,
            ManagedAgentStackOwnerConfig {
                state_directory: state_directory.to_path_buf(),
                projection: stack_projection.clone(),
                runtime_host_epoch,
                clock,
                response_key_ref: provisioning.runtime_response_key_ref(),
                response_signer: provisioning.response_signer().clone(),
                handle_broker: handle_broker.clone(),
                provider_resolver: dependencies.agent_provider_resolver(),
            },
        )?;
        let distributed_projection =
            DistributedAgentStackProjectionV1::try_from_managed_agent_stack_projection(
                stack_projection.clone(),
            )?;
        let distributed_dependencies = dependencies.distributed_agent_stack_owner_dependencies();
        let fabric_credential_resolver = distributed_dependencies
            .map(|dependencies| Arc::clone(&dependencies.fabric_credential_resolver));
        let evidence_store_config =
            distributed_dependencies.map(|dependencies| dependencies.evidence_store_config.clone());
        let distributed = DistributedAgentStackRuntimeCore::open(
            &core,
            DistributedAgentStackOwnerConfig {
                state_directory: state_directory.to_path_buf(),
                projection: distributed_projection.clone(),
                runtime_host_epoch,
                clock,
                response_key_ref: provisioning.runtime_response_key_ref(),
                response_signer: provisioning.response_signer().clone(),
                handle_broker: handle_broker.clone(),
                fabric_credential_resolver,
                evidence_store_config,
                agent_provider_resolver: dependencies.agent_provider_resolver(),
            },
        )?;
        if distributed.is_some() && stack.is_none() {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        if model_stack.is_some() && (stack.is_some() || distributed.is_some()) {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        Ok(Self {
            core,
            stack,
            stack_projection,
            model_stack,
            model_stack_projection,
            distributed,
            distributed_projection,
            handle_broker,
            state_directory: state_directory.to_path_buf(),
            provisioning,
            dependencies,
        })
    }
}

pub(crate) struct ManagedFabricControlService {
    core: ManagedFabricRuntimeCore,
    stack: Option<ManagedAgentStackRuntimeCore>,
    stack_projection: ManagedAgentStackProjectionV1,
    model_stack: Option<ManagedModelAgentStackRuntimeCore>,
    model_stack_projection: ManagedModelAgentStackProjectionV1,
    distributed: Option<DistributedAgentStackRuntimeCore>,
    distributed_projection: DistributedAgentStackProjectionV1,
    handle_broker: RuntimeAgentHandleBroker,
    state_directory: PathBuf,
    provisioning: RuntimeProvisioningV1,
    channel: ReferenceChannelBindingV1,
    dependencies: RuntimeManagedFabricServiceDependenciesV1,
}

impl ManagedFabricControlService {
    async fn handle_request(
        &mut self,
        frame: &[u8],
        live_channel: ReferenceChannelBindingV1,
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if live_channel != self.channel || frame.len() < 4 {
            return Err(RuntimeControlRequestError::Rejected);
        }
        if frame.starts_with(MANAGED_BOOTSTRAP_REQUEST_MAGIC) {
            self.handle_serving_bootstrap(frame)
        } else if frame.starts_with(APPLY_REQUEST_MAGIC) {
            self.handle_apply(frame).await
        } else {
            Err(RuntimeControlRequestError::Rejected)
        }
    }

    /// Processes one already transport-bounded canonical PXRC v1 value.
    ///
    /// This seam does not own a listener or TLS configuration. The caller must
    /// supply the exact PXCB selected by its restricted transport generation.
    /// Runtime authenticates that outer value against protected provisioning
    /// before the existing PXAR v8 mutable owner can be reached.
    pub(crate) async fn handle_restricted_distributed_agent_stack_apply_v1(
        &mut self,
        canonical_pxrc: &[u8],
        expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    ) -> Result<Box<[u8]>, RuntimeRestrictedRemoteApplyErrorV1> {
        if canonical_pxrc.is_empty()
            || canonical_pxrc.len() > MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES
        {
            return Err(RuntimeRestrictedRemoteApplyErrorV1::Rejected);
        }
        let restricted = DistributedAgentStackRestrictedApplyRequestV1::decode(canonical_pxrc)
            .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Rejected)?;
        let authenticated = authenticate_restricted_distributed_agent_stack_apply(
            &self.provisioning,
            &restricted,
            expected_carrier,
        )?;

        // The inner bytes remain contract-owned and inaccessible until the
        // concrete pinned-key verifier above issues the authenticated marker.
        // The existing handler remains the sole PXAR v8 mutable owner.
        let terminal_v1_wire = self
            .handle_distributed_agent_stack_apply(authenticated.request().canonical_wire())
            .await
            .map_err(map_restricted_inner_apply_error)?;
        let terminal_facts = validate_restricted_inner_terminal(
            &self.provisioning,
            authenticated,
            self.channel,
            &terminal_v1_wire,
        )?;
        let draft =
            DistributedAgentStackTerminalReceiptDraftV2::try_new(authenticated, terminal_facts)
                .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
        let signature = self
            .provisioning
            .response_signer()
            .sign(
                draft
                    .signing_transcript()
                    .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?
                    .as_bytes(),
            )
            .to_bytes();
        let receipt = draft
            .finalize(&signature)
            .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
        let wire = receipt.canonical_wire();
        if wire.is_empty() || wire.len() > MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES {
            return Err(RuntimeRestrictedRemoteApplyErrorV1::Internal);
        }
        // Non-ready terminals remain reportable but never enter the handle
        // broker. An ActiveReady outer receipt is not returned unless its
        // exact inner PXDS1 is still the currently published capability root.
        if receipt.facts().outcome() == DistributedAgentStackTerminalOutcomeV1::ActiveReady {
            self.handle_broker
                .register_restricted_distributed_alias(&terminal_v1_wire, wire)
                .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
        }
        Ok(wire.into())
    }

    /// Dispatches the additive PXAG carrier on the same restricted Runtime
    /// control listener as frozen PXCC v1. Unknown magic is interpreted only
    /// by the strict PXCC decoder and therefore fails closed.
    async fn handle_restricted_runtime_control_frame_v1(
        &mut self,
        canonical_request: &[u8],
        expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if canonical_request.starts_with(RUNTIME_AGENT_CONTROL_REQUEST_MAGIC) {
            let request = decode_runtime_agent_control_request(canonical_request)?;
            let authenticated = authenticate_runtime_agent_control_request(
                &self.provisioning,
                &request,
                expected_carrier,
            )?;
            self.handle_authenticated_runtime_agent_control_request_v1(authenticated)
                .await
        } else {
            let request = decode_runtime_control_carrier(canonical_request)?;
            let authenticated = authenticate_runtime_control_carrier(
                &self.provisioning,
                &request,
                expected_carrier,
            )?;
            self.handle_authenticated_runtime_control_carrier_v1(authenticated)
                .await
        }
    }

    /// The only mutable PXAG seam. Its type makes outer PXCB/Controller
    /// authentication a precondition; inner PXAR admission remains owned by
    /// the existing v6/v7 handlers below.
    async fn handle_authenticated_runtime_agent_control_request_v1(
        &mut self,
        authenticated: ControllerAuthenticatedRuntimeAgentControlRequestV1<'_>,
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        let request = authenticated.request();
        if request.target() != self.provisioning.target()
            || request.expected_runtime_store_instance_id() != self.core.store_instance_id()
            || request.expected_runtime_host_epoch() != self.core.runtime_host_epoch()
        {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let auth_claim =
            runtime_agent_control_response_auth(&self.provisioning, request.carrier())?;
        let draft = match authenticated.kind() {
            RuntimeAgentControlKindV1::ApplyManagedFabric => {
                let inner = request
                    .managed_fabric_apply_request()
                    .ok_or(RuntimeControlRequestError::Rejected)?;
                let terminal_wire = self.handle_apply(inner.canonical_wire()).await?;
                let terminal = ManagedFabricApplyTerminalReceiptV1::decode(&terminal_wire)
                    .map_err(|error| {
                        RuntimeControlRequestError::Internal(
                            RuntimeBootstrapEndpointError::ManagedFabricContract(error),
                        )
                    })?;
                RuntimeAgentControlReceiptDraftV1::try_managed_fabric_apply(
                    authenticated,
                    terminal,
                    self.channel,
                    auth_claim,
                )
            }
            RuntimeAgentControlKindV1::ApplyManagedAgentStack => {
                let inner = request
                    .managed_agent_stack_apply_request()
                    .ok_or(RuntimeControlRequestError::Rejected)?;
                let terminal_wire = self.handle_apply(inner.canonical_wire()).await?;
                let terminal = ManagedAgentStackTerminalReceiptV1::decode(&terminal_wire).map_err(
                    |error| {
                        RuntimeControlRequestError::Internal(
                            RuntimeBootstrapEndpointError::ManagedAgentStackContract(error),
                        )
                    },
                )?;
                RuntimeAgentControlReceiptDraftV1::try_managed_agent_stack_apply(
                    authenticated,
                    terminal,
                    self.channel,
                    auth_claim,
                )
            }
            RuntimeAgentControlKindV1::DescribeConversationPort => {
                let exported = self
                    .stack
                    .as_ref()
                    .ok_or(RuntimeControlRequestError::Unavailable)?
                    .export_active_conversation_port_v1(request.expected_active_pxst_digest())
                    .await
                    .map_err(map_runtime_agent_port_export_error)?;
                RuntimeAgentControlReceiptDraftV1::try_conversation_port_descriptor(
                    authenticated,
                    &exported.descriptor_wire,
                    exported.fabric_generation,
                    exported.agent_generation,
                    auth_claim,
                )
            }
        }
        .map_err(|error| {
            RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::ManagedServingContract(error),
            )
        })?;
        runtime_agent_control_receipt_response(&self.provisioning, draft)
    }

    async fn handle_authenticated_runtime_control_carrier_v1(
        &mut self,
        authenticated: ControllerAuthenticatedRuntimeControlCarrierV1<'_>,
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        match authenticated.kind() {
            RuntimeControlCarrierKindV1::Describe => {
                let facts = self.runtime_control_describe_facts()?;
                runtime_control_describe_response(&self.provisioning, authenticated, facts)
            }
            RuntimeControlCarrierKindV1::ManagedServingBootstrap => {
                let request = authenticated
                    .managed_serving_bootstrap_request()
                    .ok_or(RuntimeControlRequestError::Rejected)?;
                self.handle_request(request.canonical_wire(), self.channel)
                    .await
            }
            RuntimeControlCarrierKindV1::ReferenceQuery => {
                // PXQR describes the frozen predecessor journal and never
                // acquires a successor interpretation or fallback.
                Err(RuntimeControlRequestError::Rejected)
            }
        }
    }

    fn runtime_control_describe_facts(
        &self,
    ) -> Result<RuntimeControlDescribeReadyFactsV1, RuntimeControlRequestError> {
        let observed = self
            .core
            .recovered_observation()
            .map_err(map_managed_fabric_error)?;
        let serving = ManagedServingBootstrapFactsV1::try_recovered_ready(
            observed.target,
            observed.store_instance_id,
            observed.projection,
            observed.runtime_host_epoch,
            observed.successor_snapshot_sequence,
            observed.clock,
        )
        .map_err(|error| {
            RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::ManagedServingContract(error),
            )
        })?;
        RuntimeControlDescribeReadyFactsV1::try_new(
            RuntimeControlDescribeReadyPhaseV1::ManagedReady,
            serving,
            self.channel,
        )
        .map_err(|error| {
            RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::ManagedServingContract(error),
            )
        })
    }

    fn handle_serving_bootstrap(
        &self,
        frame: &[u8],
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if self.stack.is_some()
            || self.model_stack.is_some()
            || self.distributed.is_some()
            || frame.is_empty()
            || frame.len() > MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES
        {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = ManagedServingBootstrapRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        authenticate_managed_serving_request(&self.provisioning, &request, self.channel)?;
        let observed = self
            .core
            .recovered_observation()
            .map_err(map_managed_fabric_error)?;
        if request.target() != observed.target
            || request.expected_runtime_store_instance_id() != observed.store_instance_id
            || request.projection() != &observed.projection
            || request.channel() != self.channel
            || transition_projection_digest(request.projection())
                .map_err(ManagedFabricRuntimeError::from)
                .map_err(map_managed_fabric_error)?
                != observed.transition_projection_digest
        {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let facts = ManagedServingBootstrapFactsV1::try_recovered_ready(
            observed.target,
            observed.store_instance_id,
            observed.projection,
            observed.runtime_host_epoch,
            observed.successor_snapshot_sequence,
            observed.clock,
        )
        .map_err(|error| {
            RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::ManagedServingContract(error),
            )
        })?;
        let algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM).map_err(|_| {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidStartedState)
        })?;
        let auth_claim = ManagedServingBootstrapResponseAuthClaimV1::try_new(
            self.channel,
            self.provisioning.runtime_response_key_ref(),
            algorithm,
            ED25519_ALGORITHM_VERSION,
        )
        .map_err(|error| {
            RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::ManagedServingContract(error),
            )
        })?;
        let draft = ManagedServingBootstrapResponseDraftV1::try_new(
            &request,
            facts,
            self.channel,
            auth_claim,
        )
        .map_err(|error| {
            RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::ManagedServingContract(error),
            )
        })?;
        let signature = self
            .provisioning
            .response_signer()
            .sign(
                draft
                    .signing_transcript()
                    .map_err(|error| {
                        RuntimeControlRequestError::Internal(
                            RuntimeBootstrapEndpointError::ManagedServingContract(error),
                        )
                    })?
                    .as_bytes(),
            )
            .to_bytes();
        let response = draft.finalize(&signature).map_err(|error| {
            RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::ManagedServingContract(error),
            )
        })?;
        let wire = response.canonical_wire();
        if wire.is_empty() || wire.len() > MAX_MANAGED_SERVING_BOOTSTRAP_RESPONSE_BYTES {
            return Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::InvalidStartedState,
            ));
        }
        Ok(wire.into())
    }

    async fn handle_apply(
        &mut self,
        frame: &[u8],
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if frame.len() < 6 {
            return Err(RuntimeControlRequestError::Rejected);
        }
        match u16::from_be_bytes([frame[4], frame[5]]) {
            MANAGED_FABRIC_APPLY_REQUEST_VERSION
                if self.stack.is_none()
                    && self.model_stack.is_none()
                    && self.distributed.is_none() =>
            {
                self.handle_managed_fabric_apply(frame).await
            }
            MANAGED_AGENT_STACK_APPLY_REQUEST_VERSION
                if self.model_stack.is_none() && self.distributed.is_none() =>
            {
                self.handle_managed_agent_stack_apply(frame).await
            }
            MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION
                if self.stack.is_none() && self.distributed.is_none() =>
            {
                self.handle_managed_model_agent_stack_apply(frame).await
            }
            DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_VERSION if self.model_stack.is_none() => {
                self.handle_distributed_agent_stack_apply(frame).await
            }
            _ => Err(RuntimeControlRequestError::Rejected),
        }
    }

    async fn handle_managed_fabric_apply(
        &mut self,
        frame: &[u8],
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if frame.len() > MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = ManagedFabricApplyRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;

        // Exact terminal replay authenticates signatures and local pins but
        // intentionally does not re-admit the old temporal generation.
        self.provisioning
            .admission_policy()
            .authenticate_managed_fabric_apply_request(&request)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        match self
            .core
            .authenticated_terminal_replay(&request, self.channel)
        {
            Ok(Some(receipt)) => return managed_terminal_response_wire(&receipt),
            Ok(None) => {}
            Err(error) => return Err(map_managed_fabric_error(error)),
        }

        let reading = self
            .core
            .clock_reading()
            .map_err(map_managed_fabric_error)?;
        let verified = self
            .provisioning
            .admission_policy()
            .verify_managed_fabric_apply_request(&request, reading)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        let outcome = self
            .core
            .apply(request, verified, self.channel)
            .await
            .map_err(map_managed_fabric_error)?;
        match outcome {
            ManagedFabricApplyOutcome::Committed(receipt)
            | ManagedFabricApplyOutcome::Replayed(receipt) => {
                managed_terminal_response_wire(&receipt)
            }
        }
    }

    async fn handle_managed_agent_stack_apply(
        &mut self,
        frame: &[u8],
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if frame.len() > MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = ManagedAgentStackApplyRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        self.provisioning
            .admission_policy()
            .authenticate_managed_agent_stack_apply_request(&request)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        if let Some(stack) = self.stack.as_ref() {
            match stack.authenticated_terminal_replay(&request, self.channel) {
                Ok(Some(receipt)) => return managed_agent_stack_terminal_response_wire(&receipt),
                Ok(None) => {}
                Err(error) => return Err(map_managed_agent_stack_error(error)),
            }
        }
        let reading = self
            .core
            .clock_reading()
            .map_err(map_managed_fabric_error)?;
        let verified = self
            .provisioning
            .admission_policy()
            .verify_managed_agent_stack_apply_request(&request, reading)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        let outcome = match self.stack.as_mut() {
            Some(stack) => stack
                .apply(&mut self.core, request, verified, self.channel)
                .await
                .map_err(map_managed_agent_stack_error)?,
            None => {
                let runtime_host_epoch = self.core.runtime_host_epoch();
                let clock = self.core.stack_clock();
                let (stack, outcome) = ManagedAgentStackRuntimeCore::cutover(
                    &mut self.core,
                    ManagedAgentStackOwnerConfig {
                        state_directory: self.state_directory.clone(),
                        projection: self.stack_projection.clone(),
                        runtime_host_epoch,
                        clock,
                        response_key_ref: self.provisioning.runtime_response_key_ref(),
                        response_signer: self.provisioning.response_signer().clone(),
                        handle_broker: self.handle_broker.clone(),
                        provider_resolver: self.dependencies.agent_provider_resolver(),
                    },
                    request,
                    verified,
                    self.channel,
                )
                .await
                .map_err(map_managed_agent_stack_error)?;
                self.stack = Some(stack);
                outcome
            }
        };
        match outcome {
            ManagedAgentStackApplyOutcome::Committed(receipt)
            | ManagedAgentStackApplyOutcome::Replayed(receipt) => {
                managed_agent_stack_terminal_response_wire(&receipt)
            }
        }
    }

    async fn handle_managed_model_agent_stack_apply(
        &mut self,
        frame: &[u8],
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if frame.len() > MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = ManagedModelAgentStackApplyRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        self.provisioning
            .admission_policy()
            .authenticate_managed_model_agent_stack_apply_request(&request)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        if let Some(model_stack) = self.model_stack.as_ref() {
            match model_stack.authenticated_terminal_replay(&request, self.channel) {
                Ok(Some(receipt)) => {
                    return managed_model_agent_stack_terminal_response_wire(&receipt);
                }
                Ok(None) => {}
                Err(error) => return Err(map_managed_model_agent_stack_error(error)),
            }
        }
        let reading = self
            .core
            .clock_reading()
            .map_err(map_managed_fabric_error)?;
        let verified = self
            .provisioning
            .admission_policy()
            .verify_managed_model_agent_stack_apply_request(&request, reading)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        let outcome = match self.model_stack.as_mut() {
            Some(model_stack) => model_stack
                .apply(&mut self.core, request, verified, self.channel)
                .await
                .map_err(map_managed_model_agent_stack_error)?,
            None => {
                let runtime_host_epoch = self.core.runtime_host_epoch();
                let clock = self.core.stack_clock();
                let cutover = ManagedModelAgentStackRuntimeCore::cutover(
                    &mut self.core,
                    ManagedModelAgentStackOwnerConfig {
                        state_directory: self.state_directory.clone(),
                        projection: self.model_stack_projection.clone(),
                        runtime_host_epoch,
                        clock,
                        response_key_ref: self.provisioning.runtime_response_key_ref(),
                        response_signer: self.provisioning.response_signer().clone(),
                        handle_broker: self.handle_broker.clone(),
                        model_backend_resolver: self.dependencies.model_backend_resolver(),
                    },
                    request,
                    verified,
                    self.channel,
                )
                .await
                .map_err(map_managed_model_agent_stack_error)?;
                match cutover {
                    ManagedModelAgentStackCutoverOutcome::NoEffect(receipt) => {
                        return managed_model_agent_stack_terminal_response_wire(&receipt);
                    }
                    ManagedModelAgentStackCutoverOutcome::Installed(model_stack, outcome) => {
                        self.model_stack = Some(*model_stack);
                        outcome
                    }
                }
            }
        };
        match outcome {
            ManagedModelAgentStackApplyOutcome::Committed(receipt)
            | ManagedModelAgentStackApplyOutcome::Replayed(receipt) => {
                managed_model_agent_stack_terminal_response_wire(&receipt)
            }
        }
    }

    async fn handle_distributed_agent_stack_apply(
        &mut self,
        frame: &[u8],
    ) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if frame.len() > MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = DistributedAgentStackApplyRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        self.provisioning
            .admission_policy()
            .authenticate_distributed_agent_stack_apply_request(&request)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        if let Some(distributed) = self.distributed.as_mut() {
            match distributed.authenticated_terminal_replay(&self.core, &request, self.channel) {
                Ok(Some(receipt)) => {
                    return distributed_agent_stack_terminal_response_wire(&receipt);
                }
                Ok(None) => {}
                Err(error) => return Err(map_distributed_agent_stack_error(error)),
            }
        }
        let reading = self
            .core
            .clock_reading()
            .map_err(map_managed_fabric_error)?;
        let verified = self
            .provisioning
            .admission_policy()
            .verify_distributed_agent_stack_apply_request(&request, reading)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        let outcome = match self.distributed.as_mut() {
            Some(distributed) => distributed
                .apply(&mut self.core, request, verified, self.channel)
                .await
                .map_err(map_distributed_agent_stack_error)?,
            None => {
                let distributed_dependencies = self
                    .dependencies
                    .distributed_agent_stack_owner_dependencies();
                let fabric_credential_resolver = distributed_dependencies
                    .map(|dependencies| Arc::clone(&dependencies.fabric_credential_resolver));
                let evidence_store_config = distributed_dependencies
                    .map(|dependencies| dependencies.evidence_store_config.clone());
                let predecessor = self
                    .stack
                    .as_mut()
                    .ok_or(RuntimeControlRequestError::Rejected)?;
                let runtime_host_epoch = self.core.runtime_host_epoch();
                let clock = self.core.stack_clock();
                let (distributed, outcome) = DistributedAgentStackRuntimeCore::cutover(
                    &mut self.core,
                    predecessor,
                    DistributedAgentStackOwnerConfig {
                        state_directory: self.state_directory.clone(),
                        projection: self.distributed_projection.clone(),
                        runtime_host_epoch,
                        clock,
                        response_key_ref: self.provisioning.runtime_response_key_ref(),
                        response_signer: self.provisioning.response_signer().clone(),
                        handle_broker: self.handle_broker.clone(),
                        fabric_credential_resolver,
                        evidence_store_config,
                        agent_provider_resolver: self.dependencies.agent_provider_resolver(),
                    },
                    request,
                    verified,
                    self.channel,
                )
                .await
                .map_err(map_distributed_agent_stack_error)?;
                self.distributed = Some(distributed);
                outcome
            }
        };
        distributed_agent_stack_apply_response_wire(outcome)
    }
}

pub(crate) fn validate_restricted_runtime_apply_carrier_pins(
    provisioning: &RuntimeProvisioningV1,
    expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<Digest32, RuntimeRestrictedRemoteApplyErrorV1> {
    provisioning
        .validate_runtime_credentials()
        .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
    let controller_key_fingerprint =
        ed25519_control_key_fingerprint(provisioning.controller_key().as_bytes())
            .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
    let runtime_response_key_fingerprint =
        ed25519_control_key_fingerprint(provisioning.response_signer().verifying_key().as_bytes())
            .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
    if controller_key_fingerprint != provisioning.controller_key_fingerprint() {
        return Err(RuntimeRestrictedRemoteApplyErrorV1::Internal);
    }
    if expected_carrier.target() != provisioning.target()
        || expected_carrier.runtime_principal() != provisioning.runtime_principal()
        || expected_carrier.controller_principal() != provisioning.controller_principal()
        || expected_carrier.controller_request_key() != provisioning.controller_request_key_ref()
        || expected_carrier.controller_request_key_fingerprint() != controller_key_fingerprint
        || expected_carrier.runtime_response_key() != provisioning.runtime_response_key_ref()
        || expected_carrier.runtime_response_key_fingerprint() != runtime_response_key_fingerprint
    {
        return Err(RuntimeRestrictedRemoteApplyErrorV1::Rejected);
    }
    Ok(controller_key_fingerprint)
}

fn authenticate_restricted_distributed_agent_stack_apply<'a>(
    provisioning: &RuntimeProvisioningV1,
    restricted: &'a DistributedAgentStackRestrictedApplyRequestV1,
    expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<
    ControllerAuthenticatedDistributedAgentStackApplyRequestV1<'a>,
    RuntimeRestrictedRemoteApplyErrorV1,
> {
    let controller_key_fingerprint =
        validate_restricted_runtime_apply_carrier_pins(provisioning, expected_carrier)?;

    restricted
        .verify_controller_carrier_before_mutation(
            expected_carrier,
            |principal, key, fingerprint, transcript, signature| {
                if principal != provisioning.controller_principal()
                    || key != provisioning.controller_request_key_ref()
                    || fingerprint != controller_key_fingerprint
                {
                    return false;
                }
                let Ok(signature) = Signature::from_slice(signature) else {
                    return false;
                };
                provisioning
                    .controller_key()
                    .verify_strict(transcript, &signature)
                    .is_ok()
            },
        )
        .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Rejected)
}

fn authenticate_runtime_control_carrier<'a>(
    provisioning: &RuntimeProvisioningV1,
    request: &'a RuntimeControlCarrierRequestV1,
    expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<ControllerAuthenticatedRuntimeControlCarrierV1<'a>, RuntimeControlRequestError> {
    let controller_key_fingerprint = validate_restricted_runtime_apply_carrier_pins(
        provisioning,
        expected_carrier,
    )
    .map_err(|error| match error {
        RuntimeRestrictedRemoteApplyErrorV1::Rejected
        | RuntimeRestrictedRemoteApplyErrorV1::Unavailable => RuntimeControlRequestError::Rejected,
        RuntimeRestrictedRemoteApplyErrorV1::Internal => {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidProvisioning)
        }
    })?;
    let claim = request.authentication().claim();
    if claim.principal() != provisioning.controller_principal()
        || claim.key() != provisioning.controller_request_key_ref()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(RuntimeControlRequestError::Rejected);
    }
    request
        .verify_controller_carrier(
            expected_carrier,
            |principal, key, fingerprint, transcript, signature| {
                if principal != provisioning.controller_principal()
                    || key != provisioning.controller_request_key_ref()
                    || fingerprint != controller_key_fingerprint
                {
                    return false;
                }
                let Ok(signature) = Signature::from_slice(signature) else {
                    return false;
                };
                provisioning
                    .controller_key()
                    .verify_strict(transcript, &signature)
                    .is_ok()
            },
        )
        .map_err(|_| RuntimeControlRequestError::Rejected)
}

fn authenticate_runtime_agent_control_request<'a>(
    provisioning: &RuntimeProvisioningV1,
    request: &'a RuntimeAgentControlRequestV1,
    expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<ControllerAuthenticatedRuntimeAgentControlRequestV1<'a>, RuntimeControlRequestError> {
    let controller_key_fingerprint = validate_restricted_runtime_apply_carrier_pins(
        provisioning,
        expected_carrier,
    )
    .map_err(|error| match error {
        RuntimeRestrictedRemoteApplyErrorV1::Rejected
        | RuntimeRestrictedRemoteApplyErrorV1::Unavailable => RuntimeControlRequestError::Rejected,
        RuntimeRestrictedRemoteApplyErrorV1::Internal => {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidProvisioning)
        }
    })?;
    let claim = request.authentication().claim();
    if claim.principal() != provisioning.controller_principal()
        || claim.key() != provisioning.controller_request_key_ref()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
        || request.authentication().signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(RuntimeControlRequestError::Rejected);
    }
    request
        .verify_controller_request(
            expected_carrier,
            |principal, key, fingerprint, transcript, signature| {
                if principal != provisioning.controller_principal()
                    || key != provisioning.controller_request_key_ref()
                    || fingerprint != controller_key_fingerprint
                    || signature.len() != ED25519_SIGNATURE_BYTES
                {
                    return false;
                }
                let Ok(signature) = Signature::from_slice(signature) else {
                    return false;
                };
                provisioning
                    .controller_key()
                    .verify_strict(transcript, &signature)
                    .is_ok()
            },
        )
        .map_err(|_| RuntimeControlRequestError::Rejected)
}

fn decode_runtime_control_carrier(
    canonical_pxcc: &[u8],
) -> Result<RuntimeControlCarrierRequestV1, RuntimeControlRequestError> {
    if canonical_pxcc.is_empty() || canonical_pxcc.len() > MAX_RUNTIME_CONTROL_CARRIER_REQUEST_BYTES
    {
        return Err(RuntimeControlRequestError::Rejected);
    }
    RuntimeControlCarrierRequestV1::decode(canonical_pxcc)
        .map_err(|_| RuntimeControlRequestError::Rejected)
}

fn decode_runtime_agent_control_request(
    canonical_pxag: &[u8],
) -> Result<RuntimeAgentControlRequestV1, RuntimeControlRequestError> {
    if canonical_pxag.is_empty() || canonical_pxag.len() > MAX_RUNTIME_AGENT_CONTROL_REQUEST_BYTES {
        return Err(RuntimeControlRequestError::Rejected);
    }
    RuntimeAgentControlRequestV1::decode(canonical_pxag)
        .map_err(|_| RuntimeControlRequestError::Rejected)
}

fn runtime_agent_control_response_auth(
    provisioning: &RuntimeProvisioningV1,
    carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<RuntimeAgentControlResponseAuthClaimV1, RuntimeControlRequestError> {
    let algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM).map_err(|_| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidStartedState)
    })?;
    RuntimeAgentControlResponseAuthClaimV1::try_new(
        carrier,
        provisioning.runtime_response_key_ref(),
        algorithm,
        ED25519_ALGORITHM_VERSION,
    )
    .map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedServingContract(
            error,
        ))
    })
}

fn runtime_agent_control_receipt_response(
    provisioning: &RuntimeProvisioningV1,
    draft: RuntimeAgentControlReceiptDraftV1,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let signature = provisioning
        .response_signer()
        .sign(
            draft
                .signing_transcript()
                .map_err(|error| {
                    RuntimeControlRequestError::Internal(
                        RuntimeBootstrapEndpointError::ManagedServingContract(error),
                    )
                })?
                .as_bytes(),
        )
        .to_bytes();
    let receipt = draft.finalize(&signature).map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedServingContract(
            error,
        ))
    })?;
    let wire = receipt.canonical_wire();
    if wire.is_empty() || wire.len() > MAX_RUNTIME_AGENT_CONTROL_RECEIPT_BYTES {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    Ok(wire.into())
}

fn runtime_control_describe_response(
    provisioning: &RuntimeProvisioningV1,
    authenticated: ControllerAuthenticatedRuntimeControlCarrierV1<'_>,
    facts: RuntimeControlDescribeReadyFactsV1,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM).map_err(|_| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidStartedState)
    })?;
    let auth_claim = ManagedServingBootstrapResponseAuthClaimV1::try_new(
        facts.channel(),
        provisioning.runtime_response_key_ref(),
        algorithm,
        ED25519_ALGORITHM_VERSION,
    )
    .map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedServingContract(
            error,
        ))
    })?;
    let draft = RuntimeControlDescribeReadyResponseDraftV1::try_new(
        authenticated.request(),
        facts,
        auth_claim,
    )
    .map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedServingContract(
            error,
        ))
    })?;
    let signature = provisioning
        .response_signer()
        .sign(
            draft
                .signing_transcript()
                .map_err(|error| {
                    RuntimeControlRequestError::Internal(
                        RuntimeBootstrapEndpointError::ManagedServingContract(error),
                    )
                })?
                .as_bytes(),
        )
        .to_bytes();
    let response = draft.finalize(&signature).map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedServingContract(
            error,
        ))
    })?;
    let wire = response.canonical_wire();
    if wire.is_empty() || wire.len() > MAX_RUNTIME_CONTROL_DESCRIBE_READY_RESPONSE_BYTES {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    Ok(wire.into())
}

fn legacy_runtime_control_describe_facts<Store, Owner>(
    legacy: &RuntimeControlService<Store, Owner>,
    live_channel: ReferenceChannelBindingV1,
) -> Result<RuntimeControlDescribeReadyFactsV1, RuntimeControlRequestError>
where
    Store: RuntimeReferenceApplyStore,
    Owner: RuntimeReferenceMaterializationOwner,
{
    if live_channel != legacy.channel {
        return Err(RuntimeControlRequestError::Rejected);
    }
    let snapshot = legacy.apply.snapshot();
    validate_snapshot_pins(&legacy.provisioning, snapshot)
        .map_err(RuntimeControlRequestError::Internal)?;
    let state = RuntimeControlState::try_from_started_snapshot(snapshot).map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
    })?;
    let journal = state.bootstrap_facts().map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
    })?;
    let installation =
        verify_startup_installation(snapshot, legacy.provisioning.target(), legacy.compiled)
            .map_err(RuntimeControlRequestError::Internal)?;
    let manifest = installation.immutable_manifest_ingress().map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::Installation(error))
    })?;
    validate_startup_durable_control_state(
        snapshot,
        &manifest,
        legacy.compiled,
        &legacy.provisioning,
    )
    .map_err(RuntimeControlRequestError::Internal)?;
    let projection = ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(
        &manifest,
    )
    .map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedFabricContract(
            error,
        ))
    })?;
    let serving = ManagedServingBootstrapFactsV1::try_recovered_ready(
        legacy.provisioning.target(),
        journal.store_instance_id(),
        projection,
        journal.runtime_host_epoch(),
        journal.snapshot_sequence(),
        legacy.clock.reading().map_err(|_| {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::RuntimeClock)
        })?,
    )
    .map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedServingContract(
            error,
        ))
    })?;
    RuntimeControlDescribeReadyFactsV1::try_new(
        RuntimeControlDescribeReadyPhaseV1::LegacyReady,
        serving,
        live_channel,
    )
    .map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedServingContract(
            error,
        ))
    })
}

fn validate_restricted_inner_terminal(
    provisioning: &RuntimeProvisioningV1,
    authenticated: ControllerAuthenticatedDistributedAgentStackApplyRequestV1<'_>,
    channel: ReferenceChannelBindingV1,
    terminal_wire: &[u8],
) -> Result<DistributedAgentStackTerminalFactsV1, RuntimeRestrictedRemoteApplyErrorV1> {
    let receipt = DistributedAgentStackTerminalReceiptV1::decode(terminal_wire)
        .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
    let facts = receipt
        .validate_against_request(authenticated.request(), channel)
        .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
    if channel.target() != provisioning.target()
        || channel.runtime_peer() != provisioning.runtime_principal()
        || receipt.authentication_key() != provisioning.runtime_response_key_ref()
        || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
        || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(RuntimeRestrictedRemoteApplyErrorV1::Internal);
    }
    let signature_bytes: &[u8; ED25519_SIGNATURE_BYTES] = receipt
        .authentication_signature()
        .try_into()
        .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
    let signature = Signature::from_bytes(signature_bytes);
    let transcript = receipt
        .signing_transcript()
        .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
    provisioning
        .response_signer()
        .verifying_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| RuntimeRestrictedRemoteApplyErrorV1::Internal)?;
    Ok(facts.clone())
}

fn map_restricted_inner_apply_error(
    error: RuntimeControlRequestError,
) -> RuntimeRestrictedRemoteApplyErrorV1 {
    match error {
        RuntimeControlRequestError::Rejected => RuntimeRestrictedRemoteApplyErrorV1::Rejected,
        RuntimeControlRequestError::Unavailable => RuntimeRestrictedRemoteApplyErrorV1::Unavailable,
        RuntimeControlRequestError::Internal(_) => RuntimeRestrictedRemoteApplyErrorV1::Internal,
    }
}

fn authenticate_managed_serving_request(
    provisioning: &RuntimeProvisioningV1,
    request: &ManagedServingBootstrapRequestV1,
    channel: ReferenceChannelBindingV1,
) -> Result<(), RuntimeControlRequestError> {
    let claim = request.authentication().claim();
    if request.target() != provisioning.target()
        || request.source_scope() != provisioning.source_scope()
        || request.channel() != channel
        || channel.target() != provisioning.target()
        || channel.runtime_peer() != provisioning.runtime_principal()
        || claim.principal() != provisioning.controller_principal()
        || claim.key() != provisioning.controller_request_key_ref()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
        || claim.nonce().iter().all(|byte| *byte == 0)
    {
        return Err(RuntimeControlRequestError::Rejected);
    }
    let bytes: &[u8; ED25519_SIGNATURE_BYTES] = request
        .authentication()
        .signature()
        .try_into()
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    let signature = Signature::from_bytes(bytes);
    let transcript = request
        .signing_transcript()
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    provisioning
        .controller_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| RuntimeControlRequestError::Rejected)
}

fn managed_terminal_response_wire(
    receipt: &paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyTerminalReceiptV1,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let wire = receipt.canonical_wire();
    if wire.is_empty() || wire.len() > MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    Ok(wire.into())
}

fn managed_agent_stack_terminal_response_wire(
    receipt: &paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackTerminalReceiptV1,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let wire = receipt.canonical_wire();
    if wire.is_empty() || wire.len() > MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    Ok(wire.into())
}

fn managed_model_agent_stack_terminal_response_wire(
    receipt: &paraegox_runtime_contracts::managed_model_agent_stack_plan::ManagedModelAgentStackTerminalReceiptV1,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let wire = receipt.canonical_wire();
    if wire.is_empty() || wire.len() > MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    Ok(wire.into())
}

fn distributed_agent_stack_terminal_response_wire(
    receipt: &paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackTerminalReceiptV1,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let wire = receipt.canonical_wire();
    if wire.is_empty() || wire.len() > MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    Ok(wire.into())
}

fn distributed_agent_stack_apply_response_wire(
    outcome: DistributedAgentStackApplyOutcome,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    match outcome {
        DistributedAgentStackApplyOutcome::Committed(receipt)
        | DistributedAgentStackApplyOutcome::Replayed(receipt) => {
            distributed_agent_stack_terminal_response_wire(&receipt)
        }
        DistributedAgentStackApplyOutcome::CommittedHandleUnavailable(_) => {
            // The caller retains the durable Ready owner before classifying
            // this outcome. Do not encode terminal success; an exact
            // authenticated replay owns the bounded publication retry.
            Err(RuntimeControlRequestError::Unavailable)
        }
        DistributedAgentStackApplyOutcome::CommittedOwnerRestartRequired => {
            // The cutover owner is durable and must remain installed for
            // ordered shutdown, but it cannot serve another request in this
            // process. Exit the service loop so restart recovery owns it.
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::DistributedAgentStackRestartRequired,
            ))
        }
    }
}

fn map_managed_fabric_error(error: ManagedFabricRuntimeError) -> RuntimeControlRequestError {
    if error.is_request_rejection() {
        RuntimeControlRequestError::Rejected
    } else {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedFabric(error))
    }
}

fn map_managed_agent_stack_error(
    error: ManagedAgentStackRuntimeError,
) -> RuntimeControlRequestError {
    if error.is_request_rejection() {
        RuntimeControlRequestError::Rejected
    } else {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedAgentStack(
            error,
        ))
    }
}

fn map_runtime_agent_port_export_error(
    error: RuntimeAgentConversationPortExportErrorV1,
) -> RuntimeControlRequestError {
    match error {
        RuntimeAgentConversationPortExportErrorV1::ExpectedActiveReceiptMismatch => {
            RuntimeControlRequestError::Rejected
        }
        RuntimeAgentConversationPortExportErrorV1::OwnerUnavailable => {
            RuntimeControlRequestError::Unavailable
        }
        RuntimeAgentConversationPortExportErrorV1::InternalInvariant => {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedAgentStack(
                ManagedAgentStackRuntimeError::InvalidDurableState,
            ))
        }
    }
}

fn map_managed_model_agent_stack_error(
    error: ManagedModelAgentStackRuntimeError,
) -> RuntimeControlRequestError {
    if error.is_request_rejection() {
        RuntimeControlRequestError::Rejected
    } else {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedModelAgentStack(
            error,
        ))
    }
}

fn map_distributed_agent_stack_error(
    error: DistributedAgentStackRuntimeError,
) -> RuntimeControlRequestError {
    if matches!(
        &error,
        DistributedAgentStackRuntimeError::HandlePublicationPending
    ) {
        RuntimeControlRequestError::Unavailable
    } else if error.is_request_rejection() {
        RuntimeControlRequestError::Rejected
    } else {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::DistributedAgentStack(
            error,
        ))
    }
}

impl<Store> StartedRuntimeBootstrapService<Store>
where
    Store: RuntimeBootstrapStore + RuntimeReferenceApplyStore,
{
    fn into_control_service(
        self,
        channel: ReferenceChannelBindingV1,
    ) -> Result<RuntimeControlService<Store>, RuntimeBootstrapEndpointError> {
        let clock = self.clock;
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            self.store,
            RuntimeEndpointApplyClock { clock },
            self.owner,
            self.signer,
            channel,
        )
        .map_err(RuntimeBootstrapEndpointError::Apply)?;
        Ok(RuntimeControlService {
            apply,
            clock,
            compiled: self.compiled,
            compatibility: self.compatibility,
            provisioning: self.provisioning,
            channel,
        })
    }
}

/// Runs the production Runtime bootstrap process from an already provisioned
/// store identity and sealed key/peer policy.
///
/// Store open, strict pinned-build validation and the durable startup
/// invalidation commit all complete before the socket path can be created.
pub(crate) fn run_runtime_bootstrap_process(
    state_directory: &Path,
    expected_store_instance_id: [u8; 32],
    compiled: RuntimeCompiledInstallationFactsV1,
    provisioning: RuntimeProvisioningV1,
    dependencies: RuntimeManagedFabricServiceDependenciesV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let managed_cutover_present = match ManagedFabricStore::cutover_present(state_directory) {
        Ok(present) => present,
        Err(ManagedFabricStoreError::Open(error)) => {
            return Err(RuntimeBootstrapEndpointError::StoreOpen(error));
        }
        Err(error) => return Err(RuntimeBootstrapEndpointError::ManagedFabricStore(error)),
    };
    if managed_cutover_present {
        // Build the executor before constructing any managed owner so an
        // executor startup failure cannot strand an owner that would require
        // asynchronous shutdown.
        let runtime = build_managed_fabric_owner_runtime()?;
        let started = StartedManagedFabricService::try_start(
            state_directory,
            expected_store_instance_id,
            compiled,
            provisioning,
            dependencies,
        )?;
        let service_result = runtime.block_on(serve_managed_fabric_until(
            started,
            runtime_shutdown_signal(),
        ));
        drop(runtime);
        return service_result;
    }
    let store = RuntimeStore::open(
        state_directory,
        expected_store_instance_id,
        provisioning.owner_target_fingerprint(),
    )?;
    let started = StartedRuntimeBootstrapService::try_start(store, compiled, provisioning)?;
    // The local listener is the last startup resource: if the executor cannot
    // be built there is no socket guard whose cleanup would otherwise occur
    // only through Drop.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| RuntimeBootstrapEndpointError::Runtime)?;
    let bound = started.bind()?;
    let service_result = runtime.block_on(bound.serve_until(runtime_shutdown_signal()));
    drop(runtime);
    service_result
}

/// Runs the explicit DeveloperLocal endpoint.  A fresh store is served in
/// legacy read-only mode first so Deployment can obtain a real authenticated
/// PXBR.  Only a fully decoded, authenticated, channel-bound, and manifest-pin
/// exact PXFB can consume that legacy owner and publish the one-way PXMS
/// marker; the listener and socket identity remain unchanged across cutover.
pub(crate) async fn serve_runtime_developer_local_until<F, R>(
    state_directory: &Path,
    expected_store_instance_id: [u8; 32],
    compiled: RuntimeCompiledInstallationFactsV1,
    provisioning: RuntimeProvisioningV1,
    dependencies: RuntimeManagedFabricServiceDependenciesV1,
    shutdown: F,
    ready: R,
) -> Result<(), RuntimeBootstrapEndpointError>
where
    F: Future<Output = io::Result<()>>,
    R: FnOnce(
        ReferenceChannelBindingV1,
        RuntimeControlDescribeReadyFactsV1,
        RuntimeAgentHandleBroker,
    ) -> Result<(), RuntimeBootstrapEndpointError>,
{
    if ManagedFabricStore::cutover_present_developer_local(state_directory)? {
        let started = StartedManagedFabricService::try_start_developer_local(
            state_directory,
            expected_store_instance_id,
            compiled,
            provisioning,
            dependencies,
        )?;
        return serve_managed_fabric_until_with_ready(started, shutdown, ready).await;
    }
    let store = RuntimeStore::open_developer_local(
        state_directory,
        expected_store_instance_id,
        provisioning.owner_target_fingerprint(),
    )?;
    let started = StartedRuntimeBootstrapService::try_start(store, compiled, provisioning)?;
    serve_developer_legacy_cutover_until(
        started,
        state_directory,
        expected_store_instance_id,
        dependencies,
        shutdown,
        ready,
    )
    .await
}

enum DeveloperLocalControlState {
    Legacy(Option<Box<RuntimeControlService<RuntimeStore>>>),
    Managed(Box<ManagedFabricControlService>),
}

async fn serve_developer_legacy_cutover_until<F, R>(
    started: StartedRuntimeBootstrapService<RuntimeStore>,
    state_directory: &Path,
    expected_store_instance_id: [u8; 32],
    dependencies: RuntimeManagedFabricServiceDependenciesV1,
    shutdown: F,
    ready: R,
) -> Result<(), RuntimeBootstrapEndpointError>
where
    F: Future<Output = io::Result<()>>,
    R: FnOnce(
        ReferenceChannelBindingV1,
        RuntimeControlDescribeReadyFactsV1,
        RuntimeAgentHandleBroker,
    ) -> Result<(), RuntimeBootstrapEndpointError>,
{
    let (standard, guard) = bind_control_socket(&started.provisioning)?;
    let channel = match live_runtime_channel(&started.provisioning, &guard) {
        Ok(channel) => channel,
        Err(error) => {
            drop(standard);
            let cleanup_result = guard.cleanup();
            return aggregate_runtime_service_failures(Err(error), Ok(()), Ok(()), cleanup_result);
        }
    };
    let legacy = match started.into_control_service(channel) {
        Ok(legacy) => legacy,
        Err(error) => {
            drop(standard);
            let cleanup_result = guard.cleanup();
            return aggregate_runtime_service_failures(Err(error), Ok(()), Ok(()), cleanup_result);
        }
    };
    let handle_broker = RuntimeAgentHandleBroker::default();
    let listener = match UnixListener::from_std(standard) {
        Ok(listener) => listener,
        Err(error) => {
            let primary = RuntimeBootstrapEndpointError::Socket(error.kind());
            let cleanup_result = guard.cleanup();
            return aggregate_runtime_service_failures(
                Err(primary),
                Ok(()),
                Ok(()),
                cleanup_result,
            );
        }
    };
    // A configured restricted transport listener is part of DeveloperLocal
    // endpoint readiness, even while the UDS owner is still in legacy PXBR
    // mode. Until authenticated PXFB cutover completes, every remote request
    // receives only Fabric's fixed generic rejection and cannot reach a
    // mutation owner. The same listener/session and receiver are retained
    // across cutover; no endpoint generation is reopened or substituted.
    let mut restricted = match dependencies.restricted_runtime_apply_endpoint.clone() {
        Some(endpoint_dependencies) => {
            match RunningRestrictedRuntimeApplyEndpointV1::start(
                endpoint_dependencies,
                &legacy.provisioning,
            )
            .await
            {
                Ok(endpoint) => Some(endpoint),
                Err(error) => {
                    drop(listener);
                    let cleanup_result = guard.cleanup();
                    return aggregate_runtime_service_failures(
                        Err(error),
                        Ok(()),
                        Ok(()),
                        cleanup_result,
                    );
                }
            }
        }
        None => None,
    };
    let ready_result = legacy_runtime_control_describe_facts(&legacy, channel)
        .map_err(runtime_control_readiness_error)
        .and_then(|facts| ready(channel, facts, handle_broker.clone()));
    if let Err(error) = ready_result {
        drop(listener);
        let cleanup_result = guard.cleanup();
        let restricted_shutdown_result = match restricted.take() {
            Some(endpoint) => endpoint.shutdown().await,
            None => Ok(()),
        };
        return aggregate_runtime_service_failures(
            Err(error),
            Ok(()),
            restricted_shutdown_result,
            cleanup_result,
        );
    }
    let mut control = DeveloperLocalControlState::Legacy(Some(Box::new(legacy)));
    let mut shutdown = Box::pin(shutdown);
    let service_result = 'service: loop {
        let accepted = if let Some(restricted) = restricted.as_mut() {
            tokio::select! {
                biased;
                result = &mut shutdown => break result
                    .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind())),
                result = listener.accept() => result,
                inbound = restricted.receiver.recv() => {
                    let Some(inbound) = inbound else {
                        break Err(RuntimeBootstrapEndpointError::RestrictedRuntimeApply(
                            RestrictedRuntimeApplyErrorV1::EndpointWorkerFailed,
                        ));
                    };
                    let response = match restricted.protocol {
                        RestrictedRuntimeEndpointProtocolV1::LegacyApply => match &mut control {
                            DeveloperLocalControlState::Managed(managed) => managed
                                .handle_restricted_distributed_agent_stack_apply_v1(
                                    inbound.canonical_request(),
                                    &restricted.expected_carrier,
                                )
                                .await
                                .map_err(|error| match error {
                                    RuntimeRestrictedRemoteApplyErrorV1::Internal => Some(
                                        RuntimeBootstrapEndpointError::RestrictedRuntimeApplyOwner(
                                            error,
                                        ),
                                    ),
                                    RuntimeRestrictedRemoteApplyErrorV1::Rejected
                                    | RuntimeRestrictedRemoteApplyErrorV1::Unavailable => None,
                                }),
                            DeveloperLocalControlState::Legacy(_) => Err(None),
                        },
                        RestrictedRuntimeEndpointProtocolV1::RuntimeControl => {
                            handle_developer_restricted_runtime_control_v1(
                                &mut control,
                                DeveloperRestrictedRuntimeControlInputV1 {
                                    canonical_request: inbound.canonical_request(),
                                    expected_carrier: &restricted.expected_carrier,
                                    live_channel: channel,
                                    state_directory,
                                    expected_store_instance_id,
                                    handle_broker: &handle_broker,
                                    dependencies: &dependencies,
                                },
                            )
                            .await
                            .map_err(|error| match error {
                                RuntimeControlRequestError::Rejected
                                | RuntimeControlRequestError::Unavailable => None,
                                RuntimeControlRequestError::Internal(error) => Some(error),
                            })
                        }
                    };
                    match response {
                        Ok(response) => {
                            if let Err(error) = inbound.respond(response.into_vec()) {
                                break Err(
                                    RuntimeBootstrapEndpointError::
                                        RestrictedRuntimeApplyResponseHandoff(error),
                                );
                            }
                        }
                        Err(None) => {
                            // Every malformed, unauthorized, unavailable, or
                            // phase-incompatible request has the same fixed
                            // transport rejection and cannot observe state.
                            drop(inbound);
                        }
                        Err(Some(error)) => {
                            drop(inbound);
                            break Err(error);
                        }
                    }
                    continue;
                }
            }
        } else {
            tokio::select! {
                biased;
                result = &mut shutdown => break result
                    .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind())),
                result = listener.accept() => result,
            }
        };
        let (mut stream, _) = match accepted {
            Ok(value) => value,
            Err(error) => break Err(RuntimeBootstrapEndpointError::Socket(error.kind())),
        };
        let (expected_uid, expected_gid, expected_channel) = match &control {
            DeveloperLocalControlState::Legacy(Some(legacy)) => (
                legacy.provisioning.controller_uid(),
                legacy.provisioning.controller_gid(),
                legacy.channel,
            ),
            DeveloperLocalControlState::Managed(managed) => (
                managed.provisioning.controller_uid(),
                managed.provisioning.controller_gid(),
                managed.channel,
            ),
            DeveloperLocalControlState::Legacy(None) => {
                break Err(RuntimeBootstrapEndpointError::InvalidStartedState);
            }
        };
        if !peer_is_authorized(&stream, expected_uid, expected_gid) {
            continue;
        }
        let live_channel = match live_runtime_channel_from_state(&control, &guard) {
            Ok(live) if live == expected_channel => live,
            Ok(_) => break Err(RuntimeBootstrapEndpointError::SocketIdentityChanged),
            Err(error) => break Err(error),
        };
        let request =
            match read_bounded_frame(&mut stream, MAX_CONTROL_REQUEST_BYTES, DEFAULT_IO_TIMEOUT)
                .await
            {
                Ok(request) => request,
                Err(()) => continue,
            };

        let response = match &mut control {
            DeveloperLocalControlState::Legacy(slot) => {
                let legacy = match slot.as_mut() {
                    Some(legacy) => legacy,
                    None => {
                        break 'service Err(RuntimeBootstrapEndpointError::InvalidStartedState);
                    }
                };
                if request.starts_with(MANAGED_BOOTSTRAP_REQUEST_MAGIC) {
                    if prevalidate_developer_managed_cutover_request(legacy, &request, live_channel)
                        .is_err()
                    {
                        continue;
                    }
                    let legacy = match slot.take() {
                        Some(legacy) => legacy,
                        None => {
                            break 'service Err(RuntimeBootstrapEndpointError::InvalidStartedState);
                        }
                    };
                    let RuntimeControlService {
                        apply,
                        compiled,
                        provisioning,
                        channel,
                        ..
                    } = *legacy;
                    let legacy_store = match apply.into_developer_managed_cutover_store() {
                        Ok(store) => store,
                        Err(error) => {
                            break 'service Err(RuntimeBootstrapEndpointError::Apply(error));
                        }
                    };
                    let started =
                        match StartedManagedFabricService::try_cutover_developer_local_from_store(
                            state_directory,
                            expected_store_instance_id,
                            compiled,
                            provisioning,
                            legacy_store,
                            handle_broker.clone(),
                            dependencies.clone(),
                        ) {
                            Ok(started) => started,
                            Err(error) => break 'service Err(error),
                        };
                    let mut managed = match recover_managed_control_for_existing_channel(
                        started, channel,
                    )
                    .await
                    {
                        Ok(managed) => managed,
                        Err(error) => break 'service Err(error),
                    };
                    let response = managed.handle_request(&request, live_channel).await;
                    control = DeveloperLocalControlState::Managed(Box::new(managed));
                    response
                } else if request.starts_with(APPLY_REQUEST_MAGIC) {
                    // DeveloperLocal admits no legacy PXAR-v5 mutation: the
                    // sole fresh transition is authenticated PXFB→PXMS.
                    Err(RuntimeControlRequestError::Rejected)
                } else {
                    legacy
                        .handle_request(&request, live_channel)
                        .and_then(|response| response.ok_or(RuntimeControlRequestError::Rejected))
                }
            }
            DeveloperLocalControlState::Managed(managed) => {
                managed.handle_request(&request, live_channel).await
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(RuntimeControlRequestError::Rejected)
            | Err(RuntimeControlRequestError::Unavailable) => {
                continue;
            }
            Err(RuntimeControlRequestError::Internal(error)) => break Err(error),
        };
        let _ = write_bounded_frame(
            &mut stream,
            &response,
            MAX_CONTROL_RESPONSE_BYTES,
            DEFAULT_IO_TIMEOUT,
        )
        .await;
    };
    drop(listener);
    let cleanup_result = guard.cleanup();
    let restricted_shutdown_result = match restricted.take() {
        Some(endpoint) => endpoint.shutdown().await,
        None => Ok(()),
    };
    let managed_shutdown = match &mut control {
        DeveloperLocalControlState::Managed(managed) => {
            shutdown_managed_successor_chain(
                &mut managed.distributed,
                &mut managed.model_stack,
                &mut managed.stack,
                &mut managed.core,
            )
            .await
        }
        DeveloperLocalControlState::Legacy(_) => Ok(()),
    };
    aggregate_runtime_service_failures(
        service_result,
        managed_shutdown,
        restricted_shutdown_result,
        cleanup_result,
    )
}

fn live_runtime_channel_from_state(
    control: &DeveloperLocalControlState,
    guard: &SocketGuard,
) -> Result<ReferenceChannelBindingV1, RuntimeBootstrapEndpointError> {
    match control {
        DeveloperLocalControlState::Legacy(Some(legacy)) => {
            live_runtime_channel(&legacy.provisioning, guard)
        }
        DeveloperLocalControlState::Managed(managed) => {
            live_runtime_channel(&managed.provisioning, guard)
        }
        DeveloperLocalControlState::Legacy(None) => {
            Err(RuntimeBootstrapEndpointError::InvalidStartedState)
        }
    }
}

struct DeveloperRestrictedRuntimeControlInputV1<'a> {
    canonical_request: &'a [u8],
    expected_carrier: &'a RestrictedRuntimeApplyCarrierBindingV1,
    live_channel: ReferenceChannelBindingV1,
    state_directory: &'a Path,
    expected_store_instance_id: [u8; 32],
    handle_broker: &'a RuntimeAgentHandleBroker,
    dependencies: &'a RuntimeManagedFabricServiceDependenciesV1,
}

async fn handle_developer_restricted_runtime_control_v1(
    control: &mut DeveloperLocalControlState,
    input: DeveloperRestrictedRuntimeControlInputV1<'_>,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let DeveloperRestrictedRuntimeControlInputV1 {
        canonical_request,
        expected_carrier,
        live_channel,
        state_directory,
        expected_store_instance_id,
        handle_broker,
        dependencies,
    } = input;
    let provisioning = match control {
        DeveloperLocalControlState::Legacy(Some(legacy)) => &legacy.provisioning,
        DeveloperLocalControlState::Managed(managed) => &managed.provisioning,
        DeveloperLocalControlState::Legacy(None) => {
            return Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::InvalidStartedState,
            ));
        }
    };
    if canonical_request.starts_with(RUNTIME_AGENT_CONTROL_REQUEST_MAGIC) {
        let request = decode_runtime_agent_control_request(canonical_request)?;
        let authenticated =
            authenticate_runtime_agent_control_request(provisioning, &request, expected_carrier)?;
        if let DeveloperLocalControlState::Managed(managed) = control {
            return managed
                .handle_authenticated_runtime_agent_control_request_v1(authenticated)
                .await;
        }
        return Err(RuntimeControlRequestError::Rejected);
    }
    let request = decode_runtime_control_carrier(canonical_request)?;
    let authenticated =
        authenticate_runtime_control_carrier(provisioning, &request, expected_carrier)?;
    match control {
        DeveloperLocalControlState::Managed(managed) => {
            managed
                .handle_authenticated_runtime_control_carrier_v1(authenticated)
                .await
        }
        DeveloperLocalControlState::Legacy(slot) => {
            let legacy = slot.as_mut().ok_or(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::InvalidStartedState,
            ))?;
            match authenticated.kind() {
                RuntimeControlCarrierKindV1::Describe => {
                    let facts = legacy_runtime_control_describe_facts(legacy, live_channel)?;
                    runtime_control_describe_response(&legacy.provisioning, authenticated, facts)
                }
                RuntimeControlCarrierKindV1::ReferenceQuery => {
                    let query = authenticated
                        .reference_query_request()
                        .ok_or(RuntimeControlRequestError::Rejected)?;
                    legacy.handle_query(query.canonical_wire())
                }
                RuntimeControlCarrierKindV1::ManagedServingBootstrap => {
                    let request = authenticated
                        .managed_serving_bootstrap_request()
                        .ok_or(RuntimeControlRequestError::Rejected)?;
                    prevalidate_developer_managed_cutover_request(
                        legacy,
                        request.canonical_wire(),
                        live_channel,
                    )?;
                    let legacy = slot.take().ok_or(RuntimeControlRequestError::Internal(
                        RuntimeBootstrapEndpointError::InvalidStartedState,
                    ))?;
                    let RuntimeControlService {
                        apply,
                        compiled,
                        provisioning,
                        channel,
                        ..
                    } = *legacy;
                    let legacy_store =
                        apply
                            .into_developer_managed_cutover_store()
                            .map_err(|error| {
                                RuntimeControlRequestError::Internal(
                                    RuntimeBootstrapEndpointError::Apply(error),
                                )
                            })?;
                    let started =
                        StartedManagedFabricService::try_cutover_developer_local_from_store(
                            state_directory,
                            expected_store_instance_id,
                            compiled,
                            provisioning,
                            legacy_store,
                            handle_broker.clone(),
                            dependencies.clone(),
                        )
                        .map_err(RuntimeControlRequestError::Internal)?;
                    let mut managed =
                        recover_managed_control_for_existing_channel(started, channel)
                            .await
                            .map_err(RuntimeControlRequestError::Internal)?;
                    let response = managed
                        .handle_request(request.canonical_wire(), live_channel)
                        .await;
                    *control = DeveloperLocalControlState::Managed(Box::new(managed));
                    response
                }
            }
        }
    }
}

fn prevalidate_developer_managed_cutover_request(
    legacy: &RuntimeControlService<RuntimeStore>,
    frame: &[u8],
    live_channel: ReferenceChannelBindingV1,
) -> Result<(), RuntimeControlRequestError> {
    if live_channel != legacy.channel
        || frame.is_empty()
        || frame.len() > MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES
    {
        return Err(RuntimeControlRequestError::Rejected);
    }
    let request = ManagedServingBootstrapRequestV1::decode(frame)
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    authenticate_managed_serving_request(&legacy.provisioning, &request, legacy.channel)?;
    let snapshot = legacy.apply.snapshot();
    let installation =
        verify_startup_installation(snapshot, legacy.provisioning.target(), legacy.compiled)
            .map_err(RuntimeControlRequestError::Internal)?;
    validate_snapshot_pins(&legacy.provisioning, snapshot)
        .map_err(RuntimeControlRequestError::Internal)?;
    let manifest = installation.immutable_manifest_ingress().map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::Installation(error))
    })?;
    validate_startup_durable_control_state(
        snapshot,
        &manifest,
        legacy.compiled,
        &legacy.provisioning,
    )
    .map_err(RuntimeControlRequestError::Internal)?;
    let projection = ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(
        &manifest,
    )
    .map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedFabricContract(
            error,
        ))
    })?;
    if request.target() != legacy.provisioning.target()
        || request.expected_runtime_store_instance_id() != *snapshot.store_instance_id()
        || request.projection() != &projection
        || request.channel() != legacy.channel
    {
        return Err(RuntimeControlRequestError::Rejected);
    }
    Ok(())
}

async fn recover_managed_control_for_existing_channel(
    started: StartedManagedFabricService,
    channel: ReferenceChannelBindingV1,
) -> Result<ManagedFabricControlService, RuntimeBootstrapEndpointError> {
    let StartedManagedFabricService {
        mut core,
        mut stack,
        stack_projection,
        mut model_stack,
        model_stack_projection,
        mut distributed,
        distributed_projection,
        handle_broker,
        state_directory,
        provisioning,
        dependencies,
    } = started;
    let recovery_result = async {
        if let Some(distributed) = distributed.as_mut() {
            distributed
                .recover(&mut core)
                .await
                .map_err(RuntimeBootstrapEndpointError::DistributedAgentStack)?;
        } else if let Some(model_stack) = model_stack.as_mut() {
            if model_stack.requires_predecessor_recovery() {
                core.recover().await?;
            }
            model_stack
                .recover(&mut core)
                .await
                .map_err(RuntimeBootstrapEndpointError::ManagedModelAgentStack)?;
        } else {
            if stack
                .as_ref()
                .is_none_or(ManagedAgentStackRuntimeCore::requires_predecessor_recovery)
            {
                core.recover().await?;
            }
            if let Some(stack) = stack.as_mut() {
                stack
                    .recover(&mut core)
                    .await
                    .map_err(RuntimeBootstrapEndpointError::ManagedAgentStack)?;
            }
        }
        Ok::<(), RuntimeBootstrapEndpointError>(())
    }
    .await;
    if let Err(error) = recovery_result {
        let owner_shutdown = shutdown_managed_successor_chain(
            &mut distributed,
            &mut model_stack,
            &mut stack,
            &mut core,
        )
        .await;
        let failure =
            aggregate_runtime_service_failures(Err(error), owner_shutdown, Ok(()), Ok(()))
                .expect_err("the primary recovery failure cannot aggregate to success");
        return Err(failure);
    }
    Ok(ManagedFabricControlService {
        core,
        stack,
        stack_projection,
        model_stack,
        model_stack_projection,
        distributed,
        distributed_projection,
        handle_broker,
        state_directory,
        provisioning,
        channel,
        dependencies,
    })
}

async fn shutdown_managed_successor_chain(
    distributed: &mut Option<DistributedAgentStackRuntimeCore>,
    model_stack: &mut Option<ManagedModelAgentStackRuntimeCore>,
    stack: &mut Option<ManagedAgentStackRuntimeCore>,
    core: &mut ManagedFabricRuntimeCore,
) -> Result<(), RuntimeBootstrapEndpointError> {
    if let Some(model_stack) = model_stack.as_mut() {
        // The A2 owner is the dependency-order authority. In particular, an
        // uncertain Agent retirement forbids touching either Model or Fabric.
        // Do not let the outer generic cleanup path stop Fabric after that
        // fail-closed decision.
        model_stack
            .shutdown(core)
            .await
            .map_err(RuntimeBootstrapEndpointError::ManagedModelAgentStack)?;
        return core
            .shutdown()
            .await
            .map_err(RuntimeBootstrapEndpointError::ManagedFabric);
    }
    if let Some(distributed) = distributed.as_mut() {
        distributed
            .shutdown()
            .await
            .map_err(RuntimeBootstrapEndpointError::DistributedAgentStack)?;
    }
    if let Some(stack) = stack.as_mut() {
        stack
            .shutdown(core)
            .await
            .map_err(RuntimeBootstrapEndpointError::ManagedAgentStack)?;
    }
    core.shutdown()
        .await
        .map_err(RuntimeBootstrapEndpointError::ManagedFabric)
}

#[derive(Default)]
struct RuntimeBootstrapFailureReducerV1 {
    failures: Vec<RuntimeBootstrapFailureV1>,
}

impl RuntimeBootstrapFailureReducerV1 {
    fn record_result(
        &mut self,
        stage: RuntimeBootstrapFailureStageV1,
        result: Result<(), RuntimeBootstrapEndpointError>,
    ) {
        if let Err(error) = result {
            self.record_error(stage, error);
        }
    }

    fn record_error(
        &mut self,
        stage: RuntimeBootstrapFailureStageV1,
        error: RuntimeBootstrapEndpointError,
    ) {
        match error {
            RuntimeBootstrapEndpointError::StagedFailures(failures) => {
                self.failures.extend(failures.into_failures().into_vec());
            }
            error => self.failures.push(RuntimeBootstrapFailureV1 {
                stage,
                error: Box::new(error),
            }),
        }
    }

    fn finish(mut self) -> Result<(), RuntimeBootstrapEndpointError> {
        if self.failures.is_empty() {
            Ok(())
        } else {
            self.failures.sort_by_key(|failure| failure.stage.order());
            Err(RuntimeBootstrapEndpointError::StagedFailures(
                RuntimeBootstrapFailureSetV1 {
                    failures: self.failures.into_boxed_slice(),
                },
            ))
        }
    }
}

fn aggregate_runtime_service_failures(
    service_result: Result<(), RuntimeBootstrapEndpointError>,
    owner_shutdown: Result<(), RuntimeBootstrapEndpointError>,
    restricted_shutdown: Result<(), RuntimeBootstrapEndpointError>,
    local_cleanup: Result<(), RuntimeBootstrapEndpointError>,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let mut failures = RuntimeBootstrapFailureReducerV1::default();
    failures.record_result(RuntimeBootstrapFailureStageV1::Primary, service_result);
    failures.record_result(RuntimeBootstrapFailureStageV1::Successor, owner_shutdown);
    failures.record_result(
        RuntimeBootstrapFailureStageV1::RestrictedEndpoint,
        restricted_shutdown,
    );
    failures.record_result(
        RuntimeBootstrapFailureStageV1::LocalSocketCleanup,
        local_cleanup,
    );
    failures.finish()
}

impl<Store: RuntimeBootstrapStore> StartedRuntimeBootstrapService<Store> {
    fn bind(self) -> Result<BoundRuntimeBootstrapService<Store>, RuntimeBootstrapEndpointError> {
        let (standard, guard) = bind_control_socket(&self.provisioning)?;

        Ok(BoundRuntimeBootstrapService {
            started: self,
            standard,
            guard,
            io_timeout: DEFAULT_IO_TIMEOUT,
        })
    }
}

fn bind_control_socket(
    provisioning: &RuntimeProvisioningV1,
) -> Result<(StdUnixListener, SocketGuard), RuntimeBootstrapEndpointError> {
    provisioning.validate_runtime_credentials()?;
    let directory = open_socket_directory(
        provisioning
            .socket_path()
            .parent()
            .ok_or(RuntimeBootstrapEndpointError::InvalidProvisioning)?,
        provisioning.runtime_uid(),
        provisioning.controller_gid(),
        provisioning.socket_directory_mode(),
        provisioning.socket_mode(),
    )?;
    remove_stale_socket_if_present(&directory, provisioning.socket_path())?;
    let standard = StdUnixListener::bind(provisioning.socket_path())
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    let identity = socket_identity(provisioning.socket_path())?;
    let guard = SocketGuard {
        path: provisioning.socket_path().to_path_buf(),
        directory,
        identity,
    };
    let setup = (|| {
        chown(
            provisioning.socket_path(),
            None,
            Some(Gid::from_raw(provisioning.controller_gid())),
        )
        .map_err(nix_socket_error)?;
        fs::set_permissions(
            provisioning.socket_path(),
            fs::Permissions::from_mode(provisioning.socket_mode()),
        )
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        let metadata = fs::symlink_metadata(provisioning.socket_path())
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        validate_socket_metadata(
            &metadata,
            provisioning.runtime_uid(),
            provisioning.controller_gid(),
            provisioning.socket_mode(),
        )?;
        if !identity.matches(&metadata) {
            return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
        }
        guard.validate_directory_identity()?;
        guard
            .directory
            .file
            .sync_all()
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        standard
            .set_nonblocking(true)
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))
    })();
    if let Err(error) = setup {
        drop(standard);
        let cleanup_result = guard.cleanup();
        let failure =
            aggregate_runtime_service_failures(Err(error), Ok(()), Ok(()), cleanup_result)
                .expect_err("the primary socket setup failure cannot aggregate to success");
        return Err(failure);
    }
    Ok((standard, guard))
}

struct BoundRuntimeBootstrapService<Store> {
    started: StartedRuntimeBootstrapService<Store>,
    standard: StdUnixListener,
    guard: SocketGuard,
    io_timeout: Duration,
}

impl<Store> BoundRuntimeBootstrapService<Store>
where
    Store: RuntimeBootstrapStore + RuntimeReferenceApplyStore,
{
    async fn serve_until<F>(self, shutdown: F) -> Result<(), RuntimeBootstrapEndpointError>
    where
        F: Future<Output = io::Result<()>>,
    {
        let Self {
            started,
            standard,
            guard,
            io_timeout,
        } = self;
        let channel = match live_runtime_channel(&started.provisioning, &guard) {
            Ok(channel) => channel,
            Err(error) => {
                drop(standard);
                let cleanup_result = guard.cleanup();
                return aggregate_runtime_service_failures(
                    Err(error),
                    Ok(()),
                    Ok(()),
                    cleanup_result,
                );
            }
        };
        let mut control = match started.into_control_service(channel) {
            Ok(control) => control,
            Err(error) => {
                drop(standard);
                let cleanup_result = guard.cleanup();
                return aggregate_runtime_service_failures(
                    Err(error),
                    Ok(()),
                    Ok(()),
                    cleanup_result,
                );
            }
        };
        let listener = match UnixListener::from_std(standard) {
            Ok(listener) => listener,
            Err(error) => {
                let primary = RuntimeBootstrapEndpointError::Socket(error.kind());
                let cleanup_result = guard.cleanup();
                return aggregate_runtime_service_failures(
                    Err(primary),
                    Ok(()),
                    Ok(()),
                    cleanup_result,
                );
            }
        };
        let mut shutdown = Box::pin(shutdown);
        let service_result =
            loop {
                let accepted = tokio::select! {
                    biased;
                    result = &mut shutdown => break result
                        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind())),
                    result = listener.accept() => result,
                };
                let (mut stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        break Err(RuntimeBootstrapEndpointError::Socket(error.kind()));
                    }
                };
                if !peer_is_authorized(
                    &stream,
                    control.provisioning.controller_uid(),
                    control.provisioning.controller_gid(),
                ) {
                    continue;
                }
                let live_channel = match live_runtime_channel(&control.provisioning, &guard) {
                    Ok(channel) if channel == control.channel => channel,
                    Ok(_) => break Err(RuntimeBootstrapEndpointError::SocketIdentityChanged),
                    Err(error) => break Err(error),
                };
                let request =
                    match read_bounded_frame(&mut stream, MAX_CONTROL_REQUEST_BYTES, io_timeout)
                        .await
                    {
                        Ok(request) => request,
                        Err(()) => continue,
                    };
                let response = match control.handle_request(&request, live_channel) {
                    Ok(Some(response)) => response,
                    Ok(None)
                    | Err(RuntimeControlRequestError::Rejected)
                    | Err(RuntimeControlRequestError::Unavailable) => continue,
                    Err(RuntimeControlRequestError::Internal(error)) => break Err(error),
                };
                let _ = write_bounded_frame(
                    &mut stream,
                    &response,
                    MAX_CONTROL_RESPONSE_BYTES,
                    io_timeout,
                )
                .await;
            };
        drop(listener);
        let cleanup_result = guard.cleanup();
        aggregate_runtime_service_failures(service_result, Ok(()), Ok(()), cleanup_result)
    }
}

async fn serve_managed_fabric_until<F>(
    started: StartedManagedFabricService,
    shutdown: F,
) -> Result<(), RuntimeBootstrapEndpointError>
where
    F: Future<Output = io::Result<()>>,
{
    serve_managed_fabric_until_with_ready(started, shutdown, |_, _, _| Ok(())).await
}

struct RunningRestrictedRuntimeApplyEndpointV1 {
    endpoint: RunningRestrictedRuntimeEndpointLifecycleV1,
    receiver: RunningRestrictedRuntimeEndpointReceiverV1,
    expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
    protocol: RestrictedRuntimeEndpointProtocolV1,
}

enum RunningRestrictedRuntimeEndpointLifecycleV1 {
    LegacyApply(RestrictedRuntimeApplyEndpointV1),
    RuntimeControl(RestrictedRuntimeControlEndpointV1),
}

enum RunningRestrictedRuntimeEndpointReceiverV1 {
    LegacyApply(RestrictedRuntimeApplyReceiverV1),
    RuntimeControl(RestrictedRuntimeControlReceiverV1),
}

enum RunningRestrictedRuntimeInboundV1 {
    LegacyApply(paraegox_fabric::RestrictedRuntimeApplyInboundV1),
    RuntimeControl(RestrictedRuntimeControlInboundV1),
}

impl RunningRestrictedRuntimeEndpointReceiverV1 {
    async fn recv(&mut self) -> Option<RunningRestrictedRuntimeInboundV1> {
        match self {
            Self::LegacyApply(receiver) => receiver
                .recv()
                .await
                .map(RunningRestrictedRuntimeInboundV1::LegacyApply),
            Self::RuntimeControl(receiver) => receiver
                .recv()
                .await
                .map(RunningRestrictedRuntimeInboundV1::RuntimeControl),
        }
    }
}

impl RunningRestrictedRuntimeInboundV1 {
    fn canonical_request(&self) -> &[u8] {
        match self {
            Self::LegacyApply(inbound) => inbound.canonical_request(),
            Self::RuntimeControl(inbound) => inbound.canonical_request(),
        }
    }

    fn respond(
        self,
        canonical_response: Vec<u8>,
    ) -> Result<(), RestrictedRuntimeApplyRespondErrorV1> {
        match self {
            Self::LegacyApply(inbound) => inbound.respond(canonical_response),
            Self::RuntimeControl(inbound) => inbound.respond(canonical_response),
        }
    }
}

fn validate_restricted_runtime_apply_endpoint_dependencies(
    dependencies: &RuntimeRestrictedApplyEndpointDependenciesV1,
    provisioning: &RuntimeProvisioningV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    if !dependencies
        .endpoint_config
        .matches_restricted_carrier(&dependencies.expected_carrier)
    {
        return Err(RuntimeBootstrapEndpointError::InvalidProvisioning);
    }
    validate_restricted_runtime_apply_carrier_pins(provisioning, &dependencies.expected_carrier)
        .map(|_| ())
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidProvisioning)
}

impl RunningRestrictedRuntimeApplyEndpointV1 {
    async fn start(
        dependencies: RuntimeRestrictedApplyEndpointDependenciesV1,
        provisioning: &RuntimeProvisioningV1,
    ) -> Result<Self, RuntimeBootstrapEndpointError> {
        validate_restricted_runtime_apply_endpoint_dependencies(&dependencies, provisioning)?;
        let RuntimeRestrictedApplyEndpointDependenciesV1 {
            endpoint_config,
            expected_carrier,
            protocol,
        } = dependencies;
        let (endpoint, receiver) = match endpoint_config {
            RestrictedRuntimeEndpointConfigV1::LegacyApply(config) => {
                let (endpoint, receiver) = RestrictedRuntimeApplyEndpointV1::start(config)
                    .await
                    .map_err(RuntimeBootstrapEndpointError::RestrictedRuntimeApply)?;
                (
                    RunningRestrictedRuntimeEndpointLifecycleV1::LegacyApply(endpoint),
                    RunningRestrictedRuntimeEndpointReceiverV1::LegacyApply(receiver),
                )
            }
            RestrictedRuntimeEndpointConfigV1::RuntimeControl(config) => {
                let (endpoint, receiver) = RestrictedRuntimeControlEndpointV1::start(config)
                    .await
                    .map_err(RuntimeBootstrapEndpointError::RestrictedRuntimeApply)?;
                (
                    RunningRestrictedRuntimeEndpointLifecycleV1::RuntimeControl(endpoint),
                    RunningRestrictedRuntimeEndpointReceiverV1::RuntimeControl(receiver),
                )
            }
        };
        Ok(Self {
            endpoint,
            receiver,
            expected_carrier,
            protocol,
        })
    }

    async fn shutdown(self) -> Result<(), RuntimeBootstrapEndpointError> {
        let Self {
            endpoint,
            receiver,
            expected_carrier: _,
            protocol: _,
        } = self;
        // Closing the sole consumer drops queued responders before endpoint
        // undeclaration/join, so shutdown cannot leave the worker waiting for
        // a Runtime owner that has already stopped selecting this receiver.
        drop(receiver);
        match endpoint {
            RunningRestrictedRuntimeEndpointLifecycleV1::LegacyApply(endpoint) => {
                endpoint.shutdown().await
            }
            RunningRestrictedRuntimeEndpointLifecycleV1::RuntimeControl(endpoint) => {
                endpoint.shutdown().await
            }
        }
        .map_err(RuntimeBootstrapEndpointError::RestrictedRuntimeApply)
    }
}

pub(crate) async fn serve_managed_fabric_until_with_ready<F, R>(
    started: StartedManagedFabricService,
    shutdown: F,
    ready: R,
) -> Result<(), RuntimeBootstrapEndpointError>
where
    F: Future<Output = io::Result<()>>,
    R: FnOnce(
        ReferenceChannelBindingV1,
        RuntimeControlDescribeReadyFactsV1,
        RuntimeAgentHandleBroker,
    ) -> Result<(), RuntimeBootstrapEndpointError>,
{
    let StartedManagedFabricService {
        mut core,
        mut stack,
        stack_projection,
        mut model_stack,
        model_stack_projection,
        mut distributed,
        distributed_projection,
        handle_broker,
        state_directory,
        provisioning,
        dependencies,
    } = started;

    // Recovery is the readiness gate. No filesystem entry for the control
    // listener exists until the durable successor state and any required real
    // Fabric session have been reconciled successfully.
    let recovery = async {
        if let Some(distributed) = distributed.as_mut() {
            distributed
                .recover(&mut core)
                .await
                .map_err(RuntimeBootstrapEndpointError::DistributedAgentStack)?;
        } else if let Some(model_stack) = model_stack.as_mut() {
            if model_stack.requires_predecessor_recovery() {
                core.recover().await?;
            }
            model_stack
                .recover(&mut core)
                .await
                .map_err(RuntimeBootstrapEndpointError::ManagedModelAgentStack)?;
        } else {
            if stack
                .as_ref()
                .is_none_or(ManagedAgentStackRuntimeCore::requires_predecessor_recovery)
            {
                core.recover().await?;
            }
            if let Some(stack) = stack.as_mut() {
                stack
                    .recover(&mut core)
                    .await
                    .map_err(RuntimeBootstrapEndpointError::ManagedAgentStack)?;
            }
        }
        Ok::<(), RuntimeBootstrapEndpointError>(())
    }
    .await;
    if let Err(error) = recovery {
        let owner_shutdown = shutdown_managed_successor_chain(
            &mut distributed,
            &mut model_stack,
            &mut stack,
            &mut core,
        )
        .await;
        return aggregate_runtime_service_failures(Err(error), owner_shutdown, Ok(()), Ok(()));
    }
    let (standard, guard) = match bind_control_socket(&provisioning) {
        Ok(bound) => bound,
        Err(error) => {
            let owner_shutdown = shutdown_managed_successor_chain(
                &mut distributed,
                &mut model_stack,
                &mut stack,
                &mut core,
            )
            .await;
            return aggregate_runtime_service_failures(Err(error), owner_shutdown, Ok(()), Ok(()));
        }
    };
    let channel = match live_runtime_channel(&provisioning, &guard) {
        Ok(channel) => channel,
        Err(error) => {
            drop(standard);
            let cleanup_result = guard.cleanup();
            let shutdown_result = shutdown_managed_successor_chain(
                &mut distributed,
                &mut model_stack,
                &mut stack,
                &mut core,
            )
            .await;
            return aggregate_runtime_service_failures(
                Err(error),
                shutdown_result,
                Ok(()),
                cleanup_result,
            );
        }
    };
    let mut control = ManagedFabricControlService {
        core,
        stack,
        stack_projection,
        model_stack,
        model_stack_projection,
        distributed,
        distributed_projection,
        handle_broker,
        state_directory,
        provisioning,
        channel,
        dependencies,
    };
    let listener = match UnixListener::from_std(standard) {
        Ok(listener) => listener,
        Err(error) => {
            let primary = RuntimeBootstrapEndpointError::Socket(error.kind());
            let cleanup_result = guard.cleanup();
            let shutdown_result = shutdown_managed_successor_chain(
                &mut control.distributed,
                &mut control.model_stack,
                &mut control.stack,
                &mut control.core,
            )
            .await;
            return aggregate_runtime_service_failures(
                Err(primary),
                shutdown_result,
                Ok(()),
                cleanup_result,
            );
        }
    };
    let mut restricted = match control
        .dependencies
        .restricted_runtime_apply_endpoint
        .clone()
    {
        Some(dependencies) => {
            match RunningRestrictedRuntimeApplyEndpointV1::start(
                dependencies,
                &control.provisioning,
            )
            .await
            {
                Ok(endpoint) => Some(endpoint),
                Err(error) => {
                    drop(listener);
                    let cleanup_result = guard.cleanup();
                    let shutdown_result = shutdown_managed_successor_chain(
                        &mut control.distributed,
                        &mut control.model_stack,
                        &mut control.stack,
                        &mut control.core,
                    )
                    .await;
                    return aggregate_runtime_service_failures(
                        Err(error),
                        shutdown_result,
                        Ok(()),
                        cleanup_result,
                    );
                }
            }
        }
        None => None,
    };
    let ready_result = control
        .runtime_control_describe_facts()
        .map_err(runtime_control_readiness_error)
        .and_then(|facts| ready(control.channel, facts, control.handle_broker.clone()));
    if let Err(error) = ready_result {
        drop(listener);
        let cleanup_result = guard.cleanup();
        let restricted_shutdown_result = match restricted.take() {
            Some(endpoint) => endpoint.shutdown().await,
            None => Ok(()),
        };
        let shutdown_result = shutdown_managed_successor_chain(
            &mut control.distributed,
            &mut control.model_stack,
            &mut control.stack,
            &mut control.core,
        )
        .await;
        return aggregate_runtime_service_failures(
            Err(error),
            shutdown_result,
            restricted_shutdown_result,
            cleanup_result,
        );
    }
    let mut shutdown = Box::pin(shutdown);
    let service_result = loop {
        let accepted = if let Some(restricted) = restricted.as_mut() {
            tokio::select! {
                biased;
                result = &mut shutdown => break result
                    .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind())),
                result = listener.accept() => result,
                inbound = restricted.receiver.recv() => {
                    let Some(inbound) = inbound else {
                        break Err(RuntimeBootstrapEndpointError::RestrictedRuntimeApply(
                            RestrictedRuntimeApplyErrorV1::EndpointWorkerFailed,
                        ));
                    };
                    let response = match restricted.protocol {
                        RestrictedRuntimeEndpointProtocolV1::LegacyApply => control
                            .handle_restricted_distributed_agent_stack_apply_v1(
                                inbound.canonical_request(),
                                &restricted.expected_carrier,
                            )
                            .await
                            .map_err(|error| match error {
                                RuntimeRestrictedRemoteApplyErrorV1::Internal => Some(
                                    RuntimeBootstrapEndpointError::RestrictedRuntimeApplyOwner(
                                        error,
                                    ),
                                ),
                                RuntimeRestrictedRemoteApplyErrorV1::Rejected
                                | RuntimeRestrictedRemoteApplyErrorV1::Unavailable => None,
                            }),
                        RestrictedRuntimeEndpointProtocolV1::RuntimeControl => {
                            control
                                .handle_restricted_runtime_control_frame_v1(
                                    inbound.canonical_request(),
                                    &restricted.expected_carrier,
                                )
                                .await
                                .map_err(|error| match error {
                                    RuntimeControlRequestError::Rejected
                                    | RuntimeControlRequestError::Unavailable => None,
                                    RuntimeControlRequestError::Internal(error) => Some(error),
                                })
                        }
                    };
                    match response {
                        Ok(response) => {
                            if let Err(error) = inbound.respond(response.into_vec()) {
                                break Err(
                                    RuntimeBootstrapEndpointError::
                                        RestrictedRuntimeApplyResponseHandoff(error),
                                );
                            }
                        }
                        Err(None) => {
                            // Dropping the unanswered request makes Fabric emit
                            // only its fixed generic remote rejection.
                            drop(inbound);
                        }
                        Err(Some(error)) => {
                            drop(inbound);
                            break Err(error);
                        }
                    }
                    continue;
                }
            }
        } else {
            tokio::select! {
                biased;
                result = &mut shutdown => break result
                    .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind())),
                result = listener.accept() => result,
            }
        };
        let (mut stream, _) = match accepted {
            Ok(value) => value,
            Err(error) => break Err(RuntimeBootstrapEndpointError::Socket(error.kind())),
        };
        if !peer_is_authorized(
            &stream,
            control.provisioning.controller_uid(),
            control.provisioning.controller_gid(),
        ) {
            continue;
        }
        let live_channel = match live_runtime_channel(&control.provisioning, &guard) {
            Ok(channel) if channel == control.channel => channel,
            Ok(_) => break Err(RuntimeBootstrapEndpointError::SocketIdentityChanged),
            Err(error) => break Err(error),
        };
        let request =
            match read_bounded_frame(&mut stream, MAX_CONTROL_REQUEST_BYTES, DEFAULT_IO_TIMEOUT)
                .await
            {
                Ok(request) => request,
                Err(()) => continue,
            };
        let response = match control.handle_request(&request, live_channel).await {
            Ok(response) => response,
            Err(RuntimeControlRequestError::Rejected)
            | Err(RuntimeControlRequestError::Unavailable) => {
                continue;
            }
            Err(RuntimeControlRequestError::Internal(error)) => break Err(error),
        };
        let _ = write_bounded_frame(
            &mut stream,
            &response,
            MAX_CONTROL_RESPONSE_BYTES,
            DEFAULT_IO_TIMEOUT,
        )
        .await;
    };
    drop(listener);
    let cleanup_result = guard.cleanup();
    let restricted_shutdown_result = match restricted.take() {
        Some(endpoint) => endpoint.shutdown().await,
        None => Ok(()),
    };
    let shutdown_result = shutdown_managed_successor_chain(
        &mut control.distributed,
        &mut control.model_stack,
        &mut control.stack,
        &mut control.core,
    )
    .await;
    aggregate_runtime_service_failures(
        service_result,
        shutdown_result,
        restricted_shutdown_result,
        cleanup_result,
    )
}

async fn runtime_shutdown_signal() -> io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

fn peer_is_authorized(stream: &UnixStream, expected_uid: u32, expected_gid: u32) -> bool {
    stream.peer_cred().is_ok_and(|credentials| {
        credentials.uid() == expected_uid && credentials.gid() == expected_gid
    })
}

async fn read_bounded_frame(
    stream: &mut UnixStream,
    maximum: usize,
    io_timeout: Duration,
) -> Result<Box<[u8]>, ()> {
    timeout(io_timeout, async {
        let mut header = [0_u8; CONTROL_FRAME_HEADER_BYTES];
        stream.read_exact(&mut header).await.map_err(|_| ())?;
        let payload_length = usize::try_from(u32::from_be_bytes(header)).map_err(|_| ())?;
        if payload_length == 0 || payload_length > maximum {
            return Err(());
        }
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_length).map_err(|_| ())?;
        payload.resize(payload_length, 0);
        stream.read_exact(&mut payload).await.map_err(|_| ())?;
        Ok(payload.into_boxed_slice())
    })
    .await
    .map_err(|_| ())?
}

async fn write_bounded_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    maximum: usize,
    io_timeout: Duration,
) -> Result<(), ()> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(());
    }
    let length = u32::try_from(payload.len()).map_err(|_| ())?.to_be_bytes();
    timeout(io_timeout, async {
        stream.write_all(&length).await.map_err(|_| ())?;
        stream.write_all(payload).await.map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

fn open_socket_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_directory_mode: u32,
    expected_socket_mode: u32,
) -> Result<OpenedSocketDirectory, RuntimeBootstrapEndpointError> {
    validate_absolute_directory_path(path)?;
    let before = fs::symlink_metadata(path)
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    validate_socket_directory_metadata(
        &before,
        expected_uid,
        expected_gid,
        expected_directory_mode,
    )?;
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_socket_error)?;
    let file = File::from(owned);
    let after = file
        .metadata()
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    validate_socket_directory_metadata(
        &after,
        expected_uid,
        expected_gid,
        expected_directory_mode,
    )?;
    let identity = SocketIdentity::from_metadata(&after);
    if !identity.matches(&before) {
        return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
    }
    Ok(OpenedSocketDirectory {
        path: path.to_path_buf(),
        file,
        identity,
        expected_uid,
        expected_gid,
        expected_directory_mode,
        expected_socket_mode,
    })
}

fn validate_absolute_directory_path(path: &Path) -> Result<(), RuntimeBootstrapEndpointError> {
    validate_canonical_absolute_path(path, false)?;
    Ok(())
}

fn validate_socket_directory_metadata(
    metadata: &Metadata,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), RuntimeBootstrapEndpointError> {
    if !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & MODE_MASK != expected_mode
    {
        return Err(RuntimeBootstrapEndpointError::UnsafeSocketDirectory);
    }
    Ok(())
}

fn validate_socket_metadata(
    metadata: &Metadata,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), RuntimeBootstrapEndpointError> {
    if !metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & MODE_MASK != expected_mode
    {
        return Err(RuntimeBootstrapEndpointError::UnsafeSocket);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn matches(self, metadata: &Metadata) -> bool {
        self.device == metadata.dev() && self.inode == metadata.ino()
    }
}

fn socket_identity(path: &Path) -> Result<SocketIdentity, RuntimeBootstrapEndpointError> {
    fs::symlink_metadata(path)
        .map(|metadata| SocketIdentity::from_metadata(&metadata))
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))
}

struct OpenedSocketDirectory {
    path: PathBuf,
    file: File,
    identity: SocketIdentity,
    expected_uid: u32,
    expected_gid: u32,
    expected_directory_mode: u32,
    expected_socket_mode: u32,
}

struct SocketGuard {
    path: PathBuf,
    directory: OpenedSocketDirectory,
    identity: SocketIdentity,
}

impl SocketGuard {
    fn validate_directory_identity(&self) -> Result<(), RuntimeBootstrapEndpointError> {
        let opened = self
            .directory
            .file
            .metadata()
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        let named = fs::symlink_metadata(&self.directory.path)
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        validate_socket_directory_metadata(
            &opened,
            self.directory.expected_uid,
            self.directory.expected_gid,
            self.directory.expected_directory_mode,
        )?;
        if !self.directory.identity.matches(&opened) || !self.directory.identity.matches(&named) {
            return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
        }
        Ok(())
    }

    fn live_endpoint_identity_digest(&self) -> Result<Digest32, RuntimeBootstrapEndpointError> {
        self.validate_directory_identity()?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        validate_socket_metadata(
            &metadata,
            self.directory.expected_uid,
            self.directory.expected_gid,
            self.directory.expected_socket_mode,
        )?;
        if !self.identity.matches(&metadata) {
            return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
        }
        reference_local_control_endpoint_identity_digest_v1(
            self.path.as_os_str().as_bytes(),
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & MODE_MASK,
        )
        .map_err(Into::into)
    }

    fn cleanup(&self) -> Result<(), RuntimeBootstrapEndpointError> {
        remove_exact_socket(&self.directory, &self.path, self.identity)
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn remove_stale_socket_if_present(
    directory: &OpenedSocketDirectory,
    path: &Path,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(RuntimeBootstrapEndpointError::Socket(error.kind())),
    };
    validate_socket_metadata(
        &metadata,
        directory.expected_uid,
        directory.expected_gid,
        directory.expected_socket_mode,
    )?;
    match StdUnixStream::connect(path) {
        Ok(stream) => {
            drop(stream);
            return Err(RuntimeBootstrapEndpointError::SocketAlreadyActive);
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(RuntimeBootstrapEndpointError::Socket(error.kind())),
    }
    remove_exact_socket(directory, path, SocketIdentity::from_metadata(&metadata))
}

fn remove_exact_socket(
    directory: &OpenedSocketDirectory,
    path: &Path,
    expected: SocketIdentity,
) -> Result<(), RuntimeBootstrapEndpointError> {
    if path.parent() != Some(directory.path.as_path()) {
        return Err(RuntimeBootstrapEndpointError::InvalidProvisioning);
    }
    let opened = directory
        .file
        .metadata()
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    let named = fs::symlink_metadata(&directory.path)
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    if !directory.identity.matches(&opened) || !directory.identity.matches(&named) {
        return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    validate_socket_metadata(
        &metadata,
        directory.expected_uid,
        directory.expected_gid,
        directory.expected_socket_mode,
    )?;
    if !expected.matches(&metadata) {
        return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
    }
    let name: &OsStr = path
        .file_name()
        .ok_or(RuntimeBootstrapEndpointError::InvalidProvisioning)?;
    unlinkat(&directory.file, name, UnlinkatFlags::NoRemoveDir).map_err(nix_socket_error)?;
    directory
        .file
        .sync_all()
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))
}

fn live_runtime_channel(
    provisioning: &RuntimeProvisioningV1,
    guard: &SocketGuard,
) -> Result<ReferenceChannelBindingV1, RuntimeBootstrapEndpointError> {
    provisioning.validate_runtime_credentials()?;
    let endpoint_identity_digest = guard.live_endpoint_identity_digest()?;
    let runtime_pid = u64::try_from(getpid().as_raw())
        .map_err(|_| RuntimeBootstrapEndpointError::RuntimeCredentialsChanged)?;
    let peer_credentials_digest = reference_runtime_peer_credentials_digest_v1(
        provisioning.runtime_uid(),
        provisioning.runtime_gid(),
        runtime_pid,
    )?;
    ReferenceChannelBindingV1::try_new(
        provisioning.target(),
        provisioning.runtime_principal(),
        endpoint_identity_digest,
        peer_credentials_digest,
    )
    .map_err(Into::into)
}

fn nix_socket_error(error: nix::errno::Errno) -> RuntimeBootstrapEndpointError {
    RuntimeBootstrapEndpointError::Socket(io::Error::from_raw_os_error(error as i32).kind())
}

fn verify_startup_installation(
    snapshot: &RuntimeJournalSnapshot,
    target: RuntimeHostId,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<VerifiedRuntimeInstallationV1, RuntimeBootstrapEndpointError> {
    let state = snapshot.state();
    let installation = verify_pinned_startup(
        &state.host.build_descriptor.canonical_bytes,
        state.host.build_descriptor.digest,
        &state.host.singleton_manifest.canonical_bytes,
        state.host.singleton_manifest.digest,
        target,
        compiled,
    )?;
    let pinned: StorePinnedBuildIdentity = state.host.store_pinned_build_identity;
    let compiled_compatibility = compiled.compiled_reference_compatibility_digest()?;
    if state.host.compiled_build_instance_id != compiled.compiled_build_instance_id()
        || state.host.compiled_compatibility_digest != compiled_compatibility
        || pinned.build_instance_id() != installation.build_instance_id()
        || pinned.build_descriptor_digest() != installation.build_descriptor_digest()
        || pinned.runtime_artifact_sha256() != installation.runtime_artifact_sha256()
        || pinned.compiled_reference_compatibility_digest()
            != installation.compiled_reference_compatibility_digest()
    {
        return Err(RuntimeBootstrapEndpointError::BuildPinMismatch);
    }
    Ok(installation)
}

fn validate_startup_durable_control_state(
    snapshot: &RuntimeJournalSnapshot,
    manifest: &VerifiedRuntimeManifestIngressV1,
    compiled: RuntimeCompiledInstallationFactsV1,
    provisioning: &RuntimeProvisioningV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let state = snapshot.state();
    let expected_scope = *provisioning.source_scope().as_bytes();
    if state
        .writer_fence
        .is_some_and(|fence| fence.source_scope != expected_scope)
        || state
            .source_revision_high_water
            .is_some_and(|high_water| high_water.source_scope != expected_scope)
        || state
            .active_desired
            .as_ref()
            .is_some_and(|active| active.source_scope != expected_scope)
    {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }

    if let Some(prepared) = state.prepared.as_ref() {
        let historical_channel = prepared
            .response_channel
            .to_contract()
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        if historical_channel.target() != provisioning.target()
            || historical_channel.runtime_peer() != provisioning.runtime_principal()
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        let request = ReferenceApplyRequestV1::decode(&prepared.request.canonical_bytes)
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let authenticated = provisioning
            .admission_policy()
            .authenticate_reference_apply_request(&request)
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        request
            .validate_expected_store(*snapshot.store_instance_id())
            .and_then(|()| request.validate_manifest(manifest))
            .and_then(|()| {
                request
                    .target_execution()
                    .validate_compiled_fixture(compiled)
            })
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let provenance = request.provenance();
        let control = request.control_commitment().control();
        let temporal = request.temporal();
        let identities = authenticated.identities();
        let writer = control.writer_context();
        let proof_digest = writer
            .proof()
            .envelope_digest()
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let fence = state
            .writer_fence
            .ok_or(RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let prepared_tenure_recorded = state.host.tenure_nonces.iter().any(|record| {
            record.identity == identities.tenure_nonce_identity()
                && record.value_digest == proof_digest
        });
        let prepared_tenure_is_current = identities.tenure_nonce_identity()
            == fence.tenure_nonce_identity
            && proof_digest == fence.proof_envelope_digest
            && writer.writer().as_bytes() == &fence.writer
            && writer.epoch().value() == fence.epoch
            && request.authentication().claim().principal().as_bytes() == &fence.principal;
        let prepared_tenure_is_superseded = prepared_tenure_recorded
            && fence.source_scope == prepared.source_scope
            && fence.epoch > writer.epoch().value()
            && matches!(
                prepared.phase,
                PreparedPhase::SupersededBeforeEffects
                    | PreparedPhase::SupersededReconcileRequired
                    | PreparedPhase::StartupExpiredNoEffects
                    | PreparedPhase::StartupReconcileRequired
            );
        let expected_active_matches = match (control.expected_active(), prepared.expected_active) {
            (ExpectedActive::None, ExpectedActiveCas::None) => true,
            (ExpectedActive::Exact(left), ExpectedActiveCas::Exact(right)) => left == right,
            _ => false,
        };
        let mode_matches = matches!(
            (request.target_execution().mode(), prepared.incoming_kind),
            (
                ReferenceAssemblyModeV1::OneSourceLoop,
                DesiredHeadKind::OneSourceLoop
            ) | (
                ReferenceAssemblyModeV1::EmptyDeactivate,
                DesiredHeadKind::EmptyDeactivate
            )
        );
        if request.canonical_wire() != prepared.request.canonical_bytes.as_ref()
            || request.envelope_request_digest() != prepared.request.digest
            || request.target() != provisioning.target()
            || provenance != prepared.slice_provenance.plan_provenance()
            || request.assignment_digest() != prepared.slice_provenance.assignment_digest
            || request.target_slice_digest() != prepared.slice_provenance.target_slice_digest
            || request.target_slice_digest() != prepared.incoming_slice_digest
            || request.target_execution().manifest_digest() != prepared.manifest_digest
            || control.operation_id().as_bytes() != &prepared.operation_id
            || !expected_active_matches
            || !mode_matches
            || identities.request_nonce_identity() != prepared.request_nonce_identity
            || identities.temporal_lineage_digest() != prepared.temporal_lineage_digest
            || temporal.constraint_id().as_bytes() != &prepared.temporal_constraint_id
            || temporal.target_clock_domain().as_bytes() != &state.host.clock_domain
            || temporal.target_clock_generation().value() != prepared.installed_clock_generation
            || !prepared_tenure_recorded
            || (!prepared_tenure_is_current && !prepared_tenure_is_superseded)
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        if let Some(retiring) = prepared.retiring.as_ref() {
            validate_startup_durable_slice(
                &retiring.old_slice.canonical_bytes,
                retiring.old_slice_provenance,
                DesiredHeadKind::OneSourceLoop,
                manifest,
                compiled,
            )?;
        }
    }

    if let Some(active) = state.active_desired.as_ref() {
        validate_startup_durable_slice(
            &active.slice.canonical_bytes,
            active.slice_provenance,
            active.kind,
            manifest,
            compiled,
        )?;
    }

    if let Some(recovery) = state.recovery_action {
        let active = state
            .active_desired
            .as_ref()
            .ok_or(RuntimeBootstrapEndpointError::InvalidStartedState)?;
        if recovery.source_scope != expected_scope
            || recovery.slice_provenance != active.slice_provenance
            || recovery.active_slice_digest != active.slice_provenance.target_slice_digest
            || recovery.manifest_digest != manifest.manifest_digest()
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
    }
    for terminal in &state.recovery_terminals {
        let recovery = terminal.recovery;
        if recovery.source_scope != expected_scope
            || recovery.slice_provenance.target != *provisioning.target().as_bytes()
            || recovery.slice_provenance.source_scope != recovery.source_scope
            || recovery.slice_provenance.source_revision != recovery.source_revision
            || recovery.slice_provenance.source_plan_digest != recovery.source_plan_digest
            || recovery.slice_provenance.target_slice_digest != recovery.active_slice_digest
            || recovery.manifest_digest != manifest.manifest_digest()
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
    }
    for terminal in &state.terminal_operations {
        if terminal.source_scope != expected_scope
            || terminal.slice_provenance.target != *provisioning.target().as_bytes()
            || terminal.slice_provenance.source_scope != terminal.source_scope
            || terminal.slice_provenance.source_revision != terminal.source_revision
            || terminal.slice_provenance.source_plan_digest != terminal.source_plan_digest
            || terminal.slice_provenance.target_slice_digest != terminal.target_slice_digest
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        validate_startup_terminal_producer(snapshot, terminal, provisioning)?;
    }
    Ok(())
}

fn validate_startup_durable_slice(
    canonical_slice: &[u8],
    provenance: crate::runtime_journal::DurableSliceProvenance,
    expected_kind: DesiredHeadKind,
    manifest: &VerifiedRuntimeManifestIngressV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let execution = verify_reference_durable_slice_v1(
        canonical_slice,
        provenance.plan_provenance(),
        provenance.target_slice_digest,
        manifest,
    )
    .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    execution
        .validate_compiled_fixture(compiled)
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    let mode_matches = matches!(
        (execution.mode(), expected_kind),
        (
            ReferenceAssemblyModeV1::OneSourceLoop,
            DesiredHeadKind::OneSourceLoop
        ) | (
            ReferenceAssemblyModeV1::EmptyDeactivate,
            DesiredHeadKind::EmptyDeactivate
        )
    );
    if !mode_matches {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }
    Ok(())
}

fn startup_active_execution(
    snapshot: &RuntimeJournalSnapshot,
    manifest: &VerifiedRuntimeManifestIngressV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<Option<ReferenceTargetExecutionPlanV4>, RuntimeBootstrapEndpointError> {
    let state = snapshot.state();
    let slice = if let Some(prepared) = state.prepared.as_ref() {
        if let Some(retiring) = prepared.retiring.as_ref() {
            Some((
                retiring.old_slice.canonical_bytes.as_ref(),
                retiring.old_slice_provenance,
            ))
        } else if prepared.incoming_kind == DesiredHeadKind::OneSourceLoop {
            let request = ReferenceApplyRequestV1::decode(&prepared.request.canonical_bytes)
                .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
            request
                .target_execution()
                .validate_compiled_fixture(compiled)
                .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
            return Ok(Some(request.target_execution().clone()));
        } else {
            state
                .active_desired
                .as_ref()
                .filter(|active| active.kind == DesiredHeadKind::OneSourceLoop)
                .map(|active| {
                    (
                        active.slice.canonical_bytes.as_ref(),
                        active.slice_provenance,
                    )
                })
        }
    } else {
        state
            .active_desired
            .as_ref()
            .filter(|active| active.kind == DesiredHeadKind::OneSourceLoop)
            .map(|active| {
                (
                    active.slice.canonical_bytes.as_ref(),
                    active.slice_provenance,
                )
            })
    };
    let Some((canonical_slice, provenance)) = slice else {
        return Ok(None);
    };
    let execution = verify_reference_durable_slice_v1(
        canonical_slice,
        provenance.plan_provenance(),
        provenance.target_slice_digest,
        manifest,
    )
    .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    execution
        .validate_compiled_fixture(compiled)
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    Ok(Some(execution))
}

fn validate_startup_terminal_producer(
    snapshot: &RuntimeJournalSnapshot,
    terminal: &crate::runtime_journal::TerminalOperationRecord,
    provisioning: &RuntimeProvisioningV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let receipt =
        ReferenceApplyTerminalReceiptV1::decode(&terminal.canonical_response.canonical_bytes)
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    if receipt.canonical_wire() != terminal.canonical_response.canonical_bytes.as_ref()
        || receipt.target() != provisioning.target()
        || receipt.runtime_store_instance_id() != *snapshot.store_instance_id()
        || receipt.source_scope().as_bytes() != &terminal.source_scope
        || receipt.operation_id().as_bytes() != &terminal.operation_id
        || receipt.request_digest() != terminal.request_digest
        || receipt.authentication_runtime_peer() != provisioning.runtime_principal()
        || receipt.authentication_key() != provisioning.runtime_response_key_ref()
        || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
        || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }
    let signature = parse_terminal_signature(receipt.authentication_signature())?;
    let transcript = receipt
        .signing_transcript()
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    provisioning
        .response_signer()
        .verifying_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)
}

fn parse_terminal_signature(signature: &[u8]) -> Result<Signature, RuntimeBootstrapEndpointError> {
    let bytes: &[u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    Ok(Signature::from_bytes(bytes))
}

fn map_bootstrap_state(state: RuntimeJournalBootstrapState) -> ReferenceBootstrapStateV1 {
    match state {
        RuntimeJournalBootstrapState::ReadyForApply => ReferenceBootstrapStateV1::ReadyForApply,
        RuntimeJournalBootstrapState::NotReadyRecovering => {
            ReferenceBootstrapStateV1::NotReadyRecovering
        }
        RuntimeJournalBootstrapState::ValidatedOperationalQuarantine => {
            ReferenceBootstrapStateV1::ValidatedOperationalQuarantine
        }
        RuntimeJournalBootstrapState::RecoveryFailedNotReady => {
            ReferenceBootstrapStateV1::RecoveryFailedNotReady
        }
        RuntimeJournalBootstrapState::NotReadyBusy => ReferenceBootstrapStateV1::NotReadyBusy,
    }
}

fn map_bootstrap_reason(reason: RuntimeJournalBootstrapReason) -> ReferenceOperationalReasonV1 {
    match reason {
        RuntimeJournalBootstrapReason::Recovering => ReferenceOperationalReasonV1::Recovering,
        RuntimeJournalBootstrapReason::RecoveryFailed => {
            ReferenceOperationalReasonV1::RecoveryFailed
        }
        RuntimeJournalBootstrapReason::OwnershipUncertain => {
            ReferenceOperationalReasonV1::OwnershipUncertain
        }
        RuntimeJournalBootstrapReason::RuntimeBusy => ReferenceOperationalReasonV1::RuntimeBusy,
    }
}

struct RuntimeBootstrapCore<'a> {
    facts: ReferenceBootstrapFactsV1,
    channel: ReferenceChannelBindingV1,
    provisioning: &'a RuntimeProvisioningV1,
}

impl RuntimeBootstrapCore<'_> {
    fn handle_request(&self, frame: &[u8]) -> Result<Box<[u8]>, RuntimeBootstrapRequestError> {
        if frame.is_empty() || frame.len() > MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES {
            return Err(RuntimeBootstrapRequestError::InvalidFrameLength);
        }
        let request = ReferenceBootstrapRequestV1::decode(frame)
            .map_err(|_| RuntimeBootstrapRequestError::InvalidCanonicalRequest)?;
        authenticate_request(self.provisioning, &request)?;
        let auth_claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            self.channel,
            self.provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?,
            ED25519_ALGORITHM_VERSION,
        )
        .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?;
        let draft = ReferenceBootstrapResponseDraftV1::try_new(
            &request,
            self.facts,
            self.channel,
            auth_claim,
        )
        .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?;
        let signature = self
            .provisioning
            .response_signer()
            .sign(
                draft
                    .signing_transcript()
                    .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?
                    .as_bytes(),
            )
            .to_bytes();
        let response = draft
            .finalize(&signature)
            .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?;
        let wire = response.canonical_wire();
        if wire.len() > MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES
            || wire.len() > request.max_response_bytes() as usize
        {
            return Err(RuntimeBootstrapRequestError::ResponseBoundExceeded);
        }
        Ok(wire.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeBootstrapRequestError {
    InvalidFrameLength,
    InvalidCanonicalRequest,
    Unauthorized,
    InvalidSignature,
    ResponseBoundExceeded,
    InternalContract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeQueryRequestError {
    InvalidCanonicalRequest,
    Unauthorized,
    StoreMismatch,
    InvalidSignature,
}

/// Lifecycle stage attached to every Runtime service failure retained across
/// startup rollback or shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeBootstrapFailureStageV1 {
    Primary,
    Successor,
    RestrictedEndpoint,
    LocalSocketCleanup,
}

impl RuntimeBootstrapFailureStageV1 {
    const fn order(self) -> u8 {
        match self {
            Self::Primary => 0,
            Self::Successor => 1,
            Self::RestrictedEndpoint => 2,
            Self::LocalSocketCleanup => 3,
        }
    }
}

/// One typed lifecycle failure. The boxed error is the explicit recursion
/// boundary that keeps the endpoint error enum finite and compact even when an
/// aggregation is itself passed through another cleanup boundary.
pub(crate) struct RuntimeBootstrapFailureV1 {
    stage: RuntimeBootstrapFailureStageV1,
    error: Box<RuntimeBootstrapEndpointError>,
}

impl fmt::Debug for RuntimeBootstrapFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeBootstrapFailureV1")
            .field("stage", &self.stage)
            .field("error", &self.error)
            .finish()
    }
}

/// Ordered, lossless lifecycle failure set.
#[derive(Debug)]
pub(crate) struct RuntimeBootstrapFailureSetV1 {
    failures: Box<[RuntimeBootstrapFailureV1]>,
}

impl RuntimeBootstrapFailureSetV1 {
    pub(crate) fn len(&self) -> usize {
        self.failures.len()
    }

    fn into_failures(self) -> Box<[RuntimeBootstrapFailureV1]> {
        self.failures
    }
}

/// Fail-closed Runtime bootstrap startup/service error.
#[derive(Debug)]
pub(crate) enum RuntimeBootstrapEndpointError {
    StagedFailures(RuntimeBootstrapFailureSetV1),
    InvalidProvisioning,
    ProvisioningPinMismatch,
    BuildPinMismatch,
    InvalidStartedState,
    Runtime,
    RuntimeClock,
    UnsafeSocketDirectory,
    UnsafeSocket,
    SocketAlreadyActive,
    SocketIdentityChanged,
    RuntimeCredentialsChanged,
    Provisioning(RuntimeProvisioningError),
    Installation(RuntimeInstallationError),
    ControlContract(ReferenceControlError),
    ControlState(RuntimeControlStateError),
    Apply(RuntimeReferenceApplyError),
    ManagedFabricContract(ManagedFabricPlanError),
    ManagedAgentStackContract(ManagedAgentStackPlanError),
    ManagedModelAgentStackContract(ManagedModelAgentStackPlanError),
    DistributedAgentStackContract(DistributedAgentStackPlanError),
    ManagedServingContract(ManagedServingBootstrapError),
    ManagedFabricState(ManagedFabricStateError),
    ManagedFabricStore(ManagedFabricStoreError),
    ManagedFabric(ManagedFabricRuntimeError),
    ManagedAgentStack(ManagedAgentStackRuntimeError),
    ManagedModelAgentStack(ManagedModelAgentStackRuntimeError),
    DistributedAgentStack(DistributedAgentStackRuntimeError),
    DistributedAgentStackRestartRequired,
    RestrictedRuntimeApply(RestrictedRuntimeApplyErrorV1),
    RestrictedRuntimeApplyOwner(RuntimeRestrictedRemoteApplyErrorV1),
    RestrictedRuntimeApplyResponseHandoff(RestrictedRuntimeApplyRespondErrorV1),
    RestartReassembly(RuntimeRestartReassemblyError),
    StoreOpen(RuntimeStoreOpenError),
    Store(RuntimeStoreError),
    Socket(io::ErrorKind),
}

impl From<RuntimeInstallationError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeInstallationError) -> Self {
        Self::Installation(error)
    }
}

impl From<RuntimeProvisioningError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeProvisioningError) -> Self {
        Self::Provisioning(error)
    }
}

impl From<ReferenceControlError> for RuntimeBootstrapEndpointError {
    fn from(error: ReferenceControlError) -> Self {
        Self::ControlContract(error)
    }
}

impl From<RuntimeControlStateError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeControlStateError) -> Self {
        Self::ControlState(error)
    }
}

impl From<RuntimeStoreOpenError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeStoreOpenError) -> Self {
        Self::StoreOpen(error)
    }
}

impl From<RuntimeStoreError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ManagedFabricPlanError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedFabricPlanError) -> Self {
        Self::ManagedFabricContract(error)
    }
}

impl From<ManagedAgentStackPlanError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedAgentStackPlanError) -> Self {
        Self::ManagedAgentStackContract(error)
    }
}

impl From<ManagedModelAgentStackPlanError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedModelAgentStackPlanError) -> Self {
        Self::ManagedModelAgentStackContract(error)
    }
}

impl From<DistributedAgentStackPlanError> for RuntimeBootstrapEndpointError {
    fn from(error: DistributedAgentStackPlanError) -> Self {
        Self::DistributedAgentStackContract(error)
    }
}

impl From<ManagedServingBootstrapError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedServingBootstrapError) -> Self {
        Self::ManagedServingContract(error)
    }
}

impl From<ManagedFabricStateError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedFabricStateError) -> Self {
        Self::ManagedFabricState(error)
    }
}

impl From<ManagedFabricStoreError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedFabricStoreError) -> Self {
        Self::ManagedFabricStore(error)
    }
}

impl From<ManagedFabricRuntimeError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedFabricRuntimeError) -> Self {
        Self::ManagedFabric(error)
    }
}

impl From<ManagedAgentStackRuntimeError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedAgentStackRuntimeError) -> Self {
        Self::ManagedAgentStack(error)
    }
}

impl From<ManagedModelAgentStackRuntimeError> for RuntimeBootstrapEndpointError {
    fn from(error: ManagedModelAgentStackRuntimeError) -> Self {
        Self::ManagedModelAgentStack(error)
    }
}

impl From<DistributedAgentStackRuntimeError> for RuntimeBootstrapEndpointError {
    fn from(error: DistributedAgentStackRuntimeError) -> Self {
        Self::DistributedAgentStack(error)
    }
}

impl From<RestrictedRuntimeApplyErrorV1> for RuntimeBootstrapEndpointError {
    fn from(error: RestrictedRuntimeApplyErrorV1) -> Self {
        Self::RestrictedRuntimeApply(error)
    }
}

impl From<RuntimeRestartReassemblyError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeRestartReassemblyError) -> Self {
        Self::RestartReassembly(error)
    }
}

impl fmt::Display for RuntimeBootstrapEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StagedFailures(failures) => write!(
                formatter,
                "Runtime lifecycle reported {} staged failure(s)",
                failures.len()
            ),
            Self::InvalidProvisioning => formatter.write_str("invalid bootstrap provisioning"),
            Self::ProvisioningPinMismatch => {
                formatter.write_str("bootstrap provisioning does not match journal pins")
            }
            Self::BuildPinMismatch => formatter.write_str("Runtime build pins do not match"),
            Self::InvalidStartedState => formatter.write_str("invalid post-start Runtime state"),
            Self::Runtime => formatter.write_str("bootstrap reactor failed"),
            Self::RuntimeClock => formatter.write_str("Runtime owner clock observation failed"),
            Self::UnsafeSocketDirectory => formatter.write_str("unsafe bootstrap socket directory"),
            Self::UnsafeSocket => formatter.write_str("unsafe bootstrap socket"),
            Self::SocketAlreadyActive => {
                formatter.write_str("bootstrap socket already has a live owner")
            }
            Self::SocketIdentityChanged => formatter.write_str("bootstrap socket identity changed"),
            Self::RuntimeCredentialsChanged => {
                formatter.write_str("Runtime service credentials changed")
            }
            Self::Provisioning(error) => write!(formatter, "Runtime provisioning: {error}"),
            Self::Installation(error) => write!(formatter, "startup installation: {error}"),
            Self::ControlContract(error) => write!(formatter, "bootstrap contract: {error}"),
            Self::ControlState(error) => write!(formatter, "Runtime control state: {error:?}"),
            Self::Apply(error) => write!(formatter, "Runtime reference apply: {error:?}"),
            Self::ManagedFabricContract(error) => {
                write!(formatter, "managed Fabric contract: {error}")
            }
            Self::ManagedAgentStackContract(error) => {
                write!(formatter, "managed Agent-stack contract: {error}")
            }
            Self::ManagedModelAgentStackContract(error) => {
                write!(formatter, "managed Model+Agent-stack contract: {error}")
            }
            Self::DistributedAgentStackContract(error) => {
                write!(formatter, "distributed Agent-stack contract: {error:?}")
            }
            Self::ManagedServingContract(error) => {
                write!(formatter, "managed serving contract: {error}")
            }
            Self::ManagedFabricState(error) => {
                write!(formatter, "managed Fabric durable state: {error}")
            }
            Self::ManagedFabricStore(error) => {
                write!(formatter, "managed Fabric store: {error}")
            }
            Self::ManagedFabric(error) => write!(formatter, "managed Fabric Runtime: {error}"),
            Self::ManagedAgentStack(error) => {
                write!(formatter, "managed Agent-stack Runtime: {error}")
            }
            Self::ManagedModelAgentStack(error) => {
                write!(formatter, "managed Model+Agent-stack Runtime: {error}")
            }
            Self::DistributedAgentStack(error) => {
                write!(formatter, "distributed Agent-stack Runtime: {error}")
            }
            Self::DistributedAgentStackRestartRequired => {
                formatter.write_str("distributed Agent-stack owner requires restart recovery")
            }
            Self::RestrictedRuntimeApply(error) => {
                write!(formatter, "restricted Runtime apply transport: {error}")
            }
            Self::RestrictedRuntimeApplyOwner(error) => {
                write!(formatter, "restricted Runtime apply owner: {error}")
            }
            Self::RestrictedRuntimeApplyResponseHandoff(error) => {
                write!(
                    formatter,
                    "restricted Runtime apply response handoff: {error}"
                )
            }
            Self::RestartReassembly(error) => {
                write!(formatter, "Runtime restart reassembly: {error:?}")
            }
            Self::StoreOpen(error) => write!(formatter, "Runtime store open: {error}"),
            Self::Store(error) => write!(formatter, "Runtime store: {error}"),
            Self::Socket(kind) => write!(formatter, "bootstrap socket I/O: {kind:?}"),
        }
    }
}

impl std::error::Error for RuntimeBootstrapEndpointError {}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start_offset = source
            .find(start)
            .unwrap_or_else(|| panic!("missing section start: {start}"));
        let tail = &source[start_offset..];
        let end_offset = tail
            .find(end)
            .unwrap_or_else(|| panic!("missing section end: {end}"));
        &tail[..end_offset]
    }

    use paraegox_agent_contracts::{
        AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
        AgentConversationSessionId, AgentConversationTerminalResultV1, AgentConversationTurnId,
    };
    use paraegox_agent_service::DeterministicEchoModelProvider;
    use paraegox_evidence::{EvidenceOwnerRefV1, EvidenceRetentionPolicyV1, EvidenceStoreEpochV1};
    use paraegox_fabric::ResolvedRemoteMtlsIdentityFiles;
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_model::{
        ModelBackendFuture, ModelBackendIdentityV1, ModelBackendV1, ModelCancellationViewV1,
        ModelInvocationOutcomeV1, ModelInvocationRequestV1,
    };
    use paraegox_runtime_contracts::{
        apply::{
            ApplyOperationId, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
            RuntimeApplyControl, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
            TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
        },
        assignment::InstanceRef,
        distributed_agent_stack_plan::{
            DistributedAgentStackApplyRequestDraftV1,
            DistributedAgentStackLocalBindingEvidenceFieldsV1,
            DistributedAgentStackRestrictedApplyRequestDraftV1,
            DistributedAgentStackTargetExecutionV1, DistributedAgentStackTerminalAuthClaimV1,
            DistributedAgentStackTerminalEvidenceFieldsV1,
            DistributedAgentStackTerminalObservationsV1, DistributedAgentStackTerminalOutcomeV1,
            DistributedAgentStackTerminalReceiptDraftV1, DistributedAgentStackTerminalReceiptV2,
            DistributedFabricCredentialRefV1, DistributedFabricObservedTransportProofFieldsV1,
            DistributedFabricObservedTransportProofV1,
            DistributedFabricPeerAuthenticationRequirementV1, DistributedFabricPeerIdentityRefV1,
            DistributedFabricPeerPlanV1, DistributedFabricSessionEpochV1,
            DistributedFabricTlsEndpointV1, DistributedFabricTopologyV1,
            DistributedFabricTransportEvidenceRefV1, DistributedFabricTrustAnchorRefV1,
            DistributedFabricTrustDomainRefV1, RestrictedRuntimeApplyCarrierBindingFieldsV1,
            RestrictedRuntimeApplyTransportProfileFieldsV1,
            RestrictedRuntimeApplyTransportProfileV1,
            distributed_agent_stack_installed_binding_set_digest_v1,
        },
        execution::{CardDefinitionRef, CardImplementationRef, DomainRef},
        installation::{
            InstalledRuntimeArtifactObservationV1, generate_build_descriptor, generate_manifest,
        },
        managed_agent_stack_plan::{
            ManagedAgentIngressLimitsV1, ManagedAgentPortPlanV1, ManagedAgentProviderProfileV1,
            ManagedAgentProviderRefV1, ManagedAgentProviderSelectionV1,
            ManagedAgentSemanticLimitsV1, ManagedAgentServicePlanV1,
            ManagedAgentStackApplyRequestDraftV1, ManagedAgentStackTargetExecutionV1,
            ManagedAgentStackTerminalOutcomeV1, ManagedAgentStackTerminalReceiptV1,
        },
        managed_fabric_plan::{
            ManagedFabricApplyRequestDraftV1, ManagedFabricApplyRequestV1,
            ManagedFabricApplyTerminalOutcomeV1, ManagedFabricApplyTerminalReceiptV1,
            ManagedFabricListenEndpointV1, ManagedFabricTargetExecutionV1,
        },
        managed_model_agent_stack_plan::{
            ManagedModelAdapterBindingV1, ManagedModelAdapterVersionV1,
            ManagedModelAgentStackApplyRequestDraftV1, ManagedModelAgentStackTargetExecutionV1,
            ManagedModelAgentStackTerminalOutcomeV1, ManagedModelAgentStackTerminalReceiptV1,
            ManagedModelCapabilityIdV1, ManagedModelServicePlanV1,
        },
        managed_service::{
            ManagedServiceGeneration, ManagedServiceId, ManagedServiceLifecycleBudgetsV1,
            ManagedServiceSpecV1,
        },
        managed_serving_bootstrap::{
            ManagedServingBootstrapRequestDraftV1, ManagedServingBootstrapRequestIdV1,
            ManagedServingBootstrapResponseV1, ManagedServingReadinessV1,
            RuntimeAgentControlReceiptV1, RuntimeAgentControlRequestDraftV1,
            RuntimeAgentControlRequestFieldsV1, RuntimeAgentControlRequestIdV1,
            RuntimeControlCarrierRequestDraftV1, RuntimeControlDescribeReadyResponseV1,
        },
        provenance::{PlanProvenance, SourcePlanDigest, SourcePlanRef, SourcePlanRevision},
        reference_control::{
            ReferenceApplyRequestDraftV1, ReferenceApplyTerminalOutcomeV1, ReferenceAssemblyModeV1,
            ReferenceBootstrapRequestDraftV1, ReferenceBootstrapRequestIdV1,
            ReferenceBootstrapResponseV1, ReferenceQueryIdV1, ReferenceQueryRequestDraftV1,
            ReferenceQueryResponseV1, ReferenceQuerySelectorV1, ReferenceTargetExecutionPlanV4,
            ValidatedReferenceLifecycleBudgetsV1,
        },
        temporal::{ApplyTemporalConstraint, TemporalConstraintId},
        wire::ApplyRequestAuthClaim,
    };

    use super::*;
    use crate::distributed_fabric_runtime::{
        RuntimeFabricCredentialRequirementV1, RuntimeFabricCredentialResolveErrorV2,
        RuntimeResolvedFabricPeerCredentialV2,
    };
    use crate::managed_model_runtime::{
        RuntimeModelBackendResolveError, RuntimeResolvedModelBackendV1,
    };
    use crate::runtime_agent_provider::{
        RuntimeAgentProviderResolveError, RuntimeResolvedAgentProviderV1,
    };
    use crate::runtime_control_state::runtime_reference_apply::{
        RuntimeEmptyRetireOwnerPlan, RuntimeOneSourceOwnerPlan, RuntimeReferenceApplyStoreError,
        RuntimeReferenceMaterializationOwnerError,
    };
    use crate::runtime_control_state::runtime_reference_owner::{
        fixed_owner_start_callback_actions_for_test, fixed_owner_stop_callback_actions_for_test,
        reset_fixed_owner_callback_actions_for_test,
    };
    use crate::runtime_journal::{
        CallbackOutcome, JournalActionRef, LiveMaterialization, OpaqueCanonicalValue,
        RecoveryPhase, RuntimeJournalSequenceOne, RuntimeOneSourceOwnershipInput,
        RuntimeOneSourceResourceRefs, RuntimeOneSourceTombstonesInput, RuntimeTenureAdmissionInput,
        StorePinnedBuildIdentity, TerminalOutcome,
    };
    use crate::runtime_provisioning::RuntimeProvisioningInputV1;
    use crate::runtime_store::{
        ManagedFabricStore,
        tests::{TestDirectory, managed_fabric_store_fixture_from_snapshot},
    };

    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x11; 16]);
    const SOURCE_SCOPE: SourceScopeRef = SourceScopeRef::from_bytes([0x21; 16]);
    const CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x31; 16]);
    const CONTROLLER_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x32; 16]);
    const RUNTIME_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x33; 16]);
    const RESPONSE_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x34; 16]);
    const WRITER: PlanWriterRef = PlanWriterRef::from_bytes([0x35; 16]);
    const AUTHORITY_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x36; 16]);
    const TENURE_AUTHORITY_REF: TenureAuthorityRef = TenureAuthorityRef::from_bytes([0x37; 16]);
    const TENURE_KEY_REF: TenureKeyRef = TenureKeyRef::from_bytes([0x38; 16]);
    const CONTROLLER_SEED: [u8; 32] = [0x41; 32];
    const RESPONSE_SEED: [u8; 32] = [0x42; 32];
    const TENURE_SEED: [u8; 32] = [0x43; 32];
    const STORE_INSTANCE_ID: [u8; 32] = [0x51; 32];
    const CLOCK_DOMAIN: [u8; 16] = [0x52; 16];

    struct DeterministicFixtureResolver;

    impl RuntimeAgentProviderResolverV1 for DeterministicFixtureResolver {
        fn resolve(
            &self,
            selection: ManagedAgentProviderSelectionV1,
        ) -> Result<RuntimeResolvedAgentProviderV1, RuntimeAgentProviderResolveError> {
            if selection.profile() != ManagedAgentProviderProfileV1::DeterministicFixture {
                return Err(RuntimeAgentProviderResolveError::ResolutionFailed);
            }
            Ok(RuntimeResolvedAgentProviderV1::new(
                selection,
                DeterministicEchoModelProvider::new(),
            ))
        }
    }

    #[derive(Clone)]
    struct EndpointModelBackend {
        identity: ModelBackendIdentityV1,
    }

    impl ModelBackendV1 for EndpointModelBackend {
        fn identity(&self) -> ModelBackendIdentityV1 {
            self.identity
        }

        fn invoke(
            &self,
            request: ModelInvocationRequestV1,
            _cancellation: ModelCancellationViewV1,
        ) -> ModelBackendFuture {
            let output = format!("endpoint-model: {}", request.prompt()).into_boxed_str();
            Box::pin(async move { ModelInvocationOutcomeV1::Success(output) })
        }
    }

    struct DeterministicModelBackendResolver;

    impl RuntimeModelBackendResolverV1 for DeterministicModelBackendResolver {
        fn resolve(
            &self,
            plan: &ManagedModelServicePlanV1,
        ) -> Result<RuntimeResolvedModelBackendV1, RuntimeModelBackendResolveError> {
            let identity = ModelBackendIdentityV1::try_new(
                *plan.provider().provider_ref().as_bytes(),
                plan.provider().config_digest(),
            )
            .map_err(|_| RuntimeModelBackendResolveError::ResolutionFailed)?;
            Ok(RuntimeResolvedModelBackendV1::new(
                *plan,
                EndpointModelBackend { identity },
            ))
        }
    }

    fn deterministic_fixture_service_dependencies() -> RuntimeManagedFabricServiceDependenciesV1 {
        RuntimeManagedFabricServiceDependenciesV1::new(
            Arc::new(DeterministicFixtureResolver),
            unavailable_model_backend_resolver(),
            None,
            None,
        )
    }

    fn model_fixture_service_dependencies() -> RuntimeManagedFabricServiceDependenciesV1 {
        RuntimeManagedFabricServiceDependenciesV1::new(
            Arc::new(DeterministicFixtureResolver),
            Arc::new(DeterministicModelBackendResolver),
            None,
            None,
        )
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    const RESTRICTED_APPLY_ROUTE: &str = "paraegox/runtime/endpoint-stack/restricted/apply";
    const RESTRICTED_TLS_LISTENER: &str = "tls/192.0.2.10:7447";
    const RESTRICTED_PROFILE_REF: [u8; 16] = [0xd7; 16];
    const RESTRICTED_ENDPOINT_REF: [u8; 16] = [0xd6; 16];
    const RESTRICTED_ENDPOINT_GENERATION: u64 = 1;
    const RESTRICTED_OPERATION_TIMEOUT_NANOS: u64 = 5_000_000_000;

    fn restricted_transport_profile(
        route: &str,
        tls_listener_locator: &str,
        endpoint_generation: u64,
        operation_timeout_nanos: u64,
    ) -> RestrictedRuntimeApplyTransportProfileV1 {
        RestrictedRuntimeApplyTransportProfileV1::try_new(
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                target: TARGET,
                endpoint_ref: RESTRICTED_ENDPOINT_REF,
                endpoint_generation,
                tls_listener_locator,
                route,
                trust_domain_ref: DistributedFabricTrustDomainRefV1::try_from_bytes([0xd9; 16])
                    .unwrap_or_else(|error| panic!("restricted trust domain rejected: {error}")),
                trust_anchor_ref: DistributedFabricTrustAnchorRefV1::try_from_bytes([0xda; 16])
                    .unwrap_or_else(|error| panic!("restricted trust anchor rejected: {error}")),
                controller_connector_credential_ref:
                    DistributedFabricCredentialRefV1::try_from_bytes([0xdb; 16]).unwrap_or_else(
                        |error| panic!("restricted Controller credential rejected: {error}"),
                    ),
                runtime_listener_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                    [0xdc; 16],
                )
                .unwrap_or_else(|error| panic!("restricted Runtime credential rejected: {error}")),
                controller_principal: CONTROLLER_PRINCIPAL,
                runtime_principal: RUNTIME_PRINCIPAL,
                operation_timeout_nanos,
            },
        )
        .unwrap_or_else(|error| panic!("restricted transport profile rejected: {error}"))
    }

    fn restricted_endpoint_config(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        profile_ref: [u8; 16],
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    ) -> RestrictedRuntimeApplyEndpointConfigV1 {
        RestrictedRuntimeApplyEndpointConfigV1::try_from_transport_profile(
            profile,
            profile_ref,
            carrier,
            PathBuf::from("/tmp/paraegox-restricted-root-ca.pem"),
            ResolvedRemoteMtlsIdentityFiles::try_new(
                PathBuf::from("/tmp/paraegox-restricted-runtime.pem"),
                PathBuf::from("/tmp/paraegox-restricted-runtime.key"),
            )
            .unwrap_or_else(|error| panic!("restricted identity files rejected: {error}")),
        )
        .unwrap_or_else(|error| panic!("restricted endpoint config rejected: {error}"))
    }

    fn restricted_control_endpoint_config(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        profile_ref: [u8; 16],
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    ) -> RestrictedRuntimeControlEndpointConfigV1 {
        RestrictedRuntimeControlEndpointConfigV1::try_from_transport_profile(
            profile,
            profile_ref,
            carrier,
            PathBuf::from("/tmp/paraegox-restricted-root-ca.pem"),
            ResolvedRemoteMtlsIdentityFiles::try_new(
                PathBuf::from("/tmp/paraegox-restricted-runtime.pem"),
                PathBuf::from("/tmp/paraegox-restricted-runtime.key"),
            )
            .unwrap_or_else(|error| panic!("restricted identity files rejected: {error}")),
        )
        .unwrap_or_else(|error| panic!("restricted control endpoint config rejected: {error}"))
    }

    fn restricted_carrier_with_profile_digest(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        profile_ref: [u8; 16],
        profile_digest: Digest32,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        let controller_key_fingerprint = ed25519_control_key_fingerprint(
            SigningKey::from_bytes(&CONTROLLER_SEED)
                .verifying_key()
                .as_bytes(),
        )
        .unwrap_or_else(|error| panic!("restricted Controller fingerprint failed: {error}"));
        let runtime_response_key_fingerprint = ed25519_control_key_fingerprint(
            SigningKey::from_bytes(&RESPONSE_SEED)
                .verifying_key()
                .as_bytes(),
        )
        .unwrap_or_else(|error| panic!("restricted Runtime fingerprint failed: {error}"));
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: profile.target(),
                runtime_principal: profile.runtime_principal(),
                controller_principal: profile.controller_principal(),
                endpoint_ref: profile.endpoint_ref(),
                endpoint_generation: profile.endpoint_generation(),
                route: profile.route(),
                controller_request_key: CONTROLLER_KEY_REF,
                controller_request_key_fingerprint: controller_key_fingerprint,
                runtime_response_key: RESPONSE_KEY_REF,
                runtime_response_key_fingerprint,
                control_transport_profile_ref: profile_ref,
                control_transport_profile_digest: profile_digest,
            },
        )
        .unwrap_or_else(|error| panic!("restricted expected carrier rejected: {error}"))
    }

    fn restricted_carrier_for_profile(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        profile_ref: [u8; 16],
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        restricted_carrier_with_profile_digest(profile, profile_ref, profile.profile_digest())
    }

    fn runtime_control_auth_claim(nonce: &[u8]) -> ApplyRequestAuthClaim {
        ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("control-carrier algorithm rejected: {error}")),
            ED25519_ALGORITHM_VERSION,
            nonce,
        )
        .unwrap_or_else(|error| panic!("control-carrier claim rejected: {error}"))
    }

    fn signed_runtime_control_describe(
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        request_id_byte: u8,
        nonce: &[u8],
        signing_seed: [u8; 32],
    ) -> RuntimeControlCarrierRequestV1 {
        let draft = RuntimeControlCarrierRequestDraftV1::try_describe(
            ManagedServingBootstrapRequestIdV1::try_from_bytes([request_id_byte; 16])
                .unwrap_or_else(|error| panic!("Describe request ID rejected: {error}")),
            carrier,
            runtime_control_auth_claim(nonce),
        )
        .unwrap_or_else(|error| panic!("Describe carrier draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&signing_seed)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("Describe carrier transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("Describe carrier finalization failed: {error}"))
    }

    fn signed_runtime_control_reference_query(
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        query: ReferenceQueryRequestV1,
        request_id_byte: u8,
        nonce: &[u8],
    ) -> RuntimeControlCarrierRequestV1 {
        let draft = RuntimeControlCarrierRequestDraftV1::try_reference_query(
            ManagedServingBootstrapRequestIdV1::try_from_bytes([request_id_byte; 16])
                .unwrap_or_else(|error| panic!("ReferenceQuery request ID rejected: {error}")),
            carrier,
            query,
            runtime_control_auth_claim(nonce),
        )
        .unwrap_or_else(|error| panic!("ReferenceQuery carrier draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| {
                        panic!("ReferenceQuery carrier transcript failed: {error}")
                    })
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("ReferenceQuery carrier finalization failed: {error}"))
    }

    fn runtime_agent_control_fields(
        request_id: [u8; 16],
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        runtime_host_epoch: u64,
        nonce: &[u8],
        algorithm: u16,
        algorithm_version: u16,
    ) -> RuntimeAgentControlRequestFieldsV1 {
        RuntimeAgentControlRequestFieldsV1 {
            request_id: RuntimeAgentControlRequestIdV1::try_from_bytes(request_id)
                .unwrap_or_else(|error| panic!("Agent-control request ID rejected: {error}")),
            target: TARGET,
            expected_runtime_store_instance_id: STORE_INSTANCE_ID,
            expected_runtime_host_epoch: runtime_host_epoch,
            auth_claim: ApplyRequestAuthClaim::try_new(
                CONTROLLER_PRINCIPAL,
                CONTROLLER_KEY_REF,
                ApplyAuthAlgorithm::try_new(algorithm).unwrap_or_else(|error| {
                    panic!("Agent-control authentication algorithm rejected: {error}")
                }),
                algorithm_version,
                nonce,
            )
            .unwrap_or_else(|error| panic!("Agent-control authentication rejected: {error}")),
            carrier,
        }
    }

    fn finalize_runtime_agent_control_request(
        draft: RuntimeAgentControlRequestDraftV1,
        signature_length: usize,
    ) -> RuntimeAgentControlRequestV1 {
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| {
                        panic!("Agent-control signing transcript failed: {error}")
                    })
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature[..signature_length])
            .unwrap_or_else(|error| panic!("Agent-control request finalization failed: {error}"))
    }

    fn signed_runtime_agent_fabric_apply(
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        request: ManagedFabricApplyRequestV1,
        runtime_host_epoch: u64,
    ) -> RuntimeAgentControlRequestV1 {
        let fields = runtime_agent_control_fields(
            *request.operation_id().as_bytes(),
            carrier,
            runtime_host_epoch,
            b"runtime-agent-fabric-outer-nonce",
            ED25519_ALGORITHM,
            ED25519_ALGORITHM_VERSION,
        );
        let draft = RuntimeAgentControlRequestDraftV1::try_apply_managed_fabric(fields, request)
            .unwrap_or_else(|error| panic!("Agent-control Fabric draft rejected: {error}"));
        finalize_runtime_agent_control_request(draft, ED25519_SIGNATURE_BYTES)
    }

    fn signed_runtime_agent_stack_apply(
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        request: ManagedAgentStackApplyRequestV1,
        runtime_host_epoch: u64,
    ) -> RuntimeAgentControlRequestV1 {
        let fields = runtime_agent_control_fields(
            *request.operation_id().as_bytes(),
            carrier,
            runtime_host_epoch,
            b"runtime-agent-stack-outer-nonce",
            ED25519_ALGORITHM,
            ED25519_ALGORITHM_VERSION,
        );
        let draft =
            RuntimeAgentControlRequestDraftV1::try_apply_managed_agent_stack(fields, request)
                .unwrap_or_else(|error| panic!("Agent-control stack draft rejected: {error}"));
        finalize_runtime_agent_control_request(draft, ED25519_SIGNATURE_BYTES)
    }

    struct RuntimeAgentDescribeFixtureV1 {
        request_id_byte: u8,
        expected_active_pxst_digest: Digest32,
        intended_client: PrincipalRef,
        algorithm: u16,
        algorithm_version: u16,
        signature_length: usize,
    }

    fn signed_runtime_agent_describe(
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        runtime_host_epoch: u64,
        fixture: RuntimeAgentDescribeFixtureV1,
    ) -> RuntimeAgentControlRequestV1 {
        let fields = runtime_agent_control_fields(
            [fixture.request_id_byte; 16],
            carrier,
            runtime_host_epoch,
            b"runtime-agent-describe-outer-nonce",
            fixture.algorithm,
            fixture.algorithm_version,
        );
        let draft = RuntimeAgentControlRequestDraftV1::try_describe_conversation_port(
            fields,
            fixture.expected_active_pxst_digest,
            fixture.intended_client,
        )
        .unwrap_or_else(|error| panic!("Agent-control Describe draft rejected: {error}"));
        finalize_runtime_agent_control_request(draft, fixture.signature_length)
    }

    fn verify_runtime_agent_response_signature(
        principal: PrincipalRef,
        key: ApplyAuthKeyRef,
        fingerprint: Digest32,
        transcript: &[u8],
        signature: &[u8],
    ) -> bool {
        let verifying_key = SigningKey::from_bytes(&RESPONSE_SEED).verifying_key();
        if principal != RUNTIME_PRINCIPAL
            || key != RESPONSE_KEY_REF
            || fingerprint
                != ed25519_control_key_fingerprint(verifying_key.as_bytes())
                    .unwrap_or_else(|error| panic!("Runtime response fingerprint failed: {error}"))
        {
            return false;
        }
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        verifying_key.verify_strict(transcript, &signature).is_ok()
    }

    fn restricted_endpoint_dependencies_from_profile(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        profile_ref: [u8; 16],
    ) -> RuntimeRestrictedApplyEndpointDependenciesV1 {
        let carrier = restricted_carrier_for_profile(profile, profile_ref);
        let endpoint_config = restricted_endpoint_config(profile, profile_ref, &carrier);
        RuntimeRestrictedApplyEndpointDependenciesV1::new(endpoint_config, carrier)
    }

    fn restricted_endpoint_dependencies(
        route: &str,
    ) -> RuntimeRestrictedApplyEndpointDependenciesV1 {
        let profile = restricted_transport_profile(
            route,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        restricted_endpoint_dependencies_from_profile(&profile, RESTRICTED_PROFILE_REF)
    }

    struct FailClosedFabricCredentialResolver;

    impl RuntimeFabricCredentialResolverV2 for FailClosedFabricCredentialResolver {
        fn resolve(
            &self,
            _requirement: &RuntimeFabricCredentialRequirementV1,
        ) -> Result<RuntimeResolvedFabricPeerCredentialV2, RuntimeFabricCredentialResolveErrorV2>
        {
            Err(RuntimeFabricCredentialResolveErrorV2::ResolutionFailed)
        }
    }

    fn evidence_store_config(root: PathBuf) -> DistributedAgentStackEvidenceStoreConfigV1 {
        DistributedAgentStackEvidenceStoreConfigV1::try_new(
            root,
            EvidenceStoreEpochV1::try_from_bytes([0xe1; 16])
                .unwrap_or_else(|error| panic!("Evidence store epoch rejected: {error:?}")),
            EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
                .unwrap_or_else(|error| panic!("Evidence retention rejected: {error:?}")),
            EvidenceOwnerRefV1::try_from_bytes([0xe2; 16])
                .unwrap_or_else(|error| panic!("Evidence owner rejected: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("Evidence store config rejected: {error:?}"))
    }

    fn distributed_service_dependencies(
        evidence_store_config: DistributedAgentStackEvidenceStoreConfigV1,
    ) -> (
        RuntimeManagedFabricServiceDependenciesV1,
        Arc<dyn RuntimeFabricCredentialResolverV2>,
        Arc<dyn RuntimeAgentProviderResolverV1>,
    ) {
        let fabric_credential_resolver: Arc<dyn RuntimeFabricCredentialResolverV2> =
            Arc::new(FailClosedFabricCredentialResolver);
        let agent_provider_resolver = unavailable_provider_resolver();
        let dependencies = RuntimeManagedFabricServiceDependenciesV1::new(
            Arc::clone(&agent_provider_resolver),
            unavailable_model_backend_resolver(),
            Some(RuntimeDistributedAgentStackDependenciesV1::new(
                Arc::clone(&fabric_credential_resolver),
                evidence_store_config,
            )),
            None,
        );
        (
            dependencies,
            fabric_credential_resolver,
            agent_provider_resolver,
        )
    }

    #[test]
    fn distributed_v2_dependency_is_repeatable_and_debug_redacted() {
        let evidence_directory = TestSocketDirectory::create();
        let evidence_root = evidence_directory.path.join("evidence-store");
        let expected_evidence = evidence_store_config(evidence_root.clone());
        let expected_epoch = expected_evidence.store_epoch();
        let expected_retention = expected_evidence.retention_policy();
        let expected_owner = expected_evidence.owner_ref();
        let (dependencies, expected_resolver, expected_agent_provider) =
            distributed_service_dependencies(expected_evidence);
        let first_cutover = dependencies
            .distributed_agent_stack_owner_dependencies()
            .unwrap_or_else(|| panic!("first cutover lost distributed dependencies"));
        let restart = dependencies
            .distributed_agent_stack_owner_dependencies()
            .unwrap_or_else(|| panic!("restart lost distributed dependencies"));

        assert!(Arc::ptr_eq(
            &expected_resolver,
            &first_cutover.fabric_credential_resolver
        ));
        assert!(Arc::ptr_eq(
            &first_cutover.fabric_credential_resolver,
            &restart.fabric_credential_resolver
        ));
        assert!(Arc::ptr_eq(
            &expected_agent_provider,
            &dependencies.agent_provider_resolver()
        ));
        assert_eq!(
            first_cutover.evidence_store_config.root(),
            evidence_root.as_path()
        );
        assert_eq!(
            first_cutover.evidence_store_config.store_epoch(),
            expected_epoch
        );
        assert_eq!(
            first_cutover.evidence_store_config.retention_policy(),
            expected_retention
        );
        assert_eq!(
            first_cutover.evidence_store_config.owner_ref(),
            expected_owner
        );

        let debug = format!("{dependencies:?}");
        assert!(debug.contains("distributed_agent_stack: true"));
        assert!(!debug.contains("FailClosedFabricCredentialResolver"));
        let distributed_debug = format!(
            "{:?}",
            dependencies
                .distributed_agent_stack
                .as_ref()
                .unwrap_or_else(|| panic!("configured V2 dependency disappeared"))
        );
        assert!(distributed_debug.contains("<injected>"));
        assert!(distributed_debug.contains("<composition-pinned>"));
        assert!(!distributed_debug.contains("FailClosedFabricCredentialResolver"));
        assert!(
            !distributed_debug.contains(
                evidence_root
                    .to_str()
                    .unwrap_or_else(|| panic!("Evidence fixture root is not UTF-8"))
            )
        );
        assert!(!distributed_debug.contains(&format!("{expected_epoch:?}")));
        assert!(!distributed_debug.contains(&format!("{expected_retention:?}")));
        assert!(!distributed_debug.contains(&format!("{expected_owner:?}")));
        let evidence_debug = format!("{:?}", first_cutover.evidence_store_config);
        assert!(
            !evidence_debug.contains(
                evidence_root
                    .to_str()
                    .unwrap_or_else(|| panic!("Evidence fixture root is not UTF-8"))
            )
        );
        assert!(!evidence_debug.contains(&format!("{expected_epoch:?}")));
        assert!(!evidence_debug.contains(&format!("{expected_owner:?}")));

        let unavailable = RuntimeManagedFabricServiceDependenciesV1::unavailable();
        let unavailable_distributed = unavailable.distributed_agent_stack_owner_dependencies();
        let unavailable_resolver = unavailable_distributed
            .map(|dependencies| Arc::clone(&dependencies.fabric_credential_resolver));
        let unavailable_evidence =
            unavailable_distributed.map(|dependencies| dependencies.evidence_store_config.clone());
        assert!(unavailable_resolver.is_none());
        assert!(unavailable_evidence.is_none());
        assert!(unavailable.restricted_runtime_apply_endpoint.is_none());
        let unresolved_model = managed_model_plan(managed_agent_plan().provider());
        assert!(matches!(
            unavailable
                .model_backend_resolver()
                .resolve(&unresolved_model),
            Err(RuntimeModelBackendResolveError::ResolutionFailed)
        ));
        let unavailable_debug = format!("{unavailable:?}");
        assert!(unavailable_debug.contains("model_backend_resolver: \"<injected>\""));
        assert!(unavailable_debug.contains("restricted_runtime_apply_endpoint: false"));
    }

    #[test]
    fn restricted_endpoint_dependency_pins_exact_pair_and_redacts_composition_values() {
        let socket_directory = TestSocketDirectory::create();
        let provisioning = provisioning(socket_directory.socket_path.clone());
        let profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let restricted = restricted_endpoint_dependencies(RESTRICTED_APPLY_ROUTE);
        validate_restricted_runtime_apply_endpoint_dependencies(&restricted, &provisioning)
            .unwrap_or_else(|error| panic!("restricted dependency validation failed: {error}"));
        assert_eq!(restricted.endpoint_config.route(), RESTRICTED_APPLY_ROUTE);
        assert_eq!(restricted.expected_carrier.route(), RESTRICTED_APPLY_ROUTE);
        assert!(
            restricted
                .endpoint_config
                .matches_restricted_carrier(&restricted.expected_carrier)
        );
        assert_eq!(
            restricted.expected_carrier.control_transport_profile_ref(),
            RESTRICTED_PROFILE_REF
        );
        assert_eq!(
            restricted
                .expected_carrier
                .control_transport_profile_digest(),
            profile.profile_digest()
        );

        let dependencies = RuntimeManagedFabricServiceDependenciesV1::new(
            unavailable_provider_resolver(),
            unavailable_model_backend_resolver(),
            None,
            Some(restricted.clone()),
        );
        let cloned = dependencies.clone();
        let preserved = cloned
            .restricted_runtime_apply_endpoint
            .as_ref()
            .unwrap_or_else(|| panic!("restricted dependency disappeared during clone"));
        assert_eq!(preserved.endpoint_config, restricted.endpoint_config);
        assert_eq!(preserved.expected_carrier, restricted.expected_carrier);
        let debug = format!("{dependencies:?} {restricted:?}");
        assert!(debug.contains("restricted_runtime_apply_endpoint: true"));
        assert!(debug.contains("<composition-pinned>"));
        assert!(!debug.contains(RESTRICTED_APPLY_ROUTE));
        assert!(!debug.contains("paraegox-restricted-runtime.key"));

        let mismatched_profile = restricted_transport_profile(
            "paraegox/runtime/endpoint-stack/other-route/apply",
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let mismatched_config = restricted_endpoint_dependencies_from_profile(
            &mismatched_profile,
            RESTRICTED_PROFILE_REF,
        )
        .endpoint_config
        .into_legacy_apply();
        let mismatched = RuntimeRestrictedApplyEndpointDependenciesV1::new(
            mismatched_config,
            restricted.expected_carrier,
        );
        assert!(matches!(
            validate_restricted_runtime_apply_endpoint_dependencies(&mismatched, &provisioning),
            Err(RuntimeBootstrapEndpointError::InvalidProvisioning)
        ));
    }

    #[test]
    fn runtime_control_dependency_is_explicit_and_cannot_collapse_to_legacy_apply() {
        let profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let carrier = restricted_carrier_for_profile(&profile, RESTRICTED_PROFILE_REF);
        let legacy = RuntimeRestrictedApplyEndpointDependenciesV1::new(
            restricted_endpoint_config(&profile, RESTRICTED_PROFILE_REF, &carrier),
            carrier.clone(),
        );
        let control = RuntimeRestrictedApplyEndpointDependenciesV1::new_runtime_control(
            restricted_control_endpoint_config(&profile, RESTRICTED_PROFILE_REF, &carrier),
            carrier,
        );

        assert_eq!(
            legacy.protocol,
            RestrictedRuntimeEndpointProtocolV1::LegacyApply
        );
        assert_eq!(
            control.protocol,
            RestrictedRuntimeEndpointProtocolV1::RuntimeControl
        );
        assert!(matches!(
            legacy.endpoint_config,
            RestrictedRuntimeEndpointConfigV1::LegacyApply(_)
        ));
        assert!(matches!(
            control.endpoint_config,
            RestrictedRuntimeEndpointConfigV1::RuntimeControl(_)
        ));
    }

    #[test]
    fn runtime_control_dispatch_authenticates_before_phase_selection_and_uses_sole_owners() {
        let source = include_str!("runtime_control_endpoint.rs");
        let legacy = section(
            source,
            "async fn handle_developer_restricted_runtime_control_v1",
            "fn prevalidate_developer_managed_cutover_request",
        );
        let decode = legacy
            .find("decode_runtime_control_carrier")
            .unwrap_or_else(|| panic!("missing strict PXCC decode"));
        let authenticate = legacy
            .find("authenticate_runtime_control_carrier")
            .unwrap_or_else(|| panic!("missing outer Controller authentication"));
        let phase = authenticate
            + legacy[authenticate..]
                .find("match control")
                .unwrap_or_else(|| panic!("missing authenticated phase selection"));
        let prevalidate = legacy
            .find("prevalidate_developer_managed_cutover_request")
            .unwrap_or_else(|| panic!("missing sole PXFB prevalidation"));
        let take_store = legacy
            .find("slot.take()")
            .unwrap_or_else(|| panic!("missing one-way legacy owner transfer"));
        let cutover = legacy
            .find("try_cutover_developer_local_from_store")
            .unwrap_or_else(|| panic!("missing sole managed cutover owner"));
        assert!(decode < authenticate && authenticate < phase);
        assert!(authenticate < prevalidate && prevalidate < take_store && take_store < cutover);
        assert_eq!(legacy.match_indices("legacy.handle_query(").count(), 1);
        assert_eq!(
            legacy
                .match_indices("prevalidate_developer_managed_cutover_request")
                .count(),
            1
        );

        let managed = section(
            source,
            "async fn handle_authenticated_runtime_control_carrier_v1",
            "fn handle_serving_bootstrap",
        );
        assert!(managed.contains("RuntimeControlCarrierKindV1::Describe"));
        assert!(managed.contains("self.runtime_control_describe_facts()"));
        let reference_query = managed
            .find("RuntimeControlCarrierKindV1::ReferenceQuery")
            .unwrap_or_else(|| panic!("missing managed ReferenceQuery branch"));
        assert!(managed[reference_query..].contains("Err(RuntimeControlRequestError::Rejected)"));
        assert!(!managed[reference_query..].contains("handle_query("));
    }

    #[tokio::test]
    async fn restricted_endpoint_rejects_every_non_exact_profile_carrier_pair_before_start() {
        let socket_directory = TestSocketDirectory::create();
        let provisioning = provisioning(socket_directory.socket_path.clone());
        let base_profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let base =
            restricted_endpoint_dependencies_from_profile(&base_profile, RESTRICTED_PROFILE_REF);

        let locator_profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            "tls/192.0.2.11:7447",
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let locator_dependencies =
            restricted_endpoint_dependencies_from_profile(&locator_profile, RESTRICTED_PROFILE_REF);
        let profile_ref_dependencies =
            restricted_endpoint_dependencies_from_profile(&base_profile, [0xe7; 16]);
        let generation_profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION + 1,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let generation_config = restricted_endpoint_dependencies_from_profile(
            &generation_profile,
            RESTRICTED_PROFILE_REF,
        )
        .endpoint_config;
        let timeout_profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS + 1,
        );
        let timeout_config =
            restricted_endpoint_dependencies_from_profile(&timeout_profile, RESTRICTED_PROFILE_REF)
                .endpoint_config;
        let mismatched_profile_digest = if base_profile.profile_digest() != digest(0xe8) {
            digest(0xe8)
        } else {
            digest(0xe9)
        };
        let digest_carrier = restricted_carrier_with_profile_digest(
            &base_profile,
            RESTRICTED_PROFILE_REF,
            mismatched_profile_digest,
        );

        assert_ne!(
            locator_profile.tls_listener_locator(),
            base_profile.tls_listener_locator()
        );
        assert_ne!(
            locator_profile.profile_digest(),
            base_profile.profile_digest()
        );
        assert_ne!(
            profile_ref_dependencies
                .expected_carrier
                .control_transport_profile_ref(),
            base.expected_carrier.control_transport_profile_ref()
        );
        assert_ne!(
            generation_profile.endpoint_generation(),
            base_profile.endpoint_generation()
        );
        assert_ne!(
            generation_profile.profile_digest(),
            base_profile.profile_digest()
        );
        assert_ne!(
            timeout_profile.operation_timeout_nanos(),
            base_profile.operation_timeout_nanos()
        );
        assert_ne!(
            timeout_profile.profile_digest(),
            base_profile.profile_digest()
        );
        assert_ne!(
            digest_carrier.control_transport_profile_digest(),
            base.expected_carrier.control_transport_profile_digest()
        );
        for profile in [&locator_profile, &generation_profile, &timeout_profile] {
            assert_eq!(profile.route(), base_profile.route());
            assert_eq!(
                profile.controller_principal(),
                base_profile.controller_principal()
            );
            assert_eq!(
                profile.runtime_principal(),
                base_profile.runtime_principal()
            );
        }

        let mismatches = [
            (
                "locator",
                RuntimeRestrictedApplyEndpointDependenciesV1::new(
                    locator_dependencies.endpoint_config.into_legacy_apply(),
                    base.expected_carrier.clone(),
                ),
            ),
            (
                "profile-ref",
                RuntimeRestrictedApplyEndpointDependenciesV1::new(
                    profile_ref_dependencies.endpoint_config.into_legacy_apply(),
                    base.expected_carrier.clone(),
                ),
            ),
            (
                "profile-digest",
                RuntimeRestrictedApplyEndpointDependenciesV1::new(
                    base.endpoint_config.clone().into_legacy_apply(),
                    digest_carrier,
                ),
            ),
            (
                "endpoint-generation",
                RuntimeRestrictedApplyEndpointDependenciesV1::new(
                    generation_config.into_legacy_apply(),
                    base.expected_carrier.clone(),
                ),
            ),
            (
                "timeout",
                RuntimeRestrictedApplyEndpointDependenciesV1::new(
                    timeout_config.into_legacy_apply(),
                    base.expected_carrier.clone(),
                ),
            ),
        ];

        for (field, mismatch) in &mismatches {
            assert_eq!(
                mismatch.endpoint_config.route(),
                base.endpoint_config.route()
            );
            assert_eq!(
                mismatch.expected_carrier.route(),
                base.expected_carrier.route()
            );
            assert_eq!(
                mismatch.expected_carrier.controller_principal(),
                base.expected_carrier.controller_principal()
            );
            assert_eq!(
                mismatch.expected_carrier.runtime_principal(),
                base.expected_carrier.runtime_principal()
            );
            assert!(
                !mismatch
                    .endpoint_config
                    .matches_restricted_carrier(&mismatch.expected_carrier),
                "{field} mismatch unexpectedly paired"
            );
        }

        for (field, mismatch) in mismatches {
            assert!(
                matches!(
                    RunningRestrictedRuntimeApplyEndpointV1::start(mismatch, &provisioning).await,
                    Err(RuntimeBootstrapEndpointError::InvalidProvisioning)
                ),
                "{field} mismatch reached the Fabric listener"
            );
        }
    }

    #[test]
    fn restricted_composition_orders_verification_select_handoff_and_cleanup() {
        fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            let start = source
                .find(start)
                .unwrap_or_else(|| panic!("missing {start}"));
            let tail = &source[start..];
            let end = tail.find(end).unwrap_or_else(|| panic!("missing {end}"));
            &tail[..end]
        }

        let source = include_str!("runtime_control_endpoint.rs");
        let dependency_validation = section(
            source,
            "fn validate_restricted_runtime_apply_endpoint_dependencies",
            "impl RunningRestrictedRuntimeApplyEndpointV1",
        );
        assert!(
            dependency_validation
                .find(".matches_restricted_carrier")
                .unwrap_or_else(|| panic!("missing exact endpoint/carrier matcher"))
                < dependency_validation
                    .find("validate_restricted_runtime_apply_carrier_pins")
                    .unwrap_or_else(|| panic!("missing provisioning pin validation"))
        );
        let seam = section(
            source,
            "pub(crate) async fn handle_restricted_distributed_agent_stack_apply_v1",
            "    fn handle_serving_bootstrap",
        );
        assert!(
            seam.find("authenticate_restricted_distributed_agent_stack_apply")
                .unwrap_or_else(|| panic!("missing authenticated marker"))
                < seam
                    .find(".handle_distributed_agent_stack_apply")
                    .unwrap_or_else(|| panic!("missing sole PXAR v8 owner"))
        );
        assert!(
            seam.find("validate_restricted_inner_terminal")
                .unwrap_or_else(|| panic!("missing PXDS1 validation"))
                < seam
                    .find("DistributedAgentStackTerminalReceiptDraftV2::try_new")
                    .unwrap_or_else(|| panic!("missing PXDS2 draft"))
        );
        assert!(
            seam.find(".finalize(&signature)")
                .unwrap_or_else(|| panic!("missing signed PXDS2 finalization"))
                < seam
                    .find(".register_restricted_distributed_alias")
                    .unwrap_or_else(|| panic!("missing exact PXDS2 alias registration"))
        );
        assert!(
            seam.find(".register_restricted_distributed_alias")
                .unwrap_or_else(|| panic!("missing exact PXDS2 alias registration"))
                < seam
                    .find("Ok(wire.into())")
                    .unwrap_or_else(|| panic!("missing restricted response return"))
        );

        let outer_authentication = section(
            source,
            "fn authenticate_restricted_distributed_agent_stack_apply",
            "fn validate_restricted_inner_terminal",
        );
        assert!(outer_authentication.contains("verify_controller_carrier_before_mutation"));
        let inner_terminal = section(
            source,
            "fn validate_restricted_inner_terminal",
            "fn map_restricted_inner_apply_error",
        );
        assert!(
            inner_terminal
                .find(".verify_strict")
                .unwrap_or_else(|| panic!("missing PXDS1 signature verification"))
                < inner_terminal
                    .find("Ok(facts.clone())")
                    .unwrap_or_else(|| panic!("missing verified facts return"))
        );

        let running_endpoint = section(
            source,
            "impl RunningRestrictedRuntimeApplyEndpointV1",
            "pub(crate) async fn serve_managed_fabric_until_with_ready",
        );
        assert!(
            running_endpoint
                .find("validate_restricted_runtime_apply_endpoint_dependencies")
                .unwrap_or_else(|| panic!("missing restricted dependency validation"))
                < running_endpoint
                    .find("RestrictedRuntimeApplyEndpointV1::start")
                    .unwrap_or_else(|| panic!("listener opened before dependency validation"))
        );
        assert!(
            running_endpoint
                .find("drop(receiver)")
                .unwrap_or_else(|| panic!("receiver must close before endpoint shutdown"))
                < running_endpoint
                    .find(".shutdown()")
                    .unwrap_or_else(|| panic!("missing endpoint shutdown"))
        );

        let serve = section(
            source,
            "pub(crate) async fn serve_managed_fabric_until_with_ready",
            "async fn runtime_shutdown_signal",
        );
        assert!(
            serve
                .find("RunningRestrictedRuntimeApplyEndpointV1::start")
                .unwrap_or_else(|| panic!("missing restricted endpoint startup"))
                < serve
                    .find("if let Err(error) = ready")
                    .unwrap_or_else(|| panic!("missing readiness callback"))
        );
        assert!(serve.contains("result = &mut shutdown"));
        assert!(serve.contains("result = listener.accept()"));
        assert!(serve.contains("inbound = restricted.receiver.recv()"));
        assert_eq!(
            serve
                .match_indices(".handle_restricted_distributed_agent_stack_apply_v1")
                .count(),
            1
        );
        assert!(serve.contains("if let Err(error) = inbound.respond(response.into_vec())"));
        assert!(serve.contains("RestrictedRuntimeApplyResponseHandoff(error)"));
        let rejection = serve
            .find("RuntimeRestrictedRemoteApplyErrorV1::Rejected")
            .unwrap_or_else(|| panic!("missing generic rejection branch"));
        assert!(serve[rejection..].contains("drop(inbound)"));

        let restricted_shutdowns = serve
            .match_indices("let restricted_shutdown_result")
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        assert_eq!(restricted_shutdowns.len(), 2);
        for shutdown in restricted_shutdowns {
            let tail = &serve[shutdown..];
            assert!(
                tail.find("endpoint.shutdown().await")
                    .unwrap_or_else(|| panic!("missing restricted shutdown"))
                    < tail
                        .find("shutdown_managed_successor_chain")
                        .unwrap_or_else(|| panic!("missing managed owner cleanup"))
            );
        }
        assert_eq!(
            serve
                .match_indices("aggregate_runtime_service_failures(")
                .count(),
            7
        );
        assert!(source.contains("control_transport_profile_ref` and"));
        assert!(source.contains("opaque composition assertions"));
        assert!(
            source.contains("RestrictedRuntimeApplyEndpointConfigV1::try_from_transport_profile")
        );
        // Split the forbidden spelling so this source-scanning assertion does
        // not find its own string literal and fail unconditionally.
        let raw_constructor = ["RestrictedRuntimeApplyEndpointConfigV1::try_", "new"].concat();
        assert!(!source.contains(&raw_constructor));
    }

    #[test]
    fn lifecycle_failure_reducer_preserves_every_stage_and_nested_owner_failure() {
        let mut owner_failures = RuntimeBootstrapFailureReducerV1::default();
        owner_failures.record_result(
            RuntimeBootstrapFailureStageV1::Successor,
            Err(RuntimeBootstrapEndpointError::InvalidStartedState),
        );
        owner_failures.record_result(
            RuntimeBootstrapFailureStageV1::Successor,
            Err(RuntimeBootstrapEndpointError::Runtime),
        );

        let failure = aggregate_runtime_service_failures(
            Err(RuntimeBootstrapEndpointError::BuildPinMismatch),
            owner_failures.finish(),
            Err(RuntimeBootstrapEndpointError::RestrictedRuntimeApply(
                RestrictedRuntimeApplyErrorV1::SessionCloseFailed,
            )),
            Err(RuntimeBootstrapEndpointError::Socket(
                io::ErrorKind::PermissionDenied,
            )),
        )
        .expect_err("five staged failures must not reduce to success");
        let RuntimeBootstrapEndpointError::StagedFailures(failures) = failure else {
            panic!("reducer must return the typed failure set");
        };

        assert_eq!(failures.len(), 5);
        assert!(!failures.failures.is_empty());
        assert_eq!(
            failures
                .failures
                .iter()
                .map(|failure| failure.stage)
                .collect::<Vec<_>>(),
            vec![
                RuntimeBootstrapFailureStageV1::Primary,
                RuntimeBootstrapFailureStageV1::Successor,
                RuntimeBootstrapFailureStageV1::Successor,
                RuntimeBootstrapFailureStageV1::RestrictedEndpoint,
                RuntimeBootstrapFailureStageV1::LocalSocketCleanup,
            ]
        );
        assert!(
            failures
                .failures
                .iter()
                .find(|failure| failure.stage == RuntimeBootstrapFailureStageV1::Primary)
                .is_some_and(|failure| matches!(
                    failure.error.as_ref(),
                    RuntimeBootstrapEndpointError::BuildPinMismatch
                ))
        );
        assert!(
            failures
                .failures
                .iter()
                .find(|failure| {
                    failure.stage == RuntimeBootstrapFailureStageV1::RestrictedEndpoint
                })
                .is_some_and(|failure| matches!(
                    failure.error.as_ref(),
                    RuntimeBootstrapEndpointError::RestrictedRuntimeApply(
                        RestrictedRuntimeApplyErrorV1::SessionCloseFailed
                    )
                ))
        );
        assert!(matches!(
            failures.failures[4].error.as_ref(),
            RuntimeBootstrapEndpointError::Socket(io::ErrorKind::PermissionDenied)
        ));
    }

    #[test]
    fn lifecycle_cleanup_source_uses_lossless_staged_reducer() {
        let source = include_str!("runtime_control_endpoint.rs");
        assert!(source.contains("error: Box<RuntimeBootstrapEndpointError>"));
        assert!(source.contains("failures: Box<[RuntimeBootstrapFailureV1]>"));

        let shutdown = section(
            source,
            "async fn shutdown_managed_successor_chain",
            "#[derive(Default)]\nstruct RuntimeBootstrapFailureReducerV1",
        );
        // Dependency teardown is deliberately fail-fast rather than lossless:
        // after an uncertain Agent retirement, touching its Model/Fabric
        // dependencies would violate the owner safety boundary. Independent
        // endpoint/socket cleanup remains covered by the staged reducer below.
        let compact_shutdown = shutdown.split_whitespace().collect::<String>();
        let model = compact_shutdown
            .find("ifletSome(model_stack)=model_stack.as_mut()")
            .unwrap_or_else(|| panic!("Model+Agent shutdown branch disappeared"));
        let model_shutdown = compact_shutdown
            .find(
                "model_stack.shutdown(core).await.map_err(RuntimeBootstrapEndpointError::ManagedModelAgentStack)?",
            )
            .unwrap_or_else(|| panic!("fail-fast Model+Agent shutdown disappeared"));
        let model_fabric = compact_shutdown
            .find(
                "returncore.shutdown().await.map_err(RuntimeBootstrapEndpointError::ManagedFabric)",
            )
            .unwrap_or_else(|| panic!("Model branch Fabric shutdown disappeared"));
        let distributed = compact_shutdown
            .find("ifletSome(distributed)=distributed.as_mut()")
            .unwrap_or_else(|| panic!("distributed Agent shutdown disappeared"));
        let distributed_shutdown = compact_shutdown
            .find(
                "distributed.shutdown().await.map_err(RuntimeBootstrapEndpointError::DistributedAgentStack)?",
            )
            .unwrap_or_else(|| panic!("fail-fast distributed Agent shutdown disappeared"));
        let stack = compact_shutdown
            .find("ifletSome(stack)=stack.as_mut()")
            .unwrap_or_else(|| panic!("predecessor Agent shutdown disappeared"));
        let stack_shutdown = compact_shutdown
            .find(
                "stack.shutdown(core).await.map_err(RuntimeBootstrapEndpointError::ManagedAgentStack)?",
            )
            .unwrap_or_else(|| panic!("fail-fast predecessor Agent shutdown disappeared"));
        let fabric = compact_shutdown
            .rfind("core.shutdown().await.map_err(RuntimeBootstrapEndpointError::ManagedFabric)")
            .unwrap_or_else(|| panic!("managed Fabric shutdown disappeared"));
        assert!(model < model_shutdown && model_shutdown < model_fabric);
        assert!(
            model_fabric < distributed
                && distributed < distributed_shutdown
                && distributed_shutdown < stack
                && stack < stack_shutdown
                && stack_shutdown < fabric
        );
        assert!(!shutdown.contains("RuntimeBootstrapFailureReducerV1"));

        let reducer = section(
            source,
            "#[derive(Default)]\nstruct RuntimeBootstrapFailureReducerV1",
            "impl<Store: RuntimeBootstrapStore> StartedRuntimeBootstrapService<Store>",
        );
        assert!(reducer.contains("RuntimeBootstrapEndpointError::StagedFailures"));
        assert!(reducer.contains("RuntimeBootstrapFailureStageV1::Primary"));
        assert!(reducer.contains("RuntimeBootstrapFailureStageV1::RestrictedEndpoint"));
        assert!(reducer.contains("RuntimeBootstrapFailureStageV1::LocalSocketCleanup"));
        assert!(!reducer.contains(".and("));

        let bind = section(
            source,
            "fn bind_control_socket",
            "struct BoundRuntimeBootstrapService",
        );
        assert!(bind.contains("let cleanup_result = guard.cleanup();"));
        assert!(bind.contains("aggregate_runtime_service_failures("));
        assert!(!bind.contains("let _ = guard.cleanup()"));

        let legacy = section(
            source,
            "async fn serve_developer_legacy_cutover_until",
            "fn live_runtime_channel_from_state",
        );
        assert!(legacy.contains("let service_result = 'service: loop"));
        assert_eq!(
            legacy
                .match_indices("aggregate_runtime_service_failures(")
                .count(),
            6
        );
        assert_eq!(
            legacy
                .match_indices("RunningRestrictedRuntimeApplyEndpointV1::start")
                .count(),
            1
        );
        assert!(
            legacy
                .find("RunningRestrictedRuntimeApplyEndpointV1::start")
                .unwrap_or_else(|| panic!("missing restricted listener startup"))
                < legacy
                    .find("if let Err(error) = ready")
                    .unwrap_or_else(|| panic!("restricted listener starts after readiness"))
        );
        assert!(legacy.contains("DeveloperLocalControlState::Legacy(_)"));
        assert!(legacy.contains("RuntimeRestrictedRemoteApplyErrorV1::Rejected"));
        assert!(!legacy.contains("cleanup.and("));

        let recovery = section(
            source,
            "async fn recover_managed_control_for_existing_channel",
            "async fn shutdown_managed_successor_chain",
        );
        assert!(recovery.contains("let recovery_result = async"));
        assert!(recovery.contains("shutdown_managed_successor_chain"));
        assert!(recovery.contains("aggregate_runtime_service_failures("));

        let bound = section(
            source,
            "impl<Store> BoundRuntimeBootstrapService<Store>",
            "async fn serve_managed_fabric_until",
        );
        assert_eq!(
            bound
                .match_indices("aggregate_runtime_service_failures(")
                .count(),
            4
        );
        assert!(!bound.contains("(_, Err(error))"));

        let managed = section(
            source,
            "pub(crate) async fn serve_managed_fabric_until_with_ready",
            "async fn runtime_shutdown_signal",
        );
        assert_eq!(
            managed
                .match_indices("aggregate_runtime_service_failures(")
                .count(),
            7
        );
        assert_eq!(
            managed
                .match_indices("shutdown_managed_successor_chain")
                .count(),
            7
        );
        assert!(!managed.contains(".and("));
    }

    #[test]
    fn production_managed_fabric_owner_uses_zenoh_compatible_scheduler() {
        let runtime = build_managed_fabric_owner_runtime()
            .unwrap_or_else(|error| panic!("managed Runtime build failed: {error}"));
        assert!(matches!(
            runtime.handle().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        ));
        runtime.block_on(async { tokio::task::yield_now().await });
    }

    fn distinct_controller_uid(runtime_uid: u32) -> u32 {
        assert_ne!(
            runtime_uid, 0,
            "reference endpoint tests require a non-root uid"
        );
        if runtime_uid == u32::MAX {
            runtime_uid - 1
        } else {
            runtime_uid + 1
        }
    }

    fn distinct_authority_uid(runtime_uid: u32) -> u32 {
        if runtime_uid <= u32::MAX - 2 {
            runtime_uid + 2
        } else {
            runtime_uid - 2
        }
    }

    fn provisioning(socket_path: PathBuf) -> RuntimeProvisioningV1 {
        let key_directory = TestSocketDirectory::create();
        let controller_key = key_directory.path.join("controller.pub");
        let response_key = key_directory.path.join("runtime.pub");
        let response_seed = key_directory.path.join("runtime.seed");
        let tenure_key = key_directory.path.join("authority.pub");
        for (path, bytes) in [
            (
                &controller_key,
                SigningKey::from_bytes(&CONTROLLER_SEED)
                    .verifying_key()
                    .to_bytes(),
            ),
            (
                &response_key,
                SigningKey::from_bytes(&RESPONSE_SEED)
                    .verifying_key()
                    .to_bytes(),
            ),
            (&response_seed, RESPONSE_SEED),
            (
                &tenure_key,
                SigningKey::from_bytes(&TENURE_SEED)
                    .verifying_key()
                    .to_bytes(),
            ),
        ] {
            fs::write(path, bytes)
                .unwrap_or_else(|error| panic!("provisioning key write failed: {error}"));
            fs::set_permissions(path, fs::Permissions::from_mode(0o400))
                .unwrap_or_else(|error| panic!("provisioning key chmod failed: {error}"));
        }
        let runtime_uid = geteuid().as_raw();
        let runtime_gid = getegid().as_raw();
        assert_ne!(
            runtime_gid, 0,
            "reference endpoint tests require a non-root gid"
        );
        let controller_uid = distinct_controller_uid(runtime_uid);
        let authority_uid = distinct_authority_uid(runtime_uid);
        let input = RuntimeProvisioningInputV1 {
            socket_path,
            target: TARGET,
            source_scope: SOURCE_SCOPE,
            writer: WRITER,
            runtime_principal: RUNTIME_PRINCIPAL,
            runtime_uid,
            runtime_gid,
            controller_principal: CONTROLLER_PRINCIPAL,
            controller_uid,
            controller_gid: runtime_gid,
            controller_request_key_ref: CONTROLLER_KEY_REF,
            controller_public_key_path: controller_key,
            runtime_response_key_ref: RESPONSE_KEY_REF,
            runtime_response_public_key_path: response_key,
            runtime_response_private_seed_path: response_seed,
            authority_principal: AUTHORITY_PRINCIPAL,
            authority_uid,
            authority_gid: runtime_gid,
            tenure_authority_ref: TENURE_AUTHORITY_REF,
            tenure_key_ref: TENURE_KEY_REF,
            tenure_public_key_path: tenure_key,
        };
        let provisioning = RuntimeProvisioningV1::try_new(input)
            .unwrap_or_else(|error| panic!("valid provisioning rejected: {error}"));
        for path in fs::read_dir(&key_directory.path)
            .unwrap_or_else(|error| panic!("key fixture list failed: {error}"))
        {
            let path = path
                .unwrap_or_else(|error| panic!("key fixture entry failed: {error}"))
                .path();
            fs::remove_file(path)
                .unwrap_or_else(|error| panic!("key fixture cleanup failed: {error}"));
        }
        provisioning
    }

    fn compiled_facts() -> RuntimeCompiledInstallationFactsV1 {
        RuntimeCompiledInstallationFactsV1::try_new(
            [0x61; 32],
            CardDefinitionRef::from_bytes([0x62; 16]),
            CardImplementationRef::from_bytes([0x63; 16]),
            [0x64; 16],
            digest(0x65),
            digest(0x66),
        )
        .unwrap_or_else(|error| panic!("compiled facts rejected: {error}"))
    }

    fn installed_snapshot(
        provisioning: &RuntimeProvisioningV1,
    ) -> (RuntimeJournalSnapshot, RuntimeCompiledInstallationFactsV1) {
        let compiled = compiled_facts();
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            digest(0x67),
            "x86_64-unknown-linux-gnu",
        )
        .unwrap_or_else(|error| panic!("artifact observation rejected: {error}"));
        let descriptor = generate_build_descriptor(&artifact, compiled)
            .unwrap_or_else(|error| panic!("descriptor generation failed: {error}"));
        let installation = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            TARGET,
            &artifact,
            compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));
        let snapshot = RuntimeJournalSnapshot::try_initialize(
            STORE_INSTANCE_ID,
            provisioning.owner_target_fingerprint(),
            RuntimeJournalSequenceOne {
                clock_domain: CLOCK_DOMAIN,
                build_descriptor: OpaqueCanonicalValue::try_pinned_artifact(
                    installation.descriptor_canonical_wire(),
                    installation.descriptor_digest(),
                )
                .unwrap_or_else(|error| panic!("descriptor pin failed: {error:?}")),
                singleton_manifest: OpaqueCanonicalValue::try_pinned_artifact(
                    installation.manifest_canonical_wire(),
                    installation.manifest_digest(),
                )
                .unwrap_or_else(|error| panic!("manifest pin failed: {error:?}")),
                store_pinned_build_identity: StorePinnedBuildIdentity::try_new(
                    installation.build_instance_id(),
                    installation.build_descriptor_digest(),
                    installation.runtime_artifact_sha256(),
                    installation.compiled_reference_compatibility_digest(),
                )
                .unwrap_or_else(|error| panic!("build identity rejected: {error:?}")),
                compiled_build_instance_id: compiled.compiled_build_instance_id(),
                compiled_compatibility_digest: compiled
                    .compiled_reference_compatibility_digest()
                    .unwrap_or_else(|error| panic!("compiled compatibility failed: {error}")),
                admission_policy_fingerprint: provisioning.admission_policy_fingerprint(),
                channel_policy_fingerprint: provisioning.channel_policy_fingerprint(),
                controller_key_fingerprint: provisioning.controller_key_fingerprint(),
            },
        )
        .unwrap_or_else(|error| panic!("sequence one rejected: {error:?}"));
        (snapshot, compiled)
    }

    fn managed_started_service(
        socket_path: PathBuf,
    ) -> (TestDirectory, StartedManagedFabricService) {
        managed_started_service_with_dependencies(
            socket_path,
            deterministic_fixture_service_dependencies(),
        )
    }

    fn managed_started_service_with_dependencies(
        socket_path: PathBuf,
        dependencies: RuntimeManagedFabricServiceDependenciesV1,
    ) -> (TestDirectory, StartedManagedFabricService) {
        let provisioning = provisioning(socket_path);
        let (snapshot, compiled) = installed_snapshot(&provisioning);
        let installation = verify_startup_installation(&snapshot, provisioning.target(), compiled)
            .unwrap_or_else(|error| panic!("managed fixture installation rejected: {error}"));
        let manifest = installation
            .immutable_manifest_ingress()
            .unwrap_or_else(|error| panic!("managed fixture manifest rejected: {error}"));
        let projection =
            ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(&manifest)
                .unwrap_or_else(|error| panic!("managed fixture projection rejected: {error}"));
        let projection_digest = transition_projection_digest(&projection)
            .unwrap_or_else(|error| panic!("managed fixture projection digest failed: {error}"));
        let (state_directory, store) =
            managed_fabric_store_fixture_from_snapshot(&snapshot, projection_digest);
        let started = StartedManagedFabricService::try_start_from_store(
            state_directory.path(),
            STORE_INSTANCE_ID,
            compiled,
            provisioning,
            store,
            dependencies,
        )
        .unwrap_or_else(|error| panic!("managed startup rejected: {error}"));
        (state_directory, started)
    }

    #[tokio::test]
    async fn distributed_dependencies_survive_reopen_and_control_cutover_without_reallocation() {
        let socket_directory = TestSocketDirectory::create();
        let evidence_directory = TestSocketDirectory::create();
        let evidence_root = evidence_directory.path.join("evidence-store");
        let expected_evidence = evidence_store_config(evidence_root.clone());
        let expected_epoch = expected_evidence.store_epoch();
        let expected_retention = expected_evidence.retention_policy();
        let expected_owner = expected_evidence.owner_ref();
        let (mut dependencies, expected_resolver, expected_agent_provider) =
            distributed_service_dependencies(expected_evidence);
        let expected_restricted = restricted_endpoint_dependencies(RESTRICTED_APPLY_ROUTE);
        dependencies.restricted_runtime_apply_endpoint = Some(expected_restricted.clone());
        let (_state_directory, mut started) = managed_started_service_with_dependencies(
            socket_directory.socket_path.clone(),
            dependencies,
        );
        started
            .core
            .recover()
            .await
            .unwrap_or_else(|error| panic!("managed dependency fixture recovery failed: {error}"));

        let reopened_distributed = started
            .dependencies
            .distributed_agent_stack_owner_dependencies()
            .unwrap_or_else(|| panic!("durable reopen lost distributed dependencies"));
        let reopen_resolver = Arc::clone(&reopened_distributed.fabric_credential_resolver);
        let reopen_evidence = reopened_distributed.evidence_store_config.clone();
        let reopen_agent_provider = started.dependencies.agent_provider_resolver();
        assert!(Arc::ptr_eq(&expected_resolver, &reopen_resolver));
        assert!(Arc::ptr_eq(
            &expected_agent_provider,
            &reopen_agent_provider
        ));
        assert_eq!(reopen_evidence.root(), evidence_root.as_path());
        assert_eq!(reopen_evidence.store_epoch(), expected_epoch);
        assert_eq!(reopen_evidence.retention_policy(), expected_retention);
        assert_eq!(reopen_evidence.owner_ref(), expected_owner);
        let reopened_restricted = started
            .dependencies
            .restricted_runtime_apply_endpoint
            .as_ref()
            .unwrap_or_else(|| panic!("durable reopen lost restricted endpoint dependencies"));
        assert_eq!(
            reopened_restricted.endpoint_config,
            expected_restricted.endpoint_config
        );
        assert_eq!(
            reopened_restricted.expected_carrier,
            expected_restricted.expected_carrier
        );
        validate_restricted_runtime_apply_endpoint_dependencies(
            reopened_restricted,
            &started.provisioning,
        )
        .unwrap_or_else(|error| panic!("reopened restricted dependencies failed: {error}"));

        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x91),
            digest(0x92),
        )
        .unwrap_or_else(|error| panic!("dependency fixture channel rejected: {error}"));
        let mut control = ManagedFabricControlService {
            core: started.core,
            stack: started.stack,
            stack_projection: started.stack_projection,
            model_stack: started.model_stack,
            model_stack_projection: started.model_stack_projection,
            distributed: started.distributed,
            distributed_projection: started.distributed_projection,
            handle_broker: started.handle_broker,
            state_directory: started.state_directory,
            provisioning: started.provisioning,
            channel,
            dependencies: started.dependencies,
        };
        let cutover_distributed = control
            .dependencies
            .distributed_agent_stack_owner_dependencies()
            .unwrap_or_else(|| panic!("first cutover lost distributed dependencies"));
        let cutover_resolver = Arc::clone(&cutover_distributed.fabric_credential_resolver);
        let cutover_agent_provider = control.dependencies.agent_provider_resolver();
        assert!(Arc::ptr_eq(&reopen_resolver, &cutover_resolver));
        assert!(Arc::ptr_eq(&reopen_agent_provider, &cutover_agent_provider));
        assert_eq!(
            cutover_distributed.evidence_store_config.root(),
            evidence_root.as_path()
        );
        assert_eq!(
            cutover_distributed.evidence_store_config.store_epoch(),
            expected_epoch
        );
        assert_eq!(
            cutover_distributed.evidence_store_config.retention_policy(),
            expected_retention
        );
        assert_eq!(
            cutover_distributed.evidence_store_config.owner_ref(),
            expected_owner
        );
        let cutover_restricted = control
            .dependencies
            .restricted_runtime_apply_endpoint
            .as_ref()
            .unwrap_or_else(|| panic!("control cutover lost restricted endpoint dependencies"));
        assert_eq!(
            cutover_restricted.endpoint_config,
            expected_restricted.endpoint_config
        );
        assert_eq!(
            cutover_restricted.expected_carrier,
            expected_restricted.expected_carrier
        );
        let source = include_str!("runtime_control_endpoint.rs");
        let reopen_owner = section(
            source,
            "    fn try_start_from_store(",
            "pub(crate) struct ManagedFabricControlService",
        );
        assert!(reopen_owner.contains("fabric_credential_resolver,"));
        assert!(reopen_owner.contains("evidence_store_config,"));
        assert!(
            reopen_owner
                .contains("agent_provider_resolver: dependencies.agent_provider_resolver(),")
        );
        assert!(!reopen_owner.contains("agent_provider_resolver: unavailable_provider_resolver"));
        let cutover_owner = section(
            source,
            "    async fn handle_distributed_agent_stack_apply(",
            "pub(crate) fn validate_restricted_runtime_apply_carrier_pins",
        );
        assert!(cutover_owner.contains("fabric_credential_resolver,"));
        assert!(cutover_owner.contains("evidence_store_config,"));
        assert!(
            cutover_owner
                .contains("agent_provider_resolver: self.dependencies.agent_provider_resolver(),")
        );
        assert!(!cutover_owner.contains("agent_provider_resolver: unavailable_provider_resolver"));

        control
            .core
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("managed dependency fixture shutdown failed: {error}"));
    }

    fn managed_available_port() -> u16 {
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .unwrap_or_else(|error| panic!("ephemeral bind failed: {error}"))
            .local_addr()
            .unwrap_or_else(|error| panic!("ephemeral address failed: {error}"))
            .port()
    }

    fn managed_lifecycle_budgets() -> ManagedServiceLifecycleBudgetsV1 {
        let budget = BoundedDuration::from_nanos(3_000_000_000);
        ManagedServiceLifecycleBudgetsV1::try_new(budget, budget, budget, budget, budget)
            .unwrap_or_else(|error| panic!("managed lifecycle budgets rejected: {error}"))
    }

    fn managed_writer_context(
        epoch_value: u64,
        supersedes_value: u64,
        nonce: &[u8],
    ) -> PlanWriterContext {
        let authority = TenureProofAuthority::try_new(
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            TenureProofAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("managed tenure algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("managed tenure authority failed: {error}"));
        let epoch = PlanWriterEpoch::new(epoch_value);
        let claim = WriterTenureClaim::try_new(
            SOURCE_SCOPE,
            WRITER,
            epoch,
            PlanWriterEpoch::new(supersedes_value),
        )
        .unwrap_or_else(|error| panic!("managed tenure claim failed: {error}"));
        let unsigned =
            WriterTenureProof::try_new(authority, claim, nonce, &[1; ED25519_SIGNATURE_BYTES])
                .unwrap_or_else(|error| panic!("managed unsigned tenure failed: {error}"));
        let signature = SigningKey::from_bytes(&TENURE_SEED)
            .sign(
                unsigned
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("managed tenure transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        let proof = WriterTenureProof::try_new(authority, claim, nonce, &signature)
            .unwrap_or_else(|error| panic!("managed tenure proof failed: {error}"));
        PlanWriterContext::try_new(WRITER, epoch, proof)
            .unwrap_or_else(|error| panic!("managed writer context failed: {error}"))
    }

    fn managed_temporal(clock_generation: ClockGeneration, seed: u8) -> ApplyTemporalConstraint {
        ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([seed; 16]),
            ClockDomainRef::from_bytes(CLOCK_DOMAIN),
            clock_generation,
            BoundedDuration::from_nanos(12_000_000_000),
            BoundedDuration::from_nanos(12_000_000_000),
        )
        .unwrap_or_else(|error| panic!("managed temporal constraint rejected: {error}"))
    }

    fn managed_auth(nonce: &[u8]) -> ApplyRequestAuthClaim {
        ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("managed auth algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
            nonce,
        )
        .unwrap_or_else(|error| panic!("managed auth claim rejected: {error}"))
    }

    fn managed_fabric_active_request(
        projection: ManagedFabricManifestProjectionV1,
        port: u16,
        clock_generation: ClockGeneration,
    ) -> ManagedFabricApplyRequestV1 {
        let service = ManagedServiceSpecV1::new(
            ManagedServiceId::from_bytes([0xa0; 16]),
            managed_lifecycle_budgets(),
        );
        let endpoint = ManagedFabricListenEndpointV1::try_new(&format!("tcp/127.0.0.1:{port}"))
            .unwrap_or_else(|error| panic!("managed Fabric endpoint rejected: {error}"));
        let execution = ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
            projection, service, endpoint,
        )
        .unwrap_or_else(|error| panic!("managed Fabric execution rejected: {error}"));
        let provenance = PlanProvenance::new(
            SOURCE_SCOPE,
            SourcePlanRef::from_bytes([0xa1; 16]),
            SourcePlanRevision::new(1),
            SourcePlanDigest::new(digest(0xa2)),
        );
        let control = RuntimeApplyControl::new(
            managed_writer_context(1, 0, b"managed-fabric-tenure-nonce"),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([0xa3; 16]),
        );
        let draft = ManagedFabricApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            managed_temporal(clock_generation, 0xa4),
            STORE_INSTANCE_ID,
            managed_auth(b"managed-fabric-request-nonce"),
        )
        .unwrap_or_else(|error| panic!("managed Fabric request draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("managed Fabric transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("managed Fabric request rejected: {error}"))
    }

    fn managed_agent_plan() -> ManagedAgentServicePlanV1 {
        let service = ManagedServiceSpecV1::new(
            ManagedServiceId::from_bytes([0xb0; 16]),
            managed_lifecycle_budgets(),
        );
        let semantic = ManagedAgentSemanticLimitsV1::try_new(8, 16, 16, 32)
            .unwrap_or_else(|error| panic!("managed Agent semantics rejected: {error}"));
        let ingress = ManagedAgentIngressLimitsV1::try_new(
            8,
            512 * 1024,
            64 * 1024,
            64 * 1024,
            2_000_000_000,
        )
        .unwrap_or_else(|error| panic!("managed Agent ingress rejected: {error}"));
        let port =
            ManagedAgentPortPlanV1::try_new_target_scoped(TARGET, service.service_id(), ingress)
                .unwrap_or_else(|error| panic!("managed Agent port rejected: {error}"));
        let provider = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([0xb3; 16])
                .unwrap_or_else(|error| panic!("managed provider ref rejected: {error}")),
            digest(0xb4),
        )
        .unwrap_or_else(|error| panic!("managed fixture provider rejected: {error}"));
        ManagedAgentServicePlanV1::try_new(service, semantic, port, provider)
            .unwrap_or_else(|error| panic!("managed Agent plan rejected: {error}"))
    }

    fn managed_model_plan(provider: ManagedAgentProviderSelectionV1) -> ManagedModelServicePlanV1 {
        let service = ManagedServiceSpecV1::new(
            ManagedServiceId::from_bytes([0xc1; 16]),
            managed_lifecycle_budgets(),
        );
        let adapter = ManagedModelAdapterBindingV1::try_new(
            [0xc2; 16],
            ManagedModelAdapterVersionV1::try_new(1)
                .unwrap_or_else(|error| panic!("managed Model adapter version rejected: {error}")),
            ManagedModelCapabilityIdV1::bounded_text_v1(),
        )
        .unwrap_or_else(|error| panic!("managed Model adapter binding rejected: {error}"));
        ManagedModelServicePlanV1::try_new(service, 2, provider, adapter)
            .unwrap_or_else(|error| panic!("managed Model plan rejected: {error}"))
    }

    fn managed_model_stack_active_request(
        fabric_request: &ManagedFabricApplyRequestV1,
        projection: ManagedModelAgentStackProjectionV1,
        clock_generation: ClockGeneration,
    ) -> ManagedModelAgentStackApplyRequestV1 {
        let agent = managed_agent_plan();
        let model = managed_model_plan(agent.provider());
        let embedded = ManagedAgentStackTargetExecutionV1::try_fabric_and_agent(
            projection.managed_agent_stack_projection().clone(),
            fabric_request.target_execution().clone(),
            agent,
        )
        .unwrap_or_else(|error| panic!("managed Model+Agent embedded stack rejected: {error}"));
        let execution = ManagedModelAgentStackTargetExecutionV1::try_fabric_model_and_agent(
            projection, embedded, model,
        )
        .unwrap_or_else(|error| panic!("managed Model+Agent execution rejected: {error}"));
        let provenance = PlanProvenance::new(
            SOURCE_SCOPE,
            SourcePlanRef::from_bytes([0xa1; 16]),
            SourcePlanRevision::new(2),
            SourcePlanDigest::new(digest(0xc3)),
        );
        let control = RuntimeApplyControl::new(
            fabric_request
                .control_commitment()
                .control()
                .writer_context()
                .clone(),
            ExpectedActive::Exact(fabric_request.target_slice_digest()),
            ApplyOperationId::from_bytes([0xc4; 16]),
        );
        let draft = ManagedModelAgentStackApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            managed_temporal(clock_generation, 0xc5),
            STORE_INSTANCE_ID,
            managed_auth(b"managed-model-agent-request-nonce"),
        )
        .unwrap_or_else(|error| panic!("managed Model+Agent request draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| {
                        panic!("managed Model+Agent transcript failed: {error}")
                    })
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("managed Model+Agent request rejected: {error}"))
    }

    fn managed_stack_active_request(
        fabric_request: &ManagedFabricApplyRequestV1,
        projection: ManagedAgentStackProjectionV1,
        clock_generation: ClockGeneration,
    ) -> ManagedAgentStackApplyRequestV1 {
        let execution = ManagedAgentStackTargetExecutionV1::try_fabric_and_agent(
            projection,
            fabric_request.target_execution().clone(),
            managed_agent_plan(),
        )
        .unwrap_or_else(|error| panic!("managed stack execution rejected: {error}"));
        let provenance = PlanProvenance::new(
            SOURCE_SCOPE,
            SourcePlanRef::from_bytes([0xa1; 16]),
            SourcePlanRevision::new(2),
            SourcePlanDigest::new(digest(0xb5)),
        );
        let control = RuntimeApplyControl::new(
            fabric_request
                .control_commitment()
                .control()
                .writer_context()
                .clone(),
            ExpectedActive::Exact(fabric_request.target_slice_digest()),
            ApplyOperationId::from_bytes([0xb6; 16]),
        );
        let draft = ManagedAgentStackApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            managed_temporal(clock_generation, 0xb7),
            STORE_INSTANCE_ID,
            managed_auth(b"managed-stack-active-request-nonce"),
        )
        .unwrap_or_else(|error| panic!("managed stack request draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("managed stack transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("managed stack request rejected: {error}"))
    }

    fn managed_stack_empty_request(
        active: &ManagedAgentStackApplyRequestV1,
        clock_generation: ClockGeneration,
    ) -> ManagedAgentStackApplyRequestV1 {
        let execution = ManagedAgentStackTargetExecutionV1::try_empty_deactivate(
            active.target_execution().projection().clone(),
        )
        .unwrap_or_else(|error| panic!("managed empty stack execution rejected: {error}"));
        let provenance = PlanProvenance::new(
            SOURCE_SCOPE,
            SourcePlanRef::from_bytes([0xa1; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(digest(0xb8)),
        );
        let control = RuntimeApplyControl::new(
            active
                .control_commitment()
                .control()
                .writer_context()
                .clone(),
            ExpectedActive::Exact(active.target_slice_digest()),
            ApplyOperationId::from_bytes([0xb9; 16]),
        );
        let draft = ManagedAgentStackApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            managed_temporal(clock_generation, 0xba),
            STORE_INSTANCE_ID,
            managed_auth(b"managed-stack-empty-request-nonce"),
        )
        .unwrap_or_else(|error| panic!("managed empty stack draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("managed empty transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("managed empty request rejected: {error}"))
    }

    fn distributed_stack_active_request(
        active: &ManagedAgentStackApplyRequestV1,
        projection: DistributedAgentStackProjectionV1,
        clock_generation: ClockGeneration,
    ) -> DistributedAgentStackApplyRequestV1 {
        // This is desired topology only. The fixture keeps distributed owner
        // dependencies explicitly unavailable, so no transport or TLS proof is
        // fabricated and the legal first-cutover request fails closed to zero.
        let authentication = DistributedFabricPeerAuthenticationRequirementV1::try_mutual_tls(
            DistributedFabricTrustDomainRefV1::try_from_bytes([0xd1; 16])
                .unwrap_or_else(|error| panic!("distributed trust-domain ref rejected: {error}")),
            DistributedFabricCredentialRefV1::try_from_bytes([0xd2; 16])
                .unwrap_or_else(|error| panic!("distributed credential ref rejected: {error}")),
            DistributedFabricTrustAnchorRefV1::try_from_bytes([0xd3; 16])
                .unwrap_or_else(|error| panic!("distributed trust-anchor ref rejected: {error}")),
            DistributedFabricPeerIdentityRefV1::try_from_bytes([0xd4; 16])
                .unwrap_or_else(|error| panic!("distributed peer-identity ref rejected: {error}")),
        )
        .unwrap_or_else(|error| panic!("distributed authentication rejected: {error}"));
        let peer = DistributedFabricPeerPlanV1::try_new(
            RuntimeHostId::from_bytes([0xd5; 16]),
            DistributedFabricTlsEndpointV1::try_new("tls/192.0.2.11:7447")
                .unwrap_or_else(|error| panic!("distributed peer endpoint rejected: {error}")),
            authentication,
        )
        .unwrap_or_else(|error| panic!("distributed peer rejected: {error}"));
        let topology = DistributedFabricTopologyV1::try_new(
            projection.target(),
            active
                .target_execution()
                .fabric()
                .listen_endpoint()
                .unwrap_or_else(|| panic!("active predecessor lost its loopback listener"))
                .clone(),
            DistributedFabricTlsEndpointV1::try_new("tls/192.0.2.10:7447")
                .unwrap_or_else(|error| panic!("distributed listen endpoint rejected: {error}")),
            vec![peer],
        )
        .unwrap_or_else(|error| panic!("distributed topology rejected: {error}"));
        let execution = DistributedAgentStackTargetExecutionV1::try_distributed_fabric_and_agent(
            projection,
            active.target_execution().clone(),
            topology,
        )
        .unwrap_or_else(|error| panic!("distributed active execution rejected: {error}"));
        let provenance = PlanProvenance::new(
            SOURCE_SCOPE,
            SourcePlanRef::from_bytes([0xa1; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(digest(0xc0)),
        );
        let control = RuntimeApplyControl::new(
            active
                .control_commitment()
                .control()
                .writer_context()
                .clone(),
            ExpectedActive::Exact(active.target_slice_digest()),
            ApplyOperationId::from_bytes([0xc1; 16]),
        );
        let draft = DistributedAgentStackApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            managed_temporal(clock_generation, 0xc2),
            STORE_INSTANCE_ID,
            managed_auth(b"distributed-stack-active-request-nonce"),
        )
        .unwrap_or_else(|error| panic!("distributed active draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("distributed active transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("distributed active request rejected: {error}"))
    }

    fn distributed_active_terminal_receipt(
        request: &DistributedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
        selection_observed_at_nanos: u64,
    ) -> DistributedAgentStackTerminalReceiptV1 {
        let peer = request
            .target_execution()
            .topology()
            .and_then(|topology| topology.peers().first())
            .unwrap_or_else(|| panic!("distributed ActiveReady fixture lost its peer"));
        let proof = DistributedFabricObservedTransportProofV1::try_new(
            request.target(),
            peer,
            DistributedFabricObservedTransportProofFieldsV1 {
                local_runtime_host: request.target(),
                peer_runtime_host: peer.peer_runtime_host(),
                session_epoch: DistributedFabricSessionEpochV1::try_from_bytes([0xe3; 16])
                    .unwrap_or_else(|error| panic!("fixture session epoch rejected: {error}")),
                authenticated_peer_identity_ref: peer.authentication().expected_peer_identity_ref(),
                selected_local_credential_ref: peer.authentication().local_credential_ref(),
                transport_evidence_ref: DistributedFabricTransportEvidenceRefV1::try_from_bytes(
                    [0xe4; 16],
                )
                .unwrap_or_else(|error| panic!("fixture transport Evidence ref rejected: {error}")),
                observation_sequence: 41,
            },
        )
        .unwrap_or_else(|error| panic!("fixture transport proof rejected: {error}"));
        let observations =
            DistributedAgentStackTerminalObservationsV1::try_new(request, vec![proof])
                .unwrap_or_else(|error| panic!("fixture terminal observations rejected: {error}"));
        let installed_binding_set_digest =
            distributed_agent_stack_installed_binding_set_digest_v1(digest(0xf1), digest(0xf2))
                .unwrap_or_else(|error| panic!("fixture binding-set digest rejected: {error}"));
        let facts =
            DistributedAgentStackTerminalFactsV1::try_new(
                request,
                DistributedAgentStackTerminalOutcomeV1::ActiveReady,
                DistributedAgentStackTerminalEvidenceFieldsV1 {
                    runtime_host_epoch: 2,
                    completion_snapshot_sequence: 17,
                    selection_clock_generation: request.temporal().target_clock_generation(),
                    selection_observed_at_nanos,
                    fabric_generation: Some(ManagedServiceGeneration::try_new(2).unwrap_or_else(
                        |error| panic!("fixture Fabric generation rejected: {error}"),
                    )),
                    agent_generation: Some(ManagedServiceGeneration::try_new(3).unwrap_or_else(
                        |error| panic!("fixture Agent generation rejected: {error}"),
                    )),
                    local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1 {
                        physical_binding_census: 2,
                        census_complete: true,
                        fabric_ready: true,
                        agent_ready: true,
                        dependency_satisfied: true,
                        exact_zero: false,
                        quarantined: false,
                        installed_binding_set_digest,
                        raw_outcome_digest: digest(0xf3),
                    },
                },
                observations,
            )
            .unwrap_or_else(|error| panic!("fixture ActiveReady facts rejected: {error}"));
        let auth = DistributedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            RESPONSE_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("fixture terminal algorithm rejected: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("fixture terminal auth rejected: {error}"));
        let draft =
            DistributedAgentStackTerminalReceiptDraftV1::try_new(request, facts, channel, auth)
                .unwrap_or_else(|error| {
                    panic!("fixture ActiveReady PXDS1 draft rejected: {error}")
                });
        let signature = SigningKey::from_bytes(&RESPONSE_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| {
                        panic!("fixture ActiveReady PXDS1 transcript rejected: {error}")
                    })
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("fixture ActiveReady PXDS1 rejected: {error}"))
    }

    fn restricted_carrier(
        provisioning: &RuntimeProvisioningV1,
        request: &DistributedAgentStackApplyRequestV1,
        route: &str,
        controller_key_fingerprint: Digest32,
        runtime_response_key_fingerprint: Digest32,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: request.target(),
                runtime_principal: provisioning.runtime_principal(),
                controller_principal: provisioning.controller_principal(),
                endpoint_ref: [0xc3; 16],
                endpoint_generation: 1,
                route,
                controller_request_key: provisioning.controller_request_key_ref(),
                controller_request_key_fingerprint: controller_key_fingerprint,
                runtime_response_key: provisioning.runtime_response_key_ref(),
                runtime_response_key_fingerprint,
                control_transport_profile_ref: [0xc4; 16],
                control_transport_profile_digest: digest(0xc5),
            },
        )
        .unwrap_or_else(|error| panic!("restricted carrier rejected: {error}"))
    }

    fn pinned_restricted_carrier(
        provisioning: &RuntimeProvisioningV1,
        request: &DistributedAgentStackApplyRequestV1,
        route: &str,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        let runtime_response_key_fingerprint = ed25519_control_key_fingerprint(
            provisioning.response_signer().verifying_key().as_bytes(),
        )
        .unwrap_or_else(|error| panic!("Runtime response fingerprint failed: {error}"));
        restricted_carrier(
            provisioning,
            request,
            route,
            provisioning.controller_key_fingerprint(),
            runtime_response_key_fingerprint,
        )
    }

    fn restricted_apply_request(
        request: DistributedAgentStackApplyRequestV1,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
    ) -> DistributedAgentStackRestrictedApplyRequestV1 {
        let draft = DistributedAgentStackRestrictedApplyRequestDraftV1::try_new(request, carrier)
            .unwrap_or_else(|error| panic!("restricted request draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("restricted transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("restricted request rejected: {error}"))
    }

    async fn managed_control_with_active_stack(
        socket_path: PathBuf,
    ) -> (
        TestDirectory,
        ManagedFabricControlService,
        ManagedAgentStackApplyRequestV1,
    ) {
        let (state_directory, mut started) = managed_started_service(socket_path);
        started
            .core
            .recover()
            .await
            .unwrap_or_else(|error| panic!("restricted predecessor recovery failed: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xe5),
            digest(0xe6),
        )
        .unwrap_or_else(|error| panic!("restricted channel rejected: {error}"));
        let fabric_request = managed_fabric_active_request(
            started.stack_projection.managed_fabric_projection().clone(),
            managed_available_port(),
            started
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("restricted predecessor clock failed: {error}"))
                .generation(),
        );
        let mut control = ManagedFabricControlService {
            core: started.core,
            stack: started.stack,
            stack_projection: started.stack_projection,
            model_stack: started.model_stack,
            model_stack_projection: started.model_stack_projection,
            distributed: started.distributed,
            distributed_projection: started.distributed_projection,
            handle_broker: started.handle_broker,
            state_directory: started.state_directory,
            provisioning: started.provisioning,
            channel,
            dependencies: started.dependencies,
        };
        let profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let carrier = restricted_carrier_for_profile(&profile, RESTRICTED_PROFILE_REF);
        let fabric_outer = signed_runtime_agent_fabric_apply(
            carrier.clone(),
            fabric_request.clone(),
            control.core.runtime_host_epoch(),
        );
        let fabric_wire = control
            .handle_restricted_runtime_control_frame_v1(fabric_outer.canonical_wire(), &carrier)
            .await
            .unwrap_or_else(|error| panic!("restricted predecessor PXAG-v1 failed: {error:?}"));
        let fabric_outer_receipt = RuntimeAgentControlReceiptV1::decode(&fabric_wire)
            .unwrap_or_else(|error| panic!("restricted predecessor PXAH-v1 failed: {error}"));
        fabric_outer_receipt
            .verify_runtime_apply_receipt(
                &fabric_outer,
                channel,
                &carrier,
                verify_runtime_agent_response_signature,
            )
            .unwrap_or_else(|error| {
                panic!("restricted predecessor PXAH verification failed: {error}")
            });
        let fabric_receipt = fabric_outer_receipt
            .managed_fabric_receipt()
            .unwrap_or_else(|| panic!("restricted predecessor PXAH lost PXFT"));
        assert_eq!(
            fabric_receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        );
        let stack_request = managed_stack_active_request(
            &fabric_request,
            control.stack_projection.clone(),
            control
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("restricted stack clock failed: {error}"))
                .generation(),
        );
        let stack_outer = signed_runtime_agent_stack_apply(
            carrier.clone(),
            stack_request.clone(),
            control.core.runtime_host_epoch(),
        );
        let stack_wire = control
            .handle_restricted_runtime_control_frame_v1(stack_outer.canonical_wire(), &carrier)
            .await
            .unwrap_or_else(|error| panic!("restricted predecessor PXAG-v2 failed: {error:?}"));
        let stack_outer_receipt = RuntimeAgentControlReceiptV1::decode(&stack_wire)
            .unwrap_or_else(|error| panic!("restricted predecessor PXAH-v2 failed: {error}"));
        stack_outer_receipt
            .verify_runtime_apply_receipt(
                &stack_outer,
                channel,
                &carrier,
                verify_runtime_agent_response_signature,
            )
            .unwrap_or_else(|error| panic!("restricted stack PXAH verification failed: {error}"));
        let stack_receipt = stack_outer_receipt
            .managed_agent_stack_receipt()
            .unwrap_or_else(|| panic!("restricted stack PXAH lost PXST"));
        assert_eq!(
            stack_receipt.facts().state().outcome(),
            ManagedAgentStackTerminalOutcomeV1::ActiveReady
        );
        let replay_sequence = control
            .core
            .recovered_observation()
            .unwrap_or_else(|error| panic!("pre-replay observation failed: {error}"))
            .successor_snapshot_sequence;
        assert_eq!(
            control
                .handle_restricted_runtime_control_frame_v1(stack_outer.canonical_wire(), &carrier)
                .await
                .unwrap_or_else(|error| panic!("same PXAG-v2 replay failed: {error:?}")),
            stack_wire,
            "same-epoch exact PXAG replay must return byte-identical PXAH",
        );
        assert_eq!(
            control
                .core
                .recovered_observation()
                .unwrap_or_else(|error| panic!("post-replay observation failed: {error}"))
                .successor_snapshot_sequence,
            replay_sequence,
            "same PXAG replay must not commit a second successor transition",
        );
        assert!(control.stack.is_some());
        assert!(control.distributed.is_none());
        (state_directory, control, stack_request)
    }

    struct MockStore {
        snapshot: RuntimeJournalSnapshot,
        commit_attempts: Rc<Cell<u32>>,
        fail_commit: bool,
        socket_path: PathBuf,
    }

    impl RuntimeBootstrapStore for MockStore {
        fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeBootstrapEndpointError> {
            Ok(&self.snapshot)
        }

        fn commit(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeBootstrapEndpointError> {
            assert!(
                !self.socket_path.exists(),
                "socket became visible before startup invalidation commit"
            );
            self.commit_attempts
                .set(self.commit_attempts.get().saturating_add(1));
            if self.fail_commit {
                return Err(RuntimeBootstrapEndpointError::Runtime);
            }
            self.snapshot = next;
            Ok(())
        }
    }

    impl RuntimeReferenceApplyStore for MockStore {
        fn current_snapshot(
            &self,
        ) -> Result<RuntimeJournalSnapshot, RuntimeReferenceApplyStoreError> {
            Ok(self.snapshot.clone())
        }

        fn commit_snapshot(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeReferenceApplyStoreError> {
            assert!(
                !self.socket_path.exists(),
                "socket became visible before restart reassembly commit"
            );
            self.commit_attempts
                .set(self.commit_attempts.get().saturating_add(1));
            if self.fail_commit {
                return Err(RuntimeReferenceApplyStoreError::Unavailable);
            }
            self.snapshot = next;
            Ok(())
        }
    }

    struct StartupCrashStore {
        snapshot: RuntimeJournalSnapshot,
        durable_snapshot: Rc<RefCell<RuntimeJournalSnapshot>>,
        commit_attempts: Rc<Cell<u32>>,
        fail_after_publish_on: u32,
        socket_path: PathBuf,
    }

    impl RuntimeBootstrapStore for StartupCrashStore {
        fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeBootstrapEndpointError> {
            Ok(&self.snapshot)
        }

        fn commit(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeBootstrapEndpointError> {
            assert!(!self.socket_path.exists());
            let attempt = self.commit_attempts.get().saturating_add(1);
            self.commit_attempts.set(attempt);
            self.snapshot = next.clone();
            *self.durable_snapshot.borrow_mut() = next;
            if attempt == self.fail_after_publish_on {
                return Err(RuntimeBootstrapEndpointError::Runtime);
            }
            Ok(())
        }
    }

    impl RuntimeReferenceApplyStore for StartupCrashStore {
        fn current_snapshot(
            &self,
        ) -> Result<RuntimeJournalSnapshot, RuntimeReferenceApplyStoreError> {
            Ok(self.snapshot.clone())
        }

        fn commit_snapshot(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeReferenceApplyStoreError> {
            assert!(!self.socket_path.exists());
            let attempt = self.commit_attempts.get().saturating_add(1);
            self.commit_attempts.set(attempt);
            self.snapshot = next.clone();
            *self.durable_snapshot.borrow_mut() = next;
            if attempt == self.fail_after_publish_on {
                return Err(RuntimeReferenceApplyStoreError::Unavailable);
            }
            Ok(())
        }
    }

    struct FailingRetireOwner {
        active_slice_digest: TargetSliceDigest,
        resource_generation: u64,
        plan: RuntimeEmptyRetireOwnerPlan,
    }

    impl RuntimeReferenceMaterializationOwner for FailingRetireOwner {
        fn prepare_one_source(
            &mut self,
            _request: &ReferenceApplyRequestV1,
            _durable_action: Option<JournalActionRef>,
        ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
            Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
        }

        fn materialize_one_source(
            &mut self,
            _action: JournalActionRef,
            _resources: RuntimeOneSourceResourceRefs,
        ) -> Result<RuntimeOneSourceOwnershipInput, RuntimeReferenceMaterializationOwnerError>
        {
            Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
        }

        fn start_one_source_once(
            &mut self,
            _action: JournalActionRef,
        ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
            Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
        }

        fn prepare_empty_retire(
            &mut self,
            active_slice_digest: TargetSliceDigest,
            resource_generation: u64,
            durable_action: Option<JournalActionRef>,
        ) -> Result<RuntimeEmptyRetireOwnerPlan, RuntimeReferenceMaterializationOwnerError>
        {
            if active_slice_digest != self.active_slice_digest
                || resource_generation != self.resource_generation
                || durable_action.is_some_and(|action| action.action_id != self.plan.action_id)
            {
                return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
            }
            Ok(self.plan)
        }

        fn stop_one_source_once(
            &mut self,
            _action: JournalActionRef,
        ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
            Err(RuntimeReferenceMaterializationOwnerError::CallbackFailed)
        }

        fn cleanup_one_source_once(
            &mut self,
            _action: JournalActionRef,
        ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError>
        {
            Err(RuntimeReferenceMaterializationOwnerError::CleanupFailed)
        }
    }

    fn started_service(socket_path: PathBuf) -> StartedRuntimeBootstrapService<MockStore> {
        let initial_provisioning = provisioning(socket_path.clone());
        let (snapshot, compiled) = installed_snapshot(&initial_provisioning);
        StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            compiled,
            initial_provisioning,
        )
        .unwrap_or_else(|error| panic!("startup rejected: {error}"))
    }

    fn head_first_retiring_service(
        socket_path: PathBuf,
    ) -> (
        RuntimeControlService<MockStore, FailingRetireOwner>,
        ReferenceApplyRequestV1,
        ReferenceChannelBindingV1,
    ) {
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let active_request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"query-draining-active-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xe1),
            digest(0xe2),
        )
        .unwrap_or_else(|error| panic!("draining channel rejected: {error}"));
        let mut active_service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("draining control service rejected: {error}"));
        let active_pxrt = active_service
            .handle_request(active_request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("draining active apply rejected: {error:?}"))
            .unwrap_or_else(|| panic!("draining active apply returned no PXRT"));
        let active_receipt = ReferenceApplyTerminalReceiptV1::decode(&active_pxrt)
            .unwrap_or_else(|error| panic!("draining active PXRT decode failed: {error}"));
        assert_eq!(
            active_receipt.facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        );

        let active_snapshot = active_service.apply.snapshot().clone();
        let (active_slice_digest, resource_generation) =
            match active_snapshot.state().live_materialization {
                LiveMaterialization::LiveReady {
                    active_slice_digest,
                    resource_generation,
                    ..
                } => (active_slice_digest, resource_generation),
                other => panic!("draining fixture did not become LiveReady: {other:?}"),
            };
        let budgets = active_request
            .target_execution()
            .loop_facts()
            .unwrap_or_else(|| panic!("draining active request lost loop facts"))
            .budgets();
        let compiled = active_service.compiled;
        let compatibility = active_service.compatibility.clone();
        let clock = active_service.clock;
        drop(active_service);

        let provisioning = provisioning(socket_path.clone());
        let signer = RuntimeReferenceApplySigner::try_new(
            provisioning.response_signer().clone(),
            provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("draining response algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("draining response signer failed: {error:?}"));
        let owner = FailingRetireOwner {
            active_slice_digest,
            resource_generation,
            plan: RuntimeEmptyRetireOwnerPlan {
                action_id: [0xe3; 16],
                signed_budgets: budgets,
            },
        };
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            MockStore {
                snapshot: active_snapshot.clone(),
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            RuntimeEndpointApplyClock { clock },
            owner,
            signer,
            channel,
        )
        .unwrap_or_else(|error| panic!("draining apply core rejected: {error:?}"));
        let mut service = RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning,
            channel,
        };
        let retire_request = signed_apply_request(
            &active_snapshot,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::EmptyDeactivate,
                operation: 0xe4,
                request_nonce: b"query-draining-retire-nonce",
                tenure_nonce: b"query-draining-retire-tenure",
                writer_epoch: 2,
                supersedes_epoch: 1,
                source_revision: 2,
                temporal_constraint: 0xe5,
                expected_active: ExpectedActive::Exact(active_slice_digest),
                ..ApplyRequestFixture::valid()
            },
        );
        assert!(matches!(
            service.handle_request(retire_request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Owner(
                    RuntimeReferenceMaterializationOwnerError::CallbackFailed
                ))
            ))
        ));
        let prepared = service
            .apply
            .snapshot()
            .state()
            .prepared
            .as_ref()
            .unwrap_or_else(|| panic!("draining fixture lost prepared operation"));
        assert_eq!(prepared.phase, PreparedPhase::HeadCommittedRetiringOld);
        assert!(prepared.retiring.is_some());
        assert!(matches!(
            service.apply.snapshot().state().live_materialization,
            LiveMaterialization::Draining { .. }
        ));
        (service, retire_request, channel)
    }

    fn active_loop_restart_fixture(
        socket_path: PathBuf,
        request_nonce: &'static [u8],
    ) -> (RuntimeJournalSnapshot, RuntimeCompiledInstallationFactsV1) {
        let started = started_service(socket_path);
        let initial = started.state.snapshot().clone();
        let request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce,
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xb4),
            digest(0xb5),
        )
        .unwrap_or_else(|error| panic!("active restart channel rejected: {error}"));
        let mut service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("active restart service rejected: {error}"));
        service
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("active restart apply failed: {error:?}"))
            .unwrap_or_else(|| panic!("active restart apply returned no PXRT"));
        assert!(matches!(
            service.apply.snapshot().state().live_materialization,
            LiveMaterialization::LiveReady { .. }
        ));
        (service.apply.snapshot().clone(), service.compiled)
    }

    fn higher_tenure_successor(
        current: &RuntimeJournalSnapshot,
        evidence_byte: u8,
    ) -> RuntimeJournalSnapshot {
        let fence = current
            .state()
            .writer_fence
            .unwrap_or_else(|| panic!("takeover fixture lost writer fence"));
        current
            .try_tenure_only_successor(RuntimeTenureAdmissionInput {
                expected_store_instance_id: *current.store_instance_id(),
                owner_target_fingerprint: *current.owner_target_fingerprint(),
                source_scope: fence.source_scope,
                writer: fence.writer,
                epoch: fence
                    .epoch
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("takeover epoch overflow")),
                supersedes_through_epoch: fence.epoch,
                proof_envelope_digest: digest(evidence_byte),
                tenure_nonce_identity: digest(evidence_byte.wrapping_add(1)),
                principal: fence.principal,
            })
            .unwrap_or_else(|error| panic!("takeover successor failed: {error:?}"))
    }

    fn assert_reserved_crash_generation_is_exact_zero(
        snapshot: &RuntimeJournalSnapshot,
        generation: u64,
    ) {
        let resources = snapshot
            .state()
            .owned_resources
            .iter()
            .filter(|resource| resource.generation == generation)
            .collect::<Vec<_>>();
        assert_eq!(resources.len(), 2, "reserved generation census changed");
        assert!(resources.iter().all(|resource| {
            resource.phase == ResourcePhase::ReservedAtCrashExactZero
                && resource.action_id.is_none()
                && resource.os_identity.is_none()
                && resource.workspace_identity.is_none()
                && resource.containment_identity.is_none()
                && resource.tombstone_evidence.is_some()
        }));
    }

    fn assert_owned_crash_generation_is_tombstoned(
        snapshot: &RuntimeJournalSnapshot,
        generation: u64,
    ) {
        let resources = snapshot
            .state()
            .owned_resources
            .iter()
            .filter(|resource| resource.generation == generation)
            .collect::<Vec<_>>();
        assert_eq!(resources.len(), 2, "owned generation census changed");
        assert!(resources.iter().all(|resource| {
            resource.phase == ResourcePhase::Terminal
                && resource.action_id.is_none()
                && resource.os_identity.is_some()
                && resource.workspace_identity.is_some()
                && resource.containment_identity.is_some()
                && resource.tombstone_evidence.is_some()
        }));
    }

    fn terminal_for_request<'a>(
        snapshot: &'a RuntimeJournalSnapshot,
        request: &ReferenceApplyRequestV1,
    ) -> &'a crate::runtime_journal::TerminalOperationRecord {
        let operation_id = request.control_commitment().control().operation_id();
        snapshot
            .state()
            .terminal_operations
            .iter()
            .find(|terminal| terminal.operation_id == *operation_id.as_bytes())
            .unwrap_or_else(|| panic!("restart terminal for operation is missing"))
    }

    fn signed_bootstrap_request(
        target: RuntimeHostId,
        scope: SourceScopeRef,
        signature_seed: [u8; 32],
    ) -> ReferenceBootstrapRequestV1 {
        let auth = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("auth algorithm rejected: {error}")),
            ED25519_ALGORITHM_VERSION,
            b"endpoint-test-nonce",
        )
        .unwrap_or_else(|error| panic!("auth claim rejected: {error}"));
        let draft = ReferenceBootstrapRequestDraftV1::try_new(
            ReferenceBootstrapRequestIdV1::from_bytes([0x71; 16]),
            target,
            scope,
            auth,
            u32::try_from(MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES)
                .unwrap_or_else(|_| panic!("response bound exceeds u32")),
        )
        .unwrap_or_else(|error| panic!("bootstrap draft rejected: {error}"));
        let signer = SigningKey::from_bytes(&signature_seed);
        let signature = signer
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("request transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("request finalization failed: {error}"))
    }

    #[derive(Clone, Copy)]
    struct QueryRequestFixture {
        query: u8,
        target: RuntimeHostId,
        scope: SourceScopeRef,
        store: [u8; 32],
        operation: u8,
        expected_request_digest: Option<Digest32>,
        nonce: &'static [u8],
        controller_seed: [u8; 32],
        max_response_bytes: u32,
    }

    impl QueryRequestFixture {
        fn fresh(operation: u8) -> Self {
            Self {
                query: 0x81,
                target: TARGET,
                scope: SOURCE_SCOPE,
                store: STORE_INSTANCE_ID,
                operation,
                expected_request_digest: None,
                nonce: b"endpoint-query-nonce",
                controller_seed: CONTROLLER_SEED,
                max_response_bytes: u32::try_from(MAX_REFERENCE_QUERY_RESPONSE_BYTES)
                    .unwrap_or_else(|_| panic!("query response bound exceeds u32")),
            }
        }
    }

    fn signed_query_request(fixture: QueryRequestFixture) -> ReferenceQueryRequestV1 {
        let selector = ReferenceQuerySelectorV1::try_new(
            ReferenceQueryIdV1::from_bytes([fixture.query; 16]),
            fixture.target,
            fixture.scope,
            fixture.store,
            ApplyOperationId::from_bytes([fixture.operation; 16]),
            fixture.expected_request_digest,
        )
        .unwrap_or_else(|error| panic!("query selector rejected: {error}"));
        let claim = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("query algorithm rejected: {error}")),
            ED25519_ALGORITHM_VERSION,
            fixture.nonce,
        )
        .unwrap_or_else(|error| panic!("query claim rejected: {error}"));
        let draft =
            ReferenceQueryRequestDraftV1::try_new(selector, claim, fixture.max_response_bytes)
                .unwrap_or_else(|error| panic!("query draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&fixture.controller_seed)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("query transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("query finalization failed: {error}"))
    }

    fn independent_query_serving(
        snapshot: &RuntimeJournalSnapshot,
    ) -> ReferenceBootstrapServingIdentityV1 {
        ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            *snapshot.store_instance_id(),
            snapshot.sequence(),
            snapshot.state().host.runtime_host_epoch_high_water,
            ClockDomainRef::from_bytes(snapshot.state().host.clock_domain),
            ClockGeneration::try_new(snapshot.state().host.clock_generation_high_water)
                .unwrap_or_else(|error| panic!("query baseline clock rejected: {error}")),
        )
        .unwrap_or_else(|error| panic!("query serving baseline rejected: {error}"))
    }

    fn decode_verify_query_response(
        response_wire: &[u8],
        request: &ReferenceQueryRequestV1,
        channel: ReferenceChannelBindingV1,
        expected_serving: ReferenceBootstrapServingIdentityV1,
    ) -> (ReferenceQueryResponseV1, ReferenceQueryFactsV1) {
        let response = ReferenceQueryResponseV1::decode(response_wire)
            .unwrap_or_else(|error| panic!("PXQS decode failed: {error}"));
        let signature: [u8; ED25519_SIGNATURE_BYTES] = response
            .authentication_signature()
            .try_into()
            .unwrap_or_else(|_| panic!("PXQS signature width changed"));
        SigningKey::from_bytes(&RESPONSE_SEED)
            .verifying_key()
            .verify_strict(
                response
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("PXQS transcript failed: {error}"))
                    .as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .unwrap_or_else(|error| panic!("PXQS signature failed: {error}"));
        let facts = response
            .validate_against_request(request, channel, expected_serving)
            .unwrap_or_else(|error| panic!("PXQS correlation failed: {error}"));
        (response, facts)
    }

    #[test]
    fn runtime_control_outer_auth_precedes_legacy_describe_and_query_without_mutation() {
        let socket_directory = TestSocketDirectory::create();
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xc1),
            digest(0xc2),
        )
        .unwrap_or_else(|error| panic!("Runtime-control channel rejected: {error}"));
        let legacy = started_service(socket_directory.socket_path.clone())
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("legacy control start failed: {error}"));
        let profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let carrier = restricted_carrier_for_profile(&profile, RESTRICTED_PROFILE_REF);
        let before = legacy.apply.snapshot().clone();

        let describe = signed_runtime_control_describe(
            carrier.clone(),
            0xc3,
            b"legacy-describe-outer-nonce",
            CONTROLLER_SEED,
        );
        let decoded = decode_runtime_control_carrier(describe.canonical_wire())
            .unwrap_or_else(|_| panic!("canonical Describe carrier failed to decode"));
        let authenticated =
            authenticate_runtime_control_carrier(&legacy.provisioning, &decoded, &carrier)
                .unwrap_or_else(|_| panic!("canonical Describe carrier failed authentication"));
        let facts = legacy_runtime_control_describe_facts(&legacy, channel)
            .unwrap_or_else(|_| panic!("legacy Describe facts failed"));
        assert_eq!(
            facts.phase(),
            RuntimeControlDescribeReadyPhaseV1::LegacyReady
        );
        let response_wire =
            runtime_control_describe_response(&legacy.provisioning, authenticated, facts)
                .unwrap_or_else(|_| panic!("legacy Describe response failed"));
        let response = RuntimeControlDescribeReadyResponseV1::decode(&response_wire)
            .unwrap_or_else(|error| panic!("legacy PXDR decode failed: {error}"));
        let verified = response
            .verify_runtime_response(
                &decoded,
                &carrier,
                |principal, key, fingerprint, transcript, signature| {
                    if principal != RUNTIME_PRINCIPAL
                        || key != RESPONSE_KEY_REF
                        || fingerprint != carrier.runtime_response_key_fingerprint()
                    {
                        return false;
                    }
                    let Ok(signature) = Signature::from_slice(signature) else {
                        return false;
                    };
                    SigningKey::from_bytes(&RESPONSE_SEED)
                        .verifying_key()
                        .verify_strict(transcript, &signature)
                        .is_ok()
                },
            )
            .unwrap_or_else(|error| panic!("legacy PXDR verification failed: {error}"));
        assert_eq!(
            verified.facts().phase(),
            RuntimeControlDescribeReadyPhaseV1::LegacyReady
        );

        let query = signed_query_request(QueryRequestFixture::fresh(0xc4));
        let control_query = signed_runtime_control_reference_query(
            carrier.clone(),
            query.clone(),
            0xc5,
            b"legacy-reference-query-outer-nonce",
        );
        let authenticated_query =
            authenticate_runtime_control_carrier(&legacy.provisioning, &control_query, &carrier)
                .unwrap_or_else(|_| {
                    panic!("canonical ReferenceQuery carrier failed authentication")
                });
        let inner = authenticated_query
            .reference_query_request()
            .unwrap_or_else(|| panic!("authenticated ReferenceQuery lost its strict payload"));
        let query_response = legacy
            .handle_query(inner.canonical_wire())
            .unwrap_or_else(|_| panic!("legacy PXQR owner rejected authenticated query"));
        let _ = decode_verify_query_response(
            &query_response,
            &query,
            channel,
            independent_query_serving(&before),
        );

        let bad_signature = signed_runtime_control_describe(
            carrier.clone(),
            0xc6,
            b"bad-outer-signature-nonce",
            [0xf1; 32],
        );
        assert!(matches!(
            authenticate_runtime_control_carrier(&legacy.provisioning, &bad_signature, &carrier,),
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert_eq!(legacy.apply.snapshot(), &before);
    }

    #[tokio::test]
    async fn managed_runtime_control_describes_ready_and_rejects_predecessor_query() {
        let socket_directory = TestSocketDirectory::create();
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xd1),
            digest(0xd2),
        )
        .unwrap_or_else(|error| panic!("managed Runtime-control channel rejected: {error}"));
        let (_state_directory, started) =
            managed_started_service(socket_directory.socket_path.clone());
        let mut managed = recover_managed_control_for_existing_channel(started, channel)
            .await
            .unwrap_or_else(|error| panic!("managed recovery failed: {error}"));
        let profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let carrier = restricted_carrier_for_profile(&profile, RESTRICTED_PROFILE_REF);

        let describe = signed_runtime_control_describe(
            carrier.clone(),
            0xd3,
            b"managed-describe-outer-nonce",
            CONTROLLER_SEED,
        );
        let authenticated =
            authenticate_runtime_control_carrier(&managed.provisioning, &describe, &carrier)
                .unwrap_or_else(|_| panic!("managed Describe carrier failed authentication"));
        let response_wire = managed
            .handle_authenticated_runtime_control_carrier_v1(authenticated)
            .await
            .unwrap_or_else(|_| panic!("managed Describe failed"));
        let response = RuntimeControlDescribeReadyResponseV1::decode(&response_wire)
            .unwrap_or_else(|error| panic!("managed PXDR decode failed: {error}"));
        assert_eq!(
            response.facts().phase(),
            RuntimeControlDescribeReadyPhaseV1::ManagedReady
        );

        let query = signed_query_request(QueryRequestFixture::fresh(0xd4));
        let control_query = signed_runtime_control_reference_query(
            carrier.clone(),
            query,
            0xd5,
            b"managed-reference-query-outer-nonce",
        );
        let authenticated_query =
            authenticate_runtime_control_carrier(&managed.provisioning, &control_query, &carrier)
                .unwrap_or_else(|_| panic!("managed ReferenceQuery outer auth failed"));
        assert!(matches!(
            managed
                .handle_authenticated_runtime_control_carrier_v1(authenticated_query)
                .await,
            Err(RuntimeControlRequestError::Rejected)
        ));

        shutdown_managed_successor_chain(
            &mut managed.distributed,
            &mut managed.model_stack,
            &mut managed.stack,
            &mut managed.core,
        )
        .await
        .unwrap_or_else(|error| panic!("managed cleanup failed: {error}"));
    }

    #[test]
    fn agent_port_export_failures_keep_rejection_unavailability_and_invariants_distinct() {
        assert!(matches!(
            map_runtime_agent_port_export_error(
                RuntimeAgentConversationPortExportErrorV1::ExpectedActiveReceiptMismatch,
            ),
            RuntimeControlRequestError::Rejected
        ));
        assert!(matches!(
            map_runtime_agent_port_export_error(
                RuntimeAgentConversationPortExportErrorV1::OwnerUnavailable,
            ),
            RuntimeControlRequestError::Unavailable
        ));
        assert!(matches!(
            map_runtime_agent_port_export_error(
                RuntimeAgentConversationPortExportErrorV1::InternalInvariant,
            ),
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ManagedAgentStack(
                ManagedAgentStackRuntimeError::InvalidDurableState
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pxag_apply_and_describe_use_one_authenticated_owner_chain_and_fail_closed() {
        let socket_directory = TestSocketDirectory::create();
        let (_state_directory, mut control, stack_request) =
            managed_control_with_active_stack(socket_directory.socket_path.clone()).await;
        let profile = restricted_transport_profile(
            RESTRICTED_APPLY_ROUTE,
            RESTRICTED_TLS_LISTENER,
            RESTRICTED_ENDPOINT_GENERATION,
            RESTRICTED_OPERATION_TIMEOUT_NANOS,
        );
        let carrier = restricted_carrier_for_profile(&profile, RESTRICTED_PROFILE_REF);
        let active_wire = control
            .handle_request(stack_request.canonical_wire(), control.channel)
            .await
            .unwrap_or_else(|error| panic!("active PXST replay failed: {error:?}"));
        let active = ManagedAgentStackTerminalReceiptV1::decode(&active_wire)
            .unwrap_or_else(|error| panic!("active PXST decode failed: {error}"));
        let intended_client = PrincipalRef::from_bytes([0xf8; 16]);
        let describe = signed_runtime_agent_describe(
            carrier.clone(),
            control.core.runtime_host_epoch(),
            RuntimeAgentDescribeFixtureV1 {
                request_id_byte: 0xf1,
                expected_active_pxst_digest: active.receipt_digest(),
                intended_client,
                algorithm: ED25519_ALGORITHM,
                algorithm_version: ED25519_ALGORITHM_VERSION,
                signature_length: ED25519_SIGNATURE_BYTES,
            },
        );
        let before_sequence = control
            .core
            .recovered_observation()
            .unwrap_or_else(|error| panic!("pre-Describe observation failed: {error}"))
            .successor_snapshot_sequence;
        let response_wire = control
            .handle_restricted_runtime_control_frame_v1(describe.canonical_wire(), &carrier)
            .await
            .unwrap_or_else(|error| panic!("authenticated PXAG Describe failed: {error:?}"));
        let receipt = RuntimeAgentControlReceiptV1::decode(&response_wire)
            .unwrap_or_else(|error| panic!("PXAH descriptor decode failed: {error}"));
        receipt
            .verify_runtime_descriptor_receipt(
                &describe,
                &carrier,
                verify_runtime_agent_response_signature,
            )
            .unwrap_or_else(|error| panic!("PXAH descriptor verification failed: {error}"));
        let descriptor = receipt
            .conversation_port_descriptor()
            .unwrap_or_else(|| panic!("PXAH descriptor payload disappeared"));
        assert!(descriptor.starts_with(b"PXAP\0\x01"));
        assert_eq!(
            receipt.expected_active_pxst_digest(),
            active.receipt_digest()
        );
        assert_eq!(receipt.intended_client(), intended_client);
        assert_eq!(
            receipt.fabric_generation(),
            active.facts().state().fabric_generation()
        );
        assert_eq!(
            receipt.agent_generation(),
            active.facts().state().agent_generation()
        );
        assert_eq!(
            control
                .core
                .recovered_observation()
                .unwrap_or_else(|error| panic!("post-Describe observation failed: {error}"))
                .successor_snapshot_sequence,
            before_sequence,
            "Describe must not mutate either durable owner",
        );

        let mut wrong_signature = describe.canonical_wire().to_vec();
        *wrong_signature
            .last_mut()
            .unwrap_or_else(|| panic!("PXAG signature disappeared")) ^= 1;
        assert!(matches!(
            control
                .handle_restricted_runtime_control_frame_v1(&wrong_signature, &carrier)
                .await,
            Err(RuntimeControlRequestError::Rejected)
        ));

        for (request_id_byte, algorithm, algorithm_version, signature_length) in [
            (0xf2, ED25519_ALGORITHM + 1, ED25519_ALGORITHM_VERSION, 64),
            (0xf3, ED25519_ALGORITHM, ED25519_ALGORITHM_VERSION + 1, 64),
            (0xf4, ED25519_ALGORITHM, ED25519_ALGORITHM_VERSION, 63),
        ] {
            let invalid = signed_runtime_agent_describe(
                carrier.clone(),
                control.core.runtime_host_epoch(),
                RuntimeAgentDescribeFixtureV1 {
                    request_id_byte,
                    expected_active_pxst_digest: active.receipt_digest(),
                    intended_client,
                    algorithm,
                    algorithm_version,
                    signature_length,
                },
            );
            assert!(matches!(
                control
                    .handle_restricted_runtime_control_frame_v1(invalid.canonical_wire(), &carrier)
                    .await,
                Err(RuntimeControlRequestError::Rejected)
            ));
        }

        let wrong_active = signed_runtime_agent_describe(
            carrier.clone(),
            control.core.runtime_host_epoch(),
            RuntimeAgentDescribeFixtureV1 {
                request_id_byte: 0xf5,
                expected_active_pxst_digest: digest(0xf6),
                intended_client,
                algorithm: ED25519_ALGORITHM,
                algorithm_version: ED25519_ALGORITHM_VERSION,
                signature_length: ED25519_SIGNATURE_BYTES,
            },
        );
        assert!(matches!(
            control
                .handle_restricted_runtime_control_frame_v1(
                    wrong_active.canonical_wire(),
                    &carrier,
                )
                .await,
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert_eq!(
            control
                .core
                .recovered_observation()
                .unwrap_or_else(|error| panic!("rejected-Describe observation failed: {error}"))
                .successor_snapshot_sequence,
            before_sequence,
            "outer-auth and expected-root failures must precede mutation",
        );

        control
            .handle_broker
            .revoke()
            .unwrap_or_else(|error| panic!("broker revocation fixture failed: {error}"));
        let broken_invariant = signed_runtime_agent_describe(
            carrier.clone(),
            control.core.runtime_host_epoch(),
            RuntimeAgentDescribeFixtureV1 {
                request_id_byte: 0xf7,
                expected_active_pxst_digest: active.receipt_digest(),
                intended_client,
                algorithm: ED25519_ALGORITHM,
                algorithm_version: ED25519_ALGORITHM_VERSION,
                signature_length: ED25519_SIGNATURE_BYTES,
            },
        );
        assert!(matches!(
            control
                .handle_restricted_runtime_control_frame_v1(
                    broken_invariant.canonical_wire(),
                    &carrier,
                )
                .await,
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::ManagedAgentStack(
                    ManagedAgentStackRuntimeError::InvalidDurableState
                )
            ))
        ));

        shutdown_managed_successor_chain(
            &mut control.distributed,
            &mut control.model_stack,
            &mut control.stack,
            &mut control.core,
        )
        .await
        .unwrap_or_else(|error| panic!("Agent-control cleanup failed: {error}"));
    }

    #[derive(Clone, Copy)]
    struct ApplyRequestFixture {
        mode: ReferenceAssemblyModeV1,
        operation: u8,
        request_nonce: &'static [u8],
        tenure_nonce: &'static [u8],
        writer_epoch: u64,
        supersedes_epoch: u64,
        source_revision: u64,
        temporal_constraint: u8,
        expected_active: ExpectedActive,
        expected_store: [u8; 32],
        clock_generation: u64,
        controller_seed: [u8; 32],
        tenure_seed: [u8; 32],
    }

    impl ApplyRequestFixture {
        const fn valid() -> Self {
            Self {
                mode: ReferenceAssemblyModeV1::EmptyDeactivate,
                operation: 0x91,
                request_nonce: b"endpoint-apply-nonce",
                tenure_nonce: b"endpoint-tenure-nonce",
                writer_epoch: 1,
                supersedes_epoch: 0,
                source_revision: 1,
                temporal_constraint: 0x94,
                expected_active: ExpectedActive::None,
                expected_store: STORE_INSTANCE_ID,
                clock_generation: 1,
                controller_seed: CONTROLLER_SEED,
                tenure_seed: TENURE_SEED,
            }
        }
    }

    fn signed_apply_request(
        snapshot: &RuntimeJournalSnapshot,
        fixture: ApplyRequestFixture,
    ) -> ReferenceApplyRequestV1 {
        let manifest = verify_immutable_manifest_ingress(
            &snapshot.state().host.singleton_manifest.canonical_bytes,
            snapshot.state().host.singleton_manifest.digest,
        )
        .unwrap_or_else(|error| panic!("manifest ingress failed: {error}"));
        let execution = match fixture.mode {
            ReferenceAssemblyModeV1::OneSourceLoop => {
                let budgets = ValidatedReferenceLifecycleBudgetsV1::try_new(
                    BoundedDuration::from_nanos(1_000_000_000),
                    BoundedDuration::from_nanos(1_000_000_000),
                    BoundedDuration::from_nanos(1_000_000_000),
                )
                .unwrap_or_else(|error| panic!("lifecycle budgets failed: {error}"));
                ReferenceTargetExecutionPlanV4::try_one_source_loop(
                    &manifest,
                    InstanceRef::from_bytes([0x95; 16]),
                    DomainRef::from_bytes([0x96; 16]),
                    budgets,
                )
                .unwrap_or_else(|error| panic!("one-source PXTE failed: {error}"))
            }
            ReferenceAssemblyModeV1::EmptyDeactivate => {
                ReferenceTargetExecutionPlanV4::try_empty_deactivate(&manifest)
                    .unwrap_or_else(|error| panic!("empty PXTE failed: {error}"))
            }
        };

        let tenure_authority = TenureProofAuthority::try_new(
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            TenureProofAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("tenure algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("tenure authority failed: {error}"));
        let epoch = PlanWriterEpoch::new(fixture.writer_epoch);
        let tenure_claim = WriterTenureClaim::try_new(
            SOURCE_SCOPE,
            WRITER,
            epoch,
            PlanWriterEpoch::new(fixture.supersedes_epoch),
        )
        .unwrap_or_else(|error| panic!("tenure claim failed: {error}"));
        let unsigned_tenure = WriterTenureProof::try_new(
            tenure_authority,
            tenure_claim,
            fixture.tenure_nonce,
            &[1; ED25519_SIGNATURE_BYTES],
        )
        .unwrap_or_else(|error| panic!("tenure draft failed: {error}"));
        let tenure_signature = SigningKey::from_bytes(&fixture.tenure_seed)
            .sign(
                unsigned_tenure
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("tenure transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        let tenure = WriterTenureProof::try_new(
            tenure_authority,
            tenure_claim,
            fixture.tenure_nonce,
            &tenure_signature,
        )
        .unwrap_or_else(|error| panic!("signed tenure failed: {error}"));
        let writer = PlanWriterContext::try_new(WRITER, epoch, tenure)
            .unwrap_or_else(|error| panic!("writer context failed: {error}"));
        let control = RuntimeApplyControl::new(
            writer,
            fixture.expected_active,
            ApplyOperationId::from_bytes([fixture.operation; 16]),
        );
        let provenance = PlanProvenance::new(
            SOURCE_SCOPE,
            SourcePlanRef::from_bytes([0x92; 16]),
            SourcePlanRevision::new(fixture.source_revision),
            SourcePlanDigest::new(digest(0x93)),
        );
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([fixture.temporal_constraint; 16]),
            ClockDomainRef::from_bytes(CLOCK_DOMAIN),
            ClockGeneration::try_new(fixture.clock_generation)
                .unwrap_or_else(|error| panic!("clock generation failed: {error}")),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
        )
        .unwrap_or_else(|error| panic!("temporal constraint failed: {error}"));
        let auth = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("auth algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
            fixture.request_nonce,
        )
        .unwrap_or_else(|error| panic!("apply auth claim failed: {error}"));
        let draft = ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            temporal,
            fixture.expected_store,
            auth,
        )
        .unwrap_or_else(|error| panic!("PXAR draft failed: {error}"));
        let request_signature = SigningKey::from_bytes(&fixture.controller_seed)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("PXAR transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&request_signature)
            .unwrap_or_else(|error| panic!("signed PXAR failed: {error}"))
    }

    #[test]
    fn startup_commit_is_required_before_a_service_capability_exists() {
        let socket_path = PathBuf::from("/tmp/paraegox-startup-order-test.sock");
        let provisioning = provisioning(socket_path.clone());
        let (snapshot, compiled) = installed_snapshot(&provisioning);
        let attempts = Rc::new(Cell::new(0));
        let result = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot,
                commit_attempts: Rc::clone(&attempts),
                fail_commit: true,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning,
        );
        assert!(matches!(
            result,
            Err(RuntimeBootstrapEndpointError::Runtime)
        ));
        assert_eq!(attempts.get(), 1);
        assert!(!socket_path.exists());
    }

    #[test]
    fn restart_reassembles_live_loop_before_socket_capability_exists() {
        let socket_path = PathBuf::from("/tmp/paraegox-restart-reassembly-order-test.sock");
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"restart-reassembly-active-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x74),
            digest(0x75),
        )
        .unwrap_or_else(|error| panic!("restart channel rejected: {error}"));
        let mut active = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("active service rejected: {error}"));
        active
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("active apply failed: {error:?}"))
            .unwrap_or_else(|| panic!("active apply returned no PXRT"));
        let old_epoch = active
            .apply
            .snapshot()
            .state()
            .host
            .runtime_host_epoch_high_water;
        let snapshot = active.apply.snapshot().clone();
        let compiled = active.compiled;
        drop(active);

        let attempts = Rc::new(Cell::new(0));
        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot,
                commit_attempts: Rc::clone(&attempts),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("restart reassembly failed: {error}"));
        let state = restarted.state.snapshot().state();
        assert_eq!(state.host.runtime_host_epoch_high_water, old_epoch + 1);
        match state.live_materialization {
            LiveMaterialization::LiveReady {
                runtime_host_epoch, ..
            } => assert_eq!(runtime_host_epoch, old_epoch + 1),
            other => panic!("restart did not publish current-epoch Ready: {other:?}"),
        }
        assert!(state.recovery_action.is_none());
        assert_eq!(state.recovery_terminals.len(), 1);
        assert!(state.owned_resources.iter().all(|resource| {
            resource.phase == ResourcePhase::Terminal
                || resource.runtime_host_epoch == old_epoch + 1
        }));
        assert!(attempts.get() >= 9, "all reassembly steps must be durable");
        assert!(!socket_path.exists());
    }

    #[test]
    fn restart_after_durable_recovery_intent_never_replays_start() {
        let socket_path = PathBuf::from("/tmp/paraegox-recovery-intent-crash-test.sock");
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"recovery-intent-crash-active-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x76),
            digest(0x77),
        )
        .unwrap_or_else(|error| panic!("crash channel rejected: {error}"));
        let mut active = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("crash active service rejected: {error}"));
        active
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("crash active apply failed: {error:?}"))
            .unwrap_or_else(|| panic!("crash active apply returned no PXRT"));
        let snapshot = active.apply.snapshot().clone();
        let compiled = active.compiled;
        drop(active);

        let durable_snapshot = Rc::new(RefCell::new(snapshot.clone()));
        let attempts = Rc::new(Cell::new(0));
        let first_restart = StartedRuntimeBootstrapService::try_start(
            StartupCrashStore {
                snapshot,
                durable_snapshot: Rc::clone(&durable_snapshot),
                commit_attempts: Rc::clone(&attempts),
                // startup, old cleanup begin/tombstone, recovery plan, intent
                fail_after_publish_on: 5,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        );
        assert!(matches!(
            first_restart,
            Err(RuntimeBootstrapEndpointError::RestartReassembly(
                RuntimeRestartReassemblyError::Store(_)
            ))
        ));
        let post_intent = durable_snapshot.borrow().clone();
        assert!(post_intent.state().recovery_action.is_some_and(|recovery| {
            recovery.phase == RecoveryPhase::StartCallIntent && recovery.raw_outcome.is_none()
        }));
        assert!(
            post_intent
                .state()
                .owned_resources
                .iter()
                .all(|resource| { resource.phase == ResourcePhase::Terminal })
        );

        let second_attempts = Rc::new(Cell::new(0));
        let recovered = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: post_intent,
                commit_attempts: Rc::clone(&second_attempts),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("post-intent recovery failed: {error}"));
        assert!(matches!(
            recovered.state.snapshot().state().live_materialization,
            LiveMaterialization::RecoveryFailedNotReady { .. }
        ));
        assert!(recovered.state.snapshot().state().recovery_action.is_none());
        assert_eq!(second_attempts.get(), 2);

        let terminal_count = recovered.state.snapshot().state().recovery_terminals.len();
        let final_snapshot = recovered.state.snapshot().clone();
        let third = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: final_snapshot,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("permanent failure reopen failed: {error}"));
        assert_eq!(
            third.state.snapshot().state().recovery_terminals.len(),
            terminal_count
        );
        assert!(matches!(
            third.state.snapshot().state().live_materialization,
            LiveMaterialization::StartupInvalidated { .. }
        ));
        assert!(!socket_path.exists());
    }

    #[test]
    fn production_restart_closes_every_recovery_commit_boundary_without_callback_replay() {
        let fixture_path = PathBuf::from("/tmp/paraegox-recovery-boundary-fixture.sock");
        reset_fixed_owner_callback_actions_for_test();
        let (active_snapshot, compiled) = active_loop_restart_fixture(
            fixture_path.clone(),
            b"production-recovery-boundary-active-nonce",
        );

        // Startup reassembly publishes, in order: invalidation, old cleanup
        // begin, old tombstones, recovery plan, start intent, reservations,
        // ownership, callback latch, and Ready.
        for boundary in 1..=9_u32 {
            reset_fixed_owner_callback_actions_for_test();
            // The socket path is part of the immutable channel-policy pin, so
            // every reopen of this one installed snapshot uses the exact path
            // with which the fixture was initialized.
            let socket_path = fixture_path.clone();
            let durable_snapshot = Rc::new(RefCell::new(active_snapshot.clone()));
            let attempts = Rc::new(Cell::new(0));
            let interrupted = StartedRuntimeBootstrapService::try_start(
                StartupCrashStore {
                    snapshot: active_snapshot.clone(),
                    durable_snapshot: Rc::clone(&durable_snapshot),
                    commit_attempts: Rc::clone(&attempts),
                    fail_after_publish_on: boundary,
                    socket_path: socket_path.clone(),
                },
                compiled,
                provisioning(socket_path.clone()),
            );
            let error = match interrupted {
                Err(error) => error,
                Ok(_) => panic!("boundary {boundary} did not crash"),
            };
            assert_eq!(
                attempts.get(),
                boundary,
                "boundary {boundary} failed at the wrong stage: {error}"
            );
            assert!(!socket_path.exists());

            let crashed = durable_snapshot.borrow().clone();
            let crashed_recovery = crashed.state().recovery_action.or_else(|| {
                crashed
                    .state()
                    .recovery_terminals
                    .last()
                    .map(|value| value.recovery)
            });
            let callback_actions_before_restart = fixed_owner_start_callback_actions_for_test();
            if boundary <= 7 {
                assert!(callback_actions_before_restart.is_empty());
            } else {
                let action = crashed_recovery
                    .unwrap_or_else(|| panic!("boundary {boundary} lost recovery action"))
                    .action
                    .action_id;
                assert_eq!(callback_actions_before_restart, vec![action]);
            }
            if boundary == 8 {
                assert!(crashed.state().recovery_action.is_some_and(|recovery| {
                    recovery.phase == RecoveryPhase::StartCallIntent
                        && recovery
                            .raw_outcome
                            .is_some_and(|raw| raw.callback == CallbackOutcome::KnownSuccess)
                }));
            }

            let restarted = StartedRuntimeBootstrapService::try_start(
                MockStore {
                    snapshot: crashed,
                    commit_attempts: Rc::new(Cell::new(0)),
                    fail_commit: false,
                    socket_path: socket_path.clone(),
                },
                compiled,
                provisioning(socket_path.clone()),
            )
            .unwrap_or_else(|error| {
                panic!("boundary {boundary} production restart failed: {error}")
            });
            assert!(!socket_path.exists());
            let recovered = restarted.state.snapshot();
            let callback_actions_after_restart = fixed_owner_start_callback_actions_for_test();

            match boundary {
                1..=3 => {
                    assert!(matches!(
                        recovered.state().live_materialization,
                        LiveMaterialization::LiveReady { .. }
                    ));
                    assert_eq!(callback_actions_after_restart.len(), 1);
                }
                4 => {
                    let crashed_recovery =
                        crashed_recovery.unwrap_or_else(|| panic!("plan action missing"));
                    assert!(matches!(
                        recovered.state().live_materialization,
                        LiveMaterialization::LiveReady { .. }
                    ));
                    assert_eq!(callback_actions_after_restart.len(), 1);
                    assert_ne!(
                        callback_actions_after_restart[0], crashed_recovery.action.action_id,
                        "invalidated pre-intent action was replayed"
                    );
                    assert!(recovered.state().recovery_terminals.iter().any(|terminal| {
                        terminal.recovery.action.action_id == crashed_recovery.action.action_id
                            && terminal.selection.primary
                                == TerminalOutcome::AbortedBeforeIntentNoEffects
                    }));
                }
                5..=8 => {
                    let crashed_recovery = crashed_recovery
                        .unwrap_or_else(|| panic!("post-intent action missing at {boundary}"));
                    assert!(matches!(
                        recovered.state().live_materialization,
                        LiveMaterialization::RecoveryFailedNotReady { .. }
                    ));
                    assert_eq!(
                        callback_actions_after_restart, callback_actions_before_restart,
                        "post-intent callback was replayed at boundary {boundary}"
                    );
                    let terminal = recovered
                        .state()
                        .recovery_terminals
                        .iter()
                        .find(|terminal| {
                            terminal.recovery.action.action_id == crashed_recovery.action.action_id
                        })
                        .unwrap_or_else(|| panic!("post-intent terminal missing at {boundary}"));
                    assert_eq!(
                        terminal.selection.primary,
                        TerminalOutcome::AbortedBeforeHeadCommitExactZero
                    );
                    if boundary == 8 {
                        assert_eq!(
                            terminal.selection.raw.callback,
                            CallbackOutcome::KnownSuccess
                        );
                    }
                    if boundary == 6 {
                        assert_reserved_crash_generation_is_exact_zero(
                            recovered,
                            crashed_recovery.action.resource_generation,
                        );
                    }
                    if boundary >= 7 {
                        assert_owned_crash_generation_is_tombstoned(
                            recovered,
                            crashed_recovery.action.resource_generation,
                        );
                    }
                }
                9 => {
                    let completed = crashed_recovery
                        .unwrap_or_else(|| panic!("published recovery action missing"));
                    assert!(matches!(
                        recovered.state().live_materialization,
                        LiveMaterialization::LiveReady { .. }
                    ));
                    assert_eq!(callback_actions_after_restart.len(), 2);
                    assert_eq!(
                        callback_actions_after_restart[0],
                        completed.action.action_id
                    );
                    assert_ne!(
                        callback_actions_after_restart[1],
                        completed.action.action_id
                    );
                    assert_owned_crash_generation_is_tombstoned(
                        recovered,
                        completed.action.resource_generation,
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn restart_terminalizes_normal_start_intent_without_replaying_callback() {
        let socket_path = PathBuf::from("/tmp/paraegox-normal-start-intent-crash-test.sock");
        let initial_provisioning = provisioning(socket_path.clone());
        let (snapshot, compiled) = installed_snapshot(&initial_provisioning);
        let durable_snapshot = Rc::new(RefCell::new(snapshot.clone()));
        let started = StartedRuntimeBootstrapService::try_start(
            StartupCrashStore {
                snapshot,
                durable_snapshot: Rc::clone(&durable_snapshot),
                commit_attempts: Rc::new(Cell::new(0)),
                // startup, tenure, full admission, normal FirstActionIntent
                fail_after_publish_on: 4,
                socket_path: socket_path.clone(),
            },
            compiled,
            initial_provisioning,
        )
        .unwrap_or_else(|error| panic!("normal crash startup failed: {error}"));
        let initial = started.state.snapshot().clone();
        let request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"normal-start-intent-crash-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x78),
            digest(0x79),
        )
        .unwrap_or_else(|error| panic!("normal crash channel rejected: {error}"));
        let mut service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("normal crash service failed: {error}"));
        assert!(matches!(
            service.handle_request(request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Store(_))
            ))
        ));
        drop(service);
        let post_intent = durable_snapshot.borrow().clone();
        assert!(
            post_intent
                .state()
                .prepared
                .as_ref()
                .is_some_and(|prepared| { prepared.phase == PreparedPhase::FirstActionIntent })
        );
        assert!(post_intent.state().owned_resources.is_empty());

        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: post_intent,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("normal post-intent restart failed: {error}"));
        let state = restarted.state.snapshot().state();
        assert!(state.prepared.is_none());
        assert!(state.owned_resources.is_empty());
        assert_eq!(
            state
                .terminal_operations
                .last()
                .unwrap_or_else(|| panic!("normal crash terminal missing"))
                .selection
                .primary,
            crate::runtime_journal::TerminalOutcome::AbortedBeforeHeadCommitExactZero
        );
        assert!(matches!(
            state.live_materialization,
            LiveMaterialization::None
        ));
        assert!(!socket_path.exists());
    }

    #[test]
    fn production_restart_closes_normal_intent_reserved_and_owned_boundaries() {
        // A fresh process start is commit one; normal start then publishes
        // tenure, admission, intent, reservations, ownership, and terminal.
        for boundary in [4_u32, 5, 6] {
            reset_fixed_owner_callback_actions_for_test();
            let socket_path =
                PathBuf::from(format!("/tmp/paraegox-normal-boundary-{boundary}.sock"));
            let initial_provisioning = provisioning(socket_path.clone());
            let (snapshot, compiled) = installed_snapshot(&initial_provisioning);
            let durable_snapshot = Rc::new(RefCell::new(snapshot.clone()));
            let attempts = Rc::new(Cell::new(0));
            let started = StartedRuntimeBootstrapService::try_start(
                StartupCrashStore {
                    snapshot,
                    durable_snapshot: Rc::clone(&durable_snapshot),
                    commit_attempts: Rc::clone(&attempts),
                    fail_after_publish_on: boundary,
                    socket_path: socket_path.clone(),
                },
                compiled,
                initial_provisioning,
            )
            .unwrap_or_else(|error| panic!("boundary {boundary} startup failed: {error}"));
            let initial = started.state.snapshot().clone();
            let request = signed_apply_request(
                &initial,
                ApplyRequestFixture {
                    mode: ReferenceAssemblyModeV1::OneSourceLoop,
                    request_nonce: match boundary {
                        4 => b"normal-boundary-intent-nonce",
                        5 => b"normal-boundary-reserved-nonce",
                        6 => b"normal-boundary-owned-nonce",
                        _ => unreachable!(),
                    },
                    ..ApplyRequestFixture::valid()
                },
            );
            let channel = ReferenceChannelBindingV1::try_new(
                TARGET,
                RUNTIME_PRINCIPAL,
                digest(0xc4),
                digest(boundary as u8),
            )
            .unwrap_or_else(|error| panic!("normal boundary channel rejected: {error}"));
            let mut service = started
                .into_control_service(channel)
                .unwrap_or_else(|error| panic!("normal boundary service failed: {error}"));
            assert!(matches!(
                service.handle_request(request.canonical_wire(), channel),
                Err(RuntimeControlRequestError::Internal(
                    RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Store(_))
                ))
            ));
            drop(service);
            assert_eq!(attempts.get(), boundary);
            assert!(fixed_owner_start_callback_actions_for_test().is_empty());
            assert!(!socket_path.exists());

            let crashed = durable_snapshot.borrow().clone();
            let prepared = crashed
                .state()
                .prepared
                .as_ref()
                .unwrap_or_else(|| panic!("boundary {boundary} lost prepared action"));
            let action = prepared
                .action
                .unwrap_or_else(|| panic!("boundary {boundary} lost action identity"));
            assert_eq!(prepared.phase, PreparedPhase::FirstActionIntent);
            match boundary {
                4 => assert!(crashed.state().owned_resources.is_empty()),
                5 => assert!(crashed.state().owned_resources.iter().all(|resource| {
                    resource.generation == action.resource_generation
                        && resource.phase == ResourcePhase::Reserved
                        && resource.os_identity.is_none()
                        && resource.workspace_identity.is_none()
                        && resource.containment_identity.is_none()
                })),
                6 => assert!(crashed.state().owned_resources.iter().all(|resource| {
                    resource.generation == action.resource_generation
                        && resource.phase == ResourcePhase::Owned
                        && resource.os_identity.is_some()
                        && resource.workspace_identity.is_some()
                        && resource.containment_identity.is_some()
                })),
                _ => unreachable!(),
            }

            let restarted = StartedRuntimeBootstrapService::try_start(
                MockStore {
                    snapshot: crashed,
                    commit_attempts: Rc::new(Cell::new(0)),
                    fail_commit: false,
                    socket_path: socket_path.clone(),
                },
                compiled,
                provisioning(socket_path.clone()),
            )
            .unwrap_or_else(|error| panic!("normal boundary {boundary} restart failed: {error}"));
            let recovered = restarted.state.snapshot();
            assert!(!socket_path.exists());
            assert!(recovered.state().prepared.is_none());
            assert!(matches!(
                recovered.state().live_materialization,
                LiveMaterialization::None
            ));
            let terminal = terminal_for_request(recovered, &request);
            assert_eq!(
                terminal.selection.primary,
                TerminalOutcome::AbortedBeforeHeadCommitExactZero
            );
            let receipt = ReferenceApplyTerminalReceiptV1::decode(
                &terminal.canonical_response.canonical_bytes,
            )
            .unwrap_or_else(|error| panic!("restart PXRT decode failed: {error}"));
            assert_eq!(
                receipt.authentication_channel_binding_digest(),
                channel.binding_digest(),
                "restart PXRT did not retain the admitted historical channel"
            );
            // The durable intent makes callback truth conservative after a
            // real process loss; the test-only owner trace proves this
            // particular restart did not invoke the old action again.
            assert_eq!(
                terminal.selection.raw.callback,
                CallbackOutcome::UnknownAfterIntent
            );
            assert!(fixed_owner_start_callback_actions_for_test().is_empty());
            if boundary == 5 {
                assert_reserved_crash_generation_is_exact_zero(
                    recovered,
                    action.resource_generation,
                );
            }
            if boundary == 6 {
                assert_owned_crash_generation_is_tombstoned(recovered, action.resource_generation);
            }
        }
    }

    #[test]
    fn higher_tenure_normal_start_restart_terminalizes_superseded_exact_zero() {
        reset_fixed_owner_callback_actions_for_test();
        let socket_path = PathBuf::from("/tmp/paraegox-normal-takeover-restart.sock");
        let initial_provisioning = provisioning(socket_path.clone());
        let (snapshot, compiled) = installed_snapshot(&initial_provisioning);
        let durable_snapshot = Rc::new(RefCell::new(snapshot.clone()));
        let started = StartedRuntimeBootstrapService::try_start(
            StartupCrashStore {
                snapshot,
                durable_snapshot: Rc::clone(&durable_snapshot),
                commit_attempts: Rc::new(Cell::new(0)),
                // startup, tenure, admission, intent, reserve, ownership
                fail_after_publish_on: 6,
                socket_path: socket_path.clone(),
            },
            compiled,
            initial_provisioning,
        )
        .unwrap_or_else(|error| panic!("normal takeover startup failed: {error}"));
        let request = signed_apply_request(
            started.state.snapshot(),
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"normal-takeover-restart-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xd4),
            digest(0xd5),
        )
        .unwrap_or_else(|error| panic!("normal takeover channel rejected: {error}"));
        let mut service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("normal takeover service failed: {error}"));
        assert!(matches!(
            service.handle_request(request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Store(_))
            ))
        ));
        drop(service);
        assert!(fixed_owner_start_callback_actions_for_test().is_empty());

        let owned = durable_snapshot.borrow().clone();
        let action = owned
            .state()
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.action)
            .unwrap_or_else(|| panic!("normal takeover action missing"));
        let takeover = higher_tenure_successor(&owned, 0xd6);
        assert!(takeover.state().prepared.as_ref().is_some_and(|prepared| {
            prepared.phase == PreparedPhase::SupersededReconcileRequired
                && prepared
                    .raw_outcome
                    .is_some_and(|raw| raw.higher_tenure_takeover)
        }));

        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: takeover,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("normal takeover restart failed: {error}"));
        let recovered = restarted.state.snapshot();
        assert!(!socket_path.exists());
        assert!(recovered.state().prepared.is_none());
        assert!(matches!(
            recovered.state().live_materialization,
            LiveMaterialization::None
        ));
        let terminal = terminal_for_request(recovered, &request);
        assert_eq!(
            terminal.selection.primary,
            TerminalOutcome::SupersededAfterIntentExactZero
        );
        assert!(terminal.selection.raw.higher_tenure_takeover);
        let receipt =
            ReferenceApplyTerminalReceiptV1::decode(&terminal.canonical_response.canonical_bytes)
                .unwrap_or_else(|error| panic!("takeover PXRT decode failed: {error}"));
        assert_eq!(
            receipt.authentication_channel_binding_digest(),
            channel.binding_digest()
        );
        assert_eq!(
            terminal.selection.raw.callback,
            CallbackOutcome::UnknownAfterIntent
        );
        assert_owned_crash_generation_is_tombstoned(recovered, action.resource_generation);
        assert!(fixed_owner_start_callback_actions_for_test().is_empty());
    }

    #[test]
    fn production_restart_preserves_validated_quarantine_without_listener_or_callback() {
        let socket_path = PathBuf::from("/tmp/paraegox-quarantine-restart.sock");
        reset_fixed_owner_callback_actions_for_test();
        let (active, compiled) =
            active_loop_restart_fixture(socket_path.clone(), b"quarantine-restart-active-nonce");
        reset_fixed_owner_callback_actions_for_test();
        let old_generation = match active.state().live_materialization {
            LiveMaterialization::LiveReady {
                resource_generation,
                ..
            } => resource_generation,
            other => panic!("quarantine fixture not live: {other:?}"),
        };
        let invalidated = active
            .try_startup_invalidation_successor()
            .unwrap_or_else(|error| panic!("quarantine invalidation failed: {error:?}"));
        let quarantined = invalidated
            .try_operational_quarantine_successor(digest(0xda))
            .unwrap_or_else(|error| panic!("quarantine fixture failed: {error:?}"));
        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: quarantined,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("quarantine restart failed: {error}"));
        let recovered = restarted.state.snapshot();
        assert!(!socket_path.exists());
        assert!(matches!(
            recovered.state().live_materialization,
            LiveMaterialization::Quarantined { .. }
        ));
        assert_owned_crash_generation_is_tombstoned(recovered, old_generation);
        let live = query_live_projection(recovered, 1)
            .unwrap_or_else(|error| panic!("quarantine projection failed: {error}"));
        assert_eq!(
            live.state(),
            ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
        );
        assert_eq!(live.resource_generation(), 0);
        assert!(fixed_owner_start_callback_actions_for_test().is_empty());
        assert!(fixed_owner_stop_callback_actions_for_test().is_empty());
    }

    #[test]
    fn pre_intent_empty_crash_aborts_incoming_then_reassembles_old_loop() {
        let socket_path = PathBuf::from("/tmp/paraegox-empty-pre-intent-crash-test.sock");
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let active_request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"empty-pre-intent-old-loop-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x7a),
            digest(0x7b),
        )
        .unwrap_or_else(|error| panic!("empty pre-intent channel rejected: {error}"));
        let mut active_service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("empty pre-intent active service failed: {error}"));
        active_service
            .handle_request(active_request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("old loop apply failed: {error:?}"))
            .unwrap_or_else(|| panic!("old loop apply returned no PXRT"));
        let active_snapshot = active_service.apply.snapshot().clone();
        let active_slice_digest = match active_snapshot.state().live_materialization {
            LiveMaterialization::LiveReady {
                active_slice_digest,
                ..
            } => active_slice_digest,
            other => panic!("old loop not live before crash: {other:?}"),
        };
        let compiled = active_service.compiled;
        let compatibility = active_service.compatibility.clone();
        let clock = active_service.clock;
        drop(active_service);

        let durable_snapshot = Rc::new(RefCell::new(active_snapshot.clone()));
        let owner =
            RuntimeFixedReferenceMaterializationOwner::try_new(compiled, clock, &active_snapshot)
                .unwrap_or_else(|error| panic!("empty pre-intent owner failed: {error:?}"));
        let crash_provisioning = provisioning(socket_path.clone());
        let signer = RuntimeReferenceApplySigner::try_new(
            crash_provisioning.response_signer().clone(),
            crash_provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("empty signer algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("empty pre-intent signer failed: {error:?}"));
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            StartupCrashStore {
                snapshot: active_snapshot.clone(),
                durable_snapshot: Rc::clone(&durable_snapshot),
                commit_attempts: Rc::new(Cell::new(0)),
                // tenure then full admission; fail after PreparedNoEffects.
                fail_after_publish_on: 2,
                socket_path: socket_path.clone(),
            },
            RuntimeEndpointApplyClock { clock },
            owner,
            signer,
            channel,
        )
        .unwrap_or_else(|error| panic!("empty crash apply core failed: {error:?}"));
        let mut crash_service = RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning: crash_provisioning,
            channel,
        };
        let empty_request = signed_apply_request(
            &active_snapshot,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::EmptyDeactivate,
                operation: 0x7c,
                request_nonce: b"empty-pre-intent-incoming-nonce",
                tenure_nonce: b"empty-pre-intent-incoming-tenure",
                writer_epoch: 2,
                supersedes_epoch: 1,
                source_revision: 2,
                temporal_constraint: 0x7d,
                expected_active: ExpectedActive::Exact(active_slice_digest),
                ..ApplyRequestFixture::valid()
            },
        );
        assert!(matches!(
            crash_service.handle_request(empty_request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Store(_))
            ))
        ));
        drop(crash_service);
        let admitted = durable_snapshot.borrow().clone();
        assert!(
            admitted
                .state()
                .prepared
                .as_ref()
                .is_some_and(|prepared| { prepared.phase == PreparedPhase::PreparedNoEffects })
        );
        assert!(matches!(
            admitted.state().live_materialization,
            LiveMaterialization::LiveReady { .. }
        ));

        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: admitted,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("empty pre-intent restart failed: {error}"));
        let state = restarted.state.snapshot().state();
        assert!(state.prepared.is_none());
        assert_eq!(
            state
                .terminal_operations
                .iter()
                .find(|terminal| {
                    terminal.operation_id
                        == *empty_request
                            .control_commitment()
                            .control()
                            .operation_id()
                            .as_bytes()
                })
                .unwrap_or_else(|| panic!("empty abort terminal missing"))
                .selection
                .primary,
            crate::runtime_journal::TerminalOutcome::AbortedBeforeIntentNoEffects
        );
        assert_eq!(state.recovery_terminals.len(), 1);
        assert!(matches!(
            state.live_materialization,
            LiveMaterialization::LiveReady { .. }
        ));
        assert!(!socket_path.exists());
    }

    #[test]
    fn authenticated_bootstrap_response_is_correlated_and_runtime_signed() {
        let started = started_service(PathBuf::from("/tmp/paraegox-bootstrap-core-test.sock"));
        assert_eq!(started.state.snapshot().sequence(), 2);
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x72),
            digest(0x73),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let request = signed_bootstrap_request(TARGET, SOURCE_SCOPE, CONTROLLER_SEED);
        let response_wire = started
            .bootstrap_core(channel)
            .unwrap_or_else(|error| panic!("bootstrap core rejected: {error}"))
            .handle_request(request.canonical_wire())
            .unwrap_or_else(|error| panic!("request rejected: {error:?}"));
        let response = ReferenceBootstrapResponseV1::decode(&response_wire)
            .unwrap_or_else(|error| panic!("response decode failed: {error}"));
        let signature: [u8; ED25519_SIGNATURE_BYTES] = response
            .authentication_signature()
            .try_into()
            .unwrap_or_else(|_| panic!("response signature width changed"));
        SigningKey::from_bytes(&RESPONSE_SEED)
            .verifying_key()
            .verify_strict(
                response
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("response transcript failed: {error}"))
                    .as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .unwrap_or_else(|error| panic!("Runtime response signature failed: {error}"));
        let facts = response
            .validate_against_request(&request, channel, &started.compatibility)
            .unwrap_or_else(|error| panic!("response correlation failed: {error}"));
        assert_eq!(facts.target(), TARGET);
        assert_eq!(facts.runtime_store_instance_id(), STORE_INSTANCE_ID);
        assert_eq!(facts.snapshot_sequence(), 2);
        assert_eq!(facts.runtime_host_epoch(), 1);
        assert_eq!(
            facts.clock_domain(),
            ClockDomainRef::from_bytes(CLOCK_DOMAIN)
        );
        assert_eq!(facts.clock_generation().value(), 1);
        assert_eq!(facts.state(), ReferenceBootstrapStateV1::ReadyForApply);
    }

    #[test]
    fn bootstrap_decoder_and_authentication_fail_before_any_mutation() {
        let started = started_service(PathBuf::from("/tmp/paraegox-bootstrap-reject-test.sock"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x74),
            digest(0x75),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let core = started
            .bootstrap_core(channel)
            .unwrap_or_else(|error| panic!("bootstrap core rejected: {error}"));
        let wrong_scope = signed_bootstrap_request(
            TARGET,
            SourceScopeRef::from_bytes([0x7a; 16]),
            CONTROLLER_SEED,
        );
        assert_eq!(
            core.handle_request(wrong_scope.canonical_wire()),
            Err(RuntimeBootstrapRequestError::Unauthorized)
        );
        let wrong_signature = signed_bootstrap_request(TARGET, SOURCE_SCOPE, [0x7b; 32]);
        assert_eq!(
            core.handle_request(wrong_signature.canonical_wire()),
            Err(RuntimeBootstrapRequestError::InvalidSignature)
        );
        assert_eq!(
            core.handle_request(b"PXAR-is-not-a-bootstrap-request"),
            Err(RuntimeBootstrapRequestError::InvalidCanonicalRequest)
        );
        assert_eq!(started.state.snapshot().sequence(), 2);
    }

    #[test]
    fn authenticated_query_returns_fresh_unknown_exact_zero_without_snapshot_mutation() {
        let started = started_service(PathBuf::from("/tmp/paraegox-query-core-test.sock"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x76),
            digest(0x77),
        )
        .unwrap_or_else(|error| panic!("query channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("query control service rejected: {error}"));
        let request = signed_query_request(QueryRequestFixture::fresh(0x82));
        let before = control.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(control.apply.snapshot());
        let response_wire = control
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("fresh query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("fresh query returned no PXQS"));
        assert_eq!(&response_wire[..4], b"PXQS");
        let (response, facts) =
            decode_verify_query_response(&response_wire, &request, channel, expected_serving);
        assert_eq!(facts.serving().target(), TARGET);
        assert_eq!(
            facts.serving().runtime_store_instance_id(),
            STORE_INSTANCE_ID
        );
        assert_eq!(
            facts.operation().owner_state(),
            ReferenceQueryOwnerStateV1::Operational
        );
        assert_eq!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Unknown
        );
        assert_eq!(facts.desired().head(), ReferenceQueryDesiredHeadV1::None);
        assert_eq!(facts.desired().source_revision_high_water().value(), 0);
        assert_eq!(facts.live().state(), ReferenceQueryLiveStateV1::ExactZero);
        assert_eq!(facts.live().resource_generation(), 0);
        assert_eq!(control.apply.snapshot().canonical_wire(), before);
        let wrong_epoch_serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            STORE_INSTANCE_ID,
            control.apply.snapshot().sequence(),
            control
                .apply
                .snapshot()
                .state()
                .host
                .runtime_host_epoch_high_water
                + 1,
            ClockDomainRef::from_bytes(CLOCK_DOMAIN),
            ClockGeneration::try_new(
                control
                    .apply
                    .snapshot()
                    .state()
                    .host
                    .clock_generation_high_water,
            )
            .unwrap_or_else(|error| panic!("wrong-epoch query clock rejected: {error}")),
        )
        .unwrap_or_else(|error| panic!("wrong-epoch query baseline rejected: {error}"));
        assert!(
            response
                .validate_against_request(&request, channel, wrong_epoch_serving)
                .is_err()
        );

        let invalid = [
            QueryRequestFixture {
                scope: SourceScopeRef::from_bytes([0x83; 16]),
                ..QueryRequestFixture::fresh(0x82)
            },
            QueryRequestFixture {
                target: RuntimeHostId::from_bytes([0x84; 16]),
                ..QueryRequestFixture::fresh(0x82)
            },
            QueryRequestFixture {
                store: [0x85; 32],
                ..QueryRequestFixture::fresh(0x82)
            },
            QueryRequestFixture {
                controller_seed: [0x86; 32],
                ..QueryRequestFixture::fresh(0x82)
            },
            QueryRequestFixture {
                max_response_bytes: 1,
                ..QueryRequestFixture::fresh(0x82)
            },
        ];
        for fixture in invalid {
            let invalid = signed_query_request(fixture);
            assert!(matches!(
                control.handle_request(invalid.canonical_wire(), channel),
                Err(RuntimeControlRequestError::Rejected)
            ));
            assert_eq!(control.apply.snapshot().canonical_wire(), before);
        }
        let wrong_channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x87),
            digest(0x88),
        )
        .unwrap_or_else(|error| panic!("wrong query channel rejected: {error}"));
        assert!(matches!(
            control.handle_request(request.canonical_wire(), wrong_channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        let mut trailing = request.canonical_wire().to_vec();
        trailing.push(0);
        assert!(matches!(
            control.handle_request(&trailing, channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        let mut oversized = vec![0_u8; MAX_REFERENCE_QUERY_REQUEST_BYTES + 1];
        oversized[..4].copy_from_slice(QUERY_REQUEST_MAGIC);
        assert!(matches!(
            control.handle_request(&oversized, channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert_eq!(control.apply.snapshot().canonical_wire(), before);
    }

    #[test]
    fn validated_operational_quarantine_returns_only_typed_indeterminate() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-quarantine-test.sock");
        let provisioning = provisioning(socket_path.clone());
        let (sequence_one, compiled) = installed_snapshot(&provisioning);
        let started_once = sequence_one
            .try_startup_invalidation_successor()
            .unwrap_or_else(|error| panic!("first startup invalidation failed: {error:?}"));
        let census = started_once
            .resource_census_digest()
            .unwrap_or_else(|error| panic!("quarantine census failed: {error:?}"));
        let mut quarantined_state = started_once.state().clone();
        quarantined_state.last_transaction =
            crate::runtime_journal::RuntimeJournalTransaction::Quarantine;
        quarantined_state.live_materialization = LiveMaterialization::Quarantined {
            active_slice_digest: None,
            reason_digest: digest(0x78),
            resource_census_digest: census,
        };
        let quarantined = RuntimeJournalSnapshot::try_new(
            *started_once.store_instance_id(),
            *started_once.owner_target_fingerprint(),
            started_once.sequence() + 1,
            quarantined_state,
        )
        .unwrap_or_else(|error| panic!("validated quarantine snapshot failed: {error:?}"));
        let started = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: quarantined,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            compiled,
            provisioning,
        )
        .unwrap_or_else(|error| panic!("validated quarantine startup failed: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x79),
            digest(0x7a),
        )
        .unwrap_or_else(|error| panic!("quarantine query channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("quarantine control service rejected: {error}"));
        let query = signed_query_request(QueryRequestFixture::fresh(0x7b));
        let before = control.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(control.apply.snapshot());
        let response = control
            .handle_request(query.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("quarantine query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("quarantine query returned no PXQS"));
        let (_, facts) = decode_verify_query_response(&response, &query, channel, expected_serving);
        assert_eq!(
            facts.operation().owner_state(),
            ReferenceQueryOwnerStateV1::OwnershipUncertain
        );
        assert_eq!(
            facts.operation().reason(),
            Some(ReferenceOperationalReasonV1::OwnershipUncertain)
        );
        assert_eq!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Indeterminate {
                reason: ReferenceOperationalReasonV1::OwnershipUncertain,
            }
        );
        assert_eq!(
            facts.live().state(),
            ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
        );
        assert_eq!(control.apply.snapshot().canonical_wire(), before);
    }

    #[test]
    fn signed_empty_pxar_returns_only_correlated_runtime_signed_pxrt_and_exact_replay() {
        let socket_path = PathBuf::from("/tmp/paraegox-apply-core-test.sock");
        let started = started_service(socket_path.clone());
        let request = signed_apply_request(started.state.snapshot(), ApplyRequestFixture::valid());
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xa1),
            digest(0xa2),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("control service rejected: {error}"));

        let response = control
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("valid PXAR rejected: {error:?}"))
            .unwrap_or_else(|| panic!("terminal apply returned no PXRT"));
        assert_eq!(&response[..4], b"PXRT");
        let receipt = ReferenceApplyTerminalReceiptV1::decode(&response)
            .unwrap_or_else(|error| panic!("PXRT decode failed: {error}"));
        let facts = receipt
            .validate_against_request(&request, channel)
            .unwrap_or_else(|error| panic!("PXRT correlation failed: {error}"));
        assert_eq!(
            facts.outcome(),
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        );
        let signature: [u8; ED25519_SIGNATURE_BYTES] = receipt
            .authentication_signature()
            .try_into()
            .unwrap_or_else(|_| panic!("PXRT signature width changed"));
        SigningKey::from_bytes(&RESPONSE_SEED)
            .verifying_key()
            .verify_strict(
                receipt
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("PXRT transcript failed: {error}"))
                    .as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .unwrap_or_else(|error| panic!("PXRT signature failed: {error}"));
        let terminal_sequence = control.apply.snapshot().sequence();

        let replay = control
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("exact replay rejected: {error:?}"))
            .unwrap_or_else(|| panic!("exact replay returned no PXRT"));
        assert_eq!(replay, response);
        assert_eq!(control.apply.snapshot().sequence(), terminal_sequence);

        // A restart advances the owner clock generation and changes the live
        // channel. Historical terminal replay still returns the original exact
        // PXRT bytes without installing a new deadline or requiring Ready.
        let terminal_snapshot = control.apply.snapshot().clone();
        drop(control);
        let compiled = compiled_facts();
        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: terminal_snapshot,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path),
        )
        .unwrap_or_else(|error| panic!("restart rejected: {error}"));
        assert_eq!(
            restarted
                .state
                .bootstrap_facts()
                .map(|facts| facts.clock_generation()),
            Ok(2)
        );
        let restarted_channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xa3),
            digest(0xa4),
        )
        .unwrap_or_else(|error| panic!("restart channel rejected: {error}"));
        let mut restarted = restarted
            .into_control_service(restarted_channel)
            .unwrap_or_else(|error| panic!("restart control rejected: {error}"));
        let restarted_sequence = restarted.apply.snapshot().sequence();
        let historical = restarted
            .handle_request(request.canonical_wire(), restarted_channel)
            .unwrap_or_else(|error| panic!("historical replay rejected: {error:?}"))
            .unwrap_or_else(|| panic!("historical replay returned no PXRT"));
        assert_eq!(historical, response);
        assert_eq!(restarted.apply.snapshot().sequence(), restarted_sequence);
    }

    #[test]
    fn query_reports_terminal_known_conflict_unknown_and_current_live_ready() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-terminal-test.sock");
        let started = started_service(socket_path);
        let initial = started.state.snapshot().clone();
        let apply = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                operation: 0x88,
                request_nonce: b"queried-active-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x89),
            digest(0x8a),
        )
        .unwrap_or_else(|error| panic!("query terminal channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("query terminal control rejected: {error}"));
        control
            .handle_request(apply.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("queried apply rejected: {error:?}"))
            .unwrap_or_else(|| panic!("queried apply returned no PXRT"));
        let terminal_wire = control.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(control.apply.snapshot());

        let exact = signed_query_request(QueryRequestFixture {
            expected_request_digest: Some(apply.envelope_request_digest()),
            ..QueryRequestFixture::fresh(0x88)
        });
        let exact_response = control
            .handle_request(exact.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("exact terminal query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("exact terminal query returned no PXQS"));
        let (_, exact_facts) =
            decode_verify_query_response(&exact_response, &exact, channel, expected_serving);
        assert!(matches!(
            exact_facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Known {
                request_digest,
                durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                terminal_result: Some(_),
            } if request_digest == apply.envelope_request_digest()
        ));
        assert!(matches!(
            exact_facts.desired().head(),
            ReferenceQueryDesiredHeadV1::OneSourceLoop {
                source_revision,
                target_slice_digest,
                ..
            } if source_revision.value() == 1 && target_slice_digest == apply.target_slice_digest()
        ));
        assert_eq!(
            exact_facts.live().state(),
            ReferenceQueryLiveStateV1::LiveReady
        );
        assert!(exact_facts.live().resource_generation() > 0);

        let conflict = signed_query_request(QueryRequestFixture {
            query: 0x8b,
            expected_request_digest: Some(digest(0x8c)),
            ..QueryRequestFixture::fresh(0x88)
        });
        let conflict_response = control
            .handle_request(conflict.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("conflict query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("conflict query returned no PXQS"));
        let (_, conflict_facts) =
            decode_verify_query_response(&conflict_response, &conflict, channel, expected_serving);
        assert_eq!(
            conflict_facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Conflict {
                existing_request_digest: apply.envelope_request_digest(),
            }
        );

        let unknown = signed_query_request(QueryRequestFixture {
            query: 0x8d,
            ..QueryRequestFixture::fresh(0x8e)
        });
        let unknown_response = control
            .handle_request(unknown.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("unknown query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("unknown query returned no PXQS"));
        let (_, unknown_facts) =
            decode_verify_query_response(&unknown_response, &unknown, channel, expected_serving);
        assert_eq!(
            unknown_facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Unknown
        );
        assert_eq!(control.apply.snapshot().canonical_wire(), terminal_wire);
    }

    #[test]
    fn query_reports_durable_prepared_without_advancing_the_operation() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-prepared-test.sock");
        let started = started_service(socket_path.clone());
        let request = signed_apply_request(
            started.state.snapshot(),
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                operation: 0x8f,
                request_nonce: b"queried-prepared-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x90),
            digest(0x91),
        )
        .unwrap_or_else(|error| panic!("prepared query channel rejected: {error}"));
        let journal = started
            .state
            .bootstrap_facts()
            .unwrap_or_else(|error| panic!("started facts rejected: {error:?}"));
        let generation = ClockGeneration::try_new(journal.clock_generation())
            .unwrap_or_else(|error| panic!("prepared clock rejected: {error}"));
        let clock = RuntimeClock::new(
            ClockDomainRef::from_bytes(journal.clock_domain()),
            generation,
            1,
        );
        let signer = RuntimeReferenceApplySigner::try_new(
            started.provisioning.response_signer().clone(),
            started.provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("prepared signer algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("prepared signer rejected: {error:?}"));
        let budgets = request
            .target_execution()
            .loop_facts()
            .unwrap_or_else(|| panic!("prepared request lost loop facts"))
            .budgets();
        let owner = FailingRetireOwner {
            active_slice_digest: TargetSliceDigest::new(digest(0x92)),
            resource_generation: 1,
            plan: RuntimeEmptyRetireOwnerPlan {
                action_id: [0x93; 16],
                signed_budgets: budgets,
            },
        };
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            started.store,
            RuntimeEndpointApplyClock { clock },
            owner,
            signer,
            channel,
        )
        .unwrap_or_else(|error| panic!("prepared apply core rejected: {error:?}"));
        let mut control = RuntimeControlService {
            apply,
            clock,
            compiled: started.compiled,
            compatibility: started.compatibility,
            provisioning: started.provisioning,
            channel,
        };
        assert!(matches!(
            control.handle_request(request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Owner(
                    RuntimeReferenceMaterializationOwnerError::Unavailable
                ))
            ))
        ));
        let prepared_wire = control.apply.snapshot().canonical_wire().to_vec();
        let query = signed_query_request(QueryRequestFixture {
            expected_request_digest: Some(request.envelope_request_digest()),
            ..QueryRequestFixture::fresh(0x8f)
        });
        let expected_serving = independent_query_serving(control.apply.snapshot());
        let response = control
            .handle_request(query.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("prepared query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("prepared query returned no PXQS"));
        let (_, facts) = decode_verify_query_response(&response, &query, channel, expected_serving);
        assert_eq!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Known {
                request_digest: request.envelope_request_digest(),
                durable_phase: ReferenceQueryDurablePhaseV1::PreparedNoEffects,
                terminal_result: None,
            }
        );
        assert_eq!(facts.live().state(), ReferenceQueryLiveStateV1::NotReady);
        assert_eq!(control.apply.snapshot().canonical_wire(), prepared_wire);

        // A structurally valid PXAR signed by the wrong Controller key can be
        // represented by the owner journal, but startup must authenticate it
        // before advancing the host generation or exposing a listener.
        let invalid_request = signed_apply_request(
            control.apply.snapshot(),
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                operation: 0x8f,
                request_nonce: b"queried-prepared-nonce",
                controller_seed: [0x94; 32],
                ..ApplyRequestFixture::valid()
            },
        );
        let old_digest = request.envelope_request_digest();
        let mut invalid_state = control.apply.snapshot().state().clone();
        invalid_state
            .prepared
            .as_mut()
            .unwrap_or_else(|| panic!("prepared state disappeared"))
            .request = OpaqueCanonicalValue::try_request_or_slice(
            invalid_request.canonical_wire(),
            invalid_request.envelope_request_digest(),
        )
        .unwrap_or_else(|error| panic!("invalid signed request pin failed: {error:?}"));
        invalid_state
            .host
            .request_nonces
            .iter_mut()
            .find(|record| record.value_digest == old_digest)
            .unwrap_or_else(|| panic!("prepared request nonce record disappeared"))
            .value_digest = invalid_request.envelope_request_digest();
        let invalid_snapshot = RuntimeJournalSnapshot::try_new(
            *control.apply.snapshot().store_instance_id(),
            *control.apply.snapshot().owner_target_fingerprint(),
            control.apply.snapshot().sequence(),
            invalid_state,
        )
        .unwrap_or_else(|error| {
            panic!("structural invalid-signature snapshot rejected: {error:?}")
        });
        let attempts = Rc::new(Cell::new(0));
        let result = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: invalid_snapshot,
                commit_attempts: Rc::clone(&attempts),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled_facts(),
            provisioning(socket_path.clone()),
        );
        assert!(matches!(
            result,
            Err(RuntimeBootstrapEndpointError::InvalidStartedState)
        ));
        assert_eq!(attempts.get(), 0);
        assert!(!socket_path.exists());
    }

    #[test]
    fn query_phase_projection_preserves_the_durable_effect_boundary() {
        for (phase, is_head_first_retire, expected) in [
            (
                PreparedPhase::PreparedNoEffects,
                false,
                ReferenceQueryDurablePhaseV1::PreparedNoEffects,
            ),
            (
                PreparedPhase::SupersededBeforeEffects,
                false,
                ReferenceQueryDurablePhaseV1::PreparedNoEffects,
            ),
            (
                PreparedPhase::StartupExpiredNoEffects,
                false,
                ReferenceQueryDurablePhaseV1::PreparedNoEffects,
            ),
            (
                PreparedPhase::FirstActionIntent,
                false,
                ReferenceQueryDurablePhaseV1::FirstActionIntent,
            ),
            (
                PreparedPhase::SupersededReconcileRequired,
                false,
                ReferenceQueryDurablePhaseV1::FirstActionIntent,
            ),
            (
                PreparedPhase::StartupReconcileRequired,
                false,
                ReferenceQueryDurablePhaseV1::FirstActionIntent,
            ),
            (
                PreparedPhase::HeadCommittedRetiringOld,
                true,
                ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
            ),
            (
                PreparedPhase::SupersededReconcileRequired,
                true,
                ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
            ),
            (
                PreparedPhase::StartupReconcileRequired,
                true,
                ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
            ),
        ] {
            assert_eq!(query_prepared_phase(phase, is_head_first_retire), expected);
        }
    }

    #[test]
    fn query_preserves_head_committed_phase_after_higher_tenure_takeover() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-takeover-draining-test.sock");
        let (service, retire_request, channel) = head_first_retiring_service(socket_path.clone());
        let RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning,
            channel: service_channel,
        } = service;
        let current = apply.snapshot().clone();
        let current_fence = current
            .state()
            .writer_fence
            .unwrap_or_else(|| panic!("draining takeover lost writer fence"));
        let takeover_epoch = current_fence
            .epoch
            .checked_add(1)
            .unwrap_or_else(|| panic!("draining takeover epoch overflow"));
        let takeover = current
            .try_tenure_only_successor(RuntimeTenureAdmissionInput {
                expected_store_instance_id: *current.store_instance_id(),
                owner_target_fingerprint: *current.owner_target_fingerprint(),
                source_scope: current_fence.source_scope,
                writer: current_fence.writer,
                epoch: takeover_epoch,
                supersedes_through_epoch: current_fence.epoch,
                proof_envelope_digest: digest(0xe6),
                tenure_nonce_identity: digest(0xe7),
                principal: current_fence.principal,
            })
            .unwrap_or_else(|error| panic!("draining takeover successor failed: {error:?}"));
        let takeover_prepared = takeover
            .state()
            .prepared
            .as_ref()
            .unwrap_or_else(|| panic!("draining takeover lost prepared operation"));
        assert_eq!(
            takeover_prepared.phase,
            PreparedPhase::SupersededReconcileRequired
        );
        assert!(takeover_prepared.retiring.is_some());
        assert_eq!(
            RuntimeJournalSnapshot::decode(takeover.canonical_wire())
                .unwrap_or_else(|error| panic!("draining takeover did not reopen: {error:?}")),
            takeover
        );
        let mut non_superseded = takeover.state().clone();
        let non_superseded_prepared = non_superseded
            .prepared
            .as_mut()
            .unwrap_or_else(|| panic!("takeover corruption fixture lost prepared operation"));
        non_superseded_prepared.phase = PreparedPhase::HeadCommittedRetiringOld;
        non_superseded_prepared.raw_outcome = current
            .state()
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.raw_outcome);
        assert!(matches!(
            RuntimeJournalSnapshot::try_new(
                *takeover.store_instance_id(),
                *takeover.owner_target_fingerprint(),
                takeover.sequence(),
                non_superseded,
            ),
            Err(crate::runtime_journal::RuntimeJournalError::InvalidStateInvariant)
        ));

        let (mut store, apply_clock, owner, signer, apply_channel) =
            apply.into_test_recovery_parts();
        assert_eq!(apply_channel, channel);
        store.snapshot = takeover;
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            store,
            apply_clock,
            owner,
            signer,
            apply_channel,
        )
        .unwrap_or_else(|error| panic!("takeover apply core rejected: {error:?}"));
        let mut service = RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning,
            channel: service_channel,
        };
        let query = signed_query_request(QueryRequestFixture {
            query: 0xe8,
            expected_request_digest: Some(retire_request.envelope_request_digest()),
            ..QueryRequestFixture::fresh(0xe4)
        });
        let before = service.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(service.apply.snapshot());
        let response = service
            .handle_request(query.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("takeover draining query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("takeover draining query returned no PXQS"));
        let (_, facts) = decode_verify_query_response(&response, &query, channel, expected_serving);
        assert_eq!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Known {
                request_digest: retire_request.envelope_request_digest(),
                durable_phase: ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
                terminal_result: None,
            }
        );
        assert_eq!(
            facts.operation().owner_state(),
            ReferenceQueryOwnerStateV1::ApplyDisabled
        );
        assert_eq!(facts.live().state(), ReferenceQueryLiveStateV1::Draining);
        assert_eq!(service.apply.snapshot().canonical_wire(), before);
    }

    #[test]
    fn restart_terminalizes_head_committed_empty_as_interrupted_exact_zero() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-restart-draining-test.sock");
        let (service, retire_request, _) = head_first_retiring_service(socket_path.clone());
        let RuntimeControlService {
            apply,
            compiled,
            provisioning,
            ..
        } = service;
        let pre_restart = apply.snapshot().clone();
        drop(apply);
        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: pre_restart,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            compiled,
            provisioning,
        )
        .unwrap_or_else(|error| panic!("draining restart rejected: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xe9),
            digest(0xea),
        )
        .unwrap_or_else(|error| panic!("draining restart channel rejected: {error}"));
        let mut service = restarted
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("draining restart control rejected: {error}"));
        assert!(service.apply.snapshot().state().prepared.is_none());
        assert!(matches!(
            service.apply.snapshot().state().live_materialization,
            LiveMaterialization::ExactZero { .. }
        ));
        let terminal = service
            .apply
            .snapshot()
            .state()
            .terminal_operations
            .last()
            .unwrap_or_else(|| panic!("draining restart lost terminal"));
        assert_eq!(
            terminal.selection.primary,
            crate::runtime_journal::TerminalOutcome::InterruptedButNowExactZero
        );

        let query = signed_query_request(QueryRequestFixture {
            query: 0xeb,
            expected_request_digest: Some(retire_request.envelope_request_digest()),
            ..QueryRequestFixture::fresh(0xe4)
        });
        assert!(matches!(
            query_operation_lookup(service.apply.snapshot(), &query)
                .unwrap_or_else(|error| panic!("restart durable lookup failed: {error}")),
            ReferenceQueryOperationLookupV1::Known {
                request_digest,
                durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                terminal_result: Some(_),
            } if request_digest == retire_request.envelope_request_digest()
        ));
        let before = service.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(service.apply.snapshot());
        let response = service
            .handle_request(query.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("restart draining query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("restart draining query returned no PXQS"));
        let (_, facts) = decode_verify_query_response(&response, &query, channel, expected_serving);
        assert!(matches!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Known {
                durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                terminal_result: Some(_),
                ..
            }
        ));
        assert_eq!(facts.live().state(), ReferenceQueryLiveStateV1::ExactZero);
        assert_eq!(service.apply.snapshot().canonical_wire(), before);
    }

    #[test]
    fn higher_tenure_head_first_empty_restart_terminalizes_superseded_exact_zero() {
        let socket_path = PathBuf::from("/tmp/paraegox-empty-takeover-restart.sock");
        reset_fixed_owner_callback_actions_for_test();
        let (service, retire_request, _) = head_first_retiring_service(socket_path.clone());
        // Ignore the predecessor Loop start; the restart below must not invoke
        // either lifecycle callback for the already head-committed action.
        reset_fixed_owner_callback_actions_for_test();
        let RuntimeControlService {
            apply,
            compiled,
            provisioning,
            ..
        } = service;
        let current = apply.snapshot().clone();
        let prepared = current
            .state()
            .prepared
            .as_ref()
            .unwrap_or_else(|| panic!("empty takeover lost prepared action"));
        let retiring_generation = prepared
            .retiring
            .as_ref()
            .unwrap_or_else(|| panic!("empty takeover lost retiring facts"))
            .old_resource_generation;
        let takeover = higher_tenure_successor(&current, 0xdc);
        drop(apply);

        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: takeover,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning,
        )
        .unwrap_or_else(|error| panic!("empty takeover restart failed: {error}"));
        let recovered = restarted.state.snapshot();
        assert!(!socket_path.exists());
        assert!(recovered.state().prepared.is_none());
        assert!(matches!(
            recovered.state().live_materialization,
            LiveMaterialization::ExactZero { .. }
        ));
        let terminal = terminal_for_request(recovered, &retire_request);
        assert_eq!(
            terminal.selection.primary,
            TerminalOutcome::SupersededAfterIntentExactZero
        );
        assert!(terminal.selection.raw.higher_tenure_takeover);
        assert_owned_crash_generation_is_tombstoned(recovered, retiring_generation);
        assert!(fixed_owner_start_callback_actions_for_test().is_empty());
        assert!(fixed_owner_stop_callback_actions_for_test().is_empty());
    }

    #[test]
    fn historical_terminal_replay_bypasses_later_not_ready_busy_without_commit() {
        let socket_path = PathBuf::from("/tmp/paraegox-busy-replay-test.sock");
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let active_request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"active-one-source-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xd1),
            digest(0xd2),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let mut active_service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("control service rejected: {error}"));
        let active_pxrt = active_service
            .handle_request(active_request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("one-source apply rejected: {error:?}"))
            .unwrap_or_else(|| panic!("one-source apply returned no PXRT"));
        let active_receipt = ReferenceApplyTerminalReceiptV1::decode(&active_pxrt)
            .unwrap_or_else(|error| panic!("active PXRT decode failed: {error}"));
        assert_eq!(
            active_receipt.facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        );

        let active_snapshot = active_service.apply.snapshot().clone();
        let (active_slice_digest, resource_generation) =
            match active_snapshot.state().live_materialization {
                LiveMaterialization::LiveReady {
                    active_slice_digest,
                    resource_generation,
                    ..
                } => (active_slice_digest, resource_generation),
                other => panic!("one-source terminal did not become LiveReady: {other:?}"),
            };
        let budgets = active_request
            .target_execution()
            .loop_facts()
            .unwrap_or_else(|| panic!("active request lost loop facts"))
            .budgets();
        let compiled = active_service.compiled;
        let compatibility = active_service.compatibility.clone();
        let clock = active_service.clock;
        drop(active_service);

        let provisioning = provisioning(socket_path.clone());
        let signer = RuntimeReferenceApplySigner::try_new(
            provisioning.response_signer().clone(),
            provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("response algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("response signer failed: {error:?}"));
        let owner = FailingRetireOwner {
            active_slice_digest,
            resource_generation,
            plan: RuntimeEmptyRetireOwnerPlan {
                action_id: [0xd3; 16],
                signed_budgets: budgets,
            },
        };
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            MockStore {
                snapshot: active_snapshot.clone(),
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            RuntimeEndpointApplyClock { clock },
            owner,
            signer,
            channel,
        )
        .unwrap_or_else(|error| panic!("failing-retire core rejected: {error:?}"));
        let mut busy_service = RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning,
            channel,
        };
        let retire_request = signed_apply_request(
            &active_snapshot,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::EmptyDeactivate,
                operation: 0xd4,
                request_nonce: b"retire-to-busy-nonce",
                tenure_nonce: b"retire-to-busy-tenure",
                writer_epoch: 2,
                supersedes_epoch: 1,
                source_revision: 2,
                temporal_constraint: 0xd5,
                expected_active: ExpectedActive::Exact(active_slice_digest),
                ..ApplyRequestFixture::valid()
            },
        );
        assert!(matches!(
            busy_service.handle_request(retire_request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Owner(
                    RuntimeReferenceMaterializationOwnerError::CallbackFailed
                ))
            ))
        ));
        let busy_state =
            RuntimeControlState::try_from_started_snapshot(busy_service.apply.snapshot())
                .unwrap_or_else(|error| panic!("busy state invalid: {error:?}"));
        assert_eq!(
            busy_state.bootstrap_facts().map(|facts| facts.readiness()),
            Ok(RuntimeJournalBootstrapState::NotReadyBusy)
        );
        let busy_sequence = busy_service.apply.snapshot().sequence();

        let replay = busy_service
            .handle_request(active_request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("busy historical replay rejected: {error:?}"))
            .unwrap_or_else(|| panic!("busy historical replay returned no PXRT"));
        assert_eq!(replay, active_pxrt);
        assert_eq!(busy_service.apply.snapshot().sequence(), busy_sequence);
    }

    #[test]
    fn apply_ingress_rejects_bad_crypto_store_cas_and_operation_conflict_without_mutation() {
        let socket_path = PathBuf::from("/tmp/paraegox-apply-reject-test.sock");
        let started = started_service(socket_path);
        let initial = started.state.snapshot().clone();
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xb1),
            digest(0xb2),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("control service rejected: {error}"));

        let invalid = [
            ApplyRequestFixture {
                controller_seed: [0xc1; 32],
                ..ApplyRequestFixture::valid()
            },
            ApplyRequestFixture {
                tenure_seed: [0xc2; 32],
                ..ApplyRequestFixture::valid()
            },
            ApplyRequestFixture {
                expected_store: [0xc3; 32],
                ..ApplyRequestFixture::valid()
            },
            ApplyRequestFixture {
                expected_active: ExpectedActive::Exact(TargetSliceDigest::new(digest(0xc4))),
                ..ApplyRequestFixture::valid()
            },
        ];
        for fixture in invalid {
            let request = signed_apply_request(&initial, fixture);
            assert!(matches!(
                control.handle_request(request.canonical_wire(), channel),
                Err(RuntimeControlRequestError::Rejected)
            ));
            assert_eq!(control.apply.snapshot().sequence(), 2);
        }
        let valid = signed_apply_request(&initial, ApplyRequestFixture::valid());
        let terminal = control
            .handle_request(valid.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("valid apply rejected: {error:?}"))
            .unwrap_or_else(|| panic!("valid apply returned no terminal"));
        let terminal_sequence = control.apply.snapshot().sequence();

        let conflicting = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                request_nonce: b"conflicting-operation-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        assert!(matches!(
            control.handle_request(conflicting.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert_eq!(control.apply.snapshot().sequence(), terminal_sequence);
        assert_eq!(&terminal[..4], b"PXRT");

        let mut trailing = valid.canonical_wire().to_vec();
        trailing.push(0);
        assert!(matches!(
            control.handle_request(&trailing, channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert_eq!(control.apply.snapshot().sequence(), terminal_sequence);
    }

    #[tokio::test]
    async fn framing_rejects_zero_and_oversize_before_reading_a_payload() {
        for claimed_length in [0_u32, 65_u32] {
            let (mut reader, mut writer) = UnixStream::pair()
                .unwrap_or_else(|error| panic!("UnixStream pair failed: {error}"));
            writer
                .write_all(&claimed_length.to_be_bytes())
                .await
                .unwrap_or_else(|error| panic!("frame header write failed: {error}"));
            assert_eq!(
                read_bounded_frame(&mut reader, 64, Duration::from_secs(1)).await,
                Err(())
            );
        }

        let (mut reader, mut writer) =
            UnixStream::pair().unwrap_or_else(|error| panic!("UnixStream pair failed: {error}"));
        write_bounded_frame(
            &mut writer,
            b"bounded-response",
            MAX_CONTROL_RESPONSE_BYTES,
            Duration::from_secs(1),
        )
        .await
        .unwrap_or_else(|()| panic!("bounded response write failed"));
        let mut length = [0_u8; CONTROL_FRAME_HEADER_BYTES];
        reader
            .read_exact(&mut length)
            .await
            .unwrap_or_else(|error| panic!("response header read failed: {error}"));
        let mut payload = vec![0_u8; u32::from_be_bytes(length) as usize];
        reader
            .read_exact(&mut payload)
            .await
            .unwrap_or_else(|error| panic!("response payload read failed: {error}"));
        assert_eq!(payload, b"bounded-response");
    }

    struct TestSocketDirectory {
        path: PathBuf,
        socket_path: PathBuf,
    }

    impl TestSocketDirectory {
        fn create() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let name = format!(
                "paraegox-runtime-endpoint-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(name);
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("test socket directory create failed: {error}"));
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(CONTROL_SOCKET_DIRECTORY_MODE),
            )
            .unwrap_or_else(|error| panic!("test socket directory chmod failed: {error}"));
            let socket_path = path.join("bootstrap.sock");
            Self { path, socket_path }
        }
    }

    impl Drop for TestSocketDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.socket_path);
            let _ = fs::remove_dir(&self.path);
        }
    }

    #[test]
    fn listener_bind_occurs_after_commit_and_channel_uses_live_socket_facts() {
        let directory = TestSocketDirectory::create();
        let started = started_service(directory.socket_path.clone());
        assert!(!directory.socket_path.exists());
        let bound = started
            .bind()
            .unwrap_or_else(|error| panic!("listener bind failed: {error}"));
        assert!(directory.socket_path.exists());
        let channel = live_runtime_channel(&bound.started.provisioning, &bound.guard)
            .unwrap_or_else(|error| panic!("live channel failed: {error}"));
        assert_eq!(channel.target(), TARGET);
        assert_eq!(channel.runtime_peer(), RUNTIME_PRINCIPAL);
        let metadata = fs::symlink_metadata(&directory.socket_path)
            .unwrap_or_else(|error| panic!("socket metadata failed: {error}"));
        assert_eq!(
            channel.local_endpoint_identity_digest(),
            reference_local_control_endpoint_identity_digest_v1(
                directory.socket_path.as_os_str().as_bytes(),
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode() & MODE_MASK,
            )
            .unwrap_or_else(|error| panic!("endpoint digest failed: {error}"))
        );
        drop(bound);
        assert!(!directory.socket_path.exists());
    }

    #[tokio::test]
    async fn managed_listener_is_published_only_after_successor_recovery() {
        let socket_directory = TestSocketDirectory::create();
        let (_state_directory, started) =
            managed_started_service(socket_directory.socket_path.clone());
        assert!(matches!(
            started.core.recovered_observation(),
            Err(ManagedFabricRuntimeError::RecoveryNotCompleted)
        ));
        assert!(
            !socket_directory.socket_path.exists(),
            "managed socket must be absent before async recovery"
        );
        assert_eq!(
            started
                .core
                .clock_reading()
                .expect("managed clock must read")
                .generation()
                .value(),
            1
        );
        serve_managed_fabric_until(started, async {
            assert!(
                socket_directory.socket_path.exists(),
                "shutdown future must not be polled until recovery and bind complete"
            );
            Ok(())
        })
        .await
        .unwrap_or_else(|error| panic!("managed service shutdown failed: {error}"));
        assert!(
            !socket_directory.socket_path.exists(),
            "managed socket must be removed after exact shutdown"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_pxar9_routes_only_to_model_agent_owner_and_returns_exact_pxmt() {
        let socket_directory = TestSocketDirectory::create();
        let (_state_directory, mut started) = managed_started_service_with_dependencies(
            socket_directory.socket_path.clone(),
            model_fixture_service_dependencies(),
        );
        started
            .core
            .recover()
            .await
            .unwrap_or_else(|error| panic!("PXAR9 predecessor recovery rejected: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xe7),
            digest(0xe8),
        )
        .unwrap_or_else(|error| panic!("PXAR9 channel rejected: {error}"));
        let fabric_request = managed_fabric_active_request(
            started.stack_projection.managed_fabric_projection().clone(),
            managed_available_port(),
            started
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("PXAR9 predecessor clock failed: {error}"))
                .generation(),
        );
        let mut control = ManagedFabricControlService {
            core: started.core,
            stack: started.stack,
            stack_projection: started.stack_projection,
            model_stack: started.model_stack,
            model_stack_projection: started.model_stack_projection,
            distributed: started.distributed,
            distributed_projection: started.distributed_projection,
            handle_broker: started.handle_broker,
            state_directory: started.state_directory,
            provisioning: started.provisioning,
            channel,
            dependencies: started.dependencies,
        };
        let fabric_wire = control
            .handle_request(fabric_request.canonical_wire(), channel)
            .await
            .unwrap_or_else(|error| panic!("PXAR9 predecessor apply rejected: {error:?}"));
        let fabric_receipt = ManagedFabricApplyTerminalReceiptV1::decode(&fabric_wire)
            .unwrap_or_else(|error| panic!("PXAR9 predecessor terminal rejected: {error}"));
        assert_eq!(
            fabric_receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        );

        let request = managed_model_stack_active_request(
            &fabric_request,
            control.model_stack_projection.clone(),
            control
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("PXAR9 owner clock failed: {error}"))
                .generation(),
        );
        assert_eq!(
            u16::from_be_bytes([request.canonical_wire()[4], request.canonical_wire()[5]]),
            MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION
        );
        let terminal_wire = control
            .handle_request(request.canonical_wire(), channel)
            .await
            .unwrap_or_else(|error| panic!("valid PXAR9 rejected: {error:?}"));
        let terminal = ManagedModelAgentStackTerminalReceiptV1::decode(&terminal_wire)
            .unwrap_or_else(|error| panic!("valid PXMT rejected: {error}"));
        let facts = terminal
            .validate_against_request(&request, channel)
            .unwrap_or_else(|error| panic!("PXMT correlation failed: {error}"));
        assert_eq!(
            facts.state().outcome(),
            ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
        );
        assert_eq!(terminal.canonical_wire(), terminal_wire.as_ref());
        assert!(control.model_stack.is_some());
        assert!(control.stack.is_none());
        assert!(control.distributed.is_none());
        assert_eq!(
            control
                .handle_request(request.canonical_wire(), channel)
                .await
                .unwrap_or_else(|error| panic!("PXAR9 replay rejected: {error:?}")),
            terminal_wire,
            "owner terminal replay must preserve the exact legal PXMT bytes",
        );

        let sibling_v7 = managed_stack_active_request(
            &fabric_request,
            control.stack_projection.clone(),
            control
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("PXAR7 sibling clock failed: {error}"))
                .generation(),
        );
        assert!(matches!(
            control
                .handle_request(sibling_v7.canonical_wire(), channel)
                .await,
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert!(matches!(
            control
                .handle_request(fabric_request.canonical_wire(), channel)
                .await,
            Err(RuntimeControlRequestError::Rejected)
        ));

        shutdown_managed_successor_chain(
            &mut control.distributed,
            &mut control.model_stack,
            &mut control.stack,
            &mut control.core,
        )
        .await
        .unwrap_or_else(|error| panic!("PXAR9 successor shutdown failed: {error}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_pxar7_active_conversation_empty_and_restart_replay_are_one_vertical() {
        let socket_directory = TestSocketDirectory::create();
        let (state_directory, mut started) =
            managed_started_service(socket_directory.socket_path.clone());
        started
            .core
            .recover()
            .await
            .unwrap_or_else(|error| panic!("managed predecessor recovery rejected: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xe1),
            digest(0xe2),
        )
        .unwrap_or_else(|error| panic!("managed stack channel rejected: {error}"));
        let fabric_projection = started.stack_projection.managed_fabric_projection().clone();
        let fabric_port = managed_available_port();
        let fabric_request = managed_fabric_active_request(
            fabric_projection.clone(),
            fabric_port,
            started
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("managed predecessor clock failed: {error}"))
                .generation(),
        );
        let mut control = ManagedFabricControlService {
            core: started.core,
            stack: started.stack,
            stack_projection: started.stack_projection,
            model_stack: started.model_stack,
            model_stack_projection: started.model_stack_projection,
            distributed: started.distributed,
            distributed_projection: started.distributed_projection,
            handle_broker: started.handle_broker,
            state_directory: started.state_directory,
            provisioning: started.provisioning,
            channel,
            dependencies: started.dependencies,
        };
        let fabric_wire = control
            .handle_request(fabric_request.canonical_wire(), channel)
            .await
            .unwrap_or_else(|error| panic!("managed PXAR-v6 rejected: {error:?}"));
        let fabric_receipt = ManagedFabricApplyTerminalReceiptV1::decode(&fabric_wire)
            .unwrap_or_else(|error| panic!("managed PXFT decode failed: {error}"));
        assert_eq!(
            fabric_receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        );

        let stack_request = managed_stack_active_request(
            &fabric_request,
            control.stack_projection.clone(),
            control
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("managed stack clock failed: {error}"))
                .generation(),
        );
        let active_wire = control
            .handle_request(stack_request.canonical_wire(), channel)
            .await
            .unwrap_or_else(|error| panic!("managed PXAR-v7 rejected: {error:?}"));
        let active_receipt = ManagedAgentStackTerminalReceiptV1::decode(&active_wire)
            .unwrap_or_else(|error| panic!("managed PXST decode failed: {error}"));
        assert_eq!(
            active_receipt.facts().state().outcome(),
            ManagedAgentStackTerminalOutcomeV1::ActiveReady
        );
        assert!(control.stack.is_some());
        let handle = control
            .handle_broker
            .try_acquire()
            .unwrap_or_else(|| panic!("ActiveReady must publish one opaque Agent handle"));
        let deck_run_id = AgentConversationDeckRunId::try_from_bytes([0xc1; 16])
            .unwrap_or_else(|error| panic!("DeckRun id rejected: {error}"));
        let session_id = AgentConversationSessionId::try_from_bytes([0xc2; 16])
            .unwrap_or_else(|error| panic!("Session id rejected: {error}"));
        handle
            .open_session(deck_run_id, session_id, Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("managed Agent session failed: {error}"));
        let turn = AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            AgentConversationTurnId::try_from_bytes([0xc3; 16])
                .unwrap_or_else(|error| panic!("Turn id rejected: {error}")),
            AgentConversationRequestId::try_from_bytes([0xc4; 16])
                .unwrap_or_else(|error| panic!("Request id rejected: {error}")),
            2_000_000_000,
            "endpoint vertical",
        )
        .unwrap_or_else(|error| panic!("managed Agent request rejected: {error}"));
        let terminal = handle
            .submit(turn, Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("managed Agent turn failed: {error}"));
        assert_eq!(
            terminal.result(),
            &AgentConversationTerminalResultV1::Success("echo: endpoint vertical".into())
        );
        assert_eq!(
            control
                .handle_request(stack_request.canonical_wire(), channel)
                .await
                .unwrap_or_else(|error| panic!("managed active replay failed: {error:?}")),
            active_wire,
            "PXST replay must be byte-identical"
        );
        let mut predecessor_v6 = fabric_request.canonical_wire().to_vec();
        predecessor_v6.shrink_to_fit();
        assert!(matches!(
            control.handle_request(&predecessor_v6, channel).await,
            Err(RuntimeControlRequestError::Rejected)
        ));

        let empty_request = managed_stack_empty_request(
            &stack_request,
            control
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("managed empty clock failed: {error}"))
                .generation(),
        );
        let empty_wire = control
            .handle_request(empty_request.canonical_wire(), channel)
            .await
            .unwrap_or_else(|error| panic!("managed empty PXAR-v7 rejected: {error:?}"));
        let empty_receipt = ManagedAgentStackTerminalReceiptV1::decode(&empty_wire)
            .unwrap_or_else(|error| panic!("managed empty PXST decode failed: {error}"));
        assert_eq!(
            empty_receipt.facts().state().outcome(),
            ManagedAgentStackTerminalOutcomeV1::EmptyExactZero
        );
        assert!(control.handle_broker.try_acquire().is_none());
        assert_eq!(
            control
                .handle_request(empty_request.canonical_wire(), channel)
                .await
                .unwrap_or_else(|error| panic!("managed empty replay failed: {error:?}")),
            empty_wire
        );
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, fabric_port))
            .unwrap_or_else(|error| panic!("exact-zero did not release Fabric port: {error}"));

        if let Some(stack) = control.stack.as_mut() {
            stack
                .shutdown(&mut control.core)
                .await
                .unwrap_or_else(|error| panic!("managed stack shutdown failed: {error}"));
        }
        control
            .core
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("managed predecessor shutdown failed: {error}"));
        drop(control);

        let projection_digest = transition_projection_digest(&fabric_projection)
            .unwrap_or_else(|error| panic!("restart projection digest failed: {error}"));
        let reopened_store = ManagedFabricStore::open_fixture(
            state_directory.path(),
            STORE_INSTANCE_ID,
            provisioning(socket_directory.socket_path.clone()).owner_target_fingerprint(),
            projection_digest,
        )
        .unwrap_or_else(|error| panic!("managed successor store reopen failed: {error}"));
        let restarted = StartedManagedFabricService::try_start_from_store(
            state_directory.path(),
            STORE_INSTANCE_ID,
            compiled_facts(),
            provisioning(socket_directory.socket_path.clone()),
            reopened_store,
            RuntimeManagedFabricServiceDependenciesV1::unavailable(),
        )
        .unwrap_or_else(|error| panic!("managed exact-zero restart failed: {error}"));
        let StartedManagedFabricService {
            mut core,
            mut stack,
            stack_projection,
            model_stack,
            model_stack_projection,
            distributed,
            distributed_projection,
            handle_broker,
            state_directory,
            provisioning,
            dependencies,
        } = restarted;
        {
            let recovered_stack = stack
                .as_mut()
                .unwrap_or_else(|| panic!("managed stack cutover disappeared on restart"));
            assert!(!recovered_stack.requires_predecessor_recovery());
            recovered_stack
                .recover(&mut core)
                .await
                .unwrap_or_else(|error| panic!("managed exact-zero recovery failed: {error}"));
        }
        let mut restarted_control = ManagedFabricControlService {
            core,
            stack,
            stack_projection,
            model_stack,
            model_stack_projection,
            distributed,
            distributed_projection,
            handle_broker,
            state_directory,
            provisioning,
            channel,
            dependencies,
        };
        assert_eq!(
            restarted_control
                .handle_request(empty_request.canonical_wire(), channel)
                .await
                .unwrap_or_else(|error| panic!("restart PXST replay failed: {error:?}")),
            empty_wire
        );
        assert!(restarted_control.handle_broker.try_acquire().is_none());
        if let Some(stack) = restarted_control.stack.as_mut() {
            stack
                .shutdown(&mut restarted_control.core)
                .await
                .unwrap_or_else(|error| panic!("restart stack shutdown failed: {error}"));
        }
        restarted_control
            .core
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("restart predecessor shutdown failed: {error}"));
    }

    #[test]
    fn distributed_owner_commits_active_v1_before_publishing_any_handle() {
        let source = include_str!("distributed_agent_stack_runtime.rs");
        let evidence_commit = section(
            source,
            "    async fn commit_snapshot_evidence_and_activate(",
            "    async fn start_agent_after_verified_evidence(",
        );
        let begin = evidence_commit
            .find("self.begin_evidence_commit(owner, batch.clone())")
            .unwrap_or_else(|| panic!("durable Evidence intent disappeared"));
        let append = evidence_commit
            .find("self.append_evidence_batch_with_one_reopen(&batch)")
            .unwrap_or_else(|| panic!("Evidence append/readback disappeared"));
        let committed = evidence_commit
            .find("self.mark_evidence_committed(owner, &verified)")
            .unwrap_or_else(|| panic!("durable Evidence commit disappeared"));
        let agent_start = evidence_commit
            .find("self.start_agent_after_verified_evidence(")
            .unwrap_or_else(|| panic!("post-Evidence Agent start disappeared"));
        assert!(begin < append && append < committed && committed < agent_start);
        assert!(!evidence_commit.contains(".publish_distributed("));

        let activation = section(
            source,
            "    async fn start_agent_after_verified_evidence(",
            "    async fn complete_agent_activation_failure(",
        );
        let assembly_start = activation
            .find("ManagedAgentAssembly::start_from_execution(")
            .unwrap_or_else(|| panic!("distributed Agent start disappeared"));
        let ready_shape = activation
            .find("ready.phase = DistributedAgentStackDurablePhase::ActiveReady")
            .unwrap_or_else(|| panic!("ActiveReady state construction disappeared"));
        let clear_handoff = activation
            .find("self.snapshot.evidence_state().try_clear_committed()")
            .unwrap_or_else(|| panic!("committed Evidence clear disappeared"));
        let durable_commit = activation
            .find("self.commit_v2_transition(owner, ready, cleared_evidence)")
            .unwrap_or_else(|| panic!("durable ActiveReady commit disappeared"));
        let retain_handle = activation
            .find("self.handle = Some(handle.clone())")
            .unwrap_or_else(|| panic!("Runtime handle retention disappeared"));
        let pending_publish = activation
            .find("self.handle_publication_pending = self")
            .unwrap_or_else(|| panic!("handle publication retry marker disappeared"));
        let publish = activation
            .find(".publish_distributed(handle, &receipt)")
            .unwrap_or_else(|| panic!("distributed handle publication disappeared"));
        assert!(
            assembly_start < ready_shape
                && ready_shape < clear_handoff
                && clear_handoff < durable_commit
                && durable_commit < retain_handle
                && retain_handle < pending_publish
                && pending_publish < publish
        );
        assert_eq!(activation.match_indices(".publish_distributed(").count(), 1);
        let activation_failures = activation
            .match_indices(".complete_agent_activation_failure(")
            .map(|(failure, _)| failure)
            .collect::<Vec<_>>();
        assert!(!activation_failures.is_empty());
        assert!(
            activation_failures
                .into_iter()
                .all(|failure| failure < publish),
            "Agent start/census failures must return before broker publication"
        );
        let commit_failure = &activation[durable_commit..retain_handle];
        assert!(commit_failure.contains("drop(handle)"));
        assert!(
            commit_failure
                .contains("self.cleanup_unpublished_agent_after_commit_failure(assembly)")
        );
        assert!(commit_failure.contains("self.recovery_completed = false"));
        assert!(commit_failure.contains("return Err(error)"));
        let activation_cleanup = section(
            source,
            "    async fn complete_agent_activation_failure(",
            "    async fn cleanup_unpublished_agent_after_commit_failure(",
        );
        assert!(activation_cleanup.contains("self.handle = None"));
        assert!(activation_cleanup.contains("self.handle_publication_pending = false"));
        assert!(activation_cleanup.contains("assembly.shutdown().await"));
        assert!(!activation_cleanup.contains(".publish_distributed("));
        let commit_cleanup = section(
            source,
            "    async fn cleanup_unpublished_agent_after_commit_failure(",
            "    fn commit_agent_activation_quarantine(",
        );
        assert!(commit_cleanup.contains("self.handle = None"));
        assert!(commit_cleanup.contains("self.handle_publication_pending = false"));
        assert!(commit_cleanup.contains("assembly.shutdown().await"));
        assert!(commit_cleanup.contains("self.cleanup_live().await"));
        assert!(!commit_cleanup.contains(".publish_distributed("));
        let apply_outcome = section(
            source,
            "    fn activation_apply_outcome(",
            "    async fn complete_agent_activation_failure(",
        );
        assert!(apply_outcome.contains("if self.handle_publication_pending"));
        assert!(
            apply_outcome
                .contains("DistributedAgentStackApplyOutcome::CommittedHandleUnavailable(receipt)")
        );
        assert!(apply_outcome.contains("DistributedAgentStackApplyOutcome::Committed(receipt)"));

        let replay = section(
            source,
            "    pub(crate) fn authenticated_terminal_replay(",
            "    #[cfg(test)]\n    pub(crate) fn durable_current_is_exact_zero_for_test(",
        );
        let validate = replay
            .find("validate_request(owner, &self.projection, request, response_channel)")
            .unwrap_or_else(|| panic!("authenticated replay validation disappeared"));
        let lookup = replay
            .find("self.lookup_terminal(request, response_channel)")
            .unwrap_or_else(|| panic!("durable terminal lookup disappeared"));
        let pending = replay
            .find("if self.handle_publication_pending")
            .unwrap_or_else(|| panic!("pending publication retry disappeared"));
        let active = replay
            .find("DistributedAgentStackTerminalOutcomeV1::ActiveReady")
            .unwrap_or_else(|| panic!("pending replay ActiveReady gate disappeared"));
        let retained = replay
            .find("let handle = self")
            .unwrap_or_else(|| panic!("pending replay retained-handle gate disappeared"));
        let retry = replay
            .find(".publish_distributed(handle.clone(), active)")
            .unwrap_or_else(|| panic!("exact PXDS1 publication retry disappeared"));
        let clear_pending = replay
            .find("self.handle_publication_pending = false")
            .unwrap_or_else(|| panic!("publication retry marker clear disappeared"));
        assert!(
            validate < lookup
                && lookup < pending
                && pending < active
                && active < retained
                && retained < retry
                && retry < clear_pending
        );
        assert_eq!(replay.match_indices(".publish_distributed(").count(), 1);

        let endpoint_source = include_str!("runtime_control_endpoint.rs");
        let endpoint = section(
            endpoint_source,
            "    async fn handle_distributed_agent_stack_apply(",
            "pub(crate) fn validate_restricted_runtime_apply_carrier_pins",
        );
        let mutable_owner = endpoint
            .find("if let Some(distributed) = self.distributed.as_mut()")
            .unwrap_or_else(|| panic!("mutation-capable distributed replay owner disappeared"));
        let authenticated_replay = endpoint
            .find("distributed.authenticated_terminal_replay")
            .unwrap_or_else(|| panic!("authenticated distributed replay disappeared"));
        let exact_return = endpoint
            .find("return distributed_agent_stack_terminal_response_wire(&receipt)")
            .unwrap_or_else(|| panic!("exact PXDS1 replay return disappeared"));
        let fresh_reading = endpoint
            .find("let reading = self")
            .unwrap_or_else(|| panic!("fresh distributed admission clock disappeared"));
        assert!(
            mutable_owner < authenticated_replay
                && authenticated_replay < exact_return
                && exact_return < fresh_reading
        );
        let installed_core = endpoint
            .find("self.distributed = Some(distributed)")
            .unwrap_or_else(|| panic!("cutover core installation disappeared"));
        let classify = endpoint
            .find("distributed_agent_stack_apply_response_wire(outcome)")
            .unwrap_or_else(|| panic!("distributed outcome classification disappeared"));
        assert!(installed_core < classify);
        let response_mapping = section(
            endpoint_source,
            "fn distributed_agent_stack_apply_response_wire(",
            "fn map_managed_fabric_error(",
        );
        let handle_unavailable = response_mapping
            .find("DistributedAgentStackApplyOutcome::CommittedHandleUnavailable(_)")
            .unwrap_or_else(|| panic!("handle-unavailable outcome mapping disappeared"));
        let restart_required = response_mapping
            .find("DistributedAgentStackApplyOutcome::CommittedOwnerRestartRequired")
            .unwrap_or_else(|| panic!("retained-owner restart mapping disappeared"));
        let pending_error = response_mapping
            .find("Err(RuntimeControlRequestError::Unavailable)")
            .unwrap_or_else(|| panic!("handle-unavailable endpoint error disappeared"));
        let restart_error = response_mapping
            .find("RuntimeBootstrapEndpointError::DistributedAgentStackRestartRequired")
            .unwrap_or_else(|| panic!("restart-required endpoint error disappeared"));
        assert!(handle_unavailable < pending_error && restart_required < restart_error);
        assert!(
            !response_mapping[handle_unavailable.min(restart_required)..]
                .contains("distributed_agent_stack_terminal_response_wire(&receipt)")
        );
    }

    #[test]
    fn unavailable_is_nonfatal_in_every_endpoint_service_loop() {
        let source = include_str!("runtime_control_endpoint.rs");
        let developer = section(
            source,
            "async fn serve_developer_legacy_cutover_until<F, R>(",
            "fn prevalidate_developer_managed_cutover_request(",
        );
        let legacy = section(
            source,
            "impl<Store> BoundRuntimeBootstrapService<Store>",
            "async fn serve_managed_fabric_until<F>(",
        );
        let managed = section(
            source,
            "pub(crate) async fn serve_managed_fabric_until_with_ready<F, R>(",
            "async fn runtime_shutdown_signal()",
        );
        let assert_local_unavailable_continues = |service: &str| {
            let unavailable = service
                .find("Err(RuntimeControlRequestError::Unavailable)")
                .unwrap_or_else(|| panic!("local Unavailable classification disappeared"));
            let internal = service[unavailable..]
                .find("Err(RuntimeControlRequestError::Internal(error))")
                .map(|offset| unavailable + offset)
                .unwrap_or_else(|| panic!("local Internal classification disappeared"));
            let nonfatal = &service[unavailable..internal];
            assert!(nonfatal.contains("continue"));
            assert!(!nonfatal.contains("break"));
        };
        assert_local_unavailable_continues(developer);
        assert_local_unavailable_continues(legacy);
        assert_local_unavailable_continues(managed);

        let assert_restricted_unavailable_continues = |service: &str| {
            let unavailable = service
                .find("Err(RuntimeRestrictedRemoteApplyErrorV1::Unavailable)")
                .unwrap_or_else(|| panic!("restricted Unavailable classification disappeared"));
            let internal = service[unavailable..]
                .find("Err(error @ RuntimeRestrictedRemoteApplyErrorV1::Internal)")
                .map(|offset| unavailable + offset)
                .unwrap_or_else(|| panic!("restricted Internal classification disappeared"));
            let nonfatal = &service[unavailable..internal];
            assert!(nonfatal.contains("drop(inbound)"));
            assert!(!nonfatal.contains("break"));
            assert!(service[internal..].contains("continue;"));
        };
        assert_restricted_unavailable_continues(developer);
        assert_restricted_unavailable_continues(managed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_pxds_bridge_claims_only_exact_published_inner_and_registered_outer() {
        // The endpoint's remote-mTLS fixture remains intentionally fail-closed,
        // so this test begins at the signed PXDS1 terminal boundary. It proves
        // endpoint correlation and handle gating, not a live two-host session.
        let socket_directory = TestSocketDirectory::create();
        let (_state_directory, mut control, stack_request) =
            managed_control_with_active_stack(socket_directory.socket_path.clone()).await;
        let request = distributed_stack_active_request(
            &stack_request,
            control.distributed_projection.clone(),
            control
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("ActiveReady PXDS fixture clock failed: {error}"))
                .generation(),
        );
        let carrier =
            pinned_restricted_carrier(&control.provisioning, &request, RESTRICTED_APPLY_ROUTE);
        let restricted = restricted_apply_request(request.clone(), carrier.clone());
        let authenticated = authenticate_restricted_distributed_agent_stack_apply(
            &control.provisioning,
            &restricted,
            &carrier,
        )
        .unwrap_or_else(|error| panic!("ActiveReady PXRC authentication failed: {error}"));
        let pxds1 = distributed_active_terminal_receipt(&request, control.channel, 101);
        let pxds1_wire = distributed_agent_stack_terminal_response_wire(&pxds1)
            .unwrap_or_else(|error| panic!("ActiveReady PXDS1 response rejected: {error:?}"));
        assert_eq!(pxds1_wire.as_ref(), pxds1.canonical_wire());
        assert_eq!(
            distributed_agent_stack_apply_response_wire(
                DistributedAgentStackApplyOutcome::Committed(pxds1.clone()),
            )
            .unwrap_or_else(|error| panic!("committed PXDS1 classification failed: {error:?}")),
            pxds1_wire
        );
        assert_eq!(
            distributed_agent_stack_apply_response_wire(
                DistributedAgentStackApplyOutcome::Replayed(pxds1.clone()),
            )
            .unwrap_or_else(|error| panic!("replayed PXDS1 classification failed: {error:?}")),
            pxds1_wire
        );
        assert!(matches!(
            distributed_agent_stack_apply_response_wire(
                DistributedAgentStackApplyOutcome::CommittedHandleUnavailable(pxds1.clone()),
            ),
            Err(RuntimeControlRequestError::Unavailable)
        ));
        assert!(matches!(
            distributed_agent_stack_apply_response_wire(
                DistributedAgentStackApplyOutcome::CommittedOwnerRestartRequired,
            ),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::DistributedAgentStackRestartRequired,
            ))
        ));
        assert_eq!(
            map_restricted_inner_apply_error(RuntimeControlRequestError::Unavailable),
            RuntimeRestrictedRemoteApplyErrorV1::Unavailable
        );
        assert!(matches!(
            map_distributed_agent_stack_error(
                DistributedAgentStackRuntimeError::HandlePublicationPending,
            ),
            RuntimeControlRequestError::Unavailable
        ));

        let bridged_facts = validate_restricted_inner_terminal(
            &control.provisioning,
            authenticated,
            control.channel,
            &pxds1_wire,
        )
        .unwrap_or_else(|error| panic!("ActiveReady PXDS1 validation failed: {error}"));
        assert_eq!(&bridged_facts, pxds1.facts());
        assert_eq!(
            bridged_facts.outcome(),
            DistributedAgentStackTerminalOutcomeV1::ActiveReady
        );
        assert_eq!(bridged_facts.target(), request.target());
        assert_eq!(bridged_facts.operation_id(), request.operation_id());
        assert_eq!(
            bridged_facts.request_digest(),
            request.envelope_request_digest()
        );
        assert_eq!(
            bridged_facts.target_slice_digest(),
            request.target_slice_digest()
        );

        let draft =
            DistributedAgentStackTerminalReceiptDraftV2::try_new(authenticated, bridged_facts)
                .unwrap_or_else(|error| panic!("ActiveReady PXDS2 draft rejected: {error}"));
        let signature = control
            .provisioning
            .response_signer()
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| {
                        panic!("ActiveReady PXDS2 transcript rejected: {error}")
                    })
                    .as_bytes(),
            )
            .to_bytes();
        let pxds2 = draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("ActiveReady PXDS2 rejected: {error}"));
        let expected_runtime_fingerprint = ed25519_control_key_fingerprint(
            control
                .provisioning
                .response_signer()
                .verifying_key()
                .as_bytes(),
        )
        .unwrap_or_else(|error| panic!("Runtime response fingerprint failed: {error}"));
        let verified_v2 = pxds2
            .verify_runtime_response(
                authenticated,
                |principal, key, fingerprint, transcript, signature| {
                    let Ok(signature) = Signature::from_slice(signature) else {
                        return false;
                    };
                    principal == control.provisioning.runtime_principal()
                        && key == control.provisioning.runtime_response_key_ref()
                        && fingerprint == expected_runtime_fingerprint
                        && control
                            .provisioning
                            .response_signer()
                            .verifying_key()
                            .verify_strict(transcript, &signature)
                            .is_ok()
                },
            )
            .unwrap_or_else(|error| panic!("ActiveReady PXDS2 verification failed: {error}"));
        assert_eq!(verified_v2, pxds1.facts());
        assert_eq!(pxds2.carrier(), &carrier);
        assert_eq!(
            pxds2.restricted_request_digest(),
            restricted.restricted_request_digest()
        );

        // This fixture isolates the broker's exact-receipt gate. The separate
        // owner-ordering test proves that production publication happens only
        // after the same ActiveReady transition is durably committed.
        let live_handle = control
            .handle_broker
            .try_acquire()
            .unwrap_or_else(|| panic!("managed predecessor lost its live Agent handle"));
        assert!(
            control
                .handle_broker
                .try_claim_restricted_distributed(pxds2.canonical_wire())
                .unwrap_or_else(|error| panic!("unpublished PXDS2 claim failed: {error}"))
                .is_none(),
            "an unregistered ActiveReady PXDS2 must not claim a handle"
        );
        assert!(
            control
                .handle_broker
                .register_restricted_distributed_alias(&pxds1_wire, pxds2.canonical_wire())
                .is_err(),
            "an outer alias must not register before its exact inner PXDS1 is published"
        );
        assert!(
            control
                .handle_broker
                .try_claim_distributed(&pxds1_wire)
                .unwrap_or_else(|error| panic!("unpublished PXDS1 claim failed: {error}"))
                .is_none(),
            "an ActiveReady receipt that was not published must not claim a handle"
        );
        control
            .handle_broker
            .publish_distributed(live_handle, &pxds1)
            .unwrap_or_else(|error| panic!("fixture distributed publish failed: {error}"));
        assert!(
            control
                .handle_broker
                .try_claim_distributed(&pxds1_wire)
                .unwrap_or_else(|error| panic!("published PXDS1 claim failed: {error}"))
                .is_some(),
            "the byte-identical published ActiveReady PXDS1 must claim its handle"
        );
        assert!(
            control
                .handle_broker
                .try_claim_restricted_distributed(pxds2.canonical_wire())
                .unwrap_or_else(|error| panic!("unregistered PXDS2 claim failed: {error}"))
                .is_none(),
            "publishing inner PXDS1 alone must not make the outer PXDS2 claimable"
        );
        control
            .handle_broker
            .register_restricted_distributed_alias(&pxds1_wire, pxds2.canonical_wire())
            .unwrap_or_else(|error| panic!("exact restricted alias registration failed: {error}"));
        control
            .handle_broker
            .register_restricted_distributed_alias(&pxds1_wire, pxds2.canonical_wire())
            .unwrap_or_else(|error| panic!("exact restricted alias replay failed: {error}"));
        assert!(
            control
                .handle_broker
                .try_claim_restricted_distributed(pxds2.canonical_wire())
                .unwrap_or_else(|error| panic!("registered PXDS2 claim failed: {error}"))
                .is_some(),
            "the byte-identical registered ActiveReady PXDS2 must claim its inner handle"
        );
        let different_facts_inner =
            distributed_active_terminal_receipt(&request, control.channel, 102);
        assert_ne!(different_facts_inner.facts(), pxds1.facts());
        let different_facts_draft = DistributedAgentStackTerminalReceiptDraftV2::try_new(
            authenticated,
            different_facts_inner.facts().clone(),
        )
        .unwrap_or_else(|error| panic!("different-facts PXDS2 draft rejected: {error}"));
        let different_facts_signature = control
            .provisioning
            .response_signer()
            .sign(
                different_facts_draft
                    .signing_transcript()
                    .unwrap_or_else(|error| {
                        panic!("different-facts PXDS2 transcript rejected: {error}")
                    })
                    .as_bytes(),
            )
            .to_bytes();
        let different_facts_pxds2 = different_facts_draft
            .finalize(&different_facts_signature)
            .unwrap_or_else(|error| panic!("different-facts PXDS2 rejected: {error}"));
        assert!(
            control
                .handle_broker
                .register_restricted_distributed_alias(
                    pxds1.canonical_wire(),
                    different_facts_pxds2.canonical_wire(),
                )
                .is_err(),
            "a canonical PXDS2 with different typed/fact bytes must not alias the inner PXDS1"
        );
        let mut different_pxds1 = pxds1_wire.into_vec();
        *different_pxds1
            .last_mut()
            .unwrap_or_else(|| panic!("PXDS1 fixture must contain a signature")) ^= 1;
        assert!(
            control
                .handle_broker
                .try_claim_distributed(&different_pxds1)
                .unwrap_or_else(|error| panic!("different PXDS1 claim failed: {error}"))
                .is_none(),
            "a different canonical PXDS1 must not claim the published handle"
        );
        assert!(
            control
                .handle_broker
                .register_restricted_distributed_alias(&different_pxds1, pxds2.canonical_wire())
                .is_err(),
            "an alias must not attach to a different inner PXDS1"
        );
        let mut different_pxds2 = pxds2.canonical_wire().to_vec();
        *different_pxds2
            .last_mut()
            .unwrap_or_else(|| panic!("PXDS2 fixture must contain a signature")) ^= 1;
        assert!(
            control
                .handle_broker
                .try_claim_restricted_distributed(&different_pxds2)
                .unwrap_or_else(|error| panic!("different PXDS2 claim failed: {error}"))
                .is_none(),
            "a different canonical PXDS2 must not claim the registered alias"
        );
        assert!(
            control
                .handle_broker
                .register_restricted_distributed_alias(pxds1.canonical_wire(), &different_pxds2)
                .is_err(),
            "a different outer alias must not replace the registered PXDS2"
        );
        assert!(matches!(
            control
                .handle_broker
                .try_claim_distributed(pxds2.canonical_wire()),
            Err(ManagedAgentStackRuntimeError::RequestRejected)
        ));
        assert!(matches!(
            control
                .handle_broker
                .try_claim_restricted_distributed(pxds1.canonical_wire()),
            Err(ManagedAgentStackRuntimeError::RequestRejected)
        ));

        shutdown_managed_successor_chain(
            &mut control.distributed,
            &mut control.model_stack,
            &mut control.stack,
            &mut control.core,
        )
        .await
        .unwrap_or_else(|error| panic!("ActiveReady PXDS fixture shutdown failed: {error}"));
        assert!(
            control
                .handle_broker
                .try_claim_restricted_distributed(pxds2.canonical_wire())
                .unwrap_or_else(|error| panic!("revoked PXDS2 claim failed: {error}"))
                .is_none(),
            "ordered shutdown must revoke the inner handle and every registered alias"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restricted_pxrc_verifies_before_mutation_and_returns_exact_pinned_pxds2() {
        const ROUTE: &str = "paraegox/runtime/endpoint-stack/restricted/apply";

        let socket_directory = TestSocketDirectory::create();
        let (_state_directory, mut control, stack_request) =
            managed_control_with_active_stack(socket_directory.socket_path.clone()).await;
        let distributed_request = distributed_stack_active_request(
            &stack_request,
            control.distributed_projection.clone(),
            control
                .core
                .clock_reading()
                .unwrap_or_else(|error| panic!("restricted apply clock failed: {error}"))
                .generation(),
        );
        let carrier = pinned_restricted_carrier(&control.provisioning, &distributed_request, ROUTE);
        let restricted = restricted_apply_request(distributed_request.clone(), carrier.clone());
        let before_sequence = control
            .core
            .recovered_observation()
            .unwrap_or_else(|error| panic!("restricted preflight observation failed: {error}"))
            .successor_snapshot_sequence;

        let mut bad_signature = restricted.canonical_wire().to_vec();
        *bad_signature
            .last_mut()
            .unwrap_or_else(|| panic!("PXRC must contain a signature")) ^= 1;
        assert!(matches!(
            control
                .handle_restricted_distributed_agent_stack_apply_v1(&bad_signature, &carrier)
                .await,
            Err(RuntimeRestrictedRemoteApplyErrorV1::Rejected)
        ));
        assert!(control.distributed.is_none());

        let wrong_expected = pinned_restricted_carrier(
            &control.provisioning,
            &distributed_request,
            "paraegox/runtime/endpoint-stack/other-route/apply",
        );
        assert!(matches!(
            control
                .handle_restricted_distributed_agent_stack_apply_v1(
                    restricted.canonical_wire(),
                    &wrong_expected,
                )
                .await,
            Err(RuntimeRestrictedRemoteApplyErrorV1::Rejected)
        ));
        assert!(control.distributed.is_none());

        let runtime_response_fingerprint = ed25519_control_key_fingerprint(
            control
                .provisioning
                .response_signer()
                .verifying_key()
                .as_bytes(),
        )
        .unwrap_or_else(|error| panic!("restricted Runtime fingerprint failed: {error}"));
        let unpinned_carrier = restricted_carrier(
            &control.provisioning,
            &distributed_request,
            ROUTE,
            digest(0xee),
            runtime_response_fingerprint,
        );
        let unpinned =
            restricted_apply_request(distributed_request.clone(), unpinned_carrier.clone());
        assert!(matches!(
            control
                .handle_restricted_distributed_agent_stack_apply_v1(
                    unpinned.canonical_wire(),
                    &unpinned_carrier,
                )
                .await,
            Err(RuntimeRestrictedRemoteApplyErrorV1::Rejected)
        ));
        assert!(control.distributed.is_none());

        let unpinned_runtime_carrier = restricted_carrier(
            &control.provisioning,
            &distributed_request,
            ROUTE,
            control.provisioning.controller_key_fingerprint(),
            digest(0xef),
        );
        let unpinned_runtime = restricted_apply_request(
            distributed_request.clone(),
            unpinned_runtime_carrier.clone(),
        );
        assert!(matches!(
            control
                .handle_restricted_distributed_agent_stack_apply_v1(
                    unpinned_runtime.canonical_wire(),
                    &unpinned_runtime_carrier,
                )
                .await,
            Err(RuntimeRestrictedRemoteApplyErrorV1::Rejected)
        ));
        assert!(control.distributed.is_none());

        let mut bad_inner_signature = distributed_request.authentication().signature().to_vec();
        *bad_inner_signature
            .last_mut()
            .unwrap_or_else(|| panic!("PXAR v8 must contain a signature")) ^= 1;
        let bad_inner = DistributedAgentStackApplyRequestDraftV1::try_new(
            distributed_request.target_execution().clone(),
            distributed_request.provenance(),
            distributed_request.control_commitment().control().clone(),
            distributed_request.temporal(),
            distributed_request.expected_runtime_store_instance_id(),
            distributed_request.authentication().claim().clone(),
        )
        .unwrap_or_else(|error| panic!("bad inner PXAR draft rejected: {error}"))
        .finalize(&bad_inner_signature)
        .unwrap_or_else(|error| panic!("structurally valid bad inner PXAR rejected: {error}"));
        let authenticated_outer = restricted_apply_request(bad_inner, carrier.clone());
        let _authenticated_outer = authenticate_restricted_distributed_agent_stack_apply(
            &control.provisioning,
            &authenticated_outer,
            &carrier,
        )
        .unwrap_or_else(|error| panic!("valid outer PXRC authentication failed: {error}"));
        assert!(matches!(
            control
                .handle_restricted_distributed_agent_stack_apply_v1(
                    authenticated_outer.canonical_wire(),
                    &carrier,
                )
                .await,
            Err(RuntimeRestrictedRemoteApplyErrorV1::Rejected)
        ));
        assert!(control.distributed.is_none());
        assert_eq!(
            control
                .core
                .recovered_observation()
                .unwrap_or_else(|error| panic!("restricted rejection observation failed: {error}"))
                .successor_snapshot_sequence,
            before_sequence,
            "rejected PXRC/PXAR authentication must not mutate the PXAR v8 owner"
        );

        let response = control
            .handle_restricted_distributed_agent_stack_apply_v1(
                restricted.canonical_wire(),
                &carrier,
            )
            .await
            .unwrap_or_else(|error| panic!("valid restricted apply failed: {error}"));
        assert!(control.distributed.is_some());
        let receipt = DistributedAgentStackTerminalReceiptV2::decode(&response)
            .unwrap_or_else(|error| panic!("restricted PXDS2 decode failed: {error}"));
        assert!(matches!(
            control
                .handle_broker
                .try_claim_restricted_distributed(&response),
            Err(ManagedAgentStackRuntimeError::RequestRejected)
        ));
        assert_eq!(receipt.carrier(), &carrier);
        assert_eq!(
            receipt.restricted_request_digest(),
            restricted.restricted_request_digest()
        );
        let authenticated = authenticate_restricted_distributed_agent_stack_apply(
            &control.provisioning,
            &restricted,
            &carrier,
        )
        .unwrap_or_else(|error| panic!("restricted marker reconstruction failed: {error}"));
        let facts = receipt
            .verify_runtime_response(
                authenticated,
                |principal, key, fingerprint, transcript, signature| {
                    let Ok(signature) = Signature::from_slice(signature) else {
                        return false;
                    };
                    principal == control.provisioning.runtime_principal()
                        && key == control.provisioning.runtime_response_key_ref()
                        && fingerprint == runtime_response_fingerprint
                        && control
                            .provisioning
                            .response_signer()
                            .verifying_key()
                            .verify_strict(transcript, &signature)
                            .is_ok()
                },
            )
            .unwrap_or_else(|error| panic!("restricted Runtime signature failed: {error}"));
        assert_eq!(
            facts.outcome(),
            DistributedAgentStackTerminalOutcomeV1::TerminalNonReady
        );
        let evidence = facts.evidence();
        assert!(evidence.fabric_generation.is_none());
        assert!(evidence.agent_generation.is_none());
        assert_eq!(evidence.local_bindings.physical_binding_census, 0);
        assert!(!evidence.local_bindings.census_complete);
        assert!(!evidence.local_bindings.fabric_ready);
        assert!(!evidence.local_bindings.agent_ready);
        assert!(!evidence.local_bindings.dependency_satisfied);
        assert!(!evidence.local_bindings.exact_zero);
        assert!(!evidence.local_bindings.quarantined);
        assert!(
            facts
                .observations()
                .unwrap_or_else(|| panic!("non-ready terminal lost its empty observation set"))
                .proofs()
                .is_empty()
        );
        assert!(
            control.handle_broker.try_acquire().is_none(),
            "non-ready distributed owner must not publish an Agent handle"
        );
        assert!(
            control
                .distributed
                .as_ref()
                .is_some_and(|distributed| distributed.durable_current_is_exact_zero_for_test()),
            "conservative PXDS evidence must not weaken the independently durable exact-zero state"
        );

        let replay = control
            .handle_restricted_distributed_agent_stack_apply_v1(
                restricted.canonical_wire(),
                &carrier,
            )
            .await
            .unwrap_or_else(|error| panic!("restricted replay failed: {error}"));
        assert_eq!(replay, response, "restricted replay must be byte-identical");

        shutdown_managed_successor_chain(
            &mut control.distributed,
            &mut control.model_stack,
            &mut control.stack,
            &mut control.core,
        )
        .await
        .unwrap_or_else(|error| panic!("restricted successor shutdown failed: {error}"));
    }

    #[tokio::test]
    async fn managed_serving_bootstrap_is_signed_correlated_and_read_only() {
        let socket_directory = TestSocketDirectory::create();
        let (_state_directory, mut started) =
            managed_started_service(socket_directory.socket_path.clone());
        started
            .core
            .recover()
            .await
            .unwrap_or_else(|error| panic!("managed recovery rejected: {error}"));
        let observed = started
            .core
            .recovered_observation()
            .unwrap_or_else(|error| panic!("managed observation rejected: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xc1),
            digest(0xc2),
        )
        .unwrap_or_else(|error| panic!("managed channel rejected: {error}"));
        let claim = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("managed algorithm rejected: {error}")),
            ED25519_ALGORITHM_VERSION,
            b"managed-serving-fresh-nonce",
        )
        .unwrap_or_else(|error| panic!("managed bootstrap claim rejected: {error}"));
        let draft = ManagedServingBootstrapRequestDraftV1::try_new(
            ManagedServingBootstrapRequestIdV1::try_from_bytes([0xc3; 16])
                .unwrap_or_else(|error| panic!("managed request id rejected: {error}")),
            TARGET,
            SOURCE_SCOPE,
            STORE_INSTANCE_ID,
            observed.projection.clone(),
            channel,
            claim,
        )
        .unwrap_or_else(|error| panic!("managed bootstrap draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("managed request transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        let request = draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("managed request finalization failed: {error}"));
        let mut control = ManagedFabricControlService {
            core: started.core,
            stack: started.stack,
            stack_projection: started.stack_projection,
            model_stack: started.model_stack,
            model_stack_projection: started.model_stack_projection,
            distributed: started.distributed,
            distributed_projection: started.distributed_projection,
            handle_broker: started.handle_broker,
            state_directory: started.state_directory,
            provisioning: started.provisioning,
            channel,
            dependencies: started.dependencies,
        };

        let mut bad_signature = request.canonical_wire().to_vec();
        let last = bad_signature
            .last_mut()
            .unwrap_or_else(|| panic!("managed request must be nonempty"));
        *last ^= 0x01;
        assert!(matches!(
            control.handle_request(&bad_signature, channel).await,
            Err(RuntimeControlRequestError::Rejected)
        ));

        let response_wire = control
            .handle_request(request.canonical_wire(), channel)
            .await
            .unwrap_or_else(|error| panic!("managed bootstrap rejected: {error:?}"));
        let response = ManagedServingBootstrapResponseV1::decode(&response_wire)
            .unwrap_or_else(|error| panic!("managed response decode failed: {error}"));
        let facts = response
            .validate_against_request(&request, channel)
            .unwrap_or_else(|error| panic!("managed response correlation failed: {error}"));
        assert_eq!(facts.readiness(), ManagedServingReadinessV1::RecoveredReady);
        assert_eq!(facts.target(), TARGET);
        assert_eq!(facts.runtime_store_instance_id(), STORE_INSTANCE_ID);
        assert_eq!(facts.projection(), &observed.projection);
        assert_eq!(facts.runtime_host_epoch(), observed.runtime_host_epoch);
        assert_eq!(
            facts.snapshot_sequence(),
            observed.successor_snapshot_sequence
        );
        assert_eq!(facts.clock_domain(), observed.clock.domain());
        assert_eq!(facts.clock_generation(), observed.clock.generation());
        assert_ne!(facts.observed_at_nanos(), 0);
        assert_eq!(response.authentication_runtime_peer(), RUNTIME_PRINCIPAL);
        assert_eq!(response.authentication_key(), RESPONSE_KEY_REF);
        let response_signature: &[u8; ED25519_SIGNATURE_BYTES] = response
            .authentication_signature()
            .try_into()
            .unwrap_or_else(|_| panic!("managed response signature length changed"));
        SigningKey::from_bytes(&RESPONSE_SEED)
            .verifying_key()
            .verify_strict(
                response
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("managed response transcript failed: {error}"))
                    .as_bytes(),
                &Signature::from_bytes(response_signature),
            )
            .unwrap_or_else(|error| panic!("managed response signature failed: {error}"));
        let after = control
            .core
            .recovered_observation()
            .unwrap_or_else(|error| panic!("post-response observation failed: {error}"));
        assert_eq!(
            after.successor_snapshot_sequence, observed.successor_snapshot_sequence,
            "PXFB/PXFR read-only observation must not write the successor journal"
        );
        control
            .core
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("managed cleanup failed: {error}"));
    }

    #[tokio::test]
    async fn managed_dispatch_strictly_rejects_pxar_v5_without_legacy_fallback() {
        let socket_directory = TestSocketDirectory::create();
        let (_state_directory, mut started) =
            managed_started_service(socket_directory.socket_path.clone());
        started
            .core
            .recover()
            .await
            .unwrap_or_else(|error| panic!("managed recovery rejected: {error}"));
        let observation = started
            .core
            .recovered_observation()
            .unwrap_or_else(|error| panic!("managed observation rejected: {error}"));
        assert_eq!(observation.target, TARGET);
        assert_eq!(observation.store_instance_id, STORE_INSTANCE_ID);
        assert_eq!(observation.runtime_host_epoch, 1);
        assert_eq!(observation.clock.generation().value(), 1);
        assert_ne!(observation.transition_projection_digest, digest(0));
        assert_ne!(observation.successor_snapshot_sequence, 0);
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xd1),
            digest(0xd2),
        )
        .unwrap_or_else(|error| panic!("managed channel rejected: {error}"));
        let mut control = ManagedFabricControlService {
            core: started.core,
            stack: started.stack,
            stack_projection: started.stack_projection,
            model_stack: started.model_stack,
            model_stack_projection: started.model_stack_projection,
            distributed: started.distributed,
            distributed_projection: started.distributed_projection,
            handle_broker: started.handle_broker,
            state_directory: started.state_directory,
            provisioning: started.provisioning,
            channel,
            dependencies: started.dependencies,
        };
        let mut legacy_version = [0_u8; 18];
        legacy_version[..4].copy_from_slice(APPLY_REQUEST_MAGIC);
        legacy_version[4..6].copy_from_slice(&5_u16.to_be_bytes());
        assert!(matches!(
            control.handle_request(&legacy_version, channel).await,
            Err(RuntimeControlRequestError::Rejected)
        ));
        control
            .core
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("managed cleanup failed: {error}"));
    }

    #[tokio::test]
    async fn bound_service_checks_peer_credentials_and_cleans_up_on_shutdown() {
        let directory = TestSocketDirectory::create();
        let bound = started_service(directory.socket_path.clone())
            .bind()
            .unwrap_or_else(|error| panic!("listener bind failed: {error}"));
        let (stream, peer) =
            UnixStream::pair().unwrap_or_else(|error| panic!("UnixStream pair failed: {error}"));
        assert!(peer_is_authorized(
            &stream,
            geteuid().as_raw(),
            getegid().as_raw()
        ));
        assert!(!peer_is_authorized(
            &stream,
            distinct_controller_uid(geteuid().as_raw()),
            getegid().as_raw()
        ));
        drop((stream, peer));
        bound
            .serve_until(async { Ok(()) })
            .await
            .unwrap_or_else(|error| panic!("clean shutdown failed: {error}"));
        assert!(!directory.socket_path.exists());
    }
    #[test]
    fn production_runner_fails_before_service_on_an_unopened_store() {
        let directory = TestSocketDirectory::create();
        let missing_store = directory.path.join("missing-store");
        let result = run_runtime_bootstrap_process(
            &missing_store,
            STORE_INSTANCE_ID,
            compiled_facts(),
            provisioning(directory.socket_path.clone()),
            RuntimeManagedFabricServiceDependenciesV1::unavailable(),
        );
        assert!(matches!(
            result,
            Err(RuntimeBootstrapEndpointError::StoreOpen(_))
        ));
        assert!(!directory.socket_path.exists());
    }
}
