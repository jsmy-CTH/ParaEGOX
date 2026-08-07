#![cfg(unix)]

//! Runtime-owned preparation seam for the distributed Fabric topology.
//!
//! PXDT carries opaque credential, trust, and expected-peer references, never
//! key material. The Runtime presents each exact peer requirement to one
//! composition-owned resolver, verifies that the resolver echoed the complete
//! domain-separated requirement digest, and admits only one common resolved
//! credential set for the single Fabric session. The resulting configuration
//! is consumed once by the existing managed Fabric lifecycle owner.
//!
//! A successful local session start is deliberately not remote-link evidence:
//! this module neither observes a TLS handshake nor installs Agent bindings or
//! publishes a PXAR-v8 terminal.

use core::fmt;
use std::collections::BTreeSet;

use paraegox_fabric::{
    ExperimentalPeerCommonNameV1, ExperimentalRemoteMtlsPeerBindingV1, FabricServiceConfig,
    RemoteTlsEndpoint, ResolvedRemoteMtlsCredentialFiles, SessionEndpoint,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedAgentStackTargetExecutionV1, DistributedAgentStackTargetModeV1,
    DistributedFabricAuthenticationProfileV1, DistributedFabricCredentialRefV1,
    DistributedFabricPeerAuthenticationRequirementV1, DistributedFabricPeerIdentityRefV1,
    DistributedFabricPeerPlanV1, DistributedFabricTlsEndpointV1, DistributedFabricTopologyV1,
    DistributedFabricTrustAnchorRefV1, DistributedFabricTrustDomainRefV1,
};
use paraegox_runtime_contracts::managed_service::{ManagedServiceGeneration, ManagedServiceSpecV1};

use crate::managed_fabric_runtime::{ManagedFabricControlHandle, RuntimeManagedFabricService};
use crate::managed_service_assembly::{ManagedServiceAssembly, ManagedServiceStartupOutcome};
use crate::runtime_clock::RuntimeClock;
use crate::task_registry::CancellationSource;

const TOPOLOGY_PREPARATION_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-fabric-topology-preparation.sha256.v1";
const EXPERIMENTAL_PEER_CN_BINDING_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-fabric-peer-cn-binding.sha256.experimental.v2";

/// Exact non-secret PXDT peer requirement presented to the credential owner.
///
/// The value includes the peer RuntimeHost and endpoint because both are part
/// of the contract-owned requirement digest. A resolver must use the complete
/// value; resolving only the credential reference is not sufficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFabricCredentialRequirementV1 {
    peer_runtime_host: RuntimeHostId,
    connect_endpoint: DistributedFabricTlsEndpointV1,
    authentication: DistributedFabricPeerAuthenticationRequirementV1,
    requirement_digest: Digest32,
}

impl RuntimeFabricCredentialRequirementV1 {
    fn from_peer(peer: &DistributedFabricPeerPlanV1) -> Self {
        Self {
            peer_runtime_host: peer.peer_runtime_host(),
            connect_endpoint: peer.connect_endpoint().clone(),
            authentication: peer.authentication(),
            requirement_digest: peer.requirement_digest(),
        }
    }

    /// Returns the exact remote RuntimeHost bound by this requirement.
    #[must_use]
    pub const fn peer_runtime_host(&self) -> RuntimeHostId {
        self.peer_runtime_host
    }

    /// Returns the exact canonical TLS connect endpoint.
    #[must_use]
    pub const fn connect_endpoint(&self) -> &DistributedFabricTlsEndpointV1 {
        &self.connect_endpoint
    }

    /// Returns the required authentication profile.
    #[must_use]
    pub const fn profile(&self) -> DistributedFabricAuthenticationProfileV1 {
        self.authentication.profile()
    }

    /// Returns the exact trust-domain reference.
    #[must_use]
    pub const fn trust_domain_ref(&self) -> DistributedFabricTrustDomainRefV1 {
        self.authentication.trust_domain_ref()
    }

    /// Returns the exact local-credential reference.
    #[must_use]
    pub const fn local_credential_ref(&self) -> DistributedFabricCredentialRefV1 {
        self.authentication.local_credential_ref()
    }

    /// Returns the exact trust-anchor reference.
    #[must_use]
    pub const fn trust_anchor_ref(&self) -> DistributedFabricTrustAnchorRefV1 {
        self.authentication.trust_anchor_ref()
    }

    /// Returns the enrolled remote peer-identity reference.
    #[must_use]
    pub const fn expected_peer_identity_ref(&self) -> DistributedFabricPeerIdentityRefV1 {
        self.authentication.expected_peer_identity_ref()
    }

    /// Returns the complete contract-owned requirement digest to be echoed.
    #[must_use]
    pub const fn requirement_digest(&self) -> Digest32 {
        self.requirement_digest
    }
}

/// Stable, display-safe credential resolution failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFabricCredentialResolveError {
    /// The owner could not resolve the exact enrolled requirement.
    ResolutionFailed,
}

impl fmt::Display for RuntimeFabricCredentialResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Runtime Fabric credential resolution failed closed")
    }
}

impl std::error::Error for RuntimeFabricCredentialResolveError {}

/// Stable, display-safe failures for the strict experimental V2 resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFabricCredentialResolveErrorV2 {
    /// The owner could not resolve the exact enrolled requirement.
    ResolutionFailed,
    /// The resolved experimental Common Name is not canonical and bounded.
    InvalidExpectedPeerCommonName,
    /// The process-local identity-binding digest could not be constructed.
    IdentityBindingDigestFailed,
}

impl fmt::Display for RuntimeFabricCredentialResolveErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Runtime Fabric V2 credential resolution failed closed")
    }
}

impl std::error::Error for RuntimeFabricCredentialResolveErrorV2 {}

/// Resolved process-local files plus the complete requirement digest echoed by
/// the credential owner.
///
/// Debug never delegates to the resolved file value. The file paths are
/// consumed only while building one in-process Zenoh configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeResolvedFabricCredentialFilesV1 {
    requirement_digest: Digest32,
    credential_files: ResolvedRemoteMtlsCredentialFiles,
}

impl RuntimeResolvedFabricCredentialFilesV1 {
    /// Binds resolved files to the exact digest handled by the resolver.
    #[must_use]
    pub const fn new(
        requirement_digest: Digest32,
        credential_files: ResolvedRemoteMtlsCredentialFiles,
    ) -> Self {
        Self {
            requirement_digest,
            credential_files,
        }
    }

    /// Returns the resolver-echoed complete requirement digest.
    #[must_use]
    pub const fn requirement_digest(&self) -> Digest32 {
        self.requirement_digest
    }

    fn into_parts(self) -> (Digest32, ResolvedRemoteMtlsCredentialFiles) {
        (self.requirement_digest, self.credential_files)
    }
}

impl fmt::Debug for RuntimeResolvedFabricCredentialFilesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeResolvedFabricCredentialFilesV1")
            .field("requirement_digest", &self.requirement_digest)
            .field("credential_files", &"<redacted-resolved-paths>")
            .finish()
    }
}

/// Repeatable Runtime composition seam for one exact PXDT peer requirement.
///
/// Implementations may own secret-store clients, but this boundary admits only
/// already validated absolute file paths. It is called again during durable
/// recovery, so implementations must not consume one-shot credential state.
pub trait RuntimeFabricCredentialResolverV1: Send + Sync + 'static {
    fn resolve(
        &self,
        requirement: &RuntimeFabricCredentialRequirementV1,
    ) -> Result<RuntimeResolvedFabricCredentialFilesV1, RuntimeFabricCredentialResolveError>;
}

/// Experimental V2 result binding one exact PXDT identity reference to a CN.
///
/// The constructor validates the lower-case DNS-style CN through Fabric's one
/// comparison type and computes a domain-separated digest over the complete
/// requirement digest, expected peer-identity reference, and exact CN. Paths
/// and the CN are redacted from `Debug`. This is process-local preparation for
/// Zenoh 1.9 link introspection, not a production certificate identity claim.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeResolvedFabricPeerCredentialV2 {
    requirement_digest: Digest32,
    expected_peer_identity_ref: DistributedFabricPeerIdentityRefV1,
    expected_common_name: ExperimentalPeerCommonNameV1,
    identity_binding_digest: Digest32,
    credential_files: ResolvedRemoteMtlsCredentialFiles,
}

impl RuntimeResolvedFabricPeerCredentialV2 {
    /// Validates and binds the resolver output to one exact expected identity.
    pub fn try_new(
        requirement_digest: Digest32,
        expected_peer_identity_ref: DistributedFabricPeerIdentityRefV1,
        expected_common_name: impl Into<String>,
        credential_files: ResolvedRemoteMtlsCredentialFiles,
    ) -> Result<Self, RuntimeFabricCredentialResolveErrorV2> {
        let expected_common_name = ExperimentalPeerCommonNameV1::try_new(expected_common_name)
            .map_err(|_| RuntimeFabricCredentialResolveErrorV2::InvalidExpectedPeerCommonName)?;
        let identity_binding_digest = experimental_peer_cn_binding_digest(
            requirement_digest,
            expected_peer_identity_ref,
            &expected_common_name,
        )
        .map_err(|_| RuntimeFabricCredentialResolveErrorV2::IdentityBindingDigestFailed)?;
        Ok(Self {
            requirement_digest,
            expected_peer_identity_ref,
            expected_common_name,
            identity_binding_digest,
            credential_files,
        })
    }

    /// Returns the complete resolver-echoed PXDT requirement digest.
    #[must_use]
    pub const fn requirement_digest(&self) -> Digest32 {
        self.requirement_digest
    }

    /// Returns the resolver-echoed expected peer-identity reference.
    #[must_use]
    pub const fn expected_peer_identity_ref(&self) -> DistributedFabricPeerIdentityRefV1 {
        self.expected_peer_identity_ref
    }

    /// Returns the exact bounded canonical CN selected by the credential owner.
    #[must_use]
    pub const fn expected_common_name(&self) -> &ExperimentalPeerCommonNameV1 {
        &self.expected_common_name
    }

    /// Returns the domain-separated requirement/ref/CN binding digest.
    #[must_use]
    pub const fn identity_binding_digest(&self) -> Digest32 {
        self.identity_binding_digest
    }

    fn into_parts(
        self,
    ) -> (
        Digest32,
        DistributedFabricPeerIdentityRefV1,
        ExperimentalPeerCommonNameV1,
        Digest32,
        ResolvedRemoteMtlsCredentialFiles,
    ) {
        (
            self.requirement_digest,
            self.expected_peer_identity_ref,
            self.expected_common_name,
            self.identity_binding_digest,
            self.credential_files,
        )
    }
}

impl fmt::Debug for RuntimeResolvedFabricPeerCredentialV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeResolvedFabricPeerCredentialV2")
            .field("requirement_digest", &self.requirement_digest)
            .field(
                "expected_peer_identity_ref",
                &self.expected_peer_identity_ref,
            )
            .field("expected_common_name", &"<redacted-cn>")
            .field("identity_binding_digest", &self.identity_binding_digest)
            .field("credential_files", &"<redacted-resolved-paths>")
            .finish()
    }
}

/// Strict experimental successor for one exact PXDT peer requirement.
///
/// V2 has no V1 fallback: every resolved row must explicitly carry its echoed
/// identity reference and canonical expected CN. Implementations remain
/// repeatable across recovery and return only already validated local paths.
pub trait RuntimeFabricCredentialResolverV2: Send + Sync + 'static {
    fn resolve(
        &self,
        requirement: &RuntimeFabricCredentialRequirementV1,
    ) -> Result<RuntimeResolvedFabricPeerCredentialV2, RuntimeFabricCredentialResolveErrorV2>;
}

fn experimental_peer_cn_binding_digest(
    requirement_digest: Digest32,
    expected_peer_identity_ref: DistributedFabricPeerIdentityRefV1,
    expected_common_name: &ExperimentalPeerCommonNameV1,
) -> Result<Digest32, DigestBuildError> {
    let mut digest = Digest32Builder::try_new(EXPERIMENTAL_PEER_CN_BINDING_DIGEST_DOMAIN)?;
    digest.field_digest(&requirement_digest)?;
    digest.field_bytes(expected_peer_identity_ref.as_bytes())?;
    digest.field_bytes(expected_common_name.as_str().as_bytes())?;
    Ok(digest.finish())
}

struct PreparedDistributedFabricConfigV1 {
    config: FabricServiceConfig,
    topology_digest: Digest32,
    ordered_peer_requirements: Box<[RuntimeFabricCredentialRequirementV1]>,
    experimental_identity_binding_digests: Option<Box<[Digest32]>>,
}

impl PreparedDistributedFabricConfigV1 {
    fn peer_requirement_digests(&self) -> Box<[Digest32]> {
        self.ordered_peer_requirements
            .iter()
            .map(RuntimeFabricCredentialRequirementV1::requirement_digest)
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

impl fmt::Debug for PreparedDistributedFabricConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDistributedFabricConfigV1")
            .field("topology_digest", &self.topology_digest)
            .field("peer_count", &self.ordered_peer_requirements.len())
            .field(
                "experimental_identity_binding_count",
                &self
                    .experimental_identity_binding_digests
                    .as_deref()
                    .map_or(0, <[Digest32]>::len),
            )
            .field("config", &self.config)
            .finish()
    }
}

fn prepare_distributed_fabric_config(
    topology: &DistributedFabricTopologyV1,
    resolver: &dyn RuntimeFabricCredentialResolverV1,
) -> Result<PreparedDistributedFabricConfigV1, DistributedFabricRuntimeError> {
    let loopback =
        SessionEndpoint::try_new(topology.base_loopback_listen_endpoint().as_str().to_owned())
            .map_err(|_| DistributedFabricRuntimeError::FabricConfigurationRejected)?;
    if loopback.as_str() != topology.base_loopback_listen_endpoint().as_str() {
        return Err(DistributedFabricRuntimeError::EndpointMappingMismatch);
    }

    let remote_listen =
        RemoteTlsEndpoint::try_new(topology.remote_listen_endpoint().as_str().to_owned())
            .map_err(|_| DistributedFabricRuntimeError::FabricConfigurationRejected)?;
    if remote_listen.as_str() != topology.remote_listen_endpoint().as_str() {
        return Err(DistributedFabricRuntimeError::EndpointMappingMismatch);
    }

    let mut common_credentials = None;
    let mut connect_endpoints = Vec::with_capacity(topology.peers().len());
    let mut ordered_peer_requirements = Vec::with_capacity(topology.peers().len());
    for peer in topology.peers() {
        let requirement = RuntimeFabricCredentialRequirementV1::from_peer(peer);
        let resolved = resolver.resolve(&requirement)?;
        let (echoed_digest, credential_files) = resolved.into_parts();
        if echoed_digest != requirement.requirement_digest() {
            return Err(DistributedFabricRuntimeError::RequirementDigestMismatch);
        }
        match &common_credentials {
            Some(common) if common != &credential_files => {
                return Err(DistributedFabricRuntimeError::CredentialSetMismatch);
            }
            Some(_) => {}
            None => common_credentials = Some(credential_files),
        }

        let endpoint = RemoteTlsEndpoint::try_new(peer.connect_endpoint().as_str().to_owned())
            .map_err(|_| DistributedFabricRuntimeError::FabricConfigurationRejected)?;
        if endpoint.as_str() != peer.connect_endpoint().as_str() {
            return Err(DistributedFabricRuntimeError::EndpointMappingMismatch);
        }
        connect_endpoints.push(endpoint);
        ordered_peer_requirements.push(requirement);
    }
    let credentials =
        common_credentials.ok_or(DistributedFabricRuntimeError::MissingPeerCredentialResolution)?;
    let config = FabricServiceConfig::try_secured_hybrid_peer(
        loopback,
        remote_listen,
        connect_endpoints,
        credentials,
    )
    .map_err(|_| DistributedFabricRuntimeError::FabricConfigurationRejected)?;

    let mut digest = Digest32Builder::try_new(TOPOLOGY_PREPARATION_DIGEST_DOMAIN)?;
    digest.field_bytes(topology.canonical_wire())?;
    Ok(PreparedDistributedFabricConfigV1 {
        config,
        topology_digest: digest.finish(),
        ordered_peer_requirements: ordered_peer_requirements.into_boxed_slice(),
        experimental_identity_binding_digests: None,
    })
}

fn prepare_distributed_fabric_config_v2(
    topology: &DistributedFabricTopologyV1,
    resolver: &dyn RuntimeFabricCredentialResolverV2,
) -> Result<PreparedDistributedFabricConfigV1, DistributedFabricRuntimeError> {
    let loopback =
        SessionEndpoint::try_new(topology.base_loopback_listen_endpoint().as_str().to_owned())
            .map_err(|_| DistributedFabricRuntimeError::FabricConfigurationRejected)?;
    if loopback.as_str() != topology.base_loopback_listen_endpoint().as_str() {
        return Err(DistributedFabricRuntimeError::EndpointMappingMismatch);
    }

    let remote_listen =
        RemoteTlsEndpoint::try_new(topology.remote_listen_endpoint().as_str().to_owned())
            .map_err(|_| DistributedFabricRuntimeError::FabricConfigurationRejected)?;
    if remote_listen.as_str() != topology.remote_listen_endpoint().as_str() {
        return Err(DistributedFabricRuntimeError::EndpointMappingMismatch);
    }

    let mut common_credentials = None;
    let mut seen_common_names = BTreeSet::new();
    let mut remote_peer_bindings = Vec::with_capacity(topology.peers().len());
    let mut ordered_peer_requirements = Vec::with_capacity(topology.peers().len());
    let mut identity_binding_digests = Vec::with_capacity(topology.peers().len());
    for peer in topology.peers() {
        let requirement = RuntimeFabricCredentialRequirementV1::from_peer(peer);
        let resolved = resolver.resolve(&requirement)?;
        let (
            echoed_digest,
            echoed_identity_ref,
            expected_common_name,
            identity_binding_digest,
            credential_files,
        ) = resolved.into_parts();
        if echoed_digest != requirement.requirement_digest() {
            return Err(DistributedFabricRuntimeError::RequirementDigestMismatch);
        }
        if echoed_identity_ref != requirement.expected_peer_identity_ref() {
            return Err(DistributedFabricRuntimeError::ExpectedPeerIdentityRefMismatch);
        }
        let recomputed_identity_binding_digest = experimental_peer_cn_binding_digest(
            requirement.requirement_digest(),
            requirement.expected_peer_identity_ref(),
            &expected_common_name,
        )?;
        if identity_binding_digest != recomputed_identity_binding_digest {
            return Err(DistributedFabricRuntimeError::IdentityBindingDigestMismatch);
        }
        if !seen_common_names.insert(expected_common_name.clone()) {
            return Err(DistributedFabricRuntimeError::DuplicateExpectedPeerCommonName);
        }
        match &common_credentials {
            Some(common) if common != &credential_files => {
                return Err(DistributedFabricRuntimeError::CredentialSetMismatch);
            }
            Some(_) => {}
            None => common_credentials = Some(credential_files),
        }

        let endpoint = RemoteTlsEndpoint::try_new(peer.connect_endpoint().as_str().to_owned())
            .map_err(|_| DistributedFabricRuntimeError::FabricConfigurationRejected)?;
        if endpoint.as_str() != peer.connect_endpoint().as_str() {
            return Err(DistributedFabricRuntimeError::EndpointMappingMismatch);
        }
        remote_peer_bindings.push(ExperimentalRemoteMtlsPeerBindingV1::new(
            endpoint,
            expected_common_name,
            identity_binding_digest,
        ));
        identity_binding_digests.push(identity_binding_digest);
        ordered_peer_requirements.push(requirement);
    }
    let credentials =
        common_credentials.ok_or(DistributedFabricRuntimeError::MissingPeerCredentialResolution)?;
    let config = FabricServiceConfig::try_experimental_secured_hybrid_peer_with_cn_bindings(
        loopback,
        remote_listen,
        remote_peer_bindings,
        credentials,
    )
    .map_err(|_| DistributedFabricRuntimeError::FabricConfigurationRejected)?;

    let mut digest = Digest32Builder::try_new(TOPOLOGY_PREPARATION_DIGEST_DOMAIN)?;
    digest.field_bytes(topology.canonical_wire())?;
    Ok(PreparedDistributedFabricConfigV1 {
        config,
        topology_digest: digest.finish(),
        ordered_peer_requirements: ordered_peer_requirements.into_boxed_slice(),
        experimental_identity_binding_digests: Some(identity_binding_digests.into_boxed_slice()),
    })
}

enum DistributedFabricGenerationState {
    Prepared {
        service_spec: ManagedServiceSpecV1,
        config: FabricServiceConfig,
    },
    Live {
        assembly: ManagedServiceAssembly,
        control: ManagedFabricControlHandle,
    },
    CleanupUncertain {
        assembly: ManagedServiceAssembly,
        control: ManagedFabricControlHandle,
    },
    Stopped,
    Transitioning,
}

impl DistributedFabricGenerationState {
    const fn label(&self) -> &'static str {
        match self {
            Self::Prepared { .. } => "prepared",
            Self::Live { .. } => "live-local-session",
            Self::CleanupUncertain { .. } => "cleanup-uncertain",
            Self::Stopped => "stopped",
            Self::Transitioning => "transitioning",
        }
    }
}

/// Internal generation-scoped lifecycle input for the future PXAR-v8 owner.
///
/// `try_prepare` resolves and maps the exact active PXDT. `start` consumes that
/// configuration once through the existing managed Fabric implementation, so
/// one generation can own at most one `FabricService` and one Zenoh session.
/// `stop` retires the same generation. No method starts or reinstalls Agent.
pub(crate) struct DistributedFabricRuntimeGeneration {
    generation: ManagedServiceGeneration,
    execution_digest: Digest32,
    topology_digest: Digest32,
    peer_requirement_digests: Box<[Digest32]>,
    experimental_identity_binding_digests: Option<Box<[Digest32]>>,
    state: DistributedFabricGenerationState,
}

impl DistributedFabricRuntimeGeneration {
    pub(crate) fn try_prepare(
        execution: &DistributedAgentStackTargetExecutionV1,
        generation: ManagedServiceGeneration,
        resolver: &dyn RuntimeFabricCredentialResolverV1,
    ) -> Result<Self, DistributedFabricRuntimeError> {
        if execution.mode() != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent {
            return Err(DistributedFabricRuntimeError::ExpectedActiveExecution);
        }
        let topology = execution
            .topology()
            .ok_or(DistributedFabricRuntimeError::MissingTopology)?;
        let service_spec = execution
            .predecessor()
            .fabric()
            .service()
            .ok_or(DistributedFabricRuntimeError::MissingServiceSpec)?;
        let prepared = prepare_distributed_fabric_config(topology, resolver)?;
        let peer_requirement_digests = prepared.peer_requirement_digests();
        Ok(Self {
            generation,
            execution_digest: execution.execution_digest(),
            topology_digest: prepared.topology_digest,
            peer_requirement_digests,
            experimental_identity_binding_digests: prepared.experimental_identity_binding_digests,
            state: DistributedFabricGenerationState::Prepared {
                service_spec,
                config: prepared.config,
            },
        })
    }

    /// Prepares the strict experimental V2 CN-binding path without V1 fallback.
    pub(crate) fn try_prepare_experimental_cn_v2(
        execution: &DistributedAgentStackTargetExecutionV1,
        generation: ManagedServiceGeneration,
        resolver: &dyn RuntimeFabricCredentialResolverV2,
    ) -> Result<Self, DistributedFabricRuntimeError> {
        if execution.mode() != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent {
            return Err(DistributedFabricRuntimeError::ExpectedActiveExecution);
        }
        let topology = execution
            .topology()
            .ok_or(DistributedFabricRuntimeError::MissingTopology)?;
        let service_spec = execution
            .predecessor()
            .fabric()
            .service()
            .ok_or(DistributedFabricRuntimeError::MissingServiceSpec)?;
        let prepared = prepare_distributed_fabric_config_v2(topology, resolver)?;
        let peer_requirement_digests = prepared.peer_requirement_digests();
        Ok(Self {
            generation,
            execution_digest: execution.execution_digest(),
            topology_digest: prepared.topology_digest,
            peer_requirement_digests,
            experimental_identity_binding_digests: prepared.experimental_identity_binding_digests,
            state: DistributedFabricGenerationState::Prepared {
                service_spec,
                config: prepared.config,
            },
        })
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> ManagedServiceGeneration {
        self.generation
    }

    #[must_use]
    pub(crate) const fn execution_digest(&self) -> Digest32 {
        self.execution_digest
    }

    #[must_use]
    pub(crate) const fn topology_digest(&self) -> Digest32 {
        self.topology_digest
    }

    #[must_use]
    pub(crate) fn peer_requirement_digests(&self) -> &[Digest32] {
        &self.peer_requirement_digests
    }

    /// Returns V2 identity-binding digests in canonical PXDT peer order.
    #[must_use]
    pub(crate) fn experimental_identity_binding_digests(&self) -> Option<&[Digest32]> {
        self.experimental_identity_binding_digests.as_deref()
    }

    /// Starts the one local Fabric session for this exact generation.
    ///
    /// Ready means only that `FabricService::start` returned and the local
    /// owner slot is live. It does not mean that a remote TLS peer connected.
    pub(crate) async fn start(
        &mut self,
        expected_generation: ManagedServiceGeneration,
        clock: RuntimeClock,
        cancellation: &CancellationSource,
    ) -> Result<ManagedFabricControlHandle, DistributedFabricRuntimeError> {
        self.require_generation(expected_generation)?;
        let state = core::mem::replace(
            &mut self.state,
            DistributedFabricGenerationState::Transitioning,
        );
        let DistributedFabricGenerationState::Prepared {
            service_spec,
            config,
        } = state
        else {
            self.state = state;
            return Err(DistributedFabricRuntimeError::InvalidLifecycleState);
        };

        let (implementation, control) =
            RuntimeManagedFabricService::from_exact_config(config, self.generation);
        let mut assembly = ManagedServiceAssembly::new(
            service_spec,
            self.generation,
            Box::new(implementation),
            clock,
            cancellation,
        );
        if assembly.startup().await == ManagedServiceStartupOutcome::Ready {
            self.state = DistributedFabricGenerationState::Live {
                assembly,
                control: control.clone(),
            };
            return Ok(control);
        }

        let cleanup = assembly.shutdown().await;
        if cleanup.exact_zero() {
            self.state = DistributedFabricGenerationState::Stopped;
            Err(DistributedFabricRuntimeError::StartFailed)
        } else {
            self.state = DistributedFabricGenerationState::CleanupUncertain { assembly, control };
            Err(DistributedFabricRuntimeError::CleanupUncertain)
        }
    }

    /// Returns the exact live generation fence without exposing raw Zenoh.
    pub(crate) fn live_control(
        &self,
        expected_generation: ManagedServiceGeneration,
    ) -> Result<ManagedFabricControlHandle, DistributedFabricRuntimeError> {
        self.require_generation(expected_generation)?;
        match &self.state {
            DistributedFabricGenerationState::Live { control, .. } => Ok(control.clone()),
            DistributedFabricGenerationState::Prepared { .. } => {
                Err(DistributedFabricRuntimeError::NotStarted)
            }
            DistributedFabricGenerationState::CleanupUncertain { .. }
            | DistributedFabricGenerationState::Stopped => {
                Err(DistributedFabricRuntimeError::OwnerRetired)
            }
            DistributedFabricGenerationState::Transitioning => {
                Err(DistributedFabricRuntimeError::InvalidLifecycleState)
            }
        }
    }

    /// Stops or drops the exact generation. Repeating stop after exact cleanup
    /// is idempotent; a different generation never reaches the owner slot.
    pub(crate) async fn stop(
        &mut self,
        expected_generation: ManagedServiceGeneration,
    ) -> Result<(), DistributedFabricRuntimeError> {
        self.require_generation(expected_generation)?;
        let state = core::mem::replace(
            &mut self.state,
            DistributedFabricGenerationState::Transitioning,
        );
        match state {
            DistributedFabricGenerationState::Prepared { .. } => {
                self.state = DistributedFabricGenerationState::Stopped;
                Ok(())
            }
            DistributedFabricGenerationState::Live {
                mut assembly,
                control,
            } => {
                if assembly.shutdown().await.exact_zero() {
                    self.state = DistributedFabricGenerationState::Stopped;
                    Ok(())
                } else {
                    self.state =
                        DistributedFabricGenerationState::CleanupUncertain { assembly, control };
                    Err(DistributedFabricRuntimeError::CleanupUncertain)
                }
            }
            DistributedFabricGenerationState::CleanupUncertain { assembly, control } => {
                self.state =
                    DistributedFabricGenerationState::CleanupUncertain { assembly, control };
                Err(DistributedFabricRuntimeError::CleanupUncertain)
            }
            DistributedFabricGenerationState::Stopped => {
                self.state = DistributedFabricGenerationState::Stopped;
                Ok(())
            }
            DistributedFabricGenerationState::Transitioning => {
                self.state = DistributedFabricGenerationState::Transitioning;
                Err(DistributedFabricRuntimeError::InvalidLifecycleState)
            }
        }
    }

    fn require_generation(
        &self,
        expected_generation: ManagedServiceGeneration,
    ) -> Result<(), DistributedFabricRuntimeError> {
        if expected_generation == self.generation {
            Ok(())
        } else {
            Err(DistributedFabricRuntimeError::GenerationFenced)
        }
    }
}

impl fmt::Debug for DistributedFabricRuntimeGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributedFabricRuntimeGeneration")
            .field("generation", &self.generation)
            .field("execution_digest", &self.execution_digest)
            .field("topology_digest", &self.topology_digest)
            .field("peer_count", &self.peer_requirement_digests.len())
            .field(
                "experimental_identity_binding_count",
                &self
                    .experimental_identity_binding_digests
                    .as_deref()
                    .map_or(0, <[Digest32]>::len),
            )
            .field("state", &self.state.label())
            .finish()
    }
}

/// Stable internal failures for exact PXDT preparation and lifecycle handoff.
#[derive(Debug)]
pub(crate) enum DistributedFabricRuntimeError {
    ExpectedActiveExecution,
    MissingTopology,
    MissingServiceSpec,
    MissingPeerCredentialResolution,
    RequirementDigestMismatch,
    ExpectedPeerIdentityRefMismatch,
    IdentityBindingDigestMismatch,
    DuplicateExpectedPeerCommonName,
    CredentialSetMismatch,
    EndpointMappingMismatch,
    FabricConfigurationRejected,
    GenerationFenced,
    NotStarted,
    OwnerRetired,
    InvalidLifecycleState,
    StartFailed,
    CleanupUncertain,
    CredentialResolution(RuntimeFabricCredentialResolveError),
    CredentialResolutionV2(RuntimeFabricCredentialResolveErrorV2),
    Digest(DigestBuildError),
}

impl fmt::Display for DistributedFabricRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExpectedActiveExecution => "distributed Fabric requires active PXTE-v7",
            Self::MissingTopology => "active distributed Fabric execution has no PXDT",
            Self::MissingServiceSpec => "active distributed Fabric predecessor has no service spec",
            Self::MissingPeerCredentialResolution => {
                "distributed Fabric has no resolved peer credential set"
            }
            Self::RequirementDigestMismatch => "credential resolver requirement digest mismatch",
            Self::ExpectedPeerIdentityRefMismatch => {
                "credential resolver expected peer-identity reference mismatch"
            }
            Self::IdentityBindingDigestMismatch => {
                "credential resolver experimental CN-binding digest mismatch"
            }
            Self::DuplicateExpectedPeerCommonName => {
                "distributed Fabric resolved duplicate experimental peer CNs"
            }
            Self::CredentialSetMismatch => {
                "single distributed Fabric session resolved inconsistent credential files"
            }
            Self::EndpointMappingMismatch => "distributed Fabric endpoint mapping mismatch",
            Self::FabricConfigurationRejected => "distributed Fabric configuration rejected",
            Self::GenerationFenced => "distributed Fabric generation fenced",
            Self::NotStarted => "distributed Fabric generation is not started",
            Self::OwnerRetired => "distributed Fabric generation owner retired",
            Self::InvalidLifecycleState => "invalid distributed Fabric lifecycle state",
            Self::StartFailed => "distributed Fabric local session start failed",
            Self::CleanupUncertain => "distributed Fabric cleanup is uncertain",
            Self::CredentialResolution(_) => "distributed Fabric credential resolution failed",
            Self::CredentialResolutionV2(_) => "distributed Fabric V2 credential resolution failed",
            Self::Digest(_) => "distributed Fabric preparation digest failed",
        })
    }
}

impl std::error::Error for DistributedFabricRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CredentialResolution(error) => Some(error),
            Self::CredentialResolutionV2(error) => Some(error),
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RuntimeFabricCredentialResolveError> for DistributedFabricRuntimeError {
    fn from(value: RuntimeFabricCredentialResolveError) -> Self {
        Self::CredentialResolution(value)
    }
}

impl From<RuntimeFabricCredentialResolveErrorV2> for DistributedFabricRuntimeError {
    fn from(value: RuntimeFabricCredentialResolveErrorV2) -> Self {
        Self::CredentialResolutionV2(value)
    }
}

impl From<DigestBuildError> for DistributedFabricRuntimeError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use paraegox_fabric::{ResolvedRemoteMtlsCredentialFiles, ResolvedRemoteMtlsIdentityFiles};
    use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        DistributedAgentStackProjectionV1, DistributedFabricPeerAuthenticationRequirementV1,
        DistributedFabricPeerPlanV1, DistributedFabricTlsEndpointV1, DistributedFabricTopologyV1,
    };
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentStackProjectionV1, ManagedAgentStackTargetExecutionV1,
    };
    use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;

    use super::*;

    const STACK_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_agent_stack_successor_v1.json");

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("fixture contains non-hex byte"),
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn stack_fixture_hex_after(section: &str, key: &str) -> Vec<u8> {
        let section_start = STACK_FIXTURE
            .find(section)
            .unwrap_or_else(|| panic!("missing fixture section {section}"));
        let key_start = STACK_FIXTURE[section_start..]
            .find(key)
            .map(|offset| section_start + offset + key.len())
            .unwrap_or_else(|| panic!("missing fixture key {key}"));
        let quote_start = STACK_FIXTURE[key_start..]
            .find('"')
            .map(|offset| key_start + offset + 1)
            .unwrap_or_else(|| panic!("missing fixture value for {key}"));
        let quote_end = STACK_FIXTURE[quote_start..]
            .find('"')
            .map(|offset| quote_start + offset)
            .unwrap_or_else(|| panic!("unterminated fixture value for {key}"));
        decode_hex(&STACK_FIXTURE[quote_start..quote_end])
    }

    fn predecessor_execution() -> ManagedAgentStackTargetExecutionV1 {
        ManagedAgentStackTargetExecutionV1::decode(&stack_fixture_hex_after(
            "\"fabric_and_agent\"",
            "\"pxte_v6_hex\"",
        ))
        .expect("fixed-stack predecessor must decode")
    }

    fn projection() -> DistributedAgentStackProjectionV1 {
        let predecessor_projection = ManagedAgentStackProjectionV1::decode(
            &stack_fixture_hex_after("\"expected\"", "\"projection_pxsp_hex\""),
        )
        .expect("fixed-stack projection must decode");
        DistributedAgentStackProjectionV1::try_from_managed_agent_stack_projection(
            predecessor_projection,
        )
        .expect("distributed projection must build")
    }

    fn authentication(
        expected_peer_identity: u8,
    ) -> DistributedFabricPeerAuthenticationRequirementV1 {
        DistributedFabricPeerAuthenticationRequirementV1::try_mutual_tls(
            DistributedFabricTrustDomainRefV1::try_from_bytes([0x91; 16]).expect("trust domain"),
            DistributedFabricCredentialRefV1::try_from_bytes([0x92; 16]).expect("local credential"),
            DistributedFabricTrustAnchorRefV1::try_from_bytes([0x93; 16]).expect("trust anchor"),
            DistributedFabricPeerIdentityRefV1::try_from_bytes([expected_peer_identity; 16])
                .expect("peer identity"),
        )
        .expect("mTLS requirement")
    }

    fn topology() -> DistributedFabricTopologyV1 {
        let predecessor = predecessor_execution();
        let peers = [
            (0x81, "tls/192.0.2.11:7447", 0xa1),
            (0x82, "tls/192.0.2.12:7447", 0xa2),
        ]
        .into_iter()
        .map(|(host, endpoint, identity)| {
            DistributedFabricPeerPlanV1::try_new(
                RuntimeHostId::from_bytes([host; 16]),
                DistributedFabricTlsEndpointV1::try_new(endpoint).expect("peer endpoint"),
                authentication(identity),
            )
            .expect("peer plan")
        })
        .collect();
        DistributedFabricTopologyV1::try_new(
            projection().target(),
            predecessor
                .fabric()
                .listen_endpoint()
                .expect("predecessor loopback")
                .clone(),
            DistributedFabricTlsEndpointV1::try_new("tls/192.0.2.10:7447")
                .expect("remote listener"),
            peers,
        )
        .expect("topology")
    }

    fn execution() -> DistributedAgentStackTargetExecutionV1 {
        DistributedAgentStackTargetExecutionV1::try_distributed_fabric_and_agent(
            projection(),
            predecessor_execution(),
            topology(),
        )
        .expect("active execution")
    }

    fn credential_files(marker: &str) -> ResolvedRemoteMtlsCredentialFiles {
        let identity = |role: &str| {
            ResolvedRemoteMtlsIdentityFiles::try_new(
                PathBuf::from(format!(
                    "/private/paraegox-secrets/{marker}-{role}-certificate.pem"
                )),
                PathBuf::from(format!(
                    "/private/paraegox-secrets/{marker}-{role}-private-key.pem"
                )),
            )
            .expect("absolute normalized identity paths")
        };
        ResolvedRemoteMtlsCredentialFiles::try_new(
            PathBuf::from(format!("/private/paraegox-secrets/{marker}-root-ca.pem")),
            identity("listen"),
            identity("connect"),
        )
        .expect("absolute normalized credential paths")
    }

    struct RecordingResolver {
        seen: Mutex<Vec<RuntimeFabricCredentialRequirementV1>>,
        digest_override: Option<Digest32>,
        vary_files: bool,
    }

    impl RecordingResolver {
        fn echo() -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                digest_override: None,
                vary_files: false,
            }
        }
    }

    impl RuntimeFabricCredentialResolverV1 for RecordingResolver {
        fn resolve(
            &self,
            requirement: &RuntimeFabricCredentialRequirementV1,
        ) -> Result<RuntimeResolvedFabricCredentialFilesV1, RuntimeFabricCredentialResolveError>
        {
            self.seen
                .lock()
                .expect("recording resolver lock")
                .push(requirement.clone());
            let digest = self
                .digest_override
                .unwrap_or_else(|| requirement.requirement_digest());
            let marker = if self.vary_files {
                format!("peer-{}", requirement.peer_runtime_host().as_bytes()[0])
            } else {
                "shared".to_owned()
            };
            Ok(RuntimeResolvedFabricCredentialFilesV1::new(
                digest,
                credential_files(&marker),
            ))
        }
    }

    struct RecordingResolverV2 {
        seen: Mutex<Vec<RuntimeFabricCredentialRequirementV1>>,
        digest_override: Option<Digest32>,
        identity_ref_override: Option<DistributedFabricPeerIdentityRefV1>,
        duplicate_common_name: bool,
        vary_files: bool,
    }

    impl RecordingResolverV2 {
        fn echo() -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                digest_override: None,
                identity_ref_override: None,
                duplicate_common_name: false,
                vary_files: false,
            }
        }
    }

    impl RuntimeFabricCredentialResolverV2 for RecordingResolverV2 {
        fn resolve(
            &self,
            requirement: &RuntimeFabricCredentialRequirementV1,
        ) -> Result<RuntimeResolvedFabricPeerCredentialV2, RuntimeFabricCredentialResolveErrorV2>
        {
            self.seen
                .lock()
                .expect("recording resolver lock")
                .push(requirement.clone());
            let digest = self
                .digest_override
                .unwrap_or_else(|| requirement.requirement_digest());
            let identity_ref = self
                .identity_ref_override
                .unwrap_or_else(|| requirement.expected_peer_identity_ref());
            let host_marker = requirement.peer_runtime_host().as_bytes()[0];
            let common_name = if self.duplicate_common_name {
                "peer-shared".to_owned()
            } else {
                format!("peer-{host_marker:02x}")
            };
            let file_marker = if self.vary_files {
                format!("peer-{host_marker:02x}")
            } else {
                "shared".to_owned()
            };
            RuntimeResolvedFabricPeerCredentialV2::try_new(
                digest,
                identity_ref,
                common_name,
                credential_files(&file_marker),
            )
        }
    }

    fn generation(value: u64) -> ManagedServiceGeneration {
        ManagedServiceGeneration::try_new(value).expect("nonzero generation")
    }

    #[test]
    fn resolver_must_echo_each_complete_requirement_digest() {
        let resolver = RecordingResolver {
            seen: Mutex::new(Vec::new()),
            digest_override: Some(Digest32::from_bytes([0xff; 32])),
            vary_files: false,
        };
        assert!(matches!(
            DistributedFabricRuntimeGeneration::try_prepare(&execution(), generation(7), &resolver,),
            Err(DistributedFabricRuntimeError::RequirementDigestMismatch)
        ));
        assert_eq!(
            resolver.seen.lock().expect("recording resolver lock").len(),
            1,
            "the first mismatched echo must fail before any later resolution"
        );
    }

    #[test]
    fn mapping_preserves_canonical_peer_order_and_one_common_credential_set() {
        let resolver = RecordingResolver::echo();
        let execution = execution();
        let prepared =
            DistributedFabricRuntimeGeneration::try_prepare(&execution, generation(7), &resolver)
                .expect("exact topology must prepare");
        let seen = resolver.seen.lock().expect("recording resolver lock");
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].peer_runtime_host().as_bytes(), &[0x81; 16]);
        assert_eq!(seen[0].connect_endpoint().as_str(), "tls/192.0.2.11:7447");
        assert_eq!(seen[1].peer_runtime_host().as_bytes(), &[0x82; 16]);
        assert_eq!(seen[1].connect_endpoint().as_str(), "tls/192.0.2.12:7447");
        assert_eq!(
            prepared.peer_requirement_digests(),
            execution
                .topology()
                .expect("active topology")
                .peers()
                .iter()
                .map(DistributedFabricPeerPlanV1::requirement_digest)
                .collect::<Vec<_>>()
        );
        assert_eq!(prepared.generation(), generation(7));
        assert_eq!(prepared.execution_digest(), execution.execution_digest());
        assert_ne!(prepared.topology_digest(), Digest32::from_bytes([0; 32]));
        assert_eq!(prepared.experimental_identity_binding_digests(), None);
    }

    #[test]
    fn v2_binds_each_identity_ref_to_one_unique_canonical_cn() {
        let resolver = RecordingResolverV2::echo();
        let execution = execution();
        let prepared = DistributedFabricRuntimeGeneration::try_prepare_experimental_cn_v2(
            &execution,
            generation(7),
            &resolver,
        )
        .expect("strict V2 topology must prepare");
        let seen = resolver.seen.lock().expect("recording resolver lock");
        assert_eq!(seen.len(), 2);
        let binding_digests = prepared
            .experimental_identity_binding_digests()
            .expect("V2 must retain exact binding digests");
        assert_eq!(binding_digests.len(), 2);
        assert_ne!(binding_digests[0], binding_digests[1]);
        for (index, requirement) in seen.iter().enumerate() {
            let common_name = ExperimentalPeerCommonNameV1::try_new(format!(
                "peer-{:02x}",
                requirement.peer_runtime_host().as_bytes()[0]
            ))
            .unwrap();
            assert_eq!(
                binding_digests[index],
                experimental_peer_cn_binding_digest(
                    requirement.requirement_digest(),
                    requirement.expected_peer_identity_ref(),
                    &common_name,
                )
                .unwrap()
            );
        }
        let debug = format!("{prepared:?}");
        assert!(debug.contains("experimental_identity_binding_count: 2"));
        assert!(!debug.contains("peer-81"));
        assert!(!debug.contains("/private/paraegox-secrets"));
    }

    #[test]
    fn v2_rejects_identity_ref_drift_without_v1_fallback() {
        let resolver = RecordingResolverV2 {
            seen: Mutex::new(Vec::new()),
            digest_override: None,
            identity_ref_override: Some(
                DistributedFabricPeerIdentityRefV1::try_from_bytes([0xee; 16])
                    .expect("nonzero peer identity"),
            ),
            duplicate_common_name: false,
            vary_files: false,
        };
        assert!(matches!(
            DistributedFabricRuntimeGeneration::try_prepare_experimental_cn_v2(
                &execution(),
                generation(7),
                &resolver,
            ),
            Err(DistributedFabricRuntimeError::ExpectedPeerIdentityRefMismatch)
        ));
        assert_eq!(
            resolver.seen.lock().expect("recording resolver lock").len(),
            1,
            "V2 must fail on the first drifted row instead of consulting another path"
        );
    }

    #[test]
    fn v2_rejects_requirement_digest_drift_before_later_peer_resolution() {
        let resolver = RecordingResolverV2 {
            seen: Mutex::new(Vec::new()),
            digest_override: Some(Digest32::from_bytes([0xfe; 32])),
            identity_ref_override: None,
            duplicate_common_name: false,
            vary_files: false,
        };
        assert!(matches!(
            DistributedFabricRuntimeGeneration::try_prepare_experimental_cn_v2(
                &execution(),
                generation(7),
                &resolver,
            ),
            Err(DistributedFabricRuntimeError::RequirementDigestMismatch)
        ));
        assert_eq!(
            resolver.seen.lock().expect("recording resolver lock").len(),
            1
        );
    }

    #[test]
    fn v2_rejects_duplicate_cn_and_cross_peer_file_drift() {
        let duplicate_cn = RecordingResolverV2 {
            seen: Mutex::new(Vec::new()),
            digest_override: None,
            identity_ref_override: None,
            duplicate_common_name: true,
            vary_files: false,
        };
        assert!(matches!(
            DistributedFabricRuntimeGeneration::try_prepare_experimental_cn_v2(
                &execution(),
                generation(7),
                &duplicate_cn,
            ),
            Err(DistributedFabricRuntimeError::DuplicateExpectedPeerCommonName)
        ));

        let drifted_files = RecordingResolverV2 {
            seen: Mutex::new(Vec::new()),
            digest_override: None,
            identity_ref_override: None,
            duplicate_common_name: false,
            vary_files: true,
        };
        assert!(matches!(
            DistributedFabricRuntimeGeneration::try_prepare_experimental_cn_v2(
                &execution(),
                generation(7),
                &drifted_files,
            ),
            Err(DistributedFabricRuntimeError::CredentialSetMismatch)
        ));
    }

    #[test]
    fn v2_result_rejects_invalid_cn_and_redacts_valid_cn_and_paths() {
        let requirement = RuntimeFabricCredentialRequirementV1::from_peer(&topology().peers()[0]);
        for invalid in ["", "Peer-A", "peer_a", "peer a", "peer\n"] {
            assert_eq!(
                RuntimeResolvedFabricPeerCredentialV2::try_new(
                    requirement.requirement_digest(),
                    requirement.expected_peer_identity_ref(),
                    invalid,
                    credential_files("do-not-log"),
                ),
                Err(RuntimeFabricCredentialResolveErrorV2::InvalidExpectedPeerCommonName)
            );
        }
        let resolved = RuntimeResolvedFabricPeerCredentialV2::try_new(
            requirement.requirement_digest(),
            requirement.expected_peer_identity_ref(),
            "peer-private",
            credential_files("do-not-log"),
        )
        .unwrap();
        let debug = format!("{resolved:?}");
        assert!(!debug.contains("peer-private"));
        assert!(!debug.contains("do-not-log"));
        assert!(!debug.contains("/private/paraegox-secrets"));
    }

    #[test]
    fn v2_identity_binding_digest_changes_with_cn_or_identity_ref() {
        let requirement = RuntimeFabricCredentialRequirementV1::from_peer(&topology().peers()[0]);
        let peer_a = ExperimentalPeerCommonNameV1::try_new("peer-a").unwrap();
        let peer_b = ExperimentalPeerCommonNameV1::try_new("peer-b").unwrap();
        let first = experimental_peer_cn_binding_digest(
            requirement.requirement_digest(),
            requirement.expected_peer_identity_ref(),
            &peer_a,
        )
        .unwrap();
        let different_cn = experimental_peer_cn_binding_digest(
            requirement.requirement_digest(),
            requirement.expected_peer_identity_ref(),
            &peer_b,
        )
        .unwrap();
        let different_ref = experimental_peer_cn_binding_digest(
            requirement.requirement_digest(),
            DistributedFabricPeerIdentityRefV1::try_from_bytes([0xef; 16])
                .expect("nonzero peer identity"),
            &peer_a,
        )
        .unwrap();
        assert_ne!(first, different_cn);
        assert_ne!(first, different_ref);
    }

    #[test]
    fn one_session_rejects_resolver_file_drift_between_peer_rows() {
        let resolver = RecordingResolver {
            seen: Mutex::new(Vec::new()),
            digest_override: None,
            vary_files: true,
        };
        assert!(matches!(
            DistributedFabricRuntimeGeneration::try_prepare(&execution(), generation(7), &resolver,),
            Err(DistributedFabricRuntimeError::CredentialSetMismatch)
        ));
    }

    #[test]
    fn resolved_and_prepared_debug_never_disclose_file_paths() {
        let files = credential_files("do-not-log");
        let resolved =
            RuntimeResolvedFabricCredentialFilesV1::new(Digest32::from_bytes([0x71; 32]), files);
        let debug = format!("{resolved:?}");
        assert!(!debug.contains("do-not-log"));
        assert!(!debug.contains("/private/paraegox-secrets"));

        let resolver = RecordingResolver::echo();
        let prepared = prepare_distributed_fabric_config(&topology(), &resolver)
            .expect("exact topology must map");
        let debug = format!("{prepared:?}");
        assert!(debug.contains("secured-hybrid-mtls"));
        assert!(!debug.contains("/private/paraegox-secrets"));
        assert!(!debug.contains("private-key"));
    }

    #[tokio::test]
    async fn generation_fence_and_single_consumed_start_config_fail_closed() {
        let resolver = RecordingResolver::echo();
        let mut runtime =
            DistributedFabricRuntimeGeneration::try_prepare(&execution(), generation(7), &resolver)
                .expect("exact topology must prepare once");
        assert!(matches!(
            runtime.live_control(generation(8)),
            Err(DistributedFabricRuntimeError::GenerationFenced)
        ));
        assert!(matches!(
            runtime.live_control(generation(7)),
            Err(DistributedFabricRuntimeError::NotStarted)
        ));

        let clock = RuntimeClock::new(
            ClockDomainRef::from_bytes([0x61; 16]),
            ClockGeneration::try_new(1).expect("clock generation"),
            0,
        );
        let cancellation = CancellationSource::root();
        assert!(matches!(
            runtime.start(generation(7), clock, &cancellation).await,
            Err(DistributedFabricRuntimeError::StartFailed)
                | Err(DistributedFabricRuntimeError::CleanupUncertain)
        ));
        assert!(matches!(
            runtime.start(generation(7), clock, &cancellation).await,
            Err(DistributedFabricRuntimeError::InvalidLifecycleState)
        ));
        assert!(matches!(
            runtime.live_control(generation(7)),
            Err(DistributedFabricRuntimeError::OwnerRetired)
        ));
    }

    #[test]
    fn resolver_requirement_exposes_every_exact_non_secret_field() {
        let topology = topology();
        let peer = &topology.peers()[0];
        let requirement = RuntimeFabricCredentialRequirementV1::from_peer(peer);
        assert_eq!(requirement.peer_runtime_host(), peer.peer_runtime_host());
        assert_eq!(requirement.connect_endpoint(), peer.connect_endpoint());
        assert_eq!(
            requirement.profile(),
            DistributedFabricAuthenticationProfileV1::MutualTlsPeerIdentity
        );
        assert_eq!(
            requirement.trust_domain_ref(),
            peer.authentication().trust_domain_ref()
        );
        assert_eq!(
            requirement.local_credential_ref(),
            peer.authentication().local_credential_ref()
        );
        assert_eq!(
            requirement.trust_anchor_ref(),
            peer.authentication().trust_anchor_ref()
        );
        assert_eq!(
            requirement.expected_peer_identity_ref(),
            peer.authentication().expected_peer_identity_ref()
        );
        assert_eq!(requirement.requirement_digest(), peer.requirement_digest());
    }

    #[test]
    fn prepared_generation_can_stop_before_any_session_effect() {
        let resolver = RecordingResolver::echo();
        let mut runtime =
            DistributedFabricRuntimeGeneration::try_prepare(&execution(), generation(9), &resolver)
                .expect("exact topology must prepare");
        let reactor = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test reactor");
        reactor
            .block_on(runtime.stop(generation(9)))
            .expect("prepared stop has exact zero effects");
        reactor
            .block_on(runtime.stop(generation(9)))
            .expect("exact stopped generation is idempotent");
    }
}
