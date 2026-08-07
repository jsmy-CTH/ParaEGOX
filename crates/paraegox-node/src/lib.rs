//! Node-owned identity, observed-status, and read-only management contracts.
//!
//! This crate deliberately does not accept a Runtime apply request. A
//! [`NodeDaemonV1`] owns one Node publication incarnation and publishes bounded
//! observed facts plus Runtime endpoint discovery. Deployment remains the
//! owner of [`NodeSpecV1`], while each target RuntimeHost remains the owner of
//! its apply endpoint and admission decisions.

use core::{fmt, num::NonZeroU64};
use std::collections::{BTreeMap, BTreeSet};

use paraegox_kernel::{
    digest::{Digest32, Digest32Builder, DigestBuildError},
    identity::{PrincipalRef, RuntimeHostId},
};

/// Maximum RuntimeHost identities retained as fences by one first-version
/// NodeDaemon tenure, and therefore the maximum in one NodeStatus.
pub const MAX_RUNTIME_HOSTS_PER_NODE: usize = 8;
/// Maximum bounded relative freshness carried by one observed status.
pub const MAX_NODE_STATUS_FRESHNESS_NANOS: u64 = 60_000_000_000;
/// Exact Node management protocol version.
pub const NODE_MANAGEMENT_PROTOCOL_VERSION: u16 = 1;

/// Authenticated Runtime PXQR/PXQS observation adapter and PXOB/PXNO protocol.
#[cfg(unix)]
pub mod observation;
/// Non-production same-user NodeDaemon process and PXNB bootstrap reference.
#[cfg(unix)]
pub mod process;
/// Strict transport-neutral read-only Node management protocol.
pub mod protocol;
/// Owner-private Unix persistence for one current NodeDaemon tenure.
#[cfg(unix)]
pub mod store;

const IDENTITY_DIGEST_DOMAIN: &[u8] = b"paraegox.node.identity.v1";
const SPEC_DIGEST_DOMAIN: &[u8] = b"paraegox.node.spec.v1";
const FEATURE_DIGEST_DOMAIN: &[u8] = b"paraegox.node.feature-report.v1";
const ENDPOINT_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.apply-endpoint.v1";
const RUNTIME_STATUS_DIGEST_DOMAIN: &[u8] = b"paraegox.node.runtime-host-status.v1";
const STATUS_DIGEST_DOMAIN: &[u8] = b"paraegox.node.status.v1";

macro_rules! opaque_id {
    ($name:ident, $error:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Constructs a nonzero owner-scoped identity.
            pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, NodeContractError> {
                let mut index = 0;
                while index < bytes.len() {
                    if bytes[index] != 0 {
                        return Ok(Self(bytes));
                    }
                    index += 1;
                }
                Err(NodeContractError::$error)
            }

            /// Returns the canonical identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_id!(NodeId, ZeroNodeId);
opaque_id!(NodeIncarnation, ZeroNodeIncarnation);
opaque_id!(EnrollmentIssuerRefV1, ZeroEnrollmentIssuerRef);
opaque_id!(NodeManagementEndpointRefV1, ZeroManagementEndpointRef);
opaque_id!(RuntimeApplyEndpointRefV1, ZeroRuntimeEndpointRef);

/// Stable enrollment-owned Node identity. It contains no address or liveness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeIdentityV1 {
    node_id: NodeId,
    principal: PrincipalRef,
    enrollment_issuer: EnrollmentIssuerRefV1,
    identity_digest: Digest32,
}

impl NodeIdentityV1 {
    /// Builds the stable identity and its domain-separated commitment.
    pub fn try_new(
        node_id: NodeId,
        principal: PrincipalRef,
        enrollment_issuer: EnrollmentIssuerRefV1,
    ) -> Result<Self, NodeContractError> {
        if bytes_are_zero(principal.as_bytes()) {
            return Err(NodeContractError::ZeroPrincipalRef);
        }
        let identity_digest = digest_fields(
            IDENTITY_DIGEST_DOMAIN,
            &[
                node_id.as_bytes(),
                principal.as_bytes(),
                enrollment_issuer.as_bytes(),
            ],
        )?;
        Ok(Self {
            node_id,
            principal,
            enrollment_issuer,
            identity_digest,
        })
    }

    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub const fn principal(self) -> PrincipalRef {
        self.principal
    }

    #[must_use]
    pub const fn enrollment_issuer(self) -> EnrollmentIssuerRefV1 {
        self.enrollment_issuer
    }

    #[must_use]
    pub const fn identity_digest(self) -> Digest32 {
        self.identity_digest
    }
}

/// Deployment-owned desired facts for one Node.
///
/// Labels and platform constraints are represented by exact externally-owned
/// canonical digests here. This value contains no observed heartbeat, endpoint,
/// capacity, process, or readiness state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeSpecV1 {
    node_id: NodeId,
    deployment_revision: NonZeroU64,
    allowed_profile_digest: Digest32,
    scheduling_constraints_digest: Digest32,
    spec_digest: Digest32,
}

impl NodeSpecV1 {
    pub fn try_new(
        node_id: NodeId,
        deployment_revision: u64,
        allowed_profile_digest: Digest32,
        scheduling_constraints_digest: Digest32,
    ) -> Result<Self, NodeContractError> {
        let deployment_revision = NonZeroU64::new(deployment_revision)
            .ok_or(NodeContractError::ZeroDeploymentRevision)?;
        reject_zero_digest(allowed_profile_digest)?;
        reject_zero_digest(scheduling_constraints_digest)?;
        let revision = deployment_revision.get().to_be_bytes();
        let spec_digest = digest_fields(
            SPEC_DIGEST_DOMAIN,
            &[
                node_id.as_bytes(),
                &revision,
                allowed_profile_digest.as_bytes(),
                scheduling_constraints_digest.as_bytes(),
            ],
        )?;
        Ok(Self {
            node_id,
            deployment_revision,
            allowed_profile_digest,
            scheduling_constraints_digest,
            spec_digest,
        })
    }

    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub const fn deployment_revision(self) -> u64 {
        self.deployment_revision.get()
    }

    #[must_use]
    pub const fn allowed_profile_digest(self) -> Digest32 {
        self.allowed_profile_digest
    }

    #[must_use]
    pub const fn scheduling_constraints_digest(self) -> Digest32 {
        self.scheduling_constraints_digest
    }

    #[must_use]
    pub const fn spec_digest(self) -> Digest32 {
        self.spec_digest
    }
}

/// Platform reported by the NodeDaemon after owner-specific verification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NodeOperatingSystemV1 {
    Linux = 1,
    MacOs = 2,
    Windows = 3,
}

/// Machine architecture reported by the NodeDaemon.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NodeArchitectureV1 {
    X86_64 = 1,
    Aarch64 = 2,
}

/// Bounded observed feature report. It is not a CapabilityGrant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeFeatureReportV1 {
    node_id: NodeId,
    node_incarnation: NodeIncarnation,
    report_sequence: NonZeroU64,
    operating_system: NodeOperatingSystemV1,
    architecture: NodeArchitectureV1,
    platform_profile_digest: Digest32,
    runtime_contract_version: u16,
    fabric_contract_version: u16,
    report_digest: Digest32,
}

/// Inputs kept grouped so a producer cannot accidentally reorder report facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeFeatureReportInputV1 {
    pub node_id: NodeId,
    pub node_incarnation: NodeIncarnation,
    pub report_sequence: u64,
    pub operating_system: NodeOperatingSystemV1,
    pub architecture: NodeArchitectureV1,
    pub platform_profile_digest: Digest32,
    pub runtime_contract_version: u16,
    pub fabric_contract_version: u16,
}

impl NodeFeatureReportV1 {
    pub fn try_new(input: NodeFeatureReportInputV1) -> Result<Self, NodeContractError> {
        let report_sequence =
            NonZeroU64::new(input.report_sequence).ok_or(NodeContractError::ZeroFeatureSequence)?;
        reject_zero_digest(input.platform_profile_digest)?;
        if input.runtime_contract_version == 0 || input.fabric_contract_version == 0 {
            return Err(NodeContractError::ZeroContractVersion);
        }
        let sequence = report_sequence.get().to_be_bytes();
        let runtime_version = input.runtime_contract_version.to_be_bytes();
        let fabric_version = input.fabric_contract_version.to_be_bytes();
        let operating_system = [input.operating_system as u8];
        let architecture = [input.architecture as u8];
        let report_digest = digest_fields(
            FEATURE_DIGEST_DOMAIN,
            &[
                input.node_id.as_bytes(),
                input.node_incarnation.as_bytes(),
                &sequence,
                &operating_system,
                &architecture,
                input.platform_profile_digest.as_bytes(),
                &runtime_version,
                &fabric_version,
            ],
        )?;
        Ok(Self {
            node_id: input.node_id,
            node_incarnation: input.node_incarnation,
            report_sequence,
            operating_system: input.operating_system,
            architecture: input.architecture,
            platform_profile_digest: input.platform_profile_digest,
            runtime_contract_version: input.runtime_contract_version,
            fabric_contract_version: input.fabric_contract_version,
            report_digest,
        })
    }

    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub const fn node_incarnation(self) -> NodeIncarnation {
        self.node_incarnation
    }

    #[must_use]
    pub const fn report_sequence(self) -> u64 {
        self.report_sequence.get()
    }

    #[must_use]
    pub const fn operating_system(self) -> NodeOperatingSystemV1 {
        self.operating_system
    }

    #[must_use]
    pub const fn architecture(self) -> NodeArchitectureV1 {
        self.architecture
    }

    #[must_use]
    pub const fn platform_profile_digest(self) -> Digest32 {
        self.platform_profile_digest
    }

    #[must_use]
    pub const fn runtime_contract_version(self) -> u16 {
        self.runtime_contract_version
    }

    #[must_use]
    pub const fn fabric_contract_version(self) -> u16 {
        self.fabric_contract_version
    }

    #[must_use]
    pub const fn report_digest(self) -> Digest32 {
        self.report_digest
    }
}

/// Transport of a Runtime-owned apply endpoint discovered through Node facts.
///
/// The first remote profile deliberately admits only a restricted Zenoh query
/// endpoint. This is bootstrap control transport, not an application
/// PortBinding and not a raw Fabric handle granted to Deployment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RuntimeApplyTransportV1 {
    RestrictedZenohQuery = 1,
}

/// Public endpoint descriptor owned by one RuntimeHost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyEndpointDescriptorV1 {
    endpoint_ref: RuntimeApplyEndpointRefV1,
    runtime_host_id: RuntimeHostId,
    endpoint_generation: NonZeroU64,
    transport: RuntimeApplyTransportV1,
    route: Box<str>,
    runtime_response_key_ref: [u8; 16],
    runtime_response_public_key: [u8; 32],
    descriptor_digest: Digest32,
}

impl RuntimeApplyEndpointDescriptorV1 {
    pub fn try_new(
        endpoint_ref: RuntimeApplyEndpointRefV1,
        runtime_host_id: RuntimeHostId,
        endpoint_generation: u64,
        route: &str,
        runtime_response_key_ref: [u8; 16],
        runtime_response_public_key: [u8; 32],
    ) -> Result<Self, NodeContractError> {
        if bytes_are_zero(runtime_host_id.as_bytes()) {
            return Err(NodeContractError::ZeroRuntimeHostId);
        }
        let endpoint_generation = NonZeroU64::new(endpoint_generation)
            .ok_or(NodeContractError::ZeroRuntimeEndpointGeneration)?;
        validate_route(route)?;
        if bytes_are_zero(&runtime_response_key_ref) {
            return Err(NodeContractError::ZeroRuntimeResponseKeyRef);
        }
        if bytes_are_zero(&runtime_response_public_key) {
            return Err(NodeContractError::ZeroRuntimeResponsePublicKey);
        }
        let generation = endpoint_generation.get().to_be_bytes();
        let transport = [RuntimeApplyTransportV1::RestrictedZenohQuery as u8];
        let descriptor_digest = digest_fields(
            ENDPOINT_DIGEST_DOMAIN,
            &[
                endpoint_ref.as_bytes(),
                runtime_host_id.as_bytes(),
                &generation,
                &transport,
                route.as_bytes(),
                &runtime_response_key_ref,
                &runtime_response_public_key,
            ],
        )?;
        Ok(Self {
            endpoint_ref,
            runtime_host_id,
            endpoint_generation,
            transport: RuntimeApplyTransportV1::RestrictedZenohQuery,
            route: route.into(),
            runtime_response_key_ref,
            runtime_response_public_key,
            descriptor_digest,
        })
    }

    #[must_use]
    pub const fn endpoint_ref(&self) -> RuntimeApplyEndpointRefV1 {
        self.endpoint_ref
    }

    #[must_use]
    pub const fn runtime_host_id(&self) -> RuntimeHostId {
        self.runtime_host_id
    }

    #[must_use]
    pub const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation.get()
    }

    #[must_use]
    pub const fn transport(&self) -> RuntimeApplyTransportV1 {
        self.transport
    }

    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    #[must_use]
    pub const fn runtime_response_key_ref(&self) -> [u8; 16] {
        self.runtime_response_key_ref
    }

    #[must_use]
    pub const fn runtime_response_public_key(&self) -> [u8; 32] {
        self.runtime_response_public_key
    }

    #[must_use]
    pub const fn descriptor_digest(&self) -> Digest32 {
        self.descriptor_digest
    }
}

/// RuntimeHost liveness as observed by the NodeDaemon. This does not replace
/// detailed Runtime-owned execution/readiness facts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RuntimeHostLivenessV1 {
    Bootstrapping = 1,
    Live = 2,
    Unresponsive = 3,
    Exited = 4,
    Quarantined = 5,
}

/// One RuntimeHost discovery/liveness record embedded in NodeStatus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHostStatusV1 {
    runtime_host_id: RuntimeHostId,
    runtime_host_epoch: NonZeroU64,
    observation_sequence: NonZeroU64,
    liveness: RuntimeHostLivenessV1,
    apply_endpoint: RuntimeApplyEndpointDescriptorV1,
    status_digest: Digest32,
}

impl RuntimeHostStatusV1 {
    pub fn try_new(
        runtime_host_epoch: u64,
        observation_sequence: u64,
        liveness: RuntimeHostLivenessV1,
        apply_endpoint: RuntimeApplyEndpointDescriptorV1,
    ) -> Result<Self, NodeContractError> {
        let runtime_host_epoch =
            NonZeroU64::new(runtime_host_epoch).ok_or(NodeContractError::ZeroRuntimeHostEpoch)?;
        let observation_sequence = NonZeroU64::new(observation_sequence)
            .ok_or(NodeContractError::ZeroRuntimeObservationSequence)?;
        let runtime_host_id = apply_endpoint.runtime_host_id();
        let epoch = runtime_host_epoch.get().to_be_bytes();
        let sequence = observation_sequence.get().to_be_bytes();
        let liveness_bytes = [liveness as u8];
        let status_digest = digest_fields(
            RUNTIME_STATUS_DIGEST_DOMAIN,
            &[
                runtime_host_id.as_bytes(),
                &epoch,
                &sequence,
                &liveness_bytes,
                apply_endpoint.descriptor_digest().as_bytes(),
            ],
        )?;
        Ok(Self {
            runtime_host_id,
            runtime_host_epoch,
            observation_sequence,
            liveness,
            apply_endpoint,
            status_digest,
        })
    }

    #[must_use]
    pub const fn runtime_host_id(&self) -> RuntimeHostId {
        self.runtime_host_id
    }

    #[must_use]
    pub const fn runtime_host_epoch(&self) -> u64 {
        self.runtime_host_epoch.get()
    }

    #[must_use]
    pub const fn observation_sequence(&self) -> u64 {
        self.observation_sequence.get()
    }

    #[must_use]
    pub const fn liveness(&self) -> RuntimeHostLivenessV1 {
        self.liveness
    }

    #[must_use]
    pub const fn apply_endpoint(&self) -> &RuntimeApplyEndpointDescriptorV1 {
        &self.apply_endpoint
    }

    #[must_use]
    pub const fn status_digest(&self) -> Digest32 {
        self.status_digest
    }
}

/// Current registration tenure that fences NodeDaemon publishers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeRegistrationTenureV1 {
    node_id: NodeId,
    registration_epoch: NonZeroU64,
    node_incarnation: NodeIncarnation,
}

impl NodeRegistrationTenureV1 {
    pub fn try_new(
        node_id: NodeId,
        registration_epoch: u64,
        node_incarnation: NodeIncarnation,
    ) -> Result<Self, NodeContractError> {
        let registration_epoch =
            NonZeroU64::new(registration_epoch).ok_or(NodeContractError::ZeroRegistrationEpoch)?;
        Ok(Self {
            node_id,
            registration_epoch,
            node_incarnation,
        })
    }

    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub const fn registration_epoch(self) -> u64 {
        self.registration_epoch.get()
    }

    #[must_use]
    pub const fn node_incarnation(self) -> NodeIncarnation {
        self.node_incarnation
    }
}

/// Immutable NodeDaemon-owned observed snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStatusV1 {
    node_id: NodeId,
    node_incarnation: NodeIncarnation,
    registration_epoch: NonZeroU64,
    status_sequence: NonZeroU64,
    freshness_budget_nanos: NonZeroU64,
    valid_until_unix_nanos: Option<NonZeroU64>,
    management_endpoint_ref: NodeManagementEndpointRefV1,
    feature_report: NodeFeatureReportV1,
    runtime_hosts: Box<[RuntimeHostStatusV1]>,
    status_digest: Digest32,
}

/// Complete input for one NodeStatus publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStatusInputV1 {
    pub tenure: NodeRegistrationTenureV1,
    pub status_sequence: u64,
    pub freshness_budget_nanos: u64,
    pub management_endpoint_ref: NodeManagementEndpointRefV1,
    pub feature_report: NodeFeatureReportV1,
    pub runtime_hosts: Vec<RuntimeHostStatusV1>,
}

impl NodeStatusV1 {
    pub fn try_new(input: NodeStatusInputV1) -> Result<Self, NodeContractError> {
        Self::try_new_inner(input, None)
    }

    pub(crate) fn try_new_with_valid_until_unix_nanos(
        input: NodeStatusInputV1,
        valid_until_unix_nanos: u64,
    ) -> Result<Self, NodeContractError> {
        let valid_until_unix_nanos = NonZeroU64::new(valid_until_unix_nanos)
            .ok_or(NodeContractError::InvalidFreshnessBudget)?;
        Self::try_new_inner(input, Some(valid_until_unix_nanos))
    }

    fn try_new_inner(
        mut input: NodeStatusInputV1,
        valid_until_unix_nanos: Option<NonZeroU64>,
    ) -> Result<Self, NodeContractError> {
        let status_sequence =
            NonZeroU64::new(input.status_sequence).ok_or(NodeContractError::ZeroStatusSequence)?;
        let freshness_budget_nanos = NonZeroU64::new(input.freshness_budget_nanos)
            .ok_or(NodeContractError::InvalidFreshnessBudget)?;
        if freshness_budget_nanos.get() > MAX_NODE_STATUS_FRESHNESS_NANOS {
            return Err(NodeContractError::InvalidFreshnessBudget);
        }
        if input.feature_report.node_id() != input.tenure.node_id()
            || input.feature_report.node_incarnation() != input.tenure.node_incarnation()
        {
            return Err(NodeContractError::NodeStatusIdentityMismatch);
        }
        if input.runtime_hosts.len() > MAX_RUNTIME_HOSTS_PER_NODE {
            return Err(NodeContractError::TooManyRuntimeHosts);
        }
        input
            .runtime_hosts
            .sort_by_key(RuntimeHostStatusV1::runtime_host_id);
        for pair in input.runtime_hosts.windows(2) {
            if pair[0].runtime_host_id() == pair[1].runtime_host_id() {
                return Err(NodeContractError::DuplicateRuntimeHost);
            }
        }
        let mut builder = Digest32Builder::try_new(STATUS_DIGEST_DOMAIN)?;
        builder
            .field_bytes(input.tenure.node_id().as_bytes())?
            .field_bytes(input.tenure.node_incarnation().as_bytes())?
            .field_u64(input.tenure.registration_epoch())?
            .field_u64(status_sequence.get())?
            .field_u64(freshness_budget_nanos.get())?
            .field_bytes(input.management_endpoint_ref.as_bytes())?
            .field_digest(&input.feature_report.report_digest())?
            .field_u64(
                u64::try_from(input.runtime_hosts.len())
                    .map_err(|_| NodeContractError::TooManyRuntimeHosts)?,
            )?;
        for runtime in &input.runtime_hosts {
            builder.field_digest(&runtime.status_digest())?;
        }
        if let Some(valid_until_unix_nanos) = valid_until_unix_nanos {
            builder.field_u64(valid_until_unix_nanos.get())?;
        }
        let status_digest = builder.finish();
        Ok(Self {
            node_id: input.tenure.node_id(),
            node_incarnation: input.tenure.node_incarnation(),
            registration_epoch: NonZeroU64::new(input.tenure.registration_epoch())
                .ok_or(NodeContractError::ZeroRegistrationEpoch)?,
            status_sequence,
            freshness_budget_nanos,
            valid_until_unix_nanos,
            management_endpoint_ref: input.management_endpoint_ref,
            feature_report: input.feature_report,
            runtime_hosts: input.runtime_hosts.into_boxed_slice(),
            status_digest,
        })
    }

    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub const fn node_incarnation(&self) -> NodeIncarnation {
        self.node_incarnation
    }

    #[must_use]
    pub const fn registration_epoch(&self) -> u64 {
        self.registration_epoch.get()
    }

    #[must_use]
    pub const fn status_sequence(&self) -> u64 {
        self.status_sequence.get()
    }

    #[must_use]
    pub const fn freshness_budget_nanos(&self) -> u64 {
        self.freshness_budget_nanos.get()
    }

    /// Authenticated absolute freshness fence for observation-backed PXNS.
    ///
    /// Legacy and caller-published statuses retain only their bounded relative
    /// budget and return `None`. Consumers that receive `Some` must enforce
    /// both this Unix-time deadline and the relative budget.
    #[must_use]
    pub const fn valid_until_unix_nanos(&self) -> Option<u64> {
        match self.valid_until_unix_nanos {
            Some(value) => Some(value.get()),
            None => None,
        }
    }

    /// Applies the relative observation-clock budget and, when present, the
    /// authenticated absolute Unix-time fence without conflating the clocks.
    #[must_use]
    pub fn is_fresh_at(&self, observed_at_nanos: u64, now_nanos: u64, now_unix_nanos: u64) -> bool {
        let Some(age) = now_nanos.checked_sub(observed_at_nanos) else {
            return false;
        };
        if age > self.freshness_budget_nanos.get() {
            return false;
        }
        self.valid_until_unix_nanos
            .is_none_or(|valid_until| now_unix_nanos != 0 && now_unix_nanos < valid_until.get())
    }

    #[must_use]
    pub const fn management_endpoint_ref(&self) -> NodeManagementEndpointRefV1 {
        self.management_endpoint_ref
    }

    #[must_use]
    pub const fn feature_report(&self) -> NodeFeatureReportV1 {
        self.feature_report
    }

    #[must_use]
    pub fn runtime_hosts(&self) -> &[RuntimeHostStatusV1] {
        &self.runtime_hosts
    }

    #[must_use]
    pub const fn status_digest(&self) -> Digest32 {
        self.status_digest
    }
}

/// NodeDaemon publication owner. It exposes status/discovery only and has no
/// Runtime apply method or Deployment desired-state mutation method.
#[derive(Clone, Debug)]
pub struct NodeDaemonV1 {
    identity: NodeIdentityV1,
    tenure: NodeRegistrationTenureV1,
    management_endpoint_ref: NodeManagementEndpointRefV1,
    feature_report: NodeFeatureReportV1,
    // Retain the latest observation as a bounded tenure-local fence even after
    // it is omitted from the published inventory. Otherwise `forget` would
    // let an old RuntimeHost callback become current again.
    runtime_hosts: BTreeMap<RuntimeHostId, RuntimeHostStatusV1>,
    visible_runtime_hosts: BTreeSet<RuntimeHostId>,
    next_status_sequence: NonZeroU64,
    last_published_status: Option<NodeStatusV1>,
}

/// Result of consuming one owner-verified RuntimeHost observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeHostObservationV1 {
    Advanced,
    ExactReplay,
}

impl NodeDaemonV1 {
    pub fn try_new(
        identity: NodeIdentityV1,
        tenure: NodeRegistrationTenureV1,
        management_endpoint_ref: NodeManagementEndpointRefV1,
        feature_report: NodeFeatureReportV1,
    ) -> Result<Self, NodeContractError> {
        if identity.node_id() != tenure.node_id()
            || feature_report.node_id() != tenure.node_id()
            || feature_report.node_incarnation() != tenure.node_incarnation()
        {
            return Err(NodeContractError::NodeStatusIdentityMismatch);
        }
        Ok(Self {
            identity,
            tenure,
            management_endpoint_ref,
            feature_report,
            runtime_hosts: BTreeMap::new(),
            visible_runtime_hosts: BTreeSet::new(),
            next_status_sequence: NonZeroU64::MIN,
            last_published_status: None,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> NodeIdentityV1 {
        self.identity
    }

    /// Replaces one observed RuntimeHost fact. This does not call, proxy, or
    /// admit that RuntimeHost's apply endpoint.
    pub fn observe_runtime_host(
        &mut self,
        status: RuntimeHostStatusV1,
    ) -> Result<RuntimeHostObservationV1, NodeContractError> {
        let runtime_host_id = status.runtime_host_id();
        let observation = if let Some(current) = self.runtime_hosts.get(&runtime_host_id) {
            match status
                .runtime_host_epoch()
                .cmp(&current.runtime_host_epoch())
            {
                core::cmp::Ordering::Less => {
                    return Err(NodeContractError::StaleRuntimeHostEpoch);
                }
                core::cmp::Ordering::Equal => {
                    match status
                        .observation_sequence()
                        .cmp(&current.observation_sequence())
                    {
                        core::cmp::Ordering::Less => {
                            return Err(NodeContractError::StaleRuntimeObservationSequence);
                        }
                        core::cmp::Ordering::Equal => {
                            if status.status_digest() != current.status_digest() {
                                return Err(NodeContractError::RuntimeObservationConflict);
                            }
                            RuntimeHostObservationV1::ExactReplay
                        }
                        core::cmp::Ordering::Greater => {
                            validate_runtime_endpoint_successor(current, &status)?;
                            RuntimeHostObservationV1::Advanced
                        }
                    }
                }
                core::cmp::Ordering::Greater => {
                    validate_runtime_endpoint_successor(current, &status)?;
                    RuntimeHostObservationV1::Advanced
                }
            }
        } else {
            if self.runtime_hosts.len() >= MAX_RUNTIME_HOSTS_PER_NODE {
                return Err(NodeContractError::TooManyRuntimeHosts);
            }
            RuntimeHostObservationV1::Advanced
        };
        if observation == RuntimeHostObservationV1::Advanced {
            self.runtime_hosts.insert(runtime_host_id, status);
        }
        self.visible_runtime_hosts.insert(runtime_host_id);
        Ok(observation)
    }

    /// Removes one discovery observation without stopping the RuntimeHost or
    /// deleting its tenure-local monotonic fence.
    pub fn forget_runtime_host(&mut self, runtime_host_id: RuntimeHostId) {
        self.visible_runtime_hosts.remove(&runtime_host_id);
    }

    /// Replaces the owner-verified feature report within the same incarnation.
    pub fn replace_feature_report(
        &mut self,
        feature_report: NodeFeatureReportV1,
    ) -> Result<(), NodeContractError> {
        if feature_report.node_id() != self.tenure.node_id()
            || feature_report.node_incarnation() != self.tenure.node_incarnation()
            || feature_report.report_sequence() <= self.feature_report.report_sequence()
        {
            return Err(NodeContractError::FeatureReportNotNewer);
        }
        self.feature_report = feature_report;
        Ok(())
    }

    /// Publishes one fresh immutable snapshot and advances only Node status
    /// sequence. RuntimeHost restart/epoch changes never alter NodeIncarnation.
    pub fn publish_status(
        &mut self,
        freshness_budget_nanos: u64,
    ) -> Result<NodeStatusV1, NodeContractError> {
        self.publish_status_inner(freshness_budget_nanos, None)
    }

    pub(crate) fn publish_status_with_valid_until_unix_nanos(
        &mut self,
        freshness_budget_nanos: u64,
        valid_until_unix_nanos: u64,
    ) -> Result<NodeStatusV1, NodeContractError> {
        let valid_until_unix_nanos = NonZeroU64::new(valid_until_unix_nanos)
            .ok_or(NodeContractError::InvalidFreshnessBudget)?;
        self.publish_status_inner(freshness_budget_nanos, Some(valid_until_unix_nanos))
    }

    fn publish_status_inner(
        &mut self,
        freshness_budget_nanos: u64,
        valid_until_unix_nanos: Option<NonZeroU64>,
    ) -> Result<NodeStatusV1, NodeContractError> {
        let sequence = self.next_status_sequence;
        let input = NodeStatusInputV1 {
            tenure: self.tenure,
            status_sequence: sequence.get(),
            freshness_budget_nanos,
            management_endpoint_ref: self.management_endpoint_ref,
            feature_report: self.feature_report,
            runtime_hosts: self
                .visible_runtime_hosts
                .iter()
                .filter_map(|runtime_host_id| self.runtime_hosts.get(runtime_host_id).cloned())
                .collect(),
        };
        let status = match valid_until_unix_nanos {
            Some(valid_until) => {
                NodeStatusV1::try_new_with_valid_until_unix_nanos(input, valid_until.get())?
            }
            None => NodeStatusV1::try_new(input)?,
        };
        self.next_status_sequence = NonZeroU64::new(
            sequence
                .get()
                .checked_add(1)
                .ok_or(NodeContractError::StatusSequenceExhausted)?,
        )
        .ok_or(NodeContractError::StatusSequenceExhausted)?;
        self.last_published_status = Some(status.clone());
        Ok(status)
    }

    /// Returns the last immutable status publication, if one exists.
    ///
    /// Reading this cache never publishes a heartbeat or advances sequence.
    #[must_use]
    pub const fn current_status(&self) -> Option<&NodeStatusV1> {
        self.last_published_status.as_ref()
    }

    #[must_use]
    pub const fn tenure(&self) -> NodeRegistrationTenureV1 {
        self.tenure
    }

    #[must_use]
    pub const fn management_endpoint_ref(&self) -> NodeManagementEndpointRefV1 {
        self.management_endpoint_ref
    }
}

/// Result of consuming one authenticated NodeStatus publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeStatusObservationV1 {
    Advanced,
    ExactReplay,
}

/// Consumer-side fencing state for one Node. Authentication and transport are
/// caller-owned; this reducer handles only exact Node/tenure/sequence ordering.
#[derive(Clone, Debug, Default)]
pub struct NodeStatusTrackerV1 {
    current: Option<NodeStatusV1>,
}

impl NodeStatusTrackerV1 {
    #[must_use]
    pub const fn current(&self) -> Option<&NodeStatusV1> {
        self.current.as_ref()
    }

    pub fn observe_authenticated(
        &mut self,
        status: NodeStatusV1,
    ) -> Result<NodeStatusObservationV1, NodeContractError> {
        let Some(current) = &self.current else {
            self.current = Some(status);
            return Ok(NodeStatusObservationV1::Advanced);
        };
        if status.node_id() != current.node_id() {
            return Err(NodeContractError::NodeTrackerIdentityMismatch);
        }
        match status
            .registration_epoch()
            .cmp(&current.registration_epoch())
        {
            core::cmp::Ordering::Less => Err(NodeContractError::StaleRegistrationEpoch),
            core::cmp::Ordering::Greater => {
                if status.node_incarnation() == current.node_incarnation() {
                    return Err(NodeContractError::IncarnationDidNotAdvance);
                }
                if status.management_endpoint_ref() == current.management_endpoint_ref() {
                    return Err(NodeContractError::ManagementEndpointDidNotAdvance);
                }
                self.current = Some(status);
                Ok(NodeStatusObservationV1::Advanced)
            }
            core::cmp::Ordering::Equal => {
                if status.node_incarnation() != current.node_incarnation() {
                    return Err(NodeContractError::RegistrationIncarnationConflict);
                }
                if status.management_endpoint_ref() != current.management_endpoint_ref() {
                    return Err(NodeContractError::ManagementEndpointChangedWithinTenure);
                }
                match status.status_sequence().cmp(&current.status_sequence()) {
                    core::cmp::Ordering::Less => Err(NodeContractError::StaleStatusSequence),
                    core::cmp::Ordering::Equal => {
                        if status.status_digest() != current.status_digest() {
                            return Err(NodeContractError::StatusSequenceConflict);
                        }
                        Ok(NodeStatusObservationV1::ExactReplay)
                    }
                    core::cmp::Ordering::Greater => {
                        self.current = Some(status);
                        Ok(NodeStatusObservationV1::Advanced)
                    }
                }
            }
        }
    }
}

/// Stable fail-closed contract failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeContractError {
    ZeroNodeId,
    ZeroNodeIncarnation,
    ZeroEnrollmentIssuerRef,
    ZeroManagementEndpointRef,
    ZeroRuntimeEndpointRef,
    ZeroPrincipalRef,
    ZeroDeploymentRevision,
    ZeroFeatureSequence,
    ZeroContractVersion,
    ZeroRuntimeHostId,
    ZeroRuntimeEndpointGeneration,
    ZeroRuntimeResponseKeyRef,
    ZeroRuntimeResponsePublicKey,
    InvalidRuntimeRoute,
    ZeroRuntimeHostEpoch,
    ZeroRuntimeObservationSequence,
    StaleRuntimeHostEpoch,
    StaleRuntimeObservationSequence,
    StaleRuntimeEndpointGeneration,
    RuntimeEndpointGenerationConflict,
    RuntimeObservationConflict,
    ZeroRegistrationEpoch,
    ZeroStatusSequence,
    InvalidFreshnessBudget,
    ZeroDigest,
    NodeStatusIdentityMismatch,
    TooManyRuntimeHosts,
    DuplicateRuntimeHost,
    FeatureReportNotNewer,
    StatusSequenceExhausted,
    NodeTrackerIdentityMismatch,
    StaleRegistrationEpoch,
    IncarnationDidNotAdvance,
    ManagementEndpointDidNotAdvance,
    ManagementEndpointChangedWithinTenure,
    RegistrationIncarnationConflict,
    StaleStatusSequence,
    StatusSequenceConflict,
    Digest(DigestBuildError),
}

impl fmt::Display for NodeContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Node contract rejected: {self:?}")
    }
}

impl std::error::Error for NodeContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DigestBuildError> for NodeContractError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> Result<Digest32, NodeContractError> {
    let mut builder = Digest32Builder::try_new(domain)?;
    for field in fields {
        builder.field_bytes(field)?;
    }
    Ok(builder.finish())
}

fn reject_zero_digest(digest: Digest32) -> Result<(), NodeContractError> {
    if bytes_are_zero(digest.as_bytes()) {
        return Err(NodeContractError::ZeroDigest);
    }
    Ok(())
}

fn validate_route(route: &str) -> Result<(), NodeContractError> {
    if route.is_empty()
        || route.len() > 255
        || !route.is_ascii()
        || route.starts_with('/')
        || route.ends_with('/')
        || route.contains("//")
        || !route.starts_with("paraegox/")
        || !route.ends_with("/apply")
        || route
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        || route.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        })
    {
        return Err(NodeContractError::InvalidRuntimeRoute);
    }
    Ok(())
}

fn validate_runtime_endpoint_successor(
    current: &RuntimeHostStatusV1,
    incoming: &RuntimeHostStatusV1,
) -> Result<(), NodeContractError> {
    match incoming
        .apply_endpoint()
        .endpoint_generation()
        .cmp(&current.apply_endpoint().endpoint_generation())
    {
        core::cmp::Ordering::Less => Err(NodeContractError::StaleRuntimeEndpointGeneration),
        core::cmp::Ordering::Equal
            if incoming.apply_endpoint().descriptor_digest()
                != current.apply_endpoint().descriptor_digest() =>
        {
            Err(NodeContractError::RuntimeEndpointGenerationConflict)
        }
        core::cmp::Ordering::Equal | core::cmp::Ordering::Greater => Ok(()),
    }
}

const fn bytes_are_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn node_id(byte: u8) -> NodeId {
        NodeId::try_from_bytes([byte; 16]).unwrap_or_else(|error| panic!("node id: {error}"))
    }

    fn incarnation(byte: u8) -> NodeIncarnation {
        NodeIncarnation::try_from_bytes([byte; 16])
            .unwrap_or_else(|error| panic!("incarnation: {error}"))
    }

    fn identity() -> NodeIdentityV1 {
        NodeIdentityV1::try_new(
            node_id(1),
            PrincipalRef::from_bytes([2; 16]),
            EnrollmentIssuerRefV1::try_from_bytes([3; 16])
                .unwrap_or_else(|error| panic!("issuer: {error}")),
        )
        .unwrap_or_else(|error| panic!("identity: {error}"))
    }

    fn feature(node_incarnation: NodeIncarnation, sequence: u64) -> NodeFeatureReportV1 {
        NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
            node_id: node_id(1),
            node_incarnation,
            report_sequence: sequence,
            operating_system: NodeOperatingSystemV1::Linux,
            architecture: NodeArchitectureV1::Aarch64,
            platform_profile_digest: digest(4),
            runtime_contract_version: 7,
            fabric_contract_version: 1,
        })
        .unwrap_or_else(|error| panic!("feature: {error}"))
    }

    fn endpoint(host: u8, generation: u64) -> RuntimeApplyEndpointDescriptorV1 {
        RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes([host.wrapping_add(10); 16])
                .unwrap_or_else(|error| panic!("endpoint ref: {error}")),
            RuntimeHostId::from_bytes([host; 16]),
            generation,
            &format!("paraegox/v1/nodes/01/runtime/{host}/apply"),
            [host.wrapping_add(20); 16],
            [host.wrapping_add(30); 32],
        )
        .unwrap_or_else(|error| panic!("endpoint: {error}"))
    }

    fn runtime(host: u8, epoch: u64) -> RuntimeHostStatusV1 {
        runtime_observation(host, epoch, 1, 1)
    }

    fn runtime_observation(
        host: u8,
        epoch: u64,
        observation_sequence: u64,
        endpoint_generation: u64,
    ) -> RuntimeHostStatusV1 {
        RuntimeHostStatusV1::try_new(
            epoch,
            observation_sequence,
            RuntimeHostLivenessV1::Live,
            endpoint(host, endpoint_generation),
        )
        .unwrap_or_else(|error| panic!("runtime: {error}"))
    }

    fn daemon(registration_epoch: u64, node_incarnation: NodeIncarnation) -> NodeDaemonV1 {
        NodeDaemonV1::try_new(
            identity(),
            NodeRegistrationTenureV1::try_new(node_id(1), registration_epoch, node_incarnation)
                .unwrap_or_else(|error| panic!("tenure: {error}")),
            NodeManagementEndpointRefV1::try_from_bytes(
                [u8::try_from(registration_epoch).unwrap_or(u8::MAX); 16],
            )
            .unwrap_or_else(|error| panic!("management: {error}")),
            feature(node_incarnation, 1),
        )
        .unwrap_or_else(|error| panic!("daemon: {error}"))
    }

    #[test]
    fn identity_spec_and_observed_status_remain_distinct() {
        let stable = identity();
        let spec = NodeSpecV1::try_new(node_id(1), 9, digest(6), digest(7))
            .unwrap_or_else(|error| panic!("spec: {error}"));
        let mut daemon = daemon(4, incarnation(8));
        daemon
            .observe_runtime_host(runtime(11, 1))
            .unwrap_or_else(|error| panic!("observe runtime: {error}"));
        let status = daemon
            .publish_status(5_000_000_000)
            .unwrap_or_else(|error| panic!("status: {error}"));

        assert_eq!(stable.node_id(), spec.node_id());
        assert_eq!(status.node_id(), stable.node_id());
        assert_eq!(spec.deployment_revision(), 9);
        assert_eq!(status.registration_epoch(), 4);
        assert_eq!(status.runtime_hosts().len(), 1);
        assert_ne!(stable.identity_digest(), spec.spec_digest());
        assert_ne!(spec.spec_digest(), status.status_digest());
    }

    #[test]
    fn observation_backed_absolute_deadline_is_part_of_status_identity() {
        let mut generic = daemon(4, incarnation(8));
        generic
            .observe_runtime_host(runtime(11, 1))
            .unwrap_or_else(|error| panic!("observe generic runtime: {error}"));
        let generic_status = generic
            .publish_status(1_000)
            .unwrap_or_else(|error| panic!("generic status: {error}"));

        let mut observation_backed = daemon(4, incarnation(8));
        observation_backed
            .observe_runtime_host(runtime(11, 1))
            .unwrap_or_else(|error| panic!("observe authenticated runtime: {error}"));
        let observation_status = observation_backed
            .publish_status_with_valid_until_unix_nanos(1_000, 9_000)
            .unwrap_or_else(|error| panic!("observation-backed status: {error}"));

        assert_eq!(generic_status.valid_until_unix_nanos(), None);
        assert_eq!(observation_status.valid_until_unix_nanos(), Some(9_000));
        assert_ne!(
            generic_status.status_digest(),
            observation_status.status_digest()
        );
        assert!(generic_status.is_fresh_at(100, 1_100, 0));
        assert!(!generic_status.is_fresh_at(100, 1_101, 0));
        assert!(observation_status.is_fresh_at(100, 1_100, 8_999));
        assert!(!observation_status.is_fresh_at(100, 1_100, 9_000));
        assert!(!observation_status.is_fresh_at(100, 1_100, 0));
    }

    #[test]
    fn runtime_restart_does_not_advance_node_incarnation() {
        let node_incarnation = incarnation(8);
        let mut daemon = daemon(4, node_incarnation);
        daemon
            .observe_runtime_host(runtime(11, 1))
            .unwrap_or_else(|error| panic!("observe runtime: {error}"));
        let before = daemon
            .publish_status(1_000)
            .unwrap_or_else(|error| panic!("before: {error}"));
        daemon
            .observe_runtime_host(runtime(11, 2))
            .unwrap_or_else(|error| panic!("observe runtime restart: {error}"));
        let after = daemon
            .publish_status(1_000)
            .unwrap_or_else(|error| panic!("after: {error}"));

        assert_eq!(before.node_incarnation(), after.node_incarnation());
        assert_eq!(after.status_sequence(), before.status_sequence() + 1);
        assert_eq!(after.runtime_hosts()[0].runtime_host_epoch(), 2);
    }

    #[test]
    fn old_registration_and_conflicting_incarnation_are_fenced() {
        let mut first = daemon(4, incarnation(8));
        let first_status = first
            .publish_status(1_000)
            .unwrap_or_else(|error| panic!("first: {error}"));
        let mut tracker = NodeStatusTrackerV1::default();
        assert_eq!(
            tracker.observe_authenticated(first_status.clone()),
            Ok(NodeStatusObservationV1::Advanced)
        );
        assert_eq!(
            tracker.observe_authenticated(first_status),
            Ok(NodeStatusObservationV1::ExactReplay)
        );

        let mut stale = daemon(3, incarnation(7));
        assert_eq!(
            tracker.observe_authenticated(
                stale
                    .publish_status(1_000)
                    .unwrap_or_else(|error| panic!("stale: {error}"))
            ),
            Err(NodeContractError::StaleRegistrationEpoch)
        );
        let mut conflict = daemon(4, incarnation(9));
        assert_eq!(
            tracker.observe_authenticated(
                conflict
                    .publish_status(1_000)
                    .unwrap_or_else(|error| panic!("conflict: {error}"))
            ),
            Err(NodeContractError::RegistrationIncarnationConflict)
        );
        let mut successor = daemon(5, incarnation(10));
        assert_eq!(
            tracker.observe_authenticated(
                successor
                    .publish_status(1_000)
                    .unwrap_or_else(|error| panic!("successor: {error}"))
            ),
            Ok(NodeStatusObservationV1::Advanced)
        );
    }

    #[test]
    fn runtime_inventory_is_bounded_unique_and_canonical() {
        let mut daemon = daemon(4, incarnation(8));
        daemon
            .observe_runtime_host(runtime(22, 1))
            .unwrap_or_else(|error| panic!("observe runtime 22: {error}"));
        daemon
            .observe_runtime_host(runtime(11, 1))
            .unwrap_or_else(|error| panic!("observe runtime 11: {error}"));
        let status = daemon
            .publish_status(1_000)
            .unwrap_or_else(|error| panic!("status: {error}"));
        assert_eq!(
            status.runtime_hosts()[0].runtime_host_id(),
            RuntimeHostId::from_bytes([11; 16])
        );
        assert_eq!(
            status.runtime_hosts()[1].runtime_host_id(),
            RuntimeHostId::from_bytes([22; 16])
        );

        let duplicate = NodeStatusV1::try_new(NodeStatusInputV1 {
            tenure: NodeRegistrationTenureV1::try_new(node_id(1), 4, incarnation(8))
                .unwrap_or_else(|error| panic!("tenure: {error}")),
            status_sequence: 1,
            freshness_budget_nanos: 1_000,
            management_endpoint_ref: NodeManagementEndpointRefV1::try_from_bytes([5; 16])
                .unwrap_or_else(|error| panic!("management: {error}")),
            feature_report: feature(incarnation(8), 1),
            runtime_hosts: vec![runtime(11, 1), runtime(11, 2)],
        });
        assert_eq!(duplicate, Err(NodeContractError::DuplicateRuntimeHost));
    }

    #[test]
    fn management_owner_exposes_discovery_not_runtime_apply() {
        let endpoint = endpoint(11, 3);
        assert_eq!(
            endpoint.transport(),
            RuntimeApplyTransportV1::RestrictedZenohQuery
        );
        assert_eq!(
            endpoint.runtime_host_id(),
            RuntimeHostId::from_bytes([11; 16])
        );
        assert!(endpoint.route().ends_with("/apply"));
    }

    #[test]
    fn malformed_endpoint_and_unbounded_freshness_fail_closed() {
        assert_eq!(
            RuntimeApplyEndpointDescriptorV1::try_new(
                RuntimeApplyEndpointRefV1::try_from_bytes([1; 16])
                    .unwrap_or_else(|error| panic!("ref: {error}")),
                RuntimeHostId::from_bytes([2; 16]),
                1,
                "../escape/*",
                [3; 16],
                [4; 32],
            ),
            Err(NodeContractError::InvalidRuntimeRoute)
        );
        for route in ["../escape", "foreign/runtime/apply", "paraegox/not-apply"] {
            assert_eq!(
                RuntimeApplyEndpointDescriptorV1::try_new(
                    RuntimeApplyEndpointRefV1::try_from_bytes([1; 16])
                        .unwrap_or_else(|error| panic!("ref: {error}")),
                    RuntimeHostId::from_bytes([2; 16]),
                    1,
                    route,
                    [3; 16],
                    [4; 32],
                ),
                Err(NodeContractError::InvalidRuntimeRoute)
            );
        }
        let mut daemon = daemon(4, incarnation(8));
        assert_eq!(
            daemon.publish_status(MAX_NODE_STATUS_FRESHNESS_NANOS + 1),
            Err(NodeContractError::InvalidFreshnessBudget)
        );
    }

    #[test]
    fn runtime_observations_are_monotonic_and_forget_retains_the_fence() {
        let mut daemon = daemon(4, incarnation(8));
        let current = runtime_observation(11, 3, 7, 2);
        assert_eq!(
            daemon.observe_runtime_host(current.clone()),
            Ok(RuntimeHostObservationV1::Advanced)
        );
        assert_eq!(
            daemon.observe_runtime_host(current.clone()),
            Ok(RuntimeHostObservationV1::ExactReplay)
        );
        assert_eq!(
            daemon.observe_runtime_host(runtime_observation(11, 2, 99, 2)),
            Err(NodeContractError::StaleRuntimeHostEpoch)
        );
        assert_eq!(
            daemon.observe_runtime_host(runtime_observation(11, 3, 6, 2)),
            Err(NodeContractError::StaleRuntimeObservationSequence)
        );
        let conflicting =
            RuntimeHostStatusV1::try_new(3, 7, RuntimeHostLivenessV1::Exited, endpoint(11, 2))
                .unwrap_or_else(|error| panic!("conflicting observation: {error}"));
        assert_eq!(
            daemon.observe_runtime_host(conflicting),
            Err(NodeContractError::RuntimeObservationConflict)
        );

        daemon.forget_runtime_host(RuntimeHostId::from_bytes([11; 16]));
        let hidden = daemon
            .publish_status(1_000)
            .unwrap_or_else(|error| panic!("hidden status: {error}"));
        assert!(hidden.runtime_hosts().is_empty());
        assert_eq!(
            daemon.observe_runtime_host(runtime_observation(11, 2, 100, 2)),
            Err(NodeContractError::StaleRuntimeHostEpoch)
        );
        assert_eq!(
            daemon.observe_runtime_host(current),
            Ok(RuntimeHostObservationV1::ExactReplay)
        );
        let visible = daemon
            .publish_status(1_000)
            .unwrap_or_else(|error| panic!("visible status: {error}"));
        assert_eq!(visible.runtime_hosts().len(), 1);
    }

    #[test]
    fn runtime_fence_inventory_is_bounded_before_publication() {
        let mut daemon = daemon(4, incarnation(8));
        for host in 1..=u8::try_from(MAX_RUNTIME_HOSTS_PER_NODE)
            .unwrap_or_else(|_| panic!("test bound must fit in u8"))
        {
            assert_eq!(
                daemon.observe_runtime_host(runtime(host, 1)),
                Ok(RuntimeHostObservationV1::Advanced)
            );
        }
        assert_eq!(
            daemon.observe_runtime_host(runtime(99, 1)),
            Err(NodeContractError::TooManyRuntimeHosts)
        );
        daemon.forget_runtime_host(RuntimeHostId::from_bytes([1; 16]));
        assert_eq!(
            daemon.observe_runtime_host(runtime(99, 1)),
            Err(NodeContractError::TooManyRuntimeHosts)
        );
        assert!(daemon.publish_status(1_000).is_ok());
    }

    #[test]
    fn endpoint_generation_cannot_regress_or_change_in_place() {
        let mut daemon = daemon(4, incarnation(8));
        daemon
            .observe_runtime_host(runtime_observation(11, 3, 1, 2))
            .unwrap_or_else(|error| panic!("first observation: {error}"));
        assert_eq!(
            daemon.observe_runtime_host(runtime_observation(11, 3, 2, 1)),
            Err(NodeContractError::StaleRuntimeEndpointGeneration)
        );
        let changed_endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes([21; 16])
                .unwrap_or_else(|error| panic!("endpoint ref: {error}")),
            RuntimeHostId::from_bytes([11; 16]),
            2,
            "paraegox/v1/nodes/01/runtime/11/changed/apply",
            [31; 16],
            [41; 32],
        )
        .unwrap_or_else(|error| panic!("changed endpoint: {error}"));
        let changed =
            RuntimeHostStatusV1::try_new(3, 2, RuntimeHostLivenessV1::Live, changed_endpoint)
                .unwrap_or_else(|error| panic!("changed status: {error}"));
        assert_eq!(
            daemon.observe_runtime_host(changed),
            Err(NodeContractError::RuntimeEndpointGenerationConflict)
        );
    }

    #[test]
    fn successor_incarnation_must_rotate_management_endpoint_ref() {
        let mut first = daemon(4, incarnation(8));
        let first_status = first
            .publish_status(1_000)
            .unwrap_or_else(|error| panic!("first status: {error}"));
        let reused_endpoint = NodeStatusV1::try_new(NodeStatusInputV1 {
            tenure: NodeRegistrationTenureV1::try_new(node_id(1), 5, incarnation(10))
                .unwrap_or_else(|error| panic!("successor tenure: {error}")),
            status_sequence: 1,
            freshness_budget_nanos: 1_000,
            management_endpoint_ref: first_status.management_endpoint_ref(),
            feature_report: feature(incarnation(10), 1),
            runtime_hosts: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("successor status: {error}"));
        let mut tracker = NodeStatusTrackerV1::default();
        tracker
            .observe_authenticated(first_status)
            .unwrap_or_else(|error| panic!("track first: {error}"));
        assert_eq!(
            tracker.observe_authenticated(reused_endpoint),
            Err(NodeContractError::ManagementEndpointDidNotAdvance)
        );

        let changed_within_tenure = NodeStatusV1::try_new(NodeStatusInputV1 {
            tenure: NodeRegistrationTenureV1::try_new(node_id(1), 4, incarnation(8))
                .unwrap_or_else(|error| panic!("same tenure: {error}")),
            status_sequence: 2,
            freshness_budget_nanos: 1_000,
            management_endpoint_ref: NodeManagementEndpointRefV1::try_from_bytes([99; 16])
                .unwrap_or_else(|error| panic!("changed endpoint ref: {error}")),
            feature_report: feature(incarnation(8), 2),
            runtime_hosts: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("changed-within-tenure status: {error}"));
        let mut tracker = NodeStatusTrackerV1::default();
        let mut first = daemon(4, incarnation(8));
        tracker
            .observe_authenticated(
                first
                    .publish_status(1_000)
                    .unwrap_or_else(|error| panic!("first same-tenure status: {error}")),
            )
            .unwrap_or_else(|error| panic!("track same-tenure first: {error}"));
        assert_eq!(
            tracker.observe_authenticated(changed_within_tenure),
            Err(NodeContractError::ManagementEndpointChangedWithinTenure)
        );
    }
}
