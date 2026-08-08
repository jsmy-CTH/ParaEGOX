#![cfg(unix)]

//! Explicit non-production Runtime lifecycle for the one-process
//! DeveloperLocal composition.
//!
//! This facade owns the real Runtime journal, authenticated Unix endpoint,
//! optional all-or-nothing restricted Runtime transport listener, in-place
//! PXFB-to-PXMS/PXAS cutover, and joined shutdown. Callers receive only
//! immutable socket-ready facts and, after presenting an exact committed
//! terminal admitted by its protocol-specific claim gate, an opaque Agent
//! conversation capability.

use core::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};

use ed25519_dalek::{SigningKey, VerifyingKey};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::unistd::{getegid, geteuid};
use paraegox_evidence::{EvidenceOwnerRefV1, EvidenceRetentionPolicyV1, EvidenceStoreEpochV1};
use paraegox_fabric::{
    ResolvedRemoteMtlsIdentityFiles, RestrictedRuntimeApplyConfigErrorV1,
    RestrictedRuntimeApplyEndpointConfigV1, RestrictedRuntimeControlEndpointConfigV1,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_runtime_contracts::apply::{PlanWriterRef, TenureAuthorityRef, TenureKeyRef};
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    RestrictedRuntimeApplyCarrierBindingV1, RestrictedRuntimeApplyTransportProfileV1,
};
use paraegox_runtime_contracts::installation::{
    InstalledRuntimeArtifactObservationV1, MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES,
    RuntimeCompiledInstallationFactsV1, generate_build_descriptor, generate_manifest,
};
use paraegox_runtime_contracts::managed_serving_bootstrap::RuntimeControlDescribeReadyFactsV1;
use paraegox_runtime_contracts::provenance::SourceScopeRef;
use paraegox_runtime_contracts::reference_control::ReferenceBootstrapServingIdentityV1;
use paraegox_runtime_contracts::wire::ApplyAuthKeyRef;
use sha2::{Digest as ShaDigest, Sha256};
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

use crate::distributed_agent_stack_runtime::DistributedAgentStackEvidenceStoreConfigV1;
use crate::distributed_fabric_runtime::RuntimeFabricCredentialResolverV2;
use crate::managed_agent_runtime::RuntimeAgentConversationHandle;
use crate::managed_agent_stack_runtime::RuntimeAgentHandleBroker;
use crate::managed_model_runtime::{
    RuntimeModelBackendResolverV1, UnavailableRuntimeModelBackendResolver,
};
use crate::runtime_agent_provider::{
    RuntimeAgentProviderResolverV1, UnavailableRuntimeAgentProviderResolver,
};
use crate::runtime_build_metadata::{
    RuntimeHostEmbeddedBuildMetadataV1, runtime_compiled_installation_facts,
};
use crate::runtime_control_endpoint::{
    RuntimeBootstrapEndpointError, RuntimeDistributedAgentStackDependenciesV1,
    RuntimeManagedFabricServiceDependenciesV1, RuntimeRestrictedApplyEndpointDependenciesV1,
    build_managed_fabric_owner_runtime, serve_runtime_developer_local_until,
    validate_restricted_runtime_apply_carrier_pins,
};
use crate::runtime_initializer::{
    RuntimeInitializationInputV1, RuntimeInstallationEvidenceV1,
    initialize_runtime_store_after_preflight,
};
use crate::runtime_provisioning::{
    RuntimeDeveloperLocalProvisioningInputV1, RuntimeProvisioningV1,
    validate_canonical_absolute_path,
};
use crate::runtime_store::{
    RuntimeInitializerBeginError, RuntimeInitializerPreflight, RuntimeStore,
};

const MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES: usize = 103;
const DEVELOPER_BUILD_ID_DOMAIN: &[u8] =
    b"paraegox.runtime.developer-local-build-instance.sha256.v1";
const STARTUP_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
// The current-thread Runtime owner polls the complete authenticated control,
// Fabric, and Agent cutover future on this OS thread.  Pin a portable finite
// stack instead of inheriting smaller platform defaults.
const DEVELOPER_LOCAL_RUNTIME_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Non-secret stable identity references shared between Deployment and the
/// Runtime facade. Validation occurs when they are combined with exact role
/// verification keys and Runtime-local signing material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDeveloperLocalIdentityRefsV1 {
    pub installation_id: [u8; 16],
    pub target: [u8; 16],
    pub source_scope: [u8; 16],
    pub writer: [u8; 16],
    pub runtime_principal: [u8; 16],
    pub controller_principal: [u8; 16],
    pub authority_principal: [u8; 16],
    pub controller_request_key_ref: [u8; 16],
    pub runtime_response_key_ref: [u8; 16],
    pub tenure_authority_ref: [u8; 16],
    pub tenure_key_ref: [u8; 16],
}

/// The three distinct DeveloperLocal signing seeds.  Debug is redacted and
/// every owned copy is zeroized on drop.
pub struct RuntimeDeveloperLocalSigningSeedsV1 {
    controller: [u8; 32],
    authority: [u8; 32],
    runtime_response: [u8; 32],
}

impl RuntimeDeveloperLocalSigningSeedsV1 {
    pub fn new(controller: [u8; 32], authority: [u8; 32], runtime_response: [u8; 32]) -> Self {
        Self {
            controller,
            authority,
            runtime_response,
        }
    }
}

impl fmt::Debug for RuntimeDeveloperLocalSigningSeedsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeDeveloperLocalSigningSeedsV1(<redacted>)")
    }
}

impl Drop for RuntimeDeveloperLocalSigningSeedsV1 {
    fn drop(&mut self) {
        self.controller.zeroize();
        self.authority.zeroize();
        self.runtime_response.zeroize();
    }
}

/// Stable role and split-trust key material supplied by the DeveloperLocal owner.
///
/// Controller and tenure authority cross this boundary only as verification
/// keys. The sole retained private capability is the Runtime response signing
/// seed, which is redacted from Debug and zeroized on drop.
pub struct RuntimeDeveloperLocalIdentityV1 {
    refs: RuntimeDeveloperLocalIdentityRefsV1,
    controller_request_verification_key: [u8; 32],
    tenure_verification_key: [u8; 32],
    runtime_response_signing_seed: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RuntimeDeveloperLocalIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDeveloperLocalIdentityV1")
            .field("refs", &self.refs)
            .field("signing_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RuntimeDeveloperLocalIdentityV1 {
    /// Compatibility constructor for the original three-seed DeveloperLocal
    /// boundary. External role seeds are validated, converted immediately to
    /// verification keys, and never retained by the resulting Runtime config.
    pub fn try_new(
        refs: RuntimeDeveloperLocalIdentityRefsV1,
        seeds: RuntimeDeveloperLocalSigningSeedsV1,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        validate_developer_local_identity_refs(&refs)?;
        let seed_values = [seeds.controller, seeds.authority, seeds.runtime_response];
        if seed_values
            .iter()
            .any(|seed| seed.iter().all(|byte| *byte == 0))
            || seed_values[0] == seed_values[1]
            || seed_values[0] == seed_values[2]
            || seed_values[1] == seed_values[2]
        {
            return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
                "DeveloperLocal signing seeds must be nonzero and distinct",
            ));
        }
        let controller_request_verification_key = SigningKey::from_bytes(&seeds.controller)
            .verifying_key()
            .to_bytes();
        let tenure_verification_key = SigningKey::from_bytes(&seeds.authority)
            .verifying_key()
            .to_bytes();
        let runtime_response_signing_seed = Zeroizing::new(seeds.runtime_response);
        Self::try_new_with_verification_keys(
            refs,
            controller_request_verification_key,
            tenure_verification_key,
            runtime_response_signing_seed,
        )
    }

    /// Constructs the DeveloperLocal Runtime boundary from external role
    /// verification keys and the one Runtime-owned response signing seed.
    pub fn try_new_with_verification_keys(
        refs: RuntimeDeveloperLocalIdentityRefsV1,
        controller_request_verification_key: [u8; 32],
        tenure_verification_key: [u8; 32],
        runtime_response_signing_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        validate_developer_local_identity_refs(&refs)?;
        if runtime_response_signing_seed.iter().all(|byte| *byte == 0) {
            return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
                "DeveloperLocal Runtime response signing seed must be nonzero",
            ));
        }
        let controller_key = VerifyingKey::from_bytes(&controller_request_verification_key)
            .map_err(|_| {
                RuntimeDeveloperLocalError::InvalidConfiguration(
                    "DeveloperLocal verification keys must be valid, non-weak, and role-distinct",
                )
            })?;
        let tenure_key = VerifyingKey::from_bytes(&tenure_verification_key).map_err(|_| {
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "DeveloperLocal verification keys must be valid, non-weak, and role-distinct",
            )
        })?;
        let response_key = SigningKey::from_bytes(&runtime_response_signing_seed).verifying_key();
        if controller_key.is_weak()
            || tenure_key.is_weak()
            || controller_key == tenure_key
            || controller_key == response_key
            || tenure_key == response_key
        {
            return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
                "DeveloperLocal verification keys must be valid, non-weak, and role-distinct",
            ));
        }
        Ok(Self {
            refs,
            controller_request_verification_key,
            tenure_verification_key,
            runtime_response_signing_seed,
        })
    }

    fn facts(&self) -> RuntimeDeveloperLocalIdentityFactsV1 {
        RuntimeDeveloperLocalIdentityFactsV1 {
            target: self.refs.target,
            source_scope: self.refs.source_scope,
            writer: self.refs.writer,
            runtime_principal: self.refs.runtime_principal,
            controller_principal: self.refs.controller_principal,
            authority_principal: self.refs.authority_principal,
            controller_request_key_ref: self.refs.controller_request_key_ref,
            runtime_response_key_ref: self.refs.runtime_response_key_ref,
            tenure_authority_ref: self.refs.tenure_authority_ref,
            tenure_key_ref: self.refs.tenure_key_ref,
        }
    }

    fn provisioning_input(&self, socket_path: PathBuf) -> RuntimeDeveloperLocalProvisioningInputV1 {
        RuntimeDeveloperLocalProvisioningInputV1 {
            socket_path,
            target: RuntimeHostId::from_bytes(self.refs.target),
            source_scope: SourceScopeRef::from_bytes(self.refs.source_scope),
            writer: PlanWriterRef::from_bytes(self.refs.writer),
            runtime_principal: PrincipalRef::from_bytes(self.refs.runtime_principal),
            controller_principal: PrincipalRef::from_bytes(self.refs.controller_principal),
            controller_request_key_ref: ApplyAuthKeyRef::from_bytes(
                self.refs.controller_request_key_ref,
            ),
            controller_request_verification_key: self.controller_request_verification_key,
            runtime_response_key_ref: ApplyAuthKeyRef::from_bytes(
                self.refs.runtime_response_key_ref,
            ),
            runtime_response_signing_seed: Zeroizing::new(*self.runtime_response_signing_seed),
            authority_principal: PrincipalRef::from_bytes(self.refs.authority_principal),
            tenure_authority_ref: TenureAuthorityRef::from_bytes(self.refs.tenure_authority_ref),
            tenure_key_ref: TenureKeyRef::from_bytes(self.refs.tenure_key_ref),
            tenure_verification_key: self.tenure_verification_key,
        }
    }
}

fn validate_developer_local_identity_refs(
    refs: &RuntimeDeveloperLocalIdentityRefsV1,
) -> Result<(), RuntimeDeveloperLocalError> {
    let identities = [
        refs.installation_id,
        refs.target,
        refs.source_scope,
        refs.writer,
        refs.runtime_principal,
        refs.controller_principal,
        refs.authority_principal,
        refs.controller_request_key_ref,
        refs.runtime_response_key_ref,
        refs.tenure_authority_ref,
        refs.tenure_key_ref,
    ];
    if identities
        .iter()
        .any(|identity| identity.iter().all(|byte| *byte == 0))
        || identities.iter().enumerate().any(|(index, identity)| {
            identities[index + 1..]
                .iter()
                .any(|other| other == identity)
        })
    {
        return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
            "DeveloperLocal identities must be nonzero and pairwise distinct",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RuntimeDeveloperLocalIdentityFactsV1 {
    target: [u8; 16],
    source_scope: [u8; 16],
    writer: [u8; 16],
    runtime_principal: [u8; 16],
    controller_principal: [u8; 16],
    authority_principal: [u8; 16],
    controller_request_key_ref: [u8; 16],
    runtime_response_key_ref: [u8; 16],
    tenure_authority_ref: [u8; 16],
    tenure_key_ref: [u8; 16],
}

/// Complete process-local dependency set for the experimental distributed
/// Agent-stack successor.
///
/// The credential resolver is retained as an opaque composition capability.
/// Evidence identity, retention, and its normalized absolute root are pinned
/// into one private Runtime configuration at construction; no partial or
/// fallback distributed configuration can be added later. Debug deliberately
/// reveals none of these composition values.
#[derive(Clone)]
pub struct RuntimeDeveloperLocalDistributedAgentStackConfigV1 {
    fabric_credential_resolver: Arc<dyn RuntimeFabricCredentialResolverV2>,
    evidence_store_config: DistributedAgentStackEvidenceStoreConfigV1,
}

impl RuntimeDeveloperLocalDistributedAgentStackConfigV1 {
    pub fn try_new(
        fabric_credential_resolver: Arc<dyn RuntimeFabricCredentialResolverV2>,
        evidence_store_root: PathBuf,
        evidence_store_epoch: EvidenceStoreEpochV1,
        evidence_owner_ref: EvidenceOwnerRefV1,
        evidence_retention_policy: EvidenceRetentionPolicyV1,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        validate_canonical_absolute_path(&evidence_store_root, false).map_err(|_| {
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "distributed Evidence store root must be absolute and normalized",
            )
        })?;
        let evidence_store_config = DistributedAgentStackEvidenceStoreConfigV1::try_new(
            evidence_store_root,
            evidence_store_epoch,
            evidence_retention_policy,
            evidence_owner_ref,
        )
        .map_err(|_| {
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "distributed Evidence store configuration is invalid",
            )
        })?;
        Ok(Self {
            fabric_credential_resolver,
            evidence_store_config,
        })
    }

    fn evidence_store_root(&self) -> &Path {
        self.evidence_store_config.root()
    }

    fn into_runtime_dependencies(self) -> RuntimeDistributedAgentStackDependenciesV1 {
        RuntimeDistributedAgentStackDependenciesV1::new(
            self.fabric_credential_resolver,
            self.evidence_store_config,
        )
    }
}

impl fmt::Debug for RuntimeDeveloperLocalDistributedAgentStackConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeDeveloperLocalDistributedAgentStackConfigV1(<redacted>)")
    }
}

/// Complete input for the explicit DeveloperLocal Runtime owner.
pub struct RuntimeDeveloperLocalConfigV1 {
    state_directory: PathBuf,
    socket_path: PathBuf,
    identity: RuntimeDeveloperLocalIdentityV1,
    provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
    model_backend_resolver: Arc<dyn RuntimeModelBackendResolverV1>,
    distributed_agent_stack: Option<RuntimeDistributedAgentStackDependenciesV1>,
    restricted_runtime_apply_endpoint: Option<RuntimeRestrictedApplyEndpointDependenciesV1>,
}

struct RestrictedRuntimeApplyConstructorInput {
    state_directory: PathBuf,
    socket_path: PathBuf,
    identity: RuntimeDeveloperLocalIdentityV1,
    transport_profile: RestrictedRuntimeApplyTransportProfileV1,
    resolved_profile_ref: [u8; 16],
    expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
    root_ca_certificate_file: PathBuf,
    listener_identity: ResolvedRemoteMtlsIdentityFiles,
}

impl fmt::Debug for RuntimeDeveloperLocalConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeDeveloperLocalConfigV1(<redacted>)")
    }
}

impl RuntimeDeveloperLocalConfigV1 {
    pub fn try_new(
        state_directory: PathBuf,
        socket_path: PathBuf,
        identity: RuntimeDeveloperLocalIdentityV1,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        Self::try_new_with_provider_resolver(
            state_directory,
            socket_path,
            identity,
            Arc::new(UnavailableRuntimeAgentProviderResolver),
        )
    }

    /// Constructs DeveloperLocal with an explicit repeatable provider
    /// resolver. Both admitted provider profiles use this seam, and Runtime
    /// never substitutes a provider when resolution fails.
    pub fn try_new_with_provider_resolver(
        state_directory: PathBuf,
        socket_path: PathBuf,
        identity: RuntimeDeveloperLocalIdentityV1,
        provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        Self::try_new_with_agent_and_model_resolvers(
            state_directory,
            socket_path,
            identity,
            provider_resolver,
            Arc::new(UnavailableRuntimeModelBackendResolver),
        )
    }

    /// Constructs the additive PXAR-v9 DeveloperLocal path with two exact,
    /// repeatable composition resolvers. Runtime uses the Model resolver only
    /// for a committed managed Model plan and never substitutes a backend.
    pub fn try_new_with_agent_and_model_resolvers(
        state_directory: PathBuf,
        socket_path: PathBuf,
        identity: RuntimeDeveloperLocalIdentityV1,
        provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
        model_backend_resolver: Arc<dyn RuntimeModelBackendResolverV1>,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        validate_canonical_absolute_path(&state_directory, false).map_err(|error| {
            RuntimeDeveloperLocalError::InvalidConfigurationOwned(error.to_string().into())
        })?;
        validate_canonical_absolute_path(&socket_path, true).map_err(|error| {
            RuntimeDeveloperLocalError::InvalidConfigurationOwned(error.to_string().into())
        })?;
        if socket_path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES
            || socket_path.starts_with(&state_directory)
        {
            return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
                "socket path must be portable and outside the Runtime journal directory",
            ));
        }
        Ok(Self {
            state_directory,
            socket_path,
            identity,
            provider_resolver,
            model_backend_resolver,
            distributed_agent_stack: None,
            restricted_runtime_apply_endpoint: None,
        })
    }

    /// Adds the one complete distributed Agent-stack dependency set.
    ///
    /// The Evidence owner must be disjoint from both the Runtime journal owner
    /// and the UDS endpoint path. A second injection is rejected rather than
    /// replacing the resolver, store epoch, owner, or retention authority.
    pub fn try_with_distributed_agent_stack(
        mut self,
        distributed_agent_stack: RuntimeDeveloperLocalDistributedAgentStackConfigV1,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        if self.distributed_agent_stack.is_some() {
            return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
                "distributed Agent stack is already configured",
            ));
        }
        let evidence_root = distributed_agent_stack.evidence_store_root();
        if paths_overlap(evidence_root, &self.state_directory)
            || paths_overlap(evidence_root, &self.socket_path)
        {
            return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
                "distributed Evidence store root must not overlap Runtime state or socket paths",
            ));
        }
        self.distributed_agent_stack = Some(distributed_agent_stack.into_runtime_dependencies());
        Ok(self)
    }

    /// Constructs DeveloperLocal with one complete canonical PXRP/PXCB
    /// restricted Runtime listener input and an explicit fail-closed
    /// unavailable Agent-provider resolver.
    ///
    /// Raw Fabric endpoint configuration is deliberately not accepted. The
    /// exact profile/ref/carrier tuple is mapped and bound immediately by the
    /// Fabric public constructor before this configuration can exist.
    pub fn try_new_with_restricted_runtime_apply_endpoint(
        state_directory: PathBuf,
        socket_path: PathBuf,
        identity: RuntimeDeveloperLocalIdentityV1,
        transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        resolved_profile_ref: [u8; 16],
        expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
        listener_credentials: (PathBuf, ResolvedRemoteMtlsIdentityFiles),
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        let (root_ca_certificate_file, listener_identity) = listener_credentials;
        Self::try_new_with_restricted_runtime_apply_endpoint_input(
            RestrictedRuntimeApplyConstructorInput {
                state_directory,
                socket_path,
                identity,
                transport_profile,
                resolved_profile_ref,
                expected_carrier,
                root_ca_certificate_file,
                listener_identity,
            },
        )
    }

    /// Constructs DeveloperLocal with the additive PXCC/PXDR Runtime-control
    /// protocol on one exact PXRP/PXCB restricted listener. The legacy apply
    /// constructor remains byte-for-byte bounded to PXRC/PXDS and unchanged.
    pub fn try_new_with_restricted_runtime_control_endpoint(
        state_directory: PathBuf,
        socket_path: PathBuf,
        identity: RuntimeDeveloperLocalIdentityV1,
        transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        resolved_profile_ref: [u8; 16],
        expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
        listener_credentials: (PathBuf, ResolvedRemoteMtlsIdentityFiles),
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        let (root_ca_certificate_file, listener_identity) = listener_credentials;
        Self::try_new(state_directory, socket_path, identity)?
            .try_with_restricted_runtime_control_endpoint(
                transport_profile,
                resolved_profile_ref,
                expected_carrier,
                root_ca_certificate_file,
                listener_identity,
            )
    }

    fn try_new_with_restricted_runtime_apply_endpoint_input(
        input: RestrictedRuntimeApplyConstructorInput,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        let RestrictedRuntimeApplyConstructorInput {
            state_directory,
            socket_path,
            identity,
            transport_profile,
            resolved_profile_ref,
            expected_carrier,
            root_ca_certificate_file,
            listener_identity,
        } = input;
        Self::try_new(state_directory, socket_path, identity)?
            .try_with_restricted_runtime_apply_endpoint(
                transport_profile,
                resolved_profile_ref,
                expected_carrier,
                root_ca_certificate_file,
                listener_identity,
            )
    }

    /// Adds one complete restricted Runtime listener to a configuration built
    /// with either the fail-closed resolver or an explicit provider resolver.
    /// All five values are mandatory and become one private dependency value;
    /// there is no partial endpoint state or raw endpoint-config bypass.
    pub fn try_with_restricted_runtime_apply_endpoint(
        mut self,
        transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        resolved_profile_ref: [u8; 16],
        expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
        root_ca_certificate_file: PathBuf,
        listener_identity: ResolvedRemoteMtlsIdentityFiles,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        if self.restricted_runtime_apply_endpoint.is_some() {
            return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
                "restricted Runtime endpoint is already configured",
            ));
        }
        let endpoint_config = RestrictedRuntimeApplyEndpointConfigV1::try_from_transport_profile(
            &transport_profile,
            resolved_profile_ref,
            &expected_carrier,
            root_ca_certificate_file,
            listener_identity,
        )
        .map_err(RuntimeDeveloperLocalError::RestrictedEndpointConfiguration)?;
        let provisioning = RuntimeProvisioningV1::try_new_developer_local(
            self.identity.provisioning_input(self.socket_path.clone()),
        )
        .map_err(|error| {
            RuntimeDeveloperLocalError::InvalidConfigurationOwned(error.to_string().into())
        })?;
        validate_restricted_runtime_apply_carrier_pins(&provisioning, &expected_carrier).map_err(
            |_| {
                RuntimeDeveloperLocalError::InvalidConfiguration(
                    "restricted Runtime endpoint does not match DeveloperLocal identity pins",
                )
            },
        )?;
        self.restricted_runtime_apply_endpoint = Some(
            RuntimeRestrictedApplyEndpointDependenciesV1::new(endpoint_config, expected_carrier),
        );
        Ok(self)
    }

    /// Adds one complete PXCC/PXDR restricted Runtime-control listener. This is
    /// an explicit opt-in and cannot replace either an existing G1 apply
    /// listener or a previously configured control listener.
    pub fn try_with_restricted_runtime_control_endpoint(
        mut self,
        transport_profile: RestrictedRuntimeApplyTransportProfileV1,
        resolved_profile_ref: [u8; 16],
        expected_carrier: RestrictedRuntimeApplyCarrierBindingV1,
        root_ca_certificate_file: PathBuf,
        listener_identity: ResolvedRemoteMtlsIdentityFiles,
    ) -> Result<Self, RuntimeDeveloperLocalError> {
        if self.restricted_runtime_apply_endpoint.is_some() {
            return Err(RuntimeDeveloperLocalError::InvalidConfiguration(
                "restricted Runtime endpoint is already configured",
            ));
        }
        let endpoint_config = RestrictedRuntimeControlEndpointConfigV1::try_from_transport_profile(
            &transport_profile,
            resolved_profile_ref,
            &expected_carrier,
            root_ca_certificate_file,
            listener_identity,
        )
        .map_err(RuntimeDeveloperLocalError::RestrictedEndpointConfiguration)?;
        let provisioning = RuntimeProvisioningV1::try_new_developer_local(
            self.identity.provisioning_input(self.socket_path.clone()),
        )
        .map_err(|error| {
            RuntimeDeveloperLocalError::InvalidConfigurationOwned(error.to_string().into())
        })?;
        validate_restricted_runtime_apply_carrier_pins(&provisioning, &expected_carrier).map_err(
            |_| {
                RuntimeDeveloperLocalError::InvalidConfiguration(
                    "restricted Runtime endpoint does not match DeveloperLocal identity pins",
                )
            },
        )?;
        self.restricted_runtime_apply_endpoint = Some(
            RuntimeRestrictedApplyEndpointDependenciesV1::new_runtime_control(
                endpoint_config,
                expected_carrier,
            ),
        );
        Ok(self)
    }
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

/// Immutable facts available only after recovery and UDS identity validation.
///
/// When a restricted Runtime endpoint is configured, readiness also proves
/// that its exact transport listener has started. This is transport readiness
/// only: legacy mode still returns the fixed generic remote rejection, and it
/// does not claim that the distributed Agent stack is `ActiveReady`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDeveloperLocalReadyV1 {
    state_directory: PathBuf,
    socket_path: PathBuf,
    runtime_store_instance_id: [u8; 32],
    target: [u8; 16],
    source_scope: [u8; 16],
    writer: [u8; 16],
    runtime_principal: [u8; 16],
    controller_principal: [u8; 16],
    authority_principal: [u8; 16],
    controller_request_key_ref: [u8; 16],
    runtime_response_key_ref: [u8; 16],
    tenure_authority_ref: [u8; 16],
    tenure_key_ref: [u8; 16],
    runtime_response_public_key: [u8; 32],
    runtime_uid: u32,
    runtime_gid: u32,
    controller_uid: u32,
    controller_gid: u32,
    compiled_build_instance_id: [u8; 32],
    manifest_canonical_wire: Box<[u8]>,
    manifest_digest: [u8; 32],
    channel_binding_digest: [u8; 32],
    runtime_control_describe_ready: RuntimeControlDescribeReadyFactsV1,
}

impl RuntimeDeveloperLocalReadyV1 {
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub const fn runtime_store_instance_id(&self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    pub const fn target(&self) -> [u8; 16] {
        self.target
    }

    pub const fn source_scope(&self) -> [u8; 16] {
        self.source_scope
    }

    pub const fn writer(&self) -> [u8; 16] {
        self.writer
    }

    pub const fn runtime_principal(&self) -> [u8; 16] {
        self.runtime_principal
    }

    pub const fn controller_principal(&self) -> [u8; 16] {
        self.controller_principal
    }

    pub const fn authority_principal(&self) -> [u8; 16] {
        self.authority_principal
    }

    pub const fn controller_request_key_ref(&self) -> [u8; 16] {
        self.controller_request_key_ref
    }

    pub const fn runtime_response_key_ref(&self) -> [u8; 16] {
        self.runtime_response_key_ref
    }

    pub const fn tenure_authority_ref(&self) -> [u8; 16] {
        self.tenure_authority_ref
    }

    pub const fn tenure_key_ref(&self) -> [u8; 16] {
        self.tenure_key_ref
    }

    pub const fn runtime_response_public_key(&self) -> [u8; 32] {
        self.runtime_response_public_key
    }

    pub const fn runtime_uid(&self) -> u32 {
        self.runtime_uid
    }

    pub const fn runtime_gid(&self) -> u32 {
        self.runtime_gid
    }

    pub const fn controller_uid(&self) -> u32 {
        self.controller_uid
    }

    pub const fn controller_gid(&self) -> u32 {
        self.controller_gid
    }

    pub const fn compiled_build_instance_id(&self) -> [u8; 32] {
        self.compiled_build_instance_id
    }

    pub fn manifest_canonical_wire(&self) -> &[u8] {
        &self.manifest_canonical_wire
    }

    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub const fn channel_binding_digest(&self) -> [u8; 32] {
        self.channel_binding_digest
    }

    /// Returns the immutable Runtime-local serving and channel facts that the
    /// same owner signs into a remote PXDR Describe response. This value is
    /// not a TLS channel, signer, or mutation capability.
    pub const fn runtime_control_describe_ready(&self) -> &RuntimeControlDescribeReadyFactsV1 {
        &self.runtime_control_describe_ready
    }
}

/// Running Runtime owner.  Drop requests shutdown; callers that need proof of
/// completed cleanup use [`Self::shutdown_and_join`].
pub struct RuntimeDeveloperLocalLifecycleV1 {
    ready: RuntimeDeveloperLocalReadyV1,
    handle_broker: RuntimeAgentHandleBroker,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), Box<str>>>>,
}

impl fmt::Debug for RuntimeDeveloperLocalLifecycleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDeveloperLocalLifecycleV1")
            .field("ready", &self.ready)
            .field("running", &self.thread.is_some())
            .finish_non_exhaustive()
    }
}

impl RuntimeDeveloperLocalLifecycleV1 {
    pub const fn ready(&self) -> &RuntimeDeveloperLocalReadyV1 {
        &self.ready
    }

    /// Issues the opaque conversation capability only for the byte-identical
    /// PXST ActiveReady terminal currently published by this Runtime owner.
    pub fn claim_agent_handle(
        &self,
        committed_pxst: &[u8],
    ) -> Result<RuntimeAgentConversationHandle, RuntimeDeveloperLocalError> {
        self.handle_broker
            .try_claim(committed_pxst)
            .map_err(|_| RuntimeDeveloperLocalError::AgentReceiptRejected)?
            .ok_or(RuntimeDeveloperLocalError::AgentNotReady)
    }

    /// Issues the same opaque conversation capability only for the
    /// byte-identical PXMT ActiveReady terminal durably committed by the
    /// managed Fabric+Model+Agent owner.
    pub fn claim_model_agent_handle(
        &self,
        committed_pxmt: &[u8],
    ) -> Result<RuntimeAgentConversationHandle, RuntimeDeveloperLocalError> {
        self.handle_broker
            .try_claim_model_agent(committed_pxmt)
            .map_err(|_| RuntimeDeveloperLocalError::AgentReceiptRejected)?
            .ok_or(RuntimeDeveloperLocalError::AgentNotReady)
    }

    /// Issues the same opaque conversation capability only for the exact
    /// restricted PXDS v2 alias registered by the trusted Runtime endpoint
    /// against its byte-identical published inner PXDS v1 ActiveReady receipt.
    pub fn claim_distributed_agent_handle(
        &self,
        committed_pxds2: &[u8],
    ) -> Result<RuntimeAgentConversationHandle, RuntimeDeveloperLocalError> {
        self.handle_broker
            .try_claim_restricted_distributed(committed_pxds2)
            .map_err(|_| RuntimeDeveloperLocalError::AgentReceiptRejected)?
            .ok_or(RuntimeDeveloperLocalError::AgentNotReady)
    }

    pub fn shutdown_and_join(mut self) -> Result<(), RuntimeDeveloperLocalError> {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> Result<(), RuntimeDeveloperLocalError> {
        let sender = self.shutdown.take();
        let thread = self.thread.take();
        if sender.is_none() && thread.is_none() {
            return Err(RuntimeDeveloperLocalError::ShutdownAlreadyRequested);
        }
        let signal_closed = sender.is_some_and(|sender| sender.send(()).is_err());
        if let Some(thread) = thread {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(message)) => {
                    return Err(RuntimeDeveloperLocalError::ServiceFailed(message));
                }
                Err(_) => return Err(RuntimeDeveloperLocalError::RuntimeThreadPanicked),
            }
        }
        if signal_closed {
            Err(RuntimeDeveloperLocalError::ShutdownChannelClosed)
        } else {
            Ok(())
        }
    }
}

impl Drop for RuntimeDeveloperLocalLifecycleV1 {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

struct ReadyTemplate {
    state_directory: PathBuf,
    socket_path: PathBuf,
    runtime_store_instance_id: [u8; 32],
    identity: RuntimeDeveloperLocalIdentityFactsV1,
    runtime_response_public_key: [u8; 32],
    runtime_uid: u32,
    runtime_gid: u32,
    controller_uid: u32,
    controller_gid: u32,
    compiled_build_instance_id: [u8; 32],
    manifest_canonical_wire: Box<[u8]>,
    manifest_digest: [u8; 32],
}

impl ReadyTemplate {
    fn bind(
        self,
        channel: paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1,
        runtime_control_describe_ready: RuntimeControlDescribeReadyFactsV1,
    ) -> Result<RuntimeDeveloperLocalReadyV1, RuntimeBootstrapEndpointError> {
        let serving = runtime_control_describe_ready.serving();
        if runtime_control_describe_ready.channel() != channel
            || serving.target() != RuntimeHostId::from_bytes(self.identity.target)
            || serving.runtime_store_instance_id() != self.runtime_store_instance_id
            || runtime_control_describe_ready.manifest_digest()
                != Digest32::from_bytes(self.manifest_digest)
            || runtime_control_describe_ready.build_instance_id() != self.compiled_build_instance_id
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        ReferenceBootstrapServingIdentityV1::try_new(
            serving.target(),
            serving.runtime_store_instance_id(),
            serving.snapshot_sequence(),
            serving.runtime_host_epoch(),
            serving.clock_domain(),
            serving.clock_generation(),
        )
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        Ok(RuntimeDeveloperLocalReadyV1 {
            state_directory: self.state_directory,
            socket_path: self.socket_path,
            runtime_store_instance_id: self.runtime_store_instance_id,
            target: self.identity.target,
            source_scope: self.identity.source_scope,
            writer: self.identity.writer,
            runtime_principal: self.identity.runtime_principal,
            controller_principal: self.identity.controller_principal,
            authority_principal: self.identity.authority_principal,
            controller_request_key_ref: self.identity.controller_request_key_ref,
            runtime_response_key_ref: self.identity.runtime_response_key_ref,
            tenure_authority_ref: self.identity.tenure_authority_ref,
            tenure_key_ref: self.identity.tenure_key_ref,
            runtime_response_public_key: self.runtime_response_public_key,
            runtime_uid: self.runtime_uid,
            runtime_gid: self.runtime_gid,
            controller_uid: self.controller_uid,
            controller_gid: self.controller_gid,
            compiled_build_instance_id: self.compiled_build_instance_id,
            manifest_canonical_wire: self.manifest_canonical_wire,
            manifest_digest: self.manifest_digest,
            channel_binding_digest: *channel.binding_digest().as_bytes(),
            runtime_control_describe_ready,
        })
    }
}

struct ReadyMessage {
    facts: RuntimeDeveloperLocalReadyV1,
    handle_broker: RuntimeAgentHandleBroker,
}

type ReadyResult = Result<ReadyMessage, Box<str>>;
type ReadinessSender = Arc<Mutex<Option<mpsc::SyncSender<ReadyResult>>>>;

struct DeveloperLocalThreadInput {
    state_directory: PathBuf,
    store_instance_id: [u8; 32],
    compiled: RuntimeCompiledInstallationFactsV1,
    provisioning: RuntimeProvisioningV1,
    dependencies: RuntimeManagedFabricServiceDependenciesV1,
    shutdown: oneshot::Receiver<()>,
    ready_template: ReadyTemplate,
    readiness: ReadinessSender,
}

/// Starts a real Runtime endpoint and waits until legacy recovery and the
/// authenticated UDS identity are ready. A configured restricted listener is
/// also bound before this function returns, but remains mutation-inert until
/// the first valid PXFB performs the one-way, same-listener PXMS cutover.
pub fn start_runtime_developer_local_v1(
    config: RuntimeDeveloperLocalConfigV1,
) -> Result<RuntimeDeveloperLocalLifecycleV1, RuntimeDeveloperLocalError> {
    let RuntimeDeveloperLocalConfigV1 {
        state_directory,
        socket_path,
        identity,
        provider_resolver,
        model_backend_resolver,
        distributed_agent_stack,
        restricted_runtime_apply_endpoint,
    } = config;
    let dependencies = RuntimeManagedFabricServiceDependenciesV1::new(
        provider_resolver,
        model_backend_resolver,
        distributed_agent_stack,
        restricted_runtime_apply_endpoint,
    );
    let identity_facts = identity.facts();
    let provisioning = RuntimeProvisioningV1::try_new_developer_local(
        identity.provisioning_input(socket_path.clone()),
    )
    .map_err(|error| RuntimeDeveloperLocalError::ProvisioningFailed(error.to_string().into()))?;

    let target_triple =
        developer_target_triple().ok_or(RuntimeDeveloperLocalError::InvalidConfiguration(
            "DeveloperLocal supports only x86_64/aarch64 macOS or GNU Linux",
        ))?;
    let executable = observe_current_executable()?;
    let compiled_build_instance_id =
        derive_developer_build_instance_id(executable.length, executable.sha256, target_triple)?;
    let compiled = runtime_compiled_installation_facts(
        RuntimeHostEmbeddedBuildMetadataV1::from_final_executable(
            compiled_build_instance_id,
            target_triple,
        ),
    )
    .map_err(|error| RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into()))?;
    let artifact = InstalledRuntimeArtifactObservationV1::try_new(
        executable.length,
        Digest32::from_bytes(executable.sha256),
        target_triple,
    )
    .map_err(|error| RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into()))?;
    let descriptor = generate_build_descriptor(&artifact, compiled).map_err(|error| {
        RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
    })?;
    let installation = generate_manifest(
        descriptor.canonical_wire(),
        descriptor.descriptor_digest(),
        RuntimeHostId::from_bytes(identity_facts.target),
        &artifact,
        compiled,
    )
    .map_err(|error| RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into()))?;

    let store_instance_id =
        match RuntimeInitializerPreflight::open_developer_local(&state_directory) {
            Ok(preflight) => {
                let input = RuntimeInitializationInputV1::try_new(
                    RuntimeInstallationEvidenceV1::new(
                        installation.descriptor_canonical_wire(),
                        installation.descriptor_digest(),
                        installation.manifest_canonical_wire(),
                        installation.manifest_digest(),
                        RuntimeHostId::from_bytes(identity_facts.target),
                        &artifact,
                        compiled,
                    ),
                    &provisioning,
                )
                .map_err(|error| {
                    RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
                })?;
                *initialize_runtime_store_after_preflight(preflight, input)
                    .map_err(|error| {
                        RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
                    })?
                    .store_instance_id()
            }
            Err(RuntimeInitializerBeginError::MarkerConsumed(_)) => {
                RuntimeStore::observe_developer_local_store_instance_id(
                    &state_directory,
                    provisioning.owner_target_fingerprint(),
                )
                .map_err(|error| {
                    RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
                })?
            }
            Err(error) => {
                return Err(RuntimeDeveloperLocalError::InitializationFailed(
                    error.to_string().into(),
                ));
            }
        };

    let ready_template = ReadyTemplate {
        state_directory: state_directory.clone(),
        socket_path,
        runtime_store_instance_id: store_instance_id,
        identity: identity_facts,
        runtime_response_public_key: provisioning.runtime_response_public_key(),
        runtime_uid: provisioning.runtime_uid(),
        runtime_gid: provisioning.runtime_gid(),
        controller_uid: provisioning.controller_uid(),
        controller_gid: provisioning.controller_gid(),
        compiled_build_instance_id,
        manifest_canonical_wire: installation.manifest_canonical_wire().into(),
        manifest_digest: *installation.manifest_digest().as_bytes(),
    };

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let readiness = Arc::new(Mutex::new(Some(ready_sender)));
    let readiness_for_thread = Arc::clone(&readiness);
    let thread = thread::Builder::new()
        .name("paraegox-runtime-developer-local-v1".to_owned())
        .stack_size(DEVELOPER_LOCAL_RUNTIME_THREAD_STACK_BYTES)
        .spawn(move || {
            let result = run_developer_local_thread(DeveloperLocalThreadInput {
                state_directory,
                store_instance_id,
                compiled,
                provisioning,
                dependencies,
                shutdown: shutdown_receiver,
                ready_template,
                readiness: Arc::clone(&readiness_for_thread),
            });
            if let Err(message) = &result
                && let Ok(mut sender) = readiness_for_thread.lock()
                && let Some(sender) = sender.take()
            {
                let _ = sender.send(Err(message.clone()));
            }
            result
        })
        .map_err(|error| RuntimeDeveloperLocalError::RuntimeThreadStart(error.kind()))?;

    let ready = match ready_receiver.recv_timeout(STARTUP_READY_TIMEOUT) {
        Ok(Ok(ready)) => ready,
        Ok(Err(message)) => {
            let _ = shutdown_sender.send(());
            let _ = thread.join();
            return Err(RuntimeDeveloperLocalError::StartupFailed(message));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = shutdown_sender.send(());
            let _ = thread.join();
            return Err(RuntimeDeveloperLocalError::ReadinessChannelClosed);
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = shutdown_sender.send(());
            let _ = thread.join();
            return Err(RuntimeDeveloperLocalError::StartupTimedOut);
        }
    };
    Ok(RuntimeDeveloperLocalLifecycleV1 {
        ready: ready.facts,
        handle_broker: ready.handle_broker,
        shutdown: Some(shutdown_sender),
        thread: Some(thread),
    })
}

fn run_developer_local_thread(input: DeveloperLocalThreadInput) -> Result<(), Box<str>> {
    let DeveloperLocalThreadInput {
        state_directory,
        store_instance_id,
        compiled,
        provisioning,
        dependencies,
        shutdown,
        ready_template,
        readiness,
    } = input;
    let runtime =
        build_managed_fabric_owner_runtime().map_err(|error| error.to_string().into_boxed_str())?;
    let result = runtime.block_on(serve_runtime_developer_local_until(
        &state_directory,
        store_instance_id,
        compiled,
        provisioning,
        dependencies,
        async move {
            shutdown.await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "DeveloperLocal shutdown owner dropped",
                )
            })
        },
        move |channel, runtime_control_describe_ready, handle_broker| {
            let facts = ready_template.bind(channel, runtime_control_describe_ready)?;
            let sender = readiness
                .lock()
                .map_err(|_| RuntimeBootstrapEndpointError::Runtime)?
                .take()
                .ok_or(RuntimeBootstrapEndpointError::Runtime)?;
            sender
                .send(Ok(ReadyMessage {
                    facts,
                    handle_broker,
                }))
                .map_err(|_| RuntimeBootstrapEndpointError::Runtime)
        },
    ));
    drop(runtime);
    result.map_err(|error| error.to_string().into_boxed_str())
}

fn derive_developer_build_instance_id(
    artifact_length: u64,
    artifact_sha256: [u8; 32],
    target_triple: &str,
) -> Result<[u8; 32], RuntimeDeveloperLocalError> {
    let mut builder = Digest32Builder::try_new(DEVELOPER_BUILD_ID_DOMAIN).map_err(|error| {
        RuntimeDeveloperLocalError::InitializationFailed(format!("{error:?}").into())
    })?;
    builder.field_u64(artifact_length).map_err(|error| {
        RuntimeDeveloperLocalError::InitializationFailed(format!("{error:?}").into())
    })?;
    builder.field_bytes(&artifact_sha256).map_err(|error| {
        RuntimeDeveloperLocalError::InitializationFailed(format!("{error:?}").into())
    })?;
    builder
        .field_bytes(target_triple.as_bytes())
        .map_err(|error| {
            RuntimeDeveloperLocalError::InitializationFailed(format!("{error:?}").into())
        })?;
    Ok(*builder.finish().as_bytes())
}

#[derive(Clone, Copy)]
struct ObservedDeveloperExecutable {
    length: u64,
    sha256: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    length: u64,
}

impl ExecutableIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
        }
    }
}

/// Reopens and hashes the actual DeveloperLocal executable.  The canonical
/// installation contract therefore receives a real observed length and
/// SHA-256, never a synthetic fixture value.  A changed, linked, writable, or
/// oversized executable fails before journal initialization.
fn observe_current_executable() -> Result<ObservedDeveloperExecutable, RuntimeDeveloperLocalError> {
    let path = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|error| {
            RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
        })?;
    let before = fs::symlink_metadata(&path).map_err(|error| {
        RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
    })?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != geteuid().as_raw()
        || before.gid() != getegid().as_raw()
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES
    {
        return Err(RuntimeDeveloperLocalError::InitializationFailed(
            "current DeveloperLocal executable failed identity policy".into(),
        ));
    }
    let owned = open(
        &path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into()))?;
    let mut file = File::from(owned);
    let opened = file.metadata().map_err(|error| {
        RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
    })?;
    let expected = ExecutableIdentity::from_metadata(&before);
    if ExecutableIdentity::from_metadata(&opened) != expected {
        return Err(RuntimeDeveloperLocalError::InitializationFailed(
            "current executable changed while opening".into(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut observed_length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
        })?;
        if read == 0 {
            break;
        }
        observed_length = observed_length
            .checked_add(u64::try_from(read).map_err(|_| {
                RuntimeDeveloperLocalError::InitializationFailed(
                    "current executable length overflow".into(),
                )
            })?)
            .ok_or_else(|| {
                RuntimeDeveloperLocalError::InitializationFailed(
                    "current executable length overflow".into(),
                )
            })?;
        if observed_length > MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES {
            return Err(RuntimeDeveloperLocalError::InitializationFailed(
                "current executable exceeds installation bound".into(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|error| {
        RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
    })?;
    let named_after = fs::symlink_metadata(&path).map_err(|error| {
        RuntimeDeveloperLocalError::InitializationFailed(error.to_string().into())
    })?;
    if observed_length != expected.length
        || ExecutableIdentity::from_metadata(&after) != expected
        || ExecutableIdentity::from_metadata(&named_after) != expected
    {
        return Err(RuntimeDeveloperLocalError::InitializationFailed(
            "current executable changed while hashing".into(),
        ));
    }
    Ok(ObservedDeveloperExecutable {
        length: observed_length,
        sha256: hasher.finalize().into(),
    })
}

const fn developer_target_triple() -> Option<&'static str> {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        Some("aarch64-apple-darwin")
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        Some("x86_64-apple-darwin")
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        Some("aarch64-unknown-linux-gnu")
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        Some("x86_64-unknown-linux-gnu")
    }
    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "linux")
    )))]
    {
        None
    }
}

/// Public fail-closed DeveloperLocal lifecycle error.
#[derive(Debug)]
pub enum RuntimeDeveloperLocalError {
    InvalidConfiguration(&'static str),
    InvalidConfigurationOwned(Box<str>),
    RestrictedEndpointConfiguration(RestrictedRuntimeApplyConfigErrorV1),
    ProvisioningFailed(Box<str>),
    InitializationFailed(Box<str>),
    RuntimeThreadStart(io::ErrorKind),
    StartupFailed(Box<str>),
    StartupTimedOut,
    ReadinessChannelClosed,
    AgentReceiptRejected,
    AgentNotReady,
    ShutdownAlreadyRequested,
    ShutdownChannelClosed,
    RuntimeThreadPanicked,
    ServiceFailed(Box<str>),
}

impl RuntimeDeveloperLocalError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration(_) | Self::InvalidConfigurationOwned(_) => {
                "PXDL-CONFIG-INVALID"
            }
            Self::RestrictedEndpointConfiguration(_) => "PXDL-RESTRICTED-ENDPOINT-INVALID",
            Self::ProvisioningFailed(_) => "PXDL-PROVISIONING-FAILED",
            Self::InitializationFailed(_) => "PXDL-INITIALIZATION-FAILED",
            Self::RuntimeThreadStart(_) => "PXDL-THREAD-START-FAILED",
            Self::StartupFailed(_) | Self::StartupTimedOut | Self::ReadinessChannelClosed => {
                "PXDL-STARTUP-FAILED"
            }
            Self::AgentReceiptRejected => "PXDL-PXST-REJECTED",
            Self::AgentNotReady => "PXDL-AGENT-NOT-READY",
            Self::ShutdownAlreadyRequested | Self::ShutdownChannelClosed => "PXDL-SHUTDOWN-FAILED",
            Self::RuntimeThreadPanicked | Self::ServiceFailed(_) => "PXDL-SERVICE-FAILED",
        }
    }
}

impl fmt::Display for RuntimeDeveloperLocalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => formatter.write_str(message),
            Self::InvalidConfigurationOwned(message)
            | Self::ProvisioningFailed(message)
            | Self::InitializationFailed(message)
            | Self::StartupFailed(message)
            | Self::ServiceFailed(message) => formatter.write_str(message),
            Self::RestrictedEndpointConfiguration(error) => {
                write!(formatter, "restricted Runtime endpoint: {error}")
            }
            Self::RuntimeThreadStart(kind) => write!(formatter, "Runtime thread start: {kind:?}"),
            Self::ReadinessChannelClosed => formatter.write_str("Runtime readiness channel closed"),
            Self::StartupTimedOut => formatter.write_str("Runtime readiness timed out"),
            Self::AgentReceiptRejected => {
                formatter.write_str("committed Agent terminal claim was rejected")
            }
            Self::AgentNotReady => {
                formatter.write_str("no committed ActiveReady Agent is published")
            }
            Self::ShutdownAlreadyRequested => formatter.write_str("shutdown was already requested"),
            Self::ShutdownChannelClosed => formatter.write_str("Runtime shutdown channel closed"),
            Self::RuntimeThreadPanicked => formatter.write_str("Runtime owner thread panicked"),
        }
    }
}

impl std::error::Error for RuntimeDeveloperLocalError {}

#[cfg(test)]
mod tests {
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::net::Shutdown;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use nix::unistd::{Gid, chown, getegid};
    use paraegox_evidence::{EvidenceOwnerRefV1, EvidenceRetentionPolicyV1, EvidenceStoreEpochV1};
    use paraegox_fabric::{ResolvedRemoteMtlsIdentityFiles, RestrictedRuntimeApplyConfigErrorV1};
    use paraegox_kernel::{
        digest::Digest32,
        identity::{PrincipalRef, RuntimeHostId},
    };
    use paraegox_runtime_contracts::{
        distributed_agent_stack_plan::{
            DistributedFabricCredentialRefV1, DistributedFabricTrustAnchorRefV1,
            DistributedFabricTrustDomainRefV1, RestrictedRuntimeApplyCarrierBindingFieldsV1,
            RestrictedRuntimeApplyCarrierBindingV1, RestrictedRuntimeApplyTransportProfileFieldsV1,
            RestrictedRuntimeApplyTransportProfileV1,
        },
        installation::verify_immutable_manifest_ingress,
        managed_fabric_plan::ManagedFabricManifestProjectionV1,
        managed_serving_bootstrap::{
            ManagedServingBootstrapRequestDraftV1, ManagedServingBootstrapRequestIdV1,
            ManagedServingBootstrapRequestV1, ManagedServingBootstrapResponseV1,
            ManagedServingReadinessV1,
        },
        provenance::SourceScopeRef,
        reference_control::{
            ReferenceChannelBindingV1, ed25519_control_key_fingerprint,
            reference_local_control_endpoint_identity_digest_v1,
            reference_runtime_peer_credentials_digest_v1,
        },
        wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim},
    };
    use zeroize::Zeroizing;

    use super::{
        RuntimeDeveloperLocalConfigV1, RuntimeDeveloperLocalDistributedAgentStackConfigV1,
        RuntimeDeveloperLocalError, RuntimeDeveloperLocalIdentityRefsV1,
        RuntimeDeveloperLocalIdentityV1, RuntimeDeveloperLocalReadyV1,
        RuntimeDeveloperLocalSigningSeedsV1, RuntimeProvisioningV1,
        start_runtime_developer_local_v1,
    };
    use crate::admission::{ED25519_ALGORITHM, ED25519_ALGORITHM_VERSION};
    use crate::distributed_fabric_runtime::{
        RuntimeFabricCredentialRequirementV1, RuntimeFabricCredentialResolveErrorV2,
        RuntimeFabricCredentialResolverV2, RuntimeResolvedFabricPeerCredentialV2,
    };
    use crate::managed_model_runtime::UnavailableRuntimeModelBackendResolver;
    use crate::runtime_agent_provider::UnavailableRuntimeAgentProviderResolver;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const RESTRICTED_PROFILE_REF: [u8; 16] = [0x46; 16];
    const RESTRICTED_ROUTE: &str = "paraegox/runtime/developer-local/restricted/apply";

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

    fn distributed_config(
        evidence_store_root: PathBuf,
    ) -> RuntimeDeveloperLocalDistributedAgentStackConfigV1 {
        RuntimeDeveloperLocalDistributedAgentStackConfigV1::try_new(
            Arc::new(FailClosedFabricCredentialResolver),
            evidence_store_root,
            EvidenceStoreEpochV1::try_from_bytes([0x51; 16])
                .unwrap_or_else(|error| panic!("Evidence epoch rejected: {error}")),
            EvidenceOwnerRefV1::try_from_bytes([0x52; 16])
                .unwrap_or_else(|error| panic!("Evidence owner rejected: {error}")),
            EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
                .unwrap_or_else(|error| panic!("Evidence retention rejected: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("distributed config rejected: {error}"))
    }

    fn restricted_transport_profile() -> RestrictedRuntimeApplyTransportProfileV1 {
        RestrictedRuntimeApplyTransportProfileV1::try_new(
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                target: RuntimeHostId::from_bytes([2; 16]),
                endpoint_ref: [0x41; 16],
                endpoint_generation: 1,
                tls_listener_locator: "tls/192.0.2.10:7447",
                route: RESTRICTED_ROUTE,
                trust_domain_ref: DistributedFabricTrustDomainRefV1::try_from_bytes([0x42; 16])
                    .unwrap_or_else(|error| panic!("trust domain rejected: {error}")),
                trust_anchor_ref: DistributedFabricTrustAnchorRefV1::try_from_bytes([0x43; 16])
                    .unwrap_or_else(|error| panic!("trust anchor rejected: {error}")),
                controller_connector_credential_ref:
                    DistributedFabricCredentialRefV1::try_from_bytes([0x44; 16])
                        .unwrap_or_else(|error| panic!("Controller credential rejected: {error}")),
                runtime_listener_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                    [0x45; 16],
                )
                .unwrap_or_else(|error| panic!("Runtime credential rejected: {error}")),
                controller_principal: PrincipalRef::from_bytes([6; 16]),
                runtime_principal: PrincipalRef::from_bytes([5; 16]),
                operation_timeout_nanos: 5_000_000_000,
            },
        )
        .unwrap_or_else(|error| panic!("restricted transport profile rejected: {error}"))
    }

    fn restricted_carrier(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        restricted_carrier_with_runtime_response_key(profile, ApplyAuthKeyRef::from_bytes([9; 16]))
    }

    fn restricted_carrier_with_runtime_response_key(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        runtime_response_key: ApplyAuthKeyRef,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        let controller_key_fingerprint = ed25519_control_key_fingerprint(
            SigningKey::from_bytes(&[21; 32]).verifying_key().as_bytes(),
        )
        .unwrap_or_else(|error| panic!("Controller key fingerprint failed: {error}"));
        let runtime_response_key_fingerprint = ed25519_control_key_fingerprint(
            SigningKey::from_bytes(&[23; 32]).verifying_key().as_bytes(),
        )
        .unwrap_or_else(|error| panic!("Runtime key fingerprint failed: {error}"));
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: profile.target(),
                runtime_principal: profile.runtime_principal(),
                controller_principal: profile.controller_principal(),
                endpoint_ref: profile.endpoint_ref(),
                endpoint_generation: profile.endpoint_generation(),
                route: profile.route(),
                controller_request_key: ApplyAuthKeyRef::from_bytes([8; 16]),
                controller_request_key_fingerprint: controller_key_fingerprint,
                runtime_response_key,
                runtime_response_key_fingerprint,
                control_transport_profile_ref: RESTRICTED_PROFILE_REF,
                control_transport_profile_digest: profile.profile_digest(),
            },
        )
        .unwrap_or_else(|error| panic!("restricted carrier rejected: {error}"))
    }

    fn restricted_listener_identity() -> ResolvedRemoteMtlsIdentityFiles {
        ResolvedRemoteMtlsIdentityFiles::try_new(
            PathBuf::from("/tmp/paraegox-developer-local-runtime.pem"),
            PathBuf::from("/tmp/paraegox-developer-local-runtime.key"),
        )
        .unwrap_or_else(|error| panic!("restricted listener identity rejected: {error}"))
    }

    struct TestLayout {
        root: PathBuf,
        state: PathBuf,
        socket: PathBuf,
    }

    impl TestLayout {
        fn new() -> Self {
            let base = PathBuf::from("/tmp")
                .canonicalize()
                .unwrap_or_else(|error| panic!("temp directory canonicalization failed: {error}"));
            let root = base.join(format!(
                "pxdl-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            let state = root.join("rt");
            let run = root.join("run");
            create_directory(&root, 0o700);
            create_directory(&state, 0o700);
            create_directory(&run, 0o2750);
            Self {
                socket: run.join("r.sock"),
                root,
                state,
            }
        }
    }

    impl Drop for TestLayout {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("pxdl-"))
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn create_directory(path: &Path, mode: u32) {
        let mut builder = DirBuilder::new();
        builder.mode(mode);
        builder
            .create(path)
            .unwrap_or_else(|error| panic!("test directory creation failed: {error}"));
        chown(path, None, Some(Gid::from_raw(getegid().as_raw())))
            .unwrap_or_else(|error| panic!("test directory chgrp failed: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .unwrap_or_else(|error| panic!("test directory chmod failed: {error}"));
    }

    fn identity_refs() -> RuntimeDeveloperLocalIdentityRefsV1 {
        RuntimeDeveloperLocalIdentityRefsV1 {
            installation_id: [1; 16],
            target: [2; 16],
            source_scope: [3; 16],
            writer: [4; 16],
            runtime_principal: [5; 16],
            controller_principal: [6; 16],
            authority_principal: [7; 16],
            controller_request_key_ref: [8; 16],
            runtime_response_key_ref: [9; 16],
            tenure_authority_ref: [10; 16],
            tenure_key_ref: [11; 16],
        }
    }

    fn identity() -> RuntimeDeveloperLocalIdentityV1 {
        RuntimeDeveloperLocalIdentityV1::try_new_with_verification_keys(
            identity_refs(),
            SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes(),
            SigningKey::from_bytes(&[22; 32]).verifying_key().to_bytes(),
            Zeroizing::new([23; 32]),
        )
        .unwrap_or_else(|error| panic!("identity rejected: {error}"))
    }

    fn config(layout: &TestLayout) -> RuntimeDeveloperLocalConfigV1 {
        RuntimeDeveloperLocalConfigV1::try_new(
            layout.state.clone(),
            layout.socket.clone(),
            identity(),
        )
        .unwrap_or_else(|error| panic!("config rejected: {error}"))
    }

    fn live_channel(ready: &RuntimeDeveloperLocalReadyV1) -> ReferenceChannelBindingV1 {
        let metadata = fs::symlink_metadata(ready.socket_path())
            .unwrap_or_else(|error| panic!("live socket metadata failed: {error}"));
        let endpoint = reference_local_control_endpoint_identity_digest_v1(
            ready.socket_path().as_os_str().as_bytes(),
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o7777,
        )
        .unwrap_or_else(|error| panic!("endpoint identity rejected: {error}"));
        let peer = reference_runtime_peer_credentials_digest_v1(
            ready.runtime_uid(),
            ready.runtime_gid(),
            u64::from(std::process::id()),
        )
        .unwrap_or_else(|error| panic!("peer identity rejected: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            RuntimeHostId::from_bytes(ready.target()),
            PrincipalRef::from_bytes(ready.runtime_principal()),
            endpoint,
            peer,
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        assert_eq!(
            channel.binding_digest().as_bytes(),
            &ready.channel_binding_digest()
        );
        channel
    }

    fn managed_bootstrap_request(
        ready: &RuntimeDeveloperLocalReadyV1,
        channel: ReferenceChannelBindingV1,
        request_id: [u8; 16],
        nonce: &[u8],
    ) -> ManagedServingBootstrapRequestV1 {
        let manifest = verify_immutable_manifest_ingress(
            ready.manifest_canonical_wire(),
            Digest32::from_bytes(ready.manifest_digest()),
        )
        .unwrap_or_else(|error| panic!("manifest ingress rejected: {error}"));
        let projection =
            ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(&manifest)
                .unwrap_or_else(|error| panic!("managed projection rejected: {error}"));
        let claim = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes(ready.controller_principal()),
            ApplyAuthKeyRef::from_bytes(ready.controller_request_key_ref()),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("algorithm rejected: {error}")),
            ED25519_ALGORITHM_VERSION,
            nonce,
        )
        .unwrap_or_else(|error| panic!("claim rejected: {error}"));
        let draft = ManagedServingBootstrapRequestDraftV1::try_new(
            ManagedServingBootstrapRequestIdV1::try_from_bytes(request_id)
                .unwrap_or_else(|error| panic!("request id rejected: {error}")),
            RuntimeHostId::from_bytes(ready.target()),
            SourceScopeRef::from_bytes(ready.source_scope()),
            ready.runtime_store_instance_id(),
            projection,
            channel,
            claim,
        )
        .unwrap_or_else(|error| panic!("PXFB draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&[21; 32])
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("PXFB transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("PXFB finalization failed: {error}"))
    }

    fn exchange_frame(socket_path: &Path, frame: &[u8]) -> io::Result<Box<[u8]>> {
        let mut stream = UnixStream::connect(socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let length = u32::try_from(frame.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "oversized test frame"))?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(frame)?;
        stream.shutdown(Shutdown::Write)?;

        let mut header = [0_u8; 4];
        stream.read_exact(&mut header)?;
        let response_length = usize::try_from(u32::from_be_bytes(header))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response length"))?;
        if response_length == 0 || response_length > 4_096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "out-of-bounds response",
            ));
        }
        let mut response = vec![0_u8; response_length];
        stream.read_exact(&mut response)?;
        Ok(response.into_boxed_slice())
    }

    fn assert_rejected(socket_path: &Path, frame: &[u8]) {
        assert!(
            exchange_frame(socket_path, frame).is_err(),
            "rejected protocol frame unexpectedly received a response"
        );
    }

    fn validated_response(
        ready: &RuntimeDeveloperLocalReadyV1,
        request: &ManagedServingBootstrapRequestV1,
        channel: ReferenceChannelBindingV1,
        wire: &[u8],
    ) -> ManagedServingBootstrapResponseV1 {
        let response = ManagedServingBootstrapResponseV1::decode(wire)
            .unwrap_or_else(|error| panic!("PXFR decode failed: {error}"));
        let facts = response
            .validate_against_request(request, channel)
            .unwrap_or_else(|error| panic!("PXFR correlation failed: {error}"));
        assert_eq!(facts.readiness(), ManagedServingReadinessV1::RecoveredReady);
        assert_eq!(
            response.authentication_key().as_bytes(),
            &ready.runtime_response_key_ref()
        );
        let public_key = VerifyingKey::from_bytes(&ready.runtime_response_public_key())
            .unwrap_or_else(|error| panic!("Runtime response key rejected: {error}"));
        let signature = Signature::from_slice(response.authentication_signature())
            .unwrap_or_else(|error| panic!("Runtime response signature rejected: {error}"));
        public_key
            .verify(
                response
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("PXFR transcript failed: {error}"))
                    .as_bytes(),
                &signature,
            )
            .unwrap_or_else(|error| panic!("PXFR authentication failed: {error}"));
        response
    }

    #[test]
    fn split_trust_constructor_matches_legacy_provisioning() {
        let layout = TestLayout::new();
        let legacy_identity = RuntimeDeveloperLocalIdentityV1::try_new(
            identity_refs(),
            RuntimeDeveloperLocalSigningSeedsV1::new([21; 32], [22; 32], [23; 32]),
        )
        .unwrap_or_else(|error| panic!("legacy identity rejected: {error}"));
        let legacy = RuntimeProvisioningV1::try_new_developer_local(
            legacy_identity.provisioning_input(layout.socket.clone()),
        )
        .unwrap_or_else(|error| panic!("legacy provisioning rejected: {error}"));
        let split = RuntimeProvisioningV1::try_new_developer_local(
            identity().provisioning_input(layout.socket.clone()),
        )
        .unwrap_or_else(|error| panic!("split provisioning rejected: {error}"));

        assert_eq!(legacy.controller_key(), split.controller_key());
        assert_eq!(
            legacy.runtime_response_public_key(),
            split.runtime_response_public_key()
        );
        assert_eq!(
            legacy.owner_target_fingerprint(),
            split.owner_target_fingerprint()
        );
        assert_eq!(
            legacy.admission_policy_fingerprint(),
            split.admission_policy_fingerprint()
        );
        assert_eq!(
            legacy.channel_policy_fingerprint(),
            split.channel_policy_fingerprint()
        );
        assert_eq!(
            legacy.controller_key_fingerprint(),
            split.controller_key_fingerprint()
        );
    }

    #[test]
    fn split_trust_constructor_rejects_weak_aliased_or_missing_key_material() {
        let controller_key = SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes();
        let tenure_key = SigningKey::from_bytes(&[22; 32]).verifying_key().to_bytes();
        let response_key = SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes();
        let mut weak_key = [0_u8; 32];
        weak_key[0] = 1;
        assert!(
            VerifyingKey::from_bytes(&weak_key)
                .unwrap_or_else(|error| panic!("weak test key did not parse: {error}"))
                .is_weak()
        );

        for result in [
            RuntimeDeveloperLocalIdentityV1::try_new_with_verification_keys(
                identity_refs(),
                weak_key,
                tenure_key,
                Zeroizing::new([23; 32]),
            ),
            RuntimeDeveloperLocalIdentityV1::try_new_with_verification_keys(
                identity_refs(),
                controller_key,
                controller_key,
                Zeroizing::new([23; 32]),
            ),
            RuntimeDeveloperLocalIdentityV1::try_new_with_verification_keys(
                identity_refs(),
                controller_key,
                tenure_key,
                Zeroizing::new([0; 32]),
            ),
            RuntimeDeveloperLocalIdentityV1::try_new_with_verification_keys(
                identity_refs(),
                response_key,
                tenure_key,
                Zeroizing::new([23; 32]),
            ),
            RuntimeDeveloperLocalIdentityV1::try_new_with_verification_keys(
                identity_refs(),
                controller_key,
                response_key,
                Zeroizing::new([23; 32]),
            ),
        ] {
            assert!(matches!(
                result,
                Err(RuntimeDeveloperLocalError::InvalidConfiguration(_))
            ));
        }
    }

    #[test]
    fn default_constructors_keep_optional_composition_dependencies_disabled() {
        let legacy_layout = TestLayout::new();
        let legacy = config(&legacy_layout);
        assert!(legacy.distributed_agent_stack.is_none());
        assert!(legacy.restricted_runtime_apply_endpoint.is_none());

        let provider_layout = TestLayout::new();
        let provider = RuntimeDeveloperLocalConfigV1::try_new_with_provider_resolver(
            provider_layout.state.clone(),
            provider_layout.socket.clone(),
            identity(),
            Arc::new(UnavailableRuntimeAgentProviderResolver),
        )
        .unwrap_or_else(|error| panic!("provider config rejected: {error}"));
        assert!(provider.distributed_agent_stack.is_none());
        assert!(provider.restricted_runtime_apply_endpoint.is_none());

        let combined_layout = TestLayout::new();
        let combined = RuntimeDeveloperLocalConfigV1::try_new_with_agent_and_model_resolvers(
            combined_layout.state.clone(),
            combined_layout.socket.clone(),
            identity(),
            Arc::new(UnavailableRuntimeAgentProviderResolver),
            Arc::new(UnavailableRuntimeModelBackendResolver),
        )
        .unwrap_or_else(|error| panic!("combined resolver config rejected: {error}"));
        assert!(combined.distributed_agent_stack.is_none());
        assert!(combined.restricted_runtime_apply_endpoint.is_none());
    }

    #[test]
    fn complete_distributed_input_pins_evidence_and_redacts_debug() {
        let layout = TestLayout::new();
        let evidence_root = layout.root.join("evidence");
        let distributed = distributed_config(evidence_root.clone());

        assert_eq!(distributed.evidence_store_config.root(), evidence_root);
        assert_eq!(
            distributed.evidence_store_config.store_epoch().as_bytes(),
            &[0x51; 16]
        );
        assert_eq!(
            distributed.evidence_store_config.owner_ref().as_bytes(),
            &[0x52; 16]
        );
        assert_eq!(
            distributed.evidence_store_config.retention_policy(),
            EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
                .unwrap_or_else(|error| panic!("Evidence retention rejected: {error:?}"))
        );
        let debug = format!("{distributed:?}");
        assert_eq!(
            debug,
            "RuntimeDeveloperLocalDistributedAgentStackConfigV1(<redacted>)"
        );
        assert!(!debug.contains(evidence_root.to_string_lossy().as_ref()));

        let configured = config(&layout)
            .try_with_distributed_agent_stack(distributed)
            .unwrap_or_else(|error| panic!("distributed injection rejected: {error}"));
        assert!(configured.distributed_agent_stack.is_some());
        assert!(configured.restricted_runtime_apply_endpoint.is_none());
    }

    #[test]
    fn invalid_or_overlapping_distributed_evidence_root_fails_before_start() {
        let invalid = RuntimeDeveloperLocalDistributedAgentStackConfigV1::try_new(
            Arc::new(FailClosedFabricCredentialResolver),
            PathBuf::from("relative/evidence"),
            EvidenceStoreEpochV1::try_from_bytes([0x51; 16])
                .unwrap_or_else(|error| panic!("Evidence epoch rejected: {error}")),
            EvidenceOwnerRefV1::try_from_bytes([0x52; 16])
                .unwrap_or_else(|error| panic!("Evidence owner rejected: {error}")),
            EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
                .unwrap_or_else(|error| panic!("Evidence retention rejected: {error:?}")),
        )
        .expect_err("relative Evidence root must fail closed");
        assert!(matches!(
            invalid,
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "distributed Evidence store root must be absolute and normalized"
            )
        ));

        let layout = TestLayout::new();
        let overlapping = distributed_config(layout.state.join("evidence"));
        let overlap_error = config(&layout)
            .try_with_distributed_agent_stack(overlapping)
            .expect_err("Evidence root inside Runtime state must fail closed");
        assert!(matches!(
            overlap_error,
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "distributed Evidence store root must not overlap Runtime state or socket paths"
            )
        ));
    }

    #[test]
    fn duplicate_distributed_injection_fails_without_replacing_authority() {
        let layout = TestLayout::new();
        let configured = config(&layout)
            .try_with_distributed_agent_stack(distributed_config(layout.root.join("evidence")))
            .unwrap_or_else(|error| panic!("first distributed injection rejected: {error}"));
        let error = configured
            .try_with_distributed_agent_stack(distributed_config(
                layout.root.join("replacement-evidence"),
            ))
            .expect_err("a second distributed injection must fail closed");
        assert!(matches!(
            error,
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "distributed Agent stack is already configured"
            )
        ));
    }

    #[test]
    fn distributed_dependencies_are_wired_to_the_runtime_owner_without_network_start() {
        let source = include_str!("runtime_developer_local.rs");
        let start = source
            .split_once("pub fn start_runtime_developer_local_v1")
            .and_then(|(_, tail)| tail.split_once("fn run_developer_local_thread"))
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing DeveloperLocal start implementation"));
        assert!(start.contains("distributed_agent_stack,"));
        assert!(start.contains("RuntimeManagedFabricServiceDependenciesV1::new("));
        assert!(!start.contains("model_backend_resolver,\n        None,"));

        let config_impl = source
            .split_once("impl RuntimeDeveloperLocalConfigV1")
            .and_then(|(_, tail)| tail.split_once("pub struct RuntimeDeveloperLocalReadyV1"))
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing DeveloperLocal config implementation"));
        assert!(config_impl.contains("distributed_agent_stack: None"));
        assert!(config_impl.contains("self.distributed_agent_stack = Some("));
        assert!(config_impl.contains("distributed Agent stack is already configured"));

        let lifecycle = source
            .split_once("impl RuntimeDeveloperLocalLifecycleV1")
            .and_then(|(_, tail)| tail.split_once("impl Drop for RuntimeDeveloperLocalLifecycleV1"))
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing DeveloperLocal lifecycle implementation"));
        let restricted_claim = lifecycle
            .split_once("pub fn claim_distributed_agent_handle")
            .and_then(|(_, tail)| tail.split_once("pub fn shutdown_and_join"))
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing restricted distributed handle claim"));
        assert!(restricted_claim.contains(".try_claim_restricted_distributed(committed_pxds2)"));
        assert!(!restricted_claim.contains(".try_claim_distributed("));
    }

    #[test]
    fn complete_restricted_endpoint_input_maps_immediately_and_debug_is_redacted() {
        let layout = TestLayout::new();
        let profile = restricted_transport_profile();
        let carrier = restricted_carrier(&profile);
        let configured =
            RuntimeDeveloperLocalConfigV1::try_new_with_restricted_runtime_apply_endpoint(
                layout.state.clone(),
                layout.socket.clone(),
                identity(),
                profile,
                RESTRICTED_PROFILE_REF,
                carrier,
                (
                    PathBuf::from("/tmp/paraegox-developer-local-root-ca.pem"),
                    restricted_listener_identity(),
                ),
            )
            .unwrap_or_else(|error| panic!("restricted config rejected: {error}"));

        assert!(configured.restricted_runtime_apply_endpoint.is_some());
        assert!(configured.distributed_agent_stack.is_none());
        assert_eq!(
            format!("{configured:?}"),
            "RuntimeDeveloperLocalConfigV1(<redacted>)"
        );
    }

    #[test]
    fn runtime_control_endpoint_is_an_explicit_g2_opt_in_and_blocks_cross_protocol_replacement() {
        let layout = TestLayout::new();
        let profile = restricted_transport_profile();
        let carrier = restricted_carrier(&profile);
        let configured =
            RuntimeDeveloperLocalConfigV1::try_new_with_restricted_runtime_control_endpoint(
                layout.state.clone(),
                layout.socket.clone(),
                identity(),
                profile,
                RESTRICTED_PROFILE_REF,
                carrier,
                (
                    PathBuf::from("/tmp/paraegox-developer-local-root-ca.pem"),
                    restricted_listener_identity(),
                ),
            )
            .unwrap_or_else(|error| panic!("Runtime-control config rejected: {error}"));
        let dependency_debug = format!(
            "{:?}",
            configured
                .restricted_runtime_apply_endpoint
                .as_ref()
                .unwrap_or_else(|| panic!("Runtime-control dependency disappeared"))
        );
        assert!(dependency_debug.contains("protocol: RuntimeControl"));
        assert!(!dependency_debug.contains("paraegox-developer-local-runtime.key"));

        let replacement_profile = restricted_transport_profile();
        let replacement_carrier = restricted_carrier(&replacement_profile);
        let error = configured
            .try_with_restricted_runtime_apply_endpoint(
                replacement_profile,
                RESTRICTED_PROFILE_REF,
                replacement_carrier,
                PathBuf::from("/tmp/paraegox-developer-local-other-root-ca.pem"),
                restricted_listener_identity(),
            )
            .expect_err("G1 apply must not replace an installed G2 control endpoint");
        assert!(matches!(
            error,
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "restricted Runtime endpoint is already configured"
            )
        ));

        let source = include_str!("runtime_developer_local.rs");
        let g2 = source
            .split_once("pub fn try_new_with_restricted_runtime_control_endpoint")
            .and_then(|(_, tail)| {
                tail.split_once("fn try_new_with_restricted_runtime_apply_endpoint_input")
            })
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing explicit G2 constructor"));
        assert!(g2.contains("try_with_restricted_runtime_control_endpoint"));
        assert!(!g2.contains("RuntimeDeveloperLocalSigningSeedsV1"));
        let g2_builder = source
            .split_once("pub fn try_with_restricted_runtime_control_endpoint")
            .and_then(|(_, tail)| tail.split_once("\n    }\n}"))
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing explicit G2 builder"));
        assert!(
            g2_builder
                .contains("RestrictedRuntimeControlEndpointConfigV1::try_from_transport_profile")
        );
        assert!(
            g2_builder
                .contains("RuntimeRestrictedApplyEndpointDependenciesV1::new_runtime_control")
        );
        assert!(!g2_builder.contains("RuntimeDeveloperLocalSigningSeedsV1"));
    }

    #[test]
    fn mismatched_profile_ref_is_rejected_during_config_construction() {
        let layout = TestLayout::new();
        let profile = restricted_transport_profile();
        let carrier = restricted_carrier(&profile);
        let error = config(&layout)
            .try_with_restricted_runtime_apply_endpoint(
                profile,
                [0x47; 16],
                carrier,
                PathBuf::from("/tmp/paraegox-developer-local-root-ca.pem"),
                restricted_listener_identity(),
            )
            .expect_err("mismatched PXRP/PXCB profile ref must fail closed");
        assert!(matches!(
            error,
            RuntimeDeveloperLocalError::RestrictedEndpointConfiguration(
                RestrictedRuntimeApplyConfigErrorV1::ProfileCarrierMismatch
            )
        ));
    }

    #[test]
    fn carrier_identity_pin_mismatch_is_rejected_before_thread_start() {
        let layout = TestLayout::new();
        let profile = restricted_transport_profile();
        let carrier = restricted_carrier_with_runtime_response_key(
            &profile,
            ApplyAuthKeyRef::from_bytes([0x48; 16]),
        );
        let error = config(&layout)
            .try_with_restricted_runtime_apply_endpoint(
                profile,
                RESTRICTED_PROFILE_REF,
                carrier,
                PathBuf::from("/tmp/paraegox-developer-local-root-ca.pem"),
                restricted_listener_identity(),
            )
            .expect_err("carrier key pin drift must fail before thread startup");
        assert!(matches!(
            error,
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "restricted Runtime endpoint does not match DeveloperLocal identity pins"
            )
        ));
    }

    #[test]
    fn duplicate_restricted_endpoint_add_fails_without_replacing_generation() {
        let layout = TestLayout::new();
        let profile = restricted_transport_profile();
        let carrier = restricted_carrier(&profile);
        let configured = config(&layout)
            .try_with_restricted_runtime_apply_endpoint(
                profile,
                RESTRICTED_PROFILE_REF,
                carrier,
                PathBuf::from("/tmp/paraegox-developer-local-root-ca.pem"),
                restricted_listener_identity(),
            )
            .unwrap_or_else(|error| panic!("first restricted config rejected: {error}"));
        let replacement_profile = restricted_transport_profile();
        let replacement_carrier = restricted_carrier(&replacement_profile);
        let error = configured
            .try_with_restricted_runtime_apply_endpoint(
                replacement_profile,
                RESTRICTED_PROFILE_REF,
                replacement_carrier,
                PathBuf::from("/tmp/paraegox-developer-local-other-root-ca.pem"),
                restricted_listener_identity(),
            )
            .expect_err("a second restricted endpoint must not replace the first");
        assert!(matches!(
            error,
            RuntimeDeveloperLocalError::InvalidConfiguration(
                "restricted Runtime endpoint is already configured"
            )
        ));
    }

    #[test]
    fn restricted_endpoint_injection_has_no_raw_config_bypass_and_precedes_ready() {
        let source = include_str!("runtime_developer_local.rs");
        let config_impl = source
            .split_once("impl RuntimeDeveloperLocalConfigV1")
            .and_then(|(_, tail)| tail.split_once("pub struct RuntimeDeveloperLocalReadyV1"))
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing DeveloperLocal config implementation"));
        assert!(
            config_impl
                .contains("RestrictedRuntimeApplyEndpointConfigV1::try_from_transport_profile")
        );
        assert!(config_impl.contains("restricted_runtime_apply_endpoint: None"));
        assert!(config_impl.contains("restricted Runtime endpoint is already configured"));
        assert!(!config_impl.contains("endpoint_config: RestrictedRuntimeApplyEndpointConfigV1"));
        assert!(source.contains("RuntimeManagedFabricServiceDependenciesV1::new("));

        let endpoint_source = include_str!("runtime_control_endpoint.rs");
        let legacy = endpoint_source
            .split_once("async fn serve_developer_legacy_cutover_until")
            .and_then(|(_, tail)| tail.split_once("fn live_runtime_channel_from_state"))
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing legacy cutover service"));
        assert!(
            legacy
                .find("RunningRestrictedRuntimeApplyEndpointV1::start")
                .unwrap_or_else(|| panic!("missing restricted listener start"))
                < legacy
                    .find("if let Err(error) = ready")
                    .unwrap_or_else(|| panic!("missing readiness callback"))
        );
        assert_eq!(
            legacy
                .match_indices("RunningRestrictedRuntimeApplyEndpointV1::start")
                .count(),
            1,
            "fresh cutover must retain one endpoint generation"
        );
        assert!(legacy.contains("DeveloperLocalControlState::Legacy(_)"));
        assert!(legacy.contains("RuntimeRestrictedRemoteApplyErrorV1::Rejected"));
        assert!(legacy.contains("DeveloperLocalControlState::Managed(managed)"));
        assert!(legacy.contains("endpoint.shutdown().await"));
    }

    #[test]
    fn fresh_start_is_socket_ready_and_restart_observes_the_same_store() {
        let layout = TestLayout::new();
        let first = start_runtime_developer_local_v1(config(&layout))
            .unwrap_or_else(|error| panic!("fresh Runtime start failed: {error}"));
        assert_eq!(first.ready().socket_path(), layout.socket);
        assert!(layout.socket.exists());
        let store = first.ready().runtime_store_instance_id();
        let manifest = first.ready().manifest_canonical_wire().to_vec();
        first
            .shutdown_and_join()
            .unwrap_or_else(|error| panic!("fresh Runtime shutdown failed: {error}"));
        assert!(!layout.socket.exists());

        let restarted = start_runtime_developer_local_v1(config(&layout))
            .unwrap_or_else(|error| panic!("Runtime restart failed: {error}"));
        assert_eq!(restarted.ready().runtime_store_instance_id(), store);
        assert_eq!(restarted.ready().manifest_canonical_wire(), manifest);
        restarted
            .shutdown_and_join()
            .unwrap_or_else(|error| panic!("restarted Runtime shutdown failed: {error}"));
    }

    #[test]
    fn pxfb_is_the_authenticated_one_way_cutover_boundary_and_restart_is_managed() {
        let layout = TestLayout::new();
        let marker = layout.state.join("managed-fabric.cutover-v1");
        let runtime = start_runtime_developer_local_v1(config(&layout))
            .unwrap_or_else(|error| panic!("fresh Runtime start failed: {error}"));
        let store = runtime.ready().runtime_store_instance_id();
        let channel = live_channel(runtime.ready());
        let request = managed_bootstrap_request(
            runtime.ready(),
            channel,
            [0xa1; 16],
            b"developer-local-first-cutover",
        );

        assert!(!marker.exists());
        assert_rejected(&layout.socket, b"PXFB-not-a-canonical-request");
        assert!(
            !marker.exists(),
            "malformed PXFB published the cutover marker"
        );

        let mut wrong_signature = request.canonical_wire().to_vec();
        *wrong_signature
            .last_mut()
            .unwrap_or_else(|| panic!("canonical PXFB must be nonempty")) ^= 0x01;
        assert_rejected(&layout.socket, &wrong_signature);
        assert!(
            !marker.exists(),
            "unauthenticated PXFB published the cutover marker"
        );

        let first_wire = exchange_frame(&layout.socket, request.canonical_wire())
            .unwrap_or_else(|error| panic!("valid cutover PXFB failed: {error}"));
        assert!(marker.exists(), "valid PXFB did not durably publish PXMS");
        let first = validated_response(runtime.ready(), &request, channel, &first_wire);

        for legacy_family in [
            b"PXBR-rejected".as_slice(),
            b"PXQR-rejected",
            b"PXAR-rejected",
        ] {
            assert_rejected(&layout.socket, legacy_family);
        }

        let replay_wire = exchange_frame(&layout.socket, request.canonical_wire())
            .unwrap_or_else(|error| panic!("same-process PXFB retry failed: {error}"));
        let replay = validated_response(runtime.ready(), &request, channel, &replay_wire);
        assert_eq!(replay.facts().target(), first.facts().target());
        assert_eq!(
            replay.facts().runtime_store_instance_id(),
            first.facts().runtime_store_instance_id()
        );
        assert_eq!(replay.facts().projection(), first.facts().projection());
        assert_eq!(
            replay.facts().runtime_host_epoch(),
            first.facts().runtime_host_epoch()
        );
        assert_eq!(
            replay.facts().snapshot_sequence(),
            first.facts().snapshot_sequence()
        );
        assert_eq!(
            replay.facts().clock_generation(),
            first.facts().clock_generation()
        );
        runtime
            .shutdown_and_join()
            .unwrap_or_else(|error| panic!("cutover Runtime shutdown failed: {error}"));

        let restarted = start_runtime_developer_local_v1(config(&layout))
            .unwrap_or_else(|error| panic!("managed Runtime restart failed: {error}"));
        assert_eq!(restarted.ready().runtime_store_instance_id(), store);
        assert!(marker.exists(), "managed restart lost the one-way marker");
        let restarted_channel = live_channel(restarted.ready());
        let restarted_request = managed_bootstrap_request(
            restarted.ready(),
            restarted_channel,
            [0xa2; 16],
            b"developer-local-managed-restart",
        );
        let restarted_wire = exchange_frame(&layout.socket, restarted_request.canonical_wire())
            .unwrap_or_else(|error| panic!("managed restart PXFB failed: {error}"));
        let restarted_response = validated_response(
            restarted.ready(),
            &restarted_request,
            restarted_channel,
            &restarted_wire,
        );
        assert!(
            restarted_response.facts().runtime_host_epoch() > first.facts().runtime_host_epoch(),
            "managed restart did not advance the Runtime epoch"
        );
        assert_rejected(&layout.socket, b"PXBR-rejected-after-restart");
        restarted
            .shutdown_and_join()
            .unwrap_or_else(|error| panic!("managed Runtime shutdown failed: {error}"));
    }

    #[test]
    fn corrupt_existing_snapshot_is_not_reinitialized() {
        let layout = TestLayout::new();
        let runtime = start_runtime_developer_local_v1(config(&layout))
            .unwrap_or_else(|error| panic!("fresh Runtime start failed: {error}"));
        let store = runtime.ready().runtime_store_instance_id();
        runtime
            .shutdown_and_join()
            .unwrap_or_else(|error| panic!("fresh Runtime shutdown failed: {error}"));

        let snapshot_path = layout.state.join("runtime.snapshot");
        let mut snapshot = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snapshot_path)
            .unwrap_or_else(|error| panic!("snapshot open failed: {error}"));
        let original_length = snapshot
            .metadata()
            .unwrap_or_else(|error| panic!("snapshot metadata failed: {error}"))
            .len();
        let mut byte = [0_u8; 1];
        snapshot
            .read_exact(&mut byte)
            .unwrap_or_else(|error| panic!("snapshot read failed: {error}"));
        snapshot
            .seek(SeekFrom::Start(0))
            .unwrap_or_else(|error| panic!("snapshot seek failed: {error}"));
        byte[0] ^= 0xff;
        let corrupted_first_byte = byte[0];
        snapshot
            .write_all(&byte)
            .and_then(|()| snapshot.sync_all())
            .unwrap_or_else(|error| panic!("snapshot corruption failed: {error}"));
        drop(snapshot);

        let error = start_runtime_developer_local_v1(config(&layout))
            .expect_err("corrupt existing Runtime state must fail closed");
        assert_eq!(error.code(), "PXDL-INITIALIZATION-FAILED");
        assert_eq!(
            fs::metadata(&snapshot_path)
                .unwrap_or_else(|io| panic!("snapshot disappeared: {io}"))
                .len(),
            original_length
        );
        let mut reopened = OpenOptions::new()
            .read(true)
            .open(&snapshot_path)
            .unwrap_or_else(|error| panic!("corrupt snapshot reopen failed: {error}"));
        let mut persisted = [0_u8; 1];
        reopened
            .read_exact(&mut persisted)
            .unwrap_or_else(|error| panic!("corrupt snapshot reread failed: {error}"));
        assert_eq!(persisted[0], corrupted_first_byte);
        assert_ne!(store, [0; 32]);
    }
}
