//! Owner-private producer for the managed-fabric PXTE v5/PXAR v6 cutover.
//!
//! The producer accepts no projection or manifest fields. It derives the
//! transition projection locally from the installer manifest already pinned in
//! a strictly decoded Controller journal, and it admits Runtime/bootstrap,
//! channel, Controller-key, and tenure facts only after exact cryptographic and
//! cross-field validation.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
use paraegox_runtime_contracts::apply::{
    ApplyContractError, ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterRef,
    RuntimeApplyControl, TenureAuthorityRef, TenureKeyRef,
};
use paraegox_runtime_contracts::managed_fabric_plan::{
    MAX_MANAGED_FABRIC_LIFECYCLE_NANOS, ManagedFabricApplyRequestDraftV1,
    ManagedFabricApplyRequestV1, ManagedFabricApplySigningTranscriptV2,
    ManagedFabricListenEndpointV1, ManagedFabricManifestProjectionV1, ManagedFabricPlanError,
    ManagedFabricTargetExecutionV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceSpecV1;
use paraegox_runtime_contracts::managed_serving_bootstrap::ManagedServingBootstrapFactsV1;
use paraegox_runtime_contracts::provenance::{
    PlanProvenance, SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef,
};
use paraegox_runtime_contracts::reference_control::{
    ReferenceAdmissionPolicyInputV1, ReferenceBootstrapChannelPolicyInputV1,
    ReferenceBootstrapResponseV1, ReferenceBootstrapStateV1, ReferenceChannelBindingV1,
    ReferenceControlError, ed25519_control_key_fingerprint,
    reference_admission_policy_fingerprint_v1, reference_bootstrap_channel_policy_fingerprint_v1,
    reference_developer_local_bootstrap_channel_policy_fingerprint_v1,
};
use paraegox_runtime_contracts::temporal::{
    ApplyTemporalConstraint, TemporalConstraintId, TemporalContractError,
};
use paraegox_runtime_contracts::wire::{ApplyAuthError, ApplyAuthKeyRef, ApplyRequestAuthClaim};

use crate::controller_journal::{ControllerJournalError, ControllerJournalState};
use crate::managed_serving_client::{
    ManagedServingDescribeIngressV1, ManagedServingDescribeVerifierV1,
};
use crate::plan::DeploymentWriterRef;

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MANAGED_FABRIC_DESIRED_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.managed-fabric-desired.sha256.v1";

/// Controller and writer identities selected for the successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricControllerIdentityV1 {
    controller_principal: PrincipalRef,
    writer: DeploymentWriterRef,
}

impl ManagedFabricControllerIdentityV1 {
    pub(crate) fn try_new(
        controller_principal: PrincipalRef,
        writer: DeploymentWriterRef,
    ) -> Result<Self, ManagedFabricProducerError> {
        if bytes_are_zero(controller_principal.as_bytes()) || bytes_are_zero(writer.as_bytes()) {
            return Err(ManagedFabricProducerError::InvalidControllerIdentity);
        }
        Ok(Self {
            controller_principal,
            writer,
        })
    }
}

/// Protected Authority identity and Ed25519 verification facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricTenureAuthorityPinV1 {
    authority_principal: PrincipalRef,
    authority_uid: u32,
    authority_gid: u32,
    authority_ref: TenureAuthorityRef,
    key_ref: TenureKeyRef,
    public_key: [u8; 32],
}

impl ManagedFabricTenureAuthorityPinV1 {
    pub(crate) fn try_new(
        authority_principal: PrincipalRef,
        authority_uid: u32,
        authority_gid: u32,
        authority_ref: TenureAuthorityRef,
        key_ref: TenureKeyRef,
        public_key: [u8; 32],
    ) -> Result<Self, ManagedFabricProducerError> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| ManagedFabricProducerError::InvalidTenureAuthority)?;
        if bytes_are_zero(authority_principal.as_bytes())
            || authority_uid == 0
            || authority_gid == 0
            || bytes_are_zero(authority_ref.as_bytes())
            || bytes_are_zero(key_ref.as_bytes())
            || key.is_weak()
        {
            return Err(ManagedFabricProducerError::InvalidTenureAuthority);
        }
        Ok(Self {
            authority_principal,
            authority_uid,
            authority_gid,
            authority_ref,
            key_ref,
            public_key,
        })
    }
}

/// Distinct Runtime and Controller POSIX service identities used at bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricServiceAccountsV1 {
    runtime_uid: u32,
    runtime_gid: u32,
    controller_uid: u32,
    controller_gid: u32,
}

impl ManagedFabricServiceAccountsV1 {
    pub(crate) fn try_new(
        runtime_uid: u32,
        runtime_gid: u32,
        controller_uid: u32,
        controller_gid: u32,
    ) -> Result<Self, ManagedFabricProducerError> {
        if runtime_uid == 0
            || runtime_gid == 0
            || controller_uid == 0
            || controller_gid == 0
            || runtime_uid == controller_uid
        {
            return Err(ManagedFabricProducerError::InvalidRuntimeChannel);
        }
        Ok(Self {
            runtime_uid,
            runtime_gid,
            controller_uid,
            controller_gid,
        })
    }

    pub(crate) fn try_new_developer_local(
        runtime_uid: u32,
        runtime_gid: u32,
        controller_uid: u32,
        controller_gid: u32,
    ) -> Result<Self, ManagedFabricProducerError> {
        if runtime_uid == 0
            || runtime_gid == 0
            || controller_uid == 0
            || controller_gid == 0
            || runtime_uid != controller_uid
            || runtime_gid != controller_gid
        {
            return Err(ManagedFabricProducerError::InvalidRuntimeChannel);
        }
        Ok(Self {
            runtime_uid,
            runtime_gid,
            controller_uid,
            controller_gid,
        })
    }
}

/// Protected Runtime channel policy and response verification key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricRuntimeChannelPinV1 {
    canonical_socket_path: Box<[u8]>,
    runtime_principal: PrincipalRef,
    response_key_ref: ApplyAuthKeyRef,
    response_public_key: VerifyingKey,
    accounts: ManagedFabricServiceAccountsV1,
}

/// Complete protected provisioning required to re-derive one producer context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricControllerProvisioningV1 {
    controller: ManagedFabricControllerIdentityV1,
    authority: ManagedFabricTenureAuthorityPinV1,
    runtime: ManagedFabricRuntimeChannelPinV1,
}

/// Protected remote connector pins used after a verified PXDR Describe.
///
/// Unlike [`ManagedFabricControllerProvisioningV1`], this value contains no
/// UDS path or POSIX peer identity. The complete PXCB, Controller key and
/// Runtime response key are retained by the Describe verifier derived from
/// the out-of-band enrollment artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricRemoteControllerProvisioningV1 {
    controller: ManagedFabricControllerIdentityV1,
    authority: ManagedFabricTenureAuthorityPinV1,
    describe: ManagedServingDescribeVerifierV1,
}

impl ManagedFabricRemoteControllerProvisioningV1 {
    #[must_use]
    pub(crate) const fn new(
        controller: ManagedFabricControllerIdentityV1,
        authority: ManagedFabricTenureAuthorityPinV1,
        describe: ManagedServingDescribeVerifierV1,
    ) -> Self {
        Self {
            controller,
            authority,
            describe,
        }
    }

    #[must_use]
    pub(crate) const fn describe(&self) -> &ManagedServingDescribeVerifierV1 {
        &self.describe
    }
}

impl ManagedFabricControllerProvisioningV1 {
    #[must_use]
    pub(crate) const fn new(
        controller: ManagedFabricControllerIdentityV1,
        authority: ManagedFabricTenureAuthorityPinV1,
        runtime: ManagedFabricRuntimeChannelPinV1,
    ) -> Self {
        Self {
            controller,
            authority,
            runtime,
        }
    }
}

impl ManagedFabricRuntimeChannelPinV1 {
    pub(crate) fn try_new(
        canonical_socket_path: &[u8],
        runtime_principal: PrincipalRef,
        response_key_ref: ApplyAuthKeyRef,
        response_public_key: [u8; 32],
        accounts: ManagedFabricServiceAccountsV1,
    ) -> Result<Self, ManagedFabricProducerError> {
        let response_public_key = VerifyingKey::from_bytes(&response_public_key)
            .map_err(|_| ManagedFabricProducerError::InvalidRuntimeChannel)?;
        if canonical_socket_path.is_empty()
            || canonical_socket_path.len() > 4_096
            || canonical_socket_path.contains(&0)
            || bytes_are_zero(runtime_principal.as_bytes())
            || bytes_are_zero(response_key_ref.as_bytes())
            || response_public_key.is_weak()
        {
            return Err(ManagedFabricProducerError::InvalidRuntimeChannel);
        }
        Ok(Self {
            canonical_socket_path: canonical_socket_path.into(),
            runtime_principal,
            response_key_ref,
            response_public_key,
            accounts,
        })
    }
}

/// Fresh identities consumed only when no successor request is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshManagedFabricApplyV1 {
    operation_id: [u8; 16],
    temporal_constraint_id: [u8; 16],
    authentication_nonce: [u8; 32],
}

impl FreshManagedFabricApplyV1 {
    pub(crate) fn try_new(
        operation_id: [u8; 16],
        temporal_constraint_id: [u8; 16],
        authentication_nonce: [u8; 32],
    ) -> Result<Self, ManagedFabricProducerError> {
        if bytes_are_zero(&operation_id)
            || bytes_are_zero(&temporal_constraint_id)
            || bytes_are_zero(&authentication_nonce)
            || operation_id == temporal_constraint_id
        {
            return Err(ManagedFabricProducerError::InvalidFreshIdentity);
        }
        Ok(Self {
            operation_id,
            temporal_constraint_id,
            authentication_nonce,
        })
    }
}

/// Sealed Controller facts from which all managed-fabric plan/request bytes derive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedManagedFabricProducerContextV1 {
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    source_plan: SourcePlanRef,
    legacy_revision: u64,
    projection: ManagedFabricManifestProjectionV1,
    writer_context: PlanWriterContext,
    controller_principal: PrincipalRef,
    request_key: ApplyAuthKeyRef,
    controller_verifying_key: [u8; 32],
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    runtime_store_instance_id: [u8; 32],
    channel: ReferenceChannelBindingV1,
    runtime_response_key: ApplyAuthKeyRef,
    runtime_response_public_key: VerifyingKey,
}

impl VerifiedManagedFabricProducerContextV1 {
    pub(crate) fn try_from_provisioning(
        state: &ControllerJournalState,
        controller_signer: &SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Self, ManagedFabricProducerError> {
        Self::try_from_controller_state(
            state,
            controller_signer,
            provisioning.controller,
            provisioning.authority,
            &provisioning.runtime,
        )
    }

    pub(crate) fn try_from_controller_state(
        state: &ControllerJournalState,
        controller_signer: &SigningKey,
        controller: ManagedFabricControllerIdentityV1,
        authority: ManagedFabricTenureAuthorityPinV1,
        runtime: &ManagedFabricRuntimeChannelPinV1,
    ) -> Result<Self, ManagedFabricProducerError> {
        validate_controller_signer(state, controller_signer)?;
        let target = state.installed_manifest().target();
        let source_scope = SourceScopeRef::from_bytes(*state.scope().as_bytes());
        let source_plan = SourcePlanRef::from_bytes(*state.plan_lineage().as_bytes());
        let binding = state
            .target_binding()
            .ok_or(ManagedFabricProducerError::MissingTargetBinding)?;
        if binding.target() != target
            || binding.manifest_digest().value() != state.installed_manifest().manifest_digest()
        {
            return Err(ManagedFabricProducerError::BootstrapBindingMismatch);
        }

        let runtime_auth = binding.runtime_response_auth();
        let channel = runtime_auth.channel(target)?;
        if runtime.runtime_principal != channel.runtime_peer()
            || runtime.response_key_ref != runtime_auth.key()
            || runtime_auth.algorithm().value() != ED25519_ALGORITHM
            || runtime_auth.algorithm_version() != ED25519_ALGORITHM_VERSION
        {
            return Err(ManagedFabricProducerError::InvalidRuntimeChannel);
        }

        let request_auth = state.request_auth();
        let controller_verification_key = controller_signer.verifying_key();
        let channel_policy_input = ReferenceBootstrapChannelPolicyInputV1 {
            canonical_socket_path: &runtime.canonical_socket_path,
            target,
            source_scope,
            controller_principal: controller.controller_principal,
            controller_key_ref: request_auth.key(),
            controller_public_key: controller_verification_key.as_bytes(),
            runtime_uid: runtime.accounts.runtime_uid,
            runtime_gid: runtime.accounts.runtime_gid,
            controller_uid: runtime.accounts.controller_uid,
            controller_gid: runtime.accounts.controller_gid,
            runtime_principal: runtime.runtime_principal,
            response_key_ref: runtime.response_key_ref,
            response_public_key: runtime.response_public_key.as_bytes(),
        };
        let channel_policy = if runtime.accounts.runtime_uid == runtime.accounts.controller_uid
            && runtime.accounts.runtime_gid == runtime.accounts.controller_gid
        {
            reference_developer_local_bootstrap_channel_policy_fingerprint_v1(channel_policy_input)?
        } else {
            reference_bootstrap_channel_policy_fingerprint_v1(channel_policy_input)?
        };
        if binding.channel_auth_fingerprint().value() != channel_policy {
            return Err(ManagedFabricProducerError::InvalidRuntimeChannel);
        }

        let plan_writer = PlanWriterRef::from_bytes(*controller.writer.as_bytes());
        let proof = state
            .latest_committed_tenure_proof(plan_writer)
            .ok_or(ManagedFabricProducerError::MissingCommittedTenureProof)?
            .clone();
        validate_tenure_proof(&proof, source_scope, plan_writer, authority)?;
        let writer_context =
            PlanWriterContext::try_new(plan_writer, proof.claim().epoch(), proof.clone())?;
        let admission_policy =
            reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
                target,
                source_scope,
                writer: plan_writer,
                controller_principal: controller.controller_principal,
                controller_key_ref: request_auth.key(),
                controller_public_key: controller_signer.verifying_key().as_bytes(),
                authority_principal: authority.authority_principal,
                authority_uid: authority.authority_uid,
                authority_gid: authority.authority_gid,
                tenure_authority_ref: authority.authority_ref,
                tenure_key_ref: authority.key_ref,
                tenure_public_key: &authority.public_key,
            })?;

        let bootstrap = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())?;
        verify_bootstrap_response_signature(&bootstrap, &runtime.response_public_key)?;
        let facts = bootstrap.facts();
        if bootstrap.canonical_wire() != binding.bootstrap_response()
            || bootstrap.response_digest() != binding.bootstrap_response_digest().value()
            || bootstrap.authentication_runtime_peer() != channel.runtime_peer()
            || bootstrap.authentication_channel_binding_digest() != channel.binding_digest()
            || bootstrap.authentication_key() != runtime.response_key_ref
            || bootstrap.authentication_algorithm().value() != ED25519_ALGORITHM
            || bootstrap.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
            || facts.target() != target
            || facts.runtime_store_instance_id() != binding.runtime_store_instance_id()
            || facts.runtime_host_epoch() != binding.last_runtime_host_epoch()
            || facts.manifest_digest() != state.installed_manifest().manifest_digest()
            || facts.profile_fingerprint()
                != state
                    .installed_manifest()
                    .projection()
                    .profile_fingerprint()
            || facts.admission_policy_fingerprint() != admission_policy.digest()
            || facts.state() != ReferenceBootstrapStateV1::ReadyForApply
        {
            return Err(ManagedFabricProducerError::BootstrapBindingMismatch);
        }

        let projection = ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(
            state.installed_manifest().verified_manifest(),
        )?;
        if projection.target() != target {
            return Err(ManagedFabricProducerError::ProjectionMismatch);
        }
        Ok(Self {
            target,
            source_scope,
            source_plan,
            legacy_revision: state.current_revision(),
            projection,
            writer_context,
            controller_principal: controller.controller_principal,
            request_key: request_auth.key(),
            controller_verifying_key: controller_signer.verifying_key().to_bytes(),
            clock_domain: facts.clock_domain(),
            clock_generation: facts.clock_generation(),
            runtime_store_instance_id: binding.runtime_store_instance_id(),
            channel,
            runtime_response_key: runtime.response_key_ref,
            runtime_response_public_key: runtime.response_public_key,
        })
    }

    /// Builds the managed-Fabric producer context from an authenticated remote
    /// PXDR observation and enrollment-pinned PXCB. This path deliberately
    /// does not consult or synthesize the legacy PXBR/UDS target binding.
    pub(crate) fn try_from_remote_describe(
        state: &ControllerJournalState,
        controller_signer: &SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ingress: &ManagedServingDescribeIngressV1,
    ) -> Result<Self, ManagedFabricProducerError> {
        validate_controller_signer(state, controller_signer)?;
        ingress
            .revalidate(&provisioning.describe)
            .map_err(|_| ManagedFabricProducerError::RemoteDescribeMismatch)?;
        let target = state.installed_manifest().target();
        let source_scope = SourceScopeRef::from_bytes(*state.scope().as_bytes());
        let source_plan = SourcePlanRef::from_bytes(*state.plan_lineage().as_bytes());
        let request_auth = state.request_auth();
        let carrier = provisioning.describe.carrier();
        let facts = ingress.serving_facts();
        let channel = ingress.channel();
        if provisioning.describe.target() != target
            || provisioning.describe.manifest_digest()
                != state.installed_manifest().manifest_digest()
            || provisioning.describe.controller_public_key()
                != controller_signer.verifying_key().to_bytes()
            || carrier.target() != target
            || carrier.controller_principal() != provisioning.controller.controller_principal
            || carrier.controller_request_key() != request_auth.key()
            || channel.target() != target
            || channel.runtime_peer() != carrier.runtime_principal()
            || facts.target() != target
            || facts.runtime_store_instance_id() == [0; 32]
            || facts.projection() != ingress.projection()
        {
            return Err(ManagedFabricProducerError::RemoteDescribeMismatch);
        }
        let projection = ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(
            state.installed_manifest().verified_manifest(),
        )?;
        if projection.target() != target || &projection != ingress.projection() {
            return Err(ManagedFabricProducerError::ProjectionMismatch);
        }
        let plan_writer = PlanWriterRef::from_bytes(*provisioning.controller.writer.as_bytes());
        let proof = state
            .latest_committed_tenure_proof(plan_writer)
            .ok_or(ManagedFabricProducerError::MissingCommittedTenureProof)?
            .clone();
        validate_tenure_proof(&proof, source_scope, plan_writer, provisioning.authority)?;
        let writer_context =
            PlanWriterContext::try_new(plan_writer, proof.claim().epoch(), proof.clone())?;
        let runtime_response_public_key =
            VerifyingKey::from_bytes(&provisioning.describe.runtime_response_public_key())
                .map_err(|_| ManagedFabricProducerError::InvalidRuntimeChannel)?;
        if runtime_response_public_key.is_weak() {
            return Err(ManagedFabricProducerError::InvalidRuntimeChannel);
        }
        Ok(Self {
            target,
            source_scope,
            source_plan,
            legacy_revision: state.current_revision(),
            projection,
            writer_context,
            controller_principal: provisioning.controller.controller_principal,
            request_key: request_auth.key(),
            controller_verifying_key: controller_signer.verifying_key().to_bytes(),
            clock_domain: facts.clock_domain(),
            clock_generation: facts.clock_generation(),
            runtime_store_instance_id: facts.runtime_store_instance_id(),
            channel,
            runtime_response_key: carrier.runtime_response_key(),
            runtime_response_public_key,
        })
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn source_scope(&self) -> SourceScopeRef {
        self.source_scope
    }

    #[must_use]
    pub(crate) const fn source_plan(&self) -> SourcePlanRef {
        self.source_plan
    }

    #[must_use]
    pub(crate) const fn projection(&self) -> &ManagedFabricManifestProjectionV1 {
        &self.projection
    }

    #[must_use]
    pub(crate) const fn runtime_store_instance_id(&self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    #[must_use]
    pub(crate) const fn controller_principal(&self) -> PrincipalRef {
        self.controller_principal
    }

    #[must_use]
    pub(crate) const fn request_key(&self) -> ApplyAuthKeyRef {
        self.request_key
    }

    #[must_use]
    pub(crate) const fn writer_context(&self) -> &PlanWriterContext {
        &self.writer_context
    }

    #[must_use]
    pub(crate) const fn clock_domain(&self) -> ClockDomainRef {
        self.clock_domain
    }

    #[must_use]
    pub(crate) const fn clock_generation(&self) -> ClockGeneration {
        self.clock_generation
    }

    #[must_use]
    pub(crate) const fn controller_verifying_key(&self) -> [u8; 32] {
        self.controller_verifying_key
    }

    #[must_use]
    pub(crate) const fn channel(&self) -> ReferenceChannelBindingV1 {
        self.channel
    }

    #[must_use]
    pub(crate) const fn runtime_response_key(&self) -> ApplyAuthKeyRef {
        self.runtime_response_key
    }

    #[must_use]
    pub(crate) const fn runtime_response_public_key(&self) -> &VerifyingKey {
        &self.runtime_response_public_key
    }

    #[must_use]
    pub(crate) const fn legacy_revision(&self) -> u64 {
        self.legacy_revision
    }

    /// Rebinds only Runtime-owned volatile serving facts after an authenticated
    /// PXFB/PXFR observation. All static Controller, manifest, channel, key,
    /// tenure, and store facts remain derived from protected provisioning.
    pub(crate) fn try_with_current_serving_facts(
        &self,
        facts: &ManagedServingBootstrapFactsV1,
    ) -> Result<Self, ManagedFabricProducerError> {
        if facts.target() != self.target
            || facts.runtime_store_instance_id() != self.runtime_store_instance_id
            || facts.projection() != &self.projection
        {
            return Err(ManagedFabricProducerError::BootstrapBindingMismatch);
        }
        let mut current = self.clone();
        current.clock_domain = facts.clock_domain();
        current.clock_generation = facts.clock_generation();
        Ok(current)
    }

    pub(crate) fn validate_stored_request(
        &self,
        desired: &ManagedFabricDesiredPlanV1,
        expected_active: ExpectedActive,
        request: &ManagedFabricApplyRequestV1,
    ) -> Result<(), ManagedFabricProducerError> {
        let control = request.control_commitment().control();
        let temporal = request.temporal();
        let authentication = request.authentication();
        let claim = authentication.claim();
        if request.target() != self.target
            || request.target_execution() != desired.execution()
            || request.provenance() != desired.provenance()
            || request.expected_runtime_store_instance_id() != self.runtime_store_instance_id
            || control.expected_active() != expected_active
            || control.writer_context() != &self.writer_context
            || temporal.target_clock_domain() != self.clock_domain
            || temporal.target_clock_generation() != self.clock_generation
            || temporal.original_budget().value() != MAX_MANAGED_FABRIC_LIFECYCLE_NANOS
            || temporal.remaining_budget().value() != MAX_MANAGED_FABRIC_LIFECYCLE_NANOS
            || claim.principal() != self.controller_principal
            || claim.key() != self.request_key
            || claim.algorithm().value() != ED25519_ALGORITHM
            || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
            || authentication.signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ManagedFabricProducerError::RequestMismatch);
        }
        request.validate_projection(&self.projection)?;
        let signature = Signature::from_slice(authentication.signature())
            .map_err(|_| ManagedFabricProducerError::RequestMismatch)?;
        let transcript = request.signing_transcript()?;
        VerifyingKey::from_bytes(&self.controller_verifying_key)
            .map_err(|_| ManagedFabricProducerError::RequestMismatch)?
            .verify_strict(transcript.as_bytes(), &signature)
            .map_err(|_| ManagedFabricProducerError::RequestMismatch)
    }
}

/// Exact successor desired plan derived from trusted Controller facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricDesiredPlanV1 {
    cutover_marker_digest: Digest32,
    revision: SourcePlanRevision,
    provenance: PlanProvenance,
    execution: ManagedFabricTargetExecutionV1,
}

impl ManagedFabricDesiredPlanV1 {
    pub(crate) fn try_activate(
        context: &VerifiedManagedFabricProducerContextV1,
        cutover_marker_digest: Digest32,
        revision: u64,
        service: ManagedServiceSpecV1,
        endpoint: ManagedFabricListenEndpointV1,
    ) -> Result<Self, ManagedFabricProducerError> {
        let execution = ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
            context.projection.clone(),
            service,
            endpoint,
        )?;
        Self::try_from_execution(context, cutover_marker_digest, revision, execution)
    }

    pub(crate) fn try_empty_deactivate(
        context: &VerifiedManagedFabricProducerContextV1,
        cutover_marker_digest: Digest32,
        revision: u64,
    ) -> Result<Self, ManagedFabricProducerError> {
        let execution =
            ManagedFabricTargetExecutionV1::try_empty_deactivate(context.projection.clone())?;
        Self::try_from_execution(context, cutover_marker_digest, revision, execution)
    }

    pub(crate) fn try_restore(
        context: &VerifiedManagedFabricProducerContextV1,
        cutover_marker_digest: Digest32,
        revision: u64,
        canonical_execution: &[u8],
    ) -> Result<Self, ManagedFabricProducerError> {
        let execution = ManagedFabricTargetExecutionV1::decode(canonical_execution)?;
        if execution.projection() != &context.projection {
            return Err(ManagedFabricProducerError::ProjectionMismatch);
        }
        Self::try_from_execution(context, cutover_marker_digest, revision, execution)
    }

    fn try_from_execution(
        context: &VerifiedManagedFabricProducerContextV1,
        cutover_marker_digest: Digest32,
        revision: u64,
        execution: ManagedFabricTargetExecutionV1,
    ) -> Result<Self, ManagedFabricProducerError> {
        if digest_is_zero(cutover_marker_digest)
            || revision == 0
            || execution.projection() != &context.projection
        {
            return Err(ManagedFabricProducerError::InvalidDesiredPlan);
        }
        let revision = SourcePlanRevision::new(revision);
        let mut digest = Digest32Builder::try_new(MANAGED_FABRIC_DESIRED_DIGEST_DOMAIN)?;
        digest.field_digest(&cutover_marker_digest)?;
        digest.field_bytes(context.target.as_bytes())?;
        digest.field_bytes(context.source_scope.as_bytes())?;
        digest.field_bytes(context.source_plan.as_bytes())?;
        digest.field_u64(revision.value())?;
        digest.field_bytes(execution.canonical_wire())?;
        let provenance = PlanProvenance::new(
            context.source_scope,
            context.source_plan,
            revision,
            SourcePlanDigest::new(digest.finish()),
        );
        Ok(Self {
            cutover_marker_digest,
            revision,
            provenance,
            execution,
        })
    }

    #[must_use]
    pub(crate) const fn cutover_marker_digest(&self) -> Digest32 {
        self.cutover_marker_digest
    }

    #[must_use]
    pub(crate) const fn revision(&self) -> SourcePlanRevision {
        self.revision
    }

    #[must_use]
    pub(crate) const fn provenance(&self) -> PlanProvenance {
        self.provenance
    }

    #[must_use]
    pub(crate) const fn execution(&self) -> &ManagedFabricTargetExecutionV1 {
        &self.execution
    }
}

/// Signature-independent PXAR v6 prepared only from one sealed desired plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricControllerRequestDraftV1 {
    inner: ManagedFabricApplyRequestDraftV1,
    controller_verifying_key: [u8; 32],
}

impl ManagedFabricControllerRequestDraftV1 {
    pub(crate) fn try_new(
        context: &VerifiedManagedFabricProducerContextV1,
        desired: &ManagedFabricDesiredPlanV1,
        expected_active: ExpectedActive,
        fresh: FreshManagedFabricApplyV1,
        controller_signer: &SigningKey,
    ) -> Result<Self, ManagedFabricProducerError> {
        validate_context_signer(context, controller_signer)?;
        if desired.execution.projection() != &context.projection
            || desired.provenance.source_scope() != context.source_scope
            || desired.provenance.source_plan() != context.source_plan
        {
            return Err(ManagedFabricProducerError::InvalidDesiredPlan);
        }
        let control = RuntimeApplyControl::new(
            context.writer_context.clone(),
            expected_active,
            ApplyOperationId::from_bytes(fresh.operation_id),
        );
        let budget = BoundedDuration::from_nanos(MAX_MANAGED_FABRIC_LIFECYCLE_NANOS);
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes(fresh.temporal_constraint_id),
            context.clock_domain,
            context.clock_generation,
            budget,
            budget,
        )?;
        let auth_claim = ApplyRequestAuthClaim::try_new(
            context.controller_principal,
            context.request_key,
            state_ed25519_algorithm()?,
            ED25519_ALGORITHM_VERSION,
            &fresh.authentication_nonce,
        )?;
        let inner = ManagedFabricApplyRequestDraftV1::try_new(
            desired.execution.clone(),
            desired.provenance,
            control,
            temporal,
            context.runtime_store_instance_id,
            auth_claim,
        )?;
        Ok(Self {
            inner,
            controller_verifying_key: controller_signer.verifying_key().to_bytes(),
        })
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ManagedFabricApplySigningTranscriptV2, ManagedFabricProducerError> {
        Ok(self.inner.signing_transcript()?)
    }

    pub(crate) fn finalize(
        self,
        controller_signer: &SigningKey,
    ) -> Result<ManagedFabricApplyRequestV1, ManagedFabricProducerError> {
        if controller_signer.verifying_key().to_bytes() != self.controller_verifying_key {
            return Err(ManagedFabricProducerError::ControllerSigningKeyMismatch);
        }
        let signature = controller_signer.sign(self.inner.signing_transcript()?.as_bytes());
        let request = self.inner.finalize(&signature.to_bytes())?;
        let decoded = ManagedFabricApplyRequestV1::decode(request.canonical_wire())?;
        if decoded != request {
            return Err(ManagedFabricProducerError::RequestMismatch);
        }
        Ok(request)
    }
}

fn validate_controller_signer(
    state: &ControllerJournalState,
    signer: &SigningKey,
) -> Result<(), ManagedFabricProducerError> {
    let request_auth = state.request_auth();
    if request_auth.algorithm().value() != ED25519_ALGORITHM
        || request_auth.algorithm_version() != ED25519_ALGORITHM_VERSION
        || signer.verifying_key().is_weak()
    {
        return Err(ManagedFabricProducerError::ControllerSigningKeyMismatch);
    }
    let fingerprint = ed25519_control_key_fingerprint(signer.verifying_key().as_bytes())?;
    if fingerprint != request_auth.verification_key_fingerprint().value() {
        return Err(ManagedFabricProducerError::ControllerSigningKeyMismatch);
    }
    Ok(())
}

fn validate_context_signer(
    context: &VerifiedManagedFabricProducerContextV1,
    signer: &SigningKey,
) -> Result<(), ManagedFabricProducerError> {
    if signer.verifying_key().to_bytes() != context.controller_verifying_key {
        return Err(ManagedFabricProducerError::ControllerSigningKeyMismatch);
    }
    Ok(())
}

fn validate_tenure_proof(
    proof: &paraegox_runtime_contracts::apply::WriterTenureProof,
    source_scope: SourceScopeRef,
    writer: PlanWriterRef,
    pin: ManagedFabricTenureAuthorityPinV1,
) -> Result<(), ManagedFabricProducerError> {
    let authority = proof.authority();
    let claim = proof.claim();
    if authority.authority() != pin.authority_ref
        || authority.key() != pin.key_ref
        || authority.algorithm().value() != ED25519_ALGORITHM
        || authority.algorithm_version() != ED25519_ALGORITHM_VERSION
        || claim.source_scope() != source_scope
        || claim.writer() != writer
        || proof.signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(ManagedFabricProducerError::InvalidTenureAuthority);
    }
    let signature = Signature::from_slice(proof.signature())
        .map_err(|_| ManagedFabricProducerError::InvalidTenureAuthority)?;
    let transcript = proof
        .signing_transcript()
        .map_err(|_| ManagedFabricProducerError::InvalidTenureAuthority)?;
    VerifyingKey::from_bytes(&pin.public_key)
        .map_err(|_| ManagedFabricProducerError::InvalidTenureAuthority)?
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| ManagedFabricProducerError::InvalidTenureAuthority)
}

fn verify_bootstrap_response_signature(
    response: &ReferenceBootstrapResponseV1,
    key: &VerifyingKey,
) -> Result<(), ManagedFabricProducerError> {
    if response.authentication_signature().len() != ED25519_SIGNATURE_BYTES {
        return Err(ManagedFabricProducerError::BootstrapSignatureMismatch);
    }
    let signature = Signature::from_slice(response.authentication_signature())
        .map_err(|_| ManagedFabricProducerError::BootstrapSignatureMismatch)?;
    let transcript = response.signing_transcript()?;
    key.verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| ManagedFabricProducerError::BootstrapSignatureMismatch)
}

fn state_ed25519_algorithm()
-> Result<paraegox_runtime_contracts::wire::ApplyAuthAlgorithm, ManagedFabricProducerError> {
    paraegox_runtime_contracts::wire::ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
        .map_err(ManagedFabricProducerError::Authentication)
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

fn digest_is_zero(value: Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

/// Fail-closed producer errors; no value in this enum is a send authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricProducerError {
    Journal(ControllerJournalError),
    Contract(ManagedFabricPlanError),
    Control(ReferenceControlError),
    Apply(ApplyContractError),
    Temporal(TemporalContractError),
    Authentication(ApplyAuthError),
    Digest(DigestBuildError),
    InvalidControllerIdentity,
    InvalidTenureAuthority,
    InvalidRuntimeChannel,
    RemoteDescribeMismatch,
    MissingTargetBinding,
    MissingCommittedTenureProof,
    BootstrapBindingMismatch,
    BootstrapSignatureMismatch,
    ControllerSigningKeyMismatch,
    ProjectionMismatch,
    InvalidDesiredPlan,
    InvalidFreshIdentity,
    RequestMismatch,
}

impl From<ControllerJournalError> for ManagedFabricProducerError {
    fn from(value: ControllerJournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<ManagedFabricPlanError> for ManagedFabricProducerError {
    fn from(value: ManagedFabricPlanError) -> Self {
        Self::Contract(value)
    }
}

impl From<ReferenceControlError> for ManagedFabricProducerError {
    fn from(value: ReferenceControlError) -> Self {
        Self::Control(value)
    }
}

impl From<ApplyContractError> for ManagedFabricProducerError {
    fn from(value: ApplyContractError) -> Self {
        Self::Apply(value)
    }
}

impl From<TemporalContractError> for ManagedFabricProducerError {
    fn from(value: TemporalContractError) -> Self {
        Self::Temporal(value)
    }
}

impl From<ApplyAuthError> for ManagedFabricProducerError {
    fn from(value: ApplyAuthError) -> Self {
        Self::Authentication(value)
    }
}

impl From<DigestBuildError> for ManagedFabricProducerError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ManagedFabricProducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed-fabric producer rejected input: {self:?}"
        )
    }
}

impl std::error::Error for ManagedFabricProducerError {}
