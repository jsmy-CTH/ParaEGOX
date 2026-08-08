//! Durable Controller owner for the successor Runtime serving observation.
//!
//! PXFB may perform Runtime's one-way managed-owner cutover, so its
//! Controller-side delivery state is never ephemeral. The exact request is
//! committed before transport, the attempt is committed in-flight before a
//! move-only send action exists, and a timeout or EOF is durably closed without
//! claiming whether Runtime changed. A separately durable, fresh Describe may
//! reconcile the resulting Runtime state, but it never manufactures the PXFR
//! that an uncertain PXFB attempt did not return and never authorizes replay of
//! that PXFB.

use core::fmt;
use core::future::Future;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_runtime_contracts::distributed_agent_stack_plan::RestrictedRuntimeApplyCarrierBindingV1;
use paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricManifestProjectionV1;
use paraegox_runtime_contracts::managed_serving_bootstrap::{
    ManagedServingBootstrapError, ManagedServingBootstrapFactsV1,
    ManagedServingBootstrapRequestDraftV1, ManagedServingBootstrapRequestIdV1,
    ManagedServingBootstrapRequestV1, ManagedServingBootstrapResponseV1,
    RuntimeControlCarrierKindV1, RuntimeControlCarrierRequestDraftV1,
    RuntimeControlCarrierRequestV1, RuntimeControlDescribeReadyPhaseV1,
    RuntimeControlDescribeReadyResponseV1,
};
use paraegox_runtime_contracts::reference_control::{
    ReferenceBootstrapServingIdentityV1, ReferenceChannelBindingV1, ReferenceControlError,
    ReferenceQueryFactsV1, ReferenceQueryRequestV1, ReferenceQueryResponseV1,
    ed25519_control_key_fingerprint,
};
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthError, ApplyRequestAuthClaim};

use crate::managed_fabric_producer::{
    ManagedFabricProducerError, VerifiedManagedFabricProducerContextV1,
};
use crate::runtime_control_client::PreparedRuntimeQueryRequest;

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;

/// Fresh values supplied by one explicit observation invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshManagedServingBootstrapV1 {
    request_id: [u8; 16],
    authentication_nonce: [u8; 32],
}

impl FreshManagedServingBootstrapV1 {
    pub(crate) fn try_new(
        request_id: [u8; 16],
        authentication_nonce: [u8; 32],
    ) -> Result<Self, ManagedServingControllerError> {
        if bytes_are_zero(&request_id) || bytes_are_zero(&authentication_nonce) {
            return Err(ManagedServingControllerError::InvalidFreshIdentity);
        }
        Ok(Self {
            request_id,
            authentication_nonce,
        })
    }
}

/// Immutable Deployment pins for one restricted Runtime Describe ingress.
///
/// PXCB authenticates the remote carrier selection. The separately retained
/// public keys verify the Controller PXCC and Runtime PXDR signatures. The
/// manifest digest is the installed-artifact pin and is never learned from an
/// unverified PXDR response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedServingDescribeVerifierV1 {
    target: RuntimeHostId,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    controller_public_key: [u8; 32],
    runtime_response_public_key: [u8; 32],
    manifest_digest: Digest32,
}

impl ManagedServingDescribeVerifierV1 {
    pub(crate) fn try_new(
        target: RuntimeHostId,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        controller_public_key: [u8; 32],
        runtime_response_public_key: [u8; 32],
        manifest_digest: Digest32,
    ) -> Result<Self, ManagedServingControllerError> {
        let controller_key = VerifyingKey::from_bytes(&controller_public_key)
            .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
        let runtime_key = VerifyingKey::from_bytes(&runtime_response_public_key)
            .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
        let controller_fingerprint = ed25519_control_key_fingerprint(&controller_public_key)
            .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
        let runtime_fingerprint = ed25519_control_key_fingerprint(&runtime_response_public_key)
            .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
        if bytes_are_zero(target.as_bytes())
            || target != carrier.target()
            || controller_key.is_weak()
            || runtime_key.is_weak()
            || controller_public_key == runtime_response_public_key
            || carrier.controller_request_key_fingerprint() != controller_fingerprint
            || carrier.runtime_response_key_fingerprint() != runtime_fingerprint
            || digest_is_zero(manifest_digest)
        {
            return Err(ManagedServingControllerError::InvalidDescribePin);
        }
        Ok(Self {
            target,
            carrier,
            controller_public_key,
            runtime_response_public_key,
            manifest_digest,
        })
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        &self.carrier
    }

    #[must_use]
    pub(crate) const fn controller_public_key(&self) -> [u8; 32] {
        self.controller_public_key
    }

    #[must_use]
    pub(crate) const fn runtime_response_public_key(&self) -> [u8; 32] {
        self.runtime_response_public_key
    }

    #[must_use]
    pub(crate) const fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }

    /// Builds and self-verifies one exact fresh Controller-signed PXCC
    /// Describe. Local composition never has to hand-assemble the C1 carrier.
    pub(crate) fn try_build_request(
        &self,
        previous: Option<&ManagedServingDescribeIngressV1>,
        fresh: FreshManagedServingBootstrapV1,
        controller_signer: &SigningKey,
    ) -> Result<RuntimeControlCarrierRequestV1, ManagedServingControllerError> {
        if controller_signer.verifying_key().to_bytes() != self.controller_public_key {
            return Err(ManagedServingControllerError::ControllerKeyMismatch);
        }
        if let Some(previous) = previous
            && (previous.request.request_id().as_bytes() == &fresh.request_id
                || previous.request.authentication().claim().nonce() == fresh.authentication_nonce)
        {
            return Err(ManagedServingControllerError::FreshIdentityReused);
        }
        let claim = ApplyRequestAuthClaim::try_new(
            self.carrier.controller_principal(),
            self.carrier.controller_request_key(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)?,
            ED25519_ALGORITHM_VERSION,
            &fresh.authentication_nonce,
        )?;
        let draft = RuntimeControlCarrierRequestDraftV1::try_describe(
            ManagedServingBootstrapRequestIdV1::try_from_bytes(fresh.request_id)?,
            self.carrier.clone(),
            claim,
        )?;
        let signature = controller_signer.sign(draft.signing_transcript()?.as_bytes());
        let request = draft.finalize(&signature.to_bytes())?;
        verify_describe_request(self, &request)?;
        Ok(request)
    }

    pub(crate) fn revalidate_fresh_request(
        &self,
        previous: &ManagedServingDescribeIngressV1,
        request: &RuntimeControlCarrierRequestV1,
    ) -> Result<(), ManagedServingControllerError> {
        verify_fresh_describe_request(self, previous, request)
    }
}

/// Exact signed Describe request/response material admitted for persistence.
///
/// The contained [`ReferenceChannelBindingV1`] is Runtime-local owner/UDS
/// identity. It is deliberately never interpreted as a TLS session binding.
/// Callers persist both canonical wires before using the facts to construct
/// the existing PXFB request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedServingDescribeIngressV1 {
    request: RuntimeControlCarrierRequestV1,
    response: RuntimeControlDescribeReadyResponseV1,
}

impl ManagedServingDescribeIngressV1 {
    pub(crate) fn try_accept(
        verifier: &ManagedServingDescribeVerifierV1,
        previous: Option<&Self>,
        request: RuntimeControlCarrierRequestV1,
        response_wire: &[u8],
    ) -> Result<Self, ManagedServingControllerError> {
        verify_describe_request(verifier, &request)?;
        let response = RuntimeControlDescribeReadyResponseV1::decode(response_wire)?;
        verify_describe_response(verifier, &request, &response)?;
        let ingress = Self { request, response };
        ingress.validate_pins(verifier)?;
        if let Some(previous) = previous {
            ingress.validate_successor(previous)?;
        }
        Ok(ingress)
    }

    /// Reopens only exact canonical signed bytes and repeats every pin,
    /// signature, correlation and restart-succession check.
    pub(crate) fn decode(
        verifier: &ManagedServingDescribeVerifierV1,
        previous: Option<&Self>,
        request_wire: &[u8],
        response_wire: &[u8],
    ) -> Result<Self, ManagedServingControllerError> {
        let request = RuntimeControlCarrierRequestV1::decode(request_wire)?;
        Self::try_accept(verifier, previous, request, response_wire)
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> RuntimeControlDescribeReadyPhaseV1 {
        self.response.facts().phase()
    }

    /// Returns the original PXFB builder's target/store/projection/clock facts.
    #[must_use]
    pub(crate) const fn serving_facts(&self) -> &ManagedServingBootstrapFactsV1 {
        self.response.facts().serving()
    }

    /// Returns the Runtime-local owner binding required by the original PXFB
    /// builder. This value does not describe or authorize TLS.
    #[must_use]
    pub(crate) const fn channel(&self) -> ReferenceChannelBindingV1 {
        self.response.facts().channel()
    }

    #[must_use]
    pub(crate) const fn projection(&self) -> &ManagedFabricManifestProjectionV1 {
        self.response.facts().serving().projection()
    }

    #[must_use]
    pub(crate) fn request_wire(&self) -> &[u8] {
        self.request.canonical_wire()
    }

    #[must_use]
    pub(crate) fn response_wire(&self) -> &[u8] {
        self.response.canonical_wire()
    }

    /// Repeats signature, carrier, manifest and correlation checks before a
    /// persisted Describe observation is used to authorize another operation.
    pub(crate) fn revalidate(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
    ) -> Result<(), ManagedServingControllerError> {
        verify_describe_request(verifier, &self.request)?;
        verify_describe_response(verifier, &self.request, &self.response)?;
        self.validate_pins(verifier)
    }

    fn validate_pins(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
    ) -> Result<(), ManagedServingControllerError> {
        let facts = self.response.facts();
        let serving = facts.serving();
        if self.request.kind() != RuntimeControlCarrierKindV1::Describe
            || self.request.carrier() != &verifier.carrier
            || serving.target() != verifier.target
            || facts.channel().target() != verifier.target
            || facts.channel().runtime_peer() != verifier.carrier.runtime_principal()
        {
            return Err(ManagedServingControllerError::DescribeCorrelationMismatch);
        }
        if facts.manifest_digest() != verifier.manifest_digest {
            return Err(ManagedServingControllerError::DescribeManifestMismatch);
        }
        Ok(())
    }

    fn validate_successor(&self, previous: &Self) -> Result<(), ManagedServingControllerError> {
        if self.request.request_id() == previous.request.request_id()
            || self.request.request_digest() == previous.request.request_digest()
            || self.request.authentication().claim().nonce()
                == previous.request.authentication().claim().nonce()
        {
            return Err(ManagedServingControllerError::FreshIdentityReused);
        }
        let prior = previous.serving_facts();
        let next = self.serving_facts();
        if next.target() != prior.target()
            || next.runtime_store_instance_id() != prior.runtime_store_instance_id()
        {
            return Err(ManagedServingControllerError::DescribeStoreMismatch);
        }
        if next.projection() != prior.projection() {
            return Err(ManagedServingControllerError::DescribeManifestMismatch);
        }
        if next.runtime_host_epoch() < prior.runtime_host_epoch()
            || next.snapshot_sequence() < prior.snapshot_sequence()
        {
            return Err(ManagedServingControllerError::DescribeEpochRegression);
        }
        if self.channel() != previous.channel()
            && next.runtime_host_epoch() <= prior.runtime_host_epoch()
        {
            return Err(ManagedServingControllerError::DescribeChannelRebindWithoutRestart);
        }
        if previous.phase() == RuntimeControlDescribeReadyPhaseV1::ManagedReady
            && self.phase() == RuntimeControlDescribeReadyPhaseV1::LegacyReady
        {
            return Err(ManagedServingControllerError::DescribePhaseRegression);
        }
        Ok(())
    }
}

/// Raw response bytes returned only after one concrete remote transport has
/// selected the exact pinned PXCB. The observed digest is transport evidence;
/// it is deliberately distinct from the Runtime-local PXDR channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeReferenceQueryMtlsExchangeSuccessV1 {
    observed_runtime_certificate_principal: PrincipalRef,
    observed_carrier_binding_digest: Digest32,
    response_wire: Box<[u8]>,
}

/// Raw PXFR bytes returned by one concrete remote Runtime-control exchange.
///
/// The TLS peer and complete PXCB digest are transport observations. They are
/// checked independently from the Runtime-local [`ReferenceChannelBindingV1`]
/// carried by PXDR/PXFB/PXFR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeManagedServingMtlsExchangeSuccessV1 {
    observed_runtime_certificate_principal: PrincipalRef,
    observed_carrier_binding_digest: Digest32,
    response_wire: Box<[u8]>,
}

/// Raw PXDR bytes returned by one concrete post-PXFB Runtime-control exchange.
///
/// TLS peer evidence remains independent from the Runtime-local channel inside
/// PXDR. The exact signed PXCC Describe request is retained by PXFJ before this
/// value can exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeManagedServingDescribeMtlsExchangeSuccessV1 {
    observed_runtime_certificate_principal: PrincipalRef,
    observed_carrier_binding_digest: Digest32,
    response_wire: Box<[u8]>,
}

impl RuntimeManagedServingDescribeMtlsExchangeSuccessV1 {
    pub(crate) fn try_new(
        observed_runtime_certificate_principal: PrincipalRef,
        observed_carrier_binding_digest: Digest32,
        response_wire: Box<[u8]>,
    ) -> Result<Self, ManagedServingControllerError> {
        if bytes_are_zero(observed_runtime_certificate_principal.as_bytes())
            || digest_is_zero(observed_carrier_binding_digest)
            || response_wire.is_empty()
        {
            return Err(
                ManagedServingControllerError::ManagedReadyDescribeUnauthenticatedTransport,
            );
        }
        Ok(Self {
            observed_runtime_certificate_principal,
            observed_carrier_binding_digest,
            response_wire,
        })
    }

    #[must_use]
    pub(crate) const fn observed_runtime_certificate_principal(&self) -> PrincipalRef {
        self.observed_runtime_certificate_principal
    }

    #[must_use]
    pub(crate) const fn observed_carrier_binding_digest(&self) -> Digest32 {
        self.observed_carrier_binding_digest
    }

    #[must_use]
    pub(crate) fn response_wire(&self) -> &[u8] {
        &self.response_wire
    }
}

impl RuntimeManagedServingMtlsExchangeSuccessV1 {
    pub(crate) fn try_new(
        observed_runtime_certificate_principal: PrincipalRef,
        observed_carrier_binding_digest: Digest32,
        response_wire: Box<[u8]>,
    ) -> Result<Self, ManagedServingControllerError> {
        if bytes_are_zero(observed_runtime_certificate_principal.as_bytes())
            || digest_is_zero(observed_carrier_binding_digest)
            || response_wire.is_empty()
        {
            return Err(ManagedServingControllerError::ManagedServingUnauthenticatedTransport);
        }
        Ok(Self {
            observed_runtime_certificate_principal,
            observed_carrier_binding_digest,
            response_wire,
        })
    }

    #[must_use]
    pub(crate) const fn observed_runtime_certificate_principal(&self) -> PrincipalRef {
        self.observed_runtime_certificate_principal
    }

    #[must_use]
    pub(crate) const fn observed_carrier_binding_digest(&self) -> Digest32 {
        self.observed_carrier_binding_digest
    }

    #[must_use]
    pub(crate) fn response_wire(&self) -> &[u8] {
        &self.response_wire
    }
}

/// Authenticated PXFR retained with both outer and inner request correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedRuntimeManagedServingResponseV1 {
    carrier_request_digest: Digest32,
    inner_request_digest: Digest32,
    response: ManagedServingBootstrapResponseV1,
}

impl VerifiedRuntimeManagedServingResponseV1 {
    #[must_use]
    pub(crate) const fn carrier_request_digest(&self) -> Digest32 {
        self.carrier_request_digest
    }

    #[must_use]
    pub(crate) const fn inner_request_digest(&self) -> Digest32 {
        self.inner_request_digest
    }

    #[must_use]
    pub(crate) const fn response(&self) -> &ManagedServingBootstrapResponseV1 {
        &self.response
    }
}

impl RuntimeReferenceQueryMtlsExchangeSuccessV1 {
    pub(crate) fn try_new(
        observed_runtime_certificate_principal: PrincipalRef,
        observed_carrier_binding_digest: Digest32,
        response_wire: Box<[u8]>,
    ) -> Result<Self, ManagedServingControllerError> {
        if bytes_are_zero(observed_runtime_certificate_principal.as_bytes())
            || digest_is_zero(observed_carrier_binding_digest)
            || response_wire.is_empty()
        {
            return Err(ManagedServingControllerError::ReferenceQueryUnauthenticatedTransport);
        }
        Ok(Self {
            observed_runtime_certificate_principal,
            observed_carrier_binding_digest,
            response_wire,
        })
    }
}

/// Move-only one-shot authority containing a post-commit PXQR and its exact
/// signed outer PXCC ReferenceQuery carrier.
#[derive(Debug)]
pub(crate) struct ManagedRuntimeReferenceQueryActionV1 {
    carrier_request: RuntimeControlCarrierRequestV1,
    prepared: PreparedRuntimeQueryRequest,
}

impl ManagedRuntimeReferenceQueryActionV1 {
    #[must_use]
    pub(crate) const fn carrier_request(&self) -> &RuntimeControlCarrierRequestV1 {
        &self.carrier_request
    }

    #[must_use]
    pub(crate) const fn prepared(&self) -> &PreparedRuntimeQueryRequest {
        &self.prepared
    }
}

/// PXQS admitted only after pinned transport, Runtime signature and exact
/// current Describe channel/serving correlation all succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedRuntimeReferenceQueryResponseV1 {
    carrier_request_digest: Digest32,
    response: ReferenceQueryResponseV1,
    facts: ReferenceQueryFactsV1,
}

impl VerifiedRuntimeReferenceQueryResponseV1 {
    #[must_use]
    pub(crate) const fn carrier_request_digest(&self) -> Digest32 {
        self.carrier_request_digest
    }

    #[must_use]
    pub(crate) const fn response(&self) -> &ReferenceQueryResponseV1 {
        &self.response
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> ReferenceQueryFactsV1 {
        self.facts
    }

    #[must_use]
    pub(crate) fn into_response(self) -> ReferenceQueryResponseV1 {
        self.response
    }
}

impl ManagedServingDescribeVerifierV1 {
    pub(crate) fn revalidate_managed_serving_carrier(
        &self,
        ingress: &ManagedServingDescribeIngressV1,
        base: &VerifiedManagedFabricProducerContextV1,
        carrier_request: &RuntimeControlCarrierRequestV1,
    ) -> Result<(), ManagedServingControllerError> {
        self.validate_managed_serving_context(ingress, base)?;
        let inner = carrier_request
            .managed_serving_bootstrap_request()
            .ok_or(ManagedServingControllerError::ManagedServingCarrierRequestMismatch)?;
        validate_request(base, inner)?;
        verify_remote_carrier(self, carrier_request, inner)
    }

    /// Wraps one already-durable, independently signed PXFB in a fresh signed
    /// PXCC ManagedServingBootstrap carrier. The complete PXCB and byte-exact
    /// inner PXFB are self-verified before the value may cross persistence.
    pub(crate) fn try_build_managed_serving_bootstrap_carrier(
        &self,
        ingress: &ManagedServingDescribeIngressV1,
        base: &VerifiedManagedFabricProducerContextV1,
        fresh: FreshManagedServingBootstrapV1,
        controller_signer: &SigningKey,
        inner: &ManagedServingBootstrapRequestV1,
    ) -> Result<RuntimeControlCarrierRequestV1, ManagedServingControllerError> {
        self.validate_managed_serving_context(ingress, base)?;
        validate_request(base, inner)?;
        if controller_signer.verifying_key().to_bytes() != self.controller_public_key {
            return Err(ManagedServingControllerError::ControllerKeyMismatch);
        }
        if inner.request_id().as_bytes() != &fresh.request_id {
            return Err(ManagedServingControllerError::ManagedServingCarrierRequestMismatch);
        }
        if ingress.request.request_id() == inner.request_id()
            || ingress.request.authentication().claim().nonce() == fresh.authentication_nonce
            || inner.authentication().claim().nonce() == fresh.authentication_nonce
        {
            return Err(ManagedServingControllerError::FreshIdentityReused);
        }
        let claim = ApplyRequestAuthClaim::try_new(
            self.carrier.controller_principal(),
            self.carrier.controller_request_key(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)?,
            ED25519_ALGORITHM_VERSION,
            &fresh.authentication_nonce,
        )?;
        let draft = RuntimeControlCarrierRequestDraftV1::try_managed_serving_bootstrap(
            inner.request_id(),
            self.carrier.clone(),
            inner.clone(),
            claim,
        )?;
        let signature = controller_signer.sign(draft.signing_transcript()?.as_bytes());
        let carrier_request = draft.finalize(&signature.to_bytes())?;
        verify_runtime_control_request(
            self,
            &carrier_request,
            RuntimeControlCarrierKindV1::ManagedServingBootstrap,
            ManagedServingControllerError::ManagedServingCarrierRequestMismatch,
        )?;
        if carrier_request.managed_serving_bootstrap_request() != Some(inner) {
            return Err(ManagedServingControllerError::ManagedServingCarrierRequestMismatch);
        }
        Ok(carrier_request)
    }

    /// Verifies one raw PXFR only after the concrete TLS peer, complete PXCB,
    /// outer PXCC signature and byte-exact inner PXFB all match durable state.
    pub(crate) fn try_accept_managed_serving_response(
        &self,
        ingress: &ManagedServingDescribeIngressV1,
        base: &VerifiedManagedFabricProducerContextV1,
        carrier_request: &RuntimeControlCarrierRequestV1,
        transport: &RuntimeManagedServingMtlsExchangeSuccessV1,
    ) -> Result<VerifiedRuntimeManagedServingResponseV1, ManagedServingControllerError> {
        self.revalidate_managed_serving_carrier(ingress, base, carrier_request)?;
        let inner = carrier_request
            .managed_serving_bootstrap_request()
            .ok_or(ManagedServingControllerError::ManagedServingCarrierRequestMismatch)?;
        if transport.observed_runtime_certificate_principal != self.carrier.runtime_principal()
            || transport.observed_carrier_binding_digest != self.carrier.binding_digest()
        {
            return Err(ManagedServingControllerError::ManagedServingTransportPinMismatch);
        }
        let response = ManagedServingBootstrapResponseV1::decode(&transport.response_wire)?;
        let _ = VerifiedManagedServingPinV1::try_new(base, inner, &response)?;
        Ok(VerifiedRuntimeManagedServingResponseV1 {
            carrier_request_digest: carrier_request.request_digest(),
            inner_request_digest: inner.request_digest(),
            response,
        })
    }

    /// Admits a post-PXFB PXDR only after the pinned TLS peer, complete PXCB,
    /// exact durable Describe request, both signatures, restart succession and
    /// `ManagedReady` phase have all been verified. This proves current state;
    /// it is deliberately not a substitute for a missing PXFR.
    pub(crate) fn try_accept_managed_ready_describe_response(
        &self,
        previous: &ManagedServingDescribeIngressV1,
        request: RuntimeControlCarrierRequestV1,
        transport: &RuntimeManagedServingDescribeMtlsExchangeSuccessV1,
    ) -> Result<VerifiedManagedServingReadyV1, ManagedServingControllerError> {
        if transport.observed_runtime_certificate_principal != self.carrier.runtime_principal()
            || transport.observed_carrier_binding_digest != self.carrier.binding_digest()
        {
            return Err(ManagedServingControllerError::ManagedReadyDescribeTransportPinMismatch);
        }
        let ingress = ManagedServingDescribeIngressV1::try_accept(
            self,
            Some(previous),
            request,
            &transport.response_wire,
        )?;
        if ingress.phase() != RuntimeControlDescribeReadyPhaseV1::ManagedReady {
            return Err(ManagedServingControllerError::ManagedReadyDescribeRequired);
        }
        Ok(VerifiedManagedServingReadyV1 { ingress })
    }

    fn validate_managed_serving_context(
        &self,
        ingress: &ManagedServingDescribeIngressV1,
        base: &VerifiedManagedFabricProducerContextV1,
    ) -> Result<(), ManagedServingControllerError> {
        ingress.revalidate(self)?;
        let facts = ingress.serving_facts();
        if base.target() != self.target
            || base.target() != facts.target()
            || base.runtime_store_instance_id() != facts.runtime_store_instance_id()
            || base.projection() != facts.projection()
            || base.channel() != ingress.channel()
            || base.controller_principal() != self.carrier.controller_principal()
            || base.request_key() != self.carrier.controller_request_key()
            || base.controller_verifying_key() != self.controller_public_key
            || base.runtime_response_key() != self.carrier.runtime_response_key()
            || base.runtime_response_public_key().to_bytes() != self.runtime_response_public_key
        {
            return Err(ManagedServingControllerError::ManagedServingRemoteContextMismatch);
        }
        Ok(())
    }

    /// Wraps one ControllerStore-issued, already-durable PXQR in an exact
    /// fresh signed PXCC ReferenceQuery carrier and self-verifies both layers.
    pub(crate) fn try_build_reference_query(
        &self,
        ingress: &ManagedServingDescribeIngressV1,
        fresh: FreshManagedServingBootstrapV1,
        controller_signer: &SigningKey,
        prepared: PreparedRuntimeQueryRequest,
    ) -> Result<ManagedRuntimeReferenceQueryActionV1, ManagedServingControllerError> {
        self.validate_reference_query_context(ingress, &prepared)?;
        if controller_signer.verifying_key().to_bytes() != self.controller_public_key {
            return Err(ManagedServingControllerError::ControllerKeyMismatch);
        }
        let inner = prepared.request();
        if ingress.request.request_id().as_bytes() == &fresh.request_id
            || ingress.request.authentication().claim().nonce() == fresh.authentication_nonce
            || inner.query_id().as_bytes() == &fresh.request_id
            || inner.authentication().claim().nonce() == fresh.authentication_nonce
        {
            return Err(ManagedServingControllerError::FreshIdentityReused);
        }
        let claim = ApplyRequestAuthClaim::try_new(
            self.carrier.controller_principal(),
            self.carrier.controller_request_key(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)?,
            ED25519_ALGORITHM_VERSION,
            &fresh.authentication_nonce,
        )?;
        let draft = RuntimeControlCarrierRequestDraftV1::try_reference_query(
            ManagedServingBootstrapRequestIdV1::try_from_bytes(fresh.request_id)?,
            self.carrier.clone(),
            inner.clone(),
            claim,
        )?;
        let signature = controller_signer.sign(draft.signing_transcript()?.as_bytes());
        let carrier_request = draft.finalize(&signature.to_bytes())?;
        verify_runtime_control_request(
            self,
            &carrier_request,
            RuntimeControlCarrierKindV1::ReferenceQuery,
            ManagedServingControllerError::ReferenceQueryRequestMismatch,
        )?;
        if carrier_request.reference_query_request() != Some(inner) {
            return Err(ManagedServingControllerError::ReferenceQueryRequestMismatch);
        }
        Ok(ManagedRuntimeReferenceQueryActionV1 {
            carrier_request,
            prepared,
        })
    }

    /// Executes exactly one transport closure. The move-only action and
    /// `FnOnce` boundary make retry policy remain with the PXDN owner.
    pub(crate) async fn exchange_reference_query_once<Exchange, ExchangeFuture>(
        &self,
        ingress: &ManagedServingDescribeIngressV1,
        action: ManagedRuntimeReferenceQueryActionV1,
        exchange: Exchange,
    ) -> Result<VerifiedRuntimeReferenceQueryResponseV1, ManagedServingControllerError>
    where
        Exchange: FnOnce(Box<[u8]>) -> ExchangeFuture,
        ExchangeFuture: Future<
            Output = Result<
                RuntimeReferenceQueryMtlsExchangeSuccessV1,
                RuntimeReferenceQueryTransportErrorV1,
            >,
        >,
    {
        self.validate_reference_query_context(ingress, &action.prepared)?;
        verify_runtime_control_request(
            self,
            &action.carrier_request,
            RuntimeControlCarrierKindV1::ReferenceQuery,
            ManagedServingControllerError::ReferenceQueryRequestMismatch,
        )?;
        if action.carrier_request.reference_query_request() != Some(action.prepared.request()) {
            return Err(ManagedServingControllerError::ReferenceQueryRequestMismatch);
        }
        let transport = exchange(action.carrier_request.canonical_wire().into()).await?;
        self.try_accept_reference_query_response(
            ingress,
            &action.carrier_request,
            &action.prepared,
            transport.observed_runtime_certificate_principal,
            transport.observed_carrier_binding_digest,
            &transport.response_wire,
        )
    }

    /// Strict raw-PXQS verification entry used by the one-shot transport and
    /// focused tests. Runtime facts are exposed only after signature first,
    /// followed by exact request/channel/serving correlation.
    pub(crate) fn try_accept_reference_query_response(
        &self,
        ingress: &ManagedServingDescribeIngressV1,
        carrier_request: &RuntimeControlCarrierRequestV1,
        prepared: &PreparedRuntimeQueryRequest,
        observed_runtime_certificate_principal: PrincipalRef,
        observed_carrier_binding_digest: Digest32,
        response_wire: &[u8],
    ) -> Result<VerifiedRuntimeReferenceQueryResponseV1, ManagedServingControllerError> {
        self.validate_reference_query_context(ingress, prepared)?;
        verify_runtime_control_request(
            self,
            carrier_request,
            RuntimeControlCarrierKindV1::ReferenceQuery,
            ManagedServingControllerError::ReferenceQueryRequestMismatch,
        )?;
        if carrier_request.reference_query_request() != Some(prepared.request()) {
            return Err(ManagedServingControllerError::ReferenceQueryRequestMismatch);
        }
        if observed_runtime_certificate_principal != self.carrier.runtime_principal()
            || observed_carrier_binding_digest != self.carrier.binding_digest()
        {
            return Err(ManagedServingControllerError::ReferenceQueryTransportPinMismatch);
        }
        let response = ReferenceQueryResponseV1::decode(response_wire)?;
        if response.authentication_runtime_peer() != self.carrier.runtime_principal()
            || response.authentication_channel_binding_digest()
                != ingress.channel().binding_digest()
            || response.authentication_key() != self.carrier.runtime_response_key()
            || response.authentication_algorithm().value() != ED25519_ALGORITHM
            || response.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
            || response.authentication_signature().len() != ED25519_SIGNATURE_BYTES
            || ed25519_control_key_fingerprint(&self.runtime_response_public_key)
                .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?
                != self.carrier.runtime_response_key_fingerprint()
        {
            return Err(
                ManagedServingControllerError::ReferenceQueryResponseAuthenticationMismatch,
            );
        }
        let runtime_key = VerifyingKey::from_bytes(&self.runtime_response_public_key)
            .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
        if !verify_ed25519(
            &runtime_key,
            response.signing_transcript()?.as_bytes(),
            response.authentication_signature(),
        ) {
            return Err(
                ManagedServingControllerError::ReferenceQueryResponseAuthenticationMismatch,
            );
        }
        let facts = response
            .validate_against_request(
                prepared.request(),
                ingress.channel(),
                prepared.serving_baseline(),
            )
            .map_err(|_| {
                ManagedServingControllerError::ReferenceQueryResponseCorrelationMismatch
            })?;
        Ok(VerifiedRuntimeReferenceQueryResponseV1 {
            carrier_request_digest: carrier_request.request_digest(),
            response,
            facts,
        })
    }

    fn validate_reference_query_context(
        &self,
        ingress: &ManagedServingDescribeIngressV1,
        prepared: &PreparedRuntimeQueryRequest,
    ) -> Result<(), ManagedServingControllerError> {
        verify_describe_request(self, &ingress.request)?;
        verify_describe_response(self, &ingress.request, &ingress.response)?;
        ingress.validate_pins(self)?;
        if ingress.phase() != RuntimeControlDescribeReadyPhaseV1::LegacyReady {
            return Err(ManagedServingControllerError::ReferenceQueryRequiresLegacyReady);
        }
        let expected_serving = ingress_reference_serving_identity(ingress)?;
        let request = prepared.request();
        let decoded = ReferenceQueryRequestV1::decode(request.canonical_wire())?;
        if &decoded != request
            || prepared.request_time_channel() != ingress.channel()
            || prepared.serving_baseline() != expected_serving
            || prepared.response_key() != self.carrier.runtime_response_key()
            || prepared.response_algorithm().value() != ED25519_ALGORITHM
            || prepared.response_algorithm_version() != ED25519_ALGORITHM_VERSION
            || request.target() != self.target
            || request.expected_runtime_store_instance_id()
                != ingress.serving_facts().runtime_store_instance_id()
            || request.authentication().claim().principal() != self.carrier.controller_principal()
            || request.authentication().claim().key() != self.carrier.controller_request_key()
            || request.authentication().claim().algorithm().value() != ED25519_ALGORITHM
            || request.authentication().claim().algorithm_version() != ED25519_ALGORITHM_VERSION
            || request.authentication().signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ManagedServingControllerError::ReferenceQueryRequestMismatch);
        }
        let controller_key = VerifyingKey::from_bytes(&self.controller_public_key)
            .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
        if !verify_ed25519(
            &controller_key,
            request.signing_transcript()?.as_bytes(),
            request.authentication().signature(),
        ) {
            return Err(ManagedServingControllerError::ReferenceQueryRequestMismatch);
        }
        Ok(())
    }
}

/// Strictly revalidated, durable post-PXFB `ManagedReady` Describe facts.
///
/// The contained ingress owns the exact PXCC/PXDR bytes. Consumers that also
/// require the original PXFR must obtain its independent durable pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedManagedServingReadyV1 {
    ingress: ManagedServingDescribeIngressV1,
}

impl VerifiedManagedServingReadyV1 {
    #[must_use]
    pub(crate) const fn ingress(&self) -> &ManagedServingDescribeIngressV1 {
        &self.ingress
    }

    #[must_use]
    pub(crate) fn request_wire(&self) -> &[u8] {
        self.ingress.request_wire()
    }

    #[must_use]
    pub(crate) fn response_wire(&self) -> &[u8] {
        self.ingress.response_wire()
    }

    #[must_use]
    pub(crate) const fn serving_facts(&self) -> &ManagedServingBootstrapFactsV1 {
        self.ingress.serving_facts()
    }

    #[must_use]
    pub(crate) const fn channel(&self) -> ReferenceChannelBindingV1 {
        self.ingress.channel()
    }
}

fn ingress_reference_serving_identity(
    ingress: &ManagedServingDescribeIngressV1,
) -> Result<ReferenceBootstrapServingIdentityV1, ManagedServingControllerError> {
    let facts = ingress.serving_facts();
    Ok(ReferenceBootstrapServingIdentityV1::try_new(
        facts.target(),
        facts.runtime_store_instance_id(),
        facts.snapshot_sequence(),
        facts.runtime_host_epoch(),
        facts.clock_domain(),
        facts.clock_generation(),
    )?)
}

fn verify_runtime_control_request(
    verifier: &ManagedServingDescribeVerifierV1,
    request: &RuntimeControlCarrierRequestV1,
    expected_kind: RuntimeControlCarrierKindV1,
    mismatch: ManagedServingControllerError,
) -> Result<(), ManagedServingControllerError> {
    if request.kind() != expected_kind
        || request.authentication().claim().algorithm().value() != ED25519_ALGORITHM
        || request.authentication().claim().algorithm_version() != ED25519_ALGORITHM_VERSION
        || request.authentication().signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(mismatch);
    }
    let key = VerifyingKey::from_bytes(&verifier.controller_public_key)
        .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
    request
        .verify_controller_carrier(
            &verifier.carrier,
            |principal, key_ref, fingerprint, transcript, signature| {
                principal == verifier.carrier.controller_principal()
                    && key_ref == verifier.carrier.controller_request_key()
                    && fingerprint == verifier.carrier.controller_request_key_fingerprint()
                    && verify_ed25519(&key, transcript, signature)
            },
        )
        .map_err(|_| mismatch)?;
    Ok(())
}

fn verify_describe_request(
    verifier: &ManagedServingDescribeVerifierV1,
    request: &RuntimeControlCarrierRequestV1,
) -> Result<(), ManagedServingControllerError> {
    if request.kind() != RuntimeControlCarrierKindV1::Describe
        || request.managed_serving_bootstrap_request().is_some()
        || request.reference_query_request().is_some()
        || request.authentication().claim().algorithm().value() != ED25519_ALGORITHM
        || request.authentication().claim().algorithm_version() != ED25519_ALGORITHM_VERSION
        || request.authentication().signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(ManagedServingControllerError::DescribeRequestAuthenticationMismatch);
    }
    let key = VerifyingKey::from_bytes(&verifier.controller_public_key)
        .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
    request
        .verify_controller_carrier(
            &verifier.carrier,
            |principal, key_ref, fingerprint, transcript, signature| {
                principal == verifier.carrier.controller_principal()
                    && key_ref == verifier.carrier.controller_request_key()
                    && fingerprint == verifier.carrier.controller_request_key_fingerprint()
                    && verify_ed25519(&key, transcript, signature)
            },
        )
        .map_err(|_| ManagedServingControllerError::DescribeRequestAuthenticationMismatch)?;
    Ok(())
}

fn verify_fresh_describe_request(
    verifier: &ManagedServingDescribeVerifierV1,
    previous: &ManagedServingDescribeIngressV1,
    request: &RuntimeControlCarrierRequestV1,
) -> Result<(), ManagedServingControllerError> {
    previous.revalidate(verifier)?;
    verify_describe_request(verifier, request)?;
    if request.request_id() == previous.request.request_id()
        || request.request_digest() == previous.request.request_digest()
        || request.authentication().claim().nonce()
            == previous.request.authentication().claim().nonce()
    {
        return Err(ManagedServingControllerError::FreshIdentityReused);
    }
    Ok(())
}

fn verify_describe_response(
    verifier: &ManagedServingDescribeVerifierV1,
    request: &RuntimeControlCarrierRequestV1,
    response: &RuntimeControlDescribeReadyResponseV1,
) -> Result<(), ManagedServingControllerError> {
    let authentication = response.authentication();
    if authentication.algorithm().value() != ED25519_ALGORITHM
        || authentication.algorithm_version() != ED25519_ALGORITHM_VERSION
        || response.authentication_signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(ManagedServingControllerError::DescribeResponseAuthenticationMismatch);
    }
    let key = VerifyingKey::from_bytes(&verifier.runtime_response_public_key)
        .map_err(|_| ManagedServingControllerError::InvalidDescribePin)?;
    response
        .verify_runtime_response(
            request,
            &verifier.carrier,
            |principal, key_ref, fingerprint, transcript, signature| {
                principal == verifier.carrier.runtime_principal()
                    && key_ref == verifier.carrier.runtime_response_key()
                    && fingerprint == verifier.carrier.runtime_response_key_fingerprint()
                    && verify_ed25519(&key, transcript, signature)
            },
        )
        .map_err(|_| ManagedServingControllerError::DescribeResponseAuthenticationMismatch)?;
    Ok(())
}

fn verify_ed25519(key: &VerifyingKey, transcript: &[u8], signature: &[u8]) -> bool {
    let Ok(signature) = <[u8; ED25519_SIGNATURE_BYTES]>::try_from(signature) else {
        return false;
    };
    key.verify_strict(transcript, &Signature::from_bytes(&signature))
        .is_ok()
}

/// Durable local phase of one Controller observation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServingBootstrapPhaseV1 {
    ReadyForRequest,
    RequestDurable,
    AttemptInFlight,
    ResponseDurable,
    AttemptClosedNoResponse,
}

impl ManagedServingBootstrapPhaseV1 {
    pub(crate) const fn wire_value(self) -> u8 {
        match self {
            Self::ReadyForRequest => 1,
            Self::RequestDurable => 2,
            Self::AttemptInFlight => 3,
            Self::ResponseDurable => 4,
            Self::AttemptClosedNoResponse => 5,
        }
    }

    pub(crate) const fn try_from_wire(value: u8) -> Result<Self, ManagedServingControllerError> {
        match value {
            1 => Ok(Self::ReadyForRequest),
            2 => Ok(Self::RequestDurable),
            3 => Ok(Self::AttemptInFlight),
            4 => Ok(Self::ResponseDurable),
            5 => Ok(Self::AttemptClosedNoResponse),
            _ => Err(ManagedServingControllerError::InvalidStateEncoding),
        }
    }
}

/// Durable phase of the read-only Describe reconciliation that follows a
/// terminal remote PXFB attempt. It owns no PXFB replay authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServingDescribeReconcilePhaseV1 {
    Idle,
    RequestDurable,
    AttemptInFlight,
    ResponseDurable,
    AttemptClosedNoResponse,
}

impl ManagedServingDescribeReconcilePhaseV1 {
    pub(crate) const fn wire_value(self) -> u8 {
        match self {
            Self::Idle => 1,
            Self::RequestDurable => 2,
            Self::AttemptInFlight => 3,
            Self::ResponseDurable => 4,
            Self::AttemptClosedNoResponse => 5,
        }
    }

    pub(crate) const fn try_from_wire(value: u8) -> Result<Self, ManagedServingControllerError> {
        match value {
            1 => Ok(Self::Idle),
            2 => Ok(Self::RequestDurable),
            3 => Ok(Self::AttemptInFlight),
            4 => Ok(Self::ResponseDurable),
            5 => Ok(Self::AttemptClosedNoResponse),
            _ => Err(ManagedServingControllerError::InvalidStateEncoding),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedServingDescribeReconcileStateV1 {
    phase: ManagedServingDescribeReconcilePhaseV1,
    request: Option<RuntimeControlCarrierRequestV1>,
    response: Option<RuntimeControlDescribeReadyResponseV1>,
}

#[derive(Clone, Copy)]
pub(crate) struct ManagedServingDescribeReconcileDecodeV1<'a> {
    pub(crate) phase: ManagedServingDescribeReconcilePhaseV1,
    pub(crate) request_wire: &'a [u8],
    pub(crate) response_wire: &'a [u8],
    pub(crate) previous: Option<&'a ManagedServingDescribeIngressV1>,
}

impl ManagedServingDescribeReconcileDecodeV1<'_> {
    pub(crate) const fn idle() -> Self {
        Self {
            phase: ManagedServingDescribeReconcilePhaseV1::Idle,
            request_wire: &[],
            response_wire: &[],
            previous: None,
        }
    }
}

impl ManagedServingDescribeReconcileStateV1 {
    const fn initial() -> Self {
        Self {
            phase: ManagedServingDescribeReconcilePhaseV1::Idle,
            request: None,
            response: None,
        }
    }

    fn decode(
        phase: ManagedServingDescribeReconcilePhaseV1,
        request_wire: &[u8],
        response_wire: &[u8],
        verifier: Option<&ManagedServingDescribeVerifierV1>,
        previous: Option<&ManagedServingDescribeIngressV1>,
    ) -> Result<Self, ManagedServingControllerError> {
        match phase {
            ManagedServingDescribeReconcilePhaseV1::Idle => {
                if !request_wire.is_empty() || !response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                Ok(Self::initial())
            }
            ManagedServingDescribeReconcilePhaseV1::RequestDurable
            | ManagedServingDescribeReconcilePhaseV1::AttemptInFlight
            | ManagedServingDescribeReconcilePhaseV1::AttemptClosedNoResponse => {
                if request_wire.is_empty() || !response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                let verifier =
                    verifier.ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
                let previous =
                    previous.ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
                let request = RuntimeControlCarrierRequestV1::decode(request_wire)?;
                verify_fresh_describe_request(verifier, previous, &request)?;
                Ok(Self {
                    phase,
                    request: Some(request),
                    response: None,
                })
            }
            ManagedServingDescribeReconcilePhaseV1::ResponseDurable => {
                if request_wire.is_empty() || response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                let verifier =
                    verifier.ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
                let previous =
                    previous.ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
                let ingress = ManagedServingDescribeIngressV1::decode(
                    verifier,
                    Some(previous),
                    request_wire,
                    response_wire,
                )?;
                if ingress.phase() != RuntimeControlDescribeReadyPhaseV1::ManagedReady {
                    return Err(ManagedServingControllerError::ManagedReadyDescribeRequired);
                }
                Ok(Self {
                    phase,
                    request: Some(ingress.request),
                    response: Some(ingress.response),
                })
            }
        }
    }

    fn try_prepare(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
        previous: &ManagedServingDescribeIngressV1,
        fresh: FreshManagedServingBootstrapV1,
        controller_signer: &SigningKey,
    ) -> Result<Self, ManagedServingControllerError> {
        if !matches!(
            self.phase,
            ManagedServingDescribeReconcilePhaseV1::Idle
                | ManagedServingDescribeReconcilePhaseV1::AttemptClosedNoResponse
        ) {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        if let Some(prior_attempt) = self.request.as_ref()
            && (prior_attempt.request_id().as_bytes() == &fresh.request_id
                || prior_attempt.authentication().claim().nonce() == fresh.authentication_nonce)
        {
            return Err(ManagedServingControllerError::FreshIdentityReused);
        }
        let request = verifier.try_build_request(Some(previous), fresh, controller_signer)?;
        Ok(Self {
            phase: ManagedServingDescribeReconcilePhaseV1::RequestDurable,
            request: Some(request),
            response: None,
        })
    }

    fn try_claim(
        &self,
    ) -> Result<(Self, RuntimeControlCarrierRequestV1), ManagedServingControllerError> {
        if self.phase != ManagedServingDescribeReconcilePhaseV1::RequestDurable
            || self.response.is_some()
        {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        let request = self
            .request
            .clone()
            .ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
        Ok((
            Self {
                phase: ManagedServingDescribeReconcilePhaseV1::AttemptInFlight,
                request: Some(request.clone()),
                response: None,
            },
            request,
        ))
    }

    fn try_close_no_response(&self) -> Result<Self, ManagedServingControllerError> {
        if self.phase != ManagedServingDescribeReconcilePhaseV1::AttemptInFlight
            || self.request.is_none()
            || self.response.is_some()
        {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        Ok(Self {
            phase: ManagedServingDescribeReconcilePhaseV1::AttemptClosedNoResponse,
            request: self.request.clone(),
            response: None,
        })
    }

    fn try_accept_response(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
        previous: &ManagedServingDescribeIngressV1,
        transport: &RuntimeManagedServingDescribeMtlsExchangeSuccessV1,
    ) -> Result<(Self, VerifiedManagedServingReadyV1), ManagedServingControllerError> {
        if self.phase != ManagedServingDescribeReconcilePhaseV1::AttemptInFlight
            || self.response.is_some()
        {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        let request = self
            .request
            .clone()
            .ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
        let ready =
            verifier.try_accept_managed_ready_describe_response(previous, request, transport)?;
        Ok((
            Self {
                phase: ManagedServingDescribeReconcilePhaseV1::ResponseDurable,
                request: Some(ready.ingress.request.clone()),
                response: Some(ready.ingress.response.clone()),
            },
            ready,
        ))
    }

    fn verified_ready(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<VerifiedManagedServingReadyV1, ManagedServingControllerError> {
        if self.phase != ManagedServingDescribeReconcilePhaseV1::ResponseDurable {
            return Err(ManagedServingControllerError::ManagedReadyDescribeRequired);
        }
        let ingress = ManagedServingDescribeIngressV1::try_accept(
            verifier,
            Some(previous),
            self.request
                .clone()
                .ok_or(ManagedServingControllerError::InvalidStateEncoding)?,
            self.response
                .as_ref()
                .ok_or(ManagedServingControllerError::InvalidStateEncoding)?
                .canonical_wire(),
        )?;
        if ingress.phase() != RuntimeControlDescribeReadyPhaseV1::ManagedReady {
            return Err(ManagedServingControllerError::ManagedReadyDescribeRequired);
        }
        Ok(VerifiedManagedServingReadyV1 { ingress })
    }
}

/// Exact PXFB/PXFR bytes retained inside the successor Controller snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedServingBootstrapStateV1 {
    phase: ManagedServingBootstrapPhaseV1,
    request: Option<ManagedServingBootstrapRequestV1>,
    carrier_request: Option<RuntimeControlCarrierRequestV1>,
    response: Option<ManagedServingBootstrapResponseV1>,
    describe_reconcile: ManagedServingDescribeReconcileStateV1,
}

impl ManagedServingBootstrapStateV1 {
    #[must_use]
    pub(crate) const fn initial() -> Self {
        Self {
            phase: ManagedServingBootstrapPhaseV1::ReadyForRequest,
            request: None,
            carrier_request: None,
            response: None,
            describe_reconcile: ManagedServingDescribeReconcileStateV1::initial(),
        }
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> ManagedServingBootstrapPhaseV1 {
        self.phase
    }

    #[must_use]
    pub(crate) fn request_wire(&self) -> &[u8] {
        self.request
            .as_ref()
            .map_or(&[], ManagedServingBootstrapRequestV1::canonical_wire)
    }

    #[must_use]
    pub(crate) fn response_wire(&self) -> &[u8] {
        self.response
            .as_ref()
            .map_or(&[], ManagedServingBootstrapResponseV1::canonical_wire)
    }

    #[must_use]
    pub(crate) fn carrier_request_wire(&self) -> &[u8] {
        self.carrier_request
            .as_ref()
            .map_or(&[], RuntimeControlCarrierRequestV1::canonical_wire)
    }

    #[must_use]
    pub(crate) const fn request(&self) -> Option<&ManagedServingBootstrapRequestV1> {
        self.request.as_ref()
    }

    #[must_use]
    pub(crate) const fn carrier_request(&self) -> Option<&RuntimeControlCarrierRequestV1> {
        self.carrier_request.as_ref()
    }

    #[must_use]
    pub(crate) const fn describe_reconcile_phase(&self) -> ManagedServingDescribeReconcilePhaseV1 {
        self.describe_reconcile.phase
    }

    #[must_use]
    pub(crate) fn describe_request_wire(&self) -> &[u8] {
        self.describe_reconcile
            .request
            .as_ref()
            .map_or(&[], RuntimeControlCarrierRequestV1::canonical_wire)
    }

    #[must_use]
    pub(crate) fn describe_response_wire(&self) -> &[u8] {
        self.describe_reconcile
            .response
            .as_ref()
            .map_or(&[], RuntimeControlDescribeReadyResponseV1::canonical_wire)
    }

    #[must_use]
    pub(crate) const fn describe_request(&self) -> Option<&RuntimeControlCarrierRequestV1> {
        self.describe_reconcile.request.as_ref()
    }

    /// The current remote tranche begins only from a pristine PXFJ serving
    /// state. In particular, a closed in-flight PXCC may already have changed
    /// Runtime and must be reconciled through a new Describe before any new
    /// PXFB can be authorized.
    pub(crate) fn require_remote_prepare_ready(&self) -> Result<(), ManagedServingControllerError> {
        match self.phase {
            ManagedServingBootstrapPhaseV1::ReadyForRequest => Ok(()),
            ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse => {
                Err(ManagedServingControllerError::RemoteDescribeReconcileRequired)
            }
            _ => Err(ManagedServingControllerError::InvalidPhase),
        }
    }

    pub(crate) fn decode(
        phase: ManagedServingBootstrapPhaseV1,
        request_wire: &[u8],
        response_wire: &[u8],
        base: &VerifiedManagedFabricProducerContextV1,
    ) -> Result<Self, ManagedServingControllerError> {
        Self::decode_with_remote_carrier(phase, request_wire, response_wire, &[], base, None)
    }

    pub(crate) fn decode_with_remote_carrier(
        phase: ManagedServingBootstrapPhaseV1,
        request_wire: &[u8],
        response_wire: &[u8],
        carrier_request_wire: &[u8],
        base: &VerifiedManagedFabricProducerContextV1,
        verifier: Option<&ManagedServingDescribeVerifierV1>,
    ) -> Result<Self, ManagedServingControllerError> {
        Self::decode_with_remote_reconcile(
            phase,
            request_wire,
            response_wire,
            carrier_request_wire,
            base,
            verifier,
            ManagedServingDescribeReconcileDecodeV1::idle(),
        )
    }

    pub(crate) fn decode_with_remote_reconcile(
        phase: ManagedServingBootstrapPhaseV1,
        request_wire: &[u8],
        response_wire: &[u8],
        carrier_request_wire: &[u8],
        base: &VerifiedManagedFabricProducerContextV1,
        verifier: Option<&ManagedServingDescribeVerifierV1>,
        describe: ManagedServingDescribeReconcileDecodeV1<'_>,
    ) -> Result<Self, ManagedServingControllerError> {
        let state = match phase {
            ManagedServingBootstrapPhaseV1::ReadyForRequest => {
                if !request_wire.is_empty()
                    || !response_wire.is_empty()
                    || !carrier_request_wire.is_empty()
                {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                Self::initial()
            }
            ManagedServingBootstrapPhaseV1::RequestDurable => {
                if request_wire.is_empty() || !response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                if !carrier_request_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                let request = ManagedServingBootstrapRequestV1::decode(request_wire)?;
                validate_request(base, &request)?;
                Self {
                    phase,
                    request: Some(request),
                    carrier_request: None,
                    response: None,
                    describe_reconcile: ManagedServingDescribeReconcileStateV1::initial(),
                }
            }
            ManagedServingBootstrapPhaseV1::AttemptInFlight
            | ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse => {
                if request_wire.is_empty() || !response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                let request = ManagedServingBootstrapRequestV1::decode(request_wire)?;
                validate_request(base, &request)?;
                let carrier_request =
                    decode_optional_remote_carrier(carrier_request_wire, &request, verifier)?;
                Self {
                    phase,
                    request: Some(request),
                    carrier_request,
                    response: None,
                    describe_reconcile: ManagedServingDescribeReconcileStateV1::initial(),
                }
            }
            ManagedServingBootstrapPhaseV1::ResponseDurable => {
                if request_wire.is_empty() || response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                let request = ManagedServingBootstrapRequestV1::decode(request_wire)?;
                validate_request(base, &request)?;
                let carrier_request =
                    decode_optional_remote_carrier(carrier_request_wire, &request, verifier)?;
                let response = ManagedServingBootstrapResponseV1::decode(response_wire)?;
                let _ = VerifiedManagedServingPinV1::try_new(base, &request, &response)?;
                Self {
                    phase,
                    request: Some(request),
                    carrier_request,
                    response: Some(response),
                    describe_reconcile: ManagedServingDescribeReconcileStateV1::initial(),
                }
            }
        };
        let describe_reconcile = ManagedServingDescribeReconcileStateV1::decode(
            describe.phase,
            describe.request_wire,
            describe.response_wire,
            verifier,
            describe.previous,
        )?;
        if describe.phase != ManagedServingDescribeReconcilePhaseV1::Idle
            && !matches!(
                phase,
                ManagedServingBootstrapPhaseV1::ResponseDurable
                    | ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse
            )
        {
            return Err(ManagedServingControllerError::InvalidStateEncoding);
        }
        let state = Self {
            describe_reconcile,
            ..state
        };
        if describe.phase == ManagedServingDescribeReconcilePhaseV1::ResponseDurable {
            let verifier = verifier.ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
            let previous = describe
                .previous
                .ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
            let ready = state
                .describe_reconcile
                .verified_ready(verifier, previous)?;
            state.validate_ready_against_bootstrap_terminal(&ready)?;
        }
        Ok(state)
    }

    pub(crate) fn try_prepare(
        &self,
        base: &VerifiedManagedFabricProducerContextV1,
        fresh: FreshManagedServingBootstrapV1,
        controller_signer: &SigningKey,
    ) -> Result<Self, ManagedServingControllerError> {
        if !matches!(
            self.phase,
            ManagedServingBootstrapPhaseV1::ReadyForRequest
                | ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse
                | ManagedServingBootstrapPhaseV1::ResponseDurable
        ) || self.describe_reconcile.phase != ManagedServingDescribeReconcilePhaseV1::Idle
        {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        if controller_signer.verifying_key().to_bytes() != base.controller_verifying_key() {
            return Err(ManagedServingControllerError::ControllerKeyMismatch);
        }
        if let Some(previous) = self.request.as_ref()
            && (previous.request_id().as_bytes() == &fresh.request_id
                || previous.authentication().claim().nonce() == fresh.authentication_nonce)
        {
            return Err(ManagedServingControllerError::FreshIdentityReused);
        }
        let claim = ApplyRequestAuthClaim::try_new(
            base.controller_principal(),
            base.request_key(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)?,
            ED25519_ALGORITHM_VERSION,
            &fresh.authentication_nonce,
        )?;
        let draft = ManagedServingBootstrapRequestDraftV1::try_new(
            ManagedServingBootstrapRequestIdV1::try_from_bytes(fresh.request_id)?,
            base.target(),
            base.source_scope(),
            base.runtime_store_instance_id(),
            base.projection().clone(),
            base.channel(),
            claim,
        )?;
        let signature = controller_signer.sign(draft.signing_transcript()?.as_bytes());
        let request = draft.finalize(&signature.to_bytes())?;
        validate_request(base, &request)?;
        Ok(Self {
            phase: ManagedServingBootstrapPhaseV1::RequestDurable,
            request: Some(request),
            carrier_request: None,
            response: None,
            describe_reconcile: ManagedServingDescribeReconcileStateV1::initial(),
        })
    }

    pub(crate) fn try_claim(
        &self,
    ) -> Result<(Self, ManagedServingBootstrapRequestV1), ManagedServingControllerError> {
        if self.phase != ManagedServingBootstrapPhaseV1::RequestDurable || self.response.is_some() {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        let request = self
            .request
            .clone()
            .ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
        Ok((
            Self {
                phase: ManagedServingBootstrapPhaseV1::AttemptInFlight,
                request: Some(request.clone()),
                carrier_request: None,
                response: None,
                describe_reconcile: self.describe_reconcile.clone(),
            },
            request,
        ))
    }

    pub(crate) fn try_claim_remote(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
        carrier_request: RuntimeControlCarrierRequestV1,
    ) -> Result<(Self, ManagedServingBootstrapRequestV1), ManagedServingControllerError> {
        if self.phase != ManagedServingBootstrapPhaseV1::RequestDurable
            || self.response.is_some()
            || self.carrier_request.is_some()
        {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        let request = self
            .request
            .clone()
            .ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
        verify_remote_carrier(verifier, &carrier_request, &request)?;
        Ok((
            Self {
                phase: ManagedServingBootstrapPhaseV1::AttemptInFlight,
                request: Some(request.clone()),
                carrier_request: Some(carrier_request),
                response: None,
                describe_reconcile: self.describe_reconcile.clone(),
            },
            request,
        ))
    }

    pub(crate) fn try_close_no_response(&self) -> Result<Self, ManagedServingControllerError> {
        if self.phase != ManagedServingBootstrapPhaseV1::AttemptInFlight
            || self.request.is_none()
            || self.response.is_some()
        {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        Ok(Self {
            phase: ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse,
            request: self.request.clone(),
            carrier_request: self.carrier_request.clone(),
            response: None,
            describe_reconcile: self.describe_reconcile.clone(),
        })
    }

    pub(crate) fn try_accept_response(
        &self,
        base: &VerifiedManagedFabricProducerContextV1,
        response_wire: &[u8],
    ) -> Result<(Self, VerifiedManagedServingPinV1), ManagedServingControllerError> {
        if self.phase != ManagedServingBootstrapPhaseV1::AttemptInFlight || self.response.is_some()
        {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        let request = self
            .request
            .as_ref()
            .ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
        let response = ManagedServingBootstrapResponseV1::decode(response_wire)?;
        let pin = VerifiedManagedServingPinV1::try_new(base, request, &response)?;
        Ok((
            Self {
                phase: ManagedServingBootstrapPhaseV1::ResponseDurable,
                request: Some(request.clone()),
                carrier_request: self.carrier_request.clone(),
                response: Some(response),
                describe_reconcile: self.describe_reconcile.clone(),
            },
            pin,
        ))
    }

    pub(crate) fn try_prepare_managed_ready_describe(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
        previous: &ManagedServingDescribeIngressV1,
        fresh: FreshManagedServingBootstrapV1,
        controller_signer: &SigningKey,
    ) -> Result<Self, ManagedServingControllerError> {
        if !matches!(
            self.phase,
            ManagedServingBootstrapPhaseV1::ResponseDurable
                | ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse
        ) {
            return Err(ManagedServingControllerError::InvalidPhase);
        }
        previous.revalidate(verifier)?;
        let describe_reconcile =
            self.describe_reconcile
                .try_prepare(verifier, previous, fresh, controller_signer)?;
        Ok(Self {
            describe_reconcile,
            ..self.clone()
        })
    }

    pub(crate) fn try_claim_managed_ready_describe(
        &self,
    ) -> Result<(Self, RuntimeControlCarrierRequestV1), ManagedServingControllerError> {
        let (describe_reconcile, request) = self.describe_reconcile.try_claim()?;
        Ok((
            Self {
                describe_reconcile,
                ..self.clone()
            },
            request,
        ))
    }

    pub(crate) fn try_close_managed_ready_describe_no_response(
        &self,
    ) -> Result<Self, ManagedServingControllerError> {
        let describe_reconcile = self.describe_reconcile.try_close_no_response()?;
        Ok(Self {
            describe_reconcile,
            ..self.clone()
        })
    }

    pub(crate) fn try_accept_managed_ready_describe_response(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
        previous: &ManagedServingDescribeIngressV1,
        transport: &RuntimeManagedServingDescribeMtlsExchangeSuccessV1,
    ) -> Result<(Self, VerifiedManagedServingReadyV1), ManagedServingControllerError> {
        let (describe_reconcile, ready) = self
            .describe_reconcile
            .try_accept_response(verifier, previous, transport)?;
        self.validate_ready_against_bootstrap_terminal(&ready)?;
        Ok((
            Self {
                describe_reconcile,
                ..self.clone()
            },
            ready,
        ))
    }

    pub(crate) fn verified_managed_ready(
        &self,
        verifier: &ManagedServingDescribeVerifierV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<VerifiedManagedServingReadyV1, ManagedServingControllerError> {
        let ready = self.describe_reconcile.verified_ready(verifier, previous)?;
        self.validate_ready_against_bootstrap_terminal(&ready)?;
        Ok(ready)
    }

    fn validate_ready_against_bootstrap_terminal(
        &self,
        ready: &VerifiedManagedServingReadyV1,
    ) -> Result<(), ManagedServingControllerError> {
        if self.phase != ManagedServingBootstrapPhaseV1::ResponseDurable {
            return Ok(());
        }
        let prior = self
            .response
            .as_ref()
            .ok_or(ManagedServingControllerError::InvalidStateEncoding)?
            .facts();
        let current = ready.serving_facts();
        if current.target() != prior.target()
            || current.runtime_store_instance_id() != prior.runtime_store_instance_id()
        {
            return Err(ManagedServingControllerError::DescribeStoreMismatch);
        }
        if current.projection() != prior.projection() {
            return Err(ManagedServingControllerError::DescribeManifestMismatch);
        }
        if current.runtime_host_epoch() < prior.runtime_host_epoch()
            || current.snapshot_sequence() < prior.snapshot_sequence()
        {
            return Err(ManagedServingControllerError::DescribeEpochRegression);
        }
        Ok(())
    }

    pub(crate) fn verified_pin(
        &self,
        base: &VerifiedManagedFabricProducerContextV1,
    ) -> Result<VerifiedManagedServingPinV1, ManagedServingControllerError> {
        if self.phase != ManagedServingBootstrapPhaseV1::ResponseDurable {
            return Err(ManagedServingControllerError::ServingPinRequired);
        }
        VerifiedManagedServingPinV1::try_new(
            base,
            self.request
                .as_ref()
                .ok_or(ManagedServingControllerError::InvalidStateEncoding)?,
            self.response
                .as_ref()
                .ok_or(ManagedServingControllerError::InvalidStateEncoding)?,
        )
    }
}

/// Cryptographically verified current serving pin used to produce PXAR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedManagedServingPinV1 {
    request_digest: Digest32,
    response_digest: Digest32,
    response: ManagedServingBootstrapResponseV1,
}

impl VerifiedManagedServingPinV1 {
    fn try_new(
        base: &VerifiedManagedFabricProducerContextV1,
        request: &ManagedServingBootstrapRequestV1,
        response: &ManagedServingBootstrapResponseV1,
    ) -> Result<Self, ManagedServingControllerError> {
        validate_request(base, request)?;
        let facts = response.validate_against_request(request, base.channel())?;
        if response.authentication_runtime_peer() != base.channel().runtime_peer()
            || response.authentication_channel_binding_digest() != base.channel().binding_digest()
            || response.authentication_key() != base.runtime_response_key()
            || response.authentication_algorithm().value() != ED25519_ALGORITHM
            || response.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
            || response.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ManagedServingControllerError::ResponseAuthenticationMismatch);
        }
        let signature: [u8; ED25519_SIGNATURE_BYTES] = response
            .authentication_signature()
            .try_into()
            .map_err(|_| ManagedServingControllerError::ResponseAuthenticationMismatch)?;
        base.runtime_response_public_key()
            .verify_strict(
                response.signing_transcript()?.as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| ManagedServingControllerError::ResponseAuthenticationMismatch)?;
        let _ = base.try_with_current_serving_facts(facts)?;
        Ok(Self {
            request_digest: request.request_digest(),
            response_digest: response.response_digest(),
            response: response.clone(),
        })
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub(crate) const fn response_digest(&self) -> Digest32 {
        self.response_digest
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> &ManagedServingBootstrapFactsV1 {
        self.response.facts()
    }

    pub(crate) fn apply_context(
        &self,
        base: &VerifiedManagedFabricProducerContextV1,
    ) -> Result<VerifiedManagedFabricProducerContextV1, ManagedServingControllerError> {
        Ok(base.try_with_current_serving_facts(self.response.facts())?)
    }
}

fn decode_optional_remote_carrier(
    carrier_request_wire: &[u8],
    inner: &ManagedServingBootstrapRequestV1,
    verifier: Option<&ManagedServingDescribeVerifierV1>,
) -> Result<Option<RuntimeControlCarrierRequestV1>, ManagedServingControllerError> {
    if carrier_request_wire.is_empty() {
        if verifier.is_some() {
            return Err(ManagedServingControllerError::InvalidStateEncoding);
        }
        return Ok(None);
    }
    let verifier = verifier.ok_or(ManagedServingControllerError::InvalidStateEncoding)?;
    let carrier_request = RuntimeControlCarrierRequestV1::decode(carrier_request_wire)?;
    verify_remote_carrier(verifier, &carrier_request, inner)?;
    Ok(Some(carrier_request))
}

fn verify_remote_carrier(
    verifier: &ManagedServingDescribeVerifierV1,
    carrier_request: &RuntimeControlCarrierRequestV1,
    inner: &ManagedServingBootstrapRequestV1,
) -> Result<(), ManagedServingControllerError> {
    verify_runtime_control_request(
        verifier,
        carrier_request,
        RuntimeControlCarrierKindV1::ManagedServingBootstrap,
        ManagedServingControllerError::ManagedServingCarrierRequestMismatch,
    )?;
    if carrier_request.managed_serving_bootstrap_request() != Some(inner) {
        return Err(ManagedServingControllerError::ManagedServingCarrierRequestMismatch);
    }
    Ok(())
}

fn validate_request(
    base: &VerifiedManagedFabricProducerContextV1,
    request: &ManagedServingBootstrapRequestV1,
) -> Result<(), ManagedServingControllerError> {
    let authentication = request.authentication();
    let claim = authentication.claim();
    if request.target() != base.target()
        || request.source_scope() != base.source_scope()
        || request.expected_runtime_store_instance_id() != base.runtime_store_instance_id()
        || request.projection() != base.projection()
        || request.channel() != base.channel()
        || claim.principal() != base.controller_principal()
        || claim.key() != base.request_key()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
        || authentication.signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(ManagedServingControllerError::RequestAuthenticationMismatch);
    }
    let signature: [u8; ED25519_SIGNATURE_BYTES] = authentication
        .signature()
        .try_into()
        .map_err(|_| ManagedServingControllerError::RequestAuthenticationMismatch)?;
    VerifyingKey::from_bytes(&base.controller_verifying_key())
        .map_err(|_| ManagedServingControllerError::RequestAuthenticationMismatch)?
        .verify_strict(
            request.signing_transcript()?.as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| ManagedServingControllerError::RequestAuthenticationMismatch)
}

const fn bytes_are_zero(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

fn digest_is_zero(value: Digest32) -> bool {
    bytes_are_zero(value.as_bytes())
}

/// One-shot remote Runtime carrier delivery classification. An uncertain
/// result is never retried inside this client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeReferenceQueryTransportErrorV1 {
    NotSent,
    Uncertain,
    Rejected,
}

/// Classification returned by exactly one remote PXCC/PXFR exchange. No
/// variant grants replay authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeManagedServingTransportErrorV1 {
    NotSent,
    Uncertain,
    Rejected,
}

/// Classification returned by exactly one post-PXFB Describe exchange. No
/// variant grants replay authority for that exact PXCC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeManagedServingDescribeTransportErrorV1 {
    NotSent,
    Uncertain,
    Rejected,
}

/// Fail-closed Controller errors for PXFB/PXFR durable ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServingControllerError {
    Contract(ManagedServingBootstrapError),
    ReferenceControl(ReferenceControlError),
    Authentication(ApplyAuthError),
    Producer(ManagedFabricProducerError),
    ReferenceQueryTransport(RuntimeReferenceQueryTransportErrorV1),
    InvalidFreshIdentity,
    FreshIdentityReused,
    ControllerKeyMismatch,
    RequestAuthenticationMismatch,
    ResponseAuthenticationMismatch,
    InvalidPhase,
    ServingPinRequired,
    InvalidStateEncoding,
    InvalidDescribePin,
    DescribeRequestAuthenticationMismatch,
    DescribeResponseAuthenticationMismatch,
    DescribeCorrelationMismatch,
    DescribeStoreMismatch,
    DescribeManifestMismatch,
    DescribeEpochRegression,
    DescribeChannelRebindWithoutRestart,
    DescribePhaseRegression,
    ManagedServingRemoteContextMismatch,
    ManagedServingCarrierRequestMismatch,
    ManagedServingUnauthenticatedTransport,
    ManagedServingTransportPinMismatch,
    ManagedServingTransport(RuntimeManagedServingTransportErrorV1),
    ManagedServingTransportAuthoritySpent,
    RemoteDescribeReconcileRequired,
    ManagedReadyDescribeRequired,
    ManagedReadyDescribeUnauthenticatedTransport,
    ManagedReadyDescribeTransportPinMismatch,
    ManagedReadyDescribeTransport(RuntimeManagedServingDescribeTransportErrorV1),
    ManagedReadyDescribeTransportAuthoritySpent,
    ReferenceQueryRequiresLegacyReady,
    ReferenceQueryRequestMismatch,
    ReferenceQueryUnauthenticatedTransport,
    ReferenceQueryTransportPinMismatch,
    ReferenceQueryResponseAuthenticationMismatch,
    ReferenceQueryResponseCorrelationMismatch,
}

impl From<ManagedServingBootstrapError> for ManagedServingControllerError {
    fn from(value: ManagedServingBootstrapError) -> Self {
        Self::Contract(value)
    }
}

impl From<ReferenceControlError> for ManagedServingControllerError {
    fn from(value: ReferenceControlError) -> Self {
        Self::ReferenceControl(value)
    }
}

impl From<ApplyAuthError> for ManagedServingControllerError {
    fn from(value: ApplyAuthError) -> Self {
        Self::Authentication(value)
    }
}

impl From<ManagedFabricProducerError> for ManagedServingControllerError {
    fn from(value: ManagedFabricProducerError) -> Self {
        Self::Producer(value)
    }
}

impl From<RuntimeReferenceQueryTransportErrorV1> for ManagedServingControllerError {
    fn from(value: RuntimeReferenceQueryTransportErrorV1) -> Self {
        Self::ReferenceQueryTransport(value)
    }
}

impl From<RuntimeManagedServingTransportErrorV1> for ManagedServingControllerError {
    fn from(value: RuntimeManagedServingTransportErrorV1) -> Self {
        Self::ManagedServingTransport(value)
    }
}

impl From<RuntimeManagedServingDescribeTransportErrorV1> for ManagedServingControllerError {
    fn from(value: RuntimeManagedServingDescribeTransportErrorV1) -> Self {
        Self::ManagedReadyDescribeTransport(value)
    }
}

impl fmt::Display for ManagedServingControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed serving Controller failed: {self:?}")
    }
}

impl std::error::Error for ManagedServingControllerError {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_kernel::time::{ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant};
    use paraegox_runtime_contracts::apply::ApplyOperationId;
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        RestrictedRuntimeApplyCarrierBindingFieldsV1, RestrictedRuntimeApplyCarrierBindingV1,
    };
    use paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricManifestProjectionV1;
    use paraegox_runtime_contracts::managed_serving_bootstrap::{
        ManagedServingBootstrapError, ManagedServingBootstrapFactsV1,
        ManagedServingBootstrapRequestIdV1, ManagedServingBootstrapResponseAuthClaimV1,
        RuntimeControlCarrierKindV1, RuntimeControlCarrierRequestDraftV1,
        RuntimeControlCarrierRequestV1, RuntimeControlDescribeReadyFactsV1,
        RuntimeControlDescribeReadyPhaseV1, RuntimeControlDescribeReadyResponseDraftV1,
    };
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, SourceScopeRef};
    use paraegox_runtime_contracts::reference_control::{
        MAX_REFERENCE_QUERY_RESPONSE_BYTES, ReferenceBootstrapServingIdentityV1,
        ReferenceChannelBindingV1, ReferenceQueryDesiredHeadV1, ReferenceQueryDesiredStateV1,
        ReferenceQueryFactsV1, ReferenceQueryIdV1, ReferenceQueryLiveFactsV1,
        ReferenceQueryLiveStateV1, ReferenceQueryOperationLookupV1, ReferenceQueryOperationStateV1,
        ReferenceQueryOwnerStateV1, ReferenceQueryRequestDraftV1, ReferenceQueryRequestV1,
        ReferenceQueryResponseAuthClaimV1, ReferenceQueryResponseDraftV1, ReferenceQueryResponseV1,
        ReferenceQuerySelectorV1, ed25519_control_key_fingerprint,
    };
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
    };

    use super::{
        FreshManagedServingBootstrapV1, ManagedServingBootstrapPhaseV1,
        ManagedServingBootstrapStateV1, ManagedServingControllerError,
        ManagedServingDescribeIngressV1, ManagedServingDescribeVerifierV1,
        RuntimeReferenceQueryMtlsExchangeSuccessV1, RuntimeReferenceQueryTransportErrorV1,
        ingress_reference_serving_identity,
    };
    use crate::runtime_control_client::PreparedRuntimeQueryRequest;

    const FABRIC_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_fabric_successor_v1.json");
    const CONTROLLER_SEED: [u8; 32] = [0x41; 32];
    const RUNTIME_SEED: [u8; 32] = [0x51; 32];
    const STORE: [u8; 32] = [0x61; 32];

    #[test]
    fn remote_closed_attempt_requires_describe_reconciliation_before_another_px_f_b() {
        let closed = ManagedServingBootstrapStateV1 {
            phase: ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse,
            request: None,
            carrier_request: None,
            response: None,
            describe_reconcile: super::ManagedServingDescribeReconcileStateV1::initial(),
        };
        assert_eq!(
            closed.require_remote_prepare_ready(),
            Err(ManagedServingControllerError::RemoteDescribeReconcileRequired)
        );
        assert_eq!(
            ManagedServingBootstrapStateV1::initial().require_remote_prepare_ready(),
            Ok(())
        );
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("non-hex fixture byte"),
        }
    }

    fn projection() -> ManagedFabricManifestProjectionV1 {
        let marker = "\"projection_hex\": \"";
        let start = FABRIC_FIXTURE.find(marker).expect("projection fixture") + marker.len();
        let end = start
            + FABRIC_FIXTURE[start..]
                .find('"')
                .expect("projection fixture terminator");
        let hex = &FABRIC_FIXTURE.as_bytes()[start..end];
        let bytes: Vec<u8> = hex
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect();
        ManagedFabricManifestProjectionV1::decode(&bytes).expect("projection")
    }

    fn channel(
        target: paraegox_kernel::identity::RuntimeHostId,
        marker: u8,
    ) -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            target,
            PrincipalRef::from_bytes([0x31; 16]),
            Digest32::from_bytes([marker; 32]),
            Digest32::from_bytes([marker.wrapping_add(1); 32]),
        )
        .expect("channel")
    }

    fn carrier(
        projection: &ManagedFabricManifestProjectionV1,
        controller: &SigningKey,
        runtime: &SigningKey,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: projection.target(),
                runtime_principal: PrincipalRef::from_bytes([0x31; 16]),
                controller_principal: PrincipalRef::from_bytes([0x32; 16]),
                endpoint_ref: [0x33; 16],
                endpoint_generation: 3,
                route: "paraegox/runtime-a/apply",
                controller_request_key: ApplyAuthKeyRef::from_bytes([0x34; 16]),
                controller_request_key_fingerprint: ed25519_control_key_fingerprint(
                    controller.verifying_key().as_bytes(),
                )
                .expect("Controller fingerprint"),
                runtime_response_key: ApplyAuthKeyRef::from_bytes([0x35; 16]),
                runtime_response_key_fingerprint: ed25519_control_key_fingerprint(
                    runtime.verifying_key().as_bytes(),
                )
                .expect("Runtime fingerprint"),
                control_transport_profile_ref: [0x36; 16],
                control_transport_profile_digest: Digest32::from_bytes([0x37; 32]),
            },
        )
        .expect("carrier")
    }

    fn describe_request(
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        controller: &SigningKey,
        marker: u8,
    ) -> paraegox_runtime_contracts::managed_serving_bootstrap::RuntimeControlCarrierRequestV1 {
        let claim = ApplyRequestAuthClaim::try_new(
            carrier.controller_principal(),
            carrier.controller_request_key(),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            &[marker.wrapping_add(1); 32],
        )
        .expect("claim");
        let draft = RuntimeControlCarrierRequestDraftV1::try_describe(
            ManagedServingBootstrapRequestIdV1::try_from_bytes([marker; 16]).expect("request id"),
            carrier.clone(),
            claim,
        )
        .expect("Describe draft");
        let signature = controller.sign(draft.signing_transcript().expect("transcript").as_bytes());
        draft
            .finalize(&signature.to_bytes())
            .expect("Describe request")
    }

    struct ResponseInput<'a> {
        request: &'a paraegox_runtime_contracts::managed_serving_bootstrap::
            RuntimeControlCarrierRequestV1,
        projection: ManagedFabricManifestProjectionV1,
        channel: ReferenceChannelBindingV1,
        store: [u8; 32],
        epoch: u64,
        snapshot: u64,
        phase: RuntimeControlDescribeReadyPhaseV1,
        runtime: &'a SigningKey,
    }

    fn describe_response(input: ResponseInput<'_>) -> Box<[u8]> {
        let facts = ManagedServingBootstrapFactsV1::try_recovered_ready(
            input.request.carrier().target(),
            input.store,
            input.projection,
            input.epoch,
            input.snapshot,
            ClockReading::new(
                ClockDomainRef::from_bytes([0x71; 16]),
                ClockGeneration::try_new(input.epoch).expect("clock generation"),
                MonotonicInstant::from_ticks(input.snapshot),
            ),
        )
        .expect("serving facts");
        let ready = RuntimeControlDescribeReadyFactsV1::try_new(input.phase, facts, input.channel)
            .expect("ready facts");
        let auth = ManagedServingBootstrapResponseAuthClaimV1::try_new(
            input.channel,
            input.request.carrier().runtime_response_key(),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("response claim");
        let draft = RuntimeControlDescribeReadyResponseDraftV1::try_new(input.request, ready, auth)
            .expect("response draft");
        let signature = input.runtime.sign(
            draft
                .signing_transcript()
                .expect("response transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("response")
            .canonical_wire()
            .into()
    }

    fn fixture() -> (
        ManagedFabricManifestProjectionV1,
        SigningKey,
        SigningKey,
        RestrictedRuntimeApplyCarrierBindingV1,
        ManagedServingDescribeVerifierV1,
    ) {
        let projection = projection();
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let runtime = SigningKey::from_bytes(&RUNTIME_SEED);
        let carrier = carrier(&projection, &controller, &runtime);
        let verifier = ManagedServingDescribeVerifierV1::try_new(
            projection.target(),
            carrier.clone(),
            controller.verifying_key().to_bytes(),
            runtime.verifying_key().to_bytes(),
            projection.fields().manifest_digest,
        )
        .expect("verifier");
        (projection, controller, runtime, carrier, verifier)
    }

    fn legacy_ingress(
        projection: &ManagedFabricManifestProjectionV1,
        controller: &SigningKey,
        runtime: &SigningKey,
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        verifier: &ManagedServingDescribeVerifierV1,
        marker: u8,
    ) -> ManagedServingDescribeIngressV1 {
        let request = verifier
            .try_build_request(
                None,
                FreshManagedServingBootstrapV1::try_new([marker; 16], [marker.wrapping_add(1); 32])
                    .expect("fresh legacy Describe"),
                controller,
            )
            .expect("legacy Describe request");
        assert_eq!(request.carrier(), carrier);
        let response = describe_response(ResponseInput {
            request: &request,
            projection: projection.clone(),
            channel: channel(projection.target(), marker.wrapping_add(2)),
            store: STORE,
            epoch: 3,
            snapshot: 5,
            phase: RuntimeControlDescribeReadyPhaseV1::LegacyReady,
            runtime,
        });
        ManagedServingDescribeIngressV1::try_accept(verifier, None, request, &response)
            .expect("legacy Describe ingress")
    }

    fn query_request(
        target: paraegox_kernel::identity::RuntimeHostId,
        store: [u8; 32],
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        controller: &SigningKey,
        marker: u8,
    ) -> ReferenceQueryRequestV1 {
        let selector = ReferenceQuerySelectorV1::try_new(
            ReferenceQueryIdV1::from_bytes([marker; 16]),
            target,
            SourceScopeRef::from_bytes([0xa1; 16]),
            store,
            ApplyOperationId::from_bytes([0xa2; 16]),
            Some(Digest32::from_bytes([0xa3; 32])),
        )
        .expect("query selector");
        let claim = ApplyRequestAuthClaim::try_new(
            carrier.controller_principal(),
            carrier.controller_request_key(),
            ApplyAuthAlgorithm::try_new(1).expect("query algorithm"),
            1,
            &[marker.wrapping_add(1); 32],
        )
        .expect("query claim");
        let draft = ReferenceQueryRequestDraftV1::try_new(
            selector,
            claim,
            MAX_REFERENCE_QUERY_RESPONSE_BYTES as u32,
        )
        .expect("query draft");
        let signature = controller.sign(
            draft
                .signing_transcript()
                .expect("query transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("query request")
    }

    fn prepared_query(
        ingress: &ManagedServingDescribeIngressV1,
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        controller: &SigningKey,
        marker: u8,
    ) -> PreparedRuntimeQueryRequest {
        PreparedRuntimeQueryRequest::try_new(
            query_request(
                ingress.serving_facts().target(),
                ingress.serving_facts().runtime_store_instance_id(),
                carrier,
                controller,
                marker,
            ),
            ingress.channel(),
            carrier.runtime_response_key(),
            ApplyAuthAlgorithm::try_new(1).expect("prepared query algorithm"),
            1,
            ingress_reference_serving_identity(ingress).expect("query serving baseline"),
        )
        .expect("prepared query")
    }

    fn query_response(
        request: &ReferenceQueryRequestV1,
        serving: ReferenceBootstrapServingIdentityV1,
        channel: ReferenceChannelBindingV1,
        response_key: ApplyAuthKeyRef,
        runtime: &SigningKey,
    ) -> ReferenceQueryResponseV1 {
        let operation = ReferenceQueryOperationStateV1::try_new(
            ReferenceQueryOwnerStateV1::Operational,
            None,
            ReferenceQueryOperationLookupV1::Unknown,
        )
        .expect("query operation facts");
        let desired = ReferenceQueryDesiredStateV1::try_new(
            ReferenceQueryDesiredHeadV1::None,
            SourcePlanRevision::new(0),
        )
        .expect("query desired facts");
        let live = ReferenceQueryLiveFactsV1::try_new(
            ReferenceQueryLiveStateV1::ExactZero,
            0,
            serving.snapshot_sequence(),
            Digest32::from_bytes([0xa4; 32]),
        )
        .expect("query live facts");
        let facts =
            ReferenceQueryFactsV1::try_new(serving, operation, desired, live).expect("query facts");
        let claim = ReferenceQueryResponseAuthClaimV1::try_new(
            channel,
            response_key,
            ApplyAuthAlgorithm::try_new(1).expect("query response algorithm"),
            1,
        )
        .expect("query response claim");
        let draft = ReferenceQueryResponseDraftV1::try_new(request, facts, channel, claim)
            .expect("query response draft");
        let signature = runtime.sign(
            draft
                .signing_transcript()
                .expect("query response transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("query response")
    }

    #[test]
    fn describe_ingress_verifies_both_signatures_and_exposes_pxfb_builder_facts() {
        let (projection, controller, runtime, carrier, verifier) = fixture();
        let request = describe_request(&carrier, &controller, 0x81);
        let local_channel = channel(projection.target(), 0x82);
        let response = describe_response(ResponseInput {
            request: &request,
            projection: projection.clone(),
            channel: local_channel,
            store: STORE,
            epoch: 3,
            snapshot: 5,
            phase: RuntimeControlDescribeReadyPhaseV1::LegacyReady,
            runtime: &runtime,
        });
        let ingress = ManagedServingDescribeIngressV1::try_accept(
            &verifier,
            None,
            request.clone(),
            &response,
        )
        .expect("verified ingress");
        assert_eq!(ingress.serving_facts().target(), projection.target());
        assert_eq!(ingress.serving_facts().runtime_store_instance_id(), STORE);
        assert_eq!(ingress.projection(), &projection);
        assert_eq!(ingress.channel(), local_channel);
        assert_eq!(ingress.request_wire(), request.canonical_wire());
        assert_eq!(ingress.response_wire(), response.as_ref());
        assert_eq!(
            ManagedServingDescribeIngressV1::decode(
                &verifier,
                None,
                ingress.request_wire(),
                ingress.response_wire(),
            )
            .expect("durable reopen"),
            ingress
        );
    }

    #[test]
    fn describe_ingress_rejects_forged_controller_runtime_and_manifest_pins() {
        let (projection, controller, runtime, carrier, verifier) = fixture();
        let request = describe_request(&carrier, &controller, 0x83);
        let response = describe_response(ResponseInput {
            request: &request,
            projection: projection.clone(),
            channel: channel(projection.target(), 0x84),
            store: STORE,
            epoch: 3,
            snapshot: 5,
            phase: RuntimeControlDescribeReadyPhaseV1::LegacyReady,
            runtime: &runtime,
        });

        let mut forged_request = request.canonical_wire().to_vec();
        *forged_request.last_mut().expect("request signature") ^= 1;
        let forged_request = paraegox_runtime_contracts::managed_serving_bootstrap::
            RuntimeControlCarrierRequestV1::decode(&forged_request)
            .expect("opaque forged request signature");
        assert!(matches!(
            ManagedServingDescribeIngressV1::try_accept(&verifier, None, forged_request, &response,),
            Err(ManagedServingControllerError::DescribeRequestAuthenticationMismatch)
        ));

        let mut forged_response = response.to_vec();
        *forged_response.last_mut().expect("response signature") ^= 1;
        assert!(matches!(
            ManagedServingDescribeIngressV1::try_accept(
                &verifier,
                None,
                request.clone(),
                &forged_response,
            ),
            Err(ManagedServingControllerError::DescribeResponseAuthenticationMismatch)
        ));

        let wrong_manifest = ManagedServingDescribeVerifierV1::try_new(
            projection.target(),
            carrier,
            controller.verifying_key().to_bytes(),
            runtime.verifying_key().to_bytes(),
            Digest32::from_bytes([0xff; 32]),
        )
        .expect("wrong manifest remains a structurally valid pin");
        assert!(matches!(
            ManagedServingDescribeIngressV1::try_accept(&wrong_manifest, None, request, &response,),
            Err(ManagedServingControllerError::DescribeManifestMismatch)
        ));

        let channel_mismatch_request = describe_request(verifier.carrier(), &controller, 0x85);
        let channel_mismatch = ReferenceChannelBindingV1::try_new(
            projection.target(),
            PrincipalRef::from_bytes([0xfe; 16]),
            Digest32::from_bytes([0xed; 32]),
            Digest32::from_bytes([0xec; 32]),
        )
        .expect("well-shaped mismatched Runtime-local channel");
        let channel_mismatch_serving = ManagedServingBootstrapFactsV1::try_recovered_ready(
            projection.target(),
            STORE,
            projection,
            3,
            5,
            ClockReading::new(
                ClockDomainRef::from_bytes([0x71; 16]),
                ClockGeneration::try_new(3).expect("clock generation"),
                MonotonicInstant::from_ticks(5),
            ),
        )
        .expect("serving facts");
        let channel_mismatch_ready = RuntimeControlDescribeReadyFactsV1::try_new(
            RuntimeControlDescribeReadyPhaseV1::LegacyReady,
            channel_mismatch_serving,
            channel_mismatch,
        )
        .expect("ready facts remain structurally valid");
        let channel_mismatch_auth = ManagedServingBootstrapResponseAuthClaimV1::try_new(
            channel_mismatch,
            verifier.carrier().runtime_response_key(),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("response claim");
        assert!(matches!(
            RuntimeControlDescribeReadyResponseDraftV1::try_new(
                &channel_mismatch_request,
                channel_mismatch_ready,
                channel_mismatch_auth,
            ),
            Err(ManagedServingBootstrapError::InvalidControlReadyFacts)
        ));
    }

    #[test]
    fn describe_restart_rebinds_local_channel_only_after_a_higher_runtime_epoch() {
        let (projection, controller, runtime, carrier, verifier) = fixture();
        let first_request = describe_request(&carrier, &controller, 0x85);
        let first_response = describe_response(ResponseInput {
            request: &first_request,
            projection: projection.clone(),
            channel: channel(projection.target(), 0x86),
            store: STORE,
            epoch: 3,
            snapshot: 5,
            phase: RuntimeControlDescribeReadyPhaseV1::LegacyReady,
            runtime: &runtime,
        });
        let first = ManagedServingDescribeIngressV1::try_accept(
            &verifier,
            None,
            first_request,
            &first_response,
        )
        .expect("first ingress");

        let same_epoch_request = describe_request(&carrier, &controller, 0x87);
        let same_epoch_response = describe_response(ResponseInput {
            request: &same_epoch_request,
            projection: projection.clone(),
            channel: channel(projection.target(), 0x88),
            store: STORE,
            epoch: 3,
            snapshot: 6,
            phase: RuntimeControlDescribeReadyPhaseV1::ManagedReady,
            runtime: &runtime,
        });
        assert!(matches!(
            ManagedServingDescribeIngressV1::try_accept(
                &verifier,
                Some(&first),
                same_epoch_request,
                &same_epoch_response,
            ),
            Err(ManagedServingControllerError::DescribeChannelRebindWithoutRestart)
        ));

        let restart_request = describe_request(&carrier, &controller, 0x89);
        let restarted_channel = channel(projection.target(), 0x8a);
        let restart_response = describe_response(ResponseInput {
            request: &restart_request,
            projection: projection.clone(),
            channel: restarted_channel,
            store: STORE,
            epoch: 4,
            snapshot: 6,
            phase: RuntimeControlDescribeReadyPhaseV1::ManagedReady,
            runtime: &runtime,
        });
        let restarted = ManagedServingDescribeIngressV1::try_accept(
            &verifier,
            Some(&first),
            restart_request,
            &restart_response,
        )
        .expect("higher-epoch channel rebind");
        assert_eq!(restarted.channel(), restarted_channel);

        let wrong_store_request = describe_request(&carrier, &controller, 0x8b);
        let wrong_store_response = describe_response(ResponseInput {
            request: &wrong_store_request,
            projection,
            channel: restarted_channel,
            store: [0x62; 32],
            epoch: 5,
            snapshot: 7,
            phase: RuntimeControlDescribeReadyPhaseV1::ManagedReady,
            runtime: &runtime,
        });
        assert!(matches!(
            ManagedServingDescribeIngressV1::try_accept(
                &verifier,
                Some(&restarted),
                wrong_store_request,
                &wrong_store_response,
            ),
            Err(ManagedServingControllerError::DescribeStoreMismatch)
        ));
    }

    #[test]
    fn describe_builder_owns_fresh_identity_and_rejects_replay() {
        let (projection, controller, runtime, _, verifier) = fixture();
        let fresh = FreshManagedServingBootstrapV1::try_new([0x91; 16], [0x92; 32])
            .expect("fresh Describe identity");
        let request = verifier
            .try_build_request(None, fresh, &controller)
            .expect("crate-owned Describe request");
        assert_eq!(request.kind(), RuntimeControlCarrierKindV1::Describe);
        assert!(request.managed_serving_bootstrap_request().is_none());
        assert!(request.reference_query_request().is_none());

        let response = describe_response(ResponseInput {
            request: &request,
            projection,
            channel: channel(verifier.target(), 0x93),
            store: STORE,
            epoch: 3,
            snapshot: 5,
            phase: RuntimeControlDescribeReadyPhaseV1::LegacyReady,
            runtime: &runtime,
        });
        let ingress = ManagedServingDescribeIngressV1::try_accept(
            &verifier,
            None,
            request.clone(),
            &response,
        )
        .expect("first Describe ingress");

        assert!(matches!(
            ManagedServingDescribeIngressV1::try_accept(
                &verifier,
                Some(&ingress),
                request,
                &response,
            ),
            Err(ManagedServingControllerError::FreshIdentityReused)
        ));
        assert!(matches!(
            verifier.try_build_request(
                Some(&ingress),
                FreshManagedServingBootstrapV1::try_new([0x94; 16], [0x92; 32])
                    .expect("same nonce"),
                &controller,
            ),
            Err(ManagedServingControllerError::FreshIdentityReused)
        ));
        assert!(matches!(
            verifier.try_build_request(
                Some(&ingress),
                FreshManagedServingBootstrapV1::try_new([0x91; 16], [0x95; 32])
                    .expect("same request ID"),
                &controller,
            ),
            Err(ManagedServingControllerError::FreshIdentityReused)
        ));
        assert!(matches!(
            verifier.try_build_request(
                Some(&ingress),
                FreshManagedServingBootstrapV1::try_new([0x96; 16], [0x97; 32])
                    .expect("fresh wrong-signer request"),
                &SigningKey::from_bytes(&[0x98; 32]),
            ),
            Err(ManagedServingControllerError::ControllerKeyMismatch)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reference_query_carrier_sends_exact_durable_pxqr_once() {
        let (projection, controller, runtime, carrier, verifier) = fixture();
        let ingress = legacy_ingress(
            &projection,
            &controller,
            &runtime,
            &carrier,
            &verifier,
            0xd1,
        );
        let prepared = prepared_query(&ingress, &carrier, &controller, 0xd3);
        let expected_query = prepared.request().clone();
        let response = query_response(
            &expected_query,
            prepared.serving_baseline(),
            ingress.channel(),
            carrier.runtime_response_key(),
            &runtime,
        );
        let action = verifier
            .try_build_reference_query(
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xd5; 16], [0xd6; 32])
                    .expect("fresh query carrier"),
                &controller,
                prepared,
            )
            .expect("query carrier action");
        assert_eq!(
            action.carrier_request().kind(),
            RuntimeControlCarrierKindV1::ReferenceQuery
        );
        assert_eq!(action.prepared().request(), &expected_query);
        let expected_carrier_digest = action.carrier_request().request_digest();
        let carrier_binding_digest = carrier.binding_digest();
        let runtime_certificate_principal = carrier.runtime_principal();
        let sent_query = expected_query.clone();
        let expected_response = response.clone();
        let calls = AtomicU64::new(0);
        let verified = verifier
            .exchange_reference_query_once(&ingress, action, |wire| {
                calls.fetch_add(1, Ordering::Relaxed);
                async move {
                    let outer = RuntimeControlCarrierRequestV1::decode(&wire)
                        .unwrap_or_else(|error| panic!("query carrier decode failed: {error}"));
                    assert_eq!(outer.kind(), RuntimeControlCarrierKindV1::ReferenceQuery);
                    assert_eq!(outer.reference_query_request(), Some(&sent_query));
                    Ok::<_, RuntimeReferenceQueryTransportErrorV1>(
                        RuntimeReferenceQueryMtlsExchangeSuccessV1::try_new(
                            runtime_certificate_principal,
                            carrier_binding_digest,
                            response.canonical_wire().into(),
                        )
                        .unwrap_or_else(|error| panic!("query mTLS result failed: {error}")),
                    )
                }
            })
            .await
            .unwrap_or_else(|error| panic!("query carrier exchange failed: {error}"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(verified.carrier_request_digest(), expected_carrier_digest);
        assert_eq!(
            verified.facts().serving(),
            ingress_reference_serving_identity(&ingress).expect("accepted serving")
        );
        verified
            .response()
            .validate_against_request(
                &expected_query,
                ingress.channel(),
                ingress_reference_serving_identity(&ingress).expect("validation serving"),
            )
            .expect("strict accepted PXQS");
        assert_eq!(
            verified.into_response().canonical_wire(),
            expected_response.canonical_wire()
        );
    }

    #[test]
    fn reference_query_carrier_rejects_kind_signer_target_channel_serving_and_signature() {
        let (projection, controller, runtime, carrier, verifier) = fixture();
        let ingress = legacy_ingress(
            &projection,
            &controller,
            &runtime,
            &carrier,
            &verifier,
            0xe1,
        );
        let prepared = prepared_query(&ingress, &carrier, &controller, 0xe4);
        let valid_response = query_response(
            prepared.request(),
            prepared.serving_baseline(),
            ingress.channel(),
            carrier.runtime_response_key(),
            &runtime,
        );
        let wrong_kind = verifier
            .try_build_request(
                Some(&ingress),
                FreshManagedServingBootstrapV1::try_new([0xe6; 16], [0xe7; 32])
                    .expect("wrong-kind fresh identity"),
                &controller,
            )
            .expect("Describe carrier for wrong-kind test");
        assert!(matches!(
            verifier.try_accept_reference_query_response(
                &ingress,
                &wrong_kind,
                &prepared,
                carrier.runtime_principal(),
                carrier.binding_digest(),
                valid_response.canonical_wire(),
            ),
            Err(ManagedServingControllerError::ReferenceQueryRequestMismatch)
        ));

        assert!(matches!(
            verifier.try_build_reference_query(
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xe8; 16], [0xe9; 32])
                    .expect("wrong-signer fresh identity"),
                &SigningKey::from_bytes(&[0xea; 32]),
                prepared_query(&ingress, &carrier, &controller, 0xeb),
            ),
            Err(ManagedServingControllerError::ControllerKeyMismatch)
        ));

        let inner = query_request(projection.target(), STORE, &carrier, &controller, 0xf6);
        let mut forged_inner_wire = inner.canonical_wire().to_vec();
        *forged_inner_wire.last_mut().expect("PXQR signature") ^= 1;
        let forged_inner = ReferenceQueryRequestV1::decode(&forged_inner_wire)
            .expect("opaque forged PXQR signature");
        let forged_prepared = PreparedRuntimeQueryRequest::try_new(
            forged_inner,
            ingress.channel(),
            carrier.runtime_response_key(),
            ApplyAuthAlgorithm::try_new(1).expect("forged PXQR algorithm"),
            1,
            ingress_reference_serving_identity(&ingress).expect("forged PXQR baseline"),
        )
        .expect("structurally prepared forged PXQR");
        assert!(matches!(
            verifier.try_build_reference_query(
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xf7; 16], [0xf8; 32])
                    .expect("forged-inner fresh identity"),
                &controller,
                forged_prepared,
            ),
            Err(ManagedServingControllerError::ReferenceQueryRequestMismatch)
        ));

        let prepared = prepared_query(&ingress, &carrier, &controller, 0xec);
        let action = verifier
            .try_build_reference_query(
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xee; 16], [0xef; 32])
                    .expect("strict response fresh identity"),
                &controller,
                prepared,
            )
            .expect("strict response action");
        let prepared = action.prepared();
        assert!(matches!(
            verifier.try_accept_reference_query_response(
                &ingress,
                action.carrier_request(),
                prepared,
                carrier.runtime_principal(),
                Digest32::from_bytes([0xf0; 32]),
                valid_response.canonical_wire(),
            ),
            Err(ManagedServingControllerError::ReferenceQueryTransportPinMismatch)
        ));

        let wrong_target = paraegox_kernel::identity::RuntimeHostId::from_bytes([0xf1; 16]);
        let wrong_target_channel = ReferenceChannelBindingV1::try_new(
            wrong_target,
            carrier.runtime_principal(),
            Digest32::from_bytes([0xf2; 32]),
            Digest32::from_bytes([0xf3; 32]),
        )
        .expect("wrong target channel");
        let baseline = prepared.serving_baseline();
        let wrong_target_serving = ReferenceBootstrapServingIdentityV1::try_new(
            wrong_target,
            baseline.runtime_store_instance_id(),
            baseline.snapshot_sequence(),
            baseline.runtime_host_epoch(),
            baseline.clock_domain(),
            baseline.clock_generation(),
        )
        .expect("wrong target serving");
        let wrong_target_request = query_request(
            wrong_target,
            baseline.runtime_store_instance_id(),
            &carrier,
            &controller,
            0xf4,
        );
        let wrong_target_response = query_response(
            &wrong_target_request,
            wrong_target_serving,
            wrong_target_channel,
            carrier.runtime_response_key(),
            &runtime,
        );
        assert!(
            verifier
                .try_accept_reference_query_response(
                    &ingress,
                    action.carrier_request(),
                    prepared,
                    carrier.runtime_principal(),
                    carrier.binding_digest(),
                    wrong_target_response.canonical_wire(),
                )
                .is_err()
        );

        let wrong_channel = channel(projection.target(), 0xf5);
        let wrong_channel_response = query_response(
            prepared.request(),
            prepared.serving_baseline(),
            wrong_channel,
            carrier.runtime_response_key(),
            &runtime,
        );
        assert!(matches!(
            verifier.try_accept_reference_query_response(
                &ingress,
                action.carrier_request(),
                prepared,
                carrier.runtime_principal(),
                carrier.binding_digest(),
                wrong_channel_response.canonical_wire(),
            ),
            Err(ManagedServingControllerError::ReferenceQueryResponseAuthenticationMismatch)
        ));

        let regressed_serving = ReferenceBootstrapServingIdentityV1::try_new(
            baseline.target(),
            baseline.runtime_store_instance_id(),
            baseline.snapshot_sequence() - 1,
            baseline.runtime_host_epoch(),
            baseline.clock_domain(),
            baseline.clock_generation(),
        )
        .expect("regressed serving");
        let regressed_response = query_response(
            prepared.request(),
            regressed_serving,
            ingress.channel(),
            carrier.runtime_response_key(),
            &runtime,
        );
        assert!(matches!(
            verifier.try_accept_reference_query_response(
                &ingress,
                action.carrier_request(),
                prepared,
                carrier.runtime_principal(),
                carrier.binding_digest(),
                regressed_response.canonical_wire(),
            ),
            Err(ManagedServingControllerError::ReferenceQueryResponseCorrelationMismatch)
        ));

        let forged_claim = ReferenceQueryResponseAuthClaimV1::try_new(
            ingress.channel(),
            carrier.runtime_response_key(),
            ApplyAuthAlgorithm::try_new(1).expect("forged PXQS algorithm"),
            1,
        )
        .expect("forged PXQS claim");
        let forged_signature = ReferenceQueryResponseDraftV1::try_new(
            prepared.request(),
            valid_response.facts(),
            ingress.channel(),
            forged_claim,
        )
        .expect("forged PXQS draft")
        .finalize(&[0x7f; 64])
        .expect("opaque forged PXQS signature");
        assert!(matches!(
            verifier.try_accept_reference_query_response(
                &ingress,
                action.carrier_request(),
                prepared,
                carrier.runtime_principal(),
                carrier.binding_digest(),
                forged_signature.canonical_wire(),
            ),
            Err(ManagedServingControllerError::ReferenceQueryResponseAuthenticationMismatch)
        ));
    }
}
