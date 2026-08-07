//! Durable Controller owner for the successor Runtime serving observation.
//!
//! PXFB is read-only at Runtime, but its Controller-side delivery state is not
//! ephemeral. The exact request is committed before transport, the attempt is
//! committed in-flight before a move-only send action exists, and a timeout or
//! EOF is durably closed without claiming any Runtime effect. A later explicit
//! invocation must provide a fresh request identity and nonce.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::managed_serving_bootstrap::{
    ManagedServingBootstrapError, ManagedServingBootstrapFactsV1,
    ManagedServingBootstrapRequestDraftV1, ManagedServingBootstrapRequestIdV1,
    ManagedServingBootstrapRequestV1, ManagedServingBootstrapResponseV1,
};
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthError, ApplyRequestAuthClaim};

use crate::managed_fabric_producer::{
    ManagedFabricProducerError, VerifiedManagedFabricProducerContextV1,
};

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

/// Exact PXFB/PXFR bytes retained inside the successor Controller snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedServingBootstrapStateV1 {
    phase: ManagedServingBootstrapPhaseV1,
    request: Option<ManagedServingBootstrapRequestV1>,
    response: Option<ManagedServingBootstrapResponseV1>,
}

impl ManagedServingBootstrapStateV1 {
    #[must_use]
    pub(crate) const fn initial() -> Self {
        Self {
            phase: ManagedServingBootstrapPhaseV1::ReadyForRequest,
            request: None,
            response: None,
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
    pub(crate) const fn request(&self) -> Option<&ManagedServingBootstrapRequestV1> {
        self.request.as_ref()
    }

    pub(crate) fn decode(
        phase: ManagedServingBootstrapPhaseV1,
        request_wire: &[u8],
        response_wire: &[u8],
        base: &VerifiedManagedFabricProducerContextV1,
    ) -> Result<Self, ManagedServingControllerError> {
        let state = match phase {
            ManagedServingBootstrapPhaseV1::ReadyForRequest => {
                if !request_wire.is_empty() || !response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                Self::initial()
            }
            ManagedServingBootstrapPhaseV1::RequestDurable
            | ManagedServingBootstrapPhaseV1::AttemptInFlight
            | ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse => {
                if request_wire.is_empty() || !response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                let request = ManagedServingBootstrapRequestV1::decode(request_wire)?;
                validate_request(base, &request)?;
                Self {
                    phase,
                    request: Some(request),
                    response: None,
                }
            }
            ManagedServingBootstrapPhaseV1::ResponseDurable => {
                if request_wire.is_empty() || response_wire.is_empty() {
                    return Err(ManagedServingControllerError::InvalidStateEncoding);
                }
                let request = ManagedServingBootstrapRequestV1::decode(request_wire)?;
                validate_request(base, &request)?;
                let response = ManagedServingBootstrapResponseV1::decode(response_wire)?;
                let _ = VerifiedManagedServingPinV1::try_new(base, &request, &response)?;
                Self {
                    phase,
                    request: Some(request),
                    response: Some(response),
                }
            }
        };
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
        ) {
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
            response: None,
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
                response: None,
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
            response: None,
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
                response: Some(response),
            },
            pin,
        ))
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

/// Fail-closed Controller errors for PXFB/PXFR durable ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServingControllerError {
    Contract(ManagedServingBootstrapError),
    Authentication(ApplyAuthError),
    Producer(ManagedFabricProducerError),
    InvalidFreshIdentity,
    FreshIdentityReused,
    ControllerKeyMismatch,
    RequestAuthenticationMismatch,
    ResponseAuthenticationMismatch,
    InvalidPhase,
    ServingPinRequired,
    InvalidStateEncoding,
}

impl From<ManagedServingBootstrapError> for ManagedServingControllerError {
    fn from(value: ManagedServingBootstrapError) -> Self {
        Self::Contract(value)
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

impl fmt::Display for ManagedServingControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed serving Controller failed: {self:?}")
    }
}

impl std::error::Error for ManagedServingControllerError {}
