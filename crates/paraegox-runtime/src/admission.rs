//! Concrete authentication, replay, and temporal admission for canonical apply envelopes.
//!
//! This B2 enabler has no RuntimeHost lifecycle or retention owner. Its ledgers
//! are monotonic and bounded: filling any configured capacity rejects new keys
//! fail-closed. Eviction, compaction, clock-generation rollover, and durable
//! recovery belong to a later owner and are deliberately absent here.

use core::{fmt, num::NonZeroUsize};
use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use paraegox_kernel::digest::{Digest32, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockReading, MonotonicDeadline, TimeError};
use paraegox_runtime_contracts::apply::{
    ApplyContractError, PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
    TenureProofError,
};
use paraegox_runtime_contracts::assignment::RuntimeApplyRequest;
use paraegox_runtime_contracts::execution::RuntimeApplyRequestV2;
use paraegox_runtime_contracts::process_execution::{
    RequestV4WireError, RuntimeApplyRequestV4, RuntimePlanSliceV4,
};
use paraegox_runtime_contracts::provenance::SourceScopeRef;
use paraegox_runtime_contracts::reference_control::{
    MAX_REFERENCE_LIFECYCLE_NANOS, REFERENCE_ADMISSION_REQUEST_NONCE_CAPACITY,
    REFERENCE_ADMISSION_TEMPORAL_LINEAGE_CAPACITY, REFERENCE_ADMISSION_TENURE_NONCE_CAPACITY,
    ReferenceAdmissionPolicyFingerprintV1, ReferenceAdmissionPolicyInputV1,
    ReferenceApplyIngressIdentitiesV1, ReferenceApplyRequestV1, ReferenceControlError,
    reference_admission_policy_fingerprint_v1, reference_apply_ingress_identities_v1,
};
use paraegox_runtime_contracts::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
use paraegox_runtime_contracts::thread_execution::RuntimeApplyRequestV3;
use paraegox_runtime_contracts::wire::{
    ApplyAuthAlgorithm, ApplyAuthKeyRef, EnvelopeContractError, RuntimeApplyEnvelope, WireError,
};

use crate::apply_state::{AdmittedApply, VerifiedWriterTenure};
use crate::request::{
    RuntimeExecutionRequestAdmissionTransition, RuntimeRequestAdmissionError,
    RuntimeRequestAdmissionTransition, RuntimeThreadExecutionRequestAdmissionTransition,
};

/// Registry value for pure Ed25519 request and tenure signatures.
pub const ED25519_ALGORITHM: u16 = 1;
/// Version of the Ed25519 acceptance profile used by this Runtime admission path.
pub const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TenureTrustSelector {
    source_scope: SourceScopeRef,
    authority: TenureAuthorityRef,
    key: TenureKeyRef,
    algorithm: TenureProofAlgorithm,
    algorithm_version: u16,
}

/// One exact authority key binding admitted for writer-tenure proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedTenureKey {
    selector: TenureTrustSelector,
    authority_principal: PrincipalRef,
    authority_uid: u32,
    authority_gid: u32,
    verifying_key: VerifyingKey,
}

/// Exact service identity allowed to issue tenure proofs for one source scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedTenureIdentity {
    source_scope: SourceScopeRef,
    authority_principal: PrincipalRef,
    authority_uid: u32,
    authority_gid: u32,
    authority: TenureAuthorityRef,
}

impl TrustedTenureIdentity {
    /// Groups the provisioned Authority principal, OS identity and protocol reference.
    #[must_use]
    pub const fn new(
        source_scope: SourceScopeRef,
        authority_principal: PrincipalRef,
        authority_uid: u32,
        authority_gid: u32,
        authority: TenureAuthorityRef,
    ) -> Self {
        Self {
            source_scope,
            authority_principal,
            authority_uid,
            authority_gid,
            authority,
        }
    }
}

impl TrustedTenureKey {
    /// Builds one exact scope/authority/key/algorithm binding.
    pub fn try_new(
        identity: TrustedTenureIdentity,
        key: TenureKeyRef,
        algorithm: TenureProofAlgorithm,
        algorithm_version: u16,
        verifying_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, AdmissionConfigurationError> {
        ensure_ed25519_profile(algorithm.value(), algorithm_version)?;
        Ok(Self {
            selector: TenureTrustSelector {
                source_scope: identity.source_scope,
                authority: identity.authority,
                key,
                algorithm,
                algorithm_version,
            },
            authority_principal: identity.authority_principal,
            authority_uid: identity.authority_uid,
            authority_gid: identity.authority_gid,
            verifying_key: parse_trusted_key(verifying_key)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ApplyTrustSelector {
    source_scope: SourceScopeRef,
    target: RuntimeHostId,
    principal: PrincipalRef,
    writer: PlanWriterRef,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

/// One exact principal-to-writer key binding admitted for apply requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedApplyKey {
    selector: ApplyTrustSelector,
    verifying_key: VerifyingKey,
}

/// Route and identity fields that one request-authentication key is allowed to assert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedApplyIdentity {
    source_scope: SourceScopeRef,
    target: RuntimeHostId,
    principal: PrincipalRef,
    writer: PlanWriterRef,
}

impl TrustedApplyIdentity {
    /// Groups the explicit principal-to-writer binding for one scope and target.
    #[must_use]
    pub const fn new(
        source_scope: SourceScopeRef,
        target: RuntimeHostId,
        principal: PrincipalRef,
        writer: PlanWriterRef,
    ) -> Self {
        Self {
            source_scope,
            target,
            principal,
            writer,
        }
    }
}

impl TrustedApplyKey {
    /// Builds one exact scope/target/principal/writer/key/algorithm binding.
    pub fn try_new(
        identity: TrustedApplyIdentity,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
        verifying_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, AdmissionConfigurationError> {
        ensure_ed25519_profile(algorithm.value(), algorithm_version)?;
        Ok(Self {
            selector: ApplyTrustSelector {
                source_scope: identity.source_scope,
                target: identity.target,
                principal: identity.principal,
                writer: identity.writer,
                key,
                algorithm,
                algorithm_version,
            },
            verifying_key: parse_trusted_key(verifying_key)?,
        })
    }
}

fn ensure_ed25519_profile(
    algorithm: u16,
    algorithm_version: u16,
) -> Result<(), AdmissionConfigurationError> {
    if algorithm != ED25519_ALGORITHM || algorithm_version != ED25519_ALGORITHM_VERSION {
        return Err(AdmissionConfigurationError::UnsupportedSignatureProfile);
    }
    Ok(())
}

fn parse_trusted_key(
    bytes: [u8; ED25519_PUBLIC_KEY_BYTES],
) -> Result<VerifyingKey, AdmissionConfigurationError> {
    let verifying_key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| AdmissionConfigurationError::InvalidVerifyingKey)?;
    if verifying_key.is_weak() {
        return Err(AdmissionConfigurationError::WeakVerifyingKey);
    }
    Ok(verifying_key)
}

/// Immutable cryptographic policy for canonical apply admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyAdmissionPolicy {
    maximum_budget: BoundedDuration,
    state_limits: AdmissionStateLimits,
    tenure_keys: BTreeMap<TenureTrustSelector, TrustedTenureBinding>,
    apply_keys: BTreeMap<ApplyTrustSelector, VerifyingKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrustedTenureBinding {
    authority_principal: PrincipalRef,
    authority_uid: u32,
    authority_gid: u32,
    verifying_key: VerifyingKey,
}

impl ApplyAdmissionPolicy {
    /// Builds a bounded, fail-closed policy with nonempty, duplicate-free trust sets.
    pub fn try_new(
        maximum_budget: BoundedDuration,
        state_limits: AdmissionStateLimits,
        tenure_keys: impl IntoIterator<Item = TrustedTenureKey>,
        apply_keys: impl IntoIterator<Item = TrustedApplyKey>,
    ) -> Result<Self, AdmissionConfigurationError> {
        if maximum_budget.value() == 0 {
            return Err(AdmissionConfigurationError::ZeroMaximumBudget);
        }

        let mut trusted_tenure = BTreeMap::new();
        for trusted in tenure_keys {
            if trusted_tenure
                .insert(
                    trusted.selector,
                    TrustedTenureBinding {
                        authority_principal: trusted.authority_principal,
                        authority_uid: trusted.authority_uid,
                        authority_gid: trusted.authority_gid,
                        verifying_key: trusted.verifying_key,
                    },
                )
                .is_some()
            {
                return Err(AdmissionConfigurationError::DuplicateTenureTrust);
            }
        }
        if trusted_tenure.is_empty() {
            return Err(AdmissionConfigurationError::EmptyTenureTrust);
        }

        let mut trusted_apply = BTreeMap::new();
        for trusted in apply_keys {
            if trusted_apply
                .insert(trusted.selector, trusted.verifying_key)
                .is_some()
            {
                return Err(AdmissionConfigurationError::DuplicateApplyTrust);
            }
        }
        if trusted_apply.is_empty() {
            return Err(AdmissionConfigurationError::EmptyApplyTrust);
        }

        Ok(Self {
            maximum_budget,
            state_limits,
            tenure_keys: trusted_tenure,
            apply_keys: trusted_apply,
        })
    }

    /// Returns the largest authenticated original budget this ingress accepts.
    #[must_use]
    pub const fn maximum_budget(&self) -> BoundedDuration {
        self.maximum_budget
    }

    /// Returns the fixed replay and temporal-ledger capacities.
    #[must_use]
    pub const fn state_limits(&self) -> AdmissionStateLimits {
        self.state_limits
    }

    /// Seals this policy only after the shared reference contract reproduces `expected`.
    pub fn verify_reference_fingerprint(
        &self,
        expected: ReferenceAdmissionPolicyFingerprintV1,
    ) -> Result<(), AdmissionConfigurationError> {
        if self.maximum_budget.value() != MAX_REFERENCE_LIFECYCLE_NANOS
            || self.state_limits.tenure_nonce_capacity()
                != REFERENCE_ADMISSION_TENURE_NONCE_CAPACITY
            || self.state_limits.request_nonce_capacity()
                != REFERENCE_ADMISSION_REQUEST_NONCE_CAPACITY
            || self.state_limits.temporal_lineage_capacity()
                != REFERENCE_ADMISSION_TEMPORAL_LINEAGE_CAPACITY
            || self.tenure_keys.len() != 1
            || self.apply_keys.len() != 1
        {
            return Err(AdmissionConfigurationError::NonReferencePolicyShape);
        }
        let (tenure_selector, tenure_binding) = self
            .tenure_keys
            .first_key_value()
            .ok_or(AdmissionConfigurationError::NonReferencePolicyShape)?;
        let (apply_selector, apply_key) = self
            .apply_keys
            .first_key_value()
            .ok_or(AdmissionConfigurationError::NonReferencePolicyShape)?;
        let derived = reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
            target: apply_selector.target,
            source_scope: apply_selector.source_scope,
            writer: apply_selector.writer,
            controller_principal: apply_selector.principal,
            controller_key_ref: apply_selector.key,
            controller_public_key: apply_key.as_bytes(),
            authority_principal: tenure_binding.authority_principal,
            authority_uid: tenure_binding.authority_uid,
            authority_gid: tenure_binding.authority_gid,
            tenure_authority_ref: tenure_selector.authority,
            tenure_key_ref: tenure_selector.key,
            tenure_public_key: tenure_binding.verifying_key.as_bytes(),
        })?;
        if tenure_selector.source_scope != apply_selector.source_scope || derived != expected {
            return Err(AdmissionConfigurationError::ReferencePolicyFingerprintMismatch);
        }
        Ok(())
    }

    /// Authenticates the trust selectors and both signatures of one strict PXAR v5.
    ///
    /// This auth-only seam exists for immutable terminal replay, which remains
    /// readable after the signed target clock generation becomes historical.
    /// It grants no authority to install a fresh temporal budget.
    pub(crate) fn authenticate_reference_apply_request(
        &self,
        request: &ReferenceApplyRequestV1,
    ) -> Result<AuthenticatedReferenceApplyV1, ReferenceApplyAdmissionError> {
        let provenance = request.provenance();
        let control = request.control_commitment().control();
        let writer_context = control.writer_context();
        let proof = writer_context.proof();
        let proof_authority = proof.authority();
        let proof_claim = proof.claim();
        let authentication = request.authentication();
        let auth_claim = authentication.claim();

        if proof_claim.source_scope() != provenance.source_scope()
            || proof_claim.writer() != writer_context.writer()
            || proof_claim.epoch() != writer_context.epoch()
        {
            return Err(ReferenceApplyAdmissionError::CanonicalCorrelation);
        }

        let tenure_selector = TenureTrustSelector {
            source_scope: provenance.source_scope(),
            authority: proof_authority.authority(),
            key: proof_authority.key(),
            algorithm: proof_authority.algorithm(),
            algorithm_version: proof_authority.algorithm_version(),
        };
        let Some(tenure_key) = self.tenure_keys.get(&tenure_selector) else {
            return Err(ReferenceApplyAdmissionError::UntrustedTenureKey);
        };
        let apply_selector = ApplyTrustSelector {
            source_scope: provenance.source_scope(),
            target: request.target(),
            principal: auth_claim.principal(),
            writer: writer_context.writer(),
            key: auth_claim.key(),
            algorithm: auth_claim.algorithm(),
            algorithm_version: auth_claim.algorithm_version(),
        };
        let Some(apply_key) = self.apply_keys.get(&apply_selector) else {
            return Err(ReferenceApplyAdmissionError::UntrustedApplyKey);
        };

        let tenure_signature = parse_reference_signature(proof.signature())
            .ok_or(ReferenceApplyAdmissionError::InvalidTenureSignature)?;
        let tenure_transcript = proof
            .signing_transcript()
            .map_err(|_| ReferenceApplyAdmissionError::InvalidTenureTranscript)?;
        tenure_key
            .verifying_key
            .verify_strict(tenure_transcript.as_bytes(), &tenure_signature)
            .map_err(|_| ReferenceApplyAdmissionError::InvalidTenureSignature)?;

        let request_signature = parse_reference_signature(authentication.signature())
            .ok_or(ReferenceApplyAdmissionError::InvalidRequestSignature)?;
        let request_transcript = request
            .signing_transcript()
            .map_err(|_| ReferenceApplyAdmissionError::InvalidRequestTranscript)?;
        apply_key
            .verify_strict(request_transcript.as_bytes(), &request_signature)
            .map_err(|_| ReferenceApplyAdmissionError::InvalidRequestSignature)?;

        let identities = reference_apply_ingress_identities_v1(request)
            .map_err(ReferenceApplyAdmissionError::Identity)?;
        Ok(AuthenticatedReferenceApplyV1 { identities })
    }

    /// Authenticates and temporally admits one fresh strict PXAR v5.
    ///
    /// This path is additive and deliberately does not decode or alias any of
    /// the legacy v1-v4 envelopes. The caller supplies a real owner-local
    /// observation from the signed target clock generation.
    pub(crate) fn verify_reference_apply_request(
        &self,
        request: &ReferenceApplyRequestV1,
        reading: ClockReading,
    ) -> Result<VerifiedReferenceApplyIngressV1, ReferenceApplyAdmissionError> {
        let authenticated = self.authenticate_reference_apply_request(request)?;

        let temporal = request.temporal();
        if temporal.target_clock_domain() != reading.domain() {
            return Err(ReferenceApplyAdmissionError::ClockDomainMismatch);
        }
        if temporal.target_clock_generation() != reading.generation() {
            return Err(ReferenceApplyAdmissionError::ClockGenerationMismatch);
        }
        if temporal.original_budget().value() > self.maximum_budget.value() {
            return Err(ReferenceApplyAdmissionError::BudgetExceedsPolicy);
        }
        if temporal.remaining_budget().value() == 0 {
            return Err(ReferenceApplyAdmissionError::BudgetExpired);
        }
        let admitted_at_nanos = reading.now().value();
        if admitted_at_nanos == 0
            || admitted_at_nanos
                .checked_add(temporal.remaining_budget().value())
                .is_none()
        {
            return Err(ReferenceApplyAdmissionError::DeadlineOverflow);
        }
        Ok(VerifiedReferenceApplyIngressV1 {
            identities: authenticated.identities(),
            admitted_at_nanos,
        })
    }
}

fn parse_reference_signature(signature: &[u8]) -> Option<Signature> {
    let bytes = <&[u8; ED25519_SIGNATURE_BYTES]>::try_from(signature).ok()?;
    Some(Signature::from_bytes(bytes))
}

/// Trust- and signature-verified PXAR v5 facts safe for read-only replay lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedReferenceApplyV1 {
    identities: ReferenceApplyIngressIdentitiesV1,
}

impl AuthenticatedReferenceApplyV1 {
    #[must_use]
    pub(crate) const fn identities(self) -> ReferenceApplyIngressIdentitiesV1 {
        self.identities
    }
}

/// Cryptographically and temporally verified fresh PXAR v5 ingress evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedReferenceApplyIngressV1 {
    identities: ReferenceApplyIngressIdentitiesV1,
    admitted_at_nanos: u64,
}

impl VerifiedReferenceApplyIngressV1 {
    #[must_use]
    pub(crate) const fn identities(self) -> ReferenceApplyIngressIdentitiesV1 {
        self.identities
    }

    #[must_use]
    pub(crate) const fn admitted_at_nanos(self) -> u64 {
        self.admitted_at_nanos
    }
}

/// Fail-closed PXAR v5 authentication and target-clock admission failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReferenceApplyAdmissionError {
    CanonicalCorrelation,
    UntrustedTenureKey,
    UntrustedApplyKey,
    InvalidTenureTranscript,
    InvalidRequestTranscript,
    InvalidTenureSignature,
    InvalidRequestSignature,
    ClockDomainMismatch,
    ClockGenerationMismatch,
    BudgetExceedsPolicy,
    BudgetExpired,
    DeadlineOverflow,
    Identity(ReferenceControlError),
}

/// Explicit nonzero capacities for caller-persisted admission state.
///
/// These values are hard ceilings, not cache sizes. B2 never evicts an admitted
/// replay identity, so a filled ledger continues to reject new identities until
/// a future lifecycle owner performs an independently authorized boundary change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionStateLimits {
    tenure_nonce_capacity: NonZeroUsize,
    request_nonce_capacity: NonZeroUsize,
    temporal_lineage_capacity: NonZeroUsize,
}

impl AdmissionStateLimits {
    /// Creates independent, nonzero bounds for every retained admission ledger.
    pub const fn try_new(
        tenure_nonce_capacity: usize,
        request_nonce_capacity: usize,
        temporal_lineage_capacity: usize,
    ) -> Result<Self, AdmissionConfigurationError> {
        let Some(tenure_nonce_capacity) = NonZeroUsize::new(tenure_nonce_capacity) else {
            return Err(AdmissionConfigurationError::ZeroTenureNonceCapacity);
        };
        let Some(request_nonce_capacity) = NonZeroUsize::new(request_nonce_capacity) else {
            return Err(AdmissionConfigurationError::ZeroRequestNonceCapacity);
        };
        let Some(temporal_lineage_capacity) = NonZeroUsize::new(temporal_lineage_capacity) else {
            return Err(AdmissionConfigurationError::ZeroTemporalLineageCapacity);
        };
        Ok(Self {
            tenure_nonce_capacity,
            request_nonce_capacity,
            temporal_lineage_capacity,
        })
    }

    /// Returns the maximum retained authority-proof nonce identities.
    #[must_use]
    pub const fn tenure_nonce_capacity(self) -> usize {
        self.tenure_nonce_capacity.get()
    }

    /// Returns the maximum retained request nonce identities.
    #[must_use]
    pub const fn request_nonce_capacity(self) -> usize {
        self.request_nonce_capacity.get()
    }

    /// Returns the maximum retained temporal lineages.
    #[must_use]
    pub const fn temporal_lineage_capacity(self) -> usize {
        self.temporal_lineage_capacity.get()
    }
}

/// Stable policy-construction failures. No verifier can be supplied by a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionConfigurationError {
    /// Shared reference-contract fingerprint construction failed.
    ReferenceControl(ReferenceControlError),
    /// Policy limits or trust cardinality do not match the fixed reference profile.
    NonReferencePolicyShape,
    /// The supplied sealed token did not equal the policy's independently derived token.
    ReferencePolicyFingerprintMismatch,
    /// This implementation admits only Ed25519 algorithm 1/version 1.
    UnsupportedSignatureProfile,
    /// The 32-byte value did not decode as an Ed25519 verification key.
    InvalidVerifyingKey,
    /// Low-order public keys are forbidden by the Runtime acceptance profile.
    WeakVerifyingKey,
    /// At least one tenure authority key is required.
    EmptyTenureTrust,
    /// At least one request-authentication key is required.
    EmptyApplyTrust,
    /// Two tenure trust records had the same exact selector.
    DuplicateTenureTrust,
    /// Two request trust records had the same exact selector.
    DuplicateApplyTrust,
    /// A zero policy limit would admit no live temporal constraint.
    ZeroMaximumBudget,
    /// The authority-proof nonce ledger must retain at least one identity.
    ZeroTenureNonceCapacity,
    /// The request nonce ledger must retain at least one identity.
    ZeroRequestNonceCapacity,
    /// The temporal ledger must retain at least one lineage.
    ZeroTemporalLineageCapacity,
}

impl fmt::Display for AdmissionConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceControl(error) => write!(formatter, "policy fingerprint: {error}"),
            Self::NonReferencePolicyShape => formatter.write_str("non-reference policy shape"),
            Self::ReferencePolicyFingerprintMismatch => {
                formatter.write_str("reference policy fingerprint mismatch")
            }
            Self::UnsupportedSignatureProfile => {
                formatter.write_str("unsupported signature profile")
            }
            Self::InvalidVerifyingKey => formatter.write_str("invalid Ed25519 verifying key"),
            Self::WeakVerifyingKey => formatter.write_str("weak Ed25519 verifying key"),
            Self::EmptyTenureTrust => formatter.write_str("tenure trust must not be empty"),
            Self::EmptyApplyTrust => formatter.write_str("apply trust must not be empty"),
            Self::DuplicateTenureTrust => formatter.write_str("duplicate tenure trust selector"),
            Self::DuplicateApplyTrust => formatter.write_str("duplicate apply trust selector"),
            Self::ZeroMaximumBudget => formatter.write_str("maximum budget must be positive"),
            Self::ZeroTenureNonceCapacity => {
                formatter.write_str("tenure nonce capacity must be positive")
            }
            Self::ZeroRequestNonceCapacity => {
                formatter.write_str("request nonce capacity must be positive")
            }
            Self::ZeroTemporalLineageCapacity => {
                formatter.write_str("temporal lineage capacity must be positive")
            }
        }
    }
}

impl From<ReferenceControlError> for AdmissionConfigurationError {
    fn from(error: ReferenceControlError) -> Self {
        Self::ReferenceControl(error)
    }
}

impl std::error::Error for AdmissionConfigurationError {}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TenureNonceKey {
    source_scope: SourceScopeRef,
    authority: TenureAuthorityRef,
    key: TenureKeyRef,
    algorithm: TenureProofAlgorithm,
    algorithm_version: u16,
    nonce: Box<[u8]>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RequestNonceKey {
    source_scope: SourceScopeRef,
    target: RuntimeHostId,
    principal: PrincipalRef,
    writer: PlanWriterRef,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
    nonce: Box<[u8]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TemporalLedgerEntry {
    source_scope: SourceScopeRef,
    target: RuntimeHostId,
    original_budget: BoundedDuration,
    remaining_budget: BoundedDuration,
    deadline: MonotonicDeadline,
}

/// Replay and temporal snapshot that a future Runtime owner must retain durably.
///
/// This snapshot is not bootstrap authority and does not replace the durable writer
/// fence. Losing either durable value is a recovery failure; callers must never
/// substitute a new empty state for missing or corrupt recovered state. The maps
/// only grow in B2, have no safe eviction or generation-rollover mechanism, and
/// therefore do not claim long-running RuntimeHost liveness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionState {
    tenure_nonces: BTreeMap<TenureNonceKey, Digest32>,
    request_nonces: BTreeMap<RequestNonceKey, Digest32>,
    temporal: BTreeMap<TemporalConstraintId, TemporalLedgerEntry>,
}

impl AdmissionState {
    /// Creates state only for an independently authorized, genuinely new boundary.
    ///
    /// This constructor is not a journal-recovery fallback. A restart must recover
    /// the admission snapshot and writer fence together and use a new clock generation.
    #[must_use]
    pub fn for_new_boundary() -> Self {
        Self {
            tenure_nonces: BTreeMap::new(),
            request_nonces: BTreeMap::new(),
            temporal: BTreeMap::new(),
        }
    }

    /// Returns the number of authority-proof nonce identities retained.
    #[must_use]
    pub fn tenure_nonce_count(&self) -> usize {
        self.tenure_nonces.len()
    }

    /// Returns the number of request nonce identities retained.
    #[must_use]
    pub fn request_nonce_count(&self) -> usize {
        self.request_nonces.len()
    }

    /// Returns the number of temporal lineages retained.
    #[must_use]
    pub fn temporal_lineage_count(&self) -> usize {
        self.temporal.len()
    }
}

/// Whether a request nonce was first seen or was an exact authenticated replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDisposition {
    /// This request nonce was first admitted.
    Fresh,
    /// The same nonce and complete signed request digest were already admitted.
    Replayed,
}

/// Pure admission candidate awaiting writer-fence reduction.
///
/// Admission authenticates and bounds a request but does not establish bootstrap
/// authority or journal durability. Only after the writer-fence reducer accepts
/// `admitted` may the caller atomically persist `next_state` with the accepted
/// writer-fence transition. A fresh request is deadline-checked again by that
/// reducer at the commit reading; only an exact replay whose `next_state` equals
/// the current snapshot may remain queryable after expiry. `next_state` is one
/// opaque snapshot and must never be persisted as independent per-map updates.
/// Dropped or corrupt durable fence or admission state must fail recovery rather
/// than be reconstructed or partially merged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionTransition {
    next_state: AdmissionState,
    admitted: AdmittedApply,
    disposition: AdmissionDisposition,
}

impl AdmissionTransition {
    /// Returns the candidate snapshot to persist atomically with an accepted fence.
    #[must_use]
    pub const fn next_state(&self) -> &AdmissionState {
        &self.next_state
    }

    /// Returns the only apply value accepted by the reducer boundary.
    #[must_use]
    pub const fn admitted(&self) -> &AdmittedApply {
        &self.admitted
    }

    /// Returns whether request replay state was newly created.
    #[must_use]
    pub const fn disposition(&self) -> AdmissionDisposition {
        self.disposition
    }

    /// Consumes the candidate snapshot and value supplied to writer-fence reduction.
    #[must_use]
    pub fn into_parts(self) -> (AdmissionState, AdmittedApply) {
        (self.next_state, self.admitted)
    }
}

/// Pure v4 admission result retaining the exact signed Process execution Slice.
///
/// This boundary proves canonical bytes, trust, signatures, replay, and target
/// ingress time. It deliberately does not construct a ProcessDomain, launch a
/// worker, accept Ready, or assemble P2e runtime state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeProcessExecutionRequestAdmissionTransition {
    admission: AdmissionTransition,
    slice: RuntimePlanSliceV4,
}

impl RuntimeProcessExecutionRequestAdmissionTransition {
    const fn new(admission: AdmissionTransition, slice: RuntimePlanSliceV4) -> Self {
        Self { admission, slice }
    }

    /// Returns the candidate replay/temporal snapshot.
    #[must_use]
    pub(crate) const fn next_state(&self) -> &AdmissionState {
        self.admission.next_state()
    }

    /// Returns the apply-control value admitted by the concrete verifier.
    #[must_use]
    pub(crate) const fn admitted(&self) -> &AdmittedApply {
        self.admission.admitted()
    }

    /// Returns the exact signed v4 Slice; no live process exists at this point.
    #[must_use]
    pub(crate) const fn slice(&self) -> &RuntimePlanSliceV4 {
        &self.slice
    }

    /// Reports whether the signed envelope was fresh or an exact replay.
    #[must_use]
    pub(crate) const fn disposition(&self) -> AdmissionDisposition {
        self.admission.disposition()
    }

    /// Consumes every value a future journal/assembly owner must keep together.
    #[must_use]
    pub(crate) fn into_parts(self) -> (AdmissionState, AdmittedApply, RuntimePlanSliceV4) {
        let (state, admitted) = self.admission.into_parts();
        (state, admitted, self.slice)
    }
}

/// Fail-closed PXAR v4 decoding or authenticated admission error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeProcessExecutionRequestAdmissionError {
    /// Strict PXAR v4/PXTE v3 decoding or cross-body validation failed.
    RequestWire(RequestV4WireError),
    /// Existing exact trust, signature, replay, or temporal admission failed.
    Admission(AdmissionError),
}

impl From<RequestV4WireError> for RuntimeProcessExecutionRequestAdmissionError {
    fn from(value: RequestV4WireError) -> Self {
        Self::RequestWire(value)
    }
}

impl From<AdmissionError> for RuntimeProcessExecutionRequestAdmissionError {
    fn from(value: AdmissionError) -> Self {
        Self::Admission(value)
    }
}

impl fmt::Display for RuntimeProcessExecutionRequestAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestWire(error) => {
                write!(
                    formatter,
                    "process execution apply request rejected: {error}"
                )
            }
            Self::Admission(error) => write!(formatter, "signed apply admission rejected: {error}"),
        }
    }
}

impl std::error::Error for RuntimeProcessExecutionRequestAdmissionError {}

/// Concrete cryptographic admission mechanism for canonical apply envelopes.
///
/// This pure enabler owns policy evaluation, not a RuntimeHost, journal,
/// bootstrap authority, clock source, or persistence mechanism.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyAdmission {
    policy: ApplyAdmissionPolicy,
}

impl ApplyAdmission {
    /// Creates an admission path from an already validated concrete policy.
    #[must_use]
    pub const fn new(policy: ApplyAdmissionPolicy) -> Self {
        Self { policy }
    }

    /// Decodes one historical S2-only test frame without side effects.
    #[cfg(test)]
    fn admit(
        &self,
        frame: &[u8],
        state: &AdmissionState,
        reading: ClockReading,
    ) -> Result<AdmissionTransition, AdmissionError> {
        let envelope = RuntimeApplyEnvelope::decode(frame)?;
        self.admit_envelope(envelope, state, reading)
    }

    /// Decodes and admits one complete request before any assignment is installed.
    pub(crate) fn admit_request(
        &self,
        frame: &[u8],
        state: &AdmissionState,
        reading: ClockReading,
    ) -> Result<RuntimeRequestAdmissionTransition, RuntimeRequestAdmissionError> {
        let request = RuntimeApplyRequest::decode(frame)?;
        let slice = request.slice().clone();
        let admission = self.admit_envelope(request.envelope().clone(), state, reading)?;
        Ok(RuntimeRequestAdmissionTransition::new(admission, slice))
    }

    /// Decodes and admits one v2 request whose signed Slice commits both
    /// binding and execution bodies. There is no v1 fallback on this path.
    pub(crate) fn admit_execution_request(
        &self,
        frame: &[u8],
        state: &AdmissionState,
        reading: ClockReading,
    ) -> Result<RuntimeExecutionRequestAdmissionTransition, RuntimeRequestAdmissionError> {
        let request = RuntimeApplyRequestV2::decode(frame)?;
        let slice = request.slice().clone();
        let admission = self.admit_envelope(request.envelope().clone(), state, reading)?;
        Ok(RuntimeExecutionRequestAdmissionTransition::new(
            admission, slice,
        ))
    }

    /// Decodes and admits one v3 request whose signed Slice commits the exact
    /// Loop and Thread execution plan. There is no older-version fallback.
    pub(crate) fn admit_thread_execution_request(
        &self,
        frame: &[u8],
        state: &AdmissionState,
        reading: ClockReading,
    ) -> Result<RuntimeThreadExecutionRequestAdmissionTransition, RuntimeRequestAdmissionError>
    {
        let request = RuntimeApplyRequestV3::decode(frame)?;
        let slice = request.slice().clone();
        let admission = self.admit_envelope(request.envelope().clone(), state, reading)?;
        Ok(RuntimeThreadExecutionRequestAdmissionTransition::new(
            admission, slice,
        ))
    }

    /// Strictly decodes and admits one PXAR v4 request whose signed Slice
    /// commits the complete Loop, Thread, and Process execution plan.
    ///
    /// No v1-v3 fallback exists. Success retains desired state for the later
    /// fence/prepare/assembly boundary but grants no launch or Ready authority.
    pub(crate) fn admit_process_execution_request(
        &self,
        frame: &[u8],
        state: &AdmissionState,
        reading: ClockReading,
    ) -> Result<
        RuntimeProcessExecutionRequestAdmissionTransition,
        RuntimeProcessExecutionRequestAdmissionError,
    > {
        let request = RuntimeApplyRequestV4::decode(frame)?;
        let slice = request.slice().clone();
        let admission = self.admit_envelope(request.envelope().clone(), state, reading)?;
        Ok(RuntimeProcessExecutionRequestAdmissionTransition::new(
            admission, slice,
        ))
    }

    fn admit_envelope(
        &self,
        envelope: RuntimeApplyEnvelope,
        state: &AdmissionState,
        reading: ClockReading,
    ) -> Result<AdmissionTransition, AdmissionError> {
        let payload = envelope.control_commitment();
        payload.validate()?;
        let slice = payload.slice();
        let source_scope = slice.header().provenance().source_scope();
        let target = slice.header().target();
        let writer_context = payload.control().writer_context();
        let writer = writer_context.writer();
        let proof = writer_context.proof();
        let proof_authority = proof.authority();
        let proof_claim = proof.claim();
        let authentication = envelope.authentication();
        let auth_claim = authentication.claim();

        let tenure_selector = TenureTrustSelector {
            source_scope,
            authority: proof_authority.authority(),
            key: proof_authority.key(),
            algorithm: proof_authority.algorithm(),
            algorithm_version: proof_authority.algorithm_version(),
        };
        let Some(tenure_key) = self.policy.tenure_keys.get(&tenure_selector) else {
            return Err(AdmissionError::UntrustedTenureKey);
        };

        let apply_selector = ApplyTrustSelector {
            source_scope,
            target,
            principal: auth_claim.principal(),
            writer,
            key: auth_claim.key(),
            algorithm: auth_claim.algorithm(),
            algorithm_version: auth_claim.algorithm_version(),
        };
        let Some(apply_key) = self.policy.apply_keys.get(&apply_selector) else {
            return Err(AdmissionError::UntrustedApplyKey);
        };

        let tenure_signature = parse_signature(
            proof.signature(),
            AdmissionError::InvalidTenureSignatureLength,
        )?;
        let tenure_transcript = proof.signing_transcript()?;
        tenure_key
            .verifying_key
            .verify_strict(tenure_transcript.as_bytes(), &tenure_signature)
            .map_err(|_| AdmissionError::InvalidTenureSignature)?;

        let request_signature = parse_signature(
            authentication.signature(),
            AdmissionError::InvalidRequestSignatureLength,
        )?;
        let request_transcript = envelope.signing_transcript()?;
        apply_key
            .verify_strict(request_transcript.as_bytes(), &request_signature)
            .map_err(|_| AdmissionError::InvalidRequestSignature)?;

        let proof_envelope_digest = proof.envelope_digest()?;
        let request_digest = *envelope.request_digest();
        let tenure_nonce_key = TenureNonceKey {
            source_scope,
            authority: proof_authority.authority(),
            key: proof_authority.key(),
            algorithm: proof_authority.algorithm(),
            algorithm_version: proof_authority.algorithm_version(),
            nonce: proof.nonce().into(),
        };
        let request_nonce_key = RequestNonceKey {
            source_scope,
            target,
            principal: auth_claim.principal(),
            writer,
            key: auth_claim.key(),
            algorithm: auth_claim.algorithm(),
            algorithm_version: auth_claim.algorithm_version(),
            nonce: auth_claim.nonce().into(),
        };

        ensure_nonce_consistent(
            &state.tenure_nonces,
            &tenure_nonce_key,
            proof_envelope_digest,
            AdmissionError::TenureNonceConflict,
        )?;
        let disposition = match state.request_nonces.get(&request_nonce_key) {
            None => AdmissionDisposition::Fresh,
            Some(existing) if *existing == request_digest => AdmissionDisposition::Replayed,
            Some(_) => return Err(AdmissionError::RequestNonceConflict),
        };
        let temporal_id = envelope.temporal().constraint_id();
        if disposition == AdmissionDisposition::Replayed
            && (!state.tenure_nonces.contains_key(&tenure_nonce_key)
                || !state.temporal.contains_key(&temporal_id))
        {
            return Err(AdmissionError::AdmissionStateInconsistent);
        }

        let temporal_entry = install_temporal(
            envelope.temporal(),
            source_scope,
            target,
            state.temporal.get(&temporal_id),
            reading,
            self.policy.maximum_budget,
            disposition == AdmissionDisposition::Replayed,
        )?;
        ensure_ledger_capacity(
            &state.tenure_nonces,
            &tenure_nonce_key,
            self.policy.state_limits.tenure_nonce_capacity(),
            AdmissionError::TenureNonceCapacityExceeded,
        )?;
        ensure_ledger_capacity(
            &state.request_nonces,
            &request_nonce_key,
            self.policy.state_limits.request_nonce_capacity(),
            AdmissionError::RequestNonceCapacityExceeded,
        )?;
        ensure_ledger_capacity(
            &state.temporal,
            &temporal_id,
            self.policy.state_limits.temporal_lineage_capacity(),
            AdmissionError::TemporalLineageCapacityExceeded,
        )?;

        let verified_tenure = VerifiedWriterTenure::new(
            proof_claim.source_scope(),
            writer,
            writer_context.epoch(),
            proof_claim.supersedes_through_epoch(),
            proof_envelope_digest,
            auth_claim.principal(),
        );
        let admitted = AdmittedApply::new(
            payload.clone(),
            verified_tenure,
            request_digest,
            temporal_entry.deadline,
            disposition == AdmissionDisposition::Replayed,
        );

        let mut next_state = state.clone();
        next_state
            .tenure_nonces
            .insert(tenure_nonce_key, proof_envelope_digest);
        next_state
            .request_nonces
            .insert(request_nonce_key, request_digest);
        next_state.temporal.insert(temporal_id, temporal_entry);

        Ok(AdmissionTransition {
            next_state,
            admitted,
            disposition,
        })
    }
}

fn parse_signature(
    signature: &[u8],
    invalid_length: AdmissionError,
) -> Result<Signature, AdmissionError> {
    let Ok(bytes) = <&[u8; ED25519_SIGNATURE_BYTES]>::try_from(signature) else {
        return Err(invalid_length);
    };
    Ok(Signature::from_bytes(bytes))
}

fn ensure_nonce_consistent<Key: Ord>(
    ledger: &BTreeMap<Key, Digest32>,
    key: &Key,
    digest: Digest32,
    conflict: AdmissionError,
) -> Result<(), AdmissionError> {
    if ledger.get(key).is_some_and(|existing| *existing != digest) {
        return Err(conflict);
    }
    Ok(())
}

fn ensure_ledger_capacity<Key: Ord, Value>(
    ledger: &BTreeMap<Key, Value>,
    key: &Key,
    capacity: usize,
    capacity_exceeded: AdmissionError,
) -> Result<(), AdmissionError> {
    if !ledger.contains_key(key) && ledger.len() >= capacity {
        return Err(capacity_exceeded);
    }
    Ok(())
}

fn install_temporal(
    temporal: ApplyTemporalConstraint,
    source_scope: SourceScopeRef,
    target: RuntimeHostId,
    existing: Option<&TemporalLedgerEntry>,
    reading: ClockReading,
    maximum_budget: BoundedDuration,
    exact_replay: bool,
) -> Result<TemporalLedgerEntry, AdmissionError> {
    if temporal.target_clock_domain() != reading.domain() {
        return Err(AdmissionError::ClockDomainMismatch);
    }
    if temporal.target_clock_generation() != reading.generation() {
        return Err(AdmissionError::ClockGenerationMismatch);
    }
    if temporal.original_budget().value() > maximum_budget.value() {
        return Err(AdmissionError::BudgetExceedsPolicy);
    }
    if temporal.remaining_budget().value() == 0 {
        return Err(AdmissionError::BudgetExpired);
    }

    let previous_deadline = if let Some(previous) = existing {
        if previous.source_scope != source_scope
            || previous.target != target
            || previous.original_budget != temporal.original_budget()
            || previous.deadline.domain() != temporal.target_clock_domain()
            || previous.deadline.generation() != temporal.target_clock_generation()
        {
            return Err(AdmissionError::TemporalLineageConflict);
        }
        if exact_replay && previous.remaining_budget > temporal.remaining_budget() {
            return Err(AdmissionError::AdmissionStateInconsistent);
        }
        if exact_replay {
            return Ok(*previous);
        }
        if temporal.remaining_budget() > previous.remaining_budget {
            return Err(AdmissionError::BudgetExtended);
        }
        if previous
            .deadline
            .is_expired_at(reading)
            .map_err(map_deadline_error)?
        {
            return Err(AdmissionError::BudgetExpired);
        }
        Some(previous.deadline)
    } else {
        if exact_replay {
            return Err(AdmissionError::AdmissionStateInconsistent);
        }
        None
    };
    let candidate_deadline = reading
        .try_deadline_after(temporal.remaining_budget())
        .map_err(map_deadline_error)?;
    let deadline = if let Some(previous) = previous_deadline {
        earlier_deadline(previous, candidate_deadline)
    } else {
        candidate_deadline
    };

    Ok(TemporalLedgerEntry {
        source_scope,
        target,
        original_budget: temporal.original_budget(),
        remaining_budget: temporal.remaining_budget(),
        deadline,
    })
}

fn earlier_deadline(first: MonotonicDeadline, second: MonotonicDeadline) -> MonotonicDeadline {
    if first.deadline().value() <= second.deadline().value() {
        first
    } else {
        second
    }
}

fn map_deadline_error(error: TimeError) -> AdmissionError {
    match error {
        TimeError::ClockDomainMismatch => AdmissionError::ClockDomainMismatch,
        TimeError::ClockGenerationMismatch => AdmissionError::ClockGenerationMismatch,
        TimeError::DeadlineOverflow => AdmissionError::DeadlineOverflow,
        TimeError::InvalidClockGeneration => AdmissionError::ClockGenerationMismatch,
    }
}

/// Stable fail-closed request-admission reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// Pre-crypto canonical wire decoding failed.
    Wire(WireError),
    /// A decoded B1 commitment failed independent validation.
    Contract(ApplyContractError),
    /// A canonical signature transcript or envelope could not be rebuilt.
    Envelope(EnvelopeContractError),
    /// A proof-envelope fingerprint could not be rebuilt.
    Digest(DigestBuildError),
    /// A decoded tenure proof could not rebuild its bounded signing transcript.
    TenureProof(TenureProofError),
    /// No exact scope/authority/key/algorithm trust record exists.
    UntrustedTenureKey,
    /// No exact scope/target/principal/writer/key/algorithm trust record exists.
    UntrustedApplyKey,
    /// Ed25519 tenure signatures are exactly 64 bytes.
    InvalidTenureSignatureLength,
    /// Ed25519 request signatures are exactly 64 bytes.
    InvalidRequestSignatureLength,
    /// Strict authority signature verification failed.
    InvalidTenureSignature,
    /// Strict request signature verification failed.
    InvalidRequestSignature,
    /// One authority nonce identified two different complete proofs.
    TenureNonceConflict,
    /// One request nonce identified two different complete requests.
    RequestNonceConflict,
    /// Retained replay indexes were missing records required by an exact replay.
    AdmissionStateInconsistent,
    /// A new authority-proof nonce would exceed the configured retained bound.
    TenureNonceCapacityExceeded,
    /// A new request nonce would exceed the configured retained bound.
    RequestNonceCapacityExceeded,
    /// A new temporal lineage would exceed the configured retained bound.
    TemporalLineageCapacityExceeded,
    /// The authenticated temporal ID was reused for another route or origin budget.
    TemporalLineageConflict,
    /// The authenticated target clock domain is not local.
    ClockDomainMismatch,
    /// The authenticated target clock generation is not current.
    ClockGenerationMismatch,
    /// The authenticated original budget exceeds local policy.
    BudgetExceedsPolicy,
    /// The constraint has no remaining local time or its installed deadline elapsed.
    BudgetExpired,
    /// A repeated temporal lineage increased its prior remaining budget.
    BudgetExtended,
    /// Installing the remaining duration overflowed the local clock representation.
    DeadlineOverflow,
}

impl From<WireError> for AdmissionError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<ApplyContractError> for AdmissionError {
    fn from(value: ApplyContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<EnvelopeContractError> for AdmissionError {
    fn from(value: EnvelopeContractError) -> Self {
        Self::Envelope(value)
    }
}

impl From<DigestBuildError> for AdmissionError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<TenureProofError> for AdmissionError {
    fn from(value: TenureProofError) -> Self {
        Self::TenureProof(value)
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "canonical apply wire rejected: {error}"),
            Self::Contract(error) => write!(formatter, "apply contract rejected: {error}"),
            Self::Envelope(error) => write!(formatter, "apply envelope rejected: {error}"),
            Self::Digest(error) => write!(formatter, "apply digest rejected: {error}"),
            Self::TenureProof(error) => write!(formatter, "tenure proof rejected: {error}"),
            Self::UntrustedTenureKey => formatter.write_str("untrusted tenure key binding"),
            Self::UntrustedApplyKey => formatter.write_str("untrusted apply key binding"),
            Self::InvalidTenureSignatureLength => {
                formatter.write_str("invalid tenure signature length")
            }
            Self::InvalidRequestSignatureLength => {
                formatter.write_str("invalid request signature length")
            }
            Self::InvalidTenureSignature => formatter.write_str("invalid tenure signature"),
            Self::InvalidRequestSignature => formatter.write_str("invalid request signature"),
            Self::TenureNonceConflict => formatter.write_str("tenure nonce conflict"),
            Self::RequestNonceConflict => formatter.write_str("request nonce conflict"),
            Self::AdmissionStateInconsistent => {
                formatter.write_str("admission replay state is inconsistent")
            }
            Self::TenureNonceCapacityExceeded => {
                formatter.write_str("tenure nonce capacity exceeded")
            }
            Self::RequestNonceCapacityExceeded => {
                formatter.write_str("request nonce capacity exceeded")
            }
            Self::TemporalLineageCapacityExceeded => {
                formatter.write_str("temporal lineage capacity exceeded")
            }
            Self::TemporalLineageConflict => formatter.write_str("temporal lineage conflict"),
            Self::ClockDomainMismatch => formatter.write_str("target clock domain mismatch"),
            Self::ClockGenerationMismatch => {
                formatter.write_str("target clock generation mismatch")
            }
            Self::BudgetExceedsPolicy => formatter.write_str("temporal budget exceeds policy"),
            Self::BudgetExpired => formatter.write_str("temporal budget expired"),
            Self::BudgetExtended => formatter.write_str("temporal budget was extended"),
            Self::DeadlineOverflow => formatter.write_str("local deadline overflow"),
        }
    }
}

impl std::error::Error for AdmissionError {}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::time::Duration;
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
        RuntimeApplyControl, RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef,
        TenureProofAlgorithm, TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
        WriterTenureSigningTranscript,
    };
    use paraegox_runtime_contracts::assignment::{
        BindingAssignment, BindingId, DeliveryProfile, InstanceRef, InteractionKind, MailboxRef,
        MailboxSpec, OverflowPolicy, PortCardinality, PortDirection, PortEndpoint, PortRef,
        PortSpec, RuntimeApplyRequest, RuntimePlanSlice, SchemaRef, TargetAssignments,
    };
    use paraegox_runtime_contracts::execution::{
        CardDefinitionRef, CardImplementationRef, RuntimeApplyRequestV2,
    };
    use paraegox_runtime_contracts::process_execution::{
        RequestV4WireErrorCode, RuntimeApplyRequestV4,
    };
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
    };
    use paraegox_runtime_contracts::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use paraegox_runtime_contracts::thread_execution::RuntimeApplyRequestV3;
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
        MAX_RUNTIME_APPLY_ENVELOPE_BYTES, RuntimeApplyEnvelope, RuntimeApplyEnvelopeDraft,
        WireErrorCode,
    };

    use crate::apply_state::{
        ApplyControlState, ApplyRejection, FenceDisposition, OperationPhase, PrepareDisposition,
        evaluate_prepare, evaluate_writer_fence,
    };
    use crate::card_executor::{
        CardStartOutcome, CardStopOutcome, CooperativeLoopImplementation, TrustedCardImplementation,
    };
    use crate::card_instance::{
        CallbackFailure, CardContext, CardFuture, CardImplementation, DomainEpoch, InputView,
        InstanceGeneration, OutputProposal, RuntimeHostEpoch,
    };
    use crate::component_runtime::{
        ComponentCallbackOutcome, ComponentDispatchOutcome, ComponentRuntimeEpochs,
        SingleSubjectComponentRuntime,
    };
    use crate::mailbox::{
        EnqueueOutcome, Mailbox, MessageId, PayloadHandle, TerminalReason, ValidatedMessage,
    };
    use crate::port_binding::PortBinding;
    use crate::runtime_clock::RuntimeClock;
    use crate::task_registry::CancellationSource;
    use crate::thread_component_runtime::{
        PreparedThreadComponentRuntime, SynchronousThreadCard, ThreadCardFailure,
        ThreadCardInputView, ThreadComponentDispatchOutcome, ThreadComponentPollOutcome,
        TrustedSynchronousThreadCard, TrustedThreadCardImplementation,
    };
    use crate::thread_registry::RuntimeThreadRegistry;

    use super::{
        AdmissionConfigurationError, AdmissionDisposition, AdmissionError, AdmissionState,
        AdmissionStateLimits, ApplyAdmission, ApplyAdmissionPolicy, ED25519_ALGORITHM,
        ED25519_ALGORITHM_VERSION, RuntimeProcessExecutionRequestAdmissionError,
        TrustedApplyIdentity, TrustedApplyKey, TrustedTenureIdentity, TrustedTenureKey,
    };

    const SCOPE: u8 = 1;
    const TARGET: u8 = 2;
    const WRITER: u8 = 3;
    const PRINCIPAL: u8 = 4;
    const AUTHORITY: u8 = 5;
    const TENURE_KEY: u8 = 6;
    const APPLY_KEY: u8 = 7;
    const CLOCK_DOMAIN: u8 = 8;
    const TENURE_SEED: [u8; 32] = [11; 32];
    const APPLY_SEED: [u8; 32] = [12; 32];
    const WRONG_SEED: [u8; 32] = [13; 32];
    const DEFAULT_STATE_CAPACITY: usize = 64;
    const PYTHON_SIGNED_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s2_apply_envelope_v1.json");
    const PYTHON_COMPLETE_REQUEST_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s3_runtime_apply_request_v1.json");
    const PYTHON_EXECUTION_REQUEST_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s4_runtime_apply_request_v2.json");
    const PYTHON_THREAD_EXECUTION_REQUEST_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s5_runtime_apply_request_v3.json");
    const PYTHON_PROCESS_EXECUTION_REQUEST_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s6_runtime_apply_request_v4.json");
    // TEST-ONLY keys matching the independently encoded Python contract fixture.
    const PYTHON_FIXTURE_TENURE_SEED: [u8; 32] = [0x11; 32];
    const PYTHON_FIXTURE_REQUEST_SEED: [u8; 32] = [0x22; 32];

    struct AdmittedFixtureCard;

    impl CardImplementation for AdmittedFixtureCard {
        fn on_start<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async { Ok(()) })
        }

        fn on_input<'a>(
            &'a mut self,
            _context: &'a CardContext,
            _input: InputView<'a>,
        ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
            Box::pin(async { Ok(None) })
        }

        fn on_stop<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async { Ok(()) })
        }
    }

    impl CooperativeLoopImplementation for AdmittedFixtureCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0xa1; 16]);
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef =
            CardImplementationRef::from_bytes([0xa2; 16]);
        const BOUND_DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0xa3; 32]);
        const BOUND_ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0xa4; 32]);
    }

    struct AdmittedThreadFixtureCard {
        calls: Arc<AtomicUsize>,
    }

    impl SynchronousThreadCard for AdmittedThreadFixtureCard {
        fn on_input(
            &mut self,
            cancellation: &crate::thread_domain::ThreadCancellation,
            input: ThreadCardInputView<'_>,
        ) -> Result<(), ThreadCardFailure> {
            assert!(!cancellation.is_cancellation_requested());
            assert_eq!(input.binding(), BindingId::from_bytes([0x32; 16]));
            assert_eq!(input.mailbox(), MailboxRef::from_bytes([0x82; 16]));
            assert_eq!(input.target_port(), PortRef::from_bytes([0x72; 16]));
            assert_eq!(input.message_id(), MessageId::from_bytes([0xb4; 16]));
            assert_eq!(input.payload(), &[0xb4]);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl TrustedSynchronousThreadCard for AdmittedThreadFixtureCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0xb1; 16]);
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef =
            CardImplementationRef::from_bytes([0xb2; 16]);
        const BOUND_DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0xb3; 32]);
        const BOUND_ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0xb4; 32]);
    }

    #[derive(Clone, Debug)]
    struct Fixture {
        scope: u8,
        target: u8,
        writer: u8,
        principal: u8,
        authority: u8,
        tenure_key: u8,
        tenure_algorithm: u16,
        tenure_algorithm_version: u16,
        apply_key: u8,
        apply_algorithm: u16,
        apply_algorithm_version: u16,
        epoch: u64,
        supersedes: u64,
        operation: u8,
        tenure_nonce: Vec<u8>,
        request_nonce: Vec<u8>,
        temporal_id: u8,
        clock_domain: u8,
        clock_generation: u64,
        original_budget: u64,
        remaining_budget: u64,
        tenure_signing_seed: [u8; 32],
        request_signing_seed: [u8; 32],
        tenure_signature_length: usize,
        request_signature_length: usize,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                scope: SCOPE,
                target: TARGET,
                writer: WRITER,
                principal: PRINCIPAL,
                authority: AUTHORITY,
                tenure_key: TENURE_KEY,
                tenure_algorithm: ED25519_ALGORITHM,
                tenure_algorithm_version: ED25519_ALGORITHM_VERSION,
                apply_key: APPLY_KEY,
                apply_algorithm: ED25519_ALGORITHM,
                apply_algorithm_version: ED25519_ALGORITHM_VERSION,
                epoch: 1,
                supersedes: 0,
                operation: 9,
                tenure_nonce: b"tenure-nonce".to_vec(),
                request_nonce: b"request-nonce".to_vec(),
                temporal_id: 10,
                clock_domain: CLOCK_DOMAIN,
                clock_generation: 1,
                original_budget: 100,
                remaining_budget: 50,
                tenure_signing_seed: TENURE_SEED,
                request_signing_seed: APPLY_SEED,
                tenure_signature_length: 64,
                request_signature_length: 64,
            }
        }
    }

    impl Fixture {
        fn envelope(&self) -> RuntimeApplyEnvelope {
            self.envelope_with_assignment_digest(TargetAssignmentDigest::new(Digest32::from_bytes(
                [22; 32],
            )))
        }

        fn envelope_with_assignment_digest(
            &self,
            assignment_digest: TargetAssignmentDigest,
        ) -> RuntimeApplyEnvelope {
            let scope = SourceScopeRef::from_bytes([self.scope; 16]);
            let target = RuntimeHostId::from_bytes([self.target; 16]);
            let writer = PlanWriterRef::from_bytes([self.writer; 16]);
            let epoch = PlanWriterEpoch::new(self.epoch);
            let Ok(tenure_algorithm) = TenureProofAlgorithm::try_new(self.tenure_algorithm) else {
                panic!("fixture tenure algorithm must be nonzero");
            };
            let Ok(authority) = TenureProofAuthority::try_new(
                TenureAuthorityRef::from_bytes([self.authority; 16]),
                TenureKeyRef::from_bytes([self.tenure_key; 16]),
                tenure_algorithm,
                self.tenure_algorithm_version,
            ) else {
                panic!("fixture tenure authority must be valid");
            };
            let Ok(claim) = WriterTenureClaim::try_new(
                scope,
                writer,
                epoch,
                PlanWriterEpoch::new(self.supersedes),
            ) else {
                panic!("fixture tenure claim must be valid");
            };
            let Ok(tenure_transcript) =
                WriterTenureSigningTranscript::try_new(authority, claim, &self.tenure_nonce)
            else {
                panic!("fixture tenure transcript must be valid");
            };
            let tenure_signing_key = SigningKey::from_bytes(&self.tenure_signing_seed);
            let tenure_signature = tenure_signing_key
                .sign(tenure_transcript.as_bytes())
                .to_bytes();
            let Ok(proof) = WriterTenureProof::try_new(
                authority,
                claim,
                &self.tenure_nonce,
                &tenure_signature[..self.tenure_signature_length],
            ) else {
                panic!("fixture tenure proof must be valid");
            };
            let Ok(writer_context) = PlanWriterContext::try_new(writer, epoch, proof) else {
                panic!("fixture writer context must be valid");
            };

            let provenance = PlanProvenance::new(
                scope,
                SourcePlanRef::from_bytes([20; 16]),
                SourcePlanRevision::new(1),
                SourcePlanDigest::new(Digest32::from_bytes([21; 32])),
            );
            let header = RuntimeSliceHeader::new(target, provenance, assignment_digest);
            let Ok(slice) = RuntimeSliceCommitment::try_new(header) else {
                panic!("fixture slice must be valid");
            };
            let control = RuntimeApplyControl::new(
                writer_context,
                ExpectedActive::None,
                ApplyOperationId::from_bytes([self.operation; 16]),
            );
            let Ok(control_commitment) = RuntimeApplyControlCommitment::try_new(slice, control)
            else {
                panic!("fixture control commitment must be valid");
            };

            let Ok(clock_generation) = ClockGeneration::try_new(self.clock_generation) else {
                panic!("fixture clock generation must be nonzero");
            };
            let Ok(temporal) = ApplyTemporalConstraint::try_new(
                TemporalConstraintId::from_bytes([self.temporal_id; 16]),
                ClockDomainRef::from_bytes([self.clock_domain; 16]),
                clock_generation,
                BoundedDuration::from_nanos(self.original_budget),
                BoundedDuration::from_nanos(self.remaining_budget),
            ) else {
                panic!("fixture temporal constraint must be valid");
            };
            let Ok(apply_algorithm) = ApplyAuthAlgorithm::try_new(self.apply_algorithm) else {
                panic!("fixture apply algorithm must be nonzero");
            };
            let Ok(auth_claim) = ApplyRequestAuthClaim::try_new(
                PrincipalRef::from_bytes([self.principal; 16]),
                ApplyAuthKeyRef::from_bytes([self.apply_key; 16]),
                apply_algorithm,
                self.apply_algorithm_version,
                &self.request_nonce,
            ) else {
                panic!("fixture request-auth claim must be valid");
            };
            let Ok(draft) =
                RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
            else {
                panic!("fixture envelope draft must be valid");
            };
            let Ok(request_transcript) = draft.signing_transcript() else {
                panic!("fixture request transcript must be valid");
            };
            let request_signing_key = SigningKey::from_bytes(&self.request_signing_seed);
            let request_signature = request_signing_key
                .sign(request_transcript.as_bytes())
                .to_bytes();
            let Ok(envelope) = draft.finalize(&request_signature[..self.request_signature_length])
            else {
                panic!("fixture envelope must finalize");
            };
            envelope
        }

        fn reading(&self, now: u64) -> ClockReading {
            let Ok(generation) = ClockGeneration::try_new(self.clock_generation) else {
                panic!("fixture clock generation must be nonzero");
            };
            ClockReading::new(
                ClockDomainRef::from_bytes([self.clock_domain; 16]),
                generation,
                MonotonicInstant::from_ticks(now),
            )
        }
    }

    fn tenure_algorithm(value: u16) -> TenureProofAlgorithm {
        let Ok(algorithm) = TenureProofAlgorithm::try_new(value) else {
            panic!("test tenure algorithm must be nonzero");
        };
        algorithm
    }

    fn apply_algorithm(value: u16) -> ApplyAuthAlgorithm {
        let Ok(algorithm) = ApplyAuthAlgorithm::try_new(value) else {
            panic!("test apply algorithm must be nonzero");
        };
        algorithm
    }

    fn trusted_tenure() -> TrustedTenureKey {
        let verifying_key = SigningKey::from_bytes(&TENURE_SEED)
            .verifying_key()
            .to_bytes();
        let Ok(trusted) = TrustedTenureKey::try_new(
            TrustedTenureIdentity::new(
                SourceScopeRef::from_bytes([SCOPE; 16]),
                PrincipalRef::from_bytes([AUTHORITY; 16]),
                1_001,
                1_002,
                TenureAuthorityRef::from_bytes([AUTHORITY; 16]),
            ),
            TenureKeyRef::from_bytes([TENURE_KEY; 16]),
            tenure_algorithm(ED25519_ALGORITHM),
            ED25519_ALGORITHM_VERSION,
            verifying_key,
        ) else {
            panic!("test tenure trust must be valid");
        };
        trusted
    }

    fn trusted_apply() -> TrustedApplyKey {
        let verifying_key = SigningKey::from_bytes(&APPLY_SEED)
            .verifying_key()
            .to_bytes();
        let Ok(trusted) = TrustedApplyKey::try_new(
            TrustedApplyIdentity::new(
                SourceScopeRef::from_bytes([SCOPE; 16]),
                RuntimeHostId::from_bytes([TARGET; 16]),
                PrincipalRef::from_bytes([PRINCIPAL; 16]),
                PlanWriterRef::from_bytes([WRITER; 16]),
            ),
            ApplyAuthKeyRef::from_bytes([APPLY_KEY; 16]),
            apply_algorithm(ED25519_ALGORITHM),
            ED25519_ALGORITHM_VERSION,
            verifying_key,
        ) else {
            panic!("test apply trust must be valid");
        };
        trusted
    }

    fn state_limits(
        tenure_nonce_capacity: usize,
        request_nonce_capacity: usize,
        temporal_lineage_capacity: usize,
    ) -> AdmissionStateLimits {
        let Ok(limits) = AdmissionStateLimits::try_new(
            tenure_nonce_capacity,
            request_nonce_capacity,
            temporal_lineage_capacity,
        ) else {
            panic!("test admission-state limits must be nonzero");
        };
        limits
    }

    fn default_state_limits() -> AdmissionStateLimits {
        state_limits(
            DEFAULT_STATE_CAPACITY,
            DEFAULT_STATE_CAPACITY,
            DEFAULT_STATE_CAPACITY,
        )
    }

    fn admission(maximum_budget: u64) -> ApplyAdmission {
        admission_with_limits(maximum_budget, default_state_limits())
    }

    fn admission_with_limits(
        maximum_budget: u64,
        state_limits: AdmissionStateLimits,
    ) -> ApplyAdmission {
        let Ok(policy) = ApplyAdmissionPolicy::try_new(
            BoundedDuration::from_nanos(maximum_budget),
            state_limits,
            [trusted_tenure()],
            [trusted_apply()],
        ) else {
            panic!("test admission policy must be valid");
        };
        ApplyAdmission::new(policy)
    }

    fn admit(
        admission: &ApplyAdmission,
        fixture: &Fixture,
        state: &AdmissionState,
        now: u64,
    ) -> Result<super::AdmissionTransition, AdmissionError> {
        let envelope = fixture.envelope();
        admission.admit(envelope.canonical_wire(), state, fixture.reading(now))
    }

    fn complete_request(fixture: &Fixture) -> RuntimeApplyRequest {
        let Ok(schema) = SchemaRef::try_new([31; 16], 1, Digest32::from_bytes([32; 32])) else {
            panic!("test schema must be valid");
        };
        let source = PortEndpoint::new(
            InstanceRef::from_bytes([33; 16]),
            PortRef::from_bytes([34; 16]),
            PortSpec::new(
                PortDirection::Out,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            InstanceRef::from_bytes([35; 16]),
            PortRef::from_bytes([36; 16]),
            PortSpec::new(
                PortDirection::In,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let Ok(delivery) = DeliveryProfile::try_new(
            64,
            BoundedDuration::from_nanos(100),
            OverflowPolicy::RejectNew,
        ) else {
            panic!("test delivery must be valid");
        };
        let Ok(mailbox) = MailboxSpec::try_new(
            4,
            256,
            BoundedDuration::from_nanos(80),
            2,
            384,
            OverflowPolicy::RejectNew,
        ) else {
            panic!("test mailbox must be valid");
        };
        let Ok(binding) = BindingAssignment::try_new(
            BindingId::from_bytes([37; 16]),
            source,
            target,
            MailboxRef::from_bytes([38; 16]),
            delivery,
            mailbox,
        ) else {
            panic!("test binding must be valid");
        };
        let Ok(assignments) = TargetAssignments::try_new(vec![binding]) else {
            panic!("test assignments must be valid");
        };
        let envelope = fixture.envelope_with_assignment_digest(assignments.assignment_digest());
        let commitment = envelope.control_commitment().slice();
        let Ok(slice) = RuntimePlanSlice::try_new(commitment, assignments) else {
            panic!("test complete slice must be valid");
        };
        let Ok(request) = RuntimeApplyRequest::try_new(envelope, slice) else {
            panic!("test complete request must be valid");
        };
        request
    }

    fn mutate_tlv(frame: &mut [u8], target_tag: u16) {
        let mut cursor = b"ParaEGOX\0runtime-apply-envelope".len() + 4;
        while cursor < frame.len() {
            let tag = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]);
            let length = u32::from_be_bytes([
                frame[cursor + 2],
                frame[cursor + 3],
                frame[cursor + 4],
                frame[cursor + 5],
            ]) as usize;
            cursor += 6;
            if tag == target_tag {
                frame[cursor] ^= 1;
                return;
            }
            cursor += length;
        }
        panic!("target test TLV must exist");
    }

    fn fixture_hex_bytes(field: &str) -> Vec<u8> {
        fixture_document_hex_bytes(PYTHON_SIGNED_FIXTURE_JSON, field)
    }

    fn complete_request_fixture_hex_bytes(field: &str) -> Vec<u8> {
        fixture_document_hex_bytes(PYTHON_COMPLETE_REQUEST_FIXTURE_JSON, field)
    }

    fn execution_request_fixture_hex_bytes(field: &str) -> Vec<u8> {
        fixture_document_hex_bytes(PYTHON_EXECUTION_REQUEST_FIXTURE_JSON, field)
    }

    fn thread_execution_request_fixture_hex_bytes(field: &str) -> Vec<u8> {
        fixture_document_hex_bytes(PYTHON_THREAD_EXECUTION_REQUEST_FIXTURE_JSON, field)
    }

    fn process_execution_request_fixture_hex_bytes(field: &str) -> Vec<u8> {
        fixture_document_hex_bytes(PYTHON_PROCESS_EXECUTION_REQUEST_FIXTURE_JSON, field)
    }

    fn fixture_document_hex_bytes(document: &str, field: &str) -> Vec<u8> {
        let marker = format!("\"{field}\": \"");
        let Some((_, tail)) = document.split_once(marker.as_str()) else {
            panic!("Python fixture field must exist");
        };
        let Some((hex, _)) = tail.split_once('"') else {
            panic!("Python fixture hex value must terminate");
        };
        assert_eq!(hex.len() % 2, 0, "fixture hex must contain full bytes");

        let mut decoded = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            decoded.push((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]));
        }
        decoded
    }

    fn python_fixture_admission_for_target(
        trusted_target_byte: u8,
    ) -> (ApplyAdmission, ClockReading) {
        let scope = SourceScopeRef::from_bytes([0x01; 16]);
        let target = RuntimeHostId::from_bytes([trusted_target_byte; 16]);
        let writer = PlanWriterRef::from_bytes([0x09; 16]);
        let principal = PrincipalRef::from_bytes([0x09; 16]);

        let tenure_verifying_key = SigningKey::from_bytes(&PYTHON_FIXTURE_TENURE_SEED)
            .verifying_key()
            .to_bytes();
        let Ok(tenure_trust) = TrustedTenureKey::try_new(
            TrustedTenureIdentity::new(
                scope,
                PrincipalRef::from_bytes([0x06; 16]),
                1_001,
                1_002,
                TenureAuthorityRef::from_bytes([0x07; 16]),
            ),
            TenureKeyRef::from_bytes([0x08; 16]),
            tenure_algorithm(ED25519_ALGORITHM),
            ED25519_ALGORITHM_VERSION,
            tenure_verifying_key,
        ) else {
            panic!("Python fixture tenure trust must be valid");
        };
        let request_verifying_key = SigningKey::from_bytes(&PYTHON_FIXTURE_REQUEST_SEED)
            .verifying_key()
            .to_bytes();
        let Ok(request_trust) = TrustedApplyKey::try_new(
            TrustedApplyIdentity::new(scope, target, principal, writer),
            ApplyAuthKeyRef::from_bytes([0x0c; 16]),
            apply_algorithm(ED25519_ALGORITHM),
            ED25519_ALGORITHM_VERSION,
            request_verifying_key,
        ) else {
            panic!("Python fixture request trust must be valid");
        };
        let Ok(policy) = ApplyAdmissionPolicy::try_new(
            BoundedDuration::from_nanos(100),
            state_limits(4, 4, 4),
            [tenure_trust],
            [request_trust],
        ) else {
            panic!("Python fixture admission policy must be valid");
        };
        let Ok(generation) = ClockGeneration::try_new(3) else {
            panic!("Python fixture clock generation must be valid");
        };
        let reading = ClockReading::new(
            ClockDomainRef::from_bytes([0x0b; 16]),
            generation,
            MonotonicInstant::from_ticks(0),
        );
        (ApplyAdmission::new(policy), reading)
    }

    fn python_fixture_admission_and_reading() -> (ApplyAdmission, ClockReading) {
        python_fixture_admission_for_target(0x05)
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("fixture must contain hexadecimal digits"),
        }
    }

    #[test]
    fn policy_rejects_weak_unsupported_duplicate_and_empty_trust() {
        assert_eq!(
            AdmissionStateLimits::try_new(0, 1, 1),
            Err(AdmissionConfigurationError::ZeroTenureNonceCapacity)
        );
        assert_eq!(
            AdmissionStateLimits::try_new(1, 0, 1),
            Err(AdmissionConfigurationError::ZeroRequestNonceCapacity)
        );
        assert_eq!(
            AdmissionStateLimits::try_new(1, 1, 0),
            Err(AdmissionConfigurationError::ZeroTemporalLineageCapacity)
        );
        let limits = state_limits(2, 3, 4);
        assert_eq!(limits.tenure_nonce_capacity(), 2);
        assert_eq!(limits.request_nonce_capacity(), 3);
        assert_eq!(limits.temporal_lineage_capacity(), 4);

        let mut weak_key = [0; 32];
        weak_key[0] = 1;
        assert_eq!(
            TrustedTenureKey::try_new(
                TrustedTenureIdentity::new(
                    SourceScopeRef::from_bytes([SCOPE; 16]),
                    PrincipalRef::from_bytes([AUTHORITY; 16]),
                    1_001,
                    1_002,
                    TenureAuthorityRef::from_bytes([AUTHORITY; 16]),
                ),
                TenureKeyRef::from_bytes([TENURE_KEY; 16]),
                tenure_algorithm(ED25519_ALGORITHM),
                ED25519_ALGORITHM_VERSION,
                weak_key,
            )
            .err(),
            Some(AdmissionConfigurationError::WeakVerifyingKey)
        );
        assert_eq!(
            TrustedTenureKey::try_new(
                TrustedTenureIdentity::new(
                    SourceScopeRef::from_bytes([SCOPE; 16]),
                    PrincipalRef::from_bytes([AUTHORITY; 16]),
                    1_001,
                    1_002,
                    TenureAuthorityRef::from_bytes([AUTHORITY; 16]),
                ),
                TenureKeyRef::from_bytes([TENURE_KEY; 16]),
                tenure_algorithm(2),
                ED25519_ALGORITHM_VERSION,
                SigningKey::from_bytes(&TENURE_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .err(),
            Some(AdmissionConfigurationError::UnsupportedSignatureProfile)
        );
        assert_eq!(
            ApplyAdmissionPolicy::try_new(
                BoundedDuration::from_nanos(100),
                default_state_limits(),
                [trusted_tenure(), trusted_tenure()],
                [trusted_apply()],
            )
            .err(),
            Some(AdmissionConfigurationError::DuplicateTenureTrust)
        );
        assert_eq!(
            ApplyAdmissionPolicy::try_new(
                BoundedDuration::from_nanos(100),
                default_state_limits(),
                [trusted_tenure()],
                [trusted_apply(), trusted_apply()],
            )
            .err(),
            Some(AdmissionConfigurationError::DuplicateApplyTrust)
        );
        assert_eq!(
            ApplyAdmissionPolicy::try_new(
                BoundedDuration::from_nanos(100),
                default_state_limits(),
                [],
                [trusted_apply()],
            )
            .err(),
            Some(AdmissionConfigurationError::EmptyTenureTrust)
        );
        assert_eq!(
            ApplyAdmissionPolicy::try_new(
                BoundedDuration::from_nanos(100),
                default_state_limits(),
                [trusted_tenure()],
                [],
            )
            .err(),
            Some(AdmissionConfigurationError::EmptyApplyTrust)
        );
        assert_eq!(
            ApplyAdmissionPolicy::try_new(
                BoundedDuration::from_nanos(0),
                default_state_limits(),
                [trusted_tenure()],
                [trusted_apply()],
            )
            .err(),
            Some(AdmissionConfigurationError::ZeroMaximumBudget)
        );
    }

    #[test]
    fn valid_request_admits_and_exact_replay_does_not_renew_deadline() {
        let fixture = Fixture::default();
        let admission = admission(100);
        let empty = AdmissionState::for_new_boundary();
        let Ok(first) = admit(&admission, &fixture, &empty, 0) else {
            panic!("valid signed request must admit");
        };
        assert_eq!(first.disposition(), AdmissionDisposition::Fresh);
        assert_eq!(first.next_state().tenure_nonce_count(), 1);
        assert_eq!(first.next_state().request_nonce_count(), 1);
        assert_eq!(first.next_state().temporal_lineage_count(), 1);
        assert_eq!(first.admitted().deadline().deadline().value(), 50);
        assert_eq!(
            first.admitted().request_digest(),
            fixture.envelope().request_digest()
        );

        let Ok(replay) = admit(&admission, &fixture, first.next_state(), 20) else {
            panic!("live exact replay must remain queryable");
        };
        assert_eq!(replay.disposition(), AdmissionDisposition::Replayed);
        assert_eq!(replay.admitted().deadline().deadline().value(), 50);
        assert_eq!(replay.next_state(), first.next_state());

        let mut second_request = fixture.clone();
        second_request.operation = 10;
        second_request.request_nonce = b"request-two".to_vec();
        second_request.temporal_id = 11;
        let Ok(second) = admit(&admission, &second_request, replay.next_state(), 20) else {
            panic!("one stable tenure proof must authorize multiple requests");
        };
        assert_eq!(second.next_state().tenure_nonce_count(), 1);
        assert_eq!(second.next_state().request_nonce_count(), 2);
    }

    #[test]
    fn complete_request_validates_assignment_body_before_prepare() {
        let fixture = Fixture::default();
        let admission = admission(100);
        let request = complete_request(&fixture);
        let empty_admission = AdmissionState::for_new_boundary();

        let mut corrupted = request.canonical_wire().to_vec();
        let Some(last) = corrupted.last_mut() else {
            panic!("complete request wire must not be empty");
        };
        *last ^= 1;
        assert!(
            admission
                .admit_request(&corrupted, &empty_admission, fixture.reading(0))
                .is_err()
        );
        assert_eq!(empty_admission, AdmissionState::for_new_boundary());

        let Ok(transition) = admission.admit_request(
            request.canonical_wire(),
            &empty_admission,
            fixture.reading(0),
        ) else {
            panic!("complete signed request must admit");
        };
        assert_eq!(transition.disposition(), AdmissionDisposition::Fresh);
        assert_eq!(transition.slice().assignments().len(), 1);
        assert_eq!(
            transition.slice().assignments().assignment_digest(),
            transition
                .admitted()
                .payload()
                .slice()
                .header()
                .assignment_digest()
        );

        let control = ApplyControlState::new(
            SourceScopeRef::from_bytes([SCOPE; 16]),
            RuntimeHostId::from_bytes([TARGET; 16]),
        );
        let Ok(fenced) = evaluate_writer_fence(&control, transition.admitted(), fixture.reading(0))
        else {
            panic!("authenticated complete request must pass writer fencing");
        };
        let Ok(prepared) = evaluate_prepare(
            fenced.next_state(),
            transition.admitted(),
            None,
            fixture.reading(0),
        ) else {
            panic!("authenticated complete request must reach prepare");
        };
        assert_eq!(prepared.disposition(), PrepareDisposition::Prepared);

        let Some(&assignment) = transition.slice().assignments().as_slice().first() else {
            panic!("admitted complete request must retain its assignment");
        };
        let reading = fixture.reading(0);
        let Ok(mut mailbox) = Mailbox::try_new(
            assignment.mailbox(),
            assignment.target_spec().schema(),
            assignment.target_spec().interaction(),
            assignment.mailbox_spec(),
            reading.domain(),
            reading.generation(),
        ) else {
            panic!("admitted assignment must construct its exact target mailbox");
        };
        let mut binding = PortBinding::new(assignment.binding_id());
        let Ok(epoch) = binding.prepare(assignment, &mailbox, None) else {
            panic!("admitted assignment must prepare against its exact mailbox");
        };
        let Ok(active) = binding.activate(epoch, &mailbox, None) else {
            panic!("prepared admitted assignment must activate");
        };
        assert_eq!(active.assignment(), assignment);

        let Ok(deadline) = reading.try_deadline_after(BoundedDuration::from_nanos(40)) else {
            panic!("test message deadline must be representable");
        };
        let Ok(payload) = PayloadHandle::try_from_vec(vec![41; 8]) else {
            panic!("test payload must be representable");
        };
        let message = ValidatedMessage::new(
            MessageId::from_bytes([42; 16]),
            assignment.target_spec().schema(),
            assignment.target_spec().interaction(),
            None,
            deadline,
            payload,
        );
        let Ok(report) = binding.offer(
            assignment.binding_id(),
            epoch,
            message,
            &mut mailbox,
            reading,
        ) else {
            panic!("active binding must offer directly to the assigned mailbox");
        };
        assert!(matches!(report.outcome(), EnqueueOutcome::Admitted));
        let Ok(snapshot) = mailbox.snapshot() else {
            panic!("mailbox state must remain internally consistent");
        };
        assert_eq!(snapshot.queued_items(), 1);
        assert_eq!(snapshot.retained_bytes(), 8);
    }

    #[test]
    fn first_seen_request_installs_full_budget_at_target_ingress() {
        let fixture = Fixture::default();
        let admission = admission(100);
        let Ok(first_seen) = admit(
            &admission,
            &fixture,
            &AdmissionState::for_new_boundary(),
            10_000,
        ) else {
            panic!("unseen signed request must install its ingress-relative budget");
        };

        assert_eq!(first_seen.disposition(), AdmissionDisposition::Fresh);
        assert_eq!(first_seen.admitted().deadline().deadline().value(), 10_050);
    }

    #[test]
    fn exact_replay_rejects_torn_admission_indexes() {
        let fixture = Fixture::default();
        let admission = admission(100);
        let Ok(first) = admit(&admission, &fixture, &AdmissionState::for_new_boundary(), 0) else {
            panic!("initial request must admit");
        };

        let mut missing_tenure = first.next_state().clone();
        missing_tenure.tenure_nonces.clear();
        assert_eq!(
            admit(&admission, &fixture, &missing_tenure, 1).err(),
            Some(AdmissionError::AdmissionStateInconsistent)
        );

        let mut missing_temporal = first.next_state().clone();
        missing_temporal.temporal.clear();
        assert_eq!(
            admit(&admission, &fixture, &missing_temporal, 1).err(),
            Some(AdmissionError::AdmissionStateInconsistent)
        );

        let mut attenuation = fixture.clone();
        attenuation.operation = 10;
        attenuation.request_nonce = b"attenuation-request".to_vec();
        attenuation.remaining_budget = 40;
        let Ok(attenuated) = admit(&admission, &attenuation, first.next_state(), 1) else {
            panic!("fresh attenuation must admit");
        };
        let mut torn_attenuation = attenuated.next_state().clone();
        torn_attenuation.temporal = first.next_state().temporal.clone();
        assert_eq!(
            admit(&admission, &attenuation, &torn_attenuation, 2).err(),
            Some(AdmissionError::AdmissionStateInconsistent)
        );
    }

    #[test]
    fn python_signed_fixture_reaches_rust_cryptographic_admission() {
        let wire = fixture_hex_bytes("canonical_wire_hex");
        let expected_request_digest = fixture_hex_bytes("request_digest_hex");
        let (admission, reading) = python_fixture_admission_and_reading();
        let Ok(transition) = admission.admit(&wire, &AdmissionState::for_new_boundary(), reading)
        else {
            panic!("Python-produced canonical fixture must reach Rust admission");
        };
        assert_eq!(transition.disposition(), AdmissionDisposition::Fresh);
        assert_eq!(
            transition.admitted().request_digest().as_bytes().as_slice(),
            expected_request_digest.as_slice()
        );
        assert_eq!(transition.admitted().deadline().deadline().value(), 60);
        assert_eq!(transition.next_state().tenure_nonce_count(), 1);
        assert_eq!(transition.next_state().request_nonce_count(), 1);
        assert_eq!(transition.next_state().temporal_lineage_count(), 1);
    }

    #[test]
    fn python_complete_request_fixture_reaches_rust_assignment_and_crypto_admission() {
        let wire = complete_request_fixture_hex_bytes("outer_wire_hex");
        let expected_assignment_body = complete_request_fixture_hex_bytes("assignment_body_hex");
        let expected_request_digest = complete_request_fixture_hex_bytes("request_digest_hex");
        let expected_assignment_digest =
            complete_request_fixture_hex_bytes("assignment_digest_hex");
        let (admission, reading) = python_fixture_admission_and_reading();

        let Ok(decoded) = RuntimeApplyRequest::decode(&wire) else {
            panic!("Python-produced complete request must decode in the Rust contract owner");
        };
        assert_eq!(decoded.canonical_wire(), wire);
        assert_eq!(
            decoded.slice().assignments().canonical_wire(),
            expected_assignment_body
        );

        let Ok(transition) =
            admission.admit_request(&wire, &AdmissionState::for_new_boundary(), reading)
        else {
            panic!(
                "Python-produced complete request must reach Rust assignment and crypto admission"
            );
        };
        assert_eq!(transition.disposition(), AdmissionDisposition::Fresh);
        assert_eq!(transition.slice().assignments().len(), 2);
        assert_eq!(
            transition.slice().assignments().as_slice()[0]
                .binding_id()
                .as_bytes(),
            &[0x31; 16]
        );
        assert_eq!(
            transition.slice().assignments().as_slice()[1]
                .binding_id()
                .as_bytes(),
            &[0x32; 16]
        );
        assert_eq!(
            transition
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_assignment_digest.as_slice()
        );
        assert_eq!(
            transition.admitted().request_digest().as_bytes().as_slice(),
            expected_request_digest.as_slice()
        );
        assert_eq!(transition.admitted().deadline().deadline().value(), 60);
        assert_eq!(transition.next_state().tenure_nonce_count(), 1);
        assert_eq!(transition.next_state().request_nonce_count(), 1);
        assert_eq!(transition.next_state().temporal_lineage_count(), 1);

        let control = ApplyControlState::new(
            SourceScopeRef::from_bytes([0x01; 16]),
            RuntimeHostId::from_bytes([0x05; 16]),
        );
        let Ok(fenced) = evaluate_writer_fence(&control, transition.admitted(), reading) else {
            panic!("independent complete fixture must pass the writer fence");
        };
        let Ok(prepared) =
            evaluate_prepare(fenced.next_state(), transition.admitted(), None, reading)
        else {
            panic!("independent complete fixture must reach prepare before installation");
        };
        assert_eq!(prepared.disposition(), PrepareDisposition::Prepared);

        for (index, &assignment) in transition
            .slice()
            .assignments()
            .as_slice()
            .iter()
            .enumerate()
        {
            let Ok(mut mailbox) = Mailbox::try_new(
                assignment.mailbox(),
                assignment.target_spec().schema(),
                assignment.target_spec().interaction(),
                assignment.mailbox_spec(),
                reading.domain(),
                reading.generation(),
            ) else {
                panic!("independent fixture assignment must construct its exact mailbox");
            };
            let mut binding = PortBinding::new(assignment.binding_id());
            let Ok(epoch) = binding.prepare(assignment, &mailbox, None) else {
                panic!("independent fixture assignment must prepare");
            };
            let Ok(_) = binding.activate(epoch, &mailbox, None) else {
                panic!("independent fixture assignment must activate");
            };
            let Ok(deadline) = reading.try_deadline_after(BoundedDuration::from_nanos(40)) else {
                panic!("fixture message deadline must be representable");
            };
            let Ok(payload) = PayloadHandle::try_from_vec(vec![index as u8 + 1; index + 1]) else {
                panic!("fixture payload must be representable");
            };
            let message = ValidatedMessage::new(
                MessageId::from_bytes([index as u8 + 1; 16]),
                assignment.target_spec().schema(),
                assignment.target_spec().interaction(),
                None,
                deadline,
                payload,
            );
            let Ok(report) = binding.offer(
                assignment.binding_id(),
                epoch,
                message,
                &mut mailbox,
                reading,
            ) else {
                panic!("independent fixture route must offer to its sole mailbox");
            };
            assert!(matches!(report.outcome(), EnqueueOutcome::Admitted));
            let Ok(snapshot) = mailbox.snapshot() else {
                panic!("fixture mailbox must remain internally consistent");
            };
            assert_eq!(snapshot.queued_items(), 1);
            assert_eq!(snapshot.retained_bytes(), index as u64 + 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn python_execution_request_fixture_reaches_strict_v2_crypto_admission_and_component() {
        let wire = execution_request_fixture_hex_bytes("outer_wire_hex");
        let expected_bindings = execution_request_fixture_hex_bytes("pxta_body_hex");
        let expected_execution = execution_request_fixture_hex_bytes("pxte_body_hex");
        let expected_composite = execution_request_fixture_hex_bytes("composite_digest_hex");
        let expected_request_digest = execution_request_fixture_hex_bytes("request_digest_hex");
        let (admission, reading) = python_fixture_admission_and_reading();

        let decoded = RuntimeApplyRequestV2::decode(&wire)
            .unwrap_or_else(|error| panic!("independent v2 request must decode: {error}"));
        assert_eq!(decoded.canonical_wire(), wire);
        assert_eq!(
            decoded.slice().assignments().bindings().canonical_wire(),
            expected_bindings
        );
        assert_eq!(
            decoded.slice().assignments().execution().canonical_wire(),
            expected_execution
        );

        let transition = admission
            .admit_execution_request(&wire, &AdmissionState::for_new_boundary(), reading)
            .unwrap_or_else(|error| panic!("independent v2 request must admit: {error}"));
        assert_eq!(transition.disposition(), AdmissionDisposition::Fresh);
        assert_eq!(transition.slice().assignments().bindings().len(), 2);
        assert_eq!(
            transition
                .slice()
                .assignments()
                .execution()
                .mailbox_executions()
                .len(),
            1
        );
        assert_eq!(
            transition
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_composite.as_slice()
        );
        assert_eq!(
            transition.admitted().request_digest().as_bytes().as_slice(),
            expected_request_digest.as_slice()
        );
        assert_eq!(transition.admitted().deadline().deadline().value(), 60);
        assert_eq!(transition.next_state().tenure_nonce_count(), 1);
        assert_eq!(transition.next_state().request_nonce_count(), 1);
        assert_eq!(transition.next_state().temporal_lineage_count(), 1);

        let execution = transition
            .slice()
            .assignments()
            .execution()
            .mailbox_executions()[0];
        let binding = transition
            .slice()
            .assignments()
            .bindings()
            .as_slice()
            .iter()
            .copied()
            .find(|assignment| assignment.binding_id() == execution.binding_id())
            .unwrap_or_else(|| panic!("admitted execution binding must exist"));
        let selected =
            TrustedCardImplementation::try_resolve_loop(&[execution], || AdmittedFixtureCard)
                .unwrap_or_else(|error| {
                    panic!("admitted fixture implementation must resolve: {error}")
                });
        let host_epoch = RuntimeHostEpoch::try_new(1)
            .unwrap_or_else(|error| panic!("fixture host epoch must build: {error}"));
        let domain_epoch = DomainEpoch::try_new(1)
            .unwrap_or_else(|error| panic!("fixture domain epoch must build: {error}"));
        let instance_generation = InstanceGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("fixture instance generation must build: {error}"));
        let runtime_clock = RuntimeClock::new(
            reading.domain(),
            reading.generation(),
            reading.now().value(),
        );
        let root = CancellationSource::root();
        let mut component = SingleSubjectComponentRuntime::try_new(
            transition.slice(),
            selected,
            ComponentRuntimeEpochs::new(host_epoch, domain_epoch, instance_generation),
            runtime_clock,
            &root,
        )
        .unwrap_or_else(|error| panic!("admitted fixture must compose: {error}"));
        assert_eq!(component.start().await, Ok(CardStartOutcome::Started));
        let ingress = component
            .active_ingress(binding.binding_id())
            .unwrap_or_else(|| panic!("admitted execution binding must activate in the harness"));
        let message_deadline = runtime_clock
            .deadline_after(BoundedDuration::from_nanos(20))
            .unwrap_or_else(|error| panic!("fixture message deadline must build: {error}"));
        let payload = PayloadHandle::try_from_vec(vec![0xA4])
            .unwrap_or_else(|error| panic!("fixture payload must build: {error}"));
        let message = ValidatedMessage::new(
            MessageId::from_bytes([0xA4; 16]),
            binding.target_spec().schema(),
            binding.target_spec().interaction(),
            None,
            message_deadline,
            payload,
        );
        let offer = component
            .try_offer(&ingress, message)
            .unwrap_or_else(|failure| panic!("admitted fixture offer failed: {}", failure.error()));
        assert!(matches!(offer.outcome(), EnqueueOutcome::Admitted));
        let dispatch = component
            .dispatch_once()
            .await
            .unwrap_or_else(|error| panic!("admitted fixture dispatch failed: {error}"));
        assert!(matches!(
            dispatch.outcome(),
            ComponentDispatchOutcome::Invoked {
                callback: ComponentCallbackOutcome::Completed {
                    output_discarded: false
                },
                terminal,
            } if terminal.reason() == crate::mailbox::TerminalReason::Completed
        ));
        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("admitted fixture shutdown failed: {error}"));
        assert_eq!(shutdown.card(), CardStopOutcome::Stopped);
        assert!(shutdown.is_zero_cleanup());

        let v1 = complete_request_fixture_hex_bytes("outer_wire_hex");
        assert!(
            admission
                .admit_execution_request(&v1, &AdmissionState::for_new_boundary(), reading)
                .is_err(),
            "the v2 entry must never fall back to PXAR v1"
        );
    }

    #[test]
    fn python_thread_request_fixture_reaches_v3_admission_and_thread_component() {
        let wire = thread_execution_request_fixture_hex_bytes("outer_wire_hex");
        let expected_bindings = thread_execution_request_fixture_hex_bytes("pxta_body_hex");
        let expected_execution = thread_execution_request_fixture_hex_bytes("pxte_v2_body_hex");
        let expected_composite =
            thread_execution_request_fixture_hex_bytes("composite_v3_digest_hex");
        let expected_request_digest =
            thread_execution_request_fixture_hex_bytes("request_digest_hex");
        let s4_loop = execution_request_fixture_hex_bytes("pxte_body_hex");
        let (admission, reading) = python_fixture_admission_and_reading();

        let decoded = RuntimeApplyRequestV3::decode(&wire)
            .unwrap_or_else(|error| panic!("independent v3 request must decode: {error}"));
        assert_eq!(decoded.canonical_wire(), wire);
        assert_eq!(
            decoded.slice().assignments().bindings().canonical_wire(),
            expected_bindings
        );
        let execution = decoded.slice().assignments().execution();
        assert_eq!(execution.canonical_wire(), expected_execution);
        assert_eq!(
            execution
                .loop_plan()
                .unwrap_or_else(|| panic!("v3 fixture must retain the S4 Loop plan"))
                .canonical_wire(),
            s4_loop
        );
        assert_eq!(execution.executor_budget().max_total_threads(), 3);
        assert_eq!(execution.executor_budget().framework_threads(), 2);
        assert_eq!(execution.thread_domains().len(), 1);
        assert_eq!(execution.thread_domains()[0].worker_count(), 1);
        assert_eq!(execution.thread_mailbox_executions().len(), 1);
        assert_eq!(
            execution.thread_mailbox_executions()[0]
                .requirements()
                .native_thread_reservation(),
            0
        );

        let transition = admission
            .admit_thread_execution_request(&wire, &AdmissionState::for_new_boundary(), reading)
            .unwrap_or_else(|error| panic!("independent v3 request must admit: {error}"));
        assert_eq!(transition.disposition(), AdmissionDisposition::Fresh);
        assert_eq!(transition.slice(), decoded.slice());
        assert_eq!(
            transition
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_composite.as_slice()
        );
        assert_eq!(
            transition.admitted().request_digest().as_bytes().as_slice(),
            expected_request_digest.as_slice()
        );
        assert_eq!(transition.admitted().deadline().deadline().value(), 60);
        assert_eq!(transition.next_state().tenure_nonce_count(), 1);
        assert_eq!(transition.next_state().request_nonce_count(), 1);
        assert_eq!(transition.next_state().temporal_lineage_count(), 1);

        let thread_execution = transition
            .slice()
            .assignments()
            .execution()
            .thread_mailbox_executions()[0];
        let binding = transition
            .slice()
            .assignments()
            .bindings()
            .as_slice()
            .iter()
            .copied()
            .find(|assignment| assignment.binding_id() == thread_execution.binding_id())
            .unwrap_or_else(|| panic!("admitted Thread execution binding must exist"));
        let calls = Arc::new(AtomicUsize::new(0));
        let card_calls = Arc::clone(&calls);
        let selected =
            TrustedThreadCardImplementation::try_resolve::<AdmittedThreadFixtureCard, _>(
                thread_execution,
                move || AdmittedThreadFixtureCard { calls: card_calls },
            )
            .unwrap_or_else(|error| {
                panic!("admitted Thread fixture implementation must resolve: {error}")
            });
        let runtime_clock = RuntimeClock::new(
            reading.domain(),
            reading.generation(),
            reading.now().value(),
        );
        let prepared =
            PreparedThreadComponentRuntime::try_new(transition.slice(), selected, runtime_clock)
                .unwrap_or_else(|error| panic!("admitted Thread component must prepare: {error}"));
        let executor_budget = transition
            .slice()
            .assignments()
            .execution()
            .executor_budget();
        let mut registry = RuntimeThreadRegistry::try_new(executor_budget)
            .unwrap_or_else(|error| panic!("signed executor registry must build: {error}"));
        let domain_epoch = DomainEpoch::try_new(2)
            .unwrap_or_else(|error| panic!("Thread fixture domain epoch must build: {error}"));
        let handle = prepared
            .install(&mut registry, domain_epoch)
            .unwrap_or_else(|error| panic!("admitted Thread component must install: {error}"));

        let dispatch = registry
            .with_owner_mut(&handle, |component| {
                let ingress = component.active_ingress().unwrap_or_else(|| {
                    panic!("admitted Thread binding must activate in the registry")
                });
                let deadline = runtime_clock
                    .deadline_after(BoundedDuration::from_nanos(1_000_000_000))
                    .unwrap_or_else(|error| {
                        panic!("Thread fixture message deadline must build: {error}")
                    });
                let payload = PayloadHandle::try_from_vec(vec![0xb4])
                    .unwrap_or_else(|error| panic!("Thread fixture payload must build: {error}"));
                let message = ValidatedMessage::new(
                    MessageId::from_bytes([0xb4; 16]),
                    binding.target_spec().schema(),
                    binding.target_spec().interaction(),
                    None,
                    deadline,
                    payload,
                );
                let offer = component
                    .try_offer(ingress, message)
                    .unwrap_or_else(|failure| {
                        panic!("admitted Thread fixture offer failed: {}", failure.error())
                    });
                assert!(matches!(offer.outcome(), EnqueueOutcome::Admitted));
                component.try_dispatch_once()
            })
            .unwrap_or_else(|error| panic!("Thread component registry visit failed: {error}"))
            .unwrap_or_else(|error| panic!("admitted Thread dispatch failed: {error}"));
        assert_eq!(dispatch, ThreadComponentDispatchOutcome::Started);

        let completion_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let outcome = registry
                .with_owner_mut(&handle, |component| component.poll_pending())
                .unwrap_or_else(|error| panic!("Thread completion registry visit failed: {error}"))
                .unwrap_or_else(|error| panic!("admitted Thread completion failed: {error}"));
            match outcome {
                ThreadComponentPollOutcome::Pending(_) => {
                    assert!(
                        Instant::now() < completion_deadline,
                        "admitted Thread fixture did not complete"
                    );
                    thread::yield_now();
                }
                ThreadComponentPollOutcome::Completed {
                    callback,
                    terminal,
                    expired,
                } => {
                    assert_eq!(callback, Ok(()));
                    assert_eq!(terminal.reason(), TerminalReason::Completed);
                    assert!(expired.is_empty());
                    break;
                }
                ThreadComponentPollOutcome::NoInvocation { .. }
                | ThreadComponentPollOutcome::LateRejected { .. }
                | ThreadComponentPollOutcome::Panicked { .. } => {
                    panic!("admitted Thread fixture must complete normally")
                }
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        registry
            .shutdown()
            .unwrap_or_else(|error| panic!("admitted Thread registry shutdown failed: {error}"));
        assert_eq!(registry.domain_count(), 0);
        let zero = registry
            .budget_snapshot()
            .unwrap_or_else(|error| panic!("Thread registry zero snapshot failed: {error}"));
        assert_eq!(zero.active_reservations(), 0);
        assert_eq!(zero.managed_workers(), 0);
        assert_eq!(zero.native_threads(), 0);

        let v2 = execution_request_fixture_hex_bytes("outer_wire_hex");
        assert!(
            admission
                .admit_thread_execution_request(&v2, &AdmissionState::for_new_boundary(), reading,)
                .is_err(),
            "the v3 entry must never fall back to PXAR v2"
        );

        let mut execution_tamper = wire.clone();
        let last = execution_tamper
            .last_mut()
            .unwrap_or_else(|| panic!("v3 fixture must be nonempty"));
        *last ^= 1;
        assert!(
            admission
                .admit_thread_execution_request(
                    &execution_tamper,
                    &AdmissionState::for_new_boundary(),
                    reading,
                )
                .is_err(),
            "tampered PXTE v2 must fail before admission state changes"
        );

        let mut signature_tamper = wire;
        let envelope_len = u32::from_be_bytes([
            signature_tamper[6],
            signature_tamper[7],
            signature_tamper[8],
            signature_tamper[9],
        ]) as usize;
        mutate_tlv(&mut signature_tamper[18..18 + envelope_len], 0x25);
        assert!(
            admission
                .admit_thread_execution_request(
                    &signature_tamper,
                    &AdmissionState::for_new_boundary(),
                    reading,
                )
                .is_err(),
            "v3 outer framing must not bypass the existing request signature"
        );
    }

    #[test]
    fn python_process_request_fixture_reaches_strict_v4_admission_and_fence_only() {
        let wire = process_execution_request_fixture_hex_bytes("outer_wire_hex");
        let expected_bindings = process_execution_request_fixture_hex_bytes("pxta_body_hex");
        let expected_execution = process_execution_request_fixture_hex_bytes("pxte_v3_body_hex");
        let expected_prior =
            process_execution_request_fixture_hex_bytes("embedded_pxte_v2_body_hex");
        let expected_composite =
            process_execution_request_fixture_hex_bytes("composite_v4_digest_hex");
        let expected_request_digest =
            process_execution_request_fixture_hex_bytes("request_digest_hex");
        let (admission, reading) = python_fixture_admission_and_reading();

        let decoded = RuntimeApplyRequestV4::decode(&wire)
            .unwrap_or_else(|error| panic!("independent v4 request must decode: {error}"));
        assert_eq!(decoded.canonical_wire(), wire);
        assert_eq!(
            decoded.slice().assignments().bindings().canonical_wire(),
            expected_bindings
        );
        let execution = decoded.slice().assignments().execution();
        assert_eq!(execution.canonical_wire(), expected_execution);
        assert_eq!(
            execution
                .thread_plan()
                .unwrap_or_else(|| panic!("v4 fixture must retain exact PXTE v2"))
                .canonical_wire(),
            expected_prior
        );
        assert_eq!(execution.process_domains().len(), 1);
        assert_eq!(execution.process_mailbox_executions().len(), 1);

        let initial_state = AdmissionState::for_new_boundary();
        let transition = admission
            .admit_process_execution_request(&wire, &initial_state, reading)
            .unwrap_or_else(|error| panic!("independent v4 request must admit: {error}"));
        assert_eq!(transition.disposition(), AdmissionDisposition::Fresh);
        assert_eq!(transition.slice(), decoded.slice());
        assert_eq!(transition.slice().assignments().bindings().len(), 3);
        assert_eq!(
            transition
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_composite
        );
        assert_eq!(
            transition.admitted().request_digest().as_bytes().as_slice(),
            expected_request_digest
        );
        assert_eq!(transition.admitted().deadline().deadline().value(), 60);
        assert_eq!(transition.next_state().tenure_nonce_count(), 1);
        assert_eq!(transition.next_state().request_nonce_count(), 1);
        assert_eq!(transition.next_state().temporal_lineage_count(), 1);
        assert_eq!(initial_state, AdmissionState::for_new_boundary());

        let replay = admission
            .admit_process_execution_request(&wire, transition.next_state(), reading)
            .unwrap_or_else(|error| panic!("exact v4 replay must admit read-only: {error}"));
        assert_eq!(replay.disposition(), AdmissionDisposition::Replayed);
        assert_eq!(replay.next_state(), transition.next_state());
        assert_eq!(replay.slice(), transition.slice());

        let control = ApplyControlState::new(
            SourceScopeRef::from_bytes([0x01; 16]),
            RuntimeHostId::from_bytes([0x05; 16]),
        );
        let fenced = evaluate_writer_fence(&control, transition.admitted(), reading)
            .unwrap_or_else(|error| panic!("v4 request must pass the existing fence: {error}"));
        let prepared = evaluate_prepare(fenced.next_state(), transition.admitted(), None, reading)
            .unwrap_or_else(|error| panic!("v4 request must reach control prepare: {error}"));
        assert_eq!(prepared.disposition(), PrepareDisposition::Prepared);
        assert!(prepared.next_state().prepared().is_some());

        let (_next_admission, admitted, retained_slice) = transition.clone().into_parts();
        assert_eq!(retained_slice, *decoded.slice());
        assert_eq!(admitted.request_digest(), decoded.request_digest());

        let v3 = thread_execution_request_fixture_hex_bytes("outer_wire_hex");
        let error = admission
            .admit_process_execution_request(&v3, &initial_state, reading)
            .unwrap_err();
        assert!(matches!(
            error,
            RuntimeProcessExecutionRequestAdmissionError::RequestWire(error)
                if error.code() == RequestV4WireErrorCode::UnsupportedVersion
        ));
        assert_eq!(initial_state, AdmissionState::for_new_boundary());
    }

    #[test]
    fn v4_tamper_target_auth_cas_and_deadline_reject_before_process_side_effects() {
        let wire = process_execution_request_fixture_hex_bytes("outer_wire_hex");
        let (admission, reading) = python_fixture_admission_and_reading();
        let initial_state = AdmissionState::for_new_boundary();

        let mut execution_tamper = wire.clone();
        let last = execution_tamper
            .last_mut()
            .unwrap_or_else(|| panic!("v4 fixture must be nonempty"));
        *last ^= 1;
        assert!(matches!(
            admission
                .admit_process_execution_request(&execution_tamper, &initial_state, reading)
                .unwrap_err(),
            RuntimeProcessExecutionRequestAdmissionError::RequestWire(_)
        ));
        assert_eq!(initial_state, AdmissionState::for_new_boundary());

        let envelope_len = u32::from_be_bytes([wire[6], wire[7], wire[8], wire[9]]) as usize;
        let mut signature_tamper = wire.clone();
        mutate_tlv(&mut signature_tamper[18..18 + envelope_len], 0x25);
        assert_eq!(
            admission
                .admit_process_execution_request(&signature_tamper, &initial_state, reading)
                .unwrap_err(),
            RuntimeProcessExecutionRequestAdmissionError::Admission(
                AdmissionError::InvalidRequestSignature
            )
        );

        let mut cas_tamper = wire.clone();
        mutate_tlv(&mut cas_tamper[18..18 + envelope_len], 0x16);
        assert!(matches!(
            admission
                .admit_process_execution_request(&cas_tamper, &initial_state, reading)
                .unwrap_err(),
            RuntimeProcessExecutionRequestAdmissionError::RequestWire(_)
        ));

        let (wrong_target_trust, _) = python_fixture_admission_for_target(0x06);
        assert_eq!(
            wrong_target_trust
                .admit_process_execution_request(&wire, &initial_state, reading)
                .unwrap_err(),
            RuntimeProcessExecutionRequestAdmissionError::Admission(
                AdmissionError::UntrustedApplyKey
            )
        );

        let transition = admission
            .admit_process_execution_request(&wire, &initial_state, reading)
            .unwrap_or_else(|error| panic!("baseline v4 fixture must admit: {error}"));
        let wrong_target_control = ApplyControlState::new(
            SourceScopeRef::from_bytes([0x01; 16]),
            RuntimeHostId::from_bytes([0x06; 16]),
        );
        let fenced = evaluate_writer_fence(&wrong_target_control, transition.admitted(), reading)
            .unwrap_or_else(|error| panic!("writer fence is target-neutral: {error}"));
        assert_eq!(
            evaluate_prepare(fenced.next_state(), transition.admitted(), None, reading)
                .unwrap_err(),
            ApplyRejection::TargetMismatch
        );

        let expired_reading = ClockReading::new(
            reading.domain(),
            reading.generation(),
            MonotonicInstant::from_ticks(60),
        );
        let correct_control = ApplyControlState::new(
            SourceScopeRef::from_bytes([0x01; 16]),
            RuntimeHostId::from_bytes([0x05; 16]),
        );
        assert_eq!(
            evaluate_writer_fence(&correct_control, transition.admitted(), expired_reading)
                .unwrap_err(),
            ApplyRejection::DeadlineExpired
        );
        assert_eq!(initial_state, AdmissionState::for_new_boundary());
    }

    #[test]
    fn ledger_capacities_allow_existing_keys_but_reject_each_new_key_class() {
        let fixture = Fixture::default();

        let tenure_bounded = admission_with_limits(100, state_limits(1, 4, 4));
        let Ok(first) = admit(
            &tenure_bounded,
            &fixture,
            &AdmissionState::for_new_boundary(),
            0,
        ) else {
            panic!("first tenure-bounded request must admit");
        };
        let Ok(replay) = admit(&tenure_bounded, &fixture, first.next_state(), 1) else {
            panic!("exact replay must not consume tenure capacity");
        };
        assert_eq!(replay.disposition(), AdmissionDisposition::Replayed);
        assert_eq!(replay.next_state(), first.next_state());
        let mut new_tenure_nonce = fixture.clone();
        new_tenure_nonce.tenure_nonce = b"new-tenure-nonce".to_vec();
        new_tenure_nonce.request_nonce = b"new-tenure-request".to_vec();
        new_tenure_nonce.temporal_id = 20;
        assert_eq!(
            admit(&tenure_bounded, &new_tenure_nonce, first.next_state(), 1,).err(),
            Some(AdmissionError::TenureNonceCapacityExceeded)
        );

        let request_bounded = admission_with_limits(100, state_limits(4, 1, 4));
        let Ok(first) = admit(
            &request_bounded,
            &fixture,
            &AdmissionState::for_new_boundary(),
            0,
        ) else {
            panic!("first request-bounded request must admit");
        };
        let Ok(replay) = admit(&request_bounded, &fixture, first.next_state(), 1) else {
            panic!("exact replay must not consume request capacity");
        };
        assert_eq!(replay.disposition(), AdmissionDisposition::Replayed);
        let mut new_request_nonce = fixture.clone();
        new_request_nonce.request_nonce = b"new-request-nonce".to_vec();
        new_request_nonce.temporal_id = 21;
        assert_eq!(
            admit(&request_bounded, &new_request_nonce, first.next_state(), 1,).err(),
            Some(AdmissionError::RequestNonceCapacityExceeded)
        );

        let temporal_bounded = admission_with_limits(100, state_limits(4, 4, 1));
        let Ok(first) = admit(
            &temporal_bounded,
            &fixture,
            &AdmissionState::for_new_boundary(),
            0,
        ) else {
            panic!("first temporal-bounded request must admit");
        };
        let Ok(replay) = admit(&temporal_bounded, &fixture, first.next_state(), 1) else {
            panic!("exact replay must not consume temporal capacity");
        };
        assert_eq!(replay.disposition(), AdmissionDisposition::Replayed);
        let mut new_temporal_lineage = fixture;
        new_temporal_lineage.request_nonce = b"new-temporal-request".to_vec();
        new_temporal_lineage.temporal_id = 22;
        assert_eq!(
            admit(
                &temporal_bounded,
                &new_temporal_lineage,
                first.next_state(),
                1,
            )
            .err(),
            Some(AdmissionError::TemporalLineageCapacityExceeded)
        );
    }

    #[test]
    fn exact_trust_selectors_fail_closed() {
        let admission = admission(100);
        for mutate in [
            |fixture: &mut Fixture| fixture.authority = 31,
            |fixture: &mut Fixture| fixture.tenure_key = 32,
            |fixture: &mut Fixture| fixture.tenure_algorithm = 2,
            |fixture: &mut Fixture| fixture.tenure_algorithm_version = 2,
            |fixture: &mut Fixture| fixture.scope = 33,
        ] {
            let mut fixture = Fixture::default();
            mutate(&mut fixture);
            assert_eq!(
                admit(&admission, &fixture, &AdmissionState::for_new_boundary(), 0,).err(),
                Some(AdmissionError::UntrustedTenureKey)
            );
        }

        for mutate in [
            |fixture: &mut Fixture| fixture.principal = 41,
            |fixture: &mut Fixture| fixture.writer = 42,
            |fixture: &mut Fixture| fixture.apply_key = 43,
            |fixture: &mut Fixture| fixture.apply_algorithm = 2,
            |fixture: &mut Fixture| fixture.apply_algorithm_version = 2,
            |fixture: &mut Fixture| fixture.target = 44,
        ] {
            let mut fixture = Fixture::default();
            mutate(&mut fixture);
            assert_eq!(
                admit(&admission, &fixture, &AdmissionState::for_new_boundary(), 0,).err(),
                Some(AdmissionError::UntrustedApplyKey)
            );
        }
    }

    #[test]
    fn strict_signatures_and_tampering_fail_closed() {
        let admission = admission(100);

        let wrong_tenure_signer = Fixture {
            tenure_signing_seed: WRONG_SEED,
            ..Fixture::default()
        };
        assert_eq!(
            admit(
                &admission,
                &wrong_tenure_signer,
                &AdmissionState::for_new_boundary(),
                0,
            )
            .err(),
            Some(AdmissionError::InvalidTenureSignature)
        );

        let short_tenure_signature = Fixture {
            tenure_signature_length: 63,
            ..Fixture::default()
        };
        assert_eq!(
            admit(
                &admission,
                &short_tenure_signature,
                &AdmissionState::for_new_boundary(),
                0,
            )
            .err(),
            Some(AdmissionError::InvalidTenureSignatureLength)
        );

        let wrong_request_signer = Fixture {
            request_signing_seed: WRONG_SEED,
            ..Fixture::default()
        };
        assert_eq!(
            admit(
                &admission,
                &wrong_request_signer,
                &AdmissionState::for_new_boundary(),
                0,
            )
            .err(),
            Some(AdmissionError::InvalidRequestSignature)
        );

        let short_request_signature = Fixture {
            request_signature_length: 63,
            ..Fixture::default()
        };
        assert_eq!(
            admit(
                &admission,
                &short_request_signature,
                &AdmissionState::for_new_boundary(),
                0,
            )
            .err(),
            Some(AdmissionError::InvalidRequestSignatureLength)
        );

        let fixture = Fixture::default();
        let mut proof_tamper = fixture.envelope().canonical_wire().to_vec();
        mutate_tlv(&mut proof_tamper, 20);
        let Some(AdmissionError::Wire(proof_wire_error)) = admission
            .admit(
                &proof_tamper,
                &AdmissionState::for_new_boundary(),
                fixture.reading(0),
            )
            .err()
        else {
            panic!("proof tamper must fail during canonical decoding");
        };
        assert_eq!(
            proof_wire_error.code(),
            WireErrorCode::DerivedDigestMismatch
        );

        let mut request_tamper = fixture.envelope().canonical_wire().to_vec();
        mutate_tlv(&mut request_tamper, 37);
        assert_eq!(
            admission
                .admit(
                    &request_tamper,
                    &AdmissionState::for_new_boundary(),
                    fixture.reading(0),
                )
                .err(),
            Some(AdmissionError::InvalidRequestSignature)
        );
    }

    #[test]
    fn wire_size_and_version_reject_before_trust_or_crypto() {
        let admission = admission(100);
        let fixture = Fixture::default();
        let oversized = vec![0; MAX_RUNTIME_APPLY_ENVELOPE_BYTES + 1];
        let Some(AdmissionError::Wire(oversized_error)) = admission
            .admit(
                &oversized,
                &AdmissionState::for_new_boundary(),
                fixture.reading(0),
            )
            .err()
        else {
            panic!("oversized frame must fail in canonical decoding");
        };
        assert_eq!(oversized_error.code(), WireErrorCode::FrameTooLarge);

        let mut unsupported_version = fixture.envelope().canonical_wire().to_vec();
        let version_offset = b"ParaEGOX\0runtime-apply-envelope".len();
        unsupported_version[version_offset + 1] = 2;
        let Some(AdmissionError::Wire(version_error)) = admission
            .admit(
                &unsupported_version,
                &AdmissionState::for_new_boundary(),
                fixture.reading(0),
            )
            .err()
        else {
            panic!("unsupported version must fail in canonical decoding");
        };
        assert_eq!(version_error.code(), WireErrorCode::UnsupportedVersion);
    }

    #[test]
    fn tenure_and_request_nonce_ledgers_distinguish_replay_from_conflict() {
        let fixture = Fixture::default();
        let admission = admission(100);
        let Ok(first) = admit(&admission, &fixture, &AdmissionState::for_new_boundary(), 0) else {
            panic!("first request must admit");
        };

        let mut request_conflict = fixture.clone();
        request_conflict.operation = 21;
        request_conflict.temporal_id = 22;
        assert_eq!(
            admit(&admission, &request_conflict, first.next_state(), 1).err(),
            Some(AdmissionError::RequestNonceConflict)
        );

        let mut tenure_conflict = fixture;
        tenure_conflict.epoch = 2;
        tenure_conflict.supersedes = 1;
        tenure_conflict.operation = 23;
        tenure_conflict.request_nonce = b"request-three".to_vec();
        tenure_conflict.temporal_id = 24;
        assert_eq!(
            admit(&admission, &tenure_conflict, first.next_state(), 1).err(),
            Some(AdmissionError::TenureNonceConflict)
        );
    }

    #[test]
    fn temporal_policy_clock_and_overflow_checks_fail_closed() {
        let admission = admission(100);

        let expired = Fixture {
            remaining_budget: 0,
            ..Fixture::default()
        };
        assert_eq!(
            admit(&admission, &expired, &AdmissionState::for_new_boundary(), 0,).err(),
            Some(AdmissionError::BudgetExpired)
        );

        let oversized = Fixture {
            original_budget: 101,
            ..Fixture::default()
        };
        assert_eq!(
            admit(
                &admission,
                &oversized,
                &AdmissionState::for_new_boundary(),
                0,
            )
            .err(),
            Some(AdmissionError::BudgetExceedsPolicy)
        );

        let fixture = Fixture::default();
        let Ok(other_generation) = ClockGeneration::try_new(2) else {
            panic!("test clock generation must be valid");
        };
        let wrong_domain = ClockReading::new(
            ClockDomainRef::from_bytes([99; 16]),
            fixture.reading(0).generation(),
            MonotonicInstant::from_ticks(0),
        );
        let wrong_generation = ClockReading::new(
            fixture.reading(0).domain(),
            other_generation,
            MonotonicInstant::from_ticks(0),
        );
        let envelope = fixture.envelope();
        assert_eq!(
            admission
                .admit(
                    envelope.canonical_wire(),
                    &AdmissionState::for_new_boundary(),
                    wrong_domain,
                )
                .err(),
            Some(AdmissionError::ClockDomainMismatch)
        );
        assert_eq!(
            admission
                .admit(
                    envelope.canonical_wire(),
                    &AdmissionState::for_new_boundary(),
                    wrong_generation,
                )
                .err(),
            Some(AdmissionError::ClockGenerationMismatch)
        );
        assert_eq!(
            admit(
                &admission,
                &fixture,
                &AdmissionState::for_new_boundary(),
                u64::MAX - 49,
            )
            .err(),
            Some(AdmissionError::DeadlineOverflow)
        );
    }

    #[test]
    fn temporal_lineage_attenuates_without_extension_or_replay_renewal() {
        let fixture = Fixture::default();
        let admission = admission(100);
        let Ok(first) = admit(&admission, &fixture, &AdmissionState::for_new_boundary(), 0) else {
            panic!("first temporal lineage request must admit");
        };
        assert_eq!(first.admitted().deadline().deadline().value(), 50);

        let mut extension = fixture.clone();
        extension.operation = 31;
        extension.request_nonce = b"extension-request".to_vec();
        extension.remaining_budget = 51;
        assert_eq!(
            admit(&admission, &extension, first.next_state(), 1).err(),
            Some(AdmissionError::BudgetExtended)
        );

        let mut lineage_conflict = fixture.clone();
        lineage_conflict.operation = 32;
        lineage_conflict.request_nonce = b"lineage-conflict".to_vec();
        lineage_conflict.original_budget = 90;
        lineage_conflict.remaining_budget = 40;
        assert_eq!(
            admit(&admission, &lineage_conflict, first.next_state(), 1).err(),
            Some(AdmissionError::TemporalLineageConflict)
        );

        let mut attenuated = fixture.clone();
        attenuated.operation = 33;
        attenuated.request_nonce = b"attenuated-request".to_vec();
        attenuated.remaining_budget = 40;
        let Ok(second) = admit(&admission, &attenuated, first.next_state(), 20) else {
            panic!("lower remaining budget must admit");
        };
        assert_eq!(second.admitted().deadline().deadline().value(), 50);

        let Ok(replay) = admit(&admission, &attenuated, second.next_state(), 30) else {
            panic!("live attenuated request must replay");
        };
        assert_eq!(replay.disposition(), AdmissionDisposition::Replayed);
        assert_eq!(replay.admitted().deadline().deadline().value(), 50);
        let Ok(expired_replay) = admit(&admission, &attenuated, replay.next_state(), 50) else {
            panic!("expired exact replay must remain queryable without renewal");
        };
        assert_eq!(expired_replay.disposition(), AdmissionDisposition::Replayed);
        assert_eq!(expired_replay.admitted().deadline().deadline().value(), 50);
        assert_eq!(expired_replay.next_state(), replay.next_state());

        let Ok(earlier_request_replay) =
            admit(&admission, &fixture, expired_replay.next_state(), 50)
        else {
            panic!("earlier exact request must remain queryable after lineage attenuation");
        };
        assert_eq!(
            earlier_request_replay.disposition(),
            AdmissionDisposition::Replayed
        );
        assert_eq!(
            earlier_request_replay
                .admitted()
                .deadline()
                .deadline()
                .value(),
            50
        );
        assert_eq!(
            earlier_request_replay.next_state(),
            expired_replay.next_state()
        );

        let mut changed_nonce = attenuated.clone();
        changed_nonce.operation = 34;
        changed_nonce.request_nonce = b"post-expiry-request".to_vec();
        assert_eq!(
            admit(&admission, &changed_nonce, expired_replay.next_state(), 50,).err(),
            Some(AdmissionError::BudgetExpired)
        );

        let mut changed_lineage = attenuated;
        changed_lineage.operation = 35;
        changed_lineage.temporal_id = 55;
        assert_eq!(
            admit(
                &admission,
                &changed_lineage,
                expired_replay.next_state(),
                50,
            )
            .err(),
            Some(AdmissionError::RequestNonceConflict)
        );
    }

    #[test]
    fn expired_exact_replay_reaches_read_only_reducer_replay_but_cannot_change_state() {
        let fixture = Fixture::default();
        let admission = admission_with_limits(100, state_limits(1, 1, 1));
        let Ok(first_admission) =
            admit(&admission, &fixture, &AdmissionState::for_new_boundary(), 0)
        else {
            panic!("initial request must admit");
        };
        let control_state = ApplyControlState::new(
            SourceScopeRef::from_bytes([SCOPE; 16]),
            RuntimeHostId::from_bytes([TARGET; 16]),
        );
        let Ok(fence) = evaluate_writer_fence(
            &control_state,
            first_admission.admitted(),
            fixture.reading(0),
        ) else {
            panic!("initial admitted request must establish its fence");
        };
        let Ok(preparation) = evaluate_prepare(
            fence.next_state(),
            first_admission.admitted(),
            None,
            fixture.reading(0),
        ) else {
            panic!("initial admitted request must prepare");
        };
        let prior_operation = preparation.operation();

        let Ok(expired_replay) = admit(&admission, &fixture, first_admission.next_state(), 50)
        else {
            panic!("expired exact replay must pass authentication admission");
        };
        assert_eq!(expired_replay.disposition(), AdmissionDisposition::Replayed);
        assert_eq!(expired_replay.admitted().deadline().deadline().value(), 50);
        assert_eq!(expired_replay.next_state(), first_admission.next_state());

        let Ok(fence_replay) = evaluate_writer_fence(
            preparation.next_state(),
            expired_replay.admitted(),
            fixture.reading(50),
        ) else {
            panic!("same durable fence must remain queryable after expiry");
        };
        assert_eq!(fence_replay.disposition(), FenceDisposition::Kept);
        assert_eq!(fence_replay.next_state(), preparation.next_state());

        let Ok(read_only_replay) = evaluate_prepare(
            fence_replay.next_state(),
            expired_replay.admitted(),
            Some(&prior_operation),
            fixture.reading(50),
        ) else {
            panic!("prior operation must remain queryable after expiry");
        };
        assert_eq!(
            read_only_replay.disposition(),
            PrepareDisposition::Replayed(OperationPhase::Prepared)
        );
        assert_eq!(read_only_replay.next_state(), fence_replay.next_state());
        assert_eq!(
            evaluate_prepare(
                fence_replay.next_state(),
                expired_replay.admitted(),
                None,
                fixture.reading(50),
            )
            .err(),
            Some(ApplyRejection::DeadlineExpired)
        );
    }

    #[test]
    fn reducer_uses_complete_s2_digest_for_same_operation_conflicts() {
        let fixture = Fixture::default();
        let admission = admission(100);
        let Ok(first_admission) =
            admit(&admission, &fixture, &AdmissionState::for_new_boundary(), 0)
        else {
            panic!("first request must admit");
        };
        let control_state = ApplyControlState::new(
            SourceScopeRef::from_bytes([SCOPE; 16]),
            RuntimeHostId::from_bytes([TARGET; 16]),
        );
        let Ok(fence) = evaluate_writer_fence(
            &control_state,
            first_admission.admitted(),
            fixture.reading(0),
        ) else {
            panic!("admitted request must fence");
        };
        let Ok(preparation) = evaluate_prepare(
            fence.next_state(),
            first_admission.admitted(),
            None,
            fixture.reading(0),
        ) else {
            panic!("admitted request must prepare");
        };
        let operation = preparation.operation();

        let mut changed_auth = fixture;
        changed_auth.request_nonce = b"different-auth".to_vec();
        changed_auth.temporal_id = 77;
        let Ok(second_admission) =
            admit(&admission, &changed_auth, first_admission.next_state(), 1)
        else {
            panic!("second independently authenticated request must admit");
        };
        assert_eq!(
            first_admission.admitted().payload().commitment_digest(),
            second_admission.admitted().payload().commitment_digest()
        );
        assert_ne!(
            first_admission.admitted().request_digest(),
            second_admission.admitted().request_digest()
        );
        assert_eq!(
            evaluate_prepare(
                preparation.next_state(),
                second_admission.admitted(),
                Some(&operation),
                changed_auth.reading(1),
            )
            .err(),
            Some(ApplyRejection::OperationConflict)
        );
    }
}
