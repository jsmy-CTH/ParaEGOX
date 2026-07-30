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
use paraegox_runtime_contracts::provenance::SourceScopeRef;
use paraegox_runtime_contracts::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
use paraegox_runtime_contracts::wire::{
    ApplyAuthAlgorithm, ApplyAuthKeyRef, EnvelopeContractError, RuntimeApplyEnvelope, WireError,
};

use crate::apply_state::{AdmittedApply, VerifiedWriterTenure};

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
    verifying_key: VerifyingKey,
}

impl TrustedTenureKey {
    /// Builds one exact scope/authority/key/algorithm binding.
    pub fn try_new(
        source_scope: SourceScopeRef,
        authority: TenureAuthorityRef,
        key: TenureKeyRef,
        algorithm: TenureProofAlgorithm,
        algorithm_version: u16,
        verifying_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, AdmissionConfigurationError> {
        ensure_ed25519_profile(algorithm.value(), algorithm_version)?;
        Ok(Self {
            selector: TenureTrustSelector {
                source_scope,
                authority,
                key,
                algorithm,
                algorithm_version,
            },
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
    tenure_keys: BTreeMap<TenureTrustSelector, VerifyingKey>,
    apply_keys: BTreeMap<ApplyTrustSelector, VerifyingKey>,
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
                .insert(trusted.selector, trusted.verifying_key)
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

    /// Decodes, authenticates, and installs one canonical frame without side effects.
    pub fn admit(
        &self,
        frame: &[u8],
        state: &AdmissionState,
        reading: ClockReading,
    ) -> Result<AdmissionTransition, AdmissionError> {
        let envelope = RuntimeApplyEnvelope::decode(frame)?;
        self.admit_envelope(envelope, state, reading)
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
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
    };
    use paraegox_runtime_contracts::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
        MAX_RUNTIME_APPLY_ENVELOPE_BYTES, RuntimeApplyEnvelope, RuntimeApplyEnvelopeDraft,
        WireErrorCode,
    };

    use crate::apply_state::{
        ApplyControlState, ApplyRejection, FenceDisposition, OperationPhase, PrepareDisposition,
        evaluate_prepare, evaluate_writer_fence,
    };

    use super::{
        AdmissionConfigurationError, AdmissionDisposition, AdmissionError, AdmissionState,
        AdmissionStateLimits, ApplyAdmission, ApplyAdmissionPolicy, ED25519_ALGORITHM,
        ED25519_ALGORITHM_VERSION, TrustedApplyIdentity, TrustedApplyKey, TrustedTenureKey,
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
    // TEST-ONLY keys matching the independently encoded Python contract fixture.
    const PYTHON_FIXTURE_TENURE_SEED: [u8; 32] = [0x11; 32];
    const PYTHON_FIXTURE_REQUEST_SEED: [u8; 32] = [0x22; 32];

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
            let header = RuntimeSliceHeader::new(
                target,
                provenance,
                TargetAssignmentDigest::new(Digest32::from_bytes([22; 32])),
            );
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
            SourceScopeRef::from_bytes([SCOPE; 16]),
            TenureAuthorityRef::from_bytes([AUTHORITY; 16]),
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
        let marker = format!("\"{field}\": \"");
        let Some((_, tail)) = PYTHON_SIGNED_FIXTURE_JSON.split_once(marker.as_str()) else {
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
                SourceScopeRef::from_bytes([SCOPE; 16]),
                TenureAuthorityRef::from_bytes([AUTHORITY; 16]),
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
                SourceScopeRef::from_bytes([SCOPE; 16]),
                TenureAuthorityRef::from_bytes([AUTHORITY; 16]),
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
        let scope = SourceScopeRef::from_bytes([0x01; 16]);
        let target = RuntimeHostId::from_bytes([0x05; 16]);
        let writer = PlanWriterRef::from_bytes([0x09; 16]);
        let principal = PrincipalRef::from_bytes([0x09; 16]);

        let tenure_verifying_key = SigningKey::from_bytes(&PYTHON_FIXTURE_TENURE_SEED)
            .verifying_key()
            .to_bytes();
        let Ok(tenure_trust) = TrustedTenureKey::try_new(
            scope,
            TenureAuthorityRef::from_bytes([0x07; 16]),
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

        let admission = ApplyAdmission::new(policy);
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
