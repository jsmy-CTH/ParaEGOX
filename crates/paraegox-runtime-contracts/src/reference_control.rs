//! Public S7-E/S7-F control facade for the narrow reference Runtime profile.
//!
//! This module promotes only the canonical `PXTE` v4 / `PXAR` v5 apply path
//! and authenticated bootstrap/query/terminal-Receipt paths owned by the
//! crate-private reference assembly codec. It does not accept a raw manifest
//! constructor, verify signatures, or perform Runtime mutation. Signature
//! verifiers consume the exact transcripts and authentication facts exposed
//! here.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

use crate::apply::{
    ApplyContractError, ApplyOperationId, PlanWriterRef, RuntimeApplyControl,
    RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef,
};
use crate::assignment::InstanceRef;
use crate::execution::{CardDefinitionRef, CardImplementationRef, DomainRef};
use crate::installation::{
    RuntimeCompiledInstallationFactsV1, RuntimeInstallationError, VerifiedRuntimeInstallationV1,
    VerifiedRuntimeManifestIngressV1,
};
use crate::provenance::{
    PlanProvenance, ProvenanceContractError, RuntimeSliceCommitment, RuntimeSliceHeader,
    SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest, TargetSliceDigest,
};
use crate::reference_assembly::{
    APPLY_REQUEST_SIGNING_TRANSCRIPT_V2_VERSION, APPLY_TERMINAL_RECEIPT_SIGNING_TRANSCRIPT_VERSION,
    ApplyRequestSigningTranscriptV2, ApplyTerminalReceiptSigningTranscriptV1, BootstrapRequestId,
    CONTROL_READ_SIGNING_TRANSCRIPT_VERSION, ControlReadSigningTranscriptV1, FixtureExportRef,
    LOCAL_CONTROL_CHANNEL_BINDING_VERSION, MAX_APPLY_AUTH_NONCE_V2_BYTES,
    MAX_APPLY_AUTH_SIGNATURE_V2_BYTES, MAX_CONTROL_READ_NONCE_BYTES,
    MAX_CONTROL_READ_SIGNATURE_BYTES, MAX_QUERY_RECORD_COUNT, MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS,
    MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES, MAX_RUNTIME_APPLY_REQUEST_V5_BYTES,
    MAX_RUNTIME_APPLY_TERMINAL_RECEIPT_BYTES, MAX_RUNTIME_BOOTSTRAP_REQUEST_BYTES,
    MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES, MAX_RUNTIME_PLAN_SLICE_V5_BYTES,
    MAX_RUNTIME_QUERY_REQUEST_BYTES, MAX_RUNTIME_QUERY_RESPONSE_BYTES,
    MAX_TARGET_EXECUTION_PLAN_V4_BYTES, OperationalReasonV1 as CanonicalOperationalReasonV1,
    REFERENCE_ASSEMBLY_PROFILE_VERSION, REFERENCE_BACKGROUND_TASK_SLOTS, REFERENCE_DISPATCH_SLOTS,
    REFERENCE_LIFECYCLE_CONCURRENCY, REFERENCE_MAILBOX_SLOTS, RUNTIME_APPLY_ENVELOPE_V2_VERSION,
    RUNTIME_APPLY_REQUEST_V5_VERSION, RUNTIME_APPLY_TERMINAL_RECEIPT_VERSION,
    RUNTIME_BOOTSTRAP_PROTOCOL_VERSION, RUNTIME_QUERY_PROTOCOL_VERSION,
    ReferenceAssemblyModeV1 as CanonicalAssemblyModeV1, ReferenceContractError,
    ReferenceFixtureEntryV1, ReferenceLoopDomainSpecV1, ReferenceLoopSubjectSpecV1,
    ReferenceWireError, ReferenceWireErrorCode, RuntimeApplyEnvelopeV2Draft, RuntimeApplyRequestV5,
    RuntimeApplyTerminalFactsV1 as CanonicalApplyTerminalFactsV1,
    RuntimeApplyTerminalHeadV1 as CanonicalApplyTerminalHeadV1,
    RuntimeApplyTerminalLifecycleEffectV1 as CanonicalApplyTerminalLifecycleEffectV1,
    RuntimeApplyTerminalOutcomeV1 as CanonicalApplyTerminalOutcomeV1,
    RuntimeApplyTerminalReceiptDraftV1 as CanonicalApplyTerminalReceiptDraftV1,
    RuntimeApplyTerminalReceiptV1 as CanonicalApplyTerminalReceiptV1,
    RuntimeArtifactCompatibilityManifestProjectionV1, RuntimeArtifactCompatibilityManifestV1,
    RuntimeBootstrapCompatibilityV1 as CanonicalBootstrapCompatibilityV1,
    RuntimeBootstrapFactsV1 as CanonicalBootstrapFactsV1, RuntimeBootstrapRequestDraftV1,
    RuntimeBootstrapRequestV1 as CanonicalBootstrapRequestV1,
    RuntimeBootstrapResponseDraftV1 as CanonicalBootstrapResponseDraftV1,
    RuntimeBootstrapResponseV1 as CanonicalBootstrapResponseV1,
    RuntimeBootstrapServingIdentityV1 as CanonicalBootstrapServingIdentityV1,
    RuntimeBootstrapStateV1 as CanonicalBootstrapStateV1, RuntimeBuildDescriptorV1,
    RuntimeBuildIdentityV1, RuntimeChannelBindingV1 as CanonicalChannelBindingV1,
    RuntimeDesiredHeadV1 as CanonicalDesiredHeadV1,
    RuntimeDesiredStateV1 as CanonicalDesiredStateV1, RuntimeHostEpoch,
    RuntimeLiveFactsV1 as CanonicalLiveFactsV1, RuntimeLiveStateV1 as CanonicalLiveStateV1,
    RuntimeOperationDurablePhaseV1 as CanonicalOperationDurablePhaseV1,
    RuntimeOperationLookupV1 as CanonicalOperationLookupV1,
    RuntimeOwnerStateV1 as CanonicalOwnerStateV1, RuntimePlanSliceV5,
    RuntimeQueryFactsV1 as CanonicalQueryFactsV1, RuntimeQueryId,
    RuntimeQueryOperationStateV1 as CanonicalQueryOperationStateV1,
    RuntimeQueryRequestDraftV1 as CanonicalQueryRequestDraftV1,
    RuntimeQueryRequestV1 as CanonicalQueryRequestV1,
    RuntimeQueryResponseDraftV1 as CanonicalQueryResponseDraftV1,
    RuntimeQueryResponseV1 as CanonicalQueryResponseV1,
    RuntimeQuerySelectorV1 as CanonicalQuerySelectorV1, RuntimeResponseAuthClaimV1,
    RuntimeSnapshotSequence, RuntimeStoreInstanceId, TARGET_EXECUTION_PLAN_V4_VERSION,
    TargetExecutionPlanV4 as CanonicalTargetExecutionPlanV4, TargetPlanAssignmentsV5,
    TerminalResultRef, reference_profile_fingerprint,
};
use crate::temporal::ApplyTemporalConstraint;
use crate::wire::{
    ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, ApplyRequestAuthentication,
};

const ED25519_CONTROL_KEY_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.runtime.control-auth.ed25519-public-key.sha256.v1";
const LOCAL_CONTROL_ENDPOINT_IDENTITY_DOMAIN: &[u8] =
    b"paraegox.runtime.bootstrap-endpoint-identity.sha256.v1";
const RUNTIME_PEER_CREDENTIALS_DOMAIN: &[u8] =
    b"paraegox.runtime.bootstrap-peer-credentials.sha256.v1";
const BOOTSTRAP_CHANNEL_POLICY_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.runtime.bootstrap-channel-policy.sha256.v1";
const REFERENCE_ADMISSION_POLICY_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.runtime.apply-admission-policy.sha256.v1";
const REFERENCE_APPLY_TENURE_NONCE_IDENTITY_DOMAIN: &[u8] =
    b"paraegox.runtime.reference-apply.tenure-nonce-identity.sha256.v1";
const REFERENCE_APPLY_REQUEST_NONCE_IDENTITY_DOMAIN: &[u8] =
    b"paraegox.runtime.reference-apply.request-nonce-identity.sha256.v1";
const REFERENCE_APPLY_TEMPORAL_LINEAGE_DOMAIN: &[u8] =
    b"paraegox.runtime.reference-apply.temporal-lineage.sha256.v1";
const REFERENCE_ADMISSION_ED25519_ALGORITHM: u16 = 1;
const REFERENCE_ADMISSION_ED25519_ALGORITHM_VERSION: u16 = 1;
const REFERENCE_CONTROL_SOCKET_DIRECTORY_MODE: u32 = 0o2750;
const REFERENCE_CONTROL_SOCKET_MODE: u32 = 0o660;

/// Canonical PXTE version exposed by this facade.
pub const REFERENCE_TARGET_EXECUTION_VERSION: u16 = TARGET_EXECUTION_PLAN_V4_VERSION;
/// Canonical PXAR version exposed by this facade.
pub const REFERENCE_RUNTIME_APPLY_REQUEST_VERSION: u16 = RUNTIME_APPLY_REQUEST_V5_VERSION;
/// Canonical signed apply-envelope version carried by PXAR v5.
pub const REFERENCE_RUNTIME_APPLY_ENVELOPE_VERSION: u16 = RUNTIME_APPLY_ENVELOPE_V2_VERSION;
/// Canonical apply signing-transcript version.
pub const REFERENCE_APPLY_SIGNING_TRANSCRIPT_VERSION: u16 =
    APPLY_REQUEST_SIGNING_TRANSCRIPT_V2_VERSION;
/// Canonical authenticated bootstrap protocol version.
pub const REFERENCE_BOOTSTRAP_VERSION: u16 = RUNTIME_BOOTSTRAP_PROTOCOL_VERSION;
/// Canonical bootstrap signing-transcript version.
pub const REFERENCE_BOOTSTRAP_SIGNING_TRANSCRIPT_VERSION: u16 =
    CONTROL_READ_SIGNING_TRANSCRIPT_VERSION;
/// Canonical authenticated operation/live query protocol version.
pub const REFERENCE_QUERY_VERSION: u16 = RUNTIME_QUERY_PROTOCOL_VERSION;
/// Canonical query request/response signing-transcript version.
pub const REFERENCE_QUERY_SIGNING_TRANSCRIPT_VERSION: u16 = CONTROL_READ_SIGNING_TRANSCRIPT_VERSION;
/// Canonical Runtime apply terminal Receipt version.
pub const REFERENCE_APPLY_TERMINAL_RECEIPT_VERSION: u16 = RUNTIME_APPLY_TERMINAL_RECEIPT_VERSION;
/// Canonical Runtime apply terminal Receipt signing-transcript version.
pub const REFERENCE_APPLY_TERMINAL_RECEIPT_SIGNING_TRANSCRIPT_VERSION: u16 =
    APPLY_TERMINAL_RECEIPT_SIGNING_TRANSCRIPT_VERSION;
/// Canonical reference assembly profile version.
pub const REFERENCE_PROFILE_VERSION: u16 = REFERENCE_ASSEMBLY_PROFILE_VERSION;

/// Maximum canonical PXTE v4 body size.
pub const MAX_REFERENCE_TARGET_EXECUTION_BYTES: usize = MAX_TARGET_EXECUTION_PLAN_V4_BYTES;
/// Maximum canonical PXAR v5 request size.
pub const MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES: usize = MAX_RUNTIME_APPLY_REQUEST_V5_BYTES;
/// Maximum canonical durable `PXTA-zero || PXTE-v4` Slice body size.
pub const MAX_REFERENCE_RUNTIME_PLAN_SLICE_BYTES: usize = MAX_RUNTIME_PLAN_SLICE_V5_BYTES;
/// Maximum canonical apply-envelope v2 size.
pub const MAX_REFERENCE_RUNTIME_APPLY_ENVELOPE_BYTES: usize = MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES;
/// Maximum apply authentication nonce size.
pub const MAX_REFERENCE_APPLY_AUTH_NONCE_BYTES: usize = MAX_APPLY_AUTH_NONCE_V2_BYTES;
/// Maximum apply authentication signature size.
pub const MAX_REFERENCE_APPLY_AUTH_SIGNATURE_BYTES: usize = MAX_APPLY_AUTH_SIGNATURE_V2_BYTES;
/// Maximum bootstrap request size.
pub const MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES: usize = MAX_RUNTIME_BOOTSTRAP_REQUEST_BYTES;
/// Maximum bootstrap response size.
pub const MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES: usize = MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES;
/// Maximum canonical query request size.
pub const MAX_REFERENCE_QUERY_REQUEST_BYTES: usize = MAX_RUNTIME_QUERY_REQUEST_BYTES;
/// Maximum canonical query response size.
pub const MAX_REFERENCE_QUERY_RESPONSE_BYTES: usize = MAX_RUNTIME_QUERY_RESPONSE_BYTES;
/// Maximum query request/response nonce size.
pub const MAX_REFERENCE_QUERY_NONCE_BYTES: usize = MAX_CONTROL_READ_NONCE_BYTES;
/// Maximum query request/response signature size.
pub const MAX_REFERENCE_QUERY_SIGNATURE_BYTES: usize = MAX_CONTROL_READ_SIGNATURE_BYTES;
/// The fixed singleton operation record count carried by PXQR v1.
pub const REFERENCE_QUERY_RECORD_COUNT: u16 = MAX_QUERY_RECORD_COUNT;
/// Maximum bootstrap authentication nonce size.
pub const MAX_REFERENCE_BOOTSTRAP_NONCE_BYTES: usize = MAX_CONTROL_READ_NONCE_BYTES;
/// Maximum bootstrap authentication signature size.
pub const MAX_REFERENCE_BOOTSTRAP_SIGNATURE_BYTES: usize = MAX_CONTROL_READ_SIGNATURE_BYTES;
/// Maximum canonical Runtime apply terminal Receipt size.
pub const MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES: usize =
    MAX_RUNTIME_APPLY_TERMINAL_RECEIPT_BYTES;
/// Maximum Runtime apply terminal Receipt signature size.
pub const MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_SIGNATURE_BYTES: usize =
    MAX_CONTROL_READ_SIGNATURE_BYTES;
/// Maximum lifecycle budget in nanoseconds selected by the canonical owner.
pub const MAX_REFERENCE_LIFECYCLE_NANOS: u64 = MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS;
/// Fixed retained writer-tenure nonce capacity of the reference Runtime.
pub const REFERENCE_ADMISSION_TENURE_NONCE_CAPACITY: usize = 256;
/// Fixed retained apply-request nonce capacity of the reference Runtime.
pub const REFERENCE_ADMISSION_REQUEST_NONCE_CAPACITY: usize = 256;
/// Fixed retained temporal-lineage capacity of the reference Runtime.
pub const REFERENCE_ADMISSION_TEMPORAL_LINEAGE_CAPACITY: usize = 256;
/// Fixed lifecycle concurrency of the reference profile.
pub const REFERENCE_PROFILE_LIFECYCLE_CONCURRENCY: u16 = REFERENCE_LIFECYCLE_CONCURRENCY;
/// Fixed mailbox slots of the source-only reference profile.
pub const REFERENCE_PROFILE_MAILBOX_SLOTS: u16 = REFERENCE_MAILBOX_SLOTS;
/// Fixed dispatch slots of the source-only reference profile.
pub const REFERENCE_PROFILE_DISPATCH_SLOTS: u16 = REFERENCE_DISPATCH_SLOTS;
/// Fixed background-task slots of the source-only reference profile.
pub const REFERENCE_PROFILE_BACKGROUND_TASK_SLOTS: u16 = REFERENCE_BACKGROUND_TASK_SLOTS;
/// Canonical local-control channel binding version.
pub const REFERENCE_CHANNEL_BINDING_VERSION: u16 = LOCAL_CONTROL_CHANNEL_BINDING_VERSION;

/// Canonically fingerprints one already validated Ed25519 control public key.
///
/// The caller remains responsible for reading exactly 32 bytes from its pinned
/// key file and validating that they encode an admitted Ed25519 verification
/// key. Controller request-auth and Runtime response-auth use this same domain;
/// writer-tenure key fingerprints deliberately use a different owner/domain.
pub fn ed25519_control_key_fingerprint(
    public_key: &[u8; 32],
) -> Result<Digest32, ReferenceControlError> {
    let mut builder = Digest32Builder::try_new(ED25519_CONTROL_KEY_FINGERPRINT_DOMAIN)?;
    builder.field_u16(1)?;
    builder.field_bytes(b"Ed25519")?;
    builder.field_bytes(public_key)?;
    Ok(builder.finish())
}

/// Exact one-Authority/one-Controller admission trust selected by the profile.
///
/// Limits and algorithm selectors are deliberately absent: this contract owns
/// their fixed reference-profile values. Both Runtime and Controller derive the
/// same sealed token from protected key material and independently owned target
/// and scope truth instead of accepting a caller-supplied digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceAdmissionPolicyInputV1<'a> {
    /// Runtime target admitted by the Controller apply key.
    pub target: RuntimeHostId,
    /// Source scope shared by the tenure and apply trust bindings.
    pub source_scope: crate::provenance::SourceScopeRef,
    /// Exact source-plan writer admitted by the apply binding.
    pub writer: PlanWriterRef,
    /// Controller principal admitted to sign apply requests.
    pub controller_principal: PrincipalRef,
    /// Controller request/apply verification-key selector.
    pub controller_key_ref: ApplyAuthKeyRef,
    /// Exact Controller Ed25519 public key bytes.
    pub controller_public_key: &'a [u8; 32],
    /// Tenure Authority service principal.
    pub authority_principal: PrincipalRef,
    /// Tenure Authority effective uid.
    pub authority_uid: u32,
    /// Tenure Authority effective gid.
    pub authority_gid: u32,
    /// Tenure Authority protocol reference.
    pub tenure_authority_ref: TenureAuthorityRef,
    /// Tenure verification-key selector.
    pub tenure_key_ref: TenureKeyRef,
    /// Exact Tenure Authority Ed25519 public key bytes.
    pub tenure_public_key: &'a [u8; 32],
}

/// Sealed commitment to the exact reference Runtime admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceAdmissionPolicyFingerprintV1(Digest32);

impl ReferenceAdmissionPolicyFingerprintV1 {
    /// Returns the contract-owned commitment for durable comparison/pinning.
    #[must_use]
    pub const fn digest(self) -> Digest32 {
        self.0
    }
}

/// Derives the exact admission-policy commitment used by the reference Runtime.
///
/// The digest layout intentionally equals `ApplyAdmissionPolicy::fingerprint`
/// for the profile's singleton tenure/apply trust sets. Its lifecycle ceiling,
/// all three durable-ledger capacities, Ed25519 algorithm/version and trust-set
/// cardinalities are fixed here rather than repeated by either process.
pub fn reference_admission_policy_fingerprint_v1(
    input: ReferenceAdmissionPolicyInputV1<'_>,
) -> Result<ReferenceAdmissionPolicyFingerprintV1, ReferenceControlError> {
    if control_bytes_are_zero(input.target.as_bytes())
        || control_bytes_are_zero(input.source_scope.as_bytes())
        || control_bytes_are_zero(input.writer.as_bytes())
        || control_bytes_are_zero(input.controller_principal.as_bytes())
        || control_bytes_are_zero(input.controller_key_ref.as_bytes())
        || control_bytes_are_zero(input.controller_public_key)
        || control_bytes_are_zero(input.authority_principal.as_bytes())
        || input.authority_uid == 0
        || input.authority_gid == 0
        || control_bytes_are_zero(input.tenure_authority_ref.as_bytes())
        || control_bytes_are_zero(input.tenure_key_ref.as_bytes())
        || control_bytes_are_zero(input.tenure_public_key)
        || input.controller_principal == input.authority_principal
        || input.controller_public_key == input.tenure_public_key
    {
        return Err(ReferenceControlError::Contract(
            ReferenceControlContractErrorCode::InvalidAdmissionPolicy,
        ));
    }
    let trust_refs = [
        input.controller_key_ref.as_bytes(),
        input.tenure_authority_ref.as_bytes(),
        input.tenure_key_ref.as_bytes(),
    ];
    if trust_refs
        .iter()
        .enumerate()
        .any(|(index, reference)| trust_refs[index + 1..].contains(reference))
    {
        return Err(ReferenceControlError::Contract(
            ReferenceControlContractErrorCode::InvalidAdmissionPolicy,
        ));
    }

    let mut builder = Digest32Builder::try_new(REFERENCE_ADMISSION_POLICY_FINGERPRINT_DOMAIN)?;
    builder.field_u16(REFERENCE_ADMISSION_ED25519_ALGORITHM_VERSION)?;
    builder.field_u64(MAX_REFERENCE_LIFECYCLE_NANOS)?;
    builder.field_u64(REFERENCE_ADMISSION_TENURE_NONCE_CAPACITY as u64)?;
    builder.field_u64(REFERENCE_ADMISSION_REQUEST_NONCE_CAPACITY as u64)?;
    builder.field_u64(REFERENCE_ADMISSION_TEMPORAL_LINEAGE_CAPACITY as u64)?;
    builder.field_u64(1)?;
    builder.field_bytes(input.source_scope.as_bytes())?;
    builder.field_bytes(input.authority_principal.as_bytes())?;
    builder.field_u64(u64::from(input.authority_uid))?;
    builder.field_u64(u64::from(input.authority_gid))?;
    builder.field_bytes(input.tenure_authority_ref.as_bytes())?;
    builder.field_bytes(input.tenure_key_ref.as_bytes())?;
    builder.field_u16(REFERENCE_ADMISSION_ED25519_ALGORITHM)?;
    builder.field_u16(REFERENCE_ADMISSION_ED25519_ALGORITHM_VERSION)?;
    builder.field_bytes(input.tenure_public_key)?;
    builder.field_u64(1)?;
    builder.field_bytes(input.source_scope.as_bytes())?;
    builder.field_bytes(input.target.as_bytes())?;
    builder.field_bytes(input.controller_principal.as_bytes())?;
    builder.field_bytes(input.writer.as_bytes())?;
    builder.field_bytes(input.controller_key_ref.as_bytes())?;
    builder.field_u16(REFERENCE_ADMISSION_ED25519_ALGORITHM)?;
    builder.field_u16(REFERENCE_ADMISSION_ED25519_ALGORITHM_VERSION)?;
    builder.field_bytes(input.controller_public_key)?;
    Ok(ReferenceAdmissionPolicyFingerprintV1(builder.finish()))
}

/// Derives the exact local Runtime control-endpoint identity component.
///
/// Both endpoints must pass the same canonical Unix socket path and the live
/// socket metadata observed after the connection is established. The mode is
/// the already-masked permission/special-bit value (`st_mode & 0o7777`). This
/// helper owns the digest domain and field order so Runtime and Controller
/// cannot silently implement two similar channel protocols.
pub fn reference_local_control_endpoint_identity_digest_v1(
    canonical_socket_path: &[u8],
    device: u64,
    inode: u64,
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
) -> Result<Digest32, ReferenceControlError> {
    if canonical_socket_path.is_empty() || inode == 0 || mode > 0o7777 {
        return Err(ReferenceControlError::Contract(
            ReferenceControlContractErrorCode::InvalidChannelEvidence,
        ));
    }
    let mut builder = Digest32Builder::try_new(LOCAL_CONTROL_ENDPOINT_IDENTITY_DOMAIN)?;
    builder.field_bytes(canonical_socket_path)?;
    builder.field_u64(device)?;
    builder.field_u64(inode)?;
    builder.field_u64(u64::from(owner_uid))?;
    builder.field_u64(u64::from(group_gid))?;
    builder.field_u64(u64::from(mode))?;
    Ok(builder.finish())
}

/// Derives the Runtime process credential component of a local channel.
///
/// The fields always identify the response-signing Runtime process: Runtime
/// supplies its effective uid/gid/pid while Controller supplies the exact
/// `SO_PEERCRED` observation of that Runtime peer. Controller process
/// credentials are authenticated independently by the Runtime endpoint and
/// are deliberately not part of this direction-specific component. Missing
/// or non-positive peer pid evidence must fail closed before calling this
/// helper; zero is rejected here as a final contract guard.
pub fn reference_runtime_peer_credentials_digest_v1(
    runtime_uid: u32,
    runtime_gid: u32,
    runtime_pid: u64,
) -> Result<Digest32, ReferenceControlError> {
    if runtime_pid == 0 {
        return Err(ReferenceControlError::Contract(
            ReferenceControlContractErrorCode::InvalidChannelEvidence,
        ));
    }
    let mut builder = Digest32Builder::try_new(RUNTIME_PEER_CREDENTIALS_DOMAIN)?;
    builder.field_u64(u64::from(runtime_uid))?;
    builder.field_u64(u64::from(runtime_gid))?;
    builder.field_u64(runtime_pid)?;
    Ok(builder.finish())
}

/// Exact stable provisioning facts shared by the Runtime and Controller.
///
/// This value deliberately excludes live inode and process-id observations.
/// Those belong to a single accepted channel, while this policy fingerprint is
/// installed in both durable owner journals and remains stable across normal
/// Runtime restarts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceBootstrapChannelPolicyInputV1<'a> {
    /// Canonical absolute Runtime UDS path bytes.
    pub canonical_socket_path: &'a [u8],
    /// Exact Runtime target served by the endpoint.
    pub target: RuntimeHostId,
    /// Exact Controller-owned source scope admitted by Runtime.
    pub source_scope: crate::provenance::SourceScopeRef,
    /// Controller request-signing principal.
    pub controller_principal: PrincipalRef,
    /// Controller request verification-key selector.
    pub controller_key_ref: ApplyAuthKeyRef,
    /// Exact Controller Ed25519 public key bytes.
    pub controller_public_key: &'a [u8; 32],
    /// Runtime service effective uid.
    pub runtime_uid: u32,
    /// Runtime service effective gid.
    pub runtime_gid: u32,
    /// Controller service effective uid observed by Runtime.
    pub controller_uid: u32,
    /// Controller service effective gid observed by Runtime.
    pub controller_gid: u32,
    /// Runtime response-signing principal.
    pub runtime_principal: PrincipalRef,
    /// Runtime response verification-key selector.
    pub response_key_ref: ApplyAuthKeyRef,
    /// Exact Runtime response Ed25519 public key bytes.
    pub response_public_key: &'a [u8; 32],
}

/// Derives the stable Runtime/Controller local-channel policy fingerprint.
///
/// The exact owner-private directory (`02750`) and socket (`0660`) modes are
/// profile constants included by this helper. Both owners must independently
/// derive this value from their protected provisioning facts; a live response
/// or live inode/pid channel digest is never an input.
pub fn reference_bootstrap_channel_policy_fingerprint_v1(
    input: ReferenceBootstrapChannelPolicyInputV1<'_>,
) -> Result<Digest32, ReferenceControlError> {
    let path = input.canonical_socket_path;
    if path.len() <= 1
        || path.first() != Some(&b'/')
        || path.last() == Some(&b'/')
        || path.contains(&0)
        || path.windows(2).any(|window| window == b"//")
        || path[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
        || input.runtime_uid == 0
        || input.runtime_gid == 0
        || input.controller_uid == 0
        || input.controller_gid == 0
        || input.runtime_uid == input.controller_uid
        || control_bytes_are_zero(input.target.as_bytes())
        || control_bytes_are_zero(input.source_scope.as_bytes())
        || control_bytes_are_zero(input.controller_principal.as_bytes())
        || control_bytes_are_zero(input.controller_key_ref.as_bytes())
        || control_bytes_are_zero(input.controller_public_key)
        || control_bytes_are_zero(input.runtime_principal.as_bytes())
        || control_bytes_are_zero(input.response_key_ref.as_bytes())
        || control_bytes_are_zero(input.response_public_key)
        || input.controller_public_key == input.response_public_key
    {
        return Err(ReferenceControlError::Contract(
            ReferenceControlContractErrorCode::InvalidChannelEvidence,
        ));
    }
    let identities = [
        input.controller_principal.as_bytes(),
        input.controller_key_ref.as_bytes(),
        input.runtime_principal.as_bytes(),
        input.response_key_ref.as_bytes(),
    ];
    for (index, identity) in identities.iter().enumerate() {
        if identities[index + 1..].contains(identity) {
            return Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidChannelEvidence,
            ));
        }
    }

    let mut builder = Digest32Builder::try_new(BOOTSTRAP_CHANNEL_POLICY_FINGERPRINT_DOMAIN)?;
    builder.field_bytes(input.target.as_bytes())?;
    builder.field_bytes(path)?;
    builder.field_bytes(input.source_scope.as_bytes())?;
    builder.field_bytes(input.controller_principal.as_bytes())?;
    builder.field_bytes(input.controller_key_ref.as_bytes())?;
    builder.field_bytes(input.controller_public_key)?;
    builder.field_u64(u64::from(input.runtime_uid))?;
    builder.field_u64(u64::from(input.runtime_gid))?;
    builder.field_u64(u64::from(input.controller_uid))?;
    builder.field_u64(u64::from(input.controller_gid))?;
    builder.field_bytes(input.runtime_principal.as_bytes())?;
    builder.field_bytes(input.response_key_ref.as_bytes())?;
    builder.field_bytes(input.response_public_key)?;
    builder.field_u64(u64::from(REFERENCE_CONTROL_SOCKET_DIRECTORY_MODE))?;
    builder.field_u64(u64::from(REFERENCE_CONTROL_SOCKET_MODE))?;
    Ok(builder.finish())
}

fn control_bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Stable public copy of canonical construction rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceControlContractErrorCode {
    /// Canonical digest construction failed.
    Digest,
    /// Build instance ID was invalid.
    InvalidBuildInstanceId,
    /// Runtime store instance ID was invalid.
    InvalidRuntimeStoreInstanceId,
    /// Runtime artifact length was invalid.
    InvalidArtifactLength,
    /// Runtime artifact digest was invalid.
    InvalidArtifactDigest,
    /// Target triple was invalid.
    InvalidTargetTriple,
    /// Compatibility facts were invalid.
    InvalidCompatibility,
    /// Lifecycle budget was zero or exceeded the canonical maximum.
    InvalidLifecycleBudget,
    /// Reference profile was invalid.
    InvalidProfile,
    /// Reference shape was invalid.
    InvalidShape,
    /// Subject and domain disagreed.
    DomainMismatch,
    /// Fixture facts disagreed.
    FixtureMismatch,
    /// Configuration was not canonical empty.
    ConfigMismatch,
    /// Runtime target disagreed.
    TargetMismatch,
    /// PXTA binding was present in the zero-binding profile.
    BindingNotAllowed,
    /// Apply envelope was invalid.
    EnvelopeInvalid,
    /// Canonical frame exceeded its bound.
    RequestFrameTooLarge,
    /// Slice/control commitment disagreed.
    CommitmentMismatch,
    /// A bounded protocol value was invalid.
    InvalidBound,
    /// Bootstrap state/reason combination was invalid.
    InvalidReason,
    /// Live endpoint or Runtime process evidence was incomplete or invalid.
    InvalidChannelEvidence,
    /// Reference admission trust or identity facts were incomplete or invalid.
    InvalidAdmissionPolicy,
}

/// Stable public copy of the canonical wire rejection taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ReferenceControlWireErrorCode {
    /// Frame exceeded its protocol bound.
    FrameTooLarge = 1,
    /// Frame ended before a complete field was available.
    Truncated = 2,
    /// Frame magic was not the selected protocol.
    InvalidMagic = 3,
    /// Frame version was not the exact selected version.
    UnsupportedVersion = 4,
    /// Frame contained an unknown field.
    UnknownField = 5,
    /// Frame duplicated a field.
    DuplicateField = 6,
    /// Frame fields were not canonically ordered.
    OutOfOrderField = 7,
    /// A required field was absent.
    MissingField = 8,
    /// A field length was invalid.
    InvalidFieldLength = 9,
    /// A field value was invalid.
    InvalidFieldValue = 10,
    /// Re-encoding did not equal the received frame.
    NonCanonicalFrame = 11,
    /// A canonical digest disagreed.
    DigestMismatch = 12,
    /// Cross-referenced fields disagreed.
    CrossReferenceMismatch = 13,
    /// The selected target shape is unsupported.
    UnsupportedShape = 14,
    /// A PXTA binding appeared in the zero-binding profile.
    BindingNotAllowed = 15,
    /// The expected Runtime store disagreed.
    RuntimeStoreMismatch = 16,
    /// Runtime target disagreed.
    TargetMismatch = 17,
    /// Fixture facts disagreed.
    FixtureMismatch = 18,
    /// Response exceeded the requester's bound.
    ResponseBoundExceeded = 19,
    /// Stable operational reason was unknown.
    UnknownReason = 20,
    /// Frame contained trailing bytes.
    TrailingBytes = 21,
    /// Signature field was invalid.
    InvalidSignatureField = 22,
    /// Optional-field presence marker was invalid.
    InvalidPresence = 23,
    /// Artifact facts disagreed.
    ArtifactMismatch = 24,
    /// Runtime compatibility facts disagreed.
    CompatibilityMismatch = 25,
}

/// One canonical wire rejection with an optional field/tag detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceControlWireError {
    code: ReferenceControlWireErrorCode,
    detail: Option<u16>,
}

impl ReferenceControlWireError {
    /// Returns the stable rejection code.
    #[must_use]
    pub const fn code(self) -> ReferenceControlWireErrorCode {
        self.code
    }

    /// Returns the optional field/tag detail from the canonical decoder.
    #[must_use]
    pub const fn detail(self) -> Option<u16> {
        self.detail
    }
}

/// Fail-closed public error facade for reference control contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceControlError {
    /// Canonical reference construction failed.
    Contract(ReferenceControlContractErrorCode),
    /// Canonical strict wire decoding or cross-checking failed.
    Wire(ReferenceControlWireError),
    /// Existing provenance commitment construction failed.
    Provenance(ProvenanceContractError),
    /// Existing apply-control commitment construction failed.
    Apply(ApplyContractError),
    /// Verified installation facts could not produce compatibility facts.
    Installation(RuntimeInstallationError),
    /// Domain-separated digest construction failed.
    Digest(DigestBuildError),
}

impl fmt::Display for ReferenceControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(code) => write!(formatter, "reference control contract error: {code:?}"),
            Self::Wire(error) => {
                if let Some(detail) = error.detail {
                    write!(
                        formatter,
                        "reference control wire error {:?} at {detail}",
                        error.code
                    )
                } else {
                    write!(formatter, "reference control wire error {:?}", error.code)
                }
            }
            Self::Provenance(error) => write!(formatter, "reference provenance failed: {error}"),
            Self::Apply(error) => write!(formatter, "reference apply control failed: {error}"),
            Self::Installation(error) => {
                write!(formatter, "reference installation facts failed: {error}")
            }
            Self::Digest(error) => write!(formatter, "reference digest failed: {error}"),
        }
    }
}

impl std::error::Error for ReferenceControlError {}

impl From<ReferenceContractError> for ReferenceControlError {
    fn from(value: ReferenceContractError) -> Self {
        let code = match value {
            ReferenceContractError::Digest(_) => ReferenceControlContractErrorCode::Digest,
            ReferenceContractError::InvalidBuildInstanceId => {
                ReferenceControlContractErrorCode::InvalidBuildInstanceId
            }
            ReferenceContractError::InvalidRuntimeStoreInstanceId => {
                ReferenceControlContractErrorCode::InvalidRuntimeStoreInstanceId
            }
            ReferenceContractError::InvalidArtifactLength => {
                ReferenceControlContractErrorCode::InvalidArtifactLength
            }
            ReferenceContractError::InvalidArtifactDigest => {
                ReferenceControlContractErrorCode::InvalidArtifactDigest
            }
            ReferenceContractError::InvalidTargetTriple => {
                ReferenceControlContractErrorCode::InvalidTargetTriple
            }
            ReferenceContractError::InvalidCompatibility => {
                ReferenceControlContractErrorCode::InvalidCompatibility
            }
            ReferenceContractError::InvalidLifecycleBudget => {
                ReferenceControlContractErrorCode::InvalidLifecycleBudget
            }
            ReferenceContractError::InvalidProfile => {
                ReferenceControlContractErrorCode::InvalidProfile
            }
            ReferenceContractError::InvalidShape => ReferenceControlContractErrorCode::InvalidShape,
            ReferenceContractError::DomainMismatch => {
                ReferenceControlContractErrorCode::DomainMismatch
            }
            ReferenceContractError::FixtureMismatch => {
                ReferenceControlContractErrorCode::FixtureMismatch
            }
            ReferenceContractError::ConfigMismatch => {
                ReferenceControlContractErrorCode::ConfigMismatch
            }
            ReferenceContractError::TargetMismatch => {
                ReferenceControlContractErrorCode::TargetMismatch
            }
            ReferenceContractError::BindingNotAllowed => {
                ReferenceControlContractErrorCode::BindingNotAllowed
            }
            ReferenceContractError::EnvelopeInvalid => {
                ReferenceControlContractErrorCode::EnvelopeInvalid
            }
            ReferenceContractError::RequestFrameTooLarge => {
                ReferenceControlContractErrorCode::RequestFrameTooLarge
            }
            ReferenceContractError::CommitmentMismatch => {
                ReferenceControlContractErrorCode::CommitmentMismatch
            }
            ReferenceContractError::InvalidBound => ReferenceControlContractErrorCode::InvalidBound,
            ReferenceContractError::InvalidReason => {
                ReferenceControlContractErrorCode::InvalidReason
            }
        };
        Self::Contract(code)
    }
}

impl From<ReferenceWireError> for ReferenceControlError {
    fn from(value: ReferenceWireError) -> Self {
        let code = match value.code() {
            ReferenceWireErrorCode::FrameTooLarge => ReferenceControlWireErrorCode::FrameTooLarge,
            ReferenceWireErrorCode::Truncated => ReferenceControlWireErrorCode::Truncated,
            ReferenceWireErrorCode::InvalidMagic => ReferenceControlWireErrorCode::InvalidMagic,
            ReferenceWireErrorCode::UnsupportedVersion => {
                ReferenceControlWireErrorCode::UnsupportedVersion
            }
            ReferenceWireErrorCode::UnknownField => ReferenceControlWireErrorCode::UnknownField,
            ReferenceWireErrorCode::DuplicateField => ReferenceControlWireErrorCode::DuplicateField,
            ReferenceWireErrorCode::OutOfOrderField => {
                ReferenceControlWireErrorCode::OutOfOrderField
            }
            ReferenceWireErrorCode::MissingField => ReferenceControlWireErrorCode::MissingField,
            ReferenceWireErrorCode::InvalidFieldLength => {
                ReferenceControlWireErrorCode::InvalidFieldLength
            }
            ReferenceWireErrorCode::InvalidFieldValue => {
                ReferenceControlWireErrorCode::InvalidFieldValue
            }
            ReferenceWireErrorCode::NonCanonicalFrame => {
                ReferenceControlWireErrorCode::NonCanonicalFrame
            }
            ReferenceWireErrorCode::DigestMismatch => ReferenceControlWireErrorCode::DigestMismatch,
            ReferenceWireErrorCode::CrossReferenceMismatch => {
                ReferenceControlWireErrorCode::CrossReferenceMismatch
            }
            ReferenceWireErrorCode::UnsupportedShape => {
                ReferenceControlWireErrorCode::UnsupportedShape
            }
            ReferenceWireErrorCode::BindingNotAllowed => {
                ReferenceControlWireErrorCode::BindingNotAllowed
            }
            ReferenceWireErrorCode::RuntimeStoreMismatch => {
                ReferenceControlWireErrorCode::RuntimeStoreMismatch
            }
            ReferenceWireErrorCode::TargetMismatch => ReferenceControlWireErrorCode::TargetMismatch,
            ReferenceWireErrorCode::FixtureMismatch => {
                ReferenceControlWireErrorCode::FixtureMismatch
            }
            ReferenceWireErrorCode::ResponseBoundExceeded => {
                ReferenceControlWireErrorCode::ResponseBoundExceeded
            }
            ReferenceWireErrorCode::UnknownReason => ReferenceControlWireErrorCode::UnknownReason,
            ReferenceWireErrorCode::TrailingBytes => ReferenceControlWireErrorCode::TrailingBytes,
            ReferenceWireErrorCode::InvalidSignatureField => {
                ReferenceControlWireErrorCode::InvalidSignatureField
            }
            ReferenceWireErrorCode::InvalidPresence => {
                ReferenceControlWireErrorCode::InvalidPresence
            }
            ReferenceWireErrorCode::ArtifactMismatch => {
                ReferenceControlWireErrorCode::ArtifactMismatch
            }
            ReferenceWireErrorCode::CompatibilityMismatch => {
                ReferenceControlWireErrorCode::CompatibilityMismatch
            }
        };
        Self::Wire(ReferenceControlWireError {
            code,
            detail: value.detail(),
        })
    }
}

impl From<ProvenanceContractError> for ReferenceControlError {
    fn from(value: ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<ApplyContractError> for ReferenceControlError {
    fn from(value: ApplyContractError) -> Self {
        Self::Apply(value)
    }
}

impl From<RuntimeInstallationError> for ReferenceControlError {
    fn from(value: RuntimeInstallationError) -> Self {
        Self::Installation(value)
    }
}

impl From<DigestBuildError> for ReferenceControlError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

/// Runtime-validated lifecycle budgets for the fixed reference profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedReferenceLifecycleBudgetsV1 {
    start: BoundedDuration,
    drain: BoundedDuration,
    cleanup: BoundedDuration,
}

impl ValidatedReferenceLifecycleBudgetsV1 {
    /// Validates all budgets through the canonical PXTE v4 domain validator.
    pub fn try_new(
        start: BoundedDuration,
        drain: BoundedDuration,
        cleanup: BoundedDuration,
    ) -> Result<Self, ReferenceControlError> {
        // Domain identity does not participate in lifecycle-bound validation.
        // Calling the canonical record constructor keeps the limit single-owned.
        ReferenceLoopDomainSpecV1::try_new(DomainRef::from_bytes([0; 16]), start, drain, cleanup)?;
        Ok(Self {
            start,
            drain,
            cleanup,
        })
    }

    /// Returns the nonzero start budget.
    #[must_use]
    pub const fn start(self) -> BoundedDuration {
        self.start
    }

    /// Returns the nonzero drain budget.
    #[must_use]
    pub const fn drain(self) -> BoundedDuration {
        self.drain
    }

    /// Returns the nonzero cleanup budget.
    #[must_use]
    pub const fn cleanup(self) -> BoundedDuration {
        self.cleanup
    }
}

/// The two exact target shapes admitted by PXTE v4.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceAssemblyModeV1 {
    /// Exactly one source-only LoopDomain and one fixed fixture subject.
    OneSourceLoop,
    /// Authoritative empty desired target with no domain or subject.
    EmptyDeactivate,
}

/// Read-only one-source Loop facts decoded or built by the canonical owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceLoopFactsV1 {
    instance: InstanceRef,
    domain: DomainRef,
    budgets: ValidatedReferenceLifecycleBudgetsV1,
    config_digest: Digest32,
}

impl ReferenceLoopFactsV1 {
    /// Returns the sole planned instance.
    #[must_use]
    pub const fn instance(self) -> InstanceRef {
        self.instance
    }

    /// Returns the sole planned LoopDomain.
    #[must_use]
    pub const fn domain(self) -> DomainRef {
        self.domain
    }

    /// Returns the canonical validated lifecycle budgets.
    #[must_use]
    pub const fn budgets(self) -> ValidatedReferenceLifecycleBudgetsV1 {
        self.budgets
    }

    /// Returns the canonical-empty configuration digest.
    #[must_use]
    pub const fn config_digest(self) -> Digest32 {
        self.config_digest
    }
}

/// Sealed typed PXTE v4 body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceTargetExecutionPlanV4 {
    inner: CanonicalTargetExecutionPlanV4,
}

impl ReferenceTargetExecutionPlanV4 {
    /// Builds the sole source-Loop shape from immutable installer manifest facts.
    pub fn try_one_source_loop(
        manifest: &VerifiedRuntimeManifestIngressV1,
        instance: InstanceRef,
        domain: DomainRef,
        budgets: ValidatedReferenceLifecycleBudgetsV1,
    ) -> Result<Self, ReferenceControlError> {
        let projection = strict_projection(manifest)?;
        let domain_spec = ReferenceLoopDomainSpecV1::try_new(
            domain,
            budgets.start(),
            budgets.drain(),
            budgets.cleanup(),
        )?;
        let subject = ReferenceLoopSubjectSpecV1::try_new(
            instance,
            domain,
            fixture_from_manifest(manifest),
            manifest.canonical_empty_config_digest(),
        )?;
        Ok(Self {
            inner: CanonicalTargetExecutionPlanV4::try_one_source_loop(
                projection,
                domain_spec,
                subject,
            )?,
        })
    }

    /// Builds the authoritative empty target from immutable installer facts.
    pub fn try_empty_deactivate(
        manifest: &VerifiedRuntimeManifestIngressV1,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalTargetExecutionPlanV4::try_empty_deactivate(strict_projection(
                manifest,
            )?)?,
        })
    }

    /// Strictly decodes exactly PXTE v4 without version fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalTargetExecutionPlanV4::decode(frame)?,
        })
    }

    /// Returns the exact canonical PXTE bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        self.inner.canonical_wire()
    }

    /// Returns the canonical PXTE v4 digest.
    #[must_use]
    pub const fn execution_digest(&self) -> Digest32 {
        self.inner.execution_digest()
    }

    /// Returns the selected reference shape.
    #[must_use]
    pub const fn mode(&self) -> ReferenceAssemblyModeV1 {
        match self.inner.profile().mode() {
            CanonicalAssemblyModeV1::OneSourceLoop => ReferenceAssemblyModeV1::OneSourceLoop,
            CanonicalAssemblyModeV1::EmptyDeactivate => ReferenceAssemblyModeV1::EmptyDeactivate,
        }
    }

    /// Returns the target carried by the exact manifest projection.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.inner.projection().row().target()
    }

    /// Returns the exact installed manifest digest.
    #[must_use]
    pub const fn manifest_digest(&self) -> Digest32 {
        self.inner.projection().manifest_digest()
    }

    /// Returns the exact manifest projection bytes committed into PXTE.
    #[must_use]
    pub fn manifest_projection_wire(&self) -> &[u8] {
        self.inner.projection().canonical_wire()
    }

    /// Returns the manifest-selected fixture definition.
    #[must_use]
    pub const fn fixture_definition(&self) -> CardDefinitionRef {
        self.inner.projection().row().fixture().definition()
    }

    /// Returns the manifest-selected fixture implementation.
    #[must_use]
    pub const fn fixture_implementation(&self) -> CardImplementationRef {
        self.inner.projection().row().fixture().implementation()
    }

    /// Returns the manifest-selected fixture export.
    #[must_use]
    pub const fn fixture_export(&self) -> [u8; 16] {
        *self.inner.projection().row().fixture().export().as_bytes()
    }

    /// Returns the fixture definition digest.
    #[must_use]
    pub const fn fixture_definition_digest(&self) -> Digest32 {
        self.inner.projection().row().fixture().definition_digest()
    }

    /// Returns the fixture artifact digest.
    #[must_use]
    pub const fn fixture_artifact_digest(&self) -> Digest32 {
        self.inner
            .projection()
            .row()
            .fixture()
            .fixture_artifact_digest()
    }

    /// Returns the canonical profile fingerprint for this exact fixture.
    pub fn profile_fingerprint(&self) -> Result<Digest32, ReferenceControlError> {
        Ok(reference_profile_fingerprint(
            self.inner.projection().row().fixture(),
        )?)
    }

    /// Verifies that this PXTE selects the exact five-field fixture compiled
    /// into the running Runtime executable.
    ///
    /// The comparison is contract-owned so lifecycle owners never duplicate
    /// fixture constants or substitute a manifest-only compatibility claim.
    pub fn validate_compiled_fixture(
        &self,
        compiled: RuntimeCompiledInstallationFactsV1,
    ) -> Result<(), ReferenceControlError> {
        if self.inner.projection().row().fixture() != compiled.fixture() {
            return Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::FixtureMismatch,
            ));
        }
        Ok(())
    }

    /// Returns one source-Loop view, or `None` for authoritative empty.
    #[must_use]
    pub const fn loop_facts(&self) -> Option<ReferenceLoopFactsV1> {
        match (self.inner.domain(), self.inner.subject()) {
            (Some(domain), Some(subject)) => Some(ReferenceLoopFactsV1 {
                instance: subject.instance(),
                domain: domain.domain(),
                budgets: ValidatedReferenceLifecycleBudgetsV1 {
                    start: domain.start_budget(),
                    drain: domain.drain_budget(),
                    cleanup: domain.cleanup_budget(),
                },
                config_digest: subject.config_digest(),
            }),
            _ => None,
        }
    }

    /// Checks exact byte-identical installer projection and derived profile facts.
    pub fn validate_manifest(
        &self,
        manifest: &VerifiedRuntimeManifestIngressV1,
    ) -> Result<(), ReferenceControlError> {
        if self.manifest_projection_wire() != manifest.projection_canonical_wire()
            || self.manifest_digest() != manifest.manifest_digest()
            || self.target() != manifest.target()
            || self.profile_fingerprint()? != manifest.profile_fingerprint()
        {
            return Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidCompatibility,
            ));
        }
        Ok(())
    }
}

/// Canonical PXAR v5 signing transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceApplySigningTranscriptV2 {
    inner: ApplyRequestSigningTranscriptV2,
}

impl ReferenceApplySigningTranscriptV2 {
    /// Returns the exact bytes a Controller signer signs or a Runtime verifier verifies.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

/// Signature-independent typed PXAR v5 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceApplyRequestDraftV1 {
    envelope: RuntimeApplyEnvelopeV2Draft,
    slice: RuntimePlanSliceV5,
}

impl ReferenceApplyRequestDraftV1 {
    /// Commits one typed PXTE body to provenance, apply control, temporal and store facts.
    pub fn try_new(
        execution: ReferenceTargetExecutionPlanV4,
        provenance: PlanProvenance,
        control: RuntimeApplyControl,
        temporal: ApplyTemporalConstraint,
        expected_runtime_store_instance_id: [u8; 32],
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ReferenceControlError> {
        let assignments = TargetPlanAssignmentsV5::try_from_execution(execution.inner)?;
        let header = RuntimeSliceHeader::new(
            assignments.execution().projection().row().target(),
            provenance,
            assignments.assignment_digest(),
        );
        let commitment = RuntimeSliceCommitment::try_new(header)?;
        let slice = RuntimePlanSliceV5::try_new(commitment, assignments)?;
        let control_commitment = RuntimeApplyControlCommitment::try_new(commitment, control)?;
        let store = RuntimeStoreInstanceId::try_from_bytes(expected_runtime_store_instance_id)?;
        let envelope =
            RuntimeApplyEnvelopeV2Draft::try_new(control_commitment, temporal, store, auth_claim)?;
        Ok(Self { envelope, slice })
    }

    /// Returns the exact signature-independent Controller transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceApplySigningTranscriptV2, ReferenceControlError> {
        Ok(ReferenceApplySigningTranscriptV2 {
            inner: self.envelope.signing_transcript()?,
        })
    }

    /// Finalizes the signed envelope and complete PXAR v5 frame.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ReferenceApplyRequestV1, ReferenceControlError> {
        let envelope = self.envelope.finalize(signature)?;
        Ok(ReferenceApplyRequestV1 {
            inner: RuntimeApplyRequestV5::try_new(envelope, self.slice)?,
        })
    }
}

/// Signed, strict, sealed PXAR v5 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceApplyRequestV1 {
    inner: RuntimeApplyRequestV5,
}

impl ReferenceApplyRequestV1 {
    /// Strictly decodes exactly PXAR v5 without legacy fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: RuntimeApplyRequestV5::decode(frame)?,
        })
    }

    /// Returns exact canonical PXAR v5 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        self.inner.canonical_wire()
    }

    /// Returns the exact nested RuntimePlanSlice v5 bytes (`PXTA || PXTE`).
    ///
    /// The canonical PXAR owner determines this byte range; this facade does
    /// not parse or reproduce outer-frame offsets.
    #[must_use]
    pub fn canonical_slice_wire(&self) -> &[u8] {
        self.inner.canonical_slice_wire()
    }

    /// Returns exact canonical PXTE v4 facts retained by this request.
    #[must_use]
    pub fn target_execution(&self) -> ReferenceTargetExecutionPlanV4 {
        ReferenceTargetExecutionPlanV4 {
            inner: self.inner.slice().assignments().execution().clone(),
        }
    }

    /// Returns the exact target Runtime.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.inner.slice().commitment().header().target()
    }

    /// Returns the exact source-plan provenance.
    #[must_use]
    pub const fn provenance(&self) -> PlanProvenance {
        self.inner.slice().commitment().header().provenance()
    }

    /// Returns the composite zero-PXTA plus PXTE assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.inner.slice().commitment().header().assignment_digest()
    }

    /// Returns the target-slice commitment digest.
    #[must_use]
    pub const fn target_slice_digest(&self) -> TargetSliceDigest {
        self.inner.slice().commitment().target_slice_digest()
    }

    /// Returns the complete canonical B1 control commitment.
    #[must_use]
    pub const fn control_commitment(&self) -> &RuntimeApplyControlCommitment {
        self.inner.envelope().control_commitment()
    }

    /// Returns the authenticated temporal constraint.
    #[must_use]
    pub const fn temporal(&self) -> ApplyTemporalConstraint {
        self.inner.envelope().temporal()
    }

    /// Returns the nonzero expected Runtime store identity.
    #[must_use]
    pub const fn expected_runtime_store_instance_id(&self) -> [u8; 32] {
        *self
            .inner
            .envelope()
            .expected_runtime_store_instance_id()
            .as_bytes()
    }

    /// Returns request-authentication claim and opaque signature.
    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        self.inner.envelope().authentication()
    }

    /// Returns the complete authenticated request identity used for journal
    /// correlation. It covers the signed envelope's slice/control commitment,
    /// temporal constraint, expected Runtime store and request authentication;
    /// the opaque signature is included by the canonical envelope digest.
    #[must_use]
    pub const fn envelope_request_digest(&self) -> Digest32 {
        self.inner.envelope().request_digest()
    }

    /// Reconstructs the exact transcript a Runtime signature verifier consumes.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceApplySigningTranscriptV2, ReferenceControlError> {
        Ok(ReferenceApplySigningTranscriptV2 {
            inner: self.inner.envelope().signing_transcript()?,
        })
    }

    /// Fails closed unless the local journal store is the signed expected store.
    pub fn validate_expected_store(
        &self,
        local_runtime_store_instance_id: [u8; 32],
    ) -> Result<(), ReferenceControlError> {
        let local = RuntimeStoreInstanceId::try_from_bytes(local_runtime_store_instance_id)?;
        self.inner.envelope().validate_expected_store(local)?;
        Ok(())
    }

    /// Fails closed unless PXTE commits the exact immutable installed manifest.
    pub fn validate_manifest(
        &self,
        manifest: &VerifiedRuntimeManifestIngressV1,
    ) -> Result<(), ReferenceControlError> {
        self.target_execution().validate_manifest(manifest)
    }
}

/// Strictly restores and validates one journal-owned durable Slice body.
///
/// The body must be the exact canonical `PXTA-zero || PXTE-v4` bytes previously
/// returned by [`ReferenceApplyRequestV1::canonical_slice_wire`]. The target is
/// derived from immutable manifest ingress, while provenance and the expected
/// Slice digest remain explicit journal commitments. On success the returned
/// PXTE is already checked against the same immutable manifest.
pub fn verify_reference_durable_slice_v1(
    canonical_slice_wire: &[u8],
    provenance: PlanProvenance,
    expected_target_slice_digest: TargetSliceDigest,
    manifest: &VerifiedRuntimeManifestIngressV1,
) -> Result<ReferenceTargetExecutionPlanV4, ReferenceControlError> {
    let slice = RuntimePlanSliceV5::decode_durable(
        canonical_slice_wire,
        manifest.target(),
        provenance,
        expected_target_slice_digest,
    )?;
    let execution = ReferenceTargetExecutionPlanV4 {
        inner: slice.assignments().execution().clone(),
    };
    execution.validate_manifest(manifest)?;
    Ok(execution)
}

/// Domain-separated durable replay identities derived from one sealed PXAR v5.
///
/// The Runtime derives these only after authenticating the exact request.  The
/// helper deliberately accepts no raw field bag, so a caller cannot detach an
/// identity from the canonical request bytes whose signatures were verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceApplyIngressIdentitiesV1 {
    tenure_nonce_identity: Digest32,
    request_nonce_identity: Digest32,
    temporal_lineage_digest: Digest32,
}

impl ReferenceApplyIngressIdentitiesV1 {
    /// Returns the durable identity of the Authority selector and tenure nonce.
    #[must_use]
    pub const fn tenure_nonce_identity(self) -> Digest32 {
        self.tenure_nonce_identity
    }

    /// Returns the durable identity of the Controller selector and request nonce.
    #[must_use]
    pub const fn request_nonce_identity(self) -> Digest32 {
        self.request_nonce_identity
    }

    /// Returns the durable identity of the complete authenticated temporal lineage.
    #[must_use]
    pub const fn temporal_lineage_digest(self) -> Digest32 {
        self.temporal_lineage_digest
    }
}

/// Derives all durable ingress identities from one strict, sealed PXAR v5.
///
/// Tenure and request identities mirror their exact trust selectors plus the
/// bounded nonce.  Temporal identity covers the constraint route, target clock
/// and both authenticated budgets; reducing a forwarded budget therefore
/// creates a distinct lineage digest while retaining the same constraint ID for
/// the journal's conflict checks.
pub fn reference_apply_ingress_identities_v1(
    request: &ReferenceApplyRequestV1,
) -> Result<ReferenceApplyIngressIdentitiesV1, ReferenceControlError> {
    let provenance = request.provenance();
    let control = request.control_commitment().control();
    let writer = control.writer_context();
    let proof = writer.proof();
    let authority = proof.authority();
    let authentication = request.authentication().claim();
    let temporal = request.temporal();

    let mut tenure = Digest32Builder::try_new(REFERENCE_APPLY_TENURE_NONCE_IDENTITY_DOMAIN)?;
    tenure.field_bytes(provenance.source_scope().as_bytes())?;
    tenure.field_bytes(authority.authority().as_bytes())?;
    tenure.field_bytes(authority.key().as_bytes())?;
    tenure.field_u16(authority.algorithm().value())?;
    tenure.field_u16(authority.algorithm_version())?;
    tenure.field_bytes(proof.nonce())?;

    let mut request_nonce =
        Digest32Builder::try_new(REFERENCE_APPLY_REQUEST_NONCE_IDENTITY_DOMAIN)?;
    request_nonce.field_bytes(provenance.source_scope().as_bytes())?;
    request_nonce.field_bytes(request.target().as_bytes())?;
    request_nonce.field_bytes(authentication.principal().as_bytes())?;
    request_nonce.field_bytes(writer.writer().as_bytes())?;
    request_nonce.field_bytes(authentication.key().as_bytes())?;
    request_nonce.field_u16(authentication.algorithm().value())?;
    request_nonce.field_u16(authentication.algorithm_version())?;
    request_nonce.field_bytes(authentication.nonce())?;

    let mut temporal_lineage = Digest32Builder::try_new(REFERENCE_APPLY_TEMPORAL_LINEAGE_DOMAIN)?;
    temporal_lineage.field_bytes(provenance.source_scope().as_bytes())?;
    temporal_lineage.field_bytes(request.target().as_bytes())?;
    temporal_lineage.field_bytes(temporal.constraint_id().as_bytes())?;
    temporal_lineage.field_bytes(temporal.target_clock_domain().as_bytes())?;
    temporal_lineage.field_u64(temporal.target_clock_generation().value())?;
    temporal_lineage.field_u64(temporal.original_budget().value())?;
    temporal_lineage.field_u64(temporal.remaining_budget().value())?;

    Ok(ReferenceApplyIngressIdentitiesV1 {
        tenure_nonce_identity: tenure.finish(),
        request_nonce_identity: request_nonce.finish(),
        temporal_lineage_digest: temporal_lineage.finish(),
    })
}

/// Exact terminal outcome selected by the Runtime apply state machine.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum ReferenceApplyTerminalOutcomeV1 {
    OneSourceLoopActive = 1,
    EmptyDeactivateExactZero = 2,
    StartTimedOutBeforeIntentNoEffects = 3,
    StopTimedOutBeforeHeadCommitNoEffects = 4,
    StartFailedBeforeHeadCommitExactZero = 5,
    StartTimedOutBeforeHeadCommitExactZero = 6,
    StopFailedButExactZero = 7,
    TimedOutButExactZero = 8,
    AbortedBeforeIntentNoEffects = 9,
    AbortedBeforeHeadCommitExactZero = 10,
    SupersededAfterIntentExactZero = 11,
    InterruptedButNowExactZero = 12,
}

/// Whether lifecycle execution is proven absent or may have crossed its boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum ReferenceApplyTerminalLifecycleEffectV1 {
    ProvenNotStarted = 1,
    MayHaveStarted = 2,
}

/// Desired-head disposition atomically associated with terminal selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceApplyTerminalHeadV1 {
    /// No desired head existed and the operation preserved that fact.
    PreservedNone,
    /// The operation preserved this exact existing desired head.
    PreservedExisting(TargetSliceDigest),
    /// The operation committed the exact incoming request Slice as desired head.
    CommittedIncoming,
}

/// Contract-derived stable identity of one exact apply terminal result.
///
/// There is deliberately no public constructor: the canonical contract derives
/// this value from target, store, source scope, operation id and request digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReferenceApplyTerminalResultRefV1 {
    inner: TerminalResultRef,
}

impl ReferenceApplyTerminalResultRefV1 {
    /// Returns the nonzero canonical reference bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.inner.as_bytes()
    }
}

/// Immutable Runtime-owned facts carried by one apply terminal Receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceApplyTerminalFactsV1 {
    inner: CanonicalApplyTerminalFactsV1,
}

impl ReferenceApplyTerminalFactsV1 {
    /// Builds terminal facts for one exact PXAR request.
    ///
    /// `raw_outcome_digest` binds the Runtime-owned canonical raw latch; this
    /// facade validates only the ADR-admitted outcome/head/lifecycle shape.
    #[allow(clippy::too_many_arguments)] // GOV-WAIVER-0010
    pub fn try_new(
        request: &ReferenceApplyRequestV1,
        outcome: ReferenceApplyTerminalOutcomeV1,
        lifecycle_effect: ReferenceApplyTerminalLifecycleEffectV1,
        head: ReferenceApplyTerminalHeadV1,
        resource_census_digest: Digest32,
        raw_outcome_digest: Digest32,
        completion_runtime_host_epoch: u64,
        completion_snapshot_sequence: u64,
        selection_clock_generation: ClockGeneration,
        selection_observed_at_nanos: u64,
    ) -> Result<Self, ReferenceControlError> {
        let canonical_head = match head {
            ReferenceApplyTerminalHeadV1::PreservedNone => {
                CanonicalApplyTerminalHeadV1::PreservedNone
            }
            ReferenceApplyTerminalHeadV1::PreservedExisting(digest) => {
                CanonicalApplyTerminalHeadV1::PreservedExisting(digest)
            }
            ReferenceApplyTerminalHeadV1::CommittedIncoming => {
                CanonicalApplyTerminalHeadV1::CommittedIncoming(request.target_slice_digest())
            }
        };
        Ok(Self {
            inner: CanonicalApplyTerminalFactsV1::try_new(
                &request.inner,
                canonical_apply_terminal_outcome(outcome),
                canonical_apply_terminal_lifecycle(lifecycle_effect),
                canonical_head,
                resource_census_digest,
                raw_outcome_digest,
                RuntimeHostEpoch::try_new(completion_runtime_host_epoch)?,
                RuntimeSnapshotSequence::try_new(completion_snapshot_sequence)?,
                selection_clock_generation,
                selection_observed_at_nanos,
            )?,
        })
    }

    /// Returns the selected primary outcome.
    #[must_use]
    pub const fn outcome(self) -> ReferenceApplyTerminalOutcomeV1 {
        public_apply_terminal_outcome(self.inner.outcome())
    }

    /// Returns the lifecycle-effect boundary fact.
    #[must_use]
    pub const fn lifecycle_effect(self) -> ReferenceApplyTerminalLifecycleEffectV1 {
        public_apply_terminal_lifecycle(self.inner.lifecycle_effect())
    }

    /// Returns the desired-head disposition.
    #[must_use]
    pub const fn head(self) -> ReferenceApplyTerminalHeadV1 {
        match self.inner.head() {
            CanonicalApplyTerminalHeadV1::PreservedNone => {
                ReferenceApplyTerminalHeadV1::PreservedNone
            }
            CanonicalApplyTerminalHeadV1::PreservedExisting(digest) => {
                ReferenceApplyTerminalHeadV1::PreservedExisting(digest)
            }
            CanonicalApplyTerminalHeadV1::CommittedIncoming(_) => {
                ReferenceApplyTerminalHeadV1::CommittedIncoming
            }
        }
    }

    /// Returns the resulting desired-head digest, or `None` when absence was preserved.
    #[must_use]
    pub const fn desired_head_digest(self) -> Option<TargetSliceDigest> {
        match self.inner.head() {
            CanonicalApplyTerminalHeadV1::PreservedNone => None,
            CanonicalApplyTerminalHeadV1::PreservedExisting(digest)
            | CanonicalApplyTerminalHeadV1::CommittedIncoming(digest) => Some(digest),
        }
    }

    /// Returns the exact completion resource-census digest.
    #[must_use]
    pub const fn resource_census_digest(self) -> Digest32 {
        self.inner.resource_census_digest()
    }

    /// Returns the Runtime-owned canonical raw-outcome summary digest.
    #[must_use]
    pub const fn raw_outcome_digest(self) -> Digest32 {
        self.inner.raw_outcome_digest()
    }

    /// Returns the RuntimeHost epoch which committed completion.
    #[must_use]
    pub const fn completion_runtime_host_epoch(self) -> u64 {
        self.inner.completion_runtime_host_epoch().value()
    }

    /// Returns the Runtime snapshot sequence which committed completion.
    #[must_use]
    pub const fn completion_snapshot_sequence(self) -> u64 {
        self.inner.completion_snapshot_sequence().value()
    }

    /// Returns the owner-local clock generation used for terminal selection.
    #[must_use]
    pub const fn selection_clock_generation(self) -> ClockGeneration {
        self.inner.selection_clock_generation()
    }

    /// Returns the owner-local terminal-selection instant in nanoseconds.
    #[must_use]
    pub const fn selection_observed_at_nanos(self) -> u64 {
        self.inner.selection_observed_at_nanos()
    }

    /// Returns the contract-derived, nonzero stable terminal-result reference.
    #[must_use]
    pub const fn terminal_result_ref(self) -> ReferenceApplyTerminalResultRefV1 {
        ReferenceApplyTerminalResultRefV1 {
            inner: self.inner.terminal_result_ref(),
        }
    }
}

/// Runtime terminal-Receipt response signer bound to one live channel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceApplyTerminalReceiptAuthClaimV1 {
    inner: RuntimeResponseAuthClaimV1,
}

impl ReferenceApplyTerminalReceiptAuthClaimV1 {
    /// Selects the Runtime response key while deriving peer/channel facts.
    pub fn try_new(
        channel: ReferenceChannelBindingV1,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: RuntimeResponseAuthClaimV1::try_new(
                channel.runtime_peer(),
                channel.binding_digest(),
                key,
                algorithm,
                algorithm_version,
            )?,
        })
    }

    #[must_use]
    pub const fn runtime_peer(self) -> PrincipalRef {
        self.inner.runtime_peer()
    }

    #[must_use]
    pub const fn channel_binding_digest(self) -> Digest32 {
        self.inner.channel_binding_digest()
    }

    #[must_use]
    pub const fn key(self) -> ApplyAuthKeyRef {
        self.inner.key()
    }

    #[must_use]
    pub const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.inner.algorithm()
    }

    #[must_use]
    pub const fn algorithm_version(self) -> u16 {
        self.inner.algorithm_version()
    }
}

/// Canonical Runtime apply terminal-Receipt signing transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceApplyTerminalReceiptSigningTranscriptV1 {
    inner: ApplyTerminalReceiptSigningTranscriptV1,
}

impl ReferenceApplyTerminalReceiptSigningTranscriptV1 {
    /// Returns the exact bytes a Runtime signer signs or Controller verifies.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

/// Signature-independent terminal Receipt for one exact PXAR request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceApplyTerminalReceiptDraftV1 {
    inner: CanonicalApplyTerminalReceiptDraftV1,
}

impl ReferenceApplyTerminalReceiptDraftV1 {
    /// Binds terminal facts to the exact request, live channel and Runtime signer.
    pub fn try_new(
        request: &ReferenceApplyRequestV1,
        facts: ReferenceApplyTerminalFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ReferenceApplyTerminalReceiptAuthClaimV1,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalApplyTerminalReceiptDraftV1::try_new(
                &request.inner,
                facts.inner,
                channel.inner,
                auth_claim.inner,
            )?,
        })
    }

    /// Returns the exact signature-independent Runtime response transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceApplyTerminalReceiptSigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceApplyTerminalReceiptSigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Finalizes the signed canonical terminal Receipt.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ReferenceApplyTerminalReceiptV1, ReferenceControlError> {
        Ok(ReferenceApplyTerminalReceiptV1 {
            inner: self.inner.finalize(signature)?,
        })
    }
}

/// Signed, strict canonical Runtime apply terminal Receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceApplyTerminalReceiptV1 {
    inner: CanonicalApplyTerminalReceiptV1,
}

impl ReferenceApplyTerminalReceiptV1 {
    /// Strictly decodes exactly PXRT v1 without legacy fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalApplyTerminalReceiptV1::decode(frame)?,
        })
    }

    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.inner.target()
    }

    #[must_use]
    pub const fn runtime_store_instance_id(&self) -> [u8; 32] {
        *self.inner.store().as_bytes()
    }

    #[must_use]
    pub const fn source_scope(&self) -> crate::provenance::SourceScopeRef {
        self.inner.source_scope()
    }

    #[must_use]
    pub const fn operation_id(&self) -> crate::apply::ApplyOperationId {
        self.inner.operation_id()
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.inner.request_digest()
    }

    #[must_use]
    pub fn request_nonce(&self) -> &[u8] {
        self.inner.request_nonce()
    }

    /// Returns decoded terminal facts. Verify the signature and correlation
    /// before treating them as Runtime-owner evidence.
    #[must_use]
    pub const fn facts(&self) -> ReferenceApplyTerminalFactsV1 {
        ReferenceApplyTerminalFactsV1 {
            inner: self.inner.facts(),
        }
    }

    #[must_use]
    pub const fn authentication_runtime_peer(&self) -> PrincipalRef {
        self.inner.authentication().claim().runtime_peer()
    }

    #[must_use]
    pub const fn authentication_channel_binding_digest(&self) -> Digest32 {
        self.inner.authentication().claim().channel_binding_digest()
    }

    #[must_use]
    pub const fn authentication_key(&self) -> ApplyAuthKeyRef {
        self.inner.authentication().claim().key()
    }

    #[must_use]
    pub const fn authentication_algorithm(&self) -> ApplyAuthAlgorithm {
        self.inner.authentication().claim().algorithm()
    }

    #[must_use]
    pub const fn authentication_algorithm_version(&self) -> u16 {
        self.inner.authentication().claim().algorithm_version()
    }

    #[must_use]
    pub fn authentication_signature(&self) -> &[u8] {
        self.inner.authentication().signature()
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        self.inner.canonical_wire()
    }

    /// Returns the domain-separated digest of the complete signed Receipt.
    #[must_use]
    pub const fn receipt_digest(&self) -> Digest32 {
        self.inner.receipt_digest()
    }

    /// Reconstructs the exact Runtime response-auth transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceApplyTerminalReceiptSigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceApplyTerminalReceiptSigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Validates exact PXAR correlation and the current live channel.
    /// Signature verification against `signing_transcript()` remains caller-owned.
    pub fn validate_against_request(
        &self,
        request: &ReferenceApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<ReferenceApplyTerminalFactsV1, ReferenceControlError> {
        self.inner
            .validate_against_request(&request.inner, channel.inner)?;
        Ok(self.facts())
    }
}

const fn canonical_apply_terminal_outcome(
    value: ReferenceApplyTerminalOutcomeV1,
) -> CanonicalApplyTerminalOutcomeV1 {
    match value {
        ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive => {
            CanonicalApplyTerminalOutcomeV1::OneSourceLoopActive
        }
        ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero => {
            CanonicalApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        }
        ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects => {
            CanonicalApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects
        }
        ReferenceApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects => {
            CanonicalApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects
        }
        ReferenceApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero => {
            CanonicalApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero
        }
        ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero => {
            CanonicalApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero
        }
        ReferenceApplyTerminalOutcomeV1::StopFailedButExactZero => {
            CanonicalApplyTerminalOutcomeV1::StopFailedButExactZero
        }
        ReferenceApplyTerminalOutcomeV1::TimedOutButExactZero => {
            CanonicalApplyTerminalOutcomeV1::TimedOutButExactZero
        }
        ReferenceApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects => {
            CanonicalApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects
        }
        ReferenceApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero => {
            CanonicalApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero
        }
        ReferenceApplyTerminalOutcomeV1::SupersededAfterIntentExactZero => {
            CanonicalApplyTerminalOutcomeV1::SupersededAfterIntentExactZero
        }
        ReferenceApplyTerminalOutcomeV1::InterruptedButNowExactZero => {
            CanonicalApplyTerminalOutcomeV1::InterruptedButNowExactZero
        }
    }
}

const fn public_apply_terminal_outcome(
    value: CanonicalApplyTerminalOutcomeV1,
) -> ReferenceApplyTerminalOutcomeV1 {
    match value {
        CanonicalApplyTerminalOutcomeV1::OneSourceLoopActive => {
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        }
        CanonicalApplyTerminalOutcomeV1::EmptyDeactivateExactZero => {
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        }
        CanonicalApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects => {
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects
        }
        CanonicalApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects => {
            ReferenceApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects
        }
        CanonicalApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero => {
            ReferenceApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero
        }
        CanonicalApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero => {
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero
        }
        CanonicalApplyTerminalOutcomeV1::StopFailedButExactZero => {
            ReferenceApplyTerminalOutcomeV1::StopFailedButExactZero
        }
        CanonicalApplyTerminalOutcomeV1::TimedOutButExactZero => {
            ReferenceApplyTerminalOutcomeV1::TimedOutButExactZero
        }
        CanonicalApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects => {
            ReferenceApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects
        }
        CanonicalApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero => {
            ReferenceApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero
        }
        CanonicalApplyTerminalOutcomeV1::SupersededAfterIntentExactZero => {
            ReferenceApplyTerminalOutcomeV1::SupersededAfterIntentExactZero
        }
        CanonicalApplyTerminalOutcomeV1::InterruptedButNowExactZero => {
            ReferenceApplyTerminalOutcomeV1::InterruptedButNowExactZero
        }
    }
}

const fn canonical_apply_terminal_lifecycle(
    value: ReferenceApplyTerminalLifecycleEffectV1,
) -> CanonicalApplyTerminalLifecycleEffectV1 {
    match value {
        ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted => {
            CanonicalApplyTerminalLifecycleEffectV1::ProvenNotStarted
        }
        ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted => {
            CanonicalApplyTerminalLifecycleEffectV1::MayHaveStarted
        }
    }
}

const fn public_apply_terminal_lifecycle(
    value: CanonicalApplyTerminalLifecycleEffectV1,
) -> ReferenceApplyTerminalLifecycleEffectV1 {
    match value {
        CanonicalApplyTerminalLifecycleEffectV1::ProvenNotStarted => {
            ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted
        }
        CanonicalApplyTerminalLifecycleEffectV1::MayHaveStarted => {
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted
        }
    }
}

fn strict_projection(
    manifest: &VerifiedRuntimeManifestIngressV1,
) -> Result<RuntimeArtifactCompatibilityManifestProjectionV1, ReferenceControlError> {
    Ok(RuntimeArtifactCompatibilityManifestProjectionV1::decode(
        manifest.projection_canonical_wire(),
    )?)
}

const fn fixture_from_manifest(
    manifest: &VerifiedRuntimeManifestIngressV1,
) -> ReferenceFixtureEntryV1 {
    ReferenceFixtureEntryV1::new(
        manifest.fixture_definition(),
        manifest.fixture_implementation(),
        FixtureExportRef::from_bytes(manifest.fixture_export()),
        manifest.fixture_definition_digest(),
        manifest.fixture_artifact_digest(),
    )
}

/// Opaque identity of one authenticated bootstrap request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReferenceBootstrapRequestIdV1 {
    inner: BootstrapRequestId,
}

impl ReferenceBootstrapRequestIdV1 {
    /// Creates a request identity from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            inner: BootstrapRequestId::from_bytes(bytes),
        }
    }

    /// Returns the canonical request identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.inner.as_bytes()
    }
}

/// Sealed, identity-bound local Runtime control channel facts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceChannelBindingV1 {
    inner: CanonicalChannelBindingV1,
}

impl ReferenceChannelBindingV1 {
    /// Binds target, Runtime peer, endpoint identity and peer credentials.
    pub fn try_new(
        target: RuntimeHostId,
        runtime_peer: PrincipalRef,
        local_endpoint_identity_digest: Digest32,
        peer_credentials_digest: Digest32,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalChannelBindingV1::try_new(
                target,
                runtime_peer,
                local_endpoint_identity_digest,
                peer_credentials_digest,
            )?,
        })
    }

    /// Returns the bound Runtime target.
    #[must_use]
    pub const fn target(self) -> RuntimeHostId {
        self.inner.target()
    }

    /// Returns the authenticated local Runtime peer.
    #[must_use]
    pub const fn runtime_peer(self) -> PrincipalRef {
        self.inner.runtime_peer()
    }

    /// Returns the endpoint identity digest.
    #[must_use]
    pub const fn local_endpoint_identity_digest(self) -> Digest32 {
        self.inner.local_endpoint_identity_digest()
    }

    /// Returns the peer-credential digest.
    #[must_use]
    pub const fn peer_credentials_digest(self) -> Digest32 {
        self.inner.peer_credentials_digest()
    }

    /// Returns the domain-separated channel binding digest.
    #[must_use]
    pub const fn binding_digest(self) -> Digest32 {
        self.inner.binding_digest()
    }
}

/// Canonical authenticated-control-read signing transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceBootstrapSigningTranscriptV1 {
    inner: ControlReadSigningTranscriptV1,
}

impl ReferenceBootstrapSigningTranscriptV1 {
    /// Returns exact bytes for a bootstrap signer or verifier.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

/// Signature-independent authenticated bootstrap request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceBootstrapRequestDraftV1 {
    inner: RuntimeBootstrapRequestDraftV1,
}

impl ReferenceBootstrapRequestDraftV1 {
    /// Builds a bounded request without writer-tenure authority.
    pub fn try_new(
        request_id: ReferenceBootstrapRequestIdV1,
        target: RuntimeHostId,
        source_scope: crate::provenance::SourceScopeRef,
        auth_claim: ApplyRequestAuthClaim,
        max_response_bytes: u32,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: RuntimeBootstrapRequestDraftV1::try_new(
                request_id.inner,
                target,
                source_scope,
                auth_claim,
                max_response_bytes,
            )?,
        })
    }

    /// Returns the exact Controller request-auth signing transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceBootstrapSigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceBootstrapSigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Finalizes the signed canonical bootstrap request.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ReferenceBootstrapRequestV1, ReferenceControlError> {
        Ok(ReferenceBootstrapRequestV1 {
            inner: self.inner.finalize(signature)?,
        })
    }
}

/// Signed, bounded, strict bootstrap request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceBootstrapRequestV1 {
    inner: CanonicalBootstrapRequestV1,
}

impl ReferenceBootstrapRequestV1 {
    /// Strictly decodes exactly the bootstrap v1 protocol.
    pub fn decode(frame: &[u8]) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalBootstrapRequestV1::decode(frame)?,
        })
    }

    /// Returns the request identity.
    #[must_use]
    pub const fn request_id(&self) -> ReferenceBootstrapRequestIdV1 {
        ReferenceBootstrapRequestIdV1 {
            inner: self.inner.request_id(),
        }
    }

    /// Returns the requested Runtime target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.inner.target()
    }

    /// Returns the Controller-owned source scope.
    #[must_use]
    pub const fn source_scope(&self) -> crate::provenance::SourceScopeRef {
        self.inner.source_scope()
    }

    /// Returns the request signer claim and opaque signature.
    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        self.inner.authentication()
    }

    /// Returns the requester's exact response byte bound.
    #[must_use]
    pub const fn max_response_bytes(&self) -> u32 {
        self.inner.max_response_bytes()
    }

    /// Returns exact canonical request bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        self.inner.canonical_wire()
    }

    /// Returns the domain-separated request digest echoed by the response.
    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.inner.request_digest()
    }

    /// Reconstructs the exact Controller request-auth transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceBootstrapSigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceBootstrapSigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }
}

/// Exact Runtime host/store/snapshot/clock identity served at bootstrap.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceBootstrapServingIdentityV1 {
    inner: CanonicalBootstrapServingIdentityV1,
}

impl ReferenceBootstrapServingIdentityV1 {
    /// Validates nonzero store, snapshot sequence and Runtime epoch facts.
    pub fn try_new(
        target: RuntimeHostId,
        runtime_store_instance_id: [u8; 32],
        snapshot_sequence: u64,
        runtime_host_epoch: u64,
        clock_domain: ClockDomainRef,
        clock_generation: ClockGeneration,
    ) -> Result<Self, ReferenceControlError> {
        let store = RuntimeStoreInstanceId::try_from_bytes(runtime_store_instance_id)?;
        let sequence = RuntimeSnapshotSequence::try_new(snapshot_sequence)?;
        let epoch = RuntimeHostEpoch::try_new(runtime_host_epoch)?;
        Ok(Self {
            inner: CanonicalBootstrapServingIdentityV1::new(
                target,
                store,
                sequence,
                epoch,
                clock_domain,
                clock_generation,
            ),
        })
    }

    /// Returns the serving Runtime target.
    #[must_use]
    pub const fn target(self) -> RuntimeHostId {
        self.inner.target()
    }

    /// Returns the serving journal store identity.
    #[must_use]
    pub const fn runtime_store_instance_id(self) -> [u8; 32] {
        *self.inner.store_instance_id().as_bytes()
    }

    /// Returns the validated nonzero snapshot sequence.
    #[must_use]
    pub const fn snapshot_sequence(self) -> u64 {
        self.inner.snapshot_sequence().value()
    }

    /// Returns the validated nonzero Runtime process epoch.
    #[must_use]
    pub const fn runtime_host_epoch(self) -> u64 {
        self.inner.runtime_host_epoch().value()
    }

    /// Returns the target-local monotonic clock domain.
    #[must_use]
    pub const fn clock_domain(self) -> ClockDomainRef {
        self.inner.clock_domain()
    }

    /// Returns the target-local monotonic clock generation.
    #[must_use]
    pub const fn clock_generation(self) -> ClockGeneration {
        self.inner.clock_generation()
    }
}

/// Controller-side bootstrap expectation derived from immutable install truth.
///
/// Unlike Runtime startup compatibility, Controller cannot and must not invent
/// the executable's compiled-actual facts. This token therefore comes only
/// from a strict `VerifiedRuntimeManifestIngressV1` and an independently
/// derived admission-policy fingerprint. Response validation compares the
/// manifest's complete build identity/profile/fixture row with both the
/// compiled-actual and store-pinned facts reported by Runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceControllerBootstrapExpectationV1 {
    manifest: RuntimeArtifactCompatibilityManifestV1,
    admission_policy_fingerprint: Digest32,
}

impl ReferenceControllerBootstrapExpectationV1 {
    /// Builds a sealed Controller expectation without accepting raw build,
    /// profile, fixture, or target fields.
    pub fn try_from_verified_manifest(
        manifest_ingress: &VerifiedRuntimeManifestIngressV1,
        admission_policy: ReferenceAdmissionPolicyFingerprintV1,
    ) -> Result<Self, ReferenceControlError> {
        let manifest = RuntimeArtifactCompatibilityManifestV1::decode(
            manifest_ingress.manifest_canonical_wire(),
        )?;
        if manifest.manifest_digest() != manifest_ingress.manifest_digest()
            || manifest.row().target() != manifest_ingress.target()
        {
            return Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidCompatibility,
            ));
        }
        Ok(Self {
            manifest,
            admission_policy_fingerprint: admission_policy.digest(),
        })
    }

    /// Returns the exact target selected by the immutable manifest.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.manifest.row().target()
    }

    /// Returns the exact singleton manifest digest.
    #[must_use]
    pub const fn manifest_digest(&self) -> Digest32 {
        self.manifest.manifest_digest()
    }

    /// Returns the independently derived admission-policy fingerprint.
    #[must_use]
    pub const fn admission_policy_fingerprint(&self) -> Digest32 {
        self.admission_policy_fingerprint
    }
}

/// Verified compiled-actual and store-pinned Runtime compatibility.
///
/// There is no raw constructor. The token can only be derived from the strict
/// installation verifier and independently compiled executable facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceBootstrapCompatibilityV1 {
    inner: CanonicalBootstrapCompatibilityV1,
    manifest: RuntimeArtifactCompatibilityManifestV1,
}

impl ReferenceBootstrapCompatibilityV1 {
    /// Derives bootstrap compatibility from a strict pinned startup/install token.
    pub fn try_from_verified_installation(
        installation: &VerifiedRuntimeInstallationV1,
        compiled: RuntimeCompiledInstallationFactsV1,
        admission_policy_fingerprint: Digest32,
    ) -> Result<Self, ReferenceControlError> {
        let descriptor =
            RuntimeBuildDescriptorV1::decode(installation.descriptor_canonical_wire())?;
        let manifest =
            RuntimeArtifactCompatibilityManifestV1::decode(installation.manifest_canonical_wire())?;
        if descriptor.descriptor_digest() != installation.descriptor_digest()
            || manifest.manifest_digest() != installation.manifest_digest()
        {
            return Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidCompatibility,
            ));
        }
        let store_pinned_build_identity = RuntimeBuildIdentityV1::from_descriptor(&descriptor);
        let compiled_compatibility_digest = compiled.compiled_reference_compatibility_digest()?;
        let inner = CanonicalBootstrapCompatibilityV1::try_new(
            compiled.build_instance_id(),
            compiled_compatibility_digest,
            store_pinned_build_identity,
            &manifest,
            compiled.fixture(),
            admission_policy_fingerprint,
        )?;
        Ok(Self { inner, manifest })
    }

    /// Returns the exact Runtime target selected by the manifest.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.manifest.row().target()
    }

    /// Returns the independently compiled build instance ID.
    #[must_use]
    pub const fn compiled_build_instance_id(&self) -> [u8; 32] {
        *self.inner.compiled_build_instance_id().as_bytes()
    }

    /// Returns the independently compiled reference compatibility digest.
    #[must_use]
    pub const fn compiled_compatibility_digest(&self) -> Digest32 {
        self.inner.compiled_compatibility_digest()
    }

    /// Returns the store-pinned build instance ID.
    #[must_use]
    pub const fn store_pinned_build_instance_id(&self) -> [u8; 32] {
        *self
            .inner
            .store_pinned_build_identity()
            .build_instance_id()
            .as_bytes()
    }

    /// Returns the store-pinned descriptor digest.
    #[must_use]
    pub const fn store_pinned_build_descriptor_digest(&self) -> Digest32 {
        self.inner
            .store_pinned_build_identity()
            .build_descriptor_digest()
    }

    /// Returns the store-pinned Runtime executable SHA-256.
    #[must_use]
    pub const fn store_pinned_runtime_artifact_sha256(&self) -> Digest32 {
        self.inner
            .store_pinned_build_identity()
            .runtime_artifact_sha256()
    }

    /// Returns the store-pinned compiled compatibility digest.
    #[must_use]
    pub const fn store_pinned_compiled_compatibility_digest(&self) -> Digest32 {
        self.inner
            .store_pinned_build_identity()
            .compiled_reference_compatibility_digest()
    }

    /// Returns the exact singleton manifest digest.
    #[must_use]
    pub const fn manifest_digest(&self) -> Digest32 {
        self.inner.manifest_digest()
    }

    /// Returns the exact fixed-profile fingerprint.
    #[must_use]
    pub const fn profile_fingerprint(&self) -> Digest32 {
        self.inner.profile_fingerprint()
    }

    /// Returns the Runtime admission-policy fingerprint.
    #[must_use]
    pub const fn admission_policy_fingerprint(&self) -> Digest32 {
        self.inner.admission_policy_fingerprint()
    }
}

/// Stable bootstrap readiness state, distinct from operation completion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceBootstrapStateV1 {
    /// Runtime is ready to admit apply requests.
    ReadyForApply,
    /// Startup recovery remains in progress.
    NotReadyRecovering,
    /// Validated identity is available while operationally quarantined.
    ValidatedOperationalQuarantine,
    /// Recovery failed and apply is not ready.
    RecoveryFailedNotReady,
    /// Runtime is temporarily busy and not ready.
    NotReadyBusy,
}

/// Stable post-start operational reason.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceOperationalReasonV1 {
    /// Startup recovery is still running.
    Recovering,
    /// Active desired state is incompatible with the pinned build.
    ActiveCompatibilityMismatch,
    /// Recovery failed.
    RecoveryFailed,
    /// Resource ownership is uncertain.
    OwnershipUncertain,
    /// Required durable history is unavailable.
    HistoryUnavailable,
    /// Resource census is uncertain.
    ResourceCensusUncertain,
    /// Runtime is busy.
    RuntimeBusy,
    /// An explicit ownership transfer is required.
    OwnershipTransferRequired,
}

/// Sealed Runtime bootstrap facts used to build or obtained from a response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceBootstrapFactsV1 {
    inner: CanonicalBootstrapFactsV1,
}

impl ReferenceBootstrapFactsV1 {
    /// Combines validated serving identity and pinned compatibility facts.
    pub fn try_new(
        serving: ReferenceBootstrapServingIdentityV1,
        compatibility: &ReferenceBootstrapCompatibilityV1,
        state: ReferenceBootstrapStateV1,
        reason: Option<ReferenceOperationalReasonV1>,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalBootstrapFactsV1::try_new(
                serving.inner,
                compatibility.inner,
                canonical_bootstrap_state(state),
                reason.map(canonical_operational_reason),
            )?,
        })
    }

    /// Returns the serving Runtime target.
    #[must_use]
    pub const fn target(self) -> RuntimeHostId {
        self.inner.target()
    }

    /// Returns the exact Runtime journal store identity.
    #[must_use]
    pub const fn runtime_store_instance_id(self) -> [u8; 32] {
        *self.inner.store_instance_id().as_bytes()
    }

    /// Returns the nonzero snapshot sequence.
    #[must_use]
    pub const fn snapshot_sequence(self) -> u64 {
        self.inner.snapshot_sequence().value()
    }

    /// Returns the nonzero Runtime process epoch.
    #[must_use]
    pub const fn runtime_host_epoch(self) -> u64 {
        self.inner.runtime_host_epoch().value()
    }

    /// Returns the target-local monotonic clock domain.
    #[must_use]
    pub const fn clock_domain(self) -> ClockDomainRef {
        self.inner.clock_domain()
    }

    /// Returns the target-local monotonic clock generation.
    #[must_use]
    pub const fn clock_generation(self) -> ClockGeneration {
        self.inner.clock_generation()
    }

    /// Returns the independently compiled build instance ID.
    #[must_use]
    pub const fn compiled_build_instance_id(self) -> [u8; 32] {
        *self.inner.compiled_build_instance_id().as_bytes()
    }

    /// Returns the independently compiled compatibility digest.
    #[must_use]
    pub const fn compiled_compatibility_digest(self) -> Digest32 {
        self.inner.compiled_compatibility_digest()
    }

    /// Returns the store-pinned build instance ID.
    #[must_use]
    pub const fn store_pinned_build_instance_id(self) -> [u8; 32] {
        *self
            .inner
            .store_pinned_build_identity()
            .build_instance_id()
            .as_bytes()
    }

    /// Returns the store-pinned descriptor digest.
    #[must_use]
    pub const fn store_pinned_build_descriptor_digest(self) -> Digest32 {
        self.inner
            .store_pinned_build_identity()
            .build_descriptor_digest()
    }

    /// Returns the store-pinned Runtime artifact SHA-256.
    #[must_use]
    pub const fn store_pinned_runtime_artifact_sha256(self) -> Digest32 {
        self.inner
            .store_pinned_build_identity()
            .runtime_artifact_sha256()
    }

    /// Returns the store-pinned compiled compatibility digest.
    #[must_use]
    pub const fn store_pinned_compiled_compatibility_digest(self) -> Digest32 {
        self.inner
            .store_pinned_build_identity()
            .compiled_reference_compatibility_digest()
    }

    /// Returns the exact manifest digest.
    #[must_use]
    pub const fn manifest_digest(self) -> Digest32 {
        self.inner.manifest_digest()
    }

    /// Returns the exact fixed-profile fingerprint.
    #[must_use]
    pub const fn profile_fingerprint(self) -> Digest32 {
        self.inner.profile_fingerprint()
    }

    /// Returns the Runtime admission-policy fingerprint.
    #[must_use]
    pub const fn admission_policy_fingerprint(self) -> Digest32 {
        self.inner.admission_policy_fingerprint()
    }

    /// Returns the bootstrap readiness state.
    #[must_use]
    pub const fn state(self) -> ReferenceBootstrapStateV1 {
        public_bootstrap_state(self.inner.state())
    }

    /// Returns the optional stable operational reason.
    #[must_use]
    pub const fn reason(self) -> Option<ReferenceOperationalReasonV1> {
        match self.inner.reason() {
            Some(reason) => Some(public_operational_reason(reason)),
            None => None,
        }
    }
}

/// Sealed response-signer claim bound to one live channel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceBootstrapResponseAuthClaimV1 {
    inner: RuntimeResponseAuthClaimV1,
}

impl ReferenceBootstrapResponseAuthClaimV1 {
    /// Selects a Runtime response key while deriving peer/channel facts from the binding.
    pub fn try_new(
        channel: ReferenceChannelBindingV1,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: RuntimeResponseAuthClaimV1::try_new(
                channel.runtime_peer(),
                channel.binding_digest(),
                key,
                algorithm,
                algorithm_version,
            )?,
        })
    }

    /// Returns the authenticated Runtime peer.
    #[must_use]
    pub const fn runtime_peer(self) -> PrincipalRef {
        self.inner.runtime_peer()
    }

    /// Returns the bound live-channel digest.
    #[must_use]
    pub const fn channel_binding_digest(self) -> Digest32 {
        self.inner.channel_binding_digest()
    }

    /// Returns the selected response-auth key.
    #[must_use]
    pub const fn key(self) -> ApplyAuthKeyRef {
        self.inner.key()
    }

    /// Returns the response-auth algorithm selector.
    #[must_use]
    pub const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.inner.algorithm()
    }

    /// Returns the response-auth algorithm version.
    #[must_use]
    pub const fn algorithm_version(self) -> u16 {
        self.inner.algorithm_version()
    }
}

/// Signature-independent authenticated bootstrap response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceBootstrapResponseDraftV1 {
    inner: CanonicalBootstrapResponseDraftV1,
}

impl ReferenceBootstrapResponseDraftV1 {
    /// Binds one request, validated facts, live channel and response signer.
    pub fn try_new(
        request: &ReferenceBootstrapRequestV1,
        facts: ReferenceBootstrapFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ReferenceBootstrapResponseAuthClaimV1,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalBootstrapResponseDraftV1::try_new(
                &request.inner,
                facts.inner,
                channel.inner,
                auth_claim.inner,
            )?,
        })
    }

    /// Returns the exact Runtime response-auth signing transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceBootstrapSigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceBootstrapSigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Finalizes the signed, response-bound canonical frame.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ReferenceBootstrapResponseV1, ReferenceControlError> {
        Ok(ReferenceBootstrapResponseV1 {
            inner: self.inner.finalize(signature)?,
        })
    }
}

/// Signed, strict authenticated bootstrap response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceBootstrapResponseV1 {
    inner: CanonicalBootstrapResponseV1,
}

impl ReferenceBootstrapResponseV1 {
    /// Strictly decodes exactly the bootstrap v1 response protocol.
    pub fn decode(frame: &[u8]) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalBootstrapResponseV1::decode(frame)?,
        })
    }

    /// Returns the echoed request identity.
    #[must_use]
    pub const fn request_id(&self) -> ReferenceBootstrapRequestIdV1 {
        ReferenceBootstrapRequestIdV1 {
            inner: self.inner.request_id(),
        }
    }

    /// Returns the echoed exact request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.inner.request_digest()
    }

    /// Returns the echoed Controller nonce.
    #[must_use]
    pub fn client_nonce(&self) -> &[u8] {
        self.inner.client_nonce()
    }

    /// Returns decoded Runtime facts. Treat them as untrusted until signature
    /// verification and `validate_against_request` both succeed.
    #[must_use]
    pub const fn facts(&self) -> ReferenceBootstrapFactsV1 {
        ReferenceBootstrapFactsV1 {
            inner: self.inner.facts(),
        }
    }

    /// Returns the response signer Runtime peer.
    #[must_use]
    pub const fn authentication_runtime_peer(&self) -> PrincipalRef {
        self.inner.authentication().claim().runtime_peer()
    }

    /// Returns the response live-channel binding digest.
    #[must_use]
    pub const fn authentication_channel_binding_digest(&self) -> Digest32 {
        self.inner.authentication().claim().channel_binding_digest()
    }

    /// Returns the selected response verification-key reference.
    #[must_use]
    pub const fn authentication_key(&self) -> ApplyAuthKeyRef {
        self.inner.authentication().claim().key()
    }

    /// Returns the response signature algorithm selector.
    #[must_use]
    pub const fn authentication_algorithm(&self) -> ApplyAuthAlgorithm {
        self.inner.authentication().claim().algorithm()
    }

    /// Returns the response signature algorithm version.
    #[must_use]
    pub const fn authentication_algorithm_version(&self) -> u16 {
        self.inner.authentication().claim().algorithm_version()
    }

    /// Returns the opaque Runtime response signature.
    #[must_use]
    pub fn authentication_signature(&self) -> &[u8] {
        self.inner.authentication().signature()
    }

    /// Returns exact canonical response bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        self.inner.canonical_wire()
    }

    /// Returns the domain-separated response digest.
    #[must_use]
    pub const fn response_digest(&self) -> Digest32 {
        self.inner.response_digest()
    }

    /// Reconstructs the exact Runtime response-auth transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceBootstrapSigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceBootstrapSigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Validates request echoes, target/channel binding, response bound, exact
    /// install compatibility, fixed profile and admission-policy fingerprint.
    /// Signature verification against `signing_transcript()` remains the
    /// caller-owned cryptographic step and must precede trusting returned facts.
    pub fn validate_against_request(
        &self,
        request: &ReferenceBootstrapRequestV1,
        channel: ReferenceChannelBindingV1,
        expected: &ReferenceBootstrapCompatibilityV1,
    ) -> Result<ReferenceBootstrapFactsV1, ReferenceControlError> {
        self.inner.validate_against_request(
            &request.inner,
            channel.inner,
            &expected.manifest,
            expected.admission_policy_fingerprint(),
        )?;
        Ok(self.facts())
    }

    /// Controller-side validation against immutable manifest truth and an
    /// independently derived admission-policy fingerprint.
    pub fn validate_against_controller_expectation(
        &self,
        request: &ReferenceBootstrapRequestV1,
        channel: ReferenceChannelBindingV1,
        expected: &ReferenceControllerBootstrapExpectationV1,
    ) -> Result<ReferenceBootstrapFactsV1, ReferenceControlError> {
        self.inner.validate_against_request(
            &request.inner,
            channel.inner,
            &expected.manifest,
            expected.admission_policy_fingerprint,
        )?;
        Ok(self.facts())
    }
}

/// Opaque identity of one authenticated operation/live query.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReferenceQueryIdV1 {
    inner: RuntimeQueryId,
}

impl ReferenceQueryIdV1 {
    /// Creates a query identity from canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            inner: RuntimeQueryId::from_bytes(bytes),
        }
    }

    /// Returns canonical query identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.inner.as_bytes()
    }
}

/// Fixed selector shared by the query draft and its strict decoder.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceQuerySelectorV1 {
    inner: CanonicalQuerySelectorV1,
}

impl ReferenceQuerySelectorV1 {
    /// Selects one target-local operation and optional exact request identity.
    pub fn try_new(
        query_id: ReferenceQueryIdV1,
        target: RuntimeHostId,
        source_scope: SourceScopeRef,
        expected_runtime_store_instance_id: [u8; 32],
        requested_operation_id: ApplyOperationId,
        expected_request_digest: Option<Digest32>,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalQuerySelectorV1::try_new(
                query_id.inner,
                target,
                source_scope,
                RuntimeStoreInstanceId::try_from_bytes(expected_runtime_store_instance_id)?,
                requested_operation_id,
                expected_request_digest,
            )?,
        })
    }

    /// Returns the query identity.
    #[must_use]
    pub const fn query_id(self) -> ReferenceQueryIdV1 {
        ReferenceQueryIdV1 {
            inner: self.inner.query_id(),
        }
    }

    /// Returns the selected Runtime target.
    #[must_use]
    pub const fn target(self) -> RuntimeHostId {
        self.inner.target()
    }

    /// Returns the selected desired-state source scope.
    #[must_use]
    pub const fn source_scope(self) -> SourceScopeRef {
        self.inner.source_scope()
    }

    /// Returns the expected journal store identity.
    #[must_use]
    pub const fn expected_runtime_store_instance_id(self) -> [u8; 32] {
        *self.inner.expected_store_instance_id().as_bytes()
    }

    /// Returns the selected apply operation identity.
    #[must_use]
    pub const fn requested_operation_id(self) -> ApplyOperationId {
        self.inner.requested_operation_id()
    }

    /// Returns the optional exact request digest expectation.
    #[must_use]
    pub const fn expected_request_digest(self) -> Option<Digest32> {
        self.inner.expected_request_digest()
    }
}

/// Exact canonical query request or response signing transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceQuerySigningTranscriptV1 {
    inner: ControlReadSigningTranscriptV1,
}

impl ReferenceQuerySigningTranscriptV1 {
    /// Returns the exact bytes a signer signs or a verifier verifies.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

/// Signature-independent authenticated operation/live query request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceQueryRequestDraftV1 {
    inner: CanonicalQueryRequestDraftV1,
}

impl ReferenceQueryRequestDraftV1 {
    /// Builds a bounded singleton query without advancing Runtime state.
    pub fn try_new(
        selector: ReferenceQuerySelectorV1,
        auth_claim: ApplyRequestAuthClaim,
        max_response_bytes: u32,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalQueryRequestDraftV1::try_new(
                selector.inner,
                auth_claim,
                max_response_bytes,
            )?,
        })
    }

    /// Returns the exact Controller request-auth transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceQuerySigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceQuerySigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Finalizes the signed canonical PXQR v1 frame.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ReferenceQueryRequestV1, ReferenceControlError> {
        Ok(ReferenceQueryRequestV1 {
            inner: self.inner.finalize(signature)?,
        })
    }
}

/// Signed, strict, read-only PXQR v1 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceQueryRequestV1 {
    inner: CanonicalQueryRequestV1,
}

impl ReferenceQueryRequestV1 {
    /// Strictly decodes exactly the PXQR v1 protocol.
    pub fn decode(frame: &[u8]) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalQueryRequestV1::decode(frame)?,
        })
    }

    /// Returns the complete decoded selector.
    #[must_use]
    pub const fn selector(&self) -> ReferenceQuerySelectorV1 {
        ReferenceQuerySelectorV1 {
            inner: self.inner.selector(),
        }
    }

    /// Returns the query identity.
    #[must_use]
    pub const fn query_id(&self) -> ReferenceQueryIdV1 {
        ReferenceQueryIdV1 {
            inner: self.inner.query_id(),
        }
    }

    /// Returns the selected Runtime target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.inner.target()
    }

    /// Returns the selected desired-state source scope.
    #[must_use]
    pub const fn source_scope(&self) -> SourceScopeRef {
        self.inner.source_scope()
    }

    /// Returns the expected journal store identity.
    #[must_use]
    pub const fn expected_runtime_store_instance_id(&self) -> [u8; 32] {
        *self.inner.expected_store_instance_id().as_bytes()
    }

    /// Returns the selected operation identity.
    #[must_use]
    pub const fn requested_operation_id(&self) -> ApplyOperationId {
        self.inner.requested_operation_id()
    }

    /// Returns the optional exact request digest expectation.
    #[must_use]
    pub const fn expected_request_digest(&self) -> Option<Digest32> {
        self.inner.expected_request_digest()
    }

    /// Returns the request authentication claim and opaque signature.
    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        self.inner.authentication()
    }

    /// Returns the Controller-selected canonical response byte bound.
    #[must_use]
    pub const fn max_response_bytes(&self) -> u32 {
        self.inner.max_response_bytes()
    }

    /// Returns exact canonical PXQR bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        self.inner.canonical_wire()
    }

    /// Returns the domain-separated exact request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.inner.request_digest()
    }

    /// Reconstructs the exact Controller request-auth transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceQuerySigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceQuerySigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Fails closed unless the local journal store is the signed expected store.
    pub fn validate_expected_store(
        &self,
        local_runtime_store_instance_id: [u8; 32],
    ) -> Result<(), ReferenceControlError> {
        let store = RuntimeStoreInstanceId::try_from_bytes(local_runtime_store_instance_id)?;
        self.inner.validate_expected_store(store)?;
        Ok(())
    }
}

/// Runtime ownership/readiness state reported with a query result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceQueryOwnerStateV1 {
    Operational,
    ApplyDisabled,
    OwnershipUncertain,
}

/// Durable progress marker for one known apply operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceQueryDurablePhaseV1 {
    PreparedNoEffects,
    FirstActionIntent,
    HeadCommittedRetiringOld,
    Terminal,
}

/// Exact durable operation lookup result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceQueryOperationLookupV1 {
    Known {
        request_digest: Digest32,
        durable_phase: ReferenceQueryDurablePhaseV1,
        terminal_result: Option<ReferenceApplyTerminalResultRefV1>,
    },
    Conflict {
        existing_request_digest: Digest32,
    },
    Unknown,
    Indeterminate {
        reason: ReferenceOperationalReasonV1,
    },
}

/// Validated Runtime ownership state and operation lookup.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceQueryOperationStateV1 {
    inner: CanonicalQueryOperationStateV1,
}

impl ReferenceQueryOperationStateV1 {
    /// Validates owner/reason and lookup/reason consistency.
    pub fn try_new(
        owner_state: ReferenceQueryOwnerStateV1,
        reason: Option<ReferenceOperationalReasonV1>,
        lookup: ReferenceQueryOperationLookupV1,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalQueryOperationStateV1::try_new(
                canonical_query_owner_state(owner_state),
                reason.map(canonical_operational_reason),
                canonical_query_operation_lookup(lookup)?,
            )?,
        })
    }

    /// Returns Runtime ownership/readiness state.
    #[must_use]
    pub const fn owner_state(self) -> ReferenceQueryOwnerStateV1 {
        public_query_owner_state(self.inner.owner_state())
    }

    /// Returns the optional stable operational reason.
    #[must_use]
    pub const fn reason(self) -> Option<ReferenceOperationalReasonV1> {
        match self.inner.reason() {
            Some(reason) => Some(public_operational_reason(reason)),
            None => None,
        }
    }

    /// Returns the exact operation lookup result.
    #[must_use]
    pub const fn lookup(self) -> ReferenceQueryOperationLookupV1 {
        public_query_operation_lookup(self.inner.lookup())
    }
}

/// Durable desired head, distinct from current live materialization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceQueryDesiredHeadV1 {
    None,
    OneSourceLoop {
        source_revision: SourcePlanRevision,
        target_slice_digest: TargetSliceDigest,
        manifest_digest: Digest32,
    },
    EmptyDeactivate {
        source_revision: SourcePlanRevision,
        target_slice_digest: TargetSliceDigest,
        manifest_digest: Digest32,
    },
}

/// Validated desired head and source revision high-water mark.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceQueryDesiredStateV1 {
    inner: CanonicalDesiredStateV1,
}

impl ReferenceQueryDesiredStateV1 {
    /// Validates the desired head and monotonic source revision bound.
    pub fn try_new(
        head: ReferenceQueryDesiredHeadV1,
        source_revision_high_water: SourcePlanRevision,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalDesiredStateV1::try_new(
                canonical_query_desired_head(head)?,
                source_revision_high_water,
            )?,
        })
    }

    /// Returns the durable desired head.
    #[must_use]
    pub const fn head(self) -> ReferenceQueryDesiredHeadV1 {
        public_query_desired_head(self.inner.head())
    }

    /// Returns the monotonic source revision high-water mark.
    #[must_use]
    pub const fn source_revision_high_water(self) -> SourcePlanRevision {
        self.inner.source_revision_high_water()
    }
}

/// Current target-local live materialization state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceQueryLiveStateV1 {
    NotReady,
    Recovering,
    LiveReady,
    Draining,
    RecoveryFailedNotReady,
    ExactZero,
    ValidatedOperationalQuarantine,
    Uncertain,
}

/// Validated live state, generation, observation time and resource census.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceQueryLiveFactsV1 {
    inner: CanonicalLiveFactsV1,
}

impl ReferenceQueryLiveFactsV1 {
    /// Validates the live-state generation matrix and nonzero census digest.
    pub fn try_new(
        state: ReferenceQueryLiveStateV1,
        resource_generation: u64,
        measured_at: u64,
        census_digest: Digest32,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalLiveFactsV1::try_new(
                canonical_query_live_state(state),
                resource_generation,
                measured_at,
                census_digest,
            )?,
        })
    }

    /// Returns the current live materialization state.
    #[must_use]
    pub const fn state(self) -> ReferenceQueryLiveStateV1 {
        public_query_live_state(self.inner.state())
    }

    /// Returns the target-local resource generation.
    #[must_use]
    pub const fn resource_generation(self) -> u64 {
        self.inner.resource_generation()
    }

    /// Returns the target-local observation timestamp.
    #[must_use]
    pub const fn measured_at(self) -> u64 {
        self.inner.measured_at()
    }

    /// Returns the nonzero resource census digest.
    #[must_use]
    pub const fn census_digest(self) -> Digest32 {
        self.inner.census_digest()
    }
}

/// Complete validated query facts before response authentication.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceQueryFactsV1 {
    inner: CanonicalQueryFactsV1,
}

impl ReferenceQueryFactsV1 {
    /// Validates cross-shape consistency across serving, operation, desired and live facts.
    pub fn try_new(
        serving: ReferenceBootstrapServingIdentityV1,
        operation: ReferenceQueryOperationStateV1,
        desired: ReferenceQueryDesiredStateV1,
        live: ReferenceQueryLiveFactsV1,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalQueryFactsV1::try_new(
                serving.inner,
                operation.inner,
                desired.inner,
                live.inner,
            )?,
        })
    }

    /// Returns exact Runtime serving identity.
    #[must_use]
    pub const fn serving(self) -> ReferenceBootstrapServingIdentityV1 {
        ReferenceBootstrapServingIdentityV1 {
            inner: self.inner.serving(),
        }
    }

    /// Returns operation lookup and ownership facts.
    #[must_use]
    pub const fn operation(self) -> ReferenceQueryOperationStateV1 {
        ReferenceQueryOperationStateV1 {
            inner: self.inner.operation(),
        }
    }

    /// Returns durable desired-state facts.
    #[must_use]
    pub const fn desired(self) -> ReferenceQueryDesiredStateV1 {
        ReferenceQueryDesiredStateV1 {
            inner: self.inner.desired(),
        }
    }

    /// Returns current live materialization facts.
    #[must_use]
    pub const fn live(self) -> ReferenceQueryLiveFactsV1 {
        ReferenceQueryLiveFactsV1 {
            inner: self.inner.live(),
        }
    }
}

/// Query responses use the same live-channel signer claim as bootstrap.
pub type ReferenceQueryResponseAuthClaimV1 = ReferenceBootstrapResponseAuthClaimV1;

/// Signature-independent authenticated PXQS v1 response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceQueryResponseDraftV1 {
    inner: CanonicalQueryResponseDraftV1,
}

impl ReferenceQueryResponseDraftV1 {
    /// Binds one query, validated facts, live channel and response signer.
    pub fn try_new(
        request: &ReferenceQueryRequestV1,
        facts: ReferenceQueryFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ReferenceQueryResponseAuthClaimV1,
    ) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalQueryResponseDraftV1::try_new(
                &request.inner,
                facts.inner,
                channel.inner,
                auth_claim.inner,
            )?,
        })
    }

    /// Returns the exact Runtime response-auth transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceQuerySigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceQuerySigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Finalizes the signed, response-bound canonical PXQS frame.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ReferenceQueryResponseV1, ReferenceControlError> {
        Ok(ReferenceQueryResponseV1 {
            inner: self.inner.finalize(signature)?,
        })
    }
}

/// Signed, strict authenticated PXQS v1 response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceQueryResponseV1 {
    inner: CanonicalQueryResponseV1,
}

impl ReferenceQueryResponseV1 {
    /// Strictly decodes exactly the PXQS v1 protocol.
    pub fn decode(frame: &[u8]) -> Result<Self, ReferenceControlError> {
        Ok(Self {
            inner: CanonicalQueryResponseV1::decode(frame)?,
        })
    }

    /// Returns the echoed query identity.
    #[must_use]
    pub const fn query_id(&self) -> ReferenceQueryIdV1 {
        ReferenceQueryIdV1 {
            inner: self.inner.query_id(),
        }
    }

    /// Returns the echoed exact PXQR digest.
    #[must_use]
    pub const fn query_request_digest(&self) -> Digest32 {
        self.inner.query_request_digest()
    }

    /// Returns the echoed Controller nonce.
    #[must_use]
    pub fn client_nonce(&self) -> &[u8] {
        self.inner.client_nonce()
    }

    /// Returns decoded Runtime facts. Treat them as untrusted until signature
    /// verification and `validate_against_request` both succeed.
    #[must_use]
    pub const fn facts(&self) -> ReferenceQueryFactsV1 {
        ReferenceQueryFactsV1 {
            inner: self.inner.facts(),
        }
    }

    /// Returns the response signer Runtime peer.
    #[must_use]
    pub const fn authentication_runtime_peer(&self) -> PrincipalRef {
        self.inner.authentication().claim().runtime_peer()
    }

    /// Returns the response live-channel binding digest.
    #[must_use]
    pub const fn authentication_channel_binding_digest(&self) -> Digest32 {
        self.inner.authentication().claim().channel_binding_digest()
    }

    /// Returns the selected response verification-key reference.
    #[must_use]
    pub const fn authentication_key(&self) -> ApplyAuthKeyRef {
        self.inner.authentication().claim().key()
    }

    /// Returns the response signature algorithm selector.
    #[must_use]
    pub const fn authentication_algorithm(&self) -> ApplyAuthAlgorithm {
        self.inner.authentication().claim().algorithm()
    }

    /// Returns the response signature algorithm version.
    #[must_use]
    pub const fn authentication_algorithm_version(&self) -> u16 {
        self.inner.authentication().claim().algorithm_version()
    }

    /// Returns the opaque Runtime response signature.
    #[must_use]
    pub fn authentication_signature(&self) -> &[u8] {
        self.inner.authentication().signature()
    }

    /// Returns exact canonical PXQS bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        self.inner.canonical_wire()
    }

    /// Returns the domain-separated exact response digest.
    #[must_use]
    pub const fn response_digest(&self) -> Digest32 {
        self.inner.response_digest()
    }

    /// Reconstructs the exact Runtime response-auth transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ReferenceQuerySigningTranscriptV1, ReferenceControlError> {
        Ok(ReferenceQuerySigningTranscriptV1 {
            inner: self.inner.signing_transcript()?,
        })
    }

    /// Validates echoes, target/store/channel correlation, response bound,
    /// operation expectation and monotonic freshness against authenticated
    /// bootstrap serving identity. Signature verification remains caller-owned.
    pub fn validate_against_request(
        &self,
        request: &ReferenceQueryRequestV1,
        channel: ReferenceChannelBindingV1,
        serving_baseline: ReferenceBootstrapServingIdentityV1,
    ) -> Result<ReferenceQueryFactsV1, ReferenceControlError> {
        self.inner.validate_against_request(
            &request.inner,
            channel.inner,
            serving_baseline.inner,
        )?;
        Ok(self.facts())
    }
}

const fn canonical_query_owner_state(value: ReferenceQueryOwnerStateV1) -> CanonicalOwnerStateV1 {
    match value {
        ReferenceQueryOwnerStateV1::Operational => CanonicalOwnerStateV1::Operational,
        ReferenceQueryOwnerStateV1::ApplyDisabled => CanonicalOwnerStateV1::ApplyDisabled,
        ReferenceQueryOwnerStateV1::OwnershipUncertain => CanonicalOwnerStateV1::OwnershipUncertain,
    }
}

const fn public_query_owner_state(value: CanonicalOwnerStateV1) -> ReferenceQueryOwnerStateV1 {
    match value {
        CanonicalOwnerStateV1::Operational => ReferenceQueryOwnerStateV1::Operational,
        CanonicalOwnerStateV1::ApplyDisabled => ReferenceQueryOwnerStateV1::ApplyDisabled,
        CanonicalOwnerStateV1::OwnershipUncertain => ReferenceQueryOwnerStateV1::OwnershipUncertain,
    }
}

const fn canonical_query_durable_phase(
    value: ReferenceQueryDurablePhaseV1,
) -> CanonicalOperationDurablePhaseV1 {
    match value {
        ReferenceQueryDurablePhaseV1::PreparedNoEffects => {
            CanonicalOperationDurablePhaseV1::PreparedNoEffects
        }
        ReferenceQueryDurablePhaseV1::FirstActionIntent => {
            CanonicalOperationDurablePhaseV1::FirstActionIntent
        }
        ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld => {
            CanonicalOperationDurablePhaseV1::HeadCommittedRetiringOld
        }
        ReferenceQueryDurablePhaseV1::Terminal => CanonicalOperationDurablePhaseV1::Terminal,
    }
}

const fn public_query_durable_phase(
    value: CanonicalOperationDurablePhaseV1,
) -> ReferenceQueryDurablePhaseV1 {
    match value {
        CanonicalOperationDurablePhaseV1::PreparedNoEffects => {
            ReferenceQueryDurablePhaseV1::PreparedNoEffects
        }
        CanonicalOperationDurablePhaseV1::FirstActionIntent => {
            ReferenceQueryDurablePhaseV1::FirstActionIntent
        }
        CanonicalOperationDurablePhaseV1::HeadCommittedRetiringOld => {
            ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld
        }
        CanonicalOperationDurablePhaseV1::Terminal => ReferenceQueryDurablePhaseV1::Terminal,
    }
}

fn canonical_query_operation_lookup(
    value: ReferenceQueryOperationLookupV1,
) -> Result<CanonicalOperationLookupV1, ReferenceControlError> {
    Ok(match value {
        ReferenceQueryOperationLookupV1::Known {
            request_digest,
            durable_phase,
            terminal_result,
        } => CanonicalOperationLookupV1::try_known(
            request_digest,
            canonical_query_durable_phase(durable_phase),
            terminal_result.map(|reference| reference.inner),
        )?,
        ReferenceQueryOperationLookupV1::Conflict {
            existing_request_digest,
        } => CanonicalOperationLookupV1::try_conflict(existing_request_digest)?,
        ReferenceQueryOperationLookupV1::Unknown => CanonicalOperationLookupV1::Unknown,
        ReferenceQueryOperationLookupV1::Indeterminate { reason } => {
            CanonicalOperationLookupV1::indeterminate(canonical_operational_reason(reason))
        }
    })
}

const fn public_query_operation_lookup(
    value: CanonicalOperationLookupV1,
) -> ReferenceQueryOperationLookupV1 {
    match value {
        CanonicalOperationLookupV1::Known {
            request_digest,
            durable_phase,
            terminal_result,
        } => ReferenceQueryOperationLookupV1::Known {
            request_digest,
            durable_phase: public_query_durable_phase(durable_phase),
            terminal_result: match terminal_result {
                Some(inner) => Some(ReferenceApplyTerminalResultRefV1 { inner }),
                None => None,
            },
        },
        CanonicalOperationLookupV1::Conflict {
            existing_request_digest,
        } => ReferenceQueryOperationLookupV1::Conflict {
            existing_request_digest,
        },
        CanonicalOperationLookupV1::Unknown => ReferenceQueryOperationLookupV1::Unknown,
        CanonicalOperationLookupV1::Indeterminate { reason } => {
            ReferenceQueryOperationLookupV1::Indeterminate {
                reason: public_operational_reason(reason),
            }
        }
    }
}

fn canonical_query_desired_head(
    value: ReferenceQueryDesiredHeadV1,
) -> Result<CanonicalDesiredHeadV1, ReferenceControlError> {
    Ok(match value {
        ReferenceQueryDesiredHeadV1::None => CanonicalDesiredHeadV1::None,
        ReferenceQueryDesiredHeadV1::OneSourceLoop {
            source_revision,
            target_slice_digest,
            manifest_digest,
        } => CanonicalDesiredHeadV1::try_one_source_loop(
            source_revision,
            *target_slice_digest.value(),
            manifest_digest,
        )?,
        ReferenceQueryDesiredHeadV1::EmptyDeactivate {
            source_revision,
            target_slice_digest,
            manifest_digest,
        } => CanonicalDesiredHeadV1::try_empty_deactivate(
            source_revision,
            *target_slice_digest.value(),
            manifest_digest,
        )?,
    })
}

const fn public_query_desired_head(value: CanonicalDesiredHeadV1) -> ReferenceQueryDesiredHeadV1 {
    match value {
        CanonicalDesiredHeadV1::None => ReferenceQueryDesiredHeadV1::None,
        CanonicalDesiredHeadV1::OneSourceLoop {
            source_revision,
            target_slice_digest,
            manifest_digest,
        } => ReferenceQueryDesiredHeadV1::OneSourceLoop {
            source_revision,
            target_slice_digest: TargetSliceDigest::new(target_slice_digest),
            manifest_digest,
        },
        CanonicalDesiredHeadV1::EmptyDeactivate {
            source_revision,
            target_slice_digest,
            manifest_digest,
        } => ReferenceQueryDesiredHeadV1::EmptyDeactivate {
            source_revision,
            target_slice_digest: TargetSliceDigest::new(target_slice_digest),
            manifest_digest,
        },
    }
}

const fn canonical_query_live_state(value: ReferenceQueryLiveStateV1) -> CanonicalLiveStateV1 {
    match value {
        ReferenceQueryLiveStateV1::NotReady => CanonicalLiveStateV1::NotReady,
        ReferenceQueryLiveStateV1::Recovering => CanonicalLiveStateV1::Recovering,
        ReferenceQueryLiveStateV1::LiveReady => CanonicalLiveStateV1::LiveReady,
        ReferenceQueryLiveStateV1::Draining => CanonicalLiveStateV1::Draining,
        ReferenceQueryLiveStateV1::RecoveryFailedNotReady => {
            CanonicalLiveStateV1::RecoveryFailedNotReady
        }
        ReferenceQueryLiveStateV1::ExactZero => CanonicalLiveStateV1::ExactZero,
        ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine => {
            CanonicalLiveStateV1::ValidatedOperationalQuarantine
        }
        ReferenceQueryLiveStateV1::Uncertain => CanonicalLiveStateV1::Uncertain,
    }
}

const fn public_query_live_state(value: CanonicalLiveStateV1) -> ReferenceQueryLiveStateV1 {
    match value {
        CanonicalLiveStateV1::NotReady => ReferenceQueryLiveStateV1::NotReady,
        CanonicalLiveStateV1::Recovering => ReferenceQueryLiveStateV1::Recovering,
        CanonicalLiveStateV1::LiveReady => ReferenceQueryLiveStateV1::LiveReady,
        CanonicalLiveStateV1::Draining => ReferenceQueryLiveStateV1::Draining,
        CanonicalLiveStateV1::RecoveryFailedNotReady => {
            ReferenceQueryLiveStateV1::RecoveryFailedNotReady
        }
        CanonicalLiveStateV1::ExactZero => ReferenceQueryLiveStateV1::ExactZero,
        CanonicalLiveStateV1::ValidatedOperationalQuarantine => {
            ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
        }
        CanonicalLiveStateV1::Uncertain => ReferenceQueryLiveStateV1::Uncertain,
    }
}

const fn canonical_bootstrap_state(value: ReferenceBootstrapStateV1) -> CanonicalBootstrapStateV1 {
    match value {
        ReferenceBootstrapStateV1::ReadyForApply => CanonicalBootstrapStateV1::ReadyForApply,
        ReferenceBootstrapStateV1::NotReadyRecovering => {
            CanonicalBootstrapStateV1::NotReadyRecovering
        }
        ReferenceBootstrapStateV1::ValidatedOperationalQuarantine => {
            CanonicalBootstrapStateV1::ValidatedOperationalQuarantine
        }
        ReferenceBootstrapStateV1::RecoveryFailedNotReady => {
            CanonicalBootstrapStateV1::RecoveryFailedNotReady
        }
        ReferenceBootstrapStateV1::NotReadyBusy => CanonicalBootstrapStateV1::NotReadyBusy,
    }
}

const fn public_bootstrap_state(value: CanonicalBootstrapStateV1) -> ReferenceBootstrapStateV1 {
    match value {
        CanonicalBootstrapStateV1::ReadyForApply => ReferenceBootstrapStateV1::ReadyForApply,
        CanonicalBootstrapStateV1::NotReadyRecovering => {
            ReferenceBootstrapStateV1::NotReadyRecovering
        }
        CanonicalBootstrapStateV1::ValidatedOperationalQuarantine => {
            ReferenceBootstrapStateV1::ValidatedOperationalQuarantine
        }
        CanonicalBootstrapStateV1::RecoveryFailedNotReady => {
            ReferenceBootstrapStateV1::RecoveryFailedNotReady
        }
        CanonicalBootstrapStateV1::NotReadyBusy => ReferenceBootstrapStateV1::NotReadyBusy,
    }
}

const fn canonical_operational_reason(
    value: ReferenceOperationalReasonV1,
) -> CanonicalOperationalReasonV1 {
    match value {
        ReferenceOperationalReasonV1::Recovering => CanonicalOperationalReasonV1::Recovering,
        ReferenceOperationalReasonV1::ActiveCompatibilityMismatch => {
            CanonicalOperationalReasonV1::ActiveCompatibilityMismatch
        }
        ReferenceOperationalReasonV1::RecoveryFailed => {
            CanonicalOperationalReasonV1::RecoveryFailed
        }
        ReferenceOperationalReasonV1::OwnershipUncertain => {
            CanonicalOperationalReasonV1::OwnershipUncertain
        }
        ReferenceOperationalReasonV1::HistoryUnavailable => {
            CanonicalOperationalReasonV1::HistoryUnavailable
        }
        ReferenceOperationalReasonV1::ResourceCensusUncertain => {
            CanonicalOperationalReasonV1::ResourceCensusUncertain
        }
        ReferenceOperationalReasonV1::RuntimeBusy => CanonicalOperationalReasonV1::RuntimeBusy,
        ReferenceOperationalReasonV1::OwnershipTransferRequired => {
            CanonicalOperationalReasonV1::OwnershipTransferRequired
        }
    }
}

const fn public_operational_reason(
    value: CanonicalOperationalReasonV1,
) -> ReferenceOperationalReasonV1 {
    match value {
        CanonicalOperationalReasonV1::Recovering => ReferenceOperationalReasonV1::Recovering,
        CanonicalOperationalReasonV1::ActiveCompatibilityMismatch => {
            ReferenceOperationalReasonV1::ActiveCompatibilityMismatch
        }
        CanonicalOperationalReasonV1::RecoveryFailed => {
            ReferenceOperationalReasonV1::RecoveryFailed
        }
        CanonicalOperationalReasonV1::OwnershipUncertain => {
            ReferenceOperationalReasonV1::OwnershipUncertain
        }
        CanonicalOperationalReasonV1::HistoryUnavailable => {
            ReferenceOperationalReasonV1::HistoryUnavailable
        }
        CanonicalOperationalReasonV1::ResourceCensusUncertain => {
            ReferenceOperationalReasonV1::ResourceCensusUncertain
        }
        CanonicalOperationalReasonV1::RuntimeBusy => ReferenceOperationalReasonV1::RuntimeBusy,
        CanonicalOperationalReasonV1::OwnershipTransferRequired => {
            ReferenceOperationalReasonV1::OwnershipTransferRequired
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
        WriterTenureClaim, WriterTenureProof,
    };
    use crate::installation::{
        InstalledRuntimeArtifactObservationV1, generate_build_descriptor, generate_manifest,
    };
    use crate::provenance::{SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef};
    use crate::temporal::TemporalConstraintId;

    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x11; 16]);
    const SCOPE: SourceScopeRef = SourceScopeRef::from_bytes([0x22; 16]);
    const STORE: [u8; 32] = [0x33; 32];

    fn compiled_facts() -> RuntimeCompiledInstallationFactsV1 {
        RuntimeCompiledInstallationFactsV1::try_new(
            [0x41; 32],
            CardDefinitionRef::from_bytes([0x42; 16]),
            CardImplementationRef::from_bytes([0x43; 16]),
            [0x44; 16],
            Digest32::from_bytes([0x45; 32]),
            Digest32::from_bytes([0x46; 32]),
        )
        .expect("compiled fixture facts")
    }

    fn installation() -> (
        VerifiedRuntimeInstallationV1,
        VerifiedRuntimeManifestIngressV1,
        RuntimeCompiledInstallationFactsV1,
    ) {
        let compiled = compiled_facts();
        installation_for(TARGET, compiled)
    }

    fn installation_for(
        target: RuntimeHostId,
        compiled: RuntimeCompiledInstallationFactsV1,
    ) -> (
        VerifiedRuntimeInstallationV1,
        VerifiedRuntimeManifestIngressV1,
        RuntimeCompiledInstallationFactsV1,
    ) {
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x47; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .expect("artifact observation");
        let descriptor =
            generate_build_descriptor(&artifact, compiled).expect("descriptor generation");
        let installation = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            target,
            &artifact,
            compiled,
        )
        .expect("manifest generation");
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        (installation, ingress, compiled)
    }

    fn admission_policy(seed: u8) -> ReferenceAdmissionPolicyFingerprintV1 {
        reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
            target: TARGET,
            source_scope: SCOPE,
            writer: PlanWriterRef::from_bytes([0x73; 16]),
            controller_principal: PrincipalRef::from_bytes([0x71; 16]),
            controller_key_ref: ApplyAuthKeyRef::from_bytes([0x72; 16]),
            controller_public_key: &[seed; 32],
            authority_principal: PrincipalRef::from_bytes([0x74; 16]),
            authority_uid: 3_001,
            authority_gid: 3_002,
            tenure_authority_ref: TenureAuthorityRef::from_bytes([0x75; 16]),
            tenure_key_ref: TenureKeyRef::from_bytes([0x76; 16]),
            tenure_public_key: &[0x77; 32],
        })
        .expect("reference admission policy")
    }

    fn writer_control(expected_active: ExpectedActive) -> RuntimeApplyControl {
        writer_control_with_tenure_nonce(expected_active, b"tenure-nonce")
    }

    fn writer_control_with_tenure_nonce(
        expected_active: ExpectedActive,
        tenure_nonce: &[u8],
    ) -> RuntimeApplyControl {
        let algorithm = TenureProofAlgorithm::try_new(1).expect("tenure algorithm");
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0x51; 16]),
            TenureKeyRef::from_bytes([0x52; 16]),
            algorithm,
            1,
        )
        .expect("tenure authority");
        let writer = PlanWriterRef::from_bytes([0x53; 16]);
        let epoch = PlanWriterEpoch::new(2);
        let claim = WriterTenureClaim::try_new(SCOPE, writer, epoch, PlanWriterEpoch::new(1))
            .expect("tenure claim");
        let proof = WriterTenureProof::try_new(authority, claim, tenure_nonce, b"tenure-signature")
            .expect("tenure proof");
        let context = PlanWriterContext::try_new(writer, epoch, proof).expect("writer context");
        RuntimeApplyControl::new(
            context,
            expected_active,
            ApplyOperationId::from_bytes([0x54; 16]),
        )
    }

    fn provenance() -> PlanProvenance {
        PlanProvenance::new(
            SCOPE,
            SourcePlanRef::from_bytes([0x61; 16]),
            SourcePlanRevision::new(7),
            SourcePlanDigest::new(Digest32::from_bytes([0x62; 32])),
        )
    }

    fn temporal() -> ApplyTemporalConstraint {
        temporal_with_remaining(9_000)
    }

    fn temporal_with_remaining(remaining_nanos: u64) -> ApplyTemporalConstraint {
        ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([0x63; 16]),
            ClockDomainRef::from_bytes([0x64; 16]),
            ClockGeneration::try_new(3).expect("clock generation"),
            BoundedDuration::from_nanos(10_000),
            BoundedDuration::from_nanos(remaining_nanos),
        )
        .expect("temporal constraint")
    }

    fn request_auth(nonce: &[u8]) -> ApplyRequestAuthClaim {
        ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x71; 16]),
            ApplyAuthKeyRef::from_bytes([0x72; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("auth algorithm"),
            1,
            nonce,
        )
        .expect("request auth claim")
    }

    fn budgets() -> ValidatedReferenceLifecycleBudgetsV1 {
        ValidatedReferenceLifecycleBudgetsV1::try_new(
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(200),
            BoundedDuration::from_nanos(300),
        )
        .expect("lifecycle budgets")
    }

    fn apply_request(
        mode: ReferenceAssemblyModeV1,
        nonce: &'static [u8],
    ) -> ReferenceApplyRequestV1 {
        apply_request_with_ingress_facts(mode, b"tenure-nonce", nonce, 9_000)
    }

    fn apply_request_with_ingress_facts(
        mode: ReferenceAssemblyModeV1,
        tenure_nonce: &[u8],
        request_nonce: &[u8],
        remaining_nanos: u64,
    ) -> ReferenceApplyRequestV1 {
        let (_, ingress, _) = installation();
        let execution = match mode {
            ReferenceAssemblyModeV1::OneSourceLoop => {
                ReferenceTargetExecutionPlanV4::try_one_source_loop(
                    &ingress,
                    InstanceRef::from_bytes([0x81; 16]),
                    DomainRef::from_bytes([0x82; 16]),
                    budgets(),
                )
                .expect("loop execution")
            }
            ReferenceAssemblyModeV1::EmptyDeactivate => {
                ReferenceTargetExecutionPlanV4::try_empty_deactivate(&ingress)
                    .expect("empty execution")
            }
        };
        ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance(),
            writer_control_with_tenure_nonce(ExpectedActive::None, tenure_nonce),
            temporal_with_remaining(remaining_nanos),
            STORE,
            request_auth(request_nonce),
        )
        .expect("apply request draft")
        .finalize(b"controller-apply-signature")
        .expect("apply request")
    }

    #[test]
    fn public_constants_are_exact_canonical_aliases() {
        assert_eq!(REFERENCE_TARGET_EXECUTION_VERSION, 4);
        assert_eq!(REFERENCE_RUNTIME_APPLY_REQUEST_VERSION, 5);
        assert_eq!(REFERENCE_RUNTIME_APPLY_ENVELOPE_VERSION, 2);
        assert_eq!(REFERENCE_BOOTSTRAP_VERSION, 1);
        assert_eq!(REFERENCE_QUERY_VERSION, 1);
        assert_eq!(REFERENCE_QUERY_SIGNING_TRANSCRIPT_VERSION, 1);
        assert_eq!(REFERENCE_QUERY_RECORD_COUNT, 1);
        assert_eq!(REFERENCE_APPLY_TERMINAL_RECEIPT_VERSION, 1);
        assert_eq!(
            REFERENCE_APPLY_TERMINAL_RECEIPT_SIGNING_TRANSCRIPT_VERSION,
            1
        );
        assert_eq!(MAX_REFERENCE_RUNTIME_APPLY_ENVELOPE_BYTES, 4096);
        assert_eq!(MAX_REFERENCE_APPLY_AUTH_NONCE_BYTES, 64);
        assert_eq!(MAX_REFERENCE_APPLY_AUTH_SIGNATURE_BYTES, 512);
        assert_eq!(MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES, 1024);
        assert_eq!(MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES, 2048);
        assert_eq!(MAX_REFERENCE_QUERY_REQUEST_BYTES, 1024);
        assert_eq!(MAX_REFERENCE_QUERY_RESPONSE_BYTES, 2048);
        assert_eq!(MAX_REFERENCE_QUERY_NONCE_BYTES, 64);
        assert_eq!(MAX_REFERENCE_QUERY_SIGNATURE_BYTES, 512);
        assert_eq!(MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES, 2048);
        assert_eq!(MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_SIGNATURE_BYTES, 512);
        assert_eq!(REFERENCE_PROFILE_LIFECYCLE_CONCURRENCY, 1);
        assert_eq!(REFERENCE_PROFILE_MAILBOX_SLOTS, 0);
        assert_eq!(REFERENCE_PROFILE_DISPATCH_SLOTS, 0);
        assert_eq!(REFERENCE_PROFILE_BACKGROUND_TASK_SLOTS, 0);
    }

    #[test]
    fn lifecycle_token_uses_the_canonical_nonzero_upper_bound() {
        assert_eq!(budgets().start().value(), 100);
        assert_eq!(budgets().drain().value(), 200);
        assert_eq!(budgets().cleanup().value(), 300);

        let zero = ValidatedReferenceLifecycleBudgetsV1::try_new(
            BoundedDuration::from_nanos(0),
            BoundedDuration::from_nanos(1),
            BoundedDuration::from_nanos(1),
        );
        assert_eq!(
            zero,
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidLifecycleBudget
            ))
        );
        let too_large = ValidatedReferenceLifecycleBudgetsV1::try_new(
            BoundedDuration::from_nanos(MAX_REFERENCE_LIFECYCLE_NANOS + 1),
            BoundedDuration::from_nanos(1),
            BoundedDuration::from_nanos(1),
        );
        assert_eq!(
            too_large,
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidLifecycleBudget
            ))
        );
    }

    #[test]
    fn control_key_fingerprint_has_a_fixed_independent_vector() {
        let digest = ed25519_control_key_fingerprint(&[0x42; 32]).expect("key fingerprint");
        assert_eq!(
            digest.into_bytes(),
            [
                0xc4, 0xd4, 0xbb, 0x5d, 0x34, 0x13, 0x17, 0xef, 0xe9, 0xcc, 0x18, 0xdb, 0x1c, 0x1f,
                0xbe, 0x74, 0xa6, 0x80, 0xe1, 0x89, 0x42, 0x70, 0x96, 0x65, 0x32, 0xe8, 0xc3, 0x36,
                0x42, 0x93, 0x39, 0x1a,
            ]
        );
        assert_ne!(
            digest,
            ed25519_control_key_fingerprint(&[0x43; 32]).expect("other key fingerprint")
        );
    }

    #[test]
    fn local_channel_component_digests_have_fixed_vectors() {
        let endpoint = reference_local_control_endpoint_identity_digest_v1(
            b"/run/paraegox/runtime.sock",
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            1_001,
            2_002,
            0o660,
        )
        .expect("endpoint identity digest");
        assert_eq!(
            endpoint.into_bytes(),
            [
                0x03, 0xd1, 0x1f, 0xcc, 0xd2, 0x5b, 0x80, 0x48, 0x3a, 0xb0, 0x1a, 0x22, 0xbd, 0x90,
                0x91, 0xd8, 0x7d, 0x10, 0x68, 0x0f, 0x9c, 0x98, 0x00, 0xec, 0xe3, 0x72, 0xf4, 0x8b,
                0x97, 0xdb, 0x95, 0x8f,
            ]
        );

        let credentials = reference_runtime_peer_credentials_digest_v1(1_001, 2_002, 0x2122_2324)
            .expect("Runtime credentials digest");
        assert_eq!(
            credentials.into_bytes(),
            [
                0xd4, 0xee, 0xfb, 0xe9, 0x78, 0x4c, 0xdf, 0x31, 0x83, 0x44, 0xae, 0xd0, 0xe3, 0x58,
                0x82, 0x8c, 0xa3, 0xf6, 0x73, 0x5b, 0x53, 0x18, 0xa9, 0xb7, 0xf4, 0x9d, 0x4a, 0x41,
                0xc9, 0x56, 0xc0, 0xa4,
            ]
        );

        assert_eq!(
            reference_runtime_peer_credentials_digest_v1(1_001, 2_002, 0),
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidChannelEvidence
            ))
        );

        let policy = reference_bootstrap_channel_policy_fingerprint_v1(
            ReferenceBootstrapChannelPolicyInputV1 {
                canonical_socket_path: b"/run/paraegox/runtime.sock",
                target: TARGET,
                source_scope: SCOPE,
                controller_principal: PrincipalRef::from_bytes([0x31; 16]),
                controller_key_ref: ApplyAuthKeyRef::from_bytes([0x32; 16]),
                controller_public_key: &[0x33; 32],
                runtime_uid: 1_001,
                runtime_gid: 1_002,
                controller_uid: 2_001,
                controller_gid: 2_002,
                runtime_principal: PrincipalRef::from_bytes([0x41; 16]),
                response_key_ref: ApplyAuthKeyRef::from_bytes([0x42; 16]),
                response_public_key: &[0x43; 32],
            },
        )
        .expect("stable channel policy fingerprint");
        assert_eq!(
            policy.into_bytes(),
            [
                0x80, 0xf9, 0x37, 0xd5, 0x7e, 0x86, 0xae, 0xc7, 0xaa, 0x49, 0x80, 0x37, 0xb2, 0x55,
                0x34, 0xfb, 0xd8, 0x7e, 0x42, 0xa3, 0x95, 0xab, 0x3b, 0xb2, 0x87, 0xbc, 0x08, 0xad,
                0x89, 0x55, 0x9c, 0x54,
            ]
        );

        let admission = admission_policy(0x78);
        assert_eq!(
            admission.digest().into_bytes(),
            [
                0x99, 0x4b, 0xa1, 0xd3, 0x74, 0xb5, 0xc7, 0x15, 0xa4, 0xdf, 0x67, 0x84, 0x01, 0xb9,
                0xb4, 0x5c, 0xfa, 0xa3, 0xed, 0xd0, 0x5a, 0x5c, 0xbe, 0x9c, 0x5c, 0x80, 0xd4, 0xca,
                0xa2, 0xb9, 0xc6, 0x90,
            ]
        );
    }

    #[test]
    fn one_source_pxte_and_signed_pxar_round_trip_without_a_second_codec() {
        let (_, ingress, compiled) = installation();
        let execution = ReferenceTargetExecutionPlanV4::try_one_source_loop(
            &ingress,
            InstanceRef::from_bytes([0x81; 16]),
            DomainRef::from_bytes([0x82; 16]),
            budgets(),
        )
        .expect("one-source PXTE");
        assert_eq!(execution.mode(), ReferenceAssemblyModeV1::OneSourceLoop);
        assert_eq!(execution.target(), TARGET);
        assert_eq!(execution.manifest_digest(), ingress.manifest_digest());
        assert_eq!(
            execution.profile_fingerprint().expect("profile"),
            ingress.profile_fingerprint()
        );
        execution
            .validate_compiled_fixture(compiled)
            .expect("compiled fixture");
        let wrong_compiled = RuntimeCompiledInstallationFactsV1::try_new(
            compiled.compiled_build_instance_id(),
            CardDefinitionRef::from_bytes([0x42; 16]),
            CardImplementationRef::from_bytes([0x43; 16]),
            [0x99; 16],
            Digest32::from_bytes([0x45; 32]),
            Digest32::from_bytes([0x46; 32]),
        )
        .expect("different compiled fixture");
        assert_eq!(
            execution.validate_compiled_fixture(wrong_compiled),
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::FixtureMismatch
            ))
        );
        assert_eq!(
            ReferenceTargetExecutionPlanV4::decode(execution.canonical_wire())
                .expect("strict PXTE decode"),
            execution
        );
        let loop_facts = execution.loop_facts().expect("loop facts");
        assert_eq!(loop_facts.instance().as_bytes(), &[0x81; 16]);
        assert_eq!(loop_facts.domain().as_bytes(), &[0x82; 16]);
        assert_eq!(
            loop_facts.config_digest(),
            ingress.canonical_empty_config_digest()
        );

        let draft = ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance(),
            writer_control(ExpectedActive::None),
            temporal(),
            STORE,
            request_auth(b"apply-nonce"),
        )
        .expect("PXAR draft");
        let transcript = draft
            .signing_transcript()
            .expect("apply signing transcript")
            .as_bytes()
            .to_vec();
        let request = draft
            .finalize(b"controller-signature")
            .expect("signed PXAR");
        let canonical_slice_wire = request.canonical_slice_wire().to_vec();
        let decoded =
            ReferenceApplyRequestV1::decode(request.canonical_wire()).expect("strict PXAR decode");
        assert_eq!(decoded.canonical_wire(), request.canonical_wire());
        assert_eq!(decoded.canonical_slice_wire(), canonical_slice_wire);
        assert_eq!(&canonical_slice_wire[..4], b"PXTA");
        assert!(
            canonical_slice_wire.ends_with(decoded.target_execution().canonical_wire()),
            "the owner-returned slice must be exact zero-PXTA plus PXTE"
        );
        assert_eq!(
            decoded
                .signing_transcript()
                .expect("decoded transcript")
                .as_bytes(),
            transcript
        );
        assert_eq!(
            decoded.authentication().signature(),
            b"controller-signature"
        );
        assert_eq!(decoded.expected_runtime_store_instance_id(), STORE);
        assert_eq!(decoded.provenance(), provenance());
        decoded
            .validate_expected_store(STORE)
            .expect("expected store");
        decoded.validate_manifest(&ingress).expect("exact manifest");

        let error = decoded
            .validate_expected_store([0x34; 32])
            .expect_err("wrong store must fail");
        assert_eq!(
            error,
            ReferenceControlError::Wire(ReferenceControlWireError {
                code: ReferenceControlWireErrorCode::RuntimeStoreMismatch,
                detail: None,
            })
        );
    }

    #[test]
    fn apply_ingress_identities_have_fixed_domain_separated_vectors() {
        let request = apply_request(
            ReferenceAssemblyModeV1::OneSourceLoop,
            b"identity-request-nonce",
        );
        let identities =
            reference_apply_ingress_identities_v1(&request).expect("ingress identities");
        assert_eq!(
            identities.tenure_nonce_identity().into_bytes(),
            [
                0x9b, 0xbb, 0x9e, 0xf6, 0x2f, 0x4e, 0x64, 0x5f, 0xf0, 0x0d, 0x6c, 0xda, 0x76, 0x30,
                0x97, 0x76, 0x85, 0x8e, 0x7e, 0xad, 0x8d, 0x7b, 0xa8, 0x1d, 0x95, 0xe4, 0x9c, 0xb3,
                0x4a, 0x7c, 0x8a, 0xf2,
            ]
        );
        assert_eq!(
            identities.request_nonce_identity().into_bytes(),
            [
                0xab, 0x98, 0x24, 0x75, 0x07, 0xc3, 0x49, 0xfb, 0xa9, 0x3a, 0x90, 0xca, 0x61, 0x64,
                0x52, 0x2b, 0xcc, 0xf3, 0xa5, 0x05, 0xaf, 0x25, 0xac, 0x3e, 0x87, 0xd6, 0xb7, 0x2c,
                0x41, 0x96, 0x20, 0xf5,
            ]
        );
        assert_eq!(
            identities.temporal_lineage_digest().into_bytes(),
            [
                0x9d, 0x0b, 0xc0, 0x41, 0xcb, 0xc9, 0x0c, 0xbe, 0x96, 0x52, 0x16, 0xc7, 0xdd, 0x06,
                0xfb, 0x78, 0x0f, 0x90, 0xe8, 0x4a, 0xec, 0x80, 0xdf, 0x85, 0xa6, 0xe3, 0x82, 0x8d,
                0x85, 0xc1, 0x84, 0x3d,
            ]
        );

        let other_request = apply_request(
            ReferenceAssemblyModeV1::OneSourceLoop,
            b"other-request-nonce",
        );
        let other =
            reference_apply_ingress_identities_v1(&other_request).expect("other identities");
        assert_eq!(
            identities.tenure_nonce_identity(),
            other.tenure_nonce_identity()
        );
        assert_ne!(
            identities.request_nonce_identity(),
            other.request_nonce_identity()
        );
        assert_eq!(
            identities.temporal_lineage_digest(),
            other.temporal_lineage_digest()
        );

        let other_tenure =
            reference_apply_ingress_identities_v1(&apply_request_with_ingress_facts(
                ReferenceAssemblyModeV1::OneSourceLoop,
                b"other-tenure-nonce",
                b"identity-request-nonce",
                9_000,
            ))
            .expect("other tenure identities");
        assert_ne!(
            identities.tenure_nonce_identity(),
            other_tenure.tenure_nonce_identity()
        );
        assert_eq!(
            identities.request_nonce_identity(),
            other_tenure.request_nonce_identity()
        );
        assert_eq!(
            identities.temporal_lineage_digest(),
            other_tenure.temporal_lineage_digest()
        );

        let reduced_temporal =
            reference_apply_ingress_identities_v1(&apply_request_with_ingress_facts(
                ReferenceAssemblyModeV1::OneSourceLoop,
                b"tenure-nonce",
                b"identity-request-nonce",
                8_999,
            ))
            .expect("reduced temporal identities");
        assert_eq!(
            identities.tenure_nonce_identity(),
            reduced_temporal.tenure_nonce_identity()
        );
        assert_eq!(
            identities.request_nonce_identity(),
            reduced_temporal.request_nonce_identity()
        );
        assert_ne!(
            identities.temporal_lineage_digest(),
            reduced_temporal.temporal_lineage_digest()
        );
        assert_ne!(
            identities.tenure_nonce_identity(),
            identities.request_nonce_identity()
        );
        assert_ne!(
            identities.request_nonce_identity(),
            identities.temporal_lineage_digest()
        );
    }

    #[test]
    fn empty_deactivate_is_exact_and_strict_decode_rejects_trailing_bytes() {
        let (_, ingress, _) = installation();
        let execution =
            ReferenceTargetExecutionPlanV4::try_empty_deactivate(&ingress).expect("empty PXTE");
        assert_eq!(execution.mode(), ReferenceAssemblyModeV1::EmptyDeactivate);
        assert_eq!(execution.loop_facts(), None);

        let draft = ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance(),
            writer_control(ExpectedActive::None),
            temporal(),
            STORE,
            request_auth(b"empty-nonce"),
        )
        .expect("empty draft");
        let request = draft.finalize(b"signature").expect("empty request");
        assert_eq!(
            request.target_execution().mode(),
            ReferenceAssemblyModeV1::EmptyDeactivate
        );
        let mut trailing = request.canonical_wire().to_vec();
        trailing.push(0);
        assert!(ReferenceApplyRequestV1::decode(&trailing).is_err());
    }

    #[test]
    fn apply_terminal_receipt_facade_round_trips_without_internal_types() {
        let request = apply_request(
            ReferenceAssemblyModeV1::OneSourceLoop,
            b"terminal-receipt-nonce",
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            PrincipalRef::from_bytes([0xb1; 16]),
            Digest32::from_bytes([0xb2; 32]),
            Digest32::from_bytes([0xb3; 32]),
        )
        .expect("terminal channel");
        let facts = ReferenceApplyTerminalFactsV1::try_new(
            &request,
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
            Digest32::from_bytes([0xb4; 32]),
            Digest32::from_bytes([0xb5; 32]),
            6,
            7,
            ClockGeneration::try_new(3).expect("selection clock"),
            8_000,
        )
        .expect("terminal facts");
        assert!(
            !facts
                .terminal_result_ref()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        );
        let claim = ReferenceApplyTerminalReceiptAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0xb6; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("response algorithm"),
            1,
        )
        .expect("terminal auth claim");
        let draft = ReferenceApplyTerminalReceiptDraftV1::try_new(&request, facts, channel, claim)
            .expect("terminal receipt draft");
        let transcript = draft
            .signing_transcript()
            .expect("terminal signing transcript")
            .as_bytes()
            .to_vec();
        let receipt = draft
            .finalize(b"runtime-terminal-signature")
            .expect("terminal receipt");
        assert!(receipt.canonical_wire().len() <= MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES);
        let decoded = ReferenceApplyTerminalReceiptV1::decode(receipt.canonical_wire())
            .expect("strict terminal receipt decode");
        assert_eq!(decoded.canonical_wire(), receipt.canonical_wire());
        assert_eq!(
            decoded
                .signing_transcript()
                .expect("decoded terminal transcript")
                .as_bytes(),
            transcript
        );
        assert_eq!(decoded.target(), TARGET);
        assert_eq!(decoded.runtime_store_instance_id(), STORE);
        assert_eq!(decoded.source_scope(), SCOPE);
        assert_eq!(decoded.request_nonce(), b"terminal-receipt-nonce");
        assert_eq!(decoded.request_digest(), request.envelope_request_digest());
        assert_eq!(
            decoded.facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        );
        assert_eq!(
            decoded.facts().head(),
            ReferenceApplyTerminalHeadV1::CommittedIncoming
        );
        assert_eq!(
            decoded.facts().desired_head_digest(),
            Some(request.target_slice_digest())
        );
        assert_eq!(
            decoded.authentication_signature(),
            b"runtime-terminal-signature"
        );
        assert_eq!(
            decoded
                .validate_against_request(&request, channel)
                .expect("terminal request/channel correlation"),
            facts
        );
    }

    #[test]
    fn apply_terminal_receipt_facade_rejects_wrong_mode_head_and_channel() {
        let loop_request = apply_request(ReferenceAssemblyModeV1::OneSourceLoop, b"loop-terminal");
        assert!(
            ReferenceApplyTerminalFactsV1::try_new(
                &loop_request,
                ReferenceApplyTerminalOutcomeV1::SupersededAfterIntentExactZero,
                ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
                ReferenceApplyTerminalHeadV1::CommittedIncoming,
                Digest32::from_bytes([0xc1; 32]),
                Digest32::from_bytes([0xc2; 32]),
                4,
                5,
                ClockGeneration::try_new(3).expect("selection clock"),
                6_000,
            )
            .is_err()
        );

        let empty_request =
            apply_request(ReferenceAssemblyModeV1::EmptyDeactivate, b"empty-terminal");
        let empty_facts = ReferenceApplyTerminalFactsV1::try_new(
            &empty_request,
            ReferenceApplyTerminalOutcomeV1::InterruptedButNowExactZero,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
            Digest32::from_bytes([0xc3; 32]),
            Digest32::from_bytes([0xc4; 32]),
            8,
            9,
            ClockGeneration::try_new(4).expect("restart selection clock"),
            10_000,
        )
        .expect("head-first empty interruption");
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            PrincipalRef::from_bytes([0xc5; 16]),
            Digest32::from_bytes([0xc6; 32]),
            Digest32::from_bytes([0xc7; 32]),
        )
        .expect("empty channel");
        let receipt = ReferenceApplyTerminalReceiptDraftV1::try_new(
            &empty_request,
            empty_facts,
            channel,
            ReferenceApplyTerminalReceiptAuthClaimV1::try_new(
                channel,
                ApplyAuthKeyRef::from_bytes([0xc8; 16]),
                ApplyAuthAlgorithm::try_new(1).expect("response algorithm"),
                1,
            )
            .expect("response claim"),
        )
        .and_then(|draft| draft.finalize(b"runtime-empty-terminal-signature"))
        .expect("empty terminal receipt");
        let wrong_channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            channel.runtime_peer(),
            Digest32::from_bytes([0xd6; 32]),
            channel.peer_credentials_digest(),
        )
        .expect("wrong live channel");
        assert!(
            receipt
                .validate_against_request(&empty_request, wrong_channel)
                .is_err()
        );
    }

    #[test]
    fn authenticated_bootstrap_round_trips_and_exposes_verified_pin_facts() {
        let (installation, ingress, compiled) = installation();
        let admission_policy = admission_policy(0x91);
        let compatibility = ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            &installation,
            compiled,
            admission_policy.digest(),
        )
        .expect("bootstrap compatibility");
        let clock_generation = ClockGeneration::try_new(5).expect("clock generation");
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            STORE,
            9,
            10,
            ClockDomainRef::from_bytes([0x92; 16]),
            clock_generation,
        )
        .expect("serving identity");
        let facts = ReferenceBootstrapFactsV1::try_new(
            serving,
            &compatibility,
            ReferenceBootstrapStateV1::ReadyForApply,
            None,
        )
        .expect("bootstrap facts");
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            PrincipalRef::from_bytes([0x93; 16]),
            Digest32::from_bytes([0x94; 32]),
            Digest32::from_bytes([0x95; 32]),
        )
        .expect("channel binding");
        let request_draft = ReferenceBootstrapRequestDraftV1::try_new(
            ReferenceBootstrapRequestIdV1::from_bytes([0x96; 16]),
            TARGET,
            SCOPE,
            request_auth(b"bootstrap-client-nonce"),
            MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES as u32,
        )
        .expect("bootstrap request draft");
        let request_transcript = request_draft
            .signing_transcript()
            .expect("request transcript")
            .as_bytes()
            .to_vec();
        let request = request_draft
            .finalize(b"controller-bootstrap-signature")
            .expect("bootstrap request");
        let decoded_request = ReferenceBootstrapRequestV1::decode(request.canonical_wire())
            .expect("strict request decode");
        assert_eq!(
            decoded_request
                .signing_transcript()
                .expect("decoded request transcript")
                .as_bytes(),
            request_transcript
        );

        let response_claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0x97; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("response algorithm"),
            1,
        )
        .expect("response auth claim");
        let response_draft = ReferenceBootstrapResponseDraftV1::try_new(
            &decoded_request,
            facts,
            channel,
            response_claim,
        )
        .expect("response draft");
        let response_transcript = response_draft
            .signing_transcript()
            .expect("response transcript")
            .as_bytes()
            .to_vec();
        let response = response_draft
            .finalize(b"runtime-bootstrap-signature")
            .expect("bootstrap response");
        let decoded = ReferenceBootstrapResponseV1::decode(response.canonical_wire())
            .expect("strict response decode");
        assert_eq!(
            decoded
                .signing_transcript()
                .expect("decoded response transcript")
                .as_bytes(),
            response_transcript
        );
        assert_eq!(
            decoded.authentication_signature(),
            b"runtime-bootstrap-signature"
        );
        assert_eq!(decoded.client_nonce(), b"bootstrap-client-nonce");
        let verified_facts = decoded
            .validate_against_request(&decoded_request, channel, &compatibility)
            .expect("bootstrap compatibility and echo validation");
        let controller_expectation =
            ReferenceControllerBootstrapExpectationV1::try_from_verified_manifest(
                &ingress,
                admission_policy,
            )
            .expect("Controller bootstrap expectation");
        assert_eq!(controller_expectation.target(), TARGET);
        assert_eq!(
            controller_expectation.manifest_digest(),
            installation.manifest_digest()
        );
        assert_eq!(
            decoded
                .validate_against_controller_expectation(
                    &decoded_request,
                    channel,
                    &controller_expectation,
                )
                .expect("Controller expectation validation"),
            verified_facts
        );
        assert_eq!(verified_facts.target(), TARGET);
        assert_eq!(verified_facts.runtime_store_instance_id(), STORE);
        assert_eq!(verified_facts.snapshot_sequence(), 9);
        assert_eq!(verified_facts.runtime_host_epoch(), 10);
        assert_eq!(verified_facts.clock_generation(), clock_generation);
        assert_eq!(
            verified_facts.compiled_build_instance_id(),
            compiled.compiled_build_instance_id()
        );
        assert_eq!(
            verified_facts.manifest_digest(),
            installation.manifest_digest()
        );
        assert_eq!(
            verified_facts.admission_policy_fingerprint(),
            admission_policy.digest()
        );
        assert_eq!(
            verified_facts.state(),
            ReferenceBootstrapStateV1::ReadyForApply
        );
        assert_eq!(verified_facts.reason(), None);
    }

    #[test]
    fn bootstrap_reason_channel_and_response_bound_fail_closed() {
        let (installation, _, compiled) = installation();
        let compatibility = ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            &installation,
            compiled,
            Digest32::from_bytes([0xa1; 32]),
        )
        .expect("compatibility");
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            STORE,
            1,
            1,
            ClockDomainRef::from_bytes([0xa2; 16]),
            ClockGeneration::try_new(1).expect("clock generation"),
        )
        .expect("serving identity");
        assert_eq!(
            ReferenceBootstrapFactsV1::try_new(
                serving,
                &compatibility,
                ReferenceBootstrapStateV1::ReadyForApply,
                Some(ReferenceOperationalReasonV1::Recovering),
            ),
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidReason
            ))
        );

        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            PrincipalRef::from_bytes([0xa3; 16]),
            Digest32::from_bytes([0xa4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        )
        .expect("channel");
        let tiny_request = ReferenceBootstrapRequestDraftV1::try_new(
            ReferenceBootstrapRequestIdV1::from_bytes([0xa6; 16]),
            TARGET,
            SCOPE,
            request_auth(b"tiny"),
            1,
        )
        .expect("tiny-bound request")
        .finalize(b"signature")
        .expect("signed tiny-bound request");
        let facts = ReferenceBootstrapFactsV1::try_new(
            serving,
            &compatibility,
            ReferenceBootstrapStateV1::NotReadyRecovering,
            Some(ReferenceOperationalReasonV1::Recovering),
        )
        .expect("recovering facts");
        let claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0xa7; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("response claim");
        let draft =
            ReferenceBootstrapResponseDraftV1::try_new(&tiny_request, facts, channel, claim)
                .expect("response draft");
        assert_eq!(
            draft.finalize(b"signature"),
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidBound
            ))
        );

        let wrong_channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            PrincipalRef::from_bytes([0xa3; 16]),
            Digest32::from_bytes([0xb4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        )
        .expect("wrong channel");
        assert_ne!(channel.binding_digest(), wrong_channel.binding_digest());
    }

    #[test]
    fn durable_slice_restores_only_with_exact_journal_provenance_and_manifest() {
        let (_, ingress, _) = installation();
        let request = apply_request(
            ReferenceAssemblyModeV1::OneSourceLoop,
            b"durable-slice-request",
        );
        let durable_bytes = request.canonical_slice_wire().to_vec();
        let restored = verify_reference_durable_slice_v1(
            &durable_bytes,
            request.provenance(),
            request.target_slice_digest(),
            &ingress,
        )
        .expect("strict durable Slice restore");
        assert_eq!(restored, request.target_execution());
        assert_eq!(durable_bytes, request.canonical_slice_wire());

        let wrong_provenance = PlanProvenance::new(
            SCOPE,
            SourcePlanRef::from_bytes([0xee; 16]),
            SourcePlanRevision::new(7),
            SourcePlanDigest::new(Digest32::from_bytes([0x62; 32])),
        );
        assert_eq!(
            verify_reference_durable_slice_v1(
                &durable_bytes,
                wrong_provenance,
                request.target_slice_digest(),
                &ingress,
            ),
            Err(ReferenceControlError::Wire(ReferenceControlWireError {
                code: ReferenceControlWireErrorCode::DigestMismatch,
                detail: Some(8),
            }))
        );

        let mut wrong_binding = durable_bytes.clone();
        wrong_binding[0] ^= 1;
        assert_eq!(
            verify_reference_durable_slice_v1(
                &wrong_binding,
                request.provenance(),
                request.target_slice_digest(),
                &ingress,
            ),
            Err(ReferenceControlError::Wire(ReferenceControlWireError {
                code: ReferenceControlWireErrorCode::BindingNotAllowed,
                detail: Some(2),
            }))
        );
        assert!(matches!(
            verify_reference_durable_slice_v1(
                &durable_bytes[..9],
                request.provenance(),
                request.target_slice_digest(),
                &ingress,
            ),
            Err(ReferenceControlError::Wire(ReferenceControlWireError {
                code: ReferenceControlWireErrorCode::Truncated,
                ..
            }))
        ));
        assert!(matches!(
            verify_reference_durable_slice_v1(
                &durable_bytes,
                request.provenance(),
                TargetSliceDigest::new(Digest32::from_bytes([0xef; 32])),
                &ingress,
            ),
            Err(ReferenceControlError::Wire(ReferenceControlWireError {
                code: ReferenceControlWireErrorCode::DigestMismatch,
                detail: Some(8),
            }))
        ));

        // PXTA/PXTE deliberately carries no SourcePlanRef. A journal migration
        // missing complete provenance must fail closed instead of synthesizing it.
        let missing_provenance_substitute = PlanProvenance::new(
            SourceScopeRef::from_bytes([0; 16]),
            SourcePlanRef::from_bytes([0; 16]),
            SourcePlanRevision::new(0),
            SourcePlanDigest::new(Digest32::from_bytes([0; 32])),
        );
        assert!(
            verify_reference_durable_slice_v1(
                &durable_bytes,
                missing_provenance_substitute,
                request.target_slice_digest(),
                &ingress,
            )
            .is_err()
        );
    }

    #[test]
    fn durable_slice_empty_restore_and_public_maximum_are_exact() {
        let (_, ingress, _) = installation();
        let empty = apply_request(
            ReferenceAssemblyModeV1::EmptyDeactivate,
            b"durable-empty-request",
        );
        let restored = verify_reference_durable_slice_v1(
            empty.canonical_slice_wire(),
            empty.provenance(),
            empty.target_slice_digest(),
            &ingress,
        )
        .expect("strict empty durable Slice restore");
        assert_eq!(restored.mode(), ReferenceAssemblyModeV1::EmptyDeactivate);
        assert_eq!(restored.loop_facts(), None);

        let maximal = apply_request(
            ReferenceAssemblyModeV1::OneSourceLoop,
            b"durable-max-request",
        );
        let execution_bytes = maximal.target_execution().canonical_wire().len();
        let zero_pxta_bytes = maximal.canonical_slice_wire().len() - execution_bytes;
        assert_eq!(execution_bytes, MAX_REFERENCE_TARGET_EXECUTION_BYTES);
        assert_eq!(
            MAX_REFERENCE_RUNTIME_PLAN_SLICE_BYTES,
            zero_pxta_bytes + MAX_REFERENCE_TARGET_EXECUTION_BYTES
        );
        assert_eq!(
            maximal.canonical_slice_wire().len(),
            MAX_REFERENCE_RUNTIME_PLAN_SLICE_BYTES
        );
        assert!(empty.canonical_slice_wire().len() < MAX_REFERENCE_RUNTIME_PLAN_SLICE_BYTES);
    }

    #[test]
    fn durable_slice_rejects_wrong_target_manifest_identity_and_profile() {
        let (_, ingress, _) = installation();
        let request = apply_request(
            ReferenceAssemblyModeV1::OneSourceLoop,
            b"durable-manifest-request",
        );

        let wrong_target = RuntimeHostId::from_bytes([0xf1; 16]);
        let (_, wrong_target_ingress, _) = installation_for(wrong_target, compiled_facts());
        assert_eq!(
            verify_reference_durable_slice_v1(
                request.canonical_slice_wire(),
                request.provenance(),
                request.target_slice_digest(),
                &wrong_target_ingress,
            ),
            Err(ReferenceControlError::Wire(ReferenceControlWireError {
                code: ReferenceControlWireErrorCode::TargetMismatch,
                detail: Some(2),
            }))
        );

        let identity_compiled = RuntimeCompiledInstallationFactsV1::try_new(
            [0xf2; 32],
            CardDefinitionRef::from_bytes([0x42; 16]),
            CardImplementationRef::from_bytes([0x43; 16]),
            [0x44; 16],
            Digest32::from_bytes([0x45; 32]),
            Digest32::from_bytes([0x46; 32]),
        )
        .expect("alternate build identity");
        let (_, wrong_identity_ingress, _) = installation_for(TARGET, identity_compiled);
        assert_ne!(
            wrong_identity_ingress.manifest_digest(),
            ingress.manifest_digest()
        );
        assert_eq!(
            wrong_identity_ingress.profile_fingerprint(),
            ingress.profile_fingerprint()
        );
        assert_eq!(
            verify_reference_durable_slice_v1(
                request.canonical_slice_wire(),
                request.provenance(),
                request.target_slice_digest(),
                &wrong_identity_ingress,
            ),
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidCompatibility
            ))
        );

        let profile_compiled = RuntimeCompiledInstallationFactsV1::try_new(
            [0x41; 32],
            CardDefinitionRef::from_bytes([0xf3; 16]),
            CardImplementationRef::from_bytes([0x43; 16]),
            [0x44; 16],
            Digest32::from_bytes([0x45; 32]),
            Digest32::from_bytes([0x46; 32]),
        )
        .expect("alternate fixture profile");
        let (_, wrong_profile_ingress, _) = installation_for(TARGET, profile_compiled);
        assert_ne!(
            wrong_profile_ingress.profile_fingerprint(),
            ingress.profile_fingerprint()
        );
        assert_eq!(
            verify_reference_durable_slice_v1(
                request.canonical_slice_wire(),
                request.provenance(),
                request.target_slice_digest(),
                &wrong_profile_ingress,
            ),
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidCompatibility
            ))
        );
    }

    #[test]
    fn durable_slice_multi_invalid_precedence_is_frozen() {
        let (_, ingress, _) = installation();
        let (_, wrong_target_ingress, _) =
            installation_for(RuntimeHostId::from_bytes([0xf4; 16]), compiled_facts());
        let request = apply_request(
            ReferenceAssemblyModeV1::EmptyDeactivate,
            b"durable-precedence-request",
        );
        let canonical = request.canonical_slice_wire().to_vec();
        let wrong_digest = TargetSliceDigest::new(Digest32::from_bytes([0xf5; 32]));

        let mut binding_target_digest_trailing = canonical.clone();
        binding_target_digest_trailing[0] ^= 1;
        binding_target_digest_trailing.push(0);
        let mut target_digest_trailing = canonical.clone();
        target_digest_trailing.push(0);
        let mut binding_digest = canonical.clone();
        binding_digest[0] ^= 1;

        let cases = [
            (
                "binding precedes target, digest, and trailing",
                binding_target_digest_trailing.as_slice(),
                &wrong_target_ingress,
                wrong_digest,
                ReferenceControlWireErrorCode::BindingNotAllowed,
                Some(2),
            ),
            (
                "trailing precedes target and digest",
                target_digest_trailing.as_slice(),
                &wrong_target_ingress,
                wrong_digest,
                ReferenceControlWireErrorCode::TrailingBytes,
                None,
            ),
            (
                "target precedes digest",
                canonical.as_slice(),
                &wrong_target_ingress,
                wrong_digest,
                ReferenceControlWireErrorCode::TargetMismatch,
                Some(2),
            ),
            (
                "binding precedes digest",
                binding_digest.as_slice(),
                &ingress,
                wrong_digest,
                ReferenceControlWireErrorCode::BindingNotAllowed,
                Some(2),
            ),
            (
                "digest is reported after canonical body and target",
                canonical.as_slice(),
                &ingress,
                wrong_digest,
                ReferenceControlWireErrorCode::DigestMismatch,
                Some(8),
            ),
        ];

        for (name, frame, manifest, digest, code, detail) in cases {
            assert_eq!(
                verify_reference_durable_slice_v1(frame, request.provenance(), digest, manifest,),
                Err(ReferenceControlError::Wire(ReferenceControlWireError {
                    code,
                    detail,
                })),
                "{name}"
            );
        }
    }

    #[test]
    fn authenticated_query_facade_round_trips_and_validates_freshness() {
        let (_, ingress, _) = installation();
        let apply = apply_request(ReferenceAssemblyModeV1::OneSourceLoop, b"queried-apply");
        let expected_request_digest = apply.envelope_request_digest();
        let selector = ReferenceQuerySelectorV1::try_new(
            ReferenceQueryIdV1::from_bytes([0xd1; 16]),
            TARGET,
            SCOPE,
            STORE,
            ApplyOperationId::from_bytes([0x54; 16]),
            Some(expected_request_digest),
        )
        .expect("query selector");
        let request_draft = ReferenceQueryRequestDraftV1::try_new(
            selector,
            request_auth(b"query-client-nonce"),
            MAX_REFERENCE_QUERY_RESPONSE_BYTES as u32,
        )
        .expect("query request draft");
        let request_transcript = request_draft
            .signing_transcript()
            .expect("query request transcript")
            .as_bytes()
            .to_vec();
        let request = request_draft
            .finalize(b"controller-query-signature")
            .expect("query request");
        let decoded_request =
            ReferenceQueryRequestV1::decode(request.canonical_wire()).expect("strict PXQR decode");
        assert_eq!(decoded_request.selector(), selector);
        assert_eq!(decoded_request.source_scope(), SCOPE);
        assert_eq!(decoded_request.expected_runtime_store_instance_id(), STORE);
        assert_eq!(
            decoded_request.expected_request_digest(),
            Some(expected_request_digest)
        );
        assert_eq!(
            decoded_request.authentication().signature(),
            b"controller-query-signature"
        );
        assert_eq!(
            decoded_request
                .signing_transcript()
                .expect("decoded PXQR transcript")
                .as_bytes(),
            request_transcript
        );
        decoded_request
            .validate_expected_store(STORE)
            .expect("query expected store");

        let clock_domain = ClockDomainRef::from_bytes([0xd2; 16]);
        let clock_generation = ClockGeneration::try_new(5).expect("query clock generation");
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            STORE,
            11,
            12,
            clock_domain,
            clock_generation,
        )
        .expect("query serving identity");
        let operation = ReferenceQueryOperationStateV1::try_new(
            ReferenceQueryOwnerStateV1::Operational,
            None,
            ReferenceQueryOperationLookupV1::Known {
                request_digest: expected_request_digest,
                durable_phase: ReferenceQueryDurablePhaseV1::FirstActionIntent,
                terminal_result: None,
            },
        )
        .expect("query operation state");
        let desired = ReferenceQueryDesiredStateV1::try_new(
            ReferenceQueryDesiredHeadV1::OneSourceLoop {
                source_revision: SourcePlanRevision::new(7),
                target_slice_digest: apply.target_slice_digest(),
                manifest_digest: ingress.manifest_digest(),
            },
            SourcePlanRevision::new(8),
        )
        .expect("query desired state");
        let live = ReferenceQueryLiveFactsV1::try_new(
            ReferenceQueryLiveStateV1::LiveReady,
            4,
            50_000,
            Digest32::from_bytes([0xd3; 32]),
        )
        .expect("query live facts");
        let facts = ReferenceQueryFactsV1::try_new(serving, operation, desired, live)
            .expect("complete query facts");
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            PrincipalRef::from_bytes([0xd4; 16]),
            Digest32::from_bytes([0xd5; 32]),
            Digest32::from_bytes([0xd6; 32]),
        )
        .expect("query channel");
        let response_claim = ReferenceQueryResponseAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0xd7; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("query response algorithm"),
            1,
        )
        .expect("query response claim");
        let response_draft = ReferenceQueryResponseDraftV1::try_new(
            &decoded_request,
            facts,
            channel,
            response_claim,
        )
        .expect("query response draft");
        let response_transcript = response_draft
            .signing_transcript()
            .expect("query response transcript")
            .as_bytes()
            .to_vec();
        let response = response_draft
            .finalize(b"runtime-query-signature")
            .expect("query response");
        let decoded = ReferenceQueryResponseV1::decode(response.canonical_wire())
            .expect("strict PXQS decode");
        assert_eq!(decoded.query_id(), selector.query_id());
        assert_eq!(
            decoded.query_request_digest(),
            decoded_request.request_digest()
        );
        assert_eq!(decoded.client_nonce(), b"query-client-nonce");
        assert_eq!(
            decoded.authentication_signature(),
            b"runtime-query-signature"
        );
        assert_eq!(
            decoded
                .signing_transcript()
                .expect("decoded PXQS transcript")
                .as_bytes(),
            response_transcript
        );
        let verified = decoded
            .validate_against_request(&decoded_request, channel, serving)
            .expect("query echo, channel, expectation and freshness");
        assert_eq!(verified.operation(), operation);
        assert_eq!(verified.desired(), desired);
        assert_eq!(verified.live(), live);

        let newer_baseline = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            STORE,
            12,
            12,
            clock_domain,
            clock_generation,
        )
        .expect("newer baseline");
        assert!(matches!(
            decoded.validate_against_request(&decoded_request, channel, newer_baseline),
            Err(ReferenceControlError::Wire(ReferenceControlWireError {
                code: ReferenceControlWireErrorCode::CrossReferenceMismatch,
                detail: Some(6),
            }))
        ));
    }

    #[test]
    fn query_public_constructors_reject_invalid_operation_and_live_shapes() {
        let zero = Digest32::from_bytes([0; 32]);
        assert!(
            ReferenceQuerySelectorV1::try_new(
                ReferenceQueryIdV1::from_bytes([0xe1; 16]),
                TARGET,
                SCOPE,
                STORE,
                ApplyOperationId::from_bytes([0xe2; 16]),
                Some(zero),
            )
            .is_err()
        );
        assert!(
            ReferenceQueryOperationStateV1::try_new(
                ReferenceQueryOwnerStateV1::Operational,
                None,
                ReferenceQueryOperationLookupV1::Known {
                    request_digest: Digest32::from_bytes([0xe3; 32]),
                    durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                    terminal_result: None,
                },
            )
            .is_err()
        );
        assert!(
            ReferenceQueryOperationStateV1::try_new(
                ReferenceQueryOwnerStateV1::Operational,
                Some(ReferenceOperationalReasonV1::Recovering),
                ReferenceQueryOperationLookupV1::Unknown,
            )
            .is_err()
        );
        assert!(
            ReferenceQueryLiveFactsV1::try_new(
                ReferenceQueryLiveStateV1::LiveReady,
                0,
                1,
                Digest32::from_bytes([0xe4; 32]),
            )
            .is_err()
        );
        assert!(
            ReferenceQueryLiveFactsV1::try_new(
                ReferenceQueryLiveStateV1::ExactZero,
                1,
                1,
                Digest32::from_bytes([0xe5; 32]),
            )
            .is_err()
        );

        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            STORE,
            1,
            1,
            ClockDomainRef::from_bytes([0xe6; 16]),
            ClockGeneration::try_new(1).expect("clock generation"),
        )
        .expect("serving");
        let operation = ReferenceQueryOperationStateV1::try_new(
            ReferenceQueryOwnerStateV1::Operational,
            None,
            ReferenceQueryOperationLookupV1::Unknown,
        )
        .expect("operation");
        let desired = ReferenceQueryDesiredStateV1::try_new(
            ReferenceQueryDesiredHeadV1::OneSourceLoop {
                source_revision: SourcePlanRevision::new(1),
                target_slice_digest: TargetSliceDigest::new(Digest32::from_bytes([0xe7; 32])),
                manifest_digest: Digest32::from_bytes([0xe8; 32]),
            },
            SourcePlanRevision::new(1),
        )
        .expect("desired");
        let exact_zero = ReferenceQueryLiveFactsV1::try_new(
            ReferenceQueryLiveStateV1::ExactZero,
            0,
            1,
            Digest32::from_bytes([0xe9; 32]),
        )
        .expect("exact-zero facts");
        assert_eq!(
            ReferenceQueryFactsV1::try_new(serving, operation, desired, exact_zero),
            Err(ReferenceControlError::Contract(
                ReferenceControlContractErrorCode::InvalidShape
            ))
        );
    }
}
