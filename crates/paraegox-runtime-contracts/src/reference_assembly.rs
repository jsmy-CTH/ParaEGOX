//! Internal S7/P2e successor contracts.
//!
//! This module freezes canonical bytes and rejection behavior for the narrow
//! `OneSourceLoop` / `EmptyDeactivate` reference profile.  It is deliberately
//! crate-private until the S7-E/F producer and executable Runtime consumer are
//! connected.  Nothing here starts a RuntimeHost, mutates a journal, performs
//! installation, verifies a signature, or proves that an apply endpoint exists.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

use crate::apply::{
    ApplyOperationId, ExpectedActive, MAX_TENURE_NONCE_BYTES, MAX_TENURE_SIGNATURE_BYTES,
    PlanWriterContext, PlanWriterEpoch, PlanWriterRef, RuntimeApplyControl,
    RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
    TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
};
use crate::assignment::{InstanceRef, TargetAssignments};
use crate::execution::{CardDefinitionRef, CardImplementationRef, DomainRef};
use crate::provenance::{
    PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest, SourcePlanRef,
    SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest, TargetSliceDigest,
};
use crate::temporal::{
    APPLY_TEMPORAL_CONSTRAINT_VERSION, ApplyTemporalConstraint, TemporalConstraintId,
};
use crate::wire::{
    ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, ApplyRequestAuthentication,
};

const BUILD_DESCRIPTOR_MAGIC: &[u8; 4] = b"PXBD";
const COMPATIBILITY_MANIFEST_MAGIC: &[u8; 4] = b"PXCM";
const COMPATIBILITY_PROJECTION_MAGIC: &[u8; 4] = b"PXMP";
const TARGET_EXECUTION_MAGIC: &[u8; 4] = b"PXTE";
const RUNTIME_APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const RUNTIME_BOOTSTRAP_REQUEST_MAGIC: &[u8; 4] = b"PXBR";
const RUNTIME_BOOTSTRAP_RESPONSE_MAGIC: &[u8; 4] = b"PXBS";
const RUNTIME_QUERY_REQUEST_MAGIC: &[u8; 4] = b"PXQR";
const RUNTIME_QUERY_RESPONSE_MAGIC: &[u8; 4] = b"PXQS";
const RUNTIME_APPLY_TERMINAL_RECEIPT_MAGIC: &[u8; 4] = b"PXRT";
const APPLY_ENVELOPE_MAGIC: &[u8] = b"ParaEGOX\0runtime-apply-envelope";
const SIGNING_TRANSCRIPT_MAGIC: &[u8] = b"ParaEGOX\0canonical-signing-transcript";

const BUILD_DESCRIPTOR_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.build-descriptor.sha256.v1";
const COMPILED_REFERENCE_COMPATIBILITY_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.compiled-reference-compatibility.sha256.v1";
const COMPATIBILITY_MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.artifact-compatibility-manifest.sha256.v1";
const REFERENCE_EMPTY_CONFIG_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.reference-empty-config.sha256.v1";
const TARGET_EXECUTION_V4_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-execution.sha256.v4";
const TARGET_PLAN_ASSIGNMENTS_V5_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.target-plan-assignments.sha256.v5";
const APPLY_ENVELOPE_V2_SIGNING_DOMAIN: &[u8] = b"paraegox.runtime.apply-envelope-auth.signing.v2";
const APPLY_ENVELOPE_V2_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.apply-envelope.request.sha256.v2";
const LOCAL_CONTROL_CHANNEL_BINDING_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.local-control-channel-binding.sha256.v1";
const REFERENCE_PROFILE_FINGERPRINT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.reference-profile-fingerprint.sha256.v1";
const BOOTSTRAP_REQUEST_SIGNING_DOMAIN: &[u8] =
    b"paraegox.runtime.bootstrap.request-auth.signing.v1";
const BOOTSTRAP_REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.bootstrap.request.sha256.v1";
const BOOTSTRAP_RESPONSE_SIGNING_DOMAIN: &[u8] =
    b"paraegox.runtime.bootstrap.response-auth.signing.v1";
const BOOTSTRAP_RESPONSE_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.bootstrap.response.sha256.v1";
const QUERY_REQUEST_SIGNING_DOMAIN: &[u8] = b"paraegox.runtime.query.request-auth.signing.v1";
const QUERY_REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.query.request.sha256.v1";
const QUERY_RESPONSE_SIGNING_DOMAIN: &[u8] = b"paraegox.runtime.query.response-auth.signing.v1";
const QUERY_RESPONSE_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.query.response.sha256.v1";
const APPLY_TERMINAL_RECEIPT_SIGNING_DOMAIN: &[u8] =
    b"paraegox.runtime.apply-terminal-receipt.response-auth.signing.v1";
const APPLY_TERMINAL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.apply-terminal-receipt.sha256.v1";
const APPLY_TERMINAL_RESULT_REF_DOMAIN: &[u8] =
    b"paraegox.runtime.apply-terminal-result-ref.sha256.v1";

pub(crate) const RUNTIME_BUILD_DESCRIPTOR_VERSION: u16 = 1;
pub(crate) const RUNTIME_ARTIFACT_COMPATIBILITY_MANIFEST_VERSION: u16 = 1;
pub(crate) const RUNTIME_ARTIFACT_COMPATIBILITY_PROJECTION_VERSION: u16 = 1;
pub(crate) const REFERENCE_ASSEMBLY_PROFILE_VERSION: u16 = 1;
pub(crate) const TARGET_EXECUTION_PLAN_V4_VERSION: u16 = 4;
pub(crate) const RUNTIME_APPLY_REQUEST_V5_VERSION: u16 = 5;
pub(crate) const RUNTIME_APPLY_ENVELOPE_V2_VERSION: u16 = 2;
pub(crate) const APPLY_REQUEST_SIGNING_TRANSCRIPT_V2_VERSION: u16 = 2;
pub(crate) const LOCAL_CONTROL_CHANNEL_BINDING_VERSION: u16 = 1;
pub(crate) const RUNTIME_BOOTSTRAP_PROTOCOL_VERSION: u16 = 1;
pub(crate) const RUNTIME_QUERY_PROTOCOL_VERSION: u16 = 1;
pub(crate) const CONTROL_READ_SIGNING_TRANSCRIPT_VERSION: u16 = 1;
pub(crate) const RUNTIME_APPLY_TERMINAL_RECEIPT_VERSION: u16 = 1;
pub(crate) const APPLY_TERMINAL_RECEIPT_SIGNING_TRANSCRIPT_VERSION: u16 = 1;

pub(crate) const REFERENCE_LIFECYCLE_CONCURRENCY: u16 = 1;
pub(crate) const REFERENCE_MAILBOX_SLOTS: u16 = 0;
pub(crate) const REFERENCE_DISPATCH_SLOTS: u16 = 0;
pub(crate) const REFERENCE_BACKGROUND_TASK_SLOTS: u16 = 0;

pub(crate) const MAX_TARGET_TRIPLE_BYTES: usize = 255;
pub(crate) const MAX_RUNTIME_ARTIFACT_BYTES: u64 = 4_294_967_296;
pub(crate) const MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS: u64 = 86_400_000_000_000;
pub(crate) const MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES: usize = 4096;
pub(crate) const MAX_APPLY_AUTH_NONCE_V2_BYTES: usize = 64;
pub(crate) const MAX_APPLY_AUTH_SIGNATURE_V2_BYTES: usize = 512;
pub(crate) const MAX_CONTROL_READ_NONCE_BYTES: usize = 64;
pub(crate) const MAX_CONTROL_READ_SIGNATURE_BYTES: usize = 512;
pub(crate) const MAX_RUNTIME_BOOTSTRAP_REQUEST_BYTES: usize = 1024;
pub(crate) const MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES: usize = 2048;
pub(crate) const MAX_RUNTIME_QUERY_REQUEST_BYTES: usize = 1024;
pub(crate) const MAX_RUNTIME_QUERY_RESPONSE_BYTES: usize = 2048;
pub(crate) const MAX_RUNTIME_APPLY_TERMINAL_RECEIPT_BYTES: usize = 2048;
pub(crate) const MAX_QUERY_RECORD_COUNT: u16 = 1;

const BUILD_ID_BYTES: usize = 32;
const STORE_ID_BYTES: usize = 32;
const FIXTURE_ENTRY_BYTES: usize = 112;
const BUILD_IDENTITY_BYTES: usize = 128;
const MANIFEST_TARGET_ROW_BYTES: usize = 16 + BUILD_IDENTITY_BYTES + 2 + 2 + FIXTURE_ENTRY_BYTES;
pub(crate) const COMPATIBILITY_MANIFEST_BYTES: usize = 4 + 2 + MANIFEST_TARGET_ROW_BYTES;
const COMPATIBILITY_PROJECTION_BYTES: usize = 4 + 2 + 32 + MANIFEST_TARGET_ROW_BYTES;
const REFERENCE_LOOP_DOMAIN_BYTES: usize = 16 + 8 + 8 + 8;
const REFERENCE_LOOP_SUBJECT_BYTES: usize = 16 + 16 + FIXTURE_ENTRY_BYTES + 32;
const ZERO_BINDING_PXTA_BYTES: usize = 10;
const APPLY_REQUEST_V5_HEADER_BYTES: usize = 18;
const TLV_HEADER_BYTES: usize = 6;
const APPLY_ENVELOPE_V2_FIELD_COUNT: u16 = 38;
const APPLY_SIGNING_V2_FIELD_COUNT: u16 = APPLY_ENVELOPE_V2_FIELD_COUNT - 1;
const BOOTSTRAP_REQUEST_FIELD_COUNT: u16 = 10;
const BOOTSTRAP_REQUEST_SIGNING_FIELD_COUNT: u16 = 9;
const BOOTSTRAP_RESPONSE_FIELD_COUNT: u16 = 23;
const BOOTSTRAP_RESPONSE_SIGNING_FIELD_COUNT: u16 = 22;
const QUERY_REQUEST_FIELD_COUNT: u16 = 15;
const QUERY_REQUEST_SIGNING_FIELD_COUNT: u16 = 14;
const QUERY_RESPONSE_FIELD_COUNT: u16 = 32;
const QUERY_RESPONSE_SIGNING_FIELD_COUNT: u16 = 31;
const APPLY_TERMINAL_RECEIPT_FIELD_COUNT: u16 = 23;
const APPLY_TERMINAL_RECEIPT_SIGNING_FIELD_COUNT: u16 = 22;

pub(crate) const MAX_RUNTIME_BUILD_DESCRIPTOR_BYTES: usize =
    4 + 2 + BUILD_ID_BYTES + 8 + 32 + 2 + MAX_TARGET_TRIPLE_BYTES + 32;
pub(crate) const MAX_TARGET_EXECUTION_PLAN_V4_BYTES: usize = 4
    + 2
    + COMPATIBILITY_PROJECTION_BYTES
    + 2
    + 1
    + 1
    + REFERENCE_LOOP_DOMAIN_BYTES
    + 1
    + REFERENCE_LOOP_SUBJECT_BYTES;
pub(crate) const MAX_RUNTIME_PLAN_SLICE_V5_BYTES: usize =
    ZERO_BINDING_PXTA_BYTES + MAX_TARGET_EXECUTION_PLAN_V4_BYTES;
pub(crate) const MAX_RUNTIME_APPLY_REQUEST_V5_BYTES: usize = APPLY_REQUEST_V5_HEADER_BYTES
    + MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES
    + ZERO_BINDING_PXTA_BYTES
    + MAX_TARGET_EXECUTION_PLAN_V4_BYTES;

const ZERO_BINDING_PXTA: [u8; ZERO_BINDING_PXTA_BYTES] = [b'P', b'X', b'T', b'A', 0, 1, 0, 0, 0, 0];

/// Stable codec rejection taxonomy frozen with the S7-B vectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum ReferenceWireErrorCode {
    FrameTooLarge = 1,
    Truncated = 2,
    InvalidMagic = 3,
    UnsupportedVersion = 4,
    UnknownField = 5,
    DuplicateField = 6,
    OutOfOrderField = 7,
    MissingField = 8,
    InvalidFieldLength = 9,
    InvalidFieldValue = 10,
    NonCanonicalFrame = 11,
    DigestMismatch = 12,
    CrossReferenceMismatch = 13,
    UnsupportedShape = 14,
    BindingNotAllowed = 15,
    RuntimeStoreMismatch = 16,
    TargetMismatch = 17,
    FixtureMismatch = 18,
    ResponseBoundExceeded = 19,
    UnknownReason = 20,
    TrailingBytes = 21,
    InvalidSignatureField = 22,
    InvalidPresence = 23,
    ArtifactMismatch = 24,
    CompatibilityMismatch = 25,
}

/// One fail-closed wire rejection with an optional field/tag detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReferenceWireError {
    code: ReferenceWireErrorCode,
    detail: Option<u16>,
}

impl ReferenceWireError {
    const fn new(code: ReferenceWireErrorCode) -> Self {
        Self { code, detail: None }
    }

    const fn at(code: ReferenceWireErrorCode, detail: u16) -> Self {
        Self {
            code,
            detail: Some(detail),
        }
    }

    #[must_use]
    pub(crate) const fn code(self) -> ReferenceWireErrorCode {
        self.code
    }

    #[must_use]
    pub(crate) const fn detail(self) -> Option<u16> {
        self.detail
    }
}

impl fmt::Display for ReferenceWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(detail) = self.detail {
            write!(
                formatter,
                "reference contract wire error {:?} at {detail}",
                self.code
            )
        } else {
            write!(formatter, "reference contract wire error {:?}", self.code)
        }
    }
}

impl std::error::Error for ReferenceWireError {}

/// Construction failures raised before any canonical bytes are accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReferenceContractError {
    Digest(DigestBuildError),
    InvalidBuildInstanceId,
    InvalidRuntimeStoreInstanceId,
    InvalidArtifactLength,
    InvalidArtifactDigest,
    InvalidTargetTriple,
    InvalidCompatibility,
    InvalidLifecycleBudget,
    InvalidProfile,
    InvalidShape,
    DomainMismatch,
    FixtureMismatch,
    ConfigMismatch,
    TargetMismatch,
    BindingNotAllowed,
    EnvelopeInvalid,
    RequestFrameTooLarge,
    CommitmentMismatch,
    InvalidBound,
    InvalidReason,
}

impl From<DigestBuildError> for ReferenceContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ReferenceContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(error) => write!(formatter, "canonical digest failed: {error}"),
            Self::InvalidBuildInstanceId => formatter.write_str("invalid build instance id"),
            Self::InvalidRuntimeStoreInstanceId => {
                formatter.write_str("invalid Runtime store instance id")
            }
            Self::InvalidArtifactLength => formatter.write_str("invalid Runtime artifact length"),
            Self::InvalidArtifactDigest => formatter.write_str("invalid Runtime artifact digest"),
            Self::InvalidTargetTriple => formatter.write_str("invalid canonical target triple"),
            Self::InvalidCompatibility => {
                formatter.write_str("compiled compatibility facts do not match")
            }
            Self::InvalidLifecycleBudget => {
                formatter.write_str("invalid reference lifecycle budget")
            }
            Self::InvalidProfile => formatter.write_str("invalid reference assembly profile"),
            Self::InvalidShape => formatter.write_str("unsupported reference target shape"),
            Self::DomainMismatch => formatter.write_str("reference subject domain mismatch"),
            Self::FixtureMismatch => formatter.write_str("reference fixture mismatch"),
            Self::ConfigMismatch => formatter.write_str("reference config is not canonical empty"),
            Self::TargetMismatch => formatter.write_str("Runtime target mismatch"),
            Self::BindingNotAllowed => {
                formatter.write_str("reference target cannot carry a PXTA binding")
            }
            Self::EnvelopeInvalid => formatter.write_str("invalid apply envelope v2"),
            Self::RequestFrameTooLarge => formatter.write_str("request frame is too large"),
            Self::CommitmentMismatch => formatter.write_str("request commitment mismatch"),
            Self::InvalidBound => formatter.write_str("invalid bounded protocol value"),
            Self::InvalidReason => formatter.write_str("invalid stable reason value"),
        }
    }
}

impl std::error::Error for ReferenceContractError {}

macro_rules! opaque_ref {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub(crate) struct $name([u8; 16]);

        impl $name {
            #[must_use]
            pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_ref!(
    FixtureExportRef,
    "Exact export identity of the compiled-in reference fixture."
);
opaque_ref!(BootstrapRequestId, "Identity of one bootstrap read.");
opaque_ref!(RuntimeQueryId, "Identity of one operation/live query.");
opaque_ref!(
    TerminalResultRef,
    "Runtime-owned reference to one canonical terminal result."
);

impl TerminalResultRef {
    fn derive_for_apply(
        target: RuntimeHostId,
        store: RuntimeStoreInstanceId,
        source_scope: SourceScopeRef,
        operation_id: ApplyOperationId,
        request_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        let mut builder = Digest32Builder::try_new(APPLY_TERMINAL_RESULT_REF_DOMAIN)?;
        builder.field_u16(RUNTIME_APPLY_TERMINAL_RECEIPT_VERSION)?;
        builder.field_bytes(target.as_bytes())?;
        builder.field_bytes(store.as_bytes())?;
        builder.field_bytes(source_scope.as_bytes())?;
        builder.field_bytes(operation_id.as_bytes())?;
        builder.field_digest(&request_digest)?;
        let digest = builder.finish();
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        if all_zero(&bytes) {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        Ok(Self::from_bytes(bytes))
    }
}

/// Nonzero release-pipeline identity embedded into one Runtime binary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuntimeBuildInstanceId([u8; 32]);

impl RuntimeBuildInstanceId {
    pub(crate) const fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, ReferenceContractError> {
        if all_zero(&bytes) {
            return Err(ReferenceContractError::InvalidBuildInstanceId);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Nonzero identity generated once for one fresh Runtime journal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuntimeStoreInstanceId([u8; 32]);

impl RuntimeStoreInstanceId {
    pub(crate) const fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, ReferenceContractError> {
        if all_zero(&bytes) {
            return Err(ReferenceContractError::InvalidRuntimeStoreInstanceId);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Canonical, bounded target triple selected by the release pipeline.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuntimeTargetTriple(Box<str>);

impl RuntimeTargetTriple {
    pub(crate) fn try_new(value: &str) -> Result<Self, ReferenceContractError> {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_TARGET_TRIPLE_BYTES
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || bytes.iter().any(|byte| {
                !byte.is_ascii_lowercase()
                    && !byte.is_ascii_digit()
                    && !matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(ReferenceContractError::InvalidTargetTriple);
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The one exact compiled fixture entry selected by profile v1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ReferenceFixtureEntryV1 {
    definition: CardDefinitionRef,
    implementation: CardImplementationRef,
    export: FixtureExportRef,
    definition_digest: Digest32,
    fixture_artifact_digest: Digest32,
}

impl ReferenceFixtureEntryV1 {
    #[must_use]
    pub(crate) const fn new(
        definition: CardDefinitionRef,
        implementation: CardImplementationRef,
        export: FixtureExportRef,
        definition_digest: Digest32,
        fixture_artifact_digest: Digest32,
    ) -> Self {
        Self {
            definition,
            implementation,
            export,
            definition_digest,
            fixture_artifact_digest,
        }
    }

    #[must_use]
    pub(crate) const fn definition(self) -> CardDefinitionRef {
        self.definition
    }

    #[must_use]
    pub(crate) const fn implementation(self) -> CardImplementationRef {
        self.implementation
    }

    #[must_use]
    pub(crate) const fn export(self) -> FixtureExportRef {
        self.export
    }

    #[must_use]
    pub(crate) const fn definition_digest(self) -> Digest32 {
        self.definition_digest
    }

    #[must_use]
    pub(crate) const fn fixture_artifact_digest(self) -> Digest32 {
        self.fixture_artifact_digest
    }
}

/// Release-pipeline descriptor for one final Runtime executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeBuildDescriptorV1 {
    build_instance_id: RuntimeBuildInstanceId,
    runtime_artifact_length: u64,
    runtime_artifact_sha256: Digest32,
    target_triple: RuntimeTargetTriple,
    compiled_reference_compatibility_digest: Digest32,
    canonical_wire: Box<[u8]>,
    descriptor_digest: Digest32,
}

impl RuntimeBuildDescriptorV1 {
    pub(crate) fn try_new(
        build_instance_id: RuntimeBuildInstanceId,
        runtime_artifact_length: u64,
        runtime_artifact_sha256: Digest32,
        target_triple: RuntimeTargetTriple,
        fixture: ReferenceFixtureEntryV1,
    ) -> Result<Self, ReferenceContractError> {
        let compatibility_digest = compiled_reference_compatibility_digest(fixture)?;
        Self::try_from_parts(
            build_instance_id,
            runtime_artifact_length,
            runtime_artifact_sha256,
            target_triple,
            compatibility_digest,
        )
    }

    fn try_from_parts(
        build_instance_id: RuntimeBuildInstanceId,
        runtime_artifact_length: u64,
        runtime_artifact_sha256: Digest32,
        target_triple: RuntimeTargetTriple,
        compiled_reference_compatibility_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        if runtime_artifact_length == 0 || runtime_artifact_length > MAX_RUNTIME_ARTIFACT_BYTES {
            return Err(ReferenceContractError::InvalidArtifactLength);
        }
        if digest_is_zero(&runtime_artifact_sha256) {
            return Err(ReferenceContractError::InvalidArtifactDigest);
        }
        if digest_is_zero(&compiled_reference_compatibility_digest) {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        let canonical_wire = build_descriptor_wire(
            build_instance_id,
            runtime_artifact_length,
            runtime_artifact_sha256,
            &target_triple,
            compiled_reference_compatibility_digest,
        );
        let descriptor_digest = digest_wire(BUILD_DESCRIPTOR_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            build_instance_id,
            runtime_artifact_length,
            runtime_artifact_sha256,
            target_triple,
            compiled_reference_compatibility_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
            descriptor_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_build_descriptor(frame)
    }

    #[must_use]
    pub(crate) const fn build_instance_id(&self) -> RuntimeBuildInstanceId {
        self.build_instance_id
    }

    #[must_use]
    pub(crate) const fn runtime_artifact_length(&self) -> u64 {
        self.runtime_artifact_length
    }

    #[must_use]
    pub(crate) const fn runtime_artifact_sha256(&self) -> Digest32 {
        self.runtime_artifact_sha256
    }

    #[must_use]
    pub(crate) const fn target_triple(&self) -> &RuntimeTargetTriple {
        &self.target_triple
    }

    #[must_use]
    pub(crate) const fn compiled_reference_compatibility_digest(&self) -> Digest32 {
        self.compiled_reference_compatibility_digest
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn descriptor_digest(&self) -> Digest32 {
        self.descriptor_digest
    }
}

/// Store-pinned build identity derived from a strict descriptor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeBuildIdentityV1 {
    build_instance_id: RuntimeBuildInstanceId,
    build_descriptor_digest: Digest32,
    runtime_artifact_sha256: Digest32,
    compiled_reference_compatibility_digest: Digest32,
}

impl RuntimeBuildIdentityV1 {
    #[must_use]
    pub(crate) const fn from_descriptor(descriptor: &RuntimeBuildDescriptorV1) -> Self {
        Self {
            build_instance_id: descriptor.build_instance_id,
            build_descriptor_digest: descriptor.descriptor_digest,
            runtime_artifact_sha256: descriptor.runtime_artifact_sha256,
            compiled_reference_compatibility_digest: descriptor
                .compiled_reference_compatibility_digest,
        }
    }

    fn try_from_parts(
        build_instance_id: RuntimeBuildInstanceId,
        build_descriptor_digest: Digest32,
        runtime_artifact_sha256: Digest32,
        compiled_reference_compatibility_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        if digest_is_zero(&build_descriptor_digest)
            || digest_is_zero(&runtime_artifact_sha256)
            || digest_is_zero(&compiled_reference_compatibility_digest)
        {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        Ok(Self {
            build_instance_id,
            build_descriptor_digest,
            runtime_artifact_sha256,
            compiled_reference_compatibility_digest,
        })
    }

    #[must_use]
    pub(crate) const fn build_instance_id(self) -> RuntimeBuildInstanceId {
        self.build_instance_id
    }

    #[must_use]
    pub(crate) const fn build_descriptor_digest(self) -> Digest32 {
        self.build_descriptor_digest
    }

    #[must_use]
    pub(crate) const fn runtime_artifact_sha256(self) -> Digest32 {
        self.runtime_artifact_sha256
    }

    #[must_use]
    pub(crate) const fn compiled_reference_compatibility_digest(self) -> Digest32 {
        self.compiled_reference_compatibility_digest
    }
}

/// The one fixed target row carried by both manifest and projection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeArtifactCompatibilityTargetRowV1 {
    target: RuntimeHostId,
    build_identity: RuntimeBuildIdentityV1,
    fixture: ReferenceFixtureEntryV1,
}

impl RuntimeArtifactCompatibilityTargetRowV1 {
    fn try_new(
        target: RuntimeHostId,
        build_identity: RuntimeBuildIdentityV1,
        fixture: ReferenceFixtureEntryV1,
    ) -> Result<Self, ReferenceContractError> {
        let expected = compiled_reference_compatibility_digest(fixture)?;
        if build_identity.compiled_reference_compatibility_digest() != expected {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        Ok(Self {
            target,
            build_identity,
            fixture,
        })
    }

    #[must_use]
    pub(crate) const fn target(self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn build_identity(self) -> RuntimeBuildIdentityV1 {
        self.build_identity
    }

    #[must_use]
    pub(crate) const fn fixture(self) -> ReferenceFixtureEntryV1 {
        self.fixture
    }
}

/// Installer-produced singleton compatibility manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeArtifactCompatibilityManifestV1 {
    row: RuntimeArtifactCompatibilityTargetRowV1,
    canonical_wire: Box<[u8]>,
    manifest_digest: Digest32,
}

impl RuntimeArtifactCompatibilityManifestV1 {
    pub(crate) fn try_new(
        target: RuntimeHostId,
        descriptor: &RuntimeBuildDescriptorV1,
        fixture: ReferenceFixtureEntryV1,
    ) -> Result<Self, ReferenceContractError> {
        let row = RuntimeArtifactCompatibilityTargetRowV1::try_new(
            target,
            RuntimeBuildIdentityV1::from_descriptor(descriptor),
            fixture,
        )?;
        Self::from_row(row)
    }

    pub(crate) fn from_row(
        row: RuntimeArtifactCompatibilityTargetRowV1,
    ) -> Result<Self, ReferenceContractError> {
        let canonical_wire = build_manifest_wire(row);
        let manifest_digest = digest_wire(COMPATIBILITY_MANIFEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            row,
            canonical_wire: canonical_wire.into_boxed_slice(),
            manifest_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_compatibility_manifest(frame)
    }

    #[must_use]
    pub(crate) const fn row(&self) -> RuntimeArtifactCompatibilityTargetRowV1 {
        self.row
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }
}

/// Digest plus the byte-identical singleton target row committed into a Slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeArtifactCompatibilityManifestProjectionV1 {
    manifest_digest: Digest32,
    row: RuntimeArtifactCompatibilityTargetRowV1,
    canonical_wire: Box<[u8]>,
}

impl RuntimeArtifactCompatibilityManifestProjectionV1 {
    #[must_use]
    pub(crate) fn from_manifest(manifest: &RuntimeArtifactCompatibilityManifestV1) -> Self {
        let canonical_wire = build_projection_wire(manifest.manifest_digest, manifest.row);
        Self {
            manifest_digest: manifest.manifest_digest,
            row: manifest.row,
            canonical_wire: canonical_wire.into_boxed_slice(),
        }
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_compatibility_projection(frame)
    }

    #[must_use]
    pub(crate) const fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }

    #[must_use]
    pub(crate) const fn row(&self) -> RuntimeArtifactCompatibilityTargetRowV1 {
        self.row
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// The only two shapes admitted by the S7/P2e reference profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(crate) enum ReferenceAssemblyModeV1 {
    OneSourceLoop = 1,
    EmptyDeactivate = 2,
}

/// Digest-covered profile singleton. Its resource constants are version-owned.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ReferenceAssemblyProfileV1 {
    mode: ReferenceAssemblyModeV1,
}

impl ReferenceAssemblyProfileV1 {
    #[must_use]
    pub(crate) const fn new(mode: ReferenceAssemblyModeV1) -> Self {
        Self { mode }
    }

    #[must_use]
    pub(crate) const fn mode(self) -> ReferenceAssemblyModeV1 {
        self.mode
    }

    #[must_use]
    pub(crate) const fn lifecycle_concurrency(self) -> u16 {
        REFERENCE_LIFECYCLE_CONCURRENCY
    }

    #[must_use]
    pub(crate) const fn mailbox_slots(self) -> u16 {
        REFERENCE_MAILBOX_SLOTS
    }

    #[must_use]
    pub(crate) const fn dispatch_slots(self) -> u16 {
        REFERENCE_DISPATCH_SLOTS
    }

    #[must_use]
    pub(crate) const fn background_task_slots(self) -> u16 {
        REFERENCE_BACKGROUND_TASK_SLOTS
    }
}

/// Version-specific Loop domain record without legacy capacity fields.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ReferenceLoopDomainSpecV1 {
    domain: DomainRef,
    start_budget: BoundedDuration,
    drain_budget: BoundedDuration,
    cleanup_budget: BoundedDuration,
}

impl ReferenceLoopDomainSpecV1 {
    pub(crate) const fn try_new(
        domain: DomainRef,
        start_budget: BoundedDuration,
        drain_budget: BoundedDuration,
        cleanup_budget: BoundedDuration,
    ) -> Result<Self, ReferenceContractError> {
        if !valid_lifecycle_budget(start_budget)
            || !valid_lifecycle_budget(drain_budget)
            || !valid_lifecycle_budget(cleanup_budget)
        {
            return Err(ReferenceContractError::InvalidLifecycleBudget);
        }
        Ok(Self {
            domain,
            start_budget,
            drain_budget,
            cleanup_budget,
        })
    }

    #[must_use]
    pub(crate) const fn domain(self) -> DomainRef {
        self.domain
    }

    #[must_use]
    pub(crate) const fn start_budget(self) -> BoundedDuration {
        self.start_budget
    }

    #[must_use]
    pub(crate) const fn drain_budget(self) -> BoundedDuration {
        self.drain_budget
    }

    #[must_use]
    pub(crate) const fn cleanup_budget(self) -> BoundedDuration {
        self.cleanup_budget
    }
}

/// Version-specific source-only subject record without ingress or dispatch fields.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ReferenceLoopSubjectSpecV1 {
    instance: InstanceRef,
    domain: DomainRef,
    fixture: ReferenceFixtureEntryV1,
    config_digest: Digest32,
}

impl ReferenceLoopSubjectSpecV1 {
    pub(crate) fn try_new(
        instance: InstanceRef,
        domain: DomainRef,
        fixture: ReferenceFixtureEntryV1,
        config_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        if config_digest != reference_empty_config_digest()? {
            return Err(ReferenceContractError::ConfigMismatch);
        }
        Ok(Self {
            instance,
            domain,
            fixture,
            config_digest,
        })
    }

    #[must_use]
    pub(crate) const fn instance(self) -> InstanceRef {
        self.instance
    }

    #[must_use]
    pub(crate) const fn domain(self) -> DomainRef {
        self.domain
    }

    #[must_use]
    pub(crate) const fn fixture(self) -> ReferenceFixtureEntryV1 {
        self.fixture
    }

    #[must_use]
    pub(crate) const fn config_digest(self) -> Digest32 {
        self.config_digest
    }
}

/// Strict PXTE v4 body for exactly one source Loop or authoritative empty state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetExecutionPlanV4 {
    projection: RuntimeArtifactCompatibilityManifestProjectionV1,
    profile: ReferenceAssemblyProfileV1,
    domain: Option<ReferenceLoopDomainSpecV1>,
    subject: Option<ReferenceLoopSubjectSpecV1>,
    canonical_wire: Box<[u8]>,
    execution_digest: Digest32,
}

impl TargetExecutionPlanV4 {
    pub(crate) fn try_one_source_loop(
        projection: RuntimeArtifactCompatibilityManifestProjectionV1,
        domain: ReferenceLoopDomainSpecV1,
        subject: ReferenceLoopSubjectSpecV1,
    ) -> Result<Self, ReferenceContractError> {
        Self::try_new(
            projection,
            ReferenceAssemblyProfileV1::new(ReferenceAssemblyModeV1::OneSourceLoop),
            Some(domain),
            Some(subject),
        )
    }

    pub(crate) fn try_empty_deactivate(
        projection: RuntimeArtifactCompatibilityManifestProjectionV1,
    ) -> Result<Self, ReferenceContractError> {
        Self::try_new(
            projection,
            ReferenceAssemblyProfileV1::new(ReferenceAssemblyModeV1::EmptyDeactivate),
            None,
            None,
        )
    }

    fn try_new(
        projection: RuntimeArtifactCompatibilityManifestProjectionV1,
        profile: ReferenceAssemblyProfileV1,
        domain: Option<ReferenceLoopDomainSpecV1>,
        subject: Option<ReferenceLoopSubjectSpecV1>,
    ) -> Result<Self, ReferenceContractError> {
        validate_reference_shape(&projection, profile, domain, subject)?;
        let canonical_wire = build_target_execution_v4_wire(&projection, profile, domain, subject);
        let execution_digest = digest_wire(TARGET_EXECUTION_V4_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            projection,
            profile,
            domain,
            subject,
            canonical_wire: canonical_wire.into_boxed_slice(),
            execution_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_target_execution_v4(frame)
    }

    #[must_use]
    pub(crate) const fn projection(&self) -> &RuntimeArtifactCompatibilityManifestProjectionV1 {
        &self.projection
    }

    #[must_use]
    pub(crate) const fn profile(&self) -> ReferenceAssemblyProfileV1 {
        self.profile
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> Option<ReferenceLoopDomainSpecV1> {
        self.domain
    }

    #[must_use]
    pub(crate) const fn subject(&self) -> Option<ReferenceLoopSubjectSpecV1> {
        self.subject
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn execution_digest(&self) -> Digest32 {
        self.execution_digest
    }
}

/// PXTA-zero plus PXTE-v4 composite committed by the existing opaque Slice field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetPlanAssignmentsV5 {
    bindings: TargetAssignments,
    execution: TargetExecutionPlanV4,
    assignment_digest: TargetAssignmentDigest,
}

impl TargetPlanAssignmentsV5 {
    pub(crate) fn try_new(
        bindings: TargetAssignments,
        execution: TargetExecutionPlanV4,
    ) -> Result<Self, ReferenceContractError> {
        bindings
            .validate()
            .map_err(|_| ReferenceContractError::BindingNotAllowed)?;
        if !bindings.is_empty() || bindings.canonical_wire() != ZERO_BINDING_PXTA {
            return Err(ReferenceContractError::BindingNotAllowed);
        }
        let assignment_digest = target_plan_assignments_v5_digest(&bindings, &execution)?;
        Ok(Self {
            bindings,
            execution,
            assignment_digest,
        })
    }

    pub(crate) fn try_from_execution(
        execution: TargetExecutionPlanV4,
    ) -> Result<Self, ReferenceContractError> {
        let bindings = TargetAssignments::try_new(Vec::new())
            .map_err(|_| ReferenceContractError::BindingNotAllowed)?;
        Self::try_new(bindings, execution)
    }

    #[must_use]
    pub(crate) const fn bindings(&self) -> &TargetAssignments {
        &self.bindings
    }

    #[must_use]
    pub(crate) const fn execution(&self) -> &TargetExecutionPlanV4 {
        &self.execution
    }

    #[must_use]
    pub(crate) const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.assignment_digest
    }
}

/// Runtime Slice bound to the exact v5 composite target digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimePlanSliceV5 {
    commitment: RuntimeSliceCommitment,
    assignments: TargetPlanAssignmentsV5,
}

impl RuntimePlanSliceV5 {
    pub(crate) fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: TargetPlanAssignmentsV5,
    ) -> Result<Self, ReferenceContractError> {
        commitment
            .validate()
            .map_err(|_| ReferenceContractError::CommitmentMismatch)?;
        if commitment.header().assignment_digest() != assignments.assignment_digest() {
            return Err(ReferenceContractError::CommitmentMismatch);
        }
        if commitment.header().target() != assignments.execution().projection().row().target() {
            return Err(ReferenceContractError::TargetMismatch);
        }
        Ok(Self {
            commitment,
            assignments,
        })
    }

    /// Strictly restores the durable `PXTA-zero || PXTE-v4` Slice body.
    ///
    /// Provenance and the expected Slice digest are journal-owned facts. The
    /// PXTE target is decoded from the canonical body, then cross-checked
    /// before the existing provenance commitment owner is used to rebuild the
    /// exact Slice commitment.
    pub(crate) fn decode_durable(
        frame: &[u8],
        target: RuntimeHostId,
        provenance: PlanProvenance,
        expected_target_slice_digest: TargetSliceDigest,
    ) -> Result<Self, ReferenceWireError> {
        if frame.len() > MAX_RUNTIME_PLAN_SLICE_V5_BYTES {
            return Err(ReferenceWireError::new(
                ReferenceWireErrorCode::FrameTooLarge,
            ));
        }
        if frame.len() < ZERO_BINDING_PXTA_BYTES {
            return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
        }

        let (binding_frame, execution_frame) = frame.split_at(ZERO_BINDING_PXTA_BYTES);
        if binding_frame != ZERO_BINDING_PXTA {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::BindingNotAllowed,
                2,
            ));
        }
        let bindings = TargetAssignments::decode(binding_frame)
            .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::BindingNotAllowed, 2))?;
        let execution = TargetExecutionPlanV4::decode(execution_frame)?;
        if execution.projection().row().target() != target {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                2,
            ));
        }
        let assignments = TargetPlanAssignmentsV5::try_new(bindings, execution)
            .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::CrossReferenceMismatch))?;
        let header = RuntimeSliceHeader::new(target, provenance, assignments.assignment_digest());
        let commitment = RuntimeSliceCommitment::try_new(header)
            .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::DigestMismatch, 8))?;
        if commitment.target_slice_digest() != expected_target_slice_digest {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::DigestMismatch,
                8,
            ));
        }
        Self::try_new(commitment, assignments).map_err(|error| match error {
            ReferenceContractError::TargetMismatch => {
                ReferenceWireError::at(ReferenceWireErrorCode::TargetMismatch, 2)
            }
            _ => ReferenceWireError::at(ReferenceWireErrorCode::DigestMismatch, 7),
        })
    }

    #[must_use]
    pub(crate) const fn commitment(&self) -> RuntimeSliceCommitment {
        self.commitment
    }

    #[must_use]
    pub(crate) const fn assignments(&self) -> &TargetPlanAssignmentsV5 {
        &self.assignments
    }
}

pub(crate) fn compiled_reference_compatibility_digest(
    fixture: ReferenceFixtureEntryV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(COMPILED_REFERENCE_COMPATIBILITY_DIGEST_DOMAIN)?;
    builder.field_bytes(RUNTIME_APPLY_REQUEST_MAGIC)?;
    builder.field_u16(RUNTIME_APPLY_REQUEST_V5_VERSION)?;
    builder.field_u16(APPLY_REQUEST_V5_HEADER_BYTES as u16)?;
    builder.field_bytes(&(MAX_RUNTIME_APPLY_REQUEST_V5_BYTES as u32).to_be_bytes())?;
    builder.field_bytes(TARGET_EXECUTION_MAGIC)?;
    builder.field_u16(TARGET_EXECUTION_PLAN_V4_VERSION)?;
    builder.field_bytes(&(MAX_TARGET_EXECUTION_PLAN_V4_BYTES as u32).to_be_bytes())?;
    builder.field_u16(COMPATIBILITY_PROJECTION_BYTES as u16)?;
    builder.field_u16(REFERENCE_LOOP_DOMAIN_BYTES as u16)?;
    builder.field_u16(REFERENCE_LOOP_SUBJECT_BYTES as u16)?;
    builder.field_bytes(&ZERO_BINDING_PXTA)?;
    builder.field_bytes(APPLY_ENVELOPE_MAGIC)?;
    builder.field_u16(RUNTIME_APPLY_ENVELOPE_V2_VERSION)?;
    builder.field_u16(APPLY_ENVELOPE_V2_FIELD_COUNT)?;
    builder.field_u16(STORE_ID_BYTES as u16)?;
    builder.field_bytes(&(MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES as u32).to_be_bytes())?;
    builder.field_u16(MAX_APPLY_AUTH_NONCE_V2_BYTES as u16)?;
    builder.field_u16(MAX_APPLY_AUTH_SIGNATURE_V2_BYTES as u16)?;
    builder.field_u16(REFERENCE_ASSEMBLY_PROFILE_VERSION)?;
    builder.field_u16(REFERENCE_LIFECYCLE_CONCURRENCY)?;
    builder.field_u16(REFERENCE_MAILBOX_SLOTS)?;
    builder.field_u16(REFERENCE_DISPATCH_SLOTS)?;
    builder.field_u16(REFERENCE_BACKGROUND_TASK_SLOTS)?;
    builder.field_u64(MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS)?;
    builder.field_bytes(TARGET_EXECUTION_V4_DIGEST_DOMAIN)?;
    builder.field_bytes(TARGET_PLAN_ASSIGNMENTS_V5_DIGEST_DOMAIN)?;
    builder.field_bytes(APPLY_ENVELOPE_V2_SIGNING_DOMAIN)?;
    builder.field_bytes(APPLY_ENVELOPE_V2_REQUEST_DIGEST_DOMAIN)?;
    builder.field_bytes(REFERENCE_EMPTY_CONFIG_DIGEST_DOMAIN)?;
    builder.field_bytes(COMPATIBILITY_PROJECTION_MAGIC)?;
    builder.field_u16(RUNTIME_ARTIFACT_COMPATIBILITY_PROJECTION_VERSION)?;
    builder.field_u16(COMPATIBILITY_PROJECTION_BYTES as u16)?;
    builder.field_bytes(COMPATIBILITY_MANIFEST_MAGIC)?;
    builder.field_u16(RUNTIME_ARTIFACT_COMPATIBILITY_MANIFEST_VERSION)?;
    builder.field_u16(COMPATIBILITY_MANIFEST_BYTES as u16)?;
    builder.field_bytes(COMPATIBILITY_MANIFEST_DIGEST_DOMAIN)?;
    builder.field_u16(BUILD_IDENTITY_BYTES as u16)?;
    builder.field_u16(FIXTURE_ENTRY_BYTES as u16)?;
    builder.field_bytes(fixture.definition().as_bytes())?;
    builder.field_bytes(fixture.implementation().as_bytes())?;
    builder.field_bytes(fixture.export().as_bytes())?;
    builder.field_digest(&fixture.definition_digest())?;
    builder.field_digest(&fixture.fixture_artifact_digest())?;
    Ok(builder.finish())
}

pub(crate) fn reference_empty_config_digest() -> Result<Digest32, DigestBuildError> {
    Ok(Digest32Builder::try_new(REFERENCE_EMPTY_CONFIG_DIGEST_DOMAIN)?.finish())
}

fn target_plan_assignments_v5_digest(
    bindings: &TargetAssignments,
    execution: &TargetExecutionPlanV4,
) -> Result<TargetAssignmentDigest, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TARGET_PLAN_ASSIGNMENTS_V5_DIGEST_DOMAIN)?;
    builder.field_digest(bindings.assignment_digest().value())?;
    builder.field_digest(&execution.execution_digest())?;
    Ok(TargetAssignmentDigest::new(builder.finish()))
}

const fn valid_lifecycle_budget(value: BoundedDuration) -> bool {
    value.value() > 0 && value.value() <= MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS
}

const fn all_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

fn digest_is_zero(digest: &Digest32) -> bool {
    all_zero(digest.as_bytes())
}

fn digest_wire(domain: &[u8], wire: &[u8]) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(domain)?;
    builder.field_bytes(wire)?;
    Ok(builder.finish())
}

fn build_descriptor_wire(
    build_instance_id: RuntimeBuildInstanceId,
    runtime_artifact_length: u64,
    runtime_artifact_sha256: Digest32,
    target_triple: &RuntimeTargetTriple,
    compatibility_digest: Digest32,
) -> Vec<u8> {
    let target = target_triple.as_str().as_bytes();
    let mut encoded = Vec::with_capacity(112 + target.len());
    encoded.extend_from_slice(BUILD_DESCRIPTOR_MAGIC);
    encoded.extend_from_slice(&RUNTIME_BUILD_DESCRIPTOR_VERSION.to_be_bytes());
    encoded.extend_from_slice(build_instance_id.as_bytes());
    encoded.extend_from_slice(&runtime_artifact_length.to_be_bytes());
    encoded.extend_from_slice(runtime_artifact_sha256.as_bytes());
    encoded.extend_from_slice(&(target.len() as u16).to_be_bytes());
    encoded.extend_from_slice(target);
    encoded.extend_from_slice(compatibility_digest.as_bytes());
    encoded
}

fn decode_build_descriptor(frame: &[u8]) -> Result<RuntimeBuildDescriptorV1, ReferenceWireError> {
    const MIN_BYTES: usize = 113;
    if frame.len() > MAX_RUNTIME_BUILD_DESCRIPTOR_BYTES {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < MIN_BYTES {
        return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
    }
    if &frame[..4] != BUILD_DESCRIPTOR_MAGIC {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != RUNTIME_BUILD_DESCRIPTOR_VERSION {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::UnsupportedVersion,
        ));
    }
    let build_instance_id_bytes = read_array(&frame[6..38]);
    let runtime_artifact_length = read_u64(&frame[38..46]);
    let runtime_artifact_sha256 = Digest32::from_bytes(read_array(&frame[46..78]));
    let target_length = usize::from(read_u16(&frame[78..80]));
    if target_length == 0 || target_length > MAX_TARGET_TRIPLE_BYTES {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldLength,
            4,
        ));
    }
    let expected_length = 80_usize
        .checked_add(target_length)
        .and_then(|length| length.checked_add(32))
        .ok_or_else(|| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldLength))?;
    if frame.len() < expected_length {
        return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
    }
    if frame.len() > expected_length {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::TrailingBytes,
        ));
    }

    let build_instance_id = RuntimeBuildInstanceId::try_from_bytes(build_instance_id_bytes)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 1))?;
    if runtime_artifact_length == 0 || runtime_artifact_length > MAX_RUNTIME_ARTIFACT_BYTES {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            2,
        ));
    }
    if digest_is_zero(&runtime_artifact_sha256) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            3,
        ));
    }
    let target_bytes = &frame[80..80 + target_length];
    let target_value = core::str::from_utf8(target_bytes)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 4))?;
    let target_triple = RuntimeTargetTriple::try_new(target_value)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 4))?;
    let compatibility_digest = Digest32::from_bytes(read_array(&frame[80 + target_length..]));
    if digest_is_zero(&compatibility_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CompatibilityMismatch,
            5,
        ));
    }
    let decoded = RuntimeBuildDescriptorV1::try_from_parts(
        build_instance_id,
        runtime_artifact_length,
        runtime_artifact_sha256,
        target_triple,
        compatibility_digest,
    )
    .map_err(descriptor_contract_wire_error)?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn descriptor_contract_wire_error(error: ReferenceContractError) -> ReferenceWireError {
    match error {
        ReferenceContractError::InvalidArtifactLength => {
            ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 2)
        }
        ReferenceContractError::InvalidArtifactDigest => {
            ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 3)
        }
        ReferenceContractError::InvalidTargetTriple => {
            ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 4)
        }
        ReferenceContractError::InvalidCompatibility => {
            ReferenceWireError::at(ReferenceWireErrorCode::CompatibilityMismatch, 5)
        }
        _ => ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue),
    }
}

fn build_manifest_wire(row: RuntimeArtifactCompatibilityTargetRowV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(COMPATIBILITY_MANIFEST_BYTES);
    encoded.extend_from_slice(COMPATIBILITY_MANIFEST_MAGIC);
    encoded.extend_from_slice(&RUNTIME_ARTIFACT_COMPATIBILITY_MANIFEST_VERSION.to_be_bytes());
    append_manifest_target_row(&mut encoded, row);
    encoded
}

fn build_projection_wire(
    manifest_digest: Digest32,
    row: RuntimeArtifactCompatibilityTargetRowV1,
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(COMPATIBILITY_PROJECTION_BYTES);
    encoded.extend_from_slice(COMPATIBILITY_PROJECTION_MAGIC);
    encoded.extend_from_slice(&RUNTIME_ARTIFACT_COMPATIBILITY_PROJECTION_VERSION.to_be_bytes());
    encoded.extend_from_slice(manifest_digest.as_bytes());
    append_manifest_target_row(&mut encoded, row);
    encoded
}

fn append_manifest_target_row(encoded: &mut Vec<u8>, row: RuntimeArtifactCompatibilityTargetRowV1) {
    encoded.extend_from_slice(row.target().as_bytes());
    append_build_identity(encoded, row.build_identity());
    encoded.extend_from_slice(&RUNTIME_APPLY_REQUEST_V5_VERSION.to_be_bytes());
    encoded.extend_from_slice(&REFERENCE_ASSEMBLY_PROFILE_VERSION.to_be_bytes());
    append_fixture_entry(encoded, row.fixture());
}

fn append_build_identity(encoded: &mut Vec<u8>, identity: RuntimeBuildIdentityV1) {
    encoded.extend_from_slice(identity.build_instance_id().as_bytes());
    encoded.extend_from_slice(identity.build_descriptor_digest().as_bytes());
    encoded.extend_from_slice(identity.runtime_artifact_sha256().as_bytes());
    encoded.extend_from_slice(
        identity
            .compiled_reference_compatibility_digest()
            .as_bytes(),
    );
}

fn append_fixture_entry(encoded: &mut Vec<u8>, fixture: ReferenceFixtureEntryV1) {
    encoded.extend_from_slice(fixture.definition().as_bytes());
    encoded.extend_from_slice(fixture.implementation().as_bytes());
    encoded.extend_from_slice(fixture.export().as_bytes());
    encoded.extend_from_slice(fixture.definition_digest().as_bytes());
    encoded.extend_from_slice(fixture.fixture_artifact_digest().as_bytes());
}

fn decode_compatibility_manifest(
    frame: &[u8],
) -> Result<RuntimeArtifactCompatibilityManifestV1, ReferenceWireError> {
    if frame.len() < COMPATIBILITY_MANIFEST_BYTES {
        return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
    }
    if frame.len() > COMPATIBILITY_MANIFEST_BYTES {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::TrailingBytes,
        ));
    }
    if &frame[..4] != COMPATIBILITY_MANIFEST_MAGIC {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != RUNTIME_ARTIFACT_COMPATIBILITY_MANIFEST_VERSION {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::UnsupportedVersion,
        ));
    }
    let mut cursor = FixedCursor::new(&frame[6..]);
    let row = decode_manifest_target_row(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::TrailingBytes,
        ));
    }
    let decoded = RuntimeArtifactCompatibilityManifestV1::from_row(row)
        .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::CompatibilityMismatch))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn decode_compatibility_projection(
    frame: &[u8],
) -> Result<RuntimeArtifactCompatibilityManifestProjectionV1, ReferenceWireError> {
    if frame.len() < COMPATIBILITY_PROJECTION_BYTES {
        return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
    }
    if frame.len() > COMPATIBILITY_PROJECTION_BYTES {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::TrailingBytes,
        ));
    }
    if &frame[..4] != COMPATIBILITY_PROJECTION_MAGIC {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != RUNTIME_ARTIFACT_COMPATIBILITY_PROJECTION_VERSION {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::UnsupportedVersion,
        ));
    }
    let manifest_digest = Digest32::from_bytes(read_array(&frame[6..38]));
    let mut cursor = FixedCursor::new(&frame[38..]);
    let row = decode_manifest_target_row(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::TrailingBytes,
        ));
    }
    let manifest = RuntimeArtifactCompatibilityManifestV1::from_row(row)
        .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::CompatibilityMismatch))?;
    if manifest.manifest_digest() != manifest_digest {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::DigestMismatch,
        ));
    }
    let decoded = RuntimeArtifactCompatibilityManifestProjectionV1::from_manifest(&manifest);
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn decode_manifest_target_row(
    cursor: &mut FixedCursor<'_>,
) -> Result<RuntimeArtifactCompatibilityTargetRowV1, ReferenceWireError> {
    let target = RuntimeHostId::from_bytes(cursor.array()?);
    let identity = decode_build_identity(cursor)?;
    let selected_apply_version = cursor.u16()?;
    if selected_apply_version != RUNTIME_APPLY_REQUEST_V5_VERSION {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::UnsupportedVersion,
            1,
        ));
    }
    let selected_profile_version = cursor.u16()?;
    if selected_profile_version != REFERENCE_ASSEMBLY_PROFILE_VERSION {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::UnsupportedVersion,
            2,
        ));
    }
    let fixture = decode_fixture_entry(cursor)?;
    RuntimeArtifactCompatibilityTargetRowV1::try_new(target, identity, fixture)
        .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::CompatibilityMismatch))
}

fn decode_build_identity(
    cursor: &mut FixedCursor<'_>,
) -> Result<RuntimeBuildIdentityV1, ReferenceWireError> {
    let build_instance_id = RuntimeBuildInstanceId::try_from_bytes(cursor.array()?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 1))?;
    let descriptor_digest = Digest32::from_bytes(cursor.array()?);
    if digest_is_zero(&descriptor_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            2,
        ));
    }
    let artifact_sha = Digest32::from_bytes(cursor.array()?);
    if digest_is_zero(&artifact_sha) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            3,
        ));
    }
    let compatibility_digest = Digest32::from_bytes(cursor.array()?);
    if digest_is_zero(&compatibility_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            4,
        ));
    }
    RuntimeBuildIdentityV1::try_from_parts(
        build_instance_id,
        descriptor_digest,
        artifact_sha,
        compatibility_digest,
    )
    .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue))
}

fn decode_fixture_entry(
    cursor: &mut FixedCursor<'_>,
) -> Result<ReferenceFixtureEntryV1, ReferenceWireError> {
    Ok(ReferenceFixtureEntryV1::new(
        CardDefinitionRef::from_bytes(cursor.array()?),
        CardImplementationRef::from_bytes(cursor.array()?),
        FixtureExportRef::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
    ))
}

fn build_target_execution_v4_wire(
    projection: &RuntimeArtifactCompatibilityManifestProjectionV1,
    profile: ReferenceAssemblyProfileV1,
    domain: Option<ReferenceLoopDomainSpecV1>,
    subject: Option<ReferenceLoopSubjectSpecV1>,
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(MAX_TARGET_EXECUTION_PLAN_V4_BYTES);
    encoded.extend_from_slice(TARGET_EXECUTION_MAGIC);
    encoded.extend_from_slice(&TARGET_EXECUTION_PLAN_V4_VERSION.to_be_bytes());
    encoded.extend_from_slice(projection.canonical_wire());
    encoded.extend_from_slice(&REFERENCE_ASSEMBLY_PROFILE_VERSION.to_be_bytes());
    encoded.push(profile.mode() as u8);
    encoded.push(u8::from(domain.is_some()));
    if let Some(domain) = domain {
        append_reference_domain(&mut encoded, domain);
    }
    encoded.push(u8::from(subject.is_some()));
    if let Some(subject) = subject {
        append_reference_subject(&mut encoded, subject);
    }
    encoded
}

fn append_reference_domain(encoded: &mut Vec<u8>, domain: ReferenceLoopDomainSpecV1) {
    encoded.extend_from_slice(domain.domain().as_bytes());
    encoded.extend_from_slice(&domain.start_budget().value().to_be_bytes());
    encoded.extend_from_slice(&domain.drain_budget().value().to_be_bytes());
    encoded.extend_from_slice(&domain.cleanup_budget().value().to_be_bytes());
}

fn append_reference_subject(encoded: &mut Vec<u8>, subject: ReferenceLoopSubjectSpecV1) {
    encoded.extend_from_slice(subject.instance().as_bytes());
    encoded.extend_from_slice(subject.domain().as_bytes());
    append_fixture_entry(encoded, subject.fixture());
    encoded.extend_from_slice(subject.config_digest().as_bytes());
}

fn validate_reference_shape(
    projection: &RuntimeArtifactCompatibilityManifestProjectionV1,
    profile: ReferenceAssemblyProfileV1,
    domain: Option<ReferenceLoopDomainSpecV1>,
    subject: Option<ReferenceLoopSubjectSpecV1>,
) -> Result<(), ReferenceContractError> {
    match (profile.mode(), domain, subject) {
        (ReferenceAssemblyModeV1::OneSourceLoop, Some(domain), Some(subject)) => {
            if subject.domain() != domain.domain() {
                return Err(ReferenceContractError::DomainMismatch);
            }
            if subject.fixture() != projection.row().fixture() {
                return Err(ReferenceContractError::FixtureMismatch);
            }
            if subject.config_digest() != reference_empty_config_digest()? {
                return Err(ReferenceContractError::ConfigMismatch);
            }
            Ok(())
        }
        (ReferenceAssemblyModeV1::EmptyDeactivate, None, None) => Ok(()),
        _ => Err(ReferenceContractError::InvalidShape),
    }
}

fn decode_target_execution_v4(frame: &[u8]) -> Result<TargetExecutionPlanV4, ReferenceWireError> {
    const MIN_BYTES: usize = 4 + 2 + COMPATIBILITY_PROJECTION_BYTES + 2 + 1 + 1 + 1;
    if frame.len() > MAX_TARGET_EXECUTION_PLAN_V4_BYTES {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < MIN_BYTES {
        return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
    }
    if &frame[..4] != TARGET_EXECUTION_MAGIC {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != TARGET_EXECUTION_PLAN_V4_VERSION {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::UnsupportedVersion,
        ));
    }
    let projection_end = 6 + COMPATIBILITY_PROJECTION_BYTES;
    let mut cursor = FixedCursor::new(&frame[projection_end..]);
    let profile_version = cursor.u16()?;
    let mode_value = cursor.u8()?;
    let domain_present = decode_presence(cursor.u8()?, 4)?;
    let domain_frame = if domain_present {
        Some(cursor.take(REFERENCE_LOOP_DOMAIN_BYTES)?)
    } else {
        None
    };
    let subject_present = decode_presence(cursor.u8()?, 5)?;
    let subject_frame = if subject_present {
        Some(cursor.take(REFERENCE_LOOP_SUBJECT_BYTES)?)
    } else {
        None
    };
    if !cursor.is_empty() {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::TrailingBytes,
        ));
    }

    let projection =
        RuntimeArtifactCompatibilityManifestProjectionV1::decode(&frame[6..projection_end])?;
    if profile_version != REFERENCE_ASSEMBLY_PROFILE_VERSION {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::UnsupportedVersion,
            2,
        ));
    }
    let mode = match mode_value {
        1 => ReferenceAssemblyModeV1::OneSourceLoop,
        2 => ReferenceAssemblyModeV1::EmptyDeactivate,
        _ => {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::UnsupportedShape,
                3,
            ));
        }
    };
    let domain = match domain_frame {
        None => None,
        Some(bytes) => {
            let mut nested = FixedCursor::new(bytes);
            Some(decode_reference_domain(&mut nested)?)
        }
    };
    let subject = match subject_frame {
        None => None,
        Some(bytes) => {
            let mut nested = FixedCursor::new(bytes);
            Some(decode_reference_subject(&mut nested)?)
        }
    };
    let decoded = TargetExecutionPlanV4::try_new(
        projection,
        ReferenceAssemblyProfileV1::new(mode),
        domain,
        subject,
    )
    .map_err(|error| target_execution_contract_wire_error(error, mode, domain, subject))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn decode_reference_domain(
    cursor: &mut FixedCursor<'_>,
) -> Result<ReferenceLoopDomainSpecV1, ReferenceWireError> {
    let domain = DomainRef::from_bytes(cursor.array()?);
    let start = BoundedDuration::from_nanos(cursor.u64()?);
    let drain = BoundedDuration::from_nanos(cursor.u64()?);
    let cleanup = BoundedDuration::from_nanos(cursor.u64()?);
    ReferenceLoopDomainSpecV1::try_new(domain, start, drain, cleanup)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 4))
}

fn decode_reference_subject(
    cursor: &mut FixedCursor<'_>,
) -> Result<ReferenceLoopSubjectSpecV1, ReferenceWireError> {
    let instance = InstanceRef::from_bytes(cursor.array()?);
    let domain = DomainRef::from_bytes(cursor.array()?);
    let fixture = decode_fixture_entry(cursor)?;
    let config = Digest32::from_bytes(cursor.array()?);
    ReferenceLoopSubjectSpecV1::try_new(instance, domain, fixture, config)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::FixtureMismatch, 5))
}

fn target_execution_contract_wire_error(
    error: ReferenceContractError,
    mode: ReferenceAssemblyModeV1,
    domain: Option<ReferenceLoopDomainSpecV1>,
    subject: Option<ReferenceLoopSubjectSpecV1>,
) -> ReferenceWireError {
    match error {
        ReferenceContractError::DomainMismatch => {
            ReferenceWireError::at(ReferenceWireErrorCode::CrossReferenceMismatch, 5)
        }
        ReferenceContractError::FixtureMismatch | ReferenceContractError::ConfigMismatch => {
            ReferenceWireError::at(ReferenceWireErrorCode::FixtureMismatch, 5)
        }
        ReferenceContractError::InvalidShape => match mode {
            ReferenceAssemblyModeV1::OneSourceLoop if domain.is_none() => {
                ReferenceWireError::at(ReferenceWireErrorCode::UnsupportedShape, 4)
            }
            ReferenceAssemblyModeV1::EmptyDeactivate if domain.is_some() => {
                ReferenceWireError::at(ReferenceWireErrorCode::UnsupportedShape, 4)
            }
            ReferenceAssemblyModeV1::OneSourceLoop | ReferenceAssemblyModeV1::EmptyDeactivate
                if subject.is_some() =>
            {
                ReferenceWireError::at(ReferenceWireErrorCode::UnsupportedShape, 5)
            }
            ReferenceAssemblyModeV1::EmptyDeactivate => {
                ReferenceWireError::at(ReferenceWireErrorCode::UnsupportedShape, 4)
            }
            ReferenceAssemblyModeV1::OneSourceLoop => {
                ReferenceWireError::at(ReferenceWireErrorCode::UnsupportedShape, 5)
            }
        },
        _ => ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue),
    }
}

fn decode_presence(value: u8, detail: u16) -> Result<bool, ReferenceWireError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidPresence,
            detail,
        )),
    }
}

struct FixedCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> FixedCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ReferenceWireError> {
        if self.remaining.len() < count {
            return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReferenceWireError> {
        Ok(read_array(self.take(N)?))
    }

    fn u8(&mut self) -> Result<u8, ReferenceWireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ReferenceWireError> {
        Ok(read_u16(self.take(2)?))
    }

    fn u64(&mut self) -> Result<u64, ReferenceWireError> {
        Ok(read_u64(self.take(8)?))
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let Ok(value) = bytes.try_into() else {
        unreachable!("caller validates fixed field width")
    };
    value
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(read_array(bytes))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(read_array(bytes))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(read_array(bytes))
}

/// Canonical bytes signed by the Controller request principal for envelope v2.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ApplyRequestSigningTranscriptV2(Box<[u8]>);

impl ApplyRequestSigningTranscriptV2 {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent envelope v2 producer value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeApplyEnvelopeV2Draft {
    control_commitment: RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    expected_runtime_store_instance_id: RuntimeStoreInstanceId,
    auth_claim: ApplyRequestAuthClaim,
}

impl RuntimeApplyEnvelopeV2Draft {
    pub(crate) fn try_new(
        control_commitment: RuntimeApplyControlCommitment,
        temporal: ApplyTemporalConstraint,
        expected_runtime_store_instance_id: RuntimeStoreInstanceId,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ReferenceContractError> {
        control_commitment
            .validate()
            .map_err(|_| ReferenceContractError::EnvelopeInvalid)?;
        validate_v2_auth_claim(&auth_claim)?;
        Ok(Self {
            control_commitment,
            temporal,
            expected_runtime_store_instance_id,
            auth_claim,
        })
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ApplyRequestSigningTranscriptV2, ReferenceContractError> {
        build_apply_v2_signing_transcript(
            &self.control_commitment,
            self.temporal,
            self.expected_runtime_store_instance_id,
            &self.auth_claim,
        )
    }

    pub(crate) fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeApplyEnvelopeV2, ReferenceContractError> {
        validate_signature(signature, MAX_APPLY_AUTH_SIGNATURE_V2_BYTES)?;
        let authentication = ApplyRequestAuthentication::try_new(self.auth_claim, signature)
            .map_err(|_| ReferenceContractError::EnvelopeInvalid)?;
        RuntimeApplyEnvelopeV2::try_new(
            self.control_commitment,
            self.temporal,
            self.expected_runtime_store_instance_id,
            authentication,
        )
    }
}

/// Signed v2 apply envelope binding the request to one exact Runtime store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeApplyEnvelopeV2 {
    control_commitment: RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    expected_runtime_store_instance_id: RuntimeStoreInstanceId,
    authentication: ApplyRequestAuthentication,
    canonical_wire: Box<[u8]>,
    request_digest: Digest32,
}

impl RuntimeApplyEnvelopeV2 {
    pub(crate) fn try_new(
        control_commitment: RuntimeApplyControlCommitment,
        temporal: ApplyTemporalConstraint,
        expected_runtime_store_instance_id: RuntimeStoreInstanceId,
        authentication: ApplyRequestAuthentication,
    ) -> Result<Self, ReferenceContractError> {
        control_commitment
            .validate()
            .map_err(|_| ReferenceContractError::EnvelopeInvalid)?;
        validate_v2_auth_claim(authentication.claim())?;
        validate_signature(
            authentication.signature(),
            MAX_APPLY_AUTH_SIGNATURE_V2_BYTES,
        )?;
        let canonical_wire = build_apply_envelope_v2_wire(
            &control_commitment,
            temporal,
            expected_runtime_store_instance_id,
            &authentication,
        )?;
        if canonical_wire.len() > MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        let request_digest = digest_wire(APPLY_ENVELOPE_V2_REQUEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            control_commitment,
            temporal,
            expected_runtime_store_instance_id,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            request_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_apply_envelope_v2(frame)
    }

    #[must_use]
    pub(crate) const fn control_commitment(&self) -> &RuntimeApplyControlCommitment {
        &self.control_commitment
    }

    #[must_use]
    pub(crate) const fn temporal(&self) -> ApplyTemporalConstraint {
        self.temporal
    }

    #[must_use]
    pub(crate) const fn expected_runtime_store_instance_id(&self) -> RuntimeStoreInstanceId {
        self.expected_runtime_store_instance_id
    }

    #[must_use]
    pub(crate) const fn authentication(&self) -> &ApplyRequestAuthentication {
        &self.authentication
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    pub(crate) fn validate_expected_store(
        &self,
        local_store: RuntimeStoreInstanceId,
    ) -> Result<(), ReferenceWireError> {
        if self.expected_runtime_store_instance_id != local_store {
            return Err(ReferenceWireError::new(
                ReferenceWireErrorCode::RuntimeStoreMismatch,
            ));
        }
        Ok(())
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ApplyRequestSigningTranscriptV2, ReferenceContractError> {
        build_apply_v2_signing_transcript(
            &self.control_commitment,
            self.temporal,
            self.expected_runtime_store_instance_id,
            self.authentication.claim(),
        )
    }
}

/// Strict PXAR v5 request carrying envelope v2, zero-binding PXTA, and PXTE v4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeApplyRequestV5 {
    envelope: RuntimeApplyEnvelopeV2,
    slice: RuntimePlanSliceV5,
    canonical_wire: Box<[u8]>,
}

impl RuntimeApplyRequestV5 {
    pub(crate) fn try_new(
        envelope: RuntimeApplyEnvelopeV2,
        slice: RuntimePlanSliceV5,
    ) -> Result<Self, ReferenceContractError> {
        if envelope.control_commitment().slice() != slice.commitment() {
            return Err(ReferenceContractError::CommitmentMismatch);
        }
        if slice.commitment().header().target()
            != slice.assignments().execution().projection().row().target()
        {
            return Err(ReferenceContractError::TargetMismatch);
        }
        let canonical_wire = build_runtime_apply_request_v5_wire(&envelope, &slice);
        if canonical_wire.len() > MAX_RUNTIME_APPLY_REQUEST_V5_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_runtime_apply_request_v5(frame)
    }

    #[must_use]
    pub(crate) const fn envelope(&self) -> &RuntimeApplyEnvelopeV2 {
        &self.envelope
    }

    #[must_use]
    pub(crate) const fn slice(&self) -> &RuntimePlanSliceV5 {
        &self.slice
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the exact nested RuntimePlanSlice v5 bytes (`PXTA || PXTE`).
    ///
    /// The PXAR v5 codec owns this range calculation. Facades and Runtime
    /// consumers must not parse outer-frame offsets independently.
    #[must_use]
    pub(crate) fn canonical_slice_wire(&self) -> &[u8] {
        let slice_offset = APPLY_REQUEST_V5_HEADER_BYTES + self.envelope.canonical_wire().len();
        &self.canonical_wire[slice_offset..]
    }
}

fn validate_v2_auth_claim(claim: &ApplyRequestAuthClaim) -> Result<(), ReferenceContractError> {
    validate_nonce(claim.nonce(), MAX_APPLY_AUTH_NONCE_V2_BYTES)
}

fn validate_nonce(bytes: &[u8], maximum: usize) -> Result<(), ReferenceContractError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ReferenceContractError::InvalidBound);
    }
    Ok(())
}

fn validate_signature(bytes: &[u8], maximum: usize) -> Result<(), ReferenceContractError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ReferenceContractError::InvalidBound);
    }
    Ok(())
}

fn build_apply_v2_signing_transcript(
    commitment: &RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    store: RuntimeStoreInstanceId,
    auth_claim: &ApplyRequestAuthClaim,
) -> Result<ApplyRequestSigningTranscriptV2, ReferenceContractError> {
    let mut encoded = Vec::with_capacity(MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES);
    encoded.extend_from_slice(SIGNING_TRANSCRIPT_MAGIC);
    encoded.extend_from_slice(&APPLY_REQUEST_SIGNING_TRANSCRIPT_V2_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(APPLY_ENVELOPE_V2_SIGNING_DOMAIN.len() as u16).to_be_bytes());
    encoded.extend_from_slice(APPLY_ENVELOPE_V2_SIGNING_DOMAIN);
    encoded.extend_from_slice(&APPLY_SIGNING_V2_FIELD_COUNT.to_be_bytes());
    append_apply_v2_fields(&mut encoded, commitment, temporal, store, auth_claim, None)?;
    if encoded.len() > MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES {
        return Err(ReferenceContractError::RequestFrameTooLarge);
    }
    Ok(ApplyRequestSigningTranscriptV2(encoded.into_boxed_slice()))
}

fn build_apply_envelope_v2_wire(
    commitment: &RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    store: RuntimeStoreInstanceId,
    authentication: &ApplyRequestAuthentication,
) -> Result<Vec<u8>, ReferenceContractError> {
    let mut encoded = Vec::with_capacity(MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES);
    encoded.extend_from_slice(APPLY_ENVELOPE_MAGIC);
    encoded.extend_from_slice(&RUNTIME_APPLY_ENVELOPE_V2_VERSION.to_be_bytes());
    encoded.extend_from_slice(&APPLY_ENVELOPE_V2_FIELD_COUNT.to_be_bytes());
    append_apply_v2_fields(
        &mut encoded,
        commitment,
        temporal,
        store,
        authentication.claim(),
        Some(authentication.signature()),
    )?;
    Ok(encoded)
}

fn append_apply_v2_fields(
    encoded: &mut Vec<u8>,
    commitment: &RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    store: RuntimeStoreInstanceId,
    auth_claim: &ApplyRequestAuthClaim,
    auth_signature: Option<&[u8]>,
) -> Result<(), ReferenceContractError> {
    let slice = commitment.slice();
    let header = slice.header();
    let provenance = header.provenance();
    let control = commitment.control();
    let writer = control.writer_context();
    let proof = writer.proof();
    let proof_authority = proof.authority();
    let proof_claim = proof.claim();
    let proof_digest = proof
        .envelope_digest()
        .map_err(ReferenceContractError::Digest)?;
    let (expected_tag, expected_digest) = match control.expected_active() {
        ExpectedActive::None => (0_u16, Digest32::from_bytes([0; 32])),
        ExpectedActive::Exact(digest) => (1_u16, *digest.value()),
    };

    append_tlv(encoded, 1, &header.contract_version().to_be_bytes());
    append_tlv(encoded, 2, header.target().as_bytes());
    append_tlv(encoded, 3, provenance.source_scope().as_bytes());
    append_tlv(encoded, 4, provenance.source_plan().as_bytes());
    append_tlv(
        encoded,
        5,
        &provenance.source_revision().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        6,
        provenance.source_plan_digest().value().as_bytes(),
    );
    append_tlv(encoded, 7, header.assignment_digest().value().as_bytes());
    append_tlv(encoded, 8, slice.target_slice_digest().value().as_bytes());
    append_tlv(encoded, 9, writer.writer().as_bytes());
    append_tlv(encoded, 10, &writer.epoch().value().to_be_bytes());
    append_tlv(encoded, 11, proof_authority.authority().as_bytes());
    append_tlv(encoded, 12, proof_authority.key().as_bytes());
    append_tlv(
        encoded,
        13,
        &proof_authority.algorithm().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        14,
        &proof_authority.algorithm_version().to_be_bytes(),
    );
    append_tlv(encoded, 15, proof_claim.source_scope().as_bytes());
    append_tlv(encoded, 16, proof_claim.writer().as_bytes());
    append_tlv(encoded, 17, &proof_claim.epoch().value().to_be_bytes());
    append_tlv(
        encoded,
        18,
        &proof_claim.supersedes_through_epoch().value().to_be_bytes(),
    );
    append_tlv(encoded, 19, proof.nonce());
    append_tlv(encoded, 20, proof.signature());
    append_tlv(encoded, 21, proof_digest.as_bytes());
    append_tlv(encoded, 22, &expected_tag.to_be_bytes());
    append_tlv(encoded, 23, expected_digest.as_bytes());
    append_tlv(encoded, 24, control.operation_id().as_bytes());
    append_tlv(encoded, 25, commitment.commitment_digest().as_bytes());
    append_tlv(encoded, 26, &temporal.version().to_be_bytes());
    append_tlv(encoded, 27, temporal.constraint_id().as_bytes());
    append_tlv(encoded, 28, temporal.target_clock_domain().as_bytes());
    append_tlv(
        encoded,
        29,
        &temporal.target_clock_generation().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        30,
        &temporal.original_budget().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        31,
        &temporal.remaining_budget().value().to_be_bytes(),
    );
    append_tlv(encoded, 32, store.as_bytes());
    append_tlv(encoded, 33, auth_claim.principal().as_bytes());
    append_tlv(encoded, 34, auth_claim.key().as_bytes());
    append_tlv(encoded, 35, &auth_claim.algorithm().value().to_be_bytes());
    append_tlv(encoded, 36, &auth_claim.algorithm_version().to_be_bytes());
    append_tlv(encoded, 37, auth_claim.nonce());
    if let Some(signature) = auth_signature {
        append_tlv(encoded, 38, signature);
    }
    Ok(())
}

fn append_tlv(encoded: &mut Vec<u8>, tag: u16, value: &[u8]) {
    encoded.extend_from_slice(&tag.to_be_bytes());
    encoded.extend_from_slice(&(value.len() as u32).to_be_bytes());
    encoded.extend_from_slice(value);
}

fn decode_apply_envelope_v2(frame: &[u8]) -> Result<RuntimeApplyEnvelopeV2, ReferenceWireError> {
    let fields = parse_tlv_frame(
        frame,
        APPLY_ENVELOPE_MAGIC,
        RUNTIME_APPLY_ENVELOPE_V2_VERSION,
        APPLY_ENVELOPE_V2_FIELD_COUNT,
        MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES,
        valid_apply_v2_field_length,
    )?;

    let provenance = PlanProvenance::new(
        SourceScopeRef::from_bytes(fields.array(3)?),
        SourcePlanRef::from_bytes(fields.array(4)?),
        SourcePlanRevision::new(fields.u64(5)?),
        SourcePlanDigest::new(Digest32::from_bytes(fields.array(6)?)),
    );
    let header = RuntimeSliceHeader::new(
        RuntimeHostId::from_bytes(fields.array(2)?),
        provenance,
        TargetAssignmentDigest::new(Digest32::from_bytes(fields.array(7)?)),
    );
    if fields.u16(1)? != header.contract_version() {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::UnsupportedVersion,
            1,
        ));
    }
    let slice = RuntimeSliceCommitment::try_new(header)
        .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::DigestMismatch))?;
    if slice.target_slice_digest().value().as_bytes() != fields.get(8) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::DigestMismatch,
            8,
        ));
    }

    if fields.get(9) != fields.get(16) || fields.get(10) != fields.get(17) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CrossReferenceMismatch,
            9,
        ));
    }
    let proof_algorithm = TenureProofAlgorithm::try_new(fields.u16(13)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 13))?;
    let proof_algorithm_version = fields.u16(14)?;
    if proof_algorithm_version == 0 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            14,
        ));
    }
    if fields.get(3) != fields.get(15) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CrossReferenceMismatch,
            15,
        ));
    }
    let proof_epoch = fields.u64(17)?;
    let supersedes_through_epoch = fields.u64(18)?;
    if proof_epoch == 0 || supersedes_through_epoch >= proof_epoch {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            17,
        ));
    }

    let proof_authority = TenureProofAuthority::try_new(
        TenureAuthorityRef::from_bytes(fields.array(11)?),
        TenureKeyRef::from_bytes(fields.array(12)?),
        proof_algorithm,
        proof_algorithm_version,
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 14))?;
    let proof_claim = WriterTenureClaim::try_new(
        SourceScopeRef::from_bytes(fields.array(15)?),
        PlanWriterRef::from_bytes(fields.array(16)?),
        PlanWriterEpoch::new(proof_epoch),
        PlanWriterEpoch::new(supersedes_through_epoch),
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 17))?;
    let proof =
        WriterTenureProof::try_new(proof_authority, proof_claim, fields.get(19), fields.get(20))
            .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 19))?;
    let proof_digest = proof
        .envelope_digest()
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::DigestMismatch, 21))?;
    if proof_digest.as_bytes() != fields.get(21) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::DigestMismatch,
            21,
        ));
    }
    let writer = PlanWriterContext::try_new(
        PlanWriterRef::from_bytes(fields.array(9)?),
        PlanWriterEpoch::new(fields.u64(10)?),
        proof,
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::CrossReferenceMismatch, 9))?;
    let expected_digest = Digest32::from_bytes(fields.array(23)?);
    let expected_active = match fields.u16(22)? {
        0 if digest_is_zero(&expected_digest) => ExpectedActive::None,
        1 => ExpectedActive::Exact(TargetSliceDigest::new(expected_digest)),
        _ => {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::InvalidFieldValue,
                22,
            ));
        }
    };
    let control = RuntimeApplyControl::new(
        writer,
        expected_active,
        ApplyOperationId::from_bytes(fields.array(24)?),
    );
    let commitment = RuntimeApplyControlCommitment::try_new(slice, control)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::CrossReferenceMismatch, 15))?;
    if commitment.commitment_digest().as_bytes() != fields.get(25) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::DigestMismatch,
            25,
        ));
    }

    let temporal_version = fields.u16(26)?;
    let original_budget = fields.u64(30)?;
    let remaining_budget = fields.u64(31)?;
    if temporal_version != APPLY_TEMPORAL_CONSTRAINT_VERSION
        || original_budget == 0
        || remaining_budget > original_budget
    {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            26,
        ));
    }
    let clock_generation = ClockGeneration::try_new(fields.u64(29)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 29))?;
    let temporal = ApplyTemporalConstraint::try_from_parts(
        temporal_version,
        TemporalConstraintId::from_bytes(fields.array(27)?),
        ClockDomainRef::from_bytes(fields.array(28)?),
        clock_generation,
        BoundedDuration::from_nanos(original_budget),
        BoundedDuration::from_nanos(remaining_budget),
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 26))?;
    let store = RuntimeStoreInstanceId::try_from_bytes(fields.array(32)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 32))?;
    let auth_algorithm = ApplyAuthAlgorithm::try_new(fields.u16(35)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 35))?;
    let auth_algorithm_version = fields.u16(36)?;
    if auth_algorithm_version == 0 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            36,
        ));
    }
    let auth_claim = ApplyRequestAuthClaim::try_new(
        PrincipalRef::from_bytes(fields.array(33)?),
        ApplyAuthKeyRef::from_bytes(fields.array(34)?),
        auth_algorithm,
        auth_algorithm_version,
        fields.get(37),
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 37))?;
    let authentication = ApplyRequestAuthentication::try_new(auth_claim, fields.get(38))
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidSignatureField, 38))?;
    let decoded = RuntimeApplyEnvelopeV2::try_new(commitment, temporal, store, authentication)
        .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn valid_apply_v2_field_length(tag: u16, length: usize) -> bool {
    match tag {
        1 | 13 | 14 | 22 | 26 | 35 | 36 => length == 2,
        2..=4 | 9 | 11 | 12 | 15 | 16 | 24 | 27 | 28 | 33 | 34 => length == 16,
        5 | 10 | 17 | 18 | 29..=31 => length == 8,
        6..=8 | 21 | 23 | 25 | 32 => length == 32,
        19 => (1..=MAX_TENURE_NONCE_BYTES).contains(&length),
        20 => (1..=MAX_TENURE_SIGNATURE_BYTES).contains(&length),
        37 => (1..=MAX_APPLY_AUTH_NONCE_V2_BYTES).contains(&length),
        38 => (1..=MAX_APPLY_AUTH_SIGNATURE_V2_BYTES).contains(&length),
        _ => false,
    }
}

fn build_runtime_apply_request_v5_wire(
    envelope: &RuntimeApplyEnvelopeV2,
    slice: &RuntimePlanSliceV5,
) -> Vec<u8> {
    let bindings = slice.assignments().bindings().canonical_wire();
    let execution = slice.assignments().execution().canonical_wire();
    let mut encoded = Vec::with_capacity(
        APPLY_REQUEST_V5_HEADER_BYTES
            + envelope.canonical_wire().len()
            + bindings.len()
            + execution.len(),
    );
    encoded.extend_from_slice(RUNTIME_APPLY_REQUEST_MAGIC);
    encoded.extend_from_slice(&RUNTIME_APPLY_REQUEST_V5_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(envelope.canonical_wire().len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(bindings.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(execution.len() as u32).to_be_bytes());
    encoded.extend_from_slice(envelope.canonical_wire());
    encoded.extend_from_slice(bindings);
    encoded.extend_from_slice(execution);
    encoded
}

fn decode_runtime_apply_request_v5(
    frame: &[u8],
) -> Result<RuntimeApplyRequestV5, ReferenceWireError> {
    if frame.len() > MAX_RUNTIME_APPLY_REQUEST_V5_BYTES {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < APPLY_REQUEST_V5_HEADER_BYTES {
        return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
    }
    if &frame[..4] != RUNTIME_APPLY_REQUEST_MAGIC {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != RUNTIME_APPLY_REQUEST_V5_VERSION {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::UnsupportedVersion,
        ));
    }
    let envelope_length = read_u32(&frame[6..10]) as usize;
    let bindings_length = read_u32(&frame[10..14]) as usize;
    let execution_length = read_u32(&frame[14..18]) as usize;
    if envelope_length > MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::FrameTooLarge,
            1,
        ));
    }
    if bindings_length != ZERO_BINDING_PXTA_BYTES {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::BindingNotAllowed,
            2,
        ));
    }
    if execution_length > MAX_TARGET_EXECUTION_PLAN_V4_BYTES {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::FrameTooLarge,
            3,
        ));
    }
    let expected_length = APPLY_REQUEST_V5_HEADER_BYTES
        .checked_add(envelope_length)
        .and_then(|length| length.checked_add(bindings_length))
        .and_then(|length| length.checked_add(execution_length))
        .ok_or_else(|| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldLength))?;
    if frame.len() < expected_length {
        return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
    }
    if frame.len() > expected_length {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::TrailingBytes,
        ));
    }
    let envelope_start = APPLY_REQUEST_V5_HEADER_BYTES;
    let envelope_end = envelope_start + envelope_length;
    let bindings_end = envelope_end + bindings_length;
    let envelope = RuntimeApplyEnvelopeV2::decode(&frame[envelope_start..envelope_end])?;
    let binding_frame = &frame[envelope_end..bindings_end];
    if binding_frame != ZERO_BINDING_PXTA {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::BindingNotAllowed,
            2,
        ));
    }
    let bindings = TargetAssignments::decode(binding_frame)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::BindingNotAllowed, 2))?;
    let execution = TargetExecutionPlanV4::decode(&frame[bindings_end..])?;
    let assignments = TargetPlanAssignmentsV5::try_new(bindings, execution)
        .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::CrossReferenceMismatch))?;
    if envelope.control_commitment().slice().header().target()
        != assignments.execution().projection().row().target()
    {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::TargetMismatch,
            2,
        ));
    }
    if envelope
        .control_commitment()
        .slice()
        .header()
        .assignment_digest()
        != assignments.assignment_digest()
    {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::DigestMismatch,
            7,
        ));
    }
    let slice = RuntimePlanSliceV5::try_new(envelope.control_commitment().slice(), assignments)
        .map_err(|error| match error {
            ReferenceContractError::TargetMismatch => {
                ReferenceWireError::at(ReferenceWireErrorCode::TargetMismatch, 2)
            }
            _ => ReferenceWireError::at(ReferenceWireErrorCode::DigestMismatch, 7),
        })?;
    let decoded = RuntimeApplyRequestV5::try_new(envelope, slice)
        .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::CrossReferenceMismatch))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

struct ParsedTlvFields<'a> {
    values: Vec<&'a [u8]>,
}

impl<'a> ParsedTlvFields<'a> {
    fn get(&self, tag: u16) -> &'a [u8] {
        self.values[usize::from(tag - 1)]
    }

    fn array<const N: usize>(&self, tag: u16) -> Result<[u8; N], ReferenceWireError> {
        self.get(tag)
            .try_into()
            .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldLength, tag))
    }

    fn u16(&self, tag: u16) -> Result<u16, ReferenceWireError> {
        Ok(u16::from_be_bytes(self.array(tag)?))
    }

    fn u32(&self, tag: u16) -> Result<u32, ReferenceWireError> {
        Ok(u32::from_be_bytes(self.array(tag)?))
    }

    fn u64(&self, tag: u16) -> Result<u64, ReferenceWireError> {
        Ok(u64::from_be_bytes(self.array(tag)?))
    }
}

fn parse_tlv_frame<'a>(
    frame: &'a [u8],
    magic: &[u8],
    version: u16,
    field_count: u16,
    maximum: usize,
    valid_field_length: impl Fn(u16, usize) -> bool,
) -> Result<ParsedTlvFields<'a>, ReferenceWireError> {
    if frame.len() > maximum {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::FrameTooLarge,
        ));
    }
    let header_length = magic.len() + 4;
    if frame.len() < header_length {
        return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
    }
    if &frame[..magic.len()] != magic {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[magic.len()..magic.len() + 2]) != version {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::UnsupportedVersion,
        ));
    }
    let declared_count = read_u16(&frame[magic.len() + 2..header_length]);
    if declared_count < field_count {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::MissingField,
            declared_count + 1,
        ));
    }
    if declared_count > field_count {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::UnknownField,
            field_count + 1,
        ));
    }
    let mut cursor = header_length;
    let mut values = Vec::with_capacity(usize::from(field_count));
    for expected_tag in 1..=field_count {
        let tlv_end = cursor
            .checked_add(TLV_HEADER_BYTES)
            .ok_or_else(|| ReferenceWireError::new(ReferenceWireErrorCode::Truncated))?;
        if tlv_end > frame.len() {
            return Err(ReferenceWireError::new(ReferenceWireErrorCode::Truncated));
        }
        let tag = read_u16(&frame[cursor..cursor + 2]);
        let value_length = read_u32(&frame[cursor + 2..tlv_end]) as usize;
        cursor = tlv_end;
        if tag == 0 || tag > field_count {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::UnknownField,
                tag,
            ));
        }
        if tag < expected_tag {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::DuplicateField,
                tag,
            ));
        }
        if tag > expected_tag {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::OutOfOrderField,
                tag,
            ));
        }
        if !valid_field_length(tag, value_length) {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::InvalidFieldLength,
                tag,
            ));
        }
        let value_end = cursor
            .checked_add(value_length)
            .ok_or_else(|| ReferenceWireError::at(ReferenceWireErrorCode::Truncated, tag))?;
        if value_end > frame.len() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::Truncated,
                tag,
            ));
        }
        values.push(&frame[cursor..value_end]);
        cursor = value_end;
    }
    if cursor != frame.len() {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::TrailingBytes,
        ));
    }
    Ok(ParsedTlvFields { values })
}

/// Canonical identity-bound local control channel facts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeChannelBindingV1 {
    target: RuntimeHostId,
    runtime_peer: PrincipalRef,
    local_endpoint_identity_digest: Digest32,
    peer_credentials_digest: Digest32,
    binding_digest: Digest32,
}

impl RuntimeChannelBindingV1 {
    pub(crate) fn try_new(
        target: RuntimeHostId,
        runtime_peer: PrincipalRef,
        local_endpoint_identity_digest: Digest32,
        peer_credentials_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        if digest_is_zero(&local_endpoint_identity_digest)
            || digest_is_zero(&peer_credentials_digest)
        {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        let mut builder = Digest32Builder::try_new(LOCAL_CONTROL_CHANNEL_BINDING_DIGEST_DOMAIN)?;
        builder.field_u16(LOCAL_CONTROL_CHANNEL_BINDING_VERSION)?;
        builder.field_bytes(target.as_bytes())?;
        builder.field_bytes(runtime_peer.as_bytes())?;
        builder.field_digest(&local_endpoint_identity_digest)?;
        builder.field_digest(&peer_credentials_digest)?;
        let binding_digest = builder.finish();
        Ok(Self {
            target,
            runtime_peer,
            local_endpoint_identity_digest,
            peer_credentials_digest,
            binding_digest,
        })
    }

    #[must_use]
    pub(crate) const fn target(self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn runtime_peer(self) -> PrincipalRef {
        self.runtime_peer
    }

    #[must_use]
    pub(crate) const fn local_endpoint_identity_digest(self) -> Digest32 {
        self.local_endpoint_identity_digest
    }

    #[must_use]
    pub(crate) const fn peer_credentials_digest(self) -> Digest32 {
        self.peer_credentials_digest
    }

    #[must_use]
    pub(crate) const fn binding_digest(self) -> Digest32 {
        self.binding_digest
    }
}

pub(crate) fn reference_profile_fingerprint(
    fixture: ReferenceFixtureEntryV1,
) -> Result<Digest32, DigestBuildError> {
    let empty_config = reference_empty_config_digest()?;
    let mut builder = Digest32Builder::try_new(REFERENCE_PROFILE_FINGERPRINT_DIGEST_DOMAIN)?;
    builder.field_u16(REFERENCE_ASSEMBLY_PROFILE_VERSION)?;
    builder.field_u16(2)?;
    builder.field_bytes(&[ReferenceAssemblyModeV1::OneSourceLoop as u8])?;
    builder.field_bytes(&[ReferenceAssemblyModeV1::EmptyDeactivate as u8])?;
    builder.field_u16(REFERENCE_LIFECYCLE_CONCURRENCY)?;
    builder.field_u16(REFERENCE_MAILBOX_SLOTS)?;
    builder.field_u16(REFERENCE_DISPATCH_SLOTS)?;
    builder.field_u16(REFERENCE_BACKGROUND_TASK_SLOTS)?;
    builder.field_u64(MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS)?;
    builder.field_digest(&empty_config)?;
    builder.field_bytes(fixture.definition().as_bytes())?;
    builder.field_bytes(fixture.implementation().as_bytes())?;
    builder.field_bytes(fixture.export().as_bytes())?;
    builder.field_digest(&fixture.definition_digest())?;
    builder.field_digest(&fixture.fixture_artifact_digest())?;
    Ok(builder.finish())
}

/// Nonzero Runtime snapshot sequence reported by authenticated reads.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuntimeSnapshotSequence(u64);

impl RuntimeSnapshotSequence {
    pub(crate) const fn try_new(value: u64) -> Result<Self, ReferenceContractError> {
        if value == 0 {
            return Err(ReferenceContractError::InvalidBound);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub(crate) const fn value(self) -> u64 {
        self.0
    }
}

/// Nonzero Runtime process epoch advanced only after startup validation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuntimeHostEpoch(u64);

impl RuntimeHostEpoch {
    pub(crate) const fn try_new(value: u64) -> Result<Self, ReferenceContractError> {
        if value == 0 {
            return Err(ReferenceContractError::InvalidBound);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub(crate) const fn value(self) -> u64 {
        self.0
    }
}

/// Stable post-start reason visible only after the service-readiness gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub(crate) enum OperationalReasonV1 {
    Recovering = 1,
    ActiveCompatibilityMismatch = 2,
    RecoveryFailed = 3,
    OwnershipUncertain = 4,
    HistoryUnavailable = 5,
    ResourceCensusUncertain = 6,
    RuntimeBusy = 7,
    OwnershipTransferRequired = 8,
}

/// Bootstrap readiness fact, distinct from historical operation completion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub(crate) enum RuntimeBootstrapStateV1 {
    ReadyForApply = 1,
    NotReadyRecovering = 2,
    ValidatedOperationalQuarantine = 3,
    RecoveryFailedNotReady = 4,
    NotReadyBusy = 5,
}

/// Runtime response signer and live channel binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeResponseAuthClaimV1 {
    runtime_peer: PrincipalRef,
    channel_binding_digest: Digest32,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

impl RuntimeResponseAuthClaimV1 {
    pub(crate) fn try_new(
        runtime_peer: PrincipalRef,
        channel_binding_digest: Digest32,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, ReferenceContractError> {
        if algorithm_version == 0 || digest_is_zero(&channel_binding_digest) {
            return Err(ReferenceContractError::InvalidBound);
        }
        Ok(Self {
            runtime_peer,
            channel_binding_digest,
            key,
            algorithm,
            algorithm_version,
        })
    }

    #[must_use]
    pub(crate) const fn runtime_peer(self) -> PrincipalRef {
        self.runtime_peer
    }

    #[must_use]
    pub(crate) const fn channel_binding_digest(self) -> Digest32 {
        self.channel_binding_digest
    }

    #[must_use]
    pub(crate) const fn key(self) -> ApplyAuthKeyRef {
        self.key
    }

    #[must_use]
    pub(crate) const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub(crate) const fn algorithm_version(self) -> u16 {
        self.algorithm_version
    }
}

/// Complete Runtime response authentication value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeResponseAuthenticationV1 {
    claim: RuntimeResponseAuthClaimV1,
    signature: Box<[u8]>,
}

impl RuntimeResponseAuthenticationV1 {
    pub(crate) fn try_new(
        claim: RuntimeResponseAuthClaimV1,
        signature: &[u8],
    ) -> Result<Self, ReferenceContractError> {
        validate_signature(signature, MAX_CONTROL_READ_SIGNATURE_BYTES)?;
        Ok(Self {
            claim,
            signature: signature.into(),
        })
    }

    #[must_use]
    pub(crate) const fn claim(&self) -> RuntimeResponseAuthClaimV1 {
        self.claim
    }

    #[must_use]
    pub(crate) fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Request or response signing transcript for authenticated control reads.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ControlReadSigningTranscriptV1(Box<[u8]>);

impl ControlReadSigningTranscriptV1 {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent minimal bootstrap request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeBootstrapRequestDraftV1 {
    request_id: BootstrapRequestId,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    auth_claim: ApplyRequestAuthClaim,
    max_response_bytes: u32,
}

impl RuntimeBootstrapRequestDraftV1 {
    pub(crate) fn try_new(
        request_id: BootstrapRequestId,
        target: RuntimeHostId,
        source_scope: SourceScopeRef,
        auth_claim: ApplyRequestAuthClaim,
        max_response_bytes: u32,
    ) -> Result<Self, ReferenceContractError> {
        validate_control_read_auth_claim(&auth_claim)?;
        validate_response_bound(max_response_bytes, MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES)?;
        Ok(Self {
            request_id,
            target,
            source_scope,
            auth_claim,
            max_response_bytes,
        })
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
        build_bootstrap_request_transcript(self)
    }

    pub(crate) fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeBootstrapRequestV1, ReferenceContractError> {
        let authentication = ApplyRequestAuthentication::try_new(self.auth_claim, signature)
            .map_err(|_| ReferenceContractError::InvalidBound)?;
        RuntimeBootstrapRequestV1::try_new(
            self.request_id,
            self.target,
            self.source_scope,
            authentication,
            self.max_response_bytes,
        )
    }
}

/// Signed, bounded bootstrap request. It carries no writer tenure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeBootstrapRequestV1 {
    request_id: BootstrapRequestId,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    authentication: ApplyRequestAuthentication,
    max_response_bytes: u32,
    canonical_wire: Box<[u8]>,
    request_digest: Digest32,
}

impl RuntimeBootstrapRequestV1 {
    fn try_new(
        request_id: BootstrapRequestId,
        target: RuntimeHostId,
        source_scope: SourceScopeRef,
        authentication: ApplyRequestAuthentication,
        max_response_bytes: u32,
    ) -> Result<Self, ReferenceContractError> {
        validate_control_read_auth_claim(authentication.claim())?;
        validate_signature(authentication.signature(), MAX_CONTROL_READ_SIGNATURE_BYTES)?;
        validate_response_bound(max_response_bytes, MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES)?;
        let canonical_wire = build_bootstrap_request_wire(
            request_id,
            target,
            source_scope,
            &authentication,
            max_response_bytes,
        );
        if canonical_wire.len() > MAX_RUNTIME_BOOTSTRAP_REQUEST_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        let request_digest = digest_wire(BOOTSTRAP_REQUEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id,
            target,
            source_scope,
            authentication,
            max_response_bytes,
            canonical_wire: canonical_wire.into_boxed_slice(),
            request_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_bootstrap_request(frame)
    }

    #[must_use]
    pub(crate) const fn request_id(&self) -> BootstrapRequestId {
        self.request_id
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
    pub(crate) const fn authentication(&self) -> &ApplyRequestAuthentication {
        &self.authentication
    }

    #[must_use]
    pub(crate) const fn max_response_bytes(&self) -> u32 {
        self.max_response_bytes
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
        let draft = RuntimeBootstrapRequestDraftV1::try_new(
            self.request_id,
            self.target,
            self.source_scope,
            self.authentication.claim().clone(),
            self.max_response_bytes,
        )?;
        draft.signing_transcript()
    }
}

fn validate_control_read_auth_claim(
    claim: &ApplyRequestAuthClaim,
) -> Result<(), ReferenceContractError> {
    validate_nonce(claim.nonce(), MAX_CONTROL_READ_NONCE_BYTES)
}

const fn validate_response_bound(
    value: u32,
    protocol_maximum: usize,
) -> Result<(), ReferenceContractError> {
    if value == 0 || value as usize > protocol_maximum {
        return Err(ReferenceContractError::InvalidBound);
    }
    Ok(())
}

fn build_bootstrap_request_transcript(
    draft: &RuntimeBootstrapRequestDraftV1,
) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
    let mut encoded = begin_signing_transcript(
        BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
        BOOTSTRAP_REQUEST_SIGNING_FIELD_COUNT,
    );
    append_bootstrap_request_fields(
        &mut encoded,
        draft.request_id,
        draft.target,
        draft.source_scope,
        &draft.auth_claim,
        draft.max_response_bytes,
        None,
    );
    if encoded.len() > MAX_RUNTIME_BOOTSTRAP_REQUEST_BYTES {
        return Err(ReferenceContractError::RequestFrameTooLarge);
    }
    Ok(ControlReadSigningTranscriptV1(encoded.into_boxed_slice()))
}

fn build_bootstrap_request_wire(
    request_id: BootstrapRequestId,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    authentication: &ApplyRequestAuthentication,
    max_response_bytes: u32,
) -> Vec<u8> {
    let mut encoded = begin_tlv_frame(
        RUNTIME_BOOTSTRAP_REQUEST_MAGIC,
        RUNTIME_BOOTSTRAP_PROTOCOL_VERSION,
        BOOTSTRAP_REQUEST_FIELD_COUNT,
    );
    append_bootstrap_request_fields(
        &mut encoded,
        request_id,
        target,
        source_scope,
        authentication.claim(),
        max_response_bytes,
        Some(authentication.signature()),
    );
    encoded
}

fn append_bootstrap_request_fields(
    encoded: &mut Vec<u8>,
    request_id: BootstrapRequestId,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    auth_claim: &ApplyRequestAuthClaim,
    max_response_bytes: u32,
    signature: Option<&[u8]>,
) {
    append_tlv(encoded, 1, request_id.as_bytes());
    append_tlv(encoded, 2, target.as_bytes());
    append_tlv(encoded, 3, source_scope.as_bytes());
    append_tlv(encoded, 4, auth_claim.principal().as_bytes());
    append_tlv(encoded, 5, auth_claim.key().as_bytes());
    append_tlv(encoded, 6, &auth_claim.algorithm().value().to_be_bytes());
    append_tlv(encoded, 7, &auth_claim.algorithm_version().to_be_bytes());
    append_tlv(encoded, 8, auth_claim.nonce());
    append_tlv(encoded, 9, &max_response_bytes.to_be_bytes());
    if let Some(signature) = signature {
        append_tlv(encoded, 10, signature);
    }
}

fn decode_bootstrap_request(frame: &[u8]) -> Result<RuntimeBootstrapRequestV1, ReferenceWireError> {
    let fields = parse_tlv_frame(
        frame,
        RUNTIME_BOOTSTRAP_REQUEST_MAGIC,
        RUNTIME_BOOTSTRAP_PROTOCOL_VERSION,
        BOOTSTRAP_REQUEST_FIELD_COUNT,
        MAX_RUNTIME_BOOTSTRAP_REQUEST_BYTES,
        valid_bootstrap_request_field_length,
    )?;
    let authentication = decode_control_request_auth(&fields, 4, 5, 6, 7, 8, 10)?;
    let max_response_bytes = fields.u32(9)?;
    validate_response_bound(max_response_bytes, MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 9))?;
    let decoded = RuntimeBootstrapRequestV1::try_new(
        BootstrapRequestId::from_bytes(fields.array(1)?),
        RuntimeHostId::from_bytes(fields.array(2)?),
        SourceScopeRef::from_bytes(fields.array(3)?),
        authentication,
        max_response_bytes,
    )
    .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn decode_control_request_auth(
    fields: &ParsedTlvFields<'_>,
    principal_tag: u16,
    key_tag: u16,
    algorithm_tag: u16,
    algorithm_version_tag: u16,
    nonce_tag: u16,
    signature_tag: u16,
) -> Result<ApplyRequestAuthentication, ReferenceWireError> {
    let algorithm = ApplyAuthAlgorithm::try_new(fields.u16(algorithm_tag)?).map_err(|_| {
        ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, algorithm_tag)
    })?;
    let algorithm_version = fields.u16(algorithm_version_tag)?;
    if algorithm_version == 0 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            algorithm_version_tag,
        ));
    }
    let claim = ApplyRequestAuthClaim::try_new(
        PrincipalRef::from_bytes(fields.array(principal_tag)?),
        ApplyAuthKeyRef::from_bytes(fields.array(key_tag)?),
        algorithm,
        algorithm_version,
        fields.get(nonce_tag),
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, nonce_tag))?;
    ApplyRequestAuthentication::try_new(claim, fields.get(signature_tag)).map_err(|_| {
        ReferenceWireError::at(ReferenceWireErrorCode::InvalidSignatureField, signature_tag)
    })
}

fn valid_control_request_field_length(
    tag: u16,
    length: usize,
    exact: &[(u16, usize)],
    nonce_tag: u16,
    signature_tag: u16,
) -> bool {
    if tag == nonce_tag {
        (1..=MAX_CONTROL_READ_NONCE_BYTES).contains(&length)
    } else if tag == signature_tag {
        (1..=MAX_CONTROL_READ_SIGNATURE_BYTES).contains(&length)
    } else {
        exact
            .iter()
            .any(|(candidate, expected)| *candidate == tag && *expected == length)
    }
}

fn valid_bootstrap_request_field_length(tag: u16, length: usize) -> bool {
    valid_control_request_field_length(
        tag,
        length,
        &[
            (1, 16),
            (2, 16),
            (3, 16),
            (4, 16),
            (5, 16),
            (6, 2),
            (7, 2),
            (9, 4),
        ],
        8,
        10,
    )
}

fn begin_tlv_frame(magic: &[u8], version: u16, field_count: u16) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(magic);
    encoded.extend_from_slice(&version.to_be_bytes());
    encoded.extend_from_slice(&field_count.to_be_bytes());
    encoded
}

fn begin_signing_transcript(domain: &[u8], field_count: u16) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(SIGNING_TRANSCRIPT_MAGIC);
    encoded.extend_from_slice(&CONTROL_READ_SIGNING_TRANSCRIPT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    encoded.extend_from_slice(domain);
    encoded.extend_from_slice(&field_count.to_be_bytes());
    encoded
}

/// Exact host/store/clock tuple serving one authenticated bootstrap response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeBootstrapServingIdentityV1 {
    target: RuntimeHostId,
    store_instance_id: RuntimeStoreInstanceId,
    snapshot_sequence: RuntimeSnapshotSequence,
    runtime_host_epoch: RuntimeHostEpoch,
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
}

impl RuntimeBootstrapServingIdentityV1 {
    #[must_use]
    pub(crate) const fn new(
        target: RuntimeHostId,
        store_instance_id: RuntimeStoreInstanceId,
        snapshot_sequence: RuntimeSnapshotSequence,
        runtime_host_epoch: RuntimeHostEpoch,
        clock_domain: ClockDomainRef,
        clock_generation: ClockGeneration,
    ) -> Self {
        Self {
            target,
            store_instance_id,
            snapshot_sequence,
            runtime_host_epoch,
            clock_domain,
            clock_generation,
        }
    }

    #[must_use]
    pub(crate) const fn target(self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn store_instance_id(self) -> RuntimeStoreInstanceId {
        self.store_instance_id
    }

    #[must_use]
    pub(crate) const fn snapshot_sequence(self) -> RuntimeSnapshotSequence {
        self.snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(self) -> RuntimeHostEpoch {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn clock_domain(self) -> ClockDomainRef {
        self.clock_domain
    }

    #[must_use]
    pub(crate) const fn clock_generation(self) -> ClockGeneration {
        self.clock_generation
    }
}

/// Separately reported compiled actual and store-pinned compatibility tuple.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeBootstrapCompatibilityV1 {
    compiled_build_instance_id: RuntimeBuildInstanceId,
    compiled_compatibility_digest: Digest32,
    store_pinned_build_identity: RuntimeBuildIdentityV1,
    manifest_digest: Digest32,
    profile_fingerprint: Digest32,
    admission_policy_fingerprint: Digest32,
}

impl RuntimeBootstrapCompatibilityV1 {
    pub(crate) fn try_new(
        compiled_build_instance_id: RuntimeBuildInstanceId,
        compiled_compatibility_digest: Digest32,
        store_pinned_build_identity: RuntimeBuildIdentityV1,
        manifest: &RuntimeArtifactCompatibilityManifestV1,
        fixture: ReferenceFixtureEntryV1,
        admission_policy_fingerprint: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        if compiled_reference_compatibility_digest(fixture)? != compiled_compatibility_digest
            || manifest.row().build_identity() != store_pinned_build_identity
            || manifest.row().fixture() != fixture
        {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        Self::try_from_parts(
            compiled_build_instance_id,
            compiled_compatibility_digest,
            store_pinned_build_identity,
            manifest.manifest_digest(),
            reference_profile_fingerprint(fixture)?,
            admission_policy_fingerprint,
        )
    }

    fn try_from_parts(
        compiled_build_instance_id: RuntimeBuildInstanceId,
        compiled_compatibility_digest: Digest32,
        store_pinned_build_identity: RuntimeBuildIdentityV1,
        manifest_digest: Digest32,
        profile_fingerprint: Digest32,
        admission_policy_fingerprint: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        if compiled_build_instance_id != store_pinned_build_identity.build_instance_id()
            || compiled_compatibility_digest
                != store_pinned_build_identity.compiled_reference_compatibility_digest()
        {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        if digest_is_zero(&manifest_digest)
            || digest_is_zero(&profile_fingerprint)
            || digest_is_zero(&admission_policy_fingerprint)
        {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        Ok(Self {
            compiled_build_instance_id,
            compiled_compatibility_digest,
            store_pinned_build_identity,
            manifest_digest,
            profile_fingerprint,
            admission_policy_fingerprint,
        })
    }

    #[must_use]
    pub(crate) const fn compiled_build_instance_id(self) -> RuntimeBuildInstanceId {
        self.compiled_build_instance_id
    }

    #[must_use]
    pub(crate) const fn compiled_compatibility_digest(self) -> Digest32 {
        self.compiled_compatibility_digest
    }

    #[must_use]
    pub(crate) const fn store_pinned_build_identity(self) -> RuntimeBuildIdentityV1 {
        self.store_pinned_build_identity
    }

    #[must_use]
    pub(crate) const fn manifest_digest(self) -> Digest32 {
        self.manifest_digest
    }

    #[must_use]
    pub(crate) const fn profile_fingerprint(self) -> Digest32 {
        self.profile_fingerprint
    }

    #[must_use]
    pub(crate) const fn admission_policy_fingerprint(self) -> Digest32 {
        self.admission_policy_fingerprint
    }
}

/// Strictly validated facts returned by the minimal bootstrap read.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeBootstrapFactsV1 {
    target: RuntimeHostId,
    store_instance_id: RuntimeStoreInstanceId,
    snapshot_sequence: RuntimeSnapshotSequence,
    runtime_host_epoch: RuntimeHostEpoch,
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    compiled_build_instance_id: RuntimeBuildInstanceId,
    compiled_compatibility_digest: Digest32,
    store_pinned_build_identity: RuntimeBuildIdentityV1,
    manifest_digest: Digest32,
    profile_fingerprint: Digest32,
    admission_policy_fingerprint: Digest32,
    state: RuntimeBootstrapStateV1,
    reason: Option<OperationalReasonV1>,
}

impl RuntimeBootstrapFactsV1 {
    pub(crate) fn try_new(
        serving: RuntimeBootstrapServingIdentityV1,
        compatibility: RuntimeBootstrapCompatibilityV1,
        state: RuntimeBootstrapStateV1,
        reason: Option<OperationalReasonV1>,
    ) -> Result<Self, ReferenceContractError> {
        validate_bootstrap_state_reason(state, reason)?;
        Ok(Self {
            target: serving.target,
            store_instance_id: serving.store_instance_id,
            snapshot_sequence: serving.snapshot_sequence,
            runtime_host_epoch: serving.runtime_host_epoch,
            clock_domain: serving.clock_domain,
            clock_generation: serving.clock_generation,
            compiled_build_instance_id: compatibility.compiled_build_instance_id,
            compiled_compatibility_digest: compatibility.compiled_compatibility_digest,
            store_pinned_build_identity: compatibility.store_pinned_build_identity,
            manifest_digest: compatibility.manifest_digest,
            profile_fingerprint: compatibility.profile_fingerprint,
            admission_policy_fingerprint: compatibility.admission_policy_fingerprint,
            state,
            reason,
        })
    }

    #[must_use]
    pub(crate) const fn serving_identity(self) -> RuntimeBootstrapServingIdentityV1 {
        RuntimeBootstrapServingIdentityV1::new(
            self.target,
            self.store_instance_id,
            self.snapshot_sequence,
            self.runtime_host_epoch,
            self.clock_domain,
            self.clock_generation,
        )
    }

    #[must_use]
    pub(crate) const fn target(self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn store_instance_id(self) -> RuntimeStoreInstanceId {
        self.store_instance_id
    }

    #[must_use]
    pub(crate) const fn snapshot_sequence(self) -> RuntimeSnapshotSequence {
        self.snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(self) -> RuntimeHostEpoch {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn clock_domain(self) -> ClockDomainRef {
        self.clock_domain
    }

    #[must_use]
    pub(crate) const fn clock_generation(self) -> ClockGeneration {
        self.clock_generation
    }

    #[must_use]
    pub(crate) const fn compiled_build_instance_id(self) -> RuntimeBuildInstanceId {
        self.compiled_build_instance_id
    }

    #[must_use]
    pub(crate) const fn compiled_compatibility_digest(self) -> Digest32 {
        self.compiled_compatibility_digest
    }

    #[must_use]
    pub(crate) const fn store_pinned_build_identity(self) -> RuntimeBuildIdentityV1 {
        self.store_pinned_build_identity
    }

    #[must_use]
    pub(crate) const fn manifest_digest(self) -> Digest32 {
        self.manifest_digest
    }

    #[must_use]
    pub(crate) const fn profile_fingerprint(self) -> Digest32 {
        self.profile_fingerprint
    }

    #[must_use]
    pub(crate) const fn admission_policy_fingerprint(self) -> Digest32 {
        self.admission_policy_fingerprint
    }

    #[must_use]
    pub(crate) const fn state(self) -> RuntimeBootstrapStateV1 {
        self.state
    }

    #[must_use]
    pub(crate) const fn reason(self) -> Option<OperationalReasonV1> {
        self.reason
    }
}

fn validate_bootstrap_state_reason(
    state: RuntimeBootstrapStateV1,
    reason: Option<OperationalReasonV1>,
) -> Result<(), ReferenceContractError> {
    let valid = match state {
        RuntimeBootstrapStateV1::ReadyForApply => reason.is_none(),
        RuntimeBootstrapStateV1::NotReadyRecovering => {
            reason == Some(OperationalReasonV1::Recovering)
        }
        RuntimeBootstrapStateV1::ValidatedOperationalQuarantine => matches!(
            reason,
            Some(
                OperationalReasonV1::ActiveCompatibilityMismatch
                    | OperationalReasonV1::OwnershipUncertain
                    | OperationalReasonV1::HistoryUnavailable
                    | OperationalReasonV1::ResourceCensusUncertain
                    | OperationalReasonV1::OwnershipTransferRequired
            )
        ),
        RuntimeBootstrapStateV1::RecoveryFailedNotReady => {
            reason == Some(OperationalReasonV1::RecoveryFailed)
        }
        RuntimeBootstrapStateV1::NotReadyBusy => reason == Some(OperationalReasonV1::RuntimeBusy),
    };
    if !valid {
        return Err(ReferenceContractError::InvalidReason);
    }
    Ok(())
}

/// Signature-independent bootstrap response and channel-auth transcript owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeBootstrapResponseDraftV1 {
    request_id: BootstrapRequestId,
    request_digest: Digest32,
    client_nonce: Box<[u8]>,
    facts: RuntimeBootstrapFactsV1,
    auth_claim: RuntimeResponseAuthClaimV1,
    requested_max_response_bytes: u32,
}

impl RuntimeBootstrapResponseDraftV1 {
    pub(crate) fn try_new(
        request: &RuntimeBootstrapRequestV1,
        facts: RuntimeBootstrapFactsV1,
        channel: RuntimeChannelBindingV1,
        auth_claim: RuntimeResponseAuthClaimV1,
    ) -> Result<Self, ReferenceContractError> {
        if request.target() != facts.target
            || request.target() != channel.target()
            || auth_claim.runtime_peer() != channel.runtime_peer()
            || auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ReferenceContractError::TargetMismatch);
        }
        Ok(Self {
            request_id: request.request_id(),
            request_digest: request.request_digest(),
            client_nonce: request.authentication().claim().nonce().into(),
            facts,
            auth_claim,
            requested_max_response_bytes: request.max_response_bytes(),
        })
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
        let mut encoded = begin_signing_transcript(
            BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
            BOOTSTRAP_RESPONSE_SIGNING_FIELD_COUNT,
        );
        append_bootstrap_response_fields(
            &mut encoded,
            self.request_id,
            self.request_digest,
            &self.client_nonce,
            self.facts,
            self.auth_claim,
            None,
        );
        if encoded.len() > MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        Ok(ControlReadSigningTranscriptV1(encoded.into_boxed_slice()))
    }

    pub(crate) fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeBootstrapResponseV1, ReferenceContractError> {
        let authentication = RuntimeResponseAuthenticationV1::try_new(self.auth_claim, signature)?;
        RuntimeBootstrapResponseV1::try_new(
            self.request_id,
            self.request_digest,
            &self.client_nonce,
            self.facts,
            authentication,
            Some(self.requested_max_response_bytes),
        )
    }
}

/// Signed bootstrap response available only after startup service readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeBootstrapResponseV1 {
    request_id: BootstrapRequestId,
    request_digest: Digest32,
    client_nonce: Box<[u8]>,
    facts: RuntimeBootstrapFactsV1,
    authentication: RuntimeResponseAuthenticationV1,
    canonical_wire: Box<[u8]>,
    response_digest: Digest32,
}

impl RuntimeBootstrapResponseV1 {
    fn try_new(
        request_id: BootstrapRequestId,
        request_digest: Digest32,
        client_nonce: &[u8],
        facts: RuntimeBootstrapFactsV1,
        authentication: RuntimeResponseAuthenticationV1,
        requested_max_response_bytes: Option<u32>,
    ) -> Result<Self, ReferenceContractError> {
        validate_nonce(client_nonce, MAX_CONTROL_READ_NONCE_BYTES)?;
        if digest_is_zero(&request_digest) {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        let canonical_wire = build_bootstrap_response_wire(
            request_id,
            request_digest,
            client_nonce,
            facts,
            &authentication,
        );
        if canonical_wire.len() > MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        if requested_max_response_bytes.is_some_and(|bound| canonical_wire.len() > bound as usize) {
            return Err(ReferenceContractError::InvalidBound);
        }
        let response_digest = digest_wire(BOOTSTRAP_RESPONSE_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id,
            request_digest,
            client_nonce: client_nonce.into(),
            facts,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            response_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_bootstrap_response(frame)
    }

    #[must_use]
    pub(crate) const fn request_id(&self) -> BootstrapRequestId {
        self.request_id
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub(crate) fn client_nonce(&self) -> &[u8] {
        &self.client_nonce
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> RuntimeBootstrapFactsV1 {
        self.facts
    }

    #[must_use]
    pub(crate) const fn authentication(&self) -> &RuntimeResponseAuthenticationV1 {
        &self.authentication
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn response_digest(&self) -> Digest32 {
        self.response_digest
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
        let mut encoded = begin_signing_transcript(
            BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
            BOOTSTRAP_RESPONSE_SIGNING_FIELD_COUNT,
        );
        append_bootstrap_response_fields(
            &mut encoded,
            self.request_id,
            self.request_digest,
            &self.client_nonce,
            self.facts,
            self.authentication.claim(),
            None,
        );
        Ok(ControlReadSigningTranscriptV1(encoded.into_boxed_slice()))
    }

    pub(crate) fn validate_against_request(
        &self,
        request: &RuntimeBootstrapRequestV1,
        channel: RuntimeChannelBindingV1,
        expected_manifest: &RuntimeArtifactCompatibilityManifestV1,
        expected_admission_policy_fingerprint: Digest32,
    ) -> Result<(), ReferenceWireError> {
        self.validate_echo_fields(request, channel)?;
        self.validate_expected_compatibility(
            expected_manifest,
            expected_admission_policy_fingerprint,
        )?;
        self.validate_peer_channel_and_bound(request, channel)
    }

    fn validate_echo_fields(
        &self,
        request: &RuntimeBootstrapRequestV1,
        channel: RuntimeChannelBindingV1,
    ) -> Result<(), ReferenceWireError> {
        if self.request_id != request.request_id() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                1,
            ));
        }
        if self.request_digest != request.request_digest() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                2,
            ));
        }
        if self.client_nonce.as_ref() != request.authentication().claim().nonce() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                3,
            ));
        }
        if self.facts.target != request.target() || channel.target() != request.target() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                4,
            ));
        }
        Ok(())
    }

    fn validate_peer_channel_and_bound(
        &self,
        request: &RuntimeBootstrapRequestV1,
        channel: RuntimeChannelBindingV1,
    ) -> Result<(), ReferenceWireError> {
        if self.authentication.claim().runtime_peer() != channel.runtime_peer() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                18,
            ));
        }
        if self.authentication.claim().channel_binding_digest() != channel.binding_digest() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                19,
            ));
        }
        if self.canonical_wire.len() > request.max_response_bytes() as usize {
            return Err(ReferenceWireError::new(
                ReferenceWireErrorCode::ResponseBoundExceeded,
            ));
        }
        Ok(())
    }

    /// Internal S7-E consumer check against Controller-pinned install truth.
    fn validate_expected_compatibility(
        &self,
        expected_manifest: &RuntimeArtifactCompatibilityManifestV1,
        expected_admission_policy_fingerprint: Digest32,
    ) -> Result<(), ReferenceWireError> {
        let expected_row = expected_manifest.row();
        let expected_identity = expected_row.build_identity();
        if self.facts.target != expected_row.target() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                4,
            ));
        }
        if self.facts.compiled_build_instance_id != expected_identity.build_instance_id() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CompatibilityMismatch,
                10,
            ));
        }
        if self.facts.compiled_compatibility_digest
            != expected_identity.compiled_reference_compatibility_digest()
        {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CompatibilityMismatch,
                11,
            ));
        }
        if self.facts.store_pinned_build_identity != expected_identity {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CompatibilityMismatch,
                12,
            ));
        }
        if self.facts.manifest_digest != expected_manifest.manifest_digest() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CompatibilityMismatch,
                13,
            ));
        }
        let expected_profile =
            reference_profile_fingerprint(expected_row.fixture()).map_err(|_| {
                ReferenceWireError::at(ReferenceWireErrorCode::CompatibilityMismatch, 14)
            })?;
        if self.facts.profile_fingerprint != expected_profile {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CompatibilityMismatch,
                14,
            ));
        }
        if digest_is_zero(&expected_admission_policy_fingerprint)
            || self.facts.admission_policy_fingerprint != expected_admission_policy_fingerprint
        {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CompatibilityMismatch,
                15,
            ));
        }
        Ok(())
    }
}

fn build_bootstrap_response_wire(
    request_id: BootstrapRequestId,
    request_digest: Digest32,
    client_nonce: &[u8],
    facts: RuntimeBootstrapFactsV1,
    authentication: &RuntimeResponseAuthenticationV1,
) -> Vec<u8> {
    let mut encoded = begin_tlv_frame(
        RUNTIME_BOOTSTRAP_RESPONSE_MAGIC,
        RUNTIME_BOOTSTRAP_PROTOCOL_VERSION,
        BOOTSTRAP_RESPONSE_FIELD_COUNT,
    );
    append_bootstrap_response_fields(
        &mut encoded,
        request_id,
        request_digest,
        client_nonce,
        facts,
        authentication.claim(),
        Some(authentication.signature()),
    );
    encoded
}

fn append_bootstrap_response_fields(
    encoded: &mut Vec<u8>,
    request_id: BootstrapRequestId,
    request_digest: Digest32,
    client_nonce: &[u8],
    facts: RuntimeBootstrapFactsV1,
    auth_claim: RuntimeResponseAuthClaimV1,
    signature: Option<&[u8]>,
) {
    append_tlv(encoded, 1, request_id.as_bytes());
    append_tlv(encoded, 2, request_digest.as_bytes());
    append_tlv(encoded, 3, client_nonce);
    append_tlv(encoded, 4, facts.target.as_bytes());
    append_tlv(encoded, 5, facts.store_instance_id.as_bytes());
    append_tlv(encoded, 6, &facts.snapshot_sequence.value().to_be_bytes());
    append_tlv(encoded, 7, &facts.runtime_host_epoch.value().to_be_bytes());
    append_tlv(encoded, 8, facts.clock_domain.as_bytes());
    append_tlv(encoded, 9, &facts.clock_generation.value().to_be_bytes());
    append_tlv(encoded, 10, facts.compiled_build_instance_id.as_bytes());
    append_tlv(encoded, 11, facts.compiled_compatibility_digest.as_bytes());
    let mut identity = Vec::with_capacity(BUILD_IDENTITY_BYTES);
    append_build_identity(&mut identity, facts.store_pinned_build_identity);
    append_tlv(encoded, 12, &identity);
    append_tlv(encoded, 13, facts.manifest_digest.as_bytes());
    append_tlv(encoded, 14, facts.profile_fingerprint.as_bytes());
    append_tlv(encoded, 15, facts.admission_policy_fingerprint.as_bytes());
    append_tlv(encoded, 16, &(facts.state as u16).to_be_bytes());
    append_tlv(
        encoded,
        17,
        &facts.reason.map_or(0, |reason| reason as u16).to_be_bytes(),
    );
    append_tlv(encoded, 18, auth_claim.runtime_peer().as_bytes());
    append_tlv(encoded, 19, auth_claim.channel_binding_digest().as_bytes());
    append_tlv(encoded, 20, auth_claim.key().as_bytes());
    append_tlv(encoded, 21, &auth_claim.algorithm().value().to_be_bytes());
    append_tlv(encoded, 22, &auth_claim.algorithm_version().to_be_bytes());
    if let Some(signature) = signature {
        append_tlv(encoded, 23, signature);
    }
}

fn decode_bootstrap_response(
    frame: &[u8],
) -> Result<RuntimeBootstrapResponseV1, ReferenceWireError> {
    let fields = parse_tlv_frame(
        frame,
        RUNTIME_BOOTSTRAP_RESPONSE_MAGIC,
        RUNTIME_BOOTSTRAP_PROTOCOL_VERSION,
        BOOTSTRAP_RESPONSE_FIELD_COUNT,
        MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES,
        valid_bootstrap_response_field_length,
    )?;
    let request_digest = Digest32::from_bytes(fields.array(2)?);
    if digest_is_zero(&request_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            2,
        ));
    }

    let identity_result = {
        let mut identity_cursor = FixedCursor::new(fields.get(12));
        let identity = decode_build_identity(&mut identity_cursor);
        if !identity_cursor.is_empty() {
            Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TrailingBytes,
                12,
            ))
        } else {
            identity
        }
    };
    let store_instance_id = RuntimeStoreInstanceId::try_from_bytes(fields.array(5)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 5))?;
    let snapshot_sequence = RuntimeSnapshotSequence::try_new(fields.u64(6)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 6))?;
    let runtime_host_epoch = RuntimeHostEpoch::try_new(fields.u64(7)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 7))?;
    let clock_generation = ClockGeneration::try_new(fields.u64(9)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 9))?;
    let compiled_build_instance_id = RuntimeBuildInstanceId::try_from_bytes(fields.array(10)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 10))?;
    if fields.get(10) != &fields.get(12)[..BUILD_ID_BYTES] {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CompatibilityMismatch,
            10,
        ));
    }
    let compiled_compatibility_digest = Digest32::from_bytes(fields.array(11)?);
    if digest_is_zero(&compiled_compatibility_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CompatibilityMismatch,
            11,
        ));
    }
    if fields.get(11) != &fields.get(12)[BUILD_ID_BYTES * 3..BUILD_ID_BYTES * 4] {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CompatibilityMismatch,
            11,
        ));
    }
    let identity = identity_result
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 12))?;
    let manifest_digest = Digest32::from_bytes(fields.array(13)?);
    if digest_is_zero(&manifest_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CompatibilityMismatch,
            13,
        ));
    }
    let profile_fingerprint = Digest32::from_bytes(fields.array(14)?);
    if digest_is_zero(&profile_fingerprint) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CompatibilityMismatch,
            14,
        ));
    }
    let admission_policy_fingerprint = Digest32::from_bytes(fields.array(15)?);
    if digest_is_zero(&admission_policy_fingerprint) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::CompatibilityMismatch,
            15,
        ));
    }
    let state = decode_bootstrap_state(fields.u16(16)?)?;
    let reason = decode_operational_reason(fields.u16(17)?, 17)?;
    validate_bootstrap_state_reason(state, reason)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::UnknownReason, 17))?;

    let serving = RuntimeBootstrapServingIdentityV1::new(
        RuntimeHostId::from_bytes(fields.array(4)?),
        store_instance_id,
        snapshot_sequence,
        runtime_host_epoch,
        ClockDomainRef::from_bytes(fields.array(8)?),
        clock_generation,
    );
    let compatibility = RuntimeBootstrapCompatibilityV1::try_from_parts(
        compiled_build_instance_id,
        compiled_compatibility_digest,
        identity,
        manifest_digest,
        profile_fingerprint,
        admission_policy_fingerprint,
    )
    .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::CompatibilityMismatch))?;
    let facts = RuntimeBootstrapFactsV1::try_new(serving, compatibility, state, reason).map_err(
        |error| match error {
            ReferenceContractError::InvalidReason => {
                ReferenceWireError::at(ReferenceWireErrorCode::UnknownReason, 17)
            }
            _ => ReferenceWireError::new(ReferenceWireErrorCode::CompatibilityMismatch),
        },
    )?;
    let channel_binding_digest = Digest32::from_bytes(fields.array(19)?);
    if digest_is_zero(&channel_binding_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            19,
        ));
    }
    let auth_algorithm = ApplyAuthAlgorithm::try_new(fields.u16(21)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 21))?;
    let auth_algorithm_version = fields.u16(22)?;
    if auth_algorithm_version == 0 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            22,
        ));
    }
    let auth_claim = RuntimeResponseAuthClaimV1::try_new(
        PrincipalRef::from_bytes(fields.array(18)?),
        channel_binding_digest,
        ApplyAuthKeyRef::from_bytes(fields.array(20)?),
        auth_algorithm,
        auth_algorithm_version,
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 22))?;
    let authentication = RuntimeResponseAuthenticationV1::try_new(auth_claim, fields.get(23))
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidSignatureField, 23))?;
    let decoded = RuntimeBootstrapResponseV1::try_new(
        BootstrapRequestId::from_bytes(fields.array(1)?),
        request_digest,
        fields.get(3),
        facts,
        authentication,
        None,
    )
    .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn valid_bootstrap_response_field_length(tag: u16, length: usize) -> bool {
    match tag {
        1 | 4 | 8 | 18 | 20 => length == 16,
        2 | 5 | 10 | 11 | 13..=15 | 19 => length == 32,
        3 => (1..=MAX_CONTROL_READ_NONCE_BYTES).contains(&length),
        6 | 7 | 9 => length == 8,
        12 => length == BUILD_IDENTITY_BYTES,
        16 | 17 | 21 | 22 => length == 2,
        23 => (1..=MAX_CONTROL_READ_SIGNATURE_BYTES).contains(&length),
        _ => false,
    }
}

fn decode_bootstrap_state(value: u16) -> Result<RuntimeBootstrapStateV1, ReferenceWireError> {
    match value {
        1 => Ok(RuntimeBootstrapStateV1::ReadyForApply),
        2 => Ok(RuntimeBootstrapStateV1::NotReadyRecovering),
        3 => Ok(RuntimeBootstrapStateV1::ValidatedOperationalQuarantine),
        4 => Ok(RuntimeBootstrapStateV1::RecoveryFailedNotReady),
        5 => Ok(RuntimeBootstrapStateV1::NotReadyBusy),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            16,
        )),
    }
}

fn decode_operational_reason(
    value: u16,
    detail: u16,
) -> Result<Option<OperationalReasonV1>, ReferenceWireError> {
    let reason = match value {
        0 => return Ok(None),
        1 => OperationalReasonV1::Recovering,
        2 => OperationalReasonV1::ActiveCompatibilityMismatch,
        3 => OperationalReasonV1::RecoveryFailed,
        4 => OperationalReasonV1::OwnershipUncertain,
        5 => OperationalReasonV1::HistoryUnavailable,
        6 => OperationalReasonV1::ResourceCensusUncertain,
        7 => OperationalReasonV1::RuntimeBusy,
        8 => OperationalReasonV1::OwnershipTransferRequired,
        _ => {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::UnknownReason,
                detail,
            ));
        }
    };
    Ok(Some(reason))
}

/// Exact terminal result selected by the Runtime apply state machine.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub(crate) enum RuntimeApplyTerminalOutcomeV1 {
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
pub(crate) enum RuntimeApplyTerminalLifecycleEffectV1 {
    ProvenNotStarted = 1,
    MayHaveStarted = 2,
}

/// Desired-head state atomically associated with one terminal operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum RuntimeApplyTerminalHeadV1 {
    PreservedNone,
    PreservedExisting(TargetSliceDigest),
    CommittedIncoming(TargetSliceDigest),
}

impl RuntimeApplyTerminalHeadV1 {
    const fn disposition(self) -> u16 {
        match self {
            Self::PreservedNone => 1,
            Self::PreservedExisting(_) => 2,
            Self::CommittedIncoming(_) => 3,
        }
    }

    const fn desired_head_digest(self) -> Option<TargetSliceDigest> {
        match self {
            Self::PreservedNone => None,
            Self::PreservedExisting(digest) | Self::CommittedIncoming(digest) => Some(digest),
        }
    }

    const fn commits_incoming(self) -> bool {
        matches!(self, Self::CommittedIncoming(_))
    }
}

/// Immutable terminal facts owned by one canonical apply Receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeApplyTerminalFactsV1 {
    outcome: RuntimeApplyTerminalOutcomeV1,
    lifecycle_effect: RuntimeApplyTerminalLifecycleEffectV1,
    head: RuntimeApplyTerminalHeadV1,
    resource_census_digest: Digest32,
    raw_outcome_digest: Digest32,
    completion_runtime_host_epoch: RuntimeHostEpoch,
    completion_snapshot_sequence: RuntimeSnapshotSequence,
    selection_clock_generation: ClockGeneration,
    selection_observed_at_nanos: u64,
    terminal_result_ref: TerminalResultRef,
}

impl RuntimeApplyTerminalFactsV1 {
    #[allow(clippy::too_many_arguments)] // GOV-WAIVER-0010
    pub(crate) fn try_new(
        request: &RuntimeApplyRequestV5,
        outcome: RuntimeApplyTerminalOutcomeV1,
        lifecycle_effect: RuntimeApplyTerminalLifecycleEffectV1,
        head: RuntimeApplyTerminalHeadV1,
        resource_census_digest: Digest32,
        raw_outcome_digest: Digest32,
        completion_runtime_host_epoch: RuntimeHostEpoch,
        completion_snapshot_sequence: RuntimeSnapshotSequence,
        selection_clock_generation: ClockGeneration,
        selection_observed_at_nanos: u64,
    ) -> Result<Self, ReferenceContractError> {
        let binding = apply_terminal_request_binding(request);
        validate_apply_terminal_shape(
            outcome,
            lifecycle_effect,
            head,
            Some(binding.mode),
            Some(binding.incoming_slice_digest),
        )?;
        if digest_is_zero(&resource_census_digest)
            || digest_is_zero(&raw_outcome_digest)
            || selection_observed_at_nanos == 0
            || selection_clock_generation.value()
                < request
                    .envelope()
                    .temporal()
                    .target_clock_generation()
                    .value()
        {
            return Err(ReferenceContractError::InvalidShape);
        }
        let terminal_result_ref = derive_apply_terminal_result_ref(binding)?;
        Ok(Self {
            outcome,
            lifecycle_effect,
            head,
            resource_census_digest,
            raw_outcome_digest,
            completion_runtime_host_epoch,
            completion_snapshot_sequence,
            selection_clock_generation,
            selection_observed_at_nanos,
            terminal_result_ref,
        })
    }

    #[must_use]
    pub(crate) const fn outcome(self) -> RuntimeApplyTerminalOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub(crate) const fn lifecycle_effect(self) -> RuntimeApplyTerminalLifecycleEffectV1 {
        self.lifecycle_effect
    }

    #[must_use]
    pub(crate) const fn head(self) -> RuntimeApplyTerminalHeadV1 {
        self.head
    }

    #[must_use]
    pub(crate) const fn resource_census_digest(self) -> Digest32 {
        self.resource_census_digest
    }

    #[must_use]
    pub(crate) const fn raw_outcome_digest(self) -> Digest32 {
        self.raw_outcome_digest
    }

    #[must_use]
    pub(crate) const fn completion_runtime_host_epoch(self) -> RuntimeHostEpoch {
        self.completion_runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn completion_snapshot_sequence(self) -> RuntimeSnapshotSequence {
        self.completion_snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn selection_clock_generation(self) -> ClockGeneration {
        self.selection_clock_generation
    }

    #[must_use]
    pub(crate) const fn selection_observed_at_nanos(self) -> u64 {
        self.selection_observed_at_nanos
    }

    #[must_use]
    pub(crate) const fn terminal_result_ref(self) -> TerminalResultRef {
        self.terminal_result_ref
    }
}

#[derive(Clone, Copy)]
struct ApplyTerminalRequestBinding<'a> {
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    source_scope: SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    request_nonce: &'a [u8],
    mode: ReferenceAssemblyModeV1,
    incoming_slice_digest: TargetSliceDigest,
}

fn apply_terminal_request_binding(
    request: &RuntimeApplyRequestV5,
) -> ApplyTerminalRequestBinding<'_> {
    let commitment = request.envelope().control_commitment();
    ApplyTerminalRequestBinding {
        target: commitment.slice().header().target(),
        store: request.envelope().expected_runtime_store_instance_id(),
        source_scope: commitment.slice().header().provenance().source_scope(),
        operation_id: commitment.control().operation_id(),
        request_digest: request.envelope().request_digest(),
        request_nonce: request.envelope().authentication().claim().nonce(),
        mode: request.slice().assignments().execution().profile().mode(),
        incoming_slice_digest: commitment.slice().target_slice_digest(),
    }
}

fn derive_apply_terminal_result_ref(
    binding: ApplyTerminalRequestBinding<'_>,
) -> Result<TerminalResultRef, ReferenceContractError> {
    TerminalResultRef::derive_for_apply(
        binding.target,
        binding.store,
        binding.source_scope,
        binding.operation_id,
        binding.request_digest,
    )
}

const fn apply_terminal_outcome_accepts_mode(
    outcome: RuntimeApplyTerminalOutcomeV1,
    mode: ReferenceAssemblyModeV1,
) -> bool {
    match mode {
        ReferenceAssemblyModeV1::OneSourceLoop => matches!(
            outcome,
            RuntimeApplyTerminalOutcomeV1::OneSourceLoopActive
                | RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects
                | RuntimeApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero
                | RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero
                | RuntimeApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects
                | RuntimeApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero
                | RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero
        ),
        ReferenceAssemblyModeV1::EmptyDeactivate => matches!(
            outcome,
            RuntimeApplyTerminalOutcomeV1::EmptyDeactivateExactZero
                | RuntimeApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects
                | RuntimeApplyTerminalOutcomeV1::StopFailedButExactZero
                | RuntimeApplyTerminalOutcomeV1::TimedOutButExactZero
                | RuntimeApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects
                | RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero
                | RuntimeApplyTerminalOutcomeV1::InterruptedButNowExactZero
        ),
    }
}

const fn apply_terminal_outcome_commits_incoming(
    outcome: RuntimeApplyTerminalOutcomeV1,
    mode: ReferenceAssemblyModeV1,
) -> bool {
    match mode {
        ReferenceAssemblyModeV1::OneSourceLoop => {
            matches!(outcome, RuntimeApplyTerminalOutcomeV1::OneSourceLoopActive)
        }
        ReferenceAssemblyModeV1::EmptyDeactivate => matches!(
            outcome,
            RuntimeApplyTerminalOutcomeV1::EmptyDeactivateExactZero
                | RuntimeApplyTerminalOutcomeV1::StopFailedButExactZero
                | RuntimeApplyTerminalOutcomeV1::TimedOutButExactZero
                | RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero
                | RuntimeApplyTerminalOutcomeV1::InterruptedButNowExactZero
        ),
    }
}

const fn apply_terminal_lifecycle_is_valid(
    outcome: RuntimeApplyTerminalOutcomeV1,
    lifecycle: RuntimeApplyTerminalLifecycleEffectV1,
) -> bool {
    match outcome {
        RuntimeApplyTerminalOutcomeV1::OneSourceLoopActive
        | RuntimeApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero
        | RuntimeApplyTerminalOutcomeV1::StopFailedButExactZero => {
            matches!(
                lifecycle,
                RuntimeApplyTerminalLifecycleEffectV1::MayHaveStarted
            )
        }
        RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects
        | RuntimeApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects
        | RuntimeApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects => matches!(
            lifecycle,
            RuntimeApplyTerminalLifecycleEffectV1::ProvenNotStarted
        ),
        RuntimeApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        | RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero
        | RuntimeApplyTerminalOutcomeV1::TimedOutButExactZero
        | RuntimeApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero
        | RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero
        | RuntimeApplyTerminalOutcomeV1::InterruptedButNowExactZero => true,
    }
}

const fn apply_terminal_head_is_potentially_valid(
    outcome: RuntimeApplyTerminalOutcomeV1,
    commits_incoming: bool,
) -> bool {
    match outcome {
        RuntimeApplyTerminalOutcomeV1::OneSourceLoopActive
        | RuntimeApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        | RuntimeApplyTerminalOutcomeV1::StopFailedButExactZero
        | RuntimeApplyTerminalOutcomeV1::TimedOutButExactZero
        | RuntimeApplyTerminalOutcomeV1::InterruptedButNowExactZero => commits_incoming,
        RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects
        | RuntimeApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects
        | RuntimeApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero
        | RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero
        | RuntimeApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects
        | RuntimeApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero => !commits_incoming,
        RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero => true,
    }
}

fn validate_apply_terminal_shape(
    outcome: RuntimeApplyTerminalOutcomeV1,
    lifecycle: RuntimeApplyTerminalLifecycleEffectV1,
    head: RuntimeApplyTerminalHeadV1,
    mode: Option<ReferenceAssemblyModeV1>,
    incoming_slice_digest: Option<TargetSliceDigest>,
) -> Result<(), ReferenceContractError> {
    if !apply_terminal_lifecycle_is_valid(outcome, lifecycle)
        || !apply_terminal_head_is_potentially_valid(outcome, head.commits_incoming())
        || head
            .desired_head_digest()
            .is_some_and(|digest| digest_is_zero(digest.value()))
    {
        return Err(ReferenceContractError::InvalidShape);
    }
    if let Some(mode) = mode {
        if !apply_terminal_outcome_accepts_mode(outcome, mode)
            || apply_terminal_outcome_commits_incoming(outcome, mode) != head.commits_incoming()
        {
            return Err(ReferenceContractError::InvalidShape);
        }
        if let RuntimeApplyTerminalHeadV1::CommittedIncoming(committed) = head
            && incoming_slice_digest != Some(committed)
        {
            return Err(ReferenceContractError::InvalidShape);
        }
    }
    Ok(())
}

/// Exact bytes authenticated by the Runtime terminal-Receipt signer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ApplyTerminalReceiptSigningTranscriptV1(Box<[u8]>);

impl ApplyTerminalReceiptSigningTranscriptV1 {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent terminal Receipt bound to one exact PXAR request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeApplyTerminalReceiptDraftV1 {
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    source_scope: SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    facts: RuntimeApplyTerminalFactsV1,
    auth_claim: RuntimeResponseAuthClaimV1,
}

impl RuntimeApplyTerminalReceiptDraftV1 {
    pub(crate) fn try_new(
        request: &RuntimeApplyRequestV5,
        facts: RuntimeApplyTerminalFactsV1,
        channel: RuntimeChannelBindingV1,
        auth_claim: RuntimeResponseAuthClaimV1,
    ) -> Result<Self, ReferenceContractError> {
        let binding = apply_terminal_request_binding(request);
        validate_apply_terminal_shape(
            facts.outcome,
            facts.lifecycle_effect,
            facts.head,
            Some(binding.mode),
            Some(binding.incoming_slice_digest),
        )?;
        if facts.terminal_result_ref != derive_apply_terminal_result_ref(binding)?
            || binding.target != channel.target()
            || auth_claim.runtime_peer() != channel.runtime_peer()
            || auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ReferenceContractError::TargetMismatch);
        }
        Ok(Self {
            target: binding.target,
            store: binding.store,
            source_scope: binding.source_scope,
            operation_id: binding.operation_id,
            request_digest: binding.request_digest,
            request_nonce: binding.request_nonce.into(),
            facts,
            auth_claim,
        })
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ApplyTerminalReceiptSigningTranscriptV1, ReferenceContractError> {
        build_apply_terminal_receipt_signing_transcript(
            self.target,
            self.store,
            self.source_scope,
            self.operation_id,
            self.request_digest,
            &self.request_nonce,
            self.facts,
            self.auth_claim,
        )
    }

    pub(crate) fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeApplyTerminalReceiptV1, ReferenceContractError> {
        let authentication = RuntimeResponseAuthenticationV1::try_new(self.auth_claim, signature)?;
        RuntimeApplyTerminalReceiptV1::try_new(
            self.target,
            self.store,
            self.source_scope,
            self.operation_id,
            self.request_digest,
            &self.request_nonce,
            self.facts,
            authentication,
        )
    }
}

/// Signed canonical terminal Receipt for one exact Runtime apply operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeApplyTerminalReceiptV1 {
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    source_scope: SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    facts: RuntimeApplyTerminalFactsV1,
    authentication: RuntimeResponseAuthenticationV1,
    canonical_wire: Box<[u8]>,
    receipt_digest: Digest32,
}

impl RuntimeApplyTerminalReceiptV1 {
    #[allow(clippy::too_many_arguments)] // GOV-WAIVER-0010
    fn try_new(
        target: RuntimeHostId,
        store: RuntimeStoreInstanceId,
        source_scope: SourceScopeRef,
        operation_id: ApplyOperationId,
        request_digest: Digest32,
        request_nonce: &[u8],
        facts: RuntimeApplyTerminalFactsV1,
        authentication: RuntimeResponseAuthenticationV1,
    ) -> Result<Self, ReferenceContractError> {
        validate_nonce(request_nonce, MAX_APPLY_AUTH_NONCE_V2_BYTES)?;
        validate_apply_terminal_shape(
            facts.outcome,
            facts.lifecycle_effect,
            facts.head,
            None,
            None,
        )?;
        if digest_is_zero(&request_digest)
            || digest_is_zero(&facts.resource_census_digest)
            || digest_is_zero(&facts.raw_outcome_digest)
            || facts.selection_observed_at_nanos == 0
        {
            return Err(ReferenceContractError::InvalidShape);
        }
        let expected_result_ref = TerminalResultRef::derive_for_apply(
            target,
            store,
            source_scope,
            operation_id,
            request_digest,
        )?;
        if facts.terminal_result_ref != expected_result_ref
            || all_zero(facts.terminal_result_ref.as_bytes())
        {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        let canonical_wire = build_apply_terminal_receipt_wire(
            target,
            store,
            source_scope,
            operation_id,
            request_digest,
            request_nonce,
            facts,
            &authentication,
        );
        if canonical_wire.len() > MAX_RUNTIME_APPLY_TERMINAL_RECEIPT_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        let receipt_digest = digest_wire(APPLY_TERMINAL_RECEIPT_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            target,
            store,
            source_scope,
            operation_id,
            request_digest,
            request_nonce: request_nonce.into(),
            facts,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            receipt_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_apply_terminal_receipt(frame)
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn store(&self) -> RuntimeStoreInstanceId {
        self.store
    }

    #[must_use]
    pub(crate) const fn source_scope(&self) -> SourceScopeRef {
        self.source_scope
    }

    #[must_use]
    pub(crate) const fn operation_id(&self) -> ApplyOperationId {
        self.operation_id
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub(crate) fn request_nonce(&self) -> &[u8] {
        &self.request_nonce
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> RuntimeApplyTerminalFactsV1 {
        self.facts
    }

    #[must_use]
    pub(crate) const fn authentication(&self) -> &RuntimeResponseAuthenticationV1 {
        &self.authentication
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ApplyTerminalReceiptSigningTranscriptV1, ReferenceContractError> {
        build_apply_terminal_receipt_signing_transcript(
            self.target,
            self.store,
            self.source_scope,
            self.operation_id,
            self.request_digest,
            &self.request_nonce,
            self.facts,
            self.authentication.claim(),
        )
    }

    pub(crate) fn validate_against_request(
        &self,
        request: &RuntimeApplyRequestV5,
        channel: RuntimeChannelBindingV1,
    ) -> Result<(), ReferenceWireError> {
        let binding = apply_terminal_request_binding(request);
        if self.target != binding.target || channel.target() != binding.target {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                1,
            ));
        }
        if self.store != binding.store {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::RuntimeStoreMismatch,
                2,
            ));
        }
        if self.source_scope != binding.source_scope {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                3,
            ));
        }
        if self.operation_id != binding.operation_id {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                4,
            ));
        }
        if self.request_digest != binding.request_digest {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                5,
            ));
        }
        if self.request_nonce.as_ref() != binding.request_nonce {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                6,
            ));
        }
        validate_apply_terminal_shape(
            self.facts.outcome,
            self.facts.lifecycle_effect,
            self.facts.head,
            Some(binding.mode),
            Some(binding.incoming_slice_digest),
        )
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::CrossReferenceMismatch, 7))?;
        if self.facts.selection_clock_generation.value()
            < request
                .envelope()
                .temporal()
                .target_clock_generation()
                .value()
        {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                15,
            ));
        }
        if self.facts.terminal_result_ref
            != derive_apply_terminal_result_ref(binding)
                .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::DigestMismatch, 17))?
        {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::DigestMismatch,
                17,
            ));
        }
        if self.authentication.claim().runtime_peer() != channel.runtime_peer() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                18,
            ));
        }
        if self.authentication.claim().channel_binding_digest() != channel.binding_digest() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                19,
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)] // GOV-WAIVER-0010
fn build_apply_terminal_receipt_signing_transcript(
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    source_scope: SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    request_nonce: &[u8],
    facts: RuntimeApplyTerminalFactsV1,
    auth_claim: RuntimeResponseAuthClaimV1,
) -> Result<ApplyTerminalReceiptSigningTranscriptV1, ReferenceContractError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(SIGNING_TRANSCRIPT_MAGIC);
    encoded.extend_from_slice(&APPLY_TERMINAL_RECEIPT_SIGNING_TRANSCRIPT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(APPLY_TERMINAL_RECEIPT_SIGNING_DOMAIN.len() as u16).to_be_bytes());
    encoded.extend_from_slice(APPLY_TERMINAL_RECEIPT_SIGNING_DOMAIN);
    encoded.extend_from_slice(&APPLY_TERMINAL_RECEIPT_SIGNING_FIELD_COUNT.to_be_bytes());
    append_apply_terminal_receipt_fields(
        &mut encoded,
        target,
        store,
        source_scope,
        operation_id,
        request_digest,
        request_nonce,
        facts,
        auth_claim,
        None,
    );
    if encoded.len() > MAX_RUNTIME_APPLY_TERMINAL_RECEIPT_BYTES {
        return Err(ReferenceContractError::RequestFrameTooLarge);
    }
    Ok(ApplyTerminalReceiptSigningTranscriptV1(
        encoded.into_boxed_slice(),
    ))
}

#[allow(clippy::too_many_arguments)] // GOV-WAIVER-0010
fn build_apply_terminal_receipt_wire(
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    source_scope: SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    request_nonce: &[u8],
    facts: RuntimeApplyTerminalFactsV1,
    authentication: &RuntimeResponseAuthenticationV1,
) -> Vec<u8> {
    let mut encoded = begin_tlv_frame(
        RUNTIME_APPLY_TERMINAL_RECEIPT_MAGIC,
        RUNTIME_APPLY_TERMINAL_RECEIPT_VERSION,
        APPLY_TERMINAL_RECEIPT_FIELD_COUNT,
    );
    append_apply_terminal_receipt_fields(
        &mut encoded,
        target,
        store,
        source_scope,
        operation_id,
        request_digest,
        request_nonce,
        facts,
        authentication.claim(),
        Some(authentication.signature()),
    );
    encoded
}

#[allow(clippy::too_many_arguments)] // GOV-WAIVER-0010
fn append_apply_terminal_receipt_fields(
    encoded: &mut Vec<u8>,
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    source_scope: SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    request_nonce: &[u8],
    facts: RuntimeApplyTerminalFactsV1,
    auth_claim: RuntimeResponseAuthClaimV1,
    signature: Option<&[u8]>,
) {
    let desired_head_digest = facts
        .head
        .desired_head_digest()
        .map_or(Digest32::from_bytes([0; 32]), |digest| *digest.value());
    append_tlv(encoded, 1, target.as_bytes());
    append_tlv(encoded, 2, store.as_bytes());
    append_tlv(encoded, 3, source_scope.as_bytes());
    append_tlv(encoded, 4, operation_id.as_bytes());
    append_tlv(encoded, 5, request_digest.as_bytes());
    append_tlv(encoded, 6, request_nonce);
    append_tlv(encoded, 7, &(facts.outcome as u16).to_be_bytes());
    append_tlv(encoded, 8, &(facts.lifecycle_effect as u16).to_be_bytes());
    append_tlv(encoded, 9, &facts.head.disposition().to_be_bytes());
    append_tlv(encoded, 10, desired_head_digest.as_bytes());
    append_tlv(encoded, 11, facts.resource_census_digest.as_bytes());
    append_tlv(encoded, 12, facts.raw_outcome_digest.as_bytes());
    append_tlv(
        encoded,
        13,
        &facts.completion_runtime_host_epoch.value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        14,
        &facts.completion_snapshot_sequence.value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        15,
        &facts.selection_clock_generation.value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        16,
        &facts.selection_observed_at_nanos.to_be_bytes(),
    );
    append_tlv(encoded, 17, facts.terminal_result_ref.as_bytes());
    append_tlv(encoded, 18, auth_claim.runtime_peer().as_bytes());
    append_tlv(encoded, 19, auth_claim.channel_binding_digest().as_bytes());
    append_tlv(encoded, 20, auth_claim.key().as_bytes());
    append_tlv(encoded, 21, &auth_claim.algorithm().value().to_be_bytes());
    append_tlv(encoded, 22, &auth_claim.algorithm_version().to_be_bytes());
    if let Some(signature) = signature {
        append_tlv(encoded, 23, signature);
    }
}

fn decode_apply_terminal_receipt(
    frame: &[u8],
) -> Result<RuntimeApplyTerminalReceiptV1, ReferenceWireError> {
    let fields = parse_tlv_frame(
        frame,
        RUNTIME_APPLY_TERMINAL_RECEIPT_MAGIC,
        RUNTIME_APPLY_TERMINAL_RECEIPT_VERSION,
        APPLY_TERMINAL_RECEIPT_FIELD_COUNT,
        MAX_RUNTIME_APPLY_TERMINAL_RECEIPT_BYTES,
        valid_apply_terminal_receipt_field_length,
    )?;
    let store = RuntimeStoreInstanceId::try_from_bytes(fields.array(2)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 2))?;
    let request_digest = Digest32::from_bytes(fields.array(5)?);
    if digest_is_zero(&request_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            5,
        ));
    }
    let outcome = decode_apply_terminal_outcome(fields.u16(7)?)?;
    let lifecycle_effect = decode_apply_terminal_lifecycle(fields.u16(8)?)?;
    let head = decode_apply_terminal_head(fields.u16(9)?, fields.array(10)?)?;
    validate_apply_terminal_shape(outcome, lifecycle_effect, head, None, None)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 7))?;
    let resource_census_digest = Digest32::from_bytes(fields.array(11)?);
    if digest_is_zero(&resource_census_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            11,
        ));
    }
    let raw_outcome_digest = Digest32::from_bytes(fields.array(12)?);
    if digest_is_zero(&raw_outcome_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            12,
        ));
    }
    let completion_runtime_host_epoch = RuntimeHostEpoch::try_new(fields.u64(13)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 13))?;
    let completion_snapshot_sequence = RuntimeSnapshotSequence::try_new(fields.u64(14)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 14))?;
    let selection_clock_generation = ClockGeneration::try_new(fields.u64(15)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 15))?;
    let selection_observed_at_nanos = fields.u64(16)?;
    if selection_observed_at_nanos == 0 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            16,
        ));
    }
    let target = RuntimeHostId::from_bytes(fields.array(1)?);
    let source_scope = SourceScopeRef::from_bytes(fields.array(3)?);
    let operation_id = ApplyOperationId::from_bytes(fields.array(4)?);
    let terminal_result_ref = TerminalResultRef::derive_for_apply(
        target,
        store,
        source_scope,
        operation_id,
        request_digest,
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::DigestMismatch, 17))?;
    if terminal_result_ref.as_bytes() != fields.get(17) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::DigestMismatch,
            17,
        ));
    }
    let facts = RuntimeApplyTerminalFactsV1 {
        outcome,
        lifecycle_effect,
        head,
        resource_census_digest,
        raw_outcome_digest,
        completion_runtime_host_epoch,
        completion_snapshot_sequence,
        selection_clock_generation,
        selection_observed_at_nanos,
        terminal_result_ref,
    };
    let channel_binding_digest = Digest32::from_bytes(fields.array(19)?);
    if digest_is_zero(&channel_binding_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            19,
        ));
    }
    let algorithm = ApplyAuthAlgorithm::try_new(fields.u16(21)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 21))?;
    let algorithm_version = fields.u16(22)?;
    if algorithm_version == 0 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            22,
        ));
    }
    let auth_claim = RuntimeResponseAuthClaimV1::try_new(
        PrincipalRef::from_bytes(fields.array(18)?),
        channel_binding_digest,
        ApplyAuthKeyRef::from_bytes(fields.array(20)?),
        algorithm,
        algorithm_version,
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 22))?;
    let authentication = RuntimeResponseAuthenticationV1::try_new(auth_claim, fields.get(23))
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidSignatureField, 23))?;
    let decoded = RuntimeApplyTerminalReceiptV1::try_new(
        target,
        store,
        source_scope,
        operation_id,
        request_digest,
        fields.get(6),
        facts,
        authentication,
    )
    .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn valid_apply_terminal_receipt_field_length(tag: u16, length: usize) -> bool {
    match tag {
        1 | 3 | 4 | 17 | 18 | 20 => length == 16,
        2 | 5 | 10..=12 | 19 => length == 32,
        6 => (1..=MAX_APPLY_AUTH_NONCE_V2_BYTES).contains(&length),
        7..=9 | 21 | 22 => length == 2,
        13..=16 => length == 8,
        23 => (1..=MAX_CONTROL_READ_SIGNATURE_BYTES).contains(&length),
        _ => false,
    }
}

fn decode_apply_terminal_outcome(
    value: u16,
) -> Result<RuntimeApplyTerminalOutcomeV1, ReferenceWireError> {
    match value {
        1 => Ok(RuntimeApplyTerminalOutcomeV1::OneSourceLoopActive),
        2 => Ok(RuntimeApplyTerminalOutcomeV1::EmptyDeactivateExactZero),
        3 => Ok(RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects),
        4 => Ok(RuntimeApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects),
        5 => Ok(RuntimeApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero),
        6 => Ok(RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero),
        7 => Ok(RuntimeApplyTerminalOutcomeV1::StopFailedButExactZero),
        8 => Ok(RuntimeApplyTerminalOutcomeV1::TimedOutButExactZero),
        9 => Ok(RuntimeApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects),
        10 => Ok(RuntimeApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero),
        11 => Ok(RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero),
        12 => Ok(RuntimeApplyTerminalOutcomeV1::InterruptedButNowExactZero),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            7,
        )),
    }
}

fn decode_apply_terminal_lifecycle(
    value: u16,
) -> Result<RuntimeApplyTerminalLifecycleEffectV1, ReferenceWireError> {
    match value {
        1 => Ok(RuntimeApplyTerminalLifecycleEffectV1::ProvenNotStarted),
        2 => Ok(RuntimeApplyTerminalLifecycleEffectV1::MayHaveStarted),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            8,
        )),
    }
}

fn decode_apply_terminal_head(
    disposition: u16,
    digest_bytes: [u8; 32],
) -> Result<RuntimeApplyTerminalHeadV1, ReferenceWireError> {
    let digest = Digest32::from_bytes(digest_bytes);
    match disposition {
        1 if digest_is_zero(&digest) => Ok(RuntimeApplyTerminalHeadV1::PreservedNone),
        2 if !digest_is_zero(&digest) => Ok(RuntimeApplyTerminalHeadV1::PreservedExisting(
            TargetSliceDigest::new(digest),
        )),
        3 if !digest_is_zero(&digest) => Ok(RuntimeApplyTerminalHeadV1::CommittedIncoming(
            TargetSliceDigest::new(digest),
        )),
        1..=3 => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidPresence,
            9,
        )),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            9,
        )),
    }
}

/// Fixed selector shared by query draft, signing transcript, and strict decoder.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeQuerySelectorV1 {
    query_id: RuntimeQueryId,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    expected_store_instance_id: RuntimeStoreInstanceId,
    requested_operation_id: ApplyOperationId,
    expected_request_digest: Option<Digest32>,
}

impl RuntimeQuerySelectorV1 {
    pub(crate) fn try_new(
        query_id: RuntimeQueryId,
        target: RuntimeHostId,
        source_scope: SourceScopeRef,
        expected_store_instance_id: RuntimeStoreInstanceId,
        requested_operation_id: ApplyOperationId,
        expected_request_digest: Option<Digest32>,
    ) -> Result<Self, ReferenceContractError> {
        if expected_request_digest.is_some_and(|digest| digest_is_zero(&digest)) {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        Ok(Self {
            query_id,
            target,
            source_scope,
            expected_store_instance_id,
            requested_operation_id,
            expected_request_digest,
        })
    }

    #[must_use]
    pub(crate) const fn query_id(self) -> RuntimeQueryId {
        self.query_id
    }

    #[must_use]
    pub(crate) const fn target(self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn source_scope(self) -> SourceScopeRef {
        self.source_scope
    }

    #[must_use]
    pub(crate) const fn expected_store_instance_id(self) -> RuntimeStoreInstanceId {
        self.expected_store_instance_id
    }

    #[must_use]
    pub(crate) const fn requested_operation_id(self) -> ApplyOperationId {
        self.requested_operation_id
    }

    #[must_use]
    pub(crate) const fn expected_request_digest(self) -> Option<Digest32> {
        self.expected_request_digest
    }
}

/// Signature-independent authenticated operation/live query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeQueryRequestDraftV1 {
    selector: RuntimeQuerySelectorV1,
    auth_claim: ApplyRequestAuthClaim,
    max_response_bytes: u32,
}

impl RuntimeQueryRequestDraftV1 {
    pub(crate) fn try_new(
        selector: RuntimeQuerySelectorV1,
        auth_claim: ApplyRequestAuthClaim,
        max_response_bytes: u32,
    ) -> Result<Self, ReferenceContractError> {
        validate_control_read_auth_claim(&auth_claim)?;
        validate_response_bound(max_response_bytes, MAX_RUNTIME_QUERY_RESPONSE_BYTES)?;
        Ok(Self {
            selector,
            auth_claim,
            max_response_bytes,
        })
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
        let mut encoded = begin_signing_transcript(
            QUERY_REQUEST_SIGNING_DOMAIN,
            QUERY_REQUEST_SIGNING_FIELD_COUNT,
        );
        append_query_request_fields(
            &mut encoded,
            self.selector,
            &self.auth_claim,
            self.max_response_bytes,
            None,
        );
        if encoded.len() > MAX_RUNTIME_QUERY_REQUEST_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        Ok(ControlReadSigningTranscriptV1(encoded.into_boxed_slice()))
    }

    pub(crate) fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeQueryRequestV1, ReferenceContractError> {
        let authentication = ApplyRequestAuthentication::try_new(self.auth_claim, signature)
            .map_err(|_| ReferenceContractError::InvalidBound)?;
        RuntimeQueryRequestV1::try_new(self.selector, authentication, self.max_response_bytes)
    }
}

/// Signed query which never advances tenure, admission, nonce, or action state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeQueryRequestV1 {
    selector: RuntimeQuerySelectorV1,
    authentication: ApplyRequestAuthentication,
    max_response_bytes: u32,
    canonical_wire: Box<[u8]>,
    request_digest: Digest32,
}

impl RuntimeQueryRequestV1 {
    fn try_new(
        selector: RuntimeQuerySelectorV1,
        authentication: ApplyRequestAuthentication,
        max_response_bytes: u32,
    ) -> Result<Self, ReferenceContractError> {
        validate_control_read_auth_claim(authentication.claim())?;
        validate_signature(authentication.signature(), MAX_CONTROL_READ_SIGNATURE_BYTES)?;
        validate_response_bound(max_response_bytes, MAX_RUNTIME_QUERY_RESPONSE_BYTES)?;
        let canonical_wire =
            build_query_request_wire(selector, &authentication, max_response_bytes);
        if canonical_wire.len() > MAX_RUNTIME_QUERY_REQUEST_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        let request_digest = digest_wire(QUERY_REQUEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            selector,
            authentication,
            max_response_bytes,
            canonical_wire: canonical_wire.into_boxed_slice(),
            request_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_query_request(frame)
    }

    #[must_use]
    pub(crate) const fn selector(&self) -> RuntimeQuerySelectorV1 {
        self.selector
    }

    #[must_use]
    pub(crate) const fn query_id(&self) -> RuntimeQueryId {
        self.selector.query_id
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.selector.target
    }

    #[must_use]
    pub(crate) const fn source_scope(&self) -> SourceScopeRef {
        self.selector.source_scope
    }

    #[must_use]
    pub(crate) const fn expected_store_instance_id(&self) -> RuntimeStoreInstanceId {
        self.selector.expected_store_instance_id
    }

    #[must_use]
    pub(crate) const fn requested_operation_id(&self) -> ApplyOperationId {
        self.selector.requested_operation_id
    }

    #[must_use]
    pub(crate) const fn expected_request_digest(&self) -> Option<Digest32> {
        self.selector.expected_request_digest
    }

    #[must_use]
    pub(crate) const fn authentication(&self) -> &ApplyRequestAuthentication {
        &self.authentication
    }

    #[must_use]
    pub(crate) const fn max_response_bytes(&self) -> u32 {
        self.max_response_bytes
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    pub(crate) fn validate_expected_store(
        &self,
        local_store: RuntimeStoreInstanceId,
    ) -> Result<(), ReferenceWireError> {
        if self.selector.expected_store_instance_id != local_store {
            return Err(ReferenceWireError::new(
                ReferenceWireErrorCode::RuntimeStoreMismatch,
            ));
        }
        Ok(())
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
        let draft = RuntimeQueryRequestDraftV1::try_new(
            self.selector,
            self.authentication.claim().clone(),
            self.max_response_bytes,
        )?;
        draft.signing_transcript()
    }
}

fn build_query_request_wire(
    selector: RuntimeQuerySelectorV1,
    authentication: &ApplyRequestAuthentication,
    max_response_bytes: u32,
) -> Vec<u8> {
    let mut encoded = begin_tlv_frame(
        RUNTIME_QUERY_REQUEST_MAGIC,
        RUNTIME_QUERY_PROTOCOL_VERSION,
        QUERY_REQUEST_FIELD_COUNT,
    );
    append_query_request_fields(
        &mut encoded,
        selector,
        authentication.claim(),
        max_response_bytes,
        Some(authentication.signature()),
    );
    encoded
}

fn append_query_request_fields(
    encoded: &mut Vec<u8>,
    selector: RuntimeQuerySelectorV1,
    auth_claim: &ApplyRequestAuthClaim,
    max_response_bytes: u32,
    signature: Option<&[u8]>,
) {
    let (presence, digest) = encode_optional_digest(selector.expected_request_digest);
    append_tlv(encoded, 1, selector.query_id.as_bytes());
    append_tlv(encoded, 2, selector.target.as_bytes());
    append_tlv(encoded, 3, selector.source_scope.as_bytes());
    append_tlv(encoded, 4, selector.expected_store_instance_id.as_bytes());
    append_tlv(encoded, 5, selector.requested_operation_id.as_bytes());
    append_tlv(encoded, 6, &[presence]);
    append_tlv(encoded, 7, digest.as_bytes());
    append_tlv(encoded, 8, auth_claim.nonce());
    append_tlv(encoded, 9, &max_response_bytes.to_be_bytes());
    append_tlv(encoded, 10, &MAX_QUERY_RECORD_COUNT.to_be_bytes());
    append_tlv(encoded, 11, auth_claim.principal().as_bytes());
    append_tlv(encoded, 12, auth_claim.key().as_bytes());
    append_tlv(encoded, 13, &auth_claim.algorithm().value().to_be_bytes());
    append_tlv(encoded, 14, &auth_claim.algorithm_version().to_be_bytes());
    if let Some(signature) = signature {
        append_tlv(encoded, 15, signature);
    }
}

fn decode_query_request(frame: &[u8]) -> Result<RuntimeQueryRequestV1, ReferenceWireError> {
    let fields = parse_tlv_frame(
        frame,
        RUNTIME_QUERY_REQUEST_MAGIC,
        RUNTIME_QUERY_PROTOCOL_VERSION,
        QUERY_REQUEST_FIELD_COUNT,
        MAX_RUNTIME_QUERY_REQUEST_BYTES,
        valid_query_request_field_length,
    )?;
    let expected_store_instance_id = RuntimeStoreInstanceId::try_from_bytes(fields.array(4)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 4))?;
    let expected_request_digest = decode_optional_digest(fields.get(6)[0], fields.array(7)?, 6)?;
    let max_response_bytes = fields.u32(9)?;
    validate_response_bound(max_response_bytes, MAX_RUNTIME_QUERY_RESPONSE_BYTES)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 9))?;
    if fields.u16(10)? != MAX_QUERY_RECORD_COUNT {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            10,
        ));
    }
    let authentication = decode_control_request_auth(&fields, 11, 12, 13, 14, 8, 15)?;
    let selector = RuntimeQuerySelectorV1::try_new(
        RuntimeQueryId::from_bytes(fields.array(1)?),
        RuntimeHostId::from_bytes(fields.array(2)?),
        SourceScopeRef::from_bytes(fields.array(3)?),
        expected_store_instance_id,
        ApplyOperationId::from_bytes(fields.array(5)?),
        expected_request_digest,
    )
    .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue))?;
    let decoded = RuntimeQueryRequestV1::try_new(selector, authentication, max_response_bytes)
        .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn valid_query_request_field_length(tag: u16, length: usize) -> bool {
    valid_control_request_field_length(
        tag,
        length,
        &[
            (1, 16),
            (2, 16),
            (3, 16),
            (4, 32),
            (5, 16),
            (6, 1),
            (7, 32),
            (9, 4),
            (10, 2),
            (11, 16),
            (12, 16),
            (13, 2),
            (14, 2),
        ],
        8,
        15,
    )
}

fn encode_optional_digest(value: Option<Digest32>) -> (u8, Digest32) {
    value.map_or((0, Digest32::from_bytes([0; 32])), |digest| (1, digest))
}

fn decode_optional_digest(
    presence: u8,
    bytes: [u8; 32],
    detail: u16,
) -> Result<Option<Digest32>, ReferenceWireError> {
    let digest = Digest32::from_bytes(bytes);
    match presence {
        0 if digest_is_zero(&digest) => Ok(None),
        1 if !digest_is_zero(&digest) => Ok(Some(digest)),
        0 | 1 => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidPresence,
            detail,
        )),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidPresence,
            detail,
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub(crate) enum RuntimeOwnerStateV1 {
    Operational = 1,
    ApplyDisabled = 2,
    OwnershipUncertain = 3,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub(crate) enum RuntimeOperationDurablePhaseV1 {
    PreparedNoEffects = 1,
    FirstActionIntent = 2,
    HeadCommittedRetiringOld = 3,
    Terminal = 4,
}

/// Exact operation lookup result; invalid field combinations are unrepresentable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum RuntimeOperationLookupV1 {
    Known {
        request_digest: Digest32,
        durable_phase: RuntimeOperationDurablePhaseV1,
        terminal_result: Option<TerminalResultRef>,
    },
    Conflict {
        existing_request_digest: Digest32,
    },
    Unknown,
    Indeterminate {
        reason: OperationalReasonV1,
    },
}

impl RuntimeOperationLookupV1 {
    pub(crate) fn try_known(
        request_digest: Digest32,
        durable_phase: RuntimeOperationDurablePhaseV1,
        terminal_result: Option<TerminalResultRef>,
    ) -> Result<Self, ReferenceContractError> {
        if digest_is_zero(&request_digest)
            || (durable_phase == RuntimeOperationDurablePhaseV1::Terminal)
                != terminal_result.is_some()
            || terminal_result.is_some_and(|reference| all_zero(reference.as_bytes()))
        {
            return Err(ReferenceContractError::InvalidReason);
        }
        Ok(Self::Known {
            request_digest,
            durable_phase,
            terminal_result,
        })
    }

    pub(crate) fn try_conflict(
        existing_request_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        if digest_is_zero(&existing_request_digest) {
            return Err(ReferenceContractError::InvalidReason);
        }
        Ok(Self::Conflict {
            existing_request_digest,
        })
    }

    #[must_use]
    pub(crate) const fn indeterminate(reason: OperationalReasonV1) -> Self {
        Self::Indeterminate { reason }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub(crate) enum RuntimeDesiredHeadKindV1 {
    None = 1,
    OneSourceLoop = 2,
    EmptyDeactivate = 3,
}

/// Durable desired head, separate from current live materialization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum RuntimeDesiredHeadV1 {
    None,
    OneSourceLoop {
        source_revision: SourcePlanRevision,
        target_slice_digest: Digest32,
        manifest_digest: Digest32,
    },
    EmptyDeactivate {
        source_revision: SourcePlanRevision,
        target_slice_digest: Digest32,
        manifest_digest: Digest32,
    },
}

impl RuntimeDesiredHeadV1 {
    pub(crate) fn try_one_source_loop(
        source_revision: SourcePlanRevision,
        target_slice_digest: Digest32,
        manifest_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        validate_desired_head_values(source_revision, target_slice_digest, manifest_digest)?;
        Ok(Self::OneSourceLoop {
            source_revision,
            target_slice_digest,
            manifest_digest,
        })
    }

    pub(crate) fn try_empty_deactivate(
        source_revision: SourcePlanRevision,
        target_slice_digest: Digest32,
        manifest_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        validate_desired_head_values(source_revision, target_slice_digest, manifest_digest)?;
        Ok(Self::EmptyDeactivate {
            source_revision,
            target_slice_digest,
            manifest_digest,
        })
    }

    const fn kind(self) -> RuntimeDesiredHeadKindV1 {
        match self {
            Self::None => RuntimeDesiredHeadKindV1::None,
            Self::OneSourceLoop { .. } => RuntimeDesiredHeadKindV1::OneSourceLoop,
            Self::EmptyDeactivate { .. } => RuntimeDesiredHeadKindV1::EmptyDeactivate,
        }
    }

    fn encoded_values(self) -> (u64, Digest32, Digest32) {
        match self {
            Self::None => (
                0,
                Digest32::from_bytes([0; 32]),
                Digest32::from_bytes([0; 32]),
            ),
            Self::OneSourceLoop {
                source_revision,
                target_slice_digest,
                manifest_digest,
            }
            | Self::EmptyDeactivate {
                source_revision,
                target_slice_digest,
                manifest_digest,
            } => (
                source_revision.value(),
                target_slice_digest,
                manifest_digest,
            ),
        }
    }
}

fn validate_desired_head_values(
    source_revision: SourcePlanRevision,
    target_slice_digest: Digest32,
    manifest_digest: Digest32,
) -> Result<(), ReferenceContractError> {
    if source_revision.value() == 0
        || digest_is_zero(&target_slice_digest)
        || digest_is_zero(&manifest_digest)
    {
        return Err(ReferenceContractError::InvalidCompatibility);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeDesiredStateV1 {
    head: RuntimeDesiredHeadV1,
    source_revision_high_water: SourcePlanRevision,
}

impl RuntimeDesiredStateV1 {
    pub(crate) fn try_new(
        head: RuntimeDesiredHeadV1,
        source_revision_high_water: SourcePlanRevision,
    ) -> Result<Self, ReferenceContractError> {
        let (revision, _, _) = head.encoded_values();
        if source_revision_high_water.value() < revision {
            return Err(ReferenceContractError::InvalidBound);
        }
        Ok(Self {
            head,
            source_revision_high_water,
        })
    }

    #[must_use]
    pub(crate) const fn head(self) -> RuntimeDesiredHeadV1 {
        self.head
    }

    #[must_use]
    pub(crate) const fn source_revision_high_water(self) -> SourcePlanRevision {
        self.source_revision_high_water
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub(crate) enum RuntimeLiveStateV1 {
    NotReady = 1,
    Recovering = 2,
    LiveReady = 3,
    Draining = 4,
    RecoveryFailedNotReady = 5,
    ExactZero = 6,
    ValidatedOperationalQuarantine = 7,
    Uncertain = 8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeLiveFactsV1 {
    state: RuntimeLiveStateV1,
    resource_generation: u64,
    measured_at: u64,
    census_digest: Digest32,
}

impl RuntimeLiveFactsV1 {
    pub(crate) fn try_new(
        state: RuntimeLiveStateV1,
        resource_generation: u64,
        measured_at: u64,
        census_digest: Digest32,
    ) -> Result<Self, ReferenceContractError> {
        let generation_valid = match state {
            RuntimeLiveStateV1::LiveReady | RuntimeLiveStateV1::Draining => resource_generation > 0,
            RuntimeLiveStateV1::NotReady
            | RuntimeLiveStateV1::RecoveryFailedNotReady
            | RuntimeLiveStateV1::ExactZero
            | RuntimeLiveStateV1::ValidatedOperationalQuarantine => resource_generation == 0,
            RuntimeLiveStateV1::Recovering | RuntimeLiveStateV1::Uncertain => true,
        };
        if !generation_valid || digest_is_zero(&census_digest) {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        Ok(Self {
            state,
            resource_generation,
            measured_at,
            census_digest,
        })
    }

    #[must_use]
    pub(crate) const fn state(self) -> RuntimeLiveStateV1 {
        self.state
    }

    #[must_use]
    pub(crate) const fn resource_generation(self) -> u64 {
        self.resource_generation
    }

    #[must_use]
    pub(crate) const fn measured_at(self) -> u64 {
        self.measured_at
    }

    #[must_use]
    pub(crate) const fn census_digest(self) -> Digest32 {
        self.census_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeQueryOperationStateV1 {
    owner_state: RuntimeOwnerStateV1,
    reason: Option<OperationalReasonV1>,
    lookup: RuntimeOperationLookupV1,
}

impl RuntimeQueryOperationStateV1 {
    pub(crate) fn try_new(
        owner_state: RuntimeOwnerStateV1,
        reason: Option<OperationalReasonV1>,
        lookup: RuntimeOperationLookupV1,
    ) -> Result<Self, ReferenceContractError> {
        let lookup_valid = match lookup {
            RuntimeOperationLookupV1::Known { .. }
            | RuntimeOperationLookupV1::Conflict { .. }
            | RuntimeOperationLookupV1::Unknown => true,
            RuntimeOperationLookupV1::Indeterminate {
                reason: lookup_reason,
            } => reason.is_some_and(|reason| reason == lookup_reason),
        };
        if !valid_owner_reason(owner_state, reason) || !lookup_valid {
            return Err(ReferenceContractError::InvalidReason);
        }
        Ok(Self {
            owner_state,
            reason,
            lookup,
        })
    }

    #[must_use]
    pub(crate) const fn owner_state(self) -> RuntimeOwnerStateV1 {
        self.owner_state
    }

    #[must_use]
    pub(crate) const fn reason(self) -> Option<OperationalReasonV1> {
        self.reason
    }

    #[must_use]
    pub(crate) const fn lookup(self) -> RuntimeOperationLookupV1 {
        self.lookup
    }
}

const fn valid_owner_reason(
    owner: RuntimeOwnerStateV1,
    reason: Option<OperationalReasonV1>,
) -> bool {
    matches!(
        (owner, reason),
        (RuntimeOwnerStateV1::Operational, None)
            | (
                RuntimeOwnerStateV1::ApplyDisabled,
                Some(
                    OperationalReasonV1::Recovering
                        | OperationalReasonV1::ActiveCompatibilityMismatch
                        | OperationalReasonV1::RecoveryFailed
                        | OperationalReasonV1::RuntimeBusy,
                ),
            )
            | (
                RuntimeOwnerStateV1::OwnershipUncertain,
                Some(
                    OperationalReasonV1::OwnershipUncertain
                        | OperationalReasonV1::HistoryUnavailable
                        | OperationalReasonV1::ResourceCensusUncertain
                        | OperationalReasonV1::OwnershipTransferRequired,
                ),
            )
    )
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeQueryFactsV1 {
    serving: RuntimeBootstrapServingIdentityV1,
    operation: RuntimeQueryOperationStateV1,
    desired: RuntimeDesiredStateV1,
    live: RuntimeLiveFactsV1,
}

impl RuntimeQueryFactsV1 {
    pub(crate) const fn try_new(
        serving: RuntimeBootstrapServingIdentityV1,
        operation: RuntimeQueryOperationStateV1,
        desired: RuntimeDesiredStateV1,
        live: RuntimeLiveFactsV1,
    ) -> Result<Self, ReferenceContractError> {
        if !valid_desired_live_shape(desired.head, live.state)
            || !valid_operation_live_shape(operation.owner_state, operation.reason, live.state)
        {
            return Err(ReferenceContractError::InvalidShape);
        }
        Ok(Self {
            serving,
            operation,
            desired,
            live,
        })
    }

    #[must_use]
    pub(crate) const fn serving(self) -> RuntimeBootstrapServingIdentityV1 {
        self.serving
    }

    #[must_use]
    pub(crate) const fn operation(self) -> RuntimeQueryOperationStateV1 {
        self.operation
    }

    #[must_use]
    pub(crate) const fn desired(self) -> RuntimeDesiredStateV1 {
        self.desired
    }

    #[must_use]
    pub(crate) const fn live(self) -> RuntimeLiveFactsV1 {
        self.live
    }
}

const fn valid_desired_live_shape(desired: RuntimeDesiredHeadV1, live: RuntimeLiveStateV1) -> bool {
    match live {
        RuntimeLiveStateV1::LiveReady
        | RuntimeLiveStateV1::Recovering
        | RuntimeLiveStateV1::RecoveryFailedNotReady => {
            matches!(desired, RuntimeDesiredHeadV1::OneSourceLoop { .. })
        }
        RuntimeLiveStateV1::Draining => {
            matches!(desired, RuntimeDesiredHeadV1::EmptyDeactivate { .. })
        }
        RuntimeLiveStateV1::ExactZero => matches!(
            desired,
            RuntimeDesiredHeadV1::None | RuntimeDesiredHeadV1::EmptyDeactivate { .. }
        ),
        RuntimeLiveStateV1::NotReady
        | RuntimeLiveStateV1::ValidatedOperationalQuarantine
        | RuntimeLiveStateV1::Uncertain => true,
    }
}

const fn valid_operation_live_shape(
    owner: RuntimeOwnerStateV1,
    reason: Option<OperationalReasonV1>,
    live: RuntimeLiveStateV1,
) -> bool {
    match (owner, reason) {
        (RuntimeOwnerStateV1::Operational, None) => matches!(
            live,
            RuntimeLiveStateV1::NotReady
                | RuntimeLiveStateV1::LiveReady
                | RuntimeLiveStateV1::ExactZero
        ),
        (RuntimeOwnerStateV1::ApplyDisabled, Some(OperationalReasonV1::Recovering)) => {
            matches!(live, RuntimeLiveStateV1::Recovering)
        }
        (
            RuntimeOwnerStateV1::ApplyDisabled,
            Some(OperationalReasonV1::ActiveCompatibilityMismatch),
        ) => matches!(live, RuntimeLiveStateV1::ValidatedOperationalQuarantine),
        (RuntimeOwnerStateV1::ApplyDisabled, Some(OperationalReasonV1::RecoveryFailed)) => {
            matches!(live, RuntimeLiveStateV1::RecoveryFailedNotReady)
        }
        (RuntimeOwnerStateV1::ApplyDisabled, Some(OperationalReasonV1::RuntimeBusy)) => matches!(
            live,
            RuntimeLiveStateV1::NotReady
                | RuntimeLiveStateV1::LiveReady
                | RuntimeLiveStateV1::Draining
                | RuntimeLiveStateV1::RecoveryFailedNotReady
                | RuntimeLiveStateV1::ExactZero
        ),
        (RuntimeOwnerStateV1::OwnershipUncertain, Some(_)) => matches!(
            live,
            RuntimeLiveStateV1::Uncertain | RuntimeLiveStateV1::ValidatedOperationalQuarantine
        ),
        _ => false,
    }
}

/// Signature-independent query response and channel-auth transcript owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeQueryResponseDraftV1 {
    query_id: RuntimeQueryId,
    query_request_digest: Digest32,
    client_nonce: Box<[u8]>,
    facts: RuntimeQueryFactsV1,
    auth_claim: RuntimeResponseAuthClaimV1,
    requested_max_response_bytes: u32,
}

impl RuntimeQueryResponseDraftV1 {
    pub(crate) fn try_new(
        request: &RuntimeQueryRequestV1,
        facts: RuntimeQueryFactsV1,
        channel: RuntimeChannelBindingV1,
        auth_claim: RuntimeResponseAuthClaimV1,
    ) -> Result<Self, ReferenceContractError> {
        if request.target() != facts.serving.target
            || request.expected_store_instance_id() != facts.serving.store_instance_id
            || request.target() != channel.target()
            || auth_claim.runtime_peer() != channel.runtime_peer()
            || auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ReferenceContractError::TargetMismatch);
        }
        validate_query_expectation(request.expected_request_digest(), facts.operation.lookup)?;
        Ok(Self {
            query_id: request.query_id(),
            query_request_digest: request.request_digest(),
            client_nonce: request.authentication().claim().nonce().into(),
            facts,
            auth_claim,
            requested_max_response_bytes: request.max_response_bytes(),
        })
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
        let mut encoded = begin_signing_transcript(
            QUERY_RESPONSE_SIGNING_DOMAIN,
            QUERY_RESPONSE_SIGNING_FIELD_COUNT,
        );
        append_query_response_fields(
            &mut encoded,
            self.query_id,
            self.query_request_digest,
            &self.client_nonce,
            self.facts,
            self.auth_claim,
            None,
        );
        if encoded.len() > MAX_RUNTIME_QUERY_RESPONSE_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        Ok(ControlReadSigningTranscriptV1(encoded.into_boxed_slice()))
    }

    pub(crate) fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeQueryResponseV1, ReferenceContractError> {
        let authentication = RuntimeResponseAuthenticationV1::try_new(self.auth_claim, signature)?;
        RuntimeQueryResponseV1::try_new(
            self.query_id,
            self.query_request_digest,
            &self.client_nonce,
            self.facts,
            authentication,
            Some(self.requested_max_response_bytes),
        )
    }
}

fn validate_query_expectation(
    expected: Option<Digest32>,
    lookup: RuntimeOperationLookupV1,
) -> Result<(), ReferenceContractError> {
    let valid = match (expected, lookup) {
        (Some(expected), RuntimeOperationLookupV1::Known { request_digest, .. }) => {
            request_digest == expected
        }
        (
            Some(expected),
            RuntimeOperationLookupV1::Conflict {
                existing_request_digest,
            },
        ) => existing_request_digest != expected,
        (
            Some(_),
            RuntimeOperationLookupV1::Unknown | RuntimeOperationLookupV1::Indeterminate { .. },
        ) => true,
        (
            None,
            RuntimeOperationLookupV1::Known { .. }
            | RuntimeOperationLookupV1::Unknown
            | RuntimeOperationLookupV1::Indeterminate { .. },
        ) => true,
        (None, RuntimeOperationLookupV1::Conflict { .. }) => false,
    };
    if !valid {
        return Err(ReferenceContractError::InvalidReason);
    }
    Ok(())
}

/// Signed query response bound to the exact live channel and request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeQueryResponseV1 {
    query_id: RuntimeQueryId,
    query_request_digest: Digest32,
    client_nonce: Box<[u8]>,
    facts: RuntimeQueryFactsV1,
    authentication: RuntimeResponseAuthenticationV1,
    canonical_wire: Box<[u8]>,
    response_digest: Digest32,
}

impl RuntimeQueryResponseV1 {
    fn try_new(
        query_id: RuntimeQueryId,
        query_request_digest: Digest32,
        client_nonce: &[u8],
        facts: RuntimeQueryFactsV1,
        authentication: RuntimeResponseAuthenticationV1,
        requested_max_response_bytes: Option<u32>,
    ) -> Result<Self, ReferenceContractError> {
        validate_nonce(client_nonce, MAX_CONTROL_READ_NONCE_BYTES)?;
        if digest_is_zero(&query_request_digest) {
            return Err(ReferenceContractError::InvalidCompatibility);
        }
        let canonical_wire = build_query_response_wire(
            query_id,
            query_request_digest,
            client_nonce,
            facts,
            &authentication,
        );
        if canonical_wire.len() > MAX_RUNTIME_QUERY_RESPONSE_BYTES {
            return Err(ReferenceContractError::RequestFrameTooLarge);
        }
        if requested_max_response_bytes.is_some_and(|bound| canonical_wire.len() > bound as usize) {
            return Err(ReferenceContractError::InvalidBound);
        }
        let response_digest = digest_wire(QUERY_RESPONSE_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            query_id,
            query_request_digest,
            client_nonce: client_nonce.into(),
            facts,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            response_digest,
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, ReferenceWireError> {
        decode_query_response(frame)
    }

    #[must_use]
    pub(crate) const fn query_id(&self) -> RuntimeQueryId {
        self.query_id
    }

    #[must_use]
    pub(crate) const fn query_request_digest(&self) -> Digest32 {
        self.query_request_digest
    }

    #[must_use]
    pub(crate) fn client_nonce(&self) -> &[u8] {
        &self.client_nonce
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> RuntimeQueryFactsV1 {
        self.facts
    }

    #[must_use]
    pub(crate) const fn authentication(&self) -> &RuntimeResponseAuthenticationV1 {
        &self.authentication
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn response_digest(&self) -> Digest32 {
        self.response_digest
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<ControlReadSigningTranscriptV1, ReferenceContractError> {
        let mut encoded = begin_signing_transcript(
            QUERY_RESPONSE_SIGNING_DOMAIN,
            QUERY_RESPONSE_SIGNING_FIELD_COUNT,
        );
        append_query_response_fields(
            &mut encoded,
            self.query_id,
            self.query_request_digest,
            &self.client_nonce,
            self.facts,
            self.authentication.claim(),
            None,
        );
        Ok(ControlReadSigningTranscriptV1(encoded.into_boxed_slice()))
    }

    pub(crate) fn validate_against_request(
        &self,
        request: &RuntimeQueryRequestV1,
        channel: RuntimeChannelBindingV1,
        serving_baseline: RuntimeBootstrapServingIdentityV1,
    ) -> Result<(), ReferenceWireError> {
        self.validate_echo_fields(request, channel)?;
        self.validate_serving_freshness(serving_baseline)?;
        self.validate_expectation(request)?;
        self.validate_peer_channel_and_bound(request, channel)
    }

    fn validate_echo_fields(
        &self,
        request: &RuntimeQueryRequestV1,
        channel: RuntimeChannelBindingV1,
    ) -> Result<(), ReferenceWireError> {
        if self.query_id != request.query_id() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                1,
            ));
        }
        if self.query_request_digest != request.request_digest() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                2,
            ));
        }
        if self.client_nonce.as_ref() != request.authentication().claim().nonce() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                3,
            ));
        }
        if self.facts.serving.target != request.target() || channel.target() != request.target() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                4,
            ));
        }
        if self.facts.serving.store_instance_id != request.expected_store_instance_id() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                5,
            ));
        }
        Ok(())
    }

    fn validate_expectation(
        &self,
        request: &RuntimeQueryRequestV1,
    ) -> Result<(), ReferenceWireError> {
        match (
            request.expected_request_digest(),
            self.facts.operation.lookup,
        ) {
            (Some(expected), RuntimeOperationLookupV1::Known { request_digest, .. })
                if request_digest != expected =>
            {
                return Err(ReferenceWireError::at(
                    ReferenceWireErrorCode::CrossReferenceMismatch,
                    14,
                ));
            }
            (
                Some(expected),
                RuntimeOperationLookupV1::Conflict {
                    existing_request_digest,
                },
            ) if existing_request_digest == expected => {
                return Err(ReferenceWireError::at(
                    ReferenceWireErrorCode::CrossReferenceMismatch,
                    14,
                ));
            }
            (None, RuntimeOperationLookupV1::Conflict { .. }) => {
                return Err(ReferenceWireError::at(
                    ReferenceWireErrorCode::CrossReferenceMismatch,
                    12,
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_peer_channel_and_bound(
        &self,
        request: &RuntimeQueryRequestV1,
        channel: RuntimeChannelBindingV1,
    ) -> Result<(), ReferenceWireError> {
        if self.authentication.claim().runtime_peer() != channel.runtime_peer() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                27,
            ));
        }
        if self.authentication.claim().channel_binding_digest() != channel.binding_digest() {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                28,
            ));
        }
        if self.canonical_wire.len() > request.max_response_bytes() as usize {
            return Err(ReferenceWireError::new(
                ReferenceWireErrorCode::ResponseBoundExceeded,
            ));
        }
        Ok(())
    }

    /// Internal S7-F consumer check against the last authenticated serving baseline.
    fn validate_serving_freshness(
        &self,
        baseline: RuntimeBootstrapServingIdentityV1,
    ) -> Result<(), ReferenceWireError> {
        let serving = self.facts.serving;
        if serving.target != baseline.target {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                4,
            ));
        }
        if serving.store_instance_id != baseline.store_instance_id {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                5,
            ));
        }
        if serving.snapshot_sequence < baseline.snapshot_sequence
            || (serving.runtime_host_epoch > baseline.runtime_host_epoch
                && serving.snapshot_sequence <= baseline.snapshot_sequence)
        {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                6,
            ));
        }
        if serving.runtime_host_epoch < baseline.runtime_host_epoch {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::CrossReferenceMismatch,
                7,
            ));
        }
        if serving.clock_domain != baseline.clock_domain {
            return Err(ReferenceWireError::at(
                ReferenceWireErrorCode::TargetMismatch,
                8,
            ));
        }
        if serving.runtime_host_epoch == baseline.runtime_host_epoch {
            if serving.clock_generation != baseline.clock_generation {
                return Err(ReferenceWireError::at(
                    ReferenceWireErrorCode::CrossReferenceMismatch,
                    9,
                ));
            }
        } else {
            if serving.clock_generation <= baseline.clock_generation {
                return Err(ReferenceWireError::at(
                    ReferenceWireErrorCode::CrossReferenceMismatch,
                    9,
                ));
            }
        }
        Ok(())
    }
}

fn build_query_response_wire(
    query_id: RuntimeQueryId,
    query_request_digest: Digest32,
    client_nonce: &[u8],
    facts: RuntimeQueryFactsV1,
    authentication: &RuntimeResponseAuthenticationV1,
) -> Vec<u8> {
    let mut encoded = begin_tlv_frame(
        RUNTIME_QUERY_RESPONSE_MAGIC,
        RUNTIME_QUERY_PROTOCOL_VERSION,
        QUERY_RESPONSE_FIELD_COUNT,
    );
    append_query_response_fields(
        &mut encoded,
        query_id,
        query_request_digest,
        client_nonce,
        facts,
        authentication.claim(),
        Some(authentication.signature()),
    );
    encoded
}

fn append_query_response_fields(
    encoded: &mut Vec<u8>,
    query_id: RuntimeQueryId,
    query_request_digest: Digest32,
    client_nonce: &[u8],
    facts: RuntimeQueryFactsV1,
    auth_claim: RuntimeResponseAuthClaimV1,
    signature: Option<&[u8]>,
) {
    let lookup = encode_operation_lookup(facts.operation.lookup);
    let (desired_revision, desired_slice, desired_manifest) = facts.desired.head.encoded_values();
    append_tlv(encoded, 1, query_id.as_bytes());
    append_tlv(encoded, 2, query_request_digest.as_bytes());
    append_tlv(encoded, 3, client_nonce);
    append_tlv(encoded, 4, facts.serving.target.as_bytes());
    append_tlv(encoded, 5, facts.serving.store_instance_id.as_bytes());
    append_tlv(
        encoded,
        6,
        &facts.serving.snapshot_sequence.value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        7,
        &facts.serving.runtime_host_epoch.value().to_be_bytes(),
    );
    append_tlv(encoded, 8, facts.serving.clock_domain.as_bytes());
    append_tlv(
        encoded,
        9,
        &facts.serving.clock_generation.value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        10,
        &(facts.operation.owner_state as u16).to_be_bytes(),
    );
    append_tlv(
        encoded,
        11,
        &facts
            .operation
            .reason
            .map_or(0, |reason| reason as u16)
            .to_be_bytes(),
    );
    append_tlv(encoded, 12, &lookup.kind.to_be_bytes());
    append_tlv(encoded, 13, &[lookup.digest_presence]);
    append_tlv(encoded, 14, lookup.request_digest.as_bytes());
    append_tlv(encoded, 15, &lookup.phase.to_be_bytes());
    append_tlv(encoded, 16, &[lookup.terminal_presence]);
    append_tlv(encoded, 17, &lookup.terminal_ref);
    append_tlv(
        encoded,
        18,
        &(facts.desired.head.kind() as u16).to_be_bytes(),
    );
    append_tlv(encoded, 19, &desired_revision.to_be_bytes());
    append_tlv(encoded, 20, desired_slice.as_bytes());
    append_tlv(encoded, 21, desired_manifest.as_bytes());
    append_tlv(
        encoded,
        22,
        &facts
            .desired
            .source_revision_high_water
            .value()
            .to_be_bytes(),
    );
    append_tlv(encoded, 23, &(facts.live.state as u16).to_be_bytes());
    append_tlv(encoded, 24, &facts.live.resource_generation.to_be_bytes());
    append_tlv(encoded, 25, &facts.live.measured_at.to_be_bytes());
    append_tlv(encoded, 26, facts.live.census_digest.as_bytes());
    append_tlv(encoded, 27, auth_claim.runtime_peer().as_bytes());
    append_tlv(encoded, 28, auth_claim.channel_binding_digest().as_bytes());
    append_tlv(encoded, 29, auth_claim.key().as_bytes());
    append_tlv(encoded, 30, &auth_claim.algorithm().value().to_be_bytes());
    append_tlv(encoded, 31, &auth_claim.algorithm_version().to_be_bytes());
    if let Some(signature) = signature {
        append_tlv(encoded, 32, signature);
    }
}

struct EncodedOperationLookup {
    kind: u16,
    digest_presence: u8,
    request_digest: Digest32,
    phase: u16,
    terminal_presence: u8,
    terminal_ref: [u8; 16],
}

fn encode_operation_lookup(lookup: RuntimeOperationLookupV1) -> EncodedOperationLookup {
    let zero_digest = Digest32::from_bytes([0; 32]);
    match lookup {
        RuntimeOperationLookupV1::Known {
            request_digest,
            durable_phase,
            terminal_result,
        } => EncodedOperationLookup {
            kind: 1,
            digest_presence: 1,
            request_digest,
            phase: durable_phase as u16,
            terminal_presence: u8::from(terminal_result.is_some()),
            terminal_ref: terminal_result.map_or([0; 16], |reference| *reference.as_bytes()),
        },
        RuntimeOperationLookupV1::Conflict {
            existing_request_digest,
        } => EncodedOperationLookup {
            kind: 2,
            digest_presence: 1,
            request_digest: existing_request_digest,
            phase: 0,
            terminal_presence: 0,
            terminal_ref: [0; 16],
        },
        RuntimeOperationLookupV1::Unknown => EncodedOperationLookup {
            kind: 3,
            digest_presence: 0,
            request_digest: zero_digest,
            phase: 0,
            terminal_presence: 0,
            terminal_ref: [0; 16],
        },
        RuntimeOperationLookupV1::Indeterminate { .. } => EncodedOperationLookup {
            kind: 4,
            digest_presence: 0,
            request_digest: zero_digest,
            phase: 0,
            terminal_presence: 0,
            terminal_ref: [0; 16],
        },
    }
}

fn decode_query_response(frame: &[u8]) -> Result<RuntimeQueryResponseV1, ReferenceWireError> {
    let fields = parse_tlv_frame(
        frame,
        RUNTIME_QUERY_RESPONSE_MAGIC,
        RUNTIME_QUERY_PROTOCOL_VERSION,
        QUERY_RESPONSE_FIELD_COUNT,
        MAX_RUNTIME_QUERY_RESPONSE_BYTES,
        valid_query_response_field_length,
    )?;
    let query_request_digest = Digest32::from_bytes(fields.array(2)?);
    if digest_is_zero(&query_request_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            2,
        ));
    }

    let store_instance_id = RuntimeStoreInstanceId::try_from_bytes(fields.array(5)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 5))?;
    let snapshot_sequence = RuntimeSnapshotSequence::try_new(fields.u64(6)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 6))?;
    let runtime_host_epoch = RuntimeHostEpoch::try_new(fields.u64(7)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 7))?;
    let clock_generation = ClockGeneration::try_new(fields.u64(9)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 9))?;
    let owner_state = decode_owner_state(fields.u16(10)?)?;
    let reason = decode_operational_reason(fields.u16(11)?, 11)?;
    if !valid_owner_reason(owner_state, reason) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            11,
        ));
    }
    let lookup = decode_operation_lookup(
        fields.u16(12)?,
        fields.get(13)[0],
        fields.array(14)?,
        fields.u16(15)?,
        fields.get(16)[0],
        fields.array(17)?,
        reason,
    )?;
    let operation = RuntimeQueryOperationStateV1::try_new(owner_state, reason, lookup)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 11))?;
    let desired_head = decode_desired_head(
        fields.u16(18)?,
        fields.u64(19)?,
        Digest32::from_bytes(fields.array(20)?),
        Digest32::from_bytes(fields.array(21)?),
    )?;
    let desired =
        RuntimeDesiredStateV1::try_new(desired_head, SourcePlanRevision::new(fields.u64(22)?))
            .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 22))?;
    let live_state = decode_live_state(fields.u16(23)?)?;
    if !valid_desired_live_shape(desired.head, live_state)
        || !valid_operation_live_shape(operation.owner_state, operation.reason, live_state)
    {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            23,
        ));
    }
    let resource_generation = fields.u64(24)?;
    let generation_valid = match live_state {
        RuntimeLiveStateV1::LiveReady | RuntimeLiveStateV1::Draining => resource_generation > 0,
        RuntimeLiveStateV1::NotReady
        | RuntimeLiveStateV1::RecoveryFailedNotReady
        | RuntimeLiveStateV1::ExactZero
        | RuntimeLiveStateV1::ValidatedOperationalQuarantine => resource_generation == 0,
        RuntimeLiveStateV1::Recovering | RuntimeLiveStateV1::Uncertain => true,
    };
    if !generation_valid {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            24,
        ));
    }
    let census_digest = Digest32::from_bytes(fields.array(26)?);
    if digest_is_zero(&census_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            26,
        ));
    }
    let live = RuntimeLiveFactsV1::try_new(
        live_state,
        resource_generation,
        fields.u64(25)?,
        census_digest,
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 23))?;
    let serving = RuntimeBootstrapServingIdentityV1::new(
        RuntimeHostId::from_bytes(fields.array(4)?),
        store_instance_id,
        snapshot_sequence,
        runtime_host_epoch,
        ClockDomainRef::from_bytes(fields.array(8)?),
        clock_generation,
    );
    let facts = RuntimeQueryFactsV1::try_new(serving, operation, desired, live)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 23))?;
    let channel_binding_digest = Digest32::from_bytes(fields.array(28)?);
    if digest_is_zero(&channel_binding_digest) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            28,
        ));
    }
    let auth_algorithm = ApplyAuthAlgorithm::try_new(fields.u16(30)?)
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 30))?;
    let auth_algorithm_version = fields.u16(31)?;
    if auth_algorithm_version == 0 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            31,
        ));
    }
    let auth_claim = RuntimeResponseAuthClaimV1::try_new(
        PrincipalRef::from_bytes(fields.array(27)?),
        channel_binding_digest,
        ApplyAuthKeyRef::from_bytes(fields.array(29)?),
        auth_algorithm,
        auth_algorithm_version,
    )
    .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 31))?;
    let authentication = RuntimeResponseAuthenticationV1::try_new(auth_claim, fields.get(32))
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidSignatureField, 32))?;
    let decoded = RuntimeQueryResponseV1::try_new(
        RuntimeQueryId::from_bytes(fields.array(1)?),
        query_request_digest,
        fields.get(3),
        facts,
        authentication,
        None,
    )
    .map_err(|_| ReferenceWireError::new(ReferenceWireErrorCode::InvalidFieldValue))?;
    if decoded.canonical_wire() != frame {
        return Err(ReferenceWireError::new(
            ReferenceWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn valid_query_response_field_length(tag: u16, length: usize) -> bool {
    match tag {
        1 | 4 | 8 | 17 | 27 | 29 => length == 16,
        2 | 5 | 14 | 20 | 21 | 26 | 28 => length == 32,
        3 => (1..=MAX_CONTROL_READ_NONCE_BYTES).contains(&length),
        6 | 7 | 9 | 19 | 22 | 24 | 25 => length == 8,
        10..=12 | 15 | 18 | 23 | 30 | 31 => length == 2,
        13 | 16 => length == 1,
        32 => (1..=MAX_CONTROL_READ_SIGNATURE_BYTES).contains(&length),
        _ => false,
    }
}

fn decode_owner_state(value: u16) -> Result<RuntimeOwnerStateV1, ReferenceWireError> {
    match value {
        1 => Ok(RuntimeOwnerStateV1::Operational),
        2 => Ok(RuntimeOwnerStateV1::ApplyDisabled),
        3 => Ok(RuntimeOwnerStateV1::OwnershipUncertain),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            10,
        )),
    }
}

fn decode_operation_lookup(
    kind: u16,
    digest_presence: u8,
    request_digest_bytes: [u8; 32],
    phase: u16,
    terminal_presence: u8,
    terminal_result_bytes: [u8; 16],
    reason: Option<OperationalReasonV1>,
) -> Result<RuntimeOperationLookupV1, ReferenceWireError> {
    if !(1..=4).contains(&kind) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            12,
        ));
    }
    if kind == 4 && reason.is_none() {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            11,
        ));
    }
    let request_digest = decode_optional_digest(digest_presence, request_digest_bytes, 13)?;
    let digest_expected = matches!(kind, 1 | 2);
    if request_digest.is_some() != digest_expected {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            13,
        ));
    }
    if phase > RuntimeOperationDurablePhaseV1::Terminal as u16 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            15,
        ));
    }
    if (kind == 1 && phase == 0) || (kind != 1 && phase != 0) {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            15,
        ));
    }
    let terminal_result =
        decode_optional_terminal_ref(terminal_presence, terminal_result_bytes, 16)?;
    let terminal_expected = kind == 1 && phase == RuntimeOperationDurablePhaseV1::Terminal as u16;
    if terminal_result.is_some() != terminal_expected {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            16,
        ));
    }
    match kind {
        1 => {
            let digest = request_digest.ok_or_else(|| {
                ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 13)
            })?;
            let durable_phase = decode_durable_phase(phase)?;
            RuntimeOperationLookupV1::try_known(digest, durable_phase, terminal_result)
                .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 16))
        }
        2 => {
            let digest = request_digest.ok_or_else(|| {
                ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 13)
            })?;
            RuntimeOperationLookupV1::try_conflict(digest)
                .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 13))
        }
        3 => Ok(RuntimeOperationLookupV1::Unknown),
        4 => reason
            .map(RuntimeOperationLookupV1::indeterminate)
            .ok_or_else(|| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 11)),
        _ => unreachable!("lookup kind was range checked"),
    }
}

fn decode_durable_phase(value: u16) -> Result<RuntimeOperationDurablePhaseV1, ReferenceWireError> {
    match value {
        1 => Ok(RuntimeOperationDurablePhaseV1::PreparedNoEffects),
        2 => Ok(RuntimeOperationDurablePhaseV1::FirstActionIntent),
        3 => Ok(RuntimeOperationDurablePhaseV1::HeadCommittedRetiringOld),
        4 => Ok(RuntimeOperationDurablePhaseV1::Terminal),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            15,
        )),
    }
}

fn decode_optional_terminal_ref(
    presence: u8,
    bytes: [u8; 16],
    detail: u16,
) -> Result<Option<TerminalResultRef>, ReferenceWireError> {
    match presence {
        0 if all_zero(&bytes) => Ok(None),
        1 if !all_zero(&bytes) => Ok(Some(TerminalResultRef::from_bytes(bytes))),
        0 | 1 => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidPresence,
            detail,
        )),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidPresence,
            detail,
        )),
    }
}

fn decode_desired_head(
    kind: u16,
    revision: u64,
    target_slice_digest: Digest32,
    manifest_digest: Digest32,
) -> Result<RuntimeDesiredHeadV1, ReferenceWireError> {
    if !(RuntimeDesiredHeadKindV1::None as u16..=RuntimeDesiredHeadKindV1::EmptyDeactivate as u16)
        .contains(&kind)
    {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            18,
        ));
    }
    if revision == 0 && kind != RuntimeDesiredHeadKindV1::None as u16 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            19,
        ));
    }
    if digest_is_zero(&target_slice_digest) && kind != RuntimeDesiredHeadKindV1::None as u16 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            20,
        ));
    }
    if digest_is_zero(&manifest_digest) && kind != RuntimeDesiredHeadKindV1::None as u16 {
        return Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            21,
        ));
    }
    match kind {
        1 if revision != 0 => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            19,
        )),
        1 if !digest_is_zero(&target_slice_digest) => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            20,
        )),
        1 if !digest_is_zero(&manifest_digest) => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            21,
        )),
        1 => Ok(RuntimeDesiredHeadV1::None),
        2 => RuntimeDesiredHeadV1::try_one_source_loop(
            SourcePlanRevision::new(revision),
            target_slice_digest,
            manifest_digest,
        )
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 18)),
        3 => RuntimeDesiredHeadV1::try_empty_deactivate(
            SourcePlanRevision::new(revision),
            target_slice_digest,
            manifest_digest,
        )
        .map_err(|_| ReferenceWireError::at(ReferenceWireErrorCode::InvalidFieldValue, 18)),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            18,
        )),
    }
}

fn decode_live_state(value: u16) -> Result<RuntimeLiveStateV1, ReferenceWireError> {
    match value {
        1 => Ok(RuntimeLiveStateV1::NotReady),
        2 => Ok(RuntimeLiveStateV1::Recovering),
        3 => Ok(RuntimeLiveStateV1::LiveReady),
        4 => Ok(RuntimeLiveStateV1::Draining),
        5 => Ok(RuntimeLiveStateV1::RecoveryFailedNotReady),
        6 => Ok(RuntimeLiveStateV1::ExactZero),
        7 => Ok(RuntimeLiveStateV1::ValidatedOperationalQuarantine),
        8 => Ok(RuntimeLiveStateV1::Uncertain),
        _ => Err(ReferenceWireError::at(
            ReferenceWireErrorCode::InvalidFieldValue,
            23,
        )),
    }
}

/// Keeps the admitted internal enabler linked without promoting this module.
///
/// The crate root references this function as a const function pointer. Function
/// items are listed here solely so `dead_code` remains enforceable without a
/// lint waiver while the real S7-E/F call paths are still intentionally absent.
pub(crate) fn compile_time_anchor() {
    let _ = RuntimeBuildInstanceId::try_from_bytes;
    let _ = RuntimeBuildInstanceId::as_bytes;
    let _ = RuntimeStoreInstanceId::try_from_bytes;
    let _ = RuntimeStoreInstanceId::as_bytes;
    let _ = RuntimeTargetTriple::try_new;
    let _ = RuntimeTargetTriple::as_str;
    let _ = ReferenceFixtureEntryV1::new;
    let _ = ReferenceFixtureEntryV1::definition;
    let _ = ReferenceFixtureEntryV1::implementation;
    let _ = ReferenceFixtureEntryV1::export;
    let _ = ReferenceFixtureEntryV1::definition_digest;
    let _ = ReferenceFixtureEntryV1::fixture_artifact_digest;
    let _ = RuntimeBuildDescriptorV1::try_new;
    let _ = RuntimeBuildDescriptorV1::decode;
    let _ = RuntimeBuildDescriptorV1::build_instance_id;
    let _ = RuntimeBuildDescriptorV1::runtime_artifact_length;
    let _ = RuntimeBuildDescriptorV1::runtime_artifact_sha256;
    let _ = RuntimeBuildDescriptorV1::target_triple;
    let _ = RuntimeBuildDescriptorV1::compiled_reference_compatibility_digest;
    let _ = RuntimeBuildDescriptorV1::canonical_wire;
    let _ = RuntimeBuildDescriptorV1::descriptor_digest;
    let _ = RuntimeBuildIdentityV1::from_descriptor;
    let _ = RuntimeBuildIdentityV1::build_instance_id;
    let _ = RuntimeBuildIdentityV1::build_descriptor_digest;
    let _ = RuntimeBuildIdentityV1::runtime_artifact_sha256;
    let _ = RuntimeBuildIdentityV1::compiled_reference_compatibility_digest;
    let _ = RuntimeArtifactCompatibilityTargetRowV1::target;
    let _ = RuntimeArtifactCompatibilityTargetRowV1::build_identity;
    let _ = RuntimeArtifactCompatibilityTargetRowV1::fixture;
    let _ = RuntimeArtifactCompatibilityManifestV1::try_new;
    let _ = RuntimeArtifactCompatibilityManifestV1::decode;
    let _ = RuntimeArtifactCompatibilityManifestV1::row;
    let _ = RuntimeArtifactCompatibilityManifestV1::canonical_wire;
    let _ = RuntimeArtifactCompatibilityManifestV1::manifest_digest;
    let _ = RuntimeArtifactCompatibilityManifestProjectionV1::from_manifest;
    let _ = RuntimeArtifactCompatibilityManifestProjectionV1::decode;
    let _ = RuntimeArtifactCompatibilityManifestProjectionV1::manifest_digest;
    let _ = RuntimeArtifactCompatibilityManifestProjectionV1::row;
    let _ = RuntimeArtifactCompatibilityManifestProjectionV1::canonical_wire;
    let _ = ReferenceAssemblyProfileV1::new;
    let _ = ReferenceAssemblyProfileV1::mode;
    let _ = ReferenceAssemblyProfileV1::lifecycle_concurrency;
    let _ = ReferenceAssemblyProfileV1::mailbox_slots;
    let _ = ReferenceAssemblyProfileV1::dispatch_slots;
    let _ = ReferenceAssemblyProfileV1::background_task_slots;
    let _ = ReferenceLoopDomainSpecV1::try_new;
    let _ = ReferenceLoopDomainSpecV1::domain;
    let _ = ReferenceLoopDomainSpecV1::start_budget;
    let _ = ReferenceLoopDomainSpecV1::drain_budget;
    let _ = ReferenceLoopDomainSpecV1::cleanup_budget;
    let _ = ReferenceLoopSubjectSpecV1::try_new;
    let _ = ReferenceLoopSubjectSpecV1::instance;
    let _ = ReferenceLoopSubjectSpecV1::domain;
    let _ = ReferenceLoopSubjectSpecV1::fixture;
    let _ = ReferenceLoopSubjectSpecV1::config_digest;
    let _ = TargetExecutionPlanV4::try_one_source_loop;
    let _ = TargetExecutionPlanV4::try_empty_deactivate;
    let _ = TargetExecutionPlanV4::decode;
    let _ = TargetExecutionPlanV4::projection;
    let _ = TargetExecutionPlanV4::profile;
    let _ = TargetExecutionPlanV4::domain;
    let _ = TargetExecutionPlanV4::subject;
    let _ = TargetExecutionPlanV4::canonical_wire;
    let _ = TargetExecutionPlanV4::execution_digest;
    let _ = TargetPlanAssignmentsV5::try_new;
    let _ = TargetPlanAssignmentsV5::try_from_execution;
    let _ = TargetPlanAssignmentsV5::bindings;
    let _ = TargetPlanAssignmentsV5::execution;
    let _ = TargetPlanAssignmentsV5::assignment_digest;
    let _ = RuntimePlanSliceV5::try_new;
    let _ = RuntimePlanSliceV5::commitment;
    let _ = RuntimePlanSliceV5::assignments;
    let _ = RuntimeApplyEnvelopeV2Draft::try_new;
    let _ = RuntimeApplyEnvelopeV2Draft::signing_transcript;
    let _ = RuntimeApplyEnvelopeV2Draft::finalize;
    let _ = RuntimeApplyEnvelopeV2::try_new;
    let _ = RuntimeApplyEnvelopeV2::decode;
    let _ = RuntimeApplyEnvelopeV2::control_commitment;
    let _ = RuntimeApplyEnvelopeV2::temporal;
    let _ = RuntimeApplyEnvelopeV2::expected_runtime_store_instance_id;
    let _ = RuntimeApplyEnvelopeV2::authentication;
    let _ = RuntimeApplyEnvelopeV2::canonical_wire;
    let _ = RuntimeApplyEnvelopeV2::request_digest;
    let _ = RuntimeApplyEnvelopeV2::validate_expected_store;
    let _ = RuntimeApplyEnvelopeV2::signing_transcript;
    let _ = RuntimeApplyRequestV5::try_new;
    let _ = RuntimeApplyRequestV5::decode;
    let _ = RuntimeApplyRequestV5::envelope;
    let _ = RuntimeApplyRequestV5::slice;
    let _ = RuntimeApplyRequestV5::canonical_wire;
    let _ = RuntimeChannelBindingV1::try_new;
    let _ = RuntimeChannelBindingV1::target;
    let _ = RuntimeChannelBindingV1::runtime_peer;
    let _ = RuntimeChannelBindingV1::local_endpoint_identity_digest;
    let _ = RuntimeChannelBindingV1::peer_credentials_digest;
    let _ = RuntimeChannelBindingV1::binding_digest;
    let _ = RuntimeSnapshotSequence::try_new;
    let _ = RuntimeSnapshotSequence::value;
    let _ = RuntimeHostEpoch::try_new;
    let _ = RuntimeHostEpoch::value;
    let _ = RuntimeResponseAuthClaimV1::try_new;
    let _ = RuntimeResponseAuthClaimV1::runtime_peer;
    let _ = RuntimeResponseAuthClaimV1::channel_binding_digest;
    let _ = RuntimeResponseAuthClaimV1::key;
    let _ = RuntimeResponseAuthClaimV1::algorithm;
    let _ = RuntimeResponseAuthClaimV1::algorithm_version;
    let _ = RuntimeResponseAuthenticationV1::try_new;
    let _ = RuntimeResponseAuthenticationV1::claim;
    let _ = RuntimeResponseAuthenticationV1::signature;
    let _ = ControlReadSigningTranscriptV1::as_bytes;
    let _ = RuntimeBootstrapRequestDraftV1::try_new;
    let _ = RuntimeBootstrapRequestDraftV1::signing_transcript;
    let _ = RuntimeBootstrapRequestDraftV1::finalize;
    let _ = RuntimeBootstrapRequestV1::decode;
    let _ = RuntimeBootstrapRequestV1::request_id;
    let _ = RuntimeBootstrapRequestV1::target;
    let _ = RuntimeBootstrapRequestV1::source_scope;
    let _ = RuntimeBootstrapRequestV1::authentication;
    let _ = RuntimeBootstrapRequestV1::max_response_bytes;
    let _ = RuntimeBootstrapRequestV1::canonical_wire;
    let _ = RuntimeBootstrapRequestV1::request_digest;
    let _ = RuntimeBootstrapRequestV1::signing_transcript;
    let _ = RuntimeBootstrapServingIdentityV1::new;
    let _ = RuntimeBootstrapCompatibilityV1::try_new;
    let _ = RuntimeBootstrapFactsV1::try_new;
    let _ = RuntimeBootstrapFactsV1::serving_identity;
    let _ = RuntimeBootstrapResponseDraftV1::try_new;
    let _ = RuntimeBootstrapResponseDraftV1::signing_transcript;
    let _ = RuntimeBootstrapResponseDraftV1::finalize;
    let _ = RuntimeBootstrapResponseV1::decode;
    let _ = RuntimeBootstrapResponseV1::facts;
    let _ = RuntimeBootstrapResponseV1::authentication;
    let _ = RuntimeBootstrapResponseV1::canonical_wire;
    let _ = RuntimeBootstrapResponseV1::response_digest;
    let _ = RuntimeBootstrapResponseV1::signing_transcript;
    let _ = RuntimeBootstrapResponseV1::validate_against_request;
    let _ = RuntimeQuerySelectorV1::try_new;
    let _ = RuntimeQueryRequestDraftV1::try_new;
    let _ = RuntimeQueryRequestDraftV1::signing_transcript;
    let _ = RuntimeQueryRequestDraftV1::finalize;
    let _ = RuntimeQueryRequestV1::decode;
    let _ = RuntimeQueryRequestV1::query_id;
    let _ = RuntimeQueryRequestV1::target;
    let _ = RuntimeQueryRequestV1::expected_store_instance_id;
    let _ = RuntimeQueryRequestV1::requested_operation_id;
    let _ = RuntimeQueryRequestV1::expected_request_digest;
    let _ = RuntimeQueryRequestV1::authentication;
    let _ = RuntimeQueryRequestV1::max_response_bytes;
    let _ = RuntimeQueryRequestV1::canonical_wire;
    let _ = RuntimeQueryRequestV1::request_digest;
    let _ = RuntimeQueryRequestV1::validate_expected_store;
    let _ = RuntimeQueryRequestV1::signing_transcript;
    let _ = RuntimeOperationLookupV1::try_known;
    let _ = RuntimeOperationLookupV1::try_conflict;
    let _ = RuntimeOperationLookupV1::indeterminate;
    let _ = RuntimeDesiredHeadV1::try_one_source_loop;
    let _ = RuntimeDesiredHeadV1::try_empty_deactivate;
    let _ = RuntimeDesiredStateV1::try_new;
    let _ = RuntimeLiveFactsV1::try_new;
    let _ = RuntimeQueryOperationStateV1::try_new;
    let _ = RuntimeQueryFactsV1::try_new;
    let _ = RuntimeQueryResponseDraftV1::try_new;
    let _ = RuntimeQueryResponseDraftV1::signing_transcript;
    let _ = RuntimeQueryResponseDraftV1::finalize;
    let _ = RuntimeQueryResponseV1::decode;
    let _ = RuntimeQueryResponseV1::facts;
    let _ = RuntimeQueryResponseV1::authentication;
    let _ = RuntimeQueryResponseV1::canonical_wire;
    let _ = RuntimeQueryResponseV1::response_digest;
    let _ = RuntimeQueryResponseV1::signing_transcript;
    let _ = RuntimeQueryResponseV1::validate_against_request;
    let _ = ApplyRequestSigningTranscriptV2::as_bytes;
    let _ = ReferenceWireError::code;
    let _ = ReferenceWireError::detail;

    let _ = [
        ReferenceWireErrorCode::FrameTooLarge,
        ReferenceWireErrorCode::Truncated,
        ReferenceWireErrorCode::InvalidMagic,
        ReferenceWireErrorCode::UnsupportedVersion,
        ReferenceWireErrorCode::UnknownField,
        ReferenceWireErrorCode::DuplicateField,
        ReferenceWireErrorCode::OutOfOrderField,
        ReferenceWireErrorCode::MissingField,
        ReferenceWireErrorCode::InvalidFieldLength,
        ReferenceWireErrorCode::InvalidFieldValue,
        ReferenceWireErrorCode::NonCanonicalFrame,
        ReferenceWireErrorCode::DigestMismatch,
        ReferenceWireErrorCode::CrossReferenceMismatch,
        ReferenceWireErrorCode::UnsupportedShape,
        ReferenceWireErrorCode::BindingNotAllowed,
        ReferenceWireErrorCode::RuntimeStoreMismatch,
        ReferenceWireErrorCode::TargetMismatch,
        ReferenceWireErrorCode::FixtureMismatch,
        ReferenceWireErrorCode::ResponseBoundExceeded,
        ReferenceWireErrorCode::UnknownReason,
        ReferenceWireErrorCode::TrailingBytes,
        ReferenceWireErrorCode::InvalidSignatureField,
        ReferenceWireErrorCode::InvalidPresence,
        ReferenceWireErrorCode::ArtifactMismatch,
        ReferenceWireErrorCode::CompatibilityMismatch,
    ];
    let _ = [
        ReferenceContractError::InvalidBuildInstanceId,
        ReferenceContractError::InvalidRuntimeStoreInstanceId,
        ReferenceContractError::InvalidArtifactLength,
        ReferenceContractError::InvalidArtifactDigest,
        ReferenceContractError::InvalidTargetTriple,
        ReferenceContractError::InvalidCompatibility,
        ReferenceContractError::InvalidLifecycleBudget,
        ReferenceContractError::InvalidProfile,
        ReferenceContractError::InvalidShape,
        ReferenceContractError::DomainMismatch,
        ReferenceContractError::FixtureMismatch,
        ReferenceContractError::ConfigMismatch,
        ReferenceContractError::TargetMismatch,
        ReferenceContractError::BindingNotAllowed,
        ReferenceContractError::EnvelopeInvalid,
        ReferenceContractError::RequestFrameTooLarge,
        ReferenceContractError::CommitmentMismatch,
        ReferenceContractError::InvalidBound,
        ReferenceContractError::InvalidReason,
    ];
    let _ = [
        OperationalReasonV1::Recovering,
        OperationalReasonV1::ActiveCompatibilityMismatch,
        OperationalReasonV1::RecoveryFailed,
        OperationalReasonV1::OwnershipUncertain,
        OperationalReasonV1::HistoryUnavailable,
        OperationalReasonV1::ResourceCensusUncertain,
        OperationalReasonV1::RuntimeBusy,
        OperationalReasonV1::OwnershipTransferRequired,
    ];
    let _ = [
        RuntimeBootstrapStateV1::ReadyForApply,
        RuntimeBootstrapStateV1::NotReadyRecovering,
        RuntimeBootstrapStateV1::ValidatedOperationalQuarantine,
        RuntimeBootstrapStateV1::RecoveryFailedNotReady,
        RuntimeBootstrapStateV1::NotReadyBusy,
    ];
    let _ = [
        RuntimeOwnerStateV1::Operational,
        RuntimeOwnerStateV1::ApplyDisabled,
        RuntimeOwnerStateV1::OwnershipUncertain,
    ];
    let _ = [
        RuntimeOperationDurablePhaseV1::PreparedNoEffects,
        RuntimeOperationDurablePhaseV1::FirstActionIntent,
        RuntimeOperationDurablePhaseV1::HeadCommittedRetiringOld,
        RuntimeOperationDurablePhaseV1::Terminal,
    ];
    let _ = [
        RuntimeDesiredHeadKindV1::None,
        RuntimeDesiredHeadKindV1::OneSourceLoop,
        RuntimeDesiredHeadKindV1::EmptyDeactivate,
    ];
    let _ = [
        RuntimeLiveStateV1::NotReady,
        RuntimeLiveStateV1::Recovering,
        RuntimeLiveStateV1::LiveReady,
        RuntimeLiveStateV1::Draining,
        RuntimeLiveStateV1::RecoveryFailedNotReady,
        RuntimeLiveStateV1::ExactZero,
        RuntimeLiveStateV1::ValidatedOperationalQuarantine,
        RuntimeLiveStateV1::Uncertain,
    ];
    let _ = [
        RUNTIME_BUILD_DESCRIPTOR_VERSION,
        RUNTIME_ARTIFACT_COMPATIBILITY_MANIFEST_VERSION,
        RUNTIME_ARTIFACT_COMPATIBILITY_PROJECTION_VERSION,
        REFERENCE_ASSEMBLY_PROFILE_VERSION,
        TARGET_EXECUTION_PLAN_V4_VERSION,
        RUNTIME_APPLY_REQUEST_V5_VERSION,
        RUNTIME_APPLY_ENVELOPE_V2_VERSION,
        APPLY_REQUEST_SIGNING_TRANSCRIPT_V2_VERSION,
        LOCAL_CONTROL_CHANNEL_BINDING_VERSION,
        RUNTIME_BOOTSTRAP_PROTOCOL_VERSION,
        RUNTIME_QUERY_PROTOCOL_VERSION,
        CONTROL_READ_SIGNING_TRANSCRIPT_VERSION,
    ];
    let _ = [
        MAX_TARGET_TRIPLE_BYTES,
        MAX_RUNTIME_ARTIFACT_BYTES as usize,
        MAX_RUNTIME_BUILD_DESCRIPTOR_BYTES,
        MAX_TARGET_EXECUTION_PLAN_V4_BYTES,
        MAX_RUNTIME_APPLY_REQUEST_V5_BYTES,
        MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES,
        MAX_RUNTIME_BOOTSTRAP_REQUEST_BYTES,
        MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES,
        MAX_RUNTIME_QUERY_REQUEST_BYTES,
        MAX_RUNTIME_QUERY_RESPONSE_BYTES,
    ];
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

    use crate::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
        RuntimeApplyControl, RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef,
        TenureProofAlgorithm, TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };
    use crate::assignment::{InstanceRef, RequestWireErrorCode, RuntimeApplyRequest};
    use crate::execution::{
        CardDefinitionRef, CardImplementationRef, DomainRef, ExecutionWireErrorCode,
        RequestV2WireErrorCode, RuntimeApplyRequestV2, TargetExecutionPlan,
    };
    use crate::process_execution::{
        ProcessExecutionWireErrorCode, RequestV4WireErrorCode, RuntimeApplyRequestV4,
        TargetExecutionPlanV3,
    };
    use crate::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef,
    };
    use crate::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use crate::thread_execution::{
        RequestV3WireErrorCode, RuntimeApplyRequestV3, TargetExecutionPlanV2,
        ThreadExecutionWireErrorCode,
    };
    use crate::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim};

    use super::*;

    const S7_REFERENCE_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s7_reference_successor_v1.json");

    fn skip_json_whitespace(bytes: &[u8], cursor: &mut usize) {
        while bytes
            .get(*cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            *cursor += 1;
        }
    }

    fn json_string_end(bytes: &[u8], start: usize) -> usize {
        assert_eq!(bytes.get(start), Some(&b'"'), "expected JSON string");
        let mut cursor = start + 1;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'"' => return cursor + 1,
                b'\\' => {
                    cursor += 1;
                    assert!(cursor < bytes.len(), "unterminated JSON escape");
                    cursor += 1;
                }
                0..=0x1f => panic!("unescaped JSON control byte"),
                _ => cursor += 1,
            }
        }
        panic!("unterminated JSON string")
    }

    fn json_value_end(bytes: &[u8], start: usize) -> usize {
        assert!(start < bytes.len(), "missing JSON value");
        if bytes[start] == b'"' {
            return json_string_end(bytes, start);
        }
        if matches!(bytes[start], b'{' | b'[') {
            let mut expected_closers = vec![if bytes[start] == b'{' { b'}' } else { b']' }];
            let mut cursor = start + 1;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'"' => cursor = json_string_end(bytes, cursor),
                    b'{' => {
                        expected_closers.push(b'}');
                        cursor += 1;
                    }
                    b'[' => {
                        expected_closers.push(b']');
                        cursor += 1;
                    }
                    b'}' | b']' => {
                        assert_eq!(
                            expected_closers.pop(),
                            Some(bytes[cursor]),
                            "mismatched JSON delimiter"
                        );
                        cursor += 1;
                        if expected_closers.is_empty() {
                            return cursor;
                        }
                    }
                    _ => cursor += 1,
                }
            }
            panic!("unterminated JSON container");
        }

        let mut cursor = start;
        while cursor < bytes.len() && !matches!(bytes[cursor], b',' | b'}' | b']') {
            cursor += 1;
        }
        let mut trimmed = cursor;
        while trimmed > start && bytes[trimmed - 1].is_ascii_whitespace() {
            trimmed -= 1;
        }
        assert!(trimmed > start, "empty JSON primitive");
        trimmed
    }

    fn fixture_value<'a>(object: &'a str, key: &str) -> &'a str {
        let bytes = object.as_bytes();
        let mut cursor = 0;
        skip_json_whitespace(bytes, &mut cursor);
        assert_eq!(
            bytes.get(cursor),
            Some(&b'{'),
            "fixture scope is not an object"
        );
        cursor += 1;
        let mut found = None;

        loop {
            skip_json_whitespace(bytes, &mut cursor);
            assert!(cursor < bytes.len(), "unterminated fixture object");
            if bytes[cursor] == b'}' {
                cursor += 1;
                skip_json_whitespace(bytes, &mut cursor);
                assert_eq!(cursor, bytes.len(), "trailing bytes after fixture object");
                break;
            }

            let key_end = json_string_end(bytes, cursor);
            let raw_key = &bytes[cursor + 1..key_end - 1];
            assert!(
                !raw_key.contains(&b'\\'),
                "escaped fixture object keys are not accepted"
            );
            cursor = key_end;
            skip_json_whitespace(bytes, &mut cursor);
            assert_eq!(bytes.get(cursor), Some(&b':'), "missing fixture key colon");
            cursor += 1;
            skip_json_whitespace(bytes, &mut cursor);
            let value_start = cursor;
            let value_end = json_value_end(bytes, value_start);

            if raw_key == key.as_bytes() {
                assert!(found.is_none(), "duplicate fixture key {key}");
                found = Some(&object[value_start..value_end]);
            }

            cursor = value_end;
            skip_json_whitespace(bytes, &mut cursor);
            match bytes.get(cursor) {
                Some(b',') => {
                    cursor += 1;
                    let mut next = cursor;
                    skip_json_whitespace(bytes, &mut next);
                    assert_ne!(
                        bytes.get(next),
                        Some(&b'}'),
                        "trailing fixture object comma"
                    );
                }
                Some(b'}') => {}
                _ => panic!("fixture object member has no delimiter"),
            }
        }

        found.unwrap_or_else(|| panic!("missing fixture key {key}"))
    }

    fn fixture_object<'a>(object: &'a str, key: &str) -> &'a str {
        let value = fixture_value(object, key);
        assert_eq!(
            value.as_bytes().first(),
            Some(&b'{'),
            "fixture key {key} is not an object"
        );
        assert_eq!(
            json_value_end(value.as_bytes(), 0),
            value.len(),
            "fixture object {key} is not canonical"
        );
        value
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("fixture contains non-hex byte"),
        }
    }

    fn fixture_hex(object: &str, key: &str) -> Vec<u8> {
        let value = fixture_value(object, key);
        let bytes = value.as_bytes();
        assert!(
            bytes.len() >= 2 && bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"'),
            "fixture key {key} is not a string"
        );
        let hex = &bytes[1..bytes.len() - 1];
        assert!(
            !hex.contains(&b'\\') && hex.len().is_multiple_of(2),
            "fixture key {key} is not strict even-width hex"
        );
        hex.chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn fixture_hex_array<const N: usize>(object: &str, key: &str) -> [u8; N] {
        fixture_hex(object, key)
            .try_into()
            .unwrap_or_else(|value: Vec<u8>| {
                panic!(
                    "fixture key {key} decoded to {} bytes instead of {N}",
                    value.len()
                )
            })
    }

    fn fixture_digest(object: &str, key: &str) -> Digest32 {
        Digest32::from_bytes(fixture_hex_array(object, key))
    }

    fn fixture_string<'a>(object: &'a str, key: &str) -> &'a str {
        let value = fixture_value(object, key);
        let bytes = value.as_bytes();
        assert!(
            bytes.len() >= 2 && bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"'),
            "fixture key {key} is not a string"
        );
        assert!(
            !bytes[1..bytes.len() - 1].contains(&b'\\'),
            "fixture key {key} contains an unsupported escape"
        );
        &value[1..value.len() - 1]
    }

    fn fixture_u16(object: &str, key: &str) -> u16 {
        fixture_value(object, key)
            .parse()
            .unwrap_or_else(|error| panic!("fixture key {key} is not a u16: {error}"))
    }

    fn fixture_optional_u16(object: &str, key: &str) -> Option<u16> {
        let value = fixture_value(object, key);
        if value == "null" {
            None
        } else {
            Some(
                value
                    .parse()
                    .unwrap_or_else(|error| panic!("fixture key {key} is not a u16: {error}")),
            )
        }
    }

    fn decode_shared_precedence_vector(
        decoder: &str,
        frame: &[u8],
    ) -> Result<(), ReferenceWireError> {
        match decoder {
            "descriptor" => RuntimeBuildDescriptorV1::decode(frame).map(|_| ()),
            "identity" => {
                let mut cursor = FixedCursor::new(frame);
                decode_build_identity(&mut cursor)?;
                if cursor.is_empty() {
                    Ok(())
                } else {
                    Err(ReferenceWireError::new(
                        ReferenceWireErrorCode::TrailingBytes,
                    ))
                }
            }
            "manifest" => RuntimeArtifactCompatibilityManifestV1::decode(frame).map(|_| ()),
            "projection" => {
                RuntimeArtifactCompatibilityManifestProjectionV1::decode(frame).map(|_| ())
            }
            "pxte" => TargetExecutionPlanV4::decode(frame).map(|_| ()),
            "envelope" => RuntimeApplyEnvelopeV2::decode(frame).map(|_| ()),
            "pxar" => RuntimeApplyRequestV5::decode(frame).map(|_| ()),
            "bootstrap_request" => RuntimeBootstrapRequestV1::decode(frame).map(|_| ()),
            "bootstrap_response" => RuntimeBootstrapResponseV1::decode(frame).map(|_| ()),
            "query_request" => RuntimeQueryRequestV1::decode(frame).map(|_| ()),
            "query_response" => RuntimeQueryResponseV1::decode(frame).map(|_| ()),
            _ => panic!("unknown shared precedence decoder {decoder}"),
        }
    }

    fn overwrite_tlv_value(frame: &mut [u8], tag: u16, replacement: &[u8]) {
        let mut cursor = if frame.starts_with(APPLY_ENVELOPE_MAGIC) {
            APPLY_ENVELOPE_MAGIC.len() + 4
        } else {
            8
        };
        assert!(frame.len() >= cursor, "TLV fixture has no complete header");
        while cursor < frame.len() {
            let header_end = cursor
                .checked_add(TLV_HEADER_BYTES)
                .expect("TLV header offset overflow");
            assert!(header_end <= frame.len(), "truncated TLV fixture header");
            let current_tag = read_u16(&frame[cursor..cursor + 2]);
            let value_length = read_u32(&frame[cursor + 2..header_end]) as usize;
            let value_end = header_end
                .checked_add(value_length)
                .expect("TLV value offset overflow");
            assert!(value_end <= frame.len(), "truncated TLV fixture value");
            if current_tag == tag {
                assert_eq!(
                    value_length,
                    replacement.len(),
                    "replacement width mismatch"
                );
                frame[header_end..value_end].copy_from_slice(replacement);
                return;
            }
            cursor = value_end;
        }
        panic!("missing TLV fixture tag {tag}");
    }

    fn mutated_tlv(frame: &[u8], tag: u16, replacement: &[u8]) -> Vec<u8> {
        let mut mutated = frame.to_vec();
        overwrite_tlv_value(&mut mutated, tag, replacement);
        mutated
    }

    fn tlv_value(frame: &[u8], tag: u16) -> &[u8] {
        let mut cursor = if frame.starts_with(APPLY_ENVELOPE_MAGIC) {
            APPLY_ENVELOPE_MAGIC.len() + 4
        } else {
            8
        };
        assert!(frame.len() >= cursor, "TLV fixture has no complete header");
        while cursor < frame.len() {
            let header_end = cursor
                .checked_add(TLV_HEADER_BYTES)
                .expect("TLV header offset overflow");
            assert!(header_end <= frame.len(), "truncated TLV fixture header");
            let current_tag = read_u16(&frame[cursor..cursor + 2]);
            let value_length = read_u32(&frame[cursor + 2..header_end]) as usize;
            let value_end = header_end
                .checked_add(value_length)
                .expect("TLV value offset overflow");
            assert!(value_end <= frame.len(), "truncated TLV fixture value");
            if current_tag == tag {
                return &frame[header_end..value_end];
            }
            cursor = value_end;
        }
        panic!("missing TLV fixture tag {tag}");
    }

    fn assert_wire_error<T>(
        result: Result<T, ReferenceWireError>,
        code: ReferenceWireErrorCode,
        detail: Option<u16>,
    ) {
        let Some(error) = result.err() else {
            panic!("mutated frame unexpectedly decoded");
        };
        assert_eq!(error.code(), code);
        assert_eq!(error.detail(), detail);
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut value = *state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        *state = value;
        value
    }

    fn assert_total_strict_decode(
        decoder: &impl Fn(&[u8]) -> Result<Vec<u8>, ReferenceWireError>,
        frame: &[u8],
        maximum: usize,
    ) {
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decoder(frame)))
            .unwrap_or_else(|_| panic!("strict decoder panicked for {} bytes", frame.len()));
        match first {
            Ok(canonical) => {
                assert!(canonical.len() <= maximum);
                assert_eq!(canonical, frame);
                let second = decoder(&canonical)
                    .unwrap_or_else(|error| panic!("canonical re-decode failed: {error}"));
                assert_eq!(second, canonical);
            }
            Err(error) => {
                assert!((1..=25).contains(&(error.code() as u16)));
                let repeated = decoder(frame)
                    .err()
                    .unwrap_or_else(|| panic!("malformed frame decoded only on retry"));
                assert_eq!(repeated, error);
            }
        }
    }

    fn exercise_strict_decoder_property(
        decoder: impl Fn(&[u8]) -> Result<Vec<u8>, ReferenceWireError>,
        golden: &[u8],
        maximum: usize,
        declared_length_offset: Option<usize>,
        mut seed: u64,
    ) {
        assert!(!golden.is_empty() && golden.len() <= maximum);
        assert_total_strict_decode(&decoder, golden, maximum);

        let mut appended = golden.to_vec();
        appended.push(0xa5);
        assert_total_strict_decode(&decoder, &appended, maximum);

        let oversize = vec![0x5a; maximum + 1];
        assert!(decoder(&oversize).is_err());
        assert_total_strict_decode(&decoder, &oversize, maximum);

        if let Some(offset) = declared_length_offset {
            let end = offset
                .checked_add(4)
                .expect("declared length offset overflow");
            assert!(end <= golden.len());
            let mut length_bomb = golden.to_vec();
            length_bomb[offset..end].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(decoder(&length_bomb).is_err());
            assert_total_strict_decode(&decoder, &length_bomb, maximum);
        }

        for cut in 0..golden.len().min(64) {
            assert_total_strict_decode(&decoder, &golden[..cut], maximum);
        }
        for _ in 0..192 {
            let mut mutated = golden.to_vec();
            let index = (xorshift64(&mut seed) as usize) % mutated.len();
            let delta = (xorshift64(&mut seed) as u8) | 1;
            mutated[index] ^= delta;
            assert_total_strict_decode(&decoder, &mutated, maximum);
        }
        for _ in 0..128 {
            let length = (xorshift64(&mut seed) as usize) % (maximum + 2);
            let mut random = vec![0; length];
            for byte in &mut random {
                *byte = xorshift64(&mut seed) as u8;
            }
            assert_total_strict_decode(&decoder, &random, maximum);
        }
    }

    fn assert_control_transcript(
        transcript: &ControlReadSigningTranscriptV1,
        expected_domain: &[u8],
        expected_field_count: u16,
    ) {
        let bytes = transcript.as_bytes();
        assert!(bytes.starts_with(SIGNING_TRANSCRIPT_MAGIC));
        let base = SIGNING_TRANSCRIPT_MAGIC.len();
        let domain_start = base
            .checked_add(4)
            .expect("control transcript header overflow");
        assert!(
            bytes.len() >= domain_start,
            "control transcript header is truncated"
        );
        assert_eq!(
            read_u16(&bytes[base..base + 2]),
            CONTROL_READ_SIGNING_TRANSCRIPT_VERSION
        );
        let domain_length = usize::from(read_u16(&bytes[base + 2..domain_start]));
        let domain_end = domain_start
            .checked_add(domain_length)
            .expect("control transcript domain overflow");
        let count_end = domain_end
            .checked_add(2)
            .expect("control transcript count overflow");
        assert!(
            bytes.len() >= count_end,
            "control transcript domain is truncated"
        );
        assert_eq!(&bytes[domain_start..domain_end], expected_domain);
        assert_eq!(
            read_u16(&bytes[domain_end..count_end]),
            expected_field_count
        );
    }

    struct ReleaseFixture {
        fixture: ReferenceFixtureEntryV1,
        descriptor: RuntimeBuildDescriptorV1,
        manifest: RuntimeArtifactCompatibilityManifestV1,
        projection: RuntimeArtifactCompatibilityManifestProjectionV1,
    }

    fn release_fixture() -> ReleaseFixture {
        let fixture = ReferenceFixtureEntryV1::new(
            CardDefinitionRef::from_bytes([0xa1; 16]),
            CardImplementationRef::from_bytes([0xa2; 16]),
            FixtureExportRef::from_bytes([0xa3; 16]),
            Digest32::from_bytes([0xa4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        );
        let descriptor = RuntimeBuildDescriptorV1::try_new(
            valid_build_id(0x11),
            1_048_576,
            Digest32::from_bytes([0x22; 32]),
            RuntimeTargetTriple::try_new("aarch64-unknown-linux-gnu")
                .unwrap_or_else(|error| panic!("target fixture failed: {error}")),
            fixture,
        )
        .unwrap_or_else(|error| panic!("descriptor fixture failed: {error}"));
        let manifest = RuntimeArtifactCompatibilityManifestV1::try_new(
            RuntimeHostId::from_bytes([0x05; 16]),
            &descriptor,
            fixture,
        )
        .unwrap_or_else(|error| panic!("manifest fixture failed: {error}"));
        let projection = RuntimeArtifactCompatibilityManifestProjectionV1::from_manifest(&manifest);
        ReleaseFixture {
            fixture,
            descriptor,
            manifest,
            projection,
        }
    }

    fn valid_build_id(byte: u8) -> RuntimeBuildInstanceId {
        RuntimeBuildInstanceId::try_from_bytes([byte; 32])
            .unwrap_or_else(|error| panic!("build id fixture failed: {error}"))
    }

    fn valid_store(byte: u8) -> RuntimeStoreInstanceId {
        RuntimeStoreInstanceId::try_from_bytes([byte; 32])
            .unwrap_or_else(|error| panic!("store fixture failed: {error}"))
    }

    fn generation(value: u64) -> ClockGeneration {
        ClockGeneration::try_new(value)
            .unwrap_or_else(|error| panic!("clock generation fixture failed: {error}"))
    }

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}")
                .unwrap_or_else(|error| panic!("hex formatting failed: {error}"));
        }
        encoded
    }

    fn assert_digest(digest: Digest32, expected: &str) {
        assert_eq!(hex(digest.as_bytes()), expected);
    }

    fn one_source_execution(release: &ReleaseFixture) -> TargetExecutionPlanV4 {
        let domain = ReferenceLoopDomainSpecV1::try_new(
            DomainRef::from_bytes([0xb1; 16]),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(2_000_000_000),
            BoundedDuration::from_nanos(3_000_000_000),
        )
        .unwrap_or_else(|error| panic!("domain fixture failed: {error}"));
        let subject = ReferenceLoopSubjectSpecV1::try_new(
            InstanceRef::from_bytes([0xb2; 16]),
            domain.domain(),
            release.fixture,
            reference_empty_config_digest()
                .unwrap_or_else(|error| panic!("empty config digest failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("subject fixture failed: {error}"));
        TargetExecutionPlanV4::try_one_source_loop(release.projection.clone(), domain, subject)
            .unwrap_or_else(|error| panic!("PXTE v4 fixture failed: {error}"))
    }

    fn control_auth_claim(nonce: &[u8]) -> ApplyRequestAuthClaim {
        ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x09; 16]),
            ApplyAuthKeyRef::from_bytes([0x0c; 16]),
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("auth algorithm failed: {error}")),
            1,
            nonce,
        )
        .unwrap_or_else(|error| panic!("auth claim failed: {error}"))
    }

    fn apply_request_fixture() -> (RuntimeApplyRequestV5, RuntimeStoreInstanceId) {
        apply_request_fixture_for_mode(ReferenceAssemblyModeV1::OneSourceLoop)
    }

    fn apply_request_fixture_for_mode(
        mode: ReferenceAssemblyModeV1,
    ) -> (RuntimeApplyRequestV5, RuntimeStoreInstanceId) {
        let release = release_fixture();
        let execution = match mode {
            ReferenceAssemblyModeV1::OneSourceLoop => one_source_execution(&release),
            ReferenceAssemblyModeV1::EmptyDeactivate => {
                TargetExecutionPlanV4::try_empty_deactivate(release.projection.clone())
                    .unwrap_or_else(|error| panic!("empty execution fixture failed: {error}"))
            }
        };
        let assignments = TargetPlanAssignmentsV5::try_from_execution(execution)
            .unwrap_or_else(|error| panic!("assignment fixture failed: {error}"));
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([0x01; 16]),
            SourcePlanRef::from_bytes([0x02; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([0x04; 32])),
        );
        let header = RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes([0x05; 16]),
            provenance,
            assignments.assignment_digest(),
        );
        let slice_commitment = RuntimeSliceCommitment::try_new(header)
            .unwrap_or_else(|error| panic!("slice commitment failed: {error}"));
        let proof_authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0x07; 16]),
            TenureKeyRef::from_bytes([0x08; 16]),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("tenure algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("tenure authority failed: {error}"));
        let proof_claim = WriterTenureClaim::try_new(
            provenance.source_scope(),
            PlanWriterRef::from_bytes([0x09; 16]),
            PlanWriterEpoch::new(1),
            PlanWriterEpoch::new(0),
        )
        .unwrap_or_else(|error| panic!("tenure claim failed: {error}"));
        let proof = WriterTenureProof::try_new(
            proof_authority,
            proof_claim,
            b"test-only-tenure-nonce",
            &[0x77; 64],
        )
        .unwrap_or_else(|error| panic!("tenure proof failed: {error}"));
        let writer = PlanWriterContext::try_new(
            PlanWriterRef::from_bytes([0x09; 16]),
            PlanWriterEpoch::new(1),
            proof,
        )
        .unwrap_or_else(|error| panic!("writer context failed: {error}"));
        let control = RuntimeApplyControl::new(
            writer,
            ExpectedActive::None,
            ApplyOperationId::from_bytes([0x0d; 16]),
        );
        let commitment = RuntimeApplyControlCommitment::try_new(slice_commitment, control)
            .unwrap_or_else(|error| panic!("control commitment failed: {error}"));
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([0x0e; 16]),
            ClockDomainRef::from_bytes([0x0a; 16]),
            generation(3),
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(60),
        )
        .unwrap_or_else(|error| panic!("temporal fixture failed: {error}"));
        let store = valid_store(0x44);
        let envelope = RuntimeApplyEnvelopeV2Draft::try_new(
            commitment,
            temporal,
            store,
            control_auth_claim(b"test-only-request-nonce-one"),
        )
        .and_then(|draft| draft.finalize(&[0x88; 64]))
        .unwrap_or_else(|error| panic!("envelope fixture failed: {error}"));
        let slice = RuntimePlanSliceV5::try_new(slice_commitment, assignments)
            .unwrap_or_else(|error| panic!("v5 slice failed: {error}"));
        let request = RuntimeApplyRequestV5::try_new(envelope, slice)
            .unwrap_or_else(|error| panic!("v5 request failed: {error}"));
        (request, store)
    }

    fn apply_terminal_channel(request: &RuntimeApplyRequestV5) -> RuntimeChannelBindingV1 {
        RuntimeChannelBindingV1::try_new(
            request.slice().commitment().header().target(),
            PrincipalRef::from_bytes([0xd1; 16]),
            Digest32::from_bytes([0xd2; 32]),
            Digest32::from_bytes([0xd3; 32]),
        )
        .unwrap_or_else(|error| panic!("terminal channel fixture failed: {error}"))
    }

    fn apply_terminal_auth_claim(channel: RuntimeChannelBindingV1) -> RuntimeResponseAuthClaimV1 {
        RuntimeResponseAuthClaimV1::try_new(
            channel.runtime_peer(),
            channel.binding_digest(),
            ApplyAuthKeyRef::from_bytes([0xd4; 16]),
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("terminal algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("terminal auth claim failed: {error}"))
    }

    fn apply_terminal_facts(
        request: &RuntimeApplyRequestV5,
        outcome: RuntimeApplyTerminalOutcomeV1,
        lifecycle_effect: RuntimeApplyTerminalLifecycleEffectV1,
        head: RuntimeApplyTerminalHeadV1,
    ) -> Result<RuntimeApplyTerminalFactsV1, ReferenceContractError> {
        RuntimeApplyTerminalFactsV1::try_new(
            request,
            outcome,
            lifecycle_effect,
            head,
            Digest32::from_bytes([0xd5; 32]),
            Digest32::from_bytes([0xd6; 32]),
            RuntimeHostEpoch::try_new(7).expect("terminal host epoch"),
            RuntimeSnapshotSequence::try_new(8).expect("terminal snapshot sequence"),
            generation(3),
            900,
        )
    }

    const APPLY_TERMINAL_OUTCOMES: [RuntimeApplyTerminalOutcomeV1; 12] = [
        RuntimeApplyTerminalOutcomeV1::OneSourceLoopActive,
        RuntimeApplyTerminalOutcomeV1::EmptyDeactivateExactZero,
        RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects,
        RuntimeApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects,
        RuntimeApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero,
        RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero,
        RuntimeApplyTerminalOutcomeV1::StopFailedButExactZero,
        RuntimeApplyTerminalOutcomeV1::TimedOutButExactZero,
        RuntimeApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects,
        RuntimeApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero,
        RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero,
        RuntimeApplyTerminalOutcomeV1::InterruptedButNowExactZero,
    ];

    const APPLY_TERMINAL_LIFECYCLES: [RuntimeApplyTerminalLifecycleEffectV1; 2] = [
        RuntimeApplyTerminalLifecycleEffectV1::ProvenNotStarted,
        RuntimeApplyTerminalLifecycleEffectV1::MayHaveStarted,
    ];

    fn assert_apply_fixture(expected: &str, mode_key: &str) {
        let mode = fixture_object(expected, mode_key);
        let execution_bytes = fixture_hex(mode, "pxte_v4_body_hex");
        let execution = TargetExecutionPlanV4::decode(&execution_bytes)
            .unwrap_or_else(|error| panic!("{mode_key} PXTE decode failed: {error}"));
        assert_eq!(execution.canonical_wire(), execution_bytes);
        assert_eq!(
            execution.execution_digest(),
            fixture_digest(mode, "pxte_v4_digest_hex")
        );
        let assignments = TargetPlanAssignmentsV5::try_from_execution(execution.clone())
            .unwrap_or_else(|error| panic!("{mode_key} assignments failed: {error}"));
        assert_eq!(
            *assignments.assignment_digest().value(),
            fixture_digest(mode, "composite_v5_digest_hex")
        );

        let envelope_bytes = fixture_hex(mode, "envelope_v2_hex");
        let envelope = RuntimeApplyEnvelopeV2::decode(&envelope_bytes)
            .unwrap_or_else(|error| panic!("{mode_key} envelope decode failed: {error}"));
        assert_eq!(envelope.canonical_wire(), envelope_bytes);
        assert_eq!(
            envelope.request_digest(),
            fixture_digest(mode, "request_digest_hex")
        );
        let semantic = fixture_object(S7_REFERENCE_FIXTURE_JSON, "semantic");
        let expected_store = RuntimeStoreInstanceId::try_from_bytes(fixture_hex_array(
            semantic,
            "expected_runtime_store_instance_id_hex",
        ))
        .unwrap_or_else(|error| panic!("fixture store failed: {error}"));
        assert_eq!(envelope.validate_expected_store(expected_store), Ok(()));
        assert_eq!(
            envelope
                .validate_expected_store(valid_store(0x45))
                .map_err(ReferenceWireError::code),
            Err(ReferenceWireErrorCode::RuntimeStoreMismatch)
        );
        assert_eq!(
            envelope
                .signing_transcript()
                .unwrap_or_else(|error| panic!("{mode_key} envelope transcript failed: {error}"))
                .as_bytes(),
            fixture_hex(mode, "signing_transcript_hex")
        );

        let outer_bytes = fixture_hex(mode, "outer_v5_hex");
        let outer = RuntimeApplyRequestV5::decode(&outer_bytes)
            .unwrap_or_else(|error| panic!("{mode_key} PXAR decode failed: {error}"));
        assert_eq!(outer.canonical_wire(), outer_bytes);
        assert_eq!(outer.envelope(), &envelope);
        assert_eq!(outer.slice().assignments().execution(), &execution);
        assert_eq!(
            *outer.slice().commitment().target_slice_digest().value(),
            fixture_digest(mode, "target_slice_digest_hex")
        );
    }

    #[test]
    fn rust_strict_decoders_consume_the_independent_python_fixture() {
        let expected = fixture_object(S7_REFERENCE_FIXTURE_JSON, "expected");

        let descriptor_bytes = fixture_hex(expected, "descriptor_hex");
        let descriptor = RuntimeBuildDescriptorV1::decode(&descriptor_bytes)
            .unwrap_or_else(|error| panic!("descriptor fixture decode failed: {error}"));
        assert_eq!(descriptor.canonical_wire(), descriptor_bytes);
        assert_eq!(
            descriptor.descriptor_digest(),
            fixture_digest(expected, "descriptor_digest_hex")
        );
        let build_identity = RuntimeBuildIdentityV1::from_descriptor(&descriptor);
        let mut build_identity_bytes = Vec::with_capacity(BUILD_IDENTITY_BYTES);
        append_build_identity(&mut build_identity_bytes, build_identity);
        assert_eq!(
            build_identity_bytes,
            fixture_hex(expected, "build_identity_hex")
        );
        let mut build_identity_cursor = FixedCursor::new(&build_identity_bytes);
        let decoded_build_identity = decode_build_identity(&mut build_identity_cursor)
            .unwrap_or_else(|error| panic!("build identity fixture decode failed: {error}"));
        assert_eq!(decoded_build_identity, build_identity);
        assert!(build_identity_cursor.is_empty());
        for detail in 1..=4 {
            let mut invalid = build_identity_bytes.clone();
            let start = usize::from(detail - 1) * 32;
            invalid[start..start + 32].fill(0);
            let mut cursor = FixedCursor::new(&invalid);
            assert_wire_error(
                decode_build_identity(&mut cursor),
                ReferenceWireErrorCode::InvalidFieldValue,
                Some(detail),
            );
        }

        let manifest_bytes = fixture_hex(expected, "manifest_hex");
        let manifest = RuntimeArtifactCompatibilityManifestV1::decode(&manifest_bytes)
            .unwrap_or_else(|error| panic!("manifest fixture decode failed: {error}"));
        assert_eq!(manifest.canonical_wire(), manifest_bytes);
        assert_eq!(
            manifest.manifest_digest(),
            fixture_digest(expected, "manifest_digest_hex")
        );
        assert_eq!(manifest.row().build_identity(), build_identity);

        let projection_bytes = fixture_hex(expected, "projection_hex");
        let projection =
            RuntimeArtifactCompatibilityManifestProjectionV1::decode(&projection_bytes)
                .unwrap_or_else(|error| panic!("projection fixture decode failed: {error}"));
        assert_eq!(projection.canonical_wire(), projection_bytes);
        assert_eq!(projection.manifest_digest(), manifest.manifest_digest());
        assert_eq!(projection.row(), manifest.row());

        assert_apply_fixture(expected, "one_source_loop");
        assert_apply_fixture(expected, "empty_deactivate");

        let semantic = fixture_object(S7_REFERENCE_FIXTURE_JSON, "semantic");
        let policy = fixture_digest(semantic, "admission_policy_fingerprint_hex");
        let channel_semantic = fixture_object(semantic, "channel_binding");
        let channel = RuntimeChannelBindingV1::try_new(
            RuntimeHostId::from_bytes(fixture_hex_array(semantic, "target_hex")),
            PrincipalRef::from_bytes(fixture_hex_array(channel_semantic, "runtime_peer_hex")),
            fixture_digest(channel_semantic, "local_endpoint_identity_digest_hex"),
            fixture_digest(channel_semantic, "peer_credentials_digest_hex"),
        )
        .unwrap_or_else(|error| panic!("fixture channel binding failed: {error}"));
        assert_eq!(
            channel.binding_digest(),
            fixture_digest(expected, "channel_binding_digest_hex")
        );
        let expected_store = RuntimeStoreInstanceId::try_from_bytes(fixture_hex_array(
            semantic,
            "expected_runtime_store_instance_id_hex",
        ))
        .unwrap_or_else(|error| panic!("fixture store failed: {error}"));

        let bootstrap_request_expected = fixture_object(expected, "bootstrap_request");
        let bootstrap_request_bytes = fixture_hex(bootstrap_request_expected, "wire_hex");
        let bootstrap_request = RuntimeBootstrapRequestV1::decode(&bootstrap_request_bytes)
            .unwrap_or_else(|error| panic!("bootstrap request fixture decode failed: {error}"));
        assert_eq!(bootstrap_request.canonical_wire(), bootstrap_request_bytes);
        assert_eq!(
            bootstrap_request.request_digest(),
            fixture_digest(bootstrap_request_expected, "digest_hex")
        );
        let bootstrap_request_transcript = bootstrap_request
            .signing_transcript()
            .unwrap_or_else(|error| panic!("bootstrap request transcript failed: {error}"));
        assert_eq!(
            bootstrap_request_transcript.as_bytes(),
            fixture_hex(bootstrap_request_expected, "signing_transcript_hex")
        );
        assert_control_transcript(
            &bootstrap_request_transcript,
            BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
            BOOTSTRAP_REQUEST_SIGNING_FIELD_COUNT,
        );

        let bootstrap_response_expected = fixture_object(expected, "bootstrap_response");
        let bootstrap_response_bytes = fixture_hex(bootstrap_response_expected, "wire_hex");
        let bootstrap_response = RuntimeBootstrapResponseV1::decode(&bootstrap_response_bytes)
            .unwrap_or_else(|error| panic!("bootstrap response fixture decode failed: {error}"));
        assert_eq!(
            bootstrap_response.canonical_wire(),
            bootstrap_response_bytes
        );
        assert_eq!(
            bootstrap_response.response_digest(),
            fixture_digest(bootstrap_response_expected, "digest_hex")
        );
        assert_eq!(bootstrap_response.facts().store_instance_id, expected_store);
        assert_eq!(
            bootstrap_response.validate_against_request(
                &bootstrap_request,
                channel,
                &manifest,
                fixture_digest(semantic, "admission_policy_fingerprint_hex"),
            ),
            Ok(())
        );
        assert_eq!(
            RuntimeBootstrapResponseV1::try_new(
                bootstrap_response.request_id,
                Digest32::from_bytes([0; 32]),
                &bootstrap_response.client_nonce,
                bootstrap_response.facts,
                bootstrap_response.authentication.clone(),
                None,
            ),
            Err(ReferenceContractError::InvalidCompatibility)
        );

        let mut echo_mismatch = bootstrap_response.clone();
        echo_mismatch.request_id = BootstrapRequestId::from_bytes([0x71; 16]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(1),
        );
        let mut echo_mismatch = bootstrap_response.clone();
        echo_mismatch.request_digest = Digest32::from_bytes([0x72; 32]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(2),
        );
        let mut echo_mismatch = bootstrap_response.clone();
        echo_mismatch.client_nonce[0] ^= 0xff;
        assert_wire_error(
            echo_mismatch.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(3),
        );
        let mut echo_mismatch = bootstrap_response.clone();
        echo_mismatch.facts.target = RuntimeHostId::from_bytes([0x73; 16]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::TargetMismatch,
            Some(4),
        );
        let mut echo_mismatch = bootstrap_response.clone();
        echo_mismatch.authentication.claim.runtime_peer = PrincipalRef::from_bytes([0x74; 16]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::TargetMismatch,
            Some(18),
        );
        let mut echo_mismatch = bootstrap_response.clone();
        echo_mismatch.authentication.claim.channel_binding_digest =
            Digest32::from_bytes([0x75; 32]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::TargetMismatch,
            Some(19),
        );
        let mut bounded_request = bootstrap_request.clone();
        bounded_request.max_response_bytes = (bootstrap_response.canonical_wire().len() - 1) as u32;
        assert_wire_error(
            bootstrap_response.validate_against_request(
                &bounded_request,
                channel,
                &manifest,
                policy,
            ),
            ReferenceWireErrorCode::ResponseBoundExceeded,
            None,
        );
        let bootstrap_response_transcript = bootstrap_response
            .signing_transcript()
            .unwrap_or_else(|error| panic!("bootstrap response transcript failed: {error}"));
        assert_eq!(
            bootstrap_response_transcript.as_bytes(),
            fixture_hex(bootstrap_response_expected, "signing_transcript_hex")
        );
        assert_control_transcript(
            &bootstrap_response_transcript,
            BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
            BOOTSTRAP_RESPONSE_SIGNING_FIELD_COUNT,
        );

        let query_request_expected = fixture_object(expected, "query_request");
        let query_request_bytes = fixture_hex(query_request_expected, "wire_hex");
        let query_request = RuntimeQueryRequestV1::decode(&query_request_bytes)
            .unwrap_or_else(|error| panic!("query request fixture decode failed: {error}"));
        assert_eq!(query_request.canonical_wire(), query_request_bytes);
        assert_eq!(
            query_request.request_digest(),
            fixture_digest(query_request_expected, "digest_hex")
        );
        assert_eq!(
            query_request.validate_expected_store(expected_store),
            Ok(())
        );
        let query_request_transcript = query_request
            .signing_transcript()
            .unwrap_or_else(|error| panic!("query request transcript failed: {error}"));
        assert_eq!(
            query_request_transcript.as_bytes(),
            fixture_hex(query_request_expected, "signing_transcript_hex")
        );
        assert_control_transcript(
            &query_request_transcript,
            QUERY_REQUEST_SIGNING_DOMAIN,
            QUERY_REQUEST_SIGNING_FIELD_COUNT,
        );

        let query_response_expected = fixture_object(expected, "query_response");
        let query_response_bytes = fixture_hex(query_response_expected, "wire_hex");
        let query_response = RuntimeQueryResponseV1::decode(&query_response_bytes)
            .unwrap_or_else(|error| panic!("query response fixture decode failed: {error}"));
        assert_eq!(query_response.canonical_wire(), query_response_bytes);
        assert_eq!(
            query_response.response_digest(),
            fixture_digest(query_response_expected, "digest_hex")
        );
        assert_eq!(
            query_response.facts().serving.store_instance_id,
            expected_store
        );
        assert_eq!(
            query_response.validate_against_request(
                &query_request,
                channel,
                bootstrap_response.facts().serving_identity(),
            ),
            Ok(())
        );
        let query_response_transcript = query_response
            .signing_transcript()
            .unwrap_or_else(|error| panic!("query response transcript failed: {error}"));
        assert_eq!(
            query_response_transcript.as_bytes(),
            fixture_hex(query_response_expected, "signing_transcript_hex")
        );
        assert_control_transcript(
            &query_response_transcript,
            QUERY_RESPONSE_SIGNING_DOMAIN,
            QUERY_RESPONSE_SIGNING_FIELD_COUNT,
        );
    }

    #[test]
    fn control_contract_direct_field_errors_keep_exact_codes_and_details() {
        let expected = fixture_object(S7_REFERENCE_FIXTURE_JSON, "expected");
        let bootstrap_request =
            fixture_hex(fixture_object(expected, "bootstrap_request"), "wire_hex");
        assert_wire_error(
            RuntimeBootstrapRequestV1::decode(&mutated_tlv(
                &bootstrap_request,
                6,
                &0_u16.to_be_bytes(),
            )),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(6),
        );
        assert_wire_error(
            RuntimeBootstrapRequestV1::decode(&mutated_tlv(
                &bootstrap_request,
                7,
                &0_u16.to_be_bytes(),
            )),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(7),
        );
        assert_wire_error(
            RuntimeBootstrapRequestV1::decode(&mutated_tlv(
                &bootstrap_request,
                9,
                &0_u32.to_be_bytes(),
            )),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(9),
        );

        let query_request = fixture_hex(fixture_object(expected, "query_request"), "wire_hex");
        assert_wire_error(
            RuntimeQueryRequestV1::decode(&mutated_tlv(&query_request, 4, &[0; 32])),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(4),
        );
        assert_wire_error(
            RuntimeQueryRequestV1::decode(&mutated_tlv(&query_request, 6, &[2])),
            ReferenceWireErrorCode::InvalidPresence,
            Some(6),
        );
        assert_wire_error(
            RuntimeQueryRequestV1::decode(&mutated_tlv(&query_request, 9, &0_u32.to_be_bytes())),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(9),
        );
        assert_wire_error(
            RuntimeQueryRequestV1::decode(&mutated_tlv(&query_request, 10, &2_u16.to_be_bytes())),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(10),
        );
        assert_wire_error(
            RuntimeQueryRequestV1::decode(&mutated_tlv(&query_request, 13, &0_u16.to_be_bytes())),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(13),
        );
        assert_wire_error(
            RuntimeQueryRequestV1::decode(&mutated_tlv(&query_request, 14, &0_u16.to_be_bytes())),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(14),
        );

        let one = fixture_object(expected, "one_source_loop");
        let envelope = fixture_hex(one, "envelope_v2_hex");
        let mut unsupported_envelope_header = envelope.clone();
        unsupported_envelope_header[APPLY_ENVELOPE_MAGIC.len()..APPLY_ENVELOPE_MAGIC.len() + 2]
            .copy_from_slice(&1_u16.to_be_bytes());
        assert_wire_error(
            RuntimeApplyEnvelopeV2::decode(&unsupported_envelope_header),
            ReferenceWireErrorCode::UnsupportedVersion,
            None,
        );
        assert_wire_error(
            RuntimeApplyEnvelopeV2::decode(&mutated_tlv(&envelope, 1, &0_u16.to_be_bytes())),
            ReferenceWireErrorCode::UnsupportedVersion,
            Some(1),
        );
        let mut mismatched_scope = envelope.clone();
        overwrite_tlv_value(&mut mismatched_scope, 15, &[0x5f; 16]);
        assert_wire_error(
            RuntimeApplyEnvelopeV2::decode(&mismatched_scope),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(15),
        );
        assert_wire_error(
            RuntimeApplyEnvelopeV2::decode(&mutated_tlv(&envelope, 36, &0_u16.to_be_bytes())),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(36),
        );

        let bootstrap_response =
            fixture_hex(fixture_object(expected, "bootstrap_response"), "wire_hex");
        for (tag, replacement, code) in [
            (2, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (5, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (6, vec![0; 8], ReferenceWireErrorCode::InvalidFieldValue),
            (7, vec![0; 8], ReferenceWireErrorCode::InvalidFieldValue),
            (9, vec![0; 8], ReferenceWireErrorCode::InvalidFieldValue),
            (10, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (
                11,
                vec![0; 32],
                ReferenceWireErrorCode::CompatibilityMismatch,
            ),
            (
                13,
                vec![0; 32],
                ReferenceWireErrorCode::CompatibilityMismatch,
            ),
            (
                14,
                vec![0; 32],
                ReferenceWireErrorCode::CompatibilityMismatch,
            ),
            (
                15,
                vec![0; 32],
                ReferenceWireErrorCode::CompatibilityMismatch,
            ),
            (19, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (21, vec![0; 2], ReferenceWireErrorCode::InvalidFieldValue),
            (22, vec![0; 2], ReferenceWireErrorCode::InvalidFieldValue),
        ] {
            assert_wire_error(
                RuntimeBootstrapResponseV1::decode(&mutated_tlv(
                    &bootstrap_response,
                    tag,
                    &replacement,
                )),
                code,
                Some(tag),
            );
        }
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&mutated_tlv(&bootstrap_response, 10, &[0x66; 32])),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(10),
        );
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&mutated_tlv(&bootstrap_response, 11, &[0x67; 32])),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(11),
        );
        let mut invalid_identity = tlv_value(&bootstrap_response, 12).to_vec();
        invalid_identity[32..64].fill(0);
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&mutated_tlv(
                &bootstrap_response,
                12,
                &invalid_identity,
            )),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(12),
        );
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&mutated_tlv(
                &bootstrap_response,
                12,
                &[0; BUILD_IDENTITY_BYTES],
            )),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(10),
        );
        let mut illegal_pair = mutated_tlv(
            &bootstrap_response,
            16,
            &(RuntimeBootstrapStateV1::ReadyForApply as u16).to_be_bytes(),
        );
        overwrite_tlv_value(
            &mut illegal_pair,
            17,
            &(OperationalReasonV1::RuntimeBusy as u16).to_be_bytes(),
        );
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&illegal_pair),
            ReferenceWireErrorCode::UnknownReason,
            Some(17),
        );
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&mutated_tlv(
                &bootstrap_response,
                16,
                &99_u16.to_be_bytes(),
            )),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(16),
        );
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&mutated_tlv(
                &bootstrap_response,
                17,
                &99_u16.to_be_bytes(),
            )),
            ReferenceWireErrorCode::UnknownReason,
            Some(17),
        );

        let query_response = fixture_hex(fixture_object(expected, "query_response"), "wire_hex");
        let query_mutations = [
            (2, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (5, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (6, vec![0; 8], ReferenceWireErrorCode::InvalidFieldValue),
            (7, vec![0; 8], ReferenceWireErrorCode::InvalidFieldValue),
            (9, vec![0; 8], ReferenceWireErrorCode::InvalidFieldValue),
            (
                10,
                99_u16.to_be_bytes().to_vec(),
                ReferenceWireErrorCode::InvalidFieldValue,
            ),
            (
                11,
                99_u16.to_be_bytes().to_vec(),
                ReferenceWireErrorCode::UnknownReason,
            ),
            (
                12,
                99_u16.to_be_bytes().to_vec(),
                ReferenceWireErrorCode::InvalidFieldValue,
            ),
            (13, vec![2], ReferenceWireErrorCode::InvalidPresence),
            (
                15,
                99_u16.to_be_bytes().to_vec(),
                ReferenceWireErrorCode::InvalidFieldValue,
            ),
            (16, vec![2], ReferenceWireErrorCode::InvalidPresence),
            (
                18,
                99_u16.to_be_bytes().to_vec(),
                ReferenceWireErrorCode::InvalidFieldValue,
            ),
            (19, vec![0; 8], ReferenceWireErrorCode::InvalidFieldValue),
            (20, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (21, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (
                22,
                2_u64.to_be_bytes().to_vec(),
                ReferenceWireErrorCode::InvalidFieldValue,
            ),
            (
                23,
                99_u16.to_be_bytes().to_vec(),
                ReferenceWireErrorCode::InvalidFieldValue,
            ),
            (24, vec![0; 8], ReferenceWireErrorCode::InvalidFieldValue),
            (26, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (28, vec![0; 32], ReferenceWireErrorCode::InvalidFieldValue),
            (30, vec![0; 2], ReferenceWireErrorCode::InvalidFieldValue),
            (31, vec![0; 2], ReferenceWireErrorCode::InvalidFieldValue),
        ];
        for (tag, replacement, code) in query_mutations {
            assert_wire_error(
                RuntimeQueryResponseV1::decode(&mutated_tlv(&query_response, tag, &replacement)),
                code,
                Some(tag),
            );
        }

        let mut owner_lookup_conflict = mutated_tlv(
            &query_response,
            10,
            &(RuntimeOwnerStateV1::ApplyDisabled as u16).to_be_bytes(),
        );
        overwrite_tlv_value(
            &mut owner_lookup_conflict,
            11,
            &(OperationalReasonV1::RuntimeBusy as u16).to_be_bytes(),
        );
        assert!(RuntimeQueryResponseV1::decode(&owner_lookup_conflict).is_ok());

        let mut busy_conflict = owner_lookup_conflict;
        overwrite_tlv_value(&mut busy_conflict, 12, &(2_u16).to_be_bytes());
        overwrite_tlv_value(&mut busy_conflict, 15, &0_u16.to_be_bytes());
        overwrite_tlv_value(&mut busy_conflict, 16, &[0]);
        overwrite_tlv_value(&mut busy_conflict, 17, &[0; 16]);
        assert!(RuntimeQueryResponseV1::decode(&busy_conflict).is_ok());

        let operational_quarantine = mutated_tlv(
            &query_response,
            23,
            &(RuntimeLiveStateV1::ValidatedOperationalQuarantine as u16).to_be_bytes(),
        );
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&operational_quarantine),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(23),
        );

        let mut compatibility_mismatch_live_ready = query_response.clone();
        overwrite_tlv_value(
            &mut compatibility_mismatch_live_ready,
            10,
            &(RuntimeOwnerStateV1::ApplyDisabled as u16).to_be_bytes(),
        );
        overwrite_tlv_value(
            &mut compatibility_mismatch_live_ready,
            11,
            &(OperationalReasonV1::ActiveCompatibilityMismatch as u16).to_be_bytes(),
        );
        overwrite_tlv_value(
            &mut compatibility_mismatch_live_ready,
            23,
            &(RuntimeLiveStateV1::LiveReady as u16).to_be_bytes(),
        );
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&compatibility_mismatch_live_ready),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(23),
        );

        let mut recovery_failed_recovering = query_response.clone();
        overwrite_tlv_value(
            &mut recovery_failed_recovering,
            10,
            &(RuntimeOwnerStateV1::ApplyDisabled as u16).to_be_bytes(),
        );
        overwrite_tlv_value(
            &mut recovery_failed_recovering,
            11,
            &(OperationalReasonV1::RecoveryFailed as u16).to_be_bytes(),
        );
        overwrite_tlv_value(
            &mut recovery_failed_recovering,
            23,
            &(RuntimeLiveStateV1::Recovering as u16).to_be_bytes(),
        );
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&recovery_failed_recovering),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(23),
        );

        let mut recovering_known_terminal = query_response;
        overwrite_tlv_value(
            &mut recovering_known_terminal,
            10,
            &(RuntimeOwnerStateV1::ApplyDisabled as u16).to_be_bytes(),
        );
        overwrite_tlv_value(
            &mut recovering_known_terminal,
            11,
            &(OperationalReasonV1::Recovering as u16).to_be_bytes(),
        );
        overwrite_tlv_value(&mut recovering_known_terminal, 12, &1_u16.to_be_bytes());
        overwrite_tlv_value(&mut recovering_known_terminal, 13, &[1]);
        overwrite_tlv_value(&mut recovering_known_terminal, 14, &[0x8c; 32]);
        overwrite_tlv_value(
            &mut recovering_known_terminal,
            15,
            &(RuntimeOperationDurablePhaseV1::Terminal as u16).to_be_bytes(),
        );
        overwrite_tlv_value(&mut recovering_known_terminal, 16, &[1]);
        overwrite_tlv_value(&mut recovering_known_terminal, 17, &[0x8d; 16]);
        overwrite_tlv_value(
            &mut recovering_known_terminal,
            23,
            &(RuntimeLiveStateV1::Recovering as u16).to_be_bytes(),
        );
        assert!(RuntimeQueryResponseV1::decode(&recovering_known_terminal).is_ok());
    }

    #[test]
    fn every_shared_multi_invalid_vector_has_the_same_rust_rejection() {
        let vectors = fixture_object(S7_REFERENCE_FIXTURE_JSON, "invalid_precedence");
        let names = [
            "descriptor_structure_before_semantics",
            "descriptor_semantic_1_before_2",
            "identity_truncated",
            "identity_trailing",
            "identity_semantic_2_before_4",
            "manifest_outer_structure_before_row_semantics",
            "manifest_selected_version_1_before_2",
            "projection_outer_structure_before_row_semantics",
            "projection_selected_version_1_before_2",
            "pxte_outer_trailing_before_nested_semantics",
            "pxte_semantic_2_before_3",
            "envelope_9_before_17",
            "envelope_scope_detail_15",
            "envelope_35_before_36",
            "pxar_target_2_before_digest_7",
            "bootstrap_request_6_before_9",
            "bootstrap_response_16_before_17",
            "bootstrap_response_11_before_12",
            "bootstrap_response_10_before_11",
            "query_request_4_before_10",
            "query_response_12_before_15",
            "query_response_11_before_16",
            "query_response_23_before_24_26",
        ];
        assert_eq!(
            vectors.matches("\"decoder\"").count(),
            names.len(),
            "every shared precedence vector must be named and consumed by Rust"
        );

        for name in names {
            let vector = fixture_object(vectors, name);
            let decoder = fixture_string(vector, "decoder");
            let wire = fixture_hex(vector, "wire_hex");
            let error = decode_shared_precedence_vector(decoder, &wire)
                .expect_err("shared precedence vector was accepted");
            assert_eq!(
                error.code() as u16,
                fixture_u16(vector, "expected_code"),
                "shared precedence vector {name} returned the wrong code"
            );
            assert_eq!(
                error.detail(),
                fixture_optional_u16(vector, "expected_detail"),
                "shared precedence vector {name} returned the wrong detail"
            );
        }
    }

    #[test]
    fn semantic_decoders_freeze_multi_invalid_precedence() {
        let expected = fixture_object(S7_REFERENCE_FIXTURE_JSON, "expected");

        let descriptor = fixture_hex(expected, "descriptor_hex");
        let mut structurally_truncated = descriptor[..descriptor.len() - 1].to_vec();
        structurally_truncated[6..38].fill(0);
        assert_wire_error(
            RuntimeBuildDescriptorV1::decode(&structurally_truncated),
            ReferenceWireErrorCode::Truncated,
            None,
        );
        let mut invalid_descriptor = descriptor.clone();
        invalid_descriptor[6..38].fill(0);
        invalid_descriptor[38..46].fill(0);
        assert_wire_error(
            RuntimeBuildDescriptorV1::decode(&invalid_descriptor),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(1),
        );
        let mut invalid_descriptor = descriptor.clone();
        invalid_descriptor[38..46].fill(0);
        invalid_descriptor[46..78].fill(0);
        assert_wire_error(
            RuntimeBuildDescriptorV1::decode(&invalid_descriptor),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(2),
        );
        let mut invalid_descriptor = descriptor.clone();
        invalid_descriptor[46..78].fill(0);
        invalid_descriptor[80] = 0xff;
        assert_wire_error(
            RuntimeBuildDescriptorV1::decode(&invalid_descriptor),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(3),
        );
        let mut invalid_descriptor = descriptor.clone();
        invalid_descriptor[80] = 0xff;
        let compatibility_start = invalid_descriptor.len() - 32;
        invalid_descriptor[compatibility_start..].fill(0);
        assert_wire_error(
            RuntimeBuildDescriptorV1::decode(&invalid_descriptor),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(4),
        );
        let mut invalid_descriptor = descriptor;
        let compatibility_start = invalid_descriptor.len() - 32;
        invalid_descriptor[compatibility_start..].fill(0);
        assert_wire_error(
            RuntimeBuildDescriptorV1::decode(&invalid_descriptor),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(5),
        );

        let one = fixture_object(expected, "one_source_loop");
        let execution = fixture_hex(one, "pxte_v4_body_hex");
        let projection_end = 6 + COMPATIBILITY_PROJECTION_BYTES;
        let domain_presence_offset = projection_end + 3;
        let mut invalid_outer_presence = execution.clone();
        invalid_outer_presence[6] ^= 0xff;
        invalid_outer_presence[domain_presence_offset] = 2;
        assert_wire_error(
            TargetExecutionPlanV4::decode(&invalid_outer_presence),
            ReferenceWireErrorCode::InvalidPresence,
            Some(4),
        );
        let mut trailing_before_nested_semantics = fixture_hex(
            fixture_object(expected, "empty_deactivate"),
            "pxte_v4_body_hex",
        );
        trailing_before_nested_semantics[6] ^= 0xff;
        trailing_before_nested_semantics.push(0);
        assert_wire_error(
            TargetExecutionPlanV4::decode(&trailing_before_nested_semantics),
            ReferenceWireErrorCode::TrailingBytes,
            None,
        );

        let envelope = fixture_hex(one, "envelope_v2_hex");
        let mut writer_before_algorithm = envelope.clone();
        overwrite_tlv_value(&mut writer_before_algorithm, 9, &[0x91; 16]);
        overwrite_tlv_value(&mut writer_before_algorithm, 13, &0_u16.to_be_bytes());
        assert_wire_error(
            RuntimeApplyEnvelopeV2::decode(&writer_before_algorithm),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(9),
        );
        let mut scope_before_epoch = envelope.clone();
        overwrite_tlv_value(&mut scope_before_epoch, 15, &[0x92; 16]);
        overwrite_tlv_value(&mut scope_before_epoch, 10, &0_u64.to_be_bytes());
        overwrite_tlv_value(&mut scope_before_epoch, 17, &0_u64.to_be_bytes());
        assert_wire_error(
            RuntimeApplyEnvelopeV2::decode(&scope_before_epoch),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(15),
        );
        let mut temporal_before_generation = envelope.clone();
        overwrite_tlv_value(&mut temporal_before_generation, 26, &0_u16.to_be_bytes());
        overwrite_tlv_value(&mut temporal_before_generation, 29, &0_u64.to_be_bytes());
        assert_wire_error(
            RuntimeApplyEnvelopeV2::decode(&temporal_before_generation),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(26),
        );
        let mut algorithm_before_version = envelope;
        overwrite_tlv_value(&mut algorithm_before_version, 35, &0_u16.to_be_bytes());
        overwrite_tlv_value(&mut algorithm_before_version, 36, &0_u16.to_be_bytes());
        assert_wire_error(
            RuntimeApplyEnvelopeV2::decode(&algorithm_before_version),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(35),
        );

        let bootstrap_request =
            fixture_hex(fixture_object(expected, "bootstrap_request"), "wire_hex");
        let mut bootstrap_request_precedence = bootstrap_request;
        overwrite_tlv_value(&mut bootstrap_request_precedence, 6, &0_u16.to_be_bytes());
        overwrite_tlv_value(&mut bootstrap_request_precedence, 7, &0_u16.to_be_bytes());
        overwrite_tlv_value(&mut bootstrap_request_precedence, 9, &0_u32.to_be_bytes());
        assert_wire_error(
            RuntimeBootstrapRequestV1::decode(&bootstrap_request_precedence),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(6),
        );

        let bootstrap_response =
            fixture_hex(fixture_object(expected, "bootstrap_response"), "wire_hex");
        let mut bootstrap_response_precedence = bootstrap_response.clone();
        overwrite_tlv_value(&mut bootstrap_response_precedence, 10, &[0; 32]);
        overwrite_tlv_value(&mut bootstrap_response_precedence, 11, &[0; 32]);
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&bootstrap_response_precedence),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(10),
        );
        let mut identity_cross_before_compatibility = bootstrap_response.clone();
        overwrite_tlv_value(&mut identity_cross_before_compatibility, 10, &[0x67; 32]);
        overwrite_tlv_value(&mut identity_cross_before_compatibility, 11, &[0; 32]);
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&identity_cross_before_compatibility),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(10),
        );
        let mut zero_compatibility_everywhere = bootstrap_response;
        overwrite_tlv_value(&mut zero_compatibility_everywhere, 11, &[0; 32]);
        let mut identity = tlv_value(&zero_compatibility_everywhere, 12).to_vec();
        identity[96..128].fill(0);
        overwrite_tlv_value(&mut zero_compatibility_everywhere, 12, &identity);
        assert_wire_error(
            RuntimeBootstrapResponseV1::decode(&zero_compatibility_everywhere),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(11),
        );

        let query_request = fixture_hex(fixture_object(expected, "query_request"), "wire_hex");
        let mut query_request_precedence = query_request;
        overwrite_tlv_value(&mut query_request_precedence, 9, &0_u32.to_be_bytes());
        overwrite_tlv_value(&mut query_request_precedence, 13, &0_u16.to_be_bytes());
        assert_wire_error(
            RuntimeQueryRequestV1::decode(&query_request_precedence),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(9),
        );

        let query_response = fixture_hex(fixture_object(expected, "query_response"), "wire_hex");
        let mut kind_before_presence = query_response.clone();
        overwrite_tlv_value(&mut kind_before_presence, 12, &99_u16.to_be_bytes());
        overwrite_tlv_value(&mut kind_before_presence, 13, &[2]);
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&kind_before_presence),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(12),
        );
        let mut presence_before_phase = query_response.clone();
        overwrite_tlv_value(&mut presence_before_phase, 13, &[2]);
        overwrite_tlv_value(&mut presence_before_phase, 15, &99_u16.to_be_bytes());
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&presence_before_phase),
            ReferenceWireErrorCode::InvalidPresence,
            Some(13),
        );
        let mut phase_before_terminal = query_response.clone();
        overwrite_tlv_value(&mut phase_before_terminal, 15, &99_u16.to_be_bytes());
        overwrite_tlv_value(&mut phase_before_terminal, 16, &[2]);
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&phase_before_terminal),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(15),
        );
        let mut composite_before_terminal = query_response.clone();
        overwrite_tlv_value(&mut composite_before_terminal, 10, &2_u16.to_be_bytes());
        overwrite_tlv_value(&mut composite_before_terminal, 16, &[2]);
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&composite_before_terminal),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(11),
        );
        let mut indeterminate_without_reason = query_response.clone();
        overwrite_tlv_value(&mut indeterminate_without_reason, 12, &4_u16.to_be_bytes());
        overwrite_tlv_value(&mut indeterminate_without_reason, 13, &[2]);
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&indeterminate_without_reason),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(11),
        );
        let invalid_owner_reason = mutated_tlv(&query_response, 10, &2_u16.to_be_bytes());
        assert_wire_error(
            RuntimeQueryResponseV1::decode(&invalid_owner_reason),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(11),
        );
    }

    #[test]
    fn pxte_and_pxar_cross_field_rejections_keep_exact_details() {
        let expected = fixture_object(S7_REFERENCE_FIXTURE_JSON, "expected");
        let one = fixture_object(expected, "one_source_loop");
        let empty = fixture_object(expected, "empty_deactivate");
        let one_execution = fixture_hex(one, "pxte_v4_body_hex");
        let empty_execution = fixture_hex(empty, "pxte_v4_body_hex");
        let projection_end = 6 + COMPATIBILITY_PROJECTION_BYTES;
        let mode_offset = projection_end + 2;
        let domain_presence_offset = mode_offset + 1;
        let domain_start = domain_presence_offset + 1;
        let subject_presence_offset = domain_start + REFERENCE_LOOP_DOMAIN_BYTES;
        let subject_start = subject_presence_offset + 1;

        let mut invalid_domain_presence = one_execution.clone();
        invalid_domain_presence[domain_presence_offset] = 2;
        assert_wire_error(
            TargetExecutionPlanV4::decode(&invalid_domain_presence),
            ReferenceWireErrorCode::InvalidPresence,
            Some(4),
        );
        let mut invalid_subject_presence = one_execution.clone();
        invalid_subject_presence[subject_presence_offset] = 2;
        assert_wire_error(
            TargetExecutionPlanV4::decode(&invalid_subject_presence),
            ReferenceWireErrorCode::InvalidPresence,
            Some(5),
        );

        let mut invalid_budget = one_execution.clone();
        invalid_budget[domain_start + 16..domain_start + 24]
            .copy_from_slice(&(MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS + 1).to_be_bytes());
        assert_wire_error(
            TargetExecutionPlanV4::decode(&invalid_budget),
            ReferenceWireErrorCode::InvalidFieldValue,
            Some(4),
        );

        let mut domain_mismatch = one_execution.clone();
        domain_mismatch[subject_start + 16] ^= 0xff;
        assert_wire_error(
            TargetExecutionPlanV4::decode(&domain_mismatch),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(5),
        );
        let mut fixture_mismatch = one_execution.clone();
        fixture_mismatch[subject_start + 32] ^= 0xff;
        assert_wire_error(
            TargetExecutionPlanV4::decode(&fixture_mismatch),
            ReferenceWireErrorCode::FixtureMismatch,
            Some(5),
        );
        let mut config_mismatch = one_execution.clone();
        config_mismatch[subject_start + 32 + FIXTURE_ENTRY_BYTES] ^= 0xff;
        assert_wire_error(
            TargetExecutionPlanV4::decode(&config_mismatch),
            ReferenceWireErrorCode::FixtureMismatch,
            Some(5),
        );

        let mut missing_domain = empty_execution.clone();
        missing_domain[mode_offset] = ReferenceAssemblyModeV1::OneSourceLoop as u8;
        assert_wire_error(
            TargetExecutionPlanV4::decode(&missing_domain),
            ReferenceWireErrorCode::UnsupportedShape,
            Some(4),
        );
        let mut missing_subject = one_execution[..subject_start].to_vec();
        missing_subject[subject_presence_offset] = 0;
        assert_wire_error(
            TargetExecutionPlanV4::decode(&missing_subject),
            ReferenceWireErrorCode::UnsupportedShape,
            Some(5),
        );

        let one_outer = fixture_hex(one, "outer_v5_hex");
        let envelope_length = read_u32(&one_outer[6..10]) as usize;
        let bindings_length = read_u32(&one_outer[10..14]) as usize;
        let execution_start = APPLY_REQUEST_V5_HEADER_BYTES + envelope_length + bindings_length;
        let mut alternate_execution = one_outer[..execution_start].to_vec();
        alternate_execution.extend_from_slice(&empty_execution);
        alternate_execution[14..18].copy_from_slice(&(empty_execution.len() as u32).to_be_bytes());
        assert_wire_error(
            RuntimeApplyRequestV5::decode(&alternate_execution),
            ReferenceWireErrorCode::DigestMismatch,
            Some(7),
        );

        let release = release_fixture();
        let mismatched_manifest = RuntimeArtifactCompatibilityManifestV1::try_new(
            RuntimeHostId::from_bytes([0x06; 16]),
            &release.descriptor,
            release.fixture,
        )
        .unwrap_or_else(|error| panic!("mismatched manifest fixture failed: {error}"));
        let mismatched_release = ReleaseFixture {
            fixture: release.fixture,
            descriptor: release.descriptor,
            manifest: mismatched_manifest.clone(),
            projection: RuntimeArtifactCompatibilityManifestProjectionV1::from_manifest(
                &mismatched_manifest,
            ),
        };
        let mismatched_target_execution = one_source_execution(&mismatched_release);
        let mut target_and_digest_mismatch = one_outer[..execution_start].to_vec();
        target_and_digest_mismatch.extend_from_slice(mismatched_target_execution.canonical_wire());
        target_and_digest_mismatch[14..18].copy_from_slice(
            &(mismatched_target_execution.canonical_wire().len() as u32).to_be_bytes(),
        );
        assert_wire_error(
            RuntimeApplyRequestV5::decode(&target_and_digest_mismatch),
            ReferenceWireErrorCode::TargetMismatch,
            Some(2),
        );

        let mut invalid_binding_length = one_outer.clone();
        invalid_binding_length[10..14]
            .copy_from_slice(&((ZERO_BINDING_PXTA_BYTES - 1) as u32).to_be_bytes());
        assert_wire_error(
            RuntimeApplyRequestV5::decode(&invalid_binding_length),
            ReferenceWireErrorCode::BindingNotAllowed,
            Some(2),
        );
        let mut invalid_binding_body = one_outer;
        invalid_binding_body[APPLY_REQUEST_V5_HEADER_BYTES + envelope_length] ^= 0xff;
        assert_wire_error(
            RuntimeApplyRequestV5::decode(&invalid_binding_body),
            ReferenceWireErrorCode::BindingNotAllowed,
            Some(2),
        );
    }

    #[test]
    fn consumer_compatibility_freshness_and_owner_reason_matrices_are_fail_closed() {
        let expected = fixture_object(S7_REFERENCE_FIXTURE_JSON, "expected");
        let semantic = fixture_object(S7_REFERENCE_FIXTURE_JSON, "semantic");
        let channel_semantic = fixture_object(semantic, "channel_binding");
        let channel = RuntimeChannelBindingV1::try_new(
            RuntimeHostId::from_bytes(fixture_hex_array(semantic, "target_hex")),
            PrincipalRef::from_bytes(fixture_hex_array(channel_semantic, "runtime_peer_hex")),
            fixture_digest(channel_semantic, "local_endpoint_identity_digest_hex"),
            fixture_digest(channel_semantic, "peer_credentials_digest_hex"),
        )
        .unwrap_or_else(|error| panic!("fixture channel binding failed: {error}"));
        let policy = fixture_digest(semantic, "admission_policy_fingerprint_hex");
        let manifest =
            RuntimeArtifactCompatibilityManifestV1::decode(&fixture_hex(expected, "manifest_hex"))
                .unwrap_or_else(|error| panic!("manifest fixture decode failed: {error}"));
        let bootstrap_request = RuntimeBootstrapRequestV1::decode(&fixture_hex(
            fixture_object(expected, "bootstrap_request"),
            "wire_hex",
        ))
        .unwrap_or_else(|error| panic!("bootstrap request fixture decode failed: {error}"));
        let bootstrap_response_bytes =
            fixture_hex(fixture_object(expected, "bootstrap_response"), "wire_hex");
        let bootstrap_response = RuntimeBootstrapResponseV1::decode(&bootstrap_response_bytes)
            .unwrap_or_else(|error| panic!("bootstrap response fixture decode failed: {error}"));
        assert_eq!(
            bootstrap_response.validate_against_request(
                &bootstrap_request,
                channel,
                &manifest,
                policy,
            ),
            Ok(())
        );

        let mut altered = bootstrap_response.clone();
        altered.facts.compiled_build_instance_id = valid_build_id(0x61);
        assert_wire_error(
            altered.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(10),
        );
        let mut altered = bootstrap_response.clone();
        altered.facts.compiled_compatibility_digest = Digest32::from_bytes([0x62; 32]);
        assert_wire_error(
            altered.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(11),
        );
        let mut altered = bootstrap_response.clone();
        altered
            .facts
            .store_pinned_build_identity
            .build_descriptor_digest = Digest32::from_bytes([0x63; 32]);
        assert_wire_error(
            altered.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(12),
        );
        let mut altered = bootstrap_response.clone();
        altered.facts.manifest_digest = Digest32::from_bytes([0x64; 32]);
        assert_wire_error(
            altered.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(13),
        );
        let mut altered = bootstrap_response.clone();
        altered.facts.profile_fingerprint = Digest32::from_bytes([0x65; 32]);
        assert_wire_error(
            altered.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(14),
        );
        let mut altered = bootstrap_response.clone();
        altered.facts.admission_policy_fingerprint = Digest32::from_bytes([0x66; 32]);
        assert_wire_error(
            altered.validate_against_request(&bootstrap_request, channel, &manifest, policy),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(15),
        );
        let mut compatibility_precedence_response = bootstrap_response.clone();
        compatibility_precedence_response
            .facts
            .compiled_build_instance_id = valid_build_id(0x67);
        compatibility_precedence_response
            .authentication
            .claim
            .channel_binding_digest = Digest32::from_bytes([0x68; 32]);
        let mut compatibility_precedence_request = bootstrap_request.clone();
        compatibility_precedence_request.max_response_bytes =
            (bootstrap_response.canonical_wire().len() - 1) as u32;
        assert_wire_error(
            compatibility_precedence_response.validate_against_request(
                &compatibility_precedence_request,
                channel,
                &manifest,
                policy,
            ),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(10),
        );

        let mut coordinated = bootstrap_response_bytes;
        overwrite_tlv_value(&mut coordinated, 10, &[0xb6; 32]);
        overwrite_tlv_value(&mut coordinated, 11, &[0xb7; 32]);
        let mut identity = tlv_value(&coordinated, 12).to_vec();
        identity[..32].fill(0xb6);
        identity[96..].fill(0xb7);
        overwrite_tlv_value(&mut coordinated, 12, &identity);
        overwrite_tlv_value(&mut coordinated, 13, &[0xb8; 32]);
        overwrite_tlv_value(&mut coordinated, 14, &[0xb9; 32]);
        overwrite_tlv_value(&mut coordinated, 15, &[0xba; 32]);
        overwrite_tlv_value(&mut coordinated, 23, &[0xbb; 64]);
        let coordinated_response = RuntimeBootstrapResponseV1::decode(&coordinated)
            .unwrap_or_else(|error| panic!("coordinated response decode failed: {error}"));
        assert_wire_error(
            coordinated_response.validate_against_request(
                &bootstrap_request,
                channel,
                &manifest,
                policy,
            ),
            ReferenceWireErrorCode::CompatibilityMismatch,
            Some(10),
        );

        let query_request = RuntimeQueryRequestV1::decode(&fixture_hex(
            fixture_object(expected, "query_request"),
            "wire_hex",
        ))
        .unwrap_or_else(|error| panic!("query request fixture decode failed: {error}"));
        let query_response = RuntimeQueryResponseV1::decode(&fixture_hex(
            fixture_object(expected, "query_response"),
            "wire_hex",
        ))
        .unwrap_or_else(|error| panic!("query response fixture decode failed: {error}"));
        let serving = query_response.facts().serving;
        assert_eq!(
            query_response.validate_against_request(&query_request, channel, serving),
            Ok(())
        );
        assert_eq!(
            RuntimeQueryResponseV1::try_new(
                query_response.query_id,
                Digest32::from_bytes([0; 32]),
                &query_response.client_nonce,
                query_response.facts,
                query_response.authentication.clone(),
                None,
            ),
            Err(ReferenceContractError::InvalidCompatibility)
        );
        let mut echo_mismatch = query_response.clone();
        echo_mismatch.query_id = RuntimeQueryId::from_bytes([0x81; 16]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&query_request, channel, serving),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(1),
        );
        let mut echo_mismatch = query_response.clone();
        echo_mismatch.query_request_digest = Digest32::from_bytes([0x82; 32]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&query_request, channel, serving),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(2),
        );
        let mut echo_mismatch = query_response.clone();
        echo_mismatch.client_nonce[0] ^= 0xff;
        assert_wire_error(
            echo_mismatch.validate_against_request(&query_request, channel, serving),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(3),
        );
        let mut echo_mismatch = query_response.clone();
        echo_mismatch.facts.serving.target = RuntimeHostId::from_bytes([0x83; 16]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&query_request, channel, serving),
            ReferenceWireErrorCode::TargetMismatch,
            Some(4),
        );
        let mut echo_mismatch = query_response.clone();
        echo_mismatch.facts.serving.store_instance_id = valid_store(0x84);
        assert_wire_error(
            echo_mismatch.validate_against_request(&query_request, channel, serving),
            ReferenceWireErrorCode::TargetMismatch,
            Some(5),
        );
        let mut echo_mismatch = query_response.clone();
        echo_mismatch.authentication.claim.runtime_peer = PrincipalRef::from_bytes([0x85; 16]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&query_request, channel, serving),
            ReferenceWireErrorCode::TargetMismatch,
            Some(27),
        );
        let mut echo_mismatch = query_response.clone();
        echo_mismatch.authentication.claim.channel_binding_digest =
            Digest32::from_bytes([0x86; 32]);
        assert_wire_error(
            echo_mismatch.validate_against_request(&query_request, channel, serving),
            ReferenceWireErrorCode::TargetMismatch,
            Some(28),
        );
        let mut expectation_mismatch = query_request.clone();
        expectation_mismatch.selector.expected_request_digest =
            Some(Digest32::from_bytes([0x87; 32]));
        assert_wire_error(
            query_response.validate_against_request(&expectation_mismatch, channel, serving),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(14),
        );
        let mut no_expected = query_request.clone();
        no_expected.selector.expected_request_digest = None;
        let mut conflict_response = query_response.clone();
        conflict_response.facts.operation.lookup =
            RuntimeOperationLookupV1::try_conflict(Digest32::from_bytes([0x88; 32]))
                .unwrap_or_else(|error| panic!("conflict fixture failed: {error}"));
        assert_wire_error(
            conflict_response.validate_against_request(&no_expected, channel, serving),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(12),
        );
        let mut bounded_request = query_request.clone();
        bounded_request.max_response_bytes = (query_response.canonical_wire().len() - 1) as u32;
        assert_wire_error(
            query_response.validate_against_request(&bounded_request, channel, serving),
            ReferenceWireErrorCode::ResponseBoundExceeded,
            None,
        );
        let mut freshness_precedence_request = query_request.clone();
        freshness_precedence_request
            .selector
            .expected_request_digest = Some(Digest32::from_bytes([0x89; 32]));
        freshness_precedence_request.max_response_bytes =
            (query_response.canonical_wire().len() - 1) as u32;
        let mut freshness_precedence_response = query_response.clone();
        freshness_precedence_response
            .authentication
            .claim
            .channel_binding_digest = Digest32::from_bytes([0x8a; 32]);
        let stale_baseline = RuntimeBootstrapServingIdentityV1::new(
            serving.target,
            serving.store_instance_id,
            RuntimeSnapshotSequence::try_new(serving.snapshot_sequence.value() + 1)
                .unwrap_or_else(|error| panic!("stale baseline sequence failed: {error}")),
            serving.runtime_host_epoch,
            serving.clock_domain,
            serving.clock_generation,
        );
        assert_wire_error(
            freshness_precedence_response.validate_against_request(
                &freshness_precedence_request,
                channel,
                stale_baseline,
            ),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(6),
        );
        let domain_and_generation_mismatch = RuntimeBootstrapServingIdentityV1::new(
            serving.target,
            serving.store_instance_id,
            serving.snapshot_sequence,
            serving.runtime_host_epoch,
            ClockDomainRef::from_bytes([0x8b; 16]),
            generation(serving.clock_generation.value() + 1),
        );
        assert_wire_error(
            query_response.validate_against_request(
                &query_request,
                channel,
                domain_and_generation_mismatch,
            ),
            ReferenceWireErrorCode::TargetMismatch,
            Some(8),
        );
        let forward_baseline = RuntimeBootstrapServingIdentityV1::new(
            serving.target,
            serving.store_instance_id,
            RuntimeSnapshotSequence::try_new(serving.snapshot_sequence.value() - 1)
                .unwrap_or_else(|error| panic!("forward baseline sequence failed: {error}")),
            RuntimeHostEpoch::try_new(serving.runtime_host_epoch.value() - 1)
                .unwrap_or_else(|error| panic!("forward baseline epoch failed: {error}")),
            serving.clock_domain,
            generation(serving.clock_generation.value() - 1),
        );
        assert_eq!(
            query_response.validate_against_request(&query_request, channel, forward_baseline,),
            Ok(())
        );

        let freshness_cases = [
            (
                RuntimeBootstrapServingIdentityV1::new(
                    RuntimeHostId::from_bytes([0xfd; 16]),
                    serving.store_instance_id,
                    serving.snapshot_sequence,
                    serving.runtime_host_epoch,
                    serving.clock_domain,
                    serving.clock_generation,
                ),
                ReferenceWireErrorCode::TargetMismatch,
                4,
            ),
            (
                RuntimeBootstrapServingIdentityV1::new(
                    serving.target,
                    valid_store(0xfc),
                    serving.snapshot_sequence,
                    serving.runtime_host_epoch,
                    serving.clock_domain,
                    serving.clock_generation,
                ),
                ReferenceWireErrorCode::TargetMismatch,
                5,
            ),
            (
                RuntimeBootstrapServingIdentityV1::new(
                    serving.target,
                    serving.store_instance_id,
                    RuntimeSnapshotSequence::try_new(serving.snapshot_sequence.value() + 1)
                        .unwrap_or_else(|error| panic!("sequence baseline failed: {error}")),
                    serving.runtime_host_epoch,
                    serving.clock_domain,
                    serving.clock_generation,
                ),
                ReferenceWireErrorCode::CrossReferenceMismatch,
                6,
            ),
            (
                RuntimeBootstrapServingIdentityV1::new(
                    serving.target,
                    serving.store_instance_id,
                    serving.snapshot_sequence,
                    RuntimeHostEpoch::try_new(serving.runtime_host_epoch.value() + 1)
                        .unwrap_or_else(|error| panic!("epoch baseline failed: {error}")),
                    serving.clock_domain,
                    serving.clock_generation,
                ),
                ReferenceWireErrorCode::CrossReferenceMismatch,
                7,
            ),
            (
                RuntimeBootstrapServingIdentityV1::new(
                    serving.target,
                    serving.store_instance_id,
                    serving.snapshot_sequence,
                    serving.runtime_host_epoch,
                    serving.clock_domain,
                    generation(serving.clock_generation.value() + 1),
                ),
                ReferenceWireErrorCode::CrossReferenceMismatch,
                9,
            ),
            (
                RuntimeBootstrapServingIdentityV1::new(
                    serving.target,
                    serving.store_instance_id,
                    RuntimeSnapshotSequence::try_new(serving.snapshot_sequence.value() - 1)
                        .unwrap_or_else(|error| panic!("sequence baseline failed: {error}")),
                    RuntimeHostEpoch::try_new(serving.runtime_host_epoch.value() - 1)
                        .unwrap_or_else(|error| panic!("epoch baseline failed: {error}")),
                    serving.clock_domain,
                    serving.clock_generation,
                ),
                ReferenceWireErrorCode::CrossReferenceMismatch,
                9,
            ),
            (
                RuntimeBootstrapServingIdentityV1::new(
                    serving.target,
                    serving.store_instance_id,
                    serving.snapshot_sequence,
                    RuntimeHostEpoch::try_new(serving.runtime_host_epoch.value() - 1)
                        .unwrap_or_else(|error| panic!("epoch baseline failed: {error}")),
                    serving.clock_domain,
                    generation(serving.clock_generation.value() - 1),
                ),
                ReferenceWireErrorCode::CrossReferenceMismatch,
                6,
            ),
            (
                RuntimeBootstrapServingIdentityV1::new(
                    serving.target,
                    serving.store_instance_id,
                    serving.snapshot_sequence,
                    serving.runtime_host_epoch,
                    ClockDomainRef::from_bytes([0xfe; 16]),
                    serving.clock_generation,
                ),
                ReferenceWireErrorCode::TargetMismatch,
                8,
            ),
        ];
        for (baseline, code, detail) in freshness_cases {
            assert_wire_error(
                query_response.validate_against_request(&query_request, channel, baseline),
                code,
                Some(detail),
            );
        }

        let apply_disabled_reasons = [
            OperationalReasonV1::Recovering,
            OperationalReasonV1::ActiveCompatibilityMismatch,
            OperationalReasonV1::RecoveryFailed,
            OperationalReasonV1::RuntimeBusy,
        ];
        for reason in apply_disabled_reasons {
            assert!(
                RuntimeQueryOperationStateV1::try_new(
                    RuntimeOwnerStateV1::ApplyDisabled,
                    Some(reason),
                    RuntimeOperationLookupV1::indeterminate(reason),
                )
                .is_ok()
            );
        }
        let ownership_reasons = [
            OperationalReasonV1::OwnershipUncertain,
            OperationalReasonV1::HistoryUnavailable,
            OperationalReasonV1::ResourceCensusUncertain,
            OperationalReasonV1::OwnershipTransferRequired,
        ];
        for reason in ownership_reasons {
            assert!(
                RuntimeQueryOperationStateV1::try_new(
                    RuntimeOwnerStateV1::OwnershipUncertain,
                    Some(reason),
                    RuntimeOperationLookupV1::indeterminate(reason),
                )
                .is_ok()
            );
        }
        assert_eq!(
            RuntimeQueryOperationStateV1::try_new(
                RuntimeOwnerStateV1::ApplyDisabled,
                Some(OperationalReasonV1::OwnershipUncertain),
                RuntimeOperationLookupV1::indeterminate(OperationalReasonV1::OwnershipUncertain,),
            ),
            Err(ReferenceContractError::InvalidReason)
        );
        assert_eq!(
            RuntimeQueryOperationStateV1::try_new(
                RuntimeOwnerStateV1::OwnershipUncertain,
                Some(OperationalReasonV1::Recovering),
                RuntimeOperationLookupV1::indeterminate(OperationalReasonV1::Recovering),
            ),
            Err(ReferenceContractError::InvalidReason)
        );
    }

    #[test]
    fn strict_decoders_are_total_under_fixed_seed_malformed_and_bounded_corpora() {
        let expected = fixture_object(S7_REFERENCE_FIXTURE_JSON, "expected");
        let one = fixture_object(expected, "one_source_loop");
        let empty = fixture_object(expected, "empty_deactivate");

        exercise_strict_decoder_property(
            |frame| {
                RuntimeBuildDescriptorV1::decode(frame).map(|value| value.canonical_wire().to_vec())
            },
            &fixture_hex(expected, "descriptor_hex"),
            MAX_RUNTIME_BUILD_DESCRIPTOR_BYTES,
            None,
            0x9e37_79b9_7f4a_7c15,
        );
        exercise_strict_decoder_property(
            |frame| {
                RuntimeArtifactCompatibilityManifestV1::decode(frame)
                    .map(|value| value.canonical_wire().to_vec())
            },
            &fixture_hex(expected, "manifest_hex"),
            COMPATIBILITY_MANIFEST_BYTES,
            None,
            0x243f_6a88_85a3_08d3,
        );
        exercise_strict_decoder_property(
            |frame| {
                let mut cursor = FixedCursor::new(frame);
                let identity = decode_build_identity(&mut cursor)?;
                if !cursor.is_empty() {
                    return Err(ReferenceWireError::new(
                        ReferenceWireErrorCode::TrailingBytes,
                    ));
                }
                let mut canonical = Vec::with_capacity(BUILD_IDENTITY_BYTES);
                append_build_identity(&mut canonical, identity);
                Ok(canonical)
            },
            &fixture_hex(expected, "build_identity_hex"),
            BUILD_IDENTITY_BYTES,
            None,
            0x4528_21e6_38d0_1377,
        );
        exercise_strict_decoder_property(
            |frame| {
                RuntimeArtifactCompatibilityManifestProjectionV1::decode(frame)
                    .map(|value| value.canonical_wire().to_vec())
            },
            &fixture_hex(expected, "projection_hex"),
            COMPATIBILITY_PROJECTION_BYTES,
            None,
            0x1319_8a2e_0370_7344,
        );
        for (fixture, seed) in [(one, 0xa409_3822_299f_31d0), (empty, 0x082e_fa98_ec4e_6c89)] {
            exercise_strict_decoder_property(
                |frame| {
                    TargetExecutionPlanV4::decode(frame)
                        .map(|value| value.canonical_wire().to_vec())
                },
                &fixture_hex(fixture, "pxte_v4_body_hex"),
                MAX_TARGET_EXECUTION_PLAN_V4_BYTES,
                None,
                seed,
            );
            exercise_strict_decoder_property(
                |frame| {
                    RuntimeApplyEnvelopeV2::decode(frame)
                        .map(|value| value.canonical_wire().to_vec())
                },
                &fixture_hex(fixture, "envelope_v2_hex"),
                MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES,
                Some(APPLY_ENVELOPE_MAGIC.len() + 6),
                seed ^ 0x4528_21e6_38d0_1377,
            );
            exercise_strict_decoder_property(
                |frame| {
                    RuntimeApplyRequestV5::decode(frame)
                        .map(|value| value.canonical_wire().to_vec())
                },
                &fixture_hex(fixture, "outer_v5_hex"),
                MAX_RUNTIME_APPLY_REQUEST_V5_BYTES,
                Some(6),
                seed ^ 0xbe54_66cf_34e9_0c6c,
            );
        }
        exercise_strict_decoder_property(
            |frame| {
                RuntimeBootstrapRequestV1::decode(frame)
                    .map(|value| value.canonical_wire().to_vec())
            },
            &fixture_hex(fixture_object(expected, "bootstrap_request"), "wire_hex"),
            MAX_RUNTIME_BOOTSTRAP_REQUEST_BYTES,
            Some(10),
            0xc0ac_29b7_c97c_50dd,
        );
        exercise_strict_decoder_property(
            |frame| {
                RuntimeBootstrapResponseV1::decode(frame)
                    .map(|value| value.canonical_wire().to_vec())
            },
            &fixture_hex(fixture_object(expected, "bootstrap_response"), "wire_hex"),
            MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES,
            Some(10),
            0x3f84_d5b5_b547_0917,
        );
        exercise_strict_decoder_property(
            |frame| {
                RuntimeQueryRequestV1::decode(frame).map(|value| value.canonical_wire().to_vec())
            },
            &fixture_hex(fixture_object(expected, "query_request"), "wire_hex"),
            MAX_RUNTIME_QUERY_REQUEST_BYTES,
            Some(10),
            0x9216_d5d9_8979_fb1b,
        );
        exercise_strict_decoder_property(
            |frame| {
                RuntimeQueryResponseV1::decode(frame).map(|value| value.canonical_wire().to_vec())
            },
            &fixture_hex(fixture_object(expected, "query_response"), "wire_hex"),
            MAX_RUNTIME_QUERY_RESPONSE_BYTES,
            Some(10),
            0xd131_0ba6_98df_b5ac,
        );
    }

    #[test]
    fn release_and_reference_vectors_match_the_independent_python_oracle() {
        let release = release_fixture();
        assert_digest(
            release.descriptor.compiled_reference_compatibility_digest(),
            "d4b07fe4ae5d192b69e6c715f607988ab9eb6f2dd049c47d19b6fa74aede2bec",
        );
        assert_digest(
            reference_empty_config_digest()
                .unwrap_or_else(|error| panic!("empty digest failed: {error}")),
            "8eda4a311d0d662465999b335afaf514bfde1b0c58599e5ac936542c16dff481",
        );
        assert_eq!(release.descriptor.canonical_wire().len(), 137);
        assert_digest(
            release.descriptor.descriptor_digest(),
            "29e532abc1ac2f6ea13b45ce7029020e2863e1d302c5cdab0dab0e272652a2c1",
        );
        assert_digest(
            release.manifest.manifest_digest(),
            "fad22cd7f146653019a6b9570d06c222a34689d5b669481cdb7b314ec05edf53",
        );
        assert_eq!(release.manifest.canonical_wire().len(), 266);
        assert_eq!(release.projection.canonical_wire().len(), 298);
        assert_eq!(
            RuntimeBuildDescriptorV1::decode(release.descriptor.canonical_wire())
                .unwrap_or_else(|error| panic!("descriptor decode failed: {error}")),
            release.descriptor
        );
        assert_eq!(
            RuntimeArtifactCompatibilityManifestV1::decode(release.manifest.canonical_wire())
                .unwrap_or_else(|error| panic!("manifest decode failed: {error}")),
            release.manifest
        );

        let one = one_source_execution(&release);
        assert_eq!(one.canonical_wire().len(), 525);
        assert_digest(
            one.execution_digest(),
            "a21efbfe2f8491c1681d6e3b0646e9cda2c5a3111cfe7ebe2c36367b24847dbf",
        );
        let one_assignments = TargetPlanAssignmentsV5::try_from_execution(one.clone())
            .unwrap_or_else(|error| panic!("one assignment failed: {error}"));
        assert_eq!(
            hex(one_assignments.assignment_digest().value().as_bytes()),
            "f1f844234b9c487c7413666f63a79ea5599ff2875f106a33dd22f6ba521930a0"
        );
        assert_eq!(
            TargetExecutionPlanV4::decode(one.canonical_wire())
                .unwrap_or_else(|error| panic!("one PXTE decode failed: {error}")),
            one
        );

        let empty = TargetExecutionPlanV4::try_empty_deactivate(release.projection.clone())
            .unwrap_or_else(|error| panic!("empty PXTE failed: {error}"));
        assert_eq!(empty.canonical_wire().len(), 309);
        assert_digest(
            empty.execution_digest(),
            "1a44b9988f7e16e8caafec4b7af78ce7b0f057d38a287b2369c67feaf454bdef",
        );
        let empty_assignments = TargetPlanAssignmentsV5::try_from_execution(empty)
            .unwrap_or_else(|error| panic!("empty assignment failed: {error}"));
        assert_eq!(
            hex(empty_assignments.assignment_digest().value().as_bytes()),
            "4c691175c11f36b4e336031e51fd5dbedfce10d27b809ce8295663737cae21c7"
        );
    }

    #[test]
    fn envelope_v2_binds_store_and_pxar_v5_round_trips_without_fallback() {
        let (request, store) = apply_request_fixture();
        let decoded = RuntimeApplyRequestV5::decode(request.canonical_wire())
            .unwrap_or_else(|error| panic!("PXAR v5 decode failed: {error}"));
        assert_eq!(decoded, request);
        assert_eq!(request.envelope().validate_expected_store(store), Ok(()));
        assert_eq!(
            request
                .envelope()
                .validate_expected_store(valid_store(0x45))
                .map_err(ReferenceWireError::code),
            Err(ReferenceWireErrorCode::RuntimeStoreMismatch)
        );
        assert_ne!(
            request
                .envelope()
                .signing_transcript()
                .unwrap_or_else(|error| panic!("transcript failed: {error}"))
                .as_bytes(),
            request.envelope().canonical_wire()
        );
    }

    #[test]
    fn apply_terminal_outcome_head_lifecycle_matrix_is_exact() {
        for mode in [
            ReferenceAssemblyModeV1::OneSourceLoop,
            ReferenceAssemblyModeV1::EmptyDeactivate,
        ] {
            let (request, _) = apply_request_fixture_for_mode(mode);
            let incoming = request.slice().commitment().target_slice_digest();
            for outcome in APPLY_TERMINAL_OUTCOMES {
                for lifecycle in APPLY_TERMINAL_LIFECYCLES {
                    for head in [
                        RuntimeApplyTerminalHeadV1::PreservedNone,
                        RuntimeApplyTerminalHeadV1::PreservedExisting(TargetSliceDigest::new(
                            Digest32::from_bytes([0xe1; 32]),
                        )),
                        RuntimeApplyTerminalHeadV1::CommittedIncoming(incoming),
                    ] {
                        let expected = apply_terminal_outcome_accepts_mode(outcome, mode)
                            && apply_terminal_lifecycle_is_valid(outcome, lifecycle)
                            && apply_terminal_outcome_commits_incoming(outcome, mode)
                                == head.commits_incoming();
                        assert_eq!(
                            apply_terminal_facts(&request, outcome, lifecycle, head).is_ok(),
                            expected,
                            "unexpected matrix result for {mode:?}/{outcome:?}/{lifecycle:?}/{head:?}"
                        );
                    }
                }
            }
        }

        let (empty, _) = apply_request_fixture_for_mode(ReferenceAssemblyModeV1::EmptyDeactivate);
        assert_eq!(
            apply_terminal_facts(
                &empty,
                RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero,
                RuntimeApplyTerminalLifecycleEffectV1::MayHaveStarted,
                RuntimeApplyTerminalHeadV1::CommittedIncoming(TargetSliceDigest::new(
                    Digest32::from_bytes([0xee; 32]),
                )),
            ),
            Err(ReferenceContractError::InvalidShape)
        );
    }

    #[test]
    fn apply_terminal_receipt_round_trips_derives_stable_ref_and_authenticates_transcript() {
        let (request, _) = apply_request_fixture();
        let facts = apply_terminal_facts(
            &request,
            RuntimeApplyTerminalOutcomeV1::OneSourceLoopActive,
            RuntimeApplyTerminalLifecycleEffectV1::MayHaveStarted,
            RuntimeApplyTerminalHeadV1::CommittedIncoming(
                request.slice().commitment().target_slice_digest(),
            ),
        )
        .unwrap_or_else(|error| panic!("terminal facts failed: {error}"));
        assert!(!all_zero(facts.terminal_result_ref().as_bytes()));
        assert_eq!(
            hex(facts.terminal_result_ref().as_bytes()),
            "daeb87e4a09ad55da53d1b94d8e0d951"
        );
        let repeated = apply_terminal_facts(
            &request,
            RuntimeApplyTerminalOutcomeV1::OneSourceLoopActive,
            RuntimeApplyTerminalLifecycleEffectV1::MayHaveStarted,
            RuntimeApplyTerminalHeadV1::CommittedIncoming(
                request.slice().commitment().target_slice_digest(),
            ),
        )
        .unwrap_or_else(|error| panic!("repeated terminal facts failed: {error}"));
        assert_eq!(facts.terminal_result_ref(), repeated.terminal_result_ref());

        let channel = apply_terminal_channel(&request);
        let claim = apply_terminal_auth_claim(channel);
        let draft = RuntimeApplyTerminalReceiptDraftV1::try_new(&request, facts, channel, claim)
            .unwrap_or_else(|error| panic!("terminal receipt draft failed: {error}"));
        let transcript = draft
            .signing_transcript()
            .unwrap_or_else(|error| panic!("terminal transcript failed: {error}"))
            .as_bytes()
            .to_vec();
        assert!(transcript.starts_with(SIGNING_TRANSCRIPT_MAGIC));
        let base = SIGNING_TRANSCRIPT_MAGIC.len();
        assert_eq!(
            read_u16(&transcript[base..base + 2]),
            APPLY_TERMINAL_RECEIPT_SIGNING_TRANSCRIPT_VERSION
        );
        let domain_length = usize::from(read_u16(&transcript[base + 2..base + 4]));
        assert_eq!(
            &transcript[base + 4..base + 4 + domain_length],
            APPLY_TERMINAL_RECEIPT_SIGNING_DOMAIN
        );
        assert_eq!(
            read_u16(&transcript[base + 4 + domain_length..base + 6 + domain_length]),
            APPLY_TERMINAL_RECEIPT_SIGNING_FIELD_COUNT
        );

        let alternate = draft
            .clone()
            .finalize(&[0xa1; 64])
            .unwrap_or_else(|error| panic!("alternate terminal receipt failed: {error}"));
        let receipt = draft
            .finalize(&[0xa2; 64])
            .unwrap_or_else(|error| panic!("terminal receipt failed: {error}"));
        let decoded = RuntimeApplyTerminalReceiptV1::decode(receipt.canonical_wire())
            .unwrap_or_else(|error| panic!("terminal receipt decode failed: {error}"));
        assert_eq!(decoded, receipt);
        assert_eq!(decoded.canonical_wire(), receipt.canonical_wire());
        assert_eq!(decoded.signing_transcript().unwrap().as_bytes(), transcript);
        assert_eq!(
            alternate.signing_transcript().unwrap().as_bytes(),
            transcript
        );
        assert_ne!(alternate.receipt_digest(), receipt.receipt_digest());
        assert_eq!(decoded.validate_against_request(&request, channel), Ok(()));

        let (empty, _) = apply_request_fixture_for_mode(ReferenceAssemblyModeV1::EmptyDeactivate);
        let empty_facts = apply_terminal_facts(
            &empty,
            RuntimeApplyTerminalOutcomeV1::SupersededAfterIntentExactZero,
            RuntimeApplyTerminalLifecycleEffectV1::MayHaveStarted,
            RuntimeApplyTerminalHeadV1::CommittedIncoming(
                empty.slice().commitment().target_slice_digest(),
            ),
        )
        .expect("head-first empty superseded terminal facts");
        let empty_channel = apply_terminal_channel(&empty);
        let empty_receipt = RuntimeApplyTerminalReceiptDraftV1::try_new(
            &empty,
            empty_facts,
            empty_channel,
            apply_terminal_auth_claim(empty_channel),
        )
        .and_then(|value| value.finalize(&[0xa3; 64]))
        .expect("head-first empty superseded terminal receipt");
        assert!(matches!(
            empty_receipt.facts().head(),
            RuntimeApplyTerminalHeadV1::CommittedIncoming(_)
        ));
        assert_eq!(
            empty_receipt.validate_against_request(&empty, empty_channel),
            Ok(())
        );
    }

    #[test]
    fn apply_terminal_receipt_strict_decode_and_transcript_fail_closed() {
        let (request, _) = apply_request_fixture();
        let facts = apply_terminal_facts(
            &request,
            RuntimeApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects,
            RuntimeApplyTerminalLifecycleEffectV1::ProvenNotStarted,
            RuntimeApplyTerminalHeadV1::PreservedNone,
        )
        .expect("timeout terminal facts");
        let channel = apply_terminal_channel(&request);
        let draft = RuntimeApplyTerminalReceiptDraftV1::try_new(
            &request,
            facts,
            channel,
            apply_terminal_auth_claim(channel),
        )
        .expect("timeout terminal draft");
        assert_eq!(
            draft
                .clone()
                .finalize(&[0; MAX_CONTROL_READ_SIGNATURE_BYTES + 1]),
            Err(ReferenceContractError::InvalidBound)
        );
        let receipt = draft.finalize(&[0xb1; 64]).expect("timeout receipt");
        let wire = receipt.canonical_wire();

        let mut bad_magic = wire.to_vec();
        bad_magic[0] ^= 1;
        assert_wire_error(
            RuntimeApplyTerminalReceiptV1::decode(&bad_magic),
            ReferenceWireErrorCode::InvalidMagic,
            None,
        );
        let mut unknown_version = wire.to_vec();
        unknown_version[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_wire_error(
            RuntimeApplyTerminalReceiptV1::decode(&unknown_version),
            ReferenceWireErrorCode::UnsupportedVersion,
            None,
        );
        let mut unknown_field = wire.to_vec();
        unknown_field[6..8].copy_from_slice(&24_u16.to_be_bytes());
        assert_wire_error(
            RuntimeApplyTerminalReceiptV1::decode(&unknown_field),
            ReferenceWireErrorCode::UnknownField,
            Some(24),
        );
        for (tag, value, detail) in [(7, u16::MAX, 7), (8, u16::MAX, 8), (9, u16::MAX, 9)] {
            assert_wire_error(
                RuntimeApplyTerminalReceiptV1::decode(&mutated_tlv(
                    wire,
                    tag,
                    &value.to_be_bytes(),
                )),
                ReferenceWireErrorCode::InvalidFieldValue,
                Some(detail),
            );
        }
        let mut flipped_ref = *facts.terminal_result_ref().as_bytes();
        flipped_ref[0] ^= 1;
        assert_wire_error(
            RuntimeApplyTerminalReceiptV1::decode(&mutated_tlv(wire, 17, &flipped_ref)),
            ReferenceWireErrorCode::DigestMismatch,
            Some(17),
        );
        assert_wire_error(
            RuntimeApplyTerminalReceiptV1::decode(&mutated_tlv(wire, 9, &2_u16.to_be_bytes())),
            ReferenceWireErrorCode::InvalidPresence,
            Some(9),
        );
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert_wire_error(
            RuntimeApplyTerminalReceiptV1::decode(&trailing),
            ReferenceWireErrorCode::TrailingBytes,
            None,
        );
        assert_wire_error(
            RuntimeApplyTerminalReceiptV1::decode(&vec![
                0;
                MAX_RUNTIME_APPLY_TERMINAL_RECEIPT_BYTES
                    + 1
            ]),
            ReferenceWireErrorCode::FrameTooLarge,
            None,
        );

        let original_transcript = receipt.signing_transcript().unwrap();
        let mut changed_signature = tlv_value(wire, 23).to_vec();
        changed_signature[0] ^= 1;
        let changed_signature =
            RuntimeApplyTerminalReceiptV1::decode(&mutated_tlv(wire, 23, &changed_signature))
                .expect("opaque changed signature remains structurally canonical");
        assert_eq!(
            changed_signature.signing_transcript().unwrap(),
            original_transcript
        );
        assert_ne!(changed_signature.receipt_digest(), receipt.receipt_digest());

        let changed_census =
            RuntimeApplyTerminalReceiptV1::decode(&mutated_tlv(wire, 11, &[0xc1; 32]))
                .expect("changed signed fact remains structurally canonical");
        assert_ne!(
            changed_census.signing_transcript().unwrap(),
            original_transcript
        );
    }

    #[test]
    fn apply_terminal_receipt_request_and_channel_correlation_is_exact() {
        let (request, _) = apply_request_fixture();
        let facts = apply_terminal_facts(
            &request,
            RuntimeApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero,
            RuntimeApplyTerminalLifecycleEffectV1::MayHaveStarted,
            RuntimeApplyTerminalHeadV1::PreservedExisting(TargetSliceDigest::new(
                Digest32::from_bytes([0xc2; 32]),
            )),
        )
        .expect("aborted terminal facts");
        let channel = apply_terminal_channel(&request);
        let receipt = RuntimeApplyTerminalReceiptDraftV1::try_new(
            &request,
            facts,
            channel,
            apply_terminal_auth_claim(channel),
        )
        .and_then(|value| value.finalize(&[0xc3; 64]))
        .expect("aborted terminal receipt");

        let (wrong_request, _) =
            apply_request_fixture_for_mode(ReferenceAssemblyModeV1::EmptyDeactivate);
        assert_wire_error(
            receipt.validate_against_request(&wrong_request, channel),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(5),
        );
        let wrong_channel = RuntimeChannelBindingV1::try_new(
            channel.target(),
            channel.runtime_peer(),
            Digest32::from_bytes([0xc4; 32]),
            channel.peer_credentials_digest(),
        )
        .expect("wrong channel fixture");
        assert_wire_error(
            receipt.validate_against_request(&request, wrong_channel),
            ReferenceWireErrorCode::TargetMismatch,
            Some(19),
        );

        let mut nonce = receipt.request_nonce().to_vec();
        nonce[0] ^= 1;
        let wrong_nonce = RuntimeApplyTerminalReceiptV1::decode(&mutated_tlv(
            receipt.canonical_wire(),
            6,
            &nonce,
        ))
        .expect("different nonce is structurally canonical");
        assert_wire_error(
            wrong_nonce.validate_against_request(&request, channel),
            ReferenceWireErrorCode::CrossReferenceMismatch,
            Some(6),
        );
    }

    #[test]
    fn bootstrap_and_query_channel_contracts_round_trip_and_cross_check() {
        let release = release_fixture();
        let target = RuntimeHostId::from_bytes([0x05; 16]);
        let runtime_peer = PrincipalRef::from_bytes([0xe1; 16]);
        let channel = RuntimeChannelBindingV1::try_new(
            target,
            runtime_peer,
            Digest32::from_bytes([0xe3; 32]),
            Digest32::from_bytes([0xe4; 32]),
        )
        .unwrap_or_else(|error| panic!("channel failed: {error}"));
        assert_digest(
            channel.binding_digest(),
            "8a24e09f758b46b9e079d6f78c3ecc7556a0ace7a213520f9b2d81f4f6f92e91",
        );
        assert_digest(
            reference_profile_fingerprint(release.fixture)
                .unwrap_or_else(|error| panic!("profile fingerprint failed: {error}")),
            "260e08f4c7cedcbbfc3c79723c61ce149a595e3589adc7cabc56491afb0e5ba7",
        );
        let store = valid_store(0x44);
        let serving = RuntimeBootstrapServingIdentityV1::new(
            target,
            store,
            RuntimeSnapshotSequence::try_new(7)
                .unwrap_or_else(|error| panic!("sequence failed: {error}")),
            RuntimeHostEpoch::try_new(8).unwrap_or_else(|error| panic!("epoch failed: {error}")),
            ClockDomainRef::from_bytes([0xd1; 16]),
            generation(9),
        );
        let compatibility = RuntimeBootstrapCompatibilityV1::try_new(
            release.descriptor.build_instance_id(),
            release.descriptor.compiled_reference_compatibility_digest(),
            RuntimeBuildIdentityV1::from_descriptor(&release.descriptor),
            &release.manifest,
            release.fixture,
            Digest32::from_bytes([0xe5; 32]),
        )
        .unwrap_or_else(|error| panic!("bootstrap compatibility failed: {error}"));
        let bootstrap_facts = RuntimeBootstrapFactsV1::try_new(
            serving,
            compatibility,
            RuntimeBootstrapStateV1::ReadyForApply,
            None,
        )
        .unwrap_or_else(|error| panic!("bootstrap facts failed: {error}"));
        let bootstrap_request = RuntimeBootstrapRequestDraftV1::try_new(
            BootstrapRequestId::from_bytes([0xc1; 16]),
            target,
            SourceScopeRef::from_bytes([0x01; 16]),
            control_auth_claim(b"bootstrap-nonce"),
            MAX_RUNTIME_BOOTSTRAP_RESPONSE_BYTES as u32,
        )
        .and_then(|draft| draft.finalize(&[0x51; 64]))
        .unwrap_or_else(|error| panic!("bootstrap request failed: {error}"));
        let response_claim = RuntimeResponseAuthClaimV1::try_new(
            runtime_peer,
            channel.binding_digest(),
            ApplyAuthKeyRef::from_bytes([0xe2; 16]),
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("response algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("response claim failed: {error}"));
        let bootstrap_response = RuntimeBootstrapResponseDraftV1::try_new(
            &bootstrap_request,
            bootstrap_facts,
            channel,
            response_claim,
        )
        .and_then(|draft| draft.finalize(&[0x52; 64]))
        .unwrap_or_else(|error| panic!("bootstrap response failed: {error}"));
        let decoded_bootstrap =
            RuntimeBootstrapResponseV1::decode(bootstrap_response.canonical_wire())
                .unwrap_or_else(|error| panic!("bootstrap decode failed: {error}"));
        assert_eq!(decoded_bootstrap, bootstrap_response);
        assert_eq!(
            decoded_bootstrap.validate_against_request(
                &bootstrap_request,
                channel,
                &release.manifest,
                Digest32::from_bytes([0xe5; 32]),
            ),
            Ok(())
        );

        let expected_operation_digest = Digest32::from_bytes([0x91; 32]);
        let selector = RuntimeQuerySelectorV1::try_new(
            RuntimeQueryId::from_bytes([0xc2; 16]),
            target,
            SourceScopeRef::from_bytes([0x01; 16]),
            store,
            ApplyOperationId::from_bytes([0x92; 16]),
            Some(expected_operation_digest),
        )
        .unwrap_or_else(|error| panic!("selector failed: {error}"));
        let query_request = RuntimeQueryRequestDraftV1::try_new(
            selector,
            control_auth_claim(b"query-nonce"),
            MAX_RUNTIME_QUERY_RESPONSE_BYTES as u32,
        )
        .and_then(|draft| draft.finalize(&[0x53; 64]))
        .unwrap_or_else(|error| panic!("query request failed: {error}"));
        let lookup = RuntimeOperationLookupV1::try_known(
            expected_operation_digest,
            RuntimeOperationDurablePhaseV1::Terminal,
            Some(TerminalResultRef::from_bytes([0x93; 16])),
        )
        .unwrap_or_else(|error| panic!("lookup failed: {error}"));
        let operation =
            RuntimeQueryOperationStateV1::try_new(RuntimeOwnerStateV1::Operational, None, lookup)
                .unwrap_or_else(|error| panic!("operation state failed: {error}"));
        let desired = RuntimeDesiredStateV1::try_new(
            RuntimeDesiredHeadV1::try_one_source_loop(
                SourcePlanRevision::new(3),
                Digest32::from_bytes([0x94; 32]),
                release.manifest.manifest_digest(),
            )
            .unwrap_or_else(|error| panic!("desired head failed: {error}")),
            SourcePlanRevision::new(3),
        )
        .unwrap_or_else(|error| panic!("desired state failed: {error}"));
        let live = RuntimeLiveFactsV1::try_new(
            RuntimeLiveStateV1::LiveReady,
            4,
            5,
            Digest32::from_bytes([0x95; 32]),
        )
        .unwrap_or_else(|error| panic!("live facts failed: {error}"));
        let query_facts = RuntimeQueryFactsV1::try_new(serving, operation, desired, live)
            .unwrap_or_else(|error| panic!("query facts failed: {error}"));
        let query_response = RuntimeQueryResponseDraftV1::try_new(
            &query_request,
            query_facts,
            channel,
            response_claim,
        )
        .and_then(|draft| draft.finalize(&[0x54; 64]))
        .unwrap_or_else(|error| panic!("query response failed: {error}"));
        let decoded_query = RuntimeQueryResponseV1::decode(query_response.canonical_wire())
            .unwrap_or_else(|error| panic!("query decode failed: {error}"));
        assert_eq!(decoded_query, query_response);
        assert_eq!(
            decoded_query.validate_against_request(&query_request, channel, serving),
            Ok(())
        );
        assert_eq!(query_request.validate_expected_store(store), Ok(()));
    }

    #[test]
    fn invalid_profiles_presence_and_query_state_are_fail_closed() {
        assert_eq!(
            RuntimeBuildInstanceId::try_from_bytes([0; 32]),
            Err(ReferenceContractError::InvalidBuildInstanceId)
        );
        assert_eq!(
            RuntimeStoreInstanceId::try_from_bytes([0; 32]),
            Err(ReferenceContractError::InvalidRuntimeStoreInstanceId)
        );
        assert_eq!(
            RuntimeTargetTriple::try_new("AARCH64-unknown-linux-gnu"),
            Err(ReferenceContractError::InvalidTargetTriple)
        );
        assert_eq!(
            RuntimeOperationLookupV1::try_known(
                Digest32::from_bytes([1; 32]),
                RuntimeOperationDurablePhaseV1::Terminal,
                None,
            ),
            Err(ReferenceContractError::InvalidReason)
        );
        assert_eq!(
            RuntimeOperationLookupV1::try_conflict(Digest32::from_bytes([0; 32])),
            Err(ReferenceContractError::InvalidReason)
        );
        assert_eq!(
            RuntimeResponseAuthClaimV1::try_new(
                PrincipalRef::from_bytes([1; 16]),
                Digest32::from_bytes([0; 32]),
                ApplyAuthKeyRef::from_bytes([2; 16]),
                ApplyAuthAlgorithm::try_new(1)
                    .unwrap_or_else(|error| panic!("algorithm failed: {error}")),
                1,
            ),
            Err(ReferenceContractError::InvalidBound)
        );

        let serving = RuntimeBootstrapServingIdentityV1::new(
            RuntimeHostId::from_bytes([1; 16]),
            valid_store(2),
            RuntimeSnapshotSequence::try_new(1)
                .unwrap_or_else(|error| panic!("sequence failed: {error}")),
            RuntimeHostEpoch::try_new(1).unwrap_or_else(|error| panic!("epoch failed: {error}")),
            ClockDomainRef::from_bytes([3; 16]),
            generation(1),
        );
        let operation = RuntimeQueryOperationStateV1::try_new(
            RuntimeOwnerStateV1::Operational,
            None,
            RuntimeOperationLookupV1::Unknown,
        )
        .unwrap_or_else(|error| panic!("operation failed: {error}"));
        let desired =
            RuntimeDesiredStateV1::try_new(RuntimeDesiredHeadV1::None, SourcePlanRevision::new(0))
                .unwrap_or_else(|error| panic!("desired failed: {error}"));
        let live = RuntimeLiveFactsV1::try_new(
            RuntimeLiveStateV1::LiveReady,
            1,
            1,
            Digest32::from_bytes([4; 32]),
        )
        .unwrap_or_else(|error| panic!("live failed: {error}"));
        assert_eq!(
            RuntimeQueryFactsV1::try_new(serving, operation, desired, live),
            Err(ReferenceContractError::InvalidShape)
        );
        assert_eq!(
            RuntimeBootstrapFactsV1::try_new(
                serving,
                RuntimeBootstrapCompatibilityV1::try_from_parts(
                    valid_build_id(1),
                    Digest32::from_bytes([2; 32]),
                    RuntimeBuildIdentityV1::try_from_parts(
                        valid_build_id(1),
                        Digest32::from_bytes([3; 32]),
                        Digest32::from_bytes([4; 32]),
                        Digest32::from_bytes([2; 32]),
                    )
                    .unwrap_or_else(|error| panic!("identity failed: {error}")),
                    Digest32::from_bytes([5; 32]),
                    Digest32::from_bytes([6; 32]),
                    Digest32::from_bytes([7; 32]),
                )
                .unwrap_or_else(|error| panic!("compatibility failed: {error}")),
                RuntimeBootstrapStateV1::ValidatedOperationalQuarantine,
                Some(OperationalReasonV1::RuntimeBusy),
            ),
            Err(ReferenceContractError::InvalidReason)
        );
    }

    #[test]
    fn old_exact_decoders_reject_successor_versions_without_fallback() {
        let release = release_fixture();
        let pxte_v4 = one_source_execution(&release);
        assert_eq!(
            TargetExecutionPlan::decode(pxte_v4.canonical_wire()).map_err(|error| error.code()),
            Err(ExecutionWireErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            TargetExecutionPlanV2::decode(pxte_v4.canonical_wire()).map_err(|error| error.code()),
            Err(ThreadExecutionWireErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            TargetExecutionPlanV3::decode(pxte_v4.canonical_wire()).map_err(|error| error.code()),
            Err(ProcessExecutionWireErrorCode::UnsupportedVersion)
        );

        let mut pxar_v5_header = [0_u8; 18];
        pxar_v5_header[..4].copy_from_slice(b"PXAR");
        pxar_v5_header[4..6].copy_from_slice(&5_u16.to_be_bytes());
        assert_eq!(
            RuntimeApplyRequest::decode(&pxar_v5_header).map_err(|error| error.code()),
            Err(RequestWireErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            RuntimeApplyRequestV2::decode(&pxar_v5_header).map_err(|error| error.code()),
            Err(RequestV2WireErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            RuntimeApplyRequestV3::decode(&pxar_v5_header).map_err(|error| error.code()),
            Err(RequestV3WireErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            RuntimeApplyRequestV4::decode(&pxar_v5_header).map_err(|error| error.code()),
            Err(RequestV4WireErrorCode::UnsupportedVersion)
        );

        let expected = fixture_object(S7_REFERENCE_FIXTURE_JSON, "expected");
        let pxar_v5 = fixture_hex(fixture_object(expected, "one_source_loop"), "outer_v5_hex");
        assert_eq!(
            RuntimeApplyRequest::decode(&pxar_v5).map_err(|error| error.code()),
            Err(RequestWireErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            RuntimeApplyRequestV2::decode(&pxar_v5).map_err(|error| error.code()),
            Err(RequestV2WireErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            RuntimeApplyRequestV3::decode(&pxar_v5).map_err(|error| error.code()),
            Err(RequestV3WireErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            RuntimeApplyRequestV4::decode(&pxar_v5).map_err(|error| error.code()),
            Err(RequestV4WireErrorCode::UnsupportedVersion)
        );
    }

    #[test]
    fn stable_wire_reason_values_are_contiguous_and_frozen() {
        let values = [
            ReferenceWireErrorCode::FrameTooLarge as u16,
            ReferenceWireErrorCode::Truncated as u16,
            ReferenceWireErrorCode::InvalidMagic as u16,
            ReferenceWireErrorCode::UnsupportedVersion as u16,
            ReferenceWireErrorCode::UnknownField as u16,
            ReferenceWireErrorCode::DuplicateField as u16,
            ReferenceWireErrorCode::OutOfOrderField as u16,
            ReferenceWireErrorCode::MissingField as u16,
            ReferenceWireErrorCode::InvalidFieldLength as u16,
            ReferenceWireErrorCode::InvalidFieldValue as u16,
            ReferenceWireErrorCode::NonCanonicalFrame as u16,
            ReferenceWireErrorCode::DigestMismatch as u16,
            ReferenceWireErrorCode::CrossReferenceMismatch as u16,
            ReferenceWireErrorCode::UnsupportedShape as u16,
            ReferenceWireErrorCode::BindingNotAllowed as u16,
            ReferenceWireErrorCode::RuntimeStoreMismatch as u16,
            ReferenceWireErrorCode::TargetMismatch as u16,
            ReferenceWireErrorCode::FixtureMismatch as u16,
            ReferenceWireErrorCode::ResponseBoundExceeded as u16,
            ReferenceWireErrorCode::UnknownReason as u16,
            ReferenceWireErrorCode::TrailingBytes as u16,
            ReferenceWireErrorCode::InvalidSignatureField as u16,
            ReferenceWireErrorCode::InvalidPresence as u16,
            ReferenceWireErrorCode::ArtifactMismatch as u16,
            ReferenceWireErrorCode::CompatibilityMismatch as u16,
        ];
        assert_eq!(values, core::array::from_fn(|index| index as u16 + 1));
    }

    #[test]
    fn tlv_parser_freezes_header_tag_width_and_value_bound_precedence() {
        let short_count = begin_tlv_frame(b"PXZZ", 1, 0);
        assert_eq!(
            parse_tlv_frame(&short_count, b"PXZZ", 1, 1, 64, |tag, length| {
                tag == 1 && length == 1
            })
            .err(),
            Some(ReferenceWireError::at(
                ReferenceWireErrorCode::MissingField,
                1,
            ))
        );

        let long_count = begin_tlv_frame(b"PXZZ", 1, 2);
        assert_eq!(
            parse_tlv_frame(&long_count, b"PXZZ", 1, 1, 64, |tag, length| {
                tag == 1 && length == 1
            })
            .err(),
            Some(ReferenceWireError::at(
                ReferenceWireErrorCode::UnknownField,
                2,
            ))
        );

        let mut zero_tag = begin_tlv_frame(b"PXZZ", 1, 1);
        append_tlv(&mut zero_tag, 0, &[0]);
        assert_eq!(
            parse_tlv_frame(&zero_tag, b"PXZZ", 1, 1, 64, |tag, length| {
                tag == 1 && length == 1
            })
            .err(),
            Some(ReferenceWireError::at(
                ReferenceWireErrorCode::UnknownField,
                0,
            ))
        );

        let mut invalid_width_at_eof = begin_tlv_frame(b"PXZZ", 1, 1);
        invalid_width_at_eof.extend_from_slice(&1_u16.to_be_bytes());
        invalid_width_at_eof.extend_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            parse_tlv_frame(&invalid_width_at_eof, b"PXZZ", 1, 1, 64, |tag, length| tag
                == 1
                && length == 1,)
            .err(),
            Some(ReferenceWireError::at(
                ReferenceWireErrorCode::InvalidFieldLength,
                1,
            ))
        );

        let mut valid_width_at_eof = begin_tlv_frame(b"PXZZ", 1, 1);
        valid_width_at_eof.extend_from_slice(&1_u16.to_be_bytes());
        valid_width_at_eof.extend_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            parse_tlv_frame(&valid_width_at_eof, b"PXZZ", 1, 1, 64, |tag, length| {
                tag == 1 && length == 1
            })
            .err(),
            Some(ReferenceWireError::at(ReferenceWireErrorCode::Truncated, 1,))
        );
    }
}
