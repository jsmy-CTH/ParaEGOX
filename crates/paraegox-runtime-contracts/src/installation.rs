//! Narrow S7-E release and installation contract seam.
//!
//! This module does not read an executable, provision a service identity, mutate
//! a Runtime store, or itself expose an operator entrypoint.  The release
//! producer, installer, and Runtime initializer must obtain the artifact
//! observation and compiled facts from their own pinned executable reads.  In
//! particular, the observed target triple must come from read-only metadata or
//! compiled facts bound to that pinned executable; an operator, environment
//! variable, or mutable config may not self-report it.
//!
//! Descriptor generation accepts only that validated executable observation and
//! compiled facts.  Manifest generation accepts no manifest input and therefore
//! remains the single constructor for the installer artifact.  Strict existing
//! artifact verification is independently consumed by Runtime initialization.
//! This module deliberately exposes no raw descriptor constructor, projection,
//! apply, bootstrap, query, or general manifest constructor.

use core::fmt;

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::RuntimeHostId;

use crate::reference_assembly::{
    COMPATIBILITY_MANIFEST_BYTES, MAX_RUNTIME_ARTIFACT_BYTES, MAX_RUNTIME_BUILD_DESCRIPTOR_BYTES,
    ReferenceContractError, ReferenceFixtureEntryV1,
    RuntimeArtifactCompatibilityManifestProjectionV1, RuntimeArtifactCompatibilityManifestV1,
    RuntimeBuildDescriptorV1, RuntimeBuildIdentityV1, RuntimeBuildInstanceId, RuntimeTargetTriple,
    compiled_reference_compatibility_digest as canonical_compiled_compatibility_digest,
    reference_empty_config_digest, reference_profile_fingerprint,
};

/// Maximum accepted byte length of an installed final Runtime executable.
///
/// This is an installer-facing alias of the canonical descriptor contract's
/// single artifact-length bound.
pub const MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES: u64 = MAX_RUNTIME_ARTIFACT_BYTES;

/// Maximum canonical byte length of a Runtime build descriptor.
///
/// Pinned-file readers must use this bound before accepting descriptor bytes.
pub const MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES: usize = MAX_RUNTIME_BUILD_DESCRIPTOR_BYTES;

/// Exact byte length of the singleton Runtime compatibility manifest.
///
/// Pinned-file readers must require this exact length.  The value aliases the
/// canonical manifest codec's single size calculation.
pub const MAX_INSTALLED_RUNTIME_MANIFEST_BYTES: usize = COMPATIBILITY_MANIFEST_BYTES;

/// Facts observed from one pinned final Runtime executable.
///
/// `target_triple` is executable-derived evidence, not operator/config input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRuntimeArtifactObservationV1 {
    runtime_artifact_length: u64,
    runtime_artifact_sha256: Digest32,
    target_triple: RuntimeTargetTriple,
}

impl InstalledRuntimeArtifactObservationV1 {
    /// Validates executable-derived length, SHA-256, and canonical target facts.
    ///
    /// `target_triple` must be read from metadata or compiled facts bound to the
    /// same pinned executable.  It must not come from operator input, an
    /// environment variable, or mutable configuration.
    pub fn try_new(
        runtime_artifact_length: u64,
        runtime_artifact_sha256: Digest32,
        target_triple: &str,
    ) -> Result<Self, RuntimeInstallationError> {
        if runtime_artifact_length == 0
            || runtime_artifact_length > MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES
        {
            return Err(RuntimeInstallationError::InvalidArtifactLength);
        }
        if digest_is_zero(&runtime_artifact_sha256) {
            return Err(RuntimeInstallationError::InvalidArtifactDigest);
        }
        let target_triple = RuntimeTargetTriple::try_new(target_triple)
            .map_err(|_| RuntimeInstallationError::InvalidTargetTriple)?;
        Ok(Self {
            runtime_artifact_length,
            runtime_artifact_sha256,
            target_triple,
        })
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
}

/// Immutable facts compiled into the Runtime executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCompiledInstallationFactsV1 {
    build_instance_id: RuntimeBuildInstanceId,
    fixture: ReferenceFixtureEntryV1,
}

impl RuntimeCompiledInstallationFactsV1 {
    /// Strictly translates read-only facts compiled into the pinned executable.
    pub fn try_new(
        build_instance_id: [u8; 32],
        definition: crate::execution::CardDefinitionRef,
        implementation: crate::execution::CardImplementationRef,
        export: [u8; 16],
        definition_digest: Digest32,
        fixture_artifact_digest: Digest32,
    ) -> Result<Self, RuntimeInstallationError> {
        let build_instance_id = RuntimeBuildInstanceId::try_from_bytes(build_instance_id)
            .map_err(|_| RuntimeInstallationError::InvalidBuildInstanceId)?;
        let fixture = ReferenceFixtureEntryV1::new(
            definition,
            implementation,
            crate::reference_assembly::FixtureExportRef::from_bytes(export),
            definition_digest,
            fixture_artifact_digest,
        );
        Ok(Self {
            build_instance_id,
            fixture,
        })
    }

    /// Returns the build instance ID read independently from compiled facts.
    ///
    /// Runtime initialization must use this value, rather than echoing the
    /// corresponding field from a verified descriptor, when recording its
    /// independently observed `compiled_actual` evidence.
    #[must_use]
    pub const fn compiled_build_instance_id(self) -> [u8; 32] {
        *self.build_instance_id.as_bytes()
    }

    /// Derives the independent compiled compatibility digest from the exact
    /// compiled fixture table through its single canonical digest owner.
    ///
    /// Runtime initialization must use this value, rather than echoing the
    /// corresponding field from a verified descriptor, when recording its
    /// independently observed `compiled_actual` evidence.
    pub fn compiled_reference_compatibility_digest(
        self,
    ) -> Result<Digest32, RuntimeInstallationError> {
        canonical_compiled_compatibility_digest(self.fixture)
            .map_err(|_| RuntimeInstallationError::InternalContract)
    }

    #[must_use]
    pub(crate) const fn build_instance_id(self) -> RuntimeBuildInstanceId {
        self.build_instance_id
    }

    #[must_use]
    pub(crate) const fn fixture(self) -> ReferenceFixtureEntryV1 {
        self.fixture
    }
}

/// Immutable canonical descriptor produced for one pinned final executable.
///
/// The underlying descriptor fields are intentionally not exposed for mutation
/// or reconstruction.  The release pipeline can only persist the exact
/// canonical bytes and their domain-separated digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedRuntimeBuildDescriptorV1 {
    descriptor: RuntimeBuildDescriptorV1,
}

impl GeneratedRuntimeBuildDescriptorV1 {
    #[must_use]
    /// Returns the exact canonical descriptor bytes to persist.
    pub fn canonical_wire(&self) -> &[u8] {
        self.descriptor.canonical_wire()
    }

    #[must_use]
    /// Returns the domain-separated digest of the exact canonical bytes.
    pub const fn descriptor_digest(&self) -> Digest32 {
        self.descriptor.descriptor_digest()
    }
}

/// Exact descriptor, derived identity, and manifest verified for sequence-one
/// initialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRuntimeInstallationV1 {
    descriptor: RuntimeBuildDescriptorV1,
    build_identity: RuntimeBuildIdentityV1,
    manifest: RuntimeArtifactCompatibilityManifestV1,
}

/// Strict immutable view of the installer-produced singleton manifest.
///
/// This token has no public constructor.  A Controller or Planner ingress can
/// obtain it only by strict decoding the exact installer artifact together with
/// its separately carried digest.  The token retains those byte-identical
/// manifest bytes and derives the Runtime-owned projection and profile facts;
/// consumers cannot provide a second projection, fixture table, or profile
/// fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRuntimeManifestIngressV1 {
    manifest: RuntimeArtifactCompatibilityManifestV1,
    projection: RuntimeArtifactCompatibilityManifestProjectionV1,
    profile_fingerprint: Digest32,
    canonical_empty_config_digest: Digest32,
}

impl VerifiedRuntimeManifestIngressV1 {
    /// Returns the byte-identical canonical installer manifest.
    #[must_use]
    pub fn manifest_canonical_wire(&self) -> &[u8] {
        self.manifest.canonical_wire()
    }

    /// Returns the Runtime-contract-owned canonical projection derived from the
    /// exact manifest, never from Planner-supplied fields.
    #[must_use]
    pub fn projection_canonical_wire(&self) -> &[u8] {
        self.projection.canonical_wire()
    }

    /// Returns the domain-separated digest of the exact manifest bytes.
    #[must_use]
    pub const fn manifest_digest(&self) -> Digest32 {
        self.manifest.manifest_digest()
    }

    /// Returns the manifest's exact Runtime target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.manifest.row().target()
    }

    /// Returns the Runtime-owned reference-profile fingerprint derived from the
    /// manifest's exact fixture row and fixed protocol constants.
    #[must_use]
    pub const fn profile_fingerprint(&self) -> Digest32 {
        self.profile_fingerprint
    }

    /// Returns the Runtime-owned canonical-empty configuration digest.
    #[must_use]
    pub const fn canonical_empty_config_digest(&self) -> Digest32 {
        self.canonical_empty_config_digest
    }

    /// Returns the exact Card definition selected by the installer manifest.
    #[must_use]
    pub const fn fixture_definition(&self) -> crate::execution::CardDefinitionRef {
        self.manifest.row().fixture().definition()
    }

    /// Returns the exact Card implementation selected by the installer manifest.
    #[must_use]
    pub const fn fixture_implementation(&self) -> crate::execution::CardImplementationRef {
        self.manifest.row().fixture().implementation()
    }

    /// Returns the exact fixture export selected by the installer manifest.
    #[must_use]
    pub const fn fixture_export(&self) -> [u8; 16] {
        *self.manifest.row().fixture().export().as_bytes()
    }

    /// Returns the exact fixture definition digest selected by the manifest.
    #[must_use]
    pub const fn fixture_definition_digest(&self) -> Digest32 {
        self.manifest.row().fixture().definition_digest()
    }

    /// Returns the exact fixture artifact digest selected by the manifest.
    #[must_use]
    pub const fn fixture_artifact_digest(&self) -> Digest32 {
        self.manifest.row().fixture().fixture_artifact_digest()
    }
}

impl VerifiedRuntimeInstallationV1 {
    fn new(
        descriptor: RuntimeBuildDescriptorV1,
        manifest: RuntimeArtifactCompatibilityManifestV1,
    ) -> Self {
        let build_identity = RuntimeBuildIdentityV1::from_descriptor(&descriptor);
        Self {
            descriptor,
            build_identity,
            manifest,
        }
    }

    #[must_use]
    /// Returns the strict canonical descriptor bytes to pin in sequence one.
    pub fn descriptor_canonical_wire(&self) -> &[u8] {
        self.descriptor.canonical_wire()
    }

    #[must_use]
    /// Returns the canonical descriptor digest to pin in sequence one.
    pub const fn descriptor_digest(&self) -> Digest32 {
        self.descriptor.descriptor_digest()
    }

    #[must_use]
    /// Returns the strict canonical manifest bytes to pin in sequence one.
    pub fn manifest_canonical_wire(&self) -> &[u8] {
        self.manifest.canonical_wire()
    }

    #[must_use]
    /// Returns the canonical manifest digest to pin in sequence one.
    pub const fn manifest_digest(&self) -> Digest32 {
        self.manifest.manifest_digest()
    }

    /// Returns the compiled and descriptor-bound build instance identity.
    #[must_use]
    pub const fn build_instance_id(&self) -> [u8; 32] {
        *self.build_identity.build_instance_id().as_bytes()
    }

    /// Returns the descriptor digest field of the exact four-field identity.
    #[must_use]
    pub const fn build_descriptor_digest(&self) -> Digest32 {
        self.build_identity.build_descriptor_digest()
    }

    /// Returns the Runtime executable SHA-256 field of the exact identity.
    #[must_use]
    pub const fn runtime_artifact_sha256(&self) -> Digest32 {
        self.build_identity.runtime_artifact_sha256()
    }

    /// Returns the Runtime executable length pinned in the canonical build
    /// descriptor.
    ///
    /// Normal startup treats this persisted descriptor field as identity data;
    /// it does not re-read or re-hash the executable.
    #[must_use]
    pub const fn runtime_artifact_length(&self) -> u64 {
        self.descriptor.runtime_artifact_length()
    }

    /// Returns the binary-compiled compatibility digest field of the identity.
    #[must_use]
    pub const fn compiled_reference_compatibility_digest(&self) -> Digest32 {
        self.build_identity
            .compiled_reference_compatibility_digest()
    }

    /// Derives the immutable Controller/Planner ingress from this exact
    /// installer output without accepting caller-supplied projection facts.
    pub fn immutable_manifest_ingress(
        &self,
    ) -> Result<VerifiedRuntimeManifestIngressV1, RuntimeInstallationError> {
        immutable_manifest_ingress_from_manifest(self.manifest.clone())
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.manifest.row().target()
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn fixture(&self) -> ReferenceFixtureEntryV1 {
        self.manifest.row().fixture()
    }
}

/// Fail-closed installation-verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeInstallationError {
    /// The observed final executable length is zero or exceeds the contract bound.
    InvalidArtifactLength,
    /// The observed final executable SHA-256 is all zero.
    InvalidArtifactDigest,
    /// The executable-derived target triple is not canonical.
    InvalidTargetTriple,
    /// The binary-compiled build instance identity is all zero.
    InvalidBuildInstanceId,
    /// The descriptor does not pass the existing strict canonical decoder.
    InvalidDescriptor,
    /// The separately supplied descriptor digest does not match its exact bytes.
    DescriptorDigestMismatch,
    /// The pinned executable length does not match the descriptor.
    ArtifactLengthMismatch,
    /// The pinned executable SHA-256 does not match the descriptor.
    ArtifactDigestMismatch,
    /// The executable-derived target triple does not match the descriptor.
    TargetTripleMismatch,
    /// The binary-compiled build identity does not match the descriptor.
    CompiledBuildInstanceMismatch,
    /// The binary-compiled fixture table does not match the descriptor.
    CompiledCompatibilityMismatch,
    /// The manifest does not pass the existing strict canonical decoder.
    InvalidManifest,
    /// The separately supplied manifest digest does not match its exact bytes.
    ManifestDigestMismatch,
    /// The manifest target does not match the initializer's exact target.
    ManifestTargetMismatch,
    /// The manifest build identity does not match the verified descriptor.
    ManifestBuildIdentityMismatch,
    /// The manifest fixture does not match the binary-compiled fixture facts.
    ManifestFixtureMismatch,
    /// The manifest is not the unique canonical artifact derived from the inputs.
    ManifestCanonicalMismatch,
    /// An internal canonical contract operation failed without publishing output.
    InternalContract,
}

impl fmt::Display for RuntimeInstallationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifactLength => formatter.write_str("invalid observed artifact length"),
            Self::InvalidArtifactDigest => formatter.write_str("invalid observed artifact digest"),
            Self::InvalidTargetTriple => formatter.write_str("invalid observed target triple"),
            Self::InvalidBuildInstanceId => {
                formatter.write_str("invalid compiled build instance id")
            }
            Self::InvalidDescriptor => formatter.write_str("invalid canonical build descriptor"),
            Self::DescriptorDigestMismatch => {
                formatter.write_str("build descriptor digest mismatch")
            }
            Self::ArtifactLengthMismatch => formatter.write_str("artifact length mismatch"),
            Self::ArtifactDigestMismatch => formatter.write_str("artifact digest mismatch"),
            Self::TargetTripleMismatch => formatter.write_str("artifact target triple mismatch"),
            Self::CompiledBuildInstanceMismatch => {
                formatter.write_str("compiled build instance mismatch")
            }
            Self::CompiledCompatibilityMismatch => {
                formatter.write_str("compiled compatibility mismatch")
            }
            Self::InvalidManifest => formatter.write_str("invalid canonical manifest"),
            Self::ManifestDigestMismatch => formatter.write_str("manifest digest mismatch"),
            Self::ManifestTargetMismatch => formatter.write_str("manifest target mismatch"),
            Self::ManifestBuildIdentityMismatch => {
                formatter.write_str("manifest build identity mismatch")
            }
            Self::ManifestFixtureMismatch => formatter.write_str("manifest fixture mismatch"),
            Self::ManifestCanonicalMismatch => {
                formatter.write_str("manifest is not the uniquely generated canonical artifact")
            }
            Self::InternalContract => formatter.write_str("internal installation contract failed"),
        }
    }
}

impl std::error::Error for RuntimeInstallationError {}

/// Generates the one canonical build descriptor for a pinned final executable.
///
/// The caller must derive `artifact` from the final executable and `compiled`
/// from read-only facts compiled into that same executable.  This API accepts no
/// raw build instance ID, fixture table, target triple, or prebuilt descriptor
/// bytes, so those values cannot become a second release-pipeline authority.
pub fn generate_build_descriptor(
    artifact: &InstalledRuntimeArtifactObservationV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<GeneratedRuntimeBuildDescriptorV1, RuntimeInstallationError> {
    let descriptor = RuntimeBuildDescriptorV1::try_new(
        compiled.build_instance_id(),
        artifact.runtime_artifact_length(),
        artifact.runtime_artifact_sha256(),
        artifact.target_triple().clone(),
        compiled.fixture(),
    )
    .map_err(descriptor_generation_error)?;
    Ok(GeneratedRuntimeBuildDescriptorV1 { descriptor })
}

/// Verifies the descriptor and observed executable, then generates the one
/// canonical manifest.  There is intentionally no manifest input.
pub fn generate_manifest(
    descriptor_wire: &[u8],
    descriptor_digest: Digest32,
    target: RuntimeHostId,
    artifact: &InstalledRuntimeArtifactObservationV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<VerifiedRuntimeInstallationV1, RuntimeInstallationError> {
    let descriptor = verify_descriptor(descriptor_wire, descriptor_digest, artifact, compiled)?;
    let manifest = expected_manifest(target, &descriptor, compiled)?;
    Ok(VerifiedRuntimeInstallationV1::new(descriptor, manifest))
}

/// Strictly verifies an existing descriptor/manifest pair for the independent
/// Runtime-initializer consumer.  Both values are decoded and digested by the
/// existing canonical descriptor/manifest implementation.
pub fn verify_existing(
    descriptor_wire: &[u8],
    descriptor_digest: Digest32,
    manifest_wire: &[u8],
    manifest_digest: Digest32,
    expected_target: RuntimeHostId,
    artifact: &InstalledRuntimeArtifactObservationV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<VerifiedRuntimeInstallationV1, RuntimeInstallationError> {
    let descriptor = verify_descriptor(descriptor_wire, descriptor_digest, artifact, compiled)?;
    verify_manifest_for_descriptor(
        descriptor,
        manifest_wire,
        manifest_digest,
        expected_target,
        compiled,
    )
}

/// Strictly verifies the descriptor/manifest pair pinned during installation
/// for normal Runtime startup.
///
/// Normal startup deliberately accepts no executable observation: artifact
/// length and SHA-256 are identity facts carried only by the already pinned,
/// canonical descriptor.  The independently compiled build ID and fixture
/// compatibility remain mandatory fail-closed checks, as do the exact manifest
/// target, build identity, fixture, bytes, and digest.
pub fn verify_pinned_startup(
    descriptor_wire: &[u8],
    descriptor_digest: Digest32,
    manifest_wire: &[u8],
    manifest_digest: Digest32,
    expected_target: RuntimeHostId,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<VerifiedRuntimeInstallationV1, RuntimeInstallationError> {
    let descriptor = RuntimeBuildDescriptorV1::decode(descriptor_wire)
        .map_err(|_| RuntimeInstallationError::InvalidDescriptor)?;
    if descriptor.descriptor_digest() != descriptor_digest {
        return Err(RuntimeInstallationError::DescriptorDigestMismatch);
    }
    if descriptor.build_instance_id() != compiled.build_instance_id() {
        return Err(RuntimeInstallationError::CompiledBuildInstanceMismatch);
    }
    let compiled_compatibility = compiled.compiled_reference_compatibility_digest()?;
    if descriptor.compiled_reference_compatibility_digest() != compiled_compatibility {
        return Err(RuntimeInstallationError::CompiledCompatibilityMismatch);
    }
    verify_manifest_for_descriptor(
        descriptor,
        manifest_wire,
        manifest_digest,
        expected_target,
        compiled,
    )
}

fn verify_manifest_for_descriptor(
    descriptor: RuntimeBuildDescriptorV1,
    manifest_wire: &[u8],
    manifest_digest: Digest32,
    expected_target: RuntimeHostId,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<VerifiedRuntimeInstallationV1, RuntimeInstallationError> {
    let expected = expected_manifest(expected_target, &descriptor, compiled)?;
    let manifest = RuntimeArtifactCompatibilityManifestV1::decode(manifest_wire)
        .map_err(|_| RuntimeInstallationError::InvalidManifest)?;
    if manifest.manifest_digest() != manifest_digest {
        return Err(RuntimeInstallationError::ManifestDigestMismatch);
    }

    let row = manifest.row();
    if row.target() != expected_target {
        return Err(RuntimeInstallationError::ManifestTargetMismatch);
    }
    if row.fixture() != compiled.fixture() {
        return Err(RuntimeInstallationError::ManifestFixtureMismatch);
    }
    if row.build_identity() != RuntimeBuildIdentityV1::from_descriptor(&descriptor) {
        return Err(RuntimeInstallationError::ManifestBuildIdentityMismatch);
    }
    if manifest.canonical_wire() != expected.canonical_wire()
        || manifest.manifest_digest() != expected.manifest_digest()
    {
        return Err(RuntimeInstallationError::ManifestCanonicalMismatch);
    }

    Ok(VerifiedRuntimeInstallationV1::new(descriptor, manifest))
}

/// Strictly decodes the installer-produced singleton manifest for immutable
/// Controller/Planner consumption.
///
/// The separately transported digest must match the exact canonical bytes.  All
/// projection, fixture, profile, and canonical-empty facts are then derived by
/// the Runtime contract owner; this function accepts none of them as caller
/// input.
pub fn verify_immutable_manifest_ingress(
    manifest_wire: &[u8],
    manifest_digest: Digest32,
) -> Result<VerifiedRuntimeManifestIngressV1, RuntimeInstallationError> {
    let manifest = RuntimeArtifactCompatibilityManifestV1::decode(manifest_wire)
        .map_err(|_| RuntimeInstallationError::InvalidManifest)?;
    if manifest.manifest_digest() != manifest_digest {
        return Err(RuntimeInstallationError::ManifestDigestMismatch);
    }
    immutable_manifest_ingress_from_manifest(manifest)
}

/// Strictly reconstructs immutable Controller/Planner ingress from the exact
/// projection persisted in committed `PlanContent`.
///
/// The projection decoder proves canonical framing, its embedded manifest
/// digest, exact singleton row, selected protocol version, and fixture-derived
/// compatibility.  This function additionally requires the independently
/// persisted manifest digest and reconstructs the byte-identical manifest via
/// the same private canonical owner.
pub fn verify_immutable_manifest_projection_ingress(
    projection_wire: &[u8],
    expected_manifest_digest: Digest32,
) -> Result<VerifiedRuntimeManifestIngressV1, RuntimeInstallationError> {
    let projection = RuntimeArtifactCompatibilityManifestProjectionV1::decode(projection_wire)
        .map_err(|_| RuntimeInstallationError::InvalidManifest)?;
    if projection.manifest_digest() != expected_manifest_digest {
        return Err(RuntimeInstallationError::ManifestDigestMismatch);
    }
    let manifest = RuntimeArtifactCompatibilityManifestV1::from_row(projection.row())
        .map_err(|_| RuntimeInstallationError::InternalContract)?;
    if manifest.manifest_digest() != expected_manifest_digest {
        return Err(RuntimeInstallationError::ManifestCanonicalMismatch);
    }
    immutable_manifest_ingress_from_parts(manifest, projection)
}

fn immutable_manifest_ingress_from_manifest(
    manifest: RuntimeArtifactCompatibilityManifestV1,
) -> Result<VerifiedRuntimeManifestIngressV1, RuntimeInstallationError> {
    let projection = RuntimeArtifactCompatibilityManifestProjectionV1::from_manifest(&manifest);
    immutable_manifest_ingress_from_parts(manifest, projection)
}

fn immutable_manifest_ingress_from_parts(
    manifest: RuntimeArtifactCompatibilityManifestV1,
    projection: RuntimeArtifactCompatibilityManifestProjectionV1,
) -> Result<VerifiedRuntimeManifestIngressV1, RuntimeInstallationError> {
    let fixture = manifest.row().fixture();
    let profile_fingerprint = reference_profile_fingerprint(fixture)
        .map_err(|_| RuntimeInstallationError::InternalContract)?;
    let canonical_empty_config_digest =
        reference_empty_config_digest().map_err(|_| RuntimeInstallationError::InternalContract)?;
    Ok(VerifiedRuntimeManifestIngressV1 {
        manifest,
        projection,
        profile_fingerprint,
        canonical_empty_config_digest,
    })
}

fn verify_descriptor(
    descriptor_wire: &[u8],
    descriptor_digest: Digest32,
    artifact: &InstalledRuntimeArtifactObservationV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<RuntimeBuildDescriptorV1, RuntimeInstallationError> {
    let descriptor = RuntimeBuildDescriptorV1::decode(descriptor_wire)
        .map_err(|_| RuntimeInstallationError::InvalidDescriptor)?;
    if descriptor.descriptor_digest() != descriptor_digest {
        return Err(RuntimeInstallationError::DescriptorDigestMismatch);
    }
    if descriptor.runtime_artifact_length() != artifact.runtime_artifact_length() {
        return Err(RuntimeInstallationError::ArtifactLengthMismatch);
    }
    if descriptor.runtime_artifact_sha256() != artifact.runtime_artifact_sha256() {
        return Err(RuntimeInstallationError::ArtifactDigestMismatch);
    }
    if descriptor.target_triple() != artifact.target_triple() {
        return Err(RuntimeInstallationError::TargetTripleMismatch);
    }
    if descriptor.build_instance_id() != compiled.build_instance_id() {
        return Err(RuntimeInstallationError::CompiledBuildInstanceMismatch);
    }
    Ok(descriptor)
}

fn descriptor_generation_error(error: ReferenceContractError) -> RuntimeInstallationError {
    match error {
        ReferenceContractError::InvalidArtifactLength => {
            RuntimeInstallationError::InvalidArtifactLength
        }
        ReferenceContractError::InvalidArtifactDigest => {
            RuntimeInstallationError::InvalidArtifactDigest
        }
        ReferenceContractError::InvalidTargetTriple => {
            RuntimeInstallationError::InvalidTargetTriple
        }
        ReferenceContractError::InvalidBuildInstanceId => {
            RuntimeInstallationError::InvalidBuildInstanceId
        }
        ReferenceContractError::InvalidCompatibility => {
            RuntimeInstallationError::CompiledCompatibilityMismatch
        }
        _ => RuntimeInstallationError::InternalContract,
    }
}

fn expected_manifest(
    target: RuntimeHostId,
    descriptor: &RuntimeBuildDescriptorV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<RuntimeArtifactCompatibilityManifestV1, RuntimeInstallationError> {
    RuntimeArtifactCompatibilityManifestV1::try_new(target, descriptor, compiled.fixture()).map_err(
        |error| match error {
            ReferenceContractError::InvalidCompatibility => {
                RuntimeInstallationError::CompiledCompatibilityMismatch
            }
            _ => RuntimeInstallationError::InternalContract,
        },
    )
}

fn digest_is_zero(digest: &Digest32) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use paraegox_kernel::identity::RuntimeHostId;

    use crate::execution::{CardDefinitionRef, CardImplementationRef};
    use crate::reference_assembly::RuntimeArtifactCompatibilityManifestV1;

    const S7_REFERENCE_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s7_reference_successor_v1.json");

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("fixture contains non-hex byte"),
        }
    }

    fn fixture_hex(key: &str) -> Vec<u8> {
        let prefix = format!("\"{key}\": \"");
        let value = S7_REFERENCE_FIXTURE_JSON
            .split_once(&prefix)
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing fixture key {key}"));
        let encoded = value
            .split_once('"')
            .map(|(encoded, _)| encoded)
            .unwrap_or_else(|| panic!("unterminated fixture key {key}"));
        assert!(
            !encoded.is_empty() && encoded.len().is_multiple_of(2),
            "fixture key {key} is not strict even-width hex"
        );
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn fixture_digest(key: &str) -> Digest32 {
        let bytes: [u8; 32] = fixture_hex(key)
            .try_into()
            .unwrap_or_else(|bytes: Vec<u8>| {
                panic!(
                    "fixture key {key} decoded to {} bytes instead of 32",
                    bytes.len()
                )
            });
        Digest32::from_bytes(bytes)
    }

    struct InstallationFixture {
        target: RuntimeHostId,
        descriptor: RuntimeBuildDescriptorV1,
        artifact: InstalledRuntimeArtifactObservationV1,
        compiled: RuntimeCompiledInstallationFactsV1,
    }

    fn installation_fixture() -> InstallationFixture {
        let compiled = compiled_facts(0x11, 0xa1);
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x22; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .unwrap_or_else(|error| panic!("artifact observation failed: {error}"));
        let descriptor = RuntimeBuildDescriptorV1::try_new(
            compiled.build_instance_id(),
            artifact.runtime_artifact_length(),
            artifact.runtime_artifact_sha256(),
            artifact.target_triple().clone(),
            compiled.fixture(),
        )
        .unwrap_or_else(|error| panic!("descriptor fixture failed: {error}"));
        InstallationFixture {
            target: RuntimeHostId::from_bytes([0x05; 16]),
            descriptor,
            artifact,
            compiled,
        }
    }

    fn compiled_facts(build_byte: u8, fixture_byte: u8) -> RuntimeCompiledInstallationFactsV1 {
        RuntimeCompiledInstallationFactsV1::try_new(
            [build_byte; 32],
            CardDefinitionRef::from_bytes([fixture_byte; 16]),
            CardImplementationRef::from_bytes([fixture_byte.wrapping_add(1); 16]),
            [fixture_byte.wrapping_add(2); 16],
            Digest32::from_bytes([fixture_byte.wrapping_add(3); 32]),
            Digest32::from_bytes([fixture_byte.wrapping_add(4); 32]),
        )
        .unwrap_or_else(|error| panic!("compiled facts fixture failed: {error}"))
    }

    #[test]
    fn installer_bounds_are_exact_aliases_of_the_canonical_contract() {
        assert_eq!(MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES, 4_294_967_296);
        assert_eq!(MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES, 367);
        assert_eq!(MAX_INSTALLED_RUNTIME_MANIFEST_BYTES, 266);
        assert_eq!(
            MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES,
            MAX_RUNTIME_ARTIFACT_BYTES
        );
        assert_eq!(
            MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES,
            MAX_RUNTIME_BUILD_DESCRIPTOR_BYTES
        );
        assert_eq!(
            MAX_INSTALLED_RUNTIME_MANIFEST_BYTES,
            COMPATIBILITY_MANIFEST_BYTES
        );
    }

    #[test]
    fn generated_descriptor_exactly_round_trips_through_install_and_runtime_verification() {
        let fixture = installation_fixture();
        let generated = generate_build_descriptor(&fixture.artifact, fixture.compiled)
            .unwrap_or_else(|error| panic!("descriptor generation failed: {error}"));

        assert_eq!(generated.canonical_wire(), fixture_hex("descriptor_hex"));
        assert_eq!(
            generated.descriptor_digest(),
            fixture_digest("descriptor_digest_hex")
        );
        assert_eq!(
            generated.canonical_wire(),
            fixture.descriptor.canonical_wire()
        );

        let installed = generate_manifest(
            generated.canonical_wire(),
            generated.descriptor_digest(),
            fixture.target,
            &fixture.artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));
        assert_eq!(
            installed.manifest_canonical_wire(),
            fixture_hex("manifest_hex")
        );
        assert_eq!(
            installed.manifest_digest(),
            fixture_digest("manifest_digest_hex")
        );

        let verified = verify_existing(
            generated.canonical_wire(),
            generated.descriptor_digest(),
            installed.manifest_canonical_wire(),
            installed.manifest_digest(),
            fixture.target,
            &fixture.artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("existing artifact verification failed: {error}"));
        assert_eq!(verified, installed);
    }

    #[test]
    fn immutable_planner_ingress_preserves_the_exact_installer_manifest() {
        let fixture = installation_fixture();
        let installed = generate_manifest(
            fixture.descriptor.canonical_wire(),
            fixture.descriptor.descriptor_digest(),
            fixture.target,
            &fixture.artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));

        let ingress = verify_immutable_manifest_ingress(
            installed.manifest_canonical_wire(),
            installed.manifest_digest(),
        )
        .unwrap_or_else(|error| panic!("immutable ingress verification failed: {error}"));
        assert_eq!(
            ingress.manifest_canonical_wire(),
            installed.manifest_canonical_wire()
        );
        assert_eq!(
            ingress.projection_canonical_wire(),
            fixture_hex("projection_hex")
        );
        assert_eq!(ingress.manifest_digest(), installed.manifest_digest());
        assert_eq!(ingress.target(), fixture.target);
        assert_eq!(
            ingress.profile_fingerprint(),
            fixture_digest("profile_fingerprint_hex")
        );
        assert_eq!(
            ingress.canonical_empty_config_digest(),
            fixture_digest("empty_config_digest_hex")
        );
        assert_eq!(
            ingress.fixture_definition(),
            fixture.compiled.fixture().definition()
        );
        assert_eq!(
            ingress.fixture_implementation(),
            fixture.compiled.fixture().implementation()
        );
        assert_eq!(
            ingress.fixture_export(),
            *fixture.compiled.fixture().export().as_bytes()
        );
        assert_eq!(
            ingress.fixture_definition_digest(),
            fixture.compiled.fixture().definition_digest()
        );
        assert_eq!(
            ingress.fixture_artifact_digest(),
            fixture.compiled.fixture().fixture_artifact_digest()
        );

        let recovered = verify_immutable_manifest_projection_ingress(
            ingress.projection_canonical_wire(),
            ingress.manifest_digest(),
        )
        .unwrap_or_else(|error| panic!("projection ingress verification failed: {error}"));
        assert_eq!(recovered, ingress);

        assert_eq!(
            verify_immutable_manifest_ingress(
                installed.manifest_canonical_wire(),
                Digest32::from_bytes([0x7f; 32]),
            ),
            Err(RuntimeInstallationError::ManifestDigestMismatch)
        );
        let mut edited = installed.manifest_canonical_wire().to_vec();
        edited.push(0);
        assert_eq!(
            verify_immutable_manifest_ingress(&edited, installed.manifest_digest()),
            Err(RuntimeInstallationError::InvalidManifest)
        );

        let mut edited_projection = ingress.projection_canonical_wire().to_vec();
        edited_projection.push(0);
        assert_eq!(
            verify_immutable_manifest_projection_ingress(
                &edited_projection,
                ingress.manifest_digest(),
            ),
            Err(RuntimeInstallationError::InvalidManifest)
        );
        assert_eq!(
            verify_immutable_manifest_projection_ingress(
                ingress.projection_canonical_wire(),
                Digest32::from_bytes([0x7e; 32]),
            ),
            Err(RuntimeInstallationError::ManifestDigestMismatch)
        );
    }

    #[test]
    fn normal_startup_uses_only_pinned_artifact_identity_and_fails_compiled_mismatch() {
        let fixture = installation_fixture();
        let descriptor = generate_build_descriptor(&fixture.artifact, fixture.compiled)
            .unwrap_or_else(|error| panic!("descriptor generation failed: {error}"));
        let installed = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            fixture.target,
            &fixture.artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));

        let verified = verify_pinned_startup(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            installed.manifest_canonical_wire(),
            installed.manifest_digest(),
            fixture.target,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("pinned startup verification failed: {error}"));
        assert_eq!(
            verified.runtime_artifact_length(),
            fixture.artifact.runtime_artifact_length()
        );
        assert_eq!(
            verified.runtime_artifact_sha256(),
            fixture.artifact.runtime_artifact_sha256()
        );

        let alternate_artifact = InstalledRuntimeArtifactObservationV1::try_new(
            2_097_152,
            Digest32::from_bytes([0x33; 32]),
            fixture.artifact.target_triple().as_str(),
        )
        .unwrap_or_else(|error| panic!("alternate artifact facts failed: {error}"));
        let alternate_descriptor = generate_build_descriptor(&alternate_artifact, fixture.compiled)
            .unwrap_or_else(|error| panic!("alternate descriptor failed: {error}"));
        let alternate_installed = generate_manifest(
            alternate_descriptor.canonical_wire(),
            alternate_descriptor.descriptor_digest(),
            fixture.target,
            &alternate_artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("alternate manifest failed: {error}"));
        let alternate_verified = verify_pinned_startup(
            alternate_descriptor.canonical_wire(),
            alternate_descriptor.descriptor_digest(),
            alternate_installed.manifest_canonical_wire(),
            alternate_installed.manifest_digest(),
            fixture.target,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("alternate pinned startup failed: {error}"));
        assert_eq!(alternate_verified.runtime_artifact_length(), 2_097_152);
        assert_eq!(
            alternate_verified.runtime_artifact_sha256(),
            Digest32::from_bytes([0x33; 32])
        );

        assert_eq!(
            verify_pinned_startup(
                descriptor.canonical_wire(),
                descriptor.descriptor_digest(),
                installed.manifest_canonical_wire(),
                installed.manifest_digest(),
                fixture.target,
                compiled_facts(0x12, 0xa1),
            ),
            Err(RuntimeInstallationError::CompiledBuildInstanceMismatch)
        );
        assert_eq!(
            verify_pinned_startup(
                descriptor.canonical_wire(),
                descriptor.descriptor_digest(),
                installed.manifest_canonical_wire(),
                installed.manifest_digest(),
                fixture.target,
                compiled_facts(0x11, 0xb1),
            ),
            Err(RuntimeInstallationError::CompiledCompatibilityMismatch)
        );
    }

    #[test]
    fn generated_descriptor_rejects_mismatched_observation_and_compiled_facts() {
        let fixture = installation_fixture();
        let generated = generate_build_descriptor(&fixture.artifact, fixture.compiled)
            .unwrap_or_else(|error| panic!("descriptor generation failed: {error}"));
        let wrong_artifact = InstalledRuntimeArtifactObservationV1::try_new(
            fixture.artifact.runtime_artifact_length(),
            Digest32::from_bytes([0x23; 32]),
            fixture.artifact.target_triple().as_str(),
        )
        .unwrap_or_else(|error| panic!("mismatched artifact observation failed: {error}"));
        assert_eq!(
            generate_manifest(
                generated.canonical_wire(),
                generated.descriptor_digest(),
                fixture.target,
                &wrong_artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::ArtifactDigestMismatch)
        );

        assert_eq!(
            generate_manifest(
                generated.canonical_wire(),
                generated.descriptor_digest(),
                fixture.target,
                &fixture.artifact,
                compiled_facts(0x12, 0xa1),
            ),
            Err(RuntimeInstallationError::CompiledBuildInstanceMismatch)
        );
        assert_eq!(
            generate_manifest(
                generated.canonical_wire(),
                generated.descriptor_digest(),
                fixture.target,
                &fixture.artifact,
                compiled_facts(0x11, 0xb1),
            ),
            Err(RuntimeInstallationError::CompiledCompatibilityMismatch)
        );
    }

    #[test]
    fn generate_manifest_accepts_only_matching_descriptor_artifact_and_compiled_facts() {
        let fixture = installation_fixture();
        assert_eq!(fixture.compiled.compiled_build_instance_id(), [0x11; 32]);
        assert_eq!(
            fixture
                .compiled
                .compiled_reference_compatibility_digest()
                .unwrap_or_else(|error| panic!("compiled digest failed: {error}")),
            Digest32::from_bytes([
                0xd4, 0xb0, 0x7f, 0xe4, 0xae, 0x5d, 0x19, 0x2b, 0x69, 0xe6, 0xc7, 0x15, 0xf6, 0x07,
                0x98, 0x8a, 0xb9, 0xeb, 0x6f, 0x2d, 0xd0, 0x49, 0xc4, 0x7d, 0x19, 0xb6, 0xfa, 0x74,
                0xae, 0xde, 0x2b, 0xec,
            ])
        );
        let verified = generate_manifest(
            fixture.descriptor.canonical_wire(),
            fixture.descriptor.descriptor_digest(),
            fixture.target,
            &fixture.artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));

        let expected = RuntimeArtifactCompatibilityManifestV1::try_new(
            fixture.target,
            &fixture.descriptor,
            fixture.compiled.fixture(),
        )
        .unwrap_or_else(|error| panic!("expected manifest failed: {error}"));
        assert_eq!(
            verified.descriptor_canonical_wire(),
            fixture.descriptor.canonical_wire()
        );
        assert_eq!(
            verified.descriptor_digest(),
            fixture.descriptor.descriptor_digest()
        );
        let identity = RuntimeBuildIdentityV1::from_descriptor(&fixture.descriptor);
        assert_eq!(
            verified.build_instance_id(),
            *identity.build_instance_id().as_bytes()
        );
        assert_eq!(
            verified.build_descriptor_digest(),
            identity.build_descriptor_digest()
        );
        assert_eq!(
            verified.runtime_artifact_sha256(),
            identity.runtime_artifact_sha256()
        );
        assert_eq!(
            verified.compiled_reference_compatibility_digest(),
            identity.compiled_reference_compatibility_digest()
        );
        assert_eq!(
            verified.manifest_canonical_wire(),
            expected.canonical_wire()
        );
        assert_eq!(verified.manifest_digest(), expected.manifest_digest());
        assert_eq!(verified.target(), fixture.target);
        assert_eq!(verified.fixture(), fixture.compiled.fixture());
    }

    #[test]
    fn descriptor_observation_mismatches_fail_closed() {
        let fixture = installation_fixture();
        let wrong_digest = Digest32::from_bytes([0x91; 32]);
        assert_eq!(
            generate_manifest(
                fixture.descriptor.canonical_wire(),
                wrong_digest,
                fixture.target,
                &fixture.artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::DescriptorDigestMismatch)
        );

        let wrong_length = InstalledRuntimeArtifactObservationV1::try_new(
            fixture.artifact.runtime_artifact_length() + 1,
            fixture.artifact.runtime_artifact_sha256(),
            fixture.artifact.target_triple().as_str(),
        )
        .unwrap_or_else(|error| panic!("wrong-length observation failed: {error}"));
        assert_eq!(
            generate_manifest(
                fixture.descriptor.canonical_wire(),
                fixture.descriptor.descriptor_digest(),
                fixture.target,
                &wrong_length,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::ArtifactLengthMismatch)
        );

        let wrong_artifact = InstalledRuntimeArtifactObservationV1::try_new(
            fixture.artifact.runtime_artifact_length(),
            Digest32::from_bytes([0x92; 32]),
            fixture.artifact.target_triple().as_str(),
        )
        .unwrap_or_else(|error| panic!("wrong-artifact observation failed: {error}"));
        assert_eq!(
            generate_manifest(
                fixture.descriptor.canonical_wire(),
                fixture.descriptor.descriptor_digest(),
                fixture.target,
                &wrong_artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::ArtifactDigestMismatch)
        );

        let wrong_target = InstalledRuntimeArtifactObservationV1::try_new(
            fixture.artifact.runtime_artifact_length(),
            fixture.artifact.runtime_artifact_sha256(),
            "x86_64-unknown-linux-gnu",
        )
        .unwrap_or_else(|error| panic!("wrong-target observation failed: {error}"));
        assert_eq!(
            generate_manifest(
                fixture.descriptor.canonical_wire(),
                fixture.descriptor.descriptor_digest(),
                fixture.target,
                &wrong_target,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::TargetTripleMismatch)
        );
    }

    #[test]
    fn compiled_build_and_fixture_mismatches_fail_closed() {
        let fixture = installation_fixture();
        let wrong_build = compiled_facts(0x12, 0xa1);
        assert_eq!(
            generate_manifest(
                fixture.descriptor.canonical_wire(),
                fixture.descriptor.descriptor_digest(),
                fixture.target,
                &fixture.artifact,
                wrong_build,
            ),
            Err(RuntimeInstallationError::CompiledBuildInstanceMismatch)
        );

        let wrong_fixture = compiled_facts(0x11, 0xb1);
        assert_eq!(
            generate_manifest(
                fixture.descriptor.canonical_wire(),
                fixture.descriptor.descriptor_digest(),
                fixture.target,
                &fixture.artifact,
                wrong_fixture,
            ),
            Err(RuntimeInstallationError::CompiledCompatibilityMismatch)
        );
    }

    #[test]
    fn strict_descriptor_decode_rejects_noncanonical_input() {
        let fixture = installation_fixture();
        let mut trailing = fixture.descriptor.canonical_wire().to_vec();
        trailing.push(0);
        assert_eq!(
            generate_manifest(
                &trailing,
                fixture.descriptor.descriptor_digest(),
                fixture.target,
                &fixture.artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::InvalidDescriptor)
        );
    }

    #[test]
    fn verify_existing_accepts_the_byte_identical_generated_artifact() {
        let fixture = installation_fixture();
        let generated = generate_manifest(
            fixture.descriptor.canonical_wire(),
            fixture.descriptor.descriptor_digest(),
            fixture.target,
            &fixture.artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));

        let verified = verify_existing(
            generated.descriptor_canonical_wire(),
            generated.descriptor_digest(),
            generated.manifest_canonical_wire(),
            generated.manifest_digest(),
            fixture.target,
            &fixture.artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("existing artifact verification failed: {error}"));
        assert_eq!(verified, generated);
    }

    #[test]
    fn verify_existing_rejects_manifest_wire_digest_target_identity_and_fixture_drift() {
        let fixture = installation_fixture();
        let generated = generate_manifest(
            fixture.descriptor.canonical_wire(),
            fixture.descriptor.descriptor_digest(),
            fixture.target,
            &fixture.artifact,
            fixture.compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));

        let mut trailing = generated.manifest_canonical_wire().to_vec();
        trailing.push(0);
        assert_eq!(
            verify_existing(
                generated.descriptor_canonical_wire(),
                generated.descriptor_digest(),
                &trailing,
                generated.manifest_digest(),
                fixture.target,
                &fixture.artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::InvalidManifest)
        );
        assert_eq!(
            verify_existing(
                generated.descriptor_canonical_wire(),
                generated.descriptor_digest(),
                generated.manifest_canonical_wire(),
                Digest32::from_bytes([0x93; 32]),
                fixture.target,
                &fixture.artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::ManifestDigestMismatch)
        );

        let other_target_manifest = RuntimeArtifactCompatibilityManifestV1::try_new(
            RuntimeHostId::from_bytes([0x06; 16]),
            &fixture.descriptor,
            fixture.compiled.fixture(),
        )
        .unwrap_or_else(|error| panic!("other-target manifest failed: {error}"));
        assert_eq!(
            verify_existing(
                fixture.descriptor.canonical_wire(),
                fixture.descriptor.descriptor_digest(),
                other_target_manifest.canonical_wire(),
                other_target_manifest.manifest_digest(),
                fixture.target,
                &fixture.artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::ManifestTargetMismatch)
        );

        let other_build = compiled_facts(0x21, 0xa1);
        let other_descriptor = RuntimeBuildDescriptorV1::try_new(
            other_build.build_instance_id(),
            fixture.artifact.runtime_artifact_length(),
            fixture.artifact.runtime_artifact_sha256(),
            fixture.artifact.target_triple().clone(),
            other_build.fixture(),
        )
        .unwrap_or_else(|error| panic!("other descriptor failed: {error}"));
        let other_identity_manifest = RuntimeArtifactCompatibilityManifestV1::try_new(
            fixture.target,
            &other_descriptor,
            other_build.fixture(),
        )
        .unwrap_or_else(|error| panic!("other identity manifest failed: {error}"));
        assert_eq!(
            verify_existing(
                fixture.descriptor.canonical_wire(),
                fixture.descriptor.descriptor_digest(),
                other_identity_manifest.canonical_wire(),
                other_identity_manifest.manifest_digest(),
                fixture.target,
                &fixture.artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::ManifestBuildIdentityMismatch)
        );

        let other_fixture = compiled_facts(0x11, 0xb1);
        let other_fixture_descriptor = RuntimeBuildDescriptorV1::try_new(
            other_fixture.build_instance_id(),
            fixture.artifact.runtime_artifact_length(),
            fixture.artifact.runtime_artifact_sha256(),
            fixture.artifact.target_triple().clone(),
            other_fixture.fixture(),
        )
        .unwrap_or_else(|error| panic!("other fixture descriptor failed: {error}"));
        let other_fixture_manifest = RuntimeArtifactCompatibilityManifestV1::try_new(
            fixture.target,
            &other_fixture_descriptor,
            other_fixture.fixture(),
        )
        .unwrap_or_else(|error| panic!("other fixture manifest failed: {error}"));
        assert_eq!(
            verify_existing(
                fixture.descriptor.canonical_wire(),
                fixture.descriptor.descriptor_digest(),
                other_fixture_manifest.canonical_wire(),
                other_fixture_manifest.manifest_digest(),
                fixture.target,
                &fixture.artifact,
                fixture.compiled,
            ),
            Err(RuntimeInstallationError::ManifestFixtureMismatch)
        );
    }

    #[test]
    fn invalid_artifact_observation_is_rejected_before_verification() {
        assert_eq!(
            InstalledRuntimeArtifactObservationV1::try_new(
                0,
                Digest32::from_bytes([1; 32]),
                "aarch64-unknown-linux-gnu",
            ),
            Err(RuntimeInstallationError::InvalidArtifactLength)
        );
        assert_eq!(
            InstalledRuntimeArtifactObservationV1::try_new(
                MAX_RUNTIME_ARTIFACT_BYTES + 1,
                Digest32::from_bytes([1; 32]),
                "aarch64-unknown-linux-gnu",
            ),
            Err(RuntimeInstallationError::InvalidArtifactLength)
        );
        assert_eq!(
            InstalledRuntimeArtifactObservationV1::try_new(
                1,
                Digest32::from_bytes([0; 32]),
                "aarch64-unknown-linux-gnu",
            ),
            Err(RuntimeInstallationError::InvalidArtifactDigest)
        );
        assert_eq!(
            InstalledRuntimeArtifactObservationV1::try_new(
                1,
                Digest32::from_bytes([1; 32]),
                "AARCH64-unknown-linux-gnu",
            ),
            Err(RuntimeInstallationError::InvalidTargetTriple)
        );
        assert_eq!(
            RuntimeCompiledInstallationFactsV1::try_new(
                [0; 32],
                CardDefinitionRef::from_bytes([1; 16]),
                CardImplementationRef::from_bytes([2; 16]),
                [3; 16],
                Digest32::from_bytes([4; 32]),
                Digest32::from_bytes([5; 32]),
            ),
            Err(RuntimeInstallationError::InvalidBuildInstanceId)
        );
    }
}
