//! Installer-bound immutable manifest ingress for the pure Planner.
//!
//! This adapter owns no manifest codec, digest domain, or caller-controlled
//! projection fields. Its production path strictly decodes the exact installer
//! artifact plus its separately carried digest; Planner restart accepts only a
//! strict canonical projection plus that same manifest digest.

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};
#[cfg(test)]
use paraegox_runtime_contracts::installation::VerifiedRuntimeInstallationV1;
use paraegox_runtime_contracts::installation::{
    RuntimeInstallationError, VerifiedRuntimeManifestIngressV1, verify_immutable_manifest_ingress,
    verify_immutable_manifest_projection_ingress,
};

/// Controller-owned pin of the exact installed manifest and its derived Planner
/// projection.
///
/// There is deliberately no constructor from caller-supplied target, fixture,
/// profile, or projection fields.  A fresh pin consumes a sealed Runtime
/// contract token; a restarted Controller must strictly decode the exact
/// persisted manifest bytes together with their separately persisted digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerInstalledManifestPin {
    projection: InstalledManifestProjectionIngress,
}

impl ControllerInstalledManifestPin {
    /// Pins an already verified Runtime-contract manifest token.
    #[must_use]
    pub(crate) fn from_verified_manifest(verified: VerifiedRuntimeManifestIngressV1) -> Self {
        Self {
            projection: InstalledManifestProjectionIngress::from_verified_manifest(verified),
        }
    }

    /// Test adapter proving the installer token and persisted restart paths agree.
    #[cfg(test)]
    pub(crate) fn from_verified_installation(
        installation: &VerifiedRuntimeInstallationV1,
    ) -> Result<Self, RuntimeInstallationError> {
        Ok(Self::from_verified_manifest(
            installation.immutable_manifest_ingress()?,
        ))
    }

    /// Strictly restores an installed pin from its exact persisted bytes and
    /// independently persisted digest.
    pub(crate) fn try_from_persisted_manifest(
        canonical_manifest_wire: &[u8],
        expected_manifest_digest: Digest32,
    ) -> Result<Self, RuntimeInstallationError> {
        Ok(Self::from_verified_manifest(
            verify_immutable_manifest_ingress(canonical_manifest_wire, expected_manifest_digest)?,
        ))
    }

    #[must_use]
    pub(crate) fn canonical_manifest_wire(&self) -> &[u8] {
        self.projection.verified.manifest_canonical_wire()
    }

    #[must_use]
    pub(crate) const fn manifest_digest(&self) -> Digest32 {
        self.projection.manifest_digest()
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.projection.target()
    }

    #[must_use]
    pub(crate) const fn projection(&self) -> &InstalledManifestProjectionIngress {
        &self.projection
    }

    /// Returns the sealed installer-derived manifest token for Controller-side
    /// bootstrap expectation construction. Normal operation never rereads the
    /// installer manifest file.
    #[must_use]
    pub(crate) const fn verified_manifest(&self) -> &VerifiedRuntimeManifestIngressV1 {
        &self.projection.verified
    }
}

/// Sealed, immutable Planner view of one installer-produced singleton manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InstalledManifestProjectionIngress {
    verified: VerifiedRuntimeManifestIngressV1,
}

impl InstalledManifestProjectionIngress {
    #[must_use]
    fn from_verified_manifest(verified: VerifiedRuntimeManifestIngressV1) -> Self {
        Self { verified }
    }

    /// Test adapter proving the installer token and persisted projection agree.
    #[cfg(test)]
    pub(crate) fn from_verified_installation(
        installation: &VerifiedRuntimeInstallationV1,
    ) -> Result<Self, RuntimeInstallationError> {
        Ok(Self::from_verified_manifest(
            installation.immutable_manifest_ingress()?,
        ))
    }

    /// Strictly reconstructs the ingress embedded in persisted `PlanContent`.
    pub(crate) fn try_from_persisted_projection(
        canonical_projection: &[u8],
        expected_manifest_digest: Digest32,
    ) -> Result<Self, RuntimeInstallationError> {
        Ok(Self {
            verified: verify_immutable_manifest_projection_ingress(
                canonical_projection,
                expected_manifest_digest,
            )?,
        })
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.verified.target()
    }

    #[must_use]
    pub(crate) const fn manifest_digest(&self) -> Digest32 {
        self.verified.manifest_digest()
    }

    #[must_use]
    pub(crate) fn canonical_projection(&self) -> &[u8] {
        self.verified.projection_canonical_wire()
    }

    #[must_use]
    pub(crate) const fn profile_fingerprint(&self) -> Digest32 {
        self.verified.profile_fingerprint()
    }

    #[must_use]
    pub(crate) const fn canonical_empty_config_digest(&self) -> Digest32 {
        self.verified.canonical_empty_config_digest()
    }

    #[must_use]
    pub(crate) const fn fixture_definition(&self) -> CardDefinitionRef {
        self.verified.fixture_definition()
    }

    #[must_use]
    pub(crate) const fn fixture_implementation(&self) -> CardImplementationRef {
        self.verified.fixture_implementation()
    }

    #[must_use]
    pub(crate) const fn fixture_export(&self) -> [u8; 16] {
        self.verified.fixture_export()
    }

    #[must_use]
    pub(crate) const fn fixture_definition_digest(&self) -> Digest32 {
        self.verified.fixture_definition_digest()
    }

    #[must_use]
    pub(crate) const fn fixture_artifact_digest(&self) -> Digest32 {
        self.verified.fixture_artifact_digest()
    }
}

#[cfg(test)]
mod tests {
    use super::{ControllerInstalledManifestPin, InstalledManifestProjectionIngress};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};
    use paraegox_runtime_contracts::installation::{
        InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
        RuntimeInstallationError, generate_build_descriptor, generate_manifest,
    };

    fn installed() -> paraegox_runtime_contracts::installation::VerifiedRuntimeInstallationV1 {
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x22; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .expect("artifact facts");
        let compiled = RuntimeCompiledInstallationFactsV1::try_new(
            [0x11; 32],
            CardDefinitionRef::from_bytes([0xa1; 16]),
            CardImplementationRef::from_bytes([0xa2; 16]),
            [0xa3; 16],
            Digest32::from_bytes([0xa4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        )
        .expect("compiled facts");
        let descriptor = generate_build_descriptor(&artifact, compiled).expect("descriptor");
        generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            RuntimeHostId::from_bytes([0x05; 16]),
            &artifact,
            compiled,
        )
        .expect("manifest")
    }

    #[test]
    fn installer_and_persisted_projection_paths_produce_the_same_sealed_ingress() {
        let installation = installed();
        let ingress = InstalledManifestProjectionIngress::from_verified_installation(&installation)
            .expect("installer ingress");
        let recovered = InstalledManifestProjectionIngress::try_from_persisted_projection(
            ingress.canonical_projection(),
            ingress.manifest_digest(),
        )
        .expect("persisted projection ingress");
        assert_eq!(recovered, ingress);

        let mut trailing = ingress.canonical_projection().to_vec();
        trailing.push(0);
        assert_eq!(
            InstalledManifestProjectionIngress::try_from_persisted_projection(
                &trailing,
                ingress.manifest_digest(),
            ),
            Err(RuntimeInstallationError::InvalidManifest)
        );
        assert_eq!(
            InstalledManifestProjectionIngress::try_from_persisted_projection(
                ingress.canonical_projection(),
                Digest32::from_bytes([0x7f; 32]),
            ),
            Err(RuntimeInstallationError::ManifestDigestMismatch)
        );
    }

    #[test]
    fn controller_pin_retains_exact_manifest_and_only_restores_strict_bytes() {
        let installation = installed();
        let pin = ControllerInstalledManifestPin::from_verified_installation(&installation)
            .expect("installer pin");
        assert_eq!(
            pin.canonical_manifest_wire(),
            installation.manifest_canonical_wire()
        );
        assert_eq!(pin.manifest_digest(), installation.manifest_digest());
        assert_eq!(pin.target(), RuntimeHostId::from_bytes([0x05; 16]));

        let restored = ControllerInstalledManifestPin::try_from_persisted_manifest(
            pin.canonical_manifest_wire(),
            pin.manifest_digest(),
        )
        .expect("persisted pin");
        assert_eq!(restored, pin);
        assert_eq!(restored.projection(), pin.projection());

        let mut trailing = pin.canonical_manifest_wire().to_vec();
        trailing.push(0);
        assert_eq!(
            ControllerInstalledManifestPin::try_from_persisted_manifest(
                &trailing,
                pin.manifest_digest(),
            ),
            Err(RuntimeInstallationError::InvalidManifest)
        );
        assert_eq!(
            ControllerInstalledManifestPin::try_from_persisted_manifest(
                pin.canonical_manifest_wire(),
                Digest32::from_bytes([0x7f; 32]),
            ),
            Err(RuntimeInstallationError::ManifestDigestMismatch)
        );
    }
}
