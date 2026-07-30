//! Source-plan provenance and target-slice commitments.

use core::fmt;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;

/// The only contract version admitted by the B1 control spine.
pub const RUNTIME_SLICE_HEADER_VERSION: u16 = 1;
const TARGET_SLICE_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-slice.sha256.v1";

macro_rules! opaque_ref {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates an opaque reference from canonical bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Returns the canonical reference bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_ref!(
    SourceScopeRef,
    "Consumer-owned opaque reference to the source desired-state scope."
);
opaque_ref!(
    SourcePlanRef,
    "Consumer-owned opaque reference to the source committed plan."
);

/// Consumer-owned source plan revision; its deployment type never enters Runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourcePlanRevision(u64);

impl SourcePlanRevision {
    /// Creates a source revision without assigning revision ownership to Runtime.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the monotonically ordered source revision value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Digest of the exact committed source plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourcePlanDigest(Digest32);

impl SourcePlanDigest {
    /// Creates a typed source-plan digest.
    #[must_use]
    pub const fn new(value: Digest32) -> Self {
        Self(value)
    }

    /// Returns the underlying canonical digest.
    #[must_use]
    pub const fn value(&self) -> &Digest32 {
        &self.0
    }
}

/// Digest of one target's complete canonical assignment body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetAssignmentDigest(Digest32);

impl TargetAssignmentDigest {
    /// Creates a typed target-assignment commitment.
    #[must_use]
    pub const fn new(value: Digest32) -> Self {
        Self(value)
    }

    /// Returns the underlying canonical digest.
    #[must_use]
    pub const fn value(&self) -> &Digest32 {
        &self.0
    }
}

/// Digest of target, source provenance, and assignment commitment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetSliceDigest(Digest32);

impl TargetSliceDigest {
    /// Creates a typed target-slice digest from validated canonical bytes.
    #[must_use]
    pub const fn new(value: Digest32) -> Self {
        Self(value)
    }

    /// Returns the underlying canonical digest.
    #[must_use]
    pub const fn value(&self) -> &Digest32 {
        &self.0
    }
}

/// Runtime-owned view of the plan source; it contains no deployment domain type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PlanProvenance {
    source_scope: SourceScopeRef,
    source_plan: SourcePlanRef,
    source_revision: SourcePlanRevision,
    source_plan_digest: SourcePlanDigest,
}

impl PlanProvenance {
    /// Creates source provenance after the deployment producer maps its identities.
    #[must_use]
    pub const fn new(
        source_scope: SourceScopeRef,
        source_plan: SourcePlanRef,
        source_revision: SourcePlanRevision,
        source_plan_digest: SourcePlanDigest,
    ) -> Self {
        Self {
            source_scope,
            source_plan,
            source_revision,
            source_plan_digest,
        }
    }

    /// Returns the source desired-state scope.
    #[must_use]
    pub const fn source_scope(&self) -> SourceScopeRef {
        self.source_scope
    }

    /// Returns the source committed-plan identity.
    #[must_use]
    pub const fn source_plan(&self) -> SourcePlanRef {
        self.source_plan
    }

    /// Returns the source committed-plan revision.
    #[must_use]
    pub const fn source_revision(&self) -> SourcePlanRevision {
        self.source_revision
    }

    /// Returns the exact source-plan digest.
    #[must_use]
    pub const fn source_plan_digest(&self) -> SourcePlanDigest {
        self.source_plan_digest
    }
}

/// Long-lived header later embedded unchanged in a complete runtime slice.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeSliceHeader {
    contract_version: u16,
    target: RuntimeHostId,
    provenance: PlanProvenance,
    assignment_digest: TargetAssignmentDigest,
}

impl RuntimeSliceHeader {
    /// Creates a v1 header that commits to, but does not fabricate, assignments.
    #[must_use]
    pub const fn new(
        target: RuntimeHostId,
        provenance: PlanProvenance,
        assignment_digest: TargetAssignmentDigest,
    ) -> Self {
        Self {
            contract_version: RUNTIME_SLICE_HEADER_VERSION,
            target,
            provenance,
            assignment_digest,
        }
    }

    /// Returns the header contract version.
    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }

    /// Returns the target RuntimeHost.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    /// Returns source-plan provenance.
    #[must_use]
    pub const fn provenance(&self) -> PlanProvenance {
        self.provenance
    }

    /// Returns the commitment to the complete target assignment body.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.assignment_digest
    }
}

/// Target-specific commitment consumed by the B1 apply-control state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeSliceCommitment {
    header: RuntimeSliceHeader,
    target_slice_digest: TargetSliceDigest,
}

impl RuntimeSliceCommitment {
    /// Canonically commits the header using SHA-256-v1.
    pub fn try_new(header: RuntimeSliceHeader) -> Result<Self, ProvenanceContractError> {
        let mut builder = Digest32Builder::try_new(TARGET_SLICE_DIGEST_DOMAIN)?;
        builder.field_u16(header.contract_version())?;
        builder.field_bytes(header.target().as_bytes())?;
        builder.field_bytes(header.provenance().source_scope().as_bytes())?;
        builder.field_bytes(header.provenance().source_plan().as_bytes())?;
        builder.field_u64(header.provenance().source_revision().value())?;
        builder.field_digest(header.provenance().source_plan_digest().value())?;
        builder.field_digest(header.assignment_digest().value())?;

        Ok(Self {
            header,
            target_slice_digest: TargetSliceDigest::new(builder.finish()),
        })
    }

    /// Returns the committed header.
    #[must_use]
    pub const fn header(&self) -> RuntimeSliceHeader {
        self.header
    }

    /// Returns the target-slice digest.
    #[must_use]
    pub const fn target_slice_digest(&self) -> TargetSliceDigest {
        self.target_slice_digest
    }

    /// Recomputes the commitment and rejects mismatched stored digests.
    pub fn validate(&self) -> Result<(), ProvenanceContractError> {
        let recomputed = Self::try_new(self.header)?;
        if recomputed.target_slice_digest != self.target_slice_digest {
            return Err(ProvenanceContractError::TargetSliceDigestMismatch);
        }
        Ok(())
    }
}

/// Fail-closed errors for slice provenance and commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceContractError {
    /// Canonical digest construction failed.
    Digest(DigestBuildError),
    /// A stored target-slice digest does not match its header.
    TargetSliceDigestMismatch,
}

impl From<DigestBuildError> for ProvenanceContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ProvenanceContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(error) => write!(formatter, "canonical digest failed: {error}"),
            Self::TargetSliceDigestMismatch => {
                formatter.write_str("target-slice digest does not match its header")
            }
        }
    }
}

impl std::error::Error for ProvenanceContractError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;

    use super::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
    };

    #[derive(Clone, Copy)]
    struct SliceFixture {
        target_byte: u8,
        scope_byte: u8,
        plan_byte: u8,
        revision: u64,
        plan_digest_byte: u8,
        assignment_byte: u8,
    }

    const fn fixture() -> SliceFixture {
        SliceFixture {
            target_byte: 5,
            scope_byte: 1,
            plan_byte: 2,
            revision: 3,
            plan_digest_byte: 4,
            assignment_byte: 6,
        }
    }

    fn commitment(fixture: SliceFixture) -> RuntimeSliceCommitment {
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([fixture.scope_byte; 16]),
            SourcePlanRef::from_bytes([fixture.plan_byte; 16]),
            SourcePlanRevision::new(fixture.revision),
            SourcePlanDigest::new(Digest32::from_bytes([fixture.plan_digest_byte; 32])),
        );
        let header = RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes([fixture.target_byte; 16]),
            provenance,
            TargetAssignmentDigest::new(Digest32::from_bytes([fixture.assignment_byte; 32])),
        );
        let Ok(value) = RuntimeSliceCommitment::try_new(header) else {
            panic!("valid commitment fixture must build");
        };
        value
    }

    #[test]
    fn target_slice_has_a_stable_golden_vector() {
        let first = commitment(fixture());
        let second = commitment(fixture());
        let expected = [
            0x78, 0x9d, 0x23, 0x48, 0x56, 0xf3, 0x17, 0x04, 0xa0, 0xa5, 0x8c, 0x49, 0x1c, 0xd3,
            0x69, 0x34, 0x69, 0xd4, 0xa9, 0xe3, 0x80, 0xe3, 0x3e, 0x85, 0x3e, 0xc0, 0x4a, 0x16,
            0xd5, 0x42, 0x29, 0x80,
        ];

        assert_eq!(first, second);
        assert_eq!(first.target_slice_digest().value().as_bytes(), &expected);
        assert_eq!(first.validate(), Ok(()));
    }

    #[test]
    fn every_slice_header_field_is_committed() {
        let baseline = commitment(fixture());
        let mut variations = [fixture(); 6];
        variations[0].target_byte = 0x15;
        variations[1].scope_byte = 0x11;
        variations[2].plan_byte = 0x12;
        variations[3].revision = 4;
        variations[4].plan_digest_byte = 0x14;
        variations[5].assignment_byte = 0x16;

        for changed in variations {
            assert_ne!(baseline, commitment(changed));
        }
    }

    #[test]
    fn stored_slice_digest_is_revalidated() {
        let mut corrupted = commitment(fixture());
        corrupted.target_slice_digest =
            super::TargetSliceDigest::new(Digest32::from_bytes([99; 32]));

        assert_eq!(
            corrupted.validate(),
            Err(super::ProvenanceContractError::TargetSliceDigestMismatch)
        );
    }
}
