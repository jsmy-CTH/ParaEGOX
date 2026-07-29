//! Deployment-owned identities used by the internal commitment producer.

use paraegox_kernel::identity::RuntimeHostId;
use paraegox_runtime_contracts::apply::WriterTenureProof;
use paraegox_runtime_contracts::provenance::{SourcePlanDigest, TargetAssignmentDigest};

macro_rules! deployment_ref {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates an opaque deployment-owned reference from canonical bytes.
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

deployment_ref!(
    DeploymentScopeId,
    "Deployment-owned identity of a desired-state writer scope."
);
deployment_ref!(
    DeploymentId,
    "Deployment-owned identity of one committed plan lineage."
);
deployment_ref!(
    DeploymentWriterRef,
    "Deployment-owned identity of the active plan writer."
);

/// Deployment-owned monotonically ordered committed revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeploymentRevision(u64);

impl DeploymentRevision {
    /// Creates a deployment revision value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the ordered revision value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Deployment-owned monotonically ordered writer tenure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeploymentWriterEpoch(u64);

impl DeploymentWriterEpoch {
    /// Creates a deployment writer epoch value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the ordered writer epoch value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Identity and digest already assigned by the committed-plan owner.
///
/// This is not a replacement for the future complete DeploymentPlan body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CommittedPlanIdentity {
    scope: DeploymentScopeId,
    plan: DeploymentId,
    revision: DeploymentRevision,
    digest: SourcePlanDigest,
}

impl CommittedPlanIdentity {
    /// Creates the immutable identity portion of an already committed plan.
    #[must_use]
    pub const fn new(
        scope: DeploymentScopeId,
        plan: DeploymentId,
        revision: DeploymentRevision,
        digest: SourcePlanDigest,
    ) -> Self {
        Self {
            scope,
            plan,
            revision,
            digest,
        }
    }

    /// Returns the deployment desired-state scope.
    #[must_use]
    pub const fn scope(&self) -> DeploymentScopeId {
        self.scope
    }

    /// Returns the deployment plan identity.
    #[must_use]
    pub const fn plan(&self) -> DeploymentId {
        self.plan
    }

    /// Returns the deployment revision.
    #[must_use]
    pub const fn revision(&self) -> DeploymentRevision {
        self.revision
    }

    /// Returns the exact committed-plan digest in its runtime wire type.
    #[must_use]
    pub const fn digest(&self) -> SourcePlanDigest {
        self.digest
    }
}

/// One committed target projection, represented without fabricating assignments.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CommittedTargetProjection {
    plan: CommittedPlanIdentity,
    target: RuntimeHostId,
    assignment_digest: TargetAssignmentDigest,
}

impl CommittedTargetProjection {
    /// Binds a complete assignment commitment to a committed plan and target.
    #[must_use]
    pub const fn new(
        plan: CommittedPlanIdentity,
        target: RuntimeHostId,
        assignment_digest: TargetAssignmentDigest,
    ) -> Self {
        Self {
            plan,
            target,
            assignment_digest,
        }
    }

    /// Returns committed source-plan identity.
    #[must_use]
    pub const fn plan(&self) -> CommittedPlanIdentity {
        self.plan
    }

    /// Returns the target RuntimeHost.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    /// Returns the digest of the target's complete canonical assignment.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.assignment_digest
    }
}

/// Deployment-owned writer identity paired with its authority proof.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DeploymentWriterTenure {
    writer: DeploymentWriterRef,
    epoch: DeploymentWriterEpoch,
    proof: WriterTenureProof,
}

impl DeploymentWriterTenure {
    /// Creates a deployment-side tenure value for canonical runtime mapping.
    #[must_use]
    pub const fn new(
        writer: DeploymentWriterRef,
        epoch: DeploymentWriterEpoch,
        proof: WriterTenureProof,
    ) -> Self {
        Self {
            writer,
            epoch,
            proof,
        }
    }

    /// Returns deployment-owned writer identity.
    #[must_use]
    pub const fn writer(&self) -> DeploymentWriterRef {
        self.writer
    }

    /// Returns deployment-owned writer tenure.
    #[must_use]
    pub const fn epoch(&self) -> DeploymentWriterEpoch {
        self.epoch
    }

    /// Returns the runtime-consumer-owned authority proof envelope.
    #[must_use]
    pub const fn proof(&self) -> &WriterTenureProof {
        &self.proof
    }

    /// Splits the value so the proof can be moved into runtime writer context.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        DeploymentWriterRef,
        DeploymentWriterEpoch,
        WriterTenureProof,
    ) {
        (self.writer, self.epoch, self.proof)
    }
}
