//! Experimental node-local Inspection projection.
//!
//! This crate does not discover, authenticate, poll, or mutate source owners.
//! Callers may construct [`OwnerInspectionFactV1`] only after an owner-specific
//! adapter has verified the source fact. The local service then owns only its
//! projection revision and last immutable snapshot. It is not a registry,
//! heartbeat owner, desired-state store, health authority, Evidence store, or
//! operational control path.
//!
//! PXIS-v2 is an explicit successor that embeds the complete canonical
//! PXIS-v1 snapshot unchanged and appends one bounded public-safe NodeDaemon
//! record. It does not widen the frozen PXIS-v1 owner set.
//!
//! Observation timestamps and `projected_at_nanos` are comparable only inside
//! the exact [`InspectionObservationClockRefV1`] supplied by the local
//! Inspection owner. They are never compared across Node monotonic clocks.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder};

/// Owner-neutral source adapter and strict projection-input assembly seam.
pub mod adapter;
#[cfg(unix)]
/// Strict non-production same-user bootstrap and framing for node-local reads.
pub mod developer_local;
/// Strict transport-neutral read-only query protocol and client seam.
pub mod protocol;

/// Strict PXIS snapshot version.
pub const LOCAL_INSPECTION_SNAPSHOT_VERSION: u16 = 1;
/// The first local slice projects exactly the five currently admitted owners.
pub const LOCAL_INSPECTION_OWNER_COUNT: usize = 5;
/// Fixed canonical byte length of one PXIS-v1 snapshot.
pub const LOCAL_INSPECTION_SNAPSHOT_BYTES: usize =
    SNAPSHOT_HEADER_BYTES + LOCAL_INSPECTION_OWNER_COUNT * RECORD_BYTES;
/// Strict PXIS-v2 composite snapshot version.
pub const LOCAL_INSPECTION_SNAPSHOT_V2_VERSION: u16 = 2;
/// Fixed canonical byte length of one PXIS-v2 composite snapshot.
///
/// The payload contains one byte-exact PXIS-v1 five-owner snapshot followed by
/// one public-safe NodeDaemon projection record. PXIS-v1 bytes and semantics
/// remain unchanged.
pub const LOCAL_INSPECTION_SNAPSHOT_V2_BYTES: usize =
    SNAPSHOT_V2_HEADER_BYTES + LOCAL_INSPECTION_SNAPSHOT_BYTES + NODE_RECORD_V2_BYTES;

const SNAPSHOT_MAGIC: &[u8; 4] = b"PXIS";
const SNAPSHOT_HEADER_BYTES: usize = 112;
const SNAPSHOT_DIGEST_OFFSET: usize = 80;
const RECORD_BYTES: usize = 96;
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.local-snapshot.v1";
const SNAPSHOT_V2_HEADER_BYTES: usize = 112;
const SNAPSHOT_V2_DIGEST_OFFSET: usize = 80;
const NODE_RECORD_V2_BYTES: usize = 128;
const SNAPSHOT_V2_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.local-snapshot.v2";

/// The source owner of one public-safe fact.
///
/// Values deliberately name owners rather than generic components. Their
/// coordinates are not interchangeable even when numeric values happen to
/// match.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum InspectionSourceOwnerV1 {
    Authority = 1,
    DeploymentController = 2,
    RuntimeHost = 3,
    FabricService = 4,
    AgentService = 5,
}

impl InspectionSourceOwnerV1 {
    const ALL: [Self; LOCAL_INSPECTION_OWNER_COUNT] = [
        Self::Authority,
        Self::DeploymentController,
        Self::RuntimeHost,
        Self::FabricService,
        Self::AgentService,
    ];

    fn decode(value: u8) -> Result<Self, InspectionContractError> {
        match value {
            1 => Ok(Self::Authority),
            2 => Ok(Self::DeploymentController),
            3 => Ok(Self::RuntimeHost),
            4 => Ok(Self::FabricService),
            5 => Ok(Self::AgentService),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }
}

/// Inspection-owner-local clock domain for freshness comparisons.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InspectionObservationClockRefV1([u8; 16]);

impl InspectionObservationClockRefV1 {
    /// Creates a nonzero local observation-clock reference.
    pub fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, InspectionContractError> {
        if bytes_are_zero(&bytes) {
            return Err(InspectionContractError::ZeroObservationClockRef);
        }
        Ok(Self(bytes))
    }

    /// Returns the canonical reference bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Owner-specific generation/revision plus the owner's local fact sequence.
///
/// The variant is part of the type so a DeploymentRevision cannot silently be
/// treated as a RuntimeHostEpoch or managed-service generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InspectionSourceCoordinateV1 {
    AuthorityTenure {
        tenure_epoch: u64,
        fact_sequence: u64,
    },
    DeploymentRevision {
        revision: u64,
        fact_sequence: u64,
    },
    RuntimeHostEpoch {
        runtime_host_epoch: u64,
        snapshot_sequence: u64,
    },
    FabricServiceGeneration {
        service_generation: u64,
        observation_sequence: u64,
    },
    AgentServiceGeneration {
        service_generation: u64,
        observation_sequence: u64,
    },
}

impl InspectionSourceCoordinateV1 {
    fn owner(self) -> InspectionSourceOwnerV1 {
        match self {
            Self::AuthorityTenure { .. } => InspectionSourceOwnerV1::Authority,
            Self::DeploymentRevision { .. } => InspectionSourceOwnerV1::DeploymentController,
            Self::RuntimeHostEpoch { .. } => InspectionSourceOwnerV1::RuntimeHost,
            Self::FabricServiceGeneration { .. } => InspectionSourceOwnerV1::FabricService,
            Self::AgentServiceGeneration { .. } => InspectionSourceOwnerV1::AgentService,
        }
    }

    fn kind(self) -> u8 {
        self.owner() as u8
    }

    fn values(self) -> (u64, u64) {
        match self {
            Self::AuthorityTenure {
                tenure_epoch,
                fact_sequence,
            } => (tenure_epoch, fact_sequence),
            Self::DeploymentRevision {
                revision,
                fact_sequence,
            } => (revision, fact_sequence),
            Self::RuntimeHostEpoch {
                runtime_host_epoch,
                snapshot_sequence,
            } => (runtime_host_epoch, snapshot_sequence),
            Self::FabricServiceGeneration {
                service_generation,
                observation_sequence,
            }
            | Self::AgentServiceGeneration {
                service_generation,
                observation_sequence,
            } => (service_generation, observation_sequence),
        }
    }

    fn decode(kind: u8, value: u64, sequence: u64) -> Result<Self, InspectionContractError> {
        if value == 0 || sequence == 0 {
            return Err(InspectionContractError::ZeroSourceCoordinate);
        }
        match kind {
            1 => Ok(Self::AuthorityTenure {
                tenure_epoch: value,
                fact_sequence: sequence,
            }),
            2 => Ok(Self::DeploymentRevision {
                revision: value,
                fact_sequence: sequence,
            }),
            3 => Ok(Self::RuntimeHostEpoch {
                runtime_host_epoch: value,
                snapshot_sequence: sequence,
            }),
            4 => Ok(Self::FabricServiceGeneration {
                service_generation: value,
                observation_sequence: sequence,
            }),
            5 => Ok(Self::AgentServiceGeneration {
                service_generation: value,
                observation_sequence: sequence,
            }),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }
}

/// Whether the owner adapter has an explicit current path to the source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionSourceAvailabilityV1 {
    /// The adapter observed the owner fact. Freshness is then determined from
    /// `observed_at` and `valid_until` in the same Inspection clock domain.
    Observed = 1,
    /// The owner or transport explicitly reported a partition. Inspection
    /// never infers this state merely from a freshness timeout.
    Partitioned = 2,
}

/// Liveness is process/control responsiveness, not readiness or health.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionLivenessV1 {
    Unknown = 0,
    Bootstrapping = 1,
    Live = 2,
    Unresponsive = 3,
    Exited = 4,
    Quarantined = 5,
}

impl InspectionLivenessV1 {
    fn decode(value: u8) -> Result<Self, InspectionContractError> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Bootstrapping),
            2 => Ok(Self::Live),
            3 => Ok(Self::Unresponsive),
            4 => Ok(Self::Exited),
            5 => Ok(Self::Quarantined),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }
}

/// Readiness is ability to serve the exact current desired contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionReadinessV1 {
    Unknown = 0,
    Ready = 1,
    NotReady = 2,
    Degraded = 3,
    Blocked = 4,
}

impl InspectionReadinessV1 {
    fn decode(value: u8) -> Result<Self, InspectionContractError> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Ready),
            2 => Ok(Self::NotReady),
            3 => Ok(Self::Degraded),
            4 => Ok(Self::Blocked),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }
}

/// Health is the owner's diagnostic condition, not proof of readiness.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionHealthV1 {
    Unknown = 0,
    Healthy = 1,
    Degraded = 2,
    Faulted = 3,
}

impl InspectionHealthV1 {
    fn decode(value: u8) -> Result<Self, InspectionContractError> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Healthy),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::Faulted),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }
}

/// Support for the exact required feature set used by this local projection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionFeatureSupportV1 {
    Unknown = 0,
    AllRequiredSupported = 1,
    RequiredUnsupported = 2,
}

impl InspectionFeatureSupportV1 {
    fn decode(value: u8) -> Result<Self, InspectionContractError> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::AllRequiredSupported),
            2 => Ok(Self::RequiredUnsupported),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }
}

/// Bounded public reason vocabulary; no raw log, path, key, or transport data
/// is projected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionReasonV1 {
    None = 0,
    Bootstrapping = 1,
    DependencyUnavailable = 2,
    OwnerReportedDegraded = 3,
    OwnerReportedFailure = 4,
    FeatureUnsupported = 5,
    Quarantined = 6,
    OutcomeUncertain = 7,
    SourceUnknown = 8,
    SourceMissing = 9,
    SourceStale = 10,
    SourcePartitioned = 11,
}

impl InspectionReasonV1 {
    fn decode(value: u8) -> Result<Self, InspectionContractError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Bootstrapping),
            2 => Ok(Self::DependencyUnavailable),
            3 => Ok(Self::OwnerReportedDegraded),
            4 => Ok(Self::OwnerReportedFailure),
            5 => Ok(Self::FeatureUnsupported),
            6 => Ok(Self::Quarantined),
            7 => Ok(Self::OutcomeUncertain),
            8 => Ok(Self::SourceUnknown),
            9 => Ok(Self::SourceMissing),
            10 => Ok(Self::SourceStale),
            11 => Ok(Self::SourcePartitioned),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }

    fn is_projection_owned(self) -> bool {
        matches!(
            self,
            Self::SourceMissing | Self::SourceStale | Self::SourcePartitioned
        )
    }
}

/// Freshness of one projected source record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionFreshnessV1 {
    Fresh = 1,
    Stale = 2,
    Partitioned = 3,
    Missing = 4,
}

impl InspectionFreshnessV1 {
    fn decode(value: u8) -> Result<Self, InspectionContractError> {
        match value {
            1 => Ok(Self::Fresh),
            2 => Ok(Self::Stale),
            3 => Ok(Self::Partitioned),
            4 => Ok(Self::Missing),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }
}

/// Conservative aggregate state for the exact five-owner local projection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum LocalInspectionOverallV1 {
    /// Every owner is fresh, live, ready, healthy, and supports all required
    /// features.
    Ready = 1,
    /// At least one owner reports a current degraded condition.
    Degraded = 2,
    /// A current source explicitly reports an unavailable/faulted/unsupported
    /// condition.
    Unavailable = 3,
    /// Missing, stale, partitioned, or owner-unknown facts prevent a claim.
    Unknown = 4,
}

impl LocalInspectionOverallV1 {
    fn decode(value: u8) -> Result<Self, InspectionContractError> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::Unavailable),
            4 => Ok(Self::Unknown),
            _ => Err(InspectionContractError::UnknownEnumValue),
        }
    }
}

/// Public-safe fields copied only after an owner-specific adapter has verified
/// the source fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerInspectionFactFieldsV1 {
    pub owner: InspectionSourceOwnerV1,
    pub subject_ref: [u8; 16],
    pub coordinate: InspectionSourceCoordinateV1,
    pub observation_clock_ref: InspectionObservationClockRefV1,
    pub observed_at_nanos: u64,
    pub valid_until_nanos: u64,
    pub availability: InspectionSourceAvailabilityV1,
    pub liveness: InspectionLivenessV1,
    pub readiness: InspectionReadinessV1,
    pub health: InspectionHealthV1,
    pub feature_support: InspectionFeatureSupportV1,
    pub reason: InspectionReasonV1,
    /// Digest of the immutable owner-issued fact or Receipt selected by the
    /// adapter. Inspection correlates it but never fabricates an EffectReceipt.
    pub owner_fact_digest: Digest32,
}

/// Validated immutable fact accepted by the pure local projector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerInspectionFactV1(OwnerInspectionFactFieldsV1);

impl OwnerInspectionFactV1 {
    /// Validates public shape, owner-coordinate identity, local observation
    /// time, and cross-dimension consistency.
    pub fn try_new(fields: OwnerInspectionFactFieldsV1) -> Result<Self, InspectionContractError> {
        if bytes_are_zero(&fields.subject_ref) {
            return Err(InspectionContractError::ZeroSubjectRef);
        }
        if bytes_are_zero(fields.owner_fact_digest.as_bytes()) {
            return Err(InspectionContractError::ZeroOwnerFactDigest);
        }
        let (coordinate, sequence) = fields.coordinate.values();
        if coordinate == 0 || sequence == 0 {
            return Err(InspectionContractError::ZeroSourceCoordinate);
        }
        if fields.coordinate.owner() != fields.owner {
            return Err(InspectionContractError::SourceCoordinateOwnerMismatch);
        }
        if fields.observed_at_nanos == 0 || fields.valid_until_nanos < fields.observed_at_nanos {
            return Err(InspectionContractError::InvalidTimestamp);
        }
        validate_owner_state(
            fields.liveness,
            fields.readiness,
            fields.health,
            fields.feature_support,
            fields.reason,
        )?;
        Ok(Self(fields))
    }

    /// Returns the complete immutable fields.
    #[must_use]
    pub const fn fields(self) -> OwnerInspectionFactFieldsV1 {
        self.0
    }
}

/// One expected owner slot. Absence is explicit and projects as `Missing`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectionSourceSlotV1 {
    owner: InspectionSourceOwnerV1,
    subject_ref: [u8; 16],
    fact: Option<OwnerInspectionFactV1>,
}

impl InspectionSourceSlotV1 {
    /// Binds an optional fact to one exact expected owner and subject.
    pub fn try_new(
        owner: InspectionSourceOwnerV1,
        subject_ref: [u8; 16],
        fact: Option<OwnerInspectionFactV1>,
    ) -> Result<Self, InspectionContractError> {
        if bytes_are_zero(&subject_ref) {
            return Err(InspectionContractError::ZeroSubjectRef);
        }
        if fact.is_some_and(|fact| {
            let fields = fact.fields();
            fields.owner != owner || fields.subject_ref != subject_ref
        }) {
            return Err(InspectionContractError::SourceSlotMismatch);
        }
        Ok(Self {
            owner,
            subject_ref,
            fact,
        })
    }

    #[must_use]
    pub const fn owner(self) -> InspectionSourceOwnerV1 {
        self.owner
    }

    #[must_use]
    pub const fn subject_ref(self) -> [u8; 16] {
        self.subject_ref
    }

    #[must_use]
    pub const fn fact(self) -> Option<OwnerInspectionFactV1> {
        self.fact
    }
}

/// Complete bounded input to one pure local projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalInspectionProjectionInputV1 {
    observation_clock_ref: InspectionObservationClockRefV1,
    slots: [InspectionSourceSlotV1; LOCAL_INSPECTION_OWNER_COUNT],
}

impl LocalInspectionProjectionInputV1 {
    /// Requires the fixed canonical owner order and one slot per owner.
    pub fn try_new(
        observation_clock_ref: InspectionObservationClockRefV1,
        slots: [InspectionSourceSlotV1; LOCAL_INSPECTION_OWNER_COUNT],
    ) -> Result<Self, InspectionContractError> {
        for (slot, expected_owner) in slots.iter().zip(InspectionSourceOwnerV1::ALL) {
            if slot.owner != expected_owner {
                return Err(InspectionContractError::NonCanonicalOwnerOrder);
            }
            if slot
                .fact
                .is_some_and(|fact| fact.fields().observation_clock_ref != observation_clock_ref)
            {
                return Err(InspectionContractError::ObservationClockMismatch);
            }
        }
        Ok(Self {
            observation_clock_ref,
            slots,
        })
    }

    #[must_use]
    pub const fn observation_clock_ref(&self) -> InspectionObservationClockRefV1 {
        self.observation_clock_ref
    }

    #[must_use]
    pub fn slots(&self) -> &[InspectionSourceSlotV1; LOCAL_INSPECTION_OWNER_COUNT] {
        &self.slots
    }
}

/// One public-safe record in a local snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalInspectionRecordV1 {
    owner: InspectionSourceOwnerV1,
    freshness: InspectionFreshnessV1,
    subject_ref: [u8; 16],
    coordinate: Option<InspectionSourceCoordinateV1>,
    observed_at_nanos: Option<u64>,
    valid_until_nanos: Option<u64>,
    liveness: InspectionLivenessV1,
    readiness: InspectionReadinessV1,
    health: InspectionHealthV1,
    feature_support: InspectionFeatureSupportV1,
    reason: InspectionReasonV1,
    owner_fact_digest: Option<Digest32>,
}

impl LocalInspectionRecordV1 {
    #[must_use]
    pub const fn owner(self) -> InspectionSourceOwnerV1 {
        self.owner
    }

    #[must_use]
    pub const fn freshness(self) -> InspectionFreshnessV1 {
        self.freshness
    }

    #[must_use]
    pub const fn subject_ref(self) -> [u8; 16] {
        self.subject_ref
    }

    #[must_use]
    pub const fn coordinate(self) -> Option<InspectionSourceCoordinateV1> {
        self.coordinate
    }

    #[must_use]
    pub const fn observed_at_nanos(self) -> Option<u64> {
        self.observed_at_nanos
    }

    #[must_use]
    pub const fn valid_until_nanos(self) -> Option<u64> {
        self.valid_until_nanos
    }

    #[must_use]
    pub const fn liveness(self) -> InspectionLivenessV1 {
        self.liveness
    }

    #[must_use]
    pub const fn readiness(self) -> InspectionReadinessV1 {
        self.readiness
    }

    #[must_use]
    pub const fn health(self) -> InspectionHealthV1 {
        self.health
    }

    #[must_use]
    pub const fn feature_support(self) -> InspectionFeatureSupportV1 {
        self.feature_support
    }

    #[must_use]
    pub const fn reason(self) -> InspectionReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn owner_fact_digest(self) -> Option<Digest32> {
        self.owner_fact_digest
    }
}

/// Strict immutable PXIS-v1 value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalInspectionSnapshotV1 {
    projection_id: [u8; 16],
    observation_clock_ref: InspectionObservationClockRefV1,
    projection_revision: u64,
    projected_at_nanos: u64,
    overall: LocalInspectionOverallV1,
    records: [LocalInspectionRecordV1; LOCAL_INSPECTION_OWNER_COUNT],
    projection_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl LocalInspectionSnapshotV1 {
    /// Strictly decodes one exact PXIS-v1 value and rejects every
    /// non-canonical representation.
    pub fn decode(frame: &[u8]) -> Result<Self, InspectionContractError> {
        if frame.len() != LOCAL_INSPECTION_SNAPSHOT_BYTES {
            return Err(InspectionContractError::InvalidFrameLength);
        }
        if &frame[..4] != SNAPSHOT_MAGIC
            || read_u16(&frame[4..6]) != LOCAL_INSPECTION_SNAPSHOT_VERSION
            || usize::from(read_u16(&frame[6..8])) != SNAPSHOT_HEADER_BYTES
        {
            return Err(InspectionContractError::UnsupportedFrame);
        }
        if read_u32(&frame[8..12]) as usize != frame.len()
            || read_u32(&frame[12..16]) as usize != LOCAL_INSPECTION_OWNER_COUNT * RECORD_BYTES
            || usize::from(read_u16(&frame[64..66])) != LOCAL_INSPECTION_OWNER_COUNT
            || usize::from(read_u16(&frame[66..68])) != RECORD_BYTES
        {
            return Err(InspectionContractError::InvalidFrameLength);
        }
        if frame[69..80].iter().any(|byte| *byte != 0) {
            return Err(InspectionContractError::NonCanonicalEncoding);
        }
        let projection_id = read_array::<16>(&frame[16..32]);
        if bytes_are_zero(&projection_id) {
            return Err(InspectionContractError::ZeroProjectionId);
        }
        let observation_clock_ref =
            InspectionObservationClockRefV1::try_from_bytes(read_array::<16>(&frame[32..48]))?;
        let projection_revision = read_u64(&frame[48..56]);
        let projected_at_nanos = read_u64(&frame[56..64]);
        if projection_revision == 0 || projected_at_nanos == 0 {
            return Err(InspectionContractError::InvalidTimestamp);
        }
        let declared_overall = LocalInspectionOverallV1::decode(frame[68])?;
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[SNAPSHOT_DIGEST_OFFSET..SNAPSHOT_HEADER_BYTES],
        ));
        let computed_digest = snapshot_digest(
            &frame[..SNAPSHOT_DIGEST_OFFSET],
            &frame[SNAPSHOT_HEADER_BYTES..],
        )?;
        if declared_digest != computed_digest {
            return Err(InspectionContractError::SnapshotDigestMismatch);
        }

        let records = decode_records(&frame[SNAPSHOT_HEADER_BYTES..], projected_at_nanos)?;
        let overall = derive_overall(&records);
        if overall != declared_overall {
            return Err(InspectionContractError::InvalidAggregateState);
        }
        let snapshot = Self::try_build(
            projection_id,
            observation_clock_ref,
            projection_revision,
            projected_at_nanos,
            records,
        )?;
        if snapshot.canonical_wire() != frame {
            return Err(InspectionContractError::NonCanonicalEncoding);
        }
        Ok(snapshot)
    }

    fn try_build(
        projection_id: [u8; 16],
        observation_clock_ref: InspectionObservationClockRefV1,
        projection_revision: u64,
        projected_at_nanos: u64,
        records: [LocalInspectionRecordV1; LOCAL_INSPECTION_OWNER_COUNT],
    ) -> Result<Self, InspectionContractError> {
        if bytes_are_zero(&projection_id) {
            return Err(InspectionContractError::ZeroProjectionId);
        }
        if projection_revision == 0 || projected_at_nanos == 0 {
            return Err(InspectionContractError::InvalidTimestamp);
        }
        validate_records(&records, projected_at_nanos)?;
        let overall = derive_overall(&records);
        let canonical_wire = encode_snapshot(
            projection_id,
            observation_clock_ref,
            projection_revision,
            projected_at_nanos,
            overall,
            &records,
        )?;
        let projection_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[SNAPSHOT_DIGEST_OFFSET..SNAPSHOT_HEADER_BYTES],
        ));
        Ok(Self {
            projection_id,
            observation_clock_ref,
            projection_revision,
            projected_at_nanos,
            overall,
            records,
            projection_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn projection_id(&self) -> [u8; 16] {
        self.projection_id
    }

    #[must_use]
    pub const fn observation_clock_ref(&self) -> InspectionObservationClockRefV1 {
        self.observation_clock_ref
    }

    #[must_use]
    pub const fn projection_revision(&self) -> u64 {
        self.projection_revision
    }

    #[must_use]
    pub const fn projected_at_nanos(&self) -> u64 {
        self.projected_at_nanos
    }

    #[must_use]
    pub const fn overall(&self) -> LocalInspectionOverallV1 {
        self.overall
    }

    #[must_use]
    pub fn records(&self) -> &[LocalInspectionRecordV1; LOCAL_INSPECTION_OWNER_COUNT] {
        &self.records
    }

    /// Returns the domain-separated digest embedded in the snapshot header.
    #[must_use]
    pub const fn projection_digest(&self) -> Digest32 {
        self.projection_digest
    }

    /// Returns the exact canonical PXIS-v1 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Minimal local InspectionService role.
///
/// It owns only a monotonic projection revision and last immutable cache. It
/// performs no discovery, polling, authentication, persistence, retry, watch,
/// operational write, or source-owner mutation.
#[derive(Debug)]
pub struct LocalInspectionServiceV1 {
    projection_id: [u8; 16],
    observation_clock_ref: InspectionObservationClockRefV1,
    last_snapshot: Option<LocalInspectionSnapshotV1>,
}

impl LocalInspectionServiceV1 {
    /// Creates one bounded local projection owner.
    pub fn try_new(
        projection_id: [u8; 16],
        observation_clock_ref: InspectionObservationClockRefV1,
    ) -> Result<Self, InspectionContractError> {
        if bytes_are_zero(&projection_id) {
            return Err(InspectionContractError::ZeroProjectionId);
        }
        Ok(Self {
            projection_id,
            observation_clock_ref,
            last_snapshot: None,
        })
    }

    /// Projects a new revision. Any failure leaves revision and cache
    /// byte-for-byte unchanged.
    pub fn project(
        &mut self,
        projected_at_nanos: u64,
        input: &LocalInspectionProjectionInputV1,
    ) -> Result<&LocalInspectionSnapshotV1, InspectionContractError> {
        if input.observation_clock_ref != self.observation_clock_ref {
            return Err(InspectionContractError::ObservationClockMismatch);
        }
        if self
            .last_snapshot
            .as_ref()
            .is_some_and(|snapshot| projected_at_nanos < snapshot.projected_at_nanos)
        {
            return Err(InspectionContractError::ProjectionTimeRegressed);
        }
        let next_revision = match self.last_snapshot.as_ref() {
            Some(snapshot) => snapshot
                .projection_revision
                .checked_add(1)
                .ok_or(InspectionContractError::ProjectionRevisionExhausted)?,
            None => 1,
        };
        let next = project_local_inspection_snapshot_v1(
            self.projection_id,
            self.observation_clock_ref,
            next_revision,
            projected_at_nanos,
            input,
        )?;
        self.last_snapshot = Some(next);
        self.last_snapshot
            .as_ref()
            .ok_or(InspectionContractError::NonCanonicalEncoding)
    }

    /// Queries the last immutable local projection, if any.
    #[must_use]
    pub const fn snapshot(&self) -> Option<&LocalInspectionSnapshotV1> {
        self.last_snapshot.as_ref()
    }
}

/// Purely projects already-verified owner facts without mutating `input`.
///
/// `observed_at_nanos`, `valid_until_nanos`, and `projected_at_nanos` are
/// compared only after their exact local observation clock reference matches.
/// A partition is accepted only from the explicit input state; a timeout alone
/// produces `Stale`, never `Partitioned`.
pub fn project_local_inspection_snapshot_v1(
    projection_id: [u8; 16],
    observation_clock_ref: InspectionObservationClockRefV1,
    projection_revision: u64,
    projected_at_nanos: u64,
    input: &LocalInspectionProjectionInputV1,
) -> Result<LocalInspectionSnapshotV1, InspectionContractError> {
    if input.observation_clock_ref != observation_clock_ref {
        return Err(InspectionContractError::ObservationClockMismatch);
    }
    let mut records = [missing_record(input.slots[0]); LOCAL_INSPECTION_OWNER_COUNT];
    for (index, slot) in input.slots.iter().copied().enumerate() {
        records[index] = project_slot(slot, projected_at_nanos)?;
    }
    LocalInspectionSnapshotV1::try_build(
        projection_id,
        observation_clock_ref,
        projection_revision,
        projected_at_nanos,
        records,
    )
}

fn project_slot(
    slot: InspectionSourceSlotV1,
    projected_at_nanos: u64,
) -> Result<LocalInspectionRecordV1, InspectionContractError> {
    let Some(fact) = slot.fact else {
        return Ok(missing_record(slot));
    };
    let fields = fact.fields();
    if projected_at_nanos < fields.observed_at_nanos {
        return Err(InspectionContractError::ProjectionPrecedesObservation);
    }
    let freshness = match fields.availability {
        InspectionSourceAvailabilityV1::Partitioned => InspectionFreshnessV1::Partitioned,
        InspectionSourceAvailabilityV1::Observed
            if projected_at_nanos > fields.valid_until_nanos =>
        {
            InspectionFreshnessV1::Stale
        }
        InspectionSourceAvailabilityV1::Observed => InspectionFreshnessV1::Fresh,
    };
    let (liveness, readiness, health, feature_support, reason) = match freshness {
        InspectionFreshnessV1::Fresh => (
            fields.liveness,
            fields.readiness,
            fields.health,
            fields.feature_support,
            fields.reason,
        ),
        InspectionFreshnessV1::Stale => unknown_dimensions(InspectionReasonV1::SourceStale),
        InspectionFreshnessV1::Partitioned => {
            unknown_dimensions(InspectionReasonV1::SourcePartitioned)
        }
        InspectionFreshnessV1::Missing => {
            return Err(InspectionContractError::NonCanonicalEncoding);
        }
    };
    Ok(LocalInspectionRecordV1 {
        owner: slot.owner,
        freshness,
        subject_ref: slot.subject_ref,
        coordinate: Some(fields.coordinate),
        observed_at_nanos: Some(fields.observed_at_nanos),
        valid_until_nanos: Some(fields.valid_until_nanos),
        liveness,
        readiness,
        health,
        feature_support,
        reason,
        owner_fact_digest: Some(fields.owner_fact_digest),
    })
}

fn missing_record(slot: InspectionSourceSlotV1) -> LocalInspectionRecordV1 {
    let (liveness, readiness, health, feature_support, reason) =
        unknown_dimensions(InspectionReasonV1::SourceMissing);
    LocalInspectionRecordV1 {
        owner: slot.owner,
        freshness: InspectionFreshnessV1::Missing,
        subject_ref: slot.subject_ref,
        coordinate: None,
        observed_at_nanos: None,
        valid_until_nanos: None,
        liveness,
        readiness,
        health,
        feature_support,
        reason,
        owner_fact_digest: None,
    }
}

const fn unknown_dimensions(
    reason: InspectionReasonV1,
) -> (
    InspectionLivenessV1,
    InspectionReadinessV1,
    InspectionHealthV1,
    InspectionFeatureSupportV1,
    InspectionReasonV1,
) {
    (
        InspectionLivenessV1::Unknown,
        InspectionReadinessV1::Unknown,
        InspectionHealthV1::Unknown,
        InspectionFeatureSupportV1::Unknown,
        reason,
    )
}

fn validate_owner_state(
    liveness: InspectionLivenessV1,
    readiness: InspectionReadinessV1,
    health: InspectionHealthV1,
    feature_support: InspectionFeatureSupportV1,
    reason: InspectionReasonV1,
) -> Result<(), InspectionContractError> {
    let exact_green = liveness == InspectionLivenessV1::Live
        && readiness == InspectionReadinessV1::Ready
        && health == InspectionHealthV1::Healthy
        && feature_support == InspectionFeatureSupportV1::AllRequiredSupported;
    if exact_green != (reason == InspectionReasonV1::None)
        || reason.is_projection_owned()
        || readiness == InspectionReadinessV1::Ready
            && (!matches!(
                liveness,
                InspectionLivenessV1::Live | InspectionLivenessV1::Unknown
            ) || feature_support != InspectionFeatureSupportV1::AllRequiredSupported)
        || matches!(
            liveness,
            InspectionLivenessV1::Exited | InspectionLivenessV1::Quarantined
        ) && (matches!(
            readiness,
            InspectionReadinessV1::Ready | InspectionReadinessV1::Degraded
        ) || matches!(
            health,
            InspectionHealthV1::Healthy | InspectionHealthV1::Degraded
        ))
    {
        return Err(InspectionContractError::InvalidOwnerState);
    }
    Ok(())
}

fn validate_records(
    records: &[LocalInspectionRecordV1; LOCAL_INSPECTION_OWNER_COUNT],
    projected_at_nanos: u64,
) -> Result<(), InspectionContractError> {
    for (record, expected_owner) in records.iter().zip(InspectionSourceOwnerV1::ALL) {
        if record.owner != expected_owner || bytes_are_zero(&record.subject_ref) {
            return Err(InspectionContractError::NonCanonicalOwnerOrder);
        }
        match record.freshness {
            InspectionFreshnessV1::Missing => {
                if record.coordinate.is_some()
                    || record.observed_at_nanos.is_some()
                    || record.valid_until_nanos.is_some()
                    || record.owner_fact_digest.is_some()
                    || record.liveness != InspectionLivenessV1::Unknown
                    || record.readiness != InspectionReadinessV1::Unknown
                    || record.health != InspectionHealthV1::Unknown
                    || record.feature_support != InspectionFeatureSupportV1::Unknown
                    || record.reason != InspectionReasonV1::SourceMissing
                {
                    return Err(InspectionContractError::NonCanonicalEncoding);
                }
            }
            InspectionFreshnessV1::Fresh
            | InspectionFreshnessV1::Stale
            | InspectionFreshnessV1::Partitioned => {
                let coordinate = record
                    .coordinate
                    .ok_or(InspectionContractError::NonCanonicalEncoding)?;
                let observed_at = record
                    .observed_at_nanos
                    .ok_or(InspectionContractError::NonCanonicalEncoding)?;
                let valid_until = record
                    .valid_until_nanos
                    .ok_or(InspectionContractError::NonCanonicalEncoding)?;
                let digest = record
                    .owner_fact_digest
                    .ok_or(InspectionContractError::NonCanonicalEncoding)?;
                let (coordinate_value, sequence) = coordinate.values();
                if coordinate.owner() != record.owner
                    || coordinate_value == 0
                    || sequence == 0
                    || observed_at == 0
                    || observed_at > valid_until
                    || observed_at > projected_at_nanos
                    || bytes_are_zero(digest.as_bytes())
                {
                    return Err(InspectionContractError::NonCanonicalEncoding);
                }
                match record.freshness {
                    InspectionFreshnessV1::Fresh => {
                        if projected_at_nanos > valid_until {
                            return Err(InspectionContractError::NonCanonicalEncoding);
                        }
                        validate_owner_state(
                            record.liveness,
                            record.readiness,
                            record.health,
                            record.feature_support,
                            record.reason,
                        )?;
                    }
                    InspectionFreshnessV1::Stale => {
                        if projected_at_nanos <= valid_until
                            || !is_masked_unknown(record, InspectionReasonV1::SourceStale)
                        {
                            return Err(InspectionContractError::NonCanonicalEncoding);
                        }
                    }
                    InspectionFreshnessV1::Partitioned => {
                        if !is_masked_unknown(record, InspectionReasonV1::SourcePartitioned) {
                            return Err(InspectionContractError::NonCanonicalEncoding);
                        }
                    }
                    InspectionFreshnessV1::Missing => {
                        return Err(InspectionContractError::NonCanonicalEncoding);
                    }
                }
            }
        }
    }
    Ok(())
}

fn is_masked_unknown(record: &LocalInspectionRecordV1, reason: InspectionReasonV1) -> bool {
    record.liveness == InspectionLivenessV1::Unknown
        && record.readiness == InspectionReadinessV1::Unknown
        && record.health == InspectionHealthV1::Unknown
        && record.feature_support == InspectionFeatureSupportV1::Unknown
        && record.reason == reason
}

fn derive_overall(
    records: &[LocalInspectionRecordV1; LOCAL_INSPECTION_OWNER_COUNT],
) -> LocalInspectionOverallV1 {
    if records.iter().any(|record| {
        matches!(
            record.liveness,
            InspectionLivenessV1::Exited | InspectionLivenessV1::Quarantined
        ) || matches!(
            record.readiness,
            InspectionReadinessV1::NotReady | InspectionReadinessV1::Blocked
        ) || record.health == InspectionHealthV1::Faulted
            || record.feature_support == InspectionFeatureSupportV1::RequiredUnsupported
    }) {
        return LocalInspectionOverallV1::Unavailable;
    }
    if records.iter().any(|record| {
        record.freshness != InspectionFreshnessV1::Fresh
            || record.liveness == InspectionLivenessV1::Unknown
            || record.readiness == InspectionReadinessV1::Unknown
            || record.health == InspectionHealthV1::Unknown
            || record.feature_support == InspectionFeatureSupportV1::Unknown
    }) {
        return LocalInspectionOverallV1::Unknown;
    }
    if records.iter().any(|record| {
        matches!(
            record.liveness,
            InspectionLivenessV1::Bootstrapping | InspectionLivenessV1::Unresponsive
        ) || record.readiness == InspectionReadinessV1::Degraded
            || record.health == InspectionHealthV1::Degraded
    }) {
        return LocalInspectionOverallV1::Degraded;
    }
    LocalInspectionOverallV1::Ready
}

fn encode_snapshot(
    projection_id: [u8; 16],
    observation_clock_ref: InspectionObservationClockRefV1,
    projection_revision: u64,
    projected_at_nanos: u64,
    overall: LocalInspectionOverallV1,
    records: &[LocalInspectionRecordV1; LOCAL_INSPECTION_OWNER_COUNT],
) -> Result<Vec<u8>, InspectionContractError> {
    let mut frame = vec![0; LOCAL_INSPECTION_SNAPSHOT_BYTES];
    frame[..4].copy_from_slice(SNAPSHOT_MAGIC);
    frame[4..6].copy_from_slice(&LOCAL_INSPECTION_SNAPSHOT_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(&(SNAPSHOT_HEADER_BYTES as u16).to_be_bytes());
    frame[8..12].copy_from_slice(&(LOCAL_INSPECTION_SNAPSHOT_BYTES as u32).to_be_bytes());
    frame[12..16]
        .copy_from_slice(&((LOCAL_INSPECTION_OWNER_COUNT * RECORD_BYTES) as u32).to_be_bytes());
    frame[16..32].copy_from_slice(&projection_id);
    frame[32..48].copy_from_slice(observation_clock_ref.as_bytes());
    frame[48..56].copy_from_slice(&projection_revision.to_be_bytes());
    frame[56..64].copy_from_slice(&projected_at_nanos.to_be_bytes());
    frame[64..66].copy_from_slice(&(LOCAL_INSPECTION_OWNER_COUNT as u16).to_be_bytes());
    frame[66..68].copy_from_slice(&(RECORD_BYTES as u16).to_be_bytes());
    frame[68] = overall as u8;
    for (index, record) in records.iter().enumerate() {
        let start = SNAPSHOT_HEADER_BYTES + index * RECORD_BYTES;
        encode_record(record, &mut frame[start..start + RECORD_BYTES]);
    }
    let digest = snapshot_digest(
        &frame[..SNAPSHOT_DIGEST_OFFSET],
        &frame[SNAPSHOT_HEADER_BYTES..],
    )?;
    frame[SNAPSHOT_DIGEST_OFFSET..SNAPSHOT_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn encode_record(record: &LocalInspectionRecordV1, output: &mut [u8]) {
    output[0] = record.owner as u8;
    output[1] = record.freshness as u8;
    output[3] = record.liveness as u8;
    output[4] = record.readiness as u8;
    output[5] = record.health as u8;
    output[6] = record.feature_support as u8;
    output[7] = record.reason as u8;
    output[8..24].copy_from_slice(&record.subject_ref);
    if let Some(coordinate) = record.coordinate {
        let (value, sequence) = coordinate.values();
        output[2] = coordinate.kind();
        output[24..32].copy_from_slice(&value.to_be_bytes());
        output[32..40].copy_from_slice(&sequence.to_be_bytes());
    }
    if let Some(observed_at) = record.observed_at_nanos {
        output[40..48].copy_from_slice(&observed_at.to_be_bytes());
    }
    if let Some(valid_until) = record.valid_until_nanos {
        output[48..56].copy_from_slice(&valid_until.to_be_bytes());
    }
    if let Some(digest) = record.owner_fact_digest {
        output[56..88].copy_from_slice(digest.as_bytes());
    }
}

fn decode_records(
    payload: &[u8],
    projected_at_nanos: u64,
) -> Result<[LocalInspectionRecordV1; LOCAL_INSPECTION_OWNER_COUNT], InspectionContractError> {
    let mut records = [LocalInspectionRecordV1 {
        owner: InspectionSourceOwnerV1::Authority,
        freshness: InspectionFreshnessV1::Missing,
        subject_ref: [1; 16],
        coordinate: None,
        observed_at_nanos: None,
        valid_until_nanos: None,
        liveness: InspectionLivenessV1::Unknown,
        readiness: InspectionReadinessV1::Unknown,
        health: InspectionHealthV1::Unknown,
        feature_support: InspectionFeatureSupportV1::Unknown,
        reason: InspectionReasonV1::SourceMissing,
        owner_fact_digest: None,
    }; LOCAL_INSPECTION_OWNER_COUNT];
    for (index, output) in records.iter_mut().enumerate() {
        let start = index * RECORD_BYTES;
        *output = decode_record(&payload[start..start + RECORD_BYTES])?;
    }
    validate_records(&records, projected_at_nanos)?;
    Ok(records)
}

fn decode_record(frame: &[u8]) -> Result<LocalInspectionRecordV1, InspectionContractError> {
    if frame[88..96].iter().any(|byte| *byte != 0) {
        return Err(InspectionContractError::NonCanonicalEncoding);
    }
    let owner = InspectionSourceOwnerV1::decode(frame[0])?;
    let freshness = InspectionFreshnessV1::decode(frame[1])?;
    let liveness = InspectionLivenessV1::decode(frame[3])?;
    let readiness = InspectionReadinessV1::decode(frame[4])?;
    let health = InspectionHealthV1::decode(frame[5])?;
    let feature_support = InspectionFeatureSupportV1::decode(frame[6])?;
    let reason = InspectionReasonV1::decode(frame[7])?;
    let subject_ref = read_array::<16>(&frame[8..24]);
    let coordinate_value = read_u64(&frame[24..32]);
    let sequence = read_u64(&frame[32..40]);
    let observed_at = read_u64(&frame[40..48]);
    let valid_until = read_u64(&frame[48..56]);
    let digest_bytes = read_array::<32>(&frame[56..88]);
    let (coordinate, observed_at_nanos, valid_until_nanos, owner_fact_digest) =
        if freshness == InspectionFreshnessV1::Missing {
            if frame[2] != 0
                || coordinate_value != 0
                || sequence != 0
                || observed_at != 0
                || valid_until != 0
                || !bytes_are_zero(&digest_bytes)
            {
                return Err(InspectionContractError::NonCanonicalEncoding);
            }
            (None, None, None, None)
        } else {
            (
                Some(InspectionSourceCoordinateV1::decode(
                    frame[2],
                    coordinate_value,
                    sequence,
                )?),
                Some(observed_at),
                Some(valid_until),
                Some(Digest32::from_bytes(digest_bytes)),
            )
        };
    Ok(LocalInspectionRecordV1 {
        owner,
        freshness,
        subject_ref,
        coordinate,
        observed_at_nanos,
        valid_until_nanos,
        liveness,
        readiness,
        health,
        feature_support,
        reason,
        owner_fact_digest,
    })
}

fn snapshot_digest(header: &[u8], payload: &[u8]) -> Result<Digest32, InspectionContractError> {
    let mut builder = Digest32Builder::try_new(SNAPSHOT_DIGEST_DOMAIN)
        .map_err(|_| InspectionContractError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .and_then(|builder| builder.field_bytes(payload))
        .map_err(|_| InspectionContractError::DigestEncodingFailed)?;
    Ok(builder.finish())
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

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut output = [0; N];
    output.copy_from_slice(bytes);
    output
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Stable contract failures. No variant carries private owner material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionContractError {
    ZeroProjectionId,
    ZeroObservationClockRef,
    ZeroSubjectRef,
    ZeroOwnerFactDigest,
    ZeroSourceCoordinate,
    SourceCoordinateOwnerMismatch,
    SourceSlotMismatch,
    NonCanonicalOwnerOrder,
    ObservationClockMismatch,
    InvalidTimestamp,
    InvalidOwnerState,
    ProjectionPrecedesObservation,
    ProjectionTimeRegressed,
    ProjectionRevisionExhausted,
    InvalidFrameLength,
    UnsupportedFrame,
    UnknownEnumValue,
    SnapshotDigestMismatch,
    InvalidAggregateState,
    NonCanonicalEncoding,
    DigestEncodingFailed,
}

impl fmt::Display for InspectionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroProjectionId => "Inspection projection identity must be nonzero",
            Self::ZeroObservationClockRef => "Inspection observation clock must be nonzero",
            Self::ZeroSubjectRef => "Inspection subject reference must be nonzero",
            Self::ZeroOwnerFactDigest => "owner fact digest must be nonzero",
            Self::ZeroSourceCoordinate => "source coordinate and sequence must be nonzero",
            Self::SourceCoordinateOwnerMismatch => "source coordinate owner mismatch",
            Self::SourceSlotMismatch => "source slot owner or subject mismatch",
            Self::NonCanonicalOwnerOrder => "source owners are not in canonical order",
            Self::ObservationClockMismatch => "Inspection observation clock mismatch",
            Self::InvalidTimestamp => "invalid Inspection timestamp",
            Self::InvalidOwnerState => "inconsistent liveness/readiness/health/feature state",
            Self::ProjectionPrecedesObservation => "projection time precedes an owner observation",
            Self::ProjectionTimeRegressed => "projection time regressed",
            Self::ProjectionRevisionExhausted => "projection revision exhausted",
            Self::InvalidFrameLength => "invalid PXIS frame length",
            Self::UnsupportedFrame => "unsupported PXIS frame",
            Self::UnknownEnumValue => "unknown PXIS enum value",
            Self::SnapshotDigestMismatch => "PXIS snapshot digest mismatch",
            Self::InvalidAggregateState => "PXIS aggregate does not match source records",
            Self::NonCanonicalEncoding => "non-canonical PXIS encoding",
            Self::DigestEncodingFailed => "PXIS digest encoding failed",
        })
    }
}

impl std::error::Error for InspectionContractError {}

/// Public-safe NodeDaemon fields accepted by the PXIS-v2 projector.
///
/// The source adapter must authenticate and fence the NodeStatus before
/// constructing this value. Runtime routes, endpoint descriptors, public keys,
/// capability material, and the complete NodeStatus are deliberately absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeInspectionFactFieldsV2 {
    pub node_ref: [u8; 16],
    pub node_incarnation_ref: [u8; 16],
    pub registration_epoch: u64,
    pub status_sequence: u64,
    pub observation_clock_ref: InspectionObservationClockRefV1,
    pub observed_at_nanos: u64,
    pub valid_until_nanos: u64,
    pub availability: InspectionSourceAvailabilityV1,
    pub liveness: InspectionLivenessV1,
    pub readiness: InspectionReadinessV1,
    pub health: InspectionHealthV1,
    pub feature_support: InspectionFeatureSupportV1,
    pub reason: InspectionReasonV1,
    /// Digest of the complete authenticated NodeStatus selected by the adapter.
    pub node_status_digest: Digest32,
}

/// Validated immutable NodeDaemon fact accepted by the PXIS-v2 projector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeInspectionFactV2(NodeInspectionFactFieldsV2);

impl NodeInspectionFactV2 {
    pub fn try_new(fields: NodeInspectionFactFieldsV2) -> Result<Self, InspectionContractError> {
        if bytes_are_zero(&fields.node_ref) || bytes_are_zero(&fields.node_incarnation_ref) {
            return Err(InspectionContractError::ZeroSubjectRef);
        }
        if fields.registration_epoch == 0 || fields.status_sequence == 0 {
            return Err(InspectionContractError::ZeroSourceCoordinate);
        }
        if bytes_are_zero(fields.node_status_digest.as_bytes()) {
            return Err(InspectionContractError::ZeroOwnerFactDigest);
        }
        if fields.observed_at_nanos == 0 || fields.valid_until_nanos < fields.observed_at_nanos {
            return Err(InspectionContractError::InvalidTimestamp);
        }
        validate_owner_state(
            fields.liveness,
            fields.readiness,
            fields.health,
            fields.feature_support,
            fields.reason,
        )?;
        Ok(Self(fields))
    }

    #[must_use]
    pub const fn fields(self) -> NodeInspectionFactFieldsV2 {
        self.0
    }
}

/// The exact expected Node identity/incarnation and its optional verified fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeInspectionSourceSlotV2 {
    node_ref: [u8; 16],
    node_incarnation_ref: [u8; 16],
    fact: Option<NodeInspectionFactV2>,
}

impl NodeInspectionSourceSlotV2 {
    pub fn try_new(
        node_ref: [u8; 16],
        node_incarnation_ref: [u8; 16],
        fact: Option<NodeInspectionFactV2>,
    ) -> Result<Self, InspectionContractError> {
        if bytes_are_zero(&node_ref) || bytes_are_zero(&node_incarnation_ref) {
            return Err(InspectionContractError::ZeroSubjectRef);
        }
        if fact.is_some_and(|fact| {
            let fields = fact.fields();
            fields.node_ref != node_ref || fields.node_incarnation_ref != node_incarnation_ref
        }) {
            return Err(InspectionContractError::SourceSlotMismatch);
        }
        Ok(Self {
            node_ref,
            node_incarnation_ref,
            fact,
        })
    }

    #[must_use]
    pub const fn node_ref(self) -> [u8; 16] {
        self.node_ref
    }

    #[must_use]
    pub const fn node_incarnation_ref(self) -> [u8; 16] {
        self.node_incarnation_ref
    }

    #[must_use]
    pub const fn fact(self) -> Option<NodeInspectionFactV2> {
        self.fact
    }
}

/// Complete input for one PXIS-v2 projection.
///
/// The existing five-owner input remains an exact PXIS-v1 value. The added
/// NodeDaemon slot is independently correlated and uses the same local
/// observation clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalInspectionProjectionInputV2 {
    base: LocalInspectionProjectionInputV1,
    node: NodeInspectionSourceSlotV2,
}

impl LocalInspectionProjectionInputV2 {
    pub fn try_new(
        base: LocalInspectionProjectionInputV1,
        node: NodeInspectionSourceSlotV2,
    ) -> Result<Self, InspectionContractError> {
        if node
            .fact
            .is_some_and(|fact| fact.fields().observation_clock_ref != base.observation_clock_ref())
        {
            return Err(InspectionContractError::ObservationClockMismatch);
        }
        Ok(Self { base, node })
    }

    #[must_use]
    pub const fn observation_clock_ref(&self) -> InspectionObservationClockRefV1 {
        self.base.observation_clock_ref()
    }

    #[must_use]
    pub const fn base(&self) -> &LocalInspectionProjectionInputV1 {
        &self.base
    }

    #[must_use]
    pub const fn node(&self) -> NodeInspectionSourceSlotV2 {
        self.node
    }
}

/// Public-safe projected NodeDaemon record in a PXIS-v2 snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeInspectionRecordV2 {
    freshness: InspectionFreshnessV1,
    node_ref: [u8; 16],
    node_incarnation_ref: [u8; 16],
    registration_epoch: Option<u64>,
    status_sequence: Option<u64>,
    observed_at_nanos: Option<u64>,
    valid_until_nanos: Option<u64>,
    liveness: InspectionLivenessV1,
    readiness: InspectionReadinessV1,
    health: InspectionHealthV1,
    feature_support: InspectionFeatureSupportV1,
    reason: InspectionReasonV1,
    node_status_digest: Option<Digest32>,
}

impl NodeInspectionRecordV2 {
    #[must_use]
    pub const fn freshness(self) -> InspectionFreshnessV1 {
        self.freshness
    }

    #[must_use]
    pub const fn node_ref(self) -> [u8; 16] {
        self.node_ref
    }

    #[must_use]
    pub const fn node_incarnation_ref(self) -> [u8; 16] {
        self.node_incarnation_ref
    }

    #[must_use]
    pub const fn registration_epoch(self) -> Option<u64> {
        self.registration_epoch
    }

    #[must_use]
    pub const fn status_sequence(self) -> Option<u64> {
        self.status_sequence
    }

    #[must_use]
    pub const fn observed_at_nanos(self) -> Option<u64> {
        self.observed_at_nanos
    }

    #[must_use]
    pub const fn valid_until_nanos(self) -> Option<u64> {
        self.valid_until_nanos
    }

    #[must_use]
    pub const fn liveness(self) -> InspectionLivenessV1 {
        self.liveness
    }

    #[must_use]
    pub const fn readiness(self) -> InspectionReadinessV1 {
        self.readiness
    }

    #[must_use]
    pub const fn health(self) -> InspectionHealthV1 {
        self.health
    }

    #[must_use]
    pub const fn feature_support(self) -> InspectionFeatureSupportV1 {
        self.feature_support
    }

    #[must_use]
    pub const fn reason(self) -> InspectionReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn node_status_digest(self) -> Option<Digest32> {
        self.node_status_digest
    }
}

/// Strict immutable PXIS-v2 value composed from an exact PXIS-v1 snapshot and
/// one NodeDaemon projection record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalInspectionSnapshotV2 {
    base: LocalInspectionSnapshotV1,
    node: NodeInspectionRecordV2,
    overall: LocalInspectionOverallV1,
    projection_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl LocalInspectionSnapshotV2 {
    pub fn decode(frame: &[u8]) -> Result<Self, InspectionContractError> {
        if frame.len() != LOCAL_INSPECTION_SNAPSHOT_V2_BYTES {
            return Err(InspectionContractError::InvalidFrameLength);
        }
        if &frame[..4] != SNAPSHOT_MAGIC
            || read_u16(&frame[4..6]) != LOCAL_INSPECTION_SNAPSHOT_V2_VERSION
            || usize::from(read_u16(&frame[6..8])) != SNAPSHOT_V2_HEADER_BYTES
        {
            return Err(InspectionContractError::UnsupportedFrame);
        }
        let expected_payload = LOCAL_INSPECTION_SNAPSHOT_BYTES + NODE_RECORD_V2_BYTES;
        if read_u32(&frame[8..12]) as usize != frame.len()
            || read_u32(&frame[12..16]) as usize != expected_payload
            || read_u32(&frame[64..68]) as usize != LOCAL_INSPECTION_SNAPSHOT_BYTES
            || usize::from(read_u16(&frame[68..70])) != NODE_RECORD_V2_BYTES
            || frame[71..80].iter().any(|byte| *byte != 0)
        {
            return Err(InspectionContractError::InvalidFrameLength);
        }
        let projection_id = read_array::<16>(&frame[16..32]);
        if bytes_are_zero(&projection_id) {
            return Err(InspectionContractError::ZeroProjectionId);
        }
        let observation_clock_ref =
            InspectionObservationClockRefV1::try_from_bytes(read_array::<16>(&frame[32..48]))?;
        let projection_revision = read_u64(&frame[48..56]);
        let projected_at_nanos = read_u64(&frame[56..64]);
        if projection_revision == 0 || projected_at_nanos == 0 {
            return Err(InspectionContractError::InvalidTimestamp);
        }
        let declared_overall = LocalInspectionOverallV1::decode(frame[70])?;
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[SNAPSHOT_V2_DIGEST_OFFSET..SNAPSHOT_V2_HEADER_BYTES],
        ));
        let computed_digest = snapshot_v2_digest(
            &frame[..SNAPSHOT_V2_DIGEST_OFFSET],
            &frame[SNAPSHOT_V2_HEADER_BYTES..],
        )?;
        if declared_digest != computed_digest {
            return Err(InspectionContractError::SnapshotDigestMismatch);
        }
        let base_end = SNAPSHOT_V2_HEADER_BYTES + LOCAL_INSPECTION_SNAPSHOT_BYTES;
        let base = LocalInspectionSnapshotV1::decode(&frame[SNAPSHOT_V2_HEADER_BYTES..base_end])?;
        if base.projection_id() != projection_id
            || base.observation_clock_ref() != observation_clock_ref
            || base.projection_revision() != projection_revision
            || base.projected_at_nanos() != projected_at_nanos
        {
            return Err(InspectionContractError::NonCanonicalEncoding);
        }
        let node = decode_node_record_v2(&frame[base_end..], projected_at_nanos)?;
        let overall = derive_overall_v2(base.overall(), node);
        if declared_overall != overall {
            return Err(InspectionContractError::InvalidAggregateState);
        }
        let snapshot = Self::try_build(base, node)?;
        if snapshot.canonical_wire() != frame {
            return Err(InspectionContractError::NonCanonicalEncoding);
        }
        Ok(snapshot)
    }

    fn try_build(
        base: LocalInspectionSnapshotV1,
        node: NodeInspectionRecordV2,
    ) -> Result<Self, InspectionContractError> {
        validate_node_record_v2(node, base.projected_at_nanos())?;
        let overall = derive_overall_v2(base.overall(), node);
        let canonical_wire = encode_snapshot_v2(&base, node, overall)?;
        let projection_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[SNAPSHOT_V2_DIGEST_OFFSET..SNAPSHOT_V2_HEADER_BYTES],
        ));
        Ok(Self {
            base,
            node,
            overall,
            projection_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn projection_id(&self) -> [u8; 16] {
        self.base.projection_id()
    }

    #[must_use]
    pub const fn observation_clock_ref(&self) -> InspectionObservationClockRefV1 {
        self.base.observation_clock_ref()
    }

    #[must_use]
    pub const fn projection_revision(&self) -> u64 {
        self.base.projection_revision()
    }

    #[must_use]
    pub const fn projected_at_nanos(&self) -> u64 {
        self.base.projected_at_nanos()
    }

    #[must_use]
    pub const fn overall(&self) -> LocalInspectionOverallV1 {
        self.overall
    }

    /// Returns the byte-exact nested five-owner PXIS-v1 snapshot.
    #[must_use]
    pub const fn base_snapshot(&self) -> &LocalInspectionSnapshotV1 {
        &self.base
    }

    #[must_use]
    pub const fn node(&self) -> NodeInspectionRecordV2 {
        self.node
    }

    #[must_use]
    pub const fn projection_digest(&self) -> Digest32 {
        self.projection_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Minimal failure-atomic in-memory owner for the PXIS-v2 composite cache.
#[derive(Debug)]
pub struct LocalInspectionServiceV2 {
    projection_id: [u8; 16],
    observation_clock_ref: InspectionObservationClockRefV1,
    last_snapshot: Option<LocalInspectionSnapshotV2>,
}

impl LocalInspectionServiceV2 {
    pub fn try_new(
        projection_id: [u8; 16],
        observation_clock_ref: InspectionObservationClockRefV1,
    ) -> Result<Self, InspectionContractError> {
        if bytes_are_zero(&projection_id) {
            return Err(InspectionContractError::ZeroProjectionId);
        }
        Ok(Self {
            projection_id,
            observation_clock_ref,
            last_snapshot: None,
        })
    }

    pub fn project(
        &mut self,
        projected_at_nanos: u64,
        input: &LocalInspectionProjectionInputV2,
    ) -> Result<&LocalInspectionSnapshotV2, InspectionContractError> {
        if input.observation_clock_ref() != self.observation_clock_ref {
            return Err(InspectionContractError::ObservationClockMismatch);
        }
        if self
            .last_snapshot
            .as_ref()
            .is_some_and(|snapshot| projected_at_nanos < snapshot.projected_at_nanos())
        {
            return Err(InspectionContractError::ProjectionTimeRegressed);
        }
        let next_revision = match self.last_snapshot.as_ref() {
            Some(snapshot) => snapshot
                .projection_revision()
                .checked_add(1)
                .ok_or(InspectionContractError::ProjectionRevisionExhausted)?,
            None => 1,
        };
        let next = project_local_inspection_snapshot_v2(
            self.projection_id,
            self.observation_clock_ref,
            next_revision,
            projected_at_nanos,
            input,
        )?;
        self.last_snapshot = Some(next);
        self.last_snapshot
            .as_ref()
            .ok_or(InspectionContractError::NonCanonicalEncoding)
    }

    #[must_use]
    pub const fn snapshot(&self) -> Option<&LocalInspectionSnapshotV2> {
        self.last_snapshot.as_ref()
    }
}

/// Projects the unchanged five-owner input and one verified NodeDaemon fact
/// into one atomic PXIS-v2 snapshot.
pub fn project_local_inspection_snapshot_v2(
    projection_id: [u8; 16],
    observation_clock_ref: InspectionObservationClockRefV1,
    projection_revision: u64,
    projected_at_nanos: u64,
    input: &LocalInspectionProjectionInputV2,
) -> Result<LocalInspectionSnapshotV2, InspectionContractError> {
    if input.observation_clock_ref() != observation_clock_ref {
        return Err(InspectionContractError::ObservationClockMismatch);
    }
    let base = project_local_inspection_snapshot_v1(
        projection_id,
        observation_clock_ref,
        projection_revision,
        projected_at_nanos,
        input.base(),
    )?;
    let node = project_node_slot_v2(input.node(), projected_at_nanos)?;
    LocalInspectionSnapshotV2::try_build(base, node)
}

fn project_node_slot_v2(
    slot: NodeInspectionSourceSlotV2,
    projected_at_nanos: u64,
) -> Result<NodeInspectionRecordV2, InspectionContractError> {
    let Some(fact) = slot.fact else {
        return Ok(missing_node_record_v2(slot));
    };
    let fields = fact.fields();
    if projected_at_nanos < fields.observed_at_nanos {
        return Err(InspectionContractError::ProjectionPrecedesObservation);
    }
    let freshness = match fields.availability {
        InspectionSourceAvailabilityV1::Partitioned => InspectionFreshnessV1::Partitioned,
        InspectionSourceAvailabilityV1::Observed
            if projected_at_nanos > fields.valid_until_nanos =>
        {
            InspectionFreshnessV1::Stale
        }
        InspectionSourceAvailabilityV1::Observed => InspectionFreshnessV1::Fresh,
    };
    let (liveness, readiness, health, feature_support, reason) = match freshness {
        InspectionFreshnessV1::Fresh => (
            fields.liveness,
            fields.readiness,
            fields.health,
            fields.feature_support,
            fields.reason,
        ),
        InspectionFreshnessV1::Stale => unknown_dimensions(InspectionReasonV1::SourceStale),
        InspectionFreshnessV1::Partitioned => {
            unknown_dimensions(InspectionReasonV1::SourcePartitioned)
        }
        InspectionFreshnessV1::Missing => {
            return Err(InspectionContractError::NonCanonicalEncoding);
        }
    };
    Ok(NodeInspectionRecordV2 {
        freshness,
        node_ref: slot.node_ref,
        node_incarnation_ref: slot.node_incarnation_ref,
        registration_epoch: Some(fields.registration_epoch),
        status_sequence: Some(fields.status_sequence),
        observed_at_nanos: Some(fields.observed_at_nanos),
        valid_until_nanos: Some(fields.valid_until_nanos),
        liveness,
        readiness,
        health,
        feature_support,
        reason,
        node_status_digest: Some(fields.node_status_digest),
    })
}

fn missing_node_record_v2(slot: NodeInspectionSourceSlotV2) -> NodeInspectionRecordV2 {
    let (liveness, readiness, health, feature_support, reason) =
        unknown_dimensions(InspectionReasonV1::SourceMissing);
    NodeInspectionRecordV2 {
        freshness: InspectionFreshnessV1::Missing,
        node_ref: slot.node_ref,
        node_incarnation_ref: slot.node_incarnation_ref,
        registration_epoch: None,
        status_sequence: None,
        observed_at_nanos: None,
        valid_until_nanos: None,
        liveness,
        readiness,
        health,
        feature_support,
        reason,
        node_status_digest: None,
    }
}

fn validate_node_record_v2(
    record: NodeInspectionRecordV2,
    projected_at_nanos: u64,
) -> Result<(), InspectionContractError> {
    if bytes_are_zero(&record.node_ref) || bytes_are_zero(&record.node_incarnation_ref) {
        return Err(InspectionContractError::ZeroSubjectRef);
    }
    match record.freshness {
        InspectionFreshnessV1::Missing => {
            if record.registration_epoch.is_some()
                || record.status_sequence.is_some()
                || record.observed_at_nanos.is_some()
                || record.valid_until_nanos.is_some()
                || record.node_status_digest.is_some()
                || !is_masked_unknown_node_v2(record, InspectionReasonV1::SourceMissing)
            {
                return Err(InspectionContractError::NonCanonicalEncoding);
            }
        }
        InspectionFreshnessV1::Fresh
        | InspectionFreshnessV1::Stale
        | InspectionFreshnessV1::Partitioned => {
            let registration_epoch = record
                .registration_epoch
                .ok_or(InspectionContractError::NonCanonicalEncoding)?;
            let status_sequence = record
                .status_sequence
                .ok_or(InspectionContractError::NonCanonicalEncoding)?;
            let observed_at = record
                .observed_at_nanos
                .ok_or(InspectionContractError::NonCanonicalEncoding)?;
            let valid_until = record
                .valid_until_nanos
                .ok_or(InspectionContractError::NonCanonicalEncoding)?;
            let digest = record
                .node_status_digest
                .ok_or(InspectionContractError::NonCanonicalEncoding)?;
            if registration_epoch == 0
                || status_sequence == 0
                || observed_at == 0
                || observed_at > valid_until
                || observed_at > projected_at_nanos
                || bytes_are_zero(digest.as_bytes())
            {
                return Err(InspectionContractError::NonCanonicalEncoding);
            }
            match record.freshness {
                InspectionFreshnessV1::Fresh => {
                    if projected_at_nanos > valid_until {
                        return Err(InspectionContractError::NonCanonicalEncoding);
                    }
                    validate_owner_state(
                        record.liveness,
                        record.readiness,
                        record.health,
                        record.feature_support,
                        record.reason,
                    )?;
                }
                InspectionFreshnessV1::Stale => {
                    if projected_at_nanos <= valid_until
                        || !is_masked_unknown_node_v2(record, InspectionReasonV1::SourceStale)
                    {
                        return Err(InspectionContractError::NonCanonicalEncoding);
                    }
                }
                InspectionFreshnessV1::Partitioned => {
                    if !is_masked_unknown_node_v2(record, InspectionReasonV1::SourcePartitioned) {
                        return Err(InspectionContractError::NonCanonicalEncoding);
                    }
                }
                InspectionFreshnessV1::Missing => {
                    return Err(InspectionContractError::NonCanonicalEncoding);
                }
            }
        }
    }
    Ok(())
}

fn is_masked_unknown_node_v2(record: NodeInspectionRecordV2, reason: InspectionReasonV1) -> bool {
    record.liveness == InspectionLivenessV1::Unknown
        && record.readiness == InspectionReadinessV1::Unknown
        && record.health == InspectionHealthV1::Unknown
        && record.feature_support == InspectionFeatureSupportV1::Unknown
        && record.reason == reason
}

fn derive_overall_v2(
    base: LocalInspectionOverallV1,
    node: NodeInspectionRecordV2,
) -> LocalInspectionOverallV1 {
    if base == LocalInspectionOverallV1::Unavailable
        || matches!(
            node.liveness,
            InspectionLivenessV1::Exited | InspectionLivenessV1::Quarantined
        )
        || matches!(
            node.readiness,
            InspectionReadinessV1::NotReady | InspectionReadinessV1::Blocked
        )
        || node.health == InspectionHealthV1::Faulted
        || node.feature_support == InspectionFeatureSupportV1::RequiredUnsupported
    {
        return LocalInspectionOverallV1::Unavailable;
    }
    if base == LocalInspectionOverallV1::Unknown
        || node.freshness != InspectionFreshnessV1::Fresh
        || node.liveness == InspectionLivenessV1::Unknown
        || node.readiness == InspectionReadinessV1::Unknown
        || node.health == InspectionHealthV1::Unknown
        || node.feature_support == InspectionFeatureSupportV1::Unknown
    {
        return LocalInspectionOverallV1::Unknown;
    }
    if base == LocalInspectionOverallV1::Degraded
        || matches!(
            node.liveness,
            InspectionLivenessV1::Bootstrapping | InspectionLivenessV1::Unresponsive
        )
        || node.readiness == InspectionReadinessV1::Degraded
        || node.health == InspectionHealthV1::Degraded
    {
        return LocalInspectionOverallV1::Degraded;
    }
    LocalInspectionOverallV1::Ready
}

fn encode_snapshot_v2(
    base: &LocalInspectionSnapshotV1,
    node: NodeInspectionRecordV2,
    overall: LocalInspectionOverallV1,
) -> Result<Vec<u8>, InspectionContractError> {
    let mut frame = vec![0_u8; LOCAL_INSPECTION_SNAPSHOT_V2_BYTES];
    frame[..4].copy_from_slice(SNAPSHOT_MAGIC);
    frame[4..6].copy_from_slice(&LOCAL_INSPECTION_SNAPSHOT_V2_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(&(SNAPSHOT_V2_HEADER_BYTES as u16).to_be_bytes());
    frame[8..12].copy_from_slice(&(LOCAL_INSPECTION_SNAPSHOT_V2_BYTES as u32).to_be_bytes());
    frame[12..16].copy_from_slice(
        &((LOCAL_INSPECTION_SNAPSHOT_BYTES + NODE_RECORD_V2_BYTES) as u32).to_be_bytes(),
    );
    frame[16..32].copy_from_slice(&base.projection_id());
    frame[32..48].copy_from_slice(base.observation_clock_ref().as_bytes());
    frame[48..56].copy_from_slice(&base.projection_revision().to_be_bytes());
    frame[56..64].copy_from_slice(&base.projected_at_nanos().to_be_bytes());
    frame[64..68].copy_from_slice(&(LOCAL_INSPECTION_SNAPSHOT_BYTES as u32).to_be_bytes());
    frame[68..70].copy_from_slice(&(NODE_RECORD_V2_BYTES as u16).to_be_bytes());
    frame[70] = overall as u8;
    let base_end = SNAPSHOT_V2_HEADER_BYTES + LOCAL_INSPECTION_SNAPSHOT_BYTES;
    frame[SNAPSHOT_V2_HEADER_BYTES..base_end].copy_from_slice(base.canonical_wire());
    encode_node_record_v2(node, &mut frame[base_end..]);
    let digest = snapshot_v2_digest(
        &frame[..SNAPSHOT_V2_DIGEST_OFFSET],
        &frame[SNAPSHOT_V2_HEADER_BYTES..],
    )?;
    frame[SNAPSHOT_V2_DIGEST_OFFSET..SNAPSHOT_V2_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn encode_node_record_v2(record: NodeInspectionRecordV2, output: &mut [u8]) {
    output[0] = record.freshness as u8;
    output[1] = record.liveness as u8;
    output[2] = record.readiness as u8;
    output[3] = record.health as u8;
    output[4] = record.feature_support as u8;
    output[5] = record.reason as u8;
    output[8..24].copy_from_slice(&record.node_ref);
    output[24..40].copy_from_slice(&record.node_incarnation_ref);
    if let Some(value) = record.registration_epoch {
        output[40..48].copy_from_slice(&value.to_be_bytes());
    }
    if let Some(value) = record.status_sequence {
        output[48..56].copy_from_slice(&value.to_be_bytes());
    }
    if let Some(value) = record.observed_at_nanos {
        output[56..64].copy_from_slice(&value.to_be_bytes());
    }
    if let Some(value) = record.valid_until_nanos {
        output[64..72].copy_from_slice(&value.to_be_bytes());
    }
    if let Some(value) = record.node_status_digest {
        output[72..104].copy_from_slice(value.as_bytes());
    }
}

fn decode_node_record_v2(
    frame: &[u8],
    projected_at_nanos: u64,
) -> Result<NodeInspectionRecordV2, InspectionContractError> {
    if frame.len() != NODE_RECORD_V2_BYTES
        || frame[6..8].iter().any(|byte| *byte != 0)
        || frame[104..].iter().any(|byte| *byte != 0)
    {
        return Err(InspectionContractError::NonCanonicalEncoding);
    }
    let freshness = InspectionFreshnessV1::decode(frame[0])?;
    let liveness = InspectionLivenessV1::decode(frame[1])?;
    let readiness = InspectionReadinessV1::decode(frame[2])?;
    let health = InspectionHealthV1::decode(frame[3])?;
    let feature_support = InspectionFeatureSupportV1::decode(frame[4])?;
    let reason = InspectionReasonV1::decode(frame[5])?;
    let node_ref = read_array::<16>(&frame[8..24]);
    let node_incarnation_ref = read_array::<16>(&frame[24..40]);
    let registration_epoch = read_u64(&frame[40..48]);
    let status_sequence = read_u64(&frame[48..56]);
    let observed_at_nanos = read_u64(&frame[56..64]);
    let valid_until_nanos = read_u64(&frame[64..72]);
    let digest = Digest32::from_bytes(read_array::<32>(&frame[72..104]));
    let (registration_epoch, status_sequence, observed_at_nanos, valid_until_nanos, digest) =
        if freshness == InspectionFreshnessV1::Missing {
            if registration_epoch != 0
                || status_sequence != 0
                || observed_at_nanos != 0
                || valid_until_nanos != 0
                || !bytes_are_zero(digest.as_bytes())
            {
                return Err(InspectionContractError::NonCanonicalEncoding);
            }
            (None, None, None, None, None)
        } else {
            (
                Some(registration_epoch),
                Some(status_sequence),
                Some(observed_at_nanos),
                Some(valid_until_nanos),
                Some(digest),
            )
        };
    let record = NodeInspectionRecordV2 {
        freshness,
        node_ref,
        node_incarnation_ref,
        registration_epoch,
        status_sequence,
        observed_at_nanos,
        valid_until_nanos,
        liveness,
        readiness,
        health,
        feature_support,
        reason,
        node_status_digest: digest,
    };
    validate_node_record_v2(record, projected_at_nanos)?;
    Ok(record)
}

fn snapshot_v2_digest(header: &[u8], payload: &[u8]) -> Result<Digest32, InspectionContractError> {
    let mut builder = Digest32Builder::try_new(SNAPSHOT_V2_DIGEST_DOMAIN)
        .map_err(|_| InspectionContractError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .and_then(|builder| builder.field_bytes(payload))
        .map_err(|_| InspectionContractError::DigestEncodingFailed)?;
    Ok(builder.finish())
}
