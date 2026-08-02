//! Pure S7/P2e deployment planning.
//!
//! This module deliberately has no manifest decoder or constructor.  The
//! opaque projection ingress is a seam for the later installer-owned,
//! runtime-contract decoder path; its test-only constructor is not evidence of
//! installer provenance.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_kernel::time::BoundedDuration;
use paraegox_runtime_contracts::assignment::InstanceRef;
use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef, DomainRef};

use crate::deck::{CardUseKey, DeckLock};

const PLAN_CONTENT_DIGEST_DOMAIN: &[u8] = b"paraegox.deployment.plan-content.sha256.v1";
const INSTANCE_ALLOCATION_DOMAIN: &[u8] =
    b"paraegox.deployment.stable-instance-allocation.sha256.v1";
const DOMAIN_ALLOCATION_DOMAIN: &[u8] = b"paraegox.deployment.stable-domain-allocation.sha256.v1";
const PLAN_CONTENT_MAGIC: &[u8] = b"ParaEGOX\0deployment-plan-content";
const PLAN_CONTENT_VERSION: u16 = 1;
// Planner-local work bounds keep validation finite before the zero-dependency
// S7 profile gate; they are not manifest/PXTE protocol limits.
const MAX_SERVICE_DEPENDENCY_VERTICES: usize = 256;
const MAX_SERVICE_DEPENDENCY_EDGES: usize = 1_024;
const MAX_STABLE_ALLOCATION_RECORDS: usize = 4096;

/// Explicit target intent. Omitted is never interpreted as an empty desired target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetIntent {
    OneSourceLoop,
    EmptyTarget,
    Omitted,
}

/// Validated lifecycle budgets received from the future Runtime-contract adapter.
///
/// S7-C deliberately provides no production constructor and does not repeat
/// the Runtime-owned maximum. Tests may construct this opaque token locally;
/// S7-E must add the adapter from the authoritative validated Runtime value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedReferenceLifecycleBudgets {
    start: BoundedDuration,
    drain: BoundedDuration,
    cleanup: BoundedDuration,
}

impl ValidatedReferenceLifecycleBudgets {
    const fn values(self) -> [BoundedDuration; 3] {
        [self.start, self.drain, self.cleanup]
    }
}

/// Typed previous desired/live eligibility used by the narrow S7 transition gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreviousTargetEligibility {
    UninitializedNoneExactZero,
    OneSourceLoopLiveReady,
    OneSourceLoopRecoveryFailedExactZero,
    EmptyDeactivateRetiring,
    EmptyDeactivateTerminalExactZero,
    Busy,
    Ineligible,
}

/// Opaque facts accompanying one already-validated manifest projection.
///
/// There is intentionally no production constructor or parser in S7-C.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpaqueManifestProjectionIngress<'a> {
    canonical_projection: &'a [u8],
    manifest_digest: PlanManifestDigest,
    target: RuntimeHostId,
    profile_fingerprint: Digest32,
    canonical_empty_config_digest: Digest32,
    fixture: ManifestFixtureFacts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManifestFixtureFacts {
    definition: CardDefinitionRef,
    implementation: CardImplementationRef,
    export: [u8; 16],
    definition_digest: Digest32,
    artifact_digest: Digest32,
}

/// Stable key of one ServiceSpec vertex.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ServiceRef([u8; 16]);

impl ServiceRef {
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Provider-before-consumer lifecycle dependency, not a Deck data link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceDependency {
    provider: ServiceRef,
    consumer: ServiceRef,
}

impl ServiceDependency {
    #[must_use]
    pub(crate) const fn new(provider: ServiceRef, consumer: ServiceRef) -> Self {
        Self { provider, consumer }
    }
}

/// Stable, closed cycle witness. The first vertex is repeated at the end.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceCycleWitness(Box<[ServiceRef]>);

impl ServiceCycleWitness {
    #[must_use]
    pub(crate) fn vertices(&self) -> &[ServiceRef] {
        &self.0
    }
}

/// Lifecycle order proven independently from DeckTopology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceDependencyOrder {
    startup: Box<[ServiceRef]>,
    shutdown: Box<[ServiceRef]>,
}

impl ServiceDependencyOrder {
    #[must_use]
    pub(crate) fn startup(&self) -> &[ServiceRef] {
        &self.startup
    }

    #[must_use]
    pub(crate) fn shutdown(&self) -> &[ServiceRef] {
        &self.shutdown
    }
}

/// Service graph rejection remains distinct from Deck cycle diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ServiceDependencyError {
    TooManyVertices,
    TooManyEdges,
    DuplicateDependency,
    Cycle(ServiceCycleWitness),
}

/// Pure ServiceDependency DAG validation with stable ordering and witness selection.
pub(crate) fn validate_service_dependencies(
    dependencies: &[ServiceDependency],
) -> Result<ServiceDependencyOrder, ServiceDependencyError> {
    if dependencies.len() > MAX_SERVICE_DEPENDENCY_EDGES {
        return Err(ServiceDependencyError::TooManyEdges);
    }

    let mut nodes = BTreeSet::new();
    let mut edges = BTreeSet::new();
    for dependency in dependencies {
        nodes.insert(dependency.provider);
        nodes.insert(dependency.consumer);
        edges.insert((dependency.provider, dependency.consumer));
    }
    if nodes.len() > MAX_SERVICE_DEPENDENCY_VERTICES {
        return Err(ServiceDependencyError::TooManyVertices);
    }
    if edges.len() != dependencies.len() {
        return Err(ServiceDependencyError::DuplicateDependency);
    }

    let mut outgoing: BTreeMap<ServiceRef, Vec<ServiceRef>> = BTreeMap::new();
    let mut indegree: BTreeMap<ServiceRef, usize> = BTreeMap::new();
    for node in &nodes {
        indegree.insert(*node, 0);
    }
    for (provider, consumer) in &edges {
        outgoing.entry(*provider).or_default().push(*consumer);
        let Some(value) = indegree.get_mut(consumer) else {
            unreachable!("all edge endpoints were inserted");
        };
        *value += 1;
    }

    let mut ready: BTreeSet<ServiceRef> = indegree
        .iter()
        .filter_map(|(node, degree)| (*degree == 0).then_some(*node))
        .collect();
    let mut startup = Vec::with_capacity(nodes.len());
    while let Some(node) = ready.pop_first() {
        startup.push(node);
        if let Some(consumers) = outgoing.get(&node) {
            for consumer in consumers {
                let Some(degree) = indegree.get_mut(consumer) else {
                    unreachable!("all edge endpoints were inserted");
                };
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(*consumer);
                }
            }
        }
    }

    if startup.len() != nodes.len() {
        return Err(ServiceDependencyError::Cycle(stable_cycle_witness(
            &nodes, &outgoing,
        )));
    }
    let shutdown = startup.iter().rev().copied().collect::<Vec<_>>();
    Ok(ServiceDependencyOrder {
        startup: startup.into_boxed_slice(),
        shutdown: shutdown.into_boxed_slice(),
    })
}

fn stable_cycle_witness(
    nodes: &BTreeSet<ServiceRef>,
    outgoing: &BTreeMap<ServiceRef, Vec<ServiceRef>>,
) -> ServiceCycleWitness {
    struct Frame {
        node: ServiceRef,
        next_index: usize,
    }

    let mut state = BTreeMap::new();
    let mut path = Vec::new();
    let mut path_positions = BTreeMap::new();
    let mut frames = Vec::new();
    for root in nodes {
        if state.get(root).copied().unwrap_or(0) != 0 {
            continue;
        }
        state.insert(*root, 1);
        path_positions.insert(*root, 0);
        path.push(*root);
        frames.push(Frame {
            node: *root,
            next_index: 0,
        });

        while let Some(frame) = frames.last_mut() {
            let next = outgoing
                .get(&frame.node)
                .and_then(|next_nodes| next_nodes.get(frame.next_index))
                .copied();
            if let Some(next) = next {
                frame.next_index += 1;
                match state.get(&next).copied().unwrap_or(0) {
                    0 => {
                        state.insert(next, 1);
                        path_positions.insert(next, path.len());
                        path.push(next);
                        frames.push(Frame {
                            node: next,
                            next_index: 0,
                        });
                    }
                    1 => {
                        let Some(start) = path_positions.get(&next).copied() else {
                            unreachable!("active DFS vertex must be present in the path")
                        };
                        let mut witness = path[start..].to_vec();
                        witness.push(next);
                        return ServiceCycleWitness(witness.into_boxed_slice());
                    }
                    _ => {}
                }
                continue;
            }

            let Some(finished) = frames.pop() else {
                unreachable!("the DFS frame was observed above")
            };
            let Some(path_tail) = path.pop() else {
                unreachable!("every DFS frame owns one path vertex")
            };
            debug_assert_eq!(path_tail, finished.node);
            path_positions.remove(&finished.node);
            state.insert(finished.node, 2);
        }
    }
    unreachable!("cycle witness requested only for a cyclic graph")
}

/// State of one stable desired slot in the controller-owned allocation snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllocationState {
    Active,
    Tombstone,
}

/// One immutable stable-ID allocation record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StableAllocationRecord {
    key: [u8; 16],
    ordinal: u64,
    instance: InstanceRef,
    domain: DomainRef,
    state: AllocationState,
}

impl StableAllocationRecord {
    pub(crate) fn try_from_persisted(
        target: RuntimeHostId,
        key: [u8; 16],
        ordinal: u64,
        instance: [u8; 16],
        domain: [u8; 16],
        state: AllocationState,
    ) -> Result<Self, PlannerError> {
        if ordinal == 0
            || derive_id(INSTANCE_ALLOCATION_DOMAIN, target, &key, ordinal)? != instance
            || derive_id(DOMAIN_ALLOCATION_DOMAIN, target, &key, ordinal)? != domain
        {
            return Err(PlannerError::InvalidAllocationSnapshot);
        }
        Ok(Self {
            key,
            ordinal,
            instance: InstanceRef::from_bytes(instance),
            domain: DomainRef::from_bytes(domain),
            state,
        })
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &[u8; 16] {
        &self.key
    }

    #[must_use]
    pub(crate) const fn ordinal(self) -> u64 {
        self.ordinal
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
    pub(crate) const fn state(self) -> AllocationState {
        self.state
    }
}

/// Controller-owned immutable snapshot consumed by the pure Planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StableAllocationSnapshot {
    target: RuntimeHostId,
    generation: u64,
    high_water: u64,
    records: Box<[StableAllocationRecord]>,
}

impl StableAllocationSnapshot {
    pub(crate) fn try_new(
        target: RuntimeHostId,
        generation: u64,
        high_water: u64,
        mut records: Vec<StableAllocationRecord>,
    ) -> Result<Self, PlannerError> {
        if target.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(PlannerError::InvalidAllocationSnapshot);
        }
        if records.len() > MAX_STABLE_ALLOCATION_RECORDS {
            return Err(PlannerError::AllocationCapacityExceeded);
        }
        records.sort_unstable_by_key(|record| record.key);
        let unique_ordinals = records
            .iter()
            .map(|record| record.ordinal)
            .collect::<BTreeSet<_>>();
        let unique_instances = records
            .iter()
            .map(|record| *record.instance.as_bytes())
            .collect::<BTreeSet<_>>();
        let unique_domains = records
            .iter()
            .map(|record| *record.domain.as_bytes())
            .collect::<BTreeSet<_>>();
        let maximum_ordinal = records.iter().map(|record| record.ordinal).max();
        if records.windows(2).any(|pair| pair[0].key == pair[1].key)
            || records
                .iter()
                .any(|record| record.ordinal == 0 || record.ordinal > high_water)
            || unique_ordinals.len() != records.len()
            || unique_instances.len() != records.len()
            || unique_domains.len() != records.len()
            || match maximum_ordinal {
                None => generation != 0 || high_water != 0,
                Some(maximum) => {
                    generation == 0 || generation < high_water || high_water != maximum
                }
            }
        {
            return Err(PlannerError::InvalidAllocationSnapshot);
        }
        for record in &records {
            let expected_instance = derive_id(
                INSTANCE_ALLOCATION_DOMAIN,
                target,
                &record.key,
                record.ordinal,
            )?;
            let expected_domain = derive_id(
                DOMAIN_ALLOCATION_DOMAIN,
                target,
                &record.key,
                record.ordinal,
            )?;
            if record.instance.as_bytes() != &expected_instance
                || record.domain.as_bytes() != &expected_domain
            {
                return Err(PlannerError::InvalidAllocationSnapshot);
            }
        }
        Ok(Self {
            target,
            generation,
            high_water,
            records: records.into_boxed_slice(),
        })
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub(crate) const fn high_water(&self) -> u64 {
        self.high_water
    }

    #[must_use]
    pub(crate) fn records(&self) -> &[StableAllocationRecord] {
        &self.records
    }

    /// Applies only a Planner-owned delta to the persisted allocation snapshot.
    ///
    /// This is the single transition authority shared with the Controller
    /// journal. Callers cannot supply arbitrary derived instance/domain IDs,
    /// skip generations, reuse ordinals, or silently remove historical rows.
    pub(crate) fn apply_delta(&self, delta: &StableAllocationDelta) -> Result<Self, PlannerError> {
        if delta.base_generation != self.generation || delta.resulting_high_water < self.high_water
        {
            return Err(PlannerError::PreviousAllocationMismatch);
        }

        let mut records = self
            .records
            .iter()
            .map(|record| (*record.key(), *record))
            .collect::<BTreeMap<_, _>>();
        let mut changed_keys = BTreeSet::new();
        let mut previous_key = None;
        let mut next_ordinal = self.high_water;
        for change in &delta.records {
            if previous_key.is_some_and(|key| key >= *change.key())
                || !changed_keys.insert(*change.key())
            {
                return Err(PlannerError::InvalidAllocationSnapshot);
            }
            previous_key = Some(*change.key());
            let validated = StableAllocationRecord::try_from_persisted(
                self.target,
                *change.key(),
                change.ordinal(),
                *change.instance().as_bytes(),
                *change.domain().as_bytes(),
                change.state(),
            )?;
            match records.get(change.key()).copied() {
                None => {
                    next_ordinal = next_ordinal
                        .checked_add(1)
                        .ok_or(PlannerError::AllocationExhausted)?;
                    if validated.state != AllocationState::Active
                        || validated.ordinal != next_ordinal
                    {
                        return Err(PlannerError::InvalidAllocationSnapshot);
                    }
                }
                Some(previous)
                    if previous.ordinal == validated.ordinal
                        && previous.instance == validated.instance
                        && previous.domain == validated.domain =>
                {
                    if previous.state != AllocationState::Active
                        || validated.state != AllocationState::Tombstone
                    {
                        return Err(PlannerError::InvalidAllocationSnapshot);
                    }
                }
                Some(previous) => {
                    next_ordinal = next_ordinal
                        .checked_add(1)
                        .ok_or(PlannerError::AllocationExhausted)?;
                    if previous.state != AllocationState::Tombstone
                        || validated.state != AllocationState::Active
                        || validated.ordinal != next_ordinal
                    {
                        return Err(PlannerError::InvalidAllocationSnapshot);
                    }
                }
            }
            records.insert(*change.key(), validated);
        }

        if next_ordinal != delta.resulting_high_water {
            return Err(PlannerError::InvalidAllocationSnapshot);
        }
        let expected_generation = if delta.records.is_empty() {
            self.generation
        } else {
            self.generation
                .checked_add(1)
                .ok_or(PlannerError::AllocationExhausted)?
        };
        if delta.next_generation != expected_generation {
            return Err(PlannerError::PreviousAllocationMismatch);
        }
        Self::try_new(
            self.target,
            delta.next_generation,
            delta.resulting_high_water,
            records.into_values().collect(),
        )
    }

    /// Proves that a decoded persisted snapshot is exactly one legal
    /// Planner-allocation successor of `previous`.
    pub(crate) fn validate_successor_of(&self, previous: &Self) -> Result<(), PlannerError> {
        if self.target != previous.target || self.high_water < previous.high_water {
            return Err(PlannerError::PreviousAllocationMismatch);
        }
        let current = self
            .records
            .iter()
            .map(|record| (*record.key(), *record))
            .collect::<BTreeMap<_, _>>();
        if previous
            .records
            .iter()
            .any(|record| !current.contains_key(record.key()))
        {
            return Err(PlannerError::PreviousAllocationMismatch);
        }
        let changes = self
            .records
            .iter()
            .filter(|record| {
                previous
                    .records
                    .iter()
                    .find(|candidate| candidate.key() == record.key())
                    != Some(*record)
            })
            .copied()
            .collect::<Vec<_>>();
        let delta = StableAllocationDelta {
            base_generation: previous.generation,
            next_generation: self.generation,
            resulting_high_water: self.high_water,
            records: changes.into_boxed_slice(),
        };
        if previous.apply_delta(&delta)? != *self {
            return Err(PlannerError::PreviousAllocationMismatch);
        }
        Ok(())
    }
}

/// Atomic allocation changes committed beside a future plan revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StableAllocationDelta {
    base_generation: u64,
    next_generation: u64,
    resulting_high_water: u64,
    records: Box<[StableAllocationRecord]>,
}

impl StableAllocationDelta {
    #[must_use]
    pub(crate) const fn base_generation(&self) -> u64 {
        self.base_generation
    }

    #[must_use]
    pub(crate) const fn next_generation(&self) -> u64 {
        self.next_generation
    }

    #[must_use]
    pub(crate) const fn resulting_high_water(&self) -> u64 {
        self.resulting_high_water
    }

    #[must_use]
    pub(crate) fn records(&self) -> &[StableAllocationRecord] {
        &self.records
    }
}

/// Digest-covered target desired content.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct PlanManifestDigest(Digest32);

impl PlanManifestDigest {
    pub(crate) fn try_new(value: Digest32) -> Result<Self, PlannerError> {
        if value.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(PlannerError::InvalidManifestDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub(crate) const fn value(self) -> Digest32 {
        self.0
    }
}

/// Digest-covered target desired content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanContent {
    target: RuntimeHostId,
    shape: TargetIntent,
    manifest_digest: PlanManifestDigest,
    stable_allocation_subject: Option<(CardUseKey, InstanceRef, DomainRef)>,
    canonical_bytes: Box<[u8]>,
}

impl PlanContent {
    /// Strictly reconstructs Planner-owned committed content from canonical
    /// bytes. The journal uses this instead of accepting an untyped byte body.
    pub(crate) fn try_from_persisted(
        expected_target: RuntimeHostId,
        canonical_bytes: &[u8],
    ) -> Result<Self, PlannerError> {
        let mut reader = PersistedPlanContentReader::new(canonical_bytes);
        if reader.take(PLAN_CONTENT_MAGIC.len())? != PLAN_CONTENT_MAGIC {
            return Err(PlannerError::InvalidPersistedPlanContent);
        }
        if reader.u16()? != PLAN_CONTENT_VERSION {
            return Err(PlannerError::InvalidPersistedPlanContent);
        }
        let shape = match reader.u8()? {
            1 => TargetIntent::OneSourceLoop,
            2 => TargetIntent::EmptyTarget,
            _ => return Err(PlannerError::InvalidPersistedPlanContent),
        };
        let target = reader.array::<16>()?;
        if target != *expected_target.as_bytes() {
            return Err(PlannerError::InvalidPersistedPlanContent);
        }
        let profile_fingerprint = reader.array::<32>()?;
        let manifest_digest =
            PlanManifestDigest::try_new(Digest32::from_bytes(reader.array::<32>()?))?;
        let projection_length =
            usize::try_from(reader.u64()?).map_err(|_| PlannerError::CanonicalLengthOverflow)?;
        let projection = reader.take(projection_length)?;
        let fixture_definition = reader.array::<16>()?;
        let fixture_implementation = reader.array::<16>()?;
        let fixture_export = reader.array::<16>()?;
        let fixture_definition_digest = reader.array::<32>()?;
        let fixture_artifact_digest = reader.array::<32>()?;

        let (stable_allocation_subject, loop_fields) = if shape == TargetIntent::OneSourceLoop {
            let deck_lock_digest = reader.array::<32>()?;
            let key = reader.array::<16>()?;
            let instance = reader.array::<16>()?;
            let domain = reader.array::<16>()?;
            let lifecycle = [reader.u64()?, reader.u64()?, reader.u64()?];
            // The exact upper bound remains owned by the private Runtime
            // reference contract and is consumed through the future validated
            // adapter. The persisted Planner value can still prove the
            // constructor-level nonzero invariant without duplicating that
            // protocol constant in this crate.
            if lifecycle.contains(&0) {
                return Err(PlannerError::InvalidPersistedPlanContent);
            }
            let config_digest = reader.array::<32>()?;
            (
                Some((
                    CardUseKey::from_bytes(key),
                    InstanceRef::from_bytes(instance),
                    DomainRef::from_bytes(domain),
                )),
                Some((
                    deck_lock_digest,
                    key,
                    instance,
                    domain,
                    lifecycle,
                    config_digest,
                )),
            )
        } else {
            (None, None)
        };
        if reader.remaining() != 0 {
            return Err(PlannerError::InvalidPersistedPlanContent);
        }

        // Rebuild every parseable field through the sole canonical layout and
        // demand byte equality. The manifest projection body remains opaque;
        // its exact bytes and explicit length are nevertheless preserved.
        let mut rebuilt = Vec::with_capacity(canonical_bytes.len());
        rebuilt.extend_from_slice(PLAN_CONTENT_MAGIC);
        rebuilt.extend_from_slice(&PLAN_CONTENT_VERSION.to_be_bytes());
        rebuilt.push(match shape {
            TargetIntent::OneSourceLoop => 1,
            TargetIntent::EmptyTarget => 2,
            TargetIntent::Omitted => unreachable!("persisted PlanContent cannot be omitted"),
        });
        rebuilt.extend_from_slice(&target);
        rebuilt.extend_from_slice(&profile_fingerprint);
        rebuilt.extend_from_slice(manifest_digest.value().as_bytes());
        rebuilt.extend_from_slice(
            &u64::try_from(projection.len())
                .map_err(|_| PlannerError::CanonicalLengthOverflow)?
                .to_be_bytes(),
        );
        rebuilt.extend_from_slice(projection);
        rebuilt.extend_from_slice(&fixture_definition);
        rebuilt.extend_from_slice(&fixture_implementation);
        rebuilt.extend_from_slice(&fixture_export);
        rebuilt.extend_from_slice(&fixture_definition_digest);
        rebuilt.extend_from_slice(&fixture_artifact_digest);
        if let Some((deck_lock_digest, key, instance, domain, lifecycle, config_digest)) =
            loop_fields
        {
            rebuilt.extend_from_slice(&deck_lock_digest);
            rebuilt.extend_from_slice(&key);
            rebuilt.extend_from_slice(&instance);
            rebuilt.extend_from_slice(&domain);
            for budget in lifecycle {
                rebuilt.extend_from_slice(&budget.to_be_bytes());
            }
            rebuilt.extend_from_slice(&config_digest);
        }
        if rebuilt != canonical_bytes {
            return Err(PlannerError::InvalidPersistedPlanContent);
        }

        Ok(Self {
            target: expected_target,
            shape,
            manifest_digest,
            stable_allocation_subject,
            canonical_bytes: canonical_bytes.into(),
        })
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn shape(&self) -> TargetIntent {
        self.shape
    }

    #[must_use]
    pub(crate) const fn manifest_digest(&self) -> PlanManifestDigest {
        self.manifest_digest
    }

    #[must_use]
    pub(crate) const fn stable_allocation_subject(
        &self,
    ) -> Option<(CardUseKey, InstanceRef, DomainRef)> {
        self.stable_allocation_subject
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

struct PersistedPlanContentReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PersistedPlanContentReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PlannerError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PlannerError::CanonicalLengthOverflow)?;
        let Some(value) = self.bytes.get(self.offset..end) else {
            return Err(PlannerError::InvalidPersistedPlanContent);
        };
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PlannerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PlannerError::InvalidPersistedPlanContent)
    }

    fn u8(&mut self) -> Result<u8, PlannerError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, PlannerError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u64(&mut self) -> Result<u64, PlannerError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }
}

/// PlanContent-only digest. Allocation and diagnostics are deliberately siblings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PlanContentDigest(Digest32);

impl PlanContentDigest {
    #[must_use]
    pub(crate) const fn from_stored(value: Digest32) -> Self {
        Self(value)
    }

    pub(crate) fn try_for_content(content: &PlanContent) -> Result<Self, PlannerError> {
        let mut builder = Digest32Builder::try_new(PLAN_CONTENT_DIGEST_DOMAIN)?;
        builder.field_bytes(content.canonical_bytes())?;
        Ok(Self(builder.finish()))
    }

    #[must_use]
    pub(crate) const fn value(self) -> Digest32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlannerDiagnostic {
    FreshStableAllocation,
    ReusedStableAllocation,
    StableAllocationTombstoned,
}

/// Non-authoritative pure Planner output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeploymentPlanCandidate {
    content: PlanContent,
    allocation_delta: StableAllocationDelta,
    diagnostics: Box<[PlannerDiagnostic]>,
    content_digest: PlanContentDigest,
}

impl DeploymentPlanCandidate {
    #[must_use]
    pub(crate) const fn content(&self) -> &PlanContent {
        &self.content
    }

    #[must_use]
    pub(crate) const fn allocation_delta(&self) -> &StableAllocationDelta {
        &self.allocation_delta
    }

    #[must_use]
    pub(crate) fn diagnostics(&self) -> &[PlannerDiagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub(crate) const fn content_digest(&self) -> PlanContentDigest {
        self.content_digest
    }
}

/// Omitted has no candidate and cannot be committed as canonical empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PlannerOutcome {
    Candidate(Box<DeploymentPlanCandidate>),
    Omitted,
}

/// The only S7 desired shapes. Only the non-empty shape consumes a DeckLock.
pub(crate) enum PlannerDesired<'a> {
    OneSourceLoop {
        deck_lock: &'a DeckLock,
        lifecycle: ValidatedReferenceLifecycleBudgets,
        config_digest: Digest32,
    },
    EmptyTarget,
    Omitted,
}

/// Complete immutable input to the pure Planner.
pub(crate) struct PlannerInput<'a> {
    pub(crate) target: RuntimeHostId,
    pub(crate) desired: PlannerDesired<'a>,
    pub(crate) previous: PreviousTargetEligibility,
    pub(crate) manifest: Option<&'a OpaqueManifestProjectionIngress<'a>>,
    pub(crate) allocation: &'a StableAllocationSnapshot,
    pub(crate) service_dependencies: &'a [ServiceDependency],
}

/// Stable S7 planner rejection taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PlannerError {
    ServiceDependency(ServiceDependencyError),
    UnsupportedServiceDependency,
    MissingManifestProjection,
    ManifestTargetMismatch,
    ManifestFixtureMismatch,
    InvalidManifestDigest,
    ConfigMismatch,
    AllocationTargetMismatch,
    PreviousAllocationMismatch,
    InvalidAllocationSnapshot,
    AllocationCapacityExceeded,
    AllocationExhausted,
    UnsupportedDeckShape,
    UnsupportedLink,
    UnsupportedRequirement,
    UnsupportedPerUseConfig,
    UnsupportedPort,
    UnsupportedRefinement,
    UnsupportedGeneralCard,
    LoopToLoopRejected,
    ExplicitEmptyRequiredBeforeLoop,
    ExplicitEmptyRequiredBeforeOmit,
    EmptyBootstrapRejected,
    PreviousTargetNotTerminal,
    PreviousTargetBusy,
    PreviousTargetIneligible,
    InvalidLifecycleBudget,
    InvalidPersistedPlanContent,
    CanonicalLengthOverflow,
    Digest(DigestBuildError),
}

impl From<DigestBuildError> for PlannerError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for PlannerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ServiceDependency(ServiceDependencyError::TooManyVertices) => {
                "too many ServiceDependency vertices"
            }
            Self::ServiceDependency(ServiceDependencyError::TooManyEdges) => {
                "too many ServiceDependency edges"
            }
            Self::ServiceDependency(ServiceDependencyError::DuplicateDependency) => {
                "duplicate ServiceDependency"
            }
            Self::ServiceDependency(ServiceDependencyError::Cycle(_)) => {
                "cyclic ServiceDependency graph"
            }
            Self::UnsupportedServiceDependency => "ServiceDependency is unsupported by S7",
            Self::MissingManifestProjection => "manifest projection is required",
            Self::ManifestTargetMismatch => "manifest projection target mismatch",
            Self::ManifestFixtureMismatch => "manifest fixture mismatch",
            Self::InvalidManifestDigest => "manifest digest must be nonzero",
            Self::ConfigMismatch => "reference config digest mismatch",
            Self::AllocationTargetMismatch => "allocation snapshot target mismatch",
            Self::PreviousAllocationMismatch => {
                "previous target state and active allocation records disagree"
            }
            Self::InvalidAllocationSnapshot => "invalid stable allocation snapshot",
            Self::AllocationCapacityExceeded => "stable allocation record capacity exceeded",
            Self::AllocationExhausted => "stable allocation counter exhausted",
            Self::UnsupportedDeckShape => "unsupported S7 Deck shape",
            Self::UnsupportedLink => "Deck links are unsupported by S7",
            Self::UnsupportedRequirement => "Deck requirements are unsupported by S7",
            Self::UnsupportedPerUseConfig => "per-use config is unsupported by S7",
            Self::UnsupportedPort => "Card Ports are unsupported by S7",
            Self::UnsupportedRefinement => "Card refinement is unsupported by S7",
            Self::UnsupportedGeneralCard => "general Card role is unsupported by S7",
            Self::LoopToLoopRejected => "OneSourceLoop to OneSourceLoop is unsupported",
            Self::ExplicitEmptyRequiredBeforeLoop => {
                "failed OneSourceLoop must transition through terminal empty before restart"
            }
            Self::ExplicitEmptyRequiredBeforeOmit => {
                "active target must transition through terminal empty before omission"
            }
            Self::EmptyBootstrapRejected => "EmptyDeactivate cannot bootstrap an absent target",
            Self::PreviousTargetNotTerminal => {
                "previous EmptyDeactivate has not reached terminal exact-zero"
            }
            Self::PreviousTargetBusy => "previous target has a nonterminal Runtime action",
            Self::PreviousTargetIneligible => "previous target state is ineligible for planning",
            Self::InvalidLifecycleBudget => "invalid reference lifecycle budget",
            Self::InvalidPersistedPlanContent => "invalid persisted PlanContent",
            Self::CanonicalLengthOverflow => "PlanContent canonical length overflow",
            Self::Digest(_) => "PlanContent digest construction failed",
        })
    }
}

impl std::error::Error for PlannerError {}

pub(crate) struct DeploymentPlanner;

impl DeploymentPlanner {
    pub(crate) fn plan(input: &PlannerInput<'_>) -> Result<PlannerOutcome, PlannerError> {
        let service_order = validate_service_dependencies(input.service_dependencies)
            .map_err(PlannerError::ServiceDependency)?;
        if !service_order.startup().is_empty() {
            return Err(PlannerError::UnsupportedServiceDependency);
        }
        validate_transition(input.previous, &input.desired)?;
        if input.allocation.target != input.target {
            return Err(PlannerError::AllocationTargetMismatch);
        }
        validate_previous_allocation(input.previous, input.allocation)?;
        if matches!(&input.desired, PlannerDesired::Omitted) {
            return Ok(PlannerOutcome::Omitted);
        }
        let manifest = input
            .manifest
            .ok_or(PlannerError::MissingManifestProjection)?;
        if manifest.target != input.target {
            return Err(PlannerError::ManifestTargetMismatch);
        }

        match &input.desired {
            PlannerDesired::OneSourceLoop {
                deck_lock,
                lifecycle,
                config_digest,
            } => Self::plan_loop(input, manifest, deck_lock, *lifecycle, *config_digest),
            PlannerDesired::EmptyTarget => Self::plan_empty(input, manifest),
            PlannerDesired::Omitted => unreachable!("omitted returned before manifest planning"),
        }
    }

    fn plan_loop(
        input: &PlannerInput<'_>,
        manifest: &OpaqueManifestProjectionIngress<'_>,
        deck_lock: &DeckLock,
        lifecycle: ValidatedReferenceLifecycleBudgets,
        config_digest: Digest32,
    ) -> Result<PlannerOutcome, PlannerError> {
        if config_digest != manifest.canonical_empty_config_digest {
            return Err(PlannerError::ConfigMismatch);
        }
        let topology = deck_lock.topology();
        let closure = deck_lock.resolved_closure();
        if !topology.links().is_empty() {
            return Err(PlannerError::UnsupportedLink);
        }
        if !topology.requirements().is_empty() {
            return Err(PlannerError::UnsupportedRequirement);
        }
        if topology.card_keys().len() != 1 || closure.cards().len() != 1 {
            return Err(PlannerError::UnsupportedDeckShape);
        }
        let card = &closure.cards()[0];
        if card.has_ports() {
            return Err(PlannerError::UnsupportedPort);
        }
        if card.has_per_use_config() {
            return Err(PlannerError::UnsupportedPerUseConfig);
        }
        if card.has_refinement() {
            return Err(PlannerError::UnsupportedRefinement);
        }
        if !card.is_reference_subject() {
            return Err(PlannerError::UnsupportedGeneralCard);
        }
        if topology.card_keys()[0].as_bytes() != card.key().as_bytes() {
            return Err(PlannerError::UnsupportedDeckShape);
        }
        if manifest.fixture.definition != card.definition()
            || manifest.fixture.implementation != card.implementation()
            || manifest.fixture.export != *card.export().as_bytes()
            || manifest.fixture.definition_digest != card.definition_digest()
            || manifest.fixture.artifact_digest != card.artifact_digest()
        {
            return Err(PlannerError::ManifestFixtureMismatch);
        }

        let (allocation, delta, diagnostics) =
            allocate_active(input.target, card.key(), input.allocation)?;
        let content = build_content(
            input.target,
            TargetIntent::OneSourceLoop,
            Some(deck_lock),
            manifest,
            Some((card.key(), allocation.instance, allocation.domain)),
            Some((lifecycle, config_digest)),
        )?;
        Ok(PlannerOutcome::Candidate(Box::new(candidate(
            content,
            delta,
            diagnostics,
        )?)))
    }

    fn plan_empty(
        input: &PlannerInput<'_>,
        manifest: &OpaqueManifestProjectionIngress<'_>,
    ) -> Result<PlannerOutcome, PlannerError> {
        let active = input
            .allocation
            .records
            .iter()
            .filter(|record| record.state == AllocationState::Active)
            .map(|record| StableAllocationRecord {
                state: AllocationState::Tombstone,
                ..*record
            })
            .collect::<Vec<_>>();
        let changed = !active.is_empty();
        let next_generation = advance_generation(input.allocation.generation, changed)?;
        let delta = StableAllocationDelta {
            base_generation: input.allocation.generation,
            next_generation,
            resulting_high_water: input.allocation.high_water,
            records: active.into_boxed_slice(),
        };
        let diagnostics = changed
            .then_some(PlannerDiagnostic::StableAllocationTombstoned)
            .into_iter()
            .collect();
        let content = build_content(
            input.target,
            TargetIntent::EmptyTarget,
            None,
            manifest,
            None,
            None,
        )?;
        Ok(PlannerOutcome::Candidate(Box::new(candidate(
            content,
            delta,
            diagnostics,
        )?)))
    }
}

fn validate_transition(
    previous: PreviousTargetEligibility,
    desired: &PlannerDesired<'_>,
) -> Result<(), PlannerError> {
    if previous == PreviousTargetEligibility::Busy {
        return Err(PlannerError::PreviousTargetBusy);
    }
    if previous == PreviousTargetEligibility::Ineligible {
        return Err(PlannerError::PreviousTargetIneligible);
    }
    if previous == PreviousTargetEligibility::EmptyDeactivateRetiring {
        return Err(PlannerError::PreviousTargetNotTerminal);
    }

    match desired {
        PlannerDesired::OneSourceLoop { .. } => match previous {
            PreviousTargetEligibility::UninitializedNoneExactZero
            | PreviousTargetEligibility::EmptyDeactivateTerminalExactZero => Ok(()),
            PreviousTargetEligibility::OneSourceLoopLiveReady => {
                Err(PlannerError::LoopToLoopRejected)
            }
            PreviousTargetEligibility::OneSourceLoopRecoveryFailedExactZero => {
                Err(PlannerError::ExplicitEmptyRequiredBeforeLoop)
            }
            PreviousTargetEligibility::EmptyDeactivateRetiring
            | PreviousTargetEligibility::Busy
            | PreviousTargetEligibility::Ineligible => {
                unreachable!("globally rejected before desired-specific transition")
            }
        },
        PlannerDesired::EmptyTarget => match previous {
            PreviousTargetEligibility::UninitializedNoneExactZero => {
                Err(PlannerError::EmptyBootstrapRejected)
            }
            PreviousTargetEligibility::OneSourceLoopLiveReady
            | PreviousTargetEligibility::OneSourceLoopRecoveryFailedExactZero
            | PreviousTargetEligibility::EmptyDeactivateTerminalExactZero => Ok(()),
            PreviousTargetEligibility::EmptyDeactivateRetiring
            | PreviousTargetEligibility::Busy
            | PreviousTargetEligibility::Ineligible => {
                unreachable!("globally rejected before desired-specific transition")
            }
        },
        PlannerDesired::Omitted => match previous {
            PreviousTargetEligibility::UninitializedNoneExactZero
            | PreviousTargetEligibility::EmptyDeactivateTerminalExactZero => Ok(()),
            PreviousTargetEligibility::OneSourceLoopLiveReady
            | PreviousTargetEligibility::OneSourceLoopRecoveryFailedExactZero => {
                Err(PlannerError::ExplicitEmptyRequiredBeforeOmit)
            }
            PreviousTargetEligibility::EmptyDeactivateRetiring
            | PreviousTargetEligibility::Busy
            | PreviousTargetEligibility::Ineligible => {
                unreachable!("globally rejected before desired-specific transition")
            }
        },
    }
}

fn validate_previous_allocation(
    previous: PreviousTargetEligibility,
    snapshot: &StableAllocationSnapshot,
) -> Result<(), PlannerError> {
    let active_count = snapshot
        .records
        .iter()
        .filter(|record| record.state == AllocationState::Active)
        .count();
    let expected_active_count = match previous {
        PreviousTargetEligibility::UninitializedNoneExactZero
        | PreviousTargetEligibility::EmptyDeactivateTerminalExactZero => 0,
        PreviousTargetEligibility::OneSourceLoopLiveReady
        | PreviousTargetEligibility::OneSourceLoopRecoveryFailedExactZero => 1,
        PreviousTargetEligibility::EmptyDeactivateRetiring
        | PreviousTargetEligibility::Busy
        | PreviousTargetEligibility::Ineligible => {
            unreachable!("ineligible transitions reject before allocation coherence")
        }
    };
    if active_count != expected_active_count {
        return Err(PlannerError::PreviousAllocationMismatch);
    }
    Ok(())
}

fn allocate_active(
    target: RuntimeHostId,
    key: CardUseKey,
    snapshot: &StableAllocationSnapshot,
) -> Result<
    (
        StableAllocationRecord,
        StableAllocationDelta,
        Vec<PlannerDiagnostic>,
    ),
    PlannerError,
> {
    let desired = snapshot
        .records
        .iter()
        .find(|record| record.key == *key.as_bytes())
        .copied();
    let mut changes = snapshot
        .records
        .iter()
        .filter(|record| record.state == AllocationState::Active && record.key != *key.as_bytes())
        .map(|record| StableAllocationRecord {
            state: AllocationState::Tombstone,
            ..*record
        })
        .collect::<Vec<_>>();
    let tombstoned_extras = !changes.is_empty();

    if let Some(record) = desired.filter(|record| record.state == AllocationState::Active) {
        let changed = tombstoned_extras;
        let mut diagnostics = vec![PlannerDiagnostic::ReusedStableAllocation];
        if tombstoned_extras {
            diagnostics.push(PlannerDiagnostic::StableAllocationTombstoned);
        }
        return Ok((
            record,
            StableAllocationDelta {
                base_generation: snapshot.generation,
                next_generation: advance_live_generation(snapshot.generation, changed)?,
                resulting_high_water: snapshot.high_water,
                records: changes.into_boxed_slice(),
            },
            diagnostics,
        ));
    }
    if desired.is_none() && snapshot.records.len() == MAX_STABLE_ALLOCATION_RECORDS {
        return Err(PlannerError::AllocationCapacityExceeded);
    }

    let ordinal = snapshot
        .high_water
        .checked_add(1)
        .ok_or(PlannerError::AllocationExhausted)?;
    let instance = InstanceRef::from_bytes(derive_id(
        INSTANCE_ALLOCATION_DOMAIN,
        target,
        key.as_bytes(),
        ordinal,
    )?);
    let domain = DomainRef::from_bytes(derive_id(
        DOMAIN_ALLOCATION_DOMAIN,
        target,
        key.as_bytes(),
        ordinal,
    )?);
    let record = StableAllocationRecord {
        key: *key.as_bytes(),
        ordinal,
        instance,
        domain,
        state: AllocationState::Active,
    };
    changes.push(record);
    changes.sort_unstable_by_key(|change| change.key);
    let delta = StableAllocationDelta {
        base_generation: snapshot.generation,
        next_generation: advance_live_generation(snapshot.generation, true)?,
        resulting_high_water: ordinal,
        records: changes.into_boxed_slice(),
    };
    let mut diagnostics = vec![PlannerDiagnostic::FreshStableAllocation];
    if tombstoned_extras {
        diagnostics.push(PlannerDiagnostic::StableAllocationTombstoned);
    }
    Ok((record, delta, diagnostics))
}

fn derive_id(
    domain: &[u8],
    target: RuntimeHostId,
    key: &[u8; 16],
    ordinal: u64,
) -> Result<[u8; 16], PlannerError> {
    let mut builder = Digest32Builder::try_new(domain)?;
    builder
        .field_bytes(target.as_bytes())?
        .field_bytes(key)?
        .field_u64(ordinal)?;
    let digest = builder.finish().into_bytes();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(id)
}

fn advance_generation(base: u64, changed: bool) -> Result<u64, PlannerError> {
    if changed {
        base.checked_add(1).ok_or(PlannerError::AllocationExhausted)
    } else {
        Ok(base)
    }
}

fn advance_live_generation(base: u64, changed: bool) -> Result<u64, PlannerError> {
    if base == u64::MAX {
        return Err(PlannerError::AllocationExhausted);
    }
    let next = advance_generation(base, changed)?;
    if changed && next == u64::MAX {
        return Err(PlannerError::AllocationExhausted);
    }
    Ok(next)
}

fn build_content(
    target: RuntimeHostId,
    shape: TargetIntent,
    deck_lock: Option<&DeckLock>,
    manifest: &OpaqueManifestProjectionIngress<'_>,
    subject: Option<(CardUseKey, InstanceRef, DomainRef)>,
    loop_facts: Option<(ValidatedReferenceLifecycleBudgets, Digest32)>,
) -> Result<PlanContent, PlannerError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PLAN_CONTENT_MAGIC);
    bytes.extend_from_slice(&PLAN_CONTENT_VERSION.to_be_bytes());
    bytes.push(match shape {
        TargetIntent::OneSourceLoop => 1,
        TargetIntent::EmptyTarget => 2,
        TargetIntent::Omitted => unreachable!("omitted has no PlanContent"),
    });
    bytes.extend_from_slice(target.as_bytes());
    bytes.extend_from_slice(manifest.profile_fingerprint.as_bytes());
    bytes.extend_from_slice(manifest.manifest_digest.value().as_bytes());
    let projection_length = u64::try_from(manifest.canonical_projection.len())
        .map_err(|_| PlannerError::CanonicalLengthOverflow)?;
    bytes.extend_from_slice(&projection_length.to_be_bytes());
    bytes.extend_from_slice(manifest.canonical_projection);
    bytes.extend_from_slice(manifest.fixture.definition.as_bytes());
    bytes.extend_from_slice(manifest.fixture.implementation.as_bytes());
    bytes.extend_from_slice(&manifest.fixture.export);
    bytes.extend_from_slice(manifest.fixture.definition_digest.as_bytes());
    bytes.extend_from_slice(manifest.fixture.artifact_digest.as_bytes());
    if let Some((key, instance, domain)) = subject {
        let Some(deck_lock) = deck_lock else {
            unreachable!("subject content always carries one DeckLock");
        };
        bytes.extend_from_slice(deck_lock.digest().as_bytes());
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(instance.as_bytes());
        bytes.extend_from_slice(domain.as_bytes());
        let Some((lifecycle, config_digest)) = loop_facts else {
            unreachable!("subject content always carries lifecycle/config facts");
        };
        for budget in lifecycle.values() {
            if budget.value() == 0 {
                return Err(PlannerError::InvalidLifecycleBudget);
            }
            bytes.extend_from_slice(&budget.value().to_be_bytes());
        }
        bytes.extend_from_slice(config_digest.as_bytes());
    }
    Ok(PlanContent {
        target,
        shape,
        manifest_digest: manifest.manifest_digest,
        stable_allocation_subject: subject,
        canonical_bytes: bytes.into_boxed_slice(),
    })
}

fn candidate(
    content: PlanContent,
    allocation_delta: StableAllocationDelta,
    diagnostics: Vec<PlannerDiagnostic>,
) -> Result<DeploymentPlanCandidate, PlannerError> {
    let content_digest = PlanContentDigest::try_for_content(&content)?;
    Ok(DeploymentPlanCandidate {
        content,
        allocation_delta,
        diagnostics: diagnostics.into_boxed_slice(),
        content_digest,
    })
}

/// Test-only typed Planner output used by the Controller journal model tests.
/// Production code has no raw candidate constructor.
#[cfg(test)]
pub(crate) fn journal_test_candidate(
    target: RuntimeHostId,
    allocation: &StableAllocationSnapshot,
    desired_key: Option<[u8; 16]>,
    marker: u8,
) -> Result<DeploymentPlanCandidate, PlannerError> {
    let (shape, subject, delta, diagnostics) = if let Some(key) = desired_key {
        let (selected, delta, diagnostics) =
            allocate_active(target, CardUseKey::from_bytes(key), allocation)?;
        (
            TargetIntent::OneSourceLoop,
            Some((
                CardUseKey::from_bytes(key),
                selected.instance(),
                selected.domain(),
            )),
            delta,
            diagnostics,
        )
    } else {
        let changes = allocation
            .records()
            .iter()
            .filter(|record| record.state() == AllocationState::Active)
            .map(|record| StableAllocationRecord {
                state: AllocationState::Tombstone,
                ..*record
            })
            .collect::<Vec<_>>();
        let changed = !changes.is_empty();
        (
            TargetIntent::EmptyTarget,
            None,
            StableAllocationDelta {
                base_generation: allocation.generation(),
                next_generation: advance_generation(allocation.generation(), changed)?,
                resulting_high_water: allocation.high_water(),
                records: changes.into_boxed_slice(),
            },
            Vec::new(),
        )
    };

    let projection = [marker; 7];
    let mut canonical_bytes = Vec::new();
    canonical_bytes.extend_from_slice(PLAN_CONTENT_MAGIC);
    canonical_bytes.extend_from_slice(&PLAN_CONTENT_VERSION.to_be_bytes());
    canonical_bytes.push(match shape {
        TargetIntent::OneSourceLoop => 1,
        TargetIntent::EmptyTarget => 2,
        TargetIntent::Omitted => unreachable!("test candidate never encodes Omitted"),
    });
    canonical_bytes.extend_from_slice(target.as_bytes());
    canonical_bytes.extend_from_slice(&[marker.wrapping_add(1); 32]);
    let manifest_digest =
        PlanManifestDigest::try_new(Digest32::from_bytes([marker.wrapping_add(2); 32]))?;
    canonical_bytes.extend_from_slice(manifest_digest.value().as_bytes());
    canonical_bytes.extend_from_slice(&(projection.len() as u64).to_be_bytes());
    canonical_bytes.extend_from_slice(&projection);
    canonical_bytes.extend_from_slice(&[marker.wrapping_add(3); 16]);
    canonical_bytes.extend_from_slice(&[marker.wrapping_add(4); 16]);
    canonical_bytes.extend_from_slice(&[marker.wrapping_add(5); 16]);
    canonical_bytes.extend_from_slice(&[marker.wrapping_add(6); 32]);
    canonical_bytes.extend_from_slice(&[marker.wrapping_add(7); 32]);
    if let Some((key, instance, domain)) = subject {
        canonical_bytes.extend_from_slice(&[marker.wrapping_add(8); 32]);
        canonical_bytes.extend_from_slice(key.as_bytes());
        canonical_bytes.extend_from_slice(instance.as_bytes());
        canonical_bytes.extend_from_slice(domain.as_bytes());
        canonical_bytes.extend_from_slice(&1_u64.to_be_bytes());
        canonical_bytes.extend_from_slice(&2_u64.to_be_bytes());
        canonical_bytes.extend_from_slice(&3_u64.to_be_bytes());
        canonical_bytes.extend_from_slice(&[marker.wrapping_add(9); 32]);
    }
    candidate(
        PlanContent {
            target,
            shape,
            manifest_digest,
            stable_allocation_subject: subject,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
        },
        delta,
        diagnostics,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AllocationState, DeploymentPlanner, ManifestFixtureFacts, OpaqueManifestProjectionIngress,
        PlanManifestDigest, PlannerDesired, PlannerDiagnostic, PlannerError, PlannerInput,
        PlannerOutcome, PreviousTargetEligibility, ServiceDependency, ServiceDependencyError,
        ServiceRef, StableAllocationRecord, StableAllocationSnapshot, TargetIntent,
        ValidatedReferenceLifecycleBudgets, allocate_active, validate_service_dependencies,
        validate_transition,
    };
    use crate::deck::{
        CardRefinementRef, CardRefinementRequest, CardUseKey, DeckCardConfig, DeckCardRole,
        DeckCardSpec, DeckCompiler, DeckEndpointSpec, DeckExportRef, DeckKey, DeckLifetimeRequest,
        DeckLinkKey, DeckLinkSpec, DeckLock, DeckOwnershipRequest, DeckPortKey,
        DeckRequirementSpec, DeckResolverSnapshot, DeckSpec, DeliveryProfileRef, RequirementKey,
        RequirementRef, ResolvedCardArtifact, ResolvedCardDefinition,
        ResolvedCardRefinementCommitment, ResolvedDeckPort, ResolvedDeliveryProfileCommitment,
        ResolvedRequirementCommitment,
    };
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::assignment::{
        InstanceRef, InteractionKind, PortCardinality, PortDirection, PortSpec, SchemaRef,
    };
    use paraegox_runtime_contracts::execution::{
        CardDefinitionRef, CardImplementationRef, DomainRef,
    };

    fn service(byte: u8) -> ServiceRef {
        ServiceRef::from_bytes([byte; 16])
    }

    fn indexed_service(index: usize) -> ServiceRef {
        let mut bytes = [0_u8; 16];
        bytes[14..].copy_from_slice(
            &u16::try_from(index)
                .expect("test service index must fit")
                .to_be_bytes(),
        );
        ServiceRef::from_bytes(bytes)
    }

    fn record(
        target: RuntimeHostId,
        key: u8,
        ordinal: u64,
        state: AllocationState,
    ) -> StableAllocationRecord {
        record_with_key(target, [key; 16], ordinal, state)
    }

    fn record_with_key(
        target: RuntimeHostId,
        key_bytes: [u8; 16],
        ordinal: u64,
        state: AllocationState,
    ) -> StableAllocationRecord {
        StableAllocationRecord {
            key: key_bytes,
            ordinal,
            instance: InstanceRef::from_bytes(
                super::derive_id(
                    super::INSTANCE_ALLOCATION_DOMAIN,
                    target,
                    &key_bytes,
                    ordinal,
                )
                .expect("test instance identity must derive"),
            ),
            domain: DomainRef::from_bytes(
                super::derive_id(super::DOMAIN_ALLOCATION_DOMAIN, target, &key_bytes, ordinal)
                    .expect("test domain identity must derive"),
            ),
            state,
        }
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn target(byte: u8) -> RuntimeHostId {
        RuntimeHostId::from_bytes([byte; 16])
    }

    fn reference_deck(config: DeckCardConfig, role: DeckCardRole) -> DeckLock {
        reference_deck_with_ports(config, role, Vec::new())
    }

    fn reference_deck_with_deck_key(deck_key: u8) -> DeckLock {
        reference_deck_with_key_and_ports(
            DeckKey::from_bytes([deck_key; 16]),
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
            Vec::new(),
        )
    }

    fn reference_deck_with_ports(
        config: DeckCardConfig,
        role: DeckCardRole,
        ports: Vec<ResolvedDeckPort>,
    ) -> DeckLock {
        reference_deck_with_key_and_ports(DeckKey::from_bytes([1; 16]), config, role, ports)
    }

    fn reference_deck_with_key_and_ports(
        deck_key: DeckKey,
        config: DeckCardConfig,
        role: DeckCardRole,
        ports: Vec<ResolvedDeckPort>,
    ) -> DeckLock {
        let definition = CardDefinitionRef::from_bytes([10; 16]);
        let spec = DeckSpec::new(
            deck_key,
            vec![
                DeckCardSpec::new(CardUseKey::from_bytes([2; 16]), definition, config)
                    .with_role(role),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DeckOwnershipRequest::Deck,
            DeckLifetimeRequest::Deck,
        );
        let resolver = DeckResolverSnapshot::new(vec![ResolvedCardDefinition::new(
            definition,
            1,
            ResolvedCardArtifact::new(
                digest(10),
                CardImplementationRef::from_bytes([0x4a; 16]),
                DeckExportRef::from_bytes([0x5a; 16]),
                digest(0x6a),
            ),
            ports,
        )]);
        DeckCompiler::compile(&spec, &resolver).expect("reference Deck must compile")
    }

    fn reference_deck_with_port() -> DeckLock {
        let schema =
            SchemaRef::try_new([0x31; 16], 1, digest(0x32)).expect("test SchemaRef must validate");
        reference_deck_with_ports(
            DeckCardConfig::Digest(digest(0x34)),
            DeckCardRole::General,
            vec![ResolvedDeckPort::new(
                DeckPortKey::from_bytes([0x33; 16]),
                PortSpec::new(
                    PortDirection::Out,
                    schema,
                    InteractionKind::Event,
                    PortCardinality::One,
                ),
            )],
        )
    }

    fn reference_deck_with_refinement() -> DeckLock {
        let definition = CardDefinitionRef::from_bytes([10; 16]);
        let refinement = CardRefinementRef::from_bytes([0x7a; 16]);
        let spec = DeckSpec::new(
            DeckKey::from_bytes([1; 16]),
            vec![
                DeckCardSpec::new(
                    CardUseKey::from_bytes([2; 16]),
                    definition,
                    DeckCardConfig::CanonicalEmpty,
                )
                .with_role(DeckCardRole::General)
                .with_refinement(CardRefinementRequest::new(refinement)),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DeckOwnershipRequest::Deck,
            DeckLifetimeRequest::Deck,
        );
        let definition = ResolvedCardDefinition::new(
            definition,
            1,
            ResolvedCardArtifact::new(
                digest(10),
                CardImplementationRef::from_bytes([0x4a; 16]),
                DeckExportRef::from_bytes([0x5a; 16]),
                digest(0x6a),
            ),
            Vec::new(),
        )
        .with_refinements(vec![ResolvedCardRefinementCommitment::new(
            refinement,
            digest(0x7b),
        )]);
        DeckCompiler::compile(&spec, &DeckResolverSnapshot::new(vec![definition]))
            .expect("refined Deck must compile before the narrow Planner rejects it")
    }

    fn matrix_card(
        key: u8,
        definition: u8,
        config: DeckCardConfig,
        role: DeckCardRole,
    ) -> DeckCardSpec {
        DeckCardSpec::new(
            CardUseKey::from_bytes([key; 16]),
            CardDefinitionRef::from_bytes([definition; 16]),
            config,
        )
        .with_role(role)
    }

    fn matrix_definition(definition: u8, ports: Vec<ResolvedDeckPort>) -> ResolvedCardDefinition {
        ResolvedCardDefinition::new(
            CardDefinitionRef::from_bytes([definition; 16]),
            1,
            ResolvedCardArtifact::new(
                digest(definition),
                CardImplementationRef::from_bytes([definition.wrapping_add(0x40); 16]),
                DeckExportRef::from_bytes([definition.wrapping_add(0x50); 16]),
                digest(definition.wrapping_add(0x60)),
            ),
            ports,
        )
    }

    fn compile_matrix_deck(
        cards: Vec<DeckCardSpec>,
        links: Vec<DeckLinkSpec>,
        requirements: Vec<DeckRequirementSpec>,
        definitions: Vec<ResolvedCardDefinition>,
        delivery_profiles: Vec<ResolvedDeliveryProfileCommitment>,
        resolved_requirements: Vec<ResolvedRequirementCommitment>,
    ) -> DeckLock {
        let spec = DeckSpec::new(
            DeckKey::from_bytes([0x41; 16]),
            cards,
            links,
            requirements,
            Vec::new(),
            DeckOwnershipRequest::Deck,
            DeckLifetimeRequest::Deck,
        );
        let resolver = DeckResolverSnapshot::new(definitions)
            .with_delivery_profiles(delivery_profiles)
            .with_requirements(resolved_requirements);
        DeckCompiler::compile(&spec, &resolver)
            .expect("matrix Deck must compile before the narrow Planner rejects it")
    }

    fn manifest(target: RuntimeHostId) -> OpaqueManifestProjectionIngress<'static> {
        OpaqueManifestProjectionIngress {
            canonical_projection: b"opaque-validated-projection",
            manifest_digest: PlanManifestDigest::try_new(digest(0x70))
                .expect("fixture manifest digest must validate"),
            target,
            profile_fingerprint: digest(0x71),
            canonical_empty_config_digest: digest(0x72),
            fixture: ManifestFixtureFacts {
                definition: CardDefinitionRef::from_bytes([10; 16]),
                implementation: CardImplementationRef::from_bytes([0x4a; 16]),
                export: [0x5a; 16],
                definition_digest: digest(10),
                artifact_digest: digest(0x6a),
            },
        }
    }

    fn empty_snapshot(target: RuntimeHostId) -> StableAllocationSnapshot {
        StableAllocationSnapshot::try_new(target, 0, 0, Vec::new())
            .expect("empty allocation snapshot must validate")
    }

    fn loop_desired(deck_lock: &DeckLock) -> PlannerDesired<'_> {
        PlannerDesired::OneSourceLoop {
            deck_lock,
            lifecycle: lifecycle(10, 20, 30),
            config_digest: digest(0x72),
        }
    }

    fn lifecycle(start: u64, drain: u64, cleanup: u64) -> ValidatedReferenceLifecycleBudgets {
        ValidatedReferenceLifecycleBudgets {
            start: BoundedDuration::from_nanos(start),
            drain: BoundedDuration::from_nanos(drain),
            cleanup: BoundedDuration::from_nanos(cleanup),
        }
    }

    fn capacity_records(target: RuntimeHostId) -> Vec<StableAllocationRecord> {
        (1..=super::MAX_STABLE_ALLOCATION_RECORDS)
            .map(|ordinal| {
                let mut key = [0_u8; 16];
                key[..8].copy_from_slice(b"capacity");
                key[8..].copy_from_slice(&(ordinal as u64).to_be_bytes());
                record_with_key(target, key, ordinal as u64, AllocationState::Tombstone)
            })
            .collect()
    }

    fn candidate_outcome(outcome: PlannerOutcome) -> super::DeploymentPlanCandidate {
        let PlannerOutcome::Candidate(candidate) = outcome else {
            panic!("expected candidate");
        };
        *candidate
    }

    #[test]
    fn service_dependency_order_is_stable_and_shutdown_is_reverse() {
        let dependencies = [
            ServiceDependency::new(service(2), service(4)),
            ServiceDependency::new(service(1), service(3)),
            ServiceDependency::new(service(1), service(2)),
        ];
        let reordered = [dependencies[2], dependencies[0], dependencies[1]];

        let first = validate_service_dependencies(&dependencies).expect("DAG must validate");
        let second = validate_service_dependencies(&reordered).expect("DAG must validate");

        assert_eq!(first, second);
        assert_eq!(
            first.startup(),
            &[service(1), service(2), service(3), service(4)]
        );
        assert_eq!(
            first.shutdown(),
            &[service(4), service(3), service(2), service(1)]
        );
    }

    #[test]
    fn service_cycle_witness_is_closed_and_input_order_stable() {
        let dependencies = [
            ServiceDependency::new(service(2), service(3)),
            ServiceDependency::new(service(3), service(1)),
            ServiceDependency::new(service(1), service(2)),
        ];
        let reordered = [dependencies[2], dependencies[0], dependencies[1]];

        let first = validate_service_dependencies(&dependencies).expect_err("cycle must reject");
        let second = validate_service_dependencies(&reordered).expect_err("cycle must reject");
        assert_eq!(first, second);
        let ServiceDependencyError::Cycle(witness) = first else {
            panic!("expected a service-specific cycle reason");
        };
        assert_eq!(
            witness.vertices(),
            &[service(1), service(2), service(3), service(1)]
        );
    }

    #[test]
    fn service_self_loop_and_duplicate_have_distinct_reasons() {
        let self_loop =
            validate_service_dependencies(&[ServiceDependency::new(service(7), service(7))])
                .expect_err("self-loop must reject");
        let ServiceDependencyError::Cycle(witness) = self_loop else {
            panic!("self-loop must be a cycle");
        };
        assert_eq!(witness.vertices(), &[service(7), service(7)]);

        let duplicate = ServiceDependency::new(service(1), service(2));
        assert_eq!(
            validate_service_dependencies(&[duplicate, duplicate]),
            Err(ServiceDependencyError::DuplicateDependency)
        );
    }

    #[test]
    fn service_dependency_vertex_and_edge_bounds_are_exact() {
        let vertex_limit = super::MAX_SERVICE_DEPENDENCY_VERTICES;
        let exact_vertices = (0..vertex_limit - 1)
            .map(|index| ServiceDependency::new(indexed_service(index), indexed_service(index + 1)))
            .collect::<Vec<_>>();
        let order = validate_service_dependencies(&exact_vertices)
            .expect("the exact service vertex bound must validate");
        assert_eq!(order.startup().len(), vertex_limit);

        let mut too_many_vertices = exact_vertices;
        too_many_vertices.push(ServiceDependency::new(
            indexed_service(vertex_limit - 1),
            indexed_service(vertex_limit),
        ));
        assert_eq!(
            validate_service_dependencies(&too_many_vertices),
            Err(ServiceDependencyError::TooManyVertices)
        );

        let mut exact_edges = Vec::with_capacity(super::MAX_SERVICE_DEPENDENCY_EDGES);
        'providers: for provider in 0..vertex_limit {
            for consumer in provider + 1..vertex_limit {
                exact_edges.push(ServiceDependency::new(
                    indexed_service(provider),
                    indexed_service(consumer),
                ));
                if exact_edges.len() == super::MAX_SERVICE_DEPENDENCY_EDGES {
                    break 'providers;
                }
            }
        }
        assert_eq!(exact_edges.len(), super::MAX_SERVICE_DEPENDENCY_EDGES);
        validate_service_dependencies(&exact_edges)
            .expect("the exact service edge bound must validate");

        exact_edges.push(exact_edges[0]);
        assert_eq!(
            validate_service_dependencies(&exact_edges),
            Err(ServiceDependencyError::TooManyEdges),
            "the edge capacity gate must precede duplicate inspection"
        );
    }

    #[test]
    fn iterative_cycle_witness_is_stable_at_the_vertex_bound() {
        let vertex_limit = super::MAX_SERVICE_DEPENDENCY_VERTICES;
        let mut cycle = (0..vertex_limit - 1)
            .map(|index| ServiceDependency::new(indexed_service(index), indexed_service(index + 1)))
            .collect::<Vec<_>>();
        cycle.push(ServiceDependency::new(
            indexed_service(vertex_limit - 1),
            indexed_service(0),
        ));
        let mut reordered = cycle.clone();
        reordered.reverse();

        let first = validate_service_dependencies(&cycle).expect_err("long cycle must reject");
        let second =
            validate_service_dependencies(&reordered).expect_err("reordered cycle must reject");
        assert_eq!(first, second);
        let ServiceDependencyError::Cycle(witness) = first else {
            panic!("expected a service cycle witness");
        };
        let expected = (0..vertex_limit)
            .chain(core::iter::once(0))
            .map(indexed_service)
            .collect::<Vec<_>>();
        assert_eq!(witness.vertices(), expected);
    }

    #[test]
    fn allocation_snapshot_rejects_duplicate_keys_and_invalid_high_water() {
        let target = RuntimeHostId::from_bytes([9; 16]);
        assert_eq!(
            StableAllocationSnapshot::try_new(
                target,
                4,
                2,
                vec![
                    record(target, 1, 1, AllocationState::Active),
                    record(target, 1, 2, AllocationState::Tombstone),
                ],
            ),
            Err(PlannerError::InvalidAllocationSnapshot)
        );
        assert_eq!(
            StableAllocationSnapshot::try_new(
                target,
                4,
                1,
                vec![record(target, 1, 2, AllocationState::Active)],
            ),
            Err(PlannerError::InvalidAllocationSnapshot)
        );
        let first = record(target, 1, 1, AllocationState::Active);
        let mut duplicate_ordinal = record(target, 2, 1, AllocationState::Tombstone);
        assert_eq!(
            StableAllocationSnapshot::try_new(target, 4, 2, vec![first, duplicate_ordinal]),
            Err(PlannerError::InvalidAllocationSnapshot)
        );
        duplicate_ordinal.ordinal = 2;
        duplicate_ordinal.instance = first.instance;
        assert_eq!(
            StableAllocationSnapshot::try_new(target, 4, 2, vec![first, duplicate_ordinal]),
            Err(PlannerError::InvalidAllocationSnapshot)
        );
        duplicate_ordinal.instance = InstanceRef::from_bytes([0xf1; 16]);
        duplicate_ordinal.domain = first.domain;
        assert_eq!(
            StableAllocationSnapshot::try_new(target, 4, 2, vec![first, duplicate_ordinal]),
            Err(PlannerError::InvalidAllocationSnapshot)
        );
    }

    #[test]
    fn production_plan_content_digest_covers_semantics_and_excludes_siblings() {
        let plan_target = target(21);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let base_manifest = manifest(plan_target);
        let allocation = empty_snapshot(plan_target);
        let baseline = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: loop_desired(&deck),
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&base_manifest),
                allocation: &allocation,
                service_dependencies: &[],
            })
            .expect("baseline loop must plan"),
        );
        let baseline_digest = baseline.content_digest();

        let changed_target = target(22);
        let changed_target_manifest = manifest(changed_target);
        let changed_target_allocation = empty_snapshot(changed_target);
        let target_candidate = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: changed_target,
                desired: loop_desired(&deck),
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&changed_target_manifest),
                allocation: &changed_target_allocation,
                service_dependencies: &[],
            })
            .expect("changed target must plan"),
        );
        assert_ne!(baseline_digest, target_candidate.content_digest(), "target");

        let terminal_empty = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: PlannerDesired::EmptyTarget,
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&base_manifest),
                allocation: &allocation,
                service_dependencies: &[],
            })
            .expect("terminal empty must plan"),
        );
        assert_ne!(baseline_digest, terminal_empty.content_digest(), "shape");

        let changed_deck = reference_deck_with_deck_key(2);
        let deck_candidate = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: loop_desired(&changed_deck),
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&base_manifest),
                allocation: &allocation,
                service_dependencies: &[],
            })
            .expect("changed DeckLock must plan"),
        );
        assert_ne!(
            baseline_digest,
            deck_candidate.content_digest(),
            "DeckLock semantic digest"
        );

        let large_projection = vec![0x42_u8; 4 * 1024 + 1];
        let mut changed_projection = base_manifest;
        changed_projection.canonical_projection = &large_projection;
        let projection_candidate = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: loop_desired(&deck),
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&changed_projection),
                allocation: &allocation,
                service_dependencies: &[],
            })
            .expect("the opaque validated projection has no Planner-owned protocol cap"),
        );
        assert_ne!(
            baseline_digest,
            projection_candidate.content_digest(),
            "manifest canonical projection"
        );

        let mut changed_manifest_digest = base_manifest;
        changed_manifest_digest.manifest_digest = PlanManifestDigest::try_new(digest(0x73))
            .expect("changed manifest digest must validate");
        let manifest_digest_candidate = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: loop_desired(&deck),
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&changed_manifest_digest),
                allocation: &allocation,
                service_dependencies: &[],
            })
            .expect("changed manifest digest must plan"),
        );
        assert_ne!(
            baseline_digest,
            manifest_digest_candidate.content_digest(),
            "manifest digest"
        );

        let mut changed_profile = base_manifest;
        changed_profile.profile_fingerprint = digest(0x74);
        let profile_candidate = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: loop_desired(&deck),
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&changed_profile),
                allocation: &allocation,
                service_dependencies: &[],
            })
            .expect("changed profile fingerprint must plan"),
        );
        assert_ne!(
            baseline_digest,
            profile_candidate.content_digest(),
            "profile fingerprint"
        );

        let empty_digest = |projection: &OpaqueManifestProjectionIngress<'_>| {
            candidate_outcome(
                DeploymentPlanner::plan(&PlannerInput {
                    target: plan_target,
                    desired: PlannerDesired::EmptyTarget,
                    previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                    manifest: Some(projection),
                    allocation: &allocation,
                    service_dependencies: &[],
                })
                .expect("fixture projection must plan for canonical empty"),
            )
            .content_digest()
        };
        let empty_baseline_digest = empty_digest(&base_manifest);
        let mut fixture_variants = [base_manifest; 5];
        fixture_variants[0].fixture.definition = CardDefinitionRef::from_bytes([0x31; 16]);
        fixture_variants[1].fixture.implementation = CardImplementationRef::from_bytes([0x32; 16]);
        fixture_variants[2].fixture.export = [0x33; 16];
        fixture_variants[3].fixture.definition_digest = digest(0x34);
        fixture_variants[4].fixture.artifact_digest = digest(0x35);
        for (name, variant) in [
            "fixture definition",
            "fixture implementation",
            "fixture export",
            "fixture definition digest",
            "fixture artifact digest",
        ]
        .into_iter()
        .zip(fixture_variants.iter())
        {
            assert_ne!(empty_baseline_digest, empty_digest(variant), "{name}");
        }

        let allocation_history = StableAllocationSnapshot::try_new(
            plan_target,
            4,
            1,
            vec![record(plan_target, 9, 1, AllocationState::Tombstone)],
        )
        .expect("allocation history must validate");
        let changed_ids = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: loop_desired(&deck),
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&base_manifest),
                allocation: &allocation_history,
                service_dependencies: &[],
            })
            .expect("fresh IDs above the prior high-water must plan"),
        );
        assert_ne!(
            baseline_digest,
            changed_ids.content_digest(),
            "allocated instance/domain"
        );

        let changed_lifecycle = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: PlannerDesired::OneSourceLoop {
                    deck_lock: &deck,
                    lifecycle: lifecycle(11, 20, 30),
                    config_digest: digest(0x72),
                },
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&base_manifest),
                allocation: &allocation,
                service_dependencies: &[],
            })
            .expect("changed lifecycle must plan"),
        );
        assert_ne!(
            baseline_digest,
            changed_lifecycle.content_digest(),
            "lifecycle budgets"
        );

        let mut changed_config_manifest = base_manifest;
        changed_config_manifest.canonical_empty_config_digest = digest(0x75);
        let changed_config = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: PlannerDesired::OneSourceLoop {
                    deck_lock: &deck,
                    lifecycle: lifecycle(10, 20, 30),
                    config_digest: digest(0x75),
                },
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&changed_config_manifest),
                allocation: &allocation,
                service_dependencies: &[],
            })
            .expect("changed canonical config must plan"),
        );
        assert_ne!(
            baseline_digest,
            changed_config.content_digest(),
            "config digest"
        );

        let tombstone_history = StableAllocationSnapshot::try_new(
            plan_target,
            9,
            1,
            vec![record(plan_target, 8, 1, AllocationState::Tombstone)],
        )
        .expect("tombstone history must validate");
        let same_empty_with_history = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: PlannerDesired::EmptyTarget,
                previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                manifest: Some(&base_manifest),
                allocation: &tombstone_history,
                service_dependencies: &[],
            })
            .expect("empty with allocation history must plan"),
        );
        assert_eq!(
            terminal_empty.content_digest(),
            same_empty_with_history.content_digest()
        );
        assert_ne!(
            terminal_empty.allocation_delta(),
            same_empty_with_history.allocation_delta()
        );

        let active = StableAllocationSnapshot::try_new(
            plan_target,
            7,
            1,
            vec![record(plan_target, 2, 1, AllocationState::Active)],
        )
        .expect("active allocation must validate");
        let same_empty_with_tombstone = candidate_outcome(
            DeploymentPlanner::plan(&PlannerInput {
                target: plan_target,
                desired: PlannerDesired::EmptyTarget,
                previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
                manifest: Some(&base_manifest),
                allocation: &active,
                service_dependencies: &[],
            })
            .expect("live target must plan explicit empty"),
        );
        assert_eq!(
            terminal_empty.content_digest(),
            same_empty_with_tombstone.content_digest()
        );
        assert_ne!(
            terminal_empty.allocation_delta(),
            same_empty_with_tombstone.allocation_delta()
        );
        assert_ne!(
            terminal_empty.diagnostics(),
            same_empty_with_tombstone.diagnostics()
        );
    }

    #[test]
    fn loop_to_omitted_requires_explicit_terminal_empty() {
        let target = target(1);
        let allocation = empty_snapshot(target);
        let input = PlannerInput {
            target,
            desired: PlannerDesired::Omitted,
            previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
            manifest: None,
            allocation: &allocation,
            service_dependencies: &[],
        };

        assert_eq!(
            DeploymentPlanner::plan(&input),
            Err(PlannerError::ExplicitEmptyRequiredBeforeOmit)
        );
    }

    #[test]
    fn empty_target_is_plan_side_and_tombstones_active_allocation() {
        let target = target(2);
        let manifest = manifest(target);
        let allocation = StableAllocationSnapshot::try_new(
            target,
            7,
            3,
            vec![record(target, 2, 3, AllocationState::Active)],
        )
        .expect("snapshot must validate");
        let input = PlannerInput {
            target,
            desired: PlannerDesired::EmptyTarget,
            previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
            manifest: Some(&manifest),
            allocation: &allocation,
            service_dependencies: &[],
        };

        let candidate = candidate_outcome(DeploymentPlanner::plan(&input).expect("empty target"));
        assert_eq!(candidate.content().shape(), TargetIntent::EmptyTarget);
        assert_eq!(candidate.allocation_delta().base_generation(), 7);
        assert_eq!(candidate.allocation_delta().next_generation(), 8);
        assert_eq!(
            candidate.allocation_delta().records()[0].state(),
            AllocationState::Tombstone
        );
    }

    #[test]
    fn one_source_loop_is_deterministic_and_allocates_fresh_ids() {
        let target = target(3);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let manifest = manifest(target);
        let allocation = empty_snapshot(target);
        let make_input = || PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
            manifest: Some(&manifest),
            allocation: &allocation,
            service_dependencies: &[],
        };

        let first =
            candidate_outcome(DeploymentPlanner::plan(&make_input()).expect("loop must plan"));
        let second =
            candidate_outcome(DeploymentPlanner::plan(&make_input()).expect("loop must plan"));
        assert_eq!(first, second);
        assert_eq!(first.content().shape(), TargetIntent::OneSourceLoop);
        assert_eq!(first.allocation_delta().resulting_high_water(), 1);
        assert_eq!(
            first.diagnostics(),
            &[PlannerDiagnostic::FreshStableAllocation]
        );
    }

    #[test]
    fn loop_to_loop_is_rejected_before_allocation() {
        let target = target(4);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let manifest = manifest(target);
        let allocation = empty_snapshot(target);
        let input = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
            manifest: Some(&manifest),
            allocation: &allocation,
            service_dependencies: &[],
        };

        assert_eq!(
            DeploymentPlanner::plan(&input),
            Err(PlannerError::LoopToLoopRejected)
        );
    }

    #[test]
    fn manifest_target_and_exact_fixture_mismatch_are_rejected() {
        let target = target(5);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let allocation = empty_snapshot(target);
        let wrong_target = manifest(RuntimeHostId::from_bytes([6; 16]));
        let target_input = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::UninitializedNoneExactZero,
            manifest: Some(&wrong_target),
            allocation: &allocation,
            service_dependencies: &[],
        };
        assert_eq!(
            DeploymentPlanner::plan(&target_input),
            Err(PlannerError::ManifestTargetMismatch)
        );

        let mut wrong_fixture = manifest(target);
        wrong_fixture.fixture.artifact_digest = digest(0xff);
        let fixture_input = PlannerInput {
            manifest: Some(&wrong_fixture),
            ..target_input
        };
        assert_eq!(
            DeploymentPlanner::plan(&fixture_input),
            Err(PlannerError::ManifestFixtureMismatch)
        );
    }

    #[test]
    fn tombstoned_key_reappears_with_fresh_high_water_and_ids() {
        let target = target(8);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let manifest = manifest(target);
        let old = record(target, 2, 4, AllocationState::Tombstone);
        let allocation = StableAllocationSnapshot::try_new(target, 9, 4, vec![old])
            .expect("tombstone snapshot must validate");
        let input = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
            manifest: Some(&manifest),
            allocation: &allocation,
            service_dependencies: &[],
        };

        let candidate = candidate_outcome(DeploymentPlanner::plan(&input).expect("re-add"));
        let fresh = candidate.allocation_delta().records()[0];
        assert_eq!(fresh.ordinal(), 5);
        assert_ne!(fresh.instance(), old.instance());
        assert_ne!(fresh.domain(), old.domain());
        assert_eq!(candidate.allocation_delta().resulting_high_water(), 5);
    }

    #[test]
    fn budgets_and_config_are_digest_covered_and_config_must_be_canonical_empty() {
        let target = target(9);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let manifest = manifest(target);
        let allocation = empty_snapshot(target);
        let base = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::UninitializedNoneExactZero,
            manifest: Some(&manifest),
            allocation: &allocation,
            service_dependencies: &[],
        };
        let first = candidate_outcome(DeploymentPlanner::plan(&base).expect("base loop must plan"));
        let changed_budget = PlannerInput {
            desired: PlannerDesired::OneSourceLoop {
                deck_lock: &deck,
                lifecycle: lifecycle(11, 20, 30),
                config_digest: digest(0x72),
            },
            ..base
        };
        let second = candidate_outcome(
            DeploymentPlanner::plan(&changed_budget).expect("changed budget must plan"),
        );
        assert_ne!(first.content_digest(), second.content_digest());

        let wrong_config = PlannerInput {
            desired: PlannerDesired::OneSourceLoop {
                deck_lock: &deck,
                lifecycle: lifecycle(10, 20, 30),
                config_digest: digest(0xee),
            },
            ..changed_budget
        };
        assert_eq!(
            DeploymentPlanner::plan(&wrong_config),
            Err(PlannerError::ConfigMismatch)
        );
    }

    #[test]
    fn omitted_after_terminal_empty_has_no_commit_candidate() {
        let target = target(10);
        let allocation = empty_snapshot(target);
        let input = PlannerInput {
            target,
            desired: PlannerDesired::Omitted,
            previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
            manifest: None,
            allocation: &allocation,
            service_dependencies: &[],
        };

        assert_eq!(DeploymentPlanner::plan(&input), Ok(PlannerOutcome::Omitted));
    }

    #[test]
    fn previous_state_and_allocation_must_be_coherent_before_omission_or_reactivation() {
        let target = target(17);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let manifest = manifest(target);
        let active = StableAllocationSnapshot::try_new(
            target,
            3,
            1,
            vec![record(target, 2, 1, AllocationState::Active)],
        )
        .expect("active snapshot must validate");

        let terminal_loop = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
            manifest: Some(&manifest),
            allocation: &active,
            service_dependencies: &[],
        };
        assert_eq!(
            DeploymentPlanner::plan(&terminal_loop),
            Err(PlannerError::PreviousAllocationMismatch),
            "terminal empty must never resurrect an old active allocation"
        );

        let terminal_omitted = PlannerInput {
            desired: PlannerDesired::Omitted,
            manifest: None,
            ..terminal_loop
        };
        assert_eq!(
            DeploymentPlanner::plan(&terminal_omitted),
            Err(PlannerError::PreviousAllocationMismatch),
            "omission must never orphan an active allocation"
        );

        let other_target_allocation = empty_snapshot(RuntimeHostId::from_bytes([18; 16]));
        let wrong_target_omitted = PlannerInput {
            allocation: &other_target_allocation,
            ..terminal_omitted
        };
        assert_eq!(
            DeploymentPlanner::plan(&wrong_target_omitted),
            Err(PlannerError::AllocationTargetMismatch)
        );

        let no_active = empty_snapshot(target);
        let live_without_allocation = PlannerInput {
            target,
            desired: PlannerDesired::EmptyTarget,
            previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
            manifest: Some(&manifest),
            allocation: &no_active,
            service_dependencies: &[],
        };
        assert_eq!(
            DeploymentPlanner::plan(&live_without_allocation),
            Err(PlannerError::PreviousAllocationMismatch)
        );

        let multiple_active = StableAllocationSnapshot::try_new(
            target,
            4,
            2,
            vec![
                record(target, 2, 1, AllocationState::Active),
                record(target, 3, 2, AllocationState::Active),
            ],
        )
        .expect("multi-active snapshot remains structurally readable");
        let recovery_with_extra_allocation = PlannerInput {
            previous: PreviousTargetEligibility::OneSourceLoopRecoveryFailedExactZero,
            allocation: &multiple_active,
            ..live_without_allocation
        };
        assert_eq!(
            DeploymentPlanner::plan(&recovery_with_extra_allocation),
            Err(PlannerError::PreviousAllocationMismatch)
        );
    }

    #[test]
    fn transition_matrix_matches_empty_deactivate_protocol() {
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let one = loop_desired(&deck);
        let empty = PlannerDesired::EmptyTarget;
        let omitted = PlannerDesired::Omitted;

        let one_cases = [
            (
                PreviousTargetEligibility::UninitializedNoneExactZero,
                Ok(()),
            ),
            (
                PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                Ok(()),
            ),
            (
                PreviousTargetEligibility::OneSourceLoopLiveReady,
                Err(PlannerError::LoopToLoopRejected),
            ),
            (
                PreviousTargetEligibility::OneSourceLoopRecoveryFailedExactZero,
                Err(PlannerError::ExplicitEmptyRequiredBeforeLoop),
            ),
            (
                PreviousTargetEligibility::EmptyDeactivateRetiring,
                Err(PlannerError::PreviousTargetNotTerminal),
            ),
            (
                PreviousTargetEligibility::Busy,
                Err(PlannerError::PreviousTargetBusy),
            ),
            (
                PreviousTargetEligibility::Ineligible,
                Err(PlannerError::PreviousTargetIneligible),
            ),
        ];
        for (previous, expected) in one_cases {
            assert_eq!(validate_transition(previous, &one), expected);
        }

        let empty_cases = [
            (
                PreviousTargetEligibility::UninitializedNoneExactZero,
                Err(PlannerError::EmptyBootstrapRejected),
            ),
            (
                PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                Ok(()),
            ),
            (PreviousTargetEligibility::OneSourceLoopLiveReady, Ok(())),
            (
                PreviousTargetEligibility::OneSourceLoopRecoveryFailedExactZero,
                Ok(()),
            ),
            (
                PreviousTargetEligibility::EmptyDeactivateRetiring,
                Err(PlannerError::PreviousTargetNotTerminal),
            ),
            (
                PreviousTargetEligibility::Busy,
                Err(PlannerError::PreviousTargetBusy),
            ),
            (
                PreviousTargetEligibility::Ineligible,
                Err(PlannerError::PreviousTargetIneligible),
            ),
        ];
        for (previous, expected) in empty_cases {
            assert_eq!(validate_transition(previous, &empty), expected);
        }

        let omitted_cases = [
            (
                PreviousTargetEligibility::UninitializedNoneExactZero,
                Ok(()),
            ),
            (
                PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
                Ok(()),
            ),
            (
                PreviousTargetEligibility::OneSourceLoopLiveReady,
                Err(PlannerError::ExplicitEmptyRequiredBeforeOmit),
            ),
            (
                PreviousTargetEligibility::OneSourceLoopRecoveryFailedExactZero,
                Err(PlannerError::ExplicitEmptyRequiredBeforeOmit),
            ),
            (
                PreviousTargetEligibility::EmptyDeactivateRetiring,
                Err(PlannerError::PreviousTargetNotTerminal),
            ),
            (
                PreviousTargetEligibility::Busy,
                Err(PlannerError::PreviousTargetBusy),
            ),
            (
                PreviousTargetEligibility::Ineligible,
                Err(PlannerError::PreviousTargetIneligible),
            ),
        ];
        for (previous, expected) in omitted_cases {
            assert_eq!(validate_transition(previous, &omitted), expected);
        }
    }

    #[test]
    fn zero_port_gate_precedes_config_role_and_fixture_matching() {
        let target = target(11);
        let deck = reference_deck_with_port();
        let mut manifest = manifest(target);
        manifest.fixture.artifact_digest = digest(0xff);
        let allocation = empty_snapshot(target);
        let input = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::UninitializedNoneExactZero,
            manifest: Some(&manifest),
            allocation: &allocation,
            service_dependencies: &[],
        };

        assert_eq!(
            DeploymentPlanner::plan(&input),
            Err(PlannerError::UnsupportedPort)
        );
    }

    #[test]
    fn refinement_gate_precedes_role_and_fixture_matching() {
        let target = target(20);
        let deck = reference_deck_with_refinement();
        let mut manifest = manifest(target);
        manifest.fixture.artifact_digest = digest(0xff);
        let allocation = empty_snapshot(target);
        let input = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::UninitializedNoneExactZero,
            manifest: Some(&manifest),
            allocation: &allocation,
            service_dependencies: &[],
        };

        assert_eq!(
            DeploymentPlanner::plan(&input),
            Err(PlannerError::UnsupportedRefinement)
        );
    }

    #[test]
    fn narrow_profile_rejection_matrix_is_ordered_and_allocation_neutral() {
        let target = target(23);
        let base_manifest = manifest(target);
        let allocation = empty_snapshot(target);
        let schema =
            SchemaRef::try_new([0x61; 16], 1, digest(0x62)).expect("matrix schema must validate");
        let delivery_profile = DeliveryProfileRef::from_bytes([0x51; 16]);
        let requirement = RequirementRef::from_bytes([0x53; 16]);
        let invalid_first_card = || {
            matrix_card(
                2,
                10,
                DeckCardConfig::Digest(digest(0xa0)),
                DeckCardRole::General,
            )
        };
        let second_card =
            || matrix_card(3, 11, DeckCardConfig::CanonicalEmpty, DeckCardRole::General);

        let link_deck = compile_matrix_deck(
            vec![invalid_first_card(), second_card()],
            vec![
                DeckLinkSpec::new(
                    DeckLinkKey::from_bytes([0x50; 16]),
                    DeckEndpointSpec::new(
                        CardUseKey::from_bytes([2; 16]),
                        DeckPortKey::from_bytes([0x31; 16]),
                    ),
                    DeckEndpointSpec::new(
                        CardUseKey::from_bytes([3; 16]),
                        DeckPortKey::from_bytes([0x32; 16]),
                    ),
                )
                .with_delivery_profile(delivery_profile),
            ],
            vec![DeckRequirementSpec::new(
                RequirementKey::from_bytes([0x52; 16]),
                requirement,
            )],
            vec![
                matrix_definition(
                    10,
                    vec![ResolvedDeckPort::new(
                        DeckPortKey::from_bytes([0x31; 16]),
                        PortSpec::new(
                            PortDirection::Out,
                            schema,
                            InteractionKind::Event,
                            PortCardinality::One,
                        ),
                    )],
                ),
                matrix_definition(
                    11,
                    vec![ResolvedDeckPort::new(
                        DeckPortKey::from_bytes([0x32; 16]),
                        PortSpec::new(
                            PortDirection::In,
                            schema,
                            InteractionKind::Event,
                            PortCardinality::One,
                        ),
                    )],
                ),
            ],
            vec![ResolvedDeliveryProfileCommitment::new(
                delivery_profile,
                digest(0x54),
            )],
            vec![ResolvedRequirementCommitment::new(
                requirement,
                digest(0x55),
            )],
        );
        let requirement_deck = compile_matrix_deck(
            vec![invalid_first_card(), second_card()],
            Vec::new(),
            vec![DeckRequirementSpec::new(
                RequirementKey::from_bytes([0x52; 16]),
                requirement,
            )],
            vec![
                matrix_definition(10, Vec::new()),
                matrix_definition(11, Vec::new()),
            ],
            Vec::new(),
            vec![ResolvedRequirementCommitment::new(
                requirement,
                digest(0x55),
            )],
        );
        let multi_card_deck = compile_matrix_deck(
            vec![invalid_first_card(), second_card()],
            Vec::new(),
            Vec::new(),
            vec![
                matrix_definition(10, Vec::new()),
                matrix_definition(11, Vec::new()),
            ],
            Vec::new(),
            Vec::new(),
        );
        let configured_deck = compile_matrix_deck(
            vec![invalid_first_card()],
            Vec::new(),
            Vec::new(),
            vec![matrix_definition(10, Vec::new())],
            Vec::new(),
            Vec::new(),
        );
        let general_deck = compile_matrix_deck(
            vec![matrix_card(
                2,
                10,
                DeckCardConfig::CanonicalEmpty,
                DeckCardRole::General,
            )],
            Vec::new(),
            Vec::new(),
            vec![matrix_definition(10, Vec::new())],
            Vec::new(),
            Vec::new(),
        );

        let assert_rejection = |name: &str,
                                deck: &DeckLock,
                                manifest: Option<&OpaqueManifestProjectionIngress<'_>>,
                                service_dependencies: &[ServiceDependency],
                                expected: PlannerError| {
            let before = allocation.clone();
            let outcome = DeploymentPlanner::plan(&PlannerInput {
                target,
                desired: loop_desired(deck),
                previous: PreviousTargetEligibility::UninitializedNoneExactZero,
                manifest,
                allocation: &allocation,
                service_dependencies,
            });
            assert_eq!(outcome, Err(expected), "{name}");
            assert_eq!(allocation, before, "{name}: allocation snapshot changed");
        };

        let nonzero_acyclic_dependency = [ServiceDependency::new(service(1), service(2))];
        assert_rejection(
            "ServiceDependency precedes missing manifest and Deck gates",
            &link_deck,
            None,
            &nonzero_acyclic_dependency,
            PlannerError::UnsupportedServiceDependency,
        );
        assert_rejection(
            "missing manifest precedes Deck gates",
            &link_deck,
            None,
            &[],
            PlannerError::MissingManifestProjection,
        );
        assert_rejection(
            "Link precedes Requirement, shape, config, and role",
            &link_deck,
            Some(&base_manifest),
            &[],
            PlannerError::UnsupportedLink,
        );
        assert_rejection(
            "Requirement precedes shape, config, and role",
            &requirement_deck,
            Some(&base_manifest),
            &[],
            PlannerError::UnsupportedRequirement,
        );
        assert_rejection(
            "multi-card shape precedes config and role",
            &multi_card_deck,
            Some(&base_manifest),
            &[],
            PlannerError::UnsupportedDeckShape,
        );
        assert_rejection(
            "per-use config precedes role",
            &configured_deck,
            Some(&base_manifest),
            &[],
            PlannerError::UnsupportedPerUseConfig,
        );
        assert_rejection(
            "general role is rejected before fixture matching",
            &general_deck,
            Some(&base_manifest),
            &[],
            PlannerError::UnsupportedGeneralCard,
        );
    }

    #[test]
    fn snapshot_rejects_forged_ids_and_unreachable_counter_history() {
        let target = target(12);
        let mut forged = record(target, 1, 1, AllocationState::Active);
        forged.instance = InstanceRef::from_bytes([0xff; 16]);
        assert_eq!(
            StableAllocationSnapshot::try_new(target, 1, 1, vec![forged]),
            Err(PlannerError::InvalidAllocationSnapshot)
        );
        assert_eq!(
            StableAllocationSnapshot::try_new(target, u64::MAX, 0, Vec::new()),
            Err(PlannerError::InvalidAllocationSnapshot),
            "without compaction, nonzero generation cannot lose every tombstone"
        );
        assert_eq!(
            StableAllocationSnapshot::try_new(
                target,
                1,
                2,
                vec![record(target, 1, 1, AllocationState::Tombstone)],
            ),
            Err(PlannerError::InvalidAllocationSnapshot),
            "high-water must equal the retained maximum ordinal"
        );
        assert!(
            StableAllocationSnapshot::try_new(
                target,
                u64::MAX,
                1,
                vec![record(target, 1, 1, AllocationState::Tombstone)],
            )
            .is_ok(),
            "a saturated generation with retained history remains readable"
        );
        assert!(
            StableAllocationSnapshot::try_new(
                target,
                u64::MAX,
                u64::MAX,
                vec![record(target, 1, u64::MAX, AllocationState::Tombstone)],
            )
            .is_ok(),
            "a saturated high-water with its retained tombstone remains readable"
        );
    }

    #[test]
    fn persisted_plan_content_rebuilds_exact_fields_and_rejects_bad_lifecycle() {
        let target = target(24);
        let allocation = empty_snapshot(target);
        let candidate = super::journal_test_candidate(target, &allocation, Some([2; 16]), 0x51)
            .expect("typed fixture candidate must validate");
        let bytes = candidate.content().canonical_bytes();
        let decoded = super::PlanContent::try_from_persisted(target, bytes)
            .expect("canonical Planner content must decode");
        assert_eq!(decoded, *candidate.content());
        assert_eq!(
            super::PlanContent::try_from_persisted(RuntimeHostId::from_bytes([0x99; 16]), bytes),
            Err(PlannerError::InvalidPersistedPlanContent)
        );
        assert_eq!(
            super::PlanContent::try_from_persisted(target, &bytes[..bytes.len() - 1]),
            Err(PlannerError::InvalidPersistedPlanContent)
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            super::PlanContent::try_from_persisted(target, &trailing),
            Err(PlannerError::InvalidPersistedPlanContent)
        );

        let mut zero_manifest = bytes.to_vec();
        let manifest_offset = super::PLAN_CONTENT_MAGIC.len() + size_of::<u16>() + 1 + 16 + 32;
        zero_manifest[manifest_offset..manifest_offset + 32].fill(0);
        assert_eq!(
            super::PlanContent::try_from_persisted(target, &zero_manifest),
            Err(PlannerError::InvalidManifestDigest)
        );

        let mut zero_budget = bytes.to_vec();
        let first_lifecycle_budget = zero_budget.len() - 32 - (3 * 8);
        zero_budget[first_lifecycle_budget..first_lifecycle_budget + 8]
            .copy_from_slice(&0_u64.to_be_bytes());
        assert_eq!(
            super::PlanContent::try_from_persisted(target, &zero_budget),
            Err(PlannerError::InvalidPersistedPlanContent)
        );

        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let manifest = manifest(target);
        assert_eq!(
            DeploymentPlanner::plan(&PlannerInput {
                target,
                desired: PlannerDesired::OneSourceLoop {
                    deck_lock: &deck,
                    lifecycle: lifecycle(0, 2, 3),
                    config_digest: digest(0x72),
                },
                previous: PreviousTargetEligibility::UninitializedNoneExactZero,
                manifest: Some(&manifest),
                allocation: &allocation,
                service_dependencies: &[],
            }),
            Err(PlannerError::InvalidLifecycleBudget)
        );
    }

    #[test]
    fn allocation_delta_is_exact_one_generation_and_never_removes_history() {
        let target = target(25);
        let empty = empty_snapshot(target);
        let active_candidate = super::journal_test_candidate(target, &empty, Some([2; 16]), 0x61)
            .expect("fresh allocation candidate must validate");
        let active = empty
            .apply_delta(active_candidate.allocation_delta())
            .expect("fresh delta must apply");
        assert_eq!(active.generation(), 1);
        assert_eq!(active.high_water(), 1);

        let no_change = super::journal_test_candidate(target, &active, Some([2; 16]), 0x62)
            .expect("stable allocation candidate must validate");
        assert!(no_change.allocation_delta().records().is_empty());
        assert_eq!(
            active
                .apply_delta(no_change.allocation_delta())
                .expect("no-change delta must preserve generation"),
            active
        );

        let mut skipped = active_candidate.allocation_delta().clone();
        skipped.next_generation = 2;
        assert_eq!(
            empty.apply_delta(&skipped),
            Err(PlannerError::PreviousAllocationMismatch)
        );
        let mut wrong_base = no_change.allocation_delta().clone();
        wrong_base.base_generation = 0;
        assert_eq!(
            active.apply_delta(&wrong_base),
            Err(PlannerError::PreviousAllocationMismatch)
        );

        let two_active = StableAllocationSnapshot::try_new(
            target,
            2,
            2,
            vec![
                record(target, 1, 1, AllocationState::Active),
                record(target, 2, 2, AllocationState::Active),
            ],
        )
        .expect("structurally valid multi-active recovery input must validate");
        let mut unordered = super::journal_test_candidate(target, &two_active, None, 0x63)
            .expect("empty candidate must tombstone both records")
            .allocation_delta()
            .clone();
        unordered.records.reverse();
        assert_eq!(
            two_active.apply_delta(&unordered),
            Err(PlannerError::InvalidAllocationSnapshot)
        );

        let history = StableAllocationSnapshot::try_new(
            target,
            2,
            2,
            vec![
                record(target, 1, 1, AllocationState::Tombstone),
                record(target, 2, 2, AllocationState::Tombstone),
            ],
        )
        .expect("retained history must validate");
        let deleted = StableAllocationSnapshot::try_new(
            target,
            2,
            2,
            vec![record(target, 2, 2, AllocationState::Tombstone)],
        )
        .expect("the current snapshot is individually well formed");
        assert_eq!(
            deleted.validate_successor_of(&history),
            Err(PlannerError::PreviousAllocationMismatch)
        );
    }

    #[test]
    fn saturated_counters_fail_only_when_the_requested_delta_advances_them() {
        let target = target(15);
        let manifest = manifest(target);
        let saturated_record = record(target, 9, u64::MAX, AllocationState::Tombstone);
        let high_water_snapshot =
            StableAllocationSnapshot::try_new(target, u64::MAX, u64::MAX, vec![saturated_record])
                .expect("saturated counters with retained history must remain readable");
        let empty = PlannerInput {
            target,
            desired: PlannerDesired::EmptyTarget,
            previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
            manifest: Some(&manifest),
            allocation: &high_water_snapshot,
            service_dependencies: &[],
        };
        let candidate = candidate_outcome(
            DeploymentPlanner::plan(&empty)
                .expect("EmptyDeactivate does not advance allocation high-water"),
        );
        assert_eq!(
            candidate.allocation_delta().resulting_high_water(),
            u64::MAX
        );
        assert!(candidate.allocation_delta().records().is_empty());
        assert_eq!(candidate.allocation_delta().next_generation(), u64::MAX);

        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let exhausted_high_water =
            StableAllocationSnapshot::try_new(target, u64::MAX, u64::MAX, vec![saturated_record])
                .expect("saturated high-water snapshot must retain its tombstone");
        let fresh = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
            manifest: Some(&manifest),
            allocation: &exhausted_high_water,
            service_dependencies: &[],
        };
        assert_eq!(
            DeploymentPlanner::plan(&fresh),
            Err(PlannerError::AllocationExhausted)
        );

        let generation_snapshot = StableAllocationSnapshot::try_new(
            target,
            u64::MAX,
            1,
            vec![record(target, 2, 1, AllocationState::Active)],
        )
        .expect("saturated generation snapshot must remain readable");
        let generation_advance = PlannerInput {
            allocation: &generation_snapshot,
            previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
            ..empty
        };
        assert_eq!(
            DeploymentPlanner::plan(&generation_advance),
            Err(PlannerError::AllocationExhausted)
        );
    }

    #[test]
    fn final_allocation_generation_is_reserved_for_empty_deactivation() {
        let target = target(19);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let manifest = manifest(target);
        let final_reserve = StableAllocationSnapshot::try_new(
            target,
            u64::MAX - 1,
            1,
            vec![record(target, 9, 1, AllocationState::Tombstone)],
        )
        .expect("the final reserve snapshot must retain allocation history");
        let fresh_loop = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
            manifest: Some(&manifest),
            allocation: &final_reserve,
            service_dependencies: &[],
        };
        assert_eq!(
            DeploymentPlanner::plan(&fresh_loop),
            Err(PlannerError::AllocationExhausted),
            "a live candidate must not consume the generation reserved for deactivation"
        );

        let active_record = record(target, 2, 1, AllocationState::Active);
        let active_at_reserve =
            StableAllocationSnapshot::try_new(target, u64::MAX - 1, 1, vec![active_record])
                .expect("active reserve snapshot must validate");
        let deactivate = PlannerInput {
            target,
            desired: PlannerDesired::EmptyTarget,
            previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
            manifest: Some(&manifest),
            allocation: &active_at_reserve,
            service_dependencies: &[],
        };
        let empty = candidate_outcome(
            DeploymentPlanner::plan(&deactivate)
                .expect("EmptyDeactivate alone may consume the final generation"),
        );
        assert_eq!(empty.allocation_delta().next_generation(), u64::MAX);

        let saturated_active =
            StableAllocationSnapshot::try_new(target, u64::MAX, 1, vec![active_record])
                .expect("a saturated active snapshot is readable for quarantine");
        let stuck_deactivate = PlannerInput {
            allocation: &saturated_active,
            ..deactivate
        };
        assert_eq!(
            DeploymentPlanner::plan(&stuck_deactivate),
            Err(PlannerError::AllocationExhausted)
        );

        let extra = record(target, 3, 2, AllocationState::Active);
        let reuse_change =
            StableAllocationSnapshot::try_new(target, u64::MAX - 1, 2, vec![active_record, extra])
                .expect("multi-active snapshot must remain structurally readable");
        assert!(matches!(
            allocate_active(target, CardUseKey::from_bytes([2; 16]), &reuse_change),
            Err(PlannerError::AllocationExhausted)
        ));
        assert!(matches!(
            allocate_active(target, CardUseKey::from_bytes([2; 16]), &saturated_active),
            Err(PlannerError::AllocationExhausted)
        ));
    }

    #[test]
    fn allocation_capacity_never_evicts_tombstones() {
        let target = target(16);
        let deck = reference_deck(
            DeckCardConfig::CanonicalEmpty,
            DeckCardRole::ReferenceSubject,
        );
        let manifest = manifest(target);
        let records = capacity_records(target);
        let full = StableAllocationSnapshot::try_new(
            target,
            super::MAX_STABLE_ALLOCATION_RECORDS as u64,
            super::MAX_STABLE_ALLOCATION_RECORDS as u64,
            records.clone(),
        )
        .expect("the exact allocation bound must validate");
        let fresh = PlannerInput {
            target,
            desired: loop_desired(&deck),
            previous: PreviousTargetEligibility::EmptyDeactivateTerminalExactZero,
            manifest: Some(&manifest),
            allocation: &full,
            service_dependencies: &[],
        };
        assert_eq!(
            DeploymentPlanner::plan(&fresh),
            Err(PlannerError::AllocationCapacityExceeded)
        );
        assert_eq!(full.records().len(), super::MAX_STABLE_ALLOCATION_RECORDS);
        assert!(
            full.records()
                .iter()
                .all(|record| record.state() == AllocationState::Tombstone)
        );

        let mut too_many = records.clone();
        too_many.push(record_with_key(
            target,
            [0xfe; 16],
            (super::MAX_STABLE_ALLOCATION_RECORDS + 1) as u64,
            AllocationState::Tombstone,
        ));
        assert_eq!(
            StableAllocationSnapshot::try_new(
                target,
                1,
                (super::MAX_STABLE_ALLOCATION_RECORDS + 1) as u64,
                too_many,
            ),
            Err(PlannerError::AllocationCapacityExceeded)
        );

        let mut reusable = records;
        reusable[0] = record(target, 2, 1, AllocationState::Tombstone);
        let at_capacity_with_desired_tombstone = StableAllocationSnapshot::try_new(
            target,
            super::MAX_STABLE_ALLOCATION_RECORDS as u64,
            super::MAX_STABLE_ALLOCATION_RECORDS as u64,
            reusable,
        )
        .expect("reusable desired tombstone keeps the record count at capacity");
        let reuse = PlannerInput {
            allocation: &at_capacity_with_desired_tombstone,
            ..fresh
        };
        let candidate = candidate_outcome(
            DeploymentPlanner::plan(&reuse)
                .expect("replacing an existing tombstone does not exceed record capacity"),
        );
        assert_eq!(
            candidate.allocation_delta().resulting_high_water(),
            (super::MAX_STABLE_ALLOCATION_RECORDS + 1) as u64
        );
        assert_eq!(candidate.allocation_delta().records().len(), 1);
        assert_eq!(
            candidate.allocation_delta().records()[0].state(),
            AllocationState::Active
        );
    }

    #[test]
    fn allocation_reducer_tombstones_all_other_active_allocations() {
        let target = target(13);
        let desired = record(target, 2, 1, AllocationState::Active);
        let extra = record(target, 3, 2, AllocationState::Active);
        let allocation = StableAllocationSnapshot::try_new(target, 5, 2, vec![extra, desired])
            .expect("multi-active snapshot must be internally consistent");

        let (selected, delta, diagnostics) =
            allocate_active(target, CardUseKey::from_bytes([2; 16]), &allocation)
                .expect("the bounded reducer must tombstone every non-selected active record");
        assert_eq!(selected, desired);
        assert_eq!(delta.base_generation(), 5);
        assert_eq!(delta.next_generation(), 6);
        assert_eq!(delta.resulting_high_water(), 2);
        assert_eq!(delta.records().len(), 1);
        assert_eq!(delta.records()[0].key(), &[3; 16]);
        assert_eq!(delta.records()[0].state(), AllocationState::Tombstone);
        assert_eq!(
            diagnostics,
            &[
                PlannerDiagnostic::ReusedStableAllocation,
                PlannerDiagnostic::StableAllocationTombstoned,
            ]
        );
    }

    #[test]
    fn service_and_transition_errors_have_fixed_precedence() {
        let target = target(14);
        let allocation = empty_snapshot(target);
        let cyclic = [ServiceDependency::new(service(1), service(1))];
        let input = PlannerInput {
            target,
            desired: PlannerDesired::Omitted,
            previous: PreviousTargetEligibility::Busy,
            manifest: None,
            allocation: &allocation,
            service_dependencies: &cyclic,
        };

        assert!(matches!(
            DeploymentPlanner::plan(&input),
            Err(PlannerError::ServiceDependency(
                ServiceDependencyError::Cycle(_)
            ))
        ));
        let transition_only = PlannerInput {
            service_dependencies: &[],
            ..input
        };
        assert_eq!(
            DeploymentPlanner::plan(&transition_only),
            Err(PlannerError::PreviousTargetBusy)
        );
    }
}
