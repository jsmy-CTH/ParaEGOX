//! Internal, pure Deck specification compiler for the S7-C enabler slice.
//!
//! This module deliberately defines no file format, loader, graph foundation,
//! installation owner, Application identity, live provider, placement input, or
//! Runtime action. `DeckCompiler` consumes only caller-owned immutable values.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_runtime_contracts::assignment::{PortDirection, PortSpec, SchemaRef};
use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};

const DECK_LOCK_VERSION: u16 = 1;
const DECK_LOCK_MAGIC: &[u8; 4] = b"PXDL";
const DECK_LOCK_DIGEST_DOMAIN: &[u8] = b"paraegox.deployment.deck-lock.sha256.v1";
const MAX_DECK_CARDS: usize = 256;
const MAX_DECK_LINKS: usize = 1_024;
const MAX_DECK_REQUIREMENTS: usize = 256;
const MAX_RESOLVER_DEFINITIONS: usize = 256;
const MAX_PORTS_PER_DEFINITION: usize = 256;
const MAX_REFINEMENTS_PER_DEFINITION: usize = 64;
const MAX_RESOLVED_DELIVERY_PROFILES: usize = 256;
const MAX_RESOLVED_REQUIREMENTS: usize = 256;
const MAX_DISPLAY_ENTRIES: usize = 256;
const MAX_DISPLAY_LABEL_BYTES: usize = 256;

macro_rules! opaque_key {
    ($name:ident) => {
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

opaque_key!(DeckKey);
opaque_key!(CardUseKey);
opaque_key!(DeckPortKey);
opaque_key!(DeckLinkKey);
opaque_key!(RequirementKey);
opaque_key!(DeckExportRef);
opaque_key!(CardRefinementRef);
opaque_key!(DeliveryProfileRef);
opaque_key!(RequirementRef);

/// An attempted ownership declaration. S7-C accepts only Deck ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeckOwnershipRequest {
    Deck,
    Application,
}

/// An attempted lifetime declaration. S7-C accepts only Deck lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeckLifetimeRequest {
    Deck,
    Installation,
}

/// Optional semantic role declared by one Card use in DeckSpec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DeckCardRole {
    ReferenceSubject = 1,
    General = 2,
}

/// Per-use configuration is retained in the lock so a later Planner can reject
/// every non-empty configuration in the S7 reference profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeckCardConfig {
    CanonicalEmpty,
    Digest(Digest32),
}

/// Requested CardDefinition version interval retained beside the exact result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CardDefinitionVersionRequirement {
    minimum: u32,
    maximum_inclusive: u32,
}

impl CardDefinitionVersionRequirement {
    #[must_use]
    pub(crate) const fn exact(version: u32) -> Self {
        Self {
            minimum: version,
            maximum_inclusive: version,
        }
    }

    #[must_use]
    pub(crate) const fn inclusive(minimum: u32, maximum_inclusive: u32) -> Self {
        Self {
            minimum,
            maximum_inclusive,
        }
    }

    const fn admits(self, version: u32) -> bool {
        self.minimum != 0
            && self.minimum <= self.maximum_inclusive
            && version >= self.minimum
            && version <= self.maximum_inclusive
    }

    const fn is_valid(self) -> bool {
        self.minimum != 0 && self.minimum <= self.maximum_inclusive
    }
}

/// Optional refinement request, resolved only against a definition-owned entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CardRefinementRequest {
    reference: CardRefinementRef,
}

impl CardRefinementRequest {
    #[must_use]
    pub(crate) const fn new(reference: CardRefinementRef) -> Self {
        Self { reference }
    }
}

/// Opaque definition-owned refinement commitment admitted by a resolver snapshot.
///
/// S7-C locks the exact reference and digest for canonical rejection evidence;
/// it does not claim the wider refinement payload schema is implemented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCardRefinementCommitment {
    reference: CardRefinementRef,
    payload_digest: Digest32,
}

impl ResolvedCardRefinementCommitment {
    #[must_use]
    pub(crate) const fn new(reference: CardRefinementRef, payload_digest: Digest32) -> Self {
        Self {
            reference,
            payload_digest,
        }
    }
}

/// Display-only input intentionally excluded from DeckLock bytes and digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeckDisplayMetadata {
    label: Box<str>,
    canvas_x: i64,
    canvas_y: i64,
}

impl DeckDisplayMetadata {
    #[must_use]
    pub(crate) fn new(label: &str, canvas_x: i64, canvas_y: i64) -> Self {
        Self {
            label: label.into(),
            canvas_x,
            canvas_y,
        }
    }
}

/// One unresolved Card use in a DeckSpec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeckCardSpec {
    key: CardUseKey,
    definition: CardDefinitionRef,
    role: DeckCardRole,
    requested_version: CardDefinitionVersionRequirement,
    refinement: Option<CardRefinementRequest>,
    config: DeckCardConfig,
}

impl DeckCardSpec {
    #[must_use]
    pub(crate) const fn new(
        key: CardUseKey,
        definition: CardDefinitionRef,
        config: DeckCardConfig,
    ) -> Self {
        Self {
            key,
            definition,
            role: DeckCardRole::General,
            requested_version: CardDefinitionVersionRequirement::exact(1),
            refinement: None,
            config,
        }
    }

    #[must_use]
    pub(crate) const fn with_role(mut self, role: DeckCardRole) -> Self {
        self.role = role;
        self
    }

    #[must_use]
    pub(crate) const fn with_requested_version(
        mut self,
        requested_version: CardDefinitionVersionRequirement,
    ) -> Self {
        self.requested_version = requested_version;
        self
    }

    #[must_use]
    pub(crate) const fn with_refinement(mut self, refinement: CardRefinementRequest) -> Self {
        self.refinement = Some(refinement);
        self
    }
}

/// One closure-key-qualified Port endpoint declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeckEndpointSpec {
    card: CardUseKey,
    port: DeckPortKey,
}

impl DeckEndpointSpec {
    #[must_use]
    pub(crate) const fn new(card: CardUseKey, port: DeckPortKey) -> Self {
        Self { card, port }
    }
}

/// One topology-owned Requirement key paired with its locked contract reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeckRequirementSpec {
    key: RequirementKey,
    reference: RequirementRef,
}

impl DeckRequirementSpec {
    #[must_use]
    pub(crate) const fn new(key: RequirementKey, reference: RequirementRef) -> Self {
        Self { key, reference }
    }
}

/// One typed DataLink declaration. Its key preserves parallel multigraph edges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeckLinkSpec {
    key: DeckLinkKey,
    source: DeckEndpointSpec,
    target: DeckEndpointSpec,
    delivery_profile: Option<DeliveryProfileRef>,
}

impl DeckLinkSpec {
    #[must_use]
    pub(crate) const fn new(
        key: DeckLinkKey,
        source: DeckEndpointSpec,
        target: DeckEndpointSpec,
    ) -> Self {
        Self {
            key,
            source,
            target,
            delivery_profile: None,
        }
    }

    #[must_use]
    pub(crate) const fn with_delivery_profile(
        mut self,
        delivery_profile: DeliveryProfileRef,
    ) -> Self {
        self.delivery_profile = Some(delivery_profile);
        self
    }
}

/// Editable, internal Deck input. It is not a persisted or public schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeckSpec {
    deck_key: DeckKey,
    cards: Vec<DeckCardSpec>,
    links: Vec<DeckLinkSpec>,
    requirements: Vec<DeckRequirementSpec>,
    display: Vec<DeckDisplayMetadata>,
    ownership: DeckOwnershipRequest,
    lifetime: DeckLifetimeRequest,
}

impl DeckSpec {
    #[must_use]
    pub(crate) fn new(
        deck_key: DeckKey,
        cards: Vec<DeckCardSpec>,
        links: Vec<DeckLinkSpec>,
        requirements: Vec<DeckRequirementSpec>,
        display: Vec<DeckDisplayMetadata>,
        ownership: DeckOwnershipRequest,
        lifetime: DeckLifetimeRequest,
    ) -> Self {
        Self {
            deck_key,
            cards,
            links,
            requirements,
            display,
            ownership,
            lifetime,
        }
    }
}

/// Exact resolved Port payload supplied through the immutable resolver snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedDeckPort {
    key: DeckPortKey,
    spec: PortSpec,
}

impl ResolvedDeckPort {
    #[must_use]
    pub(crate) const fn new(key: DeckPortKey, spec: PortSpec) -> Self {
        Self { key, spec }
    }
}

/// Exact CardDefinition closure entry supplied to the pure compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCardArtifact {
    definition_digest: Digest32,
    implementation: CardImplementationRef,
    export: DeckExportRef,
    artifact_digest: Digest32,
}

impl ResolvedCardArtifact {
    #[must_use]
    pub(crate) const fn new(
        definition_digest: Digest32,
        implementation: CardImplementationRef,
        export: DeckExportRef,
        artifact_digest: Digest32,
    ) -> Self {
        Self {
            definition_digest,
            implementation,
            export,
            artifact_digest,
        }
    }
}

/// Exact CardDefinition closure entry supplied to the pure compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCardDefinition {
    definition: CardDefinitionRef,
    version: u32,
    definition_digest: Digest32,
    implementation: CardImplementationRef,
    export: DeckExportRef,
    artifact_digest: Digest32,
    ports: Vec<ResolvedDeckPort>,
    refinements: Vec<ResolvedCardRefinementCommitment>,
}

impl ResolvedCardDefinition {
    #[must_use]
    pub(crate) fn new(
        definition: CardDefinitionRef,
        version: u32,
        artifact: ResolvedCardArtifact,
        ports: Vec<ResolvedDeckPort>,
    ) -> Self {
        Self {
            definition,
            version,
            definition_digest: artifact.definition_digest,
            implementation: artifact.implementation,
            export: artifact.export,
            artifact_digest: artifact.artifact_digest,
            ports,
            refinements: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn with_refinements(
        mut self,
        refinements: Vec<ResolvedCardRefinementCommitment>,
    ) -> Self {
        self.refinements = refinements;
        self
    }
}

/// Opaque Link-owned DeliveryProfile commitment in the resolver snapshot.
///
/// Nonempty Links fail closed in the S7-C Planner. This value locks only the
/// exact reference and resolver-supplied payload digest; it is not the wider
/// typed DeliveryProfile payload promised by ADR-0004.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedDeliveryProfileCommitment {
    reference: DeliveryProfileRef,
    payload_digest: Digest32,
}

impl ResolvedDeliveryProfileCommitment {
    #[must_use]
    pub(crate) const fn new(reference: DeliveryProfileRef, payload_digest: Digest32) -> Self {
        Self {
            reference,
            payload_digest,
        }
    }
}

/// Opaque Requirement commitment; provider selection remains a later input.
///
/// S7-C locks a reference and resolver-supplied payload digest so mutations are
/// canonical, then rejects every nonempty Requirement before a candidate. It
/// does not implement the wider typed Service/Permission/Feature payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedRequirementCommitment {
    reference: RequirementRef,
    payload_digest: Digest32,
}

impl ResolvedRequirementCommitment {
    #[must_use]
    pub(crate) const fn new(reference: RequirementRef, payload_digest: Digest32) -> Self {
        Self {
            reference,
            payload_digest,
        }
    }
}

/// Caller-created immutable resolution facts. No lookup or I/O occurs here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeckResolverSnapshot {
    definitions: Vec<ResolvedCardDefinition>,
    delivery_profiles: Vec<ResolvedDeliveryProfileCommitment>,
    requirements: Vec<ResolvedRequirementCommitment>,
}

impl DeckResolverSnapshot {
    #[must_use]
    pub(crate) fn new(definitions: Vec<ResolvedCardDefinition>) -> Self {
        Self {
            definitions,
            delivery_profiles: Vec::new(),
            requirements: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn with_delivery_profiles(
        mut self,
        delivery_profiles: Vec<ResolvedDeliveryProfileCommitment>,
    ) -> Self {
        self.delivery_profiles = delivery_profiles;
        self
    }

    #[must_use]
    pub(crate) fn with_requirements(
        mut self,
        requirements: Vec<ResolvedRequirementCommitment>,
    ) -> Self {
        self.requirements = requirements;
        self
    }
}

/// One canonical DataLink retained in DeckTopology.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeckLink {
    key: DeckLinkKey,
    source: DeckEndpointSpec,
    target: DeckEndpointSpec,
    delivery_profile: DeliveryProfileRef,
}

impl DeckLink {
    #[must_use]
    pub(crate) const fn key(self) -> DeckLinkKey {
        self.key
    }

    #[must_use]
    pub(crate) const fn source(self) -> DeckEndpointSpec {
        self.source
    }

    #[must_use]
    pub(crate) const fn target(self) -> DeckEndpointSpec {
        self.target
    }

    #[must_use]
    pub(crate) const fn delivery_profile(self) -> DeliveryProfileRef {
        self.delivery_profile
    }
}

/// Canonical Requirement structure; its payload lives only in the closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeckRequirement {
    key: RequirementKey,
    reference: RequirementRef,
}

/// Canonical typed Deck multigraph structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeckTopology {
    card_keys: Vec<CardUseKey>,
    links: Vec<DeckLink>,
    requirements: Vec<DeckRequirement>,
}

impl DeckTopology {
    #[must_use]
    pub(crate) fn card_keys(&self) -> &[CardUseKey] {
        &self.card_keys
    }

    #[must_use]
    pub(crate) fn links(&self) -> &[DeckLink] {
        &self.links
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[DeckRequirement] {
        &self.requirements
    }
}

/// One exact Card use payload in the resolved closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCardUse {
    key: CardUseKey,
    definition: CardDefinitionRef,
    requested_version: CardDefinitionVersionRequirement,
    definition_version: u32,
    definition_digest: Digest32,
    implementation: CardImplementationRef,
    export: DeckExportRef,
    artifact_digest: Digest32,
    role: DeckCardRole,
    refinement: Option<ResolvedCardRefinementCommitment>,
    config: DeckCardConfig,
    ports: Vec<ResolvedDeckPort>,
}

impl ResolvedCardUse {
    #[must_use]
    pub(crate) const fn key(&self) -> CardUseKey {
        self.key
    }

    #[must_use]
    pub(crate) const fn definition(&self) -> CardDefinitionRef {
        self.definition
    }

    #[must_use]
    pub(crate) const fn definition_digest(&self) -> Digest32 {
        self.definition_digest
    }

    #[must_use]
    pub(crate) const fn implementation(&self) -> CardImplementationRef {
        self.implementation
    }

    #[must_use]
    pub(crate) const fn export(&self) -> DeckExportRef {
        self.export
    }

    #[must_use]
    pub(crate) const fn artifact_digest(&self) -> Digest32 {
        self.artifact_digest
    }

    #[must_use]
    pub(crate) const fn role(&self) -> DeckCardRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn is_reference_subject(&self) -> bool {
        matches!(self.role, DeckCardRole::ReferenceSubject)
    }

    #[must_use]
    pub(crate) const fn has_ports(&self) -> bool {
        !self.ports.is_empty()
    }

    #[must_use]
    pub(crate) const fn has_refinement(&self) -> bool {
        self.refinement.is_some()
    }

    #[must_use]
    pub(crate) const fn has_per_use_config(&self) -> bool {
        matches!(self.config, DeckCardConfig::Digest(_))
    }
}

/// S7-C resolved closure half of a DeckLock.
///
/// Card fields and Ports are exact typed values. DeliveryProfile, Requirement,
/// and refinement fields remain explicitly named opaque commitments because
/// every corresponding nonempty S7-C shape fails closed in the Planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedDeckClosure {
    cards: Vec<ResolvedCardUse>,
    delivery_profiles: Vec<ResolvedDeliveryProfileCommitment>,
    requirements: Vec<ResolvedRequirementCommitment>,
}

impl ResolvedDeckClosure {
    #[must_use]
    pub(crate) fn cards(&self) -> &[ResolvedCardUse] {
        &self.cards
    }

    #[must_use]
    pub(crate) fn delivery_profiles(&self) -> &[ResolvedDeliveryProfileCommitment] {
        &self.delivery_profiles
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[ResolvedRequirementCommitment] {
        &self.requirements
    }
}

/// Deterministic SCC and concrete edge witness for one rejected cyclic Deck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeckCycleWitness {
    component: Vec<CardUseKey>,
    cards: Vec<CardUseKey>,
    links: Vec<DeckLinkKey>,
}

impl DeckCycleWitness {
    #[must_use]
    pub(crate) fn component(&self) -> &[CardUseKey] {
        &self.component
    }

    #[must_use]
    pub(crate) fn cards(&self) -> &[CardUseKey] {
        &self.cards
    }

    #[must_use]
    pub(crate) fn links(&self) -> &[DeckLinkKey] {
        &self.links
    }
}

/// Stable validation taxonomy. Checks run in declaration-independent variant order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DeckCompileError {
    ApplicationOwnershipUnsupported,
    InstallationLifetimeUnsupported,
    TooManyCards,
    TooManyLinks,
    TooManyRequirements,
    TooManyResolverDefinitions,
    TooManyPorts(CardDefinitionRef),
    TooManyRefinements(CardDefinitionRef),
    TooManyDeliveryProfiles,
    TooManyResolvedRequirements,
    TooManyDisplayEntries,
    DisplayLabelTooLong,
    EmptyDeck,
    DuplicateCardUse(CardUseKey),
    InvalidRequestedDefinitionVersion(CardUseKey),
    DuplicateResolvedDefinition(CardDefinitionRef),
    InvalidDefinitionVersion(CardDefinitionRef),
    ResolvedDefinitionVersionMismatch(CardUseKey),
    DuplicateResolvedPort {
        definition: CardDefinitionRef,
        port: DeckPortKey,
    },
    DuplicateResolvedRefinement {
        definition: CardDefinitionRef,
        refinement: CardRefinementRef,
    },
    MissingResolvedRefinement {
        card: CardUseKey,
        refinement: CardRefinementRef,
    },
    MissingResolvedDefinition(CardDefinitionRef),
    DuplicateRequirement(RequirementKey),
    DuplicateRequirementRef(RequirementRef),
    DuplicateResolvedRequirement(RequirementRef),
    MissingResolvedRequirement(RequirementRef),
    DuplicateLink(DeckLinkKey),
    MissingDeliveryProfileRef(DeckLinkKey),
    DuplicateResolvedDeliveryProfile(DeliveryProfileRef),
    MissingResolvedDeliveryProfile(DeliveryProfileRef),
    DanglingSourceCard {
        link: DeckLinkKey,
        card: CardUseKey,
    },
    DanglingTargetCard {
        link: DeckLinkKey,
        card: CardUseKey,
    },
    DanglingSourcePort {
        link: DeckLinkKey,
        port: DeckPortKey,
    },
    DanglingTargetPort {
        link: DeckLinkKey,
        port: DeckPortKey,
    },
    SourcePortIsNotOutput(DeckLinkKey),
    TargetPortIsNotInput(DeckLinkKey),
    PortSchemaMismatch(DeckLinkKey),
    PortInteractionMismatch(DeckLinkKey),
    CyclicDeck(DeckCycleWitness),
    CanonicalLengthOverflow,
    Digest(DigestBuildError),
}

impl From<DigestBuildError> for DeckCompileError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for DeckCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DeckCompileError {}

/// Unique canonical DeckCompiler output consumed by the future pure Planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeckLock {
    deck_key: DeckKey,
    topology: DeckTopology,
    resolved_closure: ResolvedDeckClosure,
    canonical_wire: Box<[u8]>,
    digest: Digest32,
}

impl DeckLock {
    #[must_use]
    pub(crate) const fn deck_key(&self) -> DeckKey {
        self.deck_key
    }

    #[must_use]
    pub(crate) const fn topology(&self) -> &DeckTopology {
        &self.topology
    }

    #[must_use]
    pub(crate) const fn resolved_closure(&self) -> &ResolvedDeckClosure {
        &self.resolved_closure
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> Digest32 {
        self.digest
    }
}

/// Pure DeckSpec-to-DeckLock compiler.
pub(crate) struct DeckCompiler;

impl DeckCompiler {
    pub(crate) fn compile(
        spec: &DeckSpec,
        resolver: &DeckResolverSnapshot,
    ) -> Result<DeckLock, DeckCompileError> {
        // Frozen precedence: unsupported owner/lifetime, structural uniqueness,
        // resolution, link endpoints, Port semantics, cycle, canonicalization.
        if spec.ownership == DeckOwnershipRequest::Application {
            return Err(DeckCompileError::ApplicationOwnershipUnsupported);
        }
        if spec.lifetime == DeckLifetimeRequest::Installation {
            return Err(DeckCompileError::InstallationLifetimeUnsupported);
        }
        if spec.cards.len() > MAX_DECK_CARDS {
            return Err(DeckCompileError::TooManyCards);
        }
        if spec.links.len() > MAX_DECK_LINKS {
            return Err(DeckCompileError::TooManyLinks);
        }
        if spec.requirements.len() > MAX_DECK_REQUIREMENTS {
            return Err(DeckCompileError::TooManyRequirements);
        }
        if resolver.definitions.len() > MAX_RESOLVER_DEFINITIONS {
            return Err(DeckCompileError::TooManyResolverDefinitions);
        }
        if resolver.delivery_profiles.len() > MAX_RESOLVED_DELIVERY_PROFILES {
            return Err(DeckCompileError::TooManyDeliveryProfiles);
        }
        if resolver.requirements.len() > MAX_RESOLVED_REQUIREMENTS {
            return Err(DeckCompileError::TooManyResolvedRequirements);
        }
        if spec.display.len() > MAX_DISPLAY_ENTRIES {
            return Err(DeckCompileError::TooManyDisplayEntries);
        }
        if spec
            .display
            .iter()
            .any(|entry| entry.label.len() > MAX_DISPLAY_LABEL_BYTES)
        {
            return Err(DeckCompileError::DisplayLabelTooLong);
        }
        if spec.cards.is_empty() {
            return Err(DeckCompileError::EmptyDeck);
        }

        let mut cards = spec.cards.clone();
        cards.sort_by_key(|card| card.key);
        if let Some(key) = first_duplicate(cards.iter().map(|card| card.key)) {
            return Err(DeckCompileError::DuplicateCardUse(key));
        }
        if let Some(card) = cards.iter().find(|card| !card.requested_version.is_valid()) {
            return Err(DeckCompileError::InvalidRequestedDefinitionVersion(
                card.key,
            ));
        }

        let mut definition_refs = resolver
            .definitions
            .iter()
            .map(|definition| definition.definition)
            .collect::<Vec<_>>();
        definition_refs.sort_unstable();
        if let Some(definition) = first_duplicate(definition_refs.iter().copied()) {
            return Err(DeckCompileError::DuplicateResolvedDefinition(definition));
        }
        let preflight_error = resolver
            .definitions
            .iter()
            .filter_map(|definition| {
                let error = if definition.version == 0 {
                    DeckCompileError::InvalidDefinitionVersion(definition.definition)
                } else if definition.ports.len() > MAX_PORTS_PER_DEFINITION {
                    DeckCompileError::TooManyPorts(definition.definition)
                } else if definition.refinements.len() > MAX_REFINEMENTS_PER_DEFINITION {
                    DeckCompileError::TooManyRefinements(definition.definition)
                } else {
                    return None;
                };
                Some((definition.definition, error))
            })
            .min_by_key(|(definition, _)| *definition)
            .map(|(_, error)| error);
        if let Some(error) = preflight_error {
            return Err(error);
        }

        let mut definitions = resolver.definitions.clone();
        definitions.sort_by_key(|definition| definition.definition);
        for definition in &mut definitions {
            definition.ports.sort_by_key(|port| port.key);
            if let Some(port) = first_duplicate(definition.ports.iter().map(|port| port.key)) {
                return Err(DeckCompileError::DuplicateResolvedPort {
                    definition: definition.definition,
                    port,
                });
            }
            definition
                .refinements
                .sort_by_key(|refinement| refinement.reference);
            if let Some(refinement) =
                first_duplicate(definition.refinements.iter().map(|entry| entry.reference))
            {
                return Err(DeckCompileError::DuplicateResolvedRefinement {
                    definition: definition.definition,
                    refinement,
                });
            }
        }

        let definition_index: BTreeMap<_, _> = definitions
            .iter()
            .map(|definition| (definition.definition, definition))
            .collect();
        let mut resolved_cards = Vec::with_capacity(cards.len());
        for card in &cards {
            let definition = definition_index
                .get(&card.definition)
                .ok_or(DeckCompileError::MissingResolvedDefinition(card.definition))?;
            if !card.requested_version.admits(definition.version) {
                return Err(DeckCompileError::ResolvedDefinitionVersionMismatch(
                    card.key,
                ));
            }
            let refinement = if let Some(requested) = card.refinement {
                let index = definition
                    .refinements
                    .binary_search_by_key(&requested.reference, |entry| entry.reference)
                    .map_err(|_| DeckCompileError::MissingResolvedRefinement {
                        card: card.key,
                        refinement: requested.reference,
                    })?;
                Some(definition.refinements[index])
            } else {
                None
            };
            resolved_cards.push(ResolvedCardUse {
                key: card.key,
                definition: definition.definition,
                requested_version: card.requested_version,
                definition_version: definition.version,
                definition_digest: definition.definition_digest,
                implementation: definition.implementation,
                export: definition.export,
                artifact_digest: definition.artifact_digest,
                role: card.role,
                refinement,
                config: card.config,
                ports: definition.ports.clone(),
            });
        }

        let mut requirements = spec.requirements.clone();
        requirements.sort_by_key(|requirement| requirement.key);
        if let Some(key) = first_duplicate(requirements.iter().map(|entry| entry.key)) {
            return Err(DeckCompileError::DuplicateRequirement(key));
        }
        let mut requirement_refs = requirements
            .iter()
            .map(|entry| entry.reference)
            .collect::<Vec<_>>();
        requirement_refs.sort_unstable();
        if let Some(reference) = first_duplicate(requirement_refs.iter().copied()) {
            return Err(DeckCompileError::DuplicateRequirementRef(reference));
        }
        let mut available_requirements = resolver.requirements.clone();
        available_requirements.sort_by_key(|requirement| requirement.reference);
        if let Some(reference) =
            first_duplicate(available_requirements.iter().map(|entry| entry.reference))
        {
            return Err(DeckCompileError::DuplicateResolvedRequirement(reference));
        }
        let requirement_index = available_requirements
            .iter()
            .map(|requirement| (requirement.reference, *requirement))
            .collect::<BTreeMap<_, _>>();
        let mut canonical_requirements = Vec::with_capacity(requirements.len());
        let mut resolved_requirements = Vec::with_capacity(requirements.len());
        for requirement in requirements {
            let payload = requirement_index.get(&requirement.reference).ok_or(
                DeckCompileError::MissingResolvedRequirement(requirement.reference),
            )?;
            canonical_requirements.push(DeckRequirement {
                key: requirement.key,
                reference: requirement.reference,
            });
            resolved_requirements.push(*payload);
        }
        resolved_requirements.sort_by_key(|requirement| requirement.reference);

        let mut links = spec.links.clone();
        links.sort_by_key(|link| link.key);
        if let Some(key) = first_duplicate(links.iter().map(|link| link.key)) {
            return Err(DeckCompileError::DuplicateLink(key));
        }
        let mut available_delivery_profiles = resolver.delivery_profiles.clone();
        available_delivery_profiles.sort_by_key(|profile| profile.reference);
        if let Some(reference) = first_duplicate(
            available_delivery_profiles
                .iter()
                .map(|entry| entry.reference),
        ) {
            return Err(DeckCompileError::DuplicateResolvedDeliveryProfile(
                reference,
            ));
        }
        let delivery_index = available_delivery_profiles
            .iter()
            .map(|profile| (profile.reference, *profile))
            .collect::<BTreeMap<_, _>>();

        let card_index: BTreeMap<_, _> =
            resolved_cards.iter().map(|card| (card.key, card)).collect();
        let mut canonical_links = Vec::with_capacity(links.len());
        let mut used_delivery_profiles = BTreeSet::new();
        for link in links {
            let delivery_profile = link
                .delivery_profile
                .ok_or(DeckCompileError::MissingDeliveryProfileRef(link.key))?;
            if !delivery_index.contains_key(&delivery_profile) {
                return Err(DeckCompileError::MissingResolvedDeliveryProfile(
                    delivery_profile,
                ));
            }
            let source =
                card_index
                    .get(&link.source.card)
                    .ok_or(DeckCompileError::DanglingSourceCard {
                        link: link.key,
                        card: link.source.card,
                    })?;
            let target =
                card_index
                    .get(&link.target.card)
                    .ok_or(DeckCompileError::DanglingTargetCard {
                        link: link.key,
                        card: link.target.card,
                    })?;
            let source_port = find_port(source, link.source.port).ok_or(
                DeckCompileError::DanglingSourcePort {
                    link: link.key,
                    port: link.source.port,
                },
            )?;
            let target_port = find_port(target, link.target.port).ok_or(
                DeckCompileError::DanglingTargetPort {
                    link: link.key,
                    port: link.target.port,
                },
            )?;
            if source_port.spec.direction() != PortDirection::Out {
                return Err(DeckCompileError::SourcePortIsNotOutput(link.key));
            }
            if target_port.spec.direction() != PortDirection::In {
                return Err(DeckCompileError::TargetPortIsNotInput(link.key));
            }
            if source_port.spec.schema() != target_port.spec.schema() {
                return Err(DeckCompileError::PortSchemaMismatch(link.key));
            }
            if source_port.spec.interaction() != target_port.spec.interaction() {
                return Err(DeckCompileError::PortInteractionMismatch(link.key));
            }
            canonical_links.push(DeckLink {
                key: link.key,
                source: link.source,
                target: link.target,
                delivery_profile,
            });
            used_delivery_profiles.insert(delivery_profile);
        }
        let resolved_delivery_profiles = used_delivery_profiles
            .into_iter()
            .map(|reference| {
                delivery_index
                    .get(&reference)
                    .copied()
                    .ok_or(DeckCompileError::MissingResolvedDeliveryProfile(reference))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let card_keys = cards.iter().map(|card| card.key).collect::<Vec<_>>();
        if let Some(witness) = cycle_witness(&card_keys, &canonical_links) {
            return Err(DeckCompileError::CyclicDeck(witness));
        }

        let topology = DeckTopology {
            card_keys,
            links: canonical_links,
            requirements: canonical_requirements,
        };
        let resolved_closure = ResolvedDeckClosure {
            cards: resolved_cards,
            delivery_profiles: resolved_delivery_profiles,
            requirements: resolved_requirements,
        };
        let canonical_wire = encode_lock(spec.deck_key, &topology, &resolved_closure)?;
        let mut digest = Digest32Builder::try_new(DECK_LOCK_DIGEST_DOMAIN)?;
        digest.field_bytes(&canonical_wire)?;

        Ok(DeckLock {
            deck_key: spec.deck_key,
            topology,
            resolved_closure,
            canonical_wire: canonical_wire.into_boxed_slice(),
            digest: digest.finish(),
        })
    }
}

fn first_duplicate<T: Copy + Eq>(values: impl IntoIterator<Item = T>) -> Option<T> {
    let mut previous = None;
    for value in values {
        if previous == Some(value) {
            return Some(value);
        }
        previous = Some(value);
    }
    None
}

fn find_port(card: &ResolvedCardUse, key: DeckPortKey) -> Option<&ResolvedDeckPort> {
    card.ports
        .binary_search_by_key(&key, |port| port.key)
        .ok()
        .map(|index| &card.ports[index])
}

fn cycle_witness(cards: &[CardUseKey], links: &[DeckLink]) -> Option<DeckCycleWitness> {
    let forward = adjacency(cards, links, false);
    let reverse = adjacency(cards, links, true);
    let mut visited = BTreeSet::new();
    let mut finish = Vec::with_capacity(cards.len());
    for &card in cards {
        visit_finish(card, &forward, &mut visited, &mut finish);
    }

    visited.clear();
    let mut components = Vec::new();
    while let Some(card) = finish.pop() {
        if visited.contains(&card) {
            continue;
        }
        let mut component = Vec::new();
        visit_component(card, &reverse, &mut visited, &mut component);
        component.sort_unstable();
        components.push(component);
    }
    components.sort();

    for component in components {
        let cyclic = component.len() > 1
            || links
                .iter()
                .any(|link| link.source.card == component[0] && link.target.card == component[0]);
        if cyclic {
            let allowed = component.iter().copied().collect::<BTreeSet<_>>();
            if let Some((cycle_cards, cycle_links)) = concrete_cycle(&component, links, &allowed) {
                return Some(DeckCycleWitness {
                    component,
                    cards: cycle_cards,
                    links: cycle_links,
                });
            }
        }
    }
    None
}

fn adjacency(
    cards: &[CardUseKey],
    links: &[DeckLink],
    reverse: bool,
) -> BTreeMap<CardUseKey, Vec<(CardUseKey, DeckLinkKey)>> {
    let mut result = cards
        .iter()
        .copied()
        .map(|card| (card, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    for link in links {
        let (source, target) = if reverse {
            (link.target.card, link.source.card)
        } else {
            (link.source.card, link.target.card)
        };
        result.entry(source).or_default().push((target, link.key));
    }
    for edges in result.values_mut() {
        edges.sort_by_key(|(target, link)| (*link, *target));
    }
    result
}

fn visit_finish(
    card: CardUseKey,
    adjacency: &BTreeMap<CardUseKey, Vec<(CardUseKey, DeckLinkKey)>>,
    visited: &mut BTreeSet<CardUseKey>,
    finish: &mut Vec<CardUseKey>,
) {
    if !visited.insert(card) {
        return;
    }
    if let Some(edges) = adjacency.get(&card) {
        for &(target, _) in edges {
            visit_finish(target, adjacency, visited, finish);
        }
    }
    finish.push(card);
}

fn visit_component(
    card: CardUseKey,
    reverse: &BTreeMap<CardUseKey, Vec<(CardUseKey, DeckLinkKey)>>,
    visited: &mut BTreeSet<CardUseKey>,
    component: &mut Vec<CardUseKey>,
) {
    if !visited.insert(card) {
        return;
    }
    component.push(card);
    if let Some(edges) = reverse.get(&card) {
        for &(target, _) in edges {
            visit_component(target, reverse, visited, component);
        }
    }
}

fn concrete_cycle(
    component: &[CardUseKey],
    links: &[DeckLink],
    allowed: &BTreeSet<CardUseKey>,
) -> Option<(Vec<CardUseKey>, Vec<DeckLinkKey>)> {
    let mut outgoing = BTreeMap::<CardUseKey, Vec<(CardUseKey, DeckLinkKey)>>::new();
    for &card in component {
        outgoing.insert(card, Vec::new());
    }
    for link in links {
        if allowed.contains(&link.source.card) && allowed.contains(&link.target.card) {
            outgoing
                .get_mut(&link.source.card)?
                .push((link.target.card, link.key));
        }
    }
    for edges in outgoing.values_mut() {
        edges.sort_by_key(|(target, link)| (*link, *target));
    }

    let mut colors = BTreeMap::new();
    let mut stack_cards = Vec::new();
    let mut stack_links = Vec::new();
    for &card in component {
        if colors.get(&card).copied().unwrap_or(0) == 0
            && let Some(witness) = visit_cycle(
                card,
                &outgoing,
                &mut colors,
                &mut stack_cards,
                &mut stack_links,
            )
        {
            return Some(witness);
        }
    }
    None
}

fn visit_cycle(
    card: CardUseKey,
    outgoing: &BTreeMap<CardUseKey, Vec<(CardUseKey, DeckLinkKey)>>,
    colors: &mut BTreeMap<CardUseKey, u8>,
    stack_cards: &mut Vec<CardUseKey>,
    stack_links: &mut Vec<DeckLinkKey>,
) -> Option<(Vec<CardUseKey>, Vec<DeckLinkKey>)> {
    colors.insert(card, 1);
    stack_cards.push(card);
    if let Some(edges) = outgoing.get(&card) {
        for &(target, link) in edges {
            match colors.get(&target).copied().unwrap_or(0) {
                0 => {
                    stack_links.push(link);
                    if let Some(witness) =
                        visit_cycle(target, outgoing, colors, stack_cards, stack_links)
                    {
                        return Some(witness);
                    }
                    stack_links.pop();
                }
                1 => {
                    let start = stack_cards
                        .iter()
                        .position(|candidate| *candidate == target)?;
                    let mut cycle_cards = stack_cards[start..].to_vec();
                    cycle_cards.push(target);
                    let mut cycle_links = stack_links[start..].to_vec();
                    cycle_links.push(link);
                    return Some((cycle_cards, cycle_links));
                }
                _ => {}
            }
        }
    }
    stack_cards.pop();
    colors.insert(card, 2);
    None
}

fn encode_lock(
    deck_key: DeckKey,
    topology: &DeckTopology,
    closure: &ResolvedDeckClosure,
) -> Result<Vec<u8>, DeckCompileError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(DECK_LOCK_MAGIC);
    encoded.extend_from_slice(&DECK_LOCK_VERSION.to_be_bytes());
    encoded.extend_from_slice(deck_key.as_bytes());

    append_count(&mut encoded, topology.card_keys.len())?;
    for key in &topology.card_keys {
        encoded.extend_from_slice(key.as_bytes());
    }
    append_count(&mut encoded, topology.links.len())?;
    for link in &topology.links {
        encoded.extend_from_slice(link.key.as_bytes());
        append_endpoint(&mut encoded, link.source);
        append_endpoint(&mut encoded, link.target);
        encoded.extend_from_slice(link.delivery_profile.as_bytes());
    }
    append_count(&mut encoded, topology.requirements.len())?;
    for requirement in &topology.requirements {
        encoded.extend_from_slice(requirement.key.as_bytes());
        encoded.extend_from_slice(requirement.reference.as_bytes());
    }

    append_count(&mut encoded, closure.cards.len())?;
    for card in &closure.cards {
        encoded.extend_from_slice(card.key.as_bytes());
        encoded.extend_from_slice(card.definition.as_bytes());
        encoded.extend_from_slice(&card.requested_version.minimum.to_be_bytes());
        encoded.extend_from_slice(&card.requested_version.maximum_inclusive.to_be_bytes());
        encoded.extend_from_slice(&card.definition_version.to_be_bytes());
        encoded.extend_from_slice(card.definition_digest.as_bytes());
        encoded.extend_from_slice(card.implementation.as_bytes());
        encoded.extend_from_slice(card.export.as_bytes());
        encoded.extend_from_slice(card.artifact_digest.as_bytes());
        encoded.push(card.role as u8);
        if let Some(refinement) = card.refinement {
            encoded.push(1);
            encoded.extend_from_slice(refinement.reference.as_bytes());
            encoded.extend_from_slice(refinement.payload_digest.as_bytes());
        } else {
            encoded.push(0);
        }
        match card.config {
            DeckCardConfig::CanonicalEmpty => encoded.push(0),
            DeckCardConfig::Digest(digest) => {
                encoded.push(1);
                encoded.extend_from_slice(digest.as_bytes());
            }
        }
        append_count(&mut encoded, card.ports.len())?;
        for port in &card.ports {
            append_port(&mut encoded, port);
        }
    }
    append_count(&mut encoded, closure.delivery_profiles.len())?;
    for profile in &closure.delivery_profiles {
        encoded.extend_from_slice(profile.reference.as_bytes());
        encoded.extend_from_slice(profile.payload_digest.as_bytes());
    }
    append_count(&mut encoded, closure.requirements.len())?;
    for requirement in &closure.requirements {
        encoded.extend_from_slice(requirement.reference.as_bytes());
        encoded.extend_from_slice(requirement.payload_digest.as_bytes());
    }
    Ok(encoded)
}

fn append_count(encoded: &mut Vec<u8>, value: usize) -> Result<(), DeckCompileError> {
    let value = u32::try_from(value).map_err(|_| DeckCompileError::CanonicalLengthOverflow)?;
    encoded.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn append_endpoint(encoded: &mut Vec<u8>, endpoint: DeckEndpointSpec) {
    encoded.extend_from_slice(endpoint.card.as_bytes());
    encoded.extend_from_slice(endpoint.port.as_bytes());
}

fn append_port(encoded: &mut Vec<u8>, port: &ResolvedDeckPort) {
    let schema: SchemaRef = port.spec.schema();
    encoded.extend_from_slice(port.key.as_bytes());
    encoded.push(port.spec.direction() as u8);
    encoded.extend_from_slice(schema.id_bytes());
    encoded.extend_from_slice(&schema.version().to_be_bytes());
    encoded.extend_from_slice(schema.content_digest().as_bytes());
    encoded.push(port.spec.interaction() as u8);
    encoded.push(port.spec.cardinality() as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use paraegox_runtime_contracts::assignment::{InteractionKind, PortCardinality};

    fn key<T>(byte: u8, constructor: impl FnOnce([u8; 16]) -> T) -> T {
        constructor([byte; 16])
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn schema(byte: u8) -> SchemaRef {
        SchemaRef::try_new([byte; 16], 1, digest(byte))
            .unwrap_or_else(|error| panic!("test schema must be valid: {error}"))
    }

    fn port(
        key_byte: u8,
        direction: PortDirection,
        schema_byte: u8,
        interaction: InteractionKind,
    ) -> ResolvedDeckPort {
        ResolvedDeckPort::new(
            key(key_byte, DeckPortKey::from_bytes),
            PortSpec::new(
                direction,
                schema(schema_byte),
                interaction,
                PortCardinality::One,
            ),
        )
    }

    fn definition(definition_byte: u8, ports: Vec<ResolvedDeckPort>) -> ResolvedCardDefinition {
        ResolvedCardDefinition::new(
            CardDefinitionRef::from_bytes([definition_byte; 16]),
            1,
            ResolvedCardArtifact::new(
                digest(definition_byte),
                CardImplementationRef::from_bytes([definition_byte.wrapping_add(0x40); 16]),
                key(
                    definition_byte.wrapping_add(0x50),
                    DeckExportRef::from_bytes,
                ),
                digest(definition_byte.wrapping_add(0x60)),
            ),
            ports,
        )
    }

    fn card(key_byte: u8, definition_byte: u8) -> DeckCardSpec {
        DeckCardSpec::new(
            key(key_byte, CardUseKey::from_bytes),
            CardDefinitionRef::from_bytes([definition_byte; 16]),
            DeckCardConfig::CanonicalEmpty,
        )
    }

    fn endpoint(card_byte: u8, port_byte: u8) -> DeckEndpointSpec {
        DeckEndpointSpec::new(
            key(card_byte, CardUseKey::from_bytes),
            key(port_byte, DeckPortKey::from_bytes),
        )
    }

    fn link(
        link_byte: u8,
        source_card: u8,
        source_port: u8,
        target_card: u8,
        target_port: u8,
    ) -> DeckLinkSpec {
        DeckLinkSpec::new(
            key(link_byte, DeckLinkKey::from_bytes),
            endpoint(source_card, source_port),
            endpoint(target_card, target_port),
        )
        .with_delivery_profile(key(0xd0, DeliveryProfileRef::from_bytes))
    }

    fn requirement(key_byte: u8, reference_byte: u8) -> DeckRequirementSpec {
        DeckRequirementSpec::new(
            key(key_byte, RequirementKey::from_bytes),
            key(reference_byte, RequirementRef::from_bytes),
        )
    }

    fn default_delivery_profile() -> ResolvedDeliveryProfileCommitment {
        ResolvedDeliveryProfileCommitment::new(
            key(0xd0, DeliveryProfileRef::from_bytes),
            digest(0xd1),
        )
    }

    fn spec(cards: Vec<DeckCardSpec>, links: Vec<DeckLinkSpec>) -> DeckSpec {
        DeckSpec::new(
            key(1, DeckKey::from_bytes),
            cards,
            links,
            Vec::new(),
            Vec::new(),
            DeckOwnershipRequest::Deck,
            DeckLifetimeRequest::Deck,
        )
    }

    fn compile(
        spec: &DeckSpec,
        definitions: Vec<ResolvedCardDefinition>,
    ) -> Result<DeckLock, DeckCompileError> {
        DeckCompiler::compile(
            spec,
            &DeckResolverSnapshot::new(definitions)
                .with_delivery_profiles(vec![default_delivery_profile()]),
        )
    }

    fn semantic_fixture() -> (DeckSpec, DeckResolverSnapshot) {
        let source = card(1, 10)
            .with_role(DeckCardRole::ReferenceSubject)
            .with_requested_version(CardDefinitionVersionRequirement::inclusive(1, 2))
            .with_refinement(CardRefinementRequest::new(key(
                0x70,
                CardRefinementRef::from_bytes,
            )));
        let mut second_link = link(2, 1, 2, 2, 4);
        second_link.delivery_profile = Some(key(0xd2, DeliveryProfileRef::from_bytes));
        let spec = DeckSpec::new(
            key(1, DeckKey::from_bytes),
            vec![source, card(2, 20)],
            vec![link(1, 1, 1, 2, 3), second_link],
            vec![requirement(0xe0, 0xe1), requirement(0xe2, 0xe3)],
            vec![DeckDisplayMetadata::new("semantic fixture", 10, 20)],
            DeckOwnershipRequest::Deck,
            DeckLifetimeRequest::Deck,
        );
        let resolver = DeckResolverSnapshot::new(vec![
            definition(
                10,
                vec![
                    port(1, PortDirection::Out, 7, InteractionKind::Signal),
                    port(2, PortDirection::Out, 7, InteractionKind::Signal),
                ],
            )
            .with_refinements(vec![ResolvedCardRefinementCommitment::new(
                key(0x70, CardRefinementRef::from_bytes),
                digest(0x71),
            )]),
            definition(
                20,
                vec![
                    port(3, PortDirection::In, 7, InteractionKind::Signal),
                    port(4, PortDirection::In, 7, InteractionKind::Signal),
                ],
            ),
        ])
        .with_delivery_profiles(vec![
            default_delivery_profile(),
            ResolvedDeliveryProfileCommitment::new(
                key(0xd2, DeliveryProfileRef::from_bytes),
                digest(0xd3),
            ),
        ])
        .with_requirements(vec![
            ResolvedRequirementCommitment::new(key(0xe1, RequirementRef::from_bytes), digest(0xf1)),
            ResolvedRequirementCommitment::new(key(0xe3, RequirementRef::from_bytes), digest(0xf3)),
        ]);
        (spec, resolver)
    }

    fn compile_snapshot(
        spec: &DeckSpec,
        resolver: &DeckResolverSnapshot,
    ) -> Result<DeckLock, DeckCompileError> {
        DeckCompiler::compile(spec, resolver)
    }

    struct RejectionCase {
        name: &'static str,
        spec: DeckSpec,
        resolver: DeckResolverSnapshot,
        expected: DeckCompileError,
    }

    fn assert_rejection_cases(cases: Vec<RejectionCase>) {
        for case in cases {
            let actual = match compile_snapshot(&case.spec, &case.resolver) {
                Ok(_) => panic!("{} unexpectedly compiled", case.name),
                Err(error) => error,
            };
            assert_eq!(actual, case.expected, "{}", case.name);
        }
    }

    fn indexed_bytes(namespace: u8, index: usize) -> [u8; 16] {
        let index = u64::try_from(index)
            .unwrap_or_else(|_| panic!("test index must fit the canonical fixture width"));
        let mut bytes = [0; 16];
        bytes[0] = namespace;
        bytes[8..].copy_from_slice(&index.to_be_bytes());
        bytes
    }

    fn indexed_key<T>(namespace: u8, index: usize, constructor: impl FnOnce([u8; 16]) -> T) -> T {
        constructor(indexed_bytes(namespace, index))
    }

    fn indexed_definition(index: usize, ports: Vec<ResolvedDeckPort>) -> ResolvedCardDefinition {
        ResolvedCardDefinition::new(
            indexed_key(0x30, index, CardDefinitionRef::from_bytes),
            1,
            ResolvedCardArtifact::new(
                digest(0x31),
                CardImplementationRef::from_bytes([0x32; 16]),
                key(0x33, DeckExportRef::from_bytes),
                digest(0x34),
            ),
            ports,
        )
    }

    fn card_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let definition_ref = CardDefinitionRef::from_bytes([10; 16]);
        let cards = (0..count)
            .map(|index| {
                DeckCardSpec::new(
                    indexed_key(0x10, index, CardUseKey::from_bytes),
                    definition_ref,
                    DeckCardConfig::CanonicalEmpty,
                )
            })
            .collect();
        (
            spec(cards, Vec::new()),
            DeckResolverSnapshot::new(vec![definition(10, Vec::new())]),
        )
    }

    fn link_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let links = (0..count)
            .map(|index| {
                DeckLinkSpec::new(
                    indexed_key(0x20, index, DeckLinkKey::from_bytes),
                    endpoint(1, 1),
                    endpoint(2, 2),
                )
                .with_delivery_profile(key(0xd0, DeliveryProfileRef::from_bytes))
            })
            .collect();
        let resolver = DeckResolverSnapshot::new(vec![
            definition(
                10,
                vec![port(1, PortDirection::Out, 7, InteractionKind::Signal)],
            ),
            definition(
                20,
                vec![port(2, PortDirection::In, 7, InteractionKind::Signal)],
            ),
        ])
        .with_delivery_profiles(vec![default_delivery_profile()]);
        (spec(vec![card(1, 10), card(2, 20)], links), resolver)
    }

    fn requirement_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let requirements = (0..count)
            .map(|index| {
                DeckRequirementSpec::new(
                    indexed_key(0x40, index, RequirementKey::from_bytes),
                    indexed_key(0x41, index, RequirementRef::from_bytes),
                )
            })
            .collect::<Vec<_>>();
        let resolved = (0..count)
            .map(|index| {
                ResolvedRequirementCommitment::new(
                    indexed_key(0x41, index, RequirementRef::from_bytes),
                    digest(0x42),
                )
            })
            .collect();
        (
            DeckSpec::new(
                key(1, DeckKey::from_bytes),
                vec![card(1, 10)],
                Vec::new(),
                requirements,
                Vec::new(),
                DeckOwnershipRequest::Deck,
                DeckLifetimeRequest::Deck,
            ),
            DeckResolverSnapshot::new(vec![definition(10, Vec::new())]).with_requirements(resolved),
        )
    }

    fn resolver_definition_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let definitions = (0..count)
            .map(|index| indexed_definition(index, Vec::new()))
            .collect::<Vec<_>>();
        let selected = definitions
            .first()
            .map(|definition| definition.definition)
            .unwrap_or_else(|| panic!("count-bound fixture needs one definition"));
        let card = DeckCardSpec::new(
            key(1, CardUseKey::from_bytes),
            selected,
            DeckCardConfig::CanonicalEmpty,
        );
        (
            spec(vec![card], Vec::new()),
            DeckResolverSnapshot::new(definitions),
        )
    }

    fn port_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let ports = (0..count)
            .map(|index| {
                ResolvedDeckPort::new(
                    indexed_key(0x50, index, DeckPortKey::from_bytes),
                    PortSpec::new(
                        PortDirection::Out,
                        schema(7),
                        InteractionKind::Signal,
                        PortCardinality::One,
                    ),
                )
            })
            .collect();
        (
            spec(vec![card(1, 10)], Vec::new()),
            DeckResolverSnapshot::new(vec![definition(10, ports)]),
        )
    }

    fn refinement_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let refinements = (0..count)
            .map(|index| {
                ResolvedCardRefinementCommitment::new(
                    indexed_key(0x60, index, CardRefinementRef::from_bytes),
                    digest(0x61),
                )
            })
            .collect();
        (
            spec(vec![card(1, 10)], Vec::new()),
            DeckResolverSnapshot::new(vec![
                definition(10, Vec::new()).with_refinements(refinements),
            ]),
        )
    }

    fn delivery_profile_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let profiles = (0..count)
            .map(|index| {
                ResolvedDeliveryProfileCommitment::new(
                    indexed_key(0x70, index, DeliveryProfileRef::from_bytes),
                    digest(0x71),
                )
            })
            .collect();
        (
            spec(vec![card(1, 10)], Vec::new()),
            DeckResolverSnapshot::new(vec![definition(10, Vec::new())])
                .with_delivery_profiles(profiles),
        )
    }

    fn resolved_requirement_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let requirements = (0..count)
            .map(|index| {
                ResolvedRequirementCommitment::new(
                    indexed_key(0x80, index, RequirementRef::from_bytes),
                    digest(0x81),
                )
            })
            .collect();
        (
            spec(vec![card(1, 10)], Vec::new()),
            DeckResolverSnapshot::new(vec![definition(10, Vec::new())])
                .with_requirements(requirements),
        )
    }

    fn display_count_fixture(count: usize) -> (DeckSpec, DeckResolverSnapshot) {
        let mut deck = spec(vec![card(1, 10)], Vec::new());
        deck.display = vec![DeckDisplayMetadata::new("bounded", 0, 0); count];
        (
            deck,
            DeckResolverSnapshot::new(vec![definition(10, Vec::new())]),
        )
    }

    #[test]
    fn exact_reference_subject_compiles_to_canonical_lock() {
        let lock = compile(
            &spec(
                vec![card(1, 10).with_role(DeckCardRole::ReferenceSubject)],
                Vec::new(),
            ),
            vec![definition(10, Vec::new())],
        )
        .unwrap_or_else(|error| panic!("reference Deck should compile: {error}"));

        assert_eq!(lock.deck_key(), key(1, DeckKey::from_bytes));
        assert!(lock.canonical_bytes().starts_with(b"PXDL\0\x01"));
        assert_eq!(
            lock.topology().card_keys(),
            &[key(1, CardUseKey::from_bytes)]
        );
        assert!(lock.topology().links().is_empty());
        assert!(lock.topology().requirements().is_empty());
        let subject = &lock.resolved_closure().cards()[0];
        assert!(subject.is_reference_subject());
        assert_eq!(subject.role(), DeckCardRole::ReferenceSubject);
        assert!(!subject.has_ports());
        assert!(!subject.has_per_use_config());
        assert_eq!(subject.definition_digest(), digest(10));
    }

    #[test]
    fn input_permutations_are_byte_and_digest_stable_and_keep_parallel_links() {
        let definitions = vec![
            definition(
                10,
                vec![
                    port(2, PortDirection::Out, 7, InteractionKind::Signal),
                    port(1, PortDirection::Out, 7, InteractionKind::Signal),
                ],
            ),
            definition(
                20,
                vec![
                    port(4, PortDirection::In, 7, InteractionKind::Signal),
                    port(3, PortDirection::In, 7, InteractionKind::Signal),
                ],
            ),
        ];
        let first = spec(
            vec![card(2, 20), card(1, 10)],
            vec![link(2, 1, 2, 2, 4), link(1, 1, 1, 2, 3)],
        );
        let second = spec(
            vec![card(1, 10), card(2, 20)],
            vec![link(1, 1, 1, 2, 3), link(2, 1, 2, 2, 4)],
        );
        let mut reversed_definitions = definitions.clone();
        reversed_definitions.reverse();

        let first = compile(&first, definitions)
            .unwrap_or_else(|error| panic!("first permutation failed: {error}"));
        let second = compile(&second, reversed_definitions)
            .unwrap_or_else(|error| panic!("second permutation failed: {error}"));

        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.topology().links().len(), 2);
        assert_ne!(
            first.topology().links()[0].key(),
            first.topology().links()[1].key()
        );
    }

    #[test]
    fn display_metadata_is_excluded_but_semantics_change_the_digest() {
        let mut first = spec(vec![card(1, 10)], Vec::new());
        first.display = vec![DeckDisplayMetadata::new("alpha", 1, 2)];
        let mut second = first.clone();
        second.display = vec![DeckDisplayMetadata::new("renamed", -9, 400)];
        let definitions = vec![definition(10, Vec::new())];

        let first_lock = compile(&first, definitions.clone())
            .unwrap_or_else(|error| panic!("first display fixture failed: {error}"));
        let second_lock = compile(&second, definitions)
            .unwrap_or_else(|error| panic!("second display fixture failed: {error}"));
        assert_eq!(first_lock.canonical_bytes(), second_lock.canonical_bytes());
        assert_eq!(first_lock.digest(), second_lock.digest());

        second.cards[0].config = DeckCardConfig::Digest(digest(99));
        let changed = compile(&second, vec![definition(10, Vec::new())])
            .unwrap_or_else(|error| panic!("semantic mutation fixture failed: {error}"));
        assert_ne!(first_lock.digest(), changed.digest());
        assert!(changed.resolved_closure().cards()[0].has_per_use_config());
    }

    #[test]
    fn every_locked_semantic_partition_perturbs_the_deck_digest() {
        let (base_spec, base_resolver) = semantic_fixture();
        let baseline = compile_snapshot(&base_spec, &base_resolver)
            .unwrap_or_else(|error| panic!("semantic baseline failed: {error}"));
        assert!(baseline.resolved_closure().cards()[0].has_ports());
        assert!(baseline.resolved_closure().cards()[0].has_refinement());
        assert_eq!(baseline.resolved_closure().delivery_profiles().len(), 2);
        assert_eq!(baseline.resolved_closure().requirements().len(), 2);

        let assert_changed = |name: &str, spec: &DeckSpec, resolver: &DeckResolverSnapshot| {
            let changed = compile_snapshot(spec, resolver)
                .unwrap_or_else(|error| panic!("{name} mutation failed validation: {error}"));
            assert_ne!(baseline.digest(), changed.digest(), "{name}");
            assert_ne!(
                baseline.canonical_bytes(),
                changed.canonical_bytes(),
                "{name}"
            );
        };

        let mut role = base_spec.clone();
        role.cards[0].role = DeckCardRole::General;
        assert_changed("role", &role, &base_resolver);

        let mut requested_version = base_spec.clone();
        requested_version.cards[0].requested_version = CardDefinitionVersionRequirement::exact(1);
        assert_changed(
            "requested definition version",
            &requested_version,
            &base_resolver,
        );

        let mut resolved_version = base_resolver.clone();
        resolved_version.definitions[0].version = 2;
        assert_changed("resolved definition version", &base_spec, &resolved_version);

        let mut refinement_payload = base_resolver.clone();
        refinement_payload.definitions[0].refinements[0].payload_digest = digest(0x72);
        assert_changed(
            "refinement payload commitment",
            &base_spec,
            &refinement_payload,
        );

        let mut refinement_ref_spec = base_spec.clone();
        let mut refinement_ref_resolver = base_resolver.clone();
        refinement_ref_spec.cards[0].refinement = Some(CardRefinementRequest::new(key(
            0x73,
            CardRefinementRef::from_bytes,
        )));
        refinement_ref_resolver.definitions[0].refinements[0].reference =
            key(0x73, CardRefinementRef::from_bytes);
        assert_changed(
            "refinement reference",
            &refinement_ref_spec,
            &refinement_ref_resolver,
        );

        let mut resolved_port = base_resolver.clone();
        for definition in &mut resolved_port.definitions {
            for port in &mut definition.ports {
                let old = port.spec;
                port.spec = PortSpec::new(
                    old.direction(),
                    schema(8),
                    old.interaction(),
                    old.cardinality(),
                );
            }
        }
        assert_changed("resolved Port", &base_spec, &resolved_port);

        let mut link_key = base_spec.clone();
        link_key.links[0].key = key(9, DeckLinkKey::from_bytes);
        assert_changed("Link", &link_key, &base_resolver);

        let mut delivery_payload = base_resolver.clone();
        delivery_payload.delivery_profiles[0].payload_digest = digest(0xd4);
        assert_changed(
            "DeliveryProfile payload commitment",
            &base_spec,
            &delivery_payload,
        );

        let mut delivery_ref_spec = base_spec.clone();
        let mut delivery_ref_resolver = base_resolver.clone();
        delivery_ref_spec.links[0].delivery_profile =
            Some(key(0xd4, DeliveryProfileRef::from_bytes));
        delivery_ref_resolver.delivery_profiles[0].reference =
            key(0xd4, DeliveryProfileRef::from_bytes);
        assert_changed(
            "DeliveryProfile reference",
            &delivery_ref_spec,
            &delivery_ref_resolver,
        );

        let mut requirement_payload = base_resolver.clone();
        requirement_payload.requirements[0].payload_digest = digest(0xf2);
        assert_changed(
            "Requirement payload commitment",
            &base_spec,
            &requirement_payload,
        );

        let mut requirement_ref_spec = base_spec.clone();
        let mut requirement_ref_resolver = base_resolver.clone();
        requirement_ref_spec.requirements[0].reference = key(0xe5, RequirementRef::from_bytes);
        requirement_ref_resolver.requirements[0].reference = key(0xe5, RequirementRef::from_bytes);
        assert_changed(
            "Requirement reference",
            &requirement_ref_spec,
            &requirement_ref_resolver,
        );
    }

    #[test]
    fn semantic_partition_permutations_keep_canonical_bytes_stable() {
        let (spec, resolver) = semantic_fixture();
        let baseline = compile_snapshot(&spec, &resolver)
            .unwrap_or_else(|error| panic!("semantic baseline failed: {error}"));
        let mut permuted_spec = spec.clone();
        permuted_spec.cards.reverse();
        permuted_spec.links.reverse();
        permuted_spec.requirements.reverse();
        permuted_spec.display.reverse();
        let mut permuted_resolver = resolver.clone();
        permuted_resolver.definitions.reverse();
        permuted_resolver.delivery_profiles.reverse();
        permuted_resolver.requirements.reverse();
        for definition in &mut permuted_resolver.definitions {
            definition.ports.reverse();
            definition.refinements.reverse();
        }

        let permuted = compile_snapshot(&permuted_spec, &permuted_resolver)
            .unwrap_or_else(|error| panic!("semantic permutation failed: {error}"));
        assert_eq!(baseline.canonical_bytes(), permuted.canonical_bytes());
        assert_eq!(baseline.digest(), permuted.digest());
    }

    #[test]
    fn version_and_refinement_rejections_have_stable_taxonomy() {
        let mut zero_minimum = spec(vec![card(1, 10)], Vec::new());
        zero_minimum.cards[0].requested_version = CardDefinitionVersionRequirement::inclusive(0, 1);

        let mut inverted_range = spec(vec![card(1, 10)], Vec::new());
        inverted_range.cards[0].requested_version =
            CardDefinitionVersionRequirement::inclusive(2, 1);

        let below_range = spec(
            vec![card(1, 10).with_requested_version(CardDefinitionVersionRequirement::exact(2))],
            Vec::new(),
        );

        let above_range = spec(
            vec![card(1, 10).with_requested_version(CardDefinitionVersionRequirement::exact(1))],
            Vec::new(),
        );
        let mut version_two = definition(10, Vec::new());
        version_two.version = 2;

        let missing_refinement = key(0x70, CardRefinementRef::from_bytes);
        let missing_refinement_deck = spec(
            vec![card(1, 10).with_refinement(CardRefinementRequest::new(missing_refinement))],
            Vec::new(),
        );

        let duplicate_refinement = ResolvedCardRefinementCommitment::new(
            key(0x71, CardRefinementRef::from_bytes),
            digest(0x72),
        );

        assert_rejection_cases(vec![
            RejectionCase {
                name: "zero requested-version minimum",
                spec: zero_minimum,
                resolver: DeckResolverSnapshot::new(vec![definition(10, Vec::new())]),
                expected: DeckCompileError::InvalidRequestedDefinitionVersion(key(
                    1,
                    CardUseKey::from_bytes,
                )),
            },
            RejectionCase {
                name: "inverted requested-version range",
                spec: inverted_range,
                resolver: DeckResolverSnapshot::new(vec![definition(10, Vec::new())]),
                expected: DeckCompileError::InvalidRequestedDefinitionVersion(key(
                    1,
                    CardUseKey::from_bytes,
                )),
            },
            RejectionCase {
                name: "resolved definition below requested range",
                spec: below_range,
                resolver: DeckResolverSnapshot::new(vec![definition(10, Vec::new())]),
                expected: DeckCompileError::ResolvedDefinitionVersionMismatch(key(
                    1,
                    CardUseKey::from_bytes,
                )),
            },
            RejectionCase {
                name: "resolved definition above requested range",
                spec: above_range,
                resolver: DeckResolverSnapshot::new(vec![version_two]),
                expected: DeckCompileError::ResolvedDefinitionVersionMismatch(key(
                    1,
                    CardUseKey::from_bytes,
                )),
            },
            RejectionCase {
                name: "missing resolved refinement",
                spec: missing_refinement_deck,
                resolver: DeckResolverSnapshot::new(vec![definition(10, Vec::new())]),
                expected: DeckCompileError::MissingResolvedRefinement {
                    card: key(1, CardUseKey::from_bytes),
                    refinement: missing_refinement,
                },
            },
            RejectionCase {
                name: "duplicate resolved refinement",
                spec: spec(vec![card(1, 10)], Vec::new()),
                resolver: DeckResolverSnapshot::new(vec![
                    definition(10, Vec::new())
                        .with_refinements(vec![duplicate_refinement, duplicate_refinement]),
                ]),
                expected: DeckCompileError::DuplicateResolvedRefinement {
                    definition: CardDefinitionRef::from_bytes([10; 16]),
                    refinement: duplicate_refinement.reference,
                },
            },
        ]);
    }

    #[test]
    fn requirement_and_delivery_resolution_rejections_have_stable_taxonomy() {
        let requirement_ref = key(0x90, RequirementRef::from_bytes);
        let mut duplicate_requirement_ref = spec(vec![card(1, 10)], Vec::new());
        duplicate_requirement_ref.requirements = vec![
            DeckRequirementSpec::new(key(1, RequirementKey::from_bytes), requirement_ref),
            DeckRequirementSpec::new(key(2, RequirementKey::from_bytes), requirement_ref),
        ];

        let mut missing_requirement = spec(vec![card(1, 10)], Vec::new());
        missing_requirement.requirements = vec![DeckRequirementSpec::new(
            key(1, RequirementKey::from_bytes),
            requirement_ref,
        )];
        let duplicate_requirement_payload =
            ResolvedRequirementCommitment::new(requirement_ref, digest(0x91));

        let link_without_profile = DeckLinkSpec::new(
            key(1, DeckLinkKey::from_bytes),
            endpoint(1, 1),
            endpoint(2, 2),
        );
        let linked_definitions = || {
            vec![
                definition(
                    10,
                    vec![port(1, PortDirection::Out, 7, InteractionKind::Signal)],
                ),
                definition(
                    20,
                    vec![port(2, PortDirection::In, 7, InteractionKind::Signal)],
                ),
            ]
        };
        let default_profile = default_delivery_profile();

        assert_rejection_cases(vec![
            RejectionCase {
                name: "duplicate topology RequirementRef",
                spec: duplicate_requirement_ref,
                resolver: DeckResolverSnapshot::new(vec![definition(10, Vec::new())])
                    .with_requirements(vec![duplicate_requirement_payload]),
                expected: DeckCompileError::DuplicateRequirementRef(requirement_ref),
            },
            RejectionCase {
                name: "missing resolved Requirement payload",
                spec: missing_requirement.clone(),
                resolver: DeckResolverSnapshot::new(vec![definition(10, Vec::new())]),
                expected: DeckCompileError::MissingResolvedRequirement(requirement_ref),
            },
            RejectionCase {
                name: "duplicate resolved Requirement payload",
                spec: missing_requirement,
                resolver: DeckResolverSnapshot::new(vec![definition(10, Vec::new())])
                    .with_requirements(vec![
                        duplicate_requirement_payload,
                        duplicate_requirement_payload,
                    ]),
                expected: DeckCompileError::DuplicateResolvedRequirement(requirement_ref),
            },
            RejectionCase {
                name: "missing DeliveryProfile reference",
                spec: spec(vec![card(1, 10), card(2, 20)], vec![link_without_profile]),
                resolver: DeckResolverSnapshot::new(linked_definitions())
                    .with_delivery_profiles(vec![default_profile]),
                expected: DeckCompileError::MissingDeliveryProfileRef(key(
                    1,
                    DeckLinkKey::from_bytes,
                )),
            },
            RejectionCase {
                name: "missing resolved DeliveryProfile payload",
                spec: spec(vec![card(1, 10), card(2, 20)], vec![link(1, 1, 1, 2, 2)]),
                resolver: DeckResolverSnapshot::new(linked_definitions()),
                expected: DeckCompileError::MissingResolvedDeliveryProfile(
                    default_profile.reference,
                ),
            },
            RejectionCase {
                name: "duplicate resolved DeliveryProfile payload",
                spec: spec(vec![card(1, 10), card(2, 20)], vec![link(1, 1, 1, 2, 2)]),
                resolver: DeckResolverSnapshot::new(linked_definitions())
                    .with_delivery_profiles(vec![default_profile, default_profile]),
                expected: DeckCompileError::DuplicateResolvedDeliveryProfile(
                    default_profile.reference,
                ),
            },
        ]);
    }

    #[test]
    fn dangling_endpoint_rejections_cover_source_and_target_variants() {
        let delivery = vec![default_delivery_profile()];
        assert_rejection_cases(vec![
            RejectionCase {
                name: "dangling source Card",
                spec: spec(vec![card(1, 10)], vec![link(1, 9, 1, 1, 2)]),
                resolver: DeckResolverSnapshot::new(vec![definition(
                    10,
                    vec![port(2, PortDirection::In, 7, InteractionKind::Signal)],
                )])
                .with_delivery_profiles(delivery.clone()),
                expected: DeckCompileError::DanglingSourceCard {
                    link: key(1, DeckLinkKey::from_bytes),
                    card: key(9, CardUseKey::from_bytes),
                },
            },
            RejectionCase {
                name: "dangling target Card",
                spec: spec(vec![card(1, 10)], vec![link(1, 1, 1, 9, 2)]),
                resolver: DeckResolverSnapshot::new(vec![definition(
                    10,
                    vec![port(1, PortDirection::Out, 7, InteractionKind::Signal)],
                )])
                .with_delivery_profiles(delivery.clone()),
                expected: DeckCompileError::DanglingTargetCard {
                    link: key(1, DeckLinkKey::from_bytes),
                    card: key(9, CardUseKey::from_bytes),
                },
            },
            RejectionCase {
                name: "dangling source Port",
                spec: spec(vec![card(1, 10), card(2, 20)], vec![link(1, 1, 1, 2, 2)]),
                resolver: DeckResolverSnapshot::new(vec![
                    definition(
                        10,
                        vec![port(3, PortDirection::Out, 7, InteractionKind::Signal)],
                    ),
                    definition(
                        20,
                        vec![port(2, PortDirection::In, 7, InteractionKind::Signal)],
                    ),
                ])
                .with_delivery_profiles(delivery.clone()),
                expected: DeckCompileError::DanglingSourcePort {
                    link: key(1, DeckLinkKey::from_bytes),
                    port: key(1, DeckPortKey::from_bytes),
                },
            },
            RejectionCase {
                name: "dangling target Port",
                spec: spec(vec![card(1, 10), card(2, 20)], vec![link(1, 1, 1, 2, 2)]),
                resolver: DeckResolverSnapshot::new(vec![
                    definition(
                        10,
                        vec![port(1, PortDirection::Out, 7, InteractionKind::Signal)],
                    ),
                    definition(
                        20,
                        vec![port(3, PortDirection::In, 7, InteractionKind::Signal)],
                    ),
                ])
                .with_delivery_profiles(delivery),
                expected: DeckCompileError::DanglingTargetPort {
                    link: key(1, DeckLinkKey::from_bytes),
                    port: key(2, DeckPortKey::from_bytes),
                },
            },
        ]);
    }

    #[test]
    fn every_low_cost_count_bound_accepts_exact_and_rejects_plus_one() {
        type Fixture = fn(usize) -> (DeckSpec, DeckResolverSnapshot);
        struct CountBoundaryCase {
            name: &'static str,
            maximum: usize,
            fixture: Fixture,
            overflow: DeckCompileError,
        }

        let cases = [
            CountBoundaryCase {
                name: "Deck Cards",
                maximum: MAX_DECK_CARDS,
                fixture: card_count_fixture,
                overflow: DeckCompileError::TooManyCards,
            },
            CountBoundaryCase {
                name: "Deck Links",
                maximum: MAX_DECK_LINKS,
                fixture: link_count_fixture,
                overflow: DeckCompileError::TooManyLinks,
            },
            CountBoundaryCase {
                name: "Deck Requirements",
                maximum: MAX_DECK_REQUIREMENTS,
                fixture: requirement_count_fixture,
                overflow: DeckCompileError::TooManyRequirements,
            },
            CountBoundaryCase {
                name: "resolver definitions",
                maximum: MAX_RESOLVER_DEFINITIONS,
                fixture: resolver_definition_count_fixture,
                overflow: DeckCompileError::TooManyResolverDefinitions,
            },
            CountBoundaryCase {
                name: "Ports per definition",
                maximum: MAX_PORTS_PER_DEFINITION,
                fixture: port_count_fixture,
                overflow: DeckCompileError::TooManyPorts(CardDefinitionRef::from_bytes([10; 16])),
            },
            CountBoundaryCase {
                name: "refinements per definition",
                maximum: MAX_REFINEMENTS_PER_DEFINITION,
                fixture: refinement_count_fixture,
                overflow: DeckCompileError::TooManyRefinements(CardDefinitionRef::from_bytes(
                    [10; 16],
                )),
            },
            CountBoundaryCase {
                name: "resolved DeliveryProfiles",
                maximum: MAX_RESOLVED_DELIVERY_PROFILES,
                fixture: delivery_profile_count_fixture,
                overflow: DeckCompileError::TooManyDeliveryProfiles,
            },
            CountBoundaryCase {
                name: "resolved Requirements",
                maximum: MAX_RESOLVED_REQUIREMENTS,
                fixture: resolved_requirement_count_fixture,
                overflow: DeckCompileError::TooManyResolvedRequirements,
            },
            CountBoundaryCase {
                name: "display entries",
                maximum: MAX_DISPLAY_ENTRIES,
                fixture: display_count_fixture,
                overflow: DeckCompileError::TooManyDisplayEntries,
            },
        ];

        for case in cases {
            let (exact_spec, exact_resolver) = (case.fixture)(case.maximum);
            compile_snapshot(&exact_spec, &exact_resolver)
                .unwrap_or_else(|error| panic!("{} exact bound failed: {error}", case.name));

            let (overflow_spec, overflow_resolver) = (case.fixture)(case.maximum + 1);
            let actual = match compile_snapshot(&overflow_spec, &overflow_resolver) {
                Ok(_) => panic!("{} plus-one bound unexpectedly compiled", case.name),
                Err(error) => error,
            };
            assert_eq!(actual, case.overflow, "{} plus-one bound", case.name);
        }
    }

    #[test]
    fn display_label_byte_bound_accepts_exact_and_rejects_plus_one() {
        let mut exact = spec(vec![card(1, 10)], Vec::new());
        exact.display = vec![DeckDisplayMetadata::new(
            &"x".repeat(MAX_DISPLAY_LABEL_BYTES),
            0,
            0,
        )];
        compile(&exact, vec![definition(10, Vec::new())])
            .unwrap_or_else(|error| panic!("exact display-label byte bound failed: {error}"));

        let mut overflow = exact;
        overflow.display = vec![DeckDisplayMetadata::new(
            &"x".repeat(MAX_DISPLAY_LABEL_BYTES + 1),
            0,
            0,
        )];
        assert_eq!(
            compile(&overflow, vec![definition(10, Vec::new())]),
            Err(DeckCompileError::DisplayLabelTooLong)
        );
    }

    #[test]
    fn ownership_then_lifetime_then_structure_define_error_precedence() {
        let mut invalid = spec(Vec::new(), Vec::new());
        invalid.ownership = DeckOwnershipRequest::Application;
        invalid.lifetime = DeckLifetimeRequest::Installation;
        assert_eq!(
            compile(&invalid, Vec::new()),
            Err(DeckCompileError::ApplicationOwnershipUnsupported)
        );

        invalid.ownership = DeckOwnershipRequest::Deck;
        assert_eq!(
            compile(&invalid, Vec::new()),
            Err(DeckCompileError::InstallationLifetimeUnsupported)
        );

        invalid.lifetime = DeckLifetimeRequest::Deck;
        assert_eq!(
            compile(&invalid, Vec::new()),
            Err(DeckCompileError::EmptyDeck)
        );
    }

    #[test]
    fn bounded_inputs_reject_before_sorting_or_canonical_allocation() {
        let oversized_cards = DeckSpec::new(
            key(1, DeckKey::from_bytes),
            vec![card(1, 10); MAX_DECK_CARDS + 1],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DeckOwnershipRequest::Deck,
            DeckLifetimeRequest::Deck,
        );
        assert_eq!(
            compile_snapshot(&oversized_cards, &DeckResolverSnapshot::new(Vec::new())),
            Err(DeckCompileError::TooManyCards)
        );

        let mut oversized_display = spec(vec![card(1, 10)], Vec::new());
        oversized_display.display =
            vec![DeckDisplayMetadata::new("bounded", 0, 0); MAX_DISPLAY_ENTRIES + 1];
        assert_eq!(
            compile(&oversized_display, vec![definition(10, Vec::new())]),
            Err(DeckCompileError::TooManyDisplayEntries)
        );

        let repeated_port = port(1, PortDirection::Out, 7, InteractionKind::Signal);
        assert_eq!(
            compile(
                &spec(vec![card(1, 10)], Vec::new()),
                vec![definition(
                    10,
                    vec![repeated_port; MAX_PORTS_PER_DEFINITION + 1]
                )]
            ),
            Err(DeckCompileError::TooManyPorts(
                CardDefinitionRef::from_bytes([10; 16])
            ))
        );

        let resolver =
            DeckResolverSnapshot::new(vec![definition(10, Vec::new())]).with_delivery_profiles(
                vec![default_delivery_profile(); MAX_RESOLVED_DELIVERY_PROFILES + 1],
            );
        assert_eq!(
            compile_snapshot(&spec(vec![card(1, 10)], Vec::new()), &resolver),
            Err(DeckCompileError::TooManyDeliveryProfiles)
        );
    }

    #[test]
    fn duplicate_and_dangling_errors_are_sorted_not_declaration_ordered() {
        let cards = vec![card(3, 30), card(2, 20), card(3, 10), card(2, 10)];
        assert_eq!(
            compile(&spec(cards, Vec::new()), Vec::new()),
            Err(DeckCompileError::DuplicateCardUse(key(
                2,
                CardUseKey::from_bytes
            )))
        );

        let dangling = spec(
            vec![card(1, 10)],
            vec![link(9, 8, 1, 1, 2), link(3, 7, 1, 1, 2)],
        );
        assert_eq!(
            compile(&dangling, vec![definition(10, Vec::new())]),
            Err(DeckCompileError::DanglingSourceCard {
                link: key(3, DeckLinkKey::from_bytes),
                card: key(7, CardUseKey::from_bytes),
            })
        );
    }

    #[test]
    fn resolver_and_topology_uniqueness_fail_before_endpoint_semantics() {
        let deck = spec(vec![card(1, 10)], Vec::new());
        let duplicate_definition = definition(10, Vec::new());
        assert_eq!(
            compile(
                &deck,
                vec![duplicate_definition.clone(), duplicate_definition]
            ),
            Err(DeckCompileError::DuplicateResolvedDefinition(
                CardDefinitionRef::from_bytes([10; 16])
            ))
        );

        let mut invalid_version = definition(10, Vec::new());
        invalid_version.version = 0;
        assert_eq!(
            compile(&deck, vec![invalid_version]),
            Err(DeckCompileError::InvalidDefinitionVersion(
                CardDefinitionRef::from_bytes([10; 16])
            ))
        );

        let duplicate_port = port(1, PortDirection::Out, 7, InteractionKind::Signal);
        assert_eq!(
            compile(
                &deck,
                vec![definition(10, vec![duplicate_port, duplicate_port])]
            ),
            Err(DeckCompileError::DuplicateResolvedPort {
                definition: CardDefinitionRef::from_bytes([10; 16]),
                port: key(1, DeckPortKey::from_bytes),
            })
        );

        assert_eq!(
            compile(&deck, Vec::new()),
            Err(DeckCompileError::MissingResolvedDefinition(
                CardDefinitionRef::from_bytes([10; 16])
            ))
        );

        let mut duplicate_requirement = deck.clone();
        duplicate_requirement.requirements = vec![
            requirement(9, 19),
            requirement(3, 13),
            requirement(9, 29),
            requirement(3, 23),
        ];
        assert_eq!(
            compile(&duplicate_requirement, vec![definition(10, Vec::new())]),
            Err(DeckCompileError::DuplicateRequirement(key(
                3,
                RequirementKey::from_bytes
            )))
        );

        let duplicate_link = link(5, 1, 1, 1, 1);
        assert_eq!(
            compile(
                &spec(vec![card(1, 10)], vec![duplicate_link, duplicate_link]),
                vec![definition(10, Vec::new())]
            ),
            Err(DeckCompileError::DuplicateLink(key(
                5,
                DeckLinkKey::from_bytes
            )))
        );
    }

    #[test]
    fn port_direction_schema_and_interaction_fail_in_fixed_order() {
        let deck = spec(vec![card(1, 10), card(2, 20)], vec![link(1, 1, 1, 2, 2)]);
        let invalid_direction = vec![
            definition(
                10,
                vec![port(1, PortDirection::In, 7, InteractionKind::Signal)],
            ),
            definition(
                20,
                vec![port(2, PortDirection::Out, 8, InteractionKind::Event)],
            ),
        ];
        assert_eq!(
            compile(&deck, invalid_direction),
            Err(DeckCompileError::SourcePortIsNotOutput(key(
                1,
                DeckLinkKey::from_bytes
            )))
        );

        let schema_mismatch = vec![
            definition(
                10,
                vec![port(1, PortDirection::Out, 7, InteractionKind::Signal)],
            ),
            definition(
                20,
                vec![port(2, PortDirection::In, 8, InteractionKind::Event)],
            ),
        ];
        assert_eq!(
            compile(&deck, schema_mismatch),
            Err(DeckCompileError::PortSchemaMismatch(key(
                1,
                DeckLinkKey::from_bytes
            )))
        );

        let interaction_mismatch = vec![
            definition(
                10,
                vec![port(1, PortDirection::Out, 7, InteractionKind::Signal)],
            ),
            definition(
                20,
                vec![port(2, PortDirection::In, 7, InteractionKind::Event)],
            ),
        ];
        assert_eq!(
            compile(&deck, interaction_mismatch),
            Err(DeckCompileError::PortInteractionMismatch(key(
                1,
                DeckLinkKey::from_bytes
            )))
        );
    }

    #[test]
    fn cyclic_deck_reports_stable_scc_and_concrete_witness() {
        let definitions = vec![
            definition(
                10,
                vec![
                    port(1, PortDirection::Out, 7, InteractionKind::Signal),
                    port(2, PortDirection::In, 7, InteractionKind::Signal),
                ],
            ),
            definition(
                20,
                vec![
                    port(3, PortDirection::Out, 7, InteractionKind::Signal),
                    port(4, PortDirection::In, 7, InteractionKind::Signal),
                ],
            ),
        ];
        let first = spec(
            vec![card(2, 20), card(1, 10)],
            vec![link(8, 2, 3, 1, 2), link(9, 1, 1, 2, 4)],
        );
        let second = spec(
            vec![card(1, 10), card(2, 20)],
            vec![link(9, 1, 1, 2, 4), link(8, 2, 3, 1, 2)],
        );
        let first_error = compile(&first, definitions.clone())
            .expect_err("cyclic Deck must fail before a lock exists");
        let second_error =
            compile(&second, definitions).expect_err("permuted cyclic Deck must fail");
        assert_eq!(first_error, second_error);

        let DeckCompileError::CyclicDeck(witness) = first_error else {
            panic!("expected cyclic Deck error");
        };
        assert_eq!(
            witness.component(),
            &[
                key(1, CardUseKey::from_bytes),
                key(2, CardUseKey::from_bytes)
            ]
        );
        assert_eq!(witness.cards().first(), witness.cards().last());
        assert_eq!(witness.links().len() + 1, witness.cards().len());
    }

    #[test]
    fn self_loop_reports_single_card_scc_before_lock_creation() {
        let deck = spec(vec![card(1, 10)], vec![link(4, 1, 1, 1, 2)]);
        let definitions = vec![definition(
            10,
            vec![
                port(1, PortDirection::Out, 7, InteractionKind::Event),
                port(2, PortDirection::In, 7, InteractionKind::Event),
            ],
        )];
        let DeckCompileError::CyclicDeck(witness) =
            compile(&deck, definitions).expect_err("self-loop must fail closed")
        else {
            panic!("expected cyclic Deck error");
        };
        assert_eq!(witness.component(), &[key(1, CardUseKey::from_bytes)]);
        assert_eq!(
            witness.cards(),
            &[
                key(1, CardUseKey::from_bytes),
                key(1, CardUseKey::from_bytes)
            ]
        );
        assert_eq!(witness.links(), &[key(4, DeckLinkKey::from_bytes)]);
    }
}
