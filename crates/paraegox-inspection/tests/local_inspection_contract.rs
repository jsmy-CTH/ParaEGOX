use paraegox_inspection::{
    InspectionContractError, InspectionFeatureSupportV1, InspectionFreshnessV1, InspectionHealthV1,
    InspectionLivenessV1, InspectionObservationClockRefV1, InspectionReadinessV1,
    InspectionReasonV1, InspectionSourceAvailabilityV1, InspectionSourceCoordinateV1,
    InspectionSourceOwnerV1, InspectionSourceSlotV1, LOCAL_INSPECTION_SNAPSHOT_BYTES,
    LOCAL_INSPECTION_SNAPSHOT_V2_BYTES, LocalInspectionOverallV1, LocalInspectionProjectionInputV1,
    LocalInspectionProjectionInputV2, LocalInspectionServiceV1, LocalInspectionServiceV2,
    LocalInspectionSnapshotV1, LocalInspectionSnapshotV2, NodeInspectionFactFieldsV2,
    NodeInspectionFactV2, NodeInspectionSourceSlotV2, OwnerInspectionFactFieldsV1,
    OwnerInspectionFactV1, project_local_inspection_snapshot_v1,
    project_local_inspection_snapshot_v2,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder};

const PROJECTION_ID: [u8; 16] = [0xa1; 16];
const CLOCK_BYTES: [u8; 16] = [0xc1; 16];
const CROSS_LANGUAGE_PROJECTION_ID: [u8; 16] = [0x21; 16];
const CROSS_LANGUAGE_CLOCK_BYTES: [u8; 16] = [0x31; 16];
const PROJECTED_AT: u64 = 150;
const SNAPSHOT_HEADER_BYTES: usize = 112;
const SNAPSHOT_DIGEST_OFFSET: usize = 80;
const RECORD_BYTES: usize = 96;
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.local-snapshot.v1";

#[derive(Clone, Copy)]
struct FactState {
    availability: InspectionSourceAvailabilityV1,
    liveness: InspectionLivenessV1,
    readiness: InspectionReadinessV1,
    health: InspectionHealthV1,
    feature_support: InspectionFeatureSupportV1,
    reason: InspectionReasonV1,
    observed_at: u64,
    valid_until: u64,
}

impl FactState {
    const fn ready() -> Self {
        Self {
            availability: InspectionSourceAvailabilityV1::Observed,
            liveness: InspectionLivenessV1::Live,
            readiness: InspectionReadinessV1::Ready,
            health: InspectionHealthV1::Healthy,
            feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
            reason: InspectionReasonV1::None,
            observed_at: 100,
            valid_until: 200,
        }
    }
}

fn clock() -> InspectionObservationClockRefV1 {
    InspectionObservationClockRefV1::try_from_bytes(CLOCK_BYTES).expect("test clock")
}

fn subject(owner: InspectionSourceOwnerV1) -> [u8; 16] {
    [owner as u8 + 0x10; 16]
}

fn coordinate(owner: InspectionSourceOwnerV1) -> InspectionSourceCoordinateV1 {
    match owner {
        InspectionSourceOwnerV1::Authority => InspectionSourceCoordinateV1::AuthorityTenure {
            tenure_epoch: 11,
            fact_sequence: 21,
        },
        InspectionSourceOwnerV1::DeploymentController => {
            InspectionSourceCoordinateV1::DeploymentRevision {
                revision: 12,
                fact_sequence: 22,
            }
        }
        InspectionSourceOwnerV1::RuntimeHost => InspectionSourceCoordinateV1::RuntimeHostEpoch {
            runtime_host_epoch: 13,
            snapshot_sequence: 23,
        },
        InspectionSourceOwnerV1::FabricService => {
            InspectionSourceCoordinateV1::FabricServiceGeneration {
                service_generation: 14,
                observation_sequence: 24,
            }
        }
        InspectionSourceOwnerV1::AgentService => {
            InspectionSourceCoordinateV1::AgentServiceGeneration {
                service_generation: 15,
                observation_sequence: 25,
            }
        }
    }
}

fn fact(owner: InspectionSourceOwnerV1, state: FactState) -> OwnerInspectionFactV1 {
    OwnerInspectionFactV1::try_new(OwnerInspectionFactFieldsV1 {
        owner,
        subject_ref: subject(owner),
        coordinate: coordinate(owner),
        observation_clock_ref: clock(),
        observed_at_nanos: state.observed_at,
        valid_until_nanos: state.valid_until,
        availability: state.availability,
        liveness: state.liveness,
        readiness: state.readiness,
        health: state.health,
        feature_support: state.feature_support,
        reason: state.reason,
        owner_fact_digest: Digest32::from_bytes([owner as u8 + 0x50; 32]),
    })
    .expect("valid owner fact")
}

fn slot(
    owner: InspectionSourceOwnerV1,
    owner_fact: Option<OwnerInspectionFactV1>,
) -> InspectionSourceSlotV1 {
    InspectionSourceSlotV1::try_new(owner, subject(owner), owner_fact).expect("valid owner slot")
}

fn ready_slots() -> [InspectionSourceSlotV1; 5] {
    [
        slot(
            InspectionSourceOwnerV1::Authority,
            Some(fact(InspectionSourceOwnerV1::Authority, FactState::ready())),
        ),
        slot(
            InspectionSourceOwnerV1::DeploymentController,
            Some(fact(
                InspectionSourceOwnerV1::DeploymentController,
                FactState::ready(),
            )),
        ),
        slot(
            InspectionSourceOwnerV1::RuntimeHost,
            Some(fact(
                InspectionSourceOwnerV1::RuntimeHost,
                FactState::ready(),
            )),
        ),
        slot(
            InspectionSourceOwnerV1::FabricService,
            Some(fact(
                InspectionSourceOwnerV1::FabricService,
                FactState::ready(),
            )),
        ),
        slot(
            InspectionSourceOwnerV1::AgentService,
            Some(fact(
                InspectionSourceOwnerV1::AgentService,
                FactState::ready(),
            )),
        ),
    ]
}

fn input_from_slots(slots: [InspectionSourceSlotV1; 5]) -> LocalInspectionProjectionInputV1 {
    LocalInspectionProjectionInputV1::try_new(clock(), slots).expect("valid projection input")
}

fn ready_input() -> LocalInspectionProjectionInputV1 {
    input_from_slots(ready_slots())
}

fn node_fact(state: FactState) -> NodeInspectionFactV2 {
    NodeInspectionFactV2::try_new(NodeInspectionFactFieldsV2 {
        node_ref: [0x61; 16],
        node_incarnation_ref: [0x62; 16],
        registration_epoch: 31,
        status_sequence: 41,
        observation_clock_ref: clock(),
        observed_at_nanos: state.observed_at,
        valid_until_nanos: state.valid_until,
        availability: state.availability,
        liveness: state.liveness,
        readiness: state.readiness,
        health: state.health,
        feature_support: state.feature_support,
        reason: state.reason,
        node_status_digest: Digest32::from_bytes([0x63; 32]),
    })
    .expect("valid NodeDaemon fact")
}

fn input_v2(
    base: LocalInspectionProjectionInputV1,
    node_fact: Option<NodeInspectionFactV2>,
) -> LocalInspectionProjectionInputV2 {
    let node = NodeInspectionSourceSlotV2::try_new([0x61; 16], [0x62; 16], node_fact)
        .expect("valid NodeDaemon slot");
    LocalInspectionProjectionInputV2::try_new(base, node).expect("valid v2 projection input")
}

fn ready_input_v2() -> LocalInspectionProjectionInputV2 {
    input_v2(ready_input(), Some(node_fact(FactState::ready())))
}

fn cross_language_clock() -> InspectionObservationClockRefV1 {
    InspectionObservationClockRefV1::try_from_bytes(CROSS_LANGUAGE_CLOCK_BYTES)
        .expect("cross-language clock")
}

fn cross_language_input_v2() -> LocalInspectionProjectionInputV2 {
    let base = LocalInspectionProjectionInputV1::try_new(
        cross_language_clock(),
        [
            InspectionSourceSlotV1::try_new(InspectionSourceOwnerV1::Authority, [0x41; 16], None)
                .expect("missing Authority slot"),
            InspectionSourceSlotV1::try_new(
                InspectionSourceOwnerV1::DeploymentController,
                [0x42; 16],
                None,
            )
            .expect("missing DeploymentController slot"),
            InspectionSourceSlotV1::try_new(InspectionSourceOwnerV1::RuntimeHost, [0x43; 16], None)
                .expect("missing RuntimeHost slot"),
            InspectionSourceSlotV1::try_new(
                InspectionSourceOwnerV1::FabricService,
                [0x44; 16],
                None,
            )
            .expect("missing FabricService slot"),
            InspectionSourceSlotV1::try_new(
                InspectionSourceOwnerV1::AgentService,
                [0x45; 16],
                None,
            )
            .expect("missing AgentService slot"),
        ],
    )
    .expect("cross-language base input");
    let node_fact = NodeInspectionFactV2::try_new(NodeInspectionFactFieldsV2 {
        node_ref: [0x61; 16],
        node_incarnation_ref: [0x62; 16],
        registration_epoch: 31,
        status_sequence: 41,
        observation_clock_ref: cross_language_clock(),
        observed_at_nanos: 100,
        valid_until_nanos: 200,
        availability: InspectionSourceAvailabilityV1::Observed,
        liveness: InspectionLivenessV1::Live,
        readiness: InspectionReadinessV1::Ready,
        health: InspectionHealthV1::Healthy,
        feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
        reason: InspectionReasonV1::None,
        node_status_digest: Digest32::from_bytes([0x63; 32]),
    })
    .expect("cross-language NodeDaemon fact");
    let node = NodeInspectionSourceSlotV2::try_new([0x61; 16], [0x62; 16], Some(node_fact))
        .expect("cross-language NodeDaemon slot");
    LocalInspectionProjectionInputV2::try_new(base, node).expect("cross-language v2 input")
}

fn project(input: &LocalInspectionProjectionInputV1) -> LocalInspectionSnapshotV1 {
    project_at(input, PROJECTED_AT)
}

fn project_at(
    input: &LocalInspectionProjectionInputV1,
    projected_at: u64,
) -> LocalInspectionSnapshotV1 {
    project_local_inspection_snapshot_v1(PROJECTION_ID, clock(), 1, projected_at, input)
        .expect("valid local projection")
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim();
    assert_eq!(value.len() % 2, 0, "golden hex length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid golden hex"),
    }
}

fn resign(frame: &mut [u8]) {
    let mut builder = Digest32Builder::try_new(SNAPSHOT_DIGEST_DOMAIN).expect("digest domain");
    builder
        .field_bytes(&frame[..SNAPSHOT_DIGEST_OFFSET])
        .expect("header field")
        .field_bytes(&frame[SNAPSHOT_HEADER_BYTES..])
        .expect("payload field");
    frame[SNAPSHOT_DIGEST_OFFSET..SNAPSHOT_HEADER_BYTES]
        .copy_from_slice(builder.finish().as_bytes());
}

#[test]
fn exact_ready_snapshot_matches_golden_and_strictly_roundtrips() {
    let snapshot = project(&ready_input());
    assert_eq!(snapshot.overall(), LocalInspectionOverallV1::Ready);
    assert_eq!(
        snapshot.canonical_wire().len(),
        LOCAL_INSPECTION_SNAPSHOT_BYTES
    );

    let expected_hex = include_str!("fixtures/local_inspection_snapshot_v1.hex").trim();
    if expected_hex == "PENDING" {
        panic!("PXIS_GOLDEN={}", encode_hex(snapshot.canonical_wire()));
    }
    let expected = decode_hex(expected_hex);
    assert_eq!(snapshot.canonical_wire(), expected);

    let decoded = LocalInspectionSnapshotV1::decode(&expected).expect("strict decode");
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.canonical_wire(), expected);
}

#[test]
fn projection_is_pure_and_does_not_mutate_input() {
    let input = ready_input();
    let before = input.clone();
    let first = project(&input);
    let second = project(&input);

    assert_eq!(input, before);
    assert_eq!(first.canonical_wire(), second.canonical_wire());
    assert_eq!(first.projection_digest(), second.projection_digest());
}

#[test]
fn timeout_is_stale_never_partitioned_and_masks_old_fault() {
    let mut slots = ready_slots();
    let stale_fault = FactState {
        liveness: InspectionLivenessV1::Exited,
        readiness: InspectionReadinessV1::NotReady,
        health: InspectionHealthV1::Faulted,
        feature_support: InspectionFeatureSupportV1::RequiredUnsupported,
        reason: InspectionReasonV1::OwnerReportedFailure,
        valid_until: 149,
        ..FactState::ready()
    };
    slots[0] = slot(
        InspectionSourceOwnerV1::Authority,
        Some(fact(InspectionSourceOwnerV1::Authority, stale_fault)),
    );
    let snapshot = project(&input_from_slots(slots));
    let record = snapshot.records()[0];

    assert_eq!(record.freshness(), InspectionFreshnessV1::Stale);
    assert_eq!(record.liveness(), InspectionLivenessV1::Unknown);
    assert_eq!(record.readiness(), InspectionReadinessV1::Unknown);
    assert_eq!(record.health(), InspectionHealthV1::Unknown);
    assert_eq!(
        record.feature_support(),
        InspectionFeatureSupportV1::Unknown
    );
    assert_eq!(record.reason(), InspectionReasonV1::SourceStale);
    assert_eq!(snapshot.overall(), LocalInspectionOverallV1::Unknown);
}

#[test]
fn only_explicit_partition_projects_partitioned_and_masks_old_fault() {
    let mut slots = ready_slots();
    let partitioned_fault = FactState {
        availability: InspectionSourceAvailabilityV1::Partitioned,
        liveness: InspectionLivenessV1::Exited,
        readiness: InspectionReadinessV1::NotReady,
        health: InspectionHealthV1::Faulted,
        feature_support: InspectionFeatureSupportV1::RequiredUnsupported,
        reason: InspectionReasonV1::OwnerReportedFailure,
        valid_until: 300,
        ..FactState::ready()
    };
    slots[3] = slot(
        InspectionSourceOwnerV1::FabricService,
        Some(fact(
            InspectionSourceOwnerV1::FabricService,
            partitioned_fault,
        )),
    );
    let snapshot = project(&input_from_slots(slots));
    let record = snapshot.records()[3];

    assert_eq!(record.freshness(), InspectionFreshnessV1::Partitioned);
    assert_eq!(record.liveness(), InspectionLivenessV1::Unknown);
    assert_eq!(record.readiness(), InspectionReadinessV1::Unknown);
    assert_eq!(record.health(), InspectionHealthV1::Unknown);
    assert_eq!(
        record.feature_support(),
        InspectionFeatureSupportV1::Unknown
    );
    assert_eq!(record.reason(), InspectionReasonV1::SourcePartitioned);
    assert_eq!(snapshot.overall(), LocalInspectionOverallV1::Unknown);
}

#[test]
fn projected_at_equal_to_valid_until_remains_fresh() {
    let mut slots = ready_slots();
    slots[4] = slot(
        InspectionSourceOwnerV1::AgentService,
        Some(fact(
            InspectionSourceOwnerV1::AgentService,
            FactState {
                valid_until: PROJECTED_AT,
                ..FactState::ready()
            },
        )),
    );
    let snapshot = project(&input_from_slots(slots));

    assert_eq!(
        snapshot.records()[4].freshness(),
        InspectionFreshnessV1::Fresh
    );
    assert_eq!(snapshot.overall(), LocalInspectionOverallV1::Ready);
}

#[test]
fn missing_or_owner_unknown_fact_cannot_report_ready() {
    let mut missing_slots = ready_slots();
    missing_slots[2] = slot(InspectionSourceOwnerV1::RuntimeHost, None);
    let missing = project(&input_from_slots(missing_slots));
    assert_eq!(
        missing.records()[2].freshness(),
        InspectionFreshnessV1::Missing
    );
    assert_eq!(missing.overall(), LocalInspectionOverallV1::Unknown);

    let mut unknown_slots = ready_slots();
    unknown_slots[1] = slot(
        InspectionSourceOwnerV1::DeploymentController,
        Some(fact(
            InspectionSourceOwnerV1::DeploymentController,
            FactState {
                liveness: InspectionLivenessV1::Unknown,
                readiness: InspectionReadinessV1::Unknown,
                health: InspectionHealthV1::Unknown,
                feature_support: InspectionFeatureSupportV1::Unknown,
                reason: InspectionReasonV1::SourceUnknown,
                ..FactState::ready()
            },
        )),
    );
    let unknown = project(&input_from_slots(unknown_slots));
    assert_eq!(
        unknown.records()[1].freshness(),
        InspectionFreshnessV1::Fresh
    );
    assert_eq!(unknown.overall(), LocalInspectionOverallV1::Unknown);
}

#[test]
fn ready_requires_live_healthy_and_required_feature_support() {
    let error = OwnerInspectionFactV1::try_new(OwnerInspectionFactFieldsV1 {
        owner: InspectionSourceOwnerV1::AgentService,
        subject_ref: subject(InspectionSourceOwnerV1::AgentService),
        coordinate: coordinate(InspectionSourceOwnerV1::AgentService),
        observation_clock_ref: clock(),
        observed_at_nanos: 100,
        valid_until_nanos: 200,
        availability: InspectionSourceAvailabilityV1::Observed,
        liveness: InspectionLivenessV1::Unresponsive,
        readiness: InspectionReadinessV1::Ready,
        health: InspectionHealthV1::Healthy,
        feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
        reason: InspectionReasonV1::OwnerReportedDegraded,
        owner_fact_digest: Digest32::from_bytes([0x77; 32]),
    })
    .expect_err("contradictory Ready fact");
    assert_eq!(error, InspectionContractError::InvalidOwnerState);
}

#[test]
fn owner_ready_receipt_can_preserve_unknown_health_without_claiming_overall_ready() {
    let mut slots = ready_slots();
    slots[4] = slot(
        InspectionSourceOwnerV1::AgentService,
        Some(fact(
            InspectionSourceOwnerV1::AgentService,
            FactState {
                liveness: InspectionLivenessV1::Unknown,
                health: InspectionHealthV1::Unknown,
                reason: InspectionReasonV1::SourceUnknown,
                ..FactState::ready()
            },
        )),
    );

    let snapshot = project(&input_from_slots(slots));
    let agent = snapshot.records()[4];
    assert_eq!(agent.freshness(), InspectionFreshnessV1::Fresh);
    assert_eq!(agent.liveness(), InspectionLivenessV1::Unknown);
    assert_eq!(agent.readiness(), InspectionReadinessV1::Ready);
    assert_eq!(agent.health(), InspectionHealthV1::Unknown);
    assert_eq!(agent.reason(), InspectionReasonV1::SourceUnknown);
    assert_eq!(snapshot.overall(), LocalInspectionOverallV1::Unknown);
}

#[test]
fn service_failure_preserves_revision_and_last_canonical_bytes() {
    let mut service = LocalInspectionServiceV1::try_new(PROJECTION_ID, clock()).expect("service");
    let input = ready_input();
    let first = service
        .project(PROJECTED_AT, &input)
        .expect("first projection");
    let before_revision = first.projection_revision();
    let before_bytes = first.canonical_wire().to_vec();

    let mut future_slots = ready_slots();
    future_slots[0] = slot(
        InspectionSourceOwnerV1::Authority,
        Some(fact(
            InspectionSourceOwnerV1::Authority,
            FactState {
                observed_at: PROJECTED_AT + 10,
                valid_until: PROJECTED_AT + 20,
                ..FactState::ready()
            },
        )),
    );
    let future_input = input_from_slots(future_slots);
    assert_eq!(
        service.project(PROJECTED_AT, &future_input),
        Err(InspectionContractError::ProjectionPrecedesObservation)
    );

    let after = service.snapshot().expect("last snapshot retained");
    assert_eq!(after.projection_revision(), before_revision);
    assert_eq!(after.canonical_wire(), before_bytes);

    let second = service
        .project(PROJECTED_AT, &input)
        .expect("successful successor");
    assert_eq!(second.projection_revision(), before_revision + 1);
}

#[test]
fn wrong_clock_and_regressed_service_time_fail_closed() {
    let input = ready_input();
    let wrong_clock = InspectionObservationClockRefV1::try_from_bytes([0xd1; 16]).expect("clock");
    assert_eq!(
        project_local_inspection_snapshot_v1(PROJECTION_ID, wrong_clock, 1, PROJECTED_AT, &input),
        Err(InspectionContractError::ObservationClockMismatch)
    );

    let mut service = LocalInspectionServiceV1::try_new(PROJECTION_ID, clock()).expect("service");
    service.project(PROJECTED_AT, &input).expect("first");
    assert_eq!(
        service.project(PROJECTED_AT - 1, &input),
        Err(InspectionContractError::ProjectionTimeRegressed)
    );
}

#[test]
fn strict_decoder_rejects_length_version_digest_reserved_and_aggregate_tampering() {
    let canonical = project(&ready_input()).canonical_wire().to_vec();

    assert_eq!(
        LocalInspectionSnapshotV1::decode(&canonical[..canonical.len() - 1]),
        Err(InspectionContractError::InvalidFrameLength)
    );

    let mut version = canonical.clone();
    version[5] = 2;
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&version),
        Err(InspectionContractError::UnsupportedFrame)
    );

    let mut digest = canonical.clone();
    digest[SNAPSHOT_DIGEST_OFFSET] ^= 1;
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&digest),
        Err(InspectionContractError::SnapshotDigestMismatch)
    );

    let mut reserved = canonical.clone();
    reserved[69] = 1;
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&reserved),
        Err(InspectionContractError::NonCanonicalEncoding)
    );

    let mut aggregate = canonical;
    aggregate[68] = LocalInspectionOverallV1::Unknown as u8;
    resign(&mut aggregate);
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&aggregate),
        Err(InspectionContractError::InvalidAggregateState)
    );
}

#[test]
fn strict_decoder_rejects_coordinate_kind_owner_order_and_record_reserved_tampering() {
    let canonical = project(&ready_input()).canonical_wire().to_vec();

    let mut coordinate_kind = canonical.clone();
    coordinate_kind[SNAPSHOT_HEADER_BYTES + 2] = InspectionSourceOwnerV1::RuntimeHost as u8;
    resign(&mut coordinate_kind);
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&coordinate_kind),
        Err(InspectionContractError::NonCanonicalEncoding)
    );

    let mut owner_order = canonical.clone();
    owner_order[SNAPSHOT_HEADER_BYTES] = InspectionSourceOwnerV1::RuntimeHost as u8;
    resign(&mut owner_order);
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&owner_order),
        Err(InspectionContractError::NonCanonicalOwnerOrder)
    );

    let mut record_reserved = canonical;
    record_reserved[SNAPSHOT_HEADER_BYTES + RECORD_BYTES - 1] = 1;
    resign(&mut record_reserved);
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&record_reserved),
        Err(InspectionContractError::NonCanonicalEncoding)
    );
}

#[test]
fn strict_decoder_rejects_unknown_enum_and_noncanonical_missing_payload() {
    let mut unknown_enum = project(&ready_input()).canonical_wire().to_vec();
    unknown_enum[SNAPSHOT_HEADER_BYTES + 3] = 0xff;
    resign(&mut unknown_enum);
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&unknown_enum),
        Err(InspectionContractError::UnknownEnumValue)
    );

    let mut slots = ready_slots();
    slots[0] = slot(InspectionSourceOwnerV1::Authority, None);
    let mut missing = project(&input_from_slots(slots)).canonical_wire().to_vec();
    missing[SNAPSHOT_HEADER_BYTES + 2] = InspectionSourceOwnerV1::Authority as u8;
    resign(&mut missing);
    assert_eq!(
        LocalInspectionSnapshotV1::decode(&missing),
        Err(InspectionContractError::NonCanonicalEncoding)
    );
}

#[test]
fn v2_preserves_the_exact_v1_snapshot_and_adds_only_the_node_projection() {
    let base_input = ready_input();
    let expected_base =
        project_local_inspection_snapshot_v1(PROJECTION_ID, clock(), 7, PROJECTED_AT, &base_input)
            .expect("v1 projection");
    let input = input_v2(base_input, Some(node_fact(FactState::ready())));
    let snapshot =
        project_local_inspection_snapshot_v2(PROJECTION_ID, clock(), 7, PROJECTED_AT, &input)
            .expect("v2 projection");

    assert_eq!(snapshot.overall(), LocalInspectionOverallV1::Ready);
    assert_eq!(
        snapshot.base_snapshot().canonical_wire(),
        expected_base.canonical_wire()
    );
    assert_eq!(
        snapshot.canonical_wire().len(),
        LOCAL_INSPECTION_SNAPSHOT_V2_BYTES
    );
    let node = snapshot.node();
    assert_eq!(node.node_ref(), [0x61; 16]);
    assert_eq!(node.node_incarnation_ref(), [0x62; 16]);
    assert_eq!(node.registration_epoch(), Some(31));
    assert_eq!(node.status_sequence(), Some(41));
    assert_eq!(
        node.node_status_digest(),
        Some(Digest32::from_bytes([0x63; 32]))
    );

    let decoded =
        LocalInspectionSnapshotV2::decode(snapshot.canonical_wire()).expect("strict v2 decode");
    assert_eq!(decoded, snapshot);
    assert!(LocalInspectionSnapshotV1::decode(snapshot.canonical_wire()).is_err());
}

#[test]
fn v2_cross_language_snapshot_matches_the_rust_canonical_golden() {
    let snapshot = project_local_inspection_snapshot_v2(
        CROSS_LANGUAGE_PROJECTION_ID,
        cross_language_clock(),
        7,
        PROJECTED_AT,
        &cross_language_input_v2(),
    )
    .expect("cross-language v2 projection");
    let expected_hex = include_str!("fixtures/local_inspection_snapshot_v2.hex").trim();
    if expected_hex == "PENDING" {
        panic!("PXIS_V2_GOLDEN={}", encode_hex(snapshot.canonical_wire()));
    }
    let expected = decode_hex(expected_hex);

    assert_eq!(snapshot.canonical_wire(), expected);
    assert_eq!(snapshot.projection_revision(), 7);
    assert_eq!(snapshot.overall(), LocalInspectionOverallV1::Unknown);
    assert_eq!(snapshot.node().registration_epoch(), Some(31));
    assert_eq!(snapshot.node().status_sequence(), Some(41));
    assert_eq!(
        LocalInspectionSnapshotV2::decode(&expected).expect("strict golden decode"),
        snapshot
    );
}

#[test]
fn v2_stale_node_masks_old_fault_while_current_node_fault_is_unavailable() {
    let stale_fault = FactState {
        liveness: InspectionLivenessV1::Exited,
        readiness: InspectionReadinessV1::NotReady,
        health: InspectionHealthV1::Faulted,
        feature_support: InspectionFeatureSupportV1::RequiredUnsupported,
        reason: InspectionReasonV1::OwnerReportedFailure,
        valid_until: PROJECTED_AT - 1,
        ..FactState::ready()
    };
    let stale = project_local_inspection_snapshot_v2(
        PROJECTION_ID,
        clock(),
        1,
        PROJECTED_AT,
        &input_v2(ready_input(), Some(node_fact(stale_fault))),
    )
    .expect("stale node projection");
    assert_eq!(stale.node().freshness(), InspectionFreshnessV1::Stale);
    assert_eq!(stale.node().liveness(), InspectionLivenessV1::Unknown);
    assert_eq!(stale.node().readiness(), InspectionReadinessV1::Unknown);
    assert_eq!(stale.node().health(), InspectionHealthV1::Unknown);
    assert_eq!(stale.node().reason(), InspectionReasonV1::SourceStale);
    assert_eq!(stale.overall(), LocalInspectionOverallV1::Unknown);

    let current_fault = FactState {
        liveness: InspectionLivenessV1::Exited,
        readiness: InspectionReadinessV1::NotReady,
        health: InspectionHealthV1::Faulted,
        feature_support: InspectionFeatureSupportV1::RequiredUnsupported,
        reason: InspectionReasonV1::OwnerReportedFailure,
        ..FactState::ready()
    };
    let unavailable = project_local_inspection_snapshot_v2(
        PROJECTION_ID,
        clock(),
        1,
        PROJECTED_AT,
        &input_v2(ready_input(), Some(node_fact(current_fault))),
    )
    .expect("current node fault projection");
    assert_eq!(unavailable.node().freshness(), InspectionFreshnessV1::Fresh);
    assert_eq!(unavailable.overall(), LocalInspectionOverallV1::Unavailable);
}

#[test]
fn v2_service_failure_preserves_revision_and_cached_bytes() {
    let mut service = LocalInspectionServiceV2::try_new(PROJECTION_ID, clock()).expect("service");
    let input = ready_input_v2();
    let first = service
        .project(PROJECTED_AT, &input)
        .expect("first projection");
    let before_revision = first.projection_revision();
    let before_bytes = first.canonical_wire().to_vec();

    assert_eq!(
        service.project(PROJECTED_AT - 1, &input),
        Err(InspectionContractError::ProjectionTimeRegressed)
    );
    let retained = service.snapshot().expect("cached projection");
    assert_eq!(retained.projection_revision(), before_revision);
    assert_eq!(retained.canonical_wire(), before_bytes);
}
