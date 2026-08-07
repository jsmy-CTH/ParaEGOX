use core::fmt;

use paraegox_inspection::adapter::{
    InspectionSourceAdapterReadErrorV1, InspectionSourceAdapterV1,
    LocalInspectionProjectionInputBuilderErrorV1, LocalInspectionProjectionInputBuilderV1,
    NodeInspectionSourceAdapterReadErrorV2, NodeInspectionSourceAdapterV2,
    read_inspection_source_slot_once_v1, read_node_inspection_source_slot_once_v2,
};
use paraegox_inspection::{
    InspectionContractError, InspectionFeatureSupportV1, InspectionFreshnessV1, InspectionHealthV1,
    InspectionLivenessV1, InspectionObservationClockRefV1, InspectionReadinessV1,
    InspectionReasonV1, InspectionSourceAvailabilityV1, InspectionSourceCoordinateV1,
    InspectionSourceOwnerV1, InspectionSourceSlotV1, LocalInspectionOverallV1,
    LocalInspectionServiceV1, NodeInspectionFactFieldsV2, NodeInspectionFactV2,
    OwnerInspectionFactFieldsV1, OwnerInspectionFactV1,
};
use paraegox_kernel::digest::Digest32;

const CLOCK_BYTES: [u8; 16] = [0xc1; 16];
const OTHER_CLOCK_BYTES: [u8; 16] = [0xc2; 16];
const PROJECTION_ID: [u8; 16] = [0xa1; 16];

fn clock() -> InspectionObservationClockRefV1 {
    InspectionObservationClockRefV1::try_from_bytes(CLOCK_BYTES).expect("clock")
}

fn other_clock() -> InspectionObservationClockRefV1 {
    InspectionObservationClockRefV1::try_from_bytes(OTHER_CLOCK_BYTES).expect("other clock")
}

fn subject(owner: InspectionSourceOwnerV1) -> [u8; 16] {
    [owner as u8 + 0x10; 16]
}

fn coordinate(owner: InspectionSourceOwnerV1) -> InspectionSourceCoordinateV1 {
    match owner {
        InspectionSourceOwnerV1::Authority => InspectionSourceCoordinateV1::AuthorityTenure {
            tenure_epoch: 1,
            fact_sequence: 1,
        },
        InspectionSourceOwnerV1::DeploymentController => {
            InspectionSourceCoordinateV1::DeploymentRevision {
                revision: 1,
                fact_sequence: 1,
            }
        }
        InspectionSourceOwnerV1::RuntimeHost => InspectionSourceCoordinateV1::RuntimeHostEpoch {
            runtime_host_epoch: 1,
            snapshot_sequence: 1,
        },
        InspectionSourceOwnerV1::FabricService => {
            InspectionSourceCoordinateV1::FabricServiceGeneration {
                service_generation: 1,
                observation_sequence: 1,
            }
        }
        InspectionSourceOwnerV1::AgentService => {
            InspectionSourceCoordinateV1::AgentServiceGeneration {
                service_generation: 1,
                observation_sequence: 1,
            }
        }
    }
}

fn ready_fact(
    owner: InspectionSourceOwnerV1,
    subject_ref: [u8; 16],
    observation_clock_ref: InspectionObservationClockRefV1,
) -> OwnerInspectionFactV1 {
    OwnerInspectionFactV1::try_new(OwnerInspectionFactFieldsV1 {
        owner,
        subject_ref,
        coordinate: coordinate(owner),
        observation_clock_ref,
        observed_at_nanos: 100,
        valid_until_nanos: 200,
        availability: InspectionSourceAvailabilityV1::Observed,
        liveness: InspectionLivenessV1::Live,
        readiness: InspectionReadinessV1::Ready,
        health: InspectionHealthV1::Healthy,
        feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
        reason: InspectionReasonV1::None,
        owner_fact_digest: Digest32::from_bytes([owner as u8; 32]),
    })
    .expect("ready owner fact")
}

fn ready_node_fact(
    node_ref: [u8; 16],
    node_incarnation_ref: [u8; 16],
    observation_clock_ref: InspectionObservationClockRefV1,
) -> NodeInspectionFactV2 {
    NodeInspectionFactV2::try_new(NodeInspectionFactFieldsV2 {
        node_ref,
        node_incarnation_ref,
        registration_epoch: 9,
        status_sequence: 11,
        observation_clock_ref,
        observed_at_nanos: 100,
        valid_until_nanos: 200,
        availability: InspectionSourceAvailabilityV1::Observed,
        liveness: InspectionLivenessV1::Live,
        readiness: InspectionReadinessV1::Ready,
        health: InspectionHealthV1::Healthy,
        feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
        reason: InspectionReasonV1::None,
        node_status_digest: Digest32::from_bytes([0x71; 32]),
    })
    .expect("ready NodeDaemon fact")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeAdapterError {
    Unavailable,
}

impl fmt::Display for FakeAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unavailable")
    }
}

impl std::error::Error for FakeAdapterError {}

#[derive(Debug)]
struct FakeAdapter {
    owner: InspectionSourceOwnerV1,
    subject_ref: [u8; 16],
    result: Result<Option<OwnerInspectionFactV1>, FakeAdapterError>,
    calls: usize,
    received_clock: Option<InspectionObservationClockRefV1>,
}

impl InspectionSourceAdapterV1 for FakeAdapter {
    type Error = FakeAdapterError;

    fn owner(&self) -> InspectionSourceOwnerV1 {
        self.owner
    }

    fn subject_ref(&self) -> [u8; 16] {
        self.subject_ref
    }

    fn read_verified_fact_once(
        &mut self,
        observation_clock_ref: InspectionObservationClockRefV1,
    ) -> Result<Option<OwnerInspectionFactV1>, Self::Error> {
        self.calls += 1;
        self.received_clock = Some(observation_clock_ref);
        self.result
    }
}

#[derive(Debug)]
struct FakeNodeAdapter {
    node_ref: [u8; 16],
    node_incarnation_ref: [u8; 16],
    result: Result<Option<NodeInspectionFactV2>, FakeAdapterError>,
    calls: usize,
}

impl NodeInspectionSourceAdapterV2 for FakeNodeAdapter {
    type Error = FakeAdapterError;

    fn node_ref(&self) -> [u8; 16] {
        self.node_ref
    }

    fn node_incarnation_ref(&self) -> [u8; 16] {
        self.node_incarnation_ref
    }

    fn read_verified_fact_once(
        &mut self,
        _observation_clock_ref: InspectionObservationClockRefV1,
    ) -> Result<Option<NodeInspectionFactV2>, Self::Error> {
        self.calls += 1;
        self.result
    }
}

#[test]
fn adapter_error_remains_error_and_is_never_downgraded_to_missing() {
    let owner = InspectionSourceOwnerV1::RuntimeHost;
    let mut adapter = FakeAdapter {
        owner,
        subject_ref: subject(owner),
        result: Err(FakeAdapterError::Unavailable),
        calls: 0,
        received_clock: None,
    };

    assert_eq!(
        read_inspection_source_slot_once_v1(&mut adapter, clock()),
        Err(InspectionSourceAdapterReadErrorV1::Adapter(
            FakeAdapterError::Unavailable
        ))
    );
    assert_eq!(adapter.calls, 1);
    assert_eq!(adapter.received_clock, Some(clock()));
}

#[test]
fn explicit_none_is_the_only_adapter_result_that_becomes_missing() {
    let owner = InspectionSourceOwnerV1::FabricService;
    let mut adapter = FakeAdapter {
        owner,
        subject_ref: subject(owner),
        result: Ok(None),
        calls: 0,
        received_clock: None,
    };

    let slot = read_inspection_source_slot_once_v1(&mut adapter, clock()).expect("missing slot");
    assert_eq!(slot.owner(), owner);
    assert_eq!(slot.subject_ref(), subject(owner));
    assert!(slot.fact().is_none());
    assert_eq!(adapter.calls, 1);
}

#[test]
fn adapter_identity_and_returned_fact_are_strictly_correlated() {
    let owner = InspectionSourceOwnerV1::Authority;
    let mut zero_subject = FakeAdapter {
        owner,
        subject_ref: [0; 16],
        result: Ok(None),
        calls: 0,
        received_clock: None,
    };
    assert_eq!(
        read_inspection_source_slot_once_v1(&mut zero_subject, clock()),
        Err(InspectionSourceAdapterReadErrorV1::Contract(
            InspectionContractError::ZeroSubjectRef
        ))
    );
    assert_eq!(
        zero_subject.calls, 0,
        "invalid identity must fail before I/O"
    );

    let mut wrong_owner = FakeAdapter {
        owner,
        subject_ref: subject(owner),
        result: Ok(Some(ready_fact(
            InspectionSourceOwnerV1::RuntimeHost,
            subject(owner),
            clock(),
        ))),
        calls: 0,
        received_clock: None,
    };
    assert_eq!(
        read_inspection_source_slot_once_v1(&mut wrong_owner, clock()),
        Err(InspectionSourceAdapterReadErrorV1::Contract(
            InspectionContractError::SourceSlotMismatch
        ))
    );
    assert_eq!(wrong_owner.calls, 1);

    let mut wrong_clock = FakeAdapter {
        owner,
        subject_ref: subject(owner),
        result: Ok(Some(ready_fact(owner, subject(owner), other_clock()))),
        calls: 0,
        received_clock: None,
    };
    assert_eq!(
        read_inspection_source_slot_once_v1(&mut wrong_clock, clock()),
        Err(InspectionSourceAdapterReadErrorV1::Contract(
            InspectionContractError::ObservationClockMismatch
        ))
    );
    assert_eq!(wrong_clock.calls, 1);
}

#[test]
fn builder_accepts_exactly_five_owners_and_emits_canonical_order() {
    let owners = [
        InspectionSourceOwnerV1::AgentService,
        InspectionSourceOwnerV1::FabricService,
        InspectionSourceOwnerV1::RuntimeHost,
        InspectionSourceOwnerV1::DeploymentController,
        InspectionSourceOwnerV1::Authority,
    ];
    let mut builder = LocalInspectionProjectionInputBuilderV1::new(clock());
    for owner in owners {
        builder
            .try_insert(
                InspectionSourceSlotV1::try_new(owner, subject(owner), None).expect("source slot"),
            )
            .expect("unique owner");
    }
    let input = builder.try_build().expect("complete input");
    assert_eq!(
        input.slots().map(InspectionSourceSlotV1::owner),
        [
            InspectionSourceOwnerV1::Authority,
            InspectionSourceOwnerV1::DeploymentController,
            InspectionSourceOwnerV1::RuntimeHost,
            InspectionSourceOwnerV1::FabricService,
            InspectionSourceOwnerV1::AgentService,
        ]
    );

    let mut service = LocalInspectionServiceV1::try_new(PROJECTION_ID, clock()).expect("service");
    let snapshot = service.project(150, &input).expect("projection");
    assert_eq!(snapshot.overall(), LocalInspectionOverallV1::Unknown);
    assert!(
        snapshot
            .records()
            .iter()
            .all(|record| record.freshness() == InspectionFreshnessV1::Missing)
    );
}

#[test]
fn builder_rejects_duplicate_missing_and_clock_mismatched_slots() {
    let owner = InspectionSourceOwnerV1::Authority;
    let first = InspectionSourceSlotV1::try_new(owner, subject(owner), None).expect("first slot");
    let duplicate =
        InspectionSourceSlotV1::try_new(owner, [0x44; 16], None).expect("duplicate slot");
    let mut builder = LocalInspectionProjectionInputBuilderV1::new(clock());
    builder.try_insert(first).expect("first insert");
    assert_eq!(
        builder.try_insert(duplicate),
        Err(LocalInspectionProjectionInputBuilderErrorV1::DuplicateOwner(owner))
    );
    assert_eq!(
        builder.try_build(),
        Err(LocalInspectionProjectionInputBuilderErrorV1::MissingOwner(
            InspectionSourceOwnerV1::DeploymentController
        ))
    );

    let fact = ready_fact(owner, subject(owner), other_clock());
    let mismatched =
        InspectionSourceSlotV1::try_new(owner, subject(owner), Some(fact)).expect("slot");
    let mut builder = LocalInspectionProjectionInputBuilderV1::new(clock());
    assert_eq!(
        builder.try_insert(mismatched),
        Err(LocalInspectionProjectionInputBuilderErrorV1::Contract(
            InspectionContractError::ObservationClockMismatch
        ))
    );
    assert_eq!(
        builder.try_build(),
        Err(LocalInspectionProjectionInputBuilderErrorV1::MissingOwner(
            owner
        ))
    );
}

#[test]
fn node_adapter_preserves_errors_and_strictly_binds_identity_and_clock() {
    let node_ref = [0x61; 16];
    let incarnation_ref = [0x62; 16];
    let mut unavailable = FakeNodeAdapter {
        node_ref,
        node_incarnation_ref: incarnation_ref,
        result: Err(FakeAdapterError::Unavailable),
        calls: 0,
    };
    assert_eq!(
        read_node_inspection_source_slot_once_v2(&mut unavailable, clock()),
        Err(NodeInspectionSourceAdapterReadErrorV2::Adapter(
            FakeAdapterError::Unavailable
        ))
    );
    assert_eq!(unavailable.calls, 1);

    let mut wrong_identity = FakeNodeAdapter {
        node_ref,
        node_incarnation_ref: incarnation_ref,
        result: Ok(Some(ready_node_fact([0x63; 16], incarnation_ref, clock()))),
        calls: 0,
    };
    assert_eq!(
        read_node_inspection_source_slot_once_v2(&mut wrong_identity, clock()),
        Err(NodeInspectionSourceAdapterReadErrorV2::Contract(
            InspectionContractError::SourceSlotMismatch
        ))
    );
    assert_eq!(wrong_identity.calls, 1);

    let mut wrong_clock = FakeNodeAdapter {
        node_ref,
        node_incarnation_ref: incarnation_ref,
        result: Ok(Some(ready_node_fact(
            node_ref,
            incarnation_ref,
            other_clock(),
        ))),
        calls: 0,
    };
    assert_eq!(
        read_node_inspection_source_slot_once_v2(&mut wrong_clock, clock()),
        Err(NodeInspectionSourceAdapterReadErrorV2::Contract(
            InspectionContractError::ObservationClockMismatch
        ))
    );
    assert_eq!(wrong_clock.calls, 1);

    let mut zero_identity = FakeNodeAdapter {
        node_ref: [0; 16],
        node_incarnation_ref: incarnation_ref,
        result: Ok(None),
        calls: 0,
    };
    assert!(matches!(
        read_node_inspection_source_slot_once_v2(&mut zero_identity, clock()),
        Err(NodeInspectionSourceAdapterReadErrorV2::Contract(
            InspectionContractError::ZeroSubjectRef
        ))
    ));
    assert_eq!(zero_identity.calls, 0, "invalid identity fails before I/O");
}
