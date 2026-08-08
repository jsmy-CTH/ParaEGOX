use paraegox_inspection::protocol::{
    INSPECTION_REQUEST_BYTES, INSPECTION_REQUEST_V2_BYTES, InspectionClientErrorV1,
    InspectionClientV1, InspectionClientV2, InspectionEndpointErrorV1, InspectionEndpointV1,
    InspectionProtocolError, InspectionRequestV1, InspectionRequestV2, InspectionResponseOutcomeV1,
    InspectionResponseOutcomeV2, InspectionResponseV1, InspectionResponseV2,
    MAX_INSPECTION_RESPONSE_BYTES, MAX_INSPECTION_RESPONSE_V2_BYTES,
};
use paraegox_inspection::{
    InspectionFeatureSupportV1, InspectionFreshnessV1, InspectionHealthV1, InspectionLivenessV1,
    InspectionObservationClockRefV1, InspectionReadinessV1, InspectionReasonV1,
    InspectionSourceAvailabilityV1, InspectionSourceCoordinateV1, InspectionSourceOwnerV1,
    InspectionSourceSlotV1, LocalInspectionOverallV1, LocalInspectionProjectionInputV1,
    LocalInspectionProjectionInputV2, LocalInspectionServiceV1, LocalInspectionServiceV2,
    NodeInspectionFactFieldsV2, NodeInspectionFactV2, NodeInspectionSourceSlotV2,
    OwnerInspectionFactFieldsV1, OwnerInspectionFactV1,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder};

const PROJECTION_ID: [u8; 16] = [0xa1; 16];
const OTHER_PROJECTION_ID: [u8; 16] = [0xa2; 16];
const CLOCK_BYTES: [u8; 16] = [0xc1; 16];
const CROSS_LANGUAGE_PROJECTION_ID: [u8; 16] = [0x21; 16];
const CROSS_LANGUAGE_CLOCK_BYTES: [u8; 16] = [0x31; 16];
const CROSS_LANGUAGE_REQUEST_ID: [u8; 16] = [
    0x6e, 0xeb, 0x8f, 0xa5, 0x0a, 0xd6, 0x17, 0x7b, 0x24, 0xd9, 0x4c, 0x51, 0x12, 0xf5, 0x04, 0x83,
];
const REQUEST_HEADER_BYTES: usize = 96;
const REQUEST_DIGEST_OFFSET: usize = 64;
const RESPONSE_HEADER_BYTES: usize = 144;
const RESPONSE_DIGEST_OFFSET: usize = 112;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.protocol-request.v1";
const RESPONSE_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.protocol-response.v1";

fn clock() -> InspectionObservationClockRefV1 {
    InspectionObservationClockRefV1::try_from_bytes(CLOCK_BYTES).expect("test clock")
}

fn subject(owner: InspectionSourceOwnerV1) -> [u8; 16] {
    [owner as u8 + 0x10; 16]
}

fn missing_input() -> LocalInspectionProjectionInputV1 {
    LocalInspectionProjectionInputV1::try_new(
        clock(),
        [
            missing_slot(InspectionSourceOwnerV1::Authority),
            missing_slot(InspectionSourceOwnerV1::DeploymentController),
            missing_slot(InspectionSourceOwnerV1::RuntimeHost),
            missing_slot(InspectionSourceOwnerV1::FabricService),
            missing_slot(InspectionSourceOwnerV1::AgentService),
        ],
    )
    .expect("missing projection input")
}

fn missing_slot(owner: InspectionSourceOwnerV1) -> InspectionSourceSlotV1 {
    InspectionSourceSlotV1::try_new(owner, subject(owner), None).expect("missing slot")
}

fn stale_runtime_input() -> LocalInspectionProjectionInputV1 {
    let owner = InspectionSourceOwnerV1::RuntimeHost;
    let fact = OwnerInspectionFactV1::try_new(OwnerInspectionFactFieldsV1 {
        owner,
        subject_ref: subject(owner),
        coordinate: InspectionSourceCoordinateV1::RuntimeHostEpoch {
            runtime_host_epoch: 7,
            snapshot_sequence: 9,
        },
        observation_clock_ref: clock(),
        observed_at_nanos: 100,
        valid_until_nanos: 120,
        availability: InspectionSourceAvailabilityV1::Observed,
        liveness: InspectionLivenessV1::Live,
        readiness: InspectionReadinessV1::Ready,
        health: InspectionHealthV1::Healthy,
        feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
        reason: InspectionReasonV1::None,
        owner_fact_digest: Digest32::from_bytes([0x77; 32]),
    })
    .expect("owner fact");
    LocalInspectionProjectionInputV1::try_new(
        clock(),
        [
            missing_slot(InspectionSourceOwnerV1::Authority),
            missing_slot(InspectionSourceOwnerV1::DeploymentController),
            InspectionSourceSlotV1::try_new(owner, subject(owner), Some(fact))
                .expect("runtime slot"),
            missing_slot(InspectionSourceOwnerV1::FabricService),
            missing_slot(InspectionSourceOwnerV1::AgentService),
        ],
    )
    .expect("stale projection input")
}

fn service_with_snapshot(revision: u64) -> LocalInspectionServiceV1 {
    let mut service = LocalInspectionServiceV1::try_new(PROJECTION_ID, clock()).expect("service");
    let input = missing_input();
    for _ in 0..revision {
        service.project(150, &input).expect("projection");
    }
    service
}

fn service_with_snapshot_v2(revision: u64) -> LocalInspectionServiceV2 {
    let mut service = LocalInspectionServiceV2::try_new(PROJECTION_ID, clock()).expect("service");
    let node = NodeInspectionSourceSlotV2::try_new([0x61; 16], [0x62; 16], None)
        .expect("missing NodeDaemon slot");
    let input = LocalInspectionProjectionInputV2::try_new(missing_input(), node)
        .expect("v2 projection input");
    for _ in 0..revision {
        service.project(150, &input).expect("v2 projection");
    }
    service
}

fn cross_language_clock() -> InspectionObservationClockRefV1 {
    InspectionObservationClockRefV1::try_from_bytes(CROSS_LANGUAGE_CLOCK_BYTES)
        .expect("cross-language clock")
}

fn cross_language_missing_slot(
    owner: InspectionSourceOwnerV1,
    subject_byte: u8,
) -> InspectionSourceSlotV1 {
    InspectionSourceSlotV1::try_new(owner, [subject_byte; 16], None)
        .expect("cross-language missing slot")
}

fn cross_language_input_v2() -> LocalInspectionProjectionInputV2 {
    let base = LocalInspectionProjectionInputV1::try_new(
        cross_language_clock(),
        [
            cross_language_missing_slot(InspectionSourceOwnerV1::Authority, 0x41),
            cross_language_missing_slot(InspectionSourceOwnerV1::DeploymentController, 0x42),
            cross_language_missing_slot(InspectionSourceOwnerV1::RuntimeHost, 0x43),
            cross_language_missing_slot(InspectionSourceOwnerV1::FabricService, 0x44),
            cross_language_missing_slot(InspectionSourceOwnerV1::AgentService, 0x45),
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

fn cross_language_service_v2() -> LocalInspectionServiceV2 {
    let mut service =
        LocalInspectionServiceV2::try_new(CROSS_LANGUAGE_PROJECTION_ID, cross_language_clock())
            .expect("cross-language service");
    let input = cross_language_input_v2();
    for _ in 0..7 {
        service
            .project(150, &input)
            .expect("cross-language projection");
    }
    service
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

fn resign_request(frame: &mut [u8]) {
    let mut builder = Digest32Builder::try_new(REQUEST_DIGEST_DOMAIN).expect("request domain");
    builder
        .field_bytes(&frame[..REQUEST_DIGEST_OFFSET])
        .expect("request header");
    frame[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES].copy_from_slice(builder.finish().as_bytes());
}

fn resign_response(frame: &mut [u8]) {
    let mut builder = Digest32Builder::try_new(RESPONSE_DIGEST_DOMAIN).expect("response domain");
    builder
        .field_bytes(&frame[..RESPONSE_DIGEST_OFFSET])
        .expect("response header")
        .field_bytes(&frame[RESPONSE_HEADER_BYTES..])
        .expect("response payload");
    frame[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES]
        .copy_from_slice(builder.finish().as_bytes());
}

#[test]
fn request_and_all_response_outcomes_match_exact_goldens() {
    let latest = InspectionRequestV1::try_latest([0x11; 16], PROJECTION_ID).expect("latest");
    let watch = InspectionRequestV1::try_watch([0x12; 16], PROJECTION_ID, 1).expect("watch");
    let service = service_with_snapshot(1);
    let snapshot_response = service.answer_read_only_v1(&latest).expect("snapshot");
    let not_modified_response = service.answer_read_only_v1(&watch).expect("not modified");
    let blank = LocalInspectionServiceV1::try_new(PROJECTION_ID, clock()).expect("blank service");
    let not_found_response = blank.answer_read_only_v1(&latest).expect("not found");

    let fixtures = [
        (
            "LATEST_REQUEST",
            include_str!("fixtures/inspection_latest_request_v1.hex").trim(),
            latest.canonical_wire(),
        ),
        (
            "WATCH_REQUEST",
            include_str!("fixtures/inspection_watch_request_v1.hex").trim(),
            watch.canonical_wire(),
        ),
        (
            "SNAPSHOT_RESPONSE",
            include_str!("fixtures/inspection_snapshot_response_v1.hex").trim(),
            snapshot_response.canonical_wire(),
        ),
        (
            "NOT_MODIFIED_RESPONSE",
            include_str!("fixtures/inspection_not_modified_response_v1.hex").trim(),
            not_modified_response.canonical_wire(),
        ),
        (
            "NOT_FOUND_RESPONSE",
            include_str!("fixtures/inspection_not_found_response_v1.hex").trim(),
            not_found_response.canonical_wire(),
        ),
    ];
    if fixtures
        .iter()
        .any(|(_, expected, _)| *expected == "PENDING")
    {
        let values = fixtures
            .iter()
            .map(|(name, _, bytes)| format!("{name}={}", encode_hex(bytes)))
            .collect::<Vec<_>>()
            .join("\n");
        panic!("PXI_PROTOCOL_GOLDENS\n{values}");
    }
    for (_, expected, actual) in fixtures {
        assert_eq!(actual, decode_hex(expected));
    }

    assert_eq!(
        InspectionRequestV1::decode(latest.canonical_wire()).expect("latest decode"),
        latest
    );
    assert_eq!(
        InspectionRequestV1::decode(watch.canonical_wire()).expect("watch decode"),
        watch
    );
    for response in [snapshot_response, not_modified_response, not_found_response] {
        assert_eq!(
            InspectionResponseV1::decode(response.canonical_wire()).expect("response decode"),
            response
        );
    }
}

#[test]
fn latest_and_watch_read_only_semantics_use_only_last_cache() {
    let service = service_with_snapshot(2);
    let before = service.snapshot().expect("cached snapshot");
    let before_revision = before.projection_revision();
    let before_bytes = before.canonical_wire().to_vec();

    let latest = InspectionRequestV1::try_latest([0x21; 16], PROJECTION_ID).expect("latest");
    let older_watch =
        InspectionRequestV1::try_watch([0x22; 16], PROJECTION_ID, 1).expect("older watch");
    let current_watch =
        InspectionRequestV1::try_watch([0x23; 16], PROJECTION_ID, 2).expect("current watch");
    let future_watch =
        InspectionRequestV1::try_watch([0x24; 16], PROJECTION_ID, 9).expect("future watch");

    let latest_response = service
        .answer_read_only_v1(&latest)
        .expect("latest response");
    let older_response = service
        .answer_read_only_v1(&older_watch)
        .expect("older response");
    let current_response = service
        .answer_read_only_v1(&current_watch)
        .expect("current response");
    let future_response = service
        .answer_read_only_v1(&future_watch)
        .expect("future response");

    assert_eq!(
        latest_response.outcome(),
        InspectionResponseOutcomeV1::Snapshot
    );
    assert_eq!(
        older_response.outcome(),
        InspectionResponseOutcomeV1::Snapshot
    );
    assert_eq!(
        older_response
            .snapshot_value()
            .expect("current snapshot only")
            .projection_revision(),
        2
    );
    assert_eq!(
        current_response.outcome(),
        InspectionResponseOutcomeV1::NotModified
    );
    assert_eq!(
        future_response.outcome(),
        InspectionResponseOutcomeV1::NotModified
    );
    assert_eq!(
        current_response.canonical_wire().len(),
        RESPONSE_HEADER_BYTES
    );
    assert_eq!(
        future_response.canonical_wire().len(),
        RESPONSE_HEADER_BYTES
    );

    let after = service.snapshot().expect("same cached snapshot");
    assert_eq!(after.projection_revision(), before_revision);
    assert_eq!(after.canonical_wire(), before_bytes);
}

#[test]
fn absent_or_different_projection_is_not_found_without_mutation() {
    let blank = LocalInspectionServiceV1::try_new(PROJECTION_ID, clock()).expect("blank service");
    let request = InspectionRequestV1::try_latest([0x31; 16], PROJECTION_ID).expect("latest");
    let response = blank.answer_read_only_v1(&request).expect("not found");
    assert_eq!(response.outcome(), InspectionResponseOutcomeV1::NotFound);
    assert_eq!(response.current_revision(), 0);
    assert!(response.snapshot_value().is_none());
    assert!(blank.snapshot().is_none());

    let service = service_with_snapshot(1);
    let before = service
        .snapshot()
        .expect("snapshot")
        .canonical_wire()
        .to_vec();
    let other =
        InspectionRequestV1::try_latest([0x32; 16], OTHER_PROJECTION_ID).expect("other latest");
    let response = service.answer_read_only_v1(&other).expect("not found");
    assert_eq!(response.outcome(), InspectionResponseOutcomeV1::NotFound);
    assert_eq!(
        service.snapshot().expect("unchanged").canonical_wire(),
        before
    );
}

#[test]
fn stale_snapshot_is_returned_bit_identically_and_never_becomes_green() {
    let mut service = LocalInspectionServiceV1::try_new(PROJECTION_ID, clock()).expect("service");
    service
        .project(150, &stale_runtime_input())
        .expect("stale projection");
    let before = service
        .snapshot()
        .expect("snapshot")
        .canonical_wire()
        .to_vec();

    let mut client = InspectionClientV1::new(service);
    let response = client
        .latest([0x41; 16], PROJECTION_ID)
        .expect("typed latest");
    let returned = response.snapshot_value().expect("snapshot payload");
    assert_eq!(returned.canonical_wire(), before);
    assert_eq!(returned.overall(), LocalInspectionOverallV1::Unknown);
    let runtime = returned.records()[2];
    assert_eq!(runtime.freshness(), InspectionFreshnessV1::Stale);
    assert_eq!(runtime.liveness(), InspectionLivenessV1::Unknown);
    assert_eq!(runtime.readiness(), InspectionReadinessV1::Unknown);
    assert_eq!(runtime.health(), InspectionHealthV1::Unknown);
    assert_eq!(
        runtime.feature_support(),
        InspectionFeatureSupportV1::Unknown
    );

    let service = client.into_endpoint();
    assert_eq!(
        service.snapshot().expect("unchanged").canonical_wire(),
        before
    );
}

#[derive(Debug)]
struct FixedEndpoint {
    calls: usize,
    response: Box<[u8]>,
}

impl InspectionEndpointV1 for FixedEndpoint {
    fn exchange(
        &mut self,
        _canonical_request: &[u8],
    ) -> Result<Box<[u8]>, InspectionEndpointErrorV1> {
        self.calls += 1;
        Ok(self.response.clone())
    }
}

#[test]
fn typed_client_detects_exact_correlation_and_never_retries() {
    let service = service_with_snapshot(1);
    let different =
        InspectionRequestV1::try_latest([0x52; 16], PROJECTION_ID).expect("different request");
    let response = service
        .answer_read_only_v1(&different)
        .expect("different response");
    let endpoint = FixedEndpoint {
        calls: 0,
        response: response.canonical_wire().into(),
    };
    let mut client = InspectionClientV1::new(endpoint);
    assert_eq!(
        client.latest([0x51; 16], PROJECTION_ID),
        Err(InspectionClientErrorV1::CorrelationMismatch)
    );
    assert_eq!(client.into_endpoint().calls, 1);

    let endpoint = FixedEndpoint {
        calls: 0,
        response: vec![0; 8].into_boxed_slice(),
    };
    let mut client = InspectionClientV1::new(endpoint);
    assert_eq!(
        client.latest([0x53; 16], PROJECTION_ID),
        Err(InspectionClientErrorV1::InvalidResponse(
            InspectionProtocolError::InvalidFrameLength
        ))
    );
    assert_eq!(client.into_endpoint().calls, 1);
}

#[test]
fn request_codec_rejects_length_unknown_reserved_digest_and_shape_tampering() {
    let canonical = InspectionRequestV1::try_latest([0x61; 16], PROJECTION_ID)
        .expect("request")
        .canonical_wire()
        .to_vec();
    assert_eq!(canonical.len(), INSPECTION_REQUEST_BYTES);

    assert_eq!(
        InspectionRequestV1::decode(&canonical[..canonical.len() - 1]),
        Err(InspectionProtocolError::InvalidFrameLength)
    );

    let mut version = canonical.clone();
    version[5] = 2;
    assert_eq!(
        InspectionRequestV1::decode(&version),
        Err(InspectionProtocolError::UnsupportedFrame)
    );

    let mut reserved = canonical.clone();
    reserved[13] = 1;
    assert_eq!(
        InspectionRequestV1::decode(&reserved),
        Err(InspectionProtocolError::NonCanonicalEncoding)
    );

    let mut digest = canonical.clone();
    digest[REQUEST_DIGEST_OFFSET] ^= 1;
    assert_eq!(
        InspectionRequestV1::decode(&digest),
        Err(InspectionProtocolError::DigestMismatch)
    );

    let mut unknown = canonical.clone();
    unknown[12] = 0xff;
    resign_request(&mut unknown);
    assert_eq!(
        InspectionRequestV1::decode(&unknown),
        Err(InspectionProtocolError::UnknownEnumValue)
    );

    let mut wrong_shape = canonical;
    wrong_shape[55] = 1;
    resign_request(&mut wrong_shape);
    assert_eq!(
        InspectionRequestV1::decode(&wrong_shape),
        Err(InspectionProtocolError::InvalidRequestShape)
    );
}

#[test]
fn response_codec_rejects_length_unknown_reserved_digest_and_nested_tampering() {
    let request = InspectionRequestV1::try_latest([0x71; 16], PROJECTION_ID).expect("request");
    let response = service_with_snapshot(1)
        .answer_read_only_v1(&request)
        .expect("response");
    let canonical = response.canonical_wire().to_vec();
    assert_eq!(canonical.len(), MAX_INSPECTION_RESPONSE_BYTES);

    assert_eq!(
        InspectionResponseV1::decode(&canonical[..RESPONSE_HEADER_BYTES - 1]),
        Err(InspectionProtocolError::InvalidFrameLength)
    );

    let mut version = canonical.clone();
    version[5] = 2;
    assert_eq!(
        InspectionResponseV1::decode(&version),
        Err(InspectionProtocolError::UnsupportedFrame)
    );

    let mut reserved = canonical.clone();
    reserved[18] = 1;
    assert_eq!(
        InspectionResponseV1::decode(&reserved),
        Err(InspectionProtocolError::NonCanonicalEncoding)
    );

    let mut digest = canonical.clone();
    digest[RESPONSE_DIGEST_OFFSET] ^= 1;
    assert_eq!(
        InspectionResponseV1::decode(&digest),
        Err(InspectionProtocolError::DigestMismatch)
    );

    let mut unknown = canonical.clone();
    unknown[16] = 0xff;
    resign_response(&mut unknown);
    assert_eq!(
        InspectionResponseV1::decode(&unknown),
        Err(InspectionProtocolError::UnknownEnumValue)
    );

    let mut wrong_payload_length = canonical.clone();
    wrong_payload_length[12..16].copy_from_slice(&0_u32.to_be_bytes());
    resign_response(&mut wrong_payload_length);
    assert_eq!(
        InspectionResponseV1::decode(&wrong_payload_length),
        Err(InspectionProtocolError::NonCanonicalEncoding)
    );

    let mut nested = canonical;
    nested[RESPONSE_HEADER_BYTES] ^= 1;
    resign_response(&mut nested);
    assert!(matches!(
        InspectionResponseV1::decode(&nested),
        Err(InspectionProtocolError::SnapshotRejected(_))
    ));
}

#[test]
fn response_projection_and_request_correlation_tampering_is_rejected() {
    let request = InspectionRequestV1::try_latest([0x81; 16], PROJECTION_ID).expect("request");
    let response = service_with_snapshot(1)
        .answer_read_only_v1(&request)
        .expect("response");

    let mut projection = response.canonical_wire().to_vec();
    projection[40..56].copy_from_slice(&OTHER_PROJECTION_ID);
    resign_response(&mut projection);
    assert_eq!(
        InspectionResponseV1::decode(&projection),
        Err(InspectionProtocolError::CorrelationMismatch)
    );

    let mut request_id = response.canonical_wire().to_vec();
    request_id[24..40].copy_from_slice(&[0x82; 16]);
    resign_response(&mut request_id);
    let decoded = InspectionResponseV1::decode(&request_id).expect("standalone response decode");
    assert_eq!(
        decoded.validate_for(&request),
        Err(InspectionProtocolError::CorrelationMismatch)
    );

    let mut request_digest = response.canonical_wire().to_vec();
    request_digest[72] ^= 1;
    resign_response(&mut request_digest);
    let decoded =
        InspectionResponseV1::decode(&request_digest).expect("standalone response decode");
    assert_eq!(
        decoded.validate_for(&request),
        Err(InspectionProtocolError::CorrelationMismatch)
    );
}

#[test]
fn local_endpoint_rejects_malformed_request_without_changing_cache() {
    let mut service = service_with_snapshot(1);
    let before = service
        .snapshot()
        .expect("snapshot")
        .canonical_wire()
        .to_vec();
    assert_eq!(
        service.exchange(&[0; 8]),
        Err(InspectionEndpointErrorV1::MalformedRequest)
    );
    assert_eq!(
        service.snapshot().expect("unchanged").canonical_wire(),
        before
    );
}

#[test]
fn v2_protocol_is_strictly_versioned_and_returns_the_composite_cache() {
    let latest = InspectionRequestV2::try_latest([0x91; 16], PROJECTION_ID).expect("v2 latest");
    assert_eq!(latest.canonical_wire().len(), INSPECTION_REQUEST_V2_BYTES);
    assert_eq!(
        InspectionRequestV2::decode(latest.canonical_wire()),
        Ok(latest.clone())
    );
    assert!(InspectionRequestV1::decode(latest.canonical_wire()).is_err());

    let service = service_with_snapshot_v2(2);
    let response = service.answer_read_only_v2(&latest).expect("v2 response");
    assert_eq!(response.outcome(), InspectionResponseOutcomeV2::Snapshot);
    assert_eq!(
        response.canonical_wire().len(),
        MAX_INSPECTION_RESPONSE_V2_BYTES
    );
    let decoded = InspectionResponseV2::decode(response.canonical_wire()).expect("v2 decode");
    assert_eq!(decoded, response);
    assert_eq!(
        decoded
            .snapshot_value()
            .expect("composite snapshot")
            .projection_revision(),
        2
    );
    assert!(InspectionResponseV1::decode(response.canonical_wire()).is_err());

    let watch = InspectionRequestV2::try_watch([0x92; 16], PROJECTION_ID, 2).expect("v2 watch");
    let not_modified = service.answer_read_only_v2(&watch).expect("not modified");
    assert_eq!(
        not_modified.outcome(),
        InspectionResponseOutcomeV2::NotModified
    );
    assert!(not_modified.snapshot_value().is_none());

    let mut client = InspectionClientV2::new(service);
    let client_response = client
        .latest([0x93; 16], PROJECTION_ID)
        .expect("typed v2 latest");
    assert_eq!(
        client_response.outcome(),
        InspectionResponseOutcomeV2::Snapshot
    );
}

#[test]
fn v2_latest_snapshot_and_not_found_match_cross_language_goldens() {
    let latest =
        InspectionRequestV2::try_latest(CROSS_LANGUAGE_REQUEST_ID, CROSS_LANGUAGE_PROJECTION_ID)
            .expect("cross-language latest");
    let service = cross_language_service_v2();
    let snapshot_response = service
        .answer_read_only_v2(&latest)
        .expect("cross-language snapshot response");
    let blank =
        LocalInspectionServiceV2::try_new(CROSS_LANGUAGE_PROJECTION_ID, cross_language_clock())
            .expect("blank cross-language service");
    let not_found_response = blank
        .answer_read_only_v2(&latest)
        .expect("cross-language not-found response");
    let fixtures = [
        (
            "LATEST_REQUEST_V2",
            include_str!("fixtures/inspection_latest_request_v2.hex").trim(),
            latest.canonical_wire(),
        ),
        (
            "SNAPSHOT_RESPONSE_V2",
            include_str!("fixtures/inspection_snapshot_response_v2.hex").trim(),
            snapshot_response.canonical_wire(),
        ),
        (
            "NOT_FOUND_RESPONSE_V2",
            include_str!("fixtures/inspection_not_found_response_v2.hex").trim(),
            not_found_response.canonical_wire(),
        ),
    ];
    if fixtures
        .iter()
        .any(|(_, expected, _)| *expected == "PENDING")
    {
        let values = fixtures
            .iter()
            .map(|(name, _, bytes)| format!("{name}={}", encode_hex(bytes)))
            .collect::<Vec<_>>()
            .join("\n");
        panic!("PXI_PROTOCOL_V2_GOLDENS\n{values}");
    }
    for (_, expected, actual) in fixtures {
        assert_eq!(actual, decode_hex(expected));
    }

    assert_eq!(
        InspectionRequestV2::decode(latest.canonical_wire()).expect("strict latest decode"),
        latest
    );
    let decoded_snapshot = InspectionResponseV2::decode(snapshot_response.canonical_wire())
        .expect("strict snapshot response decode");
    decoded_snapshot
        .validate_for(&latest)
        .expect("exact snapshot correlation");
    assert_eq!(
        decoded_snapshot
            .snapshot_value()
            .expect("snapshot payload")
            .canonical_wire(),
        decode_hex(include_str!("fixtures/local_inspection_snapshot_v2.hex"))
    );
    let decoded_not_found = InspectionResponseV2::decode(not_found_response.canonical_wire())
        .expect("strict not-found response decode");
    decoded_not_found
        .validate_for(&latest)
        .expect("exact not-found correlation");
    assert_eq!(
        decoded_not_found.outcome(),
        InspectionResponseOutcomeV2::NotFound
    );
}
