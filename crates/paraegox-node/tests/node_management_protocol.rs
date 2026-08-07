use std::collections::VecDeque;

use paraegox_kernel::{
    digest::{Digest32, Digest32Builder},
    identity::{PrincipalRef, RuntimeHostId},
};
use paraegox_node::protocol::{
    MAX_NODE_MANAGEMENT_RESPONSE_BYTES, NODE_MANAGEMENT_REQUEST_BYTES, NodeManagementClientErrorV1,
    NodeManagementClientV1, NodeManagementEndpointErrorV1, NodeManagementEndpointV1,
    NodeManagementProtocolError, NodeManagementRequestV1, NodeManagementResponseOutcomeV1,
    NodeManagementResponseV1, NodeManagementTargetV1, NodeStatusCursorV1,
};
use paraegox_node::{
    EnrollmentIssuerRefV1, NodeArchitectureV1, NodeDaemonV1, NodeFeatureReportInputV1,
    NodeFeatureReportV1, NodeId, NodeIdentityV1, NodeIncarnation, NodeManagementEndpointRefV1,
    NodeOperatingSystemV1, NodeRegistrationTenureV1, RuntimeApplyEndpointDescriptorV1,
    RuntimeApplyEndpointRefV1, RuntimeHostLivenessV1, RuntimeHostStatusV1,
};

const REQUEST_HEADER_BYTES: usize = 160;
const REQUEST_DIGEST_OFFSET: usize = 128;
const RESPONSE_HEADER_BYTES: usize = 264;
const RESPONSE_DIGEST_OFFSET: usize = 232;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.node.management-request.v1";
const RESPONSE_DIGEST_DOMAIN: &[u8] = b"paraegox.node.management-response.v1";

fn node_id() -> NodeId {
    NodeId::try_from_bytes([1; 16]).expect("node id")
}

fn incarnation(value: u8) -> NodeIncarnation {
    NodeIncarnation::try_from_bytes([value; 16]).expect("node incarnation")
}

fn endpoint_ref(value: u8) -> NodeManagementEndpointRefV1 {
    NodeManagementEndpointRefV1::try_from_bytes([value; 16]).expect("management endpoint")
}

fn target(
    registration_epoch: u64,
    incarnation_value: u8,
    endpoint_value: u8,
) -> NodeManagementTargetV1 {
    NodeManagementTargetV1::try_new(
        node_id(),
        endpoint_ref(endpoint_value),
        incarnation(incarnation_value),
        registration_epoch,
    )
    .expect("target")
}

fn feature(node_incarnation: NodeIncarnation) -> NodeFeatureReportV1 {
    NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
        node_id: node_id(),
        node_incarnation,
        report_sequence: 1,
        operating_system: NodeOperatingSystemV1::Linux,
        architecture: NodeArchitectureV1::Aarch64,
        platform_profile_digest: Digest32::from_bytes([4; 32]),
        runtime_contract_version: 7,
        fabric_contract_version: 1,
    })
    .expect("feature report")
}

fn runtime() -> RuntimeHostStatusV1 {
    let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
        RuntimeApplyEndpointRefV1::try_from_bytes([21; 16]).expect("Runtime endpoint ref"),
        RuntimeHostId::from_bytes([11; 16]),
        3,
        "paraegox/v1/nodes/01/runtime/11/apply",
        [31; 16],
        [41; 32],
    )
    .expect("Runtime endpoint");
    RuntimeHostStatusV1::try_new(2, 5, RuntimeHostLivenessV1::Live, endpoint)
        .expect("Runtime status")
}

fn daemon(registration_epoch: u64, incarnation_value: u8, endpoint_value: u8) -> NodeDaemonV1 {
    let node_incarnation = incarnation(incarnation_value);
    NodeDaemonV1::try_new(
        NodeIdentityV1::try_new(
            node_id(),
            PrincipalRef::from_bytes([2; 16]),
            EnrollmentIssuerRefV1::try_from_bytes([3; 16]).expect("issuer"),
        )
        .expect("identity"),
        NodeRegistrationTenureV1::try_new(node_id(), registration_epoch, node_incarnation)
            .expect("tenure"),
        endpoint_ref(endpoint_value),
        feature(node_incarnation),
    )
    .expect("daemon")
}

fn published_daemon() -> NodeDaemonV1 {
    let mut daemon = daemon(4, 8, 5);
    daemon
        .observe_runtime_host(runtime())
        .expect("observe Runtime");
    daemon.publish_status(5_000_000_000).expect("publish");
    daemon
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
    let compact = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    assert_eq!(compact.len() % 2, 0, "golden hex length");
    compact
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
fn request_and_every_response_outcome_match_exact_goldens() {
    let exact_target = target(4, 8, 5);
    let latest = NodeManagementRequestV1::try_latest([0x11; 16], exact_target).expect("latest");
    let published = published_daemon();
    let status_response = published
        .answer_read_only_v1(&latest)
        .expect("status response");
    let status = status_response.status_value().expect("status payload");
    let cursor = NodeStatusCursorV1::try_from(status).expect("cursor");
    let watch =
        NodeManagementRequestV1::try_watch([0x12; 16], exact_target, cursor).expect("watch");
    let not_modified = published.answer_read_only_v1(&watch).expect("not modified");
    let blank = daemon(4, 8, 5);
    let not_found = blank.answer_read_only_v1(&latest).expect("not found");
    let stale_target = target(3, 7, 5);
    let stale = NodeManagementRequestV1::try_latest([0x13; 16], stale_target).expect("stale");
    let fenced = published.answer_read_only_v1(&stale).expect("fenced");
    let future_cursor =
        NodeStatusCursorV1::try_new(2, Digest32::from_bytes([0x99; 32])).expect("future cursor");
    let future = NodeManagementRequestV1::try_watch([0x14; 16], exact_target, future_cursor)
        .expect("future watch");
    let conflict = published
        .answer_read_only_v1(&future)
        .expect("cursor conflict");

    let fixtures = [
        (
            "LATEST_REQUEST",
            include_str!("fixtures/node_management_latest_request_v1.hex").trim(),
            latest.canonical_wire(),
        ),
        (
            "WATCH_REQUEST",
            include_str!("fixtures/node_management_watch_request_v1.hex").trim(),
            watch.canonical_wire(),
        ),
        (
            "STATUS_RESPONSE",
            include_str!("fixtures/node_management_status_response_v1.hex").trim(),
            status_response.canonical_wire(),
        ),
        (
            "NOT_MODIFIED_RESPONSE",
            include_str!("fixtures/node_management_not_modified_response_v1.hex").trim(),
            not_modified.canonical_wire(),
        ),
        (
            "NOT_FOUND_RESPONSE",
            include_str!("fixtures/node_management_not_found_response_v1.hex").trim(),
            not_found.canonical_wire(),
        ),
        (
            "FENCED_RESPONSE",
            include_str!("fixtures/node_management_fenced_response_v1.hex").trim(),
            fenced.canonical_wire(),
        ),
        (
            "CURSOR_CONFLICT_RESPONSE",
            include_str!("fixtures/node_management_cursor_conflict_response_v1.hex").trim(),
            conflict.canonical_wire(),
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
        panic!("PXN_PROTOCOL_GOLDENS\n{values}");
    }
    for (_, expected, actual) in fixtures {
        assert_eq!(actual, decode_hex(expected));
    }

    assert_eq!(
        NodeManagementRequestV1::decode(latest.canonical_wire()).expect("decode latest"),
        latest
    );
    assert_eq!(
        NodeManagementRequestV1::decode(watch.canonical_wire()).expect("decode watch"),
        watch
    );
    for response in [status_response, not_modified, not_found, fenced, conflict] {
        assert_eq!(
            NodeManagementResponseV1::decode(response.canonical_wire()).expect("decode response"),
            response
        );
    }
}

#[test]
fn latest_and_watch_are_cache_only_and_never_wait_or_publish() {
    let mut daemon = published_daemon();
    let before = daemon.current_status().expect("current").clone();
    let exact_target = target(4, 8, 5);
    let latest = NodeManagementRequestV1::try_latest([0x21; 16], exact_target).expect("latest");
    let response = daemon.answer_read_only_v1(&latest).expect("status");
    assert_eq!(response.outcome(), NodeManagementResponseOutcomeV1::Status);
    assert_eq!(daemon.current_status(), Some(&before));

    let cursor = NodeStatusCursorV1::try_from(&before).expect("cursor");
    let watch =
        NodeManagementRequestV1::try_watch([0x22; 16], exact_target, cursor).expect("watch");
    let response = daemon.answer_read_only_v1(&watch).expect("not modified");
    assert_eq!(
        response.outcome(),
        NodeManagementResponseOutcomeV1::NotModified
    );
    assert_eq!(daemon.current_status(), Some(&before));

    daemon
        .publish_status(5_000_000_000)
        .expect("second publish");
    let response = daemon.answer_read_only_v1(&watch).expect("new status");
    assert_eq!(response.outcome(), NodeManagementResponseOutcomeV1::Status);
    assert_eq!(
        response.status_value().expect("payload").status_sequence(),
        before.status_sequence() + 1
    );
}

#[test]
fn stale_tenure_is_explicitly_fenced_and_cursor_regression_conflicts() {
    let daemon = published_daemon();
    let stale =
        NodeManagementRequestV1::try_latest([0x31; 16], target(3, 7, 5)).expect("stale request");
    let response = daemon.answer_read_only_v1(&stale).expect("fenced response");
    assert_eq!(response.outcome(), NodeManagementResponseOutcomeV1::Fenced);
    assert_eq!(response.current_registration_epoch(), 4);
    assert_eq!(response.current_node_incarnation(), incarnation(8));
    assert!(response.status_value().is_none());

    let ahead =
        NodeStatusCursorV1::try_new(99, Digest32::from_bytes([0x90; 32])).expect("ahead cursor");
    let request = NodeManagementRequestV1::try_watch([0x32; 16], target(4, 8, 5), ahead)
        .expect("ahead watch");
    let response = daemon
        .answer_read_only_v1(&request)
        .expect("cursor conflict");
    assert_eq!(
        response.outcome(),
        NodeManagementResponseOutcomeV1::CursorConflict
    );
    assert!(response.status_value().is_none());
}

#[derive(Debug)]
struct FixedEndpoint {
    calls: usize,
    responses: VecDeque<Box<[u8]>>,
}

impl NodeManagementEndpointV1 for FixedEndpoint {
    fn exchange(
        &mut self,
        _canonical_request: &[u8],
    ) -> Result<Box<[u8]>, NodeManagementEndpointErrorV1> {
        self.calls += 1;
        self.responses
            .pop_front()
            .ok_or(NodeManagementEndpointErrorV1::Unavailable)
    }
}

#[test]
fn typed_client_checks_correlation_fences_replay_and_never_retries() {
    let old_daemon = published_daemon();
    let old_target = target(4, 8, 5);
    let first_request =
        NodeManagementRequestV1::try_latest([0x41; 16], old_target).expect("first request");
    let first_response = old_daemon
        .answer_read_only_v1(&first_request)
        .expect("first response");

    let mut new_daemon = daemon(5, 10, 6);
    new_daemon.publish_status(1_000).expect("new status");
    let new_target = target(5, 10, 6);
    let second_request =
        NodeManagementRequestV1::try_latest([0x42; 16], new_target).expect("second request");
    let second_response = new_daemon
        .answer_read_only_v1(&second_request)
        .expect("second response");
    let replay_request =
        NodeManagementRequestV1::try_latest([0x43; 16], old_target).expect("replay request");
    let replay_response = old_daemon
        .answer_read_only_v1(&replay_request)
        .expect("replay response");

    let endpoint = FixedEndpoint {
        calls: 0,
        responses: VecDeque::from([
            Box::<[u8]>::from(first_response.canonical_wire()),
            Box::<[u8]>::from(second_response.canonical_wire()),
            Box::<[u8]>::from(replay_response.canonical_wire()),
        ]),
    };
    let mut client = NodeManagementClientV1::new(endpoint, node_id());
    assert!(client.latest([0x41; 16], old_target).is_ok());
    assert!(client.latest([0x42; 16], new_target).is_ok());
    assert_eq!(
        client.latest([0x43; 16], old_target),
        Err(NodeManagementClientErrorV1::StatusRejected(
            paraegox_node::NodeContractError::StaleRegistrationEpoch
        ))
    );
    assert_eq!(client.into_endpoint().calls, 3);

    let wrong_request =
        NodeManagementRequestV1::try_latest([0x51; 16], old_target).expect("wrong request");
    let wrong_response = old_daemon
        .answer_read_only_v1(&wrong_request)
        .expect("wrong response");
    let endpoint = FixedEndpoint {
        calls: 0,
        responses: VecDeque::from([Box::<[u8]>::from(wrong_response.canonical_wire())]),
    };
    let mut client = NodeManagementClientV1::new(endpoint, node_id());
    assert_eq!(
        client.latest([0x52; 16], old_target),
        Err(NodeManagementClientErrorV1::CorrelationMismatch)
    );
    assert_eq!(client.into_endpoint().calls, 1);
}

#[test]
fn strict_codec_rejects_resigned_reserved_enum_and_trailing_bytes() {
    let exact_target = target(4, 8, 5);
    let request = NodeManagementRequestV1::try_latest([0x61; 16], exact_target).expect("request");
    assert_eq!(
        request.canonical_wire().len(),
        NODE_MANAGEMENT_REQUEST_BYTES
    );
    let mut noncanonical_request = request.canonical_wire().to_vec();
    noncanonical_request[13] = 1;
    resign_request(&mut noncanonical_request);
    assert_eq!(
        NodeManagementRequestV1::decode(&noncanonical_request),
        Err(NodeManagementProtocolError::NonCanonicalEncoding)
    );

    let daemon = published_daemon();
    let response = daemon.answer_read_only_v1(&request).expect("response");
    assert!(response.canonical_wire().len() <= MAX_NODE_MANAGEMENT_RESPONSE_BYTES);
    let mut unknown_transport = response.canonical_wire().to_vec();
    let nested_runtime_transport = RESPONSE_HEADER_BYTES + 128 + 33;
    unknown_transport[nested_runtime_transport] = 99;
    resign_response(&mut unknown_transport);
    assert_eq!(
        NodeManagementResponseV1::decode(&unknown_transport),
        Err(NodeManagementProtocolError::UnknownEnumValue)
    );

    let mut trailing = response.canonical_wire().to_vec();
    trailing.push(0);
    assert!(matches!(
        NodeManagementResponseV1::decode(&trailing),
        Err(NodeManagementProtocolError::NonCanonicalEncoding)
            | Err(NodeManagementProtocolError::DigestMismatch)
    ));
    assert_eq!(
        NodeManagementResponseV1::decode(&vec![0; MAX_NODE_MANAGEMENT_RESPONSE_BYTES + 1]),
        Err(NodeManagementProtocolError::InvalidFrameLength)
    );
}

#[test]
fn maximum_inventory_and_routes_fit_exactly_one_bounded_response() {
    let mut daemon = daemon(4, 8, 5);
    for host in 1_u8..=8 {
        let route = format!("paraegox/{}/apply", "a".repeat(240));
        assert_eq!(route.len(), 255);
        let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes([host.wrapping_add(10); 16])
                .expect("endpoint ref"),
            RuntimeHostId::from_bytes([host; 16]),
            1,
            &route,
            [host.wrapping_add(20); 16],
            [host.wrapping_add(30); 32],
        )
        .expect("maximum route endpoint");
        let runtime = RuntimeHostStatusV1::try_new(1, 1, RuntimeHostLivenessV1::Live, endpoint)
            .expect("maximum route status");
        daemon
            .observe_runtime_host(runtime)
            .expect("bounded Runtime inventory");
    }
    daemon.publish_status(1_000).expect("bounded status");
    let request =
        NodeManagementRequestV1::try_latest([0x70; 16], target(4, 8, 5)).expect("latest request");
    let response = daemon
        .answer_read_only_v1(&request)
        .expect("maximum response");
    assert_eq!(
        response.canonical_wire().len(),
        MAX_NODE_MANAGEMENT_RESPONSE_BYTES
    );
    assert_eq!(
        NodeManagementResponseV1::decode(response.canonical_wire()).expect("decode maximum"),
        response
    );
}

#[test]
fn endpoint_rejects_cross_target_without_disclosing_an_unrelated_status() {
    let mut daemon = published_daemon();
    let other = NodeManagementTargetV1::try_new(
        NodeId::try_from_bytes([9; 16]).expect("other node"),
        endpoint_ref(5),
        incarnation(8),
        4,
    )
    .expect("other target");
    let request = NodeManagementRequestV1::try_latest([0x71; 16], other).expect("request");
    assert_eq!(
        daemon.exchange(request.canonical_wire()),
        Err(NodeManagementEndpointErrorV1::Unavailable)
    );

    let endpoint = FixedEndpoint {
        calls: 0,
        responses: VecDeque::new(),
    };
    let mut client = NodeManagementClientV1::new(endpoint, node_id());
    assert_eq!(
        client.latest([0x72; 16], other),
        Err(NodeManagementClientErrorV1::InvalidRequest(
            NodeManagementProtocolError::TargetMismatch
        ))
    );
    assert_eq!(client.into_endpoint().calls, 0);
}
