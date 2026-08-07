use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationControlBodyV1, AgentConversationControlError,
    AgentConversationControlV1, AgentConversationGetStateV1, AgentConversationOpenOutcomeV1,
    AgentConversationWatchBatchV1, AgentConversationWatchEventKindV1,
    AgentConversationWatchEventV1, MAX_AGENT_CONVERSATION_WATCH_EVENTS,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationProtocolError, AgentConversationRequestId,
    AgentConversationRequestV1, AgentConversationSessionId, AgentConversationTerminalV1,
    AgentConversationTurnId,
};

const OPEN_REQUEST_WIRE_HEX: &str = concat!(
    "5058414300010080000000800300000000000000",
    "44444444444444444444444444444444",
    "11111111111111111111111111111111",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "43aec8b758e56091d025f7e70080fcc4d6b479bdd883084350e0d344e5775ec6",
    "000000000000000000000000",
);
const GET_PENDING_CANCEL_WIRE_HEX: &str = concat!(
    "5058414300010080000000800603000000000000",
    "44444444444444444444444444444444",
    "11111111111111111111111111111111",
    "00000000000000000000000000000000",
    "33333333333333333333333333333333",
    "8e34a6ad16173b0b86506a17ab1b7d8e2d061d8308a4af366cd2b03764254de4",
    "000000000000000000000000",
);
const WATCH_REQUEST_WIRE_HEX: &str = concat!(
    "50584143000100800000008c0700000000000000",
    "44444444444444444444444444444444",
    "11111111111111111111111111111111",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "a26fb51e56197a4417ecac0926a06ec657f8058b5daed56b15aec3aa5e8a91f4",
    "00000000000000000000000c",
    "000000000000000700000008",
);
const CANCEL_INTENT_WIRE_HEX: &str = concat!(
    "5058414300010080000000800a02000000000000",
    "44444444444444444444444444444444",
    "11111111111111111111111111111111",
    "00000000000000000000000000000000",
    "33333333333333333333333333333333",
    "663d9bcd48eecfe54117cfe7d083a5bc696ca4647c3dd85317395d1f44a76ca5",
    "000000000000000000000000",
);

fn deck() -> AgentConversationDeckRunId {
    AgentConversationDeckRunId::try_from_bytes([0x44; 16]).expect("DeckRun id")
}

fn session() -> AgentConversationSessionId {
    AgentConversationSessionId::try_from_bytes([0x11; 16]).expect("Session id")
}

fn request_id() -> AgentConversationRequestId {
    AgentConversationRequestId::try_from_bytes([0x33; 16]).expect("Request id")
}

fn request() -> AgentConversationRequestV1 {
    AgentConversationRequestV1::try_new(
        deck(),
        session(),
        AgentConversationTurnId::try_from_bytes([0x22; 16]).expect("Turn id"),
        request_id(),
        5_000_000_000,
        "hello, ParaEGOX",
    )
    .expect("request")
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[test]
fn all_control_operations_round_trip_without_reinterpreting_turn_frames() {
    let terminal =
        AgentConversationTerminalV1::try_success(&request(), "echo: hello").expect("terminal");
    let watch_batch = AgentConversationWatchBatchV1::try_new(
        vec![
            AgentConversationWatchEventV1::try_new(
                1,
                AgentConversationWatchEventKindV1::SessionOpened,
            )
            .expect("opened event"),
            AgentConversationWatchEventV1::try_new(
                2,
                AgentConversationWatchEventKindV1::RequestAccepted(request()),
            )
            .expect("accepted event"),
            AgentConversationWatchEventV1::try_new(
                3,
                AgentConversationWatchEventKindV1::CancelIntentRecorded(request_id()),
            )
            .expect("cancel event"),
            AgentConversationWatchEventV1::try_new(
                4,
                AgentConversationWatchEventKindV1::TerminalCommitted(terminal.clone()),
            )
            .expect("terminal event"),
        ]
        .into_boxed_slice(),
        4,
        5,
        true,
        false,
    )
    .expect("watch batch");
    let values = [
        AgentConversationControlV1::open_request(deck(), session()),
        AgentConversationControlV1::open_result(
            deck(),
            session(),
            AgentConversationOpenOutcomeV1::Opened,
        ),
        AgentConversationControlV1::get_request(deck(), session(), request_id()),
        AgentConversationControlV1::get_result(
            deck(),
            session(),
            request_id(),
            AgentConversationGetStateV1::Pending {
                cancel_requested: true,
            },
        )
        .expect("get pending"),
        AgentConversationControlV1::get_result(
            deck(),
            session(),
            request_id(),
            AgentConversationGetStateV1::Terminal(terminal.clone()),
        )
        .expect("get terminal"),
        AgentConversationControlV1::watch_request(deck(), session(), 0, 8).expect("watch request"),
        AgentConversationControlV1::watch_result(deck(), session(), watch_batch)
            .expect("watch result"),
        AgentConversationControlV1::cancel_request(deck(), session(), request_id()),
        AgentConversationControlV1::cancel_result(
            deck(),
            session(),
            request_id(),
            AgentConversationCancelStateV1::IntentRecorded,
        )
        .expect("cancel result"),
        AgentConversationControlV1::cancel_result(
            deck(),
            session(),
            request_id(),
            AgentConversationCancelStateV1::Terminal(terminal),
        )
        .expect("cancel terminal"),
    ];
    for value in values {
        let wire = value.canonical_wire().expect("control wire");
        assert_eq!(AgentConversationControlV1::decode(&wire), Ok(value));
        assert_eq!(
            AgentConversationRequestV1::decode(&wire),
            Err(AgentConversationProtocolError::UnknownFrameKind)
        );
        assert_eq!(
            AgentConversationTerminalV1::decode(&wire),
            Err(AgentConversationProtocolError::UnknownFrameKind)
        );
    }
}

#[test]
fn control_decoder_fails_closed_on_kind_digest_reserved_and_correlation() {
    let canonical = AgentConversationControlV1::get_request(deck(), session(), request_id())
        .canonical_wire()
        .expect("wire");

    let mut old_kind = canonical.to_vec();
    old_kind[12] = 1;
    assert_eq!(
        AgentConversationControlV1::decode(&old_kind),
        Err(AgentConversationControlError::UnknownFrameKind)
    );

    let mut digest = canonical.to_vec();
    digest[84] ^= 1;
    assert_eq!(
        AgentConversationControlV1::decode(&digest),
        Err(AgentConversationControlError::DigestMismatch)
    );

    let mut reserved_turn = canonical.to_vec();
    reserved_turn[52] = 1;
    assert_eq!(
        AgentConversationControlV1::decode(&reserved_turn),
        Err(AgentConversationControlError::ReservedBitsSet)
    );

    let terminal = AgentConversationTerminalV1::try_success(&request(), "echo").expect("terminal");
    assert_eq!(
        AgentConversationControlV1::get_result(
            AgentConversationDeckRunId::try_from_bytes([9; 16]).expect("other DeckRun"),
            session(),
            request_id(),
            AgentConversationGetStateV1::Terminal(terminal),
        ),
        Err(AgentConversationControlError::CorrelationMismatch)
    );
}

#[test]
fn watch_batches_are_finite_contiguous_and_bounded() {
    assert_eq!(
        AgentConversationControlV1::watch_request(deck(), session(), 0, 0),
        Err(AgentConversationControlError::WatchLimitOutOfRange)
    );
    assert_eq!(
        AgentConversationControlV1::watch_request(
            deck(),
            session(),
            0,
            u32::try_from(MAX_AGENT_CONVERSATION_WATCH_EVENTS + 1).expect("small bound"),
        ),
        Err(AgentConversationControlError::WatchLimitOutOfRange)
    );
    let events = vec![
        AgentConversationWatchEventV1::try_new(1, AgentConversationWatchEventKindV1::SessionOpened)
            .expect("event"),
        AgentConversationWatchEventV1::try_new(3, AgentConversationWatchEventKindV1::SessionSealed)
            .expect("event"),
    ];
    assert_eq!(
        AgentConversationWatchBatchV1::try_new(events.into_boxed_slice(), 3, 3, false, true),
        Err(AgentConversationControlError::InvalidWatchSequence)
    );

    let wrong_first = AgentConversationWatchBatchV1::try_new(
        vec![
            AgentConversationWatchEventV1::try_new(
                3,
                AgentConversationWatchEventKindV1::SessionSealed,
            )
            .expect("event"),
        ]
        .into_boxed_slice(),
        3,
        3,
        false,
        true,
    )
    .expect("standalone batch");
    assert_eq!(
        wrong_first.validate_for_request(1, 1),
        Err(AgentConversationControlError::InvalidWatchSequence)
    );

    let empty_wrong_cursor =
        AgentConversationWatchBatchV1::try_new(Box::new([]), 2, 2, false, false)
            .expect("standalone empty batch");
    assert_eq!(
        empty_wrong_cursor.validate_for_request(1, 1),
        Err(AgentConversationControlError::InvalidWatchSequence)
    );
}

#[test]
fn rust_control_codec_matches_python_golden_vectors() {
    let open = AgentConversationControlV1::open_request(deck(), session());
    let get = AgentConversationControlV1::get_result(
        deck(),
        session(),
        request_id(),
        AgentConversationGetStateV1::Pending {
            cancel_requested: true,
        },
    )
    .expect("get result");
    let watch =
        AgentConversationControlV1::watch_request(deck(), session(), 7, 8).expect("watch request");
    let cancel = AgentConversationControlV1::cancel_result(
        deck(),
        session(),
        request_id(),
        AgentConversationCancelStateV1::IntentRecorded,
    )
    .expect("cancel result");
    assert_eq!(
        lower_hex(&open.canonical_wire().expect("open")),
        OPEN_REQUEST_WIRE_HEX
    );
    assert_eq!(
        lower_hex(&get.canonical_wire().expect("get")),
        GET_PENDING_CANCEL_WIRE_HEX
    );
    assert_eq!(
        lower_hex(&watch.canonical_wire().expect("watch")),
        WATCH_REQUEST_WIRE_HEX
    );
    assert_eq!(
        lower_hex(&cancel.canonical_wire().expect("cancel")),
        CANCEL_INTENT_WIRE_HEX
    );
    assert!(matches!(
        open.body(),
        AgentConversationControlBodyV1::OpenRequest
    ));
}
