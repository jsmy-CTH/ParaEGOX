use paraegox_agent_contracts::{
    AGENT_CONVERSATION_PROTOCOL_VERSION, AgentConversationDeckRunId,
    AgentConversationProtocolError, AgentConversationRequestAcceptanceV1,
    AgentConversationRequestId, AgentConversationRequestRegistryV1, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalFailureV1,
    AgentConversationTerminalResultV1, AgentConversationTerminalV1, AgentConversationTurnId,
};

const REQUEST_DIGEST_HEX: &str = "19d46e69b3fea496d44ee43f631d0791797cc3689ddeaac3708862bee308df9a";
const REQUEST_WIRE_HEX: &str = concat!(
    "50584143000100800000008f0100000000000000",
    "44444444444444444444444444444444",
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
    "33333333333333333333333333333333",
    "19d46e69b3fea496d44ee43f631d0791797cc3689ddeaac3708862bee308df9a",
    "000000012a05f2000000000f",
    "68656c6c6f2c205061726145474f58",
);
const TERMINAL_WIRE_HEX: &str = concat!(
    "5058414300010080000000950201000000000000",
    "44444444444444444444444444444444",
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
    "33333333333333333333333333333333",
    "19d46e69b3fea496d44ee43f631d0791797cc3689ddeaac3708862bee308df9a",
    "000000012a05f20000000015",
    "6563686f3a2068656c6c6f2c205061726145474f58",
);
const UNCERTAIN_TERMINAL_WIRE_HEX: &str = concat!(
    "5058414300010080000000800202000500000000",
    "44444444444444444444444444444444",
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
    "33333333333333333333333333333333",
    "19d46e69b3fea496d44ee43f631d0791797cc3689ddeaac3708862bee308df9a",
    "000000012a05f20000000000",
);

fn request(input: &str) -> AgentConversationRequestV1 {
    AgentConversationRequestV1::try_new(
        AgentConversationDeckRunId::try_from_bytes([0x44; 16]).expect("deck run id"),
        AgentConversationSessionId::try_from_bytes([0x11; 16]).expect("session id"),
        AgentConversationTurnId::try_from_bytes([0x22; 16]).expect("turn id"),
        AgentConversationRequestId::try_from_bytes([0x33; 16]).expect("request id"),
        5_000_000_000,
        input,
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
fn rust_producer_matches_the_language_neutral_golden_vectors() {
    let request = request("hello, ParaEGOX");
    assert_eq!(
        lower_hex(request.request_digest().as_bytes()),
        REQUEST_DIGEST_HEX
    );
    assert_eq!(lower_hex(&request.canonical_wire()), REQUEST_WIRE_HEX);

    let terminal = AgentConversationTerminalV1::try_success(&request, "echo: hello, ParaEGOX")
        .expect("terminal");
    assert_eq!(lower_hex(&terminal.canonical_wire()), TERMINAL_WIRE_HEX);

    let uncertain = AgentConversationTerminalV1::failure(
        &request,
        AgentConversationTerminalFailureV1::ModelOutcomeUncertain,
    );
    assert_eq!(
        lower_hex(&uncertain.canonical_wire()),
        UNCERTAIN_TERMINAL_WIRE_HEX
    );
}

#[test]
fn producer_and_semantic_consumer_prove_replay_and_conflict() {
    let produced = request("hello, ParaEGOX");
    let consumed = AgentConversationRequestV1::decode(&produced.canonical_wire())
        .expect("consumer must accept producer bytes");
    assert_eq!(consumed, produced);

    let mut registry = AgentConversationRequestRegistryV1::new();
    assert_eq!(
        registry.accept(&consumed).expect("first admission"),
        AgentConversationRequestAcceptanceV1::Accepted
    );
    assert_eq!(
        registry.accept(&consumed).expect("pending replay"),
        AgentConversationRequestAcceptanceV1::PendingReplay
    );

    let terminal = AgentConversationTerminalV1::try_success(&consumed, "echo: hello, ParaEGOX")
        .expect("terminal");
    let committed = registry
        .commit_terminal(terminal.clone())
        .expect("terminal commit");
    assert_eq!(committed, terminal);
    assert_eq!(
        registry.accept(&consumed).expect("terminal replay"),
        AgentConversationRequestAcceptanceV1::TerminalReplay(terminal.clone())
    );
    assert_eq!(
        registry
            .commit_terminal(terminal.clone())
            .expect("same terminal commit"),
        terminal
    );

    let conflict = request("different bytes");
    assert_eq!(conflict.request_id(), consumed.request_id());
    assert_ne!(conflict.request_digest(), consumed.request_digest());
    assert_eq!(
        registry.accept(&conflict).expect("conflict is typed"),
        AgentConversationRequestAcceptanceV1::Conflict
    );
}

#[test]
fn decoder_fails_closed_on_version_reserved_and_digest_changes() {
    let canonical = request("hello, ParaEGOX").canonical_wire();

    let mut version = canonical.to_vec();
    version[4..6].copy_from_slice(&(AGENT_CONVERSATION_PROTOCOL_VERSION + 1).to_be_bytes());
    assert_eq!(
        AgentConversationRequestV1::decode(&version),
        Err(AgentConversationProtocolError::UnsupportedVersion)
    );

    let mut reserved = canonical.to_vec();
    reserved[19] = 1;
    assert_eq!(
        AgentConversationRequestV1::decode(&reserved),
        Err(AgentConversationProtocolError::ReservedBitsSet)
    );

    let mut digest = canonical.to_vec();
    digest[84] ^= 1;
    assert_eq!(
        AgentConversationRequestV1::decode(&digest),
        Err(AgentConversationProtocolError::RequestDigestMismatch)
    );

    let mut extra = canonical.to_vec();
    extra.push(0);
    assert_eq!(
        AgentConversationRequestV1::decode(&extra),
        Err(AgentConversationProtocolError::InvalidFrameLength)
    );
}

#[test]
fn registry_scopes_request_identity_by_deck_run_and_session() {
    let base = request("same bytes");
    let another_session = AgentConversationRequestV1::try_new(
        base.deck_run_id(),
        AgentConversationSessionId::try_from_bytes([0x55; 16]).expect("session id"),
        base.turn_id(),
        base.request_id(),
        base.deadline_budget_nanos(),
        base.input(),
    )
    .expect("other session request");
    let another_deck_run = AgentConversationRequestV1::try_new(
        AgentConversationDeckRunId::try_from_bytes([0x66; 16]).expect("deck run id"),
        base.session_id(),
        base.turn_id(),
        base.request_id(),
        base.deadline_budget_nanos(),
        base.input(),
    )
    .expect("other deck run request");

    let mut registry = AgentConversationRequestRegistryV1::new();
    for scoped in [&base, &another_session, &another_deck_run] {
        assert_eq!(
            registry.accept(scoped).expect("scoped request"),
            AgentConversationRequestAcceptanceV1::Accepted
        );
    }
    assert_eq!(registry.len(), 3);
}

#[test]
fn terminal_consumer_preserves_exact_request_correlation() {
    let request = request("hello, ParaEGOX");
    let terminal =
        AgentConversationTerminalV1::try_success(&request, "你好").expect("UTF-8 terminal");
    let decoded =
        AgentConversationTerminalV1::decode(&terminal.canonical_wire()).expect("terminal decode");
    assert!(decoded.correlates(&request));
    assert_eq!(
        decoded.result(),
        &AgentConversationTerminalResultV1::Success("你好".into())
    );
}
