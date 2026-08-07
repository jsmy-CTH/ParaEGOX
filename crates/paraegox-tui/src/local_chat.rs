use core::fmt;

use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTurnId,
};
use paraegox_kernel::digest::Digest32Builder;

use crate::{
    AgentConversationCapability, AgentConversationRequestFactory, BackgroundConversationClient,
    BackgroundConversationClientConfig, ConversationClientError,
};

const LOCAL_CHAT_TURN_ID_DOMAIN: &[u8] = b"paraegox.tui.local-chat.turn-id.sha256.v1";
const LOCAL_CHAT_REQUEST_ID_DOMAIN: &[u8] = b"paraegox.tui.local-chat.request-id.sha256.v1";

/// Exact size of a caller-owned local-chat client-instance nonce.
pub const LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES: usize = 32;

/// Restart-safe, scope-bound Turn and Request identity allocator.
///
/// The caller must supply a fresh nonzero nonce for every new client instance,
/// including every process restart, or restore both the same nonce and a
/// durably advanced sequence. This value is only a deterministic allocator; it
/// is not a persistence, entropy, or lifecycle owner.
#[derive(Debug)]
pub struct LocalChatRequestFactoryV1 {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    client_instance_nonce: [u8; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
    next_sequence: u64,
}

impl LocalChatRequestFactoryV1 {
    pub fn try_new(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        client_instance_nonce: [u8; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
        initial_sequence: u64,
    ) -> Result<Self, LocalChatRequestFactoryError> {
        if client_instance_nonce.iter().all(|byte| *byte == 0) {
            return Err(LocalChatRequestFactoryError::ZeroClientInstanceNonce);
        }
        if initial_sequence == 0 {
            return Err(LocalChatRequestFactoryError::InitialSequenceZero);
        }
        Ok(Self {
            deck_run_id,
            session_id,
            client_instance_nonce,
            next_sequence: initial_sequence,
        })
    }

    #[must_use]
    pub const fn deck_run_id(&self) -> AgentConversationDeckRunId {
        self.deck_run_id
    }

    #[must_use]
    pub const fn session_id(&self) -> AgentConversationSessionId {
        self.session_id
    }

    /// Returns `None` after the final `u64::MAX` sequence was allocated.
    #[must_use]
    pub const fn next_sequence(&self) -> Option<u64> {
        if self.next_sequence == 0 {
            None
        } else {
            Some(self.next_sequence)
        }
    }

    fn identity_bytes(
        &self,
        domain: &[u8],
        sequence: u64,
    ) -> Result<[u8; 16], ConversationClientError> {
        let mut builder = Digest32Builder::try_new(domain)
            .map_err(|_| ConversationClientError::new("local-chat identity domain is invalid"))?;
        builder
            .field_bytes(self.deck_run_id.as_bytes())
            .and_then(|builder| builder.field_bytes(self.session_id.as_bytes()))
            .and_then(|builder| builder.field_bytes(&self.client_instance_nonce))
            .and_then(|builder| builder.field_u64(sequence))
            .map_err(|_| ConversationClientError::new("local-chat identity derivation failed"))?;
        let digest = builder.finish();
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ConversationClientError::new(
                "local-chat identity derivation produced an invalid identity",
            ));
        }
        Ok(bytes)
    }
}

impl AgentConversationRequestFactory for LocalChatRequestFactoryV1 {
    fn create_request(
        &mut self,
        input: &str,
        deadline_budget_nanos: u64,
    ) -> Result<AgentConversationRequestV1, ConversationClientError> {
        let sequence = self.next_sequence().ok_or_else(|| {
            ConversationClientError::new("local-chat request identity space is exhausted")
        })?;
        let turn_id = AgentConversationTurnId::try_from_bytes(
            self.identity_bytes(LOCAL_CHAT_TURN_ID_DOMAIN, sequence)?,
        )
        .map_err(|_| ConversationClientError::new("local-chat Turn identity is invalid"))?;
        let request_id = AgentConversationRequestId::try_from_bytes(
            self.identity_bytes(LOCAL_CHAT_REQUEST_ID_DOMAIN, sequence)?,
        )
        .map_err(|_| ConversationClientError::new("local-chat Request identity is invalid"))?;
        let request = AgentConversationRequestV1::try_new(
            self.deck_run_id,
            self.session_id,
            turn_id,
            request_id,
            deadline_budget_nanos,
            input,
        )
        .map_err(|_| {
            ConversationClientError::new("local-chat input or deadline is outside protocol bounds")
        })?;
        self.next_sequence = sequence.checked_add(1).unwrap_or(0);
        Ok(request)
    }
}

/// Invalid caller-owned identity allocation inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalChatRequestFactoryError {
    ZeroClientInstanceNonce,
    InitialSequenceZero,
}

impl fmt::Display for LocalChatRequestFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroClientInstanceNonce => "local-chat client-instance nonce is zero",
            Self::InitialSequenceZero => "local-chat initial request sequence is zero",
        })
    }
}

impl std::error::Error for LocalChatRequestFactoryError {}

/// Production local-chat composition failure before terminal UI entry.
#[derive(Debug)]
pub enum LocalChatCompositionError {
    RequestFactory(LocalChatRequestFactoryError),
    Client(ConversationClientError),
}

impl fmt::Display for LocalChatCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestFactory(error) => {
                write!(formatter, "request identity setup failed: {error}")
            }
            Self::Client(error) => write!(formatter, "conversation adapter setup failed: {error}"),
        }
    }
}

impl std::error::Error for LocalChatCompositionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RequestFactory(error) => Some(error),
            Self::Client(error) => Some(error),
        }
    }
}

impl From<LocalChatRequestFactoryError> for LocalChatCompositionError {
    fn from(value: LocalChatRequestFactoryError) -> Self {
        Self::RequestFactory(value)
    }
}

impl From<ConversationClientError> for LocalChatCompositionError {
    fn from(value: ConversationClientError) -> Self {
        Self::Client(value)
    }
}

/// Builds the synchronous local TUI client from one Runtime-issued capability.
///
/// This function starts only the bounded adapter worker. It does not create a
/// Fabric or Zenoh session, install a route, start AgentService, or own Runtime
/// lifecycle. Those resources must already be represented by `capability`.
pub fn compose_local_chat_client(
    config: BackgroundConversationClientConfig,
    client_instance_nonce: [u8; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
    initial_sequence: u64,
    capability: impl AgentConversationCapability,
) -> Result<BackgroundConversationClient, LocalChatCompositionError> {
    let request_factory = LocalChatRequestFactoryV1::try_new(
        config.deck_run_id(),
        config.session_id(),
        client_instance_nonce,
        initial_sequence,
    )?;
    BackgroundConversationClient::spawn(config, request_factory, capability).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use core::future;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use paraegox_agent_contracts::AgentConversationTerminalV1;
    use paraegox_agent_contracts::control::{
        AgentConversationCancelStateV1, AgentConversationOpenOutcomeV1,
    };

    use super::*;
    use crate::{
        AgentConversationCapabilityFuture, ConversationClient, ConversationClientEvent,
        ConversationConnectionState,
    };

    const DEADLINE_NANOS: u64 = 1_000_000_000;

    fn scope() -> (AgentConversationDeckRunId, AgentConversationSessionId) {
        (
            AgentConversationDeckRunId::try_from_bytes([0x51; 16]).expect("DeckRun"),
            AgentConversationSessionId::try_from_bytes([0x52; 16]).expect("Session"),
        )
    }

    fn factory(
        nonce: [u8; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
        sequence: u64,
    ) -> LocalChatRequestFactoryV1 {
        let (deck_run_id, session_id) = scope();
        LocalChatRequestFactoryV1::try_new(deck_run_id, session_id, nonce, sequence)
            .expect("request factory")
    }

    #[test]
    fn identities_are_stable_domain_separated_and_sequence_unique() {
        let mut left = factory([0x61; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES], 7);
        let mut same = factory([0x61; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES], 7);
        let first = left
            .create_request("hello", DEADLINE_NANOS)
            .expect("first request");
        let same_first = same
            .create_request("hello", DEADLINE_NANOS)
            .expect("same request");
        let second = left
            .create_request("hello", DEADLINE_NANOS)
            .expect("second request");
        let different_instance = factory([0x64; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES], 7)
            .create_request("hello", DEADLINE_NANOS)
            .expect("different client instance");

        assert_eq!(first, same_first);
        assert_eq!(
            first.turn_id().as_bytes(),
            &[
                0xa9, 0xe3, 0x3f, 0x8b, 0x02, 0x3b, 0xd8, 0x1b, 0xf8, 0x70, 0xa2, 0x59, 0xd3, 0x1f,
                0x8d, 0x2f,
            ]
        );
        assert_eq!(
            first.request_id().as_bytes(),
            &[
                0xdd, 0x7b, 0x48, 0x4a, 0xa8, 0xb1, 0x04, 0x9f, 0x90, 0x6f, 0xeb, 0xc3, 0x76, 0x84,
                0x7a, 0xe4,
            ]
        );
        assert_ne!(first.turn_id().as_bytes(), first.request_id().as_bytes());
        assert_ne!(first.turn_id(), second.turn_id());
        assert_ne!(first.request_id(), second.request_id());
        assert_ne!(first.request_id(), different_instance.request_id());
        assert_eq!(left.next_sequence(), Some(9));
    }

    #[test]
    fn invalid_request_does_not_advance_and_final_sequence_is_usable_once() {
        let nonce = [0x62; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES];
        let mut candidate = factory(nonce, u64::MAX);
        assert!(candidate.create_request("invalid", 0).is_err());
        assert_eq!(candidate.next_sequence(), Some(u64::MAX));
        let request = candidate
            .create_request("last", DEADLINE_NANOS)
            .expect("last identity");
        assert_eq!(candidate.next_sequence(), None);
        assert!(
            candidate
                .create_request("exhausted", DEADLINE_NANOS)
                .is_err()
        );

        let mut reference = factory(nonce, u64::MAX);
        assert_eq!(
            request,
            reference
                .create_request("last", DEADLINE_NANOS)
                .expect("reference identity")
        );
    }

    #[test]
    fn factory_rejects_ambiguous_restart_inputs() {
        let (deck_run_id, session_id) = scope();
        assert_eq!(
            LocalChatRequestFactoryV1::try_new(
                deck_run_id,
                session_id,
                [0; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
                1,
            )
            .expect_err("zero nonce"),
            LocalChatRequestFactoryError::ZeroClientInstanceNonce
        );
        assert_eq!(
            LocalChatRequestFactoryV1::try_new(
                deck_run_id,
                session_id,
                [1; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
                0,
            )
            .expect_err("zero sequence"),
            LocalChatRequestFactoryError::InitialSequenceZero
        );
    }

    #[derive(Default)]
    struct CapabilityState {
        submitted: Option<AgentConversationRequestV1>,
        closed: bool,
    }

    struct ReadyCapability(Arc<Mutex<CapabilityState>>);

    impl AgentConversationCapability for ReadyCapability {
        fn open_session(
            &mut self,
            _deck_run_id: AgentConversationDeckRunId,
            _session_id: AgentConversationSessionId,
            _timeout: Duration,
        ) -> AgentConversationCapabilityFuture<AgentConversationOpenOutcomeV1> {
            Box::pin(async { Ok(AgentConversationOpenOutcomeV1::Opened) })
        }

        fn submit(
            &mut self,
            request: AgentConversationRequestV1,
            _timeout: Duration,
        ) -> AgentConversationCapabilityFuture<AgentConversationTerminalV1> {
            self.0.lock().expect("capability state").submitted = Some(request.clone());
            let terminal =
                AgentConversationTerminalV1::try_success(&request, "ready").expect("terminal");
            Box::pin(async move { Ok(terminal) })
        }

        fn cancel(
            &mut self,
            _deck_run_id: AgentConversationDeckRunId,
            _session_id: AgentConversationSessionId,
            _request: AgentConversationRequestId,
            _timeout: Duration,
        ) -> AgentConversationCapabilityFuture<AgentConversationCancelStateV1> {
            Box::pin(future::ready(Ok(
                AgentConversationCancelStateV1::IntentRecorded,
            )))
        }

        fn close(&mut self, _timeout: Duration) -> AgentConversationCapabilityFuture<()> {
            self.0.lock().expect("capability state").closed = true;
            Box::pin(future::ready(Ok(())))
        }
    }

    #[test]
    fn composition_uses_injected_capability_without_owning_transport() {
        let state = Arc::new(Mutex::new(CapabilityState::default()));
        let (deck_run_id, session_id) = scope();
        let config = BackgroundConversationClientConfig::try_new(
            deck_run_id,
            session_id,
            2,
            Duration::from_secs(1),
        )
        .expect("config");
        let mut client = compose_local_chat_client(
            config,
            [0x63; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
            1,
            ReadyCapability(Arc::clone(&state)),
        )
        .expect("composition");

        client.begin_connect().expect("connect");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(ConversationClientEvent::ConnectionChanged(
                ConversationConnectionState::Connected,
            )) = client.poll_event().expect("connection event")
            {
                break;
            }
            assert!(Instant::now() < deadline, "connection timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
        let request = client
            .submit_turn("production seam", DEADLINE_NANOS)
            .expect("submit");
        loop {
            if let Some(ConversationClientEvent::Terminal(terminal)) =
                client.poll_event().expect("terminal event")
            {
                assert!(terminal.correlates(&request));
                break;
            }
            assert!(Instant::now() < deadline, "terminal timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
        client.close().expect("joined close");

        let state = state.lock().expect("capability state");
        assert_eq!(state.submitted.as_ref(), Some(&request));
        assert!(state.closed);
    }
}
