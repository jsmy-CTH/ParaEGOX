//! Additive control frames for the accepted AgentConversationProtocol v1.
//!
//! Request and terminal kinds `1` and `2` remain byte-for-byte unchanged. This
//! module owns only the explicitly separate open/get/watch/cancel kinds `3` to
//! `10`; the original request and terminal decoders continue to reject them.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};

use crate::{
    AGENT_CONVERSATION_HEADER_BYTES, AGENT_CONVERSATION_PROTOCOL_MAGIC,
    AGENT_CONVERSATION_PROTOCOL_VERSION, AgentConversationDeckRunId,
    AgentConversationProtocolError, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalV1,
};

/// Maximum encoded control payload. A watch response is always a finite batch.
pub const MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum number of events in one watch response.
pub const MAX_AGENT_CONVERSATION_WATCH_EVENTS: usize = 32;
/// Maximum complete additive control frame.
pub const MAX_AGENT_CONVERSATION_CONTROL_FRAME_BYTES: usize =
    AGENT_CONVERSATION_HEADER_BYTES + MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES;

const CONTROL_DIGEST_DOMAIN: &[u8] = b"paraegox.agent.conversation.control.sha256.v1";
const ZERO_ID: [u8; 16] = [0; 16];
const OPEN_REQUEST_KIND: u8 = 3;
const OPEN_RESULT_KIND: u8 = 4;
const GET_REQUEST_KIND: u8 = 5;
const GET_RESULT_KIND: u8 = 6;
const WATCH_REQUEST_KIND: u8 = 7;
const WATCH_RESULT_KIND: u8 = 8;
const CANCEL_REQUEST_KIND: u8 = 9;
const CANCEL_RESULT_KIND: u8 = 10;
const REQUEST_OUTCOME: u8 = 0;
const WATCH_BATCH_HEADER_BYTES: usize = 24;
const WATCH_EVENT_HEADER_BYTES: usize = 16;

/// Idempotent result of an explicit session-open request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AgentConversationOpenOutcomeV1 {
    Opened = 1,
    Existing = 2,
    DeckRunSealed = 3,
    CapacityExhausted = 4,
}

/// Explicit get result for one request identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentConversationGetStateV1 {
    NotFound,
    Pending { cancel_requested: bool },
    Terminal(AgentConversationTerminalV1),
}

/// Explicit cancellation result. Intent outcomes never claim provider preemption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentConversationCancelStateV1 {
    NotFound,
    IntentRecorded,
    IntentAlreadyRecorded,
    SessionSealed,
    Terminal(AgentConversationTerminalV1),
}

/// One retained AgentService event carried by a finite watch batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentConversationWatchEventKindV1 {
    SessionOpened,
    RequestAccepted(AgentConversationRequestV1),
    TerminalCommitted(AgentConversationTerminalV1),
    CancelIntentRecorded(AgentConversationRequestId),
    SessionSealed,
}

/// One monotonically sequenced watch event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentConversationWatchEventV1 {
    sequence: u64,
    kind: AgentConversationWatchEventKindV1,
}

impl AgentConversationWatchEventV1 {
    pub fn try_new(
        sequence: u64,
        kind: AgentConversationWatchEventKindV1,
    ) -> Result<Self, AgentConversationControlError> {
        if sequence == 0 {
            return Err(AgentConversationControlError::InvalidWatchSequence);
        }
        Ok(Self { sequence, kind })
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn kind(&self) -> &AgentConversationWatchEventKindV1 {
        &self.kind
    }
}

/// Bounded cursor response. `next_cursor` is the last returned sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentConversationWatchBatchV1 {
    events: Box<[AgentConversationWatchEventV1]>,
    next_cursor: u64,
    high_watermark: u64,
    has_more: bool,
    sealed: bool,
}

impl AgentConversationWatchBatchV1 {
    pub fn try_new(
        events: Box<[AgentConversationWatchEventV1]>,
        next_cursor: u64,
        high_watermark: u64,
        has_more: bool,
        sealed: bool,
    ) -> Result<Self, AgentConversationControlError> {
        validate_watch_batch_shape(&events, next_cursor, high_watermark, has_more)?;
        Ok(Self {
            events,
            next_cursor,
            high_watermark,
            has_more,
            sealed,
        })
    }

    #[must_use]
    pub fn events(&self) -> &[AgentConversationWatchEventV1] {
        &self.events
    }

    #[must_use]
    pub const fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    #[must_use]
    pub const fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Validates cursor semantics relative to the originating watch request.
    /// A standalone response frame cannot prove these request-relative facts,
    /// so every request/response adapter must call this method.
    pub fn validate_for_request(
        &self,
        cursor: u64,
        limit: u32,
    ) -> Result<(), AgentConversationControlError> {
        validate_watch_limit(limit)?;
        let limit = usize::try_from(limit)
            .map_err(|_| AgentConversationControlError::WatchLimitOutOfRange)?;
        if self.events.len() > limit {
            return Err(AgentConversationControlError::InvalidWatchBatch);
        }
        match self.events.first() {
            Some(first)
                if cursor.checked_add(1) != Some(first.sequence)
                    || self
                        .events
                        .last()
                        .map(AgentConversationWatchEventV1::sequence)
                        != Some(self.next_cursor) =>
            {
                Err(AgentConversationControlError::InvalidWatchSequence)
            }
            None if self.next_cursor != cursor => {
                Err(AgentConversationControlError::InvalidWatchSequence)
            }
            _ => Ok(()),
        }
    }
}

/// Typed body of one control frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentConversationControlBodyV1 {
    OpenRequest,
    OpenResult(AgentConversationOpenOutcomeV1),
    GetRequest,
    GetResult(AgentConversationGetStateV1),
    WatchRequest { cursor: u64, limit: u32 },
    WatchResultNotFound,
    WatchResult(AgentConversationWatchBatchV1),
    CancelRequest,
    CancelResult(AgentConversationCancelStateV1),
}

/// Canonical additive control frame with DeckRun/Session correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentConversationControlV1 {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_id: Option<AgentConversationRequestId>,
    body: AgentConversationControlBodyV1,
}

impl AgentConversationControlV1 {
    #[must_use]
    pub const fn open_request(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
    ) -> Self {
        Self::without_request(
            deck_run_id,
            session_id,
            AgentConversationControlBodyV1::OpenRequest,
        )
    }

    #[must_use]
    pub const fn open_result(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        outcome: AgentConversationOpenOutcomeV1,
    ) -> Self {
        Self::without_request(
            deck_run_id,
            session_id,
            AgentConversationControlBodyV1::OpenResult(outcome),
        )
    }

    #[must_use]
    pub const fn get_request(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    ) -> Self {
        Self::with_request(
            deck_run_id,
            session_id,
            request_id,
            AgentConversationControlBodyV1::GetRequest,
        )
    }

    pub fn get_result(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        state: AgentConversationGetStateV1,
    ) -> Result<Self, AgentConversationControlError> {
        if let AgentConversationGetStateV1::Terminal(terminal) = &state {
            validate_terminal_correlation(deck_run_id, session_id, request_id, terminal)?;
        }
        Ok(Self::with_request(
            deck_run_id,
            session_id,
            request_id,
            AgentConversationControlBodyV1::GetResult(state),
        ))
    }

    pub fn watch_request(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        cursor: u64,
        limit: u32,
    ) -> Result<Self, AgentConversationControlError> {
        validate_watch_limit(limit)?;
        Ok(Self::without_request(
            deck_run_id,
            session_id,
            AgentConversationControlBodyV1::WatchRequest { cursor, limit },
        ))
    }

    #[must_use]
    pub const fn watch_result_not_found(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
    ) -> Self {
        Self::without_request(
            deck_run_id,
            session_id,
            AgentConversationControlBodyV1::WatchResultNotFound,
        )
    }

    pub fn watch_result(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        batch: AgentConversationWatchBatchV1,
    ) -> Result<Self, AgentConversationControlError> {
        validate_watch_event_correlation(deck_run_id, session_id, &batch)?;
        let payload = encode_watch_batch(&batch)?;
        if payload.len() > MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES {
            return Err(AgentConversationControlError::PayloadTooLarge);
        }
        Ok(Self::without_request(
            deck_run_id,
            session_id,
            AgentConversationControlBodyV1::WatchResult(batch),
        ))
    }

    #[must_use]
    pub const fn cancel_request(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    ) -> Self {
        Self::with_request(
            deck_run_id,
            session_id,
            request_id,
            AgentConversationControlBodyV1::CancelRequest,
        )
    }

    pub fn cancel_result(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        state: AgentConversationCancelStateV1,
    ) -> Result<Self, AgentConversationControlError> {
        if let AgentConversationCancelStateV1::Terminal(terminal) = &state {
            validate_terminal_correlation(deck_run_id, session_id, request_id, terminal)?;
        }
        Ok(Self::with_request(
            deck_run_id,
            session_id,
            request_id,
            AgentConversationControlBodyV1::CancelResult(state),
        ))
    }

    const fn without_request(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        body: AgentConversationControlBodyV1,
    ) -> Self {
        Self {
            deck_run_id,
            session_id,
            request_id: None,
            body,
        }
    }

    const fn with_request(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        body: AgentConversationControlBodyV1,
    ) -> Self {
        Self {
            deck_run_id,
            session_id,
            request_id: Some(request_id),
            body,
        }
    }

    #[must_use]
    pub const fn deck_run_id(&self) -> AgentConversationDeckRunId {
        self.deck_run_id
    }

    #[must_use]
    pub const fn session_id(&self) -> AgentConversationSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn request_id(&self) -> Option<AgentConversationRequestId> {
        self.request_id
    }

    #[must_use]
    pub const fn body(&self) -> &AgentConversationControlBodyV1 {
        &self.body
    }

    /// Returns one exact canonical control frame.
    pub fn canonical_wire(&self) -> Result<Box<[u8]>, AgentConversationControlError> {
        let (kind, outcome, payload) = self.encode_body()?;
        encode_control_frame(
            kind,
            outcome,
            self.deck_run_id,
            self.session_id,
            self.request_id,
            &payload,
        )
    }

    /// Strictly decodes only additive control kinds `3` to `10`.
    pub fn decode(wire: &[u8]) -> Result<Self, AgentConversationControlError> {
        let header = ControlHeader::decode(wire)?;
        let expected = control_digest(
            header.kind,
            header.outcome,
            header.deck_run_id,
            header.session_id,
            &header.request_id_raw,
            header.payload,
        )?;
        if expected != header.digest {
            return Err(AgentConversationControlError::DigestMismatch);
        }
        decode_control_body(header)
    }

    fn encode_body(&self) -> Result<(u8, u8, Box<[u8]>), AgentConversationControlError> {
        let empty = || Vec::new().into_boxed_slice();
        match &self.body {
            AgentConversationControlBodyV1::OpenRequest => {
                require_no_request_id(self.request_id)?;
                Ok((OPEN_REQUEST_KIND, REQUEST_OUTCOME, empty()))
            }
            AgentConversationControlBodyV1::OpenResult(outcome) => {
                require_no_request_id(self.request_id)?;
                Ok((OPEN_RESULT_KIND, *outcome as u8, empty()))
            }
            AgentConversationControlBodyV1::GetRequest => {
                require_request_id(self.request_id)?;
                Ok((GET_REQUEST_KIND, REQUEST_OUTCOME, empty()))
            }
            AgentConversationControlBodyV1::GetResult(state) => {
                let request_id = require_request_id(self.request_id)?;
                let (outcome, payload) = match state {
                    AgentConversationGetStateV1::NotFound => (1, empty()),
                    AgentConversationGetStateV1::Pending {
                        cancel_requested: false,
                    } => (2, empty()),
                    AgentConversationGetStateV1::Pending {
                        cancel_requested: true,
                    } => (3, empty()),
                    AgentConversationGetStateV1::Terminal(terminal) => {
                        validate_terminal_correlation(
                            self.deck_run_id,
                            self.session_id,
                            request_id,
                            terminal,
                        )?;
                        (4, terminal.canonical_wire())
                    }
                };
                Ok((GET_RESULT_KIND, outcome, payload))
            }
            AgentConversationControlBodyV1::WatchRequest { cursor, limit } => {
                require_no_request_id(self.request_id)?;
                validate_watch_limit(*limit)?;
                let mut payload = Vec::with_capacity(12);
                payload.extend_from_slice(&cursor.to_be_bytes());
                payload.extend_from_slice(&limit.to_be_bytes());
                Ok((
                    WATCH_REQUEST_KIND,
                    REQUEST_OUTCOME,
                    payload.into_boxed_slice(),
                ))
            }
            AgentConversationControlBodyV1::WatchResultNotFound => {
                require_no_request_id(self.request_id)?;
                Ok((WATCH_RESULT_KIND, 1, empty()))
            }
            AgentConversationControlBodyV1::WatchResult(batch) => {
                require_no_request_id(self.request_id)?;
                validate_watch_event_correlation(self.deck_run_id, self.session_id, batch)?;
                Ok((WATCH_RESULT_KIND, 2, encode_watch_batch(batch)?))
            }
            AgentConversationControlBodyV1::CancelRequest => {
                require_request_id(self.request_id)?;
                Ok((CANCEL_REQUEST_KIND, REQUEST_OUTCOME, empty()))
            }
            AgentConversationControlBodyV1::CancelResult(state) => {
                let request_id = require_request_id(self.request_id)?;
                let (outcome, payload) = match state {
                    AgentConversationCancelStateV1::NotFound => (1, empty()),
                    AgentConversationCancelStateV1::IntentRecorded => (2, empty()),
                    AgentConversationCancelStateV1::IntentAlreadyRecorded => (3, empty()),
                    AgentConversationCancelStateV1::SessionSealed => (4, empty()),
                    AgentConversationCancelStateV1::Terminal(terminal) => {
                        validate_terminal_correlation(
                            self.deck_run_id,
                            self.session_id,
                            request_id,
                            terminal,
                        )?;
                        (5, terminal.canonical_wire())
                    }
                };
                Ok((CANCEL_RESULT_KIND, outcome, payload))
            }
        }
    }
}

struct ControlHeader<'a> {
    kind: u8,
    outcome: u8,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_id_raw: [u8; 16],
    digest: Digest32,
    payload: &'a [u8],
}

impl<'a> ControlHeader<'a> {
    fn decode(wire: &'a [u8]) -> Result<Self, AgentConversationControlError> {
        if wire.len() < AGENT_CONVERSATION_HEADER_BYTES {
            return Err(AgentConversationControlError::Truncated);
        }
        if wire.len() > MAX_AGENT_CONVERSATION_CONTROL_FRAME_BYTES {
            return Err(AgentConversationControlError::FrameTooLarge);
        }
        if &wire[0..4] != AGENT_CONVERSATION_PROTOCOL_MAGIC {
            return Err(AgentConversationControlError::InvalidMagic);
        }
        if read_u16(wire, 4) != AGENT_CONVERSATION_PROTOCOL_VERSION {
            return Err(AgentConversationControlError::UnsupportedVersion);
        }
        if usize::from(read_u16(wire, 6)) != AGENT_CONVERSATION_HEADER_BYTES {
            return Err(AgentConversationControlError::InvalidHeaderLength);
        }
        let frame_length = usize::try_from(read_u32(wire, 8))
            .map_err(|_| AgentConversationControlError::InvalidFrameLength)?;
        if frame_length != wire.len() {
            return Err(AgentConversationControlError::InvalidFrameLength);
        }
        let kind = wire[12];
        if !matches!(kind, 3..=10) {
            return Err(AgentConversationControlError::UnknownFrameKind);
        }
        if read_u16(wire, 14) != 0
            || read_u32(wire, 16) != 0
            || wire[52..68].iter().any(|byte| *byte != 0)
            || read_u64(wire, 116) != 0
        {
            return Err(AgentConversationControlError::ReservedBitsSet);
        }
        let payload_length = usize::try_from(read_u32(wire, 124))
            .map_err(|_| AgentConversationControlError::InvalidFrameLength)?;
        if payload_length > MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES
            || AGENT_CONVERSATION_HEADER_BYTES
                .checked_add(payload_length)
                .ok_or(AgentConversationControlError::InvalidFrameLength)?
                != wire.len()
        {
            return Err(AgentConversationControlError::InvalidFrameLength);
        }
        let digest_raw = copy_array::<32>(wire, 84);
        if digest_raw.iter().all(|byte| *byte == 0) {
            return Err(AgentConversationControlError::InvalidDigest);
        }
        Ok(Self {
            kind,
            outcome: wire[13],
            deck_run_id: AgentConversationDeckRunId::try_from_bytes(copy_array(wire, 20))?,
            session_id: AgentConversationSessionId::try_from_bytes(copy_array(wire, 36))?,
            request_id_raw: copy_array(wire, 68),
            digest: Digest32::from_bytes(digest_raw),
            payload: &wire[AGENT_CONVERSATION_HEADER_BYTES..],
        })
    }
}

fn decode_control_body(
    header: ControlHeader<'_>,
) -> Result<AgentConversationControlV1, AgentConversationControlError> {
    let request_id = if header.request_id_raw == ZERO_ID {
        None
    } else {
        Some(AgentConversationRequestId::try_from_bytes(
            header.request_id_raw,
        )?)
    };
    let empty = header.payload.is_empty();
    match (header.kind, header.outcome) {
        (OPEN_REQUEST_KIND, REQUEST_OUTCOME) if empty && request_id.is_none() => Ok(
            AgentConversationControlV1::open_request(header.deck_run_id, header.session_id),
        ),
        (OPEN_RESULT_KIND, outcome) if empty && request_id.is_none() => {
            let outcome = match outcome {
                1 => AgentConversationOpenOutcomeV1::Opened,
                2 => AgentConversationOpenOutcomeV1::Existing,
                3 => AgentConversationOpenOutcomeV1::DeckRunSealed,
                4 => AgentConversationOpenOutcomeV1::CapacityExhausted,
                _ => return Err(AgentConversationControlError::InvalidOutcome),
            };
            Ok(AgentConversationControlV1::open_result(
                header.deck_run_id,
                header.session_id,
                outcome,
            ))
        }
        (GET_REQUEST_KIND, REQUEST_OUTCOME) if empty => {
            Ok(AgentConversationControlV1::get_request(
                header.deck_run_id,
                header.session_id,
                require_request_id(request_id)?,
            ))
        }
        (GET_RESULT_KIND, outcome) => {
            let request_id = require_request_id(request_id)?;
            let state = match outcome {
                1 if empty => AgentConversationGetStateV1::NotFound,
                2 if empty => AgentConversationGetStateV1::Pending {
                    cancel_requested: false,
                },
                3 if empty => AgentConversationGetStateV1::Pending {
                    cancel_requested: true,
                },
                4 => AgentConversationGetStateV1::Terminal(AgentConversationTerminalV1::decode(
                    header.payload,
                )?),
                _ => return Err(AgentConversationControlError::InvalidOutcome),
            };
            AgentConversationControlV1::get_result(
                header.deck_run_id,
                header.session_id,
                request_id,
                state,
            )
        }
        (WATCH_REQUEST_KIND, REQUEST_OUTCOME)
            if request_id.is_none() && header.payload.len() == 12 =>
        {
            AgentConversationControlV1::watch_request(
                header.deck_run_id,
                header.session_id,
                read_u64(header.payload, 0),
                read_u32(header.payload, 8),
            )
        }
        (WATCH_RESULT_KIND, 1) if request_id.is_none() && empty => {
            Ok(AgentConversationControlV1::watch_result_not_found(
                header.deck_run_id,
                header.session_id,
            ))
        }
        (WATCH_RESULT_KIND, 2) if request_id.is_none() => {
            let batch = decode_watch_batch(header.deck_run_id, header.session_id, header.payload)?;
            AgentConversationControlV1::watch_result(header.deck_run_id, header.session_id, batch)
        }
        (CANCEL_REQUEST_KIND, REQUEST_OUTCOME) if empty => {
            Ok(AgentConversationControlV1::cancel_request(
                header.deck_run_id,
                header.session_id,
                require_request_id(request_id)?,
            ))
        }
        (CANCEL_RESULT_KIND, outcome) => {
            let request_id = require_request_id(request_id)?;
            let state = match outcome {
                1 if empty => AgentConversationCancelStateV1::NotFound,
                2 if empty => AgentConversationCancelStateV1::IntentRecorded,
                3 if empty => AgentConversationCancelStateV1::IntentAlreadyRecorded,
                4 if empty => AgentConversationCancelStateV1::SessionSealed,
                5 => AgentConversationCancelStateV1::Terminal(AgentConversationTerminalV1::decode(
                    header.payload,
                )?),
                _ => return Err(AgentConversationControlError::InvalidOutcome),
            };
            AgentConversationControlV1::cancel_result(
                header.deck_run_id,
                header.session_id,
                request_id,
                state,
            )
        }
        _ => Err(AgentConversationControlError::InvalidOutcome),
    }
}

fn encode_control_frame(
    kind: u8,
    outcome: u8,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_id: Option<AgentConversationRequestId>,
    payload: &[u8],
) -> Result<Box<[u8]>, AgentConversationControlError> {
    if payload.len() > MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES {
        return Err(AgentConversationControlError::PayloadTooLarge);
    }
    let request_id_raw = request_id.map_or(ZERO_ID, |value| *value.as_bytes());
    let digest = control_digest(
        kind,
        outcome,
        deck_run_id,
        session_id,
        &request_id_raw,
        payload,
    )?;
    let frame_length = AGENT_CONVERSATION_HEADER_BYTES + payload.len();
    let mut wire = Vec::with_capacity(frame_length);
    wire.extend_from_slice(AGENT_CONVERSATION_PROTOCOL_MAGIC);
    wire.extend_from_slice(&AGENT_CONVERSATION_PROTOCOL_VERSION.to_be_bytes());
    wire.extend_from_slice(&(AGENT_CONVERSATION_HEADER_BYTES as u16).to_be_bytes());
    wire.extend_from_slice(&(frame_length as u32).to_be_bytes());
    wire.push(kind);
    wire.push(outcome);
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&0_u32.to_be_bytes());
    wire.extend_from_slice(deck_run_id.as_bytes());
    wire.extend_from_slice(session_id.as_bytes());
    wire.extend_from_slice(&ZERO_ID);
    wire.extend_from_slice(&request_id_raw);
    wire.extend_from_slice(digest.as_bytes());
    wire.extend_from_slice(&0_u64.to_be_bytes());
    wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    wire.extend_from_slice(payload);
    debug_assert_eq!(wire.len(), frame_length);
    Ok(wire.into_boxed_slice())
}

fn control_digest(
    kind: u8,
    outcome: u8,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_id_raw: &[u8; 16],
    payload: &[u8],
) -> Result<Digest32, AgentConversationControlError> {
    let mut builder = Digest32Builder::try_new(CONTROL_DIGEST_DOMAIN)?;
    builder
        .field_bytes(&[kind])?
        .field_bytes(&[outcome])?
        .field_bytes(deck_run_id.as_bytes())?
        .field_bytes(session_id.as_bytes())?
        .field_bytes(request_id_raw)?
        .field_bytes(payload)?;
    Ok(builder.finish())
}

fn encode_watch_batch(
    batch: &AgentConversationWatchBatchV1,
) -> Result<Box<[u8]>, AgentConversationControlError> {
    validate_watch_batch_shape(
        &batch.events,
        batch.next_cursor,
        batch.high_watermark,
        batch.has_more,
    )?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&batch.next_cursor.to_be_bytes());
    bytes.extend_from_slice(&batch.high_watermark.to_be_bytes());
    let flags = u8::from(batch.sealed) | (u8::from(batch.has_more) << 1);
    bytes.push(flags);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&(batch.events.len() as u32).to_be_bytes());
    for event in &batch.events {
        let (kind, payload) = match &event.kind {
            AgentConversationWatchEventKindV1::SessionOpened => (1, Box::from([])),
            AgentConversationWatchEventKindV1::RequestAccepted(request) => {
                (2, request.canonical_wire())
            }
            AgentConversationWatchEventKindV1::TerminalCommitted(terminal) => {
                (3, terminal.canonical_wire())
            }
            AgentConversationWatchEventKindV1::CancelIntentRecorded(request_id) => {
                (4, Box::from(request_id.as_bytes().as_slice()))
            }
            AgentConversationWatchEventKindV1::SessionSealed => (5, Box::from([])),
        };
        bytes.extend_from_slice(&event.sequence.to_be_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&payload);
        if bytes.len() > MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES {
            return Err(AgentConversationControlError::PayloadTooLarge);
        }
    }
    Ok(bytes.into_boxed_slice())
}

fn decode_watch_batch(
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    payload: &[u8],
) -> Result<AgentConversationWatchBatchV1, AgentConversationControlError> {
    if payload.len() < WATCH_BATCH_HEADER_BYTES {
        return Err(AgentConversationControlError::InvalidWatchBatch);
    }
    let next_cursor = read_u64(payload, 0);
    let high_watermark = read_u64(payload, 8);
    let flags = payload[16];
    if flags & !0b11 != 0 || payload[17..20].iter().any(|byte| *byte != 0) {
        return Err(AgentConversationControlError::ReservedBitsSet);
    }
    let count = usize::try_from(read_u32(payload, 20))
        .map_err(|_| AgentConversationControlError::InvalidWatchBatch)?;
    if count > MAX_AGENT_CONVERSATION_WATCH_EVENTS {
        return Err(AgentConversationControlError::WatchLimitOutOfRange);
    }
    let mut offset = WATCH_BATCH_HEADER_BYTES;
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        if payload.len().saturating_sub(offset) < WATCH_EVENT_HEADER_BYTES {
            return Err(AgentConversationControlError::InvalidWatchBatch);
        }
        let sequence = read_u64(payload, offset);
        let kind = payload[offset + 8];
        if payload[offset + 9..offset + 12]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(AgentConversationControlError::ReservedBitsSet);
        }
        let event_length = usize::try_from(read_u32(payload, offset + 12))
            .map_err(|_| AgentConversationControlError::InvalidWatchBatch)?;
        offset = offset
            .checked_add(WATCH_EVENT_HEADER_BYTES)
            .ok_or(AgentConversationControlError::InvalidWatchBatch)?;
        let end = offset
            .checked_add(event_length)
            .ok_or(AgentConversationControlError::InvalidWatchBatch)?;
        let event_payload = payload
            .get(offset..end)
            .ok_or(AgentConversationControlError::InvalidWatchBatch)?;
        let event_kind = match kind {
            1 if event_payload.is_empty() => AgentConversationWatchEventKindV1::SessionOpened,
            2 => {
                let request = AgentConversationRequestV1::decode(event_payload)?;
                if request.deck_run_id() != deck_run_id || request.session_id() != session_id {
                    return Err(AgentConversationControlError::CorrelationMismatch);
                }
                AgentConversationWatchEventKindV1::RequestAccepted(request)
            }
            3 => {
                let terminal = AgentConversationTerminalV1::decode(event_payload)?;
                if terminal.deck_run_id() != deck_run_id || terminal.session_id() != session_id {
                    return Err(AgentConversationControlError::CorrelationMismatch);
                }
                AgentConversationWatchEventKindV1::TerminalCommitted(terminal)
            }
            4 if event_payload.len() == 16 => {
                AgentConversationWatchEventKindV1::CancelIntentRecorded(
                    AgentConversationRequestId::try_from_bytes(copy_array(event_payload, 0))?,
                )
            }
            5 if event_payload.is_empty() => AgentConversationWatchEventKindV1::SessionSealed,
            _ => return Err(AgentConversationControlError::InvalidWatchEvent),
        };
        events.push(AgentConversationWatchEventV1::try_new(
            sequence, event_kind,
        )?);
        offset = end;
    }
    if offset != payload.len() {
        return Err(AgentConversationControlError::InvalidWatchBatch);
    }
    let batch = AgentConversationWatchBatchV1::try_new(
        events.into_boxed_slice(),
        next_cursor,
        high_watermark,
        flags & 0b10 != 0,
        flags & 0b01 != 0,
    )?;
    validate_watch_event_correlation(deck_run_id, session_id, &batch)?;
    Ok(batch)
}

fn validate_watch_event_correlation(
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    batch: &AgentConversationWatchBatchV1,
) -> Result<(), AgentConversationControlError> {
    for event in &batch.events {
        match &event.kind {
            AgentConversationWatchEventKindV1::RequestAccepted(request)
                if request.deck_run_id() != deck_run_id || request.session_id() != session_id =>
            {
                return Err(AgentConversationControlError::CorrelationMismatch);
            }
            AgentConversationWatchEventKindV1::TerminalCommitted(terminal)
                if terminal.deck_run_id() != deck_run_id || terminal.session_id() != session_id =>
            {
                return Err(AgentConversationControlError::CorrelationMismatch);
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_terminal_correlation(
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_id: AgentConversationRequestId,
    terminal: &AgentConversationTerminalV1,
) -> Result<(), AgentConversationControlError> {
    if terminal.deck_run_id() != deck_run_id
        || terminal.session_id() != session_id
        || terminal.request_id() != request_id
    {
        return Err(AgentConversationControlError::CorrelationMismatch);
    }
    Ok(())
}

fn validate_watch_batch_shape(
    events: &[AgentConversationWatchEventV1],
    next_cursor: u64,
    high_watermark: u64,
    has_more: bool,
) -> Result<(), AgentConversationControlError> {
    if events.len() > MAX_AGENT_CONVERSATION_WATCH_EVENTS {
        return Err(AgentConversationControlError::WatchLimitOutOfRange);
    }
    if next_cursor > high_watermark || has_more != (next_cursor < high_watermark) {
        return Err(AgentConversationControlError::InvalidWatchBatch);
    }
    for pair in events.windows(2) {
        if pair[0].sequence.checked_add(1) != Some(pair[1].sequence) {
            return Err(AgentConversationControlError::InvalidWatchSequence);
        }
    }
    if let Some(last) = events.last()
        && last.sequence != next_cursor
    {
        return Err(AgentConversationControlError::InvalidWatchSequence);
    }
    Ok(())
}

fn validate_watch_limit(limit: u32) -> Result<(), AgentConversationControlError> {
    if limit == 0
        || usize::try_from(limit).map_or(true, |value| value > MAX_AGENT_CONVERSATION_WATCH_EVENTS)
    {
        return Err(AgentConversationControlError::WatchLimitOutOfRange);
    }
    Ok(())
}

fn require_request_id(
    request_id: Option<AgentConversationRequestId>,
) -> Result<AgentConversationRequestId, AgentConversationControlError> {
    request_id.ok_or(AgentConversationControlError::InvalidRequestIdentity)
}

fn require_no_request_id(
    request_id: Option<AgentConversationRequestId>,
) -> Result<(), AgentConversationControlError> {
    if request_id.is_some() {
        Err(AgentConversationControlError::InvalidRequestIdentity)
    } else {
        Ok(())
    }
}

fn read_u16(wire: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(copy_array(wire, offset))
}

fn read_u32(wire: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(copy_array(wire, offset))
}

fn read_u64(wire: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(copy_array(wire, offset))
}

fn copy_array<const N: usize>(wire: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0; N];
    output.copy_from_slice(&wire[offset..offset + N]);
    output
}

/// Stable fail-closed error for the additive control codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentConversationControlError {
    Protocol(AgentConversationProtocolError),
    Digest(DigestBuildError),
    Truncated,
    FrameTooLarge,
    PayloadTooLarge,
    InvalidMagic,
    UnsupportedVersion,
    InvalidHeaderLength,
    InvalidFrameLength,
    UnknownFrameKind,
    ReservedBitsSet,
    InvalidDigest,
    DigestMismatch,
    InvalidOutcome,
    InvalidRequestIdentity,
    WatchLimitOutOfRange,
    InvalidWatchBatch,
    InvalidWatchEvent,
    InvalidWatchSequence,
    CorrelationMismatch,
}

impl From<AgentConversationProtocolError> for AgentConversationControlError {
    fn from(value: AgentConversationProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<DigestBuildError> for AgentConversationControlError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for AgentConversationControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Protocol(_) => "embedded conversation value is invalid",
            Self::Digest(_) => "control digest construction failed",
            Self::Truncated => "control frame is truncated",
            Self::FrameTooLarge => "control frame exceeds its bound",
            Self::PayloadTooLarge => "control payload exceeds its bound",
            Self::InvalidMagic => "control frame magic mismatched",
            Self::UnsupportedVersion => "control protocol version is unsupported",
            Self::InvalidHeaderLength => "control header length is invalid",
            Self::InvalidFrameLength => "control frame length is invalid",
            Self::UnknownFrameKind => "control frame kind is unknown",
            Self::ReservedBitsSet => "control reserved bytes are nonzero",
            Self::InvalidDigest => "control digest is all-zero",
            Self::DigestMismatch => "control digest mismatched",
            Self::InvalidOutcome => "control outcome or payload is invalid",
            Self::InvalidRequestIdentity => "control request identity presence is invalid",
            Self::WatchLimitOutOfRange => "control watch limit is out of range",
            Self::InvalidWatchBatch => "control watch batch is invalid",
            Self::InvalidWatchEvent => "control watch event is invalid",
            Self::InvalidWatchSequence => "control watch event sequence is invalid",
            Self::CorrelationMismatch => "control embedded value correlation mismatched",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AgentConversationControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}
