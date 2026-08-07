//! Narrow language-neutral contract for one text-only Agent conversation turn.
//!
//! `AgentConversationProtocol` v1 owns DeckRun-bound request correlation,
//! bounded UTF-8 text, a receiver-installed deadline budget, one terminal
//! success/failure result, and exact request replay/conflict semantics. It
//! deliberately contains no Tool, Memory, model-provider credential, effect,
//! Runtime, Fabric, or client transport contract.

pub mod control;

use core::fmt;
use std::collections::BTreeMap;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};

/// Magic prefix of every AgentConversationProtocol frame.
pub const AGENT_CONVERSATION_PROTOCOL_MAGIC: &[u8; 4] = b"PXAC";
/// Only protocol version accepted by this crate.
pub const AGENT_CONVERSATION_PROTOCOL_VERSION: u16 = 1;
/// Exact fixed header size for request and terminal frames.
pub const AGENT_CONVERSATION_HEADER_BYTES: usize = 128;
/// Maximum UTF-8 user input retained by one request.
pub const MAX_AGENT_CONVERSATION_INPUT_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 terminal output retained by one request.
pub const MAX_AGENT_CONVERSATION_OUTPUT_BYTES: usize = 32 * 1024;
/// Maximum canonical frame size.
pub const MAX_AGENT_CONVERSATION_FRAME_BYTES: usize =
    AGENT_CONVERSATION_HEADER_BYTES + MAX_AGENT_CONVERSATION_OUTPUT_BYTES;
/// Maximum relative deadline that a receiver may install on its local clock.
pub const MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS: u64 = 300_000_000_000;
/// Fixed in-memory request ledger bound for the first consumer.
pub const MAX_AGENT_CONVERSATION_REQUESTS: usize = 1_024;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.agent.conversation.request.sha256.v1";
const RESERVED_FLAGS: u32 = 0;
const REQUEST_KIND: u8 = 1;
const TERMINAL_KIND: u8 = 2;
const REQUEST_OUTCOME: u8 = 0;
const TERMINAL_SUCCESS_OUTCOME: u8 = 1;
const TERMINAL_FAILURE_OUTCOME: u8 = 2;
const NO_TERMINAL_ERROR: u16 = 0;

macro_rules! conversation_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Constructs a nonzero opaque protocol identity.
            pub const fn try_from_bytes(
                bytes: [u8; 16],
            ) -> Result<Self, AgentConversationProtocolError> {
                let mut index = 0;
                while index < bytes.len() {
                    if bytes[index] != 0 {
                        return Ok(Self(bytes));
                    }
                    index += 1;
                }
                Err(AgentConversationProtocolError::InvalidIdentity)
            }

            /// Returns the exact canonical identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

conversation_id!(AgentConversationDeckRunId);
conversation_id!(AgentConversationSessionId);
conversation_id!(AgentConversationTurnId);
conversation_id!(AgentConversationRequestId);

/// Stable terminal failures emitted after a valid request is admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AgentConversationTerminalFailureV1 {
    ModelFailed = 1,
    DeadlineExceeded = 2,
    RequestConflict = 3,
    CapacityExhausted = 4,
    /// A durable acceptance exists but recovery cannot prove whether the model ran.
    ModelOutcomeUncertain = 5,
    /// Cancellation was durably committed before the model provider was entered.
    CancelledBeforeModel = 6,
}

impl AgentConversationTerminalFailureV1 {
    fn from_wire(value: u16) -> Result<Self, AgentConversationProtocolError> {
        match value {
            1 => Ok(Self::ModelFailed),
            2 => Ok(Self::DeadlineExceeded),
            3 => Ok(Self::RequestConflict),
            4 => Ok(Self::CapacityExhausted),
            5 => Ok(Self::ModelOutcomeUncertain),
            6 => Ok(Self::CancelledBeforeModel),
            _ => Err(AgentConversationProtocolError::UnknownTerminalFailure),
        }
    }
}

/// Canonical producer value for one bounded text turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentConversationRequestV1 {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    turn_id: AgentConversationTurnId,
    request_id: AgentConversationRequestId,
    request_digest: Digest32,
    deadline_budget_nanos: u64,
    input: Box<str>,
}

impl AgentConversationRequestV1 {
    /// Produces a request and its domain-separated canonical digest.
    pub fn try_new(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        turn_id: AgentConversationTurnId,
        request_id: AgentConversationRequestId,
        deadline_budget_nanos: u64,
        input: &str,
    ) -> Result<Self, AgentConversationProtocolError> {
        validate_deadline(deadline_budget_nanos)?;
        validate_input(input.as_bytes())?;
        let request_digest = request_digest(
            deck_run_id,
            session_id,
            turn_id,
            request_id,
            deadline_budget_nanos,
            input.as_bytes(),
        )?;
        Ok(Self {
            deck_run_id,
            session_id,
            turn_id,
            request_id,
            request_digest,
            deadline_budget_nanos,
            input: input.into(),
        })
    }

    /// Strictly consumes one exact v1 request frame.
    pub fn decode(wire: &[u8]) -> Result<Self, AgentConversationProtocolError> {
        let header = ParsedHeader::decode(wire)?;
        if header.kind != REQUEST_KIND
            || header.outcome != REQUEST_OUTCOME
            || header.terminal_error != NO_TERMINAL_ERROR
        {
            return Err(AgentConversationProtocolError::InvalidRequestFields);
        }
        validate_deadline(header.deadline_budget_nanos)?;
        validate_input(header.payload)?;
        let input = core::str::from_utf8(header.payload)
            .map_err(|_| AgentConversationProtocolError::InvalidUtf8)?;
        let expected = request_digest(
            header.deck_run_id,
            header.session_id,
            header.turn_id,
            header.request_id,
            header.deadline_budget_nanos,
            header.payload,
        )?;
        if expected != header.request_digest {
            return Err(AgentConversationProtocolError::RequestDigestMismatch);
        }
        Ok(Self {
            deck_run_id: header.deck_run_id,
            session_id: header.session_id,
            turn_id: header.turn_id,
            request_id: header.request_id,
            request_digest: header.request_digest,
            deadline_budget_nanos: header.deadline_budget_nanos,
            input: input.into(),
        })
    }

    /// Returns the exact language-neutral canonical frame.
    #[must_use]
    pub fn canonical_wire(&self) -> Box<[u8]> {
        encode_frame(FrameFields {
            kind: REQUEST_KIND,
            outcome: REQUEST_OUTCOME,
            terminal_error: NO_TERMINAL_ERROR,
            deck_run_id: self.deck_run_id,
            session_id: self.session_id,
            turn_id: self.turn_id,
            request_id: self.request_id,
            request_digest: self.request_digest,
            deadline_budget_nanos: self.deadline_budget_nanos,
            payload: self.input.as_bytes(),
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

    #[must_use]
    pub const fn turn_id(&self) -> AgentConversationTurnId {
        self.turn_id
    }

    #[must_use]
    pub const fn request_id(&self) -> AgentConversationRequestId {
        self.request_id
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    /// Relative budget to install against a receiver-local monotonic clock.
    #[must_use]
    pub const fn deadline_budget_nanos(&self) -> u64 {
        self.deadline_budget_nanos
    }

    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }
}

/// One and only terminal response for an admitted request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentConversationTerminalResultV1 {
    Success(Box<str>),
    Failure(AgentConversationTerminalFailureV1),
}

/// Canonical terminal producer and strict consumer value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentConversationTerminalV1 {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    turn_id: AgentConversationTurnId,
    request_id: AgentConversationRequestId,
    request_digest: Digest32,
    deadline_budget_nanos: u64,
    result: AgentConversationTerminalResultV1,
}

impl AgentConversationTerminalV1 {
    /// Produces a successful terminal response correlated to one exact request.
    pub fn try_success(
        request: &AgentConversationRequestV1,
        output: &str,
    ) -> Result<Self, AgentConversationProtocolError> {
        validate_output(output.as_bytes())?;
        Ok(Self::from_request(
            request,
            AgentConversationTerminalResultV1::Success(output.into()),
        ))
    }

    /// Produces a payload-free stable terminal failure.
    #[must_use]
    pub fn failure(
        request: &AgentConversationRequestV1,
        failure: AgentConversationTerminalFailureV1,
    ) -> Self {
        Self::from_request(request, AgentConversationTerminalResultV1::Failure(failure))
    }

    fn from_request(
        request: &AgentConversationRequestV1,
        result: AgentConversationTerminalResultV1,
    ) -> Self {
        Self {
            deck_run_id: request.deck_run_id,
            session_id: request.session_id,
            turn_id: request.turn_id,
            request_id: request.request_id,
            request_digest: request.request_digest,
            deadline_budget_nanos: request.deadline_budget_nanos,
            result,
        }
    }

    /// Strictly consumes one exact v1 terminal frame.
    pub fn decode(wire: &[u8]) -> Result<Self, AgentConversationProtocolError> {
        let header = ParsedHeader::decode(wire)?;
        if header.kind != TERMINAL_KIND {
            return Err(AgentConversationProtocolError::InvalidTerminalFields);
        }
        validate_deadline(header.deadline_budget_nanos)?;
        let result = match header.outcome {
            TERMINAL_SUCCESS_OUTCOME if header.terminal_error == NO_TERMINAL_ERROR => {
                validate_output(header.payload)?;
                let output = core::str::from_utf8(header.payload)
                    .map_err(|_| AgentConversationProtocolError::InvalidUtf8)?;
                AgentConversationTerminalResultV1::Success(output.into())
            }
            TERMINAL_FAILURE_OUTCOME if header.payload.is_empty() => {
                AgentConversationTerminalResultV1::Failure(
                    AgentConversationTerminalFailureV1::from_wire(header.terminal_error)?,
                )
            }
            _ => return Err(AgentConversationProtocolError::InvalidTerminalFields),
        };
        Ok(Self {
            deck_run_id: header.deck_run_id,
            session_id: header.session_id,
            turn_id: header.turn_id,
            request_id: header.request_id,
            request_digest: header.request_digest,
            deadline_budget_nanos: header.deadline_budget_nanos,
            result,
        })
    }

    /// Returns the exact language-neutral canonical terminal frame.
    #[must_use]
    pub fn canonical_wire(&self) -> Box<[u8]> {
        let (outcome, terminal_error, payload) = match &self.result {
            AgentConversationTerminalResultV1::Success(output) => (
                TERMINAL_SUCCESS_OUTCOME,
                NO_TERMINAL_ERROR,
                output.as_bytes(),
            ),
            AgentConversationTerminalResultV1::Failure(failure) => {
                (TERMINAL_FAILURE_OUTCOME, *failure as u16, &[][..])
            }
        };
        encode_frame(FrameFields {
            kind: TERMINAL_KIND,
            outcome,
            terminal_error,
            deck_run_id: self.deck_run_id,
            session_id: self.session_id,
            turn_id: self.turn_id,
            request_id: self.request_id,
            request_digest: self.request_digest,
            deadline_budget_nanos: self.deadline_budget_nanos,
            payload,
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

    #[must_use]
    pub const fn turn_id(&self) -> AgentConversationTurnId {
        self.turn_id
    }

    #[must_use]
    pub const fn request_id(&self) -> AgentConversationRequestId {
        self.request_id
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub const fn deadline_budget_nanos(&self) -> u64 {
        self.deadline_budget_nanos
    }

    #[must_use]
    pub const fn result(&self) -> &AgentConversationTerminalResultV1 {
        &self.result
    }

    #[must_use]
    pub fn correlates(&self, request: &AgentConversationRequestV1) -> bool {
        self.deck_run_id == request.deck_run_id
            && self.session_id == request.session_id
            && self.turn_id == request.turn_id
            && self.request_id == request.request_id
            && self.request_digest == request.request_digest
            && self.deadline_budget_nanos == request.deadline_budget_nanos
    }
}

/// Result of admitting a request into the first bounded semantic consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentConversationRequestAcceptanceV1 {
    Accepted,
    PendingReplay,
    TerminalReplay(AgentConversationTerminalV1),
    Conflict,
}

#[derive(Clone, Debug)]
struct RequestRecord {
    request: AgentConversationRequestV1,
    terminal: Option<AgentConversationTerminalV1>,
}

type RequestScopeKey = (
    AgentConversationDeckRunId,
    AgentConversationSessionId,
    AgentConversationRequestId,
);

/// Bounded request-id consumer proving exact replay and conflict semantics.
#[derive(Debug)]
pub struct AgentConversationRequestRegistryV1 {
    records: BTreeMap<RequestScopeKey, RequestRecord>,
}

impl AgentConversationRequestRegistryV1 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Admits a new request, replays an exact request, or rejects identity reuse.
    pub fn accept(
        &mut self,
        request: &AgentConversationRequestV1,
    ) -> Result<AgentConversationRequestAcceptanceV1, AgentConversationProtocolError> {
        let key = (request.deck_run_id, request.session_id, request.request_id);
        if let Some(record) = self.records.get(&key) {
            if record.request.request_digest != request.request_digest {
                return Ok(AgentConversationRequestAcceptanceV1::Conflict);
            }
            return Ok(match &record.terminal {
                Some(terminal) => {
                    AgentConversationRequestAcceptanceV1::TerminalReplay(terminal.clone())
                }
                None => AgentConversationRequestAcceptanceV1::PendingReplay,
            });
        }
        if self.records.len() >= MAX_AGENT_CONVERSATION_REQUESTS {
            return Err(AgentConversationProtocolError::RegistryCapacityExceeded);
        }
        self.records.insert(
            key,
            RequestRecord {
                request: request.clone(),
                terminal: None,
            },
        );
        Ok(AgentConversationRequestAcceptanceV1::Accepted)
    }

    /// Commits one exact terminal result and returns byte-stable repeated commit.
    pub fn commit_terminal(
        &mut self,
        terminal: AgentConversationTerminalV1,
    ) -> Result<AgentConversationTerminalV1, AgentConversationProtocolError> {
        let key = (
            terminal.deck_run_id,
            terminal.session_id,
            terminal.request_id,
        );
        let Some(record) = self.records.get_mut(&key) else {
            return Err(AgentConversationProtocolError::UnknownRequest);
        };
        if !terminal.correlates(&record.request) {
            return Err(AgentConversationProtocolError::TerminalCorrelationMismatch);
        }
        match &record.terminal {
            Some(existing) if existing == &terminal => Ok(existing.clone()),
            Some(_) => Err(AgentConversationProtocolError::TerminalConflict),
            None => {
                record.terminal = Some(terminal.clone());
                Ok(terminal)
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Default for AgentConversationRequestRegistryV1 {
    fn default() -> Self {
        Self::new()
    }
}

struct ParsedHeader<'a> {
    kind: u8,
    outcome: u8,
    terminal_error: u16,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    turn_id: AgentConversationTurnId,
    request_id: AgentConversationRequestId,
    request_digest: Digest32,
    deadline_budget_nanos: u64,
    payload: &'a [u8],
}

impl<'a> ParsedHeader<'a> {
    fn decode(wire: &'a [u8]) -> Result<Self, AgentConversationProtocolError> {
        if wire.len() < AGENT_CONVERSATION_HEADER_BYTES {
            return Err(AgentConversationProtocolError::Truncated);
        }
        if wire.len() > MAX_AGENT_CONVERSATION_FRAME_BYTES {
            return Err(AgentConversationProtocolError::FrameTooLarge);
        }
        if &wire[0..4] != AGENT_CONVERSATION_PROTOCOL_MAGIC {
            return Err(AgentConversationProtocolError::InvalidMagic);
        }
        if read_u16(wire, 4) != AGENT_CONVERSATION_PROTOCOL_VERSION {
            return Err(AgentConversationProtocolError::UnsupportedVersion);
        }
        if usize::from(read_u16(wire, 6)) != AGENT_CONVERSATION_HEADER_BYTES {
            return Err(AgentConversationProtocolError::InvalidHeaderLength);
        }
        let frame_length = usize::try_from(read_u32(wire, 8))
            .map_err(|_| AgentConversationProtocolError::InvalidFrameLength)?;
        if frame_length != wire.len() {
            return Err(AgentConversationProtocolError::InvalidFrameLength);
        }
        let kind = wire[12];
        if !matches!(kind, REQUEST_KIND | TERMINAL_KIND) {
            return Err(AgentConversationProtocolError::UnknownFrameKind);
        }
        if read_u32(wire, 16) != RESERVED_FLAGS {
            return Err(AgentConversationProtocolError::ReservedBitsSet);
        }
        let payload_length = usize::try_from(read_u32(wire, 124))
            .map_err(|_| AgentConversationProtocolError::InvalidFrameLength)?;
        if AGENT_CONVERSATION_HEADER_BYTES
            .checked_add(payload_length)
            .ok_or(AgentConversationProtocolError::InvalidFrameLength)?
            != wire.len()
        {
            return Err(AgentConversationProtocolError::InvalidFrameLength);
        }
        let request_digest = copy_array::<32>(wire, 84);
        if request_digest.iter().all(|byte| *byte == 0) {
            return Err(AgentConversationProtocolError::InvalidRequestDigest);
        }
        Ok(Self {
            kind,
            outcome: wire[13],
            terminal_error: read_u16(wire, 14),
            deck_run_id: AgentConversationDeckRunId::try_from_bytes(copy_array(wire, 20))?,
            session_id: AgentConversationSessionId::try_from_bytes(copy_array(wire, 36))?,
            turn_id: AgentConversationTurnId::try_from_bytes(copy_array(wire, 52))?,
            request_id: AgentConversationRequestId::try_from_bytes(copy_array(wire, 68))?,
            request_digest: Digest32::from_bytes(request_digest),
            deadline_budget_nanos: read_u64(wire, 116),
            payload: &wire[AGENT_CONVERSATION_HEADER_BYTES..],
        })
    }
}

fn request_digest(
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    turn_id: AgentConversationTurnId,
    request_id: AgentConversationRequestId,
    deadline_budget_nanos: u64,
    input: &[u8],
) -> Result<Digest32, AgentConversationProtocolError> {
    let mut builder = Digest32Builder::try_new(REQUEST_DIGEST_DOMAIN)?;
    builder
        .field_bytes(deck_run_id.as_bytes())?
        .field_bytes(session_id.as_bytes())?
        .field_bytes(turn_id.as_bytes())?
        .field_bytes(request_id.as_bytes())?
        .field_u64(deadline_budget_nanos)?
        .field_bytes(input)?;
    Ok(builder.finish())
}

fn validate_input(input: &[u8]) -> Result<(), AgentConversationProtocolError> {
    if input.is_empty() {
        return Err(AgentConversationProtocolError::InputEmpty);
    }
    if input.len() > MAX_AGENT_CONVERSATION_INPUT_BYTES {
        return Err(AgentConversationProtocolError::InputTooLarge);
    }
    core::str::from_utf8(input).map_err(|_| AgentConversationProtocolError::InvalidUtf8)?;
    Ok(())
}

fn validate_output(output: &[u8]) -> Result<(), AgentConversationProtocolError> {
    if output.is_empty() {
        return Err(AgentConversationProtocolError::OutputEmpty);
    }
    if output.len() > MAX_AGENT_CONVERSATION_OUTPUT_BYTES {
        return Err(AgentConversationProtocolError::OutputTooLarge);
    }
    core::str::from_utf8(output).map_err(|_| AgentConversationProtocolError::InvalidUtf8)?;
    Ok(())
}

const fn validate_deadline(value: u64) -> Result<(), AgentConversationProtocolError> {
    if value == 0 || value > MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS {
        Err(AgentConversationProtocolError::DeadlineOutOfRange)
    } else {
        Ok(())
    }
}

struct FrameFields<'a> {
    kind: u8,
    outcome: u8,
    terminal_error: u16,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    turn_id: AgentConversationTurnId,
    request_id: AgentConversationRequestId,
    request_digest: Digest32,
    deadline_budget_nanos: u64,
    payload: &'a [u8],
}

fn encode_frame(fields: FrameFields<'_>) -> Box<[u8]> {
    let FrameFields {
        kind,
        outcome,
        terminal_error,
        deck_run_id,
        session_id,
        turn_id,
        request_id,
        request_digest,
        deadline_budget_nanos,
        payload,
    } = fields;
    let frame_length = AGENT_CONVERSATION_HEADER_BYTES + payload.len();
    let frame_length = u32::try_from(frame_length).expect("bounded frame length must fit u32");
    let payload_length = u32::try_from(payload.len()).expect("bounded payload length must fit u32");
    let mut wire = Vec::with_capacity(frame_length as usize);
    wire.extend_from_slice(AGENT_CONVERSATION_PROTOCOL_MAGIC);
    wire.extend_from_slice(&AGENT_CONVERSATION_PROTOCOL_VERSION.to_be_bytes());
    wire.extend_from_slice(
        &u16::try_from(AGENT_CONVERSATION_HEADER_BYTES)
            .expect("fixed header length must fit u16")
            .to_be_bytes(),
    );
    wire.extend_from_slice(&frame_length.to_be_bytes());
    wire.push(kind);
    wire.push(outcome);
    wire.extend_from_slice(&terminal_error.to_be_bytes());
    wire.extend_from_slice(&RESERVED_FLAGS.to_be_bytes());
    wire.extend_from_slice(deck_run_id.as_bytes());
    wire.extend_from_slice(session_id.as_bytes());
    wire.extend_from_slice(turn_id.as_bytes());
    wire.extend_from_slice(request_id.as_bytes());
    wire.extend_from_slice(request_digest.as_bytes());
    wire.extend_from_slice(&deadline_budget_nanos.to_be_bytes());
    wire.extend_from_slice(&payload_length.to_be_bytes());
    wire.extend_from_slice(payload);
    debug_assert_eq!(wire.len(), frame_length as usize);
    wire.into_boxed_slice()
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

/// Stable fail-closed construction, decoding, and semantic-consumer errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentConversationProtocolError {
    InvalidIdentity,
    InputEmpty,
    InputTooLarge,
    OutputEmpty,
    OutputTooLarge,
    InvalidUtf8,
    DeadlineOutOfRange,
    FrameTooLarge,
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    InvalidHeaderLength,
    InvalidFrameLength,
    UnknownFrameKind,
    ReservedBitsSet,
    InvalidRequestFields,
    InvalidTerminalFields,
    InvalidRequestDigest,
    RequestDigestMismatch,
    UnknownTerminalFailure,
    RegistryCapacityExceeded,
    UnknownRequest,
    TerminalCorrelationMismatch,
    TerminalConflict,
    Digest(DigestBuildError),
}

impl From<DigestBuildError> for AgentConversationProtocolError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for AgentConversationProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentity => "conversation identity is all-zero",
            Self::InputEmpty => "conversation input is empty",
            Self::InputTooLarge => "conversation input exceeds its bound",
            Self::OutputEmpty => "conversation terminal output is empty",
            Self::OutputTooLarge => "conversation terminal output exceeds its bound",
            Self::InvalidUtf8 => "conversation text is not valid UTF-8",
            Self::DeadlineOutOfRange => "conversation deadline budget is out of range",
            Self::FrameTooLarge => "conversation frame exceeds its bound",
            Self::Truncated => "conversation frame is truncated",
            Self::InvalidMagic => "conversation frame magic mismatched",
            Self::UnsupportedVersion => "conversation protocol version is unsupported",
            Self::InvalidHeaderLength => "conversation header length is invalid",
            Self::InvalidFrameLength => "conversation frame length is invalid",
            Self::UnknownFrameKind => "conversation frame kind is unknown",
            Self::ReservedBitsSet => "conversation reserved flags are nonzero",
            Self::InvalidRequestFields => "conversation request fields are invalid",
            Self::InvalidTerminalFields => "conversation terminal fields are invalid",
            Self::InvalidRequestDigest => "conversation request digest is all-zero",
            Self::RequestDigestMismatch => "conversation request digest mismatched",
            Self::UnknownTerminalFailure => "conversation terminal failure is unknown",
            Self::RegistryCapacityExceeded => "conversation registry capacity is exhausted",
            Self::UnknownRequest => "conversation terminal has no admitted request",
            Self::TerminalCorrelationMismatch => "conversation terminal correlation mismatched",
            Self::TerminalConflict => "conversation request already has a different terminal",
            Self::Digest(_) => "conversation request digest construction failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AgentConversationProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}
