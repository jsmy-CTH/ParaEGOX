//! Versioned local control contract between one RuntimeHost process and its
//! external OS service-manager adapter.
//!
//! The transport is an inherited pair of byte streams. The frame proves only
//! that the exact child generation advanced its bootstrap/reactor control
//! task; it is not Card readiness, a ProcessDomain liveness fact, or a
//! recovery receipt.

use core::fmt;

/// Fixed wire marker for the RuntimeHost watchdog protocol.
pub const HOST_WATCHDOG_PROTOCOL_MAGIC: [u8; 4] = *b"PXHW";
/// First and currently only supported protocol version.
pub const HOST_WATCHDOG_PROTOCOL_VERSION: u16 = 1;
/// Every watchdog frame has this exact size.
pub const HOST_WATCHDOG_FRAME_BYTES: usize = 40;

/// Explicit opt-in switch consumed by the RuntimeHost executable.
pub const HOST_WATCHDOG_ENABLE_ENV: &str = "PARAEGOX_HOST_WATCHDOG";
/// Child generation installed by the external lifecycle owner.
pub const HOST_WATCHDOG_GENERATION_ENV: &str = "PARAEGOX_HOST_WATCHDOG_GENERATION";
/// RuntimeHost heartbeat interval installed by the external lifecycle owner.
pub const HOST_WATCHDOG_HEARTBEAT_MILLIS_ENV: &str = "PARAEGOX_HOST_WATCHDOG_HEARTBEAT_MILLIS";
/// Maximum initial control-handshake wait installed by the external owner.
pub const HOST_WATCHDOG_HANDSHAKE_MILLIS_ENV: &str = "PARAEGOX_HOST_WATCHDOG_HANDSHAKE_MILLIS";

const BOOTSTRAP_PROGRESS_KIND: u16 = 1;
const RUNNING_HEARTBEAT_KIND: u16 = 2;
const CONTROL_PROBE_KIND: u16 = 3;
const CONTROL_ACK_KIND: u16 = 4;

/// Nonzero restart generation assigned by the sole external lifecycle owner.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostWatchdogGeneration(u64);

impl HostWatchdogGeneration {
    /// Constructs a live child generation.
    pub const fn try_new(value: u64) -> Result<Self, HostWatchdogProtocolError> {
        if value == 0 {
            Err(HostWatchdogProtocolError::ZeroGeneration)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the canonical scalar value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Nonzero, direction-local sequence used to reject replay and gaps.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostWatchdogSequence(u64);

impl HostWatchdogSequence {
    /// Constructs one direction-local sequence.
    pub const fn try_new(value: u64) -> Result<Self, HostWatchdogProtocolError> {
        if value == 0 {
            Err(HostWatchdogProtocolError::ZeroSequence)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the canonical scalar value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Nonzero nonce that binds a control acknowledgement to one external probe.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostControlProbeNonce(u64);

impl HostControlProbeNonce {
    /// Constructs a control-probe nonce.
    pub const fn try_new(value: u64) -> Result<Self, HostWatchdogProtocolError> {
        if value == 0 {
            Err(HostWatchdogProtocolError::ZeroControlProbeNonce)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the canonical scalar value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Ordered bootstrap progress emitted by the RuntimeHost reactor task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum HostBootstrapPhase {
    /// The current-thread reactor and structured root scope exist.
    ReactorStarted = 1,
    /// The inherited watchdog streams are available to the reactor task.
    ControlReady = 2,
    /// The task has emitted all bootstrap progress and entered its live loop.
    Running = 3,
}

impl HostBootstrapPhase {
    const fn try_from_wire(value: u64) -> Result<Self, HostWatchdogProtocolError> {
        match value {
            1 => Ok(Self::ReactorStarted),
            2 => Ok(Self::ControlReady),
            3 => Ok(Self::Running),
            _ => Err(HostWatchdogProtocolError::InvalidBody),
        }
    }
}

/// Direction of one watchdog frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWatchdogDirection {
    /// RuntimeHost child to external service manager.
    HostToManager,
    /// External service manager to RuntimeHost child.
    ManagerToHost,
}

/// Strictly typed watchdog message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWatchdogFrameBody {
    /// Monotonic bootstrap stage; stages cannot be skipped or repeated.
    BootstrapProgress(HostBootstrapPhase),
    /// Running reactor heartbeat. The global host sequence is the heartbeat
    /// sequence, so no second counter is transported.
    RunningHeartbeat,
    /// Read-only control responsiveness challenge from the external owner.
    ControlProbe(HostControlProbeNonce),
    /// Exact acknowledgement of one outstanding challenge.
    ControlAck(HostControlProbeNonce),
}

impl HostWatchdogFrameBody {
    /// Returns the only legal direction for this body.
    #[must_use]
    pub const fn direction(self) -> HostWatchdogDirection {
        match self {
            Self::BootstrapProgress(_) | Self::RunningHeartbeat | Self::ControlAck(_) => {
                HostWatchdogDirection::HostToManager
            }
            Self::ControlProbe(_) => HostWatchdogDirection::ManagerToHost,
        }
    }

    const fn wire_kind(self) -> u16 {
        match self {
            Self::BootstrapProgress(_) => BOOTSTRAP_PROGRESS_KIND,
            Self::RunningHeartbeat => RUNNING_HEARTBEAT_KIND,
            Self::ControlProbe(_) => CONTROL_PROBE_KIND,
            Self::ControlAck(_) => CONTROL_ACK_KIND,
        }
    }

    const fn wire_value(self) -> u64 {
        match self {
            Self::BootstrapProgress(phase) => phase as u64,
            Self::RunningHeartbeat => 0,
            Self::ControlProbe(nonce) | Self::ControlAck(nonce) => nonce.value(),
        }
    }
}

/// One complete fixed-size PXHW v1 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostWatchdogFrame {
    generation: HostWatchdogGeneration,
    sequence: HostWatchdogSequence,
    body: HostWatchdogFrameBody,
}

impl HostWatchdogFrame {
    /// Constructs a canonical typed frame.
    #[must_use]
    pub const fn new(
        generation: HostWatchdogGeneration,
        sequence: HostWatchdogSequence,
        body: HostWatchdogFrameBody,
    ) -> Self {
        Self {
            generation,
            sequence,
            body,
        }
    }

    /// Child generation fenced by this frame.
    #[must_use]
    pub const fn generation(self) -> HostWatchdogGeneration {
        self.generation
    }

    /// Direction-local sequence fenced by this frame.
    #[must_use]
    pub const fn sequence(self) -> HostWatchdogSequence {
        self.sequence
    }

    /// Typed body.
    #[must_use]
    pub const fn body(self) -> HostWatchdogFrameBody {
        self.body
    }

    /// Legal direction derived from the typed body.
    #[must_use]
    pub const fn direction(self) -> HostWatchdogDirection {
        self.body.direction()
    }

    /// Encodes the exact canonical 40-byte wire record.
    #[must_use]
    pub fn encode(self) -> [u8; HOST_WATCHDOG_FRAME_BYTES] {
        let mut frame = [0_u8; HOST_WATCHDOG_FRAME_BYTES];
        frame[0..4].copy_from_slice(&HOST_WATCHDOG_PROTOCOL_MAGIC);
        frame[4..6].copy_from_slice(&HOST_WATCHDOG_PROTOCOL_VERSION.to_be_bytes());
        frame[6..8].copy_from_slice(&self.body.wire_kind().to_be_bytes());
        frame[8..16].copy_from_slice(&self.generation.value().to_be_bytes());
        frame[16..24].copy_from_slice(&self.sequence.value().to_be_bytes());
        frame[24..32].copy_from_slice(&self.body.wire_value().to_be_bytes());
        // Bytes 32..40 are reserved and must remain zero.
        frame
    }

    /// Strictly decodes one complete canonical frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, HostWatchdogProtocolError> {
        if bytes.len() != HOST_WATCHDOG_FRAME_BYTES {
            return Err(HostWatchdogProtocolError::WrongLength);
        }
        if bytes[0..4] != HOST_WATCHDOG_PROTOCOL_MAGIC {
            return Err(HostWatchdogProtocolError::MagicMismatch);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != HOST_WATCHDOG_PROTOCOL_VERSION {
            return Err(HostWatchdogProtocolError::UnsupportedVersion);
        }
        if bytes[32..40].iter().any(|byte| *byte != 0) {
            return Err(HostWatchdogProtocolError::NonZeroReserved);
        }

        let kind = u16::from_be_bytes([bytes[6], bytes[7]]);
        let generation = HostWatchdogGeneration::try_new(read_u64(bytes, 8))?;
        let sequence = HostWatchdogSequence::try_new(read_u64(bytes, 16))?;
        let value = read_u64(bytes, 24);
        let body = match kind {
            BOOTSTRAP_PROGRESS_KIND => {
                HostWatchdogFrameBody::BootstrapProgress(HostBootstrapPhase::try_from_wire(value)?)
            }
            RUNNING_HEARTBEAT_KIND if value == 0 => HostWatchdogFrameBody::RunningHeartbeat,
            RUNNING_HEARTBEAT_KIND => return Err(HostWatchdogProtocolError::InvalidBody),
            CONTROL_PROBE_KIND => {
                HostWatchdogFrameBody::ControlProbe(HostControlProbeNonce::try_new(value)?)
            }
            CONTROL_ACK_KIND => {
                HostWatchdogFrameBody::ControlAck(HostControlProbeNonce::try_new(value)?)
            }
            _ => return Err(HostWatchdogProtocolError::UnknownKind),
        };
        Ok(Self::new(generation, sequence, body))
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(value)
}

/// Stable strict-decode error code for inspection and conformance tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HostWatchdogProtocolErrorCode {
    WrongLength = 1,
    MagicMismatch = 2,
    UnsupportedVersion = 3,
    UnknownKind = 4,
    ZeroGeneration = 5,
    ZeroSequence = 6,
    ZeroControlProbeNonce = 7,
    InvalidBody = 8,
    NonZeroReserved = 9,
}

/// Strict watchdog contract rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWatchdogProtocolError {
    WrongLength,
    MagicMismatch,
    UnsupportedVersion,
    UnknownKind,
    ZeroGeneration,
    ZeroSequence,
    ZeroControlProbeNonce,
    InvalidBody,
    NonZeroReserved,
}

impl HostWatchdogProtocolError {
    /// Stable numeric reason code.
    #[must_use]
    pub const fn code(self) -> HostWatchdogProtocolErrorCode {
        match self {
            Self::WrongLength => HostWatchdogProtocolErrorCode::WrongLength,
            Self::MagicMismatch => HostWatchdogProtocolErrorCode::MagicMismatch,
            Self::UnsupportedVersion => HostWatchdogProtocolErrorCode::UnsupportedVersion,
            Self::UnknownKind => HostWatchdogProtocolErrorCode::UnknownKind,
            Self::ZeroGeneration => HostWatchdogProtocolErrorCode::ZeroGeneration,
            Self::ZeroSequence => HostWatchdogProtocolErrorCode::ZeroSequence,
            Self::ZeroControlProbeNonce => HostWatchdogProtocolErrorCode::ZeroControlProbeNonce,
            Self::InvalidBody => HostWatchdogProtocolErrorCode::InvalidBody,
            Self::NonZeroReserved => HostWatchdogProtocolErrorCode::NonZeroReserved,
        }
    }
}

impl fmt::Display for HostWatchdogProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongLength => "watchdog frame length is not canonical",
            Self::MagicMismatch => "watchdog frame magic does not match",
            Self::UnsupportedVersion => "watchdog protocol version is unsupported",
            Self::UnknownKind => "watchdog frame kind is unknown",
            Self::ZeroGeneration => "watchdog child generation must be nonzero",
            Self::ZeroSequence => "watchdog frame sequence must be nonzero",
            Self::ZeroControlProbeNonce => "watchdog control-probe nonce must be nonzero",
            Self::InvalidBody => "watchdog frame body is invalid for its kind",
            Self::NonZeroReserved => "watchdog frame reserved bytes must be zero",
        })
    }
}

impl std::error::Error for HostWatchdogProtocolError {}

#[cfg(test)]
mod tests {
    use super::{
        HOST_WATCHDOG_FRAME_BYTES, HostBootstrapPhase, HostControlProbeNonce,
        HostWatchdogDirection, HostWatchdogFrame, HostWatchdogFrameBody, HostWatchdogGeneration,
        HostWatchdogProtocolError, HostWatchdogProtocolErrorCode, HostWatchdogSequence,
    };

    fn frame(body: HostWatchdogFrameBody) -> HostWatchdogFrame {
        HostWatchdogFrame::new(
            HostWatchdogGeneration::try_new(7).expect("test generation must build"),
            HostWatchdogSequence::try_new(9).expect("test sequence must build"),
            body,
        )
    }

    #[test]
    fn every_body_round_trips_with_an_exact_direction() {
        let nonce = HostControlProbeNonce::try_new(11).expect("test nonce must build");
        let bodies = [
            HostWatchdogFrameBody::BootstrapProgress(HostBootstrapPhase::ReactorStarted),
            HostWatchdogFrameBody::BootstrapProgress(HostBootstrapPhase::ControlReady),
            HostWatchdogFrameBody::BootstrapProgress(HostBootstrapPhase::Running),
            HostWatchdogFrameBody::RunningHeartbeat,
            HostWatchdogFrameBody::ControlProbe(nonce),
            HostWatchdogFrameBody::ControlAck(nonce),
        ];
        for body in bodies {
            let original = frame(body);
            let encoded = original.encode();
            assert_eq!(encoded.len(), HOST_WATCHDOG_FRAME_BYTES);
            assert_eq!(HostWatchdogFrame::decode(&encoded), Ok(original));
        }
        assert_eq!(
            frame(HostWatchdogFrameBody::ControlProbe(nonce)).direction(),
            HostWatchdogDirection::ManagerToHost
        );
        assert_eq!(
            frame(HostWatchdogFrameBody::ControlAck(nonce)).direction(),
            HostWatchdogDirection::HostToManager
        );
    }

    #[test]
    fn canonical_probe_bytes_are_stable() {
        let nonce = HostControlProbeNonce::try_new(11).expect("test nonce must build");
        assert_eq!(
            frame(HostWatchdogFrameBody::ControlProbe(nonce)).encode(),
            [
                0x50, 0x58, 0x48, 0x57, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn strict_decoder_rejects_all_noncanonical_axes() {
        let valid = frame(HostWatchdogFrameBody::RunningHeartbeat).encode();
        assert_eq!(
            HostWatchdogFrame::decode(&valid[..HOST_WATCHDOG_FRAME_BYTES - 1]),
            Err(HostWatchdogProtocolError::WrongLength)
        );

        let cases = [
            (0, 0xff, HostWatchdogProtocolError::MagicMismatch),
            (5, 2, HostWatchdogProtocolError::UnsupportedVersion),
            (7, 0xff, HostWatchdogProtocolError::UnknownKind),
            (15, 0, HostWatchdogProtocolError::ZeroGeneration),
            (23, 0, HostWatchdogProtocolError::ZeroSequence),
            (39, 1, HostWatchdogProtocolError::NonZeroReserved),
        ];
        for (index, value, expected) in cases {
            let mut malformed = valid;
            malformed[index] = value;
            assert_eq!(HostWatchdogFrame::decode(&malformed), Err(expected));
        }

        let mut heartbeat_with_value = valid;
        heartbeat_with_value[31] = 1;
        assert_eq!(
            HostWatchdogFrame::decode(&heartbeat_with_value),
            Err(HostWatchdogProtocolError::InvalidBody)
        );

        let mut zero_nonce = frame(HostWatchdogFrameBody::ControlProbe(
            HostControlProbeNonce::try_new(1).expect("test nonce must build"),
        ))
        .encode();
        zero_nonce[31] = 0;
        assert_eq!(
            HostWatchdogFrame::decode(&zero_nonce),
            Err(HostWatchdogProtocolError::ZeroControlProbeNonce)
        );
    }

    #[test]
    fn every_protocol_error_has_a_stable_distinct_code() {
        let errors = [
            HostWatchdogProtocolError::WrongLength,
            HostWatchdogProtocolError::MagicMismatch,
            HostWatchdogProtocolError::UnsupportedVersion,
            HostWatchdogProtocolError::UnknownKind,
            HostWatchdogProtocolError::ZeroGeneration,
            HostWatchdogProtocolError::ZeroSequence,
            HostWatchdogProtocolError::ZeroControlProbeNonce,
            HostWatchdogProtocolError::InvalidBody,
            HostWatchdogProtocolError::NonZeroReserved,
        ];
        let codes = errors.map(|error| error.code() as u8);
        assert_eq!(codes, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(
            HostWatchdogProtocolError::WrongLength.code(),
            HostWatchdogProtocolErrorCode::WrongLength
        );
    }
}
