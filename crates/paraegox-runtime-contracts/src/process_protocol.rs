//! Canonical live-worker protocol for one process-isolated card instance.
//!
//! PXWP v1 is deliberately smaller than a transport implementation. It fixes
//! frame bytes, session identity fencing, direction and phase rules, exact
//! per-direction sequencing, bounded invocation credits, and retained-byte
//! accounting. It does not define process spawning, readiness admission,
//! Receipts, device ownership, replay, or recovery policy.

use core::fmt;
use std::collections::BTreeMap;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;

use crate::assignment::InstanceRef;
pub use crate::process_execution::{
    MAX_PROCESS_WORKER_CREDITS, MAX_PROCESS_WORKER_FRAME_BYTES, MAX_PROCESS_WORKER_PAYLOAD_BYTES,
    MAX_PROCESS_WORKER_RETAINED_BYTES, PROCESS_WORKER_HEADER_BYTES,
    PROCESS_WORKER_PROTOCOL_VERSION,
};
use crate::process_execution::{ProcessDomainRef, ProcessEntrypointRef};
use crate::provenance::{SourcePlanRevision, TargetSliceDigest};

/// Magic prefix of every process-worker frame.
pub const PROCESS_WORKER_PROTOCOL_MAGIC: &[u8; 4] = b"PXWP";
const PROCESS_FRAME_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.process-worker-frame.sha256.v1";
const RESERVED_FLAGS: u8 = 0;

/// Nonzero live incarnation fences for the host, ProcessDomain, and instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessSessionGenerations {
    runtime_host_epoch: u64,
    process_domain_epoch: u64,
    instance_generation: u64,
}

impl ProcessSessionGenerations {
    /// Builds the three-level live fence; zero is never an admitted incarnation.
    pub const fn try_new(
        runtime_host_epoch: u64,
        process_domain_epoch: u64,
        instance_generation: u64,
    ) -> Result<Self, ProcessProtocolError> {
        if runtime_host_epoch == 0 || process_domain_epoch == 0 || instance_generation == 0 {
            return Err(ProcessProtocolError::InvalidIdentity);
        }
        Ok(Self {
            runtime_host_epoch,
            process_domain_epoch,
            instance_generation,
        })
    }

    #[must_use]
    pub const fn runtime_host_epoch(self) -> u64 {
        self.runtime_host_epoch
    }

    #[must_use]
    pub const fn process_domain_epoch(self) -> u64 {
        self.process_domain_epoch
    }

    #[must_use]
    pub const fn instance_generation(self) -> u64 {
        self.instance_generation
    }
}

/// Exact live identity fence shared by every frame in one worker session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessSessionIdentity {
    runtime_host: RuntimeHostId,
    runtime_host_epoch: u64,
    process_domain: ProcessDomainRef,
    process_domain_epoch: u64,
    instance: InstanceRef,
    instance_generation: u64,
    source_revision: SourcePlanRevision,
    target_slice_digest: TargetSliceDigest,
}

impl ProcessSessionIdentity {
    /// Builds a session fence. All live generations and the source revision are nonzero.
    pub fn try_new(
        runtime_host: RuntimeHostId,
        process_domain: ProcessDomainRef,
        instance: InstanceRef,
        generations: ProcessSessionGenerations,
        source_revision: SourcePlanRevision,
        target_slice_digest: TargetSliceDigest,
    ) -> Result<Self, ProcessProtocolError> {
        if source_revision.value() == 0 {
            return Err(ProcessProtocolError::InvalidIdentity);
        }
        Self::validate_nonzero_16(runtime_host.as_bytes())?;
        Self::validate_nonzero_16(process_domain.as_bytes())?;
        Self::validate_nonzero_16(instance.as_bytes())?;
        Self::validate_nonzero_32(target_slice_digest.value().as_bytes())?;
        Ok(Self {
            runtime_host,
            runtime_host_epoch: generations.runtime_host_epoch(),
            process_domain,
            process_domain_epoch: generations.process_domain_epoch(),
            instance,
            instance_generation: generations.instance_generation(),
            source_revision,
            target_slice_digest,
        })
    }

    const fn validate_nonzero_16(value: &[u8; 16]) -> Result<(), ProcessProtocolError> {
        let mut index = 0;
        while index < value.len() {
            if value[index] != 0 {
                return Ok(());
            }
            index += 1;
        }
        Err(ProcessProtocolError::InvalidIdentity)
    }

    const fn validate_nonzero_32(value: &[u8; 32]) -> Result<(), ProcessProtocolError> {
        let mut index = 0;
        while index < value.len() {
            if value[index] != 0 {
                return Ok(());
            }
            index += 1;
        }
        Err(ProcessProtocolError::InvalidIdentity)
    }

    /// RuntimeHost identity owning the worker.
    #[must_use]
    pub const fn runtime_host(self) -> RuntimeHostId {
        self.runtime_host
    }

    /// RuntimeHost incarnation fence.
    #[must_use]
    pub const fn runtime_host_epoch(self) -> u64 {
        self.runtime_host_epoch
    }

    /// Desired ProcessDomain identity.
    #[must_use]
    pub const fn process_domain(self) -> ProcessDomainRef {
        self.process_domain
    }

    /// Live ProcessDomain incarnation fence.
    #[must_use]
    pub const fn process_domain_epoch(self) -> u64 {
        self.process_domain_epoch
    }

    /// Assigned instance hosted by this worker.
    #[must_use]
    pub const fn instance(self) -> InstanceRef {
        self.instance
    }

    /// Live instance-generation fence.
    #[must_use]
    pub const fn instance_generation(self) -> u64 {
        self.instance_generation
    }

    /// Exact desired-state revision used to construct the worker.
    #[must_use]
    pub const fn source_revision(self) -> SourcePlanRevision {
        self.source_revision
    }

    /// Digest of the exact target slice used to construct the worker.
    #[must_use]
    pub const fn target_slice_digest(self) -> TargetSliceDigest {
        self.target_slice_digest
    }
}

/// Direction relative to the RuntimeHost transport endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ProcessFrameDirection {
    /// RuntimeHost to worker.
    HostToWorker = 1,
    /// Worker to RuntimeHost.
    WorkerToHost = 2,
}

impl TryFrom<u8> for ProcessFrameDirection {
    type Error = ProcessProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::HostToWorker),
            2 => Ok(Self::WorkerToHost),
            _ => Err(ProcessProtocolError::InvalidEnumValue),
        }
    }
}

/// Worker lifecycle state claimed by a frame sender.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ProcessWorkerState {
    /// Bootstrap handshake is in progress.
    Starting = 1,
    /// Card construction is in progress.
    Constructing = 2,
    /// New invocations may be admitted.
    Running = 3,
    /// New invocations are forbidden while accepted work drains.
    Draining = 4,
    /// Worker shutdown has been commanded.
    Stopping = 5,
    /// Worker reports that its protocol loop has stopped.
    Stopped = 6,
}

impl TryFrom<u8> for ProcessWorkerState {
    type Error = ProcessProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Starting),
            2 => Ok(Self::Constructing),
            3 => Ok(Self::Running),
            4 => Ok(Self::Draining),
            5 => Ok(Self::Stopping),
            6 => Ok(Self::Stopped),
            _ => Err(ProcessProtocolError::InvalidEnumValue),
        }
    }
}

/// Stable PXWP v1 frame discriminants.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ProcessFrameKind {
    Start = 1,
    Ready = 2,
    Construct = 3,
    Constructed = 4,
    Invoke = 5,
    Heartbeat = 6,
    Cancel = 7,
    Terminal = 8,
    StopAccepting = 9,
    Drained = 10,
    Stop = 11,
    Stopped = 12,
    Ping = 13,
    Pong = 14,
    /// Complete Invoke receipt for one exact invocation and credit.
    Invoked = 15,
}

impl TryFrom<u8> for ProcessFrameKind {
    type Error = ProcessProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Start),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Construct),
            4 => Ok(Self::Constructed),
            5 => Ok(Self::Invoke),
            6 => Ok(Self::Heartbeat),
            7 => Ok(Self::Cancel),
            8 => Ok(Self::Terminal),
            9 => Ok(Self::StopAccepting),
            10 => Ok(Self::Drained),
            11 => Ok(Self::Stop),
            12 => Ok(Self::Stopped),
            13 => Ok(Self::Ping),
            14 => Ok(Self::Pong),
            15 => Ok(Self::Invoked),
            _ => Err(ProcessProtocolError::InvalidEnumValue),
        }
    }
}

/// Result of the worker-side construction request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ConstructOutcome {
    Constructed = 1,
    Rejected = 2,
    Failed = 3,
}

impl TryFrom<u8> for ConstructOutcome {
    type Error = ProcessProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Constructed),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Failed),
            _ => Err(ProcessProtocolError::InvalidEnumValue),
        }
    }
}

/// Worker-reported terminal callback result. This is not an effect Receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InvocationTerminalKind {
    Completed = 1,
    Rejected = 2,
    Failed = 3,
    CancelledBeforeRun = 4,
    Uncertain = 5,
}

impl TryFrom<u8> for InvocationTerminalKind {
    type Error = ProcessProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Completed),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Failed),
            4 => Ok(Self::CancelledBeforeRun),
            5 => Ok(Self::Uncertain),
            _ => Err(ProcessProtocolError::InvalidEnumValue),
        }
    }
}

/// Reason supplied with a host shutdown command.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum StopReason {
    Planned = 1,
    ApplyReplacement = 2,
    ProtocolFailure = 3,
    HostShutdown = 4,
}

impl TryFrom<u8> for StopReason {
    type Error = ProcessProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Planned),
            2 => Ok(Self::ApplyReplacement),
            3 => Ok(Self::ProtocolFailure),
            4 => Ok(Self::HostShutdown),
            _ => Err(ProcessProtocolError::InvalidEnumValue),
        }
    }
}

/// Outcome of the worker protocol loop after a Stop command.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum StoppedOutcome {
    Clean = 1,
    Forced = 2,
    Failed = 3,
}

impl TryFrom<u8> for StoppedOutcome {
    type Error = ProcessProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Clean),
            2 => Ok(Self::Forced),
            3 => Ok(Self::Failed),
            _ => Err(ProcessProtocolError::InvalidEnumValue),
        }
    }
}

/// Canonical typed body of a PXWP v1 frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessFrameBody {
    Start {
        max_inflight: u32,
        max_retained_bytes: u64,
        max_payload_bytes: u32,
        heartbeat_interval_nanos: u64,
        heartbeat_timeout_nanos: u64,
    },
    Ready {
        worker_runtime_digest: Digest32,
    },
    Construct {
        artifact_digest: Digest32,
        config_digest: Digest32,
        entrypoint_ref: ProcessEntrypointRef,
    },
    Constructed {
        outcome: ConstructOutcome,
    },
    Invoke {
        credit_id: u64,
        response_reservation_bytes: u32,
        remaining_budget_nanos: u64,
        payload: Box<[u8]>,
    },
    /// Worker accepted the complete Invoke frame; this is not a Terminal or Receipt.
    Invoked {
        credit_id: u64,
    },
    Heartbeat {
        heartbeat_sequence: u64,
        active_invocations: u32,
        retained_bytes: u64,
    },
    Cancel {
        credit_id: u64,
        grace_remaining_nanos: u64,
    },
    Terminal {
        credit_id: u64,
        kind: InvocationTerminalKind,
        payload: Box<[u8]>,
    },
    StopAccepting,
    Drained,
    Stop {
        reason: StopReason,
    },
    Stopped {
        outcome: StoppedOutcome,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

impl ProcessFrameBody {
    /// Returns the frame discriminant fixed by this body.
    #[must_use]
    pub const fn kind(&self) -> ProcessFrameKind {
        match self {
            Self::Start { .. } => ProcessFrameKind::Start,
            Self::Ready { .. } => ProcessFrameKind::Ready,
            Self::Construct { .. } => ProcessFrameKind::Construct,
            Self::Constructed { .. } => ProcessFrameKind::Constructed,
            Self::Invoke { .. } => ProcessFrameKind::Invoke,
            Self::Invoked { .. } => ProcessFrameKind::Invoked,
            Self::Heartbeat { .. } => ProcessFrameKind::Heartbeat,
            Self::Cancel { .. } => ProcessFrameKind::Cancel,
            Self::Terminal { .. } => ProcessFrameKind::Terminal,
            Self::StopAccepting => ProcessFrameKind::StopAccepting,
            Self::Drained => ProcessFrameKind::Drained,
            Self::Stop { .. } => ProcessFrameKind::Stop,
            Self::Stopped { .. } => ProcessFrameKind::Stopped,
            Self::Ping { .. } => ProcessFrameKind::Ping,
            Self::Pong { .. } => ProcessFrameKind::Pong,
        }
    }

    const fn required_direction(&self) -> ProcessFrameDirection {
        match self {
            Self::Start { .. }
            | Self::Construct { .. }
            | Self::Invoke { .. }
            | Self::Cancel { .. }
            | Self::StopAccepting
            | Self::Stop { .. }
            | Self::Ping { .. } => ProcessFrameDirection::HostToWorker,
            Self::Ready { .. }
            | Self::Constructed { .. }
            | Self::Invoked { .. }
            | Self::Heartbeat { .. }
            | Self::Terminal { .. }
            | Self::Drained
            | Self::Stopped { .. }
            | Self::Pong { .. } => ProcessFrameDirection::WorkerToHost,
        }
    }

    const fn state_is_valid(&self, state: ProcessWorkerState) -> bool {
        match self {
            Self::Start { .. } | Self::Ready { .. } => {
                matches!(state, ProcessWorkerState::Starting)
            }
            Self::Construct { .. } | Self::Constructed { .. } => {
                matches!(state, ProcessWorkerState::Constructing)
            }
            Self::Invoke { .. } => matches!(state, ProcessWorkerState::Running),
            Self::Invoked { .. }
            | Self::Heartbeat { .. }
            | Self::Cancel { .. }
            | Self::Terminal { .. }
            | Self::Ping { .. }
            | Self::Pong { .. } => {
                matches!(
                    state,
                    ProcessWorkerState::Running | ProcessWorkerState::Draining
                )
            }
            Self::StopAccepting | Self::Drained => {
                matches!(state, ProcessWorkerState::Draining)
            }
            Self::Stop { .. } => matches!(state, ProcessWorkerState::Stopping),
            Self::Stopped { .. } => matches!(state, ProcessWorkerState::Stopped),
        }
    }

    fn validate(&self) -> Result<(), ProcessProtocolError> {
        match self {
            Self::Start {
                max_inflight,
                max_retained_bytes,
                max_payload_bytes,
                heartbeat_interval_nanos,
                heartbeat_timeout_nanos,
            } => {
                let payload_limit = u32::try_from(MAX_PROCESS_WORKER_PAYLOAD_BYTES)
                    .map_err(|_| ProcessProtocolError::IntegerOverflow)?;
                if *max_inflight == 0
                    || *max_inflight > MAX_PROCESS_WORKER_CREDITS
                    || *max_retained_bytes == 0
                    || *max_retained_bytes > MAX_PROCESS_WORKER_RETAINED_BYTES
                    || *max_payload_bytes == 0
                    || *max_payload_bytes > payload_limit
                    || *heartbeat_interval_nanos == 0
                    || *heartbeat_timeout_nanos <= *heartbeat_interval_nanos
                {
                    return Err(ProcessProtocolError::InvalidBodyValue);
                }
            }
            Self::Ready {
                worker_runtime_digest,
            } => ProcessSessionIdentity::validate_nonzero_32(worker_runtime_digest.as_bytes())?,
            Self::Construct {
                artifact_digest,
                config_digest,
                entrypoint_ref,
            } => {
                ProcessSessionIdentity::validate_nonzero_32(artifact_digest.as_bytes())?;
                ProcessSessionIdentity::validate_nonzero_32(config_digest.as_bytes())?;
                ProcessSessionIdentity::validate_nonzero_16(entrypoint_ref.as_bytes())?;
            }
            Self::Invoke {
                credit_id,
                response_reservation_bytes: _,
                remaining_budget_nanos,
                payload,
            } => {
                if *credit_id == 0
                    || *remaining_budget_nanos == 0
                    || payload.len() > MAX_PROCESS_WORKER_PAYLOAD_BYTES
                {
                    return Err(ProcessProtocolError::InvalidBodyValue);
                }
            }
            Self::Invoked { credit_id } => {
                if *credit_id == 0 {
                    return Err(ProcessProtocolError::InvalidBodyValue);
                }
            }
            Self::Heartbeat {
                heartbeat_sequence, ..
            } => {
                if *heartbeat_sequence == 0 {
                    return Err(ProcessProtocolError::InvalidBodyValue);
                }
            }
            Self::Cancel { credit_id, .. } | Self::Terminal { credit_id, .. } => {
                if *credit_id == 0 {
                    return Err(ProcessProtocolError::InvalidBodyValue);
                }
                if let Self::Terminal { payload, .. } = self
                    && payload.len() > MAX_PROCESS_WORKER_PAYLOAD_BYTES
                {
                    return Err(ProcessProtocolError::InvalidBodyValue);
                }
            }
            Self::Ping { nonce } | Self::Pong { nonce } => {
                if *nonce == 0 {
                    return Err(ProcessProtocolError::InvalidBodyValue);
                }
            }
            Self::Constructed { .. }
            | Self::StopAccepting
            | Self::Drained
            | Self::Stop { .. }
            | Self::Stopped { .. } => {}
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, ProcessProtocolError> {
        self.validate()?;
        let mut encoded = Vec::new();
        match self {
            Self::Start {
                max_inflight,
                max_retained_bytes,
                max_payload_bytes,
                heartbeat_interval_nanos,
                heartbeat_timeout_nanos,
            } => {
                encoded.extend_from_slice(&max_inflight.to_be_bytes());
                encoded.extend_from_slice(&max_retained_bytes.to_be_bytes());
                encoded.extend_from_slice(&max_payload_bytes.to_be_bytes());
                encoded.extend_from_slice(&heartbeat_interval_nanos.to_be_bytes());
                encoded.extend_from_slice(&heartbeat_timeout_nanos.to_be_bytes());
            }
            Self::Ready {
                worker_runtime_digest,
            } => encoded.extend_from_slice(worker_runtime_digest.as_bytes()),
            Self::Construct {
                artifact_digest,
                config_digest,
                entrypoint_ref,
            } => {
                encoded.extend_from_slice(artifact_digest.as_bytes());
                encoded.extend_from_slice(config_digest.as_bytes());
                encoded.extend_from_slice(entrypoint_ref.as_bytes());
            }
            Self::Constructed { outcome } => encoded.push(*outcome as u8),
            Self::Invoke {
                credit_id,
                response_reservation_bytes,
                remaining_budget_nanos,
                payload,
            } => {
                encoded.extend_from_slice(&credit_id.to_be_bytes());
                encoded.extend_from_slice(&length_u32(payload.len())?.to_be_bytes());
                encoded.extend_from_slice(&response_reservation_bytes.to_be_bytes());
                encoded.extend_from_slice(&remaining_budget_nanos.to_be_bytes());
                encoded.extend_from_slice(payload);
            }
            Self::Invoked { credit_id } => encoded.extend_from_slice(&credit_id.to_be_bytes()),
            Self::Heartbeat {
                heartbeat_sequence,
                active_invocations,
                retained_bytes,
            } => {
                encoded.extend_from_slice(&heartbeat_sequence.to_be_bytes());
                encoded.extend_from_slice(&active_invocations.to_be_bytes());
                encoded.extend_from_slice(&retained_bytes.to_be_bytes());
            }
            Self::Cancel {
                credit_id,
                grace_remaining_nanos,
            } => {
                encoded.extend_from_slice(&credit_id.to_be_bytes());
                encoded.extend_from_slice(&grace_remaining_nanos.to_be_bytes());
            }
            Self::Terminal {
                credit_id,
                kind,
                payload,
            } => {
                encoded.extend_from_slice(&credit_id.to_be_bytes());
                encoded.push(*kind as u8);
                encoded.extend_from_slice(&[0; 3]);
                encoded.extend_from_slice(&length_u32(payload.len())?.to_be_bytes());
                encoded.extend_from_slice(payload);
            }
            Self::StopAccepting | Self::Drained => {}
            Self::Stop { reason } => encoded.push(*reason as u8),
            Self::Stopped { outcome } => encoded.push(*outcome as u8),
            Self::Ping { nonce } | Self::Pong { nonce } => {
                encoded.extend_from_slice(&nonce.to_be_bytes());
            }
        }
        Ok(encoded)
    }
}

/// One validated canonical PXWP v1 frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessFrame {
    identity: ProcessSessionIdentity,
    sequence: u64,
    direction: ProcessFrameDirection,
    state: ProcessWorkerState,
    invocation_id: u64,
    body: ProcessFrameBody,
    canonical_wire: Box<[u8]>,
    digest: Digest32,
}

/// Owned invocation terminal fields extracted without copying its payload.
#[derive(Debug, Eq, PartialEq)]
pub struct ProcessTerminalParts {
    invocation_id: u64,
    credit_id: u64,
    kind: InvocationTerminalKind,
    payload: Box<[u8]>,
}

impl ProcessTerminalParts {
    #[must_use]
    pub const fn invocation_id(&self) -> u64 {
        self.invocation_id
    }

    #[must_use]
    pub const fn credit_id(&self) -> u64 {
        self.credit_id
    }

    #[must_use]
    pub const fn kind(&self) -> InvocationTerminalKind {
        self.kind
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Moves all terminal fields to the caller, including the retained payload.
    #[must_use]
    pub fn into_parts(self) -> (u64, u64, InvocationTerminalKind, Box<[u8]>) {
        (self.invocation_id, self.credit_id, self.kind, self.payload)
    }
}

impl ProcessFrame {
    /// Constructs and canonicalizes a frame before any bytes are handed to a transport.
    pub fn try_new(
        identity: ProcessSessionIdentity,
        sequence: u64,
        direction: ProcessFrameDirection,
        state: ProcessWorkerState,
        invocation_id: u64,
        body: ProcessFrameBody,
    ) -> Result<Self, ProcessProtocolError> {
        if sequence == 0 {
            return Err(ProcessProtocolError::InvalidSequence);
        }
        if direction != body.required_direction() {
            return Err(ProcessProtocolError::DirectionMismatch);
        }
        if !body.state_is_valid(state) {
            return Err(ProcessProtocolError::StateMismatch);
        }
        let invocation_scoped = matches!(
            body,
            ProcessFrameBody::Invoke { .. }
                | ProcessFrameBody::Invoked { .. }
                | ProcessFrameBody::Cancel { .. }
                | ProcessFrameBody::Terminal { .. }
        );
        if invocation_scoped != (invocation_id != 0) {
            return Err(ProcessProtocolError::InvalidInvocationScope);
        }
        let body_wire = body.encode()?;
        let canonical_wire = build_frame_wire(
            identity,
            sequence,
            direction,
            state,
            invocation_id,
            body.kind(),
            &body_wire,
        )?;
        let digest = digest_frame(&canonical_wire)?;
        Ok(Self {
            identity,
            sequence,
            direction,
            state,
            invocation_id,
            body,
            canonical_wire: canonical_wire.into_boxed_slice(),
            digest,
        })
    }

    /// Strictly decodes a complete canonical PXWP v1 frame.
    pub fn decode(frame: &[u8]) -> Result<Self, ProcessProtocolError> {
        decode_frame(frame)
    }

    #[must_use]
    pub const fn identity(&self) -> ProcessSessionIdentity {
        self.identity
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn direction(&self) -> ProcessFrameDirection {
        self.direction
    }

    #[must_use]
    pub const fn state(&self) -> ProcessWorkerState {
        self.state
    }

    #[must_use]
    pub const fn invocation_id(&self) -> u64 {
        self.invocation_id
    }

    #[must_use]
    pub const fn kind(&self) -> ProcessFrameKind {
        self.body.kind()
    }

    #[must_use]
    pub const fn body(&self) -> &ProcessFrameBody {
        &self.body
    }

    /// Consumes a Terminal frame and moves out its invocation fields and payload.
    ///
    /// `None` means the consumed frame was not Terminal. Callers that must retain
    /// non-terminal frames should inspect [`Self::kind`] before consuming it.
    #[must_use]
    pub fn into_terminal_parts(self) -> Option<ProcessTerminalParts> {
        let ProcessFrameBody::Terminal {
            credit_id,
            kind,
            payload,
        } = self.body
        else {
            return None;
        };
        Some(ProcessTerminalParts {
            invocation_id: self.invocation_id,
            credit_id,
            kind,
            payload,
        })
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub const fn digest(&self) -> &Digest32 {
        &self.digest
    }
}

/// Stateful protocol phase used to validate a complete bidirectional dialogue.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProcessProtocolPhase {
    AwaitStart,
    AwaitReady,
    AwaitConstruct,
    AwaitConstructed,
    Running,
    Draining,
    AwaitStop,
    Stopping,
    Failed,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreditLease {
    credit_id: u64,
    response_reservation_bytes: u32,
    retained_bytes: u64,
    invoked: bool,
}

/// Pure next-state validator for one PXWP dialogue.
///
/// `advance` returns a new value and never mutates the accepted state on error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessProtocolSession {
    identity: ProcessSessionIdentity,
    phase: ProcessProtocolPhase,
    host_sequence: u64,
    worker_sequence: u64,
    limits: Option<StartLimits>,
    active: BTreeMap<u64, CreditLease>,
    retained_bytes: u64,
    heartbeat_sequence: u64,
    pending_ping: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartLimits {
    max_inflight: u32,
    max_retained_bytes: u64,
    max_payload_bytes: u32,
}

impl ProcessProtocolSession {
    /// Creates an empty dialogue for an exact pre-established identity fence.
    #[must_use]
    pub fn new(identity: ProcessSessionIdentity) -> Self {
        Self {
            identity,
            phase: ProcessProtocolPhase::AwaitStart,
            host_sequence: 0,
            worker_sequence: 0,
            limits: None,
            active: BTreeMap::new(),
            retained_bytes: 0,
            heartbeat_sequence: 0,
            pending_ping: None,
        }
    }

    #[must_use]
    pub const fn phase(&self) -> ProcessProtocolPhase {
        self.phase
    }

    #[must_use]
    pub fn active_invocations(&self) -> usize {
        self.active.len()
    }

    /// Number of active invocations with an explicit worker `Invoked` acknowledgement.
    #[must_use]
    pub fn invoked_invocations(&self) -> usize {
        self.active.values().filter(|lease| lease.invoked).count()
    }

    #[must_use]
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Validates one frame and returns the advanced state.
    pub fn advance(&self, frame: &ProcessFrame) -> Result<Self, ProcessProtocolError> {
        if frame.identity != self.identity {
            return Err(ProcessProtocolError::IdentityMismatch);
        }
        let expected_sequence = match frame.direction {
            ProcessFrameDirection::HostToWorker => self.host_sequence.checked_add(1),
            ProcessFrameDirection::WorkerToHost => self.worker_sequence.checked_add(1),
        }
        .ok_or(ProcessProtocolError::IntegerOverflow)?;
        if frame.sequence != expected_sequence {
            return Err(ProcessProtocolError::SequenceViolation);
        }

        let mut next = self.clone();
        next.apply_body(frame)?;
        match frame.direction {
            ProcessFrameDirection::HostToWorker => next.host_sequence = frame.sequence,
            ProcessFrameDirection::WorkerToHost => next.worker_sequence = frame.sequence,
        }
        Ok(next)
    }

    fn apply_body(&mut self, frame: &ProcessFrame) -> Result<(), ProcessProtocolError> {
        match frame.body() {
            ProcessFrameBody::Start {
                max_inflight,
                max_retained_bytes,
                max_payload_bytes,
                ..
            } if self.phase == ProcessProtocolPhase::AwaitStart => {
                self.limits = Some(StartLimits {
                    max_inflight: *max_inflight,
                    max_retained_bytes: *max_retained_bytes,
                    max_payload_bytes: *max_payload_bytes,
                });
                self.phase = ProcessProtocolPhase::AwaitReady;
            }
            ProcessFrameBody::Ready { .. } if self.phase == ProcessProtocolPhase::AwaitReady => {
                self.phase = ProcessProtocolPhase::AwaitConstruct;
            }
            ProcessFrameBody::Construct { .. }
                if self.phase == ProcessProtocolPhase::AwaitConstruct =>
            {
                self.phase = ProcessProtocolPhase::AwaitConstructed;
            }
            ProcessFrameBody::Constructed { outcome }
                if self.phase == ProcessProtocolPhase::AwaitConstructed =>
            {
                self.phase = if *outcome == ConstructOutcome::Constructed {
                    ProcessProtocolPhase::Running
                } else {
                    ProcessProtocolPhase::Failed
                };
            }
            ProcessFrameBody::Invoke {
                credit_id,
                response_reservation_bytes,
                payload,
                ..
            } if self.phase == ProcessProtocolPhase::Running => {
                let limits = self.limits.ok_or(ProcessProtocolError::PhaseViolation)?;
                let active = u32::try_from(self.active.len())
                    .map_err(|_| ProcessProtocolError::IntegerOverflow)?;
                if active >= limits.max_inflight {
                    return Err(ProcessProtocolError::CreditExhausted);
                }
                if payload.len()
                    > usize::try_from(limits.max_payload_bytes)
                        .map_err(|_| ProcessProtocolError::IntegerOverflow)?
                    || *response_reservation_bytes > limits.max_payload_bytes
                {
                    return Err(ProcessProtocolError::InvalidBodyValue);
                }
                if self.active.contains_key(&frame.invocation_id)
                    || self
                        .active
                        .values()
                        .any(|lease| lease.credit_id == *credit_id)
                {
                    return Err(ProcessProtocolError::DuplicateCredit);
                }
                let request_bytes = u64::try_from(payload.len())
                    .map_err(|_| ProcessProtocolError::IntegerOverflow)?;
                let retained = request_bytes
                    .checked_add(u64::from(*response_reservation_bytes))
                    .ok_or(ProcessProtocolError::IntegerOverflow)?;
                let next_retained = self
                    .retained_bytes
                    .checked_add(retained)
                    .ok_or(ProcessProtocolError::IntegerOverflow)?;
                if next_retained > limits.max_retained_bytes {
                    return Err(ProcessProtocolError::RetainedBytesExceeded);
                }
                self.active.insert(
                    frame.invocation_id,
                    CreditLease {
                        credit_id: *credit_id,
                        response_reservation_bytes: *response_reservation_bytes,
                        retained_bytes: retained,
                        invoked: false,
                    },
                );
                self.retained_bytes = next_retained;
            }
            ProcessFrameBody::Invoked { credit_id }
                if matches!(
                    self.phase,
                    ProcessProtocolPhase::Running | ProcessProtocolPhase::Draining
                ) =>
            {
                let lease = self
                    .active
                    .get_mut(&frame.invocation_id)
                    .ok_or(ProcessProtocolError::UnknownCredit)?;
                if lease.credit_id != *credit_id {
                    return Err(ProcessProtocolError::UnknownCredit);
                }
                if lease.invoked {
                    return Err(ProcessProtocolError::InvocationAckViolation);
                }
                lease.invoked = true;
            }
            ProcessFrameBody::Cancel { credit_id, .. }
                if matches!(
                    self.phase,
                    ProcessProtocolPhase::Running | ProcessProtocolPhase::Draining
                ) =>
            {
                let lease = self
                    .active
                    .get(&frame.invocation_id)
                    .ok_or(ProcessProtocolError::UnknownCredit)?;
                if lease.credit_id != *credit_id {
                    return Err(ProcessProtocolError::UnknownCredit);
                }
            }
            ProcessFrameBody::Terminal {
                credit_id, payload, ..
            } if matches!(
                self.phase,
                ProcessProtocolPhase::Running | ProcessProtocolPhase::Draining
            ) =>
            {
                let lease = self
                    .active
                    .get(&frame.invocation_id)
                    .copied()
                    .ok_or(ProcessProtocolError::UnknownCredit)?;
                if lease.credit_id != *credit_id {
                    return Err(ProcessProtocolError::UnknownCredit);
                }
                if !lease.invoked {
                    return Err(ProcessProtocolError::InvocationAckViolation);
                }
                if payload.len()
                    > usize::try_from(lease.response_reservation_bytes)
                        .map_err(|_| ProcessProtocolError::IntegerOverflow)?
                {
                    return Err(ProcessProtocolError::RetainedBytesExceeded);
                }
                self.active.remove(&frame.invocation_id);
                self.retained_bytes = self
                    .retained_bytes
                    .checked_sub(lease.retained_bytes)
                    .ok_or(ProcessProtocolError::IntegerOverflow)?;
            }
            ProcessFrameBody::Heartbeat {
                heartbeat_sequence,
                active_invocations,
                retained_bytes,
            } if matches!(
                self.phase,
                ProcessProtocolPhase::Running | ProcessProtocolPhase::Draining
            ) =>
            {
                let expected = self
                    .heartbeat_sequence
                    .checked_add(1)
                    .ok_or(ProcessProtocolError::IntegerOverflow)?;
                if *heartbeat_sequence != expected {
                    return Err(ProcessProtocolError::HeartbeatSequenceViolation);
                }
                let mut invoked_active = 0_u32;
                let mut invoked_retained = 0_u64;
                for lease in self.active.values().filter(|lease| lease.invoked) {
                    invoked_active = invoked_active
                        .checked_add(1)
                        .ok_or(ProcessProtocolError::IntegerOverflow)?;
                    invoked_retained = invoked_retained
                        .checked_add(lease.retained_bytes)
                        .ok_or(ProcessProtocolError::IntegerOverflow)?;
                }
                if invoked_active != *active_invocations || invoked_retained != *retained_bytes {
                    return Err(ProcessProtocolError::RetainedSnapshotMismatch);
                }
                self.heartbeat_sequence = *heartbeat_sequence;
            }
            ProcessFrameBody::Ping { nonce }
                if matches!(
                    self.phase,
                    ProcessProtocolPhase::Running | ProcessProtocolPhase::Draining
                ) =>
            {
                if self.pending_ping.is_some() {
                    return Err(ProcessProtocolError::PingViolation);
                }
                self.pending_ping = Some(*nonce);
            }
            ProcessFrameBody::Pong { nonce }
                if matches!(
                    self.phase,
                    ProcessProtocolPhase::Running | ProcessProtocolPhase::Draining
                ) =>
            {
                if self.pending_ping != Some(*nonce) {
                    return Err(ProcessProtocolError::PingViolation);
                }
                self.pending_ping = None;
            }
            ProcessFrameBody::StopAccepting if self.phase == ProcessProtocolPhase::Running => {
                self.phase = ProcessProtocolPhase::Draining;
            }
            ProcessFrameBody::Drained if self.phase == ProcessProtocolPhase::Draining => {
                if !self.active.is_empty() || self.retained_bytes != 0 {
                    return Err(ProcessProtocolError::RetainedSnapshotMismatch);
                }
                self.phase = ProcessProtocolPhase::AwaitStop;
            }
            ProcessFrameBody::Stop { .. }
                if matches!(
                    self.phase,
                    ProcessProtocolPhase::AwaitStop | ProcessProtocolPhase::Failed
                ) =>
            {
                if !self.active.is_empty() || self.retained_bytes != 0 {
                    return Err(ProcessProtocolError::RetainedSnapshotMismatch);
                }
                self.phase = ProcessProtocolPhase::Stopping;
            }
            ProcessFrameBody::Stopped { .. } if self.phase == ProcessProtocolPhase::Stopping => {
                self.phase = ProcessProtocolPhase::Stopped;
            }
            _ => return Err(ProcessProtocolError::PhaseViolation),
        }
        Ok(())
    }
}

fn length_u32(length: usize) -> Result<u32, ProcessProtocolError> {
    u32::try_from(length).map_err(|_| ProcessProtocolError::IntegerOverflow)
}

fn build_frame_wire(
    identity: ProcessSessionIdentity,
    sequence: u64,
    direction: ProcessFrameDirection,
    state: ProcessWorkerState,
    invocation_id: u64,
    kind: ProcessFrameKind,
    body: &[u8],
) -> Result<Vec<u8>, ProcessProtocolError> {
    let total_length = PROCESS_WORKER_HEADER_BYTES
        .checked_add(body.len())
        .ok_or(ProcessProtocolError::IntegerOverflow)?;
    if total_length > MAX_PROCESS_WORKER_FRAME_BYTES {
        return Err(ProcessProtocolError::FrameTooLarge);
    }
    let mut wire = Vec::with_capacity(total_length);
    wire.extend_from_slice(PROCESS_WORKER_PROTOCOL_MAGIC);
    wire.extend_from_slice(&PROCESS_WORKER_PROTOCOL_VERSION.to_be_bytes());
    let header_length = u16::try_from(PROCESS_WORKER_HEADER_BYTES)
        .map_err(|_| ProcessProtocolError::IntegerOverflow)?;
    wire.extend_from_slice(&header_length.to_be_bytes());
    wire.extend_from_slice(&length_u32(total_length)?.to_be_bytes());
    wire.push(kind as u8);
    wire.push(direction as u8);
    wire.push(state as u8);
    wire.push(RESERVED_FLAGS);
    wire.extend_from_slice(&sequence.to_be_bytes());
    wire.extend_from_slice(identity.runtime_host().as_bytes());
    wire.extend_from_slice(&identity.runtime_host_epoch().to_be_bytes());
    wire.extend_from_slice(identity.process_domain().as_bytes());
    wire.extend_from_slice(&identity.process_domain_epoch().to_be_bytes());
    wire.extend_from_slice(identity.instance().as_bytes());
    wire.extend_from_slice(&identity.instance_generation().to_be_bytes());
    wire.extend_from_slice(&invocation_id.to_be_bytes());
    wire.extend_from_slice(&identity.source_revision().value().to_be_bytes());
    wire.extend_from_slice(identity.target_slice_digest().value().as_bytes());
    wire.extend_from_slice(&length_u32(body.len())?.to_be_bytes());
    wire.extend_from_slice(body);
    if wire.len() != total_length {
        return Err(ProcessProtocolError::InvalidFrameLength);
    }
    Ok(wire)
}

fn digest_frame(frame: &[u8]) -> Result<Digest32, ProcessProtocolError> {
    let mut builder = Digest32Builder::try_new(PROCESS_FRAME_DIGEST_DOMAIN)?;
    builder.field_bytes(frame)?;
    Ok(builder.finish())
}

fn decode_frame(frame: &[u8]) -> Result<ProcessFrame, ProcessProtocolError> {
    if frame.len() > MAX_PROCESS_WORKER_FRAME_BYTES {
        return Err(ProcessProtocolError::FrameTooLarge);
    }
    if frame.len() < PROCESS_WORKER_HEADER_BYTES {
        return Err(ProcessProtocolError::Truncated);
    }
    if &frame[..4] != PROCESS_WORKER_PROTOCOL_MAGIC {
        return Err(ProcessProtocolError::InvalidMagic);
    }
    if read_u16(frame, 4)? != PROCESS_WORKER_PROTOCOL_VERSION {
        return Err(ProcessProtocolError::UnsupportedVersion);
    }
    if usize::from(read_u16(frame, 6)?) != PROCESS_WORKER_HEADER_BYTES {
        return Err(ProcessProtocolError::InvalidHeaderLength);
    }
    let total_length =
        usize::try_from(read_u32(frame, 8)?).map_err(|_| ProcessProtocolError::IntegerOverflow)?;
    if total_length != frame.len() {
        return Err(ProcessProtocolError::InvalidFrameLength);
    }
    let kind = ProcessFrameKind::try_from(frame[12])?;
    let direction = ProcessFrameDirection::try_from(frame[13])?;
    let state = ProcessWorkerState::try_from(frame[14])?;
    if frame[15] != RESERVED_FLAGS {
        return Err(ProcessProtocolError::ReservedBitsSet);
    }
    let sequence = read_u64(frame, 16)?;
    let runtime_host = RuntimeHostId::from_bytes(read_array(frame, 24)?);
    let runtime_host_epoch = read_u64(frame, 40)?;
    let process_domain = ProcessDomainRef::from_bytes(read_array(frame, 48)?);
    let process_domain_epoch = read_u64(frame, 64)?;
    let instance = InstanceRef::from_bytes(read_array(frame, 72)?);
    let instance_generation = read_u64(frame, 88)?;
    let invocation_id = read_u64(frame, 96)?;
    let source_revision = SourcePlanRevision::new(read_u64(frame, 104)?);
    let target_slice_digest = TargetSliceDigest::new(Digest32::from_bytes(read_array(frame, 112)?));
    let body_length = usize::try_from(read_u32(frame, 144)?)
        .map_err(|_| ProcessProtocolError::IntegerOverflow)?;
    let expected_total = PROCESS_WORKER_HEADER_BYTES
        .checked_add(body_length)
        .ok_or(ProcessProtocolError::IntegerOverflow)?;
    if expected_total != frame.len() {
        return Err(ProcessProtocolError::InvalidBodyLength);
    }
    let identity = ProcessSessionIdentity::try_new(
        runtime_host,
        process_domain,
        instance,
        ProcessSessionGenerations::try_new(
            runtime_host_epoch,
            process_domain_epoch,
            instance_generation,
        )?,
        source_revision,
        target_slice_digest,
    )?;
    let body = decode_body(kind, &frame[PROCESS_WORKER_HEADER_BYTES..])?;
    let decoded = ProcessFrame::try_new(identity, sequence, direction, state, invocation_id, body)?;
    if decoded.canonical_wire() != frame {
        return Err(ProcessProtocolError::NonCanonicalFrame);
    }
    Ok(decoded)
}

fn decode_body(
    kind: ProcessFrameKind,
    body: &[u8],
) -> Result<ProcessFrameBody, ProcessProtocolError> {
    let exact = |length: usize| {
        if body.len() == length {
            Ok(())
        } else {
            Err(ProcessProtocolError::InvalidBodyLength)
        }
    };
    match kind {
        ProcessFrameKind::Start => {
            exact(32)?;
            Ok(ProcessFrameBody::Start {
                max_inflight: read_u32(body, 0)?,
                max_retained_bytes: read_u64(body, 4)?,
                max_payload_bytes: read_u32(body, 12)?,
                heartbeat_interval_nanos: read_u64(body, 16)?,
                heartbeat_timeout_nanos: read_u64(body, 24)?,
            })
        }
        ProcessFrameKind::Ready => {
            exact(32)?;
            Ok(ProcessFrameBody::Ready {
                worker_runtime_digest: Digest32::from_bytes(read_array(body, 0)?),
            })
        }
        ProcessFrameKind::Construct => {
            exact(80)?;
            Ok(ProcessFrameBody::Construct {
                artifact_digest: Digest32::from_bytes(read_array(body, 0)?),
                config_digest: Digest32::from_bytes(read_array(body, 32)?),
                entrypoint_ref: ProcessEntrypointRef::from_bytes(read_array(body, 64)?),
            })
        }
        ProcessFrameKind::Constructed => {
            exact(1)?;
            Ok(ProcessFrameBody::Constructed {
                outcome: ConstructOutcome::try_from(body[0])?,
            })
        }
        ProcessFrameKind::Invoke => {
            if body.len() < 24 {
                return Err(ProcessProtocolError::Truncated);
            }
            let payload_length = usize::try_from(read_u32(body, 8)?)
                .map_err(|_| ProcessProtocolError::IntegerOverflow)?;
            let expected_length = 24usize
                .checked_add(payload_length)
                .ok_or(ProcessProtocolError::IntegerOverflow)?;
            if body.len() != expected_length {
                return Err(ProcessProtocolError::InvalidBodyLength);
            }
            Ok(ProcessFrameBody::Invoke {
                credit_id: read_u64(body, 0)?,
                response_reservation_bytes: read_u32(body, 12)?,
                remaining_budget_nanos: read_u64(body, 16)?,
                payload: body[24..].into(),
            })
        }
        ProcessFrameKind::Invoked => {
            exact(8)?;
            Ok(ProcessFrameBody::Invoked {
                credit_id: read_u64(body, 0)?,
            })
        }
        ProcessFrameKind::Heartbeat => {
            exact(20)?;
            Ok(ProcessFrameBody::Heartbeat {
                heartbeat_sequence: read_u64(body, 0)?,
                active_invocations: read_u32(body, 8)?,
                retained_bytes: read_u64(body, 12)?,
            })
        }
        ProcessFrameKind::Cancel => {
            exact(16)?;
            Ok(ProcessFrameBody::Cancel {
                credit_id: read_u64(body, 0)?,
                grace_remaining_nanos: read_u64(body, 8)?,
            })
        }
        ProcessFrameKind::Terminal => {
            if body.len() < 16 {
                return Err(ProcessProtocolError::Truncated);
            }
            if body[9..12] != [0; 3] {
                return Err(ProcessProtocolError::ReservedBitsSet);
            }
            let payload_length = usize::try_from(read_u32(body, 12)?)
                .map_err(|_| ProcessProtocolError::IntegerOverflow)?;
            let expected_length = 16usize
                .checked_add(payload_length)
                .ok_or(ProcessProtocolError::IntegerOverflow)?;
            if body.len() != expected_length {
                return Err(ProcessProtocolError::InvalidBodyLength);
            }
            Ok(ProcessFrameBody::Terminal {
                credit_id: read_u64(body, 0)?,
                kind: InvocationTerminalKind::try_from(body[8])?,
                payload: body[16..].into(),
            })
        }
        ProcessFrameKind::StopAccepting => {
            exact(0)?;
            Ok(ProcessFrameBody::StopAccepting)
        }
        ProcessFrameKind::Drained => {
            exact(0)?;
            Ok(ProcessFrameBody::Drained)
        }
        ProcessFrameKind::Stop => {
            exact(1)?;
            Ok(ProcessFrameBody::Stop {
                reason: StopReason::try_from(body[0])?,
            })
        }
        ProcessFrameKind::Stopped => {
            exact(1)?;
            Ok(ProcessFrameBody::Stopped {
                outcome: StoppedOutcome::try_from(body[0])?,
            })
        }
        ProcessFrameKind::Ping => {
            exact(8)?;
            Ok(ProcessFrameBody::Ping {
                nonce: read_u64(body, 0)?,
            })
        }
        ProcessFrameKind::Pong => {
            exact(8)?;
            Ok(ProcessFrameBody::Pong {
                nonce: read_u64(body, 0)?,
            })
        }
    }
}

fn read_u16(frame: &[u8], offset: usize) -> Result<u16, ProcessProtocolError> {
    Ok(u16::from_be_bytes(read_array(frame, offset)?))
}

fn read_u32(frame: &[u8], offset: usize) -> Result<u32, ProcessProtocolError> {
    Ok(u32::from_be_bytes(read_array(frame, offset)?))
}

fn read_u64(frame: &[u8], offset: usize) -> Result<u64, ProcessProtocolError> {
    Ok(u64::from_be_bytes(read_array(frame, offset)?))
}

fn read_array<const N: usize>(
    frame: &[u8],
    offset: usize,
) -> Result<[u8; N], ProcessProtocolError> {
    let end = offset
        .checked_add(N)
        .ok_or(ProcessProtocolError::IntegerOverflow)?;
    let bytes = frame
        .get(offset..end)
        .ok_or(ProcessProtocolError::Truncated)?;
    bytes
        .try_into()
        .map_err(|_| ProcessProtocolError::Truncated)
}

/// Stable machine-readable PXWP error codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum ProcessProtocolErrorCode {
    FrameTooLarge = 1,
    Truncated = 2,
    InvalidMagic = 3,
    UnsupportedVersion = 4,
    InvalidHeaderLength = 5,
    InvalidFrameLength = 6,
    InvalidEnumValue = 7,
    ReservedBitsSet = 8,
    InvalidIdentity = 9,
    InvalidSequence = 10,
    InvalidInvocationScope = 11,
    InvalidBodyLength = 12,
    InvalidBodyValue = 13,
    DirectionMismatch = 14,
    StateMismatch = 15,
    PhaseViolation = 16,
    SequenceViolation = 17,
    IdentityMismatch = 18,
    CreditExhausted = 19,
    DuplicateCredit = 20,
    UnknownCredit = 21,
    RetainedBytesExceeded = 22,
    RetainedSnapshotMismatch = 23,
    HeartbeatSequenceViolation = 24,
    PingViolation = 25,
    NonCanonicalFrame = 26,
    DigestFailure = 27,
    IntegerOverflow = 28,
    InvocationAckViolation = 29,
}

/// Strict PXWP construction, decoding, or dialogue error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessProtocolError {
    FrameTooLarge,
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    InvalidHeaderLength,
    InvalidFrameLength,
    InvalidEnumValue,
    ReservedBitsSet,
    InvalidIdentity,
    InvalidSequence,
    InvalidInvocationScope,
    InvalidBodyLength,
    InvalidBodyValue,
    DirectionMismatch,
    StateMismatch,
    PhaseViolation,
    SequenceViolation,
    IdentityMismatch,
    CreditExhausted,
    DuplicateCredit,
    UnknownCredit,
    RetainedBytesExceeded,
    RetainedSnapshotMismatch,
    HeartbeatSequenceViolation,
    PingViolation,
    NonCanonicalFrame,
    DigestFailure,
    IntegerOverflow,
    InvocationAckViolation,
}

impl ProcessProtocolError {
    /// Returns the stable numeric category for telemetry and cross-language tests.
    #[must_use]
    pub const fn code(self) -> ProcessProtocolErrorCode {
        match self {
            Self::FrameTooLarge => ProcessProtocolErrorCode::FrameTooLarge,
            Self::Truncated => ProcessProtocolErrorCode::Truncated,
            Self::InvalidMagic => ProcessProtocolErrorCode::InvalidMagic,
            Self::UnsupportedVersion => ProcessProtocolErrorCode::UnsupportedVersion,
            Self::InvalidHeaderLength => ProcessProtocolErrorCode::InvalidHeaderLength,
            Self::InvalidFrameLength => ProcessProtocolErrorCode::InvalidFrameLength,
            Self::InvalidEnumValue => ProcessProtocolErrorCode::InvalidEnumValue,
            Self::ReservedBitsSet => ProcessProtocolErrorCode::ReservedBitsSet,
            Self::InvalidIdentity => ProcessProtocolErrorCode::InvalidIdentity,
            Self::InvalidSequence => ProcessProtocolErrorCode::InvalidSequence,
            Self::InvalidInvocationScope => ProcessProtocolErrorCode::InvalidInvocationScope,
            Self::InvalidBodyLength => ProcessProtocolErrorCode::InvalidBodyLength,
            Self::InvalidBodyValue => ProcessProtocolErrorCode::InvalidBodyValue,
            Self::DirectionMismatch => ProcessProtocolErrorCode::DirectionMismatch,
            Self::StateMismatch => ProcessProtocolErrorCode::StateMismatch,
            Self::PhaseViolation => ProcessProtocolErrorCode::PhaseViolation,
            Self::SequenceViolation => ProcessProtocolErrorCode::SequenceViolation,
            Self::IdentityMismatch => ProcessProtocolErrorCode::IdentityMismatch,
            Self::CreditExhausted => ProcessProtocolErrorCode::CreditExhausted,
            Self::DuplicateCredit => ProcessProtocolErrorCode::DuplicateCredit,
            Self::UnknownCredit => ProcessProtocolErrorCode::UnknownCredit,
            Self::RetainedBytesExceeded => ProcessProtocolErrorCode::RetainedBytesExceeded,
            Self::RetainedSnapshotMismatch => ProcessProtocolErrorCode::RetainedSnapshotMismatch,
            Self::HeartbeatSequenceViolation => {
                ProcessProtocolErrorCode::HeartbeatSequenceViolation
            }
            Self::PingViolation => ProcessProtocolErrorCode::PingViolation,
            Self::NonCanonicalFrame => ProcessProtocolErrorCode::NonCanonicalFrame,
            Self::DigestFailure => ProcessProtocolErrorCode::DigestFailure,
            Self::IntegerOverflow => ProcessProtocolErrorCode::IntegerOverflow,
            Self::InvocationAckViolation => ProcessProtocolErrorCode::InvocationAckViolation,
        }
    }
}

impl From<DigestBuildError> for ProcessProtocolError {
    fn from(_: DigestBuildError) -> Self {
        Self::DigestFailure
    }
}

impl fmt::Display for ProcessProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FrameTooLarge => "PXWP frame exceeds the protocol maximum",
            Self::Truncated => "PXWP frame is truncated",
            Self::InvalidMagic => "PXWP magic is invalid",
            Self::UnsupportedVersion => "PXWP version is unsupported",
            Self::InvalidHeaderLength => "PXWP fixed header length is invalid",
            Self::InvalidFrameLength => "PXWP total frame length is invalid",
            Self::InvalidEnumValue => "PXWP enum discriminant is invalid",
            Self::ReservedBitsSet => "PXWP reserved bytes are nonzero",
            Self::InvalidIdentity => "PXWP session identity is invalid",
            Self::InvalidSequence => "PXWP frame sequence is zero",
            Self::InvalidInvocationScope => "PXWP invocation scope is inconsistent with frame kind",
            Self::InvalidBodyLength => "PXWP body length is invalid",
            Self::InvalidBodyValue => "PXWP body value violates a protocol bound",
            Self::DirectionMismatch => "PXWP frame direction is invalid for its kind",
            Self::StateMismatch => "PXWP worker state is invalid for its kind",
            Self::PhaseViolation => "PXWP frame is invalid in the current dialogue phase",
            Self::SequenceViolation => "PXWP per-direction sequence is not exactly next",
            Self::IdentityMismatch => "PXWP frame identity does not match the session fence",
            Self::CreditExhausted => "PXWP invocation credits are exhausted",
            Self::DuplicateCredit => "PXWP invocation or credit identity is already active",
            Self::UnknownCredit => "PXWP invocation credit is unknown or mismatched",
            Self::RetainedBytesExceeded => "PXWP retained-byte limit would be exceeded",
            Self::RetainedSnapshotMismatch => "PXWP retained-state snapshot is inconsistent",
            Self::HeartbeatSequenceViolation => "PXWP heartbeat sequence is not exactly next",
            Self::PingViolation => "PXWP ping/pong correlation is invalid",
            Self::NonCanonicalFrame => "PXWP frame is not canonical",
            Self::DigestFailure => "PXWP canonical digest construction failed",
            Self::IntegerOverflow => "PXWP integer arithmetic overflowed",
            Self::InvocationAckViolation => {
                "PXWP invocation acknowledgement is missing or duplicated"
            }
        })
    }
}

impl std::error::Error for ProcessProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ProcessSessionIdentity {
        ProcessSessionIdentity::try_new(
            RuntimeHostId::from_bytes([0x11; 16]),
            ProcessDomainRef::from_bytes([0x22; 16]),
            InstanceRef::from_bytes([0x33; 16]),
            ProcessSessionGenerations::try_new(7, 9, 3).expect("fixture generations"),
            SourcePlanRevision::new(5),
            TargetSliceDigest::new(Digest32::from_bytes([0x44; 32])),
        )
        .expect("fixture identity")
    }

    fn frame(
        sequence: u64,
        direction: ProcessFrameDirection,
        state: ProcessWorkerState,
        invocation: u64,
        body: ProcessFrameBody,
    ) -> ProcessFrame {
        ProcessFrame::try_new(identity(), sequence, direction, state, invocation, body)
            .expect("fixture frame")
    }

    fn start() -> ProcessFrame {
        frame(
            1,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Starting,
            0,
            ProcessFrameBody::Start {
                max_inflight: 2,
                max_retained_bytes: 64,
                max_payload_bytes: 32,
                heartbeat_interval_nanos: 1_000,
                heartbeat_timeout_nanos: 3_000,
            },
        )
    }

    fn bootstrap() -> ProcessProtocolSession {
        let frames = [
            start(),
            frame(
                1,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Starting,
                0,
                ProcessFrameBody::Ready {
                    worker_runtime_digest: Digest32::from_bytes([0x55; 32]),
                },
            ),
            frame(
                2,
                ProcessFrameDirection::HostToWorker,
                ProcessWorkerState::Constructing,
                0,
                ProcessFrameBody::Construct {
                    artifact_digest: Digest32::from_bytes([0x66; 32]),
                    config_digest: Digest32::from_bytes([0x77; 32]),
                    entrypoint_ref: ProcessEntrypointRef::from_bytes([0x88; 16]),
                },
            ),
            frame(
                2,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Constructing,
                0,
                ProcessFrameBody::Constructed {
                    outcome: ConstructOutcome::Constructed,
                },
            ),
        ];
        frames
            .iter()
            .fold(ProcessProtocolSession::new(identity()), |session, value| {
                session.advance(value).expect("bootstrap transition")
            })
    }

    #[test]
    fn canonical_python_golden_start_round_trips() {
        let value = start();
        let python_wire = decode_hex(
            "5058575000010094000000b4010101000000000000000001111111111111111111111111111111110000000000000007222222222222222222222222222222220000000000000009333333333333333333333333333333330000000000000003000000000000000000000000000000054444444444444444444444444444444444444444444444444444444444444444000000200000000200000000000000400000002000000000000003e80000000000000bb8",
        );
        assert_eq!(value.canonical_wire().len(), 180);
        assert_eq!(value.canonical_wire(), python_wire);
        assert_eq!(ProcessFrame::decode(&python_wire), Ok(value.clone()));
        assert_eq!(
            value.digest().as_bytes(),
            &[
                0xb3, 0x06, 0x3e, 0x99, 0x02, 0xee, 0xf8, 0x62, 0x64, 0x30, 0xfc, 0x34, 0x95, 0xd2,
                0x6e, 0x08, 0x84, 0x4a, 0x8b, 0x11, 0x5b, 0x37, 0x04, 0x14, 0x8b, 0x78, 0x6a, 0xc3,
                0x8c, 0xae, 0xb6, 0x03,
            ]
        );
    }

    #[test]
    fn terminal_parts_move_the_original_payload_without_clone() {
        let payload: Box<[u8]> = Box::from(&b"output"[..]);
        let payload_pointer = payload.as_ptr();
        let terminal = frame(
            3,
            ProcessFrameDirection::WorkerToHost,
            ProcessWorkerState::Running,
            41,
            ProcessFrameBody::Terminal {
                credit_id: 71,
                kind: InvocationTerminalKind::Completed,
                payload,
            },
        )
        .into_terminal_parts()
        .expect("terminal parts");

        assert_eq!(terminal.invocation_id(), 41);
        assert_eq!(terminal.credit_id(), 71);
        assert_eq!(terminal.kind(), InvocationTerminalKind::Completed);
        assert_eq!(terminal.payload(), b"output");
        assert_eq!(terminal.payload().as_ptr(), payload_pointer);
        assert!(start().into_terminal_parts().is_none());
    }

    #[test]
    fn complete_invoke_heartbeat_terminal_and_shutdown_dialogue_is_bounded() {
        let mut session = bootstrap();
        let invoke = frame(
            3,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Running,
            41,
            ProcessFrameBody::Invoke {
                credit_id: 71,
                response_reservation_bytes: 8,
                remaining_budget_nanos: 10_000,
                payload: Box::from(&b"input"[..]),
            },
        );
        session = session.advance(&invoke).expect("invoke");
        assert_eq!(session.active_invocations(), 1);
        assert_eq!(session.invoked_invocations(), 0);
        assert_eq!(session.retained_bytes(), 13);

        session = session
            .advance(&frame(
                3,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Invoked { credit_id: 71 },
            ))
            .expect("invoked acknowledgement");
        assert_eq!(session.invoked_invocations(), 1);
        session = session
            .advance(&frame(
                4,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                0,
                ProcessFrameBody::Heartbeat {
                    heartbeat_sequence: 1,
                    active_invocations: 1,
                    retained_bytes: 13,
                },
            ))
            .expect("heartbeat");
        session = session
            .advance(&frame(
                4,
                ProcessFrameDirection::HostToWorker,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Cancel {
                    credit_id: 71,
                    grace_remaining_nanos: 500,
                },
            ))
            .expect("cancel");
        session = session
            .advance(&frame(
                5,
                ProcessFrameDirection::HostToWorker,
                ProcessWorkerState::Running,
                0,
                ProcessFrameBody::Ping { nonce: 91 },
            ))
            .expect("ping");
        session = session
            .advance(&frame(
                5,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                0,
                ProcessFrameBody::Pong { nonce: 91 },
            ))
            .expect("pong");
        session = session
            .advance(&frame(
                6,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Terminal {
                    credit_id: 71,
                    kind: InvocationTerminalKind::Completed,
                    payload: Box::from(&b"output"[..]),
                },
            ))
            .expect("terminal");
        assert_eq!(session.retained_bytes(), 0);

        for value in [
            frame(
                6,
                ProcessFrameDirection::HostToWorker,
                ProcessWorkerState::Draining,
                0,
                ProcessFrameBody::StopAccepting,
            ),
            frame(
                7,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Draining,
                0,
                ProcessFrameBody::Drained,
            ),
            frame(
                7,
                ProcessFrameDirection::HostToWorker,
                ProcessWorkerState::Stopping,
                0,
                ProcessFrameBody::Stop {
                    reason: StopReason::Planned,
                },
            ),
            frame(
                8,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Stopped,
                0,
                ProcessFrameBody::Stopped {
                    outcome: StoppedOutcome::Clean,
                },
            ),
        ] {
            session = session.advance(&value).expect("shutdown transition");
        }
        assert_eq!(session.phase(), ProcessProtocolPhase::Stopped);
    }

    #[test]
    fn heartbeat_snapshot_tracks_only_worker_acknowledged_invocations() {
        let mut session = bootstrap();
        session = session
            .advance(&frame(
                3,
                ProcessFrameDirection::HostToWorker,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Invoke {
                    credit_id: 71,
                    response_reservation_bytes: 8,
                    remaining_budget_nanos: 10_000,
                    payload: Box::from(&b"input"[..]),
                },
            ))
            .expect("host holds the credit before worker receipt");
        assert_eq!(session.active_invocations(), 1);
        assert_eq!(session.invoked_invocations(), 0);
        assert_eq!(session.retained_bytes(), 13);

        session = session
            .advance(&frame(
                3,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                0,
                ProcessFrameBody::Heartbeat {
                    heartbeat_sequence: 1,
                    active_invocations: 0,
                    retained_bytes: 0,
                },
            ))
            .expect("pre-ack heartbeat reports the worker's old empty snapshot");
        session = session
            .advance(&frame(
                4,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Invoked { credit_id: 71 },
            ))
            .expect("worker acknowledges complete Invoke receipt");
        session = session
            .advance(&frame(
                5,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                0,
                ProcessFrameBody::Heartbeat {
                    heartbeat_sequence: 2,
                    active_invocations: 1,
                    retained_bytes: 13,
                },
            ))
            .expect("post-ack heartbeat reports the accepted lease");
        assert_eq!(session.active_invocations(), 1);
        assert_eq!(session.invoked_invocations(), 1);
        assert_eq!(session.retained_bytes(), 13);
    }

    #[test]
    fn heartbeat_snapshot_excludes_only_the_unacknowledged_subset() {
        let mut session = bootstrap();
        for (sequence, invocation_id, credit_id, reservation, payload) in
            [(3, 41, 71, 8, &b"input"[..]), (4, 42, 72, 7, &b"xy"[..])]
        {
            session = session
                .advance(&frame(
                    sequence,
                    ProcessFrameDirection::HostToWorker,
                    ProcessWorkerState::Running,
                    invocation_id,
                    ProcessFrameBody::Invoke {
                        credit_id,
                        response_reservation_bytes: reservation,
                        remaining_budget_nanos: 10_000,
                        payload: Box::from(payload),
                    },
                ))
                .expect("host admits bounded Invoke");
        }
        assert_eq!(session.active_invocations(), 2);
        assert_eq!(session.retained_bytes(), 22);

        session = session
            .advance(&frame(
                3,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Invoked { credit_id: 71 },
            ))
            .expect("first Invoke acknowledged");
        session = session
            .advance(&frame(
                4,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                0,
                ProcessFrameBody::Heartbeat {
                    heartbeat_sequence: 1,
                    active_invocations: 1,
                    retained_bytes: 13,
                },
            ))
            .expect("snapshot excludes the second pending handoff");
        assert_eq!(session.active_invocations(), 2);
        assert_eq!(session.invoked_invocations(), 1);
        assert_eq!(session.retained_bytes(), 22);
    }

    #[test]
    fn malformed_header_direction_state_and_scope_are_rejected() {
        let baseline = start();
        for (offset, expected) in [
            (0, ProcessProtocolErrorCode::InvalidMagic),
            (4, ProcessProtocolErrorCode::UnsupportedVersion),
            (6, ProcessProtocolErrorCode::InvalidHeaderLength),
            (12, ProcessProtocolErrorCode::InvalidEnumValue),
            (13, ProcessProtocolErrorCode::InvalidEnumValue),
            (14, ProcessProtocolErrorCode::InvalidEnumValue),
            (15, ProcessProtocolErrorCode::ReservedBitsSet),
        ] {
            let mut wire = baseline.canonical_wire().to_vec();
            wire[offset] = 0xff;
            assert_eq!(
                ProcessFrame::decode(&wire).expect_err("reject").code(),
                expected
            );
        }
        assert_eq!(
            ProcessFrame::try_new(
                identity(),
                1,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Starting,
                0,
                baseline.body().clone(),
            )
            .expect_err("wrong direction")
            .code(),
            ProcessProtocolErrorCode::DirectionMismatch
        );
        assert_eq!(
            ProcessFrame::try_new(
                identity(),
                1,
                ProcessFrameDirection::HostToWorker,
                ProcessWorkerState::Running,
                0,
                baseline.body().clone(),
            )
            .expect_err("wrong state")
            .code(),
            ProcessProtocolErrorCode::StateMismatch
        );
    }

    #[test]
    fn sequence_credit_retained_and_snapshot_violations_are_fail_closed() {
        let running = bootstrap();
        let valid = frame(
            3,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Running,
            41,
            ProcessFrameBody::Invoke {
                credit_id: 71,
                response_reservation_bytes: 8,
                remaining_budget_nanos: 1,
                payload: Box::from(&b"12345"[..]),
            },
        );
        let active = running.advance(&valid).expect("valid invoke");
        let retained_overflow = frame(
            4,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Running,
            42,
            ProcessFrameBody::Invoke {
                credit_id: 72,
                response_reservation_bytes: 32,
                remaining_budget_nanos: 1,
                payload: Box::from(&b"12345678901234567890"[..]),
            },
        );
        assert_eq!(
            active
                .advance(&retained_overflow)
                .expect_err("13 + 52 > 64")
                .code(),
            ProcessProtocolErrorCode::RetainedBytesExceeded
        );
        assert_eq!(active.active_invocations(), 1);
        assert_eq!(active.invoked_invocations(), 0);
        assert_eq!(active.retained_bytes(), 13);
        assert_eq!(
            active.advance(&valid).expect_err("replay").code(),
            ProcessProtocolErrorCode::SequenceViolation
        );
        assert_eq!(
            active
                .advance(&frame(
                    3,
                    ProcessFrameDirection::WorkerToHost,
                    ProcessWorkerState::Running,
                    0,
                    ProcessFrameBody::Heartbeat {
                        heartbeat_sequence: 1,
                        active_invocations: 1,
                        retained_bytes: 13,
                    },
                ))
                .expect_err("unacknowledged handoff must not appear in the worker snapshot")
                .code(),
            ProcessProtocolErrorCode::RetainedSnapshotMismatch
        );
        let cancelled_before_ack = active
            .advance(&frame(
                4,
                ProcessFrameDirection::HostToWorker,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Cancel {
                    credit_id: 71,
                    grace_remaining_nanos: 0,
                },
            ))
            .expect("host may cancel while the explicit acknowledgement is pending");
        assert_eq!(cancelled_before_ack.invoked_invocations(), 0);
        assert_eq!(
            active
                .advance(&frame(
                    3,
                    ProcessFrameDirection::WorkerToHost,
                    ProcessWorkerState::Running,
                    41,
                    ProcessFrameBody::Terminal {
                        credit_id: 71,
                        kind: InvocationTerminalKind::CancelledBeforeRun,
                        payload: Box::default(),
                    },
                ))
                .expect_err("Terminal must never stand in for Invoked")
                .code(),
            ProcessProtocolErrorCode::InvocationAckViolation
        );
        let acknowledged = active
            .advance(&frame(
                3,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Invoked { credit_id: 71 },
            ))
            .expect("explicit ack");
        assert_eq!(acknowledged.invoked_invocations(), 1);
        assert_eq!(
            acknowledged
                .advance(&frame(
                    4,
                    ProcessFrameDirection::WorkerToHost,
                    ProcessWorkerState::Running,
                    41,
                    ProcessFrameBody::Invoked { credit_id: 71 },
                ))
                .expect_err("duplicate ack")
                .code(),
            ProcessProtocolErrorCode::InvocationAckViolation
        );
    }

    #[test]
    fn error_codes_are_stable_and_dense() {
        let codes = [
            ProcessProtocolErrorCode::FrameTooLarge as u16,
            ProcessProtocolErrorCode::Truncated as u16,
            ProcessProtocolErrorCode::InvalidMagic as u16,
            ProcessProtocolErrorCode::UnsupportedVersion as u16,
            ProcessProtocolErrorCode::InvalidHeaderLength as u16,
            ProcessProtocolErrorCode::InvalidFrameLength as u16,
            ProcessProtocolErrorCode::InvalidEnumValue as u16,
            ProcessProtocolErrorCode::ReservedBitsSet as u16,
            ProcessProtocolErrorCode::InvalidIdentity as u16,
            ProcessProtocolErrorCode::InvalidSequence as u16,
            ProcessProtocolErrorCode::InvalidInvocationScope as u16,
            ProcessProtocolErrorCode::InvalidBodyLength as u16,
            ProcessProtocolErrorCode::InvalidBodyValue as u16,
            ProcessProtocolErrorCode::DirectionMismatch as u16,
            ProcessProtocolErrorCode::StateMismatch as u16,
            ProcessProtocolErrorCode::PhaseViolation as u16,
            ProcessProtocolErrorCode::SequenceViolation as u16,
            ProcessProtocolErrorCode::IdentityMismatch as u16,
            ProcessProtocolErrorCode::CreditExhausted as u16,
            ProcessProtocolErrorCode::DuplicateCredit as u16,
            ProcessProtocolErrorCode::UnknownCredit as u16,
            ProcessProtocolErrorCode::RetainedBytesExceeded as u16,
            ProcessProtocolErrorCode::RetainedSnapshotMismatch as u16,
            ProcessProtocolErrorCode::HeartbeatSequenceViolation as u16,
            ProcessProtocolErrorCode::PingViolation as u16,
            ProcessProtocolErrorCode::NonCanonicalFrame as u16,
            ProcessProtocolErrorCode::DigestFailure as u16,
            ProcessProtocolErrorCode::IntegerOverflow as u16,
            ProcessProtocolErrorCode::InvocationAckViolation as u16,
        ];
        assert_eq!(codes, (1..=29).collect::<Vec<_>>().as_slice());
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digits = core::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(digits, 16).expect("valid fixture hex")
            })
            .collect()
    }
}
