//! Deployment-side authenticated PXNS reducer, Runtime endpoint selector, and
//! owner-private one-shot PXQR/PXQS-to-PXNO observation publisher.
//!
//! NodeDaemon remains read-only discovery. A Node response can block a send,
//! but it never authorizes or receives PXAR. The only selected dispatch route
//! is the Runtime-owned restricted Zenoh query endpoint pinned below. The
//! local PXNO seam publishes only a previously validated Runtime query pair
//! and returns typed acknowledgement evidence; it does not claim Node Ready.

use core::fmt;

#[cfg(unix)]
use core::future::Future;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use crate::controller_store::{
    ClaimedDistributedRuntimeObservationV1, ControllerDistributedAgentStackError, ControllerStore,
    DistributedRuntimeObservationCommitDispositionV1,
};
use crate::distributed_agent_stack_producer::{
    DistributedAgentStackRolloutIdV1, VerifiedDistributedAgentStackPredecessorV1,
};
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(unix)]
use nix::unistd::{getegid, geteuid};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
use paraegox_node::observation::{
    MAX_RUNTIME_OBSERVATION_REQUEST_BYTES, RUNTIME_OBSERVATION_ACK_BYTES,
    RUNTIME_OBSERVATION_REQUEST_HEADER_BYTES, RUNTIME_OBSERVATION_TOKEN_BYTES,
    RuntimeObservationAckV1, RuntimeObservationAuthorityV1, RuntimeObservationEndpointRefV1,
    RuntimeObservationRequestInputV1, RuntimeObservationRequestV1,
};
use paraegox_node::protocol::{
    MAX_NODE_MANAGEMENT_RESPONSE_BYTES, NODE_MANAGEMENT_REQUEST_BYTES, NodeManagementRequestKindV1,
    NodeManagementRequestV1, NodeManagementResponseOutcomeV1, NodeManagementResponseV1,
    NodeManagementTargetV1, NodeStatusCursorV1,
};
use paraegox_node::{
    NodeId, NodeIncarnation, NodeManagementEndpointRefV1, RuntimeApplyEndpointDescriptorV1,
    RuntimeHostLivenessV1, RuntimeHostStatusV1,
};
use paraegox_runtime_contracts::reference_control::{
    MAX_REFERENCE_QUERY_REQUEST_BYTES, MAX_REFERENCE_QUERY_RESPONSE_BYTES,
    ReferenceBootstrapServingIdentityV1, ReferenceQueryRequestV1, ReferenceQueryResponseV1,
};
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::time::{Instant, timeout_at};
#[cfg(unix)]
use zeroize::Zeroizing;

const STATE_MAGIC: &[u8; 4] = b"PXDN";
const STATE_VERSION_V2: u16 = 2;
const STATE_VERSION_V3: u16 = 3;
const STATE_CHECKSUM_BYTES: usize = 32;
const STATE_HEADER_BYTES: usize = 66;
const TARGET_FIXED_BYTES: usize = 200;
const QUERY_FIXED_BYTES: usize = 208;
const MAX_RUNTIME_QUERY_ATTEMPTS: usize = 8;
const MAX_STATE_BYTES: usize = 1024 * 1024;
const STATE_CHECKSUM_DOMAIN_V2: &[u8] =
    b"paraegox.deployment.distributed-agent-stack.node-discovery.sha256.v2";
const STATE_CHECKSUM_DOMAIN_V3: &[u8] =
    b"paraegox.deployment.distributed-agent-stack.node-discovery.sha256.v3";
const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const RUNTIME_QUERY_NONCE_BYTES: usize = 32;

#[cfg(unix)]
const LOCAL_REQUEST_MAGIC: &[u8; 4] = b"PXNL";
#[cfg(unix)]
const LOCAL_REQUEST_VERSION: u16 = 1;
#[cfg(unix)]
const LOCAL_REQUEST_HEADER_BYTES: usize = 48;
#[cfg(unix)]
const LOCAL_REQUEST_BYTES: usize = LOCAL_REQUEST_HEADER_BYTES + NODE_MANAGEMENT_REQUEST_BYTES;
#[cfg(unix)]
const LOCAL_TOKEN_BYTES: usize = 32;
#[cfg(unix)]
const NODE_SOCKET_MODE: u32 = 0o600;
#[cfg(unix)]
const MAX_NODE_SOCKET_PATH_BYTES: usize = 103;
#[cfg(unix)]
const MAX_LOCAL_NODE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(unix)]
const LOCAL_OBSERVATION_MAGIC: &[u8; 4] = b"PXOL";
#[cfg(unix)]
const LOCAL_OBSERVATION_VERSION: u16 = 1;
#[cfg(unix)]
const LOCAL_OBSERVATION_HEADER_BYTES: usize = 48;
#[cfg(unix)]
const MAX_LOCAL_OBSERVATION_BYTES: usize =
    LOCAL_OBSERVATION_HEADER_BYTES + MAX_RUNTIME_OBSERVATION_REQUEST_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackNodeTargetV1 {
    runtime_target: RuntimeHostId,
    management_target: NodeManagementTargetV1,
    carrier_binding_digest: Digest32,
}

impl DistributedAgentStackNodeTargetV1 {
    pub(crate) fn try_new(
        runtime_target: RuntimeHostId,
        management_target: NodeManagementTargetV1,
        carrier_binding_digest: Digest32,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if bytes_are_zero(runtime_target.as_bytes()) || digest_is_zero(carrier_binding_digest) {
            return Err(DistributedAgentStackNodeReconcileError::InvalidTarget);
        }
        Ok(Self {
            runtime_target,
            management_target,
            carrier_binding_digest,
        })
    }

    #[must_use]
    pub(crate) const fn runtime_target(&self) -> RuntimeHostId {
        self.runtime_target
    }

    #[must_use]
    pub(crate) const fn management_target(&self) -> NodeManagementTargetV1 {
        self.management_target
    }
}

/// Unpersisted identity of one DeploymentController process observation run.
/// A decoded PXDN never contains this value and therefore cannot become Ready
/// from a monotonic timestamp recorded by an earlier process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NodeObservationProcessGenerationV1([u8; 16]);

impl NodeObservationProcessGenerationV1 {
    pub(crate) fn try_from_bytes(
        value: [u8; 16],
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if bytes_are_zero(&value) {
            return Err(DistributedAgentStackNodeReconcileError::InvalidProcessGeneration);
        }
        Ok(Self(value))
    }
}

/// Exact owner-private local PXNL endpoint selected by deploymentd. The token
/// is never exposed by Debug. Synchronous trusted-local socket metadata is
/// pinned first; the subsequent connect/read/write phases share one deadline
/// and never retry, with server peer credentials checked before request send.
#[cfg(unix)]
pub(crate) struct TrustedLocalNodeEndpointV1 {
    socket_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    token: Zeroizing<[u8; LOCAL_TOKEN_BYTES]>,
    carrier_binding_digest: Digest32,
    exchange_timeout: Duration,
}

#[cfg(unix)]
impl TrustedLocalNodeEndpointV1 {
    pub(crate) fn try_new(
        socket_path: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
        token: [u8; LOCAL_TOKEN_BYTES],
        carrier_binding_digest: Digest32,
        exchange_timeout: Duration,
    ) -> Result<Self, TrustedLocalNodeClientErrorV1> {
        validate_socket_path(&socket_path)?;
        if expected_uid == 0
            || expected_gid == 0
            || bytes_are_zero(&token)
            || digest_is_zero(carrier_binding_digest)
            || exchange_timeout.is_zero()
            || exchange_timeout > MAX_LOCAL_NODE_EXCHANGE_TIMEOUT
        {
            return Err(TrustedLocalNodeClientErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            socket_path,
            expected_uid,
            expected_gid,
            token: Zeroizing::new(token),
            carrier_binding_digest,
            exchange_timeout,
        })
    }

    /// After synchronous trusted-local socket metadata pinning, sends exactly
    /// one PXNL/PXNQ and returns only after a complete canonical PXNS and EOF
    /// have been authenticated. Connect/write/read share one deadline and this
    /// function never retries.
    pub(crate) async fn exchange<Observe>(
        &self,
        request: &NodeManagementRequestV1,
        process_generation: NodeObservationProcessGenerationV1,
        observe: Observe,
    ) -> Result<TransportAuthenticatedNodeResponseV1, TrustedLocalNodeClientErrorV1>
    where
        Observe: FnOnce() -> u64,
    {
        let deadline = Instant::now()
            .checked_add(self.exchange_timeout)
            .ok_or(TrustedLocalNodeClientErrorV1::InvalidConfiguration)?;
        let socket_identity =
            validate_socket_metadata(&self.socket_path, self.expected_uid, self.expected_gid)?;
        let mut stream = bounded_node_connect(deadline, &self.socket_path).await?;
        if validate_socket_metadata(&self.socket_path, self.expected_uid, self.expected_gid)?
            != socket_identity
        {
            return Err(TrustedLocalNodeClientErrorV1::SocketIdentityChanged);
        }
        let peer = stream
            .peer_cred()
            .map_err(|_| TrustedLocalNodeClientErrorV1::PeerCredentialsUnavailable)?;
        if peer.uid() != self.expected_uid || peer.gid() != self.expected_gid {
            return Err(TrustedLocalNodeClientErrorV1::PeerCredentialsMismatch);
        }

        let mut frame = Zeroizing::new([0_u8; LOCAL_REQUEST_BYTES]);
        frame[..4].copy_from_slice(LOCAL_REQUEST_MAGIC);
        frame[4..6].copy_from_slice(&LOCAL_REQUEST_VERSION.to_be_bytes());
        frame[6..8].copy_from_slice(&(LOCAL_REQUEST_HEADER_BYTES as u16).to_be_bytes());
        frame[8..12].copy_from_slice(&(LOCAL_REQUEST_BYTES as u32).to_be_bytes());
        frame[12..16].copy_from_slice(&(NODE_MANAGEMENT_REQUEST_BYTES as u32).to_be_bytes());
        frame[16..LOCAL_REQUEST_HEADER_BYTES].copy_from_slice(self.token.as_ref());
        frame[LOCAL_REQUEST_HEADER_BYTES..].copy_from_slice(request.canonical_wire());
        bounded_node_io(
            deadline,
            stream.write_all(frame.as_ref()),
            TrustedLocalNodeClientErrorV1::Write,
        )
        .await?;
        bounded_node_io(
            deadline,
            stream.shutdown(),
            TrustedLocalNodeClientErrorV1::Write,
        )
        .await?;

        let mut prefix = [0_u8; 12];
        bounded_node_io(
            deadline,
            stream.read_exact(&mut prefix),
            TrustedLocalNodeClientErrorV1::TruncatedResponse,
        )
        .await?;
        let response_length = usize::try_from(u32::from_be_bytes(
            prefix[8..12]
                .try_into()
                .map_err(|_| TrustedLocalNodeClientErrorV1::TruncatedResponse)?,
        ))
        .map_err(|_| TrustedLocalNodeClientErrorV1::ResponseTooLarge)?;
        if !(12..=MAX_NODE_MANAGEMENT_RESPONSE_BYTES).contains(&response_length) {
            return Err(TrustedLocalNodeClientErrorV1::ResponseTooLarge);
        }
        let mut response = vec![0_u8; response_length];
        response[..12].copy_from_slice(&prefix);
        bounded_node_io(
            deadline,
            stream.read_exact(&mut response[12..]),
            TrustedLocalNodeClientErrorV1::TruncatedResponse,
        )
        .await?;
        let mut trailing = [0_u8; 1];
        let trailing_length = bounded_node_io(
            deadline,
            stream.read(&mut trailing),
            TrustedLocalNodeClientErrorV1::Read,
        )
        .await?;
        if trailing_length != 0 {
            return Err(TrustedLocalNodeClientErrorV1::TrailingResponseBytes);
        }
        let observed_at_nanos = observe();
        TransportAuthenticatedNodeResponseV1::try_from_verified_carrier(
            &response,
            request,
            self.carrier_binding_digest,
            process_generation,
            observed_at_nanos,
        )
        .map_err(|_| TrustedLocalNodeClientErrorV1::InvalidResponse)
    }
}

/// Complete owner-private local PXOL/PXNO endpoint selected from one PXOB.
///
/// The token is zeroized and omitted from Debug. Construction accepts only the
/// current non-root Unix identity and one canonical absolute socket path. One
/// exchange validates the mode-0600 socket identity twice, authenticates the
/// same-user server peer, shares one absolute deadline across connect/write/
/// read, and never retries.
#[cfg(unix)]
pub(crate) struct TrustedLocalRuntimeObservationEndpointV1 {
    endpoint_ref: RuntimeObservationEndpointRefV1,
    socket_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    token: Zeroizing<[u8; RUNTIME_OBSERVATION_TOKEN_BYTES]>,
    exchange_timeout: Duration,
}

#[cfg(unix)]
impl fmt::Debug for TrustedLocalRuntimeObservationEndpointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedLocalRuntimeObservationEndpointV1")
            .field("endpoint_ref", &self.endpoint_ref)
            .field("socket_path", &"<owner-private>")
            .field("expected_uid", &self.expected_uid)
            .field("expected_gid", &self.expected_gid)
            .field("token", &"<redacted>")
            .field("exchange_timeout", &self.exchange_timeout)
            .finish()
    }
}

/// Non-replayable endpoint-produced transport completion. Construction stays
/// private to this module, so a holder of a Store claim cannot manufacture a
/// successful PXNA completion without using the selected local endpoint.
#[cfg(unix)]
pub(crate) struct CompletedDistributedRuntimeObservationExchangeV1 {
    claimed: ClaimedDistributedRuntimeObservationV1,
    result: Result<RuntimeObservationAckV1, TrustedLocalRuntimeObservationExchangeErrorV1>,
}

#[cfg(unix)]
impl CompletedDistributedRuntimeObservationExchangeV1 {
    pub(crate) fn commit_into(
        self,
        store: &mut ControllerStore,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<
        DistributedRuntimeObservationCommitDispositionV1,
        ControllerDistributedAgentStackError,
    > {
        store.commit_distributed_runtime_observation_ingress(
            DistributedRuntimeObservationCompletionIngressV1 {
                claimed: self.claimed,
                result: self.result,
            },
            expected_owner_anchor,
            predecessors,
            authorities,
            observation_endpoint_refs,
        )
    }

    #[cfg(test)]
    pub(crate) fn into_transport_test_parts(
        self,
    ) -> (
        ClaimedDistributedRuntimeObservationV1,
        Result<RuntimeObservationAckV1, TrustedLocalRuntimeObservationExchangeErrorV1>,
    ) {
        (self.claimed, self.result)
    }
}

/// Opaque one-way ingress into ControllerStore. No production API returns or
/// constructs this type outside `Completed...::commit_into`.
#[cfg(unix)]
pub(crate) struct DistributedRuntimeObservationCompletionIngressV1 {
    claimed: ClaimedDistributedRuntimeObservationV1,
    result: Result<RuntimeObservationAckV1, TrustedLocalRuntimeObservationExchangeErrorV1>,
}

#[cfg(unix)]
impl DistributedRuntimeObservationCompletionIngressV1 {
    pub(crate) fn into_store_parts(
        self,
    ) -> (
        ClaimedDistributedRuntimeObservationV1,
        Result<RuntimeObservationAckV1, TrustedLocalRuntimeObservationExchangeErrorV1>,
    ) {
        (self.claimed, self.result)
    }
}

#[cfg(unix)]
impl fmt::Debug for CompletedDistributedRuntimeObservationExchangeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedDistributedRuntimeObservationExchangeV1")
            .field("target", &self.claimed.target())
            .field("request_digest", &self.claimed.request().request_digest())
            .field("succeeded", &self.result.is_ok())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl TrustedLocalRuntimeObservationEndpointV1 {
    pub(crate) fn try_new(
        endpoint_ref: RuntimeObservationEndpointRefV1,
        socket_path: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
        token: [u8; RUNTIME_OBSERVATION_TOKEN_BYTES],
        exchange_timeout: Duration,
    ) -> Result<Self, TrustedLocalRuntimeObservationClientFailureV1> {
        validate_runtime_observation_socket_path(&socket_path)?;
        if expected_uid == 0
            || expected_gid == 0
            || expected_uid != geteuid().as_raw()
            || expected_gid != getegid().as_raw()
            || bytes_are_zero(&token)
            || exchange_timeout.is_zero()
            || exchange_timeout > MAX_LOCAL_NODE_EXCHANGE_TIMEOUT
        {
            return Err(TrustedLocalRuntimeObservationClientFailureV1::InvalidConfiguration);
        }
        Ok(Self {
            endpoint_ref,
            socket_path,
            expected_uid,
            expected_gid,
            token: Zeroizing::new(token),
            exchange_timeout,
        })
    }

    /// Sends one exact PXOL/PXNO and accepts only one exact correlated PXNA
    /// followed by EOF. A failure after request writing begins is uncertain;
    /// a complete malformed or mismatched PXNA is rejected.
    pub(crate) async fn exchange(
        &self,
        claimed: ClaimedDistributedRuntimeObservationV1,
    ) -> CompletedDistributedRuntimeObservationExchangeV1 {
        let result = if claimed.observation_endpoint_ref() != self.endpoint_ref {
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(
                TrustedLocalRuntimeObservationClientFailureV1::InvalidConfiguration,
            ))
        } else {
            self.exchange_claimed_request(claimed.request()).await
        };
        CompletedDistributedRuntimeObservationExchangeV1 { claimed, result }
    }

    async fn exchange_claimed_request(
        &self,
        request: &RuntimeObservationRequestV1,
    ) -> Result<RuntimeObservationAckV1, TrustedLocalRuntimeObservationExchangeErrorV1> {
        let deadline = Instant::now().checked_add(self.exchange_timeout).ok_or(
            TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(
                TrustedLocalRuntimeObservationClientFailureV1::InvalidConfiguration,
            ),
        )?;
        let socket_identity = validate_runtime_observation_socket_metadata(
            &self.socket_path,
            self.expected_uid,
            self.expected_gid,
        )
        .map_err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent)?;
        let mut stream = bounded_runtime_observation_connect(deadline, &self.socket_path)
            .await
            .map_err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent)?;
        if validate_runtime_observation_socket_metadata(
            &self.socket_path,
            self.expected_uid,
            self.expected_gid,
        )
        .map_err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent)?
            != socket_identity
        {
            return Err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(
                TrustedLocalRuntimeObservationClientFailureV1::SocketIdentityChanged,
            ));
        }
        validate_runtime_observation_peer_credentials(
            &stream,
            self.expected_uid,
            self.expected_gid,
        )
        .map_err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent)?;

        let request_wire = request.canonical_wire();
        if !(RUNTIME_OBSERVATION_REQUEST_HEADER_BYTES..=MAX_RUNTIME_OBSERVATION_REQUEST_BYTES)
            .contains(&request_wire.len())
        {
            return Err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(
                TrustedLocalRuntimeObservationClientFailureV1::InvalidRequest,
            ));
        }
        let frame_length = LOCAL_OBSERVATION_HEADER_BYTES
            .checked_add(request_wire.len())
            .filter(|length| *length <= MAX_LOCAL_OBSERVATION_BYTES)
            .ok_or(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(
                TrustedLocalRuntimeObservationClientFailureV1::InvalidRequest,
            ))?;
        let frame_length_u32 = u32::try_from(frame_length).map_err(|_| {
            TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(
                TrustedLocalRuntimeObservationClientFailureV1::InvalidRequest,
            )
        })?;
        let request_length_u32 = u32::try_from(request_wire.len()).map_err(|_| {
            TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(
                TrustedLocalRuntimeObservationClientFailureV1::InvalidRequest,
            )
        })?;
        let mut frame = Zeroizing::new(vec![0_u8; frame_length]);
        frame[..4].copy_from_slice(LOCAL_OBSERVATION_MAGIC);
        frame[4..6].copy_from_slice(&LOCAL_OBSERVATION_VERSION.to_be_bytes());
        frame[6..8].copy_from_slice(&(LOCAL_OBSERVATION_HEADER_BYTES as u16).to_be_bytes());
        frame[8..12].copy_from_slice(&frame_length_u32.to_be_bytes());
        frame[12..16].copy_from_slice(&request_length_u32.to_be_bytes());
        frame[16..LOCAL_OBSERVATION_HEADER_BYTES].copy_from_slice(self.token.as_ref());
        frame[LOCAL_OBSERVATION_HEADER_BYTES..].copy_from_slice(request_wire);

        bounded_runtime_observation_io(
            deadline,
            stream.write_all(frame.as_ref()),
            TrustedLocalRuntimeObservationClientFailureV1::Write,
        )
        .await
        .map_err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain)?;
        bounded_runtime_observation_io(
            deadline,
            stream.shutdown(),
            TrustedLocalRuntimeObservationClientFailureV1::Write,
        )
        .await
        .map_err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain)?;
        drop(frame);

        let mut ack_wire = [0_u8; RUNTIME_OBSERVATION_ACK_BYTES];
        bounded_runtime_observation_read_exact(deadline, &mut stream, &mut ack_wire).await?;
        let mut trailing = [0_u8; 1];
        let trailing_length = bounded_runtime_observation_io(
            deadline,
            stream.read(&mut trailing),
            TrustedLocalRuntimeObservationClientFailureV1::Read,
        )
        .await
        .map_err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain)?;
        if trailing_length != 0 {
            return Err(TrustedLocalRuntimeObservationExchangeErrorV1::Rejected(
                TrustedLocalRuntimeObservationClientFailureV1::TrailingAckBytes,
            ));
        }
        let ack = RuntimeObservationAckV1::decode(&ack_wire).map_err(|_| {
            TrustedLocalRuntimeObservationExchangeErrorV1::Rejected(
                TrustedLocalRuntimeObservationClientFailureV1::InvalidAck,
            )
        })?;
        ack.validate_for(request).map_err(|_| {
            TrustedLocalRuntimeObservationExchangeErrorV1::Rejected(
                TrustedLocalRuntimeObservationClientFailureV1::AckMismatch,
            )
        })?;
        Ok(ack)
    }
}

/// Complete non-query fields needed to build one canonical PXNO after a
/// validated Runtime query. There are no optional or inferred fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeObservationPublishFieldsV1 {
    intended_status_sequence: u64,
    freshness_budget_nanos: u64,
    runtime_host_id: RuntimeHostId,
    authority_digest: Digest32,
    challenge_issued_at_unix_nanos: u64,
    challenge_expires_at_unix_nanos: u64,
}

impl RuntimeObservationPublishFieldsV1 {
    pub(crate) const fn new(
        intended_status_sequence: u64,
        freshness_budget_nanos: u64,
        runtime_host_id: RuntimeHostId,
        authority_digest: Digest32,
        challenge_issued_at_unix_nanos: u64,
        challenge_expires_at_unix_nanos: u64,
    ) -> Self {
        Self {
            intended_status_sequence,
            freshness_budget_nanos,
            runtime_host_id,
            authority_digest,
            challenge_issued_at_unix_nanos,
            challenge_expires_at_unix_nanos,
        }
    }
}

/// PXNS plus the exact carrier binding already authenticated by a concrete
/// transport. This constructor does not perform transport authentication; it
/// is the handoff boundary after such verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportAuthenticatedNodeResponseV1 {
    response: NodeManagementResponseV1,
    carrier_binding_digest: Digest32,
    process_generation: NodeObservationProcessGenerationV1,
    observed_at_nanos: u64,
}

impl TransportAuthenticatedNodeResponseV1 {
    pub(crate) fn try_from_verified_carrier(
        response_wire: &[u8],
        request: &NodeManagementRequestV1,
        carrier_binding_digest: Digest32,
        process_generation: NodeObservationProcessGenerationV1,
        observed_at_nanos: u64,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if digest_is_zero(carrier_binding_digest) || observed_at_nanos == 0 {
            return Err(DistributedAgentStackNodeReconcileError::UnauthenticatedCarrier);
        }
        let response = NodeManagementResponseV1::decode(response_wire)
            .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidNodeResponse)?;
        response
            .validate_for(request)
            .map_err(|_| DistributedAgentStackNodeReconcileError::NodeResponseMismatch)?;
        Ok(Self {
            response,
            carrier_binding_digest,
            process_generation,
            observed_at_nanos,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DistributedAgentStackNodeAvailabilityV1 {
    NeverObserved = 0,
    Current = 1,
    Disconnected = 2,
    Fenced = 3,
    NotFound = 4,
    CursorConflict = 5,
    InvalidCurrent = 6,
}

impl DistributedAgentStackNodeAvailabilityV1 {
    fn decode(value: u8) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        match value {
            0 => Ok(Self::NeverObserved),
            1 => Ok(Self::Current),
            2 => Ok(Self::Disconnected),
            3 => Ok(Self::Fenced),
            4 => Ok(Self::NotFound),
            5 => Ok(Self::CursorConflict),
            6 => Ok(Self::InvalidCurrent),
            _ => Err(DistributedAgentStackNodeReconcileError::InvalidState),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeHostObservationHighWaterV1 {
    runtime_host_epoch: u64,
    observation_sequence: u64,
    status_digest: Digest32,
    endpoint_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DistributedAgentStackNodeRowV1 {
    target: DistributedAgentStackNodeTargetV1,
    availability: DistributedAgentStackNodeAvailabilityV1,
    status_observed_at_nanos: u64,
    status_response: Option<NodeManagementResponseV1>,
    latest_observed_at_nanos: u64,
    latest_response: Option<NodeManagementResponseV1>,
    runtime_high_water: Option<RuntimeHostObservationHighWaterV1>,
    process_latest_observed_at_nanos: u64,
    process_qualified_status_digest: Option<Digest32>,
}

/// Durable coordinator phase for one exact Runtime query and its subsequent
/// Node publication. Request-only authority is intentionally resident: after
/// process loss it can only be closed, never reconstructed for another PXQR
/// send. An exact durable PXNO may be replayed because Node owns idempotency by
/// request digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DistributedAgentStackRuntimeQueryPhaseV1 {
    RequestDurableNotSent = 1,
    ResidentAuthorityLost = 2,
    QueryNotSent = 3,
    QueryUncertain = 4,
    QueryRejected = 5,
    ResponseDurable = 6,
    ObservationDurableNotSent = 7,
    ObservationAckDurable = 8,
    ObservationNotSent = 9,
    ObservationUncertain = 10,
    ObservationRejected = 11,
}

impl DistributedAgentStackRuntimeQueryPhaseV1 {
    fn decode(value: u8) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        match value {
            1 => Ok(Self::RequestDurableNotSent),
            2 => Ok(Self::ResidentAuthorityLost),
            3 => Ok(Self::QueryNotSent),
            4 => Ok(Self::QueryUncertain),
            5 => Ok(Self::QueryRejected),
            6 => Ok(Self::ResponseDurable),
            7 => Ok(Self::ObservationDurableNotSent),
            8 => Ok(Self::ObservationAckDurable),
            9 => Ok(Self::ObservationNotSent),
            10 => Ok(Self::ObservationUncertain),
            11 => Ok(Self::ObservationRejected),
            _ => Err(DistributedAgentStackNodeReconcileError::InvalidState),
        }
    }

    #[must_use]
    pub(crate) const fn is_terminal_failure(self) -> bool {
        matches!(
            self,
            Self::ResidentAuthorityLost
                | Self::QueryNotSent
                | Self::QueryUncertain
                | Self::QueryRejected
                | Self::ObservationNotSent
                | Self::ObservationRejected
        )
    }
}

/// Exact request-time facts committed with PXQR inside PXDN v3. The query
/// nonce itself is already bound to all Node challenge facts by the public
/// Node contract; the raw observation token is never persisted here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackRuntimeQueryInputV1 {
    request: ReferenceQueryRequestV1,
    serving_baseline: ReferenceBootstrapServingIdentityV1,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    intended_status_sequence: u64,
    freshness_budget_nanos: u64,
    authority_digest: Digest32,
    challenge_issued_at_unix_nanos: u64,
    challenge_expires_at_unix_nanos: u64,
}

impl DistributedAgentStackRuntimeQueryInputV1 {
    pub(crate) fn try_new(
        request: ReferenceQueryRequestV1,
        serving_baseline: ReferenceBootstrapServingIdentityV1,
        observation_endpoint_ref: RuntimeObservationEndpointRefV1,
        fields: RuntimeObservationPublishFieldsV1,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if fields.runtime_host_id != request.target() {
            return Err(DistributedAgentStackNodeReconcileError::TargetMismatch);
        }
        let value = Self {
            request,
            serving_baseline,
            observation_endpoint_ref,
            intended_status_sequence: fields.intended_status_sequence,
            freshness_budget_nanos: fields.freshness_budget_nanos,
            authority_digest: fields.authority_digest,
            challenge_issued_at_unix_nanos: fields.challenge_issued_at_unix_nanos,
            challenge_expires_at_unix_nanos: fields.challenge_expires_at_unix_nanos,
        };
        validate_runtime_query_input(&value)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DistributedAgentStackRuntimeQueryStateV1 {
    target: RuntimeHostId,
    phase: DistributedAgentStackRuntimeQueryPhaseV1,
    request: ReferenceQueryRequestV1,
    serving_baseline: ReferenceBootstrapServingIdentityV1,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    intended_status_sequence: u64,
    freshness_budget_nanos: u64,
    authority_digest: Digest32,
    challenge_issued_at_unix_nanos: u64,
    challenge_expires_at_unix_nanos: u64,
    response: Option<ReferenceQueryResponseV1>,
    observation: Option<RuntimeObservationRequestV1>,
    ack: Option<RuntimeObservationAckV1>,
}

/// Durable PXQR material. This is evidence, not send authority. Only the
/// ControllerStore commit facade may wrap it in a resident, move-only token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackRuntimeQueryMaterialV1 {
    target: RuntimeHostId,
    request: ReferenceQueryRequestV1,
    serving_baseline: ReferenceBootstrapServingIdentityV1,
}

impl DistributedAgentStackRuntimeQueryMaterialV1 {
    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ReferenceQueryRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn serving_baseline(&self) -> ReferenceBootstrapServingIdentityV1 {
        self.serving_baseline
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackNodeDiscoveryStateV1 {
    sequence: u64,
    owner_anchor: Digest32,
    rollout_id: DistributedAgentStackRolloutIdV1,
    rows: [DistributedAgentStackNodeRowV1; 2],
    runtime_query_attempts: Vec<[DistributedAgentStackRuntimeQueryStateV1; 2]>,
    process_generation: Option<NodeObservationProcessGenerationV1>,
}

impl DistributedAgentStackNodeDiscoveryStateV1 {
    pub(crate) fn try_initialize(
        owner_anchor: Digest32,
        rollout_id: DistributedAgentStackRolloutIdV1,
        targets: [DistributedAgentStackNodeTargetV1; 2],
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        validate_target_pair(&targets, predecessors)?;
        if digest_is_zero(owner_anchor) {
            return Err(DistributedAgentStackNodeReconcileError::OwnerMismatch);
        }
        let [first, second] = targets;
        Ok(Self {
            sequence: 1,
            owner_anchor,
            rollout_id,
            rows: [empty_row(first), empty_row(second)],
            runtime_query_attempts: Vec::new(),
            process_generation: None,
        })
    }

    /// Starts one unpersisted observation run. Decoded state always has no
    /// generation, and beginning a new run clears every old process-local
    /// monotonic qualification without changing durable PXDN bytes.
    pub(crate) fn try_begin_observation_process(
        &self,
        process_generation: NodeObservationProcessGenerationV1,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        let mut next = self.clone();
        next.process_generation = Some(process_generation);
        for row in &mut next.rows {
            row.process_latest_observed_at_nanos = 0;
            row.process_qualified_status_digest = None;
        }
        next.validate()?;
        Ok(next)
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn owner_anchor(&self) -> Digest32 {
        self.owner_anchor
    }

    #[must_use]
    pub(crate) const fn rollout_id(&self) -> DistributedAgentStackRolloutIdV1 {
        self.rollout_id
    }

    #[must_use]
    pub(crate) const fn runtime_targets(&self) -> [RuntimeHostId; 2] {
        [
            self.rows[0].target.runtime_target,
            self.rows[1].target.runtime_target,
        ]
    }

    /// Returns the sequence from the exact PXNS authenticated and qualified
    /// in this process. Durable status bytes alone are insufficient: callers
    /// must first transfer the matching process-local qualification after
    /// verified reopen.
    pub(crate) fn current_authenticated_status_sequence(
        &self,
        runtime_target: RuntimeHostId,
    ) -> Result<u64, DistributedAgentStackNodeReconcileError> {
        let row = self.row(runtime_target)?;
        let response = row
            .status_response
            .as_ref()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?;
        let status = response
            .status_value()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?;
        if self.process_generation.is_none()
            || row.availability != DistributedAgentStackNodeAvailabilityV1::Current
            || row.process_qualified_status_digest != Some(status.status_digest())
            || !status_matches_target(status, &row.target)
        {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        Ok(status.status_sequence())
    }

    #[must_use]
    pub(crate) fn runtime_query_phases(
        &self,
    ) -> Option<[DistributedAgentStackRuntimeQueryPhaseV1; 2]> {
        self.runtime_query_attempts
            .last()
            .map(|queries| [queries[0].phase, queries[1].phase])
    }

    #[must_use]
    pub(crate) fn runtime_observation_pair_is_durable(&self) -> bool {
        self.runtime_query_attempts.last().is_some_and(|queries| {
            queries.iter().all(|query| {
                query.phase == DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable
            })
        })
    }

    #[must_use]
    pub(crate) fn runtime_query_attempt_count(&self) -> usize {
        self.runtime_query_attempts.len()
    }

    pub(crate) fn runtime_query_phase(
        &self,
        target: RuntimeHostId,
    ) -> Result<DistributedAgentStackRuntimeQueryPhaseV1, DistributedAgentStackNodeReconcileError>
    {
        Ok(self.runtime_query(target)?.phase)
    }

    /// Atomically introduces the fixed A/B PXQR pair. Both requests enter the
    /// same PXDN v3 successor before either resident send authority is usable.
    pub(crate) fn try_prepare_runtime_query_pair(
        &self,
        inputs: [DistributedAgentStackRuntimeQueryInputV1; 2],
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if self.runtime_query_attempts.len() >= MAX_RUNTIME_QUERY_ATTEMPTS
            || self
                .runtime_query_attempts
                .last()
                .is_some_and(|attempt| !runtime_query_attempt_is_retry_closed(attempt))
        {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        let targets = self.runtime_targets();
        if inputs[0].request.target() != targets[0] || inputs[1].request.target() != targets[1] {
            return Err(DistributedAgentStackNodeReconcileError::TargetMismatch);
        }
        let queries = [
            runtime_query_state(targets[0], inputs[0].clone())?,
            runtime_query_state(targets[1], inputs[1].clone())?,
        ];
        validate_runtime_query_pair_is_fresh(&self.runtime_query_attempts, &queries)?;
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.runtime_query_attempts.push(queries);
        next.validate()?;
        Ok(next)
    }

    /// Returns canonical evidence for ControllerStore to bind into its sealed
    /// post-commit token. This value by itself is never a send authority.
    pub(crate) fn current_runtime_query_material(
        &self,
        target: RuntimeHostId,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    ) -> Result<DistributedAgentStackRuntimeQueryMaterialV1, DistributedAgentStackNodeReconcileError>
    {
        let query = self.runtime_query(target)?;
        if query.phase != DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        validate_runtime_query_against_predecessor(query, predecessor)?;
        Ok(DistributedAgentStackRuntimeQueryMaterialV1 {
            target,
            request: query.request.clone(),
            serving_baseline: query.serving_baseline,
        })
    }

    pub(crate) fn try_close_runtime_query(
        &self,
        target: RuntimeHostId,
        closure: DistributedAgentStackRuntimeQueryPhaseV1,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if !closure.is_terminal_failure() {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        let index = self.runtime_query_index(target)?;
        let queries = self
            .runtime_query_attempts
            .last()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?;
        if queries[index].phase != DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.runtime_query_attempts
            .last_mut()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?[index]
            .phase = closure;
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn try_record_runtime_query_response(
        &self,
        target: RuntimeHostId,
        response: ReferenceQueryResponseV1,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        let index = self.runtime_query_index(target)?;
        let query = self
            .runtime_query_attempts
            .last()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?
            .get(index)
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?;
        if query.phase != DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        validate_runtime_query_against_predecessor(query, predecessor)?;
        validate_runtime_query_response(query, &response, predecessor)?;
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        let next_query = &mut next
            .runtime_query_attempts
            .last_mut()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?[index];
        next_query.phase = DistributedAgentStackRuntimeQueryPhaseV1::ResponseDurable;
        next_query.response = Some(response);
        next.validate()?;
        Ok(next)
    }

    /// Builds an exact PXNO only from the already-durable PXQR/PXQS row. The
    /// returned send authority is usable only after the caller commits `next`.
    pub(crate) fn try_prepare_runtime_observation(
        &self,
        target: RuntimeHostId,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        let index = self.runtime_query_index(target)?;
        let query = self
            .runtime_query_attempts
            .last()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?
            .get(index)
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?;
        if query.phase != DistributedAgentStackRuntimeQueryPhaseV1::ResponseDurable {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        let request = runtime_observation_request(query)?;
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        let next_query = &mut next
            .runtime_query_attempts
            .last_mut()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?[index];
        next_query.phase = DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent;
        next_query.observation = Some(request.clone());
        next.validate()?;
        Ok(next)
    }

    /// Returns the exact durable PXNO evidence. ControllerStore is the only
    /// owner allowed to wrap this into a first-send or exact-replay token.
    pub(crate) fn current_runtime_observation(
        &self,
        target: RuntimeHostId,
    ) -> Result<RuntimeObservationRequestV1, DistributedAgentStackNodeReconcileError> {
        let query = self.runtime_query(target)?;
        if !matches!(
            query.phase,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent
                | DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain
        ) {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        query
            .observation
            .clone()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)
    }

    pub(crate) fn try_record_runtime_observation_ack(
        &self,
        target: RuntimeHostId,
        request: &RuntimeObservationRequestV1,
        ack: RuntimeObservationAckV1,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        let index = self.runtime_query_index(target)?;
        let query = self
            .runtime_query_attempts
            .last()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?
            .get(index)
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?;
        if !matches!(
            query.phase,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent
                | DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain
        ) || query.observation.as_ref() != Some(request)
        {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        ack.validate_for(request)
            .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        let next_query = &mut next
            .runtime_query_attempts
            .last_mut()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?[index];
        next_query.phase = DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable;
        next_query.ack = Some(ack);
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn try_close_runtime_observation(
        &self,
        target: RuntimeHostId,
        closure: DistributedAgentStackRuntimeQueryPhaseV1,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if !matches!(
            closure,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationNotSent
                | DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain
                | DistributedAgentStackRuntimeQueryPhaseV1::ObservationRejected
        ) {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        let index = self.runtime_query_index(target)?;
        let query = &self
            .runtime_query_attempts
            .last()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?[index];
        if query.phase != DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.runtime_query_attempts
            .last_mut()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?[index]
            .phase = closure;
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn validate_runtime_queries_against_predecessors(
        &self,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<(), DistributedAgentStackNodeReconcileError> {
        for attempt in &self.runtime_query_attempts {
            for index in 0..2 {
                validate_runtime_query_against_predecessor(&attempt[index], predecessors[index])?;
            }
        }
        Ok(())
    }

    pub(crate) fn validate_runtime_queries(
        &self,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<(), DistributedAgentStackNodeReconcileError> {
        self.validate_runtime_queries_against_predecessors(predecessors)?;
        for attempt in &self.runtime_query_attempts {
            for index in 0..2 {
                if attempt[index].serving_baseline != authorities[index].serving_baseline()
                    || attempt[index].authority_digest != authorities[index].authority_digest()
                    || attempt[index].target != authorities[index].runtime_host_id()
                    || attempt[index].observation_endpoint_ref != observation_endpoint_refs[index]
                {
                    return Err(DistributedAgentStackNodeReconcileError::InvalidState);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn request_for(
        &self,
        runtime_target: RuntimeHostId,
        request_id: [u8; 16],
    ) -> Result<NodeManagementRequestV1, DistributedAgentStackNodeReconcileError> {
        let row = self.row(runtime_target)?;
        match row
            .process_qualified_status_digest
            .and_then(|digest| {
                row.status_response.as_ref().filter(|response| {
                    response
                        .status_value()
                        .is_some_and(|status| status.status_digest() == digest)
                })
            })
            .and_then(status_cursor)
        {
            Some(cursor) => {
                NodeManagementRequestV1::try_watch(request_id, row.target.management_target, cursor)
            }
            None => NodeManagementRequestV1::try_latest(request_id, row.target.management_target),
        }
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidNodeRequest)
    }

    pub(crate) fn try_observe_authenticated(
        &self,
        runtime_target: RuntimeHostId,
        request: &NodeManagementRequestV1,
        exchange: TransportAuthenticatedNodeResponseV1,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        let index = self.row_index(runtime_target)?;
        let current = &self.rows[index];
        if self.process_generation != Some(exchange.process_generation)
            || request.target() != current.target.management_target
            || exchange.carrier_binding_digest != current.target.carrier_binding_digest
            || exchange.observed_at_nanos <= current.process_latest_observed_at_nanos
        {
            return Err(DistributedAgentStackNodeReconcileError::UnauthenticatedCarrier);
        }
        exchange
            .response
            .validate_for(request)
            .map_err(|_| DistributedAgentStackNodeReconcileError::NodeResponseMismatch)?;
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        let row = &mut next.rows[index];
        row.latest_observed_at_nanos = exchange.observed_at_nanos;
        row.process_latest_observed_at_nanos = exchange.observed_at_nanos;
        row.latest_response = Some(exchange.response.clone());
        match exchange.response.outcome() {
            NodeManagementResponseOutcomeV1::Status => {
                let status = exchange
                    .response
                    .status_value()
                    .ok_or(DistributedAgentStackNodeReconcileError::InvalidNodeResponse)?;
                if !status_matches_target(status, &row.target) {
                    row.process_qualified_status_digest = None;
                    row.availability = DistributedAgentStackNodeAvailabilityV1::InvalidCurrent;
                } else {
                    match compare_status_successor(
                        row.status_response.as_ref(),
                        row.runtime_high_water.as_ref(),
                        status,
                        runtime_target,
                    ) {
                        StatusSuccessor::Advanced => {
                            row.status_observed_at_nanos = exchange.observed_at_nanos;
                            advance_runtime_high_water(
                                &mut row.runtime_high_water,
                                runtime_status(status, runtime_target),
                            );
                            row.process_qualified_status_digest = Some(status.status_digest());
                            row.status_response = Some(exchange.response);
                            row.availability = DistributedAgentStackNodeAvailabilityV1::Current;
                        }
                        StatusSuccessor::ExactReplay => {
                            row.status_observed_at_nanos = exchange.observed_at_nanos;
                            row.process_qualified_status_digest = Some(status.status_digest());
                            row.status_response = Some(exchange.response);
                            row.availability = DistributedAgentStackNodeAvailabilityV1::Current;
                        }
                        StatusSuccessor::Invalid => {
                            row.process_qualified_status_digest = None;
                            row.availability =
                                DistributedAgentStackNodeAvailabilityV1::InvalidCurrent;
                        }
                    }
                }
            }
            NodeManagementResponseOutcomeV1::NotModified => {
                let Some(cursor) = row.status_response.as_ref().and_then(status_cursor) else {
                    row.availability = DistributedAgentStackNodeAvailabilityV1::InvalidCurrent;
                    return Ok(next);
                };
                if request.kind() == NodeManagementRequestKindV1::Watch
                    && request.cursor() == Some(cursor)
                    && exchange.response.current_cursor() == Some(cursor)
                    && row.process_qualified_status_digest.is_some()
                {
                    row.availability = DistributedAgentStackNodeAvailabilityV1::Current;
                } else {
                    row.process_qualified_status_digest = None;
                    row.availability = DistributedAgentStackNodeAvailabilityV1::InvalidCurrent;
                }
            }
            NodeManagementResponseOutcomeV1::NotFound => {
                row.process_qualified_status_digest = None;
                row.availability = DistributedAgentStackNodeAvailabilityV1::NotFound;
            }
            NodeManagementResponseOutcomeV1::Fenced => {
                row.process_qualified_status_digest = None;
                row.availability = DistributedAgentStackNodeAvailabilityV1::Fenced;
            }
            NodeManagementResponseOutcomeV1::CursorConflict => {
                row.process_qualified_status_digest = None;
                row.availability = DistributedAgentStackNodeAvailabilityV1::CursorConflict;
            }
        }
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn try_observe_disconnect(
        &self,
        runtime_target: RuntimeHostId,
        process_generation: NodeObservationProcessGenerationV1,
        observed_at_nanos: u64,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if self.process_generation != Some(process_generation) || observed_at_nanos == 0 {
            return Err(DistributedAgentStackNodeReconcileError::InvalidObservationTime);
        }
        let index = self.row_index(runtime_target)?;
        if observed_at_nanos <= self.rows[index].process_latest_observed_at_nanos {
            return Err(DistributedAgentStackNodeReconcileError::InvalidObservationTime);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.rows[index].availability = DistributedAgentStackNodeAvailabilityV1::Disconnected;
        next.rows[index].latest_observed_at_nanos = observed_at_nanos;
        next.rows[index].latest_response = None;
        next.rows[index].process_latest_observed_at_nanos = observed_at_nanos;
        next.rows[index].process_qualified_status_digest = None;
        next.validate()?;
        Ok(next)
    }

    /// Transfers only the unpersisted qualification from the exact state that
    /// was just committed in this process onto a separately reopened and fully
    /// verified PXDJ/PXDN snapshot. It cannot qualify different durable bytes.
    pub(crate) fn try_qualify_verified_reopen(
        &self,
        committed_in_process: &Self,
    ) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if committed_in_process.process_generation.is_none()
            || self.encode()?.as_ref() != committed_in_process.encode()?.as_ref()
        {
            return Err(DistributedAgentStackNodeReconcileError::ProcessQualificationMismatch);
        }
        let mut next = self.clone();
        next.process_generation = committed_in_process.process_generation;
        for (row, committed) in next.rows.iter_mut().zip(&committed_in_process.rows) {
            row.process_latest_observed_at_nanos = committed.process_latest_observed_at_nanos;
            row.process_qualified_status_digest = committed.process_qualified_status_digest;
        }
        next.validate()?;
        Ok(next)
    }

    /// Selects endpoints only while both the caller's monotonic observation
    /// age and any PXNS-authenticated Unix-time validity fence remain current.
    /// The two clocks are explicit and must not be substituted for each other.
    pub(crate) fn ready_endpoints(
        &self,
        now_nanos: u64,
        now_unix_nanos: u64,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<
        [ReadyDistributedAgentStackRuntimeEndpointV1; 2],
        DistributedAgentStackNodeReconcileError,
    > {
        if self.rows[0].target.runtime_target != predecessors[0].target()
            || self.rows[1].target.runtime_target != predecessors[1].target()
        {
            return Err(DistributedAgentStackNodeReconcileError::TargetMismatch);
        }
        Ok([
            ready_endpoint(&self.rows[0], now_nanos, now_unix_nanos, predecessors[0])?,
            ready_endpoint(&self.rows[1], now_nanos, now_unix_nanos, predecessors[1])?,
        ])
    }

    pub(crate) fn encode(&self) -> Result<Box<[u8]>, DistributedAgentStackNodeReconcileError> {
        self.validate()?;
        let version = if self.runtime_query_attempts.is_empty() {
            STATE_VERSION_V2
        } else {
            STATE_VERSION_V3
        };
        let mut wire = Vec::new();
        wire.extend_from_slice(STATE_MAGIC);
        wire.extend_from_slice(&version.to_be_bytes());
        wire.extend_from_slice(&self.sequence.to_be_bytes());
        wire.extend_from_slice(self.owner_anchor.as_bytes());
        wire.extend_from_slice(self.rollout_id.as_bytes());
        wire.extend_from_slice(&2_u16.to_be_bytes());
        wire.extend_from_slice(
            &u16::try_from(self.runtime_query_attempts.len())
                .map_err(|_| DistributedAgentStackNodeReconcileError::StateTooLarge)?
                .to_be_bytes(),
        );
        for row in &self.rows {
            encode_row(&mut wire, row)?;
        }
        for attempt in &self.runtime_query_attempts {
            for query in attempt {
                encode_runtime_query(&mut wire, query)?;
            }
        }
        if wire.len().saturating_add(STATE_CHECKSUM_BYTES) > MAX_STATE_BYTES {
            return Err(DistributedAgentStackNodeReconcileError::StateTooLarge);
        }
        let checksum = state_checksum(version, &wire)?;
        wire.extend_from_slice(checksum.as_bytes());
        Ok(wire.into_boxed_slice())
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackNodeReconcileError> {
        if frame.len() < STATE_HEADER_BYTES + (2 * TARGET_FIXED_BYTES) + STATE_CHECKSUM_BYTES {
            return Err(DistributedAgentStackNodeReconcileError::StateTruncated);
        }
        if frame.len() > MAX_STATE_BYTES {
            return Err(DistributedAgentStackNodeReconcileError::StateTooLarge);
        }
        let checksum_offset = frame.len() - STATE_CHECKSUM_BYTES;
        let expected = Digest32::from_bytes(
            frame[checksum_offset..]
                .try_into()
                .map_err(|_| DistributedAgentStackNodeReconcileError::StateTruncated)?,
        );
        let version = u16::from_be_bytes(
            frame
                .get(4..6)
                .ok_or(DistributedAgentStackNodeReconcileError::StateTruncated)?
                .try_into()
                .map_err(|_| DistributedAgentStackNodeReconcileError::StateTruncated)?,
        );
        if !matches!(version, STATE_VERSION_V2 | STATE_VERSION_V3)
            || state_checksum(version, &frame[..checksum_offset])? != expected
        {
            return Err(DistributedAgentStackNodeReconcileError::ChecksumMismatch);
        }
        let mut cursor = Cursor::new(&frame[..checksum_offset]);
        if cursor.array::<4>()? != *STATE_MAGIC || cursor.u16()? != version {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        let sequence = cursor.u64()?;
        let owner_anchor = Digest32::from_bytes(cursor.array()?);
        let rollout_id = DistributedAgentStackRolloutIdV1::try_from_bytes(cursor.array()?)
            .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
        let row_count = cursor.u16()?;
        let attempt_count = usize::from(cursor.u16()?);
        if row_count != 2
            || version == STATE_VERSION_V2 && attempt_count != 0
            || version == STATE_VERSION_V3
                && !(1..=MAX_RUNTIME_QUERY_ATTEMPTS).contains(&attempt_count)
            || STATE_HEADER_BYTES
                .checked_add(2 * TARGET_FIXED_BYTES)
                .and_then(|length| {
                    attempt_count
                        .checked_mul(2 * QUERY_FIXED_BYTES)
                        .and_then(|query_bytes| length.checked_add(query_bytes))
                })
                .is_none_or(|minimum| minimum > checksum_offset)
        {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        let rows = [decode_row(&mut cursor)?, decode_row(&mut cursor)?];
        let mut runtime_query_attempts = Vec::with_capacity(attempt_count);
        for _ in 0..attempt_count {
            runtime_query_attempts.push([
                decode_runtime_query(&mut cursor)?,
                decode_runtime_query(&mut cursor)?,
            ]);
        }
        cursor.finish()?;
        let state = Self {
            sequence,
            owner_anchor,
            rollout_id,
            rows,
            runtime_query_attempts,
            process_generation: None,
        };
        state.validate()?;
        if state.encode()?.as_ref() != frame {
            return Err(DistributedAgentStackNodeReconcileError::NonCanonicalState);
        }
        Ok(state)
    }

    fn validate(&self) -> Result<(), DistributedAgentStackNodeReconcileError> {
        if self.sequence == 0
            || digest_is_zero(self.owner_anchor)
            || self.rows[0].target.runtime_target.as_bytes()
                >= self.rows[1].target.runtime_target.as_bytes()
            || self.rows[0].target.management_target.node_id()
                == self.rows[1].target.management_target.node_id()
        {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        for row in &self.rows {
            validate_row(row)?;
            if self.process_generation.is_none()
                && (row.process_latest_observed_at_nanos != 0
                    || row.process_qualified_status_digest.is_some())
            {
                return Err(DistributedAgentStackNodeReconcileError::InvalidState);
            }
            if let Some(qualified) = row.process_qualified_status_digest {
                let status = row
                    .status_response
                    .as_ref()
                    .and_then(NodeManagementResponseV1::status_value)
                    .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?;
                if self.process_generation.is_none()
                    || row.process_latest_observed_at_nanos == 0
                    || row.status_observed_at_nanos == 0
                    || qualified != status.status_digest()
                {
                    return Err(DistributedAgentStackNodeReconcileError::InvalidState);
                }
            }
        }
        if self.runtime_query_attempts.len() > MAX_RUNTIME_QUERY_ATTEMPTS {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        for (attempt_index, queries) in self.runtime_query_attempts.iter().enumerate() {
            if queries[0].target != self.rows[0].target.runtime_target
                || queries[1].target != self.rows[1].target.runtime_target
            {
                return Err(DistributedAgentStackNodeReconcileError::InvalidState);
            }
            validate_runtime_query_state(&queries[0])?;
            validate_runtime_query_state(&queries[1])?;
            validate_runtime_query_pair_is_fresh(
                &self.runtime_query_attempts[..attempt_index],
                queries,
            )?;
            if attempt_index + 1 < self.runtime_query_attempts.len()
                && !runtime_query_attempt_is_retry_closed(queries)
            {
                return Err(DistributedAgentStackNodeReconcileError::InvalidState);
            }
        }
        Ok(())
    }

    fn row(
        &self,
        target: RuntimeHostId,
    ) -> Result<&DistributedAgentStackNodeRowV1, DistributedAgentStackNodeReconcileError> {
        self.rows
            .iter()
            .find(|row| row.target.runtime_target == target)
            .ok_or(DistributedAgentStackNodeReconcileError::TargetMismatch)
    }

    fn row_index(
        &self,
        target: RuntimeHostId,
    ) -> Result<usize, DistributedAgentStackNodeReconcileError> {
        self.rows
            .iter()
            .position(|row| row.target.runtime_target == target)
            .ok_or(DistributedAgentStackNodeReconcileError::TargetMismatch)
    }

    fn runtime_query(
        &self,
        target: RuntimeHostId,
    ) -> Result<&DistributedAgentStackRuntimeQueryStateV1, DistributedAgentStackNodeReconcileError>
    {
        let index = self.runtime_query_index(target)?;
        self.runtime_query_attempts
            .last()
            .and_then(|queries| queries.get(index))
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)
    }

    fn runtime_query_index(
        &self,
        target: RuntimeHostId,
    ) -> Result<usize, DistributedAgentStackNodeReconcileError> {
        self.runtime_query_attempts
            .last()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?
            .iter()
            .position(|query| query.target == target)
            .ok_or(DistributedAgentStackNodeReconcileError::TargetMismatch)
    }

    pub(crate) fn durable_digest(
        &self,
    ) -> Result<Digest32, DistributedAgentStackNodeReconcileError> {
        let wire = self.encode()?;
        let mut builder = Digest32Builder::try_new(
            b"paraegox.deployment.distributed-agent-stack.node-state-witness.sha256.v1",
        )?;
        builder.field_bytes(&wire)?;
        Ok(builder.finish())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadyDistributedAgentStackRuntimeEndpointV1 {
    runtime_target: RuntimeHostId,
    node_id: NodeId,
    node_incarnation: NodeIncarnation,
    registration_epoch: u64,
    status_sequence: u64,
    status_digest: Digest32,
    runtime_host_epoch: u64,
    runtime_observation_sequence: u64,
    endpoint: RuntimeApplyEndpointDescriptorV1,
}

impl ReadyDistributedAgentStackRuntimeEndpointV1 {
    #[must_use]
    pub(crate) const fn runtime_target(&self) -> RuntimeHostId {
        self.runtime_target
    }

    #[must_use]
    pub(crate) fn route(&self) -> &str {
        self.endpoint.route()
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &RuntimeApplyEndpointDescriptorV1 {
        &self.endpoint
    }
}

pub(crate) fn validate_distributed_agent_stack_node_initial_wire_v1(
    frame: &[u8],
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    let state = DistributedAgentStackNodeDiscoveryStateV1::decode(frame)?;
    if state.sequence != 1
        || !state.runtime_query_attempts.is_empty()
        || state.rows.iter().any(|row| {
            row.availability != DistributedAgentStackNodeAvailabilityV1::NeverObserved
                || row.status_response.is_some()
                || row.latest_response.is_some()
                || row.runtime_high_water.is_some()
        })
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    Ok(())
}

pub(crate) fn validate_distributed_agent_stack_node_wire_successor_v1(
    previous: &[u8],
    next: &[u8],
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    let previous = DistributedAgentStackNodeDiscoveryStateV1::decode(previous)?;
    let next = DistributedAgentStackNodeDiscoveryStateV1::decode(next)?;
    if next.sequence != next_sequence(previous.sequence)?
        || next.owner_anchor != previous.owner_anchor
        || next.rollout_id != previous.rollout_id
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidSuccessor);
    }
    let changed_rows = previous
        .rows
        .iter()
        .zip(next.rows.iter())
        .filter(|(old, new)| old != new)
        .count();
    if previous
        .rows
        .iter()
        .zip(next.rows.iter())
        .any(|(old, new)| old.target != new.target || status_removed_or_regressed(old, new))
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidSuccessor);
    }
    let query_transition = validate_runtime_query_successor(
        &previous.runtime_query_attempts,
        &next.runtime_query_attempts,
    )?;
    match (changed_rows, query_transition) {
        (1, RuntimeQuerySuccessorKind::Unchanged) => Ok(()),
        (0, RuntimeQuerySuccessorKind::Advanced) => Ok(()),
        _ => Err(DistributedAgentStackNodeReconcileError::InvalidSuccessor),
    }
}

fn empty_row(target: DistributedAgentStackNodeTargetV1) -> DistributedAgentStackNodeRowV1 {
    DistributedAgentStackNodeRowV1 {
        target,
        availability: DistributedAgentStackNodeAvailabilityV1::NeverObserved,
        status_observed_at_nanos: 0,
        status_response: None,
        latest_observed_at_nanos: 0,
        latest_response: None,
        runtime_high_water: None,
        process_latest_observed_at_nanos: 0,
        process_qualified_status_digest: None,
    }
}

fn runtime_query_state(
    target: RuntimeHostId,
    input: DistributedAgentStackRuntimeQueryInputV1,
) -> Result<DistributedAgentStackRuntimeQueryStateV1, DistributedAgentStackNodeReconcileError> {
    validate_runtime_query_input(&input)?;
    if input.request.target() != target {
        return Err(DistributedAgentStackNodeReconcileError::TargetMismatch);
    }
    let query = DistributedAgentStackRuntimeQueryStateV1 {
        target,
        phase: DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent,
        request: input.request,
        serving_baseline: input.serving_baseline,
        observation_endpoint_ref: input.observation_endpoint_ref,
        intended_status_sequence: input.intended_status_sequence,
        freshness_budget_nanos: input.freshness_budget_nanos,
        authority_digest: input.authority_digest,
        challenge_issued_at_unix_nanos: input.challenge_issued_at_unix_nanos,
        challenge_expires_at_unix_nanos: input.challenge_expires_at_unix_nanos,
        response: None,
        observation: None,
        ack: None,
    };
    validate_runtime_query_state(&query)?;
    Ok(query)
}

fn validate_runtime_query_input(
    input: &DistributedAgentStackRuntimeQueryInputV1,
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    if ReferenceQueryRequestV1::decode(input.request.canonical_wire())
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?
        != input.request
        || input.request.target() != input.serving_baseline.target()
        || input.request.expected_runtime_store_instance_id()
            != input.serving_baseline.runtime_store_instance_id()
        || usize::try_from(input.request.max_response_bytes()).ok()
            != Some(MAX_REFERENCE_QUERY_RESPONSE_BYTES)
        || input.request.authentication().claim().nonce().len() != RUNTIME_QUERY_NONCE_BYTES
        || input.intended_status_sequence == 0
        || input.freshness_budget_nanos == 0
        || digest_is_zero(input.authority_digest)
        || input.challenge_issued_at_unix_nanos == 0
        || input.challenge_expires_at_unix_nanos <= input.challenge_issued_at_unix_nanos
        || input.challenge_expires_at_unix_nanos - input.challenge_issued_at_unix_nanos
            > input.freshness_budget_nanos
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    Ok(())
}

fn validate_runtime_query_state(
    query: &DistributedAgentStackRuntimeQueryStateV1,
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    validate_runtime_query_input(&DistributedAgentStackRuntimeQueryInputV1 {
        request: query.request.clone(),
        serving_baseline: query.serving_baseline,
        observation_endpoint_ref: query.observation_endpoint_ref,
        intended_status_sequence: query.intended_status_sequence,
        freshness_budget_nanos: query.freshness_budget_nanos,
        authority_digest: query.authority_digest,
        challenge_issued_at_unix_nanos: query.challenge_issued_at_unix_nanos,
        challenge_expires_at_unix_nanos: query.challenge_expires_at_unix_nanos,
    })?;
    if query.target != query.request.target() {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    let shape = match query.phase {
        DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent
        | DistributedAgentStackRuntimeQueryPhaseV1::ResidentAuthorityLost
        | DistributedAgentStackRuntimeQueryPhaseV1::QueryNotSent
        | DistributedAgentStackRuntimeQueryPhaseV1::QueryUncertain
        | DistributedAgentStackRuntimeQueryPhaseV1::QueryRejected => {
            query.response.is_none() && query.observation.is_none() && query.ack.is_none()
        }
        DistributedAgentStackRuntimeQueryPhaseV1::ResponseDurable => {
            query.response.is_some() && query.observation.is_none() && query.ack.is_none()
        }
        DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent
        | DistributedAgentStackRuntimeQueryPhaseV1::ObservationNotSent
        | DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain
        | DistributedAgentStackRuntimeQueryPhaseV1::ObservationRejected => {
            query.response.is_some() && query.observation.is_some() && query.ack.is_none()
        }
        DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable => {
            query.response.is_some() && query.observation.is_some() && query.ack.is_some()
        }
    };
    if !shape {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    if let Some(response) = &query.response
        && ReferenceQueryResponseV1::decode(response.canonical_wire())
            .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?
            != *response
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    if let Some(observation) = &query.observation
        && (RuntimeObservationRequestV1::decode(observation.canonical_wire())
            .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?
            != *observation
            || observation.runtime_host_id() != query.target
            || observation.authority_digest() != query.authority_digest
            || observation.intended_status_sequence() != query.intended_status_sequence
            || observation.freshness_budget_nanos() != query.freshness_budget_nanos
            || observation.challenge_issued_at_unix_nanos() != query.challenge_issued_at_unix_nanos
            || observation.challenge_expires_at_unix_nanos()
                != query.challenge_expires_at_unix_nanos
            || observation.query_request() != &query.request
            || query.response.as_ref() != Some(observation.query_response()))
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    if let Some(ack) = &query.ack {
        let observation = query
            .observation
            .as_ref()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?;
        ack.validate_for(observation)
            .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    }
    Ok(())
}

fn runtime_query_attempt_is_retry_closed(
    attempt: &[DistributedAgentStackRuntimeQueryStateV1; 2],
) -> bool {
    attempt.iter().all(|query| {
        query.phase == DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable
            || query.phase.is_terminal_failure()
    })
}

fn validate_runtime_query_pair_is_fresh(
    history: &[[DistributedAgentStackRuntimeQueryStateV1; 2]],
    candidate: &[DistributedAgentStackRuntimeQueryStateV1; 2],
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    if candidate[0].target == candidate[1].target
        || candidate[0].observation_endpoint_ref == candidate[1].observation_endpoint_ref
        || runtime_query_identity_reused(&candidate[0], &candidate[1])
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    for previous in history {
        for old in previous {
            for new in candidate {
                if runtime_query_identity_reused(old, new) {
                    return Err(DistributedAgentStackNodeReconcileError::InvalidState);
                }
            }
        }
    }
    Ok(())
}

fn runtime_query_identity_reused(
    first: &DistributedAgentStackRuntimeQueryStateV1,
    second: &DistributedAgentStackRuntimeQueryStateV1,
) -> bool {
    first.request.query_id() == second.request.query_id()
        || first.request.authentication().claim().nonce()
            == second.request.authentication().claim().nonce()
        || first.request.request_digest() == second.request.request_digest()
}

fn validate_runtime_query_against_predecessor(
    query: &DistributedAgentStackRuntimeQueryStateV1,
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    validate_runtime_query_state(query)?;
    let request = &query.request;
    let claim = request.authentication().claim();
    if query.target != predecessor.target()
        || request.source_scope() != predecessor.source_scope()
        || request.expected_runtime_store_instance_id()
            != predecessor.request().expected_runtime_store_instance_id()
        || request.requested_operation_id() != predecessor.request().operation_id()
        || request.expected_request_digest()
            != Some(predecessor.request().envelope_request_digest())
        || claim.principal() != predecessor.controller_principal()
        || claim.key() != predecessor.request_key()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
        || request.authentication().signature().len() != ED25519_SIGNATURE_BYTES
        || query.serving_baseline.target() != predecessor.target()
        || query.serving_baseline.runtime_store_instance_id()
            != predecessor.request().expected_runtime_store_instance_id()
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    let controller_key = VerifyingKey::from_bytes(predecessor.controller_verifying_key())
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    let signature = Signature::from_slice(request.authentication().signature())
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    controller_key
        .verify_strict(
            request
                .signing_transcript()
                .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?
                .as_bytes(),
            &signature,
        )
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    if predecessor.runtime_channel().target() != query.target {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    if let Some(response) = &query.response {
        validate_runtime_query_response(query, response, predecessor)?;
    }
    Ok(())
}

fn validate_runtime_query_response(
    query: &DistributedAgentStackRuntimeQueryStateV1,
    response: &ReferenceQueryResponseV1,
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    if response.authentication_runtime_peer() != predecessor.runtime_principal()
        || response.authentication_channel_binding_digest()
            != predecessor.runtime_channel().binding_digest()
        || response.authentication_key() != predecessor.runtime_response_key()
        || response.authentication_algorithm().value() != ED25519_ALGORITHM
        || response.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        || response.authentication_signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    let signature = Signature::from_slice(response.authentication_signature())
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    predecessor
        .runtime_response_public_key()
        .verify_strict(
            response
                .signing_transcript()
                .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?
                .as_bytes(),
            &signature,
        )
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    response
        .validate_against_request(
            &query.request,
            predecessor.runtime_channel(),
            query.serving_baseline,
        )
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    Ok(())
}

fn runtime_observation_request(
    query: &DistributedAgentStackRuntimeQueryStateV1,
) -> Result<RuntimeObservationRequestV1, DistributedAgentStackNodeReconcileError> {
    RuntimeObservationRequestV1::try_new(RuntimeObservationRequestInputV1 {
        intended_status_sequence: query.intended_status_sequence,
        freshness_budget_nanos: query.freshness_budget_nanos,
        runtime_host_id: query.target,
        authority_digest: query.authority_digest,
        challenge_issued_at_unix_nanos: query.challenge_issued_at_unix_nanos,
        challenge_expires_at_unix_nanos: query.challenge_expires_at_unix_nanos,
        query_request: query.request.clone(),
        query_response: query
            .response
            .clone()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?,
    })
    .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeQuerySuccessorKind {
    Unchanged,
    Advanced,
}

fn validate_runtime_query_successor(
    previous: &[[DistributedAgentStackRuntimeQueryStateV1; 2]],
    next: &[[DistributedAgentStackRuntimeQueryStateV1; 2]],
) -> Result<RuntimeQuerySuccessorKind, DistributedAgentStackNodeReconcileError> {
    if previous == next {
        return Ok(RuntimeQuerySuccessorKind::Unchanged);
    }
    if next.len() == previous.len().saturating_add(1)
        && next[..previous.len()] == *previous
        && previous
            .last()
            .is_none_or(runtime_query_attempt_is_retry_closed)
    {
        let appended = next
            .last()
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidSuccessor)?;
        if appended.iter().all(|query| {
            query.phase == DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent
                && query.response.is_none()
                && query.observation.is_none()
                && query.ack.is_none()
        }) {
            return Ok(RuntimeQuerySuccessorKind::Advanced);
        }
    }
    if previous.len() != next.len()
        || previous.is_empty()
        || previous[..previous.len() - 1] != next[..next.len() - 1]
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidSuccessor);
    }
    let old_attempt = previous
        .last()
        .ok_or(DistributedAgentStackNodeReconcileError::InvalidSuccessor)?;
    let new_attempt = next
        .last()
        .ok_or(DistributedAgentStackNodeReconcileError::InvalidSuccessor)?;
    let mut changed = 0_u8;
    for (old, new) in old_attempt.iter().zip(new_attempt.iter()) {
        if old == new {
            continue;
        }
        changed = changed
            .checked_add(1)
            .ok_or(DistributedAgentStackNodeReconcileError::InvalidSuccessor)?;
        validate_runtime_query_row_successor(old, new)?;
    }
    if changed == 1 {
        Ok(RuntimeQuerySuccessorKind::Advanced)
    } else {
        Err(DistributedAgentStackNodeReconcileError::InvalidSuccessor)
    }
}

fn validate_runtime_query_row_successor(
    previous: &DistributedAgentStackRuntimeQueryStateV1,
    next: &DistributedAgentStackRuntimeQueryStateV1,
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    if previous.target != next.target
        || previous.request != next.request
        || previous.serving_baseline != next.serving_baseline
        || previous.observation_endpoint_ref != next.observation_endpoint_ref
        || previous.intended_status_sequence != next.intended_status_sequence
        || previous.freshness_budget_nanos != next.freshness_budget_nanos
        || previous.authority_digest != next.authority_digest
        || previous.challenge_issued_at_unix_nanos != next.challenge_issued_at_unix_nanos
        || previous.challenge_expires_at_unix_nanos != next.challenge_expires_at_unix_nanos
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidSuccessor);
    }
    let valid = match (previous.phase, next.phase) {
        (
            DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent,
            DistributedAgentStackRuntimeQueryPhaseV1::ResidentAuthorityLost
            | DistributedAgentStackRuntimeQueryPhaseV1::QueryNotSent
            | DistributedAgentStackRuntimeQueryPhaseV1::QueryUncertain
            | DistributedAgentStackRuntimeQueryPhaseV1::QueryRejected,
        ) => next.response.is_none() && next.observation.is_none() && next.ack.is_none(),
        (
            DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent,
            DistributedAgentStackRuntimeQueryPhaseV1::ResponseDurable,
        ) => {
            previous.response.is_none()
                && next.response.is_some()
                && next.observation.is_none()
                && next.ack.is_none()
        }
        (
            DistributedAgentStackRuntimeQueryPhaseV1::ResponseDurable,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent,
        ) => {
            previous.response == next.response
                && previous.observation.is_none()
                && next.observation.is_some()
                && next.ack.is_none()
        }
        (
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable,
        ) => {
            previous.response == next.response
                && previous.observation == next.observation
                && previous.ack.is_none()
                && next.ack.is_some()
        }
        (
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationNotSent
            | DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain
            | DistributedAgentStackRuntimeQueryPhaseV1::ObservationRejected,
        ) => {
            previous.response == next.response
                && previous.observation == next.observation
                && previous.ack.is_none()
                && next.ack.is_none()
        }
        (
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable,
        ) => {
            previous.response == next.response
                && previous.observation == next.observation
                && previous.ack.is_none()
                && next.ack.is_some()
        }
        _ => false,
    };
    if valid {
        validate_runtime_query_state(next)
    } else {
        Err(DistributedAgentStackNodeReconcileError::InvalidSuccessor)
    }
}

fn validate_target_pair(
    targets: &[DistributedAgentStackNodeTargetV1; 2],
    predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    if targets[0].runtime_target.as_bytes() >= targets[1].runtime_target.as_bytes()
        || targets[0].runtime_target != predecessors[0].target()
        || targets[1].runtime_target != predecessors[1].target()
        || targets[0].management_target.node_id() == targets[1].management_target.node_id()
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidTarget);
    }
    Ok(())
}

fn status_matches_target(
    status: &paraegox_node::NodeStatusV1,
    target: &DistributedAgentStackNodeTargetV1,
) -> bool {
    status.node_id() == target.management_target.node_id()
        && status.node_incarnation() == target.management_target.node_incarnation()
        && status.registration_epoch() == target.management_target.registration_epoch()
        && status.management_endpoint_ref() == target.management_target.management_endpoint_ref()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusSuccessor {
    Advanced,
    ExactReplay,
    Invalid,
}

fn compare_status_successor(
    previous: Option<&NodeManagementResponseV1>,
    runtime_high_water: Option<&RuntimeHostObservationHighWaterV1>,
    next: &paraegox_node::NodeStatusV1,
    runtime_target: RuntimeHostId,
) -> StatusSuccessor {
    if runtime_status_regressed_from_high_water(
        runtime_high_water,
        runtime_status(next, runtime_target),
    ) {
        return StatusSuccessor::Invalid;
    }
    let Some(previous) = previous.and_then(NodeManagementResponseV1::status_value) else {
        return StatusSuccessor::Advanced;
    };
    match next.status_sequence().cmp(&previous.status_sequence()) {
        core::cmp::Ordering::Less => StatusSuccessor::Invalid,
        core::cmp::Ordering::Equal => {
            if next.status_digest() == previous.status_digest() {
                StatusSuccessor::ExactReplay
            } else {
                StatusSuccessor::Invalid
            }
        }
        core::cmp::Ordering::Greater => {
            let old_runtime = runtime_status(previous, runtime_target);
            let new_runtime = runtime_status(next, runtime_target);
            if runtime_status_regressed(old_runtime, new_runtime) {
                StatusSuccessor::Invalid
            } else {
                StatusSuccessor::Advanced
            }
        }
    }
}

fn runtime_status_regressed(
    previous: Option<&RuntimeHostStatusV1>,
    next: Option<&RuntimeHostStatusV1>,
) -> bool {
    let (Some(previous), Some(next)) = (previous, next) else {
        return false;
    };
    next.runtime_host_epoch() < previous.runtime_host_epoch()
        || next.runtime_host_epoch() == previous.runtime_host_epoch()
            && (next.observation_sequence() < previous.observation_sequence()
                || next.observation_sequence() == previous.observation_sequence()
                    && next.status_digest() != previous.status_digest())
        || next.apply_endpoint().endpoint_generation()
            < previous.apply_endpoint().endpoint_generation()
}

fn runtime_status_regressed_from_high_water(
    high_water: Option<&RuntimeHostObservationHighWaterV1>,
    next: Option<&RuntimeHostStatusV1>,
) -> bool {
    let (Some(high_water), Some(next)) = (high_water, next) else {
        return false;
    };
    next.runtime_host_epoch() < high_water.runtime_host_epoch
        || next.runtime_host_epoch() == high_water.runtime_host_epoch
            && (next.observation_sequence() < high_water.observation_sequence
                || next.observation_sequence() == high_water.observation_sequence
                    && next.status_digest() != high_water.status_digest)
        || next.apply_endpoint().endpoint_generation() < high_water.endpoint_generation
}

fn advance_runtime_high_water(
    high_water: &mut Option<RuntimeHostObservationHighWaterV1>,
    next: Option<&RuntimeHostStatusV1>,
) {
    let Some(next) = next else {
        return;
    };
    *high_water = Some(RuntimeHostObservationHighWaterV1 {
        runtime_host_epoch: next.runtime_host_epoch(),
        observation_sequence: next.observation_sequence(),
        status_digest: next.status_digest(),
        endpoint_generation: next.apply_endpoint().endpoint_generation(),
    });
}

fn status_removed_or_regressed(
    previous: &DistributedAgentStackNodeRowV1,
    next: &DistributedAgentStackNodeRowV1,
) -> bool {
    if runtime_high_water_removed_or_regressed(
        previous.runtime_high_water.as_ref(),
        next.runtime_high_water.as_ref(),
    ) {
        return true;
    }
    match (
        previous.status_response.as_ref(),
        next.status_response.as_ref(),
    ) {
        (Some(_), None) => true,
        (Some(old), Some(new)) => {
            let Some(old_status) = old.status_value() else {
                return true;
            };
            let Some(new_status) = new.status_value() else {
                return true;
            };
            new_status.status_sequence() < old_status.status_sequence()
                || new_status.status_sequence() == old_status.status_sequence()
                    && new_status.status_digest() != old_status.status_digest()
        }
        _ => false,
    }
}

fn runtime_high_water_removed_or_regressed(
    previous: Option<&RuntimeHostObservationHighWaterV1>,
    next: Option<&RuntimeHostObservationHighWaterV1>,
) -> bool {
    match (previous, next) {
        (Some(_), None) => true,
        (Some(previous), Some(next)) => {
            next.runtime_host_epoch < previous.runtime_host_epoch
                || next.runtime_host_epoch == previous.runtime_host_epoch
                    && (next.observation_sequence < previous.observation_sequence
                        || next.observation_sequence == previous.observation_sequence
                            && next.status_digest != previous.status_digest)
                || next.endpoint_generation < previous.endpoint_generation
        }
        _ => false,
    }
}

fn ready_endpoint(
    row: &DistributedAgentStackNodeRowV1,
    now_nanos: u64,
    now_unix_nanos: u64,
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
) -> Result<ReadyDistributedAgentStackRuntimeEndpointV1, DistributedAgentStackNodeReconcileError> {
    if row.availability != DistributedAgentStackNodeAvailabilityV1::Current
        || row.target.runtime_target != predecessor.target()
        || row.process_qualified_status_digest.is_none()
    {
        return Err(DistributedAgentStackNodeReconcileError::EndpointNotReady);
    }
    let status = row
        .status_response
        .as_ref()
        .and_then(NodeManagementResponseV1::status_value)
        .ok_or(DistributedAgentStackNodeReconcileError::EndpointNotReady)?;
    if row.process_qualified_status_digest != Some(status.status_digest()) {
        return Err(DistributedAgentStackNodeReconcileError::EndpointNotReady);
    }
    if status.valid_until_unix_nanos().is_none()
        || !status.is_fresh_at(row.status_observed_at_nanos, now_nanos, now_unix_nanos)
    {
        return Err(DistributedAgentStackNodeReconcileError::EndpointNotReady);
    }
    let runtime = runtime_status(status, predecessor.target())
        .ok_or(DistributedAgentStackNodeReconcileError::EndpointNotReady)?;
    let endpoint = runtime.apply_endpoint();
    if runtime.liveness() != RuntimeHostLivenessV1::Live
        // PXAR pins the predecessor Runtime's clock generation and store
        // incarnation. A different Runtime epoch needs a newly produced
        // rollout; it cannot rebind this rollout to another observation
        // authority merely because the epoch increased.
        || !runtime_reaches_predecessor_snapshot(runtime, predecessor)
        || endpoint.runtime_host_id() != predecessor.target()
        || endpoint.runtime_response_key_ref() != *predecessor.runtime_response_key().as_bytes()
        || endpoint.runtime_response_public_key()
            != predecessor.runtime_response_public_key().to_bytes()
    {
        return Err(DistributedAgentStackNodeReconcileError::EndpointNotReady);
    }
    Ok(ReadyDistributedAgentStackRuntimeEndpointV1 {
        runtime_target: predecessor.target(),
        node_id: status.node_id(),
        node_incarnation: status.node_incarnation(),
        registration_epoch: status.registration_epoch(),
        status_sequence: status.status_sequence(),
        status_digest: status.status_digest(),
        runtime_host_epoch: runtime.runtime_host_epoch(),
        runtime_observation_sequence: runtime.observation_sequence(),
        endpoint: endpoint.clone(),
    })
}

fn runtime_reaches_predecessor_snapshot(
    runtime: &RuntimeHostStatusV1,
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
) -> bool {
    runtime.runtime_host_epoch() == predecessor.predecessor_runtime_host_epoch()
        // Within that Runtime epoch the Node-observed PXQS snapshot must not
        // predate the authenticated predecessor terminal used to build PXAR.
        && runtime.observation_sequence()
            >= predecessor.predecessor_completion_snapshot_sequence()
}

fn runtime_status(
    status: &paraegox_node::NodeStatusV1,
    target: RuntimeHostId,
) -> Option<&RuntimeHostStatusV1> {
    status
        .runtime_hosts()
        .iter()
        .find(|runtime| runtime.runtime_host_id() == target)
}

fn status_cursor(response: &NodeManagementResponseV1) -> Option<NodeStatusCursorV1> {
    response
        .status_value()
        .and_then(|status| NodeStatusCursorV1::try_from(status).ok())
}

fn reconstruct_request(
    response: &NodeManagementResponseV1,
) -> Result<NodeManagementRequestV1, DistributedAgentStackNodeReconcileError> {
    let request = match response.request_kind() {
        NodeManagementRequestKindV1::Latest => {
            NodeManagementRequestV1::try_latest(response.request_id(), response.target())
        }
        NodeManagementRequestKindV1::Watch => NodeManagementRequestV1::try_watch(
            response.request_id(),
            response.target(),
            response
                .request_cursor()
                .ok_or(DistributedAgentStackNodeReconcileError::InvalidNodeResponse)?,
        ),
    }
    .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidNodeResponse)?;
    response
        .validate_for(&request)
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidNodeResponse)?;
    Ok(request)
}

fn validate_row(
    row: &DistributedAgentStackNodeRowV1,
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    if bytes_are_zero(row.target.runtime_target.as_bytes())
        || digest_is_zero(row.target.carrier_binding_digest)
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    if let Some(high_water) = &row.runtime_high_water
        && (high_water.runtime_host_epoch == 0
            || high_water.observation_sequence == 0
            || digest_is_zero(high_water.status_digest)
            || high_water.endpoint_generation == 0)
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    if let Some(response) = &row.status_response {
        if row.status_observed_at_nanos == 0
            || response.outcome() != NodeManagementResponseOutcomeV1::Status
            || response.status_value().is_none()
            || response.target() != row.target.management_target
            || !status_matches_target(
                response
                    .status_value()
                    .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?,
                &row.target,
            )
        {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        if let Some(runtime) = runtime_status(
            response
                .status_value()
                .ok_or(DistributedAgentStackNodeReconcileError::InvalidState)?,
            row.target.runtime_target,
        ) && (row.runtime_high_water.is_none()
            || runtime_status_regressed_from_high_water(
                row.runtime_high_water.as_ref(),
                Some(runtime),
            )
            || row.runtime_high_water.as_ref().is_some_and(|high_water| {
                high_water.runtime_host_epoch != runtime.runtime_host_epoch()
                    || high_water.observation_sequence != runtime.observation_sequence()
                    || high_water.status_digest != runtime.status_digest()
                    || high_water.endpoint_generation
                        != runtime.apply_endpoint().endpoint_generation()
            }))
        {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        reconstruct_request(response)?;
    } else if row.status_observed_at_nanos != 0 {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    if let Some(response) = &row.latest_response {
        if row.latest_observed_at_nanos == 0 || response.target() != row.target.management_target {
            return Err(DistributedAgentStackNodeReconcileError::InvalidState);
        }
        reconstruct_request(response)?;
    } else if row.latest_observed_at_nanos != 0
        && row.availability != DistributedAgentStackNodeAvailabilityV1::Disconnected
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    let availability_shape = match row.availability {
        DistributedAgentStackNodeAvailabilityV1::NeverObserved => {
            row.status_response.is_none()
                && row.latest_response.is_none()
                && row.latest_observed_at_nanos == 0
                && row.runtime_high_water.is_none()
        }
        DistributedAgentStackNodeAvailabilityV1::Disconnected => {
            row.latest_response.is_none() && row.latest_observed_at_nanos != 0
        }
        DistributedAgentStackNodeAvailabilityV1::Current => {
            row.status_response.is_some()
                && row.latest_response.as_ref().is_some_and(|response| {
                    matches!(
                        response.outcome(),
                        NodeManagementResponseOutcomeV1::Status
                            | NodeManagementResponseOutcomeV1::NotModified
                    )
                })
        }
        DistributedAgentStackNodeAvailabilityV1::Fenced => row
            .latest_response
            .as_ref()
            .is_some_and(|response| response.outcome() == NodeManagementResponseOutcomeV1::Fenced),
        DistributedAgentStackNodeAvailabilityV1::NotFound => {
            row.latest_response.as_ref().is_some_and(|response| {
                response.outcome() == NodeManagementResponseOutcomeV1::NotFound
            })
        }
        DistributedAgentStackNodeAvailabilityV1::CursorConflict => {
            row.latest_response.as_ref().is_some_and(|response| {
                response.outcome() == NodeManagementResponseOutcomeV1::CursorConflict
            })
        }
        DistributedAgentStackNodeAvailabilityV1::InvalidCurrent => row.latest_response.is_some(),
    };
    if !availability_shape {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    Ok(())
}

fn encode_row(
    wire: &mut Vec<u8>,
    row: &DistributedAgentStackNodeRowV1,
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    wire.extend_from_slice(row.target.runtime_target.as_bytes());
    wire.extend_from_slice(row.target.management_target.node_id().as_bytes());
    wire.extend_from_slice(
        row.target
            .management_target
            .management_endpoint_ref()
            .as_bytes(),
    );
    wire.extend_from_slice(row.target.management_target.node_incarnation().as_bytes());
    wire.extend_from_slice(
        &row.target
            .management_target
            .registration_epoch()
            .to_be_bytes(),
    );
    wire.extend_from_slice(row.target.carrier_binding_digest.as_bytes());
    wire.push(row.availability as u8);
    wire.extend_from_slice(&[0; 7]);
    wire.extend_from_slice(&row.status_observed_at_nanos.to_be_bytes());
    wire.extend_from_slice(
        &u32::try_from(
            row.status_response
                .as_ref()
                .map_or(0, |response| response.canonical_wire().len()),
        )
        .map_err(|_| DistributedAgentStackNodeReconcileError::StateTooLarge)?
        .to_be_bytes(),
    );
    wire.extend_from_slice(&row.latest_observed_at_nanos.to_be_bytes());
    wire.extend_from_slice(
        &u32::try_from(
            row.latest_response
                .as_ref()
                .map_or(0, |response| response.canonical_wire().len()),
        )
        .map_err(|_| DistributedAgentStackNodeReconcileError::StateTooLarge)?
        .to_be_bytes(),
    );
    match &row.runtime_high_water {
        Some(high_water) => {
            wire.push(1);
            wire.extend_from_slice(&[0; 7]);
            wire.extend_from_slice(&high_water.runtime_host_epoch.to_be_bytes());
            wire.extend_from_slice(&high_water.observation_sequence.to_be_bytes());
            wire.extend_from_slice(high_water.status_digest.as_bytes());
            wire.extend_from_slice(&high_water.endpoint_generation.to_be_bytes());
        }
        None => wire.extend_from_slice(&[0; 64]),
    }
    if let Some(response) = &row.status_response {
        wire.extend_from_slice(response.canonical_wire());
    }
    if let Some(response) = &row.latest_response {
        wire.extend_from_slice(response.canonical_wire());
    }
    Ok(())
}

fn encode_runtime_query(
    wire: &mut Vec<u8>,
    query: &DistributedAgentStackRuntimeQueryStateV1,
) -> Result<(), DistributedAgentStackNodeReconcileError> {
    validate_runtime_query_state(query)?;
    wire.extend_from_slice(query.target.as_bytes());
    wire.push(query.phase as u8);
    wire.extend_from_slice(&[0; 7]);
    wire.extend_from_slice(query.serving_baseline.target().as_bytes());
    wire.extend_from_slice(&query.serving_baseline.runtime_store_instance_id());
    wire.extend_from_slice(&query.serving_baseline.snapshot_sequence().to_be_bytes());
    wire.extend_from_slice(&query.serving_baseline.runtime_host_epoch().to_be_bytes());
    wire.extend_from_slice(query.serving_baseline.clock_domain().as_bytes());
    wire.extend_from_slice(
        &query
            .serving_baseline
            .clock_generation()
            .value()
            .to_be_bytes(),
    );
    wire.extend_from_slice(query.observation_endpoint_ref.as_bytes());
    wire.extend_from_slice(&query.intended_status_sequence.to_be_bytes());
    wire.extend_from_slice(&query.freshness_budget_nanos.to_be_bytes());
    wire.extend_from_slice(query.authority_digest.as_bytes());
    wire.extend_from_slice(&query.challenge_issued_at_unix_nanos.to_be_bytes());
    wire.extend_from_slice(&query.challenge_expires_at_unix_nanos.to_be_bytes());
    let lengths = [
        query.request.canonical_wire().len(),
        query
            .response
            .as_ref()
            .map_or(0, |value| value.canonical_wire().len()),
        query
            .observation
            .as_ref()
            .map_or(0, |value| value.canonical_wire().len()),
        query
            .ack
            .as_ref()
            .map_or(0, |value| value.canonical_wire().len()),
    ];
    for length in lengths {
        wire.extend_from_slice(
            &u32::try_from(length)
                .map_err(|_| DistributedAgentStackNodeReconcileError::StateTooLarge)?
                .to_be_bytes(),
        );
    }
    wire.extend_from_slice(query.request.canonical_wire());
    if let Some(response) = &query.response {
        wire.extend_from_slice(response.canonical_wire());
    }
    if let Some(observation) = &query.observation {
        wire.extend_from_slice(observation.canonical_wire());
    }
    if let Some(ack) = &query.ack {
        wire.extend_from_slice(ack.canonical_wire());
    }
    Ok(())
}

fn decode_runtime_query(
    cursor: &mut Cursor<'_>,
) -> Result<DistributedAgentStackRuntimeQueryStateV1, DistributedAgentStackNodeReconcileError> {
    let target = RuntimeHostId::from_bytes(cursor.array()?);
    let phase = DistributedAgentStackRuntimeQueryPhaseV1::decode(cursor.u8()?)?;
    if cursor.take(7)?.iter().any(|byte| *byte != 0) {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    let baseline_target = RuntimeHostId::from_bytes(cursor.array()?);
    let baseline_store = cursor.array()?;
    let baseline_sequence = cursor.u64()?;
    let baseline_epoch = cursor.u64()?;
    let baseline_clock_domain = ClockDomainRef::from_bytes(cursor.array()?);
    let baseline_clock_generation = ClockGeneration::try_new(cursor.u64()?)
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    let serving_baseline = ReferenceBootstrapServingIdentityV1::try_new(
        baseline_target,
        baseline_store,
        baseline_sequence,
        baseline_epoch,
        baseline_clock_domain,
        baseline_clock_generation,
    )
    .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    let observation_endpoint_ref = RuntimeObservationEndpointRefV1::try_from_bytes(cursor.array()?)
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    let intended_status_sequence = cursor.u64()?;
    let freshness_budget_nanos = cursor.u64()?;
    let authority_digest = Digest32::from_bytes(cursor.array()?);
    let challenge_issued_at_unix_nanos = cursor.u64()?;
    let challenge_expires_at_unix_nanos = cursor.u64()?;
    let request_length = cursor.usize_u32()?;
    let response_length = cursor.usize_u32()?;
    let observation_length = cursor.usize_u32()?;
    let ack_length = cursor.usize_u32()?;
    if request_length == 0
        || request_length > MAX_REFERENCE_QUERY_REQUEST_BYTES
        || response_length > MAX_REFERENCE_QUERY_RESPONSE_BYTES
        || observation_length > MAX_RUNTIME_OBSERVATION_REQUEST_BYTES
        || !matches!(ack_length, 0 | RUNTIME_OBSERVATION_ACK_BYTES)
    {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    let request = ReferenceQueryRequestV1::decode(cursor.take(request_length)?)
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    let response = if response_length == 0 {
        None
    } else {
        Some(
            ReferenceQueryResponseV1::decode(cursor.take(response_length)?)
                .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?,
        )
    };
    let observation = if observation_length == 0 {
        None
    } else {
        Some(
            RuntimeObservationRequestV1::decode(cursor.take(observation_length)?)
                .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?,
        )
    };
    let ack = if ack_length == 0 {
        None
    } else {
        Some(
            RuntimeObservationAckV1::decode(cursor.take(ack_length)?)
                .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?,
        )
    };
    let value = DistributedAgentStackRuntimeQueryStateV1 {
        target,
        phase,
        request,
        serving_baseline,
        observation_endpoint_ref,
        intended_status_sequence,
        freshness_budget_nanos,
        authority_digest,
        challenge_issued_at_unix_nanos,
        challenge_expires_at_unix_nanos,
        response,
        observation,
        ack,
    };
    validate_runtime_query_state(&value)?;
    Ok(value)
}

fn decode_row(
    cursor: &mut Cursor<'_>,
) -> Result<DistributedAgentStackNodeRowV1, DistributedAgentStackNodeReconcileError> {
    let runtime_target = RuntimeHostId::from_bytes(cursor.array()?);
    let node_id = NodeId::try_from_bytes(cursor.array()?)
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    let management_endpoint_ref = NodeManagementEndpointRefV1::try_from_bytes(cursor.array()?)
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    let node_incarnation = NodeIncarnation::try_from_bytes(cursor.array()?)
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?;
    let registration_epoch = cursor.u64()?;
    let carrier_binding_digest = Digest32::from_bytes(cursor.array()?);
    let availability = DistributedAgentStackNodeAvailabilityV1::decode(cursor.u8()?)?;
    if cursor.take(7)?.iter().any(|byte| *byte != 0) {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    let status_observed_at_nanos = cursor.u64()?;
    let status_length = cursor.usize_u32()?;
    let latest_observed_at_nanos = cursor.u64()?;
    let latest_length = cursor.usize_u32()?;
    let high_water_present = cursor.u8()?;
    if cursor.take(7)?.iter().any(|byte| *byte != 0) {
        return Err(DistributedAgentStackNodeReconcileError::InvalidState);
    }
    let high_water_runtime_host_epoch = cursor.u64()?;
    let high_water_observation_sequence = cursor.u64()?;
    let high_water_status_digest = Digest32::from_bytes(cursor.array()?);
    let high_water_endpoint_generation = cursor.u64()?;
    let runtime_high_water = match high_water_present {
        0 if high_water_runtime_host_epoch == 0
            && high_water_observation_sequence == 0
            && digest_is_zero(high_water_status_digest)
            && high_water_endpoint_generation == 0 =>
        {
            None
        }
        1 => Some(RuntimeHostObservationHighWaterV1 {
            runtime_host_epoch: high_water_runtime_host_epoch,
            observation_sequence: high_water_observation_sequence,
            status_digest: high_water_status_digest,
            endpoint_generation: high_water_endpoint_generation,
        }),
        _ => return Err(DistributedAgentStackNodeReconcileError::InvalidState),
    };
    let target = DistributedAgentStackNodeTargetV1::try_new(
        runtime_target,
        NodeManagementTargetV1::try_new(
            node_id,
            management_endpoint_ref,
            node_incarnation,
            registration_epoch,
        )
        .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidState)?,
        carrier_binding_digest,
    )?;
    let status_response = if status_length == 0 {
        None
    } else {
        Some(
            NodeManagementResponseV1::decode(cursor.take(status_length)?)
                .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidNodeResponse)?,
        )
    };
    let latest_response = if latest_length == 0 {
        None
    } else {
        Some(
            NodeManagementResponseV1::decode(cursor.take(latest_length)?)
                .map_err(|_| DistributedAgentStackNodeReconcileError::InvalidNodeResponse)?,
        )
    };
    Ok(DistributedAgentStackNodeRowV1 {
        target,
        availability,
        status_observed_at_nanos,
        status_response,
        latest_observed_at_nanos,
        latest_response,
        runtime_high_water,
        process_latest_observed_at_nanos: 0,
        process_qualified_status_digest: None,
    })
}

fn state_checksum(version: u16, bytes: &[u8]) -> Result<Digest32, DigestBuildError> {
    let domain = match version {
        STATE_VERSION_V2 => STATE_CHECKSUM_DOMAIN_V2,
        STATE_VERSION_V3 => STATE_CHECKSUM_DOMAIN_V3,
        _ => return Err(DigestBuildError::EmptyDomain),
    };
    let mut builder = Digest32Builder::try_new(domain)?;
    builder.field_bytes(bytes)?;
    Ok(builder.finish())
}

fn next_sequence(value: u64) -> Result<u64, DistributedAgentStackNodeReconcileError> {
    value
        .checked_add(1)
        .ok_or(DistributedAgentStackNodeReconcileError::SequenceExhausted)
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn digest_is_zero(value: Digest32) -> bool {
    bytes_are_zero(value.as_bytes())
}

struct Cursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DistributedAgentStackNodeReconcileError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DistributedAgentStackNodeReconcileError::StateTruncated)?;
        let bytes = self
            .frame
            .get(self.position..end)
            .ok_or(DistributedAgentStackNodeReconcileError::StateTruncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], DistributedAgentStackNodeReconcileError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DistributedAgentStackNodeReconcileError::StateTruncated)
    }

    fn u8(&mut self) -> Result<u8, DistributedAgentStackNodeReconcileError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, DistributedAgentStackNodeReconcileError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DistributedAgentStackNodeReconcileError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DistributedAgentStackNodeReconcileError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u32(&mut self) -> Result<usize, DistributedAgentStackNodeReconcileError> {
        usize::try_from(self.u32()?)
            .map_err(|_| DistributedAgentStackNodeReconcileError::StateTooLarge)
    }

    fn finish(self) -> Result<(), DistributedAgentStackNodeReconcileError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(DistributedAgentStackNodeReconcileError::NonCanonicalState)
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeSocketIdentityV1 {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn validate_socket_path(path: &Path) -> Result<(), TrustedLocalNodeClientErrorV1> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute()
        || bytes.len() <= 1
        || bytes.len() > MAX_NODE_SOCKET_PATH_BYTES
        || bytes.first() != Some(&b'/')
        || bytes.last() == Some(&b'/')
        || bytes.contains(&0)
        || bytes.windows(2).any(|window| window == b"//")
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(TrustedLocalNodeClientErrorV1::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_socket_metadata(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<NodeSocketIdentityV1, TrustedLocalNodeClientErrorV1> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => TrustedLocalNodeClientErrorV1::Disconnected,
        _ => TrustedLocalNodeClientErrorV1::SocketMetadata,
    })?;
    if !metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != NODE_SOCKET_MODE
    {
        return Err(TrustedLocalNodeClientErrorV1::SocketMetadata);
    }
    Ok(NodeSocketIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn validate_runtime_observation_socket_path(
    path: &Path,
) -> Result<(), TrustedLocalRuntimeObservationClientFailureV1> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute()
        || bytes.len() <= 1
        || bytes.len() > MAX_NODE_SOCKET_PATH_BYTES
        || bytes.first() != Some(&b'/')
        || bytes.last() == Some(&b'/')
        || bytes.contains(&0)
        || bytes.windows(2).any(|window| window == b"//")
        || bytes.windows(3).any(|window| window == b"/./")
        || bytes.ends_with(b"/.")
        || bytes.windows(4).any(|window| window == b"/../")
        || bytes.ends_with(b"/..")
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(TrustedLocalRuntimeObservationClientFailureV1::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_runtime_observation_socket_metadata(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<NodeSocketIdentityV1, TrustedLocalRuntimeObservationClientFailureV1> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => TrustedLocalRuntimeObservationClientFailureV1::Disconnected,
        _ => TrustedLocalRuntimeObservationClientFailureV1::SocketMetadata,
    })?;
    if !metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != NODE_SOCKET_MODE
    {
        return Err(TrustedLocalRuntimeObservationClientFailureV1::SocketMetadata);
    }
    Ok(NodeSocketIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn validate_runtime_observation_peer_credentials(
    stream: &UnixStream,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), TrustedLocalRuntimeObservationClientFailureV1> {
    let peer = stream
        .peer_cred()
        .map_err(|_| TrustedLocalRuntimeObservationClientFailureV1::PeerCredentialsUnavailable)?;
    if peer.uid() != expected_uid || peer.gid() != expected_gid {
        return Err(TrustedLocalRuntimeObservationClientFailureV1::PeerCredentialsMismatch);
    }
    Ok(())
}

#[cfg(unix)]
async fn bounded_node_connect(
    deadline: Instant,
    path: &Path,
) -> Result<UnixStream, TrustedLocalNodeClientErrorV1> {
    match timeout_at(deadline, UnixStream::connect(path)).await {
        Err(_) => Err(TrustedLocalNodeClientErrorV1::DeadlineExceeded),
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(TrustedLocalNodeClientErrorV1::Disconnected)
        }
        Ok(Err(_)) => Err(TrustedLocalNodeClientErrorV1::Connect),
        Ok(Ok(stream)) => Ok(stream),
    }
}

#[cfg(unix)]
async fn bounded_runtime_observation_connect(
    deadline: Instant,
    path: &Path,
) -> Result<UnixStream, TrustedLocalRuntimeObservationClientFailureV1> {
    match timeout_at(deadline, UnixStream::connect(path)).await {
        Err(_) => Err(TrustedLocalRuntimeObservationClientFailureV1::DeadlineExceeded),
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(TrustedLocalRuntimeObservationClientFailureV1::Disconnected)
        }
        Ok(Err(_)) => Err(TrustedLocalRuntimeObservationClientFailureV1::Connect),
        Ok(Ok(stream)) => Ok(stream),
    }
}

#[cfg(unix)]
async fn bounded_node_io<Output, Operation>(
    deadline: Instant,
    operation: Operation,
    failure: TrustedLocalNodeClientErrorV1,
) -> Result<Output, TrustedLocalNodeClientErrorV1>
where
    Operation: Future<Output = io::Result<Output>>,
{
    timeout_at(deadline, operation)
        .await
        .map_err(|_| TrustedLocalNodeClientErrorV1::DeadlineExceeded)?
        .map_err(|_| failure)
}

#[cfg(unix)]
async fn bounded_runtime_observation_io<Output, Operation>(
    deadline: Instant,
    operation: Operation,
    failure: TrustedLocalRuntimeObservationClientFailureV1,
) -> Result<Output, TrustedLocalRuntimeObservationClientFailureV1>
where
    Operation: Future<Output = io::Result<Output>>,
{
    timeout_at(deadline, operation)
        .await
        .map_err(|_| TrustedLocalRuntimeObservationClientFailureV1::DeadlineExceeded)?
        .map_err(|_| failure)
}

#[cfg(unix)]
async fn bounded_runtime_observation_read_exact(
    deadline: Instant,
    stream: &mut UnixStream,
    ack_wire: &mut [u8; RUNTIME_OBSERVATION_ACK_BYTES],
) -> Result<(), TrustedLocalRuntimeObservationExchangeErrorV1> {
    match timeout_at(deadline, stream.read_exact(ack_wire)).await {
        Err(_) => Err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain(
            TrustedLocalRuntimeObservationClientFailureV1::DeadlineExceeded,
        )),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain(
                TrustedLocalRuntimeObservationClientFailureV1::TruncatedAck,
            ))
        }
        Ok(Err(_)) => Err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain(
            TrustedLocalRuntimeObservationClientFailureV1::Read,
        )),
        Ok(Ok(_)) => Ok(()),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustedLocalNodeClientErrorV1 {
    InvalidConfiguration,
    SocketMetadata,
    SocketIdentityChanged,
    PeerCredentialsUnavailable,
    PeerCredentialsMismatch,
    Disconnected,
    Connect,
    Write,
    Read,
    DeadlineExceeded,
    TruncatedResponse,
    ResponseTooLarge,
    TrailingResponseBytes,
    InvalidResponse,
}

#[cfg(unix)]
impl fmt::Display for TrustedLocalNodeClientErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "trusted local Node exchange failed: {self:?}")
    }
}

#[cfg(unix)]
impl std::error::Error for TrustedLocalNodeClientErrorV1 {}

/// Display-safe cause inside one local PXNO exchange classification.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustedLocalRuntimeObservationClientFailureV1 {
    InvalidConfiguration,
    InvalidRequest,
    SocketMetadata,
    SocketIdentityChanged,
    PeerCredentialsUnavailable,
    PeerCredentialsMismatch,
    Disconnected,
    Connect,
    Write,
    Read,
    DeadlineExceeded,
    TruncatedAck,
    TrailingAckBytes,
    InvalidAck,
    AckMismatch,
}

#[cfg(unix)]
impl fmt::Display for TrustedLocalRuntimeObservationClientFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "trusted local Runtime observation failed: {self:?}"
        )
    }
}

#[cfg(unix)]
impl std::error::Error for TrustedLocalRuntimeObservationClientFailureV1 {}

/// Delivery classification for one and only one PXNO send attempt.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustedLocalRuntimeObservationExchangeErrorV1 {
    NotSent(TrustedLocalRuntimeObservationClientFailureV1),
    Uncertain(TrustedLocalRuntimeObservationClientFailureV1),
    Rejected(TrustedLocalRuntimeObservationClientFailureV1),
}

#[cfg(unix)]
impl fmt::Display for TrustedLocalRuntimeObservationExchangeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "trusted local PXNO exchange failed: {self:?}")
    }
}

#[cfg(unix)]
impl std::error::Error for TrustedLocalRuntimeObservationExchangeErrorV1 {}

#[derive(Debug)]
pub(crate) enum DistributedAgentStackNodeReconcileError {
    Digest(DigestBuildError),
    InvalidTarget,
    TargetMismatch,
    OwnerMismatch,
    UnauthenticatedCarrier,
    InvalidObservationTime,
    InvalidProcessGeneration,
    ProcessQualificationMismatch,
    InvalidNodeRequest,
    InvalidNodeResponse,
    NodeResponseMismatch,
    EndpointNotReady,
    InvalidState,
    InvalidSuccessor,
    SequenceExhausted,
    StateTruncated,
    StateTooLarge,
    ChecksumMismatch,
    NonCanonicalState,
}

impl From<DigestBuildError> for DistributedAgentStackNodeReconcileError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for DistributedAgentStackNodeReconcileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "distributed Agent stack Node reconcile failed: {self:?}"
        )
    }
}

impl std::error::Error for DistributedAgentStackNodeReconcileError {}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::{Digest32, Digest32Builder};
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
    use paraegox_node::observation::{
        RUNTIME_OBSERVATION_ACK_BYTES, RuntimeObservationEndpointRefV1,
        RuntimeObservationRequestInputV1, RuntimeObservationRequestV1,
    };
    use paraegox_node::protocol::{NodeManagementRequestKindV1, NodeManagementResponseV1};
    use paraegox_node::{
        EnrollmentIssuerRefV1, NodeArchitectureV1, NodeDaemonV1, NodeFeatureReportInputV1,
        NodeFeatureReportV1, NodeIdentityV1, NodeIncarnation, NodeManagementEndpointRefV1,
        NodeOperatingSystemV1, NodeRegistrationTenureV1, RuntimeApplyEndpointDescriptorV1,
        RuntimeApplyEndpointRefV1, RuntimeHostLivenessV1, RuntimeHostStatusV1,
    };
    use paraegox_runtime_contracts::apply::ApplyOperationId;
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, SourceScopeRef};
    use paraegox_runtime_contracts::reference_control::{
        MAX_REFERENCE_QUERY_RESPONSE_BYTES, ReferenceBootstrapServingIdentityV1,
        ReferenceChannelBindingV1, ReferenceQueryDesiredHeadV1, ReferenceQueryDesiredStateV1,
        ReferenceQueryFactsV1, ReferenceQueryIdV1, ReferenceQueryLiveFactsV1,
        ReferenceQueryLiveStateV1, ReferenceQueryOperationLookupV1, ReferenceQueryOperationStateV1,
        ReferenceQueryOwnerStateV1, ReferenceQueryRequestDraftV1, ReferenceQueryRequestV1,
        ReferenceQueryResponseAuthClaimV1, ReferenceQueryResponseDraftV1, ReferenceQueryResponseV1,
        ReferenceQuerySelectorV1,
    };
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::time::timeout;

    use super::{
        DistributedAgentStackNodeAvailabilityV1, DistributedAgentStackNodeDiscoveryStateV1,
        DistributedAgentStackNodeReconcileError, DistributedAgentStackNodeTargetV1,
        DistributedAgentStackRuntimeQueryInputV1, DistributedAgentStackRuntimeQueryPhaseV1,
        LOCAL_OBSERVATION_HEADER_BYTES, LOCAL_OBSERVATION_MAGIC, LOCAL_OBSERVATION_VERSION,
        NodeObservationProcessGenerationV1, RuntimeObservationPublishFieldsV1,
        TransportAuthenticatedNodeResponseV1, TrustedLocalNodeEndpointV1,
        TrustedLocalRuntimeObservationClientFailureV1, TrustedLocalRuntimeObservationEndpointV1,
        TrustedLocalRuntimeObservationExchangeErrorV1, runtime_query_attempt_is_retry_closed,
        runtime_reaches_predecessor_snapshot,
        validate_distributed_agent_stack_node_wire_successor_v1,
        validate_runtime_observation_peer_credentials,
    };
    use crate::controller_store::ClaimedDistributedRuntimeObservationV1;
    use crate::distributed_agent_stack_producer::VerifiedDistributedAgentStackPredecessorV1;
    use crate::distributed_agent_stack_producer::tests::{FixtureBundle, fixture_bundle};

    const OBSERVATION_TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x11; 16]);
    const OBSERVATION_SCOPE: SourceScopeRef = SourceScopeRef::from_bytes([0x12; 16]);
    const OBSERVATION_CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x13; 16]);
    const OBSERVATION_CONTROLLER_KEY: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x14; 16]);
    const OBSERVATION_RUNTIME_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x15; 16]);
    const OBSERVATION_RESPONSE_KEY: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x16; 16]);
    const OBSERVATION_STORE: [u8; 32] = [0x17; 32];
    const OBSERVATION_CONTROLLER_SEED: [u8; 32] = [0x18; 32];
    const OBSERVATION_RUNTIME_SEED: [u8; 32] = [0x19; 32];
    const OBSERVATION_TOKEN: [u8; 32] = [0x1a; 32];
    const OBSERVATION_ENDPOINT_REF_BYTES: [u8; 16] = [0x1b; 16];
    const OBSERVATION_ACK_DIGEST_DOMAIN: &[u8] = b"paraegox.node.runtime-observation-ack.v1";
    static NEXT_OBSERVATION_SOCKET: AtomicU64 = AtomicU64::new(1);

    struct ObservationSocketFixture {
        root: PathBuf,
        path: PathBuf,
    }

    impl ObservationSocketFixture {
        fn new() -> Self {
            for _ in 0..128 {
                let sequence = NEXT_OBSERVATION_SOCKET.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir()
                    .canonicalize()
                    .unwrap_or_else(|error| panic!("observation temp root failed: {error}"))
                    .join(format!(
                        "paraegox-pxno-client-{}-{sequence}",
                        std::process::id()
                    ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                            .unwrap_or_else(|error| {
                                panic!("observation temp chmod failed: {error}")
                            });
                        let path = root.join("observation.sock");
                        return Self { root, path };
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("observation temp create failed: {error}"),
                }
            }
            panic!("could not allocate observation socket fixture")
        }

        fn bind(&self) -> UnixListener {
            let listener = UnixListener::bind(&self.path)
                .unwrap_or_else(|error| panic!("observation socket bind failed: {error}"));
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .unwrap_or_else(|error| panic!("observation socket chmod failed: {error}"));
            listener
        }

        fn endpoint(&self, exchange_timeout: Duration) -> TrustedLocalRuntimeObservationEndpointV1 {
            let uid = nix::unistd::geteuid().as_raw();
            let gid = nix::unistd::getegid().as_raw();
            assert_ne!(uid, 0, "observation client requires a non-root test user");
            assert_ne!(gid, 0, "observation client requires a non-root test group");
            TrustedLocalRuntimeObservationEndpointV1::try_new(
                RuntimeObservationEndpointRefV1::try_from_bytes(OBSERVATION_ENDPOINT_REF_BYTES)
                    .expect("observation endpoint ref"),
                self.path.clone(),
                uid,
                gid,
                OBSERVATION_TOKEN,
                exchange_timeout,
            )
            .unwrap_or_else(|error| panic!("observation endpoint rejected: {error}"))
        }
    }

    fn claimed_observation(
        request: RuntimeObservationRequestV1,
    ) -> ClaimedDistributedRuntimeObservationV1 {
        ClaimedDistributedRuntimeObservationV1::for_transport_test(
            RuntimeObservationEndpointRefV1::try_from_bytes(OBSERVATION_ENDPOINT_REF_BYTES)
                .expect("observation endpoint ref"),
            request,
        )
    }

    impl Drop for ObservationSocketFixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn observation_channel() -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            OBSERVATION_TARGET,
            OBSERVATION_RUNTIME_PRINCIPAL,
            Digest32::from_bytes([0x21; 32]),
            Digest32::from_bytes([0x22; 32]),
        )
        .unwrap_or_else(|error| panic!("observation channel failed: {error}"))
    }

    fn observation_serving() -> ReferenceBootstrapServingIdentityV1 {
        ReferenceBootstrapServingIdentityV1::try_new(
            OBSERVATION_TARGET,
            OBSERVATION_STORE,
            5,
            3,
            ClockDomainRef::from_bytes([0x23; 16]),
            ClockGeneration::try_new(4)
                .unwrap_or_else(|error| panic!("observation generation failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("observation serving failed: {error}"))
    }

    fn observation_query_request(marker: u8) -> ReferenceQueryRequestV1 {
        let selector = ReferenceQuerySelectorV1::try_new(
            ReferenceQueryIdV1::from_bytes([marker; 16]),
            OBSERVATION_TARGET,
            OBSERVATION_SCOPE,
            OBSERVATION_STORE,
            ApplyOperationId::from_bytes([0x24; 16]),
            Some(Digest32::from_bytes([0x25; 32])),
        )
        .unwrap_or_else(|error| panic!("observation query selector failed: {error}"));
        let claim = ApplyRequestAuthClaim::try_new(
            OBSERVATION_CONTROLLER_PRINCIPAL,
            OBSERVATION_CONTROLLER_KEY,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("observation algorithm failed: {error}")),
            1,
            &[marker.wrapping_add(1); 32],
        )
        .unwrap_or_else(|error| panic!("observation query claim failed: {error}"));
        let draft = ReferenceQueryRequestDraftV1::try_new(
            selector,
            claim,
            MAX_REFERENCE_QUERY_RESPONSE_BYTES as u32,
        )
        .unwrap_or_else(|error| panic!("observation query draft failed: {error}"));
        let signature = SigningKey::from_bytes(&OBSERVATION_CONTROLLER_SEED).sign(
            draft
                .signing_transcript()
                .unwrap_or_else(|error| panic!("observation query transcript failed: {error}"))
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("observation query finalize failed: {error}"))
    }

    fn observation_query_response(request: &ReferenceQueryRequestV1) -> ReferenceQueryResponseV1 {
        let operation = ReferenceQueryOperationStateV1::try_new(
            ReferenceQueryOwnerStateV1::Operational,
            None,
            ReferenceQueryOperationLookupV1::Unknown,
        )
        .unwrap_or_else(|error| panic!("observation operation facts failed: {error}"));
        let desired = ReferenceQueryDesiredStateV1::try_new(
            ReferenceQueryDesiredHeadV1::None,
            SourcePlanRevision::new(0),
        )
        .unwrap_or_else(|error| panic!("observation desired facts failed: {error}"));
        let live = ReferenceQueryLiveFactsV1::try_new(
            ReferenceQueryLiveStateV1::ExactZero,
            0,
            5,
            Digest32::from_bytes([0x26; 32]),
        )
        .unwrap_or_else(|error| panic!("observation live facts failed: {error}"));
        let facts = ReferenceQueryFactsV1::try_new(observation_serving(), operation, desired, live)
            .unwrap_or_else(|error| panic!("observation query facts failed: {error}"));
        let channel = observation_channel();
        let claim = ReferenceQueryResponseAuthClaimV1::try_new(
            channel,
            OBSERVATION_RESPONSE_KEY,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("observation response algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("observation response claim failed: {error}"));
        let draft = ReferenceQueryResponseDraftV1::try_new(request, facts, channel, claim)
            .unwrap_or_else(|error| panic!("observation response draft failed: {error}"));
        let signature = SigningKey::from_bytes(&OBSERVATION_RUNTIME_SEED).sign(
            draft
                .signing_transcript()
                .unwrap_or_else(|error| panic!("observation response transcript failed: {error}"))
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("observation response finalize failed: {error}"))
    }

    fn observation_request(sequence: u64, marker: u8) -> RuntimeObservationRequestV1 {
        let query_request = observation_query_request(marker);
        let query_response = observation_query_response(&query_request);
        RuntimeObservationRequestV1::try_new(RuntimeObservationRequestInputV1 {
            intended_status_sequence: sequence,
            freshness_budget_nanos: 1_000,
            runtime_host_id: OBSERVATION_TARGET,
            authority_digest: Digest32::from_bytes([0x27; 32]),
            challenge_issued_at_unix_nanos: 10_000,
            challenge_expires_at_unix_nanos: 11_000,
            query_request,
            query_response,
        })
        .unwrap_or_else(|error| panic!("observation request failed: {error}"))
    }

    fn observation_ack_wire(
        request: &RuntimeObservationRequestV1,
        correlated_request_digest: Digest32,
    ) -> [u8; RUNTIME_OBSERVATION_ACK_BYTES] {
        let mut wire = [0_u8; RUNTIME_OBSERVATION_ACK_BYTES];
        wire[..4].copy_from_slice(b"PXNA");
        wire[4..6].copy_from_slice(&1_u16.to_be_bytes());
        wire[6..8].copy_from_slice(&(RUNTIME_OBSERVATION_ACK_BYTES as u16).to_be_bytes());
        wire[8..12].copy_from_slice(&(RUNTIME_OBSERVATION_ACK_BYTES as u32).to_be_bytes());
        wire[12] = 1;
        wire[16..24].copy_from_slice(&request.intended_status_sequence().to_be_bytes());
        wire[24..56].copy_from_slice(&[0x31; 32]);
        wire[56..88].copy_from_slice(&[0x32; 32]);
        wire[88..120].copy_from_slice(correlated_request_digest.as_bytes());
        let mut builder = Digest32Builder::try_new(OBSERVATION_ACK_DIGEST_DOMAIN)
            .unwrap_or_else(|error| panic!("observation ACK domain failed: {error:?}"));
        builder
            .field_bytes(&wire)
            .unwrap_or_else(|error| panic!("observation ACK digest failed: {error:?}"));
        wire[128..].copy_from_slice(builder.finish().as_bytes());
        wire
    }

    async fn read_observation_exchange(stream: &mut UnixStream) -> RuntimeObservationRequestV1 {
        let mut header = [0_u8; LOCAL_OBSERVATION_HEADER_BYTES];
        stream
            .read_exact(&mut header)
            .await
            .unwrap_or_else(|error| panic!("read PXOL header failed: {error}"));
        assert_eq!(&header[..4], LOCAL_OBSERVATION_MAGIC);
        assert_eq!(
            u16::from_be_bytes(header[4..6].try_into().expect("version")),
            LOCAL_OBSERVATION_VERSION
        );
        assert_eq!(
            usize::from(u16::from_be_bytes(
                header[6..8].try_into().expect("header length")
            )),
            LOCAL_OBSERVATION_HEADER_BYTES
        );
        assert_eq!(
            &header[16..LOCAL_OBSERVATION_HEADER_BYTES],
            &OBSERVATION_TOKEN
        );
        let total = usize::try_from(u32::from_be_bytes(
            header[8..12].try_into().expect("total length"),
        ))
        .expect("bounded total length");
        let payload_length = usize::try_from(u32::from_be_bytes(
            header[12..16].try_into().expect("payload length"),
        ))
        .expect("bounded payload length");
        assert_eq!(total, LOCAL_OBSERVATION_HEADER_BYTES + payload_length);
        let mut payload = vec![0_u8; payload_length];
        stream
            .read_exact(&mut payload)
            .await
            .unwrap_or_else(|error| panic!("read PXNO failed: {error}"));
        let mut trailing = [0_u8; 1];
        assert_eq!(
            stream
                .read(&mut trailing)
                .await
                .unwrap_or_else(|error| panic!("read PXNO EOF failed: {error}")),
            0
        );
        RuntimeObservationRequestV1::decode(&payload)
            .unwrap_or_else(|error| panic!("decode PXNO failed: {error}"))
    }

    struct NodeHarness {
        daemon: NodeDaemonV1,
        management_target: paraegox_node::protocol::NodeManagementTargetV1,
        carrier_binding: Digest32,
        seed: u8,
    }

    impl NodeHarness {
        fn new(seed: u8) -> Self {
            let node_id = paraegox_node::NodeId::try_from_bytes([seed; 16]).expect("node id");
            let incarnation =
                NodeIncarnation::try_from_bytes([seed + 1; 16]).expect("node incarnation");
            let management_endpoint = NodeManagementEndpointRefV1::try_from_bytes([seed + 2; 16])
                .expect("management endpoint");
            let registration_epoch = u64::from(seed) + 1;
            let identity = NodeIdentityV1::try_new(
                node_id,
                PrincipalRef::from_bytes([seed + 3; 16]),
                EnrollmentIssuerRefV1::try_from_bytes([seed + 4; 16]).expect("enrollment issuer"),
            )
            .expect("node identity");
            let tenure =
                NodeRegistrationTenureV1::try_new(node_id, registration_epoch, incarnation)
                    .expect("node tenure");
            let feature_report = NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
                node_id,
                node_incarnation: incarnation,
                report_sequence: 1,
                operating_system: NodeOperatingSystemV1::Linux,
                architecture: NodeArchitectureV1::X86_64,
                platform_profile_digest: Digest32::from_bytes([seed + 5; 32]),
                runtime_contract_version: 1,
                fabric_contract_version: 1,
            })
            .expect("feature report");
            let daemon =
                NodeDaemonV1::try_new(identity, tenure, management_endpoint, feature_report)
                    .expect("node daemon");
            let management_target = paraegox_node::protocol::NodeManagementTargetV1::try_new(
                node_id,
                management_endpoint,
                incarnation,
                registration_epoch,
            )
            .expect("management target");
            Self {
                daemon,
                management_target,
                carrier_binding: Digest32::from_bytes([seed + 6; 32]),
                seed,
            }
        }

        fn observe_runtime(
            &mut self,
            predecessor: &VerifiedDistributedAgentStackPredecessorV1,
            runtime_host_epoch: u64,
            observation_sequence: u64,
            endpoint_generation: u64,
        ) {
            let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
                RuntimeApplyEndpointRefV1::try_from_bytes([self.seed + 7; 16])
                    .expect("Runtime endpoint ref"),
                predecessor.target(),
                endpoint_generation,
                &format!("paraegox/v1/nodes/{}/runtime/apply", u64::from(self.seed)),
                *predecessor.runtime_response_key().as_bytes(),
                predecessor.runtime_response_public_key().to_bytes(),
            )
            .expect("Runtime endpoint");
            self.daemon
                .observe_runtime_host(
                    RuntimeHostStatusV1::try_new(
                        runtime_host_epoch,
                        observation_sequence,
                        RuntimeHostLivenessV1::Live,
                        endpoint,
                    )
                    .expect("Runtime observation"),
                )
                .expect("observe Runtime");
        }

        fn publish(&mut self) {
            self.daemon.publish_status(1_000).expect("Node status");
        }
    }

    fn initialized() -> (
        FixtureBundle,
        [NodeHarness; 2],
        DistributedAgentStackNodeDiscoveryStateV1,
    ) {
        let bundle = fixture_bundle();
        let nodes = [NodeHarness::new(0x31), NodeHarness::new(0x41)];
        let targets = [
            DistributedAgentStackNodeTargetV1::try_new(
                bundle.predecessors[0].target(),
                nodes[0].management_target,
                nodes[0].carrier_binding,
            )
            .expect("first target"),
            DistributedAgentStackNodeTargetV1::try_new(
                bundle.predecessors[1].target(),
                nodes[1].management_target,
                nodes[1].carrier_binding,
            )
            .expect("second target"),
        ];
        let state = DistributedAgentStackNodeDiscoveryStateV1::try_initialize(
            Digest32::from_bytes([0xd1; 32]),
            bundle.rollout.rollout_id(),
            targets,
            [&bundle.predecessors[0], &bundle.predecessors[1]],
        )
        .expect("initial PXDN");
        (bundle, nodes, state)
    }

    fn durable_query_input(
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        marker: u8,
        endpoint_marker: u8,
    ) -> DistributedAgentStackRuntimeQueryInputV1 {
        let selector = ReferenceQuerySelectorV1::try_new(
            ReferenceQueryIdV1::from_bytes([marker; 16]),
            predecessor.target(),
            predecessor.source_scope(),
            predecessor.request().expected_runtime_store_instance_id(),
            predecessor.request().operation_id(),
            Some(predecessor.request().envelope_request_digest()),
        )
        .expect("query selector");
        let claim = ApplyRequestAuthClaim::try_new(
            predecessor.controller_principal(),
            predecessor.request_key(),
            ApplyAuthAlgorithm::try_new(1).expect("Ed25519"),
            1,
            &[marker.wrapping_add(1); 32],
        )
        .expect("query claim");
        let draft = ReferenceQueryRequestDraftV1::try_new(
            selector,
            claim,
            MAX_REFERENCE_QUERY_RESPONSE_BYTES as u32,
        )
        .expect("query draft");
        let signature = SigningKey::from_bytes(&[0x41; 32]).sign(
            draft
                .signing_transcript()
                .expect("query transcript")
                .as_bytes(),
        );
        let request = draft.finalize(&signature.to_bytes()).expect("signed query");
        let temporal = predecessor.request().temporal();
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            predecessor.target(),
            predecessor.request().expected_runtime_store_instance_id(),
            predecessor.predecessor_completion_snapshot_sequence(),
            predecessor.predecessor_runtime_host_epoch(),
            temporal.target_clock_domain(),
            temporal.target_clock_generation(),
        )
        .expect("serving baseline");
        DistributedAgentStackRuntimeQueryInputV1::try_new(
            request,
            serving,
            RuntimeObservationEndpointRefV1::try_from_bytes([endpoint_marker; 16])
                .expect("observation endpoint ref"),
            RuntimeObservationPublishFieldsV1::new(
                2,
                1_000,
                predecessor.target(),
                Digest32::from_bytes([endpoint_marker.wrapping_add(1); 32]),
                10_000,
                11_000,
            ),
        )
        .expect("durable query input")
    }

    fn observe_current(
        state: &DistributedAgentStackNodeDiscoveryStateV1,
        node: &NodeHarness,
        target_index: usize,
        generation: NodeObservationProcessGenerationV1,
        request_seed: u8,
        observed_at_nanos: u64,
    ) -> DistributedAgentStackNodeDiscoveryStateV1 {
        let target = state.runtime_targets()[target_index];
        let request = state
            .request_for(target, [request_seed; 16])
            .expect("Node request");
        let response = node
            .daemon
            .answer_read_only_v1(&request)
            .expect("Node response");
        let authenticated = TransportAuthenticatedNodeResponseV1::try_from_verified_carrier(
            response.canonical_wire(),
            &request,
            node.carrier_binding,
            generation,
            observed_at_nanos,
        )
        .expect("transport-authenticated response");
        state
            .try_observe_authenticated(target, &request, authenticated)
            .expect("reduced Node response")
    }

    #[test]
    fn query_attempts_are_atomic_append_only_and_reject_identity_reuse() {
        let (bundle, _, initial) = initialized();
        let initial_wire = initial.encode().expect("PXDN v2");
        assert_eq!(u16::from_be_bytes([initial_wire[4], initial_wire[5]]), 2);

        let first = initial
            .try_prepare_runtime_query_pair([
                durable_query_input(&bundle.predecessors[0], 0x51, 0x61),
                durable_query_input(&bundle.predecessors[1], 0x52, 0x62),
            ])
            .expect("atomic first query pair");
        let first_wire = first.encode().expect("PXDN v3");
        assert_eq!(u16::from_be_bytes([first_wire[4], first_wire[5]]), 3);
        assert_eq!(first.runtime_query_attempt_count(), 1);
        validate_distributed_agent_stack_node_wire_successor_v1(&initial_wire, &first_wire)
            .expect("v2 to v3 successor");
        assert_eq!(
            DistributedAgentStackNodeDiscoveryStateV1::decode(&first_wire)
                .expect("round trip first pair"),
            first
        );

        let targets = first.runtime_targets();
        let first = first
            .try_close_runtime_query(
                targets[0],
                DistributedAgentStackRuntimeQueryPhaseV1::QueryNotSent,
            )
            .expect("close first A");
        let first = first
            .try_close_runtime_query(
                targets[1],
                DistributedAgentStackRuntimeQueryPhaseV1::QueryRejected,
            )
            .expect("close first B");
        let second = first
            .try_prepare_runtime_query_pair([
                durable_query_input(&bundle.predecessors[0], 0x53, 0x63),
                durable_query_input(&bundle.predecessors[1], 0x54, 0x64),
            ])
            .expect("append fresh retry pair");
        assert_eq!(second.runtime_query_attempt_count(), 2);
        let second = second
            .try_close_runtime_query(
                targets[0],
                DistributedAgentStackRuntimeQueryPhaseV1::QueryUncertain,
            )
            .expect("close second A");
        let second = second
            .try_close_runtime_query(
                targets[1],
                DistributedAgentStackRuntimeQueryPhaseV1::ResidentAuthorityLost,
            )
            .expect("close second B");
        assert!(matches!(
            second.try_prepare_runtime_query_pair([
                durable_query_input(&bundle.predecessors[0], 0x51, 0x65),
                durable_query_input(&bundle.predecessors[1], 0x55, 0x66),
            ]),
            Err(DistributedAgentStackNodeReconcileError::InvalidState)
        ));
    }

    #[test]
    fn query_pair_rejects_swapped_targets_and_shared_ids_or_nonces() {
        let (bundle, _, initial) = initialized();
        let first = durable_query_input(&bundle.predecessors[0], 0x71, 0x81);
        let second = durable_query_input(&bundle.predecessors[1], 0x72, 0x82);
        assert!(matches!(
            initial.try_prepare_runtime_query_pair([second.clone(), first.clone()]),
            Err(DistributedAgentStackNodeReconcileError::TargetMismatch)
        ));
        assert!(matches!(
            initial.try_prepare_runtime_query_pair([
                durable_query_input(&bundle.predecessors[0], 0x73, 0x83),
                durable_query_input(&bundle.predecessors[1], 0x73, 0x84),
            ]),
            Err(DistributedAgentStackNodeReconcileError::InvalidState)
        ));
    }

    #[test]
    fn fully_acknowledged_attempt_is_closed_for_owner_selected_refresh() {
        let (bundle, _, initial) = initialized();
        let state = initial
            .try_prepare_runtime_query_pair([
                durable_query_input(&bundle.predecessors[0], 0x75, 0x85),
                durable_query_input(&bundle.predecessors[1], 0x76, 0x86),
            ])
            .expect("query pair");
        let mut attempt = state.runtime_query_attempts[0].clone();
        attempt[0].phase = DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable;
        attempt[1].phase = DistributedAgentStackRuntimeQueryPhaseV1::ObservationAckDurable;
        assert!(runtime_query_attempt_is_retry_closed(&attempt));
    }

    #[test]
    fn uncertain_observation_cannot_be_downgraded_by_a_replay_failure() {
        let (bundle, _, initial) = initialized();
        let mut state = initial
            .try_prepare_runtime_query_pair([
                durable_query_input(&bundle.predecessors[0], 0x77, 0x87),
                durable_query_input(&bundle.predecessors[1], 0x78, 0x88),
            ])
            .expect("query pair");
        let target = state.runtime_targets()[0];
        state.runtime_query_attempts[0][0].phase =
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain;

        for closure in [
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationNotSent,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain,
            DistributedAgentStackRuntimeQueryPhaseV1::ObservationRejected,
        ] {
            assert!(matches!(
                state.try_close_runtime_observation(target, closure),
                Err(DistributedAgentStackNodeReconcileError::InvalidState)
            ));
        }
    }

    #[test]
    fn observation_endpoint_requires_the_current_nonroot_peer_and_redacts_the_token() {
        let fixture = ObservationSocketFixture::new();
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        assert_ne!(uid, 0, "observation client requires a non-root test user");
        assert_ne!(gid, 0, "observation client requires a non-root test group");
        let wrong_uid = uid.checked_add(1).unwrap_or(uid - 1);
        assert!(matches!(
            TrustedLocalRuntimeObservationEndpointV1::try_new(
                RuntimeObservationEndpointRefV1::try_from_bytes(OBSERVATION_ENDPOINT_REF_BYTES)
                    .expect("observation endpoint ref"),
                fixture.root.join(".").join("observation.sock"),
                uid,
                gid,
                OBSERVATION_TOKEN,
                Duration::from_secs(1),
            ),
            Err(TrustedLocalRuntimeObservationClientFailureV1::InvalidConfiguration)
        ));
        assert!(matches!(
            TrustedLocalRuntimeObservationEndpointV1::try_new(
                RuntimeObservationEndpointRefV1::try_from_bytes(OBSERVATION_ENDPOINT_REF_BYTES)
                    .expect("observation endpoint ref"),
                fixture.path.clone(),
                wrong_uid,
                gid,
                OBSERVATION_TOKEN,
                Duration::from_secs(1),
            ),
            Err(TrustedLocalRuntimeObservationClientFailureV1::InvalidConfiguration)
        ));
        assert!(matches!(
            TrustedLocalRuntimeObservationEndpointV1::try_new(
                RuntimeObservationEndpointRefV1::try_from_bytes(OBSERVATION_ENDPOINT_REF_BYTES)
                    .expect("observation endpoint ref"),
                fixture.path.clone(),
                uid,
                gid,
                OBSERVATION_TOKEN,
                Duration::from_secs(11),
            ),
            Err(TrustedLocalRuntimeObservationClientFailureV1::InvalidConfiguration)
        ));
        let endpoint = TrustedLocalRuntimeObservationEndpointV1::try_new(
            RuntimeObservationEndpointRefV1::try_from_bytes(OBSERVATION_ENDPOINT_REF_BYTES)
                .expect("observation endpoint ref"),
            fixture.path.clone(),
            uid,
            gid,
            OBSERVATION_TOKEN,
            Duration::from_secs(1),
        )
        .unwrap_or_else(|error| panic!("observation endpoint rejected: {error}"));
        let debug = format!("{endpoint:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("1a1a1a1a"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observation_client_round_trips_one_exact_pxol_pxno_pxna_exchange() {
        let fixture = ObservationSocketFixture::new();
        let listener = fixture.bind();
        let endpoint = fixture.endpoint(Duration::from_secs(1));
        let request = observation_request(7, 0x41);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("accept PXNO failed: {error}"));
            let received = read_observation_exchange(&mut stream).await;
            let ack_wire = observation_ack_wire(&received, received.request_digest());
            stream
                .write_all(&ack_wire)
                .await
                .unwrap_or_else(|error| panic!("write PXNA failed: {error}"));
            stream
                .shutdown()
                .await
                .unwrap_or_else(|error| panic!("shutdown PXNA failed: {error}"));
            received
        });

        let (_spent_claim, result) = endpoint
            .exchange(claimed_observation(request.clone()))
            .await
            .into_transport_test_parts();
        let ack = result.unwrap_or_else(|error| panic!("PXNO exchange failed: {error}"));
        let received = server
            .await
            .unwrap_or_else(|error| panic!("PXNO server task failed: {error}"));
        assert_eq!(received, request);
        ack.validate_for(&request)
            .unwrap_or_else(|error| panic!("PXNA validation failed: {error}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observation_client_rejects_insecure_socket_metadata_before_send() {
        let fixture = ObservationSocketFixture::new();
        let listener = fixture.bind();
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o660))
            .unwrap_or_else(|error| panic!("weaken observation socket mode failed: {error}"));
        let endpoint = fixture.endpoint(Duration::from_secs(1));
        let request = observation_request(8, 0x42);

        let (_spent_claim, result) = endpoint
            .exchange(claimed_observation(request))
            .await
            .into_transport_test_parts();
        assert!(matches!(
            result,
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(
                TrustedLocalRuntimeObservationClientFailureV1::SocketMetadata
            ))
        ));
        drop(listener);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observation_peer_check_rejects_a_real_socket_with_the_wrong_identity_pin() {
        let fixture = ObservationSocketFixture::new();
        let listener = fixture.bind();
        let connect_path = fixture.path.clone();
        let connector = tokio::spawn(async move {
            UnixStream::connect(connect_path)
                .await
                .unwrap_or_else(|error| panic!("connect peer-check socket failed: {error}"))
        });
        let (_server, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("accept peer-check socket failed: {error}"));
        let client = connector
            .await
            .unwrap_or_else(|error| panic!("peer-check connector task failed: {error}"));
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        let wrong_uid = uid.checked_add(1).unwrap_or(uid - 1);

        assert_eq!(
            validate_runtime_observation_peer_credentials(&client, wrong_uid, gid),
            Err(TrustedLocalRuntimeObservationClientFailureV1::PeerCredentialsMismatch)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observation_client_rejects_a_complete_pxna_for_another_request() {
        let fixture = ObservationSocketFixture::new();
        let listener = fixture.bind();
        let endpoint = fixture.endpoint(Duration::from_secs(1));
        let request = observation_request(9, 0x43);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("accept mismatched PXNO failed: {error}"));
            let received = read_observation_exchange(&mut stream).await;
            let ack_wire = observation_ack_wire(&received, Digest32::from_bytes([0x44; 32]));
            stream
                .write_all(&ack_wire)
                .await
                .unwrap_or_else(|error| panic!("write mismatched PXNA failed: {error}"));
            stream
                .shutdown()
                .await
                .unwrap_or_else(|error| panic!("shutdown mismatched PXNA failed: {error}"));
        });

        let (_spent_claim, result) = endpoint
            .exchange(claimed_observation(request))
            .await
            .into_transport_test_parts();
        assert!(matches!(
            result,
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::Rejected(
                TrustedLocalRuntimeObservationClientFailureV1::AckMismatch
            ))
        ));
        server
            .await
            .unwrap_or_else(|error| panic!("mismatched PXNA task failed: {error}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observation_client_uses_one_deadline_after_the_request_is_sent() {
        let fixture = ObservationSocketFixture::new();
        let listener = fixture.bind();
        let endpoint = fixture.endpoint(Duration::from_millis(100));
        let request = observation_request(10, 0x45);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("accept deadline PXNO failed: {error}"));
            let _ = read_observation_exchange(&mut stream).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        });

        let (_spent_claim, result) = endpoint
            .exchange(claimed_observation(request))
            .await
            .into_transport_test_parts();
        assert!(matches!(
            result,
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain(
                TrustedLocalRuntimeObservationClientFailureV1::DeadlineExceeded
            ))
        ));
        server
            .await
            .unwrap_or_else(|error| panic!("deadline PXNO task failed: {error}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observation_client_makes_one_write_attempt_and_never_reconnects() {
        let fixture = ObservationSocketFixture::new();
        let listener = fixture.bind();
        let endpoint = fixture.endpoint(Duration::from_secs(1));
        let request = observation_request(11, 0x46);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("accept one-shot PXNO failed: {error}"));
            let _ = read_observation_exchange(&mut stream).await;
            drop(stream);
            assert!(
                timeout(Duration::from_millis(75), listener.accept())
                    .await
                    .is_err(),
                "PXNO client unexpectedly retried with a second connection"
            );
        });

        let (_spent_claim, result) = endpoint
            .exchange(claimed_observation(request))
            .await
            .into_transport_test_parts();
        assert!(matches!(
            result,
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain(
                TrustedLocalRuntimeObservationClientFailureV1::TruncatedAck
            ))
        ));
        server
            .await
            .unwrap_or_else(|error| panic!("one-shot PXNO task failed: {error}"));
    }

    #[test]
    fn query_then_publish_structure_preserves_the_durable_query_and_order() {
        let source = include_str!("distributed_agent_stack_node_reconcile.rs");
        let endpoint = source
            .split_once("impl TrustedLocalRuntimeObservationEndpointV1")
            .and_then(|(_, tail)| {
                tail.split_once("pub(crate) struct RuntimeObservationPublishFieldsV1")
            })
            .map(|(section, _)| section)
            .unwrap_or_else(|| panic!("missing observation endpoint implementation"));
        assert_eq!(
            endpoint
                .match_indices("validate_runtime_observation_socket_metadata(")
                .count(),
            2,
            "socket inode must be pinned before connect and revalidated after connect"
        );
        assert!(endpoint.contains("validate_runtime_observation_peer_credentials("));
        assert!(source.contains("let peer = stream.peer_cred()"));
        assert!(endpoint.contains("stream.shutdown()"));
        assert!(endpoint.contains("RuntimeObservationAckV1::decode"));
        assert!(endpoint.contains("ack.validate_for(request)"));
        assert!(!endpoint.contains("loop"));

        let production = source
            .split_once("#[cfg(all(test, unix))]\nmod tests")
            .map(|(production, _)| production)
            .unwrap_or_else(|| panic!("missing test module boundary"));
        assert!(!production.contains("query_runtime_then_publish_node_observation_v1"));
        assert!(!production.contains(".exchange(&request)"));
        assert!(!production.contains("complete_transport"));
        assert!(endpoint.contains("claimed: ClaimedDistributedRuntimeObservationV1"));
        assert!(endpoint.contains("self.exchange_claimed_request(claimed.request()).await"));
        assert!(
            endpoint
                .contains("CompletedDistributedRuntimeObservationExchangeV1 { claimed, result }")
        );
        assert!(production.contains("async fn exchange_claimed_request("));
        assert!(!production.contains("pub(crate) async fn exchange_claimed_request("));
    }

    #[test]
    fn decoded_state_needs_a_fresh_process_status_before_qualification() {
        let (bundle, mut nodes, state) = initialized();
        nodes[0].observe_runtime(&bundle.predecessors[0], 5, 5, 5);
        nodes[1].observe_runtime(&bundle.predecessors[1], 5, 5, 5);
        nodes[0].publish();
        nodes[1].publish();
        let first_generation = NodeObservationProcessGenerationV1::try_from_bytes([0xa1; 16])
            .expect("process generation");
        let state = state
            .try_begin_observation_process(first_generation)
            .expect("begin process");
        let state = observe_current(&state, &nodes[0], 0, first_generation, 0xb1, 10);
        let state = observe_current(&state, &nodes[1], 1, first_generation, 0xb2, 20);
        let durable = state.encode().expect("durable PXDN");
        let reopened =
            DistributedAgentStackNodeDiscoveryStateV1::decode(&durable).expect("reopened PXDN");

        assert!(reopened.process_generation.is_none());
        assert!(
            reopened
                .rows
                .iter()
                .all(|row| row.process_qualified_status_digest.is_none())
        );
        assert_eq!(
            reopened
                .request_for(reopened.runtime_targets()[0], [0xb3; 16])
                .expect("restart request")
                .kind(),
            NodeManagementRequestKindV1::Latest
        );
        assert!(matches!(
            reopened.ready_endpoints(21, 1, [&bundle.predecessors[0], &bundle.predecessors[1]],),
            Err(DistributedAgentStackNodeReconcileError::EndpointNotReady)
        ));

        let second_generation = NodeObservationProcessGenerationV1::try_from_bytes([0xa2; 16])
            .expect("next process generation");
        let refreshed = reopened
            .try_begin_observation_process(second_generation)
            .expect("begin restarted process");
        let refreshed = observe_current(&refreshed, &nodes[0], 0, second_generation, 0xb4, 1);
        let refreshed = observe_current(&refreshed, &nodes[1], 1, second_generation, 0xb5, 2);
        assert!(
            refreshed
                .rows
                .iter()
                .all(|row| row.process_qualified_status_digest.is_some())
        );
    }

    #[test]
    fn not_modified_keeps_the_original_status_observation_time() {
        let (bundle, mut nodes, state) = initialized();
        nodes[0].observe_runtime(&bundle.predecessors[0], 5, 5, 5);
        nodes[0].publish();
        let generation = NodeObservationProcessGenerationV1::try_from_bytes([0xa3; 16])
            .expect("process generation");
        let state = state
            .try_begin_observation_process(generation)
            .expect("begin process");
        let status = observe_current(&state, &nodes[0], 0, generation, 0xc1, 10);
        let before = status.encode().expect("status PXDN");
        let not_modified = observe_current(&status, &nodes[0], 0, generation, 0xc2, 20);
        let after = not_modified.encode().expect("NotModified PXDN");

        assert_eq!(not_modified.rows[0].status_observed_at_nanos, 10);
        assert_eq!(not_modified.rows[0].latest_observed_at_nanos, 20);
        assert_eq!(
            not_modified.rows[0].availability,
            DistributedAgentStackNodeAvailabilityV1::Current
        );
        validate_distributed_agent_stack_node_wire_successor_v1(&before, &after)
            .expect("NotModified successor");
    }

    #[test]
    fn runtime_high_water_survives_hide_reopen_and_rejects_lower_reappearance() {
        let (bundle, mut nodes, state) = initialized();
        nodes[0].observe_runtime(&bundle.predecessors[0], 5, 5, 5);
        nodes[0].publish();
        let generation = NodeObservationProcessGenerationV1::try_from_bytes([0xa4; 16])
            .expect("process generation");
        let state = state
            .try_begin_observation_process(generation)
            .expect("begin process");
        let state = observe_current(&state, &nodes[0], 0, generation, 0xd1, 10);
        let high_water = state.rows[0]
            .runtime_high_water
            .clone()
            .expect("Runtime high-water");

        nodes[0]
            .daemon
            .forget_runtime_host(bundle.predecessors[0].target());
        nodes[0].publish();
        let hidden = observe_current(&state, &nodes[0], 0, generation, 0xd2, 20);
        assert_eq!(hidden.rows[0].runtime_high_water, Some(high_water.clone()));
        assert!(
            hidden.rows[0]
                .status_response
                .as_ref()
                .and_then(NodeManagementResponseV1::status_value)
                .is_some_and(|status| status.runtime_hosts().is_empty())
        );

        let durable = hidden.encode().expect("hidden PXDN");
        let reopened = DistributedAgentStackNodeDiscoveryStateV1::decode(&durable)
            .expect("reopened hidden PXDN");
        assert_eq!(
            reopened.rows[0].runtime_high_water,
            Some(high_water.clone())
        );

        let mut lower = NodeHarness::new(nodes[0].seed);
        lower.publish();
        lower.publish();
        lower.observe_runtime(&bundle.predecessors[0], 4, 4, 4);
        lower.publish();
        let next_generation = NodeObservationProcessGenerationV1::try_from_bytes([0xa5; 16])
            .expect("next generation");
        let reopened = reopened
            .try_begin_observation_process(next_generation)
            .expect("begin reopened process");
        let rejected = observe_current(&reopened, &lower, 0, next_generation, 0xd3, 1);
        assert_eq!(
            rejected.rows[0].availability,
            DistributedAgentStackNodeAvailabilityV1::InvalidCurrent
        );
        assert_eq!(rejected.rows[0].runtime_high_water, Some(high_water));
    }

    #[test]
    fn trusted_local_client_rejects_timeout_above_the_hard_cap() {
        assert!(
            TrustedLocalNodeEndpointV1::try_new(
                PathBuf::from("/tmp/paraegox-node-test.sock"),
                1,
                1,
                [0x11; 32],
                Digest32::from_bytes([0x12; 32]),
                Duration::from_secs(11),
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_snapshot_must_reach_the_authenticated_predecessor_floor() {
        let (bundle, mut nodes, _) = initialized();
        let predecessor = &bundle.predecessors[0];
        let epoch = predecessor.predecessor_runtime_host_epoch();
        let floor = predecessor.predecessor_completion_snapshot_sequence();
        let before = floor.checked_sub(1).expect("nonzero predecessor floor");

        nodes[0].observe_runtime(predecessor, epoch, before, 5);
        nodes[0].publish();
        let before_floor = nodes[0]
            .daemon
            .current_status()
            .and_then(|status| status.runtime_hosts().first())
            .expect("Runtime before predecessor floor");
        assert!(!runtime_reaches_predecessor_snapshot(
            before_floor,
            predecessor
        ));

        nodes[0].observe_runtime(predecessor, epoch, floor, 5);
        nodes[0].publish();
        let at_floor = nodes[0]
            .daemon
            .current_status()
            .and_then(|status| status.runtime_hosts().first())
            .expect("Runtime at predecessor floor");
        assert!(runtime_reaches_predecessor_snapshot(at_floor, predecessor));

        nodes[0].observe_runtime(
            predecessor,
            epoch,
            floor.checked_add(1).expect("bounded predecessor floor"),
            5,
        );
        nodes[0].publish();
        let after_floor = nodes[0]
            .daemon
            .current_status()
            .and_then(|status| status.runtime_hosts().first())
            .expect("Runtime after predecessor floor");
        assert!(runtime_reaches_predecessor_snapshot(
            after_floor,
            predecessor
        ));
    }
}
