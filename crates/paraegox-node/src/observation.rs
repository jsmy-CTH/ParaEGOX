#![cfg(unix)]

//! Authenticated Runtime observation ingress for the Unix reference NodeDaemon.
//!
//! This module adapts the existing Runtime-owned PXQR/PXQS truth into one
//! Node-owned [`RuntimeHostStatusV1`].  It does not define a second Runtime
//! status protocol: a candidate is usable only after the exact Runtime
//! Ed25519 signature, request/response correlation, channel binding, serving
//! baseline and a short-lived Node-tenure/endpoint challenge nonce all verify.
//! The apply endpoint descriptor is pinned byte-for-byte by PXOB; PXNO cannot
//! rotate its generation or any other descriptor field.
//!
//! PXNO-v1 is a same-user DeveloperLocal capability: its token holder is the
//! trusted query producer and supplies the bounded wall-clock window. A future
//! production transport still needs Node-issued unpredictable remote
//! challenges rather than treating this local clock window as federation proof.
//! The authenticated challenge expiry is included in the resulting PXNS
//! status digest and persisted with PXND. Consumers enforce it in addition to
//! the relative freshness budget, and the local management owner refuses the
//! immutable status at or after that expiry. A multi-Runtime publication uses
//! the earliest retained deadline, so one observation cannot renew another.
//! An exact committed PXNO may still recover its lost PXNA without republishing
//! or making the status fresh again.

use core::{fmt, num::NonZeroU64};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use paraegox_kernel::{
    digest::{Digest32, Digest32Builder, DigestBuildError},
    identity::{PrincipalRef, RuntimeHostId},
    time::{ClockDomainRef, ClockGeneration},
};
use paraegox_runtime_contracts::{
    reference_control::{
        MAX_REFERENCE_QUERY_REQUEST_BYTES, MAX_REFERENCE_QUERY_RESPONSE_BYTES,
        ReferenceBootstrapServingIdentityV1, ReferenceChannelBindingV1, ReferenceQueryRequestV1,
        ReferenceQueryResponseV1,
    },
    wire::ApplyAuthKeyRef,
};
use zeroize::Zeroizing;

use crate::protocol::NodeManagementTargetV1;
use crate::{
    MAX_NODE_STATUS_FRESHNESS_NANOS, MAX_RUNTIME_HOSTS_PER_NODE, NodeContractError,
    NodeManagementEndpointRefV1, NodeStatusV1, RuntimeApplyEndpointDescriptorV1,
    RuntimeApplyEndpointRefV1, RuntimeHostLivenessV1, RuntimeHostStatusV1,
};

/// Exact PXOB/PXNO/PXNA protocol version.
pub const RUNTIME_OBSERVATION_PROTOCOL_VERSION: u16 = 1;
/// Independent capability-token width for the mutation ingress.
pub const RUNTIME_OBSERVATION_TOKEN_BYTES: usize = 32;
/// Longest wall-clock validity window admitted for one PXQR challenge.
pub const MAX_RUNTIME_OBSERVATION_CHALLENGE_NANOS: u64 = 60_000_000_000;
/// Largest strict PXNO frame.
pub const MAX_RUNTIME_OBSERVATION_REQUEST_BYTES: usize = OBSERVATION_REQUEST_HEADER_BYTES
    + MAX_REFERENCE_QUERY_REQUEST_BYTES
    + MAX_REFERENCE_QUERY_RESPONSE_BYTES;
/// Minimum and fixed PXNO header width.
pub const RUNTIME_OBSERVATION_REQUEST_HEADER_BYTES: usize = OBSERVATION_REQUEST_HEADER_BYTES;
/// Exact PXNA acknowledgement width.
pub const RUNTIME_OBSERVATION_ACK_BYTES: usize = OBSERVATION_ACK_BYTES;
/// Largest strict PXOB bootstrap including eight maximum-length authorities.
pub const MAX_RUNTIME_OBSERVATION_BOOTSTRAP_BYTES: usize = BOOTSTRAP_HEADER_BYTES
    + MAX_RUNTIME_HOSTS_PER_NODE * (AUTHORITY_FIXED_BYTES + MAX_RUNTIME_ROUTE_BYTES)
    + MAX_UNIX_SOCKET_PATH_BYTES;

const BOOTSTRAP_MAGIC: &[u8; 4] = b"PXOB";
const OBSERVATION_REQUEST_MAGIC: &[u8; 4] = b"PXNO";
const OBSERVATION_ACK_MAGIC: &[u8; 4] = b"PXNA";
const BOOTSTRAP_HEADER_BYTES: usize = 160;
const BOOTSTRAP_DIGEST_OFFSET: usize = 128;
const AUTHORITY_FIXED_BYTES: usize = 288;
const AUTHORITY_DIGEST_OFFSET: usize = 256;
const OBSERVATION_REQUEST_HEADER_BYTES: usize = 128;
const OBSERVATION_REQUEST_DIGEST_OFFSET: usize = 96;
const OBSERVATION_ACK_BYTES: usize = 160;
const OBSERVATION_ACK_DIGEST_OFFSET: usize = 128;
const MAX_RUNTIME_ROUTE_BYTES: usize = 255;
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const BOOTSTRAP_DIGEST_DOMAIN: &[u8] = b"paraegox.node.runtime-observation-bootstrap.v1";
const AUTHORITY_DIGEST_DOMAIN: &[u8] = b"paraegox.node.runtime-observation-authority.v1";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.node.runtime-observation-request.v1";
const ACK_DIGEST_DOMAIN: &[u8] = b"paraegox.node.runtime-observation-ack.v1";
const QUERY_NONCE_DOMAIN: &[u8] = b"paraegox.node.runtime-observation-query-nonce.v1";

/// Opaque identity of the independent Node mutation endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeObservationEndpointRefV1([u8; 16]);

impl RuntimeObservationEndpointRefV1 {
    /// Constructs a nonzero endpoint identity.
    pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, RuntimeObservationError> {
        if bytes_are_zero(&bytes) {
            Err(RuntimeObservationError::InvalidBootstrap)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns canonical identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// One exact Runtime authority admitted by an owner-supplied PXOB.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeObservationAuthorityV1 {
    runtime_principal: PrincipalRef,
    channel: ReferenceChannelBindingV1,
    serving_baseline: ReferenceBootstrapServingIdentityV1,
    apply_endpoint: RuntimeApplyEndpointDescriptorV1,
    authority_digest: Digest32,
}

impl RuntimeObservationAuthorityV1 {
    /// Pins one Runtime identity, signer, channel, serving baseline and full
    /// apply endpoint descriptor. Descriptor rotation requires a new PXOB.
    pub fn try_new(
        runtime_principal: PrincipalRef,
        channel: ReferenceChannelBindingV1,
        serving_baseline: ReferenceBootstrapServingIdentityV1,
        apply_endpoint: RuntimeApplyEndpointDescriptorV1,
    ) -> Result<Self, RuntimeObservationError> {
        let runtime_host_id = apply_endpoint.runtime_host_id();
        if bytes_are_zero(runtime_host_id.as_bytes())
            || bytes_are_zero(runtime_principal.as_bytes())
            || channel.target() != runtime_host_id
            || channel.runtime_peer() != runtime_principal
            || serving_baseline.target() != runtime_host_id
            || bytes_are_zero(&apply_endpoint.runtime_response_key_ref())
        {
            return Err(RuntimeObservationError::InvalidAuthority);
        }
        let verifying_key = VerifyingKey::from_bytes(&apply_endpoint.runtime_response_public_key())
            .map_err(|_| RuntimeObservationError::InvalidAuthority)?;
        if verifying_key.is_weak() {
            return Err(RuntimeObservationError::WeakRuntimeResponseKey);
        }
        let authority_digest = authority_digest(
            runtime_principal,
            channel,
            serving_baseline,
            &apply_endpoint,
        )?;
        Ok(Self {
            runtime_principal,
            channel,
            serving_baseline,
            apply_endpoint,
            authority_digest,
        })
    }

    #[must_use]
    pub const fn runtime_host_id(&self) -> RuntimeHostId {
        self.apply_endpoint.runtime_host_id()
    }

    #[must_use]
    pub const fn runtime_principal(&self) -> PrincipalRef {
        self.runtime_principal
    }

    #[must_use]
    pub const fn channel(&self) -> ReferenceChannelBindingV1 {
        self.channel
    }

    #[must_use]
    pub const fn serving_baseline(&self) -> ReferenceBootstrapServingIdentityV1 {
        self.serving_baseline
    }

    #[must_use]
    pub const fn apply_endpoint(&self) -> &RuntimeApplyEndpointDescriptorV1 {
        &self.apply_endpoint
    }

    #[must_use]
    pub const fn authority_digest(&self) -> Digest32 {
        self.authority_digest
    }

    /// Verifies the Runtime-owned PXQS and projects only process
    /// responsiveness plus the exact pinned endpoint into Node status.
    pub fn verify_and_project(
        &self,
        node_target: NodeManagementTargetV1,
        observation_endpoint_ref: RuntimeObservationEndpointRefV1,
        observation_token: &[u8; RUNTIME_OBSERVATION_TOKEN_BYTES],
        request: &RuntimeObservationRequestV1,
    ) -> Result<RuntimeHostStatusV1, RuntimeObservationError> {
        if request.runtime_host_id() != self.runtime_host_id()
            || request.authority_digest() != self.authority_digest
            || request.query_request().target() != self.runtime_host_id()
            || request.query_request().expected_runtime_store_instance_id()
                != self.serving_baseline.runtime_store_instance_id()
        {
            return Err(RuntimeObservationError::AuthorityMismatch);
        }
        request.remaining_freshness_budget_nanos()?;
        let expected_nonce = derive_runtime_observation_query_nonce_v1(
            observation_token,
            node_target,
            observation_endpoint_ref,
            self,
            request.intended_status_sequence(),
            request.challenge_issued_at_unix_nanos(),
            request.challenge_expires_at_unix_nanos(),
        )?;
        if request.query_request().authentication().claim().nonce() != expected_nonce.as_bytes() {
            return Err(RuntimeObservationError::ChallengeMismatch);
        }

        let response = request.query_response();
        if response.authentication_runtime_peer() != self.runtime_principal
            || response.authentication_key()
                != ApplyAuthKeyRef::from_bytes(self.apply_endpoint.runtime_response_key_ref())
            || response.authentication_algorithm().value() != ED25519_ALGORITHM
            || response.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        {
            return Err(RuntimeObservationError::AuthorityMismatch);
        }
        let signature_bytes: [u8; ED25519_SIGNATURE_BYTES] = response
            .authentication_signature()
            .try_into()
            .map_err(|_| RuntimeObservationError::InvalidRuntimeSignature)?;
        let transcript = response
            .signing_transcript()
            .map_err(|_| RuntimeObservationError::InvalidRuntimeResponse)?;
        let verifying_key =
            VerifyingKey::from_bytes(&self.apply_endpoint.runtime_response_public_key())
                .map_err(|_| RuntimeObservationError::InvalidAuthority)?;
        verifying_key
            .verify_strict(
                transcript.as_bytes(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| RuntimeObservationError::InvalidRuntimeSignature)?;

        let facts = response
            .validate_against_request(request.query_request(), self.channel, self.serving_baseline)
            .map_err(|_| RuntimeObservationError::InvalidRuntimeResponse)?;
        let serving = facts.serving();
        RuntimeHostStatusV1::try_new(
            serving.runtime_host_epoch(),
            serving.snapshot_sequence(),
            // This says only that a fresh, Node-challenged, Runtime-signed
            // exchange completed. It does not project PXQS readiness.
            RuntimeHostLivenessV1::Live,
            self.apply_endpoint.clone(),
        )
        .map_err(RuntimeObservationError::Node)
    }
}

/// Complete owner-supplied inputs for an independent PXOB capability.
pub struct RuntimeObservationBootstrapInputV1 {
    pub expected_uid: u32,
    pub expected_gid: u32,
    pub generation_token: [u8; RUNTIME_OBSERVATION_TOKEN_BYTES],
    pub node_target: NodeManagementTargetV1,
    pub observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    pub socket_path: PathBuf,
    pub authorities: Vec<RuntimeObservationAuthorityV1>,
}

/// Strict owner-private bootstrap for the mutation ingress.
pub struct RuntimeObservationBootstrapV1 {
    expected_uid: u32,
    expected_gid: u32,
    generation_token: Zeroizing<[u8; RUNTIME_OBSERVATION_TOKEN_BYTES]>,
    node_target: NodeManagementTargetV1,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    socket_path: PathBuf,
    authorities: Box<[RuntimeObservationAuthorityV1]>,
}

impl fmt::Debug for RuntimeObservationBootstrapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeObservationBootstrapV1")
            .field("expected_uid", &self.expected_uid)
            .field("expected_gid", &self.expected_gid)
            .field("generation_token", &"<redacted>")
            .field("node_target", &self.node_target)
            .field("observation_endpoint_ref", &self.observation_endpoint_ref)
            .field("socket_path", &self.socket_path)
            .field("authorities", &self.authorities)
            .finish()
    }
}

impl RuntimeObservationBootstrapV1 {
    pub fn try_new(
        mut input: RuntimeObservationBootstrapInputV1,
    ) -> Result<Self, RuntimeObservationError> {
        if input.expected_uid != nix::unistd::geteuid().as_raw()
            || input.expected_gid != nix::unistd::getegid().as_raw()
            || bytes_are_zero(&input.generation_token)
            || input.authorities.is_empty()
            || input.authorities.len() > MAX_RUNTIME_HOSTS_PER_NODE
        {
            return Err(RuntimeObservationError::InvalidBootstrap);
        }
        validate_absolute_socket_path(&input.socket_path)?;
        input
            .authorities
            .sort_by_key(RuntimeObservationAuthorityV1::runtime_host_id);
        if input
            .authorities
            .windows(2)
            .any(|pair| pair[0].runtime_host_id() == pair[1].runtime_host_id())
        {
            return Err(RuntimeObservationError::DuplicateAuthority);
        }
        Ok(Self {
            expected_uid: input.expected_uid,
            expected_gid: input.expected_gid,
            generation_token: Zeroizing::new(input.generation_token),
            node_target: input.node_target,
            observation_endpoint_ref: input.observation_endpoint_ref,
            socket_path: input.socket_path,
            authorities: input.authorities.into_boxed_slice(),
        })
    }

    /// Strictly decodes the one canonical PXOB-v1 representation.
    pub fn decode_canonical_wire(wire: &[u8]) -> Result<Self, RuntimeObservationError> {
        decode_bootstrap(wire)
    }

    /// Encodes secret-bearing PXOB bytes in zeroizing memory.
    pub fn canonical_wire(&self) -> Result<Zeroizing<Vec<u8>>, RuntimeObservationError> {
        encode_bootstrap(self)
    }

    /// Atomically writes a new owner-private PXOB file without replacement.
    pub fn write_owner_private_file(
        &self,
        file_path: &Path,
    ) -> Result<(), RuntimeObservationError> {
        let wire = self.canonical_wire()?;
        crate::process::write_owner_private_canonical_file_v1(
            file_path,
            wire.as_ref(),
            self.expected_uid,
            self.expected_gid,
        )
        .map_err(|error| match error {
            crate::process::NodeDaemonProcessError::BootstrapAlreadyExists => {
                RuntimeObservationError::BootstrapAlreadyExists
            }
            crate::process::NodeDaemonProcessError::BootstrapCommitUncertain => {
                RuntimeObservationError::BootstrapCommitUncertain
            }
            crate::process::NodeDaemonProcessError::InsecurePermissions => {
                RuntimeObservationError::InsecurePermissions
            }
            crate::process::NodeDaemonProcessError::InvalidPath => {
                RuntimeObservationError::InvalidPath
            }
            _ => RuntimeObservationError::BootstrapUnavailable,
        })
    }

    #[must_use]
    pub const fn expected_uid(&self) -> u32 {
        self.expected_uid
    }

    #[must_use]
    pub const fn expected_gid(&self) -> u32 {
        self.expected_gid
    }

    #[must_use]
    pub const fn node_target(&self) -> NodeManagementTargetV1 {
        self.node_target
    }

    #[must_use]
    pub const fn observation_endpoint_ref(&self) -> RuntimeObservationEndpointRefV1 {
        self.observation_endpoint_ref
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn authorities(&self) -> &[RuntimeObservationAuthorityV1] {
        &self.authorities
    }

    #[must_use]
    pub(crate) fn generation_token(&self) -> &Zeroizing<[u8; RUNTIME_OBSERVATION_TOKEN_BYTES]> {
        &self.generation_token
    }

    pub(crate) fn authority(
        &self,
        runtime_host_id: RuntimeHostId,
    ) -> Result<&RuntimeObservationAuthorityV1, RuntimeObservationError> {
        self.authorities
            .binary_search_by_key(
                &runtime_host_id,
                RuntimeObservationAuthorityV1::runtime_host_id,
            )
            .ok()
            .map(|index| &self.authorities[index])
            .ok_or(RuntimeObservationError::UnknownAuthority)
    }
}

/// Complete inputs for one short-lived canonical PXNO request.
pub struct RuntimeObservationRequestInputV1 {
    pub intended_status_sequence: u64,
    pub freshness_budget_nanos: u64,
    pub runtime_host_id: RuntimeHostId,
    pub authority_digest: Digest32,
    pub challenge_issued_at_unix_nanos: u64,
    pub challenge_expires_at_unix_nanos: u64,
    pub query_request: ReferenceQueryRequestV1,
    pub query_response: ReferenceQueryResponseV1,
}

/// Strict PXNO request carrying one short-lived canonical PXQR/PXQS pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeObservationRequestV1 {
    intended_status_sequence: NonZeroU64,
    freshness_budget_nanos: NonZeroU64,
    runtime_host_id: RuntimeHostId,
    authority_digest: Digest32,
    challenge_issued_at_unix_nanos: NonZeroU64,
    challenge_expires_at_unix_nanos: NonZeroU64,
    query_request: ReferenceQueryRequestV1,
    query_response: ReferenceQueryResponseV1,
    request_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl RuntimeObservationRequestV1 {
    pub fn try_new(
        input: RuntimeObservationRequestInputV1,
    ) -> Result<Self, RuntimeObservationError> {
        let RuntimeObservationRequestInputV1 {
            intended_status_sequence,
            freshness_budget_nanos,
            runtime_host_id,
            authority_digest,
            challenge_issued_at_unix_nanos,
            challenge_expires_at_unix_nanos,
            query_request,
            query_response,
        } = input;
        let intended_status_sequence = NonZeroU64::new(intended_status_sequence)
            .ok_or(RuntimeObservationError::InvalidRequest)?;
        let freshness_budget_nanos = NonZeroU64::new(freshness_budget_nanos)
            .filter(|value| value.get() <= MAX_NODE_STATUS_FRESHNESS_NANOS)
            .ok_or(RuntimeObservationError::InvalidRequest)?;
        let (challenge_issued_at_unix_nanos, challenge_expires_at_unix_nanos) =
            validate_challenge_window(
                challenge_issued_at_unix_nanos,
                challenge_expires_at_unix_nanos,
            )?;
        if challenge_expires_at_unix_nanos.get() - challenge_issued_at_unix_nanos.get()
            > freshness_budget_nanos.get()
        {
            return Err(RuntimeObservationError::InvalidRequest);
        }
        if bytes_are_zero(runtime_host_id.as_bytes())
            || bytes_are_zero(authority_digest.as_bytes())
            || query_request.target() != runtime_host_id
        {
            return Err(RuntimeObservationError::InvalidRequest);
        }
        let canonical_wire = encode_request(
            intended_status_sequence.get(),
            freshness_budget_nanos.get(),
            runtime_host_id,
            authority_digest,
            challenge_issued_at_unix_nanos.get(),
            challenge_expires_at_unix_nanos.get(),
            &query_request,
            &query_response,
        )?;
        let request_digest = Digest32::from_bytes(copy_array(
            &canonical_wire,
            OBSERVATION_REQUEST_DIGEST_OFFSET,
        ));
        Ok(Self {
            intended_status_sequence,
            freshness_budget_nanos,
            runtime_host_id,
            authority_digest,
            challenge_issued_at_unix_nanos,
            challenge_expires_at_unix_nanos,
            query_request,
            query_response,
            request_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    pub fn decode(frame: &[u8]) -> Result<Self, RuntimeObservationError> {
        if frame.len() < OBSERVATION_REQUEST_HEADER_BYTES
            || frame.len() > MAX_RUNTIME_OBSERVATION_REQUEST_BYTES
            || &frame[..4] != OBSERVATION_REQUEST_MAGIC
            || read_u16(frame, 4) != RUNTIME_OBSERVATION_PROTOCOL_VERSION
            || usize::from(read_u16(frame, 6)) != OBSERVATION_REQUEST_HEADER_BYTES
            || usize::try_from(read_u32(frame, 8)).ok() != Some(frame.len())
        {
            return Err(RuntimeObservationError::InvalidRequest);
        }
        let query_request_length = usize::from(read_u16(frame, 12));
        let query_response_length = usize::from(read_u16(frame, 14));
        if query_request_length == 0
            || query_request_length > MAX_REFERENCE_QUERY_REQUEST_BYTES
            || query_response_length == 0
            || query_response_length > MAX_REFERENCE_QUERY_RESPONSE_BYTES
            || OBSERVATION_REQUEST_HEADER_BYTES
                .checked_add(query_request_length)
                .and_then(|length| length.checked_add(query_response_length))
                != Some(frame.len())
            || request_digest(frame)?
                != Digest32::from_bytes(copy_array(frame, OBSERVATION_REQUEST_DIGEST_OFFSET))
        {
            return Err(RuntimeObservationError::InvalidRequest);
        }
        let query_request_end = OBSERVATION_REQUEST_HEADER_BYTES + query_request_length;
        let query_request = ReferenceQueryRequestV1::decode(
            &frame[OBSERVATION_REQUEST_HEADER_BYTES..query_request_end],
        )
        .map_err(|_| RuntimeObservationError::InvalidRuntimeRequest)?;
        let query_response = ReferenceQueryResponseV1::decode(&frame[query_request_end..])
            .map_err(|_| RuntimeObservationError::InvalidRuntimeResponse)?;
        let value = Self::try_new(RuntimeObservationRequestInputV1 {
            intended_status_sequence: read_u64(frame, 16),
            freshness_budget_nanos: read_u64(frame, 24),
            runtime_host_id: RuntimeHostId::from_bytes(copy_array(frame, 32)),
            authority_digest: Digest32::from_bytes(copy_array(frame, 48)),
            challenge_issued_at_unix_nanos: read_u64(frame, 80),
            challenge_expires_at_unix_nanos: read_u64(frame, 88),
            query_request,
            query_response,
        })?;
        if value.canonical_wire() != frame {
            return Err(RuntimeObservationError::InvalidRequest);
        }
        Ok(value)
    }

    #[must_use]
    pub const fn intended_status_sequence(&self) -> u64 {
        self.intended_status_sequence.get()
    }

    #[must_use]
    pub const fn freshness_budget_nanos(&self) -> u64 {
        self.freshness_budget_nanos.get()
    }

    #[must_use]
    pub const fn runtime_host_id(&self) -> RuntimeHostId {
        self.runtime_host_id
    }

    #[must_use]
    pub const fn authority_digest(&self) -> Digest32 {
        self.authority_digest
    }

    #[must_use]
    pub const fn challenge_issued_at_unix_nanos(&self) -> u64 {
        self.challenge_issued_at_unix_nanos.get()
    }

    #[must_use]
    pub const fn challenge_expires_at_unix_nanos(&self) -> u64 {
        self.challenge_expires_at_unix_nanos.get()
    }

    #[must_use]
    pub const fn query_request(&self) -> &ReferenceQueryRequestV1 {
        &self.query_request
    }

    #[must_use]
    pub const fn query_response(&self) -> &ReferenceQueryResponseV1 {
        &self.query_response
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    pub(crate) fn remaining_freshness_budget_nanos(&self) -> Result<u64, RuntimeObservationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeObservationError::ChallengeClockUnavailable)?;
        let now = u64::try_from(now.as_nanos())
            .map_err(|_| RuntimeObservationError::ChallengeClockUnavailable)?;
        let issued_at = self.challenge_issued_at_unix_nanos.get();
        let expires_at = self.challenge_expires_at_unix_nanos.get();
        if now < issued_at || now >= expires_at {
            return Err(RuntimeObservationError::ChallengeExpired);
        }
        let age = now - issued_at;
        let remaining_budget = self
            .freshness_budget_nanos
            .get()
            .checked_sub(age)
            .unwrap_or(0);
        let remaining_window = expires_at - now;
        let remaining = core::cmp::min(remaining_budget, remaining_window);
        if remaining == 0 {
            Err(RuntimeObservationError::ChallengeExpired)
        } else {
            Ok(remaining)
        }
    }
}

/// Durable outcome reported by PXNA.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RuntimeObservationAckOutcomeV1 {
    Published = 1,
    ExactReplay = 2,
}

/// Strict PXNA acknowledgement. It binds only the resulting durable PXNS
/// coordinate, not storage of the PXQR/PXQS source bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeObservationAckV1 {
    outcome: RuntimeObservationAckOutcomeV1,
    intended_status_sequence: NonZeroU64,
    status_digest: Digest32,
    runtime_status_digest: Digest32,
    request_digest: Digest32,
    ack_digest: Digest32,
    canonical_wire: [u8; OBSERVATION_ACK_BYTES],
}

impl RuntimeObservationAckV1 {
    pub(crate) fn try_new(
        outcome: RuntimeObservationAckOutcomeV1,
        request: &RuntimeObservationRequestV1,
        resulting_status: &NodeStatusV1,
        runtime_status_digest: Digest32,
    ) -> Result<Self, RuntimeObservationError> {
        if resulting_status.status_sequence() != request.intended_status_sequence()
            || !resulting_status.runtime_hosts().iter().any(|runtime| {
                runtime.runtime_host_id() == request.runtime_host_id()
                    && runtime.status_digest() == runtime_status_digest
            })
        {
            return Err(RuntimeObservationError::AckMismatch);
        }
        let canonical_wire = encode_ack(
            outcome,
            request,
            resulting_status.status_digest(),
            runtime_status_digest,
        )?;
        Ok(Self {
            outcome,
            intended_status_sequence: request.intended_status_sequence,
            status_digest: resulting_status.status_digest(),
            runtime_status_digest,
            request_digest: request.request_digest(),
            ack_digest: Digest32::from_bytes(copy_array(
                &canonical_wire,
                OBSERVATION_ACK_DIGEST_OFFSET,
            )),
            canonical_wire,
        })
    }

    pub fn decode(frame: &[u8]) -> Result<Self, RuntimeObservationError> {
        if frame.len() != OBSERVATION_ACK_BYTES
            || &frame[..4] != OBSERVATION_ACK_MAGIC
            || read_u16(frame, 4) != RUNTIME_OBSERVATION_PROTOCOL_VERSION
            || usize::from(read_u16(frame, 6)) != OBSERVATION_ACK_BYTES
            || usize::try_from(read_u32(frame, 8)).ok() != Some(OBSERVATION_ACK_BYTES)
            || frame[13..16].iter().any(|byte| *byte != 0)
            || frame[120..OBSERVATION_ACK_DIGEST_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
            || ack_digest(frame)?
                != Digest32::from_bytes(copy_array(frame, OBSERVATION_ACK_DIGEST_OFFSET))
        {
            return Err(RuntimeObservationError::InvalidAck);
        }
        let outcome = match frame[12] {
            1 => RuntimeObservationAckOutcomeV1::Published,
            2 => RuntimeObservationAckOutcomeV1::ExactReplay,
            _ => return Err(RuntimeObservationError::InvalidAck),
        };
        let intended_status_sequence =
            NonZeroU64::new(read_u64(frame, 16)).ok_or(RuntimeObservationError::InvalidAck)?;
        let value = Self {
            outcome,
            intended_status_sequence,
            status_digest: Digest32::from_bytes(copy_array(frame, 24)),
            runtime_status_digest: Digest32::from_bytes(copy_array(frame, 56)),
            request_digest: Digest32::from_bytes(copy_array(frame, 88)),
            ack_digest: Digest32::from_bytes(copy_array(frame, 128)),
            canonical_wire: copy_array(frame, 0),
        };
        if bytes_are_zero(value.status_digest.as_bytes())
            || bytes_are_zero(value.runtime_status_digest.as_bytes())
            || bytes_are_zero(value.request_digest.as_bytes())
        {
            return Err(RuntimeObservationError::InvalidAck);
        }
        Ok(value)
    }

    pub fn validate_for(
        &self,
        request: &RuntimeObservationRequestV1,
    ) -> Result<(), RuntimeObservationError> {
        if self.intended_status_sequence.get() != request.intended_status_sequence()
            || self.request_digest != request.request_digest()
        {
            return Err(RuntimeObservationError::AckMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn outcome(&self) -> RuntimeObservationAckOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn status_sequence(&self) -> u64 {
        self.intended_status_sequence.get()
    }

    #[must_use]
    pub const fn status_digest(&self) -> Digest32 {
        self.status_digest
    }

    #[must_use]
    pub const fn runtime_status_digest(&self) -> Digest32 {
        self.runtime_status_digest
    }

    #[must_use]
    pub const fn ack_digest(&self) -> Digest32 {
        self.ack_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Derives the exact 32-byte PXQR nonce for one proposed next PXNS sequence and
/// bounded wall-clock challenge window. The independent capability token is
/// never placed directly in PXQR/PXQS.
pub fn derive_runtime_observation_query_nonce_v1(
    observation_token: &[u8; RUNTIME_OBSERVATION_TOKEN_BYTES],
    node_target: NodeManagementTargetV1,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    authority: &RuntimeObservationAuthorityV1,
    intended_status_sequence: u64,
    challenge_issued_at_unix_nanos: u64,
    challenge_expires_at_unix_nanos: u64,
) -> Result<Digest32, RuntimeObservationError> {
    if bytes_are_zero(observation_token) || intended_status_sequence == 0 {
        return Err(RuntimeObservationError::InvalidRequest);
    }
    validate_challenge_window(
        challenge_issued_at_unix_nanos,
        challenge_expires_at_unix_nanos,
    )?;
    let mut builder = Digest32Builder::try_new(QUERY_NONCE_DOMAIN)?;
    builder
        .field_bytes(observation_token)?
        .field_bytes(node_target.node_id().as_bytes())?
        .field_bytes(node_target.node_incarnation().as_bytes())?
        .field_u64(node_target.registration_epoch())?
        .field_bytes(node_target.management_endpoint_ref().as_bytes())?
        .field_bytes(observation_endpoint_ref.as_bytes())?
        .field_bytes(authority.runtime_host_id().as_bytes())?
        .field_digest(&authority.authority_digest())?
        .field_digest(&authority.apply_endpoint().descriptor_digest())?
        .field_u64(intended_status_sequence)?
        .field_u64(challenge_issued_at_unix_nanos)?
        .field_u64(challenge_expires_at_unix_nanos)?;
    Ok(builder.finish())
}

/// Stable fail-closed observation boundary failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeObservationError {
    InvalidAuthority,
    WeakRuntimeResponseKey,
    DuplicateAuthority,
    UnknownAuthority,
    AuthorityMismatch,
    ChallengeMismatch,
    ChallengeExpired,
    ChallengeClockUnavailable,
    InvalidRuntimeSignature,
    InvalidRuntimeRequest,
    InvalidRuntimeResponse,
    InvalidBootstrap,
    BootstrapUnavailable,
    BootstrapAlreadyExists,
    BootstrapCommitUncertain,
    InsecurePermissions,
    BootstrapDigestMismatch,
    InvalidRequest,
    InvalidAck,
    AckMismatch,
    InvalidPath,
    Node(NodeContractError),
    Digest(DigestBuildError),
}

impl fmt::Display for RuntimeObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime observation rejected: {self:?}")
    }
}

impl std::error::Error for RuntimeObservationError {}

impl From<DigestBuildError> for RuntimeObservationError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

fn authority_digest(
    runtime_principal: PrincipalRef,
    channel: ReferenceChannelBindingV1,
    serving: ReferenceBootstrapServingIdentityV1,
    endpoint: &RuntimeApplyEndpointDescriptorV1,
) -> Result<Digest32, RuntimeObservationError> {
    let mut builder = Digest32Builder::try_new(AUTHORITY_DIGEST_DOMAIN)?;
    builder
        .field_bytes(endpoint.runtime_host_id().as_bytes())?
        .field_bytes(runtime_principal.as_bytes())?
        .field_digest(&channel.binding_digest())?
        .field_bytes(&serving.runtime_store_instance_id())?
        .field_u64(serving.snapshot_sequence())?
        .field_u64(serving.runtime_host_epoch())?
        .field_bytes(serving.clock_domain().as_bytes())?
        .field_u64(serving.clock_generation().value())?
        .field_digest(&endpoint.descriptor_digest())?
        .field_bytes(&endpoint.runtime_response_key_ref())?
        .field_bytes(&endpoint.runtime_response_public_key())?;
    Ok(builder.finish())
}

fn encode_bootstrap(
    value: &RuntimeObservationBootstrapV1,
) -> Result<Zeroizing<Vec<u8>>, RuntimeObservationError> {
    let socket_path = value.socket_path.as_os_str().as_bytes();
    if socket_path.is_empty() || socket_path.len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(RuntimeObservationError::InvalidBootstrap);
    }
    let mut total = BOOTSTRAP_HEADER_BYTES
        .checked_add(socket_path.len())
        .ok_or(RuntimeObservationError::InvalidBootstrap)?;
    for authority in value.authorities.iter() {
        total = total
            .checked_add(AUTHORITY_FIXED_BYTES)
            .and_then(|length| length.checked_add(authority.apply_endpoint().route().len()))
            .ok_or(RuntimeObservationError::InvalidBootstrap)?;
    }
    if total > MAX_RUNTIME_OBSERVATION_BOOTSTRAP_BYTES {
        return Err(RuntimeObservationError::InvalidBootstrap);
    }
    let mut wire = Zeroizing::new(vec![0_u8; total]);
    wire[..4].copy_from_slice(BOOTSTRAP_MAGIC);
    write_u16(&mut wire, 4, RUNTIME_OBSERVATION_PROTOCOL_VERSION);
    write_u16(
        &mut wire,
        6,
        u16::try_from(BOOTSTRAP_HEADER_BYTES)
            .map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
    );
    write_u32(
        &mut wire,
        8,
        u32::try_from(total).map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
    );
    write_u16(
        &mut wire,
        12,
        u16::try_from(socket_path.len()).map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
    );
    wire[14] = u8::try_from(value.authorities.len())
        .map_err(|_| RuntimeObservationError::InvalidBootstrap)?;
    write_u32(&mut wire, 16, value.expected_uid);
    write_u32(&mut wire, 20, value.expected_gid);
    wire[24..40].copy_from_slice(value.node_target.node_id().as_bytes());
    wire[40..56].copy_from_slice(value.node_target.management_endpoint_ref().as_bytes());
    wire[56..72].copy_from_slice(value.node_target.node_incarnation().as_bytes());
    write_u64(&mut wire, 72, value.node_target.registration_epoch());
    wire[80..96].copy_from_slice(value.observation_endpoint_ref.as_bytes());
    wire[96..128].copy_from_slice(value.generation_token.as_ref());

    let mut cursor = BOOTSTRAP_HEADER_BYTES;
    for authority in value.authorities.iter() {
        let route = authority.apply_endpoint().route().as_bytes();
        let record_end = cursor + AUTHORITY_FIXED_BYTES;
        let record = &mut wire[cursor..record_end];
        record[..16].copy_from_slice(authority.runtime_host_id().as_bytes());
        record[16..32].copy_from_slice(authority.runtime_principal().as_bytes());
        record[32..48].copy_from_slice(&authority.apply_endpoint().runtime_response_key_ref());
        record[48..80].copy_from_slice(&authority.apply_endpoint().runtime_response_public_key());
        record[80..112].copy_from_slice(
            authority
                .channel()
                .local_endpoint_identity_digest()
                .as_bytes(),
        );
        record[112..144].copy_from_slice(authority.channel().peer_credentials_digest().as_bytes());
        record[144..176].copy_from_slice(&authority.serving_baseline().runtime_store_instance_id());
        write_u64(
            record,
            176,
            authority.serving_baseline().snapshot_sequence(),
        );
        write_u64(
            record,
            184,
            authority.serving_baseline().runtime_host_epoch(),
        );
        record[192..208].copy_from_slice(authority.serving_baseline().clock_domain().as_bytes());
        write_u64(
            record,
            208,
            authority.serving_baseline().clock_generation().value(),
        );
        record[216..232].copy_from_slice(authority.apply_endpoint().endpoint_ref().as_bytes());
        write_u64(
            record,
            232,
            authority.apply_endpoint().endpoint_generation(),
        );
        write_u16(
            record,
            240,
            u16::try_from(route.len()).map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
        );
        record[AUTHORITY_DIGEST_OFFSET..AUTHORITY_FIXED_BYTES]
            .copy_from_slice(authority.authority_digest().as_bytes());
        wire[record_end..record_end + route.len()].copy_from_slice(route);
        cursor = record_end + route.len();
    }
    wire[cursor..].copy_from_slice(socket_path);
    let digest = bootstrap_digest(&wire)?;
    wire[BOOTSTRAP_DIGEST_OFFSET..BOOTSTRAP_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(wire)
}

fn decode_bootstrap(wire: &[u8]) -> Result<RuntimeObservationBootstrapV1, RuntimeObservationError> {
    if wire.len() < BOOTSTRAP_HEADER_BYTES
        || wire.len() > MAX_RUNTIME_OBSERVATION_BOOTSTRAP_BYTES
        || &wire[..4] != BOOTSTRAP_MAGIC
        || read_u16(wire, 4) != RUNTIME_OBSERVATION_PROTOCOL_VERSION
        || usize::from(read_u16(wire, 6)) != BOOTSTRAP_HEADER_BYTES
        || usize::try_from(read_u32(wire, 8)).ok() != Some(wire.len())
        || wire[15] != 0
        || wire[BOOTSTRAP_DIGEST_OFFSET..BOOTSTRAP_HEADER_BYTES]
            .iter()
            .all(|byte| *byte == 0)
        || bootstrap_digest(wire)?
            != Digest32::from_bytes(copy_array(wire, BOOTSTRAP_DIGEST_OFFSET))
    {
        return Err(RuntimeObservationError::InvalidBootstrap);
    }
    let socket_length = usize::from(read_u16(wire, 12));
    let authority_count = usize::from(wire[14]);
    if socket_length == 0
        || socket_length > MAX_UNIX_SOCKET_PATH_BYTES
        || authority_count == 0
        || authority_count > MAX_RUNTIME_HOSTS_PER_NODE
    {
        return Err(RuntimeObservationError::InvalidBootstrap);
    }
    let node_target = NodeManagementTargetV1::try_new(
        crate::NodeId::try_from_bytes(copy_array(wire, 24))
            .map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
        NodeManagementEndpointRefV1::try_from_bytes(copy_array(wire, 40))
            .map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
        crate::NodeIncarnation::try_from_bytes(copy_array(wire, 56))
            .map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
        read_u64(wire, 72),
    )
    .map_err(|_| RuntimeObservationError::InvalidBootstrap)?;
    let observation_endpoint_ref =
        RuntimeObservationEndpointRefV1::try_from_bytes(copy_array(wire, 80))?;
    let generation_token = copy_array(wire, 96);
    let mut cursor = BOOTSTRAP_HEADER_BYTES;
    let socket_start = wire
        .len()
        .checked_sub(socket_length)
        .ok_or(RuntimeObservationError::InvalidBootstrap)?;
    let mut authorities = Vec::with_capacity(authority_count);
    for _ in 0..authority_count {
        let record_end = cursor
            .checked_add(AUTHORITY_FIXED_BYTES)
            .ok_or(RuntimeObservationError::InvalidBootstrap)?;
        let record = wire
            .get(cursor..record_end)
            .ok_or(RuntimeObservationError::InvalidBootstrap)?;
        let route_length = usize::from(read_u16(record, 240));
        let route_end = record_end
            .checked_add(route_length)
            .ok_or(RuntimeObservationError::InvalidBootstrap)?;
        if route_length == 0
            || route_length > MAX_RUNTIME_ROUTE_BYTES
            || route_end > socket_start
            || record[242..AUTHORITY_DIGEST_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(RuntimeObservationError::InvalidBootstrap);
        }
        let route = core::str::from_utf8(&wire[record_end..route_end])
            .map_err(|_| RuntimeObservationError::InvalidBootstrap)?;
        let runtime_host_id = RuntimeHostId::from_bytes(copy_array(record, 0));
        let runtime_principal = PrincipalRef::from_bytes(copy_array(record, 16));
        let channel = ReferenceChannelBindingV1::try_new(
            runtime_host_id,
            runtime_principal,
            Digest32::from_bytes(copy_array(record, 80)),
            Digest32::from_bytes(copy_array(record, 112)),
        )
        .map_err(|_| RuntimeObservationError::InvalidBootstrap)?;
        let serving_baseline = ReferenceBootstrapServingIdentityV1::try_new(
            runtime_host_id,
            copy_array(record, 144),
            read_u64(record, 176),
            read_u64(record, 184),
            ClockDomainRef::from_bytes(copy_array(record, 192)),
            ClockGeneration::try_new(read_u64(record, 208))
                .map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
        )
        .map_err(|_| RuntimeObservationError::InvalidBootstrap)?;
        let apply_endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes(copy_array(record, 216))
                .map_err(|_| RuntimeObservationError::InvalidBootstrap)?,
            runtime_host_id,
            read_u64(record, 232),
            route,
            copy_array(record, 32),
            copy_array(record, 48),
        )
        .map_err(|_| RuntimeObservationError::InvalidBootstrap)?;
        let authority = RuntimeObservationAuthorityV1::try_new(
            runtime_principal,
            channel,
            serving_baseline,
            apply_endpoint,
        )?;
        if authority.authority_digest()
            != Digest32::from_bytes(copy_array(record, AUTHORITY_DIGEST_OFFSET))
        {
            return Err(RuntimeObservationError::InvalidBootstrap);
        }
        authorities.push(authority);
        cursor = route_end;
    }
    if cursor != socket_start {
        return Err(RuntimeObservationError::InvalidBootstrap);
    }
    let socket_path = PathBuf::from(OsString::from_vec(wire[socket_start..].to_vec()));
    let value = RuntimeObservationBootstrapV1::try_new(RuntimeObservationBootstrapInputV1 {
        expected_uid: read_u32(wire, 16),
        expected_gid: read_u32(wire, 20),
        generation_token,
        node_target,
        observation_endpoint_ref,
        socket_path,
        authorities,
    })?;
    if value.canonical_wire()?.as_slice() != wire {
        return Err(RuntimeObservationError::InvalidBootstrap);
    }
    Ok(value)
}

fn encode_request(
    intended_status_sequence: u64,
    freshness_budget_nanos: u64,
    runtime_host_id: RuntimeHostId,
    authority_digest: Digest32,
    challenge_issued_at_unix_nanos: u64,
    challenge_expires_at_unix_nanos: u64,
    query_request: &ReferenceQueryRequestV1,
    query_response: &ReferenceQueryResponseV1,
) -> Result<Vec<u8>, RuntimeObservationError> {
    let query_request_bytes = query_request.canonical_wire();
    let query_response_bytes = query_response.canonical_wire();
    let total = OBSERVATION_REQUEST_HEADER_BYTES
        .checked_add(query_request_bytes.len())
        .and_then(|length| length.checked_add(query_response_bytes.len()))
        .ok_or(RuntimeObservationError::InvalidRequest)?;
    if total > MAX_RUNTIME_OBSERVATION_REQUEST_BYTES {
        return Err(RuntimeObservationError::InvalidRequest);
    }
    let mut wire = vec![0_u8; total];
    wire[..4].copy_from_slice(OBSERVATION_REQUEST_MAGIC);
    write_u16(&mut wire, 4, RUNTIME_OBSERVATION_PROTOCOL_VERSION);
    write_u16(
        &mut wire,
        6,
        u16::try_from(OBSERVATION_REQUEST_HEADER_BYTES)
            .map_err(|_| RuntimeObservationError::InvalidRequest)?,
    );
    write_u32(
        &mut wire,
        8,
        u32::try_from(total).map_err(|_| RuntimeObservationError::InvalidRequest)?,
    );
    write_u16(
        &mut wire,
        12,
        u16::try_from(query_request_bytes.len())
            .map_err(|_| RuntimeObservationError::InvalidRequest)?,
    );
    write_u16(
        &mut wire,
        14,
        u16::try_from(query_response_bytes.len())
            .map_err(|_| RuntimeObservationError::InvalidRequest)?,
    );
    write_u64(&mut wire, 16, intended_status_sequence);
    write_u64(&mut wire, 24, freshness_budget_nanos);
    wire[32..48].copy_from_slice(runtime_host_id.as_bytes());
    wire[48..80].copy_from_slice(authority_digest.as_bytes());
    write_u64(&mut wire, 80, challenge_issued_at_unix_nanos);
    write_u64(&mut wire, 88, challenge_expires_at_unix_nanos);
    let query_request_end = OBSERVATION_REQUEST_HEADER_BYTES + query_request_bytes.len();
    wire[OBSERVATION_REQUEST_HEADER_BYTES..query_request_end].copy_from_slice(query_request_bytes);
    wire[query_request_end..].copy_from_slice(query_response_bytes);
    let digest = request_digest(&wire)?;
    wire[OBSERVATION_REQUEST_DIGEST_OFFSET..OBSERVATION_REQUEST_HEADER_BYTES]
        .copy_from_slice(digest.as_bytes());
    Ok(wire)
}

fn encode_ack(
    outcome: RuntimeObservationAckOutcomeV1,
    request: &RuntimeObservationRequestV1,
    status_digest: Digest32,
    runtime_status_digest: Digest32,
) -> Result<[u8; OBSERVATION_ACK_BYTES], RuntimeObservationError> {
    let mut wire = [0_u8; OBSERVATION_ACK_BYTES];
    wire[..4].copy_from_slice(OBSERVATION_ACK_MAGIC);
    write_u16(&mut wire, 4, RUNTIME_OBSERVATION_PROTOCOL_VERSION);
    write_u16(
        &mut wire,
        6,
        u16::try_from(OBSERVATION_ACK_BYTES).map_err(|_| RuntimeObservationError::InvalidAck)?,
    );
    write_u32(
        &mut wire,
        8,
        u32::try_from(OBSERVATION_ACK_BYTES).map_err(|_| RuntimeObservationError::InvalidAck)?,
    );
    wire[12] = outcome as u8;
    write_u64(&mut wire, 16, request.intended_status_sequence());
    wire[24..56].copy_from_slice(status_digest.as_bytes());
    wire[56..88].copy_from_slice(runtime_status_digest.as_bytes());
    wire[88..120].copy_from_slice(request.request_digest().as_bytes());
    let digest = ack_digest(&wire)?;
    wire[OBSERVATION_ACK_DIGEST_OFFSET..].copy_from_slice(digest.as_bytes());
    Ok(wire)
}

fn bootstrap_digest(frame: &[u8]) -> Result<Digest32, RuntimeObservationError> {
    digest_frame(
        frame,
        BOOTSTRAP_DIGEST_OFFSET,
        BOOTSTRAP_HEADER_BYTES,
        BOOTSTRAP_DIGEST_DOMAIN,
    )
}

fn request_digest(frame: &[u8]) -> Result<Digest32, RuntimeObservationError> {
    digest_frame(
        frame,
        OBSERVATION_REQUEST_DIGEST_OFFSET,
        OBSERVATION_REQUEST_HEADER_BYTES,
        REQUEST_DIGEST_DOMAIN,
    )
}

fn ack_digest(frame: &[u8]) -> Result<Digest32, RuntimeObservationError> {
    digest_frame(
        frame,
        OBSERVATION_ACK_DIGEST_OFFSET,
        OBSERVATION_ACK_BYTES,
        ACK_DIGEST_DOMAIN,
    )
}

fn digest_frame(
    frame: &[u8],
    digest_start: usize,
    digest_end: usize,
    domain: &[u8],
) -> Result<Digest32, RuntimeObservationError> {
    if digest_end > frame.len() || digest_end.saturating_sub(digest_start) != 32 {
        return Err(RuntimeObservationError::InvalidRequest);
    }
    let mut canonical = frame.to_vec();
    canonical[digest_start..digest_end].fill(0);
    let mut builder = Digest32Builder::try_new(domain)?;
    builder.field_bytes(&canonical)?;
    Ok(builder.finish())
}

fn validate_absolute_socket_path(socket_path: &Path) -> Result<(), RuntimeObservationError> {
    let bytes = socket_path.as_os_str().as_bytes();
    if !socket_path.is_absolute()
        || socket_path == Path::new("/")
        || bytes.is_empty()
        || bytes.len() > MAX_UNIX_SOCKET_PATH_BYTES
        || socket_path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(RuntimeObservationError::InvalidPath);
    }
    Ok(())
}

fn validate_challenge_window(
    issued_at_unix_nanos: u64,
    expires_at_unix_nanos: u64,
) -> Result<(NonZeroU64, NonZeroU64), RuntimeObservationError> {
    let issued_at =
        NonZeroU64::new(issued_at_unix_nanos).ok_or(RuntimeObservationError::InvalidRequest)?;
    let expires_at =
        NonZeroU64::new(expires_at_unix_nanos).ok_or(RuntimeObservationError::InvalidRequest)?;
    expires_at_unix_nanos
        .checked_sub(issued_at_unix_nanos)
        .filter(|lifetime| *lifetime > 0 && *lifetime <= MAX_RUNTIME_OBSERVATION_CHALLENGE_NANOS)
        .ok_or(RuntimeObservationError::InvalidRequest)?;
    Ok((issued_at, expires_at))
}

const fn bytes_are_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

fn copy_array<const N: usize>(wire: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0_u8; N];
    output.copy_from_slice(&wire[offset..offset + N]);
    output
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

fn write_u16(wire: &mut [u8], offset: usize, value: u16) {
    wire[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(wire: &mut [u8], offset: usize, value: u32) {
    wire[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(wire: &mut [u8], offset: usize, value: u64) {
    wire[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
