//! Owner-private Unix clients for authenticated Runtime bootstrap and apply.
//!
//! Canonical request/response values, transcripts, digests, compatibility
//! checks, and protocol bounds remain exclusively owned by
//! `paraegox_runtime_contracts::reference_control`. This module adds only a
//! four-byte big-endian transport length, validates the live Unix endpoint,
//! performs one bounded exchange, and verifies the Runtime response signature.
//! It never retries or allocates request identity, nonce, signing keys, or
//! Runtime serving facts. The apply path accepts only a Controller token which
//! proves the exact PXAR was committed before send, and returns success only
//! after strict, pinned verification of the correlated canonical PXRT. EOF,
//! transport ACKs, and empty responses are never apply success.

use core::fmt;
use std::fs::{self, File, Metadata};
use std::future::Future;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
use paraegox_runtime_contracts::reference_control::{
    MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES, MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES,
    MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES, MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES,
    ReferenceApplyRequestV1, ReferenceApplyTerminalFactsV1, ReferenceApplyTerminalReceiptV1,
    ReferenceBootstrapFactsV1, ReferenceBootstrapRequestV1, ReferenceBootstrapResponseV1,
    ReferenceChannelBindingV1, ReferenceControlError, ReferenceControllerBootstrapExpectationV1,
    ed25519_control_key_fingerprint, reference_local_control_endpoint_identity_digest_v1,
    reference_runtime_peer_credentials_digest_v1,
};
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout_at};

use crate::controller_apply::PreparedControllerApplyAttemptV1;

const RUNTIME_CONTROL_SOCKET_MODE: u32 = 0o660;
const RUNTIME_CONTROL_SOCKET_DIRECTORY_MODE: u32 = 0o2750;
const LENGTH_PREFIX_BYTES: usize = size_of::<u32>();
const ED25519_SIGNATURE_BYTES: usize = 64;
const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
pub(crate) const MAX_RUNTIME_BOOTSTRAP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const MAX_RUNTIME_APPLY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Immutable signed request plus its byte-identical length-prefixed transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedRuntimeBootstrapRequest {
    request: ReferenceBootstrapRequestV1,
    transport_frame: Box<[u8]>,
}

impl PreparedRuntimeBootstrapRequest {
    /// Freezes a canonical request without parsing or reproducing its wire.
    pub(crate) fn try_new(
        request: ReferenceBootstrapRequestV1,
    ) -> Result<Self, ReferenceControlError> {
        let decoded = ReferenceBootstrapRequestV1::decode(request.canonical_wire())?;
        debug_assert_eq!(decoded, request);
        Ok(Self {
            transport_frame: length_prefix(request.canonical_wire()),
            request,
        })
    }

    /// Reconstructs the exact request and transport bytes from durable
    /// canonical request bytes. No signing or identity allocation occurs.
    pub(crate) fn try_from_canonical_request_bytes(
        canonical_request: &[u8],
    ) -> Result<Self, ReferenceControlError> {
        Self::try_new(ReferenceBootstrapRequestV1::decode(canonical_request)?)
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ReferenceBootstrapRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn transport_frame_bytes(&self) -> &[u8] {
        &self.transport_frame
    }
}

fn length_prefix(payload: &[u8]) -> Box<[u8]> {
    debug_assert!(payload.len() <= MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES);
    let payload_length = u32::try_from(payload.len())
        .expect("canonical bootstrap request bound is smaller than u32::MAX");
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.into_boxed_slice()
}

/// Expected real/effective Runtime service credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeUnixCredentials {
    uid: u32,
    gid: u32,
}

impl RuntimeUnixCredentials {
    #[must_use]
    pub(crate) const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

/// Runtime-owned socket objects exposed to the Controller group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeControlSocketAcl {
    runtime_uid: u32,
    controller_gid: u32,
}

impl RuntimeControlSocketAcl {
    #[must_use]
    pub(crate) const fn new(runtime_uid: u32, controller_gid: u32) -> Self {
        Self {
            runtime_uid,
            controller_gid,
        }
    }
}

/// Pinned Unix endpoint, target, and Runtime response principal.
///
/// The canonical channel itself is derived only after connect from the
/// revalidated live endpoint plus `SO_PEERCRED`; callers cannot provision an
/// unrelated digest and have a Runtime response trusted against it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnixRuntimeControlEndpoint {
    socket_path: PathBuf,
    socket_acl: RuntimeControlSocketAcl,
    server_credentials: RuntimeUnixCredentials,
    target: RuntimeHostId,
    runtime_principal: PrincipalRef,
}

impl UnixRuntimeControlEndpoint {
    pub(crate) fn try_new(
        socket_path: PathBuf,
        socket_acl: RuntimeControlSocketAcl,
        server_credentials: RuntimeUnixCredentials,
        target: RuntimeHostId,
        runtime_principal: PrincipalRef,
    ) -> Result<Self, RuntimeControlClientConfigurationError> {
        validate_lexical_socket_path(&socket_path)?;
        if bytes_are_zero(runtime_principal.as_bytes()) {
            return Err(RuntimeControlClientConfigurationError::InvalidRuntimePrincipal);
        }
        if bytes_are_zero(target.as_bytes()) {
            return Err(RuntimeControlClientConfigurationError::InvalidRuntimeTarget);
        }
        Ok(Self {
            socket_path,
            socket_acl,
            server_credentials,
            target,
            runtime_principal,
        })
    }

    #[must_use]
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// Exact Controller request-auth selector allowed on this client path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeBootstrapRequestAuthPin {
    controller_principal: PrincipalRef,
    key: ApplyAuthKeyRef,
}

impl RuntimeBootstrapRequestAuthPin {
    pub(crate) fn try_new(
        controller_principal: PrincipalRef,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, RuntimeControlClientConfigurationError> {
        if bytes_are_zero(controller_principal.as_bytes()) || bytes_are_zero(key.as_bytes()) {
            return Err(RuntimeControlClientConfigurationError::InvalidRequestAuthPin);
        }
        if algorithm.value() != ED25519_ALGORITHM || algorithm_version != ED25519_ALGORITHM_VERSION
        {
            return Err(RuntimeControlClientConfigurationError::UnsupportedRequestAuthProfile);
        }
        Ok(Self {
            controller_principal,
            key,
        })
    }

    fn validate(
        self,
        request: &ReferenceBootstrapRequestV1,
    ) -> Result<(), RuntimeBootstrapClientFailure> {
        let authentication = request.authentication();
        let claim = authentication.claim();
        if claim.principal() != self.controller_principal || claim.key() != self.key {
            return Err(RuntimeBootstrapClientFailure::RequestAuthPinMismatch);
        }
        if claim.algorithm().value() != ED25519_ALGORITHM
            || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
            || authentication.signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(RuntimeBootstrapClientFailure::UnsupportedRequestAuthProfile);
        }
        Ok(())
    }
}

/// Pinned Runtime response selector and Ed25519 verification key.
#[derive(Clone, Debug)]
pub(crate) struct RuntimeBootstrapResponseVerifier {
    runtime_principal: PrincipalRef,
    key: ApplyAuthKeyRef,
    verifying_key: VerifyingKey,
}

impl RuntimeBootstrapResponseVerifier {
    pub(crate) fn try_new(
        runtime_principal: PrincipalRef,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
        expected_public_key_fingerprint: Digest32,
        verifying_key: VerifyingKey,
    ) -> Result<Self, RuntimeControlClientConfigurationError> {
        if bytes_are_zero(runtime_principal.as_bytes()) || bytes_are_zero(key.as_bytes()) {
            return Err(RuntimeControlClientConfigurationError::InvalidResponseAuthPin);
        }
        if algorithm.value() != ED25519_ALGORITHM || algorithm_version != ED25519_ALGORITHM_VERSION
        {
            return Err(RuntimeControlClientConfigurationError::UnsupportedResponseAuthProfile);
        }
        if verifying_key.is_weak() {
            return Err(RuntimeControlClientConfigurationError::WeakRuntimeResponseKey);
        }
        let fingerprint = ed25519_control_key_fingerprint(&verifying_key.to_bytes())
            .map_err(RuntimeControlClientConfigurationError::ControlContract)?;
        if bytes_are_zero(expected_public_key_fingerprint.as_bytes())
            || fingerprint != expected_public_key_fingerprint
        {
            return Err(RuntimeControlClientConfigurationError::ResponseKeyFingerprintMismatch);
        }
        Ok(Self {
            runtime_principal,
            key,
            verifying_key,
        })
    }

    fn verify(
        &self,
        response: &ReferenceBootstrapResponseV1,
    ) -> Result<(), RuntimeBootstrapClientFailure> {
        if response.authentication_runtime_peer() != self.runtime_principal {
            return Err(RuntimeBootstrapClientFailure::ResponsePrincipalMismatch);
        }
        if response.authentication_key() != self.key {
            return Err(RuntimeBootstrapClientFailure::ResponseKeyMismatch);
        }
        if response.authentication_algorithm().value() != ED25519_ALGORITHM
            || response.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        {
            return Err(RuntimeBootstrapClientFailure::UnsupportedResponseAuthProfile);
        }
        let signature: [u8; ED25519_SIGNATURE_BYTES] = response
            .authentication_signature()
            .try_into()
            .map_err(|_| RuntimeBootstrapClientFailure::InvalidResponseSignature)?;
        let transcript = response
            .signing_transcript()
            .map_err(RuntimeBootstrapClientFailure::ResponseContract)?;
        self.verifying_key
            .verify_strict(transcript.as_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| RuntimeBootstrapClientFailure::InvalidResponseSignature)
    }
}

/// Optional successor checks for a previously pinned Runtime serving identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeBootstrapServingExpectation {
    Initial,
    Pinned {
        runtime_store_instance_id: [u8; 32],
        minimum_snapshot_sequence: u64,
        minimum_runtime_host_epoch: u64,
        clock_domain: ClockDomainRef,
        minimum_clock_generation: ClockGeneration,
    },
}

impl RuntimeBootstrapServingExpectation {
    pub(crate) fn try_pinned(
        runtime_store_instance_id: [u8; 32],
        minimum_snapshot_sequence: u64,
        minimum_runtime_host_epoch: u64,
        clock_domain: ClockDomainRef,
        minimum_clock_generation: ClockGeneration,
    ) -> Result<Self, RuntimeControlClientConfigurationError> {
        if bytes_are_zero(&runtime_store_instance_id)
            || minimum_snapshot_sequence == 0
            || minimum_runtime_host_epoch == 0
            || bytes_are_zero(clock_domain.as_bytes())
        {
            return Err(RuntimeControlClientConfigurationError::InvalidServingExpectation);
        }
        Ok(Self::Pinned {
            runtime_store_instance_id,
            minimum_snapshot_sequence,
            minimum_runtime_host_epoch,
            clock_domain,
            minimum_clock_generation,
        })
    }

    fn validate(
        self,
        facts: ReferenceBootstrapFactsV1,
    ) -> Result<(), RuntimeBootstrapClientFailure> {
        let Self::Pinned {
            runtime_store_instance_id,
            minimum_snapshot_sequence,
            minimum_runtime_host_epoch,
            clock_domain,
            minimum_clock_generation,
        } = self
        else {
            return Ok(());
        };
        if facts.runtime_store_instance_id() != runtime_store_instance_id {
            return Err(RuntimeBootstrapClientFailure::RuntimeStoreMismatch);
        }
        if facts.snapshot_sequence() < minimum_snapshot_sequence {
            return Err(RuntimeBootstrapClientFailure::SnapshotSequenceRegression);
        }
        if facts.runtime_host_epoch() < minimum_runtime_host_epoch {
            return Err(RuntimeBootstrapClientFailure::RuntimeHostEpochRegression);
        }
        if facts.clock_domain() != clock_domain {
            return Err(RuntimeBootstrapClientFailure::ClockDomainMismatch);
        }
        if facts.clock_generation().value() < minimum_clock_generation.value() {
            return Err(RuntimeBootstrapClientFailure::ClockGenerationRegression);
        }
        Ok(())
    }
}

/// Authenticated response whose signature, request, channel, compatibility,
/// and optional serving successor checks have all succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedRuntimeBootstrapResponse {
    response: ReferenceBootstrapResponseV1,
    facts: ReferenceBootstrapFactsV1,
    channel: ReferenceChannelBindingV1,
}

impl ValidatedRuntimeBootstrapResponse {
    #[cfg(test)]
    pub(crate) fn try_from_contract_fixture(
        response: ReferenceBootstrapResponseV1,
        facts: ReferenceBootstrapFactsV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<Self, ReferenceControlError> {
        if response.facts() != facts
            || response.authentication_channel_binding_digest() != channel.binding_digest()
            || response.authentication_runtime_peer() != channel.runtime_peer()
            || facts.target() != channel.target()
        {
            return Err(ReferenceControlError::Contract(
                paraegox_runtime_contracts::reference_control::ReferenceControlContractErrorCode::InvalidChannelEvidence,
            ));
        }
        Ok(Self {
            response,
            facts,
            channel,
        })
    }

    #[must_use]
    pub(crate) const fn response(&self) -> &ReferenceBootstrapResponseV1 {
        &self.response
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> ReferenceBootstrapFactsV1 {
        self.facts
    }

    #[must_use]
    pub(crate) const fn channel(&self) -> ReferenceChannelBindingV1 {
        self.channel
    }
}

/// One owner-private Runtime bootstrap client with a fixed total deadline.
#[derive(Clone, Debug)]
pub(crate) struct UnixRuntimeBootstrapClient {
    endpoint: UnixRuntimeControlEndpoint,
    request_auth: RuntimeBootstrapRequestAuthPin,
    response_verifier: RuntimeBootstrapResponseVerifier,
    expected_compatibility: ReferenceControllerBootstrapExpectationV1,
    serving_expectation: RuntimeBootstrapServingExpectation,
    exchange_timeout: Duration,
}

impl UnixRuntimeBootstrapClient {
    pub(crate) fn try_new(
        endpoint: UnixRuntimeControlEndpoint,
        request_auth: RuntimeBootstrapRequestAuthPin,
        response_verifier: RuntimeBootstrapResponseVerifier,
        expected_compatibility: ReferenceControllerBootstrapExpectationV1,
        serving_expectation: RuntimeBootstrapServingExpectation,
        exchange_timeout: Duration,
    ) -> Result<Self, RuntimeControlClientConfigurationError> {
        if exchange_timeout.is_zero() || exchange_timeout > MAX_RUNTIME_BOOTSTRAP_EXCHANGE_TIMEOUT {
            return Err(RuntimeControlClientConfigurationError::InvalidExchangeTimeout);
        }
        if endpoint.runtime_principal != response_verifier.runtime_principal {
            return Err(RuntimeControlClientConfigurationError::ResponsePrincipalMismatch);
        }
        if endpoint.target != expected_compatibility.target() {
            return Err(RuntimeControlClientConfigurationError::CompatibilityTargetMismatch);
        }
        Ok(Self {
            endpoint,
            request_auth,
            response_verifier,
            expected_compatibility,
            serving_expectation,
            exchange_timeout,
        })
    }

    /// Performs exactly one exchange. Errors before request writing are
    /// `NotSent`; transport failures after writing begins are `Uncertain`; a
    /// complete but invalid authenticated response is `Rejected`.
    ///
    /// This future is not cancellation-safe after polling begins. A caller
    /// that drops it after the write boundary must classify the attempt as
    /// uncertain and replay these exact prepared bytes.
    pub(crate) async fn exchange(
        &self,
        prepared: &PreparedRuntimeBootstrapRequest,
    ) -> Result<ValidatedRuntimeBootstrapResponse, RuntimeBootstrapExchangeError> {
        self.validate_request(prepared.request())
            .map_err(RuntimeBootstrapExchangeError::NotSent)?;
        let deadline = Instant::now() + self.exchange_timeout;
        let validated_endpoint = validate_endpoint_metadata(&self.endpoint)
            .map_err(RuntimeBootstrapExchangeError::NotSent)?;

        let mut stream = bounded_io(
            deadline,
            RuntimeBootstrapIoPhase::Connect,
            DeliveryState::NotSent,
            UnixStream::connect(self.endpoint.socket_path()),
        )
        .await?;
        validated_endpoint
            .revalidate(&self.endpoint)
            .map_err(RuntimeBootstrapExchangeError::NotSent)?;
        let runtime_credentials =
            validate_peer_credentials(&stream, self.endpoint.server_credentials)
                .map_err(RuntimeBootstrapExchangeError::NotSent)?;
        let channel = validated_endpoint
            .channel(&self.endpoint, runtime_credentials)
            .map_err(RuntimeBootstrapExchangeError::NotSent)?;

        bounded_io(
            deadline,
            RuntimeBootstrapIoPhase::WriteRequest,
            DeliveryState::Uncertain,
            stream.write_all(prepared.transport_frame_bytes()),
        )
        .await?;

        let mut length_bytes = [0_u8; LENGTH_PREFIX_BYTES];
        bounded_read_exact(
            deadline,
            RuntimeBootstrapIoPhase::ReadResponseLength,
            &mut stream,
            &mut length_bytes,
        )
        .await?;
        let response_length = u32::from_be_bytes(length_bytes) as usize;
        if response_length == 0 {
            return Err(RuntimeBootstrapExchangeError::Rejected(
                RuntimeBootstrapClientFailure::InvalidResponseLength,
            ));
        }
        if response_length > MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES
            || response_length > prepared.request().max_response_bytes() as usize
        {
            return Err(RuntimeBootstrapExchangeError::Rejected(
                RuntimeBootstrapClientFailure::ResponseBoundExceeded,
            ));
        }

        let mut response_bytes = vec![0_u8; response_length];
        bounded_read_exact(
            deadline,
            RuntimeBootstrapIoPhase::ReadResponse,
            &mut stream,
            &mut response_bytes,
        )
        .await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = bounded_io(
            deadline,
            RuntimeBootstrapIoPhase::ReadTrailing,
            DeliveryState::Uncertain,
            stream.read(&mut trailing),
        )
        .await?;
        if trailing_bytes != 0 {
            return Err(RuntimeBootstrapExchangeError::Rejected(
                RuntimeBootstrapClientFailure::TrailingBytes,
            ));
        }

        let response = ReferenceBootstrapResponseV1::decode(&response_bytes).map_err(|error| {
            RuntimeBootstrapExchangeError::Rejected(
                RuntimeBootstrapClientFailure::ResponseContract(error),
            )
        })?;
        self.response_verifier
            .verify(&response)
            .map_err(RuntimeBootstrapExchangeError::Rejected)?;
        let facts = response
            .validate_against_controller_expectation(
                prepared.request(),
                channel,
                &self.expected_compatibility,
            )
            .map_err(|error| {
                RuntimeBootstrapExchangeError::Rejected(
                    RuntimeBootstrapClientFailure::ResponseContract(error),
                )
            })?;
        self.serving_expectation
            .validate(facts)
            .map_err(RuntimeBootstrapExchangeError::Rejected)?;
        Ok(ValidatedRuntimeBootstrapResponse {
            response,
            facts,
            channel,
        })
    }

    fn validate_request(
        &self,
        request: &ReferenceBootstrapRequestV1,
    ) -> Result<(), RuntimeBootstrapClientFailure> {
        if request.target() != self.endpoint.target
            || request.target() != self.expected_compatibility.target()
        {
            return Err(RuntimeBootstrapClientFailure::RequestTargetMismatch);
        }
        self.request_auth.validate(request)
    }
}

/// Pinned Runtime terminal-receipt selector and Ed25519 verification key.
///
/// The expected public-key fingerprint must come from the protected Runtime
/// provisioning policy. A matching key reference alone is never sufficient.
#[derive(Clone, Debug)]
pub(crate) struct RuntimeApplyResponseVerifier {
    runtime_principal: PrincipalRef,
    key: ApplyAuthKeyRef,
    verifying_key: VerifyingKey,
}

impl RuntimeApplyResponseVerifier {
    pub(crate) fn try_new(
        runtime_principal: PrincipalRef,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
        expected_public_key_fingerprint: Digest32,
        verifying_key: VerifyingKey,
    ) -> Result<Self, RuntimeControlClientConfigurationError> {
        if bytes_are_zero(runtime_principal.as_bytes()) || bytes_are_zero(key.as_bytes()) {
            return Err(RuntimeControlClientConfigurationError::InvalidResponseAuthPin);
        }
        if algorithm.value() != ED25519_ALGORITHM || algorithm_version != ED25519_ALGORITHM_VERSION
        {
            return Err(RuntimeControlClientConfigurationError::UnsupportedResponseAuthProfile);
        }
        if verifying_key.is_weak() {
            return Err(RuntimeControlClientConfigurationError::WeakRuntimeResponseKey);
        }
        let fingerprint = ed25519_control_key_fingerprint(&verifying_key.to_bytes())
            .map_err(RuntimeControlClientConfigurationError::ControlContract)?;
        if bytes_are_zero(expected_public_key_fingerprint.as_bytes())
            || fingerprint != expected_public_key_fingerprint
        {
            return Err(RuntimeControlClientConfigurationError::ResponseKeyFingerprintMismatch);
        }
        Ok(Self {
            runtime_principal,
            key,
            verifying_key,
        })
    }

    fn verify(
        &self,
        receipt: &ReferenceApplyTerminalReceiptV1,
    ) -> Result<(), RuntimeApplyClientFailure> {
        if receipt.authentication_runtime_peer() != self.runtime_principal {
            return Err(RuntimeApplyClientFailure::ResponsePrincipalMismatch);
        }
        if receipt.authentication_key() != self.key {
            return Err(RuntimeApplyClientFailure::ResponseKeyMismatch);
        }
        if receipt.authentication_algorithm().value() != ED25519_ALGORITHM
            || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        {
            return Err(RuntimeApplyClientFailure::UnsupportedResponseAuthProfile);
        }
        let signature: [u8; ED25519_SIGNATURE_BYTES] = receipt
            .authentication_signature()
            .try_into()
            .map_err(|_| RuntimeApplyClientFailure::InvalidResponseSignature)?;
        let transcript = receipt
            .signing_transcript()
            .map_err(RuntimeApplyClientFailure::ResponseContract)?;
        self.verifying_key
            .verify_strict(transcript.as_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| RuntimeApplyClientFailure::InvalidResponseSignature)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeApplyResponseExpectation {
    channel: ReferenceChannelBindingV1,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

/// Canonical terminal receipt after signer, exact PXAR correlation, and the
/// request-time channel have all been validated. The independently validated
/// current transport channel is retained as connection evidence only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedRuntimeApplyTerminalReceipt {
    receipt: ReferenceApplyTerminalReceiptV1,
    facts: ReferenceApplyTerminalFactsV1,
    request_time_channel: ReferenceChannelBindingV1,
    current_channel: ReferenceChannelBindingV1,
}

impl ValidatedRuntimeApplyTerminalReceipt {
    #[cfg(test)]
    pub(crate) fn try_from_contract_fixture(
        receipt: ReferenceApplyTerminalReceiptV1,
        request_time_channel: ReferenceChannelBindingV1,
        current_channel: ReferenceChannelBindingV1,
    ) -> Result<Self, ReferenceControlError> {
        if receipt.target() != request_time_channel.target()
            || receipt.target() != current_channel.target()
            || receipt.authentication_runtime_peer() != request_time_channel.runtime_peer()
            || receipt.authentication_runtime_peer() != current_channel.runtime_peer()
            || receipt.authentication_channel_binding_digest()
                != request_time_channel.binding_digest()
        {
            return Err(ReferenceControlError::Contract(
                paraegox_runtime_contracts::reference_control::ReferenceControlContractErrorCode::InvalidChannelEvidence,
            ));
        }
        let facts = receipt.facts();
        Ok(Self {
            receipt,
            facts,
            request_time_channel,
            current_channel,
        })
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &ReferenceApplyTerminalReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> ReferenceApplyTerminalFactsV1 {
        self.facts
    }

    #[must_use]
    pub(crate) const fn request_time_channel(&self) -> ReferenceChannelBindingV1 {
        self.request_time_channel
    }

    #[must_use]
    pub(crate) const fn current_channel(&self) -> ReferenceChannelBindingV1 {
        self.current_channel
    }
}

/// Direct PXAR-to-PXRT Runtime client. It never retries and never writes the
/// Controller journal; the caller owns durable receipt commit after success.
#[derive(Clone, Debug)]
pub(crate) struct UnixRuntimeApplyClient {
    endpoint: UnixRuntimeControlEndpoint,
    response_verifier: RuntimeApplyResponseVerifier,
    exchange_timeout: Duration,
}

impl UnixRuntimeApplyClient {
    pub(crate) fn try_new(
        endpoint: UnixRuntimeControlEndpoint,
        response_verifier: RuntimeApplyResponseVerifier,
        exchange_timeout: Duration,
    ) -> Result<Self, RuntimeControlClientConfigurationError> {
        if exchange_timeout.is_zero() || exchange_timeout > MAX_RUNTIME_APPLY_EXCHANGE_TIMEOUT {
            return Err(RuntimeControlClientConfigurationError::InvalidExchangeTimeout);
        }
        if endpoint.runtime_principal != response_verifier.runtime_principal {
            return Err(RuntimeControlClientConfigurationError::ResponsePrincipalMismatch);
        }
        Ok(Self {
            endpoint,
            response_verifier,
            exchange_timeout,
        })
    }

    /// Sends only the exact PXAR already committed by the Controller. Every
    /// failure from the first write onward is `Uncertain`, including a complete
    /// but invalid response, because Runtime execution may already have begun.
    ///
    /// This future is not cancellation-safe after polling begins. A dropped
    /// future must be classified as uncertain unless the caller independently
    /// proves it had not crossed the write boundary.
    pub(crate) async fn exchange(
        &self,
        prepared: &PreparedControllerApplyAttemptV1,
    ) -> Result<ValidatedRuntimeApplyTerminalReceipt, RuntimeApplyExchangeError> {
        let expectation = prepared.runtime_response_expectation();
        self.exchange_request(
            prepared.request(),
            RuntimeApplyResponseExpectation {
                channel: expectation.channel(),
                key: expectation.key(),
                algorithm: expectation.algorithm(),
                algorithm_version: expectation.algorithm_version(),
            },
        )
        .await
    }

    async fn exchange_request(
        &self,
        request: &ReferenceApplyRequestV1,
        expectation: RuntimeApplyResponseExpectation,
    ) -> Result<ValidatedRuntimeApplyTerminalReceipt, RuntimeApplyExchangeError> {
        self.validate_request(request, expectation)
            .map_err(RuntimeApplyExchangeError::NotSent)?;
        let transport_frame = length_prefix_apply(request.canonical_wire());
        let deadline = Instant::now() + self.exchange_timeout;
        let validated_endpoint = validate_endpoint_metadata(&self.endpoint)
            .map_err(RuntimeApplyClientFailure::Endpoint)
            .map_err(RuntimeApplyExchangeError::NotSent)?;

        let mut stream = bounded_apply_io(
            deadline,
            RuntimeApplyIoPhase::Connect,
            ApplyDeliveryState::NotSent,
            UnixStream::connect(self.endpoint.socket_path()),
        )
        .await?;
        validated_endpoint
            .revalidate(&self.endpoint)
            .map_err(RuntimeApplyClientFailure::Endpoint)
            .map_err(RuntimeApplyExchangeError::NotSent)?;
        let runtime_credentials =
            validate_peer_credentials(&stream, self.endpoint.server_credentials)
                .map_err(RuntimeApplyClientFailure::Endpoint)
                .map_err(RuntimeApplyExchangeError::NotSent)?;
        let current_channel = validated_endpoint
            .channel(&self.endpoint, runtime_credentials)
            .map_err(RuntimeApplyClientFailure::Endpoint)
            .map_err(RuntimeApplyExchangeError::NotSent)?;

        bounded_apply_io(
            deadline,
            RuntimeApplyIoPhase::WriteRequest,
            ApplyDeliveryState::Uncertain,
            stream.write_all(&transport_frame),
        )
        .await?;

        let mut length_bytes = [0_u8; LENGTH_PREFIX_BYTES];
        bounded_apply_read_exact(
            deadline,
            RuntimeApplyIoPhase::ReadResponseLength,
            &mut stream,
            &mut length_bytes,
        )
        .await?;
        let response_length = u32::from_be_bytes(length_bytes) as usize;
        if response_length == 0 {
            return Err(RuntimeApplyExchangeError::Uncertain(
                RuntimeApplyClientFailure::InvalidResponseLength,
            ));
        }
        if response_length > MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES {
            return Err(RuntimeApplyExchangeError::Uncertain(
                RuntimeApplyClientFailure::ResponseBoundExceeded,
            ));
        }

        let mut response_bytes = vec![0_u8; response_length];
        bounded_apply_read_exact(
            deadline,
            RuntimeApplyIoPhase::ReadResponse,
            &mut stream,
            &mut response_bytes,
        )
        .await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = bounded_apply_io(
            deadline,
            RuntimeApplyIoPhase::ReadTrailing,
            ApplyDeliveryState::Uncertain,
            stream.read(&mut trailing),
        )
        .await?;
        if trailing_bytes != 0 {
            return Err(RuntimeApplyExchangeError::Uncertain(
                RuntimeApplyClientFailure::TrailingBytes,
            ));
        }

        let receipt =
            ReferenceApplyTerminalReceiptV1::decode(&response_bytes).map_err(|error| {
                RuntimeApplyExchangeError::Uncertain(RuntimeApplyClientFailure::ResponseContract(
                    error,
                ))
            })?;
        self.response_verifier
            .verify(&receipt)
            .map_err(RuntimeApplyExchangeError::Uncertain)?;
        let facts = receipt
            .validate_against_request(request, expectation.channel)
            .map_err(|error| {
                RuntimeApplyExchangeError::Uncertain(RuntimeApplyClientFailure::ResponseContract(
                    error,
                ))
            })?;
        Ok(ValidatedRuntimeApplyTerminalReceipt {
            receipt,
            facts,
            request_time_channel: expectation.channel,
            current_channel,
        })
    }

    fn validate_request(
        &self,
        request: &ReferenceApplyRequestV1,
        expectation: RuntimeApplyResponseExpectation,
    ) -> Result<(), RuntimeApplyClientFailure> {
        if request.canonical_wire().len() > MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES {
            return Err(RuntimeApplyClientFailure::RequestBoundExceeded);
        }
        if request.target() != self.endpoint.target {
            return Err(RuntimeApplyClientFailure::RequestTargetMismatch);
        }
        if expectation.channel.target() != request.target() {
            return Err(RuntimeApplyClientFailure::RequestTimeChannelTargetMismatch);
        }
        if expectation.channel.runtime_peer() != self.response_verifier.runtime_principal {
            return Err(RuntimeApplyClientFailure::RequestTimeChannelPrincipalMismatch);
        }
        if expectation.key != self.response_verifier.key {
            return Err(RuntimeApplyClientFailure::ResponseKeyMismatch);
        }
        if expectation.algorithm.value() != ED25519_ALGORITHM
            || expectation.algorithm_version != ED25519_ALGORITHM_VERSION
        {
            return Err(RuntimeApplyClientFailure::UnsupportedResponseAuthProfile);
        }
        Ok(())
    }
}

fn length_prefix_apply(payload: &[u8]) -> Box<[u8]> {
    debug_assert!(payload.len() <= MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES);
    let payload_length = u32::try_from(payload.len())
        .expect("canonical apply request bound is smaller than u32::MAX");
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.into_boxed_slice()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeControlClientConfigurationError {
    RelativeSocketPath,
    NonCanonicalSocketPath,
    InvalidExchangeTimeout,
    InvalidRuntimePrincipal,
    InvalidRuntimeTarget,
    InvalidRequestAuthPin,
    UnsupportedRequestAuthProfile,
    InvalidResponseAuthPin,
    UnsupportedResponseAuthProfile,
    WeakRuntimeResponseKey,
    ResponseKeyFingerprintMismatch,
    ResponsePrincipalMismatch,
    CompatibilityTargetMismatch,
    InvalidServingExpectation,
    ControlContract(ReferenceControlError),
}

impl fmt::Display for RuntimeControlClientConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Runtime control client configuration rejected: {self:?}"
        )
    }
}

impl std::error::Error for RuntimeControlClientConfigurationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeBootstrapExchangeError {
    NotSent(RuntimeBootstrapClientFailure),
    Uncertain(RuntimeBootstrapClientFailure),
    Rejected(RuntimeBootstrapClientFailure),
}

impl RuntimeBootstrapExchangeError {
    #[must_use]
    pub(crate) const fn failure(self) -> RuntimeBootstrapClientFailure {
        match self {
            Self::NotSent(failure) | Self::Uncertain(failure) | Self::Rejected(failure) => failure,
        }
    }
}

impl fmt::Display for RuntimeBootstrapExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime bootstrap exchange failed: {self:?}")
    }
}

impl std::error::Error for RuntimeBootstrapExchangeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeBootstrapIoPhase {
    Connect,
    WriteRequest,
    ReadResponseLength,
    ReadResponse,
    ReadTrailing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeBootstrapClientFailure {
    RequestTargetMismatch,
    RequestAuthPinMismatch,
    UnsupportedRequestAuthProfile,
    SocketAncestorMetadataUnavailable,
    InvalidSocketAncestor,
    UntrustedSocketAncestor,
    SocketDirectoryMetadataUnavailable,
    InvalidSocketDirectoryType,
    InvalidSocketDirectoryAcl,
    SocketDirectoryOpenFailed,
    SocketMetadataUnavailable,
    InvalidSocketType,
    InvalidSocketAcl,
    SocketIdentityChanged,
    PeerCredentialsUnavailable,
    PeerCredentialsMismatch,
    PeerProcessIdentityUnavailable,
    ChannelEvidenceContract(ReferenceControlError),
    DeadlineExceeded(RuntimeBootstrapIoPhase),
    Io(RuntimeBootstrapIoPhase),
    TruncatedResponse,
    InvalidResponseLength,
    ResponseBoundExceeded,
    TrailingBytes,
    ResponseContract(ReferenceControlError),
    ResponsePrincipalMismatch,
    ResponseKeyMismatch,
    UnsupportedResponseAuthProfile,
    InvalidResponseSignature,
    RuntimeStoreMismatch,
    SnapshotSequenceRegression,
    RuntimeHostEpochRegression,
    ClockDomainMismatch,
    ClockGenerationRegression,
}

impl fmt::Display for RuntimeBootstrapClientFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// Apply delivery classification. There is intentionally no post-send
/// `Rejected` state: even an invalid response cannot prove the PXAR was not
/// executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeApplyExchangeError {
    NotSent(RuntimeApplyClientFailure),
    Uncertain(RuntimeApplyClientFailure),
}

impl RuntimeApplyExchangeError {
    #[must_use]
    pub(crate) const fn failure(self) -> RuntimeApplyClientFailure {
        match self {
            Self::NotSent(failure) | Self::Uncertain(failure) => failure,
        }
    }
}

impl fmt::Display for RuntimeApplyExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime apply exchange failed: {self:?}")
    }
}

impl std::error::Error for RuntimeApplyExchangeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeApplyIoPhase {
    Connect,
    WriteRequest,
    ReadResponseLength,
    ReadResponse,
    ReadTrailing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeApplyClientFailure {
    RequestBoundExceeded,
    RequestTargetMismatch,
    RequestTimeChannelTargetMismatch,
    RequestTimeChannelPrincipalMismatch,
    Endpoint(RuntimeBootstrapClientFailure),
    DeadlineExceeded(RuntimeApplyIoPhase),
    Io(RuntimeApplyIoPhase),
    TruncatedResponse,
    InvalidResponseLength,
    ResponseBoundExceeded,
    TrailingBytes,
    ResponseContract(ReferenceControlError),
    ResponsePrincipalMismatch,
    ResponseKeyMismatch,
    UnsupportedResponseAuthProfile,
    InvalidResponseSignature,
}

impl fmt::Display for RuntimeApplyClientFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyDeliveryState {
    NotSent,
    Uncertain,
}

impl ApplyDeliveryState {
    const fn error(self, failure: RuntimeApplyClientFailure) -> RuntimeApplyExchangeError {
        match self {
            Self::NotSent => RuntimeApplyExchangeError::NotSent(failure),
            Self::Uncertain => RuntimeApplyExchangeError::Uncertain(failure),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryState {
    NotSent,
    Uncertain,
}

impl DeliveryState {
    const fn error(self, failure: RuntimeBootstrapClientFailure) -> RuntimeBootstrapExchangeError {
        match self {
            Self::NotSent => RuntimeBootstrapExchangeError::NotSent(failure),
            Self::Uncertain => RuntimeBootstrapExchangeError::Uncertain(failure),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct ValidatedEndpoint {
    socket_directory: File,
    ancestor_identities: Box<[FileIdentity]>,
    directory_identity: FileIdentity,
    socket_identity: FileIdentity,
    endpoint_identity_digest: Digest32,
}

impl ValidatedEndpoint {
    fn revalidate(
        &self,
        endpoint: &UnixRuntimeControlEndpoint,
    ) -> Result<(), RuntimeBootstrapClientFailure> {
        let socket_directory_path = endpoint
            .socket_path()
            .parent()
            .ok_or(RuntimeBootstrapClientFailure::InvalidSocketAncestor)?;
        let ancestor_identities = validate_trusted_socket_ancestors(
            socket_directory_path,
            endpoint.socket_acl.runtime_uid,
        )?;
        if ancestor_identities != self.ancestor_identities {
            return Err(RuntimeBootstrapClientFailure::SocketIdentityChanged);
        }

        let open_metadata = self
            .socket_directory
            .metadata()
            .map_err(|_| RuntimeBootstrapClientFailure::SocketDirectoryMetadataUnavailable)?;
        validate_socket_directory_metadata(&open_metadata, endpoint.socket_acl)?;
        let path_metadata = fs::symlink_metadata(socket_directory_path)
            .map_err(|_| RuntimeBootstrapClientFailure::SocketDirectoryMetadataUnavailable)?;
        validate_socket_directory_metadata(&path_metadata, endpoint.socket_acl)?;
        if FileIdentity::from_metadata(&open_metadata) != self.directory_identity
            || FileIdentity::from_metadata(&path_metadata) != self.directory_identity
        {
            return Err(RuntimeBootstrapClientFailure::SocketIdentityChanged);
        }
        let live_socket = validate_socket_metadata(endpoint)?;
        if live_socket.identity != self.socket_identity
            || live_socket.endpoint_identity_digest != self.endpoint_identity_digest
        {
            return Err(RuntimeBootstrapClientFailure::SocketIdentityChanged);
        }
        Ok(())
    }

    fn channel(
        &self,
        endpoint: &UnixRuntimeControlEndpoint,
        runtime_credentials: ObservedRuntimePeerCredentials,
    ) -> Result<ReferenceChannelBindingV1, RuntimeBootstrapClientFailure> {
        let peer_credentials_digest = reference_runtime_peer_credentials_digest_v1(
            runtime_credentials.uid,
            runtime_credentials.gid,
            runtime_credentials.pid,
        )
        .map_err(RuntimeBootstrapClientFailure::ChannelEvidenceContract)?;
        ReferenceChannelBindingV1::try_new(
            endpoint.target,
            endpoint.runtime_principal,
            self.endpoint_identity_digest,
            peer_credentials_digest,
        )
        .map_err(RuntimeBootstrapClientFailure::ChannelEvidenceContract)
    }
}

fn validate_lexical_socket_path(path: &Path) -> Result<(), RuntimeControlClientConfigurationError> {
    if !path.is_absolute() {
        return Err(RuntimeControlClientConfigurationError::RelativeSocketPath);
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() <= 1
        || bytes.first() != Some(&b'/')
        || bytes.last() == Some(&b'/')
        || bytes.contains(&0)
        || bytes.windows(2).any(|window| window == b"//")
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
    {
        return Err(RuntimeControlClientConfigurationError::NonCanonicalSocketPath);
    }
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => normal_components += 1,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(RuntimeControlClientConfigurationError::NonCanonicalSocketPath);
            }
        }
    }
    if normal_components == 0 || path.parent().is_none() || path.file_name().is_none() {
        return Err(RuntimeControlClientConfigurationError::NonCanonicalSocketPath);
    }
    Ok(())
}

fn validate_endpoint_metadata(
    endpoint: &UnixRuntimeControlEndpoint,
) -> Result<ValidatedEndpoint, RuntimeBootstrapClientFailure> {
    let socket_directory_path = endpoint
        .socket_path()
        .parent()
        .ok_or(RuntimeBootstrapClientFailure::InvalidSocketAncestor)?;
    let ancestor_identities =
        validate_trusted_socket_ancestors(socket_directory_path, endpoint.socket_acl.runtime_uid)?;
    let before = fs::symlink_metadata(socket_directory_path)
        .map_err(|_| RuntimeBootstrapClientFailure::SocketDirectoryMetadataUnavailable)?;
    validate_socket_directory_metadata(&before, endpoint.socket_acl)?;
    let directory_identity = FileIdentity::from_metadata(&before);

    let owned = open(
        socket_directory_path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| RuntimeBootstrapClientFailure::SocketDirectoryOpenFailed)?;
    let socket_directory = File::from(owned);
    let open_metadata = socket_directory
        .metadata()
        .map_err(|_| RuntimeBootstrapClientFailure::SocketDirectoryMetadataUnavailable)?;
    validate_socket_directory_metadata(&open_metadata, endpoint.socket_acl)?;
    let path_metadata = fs::symlink_metadata(socket_directory_path)
        .map_err(|_| RuntimeBootstrapClientFailure::SocketDirectoryMetadataUnavailable)?;
    validate_socket_directory_metadata(&path_metadata, endpoint.socket_acl)?;
    if FileIdentity::from_metadata(&open_metadata) != directory_identity
        || FileIdentity::from_metadata(&path_metadata) != directory_identity
    {
        return Err(RuntimeBootstrapClientFailure::SocketIdentityChanged);
    }

    let socket = validate_socket_metadata(endpoint)?;
    Ok(ValidatedEndpoint {
        socket_directory,
        ancestor_identities,
        directory_identity,
        socket_identity: socket.identity,
        endpoint_identity_digest: socket.endpoint_identity_digest,
    })
}

fn validate_trusted_socket_ancestors(
    socket_directory_path: &Path,
    runtime_uid: u32,
) -> Result<Box<[FileIdentity]>, RuntimeBootstrapClientFailure> {
    let parent = socket_directory_path
        .parent()
        .ok_or(RuntimeBootstrapClientFailure::InvalidSocketAncestor)?;
    let mut current = PathBuf::new();
    let mut identities = Vec::new();
    for component in parent.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(RuntimeBootstrapClientFailure::InvalidSocketAncestor);
            }
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| RuntimeBootstrapClientFailure::SocketAncestorMetadataUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(RuntimeBootstrapClientFailure::InvalidSocketAncestor);
        }
        let owner_uid = metadata.uid();
        let mode = metadata.mode() & 0o7777;
        let root_owned_sticky = owner_uid == 0 && mode & 0o1000 != 0;
        let owner_is_trusted = owner_uid == 0 || owner_uid == runtime_uid;
        if !owner_is_trusted || (mode & 0o022 != 0 && !root_owned_sticky) {
            return Err(RuntimeBootstrapClientFailure::UntrustedSocketAncestor);
        }
        identities.push(FileIdentity::from_metadata(&metadata));
    }
    Ok(identities.into_boxed_slice())
}

fn validate_socket_directory_metadata(
    metadata: &Metadata,
    expected: RuntimeControlSocketAcl,
) -> Result<(), RuntimeBootstrapClientFailure> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(RuntimeBootstrapClientFailure::InvalidSocketDirectoryType);
    }
    if metadata.nlink() == 0
        || metadata.uid() != expected.runtime_uid
        || metadata.gid() != expected.controller_gid
        || metadata.mode() & 0o7777 != RUNTIME_CONTROL_SOCKET_DIRECTORY_MODE
    {
        return Err(RuntimeBootstrapClientFailure::InvalidSocketDirectoryAcl);
    }
    Ok(())
}

fn validate_socket_metadata(
    endpoint: &UnixRuntimeControlEndpoint,
) -> Result<ValidatedSocketIdentity, RuntimeBootstrapClientFailure> {
    let metadata = fs::symlink_metadata(endpoint.socket_path())
        .map_err(|_| RuntimeBootstrapClientFailure::SocketMetadataUnavailable)?;
    if !metadata.file_type().is_socket() {
        return Err(RuntimeBootstrapClientFailure::InvalidSocketType);
    }
    if metadata.nlink() != 1
        || metadata.uid() != endpoint.socket_acl.runtime_uid
        || metadata.gid() != endpoint.socket_acl.controller_gid
        || metadata.mode() & 0o7777 != RUNTIME_CONTROL_SOCKET_MODE
    {
        return Err(RuntimeBootstrapClientFailure::InvalidSocketAcl);
    }
    let endpoint_identity_digest = reference_local_control_endpoint_identity_digest_v1(
        endpoint.socket_path().as_os_str().as_bytes(),
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode() & 0o7777,
    )
    .map_err(RuntimeBootstrapClientFailure::ChannelEvidenceContract)?;
    Ok(ValidatedSocketIdentity {
        identity: FileIdentity::from_metadata(&metadata),
        endpoint_identity_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedSocketIdentity {
    identity: FileIdentity,
    endpoint_identity_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedRuntimePeerCredentials {
    uid: u32,
    gid: u32,
    pid: u64,
}

fn validate_peer_credentials(
    stream: &UnixStream,
    expected: RuntimeUnixCredentials,
) -> Result<ObservedRuntimePeerCredentials, RuntimeBootstrapClientFailure> {
    let credentials = stream
        .peer_cred()
        .map_err(|_| RuntimeBootstrapClientFailure::PeerCredentialsUnavailable)?;
    if credentials.uid() != expected.uid || credentials.gid() != expected.gid {
        return Err(RuntimeBootstrapClientFailure::PeerCredentialsMismatch);
    }
    let pid = credentials
        .pid()
        .and_then(|pid| u64::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or(RuntimeBootstrapClientFailure::PeerProcessIdentityUnavailable)?;
    Ok(ObservedRuntimePeerCredentials {
        uid: credentials.uid(),
        gid: credentials.gid(),
        pid,
    })
}

async fn bounded_io<Output, Operation>(
    deadline: Instant,
    phase: RuntimeBootstrapIoPhase,
    delivery: DeliveryState,
    operation: Operation,
) -> Result<Output, RuntimeBootstrapExchangeError>
where
    Operation: Future<Output = io::Result<Output>>,
{
    timeout_at(deadline, operation)
        .await
        .map_err(|_| delivery.error(RuntimeBootstrapClientFailure::DeadlineExceeded(phase)))?
        .map_err(|_| delivery.error(RuntimeBootstrapClientFailure::Io(phase)))
}

async fn bounded_read_exact(
    deadline: Instant,
    phase: RuntimeBootstrapIoPhase,
    stream: &mut UnixStream,
    output: &mut [u8],
) -> Result<(), RuntimeBootstrapExchangeError> {
    match timeout_at(deadline, stream.read_exact(output)).await {
        Err(_) => Err(RuntimeBootstrapExchangeError::Uncertain(
            RuntimeBootstrapClientFailure::DeadlineExceeded(phase),
        )),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(RuntimeBootstrapExchangeError::Uncertain(
                RuntimeBootstrapClientFailure::TruncatedResponse,
            ))
        }
        Ok(Err(_)) => Err(RuntimeBootstrapExchangeError::Uncertain(
            RuntimeBootstrapClientFailure::Io(phase),
        )),
        Ok(Ok(_)) => Ok(()),
    }
}

async fn bounded_apply_io<Output, Operation>(
    deadline: Instant,
    phase: RuntimeApplyIoPhase,
    delivery: ApplyDeliveryState,
    operation: Operation,
) -> Result<Output, RuntimeApplyExchangeError>
where
    Operation: Future<Output = io::Result<Output>>,
{
    timeout_at(deadline, operation)
        .await
        .map_err(|_| delivery.error(RuntimeApplyClientFailure::DeadlineExceeded(phase)))?
        .map_err(|_| delivery.error(RuntimeApplyClientFailure::Io(phase)))
}

async fn bounded_apply_read_exact(
    deadline: Instant,
    phase: RuntimeApplyIoPhase,
    stream: &mut UnixStream,
    output: &mut [u8],
) -> Result<(), RuntimeApplyExchangeError> {
    match timeout_at(deadline, stream.read_exact(output)).await {
        Err(_) => Err(RuntimeApplyExchangeError::Uncertain(
            RuntimeApplyClientFailure::DeadlineExceeded(phase),
        )),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => Err(
            RuntimeApplyExchangeError::Uncertain(RuntimeApplyClientFailure::TruncatedResponse),
        ),
        Ok(Err(_)) => Err(RuntimeApplyExchangeError::Uncertain(
            RuntimeApplyClientFailure::Io(phase),
        )),
        Ok(Ok(_)) => Ok(()),
    }
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::Future;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
        RuntimeApplyControl, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
        TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };
    use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};
    use paraegox_runtime_contracts::installation::{
        InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
        generate_build_descriptor, generate_manifest,
    };
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef,
    };
    use paraegox_runtime_contracts::reference_control::{
        MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES, MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES,
        ReferenceAdmissionPolicyFingerprintV1, ReferenceAdmissionPolicyInputV1,
        ReferenceApplyRequestDraftV1, ReferenceApplyRequestV1, ReferenceApplyTerminalFactsV1,
        ReferenceApplyTerminalHeadV1, ReferenceApplyTerminalLifecycleEffectV1,
        ReferenceApplyTerminalOutcomeV1, ReferenceApplyTerminalReceiptAuthClaimV1,
        ReferenceApplyTerminalReceiptDraftV1, ReferenceApplyTerminalReceiptV1,
        ReferenceBootstrapCompatibilityV1, ReferenceBootstrapFactsV1,
        ReferenceBootstrapRequestDraftV1, ReferenceBootstrapRequestIdV1,
        ReferenceBootstrapResponseAuthClaimV1, ReferenceBootstrapResponseDraftV1,
        ReferenceBootstrapResponseV1, ReferenceBootstrapServingIdentityV1,
        ReferenceBootstrapStateV1, ReferenceChannelBindingV1,
        ReferenceControllerBootstrapExpectationV1, ReferenceTargetExecutionPlanV4,
        ed25519_control_key_fingerprint, reference_admission_policy_fingerprint_v1,
        reference_local_control_endpoint_identity_digest_v1,
        reference_runtime_peer_credentials_digest_v1,
    };
    use paraegox_runtime_contracts::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::runtime::Builder as RuntimeBuilder;

    use super::{
        PreparedRuntimeBootstrapRequest, RUNTIME_CONTROL_SOCKET_DIRECTORY_MODE,
        RUNTIME_CONTROL_SOCKET_MODE, RuntimeApplyClientFailure, RuntimeApplyExchangeError,
        RuntimeApplyIoPhase, RuntimeApplyResponseExpectation, RuntimeApplyResponseVerifier,
        RuntimeBootstrapClientFailure, RuntimeBootstrapExchangeError,
        RuntimeBootstrapRequestAuthPin, RuntimeBootstrapResponseVerifier,
        RuntimeBootstrapServingExpectation, RuntimeControlClientConfigurationError,
        RuntimeControlSocketAcl, RuntimeUnixCredentials, UnixRuntimeApplyClient,
        UnixRuntimeBootstrapClient, UnixRuntimeControlEndpoint,
        ValidatedRuntimeApplyTerminalReceipt,
    };

    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x11; 16]);
    const SCOPE: SourceScopeRef = SourceScopeRef::from_bytes([0x22; 16]);
    const CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x31; 16]);
    const CONTROLLER_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x32; 16]);
    const RUNTIME_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x41; 16]);
    const RESPONSE_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x42; 16]);
    const STORE: [u8; 32] = [0x51; 32];
    const CLOCK_DOMAIN: ClockDomainRef = ClockDomainRef::from_bytes([0x52; 16]);
    const CONTROLLER_SEED: [u8; 32] = [0x61; 32];
    const RUNTIME_SEED: [u8; 32] = [0x62; 32];

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct FakeRuntimeSocket {
        root: PathBuf,
        directory: PathBuf,
        path: PathBuf,
    }

    impl FakeRuntimeSocket {
        fn new() -> Self {
            for _ in 0..128 {
                let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let fixture_root = std::env::temp_dir()
                    .canonicalize()
                    .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
                let root = fixture_root.join(format!("pxrc-{}-{sequence}", std::process::id()));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                            .unwrap_or_else(|error| panic!("fake root chmod failed: {error}"));
                        let directory = root.join("run");
                        fs::create_dir(&directory).unwrap_or_else(|error| {
                            panic!("fake socket directory failed: {error}")
                        });
                        fs::set_permissions(
                            &directory,
                            fs::Permissions::from_mode(RUNTIME_CONTROL_SOCKET_DIRECTORY_MODE),
                        )
                        .unwrap_or_else(|error| {
                            panic!("fake socket directory chmod failed: {error}")
                        });
                        let path = directory.join("r.sock");
                        return Self {
                            root,
                            directory,
                            path,
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("fake socket directory failed: {error}"),
                }
            }
            panic!("could not allocate a unique fake Runtime socket directory")
        }

        fn bind(&self) -> UnixListener {
            let listener = UnixListener::bind(&self.path)
                .unwrap_or_else(|error| panic!("fake Runtime bind failed: {error}"));
            fs::set_permissions(
                &self.path,
                fs::Permissions::from_mode(RUNTIME_CONTROL_SOCKET_MODE),
            )
            .unwrap_or_else(|error| panic!("fake socket chmod failed: {error}"));
            listener
        }

        fn endpoint(&self, expected_server: RuntimeUnixCredentials) -> UnixRuntimeControlEndpoint {
            let metadata = fs::symlink_metadata(&self.directory)
                .unwrap_or_else(|error| panic!("fake directory metadata failed: {error}"));
            UnixRuntimeControlEndpoint::try_new(
                self.path.clone(),
                RuntimeControlSocketAcl::new(metadata.uid(), metadata.gid()),
                expected_server,
                TARGET,
                RUNTIME_PRINCIPAL,
            )
            .unwrap_or_else(|error| panic!("fake endpoint failed: {error}"))
        }
    }

    impl Drop for FakeRuntimeSocket {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn run_async(test: impl Future<Output = ()>) {
        RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap_or_else(|error| panic!("test runtime failed: {error}"))
            .block_on(test);
    }

    fn current_credentials() -> RuntimeUnixCredentials {
        RuntimeUnixCredentials::new(
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
    }

    fn live_channel(socket: &FakeRuntimeSocket) -> ReferenceChannelBindingV1 {
        let metadata = fs::symlink_metadata(&socket.path)
            .unwrap_or_else(|error| panic!("socket metadata failed: {error}"));
        let endpoint_digest = reference_local_control_endpoint_identity_digest_v1(
            socket.path.as_os_str().as_bytes(),
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o7777,
        )
        .unwrap_or_else(|error| panic!("endpoint digest failed: {error}"));
        let credentials = current_credentials();
        let peer_digest = reference_runtime_peer_credentials_digest_v1(
            credentials.uid,
            credentials.gid,
            u64::from(std::process::id()),
        )
        .unwrap_or_else(|error| panic!("peer digest failed: {error}"));
        ReferenceChannelBindingV1::try_new(TARGET, RUNTIME_PRINCIPAL, endpoint_digest, peer_digest)
            .unwrap_or_else(|error| panic!("channel binding failed: {error}"))
    }

    fn unrelated_channel() -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            Digest32::from_bytes([0x73; 32]),
            Digest32::from_bytes([0x74; 32]),
        )
        .unwrap_or_else(|error| panic!("unrelated channel failed: {error}"))
    }

    fn compiled_facts() -> RuntimeCompiledInstallationFactsV1 {
        RuntimeCompiledInstallationFactsV1::try_new(
            [0x81; 32],
            CardDefinitionRef::from_bytes([0x82; 16]),
            CardImplementationRef::from_bytes([0x83; 16]),
            [0x84; 16],
            Digest32::from_bytes([0x85; 32]),
            Digest32::from_bytes([0x86; 32]),
        )
        .unwrap_or_else(|error| panic!("compiled facts failed: {error}"))
    }

    fn compatibility(admission_byte: u8) -> ReferenceBootstrapCompatibilityV1 {
        let compiled = compiled_facts();
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x87; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .unwrap_or_else(|error| panic!("artifact observation failed: {error}"));
        let descriptor = generate_build_descriptor(&artifact, compiled)
            .unwrap_or_else(|error| panic!("descriptor generation failed: {error}"));
        let installation = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            TARGET,
            &artifact,
            compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));
        ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            &installation,
            compiled,
            admission_policy(admission_byte).digest(),
        )
        .unwrap_or_else(|error| panic!("bootstrap compatibility failed: {error}"))
    }

    fn controller_expectation(admission_byte: u8) -> ReferenceControllerBootstrapExpectationV1 {
        let compiled = compiled_facts();
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x87; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .unwrap_or_else(|error| panic!("artifact observation failed: {error}"));
        let descriptor = generate_build_descriptor(&artifact, compiled)
            .unwrap_or_else(|error| panic!("descriptor generation failed: {error}"));
        let installation = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            TARGET,
            &artifact,
            compiled,
        )
        .unwrap_or_else(|error| panic!("manifest generation failed: {error}"));
        let ingress = installation
            .immutable_manifest_ingress()
            .unwrap_or_else(|error| panic!("manifest ingress failed: {error}"));
        ReferenceControllerBootstrapExpectationV1::try_from_verified_manifest(
            &ingress,
            admission_policy(admission_byte),
        )
        .unwrap_or_else(|error| panic!("Controller expectation failed: {error}"))
    }

    fn admission_policy(seed: u8) -> ReferenceAdmissionPolicyFingerprintV1 {
        reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
            target: TARGET,
            source_scope: SCOPE,
            writer: PlanWriterRef::from_bytes([0x33; 16]),
            controller_principal: CONTROLLER_PRINCIPAL,
            controller_key_ref: CONTROLLER_KEY_REF,
            controller_public_key: &[seed; 32],
            authority_principal: PrincipalRef::from_bytes([0x34; 16]),
            authority_uid: 3_001,
            authority_gid: 3_002,
            tenure_authority_ref: TenureAuthorityRef::from_bytes([0x35; 16]),
            tenure_key_ref: TenureKeyRef::from_bytes([0x36; 16]),
            tenure_public_key: &[0x37; 32],
        })
        .unwrap_or_else(|error| panic!("reference admission policy failed: {error}"))
    }

    fn prepared_request() -> PreparedRuntimeBootstrapRequest {
        let claim = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("request algorithm failed: {error}")),
            1,
            b"controller-bootstrap-nonce",
        )
        .unwrap_or_else(|error| panic!("request claim failed: {error}"));
        let draft = ReferenceBootstrapRequestDraftV1::try_new(
            ReferenceBootstrapRequestIdV1::from_bytes([0x91; 16]),
            TARGET,
            SCOPE,
            claim,
            MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES as u32,
        )
        .unwrap_or_else(|error| panic!("request draft failed: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED).sign(
            draft
                .signing_transcript()
                .unwrap_or_else(|error| panic!("request transcript failed: {error}"))
                .as_bytes(),
        );
        let request = draft
            .finalize(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("request finalize failed: {error}"));
        PreparedRuntimeBootstrapRequest::try_new(request)
            .unwrap_or_else(|error| panic!("request preparation failed: {error}"))
    }

    fn response(
        prepared: &PreparedRuntimeBootstrapRequest,
        expected_compatibility: &ReferenceBootstrapCompatibilityV1,
        response_channel: ReferenceChannelBindingV1,
        snapshot_sequence: u64,
        signature_override: Option<[u8; 64]>,
    ) -> ReferenceBootstrapResponseV1 {
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            STORE,
            snapshot_sequence,
            11,
            CLOCK_DOMAIN,
            ClockGeneration::try_new(12)
                .unwrap_or_else(|error| panic!("clock generation failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("serving identity failed: {error}"));
        let facts = ReferenceBootstrapFactsV1::try_new(
            serving,
            expected_compatibility,
            ReferenceBootstrapStateV1::ReadyForApply,
            None,
        )
        .unwrap_or_else(|error| panic!("bootstrap facts failed: {error}"));
        let claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            response_channel,
            RESPONSE_KEY_REF,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("response algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("response claim failed: {error}"));
        let draft = ReferenceBootstrapResponseDraftV1::try_new(
            prepared.request(),
            facts,
            response_channel,
            claim,
        )
        .unwrap_or_else(|error| panic!("response draft failed: {error}"));
        let signature = signature_override.unwrap_or_else(|| {
            SigningKey::from_bytes(&RUNTIME_SEED)
                .sign(
                    draft
                        .signing_transcript()
                        .unwrap_or_else(|error| panic!("response transcript failed: {error}"))
                        .as_bytes(),
                )
                .to_bytes()
        });
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("response finalize failed: {error}"))
    }

    fn request_auth_pin() -> RuntimeBootstrapRequestAuthPin {
        RuntimeBootstrapRequestAuthPin::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("request pin algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("request pin failed: {error}"))
    }

    fn response_verifier() -> RuntimeBootstrapResponseVerifier {
        let verifying_key = SigningKey::from_bytes(&RUNTIME_SEED).verifying_key();
        let fingerprint = ed25519_control_key_fingerprint(verifying_key.as_bytes())
            .unwrap_or_else(|error| panic!("key fingerprint failed: {error}"));
        RuntimeBootstrapResponseVerifier::try_new(
            RUNTIME_PRINCIPAL,
            RESPONSE_KEY_REF,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("response verifier algorithm failed: {error}")),
            1,
            fingerprint,
            verifying_key,
        )
        .unwrap_or_else(|error| panic!("response verifier failed: {error}"))
    }

    fn client(
        socket: &FakeRuntimeSocket,
        expected_server: RuntimeUnixCredentials,
        expected_compatibility: ReferenceControllerBootstrapExpectationV1,
        serving_expectation: RuntimeBootstrapServingExpectation,
    ) -> UnixRuntimeBootstrapClient {
        UnixRuntimeBootstrapClient::try_new(
            socket.endpoint(expected_server),
            request_auth_pin(),
            response_verifier(),
            expected_compatibility,
            serving_expectation,
            std::time::Duration::from_millis(500),
        )
        .unwrap_or_else(|error| panic!("client failed: {error}"))
    }

    fn apply_request(
        expected_store: [u8; 32],
        operation: ApplyOperationId,
        request_nonce: &[u8],
    ) -> ReferenceApplyRequestV1 {
        let compiled = compiled_facts();
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x87; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .unwrap_or_else(|error| panic!("apply artifact observation failed: {error}"));
        let descriptor = generate_build_descriptor(&artifact, compiled)
            .unwrap_or_else(|error| panic!("apply descriptor generation failed: {error}"));
        let installation = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            TARGET,
            &artifact,
            compiled,
        )
        .unwrap_or_else(|error| panic!("apply manifest generation failed: {error}"));
        let ingress = installation
            .immutable_manifest_ingress()
            .unwrap_or_else(|error| panic!("apply manifest ingress failed: {error}"));
        let execution = ReferenceTargetExecutionPlanV4::try_empty_deactivate(&ingress)
            .unwrap_or_else(|error| panic!("empty apply execution failed: {error}"));
        let provenance = PlanProvenance::new(
            SCOPE,
            SourcePlanRef::from_bytes([0xa1; 16]),
            SourcePlanRevision::new(7),
            SourcePlanDigest::new(Digest32::from_bytes([0xa2; 32])),
        );
        let writer = PlanWriterRef::from_bytes([0xa3; 16]);
        let writer_epoch = PlanWriterEpoch::new(2);
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0xa4; 16]),
            TenureKeyRef::from_bytes([0xa5; 16]),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("tenure algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("tenure authority failed: {error}"));
        let tenure_claim =
            WriterTenureClaim::try_new(SCOPE, writer, writer_epoch, PlanWriterEpoch::new(1))
                .unwrap_or_else(|error| panic!("tenure claim failed: {error}"));
        let tenure_proof = WriterTenureProof::try_new(
            authority,
            tenure_claim,
            b"apply-tenure-nonce",
            b"apply-tenure-signature",
        )
        .unwrap_or_else(|error| panic!("tenure proof failed: {error}"));
        let writer_context = PlanWriterContext::try_new(writer, writer_epoch, tenure_proof)
            .unwrap_or_else(|error| panic!("writer context failed: {error}"));
        let control = RuntimeApplyControl::new(writer_context, ExpectedActive::None, operation);
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([0xa6; 16]),
            CLOCK_DOMAIN,
            ClockGeneration::try_new(12)
                .unwrap_or_else(|error| panic!("apply clock generation failed: {error}")),
            BoundedDuration::from_nanos(10_000),
            BoundedDuration::from_nanos(9_000),
        )
        .unwrap_or_else(|error| panic!("apply temporal constraint failed: {error}"));
        let auth_claim = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("apply request algorithm failed: {error}")),
            1,
            request_nonce,
        )
        .unwrap_or_else(|error| panic!("apply request auth claim failed: {error}"));
        let draft = ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            temporal,
            expected_store,
            auth_claim,
        )
        .unwrap_or_else(|error| panic!("apply request draft failed: {error}"));
        let signature = SigningKey::from_bytes(&CONTROLLER_SEED).sign(
            draft
                .signing_transcript()
                .unwrap_or_else(|error| panic!("apply request transcript failed: {error}"))
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("apply request finalize failed: {error}"))
    }

    fn apply_receipt(
        request: &ReferenceApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        response_key: ApplyAuthKeyRef,
        signature_override: Option<[u8; 64]>,
    ) -> ReferenceApplyTerminalReceiptV1 {
        let facts = ReferenceApplyTerminalFactsV1::try_new(
            request,
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero,
            ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
            Digest32::from_bytes([0xb1; 32]),
            Digest32::from_bytes([0xb2; 32]),
            13,
            14,
            ClockGeneration::try_new(12)
                .unwrap_or_else(|error| panic!("receipt clock generation failed: {error}")),
            15_000,
        )
        .unwrap_or_else(|error| panic!("terminal facts failed: {error}"));
        let claim = ReferenceApplyTerminalReceiptAuthClaimV1::try_new(
            response_channel,
            response_key,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("receipt algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("receipt auth claim failed: {error}"));
        let draft =
            ReferenceApplyTerminalReceiptDraftV1::try_new(request, facts, response_channel, claim)
                .unwrap_or_else(|error| panic!("receipt draft failed: {error}"));
        let signature = signature_override.unwrap_or_else(|| {
            SigningKey::from_bytes(&RUNTIME_SEED)
                .sign(
                    draft
                        .signing_transcript()
                        .unwrap_or_else(|error| panic!("receipt transcript failed: {error}"))
                        .as_bytes(),
                )
                .to_bytes()
        });
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("receipt finalize failed: {error}"))
    }

    fn apply_response_verifier() -> RuntimeApplyResponseVerifier {
        let verifying_key = SigningKey::from_bytes(&RUNTIME_SEED).verifying_key();
        let fingerprint = ed25519_control_key_fingerprint(verifying_key.as_bytes())
            .unwrap_or_else(|error| panic!("apply key fingerprint failed: {error}"));
        RuntimeApplyResponseVerifier::try_new(
            RUNTIME_PRINCIPAL,
            RESPONSE_KEY_REF,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("apply verifier algorithm failed: {error}")),
            1,
            fingerprint,
            verifying_key,
        )
        .unwrap_or_else(|error| panic!("apply response verifier failed: {error}"))
    }

    fn apply_client(
        socket: &FakeRuntimeSocket,
        expected_server: RuntimeUnixCredentials,
        timeout: std::time::Duration,
    ) -> UnixRuntimeApplyClient {
        UnixRuntimeApplyClient::try_new(
            socket.endpoint(expected_server),
            apply_response_verifier(),
            timeout,
        )
        .unwrap_or_else(|error| panic!("apply client failed: {error}"))
    }

    fn apply_expectation(channel: ReferenceChannelBindingV1) -> RuntimeApplyResponseExpectation {
        RuntimeApplyResponseExpectation {
            channel,
            key: RESPONSE_KEY_REF,
            algorithm: ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("apply expectation algorithm failed: {error}")),
            algorithm_version: 1,
        }
    }

    fn apply_response_frame(receipt: &ReferenceApplyTerminalReceiptV1) -> Box<[u8]> {
        let mut frame = Vec::with_capacity(4 + receipt.canonical_wire().len());
        frame.extend_from_slice(
            &u32::try_from(receipt.canonical_wire().len())
                .unwrap_or_else(|error| panic!("apply response length failed: {error}"))
                .to_be_bytes(),
        );
        frame.extend_from_slice(receipt.canonical_wire());
        frame.into_boxed_slice()
    }

    async fn read_request_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut length = [0_u8; 4];
        stream
            .read_exact(&mut length)
            .await
            .unwrap_or_else(|error| panic!("server request length failed: {error}"));
        let mut payload = vec![0_u8; u32::from_be_bytes(length) as usize];
        stream
            .read_exact(&mut payload)
            .await
            .unwrap_or_else(|error| panic!("server request payload failed: {error}"));
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&length);
        frame.extend_from_slice(&payload);
        frame
    }

    fn response_frame(response: &ReferenceBootstrapResponseV1) -> Box<[u8]> {
        let mut frame = Vec::with_capacity(4 + response.canonical_wire().len());
        frame.extend_from_slice(
            &u32::try_from(response.canonical_wire().len())
                .unwrap_or_else(|error| panic!("response length failed: {error}"))
                .to_be_bytes(),
        );
        frame.extend_from_slice(response.canonical_wire());
        frame.into_boxed_slice()
    }

    async fn serve_frame(listener: &UnixListener, frame: &[u8]) -> Vec<u8> {
        let (mut stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("fake accept failed: {error}"));
        let request = read_request_frame(&mut stream).await;
        stream
            .write_all(frame)
            .await
            .unwrap_or_else(|error| panic!("fake response failed: {error}"));
        stream
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("fake response shutdown failed: {error}"));
        request
    }

    async fn perform_apply_exchange(
        socket: &FakeRuntimeSocket,
        listener: UnixListener,
        request: &ReferenceApplyRequestV1,
        expectation: RuntimeApplyResponseExpectation,
        frame: Box<[u8]>,
        exchange_timeout: std::time::Duration,
    ) -> (
        Result<ValidatedRuntimeApplyTerminalReceipt, RuntimeApplyExchangeError>,
        Vec<u8>,
    ) {
        let client = apply_client(socket, current_credentials(), exchange_timeout);
        let server = tokio::spawn(async move { serve_frame(&listener, &frame).await });
        let result = client.exchange_request(request, expectation).await;
        let observed = server
            .await
            .unwrap_or_else(|error| panic!("apply server task failed: {error}"));
        (result, observed)
    }

    #[test]
    fn endpoint_and_response_verifier_reject_unsealed_configuration() {
        let credentials = current_credentials();
        let acl = RuntimeControlSocketAcl::new(credentials.uid, credentials.gid);
        for path in [
            PathBuf::from("relative/runtime.sock"),
            PathBuf::from("/tmp/./runtime.sock"),
            PathBuf::from("/tmp/run/../runtime.sock"),
            PathBuf::from("/tmp//runtime.sock"),
        ] {
            assert!(
                UnixRuntimeControlEndpoint::try_new(
                    path,
                    acl,
                    credentials,
                    TARGET,
                    RUNTIME_PRINCIPAL,
                )
                .is_err()
            );
        }

        let verifying_key = SigningKey::from_bytes(&RUNTIME_SEED).verifying_key();
        assert_eq!(
            RuntimeBootstrapResponseVerifier::try_new(
                RUNTIME_PRINCIPAL,
                RESPONSE_KEY_REF,
                ApplyAuthAlgorithm::try_new(1)
                    .unwrap_or_else(|error| panic!("algorithm failed: {error}")),
                1,
                Digest32::from_bytes([0xff; 32]),
                verifying_key,
            )
            .expect_err("wrong fingerprint must fail"),
            RuntimeControlClientConfigurationError::ResponseKeyFingerprintMismatch
        );
        assert_eq!(
            RuntimeApplyResponseVerifier::try_new(
                RUNTIME_PRINCIPAL,
                RESPONSE_KEY_REF,
                ApplyAuthAlgorithm::try_new(1)
                    .unwrap_or_else(|error| panic!("apply algorithm failed: {error}")),
                1,
                Digest32::from_bytes([0xfe; 32]),
                verifying_key,
            )
            .expect_err("wrong apply fingerprint must fail"),
            RuntimeControlClientConfigurationError::ResponseKeyFingerprintMismatch
        );
    }

    #[test]
    fn successful_exchange_replays_the_exact_prepared_request_bytes() {
        run_async(async {
            let socket = FakeRuntimeSocket::new();
            let listener = socket.bind();
            let expected_channel = live_channel(&socket);
            let expected_compatibility = compatibility(0x88);
            let prepared = prepared_request();
            let response = response(
                &prepared,
                &expected_compatibility,
                expected_channel,
                9,
                None,
            );
            let frame = response_frame(&response);
            let client = client(
                &socket,
                current_credentials(),
                controller_expectation(0x88),
                RuntimeBootstrapServingExpectation::Initial,
            );

            let server = tokio::spawn(async move {
                let first = serve_frame(&listener, &frame).await;
                let second = serve_frame(&listener, &frame).await;
                (first, second)
            });
            let first = client
                .exchange(&prepared)
                .await
                .unwrap_or_else(|error| panic!("first exchange failed: {error}"));
            let second = client
                .exchange(&prepared)
                .await
                .unwrap_or_else(|error| panic!("second exchange failed: {error}"));
            let (first_frame, second_frame) = server
                .await
                .unwrap_or_else(|error| panic!("server task failed: {error}"));

            assert_eq!(first_frame, prepared.transport_frame_bytes());
            assert_eq!(second_frame, prepared.transport_frame_bytes());
            assert_eq!(first.response(), &response);
            assert_eq!(second.response(), &response);
            assert_eq!(first.facts().runtime_store_instance_id(), STORE);
            assert_eq!(first.channel(), expected_channel);
        });
    }

    #[test]
    fn peer_credential_mismatch_is_not_sent_and_writes_no_request_bytes() {
        run_async(async {
            let socket = FakeRuntimeSocket::new();
            let listener = socket.bind();
            let prepared = prepared_request();
            let current = current_credentials();
            let client = client(
                &socket,
                RuntimeUnixCredentials::new(current.uid.wrapping_add(1), current.gid),
                controller_expectation(0x88),
                RuntimeBootstrapServingExpectation::Initial,
            );

            let server = tokio::spawn(async move {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("fake accept failed: {error}"));
                let mut observed = Vec::new();
                stream
                    .read_to_end(&mut observed)
                    .await
                    .unwrap_or_else(|error| panic!("server read failed: {error}"));
                observed
            });
            let result = client.exchange(&prepared).await;
            let observed = server
                .await
                .unwrap_or_else(|error| panic!("server task failed: {error}"));
            assert!(observed.is_empty());
            assert_eq!(
                result,
                Err(RuntimeBootstrapExchangeError::NotSent(
                    RuntimeBootstrapClientFailure::PeerCredentialsMismatch
                ))
            );
        });
    }

    #[test]
    fn truncated_response_after_write_is_uncertain() {
        run_async(async {
            let socket = FakeRuntimeSocket::new();
            let listener = socket.bind();
            let prepared = prepared_request();
            let client = client(
                &socket,
                current_credentials(),
                controller_expectation(0x88),
                RuntimeBootstrapServingExpectation::Initial,
            );
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("fake accept failed: {error}"));
                let request = read_request_frame(&mut stream).await;
                stream
                    .write_all(&[0, 0])
                    .await
                    .unwrap_or_else(|error| panic!("partial response failed: {error}"));
                stream
                    .shutdown()
                    .await
                    .unwrap_or_else(|error| panic!("partial shutdown failed: {error}"));
                request
            });
            let result = client.exchange(&prepared).await;
            let observed = server
                .await
                .unwrap_or_else(|error| panic!("server task failed: {error}"));
            assert_eq!(observed, prepared.transport_frame_bytes());
            assert_eq!(
                result,
                Err(RuntimeBootstrapExchangeError::Uncertain(
                    RuntimeBootstrapClientFailure::TruncatedResponse
                ))
            );
        });
    }

    #[test]
    fn response_length_is_rejected_before_payload_allocation() {
        run_async(async {
            let socket = FakeRuntimeSocket::new();
            let listener = socket.bind();
            let prepared = prepared_request();
            let client = client(
                &socket,
                current_credentials(),
                controller_expectation(0x88),
                RuntimeBootstrapServingExpectation::Initial,
            );
            let oversized = u32::try_from(MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES + 1)
                .unwrap_or_else(|error| panic!("oversized length failed: {error}"))
                .to_be_bytes();
            let server = tokio::spawn(async move { serve_frame(&listener, &oversized).await });
            let result = client.exchange(&prepared).await;
            server
                .await
                .unwrap_or_else(|error| panic!("server task failed: {error}"));
            assert_eq!(
                result,
                Err(RuntimeBootstrapExchangeError::Rejected(
                    RuntimeBootstrapClientFailure::ResponseBoundExceeded
                ))
            );
        });
    }

    #[test]
    fn invalid_signature_and_trailing_bytes_are_rejected() {
        run_async(async {
            let prepared = prepared_request();

            let signature_socket = FakeRuntimeSocket::new();
            let signature_listener = signature_socket.bind();
            let signature_channel = live_channel(&signature_socket);
            let signature_compatibility = compatibility(0x88);
            let invalid_response = response(
                &prepared,
                &signature_compatibility,
                signature_channel,
                9,
                Some([0x7f; 64]),
            );
            let invalid_frame = response_frame(&invalid_response);
            let signature_client = client(
                &signature_socket,
                current_credentials(),
                controller_expectation(0x88),
                RuntimeBootstrapServingExpectation::Initial,
            );
            let signature_server =
                tokio::spawn(async move { serve_frame(&signature_listener, &invalid_frame).await });
            let signature_result = signature_client.exchange(&prepared).await;
            signature_server
                .await
                .unwrap_or_else(|error| panic!("signature server task failed: {error}"));
            assert_eq!(
                signature_result,
                Err(RuntimeBootstrapExchangeError::Rejected(
                    RuntimeBootstrapClientFailure::InvalidResponseSignature
                ))
            );

            let trailing_socket = FakeRuntimeSocket::new();
            let trailing_listener = trailing_socket.bind();
            let trailing_channel = live_channel(&trailing_socket);
            let trailing_compatibility = compatibility(0x88);
            let valid_response = response(
                &prepared,
                &trailing_compatibility,
                trailing_channel,
                9,
                None,
            );
            let mut trailing_frame = response_frame(&valid_response).into_vec();
            trailing_frame.push(0xaa);
            let trailing_client = client(
                &trailing_socket,
                current_credentials(),
                controller_expectation(0x88),
                RuntimeBootstrapServingExpectation::Initial,
            );
            let trailing_server =
                tokio::spawn(async move { serve_frame(&trailing_listener, &trailing_frame).await });
            let trailing_result = trailing_client.exchange(&prepared).await;
            trailing_server
                .await
                .unwrap_or_else(|error| panic!("trailing server task failed: {error}"));
            assert_eq!(
                trailing_result,
                Err(RuntimeBootstrapExchangeError::Rejected(
                    RuntimeBootstrapClientFailure::TrailingBytes
                ))
            );
        });
    }

    #[test]
    fn signed_wrong_channel_and_serving_regression_are_rejected() {
        run_async(async {
            let prepared = prepared_request();

            let channel_socket = FakeRuntimeSocket::new();
            let channel_listener = channel_socket.bind();
            let channel_compatibility = compatibility(0x88);
            let wrong_channel_response = response(
                &prepared,
                &channel_compatibility,
                unrelated_channel(),
                9,
                None,
            );
            let wrong_channel_frame = response_frame(&wrong_channel_response);
            let channel_client = client(
                &channel_socket,
                current_credentials(),
                controller_expectation(0x88),
                RuntimeBootstrapServingExpectation::Initial,
            );
            let channel_server =
                tokio::spawn(
                    async move { serve_frame(&channel_listener, &wrong_channel_frame).await },
                );
            let channel_result = channel_client.exchange(&prepared).await;
            channel_server
                .await
                .unwrap_or_else(|error| panic!("channel server task failed: {error}"));
            assert!(matches!(
                channel_result,
                Err(RuntimeBootstrapExchangeError::Rejected(
                    RuntimeBootstrapClientFailure::ResponseContract(_)
                ))
            ));

            let serving_socket = FakeRuntimeSocket::new();
            let serving_listener = serving_socket.bind();
            let serving_channel = live_channel(&serving_socket);
            let serving_compatibility = compatibility(0x88);
            let serving_response =
                response(&prepared, &serving_compatibility, serving_channel, 9, None);
            let serving_frame = response_frame(&serving_response);
            let expectation = RuntimeBootstrapServingExpectation::try_pinned(
                STORE,
                10,
                11,
                CLOCK_DOMAIN,
                ClockGeneration::try_new(12)
                    .unwrap_or_else(|error| panic!("clock generation failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("serving expectation failed: {error}"));
            let serving_client = client(
                &serving_socket,
                current_credentials(),
                controller_expectation(0x88),
                expectation,
            );
            let serving_server =
                tokio::spawn(async move { serve_frame(&serving_listener, &serving_frame).await });
            let serving_result = serving_client.exchange(&prepared).await;
            serving_server
                .await
                .unwrap_or_else(|error| panic!("serving server task failed: {error}"));
            assert_eq!(
                serving_result,
                Err(RuntimeBootstrapExchangeError::Rejected(
                    RuntimeBootstrapClientFailure::SnapshotSequenceRegression
                ))
            );
        });
    }

    #[test]
    fn apply_exchange_sends_exact_pxar_and_accepts_only_validated_pxrt() {
        run_async(async {
            let socket = FakeRuntimeSocket::new();
            let listener = socket.bind();
            let channel = live_channel(&socket);
            let request = apply_request(
                STORE,
                ApplyOperationId::from_bytes([0xc1; 16]),
                b"apply-normal",
            );
            let receipt = apply_receipt(&request, channel, RESPONSE_KEY_REF, None);
            let (result, observed) = perform_apply_exchange(
                &socket,
                listener,
                &request,
                apply_expectation(channel),
                apply_response_frame(&receipt),
                std::time::Duration::from_millis(500),
            )
            .await;
            let validated =
                result.unwrap_or_else(|error| panic!("valid apply exchange failed: {error}"));

            assert_eq!(
                u32::from_be_bytes(
                    observed[..4]
                        .try_into()
                        .unwrap_or_else(|_| panic!("missing apply frame length"))
                ) as usize,
                request.canonical_wire().len()
            );
            assert_eq!(&observed[4..], request.canonical_wire());
            assert_eq!(validated.receipt(), &receipt);
            assert_eq!(validated.facts(), receipt.facts());
            assert_eq!(validated.request_time_channel(), channel);
            assert_eq!(validated.current_channel(), channel);
        });
    }

    #[test]
    fn historical_pxrt_uses_original_channel_while_current_connection_is_revalidated() {
        run_async(async {
            let historical_socket = FakeRuntimeSocket::new();
            let historical_listener = historical_socket.bind();
            let historical_channel = live_channel(&historical_socket);
            drop(historical_listener);

            let current_socket = FakeRuntimeSocket::new();
            let current_listener = current_socket.bind();
            let current_channel = live_channel(&current_socket);
            assert_ne!(historical_channel, current_channel);

            let request = apply_request(
                STORE,
                ApplyOperationId::from_bytes([0xc2; 16]),
                b"historical-apply",
            );
            let receipt = apply_receipt(&request, historical_channel, RESPONSE_KEY_REF, None);
            let (result, observed) = perform_apply_exchange(
                &current_socket,
                current_listener,
                &request,
                apply_expectation(historical_channel),
                apply_response_frame(&receipt),
                std::time::Duration::from_millis(500),
            )
            .await;
            let validated =
                result.unwrap_or_else(|error| panic!("historical apply replay failed: {error}"));

            assert_eq!(&observed[4..], request.canonical_wire());
            assert_eq!(validated.request_time_channel(), historical_channel);
            assert_eq!(validated.current_channel(), current_channel);
            assert_ne!(
                validated.request_time_channel(),
                validated.current_channel()
            );
        });
    }

    #[test]
    fn apply_peer_mismatch_is_not_sent_and_writes_no_bytes() {
        run_async(async {
            let socket = FakeRuntimeSocket::new();
            let listener = socket.bind();
            let channel = live_channel(&socket);
            let request = apply_request(
                STORE,
                ApplyOperationId::from_bytes([0xc3; 16]),
                b"apply-not-sent",
            );
            let current = current_credentials();
            let client = apply_client(
                &socket,
                RuntimeUnixCredentials::new(current.uid.wrapping_add(1), current.gid),
                std::time::Duration::from_millis(500),
            );
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("apply peer accept failed: {error}"));
                let mut observed = Vec::new();
                stream
                    .read_to_end(&mut observed)
                    .await
                    .unwrap_or_else(|error| panic!("apply peer read failed: {error}"));
                observed
            });
            let result = client
                .exchange_request(&request, apply_expectation(channel))
                .await;
            let observed = server
                .await
                .unwrap_or_else(|error| panic!("apply peer server failed: {error}"));

            assert!(observed.is_empty());
            assert_eq!(
                result,
                Err(RuntimeApplyExchangeError::NotSent(
                    RuntimeApplyClientFailure::Endpoint(
                        RuntimeBootstrapClientFailure::PeerCredentialsMismatch
                    )
                ))
            );
        });
    }

    #[test]
    fn apply_wrong_signature_request_store_key_and_peer_are_uncertain() {
        run_async(async {
            let request = apply_request(
                STORE,
                ApplyOperationId::from_bytes([0xc4; 16]),
                b"apply-correlation",
            );

            let signature_socket = FakeRuntimeSocket::new();
            let signature_listener = signature_socket.bind();
            let signature_channel = live_channel(&signature_socket);
            let signature_receipt = apply_receipt(
                &request,
                signature_channel,
                RESPONSE_KEY_REF,
                Some([0x7f; 64]),
            );
            let (signature_result, _) = perform_apply_exchange(
                &signature_socket,
                signature_listener,
                &request,
                apply_expectation(signature_channel),
                apply_response_frame(&signature_receipt),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert_eq!(
                signature_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::InvalidResponseSignature
                ))
            );

            let request_socket = FakeRuntimeSocket::new();
            let request_listener = request_socket.bind();
            let request_channel = live_channel(&request_socket);
            let other_request = apply_request(
                STORE,
                ApplyOperationId::from_bytes([0xc5; 16]),
                b"apply-correlation",
            );
            let wrong_request_receipt =
                apply_receipt(&other_request, request_channel, RESPONSE_KEY_REF, None);
            let (wrong_request_result, _) = perform_apply_exchange(
                &request_socket,
                request_listener,
                &request,
                apply_expectation(request_channel),
                apply_response_frame(&wrong_request_receipt),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert!(matches!(
                wrong_request_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::ResponseContract(_)
                ))
            ));

            let store_socket = FakeRuntimeSocket::new();
            let store_listener = store_socket.bind();
            let store_channel = live_channel(&store_socket);
            let other_store_request = apply_request(
                [0xd1; 32],
                ApplyOperationId::from_bytes([0xc4; 16]),
                b"apply-correlation",
            );
            let wrong_store_receipt =
                apply_receipt(&other_store_request, store_channel, RESPONSE_KEY_REF, None);
            let (wrong_store_result, _) = perform_apply_exchange(
                &store_socket,
                store_listener,
                &request,
                apply_expectation(store_channel),
                apply_response_frame(&wrong_store_receipt),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert!(matches!(
                wrong_store_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::ResponseContract(_)
                ))
            ));

            let key_socket = FakeRuntimeSocket::new();
            let key_listener = key_socket.bind();
            let key_channel = live_channel(&key_socket);
            let wrong_key_receipt = apply_receipt(
                &request,
                key_channel,
                ApplyAuthKeyRef::from_bytes([0xd2; 16]),
                None,
            );
            let (wrong_key_result, _) = perform_apply_exchange(
                &key_socket,
                key_listener,
                &request,
                apply_expectation(key_channel),
                apply_response_frame(&wrong_key_receipt),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert_eq!(
                wrong_key_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::ResponseKeyMismatch
                ))
            );

            let peer_socket = FakeRuntimeSocket::new();
            let peer_listener = peer_socket.bind();
            let peer_channel = live_channel(&peer_socket);
            let wrong_peer_channel = ReferenceChannelBindingV1::try_new(
                TARGET,
                PrincipalRef::from_bytes([0xd3; 16]),
                peer_channel.local_endpoint_identity_digest(),
                peer_channel.peer_credentials_digest(),
            )
            .unwrap_or_else(|error| panic!("wrong peer channel failed: {error}"));
            let wrong_peer_receipt =
                apply_receipt(&request, wrong_peer_channel, RESPONSE_KEY_REF, None);
            let (wrong_peer_result, _) = perform_apply_exchange(
                &peer_socket,
                peer_listener,
                &request,
                apply_expectation(peer_channel),
                apply_response_frame(&wrong_peer_receipt),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert_eq!(
                wrong_peer_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::ResponsePrincipalMismatch
                ))
            );
        });
    }

    #[test]
    fn apply_ack_trailing_oversize_and_eof_are_never_success() {
        run_async(async {
            let request = apply_request(
                STORE,
                ApplyOperationId::from_bytes([0xc6; 16]),
                b"apply-framing",
            );

            let ack_socket = FakeRuntimeSocket::new();
            let ack_listener = ack_socket.bind();
            let ack_channel = live_channel(&ack_socket);
            let (ack_result, _) = perform_apply_exchange(
                &ack_socket,
                ack_listener,
                &request,
                apply_expectation(ack_channel),
                Box::from([0_u8, 0, 0, 2, b'O', b'K']),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert!(matches!(
                ack_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::ResponseContract(_)
                ))
            ));

            let empty_socket = FakeRuntimeSocket::new();
            let empty_listener = empty_socket.bind();
            let empty_channel = live_channel(&empty_socket);
            let (empty_result, _) = perform_apply_exchange(
                &empty_socket,
                empty_listener,
                &request,
                apply_expectation(empty_channel),
                Box::from([0_u8; 4]),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert_eq!(
                empty_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::InvalidResponseLength
                ))
            );

            let trailing_socket = FakeRuntimeSocket::new();
            let trailing_listener = trailing_socket.bind();
            let trailing_channel = live_channel(&trailing_socket);
            let trailing_receipt =
                apply_receipt(&request, trailing_channel, RESPONSE_KEY_REF, None);
            let mut trailing_frame = apply_response_frame(&trailing_receipt).into_vec();
            trailing_frame.push(0xaa);
            let (trailing_result, _) = perform_apply_exchange(
                &trailing_socket,
                trailing_listener,
                &request,
                apply_expectation(trailing_channel),
                trailing_frame.into_boxed_slice(),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert_eq!(
                trailing_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::TrailingBytes
                ))
            );

            let oversized_socket = FakeRuntimeSocket::new();
            let oversized_listener = oversized_socket.bind();
            let oversized_channel = live_channel(&oversized_socket);
            let oversized = u32::try_from(MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES + 1)
                .unwrap_or_else(|error| panic!("oversized PXRT length failed: {error}"))
                .to_be_bytes();
            let (oversized_result, _) = perform_apply_exchange(
                &oversized_socket,
                oversized_listener,
                &request,
                apply_expectation(oversized_channel),
                Box::from(oversized),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert_eq!(
                oversized_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::ResponseBoundExceeded
                ))
            );

            let eof_socket = FakeRuntimeSocket::new();
            let eof_listener = eof_socket.bind();
            let eof_channel = live_channel(&eof_socket);
            let (eof_result, _) = perform_apply_exchange(
                &eof_socket,
                eof_listener,
                &request,
                apply_expectation(eof_channel),
                Box::from([0_u8, 0]),
                std::time::Duration::from_millis(500),
            )
            .await;
            assert_eq!(
                eof_result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::TruncatedResponse
                ))
            );
        });
    }

    #[test]
    fn apply_response_timeout_after_send_is_uncertain() {
        run_async(async {
            let socket = FakeRuntimeSocket::new();
            let listener = socket.bind();
            let channel = live_channel(&socket);
            let request = apply_request(
                STORE,
                ApplyOperationId::from_bytes([0xc7; 16]),
                b"apply-timeout",
            );
            let client = apply_client(
                &socket,
                current_credentials(),
                std::time::Duration::from_millis(20),
            );
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("timeout accept failed: {error}"));
                let observed = read_request_frame(&mut stream).await;
                tokio::time::sleep(std::time::Duration::from_millis(75)).await;
                observed
            });
            let result = client
                .exchange_request(&request, apply_expectation(channel))
                .await;
            let observed = server
                .await
                .unwrap_or_else(|error| panic!("timeout server task failed: {error}"));

            assert_eq!(&observed[4..], request.canonical_wire());
            assert_eq!(
                result,
                Err(RuntimeApplyExchangeError::Uncertain(
                    RuntimeApplyClientFailure::DeadlineExceeded(
                        RuntimeApplyIoPhase::ReadResponseLength
                    )
                ))
            );
        });
    }
}
