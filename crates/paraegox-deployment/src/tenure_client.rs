//! Owner-private Unix client for the canonical acquire-tenure protocol.
//!
//! Request identity and nonce allocation remain Controller responsibilities.
//! This module only freezes caller-supplied request material into exact signing
//! and frame bytes, validates the local Authority endpoint, performs one
//! bounded exchange, and verifies the returned proof. It never starts a
//! background request or transparently retries transport.

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
use paraegox_kernel::digest::{Digest32, Digest32Builder};
use paraegox_runtime_contracts::apply::TenureProofAuthority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout_at};

use crate::tenure_protocol::{
    ACQUIRE_TENURE_ED25519_ALGORITHM, ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
    ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES, ACQUIRE_TENURE_FRAME_HEADER_BYTES,
    AcquireTenureFrameHeaderV1, AcquireTenureFrameKind, AcquireTenureProtocolError,
    AcquireTenureRequestDraftV1, AcquireTenureRequestV1, AcquireTenureResponseV1,
    decode_acquire_tenure_response_frame_for_request, encode_acquire_tenure_request_frame,
};

const AUTHORITY_SOCKET_MODE: u32 = 0o660;
const AUTHORITY_SOCKET_DIRECTORY_MODE: u32 = 0o2750;
const AUTHORITY_DOMAIN_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.deployment.tenure-authority-client.domain.sha256.v1";
pub(crate) const MAX_TENURE_CLIENT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Exact caller-owned request material awaiting the Controller signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquireTenureRequestToSign {
    draft: AcquireTenureRequestDraftV1,
    signing_bytes: Box<[u8]>,
}

impl AcquireTenureRequestToSign {
    pub(crate) fn try_new(
        draft: AcquireTenureRequestDraftV1,
    ) -> Result<Self, AcquireTenureProtocolError> {
        let signing_bytes = draft.signing_transcript()?.as_bytes().into();
        Ok(Self {
            draft,
            signing_bytes,
        })
    }

    /// Returns the exact bytes which the caller-owned Controller key signs.
    #[must_use]
    pub(crate) fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    /// Freezes one signed request and its exact transport frame for replay.
    pub(crate) fn finalize_ed25519(
        self,
        signature: &[u8],
    ) -> Result<PreparedAcquireTenureRequest, AcquireTenureProtocolError> {
        let request = self.draft.finalize_ed25519(signature)?;
        let frame = encode_acquire_tenure_request_frame(&request);
        Ok(PreparedAcquireTenureRequest { request, frame })
    }
}

/// Immutable request and frame bytes which may be replayed byte-identically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedAcquireTenureRequest {
    request: AcquireTenureRequestV1,
    frame: Box<[u8]>,
}

impl PreparedAcquireTenureRequest {
    /// Reconstructs the exact request frame from durable canonical request
    /// bytes. Recovery deliberately performs no signing or identity
    /// allocation; a stored request is either canonical and replayable or the
    /// caller must fail closed.
    pub(crate) fn try_from_canonical_request_bytes(
        canonical_request: &[u8],
    ) -> Result<Self, AcquireTenureProtocolError> {
        let request = AcquireTenureRequestV1::decode(canonical_request)?;
        let frame = encode_acquire_tenure_request_frame(&request);
        Ok(Self { request, frame })
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &AcquireTenureRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn frame_bytes(&self) -> &[u8] {
        &self.frame
    }
}

/// Expected real/effective Unix credentials for one local endpoint role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnixCredentials {
    uid: u32,
    gid: u32,
}

impl UnixCredentials {
    #[must_use]
    pub(crate) const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

/// Authority-owned socket objects exposed to the Controller's Unix group.
///
/// This is deliberately separate from process credentials: the group on the
/// socket and its directory is the Controller/peer group, while the serving
/// process may have a different effective group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthoritySocketAcl {
    authority_uid: u32,
    controller_gid: u32,
}

impl AuthoritySocketAcl {
    #[must_use]
    pub(crate) const fn new(authority_uid: u32, controller_gid: u32) -> Self {
        Self {
            authority_uid,
            controller_gid,
        }
    }
}

/// Pinned Unix socket path, metadata owner/group, and serving process identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnixAuthorityEndpoint {
    socket_path: PathBuf,
    socket_acl: AuthoritySocketAcl,
    server_credentials: UnixCredentials,
}

impl UnixAuthorityEndpoint {
    pub(crate) fn try_new(
        socket_path: PathBuf,
        socket_acl: AuthoritySocketAcl,
        server_credentials: UnixCredentials,
    ) -> Result<Self, TenureClientConfigurationError> {
        validate_lexical_socket_path(&socket_path)?;
        Ok(Self {
            socket_path,
            socket_acl,
            server_credentials,
        })
    }

    #[must_use]
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// Pinned proof selector and Ed25519 key for the Authority response.
#[derive(Clone, Debug)]
pub(crate) struct AuthorityProofVerifier {
    authority: TenureProofAuthority,
    verifying_key: VerifyingKey,
}

impl AuthorityProofVerifier {
    pub(crate) fn try_new(
        authority: TenureProofAuthority,
        verifying_key: VerifyingKey,
    ) -> Result<Self, TenureClientConfigurationError> {
        if authority.algorithm().value() != ACQUIRE_TENURE_ED25519_ALGORITHM
            || authority.algorithm_version() != ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION
        {
            return Err(TenureClientConfigurationError::UnsupportedProofProfile);
        }
        if verifying_key.is_weak() {
            return Err(TenureClientConfigurationError::WeakAuthorityKey);
        }
        Ok(Self {
            authority,
            verifying_key,
        })
    }

    fn verify(&self, response: &AcquireTenureResponseV1) -> Result<(), TenureClientFailure> {
        let proof = response.proof();
        if proof.authority() != self.authority {
            return Err(TenureClientFailure::ProofAuthorityMismatch);
        }
        let signature_bytes: [u8; ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES] = proof
            .signature()
            .try_into()
            .map_err(|_| TenureClientFailure::InvalidProofSignature)?;
        let transcript = proof
            .signing_transcript()
            .map_err(|_| TenureClientFailure::InvalidProofTranscript)?;
        self.verifying_key
            .verify_strict(
                transcript.as_bytes(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| TenureClientFailure::InvalidProofSignature)
    }
}

/// One provisional owner-private Authority client with a fixed total deadline.
#[derive(Clone, Debug)]
pub(crate) struct UnixTenureAuthorityClient {
    endpoint: UnixAuthorityEndpoint,
    proof_verifier: AuthorityProofVerifier,
    authority_domain_fingerprint: Digest32,
    exchange_timeout: Duration,
}

impl UnixTenureAuthorityClient {
    pub(crate) fn try_new(
        endpoint: UnixAuthorityEndpoint,
        proof_verifier: AuthorityProofVerifier,
        exchange_timeout: Duration,
    ) -> Result<Self, TenureClientConfigurationError> {
        if exchange_timeout.is_zero() || exchange_timeout > MAX_TENURE_CLIENT_EXCHANGE_TIMEOUT {
            return Err(TenureClientConfigurationError::InvalidExchangeTimeout);
        }
        let authority_domain_fingerprint =
            derive_authority_domain_fingerprint(&endpoint, &proof_verifier)?;
        Ok(Self {
            endpoint,
            proof_verifier,
            authority_domain_fingerprint,
            exchange_timeout,
        })
    }

    /// Returns the sealed identity of the exact Authority transport and proof
    /// verification domain selected by this client.
    #[must_use]
    pub(crate) const fn authority_domain_fingerprint(&self) -> Digest32 {
        self.authority_domain_fingerprint
    }

    /// Performs exactly one exchange. Any returned failure after write begins
    /// is explicitly uncertain because the Authority may already have
    /// committed.
    ///
    /// This future is deliberately **not cancellation-safe**. Once a caller
    /// starts polling it, cancellation, task loss, or an outer timeout cannot
    /// prove that no request byte was written and must be journaled as
    /// uncertain against these same prepared bytes. The admitted Controller
    /// consumer must rely on this method's total deadline and reconcile the
    /// byte-identical request; it must not replace the result with a generic
    /// cancellation outcome.
    pub(crate) async fn exchange(
        &self,
        prepared: &PreparedAcquireTenureRequest,
    ) -> Result<AcquireTenureResponseV1, AcquireTenureExchangeError> {
        let deadline = Instant::now() + self.exchange_timeout;
        let validated_endpoint = validate_endpoint_metadata(&self.endpoint)
            .map_err(AcquireTenureExchangeError::NotSent)?;

        let mut stream = bounded_io(
            deadline,
            TenureClientIoPhase::Connect,
            DeliveryState::NotSent,
            UnixStream::connect(self.endpoint.socket_path()),
        )
        .await?;

        validated_endpoint
            .revalidate(&self.endpoint)
            .map_err(AcquireTenureExchangeError::NotSent)?;
        validate_peer_credentials(&stream, self.endpoint.server_credentials)
            .map_err(AcquireTenureExchangeError::NotSent)?;

        bounded_io(
            deadline,
            TenureClientIoPhase::WriteRequest,
            DeliveryState::Uncertain,
            stream.write_all(prepared.frame_bytes()),
        )
        .await?;

        let mut header_bytes = [0_u8; ACQUIRE_TENURE_FRAME_HEADER_BYTES];
        bounded_read_exact(
            deadline,
            TenureClientIoPhase::ReadHeader,
            &mut stream,
            &mut header_bytes,
        )
        .await?;
        let header = AcquireTenureFrameHeaderV1::decode_prefix(&header_bytes).map_err(|error| {
            AcquireTenureExchangeError::Uncertain(TenureClientFailure::Protocol(error))
        })?;
        if header.kind() != AcquireTenureFrameKind::Response {
            return Err(AcquireTenureExchangeError::Uncertain(
                TenureClientFailure::UnexpectedFrameKind,
            ));
        }
        if header.payload_bytes() as usize
            > prepared.request().max_response_payload_bytes() as usize
        {
            return Err(AcquireTenureExchangeError::Uncertain(
                TenureClientFailure::ResponseBoundExceeded,
            ));
        }

        let mut payload = vec![0_u8; header.payload_bytes() as usize];
        bounded_read_exact(
            deadline,
            TenureClientIoPhase::ReadPayload,
            &mut stream,
            &mut payload,
        )
        .await?;

        let mut trailing = [0_u8; 1];
        let trailing_bytes = bounded_io(
            deadline,
            TenureClientIoPhase::ReadTrailing,
            DeliveryState::Uncertain,
            stream.read(&mut trailing),
        )
        .await?;
        if trailing_bytes != 0 {
            return Err(AcquireTenureExchangeError::Uncertain(
                TenureClientFailure::TrailingBytes,
            ));
        }

        let mut frame = Vec::with_capacity(ACQUIRE_TENURE_FRAME_HEADER_BYTES + payload.len());
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(&payload);
        let response = decode_acquire_tenure_response_frame_for_request(&frame, prepared.request())
            .map_err(|error| {
                AcquireTenureExchangeError::Uncertain(TenureClientFailure::Protocol(error))
            })?;
        self.proof_verifier
            .verify(&response)
            .map_err(AcquireTenureExchangeError::Uncertain)?;
        Ok(response)
    }
}

fn derive_authority_domain_fingerprint(
    endpoint: &UnixAuthorityEndpoint,
    proof_verifier: &AuthorityProofVerifier,
) -> Result<Digest32, TenureClientConfigurationError> {
    let authority = proof_verifier.authority;
    let mut builder = Digest32Builder::try_new(AUTHORITY_DOMAIN_FINGERPRINT_DOMAIN)
        .map_err(|_| TenureClientConfigurationError::AuthorityDomainFingerprint)?;
    builder
        .field_bytes(endpoint.socket_path.as_os_str().as_bytes())
        .and_then(|builder| builder.field_u64(u64::from(endpoint.socket_acl.authority_uid)))
        .and_then(|builder| builder.field_u64(u64::from(endpoint.socket_acl.controller_gid)))
        .and_then(|builder| builder.field_u64(u64::from(AUTHORITY_SOCKET_DIRECTORY_MODE)))
        .and_then(|builder| builder.field_u64(u64::from(AUTHORITY_SOCKET_MODE)))
        .and_then(|builder| builder.field_u64(u64::from(endpoint.server_credentials.uid)))
        .and_then(|builder| builder.field_u64(u64::from(endpoint.server_credentials.gid)))
        .and_then(|builder| builder.field_bytes(authority.authority().as_bytes()))
        .and_then(|builder| builder.field_bytes(authority.key().as_bytes()))
        .and_then(|builder| builder.field_u16(authority.algorithm().value()))
        .and_then(|builder| builder.field_u16(authority.algorithm_version()))
        .and_then(|builder| builder.field_bytes(proof_verifier.verifying_key.as_bytes()))
        .map_err(|_| TenureClientConfigurationError::AuthorityDomainFingerprint)?;
    Ok(builder.finish())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenureClientConfigurationError {
    RelativeSocketPath,
    NonCanonicalSocketPath,
    InvalidExchangeTimeout,
    UnsupportedProofProfile,
    WeakAuthorityKey,
    AuthorityDomainFingerprint,
}

impl fmt::Display for TenureClientConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RelativeSocketPath => "Authority socket path must be absolute",
            Self::NonCanonicalSocketPath => "Authority socket path must be lexically canonical",
            Self::InvalidExchangeTimeout => "Authority exchange timeout is outside its bound",
            Self::UnsupportedProofProfile => "Authority proof profile is not Ed25519 v1",
            Self::WeakAuthorityKey => "Authority verification key is weak",
            Self::AuthorityDomainFingerprint => {
                "Authority transport and proof domain fingerprint is invalid"
            }
        })
    }
}

impl std::error::Error for TenureClientConfigurationError {}

/// Whether the request is proven unsent or may already be durably committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcquireTenureExchangeError {
    NotSent(TenureClientFailure),
    Uncertain(TenureClientFailure),
}

impl AcquireTenureExchangeError {
    #[must_use]
    pub(crate) const fn failure(self) -> TenureClientFailure {
        match self {
            Self::NotSent(failure) | Self::Uncertain(failure) => failure,
        }
    }

    #[must_use]
    pub(crate) const fn is_uncertain(self) -> bool {
        matches!(self, Self::Uncertain(_))
    }
}

impl fmt::Display for AcquireTenureExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSent(failure) => {
                write!(formatter, "Authority request was not sent: {failure}")
            }
            Self::Uncertain(failure) => write!(
                formatter,
                "Authority request outcome is transport-uncertain: {failure}"
            ),
        }
    }
}

impl std::error::Error for AcquireTenureExchangeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenureClientIoPhase {
    Connect,
    WriteRequest,
    ReadHeader,
    ReadPayload,
    ReadTrailing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenureClientFailure {
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
    DeadlineExceeded(TenureClientIoPhase),
    Io(TenureClientIoPhase),
    TruncatedResponse,
    UnexpectedFrameKind,
    ResponseBoundExceeded,
    TrailingBytes,
    Protocol(AcquireTenureProtocolError),
    ProofAuthorityMismatch,
    InvalidProofTranscript,
    InvalidProofSignature,
}

impl fmt::Display for TenureClientFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketAncestorMetadataUnavailable => {
                formatter.write_str("socket ancestor metadata unavailable")
            }
            Self::InvalidSocketAncestor => {
                formatter.write_str("socket ancestor is not a real directory")
            }
            Self::UntrustedSocketAncestor => {
                formatter.write_str("socket ancestor is replaceable by an untrusted principal")
            }
            Self::SocketDirectoryMetadataUnavailable => {
                formatter.write_str("socket directory metadata unavailable")
            }
            Self::InvalidSocketDirectoryType => {
                formatter.write_str("socket directory is not a real directory")
            }
            Self::InvalidSocketDirectoryAcl => {
                formatter.write_str("socket directory ACL metadata is invalid")
            }
            Self::SocketDirectoryOpenFailed => {
                formatter.write_str("socket directory could not be opened safely")
            }
            Self::SocketMetadataUnavailable => formatter.write_str("socket metadata unavailable"),
            Self::InvalidSocketType => formatter.write_str("endpoint is not a Unix socket"),
            Self::InvalidSocketAcl => formatter.write_str("socket ACL metadata is invalid"),
            Self::SocketIdentityChanged => {
                formatter.write_str("socket identity changed during connect")
            }
            Self::PeerCredentialsUnavailable => {
                formatter.write_str("server peer credentials unavailable")
            }
            Self::PeerCredentialsMismatch => {
                formatter.write_str("server peer credentials do not match")
            }
            Self::DeadlineExceeded(phase) => {
                write!(formatter, "deadline exceeded during {phase:?}")
            }
            Self::Io(phase) => write!(formatter, "I/O failed during {phase:?}"),
            Self::TruncatedResponse => formatter.write_str("response frame is truncated"),
            Self::UnexpectedFrameKind => formatter.write_str("response frame kind is not Response"),
            Self::ResponseBoundExceeded => {
                formatter.write_str("response exceeds the authenticated bound")
            }
            Self::TrailingBytes => formatter.write_str("response stream contains trailing bytes"),
            Self::Protocol(error) => write!(formatter, "response protocol rejected: {error}"),
            Self::ProofAuthorityMismatch => {
                formatter.write_str("proof authority selector does not match")
            }
            Self::InvalidProofTranscript => {
                formatter.write_str("proof signing transcript is invalid")
            }
            Self::InvalidProofSignature => formatter.write_str("proof signature is invalid"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryState {
    NotSent,
    Uncertain,
}

impl DeliveryState {
    const fn error(self, failure: TenureClientFailure) -> AcquireTenureExchangeError {
        match self {
            Self::NotSent => AcquireTenureExchangeError::NotSent(failure),
            Self::Uncertain => AcquireTenureExchangeError::Uncertain(failure),
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
}

impl ValidatedEndpoint {
    fn revalidate(&self, endpoint: &UnixAuthorityEndpoint) -> Result<(), TenureClientFailure> {
        let socket_directory_path = endpoint
            .socket_path()
            .parent()
            .ok_or(TenureClientFailure::InvalidSocketAncestor)?;
        let ancestor_identities = validate_trusted_socket_ancestors(
            socket_directory_path,
            endpoint.socket_acl.authority_uid,
        )?;
        if ancestor_identities != self.ancestor_identities {
            return Err(TenureClientFailure::SocketIdentityChanged);
        }

        let open_metadata = self
            .socket_directory
            .metadata()
            .map_err(|_| TenureClientFailure::SocketDirectoryMetadataUnavailable)?;
        validate_socket_directory_metadata(&open_metadata, endpoint.socket_acl)?;
        let path_metadata = fs::symlink_metadata(socket_directory_path)
            .map_err(|_| TenureClientFailure::SocketDirectoryMetadataUnavailable)?;
        validate_socket_directory_metadata(&path_metadata, endpoint.socket_acl)?;
        if FileIdentity::from_metadata(&open_metadata) != self.directory_identity
            || FileIdentity::from_metadata(&path_metadata) != self.directory_identity
        {
            return Err(TenureClientFailure::SocketIdentityChanged);
        }

        if validate_socket_metadata(endpoint)? != self.socket_identity {
            return Err(TenureClientFailure::SocketIdentityChanged);
        }
        Ok(())
    }
}

fn validate_lexical_socket_path(path: &Path) -> Result<(), TenureClientConfigurationError> {
    if !path.is_absolute() {
        return Err(TenureClientConfigurationError::RelativeSocketPath);
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
        return Err(TenureClientConfigurationError::NonCanonicalSocketPath);
    }

    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => normal_components += 1,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(TenureClientConfigurationError::NonCanonicalSocketPath);
            }
        }
    }
    if normal_components == 0 || path.parent().is_none() || path.file_name().is_none() {
        return Err(TenureClientConfigurationError::NonCanonicalSocketPath);
    }
    Ok(())
}

fn validate_endpoint_metadata(
    endpoint: &UnixAuthorityEndpoint,
) -> Result<ValidatedEndpoint, TenureClientFailure> {
    let socket_directory_path = endpoint
        .socket_path()
        .parent()
        .ok_or(TenureClientFailure::InvalidSocketAncestor)?;
    let ancestor_identities = validate_trusted_socket_ancestors(
        socket_directory_path,
        endpoint.socket_acl.authority_uid,
    )?;
    let before = fs::symlink_metadata(socket_directory_path)
        .map_err(|_| TenureClientFailure::SocketDirectoryMetadataUnavailable)?;
    validate_socket_directory_metadata(&before, endpoint.socket_acl)?;
    let directory_identity = FileIdentity::from_metadata(&before);

    let owned = open(
        socket_directory_path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| TenureClientFailure::SocketDirectoryOpenFailed)?;
    let socket_directory = File::from(owned);
    let open_metadata = socket_directory
        .metadata()
        .map_err(|_| TenureClientFailure::SocketDirectoryMetadataUnavailable)?;
    validate_socket_directory_metadata(&open_metadata, endpoint.socket_acl)?;
    let path_metadata = fs::symlink_metadata(socket_directory_path)
        .map_err(|_| TenureClientFailure::SocketDirectoryMetadataUnavailable)?;
    validate_socket_directory_metadata(&path_metadata, endpoint.socket_acl)?;
    if FileIdentity::from_metadata(&open_metadata) != directory_identity
        || FileIdentity::from_metadata(&path_metadata) != directory_identity
    {
        return Err(TenureClientFailure::SocketIdentityChanged);
    }

    let socket_identity = validate_socket_metadata(endpoint)?;
    Ok(ValidatedEndpoint {
        socket_directory,
        ancestor_identities,
        directory_identity,
        socket_identity,
    })
}

fn validate_trusted_socket_ancestors(
    socket_directory_path: &Path,
    authority_uid: u32,
) -> Result<Box<[FileIdentity]>, TenureClientFailure> {
    let parent = socket_directory_path
        .parent()
        .ok_or(TenureClientFailure::InvalidSocketAncestor)?;
    let mut current = PathBuf::new();
    let mut identities = Vec::new();
    for component in parent.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(TenureClientFailure::InvalidSocketAncestor);
            }
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| TenureClientFailure::SocketAncestorMetadataUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(TenureClientFailure::InvalidSocketAncestor);
        }
        let owner_uid = metadata.uid();
        let mode = metadata.mode() & 0o7777;
        let root_owned_sticky = owner_uid == 0 && mode & 0o1000 != 0;
        let owner_is_trusted = owner_uid == 0 || owner_uid == authority_uid;
        if !owner_is_trusted || (mode & 0o022 != 0 && !root_owned_sticky) {
            return Err(TenureClientFailure::UntrustedSocketAncestor);
        }
        identities.push(FileIdentity::from_metadata(&metadata));
    }
    Ok(identities.into_boxed_slice())
}

fn validate_socket_directory_metadata(
    metadata: &Metadata,
    expected: AuthoritySocketAcl,
) -> Result<(), TenureClientFailure> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(TenureClientFailure::InvalidSocketDirectoryType);
    }
    if metadata.nlink() == 0
        || metadata.uid() != expected.authority_uid
        || metadata.gid() != expected.controller_gid
        || metadata.mode() & 0o7777 != AUTHORITY_SOCKET_DIRECTORY_MODE
    {
        return Err(TenureClientFailure::InvalidSocketDirectoryAcl);
    }
    Ok(())
}

fn validate_socket_metadata(
    endpoint: &UnixAuthorityEndpoint,
) -> Result<FileIdentity, TenureClientFailure> {
    let metadata = fs::symlink_metadata(endpoint.socket_path())
        .map_err(|_| TenureClientFailure::SocketMetadataUnavailable)?;
    if !metadata.file_type().is_socket() {
        return Err(TenureClientFailure::InvalidSocketType);
    }
    if metadata.nlink() != 1
        || metadata.uid() != endpoint.socket_acl.authority_uid
        || metadata.gid() != endpoint.socket_acl.controller_gid
        || metadata.mode() & 0o7777 != AUTHORITY_SOCKET_MODE
    {
        return Err(TenureClientFailure::InvalidSocketAcl);
    }
    Ok(FileIdentity::from_metadata(&metadata))
}

fn validate_peer_credentials(
    stream: &UnixStream,
    expected: UnixCredentials,
) -> Result<(), TenureClientFailure> {
    let credentials = stream
        .peer_cred()
        .map_err(|_| TenureClientFailure::PeerCredentialsUnavailable)?;
    if credentials.uid() != expected.uid || credentials.gid() != expected.gid {
        return Err(TenureClientFailure::PeerCredentialsMismatch);
    }
    Ok(())
}

async fn bounded_io<Output, Operation>(
    deadline: Instant,
    phase: TenureClientIoPhase,
    delivery: DeliveryState,
    operation: Operation,
) -> Result<Output, AcquireTenureExchangeError>
where
    Operation: Future<Output = io::Result<Output>>,
{
    timeout_at(deadline, operation)
        .await
        .map_err(|_| delivery.error(TenureClientFailure::DeadlineExceeded(phase)))?
        .map_err(|_| delivery.error(TenureClientFailure::Io(phase)))
}

async fn bounded_read_exact(
    deadline: Instant,
    phase: TenureClientIoPhase,
    stream: &mut UnixStream,
    output: &mut [u8],
) -> Result<(), AcquireTenureExchangeError> {
    match timeout_at(deadline, stream.read_exact(output)).await {
        Err(_) => Err(AcquireTenureExchangeError::Uncertain(
            TenureClientFailure::DeadlineExceeded(phase),
        )),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => Err(
            AcquireTenureExchangeError::Uncertain(TenureClientFailure::TruncatedResponse),
        ),
        Ok(Err(_)) => Err(AcquireTenureExchangeError::Uncertain(
            TenureClientFailure::Io(phase),
        )),
        Ok(Ok(_)) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::Future;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_runtime_contracts::apply::{
        PlanWriterEpoch, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
        TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::runtime::Builder as RuntimeBuilder;
    use tokio::time::{Duration, sleep, timeout};

    use super::{
        AUTHORITY_SOCKET_DIRECTORY_MODE, AUTHORITY_SOCKET_MODE, AcquireTenureExchangeError,
        AcquireTenureRequestToSign, AuthorityProofVerifier, AuthoritySocketAcl,
        TenureClientConfigurationError, TenureClientFailure, TenureClientIoPhase,
        UnixAuthorityEndpoint, UnixCredentials, UnixTenureAuthorityClient,
    };
    use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
    use crate::tenure_protocol::{
        ACQUIRE_TENURE_FRAME_HEADER_BYTES, AcquireTenureFrameHeaderV1, AcquireTenureOperationId,
        AcquireTenureProtocolErrorCode, AcquireTenureRequestDraftV1, AcquireTenureResponseV1,
        ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES, decode_acquire_tenure_request_frame,
        encode_acquire_tenure_response_frame,
    };

    const CONTROLLER_SEED: [u8; 32] = [0x31; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x52; 32];
    const CLIENT_NONCE: &[u8] = b"s7-e-authority-client";

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct FakeSocket {
        root: PathBuf,
        directory: PathBuf,
        path: PathBuf,
    }

    impl FakeSocket {
        fn new() -> Self {
            for _ in 0..128 {
                let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let fixture_root = std::env::temp_dir()
                    .canonicalize()
                    .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
                let root = fixture_root.join(format!("pxtc-{}-{sequence}", std::process::id()));
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
                            fs::Permissions::from_mode(AUTHORITY_SOCKET_DIRECTORY_MODE),
                        )
                        .unwrap_or_else(|error| {
                            panic!("fake socket directory chmod failed: {error}")
                        });
                        let path = directory.join("authority.sock");
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
            panic!("could not allocate a unique fake socket directory")
        }

        fn bind(&self) -> UnixListener {
            let listener = UnixListener::bind(&self.path)
                .unwrap_or_else(|error| panic!("fake Authority bind failed: {error}"));
            fs::set_permissions(
                &self.path,
                fs::Permissions::from_mode(AUTHORITY_SOCKET_MODE),
            )
            .unwrap_or_else(|error| panic!("fake socket chmod failed: {error}"));
            listener
        }

        fn endpoint(&self, expected_server: UnixCredentials) -> UnixAuthorityEndpoint {
            self.endpoint_at(self.path.clone(), expected_server)
        }

        fn endpoint_at(
            &self,
            path: PathBuf,
            expected_server: UnixCredentials,
        ) -> UnixAuthorityEndpoint {
            let metadata = fs::symlink_metadata(&self.directory)
                .unwrap_or_else(|error| panic!("fake socket directory metadata failed: {error}"));
            UnixAuthorityEndpoint::try_new(
                path,
                AuthoritySocketAcl::new(metadata.uid(), metadata.gid()),
                expected_server,
            )
            .unwrap_or_else(|error| panic!("fake endpoint failed: {error}"))
        }
    }

    impl Drop for FakeSocket {
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

    fn proof_authority(byte: u8) -> TenureProofAuthority {
        TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([byte; 16]),
            TenureKeyRef::from_bytes([byte.wrapping_add(1); 16]),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("test algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("test proof authority failed: {error}"))
    }

    fn prepared_request_with(
        operation_byte: u8,
        nonce: &[u8],
    ) -> super::PreparedAcquireTenureRequest {
        let controller_key = SigningKey::from_bytes(&CONTROLLER_SEED);
        let fingerprint = ControllerPublicKeyFingerprint::for_ed25519_key(
            &controller_key.verifying_key().to_bytes(),
        )
        .unwrap_or_else(|error| panic!("controller fingerprint failed: {error}"));
        let draft = AcquireTenureRequestDraftV1::try_new(
            crate::tenure_protocol::AcquireTenureIntentV1::new(
                DeploymentScopeId::from_bytes([0x11; 16]),
                DeploymentWriterRef::from_bytes([0x22; 16]),
                AcquireTenureOperationId::from_bytes([operation_byte; 16]),
            ),
            PrincipalRef::from_bytes([0x44; 16]),
            ControllerAcquireKeyRef::from_bytes([0x55; 16]),
            fingerprint,
            nonce,
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .unwrap_or_else(|error| panic!("response bound failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("request draft failed: {error}"));
        let to_sign = AcquireTenureRequestToSign::try_new(draft)
            .unwrap_or_else(|error| panic!("request preparation failed: {error}"));
        let signature = controller_key.sign(to_sign.signing_bytes());
        to_sign
            .finalize_ed25519(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("request finalization failed: {error}"))
    }

    fn prepared_request() -> super::PreparedAcquireTenureRequest {
        prepared_request_with(0x33, CLIENT_NONCE)
    }

    fn response_frame_with(
        prepared: &super::PreparedAcquireTenureRequest,
        authority: TenureProofAuthority,
        signing_key: &SigningKey,
        signature_override: Option<[u8; 64]>,
    ) -> Box<[u8]> {
        let claim = WriterTenureClaim::try_new(
            prepared.request().proof_source_scope(),
            prepared.request().proof_writer(),
            PlanWriterEpoch::new(9),
            PlanWriterEpoch::new(8),
        )
        .unwrap_or_else(|error| panic!("test claim failed: {error}"));
        let transcript = paraegox_runtime_contracts::apply::WriterTenureSigningTranscript::try_new(
            authority,
            claim,
            prepared.request().client_nonce(),
        )
        .unwrap_or_else(|error| panic!("test proof transcript failed: {error}"));
        let signature = signature_override
            .unwrap_or_else(|| signing_key.sign(transcript.as_bytes()).to_bytes());
        let proof = WriterTenureProof::try_new(
            authority,
            claim,
            prepared.request().client_nonce(),
            &signature,
        )
        .unwrap_or_else(|error| panic!("test proof failed: {error}"));
        let response = AcquireTenureResponseV1::try_new(prepared.request(), proof)
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        encode_acquire_tenure_response_frame(&response)
    }

    fn current_credentials() -> UnixCredentials {
        UnixCredentials::new(
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
    }

    fn proof_verifier() -> AuthorityProofVerifier {
        let signing_key = SigningKey::from_bytes(&AUTHORITY_SEED);
        AuthorityProofVerifier::try_new(proof_authority(0x66), signing_key.verifying_key())
            .unwrap_or_else(|error| panic!("proof verifier failed: {error}"))
    }

    #[derive(Clone, Copy)]
    struct AuthorityDomainFixture {
        socket_path: &'static str,
        authority_uid: u32,
        controller_gid: u32,
        server_uid: u32,
        server_gid: u32,
        authority_ref_byte: u8,
        key_ref_byte: u8,
        verifying_seed_byte: u8,
    }

    impl AuthorityDomainFixture {
        fn endpoint(self) -> UnixAuthorityEndpoint {
            UnixAuthorityEndpoint::try_new(
                PathBuf::from(self.socket_path),
                AuthoritySocketAcl::new(self.authority_uid, self.controller_gid),
                UnixCredentials::new(self.server_uid, self.server_gid),
            )
            .unwrap_or_else(|error| panic!("domain endpoint failed: {error}"))
        }

        fn authority(self, algorithm: u16, algorithm_version: u16) -> TenureProofAuthority {
            TenureProofAuthority::try_new(
                TenureAuthorityRef::from_bytes([self.authority_ref_byte; 16]),
                TenureKeyRef::from_bytes([self.key_ref_byte; 16]),
                TenureProofAlgorithm::try_new(algorithm)
                    .unwrap_or_else(|error| panic!("domain algorithm failed: {error}")),
                algorithm_version,
            )
            .unwrap_or_else(|error| panic!("domain proof authority failed: {error}"))
        }

        fn fingerprint(self) -> paraegox_kernel::digest::Digest32 {
            let verifier = AuthorityProofVerifier::try_new(
                self.authority(
                    super::ACQUIRE_TENURE_ED25519_ALGORITHM,
                    super::ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
                ),
                SigningKey::from_bytes(&[self.verifying_seed_byte; 32]).verifying_key(),
            )
            .unwrap_or_else(|error| panic!("domain verifier failed: {error}"));
            UnixTenureAuthorityClient::try_new(self.endpoint(), verifier, Duration::from_secs(1))
                .unwrap_or_else(|error| panic!("domain client failed: {error}"))
                .authority_domain_fingerprint()
        }

        fn fingerprint_with_unvalidated_profile(
            self,
            algorithm: u16,
            algorithm_version: u16,
        ) -> paraegox_kernel::digest::Digest32 {
            let verifier = AuthorityProofVerifier {
                authority: self.authority(algorithm, algorithm_version),
                verifying_key: SigningKey::from_bytes(&[self.verifying_seed_byte; 32])
                    .verifying_key(),
            };
            super::derive_authority_domain_fingerprint(&self.endpoint(), &verifier)
                .unwrap_or_else(|error| panic!("domain fingerprint failed: {error}"))
        }
    }

    fn client_for_endpoint(
        endpoint: UnixAuthorityEndpoint,
        timeout_value: Duration,
    ) -> UnixTenureAuthorityClient {
        UnixTenureAuthorityClient::try_new(endpoint, proof_verifier(), timeout_value)
            .unwrap_or_else(|error| panic!("test client failed: {error}"))
    }

    fn client(
        socket: &FakeSocket,
        listener: &UnixListener,
        timeout_value: Duration,
    ) -> UnixTenureAuthorityClient {
        let local = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("listener address failed: {error}"));
        assert!(local.as_pathname().is_some());
        client_for_endpoint(socket.endpoint(current_credentials()), timeout_value)
    }

    async fn read_request_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut header_bytes = [0_u8; ACQUIRE_TENURE_FRAME_HEADER_BYTES];
        stream
            .read_exact(&mut header_bytes)
            .await
            .unwrap_or_else(|error| panic!("server request header failed: {error}"));
        let header = AcquireTenureFrameHeaderV1::decode_prefix(&header_bytes)
            .unwrap_or_else(|error| panic!("server request header rejected: {error}"));
        let mut payload = vec![0_u8; header.payload_bytes() as usize];
        stream
            .read_exact(&mut payload)
            .await
            .unwrap_or_else(|error| panic!("server request payload failed: {error}"));
        let mut frame = Vec::with_capacity(header_bytes.len() + payload.len());
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(&payload);
        decode_acquire_tenure_request_frame(&frame)
            .unwrap_or_else(|error| panic!("server request rejected: {error}"));
        frame
    }

    async fn serve_frame(listener: UnixListener, frame: Box<[u8]>) -> Vec<u8> {
        let (mut stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("fake accept failed: {error}"));
        let request = read_request_frame(&mut stream).await;
        stream
            .write_all(&frame)
            .await
            .unwrap_or_else(|error| panic!("fake response failed: {error}"));
        request
    }

    #[test]
    fn endpoint_rejects_noncanonical_socket_paths() {
        let credentials = current_credentials();
        let acl = AuthoritySocketAcl::new(
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        );
        for (path, expected) in [
            (
                PathBuf::from("relative/authority.sock"),
                TenureClientConfigurationError::RelativeSocketPath,
            ),
            (
                PathBuf::from("/tmp/./authority.sock"),
                TenureClientConfigurationError::NonCanonicalSocketPath,
            ),
            (
                PathBuf::from("/tmp/run/../authority.sock"),
                TenureClientConfigurationError::NonCanonicalSocketPath,
            ),
            (
                PathBuf::from("/tmp//authority.sock"),
                TenureClientConfigurationError::NonCanonicalSocketPath,
            ),
            (
                PathBuf::from("/tmp/authority.sock/"),
                TenureClientConfigurationError::NonCanonicalSocketPath,
            ),
            (
                PathBuf::from("/"),
                TenureClientConfigurationError::NonCanonicalSocketPath,
            ),
        ] {
            assert_eq!(
                UnixAuthorityEndpoint::try_new(path, acl, credentials),
                Err(expected)
            );
        }
    }

    #[test]
    fn authority_domain_fingerprint_is_stable_and_binds_every_security_field() {
        let fixture = AuthorityDomainFixture {
            socket_path: "/var/run/paraegox/authority.sock",
            authority_uid: 2_001,
            controller_gid: 3_001,
            server_uid: 2_001,
            server_gid: 2_002,
            authority_ref_byte: 0x61,
            key_ref_byte: 0x62,
            verifying_seed_byte: 0x63,
        };
        let base = fixture.fingerprint();
        assert_eq!(base, fixture.fingerprint());
        let changed = [
            AuthorityDomainFixture {
                socket_path: "/var/run/paraegox/authority-next.sock",
                ..fixture
            }
            .fingerprint(),
            AuthorityDomainFixture {
                authority_uid: 2_003,
                ..fixture
            }
            .fingerprint(),
            AuthorityDomainFixture {
                controller_gid: 3_002,
                ..fixture
            }
            .fingerprint(),
            AuthorityDomainFixture {
                server_uid: 2_003,
                ..fixture
            }
            .fingerprint(),
            AuthorityDomainFixture {
                server_gid: 2_003,
                ..fixture
            }
            .fingerprint(),
            AuthorityDomainFixture {
                authority_ref_byte: 0x64,
                ..fixture
            }
            .fingerprint(),
            AuthorityDomainFixture {
                key_ref_byte: 0x64,
                ..fixture
            }
            .fingerprint(),
            AuthorityDomainFixture {
                verifying_seed_byte: 0x64,
                ..fixture
            }
            .fingerprint(),
            fixture.fingerprint_with_unvalidated_profile(2, 1),
            fixture.fingerprint_with_unvalidated_profile(1, 2),
        ];
        assert!(changed.iter().all(|fingerprint| *fingerprint != base));
        assert_eq!(
            changed
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            changed.len(),
            "each Authority security-domain field must have independent digest influence"
        );

        let unsupported = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0x71; 16]),
            TenureKeyRef::from_bytes([0x72; 16]),
            TenureProofAlgorithm::try_new(2)
                .unwrap_or_else(|error| panic!("unsupported algorithm fixture failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("unsupported authority fixture failed: {error}"));
        assert_eq!(
            AuthorityProofVerifier::try_new(
                unsupported,
                SigningKey::from_bytes(&AUTHORITY_SEED).verifying_key(),
            )
            .expect_err("unsupported profile must fail before domain construction"),
            TenureClientConfigurationError::UnsupportedProofProfile
        );
        let unsupported_version = fixture.authority(1, 2);
        assert_eq!(
            AuthorityProofVerifier::try_new(
                unsupported_version,
                SigningKey::from_bytes(&AUTHORITY_SEED).verifying_key(),
            )
            .expect_err("unsupported version must fail before domain construction"),
            TenureClientConfigurationError::UnsupportedProofProfile
        );

        let mut weak_bytes = [0_u8; 32];
        weak_bytes[0] = 1;
        let weak = ed25519_dalek::VerifyingKey::from_bytes(&weak_bytes)
            .unwrap_or_else(|error| panic!("weak key fixture failed: {error}"));
        assert!(weak.is_weak());
        assert_eq!(
            AuthorityProofVerifier::try_new(proof_authority(0x73), weak)
                .expect_err("weak key must fail before domain construction"),
            TenureClientConfigurationError::WeakAuthorityKey
        );
    }

    #[test]
    fn unsafe_socket_ancestors_and_directory_acl_are_not_sent() {
        run_async(async {
            {
                let socket = FakeSocket::new();
                let _listener = socket.bind();
                let link = socket.root.join("link");
                symlink(".", &link)
                    .unwrap_or_else(|error| panic!("ancestor symlink failed: {error}"));
                let endpoint =
                    socket.endpoint_at(link.join("run/authority.sock"), current_credentials());
                let client = client_for_endpoint(endpoint, Duration::from_millis(200));
                assert_eq!(
                    client.exchange(&prepared_request()).await,
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::InvalidSocketAncestor
                    ))
                );
            }

            {
                let socket = FakeSocket::new();
                let _listener = socket.bind();
                fs::set_permissions(&socket.root, fs::Permissions::from_mode(0o770))
                    .unwrap_or_else(|error| panic!("writable ancestor chmod failed: {error}"));
                let client = client_for_endpoint(
                    socket.endpoint(current_credentials()),
                    Duration::from_millis(200),
                );
                assert_eq!(
                    client.exchange(&prepared_request()).await,
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::UntrustedSocketAncestor
                    ))
                );
            }

            {
                let socket = FakeSocket::new();
                let not_directory = socket.root.join("not-directory");
                fs::write(&not_directory, b"not a directory")
                    .unwrap_or_else(|error| panic!("non-directory ancestor failed: {error}"));
                let endpoint = socket.endpoint_at(
                    not_directory.join("run/authority.sock"),
                    current_credentials(),
                );
                let client = client_for_endpoint(endpoint, Duration::from_millis(200));
                assert_eq!(
                    client.exchange(&prepared_request()).await,
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::InvalidSocketAncestor
                    ))
                );
            }

            {
                let socket = FakeSocket::new();
                let _listener = socket.bind();
                fs::set_permissions(&socket.directory, fs::Permissions::from_mode(0o750))
                    .unwrap_or_else(|error| panic!("socket directory chmod failed: {error}"));
                let client = client_for_endpoint(
                    socket.endpoint(current_credentials()),
                    Duration::from_millis(200),
                );
                assert_eq!(
                    client.exchange(&prepared_request()).await,
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::InvalidSocketDirectoryAcl
                    ))
                );
            }
        });
    }

    #[test]
    fn final_socket_type_acl_and_connect_failure_are_not_sent() {
        run_async(async {
            {
                let socket = FakeSocket::new();
                let listener = socket.bind();
                let client = client(&socket, &listener, Duration::from_millis(200));
                drop(listener);
                fs::remove_file(&socket.path)
                    .unwrap_or_else(|error| panic!("socket removal failed: {error}"));
                fs::write(&socket.path, b"not a socket")
                    .unwrap_or_else(|error| panic!("regular file fixture failed: {error}"));
                fs::set_permissions(
                    &socket.path,
                    fs::Permissions::from_mode(AUTHORITY_SOCKET_MODE),
                )
                .unwrap_or_else(|error| panic!("regular file chmod failed: {error}"));
                assert_eq!(
                    client.exchange(&prepared_request()).await,
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::InvalidSocketType
                    ))
                );
            }

            {
                let socket = FakeSocket::new();
                let listener = socket.bind();
                let client = client(&socket, &listener, Duration::from_millis(200));
                fs::set_permissions(&socket.path, fs::Permissions::from_mode(0o600))
                    .unwrap_or_else(|error| panic!("socket ACL chmod failed: {error}"));
                assert_eq!(
                    client.exchange(&prepared_request()).await,
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::InvalidSocketAcl
                    ))
                );
            }

            {
                let socket = FakeSocket::new();
                let listener = socket.bind();
                let client = client(&socket, &listener, Duration::from_millis(200));
                drop(listener);
                assert_eq!(
                    client.exchange(&prepared_request()).await,
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::Io(TenureClientIoPhase::Connect)
                    ))
                );
            }
        });
    }

    #[test]
    fn fragmented_response_and_exact_proof_succeed() {
        run_async(async {
            let socket = FakeSocket::new();
            let listener = socket.bind();
            let client = client(&socket, &listener, Duration::from_secs(2));
            let prepared = prepared_request();
            let response = response_frame_with(
                &prepared,
                proof_authority(0x66),
                &SigningKey::from_bytes(&AUTHORITY_SEED),
                None,
            );
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("fake accept failed: {error}"));
                let request = read_request_frame(&mut stream).await;
                for chunk in response.chunks(3) {
                    stream
                        .write_all(chunk)
                        .await
                        .unwrap_or_else(|error| panic!("fragment write failed: {error}"));
                    tokio::task::yield_now().await;
                }
                request
            });
            let result = client.exchange(&prepared).await;
            let observed = server
                .await
                .unwrap_or_else(|error| panic!("server task failed: {error}"));
            assert!(result.is_ok());
            assert_eq!(observed, prepared.frame_bytes());
        });
    }

    #[test]
    fn wrong_kind_version_and_oversize_headers_are_uncertain() {
        run_async(async {
            for (mutation, expected_code) in [
                (0_u8, None),
                (
                    1_u8,
                    Some(AcquireTenureProtocolErrorCode::UnsupportedVersion),
                ),
                (
                    2_u8,
                    Some(AcquireTenureProtocolErrorCode::InvalidFieldLength),
                ),
            ] {
                let socket = FakeSocket::new();
                let listener = socket.bind();
                let client = client(&socket, &listener, Duration::from_secs(2));
                let prepared = prepared_request();
                let mut frame = response_frame_with(
                    &prepared,
                    proof_authority(0x66),
                    &SigningKey::from_bytes(&AUTHORITY_SEED),
                    None,
                )
                .into_vec();
                match mutation {
                    0 => {
                        frame[10..12].copy_from_slice(&1_u16.to_be_bytes());
                        frame[12..16].copy_from_slice(&0_u32.to_be_bytes());
                    }
                    1 => frame[8..10].copy_from_slice(&2_u16.to_be_bytes()),
                    2 => {
                        let oversized_payload =
                            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                                .expect("protocol payload bound fits u32")
                                + 1;
                        frame[12..16].copy_from_slice(&oversized_payload.to_be_bytes());
                    }
                    _ => unreachable!(),
                }
                frame.truncate(ACQUIRE_TENURE_FRAME_HEADER_BYTES);
                let server = tokio::spawn(serve_frame(listener, frame.into_boxed_slice()));
                let error = client
                    .exchange(&prepared)
                    .await
                    .expect_err("malformed header must fail");
                server
                    .await
                    .unwrap_or_else(|join_error| panic!("server task failed: {join_error}"));
                assert!(error.is_uncertain());
                match expected_code {
                    None => assert_eq!(error.failure(), TenureClientFailure::UnexpectedFrameKind),
                    Some(expected) => match error.failure() {
                        TenureClientFailure::Protocol(actual) => {
                            assert_eq!(actual.code(), expected);
                        }
                        failure => panic!("unexpected protocol failure: {failure:?}"),
                    },
                }
            }
        });
    }

    #[test]
    fn truncated_trailing_timeout_and_close_are_uncertain() {
        run_async(async {
            for case in 0_u8..4 {
                let socket = FakeSocket::new();
                let listener = socket.bind();
                let timeout_value = if case == 2 {
                    Duration::from_millis(80)
                } else {
                    Duration::from_secs(2)
                };
                let client = client(&socket, &listener, timeout_value);
                let prepared = prepared_request();
                let mut frame = response_frame_with(
                    &prepared,
                    proof_authority(0x66),
                    &SigningKey::from_bytes(&AUTHORITY_SEED),
                    None,
                )
                .into_vec();
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener
                        .accept()
                        .await
                        .unwrap_or_else(|error| panic!("fake accept failed: {error}"));
                    let request = read_request_frame(&mut stream).await;
                    match case {
                        0 => {
                            frame.pop();
                            stream.write_all(&frame).await.expect("truncated write");
                        }
                        1 => {
                            frame.push(0xaa);
                            stream.write_all(&frame).await.expect("trailing write");
                        }
                        2 => sleep(Duration::from_millis(200)).await,
                        3 => {}
                        _ => unreachable!(),
                    }
                    request
                });
                let error = client
                    .exchange(&prepared)
                    .await
                    .expect_err("broken response must fail");
                server
                    .await
                    .unwrap_or_else(|join_error| panic!("server task failed: {join_error}"));
                assert!(error.is_uncertain());
                match case {
                    0 | 3 => assert_eq!(error.failure(), TenureClientFailure::TruncatedResponse),
                    1 => assert_eq!(error.failure(), TenureClientFailure::TrailingBytes),
                    2 => assert_eq!(
                        error.failure(),
                        TenureClientFailure::DeadlineExceeded(TenureClientIoPhase::ReadHeader)
                    ),
                    _ => unreachable!(),
                }
            }
        });
    }

    #[test]
    fn wrong_peer_is_rejected_before_any_request_byte() {
        run_async(async {
            let socket = FakeSocket::new();
            let listener = socket.bind();
            let local_uid = nix::unistd::geteuid().as_raw();
            let wrong_peer =
                UnixCredentials::new(local_uid.wrapping_add(1), nix::unistd::getegid().as_raw());
            let endpoint = socket.endpoint(wrong_peer);
            let signing_key = SigningKey::from_bytes(&AUTHORITY_SEED);
            let verifier =
                AuthorityProofVerifier::try_new(proof_authority(0x66), signing_key.verifying_key())
                    .expect("verifier");
            let client =
                UnixTenureAuthorityClient::try_new(endpoint, verifier, Duration::from_secs(2))
                    .expect("client");
            let prepared = prepared_request();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut byte = [0_u8; 1];
                timeout(Duration::from_secs(1), stream.read(&mut byte))
                    .await
                    .expect("peer rejection close deadline")
                    .expect("peer rejection read")
            });
            let error = client.exchange(&prepared).await.expect_err("wrong peer");
            let observed = server.await.expect("server join");
            assert_eq!(
                error,
                AcquireTenureExchangeError::NotSent(TenureClientFailure::PeerCredentialsMismatch)
            );
            assert_eq!(observed, 0);
        });
    }

    #[test]
    fn same_prepared_request_replays_exact_frame_bytes() {
        run_async(async {
            let socket = FakeSocket::new();
            let listener = socket.bind();
            let client = client(&socket, &listener, Duration::from_secs(2));
            let prepared = prepared_request();
            let response = response_frame_with(
                &prepared,
                proof_authority(0x66),
                &SigningKey::from_bytes(&AUTHORITY_SEED),
                None,
            );
            let server = tokio::spawn(async move {
                let mut observed = Vec::new();
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.expect("accept");
                    observed.push(read_request_frame(&mut stream).await);
                    stream.write_all(&response).await.expect("response");
                }
                observed
            });
            assert!(client.exchange(&prepared).await.is_ok());
            assert!(client.exchange(&prepared).await.is_ok());
            let observed = server.await.expect("server join");
            assert_eq!(observed.len(), 2);
            assert_eq!(observed[0], prepared.frame_bytes());
            assert_eq!(observed[1], prepared.frame_bytes());
            assert_eq!(observed[0], observed[1]);
        });
    }

    #[test]
    fn response_binding_and_proof_signature_fail_closed_as_uncertain() {
        run_async(async {
            for case in 0_u8..3 {
                let socket = FakeSocket::new();
                let listener = socket.bind();
                let client = client(&socket, &listener, Duration::from_secs(2));
                let prepared = prepared_request();
                let authority_key = SigningKey::from_bytes(&AUTHORITY_SEED);
                let frame = match case {
                    0 => response_frame_with(
                        &prepared_request_with(0x34, b"different-request"),
                        proof_authority(0x66),
                        &authority_key,
                        None,
                    ),
                    1 => {
                        response_frame_with(&prepared, proof_authority(0x67), &authority_key, None)
                    }
                    2 => response_frame_with(
                        &prepared,
                        proof_authority(0x66),
                        &authority_key,
                        Some([0xa5; 64]),
                    ),
                    _ => unreachable!(),
                };
                let server = tokio::spawn(serve_frame(listener, frame));
                let error = client
                    .exchange(&prepared)
                    .await
                    .expect_err("unbound response must fail");
                server.await.expect("server join");
                assert!(error.is_uncertain());
                match case {
                    0 => match error.failure() {
                        TenureClientFailure::Protocol(protocol) => assert_eq!(
                            protocol.code(),
                            AcquireTenureProtocolErrorCode::RequestBindingMismatch
                        ),
                        failure => panic!("unexpected binding failure: {failure:?}"),
                    },
                    1 => assert_eq!(error.failure(), TenureClientFailure::ProofAuthorityMismatch),
                    2 => assert_eq!(error.failure(), TenureClientFailure::InvalidProofSignature),
                    _ => unreachable!(),
                }
            }
        });
    }
}
