//! Explicit same-user developer lifecycle for the real tenure-authority owner.
//!
//! This facade exists only so a developer-local composition root can run the
//! authenticated Authority wire and durable journal on a non-production host.
//! It does not weaken or replace the Linux/ext4 production process profile.

#![cfg(unix)]

use core::fmt;
use core::future::Future;
use core::task::Poll;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Receiver as ReadyReceiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, getegid, geteuid, unlinkat};
use paraegox_kernel::{
    digest::{Digest32, Digest32Builder},
    identity::PrincipalRef,
};
use paraegox_runtime_contracts::apply::{
    TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::oneshot;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
use crate::tenure_authority::{
    ControllerAcquireAuthorization, DeploymentTenureAuthority, TenureAcquireError,
    TenureAuthorityFingerprints, TenureAuthorityProvisioning, ed25519_authority_key_fingerprint,
    initialize_tenure_authority_store_developer_local,
    observe_tenure_authority_store_id_developer_local,
};
use crate::tenure_protocol::{
    ACQUIRE_TENURE_FRAME_HEADER_BYTES, AcquireTenureFrameHeaderV1, AcquireTenureFrameKind,
    AcquireTenureRequestV1, ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
    MAX_ACQUIRE_TENURE_FRAME_BYTES, MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES,
    MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES, encode_acquire_tenure_response_frame,
};

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const STATE_DIRECTORY_MODE: u32 = 0o700;
// Keep the existing Unix Authority client ACL shape so the developer path
// exercises that exact client and proof verifier. DeveloperLocal differs only
// in using the same non-root uid/gid on both sides, never in wire or metadata
// validation.
const SOCKET_DIRECTORY_MODE: u32 = 0o2750;
const SOCKET_MODE: u32 = 0o660;
const MODE_MASK: u32 = 0o7777;
const MAX_SOCKET_PATH_BYTES: usize = 103;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const POLICY_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.deployment.developer-local-tenure-policy.sha256.v1";
const SERVICE_PRINCIPAL_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.deployment.developer-local-tenure-service-principal.sha256.v1";
const OWNER_IDENTITY_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.deployment.developer-local-tenure-owner.sha256.v1";

/// Raw opaque identities generated and persisted by the developer composition
/// root. `try_new` on the enclosing configuration validates every value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeveloperLocalTenureAuthorityIdentityBytesV1 {
    pub source_scope: [u8; 16],
    pub writer: [u8; 16],
    pub authority: [u8; 16],
    pub authority_key: [u8; 16],
    pub controller_principal: [u8; 16],
    pub controller_key: [u8; 16],
    pub service_principal: [u8; 16],
    pub owner: [u8; 16],
}

/// Same-user peer identity admitted by the developer-only Unix endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeveloperLocalPeerIdentityV1 {
    uid: u32,
    gid: u32,
}

impl DeveloperLocalPeerIdentityV1 {
    /// Selects the current non-root process identity explicitly.
    pub fn current() -> Result<Self, DeveloperLocalTenureAuthorityError> {
        Self::try_new(geteuid().as_raw(), getegid().as_raw())
    }

    /// Accepts only the current non-root process identity. This is not a
    /// production service-account isolation claim.
    pub fn try_new(uid: u32, gid: u32) -> Result<Self, DeveloperLocalTenureAuthorityError> {
        if uid == 0 || gid == 0 || uid != geteuid().as_raw() || gid != getegid().as_raw() {
            return Err(DeveloperLocalTenureAuthorityError::InvalidConfiguration);
        }
        Ok(Self { uid, gid })
    }

    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }
}

/// Fully explicit developer-local Authority inputs. The signing seed is
/// zeroized and never appears in `Debug` or in the returned public facts.
pub struct DeveloperLocalTenureAuthorityConfigV1 {
    state_directory: PathBuf,
    socket_path: PathBuf,
    identities: DeveloperLocalTenureAuthorityIdentityBytesV1,
    authority_seed: Zeroizing<[u8; 32]>,
    controller_verification_key: [u8; 32],
    expected_store_instance_id: Option<[u8; 32]>,
    peer: DeveloperLocalPeerIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeveloperLocalTenureAuthorityPublicPinsV1 {
    pub(crate) identities: DeveloperLocalTenureAuthorityIdentityBytesV1,
    pub(crate) authority_verification_key: [u8; 32],
    pub(crate) controller_public_key_fingerprint: [u8; 32],
}

impl fmt::Debug for DeveloperLocalTenureAuthorityConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalTenureAuthorityConfigV1")
            .field("state_directory", &self.state_directory)
            .field("socket_path", &self.socket_path)
            .field("identities", &self.identities)
            .field("authority_seed", &"<redacted>")
            .field(
                "controller_verification_key",
                &"<public-key-redacted-from-diagnostics>",
            )
            .field(
                "expected_store_instance_id",
                &self.expected_store_instance_id.is_some(),
            )
            .field("peer", &self.peer)
            .finish()
    }
}

impl DeveloperLocalTenureAuthorityConfigV1 {
    pub fn try_new(
        state_directory: PathBuf,
        socket_path: PathBuf,
        identities: DeveloperLocalTenureAuthorityIdentityBytesV1,
        authority_seed: Zeroizing<[u8; 32]>,
        controller_verification_key: [u8; 32],
        expected_store_instance_id: Option<[u8; 32]>,
        peer: DeveloperLocalPeerIdentityV1,
    ) -> Result<Self, DeveloperLocalTenureAuthorityError> {
        validate_absolute_path(&state_directory, false)?;
        validate_absolute_path(&socket_path, true)?;
        if socket_path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES
            || socket_path.starts_with(&state_directory)
            || identities_contain_zero_or_duplicate(identities)
            || authority_seed.iter().all(|byte| *byte == 0)
            || expected_store_instance_id
                .is_some_and(|identity| identity.iter().all(|byte| *byte == 0))
        {
            return Err(DeveloperLocalTenureAuthorityError::InvalidConfiguration);
        }
        let authority_verification_key = SigningKey::from_bytes(&authority_seed)
            .verifying_key()
            .to_bytes();
        let controller_key = VerifyingKey::from_bytes(&controller_verification_key)
            .map_err(|_| DeveloperLocalTenureAuthorityError::InvalidConfiguration)?;
        if controller_key.is_weak() || authority_verification_key == controller_verification_key {
            return Err(DeveloperLocalTenureAuthorityError::InvalidConfiguration);
        }
        Ok(Self {
            state_directory,
            socket_path,
            identities,
            authority_seed,
            controller_verification_key,
            expected_store_instance_id,
            peer,
        })
    }

    pub(crate) fn public_pins(
        &self,
    ) -> Result<DeveloperLocalTenureAuthorityPublicPinsV1, DeveloperLocalTenureAuthorityError> {
        let controller_public_key_fingerprint =
            ControllerPublicKeyFingerprint::for_ed25519_key(&self.controller_verification_key)
                .map_err(|_| DeveloperLocalTenureAuthorityError::InvalidConfiguration)?;
        Ok(DeveloperLocalTenureAuthorityPublicPinsV1 {
            identities: self.identities,
            authority_verification_key: SigningKey::from_bytes(&self.authority_seed)
                .verifying_key()
                .to_bytes(),
            controller_public_key_fingerprint: *controller_public_key_fingerprint.as_bytes(),
        })
    }
}

/// Non-secret facts a developer-local Controller needs for the real Authority
/// client and provisioning chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperLocalTenureAuthorityFactsV1 {
    state_directory: PathBuf,
    socket_path: PathBuf,
    identities: DeveloperLocalTenureAuthorityIdentityBytesV1,
    store_instance_id: [u8; 32],
    authority_verification_key: [u8; 32],
    controller_public_key_fingerprint: [u8; 32],
    signing_key_fingerprint: Digest32,
    policy_fingerprint: Digest32,
    service_principal_fingerprint: Digest32,
    owner_identity_fingerprint: Digest32,
    peer: DeveloperLocalPeerIdentityV1,
}

impl DeveloperLocalTenureAuthorityFactsV1 {
    #[must_use]
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub const fn identities(&self) -> DeveloperLocalTenureAuthorityIdentityBytesV1 {
        self.identities
    }

    #[must_use]
    pub const fn store_instance_id(&self) -> [u8; 32] {
        self.store_instance_id
    }

    #[must_use]
    pub const fn authority_verification_key(&self) -> [u8; 32] {
        self.authority_verification_key
    }

    #[must_use]
    pub const fn controller_public_key_fingerprint(&self) -> [u8; 32] {
        self.controller_public_key_fingerprint
    }

    #[must_use]
    pub const fn signing_key_fingerprint(&self) -> Digest32 {
        self.signing_key_fingerprint
    }

    #[must_use]
    pub const fn policy_fingerprint(&self) -> Digest32 {
        self.policy_fingerprint
    }

    #[must_use]
    pub const fn service_principal_fingerprint(&self) -> Digest32 {
        self.service_principal_fingerprint
    }

    #[must_use]
    pub const fn owner_identity_fingerprint(&self) -> Digest32 {
        self.owner_identity_fingerprint
    }

    #[must_use]
    pub const fn peer(&self) -> DeveloperLocalPeerIdentityV1 {
        self.peer
    }
}

/// Running developer-only Authority endpoint. It owns the durable store lock,
/// Unix listener, shutdown signal, and joined service thread.
pub struct DeveloperLocalTenureAuthorityV1 {
    facts: DeveloperLocalTenureAuthorityFactsV1,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<Result<(), DeveloperLocalTenureAuthorityError>>>,
}

impl fmt::Debug for DeveloperLocalTenureAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalTenureAuthorityV1")
            .field("facts", &self.facts)
            .field("running", &self.join.is_some())
            .finish()
    }
}

impl DeveloperLocalTenureAuthorityV1 {
    /// Initializes or strictly reopens the developer store, acquires its sole
    /// writer lock, binds the authenticated Unix listener, and waits for the
    /// service thread to become ready before returning.
    pub fn start(
        config: DeveloperLocalTenureAuthorityConfigV1,
    ) -> Result<Self, DeveloperLocalTenureAuthorityError> {
        validate_owned_directory(&config.state_directory, config.peer)?;
        let socket_parent = config
            .socket_path
            .parent()
            .ok_or(DeveloperLocalTenureAuthorityError::InvalidConfiguration)?;
        let socket_directory =
            SocketDirectory::open(socket_parent, config.peer, SOCKET_DIRECTORY_MODE)?;

        let authority_verification_key = SigningKey::from_bytes(&config.authority_seed)
            .verifying_key()
            .to_bytes();
        let (provisioning, derived) = build_provisioning(
            &config,
            authority_verification_key,
            socket_directory.path.as_path(),
        )?;
        let store_instance_id = match config.expected_store_instance_id {
            Some(expected) => expected,
            None => match initialize_tenure_authority_store_developer_local(
                &config.state_directory,
                provisioning,
            ) {
                Ok(receipt) => *receipt.store_instance_id(),
                Err(_) => observe_tenure_authority_store_id_developer_local(
                    &config.state_directory,
                    provisioning,
                )
                .map_err(|_| DeveloperLocalTenureAuthorityError::InitializationFailed)?,
            },
        };
        let authority = DeploymentTenureAuthority::open_developer_local(
            &config.state_directory,
            store_instance_id,
            provisioning,
            config.authority_seed,
        )
        .map_err(|_| DeveloperLocalTenureAuthorityError::StoreRejected)?;

        // The Authority store lock is already held before any stale socket can
        // be inspected or removed.
        let (standard_listener, socket_guard) =
            prepare_listener(socket_directory, &config.socket_path)?;
        let facts = DeveloperLocalTenureAuthorityFactsV1 {
            state_directory: config.state_directory,
            socket_path: config.socket_path,
            identities: config.identities,
            store_instance_id,
            authority_verification_key,
            controller_public_key_fingerprint: derived.controller_public_key_fingerprint,
            signing_key_fingerprint: derived.signing_key_fingerprint,
            policy_fingerprint: derived.policy_fingerprint,
            service_principal_fingerprint: derived.service_principal_fingerprint,
            owner_identity_fingerprint: derived.owner_identity_fingerprint,
            peer: config.peer,
        };
        let (shutdown_send, shutdown_receive) = oneshot::channel();
        let (ready_send, ready_receive) = mpsc::sync_channel(1);
        let expected_peer = config.peer;
        let join = thread::Builder::new()
            .name("paraegox-dev-tenure-authority".to_owned())
            .spawn(move || {
                run_service_thread(
                    standard_listener,
                    socket_guard,
                    authority,
                    expected_peer,
                    shutdown_receive,
                    ready_send,
                )
            })
            .map_err(|_| DeveloperLocalTenureAuthorityError::RuntimeFailed)?;
        let mut running = Self {
            facts,
            shutdown: Some(shutdown_send),
            join: Some(join),
        };
        match receive_ready(ready_receive) {
            Ok(()) => Ok(running),
            Err(error) => {
                let _ = running.shutdown_inner();
                Err(error)
            }
        }
    }

    #[must_use]
    pub const fn facts(&self) -> &DeveloperLocalTenureAuthorityFactsV1 {
        &self.facts
    }

    /// Polls for an already-completed service thread without waiting for it.
    ///
    /// `Ok(false)` means the Authority still owns its listener and store lock.
    /// `Ok(true)` means the thread was already complete and has now been joined.
    /// A completed thread failure is surfaced exactly once and also consumes
    /// the join handle, so a composition owner can fail closed without an
    /// unbounded wait in its supervision path.
    pub fn try_poll_exit(&mut self) -> Result<bool, DeveloperLocalTenureAuthorityError> {
        let Some(join) = self.join.as_ref() else {
            return Ok(true);
        };
        if !join.is_finished() {
            return Ok(false);
        }
        let join = self
            .join
            .take()
            .ok_or(DeveloperLocalTenureAuthorityError::JoinFailed)?;
        self.shutdown.take();
        join.join()
            .map_err(|_| DeveloperLocalTenureAuthorityError::JoinFailed)??;
        Ok(true)
    }

    /// Requests cooperative shutdown and joins the sole service thread.
    pub fn shutdown(mut self) -> Result<(), DeveloperLocalTenureAuthorityError> {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> Result<(), DeveloperLocalTenureAuthorityError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.join()
            .map_err(|_| DeveloperLocalTenureAuthorityError::JoinFailed)??;
        Ok(())
    }
}

impl Drop for DeveloperLocalTenureAuthorityV1 {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

fn receive_ready(
    ready: ReadyReceiver<Result<(), DeveloperLocalTenureAuthorityError>>,
) -> Result<(), DeveloperLocalTenureAuthorityError> {
    ready
        .recv_timeout(STARTUP_TIMEOUT)
        .map_err(|_| DeveloperLocalTenureAuthorityError::StartupTimedOut)??;
    Ok(())
}

fn run_service_thread(
    standard_listener: StdUnixListener,
    socket_guard: SocketGuard,
    mut authority: DeploymentTenureAuthority,
    expected_peer: DeveloperLocalPeerIdentityV1,
    mut shutdown: oneshot::Receiver<()>,
    ready: mpsc::SyncSender<Result<(), DeveloperLocalTenureAuthorityError>>,
) -> Result<(), DeveloperLocalTenureAuthorityError> {
    let runtime = match RuntimeBuilder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = ready.send(Err(DeveloperLocalTenureAuthorityError::RuntimeFailed));
            return Err(DeveloperLocalTenureAuthorityError::RuntimeFailed);
        }
    };
    let listener = {
        let _context = runtime.enter();
        match UnixListener::from_std(standard_listener) {
            Ok(listener) => listener,
            Err(_) => {
                let _ = ready.send(Err(DeveloperLocalTenureAuthorityError::SocketRejected));
                return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
            }
        }
    };
    ready
        .send(Ok(()))
        .map_err(|_| DeveloperLocalTenureAuthorityError::RuntimeFailed)?;
    let service = runtime.block_on(serve_loop(
        &listener,
        &mut authority,
        expected_peer,
        &mut shutdown,
    ));
    drop(listener);
    drop(runtime);
    let cleanup = socket_guard.cleanup();
    match (service, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn serve_loop(
    listener: &UnixListener,
    authority: &mut DeploymentTenureAuthority,
    expected_peer: DeveloperLocalPeerIdentityV1,
    shutdown: &mut oneshot::Receiver<()>,
) -> Result<(), DeveloperLocalTenureAuthorityError> {
    loop {
        match next_event(listener, shutdown).await {
            ServerEvent::Shutdown => return Ok(()),
            ServerEvent::Accept(Err(_)) => {
                return Err(DeveloperLocalTenureAuthorityError::ServiceFailed);
            }
            ServerEvent::Accept(Ok((mut stream, _))) => {
                if !peer_is_authorized(&stream, expected_peer) {
                    continue;
                }
                let request = match read_request(&mut stream).await {
                    Ok(request) => request,
                    Err(()) => continue,
                };
                let committed = match authority.acquire_authorized_request(&request) {
                    Ok(committed) => committed,
                    Err(error) if fatal_authority_error(error) => {
                        return Err(DeveloperLocalTenureAuthorityError::ServiceFailed);
                    }
                    Err(_) => continue,
                };
                let response = encode_acquire_tenure_response_frame(committed.response());
                // Commit-before-reply is preserved. A lost response is not a
                // new Authority operation; the same request may replay bytes.
                let _ = timeout(IO_TIMEOUT, stream.write_all(&response)).await;
            }
        }
    }
}

async fn next_event(listener: &UnixListener, shutdown: &mut oneshot::Receiver<()>) -> ServerEvent {
    let accept = listener.accept();
    await_event(accept, shutdown).await
}

async fn await_event<Accept, Accepted>(
    accept: Accept,
    shutdown: &mut oneshot::Receiver<()>,
) -> ServerEvent<Accepted>
where
    Accept: Future<Output = io::Result<Accepted>>,
{
    let mut accept = Box::pin(accept);
    std::future::poll_fn(|context| {
        if std::pin::Pin::new(&mut *shutdown).poll(context).is_ready() {
            return Poll::Ready(ServerEvent::Shutdown);
        }
        if let Poll::Ready(result) = accept.as_mut().poll(context) {
            return Poll::Ready(ServerEvent::Accept(result));
        }
        Poll::Pending
    })
    .await
}

enum ServerEvent<Accepted = (UnixStream, tokio::net::unix::SocketAddr)> {
    Accept(io::Result<Accepted>),
    Shutdown,
}

fn peer_is_authorized(stream: &UnixStream, expected: DeveloperLocalPeerIdentityV1) -> bool {
    stream.peer_cred().is_ok_and(|credentials| {
        credentials.uid() == expected.uid && credentials.gid() == expected.gid
    })
}

async fn read_request(stream: &mut UnixStream) -> Result<AcquireTenureRequestV1, ()> {
    timeout(IO_TIMEOUT, read_request_before_deadline(stream))
        .await
        .map_err(|_| ())?
}

async fn read_request_before_deadline(
    stream: &mut UnixStream,
) -> Result<AcquireTenureRequestV1, ()> {
    let mut header_bytes = [0; ACQUIRE_TENURE_FRAME_HEADER_BYTES];
    stream.read_exact(&mut header_bytes).await.map_err(|_| ())?;
    let header = AcquireTenureFrameHeaderV1::decode_prefix(&header_bytes).map_err(|_| ())?;
    if header.kind() != AcquireTenureFrameKind::Request {
        return Err(());
    }
    let payload_length = usize::try_from(header.payload_bytes()).map_err(|_| ())?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(payload_length).map_err(|_| ())?;
    payload.resize(payload_length, 0);
    stream.read_exact(&mut payload).await.map_err(|_| ())?;
    AcquireTenureRequestV1::decode(&payload).map_err(|_| ())
}

fn fatal_authority_error(error: TenureAcquireError) -> bool {
    matches!(
        error,
        TenureAcquireError::InvalidStoredResponse
            | TenureAcquireError::SigningFailed
            | TenureAcquireError::ResponseEncodingFailed
            | TenureAcquireError::StoreStopped
            | TenureAcquireError::RejectedBeforePublish(_)
            | TenureAcquireError::UncertainAfterPublish(_)
            | TenureAcquireError::StoreUnavailableOrInvalid(_)
    )
}

struct DerivedProvisioningFacts {
    controller_public_key_fingerprint: [u8; 32],
    signing_key_fingerprint: Digest32,
    policy_fingerprint: Digest32,
    service_principal_fingerprint: Digest32,
    owner_identity_fingerprint: Digest32,
}

fn build_provisioning(
    config: &DeveloperLocalTenureAuthorityConfigV1,
    authority_verification_key: [u8; 32],
    socket_directory: &Path,
) -> Result<
    (TenureAuthorityProvisioning, DerivedProvisioningFacts),
    DeveloperLocalTenureAuthorityError,
> {
    if config.socket_path.parent() != Some(socket_directory) {
        return Err(DeveloperLocalTenureAuthorityError::InvalidConfiguration);
    }
    let signing_key_fingerprint = ed25519_authority_key_fingerprint(&authority_verification_key)
        .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    let controller_key_fingerprint =
        ControllerPublicKeyFingerprint::for_ed25519_key(&config.controller_verification_key)
            .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    let algorithm = TenureProofAlgorithm::try_new(ED25519_ALGORITHM)
        .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    let proof_authority = TenureProofAuthority::try_new(
        TenureAuthorityRef::from_bytes(config.identities.authority),
        TenureKeyRef::from_bytes(config.identities.authority_key),
        algorithm,
        ED25519_ALGORITHM_VERSION,
    )
    .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    let service_principal_fingerprint = digest_service_principal(config)?;
    let policy_fingerprint = digest_policy(
        config,
        signing_key_fingerprint,
        controller_key_fingerprint.as_bytes(),
    )?;
    let owner_identity_fingerprint = digest_owner(config, service_principal_fingerprint)?;
    let controller_authorization = ControllerAcquireAuthorization::try_new(
        PrincipalRef::from_bytes(config.identities.controller_principal),
        ControllerAcquireKeyRef::from_bytes(config.identities.controller_key),
        config.controller_verification_key,
        controller_key_fingerprint,
    )
    .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    let provisioning = TenureAuthorityProvisioning::try_new(
        DeploymentScopeId::from_bytes(config.identities.source_scope),
        DeploymentWriterRef::from_bytes(config.identities.writer),
        proof_authority,
        authority_verification_key,
        controller_authorization,
        TenureAuthorityFingerprints::new(
            signing_key_fingerprint,
            policy_fingerprint,
            service_principal_fingerprint,
            owner_identity_fingerprint,
        ),
    )
    .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    Ok((
        provisioning,
        DerivedProvisioningFacts {
            controller_public_key_fingerprint: *controller_key_fingerprint.as_bytes(),
            signing_key_fingerprint,
            policy_fingerprint,
            service_principal_fingerprint,
            owner_identity_fingerprint,
        },
    ))
}

fn digest_service_principal(
    config: &DeveloperLocalTenureAuthorityConfigV1,
) -> Result<Digest32, DeveloperLocalTenureAuthorityError> {
    let mut digest = digest_builder(SERVICE_PRINCIPAL_FINGERPRINT_DOMAIN)?;
    digest
        .field_bytes(&config.identities.service_principal)
        .and_then(|builder| builder.field_u64(u64::from(config.peer.uid)))
        .and_then(|builder| builder.field_u64(u64::from(config.peer.gid)))
        .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    Ok(digest.finish())
}

fn digest_policy(
    config: &DeveloperLocalTenureAuthorityConfigV1,
    signing_key_fingerprint: Digest32,
    controller_key_fingerprint: &[u8; 32],
) -> Result<Digest32, DeveloperLocalTenureAuthorityError> {
    let mut digest = digest_builder(POLICY_FINGERPRINT_DOMAIN)?;
    for value in [
        &config.identities.source_scope,
        &config.identities.writer,
        &config.identities.authority,
        &config.identities.authority_key,
        &config.identities.controller_principal,
        &config.identities.controller_key,
    ] {
        digest
            .field_bytes(value)
            .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    }
    digest
        .field_u16(ED25519_ALGORITHM)
        .and_then(|builder| builder.field_u16(ED25519_ALGORITHM_VERSION))
        .and_then(|builder| builder.field_digest(&signing_key_fingerprint))
        .and_then(|builder| builder.field_bytes(controller_key_fingerprint))
        .and_then(|builder| builder.field_u64(u64::from(config.peer.uid)))
        .and_then(|builder| builder.field_u64(u64::from(config.peer.gid)))
        .and_then(|builder| builder.field_u64(MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES as u64))
        .and_then(|builder| builder.field_u64(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES as u64))
        .and_then(|builder| builder.field_u64(MAX_ACQUIRE_TENURE_FRAME_BYTES as u64))
        .and_then(|builder| builder.field_u64(u64::from(STATE_DIRECTORY_MODE)))
        .and_then(|builder| builder.field_u64(u64::from(SOCKET_DIRECTORY_MODE)))
        .and_then(|builder| builder.field_u64(u64::from(SOCKET_MODE)))
        .and_then(|builder| builder.field_bytes(config.socket_path.as_os_str().as_bytes()))
        .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    Ok(digest.finish())
}

fn digest_owner(
    config: &DeveloperLocalTenureAuthorityConfigV1,
    service_principal_fingerprint: Digest32,
) -> Result<Digest32, DeveloperLocalTenureAuthorityError> {
    let mut digest = digest_builder(OWNER_IDENTITY_FINGERPRINT_DOMAIN)?;
    digest
        .field_bytes(&config.identities.owner)
        .and_then(|builder| builder.field_digest(&service_principal_fingerprint))
        .and_then(|builder| builder.field_bytes(&config.identities.source_scope))
        .and_then(|builder| builder.field_bytes(&config.identities.authority))
        .and_then(|builder| builder.field_bytes(&config.identities.authority_key))
        .and_then(|builder| builder.field_bytes(config.state_directory.as_os_str().as_bytes()))
        .and_then(|builder| builder.field_bytes(config.socket_path.as_os_str().as_bytes()))
        .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)?;
    Ok(digest.finish())
}

fn digest_builder(domain: &[u8]) -> Result<Digest32Builder, DeveloperLocalTenureAuthorityError> {
    Digest32Builder::try_new(domain)
        .map_err(|_| DeveloperLocalTenureAuthorityError::ProvisioningRejected)
}

fn identities_contain_zero_or_duplicate(
    identities: DeveloperLocalTenureAuthorityIdentityBytesV1,
) -> bool {
    let values = [
        identities.source_scope,
        identities.writer,
        identities.authority,
        identities.authority_key,
        identities.controller_principal,
        identities.controller_key,
        identities.service_principal,
        identities.owner,
    ];
    values
        .iter()
        .any(|value| value.iter().all(|byte| *byte == 0))
        || values
            .iter()
            .enumerate()
            .any(|(index, value)| values[index + 1..].contains(value))
}

fn validate_absolute_path(
    path: &Path,
    require_file_name: bool,
) -> Result<(), DeveloperLocalTenureAuthorityError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || path == Path::new("/")
        || bytes.contains(&0)
        || bytes.windows(2).any(|window| window == b"//")
        || (require_file_name && path.file_name().is_none())
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(DeveloperLocalTenureAuthorityError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_owned_directory(
    path: &Path,
    peer: DeveloperLocalPeerIdentityV1,
) -> Result<(), DeveloperLocalTenureAuthorityError> {
    validate_path_chain(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DeveloperLocalTenureAuthorityError::InvalidConfiguration)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != peer.uid
        || metadata.gid() != peer.gid
        || metadata.mode() & MODE_MASK != STATE_DIRECTORY_MODE
    {
        return Err(DeveloperLocalTenureAuthorityError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_path_chain(path: &Path) -> Result<(), DeveloperLocalTenureAuthorityError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current)
                    .map_err(|_| DeveloperLocalTenureAuthorityError::InvalidConfiguration)?;
                if metadata.file_type().is_symlink() {
                    return Err(DeveloperLocalTenureAuthorityError::InvalidConfiguration);
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(DeveloperLocalTenureAuthorityError::InvalidConfiguration);
            }
        }
    }
    Ok(())
}

struct SocketDirectory {
    path: PathBuf,
    file: File,
    identity: SocketIdentity,
    peer: DeveloperLocalPeerIdentityV1,
}

impl SocketDirectory {
    fn open(
        path: &Path,
        peer: DeveloperLocalPeerIdentityV1,
        expected_mode: u32,
    ) -> Result<Self, DeveloperLocalTenureAuthorityError> {
        validate_path_chain(path)?;
        let path_metadata = fs::symlink_metadata(path)
            .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
        if !path_metadata.file_type().is_dir()
            || path_metadata.uid() != peer.uid
            || path_metadata.gid() != peer.gid
            || path_metadata.mode() & MODE_MASK != expected_mode
        {
            return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
        }
        let owned = open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
        let file = File::from(owned);
        let opened = file
            .metadata()
            .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
        let identity = SocketIdentity::from_metadata(&opened);
        if !opened.file_type().is_dir()
            || !identity.matches(&path_metadata)
            || opened.uid() != peer.uid
            || opened.gid() != peer.gid
            || opened.mode() & MODE_MASK != expected_mode
        {
            return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
            peer,
        })
    }

    fn revalidate(&self) -> Result<(), DeveloperLocalTenureAuthorityError> {
        let opened = self
            .file
            .metadata()
            .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
        let path = fs::symlink_metadata(&self.path)
            .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
        if !self.identity.matches(&opened)
            || !self.identity.matches(&path)
            || !opened.file_type().is_dir()
            || !path.file_type().is_dir()
            || opened.uid() != self.peer.uid
            || opened.gid() != self.peer.gid
            || opened.mode() & MODE_MASK != SOCKET_DIRECTORY_MODE
        {
            return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    fn matches(self, metadata: &Metadata) -> bool {
        self.dev == metadata.dev() && self.ino == metadata.ino()
    }
}

struct SocketGuard {
    path: PathBuf,
    directory: SocketDirectory,
    identity: SocketIdentity,
    active: bool,
}

impl SocketGuard {
    fn cleanup(mut self) -> Result<(), DeveloperLocalTenureAuthorityError> {
        let result = remove_exact_socket(&self.directory, &self.path, self.identity);
        if result.is_ok() {
            self.active = false;
        }
        result
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = remove_exact_socket(&self.directory, &self.path, self.identity);
            self.active = false;
        }
    }
}

fn prepare_listener(
    directory: SocketDirectory,
    path: &Path,
) -> Result<(StdUnixListener, SocketGuard), DeveloperLocalTenureAuthorityError> {
    if path.parent() != Some(directory.path.as_path()) {
        return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
    }
    remove_stale_socket_if_present(&directory, path)?;
    let listener = StdUnixListener::bind(path)
        .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
    let initial = fs::symlink_metadata(path)
        .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
    let identity = SocketIdentity::from_metadata(&initial);
    let guard = SocketGuard {
        path: path.to_path_buf(),
        directory,
        identity,
        active: true,
    };
    let setup = (|| {
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
        validate_socket_metadata(&metadata, guard.directory.peer)?;
        if !identity.matches(&metadata) {
            return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
        }
        guard.directory.revalidate()?;
        guard
            .directory
            .file
            .sync_all()
            .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)
    })();
    if let Err(error) = setup {
        drop(listener);
        let _ = guard.cleanup();
        return Err(error);
    }
    Ok((listener, guard))
}

fn remove_stale_socket_if_present(
    directory: &SocketDirectory,
    path: &Path,
) -> Result<(), DeveloperLocalTenureAuthorityError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(DeveloperLocalTenureAuthorityError::SocketRejected),
    };
    validate_socket_metadata(&metadata, directory.peer)?;
    match StdUnixStream::connect(path) {
        Ok(stream) => {
            drop(stream);
            Err(DeveloperLocalTenureAuthorityError::SocketRejected)
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            remove_exact_socket(directory, path, SocketIdentity::from_metadata(&metadata))
        }
        Err(_) => Err(DeveloperLocalTenureAuthorityError::SocketRejected),
    }
}

fn validate_socket_metadata(
    metadata: &Metadata,
    peer: DeveloperLocalPeerIdentityV1,
) -> Result<(), DeveloperLocalTenureAuthorityError> {
    if !metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.uid() != peer.uid
        || metadata.gid() != peer.gid
        || metadata.mode() & MODE_MASK != SOCKET_MODE
    {
        return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
    }
    Ok(())
}

fn remove_exact_socket(
    directory: &SocketDirectory,
    path: &Path,
    expected: SocketIdentity,
) -> Result<(), DeveloperLocalTenureAuthorityError> {
    if path.parent() != Some(directory.path.as_path()) {
        return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
    }
    directory.revalidate()?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
    validate_socket_metadata(&metadata, directory.peer)?;
    if !expected.matches(&metadata) {
        return Err(DeveloperLocalTenureAuthorityError::SocketRejected);
    }
    let name = path
        .file_name()
        .ok_or(DeveloperLocalTenureAuthorityError::SocketRejected)?;
    unlinkat(&directory.file, name, UnlinkatFlags::NoRemoveDir)
        .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)?;
    directory
        .file
        .sync_all()
        .map_err(|_| DeveloperLocalTenureAuthorityError::SocketRejected)
}

/// Stable, display-safe developer lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeveloperLocalTenureAuthorityError {
    InvalidConfiguration,
    ProvisioningRejected,
    InitializationFailed,
    StoreRejected,
    SocketRejected,
    RuntimeFailed,
    StartupTimedOut,
    ServiceFailed,
    JoinFailed,
}

impl fmt::Display for DeveloperLocalTenureAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "developer-local Authority configuration was rejected",
            Self::ProvisioningRejected => "developer-local Authority provisioning was rejected",
            Self::InitializationFailed => "developer-local Authority initialization failed",
            Self::StoreRejected => "developer-local Authority store failed closed",
            Self::SocketRejected => "developer-local Authority socket failed closed",
            Self::RuntimeFailed => "developer-local Authority runtime failed",
            Self::StartupTimedOut => "developer-local Authority startup timed out",
            Self::ServiceFailed => "developer-local Authority service failed",
            Self::JoinFailed => "developer-local Authority service thread failed to join",
        })
    }
}

impl std::error::Error for DeveloperLocalTenureAuthorityError {}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_runtime_contracts::apply::{
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
    };
    use tokio::runtime::Builder as RuntimeBuilder;
    use zeroize::Zeroizing;

    use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
    use crate::tenure_client::{
        AcquireTenureRequestToSign, AuthorityProofVerifier, AuthoritySocketAcl,
        UnixAuthorityEndpoint, UnixCredentials, UnixTenureAuthorityClient,
    };
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{
        DeveloperLocalPeerIdentityV1, DeveloperLocalTenureAuthorityConfigV1,
        DeveloperLocalTenureAuthorityIdentityBytesV1, DeveloperLocalTenureAuthorityV1,
        SOCKET_DIRECTORY_MODE, STATE_DIRECTORY_MODE,
    };

    const AUTHORITY_SEED: [u8; 32] = [0xa1; 32];
    const CONTROLLER_SEED: [u8; 32] = [0xb2; 32];
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        root: PathBuf,
        state: PathBuf,
        socket_directory: PathBuf,
        socket: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Self {
            let temporary_root = fs::canonicalize(std::env::temp_dir())
                .unwrap_or_else(|error| panic!("temporary root canonicalization failed: {error}"));
            let root = temporary_root.join(format!(
                "pxa-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root)
                .unwrap_or_else(|error| panic!("developer root create failed: {error}"));
            fs::set_permissions(&root, fs::Permissions::from_mode(STATE_DIRECTORY_MODE))
                .unwrap_or_else(|error| panic!("developer root mode failed: {error}"));
            let state = root.join("s");
            fs::create_dir(&state)
                .unwrap_or_else(|error| panic!("Authority state create failed: {error}"));
            fs::set_permissions(&state, fs::Permissions::from_mode(STATE_DIRECTORY_MODE))
                .unwrap_or_else(|error| panic!("Authority state mode failed: {error}"));
            let socket_directory = root.join("r");
            fs::create_dir(&socket_directory)
                .unwrap_or_else(|error| panic!("Authority run create failed: {error}"));
            fs::set_permissions(
                &socket_directory,
                fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE),
            )
            .unwrap_or_else(|error| panic!("Authority run mode failed: {error}"));
            let socket = socket_directory.join("a");
            Self {
                root,
                state,
                socket_directory,
                socket,
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn identities() -> DeveloperLocalTenureAuthorityIdentityBytesV1 {
        DeveloperLocalTenureAuthorityIdentityBytesV1 {
            source_scope: [0x11; 16],
            writer: [0x22; 16],
            authority: [0x33; 16],
            authority_key: [0x44; 16],
            controller_principal: [0x55; 16],
            controller_key: [0x66; 16],
            service_principal: [0x77; 16],
            owner: [0x88; 16],
        }
    }

    fn config(
        directory: &TestDirectory,
        expected_store: Option<[u8; 32]>,
    ) -> DeveloperLocalTenureAuthorityConfigV1 {
        DeveloperLocalTenureAuthorityConfigV1::try_new(
            directory.state.clone(),
            directory.socket.clone(),
            identities(),
            Zeroizing::new(AUTHORITY_SEED),
            SigningKey::from_bytes(&CONTROLLER_SEED)
                .verifying_key()
                .to_bytes(),
            expected_store,
            DeveloperLocalPeerIdentityV1::current()
                .unwrap_or_else(|error| panic!("current peer rejected: {error}")),
        )
        .unwrap_or_else(|error| panic!("developer config rejected: {error}"))
    }

    fn prepared_request() -> crate::tenure_client::PreparedAcquireTenureRequest {
        let ids = identities();
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let fingerprint =
            ControllerPublicKeyFingerprint::for_ed25519_key(&controller.verifying_key().to_bytes())
                .unwrap_or_else(|error| panic!("controller fingerprint failed: {error}"));
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                DeploymentScopeId::from_bytes(ids.source_scope),
                DeploymentWriterRef::from_bytes(ids.writer),
                AcquireTenureOperationId::from_bytes([0x99; 16]),
            ),
            PrincipalRef::from_bytes(ids.controller_principal),
            ControllerAcquireKeyRef::from_bytes(ids.controller_key),
            fingerprint,
            &[0xaa; 32],
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .unwrap_or_else(|error| panic!("response bound failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("request draft failed: {error}"));
        let to_sign = AcquireTenureRequestToSign::try_new(draft)
            .unwrap_or_else(|error| panic!("request preparation failed: {error}"));
        let signature = controller.sign(to_sign.signing_bytes());
        to_sign
            .finalize_ed25519(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("request finalization failed: {error}"))
    }

    fn client(authority: &DeveloperLocalTenureAuthorityV1) -> UnixTenureAuthorityClient {
        let facts = authority.facts();
        let ids = facts.identities();
        let peer = facts.peer();
        let endpoint = UnixAuthorityEndpoint::try_new(
            facts.socket_path().to_path_buf(),
            AuthoritySocketAcl::new(peer.uid(), peer.gid()),
            UnixCredentials::new(peer.uid(), peer.gid()),
        )
        .unwrap_or_else(|error| panic!("Authority endpoint failed: {error}"));
        let selector = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes(ids.authority),
            TenureKeyRef::from_bytes(ids.authority_key),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("proof algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("proof selector failed: {error}"));
        let verifier = AuthorityProofVerifier::try_new(
            selector,
            VerifyingKey::from_bytes(&facts.authority_verification_key())
                .unwrap_or_else(|error| panic!("Authority key failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("proof verifier failed: {error}"));
        UnixTenureAuthorityClient::try_new(endpoint, verifier, Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("Authority client failed: {error}"))
    }

    fn run_async<T>(future: impl Future<Output = T>) -> T {
        RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap_or_else(|error| panic!("test runtime failed: {error}"))
            .block_on(future)
    }

    #[test]
    fn real_wire_commits_replays_restarts_and_joins_exactly() {
        let directory = TestDirectory::create();
        let mut authority = DeveloperLocalTenureAuthorityV1::start(config(&directory, None))
            .unwrap_or_else(|error| panic!("Authority start failed: {error}"));
        assert_eq!(authority.try_poll_exit(), Ok(false));
        let store = authority.facts().store_instance_id();
        let prepared = prepared_request();
        let first = run_async(client(&authority).exchange(&prepared))
            .unwrap_or_else(|error| panic!("first Authority exchange failed: {error}"));
        let replay = run_async(client(&authority).exchange(&prepared))
            .unwrap_or_else(|error| panic!("replayed Authority exchange failed: {error}"));
        assert_eq!(first.canonical_bytes(), replay.canonical_bytes());
        assert_eq!(first.proof().claim().epoch().value(), 1);
        authority
            .shutdown()
            .unwrap_or_else(|error| panic!("Authority shutdown failed: {error}"));
        assert!(!directory.socket.exists());

        let restarted = DeveloperLocalTenureAuthorityV1::start(config(&directory, Some(store)))
            .unwrap_or_else(|error| panic!("Authority restart failed: {error}"));
        let after_restart = run_async(client(&restarted).exchange(&prepared))
            .unwrap_or_else(|error| panic!("restart replay failed: {error}"));
        assert_eq!(first.canonical_bytes(), after_restart.canonical_bytes());
        restarted
            .shutdown()
            .unwrap_or_else(|error| panic!("restarted shutdown failed: {error}"));
        assert!(!directory.socket.exists());
        assert!(directory.socket_directory.exists());
    }

    #[test]
    fn config_rejects_zero_duplicate_and_nested_socket_state() {
        let directory = TestDirectory::create();
        let peer = DeveloperLocalPeerIdentityV1::current()
            .unwrap_or_else(|error| panic!("current peer rejected: {error}"));
        let mut invalid = identities();
        invalid.authority_key = invalid.authority;
        assert!(
            DeveloperLocalTenureAuthorityConfigV1::try_new(
                directory.state.clone(),
                directory.state.join("authority.sock"),
                invalid,
                Zeroizing::new(AUTHORITY_SEED),
                SigningKey::from_bytes(&CONTROLLER_SEED)
                    .verifying_key()
                    .to_bytes(),
                None,
                peer,
            )
            .is_err()
        );
    }

    #[test]
    fn drop_is_joined_and_removes_only_its_socket() {
        let directory = TestDirectory::create();
        {
            let authority = DeveloperLocalTenureAuthorityV1::start(config(&directory, None))
                .unwrap_or_else(|error| panic!("Authority start failed: {error}"));
            assert_eq!(
                authority.facts().socket_path(),
                Path::new(&directory.socket)
            );
            assert!(directory.socket.exists());
        }
        assert!(!directory.socket.exists());
    }
}
