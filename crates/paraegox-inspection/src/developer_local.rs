//! Strict same-user DeveloperLocal bootstrap and request framing.
//!
//! This module owns only the bounded PXIB bootstrap bytes and the outer
//! generation-token envelope for one canonical PXIQ request. Socket binding,
//! peer-credential checks, timeouts, projection and lifecycle remain with the
//! executable producer/consumer. It is not a discovery or operational path.

use core::fmt;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use paraegox_kernel::digest::{Digest32, Digest32Builder};
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    INSPECTION_REQUEST_BYTES, INSPECTION_REQUEST_V2_BYTES, InspectionProtocolError,
    InspectionRequestV1, InspectionRequestV2,
};

/// Fixed PXIB version.
pub const DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_VERSION: u16 = 1;
/// Fixed PXIB header bytes before the Unix socket path.
pub const DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES: usize = 128;
/// Maximum bounded PXIB frame including its socket path.
pub const MAX_DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_BYTES: usize =
    DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES + MAX_BOOTSTRAP_PATH_BYTES;
/// Fixed authenticated outer request bytes: token plus canonical PXIQ.
pub const DEVELOPER_LOCAL_INSPECTION_REQUEST_BYTES: usize =
    GENERATION_TOKEN_BYTES + INSPECTION_REQUEST_BYTES;
/// Explicit PXIB-v2 bootstrap version for a PXIQ/PXIP-v2 endpoint.
pub const DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_VERSION: u16 = 2;
/// Fixed PXIB-v2 header bytes before the Unix socket path.
pub const DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES: usize = 128;
/// Maximum bounded PXIB-v2 frame including its socket path.
pub const MAX_DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_BYTES: usize =
    DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES + MAX_BOOTSTRAP_PATH_BYTES;
/// Fixed authenticated v2 outer request bytes: token plus canonical PXIQ-v2.
pub const DEVELOPER_LOCAL_INSPECTION_REQUEST_V2_BYTES: usize =
    GENERATION_TOKEN_BYTES + INSPECTION_REQUEST_V2_BYTES;

const BOOTSTRAP_MAGIC: &[u8; 4] = b"PXIB";
const BOOTSTRAP_DIGEST_OFFSET: usize = 96;
const GENERATION_TOKEN_BYTES: usize = 32;
const REQUEST_SEED_BYTES: usize = 16;
const MAX_BOOTSTRAP_PATH_BYTES: usize = 512;
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const BOOTSTRAP_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.developer-local.bootstrap.v1";
const REQUEST_ID_DOMAIN: &[u8] = b"paraegox.inspection.developer-local.request-id.v1";
const BOOTSTRAP_V2_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.developer-local.bootstrap.v2";
const REQUEST_ID_V2_DOMAIN: &[u8] = b"paraegox.inspection.developer-local.request-id.v2";

/// Strict bootstrap loaded from an owner-private PXIB file.
pub struct DeveloperLocalInspectionBootstrapV1 {
    socket_path: PathBuf,
    projection_id: [u8; 16],
    generation_token: Zeroizing<[u8; GENERATION_TOKEN_BYTES]>,
    server_uid: u32,
    server_gid: u32,
    operation_timeout_nanos: u64,
    request_seed: Zeroizing<[u8; REQUEST_SEED_BYTES]>,
}

impl fmt::Debug for DeveloperLocalInspectionBootstrapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalInspectionBootstrapV1")
            .field("socket_path", &self.socket_path)
            .field("projection_id", &self.projection_id)
            .field("generation_token", &"<redacted>")
            .field("server_uid", &self.server_uid)
            .field("server_gid", &self.server_gid)
            .field("operation_timeout_nanos", &self.operation_timeout_nanos)
            .field("request_seed", &"<redacted>")
            .finish()
    }
}

impl DeveloperLocalInspectionBootstrapV1 {
    /// Validates one exact socket identity, capability token and read budget.
    pub fn try_new(
        socket_path: PathBuf,
        projection_id: [u8; 16],
        generation_token: Zeroizing<[u8; GENERATION_TOKEN_BYTES]>,
        server_uid: u32,
        server_gid: u32,
        operation_timeout: Duration,
        request_seed: Zeroizing<[u8; REQUEST_SEED_BYTES]>,
    ) -> Result<Self, DeveloperLocalInspectionTransportErrorV1> {
        validate_socket_path(&socket_path)?;
        let operation_timeout_nanos = u64::try_from(operation_timeout.as_nanos())
            .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?;
        if bytes_are_zero(&projection_id)
            || generation_token.iter().all(|byte| *byte == 0)
            || request_seed.iter().all(|byte| *byte == 0)
            || server_uid == 0
            || server_gid == 0
            || operation_timeout.is_zero()
            || operation_timeout > MAX_OPERATION_TIMEOUT
        {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
        }
        Ok(Self {
            socket_path,
            projection_id,
            generation_token,
            server_uid,
            server_gid,
            operation_timeout_nanos,
            request_seed,
        })
    }

    /// Strictly decodes one complete canonical PXIB frame.
    pub fn decode(wire: &[u8]) -> Result<Self, DeveloperLocalInspectionTransportErrorV1> {
        if wire.len() < DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES
            || wire.len() > MAX_DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_BYTES
            || &wire[..4] != BOOTSTRAP_MAGIC
            || read_u16(wire, 4) != DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_VERSION
            || usize::from(read_u16(wire, 6)) != DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES
        {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
        }
        let frame_length = usize::try_from(read_u32(wire, 8))
            .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?;
        let path_length = usize::try_from(read_u32(wire, 12))
            .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?;
        if frame_length != wire.len()
            || path_length == 0
            || path_length > MAX_BOOTSTRAP_PATH_BYTES
            || DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES.checked_add(path_length)
                != Some(wire.len())
        {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
        }
        let projection_id = copy_array::<16>(wire, 16);
        let generation_token = Zeroizing::new(copy_array::<GENERATION_TOKEN_BYTES>(wire, 32));
        let server_uid = read_u32(wire, 64);
        let server_gid = read_u32(wire, 68);
        let operation_timeout = Duration::from_nanos(read_u64(wire, 72));
        let request_seed = Zeroizing::new(copy_array::<REQUEST_SEED_BYTES>(wire, 80));
        let socket_path = PathBuf::from(OsString::from_vec(
            wire[DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES..].to_vec(),
        ));
        let value = Self::try_new(
            socket_path,
            projection_id,
            generation_token,
            server_uid,
            server_gid,
            operation_timeout,
            request_seed,
        )?;
        let declared = Digest32::from_bytes(copy_array::<32>(wire, BOOTSTRAP_DIGEST_OFFSET));
        if declared != bootstrap_digest(&value)? || value.encode()?.as_slice() != wire {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
        }
        Ok(value)
    }

    /// Strictly decodes an owned PXIB frame and zeroizes its capability bytes
    /// when decoding finishes.
    pub fn decode_owned(wire: Vec<u8>) -> Result<Self, DeveloperLocalInspectionTransportErrorV1> {
        let wire = Zeroizing::new(wire);
        Self::decode(&wire)
    }

    /// Encodes one complete PXIB frame. The returned bytes zeroize on drop.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DeveloperLocalInspectionTransportErrorV1> {
        let path = self.socket_path.as_os_str().as_bytes();
        let frame_length = DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES
            .checked_add(path.len())
            .ok_or(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?;
        let mut wire = Zeroizing::new(vec![0_u8; frame_length]);
        wire[..4].copy_from_slice(BOOTSTRAP_MAGIC);
        wire[4..6].copy_from_slice(&DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_VERSION.to_be_bytes());
        wire[6..8].copy_from_slice(
            &u16::try_from(DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES)
                .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?
                .to_be_bytes(),
        );
        wire[8..12].copy_from_slice(
            &u32::try_from(frame_length)
                .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?
                .to_be_bytes(),
        );
        wire[12..16].copy_from_slice(
            &u32::try_from(path.len())
                .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?
                .to_be_bytes(),
        );
        wire[16..32].copy_from_slice(&self.projection_id);
        wire[32..64].copy_from_slice(self.generation_token.as_ref());
        wire[64..68].copy_from_slice(&self.server_uid.to_be_bytes());
        wire[68..72].copy_from_slice(&self.server_gid.to_be_bytes());
        wire[72..80].copy_from_slice(&self.operation_timeout_nanos.to_be_bytes());
        wire[80..96].copy_from_slice(self.request_seed.as_ref());
        wire[BOOTSTRAP_DIGEST_OFFSET..DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES]
            .copy_from_slice(bootstrap_digest(self)?.as_bytes());
        wire[DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES..].copy_from_slice(path);
        Ok(wire)
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub const fn projection_id(&self) -> [u8; 16] {
        self.projection_id
    }

    #[must_use]
    pub fn generation_token(&self) -> &[u8; GENERATION_TOKEN_BYTES] {
        &self.generation_token
    }

    #[must_use]
    pub const fn server_uid(&self) -> u32 {
        self.server_uid
    }

    #[must_use]
    pub const fn server_gid(&self) -> u32 {
        self.server_gid
    }

    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        Duration::from_nanos(self.operation_timeout_nanos)
    }

    /// Derives a nonzero correlation identity for one caller-owned sequence.
    pub fn request_id(
        &self,
        sequence: u64,
    ) -> Result<[u8; 16], DeveloperLocalInspectionTransportErrorV1> {
        if sequence == 0 {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidRequestSequence);
        }
        let mut builder = Digest32Builder::try_new(REQUEST_ID_DOMAIN)
            .map_err(|_| DeveloperLocalInspectionTransportErrorV1::DigestUnavailable)?;
        builder
            .field_bytes(self.request_seed.as_ref())
            .and_then(|builder| builder.field_bytes(&self.projection_id))
            .and_then(|builder| builder.field_u64(sequence))
            .map_err(|_| DeveloperLocalInspectionTransportErrorV1::DigestUnavailable)?;
        let digest = builder.finish();
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&digest.as_bytes()[..16]);
        if bytes_are_zero(&request_id) {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidRequestSequence);
        }
        Ok(request_id)
    }
}

impl Drop for DeveloperLocalInspectionBootstrapV1 {
    fn drop(&mut self) {
        self.generation_token.zeroize();
        self.request_seed.zeroize();
    }
}

/// Strict owner-private bootstrap for one DeveloperLocal PXIQ/PXIP-v2
/// endpoint. It is intentionally separate from PXIB-v1 so protocol selection
/// cannot be inferred from an otherwise identical path or capability.
pub struct DeveloperLocalInspectionBootstrapV2 {
    socket_path: PathBuf,
    projection_id: [u8; 16],
    generation_token: Zeroizing<[u8; GENERATION_TOKEN_BYTES]>,
    server_uid: u32,
    server_gid: u32,
    operation_timeout_nanos: u64,
    request_seed: Zeroizing<[u8; REQUEST_SEED_BYTES]>,
}

impl fmt::Debug for DeveloperLocalInspectionBootstrapV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalInspectionBootstrapV2")
            .field("socket_path", &self.socket_path)
            .field("projection_id", &self.projection_id)
            .field("generation_token", &"<redacted>")
            .field("server_uid", &self.server_uid)
            .field("server_gid", &self.server_gid)
            .field("operation_timeout_nanos", &self.operation_timeout_nanos)
            .field("request_seed", &"<redacted>")
            .finish()
    }
}

impl DeveloperLocalInspectionBootstrapV2 {
    pub fn try_new(
        socket_path: PathBuf,
        projection_id: [u8; 16],
        generation_token: Zeroizing<[u8; GENERATION_TOKEN_BYTES]>,
        server_uid: u32,
        server_gid: u32,
        operation_timeout: Duration,
        request_seed: Zeroizing<[u8; REQUEST_SEED_BYTES]>,
    ) -> Result<Self, DeveloperLocalInspectionTransportErrorV2> {
        validate_socket_path(&socket_path)?;
        let operation_timeout_nanos = u64::try_from(operation_timeout.as_nanos())
            .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?;
        if bytes_are_zero(&projection_id)
            || generation_token.iter().all(|byte| *byte == 0)
            || request_seed.iter().all(|byte| *byte == 0)
            || server_uid == 0
            || server_gid == 0
            || operation_timeout.is_zero()
            || operation_timeout > MAX_OPERATION_TIMEOUT
        {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
        }
        Ok(Self {
            socket_path,
            projection_id,
            generation_token,
            server_uid,
            server_gid,
            operation_timeout_nanos,
            request_seed,
        })
    }

    pub fn decode(wire: &[u8]) -> Result<Self, DeveloperLocalInspectionTransportErrorV2> {
        if wire.len() < DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES
            || wire.len() > MAX_DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_BYTES
            || &wire[..4] != BOOTSTRAP_MAGIC
            || read_u16(wire, 4) != DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_VERSION
            || usize::from(read_u16(wire, 6))
                != DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES
        {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
        }
        let frame_length = usize::try_from(read_u32(wire, 8))
            .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?;
        let path_length = usize::try_from(read_u32(wire, 12))
            .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?;
        if frame_length != wire.len()
            || path_length == 0
            || path_length > MAX_BOOTSTRAP_PATH_BYTES
            || DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES.checked_add(path_length)
                != Some(wire.len())
        {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
        }
        let value = Self::try_new(
            PathBuf::from(OsString::from_vec(
                wire[DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES..].to_vec(),
            )),
            copy_array::<16>(wire, 16),
            Zeroizing::new(copy_array::<GENERATION_TOKEN_BYTES>(wire, 32)),
            read_u32(wire, 64),
            read_u32(wire, 68),
            Duration::from_nanos(read_u64(wire, 72)),
            Zeroizing::new(copy_array::<REQUEST_SEED_BYTES>(wire, 80)),
        )?;
        let declared = Digest32::from_bytes(copy_array::<32>(wire, BOOTSTRAP_DIGEST_OFFSET));
        if declared != bootstrap_v2_digest(&value)? || value.encode()?.as_slice() != wire {
            return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
        }
        Ok(value)
    }

    pub fn decode_owned(wire: Vec<u8>) -> Result<Self, DeveloperLocalInspectionTransportErrorV2> {
        let wire = Zeroizing::new(wire);
        Self::decode(&wire)
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DeveloperLocalInspectionTransportErrorV2> {
        let path = self.socket_path.as_os_str().as_bytes();
        let frame_length = DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES
            .checked_add(path.len())
            .ok_or(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?;
        let mut wire = Zeroizing::new(vec![0_u8; frame_length]);
        wire[..4].copy_from_slice(BOOTSTRAP_MAGIC);
        wire[4..6].copy_from_slice(&DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_VERSION.to_be_bytes());
        wire[6..8].copy_from_slice(
            &u16::try_from(DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES)
                .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?
                .to_be_bytes(),
        );
        wire[8..12].copy_from_slice(
            &u32::try_from(frame_length)
                .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?
                .to_be_bytes(),
        );
        wire[12..16].copy_from_slice(
            &u32::try_from(path.len())
                .map_err(|_| DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)?
                .to_be_bytes(),
        );
        wire[16..32].copy_from_slice(&self.projection_id);
        wire[32..64].copy_from_slice(self.generation_token.as_ref());
        wire[64..68].copy_from_slice(&self.server_uid.to_be_bytes());
        wire[68..72].copy_from_slice(&self.server_gid.to_be_bytes());
        wire[72..80].copy_from_slice(&self.operation_timeout_nanos.to_be_bytes());
        wire[80..96].copy_from_slice(self.request_seed.as_ref());
        wire[BOOTSTRAP_DIGEST_OFFSET..DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES]
            .copy_from_slice(bootstrap_v2_digest(self)?.as_bytes());
        wire[DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES..].copy_from_slice(path);
        Ok(wire)
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub const fn projection_id(&self) -> [u8; 16] {
        self.projection_id
    }

    #[must_use]
    pub fn generation_token(&self) -> &[u8; GENERATION_TOKEN_BYTES] {
        &self.generation_token
    }

    #[must_use]
    pub const fn server_uid(&self) -> u32 {
        self.server_uid
    }

    #[must_use]
    pub const fn server_gid(&self) -> u32 {
        self.server_gid
    }

    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        Duration::from_nanos(self.operation_timeout_nanos)
    }

    pub fn request_id(
        &self,
        sequence: u64,
    ) -> Result<[u8; 16], DeveloperLocalInspectionTransportErrorV2> {
        if sequence == 0 {
            return Err(DeveloperLocalInspectionTransportErrorV2::InvalidRequestSequence);
        }
        let mut builder = Digest32Builder::try_new(REQUEST_ID_V2_DOMAIN)
            .map_err(|_| DeveloperLocalInspectionTransportErrorV2::DigestUnavailable)?;
        builder
            .field_bytes(self.request_seed.as_ref())
            .and_then(|builder| builder.field_bytes(&self.projection_id))
            .and_then(|builder| builder.field_u64(sequence))
            .map_err(|_| DeveloperLocalInspectionTransportErrorV2::DigestUnavailable)?;
        let digest = builder.finish();
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&digest.as_bytes()[..16]);
        if bytes_are_zero(&request_id) {
            return Err(DeveloperLocalInspectionTransportErrorV2::InvalidRequestSequence);
        }
        Ok(request_id)
    }
}

impl Drop for DeveloperLocalInspectionBootstrapV2 {
    fn drop(&mut self) {
        self.generation_token.zeroize();
        self.request_seed.zeroize();
    }
}

/// V2 keeps the bounded DeveloperLocal transport error taxonomy while using
/// distinct bootstrap and protocol versions on the wire.
pub type DeveloperLocalInspectionTransportErrorV2 = DeveloperLocalInspectionTransportErrorV1;

/// Adds the generation token to one already canonical PXIQ request.
pub fn encode_authenticated_request_v1(
    generation_token: &[u8; GENERATION_TOKEN_BYTES],
    request: &InspectionRequestV1,
) -> Result<Zeroizing<Vec<u8>>, DeveloperLocalInspectionTransportErrorV1> {
    if generation_token.iter().all(|byte| *byte == 0)
        || request.canonical_wire().len() != INSPECTION_REQUEST_BYTES
    {
        return Err(DeveloperLocalInspectionTransportErrorV1::InvalidAuthenticatedRequest);
    }
    let mut wire = Zeroizing::new(vec![0_u8; DEVELOPER_LOCAL_INSPECTION_REQUEST_BYTES]);
    wire[..GENERATION_TOKEN_BYTES].copy_from_slice(generation_token);
    wire[GENERATION_TOKEN_BYTES..].copy_from_slice(request.canonical_wire());
    Ok(wire)
}

/// Authenticates and strictly decodes one exact token-plus-PXIQ request.
pub fn decode_authenticated_request_v1(
    wire: &[u8],
    expected_generation_token: &[u8; GENERATION_TOKEN_BYTES],
) -> Result<InspectionRequestV1, DeveloperLocalInspectionTransportErrorV1> {
    if wire.len() != DEVELOPER_LOCAL_INSPECTION_REQUEST_BYTES
        || expected_generation_token.iter().all(|byte| *byte == 0)
        || !constant_time_eq(&wire[..GENERATION_TOKEN_BYTES], expected_generation_token)
    {
        return Err(DeveloperLocalInspectionTransportErrorV1::AuthenticationFailed);
    }
    InspectionRequestV1::decode(&wire[GENERATION_TOKEN_BYTES..])
        .map_err(DeveloperLocalInspectionTransportErrorV1::InvalidProtocolRequest)
}

/// Adds the generation token to one already canonical PXIQ-v2 request.
pub fn encode_authenticated_request_v2(
    generation_token: &[u8; GENERATION_TOKEN_BYTES],
    request: &InspectionRequestV2,
) -> Result<Zeroizing<Vec<u8>>, DeveloperLocalInspectionTransportErrorV2> {
    if generation_token.iter().all(|byte| *byte == 0)
        || request.canonical_wire().len() != INSPECTION_REQUEST_V2_BYTES
    {
        return Err(DeveloperLocalInspectionTransportErrorV2::InvalidAuthenticatedRequest);
    }
    let mut wire = Zeroizing::new(vec![0_u8; DEVELOPER_LOCAL_INSPECTION_REQUEST_V2_BYTES]);
    wire[..GENERATION_TOKEN_BYTES].copy_from_slice(generation_token);
    wire[GENERATION_TOKEN_BYTES..].copy_from_slice(request.canonical_wire());
    Ok(wire)
}

/// Authenticates and strictly decodes one exact token-plus-PXIQ-v2 request.
pub fn decode_authenticated_request_v2(
    wire: &[u8],
    expected_generation_token: &[u8; GENERATION_TOKEN_BYTES],
) -> Result<InspectionRequestV2, DeveloperLocalInspectionTransportErrorV2> {
    if wire.len() != DEVELOPER_LOCAL_INSPECTION_REQUEST_V2_BYTES
        || expected_generation_token.iter().all(|byte| *byte == 0)
        || !constant_time_eq(&wire[..GENERATION_TOKEN_BYTES], expected_generation_token)
    {
        return Err(DeveloperLocalInspectionTransportErrorV2::AuthenticationFailed);
    }
    InspectionRequestV2::decode(&wire[GENERATION_TOKEN_BYTES..])
        .map_err(DeveloperLocalInspectionTransportErrorV2::InvalidProtocolRequest)
}

fn bootstrap_digest(
    value: &DeveloperLocalInspectionBootstrapV1,
) -> Result<Digest32, DeveloperLocalInspectionTransportErrorV1> {
    let mut builder = Digest32Builder::try_new(BOOTSTRAP_DIGEST_DOMAIN)
        .map_err(|_| DeveloperLocalInspectionTransportErrorV1::DigestUnavailable)?;
    builder
        .field_u16(DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_VERSION)
        .and_then(|builder| builder.field_bytes(&value.projection_id))
        .and_then(|builder| builder.field_bytes(value.generation_token.as_ref()))
        .and_then(|builder| builder.field_u64(u64::from(value.server_uid)))
        .and_then(|builder| builder.field_u64(u64::from(value.server_gid)))
        .and_then(|builder| builder.field_u64(value.operation_timeout_nanos))
        .and_then(|builder| builder.field_bytes(value.request_seed.as_ref()))
        .and_then(|builder| builder.field_bytes(value.socket_path.as_os_str().as_bytes()))
        .map_err(|_| DeveloperLocalInspectionTransportErrorV1::DigestUnavailable)?;
    Ok(builder.finish())
}

fn bootstrap_v2_digest(
    value: &DeveloperLocalInspectionBootstrapV2,
) -> Result<Digest32, DeveloperLocalInspectionTransportErrorV2> {
    let mut builder = Digest32Builder::try_new(BOOTSTRAP_V2_DIGEST_DOMAIN)
        .map_err(|_| DeveloperLocalInspectionTransportErrorV2::DigestUnavailable)?;
    builder
        .field_u16(DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_VERSION)
        .and_then(|builder| builder.field_bytes(&value.projection_id))
        .and_then(|builder| builder.field_bytes(value.generation_token.as_ref()))
        .and_then(|builder| builder.field_u64(u64::from(value.server_uid)))
        .and_then(|builder| builder.field_u64(u64::from(value.server_gid)))
        .and_then(|builder| builder.field_u64(value.operation_timeout_nanos))
        .and_then(|builder| builder.field_bytes(value.request_seed.as_ref()))
        .and_then(|builder| builder.field_bytes(value.socket_path.as_os_str().as_bytes()))
        .map_err(|_| DeveloperLocalInspectionTransportErrorV2::DigestUnavailable)?;
    Ok(builder.finish())
}

fn validate_socket_path(path: &Path) -> Result<(), DeveloperLocalInspectionTransportErrorV1> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || path.file_name().is_none()
        || bytes.is_empty()
        || bytes.len() > MAX_BOOTSTRAP_PATH_BYTES
        || bytes.contains(&0)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap);
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(copy_array(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(copy_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(copy_array(bytes, offset))
}

fn copy_array<const BYTES: usize>(bytes: &[u8], offset: usize) -> [u8; BYTES] {
    let mut value = [0_u8; BYTES];
    value.copy_from_slice(&bytes[offset..offset + BYTES]);
    value
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Strict DeveloperLocal bootstrap or request-envelope failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeveloperLocalInspectionTransportErrorV1 {
    InvalidBootstrap,
    DigestUnavailable,
    InvalidRequestSequence,
    InvalidAuthenticatedRequest,
    AuthenticationFailed,
    InvalidProtocolRequest(InspectionProtocolError),
}

impl fmt::Display for DeveloperLocalInspectionTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBootstrap => "DeveloperLocal Inspection bootstrap is invalid",
            Self::DigestUnavailable => "DeveloperLocal Inspection digest is unavailable",
            Self::InvalidRequestSequence => "DeveloperLocal Inspection request sequence is invalid",
            Self::InvalidAuthenticatedRequest => {
                "DeveloperLocal Inspection authenticated request is invalid"
            }
            Self::AuthenticationFailed => {
                "DeveloperLocal Inspection generation authentication failed"
            }
            Self::InvalidProtocolRequest(_) => {
                "DeveloperLocal Inspection canonical request is invalid"
            }
        })
    }
}

impl std::error::Error for DeveloperLocalInspectionTransportErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProtocolRequest(error) => Some(error),
            Self::InvalidBootstrap
            | Self::DigestUnavailable
            | Self::InvalidRequestSequence
            | Self::InvalidAuthenticatedRequest
            | Self::AuthenticationFailed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[usize::from(byte >> 4)] as char);
            output.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        output
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let value = value.trim();
        assert_eq!(value.len() % 2, 0, "golden hex length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid golden hex"),
        }
    }

    fn bootstrap(token: u8) -> DeveloperLocalInspectionBootstrapV1 {
        DeveloperLocalInspectionBootstrapV1::try_new(
            PathBuf::from("/private/tmp/pxl-test/i.sock"),
            [0x21; 16],
            Zeroizing::new([token; 32]),
            501,
            20,
            Duration::from_secs(3),
            Zeroizing::new([0x33; 16]),
        )
        .expect("bootstrap")
    }

    fn bootstrap_v2(token: u8) -> DeveloperLocalInspectionBootstrapV2 {
        DeveloperLocalInspectionBootstrapV2::try_new(
            PathBuf::from("/private/tmp/pxl-test/i-v2.sock"),
            [0x31; 16],
            Zeroizing::new([token; 32]),
            501,
            20,
            Duration::from_secs(3),
            Zeroizing::new([0x43; 16]),
        )
        .expect("v2 bootstrap")
    }

    fn cross_language_bootstrap_v2() -> DeveloperLocalInspectionBootstrapV2 {
        DeveloperLocalInspectionBootstrapV2::try_new(
            PathBuf::from("/tmp/inspection.sock"),
            [0x21; 16],
            Zeroizing::new([0x5b; 32]),
            501,
            20,
            Duration::from_secs(2),
            Zeroizing::new([0x6c; 16]),
        )
        .expect("cross-language v2 bootstrap")
    }

    #[test]
    fn pxib_round_trip_commits_every_security_field_and_redacts_debug() {
        let value = bootstrap(0x44);
        let wire = value.encode().expect("PXIB encode");
        let decoded = DeveloperLocalInspectionBootstrapV1::decode(&wire).expect("PXIB decode");
        assert_eq!(decoded.socket_path(), value.socket_path());
        assert_eq!(decoded.projection_id(), value.projection_id());
        assert_eq!(decoded.generation_token(), value.generation_token());
        assert_eq!(decoded.server_uid(), 501);
        assert_eq!(decoded.server_gid(), 20);
        assert_eq!(decoded.operation_timeout(), Duration::from_secs(3));
        assert_eq!(decoded.request_id(1), value.request_id(1));
        assert_ne!(decoded.request_id(1), decoded.request_id(2));
        let debug = format!("{decoded:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&"44".repeat(32)));
    }

    #[test]
    fn pxib_rejects_corruption_trailing_bytes_and_zero_security_fields() {
        let value = bootstrap(0x45);
        let wire = value.encode().expect("PXIB encode");
        for offset in [4, 16, 32, 64, 72, 80, 96, wire.len() - 1] {
            let mut corrupted = Zeroizing::new(wire.to_vec());
            corrupted[offset] ^= 1;
            assert_eq!(
                DeveloperLocalInspectionBootstrapV1::decode(&corrupted).err(),
                Some(DeveloperLocalInspectionTransportErrorV1::InvalidBootstrap)
            );
        }
        let mut trailing = Zeroizing::new(wire.to_vec());
        trailing.push(0);
        assert!(DeveloperLocalInspectionBootstrapV1::decode(&trailing).is_err());
        assert!(
            DeveloperLocalInspectionBootstrapV1::try_new(
                PathBuf::from("/private/tmp/pxl-test/i.sock"),
                [0; 16],
                Zeroizing::new([0x11; 32]),
                501,
                20,
                Duration::from_secs(1),
                Zeroizing::new([0x22; 16]),
            )
            .is_err()
        );
    }

    #[test]
    fn authenticated_outer_request_accepts_only_the_exact_generation_and_pxiq() {
        let value = bootstrap(0x46);
        let request = InspectionRequestV1::try_latest(
            value.request_id(1).expect("request id"),
            value.projection_id(),
        )
        .expect("PXIQ");
        let wire = encode_authenticated_request_v1(value.generation_token(), &request)
            .expect("authenticated request");
        assert_eq!(
            decode_authenticated_request_v1(&wire, value.generation_token()),
            Ok(request.clone())
        );
        assert_eq!(
            decode_authenticated_request_v1(&wire, &[0x47; 32]).err(),
            Some(DeveloperLocalInspectionTransportErrorV1::AuthenticationFailed)
        );
        let mut corrupted = Zeroizing::new(wire.to_vec());
        corrupted[GENERATION_TOKEN_BYTES + 8] ^= 1;
        assert!(matches!(
            decode_authenticated_request_v1(&corrupted, value.generation_token()),
            Err(DeveloperLocalInspectionTransportErrorV1::InvalidProtocolRequest(_))
        ));
    }

    #[test]
    fn v2_bootstrap_and_authenticated_request_are_explicitly_version_isolated() {
        let value = bootstrap_v2(0x56);
        let wire = value.encode().expect("PXIB-v2 encode");
        let decoded = DeveloperLocalInspectionBootstrapV2::decode(&wire).expect("PXIB-v2 decode");
        assert_eq!(decoded.socket_path(), value.socket_path());
        assert_eq!(decoded.projection_id(), value.projection_id());
        assert_eq!(decoded.generation_token(), value.generation_token());
        assert_eq!(decoded.request_id(1), value.request_id(1));
        assert!(DeveloperLocalInspectionBootstrapV1::decode(&wire).is_err());

        let request = InspectionRequestV2::try_latest(
            value.request_id(1).expect("v2 request id"),
            value.projection_id(),
        )
        .expect("PXIQ-v2");
        let authenticated = encode_authenticated_request_v2(value.generation_token(), &request)
            .expect("authenticated v2 request");
        assert_eq!(
            decode_authenticated_request_v2(&authenticated, value.generation_token()),
            Ok(request)
        );
        assert!(decode_authenticated_request_v1(&authenticated, value.generation_token()).is_err());
    }

    #[test]
    fn v2_bootstrap_request_id_and_authenticated_request_match_cross_language_goldens() {
        let value = cross_language_bootstrap_v2();
        let request_id = value.request_id(1).expect("cross-language request id");
        assert_eq!(
            request_id,
            [
                0x6e, 0xeb, 0x8f, 0xa5, 0x0a, 0xd6, 0x17, 0x7b, 0x24, 0xd9, 0x4c, 0x51, 0x12, 0xf5,
                0x04, 0x83,
            ]
        );
        let request = InspectionRequestV2::try_latest(request_id, value.projection_id())
            .expect("cross-language PXIQ-v2");
        let bootstrap_wire = value.encode().expect("cross-language PXIB-v2");
        let authenticated = encode_authenticated_request_v2(value.generation_token(), &request)
            .expect("cross-language authenticated request");
        let fixtures = [
            (
                "PXIB_V2",
                include_str!("../tests/fixtures/developer_local_inspection_bootstrap_v2.hex")
                    .trim(),
                bootstrap_wire.as_slice(),
            ),
            (
                "PXIQ_V2",
                include_str!("../tests/fixtures/inspection_latest_request_v2.hex").trim(),
                request.canonical_wire(),
            ),
            (
                "AUTHENTICATED_PXIQ_V2",
                include_str!(
                    "../tests/fixtures/developer_local_inspection_authenticated_request_v2.hex"
                )
                .trim(),
                authenticated.as_slice(),
            ),
        ];
        if fixtures
            .iter()
            .any(|(_, expected, _)| *expected == "PENDING")
        {
            let values = fixtures
                .iter()
                .map(|(name, _, bytes)| format!("{name}={}", encode_hex(bytes)))
                .collect::<Vec<_>>()
                .join("\n");
            panic!("PXI_DEVELOPER_LOCAL_V2_GOLDENS\n{values}");
        }
        for (_, expected, actual) in fixtures {
            assert_eq!(actual, decode_hex(expected));
        }

        let decoded_bootstrap = DeveloperLocalInspectionBootstrapV2::decode(&decode_hex(
            include_str!("../tests/fixtures/developer_local_inspection_bootstrap_v2.hex"),
        ))
        .expect("strict PXIB-v2 golden decode");
        assert_eq!(
            decoded_bootstrap.socket_path(),
            Path::new("/tmp/inspection.sock")
        );
        assert_eq!(decoded_bootstrap.server_uid(), 501);
        assert_eq!(decoded_bootstrap.server_gid(), 20);
        assert_eq!(decoded_bootstrap.request_id(1), Ok(request_id));
        assert_eq!(
            decode_authenticated_request_v2(
                &decode_hex(include_str!(
                    "../tests/fixtures/developer_local_inspection_authenticated_request_v2.hex"
                )),
                value.generation_token(),
            ),
            Ok(request)
        );
    }
}
