#![cfg(unix)]

use core::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path};

use paraegox_inspection::developer_local::{
    DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES,
    DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES, DeveloperLocalInspectionBootstrapV1,
    DeveloperLocalInspectionBootstrapV2, MAX_DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_BYTES,
    MAX_DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_BYTES, encode_authenticated_request_v1,
    encode_authenticated_request_v2,
};
use paraegox_inspection::protocol::{
    InspectionClientV1, InspectionClientV2, InspectionEndpointErrorV1, InspectionEndpointErrorV2,
    InspectionEndpointV1, InspectionEndpointV2, InspectionResponseOutcomeV1,
    InspectionResponseOutcomeV2, MAX_INSPECTION_RESPONSE_BYTES, MAX_INSPECTION_RESPONSE_V2_BYTES,
};
use paraegox_inspection::{LocalInspectionSnapshotV1, LocalInspectionSnapshotV2};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const MODE_MASK: u32 = 0o7777;
const BOOTSTRAP_MODE: u32 = 0o600;
const SOCKET_MODE: u32 = 0o600;

/// Reads one strictly correlated node-local Inspection snapshot through the
/// separate owner-private PXIQ/PXIP endpoint.
pub fn read_developer_local_inspection_status_v1(
    bootstrap_path: &Path,
) -> Result<LocalInspectionSnapshotV1, DeveloperLocalInspectionClientErrorV1> {
    let bootstrap = read_private_bootstrap_file_v1(bootstrap_path)?;
    let request_id = bootstrap
        .request_id(1)
        .map_err(|_| DeveloperLocalInspectionClientErrorV1::InvalidBootstrap)?;
    let projection_id = bootstrap.projection_id();
    let endpoint = DeveloperLocalInspectionEndpointV1::try_new(bootstrap)?;
    let mut client = InspectionClientV1::new(endpoint);
    let response = client
        .latest(request_id, projection_id)
        .map_err(|_| DeveloperLocalInspectionClientErrorV1::ExchangeFailed)?;
    if response.outcome() != InspectionResponseOutcomeV1::Snapshot {
        return Err(DeveloperLocalInspectionClientErrorV1::SnapshotUnavailable);
    }
    response
        .snapshot_value()
        .cloned()
        .ok_or(DeveloperLocalInspectionClientErrorV1::SnapshotUnavailable)
}

/// Reads one strictly correlated PXIS-v2 startup snapshot through the
/// separate owner-private PXIQ/PXIP-v2 endpoint.
///
/// The returned value contains the byte-exact five-owner PXIS-v1 projection
/// plus one public-safe NodeDaemon record. This remains a single, immutable,
/// no-retry read and grants no operational authority.
pub fn read_developer_local_inspection_status_v2(
    bootstrap_path: &Path,
) -> Result<LocalInspectionSnapshotV2, DeveloperLocalInspectionClientErrorV2> {
    let bootstrap = read_private_bootstrap_file_v2(bootstrap_path)?;
    let request_id = bootstrap
        .request_id(1)
        .map_err(|_| DeveloperLocalInspectionClientErrorV2::InvalidBootstrap)?;
    let projection_id = bootstrap.projection_id();
    let endpoint = DeveloperLocalInspectionEndpointV2::try_new(bootstrap)?;
    let mut client = InspectionClientV2::new(endpoint);
    let response = client
        .latest(request_id, projection_id)
        .map_err(|_| DeveloperLocalInspectionClientErrorV2::ExchangeFailed)?;
    if response.outcome() != InspectionResponseOutcomeV2::Snapshot {
        return Err(DeveloperLocalInspectionClientErrorV2::SnapshotUnavailable);
    }
    response
        .snapshot_value()
        .cloned()
        .ok_or(DeveloperLocalInspectionClientErrorV2::SnapshotUnavailable)
}

struct DeveloperLocalInspectionEndpointV1 {
    bootstrap: DeveloperLocalInspectionBootstrapV1,
    runtime: tokio::runtime::Runtime,
}

impl fmt::Debug for DeveloperLocalInspectionEndpointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalInspectionEndpointV1")
            .field("bootstrap", &self.bootstrap)
            .finish_non_exhaustive()
    }
}

impl DeveloperLocalInspectionEndpointV1 {
    fn try_new(
        bootstrap: DeveloperLocalInspectionBootstrapV1,
    ) -> Result<Self, DeveloperLocalInspectionClientErrorV1> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| DeveloperLocalInspectionClientErrorV1::RuntimeUnavailable)?;
        Ok(Self { bootstrap, runtime })
    }
}

impl InspectionEndpointV1 for DeveloperLocalInspectionEndpointV1 {
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, InspectionEndpointErrorV1> {
        let request = paraegox_inspection::protocol::InspectionRequestV1::decode(canonical_request)
            .map_err(|_| InspectionEndpointErrorV1::MalformedRequest)?;
        let wire = encode_authenticated_request_v1(self.bootstrap.generation_token(), &request)
            .map_err(|_| InspectionEndpointErrorV1::MalformedRequest)?;
        exchange_private_socket(
            &self.runtime,
            self.bootstrap.socket_path(),
            self.bootstrap.server_uid(),
            self.bootstrap.server_gid(),
            self.bootstrap.operation_timeout(),
            &wire,
            MAX_INSPECTION_RESPONSE_BYTES,
        )
    }
}

struct DeveloperLocalInspectionEndpointV2 {
    bootstrap: DeveloperLocalInspectionBootstrapV2,
    runtime: tokio::runtime::Runtime,
}

impl fmt::Debug for DeveloperLocalInspectionEndpointV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalInspectionEndpointV2")
            .field("bootstrap", &self.bootstrap)
            .finish_non_exhaustive()
    }
}

impl DeveloperLocalInspectionEndpointV2 {
    fn try_new(
        bootstrap: DeveloperLocalInspectionBootstrapV2,
    ) -> Result<Self, DeveloperLocalInspectionClientErrorV2> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| DeveloperLocalInspectionClientErrorV2::RuntimeUnavailable)?;
        Ok(Self { bootstrap, runtime })
    }
}

impl InspectionEndpointV2 for DeveloperLocalInspectionEndpointV2 {
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, InspectionEndpointErrorV2> {
        let request = paraegox_inspection::protocol::InspectionRequestV2::decode(canonical_request)
            .map_err(|_| InspectionEndpointErrorV2::MalformedRequest)?;
        let wire = encode_authenticated_request_v2(self.bootstrap.generation_token(), &request)
            .map_err(|_| InspectionEndpointErrorV2::MalformedRequest)?;
        exchange_private_socket(
            &self.runtime,
            self.bootstrap.socket_path(),
            self.bootstrap.server_uid(),
            self.bootstrap.server_gid(),
            self.bootstrap.operation_timeout(),
            &wire,
            MAX_INSPECTION_RESPONSE_V2_BYTES,
        )
    }
}

fn exchange_private_socket(
    runtime: &tokio::runtime::Runtime,
    socket_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    operation_timeout: std::time::Duration,
    request: &[u8],
    max_response_bytes: usize,
) -> Result<Box<[u8]>, InspectionEndpointErrorV1> {
    let socket_path = socket_path.to_path_buf();
    let before = validate_socket(&socket_path, expected_uid, expected_gid)
        .map_err(|_| InspectionEndpointErrorV1::Unavailable)?;
    runtime.block_on(async move {
        timeout(operation_timeout, async {
            let mut stream = UnixStream::connect(&socket_path)
                .await
                .map_err(|_| InspectionEndpointErrorV1::Unavailable)?;
            if !stream.peer_cred().is_ok_and(|credentials| {
                credentials.uid() == expected_uid && credentials.gid() == expected_gid
            }) || validate_socket(&socket_path, expected_uid, expected_gid)
                .map_err(|_| InspectionEndpointErrorV1::Unavailable)?
                != before
            {
                return Err(InspectionEndpointErrorV1::Unavailable);
            }
            stream
                .write_all(request)
                .await
                .map_err(|_| InspectionEndpointErrorV1::Unavailable)?;
            stream
                .shutdown()
                .await
                .map_err(|_| InspectionEndpointErrorV1::Unavailable)?;
            let mut length = [0_u8; 4];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|_| InspectionEndpointErrorV1::Unavailable)?;
            let length = usize::try_from(u32::from_be_bytes(length))
                .map_err(|_| InspectionEndpointErrorV1::ResponseUnavailable)?;
            if !(1..=max_response_bytes).contains(&length) {
                return Err(InspectionEndpointErrorV1::ResponseUnavailable);
            }
            let mut response = vec![0_u8; length];
            stream
                .read_exact(&mut response)
                .await
                .map_err(|_| InspectionEndpointErrorV1::Unavailable)?;
            let mut trailing = [0_u8; 1];
            if stream
                .read(&mut trailing)
                .await
                .map_err(|_| InspectionEndpointErrorV1::Unavailable)?
                != 0
            {
                return Err(InspectionEndpointErrorV1::ResponseUnavailable);
            }
            Ok(response.into_boxed_slice())
        })
        .await
        .map_err(|_| InspectionEndpointErrorV1::Unavailable)?
    })
}

fn read_private_bootstrap_file_v1(
    path: &Path,
) -> Result<DeveloperLocalInspectionBootstrapV1, DeveloperLocalInspectionClientErrorV1> {
    let (wire, named) = read_private_bootstrap_wire(
        path,
        DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_HEADER_BYTES,
        MAX_DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_BYTES,
    )?;
    let bootstrap = DeveloperLocalInspectionBootstrapV1::decode_owned(wire)
        .map_err(|_| DeveloperLocalInspectionClientErrorV1::InvalidBootstrap)?;
    validate_bootstrap_binding(
        path,
        bootstrap.socket_path(),
        bootstrap.server_uid(),
        bootstrap.server_gid(),
        &named,
    )?;
    Ok(bootstrap)
}

fn read_private_bootstrap_file_v2(
    path: &Path,
) -> Result<DeveloperLocalInspectionBootstrapV2, DeveloperLocalInspectionClientErrorV2> {
    let (wire, named) = read_private_bootstrap_wire(
        path,
        DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_HEADER_BYTES,
        MAX_DEVELOPER_LOCAL_INSPECTION_BOOTSTRAP_V2_BYTES,
    )?;
    let bootstrap = DeveloperLocalInspectionBootstrapV2::decode_owned(wire)
        .map_err(|_| DeveloperLocalInspectionClientErrorV2::InvalidBootstrap)?;
    validate_bootstrap_binding(
        path,
        bootstrap.socket_path(),
        bootstrap.server_uid(),
        bootstrap.server_gid(),
        &named,
    )?;
    Ok(bootstrap)
}

fn read_private_bootstrap_wire(
    path: &Path,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<(Vec<u8>, fs::Metadata), DeveloperLocalInspectionClientErrorV1> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(DeveloperLocalInspectionClientErrorV1::InvalidBootstrap);
    }
    let named = fs::symlink_metadata(path)
        .map_err(|error| DeveloperLocalInspectionClientErrorV1::Io(error.kind()))?;
    validate_private_regular_file(&named)?;
    let mut file = File::open(path)
        .map_err(|error| DeveloperLocalInspectionClientErrorV1::Io(error.kind()))?;
    let opened = file
        .metadata()
        .map_err(|error| DeveloperLocalInspectionClientErrorV1::Io(error.kind()))?;
    validate_private_regular_file(&opened)?;
    if FileIdentity::from_metadata(&named) != FileIdentity::from_metadata(&opened)
        || opened.len() < u64::try_from(min_bytes).unwrap_or(u64::MAX)
        || opened.len() > u64::try_from(max_bytes).unwrap_or(0)
    {
        return Err(DeveloperLocalInspectionClientErrorV1::InvalidBootstrap);
    }
    let length = usize::try_from(opened.len())
        .map_err(|_| DeveloperLocalInspectionClientErrorV1::InvalidBootstrap)?;
    let mut wire = vec![0_u8; length];
    file.read_exact(&mut wire)
        .map_err(|error| DeveloperLocalInspectionClientErrorV1::Io(error.kind()))?;
    Ok((wire, named))
}

fn validate_bootstrap_binding(
    path: &Path,
    socket_path: &Path,
    server_uid: u32,
    server_gid: u32,
    named: &fs::Metadata,
) -> Result<(), DeveloperLocalInspectionClientErrorV1> {
    if named.uid() != server_uid
        || named.gid() != server_gid
        || path.parent() != socket_path.parent()
    {
        return Err(DeveloperLocalInspectionClientErrorV1::InvalidBootstrap);
    }
    validate_private_parent(
        path.parent()
            .ok_or(DeveloperLocalInspectionClientErrorV1::InvalidBootstrap)?,
        server_uid,
        server_gid,
    )?;
    Ok(())
}

fn validate_private_regular_file(
    metadata: &fs::Metadata,
) -> Result<(), DeveloperLocalInspectionClientErrorV1> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & MODE_MASK != BOOTSTRAP_MODE
    {
        return Err(DeveloperLocalInspectionClientErrorV1::InvalidBootstrap);
    }
    Ok(())
}

fn validate_private_parent(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalInspectionClientErrorV1> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| DeveloperLocalInspectionClientErrorV1::Io(error.kind()))?;
    let mode = metadata.permissions().mode() & MODE_MASK;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || mode & 0o700 != 0o700
        || mode & 0o022 != 0
    {
        return Err(DeveloperLocalInspectionClientErrorV1::InvalidBootstrap);
    }
    Ok(())
}

fn validate_socket(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<FileIdentity, DeveloperLocalInspectionClientErrorV1> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| DeveloperLocalInspectionClientErrorV1::Io(error.kind()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & MODE_MASK != SOCKET_MODE
    {
        return Err(DeveloperLocalInspectionClientErrorV1::InvalidSocket);
    }
    Ok(FileIdentity::from_metadata(&metadata))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeveloperLocalInspectionClientErrorV1 {
    InvalidBootstrap,
    InvalidSocket,
    RuntimeUnavailable,
    ExchangeFailed,
    SnapshotUnavailable,
    Io(io::ErrorKind),
}

impl fmt::Display for DeveloperLocalInspectionClientErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBootstrap => "DeveloperLocal Inspection bootstrap is invalid",
            Self::InvalidSocket => "DeveloperLocal Inspection socket is invalid",
            Self::RuntimeUnavailable => "DeveloperLocal Inspection client runtime is unavailable",
            Self::ExchangeFailed => "DeveloperLocal Inspection exchange failed",
            Self::SnapshotUnavailable => "DeveloperLocal Inspection snapshot is unavailable",
            Self::Io(_) => "DeveloperLocal Inspection client I/O failed",
        })
    }
}

impl std::error::Error for DeveloperLocalInspectionClientErrorV1 {}

/// V2 preserves the display-safe local transport error taxonomy while using
/// distinct PXIB/PXIQ/PXIP wire versions.
pub type DeveloperLocalInspectionClientErrorV2 = DeveloperLocalInspectionClientErrorV1;
