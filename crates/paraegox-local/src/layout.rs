//! Canonical state and compact Unix-socket layout for DeveloperLocal.

use core::fmt;
use std::fs::{self, DirBuilder, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use nix::unistd::{Gid, Uid, chown};

use crate::config::{
    DeveloperDeploymentConfigV1, DeveloperFixtureConfigV1, DeveloperNodeConfigSchemaV1,
    DeveloperNodeConfigV1, DeveloperProvisionedConfigV1,
};
use crate::identity::{
    DeveloperNodeIdentityManifestV1, DistributedDeveloperLocalIdentityManifestV1,
    DistributedDeveloperLocalTargetV1, IdentityManifestV1,
};

const CONTROLLER_STATE_DIRECTORY: &str = "ctl";
const SUCCESSOR_STATE_DIRECTORY: &str = "succ";
const AUTHORITY_STATE_DIRECTORY: &str = "auth";
const RUNTIME_STATE_DIRECTORY: &str = "rt";
const NODE_OWNER_DIRECTORY: &str = "node";
const NODE_STATE_DIRECTORY: &str = "store";
const NODE_BOOTSTRAP_DIRECTORY: &str = "bootstrap";
const NODE_SOCKET_DIRECTORY: &str = "node";
const AUTHORITY_SOCKET_FILE: &str = "a.sock";
const RUNTIME_SOCKET_FILE: &str = "r.sock";
const NODE_MANAGEMENT_SOCKET_FILE: &str = "n.sock";
const NODE_OBSERVATION_SOCKET_FILE: &str = "o.sock";
const PXNB_BOOTSTRAP_FILE: &str = "node.pxnb";
const PXOB_BOOTSTRAP_FILE: &str = "observe.pxob";
const NODE_ENROLLMENT_ARTIFACT_FILE: &str = "enrollment-v1.pxea";
const NODE_ENROLLMENT_ARTIFACT_V2_FILE: &str = "enrollment-v2.pxea";
const DEPLOYMENT_CONTROLLER_STORE_DIRECTORY: &str = "controller-store";
const DEPLOYMENT_MANAGED_FABRIC_SUCCESSOR_STORE_DIRECTORY: &str = "managed-fabric-successor-store";
const AGENT_IPC_SOCKET_FILE: &str = "c.sock";
const AGENT_IPC_BOOTSTRAP_FILE: &str = "c.pxab";
const INSPECTION_IPC_SOCKET_FILE: &str = "i.sock";
const INSPECTION_IPC_BOOTSTRAP_FILE: &str = "i.pxib";
const SOCKET_DIRECTORY_PREFIX: &str = "pxl-";
const DISTRIBUTED_STATE_DIRECTORY: &str = "developer-distributed-layout-v1";
const DISTRIBUTED_COORDINATOR_DIRECTORY: &str = "coord";
const DISTRIBUTED_COORDINATOR_CONTROLLER_DIRECTORY: &str = "controller";
const DISTRIBUTED_TARGET_A_DIRECTORY: &str = "ta";
const DISTRIBUTED_TARGET_B_DIRECTORY: &str = "tb";
const DISTRIBUTED_CONTROLLER_BASE_DIRECTORY: &str = "ctl-base";
const DISTRIBUTED_CONTROLLER_SUCCESSOR_DIRECTORY: &str = "ctl-succ";
const DISTRIBUTED_RUNTIME_STATE_DIRECTORY: &str = "runtime";
const DISTRIBUTED_EVIDENCE_STATE_DIRECTORY: &str = "evidence";
const DISTRIBUTED_AUTHORITY_STATE_DIRECTORY: &str = "authority";
const DISTRIBUTED_NODE_OBSERVATION_SOCKET_FILE: &str = "o.sock";
const DISTRIBUTED_PXOB_BOOTSTRAP_FILE: &str = "observe.pxob";
const DISTRIBUTED_RUNTIME_BOOTSTRAP_FILE: &str = "runtime.bootstrap-v1";
const DISTRIBUTED_SOCKET_DIRECTORY_PREFIX: &str = "pxd-";
const SYSTEM_SOCKET_ROOT: &str = "/tmp";
const MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES: usize = 103;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeveloperLocalLayoutError {
    Io(io::ErrorKind),
    StateRootIdentityChanged,
    NonCanonicalPath,
    InsecureDirectory,
    InsecureSocketDirectory,
    SocketPathTooLong,
    InvalidDerivedPath,
    OverlappingPath,
}

impl fmt::Display for DeveloperLocalLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "DeveloperLocal layout I/O failed",
            Self::StateRootIdentityChanged => "DeveloperLocal state root identity changed",
            Self::NonCanonicalPath => "DeveloperLocal layout path is not canonical",
            Self::InsecureDirectory => "DeveloperLocal layout directory is not owner-private",
            Self::InsecureSocketDirectory => {
                "DeveloperLocal socket directory is not an owned 02750 directory"
            }
            Self::SocketPathTooLong => "DeveloperLocal Unix socket path exceeds 103 bytes",
            Self::InvalidDerivedPath => "DeveloperLocal derived path is invalid",
            Self::OverlappingPath => "DeveloperLocal owner paths overlap",
        })
    }
}

impl std::error::Error for DeveloperLocalLayoutError {}

impl From<io::Error> for DeveloperLocalLayoutError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

#[derive(Debug)]
pub(crate) struct DeveloperLocalLayoutV1 {
    canonical_state_root: PathBuf,
    controller_state_directory: PathBuf,
    successor_state_directory: PathBuf,
    authority_state_directory: PathBuf,
    runtime_state_directory: PathBuf,
    node_owner_directory: PathBuf,
    node_state_directory: PathBuf,
    node_bootstrap_directory: PathBuf,
    socket_directory: PathBuf,
    node_socket_directory: PathBuf,
    authority_socket_path: PathBuf,
    runtime_socket_path: PathBuf,
    node_management_socket_path: PathBuf,
    pxnb_bootstrap_path: PathBuf,
    agent_ipc_socket_path: PathBuf,
    agent_ipc_bootstrap_path: PathBuf,
    inspection_ipc_socket_path: PathBuf,
    inspection_ipc_bootstrap_path: PathBuf,
}

/// Minimal filesystem ownership for `paraegox node`: one Runtime owner, one
/// NodeDaemon owner, and their private local capabilities only.
#[derive(Debug)]
pub(crate) struct DeveloperNodeLayoutV1 {
    canonical_state_root: PathBuf,
    runtime_state_directory: PathBuf,
    node_owner_directory: PathBuf,
    node_state_directory: PathBuf,
    node_bootstrap_directory: PathBuf,
    socket_directory: PathBuf,
    node_socket_directory: PathBuf,
    runtime_socket_path: PathBuf,
    node_management_socket_path: PathBuf,
    node_observation_socket_path: Option<PathBuf>,
    pxnb_bootstrap_path: PathBuf,
    pxob_bootstrap_path: Option<PathBuf>,
    node_enrollment_artifact_path: Option<PathBuf>,
}

/// Minimal state ownership for the next Deployment composition slice.
/// Authority state/socket paths remain owned by the explicit Authority config;
/// no Agent, Model, inspection, console, or credential paths are derived here.
#[derive(Debug)]
pub(crate) struct DeveloperDeploymentLayoutV1 {
    canonical_state_root: PathBuf,
    controller_store_state_directory: PathBuf,
    managed_fabric_successor_store_state_directory: PathBuf,
}

/// Shared owner paths for the two-target DeveloperLocal composition.
#[derive(Debug)]
pub(crate) struct DistributedDeveloperLocalCoordinatorLayoutV1 {
    state_directory: PathBuf,
    controller_state_directory: PathBuf,
    authority_state_directory: PathBuf,
    socket_directory: PathBuf,
    authority_socket_path: PathBuf,
}

/// Target-owned paths. A/B use sibling state roots and separate socket
/// directories, so no target can accidentally reopen the other's owner.
#[derive(Debug)]
pub(crate) struct DistributedDeveloperLocalTargetLayoutV1 {
    state_directory: PathBuf,
    controller_base_state_directory: PathBuf,
    controller_successor_state_directory: PathBuf,
    runtime_state_directory: PathBuf,
    evidence_state_directory: PathBuf,
    node_owner_directory: PathBuf,
    node_state_directory: PathBuf,
    node_bootstrap_directory: PathBuf,
    socket_directory: PathBuf,
    node_socket_directory: PathBuf,
    runtime_socket_path: PathBuf,
    node_management_socket_path: PathBuf,
    node_observation_socket_path: PathBuf,
    pxnb_bootstrap_path: PathBuf,
    pxob_bootstrap_path: PathBuf,
    runtime_bootstrap_path: PathBuf,
    agent_ipc_socket_path: PathBuf,
    agent_ipc_bootstrap_path: PathBuf,
}

/// Filesystem shape for exactly two isolated targets and one pair coordinator.
#[derive(Debug)]
pub(crate) struct DistributedDeveloperLocalLayoutV1 {
    canonical_state_root: PathBuf,
    distributed_state_directory: PathBuf,
    coordinator: DistributedDeveloperLocalCoordinatorLayoutV1,
    targets: [DistributedDeveloperLocalTargetLayoutV1; 2],
}

pub(crate) fn prepare(
    config: &DeveloperFixtureConfigV1,
    identities: &IdentityManifestV1,
) -> Result<DeveloperLocalLayoutV1, DeveloperLocalLayoutError> {
    prepare_state_root(config.state_root(), identities)
}

pub(crate) fn prepare_provisioned(
    config: &DeveloperProvisionedConfigV1,
    identities: &IdentityManifestV1,
) -> Result<DeveloperLocalLayoutV1, DeveloperLocalLayoutError> {
    prepare_state_root(config.state_root(), identities)
}

pub(crate) fn prepare_node(
    config: &DeveloperNodeConfigV1,
    identities: &DeveloperNodeIdentityManifestV1,
) -> Result<DeveloperNodeLayoutV1, DeveloperLocalLayoutError> {
    if config.schema() != identities.schema() {
        return Err(DeveloperLocalLayoutError::InvalidDerivedPath);
    }
    let (canonical_state_root, uid, gid) = canonical_private_state_root(config.state_root())?;
    let runtime_state_directory = canonical_state_root.join(RUNTIME_STATE_DIRECTORY);
    let node_owner_directory = canonical_state_root.join(NODE_OWNER_DIRECTORY);
    let node_state_directory = node_owner_directory.join(NODE_STATE_DIRECTORY);
    let node_bootstrap_directory = node_owner_directory.join(NODE_BOOTSTRAP_DIRECTORY);
    for directory in [
        &runtime_state_directory,
        &node_owner_directory,
        &node_state_directory,
        &node_bootstrap_directory,
    ] {
        ensure_private_directory(directory, uid, gid)?;
    }

    let canonical_socket_root = fs::canonicalize(SYSTEM_SOCKET_ROOT)?;
    validate_canonical_path_chain(&canonical_socket_root)?;
    let socket_directory =
        canonical_socket_root.join(socket_directory_name(identities.manifest_instance_id()));
    ensure_socket_directory(&socket_directory, uid, gid)?;
    let node_socket_directory = socket_directory.join(NODE_SOCKET_DIRECTORY);
    ensure_private_directory(&node_socket_directory, uid, gid)?;
    let runtime_socket_path = socket_directory.join(RUNTIME_SOCKET_FILE);
    let node_management_socket_path = node_socket_directory.join(NODE_MANAGEMENT_SOCKET_FILE);
    let node_observation_socket_path = config
        .node_control()
        .map(|_| node_socket_directory.join(NODE_OBSERVATION_SOCKET_FILE));
    let pxnb_bootstrap_path = node_bootstrap_directory.join(PXNB_BOOTSTRAP_FILE);
    let pxob_bootstrap_path = config
        .node_control()
        .map(|_| node_bootstrap_directory.join(PXOB_BOOTSTRAP_FILE));
    let node_enrollment_artifact_path = match config.schema() {
        DeveloperNodeConfigSchemaV1::HostLocalV1 => None,
        DeveloperNodeConfigSchemaV1::RemoteControlV2 => {
            Some(node_owner_directory.join(NODE_ENROLLMENT_ARTIFACT_FILE))
        }
        DeveloperNodeConfigSchemaV1::ManagedAgentBootstrapV3 => {
            Some(node_owner_directory.join(NODE_ENROLLMENT_ARTIFACT_V2_FILE))
        }
    };
    for path in [&runtime_socket_path, &node_management_socket_path]
        .into_iter()
        .chain(node_observation_socket_path.iter())
    {
        if path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES {
            return Err(DeveloperLocalLayoutError::SocketPathTooLong);
        }
    }
    let layout = DeveloperNodeLayoutV1 {
        canonical_state_root,
        runtime_state_directory,
        node_owner_directory,
        node_state_directory,
        node_bootstrap_directory,
        socket_directory,
        node_socket_directory,
        runtime_socket_path,
        node_management_socket_path,
        node_observation_socket_path,
        pxnb_bootstrap_path,
        pxob_bootstrap_path,
        node_enrollment_artifact_path,
    };
    layout.validate(uid, gid)?;
    Ok(layout)
}

pub(crate) fn prepare_deployment(
    config: &DeveloperDeploymentConfigV1,
) -> Result<DeveloperDeploymentLayoutV1, DeveloperLocalLayoutError> {
    let (canonical_state_root, uid, gid) = canonical_private_state_root(config.state_root())?;
    validate_deployment_state_root_entries(&canonical_state_root, false)?;
    let controller_store_state_directory =
        canonical_state_root.join(DEPLOYMENT_CONTROLLER_STORE_DIRECTORY);
    let managed_fabric_successor_store_state_directory =
        canonical_state_root.join(DEPLOYMENT_MANAGED_FABRIC_SUCCESSOR_STORE_DIRECTORY);
    for directory in [
        &controller_store_state_directory,
        &managed_fabric_successor_store_state_directory,
    ] {
        ensure_private_directory(directory, uid, gid)?;
    }
    let layout = DeveloperDeploymentLayoutV1 {
        canonical_state_root,
        controller_store_state_directory,
        managed_fabric_successor_store_state_directory,
    };
    layout.validate(uid, gid)?;
    Ok(layout)
}

/// Prepares the isolated filesystem shape consumed by the hidden distributed
/// DeveloperLocal composition.
pub(crate) fn prepare_distributed(
    state_root: &Path,
    identities: &DistributedDeveloperLocalIdentityManifestV1,
) -> Result<DistributedDeveloperLocalLayoutV1, DeveloperLocalLayoutError> {
    let (canonical_state_root, uid, gid) = canonical_private_state_root(state_root)?;
    let distributed_state_directory = canonical_state_root.join(DISTRIBUTED_STATE_DIRECTORY);
    let coordinator_state_directory =
        distributed_state_directory.join(DISTRIBUTED_COORDINATOR_DIRECTORY);
    let authority_state_directory =
        coordinator_state_directory.join(DISTRIBUTED_AUTHORITY_STATE_DIRECTORY);
    let coordinator_controller_state_directory =
        coordinator_state_directory.join(DISTRIBUTED_COORDINATOR_CONTROLLER_DIRECTORY);
    for directory in [
        &distributed_state_directory,
        &coordinator_state_directory,
        &coordinator_controller_state_directory,
        &authority_state_directory,
    ] {
        ensure_private_directory(directory, uid, gid)?;
    }

    // `/tmp` is a symlink on macOS. As in the existing v1 layout, every
    // externally consumed path starts below its canonical target.
    let canonical_socket_root = fs::canonicalize(SYSTEM_SOCKET_ROOT)?;
    validate_canonical_path_chain(&canonical_socket_root)?;
    let coordinator_socket_directory =
        canonical_socket_root.join(distributed_socket_directory_name(
            identities.manifest_instance_id(),
            DistributedSocketOwnerV1::Coordinator,
        ));
    ensure_socket_directory(&coordinator_socket_directory, uid, gid)?;
    let coordinator = DistributedDeveloperLocalCoordinatorLayoutV1 {
        authority_socket_path: coordinator_socket_directory.join(AUTHORITY_SOCKET_FILE),
        state_directory: coordinator_state_directory,
        controller_state_directory: coordinator_controller_state_directory,
        authority_state_directory,
        socket_directory: coordinator_socket_directory,
    };
    let targets = [
        prepare_distributed_target(
            &distributed_state_directory,
            &canonical_socket_root,
            identities,
            DistributedDeveloperLocalTargetV1::A,
            uid,
            gid,
        )?,
        prepare_distributed_target(
            &distributed_state_directory,
            &canonical_socket_root,
            identities,
            DistributedDeveloperLocalTargetV1::B,
            uid,
            gid,
        )?,
    ];
    let layout = DistributedDeveloperLocalLayoutV1 {
        canonical_state_root,
        distributed_state_directory,
        coordinator,
        targets,
    };
    layout.validate(uid, gid)?;
    Ok(layout)
}

fn prepare_state_root(
    state_root: &Path,
    identities: &IdentityManifestV1,
) -> Result<DeveloperLocalLayoutV1, DeveloperLocalLayoutError> {
    let (canonical_state_root, uid, gid) = canonical_private_state_root(state_root)?;

    let controller_state_directory = canonical_state_root.join(CONTROLLER_STATE_DIRECTORY);
    let successor_state_directory = canonical_state_root.join(SUCCESSOR_STATE_DIRECTORY);
    let authority_state_directory = canonical_state_root.join(AUTHORITY_STATE_DIRECTORY);
    let runtime_state_directory = canonical_state_root.join(RUNTIME_STATE_DIRECTORY);
    let node_owner_directory = canonical_state_root.join(NODE_OWNER_DIRECTORY);
    let node_state_directory = node_owner_directory.join(NODE_STATE_DIRECTORY);
    let node_bootstrap_directory = node_owner_directory.join(NODE_BOOTSTRAP_DIRECTORY);
    for directory in [
        &controller_state_directory,
        &successor_state_directory,
        &authority_state_directory,
        &runtime_state_directory,
        &node_owner_directory,
        &node_state_directory,
        &node_bootstrap_directory,
    ] {
        ensure_private_directory(directory, uid, gid)?;
    }

    // `/tmp` is a symlink on macOS. Canonicalize it first so the strict
    // Authority/Runtime path-chain checks receive `/private/tmp/...` there.
    let canonical_socket_root = fs::canonicalize(SYSTEM_SOCKET_ROOT)?;
    validate_canonical_path_chain(&canonical_socket_root)?;
    let socket_directory =
        canonical_socket_root.join(socket_directory_name(identities.manifest_instance_id()));
    ensure_socket_directory(&socket_directory, uid, gid)?;
    let node_socket_directory = socket_directory.join(NODE_SOCKET_DIRECTORY);
    ensure_private_directory(&node_socket_directory, uid, gid)?;
    let authority_socket_path = socket_directory.join(AUTHORITY_SOCKET_FILE);
    let runtime_socket_path = socket_directory.join(RUNTIME_SOCKET_FILE);
    let node_management_socket_path = node_socket_directory.join(NODE_MANAGEMENT_SOCKET_FILE);
    let pxnb_bootstrap_path = node_bootstrap_directory.join(PXNB_BOOTSTRAP_FILE);
    let agent_ipc_socket_path = socket_directory.join(AGENT_IPC_SOCKET_FILE);
    let agent_ipc_bootstrap_path = socket_directory.join(AGENT_IPC_BOOTSTRAP_FILE);
    let inspection_ipc_socket_path = socket_directory.join(INSPECTION_IPC_SOCKET_FILE);
    let inspection_ipc_bootstrap_path = socket_directory.join(INSPECTION_IPC_BOOTSTRAP_FILE);
    for path in [
        &authority_socket_path,
        &runtime_socket_path,
        &node_management_socket_path,
        &agent_ipc_socket_path,
        &inspection_ipc_socket_path,
    ] {
        if path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES {
            return Err(DeveloperLocalLayoutError::SocketPathTooLong);
        }
    }

    let layout = DeveloperLocalLayoutV1 {
        canonical_state_root,
        controller_state_directory,
        successor_state_directory,
        authority_state_directory,
        runtime_state_directory,
        node_owner_directory,
        node_state_directory,
        node_bootstrap_directory,
        socket_directory,
        node_socket_directory,
        authority_socket_path,
        runtime_socket_path,
        node_management_socket_path,
        pxnb_bootstrap_path,
        agent_ipc_socket_path,
        agent_ipc_bootstrap_path,
        inspection_ipc_socket_path,
        inspection_ipc_bootstrap_path,
    };
    layout.validate(uid, gid)?;
    Ok(layout)
}

fn canonical_private_state_root(
    state_root: &Path,
) -> Result<(PathBuf, u32, u32), DeveloperLocalLayoutError> {
    let requested_metadata = fs::symlink_metadata(state_root)?;
    let canonical_state_root = fs::canonicalize(state_root)?;
    validate_canonical_path_chain(&canonical_state_root)?;
    let canonical_metadata = fs::symlink_metadata(&canonical_state_root)?;
    if !same_file(&requested_metadata, &canonical_metadata) {
        return Err(DeveloperLocalLayoutError::StateRootIdentityChanged);
    }
    let uid = Uid::effective().as_raw();
    let gid = Gid::effective().as_raw();
    validate_private_directory(&canonical_metadata, uid, gid)?;
    Ok((canonical_state_root, uid, gid))
}

#[derive(Clone, Copy)]
enum DistributedSocketOwnerV1 {
    Coordinator,
    TargetA,
    TargetB,
}

fn prepare_distributed_target(
    distributed_state_directory: &Path,
    canonical_socket_root: &Path,
    identities: &DistributedDeveloperLocalIdentityManifestV1,
    target: DistributedDeveloperLocalTargetV1,
    uid: u32,
    gid: u32,
) -> Result<DistributedDeveloperLocalTargetLayoutV1, DeveloperLocalLayoutError> {
    let (state_name, socket_owner) = match target {
        DistributedDeveloperLocalTargetV1::A => (
            DISTRIBUTED_TARGET_A_DIRECTORY,
            DistributedSocketOwnerV1::TargetA,
        ),
        DistributedDeveloperLocalTargetV1::B => (
            DISTRIBUTED_TARGET_B_DIRECTORY,
            DistributedSocketOwnerV1::TargetB,
        ),
    };
    let state_directory = distributed_state_directory.join(state_name);
    let controller_base_state_directory =
        state_directory.join(DISTRIBUTED_CONTROLLER_BASE_DIRECTORY);
    let controller_successor_state_directory =
        state_directory.join(DISTRIBUTED_CONTROLLER_SUCCESSOR_DIRECTORY);
    let runtime_state_directory = state_directory.join(DISTRIBUTED_RUNTIME_STATE_DIRECTORY);
    let evidence_state_directory = state_directory.join(DISTRIBUTED_EVIDENCE_STATE_DIRECTORY);
    let node_owner_directory = state_directory.join(NODE_OWNER_DIRECTORY);
    let node_state_directory = node_owner_directory.join(NODE_STATE_DIRECTORY);
    let node_bootstrap_directory = node_owner_directory.join(NODE_BOOTSTRAP_DIRECTORY);
    for directory in [
        &state_directory,
        &controller_base_state_directory,
        &controller_successor_state_directory,
        &runtime_state_directory,
        &evidence_state_directory,
        &node_owner_directory,
        &node_state_directory,
        &node_bootstrap_directory,
    ] {
        ensure_private_directory(directory, uid, gid)?;
    }
    let socket_directory = canonical_socket_root.join(distributed_socket_directory_name(
        identities.manifest_instance_id(),
        socket_owner,
    ));
    ensure_socket_directory(&socket_directory, uid, gid)?;
    let node_socket_directory = socket_directory.join(NODE_SOCKET_DIRECTORY);
    ensure_private_directory(&node_socket_directory, uid, gid)?;
    Ok(DistributedDeveloperLocalTargetLayoutV1 {
        runtime_socket_path: socket_directory.join(RUNTIME_SOCKET_FILE),
        node_management_socket_path: node_socket_directory.join(NODE_MANAGEMENT_SOCKET_FILE),
        node_observation_socket_path: node_socket_directory
            .join(DISTRIBUTED_NODE_OBSERVATION_SOCKET_FILE),
        pxnb_bootstrap_path: node_bootstrap_directory.join(PXNB_BOOTSTRAP_FILE),
        pxob_bootstrap_path: node_bootstrap_directory.join(DISTRIBUTED_PXOB_BOOTSTRAP_FILE),
        runtime_bootstrap_path: runtime_state_directory.join(DISTRIBUTED_RUNTIME_BOOTSTRAP_FILE),
        agent_ipc_socket_path: socket_directory.join(AGENT_IPC_SOCKET_FILE),
        agent_ipc_bootstrap_path: socket_directory.join(AGENT_IPC_BOOTSTRAP_FILE),
        state_directory,
        controller_base_state_directory,
        controller_successor_state_directory,
        runtime_state_directory,
        evidence_state_directory,
        node_owner_directory,
        node_state_directory,
        node_bootstrap_directory,
        socket_directory,
        node_socket_directory,
    })
}

impl DeveloperLocalLayoutV1 {
    pub(crate) fn canonical_state_root(&self) -> &Path {
        &self.canonical_state_root
    }

    pub(crate) fn controller_state_directory(&self) -> &Path {
        &self.controller_state_directory
    }

    pub(crate) fn successor_state_directory(&self) -> &Path {
        &self.successor_state_directory
    }

    pub(crate) fn authority_state_directory(&self) -> &Path {
        &self.authority_state_directory
    }

    pub(crate) fn runtime_state_directory(&self) -> &Path {
        &self.runtime_state_directory
    }

    fn node_owner_directory(&self) -> &Path {
        &self.node_owner_directory
    }

    /// Exact PXND store root for the reference NodeDaemon.
    pub(crate) fn node_state_directory(&self) -> &Path {
        &self.node_state_directory
    }

    fn node_bootstrap_directory(&self) -> &Path {
        &self.node_bootstrap_directory
    }

    pub(crate) fn socket_directory(&self) -> &Path {
        &self.socket_directory
    }

    fn node_socket_directory(&self) -> &Path {
        &self.node_socket_directory
    }

    pub(crate) fn authority_socket_path(&self) -> &Path {
        &self.authority_socket_path
    }

    pub(crate) fn runtime_socket_path(&self) -> &Path {
        &self.runtime_socket_path
    }

    pub(crate) fn node_management_socket_path(&self) -> &Path {
        &self.node_management_socket_path
    }

    pub(crate) fn pxnb_bootstrap_path(&self) -> &Path {
        &self.pxnb_bootstrap_path
    }

    pub(crate) fn agent_ipc_socket_path(&self) -> &Path {
        &self.agent_ipc_socket_path
    }

    pub(crate) fn agent_ipc_bootstrap_path(&self) -> &Path {
        &self.agent_ipc_bootstrap_path
    }

    pub(crate) fn inspection_ipc_socket_path(&self) -> &Path {
        &self.inspection_ipc_socket_path
    }

    pub(crate) fn inspection_ipc_bootstrap_path(&self) -> &Path {
        &self.inspection_ipc_bootstrap_path
    }

    #[cfg(test)]
    fn owned_paths(&self) -> [&Path; 18] {
        [
            self.canonical_state_root(),
            self.controller_state_directory(),
            self.successor_state_directory(),
            self.authority_state_directory(),
            self.runtime_state_directory(),
            self.node_owner_directory(),
            self.node_state_directory(),
            self.node_bootstrap_directory(),
            self.socket_directory(),
            self.node_socket_directory(),
            self.authority_socket_path(),
            self.runtime_socket_path(),
            self.node_management_socket_path(),
            self.pxnb_bootstrap_path(),
            self.agent_ipc_socket_path(),
            self.agent_ipc_bootstrap_path(),
            self.inspection_ipc_socket_path(),
            self.inspection_ipc_bootstrap_path(),
        ]
    }

    fn validate(&self, uid: u32, gid: u32) -> Result<(), DeveloperLocalLayoutError> {
        validate_canonical_path_chain(self.canonical_state_root())?;
        let state_child_directories = [
            self.controller_state_directory(),
            self.successor_state_directory(),
            self.authority_state_directory(),
            self.runtime_state_directory(),
            self.node_owner_directory(),
        ];
        for directory in &state_child_directories {
            validate_existing_child_directory(directory, self.canonical_state_root())?;
        }
        if state_child_directories
            .iter()
            .enumerate()
            .any(|(index, left)| state_child_directories[index + 1..].contains(left))
        {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        let node_child_directories = [self.node_state_directory(), self.node_bootstrap_directory()];
        for directory in &node_child_directories {
            validate_existing_child_directory(directory, self.node_owner_directory())?;
        }
        if node_child_directories[0] == node_child_directories[1] {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        for directory in [
            self.canonical_state_root(),
            self.controller_state_directory(),
            self.successor_state_directory(),
            self.authority_state_directory(),
            self.runtime_state_directory(),
            self.node_owner_directory(),
            self.node_state_directory(),
            self.node_bootstrap_directory(),
        ] {
            validate_canonical_path_chain(directory)?;
            validate_private_directory(&fs::symlink_metadata(directory)?, uid, gid)?;
        }
        validate_canonical_path_chain(self.socket_directory())?;
        validate_socket_directory(&fs::symlink_metadata(self.socket_directory())?, uid, gid)?;
        validate_existing_child_directory(self.node_socket_directory(), self.socket_directory())?;
        validate_canonical_path_chain(self.node_socket_directory())?;
        validate_private_directory(
            &fs::symlink_metadata(self.node_socket_directory())?,
            uid,
            gid,
        )?;
        for path in [
            self.authority_socket_path(),
            self.runtime_socket_path(),
            self.agent_ipc_socket_path(),
            self.inspection_ipc_socket_path(),
        ] {
            validate_reserved_path(path, self.socket_directory())?;
            if path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES {
                return Err(DeveloperLocalLayoutError::SocketPathTooLong);
            }
        }
        validate_reserved_path(
            self.node_management_socket_path(),
            self.node_socket_directory(),
        )?;
        if self
            .node_management_socket_path()
            .as_os_str()
            .as_bytes()
            .len()
            > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES
        {
            return Err(DeveloperLocalLayoutError::SocketPathTooLong);
        }
        for path in [
            self.agent_ipc_bootstrap_path(),
            self.inspection_ipc_bootstrap_path(),
        ] {
            validate_reserved_path(path, self.socket_directory())?;
        }
        validate_reserved_path(self.pxnb_bootstrap_path(), self.node_bootstrap_directory())?;
        let leaf_paths = [
            self.authority_socket_path(),
            self.runtime_socket_path(),
            self.node_management_socket_path(),
            self.pxnb_bootstrap_path(),
            self.agent_ipc_socket_path(),
            self.agent_ipc_bootstrap_path(),
            self.inspection_ipc_socket_path(),
            self.inspection_ipc_bootstrap_path(),
        ];
        if leaf_paths
            .iter()
            .enumerate()
            .any(|(index, left)| leaf_paths[index + 1..].iter().any(|right| left == right))
        {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        Ok(())
    }
}

impl DeveloperNodeLayoutV1 {
    pub(crate) fn canonical_state_root(&self) -> &Path {
        &self.canonical_state_root
    }

    pub(crate) fn runtime_state_directory(&self) -> &Path {
        &self.runtime_state_directory
    }

    fn node_owner_directory(&self) -> &Path {
        &self.node_owner_directory
    }

    pub(crate) fn node_state_directory(&self) -> &Path {
        &self.node_state_directory
    }

    fn node_bootstrap_directory(&self) -> &Path {
        &self.node_bootstrap_directory
    }

    pub(crate) fn socket_directory(&self) -> &Path {
        &self.socket_directory
    }

    fn node_socket_directory(&self) -> &Path {
        &self.node_socket_directory
    }

    pub(crate) fn runtime_socket_path(&self) -> &Path {
        &self.runtime_socket_path
    }

    pub(crate) fn node_management_socket_path(&self) -> &Path {
        &self.node_management_socket_path
    }

    pub(crate) fn node_observation_socket_path(&self) -> Option<&Path> {
        self.node_observation_socket_path.as_deref()
    }

    pub(crate) fn pxnb_bootstrap_path(&self) -> &Path {
        &self.pxnb_bootstrap_path
    }

    pub(crate) fn pxob_bootstrap_path(&self) -> Option<&Path> {
        self.pxob_bootstrap_path.as_deref()
    }

    pub(crate) fn node_enrollment_artifact_path(&self) -> Option<&Path> {
        self.node_enrollment_artifact_path.as_deref()
    }

    #[cfg(test)]
    fn owned_paths(&self) -> [&Path; 10] {
        [
            self.canonical_state_root(),
            self.runtime_state_directory(),
            self.node_owner_directory(),
            self.node_state_directory(),
            self.node_bootstrap_directory(),
            self.socket_directory(),
            self.node_socket_directory(),
            self.runtime_socket_path(),
            self.node_management_socket_path(),
            self.pxnb_bootstrap_path(),
        ]
    }

    fn validate(&self, uid: u32, gid: u32) -> Result<(), DeveloperLocalLayoutError> {
        validate_canonical_path_chain(self.canonical_state_root())?;
        for directory in [self.runtime_state_directory(), self.node_owner_directory()] {
            validate_existing_child_directory(directory, self.canonical_state_root())?;
        }
        if self.runtime_state_directory() == self.node_owner_directory() {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        for directory in [self.node_state_directory(), self.node_bootstrap_directory()] {
            validate_existing_child_directory(directory, self.node_owner_directory())?;
        }
        if self.node_state_directory() == self.node_bootstrap_directory() {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        for directory in [
            self.canonical_state_root(),
            self.runtime_state_directory(),
            self.node_owner_directory(),
            self.node_state_directory(),
            self.node_bootstrap_directory(),
        ] {
            validate_canonical_path_chain(directory)?;
            validate_private_directory(&fs::symlink_metadata(directory)?, uid, gid)?;
        }
        validate_canonical_path_chain(self.socket_directory())?;
        validate_socket_directory(&fs::symlink_metadata(self.socket_directory())?, uid, gid)?;
        validate_existing_child_directory(self.node_socket_directory(), self.socket_directory())?;
        validate_canonical_path_chain(self.node_socket_directory())?;
        validate_private_directory(
            &fs::symlink_metadata(self.node_socket_directory())?,
            uid,
            gid,
        )?;
        validate_reserved_path(self.runtime_socket_path(), self.socket_directory())?;
        validate_reserved_path(
            self.node_management_socket_path(),
            self.node_socket_directory(),
        )?;
        if self.node_observation_socket_path().is_some() != self.pxob_bootstrap_path().is_some()
            || self.node_observation_socket_path().is_some()
                != self.node_enrollment_artifact_path().is_some()
        {
            return Err(DeveloperLocalLayoutError::InvalidDerivedPath);
        }
        if let Some(path) = self.node_observation_socket_path() {
            validate_reserved_path(path, self.node_socket_directory())?;
        }
        validate_reserved_path(self.pxnb_bootstrap_path(), self.node_bootstrap_directory())?;
        if let Some(path) = self.pxob_bootstrap_path() {
            validate_reserved_path(path, self.node_bootstrap_directory())?;
        }
        if let Some(path) = self.node_enrollment_artifact_path() {
            validate_reserved_path(path, self.node_owner_directory())?;
        }
        for path in [
            self.runtime_socket_path(),
            self.node_management_socket_path(),
        ]
        .into_iter()
        .chain(self.node_observation_socket_path())
        {
            if path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES {
                return Err(DeveloperLocalLayoutError::SocketPathTooLong);
            }
        }
        if self.runtime_socket_path() == self.node_management_socket_path()
            || self.node_observation_socket_path().is_some_and(|path| {
                path == self.runtime_socket_path() || path == self.node_management_socket_path()
            })
            || self
                .pxnb_bootstrap_path()
                .starts_with(self.node_state_directory())
            || self.pxob_bootstrap_path().is_some_and(|path| {
                path.starts_with(self.node_state_directory()) || path == self.pxnb_bootstrap_path()
            })
            || self.node_enrollment_artifact_path().is_some_and(|path| {
                path.starts_with(self.node_state_directory())
                    || path.starts_with(self.node_bootstrap_directory())
                    || path == self.runtime_socket_path()
                    || path == self.node_management_socket_path()
                    || self
                        .node_observation_socket_path()
                        .is_some_and(|socket| path == socket)
            })
        {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        Ok(())
    }
}

impl DeveloperDeploymentLayoutV1 {
    pub(crate) fn canonical_state_root(&self) -> &Path {
        &self.canonical_state_root
    }

    pub(crate) fn controller_store_state_directory(&self) -> &Path {
        &self.controller_store_state_directory
    }

    pub(crate) fn managed_fabric_successor_store_state_directory(&self) -> &Path {
        &self.managed_fabric_successor_store_state_directory
    }

    fn validate(&self, uid: u32, gid: u32) -> Result<(), DeveloperLocalLayoutError> {
        validate_canonical_path_chain(self.canonical_state_root())?;
        validate_private_directory(
            &fs::symlink_metadata(self.canonical_state_root())?,
            uid,
            gid,
        )?;
        for directory in [
            self.controller_store_state_directory(),
            self.managed_fabric_successor_store_state_directory(),
        ] {
            validate_existing_child_directory(directory, self.canonical_state_root())?;
            validate_private_directory(&fs::symlink_metadata(directory)?, uid, gid)?;
        }
        if self.controller_store_state_directory()
            == self.managed_fabric_successor_store_state_directory()
        {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        validate_deployment_state_root_entries(self.canonical_state_root(), true)
    }
}

impl DistributedDeveloperLocalCoordinatorLayoutV1 {
    pub(crate) fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    pub(crate) fn controller_state_directory(&self) -> &Path {
        &self.controller_state_directory
    }

    pub(crate) fn authority_state_directory(&self) -> &Path {
        &self.authority_state_directory
    }

    pub(crate) fn socket_directory(&self) -> &Path {
        &self.socket_directory
    }

    pub(crate) fn authority_socket_path(&self) -> &Path {
        &self.authority_socket_path
    }

    fn owned_paths(&self) -> [&Path; 5] {
        [
            self.state_directory(),
            self.controller_state_directory(),
            self.authority_state_directory(),
            self.socket_directory(),
            self.authority_socket_path(),
        ]
    }

    fn validate(&self, uid: u32, gid: u32) -> Result<(), DeveloperLocalLayoutError> {
        validate_existing_child_directory(
            self.authority_state_directory(),
            self.state_directory(),
        )?;
        validate_existing_child_directory(
            self.controller_state_directory(),
            self.state_directory(),
        )?;
        if self.authority_state_directory() == self.controller_state_directory() {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        for directory in [
            self.state_directory(),
            self.controller_state_directory(),
            self.authority_state_directory(),
        ] {
            validate_canonical_path_chain(directory)?;
            validate_private_directory(&fs::symlink_metadata(directory)?, uid, gid)?;
        }
        validate_canonical_path_chain(self.socket_directory())?;
        validate_socket_directory(&fs::symlink_metadata(self.socket_directory())?, uid, gid)?;
        validate_reserved_path(self.authority_socket_path(), self.socket_directory())?;
        if self.authority_socket_path().as_os_str().as_bytes().len()
            > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES
        {
            return Err(DeveloperLocalLayoutError::SocketPathTooLong);
        }
        Ok(())
    }
}

impl DistributedDeveloperLocalTargetLayoutV1 {
    pub(crate) fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    pub(crate) fn controller_base_state_directory(&self) -> &Path {
        &self.controller_base_state_directory
    }

    pub(crate) fn controller_successor_state_directory(&self) -> &Path {
        &self.controller_successor_state_directory
    }

    pub(crate) fn runtime_state_directory(&self) -> &Path {
        &self.runtime_state_directory
    }

    pub(crate) fn evidence_state_directory(&self) -> &Path {
        &self.evidence_state_directory
    }

    fn node_owner_directory(&self) -> &Path {
        &self.node_owner_directory
    }

    /// Exact PXND store root. Owner bootstrap files intentionally live in a
    /// sibling directory because the PXND store rejects foreign entries.
    pub(crate) fn node_state_directory(&self) -> &Path {
        &self.node_state_directory
    }

    fn node_bootstrap_directory(&self) -> &Path {
        &self.node_bootstrap_directory
    }

    pub(crate) fn socket_directory(&self) -> &Path {
        &self.socket_directory
    }

    fn node_socket_directory(&self) -> &Path {
        &self.node_socket_directory
    }

    pub(crate) fn runtime_socket_path(&self) -> &Path {
        &self.runtime_socket_path
    }

    pub(crate) fn node_management_socket_path(&self) -> &Path {
        &self.node_management_socket_path
    }

    pub(crate) fn node_observation_socket_path(&self) -> &Path {
        &self.node_observation_socket_path
    }

    pub(crate) fn pxnb_bootstrap_path(&self) -> &Path {
        &self.pxnb_bootstrap_path
    }

    pub(crate) fn pxob_bootstrap_path(&self) -> &Path {
        &self.pxob_bootstrap_path
    }

    /// Reserved coordinate for a future Runtime process-owner bootstrap.
    /// This layout does not define its codec or claim that a producer exists.
    pub(crate) fn runtime_bootstrap_path(&self) -> &Path {
        &self.runtime_bootstrap_path
    }

    pub(crate) fn agent_ipc_socket_path(&self) -> &Path {
        &self.agent_ipc_socket_path
    }

    pub(crate) fn agent_ipc_bootstrap_path(&self) -> &Path {
        &self.agent_ipc_bootstrap_path
    }

    fn owned_paths(&self) -> [&Path; 18] {
        [
            self.state_directory(),
            self.controller_base_state_directory(),
            self.controller_successor_state_directory(),
            self.runtime_state_directory(),
            self.evidence_state_directory(),
            self.node_owner_directory(),
            self.node_state_directory(),
            self.node_bootstrap_directory(),
            self.socket_directory(),
            self.node_socket_directory(),
            self.runtime_socket_path(),
            self.node_management_socket_path(),
            self.node_observation_socket_path(),
            self.pxnb_bootstrap_path(),
            self.pxob_bootstrap_path(),
            self.runtime_bootstrap_path(),
            self.agent_ipc_socket_path(),
            self.agent_ipc_bootstrap_path(),
        ]
    }

    fn validate(&self, uid: u32, gid: u32) -> Result<(), DeveloperLocalLayoutError> {
        let child_directories = [
            self.controller_base_state_directory(),
            self.controller_successor_state_directory(),
            self.runtime_state_directory(),
            self.evidence_state_directory(),
            self.node_owner_directory(),
        ];
        for directory in &child_directories {
            validate_existing_child_directory(directory, self.state_directory())?;
        }
        if child_directories
            .iter()
            .enumerate()
            .any(|(index, left)| child_directories[index + 1..].contains(left))
        {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        let node_child_directories = [self.node_state_directory(), self.node_bootstrap_directory()];
        for directory in &node_child_directories {
            validate_existing_child_directory(directory, self.node_owner_directory())?;
        }
        if node_child_directories[0] == node_child_directories[1] {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        for directory in [
            self.state_directory(),
            self.controller_base_state_directory(),
            self.controller_successor_state_directory(),
            self.runtime_state_directory(),
            self.evidence_state_directory(),
            self.node_owner_directory(),
            self.node_state_directory(),
            self.node_bootstrap_directory(),
        ] {
            validate_canonical_path_chain(directory)?;
            validate_private_directory(&fs::symlink_metadata(directory)?, uid, gid)?;
        }
        validate_canonical_path_chain(self.socket_directory())?;
        validate_socket_directory(&fs::symlink_metadata(self.socket_directory())?, uid, gid)?;
        validate_existing_child_directory(self.node_socket_directory(), self.socket_directory())?;
        validate_canonical_path_chain(self.node_socket_directory())?;
        validate_private_directory(
            &fs::symlink_metadata(self.node_socket_directory())?,
            uid,
            gid,
        )?;
        for path in [self.runtime_socket_path(), self.agent_ipc_socket_path()] {
            validate_reserved_path(path, self.socket_directory())?;
            if path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES {
                return Err(DeveloperLocalLayoutError::SocketPathTooLong);
            }
        }
        for path in [
            self.node_management_socket_path(),
            self.node_observation_socket_path(),
        ] {
            validate_reserved_path(path, self.node_socket_directory())?;
            if path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES {
                return Err(DeveloperLocalLayoutError::SocketPathTooLong);
            }
        }
        validate_reserved_path(self.pxnb_bootstrap_path(), self.node_bootstrap_directory())?;
        validate_reserved_path(self.pxob_bootstrap_path(), self.node_bootstrap_directory())?;
        validate_reserved_path(
            self.runtime_bootstrap_path(),
            self.runtime_state_directory(),
        )?;
        validate_reserved_path(self.agent_ipc_bootstrap_path(), self.socket_directory())?;
        let leaf_paths = [
            self.runtime_socket_path(),
            self.node_management_socket_path(),
            self.node_observation_socket_path(),
            self.pxnb_bootstrap_path(),
            self.pxob_bootstrap_path(),
            self.runtime_bootstrap_path(),
            self.agent_ipc_socket_path(),
            self.agent_ipc_bootstrap_path(),
        ];
        if leaf_paths
            .iter()
            .enumerate()
            .any(|(index, left)| leaf_paths[index + 1..].iter().any(|right| left == right))
        {
            return Err(DeveloperLocalLayoutError::OverlappingPath);
        }
        Ok(())
    }
}

impl DistributedDeveloperLocalLayoutV1 {
    pub(crate) fn canonical_state_root(&self) -> &Path {
        &self.canonical_state_root
    }

    pub(crate) fn distributed_state_directory(&self) -> &Path {
        &self.distributed_state_directory
    }

    pub(crate) const fn coordinator(&self) -> &DistributedDeveloperLocalCoordinatorLayoutV1 {
        &self.coordinator
    }

    pub(crate) const fn target(
        &self,
        target: DistributedDeveloperLocalTargetV1,
    ) -> &DistributedDeveloperLocalTargetLayoutV1 {
        match target {
            DistributedDeveloperLocalTargetV1::A => &self.targets[0],
            DistributedDeveloperLocalTargetV1::B => &self.targets[1],
        }
    }

    fn validate(&self, uid: u32, gid: u32) -> Result<(), DeveloperLocalLayoutError> {
        validate_existing_child_directory(
            self.coordinator.state_directory(),
            self.distributed_state_directory(),
        )?;
        validate_existing_child_directory(
            self.targets[0].state_directory(),
            self.distributed_state_directory(),
        )?;
        validate_existing_child_directory(
            self.targets[1].state_directory(),
            self.distributed_state_directory(),
        )?;
        for directory in [
            self.canonical_state_root(),
            self.distributed_state_directory(),
        ] {
            validate_canonical_path_chain(directory)?;
            validate_private_directory(&fs::symlink_metadata(directory)?, uid, gid)?;
        }
        self.coordinator.validate(uid, gid)?;
        self.targets[0].validate(uid, gid)?;
        self.targets[1].validate(uid, gid)?;
        let coordinator_paths = self.coordinator.owned_paths();
        let target_a_paths = self.targets[0].owned_paths();
        let target_b_paths = self.targets[1].owned_paths();
        validate_non_overlapping_sets(&target_a_paths, &target_b_paths)?;
        validate_non_overlapping_sets(&coordinator_paths, &target_a_paths)?;
        validate_non_overlapping_sets(&coordinator_paths, &target_b_paths)?;
        Ok(())
    }
}

fn validate_reserved_path(path: &Path, parent: &Path) -> Result<(), DeveloperLocalLayoutError> {
    if path.parent() != Some(parent) || !is_lexically_canonical_absolute(path) {
        return Err(DeveloperLocalLayoutError::InvalidDerivedPath);
    }
    Ok(())
}

fn validate_deployment_state_root_entries(
    state_root: &Path,
    require_complete: bool,
) -> Result<(), DeveloperLocalLayoutError> {
    let mut controller_store_seen = false;
    let mut successor_store_seen = false;
    for entry in fs::read_dir(state_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let seen = if name == DEPLOYMENT_CONTROLLER_STORE_DIRECTORY {
            &mut controller_store_seen
        } else if name == DEPLOYMENT_MANAGED_FABRIC_SUCCESSOR_STORE_DIRECTORY {
            &mut successor_store_seen
        } else {
            return Err(DeveloperLocalLayoutError::InvalidDerivedPath);
        };
        if *seen || !entry.file_type()?.is_dir() {
            return Err(DeveloperLocalLayoutError::InvalidDerivedPath);
        }
        *seen = true;
    }
    if require_complete && !(controller_store_seen && successor_store_seen) {
        return Err(DeveloperLocalLayoutError::InvalidDerivedPath);
    }
    Ok(())
}

fn validate_existing_child_directory(
    path: &Path,
    parent: &Path,
) -> Result<(), DeveloperLocalLayoutError> {
    if path.parent() != Some(parent) {
        return Err(DeveloperLocalLayoutError::InvalidDerivedPath);
    }
    validate_canonical_path_chain(path)
}

fn validate_non_overlapping_sets(
    left: &[&Path],
    right: &[&Path],
) -> Result<(), DeveloperLocalLayoutError> {
    if left
        .iter()
        .any(|left| right.iter().any(|right| paths_overlap(left, right)))
    {
        return Err(DeveloperLocalLayoutError::OverlappingPath);
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn is_lexically_canonical_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn ensure_private_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalLayoutError> {
    let created = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            true
        }
        Err(error) => return Err(error.into()),
    };
    validate_canonical_path_chain(path)?;
    let metadata = fs::symlink_metadata(path)?;
    validate_private_directory(&metadata, expected_uid, expected_gid)?;
    if created {
        sync_directory(existing_parent(path))?;
    }
    Ok(())
}

fn validate_private_directory(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalLayoutError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(DeveloperLocalLayoutError::InsecureDirectory);
    }
    Ok(())
}

fn ensure_socket_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalLayoutError> {
    let created = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o2750).create(path)?;
            chown(path, None, Some(Gid::from_raw(expected_gid)))
                .map_err(|_| DeveloperLocalLayoutError::InsecureSocketDirectory)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o2750))?;
            true
        }
        Err(error) => return Err(error.into()),
    };
    validate_canonical_path_chain(path)?;
    validate_socket_directory(&fs::symlink_metadata(path)?, expected_uid, expected_gid)?;
    if created {
        sync_directory(existing_parent(path))?;
    }
    Ok(())
}

fn validate_socket_directory(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalLayoutError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != 0o2750
    {
        return Err(DeveloperLocalLayoutError::InsecureSocketDirectory);
    }
    Ok(())
}

fn validate_canonical_path_chain(path: &Path) -> Result<(), DeveloperLocalLayoutError> {
    if !path.is_absolute() {
        return Err(DeveloperLocalLayoutError::NonCanonicalPath);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() {
                    return Err(DeveloperLocalLayoutError::NonCanonicalPath);
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(DeveloperLocalLayoutError::NonCanonicalPath);
            }
        }
    }
    Ok(())
}

fn socket_directory_name(identity: &[u8; 16]) -> String {
    let mut name = String::with_capacity(SOCKET_DIRECTORY_PREFIX.len() + 32);
    name.push_str(SOCKET_DIRECTORY_PREFIX);
    for byte in identity {
        use core::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    name
}

fn distributed_socket_directory_name(
    identity: &[u8; 16],
    owner: DistributedSocketOwnerV1,
) -> String {
    let suffix = match owner {
        DistributedSocketOwnerV1::Coordinator => 'c',
        DistributedSocketOwnerV1::TargetA => 'a',
        DistributedSocketOwnerV1::TargetB => 'b',
    };
    let mut name = String::with_capacity(DISTRIBUTED_SOCKET_DIRECTORY_PREFIX.len() + 32 + 2);
    name.push_str(DISTRIBUTED_SOCKET_DIRECTORY_PREFIX);
    for byte in identity {
        use core::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    name.push('-');
    name.push(suffix);
    name
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn sync_directory(path: &Path) -> Result<(), DeveloperLocalLayoutError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn existing_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temporary_root =
                fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
            let path = temporary_root.join(format!(
                "paraegox-local-distributed-layout-test-{}-{sequence}",
                std::process::id()
            ));
            assert!(!path.exists(), "test state root unexpectedly exists");
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            assert!(self.path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("paraegox-local-distributed-layout-test-")
            }));
            if let Err(error) = fs::remove_dir_all(&self.path) {
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
        }
    }

    struct SocketDirectoryCleanup<const N: usize>([PathBuf; N]);

    impl<const N: usize> Drop for SocketDirectoryCleanup<N> {
        fn drop(&mut self) {
            for path in &self.0 {
                assert!(path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with(SOCKET_DIRECTORY_PREFIX)
                        || name.starts_with(DISTRIBUTED_SOCKET_DIRECTORY_PREFIX)
                }));
                let node_socket_directory = path.join(NODE_SOCKET_DIRECTORY);
                if let Err(error) = fs::remove_dir(&node_socket_directory) {
                    assert_eq!(error.kind(), io::ErrorKind::NotFound);
                }
                if let Err(error) = fs::remove_dir(path) {
                    assert_eq!(error.kind(), io::ErrorKind::NotFound);
                }
            }
        }
    }

    fn fixture_config(state_root: &Path) -> DeveloperFixtureConfigV1 {
        let state_root = state_root.to_str().expect("UTF-8 test state root");
        let document = format!(
            "schema_version = 1\nstate_root = {state_root:?}\nfabric_listen = \"tcp/127.0.0.1:7450\"\n\n[model]\nprovider = \"deterministic-echo-v1\"\n"
        );
        match crate::config::parse_chat_config_toml_for_test(&document)
            .expect("valid fixture config")
        {
            crate::config::Command::DeveloperFixtureV1(config) => config,
            crate::config::Command::DeveloperNodeV1(_)
            | crate::config::Command::DeveloperDistributedFixtureV1(_)
            | crate::config::Command::DeveloperProvisionedV1(_)
            | crate::config::Command::DeveloperDeploymentV1(_)
            | crate::config::Command::Help => panic!("unexpected fixture command"),
        }
    }

    #[test]
    fn layout_has_private_stable_reference_node_store_and_bootstrap_siblings() {
        let directory = TestDirectory::new();
        let config = fixture_config(&directory.path);
        let identities = crate::identity::load_or_create(&config).expect("fixture identity owner");
        let first = prepare(&config, &identities).expect("fixture filesystem layout");
        let cleanup = SocketDirectoryCleanup([first.socket_directory().to_path_buf()]);

        for path in [
            first.canonical_state_root(),
            first.controller_state_directory(),
            first.successor_state_directory(),
            first.authority_state_directory(),
            first.runtime_state_directory(),
            first.node_owner_directory(),
            first.node_state_directory(),
            first.node_bootstrap_directory(),
        ] {
            assert_eq!(
                fs::canonicalize(path).expect("canonical fixture directory"),
                path
            );
            assert_eq!(
                fs::symlink_metadata(path)
                    .expect("fixture directory metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
        }
        assert_eq!(
            first.node_state_directory().parent(),
            Some(first.node_owner_directory())
        );
        assert_eq!(
            first.node_bootstrap_directory().parent(),
            Some(first.node_owner_directory())
        );
        assert_ne!(
            first.node_state_directory(),
            first.node_bootstrap_directory()
        );
        assert_eq!(
            first.pxnb_bootstrap_path().parent(),
            Some(first.node_bootstrap_directory())
        );
        assert!(
            !first
                .pxnb_bootstrap_path()
                .starts_with(first.node_state_directory())
        );
        assert_eq!(
            first.node_management_socket_path().parent(),
            Some(first.node_socket_directory())
        );
        assert_eq!(
            first.node_socket_directory().parent(),
            Some(first.socket_directory())
        );
        assert_eq!(
            fs::symlink_metadata(first.node_socket_directory())
                .expect("private Node socket directory")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert!(
            first
                .node_management_socket_path()
                .as_os_str()
                .as_bytes()
                .len()
                <= MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES
        );

        let second = prepare(&config, &identities).expect("stable fixture filesystem reopen");
        assert_eq!(first.owned_paths(), second.owned_paths());
        drop(second);
        drop(first);
        drop(cleanup);
    }

    #[test]
    fn public_node_layout_contains_only_runtime_and_node_owners() {
        let directory = TestDirectory::new();
        let config = crate::config::developer_node_config_for_test(&directory.path);
        let identities =
            crate::identity::load_or_create_node(&config).expect("node-only identity owner");
        let first = prepare_node(&config, &identities).expect("node-only filesystem layout");
        let cleanup = SocketDirectoryCleanup([first.socket_directory().to_path_buf()]);

        for path in [
            first.canonical_state_root(),
            first.runtime_state_directory(),
            first.node_owner_directory(),
            first.node_state_directory(),
            first.node_bootstrap_directory(),
        ] {
            assert_eq!(
                fs::canonicalize(path).expect("canonical node directory"),
                path
            );
            assert_eq!(
                fs::symlink_metadata(path)
                    .expect("node directory metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
        }
        for absent in [
            CONTROLLER_STATE_DIRECTORY,
            SUCCESSOR_STATE_DIRECTORY,
            AUTHORITY_STATE_DIRECTORY,
            DISTRIBUTED_STATE_DIRECTORY,
        ] {
            assert!(!first.canonical_state_root().join(absent).exists());
        }
        assert!(
            !first
                .socket_directory()
                .join(AGENT_IPC_SOCKET_FILE)
                .exists()
        );
        assert!(
            !first
                .socket_directory()
                .join(INSPECTION_IPC_SOCKET_FILE)
                .exists()
        );
        assert!(
            !first
                .node_bootstrap_directory()
                .join(DISTRIBUTED_PXOB_BOOTSTRAP_FILE)
                .exists()
        );
        assert_eq!(first.node_observation_socket_path(), None);
        assert_eq!(first.pxob_bootstrap_path(), None);
        assert_eq!(first.node_enrollment_artifact_path(), None);
        assert!(
            !first
                .node_owner_directory()
                .join(NODE_ENROLLMENT_ARTIFACT_FILE)
                .exists()
        );
        assert!(
            !first
                .node_socket_directory()
                .join(NODE_OBSERVATION_SOCKET_FILE)
                .exists()
        );
        assert!(
            !first
                .node_bootstrap_directory()
                .join(PXOB_BOOTSTRAP_FILE)
                .exists()
        );
        let second = prepare_node(&config, &identities).expect("stable node-only reopen");
        assert_eq!(first.owned_paths(), second.owned_paths());
        assert_eq!(second.node_observation_socket_path(), None);
        assert_eq!(second.pxob_bootstrap_path(), None);
        assert_eq!(second.node_enrollment_artifact_path(), None);
        drop(second);
        drop(first);
        drop(cleanup);
    }

    #[test]
    fn deployment_layout_creates_only_two_private_stable_store_owners() {
        let directory = TestDirectory::new();
        let mut builder = DirBuilder::new();
        builder
            .mode(0o700)
            .create(&directory.path)
            .expect("Deployment state root");
        fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700))
            .expect("Deployment state root mode");
        let config = crate::config::developer_deployment_config_for_test(&directory.path);
        let mut first = prepare_deployment(&config).expect("minimal Deployment layout");
        for path in [
            first.canonical_state_root(),
            first.controller_store_state_directory(),
            first.managed_fabric_successor_store_state_directory(),
        ] {
            assert_eq!(
                fs::canonicalize(path).expect("canonical Deployment path"),
                path
            );
            assert_eq!(
                fs::symlink_metadata(path)
                    .expect("Deployment path metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
        }
        let mut entries = fs::read_dir(first.canonical_state_root())
            .expect("Deployment root entries")
            .map(|entry| {
                entry
                    .expect("Deployment root entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                DEPLOYMENT_CONTROLLER_STORE_DIRECTORY.to_string(),
                DEPLOYMENT_MANAGED_FABRIC_SUCCESSOR_STORE_DIRECTORY.to_string(),
            ]
        );
        for forbidden in [
            AUTHORITY_STATE_DIRECTORY,
            RUNTIME_STATE_DIRECTORY,
            NODE_OWNER_DIRECTORY,
            "agent",
            "model",
            "inspection",
            "console",
        ] {
            assert!(!first.canonical_state_root().join(forbidden).exists());
        }

        let second = prepare_deployment(&config).expect("stable Deployment layout reopen");
        assert_eq!(
            first.controller_store_state_directory(),
            second.controller_store_state_directory()
        );
        assert_eq!(
            first.managed_fabric_successor_store_state_directory(),
            second.managed_fabric_successor_store_state_directory()
        );
        drop(second);

        let successor = first.managed_fabric_successor_store_state_directory.clone();
        first.managed_fabric_successor_store_state_directory =
            first.controller_store_state_directory.clone();
        assert_eq!(
            first
                .validate(Uid::effective().as_raw(), Gid::effective().as_raw())
                .unwrap_err(),
            DeveloperLocalLayoutError::OverlappingPath
        );
        first.managed_fabric_successor_store_state_directory = successor;
    }

    #[test]
    fn deployment_layout_rejects_unknown_and_symlinked_owner_entries_before_creation() {
        use std::os::unix::fs::symlink;

        let unknown = TestDirectory::new();
        let mut builder = DirBuilder::new();
        builder
            .mode(0o700)
            .create(&unknown.path)
            .expect("Deployment state root");
        fs::set_permissions(&unknown.path, fs::Permissions::from_mode(0o700))
            .expect("Deployment state root mode");
        let config = crate::config::developer_deployment_config_for_test(&unknown.path);
        fs::create_dir(unknown.path.join("unexpected-owner")).expect("unexpected owner entry");
        assert_eq!(
            prepare_deployment(&config).unwrap_err(),
            DeveloperLocalLayoutError::InvalidDerivedPath
        );
        assert!(
            !unknown
                .path
                .join(DEPLOYMENT_CONTROLLER_STORE_DIRECTORY)
                .exists()
        );
        assert!(
            !unknown
                .path
                .join(DEPLOYMENT_MANAGED_FABRIC_SUCCESSOR_STORE_DIRECTORY)
                .exists()
        );

        let alias = TestDirectory::new();
        let mut builder = DirBuilder::new();
        builder
            .mode(0o700)
            .create(&alias.path)
            .expect("aliased Deployment state root");
        fs::set_permissions(&alias.path, fs::Permissions::from_mode(0o700))
            .expect("aliased Deployment state root mode");
        symlink(
            &alias.path,
            alias.path.join(DEPLOYMENT_CONTROLLER_STORE_DIRECTORY),
        )
        .expect("Deployment owner symlink");
        let alias_config = crate::config::developer_deployment_config_for_test(&alias.path);
        assert_eq!(
            prepare_deployment(&alias_config).unwrap_err(),
            DeveloperLocalLayoutError::InvalidDerivedPath
        );
    }

    #[test]
    fn public_node_v2_layout_adds_only_observation_and_enrollment_coordinates() {
        let directory = TestDirectory::new();
        let config = crate::config::developer_node_config_v2_for_test(&directory.path);
        let identities =
            crate::identity::load_or_create_node(&config).expect("node v2 identity owner");
        let mut first = prepare_node(&config, &identities).expect("node v2 filesystem layout");
        let cleanup = SocketDirectoryCleanup([first.socket_directory().to_path_buf()]);
        let base_paths = first.owned_paths();
        let observation_socket = first
            .node_observation_socket_path()
            .expect("schema v2 observation socket");
        let pxob_bootstrap = first
            .pxob_bootstrap_path()
            .expect("schema v2 PXOB coordinate");
        let enrollment_artifact = first
            .node_enrollment_artifact_path()
            .expect("schema v2 enrollment artifact coordinate");

        assert_eq!(
            observation_socket.parent(),
            Some(first.node_socket_directory())
        );
        assert_eq!(
            pxob_bootstrap.parent(),
            Some(first.node_bootstrap_directory())
        );
        assert_eq!(
            enrollment_artifact.parent(),
            Some(first.node_owner_directory())
        );
        assert_ne!(observation_socket, first.node_management_socket_path());
        assert_ne!(pxob_bootstrap, first.pxnb_bootstrap_path());
        assert_ne!(enrollment_artifact, first.pxnb_bootstrap_path());
        assert_ne!(Some(enrollment_artifact), first.pxob_bootstrap_path());
        assert!(!pxob_bootstrap.starts_with(first.node_state_directory()));
        assert!(!enrollment_artifact.starts_with(first.node_state_directory()));
        assert!(!enrollment_artifact.starts_with(first.node_bootstrap_directory()));
        assert!(base_paths.iter().all(|path| {
            *path != observation_socket && *path != pxob_bootstrap && *path != enrollment_artifact
        }));
        for absent in [
            CONTROLLER_STATE_DIRECTORY,
            SUCCESSOR_STATE_DIRECTORY,
            AUTHORITY_STATE_DIRECTORY,
            DISTRIBUTED_STATE_DIRECTORY,
        ] {
            assert!(!first.canonical_state_root().join(absent).exists());
        }
        assert!(
            !first
                .socket_directory()
                .join(AGENT_IPC_SOCKET_FILE)
                .exists()
        );
        assert!(
            !first
                .socket_directory()
                .join(INSPECTION_IPC_SOCKET_FILE)
                .exists()
        );

        let second = prepare_node(&config, &identities).expect("stable node v2 reopen");
        assert_eq!(base_paths, second.owned_paths());
        assert_eq!(
            Some(observation_socket),
            second.node_observation_socket_path()
        );
        assert_eq!(Some(pxob_bootstrap), second.pxob_bootstrap_path());
        assert_eq!(
            Some(enrollment_artifact),
            second.node_enrollment_artifact_path()
        );
        drop(second);

        let uid = Uid::effective().as_raw();
        let gid = Gid::effective().as_raw();
        let original_observation_socket = first.node_observation_socket_path.clone();
        first.node_observation_socket_path = Some(first.node_management_socket_path.clone());
        assert_eq!(
            first.validate(uid, gid).unwrap_err(),
            DeveloperLocalLayoutError::OverlappingPath
        );
        first.node_observation_socket_path = original_observation_socket;
        first.pxob_bootstrap_path = Some(first.pxnb_bootstrap_path.clone());
        assert_eq!(
            first.validate(uid, gid).unwrap_err(),
            DeveloperLocalLayoutError::OverlappingPath
        );
        drop(first);
        drop(cleanup);
    }

    #[test]
    fn public_node_v3_layout_versions_only_the_enrollment_coordinate() {
        let directory = TestDirectory::new();
        let config = crate::config::developer_node_config_v3_for_test(&directory.path);
        let identities =
            crate::identity::load_or_create_node(&config).expect("node v3 identity owner");
        let first = prepare_node(&config, &identities).expect("node v3 filesystem layout");
        let cleanup = SocketDirectoryCleanup([first.socket_directory().to_path_buf()]);
        let enrollment_artifact = first
            .node_enrollment_artifact_path()
            .expect("schema v3 enrollment artifact coordinate");

        assert_eq!(
            enrollment_artifact,
            first
                .node_owner_directory()
                .join(NODE_ENROLLMENT_ARTIFACT_V2_FILE)
        );
        assert_ne!(
            enrollment_artifact,
            first
                .node_owner_directory()
                .join(NODE_ENROLLMENT_ARTIFACT_FILE)
        );
        assert!(first.node_observation_socket_path().is_some());
        assert!(first.pxob_bootstrap_path().is_some());
        assert!(
            !first
                .node_owner_directory()
                .join(NODE_ENROLLMENT_ARTIFACT_FILE)
                .exists()
        );
        for absent in [
            CONTROLLER_STATE_DIRECTORY,
            SUCCESSOR_STATE_DIRECTORY,
            AUTHORITY_STATE_DIRECTORY,
            DISTRIBUTED_STATE_DIRECTORY,
            "agent",
            "model",
            "inspection",
            "console",
        ] {
            assert!(!first.canonical_state_root().join(absent).exists());
        }
        assert!(
            !first
                .socket_directory()
                .join(AGENT_IPC_SOCKET_FILE)
                .exists()
        );
        assert!(
            !first
                .socket_directory()
                .join(INSPECTION_IPC_SOCKET_FILE)
                .exists()
        );

        let second = prepare_node(&config, &identities).expect("stable node v3 reopen");
        assert_eq!(first.owned_paths(), second.owned_paths());
        assert_eq!(
            first.node_enrollment_artifact_path(),
            second.node_enrollment_artifact_path()
        );
        drop(second);
        drop(first);
        drop(cleanup);
    }

    #[test]
    fn layout_validation_rejects_reference_node_path_overlap_and_store_bootstrap() {
        let directory = TestDirectory::new();
        let config = fixture_config(&directory.path);
        let identities = crate::identity::load_or_create(&config).expect("fixture identity owner");
        let mut layout = prepare(&config, &identities).expect("fixture filesystem layout");
        let cleanup = SocketDirectoryCleanup([layout.socket_directory().to_path_buf()]);
        let uid = Uid::effective().as_raw();
        let gid = Gid::effective().as_raw();

        let node_management_socket_path = layout.node_management_socket_path.clone();
        layout.node_management_socket_path = layout.runtime_socket_path.clone();
        assert_eq!(
            layout.validate(uid, gid).unwrap_err(),
            DeveloperLocalLayoutError::InvalidDerivedPath
        );
        layout.node_management_socket_path = node_management_socket_path;
        layout.pxnb_bootstrap_path = layout.node_state_directory.join(PXNB_BOOTSTRAP_FILE);
        assert_eq!(
            layout.validate(uid, gid).unwrap_err(),
            DeveloperLocalLayoutError::InvalidDerivedPath
        );
        drop(layout);
        drop(cleanup);
    }

    #[test]
    fn distributed_layout_is_canonical_private_stable_and_cross_target_disjoint() {
        let directory = TestDirectory::new();
        let identities = crate::identity::initialize_distributed(&directory.path)
            .expect("distributed identity owner");
        let first = prepare_distributed(&directory.path, &identities)
            .expect("distributed filesystem layout");
        let cleanup = SocketDirectoryCleanup([
            first.coordinator().socket_directory().to_path_buf(),
            first
                .target(DistributedDeveloperLocalTargetV1::A)
                .socket_directory()
                .to_path_buf(),
            first
                .target(DistributedDeveloperLocalTargetV1::B)
                .socket_directory()
                .to_path_buf(),
        ]);
        assert_eq!(
            fs::canonicalize(first.canonical_state_root()).expect("canonical state root"),
            first.canonical_state_root()
        );
        for directory in [
            first.distributed_state_directory(),
            first.coordinator().state_directory(),
            first.coordinator().controller_state_directory(),
            first.coordinator().authority_state_directory(),
        ] {
            assert_eq!(
                fs::symlink_metadata(directory)
                    .expect("coordinator directory metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
        }
        let target_a = first.target(DistributedDeveloperLocalTargetV1::A);
        let target_b = first.target(DistributedDeveloperLocalTargetV1::B);
        validate_non_overlapping_sets(&target_a.owned_paths(), &target_b.owned_paths())
            .expect("A/B path ownership must be disjoint");
        assert_ne!(target_a.state_directory(), target_b.state_directory());
        assert_ne!(
            target_a.runtime_socket_path(),
            target_b.runtime_socket_path()
        );
        assert_ne!(
            target_a.pxnb_bootstrap_path(),
            target_b.pxnb_bootstrap_path()
        );
        assert_ne!(
            target_a.pxob_bootstrap_path(),
            target_b.pxob_bootstrap_path()
        );
        assert_ne!(
            target_a.agent_ipc_socket_path(),
            target_b.agent_ipc_socket_path()
        );
        assert_ne!(
            target_a.agent_ipc_bootstrap_path(),
            target_b.agent_ipc_bootstrap_path()
        );
        assert_ne!(
            first.coordinator().controller_state_directory(),
            first.coordinator().authority_state_directory()
        );
        for socket_directory in [
            first.coordinator().socket_directory(),
            target_a.socket_directory(),
            target_b.socket_directory(),
        ] {
            assert_eq!(
                fs::symlink_metadata(socket_directory)
                    .expect("socket directory metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o2750
            );
        }
        for target in [target_a, target_b] {
            assert_eq!(
                target.node_socket_directory().parent(),
                Some(target.socket_directory())
            );
            assert_eq!(
                fs::symlink_metadata(target.node_socket_directory())
                    .expect("private target Node socket directory")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
            for directory in [
                target.state_directory(),
                target.controller_base_state_directory(),
                target.controller_successor_state_directory(),
                target.runtime_state_directory(),
                target.evidence_state_directory(),
                target.node_owner_directory(),
                target.node_state_directory(),
                target.node_bootstrap_directory(),
            ] {
                assert_eq!(
                    fs::canonicalize(directory).expect("canonical target directory"),
                    directory
                );
                assert_eq!(
                    fs::symlink_metadata(directory)
                        .expect("target directory metadata")
                        .permissions()
                        .mode()
                        & 0o7777,
                    0o700
                );
            }
            assert_eq!(
                target.node_state_directory().parent(),
                Some(target.node_owner_directory())
            );
            assert_eq!(
                target.evidence_state_directory().parent(),
                Some(target.state_directory())
            );
            assert_eq!(
                target.node_bootstrap_directory().parent(),
                Some(target.node_owner_directory())
            );
            assert_ne!(
                target.node_state_directory(),
                target.node_bootstrap_directory()
            );
            assert_eq!(
                target.pxnb_bootstrap_path().parent(),
                Some(target.node_bootstrap_directory())
            );
            assert_eq!(
                target.pxob_bootstrap_path().parent(),
                Some(target.node_bootstrap_directory())
            );
            assert!(
                !target
                    .pxnb_bootstrap_path()
                    .starts_with(target.node_state_directory())
            );
            assert!(
                !target
                    .pxob_bootstrap_path()
                    .starts_with(target.node_state_directory())
            );
            assert_eq!(
                target.agent_ipc_bootstrap_path().parent(),
                Some(target.socket_directory())
            );
            for socket in [
                target.runtime_socket_path(),
                target.node_management_socket_path(),
                target.node_observation_socket_path(),
                target.agent_ipc_socket_path(),
            ] {
                assert!(socket.as_os_str().as_bytes().len() <= 103);
            }
        }

        let second = prepare_distributed(&directory.path, &identities)
            .expect("stable distributed filesystem reopen");
        assert_eq!(
            first.coordinator().owned_paths(),
            second.coordinator().owned_paths()
        );
        assert_eq!(
            first
                .target(DistributedDeveloperLocalTargetV1::A)
                .owned_paths(),
            second
                .target(DistributedDeveloperLocalTargetV1::A)
                .owned_paths()
        );
        assert_eq!(
            first
                .target(DistributedDeveloperLocalTargetV1::B)
                .owned_paths(),
            second
                .target(DistributedDeveloperLocalTargetV1::B)
                .owned_paths()
        );
        drop(second);
        drop(first);
        drop(cleanup);
    }

    #[test]
    fn distributed_layout_validation_rejects_cross_owner_and_long_socket_paths() {
        let directory = TestDirectory::new();
        let identities = crate::identity::initialize_distributed(&directory.path)
            .expect("distributed identity owner");
        let mut layout = prepare_distributed(&directory.path, &identities)
            .expect("distributed filesystem layout");
        let cleanup = SocketDirectoryCleanup([
            layout.coordinator().socket_directory().to_path_buf(),
            layout.targets[0].socket_directory().to_path_buf(),
            layout.targets[1].socket_directory().to_path_buf(),
        ]);
        let uid = Uid::effective().as_raw();
        let gid = Gid::effective().as_raw();

        layout.targets[1].runtime_socket_path = layout.targets[0].runtime_socket_path.clone();
        assert_eq!(
            layout.validate(uid, gid).unwrap_err(),
            DeveloperLocalLayoutError::InvalidDerivedPath
        );
        layout.targets[1].runtime_socket_path = layout.targets[1]
            .socket_directory
            .join("x".repeat(MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES + 1));
        assert_eq!(
            layout.validate(uid, gid).unwrap_err(),
            DeveloperLocalLayoutError::SocketPathTooLong
        );
        drop(layout);
        drop(cleanup);
    }

    #[test]
    fn distributed_layout_validation_rejects_node_bootstrap_inside_pxnd_store() {
        let directory = TestDirectory::new();
        let identities = crate::identity::initialize_distributed(&directory.path)
            .expect("distributed identity owner");
        let mut layout = prepare_distributed(&directory.path, &identities)
            .expect("distributed filesystem layout");
        let cleanup = SocketDirectoryCleanup([
            layout.coordinator().socket_directory().to_path_buf(),
            layout.targets[0].socket_directory().to_path_buf(),
            layout.targets[1].socket_directory().to_path_buf(),
        ]);
        let uid = Uid::effective().as_raw();
        let gid = Gid::effective().as_raw();

        layout.targets[0].pxnb_bootstrap_path = layout.targets[0]
            .node_state_directory
            .join(PXNB_BOOTSTRAP_FILE);
        assert_eq!(
            layout.validate(uid, gid).unwrap_err(),
            DeveloperLocalLayoutError::InvalidDerivedPath
        );
        drop(layout);
        drop(cleanup);
    }
}
