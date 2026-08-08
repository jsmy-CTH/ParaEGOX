//! Real node-local Inspection projection and private read-only endpoint.

use core::fmt;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use nix::dir::Dir;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, SFlag, fstatat};
use nix::unistd::{UnlinkatFlags, getegid, geteuid, linkat, unlinkat};
use paraegox_deployment::{
    DeveloperFixtureModelAgentStackOutcomeV1, DeveloperProvisionedModelAgentStackOutcomeV1,
};
use paraegox_inspection::adapter::{
    InspectionSourceAdapterV1, LocalInspectionProjectionInputBuilderV1,
    NodeInspectionSourceAdapterV2, read_inspection_source_slot_once_v1,
    read_node_inspection_source_slot_once_v2,
};
use paraegox_inspection::developer_local::{
    DEVELOPER_LOCAL_INSPECTION_REQUEST_V2_BYTES, DeveloperLocalInspectionBootstrapV2,
    decode_authenticated_request_v2,
};
use paraegox_inspection::protocol::MAX_INSPECTION_RESPONSE_V2_BYTES;
use paraegox_inspection::{
    InspectionFeatureSupportV1, InspectionHealthV1, InspectionLivenessV1,
    InspectionObservationClockRefV1, InspectionReadinessV1, InspectionReasonV1,
    InspectionSourceAvailabilityV1, InspectionSourceCoordinateV1, InspectionSourceOwnerV1,
    LocalInspectionProjectionInputV1, LocalInspectionProjectionInputV2, LocalInspectionServiceV2,
    NodeInspectionFactFieldsV2, NodeInspectionFactV2, OwnerInspectionFactFieldsV1,
    OwnerInspectionFactV1,
};
use paraegox_node::NodeStatusV1;
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    ManagedModelAgentStackTerminalHeadV1, ManagedModelAgentStackTerminalOutcomeV1,
    ManagedModelAgentStackTerminalReceiptV1,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, interval, timeout, timeout_at};
use zeroize::Zeroizing;

const SOCKET_MODE: u32 = 0o600;
const BOOTSTRAP_MODE: u32 = 0o600;
const MODE_MASK: u32 = 0o7777;
const SOCKET_PIN_PREFIX: &[u8] = b".pxi-";
const SOCKET_PIN_SUFFIX: &[u8] = b"-socket.pin";
const SOCKET_PIN_NONCE_HEX_BYTES: usize = 32;
const MAX_ENDPOINT_DIRECTORY_SCAN_ENTRIES: usize = 256;
const MAX_ENDPOINT_DIRECTORY_SCAN_NAME_BYTES: usize = 16 * 1024;
const MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES: usize = 103;
const MAX_IN_FLIGHT: usize = 8;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const SOURCE_FACT_VALIDITY: Duration = Duration::from_secs(10);
const PROJECTION_TICK_INTERVAL: Duration = Duration::from_millis(100);
const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const REQUIRED_NODE_RUNTIME_CONTRACT_VERSION: u16 = 1;
const REQUIRED_NODE_FABRIC_CONTRACT_VERSION: u16 = 1;

/// Actual immutable owner outputs selected by the DeveloperLocal composition.
#[derive(Clone)]
pub(crate) struct DeveloperLocalInspectionSourcesV2 {
    pub(crate) authority_subject: [u8; 16],
    pub(crate) deployment_subject: [u8; 16],
    pub(crate) runtime_subject: [u8; 16],
    pub(crate) runtime_store_instance_id: [u8; 32],
    pub(crate) runtime_response_key_ref: [u8; 16],
    pub(crate) runtime_response_public_key: [u8; 32],
    pub(crate) fabric_subject: [u8; 16],
    pub(crate) agent_subject: [u8; 16],
    pub(crate) node_status: NodeStatusV1,
    pub(crate) node_status_observed_at: Instant,
    pub(crate) deployment: DeveloperLocalDeploymentOutcomeV1,
}

#[derive(Clone)]
pub(crate) enum DeveloperLocalDeploymentOutcomeV1 {
    Fixture(DeveloperFixtureModelAgentStackOutcomeV1),
    Provisioned(DeveloperProvisionedModelAgentStackOutcomeV1),
}

impl DeveloperLocalDeploymentOutcomeV1 {
    pub(crate) fn agent_terminal_receipt(&self) -> &[u8] {
        match self {
            Self::Fixture(outcome) => outcome.model_agent_terminal_receipt(),
            Self::Provisioned(outcome) => outcome.model_agent_terminal_receipt(),
        }
    }
}

/// Joined owner for the private PXIQ/PXIP endpoint and PXIB file.
pub(crate) struct DeveloperLocalInspectionLifecycleV2 {
    socket_path: PathBuf,
    bootstrap_path: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), DeveloperLocalInspectionErrorV1>>>,
}

impl fmt::Debug for DeveloperLocalInspectionLifecycleV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalInspectionLifecycleV2")
            .field("socket_path", &self.socket_path)
            .field("bootstrap_path", &self.bootstrap_path)
            .field("running", &self.thread.is_some())
            .finish()
    }
}

impl DeveloperLocalInspectionLifecycleV2 {
    pub(crate) fn shutdown_and_join(mut self) -> Result<(), DeveloperLocalInspectionErrorV1> {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> Result<(), DeveloperLocalInspectionErrorV1> {
        let sender = self.shutdown.take();
        let thread = self.thread.take();
        if sender.is_none() && thread.is_none() {
            return Err(DeveloperLocalInspectionErrorV1::ShutdownAlreadyRequested);
        }
        if let Some(sender) = sender {
            let _ = sender.send(());
        }
        match thread {
            None => Ok(()),
            Some(thread) => thread
                .join()
                .map_err(|_| DeveloperLocalInspectionErrorV1::ThreadPanicked)?,
        }
    }
}

impl Drop for DeveloperLocalInspectionLifecycleV2 {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

/// Starts a separate read-only Inspection endpoint from verified owner facts.
pub(crate) fn start_developer_local_inspection_v2(
    sources: DeveloperLocalInspectionSourcesV2,
    socket_path: PathBuf,
    bootstrap_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<DeveloperLocalInspectionLifecycleV2, DeveloperLocalInspectionErrorV1> {
    start_developer_local_inspection_with_owner_preamble_v2(
        sources,
        socket_path,
        bootstrap_path,
        expected_uid,
        expected_gid,
        || {},
    )
}

#[cfg(test)]
pub(crate) fn start_developer_local_inspection_with_owner_preamble_for_test_v2(
    sources: DeveloperLocalInspectionSourcesV2,
    socket_path: PathBuf,
    bootstrap_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    owner_preamble: impl FnOnce() + Send + 'static,
) -> Result<DeveloperLocalInspectionLifecycleV2, DeveloperLocalInspectionErrorV1> {
    start_developer_local_inspection_with_owner_preamble_v2(
        sources,
        socket_path,
        bootstrap_path,
        expected_uid,
        expected_gid,
        owner_preamble,
    )
}

fn start_developer_local_inspection_with_owner_preamble_v2(
    sources: DeveloperLocalInspectionSourcesV2,
    socket_path: PathBuf,
    bootstrap_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    owner_preamble: impl FnOnce() + Send + 'static,
) -> Result<DeveloperLocalInspectionLifecycleV2, DeveloperLocalInspectionErrorV1> {
    validate_endpoint_paths(&socket_path, &bootstrap_path, expected_uid, expected_gid)?;
    let (projection, bootstrap) =
        build_projection(sources, &socket_path, expected_uid, expected_gid)?;
    // Complete every fallible owner initialization on the caller before the
    // thread exists. The bound standard listener already queues connections,
    // so thread scheduling is not a second readiness condition and cannot
    // turn a bounded startup wait into an unbounded `join`.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| DeveloperLocalInspectionErrorV1::EndpointFailed)?;
    let mut files =
        EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, expected_uid, expected_gid)?;
    let listener = bind_listener(
        &runtime,
        &socket_path,
        &files.directory,
        &mut files.socket,
        expected_uid,
        expected_gid,
    )?;
    let bootstrap_wire = bootstrap
        .encode()
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidProjection)?;
    create_bootstrap_file(
        &files.directory,
        &mut files.bootstrap,
        &bootstrap_wire,
        expected_uid,
        expected_gid,
    )?;
    let bootstrap = Arc::new(bootstrap);
    let projection = Arc::new(Mutex::new(projection));
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let thread = thread::Builder::new()
        .name("paraegox-local-inspection-v2".to_owned())
        .spawn(move || {
            owner_preamble();
            let serve_result = runtime.block_on(serve_endpoint(
                listener,
                bootstrap,
                projection,
                shutdown_receiver,
            ));
            let cleanup_result = files.cleanup();
            serve_result.and(cleanup_result)
        })
        .map_err(|_| DeveloperLocalInspectionErrorV1::ThreadStartFailed)?;
    Ok(DeveloperLocalInspectionLifecycleV2 {
        socket_path,
        bootstrap_path,
        shutdown: Some(shutdown_sender),
        thread: Some(thread),
    })
}

struct ProjectionOwnerV2 {
    service: LocalInspectionServiceV2,
    input: LocalInspectionProjectionInputV2,
    clock_started: Instant,
    source_valid_until_nanos: u64,
    stale_projected: bool,
}

impl ProjectionOwnerV2 {
    fn answer(
        &self,
        request: &paraegox_inspection::protocol::InspectionRequestV2,
    ) -> Result<Box<[u8]>, DeveloperLocalInspectionErrorV1> {
        self.service
            .answer_read_only_v2(request)
            .map(|response| response.canonical_wire().into())
            .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidProjection)
    }

    fn project_stale_if_due(&mut self) -> Result<(), DeveloperLocalInspectionErrorV1> {
        if self.stale_projected {
            return Ok(());
        }
        let projected_at_nanos = monotonic_nanos(self.clock_started)?;
        if projected_at_nanos <= self.source_valid_until_nanos {
            return Ok(());
        }
        self.service
            .project(projected_at_nanos, &self.input)
            .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidProjection)?;
        self.stale_projected = true;
        Ok(())
    }
}

fn build_projection(
    sources: DeveloperLocalInspectionSourcesV2,
    socket_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(ProjectionOwnerV2, DeveloperLocalInspectionBootstrapV2), DeveloperLocalInspectionErrorV1>
{
    let receipt = verify_agent_terminal(&sources)?;
    let (
        authority_tenure_epoch,
        authority_proof_digest,
        deployment_revision,
        deployment_snapshot_sequence,
        deployment_request_digest,
    ) = match &sources.deployment {
        DeveloperLocalDeploymentOutcomeV1::Fixture(outcome) => (
            outcome.authority_tenure_epoch(),
            outcome.authority_proof_digest(),
            outcome.controller_revision(),
            outcome.controller_snapshot_sequence(),
            outcome.model_agent_request_digest(),
        ),
        DeveloperLocalDeploymentOutcomeV1::Provisioned(outcome) => (
            outcome.authority_tenure_epoch(),
            outcome.authority_proof_digest(),
            outcome.controller_revision(),
            outcome.controller_snapshot_sequence(),
            outcome.model_agent_request_digest(),
        ),
    };
    let terminal_facts = receipt.facts();
    let terminal_state = terminal_facts.state();
    let terminal_evidence = terminal_facts.evidence().fields();
    let fabric_generation = terminal_state
        .fabric_generation()
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?
        .value();
    let agent_generation = terminal_state
        .agent_generation()
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?
        .value();

    let mut entropy = Zeroizing::new([0_u8; 80]);
    getrandom::fill(entropy.as_mut())
        .map_err(|_| DeveloperLocalInspectionErrorV1::EntropyUnavailable)?;
    let projection_id = copy_array::<16>(entropy.as_ref(), 0);
    let observation_clock_ref =
        InspectionObservationClockRefV1::try_from_bytes(copy_array::<16>(entropy.as_ref(), 16))
            .map_err(|_| DeveloperLocalInspectionErrorV1::EntropyUnavailable)?;
    let generation_token = Zeroizing::new(copy_array::<32>(entropy.as_ref(), 32));
    let request_seed = Zeroizing::new(copy_array::<16>(entropy.as_ref(), 64));
    // Start the projection clock before deriving the remaining source budget.
    // Any scheduling delay while facts are assembled must consume that budget
    // instead of shifting the resulting validity window into the future.
    let clock_started = Instant::now();
    let observed_at_nanos = 1_u64;
    let node_elapsed_nanos = u64::try_from(sources.node_status_observed_at.elapsed().as_nanos())
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    let now_unix_nanos = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?
            .as_nanos(),
    )
    .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    if now_unix_nanos == 0
        || !sources
            .node_status
            .is_fresh_at(0, node_elapsed_nanos, now_unix_nanos)
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidOwnerFacts);
    }
    let relative_remaining_nanos = sources
        .node_status
        .freshness_budget_nanos()
        .checked_sub(node_elapsed_nanos)
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    let node_remaining_nanos =
        sources
            .node_status
            .valid_until_unix_nanos()
            .map_or(relative_remaining_nanos, |deadline| {
                relative_remaining_nanos
                    .min(deadline.saturating_sub(now_unix_nanos).saturating_sub(1))
            });
    let source_fact_validity_nanos = u64::try_from(SOURCE_FACT_VALIDITY.as_nanos())
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidProjection)?;
    let common_projection_validity_nanos = source_fact_validity_nanos
        .saturating_sub(node_elapsed_nanos)
        .min(node_remaining_nanos);
    let valid_until_nanos = observed_at_nanos
        .checked_add(common_projection_validity_nanos)
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidProjection)?;

    let authority =
        AuthorityInspectionSourceAdapterV1::new(owner_fact(OwnerInspectionFactFieldsV1 {
            owner: InspectionSourceOwnerV1::Authority,
            subject_ref: sources.authority_subject,
            coordinate: InspectionSourceCoordinateV1::AuthorityTenure {
                tenure_epoch: authority_tenure_epoch,
                // DeveloperLocal admits one writer; the Authority-issued epoch is
                // therefore also the exact monotonic sequence of selected facts.
                fact_sequence: authority_tenure_epoch,
            },
            observation_clock_ref,
            observed_at_nanos,
            valid_until_nanos,
            availability: InspectionSourceAvailabilityV1::Observed,
            // WriterTenureProof authenticates the selected Authority epoch;
            // it is not a current process-liveness or readiness receipt.
            liveness: InspectionLivenessV1::Unknown,
            readiness: InspectionReadinessV1::Unknown,
            health: InspectionHealthV1::Unknown,
            feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
            reason: InspectionReasonV1::SourceUnknown,
            owner_fact_digest: authority_proof_digest,
        })?);
    let deployment =
        DeploymentInspectionSourceAdapterV1::new(owner_fact(OwnerInspectionFactFieldsV1 {
            owner: InspectionSourceOwnerV1::DeploymentController,
            subject_ref: sources.deployment_subject,
            coordinate: InspectionSourceCoordinateV1::DeploymentRevision {
                revision: deployment_revision,
                fact_sequence: deployment_snapshot_sequence,
            },
            observation_clock_ref,
            observed_at_nanos,
            valid_until_nanos,
            availability: InspectionSourceAvailabilityV1::Observed,
            // This composition has no persistent Controller control endpoint.
            liveness: InspectionLivenessV1::Unknown,
            readiness: InspectionReadinessV1::Unknown,
            health: InspectionHealthV1::Unknown,
            feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
            reason: InspectionReasonV1::SourceUnknown,
            owner_fact_digest: deployment_request_digest,
        })?);
    let runtime = RuntimeInspectionSourceAdapterV1::new(owner_fact(OwnerInspectionFactFieldsV1 {
        owner: InspectionSourceOwnerV1::RuntimeHost,
        subject_ref: sources.runtime_subject,
        coordinate: InspectionSourceCoordinateV1::RuntimeHostEpoch {
            runtime_host_epoch: terminal_evidence.completion_runtime_host_epoch,
            snapshot_sequence: terminal_evidence.completion_snapshot_sequence,
        },
        observation_clock_ref,
        observed_at_nanos,
        valid_until_nanos,
        availability: InspectionSourceAvailabilityV1::Observed,
        // PXST proves committed readiness at completion, not current liveness.
        liveness: InspectionLivenessV1::Unknown,
        readiness: InspectionReadinessV1::Ready,
        health: InspectionHealthV1::Unknown,
        feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
        reason: InspectionReasonV1::SourceUnknown,
        owner_fact_digest: receipt.receipt_digest(),
    })?);
    let fabric = FabricInspectionSourceAdapterV1::new(owner_fact(OwnerInspectionFactFieldsV1 {
        owner: InspectionSourceOwnerV1::FabricService,
        subject_ref: sources.fabric_subject,
        coordinate: InspectionSourceCoordinateV1::FabricServiceGeneration {
            service_generation: fabric_generation,
            observation_sequence: terminal_evidence.completion_snapshot_sequence,
        },
        observation_clock_ref,
        observed_at_nanos,
        valid_until_nanos,
        availability: InspectionSourceAvailabilityV1::Observed,
        // PXST proves committed readiness at completion, not current liveness.
        liveness: InspectionLivenessV1::Unknown,
        readiness: InspectionReadinessV1::Ready,
        health: InspectionHealthV1::Unknown,
        feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
        reason: InspectionReasonV1::SourceUnknown,
        owner_fact_digest: receipt.receipt_digest(),
    })?);
    let agent = AgentInspectionSourceAdapterV1::new(owner_fact(OwnerInspectionFactFieldsV1 {
        owner: InspectionSourceOwnerV1::AgentService,
        subject_ref: sources.agent_subject,
        coordinate: InspectionSourceCoordinateV1::AgentServiceGeneration {
            service_generation: agent_generation,
            observation_sequence: terminal_evidence.completion_snapshot_sequence,
        },
        observation_clock_ref,
        observed_at_nanos,
        valid_until_nanos,
        availability: InspectionSourceAvailabilityV1::Observed,
        // PXST proves committed readiness at completion, not current liveness.
        liveness: InspectionLivenessV1::Unknown,
        readiness: InspectionReadinessV1::Ready,
        health: InspectionHealthV1::Unknown,
        feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
        reason: InspectionReasonV1::SourceUnknown,
        owner_fact_digest: receipt.receipt_digest(),
    })?);
    let base_input = assemble_projection_input(
        observation_clock_ref,
        authority,
        deployment,
        runtime,
        fabric,
        agent,
    )?;
    let node_valid_until_nanos = valid_until_nanos;
    let node_feature = sources.node_status.feature_report();
    let feature_support = if node_feature.runtime_contract_version()
        == REQUIRED_NODE_RUNTIME_CONTRACT_VERSION
        && node_feature.fabric_contract_version() == REQUIRED_NODE_FABRIC_CONTRACT_VERSION
    {
        InspectionFeatureSupportV1::AllRequiredSupported
    } else {
        InspectionFeatureSupportV1::RequiredUnsupported
    };
    let reason = if feature_support == InspectionFeatureSupportV1::AllRequiredSupported {
        InspectionReasonV1::SourceUnknown
    } else {
        InspectionReasonV1::FeatureUnsupported
    };
    let node_fact = NodeInspectionFactV2::try_new(NodeInspectionFactFieldsV2 {
        node_ref: *sources.node_status.node_id().as_bytes(),
        node_incarnation_ref: *sources.node_status.node_incarnation().as_bytes(),
        registration_epoch: sources.node_status.registration_epoch(),
        status_sequence: sources.node_status.status_sequence(),
        observation_clock_ref,
        observed_at_nanos,
        valid_until_nanos: node_valid_until_nanos,
        availability: InspectionSourceAvailabilityV1::Observed,
        // The authenticated management exchange proves this child answered
        // for the exact tenure. PXNS carries no Node-level readiness/health.
        liveness: InspectionLivenessV1::Live,
        readiness: InspectionReadinessV1::Unknown,
        health: InspectionHealthV1::Unknown,
        feature_support,
        reason,
        node_status_digest: sources.node_status.status_digest(),
    })
    .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    let mut node_adapter = DeveloperLocalNodeInspectionSourceAdapterV2::new(node_fact);
    let node_slot =
        read_node_inspection_source_slot_once_v2(&mut node_adapter, observation_clock_ref)
            .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    let input = LocalInspectionProjectionInputV2::try_new(base_input, node_slot)
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    let source_valid_until_nanos = valid_until_nanos.min(node_valid_until_nanos);
    let projected_at_nanos = monotonic_nanos(clock_started)?;
    let mut service = LocalInspectionServiceV2::try_new(projection_id, observation_clock_ref)
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidProjection)?;
    service
        .project(projected_at_nanos, &input)
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidProjection)?;
    let bootstrap = DeveloperLocalInspectionBootstrapV2::try_new(
        socket_path.to_path_buf(),
        projection_id,
        generation_token,
        expected_uid,
        expected_gid,
        IO_TIMEOUT,
        request_seed,
    )
    .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidProjection)?;
    Ok((
        ProjectionOwnerV2 {
            service,
            input,
            clock_started,
            source_valid_until_nanos,
            stale_projected: projected_at_nanos > source_valid_until_nanos,
        },
        bootstrap,
    ))
}

fn verify_agent_terminal(
    sources: &DeveloperLocalInspectionSourcesV2,
) -> Result<ManagedModelAgentStackTerminalReceiptV1, DeveloperLocalInspectionErrorV1> {
    let (wire, expected_digest) = match &sources.deployment {
        DeveloperLocalDeploymentOutcomeV1::Fixture(outcome) => (
            outcome.model_agent_terminal_receipt(),
            outcome.model_agent_receipt_digest(),
        ),
        DeveloperLocalDeploymentOutcomeV1::Provisioned(outcome) => (
            outcome.model_agent_terminal_receipt(),
            outcome.model_agent_receipt_digest(),
        ),
    };
    let receipt = ManagedModelAgentStackTerminalReceiptV1::decode(wire)
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    let facts = receipt.facts();
    let state = facts.state();
    let evidence = facts.evidence().fields();
    if facts.target().as_bytes() != &sources.runtime_subject
        || facts.runtime_store_instance_id() != sources.runtime_store_instance_id
        || receipt.authentication_key().as_bytes() != &sources.runtime_response_key_ref
        || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
        || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        || receipt.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        || receipt.receipt_digest() != expected_digest
        || state.outcome() != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
        || state.head() != ManagedModelAgentStackTerminalHeadV1::CommittedIncoming
        || state.fabric_generation().is_none()
        || state.model_generation().is_none()
        || state.agent_generation().is_none()
        || evidence.physical_binding_census != 2
        || !evidence.census_complete
        || !evidence.fabric_ready
        || !evidence.model_ready
        || !evidence.agent_ready
        || !evidence.fabric_to_agent_dependency_ready
        || !evidence.model_to_agent_dependency_ready
        || evidence.exact_zero
        || evidence.quarantined
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidOwnerFacts);
    }
    let signature: [u8; ED25519_SIGNATURE_BYTES] = receipt
        .authentication_signature()
        .try_into()
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    VerifyingKey::from_bytes(&sources.runtime_response_public_key)
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?
        .verify_strict(
            receipt
                .signing_transcript()
                .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?
                .as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    Ok(receipt)
}

fn owner_fact(
    fields: OwnerInspectionFactFieldsV1,
) -> Result<OwnerInspectionFactV1, DeveloperLocalInspectionErrorV1> {
    OwnerInspectionFactV1::try_new(fields)
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)
}

macro_rules! source_adapter {
    ($name:ident, $owner:path) => {
        struct $name {
            fact: Option<OwnerInspectionFactV1>,
        }

        impl $name {
            const fn new(fact: OwnerInspectionFactV1) -> Self {
                Self { fact: Some(fact) }
            }
        }

        impl InspectionSourceAdapterV1 for $name {
            type Error = DeveloperLocalSourceAdapterErrorV1;

            fn owner(&self) -> InspectionSourceOwnerV1 {
                $owner
            }

            fn subject_ref(&self) -> [u8; 16] {
                self.fact
                    .map(OwnerInspectionFactV1::fields)
                    .map_or([0; 16], |fields| fields.subject_ref)
            }

            fn read_verified_fact_once(
                &mut self,
                observation_clock_ref: InspectionObservationClockRefV1,
            ) -> Result<Option<OwnerInspectionFactV1>, Self::Error> {
                let fact = self
                    .fact
                    .take()
                    .ok_or(DeveloperLocalSourceAdapterErrorV1::AlreadyRead)?;
                if fact.fields().observation_clock_ref != observation_clock_ref {
                    return Err(DeveloperLocalSourceAdapterErrorV1::ClockMismatch);
                }
                Ok(Some(fact))
            }
        }
    };
}

source_adapter!(
    AuthorityInspectionSourceAdapterV1,
    InspectionSourceOwnerV1::Authority
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeveloperLocalSourceAdapterErrorV1 {
    AlreadyRead,
    ClockMismatch,
}

impl fmt::Display for DeveloperLocalSourceAdapterErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyRead => "DeveloperLocal Inspection source was already read",
            Self::ClockMismatch => "DeveloperLocal Inspection source clock mismatched",
        })
    }
}

impl std::error::Error for DeveloperLocalSourceAdapterErrorV1 {}
source_adapter!(
    DeploymentInspectionSourceAdapterV1,
    InspectionSourceOwnerV1::DeploymentController
);
source_adapter!(
    RuntimeInspectionSourceAdapterV1,
    InspectionSourceOwnerV1::RuntimeHost
);
source_adapter!(
    FabricInspectionSourceAdapterV1,
    InspectionSourceOwnerV1::FabricService
);
source_adapter!(
    AgentInspectionSourceAdapterV1,
    InspectionSourceOwnerV1::AgentService
);

struct DeveloperLocalNodeInspectionSourceAdapterV2 {
    fact: Option<NodeInspectionFactV2>,
}

impl DeveloperLocalNodeInspectionSourceAdapterV2 {
    const fn new(fact: NodeInspectionFactV2) -> Self {
        Self { fact: Some(fact) }
    }
}

impl NodeInspectionSourceAdapterV2 for DeveloperLocalNodeInspectionSourceAdapterV2 {
    type Error = DeveloperLocalSourceAdapterErrorV1;

    fn node_ref(&self) -> [u8; 16] {
        self.fact
            .map(NodeInspectionFactV2::fields)
            .map_or([0; 16], |fields| fields.node_ref)
    }

    fn node_incarnation_ref(&self) -> [u8; 16] {
        self.fact
            .map(NodeInspectionFactV2::fields)
            .map_or([0; 16], |fields| fields.node_incarnation_ref)
    }

    fn read_verified_fact_once(
        &mut self,
        observation_clock_ref: InspectionObservationClockRefV1,
    ) -> Result<Option<NodeInspectionFactV2>, Self::Error> {
        let fact = self
            .fact
            .take()
            .ok_or(DeveloperLocalSourceAdapterErrorV1::AlreadyRead)?;
        if fact.fields().observation_clock_ref != observation_clock_ref {
            return Err(DeveloperLocalSourceAdapterErrorV1::ClockMismatch);
        }
        Ok(Some(fact))
    }
}

fn assemble_projection_input(
    clock: InspectionObservationClockRefV1,
    mut authority: AuthorityInspectionSourceAdapterV1,
    mut deployment: DeploymentInspectionSourceAdapterV1,
    mut runtime: RuntimeInspectionSourceAdapterV1,
    mut fabric: FabricInspectionSourceAdapterV1,
    mut agent: AgentInspectionSourceAdapterV1,
) -> Result<LocalInspectionProjectionInputV1, DeveloperLocalInspectionErrorV1> {
    let mut builder = LocalInspectionProjectionInputBuilderV1::new(clock);
    for slot in [
        read_inspection_source_slot_once_v1(&mut authority, clock),
        read_inspection_source_slot_once_v1(&mut deployment, clock),
        read_inspection_source_slot_once_v1(&mut runtime, clock),
        read_inspection_source_slot_once_v1(&mut fabric, clock),
        read_inspection_source_slot_once_v1(&mut agent, clock),
    ] {
        builder
            .try_insert(slot.map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?)
            .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)?;
    }
    builder
        .try_build()
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidOwnerFacts)
}

async fn serve_endpoint(
    listener: UnixListener,
    bootstrap: Arc<DeveloperLocalInspectionBootstrapV2>,
    projection: Arc<Mutex<ProjectionOwnerV2>>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks = JoinSet::new();
    let mut task_panicked = false;
    let mut projection_tick = interval(PROJECTION_TICK_INTERVAL);
    projection_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    projection_tick.tick().await;
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = projection_tick.tick() => {
                projection
                    .lock()
                    .await
                    .project_stale_if_due()?;
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    task_panicked = true;
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                if !peer_matches(&stream, bootstrap.server_uid(), bootstrap.server_gid()) {
                    drop(stream);
                    continue;
                }
                let bootstrap = Arc::clone(&bootstrap);
                let projection = Arc::clone(&projection);
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = serve_connection(stream, bootstrap, projection).await;
                });
            }
        }
    }

    let deadline = TokioInstant::now() + SHUTDOWN_TIMEOUT;
    while !tasks.is_empty() {
        match timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(()))) => {}
            Ok(Some(Err(_))) => task_panicked = true,
            Ok(None) => break,
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
        }
    }
    if task_panicked {
        Err(DeveloperLocalInspectionErrorV1::EndpointFailed)
    } else {
        Ok(())
    }
}

fn peer_matches(stream: &UnixStream, expected_uid: u32, expected_gid: u32) -> bool {
    stream.peer_cred().is_ok_and(|credentials| {
        credentials.uid() == expected_uid && credentials.gid() == expected_gid
    })
}

async fn serve_connection(
    mut stream: UnixStream,
    bootstrap: Arc<DeveloperLocalInspectionBootstrapV2>,
    projection: Arc<Mutex<ProjectionOwnerV2>>,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let mut wire = Zeroizing::new([0_u8; DEVELOPER_LOCAL_INSPECTION_REQUEST_V2_BYTES]);
    timeout(IO_TIMEOUT, stream.read_exact(wire.as_mut()))
        .await
        .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    let mut trailing = [0_u8; 1];
    if timeout(IO_TIMEOUT, stream.read(&mut trailing))
        .await
        .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?
        != 0
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidRequest);
    }
    let request = decode_authenticated_request_v2(wire.as_ref(), bootstrap.generation_token())
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidRequest)?;
    if request.projection_id() != bootstrap.projection_id() {
        return Err(DeveloperLocalInspectionErrorV1::InvalidRequest);
    }
    let response = {
        let projection = projection.lock().await;
        projection.answer(&request)?
    };
    if response.len() > MAX_INSPECTION_RESPONSE_V2_BYTES {
        return Err(DeveloperLocalInspectionErrorV1::InvalidProjection);
    }
    let response_length = u32::try_from(response.len())
        .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidProjection)?;
    timeout(IO_TIMEOUT, async {
        stream.write_all(&response_length.to_be_bytes()).await?;
        stream.write_all(&response).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
    .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))
}

fn validate_endpoint_paths(
    socket_path: &Path,
    bootstrap_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    if expected_uid == 0
        || expected_gid == 0
        || geteuid().as_raw() != expected_uid
        || getegid().as_raw() != expected_gid
        || socket_path == bootstrap_path
        || socket_path.parent() != bootstrap_path.parent()
        || socket_path.as_os_str().as_encoded_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    for path in [socket_path, bootstrap_path] {
        if !path.is_absolute()
            || path.file_name().is_none()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
    }
    let parent = socket_path
        .parent()
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    validate_private_parent(parent, expected_uid, expected_gid)
}

fn validate_private_parent(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    validate_private_parent_metadata(&metadata, expected_uid, expected_gid)
}

fn validate_private_parent_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let mode = metadata.permissions().mode() & MODE_MASK;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || mode & 0o700 != 0o700
        || mode & 0o022 != 0
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn bind_listener(
    runtime: &tokio::runtime::Runtime,
    path: &Path,
    directory: &EndpointDirectory,
    target: &mut EndpointTarget,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<UnixListener, DeveloperLocalInspectionErrorV1> {
    bind_listener_with_post_bind(
        runtime,
        path,
        directory,
        target,
        expected_uid,
        expected_gid,
        || Ok(()),
    )
}

fn bind_listener_with_post_bind(
    runtime: &tokio::runtime::Runtime,
    path: &Path,
    directory: &EndpointDirectory,
    target: &mut EndpointTarget,
    expected_uid: u32,
    expected_gid: u32,
    post_bind: impl FnOnce() -> Result<(), DeveloperLocalInspectionErrorV1>,
) -> Result<UnixListener, DeveloperLocalInspectionErrorV1> {
    bind_listener_with_hooks(BindListenerWithHooksInput {
        runtime,
        path,
        directory,
        target,
        expected_uid,
        expected_gid,
        proof_timeout: IO_TIMEOUT,
        post_raw_bind: || {},
        post_bind,
    })
}

struct BindListenerWithHooksInput<'a, PostRawBind, PostBind> {
    runtime: &'a tokio::runtime::Runtime,
    path: &'a Path,
    directory: &'a EndpointDirectory,
    target: &'a mut EndpointTarget,
    expected_uid: u32,
    expected_gid: u32,
    proof_timeout: Duration,
    post_raw_bind: PostRawBind,
    post_bind: PostBind,
}

fn bind_listener_with_hooks<PostRawBind, PostBind>(
    input: BindListenerWithHooksInput<'_, PostRawBind, PostBind>,
) -> Result<UnixListener, DeveloperLocalInspectionErrorV1>
where
    PostRawBind: FnOnce(),
    PostBind: FnOnce() -> Result<(), DeveloperLocalInspectionErrorV1>,
{
    let BindListenerWithHooksInput {
        runtime,
        path,
        directory,
        target,
        expected_uid,
        expected_gid,
        proof_timeout,
        post_raw_bind,
        post_bind,
    } = input;
    let mut listener_proof = Zeroizing::new([0_u8; 64]);
    getrandom::fill(listener_proof.as_mut())
        .map_err(|_| DeveloperLocalInspectionErrorV1::EntropyUnavailable)?;
    recover_stale_socket_generation(directory, target, expected_uid, expected_gid)?;
    directory.validate_named_identity()?;
    let standard_listener = StdUnixListener::bind(path)
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    standard_listener
        .set_nonblocking(true)
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    post_raw_bind();
    let created_metadata = fs::symlink_metadata(path)
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    let named = read_target_metadata(directory, &target.name)?
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    let created_identity = FileIdentity::from_metadata(&created_metadata);
    if named.identity != created_identity {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    // A UnixListener descriptor is not the filesystem socket inode on macOS.
    // Pin the candidate inode with a generation-private hard link, but do not
    // arm public-name cleanup until a nonce-correlated self-connect proves that
    // this process's listener still owns the public path.
    let identity_pin_name = target
        .path_identity_pin_name
        .as_ref()
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    ensure_target_missing(directory, identity_pin_name)?;
    linkat(
        &directory.file,
        target.name.as_os_str(),
        &directory.file,
        identity_pin_name.as_os_str(),
        AtFlags::empty(),
    )
    .map_err(nix_io)?;
    target.path_identity_pin_linked = true;
    target.path_identity_pin_identity = Some(created_identity);
    let pinned = read_target_metadata(directory, identity_pin_name)?
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    target.path_identity_pin_identity = Some(pinned.identity);
    if pinned.identity != created_identity {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    let listener = {
        let _entered = runtime.enter();
        UnixListener::from_std(standard_listener)
            .map_err(|_| DeveloperLocalInspectionErrorV1::EndpointFailed)?
    };
    prove_bound_listener(runtime, &listener, path, &listener_proof, proof_timeout)?;
    let proven_public = fs::symlink_metadata(path)
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    let proven_pin = read_target_metadata(directory, identity_pin_name)?
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    if FileIdentity::from_metadata(&proven_public) != created_identity
        || proven_pin.identity != created_identity
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    target.identity = Some(created_identity);
    post_bind()?;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    validate_target(&metadata, expected_uid, expected_gid, TargetKind::Socket)?;
    let named = read_target_metadata(directory, &target.name)?
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    validate_target_metadata(&named, expected_uid, expected_gid, TargetKind::Socket)?;
    let identity = FileIdentity::from_metadata(&metadata);
    if named.identity != identity || named.identity != created_identity {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    directory.validate_named_identity()?;
    directory.sync()?;
    Ok(listener)
}

fn prove_bound_listener(
    runtime: &tokio::runtime::Runtime,
    listener: &UnixListener,
    path: &Path,
    proof: &[u8; 64],
    proof_timeout: Duration,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    runtime.block_on(async {
        let deadline = TokioInstant::now() + proof_timeout;
        let mut client = timeout_at(deadline, UnixStream::connect(path))
            .await
            .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        let (mut server, _) = timeout_at(deadline, listener.accept())
            .await
            .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        timeout_at(deadline, client.write_all(&proof[..32]))
            .await
            .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        let mut client_proof = Zeroizing::new([0_u8; 32]);
        timeout_at(deadline, server.read_exact(client_proof.as_mut()))
            .await
            .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        if client_proof[..] != proof[..32] {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        timeout_at(deadline, server.write_all(&proof[32..]))
            .await
            .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        let mut server_proof = Zeroizing::new([0_u8; 32]);
        timeout_at(deadline, client.read_exact(server_proof.as_mut()))
            .await
            .map_err(|_| DeveloperLocalInspectionErrorV1::IoTimedOut)?
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        if server_proof[..] != proof[32..] {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        Ok(())
    })
}

fn create_bootstrap_file(
    directory: &EndpointDirectory,
    target: &mut EndpointTarget,
    wire: &[u8],
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    create_bootstrap_file_with_post_write(
        directory,
        target,
        wire,
        expected_uid,
        expected_gid,
        || Ok(()),
    )
}

fn create_bootstrap_file_with_post_write(
    directory: &EndpointDirectory,
    target: &mut EndpointTarget,
    wire: &[u8],
    expected_uid: u32,
    expected_gid: u32,
    post_write: impl FnOnce() -> Result<(), DeveloperLocalInspectionErrorV1>,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    remove_stale_target(directory, target, expected_uid, expected_gid)?;
    directory.validate_named_identity()?;
    let owned = openat(
        &directory.file,
        target.name.as_os_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(nix_io)?;
    target.file_identity_pin = Some(File::from(owned));
    let created_metadata = target
        .file_identity_pin
        .as_ref()
        .ok_or(DeveloperLocalInspectionErrorV1::EndpointFailed)?
        .metadata()
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    // O_EXCL created this entry in the pinned directory. Track its identity
    // before writing or synchronizing so every later failure is recoverable.
    target.identity = Some(FileIdentity::from_metadata(&created_metadata));
    target
        .file_identity_pin
        .as_mut()
        .ok_or(DeveloperLocalInspectionErrorV1::EndpointFailed)?
        .write_all(wire)
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    post_write()?;
    let file = target
        .file_identity_pin
        .as_ref()
        .ok_or(DeveloperLocalInspectionErrorV1::EndpointFailed)?;
    file.sync_all()
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    let named = read_target_metadata(directory, &target.name)?
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    validate_target(&metadata, expected_uid, expected_gid, TargetKind::Regular)?;
    validate_target_metadata(&named, expected_uid, expected_gid, TargetKind::Regular)?;
    let identity = FileIdentity::from_metadata(&metadata);
    if named.identity != identity
        || metadata.len() != u64::try_from(wire.len()).unwrap_or(u64::MAX)
        || named.length != metadata.len()
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    directory.validate_named_identity()?;
    directory.sync()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetKind {
    Socket,
    Regular,
}

fn recover_stale_socket_generation(
    directory: &EndpointDirectory,
    target: &EndpointTarget,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    if target.kind != TargetKind::Socket || target.path_identity_pin_name.is_none() {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    let pin_name = scan_socket_generation_pin(directory)?;
    let public = read_target_metadata(directory, &target.name)?;
    match (public, pin_name) {
        (None, None) => directory.validate_named_identity(),
        (Some(public), None) => {
            validate_recovery_socket_metadata(&public, expected_uid, expected_gid, 1)?;
            let observed = observe_inactive_socket_name(directory, &target.name, public.identity)?;
            validate_recovery_socket_metadata(&observed, expected_uid, expected_gid, 1)?;
            remove_named_target_exact(directory, &target.name, &target.quarantine_name, observed)
        }
        (None, Some(pin_name)) => {
            let pin = read_target_metadata(directory, &pin_name)?
                .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
            validate_recovery_socket_metadata(&pin, expected_uid, expected_gid, 1)?;
            let observed = observe_inactive_socket_name(directory, &pin_name, pin.identity)?;
            validate_recovery_socket_metadata(&observed, expected_uid, expected_gid, 1)?;
            remove_named_target_exact(directory, &pin_name, &target.quarantine_name, observed)
        }
        (Some(public), Some(pin_name)) => {
            let pin = read_target_metadata(directory, &pin_name)?
                .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
            validate_recovery_socket_metadata(&public, expected_uid, expected_gid, 2)?;
            validate_recovery_socket_metadata(&pin, expected_uid, expected_gid, 2)?;
            if public.identity != pin.identity {
                return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
            }
            let public = observe_inactive_socket_name(directory, &target.name, public.identity)?;
            let pin = observe_inactive_socket_name(directory, &pin_name, pin.identity)?;
            validate_recovery_socket_metadata(&public, expected_uid, expected_gid, 2)?;
            validate_recovery_socket_metadata(&pin, expected_uid, expected_gid, 2)?;
            if public.identity != pin.identity {
                return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
            }
            remove_named_target_exact(directory, &pin_name, &target.quarantine_name, pin)?;
            let public = read_target_metadata(directory, &target.name)?
                .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
            validate_recovery_socket_metadata(&public, expected_uid, expected_gid, 1)?;
            if public.identity != pin.identity {
                return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
            }
            remove_named_target_exact(directory, &target.name, &target.quarantine_name, public)
        }
    }
}

fn scan_socket_generation_pin(
    directory: &EndpointDirectory,
) -> Result<Option<OsString>, DeveloperLocalInspectionErrorV1> {
    directory.validate_named_identity()?;
    let duplicate = directory
        .file
        .try_clone()
        .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
    let descriptor: OwnedFd = duplicate.into();
    let mut entries = Dir::from_fd(descriptor).map_err(nix_io)?;
    let mut scanned_entries = 0_usize;
    let mut scanned_name_bytes = 0_usize;
    let mut pin_name = None;
    for entry in entries.iter() {
        let entry = entry.map_err(nix_io)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        scanned_entries = scanned_entries
            .checked_add(1)
            .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
        scanned_name_bytes = scanned_name_bytes
            .checked_add(name.len())
            .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
        if scanned_entries > MAX_ENDPOINT_DIRECTORY_SCAN_ENTRIES
            || scanned_name_bytes > MAX_ENDPOINT_DIRECTORY_SCAN_NAME_BYTES
        {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        if !name.starts_with(SOCKET_PIN_PREFIX) {
            continue;
        }
        if !is_canonical_socket_pin_name(name) || pin_name.is_some() {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        pin_name = Some(OsString::from_vec(name.to_vec()));
    }
    directory.validate_named_identity()?;
    Ok(pin_name)
}

fn is_canonical_socket_pin_name(name: &[u8]) -> bool {
    let expected_length =
        SOCKET_PIN_PREFIX.len() + SOCKET_PIN_NONCE_HEX_BYTES + SOCKET_PIN_SUFFIX.len();
    name.len() == expected_length
        && name.starts_with(SOCKET_PIN_PREFIX)
        && name.ends_with(SOCKET_PIN_SUFFIX)
        && name[SOCKET_PIN_PREFIX.len()..SOCKET_PIN_PREFIX.len() + SOCKET_PIN_NONCE_HEX_BYTES]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn observe_inactive_socket_name(
    directory: &EndpointDirectory,
    name: &OsStr,
    expected: FileIdentity,
) -> Result<TargetMetadata, DeveloperLocalInspectionErrorV1> {
    match StdUnixStream::connect(directory.path.join(name)) {
        Ok(stream) => {
            drop(stream);
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(DeveloperLocalInspectionErrorV1::Io(error.kind())),
    }
    directory.validate_named_identity()?;
    let metadata = read_target_metadata(directory, name)?
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    if metadata.identity != expected {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    Ok(metadata)
}

fn validate_recovery_socket_metadata(
    metadata: &TargetMetadata,
    expected_uid: u32,
    expected_gid: u32,
    expected_link_count: u64,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    validate_target_metadata(metadata, expected_uid, expected_gid, TargetKind::Socket)?;
    if metadata.link_count != expected_link_count {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn remove_stale_target(
    directory: &EndpointDirectory,
    target: &EndpointTarget,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let Some(metadata) = read_target_metadata(directory, &target.name)? else {
        return Ok(());
    };
    validate_target_metadata(&metadata, expected_uid, expected_gid, target.kind)?;
    remove_target_if_same_with(directory, target, metadata.identity, || {})
}

fn validate_target(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
    kind: TargetKind,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let type_matches = match kind {
        TargetKind::Socket => metadata.file_type().is_socket(),
        TargetKind::Regular => metadata.is_file(),
    };
    let expected_mode = match kind {
        TargetKind::Socket => SOCKET_MODE,
        TargetKind::Regular => BOOTSTRAP_MODE,
    };
    if metadata.file_type().is_symlink()
        || !type_matches
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & MODE_MASK != expected_mode
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: i128,
    inode: i128,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: i128::from(metadata.dev()),
            inode: i128::from(metadata.ino()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TargetMetadata {
    identity: FileIdentity,
    is_socket: bool,
    is_regular: bool,
    uid: u64,
    gid: u64,
    mode: u64,
    length: u64,
    link_count: u64,
}

struct EndpointDirectory {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    expected_uid: u32,
    expected_gid: u32,
}

impl EndpointDirectory {
    fn try_open(
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, DeveloperLocalInspectionErrorV1> {
        let before = fs::symlink_metadata(path)
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        validate_private_parent_metadata(&before, expected_uid, expected_gid)?;
        let identity = FileIdentity::from_metadata(&before);
        let file =
            File::open(path).map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        let opened = file
            .metadata()
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        let after = fs::symlink_metadata(path)
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        validate_private_parent_metadata(&opened, expected_uid, expected_gid)?;
        validate_private_parent_metadata(&after, expected_uid, expected_gid)?;
        if FileIdentity::from_metadata(&opened) != identity
            || FileIdentity::from_metadata(&after) != identity
        {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
            expected_uid,
            expected_gid,
        })
    }

    fn validate_named_identity(&self) -> Result<(), DeveloperLocalInspectionErrorV1> {
        let opened = self
            .file
            .metadata()
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        let named = fs::symlink_metadata(&self.path)
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
        validate_private_parent_metadata(&opened, self.expected_uid, self.expected_gid)?;
        validate_private_parent_metadata(&named, self.expected_uid, self.expected_gid)?;
        if FileIdentity::from_metadata(&opened) != self.identity
            || FileIdentity::from_metadata(&named) != self.identity
        {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), DeveloperLocalInspectionErrorV1> {
        self.file
            .sync_all()
            .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))
    }
}

struct EndpointTarget {
    name: OsString,
    quarantine_name: OsString,
    path_identity_pin_name: Option<OsString>,
    path_identity_pin_linked: bool,
    path_identity_pin_identity: Option<FileIdentity>,
    identity: Option<FileIdentity>,
    file_identity_pin: Option<File>,
    kind: TargetKind,
}

impl EndpointTarget {
    fn try_new(
        path: &Path,
        quarantine_name: OsString,
        path_identity_pin_name: Option<OsString>,
        kind: TargetKind,
    ) -> Result<Self, DeveloperLocalInspectionErrorV1> {
        let name = path
            .file_name()
            .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?
            .to_owned();
        if name == quarantine_name
            || path_identity_pin_name
                .as_ref()
                .is_some_and(|pin_name| pin_name == &name || pin_name == &quarantine_name)
        {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            name,
            quarantine_name,
            path_identity_pin_name,
            path_identity_pin_linked: false,
            path_identity_pin_identity: None,
            identity: None,
            file_identity_pin: None,
            kind,
        })
    }
}

struct EndpointFilesGuard {
    directory: EndpointDirectory,
    socket: EndpointTarget,
    bootstrap: EndpointTarget,
}

impl EndpointFilesGuard {
    fn try_new(
        socket_path: &Path,
        bootstrap_path: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, DeveloperLocalInspectionErrorV1> {
        let parent = socket_path
            .parent()
            .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
        if bootstrap_path.parent() != Some(parent) {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        let directory = EndpointDirectory::try_open(parent, expected_uid, expected_gid)?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| DeveloperLocalInspectionErrorV1::EntropyUnavailable)?;
        let suffix = cleanup_suffix(nonce);
        let socket = EndpointTarget::try_new(
            socket_path,
            OsString::from(format!(".pxi-{suffix}-socket.cleanup")),
            Some(OsString::from(format!(".pxi-{suffix}-socket.pin"))),
            TargetKind::Socket,
        )?;
        let bootstrap = EndpointTarget::try_new(
            bootstrap_path,
            OsString::from(format!(".pxi-{suffix}-bootstrap.cleanup")),
            None,
            TargetKind::Regular,
        )?;
        ensure_target_missing(&directory, &socket.quarantine_name)?;
        if let Some(pin_name) = socket.path_identity_pin_name.as_ref() {
            ensure_target_missing(&directory, pin_name)?;
        }
        ensure_target_missing(&directory, &bootstrap.quarantine_name)?;
        Ok(Self {
            directory,
            socket,
            bootstrap,
        })
    }

    fn cleanup(&mut self) -> Result<(), DeveloperLocalInspectionErrorV1> {
        // Attempt both removals even when the first one fails. A normal joined
        // shutdown reports either failure; Drop remains only the panic/startup
        // fallback and may retry an entry whose identity is still armed.
        let bootstrap_result = cleanup_tracked_target(&self.directory, &mut self.bootstrap);
        let socket_result = cleanup_tracked_target(&self.directory, &mut self.socket);
        bootstrap_result.and(socket_result)
    }
}

impl Drop for EndpointFilesGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn cleanup_tracked_target(
    directory: &EndpointDirectory,
    target: &mut EndpointTarget,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let identity = match target.identity {
        Some(identity) => identity,
        None => {
            if let Some(pin) = target.file_identity_pin.as_ref() {
                let metadata = pin
                    .metadata()
                    .map_err(|error| DeveloperLocalInspectionErrorV1::Io(error.kind()))?;
                let identity = FileIdentity::from_metadata(&metadata);
                target.identity = Some(identity);
                identity
            } else if let Some(identity) = target.path_identity_pin_identity {
                let result = cleanup_path_identity_pin(directory, target, identity);
                if result.is_ok() {
                    target.path_identity_pin_identity = None;
                }
                return result;
            } else {
                return Ok(());
            }
        }
    };
    remove_target_if_same_with(directory, target, identity, || {})?;
    let pin_result = cleanup_path_identity_pin(directory, target, identity);
    if pin_result.is_ok() {
        target.identity = None;
        target.path_identity_pin_identity = None;
        target.file_identity_pin = None;
    }
    pin_result
}

fn cleanup_path_identity_pin(
    directory: &EndpointDirectory,
    target: &mut EndpointTarget,
    expected: FileIdentity,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    if !target.path_identity_pin_linked {
        return Ok(());
    }
    let name = target
        .path_identity_pin_name
        .as_ref()
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    let Some(metadata) = read_target_metadata(directory, name)? else {
        target.path_identity_pin_linked = false;
        return Ok(());
    };
    if metadata.identity != expected {
        target.path_identity_pin_linked = false;
        return Ok(());
    }
    unlinkat(
        &directory.file,
        name.as_os_str(),
        UnlinkatFlags::NoRemoveDir,
    )
    .map_err(nix_io)?;
    directory.sync()?;
    target.path_identity_pin_linked = false;
    Ok(())
}

fn remove_target_if_same_with(
    directory: &EndpointDirectory,
    target: &EndpointTarget,
    expected: FileIdentity,
    before_quarantine: impl FnOnce(),
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let Some(current) = read_target_metadata(directory, &target.name)? else {
        return Ok(());
    };
    if current.identity != expected {
        return Ok(());
    }
    quarantine_and_remove_named_target(
        directory,
        &target.name,
        &target.quarantine_name,
        |captured| captured.identity == expected,
        before_quarantine,
    )
}

fn remove_named_target_exact(
    directory: &EndpointDirectory,
    name: &OsStr,
    quarantine_name: &OsStr,
    expected: TargetMetadata,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let current = read_target_metadata(directory, name)?
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    if current != expected {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    quarantine_and_remove_named_target(
        directory,
        name,
        quarantine_name,
        |captured| *captured == expected,
        || {},
    )
}

fn quarantine_and_remove_named_target(
    directory: &EndpointDirectory,
    name: &OsStr,
    quarantine_name: &OsStr,
    captured_is_owned: impl FnOnce(&TargetMetadata) -> bool,
    before_quarantine: impl FnOnce(),
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    ensure_target_missing(directory, quarantine_name)?;
    before_quarantine();
    // Atomically capture the public name without ever replacing a quarantine
    // entry. A replacement racing the initial identity read is moved aside
    // rather than unlinked. The generation-private quarantine name then gives
    // this lifecycle exclusive coordination of the captured entry.
    rustix::fs::renameat_with(
        &directory.file,
        name,
        &directory.file,
        quarantine_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(rustix_io)?;
    let captured = read_target_metadata(directory, quarantine_name)?
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidConfiguration)?;
    if captured_is_owned(&captured) {
        unlinkat(&directory.file, quarantine_name, UnlinkatFlags::NoRemoveDir).map_err(nix_io)?;
        return directory.sync();
    }

    // The public name changed after validation. Restore the captured entry
    // atomically without overwriting anything that appeared meanwhile. If
    // restoration is impossible, leave the replacement under quarantine
    // instead of deleting data that this lifecycle does not own.
    match rustix::fs::renameat_with(
        &directory.file,
        quarantine_name,
        &directory.file,
        name,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => directory.sync()?,
        Err(rustix::io::Errno::EXIST) => {
            return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
        }
        Err(error) => return Err(rustix_io(error)),
    }
    Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
}

fn ensure_target_missing(
    directory: &EndpointDirectory,
    name: &OsStr,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    if read_target_metadata(directory, name)?.is_some() {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn read_target_metadata(
    directory: &EndpointDirectory,
    name: &OsStr,
) -> Result<Option<TargetMetadata>, DeveloperLocalInspectionErrorV1> {
    fn unsigned_metadata_value_to_u64<T: Into<u64>>(value: T) -> u64 {
        value.into()
    }

    let metadata = match fstatat(&directory.file, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(nix_io(error)),
    };
    let flags = SFlag::from_bits_truncate(metadata.st_mode);
    Ok(Some(TargetMetadata {
        identity: FileIdentity {
            device: i128::from(metadata.st_dev),
            inode: i128::from(metadata.st_ino),
        },
        is_socket: flags.contains(SFlag::S_IFSOCK),
        is_regular: flags.contains(SFlag::S_IFREG),
        uid: u64::from(metadata.st_uid),
        gid: u64::from(metadata.st_gid),
        mode: u64::from(metadata.st_mode) & u64::from(MODE_MASK),
        length: u64::try_from(metadata.st_size)
            .map_err(|_| DeveloperLocalInspectionErrorV1::InvalidConfiguration)?,
        link_count: unsigned_metadata_value_to_u64(metadata.st_nlink),
    }))
}

fn validate_target_metadata(
    metadata: &TargetMetadata,
    expected_uid: u32,
    expected_gid: u32,
    kind: TargetKind,
) -> Result<(), DeveloperLocalInspectionErrorV1> {
    let (type_matches, expected_mode) = match kind {
        TargetKind::Socket => (metadata.is_socket, SOCKET_MODE),
        TargetKind::Regular => (metadata.is_regular, BOOTSTRAP_MODE),
    };
    if !type_matches
        || metadata.uid != u64::from(expected_uid)
        || metadata.gid != u64::from(expected_gid)
        || metadata.mode != u64::from(expected_mode)
    {
        return Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn cleanup_suffix(nonce: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut suffix = String::with_capacity(32);
    for byte in nonce {
        suffix.push(char::from(HEX[usize::from(byte >> 4)]));
        suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    suffix
}

fn nix_io(error: nix::errno::Errno) -> DeveloperLocalInspectionErrorV1 {
    DeveloperLocalInspectionErrorV1::Io(io::Error::from_raw_os_error(error as i32).kind())
}

fn rustix_io(error: rustix::io::Errno) -> DeveloperLocalInspectionErrorV1 {
    DeveloperLocalInspectionErrorV1::Io(io::Error::from_raw_os_error(error.raw_os_error()).kind())
}

fn monotonic_nanos(started: Instant) -> Result<u64, DeveloperLocalInspectionErrorV1> {
    u64::try_from(started.elapsed().as_nanos())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(DeveloperLocalInspectionErrorV1::InvalidProjection)
}

fn copy_array<const BYTES: usize>(bytes: &[u8], offset: usize) -> [u8; BYTES] {
    let mut value = [0_u8; BYTES];
    value.copy_from_slice(&bytes[offset..offset + BYTES]);
    value
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeveloperLocalInspectionErrorV1 {
    InvalidConfiguration,
    EntropyUnavailable,
    InvalidOwnerFacts,
    InvalidProjection,
    InvalidRequest,
    IoTimedOut,
    Io(io::ErrorKind),
    ThreadStartFailed,
    ThreadPanicked,
    EndpointFailed,
    ShutdownAlreadyRequested,
}

impl fmt::Display for DeveloperLocalInspectionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "DeveloperLocal Inspection configuration is invalid",
            Self::EntropyUnavailable => "DeveloperLocal Inspection entropy is unavailable",
            Self::InvalidOwnerFacts => "DeveloperLocal Inspection owner facts were rejected",
            Self::InvalidProjection => "DeveloperLocal Inspection projection failed",
            Self::InvalidRequest => "DeveloperLocal Inspection request was rejected",
            Self::IoTimedOut => "DeveloperLocal Inspection I/O timed out",
            Self::Io(_) => "DeveloperLocal Inspection I/O failed",
            Self::ThreadStartFailed => "DeveloperLocal Inspection thread failed to start",
            Self::ThreadPanicked => "DeveloperLocal Inspection thread panicked",
            Self::EndpointFailed => "DeveloperLocal Inspection endpoint failed",
            Self::ShutdownAlreadyRequested => {
                "DeveloperLocal Inspection shutdown was already requested"
            }
        })
    }
}

impl std::error::Error for DeveloperLocalInspectionErrorV1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "paraegox-inspection-cleanup-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated Inspection cleanup test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("set Inspection cleanup test directory mode");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("paraegox-inspection-cleanup-")
            }) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn test_socket_pin_name(fill: char) -> OsString {
        assert!(fill.is_ascii_digit() || ('a'..='f').contains(&fill));
        OsString::from(format!(
            ".pxi-{}-socket.pin",
            fill.to_string().repeat(SOCKET_PIN_NONCE_HEX_BYTES)
        ))
    }

    fn distinct_test_socket_pin_name(target: &EndpointTarget) -> OsString {
        let first = test_socket_pin_name('0');
        if target.path_identity_pin_name.as_deref() == Some(first.as_os_str()) {
            test_socket_pin_name('1')
        } else {
            first
        }
    }

    fn create_socket_generation(socket_path: &Path, pin_path: &Path) -> StdUnixListener {
        let listener = StdUnixListener::bind(socket_path)
            .expect("bind simulated crashed Inspection socket generation");
        fs::set_permissions(socket_path, fs::Permissions::from_mode(SOCKET_MODE))
            .expect("set simulated crashed Inspection socket mode");
        fs::hard_link(socket_path, pin_path)
            .expect("pin simulated crashed Inspection socket generation");
        listener
    }

    #[test]
    fn crashed_socket_public_and_pin_pair_is_recovered_before_rebind() {
        let root = TestDirectory::new();
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let socket_path = root.path().join("i.sock");
        let bootstrap_path = root.path().join("i.pxib");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build crashed-pair Inspection test runtime");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct replacement Inspection endpoint files");
        let stale_pin_name = distinct_test_socket_pin_name(&files.socket);
        let stale_pin_path = root.path().join(&stale_pin_name);
        let stale_listener = create_socket_generation(&socket_path, &stale_pin_path);
        fs::write(root.path().join("operator-note.txt"), b"preserve")
            .expect("write unrelated private-directory entry");
        drop(stale_listener);

        let listener = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        )
        .expect("recover crashed pair and bind replacement Inspection socket");
        assert!(!stale_pin_path.exists());
        assert!(socket_path.exists());
        assert_eq!(
            fs::read(root.path().join("operator-note.txt"))
                .expect("read preserved unrelated private-directory entry"),
            b"preserve"
        );

        drop(listener);
        files
            .cleanup()
            .expect("clean replacement Inspection socket");
        assert!(!socket_path.exists());
        assert!(!root.path().join(&files.socket.quarantine_name).exists());
    }

    #[test]
    fn crashed_socket_orphan_pin_is_recovered_before_rebind() {
        let root = TestDirectory::new();
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let socket_path = root.path().join("i.sock");
        let bootstrap_path = root.path().join("i.pxib");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build orphan-pin Inspection test runtime");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct orphan-pin replacement endpoint files");
        let stale_pin_name = distinct_test_socket_pin_name(&files.socket);
        let stale_pin_path = root.path().join(&stale_pin_name);
        let stale_listener = create_socket_generation(&socket_path, &stale_pin_path);
        fs::remove_file(&socket_path).expect("simulate prior cleanup of public socket name");
        drop(stale_listener);

        let listener = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        )
        .expect("recover orphan generation pin and bind replacement Inspection socket");
        assert!(!stale_pin_path.exists());
        assert!(socket_path.exists());

        drop(listener);
        files
            .cleanup()
            .expect("clean replacement Inspection socket");
        assert!(!socket_path.exists());
    }

    #[test]
    fn socket_generation_recovery_preserves_an_active_owner() {
        let root = TestDirectory::new();
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let socket_path = root.path().join("i.sock");
        let bootstrap_path = root.path().join("i.pxib");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build active-owner Inspection test runtime");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct competing Inspection endpoint files");
        let pin_name = distinct_test_socket_pin_name(&files.socket);
        let pin_path = root.path().join(&pin_name);
        let active_listener = create_socket_generation(&socket_path, &pin_path);

        let result = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        );
        assert!(matches!(
            result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        ));
        assert!(socket_path.exists());
        assert!(pin_path.exists());
        drop(active_listener);
    }

    #[test]
    fn socket_generation_recovery_rejects_identity_drift_and_extra_hardlinks() {
        let drift_root = TestDirectory::new();
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let socket_path = drift_root.path().join("i.sock");
        let bootstrap_path = drift_root.path().join("i.pxib");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build ambiguous-generation Inspection test runtime");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct identity-drift Inspection endpoint files");
        let pin_name = distinct_test_socket_pin_name(&files.socket);
        let pin_path = drift_root.path().join(&pin_name);
        let public_listener =
            StdUnixListener::bind(&socket_path).expect("bind public identity-drift socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(SOCKET_MODE))
            .expect("set public identity-drift socket mode");
        fs::hard_link(&socket_path, drift_root.path().join("public-shadow"))
            .expect("give public identity-drift socket the expected link count");
        let other_path = drift_root.path().join("other.sock");
        let other_listener = create_socket_generation(&other_path, &pin_path);
        drop((public_listener, other_listener));

        let drift_result = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        );
        assert!(matches!(
            drift_result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        ));
        assert!(socket_path.exists());
        assert!(pin_path.exists());

        let links_root = TestDirectory::new();
        let socket_path = links_root.path().join("i.sock");
        let bootstrap_path = links_root.path().join("i.pxib");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct extra-hardlink Inspection endpoint files");
        let pin_name = distinct_test_socket_pin_name(&files.socket);
        let pin_path = links_root.path().join(&pin_name);
        let listener = create_socket_generation(&socket_path, &pin_path);
        let extra_path = links_root.path().join("operator-link");
        fs::hard_link(&socket_path, &extra_path).expect("add unexpected socket hardlink");
        drop(listener);

        let links_result = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        );
        assert!(matches!(
            links_result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        ));
        assert!(socket_path.exists());
        assert!(pin_path.exists());
        assert!(extra_path.exists());
    }

    #[test]
    fn socket_generation_recovery_rejects_reserved_malformed_symlink_and_multiple_pins() {
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build reserved-name Inspection test runtime");

        let malformed_root = TestDirectory::new();
        let socket_path = malformed_root.path().join("i.sock");
        let bootstrap_path = malformed_root.path().join("i.pxib");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct malformed-name Inspection endpoint files");
        let unrelated_path = malformed_root.path().join("operator-note.txt");
        let malformed_path = malformed_root.path().join(".pxi-not-canonical");
        fs::write(&unrelated_path, b"preserve").expect("write unrelated entry");
        fs::write(&malformed_path, b"reserved").expect("write malformed reserved entry");
        let malformed_result = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        );
        assert!(matches!(
            malformed_result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        ));
        assert_eq!(
            fs::read(&unrelated_path).expect("read unrelated entry"),
            b"preserve"
        );
        assert_eq!(
            fs::read(&malformed_path).expect("read malformed entry"),
            b"reserved"
        );

        let symlink_root = TestDirectory::new();
        let socket_path = symlink_root.path().join("i.sock");
        let bootstrap_path = symlink_root.path().join("i.pxib");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct symlink-pin Inspection endpoint files");
        let pin_name = distinct_test_socket_pin_name(&files.socket);
        let pin_path = symlink_root.path().join(&pin_name);
        let target_path = symlink_root.path().join("operator-note.txt");
        fs::write(&target_path, b"preserve").expect("write symlink target");
        std::os::unix::fs::symlink(&target_path, &pin_path).expect("create canonical-name symlink");
        let symlink_result = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        );
        assert!(matches!(
            symlink_result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        ));
        assert!(fs::symlink_metadata(&pin_path).is_ok());
        assert_eq!(
            fs::read(&target_path).expect("read preserved symlink target"),
            b"preserve"
        );

        let multiple_root = TestDirectory::new();
        let socket_path = multiple_root.path().join("i.sock");
        let bootstrap_path = multiple_root.path().join("i.pxib");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct multiple-pin Inspection endpoint files");
        let first_name = distinct_test_socket_pin_name(&files.socket);
        let second_name = if first_name == test_socket_pin_name('1') {
            test_socket_pin_name('2')
        } else {
            test_socket_pin_name('1')
        };
        let first_path = multiple_root.path().join(&first_name);
        let second_path = multiple_root.path().join(&second_name);
        let listener = create_socket_generation(&socket_path, &first_path);
        fs::hard_link(&socket_path, &second_path).expect("add second canonical generation pin");
        drop(listener);
        let multiple_result = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        );
        assert!(matches!(
            multiple_result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        ));
        assert!(socket_path.exists());
        assert!(first_path.exists());
        assert!(second_path.exists());
    }

    #[test]
    fn cleanup_quarantine_preserves_replacements_racing_identity_check() {
        let root = TestDirectory::new();
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let directory = EndpointDirectory::try_open(root.path(), uid, gid)
            .expect("open pinned Inspection cleanup directory");

        let bootstrap_path = root.path().join("i.pxib");
        fs::write(&bootstrap_path, b"owned-bootstrap")
            .expect("write original Inspection bootstrap");
        fs::set_permissions(&bootstrap_path, fs::Permissions::from_mode(BOOTSTRAP_MODE))
            .expect("set original Inspection bootstrap mode");
        let bootstrap_identity = FileIdentity::from_metadata(
            &fs::symlink_metadata(&bootstrap_path).expect("inspect original Inspection bootstrap"),
        );
        // Keep the unlinked inode alive so Linux cannot immediately recycle
        // its number for the replacement and make this race test ambiguous.
        let _bootstrap_identity_pin =
            File::open(&bootstrap_path).expect("pin original Inspection bootstrap inode");
        let bootstrap_target = EndpointTarget::try_new(
            &bootstrap_path,
            OsString::from(".bootstrap-race.cleanup"),
            None,
            TargetKind::Regular,
        )
        .expect("construct Inspection bootstrap cleanup target");
        let bootstrap_result =
            remove_target_if_same_with(&directory, &bootstrap_target, bootstrap_identity, || {
                fs::remove_file(&bootstrap_path).expect("replace original Inspection bootstrap");
                fs::write(&bootstrap_path, b"replacement-bootstrap")
                    .expect("write replacement Inspection bootstrap");
                fs::set_permissions(&bootstrap_path, fs::Permissions::from_mode(BOOTSTRAP_MODE))
                    .expect("set replacement Inspection bootstrap mode");
            });
        assert_eq!(
            bootstrap_result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        );
        assert_eq!(
            fs::read(&bootstrap_path).expect("read preserved replacement bootstrap"),
            b"replacement-bootstrap"
        );
        assert!(!root.path().join(".bootstrap-race.cleanup").exists());

        let collision_path = root.path().join("collision.pxib");
        fs::write(&collision_path, b"owned-collision-bootstrap")
            .expect("write collision Inspection bootstrap");
        fs::set_permissions(&collision_path, fs::Permissions::from_mode(BOOTSTRAP_MODE))
            .expect("set collision Inspection bootstrap mode");
        let collision_identity = FileIdentity::from_metadata(
            &fs::symlink_metadata(&collision_path).expect("inspect collision Inspection bootstrap"),
        );
        let collision_target = EndpointTarget::try_new(
            &collision_path,
            OsString::from(".quarantine-collision.cleanup"),
            None,
            TargetKind::Regular,
        )
        .expect("construct Inspection quarantine collision target");
        let quarantine_collision_path = root.path().join(".quarantine-collision.cleanup");
        let collision_result =
            remove_target_if_same_with(&directory, &collision_target, collision_identity, || {
                fs::write(&quarantine_collision_path, b"foreign-quarantine")
                    .expect("race a foreign quarantine entry");
            });
        assert_eq!(
            collision_result,
            Err(DeveloperLocalInspectionErrorV1::Io(
                io::ErrorKind::AlreadyExists
            ))
        );
        assert_eq!(
            fs::read(&collision_path).expect("read preserved collision bootstrap"),
            b"owned-collision-bootstrap"
        );
        assert_eq!(
            fs::read(&quarantine_collision_path).expect("read preserved foreign quarantine entry"),
            b"foreign-quarantine"
        );
        fs::remove_file(&collision_path).expect("remove test-owned collision bootstrap");
        fs::remove_file(&quarantine_collision_path)
            .expect("remove test-owned foreign quarantine entry");

        let socket_path = root.path().join("i.sock");
        let original_listener =
            StdUnixListener::bind(&socket_path).expect("bind original Inspection socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(SOCKET_MODE))
            .expect("set original Inspection socket mode");
        let socket_identity = FileIdentity::from_metadata(
            &fs::symlink_metadata(&socket_path).expect("inspect original Inspection socket"),
        );
        let socket_target = EndpointTarget::try_new(
            &socket_path,
            OsString::from(".socket-race.cleanup"),
            None,
            TargetKind::Socket,
        )
        .expect("construct Inspection socket cleanup target");
        let mut replacement_listener = None;
        let socket_result =
            remove_target_if_same_with(&directory, &socket_target, socket_identity, || {
                fs::remove_file(&socket_path).expect("replace original Inspection socket");
                let listener = StdUnixListener::bind(&socket_path)
                    .expect("bind replacement Inspection socket");
                fs::set_permissions(&socket_path, fs::Permissions::from_mode(SOCKET_MODE))
                    .expect("set replacement Inspection socket mode");
                replacement_listener = Some(listener);
            });
        assert_eq!(
            socket_result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        );
        assert_ne!(
            FileIdentity::from_metadata(
                &fs::symlink_metadata(&socket_path)
                    .expect("inspect preserved replacement Inspection socket")
            ),
            socket_identity
        );
        let client = std::os::unix::net::UnixStream::connect(&socket_path)
            .expect("connect to preserved replacement Inspection socket");
        let (accepted, _) = replacement_listener
            .as_ref()
            .expect("replacement Inspection listener exists")
            .accept()
            .expect("replacement Inspection listener accepts");
        drop((accepted, client, original_listener));
        assert!(!root.path().join(".socket-race.cleanup").exists());
    }

    #[test]
    fn tracked_cleanup_never_clobbers_quarantine_and_reports_the_failure() {
        let root = TestDirectory::new();
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let socket_path = root.path().join("i.sock");
        let bootstrap_path = root.path().join("i.pxib");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tracked Inspection test runtime");
        let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
            .expect("construct tracked Inspection endpoint files");
        let listener = bind_listener(
            &runtime,
            &socket_path,
            &files.directory,
            &mut files.socket,
            uid,
            gid,
        )
        .expect("bind tracked Inspection socket");
        create_bootstrap_file(
            &files.directory,
            &mut files.bootstrap,
            b"tracked-bootstrap",
            uid,
            gid,
        )
        .expect("create tracked Inspection bootstrap");
        let socket_pin_path = root.path().join(
            files
                .socket
                .path_identity_pin_name
                .as_ref()
                .expect("tracked Inspection socket has an inode pin"),
        );
        assert!(socket_pin_path.exists());

        let quarantine_path = root.path().join(&files.bootstrap.quarantine_name);
        fs::write(&quarantine_path, b"foreign-quarantine")
            .expect("create deterministic foreign quarantine entry");
        let cleanup_result = files.cleanup();
        assert_eq!(
            cleanup_result,
            Err(DeveloperLocalInspectionErrorV1::InvalidConfiguration)
        );
        assert_eq!(
            fs::read(&quarantine_path).expect("read preserved foreign quarantine entry"),
            b"foreign-quarantine"
        );
        assert_eq!(
            fs::read(&bootstrap_path).expect("read still-tracked Inspection bootstrap"),
            b"tracked-bootstrap"
        );
        assert!(!socket_path.exists());
        assert!(!socket_pin_path.exists());

        fs::remove_file(&quarantine_path).expect("remove test-owned quarantine entry");
        files
            .cleanup()
            .expect("retry tracked Inspection cleanup after collision removal");
        assert!(!bootstrap_path.exists());
        drop(listener);
    }

    #[test]
    fn partially_created_endpoint_entries_are_tracked_and_removed() {
        let root = TestDirectory::new();
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let socket_path = root.path().join("partial.sock");
        let bootstrap_path = root.path().join("partial.pxib");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build partial Inspection test runtime");

        let mut replacement_listener = None;
        let mut replacement_identity = None;
        let (replacement_result, replacement_pin_path) = {
            let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
                .expect("construct replacement-race Inspection endpoint files");
            let pin_path = root.path().join(
                files
                    .socket
                    .path_identity_pin_name
                    .as_ref()
                    .expect("replacement-race Inspection socket has an inode pin"),
            );
            let result = bind_listener_with_hooks(BindListenerWithHooksInput {
                runtime: &runtime,
                path: &socket_path,
                directory: &files.directory,
                target: &mut files.socket,
                expected_uid: uid,
                expected_gid: gid,
                proof_timeout: Duration::from_millis(100),
                post_raw_bind: || {
                    fs::remove_file(&socket_path).expect("replace raw-bound Inspection socket");
                    let listener = StdUnixListener::bind(&socket_path)
                        .expect("bind replacement before Inspection identity capture");
                    fs::set_permissions(&socket_path, fs::Permissions::from_mode(SOCKET_MODE))
                        .expect("set replacement Inspection socket mode");
                    replacement_identity = Some(FileIdentity::from_metadata(
                        &fs::symlink_metadata(&socket_path)
                            .expect("inspect replacement Inspection socket"),
                    ));
                    replacement_listener = Some(listener);
                },
                post_bind: || Ok(()),
            });
            (result, pin_path)
        };
        assert!(matches!(
            replacement_result,
            Err(DeveloperLocalInspectionErrorV1::IoTimedOut)
        ));
        assert_eq!(
            FileIdentity::from_metadata(
                &fs::symlink_metadata(&socket_path)
                    .expect("inspect preserved pre-capture replacement")
            ),
            replacement_identity.expect("replacement identity was recorded")
        );
        assert!(!replacement_pin_path.exists());
        drop(replacement_listener.take());
        fs::remove_file(&socket_path).expect("remove pre-capture replacement socket");

        let (bind_result, socket_pin_path) = {
            let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
                .expect("construct partial-bind Inspection endpoint files");
            let pin_path = root.path().join(
                files
                    .socket
                    .path_identity_pin_name
                    .as_ref()
                    .expect("partial-bind Inspection socket has an inode pin"),
            );
            let result = bind_listener_with_post_bind(
                &runtime,
                &socket_path,
                &files.directory,
                &mut files.socket,
                uid,
                gid,
                || Err(DeveloperLocalInspectionErrorV1::EndpointFailed),
            );
            (result, pin_path)
        };
        assert!(matches!(
            bind_result,
            Err(DeveloperLocalInspectionErrorV1::EndpointFailed)
        ));
        assert!(!socket_path.exists());
        assert!(!socket_pin_path.exists());

        let write_result = {
            let mut files = EndpointFilesGuard::try_new(&socket_path, &bootstrap_path, uid, gid)
                .expect("construct partial-write Inspection endpoint files");
            create_bootstrap_file_with_post_write(
                &files.directory,
                &mut files.bootstrap,
                b"partial-bootstrap",
                uid,
                gid,
                || Err(DeveloperLocalInspectionErrorV1::EndpointFailed),
            )
        };
        assert_eq!(
            write_result,
            Err(DeveloperLocalInspectionErrorV1::EndpointFailed)
        );
        assert!(!bootstrap_path.exists());
    }
}
