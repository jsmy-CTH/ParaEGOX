//! Exact one-shot process facade for the reference DeploymentController vertical.
//!
//! The facade deliberately exposes no daemon loop, retry policy, reset path, or
//! caller-constructed Planner candidate. `initialize-reference-v1` consumes the
//! exact installer manifest once; normal Controller operations subsequently use
//! only the immutable manifest pin recovered from the Controller journal.

use core::fmt;

/// Opaque, non-sensitive failure returned by `paraegox-deploymentd`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeploymentdProcessError {
    kind: ProcessErrorKind,
}

impl DeploymentdProcessError {
    const fn new(kind: ProcessErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Debug for DeploymentdProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentdProcessError")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for DeploymentdProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (code, stage) = match self.kind {
            #[cfg(not(unix))]
            ProcessErrorKind::UnsupportedPlatform => ("PXDC-PLATFORM-UNSUPPORTED", "start_process"),
            ProcessErrorKind::Arguments => ("PXDC-ARGUMENTS-INVALID", "parse_arguments"),
            ProcessErrorKind::ServiceIdentity => {
                ("PXDC-SERVICE-IDENTITY-REJECTED", "validate_identity")
            }
            ProcessErrorKind::Path => ("PXDC-PATH-REJECTED", "validate_path"),
            ProcessErrorKind::Manifest => ("PXDC-MANIFEST-REJECTED", "load_manifest"),
            ProcessErrorKind::Key => ("PXDC-KEY-REJECTED", "load_request_auth_key"),
            ProcessErrorKind::Provisioning => {
                ("PXDC-PROVISIONING-REJECTED", "build_controller_identity")
            }
            ProcessErrorKind::Initialization => {
                ("PXDC-INITIALIZATION-FAILED", "initialize_controller")
            }
            ProcessErrorKind::Store => ("PXDC-STORE-FAILED-CLOSED", "operate_controller_store"),
            ProcessErrorKind::Migration => {
                ("PXDC-MIGRATION-FAILED-CLOSED", "migrate_controller_store")
            }
            ProcessErrorKind::Planning => ("PXDC-PLANNING-REJECTED", "compile_reference_plan"),
            ProcessErrorKind::Commit => ("PXDC-COMMIT-FAILED-CLOSED", "commit_reference_plan"),
            ProcessErrorKind::Tenure => ("PXDC-TENURE-FAILED-CLOSED", "acquire_tenure"),
            ProcessErrorKind::Bootstrap => ("PXDC-BOOTSTRAP-FAILED-CLOSED", "bootstrap_runtime"),
            ProcessErrorKind::Apply => ("PXDC-APPLY-FAILED-CLOSED", "apply_reference"),
            ProcessErrorKind::Output => ("PXDC-OUTPUT-FAILED", "write_receipt"),
        };
        write!(
            formatter,
            "paraegox-deploymentd failed closed; code={code} stage={stage}"
        )
    }
}

impl std::error::Error for DeploymentdProcessError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessErrorKind {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    Arguments,
    ServiceIdentity,
    Path,
    Manifest,
    Key,
    Provisioning,
    Initialization,
    Store,
    Migration,
    Planning,
    Commit,
    Tenure,
    Bootstrap,
    Apply,
    Output,
}

/// Parses and executes exactly one versioned DeploymentController operation.
pub fn run_deploymentd_process() -> Result<(), DeploymentdProcessError> {
    platform::run()
}

#[cfg(not(unix))]
mod platform {
    use super::{DeploymentdProcessError, ProcessErrorKind};

    pub(super) fn run() -> Result<(), DeploymentdProcessError> {
        Err(DeploymentdProcessError::new(
            ProcessErrorKind::UnsupportedPlatform,
        ))
    }
}

#[cfg(unix)]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, Metadata};
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};
    use std::time::Duration;

    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    use nix::unistd::{getegid, geteuid};
    use paraegox_kernel::digest::{Digest32, Digest32Builder};
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::apply::{
        PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
    };
    use paraegox_runtime_contracts::installation::MAX_INSTALLED_RUNTIME_MANIFEST_BYTES;
    use paraegox_runtime_contracts::reference_control::{
        ReferenceAdmissionPolicyInputV1, ReferenceApplyTerminalHeadV1,
        ReferenceApplyTerminalLifecycleEffectV1, ReferenceApplyTerminalOutcomeV1,
        ReferenceBootstrapChannelPolicyInputV1, ReferenceBootstrapResponseV1,
        ValidatedReferenceLifecycleBudgetsV1, ed25519_control_key_fingerprint,
        reference_admission_policy_fingerprint_v1,
        reference_bootstrap_channel_policy_fingerprint_v1,
    };
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
    use tokio::runtime::Builder as RuntimeBuilder;
    use zeroize::Zeroizing;

    use crate::controller_apply::{
        ControllerAppliedReferenceV1, ControllerApplyProvisioningV1, FreshControllerApplyRequestV1,
        PreparedControllerApplyAttemptV1, apply_reference_once_v1, prepare_reference_apply_v1,
        replay_prepared_reference_apply_v1,
    };
    use crate::controller_bootstrap::{
        ControllerBootstrapProvisioningV1, ControllerBootstrapReceiptV1,
        FreshControllerBootstrapRequestV1, bootstrap_runtime_v1,
    };
    use crate::controller_initializer::{
        ControllerInitializationInput, ControllerInitializationReceipt, initialize_controller_store,
    };
    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerJournalSnapshot, ControllerOperationId,
        ControllerOwnerIdentityFingerprint, ControllerRequestAuthPin,
        ControllerTenureAuthorityDomainFingerprint, ControllerTenureTransaction,
    };
    use crate::controller_store::{ControllerStore, ControllerStoreMigrationDisposition};
    use crate::controller_tenure::{ControllerAcquiredTenure, acquire_tenure_once};
    use crate::deck::{
        CardDefinitionVersionRequirement, CardUseKey, DeckCardConfig, DeckCardRole, DeckCardSpec,
        DeckCompiler, DeckExportRef, DeckKey, DeckLifetimeRequest, DeckOwnershipRequest,
        DeckResolverSnapshot, DeckSpec, ResolvedCardArtifact, ResolvedCardDefinition,
    };
    use crate::manifest_ingress::ControllerInstalledManifestPin;
    use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
    use crate::planner::{
        AllocationState, DeploymentPlanCandidate, DeploymentPlanner, PlannerDesired, PlannerInput,
        PlannerOutcome, PreviousTargetEligibility, StableAllocationSnapshot, TargetIntent,
        ValidatedReferenceLifecycleBudgets,
    };
    use crate::runtime_control_client::{
        RuntimeApplyResponseVerifier, RuntimeControlSocketAcl, RuntimeUnixCredentials,
        UnixRuntimeApplyClient, UnixRuntimeControlEndpoint,
    };
    use crate::tenure_client::{
        AcquireTenureRequestToSign, AuthorityProofVerifier, AuthoritySocketAcl,
        PreparedAcquireTenureRequest, UnixAuthorityEndpoint, UnixCredentials,
        UnixTenureAuthorityClient,
    };
    use crate::tenure_protocol::{
        ACQUIRE_TENURE_ED25519_ALGORITHM, ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{DeploymentdProcessError, ProcessErrorKind};

    const ED25519_ALGORITHM: u16 = 1;
    const ED25519_ALGORITHM_VERSION: u16 = 1;
    const INITIAL_AUTH_ROTATION_GENERATION: u64 = 1;
    const CONTROLLER_OWNER_IDENTITY_DOMAIN: &[u8] =
        b"paraegox.deployment.controller.process-owner.sha256.v1";
    const COMMIT_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
        b"paraegox.deployment.controller.commit-snapshot.sha256.v1";
    const COMMIT_RECEIPT_DIGEST_DOMAIN: &[u8] =
        b"paraegox.deployment.controller.commit-receipt.sha256.v1";
    const COMMIT_RECEIPT_MAGIC: &[u8] = b"PXDCOMMIT\0";
    const COMMIT_RECEIPT_VERSION: u16 = 1;
    const EMPTY_COMMIT_RECEIPT_DIGEST_DOMAIN: &[u8] =
        b"paraegox.deployment.controller.commit-empty-receipt.sha256.v1";
    const EMPTY_COMMIT_RECEIPT_MAGIC: &[u8] = b"PXDCEMPTY\0";
    const EMPTY_COMMIT_RECEIPT_VERSION: u16 = 1;
    const MAX_ARGUMENTS: usize = 24;
    const PUBLIC_KEY_BYTES: usize = 32;
    const BOOTSTRAP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const BOOTSTRAP_ENTROPY_BYTES: usize = 48;
    const TENURE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const TENURE_ENTROPY_BYTES: usize = 48;
    const APPLY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
    const APPLY_ENTROPY_BYTES: usize = 64;

    pub(super) fn run() -> Result<(), DeploymentdProcessError> {
        let command = parse_arguments(std::env::args_os().skip(1))?;
        execute(command)
    }

    fn execute(command: ProcessCommand) -> Result<(), DeploymentdProcessError> {
        match command {
            ProcessCommand::Initialize(arguments) => initialize(arguments),
            ProcessCommand::MigrateControllerJournal(arguments) => {
                migrate_controller_journal(arguments)
            }
            ProcessCommand::CommitReferenceLoop(arguments) => commit_reference_loop(arguments),
            ProcessCommand::CommitReferenceEmpty(arguments) => commit_reference_empty(arguments),
            ProcessCommand::AcquireTenure(arguments) => acquire_tenure(arguments),
            ProcessCommand::BootstrapRuntime(arguments) => bootstrap_runtime(arguments),
            ProcessCommand::ApplyReference(arguments) => apply_reference(arguments),
        }
    }

    fn migrate_controller_journal(
        arguments: ControllerJournalMigrationArguments,
    ) -> Result<(), DeploymentdProcessError> {
        let outcome = ControllerStore::migrate_payload_v7_offline(
            &arguments.state_directory,
            &arguments.evidence_directory,
            arguments.expected_store_id,
            ControllerOwnerIdentityFingerprint::from_stored(Digest32::from_bytes(
                arguments.expected_owner_identity,
            )),
            arguments.migration_id,
        )
        .map_err(|_| process_error(ProcessErrorKind::Migration))?;
        let disposition = match outcome.disposition {
            ControllerStoreMigrationDisposition::Migrated => b"migrated".as_slice(),
            ControllerStoreMigrationDisposition::AlreadyMigrated => b"already_migrated".as_slice(),
        };
        let receipt = outcome.receipt;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(b"controller_journal_migration_v1 disposition=")
            .and_then(|()| stdout.write_all(disposition))
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex_inline(&mut stdout, b" migration_id=", receipt.migration_id())?;
        write!(
            stdout,
            " source_payload_version={}",
            receipt.source_payload_version()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex_inline(
            &mut stdout,
            b" source_checksum=",
            receipt.source_checksum().as_bytes(),
        )?;
        write_labeled_hex_inline(
            &mut stdout,
            b" store_instance_id=",
            receipt.source_store_instance_id(),
        )?;
        write_labeled_hex_inline(
            &mut stdout,
            b" owner_identity_fingerprint=",
            receipt.source_owner_identity_fingerprint().as_bytes(),
        )?;
        write!(
            stdout,
            " source_snapshot_sequence={}",
            receipt.source_snapshot_sequence()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex_inline(&mut stdout, b" receipt=", receipt.canonical_wire())?;
        stdout
            .write_all(b"\n")
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_labeled_hex_inline(
        output: &mut impl Write,
        label: &[u8],
        bytes: &[u8],
    ) -> Result<(), DeploymentdProcessError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output
            .write_all(label)
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        let mut encoded = Vec::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            encoded.push(HEX[usize::from(byte >> 4)]);
            encoded.push(HEX[usize::from(byte & 0x0f)]);
        }
        output
            .write_all(&encoded)
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn initialize(arguments: InitializeArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_separation(&arguments.common, Some(&arguments.manifest_path))?;

        let key = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let manifest = read_pinned_file(
            &arguments.manifest_path,
            FileLengthPolicy::BoundedNonZero(MAX_INSTALLED_RUNTIME_MANIFEST_BYTES),
            FileRole::Manifest,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        if key.identity == manifest.identity {
            return Err(process_error(ProcessErrorKind::Path));
        }

        let request_auth = request_auth_pin(&arguments.common, &key.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let installed_manifest = ControllerInstalledManifestPin::try_from_persisted_manifest(
            &manifest.bytes,
            arguments.manifest_digest,
        )
        .map_err(|_| process_error(ProcessErrorKind::Manifest))?;
        let allocation =
            StableAllocationSnapshot::try_new(installed_manifest.target(), 0, 0, Vec::new())
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let input = ControllerInitializationInput::try_new(
            DeploymentScopeId::from_bytes(arguments.common.scope),
            DeploymentId::from_bytes(arguments.common.plan),
            allocation,
            installed_manifest,
            request_auth.pin,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let receipt = initialize_controller_store(&arguments.common.state_directory, input)
            .map_err(|_| process_error(ProcessErrorKind::Initialization))?;
        write_initialization_receipt(&receipt)
    }

    fn commit_reference_loop(arguments: CommitArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_separation(&arguments.common, None)?;
        let key = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &key.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;

        let scope = DeploymentScopeId::from_bytes(arguments.common.scope);
        let plan = DeploymentId::from_bytes(arguments.common.plan);
        let (candidate, operation) = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let state = snapshot.state();
            if state.scope() != scope
                || state.plan_lineage() != plan
                || state.request_auth() != request_auth.pin
                || state.current_revision() > 1
            {
                return Err(process_error(ProcessErrorKind::Provisioning));
            }
            let lifecycle = ValidatedReferenceLifecycleBudgetsV1::try_new(
                BoundedDuration::from_nanos(arguments.start_nanos),
                BoundedDuration::from_nanos(arguments.drain_nanos),
                BoundedDuration::from_nanos(arguments.cleanup_nanos),
            )
            .map_err(|_| process_error(ProcessErrorKind::Planning))?;
            let candidate = build_reference_candidate(
                state.installed_manifest(),
                arguments.deck_key,
                arguments.card_use_key,
                arguments.definition_version,
                lifecycle,
            )?;
            (
                candidate,
                ControllerOperationId::from_bytes(arguments.operation_id),
            )
        };

        // Preview both transitions before the first write. This prevents a
        // competing Prepared operation from becoming durable merely because a
        // later commit check would reject it. The same path reconstructs an
        // exact candidate after a crash at Prepared and verifies an already
        // Committed operation without asking the Planner for Loop -> Loop.
        let prepared_preview = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state()
            .prepare_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        prepared_preview
            .commit_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;

        if &prepared_preview
            != store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state()
        {
            let prepared_snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .try_successor(prepared_preview)
                .map_err(|_| process_error(ProcessErrorKind::Commit))?;
            store
                .commit(prepared_snapshot)
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
        }

        let committed_state = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state()
            .commit_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        if &committed_state
            != store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state()
        {
            let committed_snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .try_successor(committed_state)
                .map_err(|_| process_error(ProcessErrorKind::Commit))?;
            store
                .commit(committed_snapshot)
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
        }

        let committed = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?;
        if committed.state().current_revision() != 1 {
            return Err(process_error(ProcessErrorKind::Commit));
        }
        write_commit_receipt(committed, operation)
    }

    fn commit_reference_empty(
        arguments: CommitEmptyArguments,
    ) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_separation(&arguments.common, None)?;
        let key = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &key.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let operation = ControllerOperationId::from_bytes(arguments.operation_id);
        let scope = DeploymentScopeId::from_bytes(arguments.common.scope);
        let plan_lineage = DeploymentId::from_bytes(arguments.common.plan);

        let committed = commit_reference_empty_in_store(
            &mut store,
            scope,
            plan_lineage,
            request_auth.pin,
            operation,
        )?;
        write_empty_commit_receipt(&committed, operation)
    }

    fn commit_reference_empty_in_store(
        store: &mut ControllerStore,
        scope: DeploymentScopeId,
        plan_lineage: DeploymentId,
        request_auth: ControllerRequestAuthPin,
        operation: ControllerOperationId,
    ) -> Result<ControllerJournalSnapshot, DeploymentdProcessError> {
        let already_committed = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let state = snapshot.state();
            validate_empty_common_state(state, scope, plan_lineage, request_auth)?;
            state.current_revision() == 2
                && state
                    .committed_plan()
                    .is_some_and(|plan| plan.content().shape() == TargetIntent::EmptyTarget)
        };
        if already_committed {
            let committed = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            validate_committed_empty_state(committed.state(), operation)?;
            return Ok(committed.clone());
        }

        let candidate = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            build_reference_empty_candidate(snapshot.state())?
        };

        // As with the Loop commit, validate both durable transitions before
        // the first write. A competing Prepared operation therefore cannot be
        // introduced by an invocation whose eventual Empty commit must fail.
        let prepared_preview = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state()
            .prepare_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        prepared_preview
            .commit_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;

        if &prepared_preview
            != store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state()
        {
            let prepared_snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .try_successor(prepared_preview)
                .map_err(|_| process_error(ProcessErrorKind::Commit))?;
            store
                .commit(prepared_snapshot)
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
        }

        let committed_state = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?
            .state()
            .commit_plan_candidate(operation, &candidate)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        if &committed_state
            != store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state()
        {
            let committed_snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .try_successor(committed_state)
                .map_err(|_| process_error(ProcessErrorKind::Commit))?;
            store
                .commit(committed_snapshot)
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
        }

        let committed = store
            .snapshot()
            .map_err(|_| process_error(ProcessErrorKind::Store))?;
        validate_committed_empty_state(committed.state(), operation)?;
        Ok(committed.clone())
    }

    fn validate_empty_common_state(
        state: &crate::controller_journal::ControllerJournalState,
        scope: DeploymentScopeId,
        plan_lineage: DeploymentId,
        request_auth: ControllerRequestAuthPin,
    ) -> Result<(), DeploymentdProcessError> {
        if state.scope() != scope
            || state.plan_lineage() != plan_lineage
            || state.request_auth() != request_auth
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn build_reference_empty_candidate(
        state: &crate::controller_journal::ControllerJournalState,
    ) -> Result<DeploymentPlanCandidate, DeploymentdProcessError> {
        let plan = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let intent = state
            .current_signed_apply_intent()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let receipt = state
            .current_direct_terminal_receipt()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let facts = receipt.facts();
        if state.current_revision() != 1
            || plan.revision().value() != 1
            || plan.content().shape() != TargetIntent::OneSourceLoop
            || !state.current_apply_is_terminal()
            || intent.source_plan_digest() != plan.deployment_plan_digest()
            || receipt.target() != plan.target()
            || receipt.source_scope()
                != paraegox_runtime_contracts::provenance::SourceScopeRef::from_bytes(
                    *state.scope().as_bytes(),
                )
            || receipt.operation_id() != intent.apply_operation()
            || receipt.request_digest() != intent.request_digest().value()
            || facts.outcome() != ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
            || facts.lifecycle_effect() != ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted
            || facts.head() != ReferenceApplyTerminalHeadV1::CommittedIncoming
            || facts.desired_head_digest() != Some(intent.target_slice_digest())
        {
            return Err(process_error(ProcessErrorKind::Commit));
        }

        let outcome = DeploymentPlanner::plan(&PlannerInput {
            target: state.installed_manifest().target(),
            desired: PlannerDesired::EmptyTarget,
            previous: PreviousTargetEligibility::OneSourceLoopLiveReady,
            manifest: Some(state.installed_manifest().projection()),
            allocation: state.allocation(),
            service_dependencies: &[],
        })
        .map_err(|_| process_error(ProcessErrorKind::Planning))?;
        match outcome {
            PlannerOutcome::Candidate(candidate) => Ok(*candidate),
            PlannerOutcome::Omitted => Err(process_error(ProcessErrorKind::Planning)),
        }
    }

    fn validate_committed_empty_state(
        state: &crate::controller_journal::ControllerJournalState,
        operation: ControllerOperationId,
    ) -> Result<paraegox_runtime_contracts::provenance::TargetSliceDigest, DeploymentdProcessError>
    {
        let plan = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let archived = state
            .last_archived_direct_terminal_receipt()
            .map_err(|_| process_error(ProcessErrorKind::Commit))?
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let facts = archived.facts();
        let expected_active = facts
            .desired_head_digest()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        if state.current_revision() != 2
            || plan.revision().value() != 2
            || plan.content().shape() != TargetIntent::EmptyTarget
            || plan.commit_operation() != operation
            || state.allocation().generation() != 2
            || state.allocation().high_water() != 1
            || state.allocation().records().len() != 1
            || state
                .allocation()
                .records()
                .iter()
                .any(|record| record.state() == AllocationState::Active)
            || archived.target() != plan.target()
            || archived.source_scope()
                != paraegox_runtime_contracts::provenance::SourceScopeRef::from_bytes(
                    *state.scope().as_bytes(),
                )
            || facts.outcome() != ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
            || facts.lifecycle_effect() != ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted
            || facts.head() != ReferenceApplyTerminalHeadV1::CommittedIncoming
            || state
                .last_terminal_target_slice_digest()
                .map_err(|_| process_error(ProcessErrorKind::Commit))?
                != Some(expected_active)
        {
            return Err(process_error(ProcessErrorKind::Commit));
        }
        Ok(expected_active)
    }

    fn acquire_tenure(arguments: AcquireTenureArguments) -> Result<(), DeploymentdProcessError> {
        // This S7-E command is deliberately ensure-once, not a writer-turnover
        // surface. It replays only the globally current matching transaction;
        // another writer's later committed epoch fences this invocation.
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_tenure_separation(&arguments)?;

        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        // The seed remains a pinned Controller-owned provisioning fact even on
        // replay. Durable request bytes are never re-signed, however.
        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        if controller_public.identity == authority_public.identity
            || controller_public.identity == controller_seed_file.identity
            || authority_public.identity == controller_seed_file.identity
        {
            return Err(process_error(ProcessErrorKind::Path));
        }

        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == authority_public_bytes {
            return Err(process_error(ProcessErrorKind::Key));
        }
        let mut seed = Zeroizing::new([0; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        let controller_verifying_key = controller_signer.verifying_key();
        if controller_verifying_key.to_bytes() != controller_public_bytes
            || controller_verifying_key.is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let proof_authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes(arguments.tenure_authority_ref),
            TenureKeyRef::from_bytes(arguments.tenure_key_ref),
            TenureProofAlgorithm::try_new(ACQUIRE_TENURE_ED25519_ALGORITHM)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?,
            ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let endpoint = UnixAuthorityEndpoint::try_new(
            arguments.authority_socket_path.clone(),
            AuthoritySocketAcl::new(arguments.authority_uid, arguments.common.expected_gid),
            UnixCredentials::new(arguments.authority_uid, arguments.authority_gid),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let proof_verifier = AuthorityProofVerifier::try_new(
            proof_authority,
            VerifyingKey::from_bytes(&authority_public_bytes)
                .map_err(|_| process_error(ProcessErrorKind::Key))?,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let client =
            UnixTenureAuthorityClient::try_new(endpoint, proof_verifier, TENURE_EXCHANGE_TIMEOUT)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let authority_domain_fingerprint = ControllerTenureAuthorityDomainFingerprint::from_stored(
            client.authority_domain_fingerprint(),
        );

        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let profile = tenure_request_profile(
            &arguments,
            &request_auth,
            controller_public_bytes,
            store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?
                .state(),
        )?;
        let prepared = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let unresolved = snapshot
                .state()
                .current_unresolved_tenure_transaction()
                .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
            let global_latest_committed = if unresolved.is_none() {
                snapshot
                    .state()
                    .global_latest_committed_tenure_transaction()
                    .map_err(|_| process_error(ProcessErrorKind::Tenure))?
            } else {
                None
            };
            match select_durable_tenure_request(
                unresolved.map(DurableTenureRequest::from),
                global_latest_committed.map(DurableTenureRequest::from),
                profile.writer,
                authority_domain_fingerprint,
            )? {
                Some(canonical_request) => {
                    recover_tenure_request(canonical_request, &profile, &controller_verifying_key)?
                }
                None => {
                    validate_fresh_tenure_plan(&arguments, snapshot.state())?;
                    fresh_tenure_request(&profile, &controller_signer)?
                }
            }
        };
        let operation = prepared.request().operation_id();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let acquired = runtime
            .block_on(acquire_tenure_once(&mut store, &client, &prepared))
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        write_tenure_receipt(
            store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?,
            operation,
            &acquired,
        )
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TenureRequestProfile {
        scope: DeploymentScopeId,
        writer: DeploymentWriterRef,
        controller_principal: PrincipalRef,
        controller_key: ControllerAcquireKeyRef,
        controller_public_key_fingerprint: ControllerPublicKeyFingerprint,
        max_response_payload_bytes: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DurableTenureRequest<'a> {
        canonical_request: &'a [u8],
        writer: DeploymentWriterRef,
        authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
    }

    impl<'a> From<&'a ControllerTenureTransaction> for DurableTenureRequest<'a> {
        fn from(transaction: &'a ControllerTenureTransaction) -> Self {
            Self {
                canonical_request: transaction.request().canonical_bytes(),
                writer: transaction.request().writer(),
                authority_domain_fingerprint: transaction.authority_domain_fingerprint(),
            }
        }
    }

    fn select_durable_tenure_request<'a>(
        unresolved: Option<DurableTenureRequest<'a>>,
        global_latest_committed: Option<DurableTenureRequest<'a>>,
        requested_writer: DeploymentWriterRef,
        authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
    ) -> Result<Option<&'a [u8]>, DeploymentdProcessError> {
        let selected = unresolved.or(global_latest_committed);
        let Some(selected) = selected else {
            return Ok(None);
        };
        if selected.writer != requested_writer
            || selected.authority_domain_fingerprint != authority_domain_fingerprint
        {
            return Err(process_error(ProcessErrorKind::Tenure));
        }
        Ok(Some(selected.canonical_request))
    }

    fn tenure_request_profile(
        arguments: &AcquireTenureArguments,
        request_auth: &RequestAuthProvisioning,
        controller_public_key: [u8; PUBLIC_KEY_BYTES],
        state: &crate::controller_journal::ControllerJournalState,
    ) -> Result<TenureRequestProfile, DeploymentdProcessError> {
        let scope = DeploymentScopeId::from_bytes(arguments.common.scope);
        let plan = DeploymentId::from_bytes(arguments.common.plan);
        if state.scope() != scope
            || state.plan_lineage() != plan
            || state.request_auth() != request_auth.pin
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(TenureRequestProfile {
            scope,
            writer: DeploymentWriterRef::from_bytes(arguments.writer_ref),
            controller_principal: PrincipalRef::from_bytes(arguments.controller_principal),
            controller_key: ControllerAcquireKeyRef::from_bytes(*request_auth.pin.key().as_bytes()),
            controller_public_key_fingerprint: ControllerPublicKeyFingerprint::for_ed25519_key(
                &controller_public_key,
            )
            .map_err(|_| process_error(ProcessErrorKind::Key))?,
            max_response_payload_bytes: u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?,
        })
    }

    fn validate_fresh_tenure_plan(
        arguments: &AcquireTenureArguments,
        state: &crate::controller_journal::ControllerJournalState,
    ) -> Result<(), DeploymentdProcessError> {
        let scope = DeploymentScopeId::from_bytes(arguments.common.scope);
        let plan = DeploymentId::from_bytes(arguments.common.plan);
        let committed = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Provisioning))?;
        if state.current_revision() != 1
            || committed.scope() != scope
            || committed.plan() != plan
            || committed.revision().value() != state.current_revision()
            || committed.target() != state.installed_manifest().target()
            || committed.content().target() != state.installed_manifest().target()
            || committed.content().shape() != TargetIntent::OneSourceLoop
            || committed.content().manifest_digest().value()
                != state.installed_manifest().manifest_digest()
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn recover_tenure_request(
        canonical_request: &[u8],
        profile: &TenureRequestProfile,
        controller_verifying_key: &VerifyingKey,
    ) -> Result<PreparedAcquireTenureRequest, DeploymentdProcessError> {
        let prepared =
            PreparedAcquireTenureRequest::try_from_canonical_request_bytes(canonical_request)
                .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let request = prepared.request();
        if request.scope() != profile.scope
            || request.writer() != profile.writer
            || request.controller_principal() != profile.controller_principal
            || request.controller_key() != profile.controller_key
            || request.controller_public_key_fingerprint()
                != profile.controller_public_key_fingerprint
            || request.auth_algorithm() != ACQUIRE_TENURE_ED25519_ALGORITHM
            || request.auth_algorithm_version() != ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION
            || request.max_response_payload_bytes() != profile.max_response_payload_bytes
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let signature_bytes: [u8; 64] = request
            .auth_signature()
            .try_into()
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let transcript = request
            .signing_transcript()
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        controller_verifying_key
            .verify_strict(
                transcript.as_bytes(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        Ok(prepared)
    }

    fn fresh_tenure_request(
        profile: &TenureRequestProfile,
        controller_signer: &SigningKey,
    ) -> Result<PreparedAcquireTenureRequest, DeploymentdProcessError> {
        let entropy = read_tenure_entropy()?;
        fresh_tenure_request_from_entropy(profile, controller_signer, &entropy)
    }

    fn fresh_tenure_request_from_entropy(
        profile: &TenureRequestProfile,
        controller_signer: &SigningKey,
        entropy: &[u8; TENURE_ENTROPY_BYTES],
    ) -> Result<PreparedAcquireTenureRequest, DeploymentdProcessError> {
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&entropy[..16]);
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                profile.scope,
                profile.writer,
                AcquireTenureOperationId::from_bytes(operation_id),
            ),
            profile.controller_principal,
            profile.controller_key,
            profile.controller_public_key_fingerprint,
            &entropy[16..],
            profile.max_response_payload_bytes,
        )
        .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let request = AcquireTenureRequestToSign::try_new(draft)
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let signature = controller_signer.sign(request.signing_bytes());
        request
            .finalize_ed25519(&signature.to_bytes())
            .map_err(|_| process_error(ProcessErrorKind::Tenure))
    }

    fn read_tenure_entropy() -> Result<[u8; TENURE_ENTROPY_BYTES], DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        let mut source = File::from(owned);
        let mut entropy = [0; TENURE_ENTROPY_BYTES];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(ProcessErrorKind::Tenure))?;
        Ok(entropy)
    }

    fn bootstrap_runtime(arguments: BootstrapArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_bootstrap_separation(&arguments)?;

        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let runtime_response_public = read_pinned_file(
            &arguments.runtime_response_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let runtime_response_public_bytes = exact_public_key(&runtime_response_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == runtime_response_public_bytes
            || controller_public_bytes == authority_public_bytes
            || runtime_response_public_bytes == authority_public_bytes
        {
            return Err(process_error(ProcessErrorKind::Key));
        }
        // Load the only secret last, after every public-key/path validation that
        // can fail without it. `PinnedFile` owns zeroizing storage, so all exits
        // after this point erase the original read buffer automatically.
        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let file_identities = [
            controller_public.identity,
            controller_seed_file.identity,
            runtime_response_public.identity,
            authority_public.identity,
        ];
        if file_identities
            .iter()
            .enumerate()
            .any(|(index, identity)| file_identities[index + 1..].contains(identity))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let mut seed = Zeroizing::new([0; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        if controller_signer.verifying_key().to_bytes() != controller_public_bytes
            || controller_signer.verifying_key().is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let admission_policy = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let state = snapshot.state();
            let expected_scope = DeploymentScopeId::from_bytes(arguments.common.scope);
            let expected_plan = DeploymentId::from_bytes(arguments.common.plan);
            if state.scope() != expected_scope
                || state.plan_lineage() != expected_plan
                || state.request_auth() != request_auth.pin
                || state.current_revision() != 1
                || state.committed_plan_digest().is_none()
            {
                return Err(process_error(ProcessErrorKind::Provisioning));
            }
            let target = state.installed_manifest().target();
            let source_scope = paraegox_runtime_contracts::provenance::SourceScopeRef::from_bytes(
                *state.scope().as_bytes(),
            );
            reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
                target,
                source_scope,
                writer: PlanWriterRef::from_bytes(arguments.writer_ref),
                controller_principal: PrincipalRef::from_bytes(arguments.controller_principal),
                controller_key_ref: request_auth.pin.key(),
                controller_public_key: &controller_public_bytes,
                authority_principal: PrincipalRef::from_bytes(arguments.authority_principal),
                authority_uid: arguments.authority_uid,
                authority_gid: arguments.authority_gid,
                tenure_authority_ref: TenureAuthorityRef::from_bytes(
                    arguments.tenure_authority_ref,
                ),
                tenure_key_ref: TenureKeyRef::from_bytes(arguments.tenure_key_ref),
                tenure_public_key: &authority_public_bytes,
            })
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?
        };

        let provisioning = ControllerBootstrapProvisioningV1::try_new(
            arguments.runtime_socket_path,
            PrincipalRef::from_bytes(arguments.controller_principal),
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            runtime_response_public_bytes,
            arguments.runtime_uid,
            arguments.runtime_gid,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
            admission_policy,
            BOOTSTRAP_EXCHANGE_TIMEOUT,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let fresh = fresh_bootstrap_request()?;
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::Bootstrap))?;
        let receipt = runtime
            .block_on(bootstrap_runtime_v1(
                &mut store,
                owner_identity,
                &controller_signer,
                provisioning,
                fresh,
            ))
            .map_err(|_| process_error(ProcessErrorKind::Bootstrap))?;
        write_bootstrap_receipt(&receipt)
    }

    fn apply_reference(arguments: BootstrapArguments) -> Result<(), DeploymentdProcessError> {
        validate_service_identity(arguments.common.expected_uid, arguments.common.expected_gid)?;
        validate_bootstrap_separation(&arguments)?;

        let controller_public = read_pinned_file(
            &arguments.common.public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let runtime_response_public = read_pinned_file(
            &arguments.runtime_response_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let authority_public = read_pinned_file(
            &arguments.authority_public_key_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PublicKey,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let request_auth = request_auth_pin(&arguments.common, &controller_public.bytes)?;
        let owner_identity = owner_identity(&arguments.common, request_auth.fingerprint)?;
        let controller_public_bytes = exact_public_key(&controller_public.bytes)?;
        let runtime_response_public_bytes = exact_public_key(&runtime_response_public.bytes)?;
        let authority_public_bytes = exact_public_key(&authority_public.bytes)?;
        if controller_public_bytes == runtime_response_public_bytes
            || controller_public_bytes == authority_public_bytes
            || runtime_response_public_bytes == authority_public_bytes
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        // Load the Controller secret only after all public files and their
        // separation have been validated. Exact durable PXAR replay never
        // re-signs with this key, but still verifies the pinned signer.
        let controller_seed_file = read_pinned_file(
            &arguments.controller_private_seed_path,
            FileLengthPolicy::Exact(PUBLIC_KEY_BYTES),
            FileRole::PrivateSeed,
            arguments.common.expected_uid,
            arguments.common.expected_gid,
        )?;
        let file_identities = [
            controller_public.identity,
            controller_seed_file.identity,
            runtime_response_public.identity,
            authority_public.identity,
        ];
        if file_identities
            .iter()
            .enumerate()
            .any(|(index, identity)| file_identities[index + 1..].contains(identity))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let mut seed = Zeroizing::new([0; PUBLIC_KEY_BYTES]);
        seed.copy_from_slice(&controller_seed_file.bytes);
        let controller_signer = SigningKey::from_bytes(&seed);
        if controller_signer.verifying_key().to_bytes() != controller_public_bytes
            || controller_signer.verifying_key().is_weak()
        {
            return Err(process_error(ProcessErrorKind::Key));
        }

        let mut store = ControllerStore::open(
            &arguments.common.state_directory,
            arguments.expected_store_id,
            owner_identity,
        )
        .map_err(|_| process_error(ProcessErrorKind::Store))?;
        let (target, provisioning) = {
            let snapshot = store
                .snapshot()
                .map_err(|_| process_error(ProcessErrorKind::Store))?;
            let state = snapshot.state();
            let expected_scope = DeploymentScopeId::from_bytes(arguments.common.scope);
            let expected_plan = DeploymentId::from_bytes(arguments.common.plan);
            if state.scope() != expected_scope
                || state.plan_lineage() != expected_plan
                || state.request_auth() != request_auth.pin
                || state.committed_plan().is_none()
                || state.target_binding().is_none()
            {
                return Err(process_error(ProcessErrorKind::Provisioning));
            }
            validate_apply_protected_policy(
                &arguments,
                state,
                &request_auth,
                &controller_public_bytes,
                &runtime_response_public_bytes,
                &authority_public_bytes,
            )?;
            let provisioning = ControllerApplyProvisioningV1::try_from_controller_state(
                state,
                &controller_signer,
                PrincipalRef::from_bytes(arguments.controller_principal),
                DeploymentWriterRef::from_bytes(arguments.writer_ref),
                PrincipalRef::from_bytes(arguments.authority_principal),
                arguments.authority_uid,
                arguments.authority_gid,
                TenureAuthorityRef::from_bytes(arguments.tenure_authority_ref),
                TenureKeyRef::from_bytes(arguments.tenure_key_ref),
                authority_public_bytes,
            )
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
            (state.installed_manifest().target(), provisioning)
        };

        let endpoint = UnixRuntimeControlEndpoint::try_new(
            arguments.runtime_socket_path,
            RuntimeControlSocketAcl::new(arguments.runtime_uid, arguments.common.expected_gid),
            RuntimeUnixCredentials::new(arguments.runtime_uid, arguments.runtime_gid),
            target,
            PrincipalRef::from_bytes(arguments.runtime_principal),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_verifying_key = VerifyingKey::from_bytes(&runtime_response_public_bytes)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let runtime_key_fingerprint =
            ed25519_control_key_fingerprint(runtime_verifying_key.as_bytes())
                .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let response_verifier = RuntimeApplyResponseVerifier::try_new(
            PrincipalRef::from_bytes(arguments.runtime_principal),
            ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
            request_auth.pin.algorithm(),
            request_auth.pin.algorithm_version(),
            runtime_key_fingerprint,
            runtime_verifying_key,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let client =
            UnixRuntimeApplyClient::try_new(endpoint, response_verifier, APPLY_EXCHANGE_TIMEOUT)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::Apply))?;

        let prepared = match replay_prepared_reference_apply_v1(
            &mut store,
            owner_identity,
            &controller_signer,
            &provisioning,
        )
        .map_err(|_| process_error(ProcessErrorKind::Apply))?
        {
            Some(prepared) => prepared,
            None => {
                let fresh = fresh_apply_request()?;
                prepare_reference_apply_v1(
                    &mut store,
                    owner_identity,
                    &controller_signer,
                    &provisioning,
                    fresh,
                )
                .map_err(|_| process_error(ProcessErrorKind::Apply))?
            }
        };
        let applied = runtime
            .block_on(apply_reference_once_v1(&mut store, &client, &prepared))
            .map_err(|_| process_error(ProcessErrorKind::Apply))?;
        write_apply_receipt(&prepared, &applied)
    }

    fn validate_apply_protected_policy(
        arguments: &BootstrapArguments,
        state: &crate::controller_journal::ControllerJournalState,
        request_auth: &RequestAuthProvisioning,
        controller_public_key: &[u8; PUBLIC_KEY_BYTES],
        runtime_response_public_key: &[u8; PUBLIC_KEY_BYTES],
        authority_public_key: &[u8; PUBLIC_KEY_BYTES],
    ) -> Result<(), DeploymentdProcessError> {
        let target = state.installed_manifest().target();
        let source_scope = paraegox_runtime_contracts::provenance::SourceScopeRef::from_bytes(
            *state.scope().as_bytes(),
        );
        let admission_policy =
            reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
                target,
                source_scope,
                writer: PlanWriterRef::from_bytes(arguments.writer_ref),
                controller_principal: PrincipalRef::from_bytes(arguments.controller_principal),
                controller_key_ref: request_auth.pin.key(),
                controller_public_key,
                authority_principal: PrincipalRef::from_bytes(arguments.authority_principal),
                authority_uid: arguments.authority_uid,
                authority_gid: arguments.authority_gid,
                tenure_authority_ref: TenureAuthorityRef::from_bytes(
                    arguments.tenure_authority_ref,
                ),
                tenure_key_ref: TenureKeyRef::from_bytes(arguments.tenure_key_ref),
                tenure_public_key: authority_public_key,
            })
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let channel_policy = reference_bootstrap_channel_policy_fingerprint_v1(
            ReferenceBootstrapChannelPolicyInputV1 {
                canonical_socket_path: arguments.runtime_socket_path.as_os_str().as_bytes(),
                target,
                source_scope,
                controller_principal: PrincipalRef::from_bytes(arguments.controller_principal),
                controller_key_ref: request_auth.pin.key(),
                controller_public_key,
                runtime_uid: arguments.runtime_uid,
                runtime_gid: arguments.runtime_gid,
                controller_uid: arguments.common.expected_uid,
                controller_gid: arguments.common.expected_gid,
                runtime_principal: PrincipalRef::from_bytes(arguments.runtime_principal),
                response_key_ref: ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref),
                response_public_key: runtime_response_public_key,
            },
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let binding = state
            .target_binding()
            .ok_or_else(|| process_error(ProcessErrorKind::Provisioning))?;
        let response = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let runtime_auth = binding.runtime_response_auth();
        if response.facts().admission_policy_fingerprint() != admission_policy.digest()
            || binding.channel_auth_fingerprint().value() != channel_policy
            || runtime_auth.runtime_peer() != PrincipalRef::from_bytes(arguments.runtime_principal)
            || runtime_auth.key() != ApplyAuthKeyRef::from_bytes(arguments.runtime_response_key_ref)
            || runtime_auth.algorithm() != request_auth.pin.algorithm()
            || runtime_auth.algorithm_version() != request_auth.pin.algorithm_version()
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn fresh_apply_request() -> Result<FreshControllerApplyRequestV1, DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(ProcessErrorKind::Apply))?;
        let mut source = File::from(owned);
        let mut entropy = [0; APPLY_ENTROPY_BYTES];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(ProcessErrorKind::Apply))?;
        fresh_apply_request_from_entropy(&entropy)
    }

    fn fresh_apply_request_from_entropy(
        entropy: &[u8; APPLY_ENTROPY_BYTES],
    ) -> Result<FreshControllerApplyRequestV1, DeploymentdProcessError> {
        let mut operation = [0; 16];
        operation.copy_from_slice(&entropy[..16]);
        let mut temporal = [0; 16];
        temporal.copy_from_slice(&entropy[16..32]);
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&entropy[32..]);
        FreshControllerApplyRequestV1::try_new(operation, temporal, nonce)
            .map_err(|_| process_error(ProcessErrorKind::Apply))
    }

    fn exact_public_key(bytes: &[u8]) -> Result<[u8; 32], DeploymentdProcessError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| process_error(ProcessErrorKind::Key))?;
        if key.is_weak() {
            return Err(process_error(ProcessErrorKind::Key));
        }
        Ok(bytes)
    }

    fn fresh_bootstrap_request()
    -> Result<FreshControllerBootstrapRequestV1, DeploymentdProcessError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| process_error(ProcessErrorKind::Bootstrap))?;
        let mut source = File::from(owned);
        let mut entropy = [0; BOOTSTRAP_ENTROPY_BYTES];
        source
            .read_exact(&mut entropy)
            .map_err(|_| process_error(ProcessErrorKind::Bootstrap))?;
        let mut request_id = [0; 16];
        request_id.copy_from_slice(&entropy[..16]);
        let mut client_nonce = [0; 32];
        client_nonce.copy_from_slice(&entropy[16..]);
        FreshControllerBootstrapRequestV1::try_new(request_id, client_nonce)
            .map_err(|_| process_error(ProcessErrorKind::Bootstrap))
    }

    fn build_reference_candidate(
        installed_manifest: &ControllerInstalledManifestPin,
        deck_key: [u8; 16],
        card_use_key: [u8; 16],
        definition_version: u32,
        lifecycle: ValidatedReferenceLifecycleBudgetsV1,
    ) -> Result<DeploymentPlanCandidate, DeploymentdProcessError> {
        let manifest = installed_manifest.projection();
        let definition = manifest.fixture_definition();
        let deck = DeckSpec::new(
            DeckKey::from_bytes(deck_key),
            vec![
                DeckCardSpec::new(
                    CardUseKey::from_bytes(card_use_key),
                    definition,
                    DeckCardConfig::CanonicalEmpty,
                )
                .with_role(DeckCardRole::ReferenceSubject)
                .with_requested_version(CardDefinitionVersionRequirement::exact(
                    definition_version,
                )),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DeckOwnershipRequest::Deck,
            DeckLifetimeRequest::Deck,
        );
        let resolver = DeckResolverSnapshot::new(vec![ResolvedCardDefinition::new(
            definition,
            definition_version,
            ResolvedCardArtifact::new(
                manifest.fixture_definition_digest(),
                manifest.fixture_implementation(),
                DeckExportRef::from_bytes(manifest.fixture_export()),
                manifest.fixture_artifact_digest(),
            ),
            Vec::new(),
        )]);
        let deck_lock = DeckCompiler::compile(&deck, &resolver)
            .map_err(|_| process_error(ProcessErrorKind::Planning))?;
        let empty_allocation =
            StableAllocationSnapshot::try_new(installed_manifest.target(), 0, 0, Vec::new())
                .map_err(|_| process_error(ProcessErrorKind::Planning))?;
        let outcome = DeploymentPlanner::plan(&PlannerInput {
            target: installed_manifest.target(),
            desired: PlannerDesired::OneSourceLoop {
                deck_lock: &deck_lock,
                lifecycle: ValidatedReferenceLifecycleBudgets::from_reference_contract(lifecycle),
                config_digest: manifest.canonical_empty_config_digest(),
            },
            previous: PreviousTargetEligibility::UninitializedNoneExactZero,
            manifest: Some(manifest),
            allocation: &empty_allocation,
            service_dependencies: &[],
        })
        .map_err(|_| process_error(ProcessErrorKind::Planning))?;
        match outcome {
            PlannerOutcome::Candidate(candidate) => Ok(*candidate),
            PlannerOutcome::Omitted => Err(process_error(ProcessErrorKind::Planning)),
        }
    }

    struct RequestAuthProvisioning {
        pin: ControllerRequestAuthPin,
        fingerprint: Digest32,
    }

    fn request_auth_pin(
        arguments: &CommonArguments,
        bytes: &[u8],
    ) -> Result<RequestAuthProvisioning, DeploymentdProcessError> {
        let public_key: [u8; PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        if verifying_key.is_weak() {
            return Err(process_error(ProcessErrorKind::Key));
        }
        let fingerprint = ed25519_control_key_fingerprint(&public_key)
            .map_err(|_| process_error(ProcessErrorKind::Key))?;
        let algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let pin = ControllerRequestAuthPin::try_new(
            ApplyAuthKeyRef::from_bytes(arguments.request_auth_key),
            algorithm,
            ED25519_ALGORITHM_VERSION,
            ControllerAuthKeyFingerprint::from_stored(fingerprint),
            INITIAL_AUTH_ROTATION_GENERATION,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        Ok(RequestAuthProvisioning { pin, fingerprint })
    }

    fn owner_identity(
        arguments: &CommonArguments,
        request_auth_fingerprint: Digest32,
    ) -> Result<ControllerOwnerIdentityFingerprint, DeploymentdProcessError> {
        // The fields are deliberately reproducible by normal startup without
        // rereading the installer artifact. The journal itself owns the exact
        // immutable manifest pin and cross-checks every later plan against it.
        let mut builder = Digest32Builder::try_new(CONTROLLER_OWNER_IDENTITY_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        builder
            .field_bytes(arguments.state_directory.as_os_str().as_bytes())
            .and_then(|builder| builder.field_u64(u64::from(arguments.expected_uid)))
            .and_then(|builder| builder.field_u64(u64::from(arguments.expected_gid)))
            .and_then(|builder| builder.field_bytes(&arguments.scope))
            .and_then(|builder| builder.field_bytes(&arguments.plan))
            .and_then(|builder| builder.field_bytes(&arguments.request_auth_key))
            .and_then(|builder| builder.field_u16(ED25519_ALGORITHM))
            .and_then(|builder| builder.field_u16(ED25519_ALGORITHM_VERSION))
            .and_then(|builder| builder.field_digest(&request_auth_fingerprint))
            .and_then(|builder| builder.field_u64(INITIAL_AUTH_ROTATION_GENERATION))
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        Ok(ControllerOwnerIdentityFingerprint::from_stored(
            builder.finish(),
        ))
    }

    fn validate_service_identity(
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), DeploymentdProcessError> {
        if expected_uid == 0
            || expected_gid == 0
            || geteuid().as_raw() != expected_uid
            || getegid().as_raw() != expected_gid
        {
            return Err(process_error(ProcessErrorKind::ServiceIdentity));
        }
        Ok(())
    }

    fn validate_separation(
        arguments: &CommonArguments,
        manifest_path: Option<&Path>,
    ) -> Result<(), DeploymentdProcessError> {
        if arguments
            .public_key_path
            .starts_with(&arguments.state_directory)
            || manifest_path.is_some_and(|path| {
                path.starts_with(&arguments.state_directory) || path == arguments.public_key_path
            })
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        Ok(())
    }

    fn validate_bootstrap_separation(
        arguments: &BootstrapArguments,
    ) -> Result<(), DeploymentdProcessError> {
        validate_separation(&arguments.common, None)?;
        let protected_paths = [
            &arguments.common.public_key_path,
            &arguments.controller_private_seed_path,
            &arguments.runtime_response_public_key_path,
            &arguments.authority_public_key_path,
        ];
        if arguments
            .runtime_socket_path
            .starts_with(&arguments.common.state_directory)
            || protected_paths.iter().any(|path| {
                path.starts_with(&arguments.common.state_directory)
                    || *path == &arguments.runtime_socket_path
            })
            || protected_paths
                .iter()
                .enumerate()
                .any(|(index, path)| protected_paths[index + 1..].contains(path))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        let principals = [
            arguments.controller_principal,
            arguments.runtime_principal,
            arguments.authority_principal,
        ];
        if principals
            .iter()
            .enumerate()
            .any(|(index, principal)| principals[index + 1..].contains(principal))
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let key_and_authority_refs = [
            arguments.common.request_auth_key,
            arguments.runtime_response_key_ref,
            arguments.tenure_key_ref,
            arguments.tenure_authority_ref,
        ];
        if key_and_authority_refs
            .iter()
            .enumerate()
            .any(|(index, reference)| key_and_authority_refs[index + 1..].contains(reference))
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let uids = [
            arguments.common.expected_uid,
            arguments.runtime_uid,
            arguments.authority_uid,
        ];
        if uids
            .iter()
            .enumerate()
            .any(|(index, uid)| uids[index + 1..].contains(uid))
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn validate_tenure_separation(
        arguments: &AcquireTenureArguments,
    ) -> Result<(), DeploymentdProcessError> {
        validate_separation(&arguments.common, None)?;
        let key_paths = [
            &arguments.common.public_key_path,
            &arguments.controller_private_seed_path,
            &arguments.authority_public_key_path,
        ];
        if arguments
            .authority_socket_path
            .starts_with(&arguments.common.state_directory)
            || key_paths.iter().any(|path| {
                path.starts_with(&arguments.common.state_directory)
                    || *path == &arguments.authority_socket_path
            })
            || key_paths
                .iter()
                .enumerate()
                .any(|(index, path)| key_paths[index + 1..].contains(path))
        {
            return Err(process_error(ProcessErrorKind::Path));
        }
        if arguments.authority_uid == arguments.common.expected_uid {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        let refs = [
            arguments.common.request_auth_key,
            arguments.tenure_authority_ref,
            arguments.tenure_key_ref,
        ];
        if refs
            .iter()
            .enumerate()
            .any(|(index, reference)| refs[index + 1..].contains(reference))
        {
            return Err(process_error(ProcessErrorKind::Provisioning));
        }
        Ok(())
    }

    fn write_initialization_receipt(
        receipt: &ControllerInitializationReceipt,
    ) -> Result<(), DeploymentdProcessError> {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_initialize_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "store_instance_id",
            receipt.store_instance_id(),
        )?;
        write_labeled_hex(
            &mut output,
            "owner_identity_fingerprint",
            receipt.owner_identity_fingerprint().value().as_bytes(),
        )?;
        writeln!(output, "snapshot_sequence={}", receipt.snapshot_sequence())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "initialized_snapshot_digest",
            receipt.initialized_snapshot_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "receipt_digest",
            receipt.receipt_digest().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "receipt_bytes", receipt.canonical_bytes())?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_commit_receipt(
        snapshot: &ControllerJournalSnapshot,
        operation: ControllerOperationId,
    ) -> Result<(), DeploymentdProcessError> {
        let plan_digest = snapshot
            .state()
            .committed_plan_digest()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let manifest_digest = snapshot.state().installed_manifest().manifest_digest();
        let encoded_snapshot = snapshot
            .encode()
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        let mut snapshot_digest = Digest32Builder::try_new(COMMIT_SNAPSHOT_DIGEST_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        snapshot_digest
            .field_bytes(&encoded_snapshot)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        let snapshot_digest = snapshot_digest.finish();

        let mut receipt = Vec::new();
        receipt.extend_from_slice(COMMIT_RECEIPT_MAGIC);
        receipt.extend_from_slice(&COMMIT_RECEIPT_VERSION.to_be_bytes());
        receipt.extend_from_slice(snapshot.store_instance_id());
        receipt.extend_from_slice(&snapshot.snapshot_sequence().to_be_bytes());
        receipt.extend_from_slice(&snapshot.state().current_revision().to_be_bytes());
        receipt.extend_from_slice(operation.as_bytes());
        receipt.extend_from_slice(plan_digest.value().as_bytes());
        receipt.extend_from_slice(manifest_digest.as_bytes());
        receipt.extend_from_slice(snapshot_digest.as_bytes());
        let mut receipt_digest = Digest32Builder::try_new(COMMIT_RECEIPT_DIGEST_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        receipt_digest
            .field_bytes(&receipt)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        let receipt_digest = receipt_digest.finish();

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_commit_reference_loop_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "store_instance_id",
            snapshot.store_instance_id(),
        )?;
        writeln!(output, "snapshot_sequence={}", snapshot.snapshot_sequence())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "plan_revision={}",
            snapshot.state().current_revision()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "operation_id", operation.as_bytes())?;
        write_labeled_hex(&mut output, "plan_digest", plan_digest.value().as_bytes())?;
        write_labeled_hex(&mut output, "manifest_digest", manifest_digest.as_bytes())?;
        write_labeled_hex(&mut output, "snapshot_digest", snapshot_digest.as_bytes())?;
        write_labeled_hex(&mut output, "receipt_digest", receipt_digest.as_bytes())?;
        write_labeled_hex(&mut output, "receipt_bytes", &receipt)?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_empty_commit_receipt(
        snapshot: &ControllerJournalSnapshot,
        operation: ControllerOperationId,
    ) -> Result<(), DeploymentdProcessError> {
        let state = snapshot.state();
        let plan = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let manifest_digest = state.installed_manifest().manifest_digest();

        let (receipt, receipt_digest, expected_active) =
            build_empty_commit_receipt(snapshot, operation)?;

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_commit_reference_empty_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "controller_store_instance_id",
            snapshot.store_instance_id(),
        )?;
        write_labeled_hex(&mut output, "source_scope", state.scope().as_bytes())?;
        write_labeled_hex(&mut output, "source_plan", state.plan_lineage().as_bytes())?;
        writeln!(output, "plan_revision={}", plan.revision().value())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "operation_id", operation.as_bytes())?;
        write_labeled_hex(&mut output, "target", plan.target().as_bytes())?;
        write_labeled_hex(
            &mut output,
            "plan_digest",
            plan.deployment_plan_digest().value().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "manifest_digest", manifest_digest.as_bytes())?;
        writeln!(
            output,
            "allocation_generation={}",
            state.allocation().generation()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "expected_active_target_slice_digest",
            expected_active.value().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "receipt_digest", receipt_digest.as_bytes())?;
        write_labeled_hex(&mut output, "receipt_bytes", &receipt)?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn build_empty_commit_receipt(
        snapshot: &ControllerJournalSnapshot,
        operation: ControllerOperationId,
    ) -> Result<
        (
            Vec<u8>,
            Digest32,
            paraegox_runtime_contracts::provenance::TargetSliceDigest,
        ),
        DeploymentdProcessError,
    > {
        let state = snapshot.state();
        let expected_active = validate_committed_empty_state(state, operation)?;
        let plan = state
            .committed_plan()
            .ok_or_else(|| process_error(ProcessErrorKind::Commit))?;
        let manifest_digest = state.installed_manifest().manifest_digest();

        // This receipt intentionally excludes the physical Controller snapshot
        // sequence and whole-snapshot digest. Bootstrap refreshes and the
        // subsequent Empty apply are legal successors, but must not change the
        // semantic result of replaying this exact committed plan operation.
        let mut receipt = Vec::new();
        receipt.extend_from_slice(EMPTY_COMMIT_RECEIPT_MAGIC);
        receipt.extend_from_slice(&EMPTY_COMMIT_RECEIPT_VERSION.to_be_bytes());
        receipt.extend_from_slice(snapshot.store_instance_id());
        receipt.extend_from_slice(state.scope().as_bytes());
        receipt.extend_from_slice(state.plan_lineage().as_bytes());
        receipt.extend_from_slice(&plan.revision().value().to_be_bytes());
        receipt.extend_from_slice(operation.as_bytes());
        receipt.extend_from_slice(plan.target().as_bytes());
        receipt.extend_from_slice(plan.deployment_plan_digest().value().as_bytes());
        receipt.extend_from_slice(manifest_digest.as_bytes());
        receipt.extend_from_slice(&state.allocation().generation().to_be_bytes());
        receipt.extend_from_slice(expected_active.value().as_bytes());
        let mut receipt_digest = Digest32Builder::try_new(EMPTY_COMMIT_RECEIPT_DIGEST_DOMAIN)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        receipt_digest
            .field_bytes(&receipt)
            .map_err(|_| process_error(ProcessErrorKind::Commit))?;
        let receipt_digest = receipt_digest.finish();
        Ok((receipt, receipt_digest, expected_active))
    }

    fn write_bootstrap_receipt(
        receipt: &ControllerBootstrapReceiptV1,
    ) -> Result<(), DeploymentdProcessError> {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_bootstrap_runtime_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "controller_store_instance_id",
            receipt.controller_store_instance_id(),
        )?;
        writeln!(
            output,
            "controller_snapshot_sequence={}",
            receipt.controller_snapshot_sequence()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "target", receipt.target().as_bytes())?;
        write_labeled_hex(
            &mut output,
            "runtime_store_instance_id",
            receipt.runtime_store_instance_id(),
        )?;
        writeln!(
            output,
            "runtime_host_epoch={}",
            receipt.runtime_host_epoch()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "channel_policy_fingerprint",
            receipt.channel_policy_fingerprint().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "bootstrap_response_digest",
            receipt.bootstrap_response_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "bootstrap_response_bytes",
            receipt.bootstrap_response(),
        )?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_tenure_receipt(
        snapshot: &ControllerJournalSnapshot,
        operation: AcquireTenureOperationId,
        acquired: &ControllerAcquiredTenure,
    ) -> Result<(), DeploymentdProcessError> {
        let transaction = snapshot
            .state()
            .tenure_transaction(operation)
            .ok_or_else(|| process_error(ProcessErrorKind::Tenure))?;
        let response = transaction
            .response()
            .ok_or_else(|| process_error(ProcessErrorKind::Tenure))?;
        if response.proof() != acquired.proof()
            || response.operation_id() != operation
            || response.request_digest() != transaction.request().request_digest()
        {
            return Err(process_error(ProcessErrorKind::Tenure));
        }
        let proof = response.proof();
        let authority = proof.authority();
        let claim = proof.claim();

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_acquire_tenure_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "controller_store_instance_id",
            snapshot.store_instance_id(),
        )?;
        write_labeled_hex(
            &mut output,
            "authority_domain_fingerprint",
            transaction
                .authority_domain_fingerprint()
                .value()
                .as_bytes(),
        )?;
        write_labeled_hex(&mut output, "operation_id", operation.as_bytes())?;
        write_labeled_hex(
            &mut output,
            "request_digest",
            transaction.request().request_digest().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "source_scope", claim.source_scope().as_bytes())?;
        write_labeled_hex(&mut output, "writer_ref", claim.writer().as_bytes())?;
        writeln!(output, "writer_epoch={}", claim.epoch().value())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "supersedes_through_epoch={}",
            claim.supersedes_through_epoch().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "tenure_authority_ref",
            authority.authority().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "tenure_key_ref", authority.key().as_bytes())?;
        writeln!(output, "proof_algorithm={}", authority.algorithm().value())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "proof_algorithm_version={}",
            authority.algorithm_version()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(&mut output, "proof_nonce", proof.nonce())?;
        write_labeled_hex(&mut output, "proof_signature", proof.signature())?;
        write_labeled_hex(
            &mut output,
            "proof_digest",
            response.proof_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "acquire_response_digest",
            response.response_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "acquire_response_bytes",
            response.canonical_bytes(),
        )?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_apply_receipt(
        prepared: &PreparedControllerApplyAttemptV1,
        applied: &ControllerAppliedReferenceV1,
    ) -> Result<(), DeploymentdProcessError> {
        let request = prepared.request();
        let receipt = applied
            .terminal_receipt()
            .ok_or_else(|| process_error(ProcessErrorKind::Apply))?;
        let provenance = request.provenance();
        let control = request.control_commitment().control();
        let writer = control.writer_context();
        let facts = receipt.facts();
        let request_time_channel = prepared.runtime_response_expectation().channel();
        let validated_facts = receipt
            .validate_against_request(request, request_time_channel)
            .map_err(|_| process_error(ProcessErrorKind::Apply))?;
        if applied.controller_store_instance_id() != prepared.controller_store_instance_id()
            || validated_facts != facts
            || receipt.target() != request.target()
            || receipt.runtime_store_instance_id() != request.expected_runtime_store_instance_id()
            || receipt.source_scope() != provenance.source_scope()
            || receipt.operation_id() != control.operation_id()
            || receipt.request_digest() != request.envelope_request_digest()
            || receipt.authentication_channel_binding_digest()
                != request_time_channel.binding_digest()
        {
            return Err(process_error(ProcessErrorKind::Apply));
        }

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "controller_apply_reference_v1")
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "controller_store_instance_id",
            applied.controller_store_instance_id(),
        )?;
        write_labeled_hex(&mut output, "target", request.target().as_bytes())?;
        write_labeled_hex(
            &mut output,
            "runtime_store_instance_id",
            &request.expected_runtime_store_instance_id(),
        )?;
        write_labeled_hex(
            &mut output,
            "source_scope",
            provenance.source_scope().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "source_plan",
            provenance.source_plan().as_bytes(),
        )?;
        writeln!(
            output,
            "source_plan_revision={}",
            provenance.source_revision().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "source_plan_digest",
            provenance.source_plan_digest().value().as_bytes(),
        )?;
        write_labeled_hex(&mut output, "writer_ref", writer.writer().as_bytes())?;
        writeln!(output, "writer_epoch={}", writer.epoch().value())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "apply_operation_id",
            control.operation_id().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "target_slice_digest",
            request.target_slice_digest().value().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "apply_request_digest",
            request.envelope_request_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "request_time_channel_binding_digest",
            request_time_channel.binding_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "apply_request_bytes",
            prepared.canonical_request_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "terminal_result_ref",
            facts.terminal_result_ref().as_bytes(),
        )?;
        writeln!(
            output,
            "terminal_outcome={}",
            terminal_outcome_code(facts.outcome())
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "terminal_lifecycle_effect={}",
            terminal_lifecycle_effect_code(facts.lifecycle_effect())
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(output, "terminal_head={}", terminal_head_code(facts.head()))
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        match facts.desired_head_digest() {
            Some(digest) => write_labeled_hex(
                &mut output,
                "desired_head_digest",
                digest.value().as_bytes(),
            )?,
            None => writeln!(output, "desired_head_digest=none")
                .map_err(|_| process_error(ProcessErrorKind::Output))?,
        }
        write_labeled_hex(
            &mut output,
            "resource_census_digest",
            facts.resource_census_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "raw_outcome_digest",
            facts.raw_outcome_digest().as_bytes(),
        )?;
        writeln!(
            output,
            "completion_runtime_host_epoch={}",
            facts.completion_runtime_host_epoch()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "completion_snapshot_sequence={}",
            facts.completion_snapshot_sequence()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "selection_clock_generation={}",
            facts.selection_clock_generation().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "selection_observed_at_nanos={}",
            facts.selection_observed_at_nanos()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "runtime_peer",
            receipt.authentication_runtime_peer().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "runtime_response_key_ref",
            receipt.authentication_key().as_bytes(),
        )?;
        writeln!(
            output,
            "runtime_response_algorithm={}",
            receipt.authentication_algorithm().value()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(
            output,
            "runtime_response_algorithm_version={}",
            receipt.authentication_algorithm_version()
        )
        .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            "terminal_receipt_digest",
            receipt.receipt_digest().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            "terminal_receipt_bytes",
            receipt.canonical_wire(),
        )?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    const fn terminal_head_code(head: ReferenceApplyTerminalHeadV1) -> u16 {
        match head {
            ReferenceApplyTerminalHeadV1::PreservedNone => 1,
            ReferenceApplyTerminalHeadV1::PreservedExisting(_) => 2,
            ReferenceApplyTerminalHeadV1::CommittedIncoming => 3,
        }
    }

    const fn terminal_lifecycle_effect_code(
        effect: ReferenceApplyTerminalLifecycleEffectV1,
    ) -> u16 {
        match effect {
            ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted => 1,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted => 2,
        }
    }

    const fn terminal_outcome_code(outcome: ReferenceApplyTerminalOutcomeV1) -> u16 {
        match outcome {
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive => 1,
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero => 2,
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects => 3,
            ReferenceApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects => 4,
            ReferenceApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero => 5,
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero => 6,
            ReferenceApplyTerminalOutcomeV1::StopFailedButExactZero => 7,
            ReferenceApplyTerminalOutcomeV1::TimedOutButExactZero => 8,
            ReferenceApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects => 9,
            ReferenceApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero => 10,
            ReferenceApplyTerminalOutcomeV1::SupersededAfterIntentExactZero => 11,
            ReferenceApplyTerminalOutcomeV1::InterruptedButNowExactZero => 12,
        }
    }

    fn write_labeled_hex(
        output: &mut impl Write,
        label: &str,
        bytes: &[u8],
    ) -> Result<(), DeploymentdProcessError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = Vec::with_capacity(label.len() + 2 + bytes.len().saturating_mul(2));
        encoded.extend_from_slice(label.as_bytes());
        encoded.push(b'=');
        for byte in bytes {
            encoded.push(HEX[usize::from(byte >> 4)]);
            encoded.push(HEX[usize::from(byte & 0x0f)]);
        }
        encoded.push(b'\n');
        output
            .write_all(&encoded)
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ProcessCommand {
        Initialize(InitializeArguments),
        MigrateControllerJournal(ControllerJournalMigrationArguments),
        CommitReferenceLoop(CommitArguments),
        CommitReferenceEmpty(CommitEmptyArguments),
        AcquireTenure(AcquireTenureArguments),
        BootstrapRuntime(BootstrapArguments),
        ApplyReference(BootstrapArguments),
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ControllerJournalMigrationArguments {
        state_directory: PathBuf,
        evidence_directory: PathBuf,
        expected_store_id: [u8; 32],
        expected_owner_identity: [u8; 32],
        migration_id: [u8; 32],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CommonArguments {
        state_directory: PathBuf,
        scope: [u8; 16],
        plan: [u8; 16],
        request_auth_key: [u8; 16],
        public_key_path: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct InitializeArguments {
        common: CommonArguments,
        manifest_path: PathBuf,
        manifest_digest: Digest32,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CommitArguments {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        deck_key: [u8; 16],
        card_use_key: [u8; 16],
        definition_version: u32,
        operation_id: [u8; 16],
        start_nanos: u64,
        drain_nanos: u64,
        cleanup_nanos: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CommitEmptyArguments {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        operation_id: [u8; 16],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct AcquireTenureArguments {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        controller_private_seed_path: PathBuf,
        controller_principal: [u8; 16],
        writer_ref: [u8; 16],
        tenure_authority_ref: [u8; 16],
        tenure_key_ref: [u8; 16],
        authority_public_key_path: PathBuf,
        authority_socket_path: PathBuf,
        authority_uid: u32,
        authority_gid: u32,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct BootstrapArguments {
        common: CommonArguments,
        expected_store_id: [u8; 32],
        controller_private_seed_path: PathBuf,
        controller_principal: [u8; 16],
        writer_ref: [u8; 16],
        authority_principal: [u8; 16],
        authority_uid: u32,
        authority_gid: u32,
        tenure_authority_ref: [u8; 16],
        tenure_key_ref: [u8; 16],
        authority_public_key_path: PathBuf,
        runtime_socket_path: PathBuf,
        runtime_principal: [u8; 16],
        runtime_response_key_ref: [u8; 16],
        runtime_response_public_key_path: PathBuf,
        runtime_uid: u32,
        runtime_gid: u32,
    }

    fn parse_arguments(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<ProcessCommand, DeploymentdProcessError> {
        let arguments = arguments
            .into_iter()
            .take(MAX_ARGUMENTS + 1)
            .collect::<Vec<_>>();
        let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
            return Err(process_error(ProcessErrorKind::Arguments));
        };
        match command {
            "migrate-controller-journal-v7-to-v8-v1" if arguments.len() == 6 => Ok(
                ProcessCommand::MigrateControllerJournal(ControllerJournalMigrationArguments {
                    state_directory: parse_absolute_path(&arguments[1])?,
                    evidence_directory: parse_absolute_path(&arguments[2])?,
                    expected_store_id: parse_nonzero_hex(&arguments[3])?,
                    expected_owner_identity: parse_nonzero_hex(&arguments[4])?,
                    migration_id: parse_nonzero_hex(&arguments[5])?,
                }),
            ),
            "initialize-reference-v1" if arguments.len() == 10 => {
                Ok(ProcessCommand::Initialize(InitializeArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[4])?,
                        plan: parse_nonzero_hex(&arguments[5])?,
                        request_auth_key: parse_nonzero_hex(&arguments[6])?,
                        public_key_path: parse_absolute_file_path(&arguments[7])?,
                        expected_uid: parse_nonzero_u32(&arguments[8])?,
                        expected_gid: parse_nonzero_u32(&arguments[9])?,
                    },
                    manifest_path: parse_absolute_file_path(&arguments[2])?,
                    manifest_digest: Digest32::from_bytes(parse_nonzero_hex(&arguments[3])?),
                }))
            }
            "commit-reference-loop-v1" if arguments.len() == 16 => {
                Ok(ProcessCommand::CommitReferenceLoop(CommitArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[3])?,
                        plan: parse_nonzero_hex(&arguments[4])?,
                        request_auth_key: parse_nonzero_hex(&arguments[5])?,
                        public_key_path: parse_absolute_file_path(&arguments[6])?,
                        expected_uid: parse_nonzero_u32(&arguments[7])?,
                        expected_gid: parse_nonzero_u32(&arguments[8])?,
                    },
                    expected_store_id: parse_nonzero_hex(&arguments[2])?,
                    deck_key: parse_nonzero_hex(&arguments[9])?,
                    card_use_key: parse_nonzero_hex(&arguments[10])?,
                    definition_version: parse_nonzero_u32(&arguments[11])?,
                    operation_id: parse_nonzero_hex(&arguments[12])?,
                    start_nanos: parse_nonzero_u64(&arguments[13])?,
                    drain_nanos: parse_nonzero_u64(&arguments[14])?,
                    cleanup_nanos: parse_nonzero_u64(&arguments[15])?,
                }))
            }
            "commit-reference-empty-v1" if arguments.len() == 10 => {
                Ok(ProcessCommand::CommitReferenceEmpty(CommitEmptyArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[3])?,
                        plan: parse_nonzero_hex(&arguments[4])?,
                        request_auth_key: parse_nonzero_hex(&arguments[5])?,
                        public_key_path: parse_absolute_file_path(&arguments[6])?,
                        expected_uid: parse_nonzero_u32(&arguments[7])?,
                        expected_gid: parse_nonzero_u32(&arguments[8])?,
                    },
                    expected_store_id: parse_nonzero_hex(&arguments[2])?,
                    operation_id: parse_nonzero_hex(&arguments[9])?,
                }))
            }
            "acquire-tenure-v1" if arguments.len() == 18 => {
                Ok(ProcessCommand::AcquireTenure(AcquireTenureArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[3])?,
                        plan: parse_nonzero_hex(&arguments[4])?,
                        request_auth_key: parse_nonzero_hex(&arguments[5])?,
                        public_key_path: parse_absolute_file_path(&arguments[6])?,
                        expected_uid: parse_nonzero_u32(&arguments[8])?,
                        expected_gid: parse_nonzero_u32(&arguments[9])?,
                    },
                    expected_store_id: parse_nonzero_hex(&arguments[2])?,
                    controller_private_seed_path: parse_absolute_file_path(&arguments[7])?,
                    controller_principal: parse_nonzero_hex(&arguments[10])?,
                    writer_ref: parse_nonzero_hex(&arguments[11])?,
                    tenure_authority_ref: parse_nonzero_hex(&arguments[12])?,
                    tenure_key_ref: parse_nonzero_hex(&arguments[13])?,
                    authority_public_key_path: parse_absolute_file_path(&arguments[14])?,
                    authority_socket_path: parse_absolute_file_path(&arguments[15])?,
                    authority_uid: parse_nonzero_u32(&arguments[16])?,
                    authority_gid: parse_nonzero_u32(&arguments[17])?,
                }))
            }
            command @ ("bootstrap-runtime-v1" | "apply-reference-v1") if arguments.len() == 24 => {
                let parsed = BootstrapArguments {
                    common: CommonArguments {
                        state_directory: parse_absolute_path(&arguments[1])?,
                        scope: parse_nonzero_hex(&arguments[3])?,
                        plan: parse_nonzero_hex(&arguments[4])?,
                        request_auth_key: parse_nonzero_hex(&arguments[5])?,
                        public_key_path: parse_absolute_file_path(&arguments[6])?,
                        expected_uid: parse_nonzero_u32(&arguments[8])?,
                        expected_gid: parse_nonzero_u32(&arguments[9])?,
                    },
                    expected_store_id: parse_nonzero_hex(&arguments[2])?,
                    controller_private_seed_path: parse_absolute_file_path(&arguments[7])?,
                    controller_principal: parse_nonzero_hex(&arguments[10])?,
                    writer_ref: parse_nonzero_hex(&arguments[11])?,
                    authority_principal: parse_nonzero_hex(&arguments[12])?,
                    authority_uid: parse_nonzero_u32(&arguments[13])?,
                    authority_gid: parse_nonzero_u32(&arguments[14])?,
                    tenure_authority_ref: parse_nonzero_hex(&arguments[15])?,
                    tenure_key_ref: parse_nonzero_hex(&arguments[16])?,
                    authority_public_key_path: parse_absolute_file_path(&arguments[17])?,
                    runtime_socket_path: parse_absolute_file_path(&arguments[18])?,
                    runtime_principal: parse_nonzero_hex(&arguments[19])?,
                    runtime_response_key_ref: parse_nonzero_hex(&arguments[20])?,
                    runtime_response_public_key_path: parse_absolute_file_path(&arguments[21])?,
                    runtime_uid: parse_nonzero_u32(&arguments[22])?,
                    runtime_gid: parse_nonzero_u32(&arguments[23])?,
                };
                if command == "bootstrap-runtime-v1" {
                    Ok(ProcessCommand::BootstrapRuntime(parsed))
                } else {
                    Ok(ProcessCommand::ApplyReference(parsed))
                }
            }
            _ => Err(process_error(ProcessErrorKind::Arguments)),
        }
    }

    fn parse_absolute_file_path(value: &OsStr) -> Result<PathBuf, DeploymentdProcessError> {
        let path = parse_absolute_path(value)?;
        if path.parent().is_none() || path.file_name().is_none() {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(path)
    }

    fn parse_absolute_path(value: &OsStr) -> Result<PathBuf, DeploymentdProcessError> {
        let path = PathBuf::from(value);
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || bytes.len() <= 1
            || bytes.first() != Some(&b'/')
            || bytes.last() == Some(&b'/')
            || bytes.contains(&0)
            || bytes.windows(2).any(|window| window == b"//")
            || bytes[1..]
                .split(|byte| *byte == b'/')
                .any(|component| component == b"." || component == b"..")
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir | Component::ParentDir | Component::Prefix(_)
                )
            })
        {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(path)
    }

    fn parse_nonzero_hex<const N: usize>(
        value: &OsStr,
    ) -> Result<[u8; N], DeploymentdProcessError> {
        let value = value
            .to_str()
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?;
        if value.len() != N.saturating_mul(2) {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        let mut decoded = [0; N];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        if decoded.iter().all(|byte| *byte == 0) {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(decoded)
    }

    fn hex_nibble(value: u8) -> Result<u8, DeploymentdProcessError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(process_error(ProcessErrorKind::Arguments)),
        }
    }

    fn parse_nonzero_u32(value: &OsStr) -> Result<u32, DeploymentdProcessError> {
        let value = parse_nonzero_u64(value)?;
        u32::try_from(value).map_err(|_| process_error(ProcessErrorKind::Arguments))
    }

    fn parse_nonzero_u64(value: &OsStr) -> Result<u64, DeploymentdProcessError> {
        let value = value
            .to_str()
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?;
        if value.is_empty()
            || value == "0"
            || value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        value
            .parse()
            .map_err(|_| process_error(ProcessErrorKind::Arguments))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        length: u64,
    }

    impl FileIdentity {
        fn from_metadata(metadata: &Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
            }
        }
    }

    struct PinnedFile {
        bytes: Zeroizing<Box<[u8]>>,
        identity: FileIdentity,
    }

    #[derive(Clone, Copy)]
    enum FileRole {
        Manifest,
        PublicKey,
        PrivateSeed,
    }

    #[derive(Clone, Copy)]
    enum FileLengthPolicy {
        Exact(usize),
        BoundedNonZero(usize),
    }

    fn read_pinned_file(
        path: &Path,
        length_policy: FileLengthPolicy,
        role: FileRole,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<PinnedFile, DeploymentdProcessError> {
        validate_existing_path_chain(path)?;
        validate_trusted_ancestors(path, expected_uid)?;
        let before = fs::symlink_metadata(path).map_err(|_| file_error(role))?;
        let observed_length =
            validate_file_metadata(&before, length_policy, role, expected_uid, expected_gid)?;
        let owned = open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| file_error(role))?;
        let mut file = File::from(owned);
        let opened = file.metadata().map_err(|_| file_error(role))?;
        let opened_length =
            validate_file_metadata(&opened, length_policy, role, expected_uid, expected_gid)?;
        let identity = FileIdentity::from_metadata(&opened);
        if FileIdentity::from_metadata(&before) != identity || opened_length != observed_length {
            return Err(file_error(role));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(observed_length)
            .map_err(|_| file_error(role))?;
        bytes.resize(observed_length, 0);
        file.read_exact(&mut bytes).map_err(|_| file_error(role))?;
        let mut trailing = [0; 1];
        if file.read(&mut trailing).map_err(|_| file_error(role))? != 0 {
            return Err(file_error(role));
        }
        let after = file.metadata().map_err(|_| file_error(role))?;
        let after_length =
            validate_file_metadata(&after, length_policy, role, expected_uid, expected_gid)?;
        if FileIdentity::from_metadata(&after) != identity || after_length != observed_length {
            return Err(file_error(role));
        }
        Ok(PinnedFile {
            bytes: Zeroizing::new(bytes.into_boxed_slice()),
            identity,
        })
    }

    fn validate_file_metadata(
        metadata: &Metadata,
        length_policy: FileLengthPolicy,
        role: FileRole,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<usize, DeploymentdProcessError> {
        let length = usize::try_from(metadata.len()).map_err(|_| file_error(role))?;
        let valid_length = match length_policy {
            FileLengthPolicy::Exact(expected) => length == expected,
            FileLengthPolicy::BoundedNonZero(maximum) => length != 0 && length <= maximum,
        };
        let mode = metadata.mode() & 0o7777;
        let valid_mode = match role {
            FileRole::Manifest => mode == 0o600,
            FileRole::PrivateSeed => mode == 0o400,
            FileRole::PublicKey => {
                mode & 0o400 == 0o400
                    && mode & 0o022 == 0
                    && mode & 0o111 == 0
                    && mode & 0o7000 == 0
            }
        };
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.uid() != expected_uid
            || metadata.gid() != expected_gid
            || !valid_length
            || !valid_mode
        {
            return Err(file_error(role));
        }
        Ok(length)
    }

    fn validate_existing_path_chain(path: &Path) -> Result<(), DeploymentdProcessError> {
        let mut current = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir => current.push(component.as_os_str()),
                Component::Normal(value) => {
                    current.push(value);
                    let metadata = fs::symlink_metadata(&current)
                        .map_err(|_| process_error(ProcessErrorKind::Path))?;
                    if metadata.file_type().is_symlink() {
                        return Err(process_error(ProcessErrorKind::Path));
                    }
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(process_error(ProcessErrorKind::Path));
                }
            }
        }
        Ok(())
    }

    fn validate_trusted_ancestors(
        path: &Path,
        service_uid: u32,
    ) -> Result<(), DeploymentdProcessError> {
        let parent = path
            .parent()
            .ok_or_else(|| process_error(ProcessErrorKind::Path))?;
        let mut current = PathBuf::new();
        for component in parent.components() {
            match component {
                Component::RootDir => current.push(component.as_os_str()),
                Component::Normal(value) => current.push(value),
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(process_error(ProcessErrorKind::Path));
                }
            }
            let metadata = fs::symlink_metadata(&current)
                .map_err(|_| process_error(ProcessErrorKind::Path))?;
            let owner = metadata.uid();
            let mode = metadata.mode() & 0o7777;
            let root_sticky = owner == 0 && mode & 0o1000 != 0;
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || (owner != 0 && owner != service_uid)
                || (mode & 0o022 != 0 && !root_sticky)
            {
                return Err(process_error(ProcessErrorKind::Path));
            }
        }
        Ok(())
    }

    const fn file_error(role: FileRole) -> DeploymentdProcessError {
        match role {
            FileRole::Manifest => DeploymentdProcessError::new(ProcessErrorKind::Manifest),
            FileRole::PublicKey | FileRole::PrivateSeed => {
                DeploymentdProcessError::new(ProcessErrorKind::Key)
            }
        }
    }

    const fn process_error(kind: ProcessErrorKind) -> DeploymentdProcessError {
        DeploymentdProcessError::new(kind)
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::OsString;
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        use ed25519_dalek::SigningKey;
        use nix::unistd::{getegid, geteuid};
        use paraegox_kernel::digest::Digest32;
        use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
        use paraegox_kernel::time::BoundedDuration;
        use paraegox_runtime_contracts::reference_control::ValidatedReferenceLifecycleBudgetsV1;
        use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

        use crate::controller_journal::{
            ControllerAuthKeyFingerprint, ControllerJournalError, ControllerJournalState,
            ControllerOperationId, ControllerRequestAuthPin,
            ControllerTenureAuthorityDomainFingerprint, controller_test_manifest,
            tests::direct_active_snapshot,
        };
        use crate::controller_store::{
            ControllerCommitFailpoint, ControllerFilesystemPolicy, ControllerStore,
            create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
            open_controller_directory, publish_initial_controller_snapshot,
        };
        use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
        use crate::planner::StableAllocationSnapshot;
        use crate::tenure_protocol::{
            ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        };

        use super::{
            APPLY_ENTROPY_BYTES, DurableTenureRequest, FileLengthPolicy, FileRole,
            FreshControllerApplyRequestV1, ProcessCommand, ProcessErrorKind, TENURE_ENTROPY_BYTES,
            TenureRequestProfile, build_empty_commit_receipt, build_reference_candidate,
            build_reference_empty_candidate, commit_reference_empty_in_store,
            fresh_apply_request_from_entropy, fresh_tenure_request_from_entropy, parse_arguments,
            parse_nonzero_hex, read_pinned_file, recover_tenure_request,
            select_durable_tenure_request,
        };

        static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(1);

        fn hex(byte: u8, length: usize) -> OsString {
            OsString::from(format!("{byte:02x}").repeat(length))
        }

        fn initialize_arguments() -> Vec<OsString> {
            vec![
                "initialize-reference-v1".into(),
                "/tmp/paraegox-controller".into(),
                "/tmp/runtime.pxcm".into(),
                hex(0x11, 32),
                hex(0x12, 16),
                hex(0x13, 16),
                hex(0x14, 16),
                "/tmp/controller.pub".into(),
                "501".into(),
                "20".into(),
            ]
        }

        fn bootstrap_arguments() -> Vec<OsString> {
            vec![
                "bootstrap-runtime-v1".into(),
                "/tmp/paraegox-controller".into(),
                hex(0x31, 32),
                hex(0x32, 16),
                hex(0x33, 16),
                hex(0x34, 16),
                "/tmp/controller.pub".into(),
                "/tmp/controller.seed".into(),
                "501".into(),
                "20".into(),
                hex(0x35, 16),
                hex(0x36, 16),
                hex(0x37, 16),
                "502".into(),
                "21".into(),
                hex(0x38, 16),
                hex(0x39, 16),
                "/tmp/authority.pub".into(),
                "/tmp/runtime.sock".into(),
                hex(0x3a, 16),
                hex(0x3b, 16),
                "/tmp/runtime-response.pub".into(),
                "503".into(),
                "22".into(),
            ]
        }

        fn tenure_arguments() -> Vec<OsString> {
            vec![
                "acquire-tenure-v1".into(),
                "/tmp/paraegox-controller".into(),
                hex(0x51, 32),
                hex(0x52, 16),
                hex(0x53, 16),
                hex(0x54, 16),
                "/tmp/controller.pub".into(),
                "/tmp/controller.seed".into(),
                "501".into(),
                "20".into(),
                hex(0x55, 16),
                hex(0x56, 16),
                hex(0x57, 16),
                hex(0x58, 16),
                "/tmp/authority.pub".into(),
                "/tmp/authority.sock".into(),
                "502".into(),
                "21".into(),
            ]
        }

        fn migration_arguments() -> Vec<OsString> {
            vec![
                "migrate-controller-journal-v7-to-v8-v1".into(),
                "/tmp/paraegox-controller".into(),
                "/tmp/paraegox-controller-migration-evidence".into(),
                hex(0x61, 32),
                hex(0x62, 32),
                hex(0x63, 32),
            ]
        }

        #[test]
        fn exact_versioned_positional_grammars_accept_only_complete_commands() {
            assert!(matches!(
                parse_arguments(migration_arguments()),
                Ok(ProcessCommand::MigrateControllerJournal(_))
            ));
            let mut missing_migration = migration_arguments();
            missing_migration.pop();
            assert!(parse_arguments(missing_migration).is_err());
            let mut extra_migration = migration_arguments();
            extra_migration.push("unexpected".into());
            assert!(parse_arguments(extra_migration).is_err());
            let mut uppercase_migration = migration_arguments();
            uppercase_migration[5] = OsString::from("AA".repeat(32));
            assert!(parse_arguments(uppercase_migration).is_err());
            let mut unversioned_migration = migration_arguments();
            unversioned_migration[0] = "migrate-controller-journal-v7-to-v8".into();
            assert!(parse_arguments(unversioned_migration).is_err());

            assert!(matches!(
                parse_arguments(initialize_arguments()),
                Ok(ProcessCommand::Initialize(_))
            ));

            let mut commit = vec![
                "commit-reference-loop-v1".into(),
                "/tmp/paraegox-controller".into(),
                hex(0x21, 32),
                hex(0x22, 16),
                hex(0x23, 16),
                hex(0x24, 16),
                "/tmp/controller.pub".into(),
                "501".into(),
                "20".into(),
                hex(0x25, 16),
                hex(0x26, 16),
                "7".into(),
                hex(0x27, 16),
                "10".into(),
                "20".into(),
                "30".into(),
            ];
            assert!(matches!(
                parse_arguments(commit.clone()),
                Ok(ProcessCommand::CommitReferenceLoop(_))
            ));
            commit.push("unexpected".into());
            assert_eq!(
                parse_arguments(commit)
                    .expect_err("extra positional value must fail")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut empty = vec![
                "commit-reference-empty-v1".into(),
                "/tmp/paraegox-controller".into(),
                hex(0x28, 32),
                hex(0x29, 16),
                hex(0x2a, 16),
                hex(0x2b, 16),
                "/tmp/controller.pub".into(),
                "501".into(),
                "20".into(),
                hex(0x2c, 16),
            ];
            assert!(matches!(
                parse_arguments(empty.clone()),
                Ok(ProcessCommand::CommitReferenceEmpty(_))
            ));
            empty.push("unexpected".into());
            assert_eq!(
                parse_arguments(empty)
                    .expect_err("Empty commit must reject extra positional values")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut tenure = tenure_arguments();
            assert!(matches!(
                parse_arguments(tenure.clone()),
                Ok(ProcessCommand::AcquireTenure(_))
            ));
            tenure.push(hex(0x59, 16));
            assert_eq!(
                parse_arguments(tenure)
                    .expect_err("tenure must reject caller operation/nonce entropy")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut missing = initialize_arguments();
            missing.pop();
            assert!(parse_arguments(missing).is_err());
            let mut unknown = initialize_arguments();
            unknown[0] = "initialize".into();
            assert!(parse_arguments(unknown).is_err());

            let mut bootstrap = bootstrap_arguments();
            assert!(matches!(
                parse_arguments(bootstrap.clone()),
                Ok(ProcessCommand::BootstrapRuntime(_))
            ));
            bootstrap.push(hex(0x40, 16));
            assert_eq!(
                parse_arguments(bootstrap)
                    .expect_err("bootstrap must reject caller entropy/extra fields")
                    .kind,
                ProcessErrorKind::Arguments
            );

            let mut apply = bootstrap_arguments();
            apply[0] = "apply-reference-v1".into();
            assert!(matches!(
                parse_arguments(apply.clone()),
                Ok(ProcessCommand::ApplyReference(_))
            ));
            apply.push(hex(0x41, 16));
            assert_eq!(
                parse_arguments(apply)
                    .expect_err("apply must reject caller operation/temporal/nonce entropy")
                    .kind,
                ProcessErrorKind::Arguments
            );
        }

        #[test]
        fn identities_require_exact_nonzero_lower_hex() {
            assert_eq!(parse_nonzero_hex::<16>(&hex(0xab, 16)), Ok([0xab; 16]));
            for rejected in [
                OsString::from("00".repeat(16)),
                OsString::from("AB".repeat(16)),
                OsString::from("ab".repeat(15)),
                OsString::from("ag".repeat(16)),
            ] {
                assert!(parse_nonzero_hex::<16>(&rejected).is_err());
            }
        }

        #[test]
        fn tenure_fresh_material_and_durable_recovery_are_byte_exact() {
            let signer = SigningKey::from_bytes(&[0x61; 32]);
            let profile = TenureRequestProfile {
                scope: DeploymentScopeId::from_bytes([0x62; 16]),
                writer: DeploymentWriterRef::from_bytes([0x63; 16]),
                controller_principal: PrincipalRef::from_bytes([0x64; 16]),
                controller_key: ControllerAcquireKeyRef::from_bytes([0x65; 16]),
                controller_public_key_fingerprint: ControllerPublicKeyFingerprint::for_ed25519_key(
                    &signer.verifying_key().to_bytes(),
                )
                .expect("valid Controller public key fingerprint"),
                max_response_payload_bytes: u32::try_from(
                    MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
                )
                .expect("protocol bound fits u32"),
            };
            let mut entropy = [0x66; TENURE_ENTROPY_BYTES];
            entropy[..16].copy_from_slice(&[0x67; 16]);
            let fresh = fresh_tenure_request_from_entropy(&profile, &signer, &entropy)
                .expect("fresh request");
            assert_eq!(fresh.request().operation_id().as_bytes(), &[0x67; 16]);
            assert_eq!(fresh.request().client_nonce(), &[0x66; 32]);

            let recovered = recover_tenure_request(
                fresh.request().canonical_bytes(),
                &profile,
                &signer.verifying_key(),
            )
            .expect("durable request must recover");
            assert_eq!(recovered.request(), fresh.request());
            assert_eq!(recovered.frame_bytes(), fresh.frame_bytes());

            let mut conflicting_profile = profile;
            conflicting_profile.writer = DeploymentWriterRef::from_bytes([0x68; 16]);
            assert!(
                recover_tenure_request(
                    fresh.request().canonical_bytes(),
                    &conflicting_profile,
                    &signer.verifying_key(),
                )
                .is_err(),
                "durable request facts cannot be rebound on restart"
            );
            assert!(
                fresh_tenure_request_from_entropy(&profile, &signer, &[0; TENURE_ENTROPY_BYTES],)
                    .is_err(),
                "an all-zero operation identity must fail closed"
            );
        }

        #[test]
        fn apply_fresh_material_is_split_exactly_and_rejects_invalid_identities() {
            let mut entropy = [0x81; APPLY_ENTROPY_BYTES];
            entropy[..16].copy_from_slice(&[0x82; 16]);
            entropy[16..32].copy_from_slice(&[0x83; 16]);
            entropy[32..].copy_from_slice(&[0x84; 32]);
            let fresh = fresh_apply_request_from_entropy(&entropy)
                .expect("valid process-owned apply entropy");
            assert_eq!(
                fresh,
                FreshControllerApplyRequestV1::try_new([0x82; 16], [0x83; 16], [0x84; 32],)
                    .expect("expected split")
            );

            assert!(fresh_apply_request_from_entropy(&[0; APPLY_ENTROPY_BYTES]).is_err());
            let mut same_identities = [0x85; APPLY_ENTROPY_BYTES];
            same_identities[16..32].copy_from_slice(&[0x85; 16]);
            assert!(fresh_apply_request_from_entropy(&same_identities).is_err());
        }

        #[test]
        fn tenure_ensure_selection_fences_domain_drift_and_a_newer_other_writer() {
            let writer_a = DeploymentWriterRef::from_bytes([0x71; 16]);
            let writer_b = DeploymentWriterRef::from_bytes([0x72; 16]);
            let domain_a = ControllerTenureAuthorityDomainFingerprint::from_stored(
                Digest32::from_bytes([0x73; 32]),
            );
            let domain_b = ControllerTenureAuthorityDomainFingerprint::from_stored(
                Digest32::from_bytes([0x74; 32]),
            );
            let a1 = DurableTenureRequest {
                canonical_request: b"writer-a-epoch-1",
                writer: writer_a,
                authority_domain_fingerprint: domain_a,
            };
            let b2 = DurableTenureRequest {
                canonical_request: b"writer-b-epoch-2",
                writer: writer_b,
                authority_domain_fingerprint: domain_a,
            };

            assert_eq!(
                select_durable_tenure_request(Some(a1), None, writer_a, domain_a),
                Ok(Some(a1.canonical_request)),
                "the unique unresolved request has priority"
            );
            assert_eq!(
                select_durable_tenure_request(None, Some(a1), writer_a, domain_a),
                Ok(Some(a1.canonical_request)),
                "the matching global latest commit is ensure-once replayable"
            );
            assert_eq!(
                select_durable_tenure_request(None, None, writer_a, domain_a),
                Ok(None),
                "fresh entropy is admitted only with no durable tenure history"
            );
            assert_eq!(
                select_durable_tenure_request(Some(a1), None, writer_a, domain_b)
                    .expect_err("unresolved domain drift must fail closed")
                    .kind,
                ProcessErrorKind::Tenure
            );
            assert_eq!(
                select_durable_tenure_request(None, Some(a1), writer_a, domain_b)
                    .expect_err("committed domain drift must fail closed")
                    .kind,
                ProcessErrorKind::Tenure
            );
            assert_eq!(
                select_durable_tenure_request(None, Some(b2), writer_a, domain_a)
                    .expect_err("B2 globally fences A1; ensure A cannot replay A1")
                    .kind,
                ProcessErrorKind::Tenure
            );
        }

        #[test]
        fn noncanonical_paths_and_numbers_are_rejected_before_execution() {
            for path in [
                "relative/state",
                "/tmp/../state",
                "/tmp//state",
                "/tmp/state/",
            ] {
                let mut arguments = initialize_arguments();
                arguments[1] = path.into();
                assert!(parse_arguments(arguments).is_err(), "accepted {path}");
            }
            for value in ["0", "01", "+1", " 1", "1 "] {
                let mut arguments = initialize_arguments();
                arguments[8] = value.into();
                assert!(parse_arguments(arguments).is_err(), "accepted {value}");
            }
        }

        #[test]
        fn manifest_reads_are_actual_length_bounded_while_public_keys_are_exact() {
            let directory = TempDirectory::new();
            let manifest = directory.write("runtime.pxcm", b"manifest", 0o600);
            let observed = read_pinned_file(
                &manifest,
                FileLengthPolicy::BoundedNonZero(64),
                FileRole::Manifest,
                geteuid().as_raw(),
                getegid().as_raw(),
            )
            .expect("bounded manifest must read its actual bytes");
            assert_eq!(observed.bytes.as_ref(), b"manifest");

            let empty = directory.write("empty.pxcm", b"", 0o600);
            assert!(
                read_pinned_file(
                    &empty,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
            let oversized = directory.write("oversized.pxcm", &[0x11; 65], 0o600);
            assert!(
                read_pinned_file(
                    &oversized,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );

            let public_key = directory.write("controller.pub", &[0x22; 32], 0o600);
            assert_eq!(
                read_pinned_file(
                    &public_key,
                    FileLengthPolicy::Exact(32),
                    FileRole::PublicKey,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .expect("exact public key must read")
                .bytes
                .len(),
                32
            );
            let short_key = directory.write("short.pub", &[0x23; 31], 0o600);
            assert!(
                read_pinned_file(
                    &short_key,
                    FileLengthPolicy::Exact(32),
                    FileRole::PublicKey,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
        }

        #[test]
        fn pinned_reads_reject_symlinks_hardlinks_modes_and_wrong_owners() {
            let directory = TempDirectory::new();
            let key = directory.write("controller.pub", &[0x31; 32], 0o600);
            let hardlink = directory.path.join("controller-hardlink.pub");
            fs::hard_link(&key, &hardlink).expect("hard link fixture");
            assert!(
                read_pinned_file(
                    &key,
                    FileLengthPolicy::Exact(32),
                    FileRole::PublicKey,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
            assert!(
                read_pinned_file(
                    &hardlink,
                    FileLengthPolicy::Exact(32),
                    FileRole::PublicKey,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );

            let target = directory.write("target.pxcm", b"manifest", 0o600);
            let linked = directory.path.join("linked.pxcm");
            symlink(&target, &linked).expect("symlink fixture");
            assert!(
                read_pinned_file(
                    &linked,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
            let unsafe_mode = directory.write("unsafe.pxcm", b"manifest", 0o640);
            assert!(
                read_pinned_file(
                    &unsafe_mode,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw(),
                    getegid().as_raw(),
                )
                .is_err()
            );
            assert!(
                read_pinned_file(
                    &target,
                    FileLengthPolicy::BoundedNonZero(64),
                    FileRole::Manifest,
                    geteuid().as_raw().wrapping_add(1),
                    getegid().as_raw(),
                )
                .is_err()
            );
        }

        #[test]
        fn compiler_planner_candidate_and_controller_commit_are_exactly_idempotent() {
            let target = RuntimeHostId::from_bytes([0x41; 16]);
            let manifest = controller_test_manifest(target);
            let lifecycle = ValidatedReferenceLifecycleBudgetsV1::try_new(
                BoundedDuration::from_nanos(10),
                BoundedDuration::from_nanos(20),
                BoundedDuration::from_nanos(30),
            )
            .expect("lifecycle fixture");
            let candidate =
                build_reference_candidate(&manifest, [0x42; 16], [0x43; 16], 7, lifecycle)
                    .expect("real DeckCompiler -> Planner path must produce a candidate");
            assert_eq!(candidate.content().target(), target);
            assert_eq!(
                candidate.content().manifest_digest().value(),
                manifest.manifest_digest()
            );

            let empty = StableAllocationSnapshot::try_new(target, 0, 0, Vec::new())
                .expect("empty allocation");
            let auth = ControllerRequestAuthPin::try_new(
                ApplyAuthKeyRef::from_bytes([0x44; 16]),
                ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
                1,
                ControllerAuthKeyFingerprint::from_stored(Digest32::from_bytes([0x45; 32])),
                1,
            )
            .expect("auth pin");
            let initial = ControllerJournalState::try_initialize(
                DeploymentScopeId::from_bytes([0x46; 16]),
                DeploymentId::from_bytes([0x47; 16]),
                empty,
                manifest,
                auth,
            )
            .expect("initial state");
            let operation = ControllerOperationId::from_bytes([0x48; 16]);
            let prepared = initial
                .prepare_plan_candidate(operation, &candidate)
                .expect("prepare");
            let committed = prepared
                .commit_plan_candidate(operation, &candidate)
                .expect("commit");
            assert_eq!(committed.current_revision(), 1);
            assert_eq!(
                committed
                    .prepare_plan_candidate(operation, &candidate)
                    .expect("committed prepare retry"),
                committed
            );
            assert_eq!(
                committed
                    .commit_plan_candidate(operation, &candidate)
                    .expect("committed commit retry"),
                committed
            );

            let changed = build_reference_candidate(
                committed.installed_manifest(),
                [0x42; 16],
                [0x43; 16],
                8,
                lifecycle,
            )
            .expect("changed resolved version remains a valid candidate");
            assert_ne!(changed.content_digest(), candidate.content_digest());
            assert_eq!(
                committed.prepare_plan_candidate(operation, &changed),
                Err(ControllerJournalError::OperationConflict)
            );
            assert!(
                committed
                    .prepare_plan_candidate(
                        ControllerOperationId::from_bytes([0x49; 16]),
                        &candidate
                    )
                    .is_err(),
                "a different operation cannot implicitly plan Loop -> Loop"
            );
        }

        #[test]
        fn empty_commit_reopens_prepared_and_committed_snapshots_exactly() {
            let (terminal, _, _) = direct_active_snapshot();
            let operation = ControllerOperationId::from_bytes([0x32; 16]);
            let candidate = build_reference_empty_candidate(terminal.state())
                .expect("the real Active terminal must plan an Empty successor");
            let prepared_state = terminal
                .state()
                .prepare_plan_candidate(operation, &candidate)
                .expect("Empty candidate must prepare");
            let prepared = terminal
                .try_successor(prepared_state)
                .expect("Prepared Empty snapshot must validate");

            let directory = TempDirectory::new();
            install_controller_snapshot(&prepared, &directory);
            let store_id = *prepared.store_instance_id();
            let owner = prepared.owner_identity_fingerprint();
            let scope = prepared.state().scope();
            let plan_lineage = prepared.state().plan_lineage();
            let request_auth = prepared.state().request_auth();

            let mut store = ControllerStore::open_with_policy(
                &directory.path,
                store_id,
                owner,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("Prepared snapshot must reopen");
            let committed = commit_reference_empty_in_store(
                &mut store,
                scope,
                plan_lineage,
                request_auth,
                operation,
            )
            .expect("same operation must finish Prepared -> Committed");
            assert_eq!(
                committed.snapshot_sequence(),
                prepared.snapshot_sequence() + 1
            );
            assert_eq!(committed.state().current_revision(), 2);
            let first_receipt = build_empty_commit_receipt(&committed, operation)
                .expect("committed Empty receipt must encode");
            drop(store);

            let mut reopened = ControllerStore::open_with_policy(
                &directory.path,
                store_id,
                owner,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("Committed snapshot must reopen");
            let replay = commit_reference_empty_in_store(
                &mut reopened,
                scope,
                plan_lineage,
                request_auth,
                operation,
            )
            .expect("same committed operation must replay");
            assert_eq!(replay, committed);
            assert_eq!(
                build_empty_commit_receipt(&replay, operation)
                    .expect("replayed Empty receipt must encode"),
                first_receipt,
                "receipt bytes and digest must remain exact across reopen"
            );

            let different_operation = ControllerOperationId::from_bytes([0x33; 16]);
            assert_eq!(
                commit_reference_empty_in_store(
                    &mut reopened,
                    scope,
                    plan_lineage,
                    request_auth,
                    different_operation,
                )
                .expect_err("a different operation must fail closed")
                .kind,
                ProcessErrorKind::Commit
            );
            assert_eq!(
                reopened.snapshot().expect("store remains readable"),
                &committed,
                "rejected operation must not mutate the open store"
            );
            drop(reopened);

            let reopened_after_rejection = ControllerStore::open_with_policy(
                &directory.path,
                store_id,
                owner,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("store must reopen after a rejected operation");
            assert_eq!(
                reopened_after_rejection
                    .snapshot()
                    .expect("reopened snapshot"),
                &committed,
                "rejected operation must not mutate durable state"
            );
        }

        fn install_controller_snapshot(
            snapshot: &crate::controller_journal::ControllerJournalSnapshot,
            directory: &TempDirectory,
        ) {
            let handle = open_controller_directory(
                &directory.path,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("fixture directory must open");
            ensure_fresh_controller_directory(&handle).expect("fixture directory must be fresh");
            let _initializer_lock = create_and_lock_controller_initializer_lock(&handle)
                .expect("fixture initializer lock");
            let encoded = snapshot.encode().expect("fixture snapshot must encode");
            publish_initial_controller_snapshot(
                &handle,
                &encoded,
                [0xd1; 16],
                ControllerCommitFailpoint::None,
            )
            .expect("fixture snapshot must publish");
        }

        struct TempDirectory {
            path: PathBuf,
        }

        impl TempDirectory {
            fn new() -> Self {
                let unique = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir()
                    .canonicalize()
                    .expect("canonical test temporary root");
                let path = root.join(format!(
                    "paraegox-deploymentd-unit-{}-{unique}",
                    std::process::id()
                ));
                fs::create_dir(&path).expect("create test directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("set test directory mode");
                Self { path }
            }

            fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
                let path = self.path.join(name);
                fs::write(&path, bytes).expect("write fixture");
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                    .expect("set fixture mode");
                path
            }
        }

        impl Drop for TempDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }
    }
}
