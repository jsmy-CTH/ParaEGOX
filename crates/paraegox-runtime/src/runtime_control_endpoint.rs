#![cfg(unix)]

//! Authenticated S7-E/S7-F Runtime bootstrap, query, and PXAR apply endpoint.
//!
//! One identity-bound local channel carries canonical PXBR bootstrap reads,
//! read-only PXQR operation/live queries, and canonical PXAR v5 applies. Apply
//! success is represented exclusively by the canonical PXRT v1 terminal
//! Receipt; no transport ACK or private status byte exists.

use core::{fmt, future::Future, time::Duration};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};

#[cfg(test)]
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
#[cfg(test)]
use nix::unistd::{getegid, geteuid};
use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
    unistd::{Gid, UnlinkatFlags, chown, getpid, unlinkat},
};
#[cfg(test)]
use paraegox_kernel::identity::PrincipalRef;
use paraegox_kernel::{
    digest::Digest32,
    identity::RuntimeHostId,
    time::{ClockDomainRef, ClockGeneration},
};
use paraegox_runtime_contracts::{
    apply::ExpectedActive,
    installation::{
        RuntimeCompiledInstallationFactsV1, RuntimeInstallationError,
        VerifiedRuntimeInstallationV1, VerifiedRuntimeManifestIngressV1,
        verify_immutable_manifest_ingress, verify_pinned_startup,
    },
    provenance::{SourcePlanRevision, TargetSliceDigest},
    reference_control::{
        MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES, MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES,
        MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES, MAX_REFERENCE_QUERY_REQUEST_BYTES,
        MAX_REFERENCE_QUERY_RESPONSE_BYTES, MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES,
        ReferenceApplyRequestV1, ReferenceApplyTerminalReceiptV1, ReferenceAssemblyModeV1,
        ReferenceBootstrapCompatibilityV1, ReferenceBootstrapFactsV1, ReferenceBootstrapRequestV1,
        ReferenceBootstrapResponseAuthClaimV1, ReferenceBootstrapResponseDraftV1,
        ReferenceBootstrapServingIdentityV1, ReferenceBootstrapStateV1, ReferenceChannelBindingV1,
        ReferenceControlError, ReferenceOperationalReasonV1, ReferenceQueryDesiredHeadV1,
        ReferenceQueryDesiredStateV1, ReferenceQueryDurablePhaseV1, ReferenceQueryFactsV1,
        ReferenceQueryLiveFactsV1, ReferenceQueryLiveStateV1, ReferenceQueryOperationLookupV1,
        ReferenceQueryOperationStateV1, ReferenceQueryOwnerStateV1, ReferenceQueryRequestV1,
        ReferenceQueryResponseAuthClaimV1, ReferenceQueryResponseDraftV1,
        ReferenceTargetExecutionPlanV4, reference_local_control_endpoint_identity_digest_v1,
        reference_runtime_peer_credentials_digest_v1, verify_reference_durable_slice_v1,
    },
    wire::ApplyAuthAlgorithm,
};
#[cfg(test)]
use paraegox_runtime_contracts::{provenance::SourceScopeRef, wire::ApplyAuthKeyRef};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

use crate::{
    admission::{ED25519_ALGORITHM, ED25519_ALGORITHM_VERSION},
    runtime_clock::RuntimeClock,
    runtime_control_state::{
        RuntimeControlState, RuntimeControlStateError, RuntimeJournalBootstrapReason,
        RuntimeJournalBootstrapState, RuntimeReferenceApplyPreflight,
        runtime_reference_apply::{
            RuntimeReferenceApplyClock, RuntimeReferenceApplyClockError, RuntimeReferenceApplyCore,
            RuntimeReferenceApplyError, RuntimeReferenceApplyOutcome, RuntimeReferenceApplySigner,
            RuntimeReferenceApplyStore, RuntimeReferenceMaterializationOwner,
            RuntimeRestartReassemblyError, RuntimeStoredReferenceApplyReceipt,
            run_runtime_restart_reassembly,
        },
        runtime_reference_owner::RuntimeFixedReferenceMaterializationOwner,
    },
    runtime_journal::{
        DesiredHeadKind, ExpectedActiveCas, LiveMaterialization, PreparedPhase,
        RuntimeDeadlineObservation, RuntimeJournalSnapshot, StorePinnedBuildIdentity,
    },
    runtime_provisioning::{
        CONTROL_SOCKET_DIRECTORY_MODE, CONTROL_SOCKET_MODE, RuntimeProvisioningError,
        RuntimeProvisioningV1, validate_canonical_absolute_path,
    },
    runtime_store::{RuntimeStore, RuntimeStoreError, RuntimeStoreOpenError},
};

#[cfg(test)]
use crate::runtime_journal::ResourcePhase;

const ED25519_SIGNATURE_BYTES: usize = 64;
const CONTROL_FRAME_HEADER_BYTES: usize = 4;
const BOOTSTRAP_REQUEST_MAGIC: &[u8; 4] = b"PXBR";
const QUERY_REQUEST_MAGIC: &[u8; 4] = b"PXQR";
const APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const MODE_MASK: u32 = 0o7777;
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONTROL_REQUEST_BYTES: usize = maximum_three(
    MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES,
    MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES,
    MAX_REFERENCE_QUERY_REQUEST_BYTES,
);
const MAX_CONTROL_RESPONSE_BYTES: usize = maximum_three(
    MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES,
    MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES,
    MAX_REFERENCE_QUERY_RESPONSE_BYTES,
);

const fn maximum_three(first: usize, second: usize, third: usize) -> usize {
    let pair = if first > second { first } else { second };
    if pair > third { pair } else { third }
}

fn validate_snapshot_pins(
    provisioning: &RuntimeProvisioningV1,
    snapshot: &RuntimeJournalSnapshot,
) -> Result<(), RuntimeBootstrapEndpointError> {
    provisioning.validate_runtime_credentials()?;
    let state = snapshot.state();
    if snapshot.owner_target_fingerprint() != &provisioning.owner_target_fingerprint()
        || state.host.admission_policy_fingerprint != provisioning.admission_policy_fingerprint()
        || state.host.controller_key_fingerprint != provisioning.controller_key_fingerprint()
        || state.host.channel_policy_fingerprint != provisioning.channel_policy_fingerprint()
    {
        return Err(RuntimeBootstrapEndpointError::ProvisioningPinMismatch);
    }
    Ok(())
}

fn authenticate_request(
    provisioning: &RuntimeProvisioningV1,
    request: &ReferenceBootstrapRequestV1,
) -> Result<(), RuntimeBootstrapRequestError> {
    let claim = request.authentication().claim();
    if request.target() != provisioning.target()
        || request.source_scope() != provisioning.source_scope()
        || claim.principal() != provisioning.controller_principal()
        || claim.key() != provisioning.controller_request_key_ref()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(RuntimeBootstrapRequestError::Unauthorized);
    }
    let signature = parse_signature(request.authentication().signature())?;
    let transcript = request
        .signing_transcript()
        .map_err(|_| RuntimeBootstrapRequestError::InvalidCanonicalRequest)?;
    provisioning
        .controller_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| RuntimeBootstrapRequestError::InvalidSignature)
}

fn authenticate_query_request(
    provisioning: &RuntimeProvisioningV1,
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceQueryRequestV1,
) -> Result<(), RuntimeQueryRequestError> {
    let claim = request.authentication().claim();
    if request.target() != provisioning.target()
        || request.source_scope() != provisioning.source_scope()
        || claim.principal() != provisioning.controller_principal()
        || claim.key() != provisioning.controller_request_key_ref()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(RuntimeQueryRequestError::Unauthorized);
    }
    request
        .validate_expected_store(*snapshot.store_instance_id())
        .map_err(|_| RuntimeQueryRequestError::StoreMismatch)?;
    let signature = parse_query_signature(request.authentication().signature())?;
    let transcript = request
        .signing_transcript()
        .map_err(|_| RuntimeQueryRequestError::InvalidCanonicalRequest)?;
    provisioning
        .controller_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| RuntimeQueryRequestError::InvalidSignature)
}

fn parse_signature(signature: &[u8]) -> Result<Signature, RuntimeBootstrapRequestError> {
    let bytes: &[u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| RuntimeBootstrapRequestError::InvalidSignature)?;
    Ok(Signature::from_bytes(bytes))
}

fn parse_query_signature(signature: &[u8]) -> Result<Signature, RuntimeQueryRequestError> {
    let bytes: &[u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| RuntimeQueryRequestError::InvalidSignature)?;
    Ok(Signature::from_bytes(bytes))
}

/// Store seam used to prove startup invalidation is durable before binding.
trait RuntimeBootstrapStore {
    fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeBootstrapEndpointError>;

    fn commit(&mut self, next: RuntimeJournalSnapshot)
    -> Result<(), RuntimeBootstrapEndpointError>;
}

impl RuntimeBootstrapStore for RuntimeStore {
    fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeBootstrapEndpointError> {
        self.snapshot().map_err(Into::into)
    }

    fn commit(
        &mut self,
        next: RuntimeJournalSnapshot,
    ) -> Result<(), RuntimeBootstrapEndpointError> {
        self.commit(next).map_err(Into::into)
    }
}

/// Service capability that exists only after strict startup verification and
/// the startup-invalidation snapshot commit have both succeeded.
struct StartedRuntimeBootstrapService<Store> {
    store: Store,
    #[cfg(test)]
    state: RuntimeControlState,
    clock: RuntimeClock,
    owner: RuntimeFixedReferenceMaterializationOwner,
    signer: RuntimeReferenceApplySigner,
    compiled: RuntimeCompiledInstallationFactsV1,
    compatibility: ReferenceBootstrapCompatibilityV1,
    provisioning: RuntimeProvisioningV1,
}

impl<Store> StartedRuntimeBootstrapService<Store>
where
    Store: RuntimeBootstrapStore + RuntimeReferenceApplyStore,
{
    fn try_start(
        mut store: Store,
        compiled: RuntimeCompiledInstallationFactsV1,
        provisioning: RuntimeProvisioningV1,
    ) -> Result<Self, RuntimeBootstrapEndpointError> {
        let previous = store.snapshot()?.clone();
        let installation = verify_startup_installation(&previous, provisioning.target(), compiled)?;
        validate_snapshot_pins(&provisioning, &previous)?;
        let manifest = installation.immutable_manifest_ingress()?;
        validate_startup_durable_control_state(&previous, &manifest, compiled, &provisioning)?;
        let compatibility = ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            &installation,
            compiled,
            previous.state().host.admission_policy_fingerprint,
        )?;
        let state = RuntimeControlState::try_start(&previous)?;
        let active_execution = startup_active_execution(&previous, &manifest, compiled)?;

        // Startup invalidation is the first durable boundary. Reassembly and
        // every exact-zero/quarantine successor below also finish before this
        // capability can be converted into a listener.
        store.commit(state.snapshot().clone())?;
        let journal = state.bootstrap_facts()?;
        let generation = ClockGeneration::try_new(journal.clock_generation())
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let clock = RuntimeClock::new(
            ClockDomainRef::from_bytes(journal.clock_domain()),
            generation,
            1,
        );
        let owner =
            RuntimeFixedReferenceMaterializationOwner::try_new(compiled, clock, state.snapshot())
                .map_err(|error| {
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Owner(error))
            })?;
        let signer = RuntimeReferenceApplySigner::try_new(
            provisioning.response_signer().clone(),
            provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?,
            ED25519_ALGORITHM_VERSION,
        )
        .map_err(RuntimeBootstrapEndpointError::Apply)?;
        let parts = run_runtime_restart_reassembly(
            store,
            state,
            RuntimeEndpointApplyClock { clock },
            owner,
            &signer,
            active_execution.as_ref(),
        )?;
        let (store, state, owner) = (parts.store, parts.state, parts.owner);
        Ok(Self {
            store,
            #[cfg(test)]
            state,
            clock,
            owner,
            signer,
            compiled,
            compatibility,
            provisioning,
        })
    }

    #[cfg(test)]
    fn bootstrap_core(
        &self,
        channel: ReferenceChannelBindingV1,
    ) -> Result<RuntimeBootstrapCore<'_>, RuntimeBootstrapEndpointError> {
        runtime_bootstrap_core(
            &self.state,
            &self.compatibility,
            &self.provisioning,
            channel,
        )
    }
}

fn runtime_bootstrap_core<'a>(
    state: &RuntimeControlState,
    compatibility: &ReferenceBootstrapCompatibilityV1,
    provisioning: &'a RuntimeProvisioningV1,
    channel: ReferenceChannelBindingV1,
) -> Result<RuntimeBootstrapCore<'a>, RuntimeBootstrapEndpointError> {
    let journal = state.bootstrap_facts()?;
    let serving = ReferenceBootstrapServingIdentityV1::try_new(
        provisioning.target(),
        journal.store_instance_id(),
        journal.snapshot_sequence(),
        journal.runtime_host_epoch(),
        ClockDomainRef::from_bytes(journal.clock_domain()),
        ClockGeneration::try_new(journal.clock_generation())
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?,
    )?;
    let facts = ReferenceBootstrapFactsV1::try_new(
        serving,
        compatibility,
        map_bootstrap_state(journal.readiness()),
        journal.reason().map(map_bootstrap_reason),
    )?;
    Ok(RuntimeBootstrapCore {
        facts,
        channel,
        provisioning,
    })
}

#[derive(Clone, Copy, Debug)]
struct RuntimeEndpointApplyClock {
    clock: RuntimeClock,
}

impl RuntimeReferenceApplyClock for RuntimeEndpointApplyClock {
    fn observe(
        &mut self,
        expected_clock_generation: u64,
    ) -> Result<RuntimeDeadlineObservation, RuntimeReferenceApplyClockError> {
        if self.clock.generation().value() != expected_clock_generation {
            return Err(RuntimeReferenceApplyClockError::Unavailable);
        }
        let reading = self
            .clock
            .reading()
            .map_err(|_| RuntimeReferenceApplyClockError::Unavailable)?;
        let observed_at_nanos = reading.now().value();
        if observed_at_nanos == 0 {
            return Err(RuntimeReferenceApplyClockError::Unavailable);
        }
        Ok(RuntimeDeadlineObservation {
            clock_generation: reading.generation().value(),
            observed_at_nanos,
        })
    }
}

struct RuntimeControlService<Store, Owner = RuntimeFixedReferenceMaterializationOwner> {
    apply: RuntimeReferenceApplyCore<Store, RuntimeEndpointApplyClock, Owner>,
    clock: RuntimeClock,
    compiled: RuntimeCompiledInstallationFactsV1,
    compatibility: ReferenceBootstrapCompatibilityV1,
    provisioning: RuntimeProvisioningV1,
    channel: ReferenceChannelBindingV1,
}

impl<Store, Owner> RuntimeControlService<Store, Owner>
where
    Store: RuntimeReferenceApplyStore,
    Owner: RuntimeReferenceMaterializationOwner,
{
    fn handle_request(
        &mut self,
        frame: &[u8],
        live_channel: ReferenceChannelBindingV1,
    ) -> Result<Option<Box<[u8]>>, RuntimeControlRequestError> {
        if live_channel != self.channel || frame.len() < 4 {
            return Err(RuntimeControlRequestError::Rejected);
        }
        if frame.starts_with(BOOTSTRAP_REQUEST_MAGIC) {
            self.handle_bootstrap(frame).map(Some)
        } else if frame.starts_with(QUERY_REQUEST_MAGIC) {
            self.handle_query(frame).map(Some)
        } else if frame.starts_with(APPLY_REQUEST_MAGIC) {
            self.handle_apply(frame)
        } else {
            Err(RuntimeControlRequestError::Rejected)
        }
    }

    fn handle_bootstrap(&self, frame: &[u8]) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        let state = RuntimeControlState::try_from_started_snapshot(self.apply.snapshot()).map_err(
            |error| {
                RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(
                    error,
                ))
            },
        )?;
        let core = runtime_bootstrap_core(
            &state,
            &self.compatibility,
            &self.provisioning,
            self.channel,
        )
        .map_err(RuntimeControlRequestError::Internal)?;
        core.handle_request(frame).map_err(|error| match error {
            RuntimeBootstrapRequestError::InternalContract => RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::InvalidStartedState,
            ),
            _ => RuntimeControlRequestError::Rejected,
        })
    }

    fn handle_query(&self, frame: &[u8]) -> Result<Box<[u8]>, RuntimeControlRequestError> {
        if frame.is_empty() || frame.len() > MAX_REFERENCE_QUERY_REQUEST_BYTES {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = ReferenceQueryRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        validate_snapshot_pins(&self.provisioning, self.apply.snapshot())
            .map_err(RuntimeControlRequestError::Internal)?;
        RuntimeControlState::try_from_started_snapshot(self.apply.snapshot()).map_err(|error| {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
        })?;
        authenticate_query_request(&self.provisioning, self.apply.snapshot(), &request)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        let facts = runtime_query_facts(
            self.apply.snapshot(),
            &self.provisioning,
            self.clock,
            &request,
        )
        .map_err(RuntimeControlRequestError::Internal)?;
        let auth_claim = ReferenceQueryResponseAuthClaimV1::try_new(
            self.channel,
            self.provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM).map_err(|_| {
                RuntimeControlRequestError::Internal(
                    RuntimeBootstrapEndpointError::InvalidStartedState,
                )
            })?,
            ED25519_ALGORITHM_VERSION,
        )
        .map_err(|_| {
            RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidStartedState)
        })?;
        let draft =
            ReferenceQueryResponseDraftV1::try_new(&request, facts, self.channel, auth_claim)
                .map_err(|_| {
                    RuntimeControlRequestError::Internal(
                        RuntimeBootstrapEndpointError::InvalidStartedState,
                    )
                })?;
        let signature = self
            .provisioning
            .response_signer()
            .sign(
                draft
                    .signing_transcript()
                    .map_err(|_| {
                        RuntimeControlRequestError::Internal(
                            RuntimeBootstrapEndpointError::InvalidStartedState,
                        )
                    })?
                    .as_bytes(),
            )
            .to_bytes();
        let response = draft
            .finalize(&signature)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        let wire = response.canonical_wire();
        if wire.is_empty()
            || wire.len() > MAX_REFERENCE_QUERY_RESPONSE_BYTES
            || wire.len() > request.max_response_bytes() as usize
        {
            return Err(RuntimeControlRequestError::Rejected);
        }
        Ok(wire.into())
    }

    fn handle_apply(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<Box<[u8]>>, RuntimeControlRequestError> {
        if frame.is_empty() || frame.len() > MAX_REFERENCE_RUNTIME_APPLY_REQUEST_BYTES {
            return Err(RuntimeControlRequestError::Rejected);
        }
        let request = ReferenceApplyRequestV1::decode(frame)
            .map_err(|_| RuntimeControlRequestError::Rejected)?;
        reference_apply_base_validation(
            &self.provisioning,
            self.compiled,
            self.apply.snapshot(),
            self.channel,
            &request,
        )?;
        match reference_terminal_match(self.apply.snapshot(), &request) {
            ReferenceTerminalMatch::Exact => {
                self.provisioning
                    .admission_policy()
                    .authenticate_reference_apply_request(&request)
                    .map_err(|_| RuntimeControlRequestError::Rejected)?;
                let replay = self
                    .apply
                    .try_exact_terminal_replay(&request)
                    .map_err(map_apply_error)?
                    .ok_or({
                        RuntimeControlRequestError::Internal(
                            RuntimeBootstrapEndpointError::InvalidStartedState,
                        )
                    })?;
                return terminal_response_wire(&replay).map(Some);
            }
            ReferenceTerminalMatch::Conflict => {
                return Err(RuntimeControlRequestError::Rejected);
            }
            ReferenceTerminalMatch::Absent => {}
        }
        let preflight = reference_apply_fresh_preflight(
            &self.provisioning,
            self.apply.snapshot(),
            self.clock,
            self.channel,
            &request,
        )?;
        let outcome = self
            .apply
            .try_apply(&request, preflight)
            .map_err(map_apply_error)?;
        match outcome {
            RuntimeReferenceApplyOutcome::Terminal(stored) => {
                terminal_response_wire(&stored).map(Some)
            }
            RuntimeReferenceApplyOutcome::TenureOnlyDurable => Ok(None),
        }
    }
}

fn runtime_query_facts(
    snapshot: &RuntimeJournalSnapshot,
    provisioning: &RuntimeProvisioningV1,
    clock: RuntimeClock,
    request: &ReferenceQueryRequestV1,
) -> Result<ReferenceQueryFactsV1, RuntimeBootstrapEndpointError> {
    let control = RuntimeControlState::try_from_started_snapshot(snapshot)?;
    let bootstrap = control.bootstrap_facts()?;
    let serving = ReferenceBootstrapServingIdentityV1::try_new(
        provisioning.target(),
        bootstrap.store_instance_id(),
        bootstrap.snapshot_sequence(),
        bootstrap.runtime_host_epoch(),
        ClockDomainRef::from_bytes(bootstrap.clock_domain()),
        ClockGeneration::try_new(bootstrap.clock_generation())
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?,
    )?;
    let reading = clock
        .reading()
        .map_err(|_| RuntimeBootstrapEndpointError::RuntimeClock)?;
    if reading.generation().value() != bootstrap.clock_generation() {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }

    let owner = query_owner_projection(bootstrap.readiness(), bootstrap.reason());
    let lookup = if let Some(reason) = owner.indeterminate_reason {
        ReferenceQueryOperationLookupV1::Indeterminate { reason }
    } else {
        query_operation_lookup(snapshot, request)?
    };
    let operation = ReferenceQueryOperationStateV1::try_new(owner.state, owner.reason, lookup)?;
    let desired = query_desired_projection(snapshot, request)?;
    let live = query_live_projection(snapshot, reading.now().value())?;
    ReferenceQueryFactsV1::try_new(serving, operation, desired, live).map_err(Into::into)
}

#[derive(Clone, Copy)]
struct QueryOwnerProjection {
    state: ReferenceQueryOwnerStateV1,
    reason: Option<ReferenceOperationalReasonV1>,
    indeterminate_reason: Option<ReferenceOperationalReasonV1>,
}

fn query_owner_projection(
    readiness: RuntimeJournalBootstrapState,
    reason: Option<RuntimeJournalBootstrapReason>,
) -> QueryOwnerProjection {
    match (readiness, reason) {
        (RuntimeJournalBootstrapState::ReadyForApply, None) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::Operational,
            reason: None,
            indeterminate_reason: None,
        },
        (
            RuntimeJournalBootstrapState::NotReadyRecovering,
            Some(RuntimeJournalBootstrapReason::Recovering),
        ) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::ApplyDisabled,
            reason: Some(ReferenceOperationalReasonV1::Recovering),
            indeterminate_reason: None,
        },
        (
            RuntimeJournalBootstrapState::RecoveryFailedNotReady,
            Some(RuntimeJournalBootstrapReason::RecoveryFailed),
        ) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::ApplyDisabled,
            reason: Some(ReferenceOperationalReasonV1::RecoveryFailed),
            indeterminate_reason: None,
        },
        (
            RuntimeJournalBootstrapState::NotReadyBusy,
            Some(RuntimeJournalBootstrapReason::RuntimeBusy),
        ) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::ApplyDisabled,
            reason: Some(ReferenceOperationalReasonV1::RuntimeBusy),
            indeterminate_reason: None,
        },
        (
            RuntimeJournalBootstrapState::ValidatedOperationalQuarantine,
            Some(RuntimeJournalBootstrapReason::OwnershipUncertain),
        ) => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::OwnershipUncertain,
            reason: Some(ReferenceOperationalReasonV1::OwnershipUncertain),
            indeterminate_reason: Some(ReferenceOperationalReasonV1::OwnershipUncertain),
        },
        _ => QueryOwnerProjection {
            state: ReferenceQueryOwnerStateV1::OwnershipUncertain,
            reason: Some(ReferenceOperationalReasonV1::HistoryUnavailable),
            indeterminate_reason: Some(ReferenceOperationalReasonV1::HistoryUnavailable),
        },
    }
}

fn query_operation_lookup(
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceQueryRequestV1,
) -> Result<ReferenceQueryOperationLookupV1, RuntimeBootstrapEndpointError> {
    let requested_scope = *request.source_scope().as_bytes();
    let requested_operation = *request.requested_operation_id().as_bytes();
    if let Some(prepared) = snapshot.state().prepared.as_ref().filter(|prepared| {
        prepared.source_scope == requested_scope && prepared.operation_id == requested_operation
    }) {
        return Ok(query_known_or_conflict(
            request.expected_request_digest(),
            prepared.request.digest,
            query_prepared_phase(prepared.phase, prepared.retiring.is_some()),
            None,
        ));
    }
    if let Some(terminal) = snapshot
        .state()
        .terminal_operations
        .iter()
        .find(|terminal| {
            terminal.source_scope == requested_scope && terminal.operation_id == requested_operation
        })
    {
        let receipt =
            ReferenceApplyTerminalReceiptV1::decode(&terminal.canonical_response.canonical_bytes)
                .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        return Ok(query_known_or_conflict(
            request.expected_request_digest(),
            terminal.request_digest,
            ReferenceQueryDurablePhaseV1::Terminal,
            Some(receipt.facts().terminal_result_ref()),
        ));
    }
    Ok(ReferenceQueryOperationLookupV1::Unknown)
}

fn query_known_or_conflict(
    expected: Option<Digest32>,
    existing: Digest32,
    durable_phase: ReferenceQueryDurablePhaseV1,
    terminal_result: Option<
        paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1,
    >,
) -> ReferenceQueryOperationLookupV1 {
    if expected.is_some_and(|expected| expected != existing) {
        ReferenceQueryOperationLookupV1::Conflict {
            existing_request_digest: existing,
        }
    } else {
        ReferenceQueryOperationLookupV1::Known {
            request_digest: existing,
            durable_phase,
            terminal_result,
        }
    }
}

const fn query_prepared_phase(
    phase: PreparedPhase,
    is_head_first_retire: bool,
) -> ReferenceQueryDurablePhaseV1 {
    match phase {
        PreparedPhase::PreparedNoEffects
        | PreparedPhase::SupersededBeforeEffects
        | PreparedPhase::StartupExpiredNoEffects => ReferenceQueryDurablePhaseV1::PreparedNoEffects,
        PreparedPhase::FirstActionIntent => ReferenceQueryDurablePhaseV1::FirstActionIntent,
        PreparedPhase::SupersededReconcileRequired | PreparedPhase::StartupReconcileRequired => {
            if is_head_first_retire {
                ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld
            } else {
                ReferenceQueryDurablePhaseV1::FirstActionIntent
            }
        }
        PreparedPhase::HeadCommittedRetiringOld => {
            ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld
        }
    }
}

fn query_desired_projection(
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceQueryRequestV1,
) -> Result<ReferenceQueryDesiredStateV1, RuntimeBootstrapEndpointError> {
    let requested_scope = *request.source_scope().as_bytes();
    let high_water = match snapshot.state().source_revision_high_water {
        Some(high_water) if high_water.source_scope == requested_scope => high_water.revision,
        Some(_) => return Err(RuntimeBootstrapEndpointError::InvalidStartedState),
        None => 0,
    };
    let head = match snapshot.state().active_desired.as_ref() {
        Some(active) if active.source_scope != requested_scope => {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        Some(active) => {
            let facts = {
                let source_revision = SourcePlanRevision::new(active.source_revision);
                let target_slice_digest = active.slice_provenance.target_slice_digest;
                let manifest_digest = active.manifest_digest;
                (source_revision, target_slice_digest, manifest_digest)
            };
            match active.kind {
                DesiredHeadKind::OneSourceLoop => ReferenceQueryDesiredHeadV1::OneSourceLoop {
                    source_revision: facts.0,
                    target_slice_digest: facts.1,
                    manifest_digest: facts.2,
                },
                DesiredHeadKind::EmptyDeactivate => ReferenceQueryDesiredHeadV1::EmptyDeactivate {
                    source_revision: facts.0,
                    target_slice_digest: facts.1,
                    manifest_digest: facts.2,
                },
            }
        }
        None => ReferenceQueryDesiredHeadV1::None,
    };
    ReferenceQueryDesiredStateV1::try_new(head, SourcePlanRevision::new(high_water))
        .map_err(Into::into)
}

fn query_live_projection(
    snapshot: &RuntimeJournalSnapshot,
    measured_at: u64,
) -> Result<ReferenceQueryLiveFactsV1, RuntimeBootstrapEndpointError> {
    let state = snapshot.state();
    let census = snapshot
        .resource_census_digest()
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    let nonterminal_generation = state
        .owned_resources
        .iter()
        .filter(|resource| !resource.phase.is_terminal())
        .map(|resource| resource.generation)
        .max()
        .unwrap_or(0);
    let (live, generation, recorded_census) = match state.live_materialization {
        LiveMaterialization::None => (
            if state.prepared.is_some() {
                ReferenceQueryLiveStateV1::NotReady
            } else {
                ReferenceQueryLiveStateV1::ExactZero
            },
            0,
            census,
        ),
        LiveMaterialization::StartupInvalidated {
            recovery_eligibility,
            resource_census_digest,
            ..
        } => match recovery_eligibility {
            crate::runtime_journal::StartupRecoveryEligibility::NoActiveHead
            | crate::runtime_journal::StartupRecoveryEligibility::CanonicalEmptyExactZero => (
                ReferenceQueryLiveStateV1::ExactZero,
                0,
                resource_census_digest,
            ),
            crate::runtime_journal::StartupRecoveryEligibility::EligibleOneSourceLoop => (
                ReferenceQueryLiveStateV1::Recovering,
                nonterminal_generation,
                resource_census_digest,
            ),
            crate::runtime_journal::StartupRecoveryEligibility::RecoveryFailureLatched => (
                ReferenceQueryLiveStateV1::RecoveryFailedNotReady,
                0,
                resource_census_digest,
            ),
            crate::runtime_journal::StartupRecoveryEligibility::ReconcileRequired => (
                if nonterminal_generation == 0 {
                    ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
                } else {
                    ReferenceQueryLiveStateV1::Uncertain
                },
                nonterminal_generation,
                resource_census_digest,
            ),
        },
        LiveMaterialization::Recovering {
            resource_generation,
            resource_census_digest,
            ..
        } => (
            ReferenceQueryLiveStateV1::Recovering,
            resource_generation,
            resource_census_digest,
        ),
        LiveMaterialization::LiveReady {
            resource_generation,
            resource_census_digest,
            ..
        } => (
            ReferenceQueryLiveStateV1::LiveReady,
            resource_generation,
            resource_census_digest,
        ),
        LiveMaterialization::RecoveryFailedNotReady {
            resource_census_digest,
            ..
        } => (
            ReferenceQueryLiveStateV1::RecoveryFailedNotReady,
            0,
            resource_census_digest,
        ),
        LiveMaterialization::Draining {
            retiring_generation,
            resource_census_digest,
            ..
        } => (
            ReferenceQueryLiveStateV1::Draining,
            retiring_generation,
            resource_census_digest,
        ),
        LiveMaterialization::ExactZero { census_digest, .. } => {
            (ReferenceQueryLiveStateV1::ExactZero, 0, census_digest)
        }
        LiveMaterialization::Quarantined {
            resource_census_digest,
            ..
        } => (
            if nonterminal_generation == 0 {
                ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
            } else {
                ReferenceQueryLiveStateV1::Uncertain
            },
            nonterminal_generation,
            resource_census_digest,
        ),
    };
    if recorded_census != census {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }
    ReferenceQueryLiveFactsV1::try_new(live, generation, measured_at, census).map_err(Into::into)
}

fn terminal_response_wire(
    stored: &RuntimeStoredReferenceApplyReceipt,
) -> Result<Box<[u8]>, RuntimeControlRequestError> {
    let wire = stored.canonical_wire();
    if wire.is_empty() || wire.len() > MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    let strict = ReferenceApplyTerminalReceiptV1::decode(wire).map_err(|_| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::InvalidStartedState)
    })?;
    if strict.canonical_wire() != wire {
        return Err(RuntimeControlRequestError::Internal(
            RuntimeBootstrapEndpointError::InvalidStartedState,
        ));
    }
    Ok(wire.into())
}

fn reference_apply_base_validation(
    provisioning: &RuntimeProvisioningV1,
    compiled: RuntimeCompiledInstallationFactsV1,
    snapshot: &RuntimeJournalSnapshot,
    channel: ReferenceChannelBindingV1,
    request: &ReferenceApplyRequestV1,
) -> Result<(), RuntimeControlRequestError> {
    validate_snapshot_pins(provisioning, snapshot).map_err(RuntimeControlRequestError::Internal)?;
    RuntimeControlState::try_from_started_snapshot(snapshot).map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
    })?;
    if request.target() != provisioning.target()
        || request.provenance().source_scope() != provisioning.source_scope()
        || request.authentication().claim().principal() != provisioning.controller_principal()
        || request.authentication().claim().key() != provisioning.controller_request_key_ref()
        || channel.target() != provisioning.target()
        || channel.runtime_peer() != provisioning.runtime_principal()
    {
        return Err(RuntimeControlRequestError::Rejected);
    }
    request
        .validate_expected_store(*snapshot.store_instance_id())
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    let manifest = verify_immutable_manifest_ingress(
        &snapshot.state().host.singleton_manifest.canonical_bytes,
        snapshot.state().host.singleton_manifest.digest,
    )
    .map_err(|_| RuntimeControlRequestError::Rejected)?;
    request
        .validate_manifest(&manifest)
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    request
        .target_execution()
        .validate_compiled_fixture(compiled)
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    Ok(())
}

fn reference_apply_fresh_preflight(
    provisioning: &RuntimeProvisioningV1,
    snapshot: &RuntimeJournalSnapshot,
    clock: RuntimeClock,
    channel: ReferenceChannelBindingV1,
    request: &ReferenceApplyRequestV1,
) -> Result<RuntimeReferenceApplyPreflight, RuntimeControlRequestError> {
    let state = RuntimeControlState::try_from_started_snapshot(snapshot).map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
    })?;
    let bootstrap = state.bootstrap_facts().map_err(|error| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::ControlState(error))
    })?;
    if bootstrap.readiness() != RuntimeJournalBootstrapState::ReadyForApply {
        return Err(RuntimeControlRequestError::Rejected);
    }
    if !reference_apply_cas_matches(snapshot, request) {
        return Err(RuntimeControlRequestError::Rejected);
    }
    let reading = clock.reading().map_err(|_| {
        RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::RuntimeClock)
    })?;
    let verified = provisioning
        .admission_policy()
        .verify_reference_apply_request(request, reading)
        .map_err(|_| RuntimeControlRequestError::Rejected)?;
    let identities = verified.identities();
    Ok(RuntimeReferenceApplyPreflight {
        local_target: provisioning.target(),
        owner_target_fingerprint: *snapshot.owner_target_fingerprint(),
        admission_policy_fingerprint: snapshot.state().host.admission_policy_fingerprint,
        channel_policy_fingerprint: snapshot.state().host.channel_policy_fingerprint,
        controller_key_fingerprint: snapshot.state().host.controller_key_fingerprint,
        tenure_nonce_identity: identities.tenure_nonce_identity(),
        request_nonce_identity: identities.request_nonce_identity(),
        temporal_lineage_digest: identities.temporal_lineage_digest(),
        admitted_at_nanos: verified.admitted_at_nanos(),
        response_channel: channel,
    })
}

fn reference_apply_cas_matches(
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceApplyRequestV1,
) -> bool {
    let expected = request.control_commitment().control().expected_active();
    match (expected, snapshot.state().active_desired.as_ref()) {
        (ExpectedActive::None, None) => true,
        (ExpectedActive::Exact(expected), Some(active)) => {
            expected == TargetSliceDigest::new(active.slice.digest)
        }
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceTerminalMatch {
    Absent,
    Exact,
    Conflict,
}

fn reference_terminal_match(
    snapshot: &RuntimeJournalSnapshot,
    request: &ReferenceApplyRequestV1,
) -> ReferenceTerminalMatch {
    let scope = request.provenance().source_scope();
    let operation = request.control_commitment().control().operation_id();
    let Some(terminal) = snapshot
        .state()
        .terminal_operations
        .iter()
        .find(|terminal| {
            terminal.source_scope == *scope.as_bytes()
                && terminal.operation_id == *operation.as_bytes()
        })
    else {
        return ReferenceTerminalMatch::Absent;
    };
    if terminal.request_digest == request.envelope_request_digest() {
        ReferenceTerminalMatch::Exact
    } else {
        ReferenceTerminalMatch::Conflict
    }
}

fn map_apply_error(error: RuntimeReferenceApplyError) -> RuntimeControlRequestError {
    match error {
        RuntimeReferenceApplyError::OperationConflict
        | RuntimeReferenceApplyError::State(RuntimeControlStateError::PreflightRejected) => {
            RuntimeControlRequestError::Rejected
        }
        other => RuntimeControlRequestError::Internal(RuntimeBootstrapEndpointError::Apply(other)),
    }
}

#[derive(Debug)]
enum RuntimeControlRequestError {
    Rejected,
    Internal(RuntimeBootstrapEndpointError),
}

impl<Store> StartedRuntimeBootstrapService<Store>
where
    Store: RuntimeBootstrapStore + RuntimeReferenceApplyStore,
{
    fn into_control_service(
        self,
        channel: ReferenceChannelBindingV1,
    ) -> Result<RuntimeControlService<Store>, RuntimeBootstrapEndpointError> {
        let clock = self.clock;
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            self.store,
            RuntimeEndpointApplyClock { clock },
            self.owner,
            self.signer,
            channel,
        )
        .map_err(RuntimeBootstrapEndpointError::Apply)?;
        Ok(RuntimeControlService {
            apply,
            clock,
            compiled: self.compiled,
            compatibility: self.compatibility,
            provisioning: self.provisioning,
            channel,
        })
    }
}

/// Runs the production Runtime bootstrap process from an already provisioned
/// store identity and sealed key/peer policy.
///
/// Store open, strict pinned-build validation and the durable startup
/// invalidation commit all complete before the socket path can be created.
pub(crate) fn run_runtime_bootstrap_process(
    state_directory: &Path,
    expected_store_instance_id: [u8; 32],
    compiled: RuntimeCompiledInstallationFactsV1,
    provisioning: RuntimeProvisioningV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let store = RuntimeStore::open(
        state_directory,
        expected_store_instance_id,
        provisioning.owner_target_fingerprint(),
    )?;
    let started = StartedRuntimeBootstrapService::try_start(store, compiled, provisioning)?;
    let bound = started.bind()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| RuntimeBootstrapEndpointError::Runtime)?;
    let service_result = runtime.block_on(bound.serve_until(runtime_shutdown_signal()));
    drop(runtime);
    service_result
}

impl<Store: RuntimeBootstrapStore> StartedRuntimeBootstrapService<Store> {
    fn bind(self) -> Result<BoundRuntimeBootstrapService<Store>, RuntimeBootstrapEndpointError> {
        self.provisioning.validate_runtime_credentials()?;
        let directory = open_socket_directory(
            self.provisioning
                .socket_path()
                .parent()
                .ok_or(RuntimeBootstrapEndpointError::InvalidProvisioning)?,
            self.provisioning.runtime_uid(),
            self.provisioning.controller_gid(),
        )?;
        remove_stale_socket_if_present(&directory, self.provisioning.socket_path())?;
        let standard = StdUnixListener::bind(self.provisioning.socket_path())
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        let identity = socket_identity(self.provisioning.socket_path())?;
        let guard = SocketGuard {
            path: self.provisioning.socket_path().to_path_buf(),
            directory,
            identity,
        };
        let setup = (|| {
            chown(
                self.provisioning.socket_path(),
                None,
                Some(Gid::from_raw(self.provisioning.controller_gid())),
            )
            .map_err(nix_socket_error)?;
            fs::set_permissions(
                self.provisioning.socket_path(),
                fs::Permissions::from_mode(CONTROL_SOCKET_MODE),
            )
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
            let metadata = fs::symlink_metadata(self.provisioning.socket_path())
                .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
            validate_socket_metadata(
                &metadata,
                self.provisioning.runtime_uid(),
                self.provisioning.controller_gid(),
            )?;
            if !identity.matches(&metadata) {
                return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
            }
            guard.validate_directory_identity()?;
            guard
                .directory
                .file
                .sync_all()
                .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
            standard
                .set_nonblocking(true)
                .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))
        })();
        if let Err(error) = setup {
            drop(standard);
            let _ = guard.cleanup();
            return Err(error);
        }

        Ok(BoundRuntimeBootstrapService {
            started: self,
            standard,
            guard,
            io_timeout: DEFAULT_IO_TIMEOUT,
        })
    }
}

struct BoundRuntimeBootstrapService<Store> {
    started: StartedRuntimeBootstrapService<Store>,
    standard: StdUnixListener,
    guard: SocketGuard,
    io_timeout: Duration,
}

impl<Store> BoundRuntimeBootstrapService<Store>
where
    Store: RuntimeBootstrapStore + RuntimeReferenceApplyStore,
{
    async fn serve_until<F>(self, shutdown: F) -> Result<(), RuntimeBootstrapEndpointError>
    where
        F: Future<Output = io::Result<()>>,
    {
        let Self {
            started,
            standard,
            guard,
            io_timeout,
        } = self;
        let channel = live_runtime_channel(&started.provisioning, &guard)?;
        let mut control = started.into_control_service(channel)?;
        let listener = UnixListener::from_std(standard)
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        let mut shutdown = Box::pin(shutdown);
        let service_result =
            loop {
                let accepted = tokio::select! {
                    biased;
                    result = &mut shutdown => break result
                        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind())),
                    result = listener.accept() => result,
                };
                let (mut stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        break Err(RuntimeBootstrapEndpointError::Socket(error.kind()));
                    }
                };
                if !peer_is_authorized(
                    &stream,
                    control.provisioning.controller_uid(),
                    control.provisioning.controller_gid(),
                ) {
                    continue;
                }
                let live_channel = match live_runtime_channel(&control.provisioning, &guard) {
                    Ok(channel) if channel == control.channel => channel,
                    Ok(_) => break Err(RuntimeBootstrapEndpointError::SocketIdentityChanged),
                    Err(error) => break Err(error),
                };
                let request =
                    match read_bounded_frame(&mut stream, MAX_CONTROL_REQUEST_BYTES, io_timeout)
                        .await
                    {
                        Ok(request) => request,
                        Err(()) => continue,
                    };
                let response = match control.handle_request(&request, live_channel) {
                    Ok(Some(response)) => response,
                    Ok(None) | Err(RuntimeControlRequestError::Rejected) => continue,
                    Err(RuntimeControlRequestError::Internal(error)) => break Err(error),
                };
                let _ = write_bounded_frame(
                    &mut stream,
                    &response,
                    MAX_CONTROL_RESPONSE_BYTES,
                    io_timeout,
                )
                .await;
            };
        drop(listener);
        let cleanup_result = guard.cleanup();
        match (service_result, cleanup_result) {
            (_, Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

async fn runtime_shutdown_signal() -> io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

fn peer_is_authorized(stream: &UnixStream, expected_uid: u32, expected_gid: u32) -> bool {
    stream.peer_cred().is_ok_and(|credentials| {
        credentials.uid() == expected_uid && credentials.gid() == expected_gid
    })
}

async fn read_bounded_frame(
    stream: &mut UnixStream,
    maximum: usize,
    io_timeout: Duration,
) -> Result<Box<[u8]>, ()> {
    timeout(io_timeout, async {
        let mut header = [0_u8; CONTROL_FRAME_HEADER_BYTES];
        stream.read_exact(&mut header).await.map_err(|_| ())?;
        let payload_length = usize::try_from(u32::from_be_bytes(header)).map_err(|_| ())?;
        if payload_length == 0 || payload_length > maximum {
            return Err(());
        }
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_length).map_err(|_| ())?;
        payload.resize(payload_length, 0);
        stream.read_exact(&mut payload).await.map_err(|_| ())?;
        Ok(payload.into_boxed_slice())
    })
    .await
    .map_err(|_| ())?
}

async fn write_bounded_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    maximum: usize,
    io_timeout: Duration,
) -> Result<(), ()> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(());
    }
    let length = u32::try_from(payload.len()).map_err(|_| ())?.to_be_bytes();
    timeout(io_timeout, async {
        stream.write_all(&length).await.map_err(|_| ())?;
        stream.write_all(payload).await.map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

fn open_socket_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<OpenedSocketDirectory, RuntimeBootstrapEndpointError> {
    validate_absolute_directory_path(path)?;
    let before = fs::symlink_metadata(path)
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    validate_socket_directory_metadata(&before, expected_uid, expected_gid)?;
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_socket_error)?;
    let file = File::from(owned);
    let after = file
        .metadata()
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    validate_socket_directory_metadata(&after, expected_uid, expected_gid)?;
    let identity = SocketIdentity::from_metadata(&after);
    if !identity.matches(&before) {
        return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
    }
    Ok(OpenedSocketDirectory {
        path: path.to_path_buf(),
        file,
        identity,
        expected_uid,
        expected_gid,
    })
}

fn validate_absolute_directory_path(path: &Path) -> Result<(), RuntimeBootstrapEndpointError> {
    validate_canonical_absolute_path(path, false)?;
    Ok(())
}

fn validate_socket_directory_metadata(
    metadata: &Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeBootstrapEndpointError> {
    if !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & MODE_MASK != CONTROL_SOCKET_DIRECTORY_MODE
    {
        return Err(RuntimeBootstrapEndpointError::UnsafeSocketDirectory);
    }
    Ok(())
}

fn validate_socket_metadata(
    metadata: &Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeBootstrapEndpointError> {
    if !metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & MODE_MASK != CONTROL_SOCKET_MODE
    {
        return Err(RuntimeBootstrapEndpointError::UnsafeSocket);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn matches(self, metadata: &Metadata) -> bool {
        self.device == metadata.dev() && self.inode == metadata.ino()
    }
}

fn socket_identity(path: &Path) -> Result<SocketIdentity, RuntimeBootstrapEndpointError> {
    fs::symlink_metadata(path)
        .map(|metadata| SocketIdentity::from_metadata(&metadata))
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))
}

struct OpenedSocketDirectory {
    path: PathBuf,
    file: File,
    identity: SocketIdentity,
    expected_uid: u32,
    expected_gid: u32,
}

struct SocketGuard {
    path: PathBuf,
    directory: OpenedSocketDirectory,
    identity: SocketIdentity,
}

impl SocketGuard {
    fn validate_directory_identity(&self) -> Result<(), RuntimeBootstrapEndpointError> {
        let opened = self
            .directory
            .file
            .metadata()
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        let named = fs::symlink_metadata(&self.directory.path)
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        validate_socket_directory_metadata(
            &opened,
            self.directory.expected_uid,
            self.directory.expected_gid,
        )?;
        if !self.directory.identity.matches(&opened) || !self.directory.identity.matches(&named) {
            return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
        }
        Ok(())
    }

    fn live_endpoint_identity_digest(&self) -> Result<Digest32, RuntimeBootstrapEndpointError> {
        self.validate_directory_identity()?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
        validate_socket_metadata(
            &metadata,
            self.directory.expected_uid,
            self.directory.expected_gid,
        )?;
        if !self.identity.matches(&metadata) {
            return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
        }
        reference_local_control_endpoint_identity_digest_v1(
            self.path.as_os_str().as_bytes(),
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & MODE_MASK,
        )
        .map_err(Into::into)
    }

    fn cleanup(&self) -> Result<(), RuntimeBootstrapEndpointError> {
        remove_exact_socket(&self.directory, &self.path, self.identity)
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn remove_stale_socket_if_present(
    directory: &OpenedSocketDirectory,
    path: &Path,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(RuntimeBootstrapEndpointError::Socket(error.kind())),
    };
    validate_socket_metadata(&metadata, directory.expected_uid, directory.expected_gid)?;
    match StdUnixStream::connect(path) {
        Ok(stream) => {
            drop(stream);
            return Err(RuntimeBootstrapEndpointError::SocketAlreadyActive);
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(RuntimeBootstrapEndpointError::Socket(error.kind())),
    }
    remove_exact_socket(directory, path, SocketIdentity::from_metadata(&metadata))
}

fn remove_exact_socket(
    directory: &OpenedSocketDirectory,
    path: &Path,
    expected: SocketIdentity,
) -> Result<(), RuntimeBootstrapEndpointError> {
    if path.parent() != Some(directory.path.as_path()) {
        return Err(RuntimeBootstrapEndpointError::InvalidProvisioning);
    }
    let opened = directory
        .file
        .metadata()
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    let named = fs::symlink_metadata(&directory.path)
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    if !directory.identity.matches(&opened) || !directory.identity.matches(&named) {
        return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))?;
    validate_socket_metadata(&metadata, directory.expected_uid, directory.expected_gid)?;
    if !expected.matches(&metadata) {
        return Err(RuntimeBootstrapEndpointError::SocketIdentityChanged);
    }
    let name: &OsStr = path
        .file_name()
        .ok_or(RuntimeBootstrapEndpointError::InvalidProvisioning)?;
    unlinkat(&directory.file, name, UnlinkatFlags::NoRemoveDir).map_err(nix_socket_error)?;
    directory
        .file
        .sync_all()
        .map_err(|error| RuntimeBootstrapEndpointError::Socket(error.kind()))
}

fn live_runtime_channel(
    provisioning: &RuntimeProvisioningV1,
    guard: &SocketGuard,
) -> Result<ReferenceChannelBindingV1, RuntimeBootstrapEndpointError> {
    provisioning.validate_runtime_credentials()?;
    let endpoint_identity_digest = guard.live_endpoint_identity_digest()?;
    let runtime_pid = u64::try_from(getpid().as_raw())
        .map_err(|_| RuntimeBootstrapEndpointError::RuntimeCredentialsChanged)?;
    let peer_credentials_digest = reference_runtime_peer_credentials_digest_v1(
        provisioning.runtime_uid(),
        provisioning.runtime_gid(),
        runtime_pid,
    )?;
    ReferenceChannelBindingV1::try_new(
        provisioning.target(),
        provisioning.runtime_principal(),
        endpoint_identity_digest,
        peer_credentials_digest,
    )
    .map_err(Into::into)
}

fn nix_socket_error(error: nix::errno::Errno) -> RuntimeBootstrapEndpointError {
    RuntimeBootstrapEndpointError::Socket(io::Error::from_raw_os_error(error as i32).kind())
}

fn verify_startup_installation(
    snapshot: &RuntimeJournalSnapshot,
    target: RuntimeHostId,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<VerifiedRuntimeInstallationV1, RuntimeBootstrapEndpointError> {
    let state = snapshot.state();
    let installation = verify_pinned_startup(
        &state.host.build_descriptor.canonical_bytes,
        state.host.build_descriptor.digest,
        &state.host.singleton_manifest.canonical_bytes,
        state.host.singleton_manifest.digest,
        target,
        compiled,
    )?;
    let pinned: StorePinnedBuildIdentity = state.host.store_pinned_build_identity;
    let compiled_compatibility = compiled.compiled_reference_compatibility_digest()?;
    if state.host.compiled_build_instance_id != compiled.compiled_build_instance_id()
        || state.host.compiled_compatibility_digest != compiled_compatibility
        || pinned.build_instance_id() != installation.build_instance_id()
        || pinned.build_descriptor_digest() != installation.build_descriptor_digest()
        || pinned.runtime_artifact_sha256() != installation.runtime_artifact_sha256()
        || pinned.compiled_reference_compatibility_digest()
            != installation.compiled_reference_compatibility_digest()
    {
        return Err(RuntimeBootstrapEndpointError::BuildPinMismatch);
    }
    Ok(installation)
}

fn validate_startup_durable_control_state(
    snapshot: &RuntimeJournalSnapshot,
    manifest: &VerifiedRuntimeManifestIngressV1,
    compiled: RuntimeCompiledInstallationFactsV1,
    provisioning: &RuntimeProvisioningV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let state = snapshot.state();
    let expected_scope = *provisioning.source_scope().as_bytes();
    if state
        .writer_fence
        .is_some_and(|fence| fence.source_scope != expected_scope)
        || state
            .source_revision_high_water
            .is_some_and(|high_water| high_water.source_scope != expected_scope)
        || state
            .active_desired
            .as_ref()
            .is_some_and(|active| active.source_scope != expected_scope)
    {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }

    if let Some(prepared) = state.prepared.as_ref() {
        let historical_channel = prepared
            .response_channel
            .to_contract()
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        if historical_channel.target() != provisioning.target()
            || historical_channel.runtime_peer() != provisioning.runtime_principal()
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        let request = ReferenceApplyRequestV1::decode(&prepared.request.canonical_bytes)
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let authenticated = provisioning
            .admission_policy()
            .authenticate_reference_apply_request(&request)
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        request
            .validate_expected_store(*snapshot.store_instance_id())
            .and_then(|()| request.validate_manifest(manifest))
            .and_then(|()| {
                request
                    .target_execution()
                    .validate_compiled_fixture(compiled)
            })
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let provenance = request.provenance();
        let control = request.control_commitment().control();
        let temporal = request.temporal();
        let identities = authenticated.identities();
        let writer = control.writer_context();
        let proof_digest = writer
            .proof()
            .envelope_digest()
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let fence = state
            .writer_fence
            .ok_or(RuntimeBootstrapEndpointError::InvalidStartedState)?;
        let prepared_tenure_recorded = state.host.tenure_nonces.iter().any(|record| {
            record.identity == identities.tenure_nonce_identity()
                && record.value_digest == proof_digest
        });
        let prepared_tenure_is_current = identities.tenure_nonce_identity()
            == fence.tenure_nonce_identity
            && proof_digest == fence.proof_envelope_digest
            && writer.writer().as_bytes() == &fence.writer
            && writer.epoch().value() == fence.epoch
            && request.authentication().claim().principal().as_bytes() == &fence.principal;
        let prepared_tenure_is_superseded = prepared_tenure_recorded
            && fence.source_scope == prepared.source_scope
            && fence.epoch > writer.epoch().value()
            && matches!(
                prepared.phase,
                PreparedPhase::SupersededBeforeEffects
                    | PreparedPhase::SupersededReconcileRequired
                    | PreparedPhase::StartupExpiredNoEffects
                    | PreparedPhase::StartupReconcileRequired
            );
        let expected_active_matches = match (control.expected_active(), prepared.expected_active) {
            (ExpectedActive::None, ExpectedActiveCas::None) => true,
            (ExpectedActive::Exact(left), ExpectedActiveCas::Exact(right)) => left == right,
            _ => false,
        };
        let mode_matches = matches!(
            (request.target_execution().mode(), prepared.incoming_kind),
            (
                ReferenceAssemblyModeV1::OneSourceLoop,
                DesiredHeadKind::OneSourceLoop
            ) | (
                ReferenceAssemblyModeV1::EmptyDeactivate,
                DesiredHeadKind::EmptyDeactivate
            )
        );
        if request.canonical_wire() != prepared.request.canonical_bytes.as_ref()
            || request.envelope_request_digest() != prepared.request.digest
            || request.target() != provisioning.target()
            || provenance != prepared.slice_provenance.plan_provenance()
            || request.assignment_digest() != prepared.slice_provenance.assignment_digest
            || request.target_slice_digest() != prepared.slice_provenance.target_slice_digest
            || request.target_slice_digest() != prepared.incoming_slice_digest
            || request.target_execution().manifest_digest() != prepared.manifest_digest
            || control.operation_id().as_bytes() != &prepared.operation_id
            || !expected_active_matches
            || !mode_matches
            || identities.request_nonce_identity() != prepared.request_nonce_identity
            || identities.temporal_lineage_digest() != prepared.temporal_lineage_digest
            || temporal.constraint_id().as_bytes() != &prepared.temporal_constraint_id
            || temporal.target_clock_domain().as_bytes() != &state.host.clock_domain
            || temporal.target_clock_generation().value() != prepared.installed_clock_generation
            || !prepared_tenure_recorded
            || (!prepared_tenure_is_current && !prepared_tenure_is_superseded)
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        if let Some(retiring) = prepared.retiring.as_ref() {
            validate_startup_durable_slice(
                &retiring.old_slice.canonical_bytes,
                retiring.old_slice_provenance,
                DesiredHeadKind::OneSourceLoop,
                manifest,
                compiled,
            )?;
        }
    }

    if let Some(active) = state.active_desired.as_ref() {
        validate_startup_durable_slice(
            &active.slice.canonical_bytes,
            active.slice_provenance,
            active.kind,
            manifest,
            compiled,
        )?;
    }

    if let Some(recovery) = state.recovery_action {
        let active = state
            .active_desired
            .as_ref()
            .ok_or(RuntimeBootstrapEndpointError::InvalidStartedState)?;
        if recovery.source_scope != expected_scope
            || recovery.slice_provenance != active.slice_provenance
            || recovery.active_slice_digest != active.slice_provenance.target_slice_digest
            || recovery.manifest_digest != manifest.manifest_digest()
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
    }
    for terminal in &state.recovery_terminals {
        let recovery = terminal.recovery;
        if recovery.source_scope != expected_scope
            || recovery.slice_provenance.target != *provisioning.target().as_bytes()
            || recovery.slice_provenance.source_scope != recovery.source_scope
            || recovery.slice_provenance.source_revision != recovery.source_revision
            || recovery.slice_provenance.source_plan_digest != recovery.source_plan_digest
            || recovery.slice_provenance.target_slice_digest != recovery.active_slice_digest
            || recovery.manifest_digest != manifest.manifest_digest()
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
    }
    for terminal in &state.terminal_operations {
        if terminal.source_scope != expected_scope
            || terminal.slice_provenance.target != *provisioning.target().as_bytes()
            || terminal.slice_provenance.source_scope != terminal.source_scope
            || terminal.slice_provenance.source_revision != terminal.source_revision
            || terminal.slice_provenance.source_plan_digest != terminal.source_plan_digest
            || terminal.slice_provenance.target_slice_digest != terminal.target_slice_digest
        {
            return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
        }
        validate_startup_terminal_producer(snapshot, terminal, provisioning)?;
    }
    Ok(())
}

fn validate_startup_durable_slice(
    canonical_slice: &[u8],
    provenance: crate::runtime_journal::DurableSliceProvenance,
    expected_kind: DesiredHeadKind,
    manifest: &VerifiedRuntimeManifestIngressV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let execution = verify_reference_durable_slice_v1(
        canonical_slice,
        provenance.plan_provenance(),
        provenance.target_slice_digest,
        manifest,
    )
    .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    execution
        .validate_compiled_fixture(compiled)
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    let mode_matches = matches!(
        (execution.mode(), expected_kind),
        (
            ReferenceAssemblyModeV1::OneSourceLoop,
            DesiredHeadKind::OneSourceLoop
        ) | (
            ReferenceAssemblyModeV1::EmptyDeactivate,
            DesiredHeadKind::EmptyDeactivate
        )
    );
    if !mode_matches {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }
    Ok(())
}

fn startup_active_execution(
    snapshot: &RuntimeJournalSnapshot,
    manifest: &VerifiedRuntimeManifestIngressV1,
    compiled: RuntimeCompiledInstallationFactsV1,
) -> Result<Option<ReferenceTargetExecutionPlanV4>, RuntimeBootstrapEndpointError> {
    let state = snapshot.state();
    let slice = if let Some(prepared) = state.prepared.as_ref() {
        if let Some(retiring) = prepared.retiring.as_ref() {
            Some((
                retiring.old_slice.canonical_bytes.as_ref(),
                retiring.old_slice_provenance,
            ))
        } else if prepared.incoming_kind == DesiredHeadKind::OneSourceLoop {
            let request = ReferenceApplyRequestV1::decode(&prepared.request.canonical_bytes)
                .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
            request
                .target_execution()
                .validate_compiled_fixture(compiled)
                .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
            return Ok(Some(request.target_execution().clone()));
        } else {
            state
                .active_desired
                .as_ref()
                .filter(|active| active.kind == DesiredHeadKind::OneSourceLoop)
                .map(|active| {
                    (
                        active.slice.canonical_bytes.as_ref(),
                        active.slice_provenance,
                    )
                })
        }
    } else {
        state
            .active_desired
            .as_ref()
            .filter(|active| active.kind == DesiredHeadKind::OneSourceLoop)
            .map(|active| {
                (
                    active.slice.canonical_bytes.as_ref(),
                    active.slice_provenance,
                )
            })
    };
    let Some((canonical_slice, provenance)) = slice else {
        return Ok(None);
    };
    let execution = verify_reference_durable_slice_v1(
        canonical_slice,
        provenance.plan_provenance(),
        provenance.target_slice_digest,
        manifest,
    )
    .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    execution
        .validate_compiled_fixture(compiled)
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    Ok(Some(execution))
}

fn validate_startup_terminal_producer(
    snapshot: &RuntimeJournalSnapshot,
    terminal: &crate::runtime_journal::TerminalOperationRecord,
    provisioning: &RuntimeProvisioningV1,
) -> Result<(), RuntimeBootstrapEndpointError> {
    let receipt =
        ReferenceApplyTerminalReceiptV1::decode(&terminal.canonical_response.canonical_bytes)
            .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    if receipt.canonical_wire() != terminal.canonical_response.canonical_bytes.as_ref()
        || receipt.target() != provisioning.target()
        || receipt.runtime_store_instance_id() != *snapshot.store_instance_id()
        || receipt.source_scope().as_bytes() != &terminal.source_scope
        || receipt.operation_id().as_bytes() != &terminal.operation_id
        || receipt.request_digest() != terminal.request_digest
        || receipt.authentication_runtime_peer() != provisioning.runtime_principal()
        || receipt.authentication_key() != provisioning.runtime_response_key_ref()
        || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
        || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(RuntimeBootstrapEndpointError::InvalidStartedState);
    }
    let signature = parse_terminal_signature(receipt.authentication_signature())?;
    let transcript = receipt
        .signing_transcript()
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    provisioning
        .response_signer()
        .verifying_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)
}

fn parse_terminal_signature(signature: &[u8]) -> Result<Signature, RuntimeBootstrapEndpointError> {
    let bytes: &[u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| RuntimeBootstrapEndpointError::InvalidStartedState)?;
    Ok(Signature::from_bytes(bytes))
}

fn map_bootstrap_state(state: RuntimeJournalBootstrapState) -> ReferenceBootstrapStateV1 {
    match state {
        RuntimeJournalBootstrapState::ReadyForApply => ReferenceBootstrapStateV1::ReadyForApply,
        RuntimeJournalBootstrapState::NotReadyRecovering => {
            ReferenceBootstrapStateV1::NotReadyRecovering
        }
        RuntimeJournalBootstrapState::ValidatedOperationalQuarantine => {
            ReferenceBootstrapStateV1::ValidatedOperationalQuarantine
        }
        RuntimeJournalBootstrapState::RecoveryFailedNotReady => {
            ReferenceBootstrapStateV1::RecoveryFailedNotReady
        }
        RuntimeJournalBootstrapState::NotReadyBusy => ReferenceBootstrapStateV1::NotReadyBusy,
    }
}

fn map_bootstrap_reason(reason: RuntimeJournalBootstrapReason) -> ReferenceOperationalReasonV1 {
    match reason {
        RuntimeJournalBootstrapReason::Recovering => ReferenceOperationalReasonV1::Recovering,
        RuntimeJournalBootstrapReason::RecoveryFailed => {
            ReferenceOperationalReasonV1::RecoveryFailed
        }
        RuntimeJournalBootstrapReason::OwnershipUncertain => {
            ReferenceOperationalReasonV1::OwnershipUncertain
        }
        RuntimeJournalBootstrapReason::RuntimeBusy => ReferenceOperationalReasonV1::RuntimeBusy,
    }
}

struct RuntimeBootstrapCore<'a> {
    facts: ReferenceBootstrapFactsV1,
    channel: ReferenceChannelBindingV1,
    provisioning: &'a RuntimeProvisioningV1,
}

impl RuntimeBootstrapCore<'_> {
    fn handle_request(&self, frame: &[u8]) -> Result<Box<[u8]>, RuntimeBootstrapRequestError> {
        if frame.is_empty() || frame.len() > MAX_REFERENCE_BOOTSTRAP_REQUEST_BYTES {
            return Err(RuntimeBootstrapRequestError::InvalidFrameLength);
        }
        let request = ReferenceBootstrapRequestV1::decode(frame)
            .map_err(|_| RuntimeBootstrapRequestError::InvalidCanonicalRequest)?;
        authenticate_request(self.provisioning, &request)?;
        let auth_claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            self.channel,
            self.provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?,
            ED25519_ALGORITHM_VERSION,
        )
        .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?;
        let draft = ReferenceBootstrapResponseDraftV1::try_new(
            &request,
            self.facts,
            self.channel,
            auth_claim,
        )
        .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?;
        let signature = self
            .provisioning
            .response_signer()
            .sign(
                draft
                    .signing_transcript()
                    .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?
                    .as_bytes(),
            )
            .to_bytes();
        let response = draft
            .finalize(&signature)
            .map_err(|_| RuntimeBootstrapRequestError::InternalContract)?;
        let wire = response.canonical_wire();
        if wire.len() > MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES
            || wire.len() > request.max_response_bytes() as usize
        {
            return Err(RuntimeBootstrapRequestError::ResponseBoundExceeded);
        }
        Ok(wire.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeBootstrapRequestError {
    InvalidFrameLength,
    InvalidCanonicalRequest,
    Unauthorized,
    InvalidSignature,
    ResponseBoundExceeded,
    InternalContract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeQueryRequestError {
    InvalidCanonicalRequest,
    Unauthorized,
    StoreMismatch,
    InvalidSignature,
}

/// Fail-closed Runtime bootstrap startup/service error.
#[derive(Debug)]
pub(crate) enum RuntimeBootstrapEndpointError {
    InvalidProvisioning,
    ProvisioningPinMismatch,
    BuildPinMismatch,
    InvalidStartedState,
    Runtime,
    RuntimeClock,
    UnsafeSocketDirectory,
    UnsafeSocket,
    SocketAlreadyActive,
    SocketIdentityChanged,
    RuntimeCredentialsChanged,
    Provisioning(RuntimeProvisioningError),
    Installation(RuntimeInstallationError),
    ControlContract(ReferenceControlError),
    ControlState(RuntimeControlStateError),
    Apply(RuntimeReferenceApplyError),
    RestartReassembly(RuntimeRestartReassemblyError),
    StoreOpen(RuntimeStoreOpenError),
    Store(RuntimeStoreError),
    Socket(io::ErrorKind),
}

impl From<RuntimeInstallationError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeInstallationError) -> Self {
        Self::Installation(error)
    }
}

impl From<RuntimeProvisioningError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeProvisioningError) -> Self {
        Self::Provisioning(error)
    }
}

impl From<ReferenceControlError> for RuntimeBootstrapEndpointError {
    fn from(error: ReferenceControlError) -> Self {
        Self::ControlContract(error)
    }
}

impl From<RuntimeControlStateError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeControlStateError) -> Self {
        Self::ControlState(error)
    }
}

impl From<RuntimeStoreOpenError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeStoreOpenError) -> Self {
        Self::StoreOpen(error)
    }
}

impl From<RuntimeStoreError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<RuntimeRestartReassemblyError> for RuntimeBootstrapEndpointError {
    fn from(error: RuntimeRestartReassemblyError) -> Self {
        Self::RestartReassembly(error)
    }
}

impl fmt::Display for RuntimeBootstrapEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProvisioning => formatter.write_str("invalid bootstrap provisioning"),
            Self::ProvisioningPinMismatch => {
                formatter.write_str("bootstrap provisioning does not match journal pins")
            }
            Self::BuildPinMismatch => formatter.write_str("Runtime build pins do not match"),
            Self::InvalidStartedState => formatter.write_str("invalid post-start Runtime state"),
            Self::Runtime => formatter.write_str("bootstrap reactor failed"),
            Self::RuntimeClock => formatter.write_str("Runtime owner clock observation failed"),
            Self::UnsafeSocketDirectory => formatter.write_str("unsafe bootstrap socket directory"),
            Self::UnsafeSocket => formatter.write_str("unsafe bootstrap socket"),
            Self::SocketAlreadyActive => {
                formatter.write_str("bootstrap socket already has a live owner")
            }
            Self::SocketIdentityChanged => formatter.write_str("bootstrap socket identity changed"),
            Self::RuntimeCredentialsChanged => {
                formatter.write_str("Runtime service credentials changed")
            }
            Self::Provisioning(error) => write!(formatter, "Runtime provisioning: {error}"),
            Self::Installation(error) => write!(formatter, "startup installation: {error}"),
            Self::ControlContract(error) => write!(formatter, "bootstrap contract: {error}"),
            Self::ControlState(error) => write!(formatter, "Runtime control state: {error:?}"),
            Self::Apply(error) => write!(formatter, "Runtime reference apply: {error:?}"),
            Self::RestartReassembly(error) => {
                write!(formatter, "Runtime restart reassembly: {error:?}")
            }
            Self::StoreOpen(error) => write!(formatter, "Runtime store open: {error}"),
            Self::Store(error) => write!(formatter, "Runtime store: {error}"),
            Self::Socket(kind) => write!(formatter, "bootstrap socket I/O: {kind:?}"),
        }
    }
}

impl std::error::Error for RuntimeBootstrapEndpointError {}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::{
        apply::{
            ApplyOperationId, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
            RuntimeApplyControl, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
            TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
        },
        assignment::InstanceRef,
        execution::{CardDefinitionRef, CardImplementationRef, DomainRef},
        installation::{
            InstalledRuntimeArtifactObservationV1, generate_build_descriptor, generate_manifest,
        },
        provenance::{PlanProvenance, SourcePlanDigest, SourcePlanRef, SourcePlanRevision},
        reference_control::{
            ReferenceApplyRequestDraftV1, ReferenceApplyTerminalOutcomeV1, ReferenceAssemblyModeV1,
            ReferenceBootstrapRequestDraftV1, ReferenceBootstrapRequestIdV1,
            ReferenceBootstrapResponseV1, ReferenceQueryIdV1, ReferenceQueryRequestDraftV1,
            ReferenceQueryResponseV1, ReferenceQuerySelectorV1, ReferenceTargetExecutionPlanV4,
            ValidatedReferenceLifecycleBudgetsV1,
        },
        temporal::{ApplyTemporalConstraint, TemporalConstraintId},
        wire::ApplyRequestAuthClaim,
    };

    use super::*;
    use crate::runtime_control_state::runtime_reference_apply::{
        RuntimeEmptyRetireOwnerPlan, RuntimeOneSourceOwnerPlan, RuntimeReferenceApplyStoreError,
        RuntimeReferenceMaterializationOwnerError,
    };
    use crate::runtime_control_state::runtime_reference_owner::{
        fixed_owner_start_callback_actions_for_test, fixed_owner_stop_callback_actions_for_test,
        reset_fixed_owner_callback_actions_for_test,
    };
    use crate::runtime_journal::{
        CallbackOutcome, JournalActionRef, LiveMaterialization, OpaqueCanonicalValue,
        RecoveryPhase, RuntimeJournalSequenceOne, RuntimeOneSourceOwnershipInput,
        RuntimeOneSourceResourceRefs, RuntimeOneSourceTombstonesInput, RuntimeTenureAdmissionInput,
        StorePinnedBuildIdentity, TerminalOutcome,
    };
    use crate::runtime_provisioning::RuntimeProvisioningInputV1;

    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x11; 16]);
    const SOURCE_SCOPE: SourceScopeRef = SourceScopeRef::from_bytes([0x21; 16]);
    const CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x31; 16]);
    const CONTROLLER_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x32; 16]);
    const RUNTIME_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x33; 16]);
    const RESPONSE_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x34; 16]);
    const WRITER: PlanWriterRef = PlanWriterRef::from_bytes([0x35; 16]);
    const AUTHORITY_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x36; 16]);
    const TENURE_AUTHORITY_REF: TenureAuthorityRef = TenureAuthorityRef::from_bytes([0x37; 16]);
    const TENURE_KEY_REF: TenureKeyRef = TenureKeyRef::from_bytes([0x38; 16]);
    const CONTROLLER_SEED: [u8; 32] = [0x41; 32];
    const RESPONSE_SEED: [u8; 32] = [0x42; 32];
    const TENURE_SEED: [u8; 32] = [0x43; 32];
    const STORE_INSTANCE_ID: [u8; 32] = [0x51; 32];
    const CLOCK_DOMAIN: [u8; 16] = [0x52; 16];

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn distinct_controller_uid(runtime_uid: u32) -> u32 {
        assert_ne!(
            runtime_uid, 0,
            "reference endpoint tests require a non-root uid"
        );
        if runtime_uid == u32::MAX {
            runtime_uid - 1
        } else {
            runtime_uid + 1
        }
    }

    fn distinct_authority_uid(runtime_uid: u32) -> u32 {
        if runtime_uid <= u32::MAX - 2 {
            runtime_uid + 2
        } else {
            runtime_uid - 2
        }
    }

    fn provisioning(socket_path: PathBuf) -> RuntimeProvisioningV1 {
        let key_directory = TestSocketDirectory::create();
        let controller_key = key_directory.path.join("controller.pub");
        let response_key = key_directory.path.join("runtime.pub");
        let response_seed = key_directory.path.join("runtime.seed");
        let tenure_key = key_directory.path.join("authority.pub");
        for (path, bytes) in [
            (
                &controller_key,
                SigningKey::from_bytes(&CONTROLLER_SEED)
                    .verifying_key()
                    .to_bytes(),
            ),
            (
                &response_key,
                SigningKey::from_bytes(&RESPONSE_SEED)
                    .verifying_key()
                    .to_bytes(),
            ),
            (&response_seed, RESPONSE_SEED),
            (
                &tenure_key,
                SigningKey::from_bytes(&TENURE_SEED)
                    .verifying_key()
                    .to_bytes(),
            ),
        ] {
            fs::write(path, bytes)
                .unwrap_or_else(|error| panic!("provisioning key write failed: {error}"));
            fs::set_permissions(path, fs::Permissions::from_mode(0o400))
                .unwrap_or_else(|error| panic!("provisioning key chmod failed: {error}"));
        }
        let runtime_uid = geteuid().as_raw();
        let runtime_gid = getegid().as_raw();
        assert_ne!(
            runtime_gid, 0,
            "reference endpoint tests require a non-root gid"
        );
        let controller_uid = distinct_controller_uid(runtime_uid);
        let authority_uid = distinct_authority_uid(runtime_uid);
        let input = RuntimeProvisioningInputV1 {
            socket_path,
            target: TARGET,
            source_scope: SOURCE_SCOPE,
            writer: WRITER,
            runtime_principal: RUNTIME_PRINCIPAL,
            runtime_uid,
            runtime_gid,
            controller_principal: CONTROLLER_PRINCIPAL,
            controller_uid,
            controller_gid: runtime_gid,
            controller_request_key_ref: CONTROLLER_KEY_REF,
            controller_public_key_path: controller_key,
            runtime_response_key_ref: RESPONSE_KEY_REF,
            runtime_response_public_key_path: response_key,
            runtime_response_private_seed_path: response_seed,
            authority_principal: AUTHORITY_PRINCIPAL,
            authority_uid,
            authority_gid: runtime_gid,
            tenure_authority_ref: TENURE_AUTHORITY_REF,
            tenure_key_ref: TENURE_KEY_REF,
            tenure_public_key_path: tenure_key,
        };
        let provisioning = RuntimeProvisioningV1::try_new(input)
            .unwrap_or_else(|error| panic!("valid provisioning rejected: {error}"));
        for path in fs::read_dir(&key_directory.path)
            .unwrap_or_else(|error| panic!("key fixture list failed: {error}"))
        {
            let path = path
                .unwrap_or_else(|error| panic!("key fixture entry failed: {error}"))
                .path();
            fs::remove_file(path)
                .unwrap_or_else(|error| panic!("key fixture cleanup failed: {error}"));
        }
        provisioning
    }

    fn compiled_facts() -> RuntimeCompiledInstallationFactsV1 {
        RuntimeCompiledInstallationFactsV1::try_new(
            [0x61; 32],
            CardDefinitionRef::from_bytes([0x62; 16]),
            CardImplementationRef::from_bytes([0x63; 16]),
            [0x64; 16],
            digest(0x65),
            digest(0x66),
        )
        .unwrap_or_else(|error| panic!("compiled facts rejected: {error}"))
    }

    fn installed_snapshot(
        provisioning: &RuntimeProvisioningV1,
    ) -> (RuntimeJournalSnapshot, RuntimeCompiledInstallationFactsV1) {
        let compiled = compiled_facts();
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            digest(0x67),
            "x86_64-unknown-linux-gnu",
        )
        .unwrap_or_else(|error| panic!("artifact observation rejected: {error}"));
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
        let snapshot = RuntimeJournalSnapshot::try_initialize(
            STORE_INSTANCE_ID,
            provisioning.owner_target_fingerprint(),
            RuntimeJournalSequenceOne {
                clock_domain: CLOCK_DOMAIN,
                build_descriptor: OpaqueCanonicalValue::try_pinned_artifact(
                    installation.descriptor_canonical_wire(),
                    installation.descriptor_digest(),
                )
                .unwrap_or_else(|error| panic!("descriptor pin failed: {error:?}")),
                singleton_manifest: OpaqueCanonicalValue::try_pinned_artifact(
                    installation.manifest_canonical_wire(),
                    installation.manifest_digest(),
                )
                .unwrap_or_else(|error| panic!("manifest pin failed: {error:?}")),
                store_pinned_build_identity: StorePinnedBuildIdentity::try_new(
                    installation.build_instance_id(),
                    installation.build_descriptor_digest(),
                    installation.runtime_artifact_sha256(),
                    installation.compiled_reference_compatibility_digest(),
                )
                .unwrap_or_else(|error| panic!("build identity rejected: {error:?}")),
                compiled_build_instance_id: compiled.compiled_build_instance_id(),
                compiled_compatibility_digest: compiled
                    .compiled_reference_compatibility_digest()
                    .unwrap_or_else(|error| panic!("compiled compatibility failed: {error}")),
                admission_policy_fingerprint: provisioning.admission_policy_fingerprint(),
                channel_policy_fingerprint: provisioning.channel_policy_fingerprint(),
                controller_key_fingerprint: provisioning.controller_key_fingerprint(),
            },
        )
        .unwrap_or_else(|error| panic!("sequence one rejected: {error:?}"));
        (snapshot, compiled)
    }

    struct MockStore {
        snapshot: RuntimeJournalSnapshot,
        commit_attempts: Rc<Cell<u32>>,
        fail_commit: bool,
        socket_path: PathBuf,
    }

    impl RuntimeBootstrapStore for MockStore {
        fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeBootstrapEndpointError> {
            Ok(&self.snapshot)
        }

        fn commit(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeBootstrapEndpointError> {
            assert!(
                !self.socket_path.exists(),
                "socket became visible before startup invalidation commit"
            );
            self.commit_attempts
                .set(self.commit_attempts.get().saturating_add(1));
            if self.fail_commit {
                return Err(RuntimeBootstrapEndpointError::Runtime);
            }
            self.snapshot = next;
            Ok(())
        }
    }

    impl RuntimeReferenceApplyStore for MockStore {
        fn current_snapshot(
            &self,
        ) -> Result<RuntimeJournalSnapshot, RuntimeReferenceApplyStoreError> {
            Ok(self.snapshot.clone())
        }

        fn commit_snapshot(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeReferenceApplyStoreError> {
            assert!(
                !self.socket_path.exists(),
                "socket became visible before restart reassembly commit"
            );
            self.commit_attempts
                .set(self.commit_attempts.get().saturating_add(1));
            if self.fail_commit {
                return Err(RuntimeReferenceApplyStoreError::Unavailable);
            }
            self.snapshot = next;
            Ok(())
        }
    }

    struct StartupCrashStore {
        snapshot: RuntimeJournalSnapshot,
        durable_snapshot: Rc<RefCell<RuntimeJournalSnapshot>>,
        commit_attempts: Rc<Cell<u32>>,
        fail_after_publish_on: u32,
        socket_path: PathBuf,
    }

    impl RuntimeBootstrapStore for StartupCrashStore {
        fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeBootstrapEndpointError> {
            Ok(&self.snapshot)
        }

        fn commit(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeBootstrapEndpointError> {
            assert!(!self.socket_path.exists());
            let attempt = self.commit_attempts.get().saturating_add(1);
            self.commit_attempts.set(attempt);
            self.snapshot = next.clone();
            *self.durable_snapshot.borrow_mut() = next;
            if attempt == self.fail_after_publish_on {
                return Err(RuntimeBootstrapEndpointError::Runtime);
            }
            Ok(())
        }
    }

    impl RuntimeReferenceApplyStore for StartupCrashStore {
        fn current_snapshot(
            &self,
        ) -> Result<RuntimeJournalSnapshot, RuntimeReferenceApplyStoreError> {
            Ok(self.snapshot.clone())
        }

        fn commit_snapshot(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeReferenceApplyStoreError> {
            assert!(!self.socket_path.exists());
            let attempt = self.commit_attempts.get().saturating_add(1);
            self.commit_attempts.set(attempt);
            self.snapshot = next.clone();
            *self.durable_snapshot.borrow_mut() = next;
            if attempt == self.fail_after_publish_on {
                return Err(RuntimeReferenceApplyStoreError::Unavailable);
            }
            Ok(())
        }
    }

    struct FailingRetireOwner {
        active_slice_digest: TargetSliceDigest,
        resource_generation: u64,
        plan: RuntimeEmptyRetireOwnerPlan,
    }

    impl RuntimeReferenceMaterializationOwner for FailingRetireOwner {
        fn prepare_one_source(
            &mut self,
            _request: &ReferenceApplyRequestV1,
            _durable_action: Option<JournalActionRef>,
        ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
            Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
        }

        fn materialize_one_source(
            &mut self,
            _action: JournalActionRef,
            _resources: RuntimeOneSourceResourceRefs,
        ) -> Result<RuntimeOneSourceOwnershipInput, RuntimeReferenceMaterializationOwnerError>
        {
            Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
        }

        fn start_one_source_once(
            &mut self,
            _action: JournalActionRef,
        ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
            Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
        }

        fn prepare_empty_retire(
            &mut self,
            active_slice_digest: TargetSliceDigest,
            resource_generation: u64,
            durable_action: Option<JournalActionRef>,
        ) -> Result<RuntimeEmptyRetireOwnerPlan, RuntimeReferenceMaterializationOwnerError>
        {
            if active_slice_digest != self.active_slice_digest
                || resource_generation != self.resource_generation
                || durable_action.is_some_and(|action| action.action_id != self.plan.action_id)
            {
                return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
            }
            Ok(self.plan)
        }

        fn stop_one_source_once(
            &mut self,
            _action: JournalActionRef,
        ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
            Err(RuntimeReferenceMaterializationOwnerError::CallbackFailed)
        }

        fn cleanup_one_source_once(
            &mut self,
            _action: JournalActionRef,
        ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError>
        {
            Err(RuntimeReferenceMaterializationOwnerError::CleanupFailed)
        }
    }

    fn started_service(socket_path: PathBuf) -> StartedRuntimeBootstrapService<MockStore> {
        let initial_provisioning = provisioning(socket_path.clone());
        let (snapshot, compiled) = installed_snapshot(&initial_provisioning);
        StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            compiled,
            initial_provisioning,
        )
        .unwrap_or_else(|error| panic!("startup rejected: {error}"))
    }

    fn head_first_retiring_service(
        socket_path: PathBuf,
    ) -> (
        RuntimeControlService<MockStore, FailingRetireOwner>,
        ReferenceApplyRequestV1,
        ReferenceChannelBindingV1,
    ) {
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let active_request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"query-draining-active-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xe1),
            digest(0xe2),
        )
        .unwrap_or_else(|error| panic!("draining channel rejected: {error}"));
        let mut active_service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("draining control service rejected: {error}"));
        let active_pxrt = active_service
            .handle_request(active_request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("draining active apply rejected: {error:?}"))
            .unwrap_or_else(|| panic!("draining active apply returned no PXRT"));
        let active_receipt = ReferenceApplyTerminalReceiptV1::decode(&active_pxrt)
            .unwrap_or_else(|error| panic!("draining active PXRT decode failed: {error}"));
        assert_eq!(
            active_receipt.facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        );

        let active_snapshot = active_service.apply.snapshot().clone();
        let (active_slice_digest, resource_generation) =
            match active_snapshot.state().live_materialization {
                LiveMaterialization::LiveReady {
                    active_slice_digest,
                    resource_generation,
                    ..
                } => (active_slice_digest, resource_generation),
                other => panic!("draining fixture did not become LiveReady: {other:?}"),
            };
        let budgets = active_request
            .target_execution()
            .loop_facts()
            .unwrap_or_else(|| panic!("draining active request lost loop facts"))
            .budgets();
        let compiled = active_service.compiled;
        let compatibility = active_service.compatibility.clone();
        let clock = active_service.clock;
        drop(active_service);

        let provisioning = provisioning(socket_path.clone());
        let signer = RuntimeReferenceApplySigner::try_new(
            provisioning.response_signer().clone(),
            provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("draining response algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("draining response signer failed: {error:?}"));
        let owner = FailingRetireOwner {
            active_slice_digest,
            resource_generation,
            plan: RuntimeEmptyRetireOwnerPlan {
                action_id: [0xe3; 16],
                signed_budgets: budgets,
            },
        };
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            MockStore {
                snapshot: active_snapshot.clone(),
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            RuntimeEndpointApplyClock { clock },
            owner,
            signer,
            channel,
        )
        .unwrap_or_else(|error| panic!("draining apply core rejected: {error:?}"));
        let mut service = RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning,
            channel,
        };
        let retire_request = signed_apply_request(
            &active_snapshot,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::EmptyDeactivate,
                operation: 0xe4,
                request_nonce: b"query-draining-retire-nonce",
                tenure_nonce: b"query-draining-retire-tenure",
                writer_epoch: 2,
                supersedes_epoch: 1,
                source_revision: 2,
                temporal_constraint: 0xe5,
                expected_active: ExpectedActive::Exact(active_slice_digest),
                ..ApplyRequestFixture::valid()
            },
        );
        assert!(matches!(
            service.handle_request(retire_request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Owner(
                    RuntimeReferenceMaterializationOwnerError::CallbackFailed
                ))
            ))
        ));
        let prepared = service
            .apply
            .snapshot()
            .state()
            .prepared
            .as_ref()
            .unwrap_or_else(|| panic!("draining fixture lost prepared operation"));
        assert_eq!(prepared.phase, PreparedPhase::HeadCommittedRetiringOld);
        assert!(prepared.retiring.is_some());
        assert!(matches!(
            service.apply.snapshot().state().live_materialization,
            LiveMaterialization::Draining { .. }
        ));
        (service, retire_request, channel)
    }

    fn active_loop_restart_fixture(
        socket_path: PathBuf,
        request_nonce: &'static [u8],
    ) -> (RuntimeJournalSnapshot, RuntimeCompiledInstallationFactsV1) {
        let started = started_service(socket_path);
        let initial = started.state.snapshot().clone();
        let request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce,
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xb4),
            digest(0xb5),
        )
        .unwrap_or_else(|error| panic!("active restart channel rejected: {error}"));
        let mut service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("active restart service rejected: {error}"));
        service
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("active restart apply failed: {error:?}"))
            .unwrap_or_else(|| panic!("active restart apply returned no PXRT"));
        assert!(matches!(
            service.apply.snapshot().state().live_materialization,
            LiveMaterialization::LiveReady { .. }
        ));
        (service.apply.snapshot().clone(), service.compiled)
    }

    fn higher_tenure_successor(
        current: &RuntimeJournalSnapshot,
        evidence_byte: u8,
    ) -> RuntimeJournalSnapshot {
        let fence = current
            .state()
            .writer_fence
            .unwrap_or_else(|| panic!("takeover fixture lost writer fence"));
        current
            .try_tenure_only_successor(RuntimeTenureAdmissionInput {
                expected_store_instance_id: *current.store_instance_id(),
                owner_target_fingerprint: *current.owner_target_fingerprint(),
                source_scope: fence.source_scope,
                writer: fence.writer,
                epoch: fence
                    .epoch
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("takeover epoch overflow")),
                supersedes_through_epoch: fence.epoch,
                proof_envelope_digest: digest(evidence_byte),
                tenure_nonce_identity: digest(evidence_byte.wrapping_add(1)),
                principal: fence.principal,
            })
            .unwrap_or_else(|error| panic!("takeover successor failed: {error:?}"))
    }

    fn assert_reserved_crash_generation_is_exact_zero(
        snapshot: &RuntimeJournalSnapshot,
        generation: u64,
    ) {
        let resources = snapshot
            .state()
            .owned_resources
            .iter()
            .filter(|resource| resource.generation == generation)
            .collect::<Vec<_>>();
        assert_eq!(resources.len(), 2, "reserved generation census changed");
        assert!(resources.iter().all(|resource| {
            resource.phase == ResourcePhase::ReservedAtCrashExactZero
                && resource.action_id.is_none()
                && resource.os_identity.is_none()
                && resource.workspace_identity.is_none()
                && resource.containment_identity.is_none()
                && resource.tombstone_evidence.is_some()
        }));
    }

    fn assert_owned_crash_generation_is_tombstoned(
        snapshot: &RuntimeJournalSnapshot,
        generation: u64,
    ) {
        let resources = snapshot
            .state()
            .owned_resources
            .iter()
            .filter(|resource| resource.generation == generation)
            .collect::<Vec<_>>();
        assert_eq!(resources.len(), 2, "owned generation census changed");
        assert!(resources.iter().all(|resource| {
            resource.phase == ResourcePhase::Terminal
                && resource.action_id.is_none()
                && resource.os_identity.is_some()
                && resource.workspace_identity.is_some()
                && resource.containment_identity.is_some()
                && resource.tombstone_evidence.is_some()
        }));
    }

    fn terminal_for_request<'a>(
        snapshot: &'a RuntimeJournalSnapshot,
        request: &ReferenceApplyRequestV1,
    ) -> &'a crate::runtime_journal::TerminalOperationRecord {
        let operation_id = request.control_commitment().control().operation_id();
        snapshot
            .state()
            .terminal_operations
            .iter()
            .find(|terminal| terminal.operation_id == *operation_id.as_bytes())
            .unwrap_or_else(|| panic!("restart terminal for operation is missing"))
    }

    fn signed_bootstrap_request(
        target: RuntimeHostId,
        scope: SourceScopeRef,
        signature_seed: [u8; 32],
    ) -> ReferenceBootstrapRequestV1 {
        let auth = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("auth algorithm rejected: {error}")),
            ED25519_ALGORITHM_VERSION,
            b"endpoint-test-nonce",
        )
        .unwrap_or_else(|error| panic!("auth claim rejected: {error}"));
        let draft = ReferenceBootstrapRequestDraftV1::try_new(
            ReferenceBootstrapRequestIdV1::from_bytes([0x71; 16]),
            target,
            scope,
            auth,
            u32::try_from(MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES)
                .unwrap_or_else(|_| panic!("response bound exceeds u32")),
        )
        .unwrap_or_else(|error| panic!("bootstrap draft rejected: {error}"));
        let signer = SigningKey::from_bytes(&signature_seed);
        let signature = signer
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("request transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("request finalization failed: {error}"))
    }

    #[derive(Clone, Copy)]
    struct QueryRequestFixture {
        query: u8,
        target: RuntimeHostId,
        scope: SourceScopeRef,
        store: [u8; 32],
        operation: u8,
        expected_request_digest: Option<Digest32>,
        nonce: &'static [u8],
        controller_seed: [u8; 32],
        max_response_bytes: u32,
    }

    impl QueryRequestFixture {
        fn fresh(operation: u8) -> Self {
            Self {
                query: 0x81,
                target: TARGET,
                scope: SOURCE_SCOPE,
                store: STORE_INSTANCE_ID,
                operation,
                expected_request_digest: None,
                nonce: b"endpoint-query-nonce",
                controller_seed: CONTROLLER_SEED,
                max_response_bytes: u32::try_from(MAX_REFERENCE_QUERY_RESPONSE_BYTES)
                    .unwrap_or_else(|_| panic!("query response bound exceeds u32")),
            }
        }
    }

    fn signed_query_request(fixture: QueryRequestFixture) -> ReferenceQueryRequestV1 {
        let selector = ReferenceQuerySelectorV1::try_new(
            ReferenceQueryIdV1::from_bytes([fixture.query; 16]),
            fixture.target,
            fixture.scope,
            fixture.store,
            ApplyOperationId::from_bytes([fixture.operation; 16]),
            fixture.expected_request_digest,
        )
        .unwrap_or_else(|error| panic!("query selector rejected: {error}"));
        let claim = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("query algorithm rejected: {error}")),
            ED25519_ALGORITHM_VERSION,
            fixture.nonce,
        )
        .unwrap_or_else(|error| panic!("query claim rejected: {error}"));
        let draft =
            ReferenceQueryRequestDraftV1::try_new(selector, claim, fixture.max_response_bytes)
                .unwrap_or_else(|error| panic!("query draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&fixture.controller_seed)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("query transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("query finalization failed: {error}"))
    }

    fn independent_query_serving(
        snapshot: &RuntimeJournalSnapshot,
    ) -> ReferenceBootstrapServingIdentityV1 {
        ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            *snapshot.store_instance_id(),
            snapshot.sequence(),
            snapshot.state().host.runtime_host_epoch_high_water,
            ClockDomainRef::from_bytes(snapshot.state().host.clock_domain),
            ClockGeneration::try_new(snapshot.state().host.clock_generation_high_water)
                .unwrap_or_else(|error| panic!("query baseline clock rejected: {error}")),
        )
        .unwrap_or_else(|error| panic!("query serving baseline rejected: {error}"))
    }

    fn decode_verify_query_response(
        response_wire: &[u8],
        request: &ReferenceQueryRequestV1,
        channel: ReferenceChannelBindingV1,
        expected_serving: ReferenceBootstrapServingIdentityV1,
    ) -> (ReferenceQueryResponseV1, ReferenceQueryFactsV1) {
        let response = ReferenceQueryResponseV1::decode(response_wire)
            .unwrap_or_else(|error| panic!("PXQS decode failed: {error}"));
        let signature: [u8; ED25519_SIGNATURE_BYTES] = response
            .authentication_signature()
            .try_into()
            .unwrap_or_else(|_| panic!("PXQS signature width changed"));
        SigningKey::from_bytes(&RESPONSE_SEED)
            .verifying_key()
            .verify_strict(
                response
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("PXQS transcript failed: {error}"))
                    .as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .unwrap_or_else(|error| panic!("PXQS signature failed: {error}"));
        let facts = response
            .validate_against_request(request, channel, expected_serving)
            .unwrap_or_else(|error| panic!("PXQS correlation failed: {error}"));
        (response, facts)
    }

    #[derive(Clone, Copy)]
    struct ApplyRequestFixture {
        mode: ReferenceAssemblyModeV1,
        operation: u8,
        request_nonce: &'static [u8],
        tenure_nonce: &'static [u8],
        writer_epoch: u64,
        supersedes_epoch: u64,
        source_revision: u64,
        temporal_constraint: u8,
        expected_active: ExpectedActive,
        expected_store: [u8; 32],
        clock_generation: u64,
        controller_seed: [u8; 32],
        tenure_seed: [u8; 32],
    }

    impl ApplyRequestFixture {
        const fn valid() -> Self {
            Self {
                mode: ReferenceAssemblyModeV1::EmptyDeactivate,
                operation: 0x91,
                request_nonce: b"endpoint-apply-nonce",
                tenure_nonce: b"endpoint-tenure-nonce",
                writer_epoch: 1,
                supersedes_epoch: 0,
                source_revision: 1,
                temporal_constraint: 0x94,
                expected_active: ExpectedActive::None,
                expected_store: STORE_INSTANCE_ID,
                clock_generation: 1,
                controller_seed: CONTROLLER_SEED,
                tenure_seed: TENURE_SEED,
            }
        }
    }

    fn signed_apply_request(
        snapshot: &RuntimeJournalSnapshot,
        fixture: ApplyRequestFixture,
    ) -> ReferenceApplyRequestV1 {
        let manifest = verify_immutable_manifest_ingress(
            &snapshot.state().host.singleton_manifest.canonical_bytes,
            snapshot.state().host.singleton_manifest.digest,
        )
        .unwrap_or_else(|error| panic!("manifest ingress failed: {error}"));
        let execution = match fixture.mode {
            ReferenceAssemblyModeV1::OneSourceLoop => {
                let budgets = ValidatedReferenceLifecycleBudgetsV1::try_new(
                    BoundedDuration::from_nanos(1_000_000_000),
                    BoundedDuration::from_nanos(1_000_000_000),
                    BoundedDuration::from_nanos(1_000_000_000),
                )
                .unwrap_or_else(|error| panic!("lifecycle budgets failed: {error}"));
                ReferenceTargetExecutionPlanV4::try_one_source_loop(
                    &manifest,
                    InstanceRef::from_bytes([0x95; 16]),
                    DomainRef::from_bytes([0x96; 16]),
                    budgets,
                )
                .unwrap_or_else(|error| panic!("one-source PXTE failed: {error}"))
            }
            ReferenceAssemblyModeV1::EmptyDeactivate => {
                ReferenceTargetExecutionPlanV4::try_empty_deactivate(&manifest)
                    .unwrap_or_else(|error| panic!("empty PXTE failed: {error}"))
            }
        };

        let tenure_authority = TenureProofAuthority::try_new(
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            TenureProofAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("tenure algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("tenure authority failed: {error}"));
        let epoch = PlanWriterEpoch::new(fixture.writer_epoch);
        let tenure_claim = WriterTenureClaim::try_new(
            SOURCE_SCOPE,
            WRITER,
            epoch,
            PlanWriterEpoch::new(fixture.supersedes_epoch),
        )
        .unwrap_or_else(|error| panic!("tenure claim failed: {error}"));
        let unsigned_tenure = WriterTenureProof::try_new(
            tenure_authority,
            tenure_claim,
            fixture.tenure_nonce,
            &[1; ED25519_SIGNATURE_BYTES],
        )
        .unwrap_or_else(|error| panic!("tenure draft failed: {error}"));
        let tenure_signature = SigningKey::from_bytes(&fixture.tenure_seed)
            .sign(
                unsigned_tenure
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("tenure transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        let tenure = WriterTenureProof::try_new(
            tenure_authority,
            tenure_claim,
            fixture.tenure_nonce,
            &tenure_signature,
        )
        .unwrap_or_else(|error| panic!("signed tenure failed: {error}"));
        let writer = PlanWriterContext::try_new(WRITER, epoch, tenure)
            .unwrap_or_else(|error| panic!("writer context failed: {error}"));
        let control = RuntimeApplyControl::new(
            writer,
            fixture.expected_active,
            ApplyOperationId::from_bytes([fixture.operation; 16]),
        );
        let provenance = PlanProvenance::new(
            SOURCE_SCOPE,
            SourcePlanRef::from_bytes([0x92; 16]),
            SourcePlanRevision::new(fixture.source_revision),
            SourcePlanDigest::new(digest(0x93)),
        );
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([fixture.temporal_constraint; 16]),
            ClockDomainRef::from_bytes(CLOCK_DOMAIN),
            ClockGeneration::try_new(fixture.clock_generation)
                .unwrap_or_else(|error| panic!("clock generation failed: {error}")),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
        )
        .unwrap_or_else(|error| panic!("temporal constraint failed: {error}"));
        let auth = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("auth algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
            fixture.request_nonce,
        )
        .unwrap_or_else(|error| panic!("apply auth claim failed: {error}"));
        let draft = ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            temporal,
            fixture.expected_store,
            auth,
        )
        .unwrap_or_else(|error| panic!("PXAR draft failed: {error}"));
        let request_signature = SigningKey::from_bytes(&fixture.controller_seed)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("PXAR transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&request_signature)
            .unwrap_or_else(|error| panic!("signed PXAR failed: {error}"))
    }

    #[test]
    fn startup_commit_is_required_before_a_service_capability_exists() {
        let socket_path = PathBuf::from("/tmp/paraegox-startup-order-test.sock");
        let provisioning = provisioning(socket_path.clone());
        let (snapshot, compiled) = installed_snapshot(&provisioning);
        let attempts = Rc::new(Cell::new(0));
        let result = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot,
                commit_attempts: Rc::clone(&attempts),
                fail_commit: true,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning,
        );
        assert!(matches!(
            result,
            Err(RuntimeBootstrapEndpointError::Runtime)
        ));
        assert_eq!(attempts.get(), 1);
        assert!(!socket_path.exists());
    }

    #[test]
    fn restart_reassembles_live_loop_before_socket_capability_exists() {
        let socket_path = PathBuf::from("/tmp/paraegox-restart-reassembly-order-test.sock");
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"restart-reassembly-active-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x74),
            digest(0x75),
        )
        .unwrap_or_else(|error| panic!("restart channel rejected: {error}"));
        let mut active = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("active service rejected: {error}"));
        active
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("active apply failed: {error:?}"))
            .unwrap_or_else(|| panic!("active apply returned no PXRT"));
        let old_epoch = active
            .apply
            .snapshot()
            .state()
            .host
            .runtime_host_epoch_high_water;
        let snapshot = active.apply.snapshot().clone();
        let compiled = active.compiled;
        drop(active);

        let attempts = Rc::new(Cell::new(0));
        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot,
                commit_attempts: Rc::clone(&attempts),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("restart reassembly failed: {error}"));
        let state = restarted.state.snapshot().state();
        assert_eq!(state.host.runtime_host_epoch_high_water, old_epoch + 1);
        match state.live_materialization {
            LiveMaterialization::LiveReady {
                runtime_host_epoch, ..
            } => assert_eq!(runtime_host_epoch, old_epoch + 1),
            other => panic!("restart did not publish current-epoch Ready: {other:?}"),
        }
        assert!(state.recovery_action.is_none());
        assert_eq!(state.recovery_terminals.len(), 1);
        assert!(state.owned_resources.iter().all(|resource| {
            resource.phase == ResourcePhase::Terminal
                || resource.runtime_host_epoch == old_epoch + 1
        }));
        assert!(attempts.get() >= 9, "all reassembly steps must be durable");
        assert!(!socket_path.exists());
    }

    #[test]
    fn restart_after_durable_recovery_intent_never_replays_start() {
        let socket_path = PathBuf::from("/tmp/paraegox-recovery-intent-crash-test.sock");
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"recovery-intent-crash-active-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x76),
            digest(0x77),
        )
        .unwrap_or_else(|error| panic!("crash channel rejected: {error}"));
        let mut active = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("crash active service rejected: {error}"));
        active
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("crash active apply failed: {error:?}"))
            .unwrap_or_else(|| panic!("crash active apply returned no PXRT"));
        let snapshot = active.apply.snapshot().clone();
        let compiled = active.compiled;
        drop(active);

        let durable_snapshot = Rc::new(RefCell::new(snapshot.clone()));
        let attempts = Rc::new(Cell::new(0));
        let first_restart = StartedRuntimeBootstrapService::try_start(
            StartupCrashStore {
                snapshot,
                durable_snapshot: Rc::clone(&durable_snapshot),
                commit_attempts: Rc::clone(&attempts),
                // startup, old cleanup begin/tombstone, recovery plan, intent
                fail_after_publish_on: 5,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        );
        assert!(matches!(
            first_restart,
            Err(RuntimeBootstrapEndpointError::RestartReassembly(
                RuntimeRestartReassemblyError::Store(_)
            ))
        ));
        let post_intent = durable_snapshot.borrow().clone();
        assert!(post_intent.state().recovery_action.is_some_and(|recovery| {
            recovery.phase == RecoveryPhase::StartCallIntent && recovery.raw_outcome.is_none()
        }));
        assert!(
            post_intent
                .state()
                .owned_resources
                .iter()
                .all(|resource| { resource.phase == ResourcePhase::Terminal })
        );

        let second_attempts = Rc::new(Cell::new(0));
        let recovered = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: post_intent,
                commit_attempts: Rc::clone(&second_attempts),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("post-intent recovery failed: {error}"));
        assert!(matches!(
            recovered.state.snapshot().state().live_materialization,
            LiveMaterialization::RecoveryFailedNotReady { .. }
        ));
        assert!(recovered.state.snapshot().state().recovery_action.is_none());
        assert_eq!(second_attempts.get(), 2);

        let terminal_count = recovered.state.snapshot().state().recovery_terminals.len();
        let final_snapshot = recovered.state.snapshot().clone();
        let third = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: final_snapshot,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("permanent failure reopen failed: {error}"));
        assert_eq!(
            third.state.snapshot().state().recovery_terminals.len(),
            terminal_count
        );
        assert!(matches!(
            third.state.snapshot().state().live_materialization,
            LiveMaterialization::StartupInvalidated { .. }
        ));
        assert!(!socket_path.exists());
    }

    #[test]
    fn production_restart_closes_every_recovery_commit_boundary_without_callback_replay() {
        let fixture_path = PathBuf::from("/tmp/paraegox-recovery-boundary-fixture.sock");
        reset_fixed_owner_callback_actions_for_test();
        let (active_snapshot, compiled) = active_loop_restart_fixture(
            fixture_path.clone(),
            b"production-recovery-boundary-active-nonce",
        );

        // Startup reassembly publishes, in order: invalidation, old cleanup
        // begin, old tombstones, recovery plan, start intent, reservations,
        // ownership, callback latch, and Ready.
        for boundary in 1..=9_u32 {
            reset_fixed_owner_callback_actions_for_test();
            // The socket path is part of the immutable channel-policy pin, so
            // every reopen of this one installed snapshot uses the exact path
            // with which the fixture was initialized.
            let socket_path = fixture_path.clone();
            let durable_snapshot = Rc::new(RefCell::new(active_snapshot.clone()));
            let attempts = Rc::new(Cell::new(0));
            let interrupted = StartedRuntimeBootstrapService::try_start(
                StartupCrashStore {
                    snapshot: active_snapshot.clone(),
                    durable_snapshot: Rc::clone(&durable_snapshot),
                    commit_attempts: Rc::clone(&attempts),
                    fail_after_publish_on: boundary,
                    socket_path: socket_path.clone(),
                },
                compiled,
                provisioning(socket_path.clone()),
            );
            let error = match interrupted {
                Err(error) => error,
                Ok(_) => panic!("boundary {boundary} did not crash"),
            };
            assert_eq!(
                attempts.get(),
                boundary,
                "boundary {boundary} failed at the wrong stage: {error}"
            );
            assert!(!socket_path.exists());

            let crashed = durable_snapshot.borrow().clone();
            let crashed_recovery = crashed.state().recovery_action.or_else(|| {
                crashed
                    .state()
                    .recovery_terminals
                    .last()
                    .map(|value| value.recovery)
            });
            let callback_actions_before_restart = fixed_owner_start_callback_actions_for_test();
            if boundary <= 7 {
                assert!(callback_actions_before_restart.is_empty());
            } else {
                let action = crashed_recovery
                    .unwrap_or_else(|| panic!("boundary {boundary} lost recovery action"))
                    .action
                    .action_id;
                assert_eq!(callback_actions_before_restart, vec![action]);
            }
            if boundary == 8 {
                assert!(crashed.state().recovery_action.is_some_and(|recovery| {
                    recovery.phase == RecoveryPhase::StartCallIntent
                        && recovery
                            .raw_outcome
                            .is_some_and(|raw| raw.callback == CallbackOutcome::KnownSuccess)
                }));
            }

            let restarted = StartedRuntimeBootstrapService::try_start(
                MockStore {
                    snapshot: crashed,
                    commit_attempts: Rc::new(Cell::new(0)),
                    fail_commit: false,
                    socket_path: socket_path.clone(),
                },
                compiled,
                provisioning(socket_path.clone()),
            )
            .unwrap_or_else(|error| {
                panic!("boundary {boundary} production restart failed: {error}")
            });
            assert!(!socket_path.exists());
            let recovered = restarted.state.snapshot();
            let callback_actions_after_restart = fixed_owner_start_callback_actions_for_test();

            match boundary {
                1..=3 => {
                    assert!(matches!(
                        recovered.state().live_materialization,
                        LiveMaterialization::LiveReady { .. }
                    ));
                    assert_eq!(callback_actions_after_restart.len(), 1);
                }
                4 => {
                    let crashed_recovery =
                        crashed_recovery.unwrap_or_else(|| panic!("plan action missing"));
                    assert!(matches!(
                        recovered.state().live_materialization,
                        LiveMaterialization::LiveReady { .. }
                    ));
                    assert_eq!(callback_actions_after_restart.len(), 1);
                    assert_ne!(
                        callback_actions_after_restart[0], crashed_recovery.action.action_id,
                        "invalidated pre-intent action was replayed"
                    );
                    assert!(recovered.state().recovery_terminals.iter().any(|terminal| {
                        terminal.recovery.action.action_id == crashed_recovery.action.action_id
                            && terminal.selection.primary
                                == TerminalOutcome::AbortedBeforeIntentNoEffects
                    }));
                }
                5..=8 => {
                    let crashed_recovery = crashed_recovery
                        .unwrap_or_else(|| panic!("post-intent action missing at {boundary}"));
                    assert!(matches!(
                        recovered.state().live_materialization,
                        LiveMaterialization::RecoveryFailedNotReady { .. }
                    ));
                    assert_eq!(
                        callback_actions_after_restart, callback_actions_before_restart,
                        "post-intent callback was replayed at boundary {boundary}"
                    );
                    let terminal = recovered
                        .state()
                        .recovery_terminals
                        .iter()
                        .find(|terminal| {
                            terminal.recovery.action.action_id == crashed_recovery.action.action_id
                        })
                        .unwrap_or_else(|| panic!("post-intent terminal missing at {boundary}"));
                    assert_eq!(
                        terminal.selection.primary,
                        TerminalOutcome::AbortedBeforeHeadCommitExactZero
                    );
                    if boundary == 8 {
                        assert_eq!(
                            terminal.selection.raw.callback,
                            CallbackOutcome::KnownSuccess
                        );
                    }
                    if boundary == 6 {
                        assert_reserved_crash_generation_is_exact_zero(
                            recovered,
                            crashed_recovery.action.resource_generation,
                        );
                    }
                    if boundary >= 7 {
                        assert_owned_crash_generation_is_tombstoned(
                            recovered,
                            crashed_recovery.action.resource_generation,
                        );
                    }
                }
                9 => {
                    let completed = crashed_recovery
                        .unwrap_or_else(|| panic!("published recovery action missing"));
                    assert!(matches!(
                        recovered.state().live_materialization,
                        LiveMaterialization::LiveReady { .. }
                    ));
                    assert_eq!(callback_actions_after_restart.len(), 2);
                    assert_eq!(
                        callback_actions_after_restart[0],
                        completed.action.action_id
                    );
                    assert_ne!(
                        callback_actions_after_restart[1],
                        completed.action.action_id
                    );
                    assert_owned_crash_generation_is_tombstoned(
                        recovered,
                        completed.action.resource_generation,
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn restart_terminalizes_normal_start_intent_without_replaying_callback() {
        let socket_path = PathBuf::from("/tmp/paraegox-normal-start-intent-crash-test.sock");
        let initial_provisioning = provisioning(socket_path.clone());
        let (snapshot, compiled) = installed_snapshot(&initial_provisioning);
        let durable_snapshot = Rc::new(RefCell::new(snapshot.clone()));
        let started = StartedRuntimeBootstrapService::try_start(
            StartupCrashStore {
                snapshot,
                durable_snapshot: Rc::clone(&durable_snapshot),
                commit_attempts: Rc::new(Cell::new(0)),
                // startup, tenure, full admission, normal FirstActionIntent
                fail_after_publish_on: 4,
                socket_path: socket_path.clone(),
            },
            compiled,
            initial_provisioning,
        )
        .unwrap_or_else(|error| panic!("normal crash startup failed: {error}"));
        let initial = started.state.snapshot().clone();
        let request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"normal-start-intent-crash-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x78),
            digest(0x79),
        )
        .unwrap_or_else(|error| panic!("normal crash channel rejected: {error}"));
        let mut service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("normal crash service failed: {error}"));
        assert!(matches!(
            service.handle_request(request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Store(_))
            ))
        ));
        drop(service);
        let post_intent = durable_snapshot.borrow().clone();
        assert!(
            post_intent
                .state()
                .prepared
                .as_ref()
                .is_some_and(|prepared| { prepared.phase == PreparedPhase::FirstActionIntent })
        );
        assert!(post_intent.state().owned_resources.is_empty());

        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: post_intent,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("normal post-intent restart failed: {error}"));
        let state = restarted.state.snapshot().state();
        assert!(state.prepared.is_none());
        assert!(state.owned_resources.is_empty());
        assert_eq!(
            state
                .terminal_operations
                .last()
                .unwrap_or_else(|| panic!("normal crash terminal missing"))
                .selection
                .primary,
            crate::runtime_journal::TerminalOutcome::AbortedBeforeHeadCommitExactZero
        );
        assert!(matches!(
            state.live_materialization,
            LiveMaterialization::None
        ));
        assert!(!socket_path.exists());
    }

    #[test]
    fn production_restart_closes_normal_intent_reserved_and_owned_boundaries() {
        // A fresh process start is commit one; normal start then publishes
        // tenure, admission, intent, reservations, ownership, and terminal.
        for boundary in [4_u32, 5, 6] {
            reset_fixed_owner_callback_actions_for_test();
            let socket_path =
                PathBuf::from(format!("/tmp/paraegox-normal-boundary-{boundary}.sock"));
            let initial_provisioning = provisioning(socket_path.clone());
            let (snapshot, compiled) = installed_snapshot(&initial_provisioning);
            let durable_snapshot = Rc::new(RefCell::new(snapshot.clone()));
            let attempts = Rc::new(Cell::new(0));
            let started = StartedRuntimeBootstrapService::try_start(
                StartupCrashStore {
                    snapshot,
                    durable_snapshot: Rc::clone(&durable_snapshot),
                    commit_attempts: Rc::clone(&attempts),
                    fail_after_publish_on: boundary,
                    socket_path: socket_path.clone(),
                },
                compiled,
                initial_provisioning,
            )
            .unwrap_or_else(|error| panic!("boundary {boundary} startup failed: {error}"));
            let initial = started.state.snapshot().clone();
            let request = signed_apply_request(
                &initial,
                ApplyRequestFixture {
                    mode: ReferenceAssemblyModeV1::OneSourceLoop,
                    request_nonce: match boundary {
                        4 => b"normal-boundary-intent-nonce",
                        5 => b"normal-boundary-reserved-nonce",
                        6 => b"normal-boundary-owned-nonce",
                        _ => unreachable!(),
                    },
                    ..ApplyRequestFixture::valid()
                },
            );
            let channel = ReferenceChannelBindingV1::try_new(
                TARGET,
                RUNTIME_PRINCIPAL,
                digest(0xc4),
                digest(boundary as u8),
            )
            .unwrap_or_else(|error| panic!("normal boundary channel rejected: {error}"));
            let mut service = started
                .into_control_service(channel)
                .unwrap_or_else(|error| panic!("normal boundary service failed: {error}"));
            assert!(matches!(
                service.handle_request(request.canonical_wire(), channel),
                Err(RuntimeControlRequestError::Internal(
                    RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Store(_))
                ))
            ));
            drop(service);
            assert_eq!(attempts.get(), boundary);
            assert!(fixed_owner_start_callback_actions_for_test().is_empty());
            assert!(!socket_path.exists());

            let crashed = durable_snapshot.borrow().clone();
            let prepared = crashed
                .state()
                .prepared
                .as_ref()
                .unwrap_or_else(|| panic!("boundary {boundary} lost prepared action"));
            let action = prepared
                .action
                .unwrap_or_else(|| panic!("boundary {boundary} lost action identity"));
            assert_eq!(prepared.phase, PreparedPhase::FirstActionIntent);
            match boundary {
                4 => assert!(crashed.state().owned_resources.is_empty()),
                5 => assert!(crashed.state().owned_resources.iter().all(|resource| {
                    resource.generation == action.resource_generation
                        && resource.phase == ResourcePhase::Reserved
                        && resource.os_identity.is_none()
                        && resource.workspace_identity.is_none()
                        && resource.containment_identity.is_none()
                })),
                6 => assert!(crashed.state().owned_resources.iter().all(|resource| {
                    resource.generation == action.resource_generation
                        && resource.phase == ResourcePhase::Owned
                        && resource.os_identity.is_some()
                        && resource.workspace_identity.is_some()
                        && resource.containment_identity.is_some()
                })),
                _ => unreachable!(),
            }

            let restarted = StartedRuntimeBootstrapService::try_start(
                MockStore {
                    snapshot: crashed,
                    commit_attempts: Rc::new(Cell::new(0)),
                    fail_commit: false,
                    socket_path: socket_path.clone(),
                },
                compiled,
                provisioning(socket_path.clone()),
            )
            .unwrap_or_else(|error| panic!("normal boundary {boundary} restart failed: {error}"));
            let recovered = restarted.state.snapshot();
            assert!(!socket_path.exists());
            assert!(recovered.state().prepared.is_none());
            assert!(matches!(
                recovered.state().live_materialization,
                LiveMaterialization::None
            ));
            let terminal = terminal_for_request(recovered, &request);
            assert_eq!(
                terminal.selection.primary,
                TerminalOutcome::AbortedBeforeHeadCommitExactZero
            );
            let receipt = ReferenceApplyTerminalReceiptV1::decode(
                &terminal.canonical_response.canonical_bytes,
            )
            .unwrap_or_else(|error| panic!("restart PXRT decode failed: {error}"));
            assert_eq!(
                receipt.authentication_channel_binding_digest(),
                channel.binding_digest(),
                "restart PXRT did not retain the admitted historical channel"
            );
            // The durable intent makes callback truth conservative after a
            // real process loss; the test-only owner trace proves this
            // particular restart did not invoke the old action again.
            assert_eq!(
                terminal.selection.raw.callback,
                CallbackOutcome::UnknownAfterIntent
            );
            assert!(fixed_owner_start_callback_actions_for_test().is_empty());
            if boundary == 5 {
                assert_reserved_crash_generation_is_exact_zero(
                    recovered,
                    action.resource_generation,
                );
            }
            if boundary == 6 {
                assert_owned_crash_generation_is_tombstoned(recovered, action.resource_generation);
            }
        }
    }

    #[test]
    fn higher_tenure_normal_start_restart_terminalizes_superseded_exact_zero() {
        reset_fixed_owner_callback_actions_for_test();
        let socket_path = PathBuf::from("/tmp/paraegox-normal-takeover-restart.sock");
        let initial_provisioning = provisioning(socket_path.clone());
        let (snapshot, compiled) = installed_snapshot(&initial_provisioning);
        let durable_snapshot = Rc::new(RefCell::new(snapshot.clone()));
        let started = StartedRuntimeBootstrapService::try_start(
            StartupCrashStore {
                snapshot,
                durable_snapshot: Rc::clone(&durable_snapshot),
                commit_attempts: Rc::new(Cell::new(0)),
                // startup, tenure, admission, intent, reserve, ownership
                fail_after_publish_on: 6,
                socket_path: socket_path.clone(),
            },
            compiled,
            initial_provisioning,
        )
        .unwrap_or_else(|error| panic!("normal takeover startup failed: {error}"));
        let request = signed_apply_request(
            started.state.snapshot(),
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"normal-takeover-restart-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xd4),
            digest(0xd5),
        )
        .unwrap_or_else(|error| panic!("normal takeover channel rejected: {error}"));
        let mut service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("normal takeover service failed: {error}"));
        assert!(matches!(
            service.handle_request(request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Store(_))
            ))
        ));
        drop(service);
        assert!(fixed_owner_start_callback_actions_for_test().is_empty());

        let owned = durable_snapshot.borrow().clone();
        let action = owned
            .state()
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.action)
            .unwrap_or_else(|| panic!("normal takeover action missing"));
        let takeover = higher_tenure_successor(&owned, 0xd6);
        assert!(takeover.state().prepared.as_ref().is_some_and(|prepared| {
            prepared.phase == PreparedPhase::SupersededReconcileRequired
                && prepared
                    .raw_outcome
                    .is_some_and(|raw| raw.higher_tenure_takeover)
        }));

        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: takeover,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("normal takeover restart failed: {error}"));
        let recovered = restarted.state.snapshot();
        assert!(!socket_path.exists());
        assert!(recovered.state().prepared.is_none());
        assert!(matches!(
            recovered.state().live_materialization,
            LiveMaterialization::None
        ));
        let terminal = terminal_for_request(recovered, &request);
        assert_eq!(
            terminal.selection.primary,
            TerminalOutcome::SupersededAfterIntentExactZero
        );
        assert!(terminal.selection.raw.higher_tenure_takeover);
        let receipt =
            ReferenceApplyTerminalReceiptV1::decode(&terminal.canonical_response.canonical_bytes)
                .unwrap_or_else(|error| panic!("takeover PXRT decode failed: {error}"));
        assert_eq!(
            receipt.authentication_channel_binding_digest(),
            channel.binding_digest()
        );
        assert_eq!(
            terminal.selection.raw.callback,
            CallbackOutcome::UnknownAfterIntent
        );
        assert_owned_crash_generation_is_tombstoned(recovered, action.resource_generation);
        assert!(fixed_owner_start_callback_actions_for_test().is_empty());
    }

    #[test]
    fn production_restart_preserves_validated_quarantine_without_listener_or_callback() {
        let socket_path = PathBuf::from("/tmp/paraegox-quarantine-restart.sock");
        reset_fixed_owner_callback_actions_for_test();
        let (active, compiled) =
            active_loop_restart_fixture(socket_path.clone(), b"quarantine-restart-active-nonce");
        reset_fixed_owner_callback_actions_for_test();
        let old_generation = match active.state().live_materialization {
            LiveMaterialization::LiveReady {
                resource_generation,
                ..
            } => resource_generation,
            other => panic!("quarantine fixture not live: {other:?}"),
        };
        let invalidated = active
            .try_startup_invalidation_successor()
            .unwrap_or_else(|error| panic!("quarantine invalidation failed: {error:?}"));
        let quarantined = invalidated
            .try_operational_quarantine_successor(digest(0xda))
            .unwrap_or_else(|error| panic!("quarantine fixture failed: {error:?}"));
        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: quarantined,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("quarantine restart failed: {error}"));
        let recovered = restarted.state.snapshot();
        assert!(!socket_path.exists());
        assert!(matches!(
            recovered.state().live_materialization,
            LiveMaterialization::Quarantined { .. }
        ));
        assert_owned_crash_generation_is_tombstoned(recovered, old_generation);
        let live = query_live_projection(recovered, 1)
            .unwrap_or_else(|error| panic!("quarantine projection failed: {error}"));
        assert_eq!(
            live.state(),
            ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
        );
        assert_eq!(live.resource_generation(), 0);
        assert!(fixed_owner_start_callback_actions_for_test().is_empty());
        assert!(fixed_owner_stop_callback_actions_for_test().is_empty());
    }

    #[test]
    fn pre_intent_empty_crash_aborts_incoming_then_reassembles_old_loop() {
        let socket_path = PathBuf::from("/tmp/paraegox-empty-pre-intent-crash-test.sock");
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let active_request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"empty-pre-intent-old-loop-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x7a),
            digest(0x7b),
        )
        .unwrap_or_else(|error| panic!("empty pre-intent channel rejected: {error}"));
        let mut active_service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("empty pre-intent active service failed: {error}"));
        active_service
            .handle_request(active_request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("old loop apply failed: {error:?}"))
            .unwrap_or_else(|| panic!("old loop apply returned no PXRT"));
        let active_snapshot = active_service.apply.snapshot().clone();
        let active_slice_digest = match active_snapshot.state().live_materialization {
            LiveMaterialization::LiveReady {
                active_slice_digest,
                ..
            } => active_slice_digest,
            other => panic!("old loop not live before crash: {other:?}"),
        };
        let compiled = active_service.compiled;
        let compatibility = active_service.compatibility.clone();
        let clock = active_service.clock;
        drop(active_service);

        let durable_snapshot = Rc::new(RefCell::new(active_snapshot.clone()));
        let owner =
            RuntimeFixedReferenceMaterializationOwner::try_new(compiled, clock, &active_snapshot)
                .unwrap_or_else(|error| panic!("empty pre-intent owner failed: {error:?}"));
        let crash_provisioning = provisioning(socket_path.clone());
        let signer = RuntimeReferenceApplySigner::try_new(
            crash_provisioning.response_signer().clone(),
            crash_provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("empty signer algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("empty pre-intent signer failed: {error:?}"));
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            StartupCrashStore {
                snapshot: active_snapshot.clone(),
                durable_snapshot: Rc::clone(&durable_snapshot),
                commit_attempts: Rc::new(Cell::new(0)),
                // tenure then full admission; fail after PreparedNoEffects.
                fail_after_publish_on: 2,
                socket_path: socket_path.clone(),
            },
            RuntimeEndpointApplyClock { clock },
            owner,
            signer,
            channel,
        )
        .unwrap_or_else(|error| panic!("empty crash apply core failed: {error:?}"));
        let mut crash_service = RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning: crash_provisioning,
            channel,
        };
        let empty_request = signed_apply_request(
            &active_snapshot,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::EmptyDeactivate,
                operation: 0x7c,
                request_nonce: b"empty-pre-intent-incoming-nonce",
                tenure_nonce: b"empty-pre-intent-incoming-tenure",
                writer_epoch: 2,
                supersedes_epoch: 1,
                source_revision: 2,
                temporal_constraint: 0x7d,
                expected_active: ExpectedActive::Exact(active_slice_digest),
                ..ApplyRequestFixture::valid()
            },
        );
        assert!(matches!(
            crash_service.handle_request(empty_request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Store(_))
            ))
        ));
        drop(crash_service);
        let admitted = durable_snapshot.borrow().clone();
        assert!(
            admitted
                .state()
                .prepared
                .as_ref()
                .is_some_and(|prepared| { prepared.phase == PreparedPhase::PreparedNoEffects })
        );
        assert!(matches!(
            admitted.state().live_materialization,
            LiveMaterialization::LiveReady { .. }
        ));

        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: admitted,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path.clone()),
        )
        .unwrap_or_else(|error| panic!("empty pre-intent restart failed: {error}"));
        let state = restarted.state.snapshot().state();
        assert!(state.prepared.is_none());
        assert_eq!(
            state
                .terminal_operations
                .iter()
                .find(|terminal| {
                    terminal.operation_id
                        == *empty_request
                            .control_commitment()
                            .control()
                            .operation_id()
                            .as_bytes()
                })
                .unwrap_or_else(|| panic!("empty abort terminal missing"))
                .selection
                .primary,
            crate::runtime_journal::TerminalOutcome::AbortedBeforeIntentNoEffects
        );
        assert_eq!(state.recovery_terminals.len(), 1);
        assert!(matches!(
            state.live_materialization,
            LiveMaterialization::LiveReady { .. }
        ));
        assert!(!socket_path.exists());
    }

    #[test]
    fn authenticated_bootstrap_response_is_correlated_and_runtime_signed() {
        let started = started_service(PathBuf::from("/tmp/paraegox-bootstrap-core-test.sock"));
        assert_eq!(started.state.snapshot().sequence(), 2);
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x72),
            digest(0x73),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let request = signed_bootstrap_request(TARGET, SOURCE_SCOPE, CONTROLLER_SEED);
        let response_wire = started
            .bootstrap_core(channel)
            .unwrap_or_else(|error| panic!("bootstrap core rejected: {error}"))
            .handle_request(request.canonical_wire())
            .unwrap_or_else(|error| panic!("request rejected: {error:?}"));
        let response = ReferenceBootstrapResponseV1::decode(&response_wire)
            .unwrap_or_else(|error| panic!("response decode failed: {error}"));
        let signature: [u8; ED25519_SIGNATURE_BYTES] = response
            .authentication_signature()
            .try_into()
            .unwrap_or_else(|_| panic!("response signature width changed"));
        SigningKey::from_bytes(&RESPONSE_SEED)
            .verifying_key()
            .verify_strict(
                response
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("response transcript failed: {error}"))
                    .as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .unwrap_or_else(|error| panic!("Runtime response signature failed: {error}"));
        let facts = response
            .validate_against_request(&request, channel, &started.compatibility)
            .unwrap_or_else(|error| panic!("response correlation failed: {error}"));
        assert_eq!(facts.target(), TARGET);
        assert_eq!(facts.runtime_store_instance_id(), STORE_INSTANCE_ID);
        assert_eq!(facts.snapshot_sequence(), 2);
        assert_eq!(facts.runtime_host_epoch(), 1);
        assert_eq!(
            facts.clock_domain(),
            ClockDomainRef::from_bytes(CLOCK_DOMAIN)
        );
        assert_eq!(facts.clock_generation().value(), 1);
        assert_eq!(facts.state(), ReferenceBootstrapStateV1::ReadyForApply);
    }

    #[test]
    fn bootstrap_decoder_and_authentication_fail_before_any_mutation() {
        let started = started_service(PathBuf::from("/tmp/paraegox-bootstrap-reject-test.sock"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x74),
            digest(0x75),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let core = started
            .bootstrap_core(channel)
            .unwrap_or_else(|error| panic!("bootstrap core rejected: {error}"));
        let wrong_scope = signed_bootstrap_request(
            TARGET,
            SourceScopeRef::from_bytes([0x7a; 16]),
            CONTROLLER_SEED,
        );
        assert_eq!(
            core.handle_request(wrong_scope.canonical_wire()),
            Err(RuntimeBootstrapRequestError::Unauthorized)
        );
        let wrong_signature = signed_bootstrap_request(TARGET, SOURCE_SCOPE, [0x7b; 32]);
        assert_eq!(
            core.handle_request(wrong_signature.canonical_wire()),
            Err(RuntimeBootstrapRequestError::InvalidSignature)
        );
        assert_eq!(
            core.handle_request(b"PXAR-is-not-a-bootstrap-request"),
            Err(RuntimeBootstrapRequestError::InvalidCanonicalRequest)
        );
        assert_eq!(started.state.snapshot().sequence(), 2);
    }

    #[test]
    fn authenticated_query_returns_fresh_unknown_exact_zero_without_snapshot_mutation() {
        let started = started_service(PathBuf::from("/tmp/paraegox-query-core-test.sock"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x76),
            digest(0x77),
        )
        .unwrap_or_else(|error| panic!("query channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("query control service rejected: {error}"));
        let request = signed_query_request(QueryRequestFixture::fresh(0x82));
        let before = control.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(control.apply.snapshot());
        let response_wire = control
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("fresh query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("fresh query returned no PXQS"));
        assert_eq!(&response_wire[..4], b"PXQS");
        let (response, facts) =
            decode_verify_query_response(&response_wire, &request, channel, expected_serving);
        assert_eq!(facts.serving().target(), TARGET);
        assert_eq!(
            facts.serving().runtime_store_instance_id(),
            STORE_INSTANCE_ID
        );
        assert_eq!(
            facts.operation().owner_state(),
            ReferenceQueryOwnerStateV1::Operational
        );
        assert_eq!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Unknown
        );
        assert_eq!(facts.desired().head(), ReferenceQueryDesiredHeadV1::None);
        assert_eq!(facts.desired().source_revision_high_water().value(), 0);
        assert_eq!(facts.live().state(), ReferenceQueryLiveStateV1::ExactZero);
        assert_eq!(facts.live().resource_generation(), 0);
        assert_eq!(control.apply.snapshot().canonical_wire(), before);
        let wrong_epoch_serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            STORE_INSTANCE_ID,
            control.apply.snapshot().sequence(),
            control
                .apply
                .snapshot()
                .state()
                .host
                .runtime_host_epoch_high_water
                + 1,
            ClockDomainRef::from_bytes(CLOCK_DOMAIN),
            ClockGeneration::try_new(
                control
                    .apply
                    .snapshot()
                    .state()
                    .host
                    .clock_generation_high_water,
            )
            .unwrap_or_else(|error| panic!("wrong-epoch query clock rejected: {error}")),
        )
        .unwrap_or_else(|error| panic!("wrong-epoch query baseline rejected: {error}"));
        assert!(
            response
                .validate_against_request(&request, channel, wrong_epoch_serving)
                .is_err()
        );

        let invalid = [
            QueryRequestFixture {
                scope: SourceScopeRef::from_bytes([0x83; 16]),
                ..QueryRequestFixture::fresh(0x82)
            },
            QueryRequestFixture {
                target: RuntimeHostId::from_bytes([0x84; 16]),
                ..QueryRequestFixture::fresh(0x82)
            },
            QueryRequestFixture {
                store: [0x85; 32],
                ..QueryRequestFixture::fresh(0x82)
            },
            QueryRequestFixture {
                controller_seed: [0x86; 32],
                ..QueryRequestFixture::fresh(0x82)
            },
            QueryRequestFixture {
                max_response_bytes: 1,
                ..QueryRequestFixture::fresh(0x82)
            },
        ];
        for fixture in invalid {
            let invalid = signed_query_request(fixture);
            assert!(matches!(
                control.handle_request(invalid.canonical_wire(), channel),
                Err(RuntimeControlRequestError::Rejected)
            ));
            assert_eq!(control.apply.snapshot().canonical_wire(), before);
        }
        let wrong_channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x87),
            digest(0x88),
        )
        .unwrap_or_else(|error| panic!("wrong query channel rejected: {error}"));
        assert!(matches!(
            control.handle_request(request.canonical_wire(), wrong_channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        let mut trailing = request.canonical_wire().to_vec();
        trailing.push(0);
        assert!(matches!(
            control.handle_request(&trailing, channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        let mut oversized = vec![0_u8; MAX_REFERENCE_QUERY_REQUEST_BYTES + 1];
        oversized[..4].copy_from_slice(QUERY_REQUEST_MAGIC);
        assert!(matches!(
            control.handle_request(&oversized, channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert_eq!(control.apply.snapshot().canonical_wire(), before);
    }

    #[test]
    fn validated_operational_quarantine_returns_only_typed_indeterminate() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-quarantine-test.sock");
        let provisioning = provisioning(socket_path.clone());
        let (sequence_one, compiled) = installed_snapshot(&provisioning);
        let started_once = sequence_one
            .try_startup_invalidation_successor()
            .unwrap_or_else(|error| panic!("first startup invalidation failed: {error:?}"));
        let census = started_once
            .resource_census_digest()
            .unwrap_or_else(|error| panic!("quarantine census failed: {error:?}"));
        let mut quarantined_state = started_once.state().clone();
        quarantined_state.last_transaction =
            crate::runtime_journal::RuntimeJournalTransaction::Quarantine;
        quarantined_state.live_materialization = LiveMaterialization::Quarantined {
            active_slice_digest: None,
            reason_digest: digest(0x78),
            resource_census_digest: census,
        };
        let quarantined = RuntimeJournalSnapshot::try_new(
            *started_once.store_instance_id(),
            *started_once.owner_target_fingerprint(),
            started_once.sequence() + 1,
            quarantined_state,
        )
        .unwrap_or_else(|error| panic!("validated quarantine snapshot failed: {error:?}"));
        let started = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: quarantined,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            compiled,
            provisioning,
        )
        .unwrap_or_else(|error| panic!("validated quarantine startup failed: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x79),
            digest(0x7a),
        )
        .unwrap_or_else(|error| panic!("quarantine query channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("quarantine control service rejected: {error}"));
        let query = signed_query_request(QueryRequestFixture::fresh(0x7b));
        let before = control.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(control.apply.snapshot());
        let response = control
            .handle_request(query.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("quarantine query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("quarantine query returned no PXQS"));
        let (_, facts) = decode_verify_query_response(&response, &query, channel, expected_serving);
        assert_eq!(
            facts.operation().owner_state(),
            ReferenceQueryOwnerStateV1::OwnershipUncertain
        );
        assert_eq!(
            facts.operation().reason(),
            Some(ReferenceOperationalReasonV1::OwnershipUncertain)
        );
        assert_eq!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Indeterminate {
                reason: ReferenceOperationalReasonV1::OwnershipUncertain,
            }
        );
        assert_eq!(
            facts.live().state(),
            ReferenceQueryLiveStateV1::ValidatedOperationalQuarantine
        );
        assert_eq!(control.apply.snapshot().canonical_wire(), before);
    }

    #[test]
    fn signed_empty_pxar_returns_only_correlated_runtime_signed_pxrt_and_exact_replay() {
        let socket_path = PathBuf::from("/tmp/paraegox-apply-core-test.sock");
        let started = started_service(socket_path.clone());
        let request = signed_apply_request(started.state.snapshot(), ApplyRequestFixture::valid());
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xa1),
            digest(0xa2),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("control service rejected: {error}"));

        let response = control
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("valid PXAR rejected: {error:?}"))
            .unwrap_or_else(|| panic!("terminal apply returned no PXRT"));
        assert_eq!(&response[..4], b"PXRT");
        let receipt = ReferenceApplyTerminalReceiptV1::decode(&response)
            .unwrap_or_else(|error| panic!("PXRT decode failed: {error}"));
        let facts = receipt
            .validate_against_request(&request, channel)
            .unwrap_or_else(|error| panic!("PXRT correlation failed: {error}"));
        assert_eq!(
            facts.outcome(),
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        );
        let signature: [u8; ED25519_SIGNATURE_BYTES] = receipt
            .authentication_signature()
            .try_into()
            .unwrap_or_else(|_| panic!("PXRT signature width changed"));
        SigningKey::from_bytes(&RESPONSE_SEED)
            .verifying_key()
            .verify_strict(
                receipt
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("PXRT transcript failed: {error}"))
                    .as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .unwrap_or_else(|error| panic!("PXRT signature failed: {error}"));
        let terminal_sequence = control.apply.snapshot().sequence();

        let replay = control
            .handle_request(request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("exact replay rejected: {error:?}"))
            .unwrap_or_else(|| panic!("exact replay returned no PXRT"));
        assert_eq!(replay, response);
        assert_eq!(control.apply.snapshot().sequence(), terminal_sequence);

        // A restart advances the owner clock generation and changes the live
        // channel. Historical terminal replay still returns the original exact
        // PXRT bytes without installing a new deadline or requiring Ready.
        let terminal_snapshot = control.apply.snapshot().clone();
        drop(control);
        let compiled = compiled_facts();
        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: terminal_snapshot,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning(socket_path),
        )
        .unwrap_or_else(|error| panic!("restart rejected: {error}"));
        assert_eq!(
            restarted
                .state
                .bootstrap_facts()
                .map(|facts| facts.clock_generation()),
            Ok(2)
        );
        let restarted_channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xa3),
            digest(0xa4),
        )
        .unwrap_or_else(|error| panic!("restart channel rejected: {error}"));
        let mut restarted = restarted
            .into_control_service(restarted_channel)
            .unwrap_or_else(|error| panic!("restart control rejected: {error}"));
        let restarted_sequence = restarted.apply.snapshot().sequence();
        let historical = restarted
            .handle_request(request.canonical_wire(), restarted_channel)
            .unwrap_or_else(|error| panic!("historical replay rejected: {error:?}"))
            .unwrap_or_else(|| panic!("historical replay returned no PXRT"));
        assert_eq!(historical, response);
        assert_eq!(restarted.apply.snapshot().sequence(), restarted_sequence);
    }

    #[test]
    fn query_reports_terminal_known_conflict_unknown_and_current_live_ready() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-terminal-test.sock");
        let started = started_service(socket_path);
        let initial = started.state.snapshot().clone();
        let apply = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                operation: 0x88,
                request_nonce: b"queried-active-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x89),
            digest(0x8a),
        )
        .unwrap_or_else(|error| panic!("query terminal channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("query terminal control rejected: {error}"));
        control
            .handle_request(apply.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("queried apply rejected: {error:?}"))
            .unwrap_or_else(|| panic!("queried apply returned no PXRT"));
        let terminal_wire = control.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(control.apply.snapshot());

        let exact = signed_query_request(QueryRequestFixture {
            expected_request_digest: Some(apply.envelope_request_digest()),
            ..QueryRequestFixture::fresh(0x88)
        });
        let exact_response = control
            .handle_request(exact.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("exact terminal query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("exact terminal query returned no PXQS"));
        let (_, exact_facts) =
            decode_verify_query_response(&exact_response, &exact, channel, expected_serving);
        assert!(matches!(
            exact_facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Known {
                request_digest,
                durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                terminal_result: Some(_),
            } if request_digest == apply.envelope_request_digest()
        ));
        assert!(matches!(
            exact_facts.desired().head(),
            ReferenceQueryDesiredHeadV1::OneSourceLoop {
                source_revision,
                target_slice_digest,
                ..
            } if source_revision.value() == 1 && target_slice_digest == apply.target_slice_digest()
        ));
        assert_eq!(
            exact_facts.live().state(),
            ReferenceQueryLiveStateV1::LiveReady
        );
        assert!(exact_facts.live().resource_generation() > 0);

        let conflict = signed_query_request(QueryRequestFixture {
            query: 0x8b,
            expected_request_digest: Some(digest(0x8c)),
            ..QueryRequestFixture::fresh(0x88)
        });
        let conflict_response = control
            .handle_request(conflict.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("conflict query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("conflict query returned no PXQS"));
        let (_, conflict_facts) =
            decode_verify_query_response(&conflict_response, &conflict, channel, expected_serving);
        assert_eq!(
            conflict_facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Conflict {
                existing_request_digest: apply.envelope_request_digest(),
            }
        );

        let unknown = signed_query_request(QueryRequestFixture {
            query: 0x8d,
            ..QueryRequestFixture::fresh(0x8e)
        });
        let unknown_response = control
            .handle_request(unknown.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("unknown query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("unknown query returned no PXQS"));
        let (_, unknown_facts) =
            decode_verify_query_response(&unknown_response, &unknown, channel, expected_serving);
        assert_eq!(
            unknown_facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Unknown
        );
        assert_eq!(control.apply.snapshot().canonical_wire(), terminal_wire);
    }

    #[test]
    fn query_reports_durable_prepared_without_advancing_the_operation() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-prepared-test.sock");
        let started = started_service(socket_path.clone());
        let request = signed_apply_request(
            started.state.snapshot(),
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                operation: 0x8f,
                request_nonce: b"queried-prepared-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0x90),
            digest(0x91),
        )
        .unwrap_or_else(|error| panic!("prepared query channel rejected: {error}"));
        let journal = started
            .state
            .bootstrap_facts()
            .unwrap_or_else(|error| panic!("started facts rejected: {error:?}"));
        let generation = ClockGeneration::try_new(journal.clock_generation())
            .unwrap_or_else(|error| panic!("prepared clock rejected: {error}"));
        let clock = RuntimeClock::new(
            ClockDomainRef::from_bytes(journal.clock_domain()),
            generation,
            1,
        );
        let signer = RuntimeReferenceApplySigner::try_new(
            started.provisioning.response_signer().clone(),
            started.provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("prepared signer algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("prepared signer rejected: {error:?}"));
        let budgets = request
            .target_execution()
            .loop_facts()
            .unwrap_or_else(|| panic!("prepared request lost loop facts"))
            .budgets();
        let owner = FailingRetireOwner {
            active_slice_digest: TargetSliceDigest::new(digest(0x92)),
            resource_generation: 1,
            plan: RuntimeEmptyRetireOwnerPlan {
                action_id: [0x93; 16],
                signed_budgets: budgets,
            },
        };
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            started.store,
            RuntimeEndpointApplyClock { clock },
            owner,
            signer,
            channel,
        )
        .unwrap_or_else(|error| panic!("prepared apply core rejected: {error:?}"));
        let mut control = RuntimeControlService {
            apply,
            clock,
            compiled: started.compiled,
            compatibility: started.compatibility,
            provisioning: started.provisioning,
            channel,
        };
        assert!(matches!(
            control.handle_request(request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Owner(
                    RuntimeReferenceMaterializationOwnerError::Unavailable
                ))
            ))
        ));
        let prepared_wire = control.apply.snapshot().canonical_wire().to_vec();
        let query = signed_query_request(QueryRequestFixture {
            expected_request_digest: Some(request.envelope_request_digest()),
            ..QueryRequestFixture::fresh(0x8f)
        });
        let expected_serving = independent_query_serving(control.apply.snapshot());
        let response = control
            .handle_request(query.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("prepared query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("prepared query returned no PXQS"));
        let (_, facts) = decode_verify_query_response(&response, &query, channel, expected_serving);
        assert_eq!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Known {
                request_digest: request.envelope_request_digest(),
                durable_phase: ReferenceQueryDurablePhaseV1::PreparedNoEffects,
                terminal_result: None,
            }
        );
        assert_eq!(facts.live().state(), ReferenceQueryLiveStateV1::NotReady);
        assert_eq!(control.apply.snapshot().canonical_wire(), prepared_wire);

        // A structurally valid PXAR signed by the wrong Controller key can be
        // represented by the owner journal, but startup must authenticate it
        // before advancing the host generation or exposing a listener.
        let invalid_request = signed_apply_request(
            control.apply.snapshot(),
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                operation: 0x8f,
                request_nonce: b"queried-prepared-nonce",
                controller_seed: [0x94; 32],
                ..ApplyRequestFixture::valid()
            },
        );
        let old_digest = request.envelope_request_digest();
        let mut invalid_state = control.apply.snapshot().state().clone();
        invalid_state
            .prepared
            .as_mut()
            .unwrap_or_else(|| panic!("prepared state disappeared"))
            .request = OpaqueCanonicalValue::try_request_or_slice(
            invalid_request.canonical_wire(),
            invalid_request.envelope_request_digest(),
        )
        .unwrap_or_else(|error| panic!("invalid signed request pin failed: {error:?}"));
        invalid_state
            .host
            .request_nonces
            .iter_mut()
            .find(|record| record.value_digest == old_digest)
            .unwrap_or_else(|| panic!("prepared request nonce record disappeared"))
            .value_digest = invalid_request.envelope_request_digest();
        let invalid_snapshot = RuntimeJournalSnapshot::try_new(
            *control.apply.snapshot().store_instance_id(),
            *control.apply.snapshot().owner_target_fingerprint(),
            control.apply.snapshot().sequence(),
            invalid_state,
        )
        .unwrap_or_else(|error| {
            panic!("structural invalid-signature snapshot rejected: {error:?}")
        });
        let attempts = Rc::new(Cell::new(0));
        let result = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: invalid_snapshot,
                commit_attempts: Rc::clone(&attempts),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled_facts(),
            provisioning(socket_path.clone()),
        );
        assert!(matches!(
            result,
            Err(RuntimeBootstrapEndpointError::InvalidStartedState)
        ));
        assert_eq!(attempts.get(), 0);
        assert!(!socket_path.exists());
    }

    #[test]
    fn query_phase_projection_preserves_the_durable_effect_boundary() {
        for (phase, is_head_first_retire, expected) in [
            (
                PreparedPhase::PreparedNoEffects,
                false,
                ReferenceQueryDurablePhaseV1::PreparedNoEffects,
            ),
            (
                PreparedPhase::SupersededBeforeEffects,
                false,
                ReferenceQueryDurablePhaseV1::PreparedNoEffects,
            ),
            (
                PreparedPhase::StartupExpiredNoEffects,
                false,
                ReferenceQueryDurablePhaseV1::PreparedNoEffects,
            ),
            (
                PreparedPhase::FirstActionIntent,
                false,
                ReferenceQueryDurablePhaseV1::FirstActionIntent,
            ),
            (
                PreparedPhase::SupersededReconcileRequired,
                false,
                ReferenceQueryDurablePhaseV1::FirstActionIntent,
            ),
            (
                PreparedPhase::StartupReconcileRequired,
                false,
                ReferenceQueryDurablePhaseV1::FirstActionIntent,
            ),
            (
                PreparedPhase::HeadCommittedRetiringOld,
                true,
                ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
            ),
            (
                PreparedPhase::SupersededReconcileRequired,
                true,
                ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
            ),
            (
                PreparedPhase::StartupReconcileRequired,
                true,
                ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
            ),
        ] {
            assert_eq!(query_prepared_phase(phase, is_head_first_retire), expected);
        }
    }

    #[test]
    fn query_preserves_head_committed_phase_after_higher_tenure_takeover() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-takeover-draining-test.sock");
        let (service, retire_request, channel) = head_first_retiring_service(socket_path.clone());
        let RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning,
            channel: service_channel,
        } = service;
        let current = apply.snapshot().clone();
        let current_fence = current
            .state()
            .writer_fence
            .unwrap_or_else(|| panic!("draining takeover lost writer fence"));
        let takeover_epoch = current_fence
            .epoch
            .checked_add(1)
            .unwrap_or_else(|| panic!("draining takeover epoch overflow"));
        let takeover = current
            .try_tenure_only_successor(RuntimeTenureAdmissionInput {
                expected_store_instance_id: *current.store_instance_id(),
                owner_target_fingerprint: *current.owner_target_fingerprint(),
                source_scope: current_fence.source_scope,
                writer: current_fence.writer,
                epoch: takeover_epoch,
                supersedes_through_epoch: current_fence.epoch,
                proof_envelope_digest: digest(0xe6),
                tenure_nonce_identity: digest(0xe7),
                principal: current_fence.principal,
            })
            .unwrap_or_else(|error| panic!("draining takeover successor failed: {error:?}"));
        let takeover_prepared = takeover
            .state()
            .prepared
            .as_ref()
            .unwrap_or_else(|| panic!("draining takeover lost prepared operation"));
        assert_eq!(
            takeover_prepared.phase,
            PreparedPhase::SupersededReconcileRequired
        );
        assert!(takeover_prepared.retiring.is_some());
        assert_eq!(
            RuntimeJournalSnapshot::decode(takeover.canonical_wire())
                .unwrap_or_else(|error| panic!("draining takeover did not reopen: {error:?}")),
            takeover
        );
        let mut non_superseded = takeover.state().clone();
        let non_superseded_prepared = non_superseded
            .prepared
            .as_mut()
            .unwrap_or_else(|| panic!("takeover corruption fixture lost prepared operation"));
        non_superseded_prepared.phase = PreparedPhase::HeadCommittedRetiringOld;
        non_superseded_prepared.raw_outcome = current
            .state()
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.raw_outcome);
        assert!(matches!(
            RuntimeJournalSnapshot::try_new(
                *takeover.store_instance_id(),
                *takeover.owner_target_fingerprint(),
                takeover.sequence(),
                non_superseded,
            ),
            Err(crate::runtime_journal::RuntimeJournalError::InvalidStateInvariant)
        ));

        let (mut store, apply_clock, owner, signer, apply_channel) =
            apply.into_test_recovery_parts();
        assert_eq!(apply_channel, channel);
        store.snapshot = takeover;
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            store,
            apply_clock,
            owner,
            signer,
            apply_channel,
        )
        .unwrap_or_else(|error| panic!("takeover apply core rejected: {error:?}"));
        let mut service = RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning,
            channel: service_channel,
        };
        let query = signed_query_request(QueryRequestFixture {
            query: 0xe8,
            expected_request_digest: Some(retire_request.envelope_request_digest()),
            ..QueryRequestFixture::fresh(0xe4)
        });
        let before = service.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(service.apply.snapshot());
        let response = service
            .handle_request(query.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("takeover draining query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("takeover draining query returned no PXQS"));
        let (_, facts) = decode_verify_query_response(&response, &query, channel, expected_serving);
        assert_eq!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Known {
                request_digest: retire_request.envelope_request_digest(),
                durable_phase: ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
                terminal_result: None,
            }
        );
        assert_eq!(
            facts.operation().owner_state(),
            ReferenceQueryOwnerStateV1::ApplyDisabled
        );
        assert_eq!(facts.live().state(), ReferenceQueryLiveStateV1::Draining);
        assert_eq!(service.apply.snapshot().canonical_wire(), before);
    }

    #[test]
    fn restart_terminalizes_head_committed_empty_as_interrupted_exact_zero() {
        let socket_path = PathBuf::from("/tmp/paraegox-query-restart-draining-test.sock");
        let (service, retire_request, _) = head_first_retiring_service(socket_path.clone());
        let RuntimeControlService {
            apply,
            compiled,
            provisioning,
            ..
        } = service;
        let pre_restart = apply.snapshot().clone();
        drop(apply);
        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: pre_restart,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            compiled,
            provisioning,
        )
        .unwrap_or_else(|error| panic!("draining restart rejected: {error}"));
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xe9),
            digest(0xea),
        )
        .unwrap_or_else(|error| panic!("draining restart channel rejected: {error}"));
        let mut service = restarted
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("draining restart control rejected: {error}"));
        assert!(service.apply.snapshot().state().prepared.is_none());
        assert!(matches!(
            service.apply.snapshot().state().live_materialization,
            LiveMaterialization::ExactZero { .. }
        ));
        let terminal = service
            .apply
            .snapshot()
            .state()
            .terminal_operations
            .last()
            .unwrap_or_else(|| panic!("draining restart lost terminal"));
        assert_eq!(
            terminal.selection.primary,
            crate::runtime_journal::TerminalOutcome::InterruptedButNowExactZero
        );

        let query = signed_query_request(QueryRequestFixture {
            query: 0xeb,
            expected_request_digest: Some(retire_request.envelope_request_digest()),
            ..QueryRequestFixture::fresh(0xe4)
        });
        assert!(matches!(
            query_operation_lookup(service.apply.snapshot(), &query)
                .unwrap_or_else(|error| panic!("restart durable lookup failed: {error}")),
            ReferenceQueryOperationLookupV1::Known {
                request_digest,
                durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                terminal_result: Some(_),
            } if request_digest == retire_request.envelope_request_digest()
        ));
        let before = service.apply.snapshot().canonical_wire().to_vec();
        let expected_serving = independent_query_serving(service.apply.snapshot());
        let response = service
            .handle_request(query.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("restart draining query rejected: {error:?}"))
            .unwrap_or_else(|| panic!("restart draining query returned no PXQS"));
        let (_, facts) = decode_verify_query_response(&response, &query, channel, expected_serving);
        assert!(matches!(
            facts.operation().lookup(),
            ReferenceQueryOperationLookupV1::Known {
                durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                terminal_result: Some(_),
                ..
            }
        ));
        assert_eq!(facts.live().state(), ReferenceQueryLiveStateV1::ExactZero);
        assert_eq!(service.apply.snapshot().canonical_wire(), before);
    }

    #[test]
    fn higher_tenure_head_first_empty_restart_terminalizes_superseded_exact_zero() {
        let socket_path = PathBuf::from("/tmp/paraegox-empty-takeover-restart.sock");
        reset_fixed_owner_callback_actions_for_test();
        let (service, retire_request, _) = head_first_retiring_service(socket_path.clone());
        // Ignore the predecessor Loop start; the restart below must not invoke
        // either lifecycle callback for the already head-committed action.
        reset_fixed_owner_callback_actions_for_test();
        let RuntimeControlService {
            apply,
            compiled,
            provisioning,
            ..
        } = service;
        let current = apply.snapshot().clone();
        let prepared = current
            .state()
            .prepared
            .as_ref()
            .unwrap_or_else(|| panic!("empty takeover lost prepared action"));
        let retiring_generation = prepared
            .retiring
            .as_ref()
            .unwrap_or_else(|| panic!("empty takeover lost retiring facts"))
            .old_resource_generation;
        let takeover = higher_tenure_successor(&current, 0xdc);
        drop(apply);

        let restarted = StartedRuntimeBootstrapService::try_start(
            MockStore {
                snapshot: takeover,
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path: socket_path.clone(),
            },
            compiled,
            provisioning,
        )
        .unwrap_or_else(|error| panic!("empty takeover restart failed: {error}"));
        let recovered = restarted.state.snapshot();
        assert!(!socket_path.exists());
        assert!(recovered.state().prepared.is_none());
        assert!(matches!(
            recovered.state().live_materialization,
            LiveMaterialization::ExactZero { .. }
        ));
        let terminal = terminal_for_request(recovered, &retire_request);
        assert_eq!(
            terminal.selection.primary,
            TerminalOutcome::SupersededAfterIntentExactZero
        );
        assert!(terminal.selection.raw.higher_tenure_takeover);
        assert_owned_crash_generation_is_tombstoned(recovered, retiring_generation);
        assert!(fixed_owner_start_callback_actions_for_test().is_empty());
        assert!(fixed_owner_stop_callback_actions_for_test().is_empty());
    }

    #[test]
    fn historical_terminal_replay_bypasses_later_not_ready_busy_without_commit() {
        let socket_path = PathBuf::from("/tmp/paraegox-busy-replay-test.sock");
        let started = started_service(socket_path.clone());
        let initial = started.state.snapshot().clone();
        let active_request = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::OneSourceLoop,
                request_nonce: b"active-one-source-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xd1),
            digest(0xd2),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let mut active_service = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("control service rejected: {error}"));
        let active_pxrt = active_service
            .handle_request(active_request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("one-source apply rejected: {error:?}"))
            .unwrap_or_else(|| panic!("one-source apply returned no PXRT"));
        let active_receipt = ReferenceApplyTerminalReceiptV1::decode(&active_pxrt)
            .unwrap_or_else(|error| panic!("active PXRT decode failed: {error}"));
        assert_eq!(
            active_receipt.facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        );

        let active_snapshot = active_service.apply.snapshot().clone();
        let (active_slice_digest, resource_generation) =
            match active_snapshot.state().live_materialization {
                LiveMaterialization::LiveReady {
                    active_slice_digest,
                    resource_generation,
                    ..
                } => (active_slice_digest, resource_generation),
                other => panic!("one-source terminal did not become LiveReady: {other:?}"),
            };
        let budgets = active_request
            .target_execution()
            .loop_facts()
            .unwrap_or_else(|| panic!("active request lost loop facts"))
            .budgets();
        let compiled = active_service.compiled;
        let compatibility = active_service.compatibility.clone();
        let clock = active_service.clock;
        drop(active_service);

        let provisioning = provisioning(socket_path.clone());
        let signer = RuntimeReferenceApplySigner::try_new(
            provisioning.response_signer().clone(),
            provisioning.runtime_response_key_ref(),
            ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
                .unwrap_or_else(|error| panic!("response algorithm failed: {error}")),
            ED25519_ALGORITHM_VERSION,
        )
        .unwrap_or_else(|error| panic!("response signer failed: {error:?}"));
        let owner = FailingRetireOwner {
            active_slice_digest,
            resource_generation,
            plan: RuntimeEmptyRetireOwnerPlan {
                action_id: [0xd3; 16],
                signed_budgets: budgets,
            },
        };
        let apply = RuntimeReferenceApplyCore::try_new_with_owner(
            MockStore {
                snapshot: active_snapshot.clone(),
                commit_attempts: Rc::new(Cell::new(0)),
                fail_commit: false,
                socket_path,
            },
            RuntimeEndpointApplyClock { clock },
            owner,
            signer,
            channel,
        )
        .unwrap_or_else(|error| panic!("failing-retire core rejected: {error:?}"));
        let mut busy_service = RuntimeControlService {
            apply,
            clock,
            compiled,
            compatibility,
            provisioning,
            channel,
        };
        let retire_request = signed_apply_request(
            &active_snapshot,
            ApplyRequestFixture {
                mode: ReferenceAssemblyModeV1::EmptyDeactivate,
                operation: 0xd4,
                request_nonce: b"retire-to-busy-nonce",
                tenure_nonce: b"retire-to-busy-tenure",
                writer_epoch: 2,
                supersedes_epoch: 1,
                source_revision: 2,
                temporal_constraint: 0xd5,
                expected_active: ExpectedActive::Exact(active_slice_digest),
                ..ApplyRequestFixture::valid()
            },
        );
        assert!(matches!(
            busy_service.handle_request(retire_request.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Internal(
                RuntimeBootstrapEndpointError::Apply(RuntimeReferenceApplyError::Owner(
                    RuntimeReferenceMaterializationOwnerError::CallbackFailed
                ))
            ))
        ));
        let busy_state =
            RuntimeControlState::try_from_started_snapshot(busy_service.apply.snapshot())
                .unwrap_or_else(|error| panic!("busy state invalid: {error:?}"));
        assert_eq!(
            busy_state.bootstrap_facts().map(|facts| facts.readiness()),
            Ok(RuntimeJournalBootstrapState::NotReadyBusy)
        );
        let busy_sequence = busy_service.apply.snapshot().sequence();

        let replay = busy_service
            .handle_request(active_request.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("busy historical replay rejected: {error:?}"))
            .unwrap_or_else(|| panic!("busy historical replay returned no PXRT"));
        assert_eq!(replay, active_pxrt);
        assert_eq!(busy_service.apply.snapshot().sequence(), busy_sequence);
    }

    #[test]
    fn apply_ingress_rejects_bad_crypto_store_cas_and_operation_conflict_without_mutation() {
        let socket_path = PathBuf::from("/tmp/paraegox-apply-reject-test.sock");
        let started = started_service(socket_path);
        let initial = started.state.snapshot().clone();
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            digest(0xb1),
            digest(0xb2),
        )
        .unwrap_or_else(|error| panic!("channel rejected: {error}"));
        let mut control = started
            .into_control_service(channel)
            .unwrap_or_else(|error| panic!("control service rejected: {error}"));

        let invalid = [
            ApplyRequestFixture {
                controller_seed: [0xc1; 32],
                ..ApplyRequestFixture::valid()
            },
            ApplyRequestFixture {
                tenure_seed: [0xc2; 32],
                ..ApplyRequestFixture::valid()
            },
            ApplyRequestFixture {
                expected_store: [0xc3; 32],
                ..ApplyRequestFixture::valid()
            },
            ApplyRequestFixture {
                expected_active: ExpectedActive::Exact(TargetSliceDigest::new(digest(0xc4))),
                ..ApplyRequestFixture::valid()
            },
        ];
        for fixture in invalid {
            let request = signed_apply_request(&initial, fixture);
            assert!(matches!(
                control.handle_request(request.canonical_wire(), channel),
                Err(RuntimeControlRequestError::Rejected)
            ));
            assert_eq!(control.apply.snapshot().sequence(), 2);
        }
        let valid = signed_apply_request(&initial, ApplyRequestFixture::valid());
        let terminal = control
            .handle_request(valid.canonical_wire(), channel)
            .unwrap_or_else(|error| panic!("valid apply rejected: {error:?}"))
            .unwrap_or_else(|| panic!("valid apply returned no terminal"));
        let terminal_sequence = control.apply.snapshot().sequence();

        let conflicting = signed_apply_request(
            &initial,
            ApplyRequestFixture {
                request_nonce: b"conflicting-operation-nonce",
                ..ApplyRequestFixture::valid()
            },
        );
        assert!(matches!(
            control.handle_request(conflicting.canonical_wire(), channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert_eq!(control.apply.snapshot().sequence(), terminal_sequence);
        assert_eq!(&terminal[..4], b"PXRT");

        let mut trailing = valid.canonical_wire().to_vec();
        trailing.push(0);
        assert!(matches!(
            control.handle_request(&trailing, channel),
            Err(RuntimeControlRequestError::Rejected)
        ));
        assert_eq!(control.apply.snapshot().sequence(), terminal_sequence);
    }

    #[tokio::test]
    async fn framing_rejects_zero_and_oversize_before_reading_a_payload() {
        for claimed_length in [0_u32, 65_u32] {
            let (mut reader, mut writer) = UnixStream::pair()
                .unwrap_or_else(|error| panic!("UnixStream pair failed: {error}"));
            writer
                .write_all(&claimed_length.to_be_bytes())
                .await
                .unwrap_or_else(|error| panic!("frame header write failed: {error}"));
            assert_eq!(
                read_bounded_frame(&mut reader, 64, Duration::from_secs(1)).await,
                Err(())
            );
        }

        let (mut reader, mut writer) =
            UnixStream::pair().unwrap_or_else(|error| panic!("UnixStream pair failed: {error}"));
        write_bounded_frame(
            &mut writer,
            b"bounded-response",
            MAX_CONTROL_RESPONSE_BYTES,
            Duration::from_secs(1),
        )
        .await
        .unwrap_or_else(|()| panic!("bounded response write failed"));
        let mut length = [0_u8; CONTROL_FRAME_HEADER_BYTES];
        reader
            .read_exact(&mut length)
            .await
            .unwrap_or_else(|error| panic!("response header read failed: {error}"));
        let mut payload = vec![0_u8; u32::from_be_bytes(length) as usize];
        reader
            .read_exact(&mut payload)
            .await
            .unwrap_or_else(|error| panic!("response payload read failed: {error}"));
        assert_eq!(payload, b"bounded-response");
    }

    struct TestSocketDirectory {
        path: PathBuf,
        socket_path: PathBuf,
    }

    impl TestSocketDirectory {
        fn create() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let name = format!(
                "paraegox-runtime-endpoint-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(name);
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("test socket directory create failed: {error}"));
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(CONTROL_SOCKET_DIRECTORY_MODE),
            )
            .unwrap_or_else(|error| panic!("test socket directory chmod failed: {error}"));
            let socket_path = path.join("bootstrap.sock");
            Self { path, socket_path }
        }
    }

    impl Drop for TestSocketDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.socket_path);
            let _ = fs::remove_dir(&self.path);
        }
    }

    #[test]
    fn listener_bind_occurs_after_commit_and_channel_uses_live_socket_facts() {
        let directory = TestSocketDirectory::create();
        let started = started_service(directory.socket_path.clone());
        assert!(!directory.socket_path.exists());
        let bound = started
            .bind()
            .unwrap_or_else(|error| panic!("listener bind failed: {error}"));
        assert!(directory.socket_path.exists());
        let channel = live_runtime_channel(&bound.started.provisioning, &bound.guard)
            .unwrap_or_else(|error| panic!("live channel failed: {error}"));
        assert_eq!(channel.target(), TARGET);
        assert_eq!(channel.runtime_peer(), RUNTIME_PRINCIPAL);
        let metadata = fs::symlink_metadata(&directory.socket_path)
            .unwrap_or_else(|error| panic!("socket metadata failed: {error}"));
        assert_eq!(
            channel.local_endpoint_identity_digest(),
            reference_local_control_endpoint_identity_digest_v1(
                directory.socket_path.as_os_str().as_bytes(),
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode() & MODE_MASK,
            )
            .unwrap_or_else(|error| panic!("endpoint digest failed: {error}"))
        );
        drop(bound);
        assert!(!directory.socket_path.exists());
    }

    #[tokio::test]
    async fn bound_service_checks_peer_credentials_and_cleans_up_on_shutdown() {
        let directory = TestSocketDirectory::create();
        let bound = started_service(directory.socket_path.clone())
            .bind()
            .unwrap_or_else(|error| panic!("listener bind failed: {error}"));
        let (stream, peer) =
            UnixStream::pair().unwrap_or_else(|error| panic!("UnixStream pair failed: {error}"));
        assert!(peer_is_authorized(
            &stream,
            geteuid().as_raw(),
            getegid().as_raw()
        ));
        assert!(!peer_is_authorized(
            &stream,
            distinct_controller_uid(geteuid().as_raw()),
            getegid().as_raw()
        ));
        drop((stream, peer));
        bound
            .serve_until(async { Ok(()) })
            .await
            .unwrap_or_else(|error| panic!("clean shutdown failed: {error}"));
        assert!(!directory.socket_path.exists());
    }
    #[test]
    fn production_runner_fails_before_service_on_an_unopened_store() {
        let directory = TestSocketDirectory::create();
        let missing_store = directory.path.join("missing-store");
        let result = run_runtime_bootstrap_process(
            &missing_store,
            STORE_INSTANCE_ID,
            compiled_facts(),
            provisioning(directory.socket_path.clone()),
        );
        assert!(matches!(
            result,
            Err(RuntimeBootstrapEndpointError::StoreOpen(_))
        ));
        assert!(!directory.socket_path.exists());
    }
}
