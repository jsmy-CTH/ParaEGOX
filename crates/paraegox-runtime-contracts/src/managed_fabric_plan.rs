//! Canonical successor plan for one Runtime-managed fabric service.
//!
//! This module is intentionally narrower than a general service graph. It
//! admits exactly one [`ManagedServiceSpecV1`] with one explicit loopback TCP
//! listen endpoint, or an authoritative empty/deactivate state. Runtime-owned
//! generations, transport-library types, key routes, and Agent identities are
//! deliberately absent from desired state. A terminal Receipt may carry the
//! Runtime-observed generation after real lifecycle execution.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockGeneration};

use crate::apply::{
    ApplyContractError, ApplyOperationId, ExpectedActive, RuntimeApplyControl,
    RuntimeApplyControlCommitment,
};
use crate::assignment::TargetAssignments;
use crate::installation::VerifiedRuntimeManifestIngressV1;
use crate::managed_service::{
    MANAGED_SERVICE_CONTRACT_VERSION, ManagedServiceGeneration, ManagedServiceId,
    ManagedServiceLifecycleBudgetsV1, ManagedServiceLifecycleStage, ManagedServiceSpecV1,
};
use crate::provenance::{
    PlanProvenance, ProvenanceContractError, RuntimeSliceCommitment, RuntimeSliceHeader,
    SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
    TargetSliceDigest,
};
use crate::reference_assembly::{
    APPLY_REQUEST_SIGNING_TRANSCRIPT_V2_VERSION, ApplyRequestSigningTranscriptV2,
    MAX_CONTROL_READ_SIGNATURE_BYTES, MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES,
    RUNTIME_APPLY_ENVELOPE_V2_VERSION, ReferenceContractError, ReferenceWireError,
    ReferenceWireErrorCode, RuntimeApplyEnvelopeV2, RuntimeApplyEnvelopeV2Draft,
    RuntimeResponseAuthClaimV1, RuntimeResponseAuthenticationV1, RuntimeStoreInstanceId,
};
use crate::reference_control::ReferenceChannelBindingV1;
use crate::temporal::ApplyTemporalConstraint;
use crate::wire::{
    ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, ApplyRequestAuthentication,
};

const PROJECTION_MAGIC: &[u8; 4] = b"PXMP";
const TARGET_EXECUTION_MAGIC: &[u8; 4] = b"PXTE";
const APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const TERMINAL_RECEIPT_MAGIC: &[u8; 4] = b"PXFT";
const SIGNING_TRANSCRIPT_MAGIC: &[u8] = b"ParaEGOX\0canonical-signing-transcript";
const EMPTY_PXTA: [u8; 10] = [b'P', b'X', b'T', b'A', 0, 1, 0, 0, 0, 0];
const APPLY_REQUEST_HEADER_BYTES: usize = 18;
const PROJECTION_BYTES: usize = 4 + 2 + 32 + 16 + (4 * 32) + 2 + 2;
const LEGACY_VERIFIED_PROJECTION_BYTES: usize = 298;
const TARGET_EXECUTION_FIXED_BYTES: usize = 4 + 2 + PROJECTION_BYTES + 2 + 1 + 1;
const MANAGED_SERVICE_FIXED_BYTES: usize = 2 + 16 + (5 * 8) + 2;
const LOOPBACK_TCP_PREFIX: &str = "tcp/127.0.0.1:";

const COMPILED_COMPATIBILITY_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.compiled-managed-fabric-compatibility.sha256.v1";
const TARGET_EXECUTION_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-execution.sha256.v5";
const TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.target-plan-assignments.sha256.v6";
const TERMINAL_RESULT_REF_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-fabric-apply-terminal-result.sha256.v1";
const TERMINAL_RECEIPT_SIGNING_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-fabric-apply-terminal-receipt.response-auth.signing.v1";
const TERMINAL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-fabric-apply-terminal-receipt.sha256.v1";
const TERMINAL_RECEIPT_FIELD_COUNT: u16 = 30;
const TERMINAL_RECEIPT_SIGNING_FIELD_COUNT: u16 = TERMINAL_RECEIPT_FIELD_COUNT - 1;
const TLV_HEADER_BYTES: usize = 6;

/// Version of the independent managed-fabric compatibility projection.
pub const MANAGED_FABRIC_PROJECTION_VERSION: u16 = 1;
/// Exact apply request version selected by the successor projection.
pub const MANAGED_FABRIC_APPLY_REQUEST_VERSION: u16 = 6;
/// Exact target execution version selected by the successor projection.
pub const MANAGED_FABRIC_TARGET_EXECUTION_VERSION: u16 = 5;
/// Exact service-only target profile version.
pub const MANAGED_FABRIC_PROFILE_VERSION: u16 = 2;
/// Existing signed envelope version retained byte-for-byte inside PXAR v6.
pub const MANAGED_FABRIC_APPLY_ENVELOPE_VERSION: u16 = RUNTIME_APPLY_ENVELOPE_V2_VERSION;
/// Existing signing transcript version retained by the envelope.
pub const MANAGED_FABRIC_APPLY_SIGNING_TRANSCRIPT_VERSION: u16 =
    APPLY_REQUEST_SIGNING_TRANSCRIPT_V2_VERSION;
/// Maximum bytes accepted for a contract-native listen endpoint.
pub const MAX_MANAGED_FABRIC_LISTEN_ENDPOINT_BYTES: usize = 256;
/// Maximum finite budget admitted for each managed-service lifecycle stage.
pub const MAX_MANAGED_FABRIC_LIFECYCLE_NANOS: u64 = 86_400_000_000_000;
/// Exact canonical projection width.
pub const MANAGED_FABRIC_PROJECTION_BYTES: usize = PROJECTION_BYTES;
/// Maximum canonical PXTE v5 body size.
pub const MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES: usize = TARGET_EXECUTION_FIXED_BYTES
    + MANAGED_SERVICE_FIXED_BYTES
    + MAX_MANAGED_FABRIC_LISTEN_ENDPOINT_BYTES;
/// Maximum canonical durable `PXTA-zero || PXTE-v5` body size.
pub const MAX_MANAGED_FABRIC_PLAN_SLICE_BYTES: usize =
    EMPTY_PXTA.len() + MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES;
/// Maximum canonical PXAR v6 request size.
pub const MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES: usize = APPLY_REQUEST_HEADER_BYTES
    + MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES
    + EMPTY_PXTA.len()
    + MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES;
/// Independent managed-fabric terminal Receipt version carried by PXFT.
pub const MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_VERSION: u16 = 1;
/// Signing-transcript version carried by the independent PXFT contract.
pub const MANAGED_FABRIC_APPLY_TERMINAL_SIGNING_TRANSCRIPT_VERSION: u16 = 1;
/// Maximum canonical PXFT receipt size.
pub const MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES: usize = 2_048;
/// Maximum opaque Runtime response signature size.
pub const MAX_MANAGED_FABRIC_APPLY_TERMINAL_SIGNATURE_BYTES: usize =
    MAX_CONTROL_READ_SIGNATURE_BYTES;

/// Immutable transition facts copied from verified legacy installation ingress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedFabricProjectionFieldsV1 {
    /// Digest of the exact verified legacy installation manifest.
    pub manifest_digest: Digest32,
    /// Runtime target selected by the manifest row.
    pub target: RuntimeHostId,
    /// Nonzero release-pipeline build identity.
    pub build_instance_id: [u8; 32],
    /// Digest of the exact build descriptor.
    pub build_descriptor_digest: Digest32,
    /// Digest of the exact Runtime executable.
    pub runtime_artifact_sha256: Digest32,
    /// Contract-owned successor compatibility digest.
    pub compatibility_digest: Digest32,
}

/// Managed-fabric transition projection derived independently at both peers.
///
/// There is no managed-fabric installer manifest in this tranche. Strict wire
/// decoding produces an untrusted value; admission additionally requires exact
/// equality with a projection locally derived from verified legacy ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFabricManifestProjectionV1 {
    fields: ManagedFabricProjectionFieldsV1,
    canonical_wire: Box<[u8]>,
}

impl ManagedFabricManifestProjectionV1 {
    /// Derives transition projection facts from a strictly verified legacy manifest.
    ///
    /// This does not claim that installation manifest v1 selects the successor
    /// profile. It retains only its already verified manifest/build/artifact
    /// identity fields and computes the managed-fabric compatibility digest
    /// locally. Controller and Runtime must derive this value independently and
    /// compare it with the untrusted projection decoded from PXTE.
    pub fn try_from_verified_legacy_manifest(
        ingress: &VerifiedRuntimeManifestIngressV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        let legacy = ingress.projection_canonical_wire();
        if legacy.len() != LEGACY_VERIFIED_PROJECTION_BYTES
            || &legacy[..4] != PROJECTION_MAGIC
            || read_u16(&legacy[4..6]) != 1
            || legacy[6..38] != *ingress.manifest_digest().as_bytes()
            || legacy[38..54] != *ingress.target().as_bytes()
        {
            return Err(ManagedFabricPlanError::InvalidProjection);
        }
        Self::try_new(ManagedFabricProjectionFieldsV1 {
            manifest_digest: ingress.manifest_digest(),
            target: ingress.target(),
            build_instance_id: read_array(&legacy[54..86]),
            build_descriptor_digest: Digest32::from_bytes(read_array(&legacy[86..118])),
            runtime_artifact_sha256: Digest32::from_bytes(read_array(&legacy[118..150])),
            compatibility_digest: managed_fabric_compatibility_digest_v1()?,
        })
    }

    fn try_new(fields: ManagedFabricProjectionFieldsV1) -> Result<Self, ManagedFabricPlanError> {
        validate_projection_fields(fields)?;
        let canonical_wire = build_projection_wire(fields);
        Ok(Self {
            fields,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes one fixed-width canonical projection.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedFabricPlanError> {
        if frame.len() > PROJECTION_BYTES {
            return Err(wire(ManagedFabricWireErrorCode::FrameTooLarge));
        }
        if frame.len() < PROJECTION_BYTES {
            return Err(wire(ManagedFabricWireErrorCode::Truncated));
        }
        if &frame[..4] != PROJECTION_MAGIC {
            return Err(wire(ManagedFabricWireErrorCode::InvalidMagic));
        }
        if read_u16(&frame[4..6]) != MANAGED_FABRIC_PROJECTION_VERSION {
            return Err(wire(ManagedFabricWireErrorCode::UnsupportedVersion));
        }
        let fields = ManagedFabricProjectionFieldsV1 {
            manifest_digest: Digest32::from_bytes(read_array(&frame[6..38])),
            target: RuntimeHostId::from_bytes(read_array(&frame[38..54])),
            build_instance_id: read_array(&frame[54..86]),
            build_descriptor_digest: Digest32::from_bytes(read_array(&frame[86..118])),
            runtime_artifact_sha256: Digest32::from_bytes(read_array(&frame[118..150])),
            compatibility_digest: Digest32::from_bytes(read_array(&frame[150..182])),
        };
        if read_u16(&frame[182..184]) != MANAGED_FABRIC_APPLY_REQUEST_VERSION {
            return Err(wire_at(ManagedFabricWireErrorCode::UnsupportedVersion, 7));
        }
        if read_u16(&frame[184..186]) != MANAGED_FABRIC_PROFILE_VERSION {
            return Err(wire_at(ManagedFabricWireErrorCode::UnsupportedVersion, 8));
        }
        let decoded = Self::try_new(fields).map_err(projection_contract_wire_error)?;
        if decoded.canonical_wire() != frame {
            return Err(wire(ManagedFabricWireErrorCode::NonCanonicalFrame));
        }
        Ok(decoded)
    }

    /// Returns read-only transition fields; this does not prove installation admission.
    #[must_use]
    pub const fn fields(&self) -> ManagedFabricProjectionFieldsV1 {
        self.fields
    }

    /// Returns the selected Runtime target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.fields.target
    }

    /// Returns exact canonical projection bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Explicit, contract-native TCP listen endpoint for the first fabric service.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedFabricListenEndpointV1(Box<str>);

impl ManagedFabricListenEndpointV1 {
    /// Accepts only canonical IPv4 loopback TCP endpoints for this tranche.
    pub fn try_new(value: &str) -> Result<Self, ManagedFabricPlanError> {
        if value.is_empty() || value.len() > MAX_MANAGED_FABRIC_LISTEN_ENDPOINT_BYTES {
            return Err(ManagedFabricPlanError::InvalidListenEndpoint);
        }
        let Some(port_text) = value.strip_prefix(LOOPBACK_TCP_PREFIX) else {
            return Err(ManagedFabricPlanError::InvalidListenEndpoint);
        };
        if port_text.is_empty()
            || port_text.len() > 5
            || !port_text.bytes().all(|byte| byte.is_ascii_digit())
            || (port_text.len() > 1 && port_text.starts_with('0'))
        {
            return Err(ManagedFabricPlanError::InvalidListenEndpoint);
        }
        let port = port_text
            .parse::<u16>()
            .map_err(|_| ManagedFabricPlanError::InvalidListenEndpoint)?;
        if port == 0 || format!("{LOOPBACK_TCP_PREFIX}{port}") != value {
            return Err(ManagedFabricPlanError::InvalidListenEndpoint);
        }
        Ok(Self(value.into()))
    }

    /// Returns the exact canonical endpoint string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the explicit nonzero TCP port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.0[LOOPBACK_TCP_PREFIX.len()..]
            .bytes()
            .fold(0_u32, |value, digit| (value * 10) + u32::from(digit - b'0')) as u16
    }
}

/// Exact desired shape admitted by PXTE v5.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedFabricTargetModeV1 {
    /// Exactly one managed fabric CoreService.
    OneManagedFabricService = 1,
    /// Authoritative empty target used to deactivate the service.
    EmptyDeactivate = 2,
}

/// Canonical PXTE v5 body for one service or authoritative empty state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFabricTargetExecutionV1 {
    projection: ManagedFabricManifestProjectionV1,
    mode: ManagedFabricTargetModeV1,
    service: Option<ManagedServiceSpecV1>,
    listen_endpoint: Option<ManagedFabricListenEndpointV1>,
    canonical_wire: Box<[u8]>,
    execution_digest: Digest32,
}

impl ManagedFabricTargetExecutionV1 {
    /// Creates the exact singleton managed-service shape.
    pub fn try_one_managed_fabric_service(
        projection: ManagedFabricManifestProjectionV1,
        service: ManagedServiceSpecV1,
        listen_endpoint: ManagedFabricListenEndpointV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        Self::try_new(
            projection,
            ManagedFabricTargetModeV1::OneManagedFabricService,
            Some(service),
            Some(listen_endpoint),
        )
    }

    /// Creates the exact authoritative empty/deactivate shape.
    pub fn try_empty_deactivate(
        projection: ManagedFabricManifestProjectionV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        Self::try_new(
            projection,
            ManagedFabricTargetModeV1::EmptyDeactivate,
            None,
            None,
        )
    }

    fn try_new(
        projection: ManagedFabricManifestProjectionV1,
        mode: ManagedFabricTargetModeV1,
        service: Option<ManagedServiceSpecV1>,
        listen_endpoint: Option<ManagedFabricListenEndpointV1>,
    ) -> Result<Self, ManagedFabricPlanError> {
        validate_service_shape(mode, service, listen_endpoint.as_ref())?;
        let canonical_wire =
            build_target_execution_wire(&projection, mode, service, listen_endpoint.as_ref());
        let execution_digest = digest_wire(TARGET_EXECUTION_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            projection,
            mode,
            service,
            listen_endpoint,
            canonical_wire: canonical_wire.into_boxed_slice(),
            execution_digest,
        })
    }

    /// Strictly decodes canonical PXTE v5 without legacy fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedFabricPlanError> {
        if frame.len() > MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES {
            return Err(wire(ManagedFabricWireErrorCode::FrameTooLarge));
        }
        if frame.len() < TARGET_EXECUTION_FIXED_BYTES {
            return Err(wire(ManagedFabricWireErrorCode::Truncated));
        }
        if &frame[..4] != TARGET_EXECUTION_MAGIC {
            return Err(wire(ManagedFabricWireErrorCode::InvalidMagic));
        }
        if read_u16(&frame[4..6]) != MANAGED_FABRIC_TARGET_EXECUTION_VERSION {
            return Err(wire(ManagedFabricWireErrorCode::UnsupportedVersion));
        }
        let projection =
            ManagedFabricManifestProjectionV1::decode(&frame[6..6 + PROJECTION_BYTES])?;
        let profile_offset = 6 + PROJECTION_BYTES;
        if read_u16(&frame[profile_offset..profile_offset + 2]) != MANAGED_FABRIC_PROFILE_VERSION {
            return Err(wire_at(ManagedFabricWireErrorCode::UnsupportedVersion, 2));
        }
        let mode = match frame[profile_offset + 2] {
            1 => ManagedFabricTargetModeV1::OneManagedFabricService,
            2 => ManagedFabricTargetModeV1::EmptyDeactivate,
            _ => {
                return Err(wire_at(ManagedFabricWireErrorCode::UnsupportedShape, 3));
            }
        };
        let present = frame[profile_offset + 3];
        let payload = &frame[TARGET_EXECUTION_FIXED_BYTES..];
        let decoded = match (mode, present) {
            (ManagedFabricTargetModeV1::EmptyDeactivate, 0) if payload.is_empty() => {
                Self::try_empty_deactivate(projection)
            }
            (ManagedFabricTargetModeV1::EmptyDeactivate, 0) => {
                return Err(wire(ManagedFabricWireErrorCode::TrailingBytes));
            }
            (ManagedFabricTargetModeV1::EmptyDeactivate, _) => {
                return Err(wire_at(ManagedFabricWireErrorCode::InvalidPresence, 4));
            }
            (ManagedFabricTargetModeV1::OneManagedFabricService, 1) => {
                decode_active_execution(projection, payload)
            }
            (ManagedFabricTargetModeV1::OneManagedFabricService, _) => {
                return Err(wire_at(ManagedFabricWireErrorCode::InvalidPresence, 4));
            }
        }
        .map_err(target_execution_contract_wire_error)?;
        if decoded.canonical_wire() != frame {
            return Err(wire(ManagedFabricWireErrorCode::NonCanonicalFrame));
        }
        Ok(decoded)
    }

    /// Returns the immutable installed-manifest projection.
    #[must_use]
    pub const fn projection(&self) -> &ManagedFabricManifestProjectionV1 {
        &self.projection
    }

    /// Returns the exact desired shape.
    #[must_use]
    pub const fn mode(&self) -> ManagedFabricTargetModeV1 {
        self.mode
    }

    /// Returns the sole service spec, absent only for empty/deactivate.
    #[must_use]
    pub const fn service(&self) -> Option<ManagedServiceSpecV1> {
        self.service
    }

    /// Returns the sole explicit listen endpoint, absent only for empty/deactivate.
    #[must_use]
    pub const fn listen_endpoint(&self) -> Option<&ManagedFabricListenEndpointV1> {
        self.listen_endpoint.as_ref()
    }

    /// Returns exact canonical PXTE v5 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the domain-separated digest of exact PXTE v5 bytes.
    #[must_use]
    pub const fn execution_digest(&self) -> Digest32 {
        self.execution_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedFabricTargetAssignmentsV1 {
    bindings: TargetAssignments,
    execution: ManagedFabricTargetExecutionV1,
    assignment_digest: TargetAssignmentDigest,
}

impl ManagedFabricTargetAssignmentsV1 {
    fn try_from_execution(
        execution: ManagedFabricTargetExecutionV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        let bindings = TargetAssignments::try_new(Vec::new())
            .map_err(|_| ManagedFabricPlanError::BindingNotAllowed)?;
        Self::try_new(bindings, execution)
    }

    fn try_new(
        bindings: TargetAssignments,
        execution: ManagedFabricTargetExecutionV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        bindings
            .validate()
            .map_err(|_| ManagedFabricPlanError::BindingNotAllowed)?;
        if !bindings.is_empty() || bindings.canonical_wire() != EMPTY_PXTA {
            return Err(ManagedFabricPlanError::BindingNotAllowed);
        }
        let mut builder = Digest32Builder::try_new(TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN)?;
        builder.field_digest(bindings.assignment_digest().value())?;
        builder.field_digest(&execution.execution_digest())?;
        let assignment_digest = TargetAssignmentDigest::new(builder.finish());
        Ok(Self {
            bindings,
            execution,
            assignment_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedFabricPlanSliceV1 {
    commitment: RuntimeSliceCommitment,
    assignments: ManagedFabricTargetAssignmentsV1,
}

impl ManagedFabricPlanSliceV1 {
    fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: ManagedFabricTargetAssignmentsV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        commitment.validate()?;
        if commitment.header().assignment_digest() != assignments.assignment_digest {
            return Err(ManagedFabricPlanError::CommitmentMismatch);
        }
        if commitment.header().target() != assignments.execution.projection().target() {
            return Err(ManagedFabricPlanError::TargetMismatch);
        }
        Ok(Self {
            commitment,
            assignments,
        })
    }
}

/// Canonical envelope-v2 signing transcript used by PXAR v6.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFabricApplySigningTranscriptV2 {
    inner: ApplyRequestSigningTranscriptV2,
}

impl ManagedFabricApplySigningTranscriptV2 {
    /// Returns exact bytes for Controller signing or Runtime verification.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

/// Signature-independent producer for one canonical PXAR v6 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFabricApplyRequestDraftV1 {
    envelope: RuntimeApplyEnvelopeV2Draft,
    slice: ManagedFabricPlanSliceV1,
}

impl ManagedFabricApplyRequestDraftV1 {
    /// Binds desired service facts to provenance, CAS, deadline, store, and auth.
    pub fn try_new(
        execution: ManagedFabricTargetExecutionV1,
        provenance: PlanProvenance,
        control: RuntimeApplyControl,
        temporal: ApplyTemporalConstraint,
        expected_runtime_store_instance_id: [u8; 32],
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ManagedFabricPlanError> {
        let assignments = ManagedFabricTargetAssignmentsV1::try_from_execution(execution)?;
        let header = RuntimeSliceHeader::new(
            assignments.execution.projection().target(),
            provenance,
            assignments.assignment_digest,
        );
        let commitment = RuntimeSliceCommitment::try_new(header)?;
        let slice = ManagedFabricPlanSliceV1::try_new(commitment, assignments)?;
        let control_commitment = RuntimeApplyControlCommitment::try_new(commitment, control)?;
        let store = RuntimeStoreInstanceId::try_from_bytes(expected_runtime_store_instance_id)
            .map_err(map_reference_contract_error)?;
        let envelope =
            RuntimeApplyEnvelopeV2Draft::try_new(control_commitment, temporal, store, auth_claim)
                .map_err(map_reference_contract_error)?;
        Ok(Self { envelope, slice })
    }

    /// Returns exact signature-independent envelope-v2 bytes.
    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedFabricApplySigningTranscriptV2, ManagedFabricPlanError> {
        Ok(ManagedFabricApplySigningTranscriptV2 {
            inner: self
                .envelope
                .signing_transcript()
                .map_err(map_reference_contract_error)?,
        })
    }

    /// Adds the opaque request signature and freezes exact PXAR v6 bytes.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ManagedFabricApplyRequestV1, ManagedFabricPlanError> {
        let envelope = self
            .envelope
            .finalize(signature)
            .map_err(map_reference_contract_error)?;
        ManagedFabricApplyRequestV1::try_new(envelope, self.slice)
    }
}

/// Signed strict PXAR v6 request carrying envelope v2, empty PXTA, and PXTE v5.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFabricApplyRequestV1 {
    envelope: RuntimeApplyEnvelopeV2,
    slice: ManagedFabricPlanSliceV1,
    canonical_wire: Box<[u8]>,
}

impl ManagedFabricApplyRequestV1 {
    fn try_new(
        envelope: RuntimeApplyEnvelopeV2,
        slice: ManagedFabricPlanSliceV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        if envelope.control_commitment().slice() != slice.commitment {
            return Err(ManagedFabricPlanError::CommitmentMismatch);
        }
        if slice.commitment.header().target() != slice.assignments.execution.projection().target() {
            return Err(ManagedFabricPlanError::TargetMismatch);
        }
        let canonical_wire = build_apply_request_wire(&envelope, &slice);
        if canonical_wire.len() > MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES {
            return Err(ManagedFabricPlanError::RequestFrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes exactly PXAR v6 without fallback to PXAR v5.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedFabricPlanError> {
        if frame.len() > MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES {
            return Err(wire(ManagedFabricWireErrorCode::FrameTooLarge));
        }
        if frame.len() < APPLY_REQUEST_HEADER_BYTES {
            return Err(wire(ManagedFabricWireErrorCode::Truncated));
        }
        if &frame[..4] != APPLY_REQUEST_MAGIC {
            return Err(wire(ManagedFabricWireErrorCode::InvalidMagic));
        }
        if read_u16(&frame[4..6]) != MANAGED_FABRIC_APPLY_REQUEST_VERSION {
            return Err(wire(ManagedFabricWireErrorCode::UnsupportedVersion));
        }
        let envelope_length = read_u32(&frame[6..10]) as usize;
        let bindings_length = read_u32(&frame[10..14]) as usize;
        let execution_length = read_u32(&frame[14..18]) as usize;
        if envelope_length > MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES {
            return Err(wire_at(ManagedFabricWireErrorCode::FrameTooLarge, 1));
        }
        if bindings_length != EMPTY_PXTA.len() {
            return Err(wire_at(ManagedFabricWireErrorCode::BindingNotAllowed, 2));
        }
        if execution_length > MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES {
            return Err(wire_at(ManagedFabricWireErrorCode::FrameTooLarge, 3));
        }
        let expected_length = APPLY_REQUEST_HEADER_BYTES
            .checked_add(envelope_length)
            .and_then(|value| value.checked_add(bindings_length))
            .and_then(|value| value.checked_add(execution_length))
            .ok_or_else(|| wire(ManagedFabricWireErrorCode::InvalidFieldLength))?;
        if frame.len() < expected_length {
            return Err(wire(ManagedFabricWireErrorCode::Truncated));
        }
        if frame.len() > expected_length {
            return Err(wire(ManagedFabricWireErrorCode::TrailingBytes));
        }
        let envelope_start = APPLY_REQUEST_HEADER_BYTES;
        let envelope_end = envelope_start + envelope_length;
        let bindings_end = envelope_end + bindings_length;
        let envelope = RuntimeApplyEnvelopeV2::decode(&frame[envelope_start..envelope_end])
            .map_err(map_reference_wire_error)?;
        let binding_frame = &frame[envelope_end..bindings_end];
        if binding_frame != EMPTY_PXTA {
            return Err(wire_at(ManagedFabricWireErrorCode::BindingNotAllowed, 2));
        }
        let bindings = TargetAssignments::decode(binding_frame)
            .map_err(|_| wire_at(ManagedFabricWireErrorCode::BindingNotAllowed, 2))?;
        let execution = ManagedFabricTargetExecutionV1::decode(&frame[bindings_end..])?;
        let assignments = ManagedFabricTargetAssignmentsV1::try_new(bindings, execution)
            .map_err(|_| wire(ManagedFabricWireErrorCode::CrossReferenceMismatch))?;
        let envelope_commitment = envelope.control_commitment().slice();
        if envelope_commitment.header().target() != assignments.execution.projection().target() {
            return Err(wire_at(ManagedFabricWireErrorCode::TargetMismatch, 2));
        }
        if envelope_commitment.header().assignment_digest() != assignments.assignment_digest {
            return Err(wire_at(ManagedFabricWireErrorCode::DigestMismatch, 7));
        }
        let slice = ManagedFabricPlanSliceV1::try_new(envelope_commitment, assignments).map_err(
            |error| match error {
                ManagedFabricPlanError::TargetMismatch => {
                    wire_at(ManagedFabricWireErrorCode::TargetMismatch, 2)
                }
                _ => wire_at(ManagedFabricWireErrorCode::DigestMismatch, 7),
            },
        )?;
        let decoded = Self::try_new(envelope, slice)
            .map_err(|_| wire(ManagedFabricWireErrorCode::CrossReferenceMismatch))?;
        if decoded.canonical_wire() != frame {
            return Err(wire(ManagedFabricWireErrorCode::NonCanonicalFrame));
        }
        Ok(decoded)
    }

    /// Returns exact canonical PXAR v6 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns exact durable `PXTA-zero || PXTE-v5` bytes.
    #[must_use]
    pub fn canonical_slice_wire(&self) -> &[u8] {
        let offset = APPLY_REQUEST_HEADER_BYTES + self.envelope.canonical_wire().len();
        &self.canonical_wire[offset..]
    }

    /// Returns exact canonical PXTE v5 facts retained by this request.
    #[must_use]
    pub const fn target_execution(&self) -> &ManagedFabricTargetExecutionV1 {
        &self.slice.assignments.execution
    }

    /// Returns the exact target Runtime.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.slice.commitment.header().target()
    }

    /// Returns complete source-plan provenance.
    #[must_use]
    pub const fn provenance(&self) -> PlanProvenance {
        self.slice.commitment.header().provenance()
    }

    /// Returns the composite PXTA/PXTE assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.slice.commitment.header().assignment_digest()
    }

    /// Returns the target-slice commitment digest.
    #[must_use]
    pub const fn target_slice_digest(&self) -> TargetSliceDigest {
        self.slice.commitment.target_slice_digest()
    }

    /// Returns the complete provenance/writer/CAS control commitment.
    #[must_use]
    pub const fn control_commitment(&self) -> &RuntimeApplyControlCommitment {
        self.envelope.control_commitment()
    }

    /// Returns the exact apply-operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> ApplyOperationId {
        self.envelope.control_commitment().control().operation_id()
    }

    /// Returns the authenticated target-clock deadline constraint.
    #[must_use]
    pub const fn temporal(&self) -> ApplyTemporalConstraint {
        self.envelope.temporal()
    }

    /// Returns the nonzero expected journal/store identity.
    #[must_use]
    pub const fn expected_runtime_store_instance_id(&self) -> [u8; 32] {
        *self
            .envelope
            .expected_runtime_store_instance_id()
            .as_bytes()
    }

    /// Returns request authentication claim and opaque signature.
    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        self.envelope.authentication()
    }

    /// Returns the digest of the exact signed envelope v2.
    #[must_use]
    pub const fn envelope_request_digest(&self) -> Digest32 {
        self.envelope.request_digest()
    }

    /// Reconstructs the exact envelope-v2 signing transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedFabricApplySigningTranscriptV2, ManagedFabricPlanError> {
        Ok(ManagedFabricApplySigningTranscriptV2 {
            inner: self
                .envelope
                .signing_transcript()
                .map_err(map_reference_contract_error)?,
        })
    }

    /// Fails closed unless the local journal is the signed expected store.
    pub fn validate_expected_store(
        &self,
        local_runtime_store_instance_id: [u8; 32],
    ) -> Result<(), ManagedFabricPlanError> {
        let local = RuntimeStoreInstanceId::try_from_bytes(local_runtime_store_instance_id)
            .map_err(map_reference_contract_error)?;
        self.envelope
            .validate_expected_store(local)
            .map_err(map_reference_wire_error)
    }

    /// Fails closed unless PXTE retains the exact installed projection.
    pub fn validate_projection(
        &self,
        projection: &ManagedFabricManifestProjectionV1,
    ) -> Result<(), ManagedFabricPlanError> {
        if self.target_execution().projection() != projection {
            return Err(wire(ManagedFabricWireErrorCode::CompatibilityMismatch));
        }
        Ok(())
    }
}

/// Strictly restores a journal-owned `PXTA-zero || PXTE-v5` body.
pub fn verify_managed_fabric_durable_slice_v1(
    canonical_slice_wire: &[u8],
    target: RuntimeHostId,
    provenance: PlanProvenance,
    expected_target_slice_digest: TargetSliceDigest,
    projection: &ManagedFabricManifestProjectionV1,
) -> Result<ManagedFabricTargetExecutionV1, ManagedFabricPlanError> {
    if canonical_slice_wire.len() > MAX_MANAGED_FABRIC_PLAN_SLICE_BYTES {
        return Err(wire(ManagedFabricWireErrorCode::FrameTooLarge));
    }
    if canonical_slice_wire.len() < EMPTY_PXTA.len() {
        return Err(wire(ManagedFabricWireErrorCode::Truncated));
    }
    let (binding_frame, execution_frame) = canonical_slice_wire.split_at(EMPTY_PXTA.len());
    if binding_frame != EMPTY_PXTA {
        return Err(wire_at(ManagedFabricWireErrorCode::BindingNotAllowed, 2));
    }
    let bindings = TargetAssignments::decode(binding_frame)
        .map_err(|_| wire_at(ManagedFabricWireErrorCode::BindingNotAllowed, 2))?;
    let execution = ManagedFabricTargetExecutionV1::decode(execution_frame)?;
    if execution.projection().target() != target {
        return Err(wire_at(ManagedFabricWireErrorCode::TargetMismatch, 2));
    }
    if execution.projection() != projection {
        return Err(wire(ManagedFabricWireErrorCode::CompatibilityMismatch));
    }
    let assignments = ManagedFabricTargetAssignmentsV1::try_new(bindings, execution)
        .map_err(|_| wire(ManagedFabricWireErrorCode::CrossReferenceMismatch))?;
    let header = RuntimeSliceHeader::new(target, provenance, assignments.assignment_digest);
    let commitment = RuntimeSliceCommitment::try_new(header)?;
    if commitment.target_slice_digest() != expected_target_slice_digest {
        return Err(wire_at(ManagedFabricWireErrorCode::DigestMismatch, 8));
    }
    let slice = ManagedFabricPlanSliceV1::try_new(commitment, assignments)?;
    Ok(slice.assignments.execution)
}

/// Computes the exact successor compatibility fingerprint embedded in projection v1.
pub fn managed_fabric_compatibility_digest_v1() -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(COMPILED_COMPATIBILITY_DIGEST_DOMAIN)?;
    builder.field_bytes(APPLY_REQUEST_MAGIC)?;
    builder.field_u16(MANAGED_FABRIC_APPLY_REQUEST_VERSION)?;
    builder.field_u16(APPLY_REQUEST_HEADER_BYTES as u16)?;
    builder.field_bytes(&(MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES as u32).to_be_bytes())?;
    builder.field_bytes(TARGET_EXECUTION_MAGIC)?;
    builder.field_u16(MANAGED_FABRIC_TARGET_EXECUTION_VERSION)?;
    builder.field_bytes(&(MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES as u32).to_be_bytes())?;
    builder.field_u16(PROJECTION_BYTES as u16)?;
    builder.field_bytes(&EMPTY_PXTA)?;
    builder.field_u16(MANAGED_FABRIC_APPLY_ENVELOPE_VERSION)?;
    builder.field_bytes(&(MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES as u32).to_be_bytes())?;
    builder.field_u16(MANAGED_FABRIC_PROFILE_VERSION)?;
    builder.field_u16(MANAGED_SERVICE_CONTRACT_VERSION)?;
    builder.field_u64(MAX_MANAGED_FABRIC_LIFECYCLE_NANOS)?;
    builder.field_u16(MAX_MANAGED_FABRIC_LISTEN_ENDPOINT_BYTES as u16)?;
    builder.field_bytes(LOOPBACK_TCP_PREFIX.as_bytes())?;
    builder.field_bytes(TARGET_EXECUTION_DIGEST_DOMAIN)?;
    builder.field_bytes(TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN)?;
    builder.field_bytes(PROJECTION_MAGIC)?;
    builder.field_u16(MANAGED_FABRIC_PROJECTION_VERSION)?;
    builder.field_bytes(TERMINAL_RECEIPT_MAGIC)?;
    builder.field_u16(MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_VERSION)?;
    builder.field_u16(TERMINAL_RECEIPT_FIELD_COUNT)?;
    builder.field_bytes(&(MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES as u32).to_be_bytes())?;
    builder.field_u16(MANAGED_FABRIC_APPLY_TERMINAL_SIGNING_TRANSCRIPT_VERSION)?;
    builder.field_u16(MAX_MANAGED_FABRIC_APPLY_TERMINAL_SIGNATURE_BYTES as u16)?;
    builder.field_bytes(TERMINAL_RECEIPT_SIGNING_DOMAIN)?;
    builder.field_bytes(TERMINAL_RECEIPT_DIGEST_DOMAIN)?;
    builder.field_bytes(TERMINAL_RESULT_REF_DOMAIN)?;
    Ok(builder.finish())
}

/// Runtime-owned terminal outcome for one managed-fabric apply operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum ManagedFabricApplyTerminalOutcomeV1 {
    /// The incoming singleton service is the committed ready generation.
    ActiveReady = 1,
    /// The incoming empty target is committed and the live generation is absent.
    EmptyExactZero = 2,
    /// Admission or expiry produced no lifecycle effect and preserved the head.
    NoEffectRejected = 3,
    /// Lifecycle effects may exist but exact ownership/live state is uncertain.
    Uncertain = 4,
    /// The incoming service head is committed but its generation is quarantined.
    Quarantined = 5,
}

/// Whether managed-service lifecycle execution crossed its first effect boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum ManagedFabricApplyTerminalLifecycleEffectV1 {
    /// Runtime proves no lifecycle callback or resource effect started.
    ProvenNotStarted = 1,
    /// At least one lifecycle/resource effect may have started.
    MayHaveStarted = 2,
}

/// Desired-head disposition atomically associated with terminal selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ManagedFabricApplyTerminalHeadV1 {
    /// No desired head existed and that absence was preserved.
    PreservedNone,
    /// This exact prior desired head was preserved.
    PreservedExisting(TargetSliceDigest),
    /// The exact incoming PXAR v6 slice was committed.
    CommittedIncoming,
}

/// Contract-derived stable identity of one exact managed-fabric terminal result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedFabricApplyTerminalResultRefV1([u8; 16]);

impl ManagedFabricApplyTerminalResultRefV1 {
    /// Returns the nonzero canonical result-reference bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Runtime-selected terminal state before it is correlated to one exact request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedFabricApplyTerminalStateV1 {
    outcome: ManagedFabricApplyTerminalOutcomeV1,
    lifecycle_effect: ManagedFabricApplyTerminalLifecycleEffectV1,
    head: ManagedFabricApplyTerminalHeadV1,
    generation: Option<ManagedServiceGeneration>,
}

impl ManagedFabricApplyTerminalStateV1 {
    /// Validates the outcome, lifecycle-effect, head, and generation shape.
    pub fn try_new(
        outcome: ManagedFabricApplyTerminalOutcomeV1,
        lifecycle_effect: ManagedFabricApplyTerminalLifecycleEffectV1,
        head: ManagedFabricApplyTerminalHeadV1,
        generation: Option<ManagedServiceGeneration>,
    ) -> Result<Self, ManagedFabricPlanError> {
        let state = Self {
            outcome,
            lifecycle_effect,
            head,
            generation,
        };
        validate_terminal_state_shape(state)?;
        Ok(state)
    }

    /// Returns the primary terminal outcome.
    #[must_use]
    pub const fn outcome(self) -> ManagedFabricApplyTerminalOutcomeV1 {
        self.outcome
    }

    /// Returns the lifecycle-effect boundary fact.
    #[must_use]
    pub const fn lifecycle_effect(self) -> ManagedFabricApplyTerminalLifecycleEffectV1 {
        self.lifecycle_effect
    }

    /// Returns the desired-head disposition.
    #[must_use]
    pub const fn head(self) -> ManagedFabricApplyTerminalHeadV1 {
        self.head
    }

    /// Returns the Runtime-produced live generation when present.
    #[must_use]
    pub const fn generation(self) -> Option<ManagedServiceGeneration> {
        self.generation
    }
}

/// Runtime-owned evidence attached to one terminal state selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedFabricApplyTerminalEvidenceV1 {
    resource_census_digest: Digest32,
    raw_outcome_digest: Digest32,
    completion_runtime_host_epoch: u64,
    completion_snapshot_sequence: u64,
    selection_clock_generation: ClockGeneration,
    selection_observed_at_nanos: u64,
}

impl ManagedFabricApplyTerminalEvidenceV1 {
    /// Validates nonzero completion and observation evidence.
    pub fn try_new(
        resource_census_digest: Digest32,
        raw_outcome_digest: Digest32,
        completion_runtime_host_epoch: u64,
        completion_snapshot_sequence: u64,
        selection_clock_generation: ClockGeneration,
        selection_observed_at_nanos: u64,
    ) -> Result<Self, ManagedFabricPlanError> {
        let evidence = Self {
            resource_census_digest,
            raw_outcome_digest,
            completion_runtime_host_epoch,
            completion_snapshot_sequence,
            selection_clock_generation,
            selection_observed_at_nanos,
        };
        validate_terminal_evidence(evidence)?;
        Ok(evidence)
    }

    /// Returns the exact completion resource/session census digest.
    #[must_use]
    pub const fn resource_census_digest(self) -> Digest32 {
        self.resource_census_digest
    }

    /// Returns the Runtime-owned raw outcome/reason digest.
    #[must_use]
    pub const fn raw_outcome_digest(self) -> Digest32 {
        self.raw_outcome_digest
    }

    /// Returns the nonzero RuntimeHost epoch that committed completion.
    #[must_use]
    pub const fn completion_runtime_host_epoch(self) -> u64 {
        self.completion_runtime_host_epoch
    }

    /// Returns the nonzero Runtime snapshot sequence that committed completion.
    #[must_use]
    pub const fn completion_snapshot_sequence(self) -> u64 {
        self.completion_snapshot_sequence
    }

    /// Returns the owner-local clock generation used for terminal selection.
    #[must_use]
    pub const fn selection_clock_generation(self) -> ClockGeneration {
        self.selection_clock_generation
    }

    /// Returns the owner-local terminal-selection tick in nanoseconds.
    #[must_use]
    pub const fn selection_observed_at_nanos(self) -> u64 {
        self.selection_observed_at_nanos
    }
}

/// Immutable Runtime-owned facts carried by one PXFT terminal Receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedFabricApplyTerminalFactsV1 {
    outcome: ManagedFabricApplyTerminalOutcomeV1,
    lifecycle_effect: ManagedFabricApplyTerminalLifecycleEffectV1,
    head: ManagedFabricApplyTerminalHeadV1,
    desired_head_digest: Option<TargetSliceDigest>,
    generation: Option<ManagedServiceGeneration>,
    resource_census_digest: Digest32,
    raw_outcome_digest: Digest32,
    completion_runtime_host_epoch: u64,
    completion_snapshot_sequence: u64,
    selection_clock_generation: ClockGeneration,
    selection_observed_at_nanos: u64,
    terminal_result_ref: ManagedFabricApplyTerminalResultRefV1,
}

impl ManagedFabricApplyTerminalFactsV1 {
    /// Builds terminal facts for one exact PXAR v6 request.
    ///
    /// The typed state and evidence inputs are validated before request-specific
    /// target mode, expected-head, and temporal correlation is admitted.
    pub fn try_new(
        request: &ManagedFabricApplyRequestV1,
        state: ManagedFabricApplyTerminalStateV1,
        evidence: ManagedFabricApplyTerminalEvidenceV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        validate_terminal_state_shape(state)?;
        validate_terminal_evidence(evidence)?;
        let desired_head_digest = resolve_terminal_head(request, state.head)?;
        let terminal_result_ref = derive_terminal_result_ref(request)?;
        let facts = Self {
            outcome: state.outcome,
            lifecycle_effect: state.lifecycle_effect,
            head: state.head,
            desired_head_digest,
            generation: state.generation,
            resource_census_digest: evidence.resource_census_digest,
            raw_outcome_digest: evidence.raw_outcome_digest,
            completion_runtime_host_epoch: evidence.completion_runtime_host_epoch,
            completion_snapshot_sequence: evidence.completion_snapshot_sequence,
            selection_clock_generation: evidence.selection_clock_generation,
            selection_observed_at_nanos: evidence.selection_observed_at_nanos,
            terminal_result_ref,
        };
        validate_terminal_facts_against_request(facts, request)?;
        Ok(facts)
    }

    /// Returns the primary terminal outcome.
    #[must_use]
    pub const fn outcome(self) -> ManagedFabricApplyTerminalOutcomeV1 {
        self.outcome
    }

    /// Returns the lifecycle-effect boundary fact.
    #[must_use]
    pub const fn lifecycle_effect(self) -> ManagedFabricApplyTerminalLifecycleEffectV1 {
        self.lifecycle_effect
    }

    /// Returns the desired-head disposition.
    #[must_use]
    pub const fn head(self) -> ManagedFabricApplyTerminalHeadV1 {
        self.head
    }

    /// Returns the resulting desired-head digest, if present.
    #[must_use]
    pub const fn desired_head_digest(self) -> Option<TargetSliceDigest> {
        self.desired_head_digest
    }

    /// Returns the Runtime-produced live generation when the outcome requires one.
    #[must_use]
    pub const fn generation(self) -> Option<ManagedServiceGeneration> {
        self.generation
    }

    /// Returns the exact completion resource/session census digest.
    #[must_use]
    pub const fn resource_census_digest(self) -> Digest32 {
        self.resource_census_digest
    }

    /// Returns the Runtime-owned raw outcome/reason digest.
    #[must_use]
    pub const fn raw_outcome_digest(self) -> Digest32 {
        self.raw_outcome_digest
    }

    /// Returns the nonzero RuntimeHost epoch that committed completion.
    #[must_use]
    pub const fn completion_runtime_host_epoch(self) -> u64 {
        self.completion_runtime_host_epoch
    }

    /// Returns the nonzero Runtime snapshot sequence that committed completion.
    #[must_use]
    pub const fn completion_snapshot_sequence(self) -> u64 {
        self.completion_snapshot_sequence
    }

    /// Returns the owner-local clock generation used for terminal selection.
    #[must_use]
    pub const fn selection_clock_generation(self) -> ClockGeneration {
        self.selection_clock_generation
    }

    /// Returns the owner-local terminal-selection tick in nanoseconds.
    #[must_use]
    pub const fn selection_observed_at_nanos(self) -> u64 {
        self.selection_observed_at_nanos
    }

    /// Returns the request-derived stable terminal-result reference.
    #[must_use]
    pub const fn terminal_result_ref(self) -> ManagedFabricApplyTerminalResultRefV1 {
        self.terminal_result_ref
    }
}

/// Runtime response signer bound to one request-time local control channel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedFabricApplyTerminalReceiptAuthClaimV1 {
    inner: RuntimeResponseAuthClaimV1,
}

impl ManagedFabricApplyTerminalReceiptAuthClaimV1 {
    /// Selects a Runtime response key while deriving peer/channel facts.
    pub fn try_new(
        channel: ReferenceChannelBindingV1,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, ManagedFabricPlanError> {
        Ok(Self {
            inner: RuntimeResponseAuthClaimV1::try_new(
                channel.runtime_peer(),
                channel.binding_digest(),
                key,
                algorithm,
                algorithm_version,
            )
            .map_err(|_| ManagedFabricPlanError::InvalidResponseAuthentication)?,
        })
    }

    /// Returns the authenticated Runtime peer.
    #[must_use]
    pub const fn runtime_peer(self) -> PrincipalRef {
        self.inner.runtime_peer()
    }

    /// Returns the exact request-time channel binding digest.
    #[must_use]
    pub const fn channel_binding_digest(self) -> Digest32 {
        self.inner.channel_binding_digest()
    }

    /// Returns the Runtime response-key selector.
    #[must_use]
    pub const fn key(self) -> ApplyAuthKeyRef {
        self.inner.key()
    }

    /// Returns the response signature algorithm selector.
    #[must_use]
    pub const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.inner.algorithm()
    }

    /// Returns the response signature algorithm version.
    #[must_use]
    pub const fn algorithm_version(self) -> u16 {
        self.inner.algorithm_version()
    }
}

/// Canonical signature-independent PXFT response transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFabricApplyTerminalReceiptSigningTranscriptV1(Box<[u8]>);

impl ManagedFabricApplyTerminalReceiptSigningTranscriptV1 {
    /// Returns exact bytes a Runtime signer signs or Controller verifies.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent terminal Receipt for one exact PXAR v6 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFabricApplyTerminalReceiptDraftV1 {
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    provenance: PlanProvenance,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    target_slice_digest: TargetSliceDigest,
    assignment_digest: TargetAssignmentDigest,
    facts: ManagedFabricApplyTerminalFactsV1,
    auth_claim: RuntimeResponseAuthClaimV1,
}

impl ManagedFabricApplyTerminalReceiptDraftV1 {
    /// Binds terminal facts to the exact PXAR v6 request and response channel.
    pub fn try_new(
        request: &ManagedFabricApplyRequestV1,
        facts: ManagedFabricApplyTerminalFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ManagedFabricApplyTerminalReceiptAuthClaimV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        validate_terminal_facts_against_request(facts, request)?;
        if channel.target() != request.target()
            || auth_claim.runtime_peer() != channel.runtime_peer()
            || auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ManagedFabricPlanError::TerminalCorrelationMismatch);
        }
        let store =
            RuntimeStoreInstanceId::try_from_bytes(request.expected_runtime_store_instance_id())
                .map_err(map_reference_contract_error)?;
        Ok(Self {
            target: request.target(),
            store,
            provenance: request.provenance(),
            operation_id: request.operation_id(),
            request_digest: request.envelope_request_digest(),
            request_nonce: request.authentication().claim().nonce().into(),
            target_slice_digest: request.target_slice_digest(),
            assignment_digest: request.assignment_digest(),
            facts,
            auth_claim: auth_claim.inner,
        })
    }

    /// Returns exact signature-independent PXFT response bytes.
    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedFabricApplyTerminalReceiptSigningTranscriptV1, ManagedFabricPlanError> {
        build_terminal_signing_transcript(self)
    }

    /// Adds the opaque Runtime signature and freezes exact PXFT bytes.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ManagedFabricApplyTerminalReceiptV1, ManagedFabricPlanError> {
        let authentication = RuntimeResponseAuthenticationV1::try_new(self.auth_claim, signature)
            .map_err(|_| ManagedFabricPlanError::InvalidResponseAuthentication)?;
        ManagedFabricApplyTerminalReceiptV1::try_new(self, authentication)
    }
}

/// Signed strict terminal Receipt for one managed-fabric apply operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFabricApplyTerminalReceiptV1 {
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    provenance: PlanProvenance,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    target_slice_digest: TargetSliceDigest,
    assignment_digest: TargetAssignmentDigest,
    facts: ManagedFabricApplyTerminalFactsV1,
    authentication: RuntimeResponseAuthenticationV1,
    canonical_wire: Box<[u8]>,
    receipt_digest: Digest32,
}

impl ManagedFabricApplyTerminalReceiptV1 {
    fn try_new(
        draft: ManagedFabricApplyTerminalReceiptDraftV1,
        authentication: RuntimeResponseAuthenticationV1,
    ) -> Result<Self, ManagedFabricPlanError> {
        validate_terminal_receipt_parts(&draft, &authentication)?;
        let canonical_wire = build_terminal_receipt_wire(&draft, &authentication);
        if canonical_wire.len() > MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES {
            return Err(ManagedFabricPlanError::RequestFrameTooLarge);
        }
        let receipt_digest = digest_wire(TERMINAL_RECEIPT_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            target: draft.target,
            store: draft.store,
            provenance: draft.provenance,
            operation_id: draft.operation_id,
            request_digest: draft.request_digest,
            request_nonce: draft.request_nonce,
            target_slice_digest: draft.target_slice_digest,
            assignment_digest: draft.assignment_digest,
            facts: draft.facts,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            receipt_digest,
        })
    }

    /// Strictly decodes exactly PXFT v1 without PXRT fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedFabricPlanError> {
        decode_terminal_receipt(frame)
    }

    /// Returns the exact Runtime target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    /// Returns the exact expected Runtime journal/store identity.
    #[must_use]
    pub const fn runtime_store_instance_id(&self) -> [u8; 32] {
        *self.store.as_bytes()
    }

    /// Returns complete source-plan provenance copied from the request slice.
    #[must_use]
    pub const fn provenance(&self) -> PlanProvenance {
        self.provenance
    }

    /// Returns the source desired-state scope.
    #[must_use]
    pub const fn source_scope(&self) -> SourceScopeRef {
        self.provenance.source_scope()
    }

    /// Returns the exact apply-operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> ApplyOperationId {
        self.operation_id
    }

    /// Returns the digest of the exact signed envelope in PXAR v6.
    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    /// Returns the exact request-auth nonce correlated by the response.
    #[must_use]
    pub fn request_nonce(&self) -> &[u8] {
        &self.request_nonce
    }

    /// Returns the exact incoming target-slice digest.
    #[must_use]
    pub const fn target_slice_digest(&self) -> TargetSliceDigest {
        self.target_slice_digest
    }

    /// Returns the exact composite assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.assignment_digest
    }

    /// Returns decoded Runtime-owned terminal facts.
    #[must_use]
    pub const fn facts(&self) -> ManagedFabricApplyTerminalFactsV1 {
        self.facts
    }

    /// Returns the live Runtime generation when the outcome requires one.
    #[must_use]
    pub const fn generation(&self) -> Option<ManagedServiceGeneration> {
        self.facts.generation()
    }

    /// Returns the authenticated Runtime peer.
    #[must_use]
    pub const fn authentication_runtime_peer(&self) -> PrincipalRef {
        self.authentication.claim().runtime_peer()
    }

    /// Returns the exact request-time response channel commitment.
    #[must_use]
    pub const fn authentication_channel_binding_digest(&self) -> Digest32 {
        self.authentication.claim().channel_binding_digest()
    }

    /// Returns the response-key selector.
    #[must_use]
    pub const fn authentication_key(&self) -> ApplyAuthKeyRef {
        self.authentication.claim().key()
    }

    /// Returns the response signature algorithm.
    #[must_use]
    pub const fn authentication_algorithm(&self) -> ApplyAuthAlgorithm {
        self.authentication.claim().algorithm()
    }

    /// Returns the response signature algorithm version.
    #[must_use]
    pub const fn authentication_algorithm_version(&self) -> u16 {
        self.authentication.claim().algorithm_version()
    }

    /// Returns the opaque Runtime response signature.
    #[must_use]
    pub fn authentication_signature(&self) -> &[u8] {
        self.authentication.signature()
    }

    /// Returns exact canonical PXFT v1 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the domain-separated digest of complete signed PXFT bytes.
    #[must_use]
    pub const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }

    /// Reconstructs exact signature-independent Runtime response bytes.
    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedFabricApplyTerminalReceiptSigningTranscriptV1, ManagedFabricPlanError> {
        let draft = self.as_draft();
        build_terminal_signing_transcript(&draft)
    }

    /// Validates exact request and request-time response-channel correlation.
    ///
    /// Cryptographic signature verification remains caller-owned and consumes
    /// [`Self::signing_transcript`] plus [`Self::authentication_signature`].
    pub fn validate_against_request(
        &self,
        request: &ManagedFabricApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<ManagedFabricApplyTerminalFactsV1, ManagedFabricPlanError> {
        if self.target != request.target() || channel.target() != request.target() {
            return Err(wire_at(ManagedFabricWireErrorCode::TargetMismatch, 1));
        }
        if self.runtime_store_instance_id() != request.expected_runtime_store_instance_id() {
            return Err(wire_at(ManagedFabricWireErrorCode::RuntimeStoreMismatch, 2));
        }
        let provenance = request.provenance();
        if self.provenance.source_scope() != provenance.source_scope()
            || self.provenance.source_plan() != provenance.source_plan()
            || self.provenance.source_revision() != provenance.source_revision()
            || self.provenance.source_plan_digest() != provenance.source_plan_digest()
        {
            return Err(wire_at(
                ManagedFabricWireErrorCode::CrossReferenceMismatch,
                3,
            ));
        }
        if self.operation_id != request.operation_id() {
            return Err(wire_at(
                ManagedFabricWireErrorCode::CrossReferenceMismatch,
                7,
            ));
        }
        if self.request_digest != request.envelope_request_digest() {
            return Err(wire_at(
                ManagedFabricWireErrorCode::CrossReferenceMismatch,
                8,
            ));
        }
        if self.request_nonce.as_ref() != request.authentication().claim().nonce() {
            return Err(wire_at(
                ManagedFabricWireErrorCode::CrossReferenceMismatch,
                9,
            ));
        }
        if self.target_slice_digest != request.target_slice_digest()
            || self.assignment_digest != request.assignment_digest()
        {
            return Err(wire_at(ManagedFabricWireErrorCode::DigestMismatch, 10));
        }
        validate_terminal_facts_against_request(self.facts, request)
            .map_err(|_| wire_at(ManagedFabricWireErrorCode::CrossReferenceMismatch, 12))?;
        if self.authentication.claim().runtime_peer() != channel.runtime_peer() {
            return Err(wire_at(ManagedFabricWireErrorCode::TargetMismatch, 25));
        }
        if self.authentication.claim().channel_binding_digest() != channel.binding_digest() {
            return Err(wire_at(ManagedFabricWireErrorCode::TargetMismatch, 26));
        }
        Ok(self.facts)
    }

    fn as_draft(&self) -> ManagedFabricApplyTerminalReceiptDraftV1 {
        ManagedFabricApplyTerminalReceiptDraftV1 {
            target: self.target,
            store: self.store,
            provenance: self.provenance,
            operation_id: self.operation_id,
            request_digest: self.request_digest,
            request_nonce: self.request_nonce.clone(),
            target_slice_digest: self.target_slice_digest,
            assignment_digest: self.assignment_digest,
            facts: self.facts,
            auth_claim: self.authentication.claim(),
        }
    }
}

/// Stable strict-wire rejection categories for the successor contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ManagedFabricWireErrorCode {
    /// Frame exceeded its protocol bound.
    FrameTooLarge = 1,
    /// Frame ended before a complete field was available.
    Truncated = 2,
    /// Frame magic was not the selected protocol.
    InvalidMagic = 3,
    /// Frame version was not the exact selected version.
    UnsupportedVersion = 4,
    /// Frame contained an unknown TLV field in the retained envelope.
    UnknownField = 5,
    /// Frame duplicated a TLV field in the retained envelope.
    DuplicateField = 6,
    /// Frame fields were not canonically ordered.
    OutOfOrderField = 7,
    /// A required retained-envelope field was absent.
    MissingField = 8,
    /// A declared or fixed field length was invalid.
    InvalidFieldLength = 9,
    /// A field value was invalid.
    InvalidFieldValue = 10,
    /// Canonical rebuilding did not equal received bytes.
    NonCanonicalFrame = 11,
    /// A committed digest disagreed.
    DigestMismatch = 12,
    /// Cross-referenced facts disagreed.
    CrossReferenceMismatch = 13,
    /// Desired target shape was not one of the two admitted modes.
    UnsupportedShape = 14,
    /// PXTA was not exact canonical empty.
    BindingNotAllowed = 15,
    /// Signed expected Runtime store did not equal the local store.
    RuntimeStoreMismatch = 16,
    /// Projection, slice, and envelope target disagreed.
    TargetMismatch = 17,
    /// Retained legacy fixture facts disagreed inside envelope decoding.
    FixtureMismatch = 18,
    /// Retained control response exceeded its bound.
    ResponseBoundExceeded = 19,
    /// Retained stable operational reason was unknown.
    UnknownReason = 20,
    /// Exact canonical frame contained trailing bytes.
    TrailingBytes = 21,
    /// Retained envelope signature field was invalid.
    InvalidSignatureField = 22,
    /// Service presence marker disagreed with the mode.
    InvalidPresence = 23,
    /// Retained artifact facts disagreed.
    ArtifactMismatch = 24,
    /// Installed successor projection disagreed.
    CompatibilityMismatch = 25,
}

/// One fail-closed wire rejection with optional field detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedFabricWireError {
    code: ManagedFabricWireErrorCode,
    detail: Option<u16>,
}

impl ManagedFabricWireError {
    /// Returns the stable rejection code.
    #[must_use]
    pub const fn code(self) -> ManagedFabricWireErrorCode {
        self.code
    }

    /// Returns optional field detail.
    #[must_use]
    pub const fn detail(self) -> Option<u16> {
        self.detail
    }
}

/// Construction and strict-decoding failures for the successor plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedFabricPlanError {
    /// Domain-separated digest construction failed.
    Digest(DigestBuildError),
    /// Projection contains zero or mismatched compatibility facts.
    InvalidProjection,
    /// Managed service identity is the reserved all-zero value.
    InvalidServiceId,
    /// One lifecycle budget is zero or exceeds the profile ceiling.
    InvalidLifecycleBudget(ManagedServiceLifecycleStage),
    /// Endpoint is not the canonical explicit loopback TCP value.
    InvalidListenEndpoint,
    /// Service and empty-mode fields do not form an admitted shape.
    InvalidShape,
    /// The zero-binding profile received a PXTA assignment.
    BindingNotAllowed,
    /// Projection and slice targets disagree.
    TargetMismatch,
    /// Existing provenance commitment construction failed.
    Provenance(ProvenanceContractError),
    /// Existing writer/CAS control construction failed.
    Apply(ApplyContractError),
    /// Existing signed envelope facts were invalid.
    EnvelopeInvalid,
    /// Runtime terminal outcome/generation/head facts violate the strict matrix.
    InvalidTerminalFacts,
    /// Runtime response authentication claim or signature field is invalid.
    InvalidResponseAuthentication,
    /// Terminal facts, request, or response channel do not correlate exactly.
    TerminalCorrelationMismatch,
    /// Expected Runtime store identity was zero.
    InvalidRuntimeStoreInstanceId,
    /// Canonical request exceeded its fixed bound.
    RequestFrameTooLarge,
    /// Slice and control commitments disagree.
    CommitmentMismatch,
    /// Strict canonical decoding rejected the frame.
    Wire(ManagedFabricWireError),
}

impl fmt::Display for ManagedFabricPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(error) => write!(formatter, "managed-fabric digest failed: {error}"),
            Self::InvalidProjection => formatter.write_str("invalid managed-fabric projection"),
            Self::InvalidServiceId => formatter.write_str("managed-service id must be nonzero"),
            Self::InvalidLifecycleBudget(stage) => write!(
                formatter,
                "managed-service {stage:?} budget is outside the profile bound"
            ),
            Self::InvalidListenEndpoint => {
                formatter.write_str("invalid canonical managed-fabric listen endpoint")
            }
            Self::InvalidShape => formatter.write_str("invalid managed-fabric target shape"),
            Self::BindingNotAllowed => {
                formatter.write_str("managed-fabric target cannot carry a PXTA binding")
            }
            Self::TargetMismatch => formatter.write_str("managed-fabric Runtime target mismatch"),
            Self::Provenance(error) => {
                write!(formatter, "managed-fabric provenance failed: {error}")
            }
            Self::Apply(error) => write!(formatter, "managed-fabric apply control failed: {error}"),
            Self::EnvelopeInvalid => formatter.write_str("invalid retained apply envelope v2"),
            Self::InvalidTerminalFacts => {
                formatter.write_str("invalid managed-fabric terminal facts")
            }
            Self::InvalidResponseAuthentication => {
                formatter.write_str("invalid managed-fabric response authentication")
            }
            Self::TerminalCorrelationMismatch => {
                formatter.write_str("managed-fabric terminal correlation mismatch")
            }
            Self::InvalidRuntimeStoreInstanceId => {
                formatter.write_str("invalid Runtime store instance id")
            }
            Self::RequestFrameTooLarge => {
                formatter.write_str("managed-fabric request frame is too large")
            }
            Self::CommitmentMismatch => {
                formatter.write_str("managed-fabric request commitment mismatch")
            }
            Self::Wire(error) => {
                if let Some(detail) = error.detail {
                    write!(
                        formatter,
                        "managed-fabric wire error {:?} at {detail}",
                        error.code
                    )
                } else {
                    write!(formatter, "managed-fabric wire error {:?}", error.code)
                }
            }
        }
    }
}

impl std::error::Error for ManagedFabricPlanError {}

impl From<DigestBuildError> for ManagedFabricPlanError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ProvenanceContractError> for ManagedFabricPlanError {
    fn from(value: ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<ApplyContractError> for ManagedFabricPlanError {
    fn from(value: ApplyContractError) -> Self {
        Self::Apply(value)
    }
}

fn resolve_terminal_head(
    request: &ManagedFabricApplyRequestV1,
    head: ManagedFabricApplyTerminalHeadV1,
) -> Result<Option<TargetSliceDigest>, ManagedFabricPlanError> {
    match head {
        ManagedFabricApplyTerminalHeadV1::PreservedNone => Ok(None),
        ManagedFabricApplyTerminalHeadV1::PreservedExisting(digest)
            if !digest_is_zero(*digest.value()) =>
        {
            Ok(Some(digest))
        }
        ManagedFabricApplyTerminalHeadV1::PreservedExisting(_) => {
            Err(ManagedFabricPlanError::InvalidTerminalFacts)
        }
        ManagedFabricApplyTerminalHeadV1::CommittedIncoming => {
            Ok(Some(request.target_slice_digest()))
        }
    }
}

fn derive_terminal_result_ref(
    request: &ManagedFabricApplyRequestV1,
) -> Result<ManagedFabricApplyTerminalResultRefV1, ManagedFabricPlanError> {
    let store =
        RuntimeStoreInstanceId::try_from_bytes(request.expected_runtime_store_instance_id())
            .map_err(map_reference_contract_error)?;
    derive_terminal_result_ref_parts(
        request.target(),
        store,
        request.provenance().source_scope(),
        request.operation_id(),
        request.envelope_request_digest(),
    )
}

fn derive_terminal_result_ref_parts(
    target: RuntimeHostId,
    store: RuntimeStoreInstanceId,
    source_scope: SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
) -> Result<ManagedFabricApplyTerminalResultRefV1, ManagedFabricPlanError> {
    let mut builder = Digest32Builder::try_new(TERMINAL_RESULT_REF_DOMAIN)?;
    builder.field_bytes(TERMINAL_RECEIPT_MAGIC)?;
    builder.field_u16(MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_VERSION)?;
    builder.field_bytes(target.as_bytes())?;
    builder.field_bytes(store.as_bytes())?;
    builder.field_bytes(source_scope.as_bytes())?;
    builder.field_bytes(operation_id.as_bytes())?;
    builder.field_digest(&request_digest)?;
    let digest = builder.finish();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ManagedFabricPlanError::InvalidTerminalFacts);
    }
    Ok(ManagedFabricApplyTerminalResultRefV1(bytes))
}

fn validate_terminal_state_shape(
    state: ManagedFabricApplyTerminalStateV1,
) -> Result<(), ManagedFabricPlanError> {
    let has_generation = state.generation.is_some();
    let disposition = terminal_head_disposition(state.head);
    let valid = match state.outcome {
        ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        | ManagedFabricApplyTerminalOutcomeV1::Quarantined => {
            has_generation
                && state.lifecycle_effect
                    == ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted
                && disposition == 3
        }
        ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero => !has_generation && disposition == 3,
        ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected => {
            !has_generation
                && state.lifecycle_effect
                    == ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted
                && disposition != 3
        }
        ManagedFabricApplyTerminalOutcomeV1::Uncertain => {
            has_generation
                && state.lifecycle_effect
                    == ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted
        }
    };
    if !valid {
        return Err(ManagedFabricPlanError::InvalidTerminalFacts);
    }
    Ok(())
}

fn validate_terminal_evidence(
    evidence: ManagedFabricApplyTerminalEvidenceV1,
) -> Result<(), ManagedFabricPlanError> {
    if digest_is_zero(evidence.resource_census_digest)
        || digest_is_zero(evidence.raw_outcome_digest)
        || evidence.completion_runtime_host_epoch == 0
        || evidence.completion_snapshot_sequence == 0
        || evidence.selection_observed_at_nanos == 0
    {
        return Err(ManagedFabricPlanError::InvalidTerminalFacts);
    }
    Ok(())
}

fn validate_terminal_facts_general(
    facts: ManagedFabricApplyTerminalFactsV1,
) -> Result<(), ManagedFabricPlanError> {
    validate_terminal_state_shape(ManagedFabricApplyTerminalStateV1 {
        outcome: facts.outcome,
        lifecycle_effect: facts.lifecycle_effect,
        head: facts.head,
        generation: facts.generation,
    })?;
    validate_terminal_evidence(ManagedFabricApplyTerminalEvidenceV1 {
        resource_census_digest: facts.resource_census_digest,
        raw_outcome_digest: facts.raw_outcome_digest,
        completion_runtime_host_epoch: facts.completion_runtime_host_epoch,
        completion_snapshot_sequence: facts.completion_snapshot_sequence,
        selection_clock_generation: facts.selection_clock_generation,
        selection_observed_at_nanos: facts.selection_observed_at_nanos,
    })?;
    match (facts.head, facts.desired_head_digest) {
        (ManagedFabricApplyTerminalHeadV1::PreservedNone, None) => {}
        (ManagedFabricApplyTerminalHeadV1::PreservedExisting(expected), Some(actual))
            if expected == actual && !digest_is_zero(*actual.value()) => {}
        (ManagedFabricApplyTerminalHeadV1::CommittedIncoming, Some(actual))
            if !digest_is_zero(*actual.value()) => {}
        _ => return Err(ManagedFabricPlanError::InvalidTerminalFacts),
    }
    Ok(())
}

fn validate_terminal_facts_against_request(
    facts: ManagedFabricApplyTerminalFactsV1,
    request: &ManagedFabricApplyRequestV1,
) -> Result<(), ManagedFabricPlanError> {
    validate_terminal_facts_general(facts)?;
    if facts.terminal_result_ref != derive_terminal_result_ref(request)?
        || facts.selection_clock_generation.value()
            < request.temporal().target_clock_generation().value()
    {
        return Err(ManagedFabricPlanError::TerminalCorrelationMismatch);
    }
    let request_mode = request.target_execution().mode();
    match facts.outcome {
        ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        | ManagedFabricApplyTerminalOutcomeV1::Quarantined
            if request_mode != ManagedFabricTargetModeV1::OneManagedFabricService =>
        {
            return Err(ManagedFabricPlanError::InvalidTerminalFacts);
        }
        ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero
            if request_mode != ManagedFabricTargetModeV1::EmptyDeactivate =>
        {
            return Err(ManagedFabricPlanError::InvalidTerminalFacts);
        }
        _ => {}
    }
    let incoming = request.target_slice_digest();
    let committed = facts.desired_head_digest == Some(incoming);
    match facts.outcome {
        ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        | ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero
        | ManagedFabricApplyTerminalOutcomeV1::Quarantined
            if !committed =>
        {
            return Err(ManagedFabricPlanError::InvalidTerminalFacts);
        }
        ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected => {}
        ManagedFabricApplyTerminalOutcomeV1::Uncertain
            if !committed && !terminal_head_preserves_expected(facts, request) =>
        {
            return Err(ManagedFabricPlanError::InvalidTerminalFacts);
        }
        _ => {}
    }
    Ok(())
}

fn terminal_head_preserves_expected(
    facts: ManagedFabricApplyTerminalFactsV1,
    request: &ManagedFabricApplyRequestV1,
) -> bool {
    match request.control_commitment().control().expected_active() {
        ExpectedActive::None => {
            facts.head == ManagedFabricApplyTerminalHeadV1::PreservedNone
                && facts.desired_head_digest.is_none()
        }
        ExpectedActive::Exact(expected) => {
            facts.head == ManagedFabricApplyTerminalHeadV1::PreservedExisting(expected)
                && facts.desired_head_digest == Some(expected)
        }
    }
}

const fn terminal_head_disposition(head: ManagedFabricApplyTerminalHeadV1) -> u16 {
    match head {
        ManagedFabricApplyTerminalHeadV1::PreservedNone => 1,
        ManagedFabricApplyTerminalHeadV1::PreservedExisting(_) => 2,
        ManagedFabricApplyTerminalHeadV1::CommittedIncoming => 3,
    }
}

fn validate_terminal_receipt_parts(
    draft: &ManagedFabricApplyTerminalReceiptDraftV1,
    authentication: &RuntimeResponseAuthenticationV1,
) -> Result<(), ManagedFabricPlanError> {
    validate_terminal_facts_general(draft.facts)?;
    if draft.request_nonce.is_empty()
        || draft.request_nonce.len() > 64
        || digest_is_zero(draft.request_digest)
        || digest_is_zero(*draft.target_slice_digest.value())
        || digest_is_zero(*draft.assignment_digest.value())
        || authentication.claim() != draft.auth_claim
        || authentication.signature().is_empty()
        || authentication.signature().len() > MAX_MANAGED_FABRIC_APPLY_TERMINAL_SIGNATURE_BYTES
        || derive_terminal_result_ref_parts(
            draft.target,
            draft.store,
            draft.provenance.source_scope(),
            draft.operation_id,
            draft.request_digest,
        )? != draft.facts.terminal_result_ref
    {
        return Err(ManagedFabricPlanError::InvalidTerminalFacts);
    }
    Ok(())
}

fn build_terminal_signing_transcript(
    draft: &ManagedFabricApplyTerminalReceiptDraftV1,
) -> Result<ManagedFabricApplyTerminalReceiptSigningTranscriptV1, ManagedFabricPlanError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(SIGNING_TRANSCRIPT_MAGIC);
    encoded
        .extend_from_slice(&MANAGED_FABRIC_APPLY_TERMINAL_SIGNING_TRANSCRIPT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(TERMINAL_RECEIPT_SIGNING_DOMAIN.len() as u16).to_be_bytes());
    encoded.extend_from_slice(TERMINAL_RECEIPT_SIGNING_DOMAIN);
    encoded.extend_from_slice(&TERMINAL_RECEIPT_SIGNING_FIELD_COUNT.to_be_bytes());
    append_terminal_receipt_fields(&mut encoded, draft, None);
    if encoded.len() > MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES {
        return Err(ManagedFabricPlanError::RequestFrameTooLarge);
    }
    Ok(ManagedFabricApplyTerminalReceiptSigningTranscriptV1(
        encoded.into_boxed_slice(),
    ))
}

fn build_terminal_receipt_wire(
    draft: &ManagedFabricApplyTerminalReceiptDraftV1,
    authentication: &RuntimeResponseAuthenticationV1,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(TERMINAL_RECEIPT_MAGIC);
    encoded.extend_from_slice(&MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&TERMINAL_RECEIPT_FIELD_COUNT.to_be_bytes());
    append_terminal_receipt_fields(&mut encoded, draft, Some(authentication.signature()));
    encoded
}

fn append_terminal_receipt_fields(
    encoded: &mut Vec<u8>,
    draft: &ManagedFabricApplyTerminalReceiptDraftV1,
    signature: Option<&[u8]>,
) {
    let facts = draft.facts;
    let desired_head = facts
        .desired_head_digest
        .map_or(Digest32::from_bytes([0; 32]), |digest| *digest.value());
    let (generation_presence, generation) = facts
        .generation
        .map_or((0_u8, 0_u64), |generation| (1, generation.value()));
    append_tlv(encoded, 1, draft.target.as_bytes());
    append_tlv(encoded, 2, draft.store.as_bytes());
    append_tlv(encoded, 3, draft.provenance.source_scope().as_bytes());
    append_tlv(encoded, 4, draft.provenance.source_plan().as_bytes());
    append_tlv(
        encoded,
        5,
        &draft.provenance.source_revision().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        6,
        draft.provenance.source_plan_digest().value().as_bytes(),
    );
    append_tlv(encoded, 7, draft.operation_id.as_bytes());
    append_tlv(encoded, 8, draft.request_digest.as_bytes());
    append_tlv(encoded, 9, &draft.request_nonce);
    append_tlv(encoded, 10, draft.target_slice_digest.value().as_bytes());
    append_tlv(encoded, 11, draft.assignment_digest.value().as_bytes());
    append_tlv(encoded, 12, &(facts.outcome as u16).to_be_bytes());
    append_tlv(encoded, 13, &(facts.lifecycle_effect as u16).to_be_bytes());
    append_tlv(
        encoded,
        14,
        &terminal_head_disposition(facts.head).to_be_bytes(),
    );
    append_tlv(encoded, 15, desired_head.as_bytes());
    append_tlv(encoded, 16, &[generation_presence]);
    append_tlv(encoded, 17, &generation.to_be_bytes());
    append_tlv(encoded, 18, facts.resource_census_digest.as_bytes());
    append_tlv(encoded, 19, facts.raw_outcome_digest.as_bytes());
    append_tlv(
        encoded,
        20,
        &facts.completion_runtime_host_epoch.to_be_bytes(),
    );
    append_tlv(
        encoded,
        21,
        &facts.completion_snapshot_sequence.to_be_bytes(),
    );
    append_tlv(
        encoded,
        22,
        &facts.selection_clock_generation.value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        23,
        &facts.selection_observed_at_nanos.to_be_bytes(),
    );
    append_tlv(encoded, 24, facts.terminal_result_ref.as_bytes());
    append_tlv(encoded, 25, draft.auth_claim.runtime_peer().as_bytes());
    append_tlv(
        encoded,
        26,
        draft.auth_claim.channel_binding_digest().as_bytes(),
    );
    append_tlv(encoded, 27, draft.auth_claim.key().as_bytes());
    append_tlv(
        encoded,
        28,
        &draft.auth_claim.algorithm().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        29,
        &draft.auth_claim.algorithm_version().to_be_bytes(),
    );
    if let Some(signature) = signature {
        append_tlv(encoded, 30, signature);
    }
}

fn append_tlv(encoded: &mut Vec<u8>, tag: u16, value: &[u8]) {
    encoded.extend_from_slice(&tag.to_be_bytes());
    encoded.extend_from_slice(&(value.len() as u32).to_be_bytes());
    encoded.extend_from_slice(value);
}

struct TerminalParsedFields<'a> {
    values: Vec<&'a [u8]>,
}

impl<'a> TerminalParsedFields<'a> {
    fn get(&self, tag: u16) -> &'a [u8] {
        self.values[usize::from(tag - 1)]
    }

    fn array<const N: usize>(&self, tag: u16) -> Result<[u8; N], ManagedFabricPlanError> {
        self.get(tag)
            .try_into()
            .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldLength, tag))
    }

    fn u16(&self, tag: u16) -> Result<u16, ManagedFabricPlanError> {
        Ok(u16::from_be_bytes(self.array(tag)?))
    }

    fn u64(&self, tag: u16) -> Result<u64, ManagedFabricPlanError> {
        Ok(u64::from_be_bytes(self.array(tag)?))
    }
}

fn parse_terminal_fields(frame: &[u8]) -> Result<TerminalParsedFields<'_>, ManagedFabricPlanError> {
    if frame.len() > MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES {
        return Err(wire(ManagedFabricWireErrorCode::FrameTooLarge));
    }
    if frame.len() < 8 {
        return Err(wire(ManagedFabricWireErrorCode::Truncated));
    }
    if &frame[..4] != TERMINAL_RECEIPT_MAGIC {
        return Err(wire(ManagedFabricWireErrorCode::InvalidMagic));
    }
    if read_u16(&frame[4..6]) != MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_VERSION {
        return Err(wire(ManagedFabricWireErrorCode::UnsupportedVersion));
    }
    let declared = read_u16(&frame[6..8]);
    if declared < TERMINAL_RECEIPT_FIELD_COUNT {
        return Err(wire_at(
            ManagedFabricWireErrorCode::MissingField,
            declared + 1,
        ));
    }
    if declared > TERMINAL_RECEIPT_FIELD_COUNT {
        return Err(wire_at(
            ManagedFabricWireErrorCode::UnknownField,
            TERMINAL_RECEIPT_FIELD_COUNT + 1,
        ));
    }
    let mut cursor = 8;
    let mut values = Vec::with_capacity(usize::from(declared));
    for expected_tag in 1..=declared {
        if cursor + TLV_HEADER_BYTES > frame.len() {
            return Err(wire(ManagedFabricWireErrorCode::Truncated));
        }
        let tag = read_u16(&frame[cursor..cursor + 2]);
        let length = read_u32(&frame[cursor + 2..cursor + 6]) as usize;
        cursor += TLV_HEADER_BYTES;
        if tag == 0 || tag > TERMINAL_RECEIPT_FIELD_COUNT {
            return Err(wire_at(ManagedFabricWireErrorCode::UnknownField, tag));
        }
        if tag < expected_tag {
            return Err(wire_at(ManagedFabricWireErrorCode::DuplicateField, tag));
        }
        if tag > expected_tag {
            return Err(wire_at(ManagedFabricWireErrorCode::OutOfOrderField, tag));
        }
        if !valid_terminal_field_length(tag, length) {
            return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldLength, tag));
        }
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| wire(ManagedFabricWireErrorCode::InvalidFieldLength))?;
        if end > frame.len() {
            return Err(wire_at(ManagedFabricWireErrorCode::Truncated, tag));
        }
        values.push(&frame[cursor..end]);
        cursor = end;
    }
    if cursor != frame.len() {
        return Err(wire(ManagedFabricWireErrorCode::TrailingBytes));
    }
    Ok(TerminalParsedFields { values })
}

fn valid_terminal_field_length(tag: u16, length: usize) -> bool {
    match tag {
        1 | 3 | 4 | 7 | 24 | 25 | 27 => length == 16,
        2 | 6 | 8 | 10 | 11 | 15 | 18 | 19 | 26 => length == 32,
        5 | 17 | 20..=23 => length == 8,
        9 => (1..=64).contains(&length),
        12..=14 | 28 | 29 => length == 2,
        16 => length == 1,
        30 => (1..=MAX_MANAGED_FABRIC_APPLY_TERMINAL_SIGNATURE_BYTES).contains(&length),
        _ => false,
    }
}

fn decode_terminal_receipt(
    frame: &[u8],
) -> Result<ManagedFabricApplyTerminalReceiptV1, ManagedFabricPlanError> {
    let fields = parse_terminal_fields(frame)?;
    let store = RuntimeStoreInstanceId::try_from_bytes(fields.array(2)?)
        .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 2))?;
    let provenance = PlanProvenance::new(
        SourceScopeRef::from_bytes(fields.array(3)?),
        SourcePlanRef::from_bytes(fields.array(4)?),
        SourcePlanRevision::new(fields.u64(5)?),
        SourcePlanDigest::new(Digest32::from_bytes(fields.array(6)?)),
    );
    if digest_is_zero(*provenance.source_plan_digest().value()) {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 6));
    }
    let request_digest = Digest32::from_bytes(fields.array(8)?);
    let target_slice_digest = TargetSliceDigest::new(Digest32::from_bytes(fields.array(10)?));
    let assignment_digest = TargetAssignmentDigest::new(Digest32::from_bytes(fields.array(11)?));
    if digest_is_zero(request_digest) {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 8));
    }
    if digest_is_zero(*target_slice_digest.value()) {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 10));
    }
    if digest_is_zero(*assignment_digest.value()) {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 11));
    }
    let outcome = decode_terminal_outcome(fields.u16(12)?)?;
    let lifecycle_effect = decode_terminal_lifecycle(fields.u16(13)?)?;
    let (head, desired_head_digest) = decode_terminal_head(fields.u16(14)?, fields.array(15)?)?;
    let generation_value = fields.u64(17)?;
    let generation = match (fields.get(16)[0], generation_value) {
        (0, 0) => None,
        (1, value) => Some(
            ManagedServiceGeneration::try_new(value)
                .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 17))?,
        ),
        _ => return Err(wire_at(ManagedFabricWireErrorCode::InvalidPresence, 16)),
    };
    let resource_census_digest = Digest32::from_bytes(fields.array(18)?);
    let raw_outcome_digest = Digest32::from_bytes(fields.array(19)?);
    if digest_is_zero(resource_census_digest) {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 18));
    }
    if digest_is_zero(raw_outcome_digest) {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 19));
    }
    let completion_runtime_host_epoch = fields.u64(20)?;
    let completion_snapshot_sequence = fields.u64(21)?;
    if completion_runtime_host_epoch == 0 {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 20));
    }
    if completion_snapshot_sequence == 0 {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 21));
    }
    let selection_clock_generation = ClockGeneration::try_new(fields.u64(22)?)
        .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 22))?;
    let selection_observed_at_nanos = fields.u64(23)?;
    if selection_observed_at_nanos == 0 {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 23));
    }
    let target = RuntimeHostId::from_bytes(fields.array(1)?);
    let operation_id = ApplyOperationId::from_bytes(fields.array(7)?);
    let terminal_result_ref = derive_terminal_result_ref_parts(
        target,
        store,
        provenance.source_scope(),
        operation_id,
        request_digest,
    )
    .map_err(|_| wire_at(ManagedFabricWireErrorCode::DigestMismatch, 24))?;
    if terminal_result_ref.as_bytes() != fields.get(24) {
        return Err(wire_at(ManagedFabricWireErrorCode::DigestMismatch, 24));
    }
    let facts = ManagedFabricApplyTerminalFactsV1 {
        outcome,
        lifecycle_effect,
        head,
        desired_head_digest,
        generation,
        resource_census_digest,
        raw_outcome_digest,
        completion_runtime_host_epoch,
        completion_snapshot_sequence,
        selection_clock_generation,
        selection_observed_at_nanos,
        terminal_result_ref,
    };
    validate_terminal_facts_general(facts)
        .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 12))?;
    let channel_binding_digest = Digest32::from_bytes(fields.array(26)?);
    if digest_is_zero(channel_binding_digest) {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 26));
    }
    let algorithm = ApplyAuthAlgorithm::try_new(fields.u16(28)?)
        .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 28))?;
    let algorithm_version = fields.u16(29)?;
    if algorithm_version == 0 {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 29));
    }
    let auth_claim = RuntimeResponseAuthClaimV1::try_new(
        PrincipalRef::from_bytes(fields.array(25)?),
        channel_binding_digest,
        ApplyAuthKeyRef::from_bytes(fields.array(27)?),
        algorithm,
        algorithm_version,
    )
    .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 29))?;
    let authentication = RuntimeResponseAuthenticationV1::try_new(auth_claim, fields.get(30))
        .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidSignatureField, 30))?;
    let draft = ManagedFabricApplyTerminalReceiptDraftV1 {
        target,
        store,
        provenance,
        operation_id,
        request_digest,
        request_nonce: fields.get(9).into(),
        target_slice_digest,
        assignment_digest,
        facts,
        auth_claim,
    };
    let decoded = ManagedFabricApplyTerminalReceiptV1::try_new(draft, authentication)
        .map_err(|_| wire(ManagedFabricWireErrorCode::InvalidFieldValue))?;
    if decoded.canonical_wire() != frame {
        return Err(wire(ManagedFabricWireErrorCode::NonCanonicalFrame));
    }
    Ok(decoded)
}

fn decode_terminal_outcome(
    value: u16,
) -> Result<ManagedFabricApplyTerminalOutcomeV1, ManagedFabricPlanError> {
    match value {
        1 => Ok(ManagedFabricApplyTerminalOutcomeV1::ActiveReady),
        2 => Ok(ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero),
        3 => Ok(ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected),
        4 => Ok(ManagedFabricApplyTerminalOutcomeV1::Uncertain),
        5 => Ok(ManagedFabricApplyTerminalOutcomeV1::Quarantined),
        _ => Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 12)),
    }
}

fn decode_terminal_lifecycle(
    value: u16,
) -> Result<ManagedFabricApplyTerminalLifecycleEffectV1, ManagedFabricPlanError> {
    match value {
        1 => Ok(ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted),
        2 => Ok(ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted),
        _ => Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 13)),
    }
}

fn decode_terminal_head(
    disposition: u16,
    digest_bytes: [u8; 32],
) -> Result<(ManagedFabricApplyTerminalHeadV1, Option<TargetSliceDigest>), ManagedFabricPlanError> {
    let digest = Digest32::from_bytes(digest_bytes);
    match disposition {
        1 if digest_is_zero(digest) => Ok((ManagedFabricApplyTerminalHeadV1::PreservedNone, None)),
        2 if !digest_is_zero(digest) => {
            let digest = TargetSliceDigest::new(digest);
            Ok((
                ManagedFabricApplyTerminalHeadV1::PreservedExisting(digest),
                Some(digest),
            ))
        }
        3 if !digest_is_zero(digest) => Ok((
            ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
            Some(TargetSliceDigest::new(digest)),
        )),
        _ => Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 14)),
    }
}

fn validate_projection_fields(
    fields: ManagedFabricProjectionFieldsV1,
) -> Result<(), ManagedFabricPlanError> {
    if digest_is_zero(fields.manifest_digest)
        || fields.build_instance_id.iter().all(|byte| *byte == 0)
        || digest_is_zero(fields.build_descriptor_digest)
        || digest_is_zero(fields.runtime_artifact_sha256)
        || fields.compatibility_digest != managed_fabric_compatibility_digest_v1()?
    {
        return Err(ManagedFabricPlanError::InvalidProjection);
    }
    Ok(())
}

fn build_projection_wire(fields: ManagedFabricProjectionFieldsV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(PROJECTION_BYTES);
    encoded.extend_from_slice(PROJECTION_MAGIC);
    encoded.extend_from_slice(&MANAGED_FABRIC_PROJECTION_VERSION.to_be_bytes());
    encoded.extend_from_slice(fields.manifest_digest.as_bytes());
    encoded.extend_from_slice(fields.target.as_bytes());
    encoded.extend_from_slice(&fields.build_instance_id);
    encoded.extend_from_slice(fields.build_descriptor_digest.as_bytes());
    encoded.extend_from_slice(fields.runtime_artifact_sha256.as_bytes());
    encoded.extend_from_slice(fields.compatibility_digest.as_bytes());
    encoded.extend_from_slice(&MANAGED_FABRIC_APPLY_REQUEST_VERSION.to_be_bytes());
    encoded.extend_from_slice(&MANAGED_FABRIC_PROFILE_VERSION.to_be_bytes());
    encoded
}

fn validate_service_shape(
    mode: ManagedFabricTargetModeV1,
    service: Option<ManagedServiceSpecV1>,
    endpoint: Option<&ManagedFabricListenEndpointV1>,
) -> Result<(), ManagedFabricPlanError> {
    match (mode, service, endpoint) {
        (ManagedFabricTargetModeV1::OneManagedFabricService, Some(service), Some(_)) => {
            validate_service_spec(service)
        }
        (ManagedFabricTargetModeV1::EmptyDeactivate, None, None) => Ok(()),
        _ => Err(ManagedFabricPlanError::InvalidShape),
    }
}

fn validate_service_spec(service: ManagedServiceSpecV1) -> Result<(), ManagedFabricPlanError> {
    if service
        .service_id()
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(ManagedFabricPlanError::InvalidServiceId);
    }
    let budgets = service.lifecycle_budgets();
    for stage in [
        ManagedServiceLifecycleStage::Prepare,
        ManagedServiceLifecycleStage::Start,
        ManagedServiceLifecycleStage::Readiness,
        ManagedServiceLifecycleStage::Drain,
        ManagedServiceLifecycleStage::Stop,
    ] {
        let value = budgets.for_stage(stage).value();
        if value == 0 || value > MAX_MANAGED_FABRIC_LIFECYCLE_NANOS {
            return Err(ManagedFabricPlanError::InvalidLifecycleBudget(stage));
        }
    }
    Ok(())
}

fn build_target_execution_wire(
    projection: &ManagedFabricManifestProjectionV1,
    mode: ManagedFabricTargetModeV1,
    service: Option<ManagedServiceSpecV1>,
    endpoint: Option<&ManagedFabricListenEndpointV1>,
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES);
    encoded.extend_from_slice(TARGET_EXECUTION_MAGIC);
    encoded.extend_from_slice(&MANAGED_FABRIC_TARGET_EXECUTION_VERSION.to_be_bytes());
    encoded.extend_from_slice(projection.canonical_wire());
    encoded.extend_from_slice(&MANAGED_FABRIC_PROFILE_VERSION.to_be_bytes());
    encoded.push(mode as u8);
    encoded.push(u8::from(service.is_some()));
    if let (Some(service), Some(endpoint)) = (service, endpoint) {
        encoded.extend_from_slice(&MANAGED_SERVICE_CONTRACT_VERSION.to_be_bytes());
        encoded.extend_from_slice(service.service_id().as_bytes());
        let budgets = service.lifecycle_budgets();
        for stage in [
            ManagedServiceLifecycleStage::Prepare,
            ManagedServiceLifecycleStage::Start,
            ManagedServiceLifecycleStage::Readiness,
            ManagedServiceLifecycleStage::Drain,
            ManagedServiceLifecycleStage::Stop,
        ] {
            encoded.extend_from_slice(&budgets.for_stage(stage).value().to_be_bytes());
        }
        encoded.extend_from_slice(&(endpoint.as_str().len() as u16).to_be_bytes());
        encoded.extend_from_slice(endpoint.as_str().as_bytes());
    }
    encoded
}

fn decode_active_execution(
    projection: ManagedFabricManifestProjectionV1,
    payload: &[u8],
) -> Result<ManagedFabricTargetExecutionV1, ManagedFabricPlanError> {
    if payload.len() < MANAGED_SERVICE_FIXED_BYTES {
        return Err(wire(ManagedFabricWireErrorCode::Truncated));
    }
    if read_u16(&payload[..2]) != MANAGED_SERVICE_CONTRACT_VERSION {
        return Err(wire_at(ManagedFabricWireErrorCode::UnsupportedVersion, 5));
    }
    let service_id = ManagedServiceId::from_bytes(read_array(&payload[2..18]));
    if service_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 6));
    }
    let mut budget_values = [0_u64; 5];
    for (index, value) in budget_values.iter_mut().enumerate() {
        let start = 18 + (index * 8);
        *value = read_u64(&payload[start..start + 8]);
        if *value == 0 || *value > MAX_MANAGED_FABRIC_LIFECYCLE_NANOS {
            return Err(wire_at(
                ManagedFabricWireErrorCode::InvalidFieldValue,
                7 + index as u16,
            ));
        }
    }
    let endpoint_length = read_u16(&payload[58..60]) as usize;
    if endpoint_length == 0 || endpoint_length > MAX_MANAGED_FABRIC_LISTEN_ENDPOINT_BYTES {
        return Err(wire_at(ManagedFabricWireErrorCode::InvalidFieldLength, 12));
    }
    let expected_length = MANAGED_SERVICE_FIXED_BYTES
        .checked_add(endpoint_length)
        .ok_or_else(|| wire_at(ManagedFabricWireErrorCode::InvalidFieldLength, 12))?;
    if payload.len() < expected_length {
        return Err(wire(ManagedFabricWireErrorCode::Truncated));
    }
    if payload.len() > expected_length {
        return Err(wire(ManagedFabricWireErrorCode::TrailingBytes));
    }
    let endpoint_text = core::str::from_utf8(&payload[60..])
        .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 12))?;
    let endpoint = ManagedFabricListenEndpointV1::try_new(endpoint_text)
        .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 12))?;
    let budgets = ManagedServiceLifecycleBudgetsV1::try_new(
        BoundedDuration::from_nanos(budget_values[0]),
        BoundedDuration::from_nanos(budget_values[1]),
        BoundedDuration::from_nanos(budget_values[2]),
        BoundedDuration::from_nanos(budget_values[3]),
        BoundedDuration::from_nanos(budget_values[4]),
    )
    .map_err(|_| wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 7))?;
    let service = ManagedServiceSpecV1::new(service_id, budgets);
    ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(projection, service, endpoint)
}

fn build_apply_request_wire(
    envelope: &RuntimeApplyEnvelopeV2,
    slice: &ManagedFabricPlanSliceV1,
) -> Vec<u8> {
    let bindings = slice.assignments.bindings.canonical_wire();
    let execution = slice.assignments.execution.canonical_wire();
    let mut encoded = Vec::with_capacity(
        APPLY_REQUEST_HEADER_BYTES
            + envelope.canonical_wire().len()
            + bindings.len()
            + execution.len(),
    );
    encoded.extend_from_slice(APPLY_REQUEST_MAGIC);
    encoded.extend_from_slice(&MANAGED_FABRIC_APPLY_REQUEST_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(envelope.canonical_wire().len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(bindings.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(execution.len() as u32).to_be_bytes());
    encoded.extend_from_slice(envelope.canonical_wire());
    encoded.extend_from_slice(bindings);
    encoded.extend_from_slice(execution);
    encoded
}

fn projection_contract_wire_error(error: ManagedFabricPlanError) -> ManagedFabricPlanError {
    match error {
        ManagedFabricPlanError::InvalidProjection => {
            wire(ManagedFabricWireErrorCode::CompatibilityMismatch)
        }
        ManagedFabricPlanError::Digest(_) => wire(ManagedFabricWireErrorCode::DigestMismatch),
        other => other,
    }
}

fn target_execution_contract_wire_error(error: ManagedFabricPlanError) -> ManagedFabricPlanError {
    match error {
        ManagedFabricPlanError::InvalidServiceId => {
            wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 6)
        }
        ManagedFabricPlanError::InvalidLifecycleBudget(stage) => wire_at(
            ManagedFabricWireErrorCode::InvalidFieldValue,
            lifecycle_detail(stage),
        ),
        ManagedFabricPlanError::InvalidListenEndpoint => {
            wire_at(ManagedFabricWireErrorCode::InvalidFieldValue, 12)
        }
        ManagedFabricPlanError::InvalidShape => {
            wire_at(ManagedFabricWireErrorCode::UnsupportedShape, 3)
        }
        ManagedFabricPlanError::Digest(_) => wire(ManagedFabricWireErrorCode::DigestMismatch),
        other => other,
    }
}

const fn lifecycle_detail(stage: ManagedServiceLifecycleStage) -> u16 {
    match stage {
        ManagedServiceLifecycleStage::Prepare => 7,
        ManagedServiceLifecycleStage::Start => 8,
        ManagedServiceLifecycleStage::Readiness => 9,
        ManagedServiceLifecycleStage::Drain => 10,
        ManagedServiceLifecycleStage::Stop => 11,
    }
}

fn map_reference_contract_error(error: ReferenceContractError) -> ManagedFabricPlanError {
    match error {
        ReferenceContractError::Digest(value) => ManagedFabricPlanError::Digest(value),
        ReferenceContractError::InvalidRuntimeStoreInstanceId => {
            ManagedFabricPlanError::InvalidRuntimeStoreInstanceId
        }
        ReferenceContractError::RequestFrameTooLarge => {
            ManagedFabricPlanError::RequestFrameTooLarge
        }
        ReferenceContractError::CommitmentMismatch => ManagedFabricPlanError::CommitmentMismatch,
        _ => ManagedFabricPlanError::EnvelopeInvalid,
    }
}

fn map_reference_wire_error(error: ReferenceWireError) -> ManagedFabricPlanError {
    let code = match error.code() {
        ReferenceWireErrorCode::FrameTooLarge => ManagedFabricWireErrorCode::FrameTooLarge,
        ReferenceWireErrorCode::Truncated => ManagedFabricWireErrorCode::Truncated,
        ReferenceWireErrorCode::InvalidMagic => ManagedFabricWireErrorCode::InvalidMagic,
        ReferenceWireErrorCode::UnsupportedVersion => {
            ManagedFabricWireErrorCode::UnsupportedVersion
        }
        ReferenceWireErrorCode::UnknownField => ManagedFabricWireErrorCode::UnknownField,
        ReferenceWireErrorCode::DuplicateField => ManagedFabricWireErrorCode::DuplicateField,
        ReferenceWireErrorCode::OutOfOrderField => ManagedFabricWireErrorCode::OutOfOrderField,
        ReferenceWireErrorCode::MissingField => ManagedFabricWireErrorCode::MissingField,
        ReferenceWireErrorCode::InvalidFieldLength => {
            ManagedFabricWireErrorCode::InvalidFieldLength
        }
        ReferenceWireErrorCode::InvalidFieldValue => ManagedFabricWireErrorCode::InvalidFieldValue,
        ReferenceWireErrorCode::NonCanonicalFrame => ManagedFabricWireErrorCode::NonCanonicalFrame,
        ReferenceWireErrorCode::DigestMismatch => ManagedFabricWireErrorCode::DigestMismatch,
        ReferenceWireErrorCode::CrossReferenceMismatch => {
            ManagedFabricWireErrorCode::CrossReferenceMismatch
        }
        ReferenceWireErrorCode::UnsupportedShape => ManagedFabricWireErrorCode::UnsupportedShape,
        ReferenceWireErrorCode::BindingNotAllowed => ManagedFabricWireErrorCode::BindingNotAllowed,
        ReferenceWireErrorCode::RuntimeStoreMismatch => {
            ManagedFabricWireErrorCode::RuntimeStoreMismatch
        }
        ReferenceWireErrorCode::TargetMismatch => ManagedFabricWireErrorCode::TargetMismatch,
        ReferenceWireErrorCode::FixtureMismatch => ManagedFabricWireErrorCode::FixtureMismatch,
        ReferenceWireErrorCode::ResponseBoundExceeded => {
            ManagedFabricWireErrorCode::ResponseBoundExceeded
        }
        ReferenceWireErrorCode::UnknownReason => ManagedFabricWireErrorCode::UnknownReason,
        ReferenceWireErrorCode::TrailingBytes => ManagedFabricWireErrorCode::TrailingBytes,
        ReferenceWireErrorCode::InvalidSignatureField => {
            ManagedFabricWireErrorCode::InvalidSignatureField
        }
        ReferenceWireErrorCode::InvalidPresence => ManagedFabricWireErrorCode::InvalidPresence,
        ReferenceWireErrorCode::ArtifactMismatch => ManagedFabricWireErrorCode::ArtifactMismatch,
        ReferenceWireErrorCode::CompatibilityMismatch => {
            ManagedFabricWireErrorCode::CompatibilityMismatch
        }
    };
    ManagedFabricPlanError::Wire(ManagedFabricWireError {
        code,
        detail: error.detail(),
    })
}

const fn wire(code: ManagedFabricWireErrorCode) -> ManagedFabricPlanError {
    ManagedFabricPlanError::Wire(ManagedFabricWireError { code, detail: None })
}

const fn wire_at(code: ManagedFabricWireErrorCode, detail: u16) -> ManagedFabricPlanError {
    ManagedFabricPlanError::Wire(ManagedFabricWireError {
        code,
        detail: Some(detail),
    })
}

fn digest_wire(domain: &[u8], wire_bytes: &[u8]) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(domain)?;
    builder.field_bytes(wire_bytes)?;
    Ok(builder.finish())
}

fn digest_is_zero(value: Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(bytes);
    value
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(read_array(bytes))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(read_array(bytes))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(read_array(bytes))
}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::BoundedDuration;

    use crate::apply::ExpectedActive;
    use crate::managed_service::{
        ManagedServiceId, ManagedServiceLifecycleBudgetsV1, ManagedServiceLifecycleStage,
        ManagedServiceSpecV1,
    };
    use crate::reference_control::{
        ReferenceApplyRequestV1, ReferenceApplyTerminalReceiptV1, ReferenceTargetExecutionPlanV4,
    };

    use super::*;

    const FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_fabric_successor_v1.json");
    const LEGACY_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s7_reference_successor_v1.json");

    fn json_string_end(bytes: &[u8], start: usize) -> usize {
        assert_eq!(bytes[start], b'"');
        let mut cursor = start + 1;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'"' => return cursor + 1,
                b'\\' => cursor += 2,
                _ => cursor += 1,
            }
        }
        panic!("unterminated fixture string")
    }

    fn json_value_end(bytes: &[u8], start: usize) -> usize {
        if bytes[start] == b'"' {
            return json_string_end(bytes, start);
        }
        if matches!(bytes[start], b'{' | b'[') {
            let mut closers = vec![if bytes[start] == b'{' { b'}' } else { b']' }];
            let mut cursor = start + 1;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'"' => cursor = json_string_end(bytes, cursor),
                    b'{' => {
                        closers.push(b'}');
                        cursor += 1;
                    }
                    b'[' => {
                        closers.push(b']');
                        cursor += 1;
                    }
                    b'}' | b']' => {
                        assert_eq!(closers.pop(), Some(bytes[cursor]));
                        cursor += 1;
                        if closers.is_empty() {
                            return cursor;
                        }
                    }
                    _ => cursor += 1,
                }
            }
            panic!("unterminated fixture value")
        }
        bytes[start..]
            .iter()
            .position(|byte| matches!(byte, b',' | b'}' | b']'))
            .map_or(bytes.len(), |offset| start + offset)
    }

    fn fixture_value<'a>(object: &'a str, key: &str) -> &'a str {
        let needle = format!("\"{key}\"");
        let key_start = object
            .find(&needle)
            .unwrap_or_else(|| panic!("missing fixture key {key}"));
        let bytes = object.as_bytes();
        let mut cursor = key_start + needle.len();
        while bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        assert_eq!(bytes[cursor], b':');
        cursor += 1;
        while bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let end = json_value_end(bytes, cursor);
        object[cursor..end].trim_end()
    }

    fn fixture_object<'a>(object: &'a str, key: &str) -> &'a str {
        let value = fixture_value(object, key);
        assert_eq!(value.as_bytes().first(), Some(&b'{'));
        value
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("fixture contains non-hex byte"),
        }
    }

    fn fixture_hex(object: &str, key: &str) -> Vec<u8> {
        let value = fixture_value(object, key);
        let hex = &value.as_bytes()[1..value.len() - 1];
        hex.chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn fixture_digest(object: &str, key: &str) -> Digest32 {
        Digest32::from_bytes(
            fixture_hex(object, key)
                .try_into()
                .unwrap_or_else(|bytes: Vec<u8>| panic!("digest has {} bytes", bytes.len())),
        )
    }

    fn expected() -> &'static str {
        fixture_object(FIXTURE_JSON, "expected")
    }

    fn vector(name: &str) -> &'static str {
        fixture_object(expected(), name)
    }

    fn terminal_vector(name: &str) -> &'static str {
        fixture_object(fixture_object(expected(), "terminal"), name)
    }

    fn fixture_usize(object: &str, key: &str) -> usize {
        fixture_value(object, key)
            .parse()
            .unwrap_or_else(|error| panic!("invalid fixture integer {key}: {error}"))
    }

    fn decoded_projection() -> ManagedFabricManifestProjectionV1 {
        ManagedFabricManifestProjectionV1::decode(&fixture_hex(expected(), "projection_hex"))
            .expect("fixture projection must decode")
    }

    fn duration(value: u64) -> BoundedDuration {
        BoundedDuration::from_nanos(value)
    }

    fn fixture_service() -> ManagedServiceSpecV1 {
        let budgets = ManagedServiceLifecycleBudgetsV1::try_new(
            duration(1_000_000_000),
            duration(2_000_000_000),
            duration(3_000_000_000),
            duration(4_000_000_000),
            duration(5_000_000_000),
        )
        .expect("fixture budgets must be valid");
        ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([0x51; 16]), budgets)
    }

    fn wire_error(error: ManagedFabricPlanError) -> (ManagedFabricWireErrorCode, Option<u16>) {
        let ManagedFabricPlanError::Wire(error) = error else {
            panic!("expected wire error, got {error:?}")
        };
        (error.code(), error.detail())
    }

    fn fixture_channel(target: RuntimeHostId) -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            target,
            PrincipalRef::from_bytes([0xe1; 16]),
            Digest32::from_bytes([0xe3; 32]),
            Digest32::from_bytes([0xe4; 32]),
        )
        .expect("fixture channel must be valid")
    }

    fn fixture_terminal_auth_claim(
        channel: ReferenceChannelBindingV1,
    ) -> ManagedFabricApplyTerminalReceiptAuthClaimV1 {
        ManagedFabricApplyTerminalReceiptAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0xe2; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("fixture algorithm must be valid"),
            1,
        )
        .expect("fixture response authentication must be valid")
    }

    fn terminal_field_offset(wire: &[u8], wanted_tag: u16) -> usize {
        let mut cursor = 8;
        while cursor < wire.len() {
            let tag = read_u16(&wire[cursor..cursor + 2]);
            let length = read_u32(&wire[cursor + 2..cursor + 6]) as usize;
            let value = cursor + TLV_HEADER_BYTES;
            if tag == wanted_tag {
                return value;
            }
            cursor = value + length;
        }
        panic!("terminal fixture is missing tag {wanted_tag}")
    }

    fn assert_wire_error(wire: &[u8], code: ManagedFabricWireErrorCode, detail: Option<u16>) {
        let error =
            ManagedFabricApplyRequestV1::decode(wire).expect_err("invalid vector must fail closed");
        assert_eq!(wire_error(error), (code, detail));
    }

    fn outer_offsets(wire: &[u8]) -> (usize, usize, usize) {
        let envelope_length = read_u32(&wire[6..10]) as usize;
        let binding_length = read_u32(&wire[10..14]) as usize;
        let envelope_start = APPLY_REQUEST_HEADER_BYTES;
        let binding_start = envelope_start + envelope_length;
        (
            envelope_start,
            binding_start,
            binding_start + binding_length,
        )
    }

    #[test]
    fn compatibility_projection_and_public_pxte_producer_match_python_golden() {
        assert_eq!(
            managed_fabric_compatibility_digest_v1().expect("digest must build"),
            fixture_digest(expected(), "compatibility_digest_hex")
        );
        let projection = decoded_projection();
        assert_eq!(projection.target().as_bytes(), &[0x05; 16]);
        assert_eq!(
            projection.canonical_wire(),
            fixture_hex(expected(), "projection_hex")
        );

        let endpoint = ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
            .expect("fixture endpoint must be valid");
        assert_eq!(endpoint.port(), 7447);
        let active = ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
            projection.clone(),
            fixture_service(),
            endpoint,
        )
        .expect("active fixture must build");
        assert_eq!(
            active.canonical_wire(),
            fixture_hex(vector("one_managed_fabric_service"), "pxte_v5_hex")
        );
        assert_eq!(
            active.execution_digest(),
            fixture_digest(vector("one_managed_fabric_service"), "pxte_v5_digest_hex")
        );
        assert_eq!(active.service(), Some(fixture_service()));
        assert_eq!(
            active
                .listen_endpoint()
                .map(ManagedFabricListenEndpointV1::as_str),
            Some("tcp/127.0.0.1:7447")
        );

        let empty = ManagedFabricTargetExecutionV1::try_empty_deactivate(projection)
            .expect("empty fixture must build");
        assert_eq!(
            empty.canonical_wire(),
            fixture_hex(vector("empty_deactivate"), "pxte_v5_hex")
        );
        assert_eq!(empty.service(), None);
        assert_eq!(empty.listen_endpoint(), None);
    }

    #[test]
    fn transition_projection_is_derived_only_from_verified_legacy_ingress() {
        let legacy_expected = fixture_object(LEGACY_FIXTURE_JSON, "expected");
        let ingress = crate::installation::verify_immutable_manifest_ingress(
            &fixture_hex(legacy_expected, "manifest_hex"),
            fixture_digest(legacy_expected, "manifest_digest_hex"),
        )
        .expect("legacy manifest fixture must verify before projection");
        let projection =
            ManagedFabricManifestProjectionV1::try_from_verified_legacy_manifest(&ingress)
                .expect("verified legacy identity facts must project");
        assert_eq!(
            projection.canonical_wire(),
            fixture_hex(expected(), "projection_hex")
        );
        assert_eq!(projection.target(), ingress.target());
        assert_eq!(
            projection.fields().manifest_digest,
            ingress.manifest_digest()
        );
        assert_eq!(
            projection.fields().compatibility_digest,
            managed_fabric_compatibility_digest_v1().expect("compatibility digest must build")
        );
    }

    #[test]
    fn public_pxft_producer_and_strict_decoder_match_python_goldens() {
        let active_request = ManagedFabricApplyRequestV1::decode(&fixture_hex(
            vector("one_managed_fabric_service"),
            "outer_v6_hex",
        ))
        .expect("active request fixture must decode");
        let empty_request = ManagedFabricApplyRequestV1::decode(&fixture_hex(
            vector("empty_deactivate"),
            "outer_v6_hex",
        ))
        .expect("empty request fixture must decode");
        let channel = fixture_channel(active_request.target());

        let cases = [
            (
                &active_request,
                "active_ready",
                ManagedFabricApplyTerminalOutcomeV1::ActiveReady,
                Some(ManagedServiceGeneration::try_new(7).expect("nonzero generation")),
                Digest32::from_bytes([0xc1; 32]),
                Digest32::from_bytes([0xc2; 32]),
                6,
                200,
            ),
            (
                &empty_request,
                "empty_exact_zero",
                ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero,
                None,
                Digest32::from_bytes([0xc3; 32]),
                Digest32::from_bytes([0xc4; 32]),
                7,
                201,
            ),
        ];
        for (request, name, outcome, generation, census, raw, snapshot, observed) in cases {
            let golden = terminal_vector(name);
            let state = ManagedFabricApplyTerminalStateV1::try_new(
                outcome,
                ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                generation,
            )
            .expect("fixture terminal state must be valid");
            let evidence = ManagedFabricApplyTerminalEvidenceV1::try_new(
                census,
                raw,
                5,
                snapshot,
                ClockGeneration::try_new(3).expect("nonzero clock generation"),
                observed,
            )
            .expect("fixture terminal evidence must be valid");
            let facts = ManagedFabricApplyTerminalFactsV1::try_new(request, state, evidence)
                .expect("fixture terminal facts must be valid");
            let draft = ManagedFabricApplyTerminalReceiptDraftV1::try_new(
                request,
                facts,
                channel,
                fixture_terminal_auth_claim(channel),
            )
            .expect("fixture terminal draft must be valid");
            assert_eq!(
                draft
                    .signing_transcript()
                    .expect("terminal signing transcript must build")
                    .as_bytes()
                    .len(),
                fixture_usize(golden, "signing_transcript_length")
            );
            let receipt = draft
                .finalize(&fixture_hex(golden, "signature_hex"))
                .expect("fixture terminal receipt must finalize");
            let golden_wire = fixture_hex(golden, "wire_hex");
            assert_eq!(receipt.canonical_wire(), golden_wire);
            assert_eq!(
                receipt.receipt_digest(),
                fixture_digest(golden, "receipt_digest_hex")
            );
            let decoded = ManagedFabricApplyTerminalReceiptV1::decode(&golden_wire)
                .expect("PXFT v1 fixture must decode strictly");
            assert_eq!(decoded, receipt);
            assert_eq!(
                decoded
                    .validate_against_request(request, channel)
                    .expect("receipt must correlate to its exact request and channel"),
                facts
            );
        }
    }

    #[test]
    fn empty_exact_zero_admits_effect_free_fast_paths_and_rejects_false_shapes() {
        let fixture_request = ManagedFabricApplyRequestV1::decode(&fixture_hex(
            vector("empty_deactivate"),
            "outer_v6_hex",
        ))
        .expect("empty request fixture must decode");
        let exact_zero = fixture_request.target_slice_digest();
        for expected_active in [ExpectedActive::None, ExpectedActive::Exact(exact_zero)] {
            let control = RuntimeApplyControl::new(
                fixture_request
                    .control_commitment()
                    .control()
                    .writer_context()
                    .clone(),
                expected_active,
                fixture_request.operation_id(),
            );
            let draft = ManagedFabricApplyRequestDraftV1::try_new(
                fixture_request.target_execution().clone(),
                fixture_request.provenance(),
                control,
                fixture_request.temporal(),
                fixture_request.expected_runtime_store_instance_id(),
                fixture_request.authentication().claim().clone(),
            )
            .expect("effect-free empty request must build");
            let request = draft
                .finalize(fixture_request.authentication().signature())
                .expect("effect-free empty request must finalize");
            let state = ManagedFabricApplyTerminalStateV1::try_new(
                ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero,
                ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
                ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                None,
            )
            .expect("empty exact-zero may prove no callback or resource effect");
            let evidence = ManagedFabricApplyTerminalEvidenceV1::try_new(
                Digest32::from_bytes([0xd1; 32]),
                Digest32::from_bytes([0xd2; 32]),
                5,
                8,
                ClockGeneration::try_new(3).expect("nonzero clock generation"),
                202,
            )
            .expect("effect-free evidence must be valid");
            let facts = ManagedFabricApplyTerminalFactsV1::try_new(&request, state, evidence)
                .expect("fresh or already-zero empty fast path must be admitted");
            assert_eq!(
                facts.lifecycle_effect(),
                ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted
            );
        }

        let active_request = ManagedFabricApplyRequestV1::decode(&fixture_hex(
            vector("one_managed_fabric_service"),
            "outer_v6_hex",
        ))
        .expect("active request fixture must decode");
        let no_effect_evidence = ManagedFabricApplyTerminalEvidenceV1::try_new(
            Digest32::from_bytes([0xd3; 32]),
            Digest32::from_bytes([0xd4; 32]),
            5,
            9,
            ClockGeneration::try_new(3).expect("nonzero clock generation"),
            203,
        )
        .expect("no-effect evidence must be valid");
        let actual_existing = TargetSliceDigest::new(Digest32::from_bytes([0xd5; 32]));
        let actual_existing_state = ManagedFabricApplyTerminalStateV1::try_new(
            ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected,
            ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
            ManagedFabricApplyTerminalHeadV1::PreservedExisting(actual_existing),
            None,
        )
        .expect("CAS reject may observe an existing head when request expected none");
        let actual_existing_facts = ManagedFabricApplyTerminalFactsV1::try_new(
            &active_request,
            actual_existing_state,
            no_effect_evidence,
        )
        .expect("signed no-effect result must report the Runtime-observed existing head");
        assert_eq!(
            actual_existing_facts.desired_head_digest(),
            Some(actual_existing)
        );

        let actual_none_state = ManagedFabricApplyTerminalStateV1::try_new(
            ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected,
            ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
            ManagedFabricApplyTerminalHeadV1::PreservedNone,
            None,
        )
        .expect("CAS reject may observe no head when request expected an exact digest");
        let actual_none_facts = ManagedFabricApplyTerminalFactsV1::try_new(
            &fixture_request,
            actual_none_state,
            no_effect_evidence,
        )
        .expect("signed no-effect result must report the Runtime-observed absent head");
        assert_eq!(actual_none_facts.desired_head_digest(), None);

        let zero_actual = ManagedFabricApplyTerminalStateV1::try_new(
            ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected,
            ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
            ManagedFabricApplyTerminalHeadV1::PreservedExisting(TargetSliceDigest::new(
                Digest32::from_bytes([0; 32]),
            )),
            None,
        )
        .expect("state shape defers digest validation to request correlation");
        assert_eq!(
            ManagedFabricApplyTerminalFactsV1::try_new(
                &active_request,
                zero_actual,
                no_effect_evidence,
            ),
            Err(ManagedFabricPlanError::InvalidTerminalFacts)
        );

        let generation = Some(ManagedServiceGeneration::try_new(7).expect("nonzero generation"));
        for invalid in [
            ManagedFabricApplyTerminalStateV1::try_new(
                ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero,
                ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
                ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                generation,
            ),
            ManagedFabricApplyTerminalStateV1::try_new(
                ManagedFabricApplyTerminalOutcomeV1::ActiveReady,
                ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
                ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                generation,
            ),
            ManagedFabricApplyTerminalStateV1::try_new(
                ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected,
                ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                ManagedFabricApplyTerminalHeadV1::PreservedNone,
                None,
            ),
            ManagedFabricApplyTerminalStateV1::try_new(
                ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected,
                ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
                ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                None,
            ),
        ] {
            assert_eq!(invalid, Err(ManagedFabricPlanError::InvalidTerminalFacts));
        }
    }

    #[test]
    fn pxft_versions_integrity_and_request_channel_correlation_fail_closed() {
        let active_request = ManagedFabricApplyRequestV1::decode(&fixture_hex(
            vector("one_managed_fabric_service"),
            "outer_v6_hex",
        ))
        .expect("active request fixture must decode");
        let empty_request = ManagedFabricApplyRequestV1::decode(&fixture_hex(
            vector("empty_deactivate"),
            "outer_v6_hex",
        ))
        .expect("empty request fixture must decode");
        let mut active_wire = fixture_hex(terminal_vector("active_ready"), "wire_hex");
        let receipt = ManagedFabricApplyTerminalReceiptV1::decode(&active_wire)
            .expect("active PXFT fixture must decode");
        assert!(ReferenceApplyTerminalReceiptV1::decode(&active_wire).is_err());
        assert!(
            receipt
                .validate_against_request(&empty_request, fixture_channel(empty_request.target()))
                .is_err()
        );

        let wrong_channel = ReferenceChannelBindingV1::try_new(
            active_request.target(),
            PrincipalRef::from_bytes([0xe5; 16]),
            Digest32::from_bytes([0xe3; 32]),
            Digest32::from_bytes([0xe4; 32]),
        )
        .expect("wrong-peer channel is structurally valid");
        assert_eq!(
            wire_error(
                receipt
                    .validate_against_request(&active_request, wrong_channel)
                    .expect_err("different authenticated peer must fail correlation")
            ),
            (ManagedFabricWireErrorCode::TargetMismatch, Some(25))
        );

        let result_ref = terminal_field_offset(&active_wire, 24);
        active_wire[result_ref] ^= 1;
        assert_eq!(
            wire_error(
                ManagedFabricApplyTerminalReceiptV1::decode(&active_wire)
                    .expect_err("derived terminal result reference must be exact")
            ),
            (ManagedFabricWireErrorCode::DigestMismatch, Some(24))
        );

        let mut target_slice_wire = fixture_hex(terminal_vector("active_ready"), "wire_hex");
        let target_slice = terminal_field_offset(&target_slice_wire, 10);
        target_slice_wire[target_slice] ^= 1;
        let mismatched = ManagedFabricApplyTerminalReceiptV1::decode(&target_slice_wire)
            .expect("untrusted receipt remains structurally canonical");
        assert_eq!(
            wire_error(
                mismatched
                    .validate_against_request(
                        &active_request,
                        fixture_channel(active_request.target()),
                    )
                    .expect_err("different target slice must fail request correlation")
            ),
            (ManagedFabricWireErrorCode::DigestMismatch, Some(10))
        );

        let mut invalid_presence = fixture_hex(terminal_vector("active_ready"), "wire_hex");
        let presence = terminal_field_offset(&invalid_presence, 16);
        invalid_presence[presence] = 0;
        assert_eq!(
            wire_error(
                ManagedFabricApplyTerminalReceiptV1::decode(&invalid_presence)
                    .expect_err("generation presence and value must agree")
            ),
            (ManagedFabricWireErrorCode::InvalidPresence, Some(16))
        );

        let mut fake_old = fixture_hex(terminal_vector("active_ready"), "wire_hex");
        fake_old[..4].copy_from_slice(b"PXRT");
        assert_eq!(
            wire_error(
                ManagedFabricApplyTerminalReceiptV1::decode(&fake_old)
                    .expect_err("PXFT decoder must not fall back to PXRT")
            ),
            (ManagedFabricWireErrorCode::InvalidMagic, None)
        );

        let mut opaque_signature = fixture_hex(terminal_vector("active_ready"), "wire_hex");
        *opaque_signature
            .last_mut()
            .expect("fixture signature is nonempty") ^= 1;
        let mutated = ManagedFabricApplyTerminalReceiptV1::decode(&opaque_signature)
            .expect("wire decoder treats the bounded signature as opaque");
        assert_ne!(mutated.receipt_digest(), receipt.receipt_digest());
        assert_ne!(
            mutated.authentication_signature(),
            receipt.authentication_signature()
        );
    }

    #[test]
    fn strict_pxar_golden_retains_provenance_target_cas_deadline_store_and_auth() {
        let active_wire = fixture_hex(vector("one_managed_fabric_service"), "outer_v6_hex");
        let active =
            ManagedFabricApplyRequestV1::decode(&active_wire).expect("active PXAR v6 must decode");
        assert_eq!(active.canonical_wire(), active_wire);
        assert_eq!(active.target().as_bytes(), &[0x05; 16]);
        assert_eq!(active.provenance().source_scope().as_bytes(), &[0x01; 16]);
        assert_eq!(active.provenance().source_plan().as_bytes(), &[0x02; 16]);
        assert_eq!(active.provenance().source_revision().value(), 3);
        assert_eq!(
            active.provenance().source_plan_digest().value().as_bytes(),
            &[0x04; 32]
        );
        assert_eq!(
            active.assignment_digest().value(),
            &fixture_digest(
                vector("one_managed_fabric_service"),
                "composite_v6_digest_hex"
            )
        );
        assert_eq!(
            active.target_slice_digest(),
            TargetSliceDigest::new(fixture_digest(
                vector("one_managed_fabric_service"),
                "target_slice_digest_hex"
            ))
        );
        assert_eq!(
            active.control_commitment().control().expected_active(),
            ExpectedActive::None
        );
        assert_eq!(active.temporal().original_budget().value(), 100);
        assert_eq!(active.temporal().remaining_budget().value(), 60);
        assert_eq!(active.temporal().target_clock_generation().value(), 3);
        assert_eq!(active.expected_runtime_store_instance_id(), [0x44; 32]);
        assert!(!active.authentication().signature().is_empty());
        assert_eq!(
            active.envelope_request_digest(),
            fixture_digest(vector("one_managed_fabric_service"), "request_digest_hex")
        );
        active
            .validate_expected_store([0x44; 32])
            .expect("signed store must admit exact local journal");
        assert_eq!(
            wire_error(
                active
                    .validate_expected_store([0x45; 32])
                    .expect_err("wrong store must fail")
            ),
            (ManagedFabricWireErrorCode::RuntimeStoreMismatch, None)
        );
        active
            .validate_projection(&decoded_projection())
            .expect("exact installed projection must match");
        let restored = verify_managed_fabric_durable_slice_v1(
            active.canonical_slice_wire(),
            active.target(),
            active.provenance(),
            active.target_slice_digest(),
            &decoded_projection(),
        )
        .expect("journal slice must restore exactly");
        assert_eq!(
            restored.canonical_wire(),
            active.target_execution().canonical_wire()
        );

        let empty_wire = fixture_hex(vector("empty_deactivate"), "outer_v6_hex");
        let empty =
            ManagedFabricApplyRequestV1::decode(&empty_wire).expect("empty PXAR v6 must decode");
        assert_eq!(empty.provenance().source_revision().value(), 4);
        assert_eq!(
            empty.target_execution().mode(),
            ManagedFabricTargetModeV1::EmptyDeactivate
        );
        assert_eq!(
            empty.control_commitment().control().expected_active(),
            ExpectedActive::Exact(active.target_slice_digest())
        );
        assert_eq!(
            empty
                .signing_transcript()
                .expect("transcript must rebuild")
                .as_bytes()
                .len(),
            930
        );
    }

    #[test]
    fn endpoint_service_id_and_lifecycle_bounds_fail_closed() {
        for endpoint in [
            "tcp/127.0.0.1:0",
            "tcp/127.0.0.1:07447",
            "tcp/127.0.0.1:65536",
            "tcp/0.0.0.0:7447",
            "tcp/localhost:7447",
            "tcp/[::1]:7447",
            "tcp/127.0.0.1:7447/key/route",
        ] {
            assert_eq!(
                ManagedFabricListenEndpointV1::try_new(endpoint),
                Err(ManagedFabricPlanError::InvalidListenEndpoint)
            );
        }

        let zero_id = ManagedServiceSpecV1::new(
            ManagedServiceId::from_bytes([0; 16]),
            fixture_service().lifecycle_budgets(),
        );
        assert_eq!(
            ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
                decoded_projection(),
                zero_id,
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("endpoint must be valid"),
            ),
            Err(ManagedFabricPlanError::InvalidServiceId)
        );

        let excessive = ManagedServiceLifecycleBudgetsV1::try_new(
            duration(MAX_MANAGED_FABRIC_LIFECYCLE_NANOS + 1),
            duration(2),
            duration(3),
            duration(4),
            duration(5),
        )
        .expect("base managed-service contract leaves successor ceiling to PXTE");
        let excessive = ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([1; 16]), excessive);
        assert_eq!(
            ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
                decoded_projection(),
                excessive,
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("endpoint must be valid"),
            ),
            Err(ManagedFabricPlanError::InvalidLifecycleBudget(
                ManagedServiceLifecycleStage::Prepare
            ))
        );
    }

    #[test]
    fn invalid_decode_precedence_is_stable_across_outer_nested_and_cross_checks() {
        let base = fixture_hex(vector("one_managed_fabric_service"), "outer_v6_hex");
        let (envelope_start, binding_start, pxte_start) = outer_offsets(&base);
        let profile_offset = pxte_start + 6 + PROJECTION_BYTES;
        let service_offset = pxte_start + TARGET_EXECUTION_FIXED_BYTES;

        let oversized = vec![0; MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES + 1];
        assert_wire_error(&oversized, ManagedFabricWireErrorCode::FrameTooLarge, None);
        assert_wire_error(&base[..17], ManagedFabricWireErrorCode::Truncated, None);

        let mut invalid = base.clone();
        invalid[0] ^= 1;
        invalid[4..6].copy_from_slice(&99_u16.to_be_bytes());
        assert_wire_error(&invalid, ManagedFabricWireErrorCode::InvalidMagic, None);

        let mut invalid = base.clone();
        invalid[4..6].copy_from_slice(&99_u16.to_be_bytes());
        invalid[10..14].copy_from_slice(&9_u32.to_be_bytes());
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::UnsupportedVersion,
            None,
        );

        let mut invalid = base.clone();
        invalid[10..14].copy_from_slice(&9_u32.to_be_bytes());
        invalid[envelope_start] ^= 1;
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::BindingNotAllowed,
            Some(2),
        );

        let mut invalid = base.clone();
        invalid[14..18].copy_from_slice(
            &((MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES + 1) as u32).to_be_bytes(),
        );
        assert_wire_error(&invalid, ManagedFabricWireErrorCode::FrameTooLarge, Some(3));

        let mut invalid = base.clone();
        let envelope_length = read_u32(&invalid[6..10]);
        invalid[6..10].copy_from_slice(&(envelope_length + 1).to_be_bytes());
        assert_wire_error(&invalid, ManagedFabricWireErrorCode::Truncated, None);

        let mut invalid = base.clone();
        invalid.push(0);
        assert_wire_error(&invalid, ManagedFabricWireErrorCode::TrailingBytes, None);

        let mut invalid = base.clone();
        invalid[envelope_start] ^= 1;
        invalid[binding_start] ^= 1;
        assert_wire_error(&invalid, ManagedFabricWireErrorCode::InvalidMagic, None);

        let mut invalid = base.clone();
        invalid[binding_start] ^= 1;
        invalid[pxte_start] ^= 1;
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::BindingNotAllowed,
            Some(2),
        );

        let mut invalid = base.clone();
        invalid[pxte_start] ^= 1;
        invalid[profile_offset..profile_offset + 2].copy_from_slice(&99_u16.to_be_bytes());
        assert_wire_error(&invalid, ManagedFabricWireErrorCode::InvalidMagic, None);

        let mut invalid = base.clone();
        invalid[pxte_start + 4..pxte_start + 6].copy_from_slice(&99_u16.to_be_bytes());
        invalid[pxte_start + 6] ^= 1;
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::UnsupportedVersion,
            None,
        );

        let mut invalid = base.clone();
        invalid[profile_offset + 3] = 0;
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::InvalidPresence,
            Some(4),
        );

        let mut invalid = base.clone();
        invalid[service_offset + 2..service_offset + 18].fill(0);
        invalid[service_offset + 18..service_offset + 26].fill(0);
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::InvalidFieldValue,
            Some(6),
        );

        let mut invalid = base.clone();
        invalid[service_offset + 18..service_offset + 26].fill(0);
        *invalid.last_mut().expect("fixture is nonempty") = b'x';
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::InvalidFieldValue,
            Some(7),
        );

        let endpoint_start = service_offset + MANAGED_SERVICE_FIXED_BYTES;
        let mut invalid = base.clone();
        invalid[endpoint_start + LOOPBACK_TCP_PREFIX.len()] = b'0';
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::InvalidFieldValue,
            Some(12),
        );

        let mut invalid = base.clone();
        invalid[pxte_start + 6 + 38] ^= 1;
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::TargetMismatch,
            Some(2),
        );

        let mut invalid = base.clone();
        invalid[endpoint_start + LOOPBACK_TCP_PREFIX.len() + 3] = b'8';
        assert_wire_error(
            &invalid,
            ManagedFabricWireErrorCode::DigestMismatch,
            Some(7),
        );
    }

    #[test]
    fn legacy_pxte4_pxar5_goldens_remain_decodable_and_versions_never_fallback() {
        let legacy_expected = fixture_object(LEGACY_FIXTURE_JSON, "expected");
        for name in ["one_source_loop", "empty_deactivate"] {
            let legacy = fixture_object(legacy_expected, name);
            let pxte = fixture_hex(legacy, "pxte_v4_body_hex");
            let pxar = fixture_hex(legacy, "outer_v5_hex");
            let old_execution = ReferenceTargetExecutionPlanV4::decode(&pxte)
                .expect("frozen PXTE v4 golden must remain decodable");
            assert_eq!(old_execution.canonical_wire(), pxte);
            let old_request = ReferenceApplyRequestV1::decode(&pxar)
                .expect("frozen PXAR v5 golden must remain decodable");
            assert_eq!(old_request.canonical_wire(), pxar);
            assert_eq!(
                wire_error(
                    ManagedFabricTargetExecutionV1::decode(&pxte)
                        .expect_err("PXTE v5 decoder must reject v4")
                ),
                (
                    if pxte.len() > MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES {
                        ManagedFabricWireErrorCode::FrameTooLarge
                    } else {
                        ManagedFabricWireErrorCode::UnsupportedVersion
                    },
                    None
                )
            );
            assert_eq!(
                wire_error(
                    ManagedFabricApplyRequestV1::decode(&pxar)
                        .expect_err("PXAR v6 decoder must reject v5")
                ),
                (ManagedFabricWireErrorCode::UnsupportedVersion, None)
            );
        }

        let successor = fixture_hex(vector("one_managed_fabric_service"), "outer_v6_hex");
        assert!(ReferenceApplyRequestV1::decode(&successor).is_err());
    }

    #[test]
    fn projection_mismatch_and_durable_target_mismatch_are_fail_closed() {
        let active = ManagedFabricApplyRequestV1::decode(&fixture_hex(
            vector("one_managed_fabric_service"),
            "outer_v6_hex",
        ))
        .expect("fixture request must decode");
        let mut fields = decoded_projection().fields();
        fields.target = RuntimeHostId::from_bytes([0x06; 16]);
        let other = ManagedFabricManifestProjectionV1::try_new(fields)
            .expect("other projection remains internally valid");
        assert_eq!(
            wire_error(
                active
                    .validate_projection(&other)
                    .expect_err("different installed projection must fail")
            ),
            (ManagedFabricWireErrorCode::CompatibilityMismatch, None)
        );
        assert_eq!(
            wire_error(
                verify_managed_fabric_durable_slice_v1(
                    active.canonical_slice_wire(),
                    RuntimeHostId::from_bytes([0x06; 16]),
                    active.provenance(),
                    active.target_slice_digest(),
                    &other,
                )
                .expect_err("journal target mismatch must fail before digest admission")
            ),
            (ManagedFabricWireErrorCode::TargetMismatch, Some(2))
        );
    }
}
