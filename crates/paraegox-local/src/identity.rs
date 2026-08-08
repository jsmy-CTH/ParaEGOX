//! Owner-private identity material for DeveloperLocal compositions.
//!
//! Production accepts only the validated launcher configuration and derives
//! every path beneath its state root. Fresh material comes only from the OS
//! CSPRNG; caller-provided entropy exists only in this module's tests. The
//! additive PXDI v2 shape is created only by the explicit hidden identity-init
//! command and strictly reopened by the hidden distributed composition; the
//! manifest alone does not start or claim an owner chain.

use core::fmt;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::SigningKey;
use nix::unistd::{Gid, Uid, chown};
use paraegox_deployment::{DeveloperFixtureDerivedIdentityV1, DeveloperFixtureIdentitySeedV1};
use paraegox_fabric::restricted_runtime_apply_peer_certificate_common_name_v1;
use paraegox_kernel::identity::PrincipalRef;
use paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentProviderRefV1;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{
    DeveloperDistributedFixtureActionV1, DeveloperDistributedFixtureConfigV1,
    DeveloperFixtureConfigV1, DeveloperNodeConfigV1, DeveloperProvisionedConfigV1,
    ProviderProfileV1,
};

const IDENTITY_DIRECTORY_NAME: &str = "developer-local-identity-v1";
const OPENAI_IDENTITY_DIRECTORY_NAME: &str = "developer-openai-identity-v1";
const DEEPSEEK_IDENTITY_DIRECTORY_NAME: &str = "developer-deepseek-chat-completions-identity-v1";
const LEGACY_DISTRIBUTED_IDENTITY_DIRECTORY_NAME: &str = "developer-distributed-identity-v1";
const DISTRIBUTED_IDENTITY_DIRECTORY_NAME: &str = "developer-distributed-identity-v2";
const NODE_IDENTITY_DIRECTORY_NAME: &str = "developer-node-identity-v1";
const MANIFEST_FILE_NAME: &str = "identity-manifest-v1.pxli";
const MANIFEST_TEMP_FILE_NAME: &str = ".identity-manifest-v1.pxli.tmp";
const OPENAI_MANIFEST_FILE_NAME: &str = "identity-manifest-v1.pxoi";
const OPENAI_MANIFEST_TEMP_FILE_NAME: &str = ".identity-manifest-v1.pxoi.tmp";
const DEEPSEEK_MANIFEST_FILE_NAME: &str = "identity-manifest-v1.pxds";
const DEEPSEEK_MANIFEST_TEMP_FILE_NAME: &str = ".identity-manifest-v1.pxds.tmp";
const DISTRIBUTED_MANIFEST_FILE_NAME: &str = "identity-manifest-v2.pxdi";
const DISTRIBUTED_MANIFEST_TEMP_FILE_NAME: &str = ".identity-manifest-v2.pxdi.tmp";
const NODE_MANIFEST_FILE_NAME: &str = "identity-manifest-v1.pxni";
const NODE_MANIFEST_TEMP_FILE_NAME: &str = ".identity-manifest-v1.pxni.tmp";
const WRITER_LOCK_FILE_NAME: &str = ".writer.lock";

const MANIFEST_MAGIC: &[u8; 4] = b"PXLI";
const OPENAI_MANIFEST_MAGIC: &[u8; 4] = b"PXOI";
const DEEPSEEK_MANIFEST_MAGIC: &[u8; 4] = b"PXDS";
const DISTRIBUTED_MANIFEST_MAGIC: &[u8; 4] = b"PXDI";
const NODE_MANIFEST_MAGIC: &[u8; 4] = b"PXNI";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_HEADER_BYTES: usize = 16;
const MANIFEST_FIELD_COUNT: u16 = 17;
const MANIFEST_FLAGS: u16 = 0;
const CHECKSUM_BYTES: usize = 32;
const IDENTITY_FIELD_COUNT: usize = 13;
const MANIFEST_PAYLOAD_BYTES: usize = (3 * 32) + (IDENTITY_FIELD_COUNT * 16) + 32;
const MANIFEST_CHECKSUM_OFFSET: usize = MANIFEST_HEADER_BYTES + MANIFEST_PAYLOAD_BYTES;
const MANIFEST_WIRE_BYTES: usize = MANIFEST_CHECKSUM_OFFSET + CHECKSUM_BYTES;
const FRESH_ENTROPY_BYTES: usize = (3 * 32) + (IDENTITY_FIELD_COUNT * 16);

const DISTRIBUTED_MANIFEST_VERSION: u16 = 2;
const DISTRIBUTED_MANIFEST_HEADER_BYTES: usize = 16;
const DISTRIBUTED_MANIFEST_FIELD_COUNT: u16 = 62;
const DISTRIBUTED_MANIFEST_FLAGS: u16 = 0;
const DISTRIBUTED_SHARED_IDENTITY_FIELD_COUNT: usize = 9;
const DISTRIBUTED_TARGET_IDENTITY_FIELD_COUNT: usize = 20;
const DISTRIBUTED_SHARED_SECRET_FIELD_COUNT: usize = 2;
const DISTRIBUTED_TARGET_SECRET_FIELD_COUNT: usize = 3;
const DISTRIBUTED_SHARED_DIGEST_FIELD_COUNT: usize = 1;
const DISTRIBUTED_TARGET_SCALAR_FIELD_COUNT: usize = 2;
const DISTRIBUTED_TARGET_COUNT: usize = 2;
const DISTRIBUTED_MANIFEST_PAYLOAD_BYTES: usize = (DISTRIBUTED_SHARED_SECRET_FIELD_COUNT * 32)
    + (DISTRIBUTED_SHARED_IDENTITY_FIELD_COUNT * 16)
    + (DISTRIBUTED_SHARED_DIGEST_FIELD_COUNT * 32)
    + DISTRIBUTED_TARGET_COUNT
        * ((DISTRIBUTED_TARGET_SECRET_FIELD_COUNT * 32)
            + (DISTRIBUTED_TARGET_IDENTITY_FIELD_COUNT * 16)
            + (DISTRIBUTED_TARGET_SCALAR_FIELD_COUNT * 8));
const DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET: usize =
    DISTRIBUTED_MANIFEST_HEADER_BYTES + DISTRIBUTED_MANIFEST_PAYLOAD_BYTES;
const DISTRIBUTED_MANIFEST_WIRE_BYTES: usize =
    DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET + CHECKSUM_BYTES;
const DISTRIBUTED_FRESH_ENTROPY_BYTES: usize =
    DISTRIBUTED_MANIFEST_PAYLOAD_BYTES - (DISTRIBUTED_SHARED_DIGEST_FIELD_COUNT * 32);

const NODE_MANIFEST_VERSION: u16 = 1;
const NODE_MANIFEST_HEADER_BYTES: usize = 16;
const NODE_MANIFEST_FIELD_COUNT: u16 = 8;
const NODE_MANIFEST_FLAGS: u16 = 0;
const NODE_IDENTITY_FIELD_COUNT: usize = 5;
const NODE_MANIFEST_PAYLOAD_BYTES: usize = (2 * 32) + (NODE_IDENTITY_FIELD_COUNT * 16) + 32;
const NODE_MANIFEST_CHECKSUM_OFFSET: usize =
    NODE_MANIFEST_HEADER_BYTES + NODE_MANIFEST_PAYLOAD_BYTES;
const NODE_MANIFEST_WIRE_BYTES: usize = NODE_MANIFEST_CHECKSUM_OFFSET + CHECKSUM_BYTES;
const NODE_FRESH_ENTROPY_BYTES: usize = (2 * 32) + (NODE_IDENTITY_FIELD_COUNT * 16);

const MANIFEST_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.local.developer-identity-manifest.checksum.sha256.v1";
const OPENAI_MANIFEST_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.local.developer-openai-identity-manifest.checksum.sha256.v1";
const DEEPSEEK_MANIFEST_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.local.developer-deepseek-chat-completions-identity-manifest.checksum.sha256.v1";
const DISTRIBUTED_MANIFEST_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.local.developer-distributed-identity-manifest.checksum.sha256.v2";
const NODE_MANIFEST_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.local.developer-node-identity-manifest.checksum.sha256.v1";
const DETERMINISTIC_PROVIDER_CONFIG_DOMAIN: &[u8] =
    b"paraegox.local.developer-fixture-provider.config.sha256.v1";
const DETERMINISTIC_PROVIDER_PROFILE: &[u8] = b"deterministic-fixture-v1";
const DISTRIBUTED_ENROLLMENT_PLAN_SCHEMA: &str =
    "paraegox.developer-distributed-certificate-enrollment.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityProviderProfileV1 {
    DeterministicFixture,
    OpenAiResponses,
    DeepSeekChatCompletions,
}

impl IdentityProviderProfileV1 {
    const fn identity_directory(self) -> &'static str {
        match self {
            Self::DeterministicFixture => IDENTITY_DIRECTORY_NAME,
            Self::OpenAiResponses => OPENAI_IDENTITY_DIRECTORY_NAME,
            Self::DeepSeekChatCompletions => DEEPSEEK_IDENTITY_DIRECTORY_NAME,
        }
    }

    const fn conflicting_identity_directories(self) -> [&'static str; 3] {
        match self {
            Self::DeterministicFixture => [
                OPENAI_IDENTITY_DIRECTORY_NAME,
                DEEPSEEK_IDENTITY_DIRECTORY_NAME,
                NODE_IDENTITY_DIRECTORY_NAME,
            ],
            Self::OpenAiResponses => [
                IDENTITY_DIRECTORY_NAME,
                DEEPSEEK_IDENTITY_DIRECTORY_NAME,
                NODE_IDENTITY_DIRECTORY_NAME,
            ],
            Self::DeepSeekChatCompletions => [
                IDENTITY_DIRECTORY_NAME,
                OPENAI_IDENTITY_DIRECTORY_NAME,
                NODE_IDENTITY_DIRECTORY_NAME,
            ],
        }
    }

    const fn manifest_file(self) -> &'static str {
        match self {
            Self::DeterministicFixture => MANIFEST_FILE_NAME,
            Self::OpenAiResponses => OPENAI_MANIFEST_FILE_NAME,
            Self::DeepSeekChatCompletions => DEEPSEEK_MANIFEST_FILE_NAME,
        }
    }

    const fn temporary_file(self) -> &'static str {
        match self {
            Self::DeterministicFixture => MANIFEST_TEMP_FILE_NAME,
            Self::OpenAiResponses => OPENAI_MANIFEST_TEMP_FILE_NAME,
            Self::DeepSeekChatCompletions => DEEPSEEK_MANIFEST_TEMP_FILE_NAME,
        }
    }

    const fn magic(self) -> &'static [u8; 4] {
        match self {
            Self::DeterministicFixture => MANIFEST_MAGIC,
            Self::OpenAiResponses => OPENAI_MANIFEST_MAGIC,
            Self::DeepSeekChatCompletions => DEEPSEEK_MANIFEST_MAGIC,
        }
    }

    const fn checksum_domain(self) -> &'static [u8] {
        match self {
            Self::DeterministicFixture => MANIFEST_CHECKSUM_DOMAIN,
            Self::OpenAiResponses => OPENAI_MANIFEST_CHECKSUM_DOMAIN,
            Self::DeepSeekChatCompletions => DEEPSEEK_MANIFEST_CHECKSUM_DOMAIN,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityManifestError {
    Io(io::ErrorKind),
    InsecureStateRoot,
    InsecureIdentityDirectory,
    UnexpectedIdentityEntry,
    ProfileLockContended,
    InsecureProfileLock,
    WriterLockContended,
    InsecureWriterLock,
    StalePublication,
    EntropyUnavailable,
    InvalidFreshEntropy,
    InsecureManifest,
    InvalidManifestLength,
    InvalidManifestMagic,
    UnsupportedManifestVersion,
    InvalidManifestHeader,
    ManifestChecksumMismatch,
    InvalidManifestField,
    PublicationConflict,
    PublicationOutcomeUncertain,
    ReopenMismatch,
    ProviderProfileMismatch,
    InsecureCredentialFile,
    DistributedManifestNotInitialized,
    EnrollmentPlanEncoding,
}

impl fmt::Display for IdentityManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "DeveloperLocal identity storage I/O failed",
            Self::InsecureStateRoot => "DeveloperLocal state root is not owner-private",
            Self::InsecureIdentityDirectory => {
                "DeveloperLocal identity directory is not owner-private"
            }
            Self::UnexpectedIdentityEntry => {
                "DeveloperLocal identity directory contains an unexpected entry"
            }
            Self::ProfileLockContended => {
                "DeveloperLocal identity profile selection is already active"
            }
            Self::InsecureProfileLock => {
                "DeveloperLocal identity profile lock root changed identity"
            }
            Self::WriterLockContended => "DeveloperLocal identity writer is already active",
            Self::InsecureWriterLock => "DeveloperLocal identity writer lock is insecure",
            Self::StalePublication => "DeveloperLocal identity publication is incomplete or stale",
            Self::EntropyUnavailable => "operating-system secure entropy is unavailable",
            Self::InvalidFreshEntropy => "secure entropy produced invalid identity material",
            Self::InsecureManifest => "DeveloperLocal identity manifest is insecure",
            Self::InvalidManifestLength => "DeveloperLocal identity manifest length is invalid",
            Self::InvalidManifestMagic => "DeveloperLocal identity manifest magic is invalid",
            Self::UnsupportedManifestVersion => {
                "DeveloperLocal identity manifest version is unsupported"
            }
            Self::InvalidManifestHeader => "DeveloperLocal identity manifest header is invalid",
            Self::ManifestChecksumMismatch => {
                "DeveloperLocal identity manifest checksum mismatched"
            }
            Self::InvalidManifestField => "DeveloperLocal identity manifest field is invalid",
            Self::PublicationConflict => "DeveloperLocal identity manifest publication conflicted",
            Self::PublicationOutcomeUncertain => {
                "DeveloperLocal identity manifest publication outcome is uncertain"
            }
            Self::ReopenMismatch => "DeveloperLocal identity manifest changed during strict reopen",
            Self::ProviderProfileMismatch => {
                "DeveloperLocal state root is pinned to a different provider profile"
            }
            Self::InsecureCredentialFile => {
                "DeveloperLocal node TLS credential file failed identity or permission checks"
            }
            Self::DistributedManifestNotInitialized => {
                "distributed DeveloperLocal identity is not explicitly initialized"
            }
            Self::EnrollmentPlanEncoding => {
                "distributed DeveloperLocal enrollment plan encoding failed"
            }
        })
    }
}

impl std::error::Error for IdentityManifestError {}

impl From<io::Error> for IdentityManifestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// Secrets and stable internal identities for exactly one local composition.
///
/// It is intentionally neither `Clone` nor byte-debuggable. Typed accessors
/// are added only beside the admitted real facade consumer.
pub(crate) struct IdentityManifestV1 {
    profile: IdentityProviderProfileV1,
    controller_signing_seed: [u8; 32],
    authority_signing_seed: [u8; 32],
    runtime_signing_seed: [u8; 32],
    manifest_instance_id: [u8; 16],
    controller_instance_id: [u8; 16],
    authority_instance_id: [u8; 16],
    runtime_instance_id: [u8; 16],
    source_scope_id: [u8; 16],
    source_plan_id: [u8; 16],
    fabric_service_id: [u8; 16],
    agent_service_id: [u8; 16],
    submit_binding_id: [u8; 16],
    control_binding_id: [u8; 16],
    provider_ref: [u8; 16],
    deck_run_id: [u8; 16],
    session_id: [u8; 16],
    provider_configuration_digest: [u8; 32],
}

impl fmt::Debug for IdentityManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityManifestV1")
            .field("version", &MANIFEST_VERSION)
            .field("profile", &self.profile)
            .field("controller_signing_seed", &Redacted)
            .field("authority_signing_seed", &Redacted)
            .field("runtime_signing_seed", &Redacted)
            .field("internal_identities", &Redacted)
            .field("provider_configuration_digest", &Redacted)
            .finish()
    }
}

impl Drop for IdentityManifestV1 {
    fn drop(&mut self) {
        self.controller_signing_seed.zeroize();
        self.authority_signing_seed.zeroize();
        self.runtime_signing_seed.zeroize();
    }
}

/// Owner-private identity for the public host-local Node command.
///
/// Only the Runtime response seed and the PXNB bearer token are secret. The
/// remote Controller request and tenure Authority keys are verification-only
/// config pins and are deliberately absent from this durable format.
pub(crate) struct DeveloperNodeIdentityManifestV1 {
    runtime_response_signing_seed: [u8; 32],
    pxnb_reference_token: [u8; 32],
    manifest_instance_id: [u8; 16],
    node_id: [u8; 16],
    node_principal: [u8; 16],
    node_incarnation: [u8; 16],
    node_management_endpoint_ref: [u8; 16],
    config_commitment: [u8; 32],
}

impl fmt::Debug for DeveloperNodeIdentityManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperNodeIdentityManifestV1")
            .field("version", &NODE_MANIFEST_VERSION)
            .field("secret_material", &Redacted)
            .field("local_identities", &Redacted)
            .field("config_commitment", &Redacted)
            .finish()
    }
}

impl Drop for DeveloperNodeIdentityManifestV1 {
    fn drop(&mut self) {
        self.runtime_response_signing_seed.zeroize();
        self.pxnb_reference_token.zeroize();
    }
}

/// Canonical target order for the additive two-target DeveloperLocal shape.
///
/// `A` and `B` are slots, not new runtime identities. The manifest assigns
/// them by strictly sorting the two durable Runtime target bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DistributedDeveloperLocalTargetV1 {
    A,
    B,
}

impl DistributedDeveloperLocalTargetV1 {
    const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}

/// Per-target source identities and local capability material for the PXDI v2
/// distributed DeveloperLocal composition.
///
/// It is neither `Clone` nor byte-debuggable. The three secret fields are
/// zeroized independently when the target material is dropped. Runtime and
/// Controller-derived identities are intentionally absent: the composition
/// obtains them only through `DeveloperFixtureDerivedIdentityV1`.
pub(crate) struct DistributedDeveloperLocalTargetIdentityV1 {
    runtime_response_signing_seed: [u8; 32],
    pxnb_reference_token: [u8; 32],
    pxob_observation_token: [u8; 32],
    installation_id: [u8; 16],
    runtime_target: [u8; 16],
    fabric_service_id: [u8; 16],
    agent_service_id: [u8; 16],
    submit_binding_id: [u8; 16],
    control_binding_id: [u8; 16],
    deck_run_id: [u8; 16],
    session_id: [u8; 16],
    node_id: [u8; 16],
    node_principal: [u8; 16],
    node_incarnation: [u8; 16],
    node_management_endpoint_ref: [u8; 16],
    runtime_observation_endpoint_ref: [u8; 16],
    runtime_apply_endpoint_ref: [u8; 16],
    transport_profile_ref: [u8; 16],
    controller_connector_credential_ref: [u8; 16],
    runtime_listener_credential_ref: [u8; 16],
    fabric_peer_identity_ref: [u8; 16],
    evidence_store_epoch: [u8; 16],
    evidence_owner_ref: [u8; 16],
    registration_epoch: u64,
    endpoint_generation: u64,
}

impl fmt::Debug for DistributedDeveloperLocalTargetIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributedDeveloperLocalTargetIdentityV2")
            .field("runtime_response_signing_seed", &Redacted)
            .field("pxnb_reference_token", &Redacted)
            .field("pxob_observation_token", &Redacted)
            .field("identities", &Redacted)
            .finish()
    }
}

impl Drop for DistributedDeveloperLocalTargetIdentityV1 {
    fn drop(&mut self) {
        self.runtime_response_signing_seed.zeroize();
        self.pxnb_reference_token.zeroize();
        self.pxob_observation_token.zeroize();
    }
}

/// Versioned source identity input for one exact two-target DeveloperLocal
/// owner.
///
/// PXDI v2 has a directory and file distinct from both PXLI/PXOI v1 and the
/// never-runnable PXDI v1 scaffold. Every older or conflicting profile fails
/// closed; no bytes are silently reinterpreted or migrated. This manifest
/// persists only source inputs. Writer, Controller-key, Authority, Runtime and
/// successor-store identities come exclusively from the existing
/// `DeveloperFixtureDerivedIdentityV1::try_from_seed` authority. Runtime,
/// Controller-base and coordinator store identities are observed from their
/// real owners after startup and are never caller-pinned here.
///
/// Stable restricted-transport refs live here, while locators, routes,
/// certificate paths and secret credential values remain mandatory inputs of
/// the explicit profile/config boundary; they must not be inferred from slot
/// position or restart count. The hidden initializer emits only a non-secret
/// derived enrollment plan, while the operational launcher strictly requires
/// this manifest to exist before starting any owner. The Rust type retains its
/// internal v1 suffix only so that layout can compile within this single-file
/// format migration; the canonical wire and storage names are unambiguously
/// v2.
pub(crate) struct DistributedDeveloperLocalIdentityManifestV1 {
    controller_signing_seed: [u8; 32],
    authority_signing_seed: [u8; 32],
    manifest_instance_id: [u8; 16],
    controller_instance_id: [u8; 16],
    authority_instance_id: [u8; 16],
    source_scope_id: [u8; 16],
    source_plan_id: [u8; 16],
    provider_ref: [u8; 16],
    enrollment_issuer_ref: [u8; 16],
    transport_trust_domain_ref: [u8; 16],
    transport_trust_anchor_ref: [u8; 16],
    provider_configuration_digest: [u8; 32],
    targets: [DistributedDeveloperLocalTargetIdentityV1; DISTRIBUTED_TARGET_COUNT],
}

impl fmt::Debug for DistributedDeveloperLocalIdentityManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributedDeveloperLocalIdentityManifestV2")
            .field("version", &DISTRIBUTED_MANIFEST_VERSION)
            .field("shared_signing_seeds", &Redacted)
            .field("source_identities", &Redacted)
            .field("provider_configuration_digest", &Redacted)
            .field("targets", &Redacted)
            .finish()
    }
}

impl Drop for DistributedDeveloperLocalIdentityManifestV1 {
    fn drop(&mut self) {
        self.controller_signing_seed.zeroize();
        self.authority_signing_seed.zeroize();
    }
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

struct SensitiveEntropy([u8; FRESH_ENTROPY_BYTES]);

impl SensitiveEntropy {
    const fn zeroed() -> Self {
        Self([0; FRESH_ENTROPY_BYTES])
    }
}

impl Drop for SensitiveEntropy {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SensitiveWire([u8; MANIFEST_WIRE_BYTES]);

impl SensitiveWire {
    const fn zeroed() -> Self {
        Self([0; MANIFEST_WIRE_BYTES])
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SensitiveWire {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SensitiveDistributedEntropy([u8; DISTRIBUTED_FRESH_ENTROPY_BYTES]);

impl SensitiveDistributedEntropy {
    const fn zeroed() -> Self {
        Self([0; DISTRIBUTED_FRESH_ENTROPY_BYTES])
    }
}

impl Drop for SensitiveDistributedEntropy {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SensitiveDistributedWire([u8; DISTRIBUTED_MANIFEST_WIRE_BYTES]);

impl SensitiveDistributedWire {
    const fn zeroed() -> Self {
        Self([0; DISTRIBUTED_MANIFEST_WIRE_BYTES])
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SensitiveDistributedWire {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SensitiveNodeEntropy([u8; NODE_FRESH_ENTROPY_BYTES]);

impl SensitiveNodeEntropy {
    const fn zeroed() -> Self {
        Self([0; NODE_FRESH_ENTROPY_BYTES])
    }
}

impl Drop for SensitiveNodeEntropy {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SensitiveNodeWire([u8; NODE_MANIFEST_WIRE_BYTES]);

impl SensitiveNodeWire {
    const fn zeroed() -> Self {
        Self([0; NODE_MANIFEST_WIRE_BYTES])
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SensitiveNodeWire {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

trait EntropySource {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityManifestError>;
}

struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityManifestError> {
        getrandom::fill(destination).map_err(|_| IdentityManifestError::EntropyUnavailable)
    }
}

struct IdentityPaths {
    directory: PathBuf,
    manifest: PathBuf,
    temporary: PathBuf,
    writer_lock: PathBuf,
}

#[derive(Clone, Copy)]
enum IdentityManifestAccessV1 {
    Initialize,
    OpenExisting,
}

struct IdentityManifestLoadOptions<'a> {
    conflicting_directories: &'a [&'static str],
    wire_bytes: usize,
    access: IdentityManifestAccessV1,
}

impl IdentityPaths {
    #[cfg(test)]
    fn from_state_root(state_root: &Path) -> Self {
        Self::from_state_root_for_profile(
            state_root,
            IdentityProviderProfileV1::DeterministicFixture,
        )
    }

    fn from_state_root_for_profile(state_root: &Path, profile: IdentityProviderProfileV1) -> Self {
        Self::from_state_root_with_names(
            state_root,
            profile.identity_directory(),
            profile.manifest_file(),
            profile.temporary_file(),
        )
    }

    fn distributed(state_root: &Path) -> Self {
        Self::from_state_root_with_names(
            state_root,
            DISTRIBUTED_IDENTITY_DIRECTORY_NAME,
            DISTRIBUTED_MANIFEST_FILE_NAME,
            DISTRIBUTED_MANIFEST_TEMP_FILE_NAME,
        )
    }

    fn node(state_root: &Path) -> Self {
        Self::from_state_root_with_names(
            state_root,
            NODE_IDENTITY_DIRECTORY_NAME,
            NODE_MANIFEST_FILE_NAME,
            NODE_MANIFEST_TEMP_FILE_NAME,
        )
    }

    fn from_state_root_with_names(
        state_root: &Path,
        directory_name: &str,
        manifest_file: &str,
        temporary_file: &str,
    ) -> Self {
        let directory = state_root.join(directory_name);
        Self {
            manifest: directory.join(manifest_file),
            temporary: directory.join(temporary_file),
            writer_lock: directory.join(WRITER_LOCK_FILE_NAME),
            directory,
        }
    }

    #[cfg(test)]
    fn from_config(config: &DeveloperFixtureConfigV1) -> Self {
        Self::from_state_root(config.state_root())
    }
}

/// Loads one durable manifest or creates it from operating-system entropy.
/// Corrupt, insecure, unknown-version, and incomplete state is never rebuilt.
pub(crate) fn load_or_create(
    config: &DeveloperFixtureConfigV1,
) -> Result<IdentityManifestV1, IdentityManifestError> {
    let mut entropy = OsEntropy;
    load_or_create_inner(config, &mut entropy)
}

pub(crate) fn load_or_create_provisioned(
    config: &DeveloperProvisionedConfigV1,
) -> Result<IdentityManifestV1, IdentityManifestError> {
    let profile = match config.provider_profile() {
        ProviderProfileV1::OpenAiResponsesV1 => IdentityProviderProfileV1::OpenAiResponses,
        ProviderProfileV1::DeepSeekChatCompletionsV1 => {
            IdentityProviderProfileV1::DeepSeekChatCompletions
        }
        ProviderProfileV1::DeterministicFixtureV1 => {
            return Err(IdentityManifestError::InvalidManifestField);
        }
    };
    let mut entropy = OsEntropy;
    load_or_create_profile(
        config.state_root(),
        profile,
        &|provider_ref| {
            let provider_ref = ManagedAgentProviderRefV1::try_from_bytes(provider_ref)
                .map_err(|_| IdentityManifestError::InvalidManifestField)?;
            config
                .provider_configuration_digest(provider_ref)
                .map_err(|_| IdentityManifestError::InvalidManifestField)
        },
        &mut entropy,
    )
}

/// Loads or creates the isolated node-only identity selected by the exact
/// semantic config commitment. Reusing the state root with changed control or
/// transport pins fails closed instead of rotating local authority.
pub(crate) fn load_or_create_node(
    config: &DeveloperNodeConfigV1,
) -> Result<DeveloperNodeIdentityManifestV1, IdentityManifestError> {
    let mut entropy = OsEntropy;
    load_or_create_node_inner(config, &mut entropy)
}

/// Performs the path-identity and mode gate required before any durable Node
/// state is created. The Runtime listener still owns parsing and using these
/// files; this check prevents Local from handing it a symlink, linked, or
/// untrusted-user-replaceable credential path. DeveloperLocal deliberately
/// trusts the same uid, which already owns the PXNI seed and PXNB token.
pub(crate) fn validate_node_tls_files(
    config: &DeveloperNodeConfigV1,
) -> Result<(), IdentityManifestError> {
    let canonical_state_root = open_existing_state_root(config.state_root())
        .map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    let restricted = config.restricted_runtime_apply();
    let files = [
        restricted.root_ca_certificate_file(),
        restricted.runtime_listener_certificate_file(),
        restricted.runtime_listener_private_key_file(),
    ];
    if files
        .iter()
        .enumerate()
        .any(|(index, path)| files[index + 1..].contains(path))
    {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    let parent = files[0]
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(IdentityManifestError::InsecureCredentialFile)?;
    if parent != canonical_state_root.join("credentials") {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    if files[1..].iter().any(|path| path.parent() != Some(parent)) {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    validate_existing_path_chain(parent)
        .map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    let parent_before =
        fs::symlink_metadata(parent).map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    validate_node_tls_parent_metadata(&parent_before)?;
    let parent_handle = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    let parent_opened = parent_handle
        .metadata()
        .map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    validate_node_tls_parent_metadata(&parent_opened)?;
    if !same_file(&parent_before, &parent_opened) {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    validate_node_tls_file(files[0], false)?;
    validate_node_tls_file(files[1], false)?;
    validate_node_tls_file(files[2], true)?;
    let parent_after =
        fs::symlink_metadata(parent).map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    validate_node_tls_parent_metadata(&parent_after)?;
    if !same_file(&parent_opened, &parent_after) {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    Ok(())
}

fn validate_node_tls_file(path: &Path, private_key: bool) -> Result<(), IdentityManifestError> {
    validate_existing_path_chain(path)
        .map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    let before =
        fs::symlink_metadata(path).map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    validate_node_tls_file_metadata(&before, private_key)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    let opened = file
        .metadata()
        .map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    let after =
        fs::symlink_metadata(path).map_err(|_| IdentityManifestError::InsecureCredentialFile)?;
    validate_node_tls_file_metadata(&opened, private_key)?;
    validate_node_tls_file_metadata(&after, private_key)?;
    if !same_file(&before, &opened) || !same_file(&opened, &after) {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    Ok(())
}

fn validate_node_tls_parent_metadata(metadata: &fs::Metadata) -> Result<(), IdentityManifestError> {
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.gid() != Gid::effective().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    Ok(())
}

fn validate_node_tls_file_metadata(
    metadata: &fs::Metadata,
    private_key: bool,
) -> Result<(), IdentityManifestError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if private_key {
        if metadata.uid() != Uid::effective().as_raw()
            || metadata.gid() != Gid::effective().as_raw()
            || mode != 0o600
        {
            return Err(IdentityManifestError::InsecureCredentialFile);
        }
    } else if mode & 0o022 != 0 {
        return Err(IdentityManifestError::InsecureCredentialFile);
    }
    Ok(())
}

/// Loads or creates the isolated PXDI v2 source manifest consumed by the
/// hidden distributed DeveloperLocal composition for owner identity,
/// transport references, and its private layout.
pub(crate) fn initialize_distributed(
    state_root: &Path,
) -> Result<DistributedDeveloperLocalIdentityManifestV1, IdentityManifestError> {
    let mut entropy = OsEntropy;
    load_or_create_distributed_inner(state_root, &mut entropy)
}

/// Strictly opens one previously initialized PXDI v2 manifest.
///
/// Unlike `initialize_distributed`, this path never creates the state root,
/// identity directory, writer lock, or manifest. The operational distributed
/// composition uses only this API so a missing certificate setup cannot use a
/// failed launch as an implicit identity initializer.
pub(crate) fn open_distributed(
    state_root: &Path,
) -> Result<DistributedDeveloperLocalIdentityManifestV1, IdentityManifestError> {
    open_distributed_inner(state_root)
}

/// Produces the explicit non-secret certificate enrollment input for the
/// initialized two-target DeveloperLocal identity and the exact launch
/// configuration that selected it.
///
/// This JSON is a deterministic derived view, not a configuration authority,
/// credential resolver, certificate, private key, CA, or Secret. The external
/// enrollment owner may use it to provision the already configured paths; the
/// operational launcher still reopens PXDI and consumes the original explicit
/// configuration. Repeating init reopens the byte-identical PXDI without fresh
/// entropy and regenerates this view from the exact supplied configuration; it
/// neither persists transport configuration nor rotates or revokes credentials.
pub(crate) fn distributed_certificate_enrollment_plan_json_v1(
    config: &DeveloperDistributedFixtureConfigV1,
    manifest: &DistributedDeveloperLocalIdentityManifestV1,
) -> Result<Box<str>, IdentityManifestError> {
    if config.action() != DeveloperDistributedFixtureActionV1::InitializeIdentity {
        return Err(IdentityManifestError::EnrollmentPlanEncoding);
    }
    let target_specs = [
        (
            "a",
            DistributedDeveloperLocalTargetV1::A,
            DistributedDeveloperLocalTargetV1::B,
            0_usize,
            1_usize,
        ),
        (
            "b",
            DistributedDeveloperLocalTargetV1::B,
            DistributedDeveloperLocalTargetV1::A,
            1_usize,
            0_usize,
        ),
    ];
    let mut targets = Vec::with_capacity(target_specs.len());
    for (label, target, peer_target, config_index, peer_config_index) in target_specs {
        let target_identity = manifest.target(target);
        let peer_identity = manifest.target(peer_target);
        let target_config = &config.targets()[config_index];
        let peer_config = &config.targets()[peer_config_index];
        let derived = manifest.developer_fixture_derived_identity(target)?;
        let controller_common_name = restricted_runtime_apply_peer_certificate_common_name_v1(
            PrincipalRef::from_bytes(derived.controller_principal()),
        );
        let runtime_common_name = restricted_runtime_apply_peer_certificate_common_name_v1(
            PrincipalRef::from_bytes(derived.runtime_principal()),
        );
        let local_fabric_common_name = peer_config.fabric().expected_peer_common_name();
        let pxrp_subject_alt_name =
            tls_listener_ipv4_subject_alt_name(target_config.pxrp().tls_listener_locator())?;
        let fabric_subject_alt_name =
            tls_listener_ipv4_subject_alt_name(target_config.fabric().tls_listener_locator())?;
        targets.push(json!({
            "label": label,
            "runtime_target": lower_hex(target_identity.runtime_target()),
            "pxrp": {
                "listener_locator": target_config.pxrp().tls_listener_locator(),
                "route": target_config.pxrp().route(),
                "root_ca_certificate_file": enrollment_path_text(
                    target_config.pxrp().root_ca_certificate_file(),
                )?,
                "controller_client": {
                    "credential_ref": lower_hex(
                        target_identity.controller_connector_credential_ref(),
                    ),
                    "certificate_common_name": controller_common_name,
                    "extended_key_usage": ["clientAuth"],
                    "certificate_file": enrollment_path_text(
                        target_config.pxrp().controller_client_certificate_file(),
                    )?,
                    "private_key_file": enrollment_path_text(
                        target_config.pxrp().controller_client_private_key_file(),
                    )?,
                },
                "runtime_server": {
                    "credential_ref": lower_hex(
                        target_identity.runtime_listener_credential_ref(),
                    ),
                    "certificate_common_name": runtime_common_name,
                    "subject_alt_name_ip": pxrp_subject_alt_name,
                    "extended_key_usage": ["serverAuth"],
                    "certificate_file": enrollment_path_text(
                        target_config.pxrp().runtime_server_certificate_file(),
                    )?,
                    "private_key_file": enrollment_path_text(
                        target_config.pxrp().runtime_server_private_key_file(),
                    )?,
                },
            },
            "fabric": {
                "listener_locator": target_config.fabric().tls_listener_locator(),
                "root_ca_certificate_file": enrollment_path_text(
                    target_config.fabric().root_ca_certificate_file(),
                )?,
                "local_credential_ref": lower_hex(
                    target_config.fabric().local_credential_ref().as_bytes(),
                ),
                "local_peer_identity_ref": lower_hex(
                    target_identity.fabric_peer_identity_ref(),
                ),
                "local_certificate_common_name": local_fabric_common_name,
                "expected_peer_identity_ref": lower_hex(
                    peer_identity.fabric_peer_identity_ref(),
                ),
                "expected_peer_common_name": target_config
                    .fabric()
                    .expected_peer_common_name(),
                "listener": {
                    "certificate_common_name": local_fabric_common_name,
                    "subject_alt_name_ip": fabric_subject_alt_name,
                    "extended_key_usage": ["serverAuth"],
                    "certificate_file": enrollment_path_text(
                        target_config.fabric().listen_certificate_file(),
                    )?,
                    "private_key_file": enrollment_path_text(
                        target_config.fabric().listen_private_key_file(),
                    )?,
                },
                "connector": {
                    "certificate_common_name": local_fabric_common_name,
                    "extended_key_usage": ["clientAuth"],
                    "certificate_file": enrollment_path_text(
                        target_config.fabric().connect_certificate_file(),
                    )?,
                    "private_key_file": enrollment_path_text(
                        target_config.fabric().connect_private_key_file(),
                    )?,
                },
            },
        }));
    }
    serde_json::to_string(&json!({
        "schema": DISTRIBUTED_ENROLLMENT_PLAN_SCHEMA,
        "version": 1,
        "contains_secret_material": false,
        "manifest_instance_id": lower_hex(manifest.manifest_instance_id()),
        "enrollment_issuer_ref": lower_hex(manifest.enrollment_issuer_ref()),
        "transport_trust_domain_ref": lower_hex(manifest.transport_trust_domain_ref()),
        "transport_trust_anchor_ref": lower_hex(manifest.transport_trust_anchor_ref()),
        "targets": targets,
    }))
    .map(String::into_boxed_str)
    .map_err(|_| IdentityManifestError::EnrollmentPlanEncoding)
}

fn enrollment_path_text(path: &Path) -> Result<&str, IdentityManifestError> {
    path.to_str()
        .ok_or(IdentityManifestError::EnrollmentPlanEncoding)
}

fn tls_listener_ipv4_subject_alt_name(locator: &str) -> Result<&str, IdentityManifestError> {
    let (address, port) = locator
        .strip_prefix("tls/")
        .and_then(|endpoint| endpoint.rsplit_once(':'))
        .ok_or(IdentityManifestError::EnrollmentPlanEncoding)?;
    address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| IdentityManifestError::EnrollmentPlanEncoding)?;
    port.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(IdentityManifestError::EnrollmentPlanEncoding)?;
    Ok(address)
}

fn lower_hex(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(LOWER_HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(*byte & 0x0f)]));
    }
    encoded
}

fn load_or_create_inner(
    config: &DeveloperFixtureConfigV1,
    entropy: &mut impl EntropySource,
) -> Result<IdentityManifestV1, IdentityManifestError> {
    load_or_create_profile(
        config.state_root(),
        IdentityProviderProfileV1::DeterministicFixture,
        &|_| Ok(deterministic_provider_configuration_digest()),
        entropy,
    )
}

fn load_or_create_profile<F>(
    state_root: &Path,
    profile: IdentityProviderProfileV1,
    expected_provider_digest: &F,
    entropy: &mut impl EntropySource,
) -> Result<IdentityManifestV1, IdentityManifestError>
where
    F: Fn([u8; 16]) -> Result<[u8; 32], IdentityManifestError>,
{
    let conflicting_profiles = profile.conflicting_identity_directories();
    load_or_create_identity_manifest(
        state_root,
        |canonical_state_root| {
            IdentityPaths::from_state_root_for_profile(canonical_state_root, profile)
        },
        IdentityManifestLoadOptions {
            conflicting_directories: &[
                conflicting_profiles[0],
                conflicting_profiles[1],
                conflicting_profiles[2],
                DISTRIBUTED_IDENTITY_DIRECTORY_NAME,
                LEGACY_DISTRIBUTED_IDENTITY_DIRECTORY_NAME,
            ],
            wire_bytes: MANIFEST_WIRE_BYTES,
            access: IdentityManifestAccessV1::Initialize,
        },
        || IdentityManifestV1::try_generate_for_profile(profile, expected_provider_digest, entropy),
        IdentityManifestV1::encode,
        |wire| IdentityManifestV1::decode_for_profile(wire, profile, expected_provider_digest),
    )
}

fn load_or_create_distributed_inner(
    state_root: &Path,
    entropy: &mut impl EntropySource,
) -> Result<DistributedDeveloperLocalIdentityManifestV1, IdentityManifestError> {
    load_or_create_identity_manifest(
        state_root,
        IdentityPaths::distributed,
        IdentityManifestLoadOptions {
            conflicting_directories: &[
                IDENTITY_DIRECTORY_NAME,
                OPENAI_IDENTITY_DIRECTORY_NAME,
                DEEPSEEK_IDENTITY_DIRECTORY_NAME,
                NODE_IDENTITY_DIRECTORY_NAME,
                LEGACY_DISTRIBUTED_IDENTITY_DIRECTORY_NAME,
            ],
            wire_bytes: DISTRIBUTED_MANIFEST_WIRE_BYTES,
            access: IdentityManifestAccessV1::Initialize,
        },
        || DistributedDeveloperLocalIdentityManifestV1::try_generate(entropy),
        DistributedDeveloperLocalIdentityManifestV1::encode,
        DistributedDeveloperLocalIdentityManifestV1::decode,
    )
}

fn load_or_create_node_inner(
    config: &DeveloperNodeConfigV1,
    entropy: &mut impl EntropySource,
) -> Result<DeveloperNodeIdentityManifestV1, IdentityManifestError> {
    let config_commitment = config.config_commitment();
    let controller_verification_key = config.control().controller_request_verification_key();
    let tenure_verification_key = config.control().tenure_verification_key();
    load_or_create_identity_manifest(
        config.state_root(),
        IdentityPaths::node,
        IdentityManifestLoadOptions {
            conflicting_directories: &[
                IDENTITY_DIRECTORY_NAME,
                OPENAI_IDENTITY_DIRECTORY_NAME,
                DEEPSEEK_IDENTITY_DIRECTORY_NAME,
                DISTRIBUTED_IDENTITY_DIRECTORY_NAME,
                LEGACY_DISTRIBUTED_IDENTITY_DIRECTORY_NAME,
            ],
            wire_bytes: NODE_MANIFEST_WIRE_BYTES,
            access: IdentityManifestAccessV1::Initialize,
        },
        || {
            DeveloperNodeIdentityManifestV1::try_generate(
                config_commitment,
                controller_verification_key,
                tenure_verification_key,
                entropy,
            )
        },
        DeveloperNodeIdentityManifestV1::encode,
        |wire| {
            DeveloperNodeIdentityManifestV1::decode(
                wire,
                config_commitment,
                controller_verification_key,
                tenure_verification_key,
            )
        },
    )
}

fn open_distributed_inner(
    state_root: &Path,
) -> Result<DistributedDeveloperLocalIdentityManifestV1, IdentityManifestError> {
    load_or_create_identity_manifest(
        state_root,
        IdentityPaths::distributed,
        IdentityManifestLoadOptions {
            conflicting_directories: &[
                IDENTITY_DIRECTORY_NAME,
                OPENAI_IDENTITY_DIRECTORY_NAME,
                DEEPSEEK_IDENTITY_DIRECTORY_NAME,
                NODE_IDENTITY_DIRECTORY_NAME,
                LEGACY_DISTRIBUTED_IDENTITY_DIRECTORY_NAME,
            ],
            wire_bytes: DISTRIBUTED_MANIFEST_WIRE_BYTES,
            access: IdentityManifestAccessV1::OpenExisting,
        },
        || Err(IdentityManifestError::DistributedManifestNotInitialized),
        DistributedDeveloperLocalIdentityManifestV1::encode,
        DistributedDeveloperLocalIdentityManifestV1::decode,
    )
}

trait SensitiveManifestWire {
    fn as_sensitive_bytes(&self) -> &[u8];
}

impl SensitiveManifestWire for SensitiveWire {
    fn as_sensitive_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl SensitiveManifestWire for SensitiveDistributedWire {
    fn as_sensitive_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl SensitiveManifestWire for SensitiveNodeWire {
    fn as_sensitive_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

fn load_or_create_identity_manifest<M, W, P, G, E, D>(
    state_root: &Path,
    paths_for_root: P,
    options: IdentityManifestLoadOptions<'_>,
    generate: G,
    encode: E,
    decode: D,
) -> Result<M, IdentityManifestError>
where
    W: SensitiveManifestWire,
    P: FnOnce(&Path) -> IdentityPaths,
    G: FnOnce() -> Result<M, IdentityManifestError>,
    E: Fn(&M) -> W,
    D: Fn(&[u8]) -> Result<M, IdentityManifestError>,
{
    let IdentityManifestLoadOptions {
        conflicting_directories,
        wire_bytes,
        access,
    } = options;
    let canonical_state_root = match access {
        IdentityManifestAccessV1::Initialize => ensure_state_root(state_root)?,
        IdentityManifestAccessV1::OpenExisting => open_existing_state_root(state_root)?,
    };
    let state_root_metadata = fs::symlink_metadata(&canonical_state_root)?;
    let profile_lock = acquire_identity_profile_lock(
        &canonical_state_root,
        state_root_metadata.uid(),
        state_root_metadata.gid(),
    )?;
    reject_conflicting_identity_profiles(&canonical_state_root, conflicting_directories)?;
    let paths = paths_for_root(&canonical_state_root);
    match access {
        IdentityManifestAccessV1::Initialize => ensure_identity_directory(
            &paths.directory,
            state_root_metadata.uid(),
            state_root_metadata.gid(),
        )?,
        IdentityManifestAccessV1::OpenExisting => validate_existing_identity_directory(
            &paths.directory,
            state_root_metadata.uid(),
            state_root_metadata.gid(),
        )?,
    }
    validate_identity_entries(&paths)?;

    let (_writer_lock, lock_created) =
        acquire_writer_lock(&paths, state_root_metadata.uid(), access)?;
    let selected_root_metadata = fs::symlink_metadata(&canonical_state_root)
        .map_err(|_| IdentityManifestError::InsecureProfileLock)?;
    validate_private_directory(
        &selected_root_metadata,
        state_root_metadata.uid(),
        state_root_metadata.gid(),
    )
    .map_err(|_| IdentityManifestError::InsecureProfileLock)?;
    if !same_file(&state_root_metadata, &selected_root_metadata) {
        return Err(IdentityManifestError::InsecureProfileLock);
    }
    drop(profile_lock);
    if lock_created {
        sync_directory(&paths.directory)?;
    }
    validate_identity_entries(&paths)?;

    match fs::symlink_metadata(&paths.temporary) {
        Ok(_) => return Err(IdentityManifestError::StalePublication),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    match fs::symlink_metadata(&paths.manifest) {
        Ok(_) => read_identity_manifest(
            &paths.manifest,
            state_root_metadata.uid(),
            wire_bytes,
            &decode,
        ),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && matches!(access, IdentityManifestAccessV1::Initialize) =>
        {
            let fresh = generate()?;
            let expected = encode(&fresh);
            if expected.as_sensitive_bytes().len() != wire_bytes {
                return Err(IdentityManifestError::InvalidManifestLength);
            }
            publish_manifest_wire(
                &paths,
                state_root_metadata.uid(),
                expected.as_sensitive_bytes(),
            )?;
            let reopened = read_identity_manifest(
                &paths.manifest,
                state_root_metadata.uid(),
                wire_bytes,
                &decode,
            )?;
            let actual = encode(&reopened);
            if expected.as_sensitive_bytes() != actual.as_sensitive_bytes() {
                return Err(IdentityManifestError::ReopenMismatch);
            }
            Ok(reopened)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(IdentityManifestError::DistributedManifestNotInitialized)
        }
        Err(error) => Err(error.into()),
    }
}

fn reject_conflicting_identity_profiles(
    state_root: &Path,
    conflicting_directories: &[&str],
) -> Result<(), IdentityManifestError> {
    for directory in conflicting_directories {
        match fs::symlink_metadata(state_root.join(directory)) {
            Ok(_) => return Err(IdentityManifestError::ProviderProfileMismatch),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl IdentityManifestV1 {
    pub(crate) fn manifest_instance_id(&self) -> &[u8; 16] {
        &self.manifest_instance_id
    }

    pub(crate) fn controller_signing_seed(&self) -> &[u8; 32] {
        &self.controller_signing_seed
    }

    pub(crate) fn authority_signing_seed(&self) -> &[u8; 32] {
        &self.authority_signing_seed
    }

    pub(crate) fn runtime_signing_seed(&self) -> &[u8; 32] {
        &self.runtime_signing_seed
    }

    pub(crate) fn controller_instance_id(&self) -> &[u8; 16] {
        &self.controller_instance_id
    }

    pub(crate) fn authority_instance_id(&self) -> &[u8; 16] {
        &self.authority_instance_id
    }

    pub(crate) fn runtime_instance_id(&self) -> &[u8; 16] {
        &self.runtime_instance_id
    }

    pub(crate) fn source_scope_id(&self) -> &[u8; 16] {
        &self.source_scope_id
    }

    pub(crate) fn source_plan_id(&self) -> &[u8; 16] {
        &self.source_plan_id
    }

    pub(crate) fn fabric_service_id(&self) -> &[u8; 16] {
        &self.fabric_service_id
    }

    pub(crate) fn agent_service_id(&self) -> &[u8; 16] {
        &self.agent_service_id
    }

    pub(crate) fn submit_binding_id(&self) -> &[u8; 16] {
        &self.submit_binding_id
    }

    pub(crate) fn control_binding_id(&self) -> &[u8; 16] {
        &self.control_binding_id
    }

    pub(crate) fn provider_ref(&self) -> &[u8; 16] {
        &self.provider_ref
    }

    pub(crate) fn deck_run_id(&self) -> &[u8; 16] {
        &self.deck_run_id
    }

    pub(crate) fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub(crate) fn provider_configuration_digest(&self) -> &[u8; 32] {
        &self.provider_configuration_digest
    }

    #[cfg(test)]
    fn try_generate(entropy: &mut impl EntropySource) -> Result<Self, IdentityManifestError> {
        Self::try_generate_for_profile(
            IdentityProviderProfileV1::DeterministicFixture,
            &|_| Ok(deterministic_provider_configuration_digest()),
            entropy,
        )
    }

    fn try_generate_for_profile<F>(
        profile: IdentityProviderProfileV1,
        expected_provider_digest: &F,
        entropy: &mut impl EntropySource,
    ) -> Result<Self, IdentityManifestError>
    where
        F: Fn([u8; 16]) -> Result<[u8; 32], IdentityManifestError>,
    {
        let mut bytes = SensitiveEntropy::zeroed();
        entropy.fill(&mut bytes.0)?;
        let mut cursor = ByteCursor::new(&bytes.0);
        let controller_signing_seed = cursor.array();
        let authority_signing_seed = cursor.array();
        let runtime_signing_seed = cursor.array();
        let manifest_instance_id = cursor.array();
        let controller_instance_id = cursor.array();
        let authority_instance_id = cursor.array();
        let runtime_instance_id = cursor.array();
        let source_scope_id = cursor.array();
        let source_plan_id = cursor.array();
        let fabric_service_id = cursor.array();
        let agent_service_id = cursor.array();
        let submit_binding_id = cursor.array();
        let control_binding_id = cursor.array();
        let provider_ref = cursor.array();
        let deck_run_id = cursor.array();
        let session_id = cursor.array();
        let manifest = Self {
            profile,
            controller_signing_seed,
            authority_signing_seed,
            runtime_signing_seed,
            manifest_instance_id,
            controller_instance_id,
            authority_instance_id,
            runtime_instance_id,
            source_scope_id,
            source_plan_id,
            fabric_service_id,
            agent_service_id,
            submit_binding_id,
            control_binding_id,
            provider_ref,
            deck_run_id,
            session_id,
            provider_configuration_digest: expected_provider_digest(provider_ref)?,
        };
        debug_assert_eq!(cursor.remaining(), 0);
        manifest.validate_fresh(expected_provider_digest)?;
        Ok(manifest)
    }

    fn encode(&self) -> SensitiveWire {
        let mut wire = SensitiveWire::zeroed();
        wire.0[0..4].copy_from_slice(self.profile.magic());
        wire.0[4..6].copy_from_slice(&MANIFEST_VERSION.to_be_bytes());
        wire.0[6..8].copy_from_slice(
            &u16::try_from(MANIFEST_HEADER_BYTES)
                .expect("manifest header width fits u16")
                .to_be_bytes(),
        );
        wire.0[8..12].copy_from_slice(
            &u32::try_from(MANIFEST_WIRE_BYTES)
                .expect("manifest wire width fits u32")
                .to_be_bytes(),
        );
        wire.0[12..14].copy_from_slice(&MANIFEST_FIELD_COUNT.to_be_bytes());
        wire.0[14..16].copy_from_slice(&MANIFEST_FLAGS.to_be_bytes());

        let mut cursor = MANIFEST_HEADER_BYTES;
        for field in [
            self.controller_signing_seed(),
            self.authority_signing_seed(),
            self.runtime_signing_seed(),
        ] {
            put_bytes(&mut wire.0, &mut cursor, field);
        }
        for field in self.identities() {
            put_bytes(&mut wire.0, &mut cursor, field);
        }
        put_bytes(
            &mut wire.0,
            &mut cursor,
            self.provider_configuration_digest(),
        );
        debug_assert_eq!(cursor, MANIFEST_CHECKSUM_OFFSET);
        let checksum = manifest_checksum(self.profile, &wire.0[..MANIFEST_CHECKSUM_OFFSET]);
        wire.0[MANIFEST_CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        wire
    }

    fn decode_for_profile<F>(
        bytes: &[u8],
        profile: IdentityProviderProfileV1,
        expected_provider_digest: &F,
    ) -> Result<Self, IdentityManifestError>
    where
        F: Fn([u8; 16]) -> Result<[u8; 32], IdentityManifestError>,
    {
        if bytes.len() != MANIFEST_WIRE_BYTES {
            return Err(IdentityManifestError::InvalidManifestLength);
        }
        if &bytes[0..4] != profile.magic() {
            return Err(IdentityManifestError::InvalidManifestMagic);
        }
        if read_u16(bytes, 4) != MANIFEST_VERSION {
            return Err(IdentityManifestError::UnsupportedManifestVersion);
        }
        if usize::from(read_u16(bytes, 6)) != MANIFEST_HEADER_BYTES
            || usize::try_from(read_u32(bytes, 8)).ok() != Some(MANIFEST_WIRE_BYTES)
            || read_u16(bytes, 12) != MANIFEST_FIELD_COUNT
            || read_u16(bytes, 14) != MANIFEST_FLAGS
        {
            return Err(IdentityManifestError::InvalidManifestHeader);
        }
        let expected_checksum = manifest_checksum(profile, &bytes[..MANIFEST_CHECKSUM_OFFSET]);
        if bytes[MANIFEST_CHECKSUM_OFFSET..] != expected_checksum {
            return Err(IdentityManifestError::ManifestChecksumMismatch);
        }

        let mut cursor = ByteCursor::new(&bytes[MANIFEST_HEADER_BYTES..MANIFEST_CHECKSUM_OFFSET]);
        let manifest = Self {
            profile,
            controller_signing_seed: cursor.array(),
            authority_signing_seed: cursor.array(),
            runtime_signing_seed: cursor.array(),
            manifest_instance_id: cursor.array(),
            controller_instance_id: cursor.array(),
            authority_instance_id: cursor.array(),
            runtime_instance_id: cursor.array(),
            source_scope_id: cursor.array(),
            source_plan_id: cursor.array(),
            fabric_service_id: cursor.array(),
            agent_service_id: cursor.array(),
            submit_binding_id: cursor.array(),
            control_binding_id: cursor.array(),
            provider_ref: cursor.array(),
            deck_run_id: cursor.array(),
            session_id: cursor.array(),
            provider_configuration_digest: cursor.array(),
        };
        debug_assert_eq!(cursor.remaining(), 0);
        manifest.validate_durable(expected_provider_digest)?;
        Ok(manifest)
    }

    fn validate_fresh<F>(&self, expected_provider_digest: &F) -> Result<(), IdentityManifestError>
    where
        F: Fn([u8; 16]) -> Result<[u8; 32], IdentityManifestError>,
    {
        self.validate_durable(expected_provider_digest)
            .map_err(|_| IdentityManifestError::InvalidFreshEntropy)
    }

    fn validate_durable<F>(&self, expected_provider_digest: &F) -> Result<(), IdentityManifestError>
    where
        F: Fn([u8; 16]) -> Result<[u8; 32], IdentityManifestError>,
    {
        let seeds = [
            &self.controller_signing_seed,
            &self.authority_signing_seed,
            &self.runtime_signing_seed,
        ];
        if seeds.iter().any(|seed| bytes_are_zero(*seed))
            || seeds[0] == seeds[1]
            || seeds[0] == seeds[2]
            || seeds[1] == seeds[2]
            || self.provider_configuration_digest != expected_provider_digest(self.provider_ref)?
        {
            return Err(IdentityManifestError::InvalidManifestField);
        }
        let identities = self.identities();
        if identities.iter().any(|identity| bytes_are_zero(*identity)) {
            return Err(IdentityManifestError::InvalidManifestField);
        }
        for (index, identity) in identities.iter().enumerate() {
            if identities[index + 1..].contains(identity) {
                return Err(IdentityManifestError::InvalidManifestField);
            }
        }
        Ok(())
    }

    fn identities(&self) -> [&[u8; 16]; IDENTITY_FIELD_COUNT] {
        [
            self.manifest_instance_id(),
            self.controller_instance_id(),
            self.authority_instance_id(),
            self.runtime_instance_id(),
            self.source_scope_id(),
            self.source_plan_id(),
            self.fabric_service_id(),
            self.agent_service_id(),
            self.submit_binding_id(),
            self.control_binding_id(),
            self.provider_ref(),
            self.deck_run_id(),
            self.session_id(),
        ]
    }
}

impl DeveloperNodeIdentityManifestV1 {
    pub(crate) const fn runtime_response_signing_seed(&self) -> &[u8; 32] {
        &self.runtime_response_signing_seed
    }

    pub(crate) const fn pxnb_reference_token(&self) -> &[u8; 32] {
        &self.pxnb_reference_token
    }

    pub(crate) const fn manifest_instance_id(&self) -> &[u8; 16] {
        &self.manifest_instance_id
    }

    pub(crate) const fn node_id(&self) -> &[u8; 16] {
        &self.node_id
    }

    pub(crate) const fn node_principal(&self) -> &[u8; 16] {
        &self.node_principal
    }

    pub(crate) const fn node_incarnation(&self) -> &[u8; 16] {
        &self.node_incarnation
    }

    pub(crate) const fn node_management_endpoint_ref(&self) -> &[u8; 16] {
        &self.node_management_endpoint_ref
    }

    pub(crate) const fn config_commitment(&self) -> &[u8; 32] {
        &self.config_commitment
    }

    fn try_generate(
        config_commitment: [u8; 32],
        controller_verification_key: [u8; 32],
        tenure_verification_key: [u8; 32],
        entropy: &mut impl EntropySource,
    ) -> Result<Self, IdentityManifestError> {
        let mut bytes = SensitiveNodeEntropy::zeroed();
        entropy.fill(&mut bytes.0)?;
        let mut cursor = ByteCursor::new(&bytes.0);
        let manifest = Self {
            runtime_response_signing_seed: cursor.array(),
            pxnb_reference_token: cursor.array(),
            manifest_instance_id: cursor.array(),
            node_id: cursor.array(),
            node_principal: cursor.array(),
            node_incarnation: cursor.array(),
            node_management_endpoint_ref: cursor.array(),
            config_commitment,
        };
        debug_assert_eq!(cursor.remaining(), 0);
        manifest
            .validate(
                config_commitment,
                controller_verification_key,
                tenure_verification_key,
            )
            .map_err(|_| IdentityManifestError::InvalidFreshEntropy)?;
        Ok(manifest)
    }

    fn encode(&self) -> SensitiveNodeWire {
        let mut wire = SensitiveNodeWire::zeroed();
        wire.0[0..4].copy_from_slice(NODE_MANIFEST_MAGIC);
        wire.0[4..6].copy_from_slice(&NODE_MANIFEST_VERSION.to_be_bytes());
        wire.0[6..8].copy_from_slice(
            &u16::try_from(NODE_MANIFEST_HEADER_BYTES)
                .expect("node manifest header width fits u16")
                .to_be_bytes(),
        );
        wire.0[8..12].copy_from_slice(
            &u32::try_from(NODE_MANIFEST_WIRE_BYTES)
                .expect("node manifest wire width fits u32")
                .to_be_bytes(),
        );
        wire.0[12..14].copy_from_slice(&NODE_MANIFEST_FIELD_COUNT.to_be_bytes());
        wire.0[14..16].copy_from_slice(&NODE_MANIFEST_FLAGS.to_be_bytes());

        let mut cursor = NODE_MANIFEST_HEADER_BYTES;
        for field in [
            self.runtime_response_signing_seed(),
            self.pxnb_reference_token(),
        ] {
            put_bytes(&mut wire.0, &mut cursor, field);
        }
        for field in self.identity_fields() {
            put_bytes(&mut wire.0, &mut cursor, field);
        }
        put_bytes(&mut wire.0, &mut cursor, self.config_commitment());
        debug_assert_eq!(cursor, NODE_MANIFEST_CHECKSUM_OFFSET);
        let checksum = node_manifest_checksum(&wire.0[..NODE_MANIFEST_CHECKSUM_OFFSET]);
        wire.0[NODE_MANIFEST_CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        wire
    }

    fn decode(
        bytes: &[u8],
        expected_config_commitment: [u8; 32],
        controller_verification_key: [u8; 32],
        tenure_verification_key: [u8; 32],
    ) -> Result<Self, IdentityManifestError> {
        if bytes.len() != NODE_MANIFEST_WIRE_BYTES {
            return Err(IdentityManifestError::InvalidManifestLength);
        }
        if &bytes[0..4] != NODE_MANIFEST_MAGIC {
            return Err(IdentityManifestError::InvalidManifestMagic);
        }
        if read_u16(bytes, 4) != NODE_MANIFEST_VERSION {
            return Err(IdentityManifestError::UnsupportedManifestVersion);
        }
        if usize::from(read_u16(bytes, 6)) != NODE_MANIFEST_HEADER_BYTES
            || usize::try_from(read_u32(bytes, 8)).ok() != Some(NODE_MANIFEST_WIRE_BYTES)
            || read_u16(bytes, 12) != NODE_MANIFEST_FIELD_COUNT
            || read_u16(bytes, 14) != NODE_MANIFEST_FLAGS
        {
            return Err(IdentityManifestError::InvalidManifestHeader);
        }
        let expected_checksum = node_manifest_checksum(&bytes[..NODE_MANIFEST_CHECKSUM_OFFSET]);
        if bytes[NODE_MANIFEST_CHECKSUM_OFFSET..] != expected_checksum {
            return Err(IdentityManifestError::ManifestChecksumMismatch);
        }
        let mut cursor =
            ByteCursor::new(&bytes[NODE_MANIFEST_HEADER_BYTES..NODE_MANIFEST_CHECKSUM_OFFSET]);
        let manifest = Self {
            runtime_response_signing_seed: cursor.array(),
            pxnb_reference_token: cursor.array(),
            manifest_instance_id: cursor.array(),
            node_id: cursor.array(),
            node_principal: cursor.array(),
            node_incarnation: cursor.array(),
            node_management_endpoint_ref: cursor.array(),
            config_commitment: cursor.array(),
        };
        debug_assert_eq!(cursor.remaining(), 0);
        manifest.validate(
            expected_config_commitment,
            controller_verification_key,
            tenure_verification_key,
        )?;
        if manifest.encode().as_bytes() != bytes {
            return Err(IdentityManifestError::InvalidManifestField);
        }
        Ok(manifest)
    }

    fn validate(
        &self,
        expected_config_commitment: [u8; 32],
        controller_verification_key: [u8; 32],
        tenure_verification_key: [u8; 32],
    ) -> Result<(), IdentityManifestError> {
        let secrets = [
            self.runtime_response_signing_seed(),
            self.pxnb_reference_token(),
        ];
        let runtime_verification_key = SigningKey::from_bytes(self.runtime_response_signing_seed())
            .verifying_key()
            .to_bytes();
        if !all_nonzero_and_distinct(&secrets)
            || !all_nonzero_and_distinct(&self.identity_fields())
            || bytes_are_zero(self.config_commitment())
            || self.config_commitment != expected_config_commitment
            || runtime_verification_key == controller_verification_key
            || runtime_verification_key == tenure_verification_key
        {
            return Err(IdentityManifestError::InvalidManifestField);
        }
        Ok(())
    }

    fn identity_fields(&self) -> [&[u8; 16]; NODE_IDENTITY_FIELD_COUNT] {
        [
            self.manifest_instance_id(),
            self.node_id(),
            self.node_principal(),
            self.node_incarnation(),
            self.node_management_endpoint_ref(),
        ]
    }
}

impl DistributedDeveloperLocalTargetIdentityV1 {
    fn from_cursor(cursor: &mut ByteCursor<'_>) -> Self {
        Self {
            runtime_response_signing_seed: cursor.array(),
            pxnb_reference_token: cursor.array(),
            pxob_observation_token: cursor.array(),
            installation_id: cursor.array(),
            runtime_target: cursor.array(),
            fabric_service_id: cursor.array(),
            agent_service_id: cursor.array(),
            submit_binding_id: cursor.array(),
            control_binding_id: cursor.array(),
            deck_run_id: cursor.array(),
            session_id: cursor.array(),
            node_id: cursor.array(),
            node_principal: cursor.array(),
            node_incarnation: cursor.array(),
            node_management_endpoint_ref: cursor.array(),
            runtime_observation_endpoint_ref: cursor.array(),
            runtime_apply_endpoint_ref: cursor.array(),
            transport_profile_ref: cursor.array(),
            controller_connector_credential_ref: cursor.array(),
            runtime_listener_credential_ref: cursor.array(),
            fabric_peer_identity_ref: cursor.array(),
            evidence_store_epoch: cursor.array(),
            evidence_owner_ref: cursor.array(),
            registration_epoch: cursor.u64(),
            endpoint_generation: cursor.u64(),
        }
    }

    pub(crate) const fn runtime_response_signing_seed(&self) -> &[u8; 32] {
        &self.runtime_response_signing_seed
    }

    pub(crate) const fn pxnb_reference_token(&self) -> &[u8; 32] {
        &self.pxnb_reference_token
    }

    pub(crate) const fn pxob_observation_token(&self) -> &[u8; 32] {
        &self.pxob_observation_token
    }

    pub(crate) const fn installation_id(&self) -> &[u8; 16] {
        &self.installation_id
    }

    pub(crate) const fn runtime_target(&self) -> &[u8; 16] {
        &self.runtime_target
    }

    pub(crate) const fn fabric_service_id(&self) -> &[u8; 16] {
        &self.fabric_service_id
    }

    pub(crate) const fn agent_service_id(&self) -> &[u8; 16] {
        &self.agent_service_id
    }

    pub(crate) const fn submit_binding_id(&self) -> &[u8; 16] {
        &self.submit_binding_id
    }

    pub(crate) const fn control_binding_id(&self) -> &[u8; 16] {
        &self.control_binding_id
    }

    pub(crate) const fn deck_run_id(&self) -> &[u8; 16] {
        &self.deck_run_id
    }

    pub(crate) const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub(crate) const fn node_id(&self) -> &[u8; 16] {
        &self.node_id
    }

    pub(crate) const fn node_principal(&self) -> &[u8; 16] {
        &self.node_principal
    }

    pub(crate) const fn node_incarnation(&self) -> &[u8; 16] {
        &self.node_incarnation
    }

    pub(crate) const fn node_management_endpoint_ref(&self) -> &[u8; 16] {
        &self.node_management_endpoint_ref
    }

    pub(crate) const fn runtime_observation_endpoint_ref(&self) -> &[u8; 16] {
        &self.runtime_observation_endpoint_ref
    }

    pub(crate) const fn runtime_apply_endpoint_ref(&self) -> &[u8; 16] {
        &self.runtime_apply_endpoint_ref
    }

    pub(crate) const fn transport_profile_ref(&self) -> &[u8; 16] {
        &self.transport_profile_ref
    }

    pub(crate) const fn controller_connector_credential_ref(&self) -> &[u8; 16] {
        &self.controller_connector_credential_ref
    }

    pub(crate) const fn runtime_listener_credential_ref(&self) -> &[u8; 16] {
        &self.runtime_listener_credential_ref
    }

    pub(crate) const fn fabric_peer_identity_ref(&self) -> &[u8; 16] {
        &self.fabric_peer_identity_ref
    }

    pub(crate) const fn evidence_store_epoch(&self) -> &[u8; 16] {
        &self.evidence_store_epoch
    }

    pub(crate) const fn evidence_owner_ref(&self) -> &[u8; 16] {
        &self.evidence_owner_ref
    }

    pub(crate) const fn registration_epoch(&self) -> u64 {
        self.registration_epoch
    }

    pub(crate) const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation
    }

    fn secret_fields(&self) -> [&[u8; 32]; DISTRIBUTED_TARGET_SECRET_FIELD_COUNT] {
        [
            self.runtime_response_signing_seed(),
            self.pxnb_reference_token(),
            self.pxob_observation_token(),
        ]
    }

    fn identity_fields(&self) -> [&[u8; 16]; DISTRIBUTED_TARGET_IDENTITY_FIELD_COUNT] {
        [
            self.installation_id(),
            self.runtime_target(),
            self.fabric_service_id(),
            self.agent_service_id(),
            self.submit_binding_id(),
            self.control_binding_id(),
            self.deck_run_id(),
            self.session_id(),
            self.node_id(),
            self.node_principal(),
            self.node_incarnation(),
            self.node_management_endpoint_ref(),
            self.runtime_observation_endpoint_ref(),
            self.runtime_apply_endpoint_ref(),
            self.transport_profile_ref(),
            self.controller_connector_credential_ref(),
            self.runtime_listener_credential_ref(),
            self.fabric_peer_identity_ref(),
            self.evidence_store_epoch(),
            self.evidence_owner_ref(),
        ]
    }

    fn encode_into(&self, destination: &mut [u8], cursor: &mut usize) {
        for field in self.secret_fields() {
            put_bytes(destination, cursor, field);
        }
        for field in self.identity_fields() {
            put_bytes(destination, cursor, field);
        }
        put_bytes(
            destination,
            cursor,
            &self.registration_epoch().to_be_bytes(),
        );
        put_bytes(
            destination,
            cursor,
            &self.endpoint_generation().to_be_bytes(),
        );
    }
}

impl DistributedDeveloperLocalIdentityManifestV1 {
    pub(crate) const fn manifest_instance_id(&self) -> &[u8; 16] {
        &self.manifest_instance_id
    }

    pub(crate) const fn controller_signing_seed(&self) -> &[u8; 32] {
        &self.controller_signing_seed
    }

    pub(crate) const fn authority_signing_seed(&self) -> &[u8; 32] {
        &self.authority_signing_seed
    }

    pub(crate) const fn controller_instance_id(&self) -> &[u8; 16] {
        &self.controller_instance_id
    }

    pub(crate) const fn authority_instance_id(&self) -> &[u8; 16] {
        &self.authority_instance_id
    }

    pub(crate) const fn source_scope_id(&self) -> &[u8; 16] {
        &self.source_scope_id
    }

    pub(crate) const fn source_plan_id(&self) -> &[u8; 16] {
        &self.source_plan_id
    }

    pub(crate) const fn provider_ref(&self) -> &[u8; 16] {
        &self.provider_ref
    }

    pub(crate) const fn enrollment_issuer_ref(&self) -> &[u8; 16] {
        &self.enrollment_issuer_ref
    }

    pub(crate) const fn transport_trust_domain_ref(&self) -> &[u8; 16] {
        &self.transport_trust_domain_ref
    }

    pub(crate) const fn transport_trust_anchor_ref(&self) -> &[u8; 16] {
        &self.transport_trust_anchor_ref
    }

    pub(crate) const fn provider_configuration_digest(&self) -> &[u8; 32] {
        &self.provider_configuration_digest
    }

    pub(crate) const fn target(
        &self,
        target: DistributedDeveloperLocalTargetV1,
    ) -> &DistributedDeveloperLocalTargetIdentityV1 {
        &self.targets[target.index()]
    }

    /// Returns the only admitted input to Deployment's existing derivation
    /// authority for one target. Callers must not reproduce derived identity
    /// domains in the composition root.
    pub(crate) fn developer_fixture_identity_seed(
        &self,
        target: DistributedDeveloperLocalTargetV1,
    ) -> DeveloperFixtureIdentitySeedV1 {
        let target = self.target(target);
        DeveloperFixtureIdentitySeedV1 {
            manifest_instance_id: *target.installation_id(),
            controller_instance_id: *self.controller_instance_id(),
            authority_instance_id: *self.authority_instance_id(),
            runtime_instance_id: *target.runtime_target(),
            source_scope_id: *self.source_scope_id(),
            source_plan_id: *self.source_plan_id(),
            fabric_service_id: *target.fabric_service_id(),
            agent_service_id: *target.agent_service_id(),
            submit_binding_id: *target.submit_binding_id(),
            control_binding_id: *target.control_binding_id(),
            provider_ref: *self.provider_ref(),
            deck_run_id: *target.deck_run_id(),
            session_id: *target.session_id(),
            provider_configuration_digest: *self.provider_configuration_digest(),
        }
    }

    pub(crate) fn developer_fixture_derived_identity(
        &self,
        target: DistributedDeveloperLocalTargetV1,
    ) -> Result<DeveloperFixtureDerivedIdentityV1, IdentityManifestError> {
        DeveloperFixtureDerivedIdentityV1::try_from_seed(
            self.developer_fixture_identity_seed(target),
        )
        .map_err(|_| IdentityManifestError::InvalidManifestField)
    }

    fn try_generate(entropy: &mut impl EntropySource) -> Result<Self, IdentityManifestError> {
        let mut bytes = SensitiveDistributedEntropy::zeroed();
        entropy.fill(&mut bytes.0)?;
        let mut cursor = ByteCursor::new(&bytes.0);
        let controller_signing_seed = cursor.array();
        let authority_signing_seed = cursor.array();
        let manifest_instance_id = cursor.array();
        let controller_instance_id = cursor.array();
        let authority_instance_id = cursor.array();
        let source_scope_id = cursor.array();
        let source_plan_id = cursor.array();
        let provider_ref = cursor.array();
        let enrollment_issuer_ref = cursor.array();
        let transport_trust_domain_ref = cursor.array();
        let transport_trust_anchor_ref = cursor.array();
        let mut targets = [
            DistributedDeveloperLocalTargetIdentityV1::from_cursor(&mut cursor),
            DistributedDeveloperLocalTargetIdentityV1::from_cursor(&mut cursor),
        ];
        if targets[0].runtime_target() > targets[1].runtime_target() {
            targets.swap(0, 1);
        }
        let manifest = Self {
            controller_signing_seed,
            authority_signing_seed,
            manifest_instance_id,
            controller_instance_id,
            authority_instance_id,
            source_scope_id,
            source_plan_id,
            provider_ref,
            enrollment_issuer_ref,
            transport_trust_domain_ref,
            transport_trust_anchor_ref,
            provider_configuration_digest: deterministic_provider_configuration_digest(),
            targets,
        };
        debug_assert_eq!(cursor.remaining(), 0);
        manifest.validate_fresh()?;
        Ok(manifest)
    }

    fn encode(&self) -> SensitiveDistributedWire {
        let mut wire = SensitiveDistributedWire::zeroed();
        wire.0[0..4].copy_from_slice(DISTRIBUTED_MANIFEST_MAGIC);
        wire.0[4..6].copy_from_slice(&DISTRIBUTED_MANIFEST_VERSION.to_be_bytes());
        wire.0[6..8].copy_from_slice(
            &u16::try_from(DISTRIBUTED_MANIFEST_HEADER_BYTES)
                .expect("distributed manifest header width fits u16")
                .to_be_bytes(),
        );
        wire.0[8..12].copy_from_slice(
            &u32::try_from(DISTRIBUTED_MANIFEST_WIRE_BYTES)
                .expect("distributed manifest wire width fits u32")
                .to_be_bytes(),
        );
        wire.0[12..14].copy_from_slice(&DISTRIBUTED_MANIFEST_FIELD_COUNT.to_be_bytes());
        wire.0[14..16].copy_from_slice(&DISTRIBUTED_MANIFEST_FLAGS.to_be_bytes());

        let mut cursor = DISTRIBUTED_MANIFEST_HEADER_BYTES;
        for field in [
            self.controller_signing_seed(),
            self.authority_signing_seed(),
        ] {
            put_bytes(&mut wire.0, &mut cursor, field);
        }
        for field in self.shared_identity_fields() {
            put_bytes(&mut wire.0, &mut cursor, field);
        }
        put_bytes(
            &mut wire.0,
            &mut cursor,
            self.provider_configuration_digest(),
        );
        for target in &self.targets {
            target.encode_into(&mut wire.0, &mut cursor);
        }
        debug_assert_eq!(cursor, DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET);
        let checksum =
            distributed_manifest_checksum(&wire.0[..DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET]);
        wire.0[DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        wire
    }

    fn decode(bytes: &[u8]) -> Result<Self, IdentityManifestError> {
        if bytes.len() >= 6
            && &bytes[0..4] == DISTRIBUTED_MANIFEST_MAGIC
            && read_u16(bytes, 4) != DISTRIBUTED_MANIFEST_VERSION
        {
            return Err(IdentityManifestError::UnsupportedManifestVersion);
        }
        if bytes.len() != DISTRIBUTED_MANIFEST_WIRE_BYTES {
            return Err(IdentityManifestError::InvalidManifestLength);
        }
        if &bytes[0..4] != DISTRIBUTED_MANIFEST_MAGIC {
            return Err(IdentityManifestError::InvalidManifestMagic);
        }
        if read_u16(bytes, 4) != DISTRIBUTED_MANIFEST_VERSION {
            return Err(IdentityManifestError::UnsupportedManifestVersion);
        }
        if usize::from(read_u16(bytes, 6)) != DISTRIBUTED_MANIFEST_HEADER_BYTES
            || usize::try_from(read_u32(bytes, 8)).ok() != Some(DISTRIBUTED_MANIFEST_WIRE_BYTES)
            || read_u16(bytes, 12) != DISTRIBUTED_MANIFEST_FIELD_COUNT
            || read_u16(bytes, 14) != DISTRIBUTED_MANIFEST_FLAGS
        {
            return Err(IdentityManifestError::InvalidManifestHeader);
        }
        let expected_checksum =
            distributed_manifest_checksum(&bytes[..DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET]);
        if bytes[DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET..] != expected_checksum {
            return Err(IdentityManifestError::ManifestChecksumMismatch);
        }

        let mut cursor = ByteCursor::new(
            &bytes[DISTRIBUTED_MANIFEST_HEADER_BYTES..DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET],
        );
        let manifest = Self {
            controller_signing_seed: cursor.array(),
            authority_signing_seed: cursor.array(),
            manifest_instance_id: cursor.array(),
            controller_instance_id: cursor.array(),
            authority_instance_id: cursor.array(),
            source_scope_id: cursor.array(),
            source_plan_id: cursor.array(),
            provider_ref: cursor.array(),
            enrollment_issuer_ref: cursor.array(),
            transport_trust_domain_ref: cursor.array(),
            transport_trust_anchor_ref: cursor.array(),
            provider_configuration_digest: cursor.array(),
            targets: [
                DistributedDeveloperLocalTargetIdentityV1::from_cursor(&mut cursor),
                DistributedDeveloperLocalTargetIdentityV1::from_cursor(&mut cursor),
            ],
        };
        debug_assert_eq!(cursor.remaining(), 0);
        manifest.validate_durable()?;
        if manifest.encode().as_bytes() != bytes {
            return Err(IdentityManifestError::InvalidManifestField);
        }
        Ok(manifest)
    }

    fn validate_fresh(&self) -> Result<(), IdentityManifestError> {
        self.validate_durable()
            .map_err(|_| IdentityManifestError::InvalidFreshEntropy)
    }

    fn validate_durable(&self) -> Result<(), IdentityManifestError> {
        let shared_secrets = [
            self.controller_signing_seed(),
            self.authority_signing_seed(),
        ];
        let target_a = self.target(DistributedDeveloperLocalTargetV1::A);
        let target_b = self.target(DistributedDeveloperLocalTargetV1::B);
        let target_a_secrets = target_a.secret_fields();
        let target_b_secrets = target_b.secret_fields();
        let secrets = [
            shared_secrets[0],
            shared_secrets[1],
            target_a_secrets[0],
            target_a_secrets[1],
            target_a_secrets[2],
            target_b_secrets[0],
            target_b_secrets[1],
            target_b_secrets[2],
        ];
        let target_a_identities = target_a.identity_fields();
        let target_b_identities = target_b.identity_fields();
        let shared_identities = self.shared_identity_fields();
        let identity_groups: [&[&[u8; 16]]; 3] = [
            &shared_identities,
            &target_a_identities,
            &target_b_identities,
        ];
        let derived_a =
            self.developer_fixture_derived_identity(DistributedDeveloperLocalTargetV1::A)?;
        let derived_b =
            self.developer_fixture_derived_identity(DistributedDeveloperLocalTargetV1::B)?;
        if !all_nonzero_and_distinct(&secrets)
            || !all_nonzero_and_distinct_groups(&identity_groups)
            || self.provider_configuration_digest()
                != &deterministic_provider_configuration_digest()
            || target_a.runtime_target() >= target_b.runtime_target()
            || target_a.node_id() == target_b.node_id()
            || target_a.node_incarnation() == target_b.node_incarnation()
            || target_a.node_management_endpoint_ref() == target_b.node_management_endpoint_ref()
            || derived_a.writer() != derived_b.writer()
            || derived_a.controller_principal() != derived_b.controller_principal()
            || derived_a.controller_key_ref() != derived_b.controller_key_ref()
            || derived_a.authority_principal() != derived_b.authority_principal()
            || derived_a.authority_ref() != derived_b.authority_ref()
            || derived_a.authority_key_ref() != derived_b.authority_key_ref()
            || derived_a.authority_service_principal() != derived_b.authority_service_principal()
            || derived_a.authority_owner() != derived_b.authority_owner()
            || derived_a.runtime_target() != *target_a.runtime_target()
            || derived_b.runtime_target() != *target_b.runtime_target()
            || derived_a.runtime_principal() == derived_b.runtime_principal()
            || derived_a.runtime_response_key_ref() == derived_b.runtime_response_key_ref()
            || derived_a.successor_store_instance_id() == derived_b.successor_store_instance_id()
            || derived_a.model_service_id() == derived_b.model_service_id()
            || target_a.registration_epoch() == 0
            || target_b.registration_epoch() == 0
            || target_a.endpoint_generation() == 0
            || target_b.endpoint_generation() == 0
        {
            return Err(IdentityManifestError::InvalidManifestField);
        }
        Ok(())
    }

    fn shared_identity_fields(&self) -> [&[u8; 16]; DISTRIBUTED_SHARED_IDENTITY_FIELD_COUNT] {
        [
            self.manifest_instance_id(),
            self.controller_instance_id(),
            self.authority_instance_id(),
            self.source_scope_id(),
            self.source_plan_id(),
            self.provider_ref(),
            self.enrollment_issuer_ref(),
            self.transport_trust_domain_ref(),
            self.transport_trust_anchor_ref(),
        ]
    }
}

fn ensure_state_root(path: &Path) -> Result<PathBuf, IdentityManifestError> {
    let expected_uid = Uid::effective().as_raw();
    let expected_gid = Gid::effective().as_raw();
    let created = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or(IdentityManifestError::InsecureStateRoot)?;
            validate_existing_path_chain(parent)?;
            let canonical_parent = fs::canonicalize(parent)?;
            if canonical_parent != parent {
                return Err(IdentityManifestError::InsecureStateRoot);
            }
            let file_name = path
                .file_name()
                .ok_or(IdentityManifestError::InsecureStateRoot)?;
            let canonical_target = canonical_parent.join(file_name);
            if canonical_target != path {
                return Err(IdentityManifestError::InsecureStateRoot);
            }
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(&canonical_target)?;
            chown(&canonical_target, None, Some(Gid::from_raw(expected_gid)))
                .map_err(|_| IdentityManifestError::InsecureStateRoot)?;
            fs::set_permissions(&canonical_target, fs::Permissions::from_mode(0o700))?;
            validate_existing_path_chain(&canonical_target)?;
            sync_directory(&canonical_parent)?;
            true
        }
        Err(error) => return Err(error.into()),
    };
    validate_existing_path_chain(path)?;
    let requested_metadata = fs::symlink_metadata(path)?;
    validate_private_directory(&requested_metadata, expected_uid, expected_gid)
        .map_err(|_| IdentityManifestError::InsecureStateRoot)?;
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(IdentityManifestError::InsecureStateRoot);
    }
    let canonical_metadata = fs::symlink_metadata(&canonical)?;
    if !same_file(&requested_metadata, &canonical_metadata) {
        return Err(IdentityManifestError::InsecureStateRoot);
    }
    if created {
        sync_directory(existing_parent(&canonical))?;
    }
    Ok(canonical)
}

fn open_existing_state_root(path: &Path) -> Result<PathBuf, IdentityManifestError> {
    let expected_uid = Uid::effective().as_raw();
    let expected_gid = Gid::effective().as_raw();
    let requested_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(IdentityManifestError::DistributedManifestNotInitialized);
        }
        Err(error) => return Err(error.into()),
    };
    validate_existing_path_chain(path)?;
    validate_private_directory(&requested_metadata, expected_uid, expected_gid)
        .map_err(|_| IdentityManifestError::InsecureStateRoot)?;
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(IdentityManifestError::InsecureStateRoot);
    }
    let canonical_metadata = fs::symlink_metadata(&canonical)?;
    if !same_file(&requested_metadata, &canonical_metadata) {
        return Err(IdentityManifestError::InsecureStateRoot);
    }
    Ok(canonical)
}

fn validate_existing_path_chain(path: &Path) -> Result<(), IdentityManifestError> {
    if !path.is_absolute() {
        return Err(IdentityManifestError::InsecureStateRoot);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() {
                    return Err(IdentityManifestError::InsecureStateRoot);
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(IdentityManifestError::InsecureStateRoot);
            }
        }
    }
    Ok(())
}

fn ensure_identity_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), IdentityManifestError> {
    let created = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(path)?;
            chown(path, None, Some(Gid::from_raw(expected_gid)))
                .map_err(|_| IdentityManifestError::InsecureIdentityDirectory)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            true
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = fs::symlink_metadata(path)?;
    validate_private_directory(&metadata, expected_uid, expected_gid)
        .map_err(|_| IdentityManifestError::InsecureIdentityDirectory)?;
    if created {
        sync_directory(existing_parent(path))?;
    }
    Ok(())
}

fn validate_existing_identity_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), IdentityManifestError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(IdentityManifestError::DistributedManifestNotInitialized);
        }
        Err(error) => return Err(error.into()),
    };
    validate_private_directory(&metadata, expected_uid, expected_gid)
        .map_err(|_| IdentityManifestError::InsecureIdentityDirectory)
}

fn validate_private_directory(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), ()> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(());
    }
    Ok(())
}

/// Serializes profile selection on the canonical state-root inode itself.
/// This closes the cross-profile first-open race without adding a migration
/// marker or changing any PXLI/PXOI/PXDI manifest path.
fn acquire_identity_profile_lock(
    state_root: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<File, IdentityManifestError> {
    let before =
        fs::symlink_metadata(state_root).map_err(|_| IdentityManifestError::InsecureProfileLock)?;
    validate_private_directory(&before, expected_uid, expected_gid)
        .map_err(|_| IdentityManifestError::InsecureProfileLock)?;
    let directory =
        File::open(state_root).map_err(|_| IdentityManifestError::InsecureProfileLock)?;
    let opened = directory
        .metadata()
        .map_err(|_| IdentityManifestError::InsecureProfileLock)?;
    let after =
        fs::symlink_metadata(state_root).map_err(|_| IdentityManifestError::InsecureProfileLock)?;
    for metadata in [&opened, &after] {
        validate_private_directory(metadata, expected_uid, expected_gid)
            .map_err(|_| IdentityManifestError::InsecureProfileLock)?;
    }
    if !same_file(&before, &opened) || !same_file(&opened, &after) {
        return Err(IdentityManifestError::InsecureProfileLock);
    }
    match directory.try_lock() {
        Ok(()) => Ok(directory),
        Err(TryLockError::WouldBlock) => Err(IdentityManifestError::ProfileLockContended),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

fn acquire_writer_lock(
    paths: &IdentityPaths,
    expected_uid: u32,
    access: IdentityManifestAccessV1,
) -> Result<(File, bool), IdentityManifestError> {
    let (writer_lock, created) = match fs::symlink_metadata(&paths.writer_lock) {
        Ok(_) => (
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&paths.writer_lock)?,
            false,
        ),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && matches!(access, IdentityManifestAccessV1::Initialize) =>
        {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&paths.writer_lock)
            {
                Ok(file) => {
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                    (file, true)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(IdentityManifestError::WriterLockContended);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(IdentityManifestError::InsecureWriterLock);
        }
        Err(error) => return Err(error.into()),
    };
    validate_open_file(
        &paths.writer_lock,
        &writer_lock,
        expected_uid,
        None,
        IdentityManifestError::InsecureWriterLock,
    )?;
    match writer_lock.try_lock() {
        Ok(()) => Ok((writer_lock, created)),
        Err(TryLockError::WouldBlock) => Err(IdentityManifestError::WriterLockContended),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

fn validate_identity_entries(paths: &IdentityPaths) -> Result<(), IdentityManifestError> {
    let manifest_name = paths
        .manifest
        .file_name()
        .ok_or(IdentityManifestError::UnexpectedIdentityEntry)?;
    let temporary_name = paths
        .temporary
        .file_name()
        .ok_or(IdentityManifestError::UnexpectedIdentityEntry)?;
    for entry in fs::read_dir(&paths.directory)? {
        let name = entry?.file_name();
        if name != manifest_name
            && name != temporary_name
            && name != OsStr::new(WRITER_LOCK_FILE_NAME)
        {
            return Err(IdentityManifestError::UnexpectedIdentityEntry);
        }
    }
    Ok(())
}

fn publish_manifest_wire(
    paths: &IdentityPaths,
    expected_uid: u32,
    wire: &[u8],
) -> Result<(), IdentityManifestError> {
    match fs::symlink_metadata(&paths.manifest) {
        Ok(_) => return Err(IdentityManifestError::PublicationConflict),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::symlink_metadata(&paths.temporary) {
        Ok(_) => return Err(IdentityManifestError::StalePublication),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let mut temporary = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&paths.temporary)?;
    temporary.set_permissions(fs::Permissions::from_mode(0o600))?;
    validate_open_file(
        &paths.temporary,
        &temporary,
        expected_uid,
        Some(0),
        IdentityManifestError::InsecureManifest,
    )?;
    temporary.write_all(wire)?;
    temporary.sync_all()?;
    validate_open_file(
        &paths.temporary,
        &temporary,
        expected_uid,
        Some(u64::try_from(wire.len()).map_err(|_| IdentityManifestError::InvalidManifestLength)?),
        IdentityManifestError::InsecureManifest,
    )?;
    drop(temporary);

    match fs::symlink_metadata(&paths.manifest) {
        Ok(_) => return Err(IdentityManifestError::PublicationConflict),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::rename(&paths.temporary, &paths.manifest)
        .map_err(|_| IdentityManifestError::PublicationOutcomeUncertain)?;
    sync_directory(&paths.directory)
        .map_err(|_| IdentityManifestError::PublicationOutcomeUncertain)?;
    Ok(())
}

fn read_identity_manifest<M, D>(
    path: &Path,
    expected_uid: u32,
    expected_wire_bytes: usize,
    decode: &D,
) -> Result<M, IdentityManifestError>
where
    D: Fn(&[u8]) -> Result<M, IdentityManifestError>,
{
    let expected_length = u64::try_from(expected_wire_bytes)
        .map_err(|_| IdentityManifestError::InvalidManifestLength)?;
    let mut file = OpenOptions::new().read(true).open(path)?;
    validate_open_file(
        path,
        &file,
        expected_uid,
        Some(expected_length),
        IdentityManifestError::InsecureManifest,
    )?;
    let mut wire = Zeroizing::new(vec![0_u8; expected_wire_bytes]);
    file.read_exact(wire.as_mut_slice()).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            IdentityManifestError::InvalidManifestLength
        } else {
            error.into()
        }
    })?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(IdentityManifestError::InvalidManifestLength);
    }
    validate_open_file(
        path,
        &file,
        expected_uid,
        Some(expected_length),
        IdentityManifestError::InsecureManifest,
    )?;
    decode(wire.as_slice())
}

fn validate_open_file(
    path: &Path,
    file: &File,
    expected_uid: u32,
    expected_length: Option<u64>,
    failure: IdentityManifestError,
) -> Result<(), IdentityManifestError> {
    let before = fs::symlink_metadata(path).map_err(|_| failure)?;
    let opened = file.metadata().map_err(|_| failure)?;
    let after = fs::symlink_metadata(path).map_err(|_| failure)?;
    for metadata in [&before, &opened, &after] {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != expected_uid
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || expected_length.is_some_and(|length| metadata.len() != length)
        {
            return Err(failure);
        }
    }
    if !same_file(&before, &opened) || !same_file(&opened, &after) {
        return Err(failure);
    }
    Ok(())
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn manifest_checksum(profile: IdentityProviderProfileV1, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(profile.checksum_domain());
    digest.update(MANIFEST_VERSION.to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn distributed_manifest_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DISTRIBUTED_MANIFEST_CHECKSUM_DOMAIN);
    digest.update(DISTRIBUTED_MANIFEST_VERSION.to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn node_manifest_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(NODE_MANIFEST_CHECKSUM_DOMAIN);
    digest.update(NODE_MANIFEST_VERSION.to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn deterministic_provider_configuration_digest() -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DETERMINISTIC_PROVIDER_CONFIG_DOMAIN);
    digest.update(DETERMINISTIC_PROVIDER_PROFILE);
    digest.finalize().into()
}

fn put_bytes(destination: &mut [u8], cursor: &mut usize, value: &[u8]) {
    let end = *cursor + value.len();
    destination[*cursor..end].copy_from_slice(value);
    *cursor = end;
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(copy_array(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(copy_array(bytes, offset))
}

fn copy_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn all_nonzero_and_distinct<const WIDTH: usize, const COUNT: usize>(
    fields: &[&[u8; WIDTH]; COUNT],
) -> bool {
    if fields.iter().any(|field| bytes_are_zero(*field)) {
        return false;
    }
    for (index, field) in fields.iter().enumerate() {
        if fields[index + 1..].contains(field) {
            return false;
        }
    }
    true
}

fn all_nonzero_and_distinct_groups<const WIDTH: usize>(groups: &[&[&[u8; WIDTH]]]) -> bool {
    for (group_index, group) in groups.iter().enumerate() {
        for (field_index, field) in group.iter().enumerate() {
            if bytes_are_zero(*field)
                || group[field_index + 1..].contains(field)
                || groups[group_index + 1..]
                    .iter()
                    .any(|later| later.contains(field))
            {
                return false;
            }
        }
    }
    true
}

fn sync_directory(path: &Path) -> Result<(), IdentityManifestError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn existing_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let value = copy_array(self.bytes, self.offset);
        self.offset += N;
        value
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

#[cfg(test)]
fn load_or_create_with_entropy(
    config: &DeveloperFixtureConfigV1,
    entropy: &mut impl EntropySource,
) -> Result<IdentityManifestV1, IdentityManifestError> {
    load_or_create_inner(config, entropy)
}

#[cfg(test)]
fn load_or_create_node_with_entropy(
    config: &DeveloperNodeConfigV1,
    entropy: &mut impl EntropySource,
) -> Result<DeveloperNodeIdentityManifestV1, IdentityManifestError> {
    load_or_create_node_inner(config, entropy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
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
                "paraegox-local-identity-test-{}-{sequence}",
                std::process::id()
            ));
            assert!(!path.exists(), "test state root unexpectedly exists");
            Self { path }
        }

        fn config(&self) -> DeveloperFixtureConfigV1 {
            let state_root = self.path.to_str().expect("UTF-8 test state root");
            let document = format!(
                "schema_version = 1\nstate_root = {state_root:?}\nfabric_listen = \"tcp/127.0.0.1:7447\"\n\n[model]\nprovider = \"deterministic-echo-v1\"\n"
            );
            match crate::config::parse_chat_config_toml_for_test(&document).expect("test config") {
                crate::config::Command::DeveloperFixtureV1(config) => config,
                crate::config::Command::DeveloperNodeV1(_)
                | crate::config::Command::DeveloperProvisionedV1(_) => {
                    panic!("unexpected provisioned command")
                }
                crate::config::Command::DeveloperDistributedFixtureV1(_) => {
                    panic!("unexpected distributed fixture command")
                }
                crate::config::Command::Help => panic!("unexpected help"),
            }
        }

        fn provisioned_config(
            &self,
            provider: &str,
            model: &str,
            secret_ref: &str,
        ) -> DeveloperProvisionedConfigV1 {
            let state_root = self.path.to_str().expect("UTF-8 test state root");
            let document = format!(
                "schema_version = 1\nstate_root = {state_root:?}\nfabric_listen = \"tcp/127.0.0.1:7447\"\n\n[model]\nprovider = {provider:?}\nmodel = {model:?}\nsecret_ref = {secret_ref:?}\n"
            );
            match crate::config::parse_chat_config_toml_for_test(&document)
                .expect("test provisioned config")
            {
                crate::config::Command::DeveloperProvisionedV1(config) => config,
                crate::config::Command::DeveloperNodeV1(_)
                | crate::config::Command::DeveloperFixtureV1(_) => {
                    panic!("unexpected fixture command")
                }
                crate::config::Command::DeveloperDistributedFixtureV1(_) => {
                    panic!("unexpected distributed fixture command")
                }
                crate::config::Command::Help => panic!("unexpected help"),
            }
        }

        fn openai_config(&self, model: &str) -> DeveloperProvisionedConfigV1 {
            self.provisioned_config("openai-responses-v1", model, "env:OPENAI_API_KEY")
        }

        fn deepseek_config(&self, model: &str) -> DeveloperProvisionedConfigV1 {
            self.provisioned_config(
                "deepseek-chat-completions-v1",
                model,
                "env:DEEPSEEK_API_KEY",
            )
        }

        fn distributed_identity_init_config(&self) -> DeveloperDistributedFixtureConfigV1 {
            let mut arguments = vec![
                OsString::from("__developer-distributed-identity-init-v1"),
                OsString::from("--state-root"),
                self.path.clone().into_os_string(),
            ];
            for (option, value) in [
                ("--fabric-listen-a", "tcp/127.0.0.1:7451"),
                ("--fabric-listen-b", "tcp/127.0.0.1:7452"),
                ("--pxrp-tls-listener-locator-a", "tls/192.0.2.10:7461"),
                ("--pxrp-route-a", "paraegox/runtime/target-a/apply"),
                (
                    "--pxrp-root-ca-certificate-file-a",
                    "/nonexistent/paraegox/pxrp-a/root-ca.pem",
                ),
                (
                    "--pxrp-controller-client-certificate-file-a",
                    "/nonexistent/paraegox/pxrp-a/controller-client.pem",
                ),
                (
                    "--pxrp-controller-client-private-key-file-a",
                    "/nonexistent/paraegox/pxrp-a/controller-client.key",
                ),
                (
                    "--pxrp-runtime-server-certificate-file-a",
                    "/nonexistent/paraegox/pxrp-a/runtime-server.pem",
                ),
                (
                    "--pxrp-runtime-server-private-key-file-a",
                    "/nonexistent/paraegox/pxrp-a/runtime-server.key",
                ),
                ("--fabric-tls-listener-locator-a", "tls/192.0.2.10:7462"),
                (
                    "--fabric-local-credential-ref-a",
                    "91919191919191919191919191919191",
                ),
                (
                    "--fabric-expected-peer-common-name-a",
                    "fabric-b.example.test",
                ),
                (
                    "--fabric-root-ca-certificate-file-a",
                    "/nonexistent/paraegox/fabric-a/root-ca.pem",
                ),
                (
                    "--fabric-listen-certificate-file-a",
                    "/nonexistent/paraegox/fabric-a/listen.pem",
                ),
                (
                    "--fabric-listen-private-key-file-a",
                    "/nonexistent/paraegox/fabric-a/listen.key",
                ),
                (
                    "--fabric-connect-certificate-file-a",
                    "/nonexistent/paraegox/fabric-a/connect.pem",
                ),
                (
                    "--fabric-connect-private-key-file-a",
                    "/nonexistent/paraegox/fabric-a/connect.key",
                ),
                ("--pxrp-tls-listener-locator-b", "tls/192.0.2.20:7461"),
                ("--pxrp-route-b", "paraegox/runtime/target-b/apply"),
                (
                    "--pxrp-root-ca-certificate-file-b",
                    "/nonexistent/paraegox/pxrp-b/root-ca.pem",
                ),
                (
                    "--pxrp-controller-client-certificate-file-b",
                    "/nonexistent/paraegox/pxrp-b/controller-client.pem",
                ),
                (
                    "--pxrp-controller-client-private-key-file-b",
                    "/nonexistent/paraegox/pxrp-b/controller-client.key",
                ),
                (
                    "--pxrp-runtime-server-certificate-file-b",
                    "/nonexistent/paraegox/pxrp-b/runtime-server.pem",
                ),
                (
                    "--pxrp-runtime-server-private-key-file-b",
                    "/nonexistent/paraegox/pxrp-b/runtime-server.key",
                ),
                ("--fabric-tls-listener-locator-b", "tls/192.0.2.20:7462"),
                (
                    "--fabric-local-credential-ref-b",
                    "92929292929292929292929292929292",
                ),
                (
                    "--fabric-expected-peer-common-name-b",
                    "fabric-a.example.test",
                ),
                (
                    "--fabric-root-ca-certificate-file-b",
                    "/nonexistent/paraegox/fabric-b/root-ca.pem",
                ),
                (
                    "--fabric-listen-certificate-file-b",
                    "/nonexistent/paraegox/fabric-b/listen.pem",
                ),
                (
                    "--fabric-listen-private-key-file-b",
                    "/nonexistent/paraegox/fabric-b/listen.key",
                ),
                (
                    "--fabric-connect-certificate-file-b",
                    "/nonexistent/paraegox/fabric-b/connect.pem",
                ),
                (
                    "--fabric-connect-private-key-file-b",
                    "/nonexistent/paraegox/fabric-b/connect.key",
                ),
            ] {
                arguments.push(OsString::from(option));
                arguments.push(OsString::from(value));
            }
            match crate::config::parse(arguments).expect("distributed identity init config") {
                crate::config::Command::DeveloperDistributedFixtureV1(config) => config,
                crate::config::Command::DeveloperNodeV1(_)
                | crate::config::Command::DeveloperFixtureV1(_) => {
                    panic!("unexpected fixture command")
                }
                crate::config::Command::DeveloperProvisionedV1(_) => {
                    panic!("unexpected provisioned command")
                }
                crate::config::Command::Help => panic!("unexpected help"),
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            assert!(self.path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("paraegox-local-identity-test-")
            }));
            if let Err(error) = fs::remove_dir_all(&self.path) {
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
        }
    }

    struct PatternEntropy {
        calls: usize,
    }

    impl PatternEntropy {
        const fn new() -> Self {
            Self { calls: 0 }
        }
    }

    impl EntropySource for PatternEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityManifestError> {
            self.calls += 1;
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte =
                    u8::try_from(((index * 73 + 19) % 251) + 1).expect("pattern byte is bounded");
            }
            Ok(())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill(&mut self, _destination: &mut [u8]) -> Result<(), IdentityManifestError> {
            Err(IdentityManifestError::EntropyUnavailable)
        }
    }

    struct ZeroEntropy;

    impl EntropySource for ZeroEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityManifestError> {
            destination.fill(0);
            Ok(())
        }
    }

    struct ControllerAliasingNodeEntropy;

    impl EntropySource for ControllerAliasingNodeEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityManifestError> {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte =
                    u8::try_from(((index * 73 + 19) % 251) + 1).expect("pattern byte is bounded");
            }
            destination[..32].fill(0x21);
            Ok(())
        }
    }

    enum TestEntropy {
        Failing(FailingEntropy),
        Zero(ZeroEntropy),
    }

    impl EntropySource for TestEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityManifestError> {
            match self {
                Self::Failing(source) => source.fill(destination),
                Self::Zero(source) => source.fill(destination),
            }
        }
    }

    #[test]
    fn node_manifest_is_private_byte_stable_and_config_pinned() {
        let directory = TestDirectory::new();
        let config = crate::config::developer_node_config_for_test(&directory.path);
        let paths = IdentityPaths::node(&directory.path);
        let mut entropy = PatternEntropy::new();
        let first = load_or_create_node_with_entropy(&config, &mut entropy)
            .expect("first node identity manifest");
        assert_eq!(entropy.calls, 1);
        assert_eq!(first.config_commitment(), &config.config_commitment());

        let metadata = fs::symlink_metadata(&paths.manifest).expect("node manifest metadata");
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), NODE_MANIFEST_WIRE_BYTES as u64);
        assert!(!paths.temporary.exists());
        let first_wire = first.encode();
        assert_eq!(&first_wire.as_bytes()[..4], NODE_MANIFEST_MAGIC);

        let reopened = load_or_create_node_with_entropy(&config, &mut FailingEntropy)
            .expect("strict node identity reopen");
        assert_eq!(reopened.encode().as_bytes(), first_wire.as_bytes());

        let state_root = directory.path.to_str().expect("UTF-8 node state root");
        let changed_document = crate::config::developer_node_document_for_test(state_root)
            .replace("endpoint_generation = 1\n", "endpoint_generation = 2\n");
        let changed_config = match crate::config::parse_node_config_toml_for_test(&changed_document)
            .expect("changed node config remains structurally valid")
        {
            crate::config::Command::DeveloperNodeV1(config) => *config,
            crate::config::Command::DeveloperFixtureV1(_)
            | crate::config::Command::DeveloperDistributedFixtureV1(_)
            | crate::config::Command::DeveloperProvisionedV1(_)
            | crate::config::Command::Help => panic!("unexpected changed node command"),
        };
        assert_ne!(
            changed_config.config_commitment(),
            config.config_commitment()
        );
        assert_eq!(
            load_or_create_node_with_entropy(&changed_config, &mut FailingEntropy).unwrap_err(),
            IdentityManifestError::InvalidManifestField
        );
        assert_eq!(
            fs::read(&paths.manifest).expect("node manifest remains unchanged"),
            first_wire.as_bytes()
        );
    }

    #[test]
    fn node_manifest_rejects_runtime_key_alias_before_publication() {
        let directory = TestDirectory::new();
        let config = crate::config::developer_node_config_for_test(&directory.path);
        let paths = IdentityPaths::node(&directory.path);
        assert_eq!(
            load_or_create_node_with_entropy(&config, &mut ControllerAliasingNodeEntropy)
                .unwrap_err(),
            IdentityManifestError::InvalidFreshEntropy
        );
        assert!(!paths.manifest.exists());
        assert!(!paths.temporary.exists());
    }

    #[test]
    fn node_tls_gate_accepts_only_pinned_private_credentials_directory() {
        let directory = TestDirectory::new();
        let config = crate::config::developer_node_config_for_test(&directory.path);
        ensure_state_root(&directory.path).expect("private node state root");
        let credentials = directory.path.join("credentials");
        let mut builder = DirBuilder::new();
        builder
            .mode(0o700)
            .create(&credentials)
            .expect("credentials directory");
        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700))
            .expect("credentials directory mode");
        let restricted = config.restricted_runtime_apply();
        for (path, mode) in [
            (restricted.root_ca_certificate_file(), 0o644),
            (restricted.runtime_listener_certificate_file(), 0o644),
            (restricted.runtime_listener_private_key_file(), 0o600),
        ] {
            fs::write(path, b"test-only credential bytes").expect("credential file");
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .expect("credential file mode");
        }
        validate_node_tls_files(&config).expect("strict credential set");

        fs::set_permissions(
            restricted.runtime_listener_private_key_file(),
            fs::Permissions::from_mode(0o640),
        )
        .expect("broaden private key mode");
        assert_eq!(
            validate_node_tls_files(&config).unwrap_err(),
            IdentityManifestError::InsecureCredentialFile
        );
    }

    #[test]
    fn first_open_atomically_publishes_and_reopen_restores_exact_manifest() {
        let directory = TestDirectory::new();
        let config = directory.config();
        let paths = IdentityPaths::from_config(&config);
        let mut entropy = PatternEntropy::new();
        let first = load_or_create_with_entropy(&config, &mut entropy).expect("first manifest");
        assert_eq!(entropy.calls, 1);

        let metadata = fs::symlink_metadata(&paths.manifest).expect("manifest metadata");
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), MANIFEST_WIRE_BYTES as u64);
        assert!(!paths.temporary.exists());

        let first_wire = first.encode();
        let mut must_not_run = FailingEntropy;
        let reopened = load_or_create_with_entropy(&config, &mut must_not_run).expect("reopen");
        let reopened_wire = reopened.encode();
        assert_eq!(first_wire.as_bytes(), reopened_wire.as_bytes());
    }

    #[test]
    fn production_open_uses_os_csprng_and_reopens_without_replacement() {
        let directory = TestDirectory::new();
        let config = directory.config();
        let first = load_or_create(&config).expect("OS-generated manifest");
        let first_wire = first.encode();
        drop(first);

        let reopened = load_or_create(&config).expect("strict reopen");
        let reopened_wire = reopened.encode();
        assert_eq!(first_wire.as_bytes(), reopened_wire.as_bytes());
    }

    #[test]
    fn provider_profiles_and_models_are_exact_state_root_pins() {
        let fixture_first = TestDirectory::new();
        load_or_create(&fixture_first.config()).expect("fixture identity");
        assert_eq!(
            load_or_create_provisioned(&fixture_first.openai_config("gpt-5-mini")).unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            load_or_create_provisioned(&fixture_first.deepseek_config("deepseek-v4-flash"))
                .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert!(
            !fixture_first
                .path
                .join(OPENAI_IDENTITY_DIRECTORY_NAME)
                .exists()
        );
        assert!(
            !fixture_first
                .path
                .join(DEEPSEEK_IDENTITY_DIRECTORY_NAME)
                .exists()
        );

        let openai_first = TestDirectory::new();
        let first_config = openai_first.openai_config("gpt-5-mini");
        let first = load_or_create_provisioned(&first_config).expect("OpenAI identity");
        assert_eq!(first.profile, IdentityProviderProfileV1::OpenAiResponses);
        let paths = IdentityPaths::from_state_root_for_profile(
            &openai_first.path,
            IdentityProviderProfileV1::OpenAiResponses,
        );
        let before = fs::read(&paths.manifest).expect("OpenAI manifest bytes");
        assert_eq!(&before[..4], OPENAI_MANIFEST_MAGIC);
        let reopened = load_or_create_provisioned(&first_config).expect("OpenAI identity reopen");
        assert_eq!(reopened.encode().as_bytes(), before);

        assert_eq!(
            load_or_create(&openai_first.config()).unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            load_or_create_provisioned(&openai_first.openai_config("gpt-5.1-mini")).unwrap_err(),
            IdentityManifestError::InvalidManifestField
        );
        assert_eq!(
            load_or_create_provisioned(&openai_first.deepseek_config("deepseek-v4-flash"))
                .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            fs::read(&paths.manifest).expect("OpenAI manifest remains unchanged"),
            before
        );

        let deepseek_first = TestDirectory::new();
        let deepseek_config = deepseek_first.deepseek_config("deepseek-v4-flash");
        let first = load_or_create_provisioned(&deepseek_config).expect("DeepSeek identity");
        assert_eq!(
            first.profile,
            IdentityProviderProfileV1::DeepSeekChatCompletions
        );
        let paths = IdentityPaths::from_state_root_for_profile(
            &deepseek_first.path,
            IdentityProviderProfileV1::DeepSeekChatCompletions,
        );
        let before = fs::read(&paths.manifest).expect("DeepSeek manifest bytes");
        assert_eq!(&before[..4], DEEPSEEK_MANIFEST_MAGIC);
        let reopened =
            load_or_create_provisioned(&deepseek_config).expect("DeepSeek identity reopen");
        assert_eq!(reopened.encode().as_bytes(), before);
        assert_eq!(
            load_or_create_provisioned(&deepseek_first.openai_config("gpt-5-mini")).unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            load_or_create_provisioned(&deepseek_first.deepseek_config("deepseek-v4-pro"))
                .unwrap_err(),
            IdentityManifestError::InvalidManifestField
        );
        assert_eq!(
            load_or_create_distributed_inner(
                deepseek_config.state_root(),
                &mut PatternEntropy::new(),
            )
            .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_ne!(
            OPENAI_MANIFEST_CHECKSUM_DOMAIN,
            DEEPSEEK_MANIFEST_CHECKSUM_DOMAIN
        );
    }

    #[test]
    fn symlinked_state_root_ancestor_is_rejected_before_identity_write() {
        let directory = TestDirectory::new();
        ensure_state_root(&directory.path).expect("outer private directory");
        let target = directory.path.join("target");
        let mut builder = DirBuilder::new();
        builder
            .mode(0o700)
            .create(&target)
            .expect("target directory");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("target permissions");
        let redirect = directory.path.join("redirect");
        std::os::unix::fs::symlink(&target, &redirect).expect("redirect symlink");
        let requested = redirect.join("state");
        let state_root = requested.to_str().expect("UTF-8 test state root");
        let document = format!(
            "schema_version = 1\nstate_root = {state_root:?}\nfabric_listen = \"tcp/127.0.0.1:7447\"\n\n[model]\nprovider = \"deterministic-echo-v1\"\n"
        );
        let config =
            match crate::config::parse_chat_config_toml_for_test(&document).expect("test config") {
                crate::config::Command::DeveloperFixtureV1(config) => config,
                crate::config::Command::DeveloperNodeV1(_)
                | crate::config::Command::DeveloperProvisionedV1(_) => {
                    panic!("unexpected provisioned command")
                }
                crate::config::Command::DeveloperDistributedFixtureV1(_) => {
                    panic!("unexpected distributed fixture command")
                }
                crate::config::Command::Help => panic!("unexpected help"),
            };

        assert_eq!(
            load_or_create_with_entropy(&config, &mut PatternEntropy::new()).unwrap_err(),
            IdentityManifestError::InsecureStateRoot
        );
        assert!(!target.join("state").exists());
    }

    #[test]
    fn corruption_and_unknown_versions_fail_without_rebuilding() {
        for (offset, expected) in [
            (
                MANIFEST_HEADER_BYTES + 7,
                IdentityManifestError::ManifestChecksumMismatch,
            ),
            (4, IdentityManifestError::UnsupportedManifestVersion),
        ] {
            let directory = TestDirectory::new();
            let config = directory.config();
            let paths = IdentityPaths::from_config(&config);
            load_or_create_with_entropy(&config, &mut PatternEntropy::new())
                .expect("initial manifest");
            let mut corrupt = fs::read(&paths.manifest).expect("manifest bytes");
            corrupt[offset] ^= 0x01;
            fs::write(&paths.manifest, &corrupt).expect("corrupt manifest");
            let before = fs::read(&paths.manifest).expect("corrupt bytes before reopen");

            assert_eq!(
                load_or_create_with_entropy(&config, &mut PatternEntropy::new()).unwrap_err(),
                expected
            );
            assert_eq!(
                fs::read(&paths.manifest).expect("corrupt bytes after reopen"),
                before
            );
        }
    }

    #[test]
    fn manifest_symlinks_hardlinks_and_broad_permissions_are_rejected() {
        let symlink_directory = TestDirectory::new();
        let symlink_config = symlink_directory.config();
        let symlink_paths = IdentityPaths::from_config(&symlink_config);
        load_or_create_with_entropy(&symlink_config, &mut PatternEntropy::new())
            .expect("initial symlink fixture");
        let target = symlink_config.state_root().join("manifest-target");
        fs::rename(&symlink_paths.manifest, &target).expect("move target");
        std::os::unix::fs::symlink(&target, &symlink_paths.manifest).expect("install symlink");
        assert_eq!(
            load_or_create_with_entropy(&symlink_config, &mut PatternEntropy::new()).unwrap_err(),
            IdentityManifestError::InsecureManifest
        );

        let hardlink_directory = TestDirectory::new();
        let hardlink_config = hardlink_directory.config();
        let hardlink_paths = IdentityPaths::from_config(&hardlink_config);
        load_or_create_with_entropy(&hardlink_config, &mut PatternEntropy::new())
            .expect("initial hardlink fixture");
        let hardlink = hardlink_config.state_root().join("manifest-copy");
        fs::hard_link(&hardlink_paths.manifest, &hardlink).expect("install hardlink");
        assert_eq!(
            load_or_create_with_entropy(&hardlink_config, &mut PatternEntropy::new()).unwrap_err(),
            IdentityManifestError::InsecureManifest
        );

        let mode_directory = TestDirectory::new();
        let mode_config = mode_directory.config();
        let mode_paths = IdentityPaths::from_config(&mode_config);
        load_or_create_with_entropy(&mode_config, &mut PatternEntropy::new())
            .expect("initial mode fixture");
        fs::set_permissions(&mode_paths.manifest, fs::Permissions::from_mode(0o640))
            .expect("broaden mode");
        assert_eq!(
            load_or_create_with_entropy(&mode_config, &mut PatternEntropy::new()).unwrap_err(),
            IdentityManifestError::InsecureManifest
        );
    }

    #[test]
    fn stale_temporary_publication_fails_closed() {
        let directory = TestDirectory::new();
        let config = directory.config();
        ensure_state_root(config.state_root()).expect("state root");
        let paths = IdentityPaths::from_config(&config);
        let uid = fs::symlink_metadata(config.state_root())
            .expect("state metadata")
            .uid();
        let gid = fs::symlink_metadata(config.state_root())
            .expect("state metadata")
            .gid();
        ensure_identity_directory(&paths.directory, uid, gid).expect("identity directory");
        let temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&paths.temporary)
            .expect("stale temp");
        temporary
            .set_permissions(fs::Permissions::from_mode(0o600))
            .expect("temp mode");
        drop(temporary);

        assert_eq!(
            load_or_create_with_entropy(&config, &mut PatternEntropy::new()).unwrap_err(),
            IdentityManifestError::StalePublication
        );
        assert!(!paths.manifest.exists());
    }

    #[test]
    fn entropy_failure_or_invalid_entropy_never_publishes_a_manifest() {
        for mut source in [
            TestEntropy::Failing(FailingEntropy),
            TestEntropy::Zero(ZeroEntropy),
        ] {
            let directory = TestDirectory::new();
            let config = directory.config();
            let paths = IdentityPaths::from_config(&config);
            assert!(load_or_create_with_entropy(&config, &mut source).is_err());
            assert!(!paths.manifest.exists());
            assert!(!paths.temporary.exists());
        }
    }

    #[test]
    fn debug_output_redacts_seeds_ids_and_nonce() {
        let manifest =
            IdentityManifestV1::try_generate(&mut PatternEntropy::new()).expect("fixture manifest");
        let debug = format!("{manifest:?}");
        assert_eq!(debug.matches("<redacted>").count(), 5);
        assert!(!debug.contains("controller_instance_id:"));
        assert!(!debug.contains("[20,"));
    }

    #[test]
    fn distributed_manifest_is_canonical_distinct_nonzero_and_redacted() {
        let manifest =
            DistributedDeveloperLocalIdentityManifestV1::try_generate(&mut PatternEntropy::new())
                .expect("distributed manifest");
        let wire = manifest.encode();
        assert_eq!(&wire.as_bytes()[..4], DISTRIBUTED_MANIFEST_MAGIC);
        assert_eq!(wire.as_bytes().len(), DISTRIBUTED_MANIFEST_WIRE_BYTES);
        let decoded = DistributedDeveloperLocalIdentityManifestV1::decode(wire.as_bytes())
            .expect("strict PXDI roundtrip");
        assert_eq!(decoded.encode().as_bytes(), wire.as_bytes());

        let target_a = decoded.target(DistributedDeveloperLocalTargetV1::A);
        let target_b = decoded.target(DistributedDeveloperLocalTargetV1::B);
        assert!(target_a.runtime_target() < target_b.runtime_target());
        assert_ne!(target_a.installation_id(), target_b.installation_id());
        assert_ne!(
            target_a.runtime_response_signing_seed(),
            target_b.runtime_response_signing_seed()
        );
        assert_ne!(
            target_a.pxnb_reference_token(),
            target_b.pxnb_reference_token()
        );
        assert_ne!(
            target_a.pxob_observation_token(),
            target_b.pxob_observation_token()
        );
        assert_ne!(target_a.node_id(), target_b.node_id());
        assert_ne!(target_a.node_incarnation(), target_b.node_incarnation());
        assert_ne!(
            target_a.node_management_endpoint_ref(),
            target_b.node_management_endpoint_ref()
        );
        assert_ne!(
            target_a.runtime_apply_endpoint_ref(),
            target_b.runtime_apply_endpoint_ref()
        );
        assert_ne!(
            target_a.controller_connector_credential_ref(),
            target_b.controller_connector_credential_ref()
        );
        assert_ne!(
            target_a.runtime_listener_credential_ref(),
            target_b.runtime_listener_credential_ref()
        );
        assert_ne!(
            target_a.fabric_peer_identity_ref(),
            target_b.fabric_peer_identity_ref()
        );
        assert_ne!(
            target_a.evidence_store_epoch(),
            target_b.evidence_store_epoch()
        );
        assert_ne!(target_a.evidence_owner_ref(), target_b.evidence_owner_ref());
        assert!(target_a.registration_epoch() != 0 && target_b.registration_epoch() != 0);
        assert!(target_a.endpoint_generation() != 0 && target_b.endpoint_generation() != 0);
        assert!(!bytes_are_zero(decoded.enrollment_issuer_ref()));
        assert!(!bytes_are_zero(decoded.transport_trust_domain_ref()));
        assert!(!bytes_are_zero(decoded.transport_trust_anchor_ref()));
        assert_eq!(
            decoded.provider_configuration_digest(),
            &deterministic_provider_configuration_digest()
        );

        let seed_a = decoded.developer_fixture_identity_seed(DistributedDeveloperLocalTargetV1::A);
        assert_eq!(seed_a.manifest_instance_id, *target_a.installation_id());
        assert_eq!(
            seed_a.controller_instance_id,
            *decoded.controller_instance_id()
        );
        assert_eq!(
            seed_a.authority_instance_id,
            *decoded.authority_instance_id()
        );
        assert_eq!(seed_a.runtime_instance_id, *target_a.runtime_target());
        assert_eq!(seed_a.source_scope_id, *decoded.source_scope_id());
        assert_eq!(seed_a.source_plan_id, *decoded.source_plan_id());
        assert_eq!(seed_a.fabric_service_id, *target_a.fabric_service_id());
        assert_eq!(seed_a.agent_service_id, *target_a.agent_service_id());
        assert_eq!(seed_a.submit_binding_id, *target_a.submit_binding_id());
        assert_eq!(seed_a.control_binding_id, *target_a.control_binding_id());
        assert_eq!(seed_a.provider_ref, *decoded.provider_ref());
        assert_eq!(seed_a.deck_run_id, *target_a.deck_run_id());
        assert_eq!(seed_a.session_id, *target_a.session_id());
        assert_eq!(
            seed_a.provider_configuration_digest,
            *decoded.provider_configuration_digest()
        );
        let derived_a = decoded
            .developer_fixture_derived_identity(DistributedDeveloperLocalTargetV1::A)
            .expect("target A owner-approved derivation");
        let derived_b = decoded
            .developer_fixture_derived_identity(DistributedDeveloperLocalTargetV1::B)
            .expect("target B owner-approved derivation");
        assert_eq!(derived_a.writer(), derived_b.writer());
        assert_eq!(
            derived_a.controller_key_ref(),
            derived_b.controller_key_ref()
        );
        assert_eq!(derived_a.authority_ref(), derived_b.authority_ref());
        assert_eq!(derived_a.authority_key_ref(), derived_b.authority_key_ref());
        assert_eq!(
            derived_a.authority_service_principal(),
            derived_b.authority_service_principal()
        );
        assert_eq!(derived_a.authority_owner(), derived_b.authority_owner());
        assert_ne!(derived_a.runtime_principal(), derived_b.runtime_principal());
        assert_ne!(
            derived_a.runtime_response_key_ref(),
            derived_b.runtime_response_key_ref()
        );
        assert_ne!(
            derived_a.successor_store_instance_id(),
            derived_b.successor_store_instance_id()
        );

        let debug = format!("{decoded:?}");
        assert_eq!(debug.matches("<redacted>").count(), 4);
        assert!(!debug.contains("runtime_target"));
        assert!(!debug.contains("pxnb_reference_token"));
        let target_debug = format!("{target_a:?}");
        assert_eq!(target_debug.matches("<redacted>").count(), 4);
        assert!(!target_debug.contains("runtime_target"));
    }

    #[test]
    fn distributed_manifest_v2_has_one_independent_frozen_field_order() {
        assert_eq!(DISTRIBUTED_MANIFEST_FIELD_COUNT, 62);
        assert_eq!(DISTRIBUTED_MANIFEST_WIRE_BYTES, 1_152);
        assert_eq!(DISTRIBUTED_FRESH_ENTROPY_BYTES, 1_072);
        let manifest = DistributedDeveloperLocalIdentityManifestV1 {
            controller_signing_seed: [0x01; 32],
            authority_signing_seed: [0x02; 32],
            manifest_instance_id: [0x10; 16],
            controller_instance_id: [0x11; 16],
            authority_instance_id: [0x12; 16],
            source_scope_id: [0x13; 16],
            source_plan_id: [0x14; 16],
            provider_ref: [0x15; 16],
            enrollment_issuer_ref: [0x16; 16],
            transport_trust_domain_ref: [0x17; 16],
            transport_trust_anchor_ref: [0x18; 16],
            provider_configuration_digest: deterministic_provider_configuration_digest(),
            targets: [
                DistributedDeveloperLocalTargetIdentityV1 {
                    runtime_response_signing_seed: [0x21; 32],
                    pxnb_reference_token: [0x22; 32],
                    pxob_observation_token: [0x23; 32],
                    installation_id: [0x30; 16],
                    runtime_target: [0x31; 16],
                    fabric_service_id: [0x32; 16],
                    agent_service_id: [0x33; 16],
                    submit_binding_id: [0x34; 16],
                    control_binding_id: [0x35; 16],
                    deck_run_id: [0x36; 16],
                    session_id: [0x37; 16],
                    node_id: [0x38; 16],
                    node_principal: [0x39; 16],
                    node_incarnation: [0x3a; 16],
                    node_management_endpoint_ref: [0x3b; 16],
                    runtime_observation_endpoint_ref: [0x3c; 16],
                    runtime_apply_endpoint_ref: [0x3d; 16],
                    transport_profile_ref: [0x3e; 16],
                    controller_connector_credential_ref: [0x3f; 16],
                    runtime_listener_credential_ref: [0x40; 16],
                    fabric_peer_identity_ref: [0x41; 16],
                    evidence_store_epoch: [0x42; 16],
                    evidence_owner_ref: [0x43; 16],
                    registration_epoch: 0x0102_0304_0506_0708,
                    endpoint_generation: 0x1112_1314_1516_1718,
                },
                DistributedDeveloperLocalTargetIdentityV1 {
                    runtime_response_signing_seed: [0x61; 32],
                    pxnb_reference_token: [0x62; 32],
                    pxob_observation_token: [0x63; 32],
                    installation_id: [0x70; 16],
                    runtime_target: [0x71; 16],
                    fabric_service_id: [0x72; 16],
                    agent_service_id: [0x73; 16],
                    submit_binding_id: [0x74; 16],
                    control_binding_id: [0x75; 16],
                    deck_run_id: [0x76; 16],
                    session_id: [0x77; 16],
                    node_id: [0x78; 16],
                    node_principal: [0x79; 16],
                    node_incarnation: [0x7a; 16],
                    node_management_endpoint_ref: [0x7b; 16],
                    runtime_observation_endpoint_ref: [0x7c; 16],
                    runtime_apply_endpoint_ref: [0x7d; 16],
                    transport_profile_ref: [0x7e; 16],
                    controller_connector_credential_ref: [0x7f; 16],
                    runtime_listener_credential_ref: [0x80; 16],
                    fabric_peer_identity_ref: [0x81; 16],
                    evidence_store_epoch: [0x82; 16],
                    evidence_owner_ref: [0x83; 16],
                    registration_epoch: 0x2122_2324_2526_2728,
                    endpoint_generation: 0x3132_3334_3536_3738,
                },
            ],
        };
        manifest.validate_durable().expect("known PXDI fields");

        let mut expected = Zeroizing::new(Vec::with_capacity(1_152));
        expected.extend_from_slice(b"PXDI");
        expected.extend_from_slice(&2_u16.to_be_bytes());
        expected.extend_from_slice(&16_u16.to_be_bytes());
        expected.extend_from_slice(&1_152_u32.to_be_bytes());
        expected.extend_from_slice(&62_u16.to_be_bytes());
        expected.extend_from_slice(&0_u16.to_be_bytes());
        for (byte, width) in [
            (0x01, 32),
            (0x02, 32),
            (0x10, 16),
            (0x11, 16),
            (0x12, 16),
            (0x13, 16),
            (0x14, 16),
            (0x15, 16),
            (0x16, 16),
            (0x17, 16),
            (0x18, 16),
        ] {
            let next = expected.len() + width;
            expected.resize(next, byte);
        }
        expected.extend_from_slice(&deterministic_provider_configuration_digest());
        for (byte, width) in [(0x21, 32), (0x22, 32), (0x23, 32)] {
            let next = expected.len() + width;
            expected.resize(next, byte);
        }
        for byte in 0x30_u8..=0x43 {
            let next = expected.len() + 16;
            expected.resize(next, byte);
        }
        expected.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
        expected.extend_from_slice(&0x1112_1314_1516_1718_u64.to_be_bytes());
        for (byte, width) in [(0x61, 32), (0x62, 32), (0x63, 32)] {
            let next = expected.len() + width;
            expected.resize(next, byte);
        }
        for byte in 0x70_u8..=0x83 {
            let next = expected.len() + 16;
            expected.resize(next, byte);
        }
        expected.extend_from_slice(&0x2122_2324_2526_2728_u64.to_be_bytes());
        expected.extend_from_slice(&0x3132_3334_3536_3738_u64.to_be_bytes());
        assert_eq!(expected.len(), 1_120);
        let mut checksum = Sha256::new();
        checksum
            .update(b"paraegox.local.developer-distributed-identity-manifest.checksum.sha256.v2");
        checksum.update(2_u16.to_be_bytes());
        checksum.update(expected.as_slice());
        let checksum: [u8; 32] = checksum.finalize().into();
        expected.extend_from_slice(&checksum);
        assert_eq!(manifest.encode().as_bytes(), expected.as_slice());

        let decoded = DistributedDeveloperLocalIdentityManifestV1::decode(&expected)
            .expect("independent PXDI vector");
        assert_repeated(decoded.controller_signing_seed(), 0x01);
        assert_repeated(decoded.authority_signing_seed(), 0x02);
        for (field, byte) in decoded
            .shared_identity_fields()
            .into_iter()
            .zip(0x10_u8..=0x18)
        {
            assert_repeated(field, byte);
        }
        assert_eq!(
            decoded.provider_configuration_digest(),
            &deterministic_provider_configuration_digest()
        );
        for (target, secret_bytes, identity_bytes, registration, endpoint) in [
            (
                decoded.target(DistributedDeveloperLocalTargetV1::A),
                [0x21, 0x22, 0x23],
                0x30_u8..=0x43,
                0x0102_0304_0506_0708_u64,
                0x1112_1314_1516_1718_u64,
            ),
            (
                decoded.target(DistributedDeveloperLocalTargetV1::B),
                [0x61, 0x62, 0x63],
                0x70_u8..=0x83,
                0x2122_2324_2526_2728_u64,
                0x3132_3334_3536_3738_u64,
            ),
        ] {
            for (field, byte) in target.secret_fields().into_iter().zip(secret_bytes) {
                assert_repeated(field, byte);
            }
            for (field, byte) in target.identity_fields().into_iter().zip(identity_bytes) {
                assert_repeated(field, byte);
            }
            assert_eq!(target.registration_epoch(), registration);
            assert_eq!(target.endpoint_generation(), endpoint);
        }
    }

    fn assert_repeated<const WIDTH: usize>(field: &[u8; WIDTH], byte: u8) {
        assert!(field.iter().all(|value| *value == byte));
    }

    #[test]
    fn distributed_manifest_atomically_reopens_byte_stable_without_entropy() {
        let directory = TestDirectory::new();
        let paths = IdentityPaths::distributed(&directory.path);
        let mut entropy = PatternEntropy::new();
        let first = load_or_create_distributed_inner(&directory.path, &mut entropy)
            .expect("first PXDI manifest");
        assert_eq!(entropy.calls, 1);
        assert_eq!(
            paths.directory.file_name().and_then(OsStr::to_str),
            Some("developer-distributed-identity-v2")
        );
        assert_eq!(
            paths.manifest.file_name().and_then(OsStr::to_str),
            Some("identity-manifest-v2.pxdi")
        );
        let first_wire = first.encode();
        let metadata = fs::symlink_metadata(&paths.manifest).expect("PXDI metadata");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), DISTRIBUTED_MANIFEST_WIRE_BYTES as u64);
        assert!(!paths.temporary.exists());

        let reopened = load_or_create_distributed_inner(&directory.path, &mut FailingEntropy)
            .expect("strict PXDI reopen");
        assert_eq!(reopened.encode().as_bytes(), first_wire.as_bytes());
    }

    #[test]
    fn distributed_operational_open_requires_explicit_initialization_without_mutation() {
        let directory = TestDirectory::new();
        assert_eq!(
            open_distributed_inner(&directory.path).unwrap_err(),
            IdentityManifestError::DistributedManifestNotInitialized
        );
        assert!(
            !directory.path.exists(),
            "strict operational open must not create the state root"
        );

        let existing_root = TestDirectory::new();
        let canonical = ensure_state_root(&existing_root.path).expect("empty private state root");
        assert_eq!(
            open_distributed_inner(&canonical).unwrap_err(),
            IdentityManifestError::DistributedManifestNotInitialized
        );
        assert_eq!(
            fs::read_dir(&canonical)
                .expect("unchanged empty state root")
                .count(),
            0,
            "strict operational open must not create an identity directory or lock"
        );

        let initialized =
            load_or_create_distributed_inner(&directory.path, &mut PatternEntropy::new())
                .expect("explicit identity initialization");
        let reopened = open_distributed_inner(&directory.path).expect("strict operational reopen");
        assert_eq!(
            reopened.encode().as_bytes(),
            initialized.encode().as_bytes()
        );
    }

    #[test]
    fn distributed_enrollment_plan_is_stable_machine_readable_and_secret_free() {
        let directory = TestDirectory::new();
        let config = directory.distributed_identity_init_config();
        let manifest =
            load_or_create_distributed_inner(&directory.path, &mut PatternEntropy::new())
                .expect("explicit identity initialization");
        let first = distributed_certificate_enrollment_plan_json_v1(&config, &manifest)
            .expect("enrollment plan");
        let reopened = open_distributed_inner(&directory.path).expect("strict identity reopen");
        let second = distributed_certificate_enrollment_plan_json_v1(&config, &reopened)
            .expect("stable enrollment plan");
        assert_eq!(first, second);

        let parsed: serde_json::Value =
            serde_json::from_str(&first).expect("machine-readable enrollment JSON");
        assert_eq!(parsed["schema"], DISTRIBUTED_ENROLLMENT_PLAN_SCHEMA);
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["contains_secret_material"], false);
        let targets = parsed["targets"].as_array().expect("two target plans");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0]["label"], "a");
        assert_eq!(targets[1]["label"], "b");
        assert_eq!(
            targets[0]["pxrp"]["runtime_server"]["subject_alt_name_ip"],
            "192.0.2.10"
        );
        assert_eq!(
            targets[1]["pxrp"]["runtime_server"]["subject_alt_name_ip"],
            "192.0.2.20"
        );
        assert_eq!(
            targets[0]["fabric"]["listener"]["subject_alt_name_ip"],
            "192.0.2.10"
        );
        assert_eq!(
            targets[1]["fabric"]["listener"]["subject_alt_name_ip"],
            "192.0.2.20"
        );
        assert_eq!(
            targets[0]["fabric"]["local_certificate_common_name"],
            "fabric-a.example.test"
        );
        assert_eq!(
            targets[0]["fabric"]["expected_peer_common_name"],
            "fabric-b.example.test"
        );
        assert_eq!(
            targets[1]["fabric"]["local_certificate_common_name"],
            "fabric-b.example.test"
        );
        assert_eq!(
            targets[1]["fabric"]["expected_peer_common_name"],
            "fabric-a.example.test"
        );
        assert_eq!(
            targets[0]["fabric"]["expected_peer_identity_ref"],
            lower_hex(
                manifest
                    .target(DistributedDeveloperLocalTargetV1::B)
                    .fabric_peer_identity_ref(),
            )
        );
        assert_eq!(
            targets[1]["fabric"]["expected_peer_identity_ref"],
            lower_hex(
                manifest
                    .target(DistributedDeveloperLocalTargetV1::A)
                    .fabric_peer_identity_ref(),
            )
        );
        let derived_a = manifest
            .developer_fixture_derived_identity(DistributedDeveloperLocalTargetV1::A)
            .expect("target A derived identity");
        let derived_b = manifest
            .developer_fixture_derived_identity(DistributedDeveloperLocalTargetV1::B)
            .expect("target B derived identity");
        let controller_common_name = restricted_runtime_apply_peer_certificate_common_name_v1(
            PrincipalRef::from_bytes(derived_a.controller_principal()),
        );
        assert_eq!(
            targets[0]["pxrp"]["controller_client"]["certificate_common_name"],
            controller_common_name
        );
        assert_eq!(
            targets[0]["pxrp"]["controller_client"]["certificate_common_name"],
            targets[1]["pxrp"]["controller_client"]["certificate_common_name"]
        );
        assert_ne!(
            targets[0]["pxrp"]["runtime_server"]["certificate_common_name"],
            targets[1]["pxrp"]["runtime_server"]["certificate_common_name"]
        );
        assert_ne!(derived_a.runtime_principal(), derived_b.runtime_principal());

        let target_a = manifest.target(DistributedDeveloperLocalTargetV1::A);
        let target_b = manifest.target(DistributedDeveloperLocalTargetV1::B);
        for secret in [
            manifest.controller_signing_seed(),
            manifest.authority_signing_seed(),
            target_a.runtime_response_signing_seed(),
            target_a.pxnb_reference_token(),
            target_a.pxob_observation_token(),
            target_b.runtime_response_signing_seed(),
            target_b.pxnb_reference_token(),
            target_b.pxob_observation_token(),
        ] {
            assert!(
                !first.contains(&lower_hex(secret)),
                "enrollment JSON must not expose identity Secret bytes"
            );
        }
    }

    #[test]
    fn distributed_enrollment_uses_the_fabric_owned_certificate_common_name_encoder() {
        let source = include_str!("identity.rs");
        let owner_encoder = [
            "restricted_runtime_apply_peer_",
            "certificate_common_name_v1",
        ]
        .concat();
        let forbidden_duplicate_prefix = ["paraegox-", "principal-"].concat();

        assert_eq!(source.matches(&owner_encoder).count(), 4);
        assert!(!source.contains(&forbidden_duplicate_prefix));
    }

    #[test]
    fn legacy_and_distributed_profiles_never_silently_migrate_each_other() {
        let legacy_directory = TestDirectory::new();
        let legacy_config = legacy_directory.config();
        let legacy_paths = IdentityPaths::from_config(&legacy_config);
        load_or_create_with_entropy(&legacy_config, &mut PatternEntropy::new())
            .expect("legacy PXLI");
        let before = fs::read(&legacy_paths.manifest).expect("legacy bytes");
        assert_eq!(&before[..4], MANIFEST_MAGIC);
        assert_eq!(
            load_or_create_distributed_inner(
                legacy_config.state_root(),
                &mut PatternEntropy::new(),
            )
            .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            fs::read(&legacy_paths.manifest).expect("unchanged PXLI"),
            before
        );
        assert!(
            !legacy_config
                .state_root()
                .join(DISTRIBUTED_IDENTITY_DIRECTORY_NAME)
                .exists()
        );
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&before).unwrap_err(),
            IdentityManifestError::InvalidManifestLength
        );

        let openai_directory = TestDirectory::new();
        let openai_config = openai_directory.openai_config("gpt-5-mini");
        load_or_create_provisioned(&openai_config).expect("legacy PXOI");
        let openai_paths = IdentityPaths::from_state_root_for_profile(
            openai_config.state_root(),
            IdentityProviderProfileV1::OpenAiResponses,
        );
        let openai_before = fs::read(&openai_paths.manifest).expect("legacy PXOI bytes");
        assert_eq!(&openai_before[..4], OPENAI_MANIFEST_MAGIC);
        assert_eq!(
            load_or_create_distributed_inner(
                openai_config.state_root(),
                &mut PatternEntropy::new(),
            )
            .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            fs::read(&openai_paths.manifest).expect("unchanged PXOI"),
            openai_before
        );
        assert!(
            !openai_config
                .state_root()
                .join(DISTRIBUTED_IDENTITY_DIRECTORY_NAME)
                .exists()
        );

        let deepseek_directory = TestDirectory::new();
        let deepseek_config = deepseek_directory.deepseek_config("deepseek-v4-flash");
        load_or_create_provisioned(&deepseek_config).expect("DeepSeek PXDS");
        let deepseek_paths = IdentityPaths::from_state_root_for_profile(
            deepseek_config.state_root(),
            IdentityProviderProfileV1::DeepSeekChatCompletions,
        );
        let deepseek_before = fs::read(&deepseek_paths.manifest).expect("DeepSeek PXDS bytes");
        assert_eq!(&deepseek_before[..4], DEEPSEEK_MANIFEST_MAGIC);
        assert_eq!(
            load_or_create_distributed_inner(
                deepseek_config.state_root(),
                &mut PatternEntropy::new(),
            )
            .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            fs::read(&deepseek_paths.manifest).expect("unchanged PXDS"),
            deepseek_before
        );

        let distributed_directory = TestDirectory::new();
        let distributed = load_or_create_distributed_inner(
            &distributed_directory.path,
            &mut PatternEntropy::new(),
        )
        .expect("PXDI");
        let distributed_wire = distributed.encode();
        assert_eq!(
            load_or_create_with_entropy(
                &distributed_directory.config(),
                &mut PatternEntropy::new(),
            )
            .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            load_or_create_provisioned(&distributed_directory.openai_config("gpt-5-mini"))
                .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            load_or_create_provisioned(&distributed_directory.deepseek_config("deepseek-v4-flash"))
                .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert_eq!(
            fs::read(IdentityPaths::distributed(&distributed_directory.path).manifest)
                .expect("unchanged PXDI"),
            distributed_wire.as_bytes()
        );
        assert!(
            !distributed_directory
                .path
                .join(IDENTITY_DIRECTORY_NAME)
                .exists()
        );
        assert!(
            !distributed_directory
                .path
                .join(OPENAI_IDENTITY_DIRECTORY_NAME)
                .exists()
        );
        assert!(
            !distributed_directory
                .path
                .join(DEEPSEEK_IDENTITY_DIRECTORY_NAME)
                .exists()
        );

        let old_pxdi_directory = TestDirectory::new();
        let canonical = ensure_state_root(&old_pxdi_directory.path).expect("private state root");
        let legacy_path = canonical.join(LEGACY_DISTRIBUTED_IDENTITY_DIRECTORY_NAME);
        let mut builder = DirBuilder::new();
        builder
            .mode(0o700)
            .create(&legacy_path)
            .expect("legacy PXDI v1 directory");
        assert_eq!(
            load_or_create_distributed_inner(&canonical, &mut PatternEntropy::new()).unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
        assert!(legacy_path.exists());
        assert!(!canonical.join(DISTRIBUTED_IDENTITY_DIRECTORY_NAME).exists());
        assert_eq!(
            load_or_create_with_entropy(&old_pxdi_directory.config(), &mut PatternEntropy::new(),)
                .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
    }

    #[test]
    fn shared_state_root_lock_serializes_cross_profile_first_open() {
        let directory = TestDirectory::new();
        let canonical = ensure_state_root(&directory.path).expect("private state root");
        let metadata = fs::symlink_metadata(&canonical).expect("state root metadata");
        let held = acquire_identity_profile_lock(&canonical, metadata.uid(), metadata.gid())
            .expect("hold profile lock");
        assert_eq!(
            fs::read_dir(&canonical)
                .expect("state root entries")
                .count(),
            0,
            "profile serialization must not add a migration marker or lock path"
        );
        assert_eq!(
            load_or_create_distributed_inner(&canonical, &mut PatternEntropy::new()).unwrap_err(),
            IdentityManifestError::ProfileLockContended
        );
        assert_eq!(
            load_or_create_with_entropy(&directory.config(), &mut PatternEntropy::new())
                .unwrap_err(),
            IdentityManifestError::ProfileLockContended
        );
        assert!(!canonical.join(DISTRIBUTED_IDENTITY_DIRECTORY_NAME).exists());
        assert!(!canonical.join(IDENTITY_DIRECTORY_NAME).exists());
        drop(held);

        load_or_create_distributed_inner(&canonical, &mut PatternEntropy::new())
            .expect("one profile wins after lock release");
        assert_eq!(
            load_or_create_with_entropy(&directory.config(), &mut PatternEntropy::new())
                .unwrap_err(),
            IdentityManifestError::ProviderProfileMismatch
        );
    }

    #[test]
    fn distributed_manifest_rejects_malformed_header_checksum_and_fields() {
        let manifest =
            DistributedDeveloperLocalIdentityManifestV1::try_generate(&mut PatternEntropy::new())
                .expect("distributed manifest");
        let canonical = manifest.encode();

        let mut legacy_v1 = vec![0_u8; 1_136];
        legacy_v1[0..4].copy_from_slice(DISTRIBUTED_MANIFEST_MAGIC);
        legacy_v1[4..6].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&legacy_v1).unwrap_err(),
            IdentityManifestError::UnsupportedManifestVersion
        );

        let mut wrong_magic = canonical.as_bytes().to_vec();
        wrong_magic[0] ^= 1;
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&wrong_magic).unwrap_err(),
            IdentityManifestError::InvalidManifestMagic
        );
        let mut unknown_version = canonical.as_bytes().to_vec();
        unknown_version[5] ^= 1;
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&unknown_version).unwrap_err(),
            IdentityManifestError::UnsupportedManifestVersion
        );
        let mut bad_header = canonical.as_bytes().to_vec();
        bad_header[13] ^= 1;
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&bad_header).unwrap_err(),
            IdentityManifestError::InvalidManifestHeader
        );
        let mut bad_checksum = canonical.as_bytes().to_vec();
        bad_checksum[DISTRIBUTED_MANIFEST_HEADER_BYTES + 3] ^= 1;
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&bad_checksum).unwrap_err(),
            IdentityManifestError::ManifestChecksumMismatch
        );

        let provider_digest_offset = DISTRIBUTED_MANIFEST_HEADER_BYTES
            + (DISTRIBUTED_SHARED_SECRET_FIELD_COUNT * 32)
            + (DISTRIBUTED_SHARED_IDENTITY_FIELD_COUNT * 16);
        let mut wrong_provider_digest = canonical.as_bytes().to_vec();
        wrong_provider_digest[provider_digest_offset] ^= 1;
        rewrite_distributed_checksum(&mut wrong_provider_digest);
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&wrong_provider_digest)
                .unwrap_err(),
            IdentityManifestError::InvalidManifestField
        );

        let first_target_offset = DISTRIBUTED_MANIFEST_HEADER_BYTES
            + (DISTRIBUTED_SHARED_SECRET_FIELD_COUNT * 32)
            + (DISTRIBUTED_SHARED_IDENTITY_FIELD_COUNT * 16)
            + (DISTRIBUTED_SHARED_DIGEST_FIELD_COUNT * 32);
        let first_registration_epoch_offset = first_target_offset
            + (DISTRIBUTED_TARGET_SECRET_FIELD_COUNT * 32)
            + (DISTRIBUTED_TARGET_IDENTITY_FIELD_COUNT * 16);
        let mut zero_epoch = canonical.as_bytes().to_vec();
        zero_epoch[first_registration_epoch_offset..first_registration_epoch_offset + 8].fill(0);
        rewrite_distributed_checksum(&mut zero_epoch);
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&zero_epoch).unwrap_err(),
            IdentityManifestError::InvalidManifestField
        );

        let second_target_offset = first_target_offset
            + (DISTRIBUTED_TARGET_SECRET_FIELD_COUNT * 32)
            + (DISTRIBUTED_TARGET_IDENTITY_FIELD_COUNT * 16)
            + (DISTRIBUTED_TARGET_SCALAR_FIELD_COUNT * 8);
        let runtime_target_within_target = (DISTRIBUTED_TARGET_SECRET_FIELD_COUNT * 32) + 16;
        let first_runtime_target = first_target_offset + runtime_target_within_target
            ..first_target_offset + runtime_target_within_target + 16;
        let second_runtime_target = second_target_offset + runtime_target_within_target
            ..second_target_offset + runtime_target_within_target + 16;
        let mut duplicate_target = canonical.as_bytes().to_vec();
        let first_target_bytes: [u8; 16] = duplicate_target[first_runtime_target]
            .try_into()
            .expect("runtime target width");
        duplicate_target[second_runtime_target].copy_from_slice(&first_target_bytes);
        rewrite_distributed_checksum(&mut duplicate_target);
        assert_eq!(
            DistributedDeveloperLocalIdentityManifestV1::decode(&duplicate_target).unwrap_err(),
            IdentityManifestError::InvalidManifestField
        );
    }

    fn rewrite_distributed_checksum(wire: &mut [u8]) {
        let checksum = distributed_manifest_checksum(&wire[..DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET]);
        wire[DISTRIBUTED_MANIFEST_CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    }
}
