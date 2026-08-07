//! Provider-neutral, agent-neutral mechanisms for bounded text model calls.
//!
//! [`ModelServiceV1`] owns no-queue admission, cancellation before backend
//! handoff, bounded terminal output, and read-only accounting. A backend owns
//! provider I/O after handoff. This crate deliberately does not own routing,
//! retries, credentials, HTTP, Agent sessions, Runtime lifecycle, or a
//! cross-process protocol.

use core::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::time::BoundedDuration;

/// Largest UTF-8 prompt accepted by bounded text v1.
pub const MAX_MODEL_INVOCATION_INPUT_BYTES: usize = 16 * 1024;
/// Largest UTF-8 success body accepted from a backend by bounded text v1.
pub const MAX_MODEL_INVOCATION_OUTPUT_BYTES: usize = 32 * 1024;
/// Largest relative deadline budget accepted by bounded text v1: 300 seconds.
pub const MAX_MODEL_INVOCATION_DEADLINE_NANOS: u64 = 300_000_000_000;
/// Hard ceiling for concurrent backend calls owned by one service instance.
pub const MAX_MODEL_SERVICE_IN_FLIGHT: usize = 256;

/// Nonzero identity for one model invocation within its source owner's scope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelInvocationIdV1([u8; 16]);

impl ModelInvocationIdV1 {
    /// Constructs an invocation identity, rejecting the reserved zero value.
    pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, ModelInvocationIdErrorV1> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(ModelInvocationIdErrorV1::Zero)
    }

    /// Returns the exact owner-scoped identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Stable failures constructing a model invocation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelInvocationIdErrorV1 {
    /// Zero is reserved for an absent or uninitialized identity.
    Zero,
}

impl fmt::Display for ModelInvocationIdErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model invocation identity bytes must not be all zero")
    }
}

impl std::error::Error for ModelInvocationIdErrorV1 {}

/// Stable identity of one configured backend instance.
///
/// `provider_ref` identifies the provider implementation or deployment. The
/// digest must commit only non-secret effective configuration; credentials and
/// other Secret material do not belong in this value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ModelBackendIdentityV1 {
    provider_ref: [u8; 16],
    config_digest: Digest32,
}

impl ModelBackendIdentityV1 {
    /// Validates opaque provider bytes and a non-secret configuration digest.
    pub const fn try_new(
        provider_ref: [u8; 16],
        config_digest: Digest32,
    ) -> Result<Self, ModelBackendIdentityErrorV1> {
        if bytes_are_zero(&provider_ref) {
            return Err(ModelBackendIdentityErrorV1::ZeroProviderRef);
        }
        if bytes_are_zero(config_digest.as_bytes()) {
            return Err(ModelBackendIdentityErrorV1::ZeroConfigDigest);
        }
        Ok(Self {
            provider_ref,
            config_digest,
        })
    }

    /// Returns the opaque provider reference.
    #[must_use]
    pub const fn provider_ref(&self) -> &[u8; 16] {
        &self.provider_ref
    }

    /// Returns the digest of effective non-secret backend configuration.
    #[must_use]
    pub const fn config_digest(&self) -> Digest32 {
        self.config_digest
    }
}

/// Stable failures constructing a backend identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelBackendIdentityErrorV1 {
    /// The provider reference is the reserved all-zero value.
    ZeroProviderRef,
    /// The effective non-secret configuration digest is all zero.
    ZeroConfigDigest,
}

impl fmt::Display for ModelBackendIdentityErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroProviderRef => "model backend provider reference must not be all zero",
            Self::ZeroConfigDigest => "model backend config digest must not be all zero",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ModelBackendIdentityErrorV1 {}

/// Validated, owned input for one bounded text invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInvocationRequestV1 {
    invocation_id: ModelInvocationIdV1,
    source_request_digest: Digest32,
    deadline_budget: BoundedDuration,
    prompt: Box<str>,
}

impl ModelInvocationRequestV1 {
    /// Validates and owns one UTF-8 prompt and its relative deadline budget.
    ///
    /// `source_request_digest` binds the call to the independently owned source
    /// request without importing that source's domain contract into this crate.
    pub fn try_new(
        invocation_id: ModelInvocationIdV1,
        source_request_digest: Digest32,
        deadline_budget: BoundedDuration,
        prompt: impl Into<Box<str>>,
    ) -> Result<Self, ModelInvocationRequestErrorV1> {
        if bytes_are_zero(source_request_digest.as_bytes()) {
            return Err(ModelInvocationRequestErrorV1::ZeroSourceRequestDigest);
        }
        if deadline_budget.value() == 0
            || deadline_budget.value() > MAX_MODEL_INVOCATION_DEADLINE_NANOS
        {
            return Err(ModelInvocationRequestErrorV1::DeadlineOutOfRange);
        }
        let prompt = prompt.into();
        if prompt.is_empty() {
            return Err(ModelInvocationRequestErrorV1::EmptyPrompt);
        }
        if prompt.len() > MAX_MODEL_INVOCATION_INPUT_BYTES {
            return Err(ModelInvocationRequestErrorV1::PromptTooLong);
        }

        Ok(Self {
            invocation_id,
            source_request_digest,
            deadline_budget,
            prompt,
        })
    }

    /// Returns the source-owner-scoped invocation identity.
    #[must_use]
    pub const fn invocation_id(&self) -> ModelInvocationIdV1 {
        self.invocation_id
    }

    /// Returns the digest binding this invocation to its source request.
    #[must_use]
    pub const fn source_request_digest(&self) -> Digest32 {
        self.source_request_digest
    }

    /// Returns the receiver-installed relative deadline budget.
    #[must_use]
    pub const fn deadline_budget(&self) -> BoundedDuration {
        self.deadline_budget
    }

    /// Returns the validated UTF-8 prompt.
    #[must_use]
    pub fn prompt(&self) -> &str {
        &self.prompt
    }
}

/// Stable request validation failures raised before service admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelInvocationRequestErrorV1 {
    /// The source request digest is the reserved all-zero value.
    ZeroSourceRequestDigest,
    /// The relative deadline is zero or greater than 300 seconds.
    DeadlineOutOfRange,
    /// Bounded text v1 does not admit an empty prompt.
    EmptyPrompt,
    /// The UTF-8 prompt exceeds [`MAX_MODEL_INVOCATION_INPUT_BYTES`].
    PromptTooLong,
}

impl fmt::Display for ModelInvocationRequestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroSourceRequestDigest => "model source request digest must not be zero",
            Self::DeadlineOutOfRange => "model invocation deadline budget is out of range",
            Self::EmptyPrompt => "model invocation prompt must not be empty",
            Self::PromptTooLong => "model invocation prompt is too long",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ModelInvocationRequestErrorV1 {}

/// Single-writer source for cooperative invocation cancellation.
///
/// This value is intentionally non-`Clone`. Any number of read-only views may
/// be given to the service or backend, while the source owner retains the only
/// mutation capability.
#[derive(Debug)]
pub struct ModelCancellationSourceV1 {
    requested: Arc<AtomicBool>,
}

impl ModelCancellationSourceV1 {
    /// Creates a source whose cancellation flag is initially clear.
    #[must_use]
    pub fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns a cloneable read-only view of this source.
    #[must_use]
    pub fn view(&self) -> ModelCancellationViewV1 {
        ModelCancellationViewV1 {
            requested: Arc::clone(&self.requested),
        }
    }

    /// Idempotently requests cancellation.
    pub fn request_cancellation(&self) {
        self.requested.store(true, Ordering::Release);
    }

    /// Reports whether cancellation has been requested.
    #[must_use]
    pub fn is_cancellation_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

impl Default for ModelCancellationSourceV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-only cooperative cancellation observation for one invocation.
#[derive(Clone, Debug)]
pub struct ModelCancellationViewV1 {
    requested: Arc<AtomicBool>,
}

impl ModelCancellationViewV1 {
    /// Reports whether the source owner has requested cancellation.
    #[must_use]
    pub fn is_cancellation_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

/// Terminal result of one bounded text invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelInvocationOutcomeV1 {
    /// Provider text admitted by the service's output bound.
    Success(Box<str>),
    /// Provider or response validation failed before any success was admitted.
    Failed,
    /// The backend observed the request's deadline.
    DeadlineExceeded,
    /// The service or backend observed cancellation before provider handoff.
    CancelledBeforeHandoff,
    /// A side effect may have happened, but no trustworthy result is known.
    OutcomeUncertain,
    /// The service refused the call because its no-queue capacity was full.
    CapacityExhausted,
}

/// One owned model operation that does not borrow its backend.
pub type ModelBackendFuture =
    Pin<Box<dyn Future<Output = ModelInvocationOutcomeV1> + Send + 'static>>;

/// Provider-facing mechanism invoked exactly once for each admitted call.
///
/// `invoke` must only construct and return the owned future; blocking I/O
/// belongs inside that future. The backend owns deadline and cooperative
/// cancellation behavior after handoff. It must not implement retries or
/// provider routing behind this interface.
pub trait ModelBackendV1: Send + Sync + 'static {
    /// Returns immutable identity for this configured backend instance.
    fn identity(&self) -> ModelBackendIdentityV1;

    /// Starts one already-admitted invocation and returns a non-borrowing future.
    fn invoke(
        &self,
        request: ModelInvocationRequestV1,
        cancellation: ModelCancellationViewV1,
    ) -> ModelBackendFuture;
}

impl<B: ModelBackendV1 + ?Sized> ModelBackendV1 for Arc<B> {
    fn identity(&self) -> ModelBackendIdentityV1 {
        (**self).identity()
    }

    fn invoke(
        &self,
        request: ModelInvocationRequestV1,
        cancellation: ModelCancellationViewV1,
    ) -> ModelBackendFuture {
        (**self).invoke(request, cancellation)
    }
}

/// Stable identity of one compiled-in model adapter implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelAdapterIdV1([u8; 16]);

impl ModelAdapterIdV1 {
    /// Constructs an adapter identity, rejecting the reserved zero value.
    pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, ModelAdapterIdErrorV1> {
        if bytes_are_zero(&bytes) {
            return Err(ModelAdapterIdErrorV1::Zero);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact adapter identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Stable failures constructing a model adapter identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelAdapterIdErrorV1 {
    /// Zero is reserved for an absent or uninitialized adapter identity.
    Zero,
}

impl fmt::Display for ModelAdapterIdErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model adapter identity bytes must not be all zero")
    }
}

impl std::error::Error for ModelAdapterIdErrorV1 {}

/// Nonzero implementation version within one model adapter identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelAdapterVersionV1(u32);

impl ModelAdapterVersionV1 {
    /// Constructs an adapter version, rejecting the reserved zero value.
    pub const fn try_new(value: u32) -> Result<Self, ModelAdapterVersionErrorV1> {
        if value == 0 {
            return Err(ModelAdapterVersionErrorV1::Zero);
        }
        Ok(Self(value))
    }

    /// Returns the nonzero adapter implementation version.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Stable failures constructing a model adapter version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelAdapterVersionErrorV1 {
    /// Zero is reserved for an absent or uninitialized adapter version.
    Zero,
}

impl fmt::Display for ModelAdapterVersionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model adapter version must be nonzero")
    }
}

impl std::error::Error for ModelAdapterVersionErrorV1 {}

/// Nonzero identity of one exact provider-neutral model capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelCapabilityIdV1([u8; 16]);

impl ModelCapabilityIdV1 {
    /// Constructs a capability identity, rejecting the reserved zero value.
    pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, ModelCapabilityIdErrorV1> {
        if bytes_are_zero(&bytes) {
            return Err(ModelCapabilityIdErrorV1::Zero);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact capability identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Stable failures constructing a model capability identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelCapabilityIdErrorV1 {
    /// Zero is reserved for an absent or uninitialized capability identity.
    Zero,
}

impl fmt::Display for ModelCapabilityIdErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model capability identity bytes must not be all zero")
    }
}

impl std::error::Error for ModelCapabilityIdErrorV1 {}

/// Fixed capability identity for one bounded-text-v1 model invocation.
pub const BOUNDED_TEXT_MODEL_CAPABILITY_ID_V1: ModelCapabilityIdV1 =
    match ModelCapabilityIdV1::try_from_bytes(*b"px-bounded-text1") {
        Ok(capability_id) => capability_id,
        Err(_) => panic!("fixed bounded-text-v1 capability identity must be nonzero"),
    };

/// Exact identity of one compiled-in adapter implementation and capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelAdapterDescriptorV1 {
    adapter_id: ModelAdapterIdV1,
    version: ModelAdapterVersionV1,
    capability_id: ModelCapabilityIdV1,
}

impl ModelAdapterDescriptorV1 {
    /// Binds an adapter ID, implementation version, and exact capability.
    #[must_use]
    pub const fn new(
        adapter_id: ModelAdapterIdV1,
        version: ModelAdapterVersionV1,
        capability_id: ModelCapabilityIdV1,
    ) -> Self {
        Self {
            adapter_id,
            version,
            capability_id,
        }
    }

    /// Returns the compiled adapter implementation identity.
    #[must_use]
    pub const fn adapter_id(self) -> ModelAdapterIdV1 {
        self.adapter_id
    }

    /// Returns the exact adapter implementation version.
    #[must_use]
    pub const fn version(self) -> ModelAdapterVersionV1 {
        self.version
    }

    /// Returns the exact provider-neutral capability identity.
    #[must_use]
    pub const fn capability_id(self) -> ModelCapabilityIdV1 {
        self.capability_id
    }
}

/// Immutable registration metadata for one configured adapter factory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelAdapterMetadataV1 {
    descriptor: ModelAdapterDescriptorV1,
    backend_identity: ModelBackendIdentityV1,
}

impl ModelAdapterMetadataV1 {
    /// Binds one exact adapter descriptor to one exact configuration.
    #[must_use]
    pub const fn new(
        descriptor: ModelAdapterDescriptorV1,
        backend_identity: ModelBackendIdentityV1,
    ) -> Self {
        Self {
            descriptor,
            backend_identity,
        }
    }

    /// Returns the complete registered adapter descriptor.
    #[must_use]
    pub const fn descriptor(self) -> ModelAdapterDescriptorV1 {
        self.descriptor
    }

    /// Returns the registered compiled adapter implementation identity.
    #[must_use]
    pub const fn adapter_id(self) -> ModelAdapterIdV1 {
        self.descriptor.adapter_id()
    }

    /// Returns the registered adapter implementation version.
    #[must_use]
    pub const fn adapter_version(self) -> ModelAdapterVersionV1 {
        self.descriptor.version()
    }

    /// Returns the registered provider-neutral capability identity.
    #[must_use]
    pub const fn capability_id(self) -> ModelCapabilityIdV1 {
        self.descriptor.capability_id()
    }

    /// Returns the configured backend identity this factory must build.
    #[must_use]
    pub const fn backend_identity(self) -> ModelBackendIdentityV1 {
        self.backend_identity
    }
}

/// Exact request to resolve one registered adapter and configured backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelAdapterSelectionV1 {
    descriptor: ModelAdapterDescriptorV1,
    backend_identity: ModelBackendIdentityV1,
}

impl ModelAdapterSelectionV1 {
    /// Constructs an exact selection without compatibility or fallback rules.
    #[must_use]
    pub const fn new(
        descriptor: ModelAdapterDescriptorV1,
        backend_identity: ModelBackendIdentityV1,
    ) -> Self {
        Self {
            descriptor,
            backend_identity,
        }
    }

    /// Returns the complete selected adapter descriptor.
    #[must_use]
    pub const fn descriptor(self) -> ModelAdapterDescriptorV1 {
        self.descriptor
    }

    /// Returns the selected compiled adapter implementation identity.
    #[must_use]
    pub const fn adapter_id(self) -> ModelAdapterIdV1 {
        self.descriptor.adapter_id()
    }

    /// Returns the selected adapter implementation version.
    #[must_use]
    pub const fn adapter_version(self) -> ModelAdapterVersionV1 {
        self.descriptor.version()
    }

    /// Returns the selected provider-neutral capability identity.
    #[must_use]
    pub const fn capability_id(self) -> ModelCapabilityIdV1 {
        self.descriptor.capability_id()
    }

    /// Returns the exact configured backend identity expected by the caller.
    #[must_use]
    pub const fn backend_identity(self) -> ModelBackendIdentityV1 {
        self.backend_identity
    }
}

/// Provider-neutral reason a configured adapter factory refused construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelAdapterBuildErrorV1 {
    /// The factory could not construct its configured backend.
    Rejected,
}

impl fmt::Display for ModelAdapterBuildErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model adapter factory rejected backend construction")
    }
}

impl std::error::Error for ModelAdapterBuildErrorV1 {}

/// Object-safe construction seam for one compiled-in model adapter.
///
/// A factory represents exactly one immutable configured backend identity. It
/// must not perform adapter discovery, routing, fallback, or credential lookup
/// behind this interface.
pub trait ModelAdapterFactoryV1: Send + Sync + 'static {
    /// Returns immutable adapter and configured-backend registration metadata.
    fn metadata(&self) -> ModelAdapterMetadataV1;

    /// Builds the backend declared by [`Self::metadata`].
    fn build(&self) -> Result<Arc<dyn ModelBackendV1>, ModelAdapterBuildErrorV1>;
}

/// Fail-closed errors from exact static adapter registration and resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelAdapterRegistryErrorV1 {
    /// An exact adapter descriptor may have only one registered factory.
    DuplicateAdapterDescriptor,
    /// No compiled-in factory has the complete selected adapter descriptor.
    UnknownAdapterDescriptor,
    /// The selected provider reference differs from registered metadata.
    SelectionProviderRefMismatch,
    /// The selected non-secret configuration digest differs from registration.
    SelectionConfigDigestMismatch,
    /// The selected factory refused to construct its configured backend.
    FactoryRejected,
    /// A factory built a backend whose identity differs from its metadata.
    BuiltBackendIdentityMismatch,
}

impl fmt::Display for ModelAdapterRegistryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DuplicateAdapterDescriptor => "model adapter descriptor is already registered",
            Self::UnknownAdapterDescriptor => "selected model adapter descriptor is not registered",
            Self::SelectionProviderRefMismatch => {
                "selected model backend provider reference does not match registration"
            }
            Self::SelectionConfigDigestMismatch => {
                "selected model backend config digest does not match registration"
            }
            Self::FactoryRejected => "selected model adapter factory rejected construction",
            Self::BuiltBackendIdentityMismatch => {
                "model adapter factory built an unexpected backend identity"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ModelAdapterRegistryErrorV1 {}

/// Exact registry of model adapter factories compiled into one composition.
///
/// Resolution only compares the complete requested adapter descriptor and
/// backend identity. This type deliberately exposes no enumeration,
/// compatibility search, automatic selection, routing, or fallback operation.
#[derive(Default)]
pub struct ModelAdapterRegistryV1 {
    entries: Vec<ModelAdapterRegistryEntryV1>,
}

impl ModelAdapterRegistryV1 {
    /// Creates an empty registry for explicit startup-time registration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Registers one compiled-in configured factory under its exact descriptor.
    pub fn register<F>(&mut self, factory: F) -> Result<(), ModelAdapterRegistryErrorV1>
    where
        F: ModelAdapterFactoryV1,
    {
        let metadata = factory.metadata();
        if self
            .entries
            .iter()
            .any(|entry| entry.metadata.descriptor() == metadata.descriptor())
        {
            return Err(ModelAdapterRegistryErrorV1::DuplicateAdapterDescriptor);
        }
        self.entries.push(ModelAdapterRegistryEntryV1 {
            metadata,
            factory: Box::new(factory),
        });
        Ok(())
    }

    /// Builds only the adapter matching the complete exact selection.
    pub fn resolve(
        &self,
        selection: ModelAdapterSelectionV1,
    ) -> Result<Arc<dyn ModelBackendV1>, ModelAdapterRegistryErrorV1> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.metadata.descriptor() == selection.descriptor())
            .ok_or(ModelAdapterRegistryErrorV1::UnknownAdapterDescriptor)?;
        let registered_identity = entry.metadata.backend_identity();
        let selected_identity = selection.backend_identity();
        if registered_identity.provider_ref() != selected_identity.provider_ref() {
            return Err(ModelAdapterRegistryErrorV1::SelectionProviderRefMismatch);
        }
        if registered_identity.config_digest() != selected_identity.config_digest() {
            return Err(ModelAdapterRegistryErrorV1::SelectionConfigDigestMismatch);
        }

        let backend = entry
            .factory
            .build()
            .map_err(|_| ModelAdapterRegistryErrorV1::FactoryRejected)?;
        if backend.identity() != registered_identity {
            return Err(ModelAdapterRegistryErrorV1::BuiltBackendIdentityMismatch);
        }
        Ok(backend)
    }
}

struct ModelAdapterRegistryEntryV1 {
    metadata: ModelAdapterMetadataV1,
    factory: Box<dyn ModelAdapterFactoryV1>,
}

/// Explicit no-queue capacity for one [`ModelServiceV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelServiceConfigV1 {
    max_in_flight: usize,
}

impl ModelServiceConfigV1 {
    /// Creates a configuration with capacity in `1..=256`.
    pub const fn try_new(max_in_flight: usize) -> Result<Self, ModelServiceConfigErrorV1> {
        if max_in_flight == 0 || max_in_flight > MAX_MODEL_SERVICE_IN_FLIGHT {
            return Err(ModelServiceConfigErrorV1::MaxInFlightOutOfRange);
        }
        Ok(Self { max_in_flight })
    }

    /// Returns the maximum number of simultaneous backend calls.
    #[must_use]
    pub const fn max_in_flight(self) -> usize {
        self.max_in_flight
    }
}

/// Stable service configuration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelServiceConfigErrorV1 {
    /// Capacity must be in `1..=256`.
    MaxInFlightOutOfRange,
}

impl fmt::Display for ModelServiceConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model service max_in_flight is out of range")
    }
}

impl std::error::Error for ModelServiceConfigErrorV1 {}

/// Saturating counters for one model service instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelServiceCountersV1 {
    admitted: u64,
    completed: u64,
    abandoned: u64,
    in_flight: usize,
}

impl ModelServiceCountersV1 {
    /// Returns the number of calls handed to the backend.
    #[must_use]
    pub const fn admitted(self) -> u64 {
        self.admitted
    }

    /// Returns the number of admitted futures that reached a terminal result.
    #[must_use]
    pub const fn completed(self) -> u64 {
        self.completed
    }

    /// Returns the number of admitted futures dropped before completion.
    #[must_use]
    pub const fn abandoned(self) -> u64 {
        self.abandoned
    }

    /// Returns the number of admitted futures that still hold capacity.
    #[must_use]
    pub const fn in_flight(self) -> usize {
        self.in_flight
    }
}

/// Coherent read-only snapshot of identity, capacity, and accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelServiceSnapshotV1 {
    identity: ModelBackendIdentityV1,
    capacity: usize,
    counters: ModelServiceCountersV1,
}

impl ModelServiceSnapshotV1 {
    /// Returns the captured backend identity.
    #[must_use]
    pub const fn identity(self) -> ModelBackendIdentityV1 {
        self.identity
    }

    /// Returns the service's fixed no-queue capacity.
    #[must_use]
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// Returns the coherent saturating counters.
    #[must_use]
    pub const fn counters(self) -> ModelServiceCountersV1 {
        self.counters
    }
}

/// Provider-neutral owner of bounded admission and terminal validation.
pub struct ModelServiceV1<B: ModelBackendV1> {
    inner: Arc<ModelServiceInnerV1<B>>,
}

impl<B: ModelBackendV1> ModelServiceV1<B> {
    /// Installs one backend under a fixed bounded service configuration.
    #[must_use]
    pub fn new(config: ModelServiceConfigV1, backend: B) -> Self {
        let identity = backend.identity();
        Self {
            inner: Arc::new(ModelServiceInnerV1 {
                backend,
                accounting: Arc::new(ModelServiceAccountingV1 {
                    identity,
                    capacity: config.max_in_flight(),
                    counters: Mutex::new(ModelServiceCountersV1 {
                        admitted: 0,
                        completed: 0,
                        abandoned: 0,
                        in_flight: 0,
                    }),
                }),
            }),
        }
    }

    /// Attempts no-queue admission and returns one owned operation.
    ///
    /// Cancellation observed before admission wins over capacity refusal. Once
    /// admitted, this method calls the backend exactly once. Dropping the
    /// returned future releases its in-flight lease and records abandonment.
    #[must_use]
    pub fn invoke(
        &self,
        request: ModelInvocationRequestV1,
        cancellation: ModelCancellationViewV1,
    ) -> ModelBackendFuture {
        if cancellation.is_cancellation_requested() {
            return Box::pin(std::future::ready(
                ModelInvocationOutcomeV1::CancelledBeforeHandoff,
            ));
        }

        let Some(lease) = self.inner.accounting.try_admit() else {
            return Box::pin(std::future::ready(
                ModelInvocationOutcomeV1::CapacityExhausted,
            ));
        };
        let backend_future = self.inner.backend.invoke(request, cancellation);
        Box::pin(ModelServiceInvocationFutureV1 {
            backend_future,
            lease: Some(lease),
        })
    }

    /// Captures a coherent read-only service snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ModelServiceSnapshotV1 {
        self.inner.accounting.snapshot()
    }
}

impl<B: ModelBackendV1> Clone for ModelServiceV1<B> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct ModelServiceInnerV1<B: ModelBackendV1> {
    backend: B,
    accounting: Arc<ModelServiceAccountingV1>,
}

struct ModelServiceAccountingV1 {
    identity: ModelBackendIdentityV1,
    capacity: usize,
    counters: Mutex<ModelServiceCountersV1>,
}

impl ModelServiceAccountingV1 {
    fn try_admit(self: &Arc<Self>) -> Option<ModelInFlightLeaseV1> {
        let mut counters = self.lock_counters();
        if counters.in_flight >= self.capacity {
            return None;
        }
        counters.in_flight += 1;
        counters.admitted = counters.admitted.saturating_add(1);
        drop(counters);
        Some(ModelInFlightLeaseV1 {
            accounting: Arc::clone(self),
            settled: false,
        })
    }

    fn snapshot(&self) -> ModelServiceSnapshotV1 {
        let counters = *self.lock_counters();
        ModelServiceSnapshotV1 {
            identity: self.identity,
            capacity: self.capacity,
            counters,
        }
    }

    fn complete(&self) {
        let mut counters = self.lock_counters();
        counters.in_flight = counters.in_flight.saturating_sub(1);
        counters.completed = counters.completed.saturating_add(1);
    }

    fn abandon(&self) {
        let mut counters = self.lock_counters();
        counters.in_flight = counters.in_flight.saturating_sub(1);
        counters.abandoned = counters.abandoned.saturating_add(1);
    }

    fn lock_counters(&self) -> MutexGuard<'_, ModelServiceCountersV1> {
        self.counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct ModelInFlightLeaseV1 {
    accounting: Arc<ModelServiceAccountingV1>,
    settled: bool,
}

impl ModelInFlightLeaseV1 {
    fn complete(&mut self) {
        if !self.settled {
            self.accounting.complete();
            self.settled = true;
        }
    }
}

impl Drop for ModelInFlightLeaseV1 {
    fn drop(&mut self) {
        if !self.settled {
            self.accounting.abandon();
            self.settled = true;
        }
    }
}

struct ModelServiceInvocationFutureV1 {
    backend_future: ModelBackendFuture,
    lease: Option<ModelInFlightLeaseV1>,
}

impl Future for ModelServiceInvocationFutureV1 {
    type Output = ModelInvocationOutcomeV1;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Poll::Ready(outcome) = self.backend_future.as_mut().poll(context) else {
            return Poll::Pending;
        };
        let outcome = validate_backend_outcome(outcome);
        if let Some(mut lease) = self.lease.take() {
            lease.complete();
        }
        Poll::Ready(outcome)
    }
}

fn validate_backend_outcome(outcome: ModelInvocationOutcomeV1) -> ModelInvocationOutcomeV1 {
    match outcome {
        ModelInvocationOutcomeV1::Success(text)
            if text.len() > MAX_MODEL_INVOCATION_OUTPUT_BYTES =>
        {
            ModelInvocationOutcomeV1::Failed
        }
        // Capacity refusal is a ModelService admission decision. A backend has
        // already consumed a lease when it returns, so it cannot originate it.
        ModelInvocationOutcomeV1::CapacityExhausted => ModelInvocationOutcomeV1::Failed,
        outcome => outcome,
    }
}

const fn bytes_are_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::task::Waker;

    #[derive(Clone)]
    enum TestBehavior {
        Pending,
        Outcome(ModelInvocationOutcomeV1),
    }

    struct TestBackend {
        identity: ModelBackendIdentityV1,
        calls: Arc<AtomicUsize>,
        behavior: TestBehavior,
    }

    impl ModelBackendV1 for TestBackend {
        fn identity(&self) -> ModelBackendIdentityV1 {
            self.identity
        }

        fn invoke(
            &self,
            _request: ModelInvocationRequestV1,
            _cancellation: ModelCancellationViewV1,
        ) -> ModelBackendFuture {
            self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            match &self.behavior {
                TestBehavior::Pending => Box::pin(std::future::pending()),
                TestBehavior::Outcome(outcome) => Box::pin(std::future::ready(outcome.clone())),
            }
        }
    }

    fn backend_identity() -> ModelBackendIdentityV1 {
        ModelBackendIdentityV1::try_new([7; 16], Digest32::from_bytes([9; 32]))
            .expect("test backend identity must be valid")
    }

    fn invocation_id() -> ModelInvocationIdV1 {
        ModelInvocationIdV1::try_from_bytes([2; 16]).expect("test invocation id must be valid")
    }

    fn request(prompt: impl Into<Box<str>>) -> ModelInvocationRequestV1 {
        ModelInvocationRequestV1::try_new(
            invocation_id(),
            Digest32::from_bytes([3; 32]),
            BoundedDuration::from_nanos(1_000_000),
            prompt,
        )
        .expect("test request must be valid")
    }

    fn service(
        capacity: usize,
        behavior: TestBehavior,
    ) -> (ModelServiceV1<TestBackend>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = TestBackend {
            identity: backend_identity(),
            calls: Arc::clone(&calls),
            behavior,
        };
        let config = ModelServiceConfigV1::try_new(capacity).expect("test capacity must be valid");
        (ModelServiceV1::new(config, backend), calls)
    }

    struct TestAdapterFactory {
        metadata: ModelAdapterMetadataV1,
        built_identity: ModelBackendIdentityV1,
        reject_build: bool,
    }

    impl ModelAdapterFactoryV1 for TestAdapterFactory {
        fn metadata(&self) -> ModelAdapterMetadataV1 {
            self.metadata
        }

        fn build(&self) -> Result<Arc<dyn ModelBackendV1>, ModelAdapterBuildErrorV1> {
            if self.reject_build {
                return Err(ModelAdapterBuildErrorV1::Rejected);
            }
            Ok(Arc::new(TestBackend {
                identity: self.built_identity,
                calls: Arc::new(AtomicUsize::new(0)),
                behavior: TestBehavior::Outcome(ModelInvocationOutcomeV1::Success(
                    "registered".into(),
                )),
            }))
        }
    }

    fn adapter_id(byte: u8) -> ModelAdapterIdV1 {
        ModelAdapterIdV1::try_from_bytes([byte; 16]).expect("test adapter id must be valid")
    }

    fn adapter_version(value: u32) -> ModelAdapterVersionV1 {
        ModelAdapterVersionV1::try_new(value).expect("test adapter version must be valid")
    }

    fn capability_id(byte: u8) -> ModelCapabilityIdV1 {
        ModelCapabilityIdV1::try_from_bytes([byte; 16]).expect("test capability id must be valid")
    }

    fn adapter_descriptor(
        adapter_id: ModelAdapterIdV1,
        version: u32,
        capability_id: ModelCapabilityIdV1,
    ) -> ModelAdapterDescriptorV1 {
        ModelAdapterDescriptorV1::new(adapter_id, adapter_version(version), capability_id)
    }

    fn backend_identity_with(provider: u8, config: u8) -> ModelBackendIdentityV1 {
        ModelBackendIdentityV1::try_new([provider; 16], Digest32::from_bytes([config; 32]))
            .expect("test backend identity must be valid")
    }

    fn adapter_factory(
        descriptor: ModelAdapterDescriptorV1,
        registered_identity: ModelBackendIdentityV1,
        built_identity: ModelBackendIdentityV1,
    ) -> TestAdapterFactory {
        TestAdapterFactory {
            metadata: ModelAdapterMetadataV1::new(descriptor, registered_identity),
            built_identity,
            reject_build: false,
        }
    }

    fn poll_once(future: &mut ModelBackendFuture) -> Poll<ModelInvocationOutcomeV1> {
        let mut context = Context::from_waker(Waker::noop());
        future.as_mut().poll(&mut context)
    }

    #[test]
    fn config_and_request_validation_are_bounded() {
        assert_eq!(
            ModelServiceConfigV1::try_new(0),
            Err(ModelServiceConfigErrorV1::MaxInFlightOutOfRange)
        );
        assert_eq!(
            ModelServiceConfigV1::try_new(MAX_MODEL_SERVICE_IN_FLIGHT + 1),
            Err(ModelServiceConfigErrorV1::MaxInFlightOutOfRange)
        );
        assert_eq!(
            ModelInvocationIdV1::try_from_bytes([0; 16]),
            Err(ModelInvocationIdErrorV1::Zero)
        );
        assert_eq!(
            ModelBackendIdentityV1::try_new([0; 16], Digest32::from_bytes([1; 32])),
            Err(ModelBackendIdentityErrorV1::ZeroProviderRef)
        );
        assert_eq!(
            ModelBackendIdentityV1::try_new([1; 16], Digest32::from_bytes([0; 32])),
            Err(ModelBackendIdentityErrorV1::ZeroConfigDigest)
        );

        let valid_id = invocation_id();
        let valid_digest = Digest32::from_bytes([1; 32]);
        assert_eq!(
            ModelInvocationRequestV1::try_new(
                valid_id,
                Digest32::from_bytes([0; 32]),
                BoundedDuration::from_nanos(1),
                "prompt",
            ),
            Err(ModelInvocationRequestErrorV1::ZeroSourceRequestDigest)
        );
        assert_eq!(
            ModelInvocationRequestV1::try_new(
                valid_id,
                valid_digest,
                BoundedDuration::from_nanos(0),
                "prompt",
            ),
            Err(ModelInvocationRequestErrorV1::DeadlineOutOfRange)
        );
        assert_eq!(
            ModelInvocationRequestV1::try_new(
                valid_id,
                valid_digest,
                BoundedDuration::from_nanos(MAX_MODEL_INVOCATION_DEADLINE_NANOS + 1),
                "prompt",
            ),
            Err(ModelInvocationRequestErrorV1::DeadlineOutOfRange)
        );
        assert_eq!(
            ModelInvocationRequestV1::try_new(
                valid_id,
                valid_digest,
                BoundedDuration::from_nanos(1),
                "",
            ),
            Err(ModelInvocationRequestErrorV1::EmptyPrompt)
        );
        assert_eq!(
            ModelInvocationRequestV1::try_new(
                valid_id,
                valid_digest,
                BoundedDuration::from_nanos(1),
                "x".repeat(MAX_MODEL_INVOCATION_INPUT_BYTES + 1),
            ),
            Err(ModelInvocationRequestErrorV1::PromptTooLong)
        );

        let valid = request("界");
        assert_eq!(valid.prompt(), "界");
        assert_eq!(valid.deadline_budget().value(), 1_000_000);
    }

    #[test]
    fn exact_adapter_selection_builds_a_backend_usable_by_model_service() {
        let descriptor = adapter_descriptor(adapter_id(41), 1, capability_id(44));
        let identity = backend_identity_with(42, 43);
        let mut registry = ModelAdapterRegistryV1::new();
        registry
            .register(adapter_factory(descriptor, identity, identity))
            .expect("first adapter registration must succeed");

        let backend = registry
            .resolve(ModelAdapterSelectionV1::new(descriptor, identity))
            .expect("exact registered selection must resolve");
        let service = ModelServiceV1::new(
            ModelServiceConfigV1::try_new(1).expect("test capacity must be valid"),
            backend,
        );
        let cancellation = ModelCancellationSourceV1::new();
        let mut future = service.invoke(request("registry"), cancellation.view());

        assert_eq!(service.snapshot().identity(), identity);
        assert_eq!(
            poll_once(&mut future),
            Poll::Ready(ModelInvocationOutcomeV1::Success("registered".into()))
        );
    }

    #[test]
    fn adapter_registry_requires_an_exact_nonzero_descriptor() {
        assert_eq!(
            ModelAdapterIdV1::try_from_bytes([0; 16]),
            Err(ModelAdapterIdErrorV1::Zero)
        );
        assert_eq!(
            ModelAdapterVersionV1::try_new(0),
            Err(ModelAdapterVersionErrorV1::Zero)
        );
        assert_eq!(
            ModelCapabilityIdV1::try_from_bytes([0; 16]),
            Err(ModelCapabilityIdErrorV1::Zero)
        );

        let registered_adapter = adapter_id(51);
        let registered_capability = capability_id(57);
        let registered_descriptor =
            adapter_descriptor(registered_adapter, 1, registered_capability);
        let identity = backend_identity_with(52, 53);
        let mut registry = ModelAdapterRegistryV1::new();
        registry
            .register(adapter_factory(registered_descriptor, identity, identity))
            .expect("first adapter registration must succeed");
        assert_eq!(
            registry.register(adapter_factory(registered_descriptor, identity, identity)),
            Err(ModelAdapterRegistryErrorV1::DuplicateAdapterDescriptor)
        );

        let version_two_descriptor =
            adapter_descriptor(registered_adapter, 2, registered_capability);
        registry
            .register(adapter_factory(version_two_descriptor, identity, identity))
            .expect("a distinct adapter version must be independently registrable");
        assert!(
            registry
                .resolve(ModelAdapterSelectionV1::new(
                    version_two_descriptor,
                    identity,
                ))
                .is_ok()
        );

        let alternate_capability_descriptor =
            adapter_descriptor(registered_adapter, 1, capability_id(58));
        registry
            .register(adapter_factory(
                alternate_capability_descriptor,
                identity,
                identity,
            ))
            .expect("a distinct adapter capability must be independently registrable");
        assert!(
            registry
                .resolve(ModelAdapterSelectionV1::new(
                    alternate_capability_descriptor,
                    identity,
                ))
                .is_ok()
        );

        assert!(matches!(
            registry.resolve(ModelAdapterSelectionV1::new(
                adapter_descriptor(adapter_id(54), 1, registered_capability),
                identity,
            )),
            Err(ModelAdapterRegistryErrorV1::UnknownAdapterDescriptor)
        ));
        assert!(matches!(
            registry.resolve(ModelAdapterSelectionV1::new(
                adapter_descriptor(registered_adapter, 3, registered_capability),
                identity,
            )),
            Err(ModelAdapterRegistryErrorV1::UnknownAdapterDescriptor)
        ));
        assert!(matches!(
            registry.resolve(ModelAdapterSelectionV1::new(
                adapter_descriptor(registered_adapter, 1, capability_id(59)),
                identity,
            )),
            Err(ModelAdapterRegistryErrorV1::UnknownAdapterDescriptor)
        ));
        assert!(matches!(
            registry.resolve(ModelAdapterSelectionV1::new(
                registered_descriptor,
                backend_identity_with(55, 53),
            )),
            Err(ModelAdapterRegistryErrorV1::SelectionProviderRefMismatch)
        ));
        assert!(matches!(
            registry.resolve(ModelAdapterSelectionV1::new(
                registered_descriptor,
                backend_identity_with(52, 56),
            )),
            Err(ModelAdapterRegistryErrorV1::SelectionConfigDigestMismatch)
        ));
    }

    #[test]
    fn adapter_registry_rejects_factory_failure_and_built_identity_drift() {
        let identity = backend_identity_with(61, 62);
        let rejecting_descriptor = adapter_descriptor(adapter_id(63), 1, capability_id(66));
        let mut registry = ModelAdapterRegistryV1::new();
        registry
            .register(TestAdapterFactory {
                metadata: ModelAdapterMetadataV1::new(rejecting_descriptor, identity),
                built_identity: identity,
                reject_build: true,
            })
            .expect("rejecting factory registration must succeed");
        assert!(matches!(
            registry.resolve(ModelAdapterSelectionV1::new(rejecting_descriptor, identity,)),
            Err(ModelAdapterRegistryErrorV1::FactoryRejected)
        ));

        let drifting_descriptor = adapter_descriptor(adapter_id(64), 1, capability_id(66));
        registry
            .register(adapter_factory(
                drifting_descriptor,
                identity,
                backend_identity_with(61, 65),
            ))
            .expect("drifting factory registration must succeed");
        assert!(matches!(
            registry.resolve(ModelAdapterSelectionV1::new(drifting_descriptor, identity,)),
            Err(ModelAdapterRegistryErrorV1::BuiltBackendIdentityMismatch)
        ));
    }

    #[test]
    fn capacity_refuses_concurrent_work_without_queueing_or_backend_call() {
        let (service, calls) = service(1, TestBehavior::Pending);
        let first_cancellation = ModelCancellationSourceV1::new();
        let first = service.invoke(request("first"), first_cancellation.view());
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(service.snapshot().counters().in_flight(), 1);

        let second_cancellation = ModelCancellationSourceV1::new();
        let mut refused = service.invoke(request("second"), second_cancellation.view());
        assert_eq!(
            poll_once(&mut refused),
            Poll::Ready(ModelInvocationOutcomeV1::CapacityExhausted)
        );
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(service.snapshot().counters().admitted(), 1);

        drop(first);
        let snapshot = service.snapshot();
        assert_eq!(snapshot.counters().in_flight(), 0);
        assert_eq!(snapshot.counters().abandoned(), 1);
    }

    #[test]
    fn cancellation_before_handoff_does_not_call_backend() {
        let (service, calls) = service(1, TestBehavior::Pending);
        let cancellation = ModelCancellationSourceV1::new();
        cancellation.request_cancellation();
        let mut future = service.invoke(request("cancelled"), cancellation.view());

        assert_eq!(
            poll_once(&mut future),
            Poll::Ready(ModelInvocationOutcomeV1::CancelledBeforeHandoff)
        );
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(
            service.snapshot().counters(),
            ModelServiceCountersV1 {
                admitted: 0,
                completed: 0,
                abandoned: 0,
                in_flight: 0,
            }
        );
    }

    #[test]
    fn completion_and_drop_both_release_the_in_flight_lease() {
        let (completed_service, _) = service(
            1,
            TestBehavior::Outcome(ModelInvocationOutcomeV1::Success("done".into())),
        );
        let completed_cancellation = ModelCancellationSourceV1::new();
        let mut completed =
            completed_service.invoke(request("complete"), completed_cancellation.view());
        assert_eq!(completed_service.snapshot().counters().in_flight(), 1);
        assert_eq!(
            poll_once(&mut completed),
            Poll::Ready(ModelInvocationOutcomeV1::Success("done".into()))
        );
        let completed_snapshot = completed_service.snapshot();
        assert_eq!(completed_snapshot.identity(), backend_identity());
        assert_eq!(completed_snapshot.capacity(), 1);
        assert_eq!(completed_snapshot.counters().in_flight(), 0);
        assert_eq!(completed_snapshot.counters().completed(), 1);
        assert_eq!(completed_snapshot.counters().abandoned(), 0);

        let (abandoned_service, _) = service(1, TestBehavior::Pending);
        let abandoned_cancellation = ModelCancellationSourceV1::new();
        let abandoned = abandoned_service.invoke(request("abandon"), abandoned_cancellation.view());
        assert_eq!(abandoned_service.snapshot().counters().in_flight(), 1);
        drop(abandoned);
        let abandoned_snapshot = abandoned_service.snapshot().counters();
        assert_eq!(abandoned_snapshot.in_flight(), 0);
        assert_eq!(abandoned_snapshot.completed(), 0);
        assert_eq!(abandoned_snapshot.abandoned(), 1);
    }

    #[test]
    fn oversized_backend_success_fails_closed() {
        let oversized = "x".repeat(MAX_MODEL_INVOCATION_OUTPUT_BYTES + 1);
        let (service, calls) = service(
            1,
            TestBehavior::Outcome(ModelInvocationOutcomeV1::Success(
                oversized.into_boxed_str(),
            )),
        );
        let cancellation = ModelCancellationSourceV1::new();
        let mut future = service.invoke(request("bounded"), cancellation.view());

        assert_eq!(
            poll_once(&mut future),
            Poll::Ready(ModelInvocationOutcomeV1::Failed)
        );
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(service.snapshot().counters().completed(), 1);
    }

    #[test]
    fn backend_can_report_cancellation_before_real_provider_handoff() {
        let (service, calls) = service(
            1,
            TestBehavior::Outcome(ModelInvocationOutcomeV1::CancelledBeforeHandoff),
        );
        let cancellation = ModelCancellationSourceV1::new();
        let mut future = service.invoke(request("cancel while scheduling"), cancellation.view());

        assert_eq!(
            poll_once(&mut future),
            Poll::Ready(ModelInvocationOutcomeV1::CancelledBeforeHandoff)
        );
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(service.snapshot().counters().completed(), 1);
    }
}
