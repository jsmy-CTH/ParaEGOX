//! Zenoh-native Fabric ownership for ParaEGOX.
//!
//! [`FabricService`] owns its general typed-binding Zenoh session. The narrow
//! restricted Runtime-apply client and endpoint own separate role-scoped
//! query-only sessions; every raw transport value remains private. Callers use versioned envelopes, owner-issued
//! [`PortBinding`] tokens, request-only [`ClientPortBindingV1`] routes, and a
//! bounded typed request receiver. The v1 binary encoding is an experimental,
//! Fabric-owned contract until a separately governed cross-language consumer
//! adopts it; this crate does not claim a stable polyglot ABI.

#![forbid(unsafe_code)]

mod contract;
mod ingress;
mod port_descriptor;
mod runtime_apply;
mod service;

pub use contract::{
    BindingEpoch, BindingRequestEnvelopeV1, BindingResponseEnvelopeV1, FabricContractError,
    REQUEST_RESPONSE_ENVELOPE_VERSION, RequestId, ResponseStatus,
};
pub use ingress::{FabricIngressSnapshot, IngressLimitError, IngressLimits};
pub use port_descriptor::{
    MAX_PORT_BINDING_DESCRIPTOR_BYTES, PORT_BINDING_DESCRIPTOR_HEADER_BYTES,
    PORT_BINDING_DESCRIPTOR_VERSION, PortBindingDescriptorError, PortBindingDescriptorV1,
};
pub use runtime_apply::{
    RestrictedRuntimeApplyClientConfigV1, RestrictedRuntimeApplyClientV1,
    RestrictedRuntimeApplyConfigErrorV1, RestrictedRuntimeApplyEndpointConfigV1,
    RestrictedRuntimeApplyEndpointV1, RestrictedRuntimeApplyErrorV1,
    RestrictedRuntimeApplyInboundV1, RestrictedRuntimeApplyPreflightV1,
    RestrictedRuntimeApplyReceiverV1, RestrictedRuntimeApplyRespondErrorV1,
    restricted_runtime_apply_peer_certificate_common_name_v1,
};
pub use service::{
    ClientPortBindingV1, ExperimentalPeerCommonNameV1, ExperimentalRemoteMtlsConfigErrorV1,
    ExperimentalRemoteMtlsLinkSnapshotV1, ExperimentalRemoteMtlsObservationErrorV1,
    ExperimentalRemoteMtlsPeerBindingV1, ExperimentalRemoteMtlsPeerLinkObservationV1,
    FabricConfigError, FabricError, FabricService, FabricServiceConfig, HandlerResponse,
    InboundRequest, InstalledBinding, PortBinding, RemoteTlsEndpoint, RequestReceiver,
    RequestResponseBindingSpec, ResolvedRemoteMtlsCredentialFiles, ResolvedRemoteMtlsIdentityFiles,
    SessionEndpoint,
};
