//! Zenoh-native Fabric ownership for ParaEGOX.
//!
//! [`FabricService`] owns its general typed-binding Zenoh session. The narrow
//! restricted Runtime-apply/Runtime-control and Unix Node-control clients and
//! endpoints own separate role-scoped query-only sessions; every raw transport
//! value remains private. Callers use versioned envelopes, owner-issued
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
#[cfg(unix)]
pub use runtime_apply::{
    RestrictedNodeControlClientConfigV1, RestrictedNodeControlClientV1,
    RestrictedNodeControlConfigErrorV1, RestrictedNodeControlEndpointConfigV1,
    RestrictedNodeControlEndpointV1, RestrictedNodeControlErrorV1, RestrictedNodeControlInboundV1,
    RestrictedNodeControlPreflightV1, RestrictedNodeControlReceiverV1,
    RestrictedNodeControlRespondErrorV1, RestrictedNodeControlTransportPinsV1,
};
pub use runtime_apply::{
    RestrictedRuntimeApplyClientConfigV1, RestrictedRuntimeApplyClientV1,
    RestrictedRuntimeApplyConfigErrorV1, RestrictedRuntimeApplyEndpointConfigV1,
    RestrictedRuntimeApplyEndpointV1, RestrictedRuntimeApplyErrorV1,
    RestrictedRuntimeApplyInboundV1, RestrictedRuntimeApplyPreflightV1,
    RestrictedRuntimeApplyReceiverV1, RestrictedRuntimeApplyRespondErrorV1,
    RestrictedRuntimeControlClientConfigV1, RestrictedRuntimeControlClientV1,
    RestrictedRuntimeControlConfigErrorV1, RestrictedRuntimeControlEndpointConfigV1,
    RestrictedRuntimeControlEndpointV1, RestrictedRuntimeControlErrorV1,
    RestrictedRuntimeControlInboundV1, RestrictedRuntimeControlPreflightV1,
    RestrictedRuntimeControlReceiverV1, RestrictedRuntimeControlRespondErrorV1,
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
