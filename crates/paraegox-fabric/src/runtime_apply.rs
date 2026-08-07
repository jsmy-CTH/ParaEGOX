//! Restricted Controller-to-Runtime query transport for canonical apply bytes.
//!
//! This module owns only transport mechanics. It never decodes, authenticates,
//! signs, admits, or persists PXRC, PXAR, or PXDS values. The Controller side
//! has one connector-only TLS session and the Runtime side has one
//! listener-only TLS session. Their application-message ACL exposes one exact
//! query route; Zenoh still owns its internal control-plane and link maintenance.
//! The configured custom CA is not an exclusive trust store in Zenoh 1.9, so
//! the ACL additionally binds the exact peer certificate common name. PXRC and
//! PXDS signature verification remains mandatory in the owning composition.

use core::{fmt, time::Duration};
use std::{path::PathBuf, sync::Arc};

use paraegox_kernel::{
    digest::Digest32,
    identity::{PrincipalRef, RuntimeHostId},
};
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES,
    MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES,
    MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES, RestrictedRuntimeApplyCarrierBindingV1,
    RestrictedRuntimeApplyTransportProfileV1,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::Instant,
};
use zenoh::{
    key_expr::OwnedNonWildKeyExpr,
    query::{ConsolidationMode, Querier, Query, QueryTarget, Queryable, Reply, ReplyKeyExpr},
};

use crate::service::{
    FabricError, RemoteMtlsRole, RemoteTlsEndpoint, ResolvedRemoteMtlsIdentityFiles,
    configure_remote_mtls_role, endpoint_array_json, json_string, set_endpoints, set_protocols,
    validate_tls_file_path,
};
use crate::{
    IngressLimits,
    ingress::{IngressBudget, IngressLease},
};

const RESTRICTED_INGRESS_CAPACITY: usize = 1;
const RESTRICTED_HANDLER_CAPACITY: usize = 1;
const RESTRICTED_REPLY_CAPACITY: usize = 1;
const RESTRICTED_ZENOH_FRAMING_ALLOWANCE_BYTES: usize = 64 * 1024;
const REMOTE_REJECTION_BODY: &[u8] = b"restricted runtime apply rejected";

/// Controller-owned, connector-only configuration for one Runtime endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct RestrictedRuntimeApplyClientConfigV1 {
    endpoint: RemoteTlsEndpoint,
    route: OwnedNonWildKeyExpr,
    root_ca_certificate_file: Box<str>,
    connector_identity: ResolvedRemoteMtlsIdentityFiles,
    expected_target: RuntimeHostId,
    expected_runtime_principal: PrincipalRef,
    expected_carrier_binding_digest: Digest32,
    operation_timeout: Duration,
}

impl RestrictedRuntimeApplyClientConfigV1 {
    /// Maps one exact canonical PXRP/PXCB pair into the Controller connector
    /// role after the composition owner resolves its non-secret profile ref.
    pub fn try_from_transport_profile(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        resolved_profile_ref: [u8; 16],
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        root_ca_certificate_file: PathBuf,
        connector_identity: ResolvedRemoteMtlsIdentityFiles,
    ) -> Result<Self, RestrictedRuntimeApplyConfigErrorV1> {
        profile
            .validate_carrier_binding(resolved_profile_ref, carrier)
            .map_err(|_| RestrictedRuntimeApplyConfigErrorV1::ProfileCarrierMismatch)?;
        let endpoint =
            RemoteTlsEndpoint::try_new(profile.tls_listener_locator().as_str().to_owned())
                .map_err(|_| RestrictedRuntimeApplyConfigErrorV1::ProfileEndpointMappingMismatch)?;
        if endpoint.as_str() != profile.tls_listener_locator().as_str() {
            return Err(RestrictedRuntimeApplyConfigErrorV1::ProfileEndpointMappingMismatch);
        }
        Self::try_new(
            endpoint,
            profile.route(),
            root_ca_certificate_file,
            connector_identity,
            profile.target(),
            profile.runtime_principal(),
            carrier.binding_digest(),
            Duration::from_nanos(profile.operation_timeout_nanos()),
        )
    }

    /// Validates one explicit endpoint, route, connector identity, expected
    /// RuntimeHost target, Runtime certificate principal, exact PXCB binding
    /// digest, and deadline.
    ///
    /// The Runtime certificate Common Name must use the deterministic
    /// `paraegox-principal-<lowercase-principal-hex>` form.
    fn try_new(
        endpoint: RemoteTlsEndpoint,
        route: impl Into<String>,
        root_ca_certificate_file: PathBuf,
        connector_identity: ResolvedRemoteMtlsIdentityFiles,
        expected_target: RuntimeHostId,
        expected_runtime_principal: PrincipalRef,
        expected_carrier_binding_digest: Digest32,
        operation_timeout: Duration,
    ) -> Result<Self, RestrictedRuntimeApplyConfigErrorV1> {
        let operation_timeout = validate_timeout(operation_timeout)?;
        validate_target(expected_target)?;
        validate_principal(expected_runtime_principal)?;
        validate_digest(expected_carrier_binding_digest)?;
        Ok(Self {
            endpoint,
            route: validate_route(route.into())?,
            root_ca_certificate_file: validate_tls_file_path(&root_ca_certificate_file)
                .map_err(|_| RestrictedRuntimeApplyConfigErrorV1::InvalidTlsFilePath)?
                .into(),
            connector_identity,
            expected_target,
            expected_runtime_principal,
            expected_carrier_binding_digest,
            operation_timeout,
        })
    }

    /// Returns the sole selected query route.
    #[must_use]
    pub fn route(&self) -> &str {
        self.route.as_str()
    }

    fn build_zenoh_config(&self) -> Result<zenoh::Config, FabricError> {
        build_restricted_zenoh_config(
            RestrictedSessionRole::ControllerConnector,
            &self.endpoint,
            self.route(),
            &self.root_ca_certificate_file,
            &self.connector_identity,
            self.expected_runtime_principal,
        )
    }
}

impl fmt::Debug for RestrictedRuntimeApplyClientConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestrictedRuntimeApplyClientConfigV1")
            .field("role", &"controller-connector-only")
            .field("endpoint", &self.endpoint)
            .field("route", &"<owner-selected-route>")
            .field("root_ca_certificate_file", &"<redacted-resolved-path>")
            .field("connector_identity", &"<redacted>")
            .field("expected_target", &"<redacted>")
            .field("expected_runtime_principal", &"<redacted>")
            .field("expected_carrier_binding_digest", &"<redacted>")
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

/// Runtime-owned, listener-only configuration for one exact apply route.
#[derive(Clone, Eq, PartialEq)]
pub struct RestrictedRuntimeApplyEndpointConfigV1 {
    endpoint: RemoteTlsEndpoint,
    route: OwnedNonWildKeyExpr,
    root_ca_certificate_file: Box<str>,
    listener_identity: ResolvedRemoteMtlsIdentityFiles,
    expected_target: RuntimeHostId,
    expected_controller_principal: PrincipalRef,
    expected_carrier_binding_digest: Digest32,
    handler_timeout: Duration,
}

impl RestrictedRuntimeApplyEndpointConfigV1 {
    /// Maps one exact canonical PXRP/PXCB pair into the Runtime listener role
    /// after the composition owner resolves its non-secret profile ref.
    pub fn try_from_transport_profile(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        resolved_profile_ref: [u8; 16],
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        root_ca_certificate_file: PathBuf,
        listener_identity: ResolvedRemoteMtlsIdentityFiles,
    ) -> Result<Self, RestrictedRuntimeApplyConfigErrorV1> {
        profile
            .validate_carrier_binding(resolved_profile_ref, carrier)
            .map_err(|_| RestrictedRuntimeApplyConfigErrorV1::ProfileCarrierMismatch)?;
        let endpoint =
            RemoteTlsEndpoint::try_new(profile.tls_listener_locator().as_str().to_owned())
                .map_err(|_| RestrictedRuntimeApplyConfigErrorV1::ProfileEndpointMappingMismatch)?;
        if endpoint.as_str() != profile.tls_listener_locator().as_str() {
            return Err(RestrictedRuntimeApplyConfigErrorV1::ProfileEndpointMappingMismatch);
        }
        Self::try_new(
            endpoint,
            profile.route(),
            root_ca_certificate_file,
            listener_identity,
            profile.target(),
            profile.controller_principal(),
            carrier.binding_digest(),
            Duration::from_nanos(profile.operation_timeout_nanos()),
        )
    }

    /// Validates one explicit endpoint, route, listener identity, expected
    /// Controller certificate principal, and handler bound.
    ///
    /// The Controller certificate Common Name must use the deterministic
    /// `paraegox-principal-<lowercase-principal-hex>` form.
    fn try_new(
        endpoint: RemoteTlsEndpoint,
        route: impl Into<String>,
        root_ca_certificate_file: PathBuf,
        listener_identity: ResolvedRemoteMtlsIdentityFiles,
        expected_target: RuntimeHostId,
        expected_controller_principal: PrincipalRef,
        expected_carrier_binding_digest: Digest32,
        handler_timeout: Duration,
    ) -> Result<Self, RestrictedRuntimeApplyConfigErrorV1> {
        let handler_timeout = validate_timeout(handler_timeout)?;
        validate_target(expected_target)?;
        validate_principal(expected_controller_principal)?;
        validate_digest(expected_carrier_binding_digest)?;
        restricted_ingress_limits(handler_timeout)?;
        Ok(Self {
            endpoint,
            route: validate_route(route.into())?,
            root_ca_certificate_file: validate_tls_file_path(&root_ca_certificate_file)
                .map_err(|_| RestrictedRuntimeApplyConfigErrorV1::InvalidTlsFilePath)?
                .into(),
            listener_identity,
            expected_target,
            expected_controller_principal,
            expected_carrier_binding_digest,
            handler_timeout,
        })
    }

    /// Returns the sole served query route.
    #[must_use]
    pub fn route(&self) -> &str {
        self.route.as_str()
    }

    /// Checks exact non-authorizing PXCB correlation before the listener can
    /// enter a Runtime process owner.
    #[must_use]
    pub fn matches_restricted_carrier(
        &self,
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    ) -> bool {
        self.expected_target == carrier.target()
            && self.route.as_str() == carrier.route()
            && self.expected_controller_principal == carrier.controller_principal()
            && self.expected_carrier_binding_digest == carrier.binding_digest()
    }

    fn build_zenoh_config(&self) -> Result<zenoh::Config, FabricError> {
        build_restricted_zenoh_config(
            RestrictedSessionRole::RuntimeListener,
            &self.endpoint,
            self.route(),
            &self.root_ca_certificate_file,
            &self.listener_identity,
            self.expected_controller_principal,
        )
    }
}

impl fmt::Debug for RestrictedRuntimeApplyEndpointConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestrictedRuntimeApplyEndpointConfigV1")
            .field("role", &"runtime-listener-only")
            .field("endpoint", &self.endpoint)
            .field("route", &"<owner-selected-route>")
            .field("root_ca_certificate_file", &"<redacted-resolved-path>")
            .field("listener_identity", &"<redacted>")
            .field("expected_target", &"<redacted>")
            .field("expected_controller_principal", &"<redacted>")
            .field("expected_carrier_binding_digest", &"<redacted>")
            .field("handler_timeout", &self.handler_timeout)
            .finish()
    }
}

#[derive(Clone, Copy)]
enum RestrictedSessionRole {
    ControllerConnector,
    RuntimeListener,
}

fn build_restricted_zenoh_config(
    role: RestrictedSessionRole,
    endpoint: &RemoteTlsEndpoint,
    route: &str,
    root_ca_certificate_file: &str,
    identity: &ResolvedRemoteMtlsIdentityFiles,
    expected_peer_principal: PrincipalRef,
) -> Result<zenoh::Config, FabricError> {
    let mut config = zenoh::Config::default();
    let (mode, listen_endpoints, connect_endpoints, tls_role) = match role {
        RestrictedSessionRole::ControllerConnector => (
            r#""client""#,
            endpoint_array_json(core::iter::empty()),
            endpoint_array_json(core::iter::once(endpoint.as_str())),
            RemoteMtlsRole::Connector,
        ),
        RestrictedSessionRole::RuntimeListener => (
            r#""peer""#,
            endpoint_array_json(core::iter::once(endpoint.as_str())),
            endpoint_array_json(core::iter::empty()),
            RemoteMtlsRole::Listener,
        ),
    };
    for (key, value) in [
        ("mode", mode),
        ("scouting/multicast/enabled", "false"),
        ("scouting/gossip/enabled", "false"),
        ("connect/timeout_ms", "0"),
        ("connect/exit_on_failure", "true"),
        ("listen/timeout_ms", "0"),
        ("listen/exit_on_failure", "true"),
        ("open/return_conditions/connect_scouted", "false"),
        ("open/return_conditions/declares", "true"),
        ("adminspace/enabled", "false"),
        ("plugins_loading/enabled", "false"),
        ("transport/unicast/accept_pending", "1"),
        ("transport/unicast/max_sessions", "1"),
        ("transport/unicast/max_links", "1"),
        ("transport/link/tls/verify_name_on_connect", "true"),
        ("transport/link/tls/close_link_on_expiration", "true"),
    ] {
        config
            .insert_json5(key, value)
            .map_err(|_| FabricError::SessionConfigurationFailed)?;
    }
    config
        .insert_json5(
            "transport/link/rx/max_message_size",
            &restricted_transport_message_limit().to_string(),
        )
        .map_err(|_| FabricError::SessionConfigurationFailed)?;
    set_protocols(&mut config, r#"["tls"]"#)?;
    set_endpoints(&mut config, listen_endpoints, connect_endpoints)?;
    configure_remote_mtls_role(&mut config, root_ca_certificate_file, identity, tls_role)?;
    configure_query_only_acl(&mut config, route, role, expected_peer_principal)?;
    Ok(config)
}

fn configure_query_only_acl(
    config: &mut zenoh::Config,
    route: &str,
    role: RestrictedSessionRole,
    expected_peer_principal: PrincipalRef,
) -> Result<(), FabricError> {
    // Zenoh 1.9 can constrain application messages and queryable declarations
    // by role, flow, and key expression. Its ACL schema has no ordinary
    // (non-liveliness) Interest message kind; Zenoh leaves that matching
    // control-plane traffic unfiltered internally.
    let route = json_string(route);
    let expected_peer_common_name = json_string(
        &restricted_runtime_apply_peer_certificate_common_name_v1(expected_peer_principal),
    );
    let (egress_rule, egress_messages, ingress_rule, ingress_messages) = match role {
        RestrictedSessionRole::ControllerConnector => (
            "controller-egress-query-v1",
            r#"["query"]"#,
            "controller-ingress-reply-v1",
            // Queryable declarations are the control-plane input required by
            // the matching preflight; Controller application data remains
            // query-egress/reply-ingress only.
            r#"["reply","declare_queryable"]"#,
        ),
        RestrictedSessionRole::RuntimeListener => (
            "runtime-egress-reply-v1",
            r#"["reply","declare_queryable"]"#,
            "runtime-ingress-query-v1",
            r#"["query"]"#,
        ),
    };
    let acl = format!(
        r#"{{
            "enabled": true,
            "default_permission": "deny",
            "rules": [{{
                "id": "{egress_rule}",
                "permission": "allow",
                "flows": ["egress"],
                "messages": {egress_messages},
                "key_exprs": [{route}]
            }}, {{
                "id": "{ingress_rule}",
                "permission": "allow",
                "flows": ["ingress"],
                "messages": {ingress_messages},
                "key_exprs": [{route}]
            }}],
            "subjects": [{{
                "id": "expected-peer-v1",
                "cert_common_names": [{expected_peer_common_name}]
            }}],
            "policies": [{{
                "rules": ["{egress_rule}", "{ingress_rule}"],
                "subjects": ["expected-peer-v1"]
            }}]
        }}"#
    );
    config
        .insert_json5("access_control", &acl)
        .map_err(|_| FabricError::SessionConfigurationFailed)
}

/// Returns the exact certificate Common Name enforced by the restricted
/// Runtime-apply ACL for one authenticated peer principal.
///
/// Credential enrollment code must call this owner function rather than
/// reproduce the prefix or hexadecimal encoding in another crate.
#[must_use]
pub fn restricted_runtime_apply_peer_certificate_common_name_v1(principal: PrincipalRef) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut common_name = String::from("paraegox-principal-");
    for byte in principal.as_bytes() {
        common_name.push(char::from(LOWER_HEX[usize::from(*byte >> 4)]));
        common_name.push(char::from(LOWER_HEX[usize::from(*byte & 0x0f)]));
    }
    common_name
}

fn validate_principal(principal: PrincipalRef) -> Result<(), RestrictedRuntimeApplyConfigErrorV1> {
    if principal.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(RestrictedRuntimeApplyConfigErrorV1::ZeroPeerPrincipal);
    }
    Ok(())
}

fn validate_target(target: RuntimeHostId) -> Result<(), RestrictedRuntimeApplyConfigErrorV1> {
    if target.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(RestrictedRuntimeApplyConfigErrorV1::ZeroTarget);
    }
    Ok(())
}

fn validate_digest(digest: Digest32) -> Result<(), RestrictedRuntimeApplyConfigErrorV1> {
    if digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(RestrictedRuntimeApplyConfigErrorV1::ZeroCarrierBindingDigest);
    }
    Ok(())
}

fn restricted_transport_message_limit() -> usize {
    MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES
        .max(MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES)
        .saturating_add(RESTRICTED_ZENOH_FRAMING_ALLOWANCE_BYTES)
}

fn validate_route(
    route: String,
) -> Result<OwnedNonWildKeyExpr, RestrictedRuntimeApplyConfigErrorV1> {
    if route.is_empty() {
        return Err(RestrictedRuntimeApplyConfigErrorV1::EmptyRoute);
    }
    if route.len() > MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES {
        return Err(RestrictedRuntimeApplyConfigErrorV1::RouteTooLong);
    }
    if !route.is_ascii() || route.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(RestrictedRuntimeApplyConfigErrorV1::InvalidRoute);
    }
    OwnedNonWildKeyExpr::try_from(route)
        .map_err(|_| RestrictedRuntimeApplyConfigErrorV1::InvalidRoute)
}

fn validate_timeout(timeout: Duration) -> Result<Duration, RestrictedRuntimeApplyConfigErrorV1> {
    if timeout.is_zero() {
        return Err(RestrictedRuntimeApplyConfigErrorV1::ZeroTimeout);
    }
    if std::time::Instant::now().checked_add(timeout).is_none() {
        return Err(RestrictedRuntimeApplyConfigErrorV1::TimeoutTooLarge);
    }
    Ok(timeout)
}

fn restricted_ingress_limits(
    handler_timeout: Duration,
) -> Result<IngressLimits, RestrictedRuntimeApplyConfigErrorV1> {
    IngressLimits::try_new(
        RESTRICTED_INGRESS_CAPACITY,
        MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES,
        MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES,
        MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES,
        handler_timeout,
    )
    .map_err(|_| RestrictedRuntimeApplyConfigErrorV1::ContractBoundsUnsupported)
}

/// Invalid restricted transport configuration rejected before session startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestrictedRuntimeApplyConfigErrorV1 {
    ProfileCarrierMismatch,
    ProfileEndpointMappingMismatch,
    EmptyRoute,
    RouteTooLong,
    InvalidRoute,
    InvalidTlsFilePath,
    ZeroTarget,
    ZeroPeerPrincipal,
    ZeroCarrierBindingDigest,
    ZeroTimeout,
    TimeoutTooLarge,
    ContractBoundsUnsupported,
}

impl fmt::Display for RestrictedRuntimeApplyConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProfileCarrierMismatch => {
                "restricted apply transport profile does not match the exact carrier"
            }
            Self::ProfileEndpointMappingMismatch => {
                "restricted apply transport profile endpoint mapping failed"
            }
            Self::EmptyRoute => "restricted apply route must not be empty",
            Self::RouteTooLong => "restricted apply route exceeds its contract bound",
            Self::InvalidRoute => "restricted apply route must be one canonical concrete key",
            Self::InvalidTlsFilePath => {
                "restricted apply TLS path must be absolute, normalized, bounded UTF-8"
            }
            Self::ZeroTarget => "restricted apply expected Runtime target must not be zero",
            Self::ZeroPeerPrincipal => "restricted apply expected peer principal must not be zero",
            Self::ZeroCarrierBindingDigest => {
                "restricted apply expected carrier binding digest must not be zero"
            }
            Self::ZeroTimeout => "restricted apply timeout must be nonzero",
            Self::TimeoutTooLarge => "restricted apply timeout is not representable",
            Self::ContractBoundsUnsupported => {
                "restricted apply contract bounds exceed Fabric ingress limits"
            }
        })
    }
}

impl std::error::Error for RestrictedRuntimeApplyConfigErrorV1 {}

/// Connector-only Controller transport. Its Zenoh session is never exposed.
pub struct RestrictedRuntimeApplyClientV1 {
    session: zenoh::Session,
    route: OwnedNonWildKeyExpr,
    expected_target: RuntimeHostId,
    expected_runtime_principal: PrincipalRef,
    expected_carrier_binding_digest: Digest32,
    operation_timeout: Duration,
    deferred_querier_cleanup_failure: bool,
}

impl RestrictedRuntimeApplyClientV1 {
    /// Opens one explicit TLS connector without scouting or application retry.
    ///
    /// Zenoh may maintain or reconnect its link while this client is alive; it
    /// does not re-issue a completed or failed request from this module.
    pub async fn start(
        config: RestrictedRuntimeApplyClientConfigV1,
    ) -> Result<Self, RestrictedRuntimeApplyErrorV1> {
        let zenoh_config = config
            .build_zenoh_config()
            .map_err(RestrictedRuntimeApplyErrorV1::Fabric)?;
        let session = zenoh::open(zenoh_config)
            .await
            .map_err(|_| RestrictedRuntimeApplyErrorV1::SessionOpenFailed)?;
        Ok(Self {
            session,
            route: config.route,
            expected_target: config.expected_target,
            expected_runtime_principal: config.expected_runtime_principal,
            expected_carrier_binding_digest: config.expected_carrier_binding_digest,
            operation_timeout: config.operation_timeout,
            deferred_querier_cleanup_failure: false,
        })
    }

    /// Checks non-authorizing target correlation before a Controller journal
    /// claim. This does not expose the session or grant physical send authority.
    #[must_use]
    pub fn matches_restricted_target(
        &self,
        target: RuntimeHostId,
        route: &str,
        runtime_principal: PrincipalRef,
        carrier_binding_digest: Digest32,
    ) -> bool {
        self.expected_target == target
            && self.route.as_str() == route
            && self.expected_runtime_principal == runtime_principal
            && self.expected_carrier_binding_digest == carrier_binding_digest
    }

    /// Validates and retains exact request bytes, then waits for one matching
    /// Runtime queryable under the operation's single absolute deadline.
    ///
    /// The returned move-only value is transport readiness, not Controller
    /// send authority. The Controller must durably claim its own send action
    /// before invoking [`RestrictedRuntimeApplyPreflightV1::send_once`].
    pub async fn preflight(
        &mut self,
        canonical_request: Vec<u8>,
    ) -> Result<RestrictedRuntimeApplyPreflightV1<'_>, RestrictedRuntimeApplyErrorV1> {
        validate_request_frame(&canonical_request)?;
        let deadline = checked_deadline(self.operation_timeout)?;
        let querier = deadline_result(
            deadline,
            self.session
                .declare_querier(self.route.as_str().to_owned())
                .target(QueryTarget::BestMatching)
                .accept_replies(ReplyKeyExpr::MatchingQuery)
                .consolidation(ConsolidationMode::None)
                .timeout(self.operation_timeout),
        )
        .await?
        .map_err(|_| RestrictedRuntimeApplyErrorV1::QuerierDeclarationFailed)?;
        let matching_listener = deadline_result(deadline, querier.matching_listener())
            .await?
            .map_err(|_| RestrictedRuntimeApplyErrorV1::MatchingObservationFailed)?;
        let mut matching = deadline_result(deadline, querier.matching_status())
            .await?
            .map_err(|_| RestrictedRuntimeApplyErrorV1::MatchingObservationFailed)?
            .matching();
        while !matching {
            matching = deadline_result(deadline, matching_listener.recv_async())
                .await?
                .map_err(|_| RestrictedRuntimeApplyErrorV1::MatchingObservationFailed)?
                .matching();
        }
        drop(matching_listener);
        Ok(RestrictedRuntimeApplyPreflightV1 {
            client: self,
            querier: Some(querier),
            canonical_request: canonical_request.into_boxed_slice(),
            deadline,
            attempt: OneQueryAttempt::new(),
        })
    }

    /// Explicitly closes the connector-only session.
    ///
    /// A querier cleanup failure observed after a completed request is reported
    /// here, after the valid response has already been returned to its caller.
    pub async fn shutdown(self) -> Result<(), RestrictedRuntimeApplyErrorV1> {
        let deferred_querier_cleanup_failure = self.deferred_querier_cleanup_failure;
        let session_close_failed = self.session.close().await.is_err();
        reduce_client_shutdown_failures(deferred_querier_cleanup_failure, session_close_failed)
    }
}

/// Matching-qualified, move-only authority for one physical query attempt.
///
/// This value does not prove a Controller journal claim. Its consuming send
/// method ensures that a qualified attempt cannot issue a second query.
///
/// ```compile_fail
/// use paraegox_fabric::RestrictedRuntimeApplyPreflightV1;
///
/// async fn cannot_send_twice(preflight: RestrictedRuntimeApplyPreflightV1<'_>) {
///     let _ = preflight.send_once().await;
///     let _ = preflight.send_once().await;
/// }
/// ```
pub struct RestrictedRuntimeApplyPreflightV1<'client> {
    client: &'client mut RestrictedRuntimeApplyClientV1,
    querier: Option<Querier<'static>>,
    canonical_request: Box<[u8]>,
    deadline: Instant,
    attempt: OneQueryAttempt,
}

impl RestrictedRuntimeApplyPreflightV1<'_> {
    /// Issues exactly one query and returns the exact bounded reply payload.
    pub async fn send_once(mut self) -> Result<Box<[u8]>, RestrictedRuntimeApplyErrorV1> {
        self.attempt.claim()?;
        let querier = self
            .querier
            .take()
            .ok_or(RestrictedRuntimeApplyErrorV1::QueryAlreadySent)?;
        let route = self.client.route.as_str();
        let outcome = async {
            // Zenoh 1.9 starts a query synchronously on the first builder poll,
            // so an outer timeout cannot be the pre-send fence: Tokio polls the
            // inner future first. Check the one absolute deadline immediately
            // before resolving the immediately-ready builder.
            let (reply_sender, mut reply_receiver) = mpsc::channel(RESTRICTED_REPLY_CAPACITY);
            let expected_route = Arc::<str>::from(route);
            // Send through the same preflight Querier. Its id owns the pending
            // QueryState, so the unconditional undeclare below cancels that
            // state after the first outcome or the absolute deadline. A
            // Session::get query would have no querier id and could retain its
            // callback/timeout state after this method returned.
            let get = querier
                .get()
                .payload(self.canonical_request.as_ref())
                .callback(move |reply| {
                    let outcome = decode_restricted_reply(&expected_route, reply);
                    // BestMatching selects one responder. The one-slot callback
                    // is an additional hard memory bound if a peer misbehaves.
                    let _ = reply_sender.try_send(outcome);
                });
            // This must be the final operation before resolving Zenoh's
            // immediately-ready builder, because that resolution is the
            // physical-send boundary.
            if Instant::now() >= self.deadline {
                return Err(RestrictedRuntimeApplyErrorV1::OperationTimedOut);
            }
            get.await
                .map_err(|_| RestrictedRuntimeApplyErrorV1::QueryStartFailed)?;
            deadline_result(self.deadline, reply_receiver.recv())
                .await?
                .ok_or(RestrictedRuntimeApplyErrorV1::NoReply)?
        }
        .await;
        let cleanup = deadline_result(self.deadline, querier.undeclare()).await;
        preserve_query_outcome(
            &mut self.client.deferred_querier_cleanup_failure,
            outcome,
            cleanup,
        )
    }
}

fn decode_restricted_reply(
    expected_route: &str,
    reply: Reply,
) -> Result<Box<[u8]>, RestrictedRuntimeApplyErrorV1> {
    let sample = reply
        .into_result()
        .map_err(|_| RestrictedRuntimeApplyErrorV1::RemoteRejected)?;
    if sample.key_expr().as_str() != expected_route {
        return Err(RestrictedRuntimeApplyErrorV1::ResponseRouteMismatch);
    }
    validate_response_frame_length(sample.payload().len())?;
    let response = sample.payload().to_bytes();
    Ok(response.as_ref().to_vec().into_boxed_slice())
}

fn preserve_query_outcome<T, CleanupError>(
    deferred_cleanup_failure: &mut bool,
    outcome: Result<T, RestrictedRuntimeApplyErrorV1>,
    cleanup: Result<Result<(), CleanupError>, RestrictedRuntimeApplyErrorV1>,
) -> Result<T, RestrictedRuntimeApplyErrorV1> {
    if !matches!(cleanup, Ok(Ok(()))) {
        *deferred_cleanup_failure = true;
    }
    outcome
}

fn reduce_queryable_declaration_failure(
    session_close_failed: bool,
) -> RestrictedRuntimeApplyErrorV1 {
    if session_close_failed {
        RestrictedRuntimeApplyErrorV1::QueryableDeclarationAndSessionCloseFailed
    } else {
        RestrictedRuntimeApplyErrorV1::QueryableDeclarationFailed
    }
}

fn reduce_client_shutdown_failures(
    querier_undeclaration_failed: bool,
    session_close_failed: bool,
) -> Result<(), RestrictedRuntimeApplyErrorV1> {
    match (querier_undeclaration_failed, session_close_failed) {
        (false, false) => Ok(()),
        (true, false) => Err(RestrictedRuntimeApplyErrorV1::QuerierUndeclarationFailed),
        (false, true) => Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed),
        (true, true) => {
            Err(RestrictedRuntimeApplyErrorV1::QuerierUndeclarationAndSessionCloseFailed)
        }
    }
}

fn reduce_endpoint_shutdown_failures(
    queryable_undeclaration_failed: bool,
    worker_join_failed: bool,
    session_close_failed: bool,
) -> Result<(), RestrictedRuntimeApplyErrorV1> {
    match (
        queryable_undeclaration_failed,
        worker_join_failed,
        session_close_failed,
    ) {
        (false, false, false) => Ok(()),
        (true, false, false) => Err(RestrictedRuntimeApplyErrorV1::QueryableUndeclarationFailed),
        (false, true, false) => Err(RestrictedRuntimeApplyErrorV1::EndpointWorkerFailed),
        (false, false, true) => Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed),
        (true, true, false) => {
            Err(RestrictedRuntimeApplyErrorV1::QueryableUndeclarationAndEndpointWorkerFailed)
        }
        (true, false, true) => {
            Err(RestrictedRuntimeApplyErrorV1::QueryableUndeclarationAndSessionCloseFailed)
        }
        (false, true, true) => {
            Err(RestrictedRuntimeApplyErrorV1::EndpointWorkerAndSessionCloseFailed)
        }
        (true, true, true) => Err(
            RestrictedRuntimeApplyErrorV1::QueryableUndeclarationAndEndpointWorkerAndSessionCloseFailed,
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OneQueryAttempt {
    claimed: bool,
}

impl OneQueryAttempt {
    const fn new() -> Self {
        Self { claimed: false }
    }

    fn claim(&mut self) -> Result<(), RestrictedRuntimeApplyErrorV1> {
        if core::mem::replace(&mut self.claimed, true) {
            return Err(RestrictedRuntimeApplyErrorV1::QueryAlreadySent);
        }
        Ok(())
    }
}

/// Runtime-side exact canonical request delivered after transport bounds.
pub struct RestrictedRuntimeApplyInboundV1 {
    canonical_request: Box<[u8]>,
    responder: Option<oneshot::Sender<Box<[u8]>>>,
}

impl RestrictedRuntimeApplyInboundV1 {
    /// Returns the byte-identical request payload. Authentication is still the
    /// Runtime owner's responsibility.
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }

    /// Supplies exact canonical response bytes once.
    pub fn respond(
        mut self,
        canonical_response: Vec<u8>,
    ) -> Result<(), RestrictedRuntimeApplyRespondErrorV1> {
        validate_response_frame(&canonical_response)
            .map_err(|_| RestrictedRuntimeApplyRespondErrorV1::ResponseTooLargeOrEmpty)?;
        let responder = self
            .responder
            .take()
            .ok_or(RestrictedRuntimeApplyRespondErrorV1::ResponseAlreadyConsumed)?;
        responder
            .send(canonical_response.into_boxed_slice())
            .map_err(|_| RestrictedRuntimeApplyRespondErrorV1::EndpointClosed)
    }
}

/// Single-consumer Runtime request stream for the exact endpoint generation.
pub struct RestrictedRuntimeApplyReceiverV1 {
    receiver: mpsc::Receiver<RestrictedRuntimeApplyInboundV1>,
    cancel: watch::Receiver<bool>,
}

impl RestrictedRuntimeApplyReceiverV1 {
    /// Waits for one bounded request or returns `None` after endpoint shutdown.
    pub async fn recv(&mut self) -> Option<RestrictedRuntimeApplyInboundV1> {
        tokio::select! {
            biased;
            changed = self.cancel.changed() => {
                if changed.is_err() || *self.cancel.borrow() {
                    None
                } else {
                    self.receiver.recv().await
                }
            }
            request = self.receiver.recv() => request,
        }
    }
}

/// Listener-only Runtime transport and its joined worker lifecycle.
pub struct RestrictedRuntimeApplyEndpointV1 {
    session: Option<zenoh::Session>,
    queryable: Option<Queryable<()>>,
    cancel: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl RestrictedRuntimeApplyEndpointV1 {
    /// Starts one TLS listener and declares exactly one queryable route.
    pub async fn start(
        config: RestrictedRuntimeApplyEndpointConfigV1,
    ) -> Result<(Self, RestrictedRuntimeApplyReceiverV1), RestrictedRuntimeApplyErrorV1> {
        let ingress_limits = restricted_ingress_limits(config.handler_timeout)
            .map_err(|_| RestrictedRuntimeApplyErrorV1::IngressConfigurationFailed)?;
        let zenoh_config = config
            .build_zenoh_config()
            .map_err(RestrictedRuntimeApplyErrorV1::Fabric)?;
        let session = zenoh::open(zenoh_config)
            .await
            .map_err(|_| RestrictedRuntimeApplyErrorV1::SessionOpenFailed)?;
        let ingress_budget = IngressBudget::new(ingress_limits);
        let (ingress_sender, ingress_receiver) = mpsc::channel(RESTRICTED_INGRESS_CAPACITY);
        let callback = RestrictedIngress {
            route: Arc::<str>::from(config.route()),
            sender: ingress_sender,
            budget: ingress_budget,
            handler_timeout: config.handler_timeout,
        };
        let queryable = match session
            .declare_queryable(config.route.as_str().to_owned())
            .callback(move |query| callback.offer(query))
            .await
        {
            Ok(queryable) => queryable,
            Err(_) => {
                let session_close_failed = session.close().await.is_err();
                return Err(reduce_queryable_declaration_failure(session_close_failed));
            }
        };
        let (request_sender, request_receiver) = mpsc::channel(RESTRICTED_HANDLER_CAPACITY);
        let (cancel_sender, cancel_receiver) = watch::channel(false);
        let worker_cancel = cancel_receiver.clone();
        let worker_route = Arc::<str>::from(config.route());
        let worker = tokio::spawn(async move {
            run_restricted_endpoint_worker(
                worker_route,
                ingress_receiver,
                request_sender,
                worker_cancel,
            )
            .await;
        });
        Ok((
            Self {
                session: Some(session),
                queryable: Some(queryable),
                cancel: cancel_sender,
                worker: Some(worker),
            },
            RestrictedRuntimeApplyReceiverV1 {
                receiver: request_receiver,
                cancel: cancel_receiver,
            },
        ))
    }

    /// Stops admission, undeclares the route, joins the worker, and closes the session.
    pub async fn shutdown(mut self) -> Result<(), RestrictedRuntimeApplyErrorV1> {
        let undeclaration_failed = match self.queryable.take() {
            Some(queryable) => queryable.undeclare().await.is_err(),
            None => false,
        };
        // A successful undeclaration drops the sole admission callback sender;
        // the worker then drains its bounded queue and lets an in-flight handler
        // reach its own absolute deadline. Cancellation is only the fail-closed
        // fallback when admission could not be stopped cleanly.
        if undeclaration_failed {
            let _ = self.cancel.send(true);
        }
        let worker_failed = match self.worker.take() {
            Some(worker) => worker.await.is_err(),
            None => false,
        };
        let close_failed = match self.session.take() {
            Some(session) => session.close().await.is_err(),
            None => false,
        };
        reduce_endpoint_shutdown_failures(undeclaration_failed, worker_failed, close_failed)
    }
}

impl Drop for RestrictedRuntimeApplyEndpointV1 {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

struct RestrictedIngress {
    route: Arc<str>,
    sender: mpsc::Sender<RestrictedIngressFrame>,
    budget: Arc<IngressBudget>,
    handler_timeout: Duration,
}

impl RestrictedIngress {
    fn offer(&self, query: Query) {
        let Some(payload) = query.payload() else {
            self.budget.rejected_malformed();
            return;
        };
        let Ok(lease) = self.budget.try_reserve(payload.len()) else {
            return;
        };
        if query.key_expr().as_str() != self.route.as_ref()
            || !query.parameters().is_empty()
            || query.attachment().is_some()
            || payload.is_empty()
        {
            self.budget.rejected_malformed();
            return;
        }
        let Ok(deadline) = checked_deadline(self.handler_timeout) else {
            self.budget.rejected_malformed();
            return;
        };
        match self.sender.try_send(RestrictedIngressFrame {
            query,
            lease,
            deadline,
        }) {
            Ok(()) => self.budget.admitted(),
            Err(_) => self.budget.rejected_closed(),
        }
    }
}

struct RestrictedIngressFrame {
    query: Query,
    lease: IngressLease,
    deadline: Instant,
}

async fn run_restricted_endpoint_worker(
    route: Arc<str>,
    mut ingress: mpsc::Receiver<RestrictedIngressFrame>,
    request_sender: mpsc::Sender<RestrictedRuntimeApplyInboundV1>,
    mut cancel: watch::Receiver<bool>,
) {
    loop {
        let frame = tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
                continue;
            }
            frame = ingress.recv() => match frame {
                Some(frame) => frame,
                None => break,
            }
        };
        handle_restricted_query(&route, frame, &request_sender, &mut cancel).await;
    }
}

async fn handle_restricted_query(
    route: &str,
    frame: RestrictedIngressFrame,
    request_sender: &mpsc::Sender<RestrictedRuntimeApplyInboundV1>,
    cancel: &mut watch::Receiver<bool>,
) {
    let RestrictedIngressFrame {
        query,
        lease: _lease,
        deadline,
    } = frame;
    let Some(payload) = query.payload() else {
        return;
    };
    if Instant::now() >= deadline {
        reply_remote_error(deadline, &query).await;
        return;
    }
    let request = payload.to_bytes();
    if validate_request_frame(request.as_ref()).is_err() {
        return;
    }
    let (response_sender, response_receiver) = oneshot::channel();
    let inbound = RestrictedRuntimeApplyInboundV1 {
        canonical_request: request.as_ref().to_vec().into_boxed_slice(),
        responder: Some(response_sender),
    };
    if request_sender.try_send(inbound).is_err() {
        reply_remote_error(deadline, &query).await;
        return;
    }
    let response = tokio::select! {
        biased;
        response = tokio::time::timeout_at(deadline, response_receiver) => {
            response.ok().and_then(Result::ok)
        },
        _ = cancel.changed() => None,
    };
    let Some(response) = response else {
        reply_remote_error(deadline, &query).await;
        return;
    };
    if validate_response_frame(&response).is_err() {
        reply_remote_error(deadline, &query).await;
        return;
    }
    let _ = deadline_result(deadline, query.reply(route, response.as_ref())).await;
}

async fn reply_remote_error(deadline: Instant, query: &Query) {
    let _ = deadline_result(deadline, query.reply_err(REMOTE_REJECTION_BODY)).await;
}

fn validate_request_frame(frame: &[u8]) -> Result<(), RestrictedRuntimeApplyErrorV1> {
    if frame.is_empty() {
        return Err(RestrictedRuntimeApplyErrorV1::EmptyRequest);
    }
    if frame.len() > MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES {
        return Err(RestrictedRuntimeApplyErrorV1::RequestTooLarge);
    }
    Ok(())
}

fn validate_response_frame(frame: &[u8]) -> Result<(), RestrictedRuntimeApplyErrorV1> {
    validate_response_frame_length(frame.len())
}

fn validate_response_frame_length(length: usize) -> Result<(), RestrictedRuntimeApplyErrorV1> {
    if length == 0 {
        return Err(RestrictedRuntimeApplyErrorV1::EmptyResponse);
    }
    if length > MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES {
        return Err(RestrictedRuntimeApplyErrorV1::ResponseTooLarge);
    }
    Ok(())
}

fn checked_deadline(timeout: Duration) -> Result<Instant, RestrictedRuntimeApplyErrorV1> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(RestrictedRuntimeApplyErrorV1::InvalidDeadline)
}

async fn deadline_result<T>(
    deadline: Instant,
    future: impl core::future::IntoFuture<Output = T>,
) -> Result<T, RestrictedRuntimeApplyErrorV1> {
    tokio::time::timeout_at(deadline, future.into_future())
        .await
        .map_err(|_| RestrictedRuntimeApplyErrorV1::OperationTimedOut)
}

/// Runtime response handoff failure before a Zenoh reply is attempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestrictedRuntimeApplyRespondErrorV1 {
    ResponseTooLargeOrEmpty,
    ResponseAlreadyConsumed,
    EndpointClosed,
}

impl fmt::Display for RestrictedRuntimeApplyRespondErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResponseTooLargeOrEmpty => {
                "restricted apply response must be nonempty and within its contract bound"
            }
            Self::ResponseAlreadyConsumed => "restricted apply response was already consumed",
            Self::EndpointClosed => "restricted apply endpoint closed before response handoff",
        })
    }
}

impl std::error::Error for RestrictedRuntimeApplyRespondErrorV1 {}

/// Fail-closed transport outcome. It makes no Runtime admission claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestrictedRuntimeApplyErrorV1 {
    Fabric(FabricError),
    SessionOpenFailed,
    SessionCloseFailed,
    QuerierDeclarationFailed,
    QuerierUndeclarationFailed,
    QuerierUndeclarationAndSessionCloseFailed,
    QueryableDeclarationFailed,
    QueryableDeclarationAndSessionCloseFailed,
    QueryableUndeclarationFailed,
    EndpointWorkerFailed,
    QueryableUndeclarationAndEndpointWorkerFailed,
    QueryableUndeclarationAndSessionCloseFailed,
    EndpointWorkerAndSessionCloseFailed,
    QueryableUndeclarationAndEndpointWorkerAndSessionCloseFailed,
    IngressConfigurationFailed,
    MatchingObservationFailed,
    QueryAlreadySent,
    QueryStartFailed,
    NoReply,
    RemoteRejected,
    ResponseRouteMismatch,
    EmptyRequest,
    RequestTooLarge,
    EmptyResponse,
    ResponseTooLarge,
    InvalidDeadline,
    OperationTimedOut,
}

impl fmt::Display for RestrictedRuntimeApplyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fabric(error) => {
                write!(formatter, "restricted Fabric configuration failed: {error}")
            }
            other => formatter.write_str(match other {
                Self::SessionOpenFailed => "restricted Fabric session failed to open",
                Self::SessionCloseFailed => "restricted Fabric session failed to close",
                Self::QuerierDeclarationFailed => "restricted apply querier declaration failed",
                Self::QuerierUndeclarationFailed => "restricted apply querier undeclaration failed",
                Self::QuerierUndeclarationAndSessionCloseFailed => {
                    "restricted apply querier undeclaration and session close both failed"
                }
                Self::QueryableDeclarationFailed => "restricted apply queryable declaration failed",
                Self::QueryableDeclarationAndSessionCloseFailed => {
                    "restricted apply queryable declaration and session close both failed"
                }
                Self::QueryableUndeclarationFailed => {
                    "restricted apply queryable undeclaration failed"
                }
                Self::EndpointWorkerFailed => "restricted apply endpoint worker failed to join",
                Self::QueryableUndeclarationAndEndpointWorkerFailed => {
                    "restricted apply queryable undeclaration and endpoint worker join both failed"
                }
                Self::QueryableUndeclarationAndSessionCloseFailed => {
                    "restricted apply queryable undeclaration and session close both failed"
                }
                Self::EndpointWorkerAndSessionCloseFailed => {
                    "restricted apply endpoint worker join and session close both failed"
                }
                Self::QueryableUndeclarationAndEndpointWorkerAndSessionCloseFailed => {
                    "restricted apply queryable undeclaration, endpoint worker join, and session close all failed"
                }
                Self::IngressConfigurationFailed => {
                    "restricted apply ingress bounds are not representable"
                }
                Self::MatchingObservationFailed => "restricted apply matching observation failed",
                Self::QueryAlreadySent => "restricted apply attempt already sent its sole query",
                Self::QueryStartFailed => "restricted apply query failed to start",
                Self::NoReply => "restricted apply query completed without a reply",
                Self::RemoteRejected => "restricted Runtime endpoint rejected the request",
                Self::ResponseRouteMismatch => {
                    "restricted Runtime response did not use the exact route"
                }
                Self::EmptyRequest => "restricted apply request must not be empty",
                Self::RequestTooLarge => "restricted apply request exceeds its contract bound",
                Self::EmptyResponse => "restricted apply response must not be empty",
                Self::ResponseTooLarge => "restricted apply response exceeds its contract bound",
                Self::InvalidDeadline => "restricted apply deadline is not representable",
                Self::OperationTimedOut => "restricted apply operation timed out",
                Self::Fabric(_) => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for RestrictedRuntimeApplyErrorV1 {}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use paraegox_kernel::{
        digest::Digest32,
        identity::{PrincipalRef, RuntimeHostId},
    };

    use super::{
        OneQueryAttempt, RestrictedRuntimeApplyClientConfigV1, RestrictedRuntimeApplyConfigErrorV1,
        RestrictedRuntimeApplyEndpointConfigV1, RestrictedRuntimeApplyErrorV1,
        RestrictedRuntimeApplyInboundV1, RestrictedRuntimeApplyRespondErrorV1, checked_deadline,
        deadline_result, preserve_query_outcome, reduce_client_shutdown_failures,
        reduce_endpoint_shutdown_failures, reduce_queryable_declaration_failure,
        restricted_runtime_apply_peer_certificate_common_name_v1, validate_request_frame,
        validate_response_frame,
    };
    use crate::{RemoteTlsEndpoint, ResolvedRemoteMtlsIdentityFiles};
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        DistributedFabricCredentialRefV1, DistributedFabricTrustAnchorRefV1,
        DistributedFabricTrustDomainRefV1,
        MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES,
        MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES,
        RestrictedRuntimeApplyCarrierBindingFieldsV1, RestrictedRuntimeApplyCarrierBindingV1,
        RestrictedRuntimeApplyTransportProfileFieldsV1, RestrictedRuntimeApplyTransportProfileV1,
    };
    use paraegox_runtime_contracts::wire::ApplyAuthKeyRef;

    fn endpoint() -> RemoteTlsEndpoint {
        RemoteTlsEndpoint::try_new("tls/192.0.2.40:7447").unwrap()
    }

    fn identity(role: &str) -> ResolvedRemoteMtlsIdentityFiles {
        ResolvedRemoteMtlsIdentityFiles::try_new(
            PathBuf::from(format!("/run/paraegox/{role}-certificate.pem")),
            PathBuf::from(format!("/run/paraegox/{role}-private-key.pem")),
        )
        .unwrap()
    }

    const fn principal(byte: u8) -> PrincipalRef {
        PrincipalRef::from_bytes([byte; 16])
    }

    #[test]
    fn restricted_peer_certificate_common_name_has_one_owner_encoding() {
        assert_eq!(
            restricted_runtime_apply_peer_certificate_common_name_v1(principal(0x52)),
            "paraegox-principal-52525252525252525252525252525252"
        );
    }

    const fn target(byte: u8) -> RuntimeHostId {
        RuntimeHostId::from_bytes([byte; 16])
    }

    const fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn restricted_profile_and_carrier() -> (
        [u8; 16],
        RestrictedRuntimeApplyTransportProfileV1,
        RestrictedRuntimeApplyCarrierBindingV1,
    ) {
        let profile_ref = [0x95; 16];
        let profile = RestrictedRuntimeApplyTransportProfileV1::try_new(
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                target: target(0x51),
                endpoint_ref: [0x54; 16],
                endpoint_generation: 7,
                tls_listener_locator: "tls/192.0.2.40:7447",
                route: "paraegox/runtime-a/apply",
                trust_domain_ref: DistributedFabricTrustDomainRefV1::try_from_bytes([0x55; 16])
                    .expect("trust domain"),
                trust_anchor_ref: DistributedFabricTrustAnchorRefV1::try_from_bytes([0x56; 16])
                    .expect("trust anchor"),
                controller_connector_credential_ref:
                    DistributedFabricCredentialRefV1::try_from_bytes([0x57; 16])
                        .expect("Controller connector credential"),
                runtime_listener_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                    [0x58; 16],
                )
                .expect("Runtime listener credential"),
                controller_principal: principal(0x43),
                runtime_principal: principal(0x52),
                operation_timeout_nanos: 5_000_000_000,
            },
        )
        .expect("restricted transport profile");
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: profile.target(),
                runtime_principal: profile.runtime_principal(),
                controller_principal: profile.controller_principal(),
                endpoint_ref: profile.endpoint_ref(),
                endpoint_generation: profile.endpoint_generation(),
                route: profile.route(),
                controller_request_key: ApplyAuthKeyRef::from_bytes([0x61; 16]),
                controller_request_key_fingerprint: digest(0x71),
                runtime_response_key: ApplyAuthKeyRef::from_bytes([0x62; 16]),
                runtime_response_key_fingerprint: digest(0x72),
                control_transport_profile_ref: profile_ref,
                control_transport_profile_digest: profile.profile_digest(),
            },
        )
        .expect("restricted carrier");
        (profile_ref, profile, carrier)
    }

    fn assert_config_path_set(config: &zenoh::Config, path: &str) {
        let value = config
            .get_json(path)
            .unwrap_or_else(|_| panic!("expected configured path {path}"));
        assert_ne!(value, "null", "expected configured path {path}");
    }

    fn assert_config_path_unset(config: &zenoh::Config, path: &str) {
        if let Ok(value) = config.get_json(path) {
            assert_eq!(value, "null", "expected absent configured path {path}");
        }
    }

    fn config_json_value(config: &zenoh::Config, path: &str) -> serde_json::Value {
        let value = config
            .get_json(path)
            .unwrap_or_else(|_| panic!("expected configured path {path}"));
        serde_json::from_str(&value)
            .unwrap_or_else(|_| panic!("expected JSON configuration at {path}"))
    }

    #[test]
    fn roles_build_connector_only_and_listener_only_tls_profiles() {
        let client = RestrictedRuntimeApplyClientConfigV1::try_new(
            endpoint(),
            "paraegox/runtime-a/apply",
            PathBuf::from("/run/paraegox/root-ca.pem"),
            identity("controller"),
            target(0x51),
            principal(0x52),
            digest(0x53),
            Duration::from_secs(5),
        )
        .unwrap()
        .build_zenoh_config()
        .unwrap();
        assert_eq!(client.get_json("mode").unwrap(), "\"client\"");
        assert_eq!(client.get_json("listen/endpoints").unwrap(), "[]");
        assert_eq!(
            client.get_json("connect/endpoints").unwrap(),
            "[\"tls/192.0.2.40:7447\"]"
        );
        assert_config_path_set(&client, "transport/link/tls/connect_certificate");
        assert_config_path_unset(&client, "transport/link/tls/listen_certificate");
        let client_acl = config_json_value(&client, "access_control");
        assert_eq!(
            client_acl["rules"][0]["flows"],
            serde_json::json!(["egress"])
        );
        assert_eq!(
            client_acl["rules"][0]["messages"],
            serde_json::json!(["query"])
        );
        assert_eq!(
            client_acl["rules"][0]["key_exprs"],
            serde_json::json!(["paraegox/runtime-a/apply"])
        );
        assert_eq!(
            client_acl["rules"][1]["flows"],
            serde_json::json!(["ingress"])
        );
        assert_eq!(
            client_acl["rules"][1]["messages"],
            serde_json::json!(["reply", "declare_queryable"])
        );
        assert_eq!(
            client_acl["rules"][1]["key_exprs"],
            serde_json::json!(["paraegox/runtime-a/apply"])
        );
        assert_eq!(
            client_acl["subjects"][0]["cert_common_names"],
            serde_json::json!(["paraegox-principal-52525252525252525252525252525252"])
        );

        let runtime = RestrictedRuntimeApplyEndpointConfigV1::try_new(
            endpoint(),
            "paraegox/runtime-a/apply",
            PathBuf::from("/run/paraegox/root-ca.pem"),
            identity("runtime"),
            target(0x51),
            principal(0x43),
            digest(0x53),
            Duration::from_secs(5),
        )
        .unwrap()
        .build_zenoh_config()
        .unwrap();
        assert_eq!(runtime.get_json("mode").unwrap(), "\"peer\"");
        assert_eq!(
            runtime.get_json("listen/endpoints").unwrap(),
            "[\"tls/192.0.2.40:7447\"]"
        );
        assert_eq!(runtime.get_json("connect/endpoints").unwrap(), "[]");
        assert_config_path_set(&runtime, "transport/link/tls/listen_certificate");
        assert_config_path_unset(&runtime, "transport/link/tls/connect_certificate");
        let runtime_acl = config_json_value(&runtime, "access_control");
        assert_eq!(
            runtime_acl["rules"][0]["flows"],
            serde_json::json!(["egress"])
        );
        assert_eq!(
            runtime_acl["rules"][0]["messages"],
            serde_json::json!(["reply", "declare_queryable"])
        );
        assert_eq!(
            runtime_acl["rules"][0]["key_exprs"],
            serde_json::json!(["paraegox/runtime-a/apply"])
        );
        assert_eq!(
            runtime_acl["rules"][1]["flows"],
            serde_json::json!(["ingress"])
        );
        assert_eq!(
            runtime_acl["rules"][1]["messages"],
            serde_json::json!(["query"])
        );
        assert_eq!(
            runtime_acl["rules"][1]["key_exprs"],
            serde_json::json!(["paraegox/runtime-a/apply"])
        );
        assert_eq!(
            runtime_acl["subjects"][0]["cert_common_names"],
            serde_json::json!(["paraegox-principal-43434343434343434343434343434343"])
        );
    }

    #[test]
    fn canonical_transport_profile_maps_to_both_exact_roles() {
        let (profile_ref, profile, carrier) = restricted_profile_and_carrier();
        let client = RestrictedRuntimeApplyClientConfigV1::try_from_transport_profile(
            &profile,
            profile_ref,
            &carrier,
            PathBuf::from("/run/paraegox/root-ca.pem"),
            identity("controller"),
        )
        .expect("Controller profile mapping");
        assert_eq!(client.endpoint, endpoint());
        assert_eq!(client.route(), profile.route());
        assert_eq!(client.expected_target, profile.target());
        assert_eq!(
            client.expected_runtime_principal,
            profile.runtime_principal()
        );
        assert_eq!(
            client.expected_carrier_binding_digest,
            carrier.binding_digest()
        );
        assert_eq!(client.operation_timeout, Duration::from_secs(5));

        let runtime = RestrictedRuntimeApplyEndpointConfigV1::try_from_transport_profile(
            &profile,
            profile_ref,
            &carrier,
            PathBuf::from("/run/paraegox/root-ca.pem"),
            identity("runtime"),
        )
        .expect("Runtime profile mapping");
        assert_eq!(runtime.endpoint, endpoint());
        assert_eq!(runtime.route(), profile.route());
        assert_eq!(runtime.expected_target, profile.target());
        assert_eq!(
            runtime.expected_controller_principal,
            profile.controller_principal()
        );
        assert_eq!(
            runtime.expected_carrier_binding_digest,
            carrier.binding_digest()
        );
        assert!(runtime.matches_restricted_carrier(&carrier));
        assert_eq!(runtime.handler_timeout, Duration::from_secs(5));

        assert_eq!(
            RestrictedRuntimeApplyClientConfigV1::try_from_transport_profile(
                &profile,
                [0x96; 16],
                &carrier,
                PathBuf::from("/run/paraegox/root-ca.pem"),
                identity("controller"),
            ),
            Err(RestrictedRuntimeApplyConfigErrorV1::ProfileCarrierMismatch)
        );
    }

    #[test]
    fn profiles_disable_discovery_pubsub_retry_and_protocol_fallback() {
        let config = RestrictedRuntimeApplyClientConfigV1::try_new(
            endpoint(),
            "paraegox/runtime-a/apply",
            PathBuf::from("/run/paraegox/root-ca.pem"),
            identity("controller"),
            target(0x51),
            principal(0x52),
            digest(0x53),
            Duration::from_secs(5),
        )
        .unwrap()
        .build_zenoh_config()
        .unwrap();
        assert_eq!(
            config.get_json("scouting/multicast/enabled").unwrap(),
            "false"
        );
        assert_eq!(config.get_json("scouting/gossip/enabled").unwrap(), "false");
        assert_eq!(config.get_json("connect/timeout_ms").unwrap(), "0");
        assert_eq!(config.get_json("connect/exit_on_failure").unwrap(), "true");
        assert_eq!(config.get_json("listen/timeout_ms").unwrap(), "0");
        assert_eq!(config.get_json("listen/exit_on_failure").unwrap(), "true");
        assert_eq!(
            config
                .get_json("open/return_conditions/connect_scouted")
                .unwrap(),
            "false"
        );
        assert_eq!(
            config.get_json("open/return_conditions/declares").unwrap(),
            "true"
        );
        assert_eq!(config.get_json("adminspace/enabled").unwrap(), "false");
        assert_eq!(config.get_json("plugins_loading/enabled").unwrap(), "false");
        assert_eq!(
            config.get_json("transport/unicast/accept_pending").unwrap(),
            "1"
        );
        assert_eq!(
            config.get_json("transport/unicast/max_sessions").unwrap(),
            "1"
        );
        assert_eq!(config.get_json("transport/unicast/max_links").unwrap(), "1");
        assert_eq!(
            config.get_json("transport/link/protocols").unwrap(),
            "[\"tls\"]"
        );
        assert_eq!(
            config
                .get_json("transport/link/rx/max_message_size")
                .unwrap(),
            super::restricted_transport_message_limit().to_string()
        );
        assert!(super::restricted_transport_message_limit() < 1024 * 1024);
        assert_eq!(config.get_json("access_control/enabled").unwrap(), "true");
        assert_eq!(
            config
                .get_json("access_control/default_permission")
                .unwrap(),
            "\"deny\""
        );
        let acl = config.get_json("access_control/rules").unwrap();
        assert!(acl.contains("query"));
        assert!(acl.contains("declare_queryable"));
        assert!(acl.contains("reply"));
        assert!(!acl.contains("put"));
        assert!(!acl.contains("declare_subscriber"));
    }

    #[test]
    fn route_timeout_and_frames_are_bounded_before_io() {
        assert_eq!(
            RestrictedRuntimeApplyClientConfigV1::try_new(
                endpoint(),
                "paraegox/*/apply",
                PathBuf::from("/run/paraegox/root-ca.pem"),
                identity("controller"),
                target(0x51),
                principal(0x52),
                digest(0x53),
                Duration::from_secs(1),
            ),
            Err(RestrictedRuntimeApplyConfigErrorV1::InvalidRoute)
        );
        assert_eq!(
            RestrictedRuntimeApplyClientConfigV1::try_new(
                endpoint(),
                "paraegox/runtime-a/\napply",
                PathBuf::from("/run/paraegox/root-ca.pem"),
                identity("controller"),
                target(0x51),
                principal(0x52),
                digest(0x53),
                Duration::from_secs(1),
            ),
            Err(RestrictedRuntimeApplyConfigErrorV1::InvalidRoute)
        );
        assert_eq!(
            RestrictedRuntimeApplyClientConfigV1::try_new(
                endpoint(),
                "paraegox/runtime-a/apply",
                PathBuf::from("/run/paraegox/root-ca.pem"),
                identity("controller"),
                target(0x51),
                principal(0x52),
                digest(0x53),
                Duration::ZERO,
            ),
            Err(RestrictedRuntimeApplyConfigErrorV1::ZeroTimeout)
        );
        assert_eq!(
            RestrictedRuntimeApplyClientConfigV1::try_new(
                endpoint(),
                "paraegox/runtime-a/apply",
                PathBuf::from("/run/paraegox/root-ca.pem"),
                identity("controller"),
                target(0),
                principal(0x52),
                digest(0x53),
                Duration::from_secs(1),
            ),
            Err(RestrictedRuntimeApplyConfigErrorV1::ZeroTarget)
        );
        assert_eq!(
            RestrictedRuntimeApplyClientConfigV1::try_new(
                endpoint(),
                "paraegox/runtime-a/apply",
                PathBuf::from("/run/paraegox/root-ca.pem"),
                identity("controller"),
                target(0x51),
                principal(0),
                digest(0x53),
                Duration::from_secs(1),
            ),
            Err(RestrictedRuntimeApplyConfigErrorV1::ZeroPeerPrincipal)
        );
        assert_eq!(
            RestrictedRuntimeApplyClientConfigV1::try_new(
                endpoint(),
                "paraegox/runtime-a/apply",
                PathBuf::from("/run/paraegox/root-ca.pem"),
                identity("controller"),
                target(0x51),
                principal(0x52),
                digest(0),
                Duration::from_secs(1),
            ),
            Err(RestrictedRuntimeApplyConfigErrorV1::ZeroCarrierBindingDigest)
        );
        assert_eq!(
            validate_request_frame(&[]),
            Err(RestrictedRuntimeApplyErrorV1::EmptyRequest)
        );
        assert_eq!(
            validate_request_frame(&vec![
                0_u8;
                MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES
                    + 1
            ]),
            Err(RestrictedRuntimeApplyErrorV1::RequestTooLarge)
        );
        assert_eq!(
            validate_response_frame(&vec![
                0_u8;
                MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES
                    + 1
            ]),
            Err(RestrictedRuntimeApplyErrorV1::ResponseTooLarge)
        );
    }

    #[test]
    fn query_gate_never_renews_or_retries_one_attempt() {
        let mut attempt = OneQueryAttempt::new();
        assert_eq!(attempt.claim(), Ok(()));
        assert_eq!(
            attempt.claim(),
            Err(RestrictedRuntimeApplyErrorV1::QueryAlreadySent)
        );
        assert!(checked_deadline(Duration::MAX).is_err());
    }

    #[tokio::test]
    async fn absolute_deadline_bounds_async_work() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1);
        assert_eq!(
            deadline_result(deadline, core::future::pending::<()>()).await,
            Err(RestrictedRuntimeApplyErrorV1::OperationTimedOut)
        );
    }

    #[test]
    fn valid_reply_wins_over_deferred_querier_cleanup_failure() {
        let response = vec![0x51, 0x52, 0x53].into_boxed_slice();
        let mut deferred_cleanup_failure = false;
        let cleanup: Result<Result<(), ()>, RestrictedRuntimeApplyErrorV1> =
            Err(RestrictedRuntimeApplyErrorV1::OperationTimedOut);
        let outcome =
            preserve_query_outcome(&mut deferred_cleanup_failure, Ok(response.clone()), cleanup);
        assert_eq!(outcome, Ok(response));
        assert!(deferred_cleanup_failure);
    }

    #[test]
    fn queryable_declaration_cleanup_reducer_preserves_dual_failure() {
        assert_eq!(
            reduce_queryable_declaration_failure(false),
            RestrictedRuntimeApplyErrorV1::QueryableDeclarationFailed
        );
        assert_eq!(
            reduce_queryable_declaration_failure(true),
            RestrictedRuntimeApplyErrorV1::QueryableDeclarationAndSessionCloseFailed
        );
    }

    #[test]
    fn client_shutdown_reducer_preserves_querier_and_session_failures() {
        assert_eq!(reduce_client_shutdown_failures(false, false), Ok(()));
        assert_eq!(
            reduce_client_shutdown_failures(true, false),
            Err(RestrictedRuntimeApplyErrorV1::QuerierUndeclarationFailed)
        );
        assert_eq!(
            reduce_client_shutdown_failures(false, true),
            Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed)
        );
        assert_eq!(
            reduce_client_shutdown_failures(true, true),
            Err(RestrictedRuntimeApplyErrorV1::QuerierUndeclarationAndSessionCloseFailed)
        );
    }

    #[test]
    fn endpoint_shutdown_reducer_preserves_every_failure_bit() {
        let cases = [
            ((false, false, false), Ok(())),
            (
                (true, false, false),
                Err(RestrictedRuntimeApplyErrorV1::QueryableUndeclarationFailed),
            ),
            (
                (false, true, false),
                Err(RestrictedRuntimeApplyErrorV1::EndpointWorkerFailed),
            ),
            (
                (false, false, true),
                Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed),
            ),
            (
                (true, true, false),
                Err(
                    RestrictedRuntimeApplyErrorV1::QueryableUndeclarationAndEndpointWorkerFailed,
                ),
            ),
            (
                (true, false, true),
                Err(
                    RestrictedRuntimeApplyErrorV1::QueryableUndeclarationAndSessionCloseFailed,
                ),
            ),
            (
                (false, true, true),
                Err(RestrictedRuntimeApplyErrorV1::EndpointWorkerAndSessionCloseFailed),
            ),
            (
                (true, true, true),
                Err(
                    RestrictedRuntimeApplyErrorV1::QueryableUndeclarationAndEndpointWorkerAndSessionCloseFailed,
                ),
            ),
        ];
        for ((queryable, worker, session), expected) in cases {
            assert_eq!(
                reduce_endpoint_shutdown_failures(queryable, worker, session),
                expected
            );
        }
    }

    #[test]
    fn inbound_handoff_preserves_exact_request_and_response_bytes() {
        let request = vec![0x51, 0x52, 0x53];
        let response = vec![0x61, 0x62, 0x63, 0x64];
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        let inbound = RestrictedRuntimeApplyInboundV1 {
            canonical_request: request.clone().into_boxed_slice(),
            responder: Some(sender),
        };
        assert_eq!(inbound.canonical_request(), request);
        inbound.respond(response.clone()).unwrap();
        assert_eq!(receiver.try_recv().unwrap().as_ref(), response);

        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let oversized = RestrictedRuntimeApplyInboundV1 {
            canonical_request: request.into_boxed_slice(),
            responder: Some(sender),
        };
        assert_eq!(
            oversized.respond(vec![
                0_u8;
                MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES
                    + 1
            ]),
            Err(RestrictedRuntimeApplyRespondErrorV1::ResponseTooLargeOrEmpty)
        );
    }
}
