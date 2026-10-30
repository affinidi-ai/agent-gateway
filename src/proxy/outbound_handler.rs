//! Outbound proxy pipeline.
//!
//! Handles requests from protected agents that want to reach external agents.
//! The route pattern is `{TP_OUTBOUND_PATH_PREFIX}/<aap-path>/<virtual-channel>/...` where:
//!
//! * `<aap-path>` matches the channel's `route` prefix.
//! * `<virtual-channel>` is the `alias` of a [`TransitPoint`].
//! * The remaining path suffix is forwarded verbatim to `target_endpoint`.
//!
//! Each pipeline step is an independent `async fn` taking `&mut OutboundPipelineContext`
//! so that steps can be tested, reordered, and replaced in isolation.

/// URL path prefix used for all outbound transit-point routes.
/// Must start with `/` and contain no trailing slash.
/// Changing this value renames the prefix everywhere without a search-and-replace.
pub const TP_OUTBOUND_PATH_PREFIX: &str = "/outbound";

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::a2a::create_error_response;
use crate::config::ChannelProtocol;
use crate::config::agent_surface::SharedTransitConfig;
use crate::config::agent_surface::TransitPoint;
use crate::observability::loggable;
use crate::proxy::backend_identity::ProtectedAgentIdentity;
use crate::state::OutboundProxyState;

// ── Domain error type ───────────────────────────────────────────────────────

/// Sub-error for identity resolution failures, distinguishing client vs server causes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum IdentityResolutionFailure {
    /// Client did not include the required identity extension → 422
    #[error("{0}")]
    ExtensionMissing(String),
    /// Server-side identity backend unavailable or failed → 502
    #[error("{0}")]
    ServiceUnavailable(String),
    /// Operator misconfiguration (cert disabled / expired / unknown, bad DID, …) → 500
    #[error("{0}")]
    Misconfigured(String),
    /// Backing store outage (cert / secret store unavailable) → 503
    #[error("{0}")]
    BackendUnavailable(String),
}

/// Typed error for the outbound pipeline.
///
/// Each variant captures a specific failure mode.  Conversion to an HTTP
/// [`Response`] happens only at the boundary (`outbound_proxy_handler`), keeping
/// the pipeline steps free of HTTP presentation concerns.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OutboundPipelineError {
    #[error("Outbound is not enabled for this channel")]
    OutboundDisabled,

    #[error("Missing virtual-channel alias in outbound path")]
    MissingVirtualChannelAlias,

    #[error("Unknown outbound virtual channel alias: '{0}'")]
    UnknownVirtualChannelAlias(String),

    #[error("{}", .0.message())]
    VariantRefused(crate::audit::request_events::RoutingRefusal),

    #[error("Failed to read request body: {0}")]
    BodyReadFailed(String),

    #[error("Request protocol '{detected}' does not match transit point protocol '{expected}'")]
    ProtocolMismatch { expected: String, detected: String },

    #[error("Outbound rate limit exceeded")]
    RateLimitExceeded,

    #[error("Extension validation failed: {0}")]
    #[allow(dead_code)]
    ExtensionValidationFailed(String),

    #[error("Identity resolution failed: {0}")]
    IdentityResolutionFailed(IdentityResolutionFailure),

    #[error("Body not available for {0}")]
    BodyNotAvailable(String),

    #[error("Header Metadata Mapping failed: {0}")]
    HeaderMetadataMappingFailed(String),

    #[error("Metadata injection failed")]
    MetadataInjectionFailed,

    #[error("MCP request validation failed: {}", .0.message)]
    McpValidation(Box<crate::mcp::request_validation::McpRequestValidationError>),

    #[error("Invalid MCP identity presentation")]
    McpIdentityInvalid,

    #[error("MCP request body refused: {}", .0.reason())]
    McpBodyRefused(crate::mcp::tool_analyzer::BodyRefusal),

    #[error("{}", crate::a2a::EXTENDED_AGENT_CARD_BATCH_REFUSAL)]
    ExtendedAgentCardBatch,

    #[error("{}", crate::a2a::url_rewriter::EXTENDED_AGENT_CARD_REFUSAL)]
    UnrewritableExtendedAgentCardResponse { rpc_request_id: Option<serde_json::Value> },

    #[error("{error}")]
    McpMetadata { error: crate::mcp::meta::McpMetadataError, body: Bytes, response: bool },

    #[error("Request blocked by gateway policy")]
    GatewayPolicyDenied,

    /// The gateway policy could not decide. Why is logged and audited, never
    /// shown to the caller.
    #[error("Request blocked by gateway policy")]
    GatewayPolicyError(crate::observability::PolicyEvaluationError),

    #[error("Request blocked by surface policy")]
    SurfacePolicyDenied,

    /// The surface or transit-point policy could not decide. Why is logged
    /// and audited, never shown to the caller.
    #[error("Request blocked by surface policy")]
    SurfacePolicyError(crate::observability::PolicyEvaluationError),

    #[error("Target authentication credentials unavailable")]
    TargetAuthUnavailable,

    /// Why the token was refused is logged, never shown to the caller.
    #[error("Transit token missing or invalid")]
    TransitTokenInvalid(String),

    /// How the Transit Point authenticates its callers cannot be enforced, or
    /// its caller authentication is unavailable, so the request is refused.
    /// The reason is logged, never shown to the caller. `mcp_request_id` is
    /// set, to the id the JSON-RPC error answers, when the Transit Point speaks
    /// MCP.
    #[error("This Transit Point is unavailable")]
    TransitPointUnavailable { mcp_request_id: Option<serde_json::Value> },

    /// The Transit Point's `source_auth` refused the caller's credential. Why
    /// is logged, never shown to the caller.
    #[error("Caller credential missing or invalid")]
    TransitCallerUnauthenticated,

    #[error("Credential delegation consent required")]
    ConsentRequired(String),

    /// The request's delegated credentials cannot be resolved, so it is refused
    /// rather than forwarded without them. `mcp_request_id` is set, to the id
    /// the JSON-RPC error answers, when the Transit Point speaks MCP.
    #[error("{refusal}")]
    DelegationRefused { refusal: DelegationRefusal, mcp_request_id: Option<serde_json::Value> },

    #[error("MCP resource authorization failed")]
    McpResourceAuthorization {
        config: Box<crate::mcp::resource_server::McpResourceServerConfig>,
        error: crate::protocols::protected_resource::ResourceTokenError,
    },

    #[error("Upstream request timed out")]
    UpstreamTimeout,

    #[error("Upstream connection failed: {0}")]
    UpstreamConnectionFailed(String),

    #[error("Upstream Fabric stream capacity reached")]
    UpstreamCapacityReached(Option<serde_json::Value>),

    #[error("Failed to read upstream response")]
    UpstreamResponseReadFailed,

    #[error("Response extension validation failed: {0}")]
    #[allow(dead_code)]
    ResponseValidationFailed(String),

    #[error("Response blocked by transit-point policy")]
    TransitPointResponsePolicyDenied,

    #[error("Tool call blocked by transit-point MCP tool gating")]
    TransitMcpToolGated,

    #[error("Failed to build response")]
    ResponseBuildFailed,

    #[error("Identity injection failed: {0}")]
    IdentityInjectionFailed(String),
}

/// Why a Transit Point refused a request whose delegated credentials it could
/// not resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DelegationRefusal {
    #[error("Delegated credentials need the caller's identity, and this request does not establish one")]
    CallerIdentityMissing,
    #[error(
        "Delegated credentials need the managed agent's identity, and neither this Transit Point's managed \
         identity nor the transit token establishes one"
    )]
    AgentIdentityMissing,
    #[error("{}", crate::proxy::credential_delegation::DELEGATION_UNAVAILABLE)]
    Unavailable,
}

impl DelegationRefusal {
    fn status_code(self) -> StatusCode {
        match self {
            Self::CallerIdentityMissing | Self::AgentIdentityMissing => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn jsonrpc_code(self) -> i32 {
        match self {
            Self::CallerIdentityMissing | Self::AgentIdentityMissing => -32001,
            Self::Unavailable => crate::mcp::errors::error_codes::INTERNAL_ERROR,
        }
    }
}

impl OutboundPipelineError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::McpValidation(error) => error.status,
            Self::VariantRefused(refusal) => refusal.status(),
            Self::McpIdentityInvalid | Self::McpBodyRefused(crate::mcp::tool_analyzer::BodyRefusal::Batch) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::McpBodyRefused(_) => StatusCode::OK,
            Self::McpMetadata { response, .. } => {
                if *response {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::BAD_REQUEST
                }
            }
            Self::OutboundDisabled | Self::MissingVirtualChannelAlias | Self::UnknownVirtualChannelAlias(_) => {
                StatusCode::NOT_FOUND
            }

            Self::BodyReadFailed(_) | Self::HeaderMetadataMappingFailed(_) | Self::ExtendedAgentCardBatch => {
                StatusCode::BAD_REQUEST
            }

            Self::ExtensionValidationFailed(_) | Self::ProtocolMismatch { .. } => StatusCode::UNPROCESSABLE_ENTITY,

            Self::RateLimitExceeded | Self::UpstreamCapacityReached(_) => StatusCode::TOO_MANY_REQUESTS,

            Self::TransitTokenInvalid(_) | Self::TransitCallerUnauthenticated | Self::ConsentRequired(_) => {
                StatusCode::UNAUTHORIZED
            }

            Self::TransitPointUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::DelegationRefused { refusal, .. } => refusal.status_code(),
            Self::McpResourceAuthorization { error, .. } => error.status_code(),

            Self::GatewayPolicyDenied
            | Self::GatewayPolicyError(_)
            | Self::SurfacePolicyDenied
            | Self::SurfacePolicyError(_)
            | Self::TransitPointResponsePolicyDenied
            | Self::TransitMcpToolGated => StatusCode::FORBIDDEN,

            Self::IdentityResolutionFailed(failure) => match failure {
                IdentityResolutionFailure::ExtensionMissing(_) => StatusCode::UNPROCESSABLE_ENTITY,
                IdentityResolutionFailure::ServiceUnavailable(_) => StatusCode::BAD_GATEWAY,
                IdentityResolutionFailure::Misconfigured(_) => StatusCode::INTERNAL_SERVER_ERROR,
                IdentityResolutionFailure::BackendUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            },

            Self::TargetAuthUnavailable
            | Self::UpstreamConnectionFailed(_)
            | Self::UpstreamResponseReadFailed
            | Self::ResponseValidationFailed(_)
            | Self::UnrewritableExtendedAgentCardResponse { .. } => StatusCode::BAD_GATEWAY,

            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,

            Self::BodyNotAvailable(_)
            | Self::MetadataInjectionFailed
            | Self::ResponseBuildFailed
            | Self::IdentityInjectionFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for OutboundPipelineError {
    fn into_response(self) -> Response {
        if let Self::McpResourceAuthorization { config, error } = self {
            return config.challenge(error);
        }
        if let Self::McpValidation(error) = self {
            return (*error).into_response();
        }
        if let Self::McpBodyRefused(refusal) = self {
            return refusal.into_response();
        }
        if let Self::UnrewritableExtendedAgentCardResponse { rpc_request_id } = self {
            return crate::a2a::url_rewriter::extended_agent_card_refusal(rpc_request_id.as_ref());
        }
        if let Self::ExtendedAgentCardBatch = self {
            return crate::a2a::create_jsonrpc_error_response(StatusCode::BAD_REQUEST, -32600, &self.to_string());
        }
        if let Self::UpstreamCapacityReached(id) = self {
            return crate::proxy::fabric_forward::capacity_response(id);
        }
        if let Self::DelegationRefused {
            refusal,
            mcp_request_id: Some(id),
        } = self
        {
            return crate::mcp::request_validation::McpRequestValidationError {
                status: refusal.status_code(),
                id: Some(id),
                code: refusal.jsonrpc_code(),
                message: refusal.to_string(),
                data: None,
            }
            .into_response();
        }
        if let Self::TransitPointUnavailable { mcp_request_id: Some(id) } = &self {
            return crate::mcp::request_validation::McpRequestValidationError {
                status: self.status_code(),
                id: Some(id.clone()),
                code: crate::mcp::errors::error_codes::INTERNAL_ERROR,
                message: self.to_string(),
                data: None,
            }
            .into_response();
        }
        if let Self::McpMetadata { error, body, response } = self {
            return error.into_response(
                &body,
                if response {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::BAD_REQUEST
                },
            );
        }
        // ConsentRequired carries a pre-formed JSON body for the caller
        if let Self::ConsentRequired(body) = self {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "application/problem+json")
                .body(axum::body::Body::from(body))
                .unwrap_or_else(|_| create_error_response(StatusCode::UNAUTHORIZED, "consent_required"));
        }
        create_error_response(self.status_code(), &self.to_string())
    }
}

// Static assertion: OutboundProxyState must satisfy axum Handler bounds.
const _: () = {
    fn _assert_send_sync_clone<T: Send + Sync + Clone + 'static>() {}
    fn _check() {
        _assert_send_sync_clone::<OutboundProxyState>();
    }
};

// ── Pipeline context ────────────────────────────────────────────────────────

/// Accumulated state for one outbound request flowing through the pipeline.
///
/// Each step method receives `&mut OutboundPipelineContext`.  A step that needs
/// to short-circuit the pipeline returns `Err(response)`.
pub struct OutboundPipelineContext {
    /// The original request from the protected agent (consumed after body extraction).
    pub request: Option<Request>,
    /// Remote address of the protected agent.
    pub remote_addr: SocketAddr,
    /// The matched transit point (resolved from path alias). Sourced from
    /// `surface.transit.points`; runtime authoritative.
    pub virtual_channel: TransitPoint,
    /// Convenience copy of the surface's `transit.shared` block
    /// (guaranteed non-None when the context is created).
    pub outbound_shared: SharedTransitConfig,
    /// Raw request body bytes (populated by the first step that reads the body).
    pub body_bytes: Option<Bytes>,
    /// Original HTTP method, preserved before the request is consumed.
    pub original_method: Method,
    /// Original request headers (minus hop-by-hop), preserved before the request is consumed.
    pub original_headers: HeaderMap,
    /// Delegated credential headers resolved for this request. Kept apart from the
    /// managed agent's headers and sent after the agent's headers are filtered, in
    /// place of any agent header of the same name.
    pub delegated_credential_headers: HeaderMap,
    /// Request path (used to build target URL).
    pub request_path: String,
    /// Protected agent identity resolved by `step_resolve_agent_identity`.
    pub resolved_identity: ProtectedAgentIdentity,
    /// Detected protocol (A2A, MCP, HTTP).
    pub protocol: Option<ChannelProtocol>,
    pub mcp_metadata_context: crate::mcp::meta::McpMetadataContext,
    pub mcp_classification: Option<crate::mcp::request_validation::McpRequestClassification>,
    /// The caller this Transit Point authenticated itself, with
    /// `mcp_http.authorization` or `source_auth`.
    pub authenticated_identity: Option<crate::source_auth::AuthenticatedIdentity>,
    /// What authenticated `authenticated_identity`, set with it. An identity
    /// without one is not reported as `input.transit.client`.
    pub authenticated_by: Option<crate::surface_context::TransitClientVerification>,
    pub mcp_resource_authorization: Option<crate::mcp::resource_server::McpResourceServerConfig>,
    pub modern_delegation: Option<Box<crate::proxy::credential_delegation::modern::PreparedDelegation>>,
    /// Extracted method / tool name / operation identifier.
    pub operation: Option<String>,
    /// Target agent context from trust registry (populated by Step 8).
    pub target_agent_context: Option<crate::surface_context::AgentContext>,
    /// Marker: the widened Trust-Check-only gate opened Step 8 but the
    /// target's agent card could not be fetched. `step_trust_check`
    /// consumes this to synthesize `AGENT_CARD_UNAVAILABLE` results per
    /// configured element instead of executing TRQP probes.
    pub target_agent_card_unavailable: bool,
    /// Marker: the routed Transit Point's `trust_check_list` is non-empty
    /// (Trust Check active) and the target card's agent identity could not
    /// be established — either the `agent-identity-credential/v1` VP is
    /// absent, or it is present but fails cryptographic verification
    /// (proof/expiry failure, or no `VCIssuer` to verify with).
    /// `step_trust_check` consumes this to synthesize one result per
    /// configured element using the carried code
    /// ([`TARGET_AGENT_IDENTITY_UNAVAILABLE`] when no VP was present;
    /// [`IDENTITY_VP_VERIFICATION_FAILED`] when a VP was present but
    /// unverifiable). Mutually exclusive with `target_agent_card_unavailable`
    /// (the card must have been fetched for verification to run).
    pub target_identity_failure: Option<crate::trust_registry_verification::TrustCheckIdentityVerificationFailure>,
    /// Per-leg Trust Check stage results (populated by
    /// `step_trust_check`). Threaded into every outbound OPA evaluation
    /// via `build_outbound_policy_input`. `None` when the routed Transit
    /// Point's `trust_check_list` is empty; otherwise the routed Transit
    /// Point's results under `target`.
    pub trust_check_results: Option<crate::trust_registry_verification::TrustCheckResultsContext>,
    /// Unique request ID for tracing.
    pub request_id: String,
    /// Timestamp recorded at context creation (used for latency metrics).
    pub start_time: Instant,
    /// Pre-compiled rules engine for outbound request extension validation (from live channel state).
    pub _outbound_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    /// Pre-compiled rules engine for outbound response extension validation (from live channel state).
    pub outbound_response_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    /// Validated transit token claims (populated by step_validate_transit_token).
    /// Carries the original caller context from the inbound request.
    pub transit_token_claims: Option<crate::proxy::transit_token::TransitTokenClaims>,
    /// Claims of a valid transit token sent to a Transit Point that does not
    /// require one. Only `input.transit.caller` reads them: delegation,
    /// Workload Binding, stream expiry and the trace id keep treating the call
    /// as carrying no token.
    pub optional_transit_token_claims: Option<crate::proxy::transit_token::TransitTokenClaims>,
    /// Size in bytes of the upstream response body, captured by
    /// `step_process_response` before the body is consumed. Used by
    /// `step_record_metrics` for per-transit-point throughput accounting.
    pub response_bytes: Option<u64>,
    /// Surface variant alias parsed from the request route (`/route$alias/tp/...`).
    /// `None` when the request targets the default variant.
    pub active_variant_alias: Option<String>,
    pub active_variant_id: Option<String>,
    /// A modern MCP request refused at routing, already recorded. It is
    /// answered before any other step, once the body has been read for its `id`.
    pub pending_variant_refusal: Option<crate::audit::request_events::RoutingRefusal>,
    /// Resolved [`AgentSurface`] for this outbound request, symmetric
    /// to inbound `ProxyState::surface`. Built once per request via
    /// `from_channel_mapping → resolve_variant(alias)` so downstream
    /// consumers can read from the surface while the legacy `channel`
    /// projection remains available during the transition.
    pub surface: Arc<crate::config::agent_surface::AgentSurface>,
    /// Rules engine scoped to identity management (compiled from managed_identity.extension_rules).
    pub identity_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    /// Identity selector with compiled JSON schema (for schema validation and x-identity field extraction).
    pub identity_selector: Option<Arc<crate::identity::IdentitySelector>>,
}

impl OutboundPipelineContext {
    /// Construct a context by resolving the virtual channel alias from the request path.
    ///
    /// Reads the latest channel configuration from the shared `channel_state` lock,
    /// ensuring that config updates are visible without restarting the listener.
    ///
    /// Returns `Err` when:
    /// * `outbound` is disabled on the channel → 404.
    /// * The `<virtual-channel>` segment is missing or unknown → 404.
    pub fn new(
        addr: SocketAddr,
        req: Request,
        state: &OutboundProxyState,
        versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
    ) -> Result<Self, OutboundPipelineError> {
        // Read the latest channel state (sub-microsecond lock).
        let cs = state
            .channel_state
            .read()
            .expect("outbound channel_state lock poisoned");
        let cs_surface_for_resolve = cs.surface.clone();
        let identity_rules_engine = cs
            .identity_rules_engine
            .clone();
        let identity_selector = cs.identity_selector.clone();
        drop(cs);

        let outbound_shared = match cs_surface_for_resolve
            .transit
            .as_ref()
            .filter(|t| !t.points.is_empty())
        {
            Some(t) => t.shared.clone(),
            None => {
                return Err(OutboundPipelineError::OutboundDisabled);
            }
        };

        // Preserve method, path, and headers before the body is consumed.
        let original_method = req.method().clone();
        let request_path = req.uri().path().to_string();
        let original_headers = req.headers().clone();

        // Resolve virtual channel. When the route was registered at a
        // custom `listen_path`, the request path no longer follows the
        // `/outbound/<route>/<alias>` convention - `state.vc_alias_override`
        // tells us exactly which VC this handler instance serves.
        let path = req.uri().path();
        let surface_for_resolve = cs_surface_for_resolve.clone();
        let (matched_virtual_channel, active_variant_alias) = if let Some(ref alias) = state.vc_alias_override {
            let vc = surface_for_resolve
                .transit_points()
                .iter()
                .find(|tp| tp.alias == *alias)
                .cloned()
                .ok_or_else(|| OutboundPipelineError::UnknownVirtualChannelAlias(alias.clone()))?;
            // Even with the listen-path override, the request URL may still
            // carry a `$alias` suffix for the surface variant; parse it.
            let variant_alias = vc
                .listen_path
                .as_deref()
                .and_then(|route| {
                    crate::proxy::route_variant::extract_variant_alias_for_route(path, route.trim_end_matches('/'))
                })
                .or_else(|| {
                    crate::proxy::route_variant::extract_variant_alias_for_route(
                        path.strip_prefix(TP_OUTBOUND_PATH_PREFIX)
                            .unwrap_or(path),
                        surface_for_resolve
                            .route()
                            .trim_end_matches('/'),
                    )
                })
                .flatten();
            (vc, variant_alias)
        } else {
            resolve_virtual_channel(path, &surface_for_resolve)?
        };

        // The URL's alias, else the default variant, else the base surface
        // serves the request. A variant that can't be resolved leaves the
        // request on the unresolved surface, to be refused below.
        let (active_variant_id, surface, unresolved) =
            match surface_for_resolve.serve_variant(active_variant_alias.as_deref()) {
                Ok(served) => {
                    crate::observability::policy_audit::set_request_variant(&served.recorded);
                    (served.id, Arc::new(served.surface), None)
                }
                Err(error) => (None, Arc::clone(&surface_for_resolve), Some(error)),
            };

        let virtual_channel = surface
            .transit_points()
            .iter()
            .find(|tp| tp.alias == matched_virtual_channel.alias)
            .cloned()
            .ok_or_else(|| {
                OutboundPipelineError::UnknownVirtualChannelAlias(
                    matched_virtual_channel
                        .alias
                        .clone(),
                )
            })?;

        // The refusal is recorded only once nothing else can fail, so its record
        // matches the answer. A modern MCP request, whatever its method, is
        // answered later, once its body is read for the `id`; every other
        // request now. So a request that reaches any later step and names an
        // alias always has that alias's `active_variant_id`.
        let modern_mcp = matched_virtual_channel.protocol == crate::config::agent_surface::TransitProtocol::Mcp
            && crate::mcp::request_validation::has_modern_header(&original_headers, versions);
        let pending_variant_refusal = match unresolved {
            None => None,
            Some(error) => {
                let rpc_error_code = modern_mcp.then_some(i64::from(crate::mcp::error_codes::INTERNAL_ERROR));
                let refusal = crate::audit::request_events::refuse_routing(
                    &crate::audit::request_events::RequestFacts {
                        surface_id: &surface_for_resolve.surface_id,
                        channel_name: &surface_for_resolve.name,
                        trace_id: None,
                        via_fabric: false,
                    },
                    &error,
                    rpc_error_code,
                );
                refusal.warn(&surface_for_resolve);
                if !modern_mcp {
                    return Err(OutboundPipelineError::VariantRefused(refusal));
                }
                Some(refusal)
            }
        };
        let outbound_shared = surface
            .transit
            .as_ref()
            .map(|t| t.shared.clone())
            .unwrap_or(outbound_shared);

        // Per-VC identity override: when this outbound virtual channel
        // declares its own `managed_identity`, build a per-VC selector
        // and rules engine that take precedence over the channel-wide
        // engines for this request. Uses the variant-effective Transit
        // Point so per-variant managed identity and header mapping stay
        // coherent.
        let (identity_rules_engine, identity_selector) = if let Some(ref mi) = virtual_channel.managed_identity {
            match crate::proxy::compile_identity_engines_from_managed_identity(mi, state.vc_issuer.as_ref()) {
                Ok(per_vc) => (per_vc.rules_engine, per_vc.selector),
                Err(e) => {
                    tracing::warn!(
                        surface = %cs_surface_for_resolve.name,
                        vc = %virtual_channel.alias,
                        error = %e,
                        "Failed to compile per-VC identity engines; falling back to channel-wide engines"
                    );
                    (identity_rules_engine, identity_selector)
                }
            }
        } else {
            (identity_rules_engine, identity_selector)
        };

        let outbound_rules_engine = None;
        let outbound_response_rules_engine = None;

        // Fallback trace continuation: reuse a valid inbound `X-Gateway-Trace-Id`
        // if the managed agent forwarded it. The authoritative carrier is the
        // transit token (see `step_validate_transit_token`, which overrides this
        // from `claims.trace_id`); this only helps when no transit token is used
        // but the agent still echoes the header. UUID-checked to block injection.
        let request_id = original_headers
            .get("X-Gateway-Trace-Id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| {
                uuid::Uuid::parse_str(s)
                    .ok()
                    .map(|_| s.to_string())
            })
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        Ok(Self {
            request: Some(req),
            remote_addr: addr,
            virtual_channel,
            outbound_shared,
            body_bytes: None,
            original_method,
            original_headers,
            delegated_credential_headers: HeaderMap::new(),
            request_path,
            resolved_identity: ProtectedAgentIdentity::Anonymous,
            protocol: None,
            mcp_metadata_context: crate::mcp::meta::McpMetadataContext::legacy(surface.mcp_legacy_metadata_output),
            mcp_classification: None,
            authenticated_identity: None,
            authenticated_by: None,
            mcp_resource_authorization: None,
            modern_delegation: None,
            operation: None,
            target_agent_context: None,
            target_agent_card_unavailable: false,
            target_identity_failure: None,
            trust_check_results: None,
            request_id,
            start_time: Instant::now(),
            _outbound_rules_engine: outbound_rules_engine,
            outbound_response_rules_engine,
            transit_token_claims: None,
            optional_transit_token_claims: None,
            response_bytes: None,
            active_variant_alias,
            active_variant_id,
            pending_variant_refusal,
            surface,
            identity_rules_engine,
            identity_selector,
        })
    }

    /// Answers a modern MCP request refused at routing with the JSON-RPC error,
    /// reading the body within the Transit Point's MCP body limit only to echo
    /// its `id`. A body that can't be read is answered without one.
    async fn answer_variant_refusal(
        &mut self,
        state: &OutboundProxyState,
        versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
        refusal: &crate::audit::request_events::RoutingRefusal,
    ) -> Response {
        crate::mcp::request_validation::answer_routing_refusal(
            refusal,
            self.virtual_channel
                .mcp_http
                .as_ref(),
            &state
                .network_config
                .get_outbound_external_urls(),
            versions,
            self.request
                .take()
                .map(Request::into_body),
        )
        .await
    }
}

// ── Virtual channel resolution ──────────────────────────────────────────────

/// Extract the transit-point name (and optional surface-variant alias) from
/// the outbound path and look up the matching outbound virtual channel.
///
/// Path layout:  `/outbound/<aap-path>[$variant-alias]/<tp-name>[/<remainder>]`
///
/// Axum provides the full request path including `/outbound/`. The optional
/// `$variant-alias` suffix on the route selects a surface variant; the
/// variant alias is returned to the caller so it can be threaded through
/// the pipeline.
fn resolve_virtual_channel(
    path: &str,
    surface: &crate::config::agent_surface::AgentSurface,
) -> Result<(TransitPoint, Option<String>), OutboundPipelineError> {
    // Strip the /outbound prefix first.
    let after_outgoing = path
        .strip_prefix(TP_OUTBOUND_PATH_PREFIX)
        .unwrap_or(path);

    // Strip the channel route prefix and any `$variant-alias` suffix.
    let route = surface
        .route()
        .trim_end_matches('/');
    let prefix: &str = if route.is_empty() {
        ""
    } else {
        route
    };
    let (variant_alias, tail) = match crate::proxy::route_variant::parse_route_with_variant(after_outgoing, prefix) {
        Some(m) => (m.alias.map(|s| s.to_string()), m.tail),
        None => (None, after_outgoing),
    };
    let after_route = tail.trim_start_matches('/');

    // The first remaining path segment is the transit-point name.
    let alias = after_route
        .split('/')
        .next()
        .unwrap_or("");

    if alias.is_empty() {
        return Err(OutboundPipelineError::MissingVirtualChannelAlias);
    }

    let vc = surface
        .transit_points()
        .iter()
        .find(|tp| tp.alias == alias)
        .cloned()
        .ok_or_else(|| OutboundPipelineError::UnknownVirtualChannelAlias(alias.to_string()))?;

    Ok((vc, variant_alias))
}

// ── Entry points ────────────────────────────────────────────────────────────

/// Axum handler for outbound requests.
///
/// Wraps [`outbound_proxy_handler_inner`] in a `catch_unwind` fence so that
/// panics inside any pipeline step produce a `500 Internal Server Error` rather
/// than crashing the listener.
pub async fn outbound_proxy_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<OutboundProxyState>,
    req: Request,
) -> Response {
    match outbound_proxy_handler_inner(addr, state, req).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

fn _assert_send<F: Send>(f: F) -> F {
    f
}

#[allow(dead_code)]
async fn outbound_proxy_handler_check(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<OutboundProxyState>,
    req: Request,
) -> Response {
    match _assert_send(outbound_proxy_handler_inner(addr, state, req)).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

/// Inner orchestrator — calls each pipeline step in sequence.
///
/// On `Err` from any step the pipeline short-circuits and the error
/// is converted to an HTTP response at the boundary.
async fn outbound_proxy_handler_inner(
    addr: SocketAddr,
    state: OutboundProxyState,
    req: Request,
) -> Result<Response, OutboundPipelineError> {
    Box::pin(outbound_proxy_handler_with_mcp_versions(
        addr,
        state,
        req,
        crate::mcp::request_validation::runtime_policy_for(crate::mcp::request_validation::McpPathKind::TransitPoint),
    ))
    .await
}

async fn outbound_proxy_handler_with_mcp_versions(
    addr: SocketAddr,
    state: OutboundProxyState,
    req: Request,
    versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
) -> Result<Response, OutboundPipelineError> {
    use crate::observability::policy_audit::{RequestScope, in_request, response_in_request};

    let scope = RequestScope::fresh();
    in_request(scope.clone(), Box::pin(outbound_proxy_handler_in_request_scope(addr, state, req, versions)))
        .await
        .map(|response| response_in_request(scope, response))
}

async fn outbound_proxy_handler_in_request_scope(
    addr: SocketAddr,
    state: OutboundProxyState,
    req: Request,
    versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
) -> Result<Response, OutboundPipelineError> {
    let mut subscription_access =
        crate::mcp::subscriptions::SubscriptionLifetime::new(std::time::Duration::from_secs(86_400), None);
    let mut ctx = OutboundPipelineContext::new(addr, req, &state, versions)?;
    if let Some(refusal) = ctx
        .pending_variant_refusal
        .take()
    {
        return Ok(ctx
            .answer_variant_refusal(&state, versions, &refusal)
            .await);
    }

    step_source_auth(&state, &mut ctx).await?;

    // [0] Transit Token Validation (§6.2 step 1)
    // Verify the transit token echoed back by the managed agent.
    // Extracts caller context and validates the token is authorized for this transit point.
    step_validate_transit_token(&state, &mut ctx).await?;

    // [2] Rate Limiting
    step_rate_limit(&state, &mut ctx).await?;

    // [3] Protocol Context Extraction (reads body, detects A2A/MCP/HTTP)
    if let Some(response) = step_extract_protocol_context_with_versions(&state, &mut ctx, versions).await? {
        return Ok(response);
    }

    if let Some(crate::mcp::request_validation::McpRequestClassification::Modern(_)) = ctx
        .mcp_classification
        .as_ref()
    {
        step_validate_transit_token(&state, &mut ctx).await?;
    }

    let subscription_lifetime = match ctx
        .mcp_classification
        .as_ref()
    {
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(request))
            if request.method == "subscriptions/listen" =>
        {
            let caller = crate::mcp::subscriptions::listen_caller(
                ctx.authenticated_identity
                    .as_ref(),
                &ctx.remote_addr
                    .ip()
                    .to_string(),
            );
            let slot = crate::mcp::subscriptions::ListenSlots::global()
                .acquire(&format!("transit:{}", ctx.virtual_channel.id), &caller)
                .ok_or_else(|| {
                    OutboundPipelineError::McpValidation(Box::new(crate::mcp::subscriptions::listen_limit_error(
                        request,
                    )))
                })?;
            subscription_access.hold(slot);
            subscription_access.record_owner(
                ctx.surface.surface_id.clone(),
                ctx.surface
                    .tenant_id
                    .as_deref(),
            );
            if let Some(vault) = &state.delegation_vault_store {
                subscription_access
                    .watch_vault(vault.clone())
                    .await
                    .map_err(|_| {
                        OutboundPipelineError::McpValidation(Box::new(
                            crate::mcp::request_validation::McpRequestValidationError {
                                status: StatusCode::SERVICE_UNAVAILABLE,
                                id: request.id.clone(),
                                code: crate::mcp::error_codes::INTERNAL_ERROR,
                                message: "MCP subscription authorization unavailable".into(),
                                data: None,
                            },
                        ))
                    })?;
            }
            subscription_access.restrict_to_identity(
                ctx.authenticated_identity
                    .as_ref(),
            );
            subscription_access.restrict_lifetime(std::time::Duration::from_secs(
                ctx.virtual_channel
                    .mcp_http
                    .clone()
                    .unwrap_or_default()
                    .stream_max_lifetime_secs
                    .get(),
            ));
            if let Some(claims) = ctx
                .transit_token_claims
                .as_ref()
            {
                subscription_access.restrict_to_expiry(claims.exp);
            }
            Some(subscription_access)
        }
        _ => None,
    };

    // [3.25] Transit Point Header Metadata Mapping (A2A/AP2 only)
    step_map_transit_point_header_metadata(&state, &mut ctx).await?;

    // [3.5] Outbound Extension Inspection (A2A only — validates watched extensions)
    step_inspect_outbound_extensions(&state, &mut ctx).await?;

    // [4] Agent Identity Resolution (extract + validate + issue_or_get_credential)
    step_resolve_agent_identity(&state, &mut ctx).await?;

    // [5] Trusted Identity Injection (VP credential into outbound body)
    step_inject_trusted_identity(&state, &mut ctx).await?;

    // [7] Custom Metadata Injection
    step_inject_custom_metadata(&state, &mut ctx).await?;

    // Public/discovery paths (agent card, UCP well-known) are metadata-
    // only GETs — skip trust context, trust check, and OPA evaluation.
    let is_discovery = ctx.original_method == Method::GET && crate::proxy::paths::is_public_path(&ctx.request_path);

    if !is_discovery {
        // [8] Trust Context Collection
        step_collect_trust_context(&state, &mut ctx).await?;

        // [8b] Trust Check stage (target leg) — runs before any OPA so all
        // three outbound OPA scopes see the same `input.trust_check_results`.
        step_trust_check(&state, &mut ctx).await?;

        // [9] Gateway-Level OPA Policy
        step_gateway_opa_policy(&state, &mut ctx).await?;

        // [10] Surface-Level OPA Policy
        step_surface_opa_policy(&state, &mut ctx).await?;

        // [9.5] Per-Transit-Point OPA Policy (§6.2 step 10)
        step_transit_point_opa_policy(&state, &mut ctx).await?;

        // [10.6] Per-Transit-Point MCP Tool Gating (tools/call leg) — blocks an
        // outbound tools/call whose tool this TP's gating firewall hides.
        step_transit_mcp_tool_gating(&state, &mut ctx).await?;
    }

    // [11] Credential Injection (§5.3 / §6.2 step 12)
    // Inject delegated OAuth tokens from the credential vault, or signal consent_required.
    if let Some(response) = step_prepare_modern_credentials(&state, &mut ctx).await? {
        return Ok(response);
    }
    step_inject_credentials(&state, &mut ctx).await?;

    request_uncompressed_extended_agent_card(&mut ctx);

    // [12] Forward Request
    let upstream_response = step_forward_request(&state, &mut ctx).await?;

    if matches!(
        ctx.mcp_classification
            .as_ref(),
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
    ) {
        let response = process_modern_outbound_response(state, ctx, upstream_response).await?;
        return Ok(match subscription_lifetime {
            Some(lifetime) => lifetime.wrap(response),
            None => response,
        });
    }

    // [13] Response Processing
    let processed_response = step_process_response(&state, &mut ctx, upstream_response).await?;

    // [13] Metrics & Logging (never fails)
    step_record_metrics(
        &state,
        &ctx,
        processed_response
            .status()
            .is_success(),
    );

    Ok(processed_response)
}

// ── Pipeline steps ──────────────────────────────────────────────────────────
//
// Each step is an independent `async fn`. Steps that are not yet
// implemented are stubs returning `Ok(())`.

/// [0] Transit Token Validation — verifies the `X-Transit-Token` header.
///
/// Per §5.5 of the Agent Surface Design, transit calls MUST include a valid
/// transit token that was injected into the original inbound response. The token
/// carries the caller context (who initiated the inbound request) and is bound
/// to specific transit points.
///
/// Without a valid transit token, the request is rejected with 401 Unauthorized,
/// and why is logged.
async fn step_validate_transit_token(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let validated = validate_transit_token(state, ctx).await;
    if let Err(OutboundPipelineError::TransitTokenInvalid(reason)) = &validated {
        warn!(
            request_id = %ctx.request_id,
            transit_point = %ctx.virtual_channel.alias,
            reason = %reason,
            "Transit token refused"
        );
    }
    validated
}

async fn validate_transit_token(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    // Public/discovery endpoints (agent card, `.well-known/*`) are unauthenticated
    // metadata GETs. The transit token is a transit-point *authorization* control,
    // so it doesn't apply to them — mirroring the discovery bypass the later
    // identity/trust-context/trust-check/OPA stages already use. Without this an
    // agent-card fetch through a transit point is rejected for a missing
    // `X-Transit-Token` before it can reach those bypasses. The trace id stays the
    // one `OutboundContext::new` derived (no token to adopt one from), which is
    // fine for a standalone metadata GET.
    if ctx.original_method == Method::GET && crate::proxy::paths::is_public_path(&ctx.request_path) {
        debug!(
            request_id = %ctx.request_id,
            "Transit token validation skipped for public discovery path"
        );
        return Ok(());
    }

    let modern = matches!(
        ctx.mcp_classification
            .as_ref(),
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
    );

    if !ctx
        .virtual_channel
        .require_transit_token
    {
        // Per-TP opt-out: this transit point is configured to accept
        // calls without a transit token (e.g. dev/testing or a TP whose
        // callers cannot carry one). A token the agent sends anyway is still
        // checked so policy sees the caller it names, and only policy: it
        // does not drive delegation, Workload Binding, stream expiry or the
        // trace id. One that does not verify is ignored and the caller stays
        // anonymous. Each pass replaces the last, so a token the first pass
        // accepted within the clock leeway and the strict modern MCP pass
        // refuses no longer names the caller.
        ctx.optional_transit_token_claims = None;
        let mut tokens = ctx
            .original_headers
            .get_all("x-transit-token")
            .iter();
        let token = match (tokens.next(), tokens.next()) {
            (Some(value), None) => value.to_str().ok(),
            _ => None,
        };
        match state
            .transit_token_issuer
            .as_ref()
            .zip(token)
        {
            Some((issuer, token)) => match verify_transit_token(ctx, issuer, token, modern) {
                Ok(claims) => ctx.optional_transit_token_claims = Some(claims),
                Err(OutboundPipelineError::TransitTokenInvalid(reason)) => debug!(
                    request_id = %ctx.request_id,
                    alias = %ctx.virtual_channel.alias,
                    reason = %reason,
                    "Optional transit token did not verify, caller treated as anonymous"
                ),
                Err(_) => {}
            },
            None => debug!(
                request_id = %ctx.request_id,
                alias = %ctx.virtual_channel.alias,
                "Transit token enforcement disabled for this transit point, skipping validation"
            ),
        }
        return Ok(());
    }

    if modern {
        ctx.transit_token_claims = None;
    }
    let Some(ref issuer) = state.transit_token_issuer else {
        return Err(OutboundPipelineError::TransitTokenInvalid("Transit token validation is unavailable".into()));
    };

    if modern
        && ctx
            .original_headers
            .get_all("x-transit-token")
            .iter()
            .count()
            != 1
    {
        return Err(OutboundPipelineError::TransitTokenInvalid("Expected exactly one X-Transit-Token header".into()));
    }

    // Extract the transit token from the X-Transit-Token header.
    let token = ctx
        .original_headers
        .get("X-Transit-Token")
        .or_else(|| {
            ctx.original_headers
                .get("x-transit-token")
        })
        .and_then(|v| v.to_str().ok());

    let Some(token) = token else {
        return Err(OutboundPipelineError::TransitTokenInvalid("missing X-Transit-Token header".to_string()));
    };

    let claims = verify_transit_token(ctx, issuer, token, modern)?;
    adopt_transit_token(ctx, claims);
    Ok(())
}

/// Validates the token and checks it was issued for this surface, lives no
/// longer than the surface now allows, and opens this transit point.
fn verify_transit_token(
    ctx: &OutboundPipelineContext,
    issuer: &crate::proxy::transit_token::TransitTokenIssuer,
    token: &str,
    modern: bool,
) -> Result<crate::proxy::transit_token::TransitTokenClaims, OutboundPipelineError> {
    let transit_point_name = &ctx.virtual_channel.alias;
    let claims = issuer
        .validate_for_transit_point(
            token,
            &ctx.surface.surface_id,
            transit_point_name,
            ctx.surface
                .transit_token_lifetime_secs(),
        )
        .map_err(|e| OutboundPipelineError::TransitTokenInvalid(e.to_string()))?;

    if modern {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                OutboundPipelineError::TransitTokenInvalid("Transit token validation clock is unavailable".into())
            })?
            .as_secs();
        if claims.exp <= now || claims.iat > now {
            return Err(OutboundPipelineError::TransitTokenInvalid(
                "Transit token is not live for this surface".into(),
            ));
        }
    }

    debug!(
        request_id = %ctx.request_id,
        caller_did = ?claims.sub,
        surface_id = %claims.surface_id,
        transit_point = %transit_point_name,
        "Transit token validated successfully"
    );
    Ok(claims)
}

/// Records a verified transit token's claims on the request.
fn adopt_transit_token(
    ctx: &mut OutboundPipelineContext,
    claims: crate::proxy::transit_token::TransitTokenClaims,
) {
    // Continue the originating inbound request's trace across the transit hop.
    // The inbound pipeline stamped its `trace_id` into this token; reusing it
    // (over the fresh id minted in `OutboundContext::new`) keeps one end-to-end
    // trace through the TP leg — so the injected VPs and audit on the GW1→TP→GW2
    // chain all share one id. The managed agent echoes the token reliably, so
    // this is the robust carrier (vs. hoping it forwards `X-Gateway-Trace-Id`).
    if let Some(tid) = claims.trace_id.clone() {
        ctx.request_id = tid;
    }

    ctx.transit_token_claims = Some(claims);
}

/// Caller authentication, before anything else reads or forwards the request.
/// A Transit Point whose caller authentication cannot be enforced
/// ([`TransitPoint::unenforceable_caller_authentication`]), or whose surface
/// sets `transit.source_auth`, which the gateway does not enforce, has every
/// request refused. An MCP Transit Point with `mcp_http.authorization` requires
/// its resource access token, and one with `source_auth` the credential it
/// names, which is never forwarded. The transit token is checked next.
async fn step_source_auth(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let unenforceable = if ctx
        .outbound_shared
        .source_auth
        .is_some()
    {
        Some(crate::config::agent_surface::TRANSIT_SOURCE_AUTH_REFUSED.to_string())
    } else {
        ctx.virtual_channel
            .unenforceable_caller_authentication()
    };
    if let Some(reason) = unenforceable {
        warn!(
            request_id = %ctx.request_id,
            surface_id = %ctx.surface.surface_id,
            transit_point = %ctx.virtual_channel.alias,
            reason = %reason,
            "Transit Point request refused: its caller authentication cannot be enforced"
        );
        return Err(transit_point_unavailable(ctx));
    }
    if let Some(source_auth) = ctx
        .virtual_channel
        .source_auth
        .clone()
    {
        return authenticate_transit_caller(state, ctx, &source_auth).await;
    }
    if let Some(authorization) = ctx
        .virtual_channel
        .mcp_http
        .as_ref()
        .and_then(|http| http.authorization.as_ref())
    {
        use crate::protocols::protected_resource::ResourceTokenError;

        let fail = |error| OutboundPipelineError::McpResourceAuthorization {
            config: Box::new(authorization.clone()),
            error,
        };
        let Some((profile, issuer)) = state
            .network_config
            .sts
            .mcp_issuer
            .as_ref()
            .zip(state.vc_issuer.as_deref())
        else {
            return Err(fail(ResourceTokenError::Unavailable));
        };
        let base_route = ctx
            .surface
            .access_point
            .route
            .trim_end_matches('/');
        let base_path = ctx
            .virtual_channel
            .listen_path
            .clone()
            .unwrap_or_else(|| format!("{TP_OUTBOUND_PATH_PREFIX}{base_route}/{}", ctx.virtual_channel.alias));
        let origins = ctx
            .virtual_channel
            .listen_address
            .as_deref()
            .or_else(|| {
                ctx.surface
                    .transit
                    .as_ref()
                    .and_then(|transit| {
                        transit
                            .outbound_listen_address
                            .as_deref()
                    })
            })
            .and_then(|address| {
                state
                    .network_config
                    .map_url_to_port_for_type(address, Some("outbound"))
            })
            .and_then(|port| {
                state
                    .network_config
                    .get_listener_by_port(port)
            })
            .map(|listener| listener.external_urls.clone())
            .unwrap_or_default();
        if ctx.virtual_channel.protocol != crate::config::agent_surface::TransitProtocol::Mcp
            || authorization
                .validate_endpoint(&origins, &base_path)
                .is_err()
            || profile
                .validate_network(&state.network_config)
                .is_err()
        {
            return Err(fail(ResourceTokenError::Unavailable));
        }
        let authorization = authorization
            .for_transit_variant(
                base_route,
                &ctx.virtual_channel,
                ctx.active_variant_alias
                    .as_deref(),
            )
            .map_err(|_| fail(ResourceTokenError::Unavailable))?;
        let keys = Arc::new(crate::jwt_bearer::JwksClient::new());
        let identity = authorization
            .authenticate(&ctx.original_headers, profile, issuer, keys)
            .await
            .map_err(|error| OutboundPipelineError::McpResourceAuthorization {
                config: Box::new(authorization.clone()),
                error,
            })?;
        ctx.original_headers
            .remove(axum::http::header::AUTHORIZATION);
        if let Some(request) = ctx.request.as_mut() {
            request
                .headers_mut()
                .remove(axum::http::header::AUTHORIZATION);
        }
        ctx.authenticated_identity = Some(identity);
        ctx.authenticated_by = Some(crate::surface_context::TransitClientVerification::ResourceToken);
        ctx.mcp_resource_authorization = Some(authorization);
    }
    Ok(())
}

/// Authenticates the caller with the Transit Point's `source_auth`, as the
/// Access Point does. A missing or refused credential is refused with `401`,
/// and a check the gateway cannot run with `503`; why is logged. The
/// credential's header is removed, so it never reaches the target.
async fn authenticate_transit_caller(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
    source_auth: &crate::source_auth::SourceAuthConfig,
) -> Result<(), OutboundPipelineError> {
    let middleware = crate::source_auth::middleware::require_installed(
        state
            .source_auth_middleware
            .clone(),
    )
    .map_err(|error| caller_authentication_unavailable(ctx, &error))?;
    // A Transit Point publishes no protected resource metadata, so its
    // `source_auth` keeps the audiences it names.
    let config = crate::source_auth::middleware::resolve_surface_audience(
        source_auth,
        None,
        state.vc_issuer.as_deref(),
        &ctx.surface.surface_id,
    )
    .await
    .map_err(|error| caller_authentication_unavailable(ctx, &error))?;
    let peer_cert = ctx
        .request
        .as_ref()
        .and_then(|request| {
            request
                .extensions()
                .get::<crate::source_auth::models::PeerCertInfo>()
        });
    let authenticated = middleware
        .authenticate(&config, &ctx.original_headers, &ctx.surface.name, &ctx.surface.surface_id, peer_cert)
        .await;
    match authenticated {
        Ok(identity) => {
            if let Some(header) = config.credential_header_name() {
                ctx.original_headers
                    .remove(header);
                if let Some(request) = ctx.request.as_mut() {
                    request
                        .headers_mut()
                        .remove(header);
                }
            }
            ctx.authenticated_identity = Some(identity);
            ctx.authenticated_by = Some(crate::surface_context::TransitClientVerification::SourceAuth);
            Ok(())
        }
        Err(error) if error.is_caller_attributable() => {
            warn!(
                request_id = %ctx.request_id,
                surface_id = %ctx.surface.surface_id,
                transit_point = %ctx.virtual_channel.alias,
                method = config.method_tag(),
                error = ?error,
                "Transit Point caller authentication failed"
            );
            crate::audit::request_events::auth_failed(
                &crate::audit::request_events::RequestFacts {
                    surface_id: &ctx.surface.surface_id,
                    channel_name: &ctx.surface.name,
                    trace_id: Some(&ctx.request_id),
                    via_fabric: false,
                },
                crate::audit::request_events::source_auth_scheme(&config),
                crate::audit::request_events::source_auth_reason(&error),
                true,
                Some(ctx.remote_addr.ip()),
            );
            Err(OutboundPipelineError::TransitCallerUnauthenticated)
        }
        Err(error) => Err(caller_authentication_unavailable(ctx, &error)),
    }
}

fn caller_authentication_unavailable(
    ctx: &OutboundPipelineContext,
    error: &crate::source_auth::errors::SourceAuthError,
) -> OutboundPipelineError {
    warn!(
        request_id = %ctx.request_id,
        surface_id = %ctx.surface.surface_id,
        transit_point = %ctx.virtual_channel.alias,
        error = ?error,
        "Transit Point caller authentication is unavailable"
    );
    transit_point_unavailable(ctx)
}

/// Refuses a request the Transit Point cannot serve; on an MCP Transit Point
/// as a JSON-RPC error, sent before the request id is read.
fn transit_point_unavailable(ctx: &OutboundPipelineContext) -> OutboundPipelineError {
    OutboundPipelineError::TransitPointUnavailable {
        mcp_request_id: (ctx.virtual_channel.protocol == crate::config::agent_surface::TransitProtocol::Mcp)
            .then_some(serde_json::Value::Null),
    }
}

/// [4] Agent Identity Resolution — extracts, validates, and resolves the
/// protected agent's identity from the request body.
///
/// Merges the old `step_extract_agent_identity` + `step_validate_identity` into
/// a single step.  Protocol dispatch happens at the call site using the
/// extraction functions from `backend_identity.rs`.
///
/// When `managed_identity` is absent, the step is a no-op (anonymous).
/// When `managed_identity` is present:
/// - Extraction failure (extension not found) → `Err(IdentityResolutionFailed(ExtensionMissing))` → 422
/// - Validation failure → `Err(IdentityResolutionFailed(ExtensionMissing))` → 422
/// - Credential issuance failure → `Err(IdentityResolutionFailed(ServiceUnavailable))` → 502
async fn step_resolve_agent_identity(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    use crate::proxy::backend_identity::{
        IdentityExtractionError, extract_a2a_identity_from_message_with_uri, extract_mcp_identity,
        flatten_json_to_dot_notation,
    };
    use std::collections::HashMap;

    // Per-TP `managed_identity` (on the TransitPoint) takes
    // precedence over the channel-level setting — this matches how
    // `OutboundPipelineContext::new` already overrides the identity
    // selector/rules engine when the TP has its own config. Without this
    // override the per-TP rule is silently skipped and the request is
    // forwarded without validation (regression on per-TP identity slots).
    let per_tp_identity_configured = ctx
        .virtual_channel
        .managed_identity
        .is_some();
    let surface_managed_identity = ctx.surface.managed_identity();
    let managed_identity = match ctx
        .virtual_channel
        .managed_identity
        .as_ref()
        .or(surface_managed_identity.as_ref())
    {
        Some(mi) => mi,
        None => return Ok(()),
    };

    // A transit point that inherits the surface-level identity (i.e. declares
    // no per-TP `managed_identity` of its own) only performs egress identity
    // resolution + VP injection when its `identity_injection.inject_vp` switch
    // is on. `inject_vp` literally means "inject a signed VP into outbound
    // requests" and defaults to `false`, so a TP that leaves it off has opted
    // out of egress identity management — skip resolution (anonymous) rather
    // than enforcing the inherited `protected`-slot payload schema on a request
    // that never carries it (which would otherwise 422). A TP with its own
    // explicit `managed_identity` always resolves, regardless of `inject_vp`.
    if !per_tp_identity_configured
        && !ctx
            .virtual_channel
            .identity_injection
            .inject_vp
    {
        debug!(
            request_id = %ctx.request_id,
            alias = %ctx.virtual_channel.alias,
            "Outbound: transit point inherits surface identity but inject_vp=false — skipping egress identity management"
        );
        return Ok(());
    }

    // Discovery requests (agent card, UCP well-known, etc.) carry no body,
    // so body-based identity extraction would always fail with 422. Skip
    // identity resolution entirely — the response-path agent card rewrite
    // still runs.
    if ctx.original_method == Method::GET && crate::proxy::paths::is_public_path(&ctx.request_path) {
        debug!(
            request_id = %ctx.request_id,
            "Outbound: public discovery path — skipping identity resolution"
        );
        return Ok(());
    }

    // `FromJwtClaim` is request-bound to the *inbound* caller's validated JWT,
    // so it has no meaning on the outbound (protected → external) path. Skip it
    // here; the inbound path (proxy/backend_identity.rs) owns this mode.
    if matches!(managed_identity, crate::source_auth::ManagedIdentityConfig::FromJwtClaim { .. }) {
        debug!(
            request_id = %ctx.request_id,
            "Outbound: from_jwt_claim managed identity is inbound-only — skipping"
        );
        return Ok(());
    }

    // Short-circuit: `ManagedIdentityConfig::{FromMtls, FromApiKey, Static}`
    // do not require body extraction — the identity is derived from a stored
    // credential (mTLS cert, API key) or fixed. Resolve them here so the
    // pipeline does not insist on parsing a JSON body when none is expected.
    let cred_id_start = Instant::now();
    let cred_id_channel = ctx
        .surface
        .config_id()
        .unwrap_or("unknown")
        .to_string();
    let mode_label = match managed_identity {
        crate::source_auth::ManagedIdentityConfig::PayloadExtraction(_) => "payload_extraction",
        crate::source_auth::ManagedIdentityConfig::FromMtls { .. } => "from_mtls",
        crate::source_auth::ManagedIdentityConfig::FromApiKey { .. } => "from_api_key",
        crate::source_auth::ManagedIdentityConfig::Static { .. } => "static",
        crate::source_auth::ManagedIdentityConfig::FromJwtClaim { .. } => {
            unreachable!("from_jwt_claim is skipped on the outbound path")
        }
    };
    match crate::identity::credential_identity::derive_credential_identity(
        managed_identity,
        state
            .certificates_store
            .as_ref(),
        state.secrets_store.as_ref(),
    )
    .await
    {
        Ok(Some(crate::identity::credential_identity::CredentialIdentity::Bound { did, identity_fields })) => {
            debug!(
                request_id = %ctx.request_id,
                did = %did,
                mode = mode_label,
                "Outbound credential identity is pre-bound — skipping VCIssuer"
            );
            crate::metrics::backends::prometheus::track_managed_identity_resolve(
                &cred_id_channel,
                mode_label,
                "ok_bound",
                cred_id_start
                    .elapsed()
                    .as_secs_f64(),
            );
            ctx.resolved_identity = ProtectedAgentIdentity::Managed { did, identity_fields };
            return Ok(());
        }
        Ok(Some(crate::identity::credential_identity::CredentialIdentity::Derived {
            identity_fields,
            identity_hash,
        })) => {
            let Some(ref vc_issuer) = state.vc_issuer else {
                crate::metrics::backends::prometheus::track_managed_identity_resolve(
                    &cred_id_channel,
                    mode_label,
                    "vc_issuer_missing",
                    cred_id_start
                        .elapsed()
                        .as_secs_f64(),
                );
                return Err(OutboundPipelineError::IdentityResolutionFailed(
                    IdentityResolutionFailure::ServiceUnavailable(
                        "Managed identity is enabled but VCIssuer is not configured".to_string(),
                    ),
                ));
            };
            let response = vc_issuer
                .issue_or_get_managed_credential(
                    identity_fields.clone(),
                    Some(identity_hash.clone()),
                    ctx.surface
                        .config_id()
                        .map(String::from),
                    ctx.surface.issuer_id.clone(),
                )
                .await
                .map_err(|e| {
                    crate::metrics::backends::prometheus::track_managed_identity_resolve(
                        &cred_id_channel,
                        mode_label,
                        "vc_issuer_error",
                        cred_id_start
                            .elapsed()
                            .as_secs_f64(),
                    );
                    OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ServiceUnavailable(
                        format!("DID creation/lookup failed for credential identity: {}", e),
                    ))
                })?;
            if response.is_new {
                info!(
                    request_id = %ctx.request_id,
                    did = %response.did,
                    hash = %identity_hash,
                    mode = mode_label,
                    "Created new DID for outbound credential-based identity"
                );
            } else {
                debug!(
                    request_id = %ctx.request_id,
                    did = %response.did,
                    hash = %identity_hash,
                    mode = mode_label,
                    "Resolved existing DID for outbound credential-based identity"
                );
            }
            crate::metrics::backends::prometheus::track_managed_identity_resolve(
                &cred_id_channel,
                mode_label,
                if response.is_new {
                    "ok_new"
                } else {
                    "ok_cached"
                },
                cred_id_start
                    .elapsed()
                    .as_secs_f64(),
            );
            ctx.resolved_identity = ProtectedAgentIdentity::Managed {
                did: response.did,
                identity_fields,
            };
            return Ok(());
        }
        Ok(None) => {
            // PayloadExtraction — fall through to body-based extraction below.
        }
        Err(e) => {
            use crate::identity::credential_identity::CredentialIdentityErrorClass;
            let reason = e.reason_label();
            crate::metrics::backends::prometheus::track_managed_identity_resolve(
                &cred_id_channel,
                mode_label,
                reason,
                cred_id_start
                    .elapsed()
                    .as_secs_f64(),
            );
            let msg = format!("Credential-based identity resolution failed: {}", e);
            let failure = match e.classify() {
                CredentialIdentityErrorClass::Misconfigured => IdentityResolutionFailure::Misconfigured(msg),
                CredentialIdentityErrorClass::BackendUnavailable => IdentityResolutionFailure::BackendUnavailable(msg),
            };
            return Err(OutboundPipelineError::IdentityResolutionFailed(failure));
        }
    }

    let Some(body) = ctx.body_bytes.as_ref() else {
        return Err(OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(
            "Identity management is enabled but request body is not available".to_string(),
        )));
    };

    if body.is_empty() {
        return Err(OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(
            "Identity management is enabled but request body is empty".to_string(),
        )));
    }

    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| OutboundPipelineError::BodyReadFailed(format!("Request body is not valid JSON: {}", e)))?;

    // Step 1: Extract identity payload (protocol dispatch)
    let surface_protocol = ctx.surface.channel_protocol();
    let protocol = ctx
        .protocol
        .as_ref()
        .unwrap_or(&surface_protocol);

    let raw_payload = match protocol {
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => {
            let extension_uri = match managed_identity {
                crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.identity_extension_uri(),
                crate::source_auth::ManagedIdentityConfig::FromApiKey { .. } => {
                    crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION
                }
                crate::source_auth::ManagedIdentityConfig::FromMtls { .. } => {
                    crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION
                }
                crate::source_auth::ManagedIdentityConfig::Static { .. } => {
                    crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION
                }
                crate::source_auth::ManagedIdentityConfig::FromJwtClaim { .. } => {
                    unreachable!("from_jwt_claim is skipped on the outbound path")
                }
            };
            extract_a2a_identity_from_message_with_uri(&json, extension_uri)
        }
        ChannelProtocol::Mcp => {
            let meta_field = match managed_identity {
                crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.meta_field.as_str(),
                crate::source_auth::ManagedIdentityConfig::FromApiKey { .. } => "_meta",
                crate::source_auth::ManagedIdentityConfig::FromMtls { .. } => "_meta",
                crate::source_auth::ManagedIdentityConfig::Static { .. } => "_meta",
                crate::source_auth::ManagedIdentityConfig::FromJwtClaim { .. } => {
                    unreachable!("from_jwt_claim is skipped on the outbound path")
                }
            };
            // `extract_mcp_identity` returns the *content* of `_meta[meta_field]`
            // (e.g. the object under `agentIdentity`). The identity schema/rules
            // are authored against the wrapped shape (`{ agentIdentity: { … } }`),
            // exactly as the inbound path builds it in `protocols::extensions`, so
            // re-wrap under `meta_field` before validation. Without this the
            // selector looks for `agentIdentity.llmInfo.provider` in a payload that
            // already starts at `llmInfo`, and every field resolves to "not found".
            extract_mcp_identity(&json, meta_field).map(|payload| serde_json::json!({ meta_field: payload }))
        }
        _ => Err(IdentityExtractionError::ExtensionNotFound),
    };

    let raw_payload = match raw_payload {
        Ok(payload) => payload,
        Err(IdentityExtractionError::DeclaredButMissing) => {
            return Err(OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(
                "agent-identity/v1 declared in extensions but missing from metadata".to_string(),
            )));
        }
        Err(_) => {
            return Err(OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(
                "Identity management is enabled but agent-identity extension not found in request".to_string(),
            )));
        }
    };

    // Step 2: Validate against identity rules engine
    if let Some(ref engine) = ctx.identity_rules_engine {
        engine
            .validate(&raw_payload, &ctx.surface.name)
            .map_err(|e| {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Outbound identity validation failed"
                );
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(format!(
                    "Identity validation failed: {}",
                    e
                )))
            })?;
        debug!(request_id = %ctx.request_id, "Outbound identity validation passed");
    }

    // Step 3: Schema validation, field extraction, hash computation, and DID resolution.
    // When an IdentitySelector is available (compiled from managed_identity.extension_rules.json_schema),
    // use it for schema validation and x-identity field extraction — same path as G2G.
    // This ensures payloads are validated against the schema before any VP is created.
    //
    // The call is split into validate+hash (schema error → 422) and DID creation
    // (backend error → 502) to return the correct status code for each failure mode.
    //
    // When the schema declares no `x-identity` fields, schema validation still
    // runs (so malformed payloads are rejected) and the flatten-based fallback
    // below produces the identity fields.
    if let Some(ref selector) = ctx.identity_selector
        && !selector.has_identity_fields()
    {
        selector
            .validate(&raw_payload)
            .map_err(|e| {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Outbound identity schema validation failed"
                );
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(format!(
                    "Identity schema validation failed: {}",
                    e
                )))
            })?;
    }

    if let Some(ref selector) = ctx.identity_selector
        && selector.has_identity_fields()
    {
        let hash = selector
            .compute_identity_hash(&raw_payload, &ctx.surface.name)
            .map_err(|e| {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Outbound identity schema validation failed"
                );
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(format!(
                    "Identity schema validation failed: {}",
                    e
                )))
            })?;

        let identity_fields = selector.extract_identity_fields(&raw_payload);

        let vc_issuer = selector.get_vc_issuer();
        let response = vc_issuer
            .issue_or_get_managed_credential(
                identity_fields.clone(),
                Some(hash.clone()),
                ctx.surface
                    .config_id()
                    .map(String::from),
                ctx.surface.issuer_id.clone(),
            )
            .await
            .map_err(|e| {
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ServiceUnavailable(format!(
                    "DID creation/lookup failed: {}",
                    e
                )))
            })?;

        if response.is_new {
            info!(
                request_id = %ctx.request_id,
                did = %response.did,
                hash = %hash,
                "Created new DID for outbound protected agent (schema-validated)"
            );
        } else {
            debug!(
                request_id = %ctx.request_id,
                did = %response.did,
                hash = %hash,
                "Resolved existing DID for outbound protected agent (schema-validated)"
            );
        }

        ctx.resolved_identity = ProtectedAgentIdentity::Managed {
            did: response.did,
            identity_fields,
        };

        return Ok(());
    }

    // Fallback: no IdentitySelector available — flatten all fields (legacy behavior).
    let mut identity_fields = HashMap::new();
    flatten_json_to_dot_notation(&raw_payload, "", &mut identity_fields);
    if identity_fields.is_empty() {
        return Err(OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(
            "Identity payload flattened to empty fields".to_string(),
        )));
    }

    let hash = crate::identity::compute_canonical_identity_hash(&identity_fields);

    let Some(ref vc_issuer) = state.vc_issuer else {
        return Err(OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ServiceUnavailable(
            "Identity management is enabled but VCIssuer is not configured".to_string(),
        )));
    };

    let response = vc_issuer
        .issue_or_get_managed_credential(
            identity_fields.clone(),
            Some(hash.clone()),
            ctx.surface
                .config_id()
                .map(String::from),
            ctx.surface.issuer_id.clone(),
        )
        .await
        .map_err(|e| {
            OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ServiceUnavailable(format!(
                "DID creation/lookup failed: {}",
                e
            )))
        })?;

    if response.is_new {
        info!(
            request_id = %ctx.request_id,
            did = %response.did,
            hash = %hash,
            "Created new DID for outbound protected agent"
        );
    } else {
        debug!(
            request_id = %ctx.request_id,
            did = %response.did,
            hash = %hash,
            "Resolved existing DID for outbound protected agent"
        );
    }

    ctx.resolved_identity = ProtectedAgentIdentity::Managed {
        did: response.did,
        identity_fields,
    };

    Ok(())
}

/// [3] Rate Limiting — enforces per-channel and per-VC outbound rate limits.
async fn step_rate_limit(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let channel_rl = ctx
        .outbound_shared
        .rate_limit
        .is_some();
    let vc_rl = ctx
        .virtual_channel
        .rate_limit
        .is_some();
    if !channel_rl && !vc_rl {
        return Ok(());
    }

    let Some(pm) = state.policy_manager.as_ref() else {
        // Rate limit configured but no policy manager — log and allow.
        warn!(
            request_id = %ctx.request_id,
            "Outbound rate limit configured but SurfacePolicyManager not available"
        );
        return Ok(());
    };

    let config_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");

    if channel_rl {
        pm.check_rate_limit(config_id)
            .await
            .map_err(|_| {
                debug!(request_id = %ctx.request_id, "Outbound rate limit exceeded (channel)");
                OutboundPipelineError::RateLimitExceeded
            })?;
    }

    if vc_rl {
        let vc_key = format!("vc:{}:{}", config_id, ctx.virtual_channel.alias);
        pm.check_rate_limit(&vc_key)
            .await
            .map_err(|_| {
                debug!(
                    request_id = %ctx.request_id,
                    vc_alias = %ctx.virtual_channel.alias,
                    "Outbound rate limit exceeded (per-VC)"
                );
                OutboundPipelineError::RateLimitExceeded
            })?;
    }

    Ok(())
}

fn transit_upstream_key(ctx: &OutboundPipelineContext) -> crate::mcp::upstream_versions::UpstreamKey {
    crate::mcp::upstream_versions::UpstreamKey {
        surface_id: ctx.surface.surface_id.clone(),
        route: crate::mcp::upstream_versions::UpstreamRoute::TransitPoint(
            ctx.virtual_channel
                .alias
                .clone(),
        ),
        target: ctx
            .virtual_channel
            .target_endpoint
            .clone(),
    }
}

/// [3] Protocol Context Extraction — reads body and determines A2A / MCP / HTTP.
///
/// Consumes the original request to extract body bytes, then detects the
/// protocol and operation from the JSON-RPC method field.
#[cfg(test)]
async fn step_extract_protocol_context(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<Option<Response>, OutboundPipelineError> {
    step_extract_protocol_context_with_versions(state, ctx, crate::mcp::request_validation::LEGACY_ONLY_POLICY).await
}

async fn step_extract_protocol_context_with_versions(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
    versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
) -> Result<Option<Response>, OutboundPipelineError> {
    use axum::body::to_bytes;

    let versions = crate::mcp::request_validation::admission_policy_for_target(
        versions,
        &ctx.virtual_channel
            .target_endpoint,
    );
    let mcp_http =
        if ctx.virtual_channel.protocol == crate::config::agent_surface::TransitProtocol::Mcp {
            Some(crate::mcp::modern_http::EndpointHttpPolicy::with_versions(
            ctx.virtual_channel.mcp_http.as_ref(),
            &state.network_config.get_outbound_external_urls(),
            versions,
        ).map_err(|error| {
            error!(request_id = %ctx.request_id, error = %error, "Invalid MCP Transit Point HTTP configuration");
            OutboundPipelineError::MetadataInjectionFailed
        })?)
        } else {
            None
        };
    if let Some(policy) = &mcp_http {
        policy
            .validate_headers(&ctx.original_headers)
            .map_err(|error| OutboundPipelineError::McpValidation(error.into_validation_error(None)))?;
        if let Some(response) = policy.non_post_response(&ctx.original_method, &ctx.original_headers) {
            return Ok(Some(response));
        }
    }

    // Extract body bytes from the request (consume the request).
    if let Some(req) = ctx.request.take() {
        let body_bytes = to_bytes(
            req.into_body(),
            mcp_http
                .as_ref()
                .map_or(usize::MAX, |policy| policy.body_limit()),
        )
        .await
        .map_err(|error| {
            if let Some(policy) = &mcp_http {
                return OutboundPipelineError::McpValidation(policy.body_read_error(error));
            }
            OutboundPipelineError::BodyReadFailed(error.to_string())
        })?;
        ctx.body_bytes = Some(body_bytes);
    }
    if let Some(policy) = &mcp_http
        && let Some(response) = policy.non_post_body_response(
            &ctx.original_method,
            ctx.body_bytes
                .as_deref()
                .unwrap_or_default(),
        )
    {
        warn!(request_id = %ctx.request_id, method = %ctx.original_method, "Rejecting MCP request with a body at admission");
        return Ok(Some(response));
    }

    if let Some(policy) = &mcp_http
        && ctx.original_method == Method::POST
    {
        let body = ctx
            .body_bytes
            .clone()
            .unwrap_or_default();
        let classification = policy
            .admit_post(
                &ctx.original_headers,
                &body,
                if ctx
                    .original_headers
                    .contains_key("mcp-session-id")
                {
                    crate::mcp::request_validation::LegacySessionEvidence::Unknown
                } else {
                    crate::mcp::request_validation::LegacySessionEvidence::Absent
                },
            )
            .map_err(|error| {
                OutboundPipelineError::McpValidation(crate::mcp::upstream_versions::restrict_unsupported(
                    error,
                    &transit_upstream_key(ctx),
                ))
            })?;
        if let Some(refusal) = crate::mcp::tool_analyzer::single_object_refusal(&body) {
            warn!(request_id = %ctx.request_id, reason = refusal.reason(), "Rejecting MCP request body at admission");
            if matches!(classification, crate::mcp::request_validation::McpRequestClassification::Modern(_)) {
                return Err(OutboundPipelineError::McpValidation(refusal.into_modern_error(&body)));
            }
            return Err(OutboundPipelineError::McpBodyRefused(refusal));
        }
        ctx.surface
            .validate_mcp_metadata_base()
            .map_err(|error| {
                error!(request_id = %ctx.request_id, error = %error, "Invalid MCP metadata configuration");
                OutboundPipelineError::MetadataInjectionFailed
            })?;
        ctx.mcp_metadata_context = crate::mcp::meta::McpMetadataContext::from_classification(
            &classification,
            ctx.surface
                .mcp_legacy_metadata_output,
        );
        let normalized = crate::mcp::meta::normalize_bytes(&body, ctx.mcp_metadata_context).map_err(|error| {
            OutboundPipelineError::McpMetadata {
                error,
                body: body.clone(),
                response: false,
            }
        })?;
        ctx.body_bytes = Some(policy.cap_legacy_initialize(
            normalized,
            &classification,
            &ctx.surface.surface_id,
            Some(&ctx.request_id),
        ));
        crate::protocols::extensions::verify_mcp_metadata_identity(
            &body,
            state.vc_issuer.as_ref(),
            &crate::audit::request_events::RequestFacts {
                surface_id: &ctx.surface.surface_id,
                channel_name: &ctx.surface.name,
                trace_id: Some(&ctx.request_id),
                via_fabric: false,
            },
            None,
        )
        .await
        .map_err(|error| {
            warn!(request_id = %ctx.request_id, error = %error, "Invalid MCP identity presentation");
            OutboundPipelineError::McpIdentityInvalid
        })?;
        if matches!(classification, crate::mcp::request_validation::McpRequestClassification::Modern(_)) {
            crate::mcp::modern_http::strip_protocol_session_headers(&mut ctx.original_headers);
        }
        ctx.mcp_classification = Some(classification);
    }

    let body = match ctx.body_bytes.as_ref() {
        Some(b) if !b.is_empty() => b,
        _ => {
            ctx.protocol = Some(ChannelProtocol::A2a);
            return Ok(None);
        }
    };

    let (protocol, operation) = match ctx
        .mcp_classification
        .as_ref()
    {
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(message)) => {
            (ChannelProtocol::Mcp, Some(message.method.clone()))
        }
        _ => detect_protocol_and_operation(body, &ctx.surface.channel_protocol()),
    };
    ctx.protocol = Some(protocol);
    ctx.operation = operation;

    // An extended agent card inside a JSON-RPC batch response cannot be
    // rewritten, so such a batch is refused on A2A/AP2 transit points.
    if transit_protocol_family(&ctx.virtual_channel.protocol) == Some("a2a")
        && crate::a2a::is_extended_agent_card_batch(body)
    {
        warn!(request_id = %ctx.request_id, "Rejected JSON-RPC batch containing an extended agent card request");
        return Err(OutboundPipelineError::ExtendedAgentCardBatch);
    }

    // Enforce that the request body actually speaks the protocol this transit
    // point is configured for. A2A/AP2 and MCP have distinct JSON-RPC method
    // shapes, so a mismatched payload (e.g. an MCP `tools/call` sent to an
    // A2A transit point) is a caller/configuration error: forwarding it would
    // "succeed" against a permissive upstream while violating the surface
    // contract. `http` transit points opt out (raw pass-through), and bodies
    // whose protocol cannot be determined are never rejected.
    if let (Some(expected), Some(detected)) =
        (transit_protocol_family(&ctx.virtual_channel.protocol), crate::protocols::detect_request_protocol_family(body))
        && expected != detected
        && !matches!(
            ctx.mcp_classification
                .as_ref(),
            Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
        )
    {
        warn!(
            request_id = %ctx.request_id,
            transit_point = %ctx.virtual_channel.alias,
            expected_protocol = %ctx.virtual_channel.protocol,
            detected_protocol = detected,
            "Outbound: request protocol does not match transit point protocol"
        );
        return Err(OutboundPipelineError::ProtocolMismatch {
            expected: ctx
                .virtual_channel
                .protocol
                .to_string(),
            detected: detected.to_string(),
        });
    }

    debug!(
        request_id = %ctx.request_id,
        protocol = ?ctx.protocol,
        operation = ?ctx.operation,
        "Outbound: protocol context extracted"
    );
    Ok(None)
}

/// Map a transit point's configured protocol to the wire "family" the gateway
/// can detect from a JSON-RPC body. A2A and AP2 share the same method shapes
/// (`message/*`, `tasks/*`), so they collapse to one family. `http` is a raw
/// pass-through and returns `None` (no shape enforcement).
fn transit_protocol_family(protocol: &crate::config::agent_surface::TransitProtocol) -> Option<&'static str> {
    use crate::config::agent_surface::TransitProtocol;
    match protocol {
        TransitProtocol::A2a | TransitProtocol::Ap2 => Some("a2a"),
        TransitProtocol::Mcp => Some("mcp"),
        TransitProtocol::Http => None,
    }
}

/// [3.25] Transit Point Header Metadata Mapping — copies configured
/// managed-agent request headers into A2A metadata before extension inspection
/// and managed-agent identity resolution run.
async fn step_map_transit_point_header_metadata(
    _state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let Some(mapping) = ctx
        .virtual_channel
        .header_metadata_mapping
        .as_ref()
    else {
        return Ok(());
    };

    if !matches!(
        ctx.virtual_channel.protocol,
        crate::config::agent_surface::TransitProtocol::A2a | crate::config::agent_surface::TransitProtocol::Ap2
    ) {
        return Ok(());
    }

    if ctx.original_method != Method::POST {
        return Ok(());
    }

    let Some(body_bytes) = ctx
        .body_bytes
        .as_ref()
        .filter(|body| !body.is_empty())
    else {
        return Ok(());
    };

    let diagnostics = mapping.diagnostics(&ctx.original_headers);
    let identity_extraction_reads_mapped_extension = matches!(
        ctx.virtual_channel
            .managed_identity
            .as_ref(),
        Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg))
            if cfg.identity_extension_uri() == mapping.extension_uri.as_str()
    );

    match crate::a2a::inject_header_metadata_extension(body_bytes, mapping, &ctx.original_headers, &ctx.surface.name) {
        Ok((modified_body, mapped_count)) => {
            info!(
                channel = %ctx.surface.name,
                surface_id = %ctx.surface.config_id().unwrap_or("unknown"),
                transit_point = %ctx.virtual_channel.alias,
                transit_point_id = %ctx.virtual_channel.id,
                extension_uri = %diagnostics.extension_uri,
                mapped_count,
                configured_fields = ?diagnostics.configured_fields,
                mapped_fields = ?diagnostics.mapped_fields,
                missing_headers = ?diagnostics.missing_headers,
                strip_mapped_headers = diagnostics.strip_mapped_headers,
                identity_extraction_reads_mapped_extension,
                result = if mapped_count > 0 { "applied" } else { "skipped" },
                "Transit Point Header Metadata Mapping evaluated"
            );
            if mapped_count > 0 {
                ctx.body_bytes = Some(modified_body);
            }
            Ok(())
        }
        Err(e) => {
            warn!(
                channel = %ctx.surface.name,
                surface_id = %ctx.surface.config_id().unwrap_or("unknown"),
                transit_point = %ctx.virtual_channel.alias,
                transit_point_id = %ctx.virtual_channel.id,
                extension_uri = %diagnostics.extension_uri,
                configured_fields = ?diagnostics.configured_fields,
                mapped_fields = ?diagnostics.mapped_fields,
                missing_headers = ?diagnostics.missing_headers,
                strip_mapped_headers = diagnostics.strip_mapped_headers,
                identity_extraction_reads_mapped_extension,
                error = %e,
                "Transit Point Header Metadata Mapping failed"
            );
            Err(OutboundPipelineError::HeaderMetadataMappingFailed(e.to_string()))
        }
    }
}

/// Whether a Transit Point caller's request header goes on to its target, over
/// HTTP or Fabric. The caller's `Authorization`, cookies, and caller-info and DID
/// identity headers ([`crate::proxy::caller_identity::CallerHeaders::NAMES`])
/// never do; its other headers, such as its own API key header for the target, do.
fn should_forward_outbound_request_header(
    name: &str,
    header_metadata_mapping: Option<&crate::config::header_metadata_mapping::HeaderMetadataMappingConfig>,
) -> bool {
    if !crate::a2a::should_forward_request_header(name) {
        return false;
    }

    if name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || crate::proxy::caller_identity::CallerHeaders::is_caller_info_header(name)
    {
        return false;
    }

    if header_metadata_mapping.is_some_and(|mapping| {
        mapping.strip_mapped_headers
            && mapping
                .headers
                .iter()
                .any(|mapped| name.eq_ignore_ascii_case(mapped.header.trim()))
    }) {
        return false;
    }

    true
}

/// The headers a Transit Point sends to its target, over HTTP or Fabric: the
/// managed agent's forwardable headers, then the target authentication header,
/// then the delegated credential headers, each replacing any earlier header of
/// the same name, so the target receives one value of each credential header. An
/// agent header named like the `target_auth` header is never forwarded, whether
/// or not the gateway adds its own value.
async fn transit_request_headers(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<HeaderMap, OutboundPipelineError> {
    let target_auth = transit_target_auth_header(state, ctx).await?;
    let mapping = ctx
        .virtual_channel
        .header_metadata_mapping_if_supported();
    let target_auth_header = ctx
        .virtual_channel
        .target_auth
        .as_ref()
        .and_then(|target_auth| {
            target_auth
                .method
                .header_name()
        });
    let mut headers = HeaderMap::new();
    for (name, value) in &ctx.original_headers {
        if should_forward_outbound_request_header(name.as_str(), mapping)
            && target_auth_header.is_none_or(|credential| {
                !name
                    .as_str()
                    .eq_ignore_ascii_case(credential)
            })
        {
            headers.append(name.clone(), value.clone());
        }
    }
    if let Some((name, value)) = target_auth {
        headers.insert(name, value);
    }
    for (name, value) in &ctx.delegated_credential_headers {
        headers.insert(name.clone(), value.clone());
    }
    Ok(headers)
}

/// The Transit Point's target authentication header, when the request may carry
/// it. A credential that cannot be resolved refuses the request when the
/// Transit Point's `target_auth.fallback` is `reject`, and is left out otherwise.
async fn transit_target_auth_header(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<Option<(axum::http::HeaderName, axum::http::HeaderValue)>, OutboundPipelineError> {
    let Some(target_auth) = ctx
        .virtual_channel
        .target_auth
        .as_ref()
    else {
        return Ok(None);
    };
    match crate::proxy::handler::inject_target_auth_header(
        target_auth,
        &crate::proxy::handler::TargetAuthContext::of_surface(
            &ctx.surface,
            state.secrets_store.as_ref(),
            state
                .credential_provider_store
                .as_ref(),
            state
                .delegation_vault_store
                .as_ref(),
        ),
        &ctx.surface.name,
        crate::proxy::handler::CallerAssertion::for_request(ctx.original_method.as_str(), &ctx.request_path),
    )
    .await
    {
        Ok(Some((name, value))) => Ok(Some((
            axum::http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| OutboundPipelineError::TargetAuthUnavailable)?,
            axum::http::HeaderValue::from_str(&value).map_err(|_| OutboundPipelineError::TargetAuthUnavailable)?,
        ))),
        Ok(None) => Ok(None),
        Err(error) => {
            warn!(request_id = %ctx.request_id, error = %error, "Failed to resolve target auth credentials");
            if matches!(target_auth.fallback, crate::config::TargetAuthFallback::Reject) {
                return Err(OutboundPipelineError::TargetAuthUnavailable);
            }
            Ok(None)
        }
    }
}

/// Remove the target response headers a Transit Point never returns to the
/// managed agent: the target's cookies, and its authentication challenges, which
/// would have the agent authenticate with the target itself rather than through
/// the gateway's credentials.
fn withhold_target_response_headers(headers: &mut HeaderMap) {
    headers.remove(axum::http::header::SET_COOKIE);
    headers.remove(axum::http::header::WWW_AUTHENTICATE);
}

/// Detect the protocol and extract the method/tool from a JSON-RPC body.
fn detect_protocol_and_operation(
    body: &Bytes,
    channel_protocol: &ChannelProtocol,
) -> (ChannelProtocol, Option<String>) {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (channel_protocol.clone(), None);
    };

    // JSON-RPC method field is present for both A2A and MCP.
    let method = json
        .get("method")
        .and_then(|m| m.as_str())
        .map(str::to_string);

    // Discriminate A2A vs MCP by method name:
    // A2A methods look like "message/send", "tasks/get" or v1.0 "SendMessage", etc.
    // MCP methods look like "tools/call", "prompts/get", etc.
    let protocol = match channel_protocol {
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => channel_protocol.clone(),
        ChannelProtocol::Mcp => channel_protocol.clone(),
        _ => {
            // Auto-detect from JSON-RPC method.
            if let Some(ref m) = method {
                if m.starts_with("message/") || m.starts_with("tasks/") || crate::a2a::is_a2a_method(m) {
                    ChannelProtocol::A2a
                } else if m.starts_with("tools/") || m.starts_with("prompts/") || m.starts_with("resources/") {
                    ChannelProtocol::Mcp
                } else {
                    channel_protocol.clone()
                }
            } else {
                channel_protocol.clone()
            }
        }
    };

    (protocol, method)
}

/// [3.5] Outbound Extension Inspection — validates that A2A requests from the
/// managed agent to this transit point carry the extensions declared in
/// `transit_point.extension_inspection.watch_extensions`.
///
/// Mirrors the inbound `payload_extraction` gate in `src/protocols/extensions.rs`:
/// - Only runs for A2A/AP2 protocol (skipped for MCP and raw HTTP).
/// - Only enforces when `extension_inspection.enabled = true` (the default).
/// - Returns 422 if any watched extension URI is absent from
///   `message.extensions` or `params.message.extensions`.
/// - When disabled, logs the absence for observability but passes through.
async fn step_inspect_outbound_extensions(
    _state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let config = &ctx
        .virtual_channel
        .extension_inspection;

    // Nothing to watch — skip all further work immediately.
    if config
        .watch_extensions
        .is_empty()
    {
        return Ok(());
    }

    // Only relevant for A2A/AP2 — skip MCP and HTTP transit points.
    let is_a2a = matches!(
        ctx.virtual_channel.protocol,
        crate::config::agent_surface::TransitProtocol::A2a | crate::config::agent_surface::TransitProtocol::Ap2
    );
    if !is_a2a {
        return Ok(());
    }

    let body = match ctx.body_bytes.as_ref() {
        Some(b) if !b.is_empty() => b,
        _ => {
            // Empty body — no extensions can be present. Reject on the first
            // watched extension when enforcement is on; pass through only when disabled.
            if config.enabled
                && let Some(watched) = config
                    .watch_extensions
                    .first()
            {
                let error_msg = format!(
                    "Outbound extension required: A2A request to transit point '{}' is missing extension `{}`",
                    ctx.virtual_channel.alias, watched
                );
                error!(
                    request_id = %ctx.request_id,
                    transit_point = %ctx.virtual_channel.alias,
                    missing_extension = %watched,
                    "✗ {}", error_msg
                );
                return Err(OutboundPipelineError::ExtensionValidationFailed(error_msg));
            }
            return Ok(());
        }
    };

    let body_json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            // Non-JSON body — extensions cannot be parsed. Same policy as empty body.
            if config.enabled
                && let Some(watched) = config
                    .watch_extensions
                    .first()
            {
                let error_msg = format!(
                    "Outbound extension required: A2A request to transit point '{}' is missing extension `{}`",
                    ctx.virtual_channel.alias, watched
                );
                error!(
                    request_id = %ctx.request_id,
                    transit_point = %ctx.virtual_channel.alias,
                    missing_extension = %watched,
                    "✗ {}", error_msg
                );
                return Err(OutboundPipelineError::ExtensionValidationFailed(error_msg));
            }
            return Ok(());
        }
    };

    // Locate the extensions array: params.message.extensions or message.extensions.
    let extensions: Vec<&str> = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .and_then(|m| m.get("extensions"))
        .and_then(|e| e.as_array())
        .or_else(|| {
            body_json
                .get("message")
                .and_then(|m| m.get("extensions"))
                .and_then(|e| e.as_array())
        })
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.get("uri")
                        .and_then(|u| u.as_str())
                })
                .collect()
        })
        .unwrap_or_default();

    for watched in &config.watch_extensions {
        if !extensions.contains(&watched.as_str()) {
            if config.enabled {
                let error_msg = format!(
                    "Outbound extension required: A2A request to transit point '{}' is missing extension `{}`",
                    ctx.virtual_channel.alias, watched
                );
                error!(
                    request_id = %ctx.request_id,
                    transit_point = %ctx.virtual_channel.alias,
                    missing_extension = %watched,
                    "✗ {}", error_msg
                );
                return Err(OutboundPipelineError::ExtensionValidationFailed(error_msg));
            } else {
                debug!(
                    request_id = %ctx.request_id,
                    transit_point = %ctx.virtual_channel.alias,
                    missing_extension = %watched,
                    "Outbound extension absent (inspection disabled — passing through)"
                );
            }
        } else {
            debug!(
                request_id = %ctx.request_id,
                transit_point = %ctx.virtual_channel.alias,
                extension = %watched,
                "✓ Outbound extension present"
            );
        }
    }

    Ok(())
}

/// [7] Custom Metadata Injection — injects configured metadata into the request body and/or headers.
///
/// For A2A/AP2 protocols: injects using the A2A extension format (injection_target not applicable).
/// For MCP protocols: respects `injection_target` — Headers injects X-Gateway-* HTTP headers,
/// Meta injects into the JSON-RPC `_meta` field, Both does both.
async fn step_inject_custom_metadata(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let Some(ref metadata_config) = ctx
        .outbound_shared
        .custom_metadata
    else {
        return Ok(());
    };

    if !metadata_config.enabled {
        return Ok(());
    }

    let body = ctx
        .body_bytes
        .as_ref()
        .ok_or(OutboundPipelineError::BodyNotAvailable("metadata injection".to_string()))?;

    let channel_name = ctx.surface.name.as_str();

    let surface_protocol = ctx.surface.channel_protocol();
    let protocol = ctx
        .protocol
        .as_ref()
        .unwrap_or(&surface_protocol);

    match protocol {
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => {
            let modified = crate::a2a::inject_custom_metadata_extension(
                body,
                metadata_config,
                channel_name,
                &state.secrets_store,
                crate::protocols::MetadataRuntimeContext {
                    request_id: Some(ctx.request_id.as_str()),
                    surface_id: ctx.surface.config_id(),
                },
            )
            .await
            .map_err(|e| {
                error!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Metadata injection failed"
                );
                OutboundPipelineError::MetadataInjectionFailed
            })?;
            ctx.body_bytes = Some(modified);
        }
        ChannelProtocol::Mcp => {
            let result = crate::mcp::metadata::inject_custom_metadata_with_context(
                body,
                metadata_config,
                channel_name,
                &state.secrets_store,
                crate::protocols::MetadataRuntimeContext {
                    request_id: Some(ctx.request_id.as_str()),
                    surface_id: ctx.surface.config_id(),
                },
                ctx.mcp_metadata_context,
                crate::mcp::meta::McpMetaTarget::TopLevel,
            )
            .await
            .map_err(|e| {
                error!(request_id = %ctx.request_id, error = %e, "MCP metadata injection failed");
                OutboundPipelineError::MetadataInjectionFailed
            })?;

            ctx.body_bytes = Some(result.body);

            for (name, value) in result.extra_headers {
                let header_name = name.to_string();
                ctx.original_headers
                    .insert(name, value);
                debug!(request_id = %ctx.request_id, header = %header_name, "Outbound: injected custom metadata as HTTP header");
            }
        }
        _ => {
            warn!("Protocols not currently supported")
        }
    }

    debug!(request_id = %ctx.request_id, "Outbound: custom metadata injected");
    Ok(())
}

/// Resolve the agent card fetch URL for a transit point.
///
/// For `fabric://` targets the endpoint is a virtual routing address (not
/// HTTP-resolvable). This helper resolves the URL from the transit point's
/// own `listen_address` + `listen_path` instead — hitting the gateway
/// itself on a public path (bypasses auth) and proxying through to the
/// real upstream agent card. For non-fabric targets the endpoint and
/// optional `agent_card_path` are returned as-is.
fn resolve_agent_card_url(tp: &TransitPoint) -> (String, Option<String>) {
    if tp
        .target_endpoint
        .starts_with("fabric://")
    {
        if let (Some(addr), Some(path)) = (tp.listen_address.as_deref(), tp.listen_path.as_deref()) {
            (format!("{}{}", addr.trim_end_matches('/'), path), None)
        } else {
            (tp.target_endpoint.clone(), tp.agent_card_path.clone())
        }
    } else {
        (tp.target_endpoint.clone(), tp.agent_card_path.clone())
    }
}

/// Fetch the agent card from a target endpoint.
///
/// When `agent_card_path` is set (the transit point overrides its
/// destination's card location), the card is fetched from the destination
/// origin + custom path only. Otherwise it tries
/// `/.well-known/agent-card.json` first, then falls back to
/// `/.well-known/agent.json`. Each URL is dialled through a client pinned to
/// the address it resolved to, under the forward step's egress policy, and the
/// card is read within the Transit Point's response bounds.
pub(crate) async fn fetch_agent_card(
    target_url: &str,
    agent_card_path: Option<&str>,
    request_id: &str,
    timeout: std::time::Duration,
    limits: crate::proxy::upstream_body::UpstreamBodyLimits,
) -> Option<serde_json::Value> {
    let urls: Vec<String> = match agent_card_path {
        Some(custom_path) => vec![agent_card_override_url(target_url, custom_path)],
        None => {
            let base = target_url.trim_end_matches('/');
            vec![format!("{}/.well-known/agent-card.json", base), format!("{}/.well-known/agent.json", base)]
        }
    };

    for card_url in &urls {
        let logged_url = loggable::url(card_url);
        let candidate = card_url.clone();
        let client = match tokio::task::spawn_blocking(move || {
            crate::egress::pinned_forward_client(&candidate, timeout)
        })
        .await
        {
            Ok(Ok((client, _target))) => client,
            Ok(Err(e)) => {
                warn!(request_id = %request_id, url = %logged_url, "Agent card URL blocked by egress policy: {}", e);
                continue;
            }
            Err(e) => {
                warn!(request_id = %request_id, url = %logged_url, "Agent card egress validation task failed: {}", e);
                continue;
            }
        };
        match client
            .get(card_url)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                match crate::proxy::upstream_body::read_bounded(resp, limits).await {
                    Ok(body) => {
                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                            return Some(json);
                        }
                    }
                    Err(e) => {
                        debug!(
                            request_id = %request_id,
                            error = %e,
                            url = %logged_url,
                            "Agent card URL response exceeded its bounds, trying next"
                        );
                    }
                }
            }
            Ok(resp) => {
                debug!(
                    request_id = %request_id,
                    status = %resp.status(),
                    url = %logged_url,
                    "Agent card URL returned non-success status, trying next"
                );
            }
            Err(e) => {
                debug!(
                    request_id = %request_id,
                    error = %e.without_url(),
                    url = %logged_url,
                    "Failed to fetch agent card URL, trying next"
                );
            }
        }
    }

    warn!(
        request_id = %request_id,
        "Failed to fetch agent card from any well-known URL"
    );
    None
}

/// [8] Trust Context Collection — fetches target agent card and queries trust registry.
///
/// Runs whenever the routed Transit Point's Trust Check list is non-empty.
/// A card-fetch failure is soft; the marker is threaded to
/// `step_trust_check` which synthesizes `AGENT_CARD_UNAVAILABLE` results
/// per element so OPA remains authoritative on how to react.
///
/// When the trigger doesn't hold the stage is a no-op and
/// `ctx.target_agent_context` stays `None`.
async fn step_collect_trust_context(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let target_trust_check_present = !ctx
        .virtual_channel
        .trust_check_list
        .is_empty();

    if !target_trust_check_present {
        return Ok(());
    }

    let (target_url, agent_card_path) = resolve_agent_card_url(&ctx.virtual_channel);

    // Consult the process-global card cache before touching the network.
    let cached = crate::proxy::agent_card_cache::lookup(&target_url, agent_card_path.as_deref());
    let card_json = match cached {
        Some(payload) => payload,
        None => {
            let fetched = fetch_agent_card(
                &target_url,
                agent_card_path.as_deref(),
                &ctx.request_id,
                resolve_outbound_timeout(ctx),
                agent_card_limits(state, ctx),
            )
            .await;
            crate::proxy::agent_card_cache::insert(&target_url, agent_card_path.as_deref(), fetched.clone());
            fetched
        }
    };

    let card_json = match card_json {
        Some(card) => card,
        None => {
            // Trust-Check-only path: leave target_agent_context unpopulated
            // and let `step_trust_check` synthesize AGENT_CARD_UNAVAILABLE
            // results per configured element.
            ctx.target_agent_card_unavailable = true;
            return Ok(());
        }
    };

    // Build AgentContext from body + optional agent card + trust registry.
    let body_json: Option<serde_json::Value> = ctx
        .body_bytes
        .as_ref()
        .and_then(|b| serde_json::from_slice(b).ok());

    let mut agent_ctx = crate::policies::build_agent_context(
        body_json.as_ref(),
        Some(&card_json),
        state
            .trust_registry_listener_manager
            .as_deref(),
        true,
    )
    .await;

    info!(
        request_id = %ctx.request_id,
        trust_verification = ?agent_ctx.trust_verification,
        "Outbound: target agent context built"
    );

    // Target-leg identity verification: when Trust Check is active on
    // the target leg, the target's identity is established
    // cryptographically instead of trusted from the card's unsigned `did`.
    // Verify the `agent-identity-credential/v1` VP and source
    // `input.agent.did` (the default target-leg entity_id) from the
    // proof-verified `credentialSubject.id`. On any failure clear the DID
    // and mark the context so `step_trust_check` synthesizes per element:
    // IDENTITY_VP_VERIFICATION_FAILED when a VP was present but could not be
    // verified, TARGET_AGENT_IDENTITY_UNAVAILABLE when no VP was present at
    // all — OPA stays authoritative.
    if target_trust_check_present {
        match crate::policies::agent_context::extract_credential_vp_from_card(&card_json) {
            Some(vp) => {
                if let Some(subject_did) = crate::proxy::agent_card_cache::lookup_verified_vp(vp) {
                    agent_ctx.did = Some(subject_did);
                } else if let Some(issuer) = state.vc_issuer.as_deref() {
                    match issuer
                        .verify_agent_presentation_full(vp)
                        .await
                    {
                        Ok(verified) => {
                            let subject_did = verified
                                .subject_id
                                .unwrap_or(verified.holder_did);
                            crate::proxy::agent_card_cache::insert_verified_vp(vp, &subject_did);
                            agent_ctx.did = Some(subject_did);
                        }
                        Err(e) => {
                            warn!(
                                request_id = %ctx.request_id,
                                error = %format!("{e:#}"),
                                "Outbound: target identity VP verification failed"
                            );
                            agent_ctx.did = None;
                            ctx.target_identity_failure =
                                Some(crate::trust_registry_verification::TrustCheckIdentityVerificationFailure {
                                    code: crate::trust_registry_verification::IDENTITY_VP_VERIFICATION_FAILED,
                                    detail: "target agent identity credential could not be verified",
                                });
                        }
                    }
                } else {
                    warn!(
                        request_id = %ctx.request_id,
                        "Outbound: target identity VP present but no VCIssuer configured to verify it"
                    );
                    agent_ctx.did = None;
                    ctx.target_identity_failure =
                        Some(crate::trust_registry_verification::TrustCheckIdentityVerificationFailure {
                            code: crate::trust_registry_verification::IDENTITY_VP_VERIFICATION_FAILED,
                            detail: "target agent identity credential could not be verified",
                        });
                }
            }
            None => {
                warn!(
                    request_id = %ctx.request_id,
                    "Outbound: target card carries no agent-identity-credential; cannot establish target identity for Trust Check"
                );
                agent_ctx.did = None;
                ctx.target_identity_failure =
                    Some(crate::trust_registry_verification::TrustCheckIdentityVerificationFailure {
                        code: crate::trust_registry_verification::TARGET_AGENT_IDENTITY_UNAVAILABLE,
                        detail: "target agent card carries no agent-identity-credential",
                    });
            }
        }
    }

    ctx.target_agent_context = Some(agent_ctx);
    Ok(())
}

/// [8b] Trust Check stage (target leg). Runs after legacy trust context
/// collection and before any OPA evaluation, so all three outbound OPA
/// scopes (gateway, channel, transit point) see the same
/// `input.trust_check_results`. Runs the routed Transit Point's list and
/// no-ops when it is empty or when the listener manager is not available. Per-element failures are encoded inside the result
/// list (`ok = false`, `error = Some(_)`); the stage never returns Err
/// — the OPA author decides how to react via `input.trust_check_results`.
///
/// When [8] set [`OutboundPipelineContext::target_agent_card_unavailable`]
/// (Trust-Check-only widened gate, card fetch failed), this stage
/// synthesizes an `AGENT_CARD_UNAVAILABLE` result per configured element
/// — preserving positional identity (`id`, `trust_registry_id`,
/// `query_type`, `name`) — and records one audit event per element with
/// `error_code = AGENT_CARD_UNAVAILABLE`, `latency_ms = 0`. No TRQP call
/// is made on that path.
///
/// When the target agent card **was** fetched but its
/// `TRUST_REGISTRY_EXTENSION` metadata block is missing a field an
/// individual element's query template references — i.e. the built
/// `target_agent_context` has `provider_did` and/or `trust_registry_did`
/// absent, and the element's `authority_id` / `entity_id` / `action` /
/// `resource` template resolves to `Unresolved` on a path that mentions
/// the missing field — this stage synthesizes a
/// `TRUST_REGISTRY_METADATA_UNAVAILABLE` result **for that element only**.
/// Peer elements with self-contained (literal) queries, templates that
/// don't reference the missing field, or `||` fallback chains whose
/// fallback branch resolves against a populated field proceed through
/// the TRQP executor and produce their real answer. The synthesized
/// `error.message` names the specific missing field(s) so the operator
/// can add it to the target's card. Distinct from
/// `AGENT_CARD_UNAVAILABLE` (card fetch itself failed) and from
/// `TEMPLATE_RESOLUTION_FAILED` (a template-authoring bug or a
/// `NonScalar` / `Malformed` result on any path).
///
/// Both "unavailable" branches omit `authority_id` / `entity_id` from
/// the synthesized `TrustCheckResult` and the audit event — the raw
/// template strings would be noise on those paths.
/// [8b] Trust Check stage (target leg). Runs after legacy trust context
/// collection and before any OPA evaluation, so all three outbound OPA
/// scopes (gateway, channel, transit point) see the same
/// `input.trust_check_results`. Runs the routed Transit Point's list and
/// no-ops when it is empty. Per-element failures are
/// encoded inside the result list (`ok = false`, `error = Some(_)`);
/// the stage never returns Err — the OPA author decides how to react
/// via `input.trust_check_results`.
///
/// When [8] set [`OutboundPipelineContext::target_agent_card_unavailable`]
/// (Trust-Check-only widened gate, card fetch failed), this stage
/// synthesizes an `AGENT_CARD_UNAVAILABLE` result per configured element
/// — preserving positional identity (`id`, `trust_registry_id`,
/// `query_type`, `name`) — and records one audit event per element with
/// `error_code = AGENT_CARD_UNAVAILABLE`, `latency_ms = 0`. No TRQP call
/// is made on that path.
///
/// When the target agent card **was** fetched but its
/// `TRUST_REGISTRY_EXTENSION` metadata block is missing a field an
/// individual element's query template references, the shared per-leg
/// metadata gate inside [`run_trust_check_stage`] synthesizes a
/// `TRUST_REGISTRY_METADATA_UNAVAILABLE` result for that element only.
/// Peer elements with self-contained (literal) queries, templates that
/// don't reference the missing field, or `||` fallback chains whose
/// fallback branch resolves against a populated field proceed through
/// the TRQP executor and produce their real answer. When no trust
/// registry listener manager is available we still surface any
/// gate-synthesized entries so the operator sees the metadata-unavailable
/// signal — runnable elements are silently dropped on that path,
/// matching the historical "no manager, no results" invariant.
///
/// Both "unavailable" branches omit `authority_id` / `entity_id` from
/// the synthesized `TrustCheckResult` and the audit event — the raw
/// template strings would be noise on those paths.
///
/// When the target card **was** fetched but its target agent identity
/// could not be established (set by [`step_collect_trust_context`] when the
/// routed Transit Point has an active `trust_check_list`), this stage synthesizes a
/// result for **every** configured element using the carried code:
/// `IDENTITY_VP_VERIFICATION_FAILED` when an `agent-identity-credential/v1`
/// VP was present but could not be cryptographically verified, or
/// `TARGET_AGENT_IDENTITY_UNAVAILABLE` when the card carried no such VP at
/// all. Either way the target's identity cannot be established, so the whole
/// leg rests on an unverified card. Like the "unavailable" branches it omits
/// `authority_id` / `entity_id`, fires no TRQP call, and returns `Ok(())` so
/// OPA remains authoritative.
async fn step_trust_check(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let target_elements = ctx
        .virtual_channel
        .trust_check_list
        .clone();
    if target_elements.is_empty() {
        return Ok(());
    }
    let surface_id = ctx.surface.surface_id.clone();
    let transit_point = ctx
        .virtual_channel
        .alias
        .clone();
    let origin = crate::observability::trust_check_audit::TrustCheckOrigin {
        surface_id: &surface_id,
        transit_point: Some(&transit_point),
    };

    if ctx.target_agent_card_unavailable {
        let synthesized = crate::trust_registry_verification::synthesize_unavailable_target(
            origin,
            &target_elements,
            crate::trust_registry_verification::AGENT_CARD_UNAVAILABLE,
            "target agent card could not be fetched",
        );
        let mut results = ctx
            .trust_check_results
            .take()
            .unwrap_or_default();
        results.target = synthesized;
        ctx.trust_check_results = Some(results);
        return Ok(());
    }

    // WS-B: the card was fetched but the target's agent identity could not be
    // established (set by `step_collect_trust_context`) — either no
    // `agent-identity-credential/v1` VP was present
    // (TARGET_AGENT_IDENTITY_UNAVAILABLE) or a VP was present but could not be
    // verified (IDENTITY_VP_VERIFICATION_FAILED). Because the target's
    // identity cannot be established, the whole target leg rests on an
    // unverified card — fail every configured element uniformly with the
    // carried code and let OPA decide. Mutually exclusive with
    // `target_agent_card_unavailable` (the card must have been fetched for
    // verification to run).
    if let Some(failure) = ctx
        .target_identity_failure
        .clone()
    {
        let synthesized = crate::trust_registry_verification::synthesize_unavailable_target(
            origin,
            &target_elements,
            failure.code,
            failure.detail,
        );
        let mut results = ctx
            .trust_check_results
            .take()
            .unwrap_or_default();
        results.target = synthesized;
        ctx.trust_check_results = Some(results);
        return Ok(());
    }

    let probe_input = serde_json::to_value(build_outbound_policy_input(ctx)).unwrap_or_default();

    let Some(manager) = state
        .trust_registry_listener_manager
        .clone()
    else {
        // No manager: preserve historical "runnable elements silently
        // dropped" behaviour but still surface any metadata-gate
        // synthesized entries so the operator sees the deny signal.
        let wrapped_input = serde_json::json!({ "input": &probe_input });
        let (synthesized_by_index, _runnable) =
            crate::trust_registry_verification::metadata_gate::synthesize_metadata_gate_failures(
                origin,
                crate::trust_registry_verification::TrustCheckLeg::Target,
                &target_elements,
                &wrapped_input,
            );
        if synthesized_by_index
            .iter()
            .any(Option::is_some)
        {
            let target: Vec<_> = synthesized_by_index
                .into_iter()
                .flatten()
                .collect();
            let mut results = ctx
                .trust_check_results
                .take()
                .unwrap_or_default();
            results.target = target;
            ctx.trust_check_results = Some(results);
        }
        return Ok(());
    };

    let client = crate::trust_registry_verification::TrqpListenerClient::new(manager);
    let target_ctx = crate::trust_registry_verification::run_trust_check_stage(
        origin,
        crate::trust_registry_verification::TrustCheckLeg::Target,
        &target_elements,
        &probe_input,
        &client,
    )
    .await;

    if let Some(target_ctx) = target_ctx {
        let mut results = ctx
            .trust_check_results
            .take()
            .unwrap_or_default();
        results.target = target_ctx.target;
        ctx.trust_check_results = Some(results);
    }
    Ok(())
}

/// The protected agent's DID for outbound policy-audit attribution, or `None`
/// when no managed identity was resolved.
fn outbound_actor_did(ctx: &OutboundPipelineContext) -> Option<&str> {
    match &ctx.resolved_identity {
        ProtectedAgentIdentity::Managed { did, .. } => Some(did.as_str()),
        ProtectedAgentIdentity::Anonymous => None,
    }
}

/// The caller of a Transit Point call, for attributing outbound decisions: the
/// inbound caller a transit token carries, else the caller the Transit Point
/// verified itself, by its resource token or `source_auth`.
fn outbound_caller(ctx: &OutboundPipelineContext) -> Option<crate::delegation_vault::audit::AuditCallerContext> {
    ctx.transit_token_claims
        .as_ref()
        .and_then(crate::delegation_vault::audit::transit_caller_context)
        .or_else(|| {
            ctx.authenticated_identity
                .as_ref()
                .filter(|_| ctx.authenticated_by.is_some())
                .map(crate::delegation_vault::audit::build_caller_context)
        })
}

/// Shared audit context for an outbound OPA evaluation so each site records a
/// `policy_decision` event (JSONL VP Audit Log + signed VP) without repeating
/// the full [`crate::observability::PolicyDecisionEvent`] literal three times.
struct OutboundPolicyAudit<'a> {
    scope: crate::observability::PolicyScope,
    policy_id: &'a str,
    policy_definition_id: Option<&'a str>,
    policy_name: Option<&'a str>,
    surface_id: Option<&'a str>,
    surface_name: Option<&'a str>,
    http_method: &'a str,
    path: &'a str,
    actor_did: Option<&'a str>,
    gateway_did: Option<&'a str>,
    trace_id: &'a str,
    policy_version: Option<u32>,
    policy_content_hash: Option<&'a str>,
    caller: Option<&'a crate::delegation_vault::audit::AuditCallerContext>,
}

impl OutboundPolicyAudit<'_> {
    /// Emit the `policy_decision` audit/VP event for one evaluation outcome.
    fn record(
        &self,
        allow: bool,
        reason: Option<&str>,
    ) {
        self.record_event(allow, reason, None);
    }

    /// Emit the `error` decision for a policy that could not decide.
    fn record_error(
        &self,
        error: crate::observability::PolicyEvaluationError,
    ) {
        self.record_event(false, None, Some(error));
    }

    fn record_event(
        &self,
        allow: bool,
        reason: Option<&str>,
        error: Option<crate::observability::PolicyEvaluationError>,
    ) {
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: self.scope,
            allow,
            reason,
            error,
            policy_id: Some(self.policy_id),
            policy_definition_id: self.policy_definition_id,
            policy_name: self.policy_name,
            surface_id: self.surface_id,
            surface_name: self.surface_name,
            http_method: Some(self.http_method),
            path: Some(self.path),
            actor_did: self.actor_did,
            gateway_did: self.gateway_did,
            trace_id: Some(self.trace_id),
            flow: crate::observability::PolicyFlow::TransitPoint,
            policy_version: self.policy_version,
            policy_content_hash: self.policy_content_hash,
            caller: self.caller,
            ..Default::default()
        });
    }
}

/// [9] Gateway-Level OPA Policy — evaluates the global Rego policy with direction=outbound.
async fn step_gateway_opa_policy(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let Some(ref gw_pm) = state.gateway_policy_manager else {
        info!(request_id = %ctx.request_id, "[OPA] Outbound gateway OPA skipped: no gateway_policy_manager");
        return Ok(());
    };

    // Only evaluate (and audit) when a gateway-level OPA policy is actually
    // configured — mirroring the inbound path. Without this gate the manager's
    // allow-by-default (no compiled policy) would be recorded as a spurious
    // "gateway allow" on every outbound request, unlike inbound which stays
    // silent when no gateway policy exists. Key on the gateway entity id
    // (`get_self_gateway_id`, the same key policies are compiled/looked-up under
    // on inbound) rather than the DID domain, so a configured self-gateway
    // policy is actually found and enforced on egress too. The policy can branch
    // on `input.gateway.direction == "outbound"` to gate egress specifically.
    let Some(gateway_id) = gw_pm.get_self_gateway_id() else {
        info!(request_id = %ctx.request_id, "[OPA] Outbound gateway OPA skipped: no self gateway id");
        return Ok(());
    };
    if !gw_pm.is_enforced(&gateway_id) {
        info!(
            request_id = %ctx.request_id,
            gateway_id = %gateway_id,
            "[OPA] Outbound gateway OPA skipped: no gateway policy configured, allowing"
        );
        return Ok(());
    }
    info!(request_id = %ctx.request_id, "[OPA] Outbound gateway OPA using gateway_id={}", gateway_id);

    let policy_input = build_outbound_policy_input(ctx);
    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
    let (policy_definition_id, policy_name, policy_version, policy_hash) = match gw_pm.policy_evidence(&gateway_id) {
        Some((id, version, hash)) => {
            let name = gw_pm
                .resolve_policy_name(id.as_deref())
                .await;
            (id, name, version, Some(hash))
        }
        None => (None, None, None, None),
    };
    let caller = outbound_caller(ctx);

    let audit = OutboundPolicyAudit {
        scope: crate::observability::PolicyScope::Gateway,
        policy_id: crate::policies::GATEWAY_POLICY_PACKAGE,
        policy_definition_id: policy_definition_id.as_deref(),
        policy_name: policy_name.as_deref(),
        surface_id: ctx.surface.config_id(),
        surface_name: Some(ctx.surface.name.as_str()),
        http_method: ctx.original_method.as_str(),
        path: ctx.request_path.as_str(),
        actor_did: outbound_actor_did(ctx),
        gateway_did: Some(&gateway_id),
        trace_id: &ctx.request_id,
        policy_version,
        policy_content_hash: policy_hash.as_deref(),
        caller: caller.as_ref(),
    };
    match gw_pm.evaluate_policy_decision(&gateway_id, input_value) {
        Ok(decision) if decision.allow => {
            audit.record(true, None);
            debug!(request_id = %ctx.request_id, "Outbound gateway OPA policy allowed");
        }
        Ok(decision) => {
            audit.record(false, decision.reason.as_deref());
            warn!(request_id = %ctx.request_id, "Outbound gateway OPA policy denied");
            return Err(OutboundPipelineError::GatewayPolicyDenied);
        }
        Err(e) => {
            let error = crate::observability::PolicyEvaluationError::EvaluationError;
            audit.record_error(error);
            warn!(request_id = %ctx.request_id, error = %e, "Gateway OPA evaluation error (denying)");
            return Err(OutboundPipelineError::GatewayPolicyError(error));
        }
    }

    Ok(())
}

/// Record the `error` decision for a configured surface or transit-point
/// policy that cannot run, and return the fail-closed pipeline error.
fn record_surface_policy_unavailable(
    ctx: &OutboundPipelineContext,
    policy_definition_id: Option<&str>,
    error: crate::observability::PolicyEvaluationError,
) -> OutboundPipelineError {
    let caller = outbound_caller(ctx);
    OutboundPolicyAudit {
        scope: crate::observability::PolicyScope::Surface,
        policy_id: crate::policies::SURFACE_POLICY_PACKAGE,
        policy_definition_id,
        policy_name: None,
        surface_id: ctx.surface.config_id(),
        surface_name: Some(ctx.surface.name.as_str()),
        http_method: ctx.original_method.as_str(),
        path: ctx.request_path.as_str(),
        actor_did: outbound_actor_did(ctx),
        gateway_did: None,
        trace_id: &ctx.request_id,
        policy_version: None,
        policy_content_hash: None,
        caller: caller.as_ref(),
    }
    .record_error(error);
    OutboundPipelineError::SurfacePolicyError(error)
}

/// [10] Surface-Level OPA Policy — evaluates the per-surface outbound Rego policy.
async fn step_surface_opa_policy(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    // opa_policy_definition_id is the source of truth — no definition means no policy.
    let Some(ref _def_id) = ctx
        .outbound_shared
        .opa_policy_definition_id
    else {
        info!(request_id = %ctx.request_id, "[OPA] Outbound channel OPA skipped: no opa_policy_definition_id on outbound config");
        return Ok(());
    };

    let Some(pm) = &state.policy_manager else {
        warn!(
            request_id = %ctx.request_id,
            "[OPA] Outbound channel OPA skipped: SurfacePolicyManager not available; denying"
        );
        return Err(record_surface_policy_unavailable(
            ctx,
            ctx.outbound_shared
                .opa_policy_definition_id
                .as_deref(),
            crate::observability::PolicyEvaluationError::NoPolicyManager,
        ));
    };

    // Outbound engines are keyed as "outbound:{config_id}" to avoid collisions with inbound.
    let config_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");
    let outbound_key = format!("outbound:{}", config_id);

    // The compiled engine MUST exist when opa_policy_definition_id is set.
    if !pm.has_policy(&outbound_key) {
        warn!(
            request_id = %ctx.request_id,
            config_id = %config_id,
            "Outbound OPA policy is configured but engine not found (compilation may have failed); denying"
        );
        return Err(record_surface_policy_unavailable(
            ctx,
            ctx.outbound_shared
                .opa_policy_definition_id
                .as_deref(),
            crate::observability::PolicyEvaluationError::PolicyNotCompiled,
        ));
    }

    let policy_input = build_outbound_policy_input(ctx);
    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();

    let def_id = ctx
        .outbound_shared
        .opa_policy_definition_id
        .as_deref();
    let (policy_name, policy_version, policy_hash) = pm
        .resolve_policy_decision_evidence(def_id)
        .await;
    let caller = outbound_caller(ctx);
    let audit = OutboundPolicyAudit {
        scope: crate::observability::PolicyScope::Surface,
        policy_id: crate::policies::SURFACE_POLICY_PACKAGE,
        policy_definition_id: def_id,
        policy_name: policy_name.as_deref(),
        surface_id: Some(config_id),
        surface_name: Some(ctx.surface.name.as_str()),
        http_method: ctx.original_method.as_str(),
        path: ctx.request_path.as_str(),
        actor_did: outbound_actor_did(ctx),
        gateway_did: None,
        trace_id: &ctx.request_id,
        policy_version,
        policy_content_hash: policy_hash.as_deref(),
        caller: caller.as_ref(),
    };
    match pm.evaluate_policy_decision(&outbound_key, input_value) {
        Ok(decision) if decision.allow => {
            audit.record(true, None);
            debug!(request_id = %ctx.request_id, "Outbound channel OPA policy allowed");
        }
        Ok(decision) => {
            audit.record(false, decision.reason.as_deref());
            warn!(request_id = %ctx.request_id, "Outbound channel OPA policy denied");
            return Err(OutboundPipelineError::SurfacePolicyDenied);
        }
        Err(e) => {
            let error = crate::observability::PolicyEvaluationError::EvaluationError;
            audit.record_error(error);
            warn!(request_id = %ctx.request_id, error = %e, "Channel OPA evaluation error (denying)");
            return Err(OutboundPipelineError::SurfacePolicyError(error));
        }
    }

    Ok(())
}

/// [9.5] Per-Transit-Point OPA Policy — evaluates an optional per-destination policy.
/// This is distinct from the shared transit policy (step 9) and allows fine-grained
/// control over individual transit destinations.
async fn step_transit_point_opa_policy(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let Some(policy_ref) = ctx
        .virtual_channel
        .policy
        .as_ref()
    else {
        return Ok(());
    };
    // Captured up front (owned) so it survives the later `ctx` mutation without
    // holding an immutable borrow of `ctx.virtual_channel` across it.
    let tp_def_id = policy_ref
        .policy_definition_id
        .clone();

    // When the policy opts in to agent context and it hasn't been
    // populated by an earlier step, fetch the target's agent card and
    // query the trust registry now.
    if policy_ref.require_agent_context
        && ctx
            .target_agent_context
            .is_none()
    {
        let (resolved_url, resolved_card_path) = resolve_agent_card_url(&ctx.virtual_channel);

        let card_json = fetch_agent_card(
            &resolved_url,
            resolved_card_path.as_deref(),
            &ctx.request_id,
            resolve_outbound_timeout(ctx),
            agent_card_limits(state, ctx),
        )
        .await;

        let body_json: Option<serde_json::Value> = ctx
            .body_bytes
            .as_ref()
            .and_then(|b| serde_json::from_slice(b).ok());

        let agent_ctx = crate::policies::build_agent_context(
            body_json.as_ref(),
            card_json.as_ref(),
            state
                .trust_registry_listener_manager
                .as_deref(),
            true,
        )
        .await;

        debug!(
            request_id = %ctx.request_id,
            alias = %ctx.virtual_channel.alias,
            trust_verification = ?agent_ctx.trust_verification,
            "Per-TP policy: agent context built on demand"
        );

        ctx.target_agent_context = Some(agent_ctx);
    }

    let Some(pm) = &state.policy_manager else {
        warn!(
            request_id = %ctx.request_id,
            alias = %ctx.virtual_channel.alias,
            "Per-transit-point OPA policy configured but SurfacePolicyManager not available; denying"
        );
        return Err(record_surface_policy_unavailable(
            ctx,
            Some(tp_def_id.as_str()),
            crate::observability::PolicyEvaluationError::NoPolicyManager,
        ));
    };

    let config_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");
    let tp_key = format!("transit:{}:{}", config_id, ctx.virtual_channel.alias);

    if !pm.has_policy(&tp_key) {
        warn!(
            request_id = %ctx.request_id,
            alias = %ctx.virtual_channel.alias,
            "Per-transit-point OPA policy configured but engine not found; denying"
        );
        return Err(record_surface_policy_unavailable(
            ctx,
            Some(tp_def_id.as_str()),
            crate::observability::PolicyEvaluationError::PolicyNotCompiled,
        ));
    }

    let policy_input = build_outbound_policy_input(ctx);
    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();

    let (policy_name, policy_version, policy_hash) = pm
        .resolve_policy_decision_evidence(Some(tp_def_id.as_str()))
        .await;
    let caller = outbound_caller(ctx);
    let audit = OutboundPolicyAudit {
        scope: crate::observability::PolicyScope::Surface,
        policy_id: crate::policies::SURFACE_POLICY_PACKAGE,
        policy_definition_id: Some(tp_def_id.as_str()),
        policy_name: policy_name.as_deref(),
        surface_id: Some(config_id),
        surface_name: Some(ctx.surface.name.as_str()),
        http_method: ctx.original_method.as_str(),
        path: ctx.request_path.as_str(),
        actor_did: outbound_actor_did(ctx),
        gateway_did: None,
        trace_id: &ctx.request_id,
        policy_version,
        policy_content_hash: policy_hash.as_deref(),
        caller: caller.as_ref(),
    };
    match pm.evaluate_policy_decision(&tp_key, input_value) {
        Ok(decision) if decision.allow => {
            audit.record(true, None);
            debug!(
                request_id = %ctx.request_id,
                alias = %ctx.virtual_channel.alias,
                "Per-transit-point OPA policy allowed"
            );
        }
        Ok(decision) => {
            audit.record(false, decision.reason.as_deref());
            warn!(
                request_id = %ctx.request_id,
                alias = %ctx.virtual_channel.alias,
                "Per-transit-point OPA policy denied"
            );
            return Err(OutboundPipelineError::SurfacePolicyDenied);
        }
        Err(e) => {
            let error = crate::observability::PolicyEvaluationError::EvaluationError;
            audit.record_error(error);
            warn!(
                request_id = %ctx.request_id,
                alias = %ctx.virtual_channel.alias,
                error = %e,
                "Per-transit-point OPA evaluation error (denying)"
            );
            return Err(OutboundPipelineError::SurfacePolicyError(error));
        }
    }

    Ok(())
}

/// The MCP tool gating in force for this request's Transit Point, when it gates
/// anything.
fn compiled_transit_mcp_tool_gating(
    state: &OutboundProxyState,
    ctx: &OutboundPipelineContext,
) -> Option<Arc<crate::policies::mcp_tool_gating::CompiledMcpToolGating>> {
    state
        .policy_manager
        .as_ref()?
        .compiled_mcp_tool_gating_for_transit(
            ctx.surface
                .config_id()
                .unwrap_or("unknown"),
            &ctx.virtual_channel.alias,
        )
        .filter(|gating| !gating.is_empty())
}

/// Whether this request's Transit Point is configured with MCP tool gating that
/// gates anything.
fn transit_mcp_tool_gating_configured(ctx: &OutboundPipelineContext) -> bool {
    ctx.virtual_channel
        .mcp_tool_gating
        .as_ref()
        .is_some_and(|gating| !gating.is_empty())
}

/// [10.6] Per-Transit-Point MCP Tool Gating — `tools/call` leg.
///
/// Blocks an outbound `tools/call` toward this transit point when the TP's
/// MCP tool gating firewall hides the named tool. Parity with the
/// `tools/list` filter applied on the response leg, so a tool the managed
/// agent can't see it also can't invoke. Only runs for MCP transit points
/// that have gating installed; absent gating passes through, while a
/// `tools/call` whose tool name can't be read is blocked. The gate condition is evaluated against the same outbound
/// `PolicyInput` the transit-point OPA gate sees, with `mcp.method` pinned to
/// `tools/call`. A Transit Point whose configuration has gating that is not in
/// force, such as one deleted while the request was in flight, blocks every
/// `tools/call`.
async fn step_transit_mcp_tool_gating(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    if ctx.virtual_channel.protocol != crate::config::agent_surface::TransitProtocol::Mcp {
        return Ok(());
    }
    if ctx.operation.as_deref() != Some("tools/call") {
        return Ok(());
    }
    let config_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");
    let alias = ctx
        .virtual_channel
        .alias
        .as_str();
    let Some(gating) = compiled_transit_mcp_tool_gating(state, ctx) else {
        if transit_mcp_tool_gating_configured(ctx) {
            warn!(
                request_id = %ctx.request_id,
                alias = %alias,
                "Per-transit-point MCP tool gating is configured but not in force; blocking tools/call"
            );
            return Err(OutboundPipelineError::TransitMcpToolGated);
        }
        return Ok(());
    };

    // Fail closed: with gating installed, a `tools/call` whose tool name can't
    // be read (missing or non-string `params.name`, unparseable body) can't be
    // checked against the gates, so it must not reach the upstream ungated.
    let Some(tool_name) = ctx
        .body_bytes
        .as_deref()
        .and_then(crate::mcp::tool_analyzer::called_tool_name)
    else {
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::McpTool,
            allow: false,
            reason: Some("tools/call without a readable tool name under per-transit-point MCP tool gating"),
            policy_id: Some("mcp_tool_gating"),
            surface_id: Some(config_id),
            surface_name: Some(ctx.surface.name.as_str()),
            trace_id: Some(ctx.request_id.as_str()),
            http_method: Some(ctx.original_method.as_str()),
            path: Some(ctx.request_path.as_str()),
            caller: outbound_caller(ctx).as_ref(),
            ..Default::default()
        });
        warn!(
            request_id = %ctx.request_id,
            alias = %alias,
            "Per-transit-point MCP tool gating blocked tools/call without a readable tool name"
        );
        return Err(OutboundPipelineError::TransitMcpToolGated);
    };

    // Only build + serialize the outbound context when a gate has an OPA
    // condition; pure-regex gating decides on the tool name alone.
    let input_value = if gating.has_policy_conditions() {
        let mut policy_input = build_outbound_policy_input(ctx);
        policy_input.mcp = ctx
            .mcp_classification
            .as_ref()
            .and_then(crate::mcp::modern_mcp_context)
            .or_else(|| {
                Some(crate::surface_context::McpContext {
                    method: "tools/call".to_string(),
                    tool_name: Some(tool_name.clone()),
                    resource_uri: None,
                    prompt_name: None,
                    params: None,
                    ..Default::default()
                })
            });
        serde_json::to_value(&policy_input).unwrap_or_default()
    } else {
        serde_json::Value::Null
    };

    let allowed = gating.is_tool_call_allowed(&tool_name, &input_value);

    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
        scope: crate::observability::PolicyScope::McpTool,
        allow: allowed,
        reason: if allowed {
            None
        } else {
            Some("blocked by per-transit-point MCP tool gating")
        },
        policy_id: Some("mcp_tool_gating"),
        surface_id: Some(config_id),
        surface_name: Some(ctx.surface.name.as_str()),
        trace_id: Some(ctx.request_id.as_str()),
        http_method: Some(ctx.original_method.as_str()),
        path: Some(ctx.request_path.as_str()),
        caller: outbound_caller(ctx).as_ref(),
        ..Default::default()
    });

    if !allowed {
        warn!(
            request_id = %ctx.request_id,
            alias = %alias,
            tool = %tool_name,
            "Per-transit-point MCP tool gating blocked tools/call"
        );
        return Err(OutboundPipelineError::TransitMcpToolGated);
    }

    Ok(())
}

/// The Transit Point response policy's definition id, if one is configured.
fn transit_response_policy_definition_id(ctx: &OutboundPipelineContext) -> Option<String> {
    ctx.virtual_channel
        .response_policy
        .as_ref()
        .map(|p| p.policy_definition_id.clone())
}

/// The Transit Point response policy's definition evidence for its audit
/// records. Resolved by the async callers, because the response pipeline is
/// synchronous and the modern path runs it under a lock. Takes the id rather
/// than the context, which is not `Sync` and so cannot be held across the await.
async fn transit_response_policy_attestation(
    state: &OutboundProxyState,
    def_id: Option<String>,
) -> crate::policies::PolicyAttestation {
    match (state.policy_manager.as_ref(), def_id) {
        (Some(pm), Some(def_id)) => {
            pm.resolve_policy_attestation(Some(def_id.as_str()))
                .await
        }
        _ => crate::policies::PolicyAttestation::default(),
    }
}

/// Per-Transit-Point Response OPA Policy.
///
/// Evaluated against the upstream's response after `step_forward_request`
/// returns. Engine key: `response:transit:{config_id}:{alias}`. Allows by
/// default when no policy is configured. Fail-closed (denies) on any
/// engine/serialization error.
fn step_transit_point_response_policy(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
    status: StatusCode,
    body_bytes: &Bytes,
    headers: &reqwest::header::HeaderMap,
    response_policy: &crate::policies::PolicyAttestation,
) -> Result<(), OutboundPipelineError> {
    let Some(def_id) = ctx
        .virtual_channel
        .response_policy
        .as_ref()
        .map(|p| &p.policy_definition_id)
    else {
        return Ok(());
    };

    let Some(pm) = state.policy_manager.as_ref() else {
        warn!(
            request_id = %ctx.request_id,
            alias = %ctx.virtual_channel.alias,
            "Per-transit-point response OPA policy configured but SurfacePolicyManager not available; denying"
        );
        return Err(OutboundPipelineError::TransitPointResponsePolicyDenied);
    };

    let config_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");
    let policy_key = format!("response:transit:{}:{}", config_id, ctx.virtual_channel.alias);

    if !pm.has_policy(&policy_key) {
        warn!(
            request_id = %ctx.request_id,
            alias = %ctx.virtual_channel.alias,
            "Per-transit-point response OPA policy configured but engine not found; denying"
        );
        return Err(OutboundPipelineError::TransitPointResponsePolicyDenied);
    }

    use crate::proxy::response_policy::{
        CallerContext as RpCallerContext, ResponseContext, ResponsePolicyInput, SurfaceContext,
        evaluate_response_policy,
    };

    let body_json: Option<serde_json::Value> = if body_bytes.is_empty() {
        None
    } else {
        serde_json::from_slice(body_bytes).ok()
    };
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let input = ResponsePolicyInput::new(
        ResponseContext {
            status_code: status.as_u16(),
            body: body_json,
            content_type,
            is_error: status.is_client_error() || status.is_server_error(),
            method: None,
        },
        RpCallerContext {
            did: match &ctx.resolved_identity {
                ProtectedAgentIdentity::Managed { did, .. } => Some(did.clone()),
                ProtectedAgentIdentity::Anonymous => None,
            },
            identity_source: None,
            dna_uai: None,
        },
        SurfaceContext {
            id: config_id.to_string(),
            name: ctx.surface.name.clone(),
            protocol: format!("{:?}", ctx.surface.channel_protocol()).to_lowercase(),
        },
    )
    .for_transit_point(
        outbound_transit_context(ctx),
        ctx.authenticated_identity
            .as_ref()
            .map(crate::surface_context::SourceAuthContext::from),
    );

    let decision = evaluate_response_policy(pm.as_ref(), &policy_key, input);
    let caller = outbound_caller(ctx);
    let audit = OutboundPolicyAudit {
        scope: crate::observability::PolicyScope::Response,
        policy_id: crate::policies::SURFACE_POLICY_PACKAGE,
        policy_definition_id: Some(def_id.as_str()),
        policy_name: response_policy
            .name
            .as_deref(),
        surface_id: Some(config_id),
        surface_name: Some(ctx.surface.name.as_str()),
        http_method: ctx.original_method.as_str(),
        path: ctx.request_path.as_str(),
        actor_did: outbound_actor_did(ctx),
        gateway_did: None,
        trace_id: &ctx.request_id,
        policy_version: response_policy.version,
        policy_content_hash: response_policy
            .content_hash
            .as_deref(),
        caller: caller.as_ref(),
    };
    if !decision.allow {
        match decision.error {
            Some(error) => audit.record_error(error),
            None => audit.record(false, decision.reason.as_deref()),
        }
        warn!(
            request_id = %ctx.request_id,
            alias = %ctx.virtual_channel.alias,
            reason = ?decision.reason,
            "Per-transit-point response OPA policy denied — blocking response"
        );
        return Err(OutboundPipelineError::TransitPointResponsePolicyDenied);
    }
    audit.record(true, None);
    debug!(
        request_id = %ctx.request_id,
        alias = %ctx.virtual_channel.alias,
        "Per-transit-point response OPA policy allowed"
    );
    Ok(())
}

/// `input.transit` for a Transit Point call. `caller` is the end user the
/// transit token names, required or optional, anonymous without one; its
/// `fields` are only those this Transit Point allowlists, as the token carries
/// every Transit Point's.
/// `client` is the principal the Transit Point authenticated itself, so a
/// policy can tell the two apart.
fn outbound_transit_context(ctx: &OutboundPipelineContext) -> crate::surface_context::TransitContext {
    use crate::surface_context::{TransitCallerContext, TransitClientContext, TransitContext};
    let caller = match ctx
        .transit_token_claims
        .as_ref()
        .or(ctx
            .optional_transit_token_claims
            .as_ref())
        .map(TransitCallerContext::from_transit_token)
    {
        Some(mut caller) => {
            let allowlist = transit_token_caller_fields(&ctx.virtual_channel);
            caller
                .fields
                .retain(|name, _| allowlist.contains(name));
            caller
        }
        None => TransitCallerContext::anonymous(),
    };
    let client = ctx
        .authenticated_identity
        .as_ref()
        .zip(ctx.authenticated_by)
        .map(|(identity, verification)| {
            TransitClientContext::new(
                identity,
                verification,
                ctx.surface
                    .tenant_id
                    .as_deref(),
            )
        });
    TransitContext { caller, client }
}

/// The caller claims a Transit Point copies from the transit token: its enabled
/// workload binding's `caller_context_fields`, when that binding reads the token.
fn transit_token_caller_fields(point: &TransitPoint) -> &[String] {
    point
        .workload_binding
        .as_ref()
        .filter(|binding| {
            binding.enabled && binding.caller_source == crate::config::types::CallerContextSource::TransitToken
        })
        .map(|binding| {
            binding
                .caller_context_fields
                .as_slice()
        })
        .unwrap_or_default()
}

/// Build the `PolicyInput` for outbound OPA evaluations.
fn build_outbound_policy_input(ctx: &OutboundPipelineContext) -> crate::surface_context::PolicyInput {
    let modern_mcp_context = ctx
        .mcp_classification
        .as_ref()
        .and_then(crate::mcp::modern_mcp_context);
    // Parse the A2A/AP2 message payload so transit-point (outbound) policies can
    // inspect the agent content (`input.a2a`), mirroring the inbound surface OPA
    // seam in `proxy::handler`. Without this `input.a2a` was absent on the
    // MA→TP (outbound) leg, so a policy reading e.g. `input.a2a.method` always
    // saw an empty object — even though the identical policy worked on the
    // AP→MA (inbound) leg.
    let a2a = if modern_mcp_context.is_none()
        && matches!(ctx.surface.channel_protocol(), ChannelProtocol::A2a | ChannelProtocol::Ap2)
    {
        ctx.body_bytes
            .as_ref()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            .map(|body| {
                let method = body
                    .get("method")
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string());
                let message = body
                    .get("params")
                    .and_then(|p| p.get("message"))
                    .or_else(|| body.get("message"))
                    .cloned();
                crate::surface_context::A2aContext::new(method, message)
            })
    } else {
        None
    };

    // Same for MCP transit points: expose the tool request as `input.mcp`
    // (method + tool_name + params) so outbound policies can gate on the MCP
    // payload, matching the inbound MCP seam. Parallel to the A2A gap above.
    let mcp = modern_mcp_context.or_else(|| {
        if ctx.surface.channel_protocol() == ChannelProtocol::Mcp {
            ctx.body_bytes
                .as_ref()
                .and_then(|body| crate::mcp::build_mcp_context(body))
        } else {
            None
        }
    });

    crate::surface_context::PolicyInput {
        http: Some(crate::surface_context::HttpContext {
            method: ctx
                .original_method
                .to_string(),
            path: ctx.request_path.clone(),
            headers: crate::surface_context::filter_sensitive_headers(&ctx.original_headers),
        }),
        gateway: Some(crate::surface_context::GatewayContext {
            direction: "outbound".to_string(),
            source_id: match &ctx.resolved_identity {
                ProtectedAgentIdentity::Managed { did, .. } => Some(did.clone()),
                ProtectedAgentIdentity::Anonymous => None,
            },
            target_id: Some(
                ctx.virtual_channel
                    .target_endpoint
                    .clone(),
            ),
        }),
        channel: Some(crate::surface_context::SurfaceRoutingContext {
            config_id: Some(ctx.surface.surface_id.clone()),
            name: Some(ctx.surface.name.clone()),
            variant_alias: ctx
                .active_variant_alias
                .clone(),
        }),
        agent: ctx
            .target_agent_context
            .clone(),
        a2a,
        mcp,
        source_auth: ctx
            .authenticated_identity
            .as_ref()
            .map(crate::surface_context::SourceAuthContext::from),
        trust_check_results: ctx
            .trust_check_results
            .clone(),
        transit: Some(outbound_transit_context(ctx)),
        ..Default::default()
    }
}

/// The caller context a Transit Point's Workload Binding binds into the signed
/// presentation. A JWT caller is read from the claims the Transit Point's own
/// authentication verified, never from an `Authorization` header it did not
/// verify; the raw header is read only when the Transit Point authenticated no
/// caller itself.
fn capture_workload_binding_caller(
    ctx: &OutboundPipelineContext,
    cfg: &crate::config::types::WorkloadBindingConfig,
) -> Option<crate::proxy::workload_binding::CapturedCallerContext> {
    match cfg.caller_source {
        crate::config::types::CallerContextSource::TransitToken => ctx
            .transit_token_claims
            .as_ref()
            .and_then(|claims| {
                crate::proxy::workload_binding::capture_from_transit_token(claims, &cfg.caller_context_fields).ok()
            }),
        crate::config::types::CallerContextSource::AuthorizationBearerJwt => match ctx
            .authenticated_identity
            .as_ref()
        {
            Some(crate::source_auth::AuthenticatedIdentity::JwtBearer { claims, .. }) => {
                crate::proxy::workload_binding::capture_from_verified_claims(claims, &cfg.caller_context_fields).ok()
            }
            Some(_) => None,
            None => ctx
                .original_headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|auth| {
                    crate::proxy::workload_binding::capture_from_bearer_jwt(auth, &cfg.caller_context_fields).ok()
                }),
        },
        // Transit Point calls are made by the managed agent, not the original
        // DID-authenticated caller — the raw DID is not available on this hop.
        // Use `TransitToken` here so the AP-hop's `SHA256(did)` user_hash flows
        // through the transit token, then set `caller_source: did` on the
        // target-leg workload binding where the AP-inbound authenticated
        // identity is still in scope.
        crate::config::types::CallerContextSource::Did => None,
    }
}

/// [5] Trusted Identity Injection — removes the raw `agent-identity/v1` extension
/// from the request body and inserts a signed `agent-identity-credential/v1`
/// containing a VP (Verifiable Presentation) JWT issued by the gateway's
/// VCIssuer.  The original identity fields are consumed — only the signed
/// credential remains in the outgoing payload.
///
/// Reads from `ctx.resolved_identity` (set by `step_resolve_agent_identity`).
/// When identity is `Anonymous`, the step is a no-op.
async fn step_inject_trusted_identity(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let (did, identity_fields) = match &ctx.resolved_identity {
        ProtectedAgentIdentity::Managed { did, identity_fields } => (did, identity_fields),
        ProtectedAgentIdentity::Anonymous => return Ok(()),
    };

    // Plain-HTTP targets (no extension carrier) → error if we have an identity to inject.
    let surface_protocol = ctx.surface.channel_protocol();
    let protocol = ctx
        .protocol
        .as_ref()
        .unwrap_or(&surface_protocol);
    match protocol {
        ChannelProtocol::A2a | ChannelProtocol::Ap2 | ChannelProtocol::Mcp => {}
        _ => {
            error!(
                request_id = %ctx.request_id,
                protocol = ?protocol,
                "Identity injection not implemented for protocol {:?}",
                protocol
            );
            return Err(OutboundPipelineError::IdentityInjectionFailed(format!(
                "Identity injection not supported for protocol {:?}",
                protocol
            )));
        }
    }

    let Some(ref vc_issuer) = state.vc_issuer else {
        error!(
            request_id = %ctx.request_id,
            "Resolved identity present but VCIssuer not configured"
        );
        return Err(OutboundPipelineError::IdentityInjectionFailed("VCIssuer is not configured".to_string()));
    };

    let body = ctx
        .body_bytes
        .as_ref()
        .ok_or(OutboundPipelineError::BodyNotAvailable("identity injection".to_string()))?;

    let channel_name = ctx.surface.name.as_str();

    // Transit Point Workload Binding: when the Transit Point configures an
    // enabled workload binding, bind the managed agent identity to the
    // configured caller context — captured from the transit token or the
    // Transit Point call's bearer JWT — in the signed VP. When absent, the VP
    // keeps the flat `identityFields` credential-subject shape.
    let workload_binding = {
        let wb_config = ctx
            .virtual_channel
            .workload_binding
            .as_ref();
        let captured = wb_config
            .filter(|c| c.enabled)
            .and_then(|cfg| capture_workload_binding_caller(ctx, cfg));
        let mut wb = crate::proxy::workload_binding::maybe_build_workload_binding_subject(
            wb_config,
            crate::proxy::workload_binding::WorkloadBindingInputs {
                agent_identity_fields: Some(identity_fields),
                caller: captured.as_ref(),
                trace_id: Some(&ctx.request_id),
                target: Some(
                    ctx.virtual_channel
                        .target_endpoint
                        .as_str(),
                ),
                ..Default::default()
            },
        );
        // Additively bind the original caller identity (carried in the transit
        // token's `sub`) as `userIdentity.id` + `delegated`, matching the
        // fabric response-leg shape, alongside the redesign's nested `caller`
        // context object. Only applies when a workloadBinding is already being
        // produced (WB configured on this Transit Point).
        if let Some(obj) = wb
            .as_mut()
            .and_then(|v| v.as_object_mut())
            && let Some(caller_did) = ctx
                .transit_token_claims
                .as_ref()
                .and_then(|c| c.sub.as_deref())
                .filter(|d| !d.is_empty())
        {
            obj.entry("userIdentity")
                .or_insert_with(|| serde_json::json!({ "id": caller_did }));
            obj.insert("delegated".to_string(), serde_json::Value::Bool(true));
        }
        wb
    };

    let surface_protocol = ctx.surface.channel_protocol();
    let protocol = ctx
        .protocol
        .as_ref()
        .unwrap_or(&surface_protocol);

    let injected_vp_jwt: Option<String> = match protocol {
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => {
            let (signed, vp_jwt) = crate::a2a::extensions::inject_identity_credential_extension(
                body,
                did,
                identity_fields,
                workload_binding,
                vc_issuer,
                channel_name,
            )
            .await
            .map_err(|e| {
                error!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Failed to inject A2A identity credential"
                );
                OutboundPipelineError::IdentityInjectionFailed(e.to_string())
            })?;
            ctx.body_bytes = Some(signed);
            debug!(request_id = %ctx.request_id, did = %did, "Outbound A2A identity credential injected");
            Some(vp_jwt)
        }
        ChannelProtocol::Mcp => {
            let (protected_meta_field, protected_strip_raw) = ctx
                .surface
                .protected_identity()
                .and_then(|c| {
                    if let crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) = c {
                        Some((cfg.meta_field.clone(), cfg.strip_raw_meta))
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| ("serverIdentity".to_string(), false));
            let (signed, vp_jwt) = crate::mcp::inject_vp_into_mcp_request(
                body,
                did,
                identity_fields,
                workload_binding,
                vc_issuer,
                channel_name,
                Vec::new(),
                &protected_meta_field,
                protected_strip_raw,
                ctx.mcp_metadata_context,
            )
            .await
            .map_err(|e| {
                error!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Failed to inject MCP identity credential"
                );
                OutboundPipelineError::IdentityInjectionFailed(e.to_string())
            })?;
            ctx.body_bytes = Some(signed);
            debug!(request_id = %ctx.request_id, did = %did, "Outbound MCP identity credential injected");
            vp_jwt
        }
        _ => unreachable!("unsupported protocols filtered above"),
    };

    // Audit the transit-point VP injection so the MA→TP identity binding is
    // recorded on this (producing) gateway, mirroring the direct/`fabric://`
    // injection sites in `proxy::handler`. The receiving gateway separately
    // audits the same VP on extraction.
    if let Some(vp_jwt) = injected_vp_jwt {
        crate::delegation_vault::audit::emit("vp_injected", || {
            crate::delegation_vault::audit::vp_injected_event(crate::delegation_vault::audit::VpInjection {
                agent_did: Some(did.as_str()),
                user_hash: None,
                surface_id: Some(
                    ctx.surface
                        .surface_id
                        .as_str(),
                ),
                channel_name,
                target_endpoint: &ctx
                    .virtual_channel
                    .target_endpoint,
                protocol: &format!("{:?}", protocol).to_lowercase(),
                mcp_tool_name: None,
                vp_jwt: &vp_jwt,
                trace_id: Some(&ctx.request_id),
                detail: "transit_point".to_string(),
                caller: outbound_caller(ctx),
                via_fabric: true,
            })
        });
    }

    Ok(())
}

async fn step_prepare_modern_credentials(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<Option<Response>, OutboundPipelineError> {
    use crate::proxy::credential_delegation::modern::{ModernDelegationError, ModernDelegationResult, prepare_transit};
    let Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) =
        ctx.mcp_classification.clone()
    else {
        return Ok(None);
    };
    if ctx
        .surface
        .outbound_credentials
        .is_empty()
    {
        return Ok(None);
    }
    if ctx
        .virtual_channel
        .withholds_delegated_credentials()
    {
        log_fabric_delegation_withheld(ctx);
        return Ok(None);
    }
    let Some(runtime) = state
        .mcp_continuations
        .as_deref()
    else {
        return Ok(Some(
            ModernDelegationError::from(crate::mcp::continuations::ContinuationError::Unavailable).response(&request),
        ));
    };
    match prepare_transit(state, runtime, ctx, &request).await {
        Ok(ModernDelegationResult::InputRequired(response)) => {
            Ok(Some(([("cache-control", "no-store")], axum::Json(response)).into_response()))
        }
        Ok(ModernDelegationResult::Prepared(prepared)) => {
            let body = ctx
                .body_bytes
                .as_ref()
                .ok_or(OutboundPipelineError::MetadataInjectionFailed)?;
            let restored = prepared
                .rewrite_body(body)
                .and_then(|body| prepared.inject_body_credentials(&body))
                .map_err(|_| OutboundPipelineError::MetadataInjectionFailed)?;
            prepared
                .credential_headers()
                .map_err(|_| refuse_delegation(ctx, DelegationRefusal::Unavailable))?;
            ctx.body_bytes = Some(restored);
            ctx.mcp_classification = Some(crate::mcp::request_validation::McpRequestClassification::Modern(Box::new(
                prepared.request.clone(),
            )));
            ctx.modern_delegation = Some(prepared);
            Ok(None)
        }
        Err(error) => Ok(Some(error.response(&request))),
    }
}

fn log_fabric_delegation_withheld(ctx: &OutboundPipelineContext) {
    debug!(
        target: "credential_delegation",
        request_id = %ctx.request_id,
        surface_id = %ctx.surface.surface_id,
        surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
        route = %ctx.virtual_channel.alias,
        reason = "fabric_delegated_credentials=false",
        "Delegated credentials withheld from Fabric peer"
    );
}

/// The JSON-RPC id a refusal of this request answers, when the Transit Point
/// speaks MCP.
fn mcp_refusal_id(ctx: &OutboundPipelineContext) -> Option<serde_json::Value> {
    (ctx.virtual_channel.protocol == crate::config::agent_surface::TransitProtocol::Mcp).then(|| {
        match ctx
            .mcp_classification
            .as_ref()
        {
            Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) => request.id.clone(),
            _ => ctx
                .body_bytes
                .as_deref()
                .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
                .and_then(|body| body.get("id").cloned()),
        }
        .unwrap_or(serde_json::Value::Null)
    })
}

/// The caller half of the vault key for a Transit Point's delegated
/// credentials: the transit token's `user_identity_hash`, else the identity
/// hash of a caller the Transit Point's `source_auth` verified, which is the
/// value the Access Point puts in a transit token for a caller it identified
/// the same way. A credential that names no subject identifies no caller.
fn delegation_caller_hash(ctx: &OutboundPipelineContext) -> Option<String> {
    if let Some(claims) = ctx
        .transit_token_claims
        .as_ref()
    {
        return claims
            .user_identity_hash
            .clone();
    }
    ctx.authenticated_identity
        .as_ref()
        .filter(|_| ctx.authenticated_by == Some(crate::surface_context::TransitClientVerification::SourceAuth))
        .and_then(|identity| {
            identity.principal_hash(
                ctx.surface
                    .tenant_id
                    .as_deref(),
            )
        })
}

/// Refuse a request whose delegated credentials cannot be resolved.
fn refuse_delegation(
    ctx: &OutboundPipelineContext,
    refusal: DelegationRefusal,
) -> OutboundPipelineError {
    OutboundPipelineError::DelegationRefused {
        refusal,
        mcp_request_id: mcp_refusal_id(ctx),
    }
}

/// [11] Credential Injection — resolve delegated OAuth tokens from the credential
/// vault and inject them into the outbound request, or return a consent_required
/// signal if the user has not yet authorized.
///
/// The caller is the one [`delegation_caller_hash`] names. The channel's `outbound_credentials`
/// bindings determine which credential providers to look up. A binding that applies
/// but cannot be resolved refuses the request; it is never forwarded without the
/// credential. A public discovery read carries no caller, so, as with target
/// authentication, no caller's credential is released for it.
async fn step_inject_credentials(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let surface_variant = crate::observability::policy_audit::current_request_variant();
    if !crate::proxy::handler::CallerAssertion::for_request(ctx.original_method.as_str(), &ctx.request_path)
        .permits_target_credential()
    {
        return Ok(());
    }
    let mut outbound_creds = ctx
        .surface
        .transit_point_outbound_credentials(&ctx.virtual_channel);
    if !outbound_creds.is_empty()
        && ctx
            .virtual_channel
            .withholds_delegated_credentials()
    {
        log_fabric_delegation_withheld(ctx);
        return Ok(());
    }
    if let Some(prepared) = ctx.modern_delegation.as_ref() {
        outbound_creds.retain(|binding| {
            !prepared
                .handled_provider_ids
                .contains(&binding.credential_provider_id)
        });
    }
    // Tool-scoped bindings never apply on a Transit Point. Bindings carry no
    // destination, and a partner upstream names its own tools, so matching on
    // the tool name would hand it a credential scoped to the Target's tools.
    outbound_creds.retain(|binding| matches!(binding.required_for, crate::config::types::CredentialRequirement::All));
    if outbound_creds.is_empty() {
        return Ok(());
    }

    // All three stores must be available
    let (vault_store, provider_store, secrets_store, base_url) = match (
        &state.delegation_vault_store,
        &state.credential_provider_store,
        &state.secrets_store,
        &state.gateway_base_url,
    ) {
        (Some(v), Some(p), Some(s), Some(b)) => (v, p, s, b),
        _ => {
            warn!(
                target: "credential_delegation",
                request_id = %ctx.request_id,
                surface_variant = surface_variant.as_deref(),
                "Credential delegation configured but stores not available - refusing the request"
            );
            return Err(refuse_delegation(ctx, DelegationRefusal::Unavailable));
        }
    };

    let Some(user_hash) = delegation_caller_hash(ctx) else {
        warn!(
            target: "credential_delegation",
            request_id = %ctx.request_id,
            surface_variant = surface_variant.as_deref(),
            "Neither the transit token nor the Transit Point's source_auth identifies the caller - refusing the request"
        );
        return Err(refuse_delegation(ctx, DelegationRefusal::CallerIdentityMissing));
    };

    // The agent half of the vault key: the Transit Point's managed identity, else the
    // caller DID the transit token carries. Without one no grant is looked up, so a
    // grant is never shared between agents or surfaces under a placeholder key.
    let Some(agent_did) = match &ctx.resolved_identity {
        ProtectedAgentIdentity::Managed { did, .. } => Some(did.clone()),
        ProtectedAgentIdentity::Anonymous => None,
    }
    .or_else(|| {
        ctx.transit_token_claims
            .as_ref()
            .and_then(|c| c.sub.clone())
    }) else {
        warn!(
            target: "credential_delegation",
            request_id = %ctx.request_id,
            surface_variant = surface_variant.as_deref(),
            "No managed agent identity for delegated credentials - refusing the request"
        );
        return Err(refuse_delegation(ctx, DelegationRefusal::AgentIdentityMissing));
    };
    let agent_did = agent_did.as_str();

    let channel_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");

    let mcp_tool = ctx
        .body_bytes
        .as_deref()
        .and_then(crate::mcp::tool_analyzer::called_tool_name);

    let audit_ctx = crate::proxy::credential_delegation::DelegationAuditContext {
        caller: outbound_caller(ctx),
        channel_name: Some(ctx.surface.name.clone()),
        target_endpoint: Some(
            ctx.virtual_channel
                .target_endpoint
                .clone(),
        ),
        protocol: ctx
            .protocol
            .as_ref()
            .map(|p| format!("{:?}", p).to_lowercase()),
        mcp_tool_name: mcp_tool.clone(),
        agent_identity_did: match &ctx.resolved_identity {
            ProtectedAgentIdentity::Managed { did, .. } => Some(did.clone()),
            ProtectedAgentIdentity::Anonymous => None,
        },
        vp_jwt: None,
        mcp_session_id: None,
    };

    let results = crate::proxy::credential_delegation::resolve_delegation_credentials(
        &outbound_creds,
        &user_hash,
        agent_did,
        channel_id,
        mcp_tool.as_deref(),
        vault_store,
        provider_store,
        secrets_store,
        base_url,
        false,
        Some(&audit_ctx),
        // Transit resolves callers to an identity hash only, which carries no
        // issuer, so it can never unlock a modern consent record.
        None,
    )
    .await;

    if results
        .iter()
        .any(|resolution| {
            matches!(&resolution.result, crate::proxy::credential_delegation::DelegationLookupResult::Unavailable)
        })
    {
        return Err(refuse_delegation(ctx, DelegationRefusal::Unavailable));
    }

    // Check for consent_required — if any binding needs consent, return the signal
    let mut consent_entries = Vec::new();
    for resolution in &results {
        if let crate::proxy::credential_delegation::DelegationLookupResult::ConsentRequired {
            authorization_url,
            provider_name,
            scopes,
        } = &resolution.result
        {
            consent_entries.push(serde_json::json!({
                "provider_name": provider_name,
                "authorization_url": authorization_url,
                "scopes": scopes,
            }));
        }
    }

    if !consent_entries.is_empty() {
        info!(
            target: "credential_delegation",
            request_id = %ctx.request_id,
            surface_variant = surface_variant.as_deref(),
            providers = %consent_entries.len(),
            user_hash = %user_hash,
            agent_did = %agent_did,
            "Transit credential delegation requires user consent — returning 401"
        );
        // Return a structured consent_required error as a pipeline error.
        // The forward step won't run; the caller receives the consent signal.
        let body = serde_json::json!({
            "type": "https://affinidi.com/atg/errors/consent-required",
            "title": "Credential Delegation Consent Required",
            "status": 401,
            "detail": "This transit point requires delegated credentials. The user must authorize access via the provided URLs.",
            "consent_required": consent_entries,
        });
        return Err(OutboundPipelineError::ConsentRequired(
            serde_json::to_string(&body).unwrap_or_else(|_| "consent_required".to_string()),
        ));
    }

    for resolution in &results {
        if let crate::proxy::credential_delegation::DelegationLookupResult::Inject(injections) = &resolution.result {
            for injection in injections {
                match injection {
                    crate::proxy::credential_delegation::ResolvedCredentialInjection::McpMeta { field, value } => {
                        let Some(body_bytes) = ctx.body_bytes.as_ref() else {
                            warn!(
                                target: "credential_delegation",
                                request_id = %ctx.request_id,
                                surface_variant = surface_variant.as_deref(),
                                meta_field = %field,
                                "Failed to inject delegated credential into outbound MCP metadata because body is unavailable"
                            );
                            return Err(OutboundPipelineError::MetadataInjectionFailed);
                        };
                        match crate::proxy::credential_delegation::inject_delegated_credential_into_mcp_meta(
                            body_bytes, field, value,
                        ) {
                            Ok(modified) => {
                                ctx.body_bytes = Some(modified.into());
                                debug!(
                                    target: "credential_delegation",
                                    request_id = %ctx.request_id,
                                    surface_variant = surface_variant.as_deref(),
                                    meta_field = %field,
                                    "Injecting delegated credential into outbound MCP metadata"
                                );
                            }
                            Err(error) => {
                                warn!(
                                    target: "credential_delegation",
                                    request_id = %ctx.request_id,
                                    surface_variant = surface_variant.as_deref(),
                                    meta_field = %field,
                                    error = %error,
                                    "Failed to inject delegated credential into outbound MCP metadata"
                                );
                                return Err(OutboundPipelineError::MetadataInjectionFailed);
                            }
                        }
                    }
                    crate::proxy::credential_delegation::ResolvedCredentialInjection::Header { name, value } => {
                        debug!(
                            target: "credential_delegation",
                            request_id = %ctx.request_id,
                            surface_variant = surface_variant.as_deref(),
                            header = %name,
                            "Injecting delegated credential header into outbound request"
                        );
                        let (Ok(header_name), Ok(header_value)) = (
                            name.parse::<axum::http::header::HeaderName>(),
                            value.parse::<axum::http::header::HeaderValue>(),
                        ) else {
                            warn!(
                                target: "credential_delegation",
                                request_id = %ctx.request_id,
                                header = %name,
                                "Delegated credential is not a valid header - refusing the request"
                            );
                            return Err(refuse_delegation(ctx, DelegationRefusal::Unavailable));
                        };
                        ctx.delegated_credential_headers
                            .insert(header_name, header_value);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Unified upstream response, abstracting over the two outbound transports so
/// `step_process_response` can normalize either into `(status, headers, body)`.
enum UpstreamResponse {
    /// Direct HTTP(S) response from the shared `reqwest` client.
    Http(reqwest::Response),
    /// Response relayed back from a remote gateway over `fabric://`.
    Fabric {
        status: StatusCode,
        headers: reqwest::header::HeaderMap,
        body: Bytes,
    },
    FabricStream(Response),
}

/// [12] Forward Request — sends the outbound request to the external agent.
///
/// Two transports are supported, selected by the transit point's
/// `target_endpoint`:
/// * `fabric://{gateway_id}/{channel_id}` — gateway-to-gateway forwarding over
///   DIDComm (the prepared request is shipped to a remote gateway channel).
/// * anything else — a direct HTTP(S) request via the shared `reqwest` client.
async fn step_forward_request(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<UpstreamResponse, OutboundPipelineError> {
    if ctx
        .virtual_channel
        .target_endpoint
        .starts_with("fabric://")
    {
        return step_forward_request_fabric(state, ctx).await;
    }

    let response = step_forward_request_http(state, ctx).await?;
    Ok(UpstreamResponse::Http(response))
}

/// The headers a Fabric forward carries, built by [`transit_request_headers`]:
/// as a map of upper-cased names, so the remote gateway and its upstream see
/// case-stable names, as the inbound Fabric forward sends them, and as the header
/// map a `2026-07-28` MCP stream sends, with that request's prepared delegated
/// credentials applied last and its session headers removed.
async fn fabric_forward_headers(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(std::collections::HashMap<String, String>, HeaderMap), OutboundPipelineError> {
    let mut headers_map = std::collections::HashMap::new();
    let mut stream_headers = HeaderMap::new();
    for (key, value) in &transit_request_headers(state, ctx).await? {
        if let Ok(v) = value.to_str() {
            headers_map.insert(key.as_str().to_uppercase(), v.to_string());
            stream_headers.append(key.clone(), value.clone());
        }
    }
    if matches!(
        ctx.mcp_classification
            .as_ref(),
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
    ) {
        if let Some(prepared) = ctx.modern_delegation.as_ref() {
            for (name, value) in prepared
                .credential_headers()
                .map_err(|_| refuse_delegation(ctx, DelegationRefusal::Unavailable))?
                .iter()
            {
                stream_headers.insert(name.clone(), value.clone());
            }
        }
        crate::mcp::modern_http::strip_protocol_session_headers(&mut stream_headers);
    }
    Ok((headers_map, stream_headers))
}

/// Forward the prepared request to a remote gateway channel over `fabric://`.
async fn step_forward_request_fabric(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<UpstreamResponse, OutboundPipelineError> {
    use crate::proxy::fabric_forward::{FabricForwardError, FabricForwardRequest, forward_via_fabric};

    let fabric_target = ctx
        .virtual_channel
        .target_endpoint
        .clone();

    // Path suffix the remote gateway appends to its channel target endpoint —
    // identical to what a direct HTTP target would receive.
    let remainder = compute_outbound_remainder_path(
        &ctx.request_path,
        &ctx.surface.access_point.route,
        &ctx.virtual_channel.alias,
        ctx.virtual_channel
            .listen_path
            .as_deref(),
    );
    let path = if remainder.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", remainder)
    };

    let is_modern = matches!(
        ctx.mcp_classification
            .as_ref(),
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
    );
    let (headers_map, stream_headers) = fabric_forward_headers(state, ctx).await?;

    let timeout = resolve_outbound_timeout(ctx);

    debug!(
        request_id = %ctx.request_id,
        target = %fabric_target,
        path = %path,
        method = %ctx.original_method,
        "Outbound: forwarding request over fabric://"
    );

    let body = ctx
        .body_bytes
        .clone()
        .unwrap_or_default();

    if is_modern {
        let response = crate::proxy::fabric_forward::forward_stream_via_fabric(
            &state.listener_manager,
            crate::proxy::fabric_forward::FabricStreamForwardRequest {
                fabric_target: &fabric_target,
                path: &path,
                headers: stream_headers,
                body,
                header_timeout: timeout,
                limits: ctx
                    .virtual_channel
                    .mcp_http
                    .clone()
                    .unwrap_or_default(),
                trace_id: uuid::Uuid::parse_str(&ctx.request_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            },
        )
        .await
        .map_err(|error| {
            warn!(request_id = %ctx.request_id, %error, "Modern outbound Fabric forward failed");
            let request_id = match ctx
                .mcp_classification
                .as_ref()
            {
                Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) => request.id.clone(),
                _ => None,
            };
            modern_fabric_failure(error, request_id)
        })?;
        return Ok(UpstreamResponse::FabricStream(response));
    }

    let result = forward_via_fabric(
        &state.listener_manager,
        FabricForwardRequest {
            fabric_target: &fabric_target,
            method: &ctx.original_method,
            path: &path,
            headers: headers_map,
            body,
            timeout,
            trace_id: &ctx.request_id,
            log_label: &ctx.surface.name,
        },
    )
    .await
    .map_err(|e| {
        error!(request_id = %ctx.request_id, error = %e, "Outbound fabric forward failed");
        match e {
            FabricForwardError::NoResponse(_) => OutboundPipelineError::UpstreamTimeout,
            other => OutboundPipelineError::UpstreamConnectionFailed(other.to_string()),
        }
    })?;

    let status = StatusCode::from_u16(result.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut header_map = reqwest::header::HeaderMap::new();
    for (key, values) in result.headers {
        let Ok(name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) else {
            continue;
        };
        for value in values {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&value) {
                header_map.append(name.clone(), val);
            }
        }
    }

    Ok(UpstreamResponse::Fabric {
        status,
        headers: header_map,
        body: Bytes::from(result.body),
    })
}

const DEFAULT_OUTBOUND_REQUEST_SECS: u64 = 30;

/// The Transit Point's timeout config, else the surface's.
/// The bounds on an agent card the Transit Point fetches: the same as on any
/// upstream response it reads.
fn agent_card_limits(
    state: &OutboundProxyState,
    ctx: &OutboundPipelineContext,
) -> crate::proxy::upstream_body::UpstreamBodyLimits {
    crate::proxy::upstream_body::UpstreamBodyLimits::new(
        state.max_response_bytes,
        outbound_timeout_config(ctx),
        DEFAULT_OUTBOUND_REQUEST_SECS,
    )
}

fn outbound_timeout_config(ctx: &OutboundPipelineContext) -> Option<&crate::config::TimeoutConfig> {
    ctx.virtual_channel
        .networking
        .as_ref()
        .and_then(|n| n.timeout.as_ref())
        .or_else(|| ctx.surface.timeout())
}

/// Resolve the request timeout from the virtual channel or surface default.
fn resolve_outbound_timeout(ctx: &OutboundPipelineContext) -> std::time::Duration {
    std::time::Duration::from_secs(
        outbound_timeout_config(ctx).map_or(DEFAULT_OUTBOUND_REQUEST_SECS, |t| t.request_secs),
    )
}

/// Forward the prepared request to a direct HTTP(S) target via `reqwest`.
async fn step_forward_request_http(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<reqwest::Response, OutboundPipelineError> {
    let target_url = build_outbound_target_url(
        &ctx.virtual_channel
            .target_endpoint,
        &ctx.request_path,
        &ctx.surface.access_point.route,
        &ctx.virtual_channel.alias,
        ctx.virtual_channel
            .listen_path
            .as_deref(),
        ctx.virtual_channel
            .agent_card_path
            .as_deref(),
    );

    // Defense-in-depth SSRF guard at the forwarding layer. `pinned_forward_client`
    // fails closed on an unparseable URL, resolves DNS once to block a host that
    // *resolves* to a cloud-metadata endpoint, and returns a redirect-disabled
    // client pinned to that exact resolved address — closing the DNS-rebinding
    // window between vetting and connect and returning an upstream 3xx to the
    // caller rather than following it to an unvetted `Location`. Loopback and
    // RFC 1918 stay allowed on purpose — a transit point legitimately targets a
    // localhost sidecar or same-VPC host.
    let candidate = target_url.clone();
    let forward_timeout = resolve_outbound_timeout(ctx);
    let forward_client =
        match tokio::task::spawn_blocking(move || crate::egress::pinned_forward_client(&candidate, forward_timeout))
            .await
        {
            Ok(Ok((client, _target))) => client,
            Ok(Err(e)) => {
                warn!(
                    request_id = %ctx.request_id,
                    target = %loggable::url(&target_url),
                    "SSRF blocked at forwarding layer: {}",
                    e
                );
                return Err(OutboundPipelineError::TargetAuthUnavailable);
            }
            Err(e) => {
                warn!(
                    request_id = %ctx.request_id,
                    target = %loggable::url(&target_url),
                    "SSRF egress validation task failed: {}",
                    e
                );
                return Err(OutboundPipelineError::TargetAuthUnavailable);
            }
        };

    debug!(
        request_id = %ctx.request_id,
        target = %loggable::url(&target_url),
        method = %ctx.original_method,
        "Outbound: forwarding request"
    );

    let body = ctx
        .body_bytes
        .clone()
        .unwrap_or_default();

    // Build request with the original HTTP method.
    let mut req_builder = forward_client
        .request(
            reqwest::Method::from_bytes(
                ctx.original_method
                    .as_str()
                    .as_bytes(),
            )
            .unwrap_or(reqwest::Method::POST),
            &target_url,
        )
        .body(body);

    for (key, value) in &transit_request_headers(state, ctx).await? {
        if let Ok(v) = value.to_str() {
            req_builder = req_builder.header(key.as_str(), v);
        }
    }

    if let Some(prepared) = ctx.modern_delegation.as_ref() {
        req_builder = req_builder.headers(
            prepared
                .credential_headers()
                .map_err(|_| refuse_delegation(ctx, DelegationRefusal::Unavailable))?,
        );
    }
    if matches!(
        ctx.mcp_classification
            .as_ref(),
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
    ) {
        let header_timeout = resolve_outbound_timeout(ctx);
        let config = ctx
            .virtual_channel
            .mcp_http
            .clone()
            .unwrap_or_default();
        let lifetime = std::time::Duration::from_secs(
            config
                .stream_max_lifetime_secs
                .get(),
        );
        let request = req_builder.timeout(header_timeout.saturating_add(lifetime));
        return tokio::time::timeout(header_timeout, request.send())
            .await
            .map_err(|_| OutboundPipelineError::UpstreamTimeout)?
            .map_err(|error| {
                if error.is_timeout() {
                    OutboundPipelineError::UpstreamTimeout
                } else {
                    OutboundPipelineError::UpstreamConnectionFailed(
                        error
                            .without_url()
                            .to_string(),
                    )
                }
            });
    }
    // Apply timeout from virtual channel or channel default.
    let req_builder = if let Some(timeout) = outbound_timeout_config(ctx) {
        req_builder.timeout(std::time::Duration::from_secs(timeout.request_secs))
    } else {
        req_builder
    };

    req_builder
        .send()
        .await
        .map_err(|e| {
            let e = e.without_url();
            if e.is_timeout() {
                warn!(request_id = %ctx.request_id, error = %e, "Outbound request timed out");
                OutboundPipelineError::UpstreamTimeout
            } else {
                error!(request_id = %ctx.request_id, error = %e, "Outbound request failed");
                OutboundPipelineError::UpstreamConnectionFailed(e.to_string())
            }
        })
}

/// Build the effective target URL by combining `target_endpoint` with the remainder of the
/// request path after the channel route + virtual-channel alias.
///
/// Example:
/// * `target_endpoint = "https://partner.example.com/a2a"`
/// * `request_path = "/surfaces/order-service/partner-a/message/send"`
/// * `channel_route = "/surfaces/order-service"`, alias = `partner-a`
///
/// Strips `/surfaces/order-service/partner-a` → remainder `/message/send`
///
/// Result: `https://partner.example.com/a2a/message/send`
fn build_outbound_target_url(
    target_endpoint: &str,
    request_path: &str,
    channel_route: &str,
    alias: &str,
    listen_path: Option<&str>,
    agent_card_path: Option<&str>,
) -> String {
    let base = target_endpoint.trim_end_matches('/');
    let remainder = compute_outbound_remainder_path(request_path, channel_route, alias, listen_path);

    // When this TP overrides its destination's agent-card location and the
    // forwarded remainder is a well-known agent-card request, resolve the card
    // from the destination origin + custom path instead of appending the
    // remainder. Mirrors the inbound access-point behaviour in
    // `protocol_router::route_protocol_request`.
    if let Some(custom_path) = agent_card_path
        && is_well_known_agent_card_remainder(&remainder)
    {
        return agent_card_override_url(target_endpoint, custom_path);
    }

    if remainder.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base, remainder.trim_end_matches('/'))
    }
}

/// Returns `true` when a forwarded path remainder (no leading slash) is a
/// well-known agent-card request (`agent-card.json` or legacy `agent.json`).
fn is_well_known_agent_card_remainder(remainder: &str) -> bool {
    let trimmed = remainder.trim_end_matches('/');
    trimmed.ends_with(".well-known/agent-card.json") || trimmed.ends_with(".well-known/agent.json")
}

/// Build the agent-card URL for an overridden location: the destination
/// origin (scheme + host + port, stripping any sub-path) joined with
/// `custom_path`. Mirrors the inbound override semantics so a TP and its
/// access point can resolve cards from different locations.
fn agent_card_override_url(
    target_endpoint: &str,
    custom_path: &str,
) -> String {
    let custom_path_clean = if custom_path.starts_with('/') {
        custom_path.to_string()
    } else {
        format!("/{}", custom_path)
    };
    let origin = if let Some(scheme_end) = target_endpoint.find("://") {
        let after_scheme = &target_endpoint[scheme_end + 3..];
        if let Some(path_start) = after_scheme.find('/') {
            &target_endpoint[..scheme_end + 3 + path_start]
        } else {
            target_endpoint
        }
    } else {
        target_endpoint
    };
    format!("{}{}", origin.trim_end_matches('/'), custom_path_clean)
}

/// Compute the path suffix to forward, after stripping the transit point's
/// listen prefix (its custom `listen_path`, or the derived
/// `/outbound/<route>/<alias>` convention).
///
/// Returns the remainder **without** a leading slash (e.g. `message/send`), or
/// an empty string when the request targets the transit point root. Both the
/// HTTP target-URL builder and the `fabric://` forwarder share this so the path
/// forwarded to a remote gateway matches what a direct HTTP target would see.
fn compute_outbound_remainder_path(
    request_path: &str,
    channel_route: &str,
    alias: &str,
    listen_path: Option<&str>,
) -> String {
    if let Some(prefix) = listen_path
        && let Some(matched) =
            crate::proxy::route_variant::parse_route_with_variant(request_path, prefix.trim_end_matches('/'))
    {
        return matched
            .tail
            .trim_start_matches('/')
            .to_string();
    }

    // Default `{TP_OUTBOUND_PATH_PREFIX}/<route>/<alias>` derivation.
    // Strip outbound prefix first.
    let after_outgoing = request_path
        .strip_prefix(TP_OUTBOUND_PATH_PREFIX)
        .unwrap_or(request_path);

    // Strip channel route prefix.
    let route = channel_route.trim_end_matches('/');
    let after_route = crate::proxy::route_variant::parse_route_with_variant(after_outgoing, route)
        .map(|matched| matched.tail)
        .unwrap_or(after_outgoing)
        .trim_start_matches('/');

    // Strip the virtual-channel alias (first path segment after the route).
    after_route
        .strip_prefix(alias)
        .map(|rest| rest.trim_start_matches('/'))
        .unwrap_or_else(|| {
            after_route
                .split_once('/')
                .map(|(_, rest)| rest)
                .unwrap_or("")
        })
        .to_string()
}

/// Whether the request fetches the extended agent card over the HTTP+JSON binding
/// on an A2A/AP2 transit point.
fn is_rest_extended_card_request(ctx: &OutboundPipelineContext) -> bool {
    transit_protocol_family(&ctx.virtual_channel.protocol) == Some("a2a")
        && crate::proxy::paths::is_rest_extended_agent_card_request(
            ctx.original_method.as_str(),
            &ctx.virtual_channel
                .target_endpoint,
            &compute_outbound_remainder_path(
                &ctx.request_path,
                &ctx.surface.access_point.route,
                &ctx.virtual_channel.alias,
                ctx.virtual_channel
                    .listen_path
                    .as_deref(),
            ),
        )
}

/// Whether the request calls an extended-card JSON-RPC method on an A2A/AP2
/// transit point.
fn is_rpc_extended_card_request(ctx: &OutboundPipelineContext) -> bool {
    transit_protocol_family(&ctx.virtual_channel.protocol) == Some("a2a")
        && ctx
            .operation
            .as_deref()
            .is_some_and(crate::a2a::is_extended_agent_card_method)
}

/// A compressed extended card cannot be rewritten, so the Target is asked for an
/// uncompressed one.
fn request_uncompressed_extended_agent_card(ctx: &mut OutboundPipelineContext) {
    if is_rest_extended_card_request(ctx) || is_rpc_extended_card_request(ctx) {
        ctx.original_headers
            .insert(axum::http::header::ACCEPT_ENCODING, axum::http::HeaderValue::from_static("identity"));
    }
}

/// Check whether the upstream response is a well-known agent card based on the request path and status.
fn is_agent_card_response(
    request_path: &str,
    status: reqwest::StatusCode,
) -> bool {
    status.is_success() && crate::proxy::paths::is_well_known_agent_card_path(request_path)
}

/// [12] Response Processing — strips headers and optionally rewrites agent card URLs.
/// Per-Transit-Point MCP Tool Gating — `tools/list` leg.
///
/// Hides the tools this transit point's gating firewall denies from a
/// `tools/list` response before the managed agent sees them, so the visible
/// tool set matches what the `tools/call` gate on the request leg permits.
/// Only rewrites MCP transit-point responses when the TP has gating installed.
/// Responses with a `result.tools` array are filtered; unparseable responses
/// fail closed to an empty tool list because they cannot be inspected. Other
/// non-tool-list responses are returned unchanged. The gate condition sees the
/// same outbound `PolicyInput` the request-leg gate uses, with `mcp.method`
/// pinned to `tools/list`.
fn filter_transit_mcp_tools_list(
    state: &OutboundProxyState,
    ctx: &OutboundPipelineContext,
    body_bytes: Bytes,
) -> Bytes {
    if ctx.virtual_channel.protocol != crate::config::agent_surface::TransitProtocol::Mcp {
        return body_bytes;
    }
    if ctx.operation.as_deref() != Some("tools/list") {
        return body_bytes;
    }
    let alias = ctx
        .virtual_channel
        .alias
        .as_str();
    let Some(gating) = compiled_transit_mcp_tool_gating(state, ctx) else {
        if transit_mcp_tool_gating_configured(ctx) {
            warn!(
                request_id = %ctx.request_id,
                alias = %alias,
                "Per-transit-point MCP tool gating is configured but not in force; failing closed (empty tool list)"
            );
            return Bytes::from(crate::mcp::fail_closed_tools_list(
                ctx.body_bytes
                    .as_deref()
                    .unwrap_or_default(),
                ctx.mcp_metadata_context,
            ));
        }
        return body_bytes;
    };
    if body_bytes.is_empty() {
        return body_bytes;
    }
    // Handle both plain JSON and SSE (Streamable HTTP text/event-stream) tool
    // lists — an SSE-replying TP must not bypass gating.
    let (mut json, was_sse) = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        Ok(v) => (v, false),
        Err(_) => match crate::mcp::sse_transport::extract_last_json_rpc_from_sse_bytes(&body_bytes)
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        {
            Some(v) => (v, true),
            // Cannot parse the tools/list response as JSON or SSE. Once a
            // gate is installed, an un-inspectable response must fail closed
            // (return an empty tool list) rather than stream through unfiltered.
            // This does not change the default allow/deny composition for a
            // parseable response; it only handles a response we cannot inspect.
            None => {
                warn!(
                    request_id = %ctx.request_id,
                    alias = %alias,
                    "Per-transit-point MCP tools/list response unparsable under gating; failing closed (empty tool list)"
                );
                return Bytes::from(crate::mcp::fail_closed_tools_list(
                    ctx.body_bytes
                        .as_deref()
                        .unwrap_or_default(),
                    ctx.mcp_metadata_context,
                ));
            }
        },
    };
    let Some(tools) = json
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    else {
        return body_bytes;
    };
    let names: Vec<String> = tools
        .iter()
        .filter_map(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .map(str::to_string)
        })
        .collect();
    if names.is_empty() {
        return body_bytes;
    }

    let input_value = if gating.has_policy_conditions() {
        let mut policy_input = build_outbound_policy_input(ctx);
        policy_input.mcp = ctx
            .mcp_classification
            .as_ref()
            .and_then(crate::mcp::modern_mcp_context)
            .or_else(|| {
                Some(crate::surface_context::McpContext {
                    method: "tools/list".to_string(),
                    tool_name: None,
                    resource_uri: None,
                    prompt_name: None,
                    params: None,
                    ..Default::default()
                })
            });
        serde_json::to_value(&policy_input).unwrap_or_default()
    } else {
        serde_json::Value::Null
    };

    let allowed = gating.filter_tools(names, &input_value);
    let before = tools.len();
    tools.retain(|t| {
        t.get("name")
            .and_then(|n| n.as_str())
            .map(|n| allowed.contains(&n.to_string()))
            .unwrap_or(false)
    });
    let after = tools.len();
    if after < before {
        info!(
            request_id = %ctx.request_id,
            alias = %alias,
            before,
            after,
            "Per-transit-point MCP tool gating filtered tools/list"
        );
    }

    // Re-serialize in the same framing the TP used, so a Streamable-HTTP
    // (SSE) response stays SSE for the managed agent.
    if was_sse {
        match serde_json::to_string(&json) {
            Ok(s) => Bytes::from(crate::mcp::sse_server::wrap_json_as_sse_event(&s).into_bytes()),
            Err(_) => body_bytes,
        }
    } else {
        match serde_json::to_vec(&json) {
            Ok(v) => Bytes::from(v),
            Err(_) => body_bytes,
        }
    }
}

async fn step_process_response(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
    upstream: UpstreamResponse,
) -> Result<Response, OutboundPipelineError> {
    let (status, upstream_headers, body_bytes) = match upstream {
        UpstreamResponse::Http(resp) => {
            let status = resp.status();
            let upstream_headers = resp.headers().clone();
            let limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(
                state.max_response_bytes,
                outbound_timeout_config(ctx),
                DEFAULT_OUTBOUND_REQUEST_SECS,
            );
            let body = crate::proxy::upstream_body::read_bounded(resp, limits).await;
            let body_bytes = body.map_err(|e| {
                error!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Failed to read upstream response body"
                );
                match e {
                    crate::proxy::upstream_body::UpstreamBodyError::TimedOut => OutboundPipelineError::UpstreamTimeout,
                    crate::proxy::upstream_body::UpstreamBodyError::TooLarge(_)
                    | crate::proxy::upstream_body::UpstreamBodyError::Read(_) => {
                        OutboundPipelineError::UpstreamResponseReadFailed
                    }
                }
            })?;
            (status, upstream_headers, body_bytes)
        }
        UpstreamResponse::Fabric { status, headers, body } => (status, headers, body),
        UpstreamResponse::FabricStream(_) => return Err(OutboundPipelineError::UpstreamResponseReadFailed),
    };

    let response_policy = transit_response_policy_attestation(state, transit_response_policy_definition_id(ctx)).await;
    process_outbound_response_body(state, ctx, status, upstream_headers, body_bytes, &response_policy)
}

async fn process_modern_outbound_response(
    state: OutboundProxyState,
    mut ctx: OutboundPipelineContext,
    upstream: UpstreamResponse,
) -> Result<Response, OutboundPipelineError> {
    use crate::mcp::modern_sse::{
        SseReadError, TransportCompletion, forwarding_response_with_completion, observe_response,
    };
    use futures::{StreamExt, TryStreamExt};
    let Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) =
        ctx.mcp_classification.clone()
    else {
        return Err(OutboundPipelineError::ResponseBuildFailed);
    };
    let request = *request;
    let config = ctx
        .virtual_channel
        .mcp_http
        .clone()
        .unwrap_or_default();
    let limits = crate::mcp::modern_sse::SseLimits::from(&config);
    let mut discovery_support = crate::mcp::modern::ForwardingSupport::for_endpoint(
        ctx.virtual_channel
            .target_endpoint
            .starts_with("fabric://"),
        crate::mcp::request_validation::McpPathKind::TransitPoint,
    )
    .recording_versions(transit_upstream_key(&ctx));
    let (status, headers, source, completion) = match upstream {
        UpstreamResponse::Http(upstream) => (
            upstream.status(),
            upstream.headers().clone(),
            upstream
                .bytes_stream()
                .map_err(std::io::Error::other)
                .boxed(),
            None,
        ),
        UpstreamResponse::FabricStream(response) => {
            discovery_support = discovery_support.restrict_to_fabric_peer(
                response
                    .extensions()
                    .get::<crate::proxy::fabric_stream::peer::StreamCapabilities>(),
            );
            let (mut parts, body) = response.into_parts();
            (
                parts.status,
                parts.headers,
                body.into_data_stream()
                    .map_err(std::io::Error::other)
                    .boxed(),
                parts
                    .extensions
                    .remove::<TransportCompletion>(),
            )
        }
        UpstreamResponse::Fabric { .. } => return Err(OutboundPipelineError::UpstreamResponseReadFailed),
    };
    let mut processing_headers = headers.clone();
    processing_headers.insert("content-type", axum::http::HeaderValue::from_static("application/json"));
    let mut headers = headers;
    withhold_target_response_headers(&mut headers);
    let prepared = ctx.modern_delegation.take();
    let continuations = state
        .mcp_continuations
        .clone();
    // Resolved once per response: the definition does not change between
    // messages, and the lock below cannot be held across an await.
    let response_policy =
        transit_response_policy_attestation(&state, transit_response_policy_definition_id(&ctx)).await;
    let shared = Arc::new(std::sync::Mutex::new((state, ctx)));
    let processing = shared.clone();
    let response = forwarding_response_with_completion(
        source,
        status,
        &headers,
        request,
        limits,
        discovery_support,
        move |message| {
            let processing = processing.clone();
            let headers = processing_headers.clone();
            let response_policy = response_policy.clone();
            async move {
                let bytes = Bytes::from(serde_json::to_vec(&message).map_err(|_| SseReadError::InvalidMessage)?);
                let response = {
                    let mut snapshot = processing
                        .lock()
                        .map_err(|_| SseReadError::ResponseRejected)?;
                    let (state, ctx) = &mut *snapshot;
                    process_outbound_response_body(state, ctx, status, headers, bytes, &response_policy).map_err(
                        |error| {
                            warn!(request_id = %ctx.request_id, error = %error, "Modern MCP response rejected");
                            SseReadError::ResponseRejected
                        },
                    )?
                };
                let bytes = axum::body::to_bytes(response.into_body(), limits.max_event_bytes.get())
                    .await
                    .map_err(|_| SseReadError::EventTooLarge)?;
                serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_| SseReadError::InvalidMessage)
            }
        },
        move |message| async move {
            let Some(prepared) = prepared else {
                return Ok(message);
            };
            let runtime = continuations
                .as_deref()
                .ok_or(SseReadError::ResponseRejected)?;
            let now =
                crate::proxy::credential_delegation::modern::now_secs().map_err(|_| SseReadError::ResponseRejected)?;
            prepared
                .finish(&runtime.service, message, runtime.config.ttl_secs, now)
                .await
                .map_err(|_| SseReadError::ResponseRejected)
        },
        completion,
    )
    .await
    .map_err(|error| {
        if let Ok(snapshot) = shared.lock() {
            warn!(request_id = %snapshot.1.request_id, error = %error, "Invalid modern MCP upstream response");
        }
        OutboundPipelineError::UpstreamResponseReadFailed
    })?;
    Ok(observe_response(response, move |outcome| {
        if let Ok(mut snapshot) = shared.lock() {
            let (state, ctx) = &mut *snapshot;
            ctx.response_bytes = Some(outcome.bytes);
            if outcome.completed || outcome.failed {
                step_record_metrics(state, ctx, outcome.completed && status.is_success());
            } else {
                warn!(request_id = %ctx.request_id, response_bytes = outcome.bytes, "Modern MCP response ended before completion");
            }
        }
    }))
}

fn process_outbound_response_body(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
    status: StatusCode,
    upstream_headers: reqwest::header::HeaderMap,
    body_bytes: Bytes,
    response_policy: &crate::policies::PolicyAttestation,
) -> Result<Response, OutboundPipelineError> {
    use crate::a2a::is_hop_by_hop_header;

    // Capture body size before any rewrites so the per-TP throughput row
    // reflects what actually came off the wire from the partner.
    ctx.response_bytes = Some(body_bytes.len() as u64);
    let body_bytes = if ctx.virtual_channel.protocol == crate::config::agent_surface::TransitProtocol::Mcp {
        crate::mcp::meta::normalize_bytes(&body_bytes, ctx.mcp_metadata_context).map_err(|error| {
            OutboundPipelineError::McpMetadata {
                error,
                body: body_bytes.clone(),
                response: true,
            }
        })?
    } else {
        body_bytes
    };

    // Validate response extensions if configured.
    if let Some(ref rules_engine) = ctx.outbound_response_rules_engine
        && !body_bytes.is_empty()
        && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
    {
        if let Err(e) = rules_engine.validate(&json, &ctx.surface.name) {
            warn!(
                request_id = %ctx.request_id,
                error = %e,
                "Outbound response extension validation failed"
            );
            return Err(OutboundPipelineError::ResponseValidationFailed(e.to_string()));
        }
        debug!(request_id = %ctx.request_id, "Outbound: response extension validation passed");
    }

    // Per-Transit-Point Response OPA Policy.
    // Independent of the inbound `target.response_policy`: filters the
    // response from THIS specific transit point before forwarding it back.
    step_transit_point_response_policy(state, ctx, status, &body_bytes, &upstream_headers, response_policy)?;

    // Per-Transit-Point MCP Tool Gating (tools/list leg). Hide the tools this
    // TP's firewall denies before the managed agent sees them — parity with
    // the tools/call block on the request leg.
    let mut body_bytes = filter_transit_mcp_tools_list(state, ctx, body_bytes);
    if matches!(
        ctx.mcp_classification
            .as_ref(),
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
    ) && (ctx
        .virtual_channel
        .mcp_tool_gating
        .is_some()
        || ctx
            .virtual_channel
            .response_policy
            .is_some()
        || ctx
            .outbound_response_rules_engine
            .is_some())
    {
        let mut message: serde_json::Value =
            serde_json::from_slice(&body_bytes).map_err(|_| OutboundPipelineError::UpstreamResponseReadFailed)?;
        crate::mcp::meta::protect_enriched_result_cache(&mut message, ctx.mcp_metadata_context);
        body_bytes = Bytes::from(serde_json::to_vec(&message).map_err(|_| OutboundPipelineError::ResponseBuildFailed)?);
    }

    // Agent card URL rewriting (Step 12 — outbound).
    // When the response is an agent card, rewrite URLs to the transit
    // point's public proxy endpoint so the protected agent routes
    // through the gateway. `TransitPoint.gateway_url` is declared
    // "computed" but never assigned, so derive it here from the surface
    // + listener config.
    let is_rest_extended_card_response = status.is_success() && is_rest_extended_card_request(ctx);
    let is_rpc_extended_card_response = is_rpc_extended_card_request(ctx);
    let is_extended_card_response = is_rest_extended_card_response || is_rpc_extended_card_response;
    let body_bytes = if is_agent_card_response(&ctx.request_path, status) || is_extended_card_response {
        let proxy_endpoint = crate::a2a::url_rewriter::build_transit_point_proxy_endpoint(
            &ctx.surface,
            &ctx.virtual_channel,
            &state.network_config,
        );
        let rewritten = if is_rpc_extended_card_response {
            crate::a2a::url_rewriter::process_outbound_extended_agent_card(
                &body_bytes,
                &proxy_endpoint,
                &ctx.surface.name,
                status,
            )
        } else {
            let kind = if is_extended_card_response {
                crate::a2a::AgentCardKind::Extended
            } else {
                crate::a2a::AgentCardKind::Public
            };
            crate::a2a::url_rewriter::process_outbound_agent_card(&body_bytes, &proxy_endpoint, &ctx.surface.name, kind)
                .map(Some)
        };
        match rewritten {
            Ok(Some(rewritten)) => {
                info!(
                    request_id = %ctx.request_id,
                    "Rewrote outbound agent card URLs to outbound virtual channel endpoint"
                );
                rewritten
            }
            Ok(None) => body_bytes,
            Err(e) if is_extended_card_response => {
                warn!(request_id = %ctx.request_id, error = %e, "Failed to rewrite outbound extended agent card URLs");
                return Err(OutboundPipelineError::UnrewritableExtendedAgentCardResponse {
                    rpc_request_id: is_rpc_extended_card_response.then(|| {
                        ctx.body_bytes
                            .as_deref()
                            .and_then(crate::a2a::url_rewriter::extended_agent_card_request_id)
                            .unwrap_or(serde_json::Value::Null)
                    }),
                });
            }
            Err(e) => {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Failed to rewrite outbound agent card URLs, returning original"
                );
                body_bytes
            }
        }
    } else {
        body_bytes
    };

    // Build the response, forwarding non-hop-by-hop headers other than the
    // withheld ones.
    // Skip content-length: the body may have been rewritten (e.g. agent card URL
    // rewriting), so the upstream content-length is stale. Axum/hyper will set
    // the correct value from the actual body bytes.
    let mut builder = axum::response::Response::builder().status(status);
    let mut upstream_headers = upstream_headers;
    withhold_target_response_headers(&mut upstream_headers);

    for (key, value) in &upstream_headers {
        if !is_hop_by_hop_header(key.as_str()) && key != axum::http::header::CONTENT_LENGTH {
            builder = builder.header(key.as_str(), value.as_bytes());
        }
    }

    builder
        .body(axum::body::Body::from(body_bytes))
        .map_err(|e| {
            error!(
                request_id = %ctx.request_id,
                error = %e,
                "Failed to build outbound response"
            );
            OutboundPipelineError::ResponseBuildFailed
        })
}

/// [13] Metrics & Logging - records latency and status, `succeeded` when the
/// target answered with a 2xx and the response reached the agent whole. Never
/// fails.
fn step_record_metrics(
    state: &OutboundProxyState,
    ctx: &OutboundPipelineContext,
    succeeded: bool,
) {
    let latency_ms = ctx
        .start_time
        .elapsed()
        .as_millis() as u64;

    debug!(
        request_id = %ctx.request_id,
        latency_ms = latency_ms,
        resolved_identity = ?ctx.resolved_identity,
        virtual_channel = %ctx.virtual_channel.alias,
        "Outbound request completed"
    );

    let request_bytes: u64 = ctx
        .body_bytes
        .as_ref()
        .map(|b| b.len() as u64)
        .unwrap_or(0);
    let response_bytes: u64 = ctx
        .response_bytes
        .unwrap_or(0);

    // Update the per-transit-point task row so the dashboard shows
    // independent throughput / total connections / last activity per TP.
    if let Some(monitor) = state.task_monitor.as_ref() {
        let config_id = ctx.surface.surface_id.clone();
        let monitor = Arc::clone(monitor);
        let alias = ctx
            .virtual_channel
            .alias
            .clone();
        tokio::spawn(async move {
            monitor
                .record_tp_request(&config_id, &alias, request_bytes, response_bytes)
                .await;
        });
    }

    if let Some(ref metrics) = state.metrics_store {
        let channel_config_id = ctx
            .surface
            .config_id()
            .map(String::from)
            .unwrap_or_else(|| "unknown".to_string());
        let source = ctx.remote_addr.to_string();
        let dest = ctx
            .virtual_channel
            .target_endpoint
            .clone();
        let transit_point_alias = ctx
            .virtual_channel
            .alias
            .clone();
        let metrics = Arc::clone(metrics);
        let status = if succeeded {
            crate::metrics::ConnectionStatus::Success
        } else {
            crate::metrics::ConnectionStatus::Failed
        };

        crate::observability::policy_audit::spawn_in_request(async move {
            metrics
                .record_connection_with_transit_point(
                    channel_config_id,
                    source,
                    dest,
                    status,
                    Some(latency_ms),
                    None,
                    crate::metrics::ConnectionDirection::Request,
                    uuid::Uuid::new_v4().to_string(),
                    0,    // bytes_sent
                    0,    // bytes_received
                    None, // ucp_operation
                    transit_point_alias,
                    None,
                    None,
                    latency_ms,
                )
                .await;
        });
    }
}

fn modern_fabric_failure(
    error: crate::proxy::fabric_forward::FabricForwardError,
    request_id: Option<serde_json::Value>,
) -> OutboundPipelineError {
    use crate::proxy::fabric_forward::FabricForwardError;
    match error {
        FabricForwardError::NoResponse(_) => OutboundPipelineError::UpstreamTimeout,
        FabricForwardError::RemoteLegacyOnly => OutboundPipelineError::McpValidation(
            crate::mcp::request_validation::McpRequestValidationError::legacy_only(request_id),
        ),
        FabricForwardError::CapacityReached => OutboundPipelineError::UpstreamCapacityReached(request_id),
        _ => OutboundPipelineError::UpstreamConnectionFailed("Modern Fabric transport is unavailable".to_string()),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_fabric_failures_map_to_their_pipeline_errors() {
        use crate::proxy::fabric_forward::FabricForwardError;

        assert!(matches!(
            modern_fabric_failure(FabricForwardError::CapacityReached, Some(json!("request-1"))),
            OutboundPipelineError::UpstreamCapacityReached(Some(id)) if id == json!("request-1")
        ));
        assert!(matches!(
            modern_fabric_failure(FabricForwardError::StreamingUnavailable, Some(json!("request-1"))),
            OutboundPipelineError::UpstreamConnectionFailed(_)
        ));
        assert!(matches!(
            modern_fabric_failure(FabricForwardError::NoResponse("gw".into()), None),
            OutboundPipelineError::UpstreamTimeout
        ));
        assert!(matches!(
            modern_fabric_failure(FabricForwardError::RemoteLegacyOnly, Some(json!(7))),
            OutboundPipelineError::McpValidation(_)
        ));
    }

    #[tokio::test]
    async fn a_peer_stream_cap_refusal_is_a_retryable_429_not_a_connection_failure() {
        let error = OutboundPipelineError::UpstreamCapacityReached(Some(json!("request-1")));
        assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap(),
            "5"
        );
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["id"], "request-1");
        assert!(body["error"]["code"].is_i64());
        assert_eq!(
            OutboundPipelineError::UpstreamConnectionFailed("transport".into()).status_code(),
            StatusCode::BAD_GATEWAY
        );
    }

    /// The Transit Point's agent-card fetch reads within its response bounds and
    /// returns a redirect rather than following it.
    #[tokio::test]
    async fn transit_agent_card_fetch_is_bounded_and_does_not_follow_redirects() {
        let app = axum::Router::new()
            .route(
                "/small/.well-known/agent-card.json",
                axum::routing::get(|| async { axum::Json(json!({"name": "card"})) }),
            )
            .route(
                "/large/.well-known/agent-card.json",
                axum::routing::get(|| async { axum::Json(json!({"name": "x".repeat(4096)})) }),
            )
            .route(
                "/redirect/.well-known/agent-card.json",
                axum::routing::get(|| async {
                    axum::response::Redirect::temporary("/small/.well-known/agent-card.json")
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        let limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(1024, None, 5);
        let fetch = |path: &'static str| {
            let url = format!("{base}/{path}");
            async move { fetch_agent_card(&url, None, "test", std::time::Duration::from_secs(5), limits).await }
        };

        assert_eq!(fetch("small").await, Some(json!({"name": "card"})));
        assert_eq!(fetch("large").await, None, "a card over the bound is dropped");
        assert_eq!(fetch("redirect").await, None, "a redirect is not followed");
    }
    use axum::http::{HeaderMap, HeaderValue};
    use bytes::Bytes;
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    use crate::config::ChannelProtocol;
    use crate::config::agent_surface::TransitPoint;

    // ── Outbound policy-decision auditing ───────────────────────────────────

    #[tokio::test]
    async fn outbound_policy_audit_records_allow_and_deny_into_collector() {
        use crate::observability::policy_audit::POLICY_DECISION_COLLECTOR;
        use std::sync::Mutex;

        let carried: Option<crate::delegation_vault::audit::AuditCallerContext> =
            serde_json::from_value(serde_json::json!({"auth_method": "transit_token", "email": "ada@example.com"}))
                .ok();
        let collector = Arc::new(Mutex::new(Vec::new()));
        POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), async {
                // Gateway-scope allow (no policy definition, carries gateway_did).
                OutboundPolicyAudit {
                    scope: crate::observability::PolicyScope::Gateway,
                    policy_id: crate::policies::GATEWAY_POLICY_PACKAGE,
                    policy_definition_id: None,
                    policy_name: None,
                    surface_id: Some("surf-1"),
                    surface_name: Some("Surface one"),
                    http_method: "GET",
                    path: "/payments/pioneer/trust",
                    actor_did: Some("did:web:agent"),
                    gateway_did: Some("gw-1"),
                    trace_id: "req-1",
                    policy_version: None,
                    policy_content_hash: None,
                    caller: None,
                }
                .record(true, None);

                // Surface-scope deny (carries a policy-definition id + reason).
                OutboundPolicyAudit {
                    scope: crate::observability::PolicyScope::Surface,
                    policy_id: crate::policies::SURFACE_POLICY_PACKAGE,
                    policy_definition_id: Some("def-uuid-7"),
                    policy_name: Some("Partner egress policy"),
                    surface_id: Some("surf-1"),
                    surface_name: Some("Surface one"),
                    http_method: "GET",
                    path: "/payments/pioneer/trust",
                    actor_did: Some("did:web:agent"),
                    gateway_did: None,
                    trace_id: "req-1",
                    policy_version: Some(5),
                    policy_content_hash: Some("sha256:egress"),
                    caller: carried.as_ref(),
                }
                .record(false, Some("blocked by policy"));
            })
            .await;

        let decisions = collector.lock().unwrap();
        assert_eq!(decisions.len(), 2, "both outbound decisions should be recorded");

        let allow = &decisions[0];
        assert_eq!(allow.scope, "gateway");
        assert_eq!(allow.decision, "allow");
        assert_eq!(allow.policy_id.as_deref(), Some("gateway.policy"));
        assert!(
            allow
                .policy_definition_id
                .is_none()
        );
        assert_eq!(allow.surface_id.as_deref(), Some("surf-1"));
        assert_eq!(allow.http_method.as_deref(), Some("GET"));
        assert_eq!(allow.http_path.as_deref(), Some("/payments/pioneer/trust"));
        assert_eq!(allow.caller_did.as_deref(), Some("did:web:agent"));
        assert!(allow.deny_reason.is_none());
        assert_eq!(allow.policy_version, None);
        assert_eq!(allow.policy_content_hash, None);

        let deny = &decisions[1];
        assert_eq!(deny.scope, "surface");
        assert_eq!(deny.decision, "deny");
        assert_eq!(deny.policy_id.as_deref(), Some("surface.policy"));
        assert_eq!(
            deny.policy_definition_id
                .as_deref(),
            Some("def-uuid-7")
        );
        assert_eq!(deny.policy_name, "Partner egress policy");
        assert_eq!(deny.deny_reason.as_deref(), Some("blocked by policy"));
        assert_eq!(deny.policy_version, Some(5), "the enforced revision is attested");
        assert_eq!(
            deny.policy_content_hash
                .as_deref(),
            Some("sha256:egress")
        );
    }

    #[tokio::test]
    async fn outbound_policy_audit_falls_back_to_the_definition_id_when_unnamed() {
        use crate::observability::policy_audit::POLICY_DECISION_COLLECTOR;
        use std::sync::Mutex;

        let collector = Arc::new(Mutex::new(Vec::new()));
        POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), async {
                OutboundPolicyAudit {
                    scope: crate::observability::PolicyScope::Response,
                    policy_id: crate::policies::SURFACE_POLICY_PACKAGE,
                    policy_definition_id: Some("def-resp-1"),
                    policy_name: None,
                    surface_id: Some("surf-2"),
                    surface_name: Some("Surface two"),
                    http_method: "POST",
                    path: "/a2a",
                    actor_did: None,
                    gateway_did: None,
                    trace_id: "req-2",
                    policy_version: None,
                    policy_content_hash: None,
                    caller: None,
                }
                .record(true, None);
            })
            .await;

        let decisions = collector.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].scope, "response");
        assert_eq!(decisions[0].policy_name, "def-resp-1");
        assert!(
            decisions[0]
                .caller_did
                .is_none()
        );
    }

    #[tokio::test]
    async fn outbound_policy_audit_records_an_evaluation_error_as_error() {
        use crate::observability::policy_audit::POLICY_DECISION_COLLECTOR;
        use std::sync::Mutex;

        let collector = Arc::new(Mutex::new(Vec::new()));
        POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), async {
                OutboundPolicyAudit {
                    scope: crate::observability::PolicyScope::Response,
                    policy_id: crate::policies::SURFACE_POLICY_PACKAGE,
                    policy_definition_id: Some("def-resp-1"),
                    policy_name: None,
                    surface_id: Some("surf-2"),
                    surface_name: Some("Surface two"),
                    http_method: "POST",
                    path: "/a2a",
                    actor_did: None,
                    gateway_did: None,
                    trace_id: "req-3",
                    policy_version: None,
                    policy_content_hash: None,
                    caller: None,
                }
                .record_error(crate::observability::PolicyEvaluationError::EvaluationError);
            })
            .await;

        let decisions = collector.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].decision, "error");
        assert_eq!(
            decisions[0]
                .deny_reason
                .as_deref(),
            Some("evaluation_error")
        );
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn test_virtual_channel() -> TransitPoint {
        serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "gateway_url": "https://gw.internal:9000/outbound/surfaces/order/partner-a",
            "identity_injection": { "inject_vp": true }
        }))
        .unwrap()
    }

    fn test_surface() -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(json!({
            "name": "test-channel",
            "description": "Test",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/surfaces/order",
                "protocol": "a2a"
            },
            "target": {
                "endpoint": "http://localhost:9000"
            },
            "transit": {
                "points": [
                    { "alias": "partner-a", "target_endpoint": "https://partner.example.com/a2a", "gateway_url": "https://gw.internal:9000/outbound/surfaces/order/partner-a" },
                    { "alias": "partner-b", "target_endpoint": "https://partner-b.example.com", "gateway_url": "https://gw.internal:9000/outbound/surfaces/order/partner-b" }
                ]
            }
        }))
        .expect("outbound_handler test_surface: AgentSurface JSON")
    }

    fn test_pipeline_context() -> OutboundPipelineContext {
        let surface = Arc::new(test_surface());
        OutboundPipelineContext {
            request: None,
            remote_addr: "127.0.0.1:12345"
                .parse::<SocketAddr>()
                .unwrap(),
            virtual_channel: test_virtual_channel(),
            outbound_shared: crate::config::agent_surface::SharedTransitConfig::default(),
            body_bytes: None,
            original_method: Method::POST,
            original_headers: HeaderMap::new(),
            delegated_credential_headers: HeaderMap::new(),
            request_path: "/outbound/surfaces/order/partner-a/message/send".to_string(),
            resolved_identity: ProtectedAgentIdentity::Anonymous,
            protocol: None,
            mcp_metadata_context: crate::mcp::meta::McpMetadataContext::default(),
            mcp_classification: None,
            authenticated_identity: None,
            authenticated_by: None,
            mcp_resource_authorization: None,
            modern_delegation: None,
            operation: None,
            target_agent_context: None,
            target_agent_card_unavailable: false,
            target_identity_failure: None,
            trust_check_results: None,
            request_id: "test-request-id".to_string(),
            start_time: Instant::now(),
            _outbound_rules_engine: None,
            outbound_response_rules_engine: None,
            transit_token_claims: None,
            optional_transit_token_claims: None,
            response_bytes: None,
            active_variant_alias: None,
            active_variant_id: None,
            pending_variant_refusal: None,
            surface,
            identity_rules_engine: None,
            identity_selector: None,
        }
    }

    fn test_outbound_state() -> OutboundProxyState {
        let network_config: crate::config::NetworkConfig = serde_json::from_value(json!({
            "did": { "domain": "test.example.com" },
            "webauthn": { "rp_id": "test", "external_origin": "https://test.example.com" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "routes": {}
        }))
        .unwrap();

        OutboundProxyState {
            network_config: Arc::new(network_config),
            channel_state: Arc::new(std::sync::RwLock::new(crate::state::OutboundSurfaceState {
                surface: Arc::new(test_surface()),
                identity_rules_engine: None,
                identity_selector: None,
            })),
            metrics_store: None,
            secrets_store: None,
            certificates_store: None,
            policy_manager: None,
            gateway_policy_manager: None,
            trust_registry_listener_manager: None,
            listener_manager: Arc::new(tokio::sync::RwLock::new(None)),
            vc_issuer: None,
            transit_token_issuer: None,
            delegation_vault_store: None,
            credential_provider_store: None,
            consent_identity_strategies: None,
            source_auth_middleware: None,
            mcp_continuations: None,
            gateway_base_url: None,
            task_monitor: None,
            max_response_bytes: crate::config::A2aConfig::default().max_body_size,
            vc_alias_override: None,
        }
    }

    fn modern_pipeline_context(method: &str) -> OutboundPipelineContext {
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        let body = json!({"jsonrpc": "2.0", "id": "stream", "method": method, "params": {
            "name": "echo", "_meta": {"progressToken": "work",
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}}
        }});
        let mut headers = HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("mcp-method", method.parse().unwrap());
        headers.insert("mcp-name", "echo".parse().unwrap());
        let classification = crate::mcp::request_validation::validate_mcp_post(
            &headers,
            &serde_json::to_vec(&body).unwrap(),
            crate::mcp::request_validation::LegacySessionEvidence::Absent,
            crate::mcp::request_validation::MODERN_ONLY_POLICY,
        )
        .unwrap();
        ctx.mcp_metadata_context = crate::mcp::meta::McpMetadataContext::from_classification(&classification, None);
        ctx.mcp_classification = Some(classification);
        ctx.body_bytes = Some(Bytes::from(body.to_string()));
        ctx.operation = Some(method.to_string());
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx
    }

    #[tokio::test]
    async fn modern_transit_consent_binds_its_resource_and_preserves_delegated_credentials() {
        if std::env::var_os("ATG_MCP_SUBSCRIPTION_TRANSIT_CHILD").is_none() {
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string();
            let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env("ATG_MCP_SUBSCRIPTION_TRANSIT_CHILD", "1")
                .env("RUST_MIN_STACK", "8388608")
                .kill_on_drop(true)
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "isolated Transit MCP test failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
        use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
        use crate::mcp::continuations::{config::ContinuationRuntime, negative_cases, protected::ContinuationRoute};
        use futures::TryStreamExt;
        use std::collections::HashMap;

        type ObservedCalls = Arc<tokio::sync::Mutex<Vec<(HeaderMap, serde_json::Value)>>>;
        let calls: ObservedCalls = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let target = axum::Router::new()
            .fallback(axum::routing::post(
                |State(calls): State<ObservedCalls>,
                 uri: axum::http::Uri,
                 headers: HeaderMap,
                 axum::Json(body): axum::Json<serde_json::Value>| async move {
                    let result = if body["params"]
                        .get("requestState")
                        .is_some()
                    {
                        json!({"resultType": "complete", "content": []})
                    } else {
                        json!({"resultType": "input_required", "requestState": "transit opaque upstream state",
                        "inputRequests": {"upstream": {"method": "elicitation/create", "params": {
                            "mode": "url", "url": "https://provider.example/consent", "message": "Authorize"
                        }}}})
                    };
                    let response = json!({"jsonrpc": "2.0", "id": body["id"], "result": result});
                    calls
                        .lock()
                        .await
                        .push((headers, body));
                    if uri.path().contains("sse") {
                        ([("content-type", "text/event-stream")], format!("data: {response}\n\n")).into_response()
                    } else {
                        axum::Json(response).into_response()
                    }
                },
            ))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let target_address = listener.local_addr().unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, target)
                .await
                .unwrap();
        });
        let (issuer, directory) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let providers = Arc::new(
            FileSystemCredentialProviderStore::new(
                directory
                    .path()
                    .join("providers"),
            )
            .await
            .unwrap(),
        );
        let strategies = Arc::new(
            FileSystemJwtVerificationStrategyStore::new(
                directory
                    .path()
                    .join("strategies"),
            )
            .await
            .unwrap(),
        );
        let vault = Arc::new(
            FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let strategy = strategies
            .create(
                crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &json!({"keys": []}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let provider = providers
            .create(
                serde_json::from_value(json!({
                    "id": "provider", "name": "Provider", "provider_id": "provider",
                    "resource": "https://provider.example/api", "consent_identity_strategy_id": strategy.id,
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let mut state = test_outbound_state();
        state.network_config = Arc::new(
            serde_json::from_value(json!({
                "did": {"domain": "gateway.example"},
                "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
                "integration": {"types": [], "categories": []},
                "listeners": [
                    {"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080,
                        "protocol": "http", "external_urls": ["https://gateway.example"]},
                    {"id": "out", "name": "out", "bind_address": "127.0.0.1", "port": 8081,
                        "protocol": "http", "listener_type": "outbound", "external_urls": ["https://outbound.example"]}
                ],
                "routes": {"identity": {"type": "identity_api", "prefix": "/api"}},
                "sts": {"mcp_issuer": {"issuer": "https://gateway.example/api/oauth2/mcp"}}
            }))
            .unwrap(),
        );
        state.vc_issuer = Some(issuer.clone());
        state.credential_provider_store = Some(providers);
        state.consent_identity_strategies = Some(strategies);
        state.delegation_vault_store = Some(vault.clone());
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        let runtime = negative_cases::continuation_runtime(now, 300);
        state.mcp_continuations = Some(runtime.clone());
        let resource = "https://outbound.example/outbound/mcp/partner-a";
        let caller_claims = json!({"iss": "https://gateway.example/api/oauth2/mcp", "sub": "user",
            "aud": resource, "scope": "read", "exp": now + 300});
        let bearer = issuer
            .sign_jwt_with_gateway_key_typ(&caller_claims, "at+jwt")
            .await
            .unwrap();
        let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "transit-consent", "name": "Transit consent",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
            "target": {"endpoint": "https://managed.example/agent"},
            "transit": {"outbound_listen_address": "https://outbound.example", "points": [{
                "alias": "partner-a", "protocol": "mcp", "target_endpoint": format!("http://{target_address}/json"),
                "mcp_http": {"authorization": {"resource": resource, "scopes": ["read"]}}
            }]},
            "outbound_credentials": [{"credential_provider_id": "provider", "scopes": ["read"]}]
        }))
        .unwrap();
        let context_for = |message: &serde_json::Value, surface: &crate::config::agent_surface::AgentSurface| {
            let mut ctx = modern_pipeline_context("tools/call");
            ctx.surface = Arc::new(surface.clone());
            ctx.virtual_channel = surface
                .transit
                .as_ref()
                .unwrap()
                .points[0]
                .clone();
            ctx.request_path = "/outbound/mcp/partner-a".into();
            ctx.original_headers.insert(
                "authorization",
                format!("Bearer {bearer}")
                    .parse()
                    .unwrap(),
            );
            ctx.original_headers.insert(
                "content-type",
                "application/json"
                    .parse()
                    .unwrap(),
            );
            ctx.original_headers.insert(
                "accept",
                "application/json, text/event-stream"
                    .parse()
                    .unwrap(),
            );
            ctx.original_headers.insert(
                "mcp-protocol-version",
                crate::mcp::MCP_MODERN_VERSION
                    .parse()
                    .unwrap(),
            );
            ctx.original_headers
                .insert("mcp-method", "tools/call".parse().unwrap());
            ctx.original_headers
                .insert("mcp-name", "echo".parse().unwrap());
            ctx.original_headers
                .insert("mcp-param-region", "eu".parse().unwrap());
            let body = serde_json::to_vec(message).unwrap();
            let classification = crate::mcp::request_validation::validate_mcp_post(
                &ctx.original_headers,
                &body,
                crate::mcp::request_validation::LegacySessionEvidence::Absent,
                crate::mcp::request_validation::MODERN_ONLY_POLICY,
            )
            .unwrap();
            ctx.mcp_metadata_context = crate::mcp::meta::McpMetadataContext::from_classification(&classification, None);
            ctx.mcp_classification = Some(classification);
            ctx.body_bytes = Some(body.into());
            ctx.resolved_identity = ProtectedAgentIdentity::Managed {
                did: "did:web:agent.example".into(),
                identity_fields: HashMap::new(),
            };
            ctx
        };
        let mut message = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "echo", "_meta": {"io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"url": {}}}}
        }});
        let mut ctx = context_for(&message, &surface);
        let missing = step_prepare_modern_credentials(&state, &mut ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);
        step_source_auth(&state, &mut ctx)
            .await
            .unwrap();
        assert!(
            !ctx.original_headers
                .contains_key("authorization")
        );
        assert_eq!(
            ctx.mcp_resource_authorization
                .as_ref()
                .unwrap()
                .resource,
            resource
        );
        let response = step_prepare_modern_credentials(&state, &mut ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["result"]["resultType"], "input_required");
        {
            async fn prepare(
                state: &OutboundProxyState,
                mut ctx: OutboundPipelineContext,
            ) -> (StatusCode, serde_json::Value) {
                // As in the flow below: the first pass asks for resource
                // authorization, which source authentication then supplies.
                let _ = step_prepare_modern_credentials(state, &mut ctx).await;
                step_source_auth(state, &mut ctx)
                    .await
                    .unwrap();
                let response = step_prepare_modern_credentials(state, &mut ctx)
                    .await
                    .unwrap()
                    .expect("the credential step answers without forwarding");
                let status = response.status();
                let body = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 16384)
                        .await
                        .unwrap(),
                )
                .unwrap();
                (status, body)
            }
            let send = |message: serde_json::Value, bearer: Option<String>, runtime: Arc<ContinuationRuntime>| {
                let mut state = state.clone();
                state.mcp_continuations = Some(runtime);
                let mut ctx = context_for(&message, &surface);
                if let Some(bearer) = bearer {
                    ctx.original_headers.insert(
                        "authorization",
                        format!("Bearer {bearer}")
                            .parse()
                            .unwrap(),
                    );
                }
                async move { prepare(&state, ctx).await }
            };
            let mut other_claims = caller_claims.clone();
            other_claims["sub"] = json!("other-user");
            let other = issuer
                .sign_jwt_with_gateway_key_typ(&other_claims, "at+jwt")
                .await
                .unwrap();
            let issued_state =
                negative_cases::assert_rejected_retries(&message, runtime.clone(), other, now, send).await;

            // It is bound to the Transit Point that issued it: another Transit
            // Point, reached with a token for its own resource, cannot resume it.
            let resource_b = "https://outbound.example/outbound/mcp/partner-b";
            let mut surface_b = serde_json::to_value(&surface).unwrap();
            surface_b["transit"]["points"][0]["alias"] = json!("partner-b");
            surface_b["transit"]["points"][0]["mcp_http"]["authorization"]["resource"] = json!(resource_b);
            let surface_b: crate::config::agent_surface::AgentSurface = serde_json::from_value(surface_b).unwrap();
            let mut claims_b = caller_claims.clone();
            claims_b["aud"] = json!(resource_b);
            let bearer_b = issuer
                .sign_jwt_with_gateway_key_typ(&claims_b, "at+jwt")
                .await
                .unwrap();
            let cross_route = negative_cases::retry(&message, "cross-route", Some(&issued_state));
            let mut cross_route = context_for(&cross_route, &surface_b);
            cross_route.request_path = "/outbound/mcp/partner-b".into();
            cross_route
                .original_headers
                .insert(
                    "authorization",
                    format!("Bearer {bearer_b}")
                        .parse()
                        .unwrap(),
                );
            let (status, body) = prepare(&state, cross_route).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "cross-route: {body}");
            assert_eq!(body["error"]["code"], -32001, "cross-route: {body}");
            assert!(calls.lock().await.is_empty(), "no negative case reaches the upstream");
        }
        let mut retry = match ctx
            .mcp_classification
            .clone()
            .unwrap()
        {
            crate::mcp::request_validation::McpRequestClassification::Modern(request) => *request,
            _ => unreachable!(),
        };
        retry.id = Some(json!(2));
        let bound = runtime
            .service
            .request_binding(
                response["result"]["requestState"]
                    .as_str()
                    .unwrap(),
                &retry,
                now,
            )
            .unwrap();
        assert!(bound.route == ContinuationRoute::TransitPoint { alias: "partner-a".into() });
        assert_eq!(bound.resource, resource);
        assert!(calls.lock().await.is_empty());
        let token = serde_json::from_value(json!({
            "id": "verified-token", "agent_did": "did:web:agent.example", "user_identity_hash": bound.user_identity_hash,
            "credential_provider_id": "provider", "provider_id": "provider", "access_token": "verified-transit-credential", "scopes": ["read"],
            "consent_granted_at": "2026-09-01T00:00:00Z", "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z",
            "consent_identity": {"principal": bound.principal,
                "provider_digest": crate::mcp::continuations::delegation::provider_digest(&provider).unwrap(),
                "strategy_digest": crate::mcp::continuations::delegation::identity_strategy_digest(&strategy).unwrap()}
        })).unwrap();
        vault
            .store(token)
            .await
            .unwrap();
        for format in ["json", "sse"] {
            surface
                .transit
                .as_mut()
                .unwrap()
                .points[0]
                .target_endpoint = format!("http://{target_address}/{format}");
            message["id"] = json!(10);
            message["params"]
                .as_object_mut()
                .unwrap()
                .remove("requestState");
            message["params"]
                .as_object_mut()
                .unwrap()
                .remove("inputResponses");
            let before = calls.lock().await.len();
            for round in 0..2 {
                let mut ctx = context_for(&message, &surface);
                step_source_auth(&state, &mut ctx)
                    .await
                    .unwrap();
                assert!(
                    step_prepare_modern_credentials(&state, &mut ctx)
                        .await
                        .unwrap()
                        .is_none()
                );
                step_inject_credentials(&state, &mut ctx)
                    .await
                    .unwrap();
                let upstream = step_forward_request(&state, &mut ctx)
                    .await
                    .unwrap();
                let response = process_modern_outbound_response(state.clone(), ctx, upstream)
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap();
                let response: serde_json::Value = if format == "json" {
                    serde_json::from_slice(&bytes).unwrap()
                } else {
                    let events: Vec<_> = crate::mcp::modern_sse::decode_events(
                        futures::stream::iter([Ok::<_, std::io::Error>(bytes)]),
                        crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default()),
                    )
                    .try_collect()
                    .await
                    .unwrap();
                    serde_json::from_str(&events.last().unwrap().data).unwrap()
                };
                if round == 0 {
                    assert_eq!(response["result"]["resultType"], "input_required");
                    assert_ne!(response["result"]["requestState"], "transit opaque upstream state");
                    message["id"] = json!(11);
                    message["params"]["requestState"] = response["result"]["requestState"].clone();
                    message["params"]["inputResponses"] =
                        json!({"upstream": {"action": "accept"}, "ignored": {"action": "cancel"}});
                } else {
                    assert_eq!(response["result"]["resultType"], "complete");
                }
            }
            let mut replay = context_for(&message, &surface);
            step_source_auth(&state, &mut replay)
                .await
                .unwrap();
            assert_eq!(
                step_prepare_modern_credentials(&state, &mut replay)
                    .await
                    .unwrap()
                    .unwrap()
                    .status(),
                StatusCode::CONFLICT
            );
            let observed = calls.lock().await;
            assert_eq!(observed.len(), before + 2);
            for (headers, _) in &observed[before..] {
                assert_eq!(
                    headers
                        .get_all("authorization")
                        .iter()
                        .count(),
                    1
                );
                assert_eq!(headers["authorization"], "Bearer verified-transit-credential");
                // Transit Points are transparent for the modern routing headers.
                for (name, value) in [
                    ("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION),
                    ("mcp-method", "tools/call"),
                    ("mcp-name", "echo"),
                    ("mcp-param-region", "eu"),
                ] {
                    assert_eq!(headers[name], value, "{name} reaches the upstream");
                }
                assert!(!headers.contains_key("mcp-session-id"));
            }
            assert_eq!(observed[before + 1].1["params"]["requestState"], "transit opaque upstream state");
            assert_eq!(observed[before + 1].1["params"]["inputResponses"], json!({"upstream": {"action": "accept"}}));
        }
        use futures::StreamExt;
        let (subscriptions_tx, mut subscriptions_rx) = tokio::sync::mpsc::channel(2);
        let subscription_target = axum::Router::new().fallback(axum::routing::post(
            move |headers: HeaderMap, axum::Json(request): axum::Json<serde_json::Value>| {
                let subscriptions = subscriptions_tx.clone();
                async move {
                    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
                    let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
                    let ack = json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": {
                        "_meta": {"io.modelcontextprotocol/subscriptionId": request["id"]},
                        "notifications": request["params"]["notifications"]
                    }});
                    sender
                        .send(Ok(Bytes::from(format!("data: {ack}\n\n"))))
                        .await
                        .unwrap();
                    subscriptions
                        .send((headers, request, sender, outcome_rx))
                        .await
                        .unwrap();
                    let response = Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver)))
                        .unwrap();
                    crate::mcp::modern_sse::observe_response(response, move |outcome| {
                        let _ = outcome_tx.send(outcome);
                    })
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let subscription_address = listener.local_addr().unwrap();
        tasks.spawn(async move {
            axum::serve(listener, subscription_target)
                .await
                .unwrap();
        });
        let mut agent =
            crate::identity::test_helpers::test_surface_identity_record("did:web:agent.example", &surface.surface_id);
        agent.private_key = Some(serde_json::to_value(ssi::jwk::JWK::generate_ed25519().unwrap()).unwrap());
        issuer
            .get_identity_store()
            .create(agent)
            .await
            .unwrap();
        let point = &mut surface
            .transit
            .as_mut()
            .unwrap()
            .points[0];
        point.target_endpoint = format!("http://{subscription_address}/mcp");
        point.managed_identity =
            Some(serde_json::from_value(json!({"type": "static", "did": "did:web:agent.example"})).unwrap());
        point
            .identity_injection
            .inject_vp = false;
        point.require_transit_token = false;
        state
            .channel_state
            .write()
            .unwrap()
            .surface = Arc::new(surface.clone());
        state.vc_alias_override = None;
        let subscription = json!({"jsonrpc": "2.0", "id": "transit-subscription", "method": "subscriptions/listen", "params": {
            "notifications": {"toolsListChanged": true}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }});
        let subscription_request = || {
            Request::builder()
                .method("POST")
                .uri(resource)
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                .header("mcp-method", "subscriptions/listen")
                .header("mcp-session-id", "unused-transit-session")
                .body(axum::body::Body::from(serde_json::to_vec(&subscription).unwrap()))
                .unwrap()
        };
        let address = "127.0.0.1:12345"
            .parse()
            .unwrap();
        let versions = crate::mcp::request_validation::MODERN_CAPABLE_POLICY;
        assert!(
            subscriptions_rx
                .try_recv()
                .is_err()
        );
        for invalid in ["missing", "audience", "scope", "expired"] {
            let mut request = subscription_request();
            if invalid == "missing" {
                request
                    .headers_mut()
                    .remove("authorization");
            } else {
                let claims = json!({"iss": "https://gateway.example/api/oauth2/mcp", "sub": "user",
                    "aud": if invalid == "audience" { "https://gateway.example/mcp" } else { resource },
                    "scope": if invalid == "scope" { "write" } else { "read" },
                    "exp": if invalid == "expired" { now - 1 } else { now + 300 }
                });
                let token = issuer
                    .sign_jwt_with_gateway_key_typ(&claims, "at+jwt")
                    .await
                    .unwrap();
                request.headers_mut().insert(
                    "authorization",
                    format!("Bearer {token}")
                        .parse()
                        .unwrap(),
                );
            }
            let response =
                Box::pin(outbound_proxy_handler_with_mcp_versions(address, state.clone(), request, versions))
                    .await
                    .unwrap_or_else(|error| error.into_response());
            assert_eq!(
                response.status(),
                if invalid == "scope" {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::UNAUTHORIZED
                },
                "{invalid}"
            );
            assert!(
                response
                    .headers()
                    .contains_key("www-authenticate")
            );
            assert!(
                subscriptions_rx
                    .try_recv()
                    .is_err(),
                "invalid {invalid} reached the Transit Target"
            );
        }
        let transit_issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            crate::proxy::transit_token::TransitTokenKey::generate().unwrap(),
            "gateway".into(),
        );
        state.transit_token_issuer = Some(Arc::new(transit_issuer.clone()));
        surface
            .transit
            .as_mut()
            .unwrap()
            .points[0]
            .require_transit_token = true;
        let mut variant_point = surface
            .transit
            .as_ref()
            .unwrap()
            .points[0]
            .clone();
        variant_point.target_endpoint = format!("http://{subscription_address}/variant");
        surface.variants.push(
            serde_json::from_value(json!({
                "id": "candidate", "alias": "candidate", "name": "Candidate",
                "overrides": {"transit": {"points": [variant_point]}}
            }))
            .unwrap(),
        );
        state
            .channel_state
            .write()
            .unwrap()
            .surface = Arc::new(surface.clone());
        for invalid in ["missing", "surface", "point", "expired", "duplicate", "missing-issuer"] {
            let mut request = subscription_request();
            let token = transit_issuer
                .issue_with_caller_context(
                    if invalid == "surface" {
                        "different-surface"
                    } else {
                        &surface.surface_id
                    },
                    None,
                    None,
                    None,
                    None,
                    None,
                    vec![if invalid == "point" {
                        "partner-b".into()
                    } else {
                        "partner-a".into()
                    }],
                    serde_json::Map::new(),
                    300,
                )
                .unwrap();
            let token = if invalid == "expired" {
                let mut claims = transit_issuer
                    .validate(&token, 300)
                    .unwrap();
                claims.iat -= 600;
                claims.exp -= 600;
                transit_issuer
                    .sign(&claims)
                    .unwrap()
            } else {
                token
            };
            if invalid != "missing" {
                request
                    .headers_mut()
                    .insert("x-transit-token", token.parse().unwrap());
            }
            if invalid == "duplicate" {
                request
                    .headers_mut()
                    .append("x-transit-token", token.parse().unwrap());
            }
            let mut request_state = state.clone();
            if invalid == "missing-issuer" {
                request_state.transit_token_issuer = None;
            }
            let response =
                Box::pin(outbound_proxy_handler_with_mcp_versions(address, request_state, request, versions))
                    .await
                    .unwrap_or_else(|error| error.into_response());
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Transit token {invalid}");
            assert!(
                subscriptions_rx
                    .try_recv()
                    .is_err(),
                "Transit token {invalid} reached the Target"
            );
        }
        for termination in ["variant", "custom-variant", "encoded-custom-variant", "transit-expiry", "vault"] {
            let custom = termination.contains("custom");
            let named_variant = termination.ends_with("variant");
            let mut request_state = state.clone();
            let variant_resource = if custom {
                "https://outbound.example/custom/mcp$candidate"
            } else {
                "https://outbound.example/outbound/mcp$candidate/partner-a"
            };
            let variant_uri = if termination == "encoded-custom-variant" {
                "https://outbound.example/custom/mcp%24candidate"
            } else {
                variant_resource
            };
            if custom {
                let mut custom_surface = surface.clone();
                let mut custom_point = custom_surface
                    .transit
                    .as_ref()
                    .unwrap()
                    .points[0]
                    .clone();
                custom_point.listen_path = Some("/custom/mcp".into());
                custom_point
                    .mcp_http
                    .as_mut()
                    .unwrap()
                    .authorization
                    .as_mut()
                    .unwrap()
                    .resource = "https://outbound.example/custom/mcp".into();
                custom_surface
                    .transit
                    .as_mut()
                    .unwrap()
                    .points[0] = custom_point.clone();
                custom_point.target_endpoint = variant_point
                    .target_endpoint
                    .clone();
                custom_surface.variants[0] = serde_json::from_value(json!({
                    "id": "candidate", "alias": "candidate", "name": "Candidate",
                    "overrides": {"transit": {"points": [custom_point]}}
                }))
                .unwrap();
                request_state.channel_state = Arc::new(std::sync::RwLock::new(crate::state::OutboundSurfaceState {
                    surface: Arc::new(custom_surface),
                    ..state
                        .channel_state
                        .read()
                        .unwrap()
                        .clone()
                }));
                request_state.vc_alias_override = Some("partner-a".into());
            }
            if named_variant {
                let path = url::Url::parse(variant_resource)
                    .unwrap()
                    .path()
                    .to_string();
                let metadata = crate::mcp::resource_server::transit_metadata(
                    State(crate::mcp::resource_server::TransitMetadataState {
                        network: request_state
                            .network_config
                            .clone(),
                        surfaces: vec![
                            request_state
                                .channel_state
                                .clone(),
                        ],
                        port: 8081,
                    }),
                    axum::extract::OriginalUri(
                        format!("/.well-known/oauth-protected-resource{path}")
                            .parse()
                            .unwrap(),
                    ),
                )
                .await;
                assert_eq!(metadata.status(), StatusCode::OK, "metadata for {termination}");
                assert_eq!(metadata.headers()["cache-control"], "no-store");
                let metadata: serde_json::Value = serde_json::from_slice(
                    &axum::body::to_bytes(metadata.into_body(), 16384)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(metadata["resource"], variant_resource);
                assert_eq!(metadata["scopes_supported"], json!(["read"]));
            }
            let token = transit_issuer
                .issue_with_caller_context(
                    &surface.surface_id,
                    None,
                    None,
                    None,
                    None,
                    None,
                    vec!["partner-a".into()],
                    serde_json::Map::new(),
                    300,
                )
                .unwrap();
            // The shortest lifetime the issuer allows is 30 seconds, so back-date a
            // token to leave it three seconds.
            let token = if termination == "transit-expiry" {
                let mut claims = transit_issuer
                    .validate(&token, 300)
                    .unwrap();
                claims.iat -= 297;
                claims.exp -= 297;
                transit_issuer
                    .sign(&claims)
                    .unwrap()
            } else {
                token
            };
            let mut authenticated_request = subscription_request();
            authenticated_request
                .headers_mut()
                .insert("x-transit-token", token.parse().unwrap());
            if named_variant {
                *authenticated_request.uri_mut() = variant_uri.parse().unwrap();
                if custom {
                    let custom_bearer = issuer
                        .sign_jwt_with_gateway_key_typ(
                            &json!({
                                "iss": "https://gateway.example/api/oauth2/mcp", "sub": "user", "scope": "read",
                                "aud": "https://outbound.example/custom/mcp", "exp": now + 300
                            }),
                            "at+jwt",
                        )
                        .await
                        .unwrap();
                    authenticated_request
                        .headers_mut()
                        .insert(
                            "authorization",
                            format!("Bearer {custom_bearer}")
                                .parse()
                                .unwrap(),
                        );
                }
                let denied = Box::pin(outbound_proxy_handler_with_mcp_versions(
                    address,
                    request_state.clone(),
                    authenticated_request,
                    versions,
                ))
                .await
                .unwrap_or_else(|error| error.into_response());
                assert_eq!(denied.status(), StatusCode::UNAUTHORIZED, "base audience for {termination}");
                let metadata_path = url::Url::parse(variant_resource)
                    .unwrap()
                    .path()
                    .to_string();
                assert!(
                    denied.headers()["www-authenticate"]
                        .to_str()
                        .unwrap()
                        .contains(&format!(
                            "https://outbound.example/.well-known/oauth-protected-resource{metadata_path}"
                        ))
                );
                assert!(
                    subscriptions_rx
                        .try_recv()
                        .is_err(),
                    "base audience reached the variant Target"
                );
                let variant_bearer = issuer
                    .sign_jwt_with_gateway_key_typ(
                        &json!({
                            "iss": "https://gateway.example/api/oauth2/mcp", "sub": "user", "scope": "read",
                            "aud": variant_resource, "exp": now + 300
                        }),
                        "at+jwt",
                    )
                    .await
                    .unwrap();
                authenticated_request = subscription_request();
                *authenticated_request.uri_mut() = variant_uri.parse().unwrap();
                authenticated_request
                    .headers_mut()
                    .insert(
                        "authorization",
                        format!("Bearer {variant_bearer}")
                            .parse()
                            .unwrap(),
                    );
                authenticated_request
                    .headers_mut()
                    .insert("x-transit-token", token.parse().unwrap());
                let mut context_request = subscription_request();
                *context_request.uri_mut() = variant_uri.parse().unwrap();
                let context = OutboundPipelineContext::new(
                    address,
                    context_request,
                    &request_state,
                    crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
                )
                .unwrap();
                assert_eq!(
                    context
                        .active_variant_id
                        .as_deref(),
                    Some("candidate")
                );
                assert_eq!(
                    context
                        .active_variant_alias
                        .as_deref(),
                    Some("candidate")
                );
                assert!(
                    context
                        .surface
                        .variants
                        .is_empty()
                );
                assert_eq!(
                    context
                        .virtual_channel
                        .target_endpoint,
                    variant_point.target_endpoint
                );
            }
            let response = Box::pin(outbound_proxy_handler_with_mcp_versions(
                address,
                request_state.clone(),
                authenticated_request,
                versions,
            ))
            .await
            .expect("authorized Transit subscription pipeline");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(
                !response
                    .headers()
                    .contains_key("mcp-session-id")
            );
            let (headers, request, sender, outcome) = subscriptions_rx
                .recv()
                .await
                .unwrap();
            assert_eq!(headers["authorization"], "Bearer verified-transit-credential");
            assert!(!headers.contains_key("mcp-session-id"));
            assert_eq!(request["id"], subscription["id"]);
            assert_eq!(request["method"], "subscriptions/listen");
            let limits = crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
            let mut events = Box::pin(crate::mcp::modern_sse::decode_events(
                response
                    .into_body()
                    .into_data_stream(),
                limits,
            ));
            let ack = tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let ack: serde_json::Value = serde_json::from_str(&ack.data).unwrap();
            assert_eq!(ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], subscription["id"]);
            assert_eq!(ack["params"]["notifications"], json!({"toolsListChanged": true}));
            let active = vault
                .list_all()
                .await
                .unwrap()
                .into_iter()
                .find(|token| token.provider_id == "provider")
                .unwrap();
            assert!(futures::poll!(events.next()).is_pending());
            assert!(!sender.is_closed());
            // A change notification from the upstream reaches the client with
            // its subscription tag.
            let changed = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {
                "_meta": {"io.modelcontextprotocol/subscriptionId": subscription["id"]}
            }});
            sender
                .send(Ok(bytes::Bytes::from(format!("data: {changed}\n\n"))))
                .await
                .unwrap();
            let relayed = tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let relayed: serde_json::Value = serde_json::from_str(&relayed.data).unwrap();
            assert_eq!(relayed["method"], "notifications/tools/list_changed");
            assert_eq!(relayed["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], subscription["id"]);
            if named_variant {
                drop(events);
                assert!(
                    !tokio::time::timeout(std::time::Duration::from_secs(2), outcome)
                        .await
                        .unwrap()
                        .unwrap()
                        .completed
                );
                assert!(sender.is_closed());
                continue;
            }
            if termination == "vault" {
                assert!(
                    vault
                        .delete(&active.id)
                        .await
                        .unwrap()
                );
            }
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(5), events.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            drop(events);
            assert!(
                !tokio::time::timeout(std::time::Duration::from_secs(2), outcome)
                    .await
                    .unwrap()
                    .unwrap()
                    .completed
            );
            assert!(sender.is_closed());
            let mut reconnect = subscription_request();
            reconnect
                .headers_mut()
                .insert("x-transit-token", token.parse().unwrap());
            let response =
                Box::pin(outbound_proxy_handler_with_mcp_versions(address, state.clone(), reconnect, versions))
                    .await
                    .unwrap_or_else(|error| error.into_response());
            assert_eq!(
                response.status(),
                if termination == "vault" {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::UNAUTHORIZED
                }
            );
            assert!(
                subscriptions_rx
                    .try_recv()
                    .is_err(),
                "{termination} reconnect reached the Transit Target"
            );
        }
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn modern_outbound_notifications_preserve_empty_acceptance_and_idless_errors() {
        use crate::mcp::request_validation::{McpMessageKind, McpRequestClassification};

        for fabric in [false, true] {
            for reject in [false, true] {
                let mut context = modern_pipeline_context("tools/list");
                let Some(McpRequestClassification::Modern(request)) = context
                    .mcp_classification
                    .as_mut()
                else {
                    panic!("expected an admitted modern fixture");
                };
                request.kind = McpMessageKind::Notification;
                request.id = None;
                request.method = "notifications/com.example/changed".into();
                request.client_capabilities = None;
                request.params = Some(json!({"revision": 1}));
                let status = if reject {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::ACCEPTED
                };
                let bytes = if reject {
                    Bytes::from_static(br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Unknown notification"}}"#)
                } else {
                    Bytes::new()
                };
                let upstream = axum::http::Response::builder()
                    .status(status)
                    .header("mcp-session-id", "unused-session")
                    .header("x-upstream", "retained");
                let upstream = if fabric {
                    UpstreamResponse::FabricStream(
                        upstream
                            .body(axum::body::Body::from(bytes.clone()))
                            .unwrap(),
                    )
                } else {
                    UpstreamResponse::Http(reqwest::Response::from(
                        upstream
                            .body(reqwest::Body::from(bytes.clone()))
                            .unwrap(),
                    ))
                };
                let response = process_modern_outbound_response(test_outbound_state(), context, upstream)
                    .await
                    .unwrap();
                assert_eq!(response.status(), status);
                assert_eq!(response.headers()["x-upstream"], "retained");
                assert_eq!(response.headers()["cache-control"], "no-store");
                assert!(
                    !response
                        .headers()
                        .contains_key("mcp-session-id")
                );
                assert_eq!(
                    response
                        .headers()
                        .contains_key("content-type"),
                    reject
                );
                assert_eq!(
                    axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap(),
                    bytes
                );
            }
        }
    }

    #[tokio::test]
    async fn modern_outbound_response_processes_fabric_bytes_without_buffering_progress() {
        use http_body_util::BodyExt;
        for complete in [false, true] {
            let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
            let mut upstream =
                Response::new(axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver)));
            upstream.headers_mut().insert(
                "content-type",
                "text/event-stream"
                    .parse()
                    .unwrap(),
            );
            upstream
                .headers_mut()
                .append("x-repeated", "first".parse().unwrap());
            upstream
                .headers_mut()
                .append("x-repeated", "second".parse().unwrap());
            let response = process_modern_outbound_response(
                test_outbound_state(),
                modern_pipeline_context("tools/call"),
                UpstreamResponse::FabricStream(upstream),
            )
            .await
            .unwrap();
            assert_eq!(
                response
                    .headers()
                    .get_all("x-repeated")
                    .iter()
                    .count(),
                2
            );
            let mut body = response.into_body();
            sender.send(Ok(Bytes::from(format!("data: {}\n\n", json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "work", "progress": 1}}))))).await.unwrap();
            let progress = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap();
            assert!(
                std::str::from_utf8(&progress)
                    .unwrap()
                    .contains("notifications/progress")
            );
            assert!(!sender.is_closed());
            if complete {
                sender
                    .send(Ok(Bytes::from(format!(
                        "data: {}\n\n",
                        json!({"jsonrpc": "2.0", "id": "stream", "result": {
                            "resultType": "complete", "content": [], "structuredContent": [true, null],
                            "_meta": {crate::config::TRUST_REGISTRY_EXTENSION: {"kept": true}}
                        }})
                    ))))
                    .await
                    .unwrap();
                let final_bytes = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .into_data()
                    .unwrap();
                let text = std::str::from_utf8(&final_bytes).unwrap();
                assert!(text.contains("io.affinidi.fabric/trust-registry"));
                assert!(text.contains("structuredContent"));
            }
            drop(body);
            assert!(sender.is_closed());
        }
    }

    #[tokio::test]
    async fn modern_outbound_response_streams_progress_before_processing_completion() {
        use http_body_util::BodyExt;

        let state = test_outbound_state();
        let ctx = modern_pipeline_context("tools/call");
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
        let upstream = reqwest::Response::from(
            axum::http::Response::builder()
                .header("content-type", "text/event-stream")
                .header("mcp-session-id", "must-not-escape")
                .body(reqwest::Body::wrap_stream(tokio_stream::wrappers::ReceiverStream::new(receiver)))
                .unwrap(),
        );
        let response = process_modern_outbound_response(state, ctx, UpstreamResponse::Http(upstream))
            .await
            .unwrap();
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert!(
            !response
                .headers()
                .contains_key("mcp-session-id")
        );
        let mut stream = response.into_body();
        sender.send(Ok(Bytes::from(format!("data: {}\n\n", json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "work", "progress": 1}}))))).await.unwrap();
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), stream.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert!(
            std::str::from_utf8(&first)
                .unwrap()
                .contains("notifications/progress")
        );
        assert!(!sender.is_closed());
        sender
            .send(Ok(Bytes::from(format!(
                "data: {}\n\n",
                json!({"jsonrpc": "2.0", "id": "stream", "result": {
                    "resultType": "complete", "content": [], "structuredContent": [true, null],
                    "_meta": {crate::config::TRUST_REGISTRY_EXTENSION: {"kept": true}}
                }})
            ))))
            .await
            .unwrap();
        let final_bytes = tokio::time::timeout(std::time::Duration::from_secs(1), stream.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        let final_text = std::str::from_utf8(&final_bytes).unwrap();
        assert!(final_text.contains("io.affinidi.fabric/trust-registry"));
        assert!(!final_text.contains(crate::config::TRUST_REGISTRY_EXTENSION));
        assert!(stream.frame().await.is_none());
        assert!(sender.is_closed());
    }

    #[tokio::test]
    async fn modern_outbound_response_cancels_a_quiet_upstream() {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
        let upstream = reqwest::Response::from(
            axum::http::Response::builder()
                .header("content-type", "text/event-stream")
                .body(reqwest::Body::wrap_stream(tokio_stream::wrappers::ReceiverStream::new(receiver)))
                .unwrap(),
        );
        let response = process_modern_outbound_response(
            test_outbound_state(),
            modern_pipeline_context("tools/call"),
            UpstreamResponse::Http(upstream),
        )
        .await
        .unwrap();
        assert!(!sender.is_closed());
        drop(response);
        assert!(sender.is_closed());
    }

    #[tokio::test]
    async fn modern_outbound_response_policy_failure_never_delivers_a_final_result() {
        for content_type in ["application/json", "text/event-stream"] {
            let mut ctx = modern_pipeline_context("tools/call");
            ctx.virtual_channel
                .response_policy =
                Some(serde_json::from_value(json!({"policy_definition_id": "unavailable-policy"})).unwrap());
            let message =
                json!({"jsonrpc": "2.0", "id": "stream", "result": {"resultType": "complete", "content": []}});
            let payload = if content_type == "application/json" {
                message.to_string()
            } else {
                format!("data: {message}\n\n")
            };
            let upstream = reqwest::Response::from(
                axum::http::Response::builder()
                    .header("content-type", content_type)
                    .body(reqwest::Body::from(payload))
                    .unwrap(),
            );
            let result =
                process_modern_outbound_response(test_outbound_state(), ctx, UpstreamResponse::Http(upstream)).await;
            if content_type == "application/json" {
                assert!(matches!(result, Err(OutboundPipelineError::UpstreamResponseReadFailed)));
            } else {
                let response = result.unwrap();
                assert!(
                    axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .is_err()
                );
            }
        }
    }

    /// An upstream result carrying every preservation field
    /// reaches the managed agent through a Transit Point intact, in JSON and SSE.
    #[tokio::test]
    async fn modern_outbound_response_preserves_every_result_field() {
        use futures::TryStreamExt;

        for fixture in crate::mcp::result_fixtures::result_fixtures() {
            for content_type in ["application/json", "text/event-stream"] {
                let mut ctx = test_pipeline_context();
                ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
                let (body, request_headers) = fixture.request("stream");
                let mut headers = HeaderMap::new();
                for (name, value) in &request_headers {
                    headers.insert(*name, value.parse().unwrap());
                }
                let classification = crate::mcp::request_validation::validate_mcp_post(
                    &headers,
                    &serde_json::to_vec(&body).unwrap(),
                    crate::mcp::request_validation::LegacySessionEvidence::Absent,
                    crate::mcp::request_validation::MODERN_ONLY_POLICY,
                )
                .unwrap();
                ctx.mcp_metadata_context =
                    crate::mcp::meta::McpMetadataContext::from_classification(&classification, None);
                ctx.mcp_classification = Some(classification);
                ctx.body_bytes = Some(Bytes::from(body.to_string()));
                ctx.operation = Some(fixture.method.clone());
                let message = fixture.response("stream");
                let payload = if content_type == "application/json" {
                    message.to_string()
                } else {
                    format!("data: {message}\n\n")
                };
                let upstream = reqwest::Response::from(
                    axum::http::Response::builder()
                        .header("content-type", content_type)
                        .body(reqwest::Body::from(payload))
                        .unwrap(),
                );
                let response =
                    process_modern_outbound_response(test_outbound_state(), ctx, UpstreamResponse::Http(upstream))
                        .await
                        .unwrap_or_else(|error| panic!("{} {content_type}: {error}", fixture.method));
                let bytes = axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap();
                let received: serde_json::Value = if content_type == "application/json" {
                    serde_json::from_slice(&bytes).unwrap()
                } else {
                    let limits = crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
                    let events: Vec<_> = crate::mcp::modern_sse::decode_events(
                        futures::stream::iter([Ok::<_, std::io::Error>(bytes)]),
                        limits,
                    )
                    .try_collect()
                    .await
                    .unwrap();
                    serde_json::from_str(&events.last().unwrap().data).unwrap()
                };
                assert_eq!(received["id"], "stream");
                fixture.assert_preserved(&received["result"], &format!("Transit Point ({content_type})"));
            }
        }
    }

    #[tokio::test]
    async fn modern_outbound_response_filters_tools_and_protects_cache_in_both_formats() {
        use futures::TryStreamExt;

        for content_type in ["application/json", "text/event-stream"] {
            let mut ctx = modern_pipeline_context("tools/list");
            ctx.virtual_channel
                .mcp_tool_gating = Some(
                serde_json::from_value(json!({"gates": [{
                    "id": "deny-admin", "name": "Hide admin", "action": {"effect": "deny", "patterns": ["^admin_"]}
                }]}))
                .unwrap(),
            );
            let surface = Arc::make_mut(&mut ctx.surface);
            surface.surface_id = "modern-tp-gate".to_string();
            surface
                .transit
                .as_mut()
                .unwrap()
                .points = vec![ctx.virtual_channel.clone()];
            let manager = Arc::new(crate::policies::SurfacePolicyManager::new());
            manager
                .update_channel_policy(surface)
                .await
                .unwrap();
            let mut state = test_outbound_state();
            state.policy_manager = Some(manager);
            let visible = json!({"name": "search", "inputSchema": {"type": "object", "$defs": {"shared": {"type": "string"}}, "properties": {"query": {"$ref": "#/$defs/shared"}}}, "title": "Search", "com.example/opaque": [1, null]});
            let message = json!({"jsonrpc": "2.0", "id": "stream", "result": {
                "resultType": "complete", "tools": [visible, {"name": "admin_delete", "inputSchema": {"type": "object"}}],
                "ttlMs": 60000, "cacheScope": "public", "nextCursor": "opaque"
            }});
            let payload = if content_type == "application/json" {
                message.to_string()
            } else {
                format!("data: {message}\n\n")
            };
            let upstream = reqwest::Response::from(
                axum::http::Response::builder()
                    .header("content-type", content_type)
                    .body(reqwest::Body::from(payload))
                    .unwrap(),
            );
            let response = process_modern_outbound_response(state, ctx, UpstreamResponse::Http(upstream))
                .await
                .unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            let bytes = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            let received: serde_json::Value = if content_type == "application/json" {
                serde_json::from_slice(&bytes).unwrap()
            } else {
                let limits = crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
                let events: Vec<_> = crate::mcp::modern_sse::decode_events(
                    futures::stream::iter([Ok::<_, std::io::Error>(bytes)]),
                    limits,
                )
                .try_collect()
                .await
                .unwrap();
                assert_eq!(events.len(), 1);
                serde_json::from_str(&events[0].data).unwrap()
            };
            assert_eq!(received["result"]["tools"], json!([visible]));
            assert_eq!(received["result"]["cacheScope"], "private");
            assert_eq!(received["result"]["ttlMs"], 0);
            assert_eq!(received["result"]["nextCursor"], "opaque");
            assert_eq!(received["id"], "stream");
        }
    }

    #[tokio::test]
    async fn outbound_response_body_preserves_payload_headers_and_legacy_metadata() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        let message = json!({"jsonrpc": "2.0", "id": "response", "result": {
            "content": [{"type": "text", "text": "kept"}], "structuredContent": [false, null],
            "isError": true, "_meta": {crate::config::TRUST_REGISTRY_EXTENSION: {"marker": [1, true]}}
        }});
        let bytes = Bytes::from(serde_json::to_vec(&message).unwrap());
        let byte_count = bytes.len() as u64;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "content-type",
            "application/json"
                .parse()
                .unwrap(),
        );
        headers.insert("content-length", "999".parse().unwrap());
        headers.insert(
            "mcp-session-id",
            "legacy-session"
                .parse()
                .unwrap(),
        );
        headers.append("x-example", "first".parse().unwrap());
        headers.append("x-example", "second".parse().unwrap());
        let response = process_outbound_response_body(
            &state,
            &mut ctx,
            StatusCode::OK,
            headers,
            bytes,
            &crate::policies::PolicyAttestation::default(),
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["mcp-session-id"], "legacy-session");
        assert_eq!(
            response
                .headers()
                .get_all("x-example")
                .iter()
                .count(),
            2
        );
        assert!(
            !response
                .headers()
                .contains_key("content-length")
        );
        assert_eq!(ctx.response_bytes, Some(byte_count));
        let received: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(received, message);
    }

    #[tokio::test]
    async fn transit_tool_gating_denies_gated_tools_call_with_or_without_id() {
        let manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "cfg-tp-gate-call",
            "name": "tp-gate-call",
            "description": "",
            "status": "active",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/surfaces/order",
                "protocol": "mcp"
            },
            "target": { "endpoint": "http://localhost:9000" },
            "transit": {
                "points": [{
                    "alias": "partner-mcp",
                    "target_endpoint": "https://partner.example.com/mcp",
                    "protocol": "mcp",
                    "mcp_tool_gating": {
                        "gates": [{
                            "id": "g1",
                            "name": "no admin",
                            "action": { "effect": "deny", "patterns": ["^admin_"] }
                        }]
                    }
                }]
            }
        }))
        .expect("surface json");
        manager
            .update_channel_policy(&surface)
            .await
            .unwrap();
        let mut state = test_outbound_state();
        state.policy_manager = Some(manager);
        let surface = Arc::new(surface);

        for (body, denied) in [
            (json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "admin_reset"}}), true),
            (json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "admin_reset"}}), true),
            (json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_orders"}}), false),
            (json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {}}), true),
            (json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call"}), true),
            (json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": 42}}), true),
            (
                json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": {"value": "admin_reset"}}}),
                true,
            ),
        ] {
            let mut ctx = test_pipeline_context();
            ctx.surface = surface.clone();
            ctx.virtual_channel = serde_json::from_value(json!({
                "alias": "partner-mcp",
                "target_endpoint": "https://partner.example.com/mcp",
                "protocol": "mcp"
            }))
            .expect("transit point json");
            ctx.operation = Some("tools/call".to_string());
            ctx.body_bytes = Some(Bytes::from(serde_json::to_vec(&body).unwrap()));

            let result = step_transit_mcp_tool_gating(&state, &mut ctx).await;

            assert_eq!(matches!(result, Err(OutboundPipelineError::TransitMcpToolGated)), denied, "{body}: {result:?}");
            assert!(denied || result.is_ok(), "{body}: {result:?}");
        }
    }

    #[tokio::test]
    async fn filter_transit_mcp_tools_list_fails_closed_for_unparseable_gated_response() {
        let manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "cfg-tp-gate",
            "name": "tp-gate",
            "description": "",
            "status": "active",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/surfaces/order",
                "protocol": "mcp"
            },
            "target": { "endpoint": "http://localhost:9000" },
            "transit": {
                "points": [{
                    "alias": "partner-mcp",
                    "target_endpoint": "https://partner.example.com/mcp",
                    "protocol": "mcp",
                    "mcp_tool_gating": {
                        "gates": [{
                            "id": "g1",
                            "name": "no admin",
                            "action": { "effect": "deny", "patterns": ["^admin_"] }
                        }]
                    }
                }]
            }
        }))
        .expect("surface json");

        manager
            .update_channel_policy(&surface)
            .await
            .unwrap();

        let mut state = test_outbound_state();
        state.policy_manager = Some(manager);

        let mut ctx = test_pipeline_context();
        ctx.surface = Arc::new(surface);
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "partner-mcp",
            "target_endpoint": "https://partner.example.com/mcp",
            "protocol": "mcp"
        }))
        .expect("transit point json");
        ctx.operation = Some("tools/list".to_string());

        let filtered = filter_transit_mcp_tools_list(&state, &ctx, Bytes::from_static(b"not-json-or-sse"));

        assert_eq!(filtered, Bytes::from_static(br#"{"jsonrpc":"2.0","id":null,"result":{"tools":[]}}"#));

        ctx.operation = Some("tools/call".to_string());
        let raw_body = Bytes::from_static(b"not-json-or-sse");
        let unchanged = filter_transit_mcp_tools_list(&state, &ctx, raw_body.clone());

        assert_eq!(unchanged, raw_body);
    }

    #[tokio::test]
    async fn transit_tool_scoped_binding_never_applies() {
        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
        use crate::secrets::SecretsStore;

        let directory = tempfile::tempdir().unwrap();
        let providers = Arc::new(
            FileSystemCredentialProviderStore::new(
                directory
                    .path()
                    .join("providers"),
            )
            .await
            .unwrap(),
        );
        providers
            .create(
                serde_json::from_value(json!({
                    "id": "provider", "name": "Provider", "provider_id": "provider",
                    "authorization_endpoint": "https://provider.example/authorize",
                    "client_id_secret_ref": "provider-client-id",
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let vault = Arc::new(
            FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        vault
            .store(
                serde_json::from_value(json!({
                    "id": "token", "agent_did": "did:web:caller.example", "user_identity_hash": "user-hash",
                    "credential_provider_id": "provider", "provider_id": "provider",
                    "access_token": "tool-scoped-credential", "token_type": "bearer", "scopes": [],
                    "consent_granted_at": "2026-09-01T00:00:00Z",
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let secrets = crate::secrets::FilesystemSecretsStore::new_async(
            directory
                .path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        secrets
            .create(
                serde_json::from_value(json!({
                    "name": "Provider client id", "secret_id": "provider-client-id", "value": "client-id"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let mut state = test_outbound_state();
        state.credential_provider_store = Some(providers);
        state.delegation_vault_store = Some(vault.clone());
        state.secrets_store = Some(Arc::new(secrets));
        state.gateway_base_url = Some("https://gateway.example".to_string());

        let mut surface = test_surface();
        surface.outbound_credentials = vec![
            serde_json::from_value(json!({
                "credential_provider_id": "provider",
                "required_for": {"tools": ["get_current_date_time"]}
            }))
            .unwrap(),
        ];
        let mut all_surface = surface.clone();
        all_surface.outbound_credentials[0].required_for = crate::config::types::CredentialRequirement::All;
        let surface = Arc::new(surface);
        let all_surface = Arc::new(all_surface);
        let claims: crate::proxy::transit_token::TransitTokenClaims = serde_json::from_value(json!({
            "iss": "gateway", "sub": "did:web:caller.example", "surface_id": "surface",
            "iat": 0, "exp": 0, "jti": "jti", "user_identity_hash": "user-hash"
        }))
        .unwrap();

        // A partner upstream names its own tools, so a binding scoped to a tool
        // name is never sent to it, even for a listed tool or a JSON-RPC method.
        // An `all` binding still is.
        for (surface, body, expected) in [
            (
                &surface,
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_current_date_time"}}),
                None,
            ),
            (
                &surface,
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "other_tool"}}),
                None,
            ),
            (&surface, json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}), None),
            (
                &all_surface,
                json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_current_date_time"}}),
                Some("Bearer tool-scoped-credential"),
            ),
        ] {
            let mut ctx = test_pipeline_context();
            ctx.surface = surface.clone();
            ctx.protocol = Some(ChannelProtocol::Mcp);
            ctx.operation = body["method"]
                .as_str()
                .map(str::to_string);
            ctx.body_bytes = Some(Bytes::from(serde_json::to_vec(&body).unwrap()));
            ctx.transit_token_claims = Some(claims.clone());

            step_inject_credentials(&state, &mut ctx)
                .await
                .unwrap_or_else(|error| panic!("{body}: {error:?}"));

            assert_eq!(
                ctx.delegated_credential_headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok()),
                expected,
                "{body}"
            );
        }

        // Modern MCP: the prepared delegation claims every binding on the
        // surface, so the legacy step never injects a tool-scoped credential.
        let mut ctx = test_pipeline_context();
        ctx.surface = surface.clone();
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx.operation = Some("tools/call".to_string());
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(
                &json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "get_current_date_time"}}),
            )
            .unwrap(),
        ));
        ctx.transit_token_claims = Some(claims.clone());
        ctx.modern_delegation =
            Some(Box::new(crate::proxy::credential_delegation::modern::PreparedDelegation::handling(
                crate::mcp::request_validation::ValidatedModernMessage {
                    protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
                    client_capabilities: None,
                    client_info: None,
                    method: "tools/call".into(),
                    id: Some(json!(5)),
                    kind: crate::mcp::request_validation::McpMessageKind::Request,
                    params: Some(json!({"name": "get_current_date_time"})),
                },
                vec!["provider".to_string()],
            )));

        step_inject_credentials(&state, &mut ctx)
            .await
            .unwrap();

        assert!(
            ctx.delegated_credential_headers
                .get("authorization")
                .is_none()
        );

        assert!(
            vault
                .delete("token")
                .await
                .unwrap()
        );
        // With no stored token, a tool-scoped binding asks for no consent either.
        for tool in ["get_current_date_time", "other_tool"] {
            let mut ctx = test_pipeline_context();
            ctx.surface = surface.clone();
            ctx.protocol = Some(ChannelProtocol::Mcp);
            ctx.body_bytes = Some(Bytes::from(
                serde_json::to_vec(
                    &json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": tool}}),
                )
                .unwrap(),
            ));
            ctx.transit_token_claims = Some(claims.clone());

            let result = step_inject_credentials(&state, &mut ctx).await;

            assert!(result.is_ok(), "{tool}: {result:?}");
        }
    }

    #[tokio::test]
    async fn transit_tool_call_batches_are_refused_before_tool_level_controls() {
        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": 2, "result": {"content": []}}).to_string(),
        )
        .await;
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "batch-surface", "name": "Batch surface",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
            "target": {"endpoint": "http://127.0.0.1:1"},
            "transit": {"points": [{"alias": "partner-a", "protocol": "mcp",
                "require_transit_token": false, "allow_unauthenticated_callers": true,
                "target_endpoint": format!("http://{}", target.addr),
                "mcp_tool_gating": {"gates": [{"id": "g1", "name": "no admin",
                    "action": {"effect": "deny", "patterns": ["^admin_"]}}]}}]},
            "outbound_credentials": [{"credential_provider_id": "provider", "required_for": {"tools": ["scoped_tool"]}}]
        }))
        .unwrap();
        let manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        manager
            .update_channel_policy(&surface)
            .await
            .unwrap();
        let state = test_outbound_state();
        state
            .channel_state
            .write()
            .unwrap()
            .surface = Arc::new(surface);
        let mut state = state;
        state.policy_manager = Some(manager);

        // A UTF-8 BOM hides the batch from serde, but a lenient upstream parser
        // strips it and runs every call, so it is refused as a JSON-RPC parse error.
        for (tool, bom) in [("admin_reset", false), ("scoped_tool", false), ("admin_reset", true)] {
            let batch = json!([
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": {}}}
            ]);
            let mut body = if bom {
                b"\xEF\xBB\xBF".to_vec()
            } else {
                Vec::new()
            };
            body.extend_from_slice(batch.to_string().as_bytes());
            let request = Request::builder()
                .method("POST")
                .uri("/outbound/mcp/partner-a")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(axum::body::Body::from(body))
                .unwrap();

            let response = Box::pin(outbound_proxy_handler_with_mcp_versions(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                state.clone(),
                request,
                crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            ))
            .await
            .unwrap_or_else(|error| error.into_response());

            let status = response.status();
            let error: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 16384)
                    .await
                    .unwrap(),
            )
            .unwrap();
            if bom {
                assert_eq!(status, StatusCode::OK, "{tool} bom");
                assert_eq!(error["error"]["code"], -32700, "{tool} bom: {error}");
            } else {
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{tool}");
                assert_eq!(
                    error,
                    json!({"type": "https://a2a-protocol.org/errors/proxy-error", "title": "Unprocessable Entity", "status": 422, "detail": "JSON-RPC batches are not supported"}),
                    "{tool}"
                );
            }
            assert_eq!(
                target
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{tool} bom={bom}"
            );
        }
    }

    #[tokio::test]
    async fn transit_refuses_methods_and_bodies_outside_post() {
        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}).to_string(),
        )
        .await;
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "method-surface", "name": "Method surface",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
            "target": {"endpoint": "http://127.0.0.1:1"},
            "transit": {"points": [{"alias": "partner-a", "protocol": "mcp",
                "require_transit_token": false, "allow_unauthenticated_callers": true,
                "target_endpoint": format!("http://{}", target.addr)}]}
        }))
        .unwrap();
        let state = test_outbound_state();
        state
            .channel_state
            .write()
            .unwrap()
            .surface = Arc::new(surface);
        let send = |method: &'static str, body: &'static str| {
            let state = state.clone();
            async move {
                let request = Request::builder()
                    .method(method)
                    .uri("/outbound/mcp/partner-a")
                    .body(axum::body::Body::from(body))
                    .unwrap();
                Box::pin(outbound_proxy_handler_with_mcp_versions(
                    "127.0.0.1:12345"
                        .parse()
                        .unwrap(),
                    state,
                    request,
                    crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
                ))
                .await
                .unwrap_or_else(|error| error.into_response())
            }
        };

        for (method, body, status) in [
            ("PUT", "", StatusCode::METHOD_NOT_ALLOWED),
            ("PATCH", "", StatusCode::METHOD_NOT_ALLOWED),
            ("FOO", "", StatusCode::METHOD_NOT_ALLOWED),
            ("GET", "{}", StatusCode::BAD_REQUEST),
            ("DELETE", "{}", StatusCode::BAD_REQUEST),
        ] {
            let response = send(method, body).await;
            assert_eq!(response.status(), status, "{method}");
            if status == StatusCode::METHOD_NOT_ALLOWED {
                assert_eq!(response.headers()["allow"], "POST, GET, DELETE, HEAD, OPTIONS", "{method}");
            } else {
                let error: serde_json::Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(error["error"]["code"], crate::mcp::error_codes::INVALID_REQUEST, "{method}");
            }
        }
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no refused method reaches the upstream"
        );

        for (forwarded, method) in [(1, "GET"), (2, "DELETE")] {
            send(method, "").await;
            assert_eq!(
                target
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                forwarded,
                "an unmarked {method} without a body is forwarded"
            );
        }
    }

    #[tokio::test]
    async fn transit_requests_each_carry_their_own_request_id() {
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "request-id-surface", "name": "Request id surface",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
            "target": {"endpoint": "http://127.0.0.1:1"},
            "transit": {"opa_policy_definition_id": "def-1", "points": [{"alias": "partner-a", "protocol": "mcp",
                "require_transit_token": false, "allow_unauthenticated_callers": true,
                "target_endpoint": "http://127.0.0.1:9"}]}
        }))
        .unwrap();
        let state = test_outbound_state();
        state
            .channel_state
            .write()
            .unwrap()
            .surface = Arc::new(surface);

        let mut seen = Vec::new();
        for _ in 0..2 {
            let request = Request::builder()
                .method("POST")
                .uri("/outbound/mcp/partner-a")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(axum::body::Body::from(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string()))
                .unwrap();
            let (_, events) = crate::audit::producer::capture(Box::pin(outbound_proxy_handler_with_mcp_versions(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                state.clone(),
                request,
                crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            )))
            .await;
            let decisions: Vec<_> = events
                .iter()
                .filter(|event| {
                    matches!(event.event, crate::delegation_vault::audit::DelegationAuditAction::PolicyDecision { .. })
                })
                .collect();
            assert_eq!(decisions.len(), 1, "{events:?}");
            assert_eq!(
                decisions[0]
                    .channel_name
                    .as_deref(),
                Some("Request id surface")
            );
            assert_eq!(
                decisions[0]
                    .surface_id
                    .as_deref(),
                Some("request-id-surface")
            );
            seen.push(
                decisions[0]
                    .request_id
                    .clone()
                    .expect("the decision carries the request id"),
            );
        }
        assert!(seen.iter().all(|id| {
            id.len() == 16
                && id
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        }));
        assert_ne!(seen[0], seen[1], "each request has its own id");
    }

    // ── detect_protocol_and_operation ───────────────────────────────────────

    #[test]
    fn test_detect_protocol_a2a() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send"
            }))
            .unwrap(),
        );
        let (protocol, op) = detect_protocol_and_operation(&body, &ChannelProtocol::A2a);
        assert_eq!(protocol, ChannelProtocol::A2a);
        assert_eq!(op.as_deref(), Some("message/send"));
    }

    #[test]
    fn test_detect_protocol_mcp() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call"
            }))
            .unwrap(),
        );
        let (protocol, op) = detect_protocol_and_operation(&body, &ChannelProtocol::Mcp);
        assert_eq!(protocol, ChannelProtocol::Mcp);
        assert_eq!(op.as_deref(), Some("tools/call"));
    }

    #[test]
    fn test_detect_protocol_auto_from_mcp_method() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call"
            }))
            .unwrap(),
        );
        let (protocol, op) = detect_protocol_and_operation(&body, &ChannelProtocol::DIDComm);
        assert_eq!(protocol, ChannelProtocol::Mcp);
        assert_eq!(op.as_deref(), Some("tools/call"));
    }

    #[test]
    fn test_detect_protocol_auto_from_a2a_method() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tasks/get"
            }))
            .unwrap(),
        );
        let (protocol, _) = detect_protocol_and_operation(&body, &ChannelProtocol::DIDComm);
        assert_eq!(protocol, ChannelProtocol::A2a);
    }

    #[test]
    fn test_detect_protocol_auto_from_a2a_v1_method() {
        for method in ["SendMessage", "ListTasks", "GetExtendedAgentCard"] {
            let body = Bytes::from(serde_json::to_vec(&json!({ "jsonrpc": "2.0", "method": method })).unwrap());
            let (protocol, op) = detect_protocol_and_operation(&body, &ChannelProtocol::DIDComm);
            assert_eq!(protocol, ChannelProtocol::A2a, "{method}");
            assert_eq!(op.as_deref(), Some(method));
        }
    }

    #[test]
    fn test_detect_protocol_auto_keeps_channel_protocol_for_unknown_pascal_case_method() {
        let body = Bytes::from(serde_json::to_vec(&json!({ "jsonrpc": "2.0", "method": "DoSomething" })).unwrap());
        let (protocol, op) = detect_protocol_and_operation(&body, &ChannelProtocol::DIDComm);
        assert_eq!(protocol, ChannelProtocol::DIDComm);
        assert_eq!(op.as_deref(), Some("DoSomething"));
    }

    #[test]
    fn test_detect_protocol_non_json() {
        let body = Bytes::from("plain text body");
        let (protocol, op) = detect_protocol_and_operation(&body, &ChannelProtocol::A2a);
        assert_eq!(protocol, ChannelProtocol::A2a);
        assert!(op.is_none());
    }

    // ── build_outbound_target_url ──────────────────────────────────────────

    #[test]
    fn test_build_target_url_with_remainder() {
        let url = build_outbound_target_url(
            "https://partner.example.com/a2a",
            "/outbound/surfaces/order/partner-a/message/send",
            "/surfaces/order",
            "partner-a",
            None,
            None,
        );
        assert_eq!(url, "https://partner.example.com/a2a/message/send");
    }

    #[test]
    fn test_build_target_url_no_remainder() {
        let url = build_outbound_target_url(
            "https://partner.example.com/a2a",
            "/outbound/surfaces/order/partner-a",
            "/surfaces/order",
            "partner-a",
            None,
            None,
        );
        assert_eq!(url, "https://partner.example.com/a2a");
    }

    #[test]
    fn test_build_target_url_root_route() {
        let url = build_outbound_target_url(
            "https://partner.example.com",
            "/outbound/partner-a/some/path",
            "/",
            "partner-a",
            None,
            None,
        );
        assert_eq!(url, "https://partner.example.com/some/path");
    }

    #[test]
    fn test_build_target_url_trailing_slash() {
        let url = build_outbound_target_url(
            "https://partner.example.com/a2a/",
            "/outbound/surfaces/order/partner-a/path",
            "/surfaces/order",
            "partner-a",
            None,
            None,
        );
        assert_eq!(url, "https://partner.example.com/a2a/path");
    }

    #[test]
    fn test_build_target_url_custom_listen_path() {
        let url = build_outbound_target_url(
            "https://api.partner-a.com",
            "/partner-a-webhook/orders/42",
            "/whatever",
            "partner-a",
            Some("/partner-a-webhook"),
            None,
        );
        assert_eq!(url, "https://api.partner-a.com/orders/42");
    }

    #[test]
    fn test_build_target_url_custom_listen_path_root() {
        let url = build_outbound_target_url(
            "https://api.partner-a.com",
            "/partner-a-webhook",
            "/whatever",
            "partner-a",
            Some("/partner-a-webhook"),
            None,
        );
        assert_eq!(url, "https://api.partner-a.com");
    }

    #[test]
    fn test_build_target_url_agent_card_override_strips_subpath() {
        // Default would append to the /a2a sub-path; the TP override resolves
        // the card from the destination ORIGIN + custom path instead.
        let url = build_outbound_target_url(
            "https://partner.example.com/a2a",
            "/outbound/surfaces/order/partner-a/.well-known/agent-card.json",
            "/surfaces/order",
            "partner-a",
            None,
            Some("custom/agent.json"),
        );
        assert_eq!(url, "https://partner.example.com/custom/agent.json");
    }

    #[test]
    fn test_build_target_url_agent_card_override_ignored_for_non_card_path() {
        // The override only applies to well-known agent-card remainders; a
        // normal RPC path is forwarded verbatim regardless of the override.
        let url = build_outbound_target_url(
            "https://partner.example.com/a2a",
            "/outbound/surfaces/order/partner-a/message/send",
            "/surfaces/order",
            "partner-a",
            None,
            Some("custom/agent.json"),
        );
        assert_eq!(url, "https://partner.example.com/a2a/message/send");
    }

    #[test]
    fn test_build_target_url_agent_card_override_leading_slash() {
        let url = build_outbound_target_url(
            "https://partner.example.com/a2a",
            "/outbound/surfaces/order/partner-a/.well-known/agent.json",
            "/surfaces/order",
            "partner-a",
            None,
            Some("/.well-known/partner-card.json"),
        );
        assert_eq!(url, "https://partner.example.com/.well-known/partner-card.json");
    }

    // ── compute_outbound_remainder_path (fabric:// path suffix) ─────────────

    #[test]
    fn test_remainder_default_route() {
        let remainder = compute_outbound_remainder_path(
            "/outbound/surfaces/order/partner-a/message/send",
            "/surfaces/order",
            "partner-a",
            None,
        );
        assert_eq!(remainder, "message/send");
    }

    #[test]
    fn test_remainder_root_of_transit_point() {
        let remainder =
            compute_outbound_remainder_path("/outbound/surfaces/order/partner-a", "/surfaces/order", "partner-a", None);
        assert_eq!(remainder, "");
    }

    #[test]
    fn test_remainder_custom_listen_path() {
        let remainder = compute_outbound_remainder_path(
            "/partner-a-webhook/orders/42",
            "/whatever",
            "partner-a",
            Some("/partner-a-webhook"),
        );
        assert_eq!(remainder, "orders/42");
    }

    #[test]
    fn test_remainder_variant_routes() {
        for separator in ["", "$candidate", "%24candidate"] {
            for suffix in ["", "/orders/42"] {
                let expected = suffix.trim_start_matches('/');
                let canonical = format!("/outbound/surfaces/order{separator}/partner-a{suffix}");
                for listen_path in [None, Some("/custom/mcp")] {
                    assert_eq!(
                        compute_outbound_remainder_path(&canonical, "/surfaces/order", "partner-a", listen_path),
                        expected,
                        "canonical {canonical} with {listen_path:?}"
                    );
                }
                let custom = format!("/custom/mcp{separator}{suffix}");
                assert_eq!(
                    compute_outbound_remainder_path(&custom, "/surfaces/order", "partner-a", Some("/custom/mcp/")),
                    expected,
                    "custom {custom}"
                );
            }
        }
    }

    // ── resolve_virtual_channel ────────────────────────────────────────────

    #[test]
    fn test_resolve_virtual_channel_found() {
        let (vc, alias) =
            resolve_virtual_channel("/outbound/surfaces/order/partner-a/message/send", &test_surface()).unwrap();
        assert_eq!(vc.alias, "partner-a");
        assert_eq!(vc.target_endpoint, "https://partner.example.com/a2a");
        assert_eq!(alias, None);
    }

    #[test]
    fn test_resolve_virtual_channel_second_alias() {
        let (vc, alias) = resolve_virtual_channel("/outbound/surfaces/order/partner-b/foo", &test_surface()).unwrap();
        assert_eq!(vc.alias, "partner-b");
        assert_eq!(alias, None);
    }

    #[test]
    fn test_resolve_virtual_channel_unknown_alias() {
        let result = resolve_virtual_channel("/outbound/surfaces/order/unknown/foo", &test_surface());
        assert!(matches!(result, Err(OutboundPipelineError::UnknownVirtualChannelAlias(_))));
    }

    #[test]
    fn test_resolve_virtual_channel_missing_alias() {
        let result = resolve_virtual_channel("/outbound/surfaces/order/", &test_surface());
        assert!(matches!(result, Err(OutboundPipelineError::MissingVirtualChannelAlias)));
    }

    #[test]
    fn test_resolve_virtual_channel_with_variant_alias_suffix() {
        // `$dev` is a surface-variant alias attached to the route; it is
        // stripped silently here and the next segment (`partner-a`) is the TP.
        let (vc, variant_alias) =
            resolve_virtual_channel("/outbound/surfaces/order$dev/partner-a/message/send", &test_surface()).unwrap();
        assert_eq!(vc.alias, "partner-a");
        assert_eq!(variant_alias.as_deref(), Some("dev"));
    }

    #[test]
    fn test_resolve_virtual_channel_with_variant_alias_percent_encoded() {
        let (vc, variant_alias) =
            resolve_virtual_channel("/outbound/surfaces/order%24dev/partner-b/foo", &test_surface()).unwrap();
        assert_eq!(vc.alias, "partner-b");
        assert_eq!(variant_alias.as_deref(), Some("dev"));
    }

    #[tokio::test]
    async fn transit_variant_failures_are_refused_and_never_dispatch_the_base_target() {
        use crate::audit::request_events::{RejectionReason, RejectionStage};
        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({
                "jsonrpc": "2.0", "id": "variant", "result": {
                    "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"
                }
            })
            .to_string(),
        )
        .await;
        let versions = crate::mcp::request_validation::MODERN_CAPABLE_POLICY;
        let code = i64::from(crate::mcp::error_codes::INTERNAL_ERROR);
        for (case, modern, sent, status, reason, requested_variant) in [
            ("empty-catalog", true, "envelope", 404, RejectionReason::UnknownVariant, Some("unknown")),
            ("unknown", true, "envelope", 404, RejectionReason::UnknownVariant, Some("unknown")),
            ("unknown", true, "malformed", 404, RejectionReason::UnknownVariant, Some("unknown")),
            ("unknown", true, "20 KiB", 404, RejectionReason::UnknownVariant, Some("unknown")),
            ("unknown", true, "GET", 404, RejectionReason::UnknownVariant, Some("unknown")),
            ("unknown", true, "DELETE", 404, RejectionReason::UnknownVariant, Some("unknown")),
            ("unknown", false, "envelope", 404, RejectionReason::UnknownVariant, Some("unknown")),
            ("disabled", true, "envelope", 404, RejectionReason::VariantDisabled, None),
            ("disabled", false, "envelope", 404, RejectionReason::VariantDisabled, None),
            ("missing-default", true, "envelope", 500, RejectionReason::MisconfiguredDefault, None),
            ("missing-default", false, "envelope", 500, RejectionReason::MisconfiguredDefault, None),
            ("empty-catalog-missing-default", false, "envelope", 500, RejectionReason::MisconfiguredDefault, None),
            ("disabled-default", true, "envelope", 404, RejectionReason::VariantDisabled, None),
        ] {
            let label = format!("{case} modern={modern} body={sent}");
            let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
                "surface_id": "variant-surface", "name": "Variant surface",
                "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
                "target": {"endpoint": "http://127.0.0.1:1"},
                "transit": {"points": [{"alias": "partner-a", "protocol": "mcp",
                    "require_transit_token": false, "allow_unauthenticated_callers": true,
                    "target_endpoint": format!("http://{}", target.addr)}]},
                "variants": [{"id": "candidate", "alias": "candidate", "name": "Candidate", "enabled": false}]
            }))
            .unwrap();
            if case.starts_with("empty-catalog") {
                surface.variants.clear();
            }
            if case.ends_with("missing-default") {
                surface.default_variant_id = Some("absent".into());
            }
            if case == "disabled-default" {
                surface.default_variant_id = Some("candidate".into());
            }
            let path = match case {
                "disabled" => "/outbound/mcp$candidate/partner-a",
                "missing-default" | "disabled-default" | "empty-catalog-missing-default" => "/outbound/mcp/partner-a",
                _ => "/outbound/mcp$unknown/partner-a",
            };
            let state = test_outbound_state();
            state
                .channel_state
                .write()
                .unwrap()
                .surface = Arc::new(surface);
            let method = match sent {
                "GET" | "DELETE" => sent,
                _ => "POST",
            };
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream");
            let mut body = json!({"jsonrpc": "2.0", "id": "variant", "method": "tools/list"});
            if modern {
                request = request
                    .header("mcp-method", "tools/list")
                    .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION);
                body["params"] = json!({"_meta": {
                    "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }});
            }
            if sent == "20 KiB" {
                body["params"]["padding"] = json!("x".repeat(20 * 1024));
            }
            let body = match sent {
                "malformed" => "not json".to_string(),
                "GET" | "DELETE" => String::new(),
                _ => body.to_string(),
            };
            let request = request
                .body(axum::body::Body::from(body))
                .unwrap();
            let (response, events) =
                crate::audit::producer::capture(Box::pin(outbound_proxy_handler_with_mcp_versions(
                    "127.0.0.1:12345"
                        .parse()
                        .unwrap(),
                    state,
                    request,
                    versions,
                )))
                .await;
            let response = response.unwrap_or_else(|error| error.into_response());
            assert_eq!(response.status().as_u16(), status, "{label}");
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let answer: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 16384)
                    .await
                    .unwrap(),
            )
            .unwrap();
            if modern {
                assert_eq!(content_type, "application/json", "{label}");
                assert_eq!(answer["jsonrpc"], "2.0", "{label}: {answer}");
                let id = (sent == "envelope").then_some("variant");
                assert_eq!(
                    answer
                        .get("id")
                        .and_then(serde_json::Value::as_str),
                    id,
                    "{label}: {answer}"
                );
                assert_eq!(answer.get("id").is_some(), id.is_some(), "{label}: no null id: {answer}");
                assert_eq!(answer["error"]["code"], code, "{label}: {answer}");
            } else {
                assert_eq!(content_type, "application/problem+json", "{label}");
                assert!(
                    answer
                        .get("jsonrpc")
                        .is_none(),
                    "{label}: {answer}"
                );
            }
            let refusals: Vec<_> = events
                .iter()
                .filter_map(|event| match &event.event {
                    crate::delegation_vault::audit::DelegationAuditAction::RequestRejected {
                        stage,
                        reason,
                        http_status,
                        rpc_error_code,
                        requested_variant,
                    } => Some((*stage, *reason, *http_status, *rpc_error_code, requested_variant.clone())),
                    _ => None,
                })
                .collect();
            assert_eq!(
                refusals,
                vec![(
                    RejectionStage::Routing,
                    reason,
                    Some(status),
                    modern.then_some(code),
                    requested_variant.map(str::to_string)
                )],
                "{label}"
            );
            let expected_variant = match reason {
                RejectionReason::UnknownVariant => Some("_unknown_"),
                RejectionReason::VariantDisabled => Some("candidate"),
                _ => None,
            };
            assert_eq!(
                events[0]
                    .surface_variant
                    .as_deref(),
                expected_variant,
                "{label}"
            );
            assert_eq!(
                target
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{label}"
            );
        }
    }

    #[test]
    fn a_credential_delegation_line_names_the_request_variant() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let ctx = test_pipeline_context();

        crate::observability::policy_audit::with_request_variant("beta", || log_fabric_delegation_withheld(&ctx));
        log_fabric_delegation_withheld(&ctx);

        let lines: Vec<String> = logs
            .text()
            .lines()
            .filter(|line| line.contains("Delegated credentials withheld"))
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("surface_variant=\"beta\""), "{}", lines[0]);
        assert!(!lines[1].contains("surface_variant"), "{}", lines[1]);
    }

    #[tokio::test]
    async fn every_transit_point_record_names_the_variant_that_served_it() {
        for (variants, path, expected) in [
            (json!([{"id": "v-beta", "alias": "beta", "name": "Beta"}]), "/outbound/mcp$beta/partner-a", "beta"),
            (json!([]), "/outbound/mcp/partner-a", "_base_"),
        ] {
            let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
                "surface_id": "variant-surface", "name": "Variant surface",
                "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
                "target": {"endpoint": "http://127.0.0.1:1"},
                "transit": {
                    "shared": {"opa_policy_definition_id": "unavailable"},
                    "points": [{"alias": "partner-a", "protocol": "mcp",
                        "require_transit_token": false, "allow_unauthenticated_callers": true,
                        "target_endpoint": "http://127.0.0.1:1"}]
                },
                "variants": variants
            }))
            .unwrap();
            let state = test_outbound_state();
            state
                .channel_state
                .write()
                .unwrap()
                .surface = Arc::new(surface);
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string()))
                .unwrap();
            let (_, events) = crate::audit::producer::capture(Box::pin(outbound_proxy_handler_with_mcp_versions(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                state,
                request,
                crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            )))
            .await;
            assert!(!events.is_empty(), "{path}: the Transit Point request writes records");
            for event in &events {
                assert_eq!(
                    event
                        .surface_variant
                        .as_deref(),
                    Some(expected),
                    "{path}: {event:?}"
                );
            }
        }
    }

    #[test]
    fn test_context_new_uses_variant_effective_transit_point() {
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface-variant-tp",
            "name": "variant-tp",
            "description": "",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/surfaces/order",
                "protocol": "a2a"
            },
            "target": { "endpoint": "https://managed.example/a2a" },
            "transit": {
                "points": [{
                    "id": "tp-base",
                    "alias": "partner-a",
                    "target_endpoint": "https://base.example/a2a",
                    "protocol": "a2a"
                }]
            },
            "variants": [{
                "id": "variant-dev",
                "alias": "dev",
                "name": "Development",
                "enabled": true,
                "overrides": {
                    "transit": {
                        "points": [{
                            "id": "tp-dev",
                            "alias": "partner-a",
                            "target_endpoint": "https://dev.example/a2a",
                            "protocol": "a2a",
                            "header_metadata_mapping": {
                                "headers": [{ "header": "x-ms-entra-agent-id", "field": "entra_agent_id" }]
                            }
                        }]
                    }
                }
            }]
        }))
        .expect("surface should deserialize");
        let state = test_outbound_state();
        state
            .channel_state
            .write()
            .unwrap()
            .surface = Arc::new(surface);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/outbound/surfaces/order$dev/partner-a/message/send")
            .body(axum::body::Body::empty())
            .unwrap();

        let ctx = OutboundPipelineContext::new(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            req,
            &state,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
        )
        .expect("context should resolve variant Transit Point");

        assert_eq!(
            ctx.active_variant_alias
                .as_deref(),
            Some("dev")
        );
        assert_eq!(
            ctx.active_variant_id
                .as_deref(),
            Some("variant-dev")
        );
        assert_eq!(ctx.virtual_channel.id, "tp-dev");
        assert_eq!(
            ctx.virtual_channel
                .target_endpoint,
            "https://dev.example/a2a"
        );
        assert!(
            ctx.virtual_channel
                .header_metadata_mapping
                .is_some()
        );
    }

    #[test]
    fn a_retired_outbound_state_refuses_every_route_still_holding_it() {
        let mut held_by_listen_path_route = test_outbound_state();
        held_by_listen_path_route.vc_alias_override = Some("partner-a".into());
        let held_by_outbound_route = test_outbound_state();
        held_by_listen_path_route.channel_state = held_by_outbound_route
            .channel_state
            .clone();

        crate::proxy::server::retire_outbound_channel_state(&held_by_outbound_route.channel_state);

        for (state, path) in [
            (&held_by_outbound_route, "/outbound/surfaces/order/partner-a/message/send"),
            (&held_by_outbound_route, "/outbound/surfaces/order$dev/partner-a/message/send"),
            (&held_by_listen_path_route, "/custom/partner-a"),
        ] {
            let request = Request::builder()
                .method(Method::POST)
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            let result = OutboundPipelineContext::new(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                request,
                state,
                crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            );
            assert!(matches!(result, Err(OutboundPipelineError::OutboundDisabled)), "{path}");
        }
    }

    // ── step_source_auth ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_step_source_auth_noop_when_none() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.outbound_shared
            .source_auth = None;
        let result = step_source_auth(&state, &mut ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn transit_source_auth_refuses_every_request() {
        let state = test_outbound_state();
        for (case, method, path, mcp_resource_authorization) in [
            ("tool call", Method::POST, "/outbound/surfaces/order/partner-a", false),
            ("discovery read", Method::GET, "/outbound/surfaces/order/partner-a/.well-known/agent-card.json", false),
            ("resource token", Method::POST, "/outbound/surfaces/order/partner-a", true),
        ] {
            let mut ctx = test_pipeline_context();
            ctx.original_method = method;
            ctx.request_path = path.to_string();
            ctx.outbound_shared
                .source_auth = Some(
                serde_json::from_value(json!({
                    "type": "api_key",
                    "extraction": { "source": "http_header", "field": "X-API-Key" },
                    "secret_id": "transit-caller-key"
                }))
                .unwrap(),
            );
            if mcp_resource_authorization {
                ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
                ctx.virtual_channel.mcp_http = Some(
                    serde_json::from_value(json!({
                        "authorization": {
                            "resource": "https://outbound.example/outbound/surfaces/order/partner-a",
                            "scopes": ["read"]
                        }
                    }))
                    .unwrap(),
                );
            }

            let error = step_source_auth(&state, &mut ctx)
                .await
                .unwrap_err();

            assert!(matches!(error, OutboundPipelineError::TransitPointUnavailable { .. }), "{case}: {error:?}");
            assert!(
                ctx.authenticated_identity
                    .is_none(),
                "{case}"
            );
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{case}");
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            if mcp_resource_authorization {
                assert_eq!(
                    body,
                    json!({"jsonrpc": "2.0", "id": null, "error": {
                        "code": crate::mcp::errors::error_codes::INTERNAL_ERROR,
                        "message": "This Transit Point is unavailable"
                    }}),
                    "{case}"
                );
            } else {
                assert_eq!(body["detail"], "This Transit Point is unavailable", "{case}: {body}");
            }
            assert!(
                !body
                    .to_string()
                    .contains("source_auth"),
                "{case}: the caller is not told why: {body}"
            );
        }
    }

    #[tokio::test]
    async fn a_transit_point_whose_caller_authentication_cannot_be_enforced_refuses_every_request() {
        let state = test_outbound_state();
        let point = |fields: serde_json::Value| -> TransitPoint {
            let mut point = serde_json::to_value(test_virtual_channel()).unwrap();
            point
                .as_object_mut()
                .unwrap()
                .extend(
                    fields
                        .as_object()
                        .unwrap()
                        .clone(),
                );
            serde_json::from_value(point).unwrap()
        };
        let cases = [
            ("no caller authentication", point(json!({ "require_transit_token": false }))),
            (
                "DID Auth",
                point(json!({ "source_auth": {
                    "type": "did_auth", "extraction": { "source": "http_header", "field": "X-Session" }
                }})),
            ),
            (
                "a forwarded JWT",
                point(json!({ "source_auth": {
                    "type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": [],
                    "forward_header": true
                }})),
            ),
            (
                "source_auth beside mcp_http.authorization",
                point(json!({
                    "protocol": "mcp",
                    "mcp_http": { "authorization": {
                        "resource": "https://outbound.example/outbound/surfaces/order/partner-a"
                    }},
                    "source_auth": {
                        "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" },
                        "secret_id": "transit-caller-key"
                    }
                })),
            ),
        ];
        for (case, transit_point) in cases {
            for method in [Method::POST, Method::GET] {
                let mut ctx = test_pipeline_context();
                ctx.original_method = method.clone();
                ctx.request_path = "/outbound/surfaces/order/partner-a/.well-known/agent-card.json".to_string();
                ctx.virtual_channel = transit_point.clone();
                ctx.original_headers
                    .insert("x-api-key", HeaderValue::from_static("any-key"));

                let error = step_source_auth(&state, &mut ctx)
                    .await
                    .unwrap_err();

                assert!(matches!(error, OutboundPipelineError::TransitPointUnavailable { .. }), "{case} {method}");
                assert!(
                    ctx.authenticated_identity
                        .is_none(),
                    "{case}"
                );
                let response = error.into_response();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{case} {method}");
                let body = String::from_utf8(
                    axum::body::to_bytes(response.into_body(), usize::MAX)
                        .await
                        .unwrap()
                        .to_vec(),
                )
                .unwrap();
                assert!(body.contains("This Transit Point is unavailable"), "{case}: {body}");
                for detail in ["source_auth", "authenticat", "did_auth", "mcp_http"] {
                    assert!(!body.contains(detail), "{case}: the caller is not told why: {body}");
                }
            }
        }

        let mut open = test_pipeline_context();
        open.virtual_channel
            .require_transit_token = false;
        open.virtual_channel
            .allow_unauthenticated_callers = true;
        step_source_auth(&state, &mut open)
            .await
            .unwrap();
        assert!(
            open.authenticated_identity
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_transit_point_refuses_its_source_auth_when_the_gateway_cannot_run_it() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .require_transit_token = false;
        ctx.virtual_channel
            .source_auth = Some(
            serde_json::from_value(json!({
                "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" },
                "secret_id": "transit-caller-key"
            }))
            .unwrap(),
        );
        ctx.original_headers
            .insert("x-api-key", HeaderValue::from_static("caller-key"));

        let error = step_source_auth(&state, &mut ctx)
            .await
            .unwrap_err();

        assert!(matches!(error, OutboundPipelineError::TransitPointUnavailable { .. }), "{error:?}");
        assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            ctx.authenticated_identity
                .is_none()
        );
    }

    /// An outbound state whose `source_auth` middleware knows the API key
    /// secret `transit-caller-key`, whose value is `right-key`.
    async fn transit_caller_key_state(directory: &std::path::Path) -> OutboundProxyState {
        use crate::secrets::SecretsStore;

        let secrets = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                directory
                    .join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "Transit Point callers".to_string(),
                secret_id: "transit-caller-key".to_string(),
                description: None,
                value: "right-key".to_string(),
                secret_type: "ApiKey".to_string(),
                tags: Vec::new(),
            })
            .await
            .unwrap();
        let strategies =
            crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(directory.join("strategies"))
                .await
                .unwrap();
        let mut state = test_outbound_state();
        state.source_auth_middleware = Some(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
            Arc::new(crate::didauth::sessions::DidAuthSessionStore::new()),
            Arc::new(strategies),
            Arc::new(crate::jwt_bearer::JwksClient::new()),
            Some(secrets),
            Arc::new(dashmap::DashMap::new()),
            None,
            None,
        )));
        state
    }

    /// A Transit Point records every caller its `source_auth` refuses as an
    /// `auth_failed` event, and names the caller it admitted on its policy and
    /// delegation audit records.
    #[tokio::test]
    async fn a_transit_point_audits_the_callers_its_source_auth_refuses_and_names_the_one_it_admits() {
        use crate::delegation_vault::audit::DelegationAuditAction;

        let directory = tempfile::tempdir().unwrap();
        let state = transit_caller_key_state(directory.path()).await;
        let context = |key: Option<&'static str>| {
            let mut ctx = test_pipeline_context();
            ctx.virtual_channel
                .require_transit_token = false;
            ctx.virtual_channel
                .source_auth = Some(
                serde_json::from_value(json!({
                    "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" },
                    "secret_id": "transit-caller-key"
                }))
                .unwrap(),
            );
            if let Some(key) = key {
                ctx.original_headers
                    .insert("x-api-key", HeaderValue::from_static(key));
            }
            ctx
        };

        for (key, reason) in [(Some("wrong-key"), "invalid_credential"), (None, "missing_credential")] {
            let mut ctx = context(key);
            let (result, events) = crate::audit::producer::capture(step_source_auth(&state, &mut ctx)).await;
            assert!(matches!(result, Err(OutboundPipelineError::TransitCallerUnauthenticated)), "{result:?}");
            assert_eq!(events.len(), 1, "{reason}: {events:?}");
            assert!(
                matches!(
                    &events[0].event,
                    DelegationAuditAction::AuthFailed {
                        scheme: crate::audit::events::AuthScheme::ApiKey,
                        reason: recorded,
                        blocking: true,
                        client_ip: Some(ip),
                    } if recorded == reason && ip == "127.0.0.1"
                ),
                "{reason}: {events:?}"
            );
            assert_eq!(
                events[0]
                    .surface_id
                    .as_deref(),
                Some(
                    ctx.surface
                        .surface_id
                        .as_str()
                )
            );
            assert_eq!(events[0].trace_id.as_deref(), Some("test-request-id"));
        }

        let mut admitted = context(Some("right-key"));
        let (result, events) = crate::audit::producer::capture(step_source_auth(&state, &mut admitted)).await;
        assert!(result.is_ok(), "{result:?}");
        assert!(events.is_empty(), "{events:?}");
        let caller = outbound_caller(&admitted).expect("the admitted caller is named");
        assert_eq!(caller.auth_method, "api_key");
        assert_eq!(caller.sub.as_deref(), Some("transit-caller-key"));

        admitted.authenticated_by = None;
        assert!(outbound_caller(&admitted).is_none(), "an identity nothing verified names no caller");
    }

    /// The `auth_failed` record a Transit Point's `source_auth` writes names
    /// the surface variant that served the request, as every other Transit
    /// Point record does.
    #[tokio::test]
    async fn a_transit_point_source_auth_refusal_names_the_variant_that_served_it() {
        use crate::delegation_vault::audit::DelegationAuditAction;

        for (variants, path, expected) in [
            (json!([{"id": "v-beta", "alias": "beta", "name": "Beta"}]), "/outbound/mcp$beta/partner-a", "beta"),
            (json!([]), "/outbound/mcp/partner-a", "_base_"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
                "surface_id": "variant-surface", "name": "Variant surface",
                "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
                "target": {"endpoint": "http://127.0.0.1:1"},
                "transit": {"points": [{"alias": "partner-a", "protocol": "mcp",
                    "require_transit_token": false, "target_endpoint": "http://127.0.0.1:1",
                    "source_auth": {
                        "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" },
                        "secret_id": "transit-caller-key"
                    }}]},
                "variants": variants
            }))
            .unwrap();
            let state = transit_caller_key_state(directory.path()).await;
            state
                .channel_state
                .write()
                .unwrap()
                .surface = Arc::new(surface);
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("x-api-key", "wrong-key")
                .body(axum::body::Body::from(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string()))
                .unwrap();
            let (response, events) =
                crate::audit::producer::capture(Box::pin(outbound_proxy_handler_with_mcp_versions(
                    "127.0.0.1:12345"
                        .parse()
                        .unwrap(),
                    state,
                    request,
                    crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
                )))
                .await;
            assert!(
                matches!(response, Err(OutboundPipelineError::TransitCallerUnauthenticated)),
                "{path}: {response:?}"
            );
            let refusals = events
                .iter()
                .filter(|event| matches!(event.event, DelegationAuditAction::AuthFailed { .. }))
                .count();
            assert_eq!(refusals, 1, "{path}: {events:?}");
            for event in &events {
                assert_eq!(
                    event
                        .surface_variant
                        .as_deref(),
                    Some(expected),
                    "{path}: {event:?}"
                );
            }
        }
    }

    // ── step_rate_limit ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_step_rate_limit_noop_when_none() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.outbound_shared.rate_limit = None;
        let result = step_rate_limit(&state, &mut ctx).await;
        assert!(result.is_ok());
    }

    // ── step_extract_protocol_context ──────────────────────────────────────

    #[tokio::test]
    async fn test_step_extract_protocol_context_mcp_http_rejects_explicit_modern_non_posts() {
        let state = test_outbound_state();
        for method in [Method::GET, Method::DELETE] {
            let mut ctx = test_pipeline_context();
            ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
            ctx.original_method = method;
            ctx.original_headers.insert(
                "mcp-protocol-version",
                crate::mcp::MCP_MODERN_VERSION
                    .parse()
                    .unwrap(),
            );
            ctx.original_headers.insert(
                "mcp-session-id",
                "legacy-session"
                    .parse()
                    .unwrap(),
            );
            ctx.request = Some(axum::http::Request::new(axum::body::Body::empty()));
            let response = step_extract_protocol_context(&state, &mut ctx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()["allow"], "POST");
            assert!(ctx.request.is_some());
            assert!(ctx.body_bytes.is_none());
        }
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_mcp_http_applies_the_transit_point_origin_policy() {
        let state = test_outbound_state();
        for (origin, blocked) in
            [("https://agent.example", false), ("https://console.example", true), ("https://untrusted.example", true)]
        {
            let mut ctx = test_pipeline_context();
            let surface = Arc::make_mut(&mut ctx.surface);
            surface.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
            surface.mcp_http =
                Some(serde_json::from_value(json!({"allowed_origins": ["https://console.example"]})).unwrap());
            ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
            ctx.virtual_channel.mcp_http =
                Some(serde_json::from_value(json!({"allowed_origins": ["https://agent.example"]})).unwrap());
            ctx.original_headers
                .insert("origin", origin.parse().unwrap());
            ctx.request = Some(axum::http::Request::new(axum::body::Body::from(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
            )));
            let result = step_extract_protocol_context(&state, &mut ctx).await;
            if blocked {
                let OutboundPipelineError::McpValidation(error) = result.unwrap_err() else {
                    panic!("expected MCP HTTP validation error");
                };
                assert_eq!(error.status, StatusCode::FORBIDDEN);
                assert!(ctx.request.is_some());
                assert!(ctx.body_bytes.is_none());
            } else {
                assert!(result.is_ok(), "{result:?}");
                assert_eq!(ctx.protocol, Some(ChannelProtocol::Mcp));
            }
        }
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_rejects_every_admission_negative_case() {
        use crate::mcp::admission_cases::{ALLOWED_ORIGIN, admission_cases, assert_rejected, body_refusal_cases};

        let state = test_outbound_state();
        let versions = crate::mcp::request_validation::MODERN_CAPABLE_POLICY;
        for case in admission_cases()
            .into_iter()
            .chain(body_refusal_cases())
        {
            let mut ctx = test_pipeline_context();
            Arc::make_mut(&mut ctx.surface)
                .access_point
                .protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
            ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
            ctx.virtual_channel.mcp_http =
                Some(serde_json::from_value(json!({"allowed_origins": [ALLOWED_ORIGIN]})).unwrap());
            ctx.original_headers = case.header_map();
            ctx.request = Some(axum::http::Request::new(axum::body::Body::from(case.body.clone())));
            let result = step_extract_protocol_context_with_versions(&state, &mut ctx, versions).await;
            let Err(OutboundPipelineError::McpValidation(error)) = result else {
                panic!("Transit Point admitted {}: {result:?}", case.name);
            };
            let body = json!({"id": error.id, "error": {"code": error.code, "data": error.data}});
            assert_rejected(&case, error.status, &body, "Transit Point");
        }
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_refuses_case_variant_fields() {
        let state = test_outbound_state();
        for body in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"Name": "admin_reset"}}),
            json!({"jsonrpc": "2.0", "id": 2, "Method": "tools/call", "params": {"name": "admin_reset"}}),
        ] {
            let mut ctx = test_pipeline_context();
            Arc::make_mut(&mut ctx.surface)
                .access_point
                .protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
            ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
            ctx.request = Some(axum::http::Request::new(axum::body::Body::from(body.to_string())));
            let result = step_extract_protocol_context(&state, &mut ctx).await;
            assert!(
                matches!(
                    result,
                    Err(OutboundPipelineError::McpBodyRefused(crate::mcp::tool_analyzer::BodyRefusal::AmbiguousKeys))
                ),
                "{body}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_strips_session_and_resumption_state_from_modern_requests() {
        let state = test_outbound_state();
        let versions = crate::mcp::request_validation::MODERN_CAPABLE_POLICY;
        let mut ctx = test_pipeline_context();
        Arc::make_mut(&mut ctx.surface)
            .access_point
            .protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        for (name, value) in [
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION),
            ("mcp-method", "tools/list"),
            ("mcp-session-id", "legacy-session"),
            ("last-event-id", "7"),
        ] {
            ctx.original_headers
                .insert(name, value.parse().unwrap());
        }
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        ctx.request = Some(axum::http::Request::new(axum::body::Body::from(body.to_string())));
        step_extract_protocol_context_with_versions(&state, &mut ctx, versions)
            .await
            .unwrap();
        // The Transit Point forwards `original_headers` to its upstream.
        for name in ["mcp-session-id", "last-event-id"] {
            assert!(
                !ctx.original_headers
                    .contains_key(name),
                "{name} is removed from a modern request"
            );
        }
        assert_eq!(ctx.original_headers["mcp-method"], "tools/list");
    }

    /// A caller cannot present an Affinidi identity credential the gateway did
    /// not issue: the Transit Point refuses it with 422 before forwarding.
    #[tokio::test]
    async fn test_step_extract_protocol_context_rejects_a_spoofed_identity_credential() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        Arc::make_mut(&mut ctx.surface)
            .access_point
            .protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        let body = json!({"jsonrpc": "2.0", "id": "spoofed", "method": "tools/list", "params": {"_meta": {
            "io.affinidi.fabric/agent-identity-credential": {"did": "did:example:spoofed"}
        }}});
        ctx.request = Some(axum::http::Request::new(axum::body::Body::from(body.to_string())));
        let result = step_extract_protocol_context(&state, &mut ctx).await;
        let Err(error @ OutboundPipelineError::McpIdentityInvalid) = result else {
            panic!("a spoofed identity credential must be refused: {result:?}");
        };
        assert_eq!(error.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_caps_initialize_to_a_served_revision() {
        let state = test_outbound_state();
        let legacy = crate::mcp::MCP_LEGACY_VERSION;
        for (requested, forwarded) in [("2099-01-01", legacy), (legacy, legacy), ("2025-06-18", "2025-06-18")] {
            let mut ctx = test_pipeline_context();
            Arc::make_mut(&mut ctx.surface)
                .access_point
                .protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
            ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": requested, "capabilities": {}, "clientInfo": {"name": "client", "version": "1"}
            }})
            .to_string();
            ctx.request = Some(axum::http::Request::new(axum::body::Body::from(body.clone())));
            step_extract_protocol_context(&state, &mut ctx)
                .await
                .unwrap();
            let sent = ctx
                .body_bytes
                .expect("body read");
            let sent: serde_json::Value = serde_json::from_slice(&sent).unwrap();
            assert_eq!(sent["params"]["protocolVersion"], forwarded, "{requested}");
            assert_eq!(sent["params"]["clientInfo"]["name"], "client");
            if requested == forwarded {
                assert_eq!(sent, serde_json::from_str::<serde_json::Value>(&body).unwrap());
            }
        }
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_mcp_http_bounds_body_on_a2a_parent() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        ctx.virtual_channel.mcp_http = Some(serde_json::from_value(json!({"max_request_bytes": 32})).unwrap());
        ctx.request = Some(axum::http::Request::new(axum::body::Body::from(" ".repeat(33))));
        let OutboundPipelineError::McpValidation(error) = step_extract_protocol_context(&state, &mut ctx)
            .await
            .unwrap_err()
        else {
            panic!("expected MCP HTTP size error");
        };
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.id, None);
        assert!(ctx.body_bytes.is_none());
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_limits_fabric_transit_points_to_fabric_send() {
        let state = test_outbound_state();
        let versions = crate::mcp::request_validation::MODERN_CAPABLE_POLICY;
        // A `fabric://` Transit Point resolves to the Fabric send policy, which
        // admits the same revisions as an HTTP(S) Target; each row pins that
        // the two Targets still agree.
        for (target, version, admitted) in [
            ("fabric://gateway/channel", crate::mcp::MCP_MODERN_VERSION, true),
            ("https://agent.example/mcp", crate::mcp::MCP_MODERN_VERSION, true),
            ("fabric://gateway/channel", "2099-01-01", false),
            ("https://agent.example/mcp", "2099-01-01", false),
        ] {
            let mut ctx = test_pipeline_context();
            ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
            ctx.virtual_channel
                .target_endpoint = target.to_string();
            for (name, value) in [
                ("mcp-protocol-version", version),
                ("mcp-method", "tools/list"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ] {
                ctx.original_headers
                    .insert(name, value.parse().unwrap());
            }
            ctx.request = Some(axum::http::Request::new(axum::body::Body::from(
                json!({"jsonrpc": "2.0", "id": "transit-admission", "method": "tools/list", "params": {"_meta": {
                    "io.modelcontextprotocol/protocolVersion": version,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }}})
                .to_string(),
            )));
            let result = step_extract_protocol_context_with_versions(&state, &mut ctx, versions).await;
            if !admitted {
                let OutboundPipelineError::McpValidation(error) = result.unwrap_err() else {
                    panic!("expected MCP version rejection for {target} {version}");
                };
                assert_eq!(error.status, StatusCode::BAD_REQUEST);
                assert_eq!(error.code, crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
                assert_eq!(error.id, Some(json!("transit-admission")));
                assert_eq!(error.data.unwrap()["supported"], json!(versions.supported_versions()));
                assert!(
                    ctx.mcp_classification
                        .is_none()
                );
            } else {
                assert!(result.is_ok(), "{target}: {result:?}");
                assert!(
                    matches!(
                        ctx.mcp_classification,
                        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
                    ),
                    "{target}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_advertises_versions_learned_from_transit_discovery() {
        use crate::mcp::MCP_MODERN_VERSION;

        let versions = crate::mcp::request_validation::MODERN_CAPABLE_POLICY;
        let transit_point = |ctx: &mut OutboundPipelineContext, alias: &str| {
            ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
            ctx.virtual_channel.alias = alias.to_string();
            ctx.virtual_channel
                .target_endpoint = "https://agent.example/mcp".to_string();
        };
        let mut discovery = modern_pipeline_context("server/discover");
        transit_point(&mut discovery, "learned-discovery");
        let upstream = reqwest::Response::from(
            axum::http::Response::builder()
                .header("content-type", "application/json")
                .body(reqwest::Body::from(
                    json!({"jsonrpc": "2.0", "id": "stream", "error": {
                        "code": crate::mcp::error_codes::METHOD_NOT_FOUND, "message": "Method not found"
                    }})
                    .to_string(),
                ))
                .unwrap(),
        );
        let response =
            process_modern_outbound_response(test_outbound_state(), discovery, UpstreamResponse::Http(upstream))
                .await
                .unwrap();
        let delivered: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(delivered["error"]["code"], crate::mcp::error_codes::METHOD_NOT_FOUND);

        let state = test_outbound_state();
        let admit = async |alias: &str, version: &str| {
            let mut ctx = test_pipeline_context();
            transit_point(&mut ctx, alias);
            for (name, value) in [
                ("mcp-protocol-version", version),
                ("mcp-method", "tools/list"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ] {
                ctx.original_headers
                    .insert(name, value.parse().unwrap());
            }
            ctx.request = Some(axum::http::Request::new(axum::body::Body::from(
                json!({"jsonrpc": "2.0", "id": "learned", "method": "tools/list", "params": {"_meta": {
                    "io.modelcontextprotocol/protocolVersion": version,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }}})
                .to_string(),
            )));
            step_extract_protocol_context_with_versions(&state, &mut ctx, versions)
                .await
                .map(|_| ctx.mcp_classification)
        };
        for (alias, supported) in [
            ("learned-discovery", json!(crate::mcp::request_validation::SESSION_VERSIONS)),
            ("unlearned-discovery", json!(versions.supported_versions())),
        ] {
            let Err(OutboundPipelineError::McpValidation(error)) = admit(alias, "2099-01-01").await else {
                panic!("expected MCP version rejection for {alias}");
            };
            assert_eq!(error.code, crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
            assert_eq!(error.id, Some(json!("learned")));
            assert_eq!(error.data.unwrap()["supported"], supported, "{alias}");
        }
        assert!(matches!(
            admit("learned-discovery", MCP_MODERN_VERSION).await,
            Ok(Some(crate::mcp::request_validation::McpRequestClassification::Modern(_)))
        ));
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_a2a() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {}
            }))
            .unwrap(),
        ));

        step_extract_protocol_context(&state, &mut ctx)
            .await
            .unwrap();
        assert_eq!(ctx.protocol, Some(ChannelProtocol::A2a));
        assert_eq!(ctx.operation.as_deref(), Some("message/send"));
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_empty_body() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.body_bytes = None;

        step_extract_protocol_context(&state, &mut ctx)
            .await
            .unwrap();
        assert_eq!(ctx.protocol, Some(ChannelProtocol::A2a));
        assert!(ctx.operation.is_none());
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_rejects_mcp_on_a2a_transit_point() {
        // The default test transit point is A2A. An MCP `tools/call` body must
        // be rejected with a protocol-mismatch error rather than silently
        // forwarded to the upstream.
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        assert_eq!(ctx.virtual_channel.protocol, crate::config::agent_surface::TransitProtocol::A2a);
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "echo" }
            }))
            .unwrap(),
        ));

        let err = step_extract_protocol_context(&state, &mut ctx)
            .await
            .expect_err("MCP body on an A2A transit point must be rejected");
        assert_eq!(err.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
        match err {
            OutboundPipelineError::ProtocolMismatch { expected, detected } => {
                assert_eq!(expected, "a2a");
                assert_eq!(detected, "mcp");
            }
            other => panic!("expected ProtocolMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_rejects_a2a_on_mcp_transit_point() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {}
            }))
            .unwrap(),
        ));

        let err = step_extract_protocol_context(&state, &mut ctx)
            .await
            .expect_err("A2A body on an MCP transit point must be rejected");
        match err {
            OutboundPipelineError::ProtocolMismatch { expected, detected } => {
                assert_eq!(expected, "mcp");
                assert_eq!(detected, "a2a");
            }
            other => panic!("expected ProtocolMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_allows_matching_protocol() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "echo" }
            }))
            .unwrap(),
        ));

        step_extract_protocol_context(&state, &mut ctx)
            .await
            .expect("matching MCP body on an MCP transit point must pass");
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_ap2_accepts_a2a_shape() {
        // AP2 builds on A2A method shapes, so an `message/send` body must not
        // be flagged as a mismatch against an AP2 transit point.
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Ap2;
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {}
            }))
            .unwrap(),
        ));

        step_extract_protocol_context(&state, &mut ctx)
            .await
            .expect("A2A-shaped body on an AP2 transit point must pass");
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_http_transit_point_skips_check() {
        // `http` transit points are raw pass-throughs and must never reject on
        // protocol shape, regardless of body.
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Http;
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call"
            }))
            .unwrap(),
        ));

        step_extract_protocol_context(&state, &mut ctx)
            .await
            .expect("http transit point must skip protocol enforcement");
    }

    #[tokio::test]
    async fn test_step_extract_protocol_context_unknown_method_not_rejected() {
        // A body whose method prefix is neither A2A nor MCP cannot be
        // classified, so it must be left alone rather than rejected.
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "custom/thing"
            }))
            .unwrap(),
        ));

        step_extract_protocol_context(&state, &mut ctx)
            .await
            .expect("unclassifiable body must not be rejected");
    }

    // ── step_map_transit_point_header_metadata ───────────────────────────

    fn test_header_metadata_mapping(
        strip_mapped_headers: bool
    ) -> crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
        crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
            headers: vec![
                crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                    header: "x-ms-entra-agent-id".to_string(),
                    field: "entra_agent_id".to_string(),
                },
                crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                    header: "x-ms-client-tenant-id".to_string(),
                    field: "client_tenant_id".to_string(),
                },
            ],
            strip_mapped_headers,
            ..Default::default()
        }
    }

    fn a2a_message_body(metadata: serde_json::Value) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{ "kind": "text", "text": "hello" }],
                        "metadata": metadata
                    }
                }
            }))
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_step_map_transit_point_header_metadata_injects_metadata() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .header_metadata_mapping = Some(test_header_metadata_mapping(true));
        ctx.body_bytes = Some(a2a_message_body(json!({})));
        ctx.original_headers
            .insert("x-ms-entra-agent-id", HeaderValue::from_static("agent-123"));
        ctx.original_headers
            .insert("x-ms-client-tenant-id", HeaderValue::from_static("tenant-456"));

        step_map_transit_point_header_metadata(&state, &mut ctx)
            .await
            .expect("mapping should apply");

        let body: serde_json::Value = serde_json::from_slice(
            ctx.body_bytes
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        let metadata = &body["params"]["message"]["metadata"]
            [crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI];
        assert_eq!(metadata["entra_agent_id"], "agent-123");
        assert_eq!(metadata["client_tenant_id"], "tenant-456");
        assert_eq!(
            body["params"]["message"]["extensions"],
            json!([crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI])
        );
    }

    #[tokio::test]
    async fn test_step_map_transit_point_header_metadata_overrides_colliding_fields() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .header_metadata_mapping = Some(test_header_metadata_mapping(true));
        ctx.body_bytes = Some(a2a_message_body(json!({
            crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI: {
                "entra_agent_id": "stale-agent",
                "other": "kept"
            }
        })));
        ctx.original_headers
            .insert("x-ms-entra-agent-id", HeaderValue::from_static("agent-123"));

        step_map_transit_point_header_metadata(&state, &mut ctx)
            .await
            .expect("mapping should apply");

        let body: serde_json::Value = serde_json::from_slice(
            ctx.body_bytes
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        let metadata = &body["params"]["message"]["metadata"]
            [crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI];
        assert_eq!(metadata["entra_agent_id"], "agent-123");
        assert_eq!(metadata["other"], "kept");
    }

    #[tokio::test]
    async fn test_step_map_transit_point_header_metadata_missing_headers_do_not_change_body() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .header_metadata_mapping = Some(test_header_metadata_mapping(true));
        let original = a2a_message_body(json!({}));
        ctx.body_bytes = Some(original.clone());

        step_map_transit_point_header_metadata(&state, &mut ctx)
            .await
            .expect("missing headers should be non-fatal");

        assert_eq!(ctx.body_bytes, Some(original));
    }

    #[test]
    fn test_should_forward_outbound_request_header_strips_mapped_headers_when_enabled() {
        let mapping = test_header_metadata_mapping(true);

        assert!(!should_forward_outbound_request_header("x-ms-entra-agent-id", Some(&mapping)));
        assert!(should_forward_outbound_request_header("x-other-context", Some(&mapping)));
    }

    #[test]
    fn test_should_forward_outbound_request_header_preserves_mapped_headers_when_disabled() {
        let mapping = test_header_metadata_mapping(false);

        assert!(should_forward_outbound_request_header("x-ms-entra-agent-id", Some(&mapping)));
    }

    #[test]
    fn a_managed_agents_cookies_and_authorization_never_reach_a_transit_point_target() {
        for withheld in [
            "cookie",
            "Cookie",
            "authorization",
            "x-transit-token",
            "X-Caller-DID",
            "x-caller-identity-source",
            "x-caller-dna-uai",
            "x-gateway-did",
            "X-DID-Identity",
            "x-did-signed-identity",
        ] {
            assert!(!should_forward_outbound_request_header(withheld, None), "{withheld}");
        }
        for forwarded in
            ["x-api-key", "accept", "content-type", "x-forwarded-for", "mcp-protocol-version", "x-caller-context"]
        {
            assert!(should_forward_outbound_request_header(forwarded, None), "{forwarded}");
        }
    }

    #[test]
    fn a_legacy_transit_point_response_withholds_the_targets_cookies_and_challenges() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.append("set-cookie", HeaderValue::from_static("vendor_sid=one; HttpOnly"));
        upstream_headers.append("set-cookie", HeaderValue::from_static("vendor_lb=two"));
        upstream_headers.insert(
            "www-authenticate",
            HeaderValue::from_static(
                r#"Bearer resource_metadata="https://vendor.example/.well-known/oauth-protected-resource""#,
            ),
        );
        upstream_headers.insert("content-type", HeaderValue::from_static("application/json"));
        upstream_headers.insert("x-vendor-request-id", HeaderValue::from_static("vendor-7"));

        let response = process_outbound_response_body(
            &state,
            &mut ctx,
            StatusCode::UNAUTHORIZED,
            upstream_headers,
            Bytes::from_static(br#"{"error":"invalid_token"}"#),
            &crate::policies::PolicyAttestation::default(),
        )
        .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !response
                .headers()
                .contains_key("set-cookie")
        );
        assert!(
            !response
                .headers()
                .contains_key("www-authenticate")
        );
        assert_eq!(response.headers()["x-vendor-request-id"], "vendor-7");
        assert_eq!(response.headers()["content-type"], "application/json");
    }

    #[tokio::test]
    async fn a_modern_transit_point_response_withholds_the_targets_cookies_and_challenges() {
        let upstream = reqwest::Response::from(
            axum::http::Response::builder()
                .header("content-type", "application/json")
                .header("set-cookie", "vendor_sid=one; HttpOnly")
                .header("www-authenticate", "Bearer error=\"insufficient_scope\"")
                .header("x-vendor-request-id", "vendor-8")
                .body(reqwest::Body::from(
                    json!({"jsonrpc": "2.0", "id": "stream", "result": {"resultType": "complete", "content": []}})
                        .to_string(),
                ))
                .unwrap(),
        );

        let response = process_modern_outbound_response(
            test_outbound_state(),
            modern_pipeline_context("tools/call"),
            UpstreamResponse::Http(upstream),
        )
        .await
        .unwrap();

        assert!(
            !response
                .headers()
                .contains_key("set-cookie")
        );
        assert!(
            !response
                .headers()
                .contains_key("www-authenticate")
        );
        assert_eq!(response.headers()["x-vendor-request-id"], "vendor-8");
    }

    // ── step_resolve_agent_identity ──────────────────────────────────────

    #[tokio::test]
    async fn test_step_resolve_agent_identity_skipped_when_no_managed_identity() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        // Surface has no managed_identity — step is a no-op
        assert!(
            ctx.surface
                .managed_identity()
                .is_none()
        );
        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous));
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_skipped_with_body_but_no_managed_identity() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.body_bytes = Some(Bytes::from(r#"{"key": "value"}"#));

        // No managed_identity → skipped even with body present
        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous));
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_skipped_when_tp_inject_vp_disabled() {
        // Regression: a transit point that inherits the surface `protected`
        // identity slot (no per-TP `managed_identity`) and leaves
        // `identity_injection.inject_vp = false` has opted out of egress
        // identity management. A plain request that lacks the protected payload
        // must resolve anonymous — NOT 422 — because the operator did not ask
        // for a VP on this transit point.
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        // Opt this transit point out of egress VP injection.
        ctx.virtual_channel
            .identity_injection
            .inject_vp = false;
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::Mcp);
        // Plain MCP request carrying no agentIdentity payload.
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "test-tool" }
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_ok(), "inject_vp=false must opt the TP out of egress identity, got: {result:?}");
        assert!(
            matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous),
            "opted-out transit point must resolve anonymous"
        );
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_enforces_protected_slot_when_inject_vp_enabled() {
        // Counterpart to the opt-out test: with `inject_vp = true` the transit
        // point inherits and enforces the surface `protected` slot, so a body
        // missing the payload is a 422 (identity resolution failure) rather
        // than a silent anonymous pass-through.
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .identity_injection
            .inject_vp = true;
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "test-tool" }
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err(), "inject_vp=true must enforce the inherited protected slot, got: {result:?}");
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_errors_when_extension_missing() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::A2a);
        // A2A body without agent-identity extension
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": { "message": {} }
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(_))
            ),
            "expected IdentityResolutionFailed(ExtensionMissing), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_validation_fails() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();

        // Rule: cloudProvider must equal "local"
        let ext_rules = crate::config::ExtensionRules {
            json_schema: None,
            rules: vec![crate::config::ValidationRule::Equals {
                path: "cloudProvider".to_string(),
                value: json!("local"),
            }],
            filter_rules: vec![],
            default_action: None,
        };
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: Some(ext_rules.clone()),
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.identity_rules_engine = Some(Arc::new(crate::proxy::RulesEngine::new(&ext_rules).unwrap()));
        ctx.protocol = Some(ChannelProtocol::A2a);

        // A2A body with agent-identity/v1 — value does NOT match the rule
        let body_json = json!({
            "jsonrpc": "2.0",
            "method": "message/send",
            "params": { "message": { "metadata": {
                "https://fabric.affinidi.io/extensions/agent-identity/v1": { "cloudProvider": "aws" }
            } } }
        });
        ctx.body_bytes = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err(), "expected Err, got: {result:?}");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(_))
            ),
            "expected IdentityResolutionFailed(ExtensionMissing), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_errors_on_empty_body() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::A2a);
        ctx.body_bytes = Some(Bytes::new());

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(_))
            ),
            "expected IdentityResolutionFailed(ExtensionMissing), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_errors_on_invalid_json() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::A2a);
        ctx.body_bytes = Some(Bytes::from("not json"));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OutboundPipelineError::BodyReadFailed(_)), "expected BodyReadFailed, got: {err:?}");
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_errors_on_declared_but_missing() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::A2a);
        // A2A body: extension declared in extensions[] but missing from metadata
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": { "message": {
                    "extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"],
                    "metadata": {}
                }}
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        let err_msg = result
            .unwrap_err()
            .to_string();
        assert!(
            err_msg.contains("declared in extensions but missing"),
            "expected DeclaredButMissing message, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_errors_when_no_vc_issuer() {
        let mut state = test_outbound_state();
        state.vc_issuer = None;
        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::A2a);
        // Valid A2A body with agent-identity extension
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": { "message": { "metadata": {
                    "https://fabric.affinidi.io/extensions/agent-identity/v1": { "cloudProvider": "local" }
                }}}
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        let err_msg = result
            .unwrap_err()
            .to_string();
        assert!(err_msg.contains("VCIssuer"), "expected VCIssuer error, got: {err_msg}");
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_mcp_errors_when_no_vc_issuer() {
        let mut state = test_outbound_state();
        state.vc_issuer = None;
        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::Mcp);
        // MCP body with agentIdentity in _meta
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "_meta": { "agentIdentity": { "cloud": "local" } },
                    "name": "test-tool"
                }
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        // Reaches the vc_issuer check — meaning MCP extraction worked
        let err_msg = result
            .unwrap_err()
            .to_string();
        assert!(err_msg.contains("VCIssuer"), "expected VCIssuer error (MCP extraction succeeded), got: {err_msg}");
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_mcp_extension_missing() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::Mcp);
        // MCP body without _meta
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "test-tool" }
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(_))
            ),
            "expected IdentityResolutionFailed(ExtensionMissing), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_happy_path_a2a() {
        let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let mut state = test_outbound_state();
        state.vc_issuer = Some(Arc::new(vc_issuer));

        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::A2a);
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": { "message": { "metadata": {
                    "https://fabric.affinidi.io/extensions/agent-identity/v1": {
                        "cloudProvider": "local",
                        "model": "gpt-4"
                    }
                }}}
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        match &ctx.resolved_identity {
            ProtectedAgentIdentity::Managed { did, identity_fields } => {
                assert!(did.starts_with("did:"), "DID should start with 'did:', got: {did}");
                assert!(!identity_fields.is_empty(), "identity_fields should not be empty");
            }
            ProtectedAgentIdentity::Anonymous => {
                panic!("expected Managed identity, got Anonymous");
            }
        }
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_reads_transit_point_mapped_header_metadata() {
        let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let vc_issuer = Arc::new(vc_issuer);
        let mut state = test_outbound_state();
        state.vc_issuer = Some(vc_issuer.clone());

        let schema = crate::config::header_metadata_mapping::copilot_header_metadata_identity_schema();
        let selector = crate::identity::IdentitySelector::new(&schema, vc_issuer).unwrap();

        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::A2a);
        ctx.virtual_channel
            .header_metadata_mapping = Some(test_header_metadata_mapping(true));
        ctx.virtual_channel
            .managed_identity = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
            crate::source_auth::models::PayloadExtractionConfig {
                extension_uri: Some(
                    crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI.to_string(),
                ),
                meta_field: "agentIdentity".to_string(),
                fields: Vec::new(),
                json_schema: Some(schema),
                extension_rules: None,
                strip_raw_meta: false,
            },
        ));
        ctx.identity_selector = Some(Arc::new(selector));
        ctx.body_bytes = Some(a2a_message_body(json!({})));
        ctx.original_headers
            .insert("x-ms-entra-agent-id", HeaderValue::from_static("agent-123"));
        ctx.original_headers
            .insert("x-ms-client-tenant-id", HeaderValue::from_static("tenant-456"));

        step_map_transit_point_header_metadata(&state, &mut ctx)
            .await
            .expect("mapping should apply before identity resolution");
        step_resolve_agent_identity(&state, &mut ctx)
            .await
            .expect("mapped header metadata should resolve identity");

        match &ctx.resolved_identity {
            ProtectedAgentIdentity::Managed { did, identity_fields } => {
                assert!(did.starts_with("did:"), "DID should start with 'did:', got: {did}");
                assert_eq!(
                    identity_fields
                        .get("entra_agent_id")
                        .and_then(|value| value.as_str()),
                    Some("agent-123")
                );
                assert_eq!(
                    identity_fields
                        .get("client_tenant_id")
                        .and_then(|value| value.as_str()),
                    Some("tenant-456")
                );
            }
            ProtectedAgentIdentity::Anonymous => panic!("expected Managed identity, got Anonymous"),
        }
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_rejects_missing_required_mapped_header_metadata() {
        let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let vc_issuer = Arc::new(vc_issuer);
        let mut state = test_outbound_state();
        state.vc_issuer = Some(vc_issuer.clone());

        let schema = crate::config::header_metadata_mapping::copilot_header_metadata_identity_schema();
        let selector = crate::identity::IdentitySelector::new(&schema, vc_issuer).unwrap();

        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::A2a);
        ctx.virtual_channel
            .header_metadata_mapping = Some(test_header_metadata_mapping(true));
        ctx.virtual_channel
            .managed_identity = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
            crate::source_auth::models::PayloadExtractionConfig {
                extension_uri: Some(
                    crate::config::header_metadata_mapping::DEFAULT_HEADER_METADATA_EXTENSION_URI.to_string(),
                ),
                meta_field: "agentIdentity".to_string(),
                fields: Vec::new(),
                json_schema: Some(schema),
                extension_rules: None,
                strip_raw_meta: false,
            },
        ));
        ctx.identity_selector = Some(Arc::new(selector));
        ctx.body_bytes = Some(a2a_message_body(json!({})));
        ctx.original_headers
            .insert("x-ms-entra-agent-id", HeaderValue::from_static("agent-123"));

        step_map_transit_point_header_metadata(&state, &mut ctx)
            .await
            .expect("mapping should not reject missing optional headers");
        let err = step_resolve_agent_identity(&state, &mut ctx)
            .await
            .expect_err("identity schema should reject missing required tenant id");

        assert_eq!(err.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            matches!(
                err,
                OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::ExtensionMissing(_))
            ),
            "expected identity validation failure, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_with_selector_filters_extra_fields() {
        let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let vc_issuer = Arc::new(vc_issuer);
        let mut state = test_outbound_state();
        state.vc_issuer = Some(vc_issuer.clone());

        // Schema marks only "cloudProvider" as x-identity; "model" is a normal field
        let schema = json!({
            "type": "object",
            "properties": {
                "cloudProvider": {
                    "type": "string",
                    "x-identity": true
                },
                "model": {
                    "type": "string"
                }
            }
        });
        let selector = crate::identity::IdentitySelector::new(&schema, vc_issuer.clone()).unwrap();
        assert!(selector.has_identity_fields());

        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::A2a);
        ctx.identity_selector = Some(Arc::new(selector));

        // Payload has both "cloudProvider" (x-identity) and "model" (not x-identity)
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": { "message": { "metadata": {
                    "https://fabric.affinidi.io/extensions/agent-identity/v1": {
                        "cloudProvider": "aws",
                        "model": "gpt-4"
                    }
                }}}
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        match &ctx.resolved_identity {
            ProtectedAgentIdentity::Managed { did, identity_fields } => {
                assert!(did.starts_with("did:"), "DID should start with 'did:', got: {did}");
                // Only "cloudProvider" should be in identity_fields (marked x-identity)
                assert!(
                    identity_fields.contains_key("cloudProvider"),
                    "identity_fields should contain 'cloudProvider', got: {identity_fields:?}"
                );
                // "model" should NOT be in identity_fields (not marked x-identity)
                assert!(
                    !identity_fields.contains_key("model"),
                    "identity_fields should NOT contain 'model', got: {identity_fields:?}"
                );
                assert_eq!(identity_fields.len(), 1, "expected exactly 1 identity field, got: {identity_fields:?}");
            }
            ProtectedAgentIdentity::Anonymous => {
                panic!("expected Managed identity, got Anonymous");
            }
        }
    }

    #[tokio::test]
    async fn test_step_resolve_agent_identity_happy_path_mcp() {
        let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let mut state = test_outbound_state();
        state.vc_issuer = Some(Arc::new(vc_issuer));

        let mut ctx = test_pipeline_context();
        {
            let surface = Arc::make_mut(&mut ctx.surface);
            surface
                .identity_slots
                .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
                crate::source_auth::models::PayloadExtractionConfig {
                    extension_uri: None,
                    meta_field: "agentIdentity".to_string(),
                    fields: Vec::new(),
                    json_schema: None,
                    extension_rules: None,
                    strip_raw_meta: false,
                },
            ));
        }
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "_meta": { "agentIdentity": { "cloud": "local", "model": "gpt-4" } },
                    "name": "test-tool"
                }
            }))
            .unwrap(),
        ));

        let result = step_resolve_agent_identity(&state, &mut ctx).await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        match &ctx.resolved_identity {
            ProtectedAgentIdentity::Managed { did, identity_fields } => {
                assert!(did.starts_with("did:"), "DID should start with 'did:', got: {did}");
                assert!(!identity_fields.is_empty(), "identity_fields should not be empty");
            }
            ProtectedAgentIdentity::Anonymous => {
                panic!("expected Managed identity, got Anonymous");
            }
        }
    }

    // ── step_inject_custom_metadata ────────────────────────────────────────

    #[tokio::test]
    async fn test_step_inject_custom_metadata_noop_when_none() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.outbound_shared
            .custom_metadata = None;
        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_step_inject_custom_metadata_noop_when_disabled() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        let body = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","method":"tools/list","id":1})).unwrap();
        ctx.body_bytes = Some(bytes::Bytes::from(body.clone()));
        ctx.outbound_shared
            .custom_metadata = Some(crate::config::CustomMetadata {
            enabled: false,
            payload: Some(serde_json::json!({ "tenant": "acme" })),
            injection_target: None,
        });
        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert_eq!(ctx.body_bytes.unwrap(), bytes::Bytes::from(body));
    }

    fn mcp_custom_metadata(
        injection_target: Option<crate::config::MetadataInjectionTarget>
    ) -> crate::config::CustomMetadata {
        crate::config::CustomMetadata {
            enabled: true,
            payload: Some(serde_json::json!({ "env": "staging", "tenant_id": "t123" })),
            injection_target,
        }
    }

    fn disabled_mcp_custom_metadata(
        injection_target: Option<crate::config::MetadataInjectionTarget>
    ) -> crate::config::CustomMetadata {
        crate::config::CustomMetadata {
            enabled: false,
            payload: Some(serde_json::json!({ "env": "staging", "tenant_id": "t123" })),
            injection_target,
        }
    }

    fn mcp_body() -> bytes::Bytes {
        bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "echo", "arguments": {} }
            }))
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_step_inject_custom_metadata_mcp_meta_only() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx.body_bytes = Some(mcp_body());
        ctx.outbound_shared
            .custom_metadata = Some(mcp_custom_metadata(Some(crate::config::MetadataInjectionTarget::Meta)));

        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(result.is_ok());

        let body: serde_json::Value = serde_json::from_slice(
            ctx.body_bytes
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["_meta"]["env"].as_str(), Some("staging"), "_meta.env should be injected at root");
        assert_eq!(body["_meta"]["tenant_id"].as_str(), Some("t123"), "_meta.tenant_id should be injected at root");
        assert!(body["params"]["_meta"].is_null(), "_meta should not be nested inside params");

        assert!(
            ctx.original_headers
                .get("x-gateway-env")
                .is_none(),
            "no HTTP header should be injected for Meta-only target"
        );
    }

    #[tokio::test]
    async fn test_step_inject_custom_metadata_mcp_skips_when_disabled() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::Mcp);
        let original_body = mcp_body();
        ctx.body_bytes = Some(original_body.clone());
        ctx.outbound_shared
            .custom_metadata = Some(disabled_mcp_custom_metadata(Some(crate::config::MetadataInjectionTarget::Both)));

        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert_eq!(
            ctx.body_bytes.as_deref(),
            Some(original_body.as_ref()),
            "disabled metadata should not modify the body"
        );
        assert!(
            ctx.original_headers
                .get("x-gateway-env")
                .is_none(),
            "disabled metadata should not inject headers"
        );
    }

    #[tokio::test]
    async fn test_step_inject_custom_metadata_a2a_skips_when_disabled_before_parsing_body() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::A2a);
        let original_body = Bytes::from("not json");
        ctx.body_bytes = Some(original_body.clone());
        ctx.outbound_shared
            .custom_metadata = Some(disabled_mcp_custom_metadata(None));

        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert_eq!(
            ctx.body_bytes.as_deref(),
            Some(original_body.as_ref()),
            "disabled metadata should skip before A2A body parsing"
        );
    }

    #[tokio::test]
    async fn test_step_inject_custom_metadata_mcp_errors_when_requested_meta_cannot_be_injected() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx.body_bytes = Some(Bytes::from("not json"));
        ctx.outbound_shared
            .custom_metadata = Some(mcp_custom_metadata(Some(crate::config::MetadataInjectionTarget::Meta)));

        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(
            matches!(result, Err(OutboundPipelineError::MetadataInjectionFailed)),
            "expected MetadataInjectionFailed, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_step_inject_custom_metadata_mcp_headers_only() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx.body_bytes = Some(mcp_body());
        ctx.outbound_shared
            .custom_metadata = Some(mcp_custom_metadata(Some(crate::config::MetadataInjectionTarget::Headers)));

        let original_body = mcp_body();
        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(result.is_ok());

        assert_eq!(
            ctx.original_headers
                .get("x-gateway-env")
                .and_then(|v| v.to_str().ok()),
            Some("staging"),
            "X-Gateway-env header should be injected"
        );
        assert_eq!(
            ctx.original_headers
                .get("x-gateway-tenant-id")
                .and_then(|v| v.to_str().ok()),
            Some("t123"),
            "X-Gateway-tenant-id header should be injected"
        );

        assert_eq!(
            ctx.body_bytes.as_deref(),
            Some(original_body.as_ref()),
            "body should be unchanged for Headers-only target"
        );
    }

    #[tokio::test]
    async fn test_step_inject_custom_metadata_mcp_both() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx.body_bytes = Some(mcp_body());
        ctx.outbound_shared
            .custom_metadata = Some(mcp_custom_metadata(Some(crate::config::MetadataInjectionTarget::Both)));

        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(result.is_ok());

        let body: serde_json::Value = serde_json::from_slice(
            ctx.body_bytes
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["_meta"]["env"].as_str(), Some("staging"), "_meta.env should be injected");
        assert_eq!(
            ctx.original_headers
                .get("x-gateway-env")
                .and_then(|v| v.to_str().ok()),
            Some("staging"),
            "X-Gateway-env header should be injected"
        );
    }

    #[tokio::test]
    async fn test_step_inject_custom_metadata_mcp_default_target_injects_both() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::Mcp);
        ctx.body_bytes = Some(mcp_body());
        ctx.outbound_shared
            .custom_metadata = Some(mcp_custom_metadata(None));

        let result = step_inject_custom_metadata(&state, &mut ctx).await;
        assert!(result.is_ok());

        let body: serde_json::Value = serde_json::from_slice(
            ctx.body_bytes
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["_meta"]["env"].as_str(), Some("staging"), "default: _meta.env should be injected");
        assert_eq!(
            ctx.original_headers
                .get("x-gateway-env")
                .and_then(|v| v.to_str().ok()),
            Some("staging"),
            "default: X-Gateway-env header should be injected"
        );
    }

    // ── step_inject_trusted_identity ──────────────────────────────────────

    #[tokio::test]
    async fn test_step_inject_trusted_identity_skips_when_anonymous() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        // resolved_identity is Anonymous by default → skip
        ctx.body_bytes = Some(Bytes::from(r#"{"jsonrpc":"2.0"}"#));

        let result = step_inject_trusted_identity(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert_eq!(
            ctx.body_bytes
                .as_ref()
                .map(|b| b.as_ref()),
            Some(r#"{"jsonrpc":"2.0"}"#.as_bytes())
        );
    }

    #[tokio::test]
    async fn test_step_inject_trusted_identity_errors_unsupported_protocol() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::DIDComm);
        ctx.body_bytes = Some(Bytes::from(r#"{"data":"test"}"#));
        ctx.resolved_identity = ProtectedAgentIdentity::Managed {
            did: "did:web:test".to_string(),
            identity_fields: std::collections::HashMap::new(),
        };

        let result = step_inject_trusted_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OutboundPipelineError::IdentityInjectionFailed(_)),
            "expected IdentityInjectionFailed, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_step_inject_trusted_identity_errors_when_no_vc_issuer() {
        let mut state = test_outbound_state();
        state.vc_issuer = None;
        let mut ctx = test_pipeline_context();
        ctx.protocol = Some(ChannelProtocol::A2a);
        ctx.body_bytes = Some(Bytes::from(r#"{"jsonrpc":"2.0"}"#));
        ctx.resolved_identity = ProtectedAgentIdentity::Managed {
            did: "did:web:test".to_string(),
            identity_fields: std::collections::HashMap::new(),
        };

        let result = step_inject_trusted_identity(&state, &mut ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OutboundPipelineError::IdentityInjectionFailed(_)),
            "expected IdentityInjectionFailed, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn the_transit_point_vp_injection_record_names_the_transit_caller() {
        let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let mut state = test_outbound_state();
        state.vc_issuer = Some(Arc::new(vc_issuer));
        let mut ctx = test_pipeline_context();
        Arc::make_mut(&mut ctx.surface)
            .identity_slots
            .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
            crate::source_auth::models::PayloadExtractionConfig {
                extension_uri: None,
                meta_field: "agentIdentity".to_string(),
                fields: Vec::new(),
                json_schema: None,
                extension_rules: None,
                strip_raw_meta: false,
            },
        ));
        ctx.protocol = Some(ChannelProtocol::A2a);
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": { "message": { "metadata": {
                    "https://fabric.affinidi.io/extensions/agent-identity/v1": { "cloudProvider": "local", "model": "gpt-4" }
                }}}
            }))
            .unwrap(),
        ));
        step_resolve_agent_identity(&state, &mut ctx)
            .await
            .unwrap();
        ctx.transit_token_claims = Some(crate::proxy::transit_token::TransitTokenClaims {
            iss: "gw".to_string(),
            sub: None,
            surface_id: "surf-001".to_string(),
            iat: 0,
            exp: u64::MAX,
            jti: "jti".to_string(),
            identity_source: None,
            caller_dna_uai: None,
            user_identity_hash: None,
            caller_context_fields: serde_json::Map::from_iter([("email".to_string(), json!("ada@example.com"))]),
            allowed_transit_points: vec![],
            trace_id: None,
        });

        let (result, events) =
            crate::audit::producer::capture(async { step_inject_trusted_identity(&state, &mut ctx).await }).await;

        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        let injected: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.event, crate::delegation_vault::audit::DelegationAuditAction::VpInjected))
            .collect();
        assert_eq!(injected.len(), 1);
        assert_eq!(injected[0].detail.as_deref(), Some("transit_point"));
        assert_eq!(
            injected[0]
                .caller
                .as_ref()
                .and_then(|caller| caller.email.as_deref()),
            Some("ada@example.com")
        );
    }

    // ── step_collect_trust_context ─────────────────────────────────────────

    #[tokio::test]
    async fn test_step_collect_trust_context_noop_when_none() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        let result = step_collect_trust_context(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert!(
            ctx.target_agent_context
                .is_none()
        );
    }

    // ── step_gateway_opa_policy ────────────────────────────────────────────

    #[tokio::test]
    async fn test_step_gateway_opa_noop_when_not_configured() {
        let mut state = test_outbound_state();
        state.gateway_policy_manager = None;
        let mut ctx = test_pipeline_context();
        let result = step_gateway_opa_policy(&state, &mut ctx).await;
        assert!(result.is_ok());
    }

    // ── step_surface_opa_policy ────────────────────────────────────────────

    #[tokio::test]
    async fn test_step_surface_opa_noop_when_not_configured() {
        let mut state = test_outbound_state();
        state.policy_manager = None;
        let mut ctx = test_pipeline_context();
        ctx.outbound_shared
            .opa_policy_definition_id = None;
        let result = step_surface_opa_policy(&state, &mut ctx).await;
        assert!(result.is_ok());
    }

    /// Run `step_surface_opa_policy` with a policy definition configured and
    /// return the pipeline result plus the recorded decisions.
    async fn surface_opa_outcome(
        manager: Option<Arc<crate::policies::SurfacePolicyManager>>
    ) -> (Result<(), OutboundPipelineError>, Vec<crate::observability::policy_audit::PolicyDecisionSummary>) {
        use crate::observability::policy_audit::POLICY_DECISION_COLLECTOR;
        use std::sync::Mutex;

        let mut state = test_outbound_state();
        state.policy_manager = manager;
        let mut ctx = test_pipeline_context();
        ctx.outbound_shared
            .opa_policy_definition_id = Some("def-out-1".to_string());
        let collector = Arc::new(Mutex::new(Vec::new()));
        let result = POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), step_surface_opa_policy(&state, &mut ctx))
            .await;
        let decisions = collector
            .lock()
            .unwrap()
            .clone();
        (result, decisions)
    }

    fn assert_error_decision(
        result: Result<(), OutboundPipelineError>,
        decisions: &[crate::observability::policy_audit::PolicyDecisionSummary],
        expected: crate::observability::PolicyEvaluationError,
    ) {
        let err = result.expect_err("a policy that could not decide fails closed");
        assert!(
            matches!(err, OutboundPipelineError::SurfacePolicyError(e) if e == expected),
            "expected SurfacePolicyError({expected:?}), got {err:?}"
        );
        assert_eq!(err.to_string(), "Request blocked by surface policy", "no engine detail for the caller");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].decision, "error");
        assert_eq!(
            decisions[0]
                .deny_reason
                .as_deref(),
            Some(expected.as_str())
        );
    }

    #[tokio::test]
    async fn surface_opa_without_policy_manager_records_an_error_decision() {
        let (result, decisions) = surface_opa_outcome(None).await;
        assert_error_decision(result, &decisions, crate::observability::PolicyEvaluationError::NoPolicyManager);
    }

    #[tokio::test]
    async fn surface_opa_without_compiled_policy_records_an_error_decision() {
        let manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        let (result, decisions) = surface_opa_outcome(Some(manager)).await;
        assert_error_decision(result, &decisions, crate::observability::PolicyEvaluationError::PolicyNotCompiled);
    }

    #[tokio::test]
    async fn surface_opa_evaluation_error_records_an_error_decision() {
        let manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        let config_id = test_pipeline_context()
            .surface
            .config_id()
            .unwrap_or("unknown")
            .to_string();
        // Compiles, but `allow` gets two values for every input.
        manager
            .load_policy_text(
                &format!("outbound:{config_id}"),
                "package surface.policy\n\nallow := true if {\n    true\n}\n\nallow := false if {\n    true\n}\n",
            )
            .unwrap();
        let (result, decisions) = surface_opa_outcome(Some(manager)).await;
        assert_error_decision(result, &decisions, crate::observability::PolicyEvaluationError::EvaluationError);
    }

    // ── step_record_metrics ────────────────────────────────────────────────

    #[test]
    fn test_step_record_metrics_noop_when_no_metrics() {
        let mut state = test_outbound_state();
        state.metrics_store = None;
        let ctx = test_pipeline_context();
        step_record_metrics(&state, &ctx, true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transit_point_records_a_target_error_as_a_failed_call() {
        for (target_status, recorded) in [
            (StatusCode::OK, crate::metrics::ConnectionStatus::Success),
            (StatusCode::UNAUTHORIZED, crate::metrics::ConnectionStatus::Failed),
            (StatusCode::BAD_GATEWAY, crate::metrics::ConnectionStatus::Failed),
        ] {
            let target = crate::component_tests::helpers::RecordingTarget::start(target_status, &[]).await;
            let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
            let mut state = test_outbound_state();
            state.metrics_store = Some(metrics.clone());
            state
                .channel_state
                .write()
                .unwrap()
                .surface = Arc::new(transit_surface(
                json!([{"alias": "partner", "protocol": "http", "require_transit_token": false,
                    "allow_unauthenticated_callers": true, "target_endpoint": target.url}]),
                json!([]),
            ));
            let request = Request::builder()
                .method("POST")
                .uri("/outbound/mcp/partner")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"ping":true}"#))
                .unwrap();

            let response = Box::pin(outbound_proxy_handler_with_mcp_versions(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                state,
                request,
                crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            ))
            .await
            .unwrap();
            assert_eq!(response.status(), target_status);

            let mut connections = Vec::new();
            for _ in 0..50 {
                connections = metrics
                    .get_recent_connections(10)
                    .await;
                if !connections.is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert_eq!(connections.len(), 1, "{target_status}");
            assert_eq!(connections[0].status, recorded, "{target_status}");
        }
    }

    /// A `2026-07-28` MCP response stream that fails part way through is
    /// recorded as a failed call, and one that completes as a successful call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transit_point_records_a_modern_stream_that_fails_as_a_failed_call() {
        let event = |message: serde_json::Value| {
            Ok::<_, std::io::Error>(Bytes::from(format!("event: message\ndata: {message}\n\n")))
        };
        let progress = json!({"jsonrpc": "2.0", "method": "notifications/progress",
            "params": {"progressToken": "work", "progress": 1}});
        let result = json!({"jsonrpc": "2.0", "id": "stream", "result": {"resultType": "complete", "content": []}});
        for (case, events, recorded) in [
            (
                "fails",
                vec![event(progress.clone()), Err(std::io::Error::other("the target reset the stream"))],
                crate::metrics::ConnectionStatus::Failed,
            ),
            (
                "completes",
                vec![event(progress.clone()), event(result.clone())],
                crate::metrics::ConnectionStatus::Success,
            ),
        ] {
            let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
            let mut state = test_outbound_state();
            state.metrics_store = Some(metrics.clone());
            let upstream = reqwest::Response::from(
                axum::http::Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(reqwest::Body::wrap_stream(futures::stream::iter(events)))
                    .unwrap(),
            );

            let response = process_modern_outbound_response(
                state,
                modern_pipeline_context("tools/call"),
                UpstreamResponse::Http(upstream),
            )
            .await
            .unwrap();
            let read = axum::body::to_bytes(response.into_body(), usize::MAX).await;
            assert_eq!(read.is_ok(), recorded == crate::metrics::ConnectionStatus::Success, "{case}: {read:?}");

            let mut connections = Vec::new();
            for _ in 0..50 {
                connections = metrics
                    .get_recent_connections(10)
                    .await;
                if !connections.is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert_eq!(connections.len(), 1, "{case}");
            assert_eq!(connections[0].status, recorded, "{case}");
        }
    }

    // ── build_outbound_policy_input ────────────────────────────────────────

    #[test]
    fn test_build_outbound_policy_input() {
        let mut ctx = test_pipeline_context();
        ctx.resolved_identity = ProtectedAgentIdentity::Managed {
            did: "did:web:my-agent.example.com".to_string(),
            identity_fields: std::collections::HashMap::new(),
        };
        ctx.protocol = Some(ChannelProtocol::A2a);

        let input = build_outbound_policy_input(&ctx);
        assert_eq!(
            input
                .gateway
                .as_ref()
                .unwrap()
                .direction,
            "outbound"
        );
        assert_eq!(
            input
                .gateway
                .as_ref()
                .unwrap()
                .source_id
                .as_deref(),
            Some("did:web:my-agent.example.com")
        );
        assert_eq!(
            input
                .gateway
                .as_ref()
                .unwrap()
                .target_id
                .as_deref(),
            Some("https://partner.example.com/a2a")
        );
        assert_eq!(
            input
                .channel
                .as_ref()
                .unwrap()
                .name
                .as_deref(),
            Some("test-channel")
        );
    }

    fn caller_claims(
        sub: Option<&str>,
        identity_source: Option<&str>,
        user_identity_hash: Option<&str>,
        fields: serde_json::Value,
    ) -> crate::proxy::transit_token::TransitTokenClaims {
        crate::proxy::transit_token::TransitTokenClaims {
            iss: "gw".to_string(),
            sub: sub.map(str::to_string),
            surface_id: "s".to_string(),
            iat: 0,
            exp: u64::MAX,
            jti: "jti".to_string(),
            identity_source: identity_source.map(str::to_string),
            caller_dna_uai: Some("uai:1".to_string()),
            user_identity_hash: user_identity_hash.map(str::to_string),
            caller_context_fields: fields
                .as_object()
                .cloned()
                .unwrap_or_default(),
            allowed_transit_points: vec![],
            trace_id: None,
        }
    }

    fn transit_caller_json(ctx: &OutboundPipelineContext) -> serde_json::Value {
        serde_json::to_value(build_outbound_policy_input(ctx)).unwrap()["transit"]["caller"].clone()
    }

    #[test]
    fn outbound_policy_input_says_a_call_with_no_caller_is_anonymous() {
        let ctx = test_pipeline_context();
        assert_eq!(transit_caller_json(&ctx), json!({ "verified": false, "verification": "anonymous" }));
    }

    #[test]
    fn a_tool_gating_condition_reads_the_transit_caller() {
        // Hides `admin_*` unless the caller is verified; written so an absent
        // `input.transit` keeps the deny gate active.
        let config: crate::config::agent_surface::McpToolGatingConfig = serde_json::from_value(json!({
            "gates": [{
                "id": "g1", "name": "admin for verified callers",
                "condition_policy_definition_id": "unverified-caller",
                "action": { "effect": "deny", "patterns": ["^admin_"] }
            }]
        }))
        .unwrap();
        let gating = crate::policies::mcp_tool_gating::CompiledMcpToolGating::build(&config, |_| {
            Some(
                "package surface.policy\n\ndefault allow := true\n\nallow := false if {\n    input.transit.caller.verified\n}\n"
                    .to_string(),
            )
        });

        let mut ctx = test_pipeline_context();
        let anonymous = serde_json::to_value(build_outbound_policy_input(&ctx)).unwrap();
        assert!(!gating.is_tool_call_allowed("admin_reset", &anonymous));

        ctx.transit_token_claims = Some(caller_claims(None, Some("gateway-computed"), Some("abc123"), json!({})));
        let verified = serde_json::to_value(build_outbound_policy_input(&ctx)).unwrap();
        assert!(gating.is_tool_call_allowed("admin_reset", &verified));
    }

    fn allowlist_caller_fields(
        point: &mut TransitPoint,
        fields: &[&str],
    ) {
        point.workload_binding = Some(
            serde_json::from_value(json!({
                "enabled": true, "caller_source": "transit_token", "caller_context_fields": fields
            }))
            .unwrap(),
        );
    }

    #[test]
    fn outbound_policy_input_carries_the_verified_caller_of_a_transit_token() {
        let mut ctx = test_pipeline_context();
        allowlist_caller_fields(&mut ctx.virtual_channel, &["email"]);
        ctx.transit_token_claims = Some(caller_claims(
            Some("did:example:alice-agent"),
            Some("self-presented"),
            Some("abc123"),
            json!({ "email": "alice@example.com" }),
        ));
        assert_eq!(
            transit_caller_json(&ctx),
            json!({
                "verified": true,
                "verification": "transit_token",
                "identity_source": "self-presented",
                "user_identity_hash": "abc123",
                "did": "did:example:alice-agent",
                "fields": { "email": "alice@example.com" }
            })
        );
    }

    /// The transit token carries the fields every Transit Point of the surface
    /// allowlists; a Transit Point's policy sees only those it allowlists itself.
    #[test]
    fn outbound_policy_input_carries_only_the_fields_this_transit_point_allowlists() {
        let mut ctx = test_pipeline_context();
        ctx.transit_token_claims = Some(caller_claims(
            None,
            Some("gateway-computed"),
            Some("abc123"),
            json!({ "email": "alice@example.com", "tid": "tenant-1" }),
        ));
        allowlist_caller_fields(&mut ctx.virtual_channel, &["tid"]);
        assert_eq!(transit_caller_json(&ctx)["fields"], json!({ "tid": "tenant-1" }));

        ctx.virtual_channel
            .workload_binding = None;
        assert!(
            transit_caller_json(&ctx)
                .get("fields")
                .is_none(),
            "{}",
            transit_caller_json(&ctx)
        );

        allowlist_caller_fields(&mut ctx.virtual_channel, &["email", "tid"]);
        ctx.virtual_channel
            .workload_binding
            .as_mut()
            .unwrap()
            .enabled = false;
        assert!(
            transit_caller_json(&ctx)
                .get("fields")
                .is_none(),
            "a disabled binding allowlists nothing"
        );
    }

    /// Nothing verifies a DID presentation or an Agent DNA UAI yet, so a token
    /// that claims either must not reach policy as a verified-looking value.
    #[test]
    fn outbound_policy_input_omits_a_claimed_did_verification_and_dna_uai() {
        let mut ctx = test_pipeline_context();
        ctx.transit_token_claims = Some(caller_claims(
            Some("did:example:alice-agent"),
            Some("verified-presentation"),
            Some("abc123"),
            json!({}),
        ));
        let caller = transit_caller_json(&ctx);
        assert_eq!(caller["did"], "did:example:alice-agent");
        assert!(
            caller
                .get("did_verified")
                .is_none(),
            "{caller}"
        );
        assert!(
            caller
                .get("caller_dna_uai")
                .is_none(),
            "{caller}"
        );
    }

    #[test]
    fn outbound_policy_input_does_not_verify_a_token_that_only_names_a_did() {
        let mut ctx = test_pipeline_context();
        ctx.transit_token_claims = Some(caller_claims(
            Some("did:example:claimed"),
            Some("self-presented"),
            None,
            json!({ "email": "claimed@example.com" }),
        ));
        assert_eq!(
            transit_caller_json(&ctx),
            json!({
                "verified": false,
                "verification": "unverified",
                "identity_source": "self-presented",
                "did": "did:example:claimed"
            })
        );
    }

    fn transit_client_json(ctx: &OutboundPipelineContext) -> serde_json::Value {
        serde_json::to_value(build_outbound_policy_input(ctx)).unwrap()["transit"]["client"].clone()
    }

    fn authenticate_by_resource_token(
        ctx: &mut OutboundPipelineContext,
        identity: crate::source_auth::AuthenticatedIdentity,
    ) {
        ctx.authenticated_identity = Some(identity);
        ctx.authenticated_by = Some(crate::surface_context::TransitClientVerification::ResourceToken);
    }

    /// A transit token that names no verified end user is not replaced by the
    /// client the Transit Point authenticated: that client's grant belongs to
    /// the client, not to an end user the Access Point could not identify.
    #[test]
    fn delegation_keys_on_the_transit_point_client_only_when_no_token_names_the_caller() {
        let mut ctx = test_pipeline_context();
        ctx.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::ApiKey {
            key_name: "copilot-studio".to_string(),
            provider_agent_id: None,
        });
        ctx.authenticated_by = Some(crate::surface_context::TransitClientVerification::SourceAuth);
        let client_hash = delegation_caller_hash(&ctx).expect("a client the Transit Point verified keys its grant");

        ctx.transit_token_claims = Some(caller_claims(None, Some("gateway-computed"), None, json!({})));
        assert_eq!(delegation_caller_hash(&ctx), None, "a token with no verified end user refuses, not falls back");

        ctx.transit_token_claims = Some(caller_claims(None, Some("gateway-computed"), Some("abc123"), json!({})));
        assert_eq!(delegation_caller_hash(&ctx).as_deref(), Some("abc123"));
        assert_ne!(Some("abc123"), Some(client_hash.as_str()));
    }

    /// Delegated credentials on a `2026-07-28` MCP request are keyed through the
    /// Transit Point's resource-server authorization. A Transit Point cannot have
    /// both that and `source_auth`, so a caller its `source_auth` verified, or one
    /// only a transit token names, is refused there, while the legacy path keys a
    /// `source_auth` caller by its identity hash.
    #[tokio::test]
    async fn a_modern_mcp_request_from_a_source_auth_caller_cannot_use_delegated_credentials() {
        use crate::mcp::continuations::ContinuationError;
        use crate::mcp::continuations::negative_cases::continuation_runtime;
        use crate::mcp::request_validation::{McpMessageKind, ValidatedModernMessage};
        use crate::proxy::credential_delegation::modern::{ModernDelegationError, prepare_transit};

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let runtime = continuation_runtime(now, 60);
        let request = ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: None,
            client_info: None,
            method: "tools/call".into(),
            params: None,
            id: Some(json!(1)),
            kind: McpMessageKind::Request,
        };
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::ApiKey {
            key_name: "copilot-studio".to_string(),
            provider_agent_id: None,
        });
        ctx.authenticated_by = Some(crate::surface_context::TransitClientVerification::SourceAuth);
        assert!(
            delegation_caller_hash(&ctx).is_some(),
            "the legacy path keys this caller by its identity hash when no transit token names one"
        );
        ctx.transit_token_claims = Some(caller_claims(Some("did:example:agent"), None, None, json!({})));
        assert!(
            ctx.mcp_resource_authorization
                .is_none()
        );

        let refused = prepare_transit(&state, &runtime, &mut ctx, &request)
            .await
            .err()
            .expect("the modern path refuses without a resource-server authorization");
        assert!(matches!(refused, ModernDelegationError::Continuation(ContinuationError::BindingMismatch)));

        ctx.authenticated_identity = None;
        ctx.authenticated_by = None;
        ctx.transit_token_claims =
            Some(caller_claims(Some("did:example:agent"), Some("gateway-computed"), Some("abc123"), json!({})));
        let refused = prepare_transit(&state, &runtime, &mut ctx, &request)
            .await
            .err()
            .expect("a caller only a transit token names is refused on the modern path too");
        assert!(matches!(refused, ModernDelegationError::Continuation(ContinuationError::BindingMismatch)));
    }

    fn bearer_workload_binding() -> crate::config::types::WorkloadBindingConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "caller_source": "authorization_bearer_jwt",
            "caller_context_fields": ["tid"]
        }))
        .unwrap()
    }

    fn unverified_bearer(claims: serde_json::Value) -> axum::http::HeaderValue {
        use base64::Engine as _;
        let b64 = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
        axum::http::HeaderValue::from_str(&format!(
            "Bearer {}.{}.sig",
            b64(br#"{"alg":"none"}"#),
            b64(claims.to_string().as_bytes())
        ))
        .unwrap()
    }

    /// A Workload Binding that reads the caller's bearer JWT binds the claims the
    /// Transit Point's own authentication verified, whichever header or method
    /// carried them, and never those of an `Authorization` header nothing verified.
    #[test]
    fn a_bearer_workload_binding_reads_the_claims_the_transit_point_verified() {
        let config = bearer_workload_binding();
        let mut ctx = test_pipeline_context();
        ctx.original_headers
            .insert(axum::http::header::AUTHORIZATION, unverified_bearer(json!({ "tid": "forged" })));

        ctx.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            claims: json!({ "iss": "https://idp.example", "sub": "alice", "tid": "contoso" }),
        });
        ctx.authenticated_by = Some(crate::surface_context::TransitClientVerification::SourceAuth);
        let captured = capture_workload_binding_caller(&ctx, &config).expect("a verified JWT caller is captured");
        assert_eq!(captured.fields.get("tid"), Some(&json!("contoso")), "the verified claims win over the header");
        assert_eq!(captured.fields.len(), 1, "only the allowlisted claim is bound");

        ctx.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::ApiKey {
            key_name: "copilot-studio".to_string(),
            provider_agent_id: None,
        });
        assert!(
            capture_workload_binding_caller(&ctx, &config).is_none(),
            "a caller verified another way binds nothing from a header the gateway did not verify"
        );
    }

    #[test]
    fn a_bearer_workload_binding_reads_the_header_when_the_transit_point_authenticates_no_caller() {
        let config = bearer_workload_binding();
        let mut ctx = test_pipeline_context();
        assert!(capture_workload_binding_caller(&ctx, &config).is_none(), "no credential, nothing to bind");
        ctx.original_headers
            .insert(axum::http::header::AUTHORIZATION, unverified_bearer(json!({ "tid": "contoso" })));
        let captured = capture_workload_binding_caller(&ctx, &config).expect("the header is read");
        assert_eq!(captured.fields.get("tid"), Some(&json!("contoso")));
    }

    #[test]
    fn outbound_policy_input_carries_a_client_the_transit_points_source_auth_verified() {
        let mut ctx = test_pipeline_context();
        ctx.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            claims: json!({ "iss": "https://idp.example", "sub": "alice", "tid": "tenant-1" }),
        });
        ctx.authenticated_by = Some(crate::surface_context::TransitClientVerification::SourceAuth);
        Arc::make_mut(&mut ctx.surface).tenant_id = Some("tenant-a".to_string());
        assert_eq!(
            transit_client_json(&ctx),
            json!({
                "verification": "source_auth",
                "method": "jwt_bearer",
                "user_identity_hash": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                    br#"["jwt_bearer","https://idp.example","tenant-a","alice"]"#
                )),
                "subject": "alice"
            })
        );
        assert_eq!(
            serde_json::to_value(build_outbound_policy_input(&ctx).source_auth).unwrap()["claims"]["tid"],
            "tenant-1",
            "the verified token's claims stay in input.source_auth"
        );
        assert_eq!(transit_caller_json(&ctx)["verification"], "anonymous", "the client is not the caller");

        ctx.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "<none>".to_string(),
            claims: json!({ "iss": "https://idp.example", "client_id": "no-subject" }),
        });
        assert_eq!(
            transit_client_json(&ctx),
            json!({ "verification": "source_auth", "method": "jwt_bearer" }),
            "a token that names no subject has neither a hash nor a subject"
        );
    }

    #[test]
    fn outbound_policy_input_carries_the_client_the_transit_point_authenticated() {
        let mut ctx = test_pipeline_context();
        authenticate_by_resource_token(
            &mut ctx,
            crate::source_auth::AuthenticatedIdentity::JwtBearer {
                subject: "alice".to_string(),
                claims: json!({ "iss": "https://idp.example", "sub": "alice" }),
            },
        );
        assert_eq!(
            transit_client_json(&ctx),
            json!({
                "verification": "resource_token",
                "method": "jwt_bearer",
                "user_identity_hash": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                    br#"["jwt_bearer","https://idp.example",null,"alice"]"#
                )),
                "subject": "alice"
            })
        );
        assert_eq!(transit_caller_json(&ctx)["verification"], "anonymous", "the client is not the end user");
    }

    /// The end user a transit token names and the client the Transit Point
    /// authenticated are both verified, and a policy sees each in its own field.
    #[test]
    fn outbound_policy_input_keeps_the_transit_token_caller_and_the_client_apart() {
        let mut ctx = test_pipeline_context();
        authenticate_by_resource_token(
            &mut ctx,
            crate::source_auth::AuthenticatedIdentity::ApiKey {
                key_name: "cloud-agent".to_string(),
                provider_agent_id: None,
            },
        );
        ctx.transit_token_claims = Some(caller_claims(None, Some("gateway-computed"), Some("abc123"), json!({})));
        let caller = transit_caller_json(&ctx);
        assert_eq!(caller["verification"], "transit_token");
        assert_eq!(caller["user_identity_hash"], "abc123");
        let client = transit_client_json(&ctx);
        assert_eq!(client["verification"], "resource_token");
        assert_eq!(client["method"], "api_key");
        assert_eq!(client["subject"], "cloud-agent");

        ctx.transit_token_claims = Some(caller_claims(Some("did:example:claimed"), None, None, json!({})));
        assert_eq!(transit_caller_json(&ctx)["verification"], "unverified");
        assert_eq!(transit_client_json(&ctx)["subject"], "cloud-agent");
    }

    /// An identity set without the mechanism that authenticated it is never
    /// reported, so it cannot be mislabelled.
    #[test]
    fn outbound_policy_input_omits_an_identity_without_its_mechanism() {
        let mut ctx = test_pipeline_context();
        ctx.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::ApiKey {
            key_name: "cloud-agent".to_string(),
            provider_agent_id: None,
        });
        assert!(transit_client_json(&ctx).is_null());
        assert_eq!(transit_caller_json(&ctx)["verification"], "anonymous");
    }

    /// A Transit Point response policy reads the caller as its request policies
    /// do, so a deny-list rule on an anonymous caller holds the response back
    /// and one on a claim of the verified caller sees that claim.
    #[test]
    fn a_transit_point_response_policy_sees_the_caller_of_the_call() {
        let decide = |ctx: &mut OutboundPipelineContext, rego: &str| {
            ctx.virtual_channel
                .response_policy = Some(serde_json::from_value(json!({"policy_definition_id": "response"})).unwrap());
            let manager = crate::policies::SurfacePolicyManager::new();
            let key = format!(
                "response:transit:{}:{}",
                ctx.surface
                    .config_id()
                    .unwrap_or("unknown"),
                ctx.virtual_channel.alias
            );
            manager
                .load_policy_text(&key, rego)
                .unwrap();
            let mut state = test_outbound_state();
            state.policy_manager = Some(Arc::new(manager));
            step_transit_point_response_policy(
                &state,
                ctx,
                StatusCode::OK,
                &Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
                &reqwest::header::HeaderMap::new(),
                &crate::policies::PolicyAttestation::default(),
            )
            .is_ok()
        };
        let refuse_anonymous = "package surface.policy\n\ndefault allow := true\n\n\
                                allow := false if input.transit.caller.verification == \"anonymous\"\n";
        let only_tenant = "package surface.policy\n\ndefault allow := false\n\n\
                           allow if {\n    input.transit.client.verification == \"resource_token\"\n    \
                           input.source_auth.claims.tid == \"tenant-1\"\n}\n";

        let mut anonymous = test_pipeline_context();
        assert!(!decide(&mut anonymous, refuse_anonymous), "the response to an anonymous caller is held back");

        let mut verified = test_pipeline_context();
        verified.transit_token_claims = Some(caller_claims(None, Some("gateway-computed"), Some("abc123"), json!({})));
        assert!(decide(&mut verified, refuse_anonymous), "the response to a verified caller is released");

        let mut resource_caller = test_pipeline_context();
        authenticate_by_resource_token(
            &mut resource_caller,
            crate::source_auth::AuthenticatedIdentity::JwtBearer {
                subject: "alice".to_string(),
                claims: json!({ "sub": "alice", "tid": "tenant-1" }),
            },
        );
        assert!(decide(&mut resource_caller, only_tenant), "the verified client's claims reach the response policy");
        assert!(!decide(&mut anonymous, only_tenant));
    }

    #[test]
    fn build_outbound_policy_input_includes_only_non_sensitive_headers() {
        let mut ctx = test_pipeline_context();
        ctx.original_headers
            .insert("x-signal-id", HeaderValue::from_static("TA-CVE-2023-29300"));
        ctx.original_headers
            .insert("x-tlp", HeaderValue::from_static("GREEN"));
        ctx.original_headers
            .insert("authorization", HeaderValue::from_static("Bearer secret"));
        ctx.original_headers
            .insert("proxy-authorization", HeaderValue::from_static("Bearer proxy-secret"));
        ctx.original_headers
            .insert("cookie", HeaderValue::from_static("session_id=secret"));
        ctx.original_headers
            .insert("set-cookie", HeaderValue::from_static("session_id=secret"));
        ctx.original_headers
            .insert("x-transit-token", HeaderValue::from_static("transit-secret"));
        ctx.original_headers
            .insert("x-api-key", HeaderValue::from_static("api-key-secret"));
        ctx.original_headers
            .insert("x-client-secret", HeaderValue::from_static("client-secret-value"));
        ctx.original_headers
            .insert("x-credential-id", HeaderValue::from_static("credential-value"));
        ctx.original_headers
            .insert("x-apikey", HeaderValue::from_static("apikey-no-dash"));

        let input = build_outbound_policy_input(&ctx);
        let headers = &input
            .http
            .as_ref()
            .expect("http context should be present")
            .headers;

        assert_eq!(
            headers
                .get("x-signal-id")
                .map(String::as_str),
            Some("TA-CVE-2023-29300")
        );
        assert_eq!(
            headers
                .get("x-tlp")
                .map(String::as_str),
            Some("GREEN")
        );
        assert!(!headers.contains_key("authorization"));
        assert!(!headers.contains_key("proxy-authorization"));
        assert!(!headers.contains_key("cookie"));
        assert!(!headers.contains_key("set-cookie"));
        assert!(!headers.contains_key("x-transit-token"));
        assert!(!headers.contains_key("x-api-key"));
        assert!(!headers.contains_key("x-client-secret"));
        assert!(!headers.contains_key("x-credential-id"));
        assert!(!headers.contains_key("x-apikey"));
    }

    // ── step_validate_transit_token ────────────────────────────────────────

    #[tokio::test]
    async fn modern_transit_tokens_require_live_surface_bound_authority() {
        use crate::proxy::transit_token::{TransitTokenClaims, TransitTokenIssuer, TransitTokenKey};

        let issuer = TransitTokenIssuer::new(TransitTokenKey::generate().unwrap(), "gateway".into());
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        for case in ["valid", "other-surface", "expired", "future-issued", "other-point", "duplicate", "missing-issuer"]
        {
            let mut state = test_outbound_state();
            if case != "missing-issuer" {
                state.transit_token_issuer = Some(Arc::new(issuer.clone()));
            }
            let mut ctx = modern_pipeline_context("tools/list");
            Arc::make_mut(&mut ctx.surface).surface_id = "current-surface".into();
            ctx.virtual_channel
                .require_transit_token = true;
            let claims: TransitTokenClaims = serde_json::from_value(json!({
                "iss": "gateway", "surface_id": if case == "other-surface" { "another-surface" } else { "current-surface" },
                "iat": if case == "future-issued" { now + 120 } else { now - 1 },
                "exp": if case == "expired" { now - 1 } else { now + 299 },
                "jti": uuid::Uuid::new_v4().to_string(),
                "allowed_transit_points": [if case == "other-point" { "partner-b" } else { "partner-a" }]
            })).unwrap();
            let token = issuer.sign(&claims).unwrap();
            ctx.original_headers
                .insert("x-transit-token", token.parse().unwrap());
            if case == "duplicate" {
                ctx.original_headers
                    .append("x-transit-token", token.parse().unwrap());
            }
            let result = step_validate_transit_token(&state, &mut ctx).await;
            if case == "valid" {
                result.unwrap();
                assert_eq!(
                    ctx.transit_token_claims
                        .as_ref()
                        .unwrap()
                        .surface_id,
                    "current-surface"
                );
            } else {
                assert!(matches!(result, Err(OutboundPipelineError::TransitTokenInvalid(_))), "{case}: {result:?}");
            }
        }
    }

    /// A Transit Point checks a transit token against the lifetime its surface
    /// sets when the token is presented.
    #[tokio::test]
    async fn the_transit_token_step_checks_the_lifetime_the_surface_sets() {
        use crate::proxy::transit_token::{TransitTokenClaims, TransitTokenIssuer, TransitTokenKey};

        let issuer = TransitTokenIssuer::new(TransitTokenKey::generate().unwrap(), "gateway".into());
        let mut state = test_outbound_state();
        state.transit_token_issuer = Some(Arc::new(issuer.clone()));
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        for (case, lifetime, iat, exp, accepted) in [
            ("issued 400 s ago to live 600 s", Some(600), now - 400, now + 200, true),
            ("the same token once the surface allows 300 s", Some(300), now - 400, now + 200, false),
            ("the same token on a surface that sets no lifetime", None, now - 400, now + 200, false),
            ("living 1 s longer than the surface allows", Some(600), now, now + 601, false),
        ] {
            let mut ctx = test_pipeline_context();
            let surface = Arc::make_mut(&mut ctx.surface);
            surface.surface_id = "surf-001".into();
            surface
                .transit
                .as_mut()
                .unwrap()
                .shared
                .transit_token_lifetime_secs = lifetime;
            let claims: TransitTokenClaims = serde_json::from_value(json!({
                "iss": "gateway", "surface_id": "surf-001", "iat": iat, "exp": exp,
                "jti": uuid::Uuid::new_v4().to_string(), "allowed_transit_points": ["partner-a"]
            }))
            .unwrap();
            ctx.original_headers.insert(
                "x-transit-token",
                issuer
                    .sign(&claims)
                    .unwrap()
                    .parse()
                    .unwrap(),
            );

            let result = step_validate_transit_token(&state, &mut ctx).await;

            if accepted {
                result.unwrap();
                assert_eq!(
                    ctx.transit_token_claims
                        .as_ref()
                        .map(|claims| (claims.iat, claims.exp)),
                    Some((iat, exp)),
                    "{case}"
                );
            } else {
                assert!(
                    matches!(&result, Err(OutboundPipelineError::TransitTokenInvalid(reason))
                        if reason == "transit token lives longer than its surface allows"),
                    "{case}: {result:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_transit_token_validation_refuses_when_no_issuer() {
        let state = test_outbound_state(); // transit_token_issuer = None
        let mut ctx = test_pipeline_context();
        let result = step_validate_transit_token(&state, &mut ctx).await;
        assert!(
            matches!(result, Err(OutboundPipelineError::TransitTokenInvalid(ref reason)) if reason.contains("unavailable")),
            "a Transit Point that requires the token refuses when it cannot check it: {result:?}"
        );
        assert!(
            ctx.transit_token_claims
                .is_none()
        );

        ctx.virtual_channel
            .require_transit_token = false;
        assert!(
            step_validate_transit_token(&state, &mut ctx)
                .await
                .is_ok(),
            "a Transit Point that does not require the token is unaffected"
        );
    }

    #[tokio::test]
    async fn test_transit_token_validation_rejects_missing_header() {
        let mut state = test_outbound_state();
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            crate::proxy::transit_token::TransitTokenKey::generate().unwrap(),
            "gw-test".to_string(),
        );
        state.transit_token_issuer = Some(Arc::new(issuer));

        let mut ctx = test_pipeline_context();
        // No X-Transit-Token header
        let result = step_validate_transit_token(&state, &mut ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            OutboundPipelineError::TransitTokenInvalid(msg) => {
                assert!(msg.contains("missing"));
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_transit_token_validation_rejects_invalid_token() {
        let mut state = test_outbound_state();
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            crate::proxy::transit_token::TransitTokenKey::generate().unwrap(),
            "gw-test".to_string(),
        );
        state.transit_token_issuer = Some(Arc::new(issuer));

        let mut ctx = test_pipeline_context();
        ctx.original_headers.insert(
            "X-Transit-Token",
            "invalid-garbage-token"
                .parse()
                .unwrap(),
        );

        let result = step_validate_transit_token(&state, &mut ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            OutboundPipelineError::TransitTokenInvalid(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_transit_token_validation_accepts_valid_token() {
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            crate::proxy::transit_token::TransitTokenKey::generate().unwrap(),
            "gw-test".to_string(),
        );

        // Issue a token that allows "partner-a" transit point
        let token = issuer
            .issue(
                "surf-001",
                Some("did:example:caller"),
                Some("gateway_computed"),
                None,
                None,
                None,
                vec!["partner-a".to_string(), "partner-b".to_string()],
            )
            .unwrap();

        let mut state = test_outbound_state();
        state.transit_token_issuer = Some(Arc::new(issuer));

        let mut ctx = test_pipeline_context();
        Arc::make_mut(&mut ctx.surface).surface_id = "surf-001".into();
        ctx.original_headers
            .insert("X-Transit-Token", token.parse().unwrap());

        let result = step_validate_transit_token(&state, &mut ctx).await;
        assert!(result.is_ok());

        let claims = ctx
            .transit_token_claims
            .unwrap();
        assert_eq!(claims.sub, Some("did:example:caller".to_string()));
        assert_eq!(claims.surface_id, "surf-001");
        assert_eq!(claims.identity_source, Some("gateway_computed".to_string()));
    }

    /// A valid token sent to a Transit Point that does not require one names
    /// the caller to policy only. The claims that drive delegation, Workload
    /// Binding, stream expiry and the trace id stay empty, as without a token.
    #[tokio::test]
    async fn an_optional_transit_token_reaches_policy_only() {
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            crate::proxy::transit_token::TransitTokenKey::generate().unwrap(),
            "gw-test".to_string(),
        );
        let token = issuer
            .issue(
                "surf-001",
                Some("did:example:caller"),
                Some("gateway_computed"),
                None,
                None,
                None,
                vec!["partner-a".to_string()],
            )
            .unwrap();
        let mut state = test_outbound_state();
        state.transit_token_issuer = Some(Arc::new(issuer));
        let mut ctx = test_pipeline_context();
        Arc::make_mut(&mut ctx.surface).surface_id = "surf-001".into();
        ctx.virtual_channel
            .require_transit_token = false;
        ctx.original_headers
            .insert("X-Transit-Token", token.parse().unwrap());

        step_validate_transit_token(&state, &mut ctx)
            .await
            .unwrap();

        assert!(
            ctx.transit_token_claims
                .is_none()
        );
        assert_eq!(ctx.request_id, "test-request-id");
        let caller = transit_caller_json(&ctx);
        assert_eq!(caller["verification"], "unverified", "{caller}");
        assert_eq!(caller["did"], "did:example:caller", "{caller}");
    }

    /// On a Transit Point that does not require a transit token, a token that
    /// expired within the clock leeway passes the first check, but once the
    /// strict modern MCP check refuses it the caller is anonymous again.
    #[tokio::test]
    async fn an_optional_transit_token_the_strict_check_refuses_names_no_caller() {
        use crate::proxy::transit_token::{TransitTokenClaims, TransitTokenIssuer, TransitTokenKey};

        let issuer = TransitTokenIssuer::new(TransitTokenKey::generate().unwrap(), "gateway".into());
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        let claims: TransitTokenClaims = serde_json::from_value(json!({
            "iss": "gateway", "surface_id": "surf-001", "sub": "did:example:caller",
            "iat": now - 2, "exp": now - 1, "jti": uuid::Uuid::new_v4().to_string(),
            "allowed_transit_points": ["partner-a"]
        }))
        .unwrap();
        let mut state = test_outbound_state();
        state.transit_token_issuer = Some(Arc::new(issuer.clone()));
        let mut ctx = modern_pipeline_context("tools/call");
        Arc::make_mut(&mut ctx.surface).surface_id = "surf-001".into();
        ctx.virtual_channel
            .require_transit_token = false;
        ctx.original_headers.insert(
            "x-transit-token",
            issuer
                .sign(&claims)
                .unwrap()
                .parse()
                .unwrap(),
        );
        let classification = ctx.mcp_classification.take();

        step_validate_transit_token(&state, &mut ctx)
            .await
            .unwrap();
        assert!(
            ctx.optional_transit_token_claims
                .is_some(),
            "the lenient check accepts the token"
        );

        ctx.mcp_classification = classification;
        step_validate_transit_token(&state, &mut ctx)
            .await
            .unwrap();

        assert!(
            ctx.optional_transit_token_claims
                .is_none()
        );
        let caller = transit_caller_json(&ctx);
        assert_eq!(caller["verification"], "anonymous", "{caller}");
    }

    #[tokio::test]
    async fn test_transit_token_validation_rejects_wrong_transit_point() {
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            crate::proxy::transit_token::TransitTokenKey::generate().unwrap(),
            "gw-test".to_string(),
        );

        // Issue a token that only allows "other-service" — not "partner-a"
        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec!["other-service".to_string()])
            .unwrap();

        let mut state = test_outbound_state();
        state.transit_token_issuer = Some(Arc::new(issuer));

        let mut ctx = test_pipeline_context();
        Arc::make_mut(&mut ctx.surface).surface_id = "surf-001".into();
        ctx.original_headers
            .insert("X-Transit-Token", token.parse().unwrap());

        let result = step_validate_transit_token(&state, &mut ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            OutboundPipelineError::TransitTokenInvalid(msg) => {
                assert!(msg.contains("partner-a"));
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    /// A refused transit token is answered without saying which check it
    /// failed, such as that it was issued for another surface.
    #[tokio::test]
    async fn a_refused_transit_token_is_not_told_why() {
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            crate::proxy::transit_token::TransitTokenKey::generate().unwrap(),
            "gw-test".to_string(),
        );
        let token = issuer
            .issue("another-surface", None, None, None, None, None, vec![])
            .unwrap();
        let mut state = test_outbound_state();
        state.transit_token_issuer = Some(Arc::new(issuer));
        let mut ctx = test_pipeline_context();
        Arc::make_mut(&mut ctx.surface).surface_id = "surf-001".into();
        ctx.original_headers
            .insert("X-Transit-Token", token.parse().unwrap());

        let error = step_validate_transit_token(&state, &mut ctx)
            .await
            .unwrap_err();

        assert!(
            matches!(&error, OutboundPipelineError::TransitTokenInvalid(reason) if reason.contains("another surface")),
            "{error:?}"
        );
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["detail"], "Transit token missing or invalid", "{body}");
    }

    /// A Transit Point configured with MCP tool gating that is not in force, as
    /// when its surface was deleted while the request was in flight, refuses a
    /// `tools/call` and lists no tools.
    #[tokio::test]
    async fn a_transit_point_whose_tool_gating_is_not_in_force_fails_closed() {
        let mut state = test_outbound_state();
        state.policy_manager = Some(Arc::new(crate::policies::SurfacePolicyManager::new()));
        let gated = |operation: &str| {
            let mut ctx = test_pipeline_context();
            ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
            ctx.operation = Some(operation.to_string());
            ctx.body_bytes = Some(Bytes::from(
                json!({"jsonrpc": "2.0", "id": 9, "method": operation, "params": {"name": "admin_reset"}}).to_string(),
            ));
            ctx.virtual_channel
                .mcp_tool_gating = Some(
                serde_json::from_value(json!({"gates": [{"id": "g1", "name": "no admin",
                    "action": {"effect": "deny", "patterns": ["^admin_"]}}]}))
                .unwrap(),
            );
            ctx
        };

        let mut call = gated("tools/call");
        assert!(matches!(
            step_transit_mcp_tool_gating(&state, &mut call).await,
            Err(OutboundPipelineError::TransitMcpToolGated)
        ));
        let listed = filter_transit_mcp_tools_list(
            &state,
            &gated("tools/list"),
            Bytes::from(json!({"jsonrpc": "2.0", "id": 9, "result": {"tools": [{"name": "admin_reset"}]}}).to_string()),
        );
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&listed).unwrap()["result"]["tools"], json!([]));

        let mut ungated = gated("tools/call");
        ungated
            .virtual_channel
            .mcp_tool_gating = None;
        assert!(
            step_transit_mcp_tool_gating(&state, &mut ungated)
                .await
                .is_ok()
        );
    }

    // ── step_collect_trust_context ─────────────────────────────────────────

    #[tokio::test]
    async fn test_collect_trust_context_noop_when_no_config() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();

        let result = step_collect_trust_context(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert!(
            ctx.target_agent_context
                .is_none()
        );
    }

    // ── step_inspect_outbound_extensions ────────────────────────────────────

    fn a2a_body_with_extension(extension_uri: &str) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {
                    "message": {
                        "extensions": [{ "uri": extension_uri }]
                    }
                }
            }))
            .unwrap(),
        )
    }

    fn a2a_body_no_extensions() -> Bytes {
        Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {
                    "message": {}
                }
            }))
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_outbound_extension_inspection_passes_when_extension_present() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "extension_inspection": {
                "enabled": true,
                "watch_extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            }
        }))
        .unwrap();
        ctx.body_bytes = Some(a2a_body_with_extension("https://fabric.affinidi.io/extensions/agent-identity/v1"));
        let result = step_inspect_outbound_extensions(&state, &mut ctx).await;
        assert!(result.is_ok(), "should pass when watched extension is present");
    }

    #[tokio::test]
    async fn test_outbound_extension_inspection_rejects_when_extension_missing() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "extension_inspection": {
                "enabled": true,
                "watch_extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            }
        }))
        .unwrap();
        ctx.body_bytes = Some(a2a_body_no_extensions());
        let result = step_inspect_outbound_extensions(&state, &mut ctx).await;
        assert!(
            matches!(result, Err(OutboundPipelineError::ExtensionValidationFailed(_))),
            "should reject with ExtensionValidationFailed when extension absent"
        );
    }

    // ── Outbound target-leg Trust Check (widened gate) ─────────────────────
    //
    // Coverage matrix:
    //   T1 — agent context populated when trust_check_list non-empty and TR-verify disabled
    //   T2 — agent context extracts DID but no provider_did when extension params empty
    //   T3 — synthesizes AGENT_CARD_UNAVAILABLE per element on fetch failure
    //   T4 — already covered above (`test_collect_trust_context_fails_when_agent_card_unreachable`)
    //   T5..T7 — cache-level TTL / key isolation / invalidate_all coverage lives in
    //            `crate::proxy::agent_card_cache::tests` (module-owned unit tests)
    //   T8 — `build_outbound_policy_input` puts target DID on `input.agent.did`
    //   T9 — synthesized results emit one audit event per element

    /// Minimal in-process agent-card server. Serves the supplied JSON
    /// body at `GET /.well-known/agent-card.json` on an ephemeral port
    /// and shuts down when the returned [`TrustCheckTestServer`] is
    /// dropped.
    struct TrustCheckTestServer(tokio::task::JoinHandle<()>);

    impl Drop for TrustCheckTestServer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn spawn_agent_card_server(card_body: serde_json::Value) -> (String, TrustCheckTestServer) {
        use axum::Router;
        use axum::routing::get;
        let body_str = card_body.to_string();
        let app = Router::new().route(
            "/.well-known/agent-card.json",
            get(move || {
                let body = body_str.clone();
                async move { ([("Content-Type", "application/json")], body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener
            .local_addr()
            .expect("addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{}", addr), TrustCheckTestServer(handle))
    }

    fn attach_transit_point_trust_check_list(
        ctx: &mut OutboundPipelineContext,
        elements: Vec<crate::trust_registry_verification::TrustCheckElement>,
    ) {
        ctx.virtual_channel
            .trust_check_list = elements;
    }

    fn attach_surface_target_trust_check_list(
        ctx: &mut OutboundPipelineContext,
        elements: Vec<crate::trust_registry_verification::TrustCheckElement>,
    ) {
        let mut surface = (*ctx.surface).clone();
        surface
            .target
            .trust_check_list = elements;
        ctx.surface = Arc::new(surface);
    }

    async fn spawn_counting_agent_card_server(
        card_body: serde_json::Value
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>, TrustCheckTestServer) {
        use axum::Router;
        use axum::routing::get;
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        let body_str = card_body.to_string();
        let app = Router::new().fallback(get(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = body_str.clone();
            async move { ([("Content-Type", "application/json")], body) }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener
            .local_addr()
            .expect("addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{}", addr), hits, TrustCheckTestServer(handle))
    }

    fn result_ids(ctx: &OutboundPipelineContext) -> Vec<String> {
        ctx.trust_check_results
            .as_ref()
            .expect("trust check results populated")
            .target
            .iter()
            .map(|r| r.id.clone())
            .collect()
    }

    #[tokio::test]
    async fn outbound_transit_point_without_trust_checks_skips_card_fetch_and_results() {
        crate::proxy::agent_card_cache::invalidate_all();
        let (endpoint, hits, _server) = spawn_counting_agent_card_server(json!({"protocolVersion": "1.0"})).await;
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.alias = "tp2".to_string();
        ctx.virtual_channel
            .target_endpoint = endpoint;
        attach_surface_target_trust_check_list(&mut ctx, vec![make_test_element("surface-wide")]);

        step_collect_trust_context(&state, &mut ctx)
            .await
            .expect("collect ok");
        step_trust_check(&state, &mut ctx)
            .await
            .expect("trust check ok");

        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "no Trust Check agent-card fetch for tp2");
        assert!(
            ctx.target_agent_context
                .is_none()
        );
        assert!(!ctx.target_agent_card_unavailable);
        assert!(
            ctx.target_identity_failure
                .is_none()
        );
        assert!(
            ctx.trust_check_results
                .is_none(),
            "tp2 has no Trust Checks, so no results"
        );
    }

    #[tokio::test]
    async fn outbound_transit_point_with_trust_checks_fetches_its_card() {
        crate::proxy::agent_card_cache::invalidate_all();
        let (endpoint, hits, _server) = spawn_counting_agent_card_server(json!({"protocolVersion": "1.0"})).await;
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.alias = "tp1".to_string();
        ctx.virtual_channel
            .target_endpoint = endpoint;
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tp1-a")]);

        step_collect_trust_context(&state, &mut ctx)
            .await
            .expect("collect ok");

        assert!(hits.load(std::sync::atomic::Ordering::SeqCst) >= 1, "tp1's Trust Check fetches its card");
        assert!(
            ctx.target_agent_context
                .is_some()
        );
        assert_eq!(
            ctx.target_identity_failure
                .as_ref()
                .map(|f| f.code),
            Some(crate::trust_registry_verification::TARGET_AGENT_IDENTITY_UNAVAILABLE)
        );
    }

    #[tokio::test]
    async fn outbound_card_unavailable_results_cover_only_the_routed_transit_points_elements() {
        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.alias = "tp1".to_string();
        ctx.virtual_channel
            .target_endpoint = "http://127.0.0.1:1".to_string();
        attach_surface_target_trust_check_list(&mut ctx, vec![make_test_element("surface-wide")]);
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tp1-a"), make_test_element("tp1-b")]);

        let (_guard, events) = crate::observability::trust_check_audit::test_support::capture_until_dropped();
        step_collect_trust_context(&state, &mut ctx)
            .await
            .expect("collect ok");
        step_trust_check(&state, &mut ctx)
            .await
            .expect("trust check ok");

        assert!(ctx.target_agent_card_unavailable);
        assert_eq!(result_ids(&ctx), vec!["tp1-a".to_string(), "tp1-b".to_string()]);
        let results = ctx
            .trust_check_results
            .as_ref()
            .expect("results");
        assert!(results.caller.is_empty());
        assert!(
            results
                .target
                .iter()
                .all(|r| !r.ok
                    && r.error
                        .as_ref()
                        .map(|e| e.code.as_str())
                        == Some(crate::trust_registry_verification::AGENT_CARD_UNAVAILABLE))
        );

        use crate::observability::trust_check_audit::test_support::field;
        let events = events
            .lock()
            .expect("events lock")
            .clone();
        let audited: Vec<_> = events
            .iter()
            .filter(|e| field(e, "element_id").is_some_and(|id| id.starts_with("tp1-") || id == "surface-wide"))
            .map(|e| (field(e, "element_id").unwrap_or_default(), field(e, "transit_point").unwrap_or_default()))
            .collect();
        assert_eq!(audited, vec![("tp1-a", "tp1"), ("tp1-b", "tp1")]);
    }

    #[tokio::test]
    async fn outbound_variant_request_runs_the_variants_transit_point_list() {
        crate::proxy::agent_card_cache::invalidate_all();
        let element = |id: &str| serde_json::to_value(make_test_element(id)).expect("element");
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface-variant-tc",
            "name": "variant-tc",
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/surfaces/order", "protocol": "a2a"},
            "target": {"endpoint": "https://managed.example/a2a"},
            "transit": {"points": [{
                "id": "tp-base", "alias": "partner-a", "target_endpoint": "http://127.0.0.1:1",
                "protocol": "a2a", "trust_check_list": [element("base-check")]
            }]},
            "variants": [{
                "id": "variant-dev", "alias": "dev", "name": "Development", "enabled": true,
                "overrides": {"transit": {"points": [{
                    "id": "tp-dev", "alias": "partner-a", "target_endpoint": "http://127.0.0.1:1",
                    "protocol": "a2a", "trust_check_list": [element("dev-check-1"), element("dev-check-2")]
                }]}}
            }]
        }))
        .expect("surface should deserialize");
        let state = test_outbound_state();
        state
            .channel_state
            .write()
            .unwrap()
            .surface = Arc::new(surface);

        let mut ran = Vec::new();
        for path in
            ["/outbound/surfaces/order$dev/partner-a/message/send", "/outbound/surfaces/order/partner-a/message/send"]
        {
            let req = Request::builder()
                .method(Method::POST)
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            let mut ctx = OutboundPipelineContext::new(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                req,
                &state,
                crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            )
            .expect("context resolves the Transit Point");
            step_collect_trust_context(&state, &mut ctx)
                .await
                .expect("collect ok");
            step_trust_check(&state, &mut ctx)
                .await
                .expect("trust check ok");
            ran.push(result_ids(&ctx));
        }

        assert_eq!(
            ran,
            vec![vec!["dev-check-1".to_string(), "dev-check-2".to_string()], vec!["base-check".to_string()]]
        );
    }

    #[tokio::test]
    async fn outbound_mcp_transit_point_runs_its_trust_check_list() {
        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        ctx.virtual_channel
            .target_endpoint = "http://127.0.0.1:1".to_string();
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("mcp-check")]);

        step_collect_trust_context(&state, &mut ctx)
            .await
            .expect("collect ok");
        step_trust_check(&state, &mut ctx)
            .await
            .expect("trust check ok");

        assert_eq!(result_ids(&ctx), vec!["mcp-check".to_string()]);
    }

    #[tokio::test]
    async fn outbound_identity_failure_results_cover_only_the_routed_transit_points_elements() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        attach_surface_target_trust_check_list(&mut ctx, vec![make_test_element("surface-wide")]);
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tp1-a")]);
        ctx.target_identity_failure = Some(crate::trust_registry_verification::TrustCheckIdentityVerificationFailure {
            code: crate::trust_registry_verification::IDENTITY_VP_VERIFICATION_FAILED,
            detail: "target agent identity credential could not be verified",
        });

        step_trust_check(&state, &mut ctx)
            .await
            .expect("trust check ok");

        assert_eq!(result_ids(&ctx), vec!["tp1-a".to_string()]);
        assert_eq!(
            ctx.trust_check_results
                .as_ref()
                .expect("results")
                .target[0]
                .error
                .as_ref()
                .map(|e| e.code.as_str()),
            Some(crate::trust_registry_verification::IDENTITY_VP_VERIFICATION_FAILED)
        );
    }

    fn make_test_element(id: &str) -> crate::trust_registry_verification::TrustCheckElement {
        use crate::trust_registry_verification::trust_check_element::{
            TrqpQueryParams, TrqpQueryType, TrustCheckElement,
        };
        TrustCheckElement {
            id: id.to_string(),
            trust_registry_id: "tr-test".to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams {
                authority_id: "did:test:authority".to_string(),
                entity_id: "{{ input.agent.did }}".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: Some(format!("elem-{}", id)),
        }
    }

    /// Test element whose `entity_id` references
    /// `input.agent.provider_did` — the per-element predicate
    /// [`element_needs_missing_tr_metadata`] only fires when the
    /// template names a missing TR-metadata field.
    fn make_test_element_referencing_provider_did(id: &str) -> crate::trust_registry_verification::TrustCheckElement {
        use crate::trust_registry_verification::trust_check_element::{
            TrqpQueryParams, TrqpQueryType, TrustCheckElement,
        };
        TrustCheckElement {
            id: id.to_string(),
            trust_registry_id: "tr-test".to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams {
                authority_id: "did:test:authority".to_string(),
                entity_id: "{{ input.agent.provider_did }}".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: Some(format!("elem-{}", id)),
        }
    }

    #[tokio::test]
    async fn outbound_target_agent_context_populated_when_trust_check_list_non_empty_and_tr_verification_disabled() {
        crate::proxy::agent_card_cache::invalidate_all();
        let card = json!({
            "protocolVersion": "1.0",
            "id": "did:example:target",
            "capabilities": {
                "extensions": [
                    {
                        "uri": "https://fabric.affinidi.io/extensions/agent-identity-credential/v1",
                        "params": {
                            "did": "did:example:target",
                            "verifiablePresentation": "{}"
                        }
                    },
                    {
                        "uri": "https://fabric.affinidi.io/extensions/trust-registry",
                        "params": {
                            "agent_did": "did:example:target",
                            "trust_registry_did": "did:example:registry",
                            "provider_did": "did:example:provider",
                            "authority_did": "did:example:authority"
                        }
                    }
                ]
            }
        });
        let (endpoint, _server) = spawn_agent_card_server(card).await;

        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .target_endpoint = endpoint;
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tc-1")]);

        let result = step_collect_trust_context(&state, &mut ctx).await;
        assert!(result.is_ok(), "widened gate should open without TR-verify: {:?}", result);
        assert!(!ctx.target_agent_card_unavailable);

        // WS-B: the card carries a VP but no VCIssuer is configured to verify
        // it, so the target identity cannot be established — the did is cleared
        // and the whole target leg is flagged so `step_trust_check` synthesizes
        // IDENTITY_VP_VERIFICATION_FAILED (a VP was present, it just could not
        // be verified). The rest of the agent context (built from the card) is
        // still populated.
        let failure = ctx
            .target_identity_failure
            .as_ref()
            .expect("unverifiable target VP should flag the leg");
        assert_eq!(
            failure.code,
            crate::trust_registry_verification::IDENTITY_VP_VERIFICATION_FAILED,
            "a present-but-unverifiable VP is a verification failure"
        );
        let agent_ctx = ctx
            .target_agent_context
            .expect("target agent context populated");
        assert_eq!(agent_ctx.did, None, "did cleared when target VP cannot be verified");
        assert_eq!(
            agent_ctx
                .provider_did
                .as_deref(),
            Some("did:example:provider")
        );
    }

    #[tokio::test]
    async fn outbound_target_leg_flags_identity_unavailable_when_card_carries_no_vp() {
        crate::proxy::agent_card_cache::invalidate_all();
        let card = json!({
            "protocolVersion": "1.0",
            "id": "did:example:target",
            "capabilities": {
                "extensions": [
                    {
                        "uri": "https://fabric.affinidi.io/extensions/trust-registry",
                        "params": {
                            "agent_did": "did:example:target",
                            "trust_registry_did": "did:example:registry",
                            "provider_did": "did:example:provider",
                            "authority_did": "did:example:authority"
                        }
                    }
                ]
            }
        });
        let (endpoint, _server) = spawn_agent_card_server(card).await;

        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .target_endpoint = endpoint;
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tc-1")]);

        let result = step_collect_trust_context(&state, &mut ctx).await;
        assert!(result.is_ok(), "widened gate should open without TR-verify: {:?}", result);
        assert!(!ctx.target_agent_card_unavailable);

        let failure = ctx
            .target_identity_failure
            .as_ref()
            .expect("absent target VP should flag the leg");
        assert_eq!(
            failure.code,
            crate::trust_registry_verification::TARGET_AGENT_IDENTITY_UNAVAILABLE,
            "no VP present is an unavailable identity, not a verification failure"
        );

        let agent_ctx = ctx
            .target_agent_context
            .expect("target agent context populated");
        assert_eq!(agent_ctx.did, None, "did cleared when target identity is unavailable");
    }

    #[tokio::test]
    async fn outbound_target_leg_synthesizes_identity_unavailable_per_element() {
        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tc-1"), make_test_element("tc-2")]);
        ctx.target_identity_failure = Some(crate::trust_registry_verification::TrustCheckIdentityVerificationFailure {
            code: crate::trust_registry_verification::TARGET_AGENT_IDENTITY_UNAVAILABLE,
            detail: "target agent card carries no agent-identity-credential",
        });

        step_trust_check(&state, &mut ctx)
            .await
            .expect("synthesis ok");

        let results = ctx
            .trust_check_results
            .expect("results populated");
        assert_eq!(results.target.len(), 2, "one result per configured element");
        for res in &results.target {
            let err = res
                .error
                .as_ref()
                .expect("synthesized result carries an error");
            assert_eq!(err.code, "TARGET_AGENT_IDENTITY_UNAVAILABLE");
            assert!(res.authority_id.is_none(), "code omits authority_id on the wire");
            assert!(res.entity_id.is_none(), "code omits entity_id on the wire");
        }
    }

    #[tokio::test]
    async fn test_outbound_extension_inspection_passes_when_disabled() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "extension_inspection": {
                "enabled": false,
                "watch_extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            }
        }))
        .unwrap();
        ctx.body_bytes = Some(a2a_body_no_extensions());
        let result = step_inspect_outbound_extensions(&state, &mut ctx).await;
        assert!(result.is_ok(), "should pass when inspection is disabled");
    }

    #[tokio::test]
    async fn test_outbound_extension_inspection_skipped_for_mcp() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "mcp-tool",
            "target_endpoint": "https://mcp.example.com",
            "protocol": "mcp",
            "extension_inspection": {
                "enabled": true,
                "watch_extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            }
        }))
        .unwrap();
        ctx.body_bytes = Some(a2a_body_no_extensions());
        let result = step_inspect_outbound_extensions(&state, &mut ctx).await;
        assert!(result.is_ok(), "should skip inspection for MCP transit points");
    }

    #[tokio::test]
    async fn test_outbound_extension_inspection_rejects_empty_body_when_enabled() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "extension_inspection": {
                "enabled": true,
                "watch_extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            }
        }))
        .unwrap();
        ctx.body_bytes = Some(bytes::Bytes::new());
        let result = step_inspect_outbound_extensions(&state, &mut ctx).await;
        assert!(
            matches!(result, Err(OutboundPipelineError::ExtensionValidationFailed(_))),
            "should reject empty body when watch_extensions is non-empty and enabled"
        );
    }

    #[tokio::test]
    async fn outbound_target_agent_context_missing_provider_did_when_trust_registry_extension_empty() {
        crate::proxy::agent_card_cache::invalidate_all();
        // Card carries the TR extension but no params — provider_did is
        // therefore absent, and (because agent_did also lives in params)
        // did too. The important assertion is that the stage still runs
        // without error and OPA sees the AgentContext with the missing
        // fields, i.e. the widened gate is fully forgiving of a
        // provider-less target card.
        let card = json!({
            "protocolVersion": "1.0",
            "id": "did:example:target",
            "capabilities": {
                "extensions": [{
                    "uri": "https://fabric.affinidi.io/extensions/trust-registry",
                    "params": {}
                }]
            }
        });
        let (endpoint, _server) = spawn_agent_card_server(card).await;

        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .target_endpoint = endpoint;
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tc-1")]);

        step_collect_trust_context(&state, &mut ctx)
            .await
            .expect("stage ok");
        let agent_ctx = ctx
            .target_agent_context
            .expect("target agent context populated");
        assert!(
            agent_ctx
                .provider_did
                .is_none(),
            "empty extension params yield no provider_did"
        );
        assert!(
            agent_ctx
                .trust_verification
                .is_none(),
            "TR-verify off skips recognition queries"
        );
    }

    #[tokio::test]
    async fn test_outbound_extension_inspection_passes_empty_body_when_disabled() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "extension_inspection": {
                "enabled": false,
                "watch_extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            }
        }))
        .unwrap();
        ctx.body_bytes = Some(bytes::Bytes::new());
        let result = step_inspect_outbound_extensions(&state, &mut ctx).await;
        assert!(result.is_ok(), "should pass empty body when inspection is disabled");
    }

    #[tokio::test]
    async fn test_outbound_extension_inspection_rejects_non_json_body_when_enabled() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "extension_inspection": {
                "enabled": true,
                "watch_extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            }
        }))
        .unwrap();
        ctx.body_bytes = Some(bytes::Bytes::from("not valid json"));
        let result = step_inspect_outbound_extensions(&state, &mut ctx).await;
        assert!(
            matches!(result, Err(OutboundPipelineError::ExtensionValidationFailed(_))),
            "should reject non-JSON body when watch_extensions is non-empty and enabled"
        );
    }

    #[tokio::test]
    async fn test_outbound_extension_inspection_passes_non_json_body_when_disabled() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel = serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "extension_inspection": {
                "enabled": false,
                "watch_extensions": ["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            }
        }))
        .unwrap();
        ctx.body_bytes = Some(bytes::Bytes::from("not valid json"));
        let result = step_inspect_outbound_extensions(&state, &mut ctx).await;
        assert!(result.is_ok(), "should pass non-JSON body when inspection is disabled");
    }

    #[tokio::test]
    async fn outbound_target_leg_trust_check_emits_agent_card_unavailable_result_per_element_on_fetch_failure() {
        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .target_endpoint = "http://127.0.0.1:1".to_string();
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tc-1"), make_test_element("tc-2")]);

        step_collect_trust_context(&state, &mut ctx)
            .await
            .expect("Trust-Check-only path is soft on card-fetch failure");
        assert!(ctx.target_agent_card_unavailable, "card unavailable marker must be set for step_trust_check");

        step_trust_check(&state, &mut ctx)
            .await
            .expect("synthesis never errors");

        let results = ctx
            .trust_check_results
            .expect("results populated");
        assert!(results.caller.is_empty(), "caller leg not touched by target-side stage");
        assert_eq!(results.target.len(), 2, "one synthesized result per configured element");
        assert_eq!(results.target[0].id, "tc-1", "positional order preserved");
        assert_eq!(results.target[1].id, "tc-2", "positional order preserved");
        for r in &results.target {
            assert!(!r.ok, "synthesized result is a failure");
            let err = r
                .error
                .as_ref()
                .expect("error present");
            assert_eq!(err.code, "AGENT_CARD_UNAVAILABLE");
        }
    }

    #[tokio::test]
    async fn outbound_agent_card_unavailable_synthesized_results_emit_audit_events() {
        use crate::observability::trust_check_audit::test_support::{CapturedEvent, capture_until_dropped, field};

        let (default_guard, events) = capture_until_dropped();
        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .target_endpoint = "http://127.0.0.1:1".to_string();
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tc-1"), make_test_element("tc-2")]);
        ctx.target_agent_card_unavailable = true;

        step_trust_check(&state, &mut ctx)
            .await
            .expect("synthesis ok");

        drop(default_guard);
        let events = events
            .lock()
            .expect("events lock")
            .clone();
        let agent_card_unavailable_events: Vec<&CapturedEvent> = events
            .iter()
            .filter(|e| field(e, "error_code") == Some("AGENT_CARD_UNAVAILABLE"))
            .collect();
        assert_eq!(agent_card_unavailable_events.len(), 2, "one audit event per synthesized element");
        for ev in agent_card_unavailable_events {
            assert_eq!(ev.level, "WARN", "failures log at WARN so OTEL exporter captures them");
            assert_eq!(field(ev, "latency_ms"), Some("0"), "no network call fired");
        }
    }

    #[tokio::test]
    async fn outbound_target_leg_trust_check_emits_trust_registry_metadata_unavailable_when_extension_missing() {
        // Card was fetched OK (target_agent_card_unavailable = false, and
        // step_collect_trust_context populates target_agent_context) but
        // the built context has no provider_did / trust_registry_did.
        // Both configured elements reference input.agent.provider_did
        // in their entity_id, so the per-element gate must fire for
        // both and synthesize TRUST_REGISTRY_METADATA_UNAVAILABLE
        // without any TRQP call.
        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        attach_transit_point_trust_check_list(
            &mut ctx,
            vec![
                make_test_element_referencing_provider_did("tc-1"),
                make_test_element_referencing_provider_did("tc-2"),
            ],
        );
        ctx.target_agent_context = Some(crate::surface_context::AgentContext {
            did_verified: false,
            did_verification: None,
            did: Some("did:web:target".to_string()),
            provider_did: None,
            authority_did: None,
            identity_issuer_did: None,
            trust_registry_did: None,
            agent_dna: None,
            trust_verification: None,
            source_trust_verification: None,
            target_trust_verification: None,
            tr_identity_mismatch: false,
        });

        step_trust_check(&state, &mut ctx)
            .await
            .expect("synthesis never errors");

        let results = ctx
            .trust_check_results
            .expect("results populated");
        assert!(results.caller.is_empty());
        assert_eq!(results.target.len(), 2, "one synthesized result per configured element");
        assert_eq!(results.target[0].id, "tc-1");
        assert_eq!(results.target[1].id, "tc-2");
        for r in &results.target {
            assert!(!r.ok);
            let err = r
                .error
                .as_ref()
                .expect("error present");
            assert_eq!(err.code, "TRUST_REGISTRY_METADATA_UNAVAILABLE");
            assert_eq!(
                err.message, "target agent card does not populate provider_did in its trust registry metadata",
                "per-field message names the missing field"
            );
            assert!(
                r.authority_id.is_none(),
                "authority_id must be omitted so the operator doesn't see raw template noise"
            );
            assert!(r.entity_id.is_none(), "entity_id must be omitted for the same reason");
        }
    }

    #[tokio::test]
    async fn outbound_target_leg_trust_check_gates_per_element_and_preserves_order() {
        // Mixed list: element 1 references the missing provider_did
        // (must synthesize TRUST_REGISTRY_METADATA_UNAVAILABLE);
        // element 2 has literal DIDs only (must fall through to the
        // executor). The test outbound state has no listener manager
        // configured, so element 2's slot stays empty — the assertion
        // is that the synthesized entry preserves its index-0 position
        // and the surface's fast-path invariant still holds.
        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        attach_transit_point_trust_check_list(
            &mut ctx,
            vec![make_test_element_referencing_provider_did("gated"), make_test_element("runnable")],
        );
        ctx.target_agent_context = Some(crate::surface_context::AgentContext {
            did_verified: false,
            did_verification: None,
            did: Some("did:web:target".to_string()),
            provider_did: None,
            authority_did: None,
            identity_issuer_did: None,
            trust_registry_did: None,
            agent_dna: None,
            trust_verification: None,
            source_trust_verification: None,
            target_trust_verification: None,
            tr_identity_mismatch: false,
        });

        step_trust_check(&state, &mut ctx)
            .await
            .expect("gate + no-manager path");

        let results = ctx
            .trust_check_results
            .expect("synthesized entry must still surface even with no listener manager");
        assert!(results.caller.is_empty());
        // Only the synthesized entry — the runnable element could not
        // execute because the test state has no listener manager. The
        // synthesized entry keeps its configured position and identity.
        assert_eq!(results.target.len(), 1);
        assert_eq!(results.target[0].id, "gated");
        assert_eq!(
            results.target[0]
                .error
                .as_ref()
                .expect("error present")
                .code,
            "TRUST_REGISTRY_METADATA_UNAVAILABLE"
        );
    }

    #[tokio::test]
    async fn outbound_target_leg_trust_check_runs_executor_when_target_agent_context_has_tr_metadata() {
        // Regression guard for the third arm of the ordered gate in
        // step_trust_check: a fully-populated target_agent_context must
        // fall through to the executor, not the new pre-check branch.
        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        attach_transit_point_trust_check_list(&mut ctx, vec![make_test_element("tc-1")]);
        ctx.target_agent_context = Some(crate::surface_context::AgentContext {
            did_verified: false,
            did_verification: None,
            did: Some("did:web:target".to_string()),
            provider_did: Some("did:web:provider".to_string()),
            authority_did: None,
            identity_issuer_did: None,
            trust_registry_did: Some("did:web:tr".to_string()),
            agent_dna: None,
            trust_verification: None,
            source_trust_verification: None,
            target_trust_verification: None,
            tr_identity_mismatch: false,
        });

        step_trust_check(&state, &mut ctx)
            .await
            .expect("no synthesis path taken");

        // The test outbound state has no trust_registry_listener_manager
        // configured, so the executor branch returns Ok(()) without
        // populating trust_check_results. What matters here is that we
        // did NOT synthesize any per-element unavailable result — the
        // pre-check was skipped correctly.
        assert!(
            ctx.trust_check_results
                .is_none(),
            "with tr metadata populated, no pre-check should have synthesized results"
        );
    }

    #[test]
    fn build_outbound_policy_input_puts_target_did_on_input_agent_did() {
        let mut ctx = test_pipeline_context();
        ctx.target_agent_context = Some(crate::surface_context::AgentContext {
            did_verified: false,
            did_verification: None,
            did: Some("did:test:target".to_string()),
            provider_did: None,
            authority_did: None,
            identity_issuer_did: None,
            trust_registry_did: None,
            agent_dna: None,
            trust_verification: None,
            source_trust_verification: None,
            target_trust_verification: None,
            tr_identity_mismatch: false,
        });

        let policy_input = build_outbound_policy_input(&ctx);
        let agent = policy_input
            .agent
            .expect("agent context set");
        assert_eq!(
            agent.did.as_deref(),
            Some("did:test:target"),
            "target agent DID must land on input.agent.did for Trust Check template resolution"
        );
    }

    #[test]
    fn build_outbound_policy_input_populates_a2a_from_body() {
        // The outbound (MA→TP) surface/transit-point OPA input must
        // expose the A2A payload as `input.a2a`, exactly like the inbound
        // (AP→MA) seam, so a transit-point policy can read `input.a2a.method`.
        // Pre-fix this field was never set on the outbound leg, so the identical
        // policy that passed inbound denied outbound.
        let mut ctx = test_pipeline_context(); // test_surface() is A2A
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{ "kind": "text", "text": "hello" }]
                    }
                }
            }))
            .unwrap(),
        ));

        let policy_input = build_outbound_policy_input(&ctx);
        let a2a = policy_input
            .a2a
            .as_ref()
            .expect("input.a2a must be populated on the outbound leg");
        assert_eq!(a2a.method.as_deref(), Some("message/send"));
        assert!(a2a.message.is_some(), "the A2A message payload must be carried through");

        // Exactly what OPA sees: the serialized PolicyInput's top-level `a2a`.
        let opa_input = serde_json::to_value(&policy_input).unwrap();
        assert_eq!(
            opa_input
                .get("a2a")
                .and_then(|a| a.get("method"))
                .and_then(|m| m.as_str()),
            Some("message/send"),
            "policy `input.a2a.method` must resolve on the transit-point leg"
        );
    }

    #[test]
    fn build_outbound_policy_input_omits_a2a_without_body() {
        // No body → no `a2a`: a clean absence so policies that guard on its
        // presence behave predictably (and non-A2A surfaces stay unaffected).
        let ctx = test_pipeline_context();
        let policy_input = build_outbound_policy_input(&ctx);
        assert!(policy_input.a2a.is_none(), "a2a must be absent when there is no request body to parse");
    }

    #[test]
    fn build_outbound_policy_input_populates_mcp_from_body() {
        // Parallel gap: an MCP transit-point policy must see the
        // tool request as `input.mcp` on the outbound leg, exactly like the
        // inbound MCP seam. `input.a2a` stays absent for an MCP surface.
        let mcp_surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "name": "test-mcp",
            "description": "Test",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/surfaces/order",
                "protocol": "mcp"
            },
            "target": { "endpoint": "http://localhost:9000" },
            "transit": {
                "points": [
                    { "alias": "partner-a", "target_endpoint": "https://partner.example.com/mcp", "gateway_url": "https://gw.internal:9000/outbound/surfaces/order/partner-a" }
                ]
            }
        }))
        .expect("mcp surface");

        let mut ctx = test_pipeline_context();
        ctx.surface = Arc::new(mcp_surface);
        ctx.body_bytes = Some(Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "search", "arguments": { "q": "hello" } }
            }))
            .unwrap(),
        ));

        let policy_input = build_outbound_policy_input(&ctx);
        let mcp = policy_input
            .mcp
            .as_ref()
            .expect("input.mcp must be populated on the outbound MCP leg");
        assert_eq!(mcp.method, "tools/call");
        assert_eq!(mcp.tool_name.as_deref(), Some("search"));

        let opa_input = serde_json::to_value(&policy_input).unwrap();
        assert_eq!(
            opa_input
                .get("mcp")
                .and_then(|m| m.get("method"))
                .and_then(|m| m.as_str()),
            Some("tools/call"),
            "policy `input.mcp.method` must resolve on the transit-point leg"
        );
        assert!(policy_input.a2a.is_none(), "a2a must be absent on an MCP surface");
    }

    #[test]
    fn build_outbound_policy_input_uses_modern_transit_admission_snapshot() {
        use crate::mcp::request_validation::{LegacySessionEvidence, validate_mcp_post};
        let body = json!({"jsonrpc": "2.0", "id": "task", "method": "tasks/get", "params": {
            "taskId": "original-task", "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {"extensions": {"io.modelcontextprotocol/tasks": {}}}
            }
        }});
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
        ctx.original_headers.insert(
            "mcp-protocol-version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        ctx.original_headers
            .insert("mcp-method", "tasks/get".parse().unwrap());
        ctx.mcp_classification = Some(
            validate_mcp_post(
                &ctx.original_headers,
                &serde_json::to_vec(&body).unwrap(),
                LegacySessionEvidence::Absent,
                crate::mcp::request_validation::MODERN_ONLY_POLICY,
            )
            .unwrap(),
        );
        ctx.body_bytes =
            Some(Bytes::from_static(br#"{"id":1,"method":"message/send","params":{"message":{"role":"user"}}}"#));

        let input = build_outbound_policy_input(&ctx);
        assert!(input.a2a.is_none());
        let mcp = serde_json::to_value(input.mcp.unwrap()).unwrap();
        assert_eq!(
            mcp,
            json!({
                "method": "tasks/get", "params": body["params"], "protocol_version": crate::mcp::MCP_MODERN_VERSION,
                "client_capabilities": body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
            })
        );
    }

    async fn delegation_state(
        directory: &std::path::Path,
        tokens: &[(&str, &str)],
    ) -> OutboundProxyState {
        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};

        let providers = Arc::new(
            FileSystemCredentialProviderStore::new(directory.join("providers"))
                .await
                .unwrap(),
        );
        let vault = Arc::new(
            FileSystemDelegationVaultStore::new(directory.join("vault"))
                .await
                .unwrap(),
        );
        let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new(
                directory
                    .join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .unwrap(),
        );
        for (provider, access_token) in tokens {
            providers
                .create(
                    serde_json::from_value(json!({
                        "id": provider, "name": provider, "provider_id": provider,
                        "resource": "https://provider.example/api",
                        "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
            vault
                .store(
                    serde_json::from_value(json!({
                        "id": format!("{provider}-token"), "agent_did": "did:web:agent.example",
                        "user_identity_hash": "sha256:user", "credential_provider_id": provider,
                        "provider_id": provider, "access_token": access_token,
                        "refresh_token": format!("{provider}-refresh"), "scopes": ["read"],
                        "expires_at": chrono::Utc::now() + chrono::Duration::hours(1),
                        "consent_granted_at": "2026-09-01T00:00:00Z",
                        "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        let mut state = test_outbound_state();
        state.credential_provider_store = Some(providers);
        state.delegation_vault_store = Some(vault);
        state.secrets_store = Some(secrets);
        state.gateway_base_url = Some("https://gateway.example".into());
        state
    }

    const DELEGATED_CREDENTIAL_FIELD: &str = "io.affinidi.fabric/delegated-credential";

    fn legacy_delegation_context(
        surface: Arc<crate::config::agent_surface::AgentSurface>,
        transit_point: TransitPoint,
    ) -> OutboundPipelineContext {
        let mut ctx = test_pipeline_context();
        ctx.surface = surface;
        ctx.virtual_channel = transit_point;
        ctx.body_bytes = Some(bytes::Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#,
        ));
        ctx.transit_token_claims = Some(
            serde_json::from_value(json!({"iss": "https://gateway.example", "surface_id": "transit-fabric",
                "iat": 0, "exp": u64::MAX, "jti": "jti", "user_identity_hash": "sha256:user"}))
            .unwrap(),
        );
        ctx.resolved_identity = ProtectedAgentIdentity::Managed {
            did: "did:web:agent.example".into(),
            identity_fields: std::collections::HashMap::new(),
        };
        ctx
    }

    async fn injected_credential(
        state: &OutboundProxyState,
        mut ctx: OutboundPipelineContext,
    ) -> serde_json::Value {
        step_inject_credentials(state, &mut ctx)
            .await
            .unwrap();
        let body = ctx
            .body_bytes
            .as_ref()
            .unwrap();
        assert!(!String::from_utf8_lossy(body).contains("-refresh"));
        serde_json::from_slice::<serde_json::Value>(body).unwrap()["params"]["_meta"][DELEGATED_CREDENTIAL_FIELD]
            .clone()
    }

    fn meta_transit_point(
        alias: &str,
        endpoint: &str,
        opted_in: bool,
        provider: Option<&str>,
    ) -> serde_json::Value {
        let mut point = json!({"alias": alias, "target_endpoint": endpoint, "fabric_delegated_credentials": opted_in});
        if let Some(provider) = provider {
            point["transit_credentials"] = json!({"credential_provider_id": provider, "scopes": ["read"],
                "inject_as": {"type": "meta", "field": DELEGATED_CREDENTIAL_FIELD}});
        }
        point
    }

    fn transit_surface(
        points: serde_json::Value,
        variants: serde_json::Value,
    ) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "transit-fabric", "name": "Transit Fabric",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://managed.example/agent"},
            "transit": {"points": points},
            "variants": variants
        }))
        .unwrap()
    }

    fn resolved_transit_point(
        surface: &crate::config::agent_surface::AgentSurface,
        variant: Option<&str>,
        alias: &str,
    ) -> (Arc<crate::config::agent_surface::AgentSurface>, TransitPoint) {
        let resolved = Arc::new(
            surface
                .resolve_variant(variant)
                .unwrap(),
        );
        let point = resolved
            .transit_points()
            .iter()
            .find(|point| point.alias == alias)
            .cloned()
            .unwrap();
        (resolved, point)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fabric_transit_points_withhold_delegated_credentials_unless_opted_in() {
        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[("provider", "transit-access")]).await;
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "transit-fabric", "name": "Transit Fabric",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://managed.example/agent"},
            "outbound_credentials": [{"credential_provider_id": "provider", "scopes": ["read"],
                "inject_as": {"type": "meta", "field": DELEGATED_CREDENTIAL_FIELD}}]
        }))
        .unwrap();
        let surface = Arc::new(surface);

        for (endpoint, opted_in, delegates) in [
            ("fabric://peer-gateway/peer-surface", false, false),
            ("fabric://peer-gateway/peer-surface", true, true),
            ("https://partner.example/mcp", false, true),
        ] {
            let transit_point = |mut ctx: OutboundPipelineContext| {
                ctx.surface = surface.clone();
                ctx.virtual_channel
                    .target_endpoint = endpoint.into();
                ctx.virtual_channel
                    .fabric_delegated_credentials = opted_in;
                ctx
            };
            let legacy = transit_point(test_pipeline_context());
            assert_eq!(
                legacy
                    .virtual_channel
                    .withholds_delegated_credentials(),
                !delegates,
                "{endpoint} opted_in={opted_in}"
            );
            let injected =
                injected_credential(&state, legacy_delegation_context(surface.clone(), legacy.virtual_channel)).await;
            if delegates {
                assert_eq!(injected, "transit-access", "{endpoint} opted_in={opted_in}");
            } else {
                assert!(injected.is_null(), "{endpoint} opted_in={opted_in}");
            }

            let mut modern = transit_point(modern_pipeline_context("tools/call"));
            let response = step_prepare_modern_credentials(&state, &mut modern)
                .await
                .unwrap();
            assert_eq!(response.is_some(), delegates, "{endpoint} opted_in={opted_in}");
            assert!(
                modern
                    .modern_delegation
                    .is_none()
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transit_points_inject_only_their_own_transit_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[("provider-a", "a-access"), ("provider-b", "b-access")]).await;
        let partner = meta_transit_point("partner", "https://partner.example/mcp", false, Some("provider-a"));
        let peer_endpoint = "fabric://peer-gateway/peer-surface";

        let surface =
            transit_surface(json!([partner, meta_transit_point("peer", peer_endpoint, true, None)]), json!([]));
        let (resolved, peer) = resolved_transit_point(&surface, None, "peer");
        assert!(
            injected_credential(&state, legacy_delegation_context(resolved.clone(), peer))
                .await
                .is_null()
        );
        let (_, partner_point) = resolved_transit_point(&surface, None, "partner");
        assert_eq!(injected_credential(&state, legacy_delegation_context(resolved, partner_point)).await, "a-access");

        let surface = transit_surface(
            json!([partner, meta_transit_point("peer", peer_endpoint, true, Some("provider-b"))]),
            json!([]),
        );
        let (resolved, peer) = resolved_transit_point(&surface, None, "peer");
        assert_eq!(injected_credential(&state, legacy_delegation_context(resolved, peer)).await, "b-access");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_caller_the_transit_points_source_auth_verified_keys_delegated_credentials_by_its_identity_hash() {
        use crate::surface_context::TransitClientVerification::{ResourceToken, SourceAuth};

        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[("provider", "token-caller-access")]).await;
        let jwt_caller = |subject: &str| crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: subject.to_string(),
            claims: json!({ "iss": "https://idp.example", "sub": subject }),
        };
        state
            .delegation_vault_store
            .as_ref()
            .unwrap()
            .store(
                serde_json::from_value(json!({
                    "id": "alice-token", "agent_did": "did:web:agent.example",
                    "user_identity_hash": jwt_caller("alice").principal_hash(None), "credential_provider_id": "provider",
                    "provider_id": "provider", "access_token": "alice-access",
                    "refresh_token": "alice-refresh", "scopes": ["read"],
                    "expires_at": chrono::Utc::now() + chrono::Duration::hours(1),
                    "consent_granted_at": "2026-09-01T00:00:00Z",
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let surface = transit_surface(
            json!([meta_transit_point("partner", "https://partner.example/mcp", false, Some("provider"))]),
            json!([]),
        );
        let (resolved, point) = resolved_transit_point(&surface, None, "partner");
        let context = |identity, verified_by, with_transit_token: bool| {
            let mut ctx = legacy_delegation_context(resolved.clone(), point.clone());
            if !with_transit_token {
                ctx.transit_token_claims = None;
            }
            ctx.authenticated_identity = Some(identity);
            ctx.authenticated_by = Some(verified_by);
            ctx
        };

        assert_eq!(injected_credential(&state, context(jwt_caller("alice"), SourceAuth, false)).await, "alice-access");
        assert_eq!(
            injected_credential(&state, context(jwt_caller("alice"), SourceAuth, true)).await,
            "token-caller-access",
            "the transit token's caller keys the grant when there is one"
        );

        let mut bob = context(jwt_caller("bob"), SourceAuth, false);
        assert!(
            step_inject_credentials(&state, &mut bob)
                .await
                .is_err(),
            "a caller without a grant of its own is not given another caller's"
        );

        let mut resource_token_caller = context(jwt_caller("alice"), ResourceToken, false);
        let refused = step_inject_credentials(&state, &mut resource_token_caller)
            .await
            .unwrap_err();
        assert!(
            matches!(
                refused,
                OutboundPipelineError::DelegationRefused {
                    refusal: DelegationRefusal::CallerIdentityMissing,
                    ..
                }
            ),
            "{refused:?}"
        );
    }

    /// A caller the Transit Point's `source_auth` verified reaches only the
    /// grant consented under how it was identified: the same subject from
    /// another issuer, the same name from another method, the same caller on
    /// another tenant's surface, and a token that names no subject get none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delegated_grants_are_keyed_by_how_the_caller_was_identified() {
        use crate::source_auth::AuthenticatedIdentity;
        use crate::surface_context::TransitClientVerification::SourceAuth;

        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[("provider", "token-caller-access")]).await;
        let jwt = |claims: serde_json::Value| AuthenticatedIdentity::JwtBearer {
            subject: claims["sub"]
                .as_str()
                .unwrap_or("<none>")
                .to_string(),
            claims,
        };
        let alice = jwt(json!({ "iss": "https://idp.example", "sub": "alice" }));
        let store_grant = |id: &'static str, user_identity_hash: String, access_token: &'static str| {
            let vault = state
                .delegation_vault_store
                .clone()
                .unwrap();
            async move {
                vault
                    .store(
                        serde_json::from_value(json!({
                            "id": id, "agent_did": "did:web:agent.example",
                            "user_identity_hash": user_identity_hash, "credential_provider_id": "provider",
                            "provider_id": "provider", "access_token": access_token,
                            "refresh_token": format!("{id}-refresh"), "scopes": ["read"],
                            "expires_at": chrono::Utc::now() + chrono::Duration::hours(1),
                            "consent_granted_at": "2026-09-01T00:00:00Z",
                            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                        }))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        };
        store_grant(
            "alice-token",
            alice
                .principal_hash(None)
                .unwrap(),
            "alice-access",
        )
        .await;
        // A grant under the hash of the `<none>` subject placeholder, which no
        // caller's identity hash is.
        store_grant(
            "no-subject-token",
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"<none>")),
            "no-subject-access",
        )
        .await;
        let surface = transit_surface(
            json!([meta_transit_point("partner", "https://partner.example/mcp", false, Some("provider"))]),
            json!([]),
        );
        let (resolved, point) = resolved_transit_point(&surface, None, "partner");
        let context = |identity: AuthenticatedIdentity, tenant: Option<&str>| {
            let mut ctx = legacy_delegation_context(resolved.clone(), point.clone());
            ctx.transit_token_claims = None;
            Arc::make_mut(&mut ctx.surface).tenant_id = tenant.map(str::to_string);
            ctx.authenticated_identity = Some(identity);
            ctx.authenticated_by = Some(SourceAuth);
            ctx
        };

        assert_eq!(injected_credential(&state, context(alice.clone(), None)).await, "alice-access");

        let refused = async |identity: AuthenticatedIdentity, tenant: Option<&str>| {
            step_inject_credentials(&state, &mut context(identity, tenant))
                .await
                .err()
        };
        for (case, identity, tenant) in [
            (
                "the same subject from another issuer",
                jwt(json!({ "iss": "https://partner.example", "sub": "alice" })),
                None,
            ),
            (
                "an API key secret of the same name",
                AuthenticatedIdentity::ApiKey {
                    key_name: "alice".into(),
                    provider_agent_id: None,
                },
                None,
            ),
            ("the same caller on another tenant's surface", alice.clone(), Some("tenant-b")),
        ] {
            assert!(
                refused(identity, tenant)
                    .await
                    .is_some(),
                "{case} must not get alice's grant"
            );
        }
        let second_without_subject = jwt(json!({ "iss": "https://idp.example", "client_id": "second" }));
        assert!(
            matches!(
                refused(second_without_subject, None).await,
                Some(OutboundPipelineError::DelegationRefused {
                    refusal: DelegationRefusal::CallerIdentityMissing,
                    ..
                })
            ),
            "a token that names no subject identifies no caller, so it gets no grant"
        );
    }

    /// The `credential_delegation` lines that refuse a Transit Point call for
    /// want of a caller or an agent to key its delegated credentials by name
    /// the surface variant that served it; a `source_auth` caller with no
    /// managed agent identity takes the second.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delegation_refusal_line_names_the_request_variant() {
        use crate::observability::policy_audit::{RequestScope, in_request, set_request_variant};
        use crate::surface_context::TransitClientVerification::SourceAuth;

        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[("provider", "transit-access")]).await;
        let surface = transit_surface(
            json!([meta_transit_point("partner", "https://partner.example/mcp", false, Some("provider"))]),
            json!([]),
        );
        let (resolved, point) = resolved_transit_point(&surface, None, "partner");
        let no_caller = || {
            let mut ctx = legacy_delegation_context(resolved.clone(), point.clone());
            ctx.transit_token_claims = None;
            ctx
        };
        let mut no_agent = no_caller();
        no_agent.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            claims: json!({ "iss": "https://idp.example", "sub": "alice" }),
        });
        no_agent.authenticated_by = Some(SourceAuth);
        no_agent.resolved_identity = ProtectedAgentIdentity::Anonymous;

        for (mut ctx, expected, line) in [
            (no_caller(), DelegationRefusal::CallerIdentityMissing, "identifies the caller - refusing the request"),
            (no_agent, DelegationRefusal::AgentIdentityMissing, "No managed agent identity for delegated credentials"),
        ] {
            let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
            let refused = in_request(RequestScope::fresh(), async {
                set_request_variant("beta");
                step_inject_credentials(&state, &mut ctx).await
            })
            .await
            .unwrap_err();
            assert!(
                matches!(refused, OutboundPipelineError::DelegationRefused { refusal, .. } if refusal == expected),
                "{line}: {refused:?}"
            );
            let lines: Vec<String> = logs
                .text()
                .lines()
                .filter(|text| text.contains(line))
                .map(str::to_string)
                .collect();
            assert_eq!(lines.len(), 1, "{line}: {lines:?}");
            assert!(lines[0].contains("surface_variant=\"beta\""), "{}", lines[0]);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fabric_transit_point_with_only_transit_credentials_follows_its_switch() {
        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[("provider", "transit-access")]).await;
        let peer_endpoint = "fabric://peer-gateway/peer-surface";

        for (opted_in, expected) in [(false, serde_json::Value::Null), (true, json!("transit-access"))] {
            let surface = transit_surface(
                json!([meta_transit_point("peer", peer_endpoint, opted_in, Some("provider"))]),
                json!([]),
            );
            assert!(
                surface
                    .outbound_credentials
                    .is_empty()
            );
            let (resolved, peer) = resolved_transit_point(&surface, None, "peer");
            assert_eq!(
                injected_credential(&state, legacy_delegation_context(resolved, peer)).await,
                expected,
                "opted_in={opted_in}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn variant_points_override_sets_the_transit_point_fabric_switch() {
        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[("provider", "transit-access")]).await;
        let peer_endpoint = "fabric://peer-gateway/peer-surface";
        let surface = transit_surface(
            json!([meta_transit_point("peer", peer_endpoint, false, Some("provider"))]),
            json!([
                {"id": "variant-on", "alias": "on", "name": "On", "overrides": {"transit": {"points": [
                    meta_transit_point("peer", peer_endpoint, true, Some("provider"))
                ]}}},
                {"id": "variant-off", "alias": "off", "name": "Off", "overrides": {"transit": {"points": [
                    meta_transit_point("peer", peer_endpoint, false, Some("provider"))
                ]}}}
            ]),
        );

        for (variant, expected) in [
            (None, serde_json::Value::Null),
            (Some("on"), json!("transit-access")),
            (Some("off"), serde_json::Value::Null),
        ] {
            let (resolved, peer) = resolved_transit_point(&surface, variant, "peer");
            assert_eq!(
                injected_credential(&state, legacy_delegation_context(resolved, peer)).await,
                expected,
                "{variant:?}"
            );
        }
    }

    fn header_values<'a>(
        headers: &'a HeaderMap,
        name: &str,
    ) -> Vec<&'a str> {
        headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect()
    }

    /// The managed agent's own credential headers on every request below.
    fn with_agent_supplied_credentials(mut ctx: OutboundPipelineContext) -> OutboundPipelineContext {
        for (name, value) in [
            ("authorization", "Bearer agent-supplied-token"),
            ("x-vendor-key", "agent-supplied-key"),
            ("cookie", "agent_session=1"),
        ] {
            ctx.original_headers
                .insert(name, HeaderValue::from_static(value));
        }
        ctx
    }

    /// A Transit Point context over [`delegation_state`] whose agent sends its
    /// own credential headers and `accept`, with `delegated` resolved for it and
    /// a `target_auth` static key under `target_auth_header`, for `method` and
    /// `path`.
    async fn credential_header_case(
        state: &OutboundProxyState,
        target_auth_header: Option<&str>,
        delegated: &[(&'static str, &'static str)],
        method: Method,
        path: &str,
    ) -> OutboundPipelineContext {
        if state
            .secrets_store
            .as_ref()
            .unwrap()
            .get_by_secret_id("target-key")
            .await
            .unwrap()
            .is_none()
        {
            state
                .secrets_store
                .as_ref()
                .unwrap()
                .create(crate::secrets::CreateSecretRequest {
                    tenant_id: None,
                    name: "Target key".into(),
                    secret_id: "target-key".into(),
                    description: None,
                    value: "target-static".into(),
                    secret_type: "ApiKey".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        let mut ctx = with_agent_supplied_credentials(test_pipeline_context());
        ctx.original_headers
            .insert("accept", HeaderValue::from_static("application/json"));
        ctx.original_method = method;
        ctx.request_path = path.to_string();
        ctx.virtual_channel
            .target_auth = target_auth_header.map(|header| {
            serde_json::from_value(json!({"method": {"static_secret": {
                "secret_id": "target-key", "header_name": header, "header_format": "Key {value}"}}}))
            .unwrap()
        });
        for (name, value) in delegated {
            ctx.delegated_credential_headers
                .insert(*name, HeaderValue::from_static(value));
        }
        ctx
    }

    fn sorted_headers(headers: impl IntoIterator<Item = (String, String)>) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = headers.into_iter().collect();
        headers.sort();
        headers
    }

    fn header_pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        sorted_headers(
            pairs
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string())),
        )
    }

    /// A case of the Transit Point header rule: its name, the `target_auth`
    /// header, the delegated credential headers, the request's method and path,
    /// and the headers the target receives, by lower-case name.
    type CredentialHeaderCase = (
        &'static str,
        Option<&'static str>,
        Vec<(&'static str, &'static str)>,
        Method,
        &'static str,
        Vec<(&'static str, &'static str)>,
    );

    /// Every case the Transit Point header rule decides.
    fn credential_header_rule_cases() -> Vec<CredentialHeaderCase> {
        let call = "/outbound/surfaces/order/partner-a/message/send";
        let discovery = "/outbound/surfaces/order/partner-a/.well-known/agent-card.json";
        vec![
            (
                "a delegated credential in place of the agent's header",
                None,
                vec![("authorization", "Bearer delegated-access"), ("x-vendor-key", "Key delegated-access")],
                Method::POST,
                call,
                vec![
                    ("accept", "application/json"),
                    ("authorization", "Bearer delegated-access"),
                    ("x-vendor-key", "Key delegated-access"),
                ],
            ),
            (
                "target authentication in place of the agent's header",
                Some("X-Vendor-Key"),
                vec![],
                Method::POST,
                call,
                vec![("accept", "application/json"), ("x-vendor-key", "Key target-static")],
            ),
            (
                "the agent's header named like target authentication withheld on a discovery read",
                Some("X-Vendor-Key"),
                vec![],
                Method::GET,
                discovery,
                vec![("accept", "application/json")],
            ),
            (
                "a delegated credential in place of target authentication of the same name",
                Some("Authorization"),
                vec![("authorization", "Bearer delegated-access")],
                Method::POST,
                call,
                vec![
                    ("accept", "application/json"),
                    ("authorization", "Bearer delegated-access"),
                    ("x-vendor-key", "agent-supplied-key"),
                ],
            ),
        ]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transit_request_headers_send_one_value_of_each_credential_header_and_never_the_agents_own() {
        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[]).await;
        for (case, target_auth_header, delegated, method, path, expected) in credential_header_rule_cases() {
            let mut ctx = credential_header_case(&state, target_auth_header, &delegated, method, path).await;

            let sent = transit_request_headers(&state, &mut ctx)
                .await
                .unwrap();

            assert_eq!(
                sorted_headers(
                    sent.iter()
                        .map(|(name, value)| (
                            name.to_string(),
                            value
                                .to_str()
                                .unwrap()
                                .to_string()
                        ))
                ),
                header_pairs(&expected),
                "{case}"
            );
        }
    }

    /// The Fabric leg hands the transport the headers of the Transit Point rule,
    /// in its buffered and its streamed form: delegated credentials and target
    /// authentication, never the agent's own `Authorization`, `Cookie` or a
    /// header named like the `target_auth` one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fabric_forward_carries_the_transit_point_credential_headers_and_no_agent_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[]).await;
        for (case, target_auth_header, delegated, method, path, expected) in credential_header_rule_cases() {
            let mut ctx = credential_header_case(&state, target_auth_header, &delegated, method, path).await;
            ctx.virtual_channel
                .target_endpoint = "fabric://peer-gateway/peer-surface".into();

            let (buffered, streamed) = fabric_forward_headers(&state, &mut ctx)
                .await
                .unwrap();

            assert_eq!(
                sorted_headers(buffered),
                sorted_headers(
                    header_pairs(&expected)
                        .into_iter()
                        .map(|(name, value)| (name.to_uppercase(), value))
                ),
                "{case}: buffered"
            );
            assert_eq!(
                sorted_headers(
                    streamed
                        .iter()
                        .map(|(name, value)| (
                            name.to_string(),
                            value
                                .to_str()
                                .unwrap()
                                .to_string()
                        ))
                ),
                header_pairs(&expected),
                "{case}: streamed"
            );
        }
    }

    /// A Fabric peer's response reaches the managed agent without the target's
    /// cookies and authentication challenges, on a buffered and on a streamed
    /// `2026-07-28` MCP response.
    #[tokio::test]
    async fn a_fabric_transit_point_response_withholds_the_targets_cookies_and_challenges() {
        let challenge_headers = || {
            let mut headers = HeaderMap::new();
            headers.append("set-cookie", HeaderValue::from_static("vendor_sid=one; HttpOnly"));
            headers.insert("www-authenticate", HeaderValue::from_static("Bearer error=\"invalid_token\""));
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            headers.insert("x-vendor-request-id", HeaderValue::from_static("vendor-9"));
            headers
        };
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .target_endpoint = "fabric://peer-gateway/peer-surface".into();
        let buffered = step_process_response(
            &state,
            &mut ctx,
            UpstreamResponse::Fabric {
                status: StatusCode::UNAUTHORIZED,
                headers: challenge_headers(),
                body: Bytes::from_static(br#"{"error":"invalid_token"}"#),
            },
        )
        .await
        .unwrap();

        let mut streamed_upstream = axum::response::Response::new(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": "stream", "result": {"resultType": "complete", "content": []}}).to_string(),
        ));
        *streamed_upstream.headers_mut() = challenge_headers();
        let mut modern = modern_pipeline_context("tools/call");
        modern
            .virtual_channel
            .target_endpoint = "fabric://peer-gateway/peer-surface".into();
        let streamed = process_modern_outbound_response(
            test_outbound_state(),
            modern,
            UpstreamResponse::FabricStream(streamed_upstream),
        )
        .await
        .unwrap();

        for (case, response) in [("buffered", buffered), ("streamed", streamed)] {
            assert!(
                !response
                    .headers()
                    .contains_key("set-cookie"),
                "{case}"
            );
            assert!(
                !response
                    .headers()
                    .contains_key("www-authenticate"),
                "{case}"
            );
            assert_eq!(response.headers()["x-vendor-request-id"], "vendor-9", "{case}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delegated_credential_headers_reach_the_target_and_the_agent_cannot_supply_or_replace_them() {
        let directory = tempfile::tempdir().unwrap();
        let state = delegation_state(directory.path(), &[("provider", "vendor-access")]).await;
        state
            .secrets_store
            .as_ref()
            .unwrap()
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "Target key".into(),
                secret_id: "target-key".into(),
                description: None,
                value: "target-static".into(),
                secret_type: "ApiKey".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        let target = crate::component_tests::helpers::RecordingTarget::start(StatusCode::OK, &[]).await;
        let delegated = |alias: &str, inject_as: serde_json::Value| {
            json!({"alias": alias, "target_endpoint": target.url, "transit_credentials":
                {"credential_provider_id": "provider", "scopes": ["read"], "inject_as": inject_as}})
        };
        let surface = transit_surface(
            json!([
                delegated("bearer", json!({"type": "bearer_header"})),
                delegated("custom", json!({"type": "custom_header", "name": "X-Vendor-Key", "format": "Key {value}"})),
                {"alias": "fixed", "target_endpoint": target.url, "target_auth": {"method": {"static_secret": {
                    "secret_id": "target-key", "header_name": "Authorization", "header_format": "Bearer {value}"}}}}
            ]),
            json!([]),
        );

        for (alias, authorization, vendor_key) in [
            ("bearer", vec!["Bearer vendor-access"], vec!["agent-supplied-key"]),
            ("custom", vec![], vec!["Key vendor-access"]),
            ("fixed", vec!["Bearer target-static"], vec!["agent-supplied-key"]),
        ] {
            let (resolved, point) = resolved_transit_point(&surface, None, alias);
            let mut ctx = with_agent_supplied_credentials(legacy_delegation_context(resolved, point));

            step_inject_credentials(&state, &mut ctx)
                .await
                .unwrap();
            step_forward_request(&state, &mut ctx)
                .await
                .unwrap();

            let received = target.received();
            let sent = received.last().unwrap();
            assert_eq!(header_values(sent, "authorization"), authorization, "{alias}: {sent:?}");
            assert_eq!(header_values(sent, "x-vendor-key"), vendor_key, "{alias}: {sent:?}");
            assert!(header_values(sent, "cookie").is_empty(), "{alias}: {sent:?}");
        }
        assert_eq!(target.received().len(), 3);
    }

    /// The Transit Point pipeline of a surface whose Transit Points, one per
    /// `(alias, protocol, binding)`, forward to `target_url`, over the vault and
    /// providers of [`delegation_state`], with the issuer whose tokens open them.
    async fn delegation_pipeline(
        directory: &std::path::Path,
        target_url: &str,
        points: &[(&str, &str, serde_json::Value)],
    ) -> (OutboundProxyState, crate::proxy::transit_token::TransitTokenIssuer) {
        let mut state = delegation_state(directory, &[("provider", "vendor-access")]).await;
        let providers = state
            .credential_provider_store
            .clone()
            .unwrap();
        for provider in [
            json!({"id": "no-endpoint", "name": "No endpoint", "provider_id": "no-endpoint"}),
            json!({"id": "broken-key", "name": "Broken key", "provider_id": "broken-key",
                "provider_type": "api_key", "api_key_secret_ref": "missing-secret"}),
            json!({"id": "consent", "name": "Consent", "provider_id": "consent",
                "authorization_endpoint": "https://provider.example/authorize", "client_id_secret_ref": "client-id"}),
        ] {
            let mut provider = provider;
            provider["created_at"] = json!("2026-10-01T00:00:00Z");
            provider["updated_at"] = json!("2026-10-01T00:00:00Z");
            providers
                .create(serde_json::from_value(provider).unwrap())
                .await
                .unwrap();
        }
        state
            .secrets_store
            .as_ref()
            .unwrap()
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "Client id".into(),
                secret_id: "client-id".into(),
                description: None,
                value: "gateway-client".into(),
                secret_type: "ApiKey".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        state
            .delegation_vault_store
            .as_ref()
            .unwrap()
            .store(
                serde_json::from_value(json!({
                    "id": "consented-elsewhere", "agent_did": "unknown", "user_identity_hash": "sha256:user",
                    "credential_provider_id": "provider", "provider_id": "provider",
                    "access_token": "grant-consented-on-another-surface", "scopes": ["read"],
                    "expires_at": chrono::Utc::now() + chrono::Duration::hours(1),
                    "consent_granted_at": "2026-10-01T00:00:00Z",
                    "created_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let points: Vec<serde_json::Value> = points
            .iter()
            .map(|(alias, protocol, binding)| {
                json!({"alias": alias, "protocol": protocol, "target_endpoint": target_url,
                    "transit_credentials": binding})
            })
            .collect();
        state
            .channel_state
            .write()
            .unwrap()
            .surface = Arc::new(transit_surface(json!(points), json!([])));
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            crate::proxy::transit_token::TransitTokenKey::generate().unwrap(),
            "gateway".into(),
        );
        state.transit_token_issuer = Some(Arc::new(issuer.clone()));
        (state, issuer)
    }

    async fn through_the_pipeline(
        state: &OutboundProxyState,
        alias: &str,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/outbound/mcp/{alias}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("x-transit-token", token)
            .body(axum::body::Body::from(
                json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "echo"}}).to_string(),
            ))
            .unwrap();
        let response = Box::pin(outbound_proxy_handler_with_mcp_versions(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            state.clone(),
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
        ))
        .await
        .unwrap_or_else(|error| error.into_response());
        let status = response.status();
        let body = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    fn binding(
        provider: &str,
        inject_as: serde_json::Value,
    ) -> serde_json::Value {
        json!({"credential_provider_id": provider, "scopes": ["read"], "inject_as": inject_as})
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transit_point_refuses_a_request_whose_delegated_credential_cannot_be_resolved() {
        let directory = tempfile::tempdir().unwrap();
        let target = crate::component_tests::helpers::RecordingTarget::start(StatusCode::OK, &[]).await;
        let bearer = json!({"type": "bearer_header"});
        let (state, issuer) = delegation_pipeline(
            directory.path(),
            &target.url,
            &[
                ("granted", "mcp", binding("provider", bearer.clone())),
                ("gone", "mcp", binding("deleted-provider", bearer.clone())),
                ("no-endpoint", "mcp", binding("no-endpoint", bearer.clone())),
                ("broken-key", "mcp", binding("broken-key", bearer.clone())),
                (
                    "bad-header",
                    "mcp",
                    binding("provider", json!({"type": "custom_header", "name": "Bad Header", "format": "{value}"})),
                ),
                ("plain", "http", binding("deleted-provider", bearer.clone())),
                ("untokened", "mcp", binding("provider", bearer.clone())),
            ],
        )
        .await;
        {
            let mut channel_state = state
                .channel_state
                .write()
                .unwrap();
            let mut surface = (*channel_state.surface).clone();
            for point in &mut surface
                .transit
                .as_mut()
                .unwrap()
                .points
            {
                point.require_transit_token = point.alias != "untokened";
                point.allow_unauthenticated_callers = point.alias == "untokened";
            }
            channel_state.surface = Arc::new(surface);
        }
        let token = |user: Option<&str>, agent: Option<&str>| {
            issuer
                .issue("transit-fabric", agent, None, None, user, None, vec![])
                .unwrap()
        };
        let authenticated = token(Some("sha256:user"), Some("did:web:agent.example"));
        let mut without_stores = state.clone();
        without_stores.delegation_vault_store = None;

        for (case, state, alias, token, status, code) in [
            ("anonymous caller", &state, "granted", token(None, Some("did:web:agent.example")), 403, -32001),
            ("no transit token where none is required", &state, "untokened", String::new(), 403, -32001),
            ("no agent identity", &state, "granted", token(Some("sha256:user"), None), 403, -32001),
            ("provider deleted", &state, "gone", authenticated.clone(), 503, -32603),
            ("no authorization endpoint", &state, "no-endpoint", authenticated.clone(), 503, -32603),
            ("api key unresolvable", &state, "broken-key", authenticated.clone(), 503, -32603),
            ("invalid credential header", &state, "bad-header", authenticated.clone(), 503, -32603),
            ("stores unavailable", &without_stores, "granted", authenticated.clone(), 503, -32603),
        ] {
            let (actual, body) = through_the_pipeline(state, alias, &token).await;

            assert_eq!(actual.as_u16(), status, "{case}: {body}");
            assert_eq!(body["jsonrpc"], "2.0", "{case}: {body}");
            assert_eq!(body["id"], 7, "{case}: {body}");
            assert_eq!(body["error"]["code"], code, "{case}: {body}");
            assert!(target.received().is_empty(), "{case}: the target must not be called");
        }

        let (status, body) = through_the_pipeline(&state, "plain", &authenticated).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["detail"], "Delegated credentials unavailable", "{body}");
        assert!(target.received().is_empty());

        let (status, body) = through_the_pipeline(&state, "granted", &authenticated).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let received = target.received();
        assert_eq!(received.len(), 1);
        assert_eq!(header_values(&received[0], "authorization"), ["Bearer vendor-access"]);
    }

    /// A public discovery read needs no transit token and names no caller, so
    /// it reaches the target without a delegated credential, as it does without
    /// a target authentication one, rather than being refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_public_discovery_read_through_a_credentialed_transit_point_carries_no_credential() {
        let directory = tempfile::tempdir().unwrap();
        let target = crate::component_tests::helpers::RecordingTarget::start(StatusCode::OK, &[]).await;
        let (state, _) = delegation_pipeline(
            directory.path(),
            &target.url,
            &[("granted", "mcp", binding("provider", json!({"type": "bearer_header"})))],
        )
        .await;
        let request = Request::builder()
            .method("GET")
            .uri("/outbound/mcp/granted/.well-known/agent-card.json")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = Box::pin(outbound_proxy_handler_with_mcp_versions(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            state,
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
        ))
        .await
        .unwrap_or_else(|error| error.into_response());

        assert_eq!(response.status(), StatusCode::OK);
        let received = target.received();
        assert_eq!(received.len(), 1);
        assert!(header_values(&received[0], "authorization").is_empty(), "{:?}", received[0]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transit_point_still_asks_for_consent_when_no_grant_is_stored() {
        let directory = tempfile::tempdir().unwrap();
        let target = crate::component_tests::helpers::RecordingTarget::start(StatusCode::OK, &[]).await;
        let (state, issuer) = delegation_pipeline(
            directory.path(),
            &target.url,
            &[("consent", "mcp", binding("consent", json!({"type": "bearer_header"})))],
        )
        .await;
        let token = issuer
            .issue("transit-fabric", Some("did:web:agent.example"), None, None, Some("sha256:user"), None, vec![])
            .unwrap();

        let (status, body) = through_the_pipeline(&state, "consent", &token).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["type"], "https://affinidi.com/atg/errors/consent-required");
        assert_eq!(body["consent_required"][0]["provider_name"], "Consent");
        assert!(
            body["consent_required"][0]["authorization_url"]
                .as_str()
                .unwrap()
                .starts_with("https://provider.example/authorize?"),
            "{body}"
        );
        assert_eq!(
            body.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            ["consent_required", "detail", "status", "title", "type"].into()
        );
        assert!(target.received().is_empty());
    }
}
