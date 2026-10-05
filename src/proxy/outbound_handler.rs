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

    #[error("{error}")]
    McpMetadata { error: crate::mcp::meta::McpMetadataError, body: Bytes, response: bool },

    #[error("Request blocked by gateway policy")]
    GatewayPolicyDenied,

    #[error("Request blocked by gateway policy: {0}")]
    GatewayPolicyError(String),

    #[error("Request blocked by surface policy")]
    SurfacePolicyDenied,

    #[error("Request blocked by surface policy: {0}")]
    SurfacePolicyError(String),

    #[error("Target authentication credentials unavailable")]
    TargetAuthUnavailable,

    #[error("Transit token missing or invalid: {0}")]
    TransitTokenInvalid(String),

    #[error("Credential delegation consent required")]
    ConsentRequired(String),

    #[error("Delegated credentials unavailable")]
    DelegationUnavailable,

    #[error("MCP resource authorization failed")]
    McpResourceAuthorization {
        config: Box<crate::mcp::resource_server::McpResourceServerConfig>,
        error: crate::mcp::resource_server::ResourceTokenError,
    },

    #[error("Upstream request timed out")]
    UpstreamTimeout,

    #[error("Upstream connection failed: {0}")]
    UpstreamConnectionFailed(String),

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

impl OutboundPipelineError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::McpValidation(error) => error.status,
            Self::McpIdentityInvalid => StatusCode::UNPROCESSABLE_ENTITY,
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

            Self::BodyReadFailed(_) | Self::HeaderMetadataMappingFailed(_) => StatusCode::BAD_REQUEST,

            Self::ExtensionValidationFailed(_) | Self::ProtocolMismatch { .. } => StatusCode::UNPROCESSABLE_ENTITY,

            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,

            Self::TransitTokenInvalid(_) | Self::ConsentRequired(_) => StatusCode::UNAUTHORIZED,

            Self::DelegationUnavailable => StatusCode::SERVICE_UNAVAILABLE,
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
            | Self::ResponseValidationFailed(_) => StatusCode::BAD_GATEWAY,

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
    /// Request path (used to build target URL).
    pub request_path: String,
    /// Protected agent identity resolved by `step_resolve_agent_identity`.
    pub resolved_identity: ProtectedAgentIdentity,
    /// Detected protocol (A2A, MCP, HTTP).
    pub protocol: Option<ChannelProtocol>,
    pub mcp_metadata_context: crate::mcp::meta::McpMetadataContext,
    pub mcp_classification: Option<crate::mcp::request_validation::McpRequestClassification>,
    pub authenticated_identity: Option<crate::source_auth::AuthenticatedIdentity>,
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
    /// Marker: the surface has a non-empty target-leg `trust_check_list`
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
    /// via `build_outbound_policy_input`. `None` when the target leg has
    /// no `trust_check_list` configured for this surface variant.
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
    /// Size in bytes of the upstream response body, captured by
    /// `step_process_response` before the body is consumed. Used by
    /// `step_record_metrics` for per-transit-point throughput accounting.
    pub response_bytes: Option<u64>,
    /// Surface variant alias parsed from the request route (`/route$alias/tp/...`).
    /// `None` when the request targets the default variant.
    pub active_variant_alias: Option<String>,
    pub active_variant_id: Option<String>,
    pub variant_resolution_error: Option<crate::config::agent_surface_variants::VariantResolveError>,
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
        // `/outgoing/<route>/<alias>` convention — `state.vc_alias_override`
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

        // Resolve the variant from the surface. On failure we fall
        // back to the unresolved base surface so the request still
        // proceeds.
        let active_variant_id = match active_variant_alias.as_deref() {
            Some(alias) => surface_for_resolve
                .variants
                .iter()
                .find(|variant| variant.enabled && variant.alias == alias)
                .map(|variant| variant.id.clone()),
            None => surface_for_resolve
                .default_variant_id
                .clone(),
        };
        let (surface, variant_resolution_error) =
            match surface_for_resolve.resolve_variant(active_variant_alias.as_deref()) {
                Ok(resolved) => {
                    let error = active_variant_alias
                        .as_deref()
                        .filter(|alias| {
                            !surface_for_resolve
                                .variants
                                .iter()
                                .any(|variant| variant.alias == *alias)
                        })
                        .map(|alias| {
                            crate::config::agent_surface_variants::VariantResolveError::UnknownAlias(alias.to_string())
                        });
                    (Arc::new(resolved), error)
                }
                Err(e) => {
                    tracing::warn!(
                        surface = %cs_surface_for_resolve.name,
                        alias = ?active_variant_alias,
                        error = %e,
                        "AgentSurface variant resolution failed; using base surface"
                    );
                    (surface_for_resolve, Some(e))
                }
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
            request_path,
            resolved_identity: ProtectedAgentIdentity::Anonymous,
            protocol: None,
            mcp_metadata_context: crate::mcp::meta::McpMetadataContext::legacy(surface.mcp_legacy_metadata_output),
            mcp_classification: None,
            authenticated_identity: None,
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
            response_bytes: None,
            active_variant_alias,
            active_variant_id,
            variant_resolution_error,
            surface,
            identity_rules_engine,
            identity_selector,
        })
    }
}

// ── Virtual channel resolution ──────────────────────────────────────────────

/// Extract the transit-point name (and optional surface-variant alias) from
/// the outbound path and look up the matching outbound virtual channel.
///
/// Path layout:  `/outgoing/<aap-path>[$variant-alias]/<tp-name>[/<remainder>]`
///
/// Axum provides the full request path including `/outgoing/`. The optional
/// `$variant-alias` suffix on the route selects a surface variant; the
/// variant alias is returned to the caller so it can be threaded through
/// the pipeline.
fn resolve_virtual_channel(
    path: &str,
    surface: &crate::config::agent_surface::AgentSurface,
) -> Result<(TransitPoint, Option<String>), OutboundPipelineError> {
    // Strip the /outgoing prefix first.
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
    let mut subscription_access =
        crate::mcp::subscriptions::SubscriptionLifetime::new(std::time::Duration::from_secs(86_400), None);
    let mut ctx = OutboundPipelineContext::new(addr, req, &state)?;

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

    if let Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) = ctx
        .mcp_classification
        .as_ref()
    {
        if let Some(error) = ctx
            .variant_resolution_error
            .as_ref()
        {
            let status = match error {
                crate::config::agent_surface_variants::VariantResolveError::UnknownAlias(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            return Err(OutboundPipelineError::McpValidation(Box::new(
                crate::mcp::request_validation::McpRequestValidationError {
                    status,
                    id: request.id.clone(),
                    code: crate::mcp::error_codes::INTERNAL_ERROR,
                    message: "MCP Transit Point variant is unavailable".into(),
                    data: None,
                },
            )));
        }
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
    step_record_metrics(&state, &ctx);

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
/// Without a valid transit token, the request is rejected with 401 Unauthorized.
async fn step_validate_transit_token(
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

    if !ctx
        .virtual_channel
        .require_transit_token
    {
        // Per-TP opt-out: this transit point is configured to accept
        // calls without a transit token (e.g. dev/testing or a TP whose
        // callers cannot carry one).
        debug!(
            request_id = %ctx.request_id,
            alias = %ctx.virtual_channel.alias,
            "Transit token enforcement disabled for this transit point, skipping validation"
        );
        return Ok(());
    }

    let modern = matches!(
        ctx.mcp_classification
            .as_ref(),
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
    );
    if modern {
        ctx.transit_token_claims = None;
    }
    let Some(ref issuer) = state.transit_token_issuer else {
        if modern {
            return Err(OutboundPipelineError::TransitTokenInvalid("Transit token validation is unavailable".into()));
        }
        // Transit token issuer not configured — skip validation.
        // This allows the outbound pipeline to degrade gracefully when the
        // gateway is not configured for transit token enforcement.
        debug!(request_id = %ctx.request_id, "Transit token issuer not configured, skipping validation");
        return Ok(());
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

    // Validate the token and check it's authorized for this specific transit point.
    let transit_point_name = &ctx.virtual_channel.alias;
    let claims = issuer
        .validate_for_transit_point(token, transit_point_name)
        .map_err(|e| OutboundPipelineError::TransitTokenInvalid(e.to_string()))?;

    if modern {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                OutboundPipelineError::TransitTokenInvalid("Transit token validation clock is unavailable".into())
            })?
            .as_secs();
        if claims.surface_id != ctx.surface.surface_id
            || claims.surface_id.is_empty()
            || claims.exp <= now
            || claims.iat > now
            || claims.exp <= claims.iat
            || claims.jti.is_empty()
        {
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
    Ok(())
}

async fn step_source_auth(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    if let Some(authorization) = ctx
        .virtual_channel
        .mcp_http
        .as_ref()
        .and_then(|http| http.authorization.as_ref())
    {
        use crate::mcp::resource_server::ResourceTokenError;

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
            || ctx
                .outbound_shared
                .source_auth
                .is_some()
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
        ctx.mcp_resource_authorization = Some(authorization);
        return Ok(());
    }
    if ctx
        .outbound_shared
        .source_auth
        .is_none()
    {
        return Ok(());
    }
    // Future: delegate to SourceAuthMiddleware.
    debug!(request_id = %ctx.request_id, "step_source_auth: source_auth present but not yet enforced (MVP)");
    Ok(())
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
        let mut normalized = crate::mcp::meta::normalize_bytes(&body, ctx.mcp_metadata_context).map_err(|error| {
            OutboundPipelineError::McpMetadata {
                error,
                body: body.clone(),
                response: false,
            }
        })?;
        if let Some(capped) = policy.cap_legacy_initialize(&normalized, &classification) {
            info!(
                request_id = %ctx.request_id,
                "Forwarding MCP initialize with protocolVersion {} in place of unsupported {}",
                capped.offered,
                capped.requested_for_log()
            );
            normalized = capped.body;
        }
        ctx.body_bytes = Some(normalized);
        crate::protocols::extensions::verify_mcp_metadata_identity(
            &body,
            state.vc_issuer.as_ref(),
            &ctx.surface.surface_id,
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

fn should_forward_outbound_request_header(
    name: &str,
    header_metadata_mapping: Option<&crate::config::header_metadata_mapping::HeaderMetadataMappingConfig>,
) -> bool {
    if !crate::a2a::should_forward_request_header(name) {
        return false;
    }

    if name.eq_ignore_ascii_case("authorization") {
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
async fn fetch_agent_card(
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
        let candidate = card_url.clone();
        let client = match tokio::task::spawn_blocking(move || {
            crate::egress::pinned_forward_client(&candidate, timeout)
        })
        .await
        {
            Ok(Ok((client, _target))) => client,
            Ok(Err(e)) => {
                warn!(request_id = %request_id, url = %card_url, "Agent card URL blocked by egress policy: {}", e);
                continue;
            }
            Err(e) => {
                warn!(request_id = %request_id, url = %card_url, "Agent card egress validation task failed: {}", e);
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
                            url = %card_url,
                            "Agent card URL response exceeded its bounds, trying next"
                        );
                    }
                }
            }
            Ok(resp) => {
                debug!(
                    request_id = %request_id,
                    status = %resp.status(),
                    url = %card_url,
                    "Agent card URL returned non-success status, trying next"
                );
            }
            Err(e) => {
                debug!(
                    request_id = %request_id,
                    error = %e,
                    url = %card_url,
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
/// Runs whenever the surface's target-leg Trust Check list is non-empty.
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
        .surface
        .target
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
/// `input.trust_check_results`. No-ops when the surface variant has no
/// `target.trust_check_list` configured or when the listener manager is
/// not available. Per-element failures are encoded inside the result
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
/// `input.trust_check_results`. No-ops when the surface variant has no
/// `target.trust_check_list` configured. Per-element failures are
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
/// target leg has an active `trust_check_list`), this stage synthesizes a
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
        .surface
        .target
        .trust_check_list
        .clone();
    if target_elements.is_empty() {
        return Ok(());
    }

    if ctx.target_agent_card_unavailable {
        let synthesized = synthesize_target_unavailable_results(
            ctx.surface
                .surface_id
                .as_str(),
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
        let synthesized = synthesize_target_unavailable_results(
            ctx.surface
                .surface_id
                .as_str(),
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
                ctx.surface
                    .surface_id
                    .as_str(),
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
        ctx.surface
            .surface_id
            .as_str(),
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

/// Build the per-element target-leg `TrustCheckResult` list for the
/// whole-surface `AGENT_CARD_UNAVAILABLE` path (card fetch itself
/// failed) and emit the matching audit events. The
/// `TRUST_REGISTRY_METADATA_UNAVAILABLE` path is per-element and lives
/// in [`crate::trust_registry_verification::metadata_gate`], driven
/// automatically by [`run_trust_check_stage`].
fn synthesize_target_unavailable_results(
    surface_id: &str,
    elements: &[crate::trust_registry_verification::TrustCheckElement],
    error_code: &'static str,
    error_detail: &'static str,
) -> Vec<crate::trust_registry_verification::TrustCheckResult> {
    elements
        .iter()
        .map(|elem| {
            let result =
                crate::trust_registry_verification::synthesize_failure(elem, error_code, error_detail.to_string());
            crate::observability::trust_check_audit::record_trust_check(
                crate::observability::trust_check_audit::TrustCheckAuditEvent {
                    surface_id,
                    leg: crate::trust_registry_verification::TrustCheckLeg::Target,
                    element_id: elem.id.as_str(),
                    element_name: elem.name.as_deref(),
                    // Match the wire shape: the two "unavailable" codes
                    // omit authority_id / entity_id since the raw
                    // template strings would be noise on those paths.
                    authority_id: None,
                    entity_id: None,
                    trust_registry_id: elem
                        .trust_registry_id
                        .as_str(),
                    query_type: elem.query_type,
                    ok: false,
                    error_code: Some(error_code),
                    error_detail: Some(error_detail),
                    latency_ms: 0,
                },
            );
            result
        })
        .collect()
}

/// The protected agent's DID for outbound policy-audit attribution, or `None`
/// when no managed identity was resolved.
fn outbound_actor_did(ctx: &OutboundPipelineContext) -> Option<&str> {
    match &ctx.resolved_identity {
        ProtectedAgentIdentity::Managed { did, .. } => Some(did.as_str()),
        ProtectedAgentIdentity::Anonymous => None,
    }
}

/// The inbound caller a transit token carries, for attributing outbound decisions.
fn outbound_caller(ctx: &OutboundPipelineContext) -> Option<crate::delegation_vault::audit::AuditCallerContext> {
    ctx.transit_token_claims
        .as_ref()
        .and_then(crate::delegation_vault::audit::transit_caller_context)
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
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: self.scope,
            allow,
            reason,
            policy_id: Some(self.policy_id),
            policy_definition_id: self.policy_definition_id,
            policy_name: self.policy_name,
            surface_id: self.surface_id,
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
        info!(request_id = %ctx.request_id, "[OPA-INPUT] Outbound gateway OPA skipped: no gateway_policy_manager");
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
        info!(request_id = %ctx.request_id, "[OPA-INPUT] Outbound gateway OPA skipped: no self gateway id");
        return Ok(());
    };
    if !gw_pm.is_enforced(&gateway_id) {
        info!(
            request_id = %ctx.request_id,
            gateway_id = %gateway_id,
            "[OPA-INPUT] Outbound gateway OPA skipped: no gateway policy configured, allowing"
        );
        return Ok(());
    }
    info!(request_id = %ctx.request_id, "[OPA-INPUT] Outbound gateway OPA using gateway_id={}", gateway_id);

    let policy_input = build_outbound_policy_input(ctx);
    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
    // [OPA-INPUT] Outbound gateway policy input before eval
    info!(request_id = %ctx.request_id, "[OPA-INPUT] Outbound gateway policy input before eval: {}", input_value);
    let (policy_definition_id, policy_name, policy_version, policy_hash) = match gw_pm.policy_evidence(&gateway_id) {
        Some((id, version, hash)) => {
            let name = gw_pm
                .resolve_policy_name_or_default(id.as_deref())
                .await;
            (id, name, version, Some(hash))
        }
        None => (None, crate::policies::GATEWAY_POLICY_PACKAGE.to_string(), None, None),
    };
    let caller = outbound_caller(ctx);

    let audit = OutboundPolicyAudit {
        scope: crate::observability::PolicyScope::Gateway,
        policy_id: crate::policies::GATEWAY_POLICY_PACKAGE,
        policy_definition_id: policy_definition_id.as_deref(),
        policy_name: Some(policy_name.as_str()),
        surface_id: ctx.surface.config_id(),
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
            audit.record(false, Some(e.as_str()));
            warn!(request_id = %ctx.request_id, error = %e, "Gateway OPA evaluation error (denying)");
            return Err(OutboundPipelineError::GatewayPolicyError(e.to_string()));
        }
    }

    Ok(())
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
        info!(request_id = %ctx.request_id, "[OPA-INPUT] Outbound channel OPA skipped: no opa_policy_definition_id on outbound config");
        return Ok(());
    };

    let Some(pm) = &state.policy_manager else {
        warn!(
            request_id = %ctx.request_id,
            "[OPA-INPUT] Outbound channel OPA skipped: SurfacePolicyManager not available; denying"
        );
        return Err(OutboundPipelineError::SurfacePolicyError(
            "Outbound OPA policy configured but policy manager not available".to_string(),
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
        return Err(OutboundPipelineError::SurfacePolicyError(
            "Outbound OPA policy configured but not compiled".to_string(),
        ));
    }

    let policy_input = build_outbound_policy_input(ctx);
    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
    // [OPA-INPUT] Outbound surface policy input before eval
    info!(request_id = %ctx.request_id, config_id = %config_id,
        "[OPA-INPUT] Outbound surface policy input before eval: {}", input_value);

    debug!(
        request_id = %ctx.request_id,
        config_id = %config_id,
        input = %serde_json::to_string_pretty(&input_value).unwrap_or_default(),
        "Outbound channel OPA policy input"
    );

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
        policy_name: Some(policy_name.as_str()),
        surface_id: Some(config_id),
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
            audit.record(false, Some(e.as_str()));
            warn!(request_id = %ctx.request_id, error = %e, "Channel OPA evaluation error (denying)");
            return Err(OutboundPipelineError::SurfacePolicyError(e.to_string()));
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
        return Err(OutboundPipelineError::SurfacePolicyError(
            "Transit point OPA policy configured but policy manager not available".to_string(),
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
        return Err(OutboundPipelineError::SurfacePolicyError(
            "Transit point OPA policy configured but not compiled".to_string(),
        ));
    }

    let policy_input = build_outbound_policy_input(ctx);
    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
    // [OPA-INPUT] Outbound transit point policy input before eval
    info!(request_id = %ctx.request_id, alias = %ctx.virtual_channel.alias,
        "[OPA-INPUT] Outbound transit point policy input before eval: {}", input_value);

    let (policy_name, policy_version, policy_hash) = pm
        .resolve_policy_decision_evidence(Some(tp_def_id.as_str()))
        .await;
    let caller = outbound_caller(ctx);
    let audit = OutboundPolicyAudit {
        scope: crate::observability::PolicyScope::Surface,
        policy_id: crate::policies::SURFACE_POLICY_PACKAGE,
        policy_definition_id: Some(tp_def_id.as_str()),
        policy_name: Some(policy_name.as_str()),
        surface_id: Some(config_id),
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
            audit.record(false, Some(e.as_str()));
            warn!(
                request_id = %ctx.request_id,
                alias = %ctx.virtual_channel.alias,
                error = %e,
                "Per-transit-point OPA evaluation error (denying)"
            );
            return Err(OutboundPipelineError::SurfacePolicyError(e.to_string()));
        }
    }

    Ok(())
}

/// [10.6] Per-Transit-Point MCP Tool Gating — `tools/call` leg.
///
/// Blocks an outbound `tools/call` toward this transit point when the TP's
/// MCP tool gating firewall hides the named tool. Parity with the
/// `tools/list` filter applied on the response leg, so a tool the managed
/// agent can't see it also can't invoke. Only runs for MCP transit points
/// that have gating installed; a missing tool name or absent gating passes
/// through. The gate condition is evaluated against the same outbound
/// `PolicyInput` the transit-point OPA gate sees, with `mcp.method` pinned to
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
    let Some(pm) = state.policy_manager.as_ref() else {
        return Ok(());
    };
    let config_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");
    let alias = ctx
        .virtual_channel
        .alias
        .as_str();
    let Some(gating) = pm
        .compiled_mcp_tool_gating_for_transit(config_id, alias)
        .filter(|g| !g.is_empty())
    else {
        return Ok(());
    };

    let tool_name = ctx
        .body_bytes
        .as_ref()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .and_then(|v| {
            v.get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .map(str::to_string)
        });
    let Some(tool_name) = tool_name else {
        return Ok(());
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

    let input = ResponsePolicyInput {
        response: ResponseContext {
            status_code: status.as_u16(),
            body: body_json,
            content_type,
            is_error: status.is_client_error() || status.is_server_error(),
            method: None,
        },
        caller: RpCallerContext {
            did: match &ctx.resolved_identity {
                ProtectedAgentIdentity::Managed { did, .. } => Some(did.clone()),
                ProtectedAgentIdentity::Anonymous => None,
            },
            identity_source: None,
            dna_uai: None,
        },
        surface: SurfaceContext {
            id: config_id.to_string(),
            name: ctx.surface.name.clone(),
            protocol: format!("{:?}", ctx.surface.channel_protocol()).to_lowercase(),
        },
        metadata: None,
    };

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
        audit.record(false, decision.reason.as_deref());
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
        ..Default::default()
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
            .and_then(|cfg| match cfg.caller_source {
                crate::config::types::CallerContextSource::TransitToken => ctx
                    .transit_token_claims
                    .as_ref()
                    .and_then(|claims| {
                        crate::proxy::workload_binding::capture_from_transit_token(claims, &cfg.caller_context_fields)
                            .ok()
                    }),
                crate::config::types::CallerContextSource::AuthorizationBearerJwt => ctx
                    .original_headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|auth| {
                        crate::proxy::workload_binding::capture_from_bearer_jwt(auth, &cfg.caller_context_fields).ok()
                    }),
                // Transit Point calls are made by the managed agent, not the
                // original DID-authenticated caller — the raw DID is not
                // available on this hop. Use `TransitToken` here so the
                // AP-hop's `SHA256(did)` user_hash flows through the transit
                // token, then set `caller_source: did` on the target-leg
                // workload binding where the AP-inbound authenticated
                // identity is still in scope.
                crate::config::types::CallerContextSource::Did => None,
            });
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
                policy_decisions: crate::observability::policy_audit::current_policy_decisions(),
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
    if let Some(vp_jwt) = injected_vp_jwt
        && crate::delegation_vault::audit::identity_binding_vp_audit_enabled()
    {
        let mut evt = crate::delegation_vault::audit::audit_event(
            crate::delegation_vault::audit::DelegationAuditAction::VpInjected,
            None,
            None,
            None,
            Some(
                ctx.surface
                    .surface_id
                    .as_str(),
            ),
        );
        evt.agent_identity_did = Some(did.clone());
        evt.channel_name = Some(channel_name.to_string());
        evt.target_endpoint = Some(
            ctx.virtual_channel
                .target_endpoint
                .clone(),
        );
        evt.protocol = Some(format!("{:?}", protocol).to_lowercase());
        evt.via_fabric = true;
        evt.vp_fingerprint = Some(crate::delegation_vault::audit::vp_fingerprint(&vp_jwt));
        evt.vp_jwt = Some(vp_jwt);
        evt.trace_id = Some(ctx.request_id.clone());
        evt.detail = Some("transit_point".to_string());
        crate::delegation_vault::audit::audit(evt);
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
                .map_err(|_| OutboundPipelineError::DelegationUnavailable)?;
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

/// [11] Credential Injection — resolve delegated OAuth tokens from the credential
/// vault and inject them into the outbound request, or return a consent_required
/// signal if the user has not yet authorized.
///
/// The user identity hash is extracted from the transit token claims (which encodes
/// the original caller's authenticated identity). The channel's `outbound_credentials`
/// bindings determine which credential providers to look up.
async fn step_inject_credentials(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
) -> Result<(), OutboundPipelineError> {
    let mut outbound_creds = ctx
        .surface
        .outbound_credentials();
    if let Some(prepared) = ctx.modern_delegation.as_ref() {
        outbound_creds.retain(|binding| {
            !prepared
                .handled_provider_ids
                .contains(&binding.credential_provider_id)
        });
    }
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
                "Credential delegation configured but stores not available — skipping"
            );
            return Ok(());
        }
    };

    // Extract user_identity_hash from the transit token (carries the original caller context)
    let user_hash = match ctx
        .transit_token_claims
        .as_ref()
        .and_then(|c| {
            c.user_identity_hash
                .as_deref()
        }) {
        Some(h) => h.to_string(),
        None => {
            warn!(
                target: "credential_delegation",
                request_id = %ctx.request_id,
                "Transit token does not carry user_identity_hash — cannot look up credentials"
            );
            return Ok(());
        }
    };

    // Use agent DID from identity extraction or fall back to surface_id from token
    let agent_did = match &ctx.resolved_identity {
        ProtectedAgentIdentity::Managed { did, .. } => Some(did.as_str()),
        ProtectedAgentIdentity::Anonymous => None,
    }
    .or_else(|| {
        ctx.transit_token_claims
            .as_ref()
            .and_then(|c| c.sub.as_deref())
    })
    .unwrap_or("unknown");

    let channel_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");

    let mcp_tool = ctx.operation.as_deref();

    let audit_ctx = crate::proxy::credential_delegation::DelegationAuditContext {
        caller: None,
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
        mcp_tool_name: mcp_tool.map(String::from),
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
        mcp_tool,
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
        return Err(OutboundPipelineError::DelegationUnavailable);
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
                                    meta_field = %field,
                                    "Injecting delegated credential into outbound MCP metadata"
                                );
                            }
                            Err(error) => {
                                warn!(
                                    target: "credential_delegation",
                                    request_id = %ctx.request_id,
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
                            header = %name,
                            "Injecting delegated credential header into outbound request"
                        );
                        if let Ok(header_name) = name.parse::<axum::http::header::HeaderName>()
                            && let Ok(header_value) = value.parse::<axum::http::header::HeaderValue>()
                        {
                            ctx.original_headers
                                .insert(header_name, header_value);
                        }
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

    // Forward safe, non-hop-by-hop request headers (keys uppercased so the
    // remote gateway and upstream see case-stable header names, matching the
    // inbound fabric forward).
    let mut headers_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut stream_headers = axum::http::HeaderMap::new();
    let is_modern = matches!(
        ctx.mcp_classification
            .as_ref(),
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
    );
    for (key, value) in &ctx.original_headers {
        if should_forward_outbound_request_header(
            key.as_str(),
            ctx.virtual_channel
                .header_metadata_mapping_if_supported(),
        ) && let Ok(v) = value.to_str()
        {
            headers_map.insert(key.as_str().to_uppercase(), v.to_string());
            stream_headers.append(key.clone(), value.clone());
        }
    }

    // Apply target authentication if configured.
    if let Some(ref target_auth) = ctx
        .virtual_channel
        .target_auth
    {
        match crate::proxy::handler::inject_target_auth_header(
            target_auth,
            &state.secrets_store,
            &ctx.surface.name,
            crate::proxy::handler::CallerAssertion::for_request(ctx.original_method.as_str(), &ctx.request_path),
        )
        .await
        {
            Ok(Some((header_name, header_value))) => {
                if is_modern {
                    let name = axum::http::HeaderName::from_bytes(header_name.as_bytes())
                        .map_err(|_| OutboundPipelineError::TargetAuthUnavailable)?;
                    let value = axum::http::HeaderValue::from_str(&header_value)
                        .map_err(|_| OutboundPipelineError::TargetAuthUnavailable)?;
                    stream_headers.insert(name, value);
                }
                headers_map.insert(header_name.to_uppercase(), header_value);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Failed to resolve target auth credentials for fabric forward"
                );
                if matches!(target_auth.fallback, crate::config::TargetAuthFallback::Reject) {
                    return Err(OutboundPipelineError::TargetAuthUnavailable);
                }
            }
        }
    }

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
        if let Some(prepared) = ctx.modern_delegation.as_ref() {
            for (name, value) in prepared
                .credential_headers()
                .map_err(|_| OutboundPipelineError::DelegationUnavailable)?
                .iter()
            {
                stream_headers.insert(name.clone(), value.clone());
            }
        }
        crate::mcp::modern_http::strip_protocol_session_headers(&mut stream_headers);
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
            match error {
                FabricForwardError::NoResponse(_) => OutboundPipelineError::UpstreamTimeout,
                FabricForwardError::RemoteLegacyOnly => OutboundPipelineError::McpValidation(
                    crate::mcp::request_validation::McpRequestValidationError::legacy_only(
                        match ctx
                            .mcp_classification
                            .as_ref()
                        {
                            Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) => {
                                request.id.clone()
                            }
                            _ => None,
                        },
                    ),
                ),
                _ => OutboundPipelineError::UpstreamConnectionFailed(
                    "Modern Fabric transport is unavailable".to_string(),
                ),
            }
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
                warn!(request_id = %ctx.request_id, target = %target_url, "SSRF blocked at forwarding layer: {}", e);
                return Err(OutboundPipelineError::TargetAuthUnavailable);
            }
            Err(e) => {
                warn!(request_id = %ctx.request_id, target = %target_url, "SSRF egress validation task failed: {}", e);
                return Err(OutboundPipelineError::TargetAuthUnavailable);
            }
        };

    debug!(
        request_id = %ctx.request_id,
        target = %target_url,
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

    // Forward safe, non-hop-by-hop request headers.
    for (key, value) in &ctx.original_headers {
        if should_forward_outbound_request_header(
            key.as_str(),
            ctx.virtual_channel
                .header_metadata_mapping_if_supported(),
        ) && let Ok(v) = value.to_str()
        {
            req_builder = req_builder.header(key.as_str(), v);
        }
    }

    // Apply target authentication if configured.
    if let Some(ref target_auth) = ctx
        .virtual_channel
        .target_auth
    {
        match crate::proxy::handler::inject_target_auth_header(
            target_auth,
            &state.secrets_store,
            &ctx.surface.name,
            crate::proxy::handler::CallerAssertion::for_request(ctx.original_method.as_str(), &ctx.request_path),
        )
        .await
        {
            Ok(Some((header_name, header_value))) => {
                req_builder = req_builder.header(header_name, header_value);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Failed to resolve target auth credentials"
                );
                if matches!(
                    ctx.virtual_channel
                        .target_auth
                        .as_ref()
                        .map(|ta| &ta.fallback),
                    Some(crate::config::TargetAuthFallback::Reject)
                ) {
                    return Err(OutboundPipelineError::TargetAuthUnavailable);
                }
            }
        }
    }

    if let Some(prepared) = ctx.modern_delegation.as_ref() {
        req_builder = req_builder.headers(
            prepared
                .credential_headers()
                .map_err(|_| OutboundPipelineError::DelegationUnavailable)?,
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
                    OutboundPipelineError::UpstreamConnectionFailed(error.to_string())
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
/// `/outgoing/<route>/<alias>` convention).
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

/// Check whether the upstream response is an agent card based on the request path and status.
fn is_agent_card_response(
    request_path: &str,
    status: reqwest::StatusCode,
) -> bool {
    status.is_success()
        && (request_path.ends_with("/.well-known/agent-card.json") || request_path.ends_with("/.well-known/agent.json"))
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
    let Some(pm) = state.policy_manager.as_ref() else {
        return body_bytes;
    };
    let config_id = ctx
        .surface
        .config_id()
        .unwrap_or("unknown");
    let alias = ctx
        .virtual_channel
        .alias
        .as_str();
    let Some(gating) = pm
        .compiled_mcp_tool_gating_for_transit(config_id, alias)
        .filter(|g| !g.is_empty())
    else {
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
            if outcome.completed {
                step_record_metrics(state, ctx);
            } else {
                warn!(request_id = %ctx.request_id, failed = outcome.failed, response_bytes = outcome.bytes, "Modern MCP response ended before completion");
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
    let body_bytes = if is_agent_card_response(&ctx.request_path, status) {
        let proxy_endpoint = crate::a2a::url_rewriter::build_transit_point_proxy_endpoint(
            &ctx.surface,
            &ctx.virtual_channel,
            &state.network_config,
        );
        match crate::a2a::url_rewriter::process_outbound_agent_card(&body_bytes, &proxy_endpoint, &ctx.surface.name) {
            Ok(rewritten) => {
                info!(
                    request_id = %ctx.request_id,
                    "Rewrote outbound agent card URLs to outbound virtual channel endpoint"
                );
                rewritten
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

    // Build the response, forwarding non-hop-by-hop headers.
    // Skip content-length: the body may have been rewritten (e.g. agent card URL
    // rewriting), so the upstream content-length is stale. Axum/hyper will set
    // the correct value from the actual body bytes.
    let mut builder = axum::response::Response::builder().status(status);

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

/// [13] Metrics & Logging — records latency and status.  Never fails.
fn step_record_metrics(
    state: &OutboundProxyState,
    ctx: &OutboundPipelineContext,
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
        let variant_alias = ctx
            .active_variant_alias
            .clone();
        let metrics = Arc::clone(metrics);

        tokio::spawn(async move {
            metrics
                .record_connection_with_transit_point(
                    channel_config_id,
                    source,
                    dest,
                    crate::metrics::ConnectionStatus::Success,
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
                    variant_alias,
                )
                .await;
        });
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn outbound_policy_audit_falls_back_to_package_name_when_unnamed() {
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
        // No operator name → the human-readable name falls back to the package.
        assert_eq!(decisions[0].policy_name, "surface.policy");
        assert!(
            decisions[0]
                .caller_did
                .is_none()
        );
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn test_virtual_channel() -> TransitPoint {
        serde_json::from_value(json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example.com/a2a",
            "gateway_url": "https://gw.internal:9000/outgoing/surfaces/order/partner-a",
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
                    { "alias": "partner-a", "target_endpoint": "https://partner.example.com/a2a", "gateway_url": "https://gw.internal:9000/outgoing/surfaces/order/partner-a" },
                    { "alias": "partner-b", "target_endpoint": "https://partner-b.example.com", "gateway_url": "https://gw.internal:9000/outgoing/surfaces/order/partner-b" }
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
            request_path: "/outbound/surfaces/order/partner-a/message/send".to_string(),
            resolved_identity: ProtectedAgentIdentity::Anonymous,
            protocol: None,
            mcp_metadata_context: crate::mcp::meta::McpMetadataContext::default(),
            mcp_classification: None,
            authenticated_identity: None,
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
            response_bytes: None,
            active_variant_alias: None,
            active_variant_id: None,
            variant_resolution_error: None,
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
            crate::mcp::request_validation::McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_MODERN_VERSION],
            ),
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
        use crate::mcp::continuations::{
            config::ContinuationRuntime,
            embedded::EmbeddedContinuations,
            protected::{ContinuationCipher, ContinuationKey, ContinuationRoute},
            service::ContinuationService,
        };
        use futures::TryStreamExt;
        use sha2::{Digest, Sha256};
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
        let runtime = Arc::new(ContinuationRuntime {
            config: serde_json::from_value(json!({"deployment": "deployment", "ttl_secs": 300, "active_key": "key",
                "keys": [{"id": "key", "secret_id": "key-secret", "not_before": now - 1, "seal_until": now + 3600, "open_until": now + 4500}],
                "storage": {"backend": "embedded", "capacity": 32}})).unwrap(),
            service: Arc::new(ContinuationService::new(ContinuationCipher::new("deployment".into(), "key".into(), vec![
                ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap(),
            ]).unwrap(), Arc::new(EmbeddedContinuations::new(32).unwrap()))),
        });
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
                crate::mcp::request_validation::McpVersionPolicy::new(
                    &[crate::mcp::MCP_MODERN_VERSION],
                    &[crate::mcp::MCP_MODERN_VERSION],
                ),
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
        // Tampered, expired, cross-user and incapable MRTR retries, on a continuation of their
        // own so the flow below keeps its state.
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
            let pending = |id: &str, request_state: Option<&str>| {
                let mut pending = message.clone();
                pending["id"] = json!(id);
                if let Some(request_state) = request_state {
                    pending["params"]["requestState"] = json!(request_state);
                }
                pending
            };
            let (_, issued) = prepare(&state, context_for(&pending("negatives", None), &surface)).await;
            let issued_state = issued["result"]["requestState"]
                .as_str()
                .expect("a continuation to replay")
                .to_string();

            // A tampered state does not open.
            let mut bytes = issued_state
                .clone()
                .into_bytes();
            let last = bytes.len() - 1;
            bytes[last] = if bytes[last] == b'A' {
                b'B'
            } else {
                b'A'
            };
            let tampered = String::from_utf8(bytes).unwrap();
            let (status, body) = prepare(&state, context_for(&pending("tampered", Some(&tampered)), &surface)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "tampered: {body}");
            assert_eq!(body["error"]["code"], crate::mcp::error_codes::INVALID_PARAMS, "tampered: {body}");

            // Another principal cannot resume it.
            let mut other_claims = caller_claims.clone();
            other_claims["sub"] = json!("other-user");
            let other = issuer
                .sign_jwt_with_gateway_key_typ(&other_claims, "at+jwt")
                .await
                .unwrap();
            let mut cross_user = context_for(&pending("cross-user", Some(&issued_state)), &surface);
            cross_user
                .original_headers
                .insert(
                    "authorization",
                    format!("Bearer {other}")
                        .parse()
                        .unwrap(),
                );
            let (status, body) = prepare(&state, cross_user).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "cross-user: {body}");
            assert_eq!(body["error"]["code"], -32001, "cross-user: {body}");

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
            let mut cross_route = context_for(&pending("cross-route", Some(&issued_state)), &surface_b);
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

            // A client that did not declare URL elicitation is not sent a consent request.
            let mut incapable = pending("incapable", None);
            incapable["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
            let (status, body) = prepare(&state, context_for(&incapable, &surface)).await;
            assert_eq!(
                body["error"]["code"],
                crate::mcp::error_codes::MISSING_REQUIRED_CLIENT_CAPABILITY,
                "incapable: {status} {body}"
            );

            // An expired state does not open.
            let mut short_state = state.clone();
            short_state.mcp_continuations = Some(Arc::new(ContinuationRuntime {
                config: serde_json::from_value(json!({"deployment": "deployment", "ttl_secs": 1, "active_key": "key",
                    "keys": [{"id": "key", "secret_id": "key-secret", "not_before": now - 1, "seal_until": now + 3600, "open_until": now + 4500}],
                    "storage": {"backend": "embedded", "capacity": 32}})).unwrap(),
                service: Arc::new(ContinuationService::new(ContinuationCipher::new("deployment".into(), "key".into(), vec![
                    ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap(),
                ]).unwrap(), Arc::new(EmbeddedContinuations::new(32).unwrap()))),
            }));
            let (_, short_issued) = prepare(&short_state, context_for(&pending("short", None), &surface)).await;
            tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
            let short_request_state = short_issued["result"]["requestState"]
                .as_str()
                .unwrap()
                .to_string();
            let (status, body) =
                prepare(&short_state, context_for(&pending("expired", Some(&short_request_state)), &surface)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "expired: {body}");
            assert_eq!(body["error"]["code"], crate::mcp::error_codes::INVALID_PARAMS, "expired: {body}");
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
            "id": "verified-token", "agent_did": "did:web:agent.example", "user_identity_hash": hex::encode(Sha256::digest(b"user")),
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
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
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
            b"subscription-transit-fixture-signing-key",
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
                .clone()
                .with_ttl(if invalid == "expired" {
                    0
                } else {
                    300
                })
                .issue(
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
                )
                .unwrap();
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
                .clone()
                .with_ttl(if termination == "transit-expiry" {
                    3
                } else {
                    300
                })
                .issue(&surface.surface_id, None, None, None, None, None, vec!["partner-a".into()])
                .unwrap();
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
                let context = OutboundPipelineContext::new(address, context_request, &request_state).unwrap();
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
                    crate::mcp::request_validation::McpVersionPolicy::new(
                        &[crate::mcp::MCP_MODERN_VERSION],
                        &[crate::mcp::MCP_MODERN_VERSION],
                    ),
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
    async fn modern_transit_variant_failures_never_dispatch_the_base_target() {
        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({
                "jsonrpc": "2.0", "id": "variant", "result": {
                    "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"
                }
            })
            .to_string(),
        )
        .await;
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        for case in ["empty-catalog", "unknown", "disabled", "missing-default", "disabled-default"] {
            let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
                "surface_id": "variant-surface", "name": "Variant surface",
                "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
                "target": {"endpoint": "http://127.0.0.1:1"},
                "transit": {"points": [{"alias": "partner-a", "protocol": "mcp",
                    "require_transit_token": false, "target_endpoint": format!("http://{}", target.addr)}]},
                "variants": [{"id": "candidate", "alias": "candidate", "name": "Candidate", "enabled": false}]
            }))
            .unwrap();
            if case == "empty-catalog" {
                surface.variants.clear();
            }
            if case == "missing-default" {
                surface.default_variant_id = Some("absent".into());
            }
            if case == "disabled-default" {
                surface.default_variant_id = Some("candidate".into());
            }
            let path = match case {
                "disabled" => "/outbound/mcp$candidate/partner-a",
                "missing-default" | "disabled-default" => "/outbound/mcp/partner-a",
                _ => "/outbound/mcp$unknown/partner-a",
            };
            let state = test_outbound_state();
            state
                .channel_state
                .write()
                .unwrap()
                .surface = Arc::new(surface);
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("mcp-method", "tools/list")
                .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(axum::body::Body::from(
                    json!({"jsonrpc": "2.0", "id": "variant", "method": "tools/list", "params": {"_meta": {
                        "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }}})
                    .to_string(),
                ))
                .unwrap();
            let response = Box::pin(outbound_proxy_handler_with_mcp_versions(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                state,
                request,
                versions,
            ))
            .await
            .unwrap_or_else(|error| error.into_response());
            assert_eq!(
                response.status(),
                if matches!(case, "empty-catalog" | "unknown") {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                },
                "{case}"
            );
            let error: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 16384)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(error["id"], "variant");
            assert!(error.get("result").is_none());
            assert_eq!(
                target
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{case}"
            );
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

    // ── step_source_auth (MVP: no-op) ──────────────────────────────────────

    #[tokio::test]
    async fn test_step_source_auth_noop_when_none() {
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.outbound_shared
            .source_auth = None;
        let result = step_source_auth(&state, &mut ctx).await;
        assert!(result.is_ok());
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
        use crate::mcp::admission_cases::{ALLOWED_ORIGIN, admission_cases, assert_rejected};

        let state = test_outbound_state();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        for case in admission_cases() {
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
    async fn test_step_extract_protocol_context_strips_session_and_resumption_state_from_modern_requests() {
        let state = test_outbound_state();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
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
        for (requested, forwarded) in [("2025-11-25", "2024-11-05"), ("2024-11-05", "2024-11-05")] {
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
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        // A `fabric://` Transit Point resolves to the Fabric send policy, which
        // admits the same revisions as an HTTP(S) Target; each row pins that
        // the two Targets still agree.
        for (target, version, admitted) in [
            ("fabric://gateway/channel", crate::mcp::MCP_MODERN_VERSION, true),
            ("https://agent.example/mcp", crate::mcp::MCP_MODERN_VERSION, true),
            ("fabric://gateway/channel", "2025-11-25", false),
            ("https://agent.example/mcp", "2025-11-25", false),
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
                assert_eq!(
                    error.data.unwrap()["supported"],
                    json!([crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION])
                );
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
        use crate::mcp::{MCP_LEGACY_VERSION, MCP_MODERN_VERSION};

        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[MCP_MODERN_VERSION],
            &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION],
        );
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
            ("learned-discovery", json!([MCP_LEGACY_VERSION])),
            ("unlearned-discovery", json!([MCP_LEGACY_VERSION, MCP_MODERN_VERSION])),
        ] {
            let Err(OutboundPipelineError::McpValidation(error)) = admit(alias, "2025-11-25").await else {
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

    // ── step_record_metrics ────────────────────────────────────────────────

    #[test]
    fn test_step_record_metrics_noop_when_no_metrics() {
        let mut state = test_outbound_state();
        state.metrics_store = None;
        let ctx = test_pipeline_context();
        step_record_metrics(&state, &ctx);
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
        use crate::proxy::transit_token::{TransitTokenClaims, TransitTokenIssuer};

        let signing_secret = b"modern-transit-fixture-signing-key";
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        for case in ["valid", "other-surface", "expired", "future-issued", "other-point", "duplicate", "missing-issuer"]
        {
            let mut state = test_outbound_state();
            if case != "missing-issuer" {
                state.transit_token_issuer = Some(Arc::new(TransitTokenIssuer::new(signing_secret, "gateway".into())));
            }
            let mut ctx = modern_pipeline_context("tools/list");
            Arc::make_mut(&mut ctx.surface).surface_id = "current-surface".into();
            ctx.virtual_channel
                .require_transit_token = true;
            let claims: TransitTokenClaims = serde_json::from_value(json!({
                "iss": "gateway", "surface_id": if case == "other-surface" { "another-surface" } else { "current-surface" },
                "iat": if case == "future-issued" { now + 120 } else { now - 1 },
                "exp": if case == "expired" { now - 1 } else { now + 300 },
                "jti": uuid::Uuid::new_v4().to_string(),
                "allowed_transit_points": [if case == "other-point" { "partner-b" } else { "partner-a" }]
            })).unwrap();
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(signing_secret),
            )
            .unwrap();
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

    #[tokio::test]
    async fn test_transit_token_validation_skipped_when_no_issuer() {
        let state = test_outbound_state(); // transit_token_issuer = None
        let mut ctx = test_pipeline_context();
        let result = step_validate_transit_token(&state, &mut ctx).await;
        assert!(result.is_ok());
        assert!(
            ctx.transit_token_claims
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_transit_token_validation_rejects_missing_header() {
        let mut state = test_outbound_state();
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            b"test-secret-key-32-bytes-long!!",
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
            b"test-secret-key-32-bytes-long!!",
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
            b"test-secret-key-32-bytes-long!!",
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

    #[tokio::test]
    async fn test_transit_token_validation_rejects_wrong_transit_point() {
        let issuer = crate::proxy::transit_token::TransitTokenIssuer::new(
            b"test-secret-key-32-bytes-long!!",
            "gw-test".to_string(),
        );

        // Issue a token that only allows "other-service" — not "partner-a"
        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec!["other-service".to_string()])
            .unwrap();

        let mut state = test_outbound_state();
        state.transit_token_issuer = Some(Arc::new(issuer));

        let mut ctx = test_pipeline_context();
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

    fn attach_target_trust_check_list(
        ctx: &mut OutboundPipelineContext,
        elements: Vec<crate::trust_registry_verification::TrustCheckElement>,
    ) {
        let mut surface = (*ctx.surface).clone();
        surface
            .target
            .trust_check_list = elements;
        ctx.surface = Arc::new(surface);
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
        attach_target_trust_check_list(&mut ctx, vec![make_test_element("tc-1")]);

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
        attach_target_trust_check_list(&mut ctx, vec![make_test_element("tc-1")]);

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
        attach_target_trust_check_list(&mut ctx, vec![make_test_element("tc-1"), make_test_element("tc-2")]);
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
        attach_target_trust_check_list(&mut ctx, vec![make_test_element("tc-1")]);

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
        attach_target_trust_check_list(&mut ctx, vec![make_test_element("tc-1"), make_test_element("tc-2")]);

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
        use std::sync::{Arc as StdArc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::{Context as LayerContext, Layer};
        use tracing_subscriber::prelude::*;

        #[derive(Default, Clone)]
        struct CapturedEvent {
            level: String,
            fields: Vec<(String, String)>,
        }
        struct FieldVisitor(Vec<(String, String)>);
        impl Visit for FieldVisitor {
            fn record_debug(
                &mut self,
                f: &Field,
                v: &dyn std::fmt::Debug,
            ) {
                self.0
                    .push((f.name().to_string(), format!("{:?}", v)));
            }
            fn record_str(
                &mut self,
                f: &Field,
                v: &str,
            ) {
                self.0
                    .push((f.name().to_string(), v.to_string()));
            }
            fn record_u64(
                &mut self,
                f: &Field,
                v: u64,
            ) {
                self.0
                    .push((f.name().to_string(), v.to_string()));
            }
            fn record_bool(
                &mut self,
                f: &Field,
                v: bool,
            ) {
                self.0
                    .push((f.name().to_string(), v.to_string()));
            }
        }
        struct CapturingLayer(StdArc<Mutex<Vec<CapturedEvent>>>);
        impl<S: tracing::Subscriber> Layer<S> for CapturingLayer {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: LayerContext<'_, S>,
            ) {
                let mut v = FieldVisitor(Vec::new());
                event.record(&mut v);
                self.0
                    .lock()
                    .unwrap()
                    .push(CapturedEvent {
                        level: event
                            .metadata()
                            .level()
                            .to_string(),
                        fields: v.0,
                    });
            }
        }

        let events = StdArc::new(Mutex::new(Vec::<CapturedEvent>::new()));
        let subscriber = tracing_subscriber::registry().with(CapturingLayer(events.clone()));
        let _default_guard = tracing::subscriber::set_default(subscriber);

        crate::proxy::agent_card_cache::invalidate_all();
        let state = test_outbound_state();
        let mut ctx = test_pipeline_context();
        ctx.virtual_channel
            .target_endpoint = "http://127.0.0.1:1".to_string();
        attach_target_trust_check_list(&mut ctx, vec![make_test_element("tc-1"), make_test_element("tc-2")]);
        ctx.target_agent_card_unavailable = true;

        step_trust_check(&state, &mut ctx)
            .await
            .expect("synthesis ok");

        drop(_default_guard);
        let events = events.lock().unwrap();
        let agent_card_unavailable_events: Vec<&CapturedEvent> = events
            .iter()
            .filter(|e| {
                e.fields
                    .iter()
                    .any(|(k, v)| k == "error_code" && v == "AGENT_CARD_UNAVAILABLE")
            })
            .collect();
        assert_eq!(agent_card_unavailable_events.len(), 2, "one audit event per synthesized element");
        for ev in agent_card_unavailable_events {
            assert_eq!(ev.level, "WARN", "failures log at WARN so OTEL exporter captures them");
            let latency = ev
                .fields
                .iter()
                .find(|(k, _)| k == "latency_ms")
                .map(|(_, v)| v.as_str());
            assert_eq!(latency, Some("0"), "no network call fired");
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
        attach_target_trust_check_list(
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
        attach_target_trust_check_list(
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
        attach_target_trust_check_list(&mut ctx, vec![make_test_element("tc-1")]);
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
                    { "alias": "partner-a", "target_endpoint": "https://partner.example.com/mcp", "gateway_url": "https://gw.internal:9000/outgoing/surfaces/order/partner-a" }
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
        use crate::mcp::request_validation::{LegacySessionEvidence, McpVersionPolicy, validate_mcp_post};
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
                McpVersionPolicy::new(&[crate::mcp::MCP_MODERN_VERSION], &[crate::mcp::MCP_MODERN_VERSION]),
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
}
