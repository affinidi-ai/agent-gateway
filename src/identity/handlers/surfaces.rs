//! CRUD API handlers for Agent Surfaces

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{debug, error, info, warn};

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::config::agent_surface::AgentSurface;
use crate::identity::state::IdentityApiState;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

/// Validate that all variant aliases within a surface are unique.
fn validate_variant_aliases(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    surface
        .validate_variants()
        .map_err(|e| SurfaceApiError::BadRequest(e.to_string()))
}

/// When `PayloadExtraction` identity extraction is configured (either via
/// the dedicated `identity_slots.inbound` slot or the legacy
/// `target.identity_injection` shape), the surface MUST declare at least
/// one identity field. Without fields the inbound payload is never
/// matched against anything meaningful: any request — including ones
/// missing `_meta.<meta_field>` entirely — passes through with
/// `identity_result = None`, which silently disables VP minting and the
/// `VpInjected` audit row downstream. Reject at save time so this
/// misconfiguration cannot reach disk.
fn validate_identity_extraction(
    surface: &AgentSurface,
    label: &str,
) -> Result<(), SurfaceApiError> {
    use crate::source_auth::ManagedIdentityConfig;

    let prefix = if label.is_empty() {
        String::new()
    } else {
        format!("{}: ", label)
    };

    let cfg = surface
        .inbound_identity()
        .cloned()
        .or_else(|| {
            crate::config::agent_surface_compat::identity_injection_to_managed_identity(
                &surface
                    .target
                    .identity_injection,
            )
        });

    if let Some(ManagedIdentityConfig::PayloadExtraction(pe)) = cfg {
        if let Some(extension_uri) = pe.extension_uri.as_deref() {
            let trimmed = extension_uri.trim();
            if trimmed.is_empty() {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{}identity extraction extension_uri must not be blank",
                    prefix
                )));
            }
            let parsed = url::Url::parse(trimmed).map_err(|e| {
                SurfaceApiError::BadRequest(format!(
                    "{}identity extraction extension_uri must be an absolute http(s) URI: {}",
                    prefix, e
                ))
            })?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{}identity extraction extension_uri must be an absolute http(s) URI: {}",
                    prefix, extension_uri
                )));
            }
        }
        if pe.fields.is_empty() {
            return Err(SurfaceApiError::BadRequest(format!(
                "{}identity extraction is configured (meta_field='{}') but no identity fields are declared — \
                 add at least one field (e.g. 'agentIdentity.llmInfo.provider') so the inbound payload \
                 produces an extractable agent identity",
                prefix, pe.meta_field
            )));
        }
    }
    Ok(())
}

/// Structural shape check for the always-required surface fields.
///
/// `label` is prefixed on every error so callers can distinguish a base
/// failure from a per-variant failure (e.g. `"Variant 'alias1'"`).
/// Intentionally cheap — defers any field-by-field semantic validation
/// (payment policies, transit aliases) to the dedicated helpers.
/// Refuse a surface whose own route is one of the always-public paths.
///
/// `proxy::paths::is_public_path` runs on the full request path and switches off
/// source authentication and the policy layers for it. A surface whose route
/// itself matches that predicate is therefore permanently public on its root,
/// with no warning anywhere in the UI. Reject it at write time rather than
/// leave an operator to discover it from traffic.
fn reject_public_predicate_route(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    let route = surface
        .access_point
        .route
        .as_str();
    if !route.is_empty() && crate::proxy::paths::is_public_path(route) {
        return Err(SurfaceApiError::BadRequest(format!(
            "route '{route}' matches an always-public discovery path, so the surface would skip caller \
             authentication and every policy layer on that path. Choose a different route."
        )));
    }
    Ok(())
}

fn validate_required_fields(
    surface: &AgentSurface,
    label: &str,
) -> Result<(), SurfaceApiError> {
    let prefix = if label.is_empty() {
        String::new()
    } else {
        format!("{}: ", label)
    };
    if surface.name.is_empty() {
        return Err(SurfaceApiError::BadRequest(format!("{}name is required", prefix)));
    }
    if surface
        .access_point
        .listen_address
        .is_empty()
    {
        return Err(SurfaceApiError::BadRequest(format!("{}access_point.listen_address is required", prefix)));
    }
    if surface
        .access_point
        .route
        .is_empty()
    {
        return Err(SurfaceApiError::BadRequest(format!("{}access_point.route is required", prefix)));
    }
    if !surface
        .access_point
        .route
        .starts_with('/')
    {
        return Err(SurfaceApiError::BadRequest(format!("{}access_point.route must start with '/'", prefix)));
    }
    if surface
        .target
        .endpoint
        .is_empty()
    {
        return Err(SurfaceApiError::BadRequest(format!("{}target.endpoint is required", prefix)));
    }
    Ok(())
}

/// Resolve every variant (and the implicit base) and re-run the basic
/// shape checks on the resolved view. Catches the case where a variant
/// override blanks out a required field — for example
/// `overrides.target.endpoint = ""` — that the bare base check can't
/// see because it only inspects the unresolved surface.
///
/// Surface-level concerns (variant alias uniqueness, transit aliases,
/// payment policies) are validated separately by their own helpers;
/// this function only re-checks the always-required scalar fields.
fn validate_resolved_variants(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    if surface.variants.is_empty() {
        return Ok(());
    }
    // Iterate the catalog directly (rather than `resolve_variant(None)`)
    // so a missing/misconfigured default doesn't mask a variant-level
    // shape problem — the catalog is the source of truth here.
    for variant in &surface.variants {
        let resolved = match surface.resolve_variant(Some(&variant.alias)) {
            Ok(r) => r,
            Err(crate::config::agent_surface_variants::VariantResolveError::DisabledVariant(_)) => {
                // Disabled variants are persisted as-is and never
                // resolved at request time — skip them so the user
                // can keep a broken-but-disabled variant on disk
                // while they fix it.
                continue;
            }
            Err(e) => {
                return Err(SurfaceApiError::BadRequest(format!("Variant '{}' is unresolvable: {}", variant.alias, e)));
            }
        };
        let label = format!("Variant '{}'", variant.alias);
        validate_required_fields(&resolved, &label)?;
        validate_identity_extraction(&resolved, &label)?;

        // Block cloud-metadata URLs on variant target endpoints (SSRF protection)
        if (resolved
            .target
            .endpoint
            .starts_with("http://")
            || resolved
                .target
                .endpoint
                .starts_with("https://"))
            && let Err(e) = crate::url_validation::reject_cloud_metadata_url(&resolved.target.endpoint)
        {
            return Err(SurfaceApiError::BadRequest(format!("{}: {}", label, e)));
        }
    }
    Ok(())
}

/// Validate Trust Check list invariants (caller + target legs, plus
/// every variant's resolved view). Delegates to `AgentSurface::validate`
/// and maps the structured [`crate::config::agent_surface::TrustCheckValidationError`]
/// into a `400 BadRequest`.
fn validate_trust_checks(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    surface
        .validate()
        .map_err(|e| SurfaceApiError::BadRequest(e.to_string()))
}

/// Validate Transit Point-scoped Workload Binding on the base surface and
/// every resolved variant, mapping the structured
/// [`crate::config::agent_surface::WorkloadBindingSurfaceError`] into a
/// `400 BadRequest`.
fn validate_workload_binding_config(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    surface
        .validate_workload_binding()
        .map_err(|e| SurfaceApiError::BadRequest(e.to_string()))
}

/// Validate the surface's `source_auth` configuration on the HTTP save path.
///
/// Shares the exact same rules the boot-time [`crate::config::proxy::GatewayConfig::validate`]
/// runs: mTLS trust-store references, DID-Auth `allowed_dids` well-formedness,
/// challenge/session TTL bounds, and JWS algorithm allow-list membership.
/// Without this hook a dashboard save could persist values that would then
/// be rejected on the next process restart (`challenge_ttl_seconds: 0`,
/// unsupported `allowed_algorithms`, etc.).
fn validate_source_auth(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    crate::config::validate_source_auth_config(surface).map_err(|e| SurfaceApiError::BadRequest(e.to_string()))
}

/// Validate every transit point: alias must match the URL-safe pattern,
/// be non-empty, and be unique within the surface. Also assigns a fresh
/// UUID `id` to any TP that was sent without one so older payloads keep
/// working without forcing the dashboard to mint IDs client-side.
fn validate_transit_points(surface: &mut AgentSurface) -> Result<(), SurfaceApiError> {
    let Some(transit) = surface.transit.as_mut() else {
        return Ok(());
    };
    let mut seen = std::collections::HashSet::with_capacity(transit.points.len());
    for (idx, tp) in transit
        .points
        .iter_mut()
        .enumerate()
    {
        if tp.id.is_empty() {
            tp.id = uuid::Uuid::new_v4().to_string();
        }
        if let Err(msg) = crate::config::agent_surface::TransitPoint::validate_alias(&tp.alias) {
            return Err(SurfaceApiError::BadRequest(format!("transit.points[{}]: {}", idx, msg)));
        }
        if !seen.insert(tp.alias.clone()) {
            return Err(SurfaceApiError::BadRequest(format!(
                "transit.points[{}]: duplicate alias '{}'. Each transit point alias must be unique within the surface.",
                idx, tp.alias
            )));
        }
    }
    Ok(())
}

/// Identity of the listener a surface route is served on.
///
/// Runtime routing buckets by **resolved listener port** — outbound via
/// [`crate::config::group_outbound_vcs_by_port`], inbound via the
/// orchestrator's `channels_by_port` grouping — so two different address
/// strings (e.g. `http://localhost:9111` and the listener's public external
/// URL) can name the same listener. Collision checks must therefore key by
/// the resolved port, not the raw address string — otherwise address aliases
/// bypass validation and either panic the outbound router rebuild
/// (`Router::merge`) or silently shadow an inbound surface.
///
/// Addresses that resolve to no listener keep their raw string as the key:
/// routing skips them (they serve no route), but string equality still
/// catches literal duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ListenerKey {
    Port(u16),
    Unresolved(String),
}

impl ListenerKey {
    /// Human-readable label for error messages. `direction` is "inbound" or
    /// "outbound".
    fn label(
        &self,
        direction: &str,
    ) -> String {
        match self {
            Self::Port(port) => format!("{} listener port {}", direction, port),
            Self::Unresolved(addr) if addr.trim().is_empty() => format!("the default {} listener", direction),
            Self::Unresolved(addr) => format!("{} listener '{}'", direction, addr),
        }
    }
}

/// Collect every `(listener, listen_path)` claimed by a surface's transit
/// points, keyed by resolved outbound listener. Mirrors the precedence used
/// by [`crate::config::group_outbound_vcs_by_port`]:
/// `resolve(tp.listen_address ?? channel_addr) ?? resolve(channel_addr)`.
/// Only transit points that set a custom `listen_path` are returned, since
/// those are the ones registered as exact Axum routes on the outbound
/// listener.
fn outbound_listen_path_claims(
    surface: &AgentSurface,
    resolve_port: &impl Fn(&str) -> Option<u16>,
) -> Vec<(ListenerKey, String)> {
    let Some(transit) = surface.transit.as_ref() else {
        return Vec::new();
    };
    let channel_addr = transit
        .outbound_listen_address
        .as_deref();
    let channel_port = channel_addr.and_then(resolve_port);
    transit
        .points
        .iter()
        .filter_map(|tp| {
            let path = tp.listen_path.as_ref()?;
            let effective_addr = tp
                .listen_address
                .as_deref()
                .or(channel_addr);
            let key = match effective_addr
                .and_then(resolve_port)
                .or(channel_port)
            {
                Some(port) => ListenerKey::Port(port),
                None => ListenerKey::Unresolved(
                    effective_addr
                        .unwrap_or_default()
                        .to_string(),
                ),
            };
            Some((key, path.clone()))
        })
        .collect()
}

/// Reject a surface whose outbound transit-point `listen_path` overrides
/// would produce overlapping Axum routes.
///
/// Each custom `listen_path` is registered as an exact route on the shared
/// outbound port listener (`run_outbound_port_server`). Two transit points
/// that resolve to the same effective listen address **and** the same
/// `listen_path` register the same route; `Router::merge` then panics when
/// the listener is (re)built after a save — taking the whole gateway down.
///
/// This guard runs at save time, before the surface is persisted and the
/// listener rebuilt, so the collision is reported as a `400 Bad Request`
/// instead of crashing the process. It covers both duplicates *within* the
/// surface under validation and clashes with any other persisted surface
/// (the surface being updated is excluded by `surface_id`).
async fn validate_listen_path_collisions(
    surface: &AgentSurface,
    store: &std::sync::Arc<crate::surfaces::FileSystemAgentSurfaceStore>,
    network_config: &crate::config::NetworkConfig,
) -> Result<(), SurfaceApiError> {
    let resolve_port = |addr: &str| network_config.map_url_to_port_for_type(addr, Some("outbound"));
    if outbound_listen_path_claims(surface, &resolve_port).is_empty() {
        return Ok(());
    }

    let existing = store
        .list_all()
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to list surfaces for route validation: {}", e)))?;

    check_listen_path_collisions(surface, &existing, resolve_port)
}

/// Pure collision check: validate `surface`'s outbound `listen_path` routes
/// against its own transit points and every other surface in `others`. The
/// surface being saved is excluded from `others` by `surface_id`, and
/// disabled surfaces never reserve a route. Claims are keyed by **resolved
/// listener port** (via `resolve_port`), so different address strings that
/// alias the same outbound listener still collide. Returns the first
/// collision as a `BadRequest`.
fn check_listen_path_collisions(
    surface: &AgentSurface,
    others: &[AgentSurface],
    resolve_port: impl Fn(&str) -> Option<u16>,
) -> Result<(), SurfaceApiError> {
    // A disabled surface reserves no routes (routing skips it), so saving
    // one can never introduce a collision. Skipping here keeps disabling a
    // conflicting surface possible — the natural way out of a duplicate.
    if surface.status == crate::config::agent_surface::SurfaceStatus::Disabled {
        return Ok(());
    }

    // Routes claimed by every *other* persisted, non-disabled surface,
    // keyed by `(resolved listener, listen_path)` → owning surface name.
    let mut claimed: std::collections::HashMap<(ListenerKey, String), String> = std::collections::HashMap::new();
    for other in others {
        if other.surface_id == surface.surface_id {
            continue;
        }
        if other.status == crate::config::agent_surface::SurfaceStatus::Disabled {
            continue;
        }
        for key in outbound_listen_path_claims(other, &resolve_port) {
            claimed.insert(key, other.name.clone());
        }
    }

    // Walk the surface's own claims: first catch in-surface duplicates,
    // then clashes against other surfaces.
    let mut seen: std::collections::HashSet<(ListenerKey, String)> = std::collections::HashSet::new();
    for (listener, path) in outbound_listen_path_claims(surface, &resolve_port) {
        let key = (listener.clone(), path.clone());
        if !seen.insert(key.clone()) {
            return Err(SurfaceApiError::BadRequest(format!(
                "listen_path '{}' is used by more than one transit point on {} within this surface — \
                 each custom listener path must be unique",
                path,
                listener.label("outbound")
            )));
        }
        if let Some(other_name) = claimed.get(&key) {
            return Err(SurfaceApiError::BadRequest(format!(
                "listen_path '{}' on {} is already in use by surface '{}' — choose a different listener path",
                path,
                listener.label("outbound"),
                other_name
            )));
        }
    }

    Ok(())
}

/// Returns the `(listener, route)` claim of a surface's access point, keyed
/// by resolved listener port. Mirrors the orchestrator's `channels_by_port`
/// grouping, which resolves `access_point.listen_address` with the
/// **unrestricted** `map_url_to_port` — so validation must use the same
/// resolver to collide exactly where runtime routing would.
fn access_point_route_claim(
    surface: &AgentSurface,
    resolve_port: &impl Fn(&str) -> Option<u16>,
) -> (ListenerKey, String) {
    let addr = surface
        .access_point
        .listen_address
        .as_str();
    let key = match resolve_port(addr) {
        Some(port) => ListenerKey::Port(port),
        None => ListenerKey::Unresolved(addr.to_string()),
    };
    (
        key,
        surface
            .access_point
            .route
            .clone(),
    )
}

/// Reject a surface whose `access_point.route` would shadow an existing
/// surface on the same listener.
///
/// The inbound handler (`multi_channel_proxy_handler`) picks the **first**
/// surface whose route prefix matches the incoming request path. When two
/// surfaces share the same `(listen_address, route)` one of them silently
/// never receives traffic. This guard turns that silent data-loss into a
/// clear `400 Bad Request` at save time.
async fn validate_access_point_route_collisions(
    surface: &AgentSurface,
    store: &std::sync::Arc<crate::surfaces::FileSystemAgentSurfaceStore>,
    network_config: &crate::config::NetworkConfig,
) -> Result<(), SurfaceApiError> {
    let existing = store
        .list_all()
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to list surfaces for route validation: {}", e)))?;

    check_access_point_route_collisions(surface, &existing, |addr| network_config.map_url_to_port(addr))
}

/// Pure collision check: validate `surface`'s `access_point.route` against
/// every other surface in `others`. The surface being saved is excluded by
/// `surface_id`, and disabled surfaces never reserve a route. Claims are
/// keyed by **resolved listener port** (via `resolve_port`), so different
/// address strings that alias the same listener still collide.
fn check_access_point_route_collisions(
    surface: &AgentSurface,
    others: &[AgentSurface],
    resolve_port: impl Fn(&str) -> Option<u16>,
) -> Result<(), SurfaceApiError> {
    // A disabled surface reserves no routes, so saving one can never
    // introduce a collision (mirrors check_listen_path_collisions).
    if surface.status == crate::config::agent_surface::SurfaceStatus::Disabled {
        return Ok(());
    }

    if surface
        .access_point
        .route
        .is_empty()
    {
        return Ok(());
    }

    let (listener, route) = access_point_route_claim(surface, &resolve_port);

    for other in others {
        if other.surface_id == surface.surface_id {
            continue;
        }
        if other.status == crate::config::agent_surface::SurfaceStatus::Disabled {
            continue;
        }
        let (other_listener, other_route) = access_point_route_claim(other, &resolve_port);
        if listener == other_listener && route == other_route {
            return Err(SurfaceApiError::BadRequest(format!(
                "access_point.route '{}' on {} is already in use by surface '{}' — \
                 choose a different route",
                route,
                listener.label("inbound"),
                other.name
            )));
        }
    }

    Ok(())
}

/// Application error type for surface handlers
#[derive(Debug)]
pub enum SurfaceApiError {
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    UnsupportedMediaType(String),
    InternalError(String),
}

impl IntoResponse for SurfaceApiError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            SurfaceApiError::BadRequest(msg) => {
                warn!("Surface API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            SurfaceApiError::Forbidden(msg) => {
                warn!("Surface API Forbidden: {}", msg);
                (StatusCode::FORBIDDEN, "Forbidden", Some(msg.clone()))
            }
            SurfaceApiError::NotFound(msg) => {
                warn!("Surface API Not Found: {}", msg);
                (StatusCode::NOT_FOUND, "Not Found", Some(msg.clone()))
            }
            SurfaceApiError::UnsupportedMediaType(msg) => {
                warn!("Surface API Unsupported Media Type: {}", msg);
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type", Some(msg.clone()))
            }
            SurfaceApiError::InternalError(msg) => {
                error!("Surface API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
            }
        };

        let body = Json(SurfaceErrorResponse {
            error: message.to_string(),
            details,
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct SurfaceErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

// ─── Handlers ───────────────────────────────────────────────────────────────

/// List all agent surfaces
pub async fn list_surfaces(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<AgentSurface>>, SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;

    let mut surfaces = store
        .list_all()
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to list surfaces: {}", e)))?;

    let context = tenant_context(&context);
    let scope = resource_scope(&scope);
    surfaces.retain(|surface| {
        can_access(surface.tenant_id.as_deref(), context)
            && scope_allows_resource(scope, context, ResourceKind::Surfaces, &surface.surface_id)
    });

    debug!("Listed {} agent surface(s)", surfaces.len());
    Ok(Json(surfaces))
}

/// Get a single agent surface by ID
pub async fn get_surface(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AgentSurface>, SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;

    let surface = store
        .get(&surface_id)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to get surface: {}", e)))?;

    match surface {
        Some(surface)
            if can_access(surface.tenant_id.as_deref(), tenant_context(&context))
                && scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::Surfaces,
                    &surface.surface_id,
                ) =>
        {
            Ok(Json(surface))
        }
        Some(_) => Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id))),
        None => Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id))),
    }
}

/// Validate (and resolve) every x402 payment policy attached to the
/// surface: the base `target.payment_policy` plus every variant
/// override. Reuses the channel-handler validator so behaviour stays
/// identical across both APIs — the global x402 recipient list is the
/// only source of wallet addresses, and any client-supplied `pay_to`
/// is overwritten in place.
async fn validate_surface_payment_policies(surface: &mut AgentSurface) -> Result<(), SurfaceApiError> {
    let recipients: Vec<crate::identity::handlers::config::X402RecipientAddress> =
        match crate::x402::config_cache::get_x402_metadata().await {
            Some(metadata) => metadata
                .recipient_addresses
                .clone(),
            None => Vec::new(),
        };

    if let Some(crate::config::agent_surface::PaymentPolicy::X402(ref mut cfg)) = surface.target.payment_policy {
        crate::identity::handlers::policy_validation::validate_payment_policy(
            cfg,
            &recipients,
            "Surface payment policy",
        )
        .map_err(SurfaceApiError::BadRequest)?;
    }

    for variant in surface.variants.iter_mut() {
        let Some(target_overrides) = variant
            .overrides
            .target
            .as_mut()
        else {
            continue;
        };
        if let Some(crate::config::agent_surface::PaymentPolicy::X402(ref mut cfg)) = target_overrides.payment_policy {
            let label = format!("Variant '{}' payment policy", variant.alias);
            crate::identity::handlers::policy_validation::validate_payment_policy(cfg, &recipients, &label)
                .map_err(SurfaceApiError::BadRequest)?;
        }
    }

    Ok(())
}

/// Validate MPP crypto-verification posture (base + every variant): reject a
/// `passthrough` (unverified) mode or a 0-confirmation on-chain mode fronting
/// a mainnet crypto payment method before the surface reaches disk.
fn validate_surface_mpp_posture(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    if let Some(crate::config::agent_surface::PaymentPolicy::Mpp(cfg)) = surface
        .target
        .payment_policy
        .as_ref()
    {
        crate::mpp::posture::validate_mpp_posture(cfg, "Surface MPP config").map_err(SurfaceApiError::BadRequest)?;
    }

    for variant in &surface.variants {
        let Some(crate::config::agent_surface::PaymentPolicy::Mpp(cfg)) = variant
            .overrides
            .target
            .as_ref()
            .and_then(|t| t.payment_policy.as_ref())
        else {
            continue;
        };
        let label = format!("Variant '{}' MPP config", variant.alias);
        crate::mpp::posture::validate_mpp_posture(cfg, &label).map_err(SurfaceApiError::BadRequest)?;
    }

    Ok(())
}

/// Reject an A2A surface that delegates x402 to a remote MPP rail while using
/// `jwt_bearer` source auth on the `Authorization` header: MPP's A2A credential
/// (`Authorization: Payment <cred>`) collides with the Bearer scheme the
/// source-auth gate expects — the credential is rejected as a malformed Bearer
/// token before delegation ever runs, and even a valid Bearer token would have
/// the `Authorization` header stripped before the request is forwarded, so
/// the remote payment gateway never receives the credential either way.
fn validate_delegation_source_auth(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    if surface.access_point.protocol != crate::config::agent_surface::SurfaceProtocol::A2a {
        return Ok(());
    }
    let Some(crate::config::agent_surface::PaymentPolicy::X402(cfg)) = surface
        .target
        .payment_policy
        .as_ref()
    else {
        return Ok(());
    };
    let is_delegated_mpp = cfg.provider == crate::config::types::X402Provider::AgentPay
        && cfg.delegated_rail == crate::config::types::DelegatedPaymentRail::Mpp;
    if !is_delegated_mpp {
        return Ok(());
    }
    if let Some(crate::source_auth::SourceAuthConfig::JwtBearer(_)) = surface.source_auth()
        && surface
            .source_auth()
            .and_then(|sa| sa.credential_header_name())
            .is_some_and(|h| h.eq_ignore_ascii_case("authorization"))
    {
        return Err(SurfaceApiError::BadRequest(format!(
            "Surface '{}': an A2A surface delegating payment to a remote MPP rail cannot use jwt_bearer source \
             auth on the 'Authorization' header — MPP's A2A credential ('Authorization: Payment <cred>') collides \
             with the Bearer scheme, so payment can never succeed. Use api_key, mtls, or did_auth source auth instead.",
            surface.name
        )));
    }
    Ok(())
}

/// Validate MCP Tool Gating regex patterns on the surface (base + variants).
/// Regex compilation is the only failure mode checked here; condition policy
/// references are resolved (and fail closed) at surface-compile time.
fn validate_surface_mcp_tool_gating(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    let mut errors = Vec::new();
    if let Some(cfg) = surface
        .target
        .mcp_tool_gating
        .as_ref()
    {
        errors.extend(cfg.validate(&surface.name));
    }
    for variant in &surface.variants {
        if let Some(cfg) = variant
            .overrides
            .target
            .as_ref()
            .and_then(|t| t.mcp_tool_gating.as_ref())
        {
            let label = format!("{} (variant '{}')", surface.name, variant.alias);
            errors.extend(cfg.validate(&label));
        }
    }
    for tp in surface.transit_points() {
        let Some(cfg) = tp.mcp_tool_gating.as_ref() else {
            continue;
        };
        let label = format!("{} (transit point '{}')", surface.name, tp.alias);
        errors.extend(cfg.validate(&label));
        if !cfg.is_empty() && tp.protocol != crate::config::agent_surface::TransitProtocol::Mcp {
            errors.push(format!(
                "Surface '{}': transit point '{}' declares MCP tool gating but its protocol is not 'mcp'",
                surface.name, tp.alias
            ));
        }
    }
    if !errors.is_empty() {
        return Err(SurfaceApiError::BadRequest(errors.join("; ")));
    }
    Ok(())
}

/// Create a new agent surface
pub async fn create_surface(
    State(state): State<IdentityApiState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut surface): Json<AgentSurface>,
) -> Result<(StatusCode, Json<AgentSurface>), SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;

    // Assign a new ID if not provided
    if surface.surface_id.is_empty() {
        surface.surface_id = uuid::Uuid::new_v4().to_string();
    }
    surface.tenant_id = tenant_for_create(surface.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| SurfaceApiError::Forbidden(message.to_string()))?;
    if !scope_allows_resource(
        resource_scope(&scope),
        tenant_context(&context),
        ResourceKind::Surfaces,
        &surface.surface_id,
    ) {
        return Err(SurfaceApiError::Forbidden("surface is outside this token's permitted scope".to_string()));
    }

    // Ensure route starts with / BEFORE the shape check so the
    // historical "missing slash is auto-fixed" behaviour is preserved.
    if !surface
        .access_point
        .route
        .is_empty()
        && !surface
            .access_point
            .route
            .starts_with('/')
    {
        surface.access_point.route = format!("/{}", surface.access_point.route);
    }

    // Required-field shape check on the base surface.
    validate_required_fields(&surface, "")?;
    validate_identity_extraction(&surface, "")?;
    reject_public_predicate_route(&surface)?;

    // Block cloud-metadata URLs on target endpoint (SSRF protection)
    if (surface
        .target
        .endpoint
        .starts_with("http://")
        || surface
            .target
            .endpoint
            .starts_with("https://"))
        && let Err(e) = crate::url_validation::reject_cloud_metadata_url(&surface.target.endpoint)
    {
        return Err(SurfaceApiError::BadRequest(format!("target.endpoint: {}", e)));
    }

    // Validate variant alias uniqueness
    validate_variant_aliases(&surface)?;

    // Validate transit point aliases (URL-safe, non-empty, unique) and
    // backfill missing UUIDs.
    validate_transit_points(&mut surface)?;

    super::surface_tenancy::validate_surface_references(
        &state,
        &surface,
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;

    // Reject overlapping outbound listener routes before they can reach
    // the Axum router and panic the gateway on rebuild.
    validate_listen_path_collisions(&surface, store, &state.network_config).await?;

    // Reject duplicate access point routes — two surfaces on the same
    // (listen_address, route) would cause one to silently never receive traffic.
    validate_access_point_route_collisions(&surface, store, &state.network_config).await?;

    // Validate and resolve x402 payment policies (base + every variant).
    // This is the trust boundary for wallet addresses on the surface API.
    validate_surface_payment_policies(&mut surface).await?;

    // Validate MPP crypto-verification posture (base + every variant).
    validate_surface_mpp_posture(&surface)?;

    // Reject an A2A + jwt_bearer(Authorization) surface that delegates to a
    // remote MPP rail before it can be saved unreachable.
    validate_delegation_source_auth(&surface)?;

    // Validate MCP Tool Gating regex patterns (base + every variant).
    validate_surface_mcp_tool_gating(&surface)?;

    // Re-run the shape check against every resolved variant so a
    // variant override can't blank out a required field unnoticed.
    validate_resolved_variants(&surface)?;

    surface
        .validate()
        .map_err(|e| SurfaceApiError::BadRequest(e.to_string()))?;

    // Check for duplicate surface_id
    surface
        .validate_mcp_metadata()
        .map_err(SurfaceApiError::BadRequest)?;
    validate_mcp_resource_declarations(&state, &surface).await?;
    if let Ok(Some(_)) = store
        .get(&surface.surface_id)
        .await
    {
        return Err(SurfaceApiError::BadRequest(format!("Surface with ID '{}' already exists", surface.surface_id)));
    }

    // Enforce the appliance surface limit (per-type plus the total) before persisting.
    crate::config::enforce_add("surfaces.agent")
        .await
        .map_err(|e| SurfaceApiError::Forbidden(e.message()))?;

    store
        .save(&surface)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to save surface: {}", e)))?;

    info!("Created agent surface '{}' (surface_id={})", surface.name, surface.surface_id);

    apply_surface_change(&state, SurfaceChange::Upsert(&surface)).await;

    Ok((StatusCode::CREATED, Json(surface)))
}

/// Update an existing agent surface
pub async fn update_surface(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut surface): Json<AgentSurface>,
) -> Result<Json<AgentSurface>, SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;

    // Ensure the path ID matches the body ID
    if !surface.surface_id.is_empty() && surface.surface_id != surface_id {
        return Err(SurfaceApiError::BadRequest("surface_id in body does not match URL parameter".to_string()));
    }
    surface.surface_id = surface_id.clone();

    let existing = store
        .get(&surface_id)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to get surface: {}", e)))?;
    let existing = existing.ok_or_else(|| SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id)))?;
    if !surface_writable(existing.tenant_id.as_deref(), &surface_id, tenant_context(&context), resource_scope(&scope)) {
        return Err(SurfaceApiError::Forbidden("surface is outside this token's permitted scope".to_string()));
    }
    surface.tenant_id = existing.tenant_id.clone();
    if surface
        .mcp_legacy_metadata_output
        .is_none()
    {
        surface.mcp_legacy_metadata_output = existing.mcp_legacy_metadata_output;
    }
    retain_mcp_settings(&mut surface, &existing);

    let saved = validate_and_save_surface(
        &state,
        store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    Ok(Json(saved))
}

fn retain_mcp_settings(
    surface: &mut AgentSurface,
    existing: &AgentSurface,
) {
    surface.mcp_protocol_mode = surface
        .mcp_protocol_mode
        .or(existing.mcp_protocol_mode);
    retain_mcp_http(&mut surface.mcp_http, existing.mcp_http.as_ref());
    let retain_points = |points: &mut [crate::config::agent_surface::TransitPoint],
                         stored: &[crate::config::agent_surface::TransitPoint]| {
        for point in points {
            if let Some(previous) = stored
                .iter()
                .find(|previous| previous.id == point.id)
            {
                point.mcp_protocol_mode = point
                    .mcp_protocol_mode
                    .or(previous.mcp_protocol_mode);
                retain_mcp_http(&mut point.mcp_http, previous.mcp_http.as_ref());
            }
        }
    };
    if let (Some(transit), Some(stored)) = (&mut surface.transit, &existing.transit) {
        retain_points(&mut transit.points, &stored.points);
    }
    for variant in &mut surface.variants {
        let stored = existing
            .variants
            .iter()
            .find(|previous| previous.id == variant.id);
        let points = variant
            .overrides
            .transit
            .as_mut()
            .and_then(|transit| transit.points.as_mut());
        let stored_points = stored
            .and_then(|previous| {
                previous
                    .overrides
                    .transit
                    .as_ref()
            })
            .and_then(|transit| transit.points.as_ref());
        if let (Some(points), Some(stored_points)) = (points, stored_points) {
            retain_points(points, stored_points);
        }
    }
}

/// PUT carries the whole record, so an omitted `mcp_http` — or an `mcp_http`
/// that omits `authorization` — means "unchanged", never "remove". Resource
/// Server authorization is enforced in every protocol mode, so dropping it on
/// an unrelated edit would silently unauthenticate the endpoint. Removal is
/// explicit, via PATCH with a `null`.
fn retain_mcp_http(
    incoming: &mut Option<crate::config::McpHttpConfig>,
    previous: Option<&crate::config::McpHttpConfig>,
) {
    let Some(previous) = previous else {
        return;
    };
    match incoming {
        None => *incoming = Some(previous.clone()),
        Some(incoming)
            if incoming
                .authorization
                .is_none() =>
        {
            incoming.authorization = previous.authorization.clone();
        }
        Some(_) => {}
    }
}

/// Every `mcp_http.authorization.resource` the surface declares (base, enabled
/// variants and Transit Points) must be one it serves, and no other stored
/// surface or MCP Proxy may serve it. Otherwise a declaration could block
/// another tenant's STS clients, or two endpoints would accept the same
/// tokens (`crate::sts::resource_owners`).
async fn validate_mcp_resource_declarations(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    use crate::sts::resource_owners::{ApplianceResourceOwners, ResourceDeclarationError, ResourceEndpoint};
    let declarations = crate::mcp::resource_server::surface_resource_declarations(surface, &state.network_config);
    ApplianceResourceOwners::new(
        state
            .agent_surface_store
            .clone()
            .map(|store| store as std::sync::Arc<dyn crate::surfaces::AgentSurfaceStore>),
        state
            .mcp_proxy_store
            .clone()
            .map(|store| store as std::sync::Arc<dyn crate::mcp_proxies::McpProxyStore>),
        state.network_config.clone(),
    )
    .ensure_endpoint_may_declare(&ResourceEndpoint::Surface(surface.surface_id.clone()), &declarations)
    .await
    .map_err(|error| match error {
        ResourceDeclarationError::Unavailable => SurfaceApiError::InternalError(error.to_string()),
        _ => SurfaceApiError::BadRequest(error.to_string()),
    })
}

/// Shared validation + persist + broadcast pipeline used by both PUT and
/// PATCH on `/v1/surfaces/{id}`. The caller is responsible for resolving
/// `surface_id`/`existing` and asserting that the surface already exists
/// (PUT/PATCH semantics differ from POST on first-write). Takes `surface`
/// by value so it can be returned to the caller without a defensive clone.
async fn validate_and_save_surface(
    state: &IdentityApiState,
    store: &std::sync::Arc<crate::surfaces::FileSystemAgentSurfaceStore>,
    mut surface: AgentSurface,
    existing: Option<&AgentSurface>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<AgentSurface, SurfaceApiError> {
    // Ensure route starts with / BEFORE the shape check so the
    // historical "missing slash is auto-fixed" behaviour is preserved.
    if !surface
        .access_point
        .route
        .is_empty()
        && !surface
            .access_point
            .route
            .starts_with('/')
    {
        surface.access_point.route = format!("/{}", surface.access_point.route);
    }

    validate_required_fields(&surface, "")?;
    validate_identity_extraction(&surface, "")?;
    reject_public_predicate_route(&surface)?;

    if (surface
        .target
        .endpoint
        .starts_with("http://")
        || surface
            .target
            .endpoint
            .starts_with("https://"))
        && let Err(e) = crate::url_validation::reject_cloud_metadata_url(&surface.target.endpoint)
    {
        return Err(SurfaceApiError::BadRequest(format!("target.endpoint: {}", e)));
    }

    validate_variant_aliases(&surface)?;
    validate_transit_points(&mut surface)?;
    super::surface_tenancy::validate_surface_references(state, &surface, context, scope).await?;
    validate_listen_path_collisions(&surface, store, &state.network_config).await?;
    validate_access_point_route_collisions(&surface, store, &state.network_config).await?;
    validate_surface_payment_policies(&mut surface).await?;
    validate_surface_mpp_posture(&surface)?;
    validate_delegation_source_auth(&surface)?;
    validate_surface_mcp_tool_gating(&surface)?;
    validate_resolved_variants(&surface)?;
    validate_trust_checks(&surface)?;
    validate_workload_binding_config(&surface)?;
    validate_source_auth(&surface)?;
    surface
        .validate_mcp_metadata()
        .map_err(SurfaceApiError::BadRequest)?;
    validate_mcp_resource_declarations(state, &surface).await?;

    store
        .save(&surface)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to save surface: {}", e)))?;

    info!("Updated agent surface '{}' (surface_id={})", surface.name, surface.surface_id);

    // Agent-in-TR writes are owned by the Trust Recorder stage now; the
    // legacy `spawn_tr_issuer_sweep` was removed together with
    // `VCIssuer::register_agent_in_trust_registry` / `deregister_agent_from_trust_registry`.
    let _ = existing;

    apply_surface_change(state, SurfaceChange::Upsert(&surface)).await;

    Ok(surface)
}

/// Per RFC 7396 the media type for a JSON Merge Patch body MUST be
/// `application/merge-patch+json`. Reject anything else with `415` so a
/// client that confuses PATCH with PUT (and sends `application/json`)
/// gets a clear error rather than the silent surprise of array
/// replacement, key deletion via `null`, and so on.
fn require_merge_patch_content_type(headers: &axum::http::HeaderMap) -> Result<(), SurfaceApiError> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let primary = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if primary.eq_ignore_ascii_case("application/merge-patch+json") {
        Ok(())
    } else {
        Err(SurfaceApiError::UnsupportedMediaType("Content-Type must be application/merge-patch+json".to_string()))
    }
}

/// `PATCH /v1/surfaces/{id}`
///
/// RFC 7396 JSON Merge Patch over an existing surface. Loads the
/// surface, merges the patch, deserialises the result, and reuses the
/// PUT validation+save pipeline so PATCH and PUT produce identical
/// persisted state for equivalent terminal values. Returns 415 on a
/// wrong content type, 404 when the surface is unknown, 400 on a
/// malformed patch or on validation failure of the merged result.
pub async fn patch_surface(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<AgentSurface>, SurfaceApiError> {
    require_merge_patch_content_type(&headers)?;

    if body.is_empty() {
        return Err(SurfaceApiError::BadRequest("PATCH body must not be empty".to_string()));
    }
    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| SurfaceApiError::BadRequest(format!("PATCH body is not valid JSON: {}", e)))?;
    if !patch.is_object() {
        return Err(SurfaceApiError::BadRequest("PATCH body must be a JSON object at the top level".to_string()));
    }

    let (store, existing) = load_surface_or_404(
        &state,
        &surface_id,
        tenant_context(&context),
        resource_scope(&scope),
        SurfaceAccess::Mutate,
    )
    .await?;

    let mut merged = serde_json::to_value(&existing)
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to serialise surface for merge: {}", e)))?;
    json_patch::merge(&mut merged, &patch);

    if let Some(obj) = merged.as_object_mut() {
        obj.insert("surface_id".to_string(), serde_json::Value::String(surface_id.clone()));
    }

    let mut surface: AgentSurface = serde_json::from_value(merged)
        .map_err(|e| SurfaceApiError::BadRequest(format!("Merged surface failed to deserialise: {}", e)))?;
    surface.surface_id = surface_id.clone();

    let saved = validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    Ok(Json(saved))
}

/// `PATCH /v1/surfaces/{id}/variants/{variant_id}`
///
/// RFC 7396 JSON Merge Patch over a single variant on the surface. The
/// merge happens against the variant's serialised JSON; the resulting
/// variant is substituted back into the surface's `variants[]` and the
/// whole surface is then validated and saved via the same pipeline as
/// PUT, so an override that breaks the resolved surface (e.g. clears a
/// required field, or invalidates a `trust_check_list`) is rejected
/// with 400 — never silently saved.
pub async fn patch_variant(
    Path((surface_id, variant_id)): Path<(String, String)>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<AgentSurface>, SurfaceApiError> {
    require_merge_patch_content_type(&headers)?;

    if body.is_empty() {
        return Err(SurfaceApiError::BadRequest("PATCH body must not be empty".to_string()));
    }
    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| SurfaceApiError::BadRequest(format!("PATCH body is not valid JSON: {}", e)))?;
    if !patch.is_object() {
        return Err(SurfaceApiError::BadRequest("PATCH body must be a JSON object at the top level".to_string()));
    }

    let (store, existing) = load_surface_or_404(
        &state,
        &surface_id,
        tenant_context(&context),
        resource_scope(&scope),
        SurfaceAccess::Mutate,
    )
    .await?;

    let variant_index = existing
        .variants
        .iter()
        .position(|v| v.id == variant_id)
        .ok_or_else(|| {
            SurfaceApiError::NotFound(format!("Variant '{}' not found on surface '{}'", variant_id, surface_id))
        })?;

    let mut merged_variant = serde_json::to_value(&existing.variants[variant_index])
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to serialise variant for merge: {}", e)))?;
    json_patch::merge(&mut merged_variant, &patch);

    if let Some(obj) = merged_variant.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(variant_id.clone()));
    }

    let new_variant: crate::config::agent_surface_variants::SurfaceVariant = serde_json::from_value(merged_variant)
        .map_err(|e| SurfaceApiError::BadRequest(format!("Merged variant failed to deserialise: {}", e)))?;

    let mut surface = existing.clone();
    surface.variants[variant_index] = new_variant;

    let saved = validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    Ok(Json(saved))
}

/// Delete an agent surface (hard delete: removes from cache + filesystem).
pub async fn delete_surface(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<DeleteSurfaceResponse>, SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;

    let existing = store
        .get(&surface_id)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to get surface: {}", e)))?;

    match existing {
        Some(surface)
            if surface_writable(
                surface.tenant_id.as_deref(),
                &surface_id,
                tenant_context(&context),
                resource_scope(&scope),
            ) =>
        {
            store
                .delete(&surface_id)
                .await
                .map_err(|e| SurfaceApiError::InternalError(format!("Failed to delete surface: {}", e)))?;

            info!("Deleted agent surface '{}' (surface_id={})", surface.name, surface_id);

            apply_surface_change(&state, SurfaceChange::Delete(&surface_id)).await;

            Ok(Json(DeleteSurfaceResponse {
                success: true,
                message: format!("Surface '{}' deleted", surface_id),
            }))
        }
        Some(_) => Err(SurfaceApiError::Forbidden("surface is outside this token's permitted scope".to_string())),
        None => Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id))),
    }
}

#[derive(Debug, Serialize)]
pub struct DeleteSurfaceResponse {
    pub success: bool,
    pub message: String,
}

/// Action being applied to the running gateway after a surface mutation.
enum SurfaceChange<'a> {
    /// Create or update — the new surface is materialised into a single
    /// `ChannelMapping` and slotted into the existing port listener
    /// without restarting other channels' tasks.
    Upsert(&'a crate::config::agent_surface::AgentSurface),
    /// Delete — the matching channel is removed from the running port
    /// listener and its tasks unregistered.
    Delete(&'a str),
}

/// Apply a surface change to the running gateway with the smallest
/// possible disruption.
///
/// Fast paths (no other channel is touched):
///   * `Upsert` of an active surface that maps to an existing port
///     listener → `reload_single_channel_with_fallback`.
///   * `Delete` of a surface whose channel is currently in the live
///     config → `remove_single_channel`.
///
/// Slow path (full reload of every channel + surface):
///   * Inactive-status upsert (channel must be removed from the live
///     listener; we do not yet have a "deactivate" fast path).
///   * Any change where inbound variant alias routes may have changed.
///     The inbound Axum router bakes `{route}$alias` and
///     `{route}%24alias` paths at listener startup, so adding, removing,
///     or clearing `variants[]` requires a listener rebuild.
///   * The fast path returned an error (e.g. listener port changed,
///     port not found, compile failure) — we fall back to a full reload
///     so the operator does not have to call /v1/config/reload manually.
///
/// Failures are logged but never propagated: the surface has already
/// been persisted, so an operator can always recover by hitting
/// `/v1/config/reload` explicitly.
async fn apply_surface_change(
    state: &IdentityApiState,
    change: SurfaceChange<'_>,
) {
    let (action, surface_id) = match change {
        SurfaceChange::Upsert(s) => ("upsert", s.surface_id.as_str()),
        SurfaceChange::Delete(id) => ("delete", id),
    };

    // Drop cached outbound target agent cards so a surface whose
    // target endpoint / agent_card_path just changed doesn't feed a
    // stale card into `step_collect_trust_context`. Cheap (a single
    // DashMap clear) and safe (worst case is the next few requests
    // re-fetch).
    crate::proxy::agent_card_cache::invalidate_all();

    // Phase C — keep the resolved-surface snapshot cache in lockstep
    // with the on-disk store. Done up-front (before reload) so the
    // cache reflects the change even if the channel reload below
    // fails: the next request will then hit either the new snapshots
    // (which match what was just persisted) or a clean miss for a
    // deleted surface.
    match change {
        SurfaceChange::Upsert(surface) => {
            if surface.status == crate::config::agent_surface::SurfaceStatus::Active {
                if let Err(e) = state
                    .resolved_surface_cache
                    .upsert(surface)
                {
                    warn!(
                        surface = %surface_id,
                        "Failed to refresh resolved-surface cache after upsert: {e}"
                    );
                }
            } else {
                // Inactive surfaces must not serve traffic — drop any
                // stale snapshot so a misrouted request fails fast
                // instead of using yesterday's config.
                state
                    .resolved_surface_cache
                    .remove(surface_id);
            }
        }
        SurfaceChange::Delete(id) => {
            state
                .resolved_surface_cache
                .remove(id);
        }
    }

    let variant_routes_need_rebuild = {
        let current_config = state
            .channel_manager
            .get_config()
            .await;
        let existing_has_variants = current_config
            .surfaces
            .iter()
            .find(|surface| surface.config_id() == Some(surface_id))
            .is_some_and(|surface| !surface.variants.is_empty());

        match change {
            SurfaceChange::Upsert(surface) => !surface.variants.is_empty() || existing_has_variants,
            SurfaceChange::Delete(_) => existing_has_variants,
        }
    };

    let fast_result: anyhow::Result<bool> = match change {
        SurfaceChange::Upsert(surface) => {
            if surface.status != crate::config::agent_surface::SurfaceStatus::Active {
                // Inactive surfaces shouldn't be running — fall through
                // to full reload, which filters them out via
                // inject_surfaces_into_config.
                Ok(false)
            } else if variant_routes_need_rebuild {
                // Inbound variant alias routes are statically registered
                // on the port listener at startup (`/route$alias` and
                // `/route%24alias`). `reload_single_channel` only swaps
                // the in-memory SurfaceInfo, so it cannot add/remove
                // those Axum routes. Fall through to full reload so the
                // listener is rebuilt with the current alias set.
                Ok(false)
            } else if surface
                .transit
                .as_ref()
                .is_some_and(|t| !t.points.is_empty())
            {
                // Surfaces with transit points need the outbound port
                // listener (re)spawned with the up-to-date VC list, and
                // `reload_single_channel` only updates the inbound side.
                // Fall through to full reload so outbound bucketing
                // re-runs and the outbound listener is restarted.
                Ok(false)
            } else {
                let channel_name = surface.name.clone();
                state
                    .channel_manager
                    .reload_single_channel_with_fallback(
                        &channel_name,
                        Ok(surface.clone()),
                        state.tls_acceptor.clone(),
                        Some(state.metrics_store.clone()),
                        state.task_monitor.clone(),
                    )
                    .await
                    .map(|_| true)
            }
        }
        SurfaceChange::Delete(id) => {
            if variant_routes_need_rebuild {
                // Deleting a variant-bearing surface must rebuild the
                // inbound listener to remove its statically-registered
                // alias routes. Leaving them behind would let future
                // surfaces on the same base route match stale alias
                // paths incorrectly.
                Ok(false)
            } else {
                state
                    .channel_manager
                    .remove_single_channel(id, state.task_monitor.clone())
                    .await
            }
        }
    };

    match fast_result {
        Ok(true) => {
            info!("Surface {action} for '{surface_id}' applied via single-channel fast path");
        }
        Ok(false) => {
            // Channel wasn't found in the running gateway (e.g. delete
            // of an inactive surface, or first-time activation). Do a
            // full reload so the new state takes effect.
            full_reload_after_surface_change(state, action, surface_id).await;
        }
        Err(e) => {
            warn!(
                "Single-channel reload for surface {action} '{surface_id}' failed ({e}); \
                 falling back to full reload"
            );
            full_reload_after_surface_change(state, action, surface_id).await;
        }
    }

    // Compile / refresh the OPA policy for the surface-derived channel.
    // The reload paths above register the ChannelMapping with the runtime
    // but do NOT invoke SurfacePolicyManager — so without this, an active
    // surface with `policy_definition_id` set would have `opa_enabled=true`
    // on the channel but no compiled engine, producing the misleading
    // "OPA policy enforcement is enabled but no policy is loaded" 403.
    if let SurfaceChange::Upsert(surface) = change
        && surface.status == crate::config::agent_surface::SurfaceStatus::Active
        && let Err(e) = state
            .policy_manager
            .update_channel_policy(surface)
            .await
    {
        warn!("Failed to compile OPA policy for surface '{surface_id}': {e}");
    }
}

// wraps original function to avoid leaking implementation details
pub(crate) async fn apply_surface_upsert_from_storage(
    state: &IdentityApiState,
    surface: AgentSurface,
) {
    apply_surface_change(state, SurfaceChange::Upsert(&surface)).await;
}

// wraps original function to avoid leaking implementation details
pub(crate) async fn apply_surface_delete_from_storage(
    state: &IdentityApiState,
    surface_id: &str,
) {
    apply_surface_change(state, SurfaceChange::Delete(surface_id)).await;
}

/// Trigger a full in-process gateway reload. Used as the slow-path
/// fallback when the per-surface fast path can't apply the change
/// (port change, inactive surface activation, compile error, etc.).
async fn full_reload_after_surface_change(
    state: &IdentityApiState,
    action: &str,
    surface_id: &str,
) {
    match crate::identity::handlers::config::perform_config_reload(state).await {
        Ok((channels, surfaces, is_fallback, warning)) => {
            info!(
                "Surface {action} for '{surface_id}' triggered full reload: \
                 {channels} channels + {surfaces} surfaces (fallback={is_fallback})"
            );
            if let Some(warn_msg) = warning {
                warn!("Surface reload warning: {warn_msg}");
            }
        }
        Err(e) => {
            error!(
                "Surface {action} for '{surface_id}' persisted to storage but \
                 in-process reload failed: {e}. Operator must call POST /v1/config/reload \
                 for the change to take effect."
            );
        }
    }
}

// ─── Variant CRUD ───────────────────────────────────────────────────────────
//
// Implements the variant CRUD endpoints:
//
//   POST   /v1/surfaces/{id}/variants
//   PUT    /v1/surfaces/{id}/variants/{variant_id}
//   DELETE /v1/surfaces/{id}/variants/{variant_id}
//   POST   /v1/surfaces/{id}/variants/{variant_id}/promote-to-default
//   GET    /v1/surfaces/{id}/variants/{alias}/resolved
//
// All mutating endpoints reuse `apply_surface_change` so the running
// gateway picks up the new variant catalog via the same fast/slow path
// that `update_surface` uses.

use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant};

#[derive(Debug, serde::Deserialize)]
pub struct CreateVariantRequest {
    pub alias: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub source_alias: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateVariantRequest {
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub overrides: Option<SurfaceOverrides>,
}

/// May this caller change or delete the surface? Reading an operator's surface
/// through a tenant PAT is allowed; changing it is not.
fn surface_writable(
    tenant_id: Option<&str>,
    surface_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_mutate(tenant_id, context) && scope_allows_resource(scope, context, ResourceKind::Surfaces, surface_id)
}

/// What the caller means to do with a surface it loads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SurfaceAccess {
    Read,
    Mutate,
}

/// Look up an existing surface or return 404. A surface the caller may read
/// but not change (an operator's, seen through a tenant PAT) is 403 for
/// [`SurfaceAccess::Mutate`].
async fn load_surface_or_404(
    state: &IdentityApiState,
    surface_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
    access: SurfaceAccess,
) -> Result<(std::sync::Arc<crate::surfaces::FileSystemAgentSurfaceStore>, AgentSurface), SurfaceApiError> {
    let store = state
        .agent_surface_store
        .clone()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;

    let surface = store
        .get(surface_id)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to get surface: {}", e)))?
        .ok_or_else(|| SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id)))?;

    if !can_access(surface.tenant_id.as_deref(), context)
        || !scope_allows_resource(scope, context, ResourceKind::Surfaces, surface_id)
    {
        return Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id)));
    }
    if access == SurfaceAccess::Mutate && !surface_writable(surface.tenant_id.as_deref(), surface_id, context, scope) {
        return Err(SurfaceApiError::Forbidden("surface is outside this token's permitted scope".to_string()));
    }

    Ok((store, surface))
}

/// `POST /v1/surfaces/{id}/variants`
///
/// Create a new variant on the surface. When `source_alias` is provided
/// the new variant inherits that variant's `overrides` block as a
/// starting point; otherwise it inherits from the current default
/// variant (if any) and falls back to empty overrides.
pub async fn create_variant(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(body): Json<CreateVariantRequest>,
) -> Result<(StatusCode, Json<SurfaceVariant>), SurfaceApiError> {
    let (store, mut surface) = load_surface_or_404(
        &state,
        &surface_id,
        tenant_context(&context),
        resource_scope(&scope),
        SurfaceAccess::Mutate,
    )
    .await?;
    let existing = surface.clone();

    if body.name.trim().is_empty() {
        return Err(SurfaceApiError::BadRequest("variant name is required".to_string()));
    }
    SurfaceVariant::validate_alias(&body.alias).map_err(SurfaceApiError::BadRequest)?;

    if surface
        .variants
        .iter()
        .any(|v| v.alias == body.alias)
    {
        return Err(SurfaceApiError::BadRequest(format!(
            "variant alias '{}' already exists on surface '{}'",
            body.alias, surface_id
        )));
    }

    // Choose seed overrides: explicit source_alias > current default > empty.
    let seed_overrides = if let Some(ref src) = body.source_alias {
        match surface
            .variants
            .iter()
            .find(|v| &v.alias == src)
        {
            Some(v) => v.overrides.clone(),
            None => {
                return Err(SurfaceApiError::BadRequest(format!(
                    "source_alias '{}' does not match any variant on surface '{}'",
                    src, surface_id
                )));
            }
        }
    } else if let Some(ref default_id) = surface.default_variant_id {
        surface
            .variants
            .iter()
            .find(|v| &v.id == default_id)
            .map(|v| v.overrides.clone())
            .unwrap_or_default()
    } else {
        SurfaceOverrides::default()
    };

    let new_variant = SurfaceVariant {
        id: uuid::Uuid::new_v4().to_string(),
        alias: body.alias,
        name: body.name,
        description: body.description,
        enabled: true,
        overrides: seed_overrides,
    };

    surface
        .variants
        .push(new_variant.clone());

    let saved = validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    let new_variant = saved
        .variants
        .iter()
        .find(|variant| variant.id == new_variant.id)
        .cloned()
        .ok_or_else(|| SurfaceApiError::InternalError("Created variant disappeared during validation".to_string()))?;

    info!("Created variant '{}' (id={}) on surface '{}'", new_variant.alias, new_variant.id, surface_id);

    Ok((StatusCode::CREATED, Json(new_variant)))
}

/// `PUT /v1/surfaces/{id}/variants/{variant_id}`
///
/// Patch an existing variant in place. Any field left out in the
/// request body is preserved. Renaming `alias` enforces the global
/// uniqueness check that `validate_variant_aliases` performs on
/// surface PUT.
pub async fn update_variant(
    Path((surface_id, variant_id)): Path<(String, String)>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(body): Json<UpdateVariantRequest>,
) -> Result<Json<SurfaceVariant>, SurfaceApiError> {
    let (store, mut surface) = load_surface_or_404(
        &state,
        &surface_id,
        tenant_context(&context),
        resource_scope(&scope),
        SurfaceAccess::Mutate,
    )
    .await?;
    let existing = surface.clone();

    if let Some(ref new_alias) = body.alias {
        SurfaceVariant::validate_alias(new_alias).map_err(SurfaceApiError::BadRequest)?;
        if surface
            .variants
            .iter()
            .any(|v| v.id != variant_id && &v.alias == new_alias)
        {
            return Err(SurfaceApiError::BadRequest(format!(
                "variant alias '{}' already in use on surface '{}'",
                new_alias, surface_id
            )));
        }
    }

    if let Some(ref new_name) = body.name
        && new_name.trim().is_empty()
    {
        return Err(SurfaceApiError::BadRequest("variant name cannot be empty".to_string()));
    }

    let variant = surface
        .variants
        .iter_mut()
        .find(|v| v.id == variant_id)
        .ok_or_else(|| {
            SurfaceApiError::NotFound(format!("Variant '{}' not found on surface '{}'", variant_id, surface_id))
        })?;

    if let Some(alias) = body.alias {
        variant.alias = alias;
    }
    if let Some(name) = body.name {
        variant.name = name;
    }
    if let Some(description) = body.description {
        variant.description = description;
    }
    if let Some(enabled) = body.enabled {
        variant.enabled = enabled;
    }
    if let Some(overrides) = body.overrides {
        variant.overrides = overrides;
    }

    let saved = validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;

    let updated = saved
        .variants
        .iter()
        .find(|v| v.id == variant_id)
        .cloned()
        .ok_or_else(|| {
            SurfaceApiError::InternalError(format!(
                "Variant '{}' disappeared from surface '{}' during validation",
                variant_id, surface_id
            ))
        })?;

    info!("Updated variant '{}' (id={}) on surface '{}'", updated.alias, updated.id, surface_id);

    Ok(Json(updated))
}

/// `DELETE /v1/surfaces/{id}/variants/{variant_id}`
///
/// Refuses to delete the variant currently pointed at by
/// `default_variant_id` and refuses to delete the only remaining
/// variant on the surface.
pub async fn delete_variant(
    Path((surface_id, variant_id)): Path<(String, String)>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<DeleteSurfaceResponse>, SurfaceApiError> {
    let (store, mut surface) = load_surface_or_404(
        &state,
        &surface_id,
        tenant_context(&context),
        resource_scope(&scope),
        SurfaceAccess::Mutate,
    )
    .await?;
    let existing = surface.clone();

    if surface
        .default_variant_id
        .as_deref()
        == Some(&variant_id)
    {
        return Err(SurfaceApiError::BadRequest(
            "cannot delete the default variant; promote another variant to default first".to_string(),
        ));
    }

    let position = surface
        .variants
        .iter()
        .position(|v| v.id == variant_id)
        .ok_or_else(|| {
            SurfaceApiError::NotFound(format!("Variant '{}' not found on surface '{}'", variant_id, surface_id))
        })?;

    if surface.variants.len() == 1 {
        return Err(SurfaceApiError::BadRequest("cannot delete the only variant on this surface".to_string()));
    }

    let removed = surface
        .variants
        .remove(position);

    validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;

    info!("Deleted variant '{}' (id={}) from surface '{}'", removed.alias, removed.id, surface_id);

    Ok(Json(DeleteSurfaceResponse {
        success: true,
        message: format!("Variant '{}' deleted from surface '{}'", variant_id, surface_id),
    }))
}

/// `POST /v1/surfaces/{id}/variants/{variant_id}/promote-to-default`
///
/// Set the surface's `default_variant_id` to the given variant. The
/// variant must exist and be `enabled` (a disabled default would be
/// unreachable). `apply_variant_overrides` already handles the new
/// default the next time the channel is materialised — there is no
/// need to re-base the other variants because each variant carries a
/// full delta against the base, not against the previous default.
pub async fn promote_variant_to_default(
    Path((surface_id, variant_id)): Path<(String, String)>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AgentSurface>, SurfaceApiError> {
    let (store, mut surface) = load_surface_or_404(
        &state,
        &surface_id,
        tenant_context(&context),
        resource_scope(&scope),
        SurfaceAccess::Mutate,
    )
    .await?;
    let existing = surface.clone();

    let variant = surface
        .variants
        .iter()
        .find(|v| v.id == variant_id)
        .ok_or_else(|| {
            SurfaceApiError::NotFound(format!("Variant '{}' not found on surface '{}'", variant_id, surface_id))
        })?;

    if !variant.enabled {
        return Err(SurfaceApiError::BadRequest(format!(
            "variant '{}' is disabled and cannot be promoted to default",
            variant.alias
        )));
    }

    let variant_alias = variant.alias.clone();
    surface.default_variant_id = Some(variant_id.clone());

    let saved = validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;

    info!("Promoted variant '{}' (id={}) to default on surface '{}'", variant_alias, variant_id, surface_id);

    Ok(Json(saved))
}

/// `GET /v1/surfaces/{id}/variants/{alias}/resolved`
///
/// Return the fully-materialised `AgentSurface` for a single variant.
/// Useful for the dashboard's "show effective config" debug pane and
/// for support troubleshooting. Read-only — never mutates anything.
pub async fn get_resolved_variant(
    Path((surface_id, alias)): Path<(String, String)>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AgentSurface>, SurfaceApiError> {
    let (_store, surface) =
        load_surface_or_404(&state, &surface_id, tenant_context(&context), resource_scope(&scope), SurfaceAccess::Read)
            .await?;

    let resolved = surface
        .resolve_variant(Some(&alias))
        .map_err(|e| match e {
            crate::config::agent_surface_variants::VariantResolveError::UnknownAlias(a) => {
                SurfaceApiError::NotFound(format!("Variant '{}' not found on surface '{}'", a, surface_id))
            }
            crate::config::agent_surface_variants::VariantResolveError::DisabledVariant(_)
            | crate::config::agent_surface_variants::VariantResolveError::MisconfiguredDefault(_) => {
                SurfaceApiError::BadRequest(e.to_string())
            }
        })?;

    Ok(Json(resolved))
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::config::agent_surface::{AccessPoint, IdentityInjectionConfig, SurfaceProtocol, SurfaceStatus, Target};
    use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant, TargetOverrides};

    #[test]
    fn a_put_that_rewrites_mcp_http_keeps_resource_authorization() {
        let authorization = crate::mcp::resource_server::McpResourceServerConfig {
            resource: "https://gateway.example/api".to_string(),
            scopes: vec!["mcp.read".to_string()],
        };
        let mut existing = base_surface();
        existing.mcp_http = Some(crate::config::McpHttpConfig {
            authorization: Some(authorization.clone()),
            ..Default::default()
        });

        // A PUT that only means to change allowed_origins still sends the whole
        // record, so `authorization` is absent without the caller removing it.
        let mut rewritten = base_surface();
        rewritten.mcp_http = Some(crate::config::McpHttpConfig {
            allowed_origins: vec!["https://app.example".to_string()],
            ..Default::default()
        });
        retain_mcp_settings(&mut rewritten, &existing);
        let retained = rewritten
            .mcp_http
            .expect("mcp_http stays present");
        assert_eq!(retained.authorization, Some(authorization));
        assert_eq!(retained.allowed_origins, vec!["https://app.example".to_string()]);

        // Omitting the block entirely keeps the stored one unchanged.
        let mut omitted = base_surface();
        omitted.mcp_http = None;
        retain_mcp_settings(&mut omitted, &existing);
        assert_eq!(omitted.mcp_http, existing.mcp_http);

        // A surface that never had authorization does not gain one.
        let mut fresh = base_surface();
        fresh.mcp_http = Some(crate::config::McpHttpConfig::default());
        retain_mcp_settings(&mut fresh, &base_surface());
        assert_eq!(
            fresh
                .mcp_http
                .and_then(|http| http.authorization),
            None
        );
    }

    fn base_surface() -> AgentSurface {
        AgentSurface {
            surface_id: "s1".to_string(),
            tenant_id: None,
            name: "test".to_string(),
            description: String::new(),
            status: SurfaceStatus::Active,
            agent_did: None,
            issuer_id: None,
            tags: Vec::new(),
            access_point: AccessPoint {
                name: None,
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/api".to_string(),
                protocol: SurfaceProtocol::A2a,
                caller_authentication: None,
                caller_context: Default::default(),
                identity_resolution: None,
                inbound_policy: None,
                rate_limit: None,
                extension_validation: None,
                trust_check_list: Vec::new(),
                header_metadata_mapping: None,
                trust_recorder: None,
                publish_to_did_document: false,
                supported_extensions: Vec::new(),
                primary_extension: None,
                agent_card_path: None,
                response_custom_metadata: None,
                didwebvh_identity: None,
                terminate_trace_id: false,
            },
            target: Target {
                endpoint: "https://prod.example.com".to_string(),
                auth: None,
                policy: None,
                response_policy: None,
                payment_policy: None,
                mcp_tool_policies: Vec::new(),
                mcp_tool_policies_enabled: false,
                mcp_tool_gating: None,
                networking: None,
                identity_injection: IdentityInjectionConfig::default(),
                workload_binding: None,
                extension_rules: None,
                custom_metadata: None,
                response_custom_metadata: None,
                trust_check_list: Vec::new(),
                mcp_proxy_id: None,
                a2a_proxy_id: None,
                fabric_target_name: None,
                mpp_auto_pay: false,
                mpp_auto_pay_max_amount: None,
            },
            transit: None,
            canvas: None,
            variants: Vec::new(),
            default_variant_id: None,
            outbound_credentials: Vec::new(),
            identity_slots: Default::default(),
            mcp_legacy_metadata_output: None,
            mcp_protocol_mode: None,
            mcp_http: None,
        }
    }

    #[test]
    fn required_fields_accepts_a_well_formed_surface() {
        let s = base_surface();
        validate_required_fields(&s, "").expect("base surface is valid");
    }

    #[test]
    fn required_fields_rejects_missing_endpoint() {
        let mut s = base_surface();
        s.target.endpoint.clear();
        let err = validate_required_fields(&s, "").expect_err("empty endpoint must fail");
        match err {
            SurfaceApiError::BadRequest(msg) => assert!(msg.contains("target.endpoint")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn resolved_variants_accept_when_base_already_valid() {
        let mut s = base_surface();
        s.variants
            .push(SurfaceVariant {
                id: "v-dev".to_string(),
                alias: "dev".to_string(),
                name: "dev".to_string(),
                description: String::new(),
                enabled: true,
                overrides: SurfaceOverrides {
                    target: Some(TargetOverrides {
                        endpoint: Some("https://dev.example.com".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            });
        validate_resolved_variants(&s).expect("dev variant resolves cleanly");
    }

    #[test]
    fn resolved_variants_reject_variant_blanking_endpoint() {
        let mut s = base_surface();
        s.variants
            .push(SurfaceVariant {
                id: "v-broken".to_string(),
                alias: "broken".to_string(),
                name: "broken".to_string(),
                description: String::new(),
                enabled: true,
                overrides: SurfaceOverrides {
                    target: Some(TargetOverrides {
                        endpoint: Some(String::new()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            });
        let err = validate_resolved_variants(&s).expect_err("blanked endpoint must fail");
        match err {
            SurfaceApiError::BadRequest(msg) => {
                assert!(msg.contains("Variant 'broken'"), "label missing: {msg}");
                assert!(msg.contains("target.endpoint"), "field missing: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn resolved_variants_skip_disabled_variant_with_broken_overrides() {
        let mut s = base_surface();
        s.variants
            .push(SurfaceVariant {
                id: "v-off".to_string(),
                alias: "off".to_string(),
                name: "off".to_string(),
                description: String::new(),
                enabled: false,
                overrides: SurfaceOverrides {
                    target: Some(TargetOverrides {
                        endpoint: Some(String::new()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            });
        validate_resolved_variants(&s).expect("disabled variant is skipped");
    }

    /// Attach a transit config (parsed from JSON for brevity) to a surface.
    fn with_transit(
        mut s: AgentSurface,
        transit: serde_json::Value,
    ) -> AgentSurface {
        s.transit = Some(serde_json::from_value(transit).expect("valid transit config"));
        s
    }

    fn surface_with_tp(
        id: &str,
        name: &str,
        outbound_addr: &str,
        alias: &str,
        listen_path: &str,
    ) -> AgentSurface {
        let mut s = base_surface();
        s.surface_id = id.to_string();
        s.name = name.to_string();
        with_transit(
            s,
            serde_json::json!({
                "outbound_listen_address": outbound_addr,
                "points": [{
                    "alias": alias,
                    "target_endpoint": "https://partner.example.com",
                    "protocol": "a2a",
                    "listen_path": listen_path,
                }],
            }),
        )
    }

    /// Resolver standing in for `map_url_to_port_for_type` when no listener
    /// config is involved: nothing resolves, so claims fall back to raw
    /// address strings.
    fn no_ports(_addr: &str) -> Option<u16> {
        None
    }

    #[test]
    fn listen_path_claims_uses_channel_address_when_tp_has_none() {
        let s = surface_with_tp("s1", "one", "0.0.0.0:9443", "partner", "/hook");
        let claims = outbound_listen_path_claims(&s, &no_ports);
        assert_eq!(claims, vec![(ListenerKey::Unresolved("0.0.0.0:9443".to_string()), "/hook".to_string())]);
    }

    #[test]
    fn listen_path_claims_resolves_address_to_port() {
        let s = surface_with_tp("s1", "one", "https://gw-out.example.com", "partner", "/hook");
        let resolve = |addr: &str| (addr == "https://gw-out.example.com").then_some(9111);
        let claims = outbound_listen_path_claims(&s, &resolve);
        assert_eq!(claims, vec![(ListenerKey::Port(9111), "/hook".to_string())]);
    }

    #[test]
    fn listen_path_claims_skips_tps_without_a_custom_path() {
        let s = with_transit(
            base_surface(),
            serde_json::json!({
                "outbound_listen_address": "0.0.0.0:9443",
                "points": [{ "alias": "partner", "target_endpoint": "https://p.example.com", "protocol": "a2a" }],
            }),
        );
        assert!(outbound_listen_path_claims(&s, &no_ports).is_empty());
    }

    #[test]
    fn collision_check_accepts_unique_paths_across_surfaces() {
        let a = surface_with_tp("s1", "one", "0.0.0.0:9443", "pa", "/hook-a");
        let b = surface_with_tp("s2", "two", "0.0.0.0:9443", "pb", "/hook-b");
        check_listen_path_collisions(&a, &[b], no_ports).expect("distinct paths must pass");
    }

    #[test]
    fn collision_check_rejects_duplicate_path_on_same_listener() {
        let a = surface_with_tp("s1", "one", "0.0.0.0:9443", "pa", "/hook");
        let b = surface_with_tp("s2", "two", "0.0.0.0:9443", "pb", "/hook");
        let err = check_listen_path_collisions(&a, &[b], no_ports).expect_err("same path + addr must collide");
        match err {
            SurfaceApiError::BadRequest(msg) => {
                assert!(msg.contains("/hook"), "message should name the path: {msg}");
                assert!(msg.contains("'two'"), "message should name the owning surface: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn collision_check_rejects_duplicate_path_via_address_aliases() {
        // The bug scenario: two different address strings resolving to the
        // same outbound listener port must collide even though the raw
        // strings differ.
        let a = surface_with_tp("s1", "one", "http://localhost:9111", "pa", "/agents/responder");
        let b = surface_with_tp("s2", "two", "https://gw1-out.proxy.example.com", "pb", "/agents/responder");
        let resolve =
            |addr: &str| matches!(addr, "http://localhost:9111" | "https://gw1-out.proxy.example.com").then_some(9111);
        let err =
            check_listen_path_collisions(&a, &[b], resolve).expect_err("address aliases of the same port must collide");
        match err {
            SurfaceApiError::BadRequest(msg) => {
                assert!(msg.contains("/agents/responder"), "message should name the path: {msg}");
                assert!(msg.contains("port 9111"), "message should name the resolved port: {msg}");
                assert!(msg.contains("'two'"), "message should name the owning surface: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn collision_check_allows_same_path_on_different_resolved_ports() {
        let a = surface_with_tp("s1", "one", "http://localhost:9111", "pa", "/hook");
        let b = surface_with_tp("s2", "two", "http://localhost:9222", "pb", "/hook");
        let resolve = |addr: &str| match addr {
            "http://localhost:9111" => Some(9111),
            "http://localhost:9222" => Some(9222),
            _ => None,
        };
        check_listen_path_collisions(&a, &[b], resolve).expect("same path on different ports is fine");
    }

    #[test]
    fn collision_check_allows_same_path_on_different_listeners() {
        let a = surface_with_tp("s1", "one", "0.0.0.0:9443", "pa", "/hook");
        let b = surface_with_tp("s2", "two", "0.0.0.0:9444", "pb", "/hook");
        check_listen_path_collisions(&a, &[b], no_ports).expect("same path on different ports is fine");
    }

    #[test]
    fn collision_check_excludes_self_on_update() {
        // The surface being updated reappears in the existing list under
        // the same id; it must not collide with its own persisted copy.
        let updated = surface_with_tp("s1", "one", "0.0.0.0:9443", "pa", "/hook");
        let persisted_self = surface_with_tp("s1", "one", "0.0.0.0:9443", "pa", "/hook");
        check_listen_path_collisions(&updated, &[persisted_self], no_ports)
            .expect("self must be excluded by surface_id");
    }

    #[test]
    fn collision_check_ignores_disabled_surfaces() {
        let a = surface_with_tp("s1", "one", "0.0.0.0:9443", "pa", "/hook");
        let mut disabled = surface_with_tp("s2", "two", "0.0.0.0:9443", "pb", "/hook");
        disabled.status = SurfaceStatus::Disabled;
        check_listen_path_collisions(&a, &[disabled], no_ports).expect("disabled surface reserves no route");
    }

    #[test]
    fn collision_check_allows_disabling_a_conflicting_surface() {
        // Remediation flow for an on-disk duplicate: PATCHing one copy to
        // disabled must save even though its listen_path still matches the
        // active copy — a disabled surface reserves no routes.
        let mut being_disabled = surface_with_tp("s1", "one", "0.0.0.0:9443", "pa", "/hook");
        being_disabled.status = SurfaceStatus::Disabled;
        let active_duplicate = surface_with_tp("s2", "two", "0.0.0.0:9443", "pb", "/hook");
        check_listen_path_collisions(&being_disabled, &[active_duplicate], no_ports)
            .expect("disabling a surface must pass collision validation");
    }

    #[test]
    fn collision_check_rejects_in_surface_duplicate() {
        let s = with_transit(
            base_surface(),
            serde_json::json!({
                "outbound_listen_address": "0.0.0.0:9443",
                "points": [
                    { "alias": "pa", "target_endpoint": "https://a.example.com", "protocol": "a2a", "listen_path": "/hook" },
                    { "alias": "pb", "target_endpoint": "https://b.example.com", "protocol": "a2a", "listen_path": "/hook" },
                ],
            }),
        );
        let err = check_listen_path_collisions(&s, &[], no_ports).expect_err("two TPs with same path must collide");
        match err {
            SurfaceApiError::BadRequest(msg) => assert!(msg.contains("within this surface"), "{msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    // ── access_point route collision checks ────────────────────────────

    fn surface_with_route(
        id: &str,
        name: &str,
        listen_address: &str,
        route: &str,
    ) -> AgentSurface {
        let mut s = base_surface();
        s.surface_id = id.to_string();
        s.name = name.to_string();
        s.access_point.listen_address = listen_address.to_string();
        s.access_point.route = route.to_string();
        s
    }

    #[test]
    fn ap_route_collision_accepts_unique_routes() {
        let a = surface_with_route("s1", "alpha", "0.0.0.0:8443", "/api/v1");
        let b = surface_with_route("s2", "beta", "0.0.0.0:8443", "/api/v2");
        check_access_point_route_collisions(&a, &[b], no_ports).expect("distinct routes must pass");
    }

    #[test]
    fn ap_route_collision_rejects_same_route_same_listener() {
        let a = surface_with_route("s1", "alpha", "0.0.0.0:8443", "/api");
        let b = surface_with_route("s2", "beta", "0.0.0.0:8443", "/api");
        let err = check_access_point_route_collisions(&a, &[b], no_ports)
            .expect_err("same route + same listener must collide");
        match err {
            SurfaceApiError::BadRequest(msg) => {
                assert!(msg.contains("/api"), "message should name the route: {msg}");
                assert!(msg.contains("'beta'"), "message should name the owning surface: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn ap_route_collision_allows_same_route_on_different_listeners() {
        let a = surface_with_route("s1", "alpha", "0.0.0.0:8443", "/api");
        let b = surface_with_route("s2", "beta", "0.0.0.0:8444", "/api");
        check_access_point_route_collisions(&a, &[b], no_ports).expect("same route on different listeners must pass");
    }

    #[test]
    fn ap_route_collision_rejects_same_route_via_address_aliases() {
        // Two different address strings resolving to the same inbound
        // listener port must collide — otherwise the second surface is
        // silently shadowed at runtime (first prefix match wins).
        let a = surface_with_route("s1", "alpha", "0.0.0.0:8443", "/api");
        let b = surface_with_route("s2", "beta", "https://gw.proxy.example.com", "/api");
        let resolve = |addr: &str| matches!(addr, "0.0.0.0:8443" | "https://gw.proxy.example.com").then_some(8443);
        let err = check_access_point_route_collisions(&a, &[b], resolve)
            .expect_err("address aliases of the same listener must collide");
        match err {
            SurfaceApiError::BadRequest(msg) => {
                assert!(msg.contains("port 8443"), "message should name the resolved port: {msg}");
                assert!(msg.contains("'beta'"), "message should name the owning surface: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn ap_route_collision_allows_same_route_on_different_resolved_ports() {
        let a = surface_with_route("s1", "alpha", "https://gw-a.example.com", "/api");
        let b = surface_with_route("s2", "beta", "https://gw-b.example.com", "/api");
        let resolve = |addr: &str| match addr {
            "https://gw-a.example.com" => Some(8443),
            "https://gw-b.example.com" => Some(8444),
            _ => None,
        };
        check_access_point_route_collisions(&a, &[b], resolve).expect("different resolved ports must pass");
    }

    #[test]
    fn ap_route_collision_excludes_self_on_update() {
        let updated = surface_with_route("s1", "alpha", "0.0.0.0:8443", "/api");
        let persisted_self = surface_with_route("s1", "alpha", "0.0.0.0:8443", "/api");
        check_access_point_route_collisions(&updated, &[persisted_self], no_ports)
            .expect("self must be excluded by surface_id");
    }

    #[test]
    fn ap_route_collision_ignores_disabled_surfaces() {
        let a = surface_with_route("s1", "alpha", "0.0.0.0:8443", "/api");
        let mut disabled = surface_with_route("s2", "beta", "0.0.0.0:8443", "/api");
        disabled.status = SurfaceStatus::Disabled;
        check_access_point_route_collisions(&a, &[disabled], no_ports).expect("disabled surface reserves no route");
    }

    #[test]
    fn ap_route_collision_allows_disabling_a_conflicting_surface() {
        let mut being_disabled = surface_with_route("s1", "alpha", "0.0.0.0:8443", "/api");
        being_disabled.status = SurfaceStatus::Disabled;
        let active_duplicate = surface_with_route("s2", "beta", "0.0.0.0:8443", "/api");
        check_access_point_route_collisions(&being_disabled, &[active_duplicate], no_ports)
            .expect("disabling a surface must pass collision validation");
    }

    #[test]
    fn ap_route_collision_skips_check_when_route_is_empty() {
        let mut a = base_surface();
        a.surface_id = "s1".to_string();
        a.access_point.route = String::new();
        let mut b = base_surface();
        b.surface_id = "s2".to_string();
        b.access_point.route = String::new();
        check_access_point_route_collisions(&a, &[b], no_ports).expect("empty route must short-circuit without error");
    }

    // ── PATCH content-type guard + merge-patch round trip ──────────────

    fn headers_with(ct: Option<&str>) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        if let Some(v) = ct {
            h.insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn require_merge_patch_content_type_accepts_canonical_value() {
        let h = headers_with(Some("application/merge-patch+json"));
        assert!(require_merge_patch_content_type(&h).is_ok());
    }

    #[test]
    fn require_merge_patch_content_type_accepts_case_insensitive() {
        let h = headers_with(Some("Application/Merge-Patch+JSON"));
        assert!(require_merge_patch_content_type(&h).is_ok());
    }

    #[test]
    fn require_merge_patch_content_type_accepts_charset_suffix() {
        let h = headers_with(Some("application/merge-patch+json; charset=utf-8"));
        assert!(require_merge_patch_content_type(&h).is_ok());
    }

    #[test]
    fn require_merge_patch_content_type_rejects_plain_json_with_415() {
        let h = headers_with(Some("application/json"));
        match require_merge_patch_content_type(&h) {
            Err(SurfaceApiError::UnsupportedMediaType(_)) => {}
            other => panic!("expected UnsupportedMediaType, got {other:?}"),
        }
    }

    #[test]
    fn require_merge_patch_content_type_rejects_missing_header_with_415() {
        let h = headers_with(None);
        match require_merge_patch_content_type(&h) {
            Err(SurfaceApiError::UnsupportedMediaType(_)) => {}
            other => panic!("expected UnsupportedMediaType, got {other:?}"),
        }
    }

    /// PATCH semantics: a merge-patch over the existing surface plus a
    /// PUT carrying the post-merge surface body must produce the same
    /// terminal state. This is the equivalence the API promises.
    #[test]
    fn merge_patch_over_surface_is_equivalent_to_put_of_merged_body() {
        let s = base_surface();
        let s_json = serde_json::to_value(&s).unwrap();

        let patch = serde_json::json!({
            "name": "renamed",
            "tags": ["touched"],
            "access_point": {
                "trust_check_list": [
                    {
                        "id": "tc-1",
                        "trust_registry_id": "tr-1",
                        "query_type": "recognition",
                        "query": {
                            "authority_id": "did:web:authority.example",
                            "entity_id": "{{ caller.did }}"
                        }
                    }
                ]
            }
        });

        let mut via_patch = s_json.clone();
        json_patch::merge(&mut via_patch, &patch);
        let via_patch: AgentSurface = serde_json::from_value(via_patch).unwrap();

        let mut via_put = s;
        via_put.name = "renamed".to_string();
        via_put.tags = vec!["touched".to_string()];
        via_put
            .access_point
            .trust_check_list = vec![crate::trust_registry_verification::trust_check_element::TrustCheckElement {
            id: "tc-1".to_string(),
            trust_registry_id: "tr-1".to_string(),
            query_type: crate::trust_registry_verification::trust_check_element::TrqpQueryType::Recognition,
            query: crate::trust_registry_verification::trust_check_element::TrqpQueryParams {
                authority_id: "did:web:authority.example".to_string(),
                entity_id: "{{ caller.did }}".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: None,
        }];

        assert_eq!(
            serde_json::to_value(&via_patch).unwrap(),
            serde_json::to_value(&via_put).unwrap(),
            "PATCH of the diff must produce the same wire shape as PUT of the merged body"
        );
        assert_eq!(via_patch.validate(), Ok(()), "merged surface must pass validate()");
    }

    /// A PATCH that names a key with `null` deletes it.
    #[test]
    fn merge_patch_null_deletes_optional_field() {
        let mut s = base_surface();
        s.description = "to-be-cleared".to_string();
        s.tags = vec!["a".to_string(), "b".to_string()];
        let mut s_json = serde_json::to_value(&s).unwrap();
        json_patch::merge(&mut s_json, &serde_json::json!({ "tags": null }));
        let merged: AgentSurface = serde_json::from_value(s_json).unwrap();
        assert!(merged.tags.is_empty(), "null on tags must clear the list");
    }

    /// A PATCH that produces an invalid trust_check_list must be rejected
    /// by `validate()` — guaranteeing that the handler's validate-or-save
    /// gate would return 400 rather than persisting bad state.
    #[test]
    fn merge_patch_that_violates_trust_check_list_constraints_fails_validate() {
        let s = base_surface();
        let mut s_json = serde_json::to_value(&s).unwrap();
        json_patch::merge(
            &mut s_json,
            &serde_json::json!({
                "access_point": {
                    "trust_check_list": [
                        {
                            "id": "dup",
                            "trust_registry_id": "tr-1",
                            "query_type": "recognition",
                            "query": {
                                "authority_id": "did:web:a.example",
                                "entity_id": "{{ caller.did }}"
                            }
                        },
                        {
                            "id": "dup",
                            "trust_registry_id": "tr-1",
                            "query_type": "recognition",
                            "query": {
                                "authority_id": "did:web:a.example",
                                "entity_id": "{{ caller.did }}"
                            }
                        }
                    ]
                }
            }),
        );
        let merged: AgentSurface = serde_json::from_value(s_json).unwrap();
        match merged.validate() {
            Err(crate::config::agent_surface::TrustCheckValidationError::TrustCheckDuplicateId { leg, id }) => {
                assert_eq!(leg, "caller");
                assert_eq!(id, "dup");
            }
            other => panic!("expected duplicate-id error, got {other:?}"),
        }
    }

    // ── DID Auth source-auth validation on the surface save path ─────────
    //
    // These tests pin the exact scenario the review flagged: `PUT/PATCH
    // /v1/surfaces/...` used to skip the DID Auth invariants that
    // `GatewayConfig::validate` enforces at boot, letting the JSON API
    // persist values that would then blow up on the next process restart.
    // `validate_source_auth` (called from `validate_and_save_surface`) now
    // gates the save on the same helper used at boot time.

    fn didauth_surface(cfg: crate::source_auth::models::DidAuthAuthConfig) -> AgentSurface {
        use crate::config::agent_surface::CallerAuthentication;
        use crate::source_auth::models::SourceAuthConfig;
        let mut s = base_surface();
        s.access_point
            .caller_authentication = Some(CallerAuthentication {
            methods: vec![SourceAuthConfig::DidAuth(cfg)],
        });
        s
    }

    fn valid_didauth_config() -> crate::source_auth::models::DidAuthAuthConfig {
        use crate::source_auth::models::{CredentialExtraction, DidAuthAuthConfig};
        DidAuthAuthConfig {
            extraction: CredentialExtraction::HttpHeader {
                field: "X-Session-Token".into(),
            },
            allowed_dids: vec![],
            challenge_ttl_seconds: None,
            session_ttl_seconds: None,
            audience: None,
            allowed_algorithms: vec![],
        }
    }

    #[test]
    fn source_auth_validation_accepts_defaults() {
        let s = didauth_surface(valid_didauth_config());
        validate_source_auth(&s).expect("defaults must pass");
    }

    #[test]
    fn source_auth_validation_rejects_zero_challenge_ttl() {
        let mut cfg = valid_didauth_config();
        cfg.challenge_ttl_seconds = Some(0);
        let s = didauth_surface(cfg);
        let err = validate_source_auth(&s).expect_err("challenge_ttl_seconds=0 must fail on save");
        match err {
            SurfaceApiError::BadRequest(msg) => assert!(
                msg.contains("challenge_ttl_seconds"),
                "expected error to mention challenge_ttl_seconds, got: {msg}"
            ),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn source_auth_validation_rejects_zero_session_ttl() {
        let mut cfg = valid_didauth_config();
        cfg.session_ttl_seconds = Some(0);
        let s = didauth_surface(cfg);
        let err = validate_source_auth(&s).expect_err("session_ttl_seconds=0 must fail on save");
        assert!(matches!(err, SurfaceApiError::BadRequest(_)));
    }

    #[test]
    fn source_auth_validation_rejects_unsupported_algorithm() {
        let mut cfg = valid_didauth_config();
        cfg.allowed_algorithms = vec!["HS256".into()];
        let s = didauth_surface(cfg);
        let err = validate_source_auth(&s).expect_err("HS256 must fail on save");
        match err {
            SurfaceApiError::BadRequest(msg) => assert!(msg.contains("allowed_algorithms")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn source_auth_validation_rejects_blank_allowed_did() {
        let mut cfg = valid_didauth_config();
        cfg.allowed_dids = vec!["   ".into()];
        let s = didauth_surface(cfg);
        let err = validate_source_auth(&s).expect_err("blank DID must fail on save");
        assert!(matches!(err, SurfaceApiError::BadRequest(_)));
    }

    #[test]
    fn source_auth_validation_rejects_malformed_did() {
        let mut cfg = valid_didauth_config();
        cfg.allowed_dids = vec!["not-a-did".into()];
        let s = didauth_surface(cfg);
        let err = validate_source_auth(&s).expect_err("non-DID string must fail on save");
        assert!(matches!(err, SurfaceApiError::BadRequest(_)));
    }

    #[test]
    fn source_auth_validation_ignores_surfaces_without_caller_auth() {
        // No caller auth → nothing to check; must succeed regardless.
        let s = base_surface();
        validate_source_auth(&s).expect("no caller_auth must pass");
    }

    // Delegated (Model B) A2A + jwt_bearer(Authorization) is unreachable: MPP's
    // A2A credential collides with the Bearer scheme (see `validate_delegation_source_auth`).

    fn delegated_mpp_surface() -> AgentSurface {
        use crate::config::agent_surface::PaymentPolicy;
        use crate::config::types::{DelegatedPaymentRail, X402Config, X402Provider};
        let mut s = base_surface();
        s.access_point.protocol = SurfaceProtocol::A2a;
        s.target.payment_policy = Some(PaymentPolicy::X402(X402Config {
            provider: X402Provider::AgentPay,
            delegated_rail: DelegatedPaymentRail::Mpp,
            payment_gateway_id: Some("gw1".to_string()),
            payment_surface_id: Some("surf1".to_string()),
            ..Default::default()
        }));
        s
    }

    fn jwt_bearer_auth(token_header: &str) -> crate::config::agent_surface::CallerAuthentication {
        use crate::config::agent_surface::CallerAuthentication;
        use crate::jwt_bearer::models::JwtBearerAuthConfig;
        use crate::source_auth::models::SourceAuthConfig;
        CallerAuthentication {
            methods: vec![SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
                token_header: token_header.to_string(),
                ..Default::default()
            })],
        }
    }

    #[test]
    fn delegation_source_auth_rejects_a2a_mpp_delegate_with_jwt_bearer_authorization_header() {
        let mut s = delegated_mpp_surface();
        s.access_point
            .caller_authentication = Some(jwt_bearer_auth("Authorization"));
        let err = validate_delegation_source_auth(&s).expect_err("jwt_bearer on Authorization must fail");
        match err {
            SurfaceApiError::BadRequest(msg) => {
                assert!(msg.contains("jwt_bearer"), "expected mention of jwt_bearer, got: {msg}")
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn delegation_source_auth_accepts_jwt_bearer_on_a_different_header() {
        let mut s = delegated_mpp_surface();
        s.access_point
            .caller_authentication = Some(jwt_bearer_auth("X-Auth-Token"));
        validate_delegation_source_auth(&s).expect("jwt_bearer on a non-Authorization header is fine");
    }

    #[test]
    fn delegation_source_auth_ignores_non_delegated_x402() {
        let mut s = base_surface();
        s.access_point.protocol = SurfaceProtocol::A2a;
        s.access_point
            .caller_authentication = Some(jwt_bearer_auth("Authorization"));
        // Not a delegated MPP config (no payment_policy at all) — must pass.
        validate_delegation_source_auth(&s).expect("no delegated MPP config must pass");
    }

    #[test]
    fn delegation_source_auth_ignores_mcp_delegated_mpp_with_jwt_bearer() {
        let mut s = delegated_mpp_surface();
        s.access_point.protocol = SurfaceProtocol::Mcp;
        s.access_point
            .caller_authentication = Some(jwt_bearer_auth("Authorization"));
        // MPP-over-MCP carries its credential in the `_meta` body, not a header — unaffected.
        validate_delegation_source_auth(&s).expect("MCP delegated MPP is unaffected by header collision");
    }
}

#[cfg(test)]
mod tenancy_tests {
    use super::*;

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: id.into(),
        }
    }

    fn scope(pattern: &str) -> PatResourceScope {
        PatResourceScope(std::sync::Arc::new(regex::Regex::new(pattern).unwrap()))
    }

    #[test]
    fn a_tenant_cannot_write_an_operators_surface_it_can_read() {
        let tenant = tenant("tenant-a");
        let open = scope(r"\ATENANT:tenant-a:surfaces:.*\z");
        assert!(can_access(None, Some(&tenant)), "reading stays allowed");
        assert!(!surface_writable(None, "operator-surface", Some(&tenant), Some(&open)));
    }

    #[test]
    fn a_tenant_writes_only_its_own_surfaces_inside_its_scope() {
        let tenant = tenant("tenant-a");
        let prefixed = scope(r"\ATENANT:tenant-a:surfaces:boris-.*\z");
        assert!(surface_writable(Some("tenant-a"), "boris-s1", Some(&tenant), Some(&prefixed)));
        assert!(!surface_writable(Some("tenant-a"), "other-s1", Some(&tenant), Some(&prefixed)));
        assert!(!surface_writable(Some("tenant-b"), "boris-s1", Some(&tenant), Some(&prefixed)));
    }

    #[test]
    fn an_appliance_wide_caller_writes_any_surface() {
        assert!(surface_writable(None, "operator-surface", None, None));
        assert!(surface_writable(Some("tenant-a"), "boris-s1", None, None));
    }
}
