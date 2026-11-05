//! CRUD API handlers for Agent Surfaces

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{debug, error, info, warn};

use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatContext, PatDelegationContext, PatResourceScope};
use crate::config::agent_surface::{AccessPointStatus, AgentSurface, SharedTransitConfig, TransitConfig};
use crate::identity::state::IdentityApiState;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};
use crate::trust_registry_verification::recorder_status::{RecorderStatus, global_store};

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

/// Whether the caller's token carries a resource scope of any kind, including
/// one made of required headers alone, which yields neither a tenant nor a
/// [`PatResourceScope`].
/// The management caller a surface change is audited under: the console user,
/// and the access token when the request came with one.
fn management_actor(
    caller: &Option<Extension<AuthGuardOk>>,
    delegation: &Option<Extension<PatDelegationContext>>,
) -> Option<crate::delegation_vault::audit::AuditCallerContext> {
    crate::delegation_vault::audit::management_caller_context(
        caller
            .as_ref()
            .map(|Extension(AuthGuardOk(user_id))| user_id.as_str()),
        delegation
            .as_ref()
            .map(|Extension(delegation)| delegation.token_id.as_str()),
    )
}

fn resource_scoped(delegation: &Option<Extension<PatDelegationContext>>) -> bool {
    delegation
        .as_ref()
        .is_some_and(|Extension(delegation)| delegation.resource_scoped)
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

pub(crate) const INBOUND_API_KEY_NEEDS_API_KEY_CALLER: &str =
    "Identity 'From API Key' needs every Caller Context method to be API Key or API Key Provider";
pub(crate) const INBOUND_API_KEY_WITH_RESOURCE_TOKENS: &str = "Identity 'From API Key' cannot be used with \
     mcp_http.authorization, which identifies callers by their resource token; remove one of them";
pub(crate) const INBOUND_API_KEY_ON_MCP_PROXY: &str =
    "Identity 'From API Key' is not supported on a proxy:// MCP Proxy target; choose another inbound Identity mode";
pub(crate) const API_KEY_IDENTITY_NEEDS_ID: &str = "Identity 'From API Key' needs a non-empty api_key_id";

/// The inbound slot identifies each caller by the key it presents, so a stored
/// `api_key_id` there is never read. Variants replace `identity_slots`
/// wholesale, so every variant override is cleared too, enabled or not.
pub(crate) fn drop_inbound_api_key_ids(surface: &mut AgentSurface) {
    let variant_slots = surface
        .variants
        .iter_mut()
        .filter_map(|variant| {
            variant
                .overrides
                .identity_slots
                .as_mut()
        });
    for slots in std::iter::once(&mut surface.identity_slots).chain(variant_slots) {
        if let Some(crate::source_auth::ManagedIdentityConfig::FromApiKey { api_key_id }) = slots.inbound.as_mut() {
            *api_key_id = None;
        }
    }
}

fn configured_api_key_id<'a>(
    identity: Option<&'a crate::source_auth::ManagedIdentityConfig>,
    slot: &str,
) -> Result<Option<&'a str>, String> {
    match identity {
        Some(crate::source_auth::ManagedIdentityConfig::FromApiKey { api_key_id }) => api_key_id
            .as_deref()
            .filter(|id| !id.trim().is_empty())
            .map(Some)
            .ok_or_else(|| format!("{slot}: {API_KEY_IDENTITY_NEEDS_ID}")),
        _ => Ok(None),
    }
}

/// Refuse `from_api_key` identities the request path cannot resolve: an
/// inbound slot on a surface with a caller method other than an API key, whose
/// callers it could not identify, and a stored slot without a key.
fn validate_api_key_identities(
    surface: &AgentSurface,
    label: &str,
) -> Result<(), SurfaceApiError> {
    use crate::source_auth::SourceAuthConfig;

    let refuse = |message: &str| {
        let prefix = if label.is_empty() {
            String::new()
        } else {
            format!("{label}: ")
        };
        SurfaceApiError::BadRequest(format!("{prefix}{message}"))
    };
    let inbound_from_api_key = surface.inbound_identity_from_api_key();
    if inbound_from_api_key {
        let methods = surface.source_auth_methods();
        if methods.is_empty()
            || !methods
                .iter()
                .all(|method| matches!(method, SourceAuthConfig::ApiKey(_) | SourceAuthConfig::ApiKeyProvider(_)))
        {
            return Err(refuse(INBOUND_API_KEY_NEEDS_API_KEY_CALLER));
        }
        if surface
            .mcp_http
            .as_ref()
            .is_some_and(|http| http.authorization.is_some())
        {
            return Err(refuse(INBOUND_API_KEY_WITH_RESOURCE_TOKENS));
        }
        if surface.channel_protocol() == crate::config::ChannelProtocol::Mcp
            && surface
                .target
                .endpoint
                .starts_with("proxy://")
        {
            return Err(refuse(INBOUND_API_KEY_ON_MCP_PROXY));
        }
    }

    let protected = surface.managed_identity();
    configured_api_key_id(protected.as_ref(), "identity_slots.protected").map_err(|message| refuse(&message))?;
    for point in surface
        .transit
        .iter()
        .flat_map(|transit| transit.points.iter())
    {
        let slot = format!("transit.points['{}'].managed_identity", point.alias);
        configured_api_key_id(
            point
                .managed_identity
                .as_ref(),
            &slot,
        )
        .map_err(|message| refuse(&message))?;
    }
    configured_api_key_id(surface.external_identity(), "identity_slots.external")
        .map_err(|message| refuse(&message))?;
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
        validate_api_key_identities(&resolved, &label)?;

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

/// Reject a non-empty `target.trust_check_list` unless the Managed Agent
/// target runs it on its own target leg (`a2a-proxy://` and `fabric://`): the
/// base list against the base target, and a list a variant sets in its own
/// override (enabled or not) against that variant's target. A base list a
/// variant only inherits is not checked against the variant, since it never
/// runs there. Transit Point traffic runs each Transit Point's own list.
fn reject_target_trust_checks_unless_target_runs_them(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    let offending = |target: &crate::config::agent_surface::Target| {
        !target
            .trust_check_list
            .is_empty()
            && !target.runs_own_trust_checks()
    };
    let message = |label: &str| {
        SurfaceApiError::BadRequest(format!(
            "{label}target.trust_check_list is only allowed for a2a-proxy:// and fabric:// Managed Agent targets; \
             configure target-leg Trust Checks per Transit Point in transit.points[].trust_check_list"
        ))
    };
    if offending(&surface.target) {
        return Err(message(""));
    }
    for variant in &surface.variants {
        let sets_own_list = variant
            .overrides
            .target
            .as_ref()
            .and_then(|target| {
                target
                    .trust_check_list
                    .as_ref()
            })
            .is_some_and(|list| !list.is_empty());
        if sets_own_list && offending(&surface.variant_target(variant)) {
            return Err(message(&format!("Variant '{}': ", variant.alias)));
        }
    }
    Ok(())
}

/// Convert a full surface body written in the old shape, where
/// `target.trust_check_list` ran for every Transit Point, the way a stored
/// surface is converted on load: the list is copied onto the Transit Points
/// and cleared unless the Managed Agent target runs it. Only the Trust Check
/// parts of the conversion are taken, so every other field keeps exactly what
/// the client sent. A body declaring `trust_check_split: true`, without a
/// target list, or already carrying Transit Point lists (which the old shape
/// cannot express) is left as sent. The conversion is logged only when it
/// changed something.
fn convert_old_shape_body(surface: &mut AgentSurface) -> Result<(), SurfaceApiError> {
    if surface.trust_check_split || !surface.has_target_trust_checks() || surface.has_transit_point_trust_checks() {
        return Ok(());
    }
    let mut value = serde_json::to_value(&*surface)
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to serialise surface: {}", e)))?;
    let sent = value.clone();
    if !crate::config::agent_surface::split_target_trust_checks_per_transit_point(&mut value) {
        return Ok(());
    }
    if let Some(obj) = value.as_object_mut() {
        obj.remove("trust_check_split");
    }
    if value == sent {
        return Ok(());
    }
    let converted: AgentSurface = serde_json::from_value(value)
        .map_err(|e| SurfaceApiError::BadRequest(format!("Converted surface is invalid: {}", e)))?;
    surface
        .target
        .trust_check_list = converted
        .target
        .trust_check_list;
    surface.transit = converted.transit;
    for (variant, converted) in surface
        .variants
        .iter_mut()
        .zip(converted.variants)
    {
        variant.overrides.transit = converted.overrides.transit;
        if let (Some(target), Some(converted)) = (
            variant
                .overrides
                .target
                .as_mut(),
            converted.overrides.target,
        ) {
            target.trust_check_list = converted.trust_check_list;
        }
    }
    let migrated = |points: &[crate::config::agent_surface::TransitPoint]| {
        points
            .iter()
            .filter(|point| point.trust_check_migrated)
            .map(|point| point.alias.clone())
            .collect::<Vec<_>>()
    };
    let mut aliases = surface
        .transit
        .as_ref()
        .map(|transit| migrated(&transit.points))
        .unwrap_or_default();
    for variant in &surface.variants {
        if let Some(points) = variant
            .overrides
            .transit
            .as_ref()
            .and_then(|transit| transit.points.as_deref())
        {
            aliases.extend(migrated(points));
        }
    }
    warn!(
        surface_id = %surface.surface_id,
        transit_points = ?aliases,
        "converted a surface write without trust_check_split: copied target.trust_check_list onto its \
         Transit Points"
    );
    Ok(())
}

/// A JSON request body as `T`, rejected exactly as [`Json<T>`] would reject
/// it, together with the JSON the client sent, so a handler can tell an absent
/// field from an empty one.
pub struct JsonWithSent<T>(T, serde_json::Value);

impl<S, T> axum::extract::FromRequest<S> for JsonWithSent<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let headers = request.headers().clone();
        let mut bytes = axum::body::Bytes::from_request(request, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let mut sent = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        if drop_access_point_status(&mut sent) {
            bytes = serde_json::to_vec(&sent)
                .map_err(|error| SurfaceApiError::InternalError(error.to_string()).into_response())?
                .into();
        }
        let mut typed = axum::extract::Request::new(axum::body::Body::from(bytes));
        *typed.headers_mut() = headers;
        let Json(value) = Json::<T>::from_request(typed, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self(value, sent))
    }
}

/// Removes the read-only `access_point_status` of a [`SurfaceResponse`] from
/// a write body, so a client can send back what a read or a save returned.
/// Whether it was there.
fn drop_access_point_status(body: &mut serde_json::Value) -> bool {
    body.as_object_mut()
        .is_some_and(|body| {
            body.remove("access_point_status")
                .is_some()
        })
}

const PER_TRANSIT_POINT_REQUIRED: &str = "this surface uses the per-Transit-Point Trust Check shape; send \
                                          trust_check_split: true to change its Trust Check lists \
                                          (transit.points[].trust_check_list, target.trust_check_list)";

/// Settle a PUT without `trust_check_split: true` on a surface whose stored
/// Transit Points already hold lists (base or variant override points). Such a
/// body is never converted. `sent` is the request JSON as the client sent it,
/// so an absent field can be told from an empty one.
///
/// - Each incoming Transit Point sent without a list (matched by `id` when the
///   client sent one, otherwise by `alias`; a variant's own points against the
///   same stored variant's, by variant `id`) keeps the stored list and its
///   `trust_check_migrated` flag as stored; a list that differs from the
///   stored one is refused.
/// - A base `target.trust_check_list` (or a variant override's) that is absent
///   or `null` keeps the stored one; a sent list, empty included, that differs
///   from the stored one is refused.
/// - A variant sent without its own Transit Points while the stored variant's
///   own Transit Points hold lists is refused, since dropping them would drop
///   their lists.
///
/// A client in the old shape cannot express per-Transit-Point lists, so it
/// keeps them; only a declared write changes or removes them.
fn keep_stored_point_lists(
    surface: &mut AgentSurface,
    stored: &AgentSurface,
    sent: &serde_json::Value,
) -> Result<(), SurfaceApiError> {
    use crate::config::agent_surface::TransitPoint;
    let refused = || SurfaceApiError::BadRequest(PER_TRANSIT_POINT_REQUIRED.to_string());
    let sends = |value: Option<&serde_json::Value>| value.is_some_and(|value| !value.is_null());
    fn keep(
        points: &mut [TransitPoint],
        stored_points: &[TransitPoint],
        sent_points: Option<&Vec<serde_json::Value>>,
    ) -> bool {
        for (index, point) in points.iter_mut().enumerate() {
            let sent_id = sent_points
                .and_then(|sent| sent.get(index))
                .and_then(|sent| sent.get("id"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| !id.is_empty());
            let stored_point = if sent_id {
                stored_points
                    .iter()
                    .find(|stored| stored.id == point.id)
            } else {
                stored_points
                    .iter()
                    .find(|stored| stored.alias == point.alias)
            };
            if point
                .trust_check_list
                .is_empty()
            {
                if let Some(stored_point) = stored_point {
                    point.trust_check_list = stored_point
                        .trust_check_list
                        .clone();
                    point.trust_check_migrated = stored_point.trust_check_migrated;
                }
            } else if stored_point.is_none_or(|stored| stored.trust_check_list != point.trust_check_list) {
                return false;
            }
        }
        true
    }

    if !sends(sent.pointer("/target/trust_check_list")) {
        surface
            .target
            .trust_check_list = stored
            .target
            .trust_check_list
            .clone();
    } else if surface
        .target
        .trust_check_list
        != stored.target.trust_check_list
    {
        return Err(refused());
    }
    let stored_base_points = stored
        .transit
        .as_ref()
        .map(|transit| transit.points.as_slice())
        .unwrap_or_default();
    fn sent_points(value: Option<&serde_json::Value>) -> Option<&Vec<serde_json::Value>> {
        value.and_then(serde_json::Value::as_array)
    }
    if let Some(transit) = surface.transit.as_mut()
        && !keep(&mut transit.points, stored_base_points, sent_points(sent.pointer("/transit/points")))
    {
        return Err(refused());
    }

    let sent_variants = sent
        .get("variants")
        .and_then(serde_json::Value::as_array);
    for (index, variant) in surface
        .variants
        .iter_mut()
        .enumerate()
    {
        let stored_variant = stored
            .variants
            .iter()
            .find(|stored| stored.id == variant.id);
        let stored_target_list = stored_variant
            .and_then(|stored| {
                stored
                    .overrides
                    .target
                    .as_ref()
            })
            .and_then(|target| {
                target
                    .trust_check_list
                    .clone()
            });
        let sent_list = sent_variants
            .and_then(|variants| variants.get(index))
            .and_then(|variant| variant.pointer("/overrides/target/trust_check_list"));
        if !sends(sent_list) {
            if let Some(list) = stored_target_list {
                variant
                    .overrides
                    .target
                    .get_or_insert_with(Default::default)
                    .trust_check_list = Some(list);
            }
        } else {
            let list = variant
                .overrides
                .target
                .as_ref()
                .and_then(|target| {
                    target
                        .trust_check_list
                        .clone()
                })
                .unwrap_or_default();
            if list != stored_target_list.unwrap_or_default() {
                return Err(refused());
            }
        }
        let stored_points = stored_variant
            .and_then(|stored| {
                stored
                    .overrides
                    .transit
                    .as_ref()
            })
            .and_then(|transit| transit.points.as_deref())
            .unwrap_or_default();
        let sends_points = variant
            .overrides
            .transit
            .as_ref()
            .is_some_and(|transit| transit.points.is_some());
        if !sends_points
            && stored_points
                .iter()
                .any(|point| {
                    !point
                        .trust_check_list
                        .is_empty()
                })
        {
            return Err(refused());
        }
        if let Some(points) = variant
            .overrides
            .transit
            .as_mut()
            .and_then(|transit| transit.points.as_mut())
            && !keep(
                points,
                stored_points,
                sent_points(
                    sent_variants
                        .and_then(|variants| variants.get(index))
                        .and_then(|variant| variant.pointer("/overrides/transit/points")),
                ),
            )
        {
            return Err(refused());
        }
    }
    Ok(())
}

/// Settle the Trust Check lists of a PUT body. A body declaring
/// `trust_check_split: true` is taken as sent. Otherwise a stored surface with
/// no Trust Check lists (no stored marker and no Transit Point lists) is
/// unsplit and the body is converted with [`convert_old_shape_body`]; an
/// already split one goes through [`keep_stored_point_lists`].
fn settle_undeclared_put(
    surface: &mut AgentSurface,
    stored: &AgentSurface,
    sent: &serde_json::Value,
) -> Result<(), SurfaceApiError> {
    if surface.trust_check_split {
        return Ok(());
    }
    if stored.trust_check_split || stored.has_transit_point_trust_checks() {
        keep_stored_point_lists(surface, stored, sent)
    } else {
        convert_old_shape_body(surface)
    }
}

/// Reject a partial write without `trust_check_split: true` that touches
/// `target.trust_check_list` or `transit.points` (base or variant override)
/// while the stored surface keeps Trust Checks on its Transit Points: a
/// client in the old shape cannot edit them without losing them.
fn reject_undeclared_trust_check_edit(
    touches_trust_checks: bool,
    stored: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    if touches_trust_checks && stored.has_transit_point_trust_checks() {
        return Err(SurfaceApiError::BadRequest(PER_TRANSIT_POINT_REQUIRED.to_string()));
    }
    Ok(())
}

/// Whether a merge patch reaches `path`: it sets the path itself, or sets
/// one of its ancestors to `null`, which removes everything below it.
fn patch_reaches(
    patch: &serde_json::Value,
    path: &[&str],
) -> bool {
    let mut current = patch;
    for key in path {
        match current.get(key) {
            None => return false,
            Some(serde_json::Value::Null) => return true,
            Some(next) => current = next,
        }
    }
    true
}

/// Whether a surface merge patch touches `target.trust_check_list` or
/// `transit.points`, on the base or in a variant override, including through a
/// `null` ancestor. Replacing the `variants` array touches them whenever a
/// stored variant override holds Transit Point lists.
fn patch_touches_trust_checks(
    patch: &serde_json::Value,
    stored: &AgentSurface,
) -> bool {
    let stored_variant_lists = stored
        .variants
        .iter()
        .any(variant_holds_transit_point_lists);
    patch_reaches(patch, &["target", "trust_check_list"])
        || patch_reaches(patch, &["transit", "points"])
        || match patch.get("variants") {
            None => false,
            Some(serde_json::Value::Array(variants)) => {
                stored_variant_lists
                    || variants
                        .iter()
                        .any(variant_patch_touches_trust_checks)
            }
            Some(_) => stored_variant_lists,
        }
}

/// Whether a variant merge patch touches `overrides.target.trust_check_list`
/// or `overrides.transit.points`, including through a `null` ancestor.
fn variant_patch_touches_trust_checks(variant: &serde_json::Value) -> bool {
    patch_reaches(variant, &["overrides", "target", "trust_check_list"])
        || patch_reaches(variant, &["overrides", "transit", "points"])
}

fn variant_holds_transit_point_lists(variant: &crate::config::agent_surface_variants::SurfaceVariant) -> bool {
    variant
        .overrides
        .transit
        .as_ref()
        .and_then(|transit| transit.points.as_deref())
        .is_some_and(|points| {
            points.iter().any(|point| {
                !point
                    .trust_check_list
                    .is_empty()
            })
        })
}

/// Whether a write body declares the per-Transit-Point shape with
/// `trust_check_split: true`.
fn declares_split(body: &serde_json::Value) -> bool {
    body.get("trust_check_split") == Some(&serde_json::Value::Bool(true))
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
///
/// Each enabled variant is validated as resolved, against the stored variant
/// of the same alias, since it can override the caller authentication methods
/// and the identity slots.
fn validate_source_auth(
    surface: &AgentSurface,
    stored: Option<&AgentSurface>,
) -> Result<(), SurfaceApiError> {
    crate::config::validate_source_auth_config(surface, stored)
        .map_err(|e| SurfaceApiError::BadRequest(e.to_string()))?;
    for variant in &surface.variants {
        let Ok(resolved) = surface.resolve_variant(Some(&variant.alias)) else {
            continue;
        };
        let stored_resolved = stored.and_then(|stored| {
            stored
                .resolve_variant(Some(&variant.alias))
                .ok()
        });
        crate::config::validate_source_auth_config(&resolved, stored_resolved.as_ref())
            .map_err(|e| SurfaceApiError::BadRequest(format!("variant '{}': {e}", variant.alias)))?;
    }
    Ok(())
}

/// Validate every transit point: alias must match the URL-safe pattern,
/// be non-empty, and be unique within the surface. Also assigns a fresh
/// UUID `id` to any TP that was sent without one so older payloads keep
/// working without forcing the dashboard to mint IDs client-side. A
/// `transit.source_auth`, which the gateway does not enforce, is refused, and
/// so is a transit token lifetime outside its bounds, unless it is the stored
/// one (`stored`): a save that keeps it, such as a dashboard round trip, is
/// accepted, and the gateway holds it to the nearer bound. So is a Transit
/// Point, on the surface or in a variant's overrides, whose caller
/// authentication cannot be enforced. `transit_token_mode: reference`, on the
/// surface or in a variant's overrides, is refused; a stored one is rewritten to
/// `embedded` when the surface loads, so none reaches this check.
fn validate_transit_points(
    surface: &mut AgentSurface,
    max_lifetime_secs: u64,
    stored: Option<&AgentSurface>,
) -> Result<(), SurfaceApiError> {
    let stored_lifetime_secs = stored
        .and_then(|stored| stored.transit.as_ref())
        .and_then(|transit| {
            transit
                .shared
                .transit_token_lifetime_secs
        });
    let surface_sets_source_auth = surface
        .transit
        .as_ref()
        .is_some_and(|transit| {
            transit
                .shared
                .source_auth
                .is_some()
        });
    let variant_sets_source_auth = surface
        .variants
        .iter()
        .any(|variant| {
            variant
                .overrides
                .transit
                .as_ref()
                .and_then(|transit| transit.shared.as_ref())
                .is_some_and(|shared| shared.source_auth.is_some())
        });
    if surface_sets_source_auth || variant_sets_source_auth {
        return Err(SurfaceApiError::BadRequest(crate::config::agent_surface::TRANSIT_SOURCE_AUTH_REFUSED.to_string()));
    }
    refuse_reference_transit_tokens(surface)?;
    validate_transit_point_caller_authentication(surface, stored)?;
    refuse_duplicate_transit_point_ids(surface)?;
    for variant in &mut surface.variants {
        if let Some(points) = variant
            .overrides
            .transit
            .as_mut()
            .and_then(|transit| transit.points.as_mut())
        {
            identify_transit_points(points, &format!("variant '{}' ", variant.alias))?;
        }
    }
    let Some(transit) = surface.transit.as_mut() else {
        return Ok(());
    };
    let kept = transit
        .shared
        .transit_token_lifetime_secs
        .is_some_and(|secs| Some(secs) == stored_lifetime_secs);
    if !kept {
        transit
            .shared
            .validate_transit_token_lifetime(max_lifetime_secs)
            .map_err(SurfaceApiError::BadRequest)?;
    }
    identify_transit_points(&mut transit.points, "")
}

/// Give each Transit Point of one list, the surface's or a variant's (named by
/// `place`), an id when it has none, and refuse an alias that is not URL-safe
/// or that another point of the list has.
fn identify_transit_points(
    points: &mut [crate::config::agent_surface::TransitPoint],
    place: &str,
) -> Result<(), SurfaceApiError> {
    let mut seen = std::collections::HashSet::with_capacity(points.len());
    for (idx, tp) in points.iter_mut().enumerate() {
        if tp.id.is_empty() {
            tp.id = uuid::Uuid::new_v4().to_string();
        }
        if let Err(msg) = crate::config::agent_surface::TransitPoint::validate_alias(&tp.alias) {
            return Err(SurfaceApiError::BadRequest(format!("{place}transit.points[{idx}]: {msg}")));
        }
        if let Err(msg) = tp.validate_per_caller_rate_limit() {
            return Err(SurfaceApiError::BadRequest(format!("{place}transit.points[{idx}]: {msg}")));
        }
        if let Some(limit) = &tp.per_caller_rate_limit
            && let Err(error) = crate::policies::CallerRateLimiter::new(&limit.into(), tp.alias.as_str())
        {
            return Err(SurfaceApiError::BadRequest(format!(
                "{place}transit.points[{idx}]: per_caller_rate_limit cannot be enforced: {error}"
            )));
        }
        if !seen.insert(tp.alias.clone()) {
            return Err(SurfaceApiError::BadRequest(format!(
                "{place}transit.points[{idx}]: duplicate alias '{}'. Each transit point alias must be unique within \
                 the surface.",
                tp.alias
            )));
        }
    }
    Ok(())
}

/// Refuse `transit_token_mode: reference`, set on the surface or in a variant's
/// overrides: the gateway only issues embedded tokens.
fn refuse_reference_transit_tokens(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    use crate::config::agent_surface::{TRANSIT_TOKEN_REFERENCE_REFUSED, TransitTokenMode};
    if surface
        .transit
        .as_ref()
        .is_some_and(|transit| {
            transit
                .shared
                .transit_token_mode
                == TransitTokenMode::Reference
        })
    {
        return Err(SurfaceApiError::BadRequest(TRANSIT_TOKEN_REFERENCE_REFUSED.to_string()));
    }
    for variant in &surface.variants {
        let asks = variant
            .overrides
            .transit
            .as_ref()
            .and_then(|transit| transit.shared.as_ref())
            .is_some_and(|shared| shared.transit_token_mode == Some(TransitTokenMode::Reference));
        if asks {
            return Err(SurfaceApiError::BadRequest(format!(
                "variant '{}' {}",
                variant.alias, TRANSIT_TOKEN_REFERENCE_REFUSED
            )));
        }
    }
    Ok(())
}

/// Refuse two Transit Points with one `id`, on the surface or in a variant's overrides (whose
/// points replace the surface's). The id names a leg when a save keeps what the stored leg
/// already had, so it must name one point only.
fn refuse_duplicate_transit_point_ids(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    let base = surface
        .transit
        .as_ref()
        .map(|transit| (String::new(), transit.points.as_slice()));
    let variants = surface
        .variants
        .iter()
        .filter_map(|variant| {
            let points = variant
                .overrides
                .transit
                .as_ref()?
                .points
                .as_deref()?;
            Some((format!("variants['{}'].", variant.alias), points))
        });
    for (prefix, points) in base
        .into_iter()
        .chain(variants)
    {
        let mut seen = std::collections::HashSet::with_capacity(points.len());
        for (idx, point) in points.iter().enumerate() {
            if !point.id.is_empty() && !seen.insert(point.id.as_str()) {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{prefix}transit.points[{idx}]: duplicate id '{}'. Each transit point id must be unique within the surface.",
                    point.id
                )));
            }
        }
    }
    Ok(())
}

/// Refuse a Transit Point, on the surface or in a variant's overrides, whose
/// caller authentication cannot be enforced or whose `source_auth` is invalid.
/// A Transit Point the save leaves exactly as `stored` has it is not refused
/// for authenticating no caller, so a surface stored before that was refused
/// can still be saved; the gateway keeps answering `503` for it until it is
/// given caller authentication or marked open.
fn validate_transit_point_caller_authentication(
    surface: &AgentSurface,
    stored: Option<&AgentSurface>,
) -> Result<(), SurfaceApiError> {
    let unchanged = |point: &crate::config::agent_surface::TransitPoint,
                     stored_points: Option<&[crate::config::agent_surface::TransitPoint]>| {
        !point.id.is_empty()
            && stored_points
                .into_iter()
                .flatten()
                .any(|previous| {
                    previous.id == point.id && serde_json::to_value(previous).ok() == serde_json::to_value(point).ok()
                })
    };
    let surface_points = surface
        .transit
        .iter()
        .flat_map(|transit| {
            let stored_points = stored
                .and_then(|stored| stored.transit.as_ref())
                .map(|transit| transit.points.as_slice());
            transit
                .points
                .iter()
                .enumerate()
                .map(move |(idx, tp)| (format!("transit.points[{idx}]"), tp, stored_points))
        });
    let variant_points = surface
        .variants
        .iter()
        .flat_map(|variant| {
            let stored_points = stored.and_then(|stored| variant_stored_points(stored, &variant.id));
            variant
                .overrides
                .transit
                .iter()
                .filter_map(|transit| transit.points.as_ref())
                .flatten()
                .enumerate()
                .map(move |(idx, tp)| (format!("variant '{}' transit.points[{idx}]", variant.alias), tp, stored_points))
        });
    for (path, tp, stored_points) in surface_points.chain(variant_points) {
        if !unchanged(tp, stored_points) {
            tp.validate_caller_authentication()
                .map_err(|error| SurfaceApiError::BadRequest(format!("{path}: {error}")))?;
        }
        if let Some(source_auth) = &tp.source_auth {
            let stored_source_auth = stored_points
                .into_iter()
                .flatten()
                .find(|previous| !tp.id.is_empty() && previous.id == tp.id)
                .and_then(|previous| previous.source_auth.as_ref());
            crate::config::validate_source_auth_method(source_auth, stored_source_auth, &surface.name)
                .map_err(|error| SurfaceApiError::BadRequest(format!("{path}: {error}")))?;
        }
    }
    Ok(())
}

/// A saved surface, with the [`save_warnings`] it calls for.
type SavedSurface = (axum::http::HeaderMap, Json<SurfaceResponse<AgentSurface>>);

/// The `Warning` headers (code 299) a save of `surface` answers with: its
/// Access Point's ([`AgentSurface::access_point_warnings`]), then one naming
/// each Transit Point that serves callers it does not authenticate where other hosts reach it, each
/// that accepts the Access Point's own tokens ([`shared_audience_warnings`]),
/// each whose JWT verification strategy names an issuer the surface also
/// accepts through another ([`shared_issuer_warnings`]), each whose stored
/// principal claim names no caller ([`unusable_principal_claim_warnings`]),
/// each to a peer
/// gateway that does not require the transit token ([`fabric_hop_limit_warnings`]),
/// each that opts Fabric callers in to delegated credentials without a
/// managed identity ([`fabric_delegation_identity_warnings`]), each that
/// does so where the surface cannot tell a partner's users apart
/// ([`fabric_caller_delegation_warnings`]), and each with external consent
/// that a variant keeps under its own settings
/// ([`inherited_external_point_warnings`]), as the Access Point Target's
/// binding with external consent ([`inherited_target_binding_warnings`]),
/// each enabled view that reaches that binding's vendor without it or a
/// credential of its own ([`unbound_vendor_view_warnings`]), and each Target
/// authentication that breaks a `target_https` or `target_source_auth` rule in `warn`.
async fn save_warnings(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> axum::http::HeaderMap {
    let issuers = jwt_strategy_issuers(state, surface).await;
    let https_proxies = super::surface_target_auth::https_mcp_proxies(state).await;
    let mut headers = axum::http::HeaderMap::new();
    for warning in surface
        .access_point_warnings()
        .into_iter()
        .chain(
            crate::proxy::server::open_transit_points(&state.network_config, surface)
                .iter()
                .filter_map(crate::proxy::server::OpenTransitPoint::exposure),
        )
        .chain(shared_audience_warnings(surface))
        .chain(shared_issuer_warnings(surface, &issuers))
        .chain(unusable_principal_claim_warnings(surface, &issuers))
        .chain(modern_delegation_warnings(surface))
        .chain(fabric_hop_limit_warnings(surface))
        .chain(fabric_delegation_identity_warnings(surface))
        .chain(fabric_caller_delegation_warnings(surface, &issuers))
        .chain(inherited_external_point_warnings(surface))
        .chain(inherited_target_binding_warnings(surface))
        .chain(unbound_vendor_view_warnings(surface))
        .chain(super::surface_target_auth::target_rule_warnings(surface, &https_proxies))
    {
        if let Some(value) = warning_header(&warning) {
            headers.append(axum::http::header::WARNING, value);
        }
    }
    headers
}

/// A `Warning` header (code 299) carrying `warning`.
pub(crate) fn warning_header(warning: &str) -> Option<axum::http::HeaderValue> {
    let quoted = warning
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    axum::http::HeaderValue::from_str(&format!("299 - \"{quoted}\"")).ok()
}

/// Each MCP Transit Point, on the surface or in a variant, that authenticates
/// its callers with `source_auth` on a surface whose outbound credentials apply
/// to every request. A `2026-07-28` MCP request keys a delegated grant only
/// through `mcp_http.authorization`, which such a Transit Point cannot set, so
/// every such request to it is refused with `403`.
fn modern_delegation_warnings(surface: &AgentSurface) -> Vec<String> {
    if !crate::proxy::credential_delegation::modern::transit_point_bindings_apply(surface) {
        return Vec::new();
    }
    let mut warnings = Vec::new();
    for (_, view) in surface_views(surface) {
        for point in view
            .transit
            .iter()
            .flat_map(|transit| transit.points.iter())
            .filter(|point| {
                point.protocol == crate::config::agent_surface::TransitProtocol::Mcp && point.source_auth.is_some()
            })
        {
            let warning = format!(
                "Transit Point '{}' authenticates its callers with source_auth on a surface whose outbound \
                 credentials apply to every request: every 2026-07-28 MCP request to it is refused with 403, \
                 because only mcp_http.authorization can key a delegated grant there",
                point.alias
            );
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    warnings
}

/// `surface` and each of its enabled variants as it resolves, with the
/// variant's alias.
fn surface_views(surface: &AgentSurface) -> Vec<(Option<String>, AgentSurface)> {
    std::iter::once((None, surface.clone()))
        .chain(
            surface
                .variants
                .iter()
                .filter_map(|variant| {
                    surface
                        .resolve_variant(Some(&variant.alias))
                        .ok()
                        .map(|view| (Some(variant.alias.clone()), view))
                }),
        )
        .collect()
}

/// How a warning names the Transit Point `alias` of the view `variant`: with
/// the variant when that variant's overrides define its Transit Points, as
/// [`crate::proxy::server::OpenTransitPoint::exposure`] does, and as the
/// surface's own when the view inherits them.
fn transit_point_name(
    surface: &AgentSurface,
    variant: Option<&str>,
    alias: &str,
) -> String {
    let defined_by = variant.filter(|variant| {
        surface
            .variants
            .iter()
            .any(|candidate| {
                candidate.alias == *variant
                    && candidate
                        .overrides
                        .transit
                        .as_ref()
                        .is_some_and(|transit| transit.points.is_some())
            })
    });
    match defined_by {
        Some(variant) => format!("'{alias}' in variant '{variant}'"),
        None => format!("'{alias}'"),
    }
}

/// The `jwt_bearer` configurations a view's Access Point accepts, and those of
/// its Transit Points with each Transit Point's alias. An Access Point that
/// publishes protected resource metadata accepts only the resource of the
/// route called (`alias`) as the audience, as at runtime.
fn jwt_bearer_methods(
    view: &AgentSurface,
    alias: Option<&str>,
) -> (Vec<crate::jwt_bearer::models::JwtBearerAuthConfig>, Vec<(String, crate::jwt_bearer::models::JwtBearerAuthConfig)>)
{
    use crate::source_auth::SourceAuthConfig;
    let jwt = |config: &SourceAuthConfig| match config {
        SourceAuthConfig::JwtBearer(config) => Some(config.clone()),
        _ => None,
    };
    let protected_resource = view
        .protected_resource()
        .and_then(|protected| {
            protected
                .for_variant(alias)
                .ok()
        });
    let access_point = view
        .access_point
        .caller_authentication
        .iter()
        .flat_map(|authentication| authentication.methods.iter())
        .map(|method| match &protected_resource {
            Some(protected) => protected.bind_audience(method.clone()),
            None => method.clone(),
        })
        .filter_map(|method| jwt(&method))
        .collect();
    let transit_points = view
        .transit_points()
        .iter()
        .filter_map(|point| {
            point
                .source_auth
                .as_ref()
                .and_then(jwt)
                .map(|config| (point.alias.clone(), config))
        })
        .collect();
    (access_point, transit_points)
}

/// The `expected_issuer` of each JWT verification strategy `surface` names, on
/// an Access Point or a Transit Point, by strategy id. A strategy that cannot
/// be read is left out.
async fn jwt_strategy_issuers(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> std::collections::HashMap<String, StrategyCallerNaming> {
    let mut issuers = std::collections::HashMap::new();
    let Some(store) = state
        .jwt_verification_strategy_store
        .as_ref()
    else {
        return issuers;
    };
    for (alias, view) in surface_views(surface) {
        let (access_point, transit_points) = jwt_bearer_methods(&view, alias.as_deref());
        for config in access_point.iter().chain(
            transit_points
                .iter()
                .map(|(_, config)| config),
        ) {
            let id = &config.jwt_verification_strategy_id;
            if issuers.contains_key(id) {
                continue;
            }
            if let Ok(Some(strategy)) = store.get(id).await {
                let principal_claim = strategy
                    .principal_claim_name()
                    .map(str::to_string)
                    .map_err(|_| {
                        strategy
                            .principal_claim
                            .clone()
                            .unwrap_or_default()
                    });
                issuers.insert(
                    id.clone(),
                    StrategyCallerNaming {
                        issuer: strategy.expected_issuer,
                        principal_claim,
                    },
                );
            }
        }
    }
    issuers
}

/// The issuer a JWT verification strategy accepts and the claim it names
/// callers by: together they decide which callers of two strategies are one.
/// A stored claim the API refuses is `Err` with that claim: such a strategy
/// names no caller.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StrategyCallerNaming {
    issuer: String,
    principal_claim: Result<String, String>,
}

/// Each Transit Point, on the surface or in an enabled variant, whose
/// `jwt_bearer` strategy names the same issuer, in `issuers`, as another
/// strategy the same view accepts, on its Access Point or another Transit
/// Point, and each pair of Access Point strategies that name one issuer but
/// different claims ([`access_point_claim_warnings`]). The identity hash keys a
/// JWT caller by its
/// issuer, subject and principal claim, so callers verified through two
/// strategies naming one claim are one caller, with the same delegated
/// credentials, and through two naming different claims are two. A strategy
/// whose stored claim names no caller is warned of on its own
/// ([`unusable_principal_claim_warnings`]).
fn shared_issuer_warnings(
    surface: &AgentSurface,
    issuers: &std::collections::HashMap<String, StrategyCallerNaming>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for (variant, view) in surface_views(surface) {
        let (access_point, transit_points) = jwt_bearer_methods(&view, variant.as_deref());
        let accepted: Vec<&str> = access_point
            .iter()
            .chain(
                transit_points
                    .iter()
                    .map(|(_, config)| config),
            )
            .map(|config| {
                config
                    .jwt_verification_strategy_id
                    .as_str()
            })
            .collect();
        for (alias, config) in &transit_points {
            let strategy = config
                .jwt_verification_strategy_id
                .as_str();
            let Some((issuer, claim)) = usable_naming(issuers, strategy) else {
                continue;
            };
            for (other, other_claim) in accepted
                .iter()
                .filter(|other| **other != strategy)
                .filter_map(|other| {
                    usable_naming(issuers, other)
                        .filter(|(other_issuer, _)| *other_issuer == issuer)
                        .map(|(_, other_claim)| (other, other_claim))
                })
            {
                let name = transit_point_name(surface, variant.as_deref(), alias);
                let warning = if other_claim == claim {
                    format!(
                        "Transit Point {name} accepts tokens from issuer '{issuer}' through JWT verification \
                         strategy '{strategy}', and this surface accepts that issuer through '{other}' too: a caller \
                         with the same subject through either is one caller, with the same delegated credentials; \
                         use one strategy per issuer"
                    )
                } else {
                    format!(
                        "Transit Point {name} accepts tokens from issuer '{issuer}' through JWT verification \
                         strategy '{strategy}', and this surface accepts that issuer through '{other}' too, but they \
                         name callers by different claims ('{}' and '{}'): the same person through either is two \
                         callers, each with delegated credentials of their own; use one strategy per issuer",
                        claim, other_claim
                    )
                };
                if !warnings.contains(&warning) {
                    warnings.push(warning);
                }
            }
        }
    }
    for warning in access_point_claim_warnings(surface, issuers) {
        if !warnings.contains(&warning) {
            warnings.push(warning);
        }
    }
    warnings
}

/// Each pair of JWT verification strategies the surface's Access Point
/// accepts, on the surface or in an enabled variant, that name one issuer but
/// different claims: the same person reaching the surface through either is
/// two callers. A strategy is named with a variant only when that variant's
/// overrides set the Access Point's caller authentication; one a variant
/// inherits is the surface's own, so each pair is warned of once.
fn access_point_claim_warnings(
    surface: &AgentSurface,
    issuers: &std::collections::HashMap<String, StrategyCallerNaming>,
) -> Vec<String> {
    let mut accepted: Vec<(String, Option<String>)> = Vec::new();
    for (variant, view) in surface_views(surface) {
        let defined_by = variant
            .as_deref()
            .filter(|alias| variant_sets_caller_authentication(surface, alias))
            .map(str::to_string);
        let (access_point, _) = jwt_bearer_methods(&view, variant.as_deref());
        for config in access_point {
            let entry = (config.jwt_verification_strategy_id, defined_by.clone());
            if !accepted.contains(&entry) {
                accepted.push(entry);
            }
        }
    }
    let located = |strategy: &str, variant: &Option<String>| match variant {
        Some(alias) => format!("'{strategy}' in variant '{alias}'"),
        None => format!("'{strategy}'"),
    };
    let mut warnings = Vec::new();
    for (index, (strategy, variant)) in accepted.iter().enumerate() {
        let Some((issuer, claim)) = usable_naming(issuers, strategy) else {
            continue;
        };
        for (other, other_variant) in accepted
            .iter()
            .skip(index + 1)
        {
            let Some((other_issuer, other_claim)) = usable_naming(issuers, other) else {
                continue;
            };
            if other_issuer != issuer || other_claim == claim {
                continue;
            }
            let warning = format!(
                "The Access Point accepts tokens from issuer '{issuer}' through JWT verification strategies {} and \
                 {}, which name callers by different claims ('{claim}' and '{other_claim}'): the same person \
                 through either is two callers, each with delegated credentials of their own; use one strategy \
                 per issuer",
                located(strategy, variant),
                located(other, other_variant)
            );
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    warnings
}

/// Whether the enabled variant `alias` overrides the Access Point's caller
/// authentication rather than inheriting the surface's.
fn variant_sets_caller_authentication(
    surface: &AgentSurface,
    alias: &str,
) -> bool {
    surface
        .variants
        .iter()
        .any(|candidate| {
            candidate.alias == alias
                && candidate
                    .overrides
                    .access_point
                    .as_ref()
                    .is_some_and(|access_point| {
                        access_point
                            .caller_authentication
                            .is_some()
                    })
        })
}

/// The issuer and principal claim of `strategy` in `issuers`, unless its
/// stored claim names no caller.
fn usable_naming<'a>(
    issuers: &'a std::collections::HashMap<String, StrategyCallerNaming>,
    strategy: &str,
) -> Option<(&'a str, &'a str)> {
    let naming = issuers.get(strategy)?;
    let claim = naming
        .principal_claim
        .as_deref()
        .ok()?;
    Some((naming.issuer.as_str(), claim))
}

/// Each JWT verification strategy a view of the surface accepts, on its
/// Access Point or a Transit Point, whose stored `principal_claim` is one the
/// API refuses, such as one written to storage by hand: it names no caller,
/// so JWT source authentication through it answers `500`.
fn unusable_principal_claim_warnings(
    surface: &AgentSurface,
    issuers: &std::collections::HashMap<String, StrategyCallerNaming>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for (variant, view) in surface_views(surface) {
        let (access_point, transit_points) = jwt_bearer_methods(&view, variant.as_deref());
        for strategy in access_point.iter().chain(
            transit_points
                .iter()
                .map(|(_, config)| config),
        ) {
            let strategy = strategy
                .jwt_verification_strategy_id
                .as_str();
            let Some(Err(stored)) = issuers
                .get(strategy)
                .map(|naming| {
                    naming
                        .principal_claim
                        .as_ref()
                })
            else {
                continue;
            };
            let warning = format!(
                "JWT verification strategy '{strategy}' names callers by '{stored}', a claim the API refuses: it \
                 identifies no caller, and JWT source authentication through it answers 500; create a strategy \
                 that names another claim"
            );
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    warnings
}

/// Each `fabric://` Transit Point, on the surface or in an enabled variant,
/// that does not require the transit token: a call without one carries no
/// Fabric hop count, so a chain through it can start again at 1.
fn fabric_hop_limit_warnings(surface: &AgentSurface) -> Vec<String> {
    let mut warnings = Vec::new();
    for (_, view) in surface_views(surface) {
        for transit_point in view
            .transit_points()
            .iter()
            .filter(|point| {
                point
                    .target_endpoint
                    .starts_with("fabric://")
                    && !point.require_transit_token
            })
        {
            let warning = format!(
                "Transit Point '{}' sends to a peer gateway without requiring the transit token, so the Fabric hop \
                 limit holds through it only when the agent sends one; require the transit token",
                transit_point.alias
            );
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    warnings
}

/// Each Transit Point, on the surface or in an enabled variant, that sets
/// `delegated_credentials_for_fabric_callers` but resolves no managed identity.
/// A Fabric caller's DID is never the agent half of a delegated credential's
/// key, so a binding that applies refuses every Fabric caller there.
fn fabric_delegation_identity_warnings(surface: &AgentSurface) -> Vec<String> {
    let mut warnings = Vec::new();
    for (_, view) in surface_views(surface) {
        for point in view
            .transit_points()
            .iter()
            .filter(|point| {
                point.delegated_credentials_for_fabric_callers && !view.transit_point_has_managed_identity(point)
            })
        {
            let warning = format!(
                "Transit Point '{}' sets delegated_credentials_for_fabric_callers but has no managed identity, so a \
                 delegated credential binding that applies refuses every Fabric caller with 403; give it a managed \
                 identity, or inject a VP with the surface's",
                point.alias
            );
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    warnings
}

/// Each Transit Point, on the surface or in an enabled variant, that sets
/// `delegated_credentials_for_fabric_callers` where the view's caller
/// authentication cannot tell a partner's users apart
/// ([`AgentSurface::fabric_caller_authentication_gap`]), or names a JWT
/// verification strategy that, in `issuers`, names no issuer. The receiving
/// surface then puts no principal in a partner's transit token, so the
/// Transit Point releases no delegated credential to Fabric callers.
fn fabric_caller_delegation_warnings(
    surface: &AgentSurface,
    issuers: &std::collections::HashMap<String, StrategyCallerNaming>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for (variant, view) in surface_views(surface) {
        let Some(point) = view
            .transit_points()
            .iter()
            .find(|point| point.delegated_credentials_for_fabric_callers)
        else {
            continue;
        };
        let gap = view
            .fabric_caller_authentication_gap()
            .map(str::to_string)
            .or_else(|| {
                let (access_point, _) = jwt_bearer_methods(&view, None);
                access_point
                    .iter()
                    .map(|config| {
                        config
                            .jwt_verification_strategy_id
                            .as_str()
                    })
                    .find(|strategy| {
                        issuers
                            .get(*strategy)
                            .is_none_or(|naming| {
                                naming
                                    .issuer
                                    .trim()
                                    .is_empty()
                            })
                    })
                    .map(|strategy| {
                        format!("its JWT verification strategy '{strategy}' names no issuer, or cannot be read")
                    })
            });
        if let Some(gap) = gap {
            let label = variant.map_or_else(String::new, |alias| format!("variant '{alias}': "));
            warnings.push(format!(
                "{label}Transit Point '{}' sets delegated_credentials_for_fabric_callers, but the surface's caller \
                 authentication cannot tell a partner's users apart, and {gap}, so it releases no delegated \
                 credential to Fabric callers",
                point.alias
            ));
        }
    }
    warnings
}

/// Each Transit Point with `consent_mode: external` that an enabled variant
/// keeps from the surface, rather than listing its own points, while it
/// overrides the shared transit settings or the Access Point. A grant by
/// binding is kept under the Transit Point's id, so calls through the variant
/// use the surface's grants under the variant's own transit policy, rate limit
/// and Access Point.
fn inherited_external_point_warnings(surface: &AgentSurface) -> Vec<String> {
    let external: Vec<&str> = surface
        .transit_points()
        .iter()
        .filter(|point| {
            point
                .transit_credentials
                .as_ref()
                .is_some_and(|binding| binding.is_external())
        })
        .map(|point| point.alias.as_str())
        .collect();
    let mut warnings = Vec::new();
    for variant in surface
        .variants
        .iter()
        .filter(|variant| variant.enabled)
    {
        let transit = variant
            .overrides
            .transit
            .as_ref();
        let keeps_the_points = transit.is_none_or(|transit| transit.disabled != Some(true) && transit.points.is_none());
        let overrides_access = transit.is_some_and(|transit| transit.shared.is_some())
            || variant
                .overrides
                .access_point
                .is_some();
        if !keeps_the_points || !overrides_access {
            continue;
        }
        for alias in &external {
            warnings.push(format!(
                "Variant '{}' keeps Transit Point '{alias}', which has consent_mode external, and overrides its \
                 transit settings or its Access Point: calls through the variant use the Transit Point's grants under \
                 the variant's own transit policy, rate limit and Access Point; to keep them apart, give the variant \
                 its own Transit Points in overrides.transit.points, with new ids",
                variant.alias
            ));
        }
    }
    warnings
}

/// Each served view of `surface`, its own route (unless a default variant takes
/// its requests) or an enabled variant, that sends its requests to the origin
/// the Access Point Target's binding with `consent_mode: external` sends its
/// grant to, without that binding or a credential of its own for the vendor
/// (`target.auth`, another binding, or a caller credential every method
/// forwards): such as a variant copied from the one holding the binding and
/// then enabled. Its callers' requests reach the vendor with no grant.
fn unbound_vendor_view_warnings(surface: &AgentSurface) -> Vec<String> {
    let origin = |endpoint: &str| {
        url::Url::parse(endpoint)
            .ok()
            .map(|url| url.origin())
            .filter(url::Origin::is_tuple)
    };
    let bound: Vec<_> = super::surface_grants::served_external_bindings(surface)
        .iter()
        .filter(|binding| binding.hop == crate::delegation_vault::grants::ACCESS_POINT_TARGET_HOP)
        .filter_map(|binding| origin(&binding.target_endpoint))
        .collect();
    if bound.is_empty() {
        return Vec::new();
    }
    surface
        .default_variant_id
        .is_none()
        .then(|| (None, surface.clone()))
        .into_iter()
        .chain(
            surface
                .variants
                .iter()
                .filter(|variant| variant.enabled)
                .filter_map(|variant| {
                    surface
                        .resolve_variant(Some(&variant.alias))
                        .ok()
                        .map(|view| (Some(variant.alias.clone()), view))
                }),
        )
        .filter(|(_, view)| {
            view.target_auth().is_none()
                && view
                    .outbound_credentials
                    .is_empty()
                && !view.forwards_every_caller_credential()
                && origin(&view.target.endpoint).is_some_and(|view_origin| bound.contains(&view_origin))
        })
        .map(|(variant, view)| {
            let named =
                variant.map_or_else(|| "The surface's own route".to_string(), |alias| format!("Variant '{alias}'"));
            format!(
                "{named} sends requests to the vendor of the external consent binding without the binding or a \
                 credential of its own: callers' requests reach the vendor with no grant. Give it another Target or \
                 its own credential (target.auth, a binding or forward_header). Target: {}",
                view.target.endpoint
            )
        })
        .collect()
}

/// Each enabled variant that keeps the surface's `outbound_credentials`, and
/// with them the Access Point Target's binding with `consent_mode: external`,
/// while it overrides the Access Point or the Target. Its grants are kept
/// under the hop `target`, so calls through the variant use the surface's
/// grants under the variant's own caller authentication, policies and tool
/// gating.
fn inherited_target_binding_warnings(surface: &AgentSurface) -> Vec<String> {
    if surface
        .target_external_credentials()
        .is_none()
    {
        return Vec::new();
    }
    surface
        .variants
        .iter()
        .filter(|variant| {
            variant.enabled
                && variant
                    .overrides
                    .outbound_credentials
                    .is_none()
                && (variant
                    .overrides
                    .access_point
                    .is_some()
                    || variant
                        .overrides
                        .target
                        .is_some())
        })
        .map(|variant| {
            format!(
                "Variant '{}' keeps the Access Point Target's binding with consent_mode external, and overrides its \
                 Access Point or its Target: calls through the variant use the Target's grants under the variant's \
                 own caller authentication, policies and tool gating; to keep them apart, give the variant \
                 outbound_credentials of its own",
                variant.alias
            )
        })
        .collect()
}

/// Each Transit Point, on the surface or in an enabled variant, whose
/// `jwt_bearer` accepts tokens issued for the Access Point, base or enabled
/// variant: the same JWT verification strategy and an audience both name. An
/// Access Point that publishes protected resource metadata accepts the resource
/// of each route, so a Transit Point that names any of them is one. A caller of
/// the Access Point could then call that Transit Point directly, with its
/// credentials.
fn shared_audience_warnings(surface: &AgentSurface) -> Vec<String> {
    let views: Vec<_> = surface_views(surface)
        .into_iter()
        .map(|(variant, view)| (variant.clone(), jwt_bearer_methods(&view, variant.as_deref())))
        .collect();
    let access_point: Vec<_> = views
        .iter()
        .flat_map(|(_, (access_point, _))| access_point.iter())
        .collect();
    let mut warnings = Vec::new();
    for (variant, (_, transit_points)) in &views {
        for (alias, transit_point) in transit_points {
            for accepted in access_point
                .iter()
                .filter(|accepted| accepted.jwt_verification_strategy_id == transit_point.jwt_verification_strategy_id)
            {
                let Some(audience) = transit_point
                    .audiences
                    .iter()
                    .find(|audience| {
                        accepted
                            .audiences
                            .contains(audience)
                    })
                else {
                    continue;
                };
                let warning = format!(
                    "Transit Point {} accepts the Access Point's own tokens (JWT verification strategy '{}', \
                     audience '{audience}'), so a caller of the Access Point can call it directly; give it an \
                     audience of its own",
                    transit_point_name(surface, variant.as_deref(), alias),
                    transit_point.jwt_verification_strategy_id
                );
                if !warnings.contains(&warning) {
                    warnings.push(warning);
                }
            }
        }
    }
    warnings
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
    Unavailable(String),
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
            SurfaceApiError::Unavailable(msg) => {
                warn!("Surface API Service Unavailable: {}", msg);
                (StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable", Some(msg.clone()))
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
) -> Result<Json<Vec<SurfaceResponse<AgentSurface>>>, SurfaceApiError> {
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
    Ok(Json(
        surfaces
            .into_iter()
            .map(SurfaceResponse::from)
            .collect(),
    ))
}

/// Get a single agent surface by ID
pub async fn get_surface(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<SurfaceResponse<AgentSurface>>, SurfaceApiError> {
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
            Ok(Json(surface.into()))
        }
        Some(_) => Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id))),
        None => Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id))),
    }
}

#[derive(Serialize)]
pub struct TrustRecorderStatusResponse {
    pub status: Option<RecorderStatus>,
}

/// Last known Trust Recorder outcome of a surface: the most recently attempted of its
/// managed agents. `status` is `null` until the recorder has run, and while the surface
/// has no Trust Recorder.
pub async fn get_trust_recorder_status(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<TrustRecorderStatusResponse>, SurfaceApiError> {
    let (_, surface) =
        load_surface_or_404(&state, &surface_id, tenant_context(&context), resource_scope(&scope), SurfaceAccess::Read)
            .await?;
    let has_recorder = surface
        .trust_recorder()
        .is_some_and(|recorder| !recorder.entries.is_empty());
    let status = match global_store() {
        Some(store) if has_recorder => {
            store
                .latest_for_surface(&surface.surface_id)
                .await
        }
        _ => None,
    };
    Ok(Json(TrustRecorderStatusResponse { status }))
}

/// `GET /v1/surfaces/{id}/agent-card`
///
/// The base route's agent card beside the agent's own card, with how the gateway's
/// fetch went. Every fetch result is a `200`. Past the per-user or per-surface fetch
/// limit the last preview of the same running surface answers, or `429` without one.
pub async fn get_surface_agent_card(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Extension(AuthGuardOk(user_id)): Extension<AuthGuardOk>,
) -> Result<Response, SurfaceApiError> {
    let caller = CardPreviewCaller {
        context: tenant_context(&context),
        scope: resource_scope(&scope),
        user_id: &user_id,
    };
    agent_card_preview(&state, &surface_id, &caller, crate::proxy::card_preview::PreviewRequest::Read).await
}

/// `POST /v1/surfaces/{id}/agent-card/refresh`
///
/// Fetch the base route's agent card again, as [`get_surface_agent_card`] reports
/// it. The request body is ignored. Past the per-user or per-surface fetch limit, `429`.
pub async fn refresh_surface_agent_card(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Extension(AuthGuardOk(user_id)): Extension<AuthGuardOk>,
) -> Result<Response, SurfaceApiError> {
    let caller = CardPreviewCaller {
        context: tenant_context(&context),
        scope: resource_scope(&scope),
        user_id: &user_id,
    };
    agent_card_preview(&state, &surface_id, &caller, crate::proxy::card_preview::PreviewRequest::Refresh).await
}

struct CardPreviewCaller<'a> {
    context: Option<&'a PatTenantContext>,
    scope: Option<&'a PatResourceScope>,
    user_id: &'a str,
}

const CARD_FETCH_LIMITED: &str = "Too many card fetches; try again in a few seconds";

/// The agent card preview of a surface the caller may read, or for a refresh,
/// change. A surface of another tenant is `404`, never its card, and a tenant token
/// never makes the gateway fetch an appliance-wide surface's card.
async fn agent_card_preview(
    state: &IdentityApiState,
    surface_id: &str,
    caller: &CardPreviewCaller<'_>,
    request: crate::proxy::card_preview::PreviewRequest,
) -> Result<Response, SurfaceApiError> {
    use crate::proxy::card_preview::{
        AgentCardPreview, PreviewCaller, PreviewRequest, RateLimited, UnsupportedReason, preview_memory,
        unsupported_reason,
    };

    let access = match request {
        PreviewRequest::Read => SurfaceAccess::Read,
        PreviewRequest::Refresh => SurfaceAccess::Mutate,
    };
    let (_store, surface) = load_surface_or_404(state, surface_id, caller.context, caller.scope, access).await?;
    let unsupported = |reason| Ok(Json(AgentCardPreview::unsupported(&surface.surface_id, reason)).into_response());
    if let Some(reason) = unsupported_reason(&surface, caller.context.is_some(), crate::server::mode::is_standby()) {
        return unsupported(reason);
    }
    let Some(proxy_state) = state
        .channel_manager
        .card_preview_state(&surface.surface_id)
        .await
    else {
        return unsupported(UnsupportedReason::NotRunning);
    };
    if !proxy_state
        .surface
        .uses_a2a_settings()
    {
        return unsupported(UnsupportedReason::NotA2a);
    }

    let preview_caller = PreviewCaller {
        user_id: caller.user_id,
        tenant_id: caller
            .context
            .map(|context| context.tenant_id.as_str()),
    };
    match preview_memory()
        .preview(&proxy_state, &preview_caller, request)
        .await
    {
        Ok(preview) => Ok(Json(preview).into_response()),
        Err(RateLimited { retry_after_secs }) => {
            warn!(surface_id = %surface.surface_id, "Agent card preview refused: fetch limit reached");
            Ok((
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, retry_after_secs.to_string())],
                Json(serde_json::json!({"error": CARD_FETCH_LIMITED, "code": "rate_limited"})),
            )
                .into_response())
        }
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
    if surface
        .source_auth_methods()
        .iter()
        .any(|method| {
            matches!(method, crate::source_auth::SourceAuthConfig::JwtBearer(jwt)
                if jwt.token_header.eq_ignore_ascii_case("authorization"))
        })
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
    errors.extend(variant_transit_point_enforcement_overrides(surface));
    if !errors.is_empty() {
        return Err(SurfaceApiError::BadRequest(errors.join("; ")));
    }
    Ok(())
}

/// A variant's Transit Point is enforced with the MCP tool gating, policy,
/// response policy and per-caller rate limit of the surface's Transit Point of
/// the same alias, so one that sets any of them to something else is refused
/// rather than silently ignored.
fn variant_transit_point_enforcement_overrides(surface: &AgentSurface) -> Vec<String> {
    let mut errors = Vec::new();
    for variant in &surface.variants {
        let Some(points) = variant
            .overrides
            .transit
            .as_ref()
            .and_then(|transit| transit.points.as_ref())
        else {
            continue;
        };
        for point in points {
            let base = surface
                .transit_points()
                .iter()
                .find(|base| base.alias == point.alias);
            let changed = [
                (
                    "mcp_tool_gating",
                    gating_in_force(Some(point)).is_some() && gating_in_force(Some(point)) != gating_in_force(base),
                ),
                ("policy", changes_policy(point.policy.as_ref(), base.and_then(|base| base.policy.as_ref()))),
                (
                    "response_policy",
                    changes_policy(point.response_policy.as_ref(), base.and_then(|base| base.response_policy.as_ref())),
                ),
                (
                    "per_caller_rate_limit",
                    point
                        .per_caller_rate_limit
                        .is_some()
                        && !base.is_some_and(|base| base.has_same_per_caller_rate_limit(point)),
                ),
            ];
            for (field, changed) in changed {
                if changed {
                    errors.push(format!(
                        "Surface '{}': variant '{}' transit point '{}' sets '{field}', which a variant cannot change; \
                         set it on the surface's transit point '{}' instead",
                        surface.name, variant.alias, point.alias, point.alias
                    ));
                }
            }
        }
    }
    errors
}

fn gating_in_force(
    point: Option<&crate::config::agent_surface::TransitPoint>
) -> Option<&crate::config::agent_surface::McpToolGatingConfig> {
    point
        .and_then(|point| point.mcp_tool_gating.as_ref())
        .filter(|gating| !gating.is_empty())
}

fn changes_policy(
    set: Option<&crate::config::agent_surface::PolicyRef>,
    enforced: Option<&crate::config::agent_surface::PolicyRef>,
) -> bool {
    set.is_some_and(|set| {
        !enforced.is_some_and(|enforced| {
            set.policy_definition_id == enforced.policy_definition_id
                && set.require_agent_context == enforced.require_agent_context
        })
    })
}

/// Create a new agent surface
pub async fn create_surface(
    State(state): State<IdentityApiState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
    JsonWithSent(mut surface, _): JsonWithSent<AgentSurface>,
) -> Result<(StatusCode, axum::http::HeaderMap, Json<SurfaceResponse<AgentSurface>>), SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;
    refuse_a2a_settings_sent_on_other_protocols(&surface)?;
    convert_old_shape_body(&mut surface)?;
    drop_inbound_api_key_ids(&mut surface);

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
    validate_api_key_identities(&surface, "")?;
    validate_source_auth(&surface, None)?;
    reject_public_predicate_route(&surface)?;
    surface.access_point.public = Some(
        surface
            .access_point
            .public
            .unwrap_or(false),
    );
    surface.apply_public_access();

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
    validate_transit_points(
        &mut surface,
        state
            .network_config
            .transit_token_max_lifetime_secs,
        None,
    )?;

    super::surface_tenancy::validate_surface_references(
        &state,
        &surface,
        None,
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    super::surface_tenancy::validate_external_consent_bindings(&state, &surface).await?;

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
    reject_target_trust_checks_unless_target_runs_them(&surface)?;

    // Check for duplicate surface_id
    surface
        .validate_mcp_metadata()
        .map_err(SurfaceApiError::BadRequest)?;
    normalize_a2a_settings(&mut surface, None).map_err(SurfaceApiError::BadRequest)?;
    refuse_validation_off_by_scoped_caller(
        &surface,
        None,
        tenant_context(&context),
        resource_scope(&scope),
        resource_scoped(&delegation),
    )?;
    validate_protected_resource_issuers(&state, &surface).await?;
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
    let allowlist = crate::egress::bdd_egress_allowlist();
    let actor = management_actor(&caller, &delegation);
    surface.trust_check_split = surface.has_trust_check_lists();
    surface.transit_point_source_auth = surface.has_transit_point_source_auth();
    super::surface_grants::write_surface(
        &super::surface_grants::GrantRemoval::of(&state, allowlist.as_deref(), actor.as_ref()),
        store.clone(),
        &surface.surface_id,
        super::surface_grants::Stored::Absent,
        Some(&surface),
        || async {
            store
                .save(&surface)
                .await
                .map_err(|e| SurfaceApiError::InternalError(format!("Failed to save surface: {}", e)))
        },
    )
    .await?;

    info!("Created agent surface '{}' (surface_id={})", surface.name, surface.surface_id);

    apply_surface_change(&state, SurfaceChange::Upsert(&surface)).await;

    Ok((StatusCode::CREATED, save_warnings(&state, &surface).await, Json(surface.into())))
}

/// Whether `access_point` in a PUT body removes its discovery setting.
fn removes_protected_resource(access_point: Option<&serde_json::Value>) -> bool {
    access_point
        .and_then(|access_point| access_point.pointer("/caller_authentication/protected_resource"))
        .is_some_and(serde_json::Value::is_null)
}

/// The discovery settings a PUT removes, for the surface and by variant id. A
/// PUT that omits a setting keeps it, so `null` is how a PUT removes one, in
/// the same request as the rest of the edit. Retention skips them, so a stored
/// setting the PUT removes is never restored and checked against the edit.
#[derive(Debug, Default)]
struct ProtectedResourceRemovals {
    base: bool,
    variant_ids: Vec<String>,
}

impl ProtectedResourceRemovals {
    fn of(body: &serde_json::Value) -> Self {
        Self {
            base: removes_protected_resource(body.get("access_point")),
            variant_ids: body
                .get("variants")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter(|variant| removes_protected_resource(variant.pointer("/overrides/access_point")))
                .filter_map(|variant| {
                    variant
                        .get("id")?
                        .as_str()
                        .map(str::to_string)
                })
                .collect(),
        }
    }
}

/// Update an existing agent surface
pub async fn update_surface(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
    JsonWithSent(mut surface, sent): JsonWithSent<AgentSurface>,
) -> Result<SavedSurface, SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;

    // Ensure the path ID matches the body ID
    if !surface.surface_id.is_empty() && surface.surface_id != surface_id {
        return Err(SurfaceApiError::BadRequest("surface_id in body does not match URL parameter".to_string()));
    }
    surface.surface_id = surface_id.clone();
    refuse_a2a_settings_sent_on_other_protocols(&surface)?;

    let existing = store
        .get(&surface_id)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to get surface: {}", e)))?;
    let existing = existing.ok_or_else(|| SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id)))?;
    if !surface_visible(existing.tenant_id.as_deref(), &surface_id, tenant_context(&context), resource_scope(&scope)) {
        return Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id)));
    }
    if !surface_writable(existing.tenant_id.as_deref(), &surface_id, tenant_context(&context), resource_scope(&scope)) {
        return Err(SurfaceApiError::Forbidden("surface is outside this token's permitted scope".to_string()));
    }
    settle_undeclared_put(&mut surface, &existing, &sent)?;
    carry_transit_point_ids(&mut surface, &existing, &sent);
    surface.tenant_id = existing.tenant_id.clone();
    if surface
        .mcp_legacy_metadata_output
        .is_none()
    {
        surface.mcp_legacy_metadata_output = existing.mcp_legacy_metadata_output;
    }
    retain_mcp_settings(&mut surface, &existing, &state.network_config, &ProtectedResourceRemovals::of(&sent))?;
    retain_a2a_settings(&mut surface, &existing);
    retain_transit_token_lifetime(&mut surface, &existing);
    retain_transit_caller_authentication(&mut surface, &existing, &sent);

    let saved = validate_and_save_surface(
        &state,
        store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
        resource_scoped(&delegation),
        management_actor(&caller, &delegation).as_ref(),
    )
    .await?;
    Ok((save_warnings(&state, &saved).await, Json(saved.into())))
}

/// PUT carries the whole record, so an omitted
/// `transit.transit_token_lifetime_secs` means "unchanged", never "back to
/// 300". The Surface Builder does not show the field, so a save from it omits
/// it, and resetting it would silently widen a tightened lifetime or cut short
/// a lengthened one. Removal is explicit, via PATCH with a `null`. A stored
/// base `transit` block with no Transit Points, which carries the lifetime of
/// a surface whose Transit Points exist only in a variant, is kept with only
/// its lifetime when the PUT has no `transit`, as a dashboard save sends.
fn retain_transit_token_lifetime(
    surface: &mut AgentSurface,
    existing: &AgentSurface,
) {
    let Some(stored) = &existing.transit else {
        return;
    };
    let Some(stored_secs) = stored
        .shared
        .transit_token_lifetime_secs
    else {
        return;
    };
    match &mut surface.transit {
        Some(incoming) => {
            incoming
                .shared
                .transit_token_lifetime_secs
                .get_or_insert(stored_secs);
        }
        None if stored.points.is_empty() => {
            surface.transit = Some(TransitConfig {
                points: Vec::new(),
                outbound_listen_address: None,
                shared: SharedTransitConfig {
                    transit_token_lifetime_secs: Some(stored_secs),
                    ..Default::default()
                },
            });
        }
        None => {}
    }
}

/// PUT carries the whole record, so an omitted `access_point.a2a` on an A2A or
/// AP2 surface means "unchanged".
fn retain_a2a_settings(
    surface: &mut AgentSurface,
    existing: &AgentSurface,
) {
    if surface
        .access_point
        .a2a
        .is_none()
        && surface.uses_a2a_settings()
    {
        surface.access_point.a2a = existing
            .access_point
            .a2a
            .clone();
    }
}

/// Refuse an `access_point.a2a` the request itself carries on a surface that is
/// not A2A or AP2, as `mcp_http` is refused on a surface that is not MCP. A block
/// that only came from the stored surface, as when a merge `PATCH` changes the
/// protocol, is dropped by [`normalize_a2a_settings`] instead.
fn refuse_a2a_settings_sent_on_other_protocols(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    if surface.uses_a2a_settings() {
        return Ok(());
    }
    surface
        .validate_a2a_settings()
        .map_err(SurfaceApiError::BadRequest)
}

/// Whether a merge `PATCH` body itself sets `access_point.a2a` (to anything
/// other than `null`, which removes it).
fn patch_sets_a2a_settings(patch: &serde_json::Value) -> bool {
    patch
        .pointer("/access_point/a2a")
        .is_some_and(|a2a| !a2a.is_null())
}

/// Settle `access_point.a2a` before a save, given the stored surface (`None` on
/// create). A surface that is not A2A or AP2 drops a block left over from the
/// stored surface, so a protocol change never fails on it; a block the request
/// itself sent was already refused by [`refuse_a2a_settings_sent_on_other_protocols`].
///
/// Every A2A or AP2 surface stores the block explicitly, the defaults when it
/// was not sent.
///
/// The accepted versions of a surface whose Target is an A2A proxy are fixed:
/// the stored ones when the stored Target was already an A2A proxy (the ones it
/// is served with when the stored list is invalid), and `["1.0"]` on create or
/// when the Target moves to an A2A proxy. A block that
/// does not name `accepted_versions`, or carries the stored versions unchanged,
/// takes the fixed ones; one that names other versions is refused.
///
/// Where the validation level applies to no request (an A2A-proxy Target with
/// no URL variant), a level other than `envelope` is refused, unless it is the
/// stored one: an edit that leaves only proxy Targets (a Target moved to a proxy,
/// the last URL variant removed) then resets it to `envelope` rather than fail
/// on a level the surface already had.
fn normalize_a2a_settings(
    surface: &mut AgentSurface,
    existing: Option<&AgentSurface>,
) -> Result<(), String> {
    use crate::config::agent_surface::{A2aAccessPointSettings, A2aValidation};
    if !surface.uses_a2a_settings() {
        surface.access_point.a2a = None;
        return Ok(());
    }
    let stored = existing.and_then(|existing| {
        existing
            .access_point
            .a2a
            .as_ref()
    });
    let fixed_versions = surface
        .is_a2a_proxy_target()
        .then(|| match existing {
            Some(existing) if existing.is_a2a_proxy_target() => match stored {
                Some(stored) if stored.validate().is_err() => existing
                    .a2a_settings()
                    .accepted_versions
                    .iter()
                    .map(|version| version.to_string())
                    .collect(),
                _ => {
                    stored
                        .cloned()
                        .unwrap_or_default()
                        .accepted_versions
                }
            },
            _ => A2aAccessPointSettings::a2a_proxy().accepted_versions,
        });
    let validation_applies = surface.a2a_validation_applies();
    let surface_name = surface.name.clone();
    let settings = surface
        .access_point
        .a2a
        .get_or_insert_with(|| A2aAccessPointSettings {
            accepted_versions: fixed_versions
                .clone()
                .unwrap_or_else(|| A2aAccessPointSettings::default().accepted_versions),
            validation: A2aValidation::default(),
            accepted_versions_sent: false,
        });
    if let Some(fixed) = fixed_versions
        && settings.accepted_versions != fixed
    {
        if settings.accepted_versions_sent
            && stored.is_none_or(|stored| stored.accepted_versions != settings.accepted_versions)
        {
            return Err(format!(
                "the accepted A2A versions of a surface whose Target is an A2A proxy are fixed at [{}]",
                fixed.join(", ")
            ));
        }
        if let Some(stored) = stored
            && stored.accepted_versions != fixed
            && !existing.is_some_and(AgentSurface::is_a2a_proxy_target)
        {
            warn!(
                surface = ?crate::a2a::clip_for_log(&surface_name),
                "The Target moved to an A2A proxy, so the surface now accepts A2A {} only, not {}; callers using \
                 another version are refused with -32009",
                fixed.join(", "),
                stored
                    .accepted_versions
                    .join(", ")
            );
        }
        settings.accepted_versions = fixed;
    }
    if !validation_applies
        && settings.validation != A2aValidation::Envelope
        && stored.is_some_and(|stored| stored.validation == settings.validation)
    {
        settings.validation = A2aValidation::Envelope;
    }
    surface.validate_a2a_settings()
}

/// Only an appliance-wide caller may turn a surface's A2A validation `off`. With
/// it off, a JSON-RPC batch or a non-string `method` reaches policy and the
/// payment filters without a method to match, so a scoped token could otherwise
/// step around operator-wide method rules. A caller is appliance-wide when its
/// token has no tenant, no resource pattern and no required headers; each is
/// checked on its own, so a token scoped by required headers alone is refused
/// too. A surface that is already `off` stays editable.
fn refuse_validation_off_by_scoped_caller(
    surface: &AgentSurface,
    stored: Option<&crate::config::agent_surface::A2aAccessPointSettings>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
    resource_scoped: bool,
) -> Result<(), SurfaceApiError> {
    use crate::config::agent_surface::A2aValidation;
    let is_off = |settings: Option<&crate::config::agent_surface::A2aAccessPointSettings>| {
        settings.is_some_and(|settings| settings.validation == A2aValidation::Off)
    };
    if (context.is_some() || scope.is_some() || resource_scoped)
        && is_off(
            surface
                .access_point
                .a2a
                .as_ref(),
        )
        && !is_off(stored)
    {
        return Err(SurfaceApiError::Forbidden(
            "only an appliance-wide administrator can set access_point.a2a.validation to \"off\"".to_string(),
        ));
    }
    Ok(())
}

fn retain_mcp_settings(
    surface: &mut AgentSurface,
    existing: &AgentSurface,
    network: &crate::config::NetworkConfig,
    removals: &ProtectedResourceRemovals,
) -> Result<(), SurfaceApiError> {
    retain_mcp_http(&mut surface.mcp_http, existing.mcp_http.as_ref());
    let base_retained = !removals.base
        && retain_protected_resource(
            surface
                .access_point
                .caller_authentication
                .as_mut(),
            existing
                .access_point
                .caller_authentication
                .as_ref(),
        );
    let mut retained_aliases = Vec::new();
    let retain_points = |points: &mut [crate::config::agent_surface::TransitPoint],
                         stored: &[crate::config::agent_surface::TransitPoint]| {
        for point in points {
            if let Some(previous) = stored
                .iter()
                .find(|previous| previous.id == point.id)
            {
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
        if !removals
            .variant_ids
            .contains(&variant.id)
            && retain_protected_resource(
                variant
                    .overrides
                    .access_point
                    .as_mut()
                    .and_then(|access_point| {
                        access_point
                            .caller_authentication
                            .as_mut()
                    }),
                stored
                    .and_then(|previous| {
                        previous
                            .overrides
                            .access_point
                            .as_ref()
                    })
                    .and_then(|access_point| {
                        access_point
                            .caller_authentication
                            .as_ref()
                    }),
            )
        {
            retained_aliases.push(variant.alias.clone());
        }
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
    settle_retained_protected_resources(surface, base_retained, &retained_aliases, network)
}

/// PUT carries the whole record, or a variant PUT its whole overrides, but a
/// Surface Builder save may leave out a Transit Point's `source_auth` and
/// `allow_unauthenticated_callers`, and never sends
/// `delegated_credentials_for_fabric_callers`. An omitted
/// `source_auth` means unchanged, as an omitted `mcp_http.authorization` does;
/// removal is explicit: a `null` `source_auth` in the PUT, or a merge PATCH
/// whose Transit Points leave it out. The save rules then refuse a Transit
/// Point left authenticating no caller. An omitted
/// `allow_unauthenticated_callers` is kept while the Transit Point still
/// authenticates no caller, and dropped once it does. An omitted
/// `delegated_credentials_for_fabric_callers` is kept while the Transit Point
/// still requires the transit token, and dropped once it does not.
fn retain_transit_caller_authentication(
    surface: &mut AgentSurface,
    existing: &AgentSurface,
    sent: &serde_json::Value,
) {
    fn sent_points(transit: Option<&serde_json::Value>) -> Option<&serde_json::Value> {
        transit.and_then(|transit| transit.get("points"))
    }
    if let (Some(transit), Some(stored)) = (&mut surface.transit, &existing.transit) {
        retain_transit_points_caller_authentication(
            &mut transit.points,
            &stored.points,
            sent_points(sent.get("transit")),
        );
    }
    for (index, variant) in surface
        .variants
        .iter_mut()
        .enumerate()
    {
        let stored_points = variant_stored_points(existing, &variant.id);
        let points = variant
            .overrides
            .transit
            .as_mut()
            .and_then(|transit| transit.points.as_mut());
        if let (Some(points), Some(stored_points)) = (points, stored_points) {
            let sent_transit = sent
                .get("variants")
                .and_then(|variants| variants.get(index))
                .and_then(|variant| variant.get("overrides"))
                .and_then(|overrides| overrides.get("transit"));
            retain_transit_points_caller_authentication(points, stored_points, sent_points(sent_transit));
        }
    }
}

/// The Transit Points a stored variant's own overrides define, else the stored
/// surface's: a variant without its own list, or one added in this save,
/// inherits them, and the Surface Builder sends it a copy of the surface's list
/// that leaves out each Transit Point's caller authentication.
fn variant_stored_points<'a>(
    existing: &'a AgentSurface,
    variant_id: &str,
) -> Option<&'a [crate::config::agent_surface::TransitPoint]> {
    existing
        .variants
        .iter()
        .find(|previous| previous.id == variant_id)
        .and_then(|previous| {
            previous
                .overrides
                .transit
                .as_ref()
        })
        .and_then(|transit| transit.points.as_deref())
        .or_else(|| {
            existing
                .transit
                .as_ref()
                .map(|transit| transit.points.as_slice())
        })
}

/// The Transit Points a stored variant's own overrides define, without the
/// surface's that a variant without its own list inherits.
fn variant_own_points<'a>(
    existing: &'a AgentSurface,
    variant_id: &str,
) -> Option<&'a [crate::config::agent_surface::TransitPoint]> {
    existing
        .variants
        .iter()
        .find(|stored| stored.id == variant_id)
        .and_then(|stored| {
            stored
                .overrides
                .transit
                .as_ref()
        })
        .and_then(|transit| transit.points.as_deref())
}

/// The Transit Points a variant PUT sends, `points`, with what the save keeps
/// of the stored ones, `sent_points` being their JSON: the ids of external
/// consent Transit Points from the variant's own stored list only
/// ([`carry_point_ids`]), so the copy of an inherited one is a Transit Point
/// of its own, and the caller authentication they leave out from the
/// variant's list or, for a variant that inherits, the surface's
/// ([`variant_stored_points`]).
fn settle_variant_put_points(
    points: &mut [crate::config::agent_surface::TransitPoint],
    existing: &AgentSurface,
    variant_id: &str,
    sent_points: Option<&serde_json::Value>,
) {
    if let Some(own_points) = variant_own_points(existing, variant_id) {
        carry_point_ids(points, own_points, sent_points);
    }
    if let Some(stored_points) = variant_stored_points(existing, variant_id) {
        retain_transit_points_caller_authentication(points, stored_points, sent_points);
    }
}

/// A save that leaves out the `id` of a Transit Point with a
/// `consent_mode: external` binding keeps the id stored for the Transit Point
/// with its alias in the same place, the surface's own list or the variant's
/// of the same id. Without this, every such save would give the Transit Point
/// a new id, and with it a new binding, so its grants by binding would be
/// revoked. Other Transit Points are left as sent: one sent without its id is
/// a new Transit Point, which keeps none of the stored one's settings. `sent`
/// is the JSON the request sent: a PUT's whole body or a merge PATCH's. A list
/// the request did not send keeps its stored ids already.
fn carry_transit_point_ids(
    surface: &mut AgentSurface,
    existing: &AgentSurface,
    sent: &serde_json::Value,
) {
    if let Some(transit) = surface.transit.as_mut() {
        carry_point_ids(&mut transit.points, existing.transit_points(), sent.pointer("/transit/points"));
    }
    for (index, variant) in surface
        .variants
        .iter_mut()
        .enumerate()
    {
        let stored = variant_own_points(existing, &variant.id);
        let points = variant
            .overrides
            .transit
            .as_mut()
            .and_then(|transit| transit.points.as_mut());
        if let (Some(points), Some(stored)) = (points, stored) {
            carry_point_ids(points, stored, sent.pointer(&format!("/variants/{index}/overrides/transit/points")));
        }
    }
}

/// [`carry_transit_point_ids`] for one list: each point with an external
/// consent binding whose JSON in `sent_points` has no `id`, or an empty one,
/// takes the stored id of the point with its alias, unless another point of the
/// list already has that id.
fn carry_point_ids(
    points: &mut [crate::config::agent_surface::TransitPoint],
    stored: &[crate::config::agent_surface::TransitPoint],
    sent_points: Option<&serde_json::Value>,
) {
    let Some(sent_points) = sent_points.and_then(serde_json::Value::as_array) else {
        return;
    };
    let sends_id = |index: usize| {
        sent_points
            .get(index)
            .and_then(|point| point.get("id"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| !id.is_empty())
    };
    let mut taken: std::collections::HashSet<String> = points
        .iter()
        .enumerate()
        .filter(|(index, _)| sends_id(*index))
        .map(|(_, point)| point.id.clone())
        .collect();
    for (index, point) in points.iter_mut().enumerate() {
        let external = point
            .transit_credentials
            .as_ref()
            .is_some_and(|binding| binding.is_external());
        if sends_id(index) || !external {
            continue;
        }
        if let Some(previous) = stored
            .iter()
            .find(|previous| previous.alias == point.alias)
            && taken.insert(previous.id.clone())
        {
            point.id = previous.id.clone();
        }
    }
}

/// Keeps each Transit Point's stored `source_auth`,
/// `allow_unauthenticated_callers` and
/// `delegated_credentials_for_fabric_callers` that `sent_points`, the JSON the
/// request sent for `points`, leaves out; see
/// `retain_transit_caller_authentication`.
fn retain_transit_points_caller_authentication(
    points: &mut [crate::config::agent_surface::TransitPoint],
    stored: &[crate::config::agent_surface::TransitPoint],
    sent_points: Option<&serde_json::Value>,
) {
    for (index, point) in points.iter_mut().enumerate() {
        let Some(previous) = stored
            .iter()
            .find(|previous| previous.id == point.id)
        else {
            continue;
        };
        let sent_point = sent_points.and_then(|points| points.get(index));
        let removes_source_auth = sent_point
            .and_then(|point| point.get("source_auth"))
            .is_some_and(serde_json::Value::is_null);
        if point.source_auth.is_none() && !removes_source_auth {
            point.source_auth = previous.source_auth.clone();
        }
        let sends_open_flag = sent_point.is_some_and(|point| {
            point
                .get("allow_unauthenticated_callers")
                .is_some()
        });
        if !sends_open_flag && previous.allow_unauthenticated_callers && !point.authenticates_callers() {
            point.allow_unauthenticated_callers = true;
        }
        let sends_fabric_caller_delegation = sent_point.is_some_and(|point| {
            point
                .get("delegated_credentials_for_fabric_callers")
                .is_some()
        });
        if !sends_fabric_caller_delegation
            && previous.delegated_credentials_for_fabric_callers
            && point.require_transit_token
        {
            point.delegated_credentials_for_fabric_callers = true;
        }
    }
}

/// PUT carries the whole record, so an omitted `mcp_http` — or an `mcp_http`
/// that omits `authorization` — means "unchanged", never "remove". Resource
/// Server authorization is enforced for every MCP revision, so dropping it on
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

/// PUT carries the whole record, and the dashboard rebuilds
/// `caller_authentication` from its methods alone, so a `caller_authentication`
/// that omits `protected_resource` means "unchanged". Dropping it on an
/// unrelated edit would silently switch off the discovery the operator set up.
/// Removal is explicit: a `null`, sent with PUT or PATCH. Returns whether a
/// stored setting was restored.
fn retain_protected_resource(
    incoming: Option<&mut crate::config::agent_surface::CallerAuthentication>,
    previous: Option<&crate::config::agent_surface::CallerAuthentication>,
) -> bool {
    if let (Some(incoming), Some(previous)) = (incoming, previous)
        && incoming
            .protected_resource
            .is_none()
    {
        incoming.protected_resource = previous
            .protected_resource
            .clone();
        return incoming
            .protected_resource
            .is_some();
    }
    false
}

/// A restored `protected_resource` the Access Point would no longer serve.
/// When the setting itself no longer fits, after the dashboard switched the
/// method, set `forward_header` or audiences, or moved the protocol off MCP, it
/// is dropped with a warning: the client did not send it, and refusing the save
/// over it would leave the client no way out. When it no longer fits the
/// Access Point, for example after a route or listen address change, the save
/// is refused instead: dropping it would leave the JWT Bearer method checking
/// no audience, so the client must send a new resource or `null`. A setting
/// sent in the request is validated and refused as usual.
fn settle_retained_protected_resources(
    surface: &mut AgentSurface,
    base_retained: bool,
    retained_aliases: &[String],
    network: &crate::config::NetworkConfig,
) -> Result<(), SurfaceApiError> {
    // `true` drops the setting; a setting the Access Point cannot serve
    // refuses the save.
    let settle = |resolved: &AgentSurface, alias: Option<&str>| -> Result<bool, SurfaceApiError> {
        if resolved
            .validate_protected_resource()
            .is_err()
        {
            warn!(
                surface_id = %resolved.surface_id,
                variant = alias.unwrap_or(""),
                "Dropped a stored protected_resource the edited Access Point no longer supports; its JWT Bearer \
                 method now checks audiences only if the edit set them"
            );
            return Ok(true);
        }
        match crate::protocols::protected_resource::access_point_protected_resource(resolved, alias, network) {
            Some(Err(reason)) => Err(SurfaceApiError::BadRequest(format!(
                "{}access_point.caller_authentication.protected_resource: the stored setting no longer fits this \
                 Access Point ({reason}); send protected_resource with a new resource, or null to turn discovery off",
                alias.map_or_else(String::new, |alias| format!("variant '{alias}': "))
            ))),
            _ => Ok(false),
        }
    };
    if base_retained
        && settle(surface, None)?
        && let Some(caller) = surface
            .access_point
            .caller_authentication
            .as_mut()
    {
        caller.protected_resource = None;
    }
    for alias in retained_aliases {
        // A disabled variant does not resolve and is not validated on save.
        let Ok(resolved) = surface.resolve_variant(Some(alias)) else {
            continue;
        };
        if settle(&resolved, Some(alias))?
            && let Some(caller) = surface
                .variants
                .iter_mut()
                .find(|variant| &variant.alias == alias)
                .and_then(|variant| {
                    variant
                        .overrides
                        .access_point
                        .as_mut()
                })
                .and_then(|access_point| {
                    access_point
                        .caller_authentication
                        .as_mut()
                })
        {
            caller.protected_resource = None;
        }
    }
    Ok(())
}

/// The authorization servers an Access Point advertises (base and each enabled
/// variant) must be exactly the issuer its JWT verification strategy trusts.
/// Only that issuer's tokens are accepted, so a client following metadata that
/// names another server, even listed beside it, gets tokens that are always
/// refused and loops on the 401 challenge. `validate_surface_references` has already checked that the
/// strategy exists and that the caller may use it.
async fn validate_protected_resource_issuers(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    let variants = surface
        .variants
        .iter()
        .filter_map(|variant| {
            surface
                .resolve_variant(Some(&variant.alias))
                .ok()
                .map(|resolved| (format!("variant '{}': ", variant.alias), resolved))
        });
    for (label, resolved) in std::iter::once((String::new(), surface.clone())).chain(variants) {
        let (Some(protected), Some(crate::source_auth::SourceAuthConfig::JwtBearer(jwt))) = (
            resolved.protected_resource(),
            resolved
                .source_auth_methods()
                .first(),
        ) else {
            continue;
        };
        let strategy = state
            .jwt_verification_strategy_store
            .as_ref()
            .ok_or_else(|| SurfaceApiError::InternalError("JWT verification strategy store not initialized".into()))?
            .get(&jwt.jwt_verification_strategy_id)
            .await
            .map_err(|e| SurfaceApiError::InternalError(format!("Failed to load the JWT verification strategy: {e}")))?
            .ok_or_else(|| SurfaceApiError::BadRequest(format!("{label}JWT verification strategy not found")))?;
        if protected.authorization_servers
            != [strategy
                .expected_issuer
                .as_str()]
        {
            return Err(SurfaceApiError::BadRequest(format!(
                "{label}access_point.caller_authentication.protected_resource: authorization_servers must be \
                 exactly [\"{}\"], the issuer the JWT verification strategy trusts: tokens from any other server \
                 are refused",
                strategy.expected_issuer
            )));
        }
    }
    Ok(())
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
    resource_scoped: bool,
    actor: Option<&crate::delegation_vault::audit::AuditCallerContext>,
) -> Result<AgentSurface, SurfaceApiError> {
    drop_inbound_api_key_ids(&mut surface);
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
    validate_api_key_identities(&surface, "")?;
    reject_public_predicate_route(&surface)?;
    if surface
        .access_point
        .public
        .is_none()
    {
        surface.access_point.public = existing.and_then(|existing| existing.access_point.public);
    }
    surface.apply_public_access();

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
    validate_transit_points(
        &mut surface,
        state
            .network_config
            .transit_token_max_lifetime_secs,
        existing,
    )?;
    super::surface_tenancy::validate_surface_references(state, &surface, existing, context, scope).await?;
    super::surface_tenancy::validate_external_consent_bindings(state, &surface).await?;
    validate_listen_path_collisions(&surface, store, &state.network_config).await?;
    validate_access_point_route_collisions(&surface, store, &state.network_config).await?;
    validate_surface_payment_policies(&mut surface).await?;
    validate_surface_mpp_posture(&surface)?;
    validate_delegation_source_auth(&surface)?;
    validate_surface_mcp_tool_gating(&surface)?;
    validate_resolved_variants(&surface)?;
    validate_trust_checks(&surface)?;
    reject_target_trust_checks_unless_target_runs_them(&surface)?;
    validate_workload_binding_config(&surface)?;
    validate_source_auth(&surface, existing)?;
    surface
        .validate_mcp_metadata()
        .map_err(SurfaceApiError::BadRequest)?;
    normalize_a2a_settings(&mut surface, existing).map_err(SurfaceApiError::BadRequest)?;
    let stored_a2a = existing.and_then(|existing| {
        existing
            .access_point
            .a2a
            .as_ref()
    });
    refuse_validation_off_by_scoped_caller(&surface, stored_a2a, context, scope, resource_scoped)?;
    validate_protected_resource_issuers(state, &surface).await?;
    validate_mcp_resource_declarations(state, &surface).await?;
    let allowlist = crate::egress::bdd_egress_allowlist();
    surface.trust_check_split = surface.has_trust_check_lists();
    surface.transit_point_source_auth = surface.has_transit_point_source_auth();
    super::surface_grants::write_surface(
        &super::surface_grants::GrantRemoval::of(state, allowlist.as_deref(), actor),
        store.clone(),
        &surface.surface_id,
        super::surface_grants::Stored::Any,
        Some(&surface),
        || async {
            store
                .save(&surface)
                .await
                .map_err(|e| SurfaceApiError::InternalError(format!("Failed to save surface: {}", e)))
        },
    )
    .await?;

    info!("Updated agent surface '{}' (surface_id={})", surface.name, surface.surface_id);

    if existing.is_some_and(|existing| existing.name != surface.name) {
        crate::trust_registries::reference_fields::spawn_surface_rename_publish(surface.clone());
    }

    if existing.is_some_and(|existing| trust_recorder_changed(existing, &surface))
        && let Some(recorder_status) = global_store()
    {
        recorder_status
            .clear_surface(&surface.surface_id)
            .await;
    }

    apply_surface_change(state, SurfaceChange::Upsert(&surface)).await;

    Ok(surface)
}

/// Whether an edit added, removed or changed the entries of the surface's Trust Recorder.
/// No recorder and a recorder without entries are the same.
fn trust_recorder_changed(
    before: &AgentSurface,
    after: &AgentSurface,
) -> bool {
    let entries = |surface: &AgentSurface| {
        serde_json::to_value(
            surface
                .trust_recorder()
                .map(|recorder| recorder.entries.as_slice())
                .unwrap_or_default(),
        )
        .unwrap_or_default()
    };
    entries(before) != entries(after)
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
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<SavedSurface, SurfaceApiError> {
    require_merge_patch_content_type(&headers)?;

    if body.is_empty() {
        return Err(SurfaceApiError::BadRequest("PATCH body must not be empty".to_string()));
    }
    let mut patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| SurfaceApiError::BadRequest(format!("PATCH body is not valid JSON: {}", e)))?;
    drop_access_point_status(&mut patch);
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
    if !declares_split(&patch) {
        reject_undeclared_trust_check_edit(patch_touches_trust_checks(&patch, &existing), &existing)?;
    }

    let mut surface: AgentSurface = serde_json::from_value(merged)
        .map_err(|e| SurfaceApiError::BadRequest(format!("Merged surface failed to deserialise: {}", e)))?;
    surface.surface_id = surface_id.clone();
    carry_transit_point_ids(&mut surface, &existing, &patch);
    if patch_sets_a2a_settings(&patch) {
        refuse_a2a_settings_sent_on_other_protocols(&surface)?;
    }

    let saved = validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
        resource_scoped(&delegation),
        management_actor(&caller, &delegation).as_ref(),
    )
    .await?;
    Ok((save_warnings(&state, &saved).await, Json(saved.into())))
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
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<SavedSurface, SurfaceApiError> {
    require_merge_patch_content_type(&headers)?;

    if body.is_empty() {
        return Err(SurfaceApiError::BadRequest("PATCH body must not be empty".to_string()));
    }
    let mut patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| SurfaceApiError::BadRequest(format!("PATCH body is not valid JSON: {}", e)))?;
    drop_access_point_status(&mut patch);
    let Some(patch_obj) = patch.as_object_mut() else {
        return Err(SurfaceApiError::BadRequest("PATCH body must be a JSON object at the top level".to_string()));
    };
    let declared = patch_obj
        .remove("trust_check_split")
        .is_some_and(|marker| marker == serde_json::Value::Bool(true));

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
    if !declared {
        reject_undeclared_trust_check_edit(variant_patch_touches_trust_checks(&patch), &existing)?;
    }

    let mut merged_variant = serde_json::to_value(&existing.variants[variant_index])
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to serialise variant for merge: {}", e)))?;
    json_patch::merge(&mut merged_variant, &patch);

    if let Some(obj) = merged_variant.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(variant_id.clone()));
    }

    let mut new_variant: crate::config::agent_surface_variants::SurfaceVariant = serde_json::from_value(merged_variant)
        .map_err(|e| SurfaceApiError::BadRequest(format!("Merged variant failed to deserialise: {}", e)))?;
    if let (Some(points), Some(stored)) = (
        new_variant
            .overrides
            .transit
            .as_mut()
            .and_then(|transit| transit.points.as_mut()),
        existing.variants[variant_index]
            .overrides
            .transit
            .as_ref()
            .and_then(|transit| transit.points.as_deref()),
    ) {
        carry_point_ids(points, stored, patch.pointer("/overrides/transit/points"));
    }

    let mut surface = existing.clone();
    surface.variants[variant_index] = new_variant;

    let saved = validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
        resource_scoped(&delegation),
        management_actor(&caller, &delegation).as_ref(),
    )
    .await?;
    Ok((save_warnings(&state, &saved).await, Json(saved.into())))
}

/// Delete an agent surface (hard delete: removes from cache + filesystem).
pub async fn delete_surface(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
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
            let allowlist = crate::egress::bdd_egress_allowlist();
            let actor = management_actor(&caller, &delegation);
            super::surface_grants::write_surface(
                &super::surface_grants::GrantRemoval::of(&state, allowlist.as_deref(), actor.as_ref()),
                store.clone(),
                &surface_id,
                super::surface_grants::Stored::Any,
                None,
                || async {
                    store
                        .delete(&surface_id)
                        .await
                        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to delete surface: {}", e)))
                },
            )
            .await?;

            info!("Deleted agent surface '{}' (surface_id={})", surface.name, surface_id);

            if let Some(recorder_status) = global_store() {
                recorder_status
                    .clear_surface(&surface_id)
                    .await;
            }
            apply_surface_change(&state, SurfaceChange::Delete(&surface_id)).await;

            Ok(Json(DeleteSurfaceResponse {
                success: true,
                message: format!("Surface '{}' deleted", surface_id),
            }))
        }
        Some(surface)
            if surface_visible(
                surface.tenant_id.as_deref(),
                &surface_id,
                tenant_context(&context),
                resource_scope(&scope),
            ) =>
        {
            Err(SurfaceApiError::Forbidden("surface is outside this token's permitted scope".to_string()))
        }
        _ => Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id))),
    }
}

/// A surface, or one of its variants, as the admin API returns it, with the
/// status of the Access Point it serves. The status is derived on every
/// response, never stored, and dropped from a write body that sends it back.
#[derive(Debug, Serialize)]
pub struct SurfaceResponse<T> {
    #[serde(flatten)]
    pub resource: T,
    pub access_point_status: AccessPointStatus,
}

impl From<AgentSurface> for SurfaceResponse<AgentSurface> {
    /// The status is that of the surface its URL serves: the default variant,
    /// when there is one ([`AgentSurface::served_access_point_status`]).
    fn from(surface: AgentSurface) -> Self {
        Self {
            access_point_status: surface.served_access_point_status(),
            resource: surface,
        }
    }
}

impl SurfaceResponse<SurfaceVariant> {
    /// `variant` of `surface`, with the status of the Access Point the variant
    /// serves.
    fn variant(
        variant: SurfaceVariant,
        surface: &AgentSurface,
    ) -> Self {
        Self {
            access_point_status: surface
                .serve_selected(Some(&variant))
                .surface
                .access_point_status(),
            resource: variant,
        }
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
///
/// Holds the surface reload lock; see [`apply_surface_change_while_locked`].
async fn apply_surface_change(
    state: &IdentityApiState,
    change: SurfaceChange<'_>,
) {
    let _reloading = state
        .surface_reload_lock
        .lock()
        .await;
    apply_surface_change_while_locked(state, change).await;
}

/// [`apply_surface_change`] for a caller already holding the surface reload lock.
async fn apply_surface_change_while_locked(
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

    let provider_key_gate = crate::identity::provider_key_gate::gate();
    let changed_id = match change {
        SurfaceChange::Upsert(surface) => surface.surface_id.as_str(),
        SurfaceChange::Delete(id) => id,
    };
    provider_key_gate.owner_changed(changed_id);
    match change {
        SurfaceChange::Upsert(surface) if surface.status == crate::config::agent_surface::SurfaceStatus::Active => {
            provider_key_gate
                .admit(surface)
                .await
        }
        SurfaceChange::Upsert(surface) => provider_key_gate.forget(&surface.surface_id),
        SurfaceChange::Delete(id) => provider_key_gate.forget(id),
    }

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

    // The reload paths above register the ChannelMapping with the runtime
    // but do NOT invoke SurfacePolicyManager — so without this, an active
    // surface with `policy_definition_id` set would have `opa_enabled=true`
    // on the channel but no compiled engine, producing the misleading
    // "OPA policy enforcement is enabled but no policy is loaded" 403.
    refresh_surface_policies(&state.policy_manager, change).await;
}

/// Compile or refresh the OPA policy of an upserted active surface, or evict
/// every policy, tool gate and rate limiter of a deleted or inactive one.
async fn refresh_surface_policies(
    policy_manager: &crate::policies::SurfacePolicyManager,
    change: SurfaceChange<'_>,
) {
    match change {
        SurfaceChange::Upsert(surface) if surface.status == crate::config::agent_surface::SurfaceStatus::Active => {
            if let Err(e) = policy_manager
                .update_channel_policy(surface)
                .await
            {
                warn!("Failed to compile OPA policy for surface '{}': {e}", surface.surface_id);
            }
        }
        SurfaceChange::Upsert(surface) => {
            policy_manager
                .remove_channel(&surface.surface_id)
                .await;
        }
        SurfaceChange::Delete(id) => {
            policy_manager
                .remove_channel(id)
                .await;
        }
    }
}

/// Apply the surface as currently stored, or remove it when it is no longer stored.
/// The surface reload lock is held from the read until the change is applied, so a
/// change raised before a configuration reload cannot overwrite what that reload
/// applied. An A2A surface stored without its own settings is served with the
/// carried-over ones, as a load gives them, and one whose caller authentication
/// methods break the rules for several methods with its first method alone, as
/// a load trims it; nothing is written back, because the load that gives the
/// settings or the trim also stores them.
pub(crate) async fn apply_surface_from_storage(
    state: &IdentityApiState,
    surface_id: &str,
) {
    let Some(store) = state
        .agent_surface_store
        .as_deref()
    else {
        return;
    };
    let _reloading = state
        .surface_reload_lock
        .lock()
        .await;
    let surface = match store.get(surface_id).await {
        Ok(Some(surface)) => surface,
        Ok(None) => {
            apply_surface_change_while_locked(state, SurfaceChange::Delete(surface_id)).await;
            return;
        }
        Err(error) => {
            error!(
                surface = %surface_id,
                "Could not read the surface to apply a change from storage: {error}. \
                 Call POST /v1/config/reload for the change to take effect."
            );
            return;
        }
    };
    let mut surfaces = vec![surface];
    crate::surfaces::carry_over_a2a_settings(store, &mut surfaces, false, || {
        crate::surfaces::RetiredA2aSwitches::read(&state.bootstrap_config)
    })
    .await;
    crate::config::fall_back_to_first_source_auth_methods_in_memory(&mut surfaces);
    for surface in &surfaces {
        apply_surface_change_while_locked(state, SurfaceChange::Upsert(surface)).await;
    }
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
    /// `true` declares `overrides` per-Transit-Point; without it, a body that
    /// touches the Trust Check lists of a surface that keeps them per Transit
    /// Point is refused.
    #[serde(default)]
    pub trust_check_split: bool,
}

/// May this caller change or delete the surface? Reading an operator's surface
/// through a tenant PAT is allowed; changing it is not.
fn surface_visible(
    tenant_id: Option<&str>,
    surface_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_access(tenant_id, context) && scope_allows_resource(scope, context, ResourceKind::Surfaces, surface_id)
}

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

    if !surface_visible(surface.tenant_id.as_deref(), surface_id, context, scope) {
        return Err(SurfaceApiError::NotFound(format!("Surface '{}' not found", surface_id)));
    }
    if access == SurfaceAccess::Mutate && !surface_writable(surface.tenant_id.as_deref(), surface_id, context, scope) {
        return Err(SurfaceApiError::Forbidden("surface is outside this token's permitted scope".to_string()));
    }

    Ok((store, surface))
}

/// Another variant's `overrides`, as a new variant starts from them, and
/// whether the Access Point Target's binding with external consent was left
/// out. A binding with external consent is kept in one place: a Transit Point
/// that has one gets an id of its own, and its own grants once consented, and
/// the Access Point Target's binding is not copied, so the new variant keeps
/// the rest of the copied `outbound_credentials` without it.
fn copied_overrides(mut overrides: SurfaceOverrides) -> (SurfaceOverrides, bool) {
    for point in overrides
        .transit
        .iter_mut()
        .filter_map(|transit| transit.points.as_mut())
        .flatten()
        .filter(|point| {
            point
                .transit_credentials
                .as_ref()
                .is_some_and(|binding| binding.is_external())
        })
    {
        point.id = uuid::Uuid::new_v4().to_string();
    }
    let mut left_out_target_binding = false;
    if let Some(bindings) = overrides
        .outbound_credentials
        .as_mut()
    {
        let copied = bindings.len();
        bindings.retain(|binding| !binding.is_external());
        left_out_target_binding = bindings.len() != copied;
    }
    (overrides, left_out_target_binding)
}

/// What a variant created from one holding the Access Point Target's binding
/// with external consent is told: it is created disabled, since it keeps the
/// copied Target, which it would send requests without the grant, its
/// callers' own headers among them.
fn copied_target_binding_warning(alias: &str) -> String {
    format!(
        "Variant '{alias}' is created disabled: the variant it was copied from holds the Access Point Target's \
         consent_mode external binding, which is kept in one place and not copied, so this variant would send its \
         Target requests without the grant; give it another Target or a credential of its own before enabling it"
    )
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
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
    Json(body): Json<CreateVariantRequest>,
) -> Result<(StatusCode, axum::http::HeaderMap, Json<SurfaceResponse<SurfaceVariant>>), SurfaceApiError> {
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
    let (seed_overrides, left_out_target_binding) = copied_overrides(seed_overrides);

    let new_variant = SurfaceVariant {
        id: uuid::Uuid::new_v4().to_string(),
        alias: body.alias,
        name: body.name,
        description: body.description,
        enabled: !left_out_target_binding,
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
        resource_scoped(&delegation),
        management_actor(&caller, &delegation).as_ref(),
    )
    .await?;
    let new_variant = saved
        .variants
        .iter()
        .find(|variant| variant.id == new_variant.id)
        .cloned()
        .ok_or_else(|| SurfaceApiError::InternalError("Created variant disappeared during validation".to_string()))?;

    info!("Created variant '{}' (id={}) on surface '{}'", new_variant.alias, new_variant.id, surface_id);

    let mut warnings = save_warnings(&state, &saved).await;
    if left_out_target_binding && let Some(value) = warning_header(&copied_target_binding_warning(&new_variant.alias)) {
        warnings.append(axum::http::header::WARNING, value);
    }
    Ok((StatusCode::CREATED, warnings, Json(SurfaceResponse::variant(new_variant, &saved))))
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
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
    JsonWithSent(body, sent): JsonWithSent<UpdateVariantRequest>,
) -> Result<(axum::http::HeaderMap, Json<SurfaceResponse<SurfaceVariant>>), SurfaceApiError> {
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
    let stored_variant_lists = existing
        .variants
        .iter()
        .any(|stored| stored.id == variant_id && variant_holds_transit_point_lists(stored));
    let touches_trust_checks = body
        .overrides
        .as_ref()
        .is_some_and(|overrides| {
            stored_variant_lists
                || overrides
                    .target
                    .as_ref()
                    .is_some_and(|target| {
                        target
                            .trust_check_list
                            .is_some()
                    })
                || overrides
                    .transit
                    .as_ref()
                    .is_some_and(|transit| transit.points.is_some())
        });
    if !body.trust_check_split {
        reject_undeclared_trust_check_edit(touches_trust_checks, &existing)?;
    }
    // New overrides replace the stored ones, but keep the stored discovery
    // setting unless they remove it, and the Transit Points' caller
    // authentication they leave out, as a PUT of the whole surface does.
    let mut retained = Vec::new();
    if let Some(mut overrides) = body.overrides {
        if !removes_protected_resource(sent.pointer("/overrides/access_point"))
            && retain_protected_resource(
                overrides
                    .access_point
                    .as_mut()
                    .and_then(|access_point| {
                        access_point
                            .caller_authentication
                            .as_mut()
                    }),
                variant
                    .overrides
                    .access_point
                    .as_ref()
                    .and_then(|access_point| {
                        access_point
                            .caller_authentication
                            .as_ref()
                    }),
            )
        {
            retained.push(variant.alias.clone());
        }
        if let Some(points) = overrides
            .transit
            .as_mut()
            .and_then(|transit| transit.points.as_mut())
        {
            settle_variant_put_points(points, &existing, &variant_id, sent.pointer("/overrides/transit/points"));
        }
        variant.overrides = overrides;
    }
    settle_retained_protected_resources(&mut surface, false, &retained, &state.network_config)?;

    let saved = validate_and_save_surface(
        &state,
        &store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
        resource_scoped(&delegation),
        management_actor(&caller, &delegation).as_ref(),
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

    Ok((save_warnings(&state, &saved).await, Json(SurfaceResponse::variant(updated, &saved))))
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
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
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
        resource_scoped(&delegation),
        management_actor(&caller, &delegation).as_ref(),
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
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
) -> Result<SavedSurface, SurfaceApiError> {
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
        resource_scoped(&delegation),
        management_actor(&caller, &delegation).as_ref(),
    )
    .await?;

    info!("Promoted variant '{}' (id={}) to default on surface '{}'", variant_alias, variant_id, surface_id);

    Ok((save_warnings(&state, &saved).await, Json(saved.into())))
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
) -> Result<Json<SurfaceResponse<AgentSurface>>, SurfaceApiError> {
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

    Ok(Json(resolved.into()))
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::config::agent_surface::A2aValidation;
    use crate::config::agent_surface::{AccessPoint, IdentityInjectionConfig, SurfaceProtocol, SurfaceStatus, Target};
    use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant, TargetOverrides};
    use crate::protocols::protected_resource::fixtures::discovery_network;

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
        retain_mcp_settings(&mut rewritten, &existing, &discovery_network(), &ProtectedResourceRemovals::default())
            .unwrap();
        let retained = rewritten
            .mcp_http
            .expect("mcp_http stays present");
        assert_eq!(retained.authorization, Some(authorization));
        assert_eq!(retained.allowed_origins, vec!["https://app.example".to_string()]);

        // Omitting the block entirely keeps the stored one unchanged.
        let mut omitted = base_surface();
        omitted.mcp_http = None;
        retain_mcp_settings(&mut omitted, &existing, &discovery_network(), &ProtectedResourceRemovals::default())
            .unwrap();
        assert_eq!(omitted.mcp_http, existing.mcp_http);

        // A surface that never had authorization does not gain one.
        let mut fresh = base_surface();
        fresh.mcp_http = Some(crate::config::McpHttpConfig::default());
        retain_mcp_settings(&mut fresh, &base_surface(), &discovery_network(), &ProtectedResourceRemovals::default())
            .unwrap();
        assert_eq!(
            fresh
                .mcp_http
                .and_then(|http| http.authorization),
            None
        );
    }

    #[test]
    fn a_put_that_rebuilds_caller_authentication_keeps_the_protected_resource_it_still_supports() {
        let protected = serde_json::json!({
            "resource": "https://gateway.example/mcp", "authorization_servers": ["https://idp.example"]
        });
        let methods =
            serde_json::json!([{"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []}]);
        let caller_authentication = |with_resource: bool| -> crate::config::agent_surface::CallerAuthentication {
            let mut value = serde_json::json!({"methods": methods});
            if with_resource {
                value["protected_resource"] = protected.clone();
            }
            serde_json::from_value(value).unwrap()
        };
        let variant = |with_resource: bool| -> SurfaceVariant {
            serde_json::from_value(serde_json::json!({
                "id": "v-beta", "alias": "beta", "name": "beta", "enabled": true,
                "overrides": {"access_point": {"caller_authentication": caller_authentication(with_resource)}}
            }))
            .unwrap()
        };
        let stored_resource = |surface: &AgentSurface| {
            (
                surface
                    .protected_resource()
                    .cloned(),
                surface.variants[0]
                    .overrides
                    .access_point
                    .as_ref()
                    .and_then(|access_point| {
                        access_point
                            .caller_authentication
                            .as_ref()
                    })
                    .and_then(|caller| {
                        caller
                            .protected_resource
                            .clone()
                    }),
            )
        };
        let mcp_surface = || {
            let mut surface = base_surface();
            surface.access_point.protocol = SurfaceProtocol::Mcp;
            surface
                .access_point
                .listen_address = "https://gateway.example".to_string();
            surface.access_point.route = "/mcp".to_string();
            surface
        };
        let mut existing = mcp_surface();
        existing
            .access_point
            .caller_authentication = Some(caller_authentication(true));
        existing.variants = vec![variant(true)];
        let expected = Some(
            serde_json::from_value::<crate::protocols::protected_resource::ProtectedResourceConfig>(protected.clone())
                .unwrap(),
        );

        // The dashboard sends caller authentication rebuilt from its methods.
        let mut rewritten = mcp_surface();
        rewritten
            .access_point
            .caller_authentication = Some(caller_authentication(false));
        rewritten.variants = vec![variant(false)];
        retain_mcp_settings(&mut rewritten, &existing, &discovery_network(), &ProtectedResourceRemovals::default())
            .unwrap();
        assert_eq!(stored_resource(&rewritten), (expected.clone(), expected.clone()));

        // Removing caller authentication does not bring the setting back.
        let mut removed = mcp_surface();
        removed.variants = vec![variant(false)];
        retain_mcp_settings(&mut removed, &existing, &discovery_network(), &ProtectedResourceRemovals::default())
            .unwrap();
        assert!(
            removed
                .access_point
                .caller_authentication
                .is_none()
        );

        // A surface that never published one does not gain one.
        let mut fresh = mcp_surface();
        fresh
            .access_point
            .caller_authentication = Some(caller_authentication(false));
        fresh.variants = vec![variant(false)];
        let mut never = mcp_surface();
        never.variants = vec![variant(false)];
        retain_mcp_settings(&mut fresh, &never, &discovery_network(), &ProtectedResourceRemovals::default()).unwrap();
        assert_eq!(stored_resource(&fresh), (None, None));

        // An edit the stored setting no longer fits drops it instead of
        // refusing the save over a field the dashboard cannot show.
        let other_method = serde_json::json!([
            {"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}
        ]);
        let forwarding = serde_json::json!([
            {"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "forward_header": true}
        ]);
        let audience = serde_json::json!([
            {"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": ["https://gateway.example/mcp"]}
        ]);
        for (change, changed_methods) in
            [("method", other_method), ("forward_header", forwarding), ("audiences", audience)]
        {
            let changed: crate::config::agent_surface::CallerAuthentication =
                serde_json::from_value(serde_json::json!({"methods": changed_methods})).unwrap();
            let mut switched = mcp_surface();
            switched
                .access_point
                .caller_authentication = Some(changed.clone());
            switched.variants = vec![variant(false)];
            switched.variants[0]
                .overrides
                .access_point
                .as_mut()
                .unwrap()
                .caller_authentication = Some(changed);
            retain_mcp_settings(&mut switched, &existing, &discovery_network(), &ProtectedResourceRemovals::default())
                .unwrap();
            assert_eq!(stored_resource(&switched), (None, None), "{change}");
        }
        // An edit that moves the Access Point off the resource, to another route
        // or a listener without its public origin, is refused: dropping the
        // setting would leave the method checking no audience.
        for (change, moved) in [("route", "/mcp/beta"), ("listen_address", "http://localhost:9999")] {
            let mut edited = mcp_surface();
            match change {
                "route" => edited.access_point.route = moved.to_string(),
                _ => {
                    edited
                        .access_point
                        .listen_address = moved.to_string()
                }
            }
            edited
                .access_point
                .caller_authentication = Some(caller_authentication(false));
            edited.variants = vec![variant(false)];
            let Err(SurfaceApiError::BadRequest(refused)) = retain_mcp_settings(
                &mut edited,
                &existing,
                &discovery_network(),
                &ProtectedResourceRemovals::default(),
            ) else {
                panic!("{change}: expected a refusal");
            };
            assert!(
                refused.starts_with(
                    "access_point.caller_authentication.protected_resource: the stored setting no longer fits"
                ) && refused.contains("or null to turn discovery off"),
                "{change}: {refused}"
            );
        }
        let mut a2a = mcp_surface();
        a2a.access_point.protocol = SurfaceProtocol::A2a;
        a2a.access_point
            .caller_authentication = Some(caller_authentication(false));
        a2a.variants = vec![variant(false)];
        retain_mcp_settings(&mut a2a, &existing, &discovery_network(), &ProtectedResourceRemovals::default()).unwrap();
        assert_eq!(stored_resource(&a2a), (None, None));

        // A setting the request itself sends is kept, for validation to refuse.
        let mut sent = mcp_surface();
        sent.access_point
            .caller_authentication = Some(
            serde_json::from_value(serde_json::json!({
                "methods": [{"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}],
                "protected_resource": protected.clone()
            }))
            .unwrap(),
        );
        retain_mcp_settings(&mut sent, &existing, &discovery_network(), &ProtectedResourceRemovals::default()).unwrap();
        assert_eq!(
            sent.protected_resource()
                .cloned(),
            expected
        );
    }

    #[test]
    fn a_put_that_sends_a_null_protected_resource_removes_it() {
        let protected = serde_json::json!({
            "resource": "https://gateway.example/mcp", "authorization_servers": ["https://idp.example"]
        });
        let caller = |protected_resource: Option<serde_json::Value>| {
            let mut caller = serde_json::json!({"methods": [
                {"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []}
            ]});
            if let Some(protected_resource) = protected_resource {
                caller["protected_resource"] = protected_resource;
            }
            caller
        };
        let variant = |id: &str, protected_resource: Option<serde_json::Value>| {
            serde_json::json!({"id": id, "alias": id, "name": id, "enabled": true,
                "overrides": {"access_point": {"caller_authentication": caller(protected_resource)}}})
        };
        let surface =
            |base: Option<serde_json::Value>, beta: Option<serde_json::Value>, gamma: Option<serde_json::Value>| {
                serde_json::json!({
                    "surface_id": "s-1", "name": "s-1",
                    "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp",
                        "caller_authentication": caller(base)},
                    "target": {"endpoint": "https://tools.example/mcp"},
                    "variants": [variant("beta", beta), variant("gamma", gamma)]
                })
            };
        let existing: AgentSurface =
            serde_json::from_value(surface(Some(protected.clone()), Some(protected.clone()), Some(protected.clone())))
                .unwrap();
        let resources = |surface: &AgentSurface| {
            let variants = surface
                .variants
                .iter()
                .map(|variant| {
                    variant
                        .overrides
                        .access_point
                        .as_ref()
                        .and_then(|access_point| {
                            access_point
                                .caller_authentication
                                .as_ref()
                        })
                        .is_some_and(|caller| {
                            caller
                                .protected_resource
                                .is_some()
                        })
                })
                .collect::<Vec<_>>();
            (
                surface
                    .protected_resource()
                    .is_some(),
                variants,
            )
        };

        // A null removes the setting where it is sent; an omitted one is kept.
        let body = surface(Some(serde_json::Value::Null), Some(serde_json::Value::Null), None);
        let removals = ProtectedResourceRemovals::of(&body);
        assert!(removals.base);
        assert_eq!(removals.variant_ids, vec!["beta".to_string()]);
        let mut put: AgentSurface = serde_json::from_value(body).unwrap();
        retain_mcp_settings(&mut put, &existing, &discovery_network(), &removals).unwrap();
        assert_eq!(resources(&put), (false, vec![false, true]));

        // Also with a route or listen address change, which a restored
        // setting would no longer fit: a removed one is never restored.
        for (field, moved) in [("route", "/mcp/moved"), ("listen_address", "http://localhost:9999")] {
            let mut body = surface(Some(serde_json::Value::Null), Some(serde_json::Value::Null), None);
            body["access_point"][field] = serde_json::json!(moved);
            body["variants"]
                .as_array_mut()
                .unwrap()
                .truncate(1);
            let removals = ProtectedResourceRemovals::of(&body);
            let mut put: AgentSurface = serde_json::from_value(body).unwrap();
            retain_mcp_settings(&mut put, &existing, &discovery_network(), &removals).unwrap();
            assert_eq!(resources(&put), (false, vec![false]), "{field}");
        }

        // Without a null, a PUT removes nothing.
        let body = surface(None, None, None);
        let removals = ProtectedResourceRemovals::of(&body);
        assert!(
            !removals.base
                && removals
                    .variant_ids
                    .is_empty()
        );
        let mut put: AgentSurface = serde_json::from_value(body).unwrap();
        retain_mcp_settings(&mut put, &existing, &discovery_network(), &removals).unwrap();
        assert_eq!(resources(&put), (true, vec![true, true]));
    }

    fn surface_with_transit_points(
        points: serde_json::Value,
        variant_points: serde_json::Value,
    ) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "name": "callers",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/callers", "protocol": "a2a" },
            "target": { "endpoint": "https://agent.internal" },
            "transit": { "outbound_listen_address": "http://localhost:9111", "points": points },
            "variants": [{ "id": "candidate", "alias": "candidate", "name": "Candidate", "overrides": {
                "transit": { "points": variant_points }
            }}]
        }))
        .unwrap()
    }

    #[test]
    fn two_transit_points_with_one_id_are_refused_in_the_surface_and_in_a_variant() {
        let point = |id: &str, alias: &str| serde_json::json!({ "id": id, "alias": alias, "target_endpoint": format!("https://{alias}.example") });
        let distinct = serde_json::json!([point("a-id", "partner"), point("b-id", "peer")]);
        let shared = serde_json::json!([point("a-id", "partner"), point("a-id", "peer")]);
        for (points, variant_points, expected) in [
            (
                shared.clone(),
                distinct.clone(),
                "transit.points[1]: duplicate id 'a-id'. Each transit point id must be unique within the surface.",
            ),
            (
                distinct.clone(),
                shared,
                "variants['candidate'].transit.points[1]: duplicate id 'a-id'. Each transit point id must be unique \
                 within the surface.",
            ),
        ] {
            let mut surface = surface_with_transit_points(points, variant_points);
            match validate_transit_points(&mut surface, 30, None) {
                Err(SurfaceApiError::BadRequest(message)) => assert_eq!(message, expected),
                other => panic!("expected a 400, got {other:?}"),
            }
        }
        let mut surface = surface_with_transit_points(distinct.clone(), distinct);
        assert!(validate_transit_points(&mut surface, 30, None).is_ok(), "the variant may reuse the surface's ids");
    }

    fn caller_key() -> serde_json::Value {
        serde_json::json!({
            "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" },
            "secret_id": "partner-callers"
        })
    }

    /// A save warns of a `fabric://` Transit Point, on the surface or in a
    /// variant, that does not require the transit token, once per alias, and
    /// not of one that requires it or of an HTTP Transit Point that does not.
    #[test]
    fn a_save_warns_of_a_fabric_transit_point_that_does_not_require_the_transit_token() {
        let point = |alias: &str, target: &str, require: bool| {
            serde_json::json!({ "alias": alias, "target_endpoint": target, "require_transit_token": require,
                "source_auth": caller_key() })
        };
        let warning = |alias: &str| {
            format!(
                "Transit Point '{alias}' sends to a peer gateway without requiring the transit token, so the Fabric \
                 hop limit holds through it only when the agent sends one; require the transit token"
            )
        };

        assert_eq!(
            fabric_hop_limit_warnings(&surface_with_transit_points(
                serde_json::json!([
                    point("partner", "fabric://partner-gateway/partner-surface", false),
                    point("crm", "https://crm.example", false),
                    point("peer", "fabric://peer-gateway/peer-surface", true)
                ]),
                serde_json::json!([point("partner", "fabric://partner-gateway/partner-surface", false)]),
            )),
            vec![warning("partner")]
        );
        assert_eq!(
            fabric_hop_limit_warnings(&surface_with_transit_points(
                serde_json::json!([point("peer", "fabric://peer-gateway/peer-surface", true)]),
                serde_json::json!([point("peer", "fabric://peer-gateway/peer-surface", false)]),
            )),
            vec![warning("peer")],
            "a variant's Transit Point is warned of"
        );
        assert!(
            fabric_hop_limit_warnings(&surface_with_transit_points(
                serde_json::json!([
                    point("peer", "fabric://peer-gateway/peer-surface", true),
                    point("crm", "https://crm.example", false)
                ]),
                serde_json::json!(null),
            ))
            .is_empty()
        );
    }

    /// A save warns of a Transit Point whose `jwt_bearer` accepts tokens issued
    /// for the Access Point: the same strategy and an audience both name.
    #[test]
    fn a_save_warns_of_a_transit_point_that_accepts_the_access_points_own_tokens() {
        let jwt = |strategy: &str, audiences: serde_json::Value| serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": strategy, "audiences": audiences });
        let surface_with = |transit_point_auth: serde_json::Value| {
            let mut surface = surface_with_transit_points(
                serde_json::json!([{ "alias": "crm", "target_endpoint": "https://crm.example",
                    "require_transit_token": false, "source_auth": transit_point_auth }]),
                serde_json::json!(null),
            );
            surface.variants.clear();
            surface
                .access_point
                .caller_authentication = Some(
                serde_json::from_value(serde_json::json!({
                    "methods": [jwt("entra", serde_json::json!(["{{ surface.agent_did }}", "api://agent"]))]
                }))
                .unwrap(),
            );
            surface
        };

        assert_eq!(
            shared_audience_warnings(&surface_with(jwt("entra", serde_json::json!(["{{ surface.agent_did }}"])))),
            vec![
                "Transit Point 'crm' accepts the Access Point's own tokens (JWT verification strategy 'entra', \
                 audience '{{ surface.agent_did }}'), so a caller of the Access Point can call it directly; give it \
                 an audience of its own"
                    .to_string()
            ]
        );
        for (case, transit_point_auth) in [
            ("an audience of its own", jwt("entra", serde_json::json!(["api://crm-transit"]))),
            ("another strategy", jwt("partner", serde_json::json!(["{{ surface.agent_did }}"]))),
            ("an API key", caller_key()),
        ] {
            assert!(shared_audience_warnings(&surface_with(transit_point_auth)).is_empty(), "{case}");
        }
    }

    /// An MCP Access Point that publishes protected resource metadata accepts
    /// a token whose audience is the resource of the route called, the base
    /// resource or a variant's own, and lists no audiences itself. A save warns
    /// of a Transit Point whose `jwt_bearer`, with the same strategy, names
    /// either resource.
    #[test]
    fn a_save_warns_of_a_transit_point_that_accepts_the_tokens_of_an_access_points_protected_resource() {
        let jwt = |audiences: serde_json::Value| serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": audiences });
        let surface_with = |variant_enabled: bool, transit_point_auth: serde_json::Value| -> AgentSurface {
            serde_json::from_value(serde_json::json!({
                "name": "tools",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/mcp", "protocol": "mcp",
                    "caller_authentication": {
                        "methods": [jwt(serde_json::json!([]))],
                        "protected_resource": { "resource": "https://gateway.example/mcp",
                            "authorization_servers": ["https://idp.example"] }
                    } },
                "target": { "endpoint": "https://tools.internal/mcp" },
                "transit": { "outbound_listen_address": "http://localhost:9111", "points": [
                    { "alias": "crm", "target_endpoint": "https://crm.example", "protocol": "mcp",
                        "require_transit_token": false, "source_auth": transit_point_auth }
                ] },
                "variants": [{ "id": "beta", "alias": "beta", "name": "Beta", "enabled": variant_enabled }]
            }))
            .unwrap()
        };
        let warning = |audience: &str| {
            format!(
                "Transit Point 'crm' accepts the Access Point's own tokens (JWT verification strategy 'idp', \
                 audience '{audience}'), so a caller of the Access Point can call it directly; give it an audience \
                 of its own"
            )
        };

        assert_eq!(
            shared_audience_warnings(&surface_with(true, jwt(serde_json::json!(["https://gateway.example/mcp"])))),
            vec![warning("https://gateway.example/mcp")]
        );
        assert_eq!(
            shared_audience_warnings(&surface_with(true, jwt(serde_json::json!(["https://gateway.example/mcp$beta"])))),
            vec![warning("https://gateway.example/mcp$beta")]
        );
        // A Transit Point only the variant defines, naming the base resource.
        let mut variant_only = surface_with(true, jwt(serde_json::json!(["api://crm-transit"])));
        variant_only.variants[0]
            .overrides
            .transit = Some(
            serde_json::from_value(serde_json::json!({ "points": [
                { "alias": "crm", "target_endpoint": "https://crm.example", "protocol": "mcp",
                    "require_transit_token": false, "source_auth": jwt(serde_json::json!(["https://gateway.example/mcp"])) }
            ] }))
            .unwrap(),
        );
        assert_eq!(
            shared_audience_warnings(&variant_only),
            vec![
                "Transit Point 'crm' in variant 'beta' accepts the Access Point's own tokens (JWT verification \
                 strategy 'idp', audience 'https://gateway.example/mcp'), so a caller of the Access Point can call it \
                 directly; give it an audience of its own"
                    .to_string()
            ]
        );
        for (case, surface) in [
            ("an audience of its own", surface_with(true, jwt(serde_json::json!(["api://crm-transit"])))),
            (
                "a disabled variant's resource",
                surface_with(false, jwt(serde_json::json!(["https://gateway.example/mcp$beta"]))),
            ),
        ] {
            assert!(shared_audience_warnings(&surface).is_empty(), "{case}");
        }
    }

    /// The Surface Builder sends every variant a copy of the surface's Transit
    /// Points, without their `source_auth`. A variant that stored no list of its
    /// own, or one added in the same save, keeps the caller authentication of
    /// the surface's Transit Point with the same id, unless the save removes it.
    /// A surface stored before a Transit Point had to authenticate its callers can
    /// still be saved while that Transit Point is left as stored. Changing it, or
    /// adding another like it, is refused as for any save.
    #[test]
    fn a_save_accepts_a_stored_transit_point_that_authenticates_no_caller_only_while_unchanged() {
        let legacy = serde_json::json!([{ "id": "legacy", "alias": "legacy", "target_endpoint": "https://legacy.example",
            "require_transit_token": false }]);
        let stored = surface_with_transit_points(legacy.clone(), legacy.clone());

        let mut unchanged = stored.clone();
        assert!(validate_transit_points(&mut unchanged, 30, Some(&stored)).is_ok(), "left as stored");
        assert!(validate_transit_points(&mut stored.clone(), 30, None).is_err(), "new, it is refused");

        let mut edited = stored.clone();
        edited
            .transit
            .as_mut()
            .unwrap()
            .points[0]
            .target_endpoint = "https://elsewhere.example".to_string();
        match validate_transit_points(&mut edited, 30, Some(&stored)) {
            Err(SurfaceApiError::BadRequest(message)) => {
                assert!(message.contains("authenticates no caller"), "{message}")
            }
            other => panic!("a changed Transit Point is refused with a 400, got {other:?}"),
        }

        let mut variant_edited = stored.clone();
        variant_edited.variants[0]
            .overrides
            .transit
            .as_mut()
            .unwrap()
            .points
            .as_mut()
            .unwrap()[0]
            .target_endpoint = "https://elsewhere.example".to_string();
        assert!(validate_transit_points(&mut variant_edited, 30, Some(&stored)).is_err(), "a changed variant copy");

        let mut added = stored.clone();
        let mut another = added
            .transit
            .as_ref()
            .unwrap()
            .points[0]
            .clone();
        another.id = "another".to_string();
        another.alias = "another".to_string();
        added
            .transit
            .as_mut()
            .unwrap()
            .points
            .push(another);
        assert!(validate_transit_points(&mut added, 30, Some(&stored)).is_err(), "a new Transit Point");

        let mut closed = stored.clone();
        closed
            .transit
            .as_mut()
            .unwrap()
            .points[0]
            .allow_unauthenticated_callers = true;
        closed.variants[0]
            .overrides
            .transit
            .as_mut()
            .unwrap()
            .points
            .as_mut()
            .unwrap()[0]
            .allow_unauthenticated_callers = true;
        assert!(validate_transit_points(&mut closed, 30, Some(&stored)).is_ok(), "marking it open is accepted");
    }

    #[test]
    fn a_save_warns_of_a_source_auth_mcp_transit_point_on_a_surface_with_credentials_for_every_request() {
        let point = |protocol: &str| {
            serde_json::json!([{ "id": "crm", "alias": "crm", "protocol": protocol,
                "target_endpoint": "https://crm.example", "require_transit_token": false,
                "source_auth": caller_key() }])
        };
        let surface = |protocol: &str, required_for: serde_json::Value| {
            let mut surface = surface_with_transit_points(point(protocol), serde_json::json!(null));
            surface.outbound_credentials = vec![
                serde_json::from_value(
                    serde_json::json!({ "credential_provider_id": "provider", "required_for": required_for }),
                )
                .unwrap(),
            ];
            surface
        };

        let warnings = modern_delegation_warnings(&surface("mcp", serde_json::json!("all")));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with("Transit Point 'crm' authenticates its callers with source_auth"));
        assert!(warnings[0].contains("refused with 403"));

        assert!(
            modern_delegation_warnings(&surface("mcp", serde_json::json!({ "tools": ["lookup"] }))).is_empty(),
            "tool-scoped bindings never apply on a Transit Point"
        );
        assert!(modern_delegation_warnings(&surface("a2a", serde_json::json!("all"))).is_empty(), "not MCP");
        let mut no_auth = surface("mcp", serde_json::json!("all"));
        no_auth
            .transit
            .as_mut()
            .unwrap()
            .points[0]
            .source_auth = None;
        assert!(modern_delegation_warnings(&no_auth).is_empty(), "no source_auth");
    }

    #[test]
    fn a_variant_that_inherits_the_surfaces_transit_points_keeps_their_caller_authentication() {
        let stored_points = serde_json::json!([
            { "id": "keyed", "alias": "keyed", "target_endpoint": "https://keyed.example",
                "require_transit_token": false, "source_auth": caller_key() },
            { "id": "dropped", "alias": "dropped", "target_endpoint": "https://dropped.example",
                "require_transit_token": true, "source_auth": caller_key() },
            { "id": "bare", "alias": "bare", "target_endpoint": "https://bare.example",
                "require_transit_token": true }
        ]);
        let mut existing = surface_with_transit_points(stored_points, serde_json::json!(null));
        assert!(
            existing.variants[0]
                .overrides
                .transit
                .as_ref()
                .unwrap()
                .points
                .is_none()
        );

        let frozen = serde_json::json!([
            { "id": "keyed", "alias": "keyed", "target_endpoint": "https://keyed.example",
                "require_transit_token": false },
            { "id": "dropped", "alias": "dropped", "target_endpoint": "https://dropped.example",
                "require_transit_token": true, "source_auth": null },
            { "id": "bare", "alias": "bare", "target_endpoint": "https://bare.example",
                "require_transit_token": true },
            { "id": "variant-only", "alias": "variant-only", "target_endpoint": "https://only.example",
                "require_transit_token": true }
        ]);
        let mut surface = surface_with_transit_points(frozen.clone(), frozen.clone());
        let mut added = surface.variants[0].clone();
        added.id = "added".to_string();
        added.alias = "added".to_string();
        surface.variants.push(added);
        let sent = serde_json::json!({
            "transit": { "points": frozen },
            "variants": [
                { "id": "candidate", "overrides": { "transit": { "points": frozen } } },
                { "id": "added", "overrides": { "transit": { "points": frozen } } }
            ]
        });

        retain_transit_caller_authentication(&mut surface, &existing, &sent);

        for variant in &surface.variants {
            let points = variant
                .overrides
                .transit
                .as_ref()
                .and_then(|transit| transit.points.as_ref())
                .unwrap();
            assert_eq!(
                points[0].source_auth,
                Some(serde_json::from_value(caller_key()).unwrap()),
                "{}: kept from the surface's Transit Point with the same id",
                variant.alias
            );
            assert!(
                points[1]
                    .source_auth
                    .is_none(),
                "{}: a null in the save removes it",
                variant.alias
            );
            assert!(
                points[2]
                    .source_auth
                    .is_none(),
                "{}: nothing stored, nothing invented",
                variant.alias
            );
            assert!(
                points[3]
                    .source_auth
                    .is_none(),
                "{}: a Transit Point the surface does not have keeps none",
                variant.alias
            );
        }

        existing.variants[0]
            .overrides
            .transit
            .as_mut()
            .unwrap()
            .points = Some(Vec::new());
        let mut surface = surface_with_transit_points(frozen.clone(), frozen.clone());
        let sent = serde_json::json!({ "variants": [{ "id": "candidate", "overrides": { "transit": { "points": frozen } } }] });
        retain_transit_caller_authentication(&mut surface, &existing, &sent);
        assert!(
            surface.variants[0]
                .overrides
                .transit
                .as_ref()
                .and_then(|transit| transit.points.as_ref())
                .unwrap()[0]
                .source_auth
                .is_none(),
            "a variant that stores a list of its own is matched against that list, not the surface's"
        );
    }

    /// A Transit Point stored with the removed `allow_fabric_callers` still
    /// loads, on the surface and in a variant, and a save writes it without
    /// the setting.
    #[test]
    fn a_stored_allow_fabric_callers_loads_and_is_not_written_back() {
        let point = serde_json::json!({ "id": "tp-crm", "alias": "crm", "target_endpoint": "fabric://gw/crm",
            "require_transit_token": true, "allow_fabric_callers": true });
        let surface = surface_with_transit_points(serde_json::json!([point.clone()]), serde_json::json!([point]));
        let written = serde_json::to_value(&surface).expect("surface serializes");
        assert_eq!(written["transit"]["points"][0]["alias"], "crm");
        assert!(
            written["transit"]["points"][0]
                .get("allow_fabric_callers")
                .is_none()
        );
        assert!(
            written["variants"][0]["overrides"]["transit"]["points"][0]
                .get("allow_fabric_callers")
                .is_none()
        );
    }

    /// A shared-issuer warning names the variant whose overrides define the
    /// Transit Point, and names a Transit Point a variant inherits as the
    /// surface's own, once.
    #[test]
    fn a_shared_issuer_warning_names_the_variant_that_defines_the_transit_point() {
        let point = |strategy: &str| {
            serde_json::json!({ "alias": "crm", "target_endpoint": "https://crm.example", "require_transit_token": false,
                "source_auth": { "type": "jwt_bearer", "jwt_verification_strategy_id": strategy,
                    "audiences": ["api://crm-transit"] } })
        };
        let surface_with = |variant_overrides: serde_json::Value| -> AgentSurface {
            serde_json::from_value(serde_json::json!({
                "name": "agent",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a2a", "protocol": "a2a",
                    "caller_authentication": { "methods": [{ "type": "jwt_bearer",
                        "jwt_verification_strategy_id": "workforce", "audiences": ["api://agent"] }] } },
                "target": { "endpoint": "https://agent.internal" },
                "transit": { "outbound_listen_address": "http://localhost:9111", "points": [point("own-issuer")] },
                "variants": [{ "id": "beta", "alias": "beta", "name": "Beta", "enabled": true,
                    "overrides": variant_overrides }]
            }))
            .unwrap()
        };
        let issuers = std::collections::HashMap::from([
            ("workforce".to_string(), naming("https://login.example", "sub")),
            ("partner-keys".to_string(), naming("https://login.example", "sub")),
            ("own-issuer".to_string(), naming("https://crm.example", "sub")),
        ]);
        let warning = |name: &str| {
            format!(
                "Transit Point {name} accepts tokens from issuer 'https://login.example' through JWT verification \
                 strategy 'partner-keys', and this surface accepts that issuer through 'workforce' too: a caller \
                 with the same subject through either is one caller, with the same delegated credentials; use one \
                 strategy per issuer"
            )
        };

        let defined = surface_with(serde_json::json!({ "transit": { "points": [point("partner-keys")] } }));
        assert_eq!(shared_issuer_warnings(&defined, &issuers), vec![warning("'crm' in variant 'beta'")]);

        let mut inherited = surface_with(serde_json::json!({}));
        inherited
            .transit
            .as_mut()
            .unwrap()
            .points = vec![serde_json::from_value(point("partner-keys")).unwrap()];
        assert_eq!(shared_issuer_warnings(&inherited, &issuers), vec![warning("'crm'")]);

        let by_other_claims = std::collections::HashMap::from([
            ("workforce".to_string(), naming("https://login.example", "sub")),
            ("partner-keys".to_string(), naming("https://login.example", "oid")),
        ]);
        assert_eq!(
            shared_issuer_warnings(&inherited, &by_other_claims),
            vec![
                "Transit Point 'crm' accepts tokens from issuer 'https://login.example' through JWT verification \
                 strategy 'partner-keys', and this surface accepts that issuer through 'workforce' too, but they \
                 name callers by different claims ('oid' and 'sub'): the same person through either is two \
                 callers, each with delegated credentials of their own; use one strategy per issuer"
                    .to_string()
            ]
        );
    }

    /// The Access Point different-claims warning compares the strategies of
    /// every view: a variant that inherits the Access Point's methods adds no
    /// copy of it, and one that overrides them with a strategy naming another
    /// claim for the same issuer is warned of, under its name.
    #[test]
    fn the_access_point_claims_warning_compares_every_view_once() {
        let jwt = |strategy: &str, header: &str| {
            serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": strategy,
                "audiences": ["api://agent"], "token_header": header })
        };
        let surface_with = |methods: serde_json::Value, overrides: serde_json::Value| -> AgentSurface {
            serde_json::from_value(serde_json::json!({
                "name": "agent",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a2a", "protocol": "a2a",
                    "caller_authentication": { "methods": methods } },
                "target": { "endpoint": "https://agent.internal" },
                "variants": [{ "id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": overrides }]
            }))
            .unwrap()
        };
        let issuers = std::collections::HashMap::from([
            ("by-sub".to_string(), naming("https://login.example", "sub")),
            ("by-oid".to_string(), naming("https://login.example", "oid")),
        ]);
        let expected = |second: &str| {
            format!(
                "The Access Point accepts tokens from issuer 'https://login.example' through JWT verification \
                 strategies 'by-sub' and {second}, which name callers by different claims ('sub' and 'oid'): the \
                 same person through either is two callers, each with delegated credentials of their own; use one \
                 strategy per issuer"
            )
        };

        let inheriting = surface_with(
            serde_json::json!([jwt("by-sub", "Authorization"), jwt("by-oid", "X-Entra-Token")]),
            serde_json::json!({}),
        );
        assert_eq!(shared_issuer_warnings(&inheriting, &issuers), vec![expected("'by-oid'")]);

        let overriding = surface_with(
            serde_json::json!([jwt("by-sub", "Authorization")]),
            serde_json::json!({ "access_point": { "caller_authentication": { "methods": [jwt("by-oid", "Authorization")] } } }),
        );
        assert_eq!(shared_issuer_warnings(&overriding, &issuers), vec![expected("'by-oid' in variant 'beta'")]);
    }

    fn naming(
        issuer: &str,
        principal_claim: &str,
    ) -> StrategyCallerNaming {
        StrategyCallerNaming {
            issuer: issuer.to_string(),
            principal_claim: Ok(principal_claim.to_string()),
        }
    }

    /// Two Access Point methods whose strategies name one issuer but different
    /// claims split one person into two callers, and a strategy stored with a
    /// claim the API refuses names nobody: a save says both, and neither is
    /// mistaken for a claim the other strategies are compared with.
    #[test]
    fn a_save_warns_of_access_point_methods_naming_different_claims_and_of_an_unusable_claim() {
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "name": "agent",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a2a", "protocol": "a2a",
                "caller_authentication": { "methods": [
                    { "type": "jwt_bearer", "jwt_verification_strategy_id": "by-sub", "audiences": ["api://agent"] },
                    { "type": "jwt_bearer", "jwt_verification_strategy_id": "by-oid", "audiences": ["api://agent"],
                        "token_header": "X-Entra-Token" },
                    { "type": "jwt_bearer", "jwt_verification_strategy_id": "hand-edited", "audiences": ["api://agent"],
                        "token_header": "X-Other-Token" }
                ] } },
            "target": { "endpoint": "https://agent.internal" }
        }))
        .unwrap();
        let issuers = std::collections::HashMap::from([
            ("by-sub".to_string(), naming("https://login.example", "sub")),
            ("by-oid".to_string(), naming("https://login.example", "oid")),
            (
                "hand-edited".to_string(),
                StrategyCallerNaming {
                    issuer: "https://login.example".to_string(),
                    principal_claim: Err("iss".to_string()),
                },
            ),
        ]);

        assert_eq!(
            shared_issuer_warnings(&surface, &issuers),
            vec![
                "The Access Point accepts tokens from issuer 'https://login.example' through JWT verification \
                 strategies 'by-sub' and 'by-oid', which name callers by different claims ('sub' and 'oid'): the \
                 same person through either is two callers, each with delegated credentials of their own; use one \
                 strategy per issuer"
                    .to_string()
            ]
        );
        assert_eq!(
            unusable_principal_claim_warnings(&surface, &issuers),
            vec![
                "JWT verification strategy 'hand-edited' names callers by 'iss', a claim the API refuses: it \
                 identifies no caller, and JWT source authentication through it answers 500; create a strategy that \
                 names another claim"
                    .to_string()
            ]
        );
    }

    /// A Transit Point that releases delegated credentials to Fabric callers
    /// but resolves no managed identity refuses every such call a binding
    /// applies to, since a Fabric caller's DID is never the agent half of the
    /// key: a save says so.
    #[test]
    fn a_save_warns_of_a_transit_point_that_opts_fabric_callers_in_without_a_managed_identity() {
        let agent = serde_json::json!({ "type": "static", "did": "did:web:agent.example" });
        let surface_with = |point: serde_json::Value, surface_identity: bool| -> AgentSurface {
            let mut surface = serde_json::json!({
                "name": "tools",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/mcp", "protocol": "mcp" },
                "target": { "endpoint": "https://tools.internal/mcp" },
                "transit": { "outbound_listen_address": "http://localhost:9111", "points": [point] },
                "variants": [{ "id": "beta", "alias": "beta", "name": "Beta", "enabled": true }]
            });
            if surface_identity {
                surface["identity_slots"] = serde_json::json!({ "protected": agent });
            }
            serde_json::from_value(surface).unwrap()
        };
        let point = |opted_in: bool, identity: serde_json::Value| {
            let mut point = serde_json::json!({ "alias": "crm", "target_endpoint": "https://crm.example",
                "protocol": "mcp", "require_transit_token": true,
                "delegated_credentials_for_fabric_callers": opted_in });
            if let serde_json::Value::Object(identity) = identity {
                point
                    .as_object_mut()
                    .unwrap()
                    .extend(identity);
            }
            point
        };
        let warning = vec![
            "Transit Point 'crm' sets delegated_credentials_for_fabric_callers but has no managed identity, so a \
             delegated credential binding that applies refuses every Fabric caller with 403; give it a managed \
             identity, or inject a VP with the surface's"
                .to_string(),
        ];

        for (case, surface) in [
            ("no identity", surface_with(point(true, serde_json::json!({})), false)),
            ("the surface's identity without a VP", surface_with(point(true, serde_json::json!({})), true)),
            (
                "an inbound-only identity",
                surface_with(
                    point(true, serde_json::json!({ "managed_identity": { "type": "from_jwt_claim" } })),
                    false,
                ),
            ),
        ] {
            assert_eq!(fabric_delegation_identity_warnings(&surface), warning, "{case}");
        }
        let mut variant_only = surface_with(point(false, serde_json::json!({})), false);
        variant_only.variants[0]
            .overrides
            .transit = Some(
            serde_json::from_value(serde_json::json!({ "points": [point(true, serde_json::json!({}))] })).unwrap(),
        );
        assert_eq!(fabric_delegation_identity_warnings(&variant_only), warning, "a Transit Point a variant defines");

        for (case, surface) in [
            ("its own identity", surface_with(point(true, serde_json::json!({ "managed_identity": agent })), false)),
            (
                "the surface's identity with a VP",
                surface_with(point(true, serde_json::json!({ "identity_injection": { "inject_vp": true } })), true),
            ),
            ("the switch off", surface_with(point(false, serde_json::json!({})), false)),
        ] {
            assert!(fabric_delegation_identity_warnings(&surface).is_empty(), "{case}");
        }
    }

    /// A variant that keeps the surface's Transit Points uses their grants by
    /// binding under its own transit settings and Access Point: a save says so
    /// when the variant overrides either.
    #[test]
    fn a_save_warns_of_a_variant_that_uses_inherited_grants_under_its_own_settings() {
        let surface_with = |enabled: bool, overrides: serde_json::Value| -> AgentSurface {
            serde_json::from_value(serde_json::json!({
                "name": "tools",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/mcp", "protocol": "mcp" },
                "target": { "endpoint": "https://tools.internal/mcp" },
                "transit": { "points": [
                    { "id": "crm-id", "alias": "crm", "target_endpoint": "https://crm.example/mcp",
                        "require_transit_token": true, "transit_credentials": {
                            "credential_provider_id": "vendor", "consent_mode": "external", "subject": "owner" } },
                    { "id": "docs-id", "alias": "docs", "target_endpoint": "https://docs.example/mcp",
                        "require_transit_token": true }
                ] },
                "variants": [{ "id": "dev", "alias": "dev", "name": "Dev", "enabled": enabled,
                    "overrides": overrides }]
            }))
            .unwrap()
        };
        let warning = vec![
            "Variant 'dev' keeps Transit Point 'crm', which has consent_mode external, and overrides its transit \
             settings or its Access Point: calls through the variant use the Transit Point's grants under the \
             variant's own transit policy, rate limit and Access Point; to keep them apart, give the variant its own \
             Transit Points in overrides.transit.points, with new ids"
                .to_string(),
        ];
        for (case, overrides) in [
            (
                "its own transit policy",
                serde_json::json!({ "transit": { "shared": { "opa_policy_definition_id": "dev" } } }),
            ),
            (
                "its own Access Point",
                serde_json::json!({ "access_point": { "caller_authentication": { "methods": [caller_key()] } } }),
            ),
        ] {
            assert_eq!(inherited_external_point_warnings(&surface_with(true, overrides)), warning, "{case}");
        }
        for (case, surface) in [
            ("no overrides", surface_with(true, serde_json::json!({}))),
            (
                "its own target",
                surface_with(true, serde_json::json!({ "target": { "endpoint": "https://dev.internal" } })),
            ),
            (
                "its own Transit Points",
                surface_with(
                    true,
                    serde_json::json!({ "transit": { "points": [], "shared": { "opa_policy_definition_id": "dev" } } }),
                ),
            ),
            (
                "transit turned off",
                surface_with(
                    true,
                    serde_json::json!({ "transit": { "disabled": true }, "access_point": { "caller_authentication": {
                        "methods": [caller_key()] } } }),
                ),
            ),
            (
                "a disabled variant",
                surface_with(
                    false,
                    serde_json::json!({ "transit": { "shared": { "opa_policy_definition_id": "dev" } } }),
                ),
            ),
        ] {
            assert!(inherited_external_point_warnings(&surface).is_empty(), "{case}");
        }
    }

    /// A variant that keeps the surface's `outbound_credentials` uses the
    /// Access Point Target's grants by binding under its own Access Point and
    /// Target settings: a save says so when the variant overrides either.
    #[test]
    fn a_save_warns_of_a_variant_that_uses_the_targets_grants_under_its_own_settings() {
        let surface_with = |enabled: bool, overrides: serde_json::Value| -> AgentSurface {
            serde_json::from_value(serde_json::json!({
                "name": "vendor",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/mcp", "protocol": "mcp" },
                "target": { "endpoint": "https://mcp.vendor.example/mcp" },
                "outbound_credentials": [{ "credential_provider_id": "vendor", "consent_mode": "external",
                    "subject": "owner" }],
                "variants": [{ "id": "dev", "alias": "dev", "name": "Dev", "enabled": enabled,
                    "overrides": overrides }]
            }))
            .unwrap()
        };
        let warning = vec![
            "Variant 'dev' keeps the Access Point Target's binding with consent_mode external, and overrides its \
             Access Point or its Target: calls through the variant use the Target's grants under the variant's own \
             caller authentication, policies and tool gating; to keep them apart, give the variant \
             outbound_credentials of its own"
                .to_string(),
        ];
        for (case, overrides) in [
            (
                "its own Access Point",
                serde_json::json!({ "access_point": { "caller_authentication": { "methods": [caller_key()] } } }),
            ),
            ("its own Target settings", serde_json::json!({ "target": { "mcp_tool_policies_enabled": false } })),
        ] {
            assert_eq!(inherited_target_binding_warnings(&surface_with(true, overrides)), warning, "{case}");
        }
        for (case, surface) in [
            ("no overrides", surface_with(true, serde_json::json!({}))),
            (
                "its own outbound_credentials",
                surface_with(
                    true,
                    serde_json::json!({ "outbound_credentials": [], "access_point": { "caller_authentication": {
                        "methods": [caller_key()] } } }),
                ),
            ),
            (
                "a disabled variant",
                surface_with(
                    false,
                    serde_json::json!({ "access_point": { "caller_authentication": { "methods": [caller_key()] } } }),
                ),
            ),
        ] {
            assert!(inherited_target_binding_warnings(&surface).is_empty(), "{case}");
        }
    }

    /// While the Access Point Target's binding is served, a save warns of each
    /// enabled view that sends requests to its vendor's origin without the
    /// binding or a credential of its own, as an enabled copy of the variant
    /// holding it does; a disabled one, one at another origin, or one with a
    /// credential of its own draws no warning.
    #[test]
    fn a_save_warns_of_an_enabled_view_that_reaches_the_bound_vendor_without_the_grant() {
        let external = serde_json::json!([{ "credential_provider_id": "vendor", "consent_mode": "external",
            "subject": "owner" }]);
        let surface_with = |base: serde_json::Value, enabled: bool, overrides: serde_json::Value| -> AgentSurface {
            serde_json::from_value(serde_json::json!({
                "name": "vendor",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/mcp", "protocol": "mcp" },
                "target": { "endpoint": "https://mcp.vendor.example/mcp" },
                "outbound_credentials": base,
                "variants": [{ "id": "copy", "alias": "copy", "name": "Copy", "enabled": enabled,
                    "overrides": overrides }]
            }))
            .unwrap()
        };
        let warning = |named: &str| {
            format!(
                "{named} sends requests to the vendor of the external consent binding without the binding or a \
                 credential of its own: callers' requests reach the vendor with no grant. Give it another Target or \
                 its own credential (target.auth, a binding or forward_header). Target: \
                 https://mcp.vendor.example/mcp"
            )
        };
        let api_key = serde_json::json!({ "type": "api_key",
            "extraction": { "source": "http_header", "field": "X-API-Key" }, "secret_id": "key" });
        let jwt_bearer = |forward_header: bool| {
            serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": "idp",
                "audiences": ["vendor"], "forward_header": forward_header })
        };
        let with_methods = |methods: serde_json::Value| {
            serde_json::json!({ "outbound_credentials": [],
                "access_point": { "caller_authentication": { "methods": methods } } })
        };
        assert_eq!(
            unbound_vendor_view_warnings(&surface_with(
                external.clone(),
                true,
                serde_json::json!({ "outbound_credentials": [] })
            )),
            vec![warning("Variant 'copy'")],
            "an enabled variant that drops the binding"
        );
        assert_eq!(
            unbound_vendor_view_warnings(&surface_with(
                serde_json::json!([]),
                true,
                serde_json::json!({ "outbound_credentials": external.clone() })
            )),
            vec![warning("The surface's own route")],
            "the surface's own route beside a variant that holds it"
        );
        for (case, surface) in [
            (
                "a disabled variant that drops the binding",
                surface_with(external.clone(), false, serde_json::json!({ "outbound_credentials": [] })),
            ),
            ("a variant that keeps the binding", surface_with(external.clone(), true, serde_json::json!({}))),
            (
                "a variant at another origin",
                surface_with(
                    external.clone(),
                    true,
                    serde_json::json!({ "outbound_credentials": [],
                        "target": { "endpoint": "https://managed.example/agent" } }),
                ),
            ),
            (
                "a variant with a credential of its own",
                surface_with(
                    external.clone(),
                    true,
                    serde_json::json!({ "outbound_credentials": [], "target": { "auth": { "method": {
                        "static_secret": { "secret_id": "s", "header_name": "X-Api-Key" } } } } }),
                ),
            ),
            (
                "a variant with another binding",
                surface_with(
                    external.clone(),
                    true,
                    serde_json::json!({ "outbound_credentials": [{ "credential_provider_id": "agent-keyed" }] }),
                ),
            ),
            (
                "a variant whose every method forwards the caller's JWT",
                surface_with(
                    external.clone(),
                    true,
                    with_methods(serde_json::json!([jwt_bearer(true), jwt_bearer(true)])),
                ),
            ),
            ("the surface's own route while a default variant takes its requests", {
                let mut surface = surface_with(
                    serde_json::json!([]),
                    true,
                    serde_json::json!({ "outbound_credentials": external.clone() }),
                );
                surface.default_variant_id = Some("copy".to_string());
                surface
            }),
        ] {
            assert!(unbound_vendor_view_warnings(&surface).is_empty(), "{case}");
        }
        // A request is forwarded with the credential of the method it matched, so
        // a method that forwards none leaves its callers without one.
        for (case, methods) in [
            ("a forwarding JWT method after an API key", serde_json::json!([api_key.clone(), jwt_bearer(true)])),
            ("a forwarding JWT method before an API key", serde_json::json!([jwt_bearer(true), api_key.clone()])),
            ("a JWT method that forwards nothing", serde_json::json!([api_key.clone(), jwt_bearer(false)])),
        ] {
            assert_eq!(
                unbound_vendor_view_warnings(&surface_with(external.clone(), true, with_methods(methods))),
                vec![warning("Variant 'copy'")],
                "{case}"
            );
        }
    }

    /// A variant created from another keeps no binding with external consent
    /// in a second place: its Transit Points with one get ids of their own,
    /// and the Access Point Target's binding is left out of its copy.
    #[test]
    fn a_new_variant_copies_no_binding_with_external_consent_into_a_second_place() {
        let overrides: SurfaceOverrides = serde_json::from_value(serde_json::json!({
            "transit": { "points": [
                { "id": "crm-id", "alias": "crm", "target_endpoint": "https://crm.example/mcp",
                    "transit_credentials": { "credential_provider_id": "vendor", "consent_mode": "external",
                        "subject": "owner" } },
                { "id": "docs-id", "alias": "docs", "target_endpoint": "https://docs.example/mcp" }
            ] },
            "outbound_credentials": [
                { "credential_provider_id": "vendor", "consent_mode": "external", "subject": "caller" },
                { "credential_provider_id": "agent-keyed" }
            ]
        }))
        .unwrap();
        let (copied, left_out_target_binding) = copied_overrides(overrides);
        assert!(left_out_target_binding, "the Access Point Target's binding is left out");
        let points = copied
            .transit
            .as_ref()
            .and_then(|transit| transit.points.as_ref())
            .unwrap();
        assert_ne!(points[0].id, "crm-id");
        assert_eq!(points[1].id, "docs-id");
        let providers: Vec<&str> = copied
            .outbound_credentials
            .as_ref()
            .unwrap()
            .iter()
            .map(|binding| {
                binding
                    .credential_provider_id
                    .as_str()
            })
            .collect();
        assert_eq!(providers, ["agent-keyed"]);
        let (none, left_out_target_binding) = copied_overrides(SurfaceOverrides::default());
        assert!(
            none.outbound_credentials
                .is_none(),
            "a variant that kept the surface's still does"
        );
        assert!(!left_out_target_binding, "nothing was left out");
        let agent_keyed: SurfaceOverrides = serde_json::from_value(serde_json::json!({
            "outbound_credentials": [{ "credential_provider_id": "agent-keyed" }]
        }))
        .unwrap();
        assert!(!copied_overrides(agent_keyed).1, "a binding without external consent is copied as it is");
        assert_eq!(
            warning_header(&copied_target_binding_warning("copy")).map(|value| value
                .to_str()
                .unwrap()
                .to_string()),
            Some(format!("299 - \"{}\"", copied_target_binding_warning("copy")))
        );
    }

    #[test]
    fn a_put_that_omits_a_transit_points_caller_authentication_keeps_it_while_it_applies() {
        let stored_points = serde_json::json!([
            { "id": "keyed", "alias": "keyed", "target_endpoint": "https://keyed.example",
                "require_transit_token": false, "source_auth": caller_key() },
            { "id": "open", "alias": "open", "target_endpoint": "https://open.example",
                "require_transit_token": false, "allow_unauthenticated_callers": true },
            { "id": "reopened", "alias": "reopened", "target_endpoint": "https://reopened.example",
                "require_transit_token": false, "allow_unauthenticated_callers": true },
            { "id": "closed", "alias": "closed", "target_endpoint": "https://closed.example",
                "require_transit_token": false, "allow_unauthenticated_callers": true },
            { "id": "removed", "alias": "removed", "target_endpoint": "https://removed.example",
                "require_transit_token": true, "source_auth": caller_key() }
        ]);
        let existing = surface_with_transit_points(stored_points.clone(), stored_points);
        let sent_points = serde_json::json!([
            { "id": "keyed", "alias": "keyed", "target_endpoint": "https://keyed.example",
                "require_transit_token": false },
            { "id": "open", "alias": "open", "target_endpoint": "https://open.example",
                "require_transit_token": false },
            { "id": "reopened", "alias": "reopened", "target_endpoint": "https://reopened.example",
                "require_transit_token": true },
            { "id": "closed", "alias": "closed", "target_endpoint": "https://closed.example",
                "require_transit_token": false, "allow_unauthenticated_callers": false },
            { "id": "removed", "alias": "removed", "target_endpoint": "https://removed.example",
                "require_transit_token": true, "source_auth": null }
        ]);
        let sent = serde_json::json!({
            "transit": { "points": sent_points },
            "variants": [{ "id": "candidate", "overrides": { "transit": { "points": sent_points } } }]
        });
        let mut surface = surface_with_transit_points(sent_points.clone(), sent_points);

        retain_transit_caller_authentication(&mut surface, &existing, &sent);

        let variant_points = surface.variants[0]
            .overrides
            .transit
            .as_ref()
            .and_then(|transit| transit.points.clone())
            .unwrap();
        for points in [
            &surface
                .transit
                .as_ref()
                .unwrap()
                .points,
            &variant_points,
        ] {
            assert_eq!(points[0].source_auth, Some(serde_json::from_value(caller_key()).unwrap()), "kept");
            assert!(points[1].allow_unauthenticated_callers, "kept while it still authenticates no caller");
            assert!(!points[2].allow_unauthenticated_callers, "dropped once it authenticates its callers");
            assert!(!points[3].allow_unauthenticated_callers, "a false the caller sent is honoured");
            assert_eq!(points[4].source_auth, None, "a null the caller sent removes it");
            for point in points {
                assert_eq!(
                    point
                        .validate_caller_authentication()
                        .is_ok(),
                    point.alias != "closed",
                    "{}",
                    point.alias
                );
            }
        }
    }

    /// `surface` with an Access Point that verifies its callers with `methods`.
    fn with_caller_authentication(
        mut surface: AgentSurface,
        methods: serde_json::Value,
    ) -> AgentSurface {
        surface
            .access_point
            .caller_authentication = Some(serde_json::from_value(serde_json::json!({ "methods": methods })).unwrap());
        surface
    }

    /// A `jwt_bearer` method that names an audience and the JWT verification
    /// strategy `idp`.
    fn per_user_jwt() -> serde_json::Value {
        serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": ["api://agent"] })
    }

    /// A save that leaves out the ids of Transit Points with external consent
    /// keeps the stored ones, matched by alias in the same place, so each
    /// binding keeps its id, and with it its grants. An id the request sends is
    /// kept as sent, and a Transit Point without external consent sent without
    /// its id is a new one, as before.
    #[tokio::test]
    async fn a_save_that_leaves_transit_point_ids_out_keeps_them_and_their_grants() {
        let binding = serde_json::json!({"credential_provider_id": "vendor", "consent_mode": "external",
            "subject": "owner"});
        let stored_points = serde_json::json!([
            { "id": "hop-vendor", "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp",
                "require_transit_token": true, "transit_credentials": binding },
            { "id": "hop-other", "alias": "other", "target_endpoint": "https://203.0.113.31/mcp",
                "require_transit_token": true, "transit_credentials": binding },
            { "id": "hop-plain", "alias": "plain", "target_endpoint": "https://203.0.113.33/mcp",
                "require_transit_token": true }
        ]);
        let mut existing = surface_with_transit_points(stored_points.clone(), stored_points);
        existing.surface_id = "surface".into();
        let sent_points = serde_json::json!([
            { "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp", "require_transit_token": true,
                "transit_credentials": binding },
            { "id": "", "alias": "other", "target_endpoint": "https://203.0.113.31/mcp",
                "require_transit_token": true, "transit_credentials": binding },
            { "id": "hop-new", "alias": "added", "target_endpoint": "https://203.0.113.32/mcp",
                "require_transit_token": true },
            { "alias": "plain", "target_endpoint": "https://203.0.113.33/mcp", "require_transit_token": true }
        ]);
        let sent = serde_json::json!({
            "transit": { "points": sent_points },
            "variants": [{ "id": "candidate", "overrides": { "transit": { "points": sent_points } } }]
        });
        let mut surface = surface_with_transit_points(sent_points.clone(), sent_points);
        surface.surface_id = "surface".into();

        carry_transit_point_ids(&mut surface, &existing, &sent);

        let variant_points = surface.variants[0]
            .overrides
            .transit
            .as_ref()
            .and_then(|transit| transit.points.clone())
            .unwrap();
        for points in [
            &surface
                .transit
                .as_ref()
                .unwrap()
                .points,
            &variant_points,
        ] {
            let ids: Vec<&str> = points
                .iter()
                .map(|point| point.id.as_str())
                .collect();
            assert_eq!(ids[..3], ["hop-vendor", "hop-other", "hop-new"]);
            assert_ne!(ids[3], "hop-plain", "a Transit Point without external consent is new");
        }
        let no_vault = super::super::surface_grants::GrantRemoval {
            vault: None,
            providers: None,
            secrets: None,
            exact_allowlist: None,
            actor: None,
        };
        assert!(
            super::super::surface_grants::remove_changed_binding_grants(
                &no_vault,
                Some(&existing),
                Some(&surface),
                None,
                None
            )
            .await
            .is_ok(),
            "no binding changed, so no grant is revoked"
        );

        let mut renamed = surface_with_transit_points(
            serde_json::json!([{ "id": "hop-vendor", "alias": "renamed", "target_endpoint": "https://203.0.113.30/mcp",
                "require_transit_token": true, "transit_credentials": binding }]),
            serde_json::json!([]),
        );
        let sent = serde_json::json!({ "transit": { "points": [{ "id": "hop-vendor", "alias": "renamed" }] } });
        carry_transit_point_ids(&mut renamed, &existing, &sent);
        assert_eq!(
            renamed
                .transit
                .as_ref()
                .unwrap()
                .points[0]
                .id,
            "hop-vendor",
            "a sent id is kept"
        );
    }

    /// A variant PUT carries a Transit Point's id only from the variant's own
    /// stored list, as a surface PUT does: a variant that inherits the
    /// surface's points and is sent its own copy of an external one, without
    /// an id, as the Surface Builder sends it, gets a new Transit Point, and is
    /// saved, instead of taking the surface's id and being refused for using
    /// it in two places. A variant with its own list keeps its own ids.
    #[test]
    fn a_variant_put_carries_transit_point_ids_from_the_variants_own_list_only() {
        let binding = serde_json::json!({"credential_provider_id": "vendor", "consent_mode": "external",
            "subject": "owner"});
        let base_points = serde_json::json!([
            { "id": "hop-vendor", "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp",
                "require_transit_token": true, "transit_credentials": binding }
        ]);
        let sent_points = serde_json::json!([
            { "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp", "require_transit_token": true,
                "transit_credentials": binding }
        ]);
        let mut inheriting = surface_with_transit_points(base_points.clone(), serde_json::json!([]));
        inheriting.variants[0]
            .overrides
            .transit = None;
        let mut points: Vec<crate::config::agent_surface::TransitPoint> =
            serde_json::from_value(sent_points.clone()).unwrap();

        settle_variant_put_points(&mut points, &inheriting, "candidate", Some(&sent_points));
        assert_ne!(points[0].id, "hop-vendor", "the surface's id is not carried into the variant's copy");
        identify_transit_points(&mut points, "variant 'candidate' ").unwrap();
        let mut saved = inheriting.clone();
        saved.variants[0]
            .overrides
            .transit = Some(serde_json::from_value(serde_json::json!({ "points": points })).unwrap());
        assert!(
            super::super::surface_tenancy::check_external_transit_point_ids(&saved).is_ok(),
            "the variant's copy is a Transit Point of its own"
        );

        let own = surface_with_transit_points(
            base_points,
            serde_json::json!([{ "id": "hop-variant", "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp",
                "require_transit_token": true, "transit_credentials": binding }]),
        );
        let mut points: Vec<crate::config::agent_surface::TransitPoint> =
            serde_json::from_value(sent_points.clone()).unwrap();
        settle_variant_put_points(&mut points, &own, "candidate", Some(&sent_points));
        assert_eq!(points[0].id, "hop-variant", "a variant with its own list keeps its own id");
    }

    /// The Surface Builder does not show `delegated_credentials_for_fabric_callers`,
    /// so a PUT, of the surface or a variant within it, that omits it keeps the
    /// stored value while the Transit Point still requires the transit token,
    /// whatever the surface's caller authentication; a value the request sends
    /// is honoured.
    #[test]
    fn a_put_that_omits_a_transit_points_fabric_caller_delegation_keeps_it_while_it_applies() {
        let stored_points = serde_json::json!([
            { "id": "kept", "alias": "kept", "target_endpoint": "https://kept.example",
                "delegated_credentials_for_fabric_callers": true },
            { "id": "cleared", "alias": "cleared", "target_endpoint": "https://cleared.example",
                "delegated_credentials_for_fabric_callers": true },
            { "id": "tokenless", "alias": "tokenless", "target_endpoint": "https://tokenless.example",
                "delegated_credentials_for_fabric_callers": true },
            { "id": "never", "alias": "never", "target_endpoint": "https://never.example" }
        ]);
        let existing = surface_with_transit_points(stored_points.clone(), stored_points);
        let sent_points = serde_json::json!([
            { "id": "kept", "alias": "kept", "target_endpoint": "https://kept.example" },
            { "id": "cleared", "alias": "cleared", "target_endpoint": "https://cleared.example",
                "delegated_credentials_for_fabric_callers": false },
            { "id": "tokenless", "alias": "tokenless", "target_endpoint": "https://tokenless.example",
                "require_transit_token": false, "source_auth": caller_key() },
            { "id": "never", "alias": "never", "target_endpoint": "https://never.example" }
        ]);
        let sent = serde_json::json!({
            "transit": { "points": sent_points },
            "variants": [{ "id": "candidate", "overrides": { "transit": { "points": sent_points } } }]
        });
        for (methods, expected) in [
            (serde_json::json!([per_user_jwt()]), [true, false, false, false]),
            (serde_json::json!([caller_key()]), [true, false, false, false]),
        ] {
            let mut surface = with_caller_authentication(
                surface_with_transit_points(sent_points.clone(), sent_points.clone()),
                methods,
            );

            retain_transit_caller_authentication(&mut surface, &existing, &sent);

            let variant_points = surface.variants[0]
                .overrides
                .transit
                .as_ref()
                .and_then(|transit| transit.points.clone())
                .unwrap();
            for points in [
                &surface
                    .transit
                    .as_ref()
                    .unwrap()
                    .points,
                &variant_points,
            ] {
                let opted_in: Vec<bool> = points
                    .iter()
                    .map(|point| point.delegated_credentials_for_fabric_callers)
                    .collect();
                assert_eq!(opted_in, expected, "kept, cleared, dropped without the token, never set");
                for point in points {
                    assert_eq!(point.validate_caller_authentication(), Ok(()), "{}", point.alias);
                }
            }
        }
    }

    /// A save of a Transit Point that sets
    /// `delegated_credentials_for_fabric_callers` is accepted with a warning
    /// wherever the surface's caller authentication cannot tell a partner's
    /// users apart: only a resource token, or a JWT naming an audience through
    /// a strategy that names an issuer, can. An mTLS method beside one of them
    /// is no gap.
    #[test]
    fn a_transit_point_that_opts_fabric_callers_in_is_warned_of_where_the_surface_cannot_tell_users_apart() {
        let issuers = std::collections::HashMap::from([
            ("idp".to_string(), naming("https://idp.example", "sub")),
            ("blank".to_string(), naming("", "sub")),
        ]);
        let jwt = |strategy: &str, audiences: serde_json::Value| serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": strategy, "audiences": audiences });
        let mtls = serde_json::json!({ "type": "mtls", "trust": { "type": "pinned", "certificate_ids": ["cert"] },
            "identity_binding": { "type": "fingerprint" } });
        let point = |opted_in: bool| {
            serde_json::json!([{ "alias": "crm", "target_endpoint": "https://crm.example",
                "require_transit_token": true, "delegated_credentials_for_fabric_callers": opted_in }])
        };
        let surface = |methods: serde_json::Value| {
            with_caller_authentication(surface_with_transit_points(point(true), point(true)), methods)
        };
        let warning = "Transit Point 'crm' sets delegated_credentials_for_fabric_callers, but the surface's caller \
                       authentication cannot tell a partner's users apart, and";

        let mut resource_tokens = surface(serde_json::json!([mtls.clone()]));
        resource_tokens.mcp_http = Some(
            serde_json::from_value(serde_json::json!({ "authorization": { "resource": "https://gw.example/mcp" } }))
                .unwrap(),
        );
        for (case, quiet) in [
            ("a JWT naming an audience", surface(serde_json::json!([per_user_jwt()]))),
            ("a JWT naming an audience beside mTLS", surface(serde_json::json!([mtls.clone(), per_user_jwt()]))),
            ("a resource token beside mTLS", resource_tokens),
            (
                "the switch off",
                with_caller_authentication(
                    surface_with_transit_points(point(false), point(false)),
                    serde_json::json!([caller_key()]),
                ),
            ),
        ] {
            assert!(fabric_caller_delegation_warnings(&quiet, &issuers).is_empty(), "{case}");
        }

        for (case, methods, reason) in [
            ("no caller authentication", serde_json::json!([]), "it verifies no caller"),
            ("mTLS only", serde_json::json!([mtls.clone()]), "it verifies no caller"),
            ("an API key", serde_json::json!([caller_key()]), "every key in its secret as one caller"),
            (
                "an API key beside a JWT",
                serde_json::json!([per_user_jwt(), caller_key()]),
                "every key in its secret as one caller",
            ),
            (
                "an API Key Provider key",
                serde_json::json!([{ "type": "api_key_provider", "agent_id": "keys",
                    "extraction": { "source": "http_header", "field": "X-API-Key" } }]),
                "names the client that holds it",
            ),
            ("a JWT naming no audience", serde_json::json!([jwt("idp", serde_json::json!([]))]), "names no audience"),
            (
                "a JWT naming no strategy",
                serde_json::json!([jwt("", serde_json::json!(["api://agent"]))]),
                "names no JWT verification strategy",
            ),
            (
                "a JWT whose strategy cannot be read",
                serde_json::json!([jwt("missing", serde_json::json!(["api://agent"]))]),
                "JWT verification strategy 'missing' names no issuer",
            ),
            (
                "a JWT whose strategy names no issuer",
                serde_json::json!([jwt("blank", serde_json::json!(["api://agent"]))]),
                "JWT verification strategy 'blank' names no issuer",
            ),
        ] {
            let warnings = fabric_caller_delegation_warnings(&surface(methods), &issuers);
            assert!(warnings[0].starts_with(warning), "{case}: {warnings:?}");
            for warning in &warnings {
                assert!(warning.contains(reason), "{case}: {warning}");
            }
        }

        let mut variant_key = surface(serde_json::json!([per_user_jwt()]));
        variant_key.variants[0].enabled = true;
        variant_key.variants[0]
            .overrides
            .access_point = Some(
            serde_json::from_value(serde_json::json!({ "caller_authentication": { "methods": [caller_key()] } }))
                .unwrap(),
        );
        assert_eq!(
            fabric_caller_delegation_warnings(&variant_key, &issuers)
                .iter()
                .map(|found| found.starts_with(&format!("variant 'candidate': {warning}")))
                .collect::<Vec<_>>(),
            [true],
            "only the variant that verifies an API key"
        );
    }

    #[test]
    fn a_transit_point_that_cannot_authenticate_its_callers_is_refused_on_the_surface_and_in_a_variant() {
        let valid = serde_json::json!([{ "alias": "partner", "target_endpoint": "https://partner.example" }]);
        let unauthenticated = serde_json::json!([{ "alias": "partner", "target_endpoint": "https://partner.example",
                "require_transit_token": false }]);
        let refusal = "Transit Point 'partner' authenticates no caller";
        for (case, points, variant_points, expected) in [
            ("on the surface", unauthenticated.clone(), valid.clone(), format!("transit.points[0]: {refusal}")),
            (
                "in a variant",
                valid.clone(),
                unauthenticated.clone(),
                format!("variant 'candidate' transit.points[0]: {refusal}"),
            ),
            (
                "an mTLS source_auth that trusts no certificate",
                serde_json::json!([{ "alias": "partner", "target_endpoint": "https://partner.example",
                    "source_auth": { "type": "mtls", "trust": { "type": "pinned", "certificate_ids": [] },
                        "identity_binding": { "type": "fingerprint" } } }]),
                valid.clone(),
                "transit.points[0]: Channel 'callers': mTLS pinned trust requires at least one certificate_id"
                    .to_string(),
            ),
            (
                "delegated credentials for Fabric callers without the transit token, in a variant",
                valid.clone(),
                serde_json::json!([{ "alias": "partner", "target_endpoint": "https://partner.example",
                    "require_transit_token": false, "source_auth": caller_key(),
                    "delegated_credentials_for_fabric_callers": true }]),
                "variant 'candidate' transit.points[0]: Transit Point 'partner' sets \
                 delegated_credentials_for_fabric_callers but does not require the transit token"
                    .to_string(),
            ),
        ] {
            let mut surface = surface_with_transit_points(points, variant_points);
            match validate_transit_points(&mut surface, 30, None) {
                Err(SurfaceApiError::BadRequest(message)) => {
                    assert!(message.starts_with(&expected), "{case}: {message}")
                }
                other => panic!("{case}: expected a 400, got {other:?}"),
            }
        }

        let mut open = surface_with_transit_points(
            serde_json::json!([{ "alias": "partner", "target_endpoint": "https://partner.example",
                "require_transit_token": false, "allow_unauthenticated_callers": true }]),
            serde_json::json!([{ "alias": "partner", "target_endpoint": "https://partner.example",
                "require_transit_token": false, "source_auth": caller_key() }]),
        );
        assert!(validate_transit_points(&mut open, 30, None).is_ok());
    }

    /// A variant's own Transit Points get an id when sent without one, as the
    /// surface's do, so a grant by binding never sits under an empty id, and
    /// their aliases follow the same rules within the variant's list.
    #[test]
    fn a_variants_transit_points_get_ids_and_checked_aliases() {
        let point = |alias: &str| {
            serde_json::json!({ "id": "", "alias": alias, "target_endpoint": "https://partner.example",
                "require_transit_token": true })
        };
        let mut surface = surface_with_transit_points(
            serde_json::json!([point("partner")]),
            serde_json::json!([point("partner"), point("vendor")]),
        );
        validate_transit_points(&mut surface, 30, None).unwrap();
        let ids: Vec<&str> = surface.variants[0]
            .overrides
            .transit
            .as_ref()
            .unwrap()
            .points
            .as_ref()
            .unwrap()
            .iter()
            .map(|point| point.id.as_str())
            .collect();
        assert!(
            ids.iter()
                .all(|id| !id.is_empty()),
            "{ids:?}"
        );
        assert_ne!(ids[0], ids[1]);

        for (case, variant_points, expected) in [
            (
                "a duplicate alias",
                serde_json::json!([point("vendor"), point("vendor")]),
                "variant 'candidate' transit.points[1]: duplicate alias 'vendor'",
            ),
            (
                "an alias that is not URL-safe",
                serde_json::json!([point("no spaces")]),
                "variant 'candidate' transit.points[0]: ",
            ),
        ] {
            let mut surface = surface_with_transit_points(serde_json::json!([]), variant_points);
            match validate_transit_points(&mut surface, 30, None) {
                Err(SurfaceApiError::BadRequest(message)) => {
                    assert!(message.starts_with(expected), "{case}: {message}")
                }
                other => panic!("{case}: expected a 400, got {other:?}"),
            }
        }
    }

    /// A Transit Point's per-caller rate limit is checked when the surface is
    /// saved, on the surface and in a variant's own points: a limit that could
    /// never admit a request, or has no window, is refused with the point named.
    #[test]
    fn a_save_refuses_a_per_caller_rate_limit_that_cannot_work() {
        let point = |limit: serde_json::Value| {
            serde_json::json!({ "alias": "partner", "target_endpoint": "https://partner.example",
                "require_transit_token": true, "per_caller_rate_limit": limit })
        };
        for (case, limit, expected) in [
            ("no requests", serde_json::json!({ "requests": 0, "window_secs": 60 }), "requests"),
            ("no window", serde_json::json!({ "requests": 5, "window_secs": 0 }), "window_secs"),
            ("a zero burst", serde_json::json!({ "requests": 5, "window_secs": 60, "burst": 0 }), "burst"),
            (
                "more requests than the window can count",
                serde_json::json!({ "requests": 4_000_000_000_u32, "window_secs": 1 }),
                "cannot be enforced",
            ),
            (
                "a window too long to count",
                serde_json::json!({ "requests": 1, "window_secs": 20_000_000_000_u64 }),
                "cannot be enforced",
            ),
            (
                "a burst too long to refill",
                serde_json::json!({ "requests": 1, "window_secs": 1_000_000_000_u64, "burst": 100 }),
                "cannot be enforced",
            ),
        ] {
            let mut on_surface =
                surface_with_transit_points(serde_json::json!([point(limit.clone())]), serde_json::json!([]));
            match validate_transit_points(&mut on_surface, 30, None) {
                Err(SurfaceApiError::BadRequest(message)) => {
                    assert!(
                        message.starts_with("transit.points[0]: ") && message.contains(expected),
                        "{case}: {message}"
                    )
                }
                other => panic!("{case}: expected a 400, got {other:?}"),
            }
            let mut in_variant = surface_with_transit_points(serde_json::json!([]), serde_json::json!([point(limit)]));
            assert!(
                matches!(validate_transit_points(&mut in_variant, 30, None), Err(SurfaceApiError::BadRequest(_))),
                "{case} in a variant"
            );
        }
        let mut fine = surface_with_transit_points(
            serde_json::json!([point(serde_json::json!({ "requests": 5, "window_secs": 60, "burst": 10 }))]),
            serde_json::json!([]),
        );
        assert!(validate_transit_points(&mut fine, 30, None).is_ok());
    }

    /// A save refuses `transit_token_mode: reference`, on the surface or in a
    /// variant's overrides, naming the setting and saying plainly it is not
    /// supported; `embedded` and an absent mode are accepted.
    #[test]
    fn a_save_refuses_reference_transit_tokens_on_the_surface_and_in_a_variant() {
        let surface_with = |base: serde_json::Value, variant: serde_json::Value| {
            let mut surface = surface_with_transit_points(serde_json::json!([]), serde_json::json!([]));
            let transit = surface
                .transit
                .as_mut()
                .unwrap();
            transit
                .shared
                .transit_token_mode = serde_json::from_value(base).unwrap();
            surface.variants[0]
                .overrides
                .transit
                .as_mut()
                .unwrap()
                .shared = Some(serde_json::from_value(serde_json::json!({ "transit_token_mode": variant })).unwrap());
            surface
        };
        for (case, base, variant, expected) in [
            (
                "on the surface",
                serde_json::json!("reference"),
                serde_json::json!("embedded"),
                "transit.transit_token_mode 'reference' is not supported",
            ),
            (
                "in a variant",
                serde_json::json!("embedded"),
                serde_json::json!("reference"),
                "variant 'candidate' transit.transit_token_mode 'reference' is not supported",
            ),
        ] {
            let mut surface = surface_with(base, variant);
            match validate_transit_points(&mut surface, 30, None) {
                Err(SurfaceApiError::BadRequest(message)) => {
                    assert!(message.starts_with(expected), "{case}: {message}");
                    assert!(message.contains("set it to 'embedded'"), "{case}: {message}");
                }
                other => panic!("{case}: expected a 400, got {other:?}"),
            }
        }
        let mut embedded = surface_with(serde_json::json!("embedded"), serde_json::json!("embedded"));
        assert!(validate_transit_points(&mut embedded, 30, None).is_ok());
        let mut absent = surface_with_transit_points(serde_json::json!([]), serde_json::json!([]));
        assert!(validate_transit_points(&mut absent, 30, None).is_ok());
    }

    fn a2a_block(
        versions: &[&str],
        validation: crate::config::agent_surface::A2aValidation,
    ) -> crate::config::agent_surface::A2aAccessPointSettings {
        crate::config::agent_surface::A2aAccessPointSettings {
            accepted_versions: versions
                .iter()
                .map(|v| v.to_string())
                .collect(),
            validation,
            accepted_versions_sent: true,
        }
    }

    #[test]
    fn a_saved_a2a_surface_always_stores_its_a2a_block() {
        let mut surface = base_surface();
        assert_eq!(normalize_a2a_settings(&mut surface, None), Ok(()));
        assert_eq!(surface.access_point.a2a, Some(a2a_block(&["0.3", "1.0"], A2aValidation::Envelope)));

        let mut explicit = base_surface();
        explicit.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Full));
        assert_eq!(normalize_a2a_settings(&mut explicit, None), Ok(()));
        assert_eq!(
            explicit.access_point.a2a,
            Some(a2a_block(&["1.0"], A2aValidation::Full)),
            "an explicit block is kept as sent"
        );
    }

    #[test]
    fn a_saved_surface_with_no_accepted_version_is_refused() {
        let mut surface = base_surface();
        surface.access_point.a2a = Some(a2a_block(&[], A2aValidation::Envelope));
        assert!(
            normalize_a2a_settings(&mut surface, None)
                .unwrap_err()
                .contains("at least one version")
        );
    }

    #[test]
    fn a_new_a2a_proxy_surface_starts_with_a2a_1_0_only() {
        let mut omitted = base_surface();
        omitted.target.endpoint = "a2a-proxy://worker".to_string();
        assert_eq!(normalize_a2a_settings(&mut omitted, None), Ok(()));
        assert_eq!(omitted.access_point.a2a, Some(a2a_block(&["1.0"], A2aValidation::Envelope)));

        let mut both = base_surface();
        both.target.endpoint = "a2a-proxy://worker".to_string();
        both.access_point.a2a = Some(a2a_block(&["0.3", "1.0"], A2aValidation::Envelope));
        assert_eq!(
            normalize_a2a_settings(&mut both, None),
            Err("the accepted A2A versions of a surface whose Target is an A2A proxy are fixed at [1.0]".to_string())
        );
    }

    /// A block that sets only the validation level asks for no versions, so an
    /// A2A-proxy surface takes its fixed ones rather than refusing the defaults
    /// the block was read with.
    #[test]
    fn a_block_without_versions_takes_the_fixed_versions_of_an_a2a_proxy_surface() {
        let block = |json: serde_json::Value| -> crate::config::agent_surface::A2aAccessPointSettings {
            serde_json::from_value(json).unwrap()
        };

        let mut created = base_surface();
        created.target.endpoint = "a2a-proxy://worker".to_string();
        created.access_point.a2a = Some(block(serde_json::json!({ "validation": "envelope" })));
        assert_eq!(normalize_a2a_settings(&mut created, None), Ok(()));
        assert_eq!(created.access_point.a2a, Some(a2a_block(&["1.0"], A2aValidation::Envelope)));

        let existing = stored_surface("a2a-proxy://worker", a2a_block(&["0.3", "1.0"], A2aValidation::Envelope));
        let mut edited = existing.clone();
        edited.access_point.a2a = Some(block(serde_json::json!({ "validation": "envelope" })));
        assert_eq!(normalize_a2a_settings(&mut edited, Some(&existing)), Ok(()));
        assert_eq!(edited.access_point.a2a, Some(a2a_block(&["0.3", "1.0"], A2aValidation::Envelope)));

        let mut named = base_surface();
        named.target.endpoint = "a2a-proxy://worker".to_string();
        named.access_point.a2a = Some(block(serde_json::json!({ "accepted_versions": ["0.3", "1.0"] })));
        assert!(normalize_a2a_settings(&mut named, None).is_err(), "versions a caller names are still checked");
    }

    /// A hand-edited invalid version list is served as both versions, or as the
    /// one valid version it names, and those become the fixed versions, so the
    /// surface can be saved again.
    #[test]
    fn an_a2a_proxy_surface_with_an_invalid_stored_list_takes_the_versions_it_is_served_with() {
        for (stored_versions, served) in
            [(&[][..], &["0.3", "1.0"][..]), (&["9.9"][..], &["0.3", "1.0"][..]), (&["1.0", "9.9"][..], &["1.0"][..])]
        {
            let existing = stored_surface("a2a-proxy://worker", a2a_block(stored_versions, A2aValidation::Envelope));
            let mut omitted = existing.clone();
            omitted.access_point.a2a = None;
            assert_eq!(normalize_a2a_settings(&mut omitted, Some(&existing)), Ok(()), "{stored_versions:?}");
            assert_eq!(omitted.access_point.a2a, Some(a2a_block(served, A2aValidation::Envelope)));

            let mut echoed = existing.clone();
            assert_eq!(normalize_a2a_settings(&mut echoed, Some(&existing)), Ok(()), "{stored_versions:?}");
            assert_eq!(echoed.access_point.a2a, Some(a2a_block(served, A2aValidation::Envelope)));
        }
    }

    fn stored_surface(
        endpoint: &str,
        block: crate::config::agent_surface::A2aAccessPointSettings,
    ) -> AgentSurface {
        let mut surface = base_surface();
        surface.target.endpoint = endpoint.to_string();
        surface.access_point.a2a = Some(block);
        surface
    }

    /// An A2A-proxy surface stored with A2A 0.3, as one from before per-surface
    /// settings is, keeps exactly those versions: sent unchanged, omitted, or
    /// changed, which is refused.
    #[test]
    fn an_existing_a2a_proxy_surface_keeps_its_versions() {
        let existing = stored_surface("a2a-proxy://worker", a2a_block(&["0.3", "1.0"], A2aValidation::Envelope));

        let mut echoed = existing.clone();
        assert_eq!(normalize_a2a_settings(&mut echoed, Some(&existing)), Ok(()));
        assert_eq!(echoed.access_point.a2a, Some(a2a_block(&["0.3", "1.0"], A2aValidation::Envelope)));

        let mut omitted = base_surface();
        omitted.target.endpoint = "a2a-proxy://worker".to_string();
        retain_a2a_settings(&mut omitted, &existing);
        assert_eq!(normalize_a2a_settings(&mut omitted, Some(&existing)), Ok(()));
        assert_eq!(omitted.access_point.a2a, Some(a2a_block(&["0.3", "1.0"], A2aValidation::Envelope)));

        for versions in [&["1.0"][..], &["0.3"]] {
            let mut changed = existing.clone();
            changed.access_point.a2a = Some(a2a_block(versions, A2aValidation::Envelope));
            assert_eq!(
                normalize_a2a_settings(&mut changed, Some(&existing)),
                Err("the accepted A2A versions of a surface whose Target is an A2A proxy are fixed at [0.3, 1.0]"
                    .to_string()),
                "{versions:?}"
            );
        }
    }

    fn surface_with_transit_lifetime(lifetime: Option<u64>) -> AgentSurface {
        let mut s = base_surface();
        s.transit = Some(crate::config::agent_surface::TransitConfig {
            points: Vec::new(),
            outbound_listen_address: None,
            shared: Default::default(),
        });
        s.transit
            .as_mut()
            .expect("transit")
            .shared
            .transit_token_lifetime_secs = lifetime;
        s
    }

    fn stored_lifetime(surface: &AgentSurface) -> Option<u64> {
        surface
            .transit
            .as_ref()
            .and_then(|transit| {
                transit
                    .shared
                    .transit_token_lifetime_secs
            })
    }

    /// A PUT that omits the lifetime keeps the stored one, tightened or
    /// lengthened, and one that sets it wins.
    #[test]
    fn a_put_that_omits_the_transit_token_lifetime_keeps_the_stored_one() {
        for stored in [30, 900] {
            let existing = surface_with_transit_lifetime(Some(stored));
            let mut omitted = surface_with_transit_lifetime(None);
            retain_transit_token_lifetime(&mut omitted, &existing);
            assert_eq!(stored_lifetime(&omitted), Some(stored));
        }
        let existing = surface_with_transit_lifetime(Some(900));
        let mut changed = surface_with_transit_lifetime(Some(60));
        retain_transit_token_lifetime(&mut changed, &existing);
        assert_eq!(stored_lifetime(&changed), Some(60));
        let mut fresh = surface_with_transit_lifetime(None);
        retain_transit_token_lifetime(&mut fresh, &surface_with_transit_lifetime(None));
        assert_eq!(stored_lifetime(&fresh), None);
    }

    /// A PUT without `transit` keeps the lifetime a stored base block with no
    /// Transit Points carries, and removes a block that has Transit Points.
    #[test]
    fn a_put_without_transit_keeps_the_lifetime_of_a_base_block_with_no_transit_points() {
        let existing = surface_with_transit_lifetime(Some(600));
        let mut omitted = base_surface();
        retain_transit_token_lifetime(&mut omitted, &existing);
        assert_eq!(stored_lifetime(&omitted), Some(600));
        assert!(
            omitted
                .transit
                .as_ref()
                .is_some_and(|transit| transit.points.is_empty())
        );

        let mut without_lifetime = base_surface();
        retain_transit_token_lifetime(&mut without_lifetime, &surface_with_transit_lifetime(None));
        assert!(
            without_lifetime
                .transit
                .is_none()
        );

        let mut with_points = surface_with_transit_lifetime(Some(600));
        with_points
            .transit
            .as_mut()
            .expect("transit")
            .points
            .push(
                serde_json::from_value(serde_json::json!({
                    "name": "partner",
                    "target_endpoint": "https://partner.example/a2a",
                    "protocol": "a2a"
                }))
                .expect("transit point"),
            );
        let mut removed = base_surface();
        retain_transit_token_lifetime(&mut removed, &with_points);
        assert!(removed.transit.is_none());
    }

    /// A merge PATCH with a `null` is the way to reset the lifetime to its
    /// default.
    #[test]
    fn a_merge_patch_that_nulls_the_transit_token_lifetime_resets_it() {
        let existing = surface_with_transit_lifetime(Some(900));
        let mut merged = serde_json::to_value(&existing).unwrap();
        json_patch::merge(&mut merged, &serde_json::json!({ "transit": { "transit_token_lifetime_secs": null } }));
        let surface: AgentSurface = serde_json::from_value(merged).unwrap();
        assert_eq!(stored_lifetime(&surface), None);
        assert_eq!(surface.transit_token_lifetime_secs(), 300);
    }

    fn with_url_variant(surface: AgentSurface) -> AgentSurface {
        let mut value = serde_json::to_value(surface).unwrap();
        value["variants"] = serde_json::json!([{
            "id": "v", "alias": "url", "name": "url", "enabled": true,
            "overrides": {"target": {"endpoint": "https://agent.example"}}
        }]);
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn an_a2a_proxy_surface_with_a_url_variant_stores_its_block() {
        let mut sent = base_surface();
        sent.target.endpoint = "a2a-proxy://worker".to_string();
        sent.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Full));
        let mut sent = with_url_variant(sent);
        assert_eq!(normalize_a2a_settings(&mut sent, None), Ok(()));
        assert_eq!(sent.access_point.a2a, Some(a2a_block(&["1.0"], A2aValidation::Full)));

        let mut omitted = base_surface();
        omitted.target.endpoint = "a2a-proxy://worker".to_string();
        let mut omitted = with_url_variant(omitted);
        assert_eq!(normalize_a2a_settings(&mut omitted, None), Ok(()));
        assert_eq!(
            omitted.access_point.a2a,
            Some(a2a_block(&["1.0"], A2aValidation::Envelope)),
            "a new A2A-proxy surface starts from 1.0 only, URL variant or not"
        );
    }

    #[test]
    fn a_put_that_omits_the_block_keeps_it_on_an_a2a_proxy_surface_with_a_url_variant() {
        let mut existing = base_surface();
        existing.target.endpoint = "a2a-proxy://worker".to_string();
        existing.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Full));
        let existing = with_url_variant(existing);

        let mut omitted = base_surface();
        omitted.target.endpoint = "a2a-proxy://worker".to_string();
        let mut omitted = with_url_variant(omitted);
        retain_a2a_settings(&mut omitted, &existing);
        assert_eq!(normalize_a2a_settings(&mut omitted, None), Ok(()));
        assert_eq!(omitted.access_point.a2a, Some(a2a_block(&["1.0"], A2aValidation::Full)));
    }

    #[test]
    fn a_new_a2a_proxy_surface_refuses_a_validation_level_other_than_envelope() {
        for validation in [A2aValidation::Full, A2aValidation::Off] {
            let mut surface = base_surface();
            surface.target.endpoint = "a2a-proxy://worker".to_string();
            surface.access_point.a2a = Some(a2a_block(&["1.0"], validation));
            assert!(
                normalize_a2a_settings(&mut surface, None)
                    .unwrap_err()
                    .starts_with("an A2A proxy target always checks the JSON-RPC envelope only")
            );
        }
    }

    #[test]
    fn a_non_a2a_surface_stores_no_a2a_block() {
        let mut surface = base_surface();
        surface.access_point.protocol = SurfaceProtocol::Mcp;
        surface.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Envelope));
        assert_eq!(normalize_a2a_settings(&mut surface, None), Ok(()));
        assert_eq!(surface.access_point.a2a, None);
    }

    #[test]
    fn a_block_sent_on_a_non_a2a_surface_is_refused() {
        let mut mcp = base_surface();
        mcp.access_point.protocol = SurfaceProtocol::Mcp;
        mcp.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Envelope));
        match refuse_a2a_settings_sent_on_other_protocols(&mcp) {
            Err(SurfaceApiError::BadRequest(message)) => {
                assert_eq!(message, "access_point.a2a requires an A2A or AP2 Access Point")
            }
            other => panic!("expected a 400, got {other:?}"),
        }

        mcp.access_point.a2a = None;
        assert!(refuse_a2a_settings_sent_on_other_protocols(&mcp).is_ok(), "no block, nothing to refuse");

        let mut a2a = base_surface();
        a2a.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Full));
        assert!(refuse_a2a_settings_sent_on_other_protocols(&a2a).is_ok(), "an A2A surface may carry it");
    }

    #[test]
    fn only_a_patch_body_that_sets_the_block_counts_as_sending_it() {
        assert!(patch_sets_a2a_settings(&serde_json::json!({ "access_point": { "a2a": { "validation": "off" } } })));
        assert!(!patch_sets_a2a_settings(&serde_json::json!({ "access_point": { "a2a": null } })));
        assert!(!patch_sets_a2a_settings(&serde_json::json!({ "access_point": { "protocol": "mcp" } })));
        assert!(!patch_sets_a2a_settings(&serde_json::json!({ "name": "renamed" })));
    }

    /// A level the surface already had must not turn an edit that leaves only
    /// A2A-proxy Targets into a 400: a merge `PATCH` moving the Target to a proxy,
    /// a `PUT` echoing the block from `GET`, or a variant change that removes the
    /// last URL Target all carry it unchanged. It is reset to `envelope`, and
    /// the versions are kept.
    #[test]
    fn an_unchanged_stored_level_is_reset_to_envelope_once_it_applies_to_nothing() {
        for level in [A2aValidation::Envelope, A2aValidation::Full, A2aValidation::Off] {
            let existing = stored_surface("a2a-proxy://worker", a2a_block(&["1.0"], level));
            let mut edited = existing.clone();
            edited.name = "renamed".to_string();

            assert_eq!(normalize_a2a_settings(&mut edited, Some(&existing)), Ok(()), "{level:?}");
            assert_eq!(edited.access_point.a2a, Some(a2a_block(&["1.0"], A2aValidation::Envelope)));
        }
    }

    #[test]
    fn a_changed_level_that_applies_to_nothing_is_still_refused() {
        let existing = stored_surface("a2a-proxy://worker", a2a_block(&["1.0"], A2aValidation::Envelope));
        let mut changed = existing.clone();
        changed.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Full));

        assert!(
            normalize_a2a_settings(&mut changed, Some(&existing))
                .unwrap_err()
                .starts_with("an A2A proxy target always checks the JSON-RPC envelope only")
        );
    }

    fn tenant() -> PatTenantContext {
        PatTenantContext {
            token_id: "token".to_string(),
            tenant_id: "tenant-a".to_string(),
        }
    }

    #[test]
    fn a_tenant_token_cannot_turn_validation_off() {
        let mut surface = base_surface();
        surface.access_point.a2a = Some(a2a_block(&["0.3", "1.0"], A2aValidation::Off));
        let envelope = a2a_block(&["0.3", "1.0"], A2aValidation::Envelope);

        match refuse_validation_off_by_scoped_caller(&surface, Some(&envelope), Some(&tenant()), None, false) {
            Err(SurfaceApiError::Forbidden(message)) => assert!(message.contains("appliance-wide administrator")),
            other => panic!("expected a 403, got {other:?}"),
        }
        assert!(
            matches!(
                refuse_validation_off_by_scoped_caller(&surface, None, Some(&tenant()), None, false),
                Err(SurfaceApiError::Forbidden(_))
            ),
            "on create too"
        );
    }

    /// A resource scope makes a caller scoped on its own, without relying on the
    /// token model always pairing it with a tenant.
    #[test]
    fn a_resource_scoped_token_cannot_turn_validation_off_with_or_without_a_tenant() {
        let mut surface = base_surface();
        surface.access_point.a2a = Some(a2a_block(&["0.3", "1.0"], A2aValidation::Off));
        let envelope = a2a_block(&["0.3", "1.0"], A2aValidation::Envelope);
        let scope =
            PatResourceScope(std::sync::Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:surfaces:.*\z").unwrap()));

        for context in [None, Some(tenant())] {
            assert!(
                matches!(
                    refuse_validation_off_by_scoped_caller(
                        &surface,
                        Some(&envelope),
                        context.as_ref(),
                        Some(&scope),
                        false
                    ),
                    Err(SurfaceApiError::Forbidden(_))
                ),
                "tenant context: {context:?}"
            );
        }
        let off = a2a_block(&["1.0"], A2aValidation::Off);
        assert!(
            refuse_validation_off_by_scoped_caller(&surface, Some(&off), None, Some(&scope), false).is_ok(),
            "a scoped caller may edit a surface that is already off"
        );
    }

    /// A token scoped by required headers alone carries neither a tenant nor a
    /// resource scope, yet is still a scoped caller.
    #[test]
    fn a_token_scoped_by_required_headers_alone_cannot_turn_validation_off() {
        let mut surface = base_surface();
        surface.access_point.a2a = Some(a2a_block(&["0.3", "1.0"], A2aValidation::Off));
        let envelope = a2a_block(&["0.3", "1.0"], A2aValidation::Envelope);

        assert!(matches!(
            refuse_validation_off_by_scoped_caller(&surface, Some(&envelope), None, None, true),
            Err(SurfaceApiError::Forbidden(_))
        ));
        let off = a2a_block(&["1.0"], A2aValidation::Off);
        assert!(
            refuse_validation_off_by_scoped_caller(&surface, Some(&off), None, None, true).is_ok(),
            "it may edit a surface that is already off"
        );
    }

    #[test]
    fn validation_off_is_allowed_for_an_appliance_wide_caller_or_when_already_off() {
        let mut surface = base_surface();
        surface.access_point.a2a = Some(a2a_block(&["0.3", "1.0"], A2aValidation::Off));
        let off = a2a_block(&["1.0"], A2aValidation::Off);

        assert!(
            refuse_validation_off_by_scoped_caller(&surface, None, None, None, false).is_ok(),
            "appliance-wide caller"
        );
        assert!(
            refuse_validation_off_by_scoped_caller(&surface, Some(&off), Some(&tenant()), None, false).is_ok(),
            "a tenant may edit a surface that is already off"
        );

        surface.access_point.a2a = Some(a2a_block(&["0.3", "1.0"], A2aValidation::Full));
        assert!(
            refuse_validation_off_by_scoped_caller(&surface, None, Some(&tenant()), None, false).is_ok(),
            "a tenant may choose any other level"
        );
    }

    #[test]
    fn a_put_that_omits_the_a2a_block_keeps_the_stored_one() {
        let mut existing = base_surface();
        existing.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Envelope));

        let mut omitted = base_surface();
        retain_a2a_settings(&mut omitted, &existing);
        assert_eq!(omitted.access_point.a2a, existing.access_point.a2a);

        let mut changed = base_surface();
        changed.access_point.a2a = Some(a2a_block(&["0.3"], A2aValidation::Full));
        retain_a2a_settings(&mut changed, &existing);
        assert_eq!(
            changed.access_point.a2a,
            Some(a2a_block(&["0.3"], A2aValidation::Full)),
            "a sent block replaces the stored one"
        );
    }

    #[test]
    fn a_put_that_changes_the_protocol_away_from_a2a_drops_the_stored_block() {
        let mut existing = base_surface();
        existing.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Full));

        let mut mcp = base_surface();
        mcp.access_point.protocol = SurfaceProtocol::Mcp;
        retain_a2a_settings(&mut mcp, &existing);
        assert_eq!(normalize_a2a_settings(&mut mcp, None), Ok(()));
        assert_eq!(mcp.access_point.a2a, None);
    }

    #[test]
    fn a_merge_patch_that_changes_the_protocol_away_from_a2a_drops_the_stored_block() {
        let mut existing = base_surface();
        existing.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Full));

        let mut merged = serde_json::to_value(&existing).unwrap();
        json_patch::merge(&mut merged, &serde_json::json!({ "access_point": { "protocol": "mcp" } }));
        let mut patched: AgentSurface = serde_json::from_value(merged).unwrap();
        assert!(
            patched
                .access_point
                .a2a
                .is_some(),
            "the merge carries the stored block"
        );

        assert_eq!(normalize_a2a_settings(&mut patched, None), Ok(()));
        assert_eq!(patched.access_point.a2a, None);
    }

    /// A Target moved to an A2A proxy is treated as a new A2A-proxy surface: the
    /// carried versions become `["1.0"]` and the carried level `envelope`.
    #[test]
    fn a_save_that_moves_the_target_to_an_a2a_proxy_starts_at_a2a_1_0_only() {
        let existing = stored_surface("https://agent.example", a2a_block(&["0.3", "1.0"], A2aValidation::Full));

        let mut omitted = base_surface();
        omitted.target.endpoint = "a2a-proxy://worker".to_string();
        retain_a2a_settings(&mut omitted, &existing);
        assert_eq!(normalize_a2a_settings(&mut omitted, Some(&existing)), Ok(()));
        assert_eq!(omitted.access_point.a2a, Some(a2a_block(&["1.0"], A2aValidation::Envelope)));

        let mut carried = existing.clone();
        carried.target.endpoint = "a2a-proxy://worker".to_string();
        assert_eq!(normalize_a2a_settings(&mut carried, Some(&existing)), Ok(()));
        assert_eq!(carried.access_point.a2a, Some(a2a_block(&["1.0"], A2aValidation::Envelope)));

        let mut asked_for_0_3 = existing.clone();
        asked_for_0_3.target.endpoint = "a2a-proxy://worker".to_string();
        asked_for_0_3.access_point.a2a = Some(a2a_block(&["0.3"], A2aValidation::Envelope));
        assert!(normalize_a2a_settings(&mut asked_for_0_3, Some(&existing)).is_err());
    }

    #[test]
    fn a_put_that_moves_off_an_a2a_proxy_keeps_the_stored_versions() {
        let mut existing = base_surface();
        existing.target.endpoint = "a2a-proxy://worker".to_string();
        existing.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Envelope));

        let mut moved = base_surface();
        retain_a2a_settings(&mut moved, &existing);
        assert_eq!(normalize_a2a_settings(&mut moved, Some(&existing)), Ok(()));
        assert_eq!(moved.access_point.a2a, Some(a2a_block(&["1.0"], A2aValidation::Envelope)));
    }

    #[test]
    fn a_merge_patch_that_nulls_the_a2a_block_resets_it_to_the_defaults() {
        let mut existing = base_surface();
        existing.access_point.a2a = Some(a2a_block(&["1.0"], A2aValidation::Full));

        let mut merged = serde_json::to_value(&existing).unwrap();
        json_patch::merge(&mut merged, &serde_json::json!({ "access_point": { "a2a": null } }));
        let mut patched: AgentSurface = serde_json::from_value(merged).unwrap();
        assert_eq!(patched.access_point.a2a, None);

        assert_eq!(normalize_a2a_settings(&mut patched, None), Ok(()));
        assert_eq!(patched.access_point.a2a, Some(a2a_block(&["0.3", "1.0"], A2aValidation::Envelope)));
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
                a2a: None,
                public: None,
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
                fabric_delegated_credentials: false,
            },
            transit: None,
            canvas: None,
            variants: Vec::new(),
            default_variant_id: None,
            outbound_credentials: Vec::new(),
            identity_slots: Default::default(),
            mcp_legacy_metadata_output: None,
            _retired_protocol_mode: Default::default(),
            mcp_http: None,
            trust_check_split: false,
            transit_point_source_auth: false,
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

    #[tokio::test]
    async fn a_default_variant_on_a_surface_with_no_variants_is_saved_as_a_bad_request() {
        let mut s = base_surface();
        s.default_variant_id = Some("x".to_string());

        let response = validate_variant_aliases(&s)
            .expect_err("a default naming no variant must fail")
            .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"], "Bad Request");
        assert!(
            body["details"]
                .as_str()
                .is_some_and(|details| details.contains("'x'")),
            "{body}"
        );
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

    fn api_key_caller(secret_id: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "api_key",
            "extraction": { "source": "http_header", "field": "X-API-Key" },
            "secret_id": secret_id
        })
    }

    fn provider_caller() -> serde_json::Value {
        serde_json::json!({
            "type": "api_key_provider",
            "extraction": { "source": "http_header", "field": "X-API-Key" },
            "agent_id": "agent-1"
        })
    }

    fn jwt_caller() -> serde_json::Value {
        serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [] })
    }

    fn caller_methods(methods: &[serde_json::Value]) -> Option<crate::config::agent_surface::CallerAuthentication> {
        Some(serde_json::from_value(serde_json::json!({ "methods": methods })).expect("valid caller authentication"))
    }

    fn from_api_key(id: Option<&str>) -> Option<crate::source_auth::ManagedIdentityConfig> {
        Some(crate::source_auth::ManagedIdentityConfig::FromApiKey {
            api_key_id: id.map(str::to_string),
        })
    }

    fn inbound_api_key_surface(caller: &[serde_json::Value]) -> AgentSurface {
        let mut s = base_surface();
        s.access_point
            .caller_authentication = caller_methods(caller);
        s.identity_slots.inbound = from_api_key(None);
        s
    }

    fn refusal(result: Result<(), SurfaceApiError>) -> String {
        match result {
            Err(SurfaceApiError::BadRequest(message)) => message,
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn inbound_from_api_key_is_accepted_behind_api_key_or_provider_caller_methods() {
        for (case, callers) in [
            ("api key", vec![api_key_caller("caller-keys")]),
            ("api key provider", vec![provider_caller()]),
            ("both", vec![api_key_caller("caller-keys"), provider_caller()]),
        ] {
            let s = inbound_api_key_surface(&callers);
            assert!(validate_api_key_identities(&s, "").is_ok(), "{case}");
        }
    }

    #[test]
    fn inbound_from_api_key_refusal_matches_the_dashboard_text() {
        assert_eq!(
            INBOUND_API_KEY_NEEDS_API_KEY_CALLER,
            "Identity 'From API Key' needs every Caller Context method to be API Key or API Key Provider"
        );
    }

    #[test]
    fn inbound_from_api_key_is_refused_unless_every_caller_method_is_an_api_key() {
        for (case, caller) in [
            ("no caller authentication", vec![]),
            ("jwt only", vec![jwt_caller()]),
            ("api key second", vec![jwt_caller(), provider_caller()]),
            ("jwt second", vec![api_key_caller("caller-keys"), jwt_caller()]),
        ] {
            let s = inbound_api_key_surface(&caller);
            assert!(refusal(validate_api_key_identities(&s, "")) == INBOUND_API_KEY_NEEDS_API_KEY_CALLER, "{case}");
        }

        let mut other_mode = inbound_api_key_surface(&[jwt_caller()]);
        other_mode
            .identity_slots
            .inbound = None;
        assert!(validate_api_key_identities(&other_mode, "").is_ok(), "another inbound mode");
    }

    #[test]
    fn inbound_from_api_key_is_refused_beside_mcp_resource_tokens() {
        let mut s = inbound_api_key_surface(&[provider_caller()]);
        s.access_point.protocol = SurfaceProtocol::Mcp;
        s.mcp_http = Some(Default::default());
        assert!(validate_api_key_identities(&s, "").is_ok(), "mcp_http without authorization");

        s.mcp_http = Some(
            serde_json::from_value(serde_json::json!({ "authorization": { "resource": "https://mcp.example/mcp" } }))
                .unwrap(),
        );
        assert!(refusal(validate_api_key_identities(&s, "")) == INBOUND_API_KEY_WITH_RESOURCE_TOKENS);
    }

    #[test]
    fn inbound_from_api_key_is_refused_on_an_mcp_proxy_target() {
        let mut s = inbound_api_key_surface(&[provider_caller()]);
        s.access_point.protocol = SurfaceProtocol::Mcp;
        s.target.endpoint = "proxy://mcp-proxy-1".to_string();
        assert!(refusal(validate_api_key_identities(&s, "")) == INBOUND_API_KEY_ON_MCP_PROXY);

        s.identity_slots.inbound = None;
        assert!(validate_api_key_identities(&s, "").is_ok(), "another inbound mode");

        let mut a2a = inbound_api_key_surface(&[provider_caller()]);
        a2a.target.endpoint = "a2a-proxy://worker".to_string();
        assert!(validate_api_key_identities(&a2a, "").is_ok(), "a2a-proxy target");
    }

    #[test]
    fn stored_from_api_key_slots_need_a_non_empty_key_id() {
        for (case, id) in [("no id", None), ("empty id", Some("")), ("blank id", Some("  "))] {
            let mut protected = base_surface();
            protected
                .identity_slots
                .protected = from_api_key(id);
            assert!(
                refusal(validate_api_key_identities(&protected, ""))
                    == format!("identity_slots.protected: {API_KEY_IDENTITY_NEEDS_ID}"),
                "{case}"
            );

            let mut external = base_surface();
            external
                .identity_slots
                .external = from_api_key(id);
            assert!(
                refusal(validate_api_key_identities(&external, ""))
                    == format!("identity_slots.external: {API_KEY_IDENTITY_NEEDS_ID}"),
                "{case}"
            );
        }

        let transit = with_transit(
            base_surface(),
            serde_json::json!({ "points": [{
                "alias": "partner", "target_endpoint": "https://partner.example",
                "managed_identity": { "type": "from_api_key", "api_key_id": "" }
            }] }),
        );
        assert!(
            refusal(validate_api_key_identities(&transit, ""))
                == format!("transit.points['partner'].managed_identity: {API_KEY_IDENTITY_NEEDS_ID}")
        );

        let mut keyed = base_surface();
        keyed.identity_slots.protected = from_api_key(Some("managed-key"));
        keyed.identity_slots.external = from_api_key(Some("external-key"));
        assert!(validate_api_key_identities(&keyed, "").is_ok(), "both slots keyed");
    }

    #[test]
    fn one_key_may_identify_both_a_managed_agent_and_a_caller() {
        let mut slots = base_surface();
        slots.identity_slots.protected = from_api_key(Some("shared"));
        slots.identity_slots.external = from_api_key(Some("shared"));
        assert!(validate_api_key_identities(&slots, "").is_ok(), "protected and external");

        let mut plain_caller = inbound_api_key_surface(&[api_key_caller("shared")]);
        plain_caller
            .identity_slots
            .protected = from_api_key(Some("shared"));
        assert!(validate_api_key_identities(&plain_caller, "").is_ok(), "protected and plain caller secret");

        let mut transit = with_transit(
            base_surface(),
            serde_json::json!({ "points": [{
                "alias": "partner", "target_endpoint": "https://partner.example",
                "managed_identity": { "type": "from_api_key", "api_key_id": "shared" }
            }] }),
        );
        transit
            .identity_slots
            .external = from_api_key(Some("shared"));
        assert!(validate_api_key_identities(&transit, "").is_ok(), "Transit Point and external");
    }

    fn variant_with_caller(
        alias: &str,
        enabled: bool,
        caller: &[serde_json::Value],
    ) -> SurfaceVariant {
        SurfaceVariant {
            id: format!("v-{alias}"),
            alias: alias.to_string(),
            name: alias.to_string(),
            description: String::new(),
            enabled,
            overrides: SurfaceOverrides {
                access_point: Some(
                    serde_json::from_value(serde_json::json!({ "caller_authentication": { "methods": caller } }))
                        .unwrap(),
                ),
                ..Default::default()
            },
        }
    }

    #[test]
    fn a_variant_switching_inbound_from_api_key_callers_to_jwt_is_refused() {
        let mut s = inbound_api_key_surface(&[provider_caller()]);
        s.variants
            .push(variant_with_caller("jwt", true, &[jwt_caller()]));
        assert!(
            refusal(validate_resolved_variants(&s)) == format!("Variant 'jwt': {INBOUND_API_KEY_NEEDS_API_KEY_CALLER}")
        );

        s.variants[0].enabled = false;
        assert!(validate_resolved_variants(&s).is_ok(), "a disabled variant is not resolved");
    }

    #[test]
    fn inbound_api_key_ids_are_dropped_from_the_base_and_every_variant() {
        let mut s = base_surface();
        s.identity_slots.inbound = from_api_key(Some("stale-inbound"));
        s.identity_slots.protected = from_api_key(Some("managed-key"));
        for (alias, enabled) in [("on", true), ("off", false)] {
            let mut variant = variant_with_caller(alias, enabled, &[provider_caller()]);
            variant
                .overrides
                .identity_slots = Some(crate::config::agent_surface::SurfaceIdentitySlots {
                inbound: from_api_key(Some("stale-variant")),
                protected: from_api_key(Some("variant-managed-key")),
                external: None,
            });
            s.variants.push(variant);
        }

        drop_inbound_api_key_ids(&mut s);

        assert_eq!(s.identity_slots.inbound, from_api_key(None));
        assert_eq!(s.identity_slots.protected, from_api_key(Some("managed-key")));
        for variant in &s.variants {
            let slots = variant
                .overrides
                .identity_slots
                .as_ref()
                .unwrap();
            assert_eq!(slots.inbound, from_api_key(None), "{}", variant.alias);
            assert_eq!(slots.protected, from_api_key(Some("variant-managed-key")), "{}", variant.alias);
        }
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
            protected_resource: None,
            on_failure: crate::config::agent_surface::OnFailure::Continue,
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
        validate_source_auth(&s, None).expect("defaults must pass");
    }

    #[test]
    fn source_auth_validation_rejects_zero_challenge_ttl() {
        let mut cfg = valid_didauth_config();
        cfg.challenge_ttl_seconds = Some(0);
        let s = didauth_surface(cfg);
        let err = validate_source_auth(&s, None).expect_err("challenge_ttl_seconds=0 must fail on save");
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
        let err = validate_source_auth(&s, None).expect_err("session_ttl_seconds=0 must fail on save");
        assert!(matches!(err, SurfaceApiError::BadRequest(_)));
    }

    /// A DID Auth session lasts at most 24 hours: a longer
    /// `session_ttl_seconds` is refused on save, and the longest is accepted.
    #[test]
    fn source_auth_validation_rejects_a_session_ttl_over_the_longest() {
        use crate::source_auth::models::DidAuthAuthConfig;
        let mut cfg = valid_didauth_config();
        cfg.session_ttl_seconds = Some(DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS + 1);
        let err =
            validate_source_auth(&didauth_surface(cfg.clone()), None).expect_err("over the longest must fail on save");
        match err {
            SurfaceApiError::BadRequest(msg) => assert!(msg.contains("session_ttl_seconds"), "{msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
        cfg.session_ttl_seconds = Some(DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS);
        validate_source_auth(&didauth_surface(cfg), None).expect("the longest passes");
    }

    #[test]
    fn source_auth_validation_rejects_unsupported_algorithm() {
        let mut cfg = valid_didauth_config();
        cfg.allowed_algorithms = vec!["HS256".into()];
        let s = didauth_surface(cfg);
        let err = validate_source_auth(&s, None).expect_err("HS256 must fail on save");
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
        let err = validate_source_auth(&s, None).expect_err("blank DID must fail on save");
        assert!(matches!(err, SurfaceApiError::BadRequest(_)));
    }

    #[test]
    fn source_auth_validation_rejects_malformed_did() {
        let mut cfg = valid_didauth_config();
        cfg.allowed_dids = vec!["not-a-did".into()];
        let s = didauth_surface(cfg);
        let err = validate_source_auth(&s, None).expect_err("non-DID string must fail on save");
        assert!(matches!(err, SurfaceApiError::BadRequest(_)));
    }

    #[test]
    fn source_auth_validation_ignores_surfaces_without_caller_auth() {
        // No caller auth → nothing to check; must succeed regardless.
        let s = base_surface();
        validate_source_auth(&s, None).expect("no caller_auth must pass");
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
            protected_resource: None,
            on_failure: crate::config::agent_surface::OnFailure::Continue,
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
    fn delegation_source_auth_rejects_a_later_jwt_bearer_method_on_the_authorization_header() {
        use crate::source_auth::models::{ApiKeyAuthConfig, CredentialExtraction, SourceAuthConfig};
        let mut s = delegated_mpp_surface();
        let mut caller = jwt_bearer_auth("Authorization");
        caller.methods.insert(
            0,
            SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
                extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".into() },
                secret_id: "keys".into(),
            }),
        );
        s.access_point
            .caller_authentication = Some(caller);
        assert!(matches!(validate_delegation_source_auth(&s), Err(SurfaceApiError::BadRequest(_))));
    }

    #[test]
    fn source_auth_validation_checks_each_enabled_variant() {
        let mut s = didauth_surface(valid_didauth_config());
        s.variants = vec![serde_json::from_value(serde_json::json!({
            "id": "partner",
            "alias": "partner",
            "name": "Partner",
            "enabled": true,
            "overrides": {
                "access_point": {
                    "caller_authentication": {
                        "methods": [
                            {"type": "api_key", "extraction": {"source": "http_header", "field": "X-Key"}, "secret_id": "a"},
                            {"type": "api_key", "extraction": {"source": "http_header", "field": "x-key"}, "secret_id": "b"}
                        ]
                    }
                }
            }
        }))
        .unwrap()];
        match validate_source_auth(&s, None) {
            Err(SurfaceApiError::BadRequest(msg)) => {
                assert!(msg.starts_with("variant 'partner': ") && msg.contains("both read the 'x-key' header"), "{msg}")
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        s.variants[0].enabled = false;
        validate_source_auth(&s, None).expect("a disabled variant is not validated on save");
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

    fn target_trust_check(id: &str) -> crate::trust_registry_verification::TrustCheckElement {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "trust_registry_id": "tr-1",
            "query_type": "recognition",
            "query": {
                "authority_id": "did:web:authority.example",
                "entity_id": "{{ target.did }}"
            }
        }))
        .expect("trust check element")
    }

    fn bad_request_message(result: Result<(), SurfaceApiError>) -> String {
        match result {
            Err(SurfaceApiError::BadRequest(msg)) => msg,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    fn variant_with_target(
        overrides: TargetOverrides,
        enabled: bool,
    ) -> SurfaceVariant {
        SurfaceVariant {
            id: "v-dev".to_string(),
            alias: "dev".to_string(),
            name: "dev".to_string(),
            description: String::new(),
            enabled,
            overrides: SurfaceOverrides {
                target: Some(overrides),
                ..Default::default()
            },
        }
    }

    fn fabric_surface_with_point(
        point_list: Vec<crate::trust_registry_verification::TrustCheckElement>
    ) -> AgentSurface {
        let mut s = base_surface();
        s.target.endpoint = "fabric://gateway-1/surface-1".to_string();
        s.target.trust_check_list = vec![target_trust_check("fabric-target")];
        let mut point: crate::config::agent_surface::TransitPoint = serde_json::from_value(serde_json::json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example/a2a",
            "protocol": "a2a"
        }))
        .expect("transit point");
        point.trust_check_list = point_list;
        s.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![point],
            outbound_listen_address: None,
            shared: Default::default(),
        });
        s
    }

    fn point(surface: &AgentSurface) -> &crate::config::agent_surface::TransitPoint {
        &surface
            .transit
            .as_ref()
            .expect("transit")
            .points[0]
    }

    fn migrated(mut surface: AgentSurface) -> AgentSurface {
        for point in surface
            .transit
            .iter_mut()
            .flat_map(|transit| transit.points.iter_mut())
        {
            point.trust_check_migrated = !point
                .trust_check_list
                .is_empty();
        }
        surface
    }

    #[test]
    fn an_undeclared_https_body_is_converted_and_then_passes_the_target_rule() {
        let mut body = fabric_surface_with_point(Vec::new());
        body.target.endpoint = "https://prod.example.com".to_string();
        assert!(reject_target_trust_checks_unless_target_runs_them(&body).is_err());

        convert_old_shape_body(&mut body).expect("converted");

        assert!(
            body.target
                .trust_check_list
                .is_empty()
        );
        assert_eq!(point(&body).trust_check_list[0].id, "fabric-target");
        assert!(point(&body).trust_check_migrated);
        assert!(reject_target_trust_checks_unless_target_runs_them(&body).is_ok());
        assert!(body.has_trust_check_lists(), "a Transit Point list remains, so the marker is persisted");
    }

    #[test]
    fn declared_bodies_and_bodies_without_target_lists_are_not_converted() {
        let mut declared = fabric_surface_with_point(Vec::new());
        declared.trust_check_split = true;
        convert_old_shape_body(&mut declared).expect("declared");
        assert!(
            point(&declared)
                .trust_check_list
                .is_empty()
        );

        let mut without_target_list = fabric_surface_with_point(Vec::new());
        without_target_list
            .target
            .trust_check_list
            .clear();
        convert_old_shape_body(&mut without_target_list).expect("no target list");
        assert!(
            point(&without_target_list)
                .trust_check_list
                .is_empty()
        );
    }

    #[test]
    fn conversion_leaves_fields_outside_the_trust_check_lists_as_sent() {
        let mut body = fabric_surface_with_point(Vec::new());
        body.target.endpoint = "https://prod.example.com".to_string();
        body.access_point.a2a = None;
        let before = body.access_point.clone();

        convert_old_shape_body(&mut body).expect("converted");

        assert_eq!(serde_json::to_value(&body.access_point).unwrap(), serde_json::to_value(&before).unwrap());
        assert!(
            body.access_point
                .a2a
                .is_none()
        );
    }

    fn two_point_fabric_surface(
        first: Vec<crate::trust_registry_verification::TrustCheckElement>,
        second: Vec<crate::trust_registry_verification::TrustCheckElement>,
    ) -> AgentSurface {
        let mut s = fabric_surface_with_point(first);
        let mut point: crate::config::agent_surface::TransitPoint = serde_json::from_value(serde_json::json!({
            "id": "tp-b", "alias": "partner-b", "target_endpoint": "https://b.example/a2a"
        }))
        .unwrap();
        point.trust_check_list = second;
        s.transit
            .as_mut()
            .unwrap()
            .points
            .push(point);
        s
    }

    fn points_of(surface: &AgentSurface) -> Vec<(Vec<String>, bool)> {
        surface
            .transit
            .as_ref()
            .unwrap()
            .points
            .iter()
            .map(|p| {
                (
                    p.trust_check_list
                        .iter()
                        .map(|e| e.id.clone())
                        .collect(),
                    p.trust_check_migrated,
                )
            })
            .collect()
    }

    fn with_stored_point_ids(
        mut body: AgentSurface,
        stored: &AgentSurface,
    ) -> AgentSurface {
        let stored_points = &stored
            .transit
            .as_ref()
            .unwrap()
            .points;
        for (point, stored_point) in body
            .transit
            .as_mut()
            .unwrap()
            .points
            .iter_mut()
            .zip(stored_points)
        {
            point.id = stored_point.id.clone();
        }
        body
    }

    fn put(
        body: &mut AgentSurface,
        stored: &AgentSurface,
    ) -> Result<(), SurfaceApiError> {
        let sent = serde_json::to_value(&*body).expect("sent");
        settle_undeclared_put(body, stored, &sent)
    }

    #[test]
    fn an_undeclared_put_does_not_refill_transit_points_emptied_on_a_marked_surface() {
        let mut stored = fabric_surface_with_point(Vec::new());
        stored.trust_check_split = true;
        let mut body = stored.clone();
        body.trust_check_split = false;

        put(&mut body, &stored).expect("unchanged body");

        assert!(
            point(&body)
                .trust_check_list
                .is_empty(),
            "the emptied Transit Point stays empty"
        );
        assert!(!point(&body).trust_check_migrated);
        assert_eq!(body.target.trust_check_list[0].id, "fabric-target");
    }

    #[test]
    fn a_body_that_already_carries_transit_point_lists_is_not_converted() {
        let mut body = two_point_fabric_surface(vec![target_trust_check("own")], Vec::new());

        convert_old_shape_body(&mut body).expect("new-shape body");

        assert_eq!(
            points_of(&body),
            vec![(vec!["own".to_string()], false), (Vec::new(), false)],
            "a Transit Point meant to have no checks is left without them"
        );
        assert_eq!(body.target.trust_check_list[0].id, "fabric-target");
    }

    #[test]
    fn an_undeclared_put_that_drops_a_variants_transit_points_is_refused() {
        let mut stored = base_surface();
        stored.variants = vec![variant_with_points(None, vec![target_trust_check("dev-copy")], true)];
        let mut body = stored.clone();
        body.variants[0]
            .overrides
            .transit = None;

        assert_eq!(refused(put(&mut body, &stored)), PER_TRANSIT_POINT_REQUIRED);

        let mut kept = stored.clone();
        put(&mut kept, &stored).expect("variant sent with its Transit Points");
    }

    #[test]
    fn an_unmarked_surface_without_lists_is_still_converted() {
        let mut stored = fabric_surface_with_point(Vec::new());
        stored
            .target
            .trust_check_list
            .clear();
        let mut body = stored.clone();
        body.target.trust_check_list = vec![target_trust_check("old-shape")];

        put(&mut body, &stored).expect("converted");

        assert_eq!(point(&body).trust_check_list[0].id, "old-shape");
        assert!(point(&body).trust_check_migrated);
    }

    #[test]
    fn a_transit_point_sent_with_a_new_id_does_not_take_a_stored_list_by_alias() {
        let stored = migrated(fabric_surface_with_point(vec![target_trust_check("copied")]));
        let mut body = stored.clone();
        body.transit
            .as_mut()
            .unwrap()
            .points[0]
            .id = "replacement-point".to_string();
        {
            let replacement = &mut body
                .transit
                .as_mut()
                .unwrap()
                .points[0];
            replacement
                .trust_check_list
                .clear();
            replacement.trust_check_migrated = false;
        }

        put(&mut body, &stored).expect("replacement point");

        assert!(
            point(&body)
                .trust_check_list
                .is_empty(),
            "a point with a different id is a new point, whatever its alias"
        );
        assert!(!point(&body).trust_check_migrated);
    }

    #[test]
    fn a_transit_point_sent_without_an_id_keeps_the_stored_list_by_alias() {
        let stored = migrated(fabric_surface_with_point(vec![target_trust_check("copied")]));
        let mut body = stored.clone();
        body.transit
            .as_mut()
            .unwrap()
            .points[0]
            .trust_check_list
            .clear();
        let mut sent = serde_json::to_value(&body).unwrap();
        sent["transit"]["points"][0]
            .as_object_mut()
            .unwrap()
            .remove("id");

        settle_undeclared_put(&mut body, &stored, &sent).expect("point without id");

        assert_eq!(point(&body).trust_check_list[0].id, "copied");
        assert!(point(&body).trust_check_migrated);
    }

    #[test]
    fn a_missing_base_target_list_keeps_the_stored_one_and_an_explicit_empty_one_is_refused() {
        let stored = migrated(fabric_surface_with_point(vec![target_trust_check("copied")]));
        let mut body = fabric_surface_with_point(Vec::new());
        body.target
            .trust_check_list
            .clear();

        let mut missing = body.clone();
        put(&mut missing, &stored).expect("missing target list");
        assert_eq!(
            missing
                .target
                .trust_check_list[0]
                .id,
            "fabric-target",
            "the stored target list is kept"
        );

        let mut sent = serde_json::to_value(&body).unwrap();
        sent["target"]["trust_check_list"] = serde_json::json!(null);
        let mut null_list = body.clone();
        settle_undeclared_put(&mut null_list, &stored, &sent).expect("null target list");
        assert_eq!(
            null_list
                .target
                .trust_check_list[0]
                .id,
            "fabric-target"
        );

        sent["target"]["trust_check_list"] = serde_json::json!([]);
        let mut empty = body.clone();
        assert_eq!(refused(settle_undeclared_put(&mut empty, &stored, &sent)), PER_TRANSIT_POINT_REQUIRED);
    }

    #[test]
    fn a_missing_variant_target_list_keeps_the_stored_one_and_an_explicit_empty_one_is_refused() {
        let mut stored = base_surface();
        stored.variants = vec![variant_with_points(
            Some(vec![target_trust_check("dev-target")]),
            vec![target_trust_check("dev-copy")],
            true,
        )];
        let mut body = base_surface();
        body.variants = vec![variant_with_points(None, Vec::new(), false)];

        let mut missing = body.clone();
        put(&mut missing, &stored).expect("missing variant target list");
        let kept = missing.variants[0]
            .overrides
            .target
            .as_ref()
            .and_then(|target| {
                target
                    .trust_check_list
                    .clone()
            })
            .expect("kept list");
        assert_eq!(kept[0].id, "dev-target");

        let mut sent = serde_json::to_value(&body).unwrap();
        sent["variants"][0]["overrides"]["target"]["trust_check_list"] = serde_json::json!([]);
        let mut empty = body.clone();
        empty.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .trust_check_list = Some(Vec::new());
        assert_eq!(refused(settle_undeclared_put(&mut empty, &stored, &sent)), PER_TRANSIT_POINT_REQUIRED);
    }

    #[test]
    fn an_explicit_empty_target_list_matching_an_empty_stored_one_is_accepted() {
        let mut stored = migrated(fabric_surface_with_point(vec![target_trust_check("copied")]));
        stored
            .target
            .trust_check_list
            .clear();
        let mut body = fabric_surface_with_point(Vec::new());
        body.target
            .trust_check_list
            .clear();
        let mut sent = serde_json::to_value(&body).unwrap();
        sent["target"]["trust_check_list"] = serde_json::json!([]);

        settle_undeclared_put(&mut body, &stored, &sent).expect("unchanged empty list");
        assert!(
            body.target
                .trust_check_list
                .is_empty()
        );
    }

    fn refused(result: Result<(), SurfaceApiError>) -> String {
        match result {
            Err(SurfaceApiError::BadRequest(msg)) => msg,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn an_undeclared_get_put_of_a_split_fabric_surface_leaves_an_emptied_point_empty() {
        let stored = migrated(two_point_fabric_surface(vec![target_trust_check("fabric-target")], Vec::new()));
        let mut body = stored.clone();

        put(&mut body, &stored).expect("unchanged body");

        assert_eq!(points_of(&body), vec![(vec!["fabric-target".to_string()], true), (Vec::new(), false)]);
        assert_eq!(body.target.trust_check_list[0].id, "fabric-target");
    }

    #[test]
    fn an_undeclared_put_without_point_lists_keeps_stored_lists_and_flags() {
        let mut stored = two_point_fabric_surface(vec![target_trust_check("copied")], vec![target_trust_check("kept")]);
        stored
            .transit
            .as_mut()
            .unwrap()
            .points[0]
            .trust_check_migrated = true;
        let mut body = with_stored_point_ids(two_point_fabric_surface(Vec::new(), Vec::new()), &stored);

        put(&mut body, &stored).expect("old-shape body");

        assert_eq!(
            points_of(&body),
            vec![(vec!["copied".to_string()], true), (vec!["kept".to_string()], false)],
            "a Keep-cleared or manually added list survives with its flag as stored"
        );
    }

    #[test]
    fn an_undeclared_put_that_changes_a_list_on_a_split_surface_is_refused() {
        let stored = migrated(fabric_surface_with_point(vec![target_trust_check("copied")]));

        let mut changed_target = fabric_surface_with_point(Vec::new());
        changed_target
            .target
            .trust_check_list = vec![target_trust_check("other")];
        assert_eq!(refused(put(&mut changed_target, &stored)), PER_TRANSIT_POINT_REQUIRED);

        let mut changed_point = fabric_surface_with_point(vec![target_trust_check("other")]);
        assert_eq!(refused(put(&mut changed_point, &stored)), PER_TRANSIT_POINT_REQUIRED);

        let mut new_point = two_point_fabric_surface(Vec::new(), vec![target_trust_check("new")]);
        assert_eq!(refused(put(&mut new_point, &stored)), PER_TRANSIT_POINT_REQUIRED);

        let mut same = with_stored_point_ids(fabric_surface_with_point(vec![target_trust_check("copied")]), &stored);
        put(&mut same, &stored).expect("an unchanged list is accepted");
    }

    #[test]
    fn stored_lists_are_matched_by_id_then_alias() {
        let mut stored = migrated(fabric_surface_with_point(vec![target_trust_check("copied")]));
        stored
            .transit
            .as_mut()
            .unwrap()
            .points[0]
            .id = "tp-1".to_string();
        let mut renamed = fabric_surface_with_point(Vec::new());
        {
            let point = &mut renamed
                .transit
                .as_mut()
                .unwrap()
                .points[0];
            point.id = "tp-1".to_string();
            point.alias = "renamed".to_string();
        }

        put(&mut renamed, &stored).expect("renamed point");

        assert_eq!(points_of(&renamed), vec![(vec!["copied".to_string()], true)]);
    }

    fn variant_with_points(
        target_list: Option<Vec<crate::trust_registry_verification::TrustCheckElement>>,
        point_list: Vec<crate::trust_registry_verification::TrustCheckElement>,
        migrated: bool,
    ) -> SurfaceVariant {
        let mut point: crate::config::agent_surface::TransitPoint = serde_json::from_value(serde_json::json!({
            "id": "tp-dev", "alias": "dev-partner", "target_endpoint": "https://d.example/a2a"
        }))
        .unwrap();
        point.trust_check_list = point_list;
        point.trust_check_migrated = migrated;
        let mut variant = variant_with_target(
            TargetOverrides {
                endpoint: Some("fabric://gateway-1/dev".to_string()),
                trust_check_list: target_list,
                ..Default::default()
            },
            true,
        );
        variant.overrides.transit = Some(crate::config::agent_surface_variants::TransitOverrides {
            points: Some(vec![point]),
            ..Default::default()
        });
        variant
    }

    fn variant_point(surface: &AgentSurface) -> (Vec<String>, bool) {
        let point = &surface.variants[0]
            .overrides
            .transit
            .as_ref()
            .unwrap()
            .points
            .as_ref()
            .unwrap()[0];
        (
            point
                .trust_check_list
                .iter()
                .map(|e| e.id.clone())
                .collect(),
            point.trust_check_migrated,
        )
    }

    #[test]
    fn variant_points_keep_stored_lists_and_refuse_changes_on_an_undeclared_put() {
        let mut stored = base_surface();
        stored.variants = vec![variant_with_points(
            Some(vec![target_trust_check("dev-target")]),
            vec![target_trust_check("dev-copy")],
            true,
        )];

        let mut kept = base_surface();
        kept.variants = vec![variant_with_points(Some(vec![target_trust_check("dev-target")]), Vec::new(), false)];
        put(&mut kept, &stored).expect("old-shape variant body");
        assert_eq!(variant_point(&kept), (vec!["dev-copy".to_string()], true));

        let mut changed_target = base_surface();
        changed_target.variants = vec![variant_with_points(Some(vec![target_trust_check("other")]), Vec::new(), false)];
        assert_eq!(refused(put(&mut changed_target, &stored)), PER_TRANSIT_POINT_REQUIRED);

        let mut changed_point = base_surface();
        changed_point.variants = vec![variant_with_points(None, vec![target_trust_check("other")], false)];
        assert_eq!(refused(put(&mut changed_point, &stored)), PER_TRANSIT_POINT_REQUIRED);
    }

    #[test]
    fn an_undeclared_put_on_an_unsplit_surface_is_still_converted() {
        let stored = fabric_surface_with_point(Vec::new());
        let mut body = fabric_surface_with_point(Vec::new());
        body.target.endpoint = "https://prod.example.com".to_string();

        put(&mut body, &stored).expect("converted");

        assert_eq!(points_of(&body), vec![(vec!["fabric-target".to_string()], true)]);
        assert!(
            body.target
                .trust_check_list
                .is_empty()
        );
    }

    #[test]
    fn a_declared_put_is_taken_as_sent() {
        let stored = migrated(fabric_surface_with_point(vec![target_trust_check("copied")]));
        let mut body = fabric_surface_with_point(Vec::new());
        body.trust_check_split = true;

        put(&mut body, &stored).expect("declared");

        assert_eq!(points_of(&body), vec![(Vec::new(), false)]);
    }

    #[test]
    fn a_variant_only_inheriting_a_base_list_is_not_checked_against_its_endpoint() {
        let mut s = base_surface();
        s.target.endpoint = "a2a-proxy://worker".to_string();
        s.target.trust_check_list = vec![target_trust_check("proxy-target")];
        s.variants = vec![variant_with_target(
            TargetOverrides {
                endpoint: Some("https://dev.example.com".to_string()),
                ..Default::default()
            },
            true,
        )];
        assert!(reject_target_trust_checks_unless_target_runs_them(&s).is_ok());

        s.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .trust_check_list = Some(vec![target_trust_check("own")]);
        assert!(reject_target_trust_checks_unless_target_runs_them(&s).is_err());
    }

    #[test]
    fn an_undeclared_edit_of_trust_check_lists_is_refused_only_when_points_hold_lists() {
        let with_lists = migrated(fabric_surface_with_point(vec![target_trust_check("copied")]));
        let without_lists = fabric_surface_with_point(Vec::new());

        let msg = match reject_undeclared_trust_check_edit(true, &with_lists) {
            Err(SurfaceApiError::BadRequest(msg)) => msg,
            other => panic!("expected BadRequest, got {other:?}"),
        };
        assert_eq!(
            msg,
            "this surface uses the per-Transit-Point Trust Check shape; send trust_check_split: true to \
             change its Trust Check lists (transit.points[].trust_check_list, target.trust_check_list)"
        );
        assert!(reject_undeclared_trust_check_edit(false, &with_lists).is_ok());
        assert!(reject_undeclared_trust_check_edit(true, &without_lists).is_ok());
    }

    #[test]
    fn patches_touch_trust_checks_through_list_paths_or_null_ancestors() {
        let without_variant_lists = base_surface();
        for touching in [
            serde_json::json!({"target": {"trust_check_list": []}}),
            serde_json::json!({"target": {"trust_check_list": null}}),
            serde_json::json!({"target": null}),
            serde_json::json!({"transit": {"points": []}}),
            serde_json::json!({"transit": null}),
            serde_json::json!({"variants": [{"overrides": {"target": {"trust_check_list": []}}}]}),
            serde_json::json!({"variants": [{"overrides": {"transit": {"points": []}}}]}),
            serde_json::json!({"variants": [{"overrides": {"transit": null}}]}),
            serde_json::json!({"variants": [{"overrides": {"target": null}}]}),
            serde_json::json!({"variants": [{"overrides": null}]}),
        ] {
            assert!(patch_touches_trust_checks(&touching, &without_variant_lists), "{touching}");
        }
        for other in [
            serde_json::json!({"description": "d"}),
            serde_json::json!({"target": {"endpoint": "https://x"}}),
            serde_json::json!({"transit": {"shared": {}}}),
            serde_json::json!({"variants": [{"overrides": {"target": {"endpoint": "https://x"}}}]}),
            serde_json::json!({"variants": []}),
        ] {
            assert!(!patch_touches_trust_checks(&other, &without_variant_lists), "{other}");
        }
        for touching in [
            serde_json::json!({"overrides": {"transit": {"points": null}}}),
            serde_json::json!({"overrides": {"transit": null}}),
            serde_json::json!({"overrides": {"target": null}}),
            serde_json::json!({"overrides": null}),
        ] {
            assert!(variant_patch_touches_trust_checks(&touching), "{touching}");
        }
        assert!(!variant_patch_touches_trust_checks(&serde_json::json!({"name": "dev"})));
        assert!(!variant_patch_touches_trust_checks(&serde_json::json!({"overrides": {"canvas": null}})));
    }

    #[test]
    fn replacing_variants_touches_trust_checks_when_a_stored_variant_holds_point_lists() {
        let mut point: crate::config::agent_surface::TransitPoint = serde_json::from_value(serde_json::json!({
            "alias": "dev-partner", "target_endpoint": "https://d.example/a2a"
        }))
        .unwrap();
        point.trust_check_list = vec![target_trust_check("dev-copy")];
        let mut variant = variant_with_target(TargetOverrides::default(), true);
        variant.overrides.transit = Some(crate::config::agent_surface_variants::TransitOverrides {
            points: Some(vec![point]),
            ..Default::default()
        });
        let mut stored = base_surface();
        stored.variants = vec![variant];

        assert!(patch_touches_trust_checks(&serde_json::json!({"variants": []}), &stored));
        assert!(patch_touches_trust_checks(&serde_json::json!({"variants": null}), &stored));
        assert!(!patch_touches_trust_checks(&serde_json::json!({"description": "d"}), &stored));
    }

    #[test]
    fn target_trust_checks_rejected_unless_the_target_runs_them() {
        for endpoint in ["https://prod.example.com", "http://prod.example.com", "proxy://mcp-proxy-1", ""] {
            let mut s = base_surface();
            s.target.endpoint = endpoint.to_string();
            s.target.trust_check_list = vec![target_trust_check("target-check")];

            let msg = bad_request_message(reject_target_trust_checks_unless_target_runs_them(&s));
            assert!(
                msg.starts_with(
                    "target.trust_check_list is only allowed for a2a-proxy:// and fabric:// Managed Agent targets"
                ),
                "{endpoint}: {msg}"
            );
            assert!(msg.contains("transit.points[].trust_check_list"), "{msg}");
        }
    }

    #[test]
    fn target_trust_checks_accepted_on_fabric_and_a2a_proxy_targets() {
        for endpoint in ["fabric://gateway-1/surface-1", "a2a-proxy://proxy-1"] {
            let mut s = base_surface();
            s.target.endpoint = endpoint.to_string();
            s.target.trust_check_list = vec![target_trust_check("target-check")];

            assert!(reject_target_trust_checks_unless_target_runs_them(&s).is_ok(), "{endpoint} must be accepted");
        }
    }

    #[test]
    fn https_target_without_target_list_accepts_transit_point_lists() {
        let mut s = base_surface();
        let mut point: crate::config::agent_surface::TransitPoint = serde_json::from_value(serde_json::json!({
            "alias": "partner-a",
            "target_endpoint": "https://partner.example/a2a",
            "protocol": "a2a"
        }))
        .expect("transit point");
        point.trust_check_list = vec![target_trust_check("partner-check")];
        s.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![point],
            outbound_listen_address: None,
            shared: Default::default(),
        });

        assert!(reject_target_trust_checks_unless_target_runs_them(&s).is_ok());
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn variant_target_trust_checks_rejected_on_https_variant_target() {
        for enabled in [true, false] {
            let mut s = base_surface();
            s.target.endpoint = "fabric://gateway-1/surface-1".to_string();
            s.variants = vec![variant_with_target(
                TargetOverrides {
                    endpoint: Some("https://dev.example.com".to_string()),
                    trust_check_list: Some(vec![target_trust_check("dev-check")]),
                    ..Default::default()
                },
                enabled,
            )];

            let msg = bad_request_message(reject_target_trust_checks_unless_target_runs_them(&s));
            assert!(msg.starts_with("Variant 'dev': target.trust_check_list is only allowed"), "{msg}");
            assert!(msg.contains("transit.points[].trust_check_list"), "{msg}");
        }
    }

    #[test]
    fn variant_clearing_list_on_https_target_is_accepted() {
        let mut s = base_surface();
        s.target.endpoint = "fabric://gateway-1/surface-1".to_string();
        s.target.trust_check_list = vec![target_trust_check("base-check")];
        s.variants = vec![variant_with_target(
            TargetOverrides {
                endpoint: Some("https://dev.example.com".to_string()),
                trust_check_list: Some(Vec::new()),
                ..Default::default()
            },
            true,
        )];

        assert!(reject_target_trust_checks_unless_target_runs_them(&s).is_ok());
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
    fn another_tenants_or_out_of_scope_surface_is_hidden_but_an_operators_is_visible() {
        let tenant = tenant("tenant-a");
        let prefixed = scope(r"\ATENANT:tenant-a:surfaces:boris-.*\z");
        assert!(surface_visible(None, "boris-op", Some(&tenant), Some(&prefixed)));
        assert!(surface_visible(Some("tenant-a"), "boris-s1", Some(&tenant), Some(&prefixed)));
        assert!(!surface_visible(Some("tenant-b"), "boris-s1", Some(&tenant), Some(&prefixed)));
        assert!(!surface_visible(Some("tenant-a"), "other-s1", Some(&tenant), Some(&prefixed)));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{TrustRecorderConfig, TrustRecorderEntry};

    #[test]
    fn test_surface_response_reports_the_status_of_the_surface_its_url_serves() {
        let api_key = serde_json::json!({"methods": [{"type": "api_key",
            "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}]});
        let surface = |public: serde_json::Value, default_variant: Option<&str>| -> AgentSurface {
            serde_json::from_value(serde_json::json!({
                "surface_id": "saved", "name": "saved",
                "access_point": {"listen_address": "http://localhost:8080", "route": "/agent", "protocol": "a2a",
                    "public": public, "caller_authentication": api_key},
                "target": {"endpoint": "http://localhost:8081"},
                "variants": [{"id": "beta", "alias": "beta", "name": "Beta", "enabled": true,
                    "overrides": {"complete": true, "access_point": {}}}],
                "default_variant_id": default_variant
            }))
            .unwrap()
        };

        let response = serde_json::to_value(SurfaceResponse::from(surface(serde_json::json!(false), None))).unwrap();
        assert_eq!(response["surface_id"], "saved");
        assert_eq!(response["access_point_status"], "ready");
        assert!(
            response
                .get("warnings")
                .is_none(),
            "warnings are Warning headers: {response}"
        );
        assert!(
            response["access_point"]
                .get("access_point_status")
                .is_none(),
            "the status is top-level, never inside access_point: {response}"
        );

        let response =
            serde_json::to_value(SurfaceResponse::from(surface(serde_json::json!(false), Some("beta")))).unwrap();
        assert_eq!(
            response["access_point_status"], "not_ready",
            "the URL serves the default variant, which authenticates no caller: {response}"
        );

        let response =
            serde_json::to_value(SurfaceResponse::from(surface(serde_json::json!(true), Some("beta")))).unwrap();
        assert_eq!(response["access_point_status"], "ready");
    }

    #[test]
    fn test_variant_response_reports_the_status_of_that_variant() {
        let api_key = serde_json::json!({"methods": [{"type": "api_key",
            "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}]});
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "saved", "name": "saved",
            "access_point": {"listen_address": "http://localhost:8080", "route": "/agent", "protocol": "a2a",
                "public": false, "caller_authentication": api_key},
            "target": {"endpoint": "http://localhost:8081"},
            "variants": [{"id": "beta", "alias": "beta", "name": "Beta", "enabled": true,
                "overrides": {"complete": true, "access_point": {}}}]
        }))
        .unwrap();
        let variant = surface.variants[0].clone();

        let response = serde_json::to_value(SurfaceResponse::variant(variant, &surface)).unwrap();

        assert_eq!(response["id"], "beta");
        assert_eq!(response["access_point_status"], "not_ready");
        assert!(
            response
                .get("warnings")
                .is_none(),
            "warnings are Warning headers: {response}"
        );
        assert_eq!(serde_json::to_value(SurfaceResponse::from(surface)).unwrap()["access_point_status"], "ready");
    }

    #[test]
    fn test_write_body_sent_back_from_a_response_loses_only_its_access_point_status() {
        let mut sent = serde_json::json!({"name": "saved", "access_point_status": "ready"});
        assert!(drop_access_point_status(&mut sent));
        assert_eq!(sent, serde_json::json!({"name": "saved"}));
        assert!(!drop_access_point_status(&mut sent));
        let mut not_an_object = serde_json::json!(["access_point_status"]);
        assert!(!drop_access_point_status(&mut not_an_object));
    }

    fn entry(registry: &str) -> TrustRecorderEntry {
        TrustRecorderEntry {
            trust_registry_id: registry.into(),
            issuer_did: "did:example:issuer".into(),
            authority_did: "did:example:authority".into(),
            include_owned_agent: true,
            custom_resources: vec![],
        }
    }

    fn surface_recording(registries: &[&str]) -> AgentSurface {
        let mut surface = AgentSurface::default();
        surface
            .access_point
            .trust_recorder = Some(TrustRecorderConfig {
            entries: registries
                .iter()
                .map(|registry| entry(registry))
                .collect(),
        });
        surface
    }

    #[tokio::test]
    async fn deleting_a_surface_evicts_its_transit_point_tool_gating() {
        let manager = crate::policies::SurfacePolicyManager::new();
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "doomed", "name": "doomed", "description": "", "status": "active",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/doomed", "protocol": "mcp" },
            "target": { "endpoint": "http://localhost:9000" },
            "transit": { "points": [{
                "alias": "partner", "target_endpoint": "https://partner.example.com/mcp", "protocol": "mcp",
                "mcp_tool_gating": { "gates": [{ "id": "g1", "name": "no admin",
                    "action": { "effect": "deny", "patterns": ["^admin_"] } }] }
            }] }
        }))
        .unwrap();
        refresh_surface_policies(&manager, SurfaceChange::Upsert(&surface)).await;
        assert!(manager.has_transit_mcp_tool_gating("doomed", "partner"));

        refresh_surface_policies(&manager, SurfaceChange::Delete("doomed")).await;

        assert!(!manager.has_transit_mcp_tool_gating("doomed", "partner"));
    }

    fn surface_with_variant_transit_points(points: serde_json::Value) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "gated", "name": "gated", "description": "", "status": "active",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/gated", "protocol": "mcp" },
            "target": { "endpoint": "http://localhost:9000" },
            "transit": { "points": [{
                "alias": "partner", "target_endpoint": "https://partner.example.com/mcp", "protocol": "mcp",
                "policy": { "policy_definition_id": "partner-policy" },
                "mcp_tool_gating": { "gates": [{ "id": "g1", "name": "no admin",
                    "action": { "effect": "deny", "patterns": ["^admin_"] } }] },
                "per_caller_rate_limit": { "requests": 5, "window_secs": 60 }
            }] },
            "variants": [{ "id": "v-dev", "alias": "dev", "name": "dev", "enabled": true,
                "overrides": { "transit": { "points": points } } }]
        }))
        .unwrap()
    }

    fn variant_point(settings: serde_json::Value) -> serde_json::Value {
        let mut point = serde_json::json!({
            "alias": "partner", "target_endpoint": "https://partner-dev.example.com/mcp", "protocol": "mcp"
        });
        point
            .as_object_mut()
            .unwrap()
            .extend(
                settings
                    .as_object()
                    .unwrap()
                    .clone(),
            );
        point
    }

    #[test]
    fn a_variant_transit_point_may_restate_or_omit_the_surface_transit_point_enforcement() {
        let restated = variant_point(serde_json::json!({
            "policy": { "policy_definition_id": "partner-policy" },
            "mcp_tool_gating": { "gates": [{ "id": "g1", "name": "no admin",
                "action": { "effect": "deny", "patterns": ["^admin_"] } }] },
            "per_caller_rate_limit": { "requests": 5, "window_secs": 60 }
        }));
        let omitted = variant_point(serde_json::json!({}));
        let burst_written_out = variant_point(
            serde_json::json!({ "per_caller_rate_limit": { "requests": 5, "window_secs": 60, "burst": 5 } }),
        );

        for points in
            [serde_json::json!([restated]), serde_json::json!([omitted]), serde_json::json!([burst_written_out])]
        {
            let surface = surface_with_variant_transit_points(points.clone());
            assert!(validate_surface_mcp_tool_gating(&surface).is_ok(), "{points}");
        }
    }

    #[test]
    fn a_variant_transit_point_that_changes_the_surface_transit_point_enforcement_is_refused() {
        let other_gating = serde_json::json!({ "gates": [{ "id": "g2", "name": "no delete",
            "action": { "effect": "deny", "patterns": ["^delete_"] } }] });
        for (field, point) in [
            ("mcp_tool_gating", variant_point(serde_json::json!({ "mcp_tool_gating": other_gating }))),
            ("policy", variant_point(serde_json::json!({ "policy": { "policy_definition_id": "dev-policy" } }))),
            (
                "policy",
                variant_point(serde_json::json!({
                    "policy": { "policy_definition_id": "partner-policy", "require_agent_context": true }
                })),
            ),
            (
                "response_policy",
                variant_point(serde_json::json!({ "response_policy": { "policy_definition_id": "dev-response" } })),
            ),
            (
                "per_caller_rate_limit",
                variant_point(serde_json::json!({ "per_caller_rate_limit": { "requests": 50, "window_secs": 60 } })),
            ),
            (
                "per_caller_rate_limit",
                serde_json::json!({
                    "alias": "dev-only", "target_endpoint": "https://dev-only.example.com/mcp", "protocol": "mcp",
                    "per_caller_rate_limit": { "requests": 5, "window_secs": 60 }
                }),
            ),
            (
                "policy",
                serde_json::json!({
                    "alias": "dev-only", "target_endpoint": "https://dev-only.example.com/mcp", "protocol": "mcp",
                    "policy": { "policy_definition_id": "partner-policy" }
                }),
            ),
        ] {
            let surface = surface_with_variant_transit_points(serde_json::json!([point]));

            let Err(SurfaceApiError::BadRequest(message)) = validate_surface_mcp_tool_gating(&surface) else {
                panic!("a variant transit point changing '{field}' must be refused: {point}");
            };
            assert!(message.contains("variant 'dev'"), "{message}");
            assert!(message.contains(&format!("sets '{field}'")), "{message}");
        }
    }

    #[tokio::test]
    async fn disabling_a_surface_evicts_its_transit_point_tool_gating() {
        let manager = crate::policies::SurfacePolicyManager::new();
        let mut surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "paused", "name": "paused", "description": "", "status": "active",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/paused", "protocol": "mcp" },
            "target": { "endpoint": "http://localhost:9000" },
            "transit": { "points": [{
                "alias": "partner", "target_endpoint": "https://partner.example.com/mcp", "protocol": "mcp",
                "mcp_tool_gating": { "gates": [{ "id": "g1", "name": "no admin",
                    "action": { "effect": "deny", "patterns": ["^admin_"] } }] }
            }] }
        }))
        .unwrap();
        refresh_surface_policies(&manager, SurfaceChange::Upsert(&surface)).await;
        assert!(manager.has_transit_mcp_tool_gating("paused", "partner"));

        surface.status = crate::config::agent_surface::SurfaceStatus::Disabled;
        refresh_surface_policies(&manager, SurfaceChange::Upsert(&surface)).await;

        assert!(!manager.has_transit_mcp_tool_gating("paused", "partner"));
    }

    #[test]
    fn an_unchanged_recorder_is_not_a_change() {
        assert!(!trust_recorder_changed(&surface_recording(&["tr-1"]), &surface_recording(&["tr-1"])));
        assert!(!trust_recorder_changed(&AgentSurface::default(), &AgentSurface::default()));
    }

    #[test]
    fn no_recorder_and_a_recorder_without_entries_are_the_same() {
        assert!(!trust_recorder_changed(&AgentSurface::default(), &surface_recording(&[])));
        assert!(!trust_recorder_changed(&surface_recording(&[]), &AgentSurface::default()));
    }

    #[test]
    fn adding_removing_or_changing_entries_is_a_change() {
        assert!(trust_recorder_changed(&AgentSurface::default(), &surface_recording(&["tr-1"])));
        assert!(trust_recorder_changed(&surface_recording(&["tr-1"]), &AgentSurface::default()));
        assert!(trust_recorder_changed(&surface_recording(&["tr-1"]), &surface_recording(&["tr-2"])));
        assert!(trust_recorder_changed(&surface_recording(&["tr-1"]), &surface_recording(&["tr-1", "tr-2"])));
    }

    #[test]
    fn an_edit_to_an_entry_field_is_a_change() {
        let before = surface_recording(&["tr-1"]);
        let mut after = surface_recording(&["tr-1"]);
        after
            .access_point
            .trust_recorder
            .as_mut()
            .unwrap()
            .entries[0]
            .authority_did = "did:example:other".into();
        assert!(trust_recorder_changed(&before, &after));
    }

    #[test]
    fn changes_outside_the_recorder_are_not_a_change() {
        let before = surface_recording(&["tr-1"]);
        let mut after = surface_recording(&["tr-1"]);
        after.name = "renamed".into();
        assert!(!trust_recorder_changed(&before, &after));
    }
}
