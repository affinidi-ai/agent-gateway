//! CRUD API handlers for Agent Surfaces

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{debug, error, info, warn};

use crate::auth_manager::pat::{PatContext, PatDelegationContext, PatResourceScope};
use crate::config::agent_surface::AgentSurface;
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
        let bytes = axum::body::Bytes::from_request(request, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let mut typed = axum::extract::Request::new(axum::body::Body::from(bytes.clone()));
        *typed.headers_mut() = headers;
        let Json(value) = Json::<T>::from_request(typed, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let sent = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        Ok(Self(value, sent))
    }
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
    delegation: Option<Extension<PatDelegationContext>>,
    Json(mut surface): Json<AgentSurface>,
) -> Result<(StatusCode, Json<AgentSurface>), SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;
    refuse_a2a_settings_sent_on_other_protocols(&surface)?;
    convert_old_shape_body(&mut surface)?;

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

    surface.trust_check_split = surface.has_trust_check_lists();
    store
        .save(&surface)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to save surface: {}", e)))?;

    info!("Created agent surface '{}' (surface_id={})", surface.name, surface.surface_id);

    apply_surface_change(&state, SurfaceChange::Upsert(&surface)).await;

    Ok((StatusCode::CREATED, Json(surface)))
}

/// Whether `access_point` in a PUT body removes its discovery setting.
fn removes_protected_resource(access_point: Option<&serde_json::Value>) -> bool {
    access_point
        .and_then(|access_point| access_point.pointer("/caller_authentication/protected_resource"))
        .is_some_and(serde_json::Value::is_null)
}

/// The discovery settings a PUT removes, for the surface and by variant id. A
/// PUT that omits a setting keeps it, so `null` is how a PUT removes one, in
/// the same request as the rest of the edit.
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

    /// Clears the removed settings, which retention restored from storage.
    fn apply(
        &self,
        surface: &mut AgentSurface,
    ) {
        if self.base
            && let Some(caller) = surface
                .access_point
                .caller_authentication
                .as_mut()
        {
            caller.protected_resource = None;
        }
        for variant in &mut surface.variants {
            if self
                .variant_ids
                .contains(&variant.id)
                && let Some(caller) = variant
                    .overrides
                    .access_point
                    .as_mut()
                    .and_then(|access_point| {
                        access_point
                            .caller_authentication
                            .as_mut()
                    })
            {
                caller.protected_resource = None;
            }
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
    JsonWithSent(mut surface, sent): JsonWithSent<AgentSurface>,
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
    surface.tenant_id = existing.tenant_id.clone();
    if surface
        .mcp_legacy_metadata_output
        .is_none()
    {
        surface.mcp_legacy_metadata_output = existing.mcp_legacy_metadata_output;
    }
    retain_mcp_settings(&mut surface, &existing, &state.network_config)?;
    ProtectedResourceRemovals::of(&sent).apply(&mut surface);
    retain_a2a_settings(&mut surface, &existing);

    let saved = validate_and_save_surface(
        &state,
        store,
        surface,
        Some(&existing),
        tenant_context(&context),
        resource_scope(&scope),
        resource_scoped(&delegation),
    )
    .await?;
    Ok(Json(saved))
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
) -> Result<(), SurfaceApiError> {
    retain_mcp_http(&mut surface.mcp_http, existing.mcp_http.as_ref());
    let base_retained = retain_protected_resource(
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
        if retain_protected_resource(
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
        ) {
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
        let (Some(protected), Some(crate::source_auth::SourceAuthConfig::JwtBearer(jwt))) =
            (resolved.protected_resource(), resolved.source_auth())
        else {
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
    reject_target_trust_checks_unless_target_runs_them(&surface)?;
    validate_workload_binding_config(&surface)?;
    validate_source_auth(&surface)?;
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

    surface.trust_check_split = surface.has_trust_check_lists();
    store
        .save(&surface)
        .await
        .map_err(|e| SurfaceApiError::InternalError(format!("Failed to save surface: {}", e)))?;

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
    if !declares_split(&patch) {
        reject_undeclared_trust_check_edit(patch_touches_trust_checks(&patch, &existing), &existing)?;
    }

    let mut surface: AgentSurface = serde_json::from_value(merged)
        .map_err(|e| SurfaceApiError::BadRequest(format!("Merged surface failed to deserialise: {}", e)))?;
    surface.surface_id = surface_id.clone();
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
    delegation: Option<Extension<PatDelegationContext>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<AgentSurface>, SurfaceApiError> {
    require_merge_patch_content_type(&headers)?;

    if body.is_empty() {
        return Err(SurfaceApiError::BadRequest("PATCH body must not be empty".to_string()));
    }
    let mut patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| SurfaceApiError::BadRequest(format!("PATCH body is not valid JSON: {}", e)))?;
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
        resource_scoped(&delegation),
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

/// Apply the surface as currently stored, or remove it when it is no longer stored.
/// The surface reload lock is held from the read until the change is applied, so a
/// change raised before a configuration reload cannot overwrite what that reload
/// applied. An A2A surface stored without its own settings is served with the
/// carried-over ones, as a load gives them; nothing is written back, because the
/// load that gives the settings also stores them.
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
        resource_scoped(&delegation),
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
    delegation: Option<Extension<PatDelegationContext>>,
    JsonWithSent(body, sent): JsonWithSent<UpdateVariantRequest>,
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
    // setting unless they remove it, as a PUT of the whole surface does.
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
    delegation: Option<Extension<PatDelegationContext>>,
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
        resource_scoped(&delegation),
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
        retain_mcp_settings(&mut rewritten, &existing, &discovery_network()).unwrap();
        let retained = rewritten
            .mcp_http
            .expect("mcp_http stays present");
        assert_eq!(retained.authorization, Some(authorization));
        assert_eq!(retained.allowed_origins, vec!["https://app.example".to_string()]);

        // Omitting the block entirely keeps the stored one unchanged.
        let mut omitted = base_surface();
        omitted.mcp_http = None;
        retain_mcp_settings(&mut omitted, &existing, &discovery_network()).unwrap();
        assert_eq!(omitted.mcp_http, existing.mcp_http);

        // A surface that never had authorization does not gain one.
        let mut fresh = base_surface();
        fresh.mcp_http = Some(crate::config::McpHttpConfig::default());
        retain_mcp_settings(&mut fresh, &base_surface(), &discovery_network()).unwrap();
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
        retain_mcp_settings(&mut rewritten, &existing, &discovery_network()).unwrap();
        assert_eq!(stored_resource(&rewritten), (expected.clone(), expected.clone()));

        // Removing caller authentication does not bring the setting back.
        let mut removed = mcp_surface();
        removed.variants = vec![variant(false)];
        retain_mcp_settings(&mut removed, &existing, &discovery_network()).unwrap();
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
        retain_mcp_settings(&mut fresh, &never, &discovery_network()).unwrap();
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
            retain_mcp_settings(&mut switched, &existing, &discovery_network()).unwrap();
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
            let Err(SurfaceApiError::BadRequest(refused)) =
                retain_mcp_settings(&mut edited, &existing, &discovery_network())
            else {
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
        retain_mcp_settings(&mut a2a, &existing, &discovery_network()).unwrap();
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
        retain_mcp_settings(&mut sent, &existing, &discovery_network()).unwrap();
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
        retain_mcp_settings(&mut put, &existing, &discovery_network()).unwrap();
        removals.apply(&mut put);
        assert_eq!(resources(&put), (false, vec![false, true]));

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
        retain_mcp_settings(&mut put, &existing, &discovery_network()).unwrap();
        removals.apply(&mut put);
        assert_eq!(resources(&put), (true, vec![true, true]));
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
            protected_resource: None,
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
            protected_resource: None,
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
