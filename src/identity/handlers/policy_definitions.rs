//! Policy Definition API handlers
//!
//! CRUD endpoints for managing reusable OPA policy definitions.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::identity::state::IdentityApiState;
use crate::policies::policy_definitions::{
    FileSystemPolicyDefinitionStore, PolicyDefinition, PolicyType, PolicyVersion, validate_policy_scope,
};
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};

/// Application error type for policy definition handlers
#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    InvalidInput(String),
    Forbidden(String),
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct PolicyDefinitionsQuery {
    pub policy_type: Option<String>,
}

/// Returns `true` when `surface` references `policy_id` in any compiled
/// policy slot (target, inbound, response, outbound, per-transit-point) —
/// including per-variant overrides.
fn surface_references_policy(
    surface: &crate::config::agent_surface::AgentSurface,
    policy_id: &str,
) -> bool {
    let matches = |id: Option<&str>| id == Some(policy_id);

    // Base surface slots
    if matches(
        surface
            .target
            .policy
            .as_ref()
            .map(|p| {
                p.policy_definition_id
                    .as_str()
            }),
    ) {
        return true;
    }
    if matches(
        surface
            .access_point
            .inbound_policy
            .as_ref()
            .map(|p| {
                p.policy_definition_id
                    .as_str()
            }),
    ) {
        return true;
    }
    if matches(
        surface
            .target
            .response_policy
            .as_ref()
            .map(|p| {
                p.policy_definition_id
                    .as_str()
            }),
    ) {
        return true;
    }
    if matches(
        surface
            .transit
            .as_ref()
            .and_then(|t| {
                t.shared
                    .opa_policy_definition_id
                    .as_deref()
            }),
    ) {
        return true;
    }

    // Per-transit-point policies (request + response)
    if let Some(ref transit) = surface.transit {
        for tp in &transit.points {
            if matches(tp.policy.as_ref().map(|p| {
                p.policy_definition_id
                    .as_str()
            })) {
                return true;
            }
            if matches(
                tp.response_policy
                    .as_ref()
                    .map(|p| {
                        p.policy_definition_id
                            .as_str()
                    }),
            ) {
                return true;
            }
        }
    }

    // Variant-level overrides for all slots + transit points
    surface
        .variants
        .iter()
        .any(|v| {
            let ov = &v.overrides;
            matches(
                ov.target
                    .as_ref()
                    .and_then(|t| t.policy.as_ref())
                    .map(|p| {
                        p.policy_definition_id
                            .as_str()
                    }),
            ) || matches(
                ov.access_point
                    .as_ref()
                    .and_then(|ap| ap.inbound_policy.as_ref())
                    .map(|p| {
                        p.policy_definition_id
                            .as_str()
                    }),
            ) || matches(
                ov.target
                    .as_ref()
                    .and_then(|t| t.response_policy.as_ref())
                    .map(|p| {
                        p.policy_definition_id
                            .as_str()
                    }),
            ) || matches(
                ov.transit
                    .as_ref()
                    .and_then(|t| t.shared.as_ref())
                    .and_then(|s| {
                        s.opa_policy_definition_id
                            .as_deref()
                    }),
            ) || ov
                .transit
                .as_ref()
                .and_then(|t| t.points.as_ref())
                .is_some_and(|pts| {
                    pts.iter().any(|tp| {
                        matches(tp.policy.as_ref().map(|p| {
                            p.policy_definition_id
                                .as_str()
                        })) || matches(
                            tp.response_policy
                                .as_ref()
                                .map(|p| {
                                    p.policy_definition_id
                                        .as_str()
                                }),
                        )
                    })
                })
        })
}

fn get_policy_store(state: &IdentityApiState) -> Result<&FileSystemPolicyDefinitionStore, AppError> {
    state
        .policy_definition_store
        .as_ref()
        .map(|s| s.as_ref())
        .ok_or_else(|| AppError::InternalError("Policy definition store not configured".to_string()))
}

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

fn policy_allowed(
    tenant_id: Option<&str>,
    policy_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(tenant_id, tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::PolicyDefinitions,
            policy_id,
        )
}

/// May this caller change or delete the policy? Requires [`can_mutate`]
/// ownership and a resource scope that matches the policy id.
fn policy_writable(
    tenant_id: Option<&str>,
    policy_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_mutate(tenant_id, tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::PolicyDefinitions,
            policy_id,
        )
}

/// List all policy definitions, optionally filtered by type
pub async fn list_policy_definitions(
    State(state): State<IdentityApiState>,
    Query(query): Query<PolicyDefinitionsQuery>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<PolicyDefinition>>, AppError> {
    let store = get_policy_store(&state)?;

    let mut policies: Vec<PolicyDefinition> = store.list().await;
    if let Some(ref pt) = query.policy_type {
        policies.retain(|p| p.policy_type.to_string() == *pt && p.enabled);
    }
    policies.retain(|policy| policy_allowed(policy.tenant_id.as_deref(), &policy.id, &context, &scope));
    Ok(Json(policies))
}

/// Get a single policy definition by ID
pub async fn get_policy_definition(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<PolicyDefinition>, AppError> {
    let store = get_policy_store(&state)?;

    let policy: PolicyDefinition = store
        .get(&policy_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    if !policy_allowed(policy.tenant_id.as_deref(), &policy.id, &context, &scope) {
        return Err(AppError::NotFound(format!("Policy definition not found: {}", policy_id)));
    }

    Ok(Json(policy))
}

/// Create a new policy definition
/// Resolve the authenticated caller to a human-readable username for the policy
/// version author, falling back to the raw user id when it can't be resolved
/// (unknown user, or no passkey store on this route).
async fn resolve_author(
    caller: Option<Extension<AuthGuardOk>>,
    passkey_storage: Option<Extension<std::sync::Arc<PasskeyStorage>>>,
) -> Option<String> {
    let id = caller.map(|Extension(AuthGuardOk(id))| id)?;
    if let Some(Extension(ps)) = passkey_storage
        && let Ok(Some(user)) = ps.load_user_by_id(&id).await
    {
        return Some(user.username);
    }
    Some(id)
}

pub async fn create_policy_definition(
    State(state): State<IdentityApiState>,
    caller: Option<Extension<AuthGuardOk>>,
    passkey_storage: Option<Extension<std::sync::Arc<PasskeyStorage>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut policy): Json<PolicyDefinition>,
) -> Result<(StatusCode, Json<PolicyDefinition>), AppError> {
    let store = get_policy_store(&state)?;

    policy.tenant_id = tenant_for_create(policy.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| AppError::Forbidden(message.to_string()))?;
    if !policy_allowed(policy.tenant_id.as_deref(), &policy.id, &context, &scope) {
        return Err(AppError::Forbidden("Policy definition is outside this token's permitted scope".into()));
    }

    if store.exists(&policy.id).await {
        return Err(AppError::InvalidInput(format!("Policy definition already exists: {}", policy.id)));
    }

    validate_policy_scope(&policy)
        .map_err(|e| AppError::InvalidInput(format!("Invalid policy definition '{}': {}", policy.id, e)))?;

    // Enforce the appliance policy limit (per-type plus the total) before persisting.
    let policy_leaf = match policy.policy_type {
        PolicyType::Gateway => "policies.fabric",
        PolicyType::AgentSurface => "policies.agent-surface",
    };
    crate::config::enforce_add(policy_leaf)
        .await
        .map_err(|e| AppError::Forbidden(e.message()))?;

    info!("Creating policy definition: {} ({})", policy.name, policy.id);

    let author = resolve_author(caller, passkey_storage).await;
    let response = policy.clone();
    store
        .save_authored(policy, author, None)
        .await
        .map_err(|e| {
            error!("Failed to save policy definition: {}", e);
            AppError::InternalError(format!("Failed to save policy definition: {}", e))
        })?;

    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok((StatusCode::CREATED, Json(response)))
}

/// Update an existing policy definition
pub async fn update_policy_definition(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    caller: Option<Extension<AuthGuardOk>>,
    passkey_storage: Option<Extension<std::sync::Arc<PasskeyStorage>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut policy): Json<PolicyDefinition>,
) -> Result<Json<PolicyDefinition>, AppError> {
    let store = get_policy_store(&state)?;

    if policy.id != policy_id {
        return Err(AppError::InvalidInput("Policy definition ID mismatch".to_string()));
    }

    let existing = store
        .get(&policy_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    if !policy_writable(existing.tenant_id.as_deref(), &existing.id, &context, &scope) {
        return Err(AppError::Forbidden("Policy definition is not this token's to change".into()));
    }
    policy.tenant_id = existing.tenant_id.clone();
    // A policy's type fixes its Rego package / query path and which objects may
    // reference it, so it is immutable after creation.
    if existing.policy_type != policy.policy_type {
        return Err(AppError::InvalidInput("A policy's type cannot be changed after creation".to_string()));
    }

    validate_policy_scope(&policy)
        .map_err(|e| AppError::InvalidInput(format!("Invalid policy definition '{}': {}", policy.id, e)))?;

    // If the policy type is changing, enforce the destination type's per-type
    // limit. A re-type leaves the umbrella total unchanged, so only the leaf is
    // checked (the policy is not yet part of the destination type's count).
    if let Some(existing) = store.get(&policy_id).await
        && existing.policy_type != policy.policy_type
    {
        let policy_leaf = match policy.policy_type {
            PolicyType::Gateway => "policies.fabric",
            PolicyType::AgentSurface => "policies.agent-surface",
        };
        crate::config::enforce_leaf(policy_leaf)
            .await
            .map_err(|e| AppError::Forbidden(e.message()))?;
    }

    policy.updated_at = Some(chrono::Utc::now().to_rfc3339());

    info!("Updating policy definition: {} ({})", policy.name, policy.id);

    let author = resolve_author(caller, passkey_storage).await;
    let response = policy.clone();
    store
        .save_authored(policy, author, None)
        .await
        .map_err(|e| {
            error!("Failed to update policy definition: {}", e);
            AppError::InternalError(format!("Failed to update policy definition: {}", e))
        })?;

    // Recompile OPA engines for all surfaces that reference this policy definition
    // in any compiled slot (target, inbound, response, outbound, per-TP) or variant override.
    if let Some(ref agent_surface_store) = state.agent_surface_store {
        match agent_surface_store
            .list_all()
            .await
        {
            Ok(surfaces) => {
                let matched: Vec<_> = surfaces
                    .iter()
                    .filter(|s| surface_references_policy(s, &policy_id))
                    .collect();
                info!(
                    "Policy definition '{}' update: {} of {} surfaces reference it",
                    policy_id,
                    matched.len(),
                    surfaces.len()
                );
                for surface in matched {
                    let ch_name = surface.name.clone();
                    let _ = state
                        .policy_manager
                        .update_channel_policy(surface)
                        .await
                        .inspect_err(|e| warn!("Failed to recompile OPA policy for channel '{}': {}", ch_name, e))
                        .inspect(|_| {
                            info!("Recompiled OPA policy for channel '{}' after policy definition update", ch_name)
                        });
                }
            }
            Err(e) => {
                warn!("Failed to list channels for policy recompilation: {}", e);
            }
        }
    } else {
        warn!(
            "Policy definition '{}' updated but agent_surface_store is not available — no surfaces recompiled",
            policy_id
        );
    }

    // Recompile gateways that reference this policy definition (reference-only),
    // so editing a definition takes effect live on every gateway that uses it.
    if let Some(ref manager) = state.gateway_policy_manager {
        match crate::storage::filesystem::cached_storage::<crate::gateways::types::Gateway>(
            std::path::PathBuf::from(
                &state
                    .bootstrap_config
                    .storage_paths
                    .gateways,
            ),
            "gateway",
        )
        .await
        {
            Ok(backend) => {
                if let Ok(gateways) = backend.list_all().await {
                    for gw in gateways.iter().filter(|g| {
                        g.opa_policy_config
                            .as_ref()
                            .is_some_and(|c| {
                                c.policy_definition_id
                                    .as_deref()
                                    == Some(policy_id.as_str())
                            })
                    }) {
                        if let Err(e) = manager
                            .update_gateway_policy(gw)
                            .await
                        {
                            warn!("Failed to recompile gateway '{}' after policy definition update: {}", gw.id, e);
                        } else {
                            info!("Recompiled gateway '{}' after policy definition update", gw.id);
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to open gateway store for policy fan-out: {}", e),
        }
    }

    // Recompile the appliance-wide (global) set if it references this policy.
    if let (Some(gstore), Some(manager)) = (&state.global_policy_store, &state.global_policy_manager) {
        let assignments = gstore.get().await;
        if assignments.references_policy(&policy_id) {
            manager
                .refresh(&assignments)
                .await;
            info!("Recompiled appliance-wide policy set after policy definition update: {}", policy_id);
        }
    }

    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok(Json(response))
}

/// Delete a policy definition
pub async fn delete_policy_definition(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, AppError> {
    let store = get_policy_store(&state)?;

    let policy = store
        .get(&policy_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    if !policy_writable(policy.tenant_id.as_deref(), &policy.id, &context, &scope) {
        return Err(AppError::Forbidden("Policy definition is not this token's to delete".into()));
    }

    info!("Deleting policy definition: {}", policy_id);

    // Prune global assignments before deleting the definition: if the prune
    // fails the definition still exists, so a retry reaches this step again.
    if let Some(gstore) = &state.global_policy_store {
        let mut assignments = gstore.get().await;
        if assignments.remove_policy(&policy_id) {
            gstore
                .save(assignments.clone())
                .await
                .map_err(|e| {
                    error!("Failed to remove policy from global assignments: {}", e);
                    AppError::InternalError(format!("Failed to update global assignments: {}", e))
                })?;
            if let Some(manager) = &state.global_policy_manager {
                manager
                    .refresh(&assignments)
                    .await;
            }
            info!("Removed policy definition from appliance-wide assignments: {}", policy_id);
        }
    }

    store
        .delete(&policy_id)
        .await
        .map_err(|e| {
            error!("Failed to delete policy definition: {}", e);
            AppError::InternalError(format!("Failed to delete policy definition: {}", e))
        })?;

    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok(StatusCode::NO_CONTENT)
}

/// List a policy definition's immutable version history, newest first, so an
/// operator can review what changed and resolve any historical revision.
/// Read-only.
pub async fn list_policy_versions(
    State(state): State<IdentityApiState>,
    passkey_storage: Option<Extension<std::sync::Arc<PasskeyStorage>>>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<PolicyVersion>>, AppError> {
    let store = get_policy_store(&state)?;
    let doc = store
        .get_document(&policy_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    if !policy_allowed(doc.tenant_id.as_deref(), &doc.id, &context, &scope) {
        return Err(AppError::NotFound(format!("Policy definition not found: {}", policy_id)));
    }
    let mut versions = doc.versions;
    versions.sort_by_key(|v| std::cmp::Reverse(v.version));

    // Resolve each author id to its username for display; leave an unresolvable
    // value (deleted user, an already-resolved username, or a literal) as-is.
    if let Some(Extension(ps)) = passkey_storage {
        for v in &mut versions {
            if let Some(id) = v.created_by.clone()
                && let Ok(Some(user)) = ps.load_user_by_id(&id).await
            {
                v.created_by = Some(user.username);
            }
        }
    }

    Ok(Json(versions))
}

/// Request body for a policy dry-run.
#[derive(Debug, Deserialize)]
pub struct SimulatePolicyRequest {
    /// The `input` document to evaluate.
    pub input: serde_json::Value,
    /// Optional historical version to evaluate; defaults to the current version.
    /// Ignored when `policy` (a draft body) is supplied.
    #[serde(default)]
    pub version: Option<u32>,
    /// Optional draft Rego to evaluate instead of a stored version — lets an
    /// operator test edits before saving.
    #[serde(default)]
    pub policy: Option<String>,
    /// Optional policy type (`gateway` / `agent_surface`) for a draft body — used
    /// when the type was changed in the editor before saving. Ignored for a
    /// stored version.
    #[serde(default)]
    pub policy_type: Option<String>,
}

/// Result of a policy dry-run.
#[derive(Debug, Serialize)]
pub struct SimulatePolicyResponse {
    /// Whether the policy allowed the sample input.
    pub allow: bool,
    /// The policy's stated reason, when it provides one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The definition's policy type (`gateway` / `agent_surface`).
    pub policy_type: String,
    /// The evaluated stored version, or `null` for a draft body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// `sha256:<hex>` hash of the exact Rego evaluated (stored or draft).
    pub content_hash: String,
    /// The Rego query path the engine evaluated.
    pub query: String,
}

/// The resolved inputs for a dry-run evaluation.
struct ResolvedSimulation {
    rego: String,
    query: String,
    policy_type: String,
    version: Option<u32>,
    content_hash: String,
}

fn parse_policy_type(s: &str) -> Option<crate::policies::policy_definitions::PolicyType> {
    use crate::policies::policy_definitions::PolicyType;
    match s {
        "gateway" => Some(PolicyType::Gateway),
        "agent_surface" => Some(PolicyType::AgentSurface),
        _ => None,
    }
}

/// Resolve the exact Rego + query + attribution for a dry-run: a non-empty draft
/// body (optionally under a supplied, unsaved type), else the requested stored
/// version, else the current version. Pure — touches no engine or live traffic.
fn resolve_simulation(
    doc: &crate::policies::policy_definitions::PolicyDocument,
    version: Option<u32>,
    draft: Option<&str>,
    type_override: Option<&str>,
) -> Result<ResolvedSimulation, AppError> {
    use crate::policies::policy_definitions::content_hash;
    let has_draft = draft.is_some_and(|d| !d.trim().is_empty());
    // A draft may declare a different (unsaved) type than the stored document.
    let effective_type = match type_override {
        Some(t) if has_draft => {
            parse_policy_type(t).ok_or_else(|| AppError::InvalidInput(format!("Unknown policy type: {}", t)))?
        }
        _ => doc.policy_type.clone(),
    };
    let (rego, version, hash) = match draft {
        Some(draft) if has_draft => (draft.to_string(), None, content_hash(&effective_type, draft)),
        _ => {
            let v = match version {
                Some(v) => doc
                    .version(v)
                    .ok_or_else(|| AppError::InvalidInput(format!("Version {} not found for policy {}", v, doc.id)))?,
                None => doc
                    .current()
                    .ok_or_else(|| AppError::InternalError(format!("Policy {} has no current version", doc.id)))?,
            };
            (v.policy.clone(), Some(v.version), v.content_hash.clone())
        }
    };
    if rego.trim().is_empty() {
        return Err(AppError::InvalidInput("Policy body is empty; nothing to simulate".to_string()));
    }
    let query = format!("data.{}.allow", effective_type.expected_package());
    Ok(ResolvedSimulation {
        rego,
        query,
        policy_type: effective_type.to_string(),
        version,
        content_hash: hash,
    })
}

/// Compile a throwaway engine and evaluate — returns `(allow, reason)`. Runs on a
/// blocking worker under the dry-run handler's time bound. Fails closed with an
/// actionable reason when the module declares the wrong package / omits `allow`.
fn compile_and_eval(
    rego: &str,
    query: &str,
    input: serde_json::Value,
) -> Result<(bool, Option<String>), String> {
    let mut engine = regorus::Engine::new();
    engine
        .add_policy("simulate".to_string(), rego.to_string())
        .map_err(|e| format!("Policy failed to compile: {}", e))?;
    let input_json = serde_json::to_string(&input).map_err(|e| format!("Failed to serialize input: {}", e))?;
    engine
        .set_input_json(&input_json)
        .map_err(|e| format!("Failed to set policy input: {}", e))?;
    let allow = match engine.eval_bool_query(query.to_string(), false) {
        Ok(a) => a,
        Err(e)
            if e.to_string()
                .contains(crate::policies::REGORUS_QUERY_NO_VALUE_MARKER) =>
        {
            return Ok((
                false,
                Some(format!(
                    "Policy produced no `allow` decision for `{query}`; check the package declaration and that `allow` is defined (e.g. `default allow = false`)"
                )),
            ));
        }
        Err(e) => return Err(format!("Policy evaluation error: {}", e)),
    };
    let reason = if allow {
        None
    } else {
        let base = query
            .strip_suffix(".allow")
            .unwrap_or(query);
        engine
            .eval_rule(format!("{base}.deny_reason"))
            .ok()
            .and_then(|v| {
                v.as_string()
                    .ok()
                    .map(|s| s.to_string())
            })
    };
    Ok((allow, reason))
}

/// Synchronous dry-run core used by tests (mirrors the handler without the
/// worker offload / time bound).
#[cfg(test)]
fn run_policy_simulation(
    doc: &crate::policies::policy_definitions::PolicyDocument,
    version: Option<u32>,
    draft: Option<&str>,
    input: serde_json::Value,
) -> Result<SimulatePolicyResponse, AppError> {
    let r = resolve_simulation(doc, version, draft, None)?;
    let (allow, reason) = compile_and_eval(&r.rego, &r.query, input).map_err(AppError::InvalidInput)?;
    Ok(SimulatePolicyResponse {
        allow,
        reason,
        policy_type: r.policy_type,
        version: r.version,
        content_hash: r.content_hash,
        query: r.query,
    })
}

/// Maximum draft Rego / sample input sizes and the wall-clock bound on a single
/// dry-run evaluation — it compiles and runs caller-supplied Rego, so it is
/// bounded to keep a pathological policy from tying up a worker.
const MAX_SIMULATE_REGO: usize = 128 * 1024;
const MAX_SIMULATE_INPUT: usize = 256 * 1024;
const SIMULATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Dry-run a policy definition against a sample input. Compiles the requested
/// version (current by default), or an inline draft body under an optional
/// (unsaved) type, into a throwaway engine and evaluates it — no runtime engine,
/// binding, or live traffic is affected. The draft size, input size, and
/// evaluation time are bounded.
pub async fn simulate_policy_definition(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<SimulatePolicyRequest>,
) -> Result<Json<SimulatePolicyResponse>, AppError> {
    if req
        .policy
        .as_deref()
        .is_some_and(|p| p.len() > MAX_SIMULATE_REGO)
    {
        return Err(AppError::InvalidInput("Draft policy is too large to simulate".to_string()));
    }
    if serde_json::to_vec(&req.input)
        .map(|v| v.len())
        .unwrap_or(0)
        > MAX_SIMULATE_INPUT
    {
        return Err(AppError::InvalidInput("Sample input is too large to simulate".to_string()));
    }

    let store = get_policy_store(&state)?;
    let doc = store
        .get_document(&policy_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    if !policy_allowed(doc.tenant_id.as_deref(), &doc.id, &context, &scope) {
        return Err(AppError::NotFound(format!("Policy definition not found: {}", policy_id)));
    }
    let ResolvedSimulation {
        rego,
        query,
        policy_type,
        version,
        content_hash,
    } = resolve_simulation(&doc, req.version, req.policy.as_deref(), req.policy_type.as_deref())?;

    // Compile + evaluate off the async worker, under a wall-clock bound.
    let (rego_eval, query_eval, input) = (rego, query.clone(), req.input);
    let (allow, reason) = match tokio::time::timeout(
        SIMULATE_TIMEOUT,
        tokio::task::spawn_blocking(move || compile_and_eval(&rego_eval, &query_eval, input)),
    )
    .await
    {
        Err(_) => return Err(AppError::InvalidInput("Policy simulation exceeded the time limit".to_string())),
        Ok(Err(_join)) => return Err(AppError::InternalError("Policy simulation task failed".to_string())),
        Ok(Ok(Err(msg))) => return Err(AppError::InvalidInput(msg)),
        Ok(Ok(Ok(decision))) => decision,
    };

    Ok(Json(SimulatePolicyResponse {
        allow,
        reason,
        policy_type,
        version,
        content_hash,
        query,
    }))
}

/// The blast radius of a policy definition: how many runtime objects reference
/// it, so a UI can warn before a fleet-wide edit or delete.
#[derive(Debug, Serialize)]
pub struct PolicyImpactResponse {
    pub policy_id: String,
    /// Agent surfaces referencing this policy (any slot / variant).
    pub surfaces: usize,
    /// Gateways referencing this policy.
    pub gateways: usize,
    /// Sum across surfaces and gateways.
    pub total: usize,
    /// Whether this policy is enforced appliance-wide on at least one plane.
    pub globally_enforced: bool,
    /// The planes (`gateway`, `agent_surface`) enforcing it appliance-wide.
    pub planes: Vec<String>,
    /// Total agent surfaces on the appliance — the reach of an agent_surface
    /// global assignment (every surface is enforced, not only referencing ones).
    pub total_surfaces: usize,
    /// Total gateways on the appliance — the reach of a gateway global assignment.
    pub total_gateways: usize,
}

/// Report a policy definition's blast radius — the agent surfaces and gateways
/// that reference it — so an operator can gauge the impact of changing or
/// deleting it before acting. Read-only.
pub async fn policy_definition_impact(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<PolicyImpactResponse>, AppError> {
    let store = get_policy_store(&state)?;
    let policy = store
        .get(&policy_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    if !policy_allowed(policy.tenant_id.as_deref(), &policy.id, &context, &scope) {
        return Err(AppError::NotFound(format!("Policy definition not found: {}", policy_id)));
    }

    let surfaces_fut = async {
        match &state.agent_surface_store {
            Some(s) => match s.list_all().await {
                Ok(list) => {
                    let referencing = list
                        .iter()
                        .filter(|surface| surface_references_policy(surface, &policy_id))
                        .count();
                    (referencing, list.len())
                }
                Err(e) => {
                    warn!(policy_id = %policy_id, error = %e, "Failed to list surfaces for policy impact");
                    (0, 0)
                }
            },
            None => (0, 0),
        }
    };
    let gateways_fut = async {
        // Read gateways through the storage backend directly (not the store
        // wrapper, which would create a self-gateway on an empty directory).
        match crate::storage::filesystem::cached_storage::<crate::gateways::types::Gateway>(
            std::path::PathBuf::from(
                &state
                    .bootstrap_config
                    .storage_paths
                    .gateways,
            ),
            "gateway",
        )
        .await
        {
            Ok(backend) => match backend.list_all().await {
                Ok(list) => {
                    let referencing = list
                        .iter()
                        .filter(|g| {
                            g.opa_policy_config
                                .as_ref()
                                .is_some_and(|c| {
                                    c.policy_definition_id
                                        .as_deref()
                                        == Some(policy_id.as_str())
                                        || c.policy_definition_ids
                                            .iter()
                                            .any(|id| id == &policy_id)
                                })
                        })
                        .count();
                    (referencing, list.len())
                }
                Err(e) => {
                    warn!(policy_id = %policy_id, error = %e, "Failed to list gateways for policy impact");
                    (0, 0)
                }
            },
            Err(e) => {
                warn!(policy_id = %policy_id, error = %e, "Failed to open gateway store for policy impact");
                (0, 0)
            }
        }
    };
    let ((surfaces, total_surfaces), (gateways, total_gateways)) = tokio::join!(surfaces_fut, gateways_fut);
    let total = surfaces + gateways;
    let planes = match &state.global_policy_store {
        Some(gs) => gs
            .get()
            .await
            .planes_enforcing(&policy_id),
        None => Vec::new(),
    };
    let globally_enforced = !planes.is_empty();
    Ok(Json(PolicyImpactResponse {
        policy_id,
        surfaces,
        gateways,
        total,
        globally_enforced,
        planes,
        total_surfaces,
        total_gateways,
    }))
}

/// The appliance-wide (global) policy assignments — the policies enforced on
/// every object of a plane, independent of each object's own configuration.
/// Read-only.
pub async fn get_policy_assignments(
    State(state): State<IdentityApiState>
) -> Result<Json<crate::policies::GlobalPolicyAssignments>, AppError> {
    let store = state
        .global_policy_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Global policy store not initialized".to_string()))?;
    Ok(Json(store.get().await))
}

/// Validate one global-assignment candidate against its resolved definition:
/// the type must match the plane, and a non-monitor-only assignment must
/// reference an enabled, compiling definition — otherwise `GlobalPolicyManager`
/// would mark the whole plane broken (fail-closed) on the next recompile.
fn validate_global_assignment(
    plane: &str,
    expected_type: PolicyType,
    assignment: &crate::policies::global_policy::GlobalAssignment,
    def: &crate::policies::policy_definitions::PolicyDefinition,
) -> Result<(), AppError> {
    if def.policy_type != expected_type {
        return Err(AppError::InvalidInput(format!(
            "Policy {} is type {} but plane {} requires {}",
            assignment.policy_id, def.policy_type, plane, expected_type
        )));
    }
    if assignment.monitor_only {
        return Ok(());
    }
    if !def.enabled {
        return Err(AppError::InvalidInput(format!(
            "Policy {} is disabled; enable it or set monitor_only=true before enforcing it appliance-wide",
            assignment.policy_id
        )));
    }
    let mut engine = regorus::Engine::new();
    if engine
        .add_policy(format!("validate_{}_{}", plane, assignment.policy_id), def.policy.clone())
        .is_err()
    {
        return Err(AppError::InvalidInput(format!(
            "Policy {} fails to compile; fix it or set monitor_only=true before enforcing it appliance-wide",
            assignment.policy_id
        )));
    }
    Ok(())
}

/// Replace the appliance-wide (global) policy assignments. Each referenced
/// policy must exist and its type must match the plane it is assigned to.
/// Persists and recompiles the live global set (fail-closed on a broken
/// enforced member). Gated by `policies.edit`.
pub async fn update_policy_assignments(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    Json(body): Json<crate::policies::GlobalPolicyAssignments>,
) -> Result<Json<crate::policies::GlobalPolicyAssignments>, AppError> {
    // Only an appliance-wide caller may change the global assignment set.
    if context.is_some() {
        return Err(AppError::Forbidden(
            "Appliance-wide policy assignments cannot be changed by a tenant-scoped token".into(),
        ));
    }
    let def_store = get_policy_store(&state)?;
    for (plane, list) in &body.assignments {
        let expected = crate::policies::global_policy::plane_policy_type(plane)
            .ok_or_else(|| AppError::InvalidInput(format!("Unknown policy plane: {}", plane)))?;
        for a in list {
            let def = def_store
                .get(&a.policy_id)
                .await
                .ok_or_else(|| AppError::InvalidInput(format!("Unknown policy definition: {}", a.policy_id)))?;
            if def.tenant_id.is_some() {
                return Err(AppError::InvalidInput(format!(
                    "Tenant-owned policy {} cannot be assigned appliance-wide",
                    a.policy_id
                )));
            }
            validate_global_assignment(plane, expected.clone(), a, &def)?;
        }
    }
    let store = state
        .global_policy_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Global policy store not initialized".to_string()))?;
    store
        .save(body.clone())
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to save global assignments: {}", e)))?;
    if let Some(mgr) = &state.global_policy_manager {
        mgr.refresh(&body).await;
    }
    info!("Updated appliance-wide policy assignments ({} plane(s))", body.assignments.len());
    Ok(Json(body))
}

#[cfg(test)]
mod global_assignment_validation_tests {
    use super::*;
    use crate::policies::global_policy::{GlobalAssignment, PLANE_GATEWAY};

    fn def(
        policy_type: PolicyType,
        enabled: bool,
        rego: &str,
    ) -> PolicyDefinition {
        PolicyDefinition {
            id: "p1".to_string(),
            tenant_id: None,
            name: "p1".to_string(),
            description: String::new(),
            policy_type,
            policy: rego.to_string(),
            enabled,
            created_at: "t".to_string(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
        }
    }

    fn assignment(monitor_only: bool) -> GlobalAssignment {
        GlobalAssignment {
            policy_id: "p1".to_string(),
            monitor_only,
        }
    }

    #[test]
    fn rejects_wrong_type_regardless_of_monitor_only() {
        let d = def(PolicyType::AgentSurface, true, "package surface.policy\ndefault allow = true");
        assert!(validate_global_assignment(PLANE_GATEWAY, PolicyType::Gateway, &assignment(true), &d).is_err());
        assert!(validate_global_assignment(PLANE_GATEWAY, PolicyType::Gateway, &assignment(false), &d).is_err());
    }

    #[test]
    fn rejects_disabled_enforced_but_allows_disabled_monitor_only() {
        let d = def(PolicyType::Gateway, false, "package gateway.policy\ndefault allow = true");
        assert!(validate_global_assignment(PLANE_GATEWAY, PolicyType::Gateway, &assignment(false), &d).is_err());
        assert!(validate_global_assignment(PLANE_GATEWAY, PolicyType::Gateway, &assignment(true), &d).is_ok());
    }

    #[test]
    fn rejects_uncompilable_enforced_but_allows_uncompilable_monitor_only() {
        let d = def(PolicyType::Gateway, true, "this is not valid rego {{{");
        assert!(validate_global_assignment(PLANE_GATEWAY, PolicyType::Gateway, &assignment(false), &d).is_err());
        assert!(validate_global_assignment(PLANE_GATEWAY, PolicyType::Gateway, &assignment(true), &d).is_ok());
    }

    #[test]
    fn allows_enabled_compiling_enforced() {
        let d = def(PolicyType::Gateway, true, "package gateway.policy\ndefault allow = true");
        assert!(validate_global_assignment(PLANE_GATEWAY, PolicyType::Gateway, &assignment(false), &d).is_ok());
    }
}

#[cfg(test)]
mod simulate_tests {
    use super::*;
    use crate::policies::policy_definitions::{PolicyDocument, PolicyType, PolicyVersion, content_hash};

    fn doc(
        policy_type: PolicyType,
        rego: &str,
    ) -> PolicyDocument {
        PolicyDocument {
            id: "p1".into(),
            tenant_id: None,
            name: "p1".into(),
            description: String::new(),
            policy_type: policy_type.clone(),
            enabled: true,
            current_version: 1,
            created_at: "t".into(),
            updated_at: None,
            versions: vec![PolicyVersion {
                version: 1,
                policy: rego.into(),
                content_hash: content_hash(&policy_type, rego),
                created_at: "t".into(),
                created_by: None,
                note: None,
                name: None,
                description: None,
            }],
            sample_input: None,
        }
    }

    fn sample_input() -> serde_json::Value {
        serde_json::json!({ "jwt": { "sub": "alice" } })
    }

    const ALLOW: &str = "package gateway.policy\n\ndefault allow = true";
    const DENY: &str = "package gateway.policy\n\ndefault allow = false";

    #[test]
    fn simulate_current_version_allows_with_query_and_hash() {
        let d = doc(PolicyType::Gateway, ALLOW);
        let r = run_policy_simulation(&d, None, None, sample_input()).unwrap();
        assert!(r.allow);
        assert_eq!(r.query, "data.gateway.policy.allow");
        assert_eq!(r.policy_type, "gateway");
        assert_eq!(r.version, Some(1));
        assert_eq!(r.content_hash, content_hash(&PolicyType::Gateway, ALLOW));
    }

    #[test]
    fn simulate_denies() {
        let d = doc(PolicyType::Gateway, DENY);
        let r = run_policy_simulation(&d, None, None, sample_input()).unwrap();
        assert!(!r.allow);
    }

    #[test]
    fn simulate_draft_overrides_stored_version() {
        let d = doc(PolicyType::Gateway, ALLOW);
        let r = run_policy_simulation(&d, None, Some(DENY), sample_input()).unwrap();
        assert!(!r.allow, "the draft (deny) must override the stored allow");
        assert_eq!(r.version, None, "a draft has no stored version");
        assert!(
            r.content_hash
                .starts_with("sha256:")
        );
    }

    #[test]
    fn simulate_unknown_version_is_invalid_input() {
        let d = doc(PolicyType::Gateway, ALLOW);
        let err = run_policy_simulation(&d, Some(99), None, sample_input()).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn simulate_agent_surface_uses_surface_query() {
        let d = doc(PolicyType::AgentSurface, "package surface.policy\n\ndefault allow = true");
        let r = run_policy_simulation(&d, None, None, sample_input()).unwrap();
        assert_eq!(r.query, "data.surface.policy.allow");
        assert!(r.allow);
    }

    #[test]
    fn simulate_wrong_package_fails_closed() {
        // Declares the surface package but is being evaluated as a gateway policy.
        let d = doc(PolicyType::Gateway, "package surface.policy\n\ndefault allow = true");
        let r = run_policy_simulation(&d, None, None, sample_input()).unwrap();
        assert!(!r.allow, "a wrong-package policy must fail closed");
        assert!(r.reason.is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::AgentSurface;

    const POL: &str = "pol-1";
    const AP: &str = "0.0.0.0:8443";

    fn base_surface() -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "s-1",
            "name": "test",
            "access_point": { "listen_address": AP, "route": "/test", "protocol": "a2a" },
            "target": { "endpoint": "https://upstream" },
        }))
        .unwrap()
    }

    #[test]
    fn no_policy_refs_returns_false() {
        let s = base_surface();
        assert!(!surface_references_policy(&s, POL));
    }

    #[test]
    fn target_policy_matches() {
        let s: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "s-1", "name": "test",
            "access_point": { "listen_address": AP, "route": "/test", "protocol": "a2a" },
            "target": {
                "endpoint": "https://upstream",
                "policy": { "policy_definition_id": POL },
            },
        }))
        .unwrap();
        assert!(surface_references_policy(&s, POL));
        assert!(!surface_references_policy(&s, "other"));
    }

    #[test]
    fn inbound_policy_matches() {
        let s: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "s-1", "name": "test",
            "access_point": {
                "listen_address": AP, "route": "/test", "protocol": "a2a",
                "inbound_policy": { "policy_definition_id": POL },
            },
            "target": { "endpoint": "https://upstream" },
        }))
        .unwrap();
        assert!(surface_references_policy(&s, POL));
    }

    #[test]
    fn response_policy_matches() {
        let s: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "s-1", "name": "test",
            "access_point": { "listen_address": AP, "route": "/test", "protocol": "a2a" },
            "target": {
                "endpoint": "https://upstream",
                "response_policy": { "policy_definition_id": POL },
            },
        }))
        .unwrap();
        assert!(surface_references_policy(&s, POL));
    }

    #[test]
    fn outbound_transit_policy_matches() {
        let s: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "s-1", "name": "test",
            "access_point": { "listen_address": AP, "route": "/test", "protocol": "a2a" },
            "target": { "endpoint": "https://upstream" },
            "transit": {
                "points": [],
                "opa_policy_definition_id": POL,
            },
        }))
        .unwrap();
        assert!(surface_references_policy(&s, POL));
    }

    #[test]
    fn variant_target_policy_matches() {
        let mut s = base_surface();
        s.variants.push(
            serde_json::from_value(serde_json::json!({
                "id": "v-1", "alias": "beta", "name": "Beta",
                "overrides": {
                    "target": { "policy": { "policy_definition_id": POL } }
                }
            }))
            .unwrap(),
        );
        assert!(surface_references_policy(&s, POL));
    }

    #[test]
    fn variant_inbound_policy_matches() {
        let mut s = base_surface();
        s.variants.push(
            serde_json::from_value(serde_json::json!({
                "id": "v-1", "alias": "beta", "name": "Beta",
                "overrides": {
                    "access_point": { "inbound_policy": { "policy_definition_id": POL } }
                }
            }))
            .unwrap(),
        );
        assert!(surface_references_policy(&s, POL));
    }

    #[test]
    fn variant_response_policy_matches() {
        let mut s = base_surface();
        s.variants.push(
            serde_json::from_value(serde_json::json!({
                "id": "v-1", "alias": "beta", "name": "Beta",
                "overrides": {
                    "target": { "response_policy": { "policy_definition_id": POL } }
                }
            }))
            .unwrap(),
        );
        assert!(surface_references_policy(&s, POL));
    }

    #[test]
    fn variant_outbound_policy_matches() {
        let mut s = base_surface();
        s.variants.push(
            serde_json::from_value(serde_json::json!({
                "id": "v-1", "alias": "beta", "name": "Beta",
                "overrides": {
                    "transit": {
                        "shared": { "opa_policy_definition_id": POL }
                    }
                }
            }))
            .unwrap(),
        );
        assert!(surface_references_policy(&s, POL));
    }

    #[test]
    fn transit_point_request_policy_matches() {
        let s: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "s-1", "name": "test",
            "access_point": { "listen_address": AP, "route": "/test", "protocol": "a2a" },
            "target": { "endpoint": "https://upstream" },
            "transit": {
                "points": [{
                    "alias": "tp-1",
                    "target_endpoint": "https://dest",
                    "policy": { "policy_definition_id": POL },
                }],
            },
        }))
        .unwrap();
        assert!(surface_references_policy(&s, POL));
        assert!(!surface_references_policy(&s, "other"));
    }

    #[test]
    fn transit_point_response_policy_matches() {
        let s: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "s-1", "name": "test",
            "access_point": { "listen_address": AP, "route": "/test", "protocol": "a2a" },
            "target": { "endpoint": "https://upstream" },
            "transit": {
                "points": [{
                    "alias": "tp-1",
                    "target_endpoint": "https://dest",
                    "response_policy": { "policy_definition_id": POL },
                }],
            },
        }))
        .unwrap();
        assert!(surface_references_policy(&s, POL));
    }

    #[test]
    fn different_policy_id_not_matched() {
        let s: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "s-1", "name": "test",
            "access_point": {
                "listen_address": AP, "route": "/test", "protocol": "a2a",
                "inbound_policy": { "policy_definition_id": "other-pol" },
            },
            "target": {
                "endpoint": "https://upstream",
                "policy": { "policy_definition_id": "other-pol" },
                "response_policy": { "policy_definition_id": "other-pol" },
            },
        }))
        .unwrap();
        assert!(!surface_references_policy(&s, POL));
    }

    fn tenant(id: &str) -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: id.into(),
        }))
    }

    fn scope(pattern: &str) -> Option<Extension<PatResourceScope>> {
        Some(Extension(PatResourceScope(std::sync::Arc::new(regex::Regex::new(pattern).unwrap()))))
    }

    #[test]
    fn policy_writable_rejects_untenanted_policy_for_tenant_context() {
        assert!(!policy_writable(None, POL, &tenant("tenant-a"), &None));
    }

    #[test]
    fn policy_writable_rejects_own_policy_outside_scope() {
        let scope = scope(r"\ATENANT:tenant-a:policy-definitions:other\z");
        assert!(!policy_writable(Some("tenant-a"), POL, &tenant("tenant-a"), &scope));
    }

    #[test]
    fn policy_writable_allows_own_policy_inside_scope() {
        let scope = scope(r"\ATENANT:tenant-a:policy-definitions:pol-1\z");
        assert!(policy_writable(Some("tenant-a"), POL, &tenant("tenant-a"), &scope));
    }

    #[test]
    fn policy_writable_allows_caller_without_tenant_context() {
        assert!(policy_writable(None, POL, &None, &None));
        assert!(policy_writable(Some("tenant-a"), POL, &None, &None));
    }
}
