use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::mediators::utils::fetch_mediator_did_from_url;
use crate::mediators::utils::set_acl_to_allow_everything_and_more;
use crate::messages::MessageType;

use super::GatewayStore;
use super::connection_points::ConnectionPointStore;
use super::connection_points::ws_listener::{ConnectionPointListenerManager, ListenerInfo};
use super::surface_cache::GatewaySurfaceCache;
use super::types::{ExposureMode, Gateway, GatewayStatus, GatewayType};
use crate::auth::storage::PasskeyStorage;
use crate::auth::types::UserRole;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::rbac::{Feature, RbacConfig};
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, can_reference, scope_allows_resource, tenant_for_create,
};

/// Request body for creating a gateway
#[derive(Debug, Deserialize)]
pub struct CreateGatewayRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub did: String,
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

pub(crate) fn gateway_allowed(
    gateway: &Gateway,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(gateway.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Gateways, &gateway.id)
}

/// May this caller change or delete the gateway record? A tenant token may read
/// an appliance-wide gateway but change only its own tenant's, so it cannot, for
/// example, widen an appliance peer's exposure.
pub(crate) fn gateway_writable(
    gateway: &Gateway,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_mutate(gateway.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Gateways, &gateway.id)
}

/// Request body for updating a gateway. The attested `issuer_did` is
/// established by the gateway and cannot be set here; operator-trusted issuers
/// have their own endpoints.
#[derive(Debug, Deserialize)]
pub struct UpdateGatewayRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<GatewayStatus>,
}

/// Request body for trusting an issuer DID on a remote gateway connection.
#[derive(Debug, Deserialize)]
pub struct TrustedIssuerRequest {
    pub issuer_did: String,
}

/// Request body for updating a remote gateway's exposure. Without
/// `exposure_mode`, a non-empty list selects `list` and an empty one `none`.
#[derive(Debug, Deserialize)]
pub struct UpdateExposedChannelsRequest {
    #[serde(default)]
    pub exposure_mode: Option<ExposureMode>,
    #[serde(default)]
    pub exposed_channels: Vec<String>,
}

impl UpdateExposedChannelsRequest {
    fn mode(&self) -> ExposureMode {
        self.exposure_mode.unwrap_or(
            if self
                .exposed_channels
                .is_empty()
            {
                ExposureMode::None
            } else {
                ExposureMode::List
            },
        )
    }
}

fn authorize_gateway_delete(
    caller_role: &UserRole,
    gateway: &Gateway,
    rbac_config: &RbacConfig,
) -> Result<(), (StatusCode, String)> {
    if gateway.gateway_type == GatewayType::SelfGateway {
        return Err((StatusCode::FORBIDDEN, "Cannot delete self gateway".to_string()));
    }

    if !rbac_config.has_permission(caller_role, &Feature::GatewaysDelete) {
        return Err((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()));
    }

    Ok(())
}

/// Derive the effective status of a remote gateway from its connection points'
/// persisted runtime health (proposal section F — status precedence).
///
/// Precedence: explicit workflow / manual states (AwaitingApproval, Disabled,
/// Pending) are preserved as-is; otherwise a live listener or a `Connected`
/// connection point means Active, any connection point with recorded-but-
/// unhealthy runtime means Failed, and no runtime information yet means Pending.
fn effective_remote_gateway_status(
    current: GatewayStatus,
    has_active_listener: bool,
    connection_points: &[crate::gateways::connection_points::types::GatewayConnectionPoint],
) -> GatewayStatus {
    // Preserve explicit workflow / manual states.
    if matches!(current, GatewayStatus::AwaitingApproval | GatewayStatus::Disabled | GatewayStatus::Pending) {
        return current;
    }

    if has_active_listener {
        return GatewayStatus::Active;
    }

    // No live listener (broken, or this Standby node holds none): fall
    // back to the persisted connection-point runtime health.
    let mut any_connected = false;
    let mut any_runtime = false;
    for cp in connection_points {
        if let Some(runtime) = &cp.runtime_status {
            any_runtime = true;
            if matches!(runtime.status, crate::gateways::ConnectionStatus::Connected) {
                any_connected = true;
                break;
            }
        }
    }

    if any_connected {
        GatewayStatus::Active
    } else if any_runtime {
        GatewayStatus::Failed
    } else {
        GatewayStatus::Pending
    }
}

/// Pick a representative runtime status for a gateway from its connection
/// points, so the list view can show *why* a gateway is failed even though the
/// underlying OOB/system connection points are hidden from the CP list. Prefers
/// a `Connected` connection point; otherwise the first unhealthy one.
fn representative_runtime_status(
    connection_points: &[crate::gateways::connection_points::types::GatewayConnectionPoint]
) -> Option<crate::comm::connection_health::ConnectionRuntimeStatus> {
    let mut fallback = None;
    for cp in connection_points {
        if let Some(runtime) = &cp.runtime_status {
            if matches!(runtime.status, crate::gateways::ConnectionStatus::Connected) {
                return Some(runtime.clone());
            }
            if fallback.is_none() {
                fallback = Some(runtime.clone());
            }
        }
    }
    fallback
}

/// A gateway plus its derived connection health for the list view.
///
/// `runtime_status` is derived from the gateway's connection points (including
/// the hidden OOB/system ones) and is not persisted on the gateway record.
#[derive(Debug, Serialize)]
pub struct GatewayListItem {
    #[serde(flatten)]
    pub gateway: Gateway,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_status: Option<crate::comm::connection_health::ConnectionRuntimeStatus>,
}

/// List all gateways
pub async fn list_gateways<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>,
    Extension(cp_store): Extension<Option<Arc<crate::gateways::FileSystemConnectionPointStore>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<GatewayListItem>>, (StatusCode, String)> {
    let mut gateways = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list gateways: {}", e)))?;
    gateways.retain(|gateway| gateway_allowed(gateway, &context, &scope));

    // Group connection points by gateway once (avoids a per-gateway scan).
    let cps_by_gateway: std::collections::HashMap<String, Vec<_>> = match cp_store.as_ref() {
        Some(store) => {
            let mut map: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for cp in store
                .list_all()
                .await
                .unwrap_or_default()
            {
                map.entry(cp.gateway_id.clone())
                    .or_default()
                    .push(cp);
            }
            map
        }
        None => std::collections::HashMap::new(),
    };

    // Only derive status when the listener infrastructure is present (preserves
    // prior behavior when it is not). Runtime status is attached whenever
    // connection-point health is available.
    let active_listeners = match listener_manager.as_ref() {
        Some(manager) => Some(
            manager
                .get_active_listeners()
                .await,
        ),
        None => None,
    };

    let items = gateways
        .into_iter()
        .map(|mut gateway| {
            if gateway.gateway_type == GatewayType::SelfGateway {
                return GatewayListItem { gateway, runtime_status: None };
            }

            let cps = cps_by_gateway
                .get(&gateway.id)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let runtime_status = representative_runtime_status(cps);

            if let Some(listeners) = active_listeners.as_ref() {
                let has_listener = listeners
                    .iter()
                    .any(|listener| listener.gateway_id == gateway.id);
                gateway.status = effective_remote_gateway_status(gateway.status.clone(), has_listener, cps);
            }

            GatewayListItem { gateway, runtime_status }
        })
        .collect();

    Ok(Json(items))
}

/// Get a gateway by ID
pub async fn get_gateway<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notif_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(listener_manager): Extension<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>,
    Extension(cp_store): Extension<Option<Arc<crate::gateways::FileSystemConnectionPointStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<GatewayListItem>, (StatusCode, String)> {
    let mut gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
    }

    // Trigger gateway.accessed integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        let notif = notif.clone();
        let gateway_clone = gateway.clone();
        crate::observability::spawn_traced_task("integration.gateway_accessed", async move {
            crate::integrations::trigger_gateway_accessed(notif.as_ref(), &gateway_clone).await;
        });
    }

    // Derive runtime health from the gateway's connection points (including the
    // hidden OOB/system ones), mirroring the list endpoint.
    let mut runtime_status = None;
    if gateway.gateway_type != GatewayType::SelfGateway {
        let cps = match cp_store.as_ref() {
            Some(store) => store
                .list_by_gateway(&id)
                .await
                .unwrap_or_default(),
            None => Vec::new(),
        };
        runtime_status = representative_runtime_status(&cps);
        if let Some(manager) = listener_manager.as_ref() {
            let has_listener = manager
                .get_active_listeners()
                .await
                .iter()
                .any(|listener| listener.gateway_id == gateway.id);
            gateway.status = effective_remote_gateway_status(gateway.status.clone(), has_listener, &cps);
        }
    }

    Ok(Json(GatewayListItem { gateway, runtime_status }))
}

/// Create a new gateway
pub async fn create_gateway<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notif_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateGatewayRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    crate::config::enforce_add("connections.gateways")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;
    let mut gateway = Gateway::new(req.name, req.description, req.did, GatewayType::Remote);
    gateway.tenant_id = req.tenant_id;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    store
        .create(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store gateway: {}", e)))?;

    // Trigger gateway.created integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        let notif = notif.clone();
        let gateway_clone = gateway.clone();
        crate::observability::spawn_traced_task("integration.gateway_created", async move {
            crate::integrations::trigger_gateway_created(notif.as_ref(), &gateway_clone).await;
        });
    }

    Ok(Json(gateway))
}

/// Update a gateway
pub async fn update_gateway<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notif_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateGatewayRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    let mut gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_writable(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    // Clone old gateway state for integration trigger
    let old_gateway = gateway.clone();

    if let Some(name) = req.name {
        gateway.name = name;
    }
    if let Some(description) = req.description {
        gateway.description = description;
    }
    // DID cannot be changed after creation - ignore req.did
    if let Some(status) = req.status {
        gateway.status = status;
    }

    gateway.updated_at = chrono::Utc::now();

    store
        .update(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;

    // Trigger gateway.updated integration
    if let Some(notif) = notif_store.as_ref() {
        crate::integrations::trigger_gateway_updated(notif.as_ref(), &old_gateway, &gateway).await;
    }

    Ok(Json(gateway))
}

/// Update exposed channels for a gateway
pub async fn update_gateway_exposed_surfaces<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(surface_store): Extension<Option<Arc<crate::surfaces::FileSystemAgentSurfaceStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateExposedChannelsRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    let mut gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_writable(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }
    if gateway.gateway_type != GatewayType::Remote {
        return Err((StatusCode::BAD_REQUEST, "Exposure applies only to remote gateways".to_string()));
    }
    let mode = req.mode();
    let exposed_channels = if mode == ExposureMode::List {
        req.exposed_channels
    } else {
        Vec::new()
    };

    if !exposed_channels.is_empty() {
        let surface_store = surface_store
            .as_ref()
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Surface store not configured".to_string()))?;
        for surface_id in &exposed_channels {
            let surface = surface_store
                .get(surface_id)
                .await
                .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "Surface reference is not accessible".to_string()))?;
            if !can_reference(gateway.tenant_id.as_deref(), surface.tenant_id.as_deref())
                || !scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::Surfaces,
                    &surface.surface_id,
                )
            {
                return Err((StatusCode::BAD_REQUEST, "Surface reference is not accessible".to_string()));
            }
        }
    }

    gateway.exposure_mode = Some(mode);
    gateway.exposed_channels = exposed_channels;
    gateway.updated_at = chrono::Utc::now();

    store
        .update(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;

    Ok(Json(gateway))
}

/// Request body for updating a gateway's OPA policy
#[derive(Debug, Deserialize)]
pub struct UpdateGatewayPolicyRequest {
    pub opa_policy_config: Option<crate::gateways::types::GatewayOpaPolicyConfig>,
}

/// Response for gateway policy operations
#[derive(Debug, Serialize)]
pub struct GatewayPolicyResponse {
    pub opa_policy_config: Option<crate::gateways::types::GatewayOpaPolicyConfig>,
}

/// Get the OPA policy for a gateway
pub async fn get_gateway_policy<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<GatewayPolicyResponse>, (StatusCode, String)> {
    let gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
    }

    Ok(Json(GatewayPolicyResponse {
        opa_policy_config: gateway.opa_policy_config,
    }))
}

/// Update the OPA policy for a gateway
pub async fn update_gateway_policy<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(gateway_policy_manager): Extension<Option<Arc<crate::policies::GatewayPolicyManager>>>,
    Extension(policy_definition_store): Extension<Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateGatewayPolicyRequest>,
) -> Result<Json<GatewayPolicyResponse>, (StatusCode, String)> {
    let mut gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_writable(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    // If a policy_definition_id is provided, resolve the latest policy text from the
    // definition store — the backend is the single source of truth, not the frontend.
    let mut resolved_config = req.opa_policy_config;
    if let Some(ref mut policy_config) = resolved_config
        && policy_config.enabled
        && let Some(ref def_id) = policy_config.policy_definition_id
        && !def_id.is_empty()
    {
        // Reference-only: the definition is the single source of truth. Verify it
        // exists and clear any inline copy so editing the definition later takes
        // effect on this gateway (via the recompile fan-out) without re-saving here.
        match &policy_definition_store {
            Some(def_store) => {
                let definition = def_store
                    .get(def_id)
                    .await
                    .ok_or_else(|| (StatusCode::BAD_REQUEST, "Policy definition is not accessible".to_string()))?;
                if !can_reference(
                    gateway.tenant_id.as_deref(),
                    definition
                        .tenant_id
                        .as_deref(),
                ) || !scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::PolicyDefinitions,
                    &definition.id,
                ) {
                    return Err((StatusCode::BAD_REQUEST, "Policy definition is not accessible".to_string()));
                }
                policy_config.policy = String::new();
            }
            None => {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Policy definition store not configured".to_string()));
            }
        }
    }

    // Validate any additional deny-overrides members (reference-only): each must
    // resolve to an existing definition. Clear the inline copy when the set is
    // defined by reference so a later definition edit fans out to this gateway.
    if let Some(ref mut policy_config) = resolved_config
        && policy_config.enabled
        && !policy_config
            .policy_definition_ids
            .is_empty()
    {
        match &policy_definition_store {
            Some(def_store) => {
                for def_id in &policy_config.policy_definition_ids {
                    if def_id.is_empty() {
                        continue;
                    }
                    let definition = def_store
                        .get(def_id)
                        .await
                        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Policy definition is not accessible".to_string()))?;
                    if !can_reference(
                        gateway.tenant_id.as_deref(),
                        definition
                            .tenant_id
                            .as_deref(),
                    ) || !scope_allows_resource(
                        resource_scope(&scope),
                        tenant_context(&context),
                        ResourceKind::PolicyDefinitions,
                        &definition.id,
                    ) {
                        return Err((StatusCode::BAD_REQUEST, "Policy definition is not accessible".to_string()));
                    }
                }
                policy_config.policy = String::new();
            }
            None => {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Policy definition store not configured".to_string()));
            }
        }
    }

    // Validate the policy syntax if provided and non-empty
    if let Some(ref policy_config) = resolved_config
        && policy_config.enabled
        && !policy_config
            .policy
            .trim()
            .is_empty()
    {
        // Reject a Rego package that doesn't match the gateway scope. Otherwise
        // the fixed `data.gateway.policy.allow` query never resolves and every
        // request fails closed at runtime. Surface policies get this check when
        // their definition is saved; gateway inline policies are validated here.
        if let Err(e) = crate::policies::policy_definitions::validate_scope_text(
            &policy_config.policy,
            &crate::policies::policy_definitions::PolicyType::Gateway,
        ) {
            return Err((StatusCode::BAD_REQUEST, e));
        }

        let test_engine = crate::policies::OpaEngine::new();
        if let Err(e) = test_engine.load_policy("validation_test", &policy_config.policy) {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid Rego policy: {}", e)));
        }
    }

    gateway.opa_policy_config = resolved_config;
    gateway.updated_at = chrono::Utc::now();

    store
        .update(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;

    // Update the gateway policy manager with new policy
    if let Some(ref manager) = gateway_policy_manager
        && let Err(e) = manager
            .update_gateway_policy(&gateway)
            .await
    {
        warn!("Failed to update gateway policy engine: {}", e);
    }

    info!(gateway_id = %id, "Gateway OPA policy updated");

    Ok(Json(GatewayPolicyResponse {
        opa_policy_config: gateway.opa_policy_config,
    }))
}

/// Delete a gateway
pub async fn delete_gateway<S: GatewayStore, P: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(connection_point_store): Extension<std::sync::Arc<P>>,
    Extension(listener_manager): Extension<std::sync::Arc<ConnectionPointListenerManager>>,
    Extension(notif_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(caller_user_id): Extension<String>,
    Extension(user_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_writable(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    let caller = user_storage
        .load_user_by_id(&caller_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load caller: {}", e)))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Caller not found".to_string()))?;

    authorize_gateway_delete(&caller.role, &gateway, &rbac_config)?;

    // Clone gateway for trigger before deletion
    let gateway_for_trigger = gateway.clone();

    // Stop all WebSocket listeners for connection points associated with this gateway
    // and delete system-created connection points (user-created ones are kept)
    match connection_point_store
        .list_by_gateway(&id)
        .await
    {
        Ok(connection_points) => {
            for cp in connection_points {
                // Stop the listener
                if let Err(e) = listener_manager
                    .stop_listener(&cp.id)
                    .await
                {
                    warn!("Failed to stop listener for connection point {}: {}", cp.id, e);
                } else {
                    info!("Stopped listener for connection point {} (gateway {})", cp.id, id);
                }

                // Delete system-created connection points (they're tied to this gateway)
                // Keep user-created connection points (they may be reused)
                if cp.cp_type != crate::gateways::connection_points::ConnectionPointType::User {
                    if let Err(e) = connection_point_store
                        .delete(&cp.id)
                        .await
                    {
                        warn!("Failed to delete system connection point {}: {}", cp.id, e);
                    } else {
                        info!("Deleted system connection point {} for gateway {}", cp.id, id);
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to list connection points for gateway {}: {}", id, e);
        }
    }

    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete gateway: {}", e)))?;

    info!("Deleted gateway {} and stopped all associated listeners", id);

    // Trigger gateway.deleted integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        let notif = notif.clone();
        let gateway_clone = gateway_for_trigger.clone();
        crate::observability::spawn_traced_task("integration.gateway_deleted", async move {
            crate::integrations::trigger_gateway_deleted(notif.as_ref(), &gateway_clone).await;
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::gateways::types::GatewayCreationType;
    use tempfile::TempDir;

    #[test]
    fn effective_remote_gateway_status_derivation() {
        use crate::comm::connection_health::ConnectionRuntimeStatus;
        use crate::gateways::ConnectionStatus;
        use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};

        fn cp(runtime: Option<ConnectionStatus>) -> GatewayConnectionPoint {
            let mut c = GatewayConnectionPoint::new(
                "gw".to_string(),
                "med".to_string(),
                "did".to_string(),
                "name".to_string(),
                "desc".to_string(),
                "oob".to_string(),
                "url".to_string(),
                serde_json::json!({}),
                None,
                ConnectionPointType::User,
                String::new(),
            );
            c.runtime_status = runtime.map(|status| ConnectionRuntimeStatus {
                status,
                ..ConnectionRuntimeStatus::default()
            });
            c
        }

        // Explicit workflow / manual states are preserved regardless of runtime.
        assert_eq!(
            effective_remote_gateway_status(GatewayStatus::AwaitingApproval, false, &[]),
            GatewayStatus::AwaitingApproval
        );
        assert_eq!(effective_remote_gateway_status(GatewayStatus::Pending, false, &[]), GatewayStatus::Pending);
        assert_eq!(effective_remote_gateway_status(GatewayStatus::Disabled, true, &[]), GatewayStatus::Disabled);

        // A live listener means Active.
        assert_eq!(effective_remote_gateway_status(GatewayStatus::Active, true, &[]), GatewayStatus::Active);

        // No listener: derive from connection-point runtime health.
        assert_eq!(
            effective_remote_gateway_status(GatewayStatus::Active, false, &[cp(Some(ConnectionStatus::Connected))]),
            GatewayStatus::Active
        );
        assert_eq!(
            effective_remote_gateway_status(GatewayStatus::Active, false, &[cp(Some(ConnectionStatus::Failed))]),
            GatewayStatus::Failed
        );
        assert_eq!(
            effective_remote_gateway_status(GatewayStatus::Active, false, &[cp(Some(ConnectionStatus::Reconnecting))]),
            GatewayStatus::Failed
        );
        // No runtime recorded yet -> Pending (still connecting / never attempted).
        assert_eq!(effective_remote_gateway_status(GatewayStatus::Active, false, &[cp(None)]), GatewayStatus::Pending);
    }

    #[test]
    fn surface_info_defaults_are_backward_compatible() {
        // A discovery response from a peer that predates connection-point tags
        // and the payment marker omits both fields.
        let legacy = serde_json::json!({
            "config_id": "cfg-1",
            "name": "Legacy",
            "description": "",
            "listen_address": "0.0.0.0:8080",
            "protocol": "a2a",
        });
        let info: SurfaceInfo = serde_json::from_value(legacy).expect("legacy surface info");
        assert!(info.tags.is_empty());
        assert_eq!(info.is_payment_surface, None);

        // A modern peer sends both fields.
        let modern = serde_json::json!({
            "config_id": "cfg-2",
            "name": "Pay",
            "description": "",
            "listen_address": "0.0.0.0:8080",
            "protocol": "a2a",
            "tags": ["payment"],
            "is_payment_surface": true,
        });
        let info: SurfaceInfo = serde_json::from_value(modern).expect("modern surface info");
        assert_eq!(info.tags, vec!["payment".to_string()]);
        assert_eq!(info.is_payment_surface, Some(true));
    }

    fn make_user_data(
        user_id: &str,
        role: UserRole,
    ) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: user_id.to_string(),
            username: "alice".to_string(),
            passkeys: Vec::new(),
            role,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: None,
        }
    }

    async fn make_passkey_storage() -> (Arc<PasskeyStorage>, TempDir) {
        let tmp = TempDir::new().expect("tempdir");
        let storage_path = tmp
            .path()
            .join("passkeys")
            .to_string_lossy()
            .to_string();
        let avatars_path = tmp
            .path()
            .join("avatars")
            .to_string_lossy()
            .to_string();
        let storage = PasskeyStorage::new(storage_path, avatars_path)
            .await
            .expect("storage init");
        (Arc::new(storage), tmp)
    }

    fn remote_gateway() -> Gateway {
        Gateway::new_with_creation_type(
            "Remote Gateway".to_string(),
            "Remote gateway".to_string(),
            "did:web:remote.example".to_string(),
            GatewayType::Remote,
            GatewayCreationType::User,
        )
    }

    #[test]
    fn authorize_gateway_delete_requires_gateway_delete_permission() {
        let gateway = remote_gateway();
        let rbac_config = RbacConfig::default();

        assert!(authorize_gateway_delete(&UserRole::Administrator, &gateway, &rbac_config).is_ok());

        let err = authorize_gateway_delete(&UserRole::PowerUser, &gateway, &rbac_config)
            .expect_err("power user should not be allowed to delete gateways");
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let err = authorize_gateway_delete(&UserRole::User, &gateway, &rbac_config)
            .expect_err("user role should not be allowed to delete gateways");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn authorize_gateway_delete_rejects_self_gateway() {
        let gateway = Gateway::new(
            "Local Gateway".to_string(),
            "Local gateway".to_string(),
            "did:web:local.example".to_string(),
            GatewayType::SelfGateway,
        );
        let rbac_config = RbacConfig::default();

        let err = authorize_gateway_delete(&UserRole::Administrator, &gateway, &rbac_config)
            .expect_err("self gateway must never be deletable");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authorize_gateway_delete_rejects_file_backed_regular_user() {
        let (storage, _tmp) = make_passkey_storage().await;
        let caller = make_user_data("user-123", UserRole::User);
        storage
            .save_user(&caller)
            .await
            .expect("save user");

        let loaded_caller = storage
            .load_user_by_id("user-123")
            .await
            .expect("load caller")
            .expect("caller exists");

        let gateway = remote_gateway();
        let rbac_config = RbacConfig::default();

        let err = authorize_gateway_delete(&loaded_caller.role, &gateway, &rbac_config)
            .expect_err("file-backed normal user should not be able to delete gateways");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    async fn gateway_store_with(gateway: &Gateway) -> (Arc<crate::gateways::FileSystemGatewayStore>, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            crate::gateways::FileSystemGatewayStore::new(
                dir.path().to_path_buf(),
                Some("did:web:self.example".to_string()),
            )
            .await
            .expect("gateway store"),
        );
        store
            .create(gateway)
            .await
            .expect("create gateway");
        (store, dir)
    }

    #[tokio::test]
    async fn a_tenant_token_reads_but_cannot_change_an_appliance_gateway() {
        let mut appliance = remote_gateway();
        appliance.exposed_channels = vec!["shared".into()];
        let (store, _dir) = gateway_store_with(&appliance).await;
        let tenant = Some(Extension(PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let update = |id: String, context: Option<Extension<PatTenantContext>>| {
            update_gateway_exposed_surfaces(
                Extension(store.clone()),
                Extension(None),
                Path(id),
                context,
                None,
                Json(UpdateExposedChannelsRequest {
                    exposure_mode: Some(ExposureMode::All),
                    exposed_channels: Vec::new(),
                }),
            )
        };

        assert!(gateway_allowed(&appliance, &tenant, &None), "a tenant may read an appliance gateway");
        let err = update(appliance.id.clone(), tenant.clone())
            .await
            .expect_err("a tenant cannot widen an appliance peer's exposure");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        let kept = store
            .get(&appliance.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.exposed_channels, vec!["shared".to_string()]);

        let mut owned = remote_gateway();
        owned.id = "tenant-gateway".into();
        owned.did = "did:web:tenant-peer.example".into();
        owned.tenant_id = Some("tenant-a".into());
        store
            .create(&owned)
            .await
            .unwrap();
        assert!(
            update(owned.id.clone(), tenant)
                .await
                .is_ok(),
            "a tenant manages its own gateway"
        );
        assert!(
            update(appliance.id.clone(), None)
                .await
                .is_ok(),
            "an appliance-wide caller is unaffected"
        );
    }

    async fn update_exposure(
        store: &Arc<crate::gateways::FileSystemGatewayStore>,
        id: &str,
        body: serde_json::Value,
    ) -> Result<Json<Gateway>, (StatusCode, String)> {
        update_gateway_exposed_surfaces(
            Extension(store.clone()),
            Extension(None),
            Path(id.to_string()),
            None,
            None,
            Json(serde_json::from_value(body).expect("valid exposure request")),
        )
        .await
    }

    #[tokio::test]
    async fn exposure_update_stores_the_mode_and_clears_the_list_outside_list_mode() {
        let mut gateway = remote_gateway();
        gateway.exposure_mode = Some(ExposureMode::List);
        gateway.exposed_channels = vec!["alpha".into()];
        let (store, _dir) = gateway_store_with(&gateway).await;

        for (mode, expected) in [("all", ExposureMode::All), ("none", ExposureMode::None)] {
            let Json(updated) = update_exposure(
                &store,
                &gateway.id,
                serde_json::json!({ "exposure_mode": mode, "exposed_channels": ["alpha"] }),
            )
            .await
            .expect("update");
            assert_eq!(updated.exposure_mode, Some(expected));
            assert!(
                updated
                    .exposed_channels
                    .is_empty(),
                "{mode}"
            );
            let stored = store
                .get(&gateway.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.exposure_mode, Some(expected));
        }
    }

    #[tokio::test]
    async fn exposure_update_without_a_mode_never_means_all() {
        let gateway = remote_gateway();
        let (store, _dir) = gateway_store_with(&gateway).await;

        let Json(updated) = update_exposure(&store, &gateway.id, serde_json::json!({ "exposed_channels": [] }))
            .await
            .expect("update");

        assert_eq!(updated.exposure_mode, Some(ExposureMode::None));
        assert!(!updated.exposes_surface("alpha"));
    }

    #[tokio::test]
    async fn exposure_update_rejects_an_unknown_mode_and_the_self_gateway() {
        assert!(
            serde_json::from_value::<UpdateExposedChannelsRequest>(serde_json::json!({ "exposure_mode": "some" }))
                .is_err()
        );
        let (store, _dir) = gateway_store_with(&remote_gateway()).await;
        let self_id = self_gateway_id(&store).await;

        let err = update_exposure(&store, &self_id, serde_json::json!({ "exposure_mode": "all" }))
            .await
            .expect_err("the self gateway has no exposure");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    async fn self_gateway_id(store: &crate::gateways::FileSystemGatewayStore) -> String {
        store
            .list_all()
            .await
            .expect("list gateways")
            .into_iter()
            .find(|g| g.gateway_type == GatewayType::SelfGateway)
            .expect("self gateway")
            .id
    }

    fn update_request(json: serde_json::Value) -> UpdateGatewayRequest {
        serde_json::from_value(json).expect("valid update request")
    }

    async fn update(
        store: &Arc<crate::gateways::FileSystemGatewayStore>,
        id: &str,
        req: UpdateGatewayRequest,
    ) -> Result<Gateway, (StatusCode, String)> {
        update_gateway(Extension(Arc::clone(store)), Extension(None), Path(id.to_string()), None, None, Json(req))
            .await
            .map(|Json(gateway)| gateway)
    }

    async fn trust(
        store: &Arc<crate::gateways::FileSystemGatewayStore>,
        id: &str,
        issuer_did: &str,
    ) -> Result<Gateway, (StatusCode, String)> {
        add_trusted_issuer(
            Extension(Arc::clone(store)),
            Path(id.to_string()),
            None,
            None,
            Json(TrustedIssuerRequest {
                issuer_did: issuer_did.to_string(),
            }),
        )
        .await
        .map(|Json(gateway)| gateway)
    }

    async fn untrust(
        store: &Arc<crate::gateways::FileSystemGatewayStore>,
        id: &str,
        issuer_did: &str,
    ) -> Result<Gateway, (StatusCode, String)> {
        remove_trusted_issuer(Extension(Arc::clone(store)), Path((id.to_string(), issuer_did.to_string())), None, None)
            .await
            .map(|Json(gateway)| gateway)
    }

    #[tokio::test]
    async fn update_ignores_an_issuer_did_field() {
        let mut remote = remote_gateway();
        remote.issuer_did = Some("did:web:peer.example".to_string());
        let (store, _dir) = gateway_store_with(&remote).await;

        let updated = update(
            &store,
            &remote.id,
            update_request(serde_json::json!({ "name": "renamed", "issuer_did": "did:web:attacker.example" })),
        )
        .await
        .expect("update succeeds");

        assert_eq!(updated.name, "renamed");
        assert_eq!(updated.issuer_did, Some("did:web:peer.example".to_string()));
    }

    #[tokio::test]
    async fn trusting_an_issuer_adds_it_to_the_connection() {
        let remote = remote_gateway();
        let (store, _dir) = gateway_store_with(&remote).await;

        let updated = trust(&store, &remote.id, "did:web:legacy.example")
            .await
            .expect("trust succeeds");

        assert_eq!(updated.trusted_issuer_dids, vec!["did:web:legacy.example".to_string()]);
        assert_eq!(updated.issuer_did, None, "trusting an issuer must not touch the attested issuer");
        let stored = store
            .get(&remote.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.trusted_issuer_dids, vec!["did:web:legacy.example".to_string()]);
    }

    #[tokio::test]
    async fn trusting_an_issuer_twice_keeps_one_entry() {
        let remote = remote_gateway();
        let (store, _dir) = gateway_store_with(&remote).await;

        trust(&store, &remote.id, "did:web:legacy.example")
            .await
            .expect("first trust succeeds");
        let updated = trust(&store, &remote.id, "did:web:legacy.example")
            .await
            .expect("second trust succeeds");

        assert_eq!(updated.trusted_issuer_dids, vec!["did:web:legacy.example".to_string()]);
    }

    #[tokio::test]
    async fn trusting_a_non_did_is_rejected() {
        let remote = remote_gateway();
        let (store, _dir) = gateway_store_with(&remote).await;

        let err = trust(&store, &remote.id, "https://legacy.example")
            .await
            .expect_err("non-DID must be rejected");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let stored = store
            .get(&remote.id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            stored
                .trusted_issuer_dids
                .is_empty()
        );
    }

    #[tokio::test]
    async fn trusting_an_issuer_on_the_self_gateway_is_rejected() {
        let (store, _dir) = gateway_store_with(&remote_gateway()).await;
        let self_id = self_gateway_id(&store).await;

        let err = trust(&store, &self_id, "did:web:legacy.example")
            .await
            .expect_err("self gateway has no connection to trust issuers on");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn untrusting_an_issuer_removes_only_that_entry() {
        let mut remote = remote_gateway();
        remote.trusted_issuer_dids = vec!["did:web:legacy.example".to_string(), "did:web:relay.example".to_string()];
        let (store, _dir) = gateway_store_with(&remote).await;

        let updated = untrust(&store, &remote.id, "did:web:legacy.example")
            .await
            .expect("untrust succeeds");

        assert_eq!(updated.trusted_issuer_dids, vec!["did:web:relay.example".to_string()]);
    }

    #[tokio::test]
    async fn untrusting_an_unknown_issuer_is_not_found() {
        let remote = remote_gateway();
        let (store, _dir) = gateway_store_with(&remote).await;

        let err = untrust(&store, &remote.id, "did:web:legacy.example")
            .await
            .expect_err("nothing to remove");

        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn forgetting_the_attested_issuer_clears_it_and_its_source() {
        let mut remote = remote_gateway();
        remote.issuer_did = Some("did:web:peer.example".to_string());
        remote.issuer_did_source = Some(crate::gateways::types::IssuerDidSource::Handshake);
        remote.trusted_issuer_dids = vec!["did:web:legacy.example".to_string()];
        let (store, _dir) = gateway_store_with(&remote).await;

        let Json(updated) = forget_gateway_issuer(Extension(Arc::clone(&store)), Path(remote.id.clone()), None, None)
            .await
            .expect("forget succeeds");

        assert_eq!(updated.issuer_did, None);
        assert_eq!(updated.issuer_did_source, None);
        assert_eq!(
            updated.trusted_issuer_dids,
            vec!["did:web:legacy.example".to_string()],
            "forgetting the attested issuer must keep operator-trusted issuers"
        );
    }

    #[tokio::test]
    async fn forgetting_the_issuer_of_the_self_gateway_is_rejected() {
        let (store, _dir) = gateway_store_with(&remote_gateway()).await;
        let self_id = self_gateway_id(&store).await;

        let err = forget_gateway_issuer(Extension(store), Path(self_id), None, None)
            .await
            .expect_err("self gateway has no attested issuer");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn issuer_request_without_listener_manager_is_unavailable() {
        let remote = remote_gateway();
        let (store, _dir) = gateway_store_with(&remote).await;

        let err = request_gateway_issuer(Extension(store), Extension(None), Path(remote.id.clone()), None, None)
            .await
            .expect_err("no listener manager");

        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn issuer_request_for_self_gateway_is_rejected() {
        let (store, _dir) = gateway_store_with(&remote_gateway()).await;
        let self_id = self_gateway_id(&store).await;

        let err = request_gateway_issuer(Extension(store), Extension(None), Path(self_id), None, None)
            .await
            .expect_err("self gateway has no peer issuer");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn issuer_request_for_unknown_gateway_is_not_found() {
        let (store, _dir) = gateway_store_with(&remote_gateway()).await;

        let err = request_gateway_issuer(Extension(store), Extension(None), Path("missing".to_string()), None, None)
            .await
            .expect_err("unknown gateway");

        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn account_not_found_is_recognised_only_from_its_problem_report() {
        use affinidi_messaging_sdk::errors::ATMError;

        let missing = ATMError::ProblemReport("e.p.account.not_found".into(), "gone".into(), "false".into());
        assert!(is_account_not_found(&missing));

        let other_report = ATMError::ProblemReport("e.p.access_list.denied".into(), "denied".into(), "false".into());
        assert!(!is_account_not_found(&other_report));

        let transport = ATMError::TransportError("account.not_found".into());
        assert!(!is_account_not_found(&transport));

        let near_miss = ATMError::ProblemReport("e.p.account.not_found_else".into(), "other".into(), "false".into());
        assert!(!is_account_not_found(&near_miss));
    }

    fn probed_account(access_list_mode: &str) -> AccountProbe {
        Ok(Ok(serde_json::from_value(serde_json::json!({
            "did": "did:example:connection-point",
            "accountType": "standard",
            "acl": { "accessListMode": access_list_mode }
        }))
        .unwrap()))
    }

    fn probe_error(error: affinidi_messaging_sdk::errors::ATMError) -> AccountProbe {
        Ok(Err(error))
    }

    #[tokio::test]
    async fn a_ping_timeout_restarts_the_listener_only_when_the_account_is_missing() {
        use affinidi_messaging_sdk::errors::ATMError;

        let missing =
            probe_error(ATMError::ProblemReport(ACCOUNT_NOT_FOUND_CODE.into(), "gone".into(), "false".into()));
        assert_eq!(ping_timeout_recovery(&missing), PingTimeoutRecovery::RestartListener);

        let other_report =
            probe_error(ATMError::ProblemReport("e.p.access_list.denied".into(), "denied".into(), "false".into()));
        assert_eq!(ping_timeout_recovery(&other_report), PingTimeoutRecovery::ReportTimeout);

        let near_miss =
            probe_error(ATMError::ProblemReport("e.p.account.not_found_else".into(), "other".into(), "false".into()));
        assert_eq!(ping_timeout_recovery(&near_miss), PingTimeoutRecovery::ReportTimeout);

        let transport = probe_error(ATMError::TransportError("connection reset".into()));
        assert_eq!(ping_timeout_recovery(&transport), PingTimeoutRecovery::ReportTimeout);

        let probe_timed_out: AccountProbe =
            Err(tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
                .await
                .unwrap_err());
        assert_eq!(ping_timeout_recovery(&probe_timed_out), PingTimeoutRecovery::ReportTimeout);
    }

    #[test]
    fn a_ping_timeout_reopens_only_a_closed_receive_list() {
        assert_eq!(ping_timeout_recovery(&probed_account("explicitDeny")), PingTimeoutRecovery::ReportTimeout);
        assert_eq!(ping_timeout_recovery(&probed_account("explicitAllow")), PingTimeoutRecovery::ReopenReceiveList);
    }

    #[tokio::test]
    async fn a_failed_restart_after_a_missing_account_still_reports_the_ping_timeout() {
        let root = TempDir::new().unwrap();
        let (manager, _issuer_dir) = crate::gateways::test_helpers::test_listener_manager(root.path()).await;
        let listener = crate::gateways::test_helpers::test_listener("probed").await;
        manager
            .register_test_listener(listener.clone())
            .await;

        let response = restart_after_missing_account(uuid::Uuid::new_v4(), &manager, &listener).await;

        assert!(!response.success);
        assert_eq!(response.message, "Gateway ping timed out - no response received");
        assert_eq!(response.round_trip_ms, None);
    }
}

/// Request body for connecting to a gateway via OOB
#[derive(Debug, Deserialize)]
pub struct ConnectViaOOBRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub oob_url: String,
    pub secret: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub did_method: Option<crate::gateways::connection_points::types::ConnectionPointDidMethod>,
}

/// Response for connecting to a gateway via OOB
#[derive(Debug, Serialize)]
pub struct ConnectViaOOBResponse {
    pub gateway: Gateway,
}

/// Connect to a remote gateway using an OOB (Out-of-Band) invitation link
pub async fn connect_via_oob<
    S: GatewayStore + 'static,
    P: ConnectionPointStore + 'static,
    M: crate::mediators::MediatorStore,
>(
    Extension(store): Extension<Arc<S>>,
    Extension(cp_store): Extension<Arc<P>>,
    Extension(mediator_store): Extension<Arc<M>>,
    Extension(vc_issuer): Extension<Arc<crate::identity::VCIssuer>>,
    Extension(bootstrap_config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(network_config): Extension<Arc<crate::config::NetworkConfig>>,
    Extension(pending_store): Extension<Arc<crate::gateways::PendingConnectionStore>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    #[cfg(feature = "didwebvh")] Extension(log_storage): Extension<
        Option<std::sync::Arc<dyn crate::storage::DidLogStorage>>,
    >,
    #[cfg(feature = "didwebvh")] Extension(identity_store): Extension<
        Option<std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
    >,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<ConnectViaOOBRequest>,
) -> Result<Json<ConnectViaOOBResponse>, (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    let pending_gateway_id = uuid::Uuid::new_v4().to_string();
    if !scope_allows_resource(
        resource_scope(&scope),
        tenant_context(&context),
        ResourceKind::Gateways,
        &pending_gateway_id,
    ) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".to_string()));
    }
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("🔗 Starting OOB connection flow (ACCEPTOR role)");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  OOB URL: {}", req.oob_url);
    info!("  Gateway Name: {}", req.name);
    info!("  Gateway Description: {}", req.description);
    info!("  IMPORTANT: ACCEPTOR does not need a mediator configured");
    info!("  Messages will be sent to inviter's mediator (from OOB URL)");
    info!("");

    // Enforce the appliance gateway limit before starting the OOB handshake.
    crate::config::enforce_add("connections.gateways")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;

    // Step 1: Retrieve OOB invitation (simple HTTP GET, no ATM needed)
    info!("📥 Step 1: Retrieving OOB invitation from URL...");
    info!("  Initializing TDK shared state for DID caching...");
    let tdk = Arc::new(
        affinidi_tdk_common::TDKSharedState::new(crate::gateways::did_cache::headless_tdk_config().map_err(|e| {
            error!("❌ Failed to build TDK config: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build TDK config: {:?}", e))
        })?)
        .await
        .map_err(|e| {
            error!("❌ Failed to create TDK shared state: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create TDK shared state: {:?}", e))
        })?,
    );
    info!("  URL: {}", req.oob_url);
    let invitation_message = crate::comm::didcomm::client::DIDCommClient::retrieve_oob_invite(&req.oob_url)
        .await
        .map_err(|e| {
            error!("❌ Failed to retrieve OOB invitation: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to retrieve OOB invitation: {:?}", e))
        })?;

    info!("✓ OOB invitation retrieved successfully");
    info!("  Invitation ID: {}", invitation_message.id);
    info!("  Invitation from: {:?}", invitation_message.from);
    info!("  Invitation type: {}", invitation_message.typ);
    info!("");

    // Step 2: Extract inviter's temporary DID (used for handshake)
    info!("🔍 Step 2: Extracting inviter's temporary DID...");
    let inviter_temporary_did = invitation_message
        .from
        .ok_or_else(|| {
            error!("❌ Invitation missing 'from' field");
            (StatusCode::BAD_REQUEST, "Invitation missing 'from' field".to_string())
        })?;

    info!("✓ Inviter's temporary DID extracted: {}", inviter_temporary_did);
    info!("");

    // Check if already connected
    info!("🔍 Step 3: Checking for existing gateway connection...");
    if let Ok(Some(existing_gateway)) = store
        .get_by_did(&inviter_temporary_did)
        .await
    {
        if !gateway_allowed(&existing_gateway, &context, &scope) {
            return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
        }
        info!("⚠️  Gateway already exists for DID {}", inviter_temporary_did);
        info!("  Gateway ID: {}", existing_gateway.id);
        info!("  Returning existing gateway instead of creating new connection");
        return Ok(Json(ConnectViaOOBResponse { gateway: existing_gateway }));
    }
    info!("✓ No existing gateway found - proceeding with new connection");
    info!("");

    // Step 4: Extract inviter's mediator from OOB URL
    info!("🔍 Step 4: Extracting inviter's mediator endpoint from OOB URL...");
    let their_mediator_endpoint = req
        .oob_url
        .split("/oob")
        .next()
        .ok_or_else(|| {
            error!("❌ Invalid OOB URL format - missing /oob path");
            (StatusCode::BAD_REQUEST, "Invalid OOB URL format".to_string())
        })?
        .to_string();
    info!("  Mediator endpoint: {}", their_mediator_endpoint);

    // Convert mediator endpoint to DID (replace / with : for did:web format)
    // https://fabric-mediator-1.example.com/mediator/v1 -> did:web:fabric-mediator-1.example.com:mediator:v1:.well-known
    let their_mediator_did = fetch_mediator_did_from_url(&their_mediator_endpoint)
        .await
        .map_err(|e| {
            error!("❌ Failed to fetch inviter's mediator DID from URL: {}", e);
            (StatusCode::BAD_REQUEST, format!("Failed to fetch inviter's mediator DID from URL: {}", e))
        })?;

    info!("✓ Inviter's mediator DID: {}", their_mediator_did);

    let their_mediator_did_document = match mediator_store
        .list_all()
        .await
    {
        Ok(mediators) => mediators
            .into_iter()
            .find(|mediator| mediator.did == their_mediator_did)
            .and_then(|mediator| mediator.did_document),
        Err(e) => {
            warn!("Failed to list configured mediators while preloading inviter mediator DID document: {}", e);
            None
        }
    };

    if let Some(did_document) = their_mediator_did_document.clone() {
        crate::comm::didcomm::mediator::cache_did_document_in_tdk_state(&tdk, &their_mediator_did, did_document)
            .await
            .map_err(|e| {
                error!("❌ Failed to cache inviter mediator DID document: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to cache inviter mediator DID document: {}", e))
            })?;
        info!("✓ Inviter mediator DID document cached for ATM profile creation");
    } else {
        debug!(
            "No configured DID document found for inviter mediator {}; ATM will use live DID resolution",
            their_mediator_did
        );
    }

    info!("");

    // Step 5: Create TWO DIDs for proper OOB flow
    info!("🔑 Step 5: Creating temporary DID for handshake...");
    info!("  DID #1: Temporary (ephemeral) - used only for initial handshake");

    let temp_cp_id = uuid::Uuid::new_v4().to_string();
    info!("  Temporary CP ID: {}", temp_cp_id);
    info!("  Generating identity...");

    let did_method = req
        .did_method
        .as_ref()
        .unwrap_or(&crate::gateways::connection_points::types::ConnectionPointDidMethod::Web);

    let (temporary_did, temp_secrets, _temp_doc) =
        crate::gateways::connection_points::handlers::generate_connection_point_identity(
            &temp_cp_id,
            &network_config.did.domain,
            std::path::Path::new(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ),
            &their_mediator_endpoint,
            did_method,
            #[cfg(feature = "didwebvh")]
            log_storage.clone(),
            #[cfg(feature = "didwebvh")]
            identity_store.clone(),
        )
        .await
        .map_err(|e| {
            error!("❌ Failed to generate temporary DID: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate temporary DID: {}", e))
        })?;

    info!("✓ Temporary DID created: {}", temporary_did);
    info!("  Number of secrets: {}", temp_secrets.len());

    // Create DIDCommClient for the temporary DID (handles TDK, ATM, profiles internally)
    info!("  Creating DIDCommClient for temporary DID...");
    let mut didcomm_client = crate::comm::didcomm::client::DIDCommClient::new(
        temporary_did.clone(),
        temp_secrets,
        Some(their_mediator_did.clone()),
        Some(format!("oob-acceptor-{}", temp_cp_id)),
    )
    .await
    .map_err(|e| {
        error!("❌ Failed to create DIDCommClient: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create DIDCommClient: {}", e))
    })?;
    info!("✓ DIDCommClient created for temporary DID");
    info!("");

    // Step 6: Create secure DID #2 (permanent connection)
    info!("🔑 Step 6: Creating secure DID for permanent connection...");
    info!("  DID #2: Secure (permanent) - used for actual connection after handshake");

    let secure_cp_id = uuid::Uuid::new_v4().to_string();
    info!("  Secure CP ID: {}", secure_cp_id);
    info!("  Generating identity...");

    let (secure_did, secure_secrets, _secure_doc) =
        crate::gateways::connection_points::handlers::generate_connection_point_identity(
            &secure_cp_id,
            &network_config.did.domain,
            std::path::Path::new(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ),
            &their_mediator_endpoint,
            did_method,
            #[cfg(feature = "didwebvh")]
            log_storage.clone(),
            #[cfg(feature = "didwebvh")]
            identity_store.clone(),
        )
        .await
        .map_err(|e| {
            error!("❌ Failed to generate secure DID: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate secure DID: {}", e))
        })?;

    info!("✓ Secure DID created: {}", secure_did);
    info!("");

    // Step 7: Store pending connection state (so we can complete handshake when connection-accepted arrives)
    info!("💾 Step 7: Storing pending connection state...");
    // Note: We store the inviter's mediator DID (not ours, since we don't have one on ACCEPTOR side)
    let pending_connection = crate::gateways::PendingOOBConnection {
        id: invitation_message.id.clone(),
        invitation_id: invitation_message.id.clone(),
        our_temporary_did: temporary_did.clone(),
        our_secure_did: secure_did.clone(),
        their_temporary_did: inviter_temporary_did.clone(),
        their_secure_did: None, // Will be set when we receive connection-accepted
        their_issuer_did: None,
        mediator_did: their_mediator_did.clone(), // Store inviter's mediator
        connection_point_id: String::new(),       // No connection point needed for OOB
        role: crate::gateways::ConnectionRole::Acceptor,
        state: crate::gateways::ConnectionState::WaitingForResponse,
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        secure_cp_id: Some(secure_cp_id.clone()),
        temporary_cp_id: Some(temp_cp_id.clone()),
    };

    info!("  Pending connection details:");
    info!("    ID: {}", pending_connection.id);
    info!("    Our temporary DID: {}", pending_connection.our_temporary_did);
    info!("    Our secure DID: {}", pending_connection.our_secure_did);
    info!("    Their temporary DID: {}", pending_connection.their_temporary_did);
    info!("    Mediator DID: {}", pending_connection.mediator_did);
    info!("    Role: {:?}", pending_connection.role);
    info!("    State: {:?}", pending_connection.state);

    pending_store
        .store(pending_connection)
        .await;
    info!("✓ Pending connection state stored");
    info!("");

    // Step 8: Build connection-setup message
    info!("📝 Step 8: Building connection-setup message...");

    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    use crate::gateways::connection_points::message_processor::{channel_did_proof_challenge, sign_channel_did_proof};

    // The thread id doubles as the attestation nonce so the inviter can bind
    // the attestation to this exact message.
    let connection_thid = uuid::Uuid::new_v4().to_string();
    let issuer_attestation = crate::gateways::issuer_attestation::build_issuer_attestation(
        &vc_issuer,
        &secure_did,
        &inviter_temporary_did,
        &connection_thid,
    )
    .await
    .map_err(|e| {
        error!("❌ Failed to build issuer attestation: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build issuer attestation: {}", e))
    })?;

    // Independent of the attestation above: the attestation binds this
    // appliance's identity VC to the channel, this proves control of the
    // key behind the channel_did the body claims.
    let channel_did_proof = sign_channel_did_proof(
        &secure_secrets,
        &channel_did_proof_challenge(&temporary_did, &inviter_temporary_did, &secure_did),
    )
    .map_err(|e| {
        error!("❌ Failed to sign channel_did proof: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to sign channel_did proof: {}", e))
    })?;

    let connection_message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::ConnectionSetup.to_string(),
        json!({
            "channel_did": secure_did.clone(),
            "secret": req.secret.clone(),
            "issuer_attestation": issuer_attestation,
            "channel_did_proof": channel_did_proof,
        }),
    )
    .from(temporary_did.clone())
    .to(inviter_temporary_did.clone())
    .thid(connection_thid)
    .pthid(invitation_message.id.clone())
    .finalize();

    info!("✓ Connection-setup message built:");
    info!("    Message ID: {}", connection_message.id);
    info!("    Type: {}", connection_message.typ);
    info!("    From: {}", temporary_did);
    info!("    To: {}", inviter_temporary_did);
    info!("    Body: channel_did={}", secure_did);
    info!("    Body: secret=[REDACTED]");
    info!("");

    // Step 9: Pre-resolve and cache the inviter's DID document
    info!("🔍 Step 9: Pre-resolving inviter's DID document for encryption...");
    info!("  Target DID: {}", inviter_temporary_did);

    let did_cache = listener_manager
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Listener manager not available".to_string()))?
        .get_did_cache();

    match did_cache
        .resolve_and_cache_for_atm(&inviter_temporary_did, didcomm_client.tdk_state())
        .await
    {
        Ok((_, was_cached)) => {
            if was_cached {
                info!("✓ Using cached DID document for {}", inviter_temporary_did);
            } else {
                info!("✓ DID document resolved and cached for {}", inviter_temporary_did);
            }
        }
        Err(e) => {
            error!("❌ Failed to resolve inviter's DID document: {}", e);
            return Err((StatusCode::SERVICE_UNAVAILABLE, format!("Cannot resolve inviter's DID document: {}", e)));
        }
    }
    info!("");

    // Step 10: Register profile and send message via DIDCommClient
    info!("📤 Step 10: Connecting to inviter's mediator and sending message...");
    info!("  Target mediator DID: {}", their_mediator_did);
    info!("  Target recipient DID: {}", inviter_temporary_did);

    didcomm_client
        .register_profile()
        .await
        .map_err(|e| {
            error!("❌ Failed to register profile with mediator: {}", e);
            (StatusCode::UNAUTHORIZED, format!("Failed to register profile: {}", e))
        })?;
    info!("  ✓ Profile registered with mediator");

    // Open ACL so the inviter's connection-accepted can reach us on mediators
    // with explicit-allow defaults (the temporary listener is System type and
    // ws_listener skips ACL setup for that type).
    set_acl_to_allow_everything_and_more(didcomm_client.atm(), Arc::clone(didcomm_client.profile()))
        .await
        .map_err(|e| {
            info!("  ℹ️  Could not set ACL: {:?}", e);
            info!("  Continuing anyway - may work with default mediator permissions");
        })
        .ok();
    info!("  ✓ ACL set to allow-all for temporary DID");

    didcomm_client
        .pack_and_send_message(&connection_message, &inviter_temporary_did, &temporary_did)
        .await
        .map_err(|e| {
            error!("❌ Failed to send connection-setup: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send connection-setup: {}", e))
        })?;

    info!("✓ Connection-setup sent successfully to inviter's mediator");
    info!("");
    info!("⏳ Step 11: Creating pending gateway and temporary connection point listener...");
    info!("  The inviter will receive our connection-setup message");
    info!("  They will send connection-accepted back");

    // Create and store pending gateway FIRST (so we have the ID for the listener)
    let mut pending_gateway =
        Gateway::new(req.name.clone(), req.description.clone(), inviter_temporary_did.clone(), GatewayType::Remote);

    pending_gateway.id = pending_gateway_id;
    pending_gateway.tenant_id = req.tenant_id;
    pending_gateway.status = GatewayStatus::Pending;

    store
        .create(&pending_gateway)
        .await
        .map_err(|e| {
            error!("❌ Failed to create pending gateway: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create pending gateway: {}", e))
        })?;

    info!("  ✓ Pending gateway created with ID: {}", pending_gateway.id);

    let listener_mgr = listener_manager.ok_or_else(|| {
        error!("❌ Listener manager not available");
        (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available - cannot start listener".to_string())
    })?;

    // Extract mediator URL from mediator DID
    let mediator_url = their_mediator_endpoint.clone();

    // Calculate expiry time from config
    let expiry_hours = bootstrap_config
        .oob_connection
        .pending_expiry_hours;
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expiry_hours as i64);

    info!("  Creating temporary connection point for receiving connection-accepted...");
    info!("  Expiry: {} hours from now ({})", expiry_hours, expires_at.format("%Y-%m-%d %H:%M:%S UTC"));

    // Create temporary connection point with expiry metadata
    // temp_cp_id (UUID) was set in Step 5 and matches the directory where keys were saved
    let mut temp_connection_point = super::connection_points::types::GatewayConnectionPoint::new(
        pending_gateway.id.clone(),
        their_mediator_did.clone(),
        temporary_did.clone(),
        format!("Temporary listener for pending gateway {}", &pending_gateway.id[..8]),
        format!(
            "Awaiting connection-accepted from {}",
            &inviter_temporary_did[inviter_temporary_did
                .len()
                .saturating_sub(12)..]
        ),
        String::new(),
        String::new(),
        serde_json::json!({
            "expires_at": expires_at,
            "pending_gateway_id": pending_gateway.id,
            "secure_cp_id": secure_cp_id,
            "secure_did": secure_did,
        }),
        None,
        super::connection_points::types::ConnectionPointType::System, // Temporary system CP
        String::new(),
    );
    temp_connection_point.id = temp_cp_id.clone();
    temp_connection_point.did_method = did_method.clone();

    // Store the temporary connection point
    cp_store
        .create(&temp_connection_point)
        .await
        .map_err(|e| {
            error!("❌ Failed to create temporary connection point: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create temporary connection point: {}", e))
        })?;

    info!("  ✓ Temporary connection point created: {}", temp_cp_id);

    // Start WebSocket listener for the temporary connection point
    info!("  Starting WebSocket listener (not polling!)...");
    listener_mgr
        .request_start_listener(temp_connection_point, their_mediator_did.clone(), mediator_url)
        .map_err(|e| {
            error!("❌ Failed to start temporary listener: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to start temporary listener: {}", e))
        })?;

    info!("  ✓ WebSocket listener started for temporary DID");
    info!("  Listener will automatically stop when connection-accepted is received or after {} hours", expiry_hours);
    info!("");

    // Step 12: Return with pending gateway
    info!("✅ OOB connection initiated successfully!");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("");

    Ok(Json(ConnectViaOOBResponse { gateway: pending_gateway }))
}

/// Response body for gateway ping
#[derive(Debug, Serialize)]
pub struct GatewayPingResponse {
    pub success: bool,
    pub message: String,
    pub round_trip_ms: Option<u64>,
}

/// Response body for a peer issuer DID request
#[derive(Debug, Serialize)]
pub struct GatewayIssuerResponse {
    pub gateway_id: String,
    pub issuer_did: String,
}

/// Return the verified issuer DID of a remote gateway, running the
/// gateway-issuer-request exchange over the pairing when it is not stored yet.
pub async fn request_gateway_issuer<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<GatewayIssuerResponse>, (StatusCode, String)> {
    use crate::gateways::issuer_exchange::PeerIssuerError;

    let gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_writable(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".to_string()));
    }
    if gateway.gateway_type != GatewayType::Remote {
        return Err((StatusCode::BAD_REQUEST, "Issuer DID can only be requested for remote gateways".to_string()));
    }
    let manager = listener_manager
        .as_ref()
        .ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, "Connection point listener manager not available".to_string())
        })?;

    let issuer_did = manager
        .ensure_peer_issuer_did(&id)
        .await
        .map_err(|e| {
            let status = match &e {
                PeerIssuerError::GatewayNotFound(_) => StatusCode::NOT_FOUND,
                PeerIssuerError::NoListener(_) => StatusCode::SERVICE_UNAVAILABLE,
                PeerIssuerError::Send(_) | PeerIssuerError::Timeout => StatusCode::GATEWAY_TIMEOUT,
                PeerIssuerError::UnexpectedResponder { .. }
                | PeerIssuerError::UnexpectedMessageType(_)
                | PeerIssuerError::Attestation(_) => StatusCode::BAD_GATEWAY,
                PeerIssuerError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.to_string())
        })?;

    Ok(Json(GatewayIssuerResponse { gateway_id: id, issuer_did }))
}

/// Load a remote gateway the caller may manage, for the issuer endpoints.
async fn load_remote_gateway_for_issuers<S: GatewayStore>(
    store: &S,
    id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<Gateway, (StatusCode, String)> {
    let gateway = store
        .get(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_writable(&gateway, context, scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".to_string()));
    }
    if gateway.gateway_type != GatewayType::Remote {
        return Err((StatusCode::BAD_REQUEST, "Issuer DIDs apply to remote gateway connections only".to_string()));
    }
    Ok(gateway)
}

async fn save_gateway<S: GatewayStore>(
    store: &S,
    mut gateway: Gateway,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    gateway.updated_at = chrono::Utc::now();
    store
        .update(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;
    Ok(Json(gateway))
}

/// Trust an issuer DID for identity presentations arriving over this remote
/// gateway's connection, in addition to the peer's attested issuer.
pub async fn add_trusted_issuer<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<TrustedIssuerRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    let issuer_did = req
        .issuer_did
        .trim()
        .to_string();
    if !issuer_did.starts_with("did:") {
        return Err((StatusCode::BAD_REQUEST, format!("issuer_did must be a DID, got {issuer_did:?}")));
    }
    let mut gateway = load_remote_gateway_for_issuers(store.as_ref(), &id, &context, &scope).await?;
    if !gateway
        .trusted_issuer_dids
        .contains(&issuer_did)
    {
        gateway
            .trusted_issuer_dids
            .push(issuer_did);
    }
    save_gateway(store.as_ref(), gateway).await
}

/// Stop trusting an operator-added issuer DID on this connection.
pub async fn remove_trusted_issuer<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Path((id, issuer_did)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    let mut gateway = load_remote_gateway_for_issuers(store.as_ref(), &id, &context, &scope).await?;
    let before = gateway
        .trusted_issuer_dids
        .len();
    gateway
        .trusted_issuer_dids
        .retain(|trusted| trusted != &issuer_did);
    if gateway
        .trusted_issuer_dids
        .len()
        == before
    {
        return Err((StatusCode::NOT_FOUND, format!("{issuer_did} is not a trusted issuer of this gateway")));
    }
    save_gateway(store.as_ref(), gateway).await
}

/// Forget the peer's attested issuer DID. It is re-established from the next
/// issuer exchange (on the next fabric request or listener start); operator-
/// trusted issuers are kept.
pub async fn forget_gateway_issuer<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    let mut gateway = load_remote_gateway_for_issuers(store.as_ref(), &id, &context, &scope).await?;
    gateway.issuer_did = None;
    gateway.issuer_did_source = None;
    save_gateway(store.as_ref(), gateway).await
}

/// How long to wait for a gateway pong on the WebSocket before treating the
/// ping as timed out.
const PING_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a pre-flight mediator status check may take before the connection
/// is treated as stale and reconnected.
const PREFLIGHT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// How long to wait for an in-place listener reconnect to complete.
const LISTENER_RECONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// How long to wait for the mediator to return our own account when probing
/// after a ping timeout.
const ACCOUNT_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long to wait for a get-surfaces response from a remote gateway.
const SURFACES_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Ensure a connection point's listener is live before sending on it. If a
/// pre-flight status check fails (e.g. the mediator flushed our account), the
/// listener is reconnected in place so the caller's very first send succeeds
/// instead of timing out. Mirrors the trust-registry `send_with_reconnect`
/// pattern (pre-flight → reconnect) using the connection-point listener manager.
async fn ensure_live_listener(
    manager: &ConnectionPointListenerManager,
    listener: ListenerInfo,
) -> Result<ListenerInfo, (StatusCode, String)> {
    if listener
        .client
        .preflight_check(PREFLIGHT_TIMEOUT)
        .await
        .is_ok()
    {
        return Ok(listener);
    }
    warn!("Connection point '{}' failed mediator pre-flight; reconnecting before send.", listener.name);
    manager
        .reconnect_listener(&listener.connection_point_id, LISTENER_RECONNECT_TIMEOUT)
        .await
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, format!("Failed to reconnect connection point: {}", e)))
}

/// The problem-report code a mediator answers with when it no longer has the
/// requesting account.
const ACCOUNT_NOT_FOUND_CODE: &str = "e.p.account.not_found";

/// Whether a mediator error is its `account.not_found` problem report.
fn is_account_not_found(error: &affinidi_messaging_sdk::errors::ATMError) -> bool {
    matches!(
        error,
        affinidi_messaging_sdk::errors::ATMError::ProblemReport(code, _, _) if code == ACCOUNT_NOT_FOUND_CODE
    )
}

type AccountProbe = Result<
    Result<trust_tasks_rs::specs::messaging::account::get::v0_1::Account, affinidi_messaging_sdk::errors::ATMError>,
    tokio::time::error::Elapsed,
>;

/// What a gateway-ping timeout leads to once our own mediator account has been
/// probed.
#[derive(Debug, PartialEq, Eq)]
enum PingTimeoutRecovery {
    /// The remote gateway did not answer, or our account could not be read.
    ReportTimeout,
    /// The mediator no longer has our account: restart the listener so it
    /// re-authenticates and re-registers.
    RestartListener,
    /// Our account exists but its receive-list is closed: re-open it and retry.
    ReopenReceiveList,
}

fn ping_timeout_recovery(probe: &AccountProbe) -> PingTimeoutRecovery {
    match probe {
        Ok(Ok(account)) => {
            let receive_list_open = account
                .acl
                .access_list_mode
                .as_ref()
                .is_some_and(|mode| mode.to_string() == "explicitDeny");
            if receive_list_open {
                PingTimeoutRecovery::ReportTimeout
            } else {
                PingTimeoutRecovery::ReopenReceiveList
            }
        }
        Ok(Err(error)) if is_account_not_found(error) => PingTimeoutRecovery::RestartListener,
        Ok(Err(_)) | Err(_) => PingTimeoutRecovery::ReportTimeout,
    }
}

fn ping_timed_out() -> Json<GatewayPingResponse> {
    Json(GatewayPingResponse {
        success: false,
        message: "Gateway ping timed out - no response received".to_string(),
        round_trip_ms: None,
    })
}

/// Restart the listener the account probe ran on, unless a concurrent caller
/// already replaced it, and report the ping as timed out whatever the restart
/// outcome.
async fn restart_after_missing_account(
    request_id: uuid::Uuid,
    manager: &ConnectionPointListenerManager,
    gateway_listener: &ListenerInfo,
) -> Json<GatewayPingResponse> {
    if let Err(restart_error) = manager
        .restart_listener_if_current(
            &gateway_listener.connection_point_id,
            &gateway_listener.instance_id,
            LISTENER_RECONNECT_TIMEOUT,
        )
        .await
    {
        warn!("[{request_id}] Connection point restart failed: {}", restart_error);
    }
    ping_timed_out()
}

/// Handle a gateway-ping timeout by probing our own mediator account and
/// acting on [`ping_timeout_recovery`]: a closed receive-list is re-opened and
/// the ping retried once; a missing account restarts the Connection Point
/// listener so it re-authenticates and re-registers; anything else is
/// reported as a timeout.
async fn recover_ping_after_timeout(
    request_id: uuid::Uuid,
    manager: &ConnectionPointListenerManager,
    gateway_listener: &ListenerInfo,
    gateway: &Gateway,
) -> Result<Json<GatewayPingResponse>, (StatusCode, String)> {
    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    // A ping timeout is ambiguous: the remote gateway may simply be down or
    // slow, OR our own mediator account/receive-list may have been reset (e.g.
    // after a mediator store flush) so the pong was silently dropped.
    let account_probe: AccountProbe = tokio::time::timeout(
        ACCOUNT_PROBE_TIMEOUT,
        gateway_listener
            .client
            .atm()
            .trust_tasks()
            .account_get(
                gateway_listener
                    .client
                    .profile(),
                None,
            ),
    )
    .await;

    match ping_timeout_recovery(&account_probe) {
        PingTimeoutRecovery::ReportTimeout => {
            match &account_probe {
                Ok(Ok(_)) => {
                    debug!("[{request_id}] Own mediator receive-list is open; treating timeout as remote non-response.")
                }
                Ok(Err(e)) => warn!(
                    "[{request_id}] Mediator could not return our account after ping timeout ({}). Reporting timeout.",
                    e
                ),
                Err(_) => warn!(
                    "[{request_id}] Timed out reading our own mediator account after ping timeout. Reporting timeout."
                ),
            }
            return Ok(ping_timed_out());
        }
        PingTimeoutRecovery::RestartListener => {
            warn!(
                "[{request_id}] Mediator no longer has our account after ping timeout; restarting the Connection Point to re-authenticate and re-register. Reporting timeout."
            );
            return Ok(restart_after_missing_account(request_id, manager, gateway_listener).await);
        }
        PingTimeoutRecovery::ReopenReceiveList => {}
    }

    warn!("[{request_id}] Own mediator receive-list is closed; re-opening ACL and retrying ping once.");
    if let Err(e) = set_acl_to_allow_everything_and_more(
        gateway_listener.client.atm(),
        Arc::clone(
            gateway_listener
                .client
                .profile(),
        ),
    )
    .await
    {
        error!("[{request_id}] Failed to re-open ACL after ping timeout: {}", e);
        return Ok(ping_timed_out());
    }

    // Retry the ping once now that our receive-list accepts inbound pongs.
    let retry_message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::GatewayPing.to_string(),
        json!({ "timestamp": chrono::Utc::now().to_rfc3339() }),
    )
    .from(
        gateway_listener
            .gateway_did
            .clone(),
    )
    .to(gateway.did.clone())
    .finalize();

    let retry_start = std::time::Instant::now();
    if let Err(e) = gateway_listener
        .client
        .pack_and_send_message(&retry_message, &gateway.did, &gateway_listener.gateway_did)
        .await
    {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send retry ping message: {}", e)));
    }

    let retry_response = gateway_listener
        .client
        .atm()
        .message_pickup()
        .live_stream_get(
            gateway_listener
                .client
                .profile(),
            &retry_message.id,
            PING_RESPONSE_TIMEOUT,
            true, // auto_delete
        )
        .await;

    let retry_elapsed = retry_start.elapsed();
    match retry_response {
        Ok(Some((pong, _metadata))) if pong.typ == MessageType::GatewayPong.as_str() => {
            info!("[{request_id}] ✓ Received pong after re-opening receive-list ({}ms)", retry_elapsed.as_millis());
            Ok(Json(GatewayPingResponse {
                success: true,
                message: "Gateway ping successful (after re-opening receive-list)".to_string(),
                round_trip_ms: Some(retry_elapsed.as_millis() as u64),
            }))
        }
        _ => {
            warn!("[{request_id}] ✗ Ping still failed after re-opening receive-list");
            Ok(Json(GatewayPingResponse {
                success: false,
                message: "Gateway ping timed out - no response received (after re-opening receive-list)".to_string(),
                round_trip_ms: None,
            }))
        }
    }
}

/// Send a ping message to a gateway to test connectivity
pub async fn ping_gateway<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<GatewayPingResponse>, (StatusCode, String)> {
    let request_id = uuid::Uuid::new_v4();
    info!("[{request_id}] Ping requested for gateway: {}", id);

    let total_start = std::time::Instant::now();

    // Get gateway
    let gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".to_string()));
    }

    info!("[{request_id}] Gateway found: {} (DID: {})", gateway.name, gateway.did);

    // Check if gateway is active
    if gateway.status != GatewayStatus::Active {
        warn!("[{request_id}] Gateway is not active (status: {:?})", gateway.status);
        return Ok(Json(GatewayPingResponse {
            success: false,
            message: format!("Gateway is not active (status: {:?})", gateway.status),
            round_trip_ms: None,
        }));
    }

    // Get listener manager
    let manager = listener_manager
        .as_ref()
        .ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, "Connection point listener manager not available".to_string())
        })?;

    // Get an active connection point listener for this gateway
    let listeners = manager
        .get_active_listeners()
        .await;
    info!("[{request_id}] Looking for gateway with ID: {}", id);

    let gateway_listener = listeners.iter()
        .find(|listener| listener.gateway_id == id)
        .cloned()
        .ok_or_else(|| {
            error!("[{request_id}] No active connection point listener found for gateway '{}'", id);
            error!("[{request_id}] This usually means:");
            error!("[{request_id}]   1. You accepted an OOB invitation but don't have your own connection point");
            error!("[{request_id}]   2. The remote gateway needs to accept YOUR OOB invitation for bidirectional communication");
            error!("[{request_id}]   3. You need to create a connection point to receive messages");
            (StatusCode::SERVICE_UNAVAILABLE, format!("No active connection point listener found for gateway. Gateway ping requires bidirectional communication. You have {} listeners total, but none matched gateway ID '{}'. Create an OOB invitation and have the remote gateway accept it to enable bidirectional messaging.", listeners.len(), id))
        })?;

    info!(
        "[{request_id}] Using connection point listener: {} (DID: {})",
        gateway_listener.name, gateway_listener.gateway_did
    );

    // Instant recovery: make sure our own connection to the mediator is live
    // before sending. If a pre-flight status check fails (e.g. the mediator
    // flushed our account) the connection point is reconnected in place so the
    // very first ping succeeds instead of timing out.
    let gateway_listener = ensure_live_listener(manager, gateway_listener).await?;

    let start = std::time::Instant::now();

    // Build ping message using MessageType enum
    use crate::messages::MessageType;
    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    let ping_message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::GatewayPing.to_string(),
        json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }),
    )
    .from(
        gateway_listener
            .gateway_did
            .clone(),
    )
    .to(gateway.did.clone())
    .finalize();

    info!("[{request_id}] 🔵 Sending ping message (ID: {})...", ping_message.id);

    // Pre-resolve and cache the gateway DID
    if let Some(listener_mgr) = &listener_manager {
        let did_cache = listener_mgr.get_did_cache();
        let tdk_state = gateway_listener
            .client
            .atm()
            .get_tdk();

        match did_cache
            .resolve_and_cache_for_atm(&gateway.did, tdk_state)
            .await
        {
            Ok((_, was_cached)) => {
                if was_cached {
                    debug!("[{request_id}] Using cached DID document for gateway {}", gateway.did);
                } else {
                    debug!("[{request_id}] DID document resolved and cached for gateway {}", gateway.did);
                }
            }
            Err(e) => {
                warn!("[{request_id}] Failed to pre-resolve gateway DID: {}. Continuing anyway.", e);
            }
        }
    }

    // Pack and send the message
    gateway_listener
        .client
        .pack_and_send_message(&ping_message, &gateway.did, &gateway_listener.gateway_did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send ping message: {}", e)))?;

    info!("[{request_id}] 🟢 Ping sent, waiting for pong via WebSocket...");

    // Wait for pong response via WebSocket.
    let response = gateway_listener
        .client
        .atm()
        .message_pickup()
        .live_stream_get(
            gateway_listener
                .client
                .profile(),
            &ping_message.id,
            PING_RESPONSE_TIMEOUT,
            true, // auto_delete
        )
        .await;

    let elapsed = start.elapsed();
    let total_elapsed = total_start.elapsed();

    info!("[{request_id}] WebSocket wait completed after {}ms", elapsed.as_millis());
    info!("🏁 [{request_id}] Gateway ping operation COMPLETE - total time: {}ms", total_elapsed.as_millis());

    match response {
        Ok(Some((pong, _metadata))) => {
            info!("[{request_id}] ✓ Received pong response ({}ms)", elapsed.as_millis());

            // Verify it's a pong message using MessageType enum
            let is_pong = pong.typ == MessageType::GatewayPong.as_str();

            if is_pong {
                Ok(Json(GatewayPingResponse {
                    success: true,
                    message: "Gateway ping successful".to_string(),
                    round_trip_ms: Some(elapsed.as_millis() as u64),
                }))
            } else {
                warn!("[{request_id}] Received unexpected message type: {}", pong.typ);
                Ok(Json(GatewayPingResponse {
                    success: false,
                    message: format!("Received unexpected message type: {}", pong.typ),
                    round_trip_ms: None,
                }))
            }
        }
        Ok(None) => {
            warn!("[{request_id}] ✗ Ping timed out after {}ms", elapsed.as_millis());
            recover_ping_after_timeout(request_id, manager, &gateway_listener, &gateway).await
        }
        Err(e) => {
            error!("[{request_id}] ✗ Ping failed: {:?}", e);
            Ok(Json(GatewayPingResponse {
                success: false,
                message: format!("Gateway ping failed: {:?}", e),
                round_trip_ms: None,
            }))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GetGatewaySurfacesQuery {
    #[serde(default)]
    pub force_refresh: bool,
}

/// Response for getting gateway channels
#[derive(Debug, Serialize)]
pub struct GetGatewaySurfacesResponse {
    pub success: bool,
    pub channels: Vec<SurfaceInfo>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SurfaceInfo {
    pub config_id: String,
    pub name: String,
    pub description: String,
    pub listen_address: String,
    pub protocol: String,
    /// Tags of the connection point this surface is exposed through (e.g.
    /// `"payment"`). Populated by the peer gateway's discovery response;
    /// defaults to empty for peers that predate connection-point tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the remote surface is itself a payment surface (has an x402 or
    /// MPP payment policy). This is the authoritative signal for the delegated
    /// payment picker — the connection-point `tags` cannot guarantee a given
    /// surface is payable. `None` when the peer gateway predates this field,
    /// which lets the picker fall back to showing every surface instead of
    /// hiding a legacy peer's surfaces behind the payment filter.
    #[serde(default)]
    pub is_payment_surface: Option<bool>,
}

/// Outcome of a failed surface discovery. `status` / `message` reproduce the
/// HTTP response the per-gateway endpoint historically returned; `soft` marks
/// the timeout / unexpected-reply cases that endpoint served as
/// `200 { success: false }` rather than an error status. The aggregation
/// endpoint treats every failure as "skip this gateway".
struct DiscoveryFailure {
    status: StatusCode,
    message: String,
    soft: bool,
}

impl DiscoveryFailure {
    fn hard(
        status: StatusCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            soft: false,
        }
    }

    fn soft(
        status: StatusCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            soft: true,
        }
    }
}

/// Discover a remote gateway's exposed surfaces over the fabric, honouring the
/// 5-minute [`GatewaySurfaceCache`] unless `force_refresh`. Shared by the
/// per-gateway endpoint ([`get_gateway_surfaces`]) and the payment-provider
/// aggregation ([`list_payment_gateways`]) so the DIDComm discovery logic lives
/// in exactly one place.
async fn discover_gateway_surfaces<S: GatewayStore>(
    store: &Arc<S>,
    listener_manager: &Option<Arc<ConnectionPointListenerManager>>,
    cache: &Arc<GatewaySurfaceCache>,
    gateway_id: &str,
    force_refresh: bool,
) -> Result<Vec<SurfaceInfo>, DiscoveryFailure> {
    let request_id = uuid::Uuid::new_v4().to_string();
    debug!("🔍 [{request_id}] Discovering surfaces for gateway: {gateway_id} (force_refresh: {force_refresh})");

    // Check cache first (5 minute TTL) unless force_refresh is set.
    if !force_refresh
        && cache
            .is_fresh(gateway_id, 300)
            .await
        && let Some(cached) = cache.get(gateway_id).await
    {
        debug!("[{request_id}] ✓ Using cached surfaces ({} entries)", cached.channels.len());
        return Ok(cached.channels);
    }

    let gateway = store
        .get(gateway_id)
        .await
        .map_err(|e| DiscoveryFailure::hard(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {e}")))?
        .ok_or_else(|| DiscoveryFailure::hard(StatusCode::NOT_FOUND, "Gateway not found"))?;

    let listener_mgr = listener_manager
        .as_ref()
        .ok_or_else(|| DiscoveryFailure::hard(StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available"))?;

    let gateway_listener = listener_mgr
        .get_listener(gateway_id)
        .await
        .ok_or_else(|| {
            debug!("[{request_id}] No active listener found for gateway {gateway_id}");
            DiscoveryFailure::hard(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway not connected - no active WebSocket listener",
            )
        })?;

    debug!("[{request_id}] Found active WebSocket listener for gateway");

    // Instant recovery: ensure our mediator connection is live before querying,
    // so a flushed account is re-registered on the first attempt rather than
    // timing out with "gateway did not respond".
    let gateway_listener = ensure_live_listener(listener_mgr, gateway_listener)
        .await
        .map_err(|(status, message)| DiscoveryFailure::hard(status, message))?;

    // Build get-channels message
    use crate::messages::MessageType;
    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    let get_channels_message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::GetSurfaces
            .as_str()
            .to_string(),
        json!({
            "request_id": request_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }),
    )
    .from(
        gateway_listener
            .gateway_did
            .clone(),
    )
    .to(gateway.did.clone())
    .thid(uuid::Uuid::new_v4().to_string())
    .finalize();

    // Pre-resolve and cache the gateway DID (best-effort).
    let did_cache = listener_mgr.get_did_cache();
    let tdk_state = gateway_listener
        .client
        .atm()
        .get_tdk();
    if let Err(e) = did_cache
        .resolve_and_cache_for_atm(&gateway.did, tdk_state)
        .await
    {
        warn!("[{request_id}] Failed to pre-resolve gateway DID: {e}. Continuing anyway.");
    }

    gateway_listener
        .client
        .pack_and_send_message(&get_channels_message, &gateway.did, &gateway_listener.gateway_did)
        .await
        .map_err(|e| {
            DiscoveryFailure::hard(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send get-channels: {e}"))
        })?;

    // Wait for get-channels-response via WebSocket (5s timeout).
    let response = gateway_listener
        .client
        .atm()
        .message_pickup()
        .live_stream_get(
            gateway_listener
                .client
                .profile(),
            &get_channels_message.id,
            SURFACES_RESPONSE_TIMEOUT,
            true, // auto_delete
        )
        .await;

    match response {
        Ok(Some((response_msg, _metadata))) => {
            if response_msg.typ == MessageType::GetSurfacesResponse.as_str() {
                let channels: Vec<SurfaceInfo> = response_msg
                    .body
                    .get("channels")
                    .and_then(|arr| {
                        serde_json::from_value::<Vec<SurfaceInfo>>(arr.clone())
                            .map_err(|e| warn!("[{request_id}] Failed to parse channels from response: {e}"))
                            .ok()
                    })
                    .unwrap_or_default();
                cache
                    .set(gateway_id.to_string(), channels.clone())
                    .await;
                Ok(channels)
            } else {
                Err(DiscoveryFailure::soft(
                    StatusCode::BAD_GATEWAY,
                    format!("Received unexpected message type: {}", response_msg.typ),
                ))
            }
        }
        Ok(None) => {
            cache
                .set_error(gateway_id.to_string(), "Request timed out".to_string())
                .await;
            Err(DiscoveryFailure::soft(StatusCode::GATEWAY_TIMEOUT, "Request timed out - gateway did not respond"))
        }
        Err(e) => {
            cache
                .set_error(gateway_id.to_string(), format!("Request failed: {e:?}"))
                .await;
            Err(DiscoveryFailure::soft(StatusCode::BAD_GATEWAY, format!("Request failed: {e:?}")))
        }
    }
}

/// Query available channels from a remote gateway.
pub async fn get_gateway_surfaces<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    Extension(cache): Extension<Arc<GatewaySurfaceCache>>,
    Path(gateway_id): Path<String>,
    Query(query): Query<GetGatewaySurfacesQuery>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<GetGatewaySurfacesResponse>, (StatusCode, String)> {
    let gateway = store
        .get(&gateway_id)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
    }
    match discover_gateway_surfaces(&store, &listener_manager, &cache, &gateway_id, query.force_refresh).await {
        Ok(channels) => Ok(Json(GetGatewaySurfacesResponse {
            success: true,
            channels,
            message: None,
        })),
        // Timeout / unexpected reply were historically served as 200 {success:false}.
        Err(f) if f.soft => Ok(Json(GetGatewaySurfacesResponse {
            success: false,
            channels: Vec::new(),
            message: Some(f.message),
        })),
        Err(f) => Err((f.status, f.message)),
    }
}

/// A connected remote gateway that exposes at least one payment surface,
/// together with those surfaces. Returned by [`list_payment_gateways`].
#[derive(Debug, Serialize)]
pub struct PaymentGatewayInfo {
    pub id: String,
    pub name: String,
    pub payment_surfaces: Vec<SurfaceInfo>,
}

/// A discovered surface is a payment delegation target when the remote marks it
/// as a payment surface (`is_payment_surface == true`), or exposes it through a
/// connection point the operator tagged `payment` (fallback for peers that
/// predate the authoritative flag).
fn is_payment_target(surface: &SurfaceInfo) -> bool {
    surface.is_payment_surface == Some(true)
        || surface
            .tags
            .iter()
            .any(|t| t == "payment")
}

/// List connected user-created remote gateways that expose at least one payment
/// surface, together with those surfaces. Server-side replacement for the
/// delegated payment picker's per-gateway discovery fan-out: the gateway does
/// the (cached, concurrent) discovery and filtering so the client makes a
/// single request. Unreachable gateways, and gateways exposing no payment
/// surface, are omitted.
pub async fn list_payment_gateways<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    Extension(cache): Extension<Arc<GatewaySurfaceCache>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<PaymentGatewayInfo>>, (StatusCode, String)> {
    let gateways = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list gateways: {e}")))?;

    // Only user-created remote gateways are delegation candidates (mirrors the
    // client's `gateway_type == 'remote' && creation_type == 'user'` filter).
    let candidates: Vec<Gateway> = gateways
        .into_iter()
        .filter(|g| {
            g.gateway_type == GatewayType::Remote
                && g.creation_type == crate::gateways::types::GatewayCreationType::User
                && gateway_allowed(g, &context, &scope)
        })
        .collect();

    // Discover each candidate concurrently, reusing the 5-minute cache. A
    // disconnected gateway fails fast (no active listener) and is skipped.
    let discovered = futures::future::join_all(
        candidates
            .into_iter()
            .map(|gw| {
                let store = store.clone();
                let listener_manager = listener_manager.clone();
                let cache = cache.clone();
                async move {
                    let surfaces = discover_gateway_surfaces(&store, &listener_manager, &cache, &gw.id, false)
                        .await
                        .unwrap_or_default();
                    (gw, surfaces)
                }
            }),
    )
    .await;

    let providers: Vec<PaymentGatewayInfo> = discovered
        .into_iter()
        .filter_map(|(gw, surfaces)| {
            let payment_surfaces: Vec<SurfaceInfo> = surfaces
                .into_iter()
                .filter(is_payment_target)
                .collect();
            if payment_surfaces.is_empty() {
                None
            } else {
                Some(PaymentGatewayInfo {
                    id: gw.id,
                    name: gw.name,
                    payment_surfaces,
                })
            }
        })
        .collect();

    Ok(Json(providers))
}

/// Refresh channel cache for all connected gateways
/// This queries all gateways that have active WebSocket connections
pub async fn refresh_gateway_surfaces_cache<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    Extension(cache): Extension<Arc<GatewaySurfaceCache>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    const COOLDOWN_SECONDS: i64 = 5;

    // Check cooldown first - prevent refreshes within 5 seconds of last refresh
    if !cache
        .can_refresh(COOLDOWN_SECONDS)
        .await
    {
        debug!("⏱️ Gateway channel cache refresh in cooldown period ({}s), skipping", COOLDOWN_SECONDS);
        return Ok(Json(serde_json::json!({
            "success": true,
            "message": "Refresh in cooldown period",
            "refreshed": [],
            "skipped": [],
            "failed": []
        })));
    }

    // Try to acquire the refresh lock
    let acquired = cache.try_acquire_refresh_lock();
    debug!("🔐 Refresh lock acquisition attempt: acquired={}", acquired);

    if !acquired {
        debug!("⏭️ Gateway channel cache refresh already in progress, skipping");
        return Ok(Json(serde_json::json!({
            "success": true,
            "message": "Refresh already in progress",
            "refreshed": [],
            "skipped": [],
            "failed": []
        })));
    }

    // Ensure lock is released when function exits
    let cache_clone = cache.clone();
    let _guard = scopeguard::guard((), move |_| {
        debug!("🔓 Releasing refresh lock");
        tokio::spawn(async move {
            cache_clone
                .release_refresh_lock()
                .await;
        });
    });

    info!("🔄 Refreshing gateway channel cache for all connected gateways");

    let listener_mgr = listener_manager
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()))?;

    // Get all gateways
    let gateways = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list gateways: {}", e)))?;

    let mut refreshed = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();

    for gateway in gateways {
        if !gateway_allowed(&gateway, &context, &scope) {
            continue;
        }
        // Skip self-gateway
        if gateway.gateway_type == GatewayType::SelfGateway {
            skipped.push(gateway.id.clone());
            continue;
        }

        // Check if gateway has active listener (is connected)
        if listener_mgr
            .get_listener(&gateway.id)
            .await
            .is_none()
        {
            debug!("Skipping gateway {} - not connected", gateway.name);
            skipped.push(gateway.id.clone());
            continue;
        }

        // Query channels for this gateway
        debug!("Querying channels for gateway {}", gateway.name);

        // Call get_gateway_channels but force refresh by clearing cache first
        cache.clear(&gateway.id).await;

        // Make a recursive call to get_gateway_channels (it will query and cache)
        match get_gateway_surfaces(
            Extension(store.clone()),
            Extension(Some(listener_mgr.clone())),
            Extension(cache.clone()),
            Path(gateway.id.clone()),
            Query(GetGatewaySurfacesQuery { force_refresh: true }),
            context.clone(),
            scope.clone(),
        )
        .await
        {
            Ok(response) => {
                if response.0.success {
                    refreshed.push(gateway.id.clone());
                    debug!("✓ Refreshed {} channels for gateway {}", response.0.channels.len(), gateway.name);
                } else {
                    failed.push(gateway.id.clone());
                    debug!("✗ Failed to refresh channels for gateway {}: {:?}", gateway.name, response.0.message);
                }
            }
            Err(e) => {
                failed.push(gateway.id.clone());
                warn!("✗ Error refreshing channels for gateway {}: {:?}", gateway.name, e);
            }
        }
    }

    info!(
        "✓ Cache refresh complete: {} refreshed, {} skipped, {} failed",
        refreshed.len(),
        skipped.len(),
        failed.len()
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "refreshed": refreshed,
        "skipped": skipped,
        "failed": failed,
    })))
}

/// Get gateway configuration (serves gateway.json)
pub async fn get_gateway_config(
    Extension(bootstrap_config): Extension<Arc<crate::config::BootstrapConfig>>
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Read gateway.json file from configured path
    let config_path = std::path::Path::new(
        &bootstrap_config
            .config_files
            .gateway,
    );

    let config_content = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read gateway config from {}: {}", config_path.display(), e),
            )
        })?;

    let config: serde_json::Value = serde_json::from_str(&config_content)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse gateway config: {}", e)))?;

    Ok(Json(config))
}
