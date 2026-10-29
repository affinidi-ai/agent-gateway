use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

/// Timeout for the final preflight check confirming the reconnected WebSocket is usable.
const RECONNECT_READINESS_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

use super::TrustRegistryStore;
use super::communication::TrustRegistryListenerManager;
use super::did_manager::DidMethod;
use super::types::{
    TrustRegistry, TrustRegistryConnectionStatus, TrustRegistryListRecordsResponse, TrustRegistryStatus,
};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};

/// Request body for creating a trust registry
#[derive(Debug, Deserialize)]
pub struct CreateTrustRegistryRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    /// OOB invitation URL from the trust registry's connection point
    pub oob_url: String,
    /// DID method for the per-registry identity (defaults to "web")
    pub did_method: Option<DidMethod>,
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

fn registry_allowed(
    registry: &TrustRegistry,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(registry.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::TrustRegistries,
            &registry.id,
        )
}

/// May this caller change or delete the trust registry? Requires [`can_mutate`]
/// ownership and a resource scope that matches the trust registry id.
fn registry_writable(
    registry: &TrustRegistry,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_mutate(registry.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::TrustRegistries,
            &registry.id,
        )
}

/// Request body for updating a trust registry
#[derive(Debug, Deserialize)]
pub struct UpdateTrustRegistryRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<TrustRegistryStatus>,
    pub main_did: Option<String>,
}

/// List all trust registries
pub async fn list_trust_registries<S: TrustRegistryStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<TrustRegistry>>, (StatusCode, String)> {
    let mut trust_registries = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list trust registries: {}", e)))?;
    trust_registries.retain(|registry| registry_allowed(registry, &context, &scope));

    Ok(Json(trust_registries))
}

/// Get a trust registry by ID
pub async fn get_trust_registry<S: TrustRegistryStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<TrustRegistry>, (StatusCode, String)> {
    let trust_registry = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get trust registry: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Trust registry not found".to_string()))?;
    if !registry_allowed(&trust_registry, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Trust registry not found".to_string()));
    }

    Ok(Json(trust_registry))
}

/// Writes `trust_registry` only while its record still exists, so a write racing a
/// delete never brings the record back.
async fn update_existing<S: TrustRegistryStore + ?Sized>(
    store: &S,
    trust_registry: &TrustRegistry,
) -> Result<(), anyhow::Error> {
    if store
        .update_if_exists(trust_registry)
        .await?
    {
        Ok(())
    } else {
        Err(anyhow::anyhow!("trust registry '{}' was deleted", trust_registry.id))
    }
}

/// Saves `trust_registry` on its own task, so a cancelled request cannot report the DID
/// it announced as failed while the record is written, and reports it `created` once the
/// record, which now names that DID, is stored.
async fn save_announced<S: TrustRegistryStore + 'static>(
    store: &Arc<S>,
    trust_registry: &TrustRegistry,
    announcement: crate::event_hook::CreationGuard,
) -> Result<(), anyhow::Error> {
    let (Some(our_did), Some(mediator_did)) = (&trust_registry.our_did, &trust_registry.mediator_did) else {
        return update_existing(store.as_ref(), trust_registry).await;
    };
    let saved = super::communication::trust_registry_payload(&trust_registry.id, mediator_did, our_did);
    let record = trust_registry.clone();
    let store = store.clone();
    tokio::spawn(async move {
        announcement
            .complete(async move { update_existing(store.as_ref(), &record).await }, saved)
            .await
    })
    .await
    .map_err(|e| anyhow::anyhow!("the save task failed: {e}"))?
}

/// Records an accepted OOB invitation on `trust_registry`, which is then
/// Connecting until the registry approves it, and returns the announcement of
/// its new DID for the save.
fn record_oob_connection(
    trust_registry: &mut TrustRegistry,
    connection_info: super::communication::OobConnectionInfo,
) -> crate::event_hook::CreationGuard {
    trust_registry.our_did = Some(connection_info.our_did);
    trust_registry.registry_did = Some(
        connection_info
            .registry_did
            .clone(),
    );
    trust_registry.did = Some(connection_info.registry_did);
    trust_registry.main_did = connection_info.main_did;
    trust_registry.mediator_url = Some(connection_info.mediator_url);
    trust_registry.mediator_did = Some(connection_info.mediator_did);
    trust_registry.connection_status = TrustRegistryConnectionStatus::Connecting;
    trust_registry.updated_at = chrono::Utc::now();
    connection_info.announcement
}

/// The status a successful reconnect stores, when it changes one: rebuilding the
/// transport says nothing about the registry's approval, so only Failed moves.
fn status_after_reconnect(status: &TrustRegistryConnectionStatus) -> Option<TrustRegistryConnectionStatus> {
    (*status == TrustRegistryConnectionStatus::Failed).then_some(TrustRegistryConnectionStatus::Connected)
}

/// The response for a trust registry connection request on a Standby node.
fn standby_refusal() -> (StatusCode, String) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "This node is in Standby; connect trust registries on the Active node".to_string(),
    )
}

/// Create a new trust registry
pub async fn create_trust_registry<S: TrustRegistryStore + 'static>(
    Extension(store): Extension<std::sync::Arc<S>>,
    listener_manager: Option<Extension<Arc<TrustRegistryListenerManager>>>,
    worker: Option<Extension<Arc<super::TrustRegistryWorker>>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(ws_state): Extension<Option<Arc<crate::server::websocket::WsState>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateTrustRegistryRequest>,
) -> Result<Json<TrustRegistry>, (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    crate::config::enforce_add("connections.trustregistries")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;

    // Create the trust registry object with Connecting status
    let did_method = req
        .did_method
        .unwrap_or_default();
    let mut trust_registry = TrustRegistry::new(req.name, req.description, req.oob_url, did_method);
    trust_registry.tenant_id = req.tenant_id;
    if !registry_writable(&trust_registry, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Trust registry is outside this token's permitted scope".into()));
    }
    if listener_manager
        .as_ref()
        .is_some_and(|Extension(manager)| !manager.is_active())
    {
        return Err(standby_refusal());
    }

    // Store the trust registry first
    store
        .create(&trust_registry)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store trust registry: {}", e)))?;

    // Attempt OOB connection if listener_manager is available
    if let Some(Extension(listener_mgr)) = listener_manager {
        match listener_mgr
            .accept_oob_and_connect(&trust_registry.id, &trust_registry.oob_url, &trust_registry.did_method)
            .await
        {
            Ok(connection_info) => {
                let announcement = record_oob_connection(&mut trust_registry, connection_info);

                // Update store with connection info
                if let Err(e) = save_announced(&store, &trust_registry, announcement).await {
                    listener_mgr
                        .remove_connection(&trust_registry.id)
                        .await;
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update trust registry: {}", e)));
                }

                // Start background listener for connection protocol messages
                if let (Some(Extension(w)), Some(ws)) = (&worker, &ws_state) {
                    w.start_listener(&trust_registry, store.clone(), (**ws).clone())
                        .await;
                }
            }
            Err(e) => {
                tracing::error!("OOB connection failed for trust registry '{}': {}", trust_registry.id, e);
                // Update status to Failed
                trust_registry.connection_status = TrustRegistryConnectionStatus::Failed;
                trust_registry.updated_at = chrono::Utc::now();
                let _ = store
                    .update_if_exists(&trust_registry)
                    .await;
                return Err((StatusCode::BAD_GATEWAY, format!("OOB connection failed: {}", e)));
            }
        }
    } else {
        tracing::warn!(
            "Trust registry '{}' created without connection (listener manager not available)",
            trust_registry.name
        );
        trust_registry.connection_status = TrustRegistryConnectionStatus::Failed;
        trust_registry.updated_at = chrono::Utc::now();
        let _ = store
            .update_if_exists(&trust_registry)
            .await;
    }

    // Trigger integration event
    if let Some(notif_store) = notification_store {
        let trigger_registry = build_trigger_registry(&trust_registry);
        tokio::spawn(async move {
            crate::integrations::trigger_trust_registry_created(&notif_store, &trigger_registry).await;
        });
    }

    Ok(Json(trust_registry))
}

/// Update a trust registry
pub async fn update_trust_registry<S: TrustRegistryStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateTrustRegistryRequest>,
) -> Result<Json<TrustRegistry>, (StatusCode, String)> {
    let mut trust_registry = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get trust registry: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Trust registry not found".to_string()))?;
    if !registry_allowed(&trust_registry, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Trust registry not found".to_string()));
    }
    if !registry_writable(&trust_registry, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Trust registry is outside this token's permitted scope".into()));
    }

    // Capture old state
    let old_status = trust_registry.status.clone();
    let old_registry = build_trigger_registry(&trust_registry);

    if let Some(name) = req.name {
        trust_registry.name = name;
    }
    if let Some(description) = req.description {
        trust_registry.description = description;
    }
    if let Some(status) = req.status {
        trust_registry.status = status;
    }
    if let Some(main_did) = req.main_did {
        trust_registry.main_did = Some(main_did);
    }

    trust_registry.updated_at = chrono::Utc::now();

    let written = store
        .update_if_exists(&trust_registry)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update trust registry: {}", e)))?;
    if !written {
        return Err((StatusCode::NOT_FOUND, "Trust registry not found".to_string()));
    }

    // Trigger integration events
    let new_registry = build_trigger_registry(&trust_registry);
    if let Some(store) = notification_store {
        crate::integrations::trigger_trust_registry_updated(&store, &old_registry, &new_registry).await;

        // Trigger status change event if status changed
        if old_status != trust_registry.status {
            crate::integrations::trigger_trust_registry_status_changed(&store, &old_registry, &new_registry).await;
        }
    }

    Ok(Json(trust_registry))
}

/// Delete a trust registry
pub async fn delete_trust_registry<S: TrustRegistryStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    listener_manager: Option<Extension<Arc<TrustRegistryListenerManager>>>,
    worker: Option<Extension<Arc<super::TrustRegistryWorker>>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Get trust registry before deletion
    let trust_registry = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get trust registry: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Trust registry not found".to_string()))?;
    if !registry_allowed(&trust_registry, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Trust registry not found".to_string()));
    }
    if !registry_writable(&trust_registry, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Trust registry is outside this token's permitted scope".into()));
    }

    // Stop background worker listener
    if let Some(Extension(ref w)) = worker {
        w.stop_listener(&id).await;
    }

    // Stop owning the registry: no build for it can install a client from here on
    if let Some(Extension(listener_mgr)) = &listener_manager {
        listener_mgr
            .delete_registry(&id)
            .await;
    }

    // A record that survives keeps its keys and can be built again
    if let Err(e) = store.delete(&id).await {
        if let Some(Extension(listener_mgr)) = &listener_manager {
            listener_mgr
                .restore_registry(&id)
                .await;
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete trust registry: {}", e)));
    }

    // Clean up per-registry DID keys from disk
    let keys_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .trust_registries,
    )
    .join(&id);
    if keys_path.exists()
        && let Err(e) = tokio::fs::remove_dir_all(&keys_path).await
    {
        tracing::warn!("Failed to clean up trust registry keys at {:?}: {}", keys_path, e);
    }

    if let Some(Extension(listener_mgr)) = &listener_manager {
        listener_mgr.announce_deleted(&trust_registry);
    }

    // Trigger integration event
    let trigger_registry = build_trigger_registry(&trust_registry);
    if let Some(store) = notification_store {
        crate::integrations::trigger_trust_registry_deleted(&store, &trigger_registry).await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Helper to build a trigger registry struct from a TrustRegistry
fn build_trigger_registry(
    tr: &TrustRegistry
) -> crate::integrations::trust_registry_integration_triggers::TrustRegistry {
    let status_str = match tr.status {
        TrustRegistryStatus::Active => "Active".to_string(),
        TrustRegistryStatus::Disabled => "Disabled".to_string(),
    };
    crate::integrations::trust_registry_integration_triggers::TrustRegistry {
        id: tr.id.clone(),
        name: tr.name.clone(),
        description: tr.description.clone(),
        did: tr
            .did
            .clone()
            .unwrap_or_default(),
        status: status_str,
        created_at: tr.created_at.to_rfc3339(),
        updated_at: tr.updated_at.to_rfc3339(),
    }
}

fn trust_registry_artifact_dir(
    base: &std::path::Path,
    tr_id: &str,
) -> anyhow::Result<std::path::PathBuf> {
    crate::storage::validate_storage_id(tr_id)?;
    let tr_dir = base.join(tr_id);
    crate::storage::assert_within_storage_dir(base, &tr_dir)?;
    Ok(tr_dir)
}

/// Serve DID document for a trust registry's per-registry identity.
///
/// Reads the `did.json` from disk (same pattern as departments).
pub async fn serve_trust_registry_did_document<S: TrustRegistryStore>(
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(_store): Extension<Arc<S>>,
    Path(tr_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let base = std::path::Path::new(
        &config
            .storage_paths
            .trust_registries,
    );
    let tr_dir = match trust_registry_artifact_dir(base, &tr_id) {
        Ok(dir) => dir,
        Err(e) => {
            tracing::warn!(error = %e, trust_registry_id = %tr_id, "Rejected trust registry DID document request");
            return Err((StatusCode::BAD_REQUEST, "Invalid trust registry id".to_string()));
        }
    };

    let did_doc_content = match crate::storage::did_artifacts::read_did_document(&tr_dir).await {
        Ok(Some(content)) => content,
        Ok(None) => {
            return Err((StatusCode::NOT_FOUND, format!("DID document not found for trust registry: {}", tr_id)));
        }
        Err(e) => {
            tracing::warn!("Failed to read DID document for trust registry {}: {}", tr_id, e);
            return Err((StatusCode::NOT_FOUND, format!("DID document not found for trust registry: {}", tr_id)));
        }
    };

    let did_document: serde_json::Value = serde_json::from_str(&did_doc_content).map_err(|e| {
        tracing::error!("Failed to parse DID document for trust registry {}: {}", tr_id, e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Invalid DID document".to_string())
    })?;

    Ok(Json(did_document))
}

/// Serve the verifiable DID log (`did.jsonl`) for a trust registry's did:webvh identity.
///
/// Returns 404 (RFC 9457 problem-details) when the log has not been created yet.
#[cfg(feature = "didwebvh")]
pub async fn serve_trust_registry_did_jsonl<S: TrustRegistryStore>(
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(_store): Extension<Arc<S>>,
    Path(tr_id): Path<String>,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;

    let base = std::path::Path::new(
        &config
            .storage_paths
            .trust_registries,
    );
    let tr_dir = match trust_registry_artifact_dir(base, &tr_id) {
        Ok(dir) => dir,
        Err(e) => {
            tracing::warn!(error = %e, trust_registry_id = %tr_id, "Rejected trust registry DID log request");
            let problem = serde_json::json!({
                "type": "https://identity.foundation/didwebvh/v1.0/#problem-details",
                "title": "invalidDid",
                "status": 400,
                "detail": "Invalid trust registry id"
            });
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/problem+json")],
                problem.to_string(),
            )
                .into_response();
        }
    };

    match crate::storage::did_artifacts::read_did_log_raw(&tr_dir).await {
        Ok(Some(content)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/jsonl"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            content,
        )
            .into_response(),
        Ok(None) => {
            let problem = serde_json::json!({
                "type": "https://identity.foundation/didwebvh/v1.0/#problem-details",
                "title": "notFound",
                "status": 404,
                "detail": format!("DID log not found for trust registry: {}", tr_id)
            });
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/problem+json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                problem.to_string(),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, trust_registry_id = %tr_id, "Failed to read trust registry did.jsonl");
            let problem = serde_json::json!({
                "type": "https://identity.foundation/didwebvh/v1.0/#problem-details",
                "title": "internalError",
                "status": 500,
                "detail": "Failed to read DID log"
            });
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/problem+json")],
                problem.to_string(),
            )
                .into_response()
        }
    }
}

/// Serve an empty `did-witness.json` for a trust registry's did:webvh identity.
///
/// The did:webvh specification requires this file to exist alongside `did.jsonl`.
/// Since trust registry identities don't use witnessing, we return an empty proofs array.
#[cfg(feature = "didwebvh")]
pub async fn serve_trust_registry_did_witness<S: TrustRegistryStore>(
    Extension(_config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(_store): Extension<Arc<S>>,
    Path(_tr_id): Path<String>,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;

    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], "[]")
        .into_response()
}

/// Rebuild a trust registry's connection from its stored keys, so the registry
/// keeps its identity. A failure leaves the stored status unchanged; a success
/// moves a Failed registry back to Connected and keeps any other status.
///
/// A registry whose setup never connected has no identity to keep, so its OOB
/// invitation is accepted again instead, as when it was created.
pub async fn reconnect_trust_registry<S: TrustRegistryStore + 'static>(
    Extension(store): Extension<Arc<S>>,
    listener_manager: Option<Extension<Arc<TrustRegistryListenerManager>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<TrustRegistry>, (StatusCode, String)> {
    let tr = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get trust registry: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Trust registry not found".to_string()))?;
    if !registry_allowed(&tr, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Trust registry not found".to_string()));
    }
    if !registry_writable(&tr, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Trust registry is outside this token's permitted scope".to_string()));
    }

    let Extension(listener_mgr) = listener_manager
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()))?;
    if !listener_mgr.is_active() {
        return Err(standby_refusal());
    }
    if tr.our_did.is_none() {
        return complete_setup(&store, &listener_mgr, tr).await;
    }

    let connection = listener_mgr
        .reconnect(&id)
        .await
        .map_err(|e| {
            tracing::warn!("Reconnect failed for trust registry '{}': {}", id, e);
            (StatusCode::BAD_GATEWAY, format!("Reconnection failed: {}", e))
        })?;

    // enable_websocket() may return before the WS is fully ready.
    super::communication::await_websocket_ready(&connection.client).await;
    if connection
        .client
        .preflight_check(RECONNECT_READINESS_CHECK_TIMEOUT)
        .await
        .is_err()
    {
        tracing::warn!("Reconnected transport not ready for trust registry '{}'", id);
        return Err((StatusCode::BAD_GATEWAY, "Reconnection failed: WebSocket not ready after retries".to_string()));
    }

    let mut current = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get trust registry: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Trust registry not found".to_string()))?;
    if let Some(status) = status_after_reconnect(&current.connection_status) {
        current.connection_status = status;
        current.updated_at = chrono::Utc::now();
        let written = store
            .update_if_exists(&current)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update trust registry: {}", e)))?;
        if !written {
            return Err((StatusCode::NOT_FOUND, "Trust registry not found".to_string()));
        }
    }

    Ok(Json(current))
}

/// Accept the OOB invitation of a registry whose setup never connected and save
/// its new identity. A failure leaves the record unchanged.
async fn complete_setup<S: TrustRegistryStore + 'static>(
    store: &Arc<S>,
    listener_mgr: &Arc<TrustRegistryListenerManager>,
    mut trust_registry: TrustRegistry,
) -> Result<Json<TrustRegistry>, (StatusCode, String)> {
    let connection_info = listener_mgr
        .accept_oob_and_connect(&trust_registry.id, &trust_registry.oob_url, &trust_registry.did_method)
        .await
        .map_err(|e| {
            tracing::warn!("OOB setup retry failed for trust registry '{}': {}", trust_registry.id, e);
            (StatusCode::BAD_GATEWAY, format!("Reconnection failed: OOB connection failed: {}", e))
        })?;
    let announcement = record_oob_connection(&mut trust_registry, connection_info);
    if let Err(e) = save_announced(store, &trust_registry, announcement).await {
        listener_mgr
            .remove_connection(&trust_registry.id)
            .await;
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update trust registry: {}", e)));
    }
    Ok(Json(trust_registry))
}

pub async fn list_trust_registry_records<S: TrustRegistryStore>(
    Extension(store): Extension<Arc<S>>,
    listener_manager: Option<Extension<Arc<TrustRegistryListenerManager>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tr = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get trust registry: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Trust registry not found".to_string()))?;
    if !registry_allowed(&tr, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Trust registry not found".to_string()));
    }

    if tr.connection_status != TrustRegistryConnectionStatus::Connected {
        return Err((StatusCode::CONFLICT, "Trust registry connection is not approved yet".to_string()));
    }

    let registry_did = tr
        .registry_did
        .as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Trust registry has no registry DID".to_string()))?;

    let Extension(listener_mgr) = listener_manager
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()))?;

    let start = std::time::Instant::now();

    let response = listener_mgr
        .list_records(registry_did)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to list records: {}", e)))?;

    let response = TrustRegistryListRecordsResponse::from_list_records(response, start.elapsed().as_millis() as u64);

    serde_json::to_value(&response)
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_manager::pat::PatResourceScope;
    use crate::tenancy::PatTenantContext;
    use regex::Regex;

    #[test]
    fn trust_registry_actions_require_tenant_and_scope_access() {
        let mut registry = TrustRegistry::new(
            "Registry".into(),
            String::new(),
            "https://example.com/oob".into(),
            DidMethod::default(),
        );
        registry.id = "registry-a".into();
        registry.tenant_id = Some("tenant-a".into());
        let context = PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(Regex::new(r"\ATENANT:tenant-a:trust-registries:registry-a\z").unwrap()));

        assert!(registry_allowed(&registry, &Some(Extension(context.clone())), &Some(Extension(scope.clone()))));
        registry.tenant_id = Some("tenant-b".into());
        assert!(!registry_allowed(&registry, &Some(Extension(context)), &Some(Extension(scope))));
    }

    #[test]
    fn trust_registry_artifact_dir_rejects_traversal_and_stays_within_base() {
        let base = tempfile::tempdir().unwrap();
        for tr_id in ["../../etc", "../did.json", "..", ".", "", "/etc/passwd", "a/b", "./x"] {
            assert!(trust_registry_artifact_dir(base.path(), tr_id).is_err(), "{tr_id:?} must be rejected");
        }

        let tr_id = "123e4567-e89b-12d3-a456-426614174000";
        assert_eq!(trust_registry_artifact_dir(base.path(), tr_id).unwrap(), base.path().join(tr_id));

        let still_encoded = trust_registry_artifact_dir(base.path(), "..%2F..%2Fetc").unwrap();
        assert_eq!(still_encoded.parent(), Some(base.path()));
    }

    #[test]
    fn a_tenant_may_read_an_appliance_wide_trust_registry_but_not_change_it() {
        let tenant = Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }));
        let mut record = TrustRegistry::new(
            "Registry".into(),
            String::new(),
            "https://example.com/oob".into(),
            DidMethod::default(),
        );
        record.id = "registry-a".into();
        record.tenant_id = None;
        assert!(registry_allowed(&record, &tenant, &None));
        assert!(!registry_writable(&record, &tenant, &None));
        assert!(registry_writable(&record, &None, &None));

        record.tenant_id = Some("tenant-a".into());
        assert!(registry_writable(&record, &tenant, &None));

        record.tenant_id = Some("tenant-b".into());
        assert!(!registry_writable(&record, &tenant, &None));
    }

    async fn stored_registry(
        tenant_id: Option<&str>
    ) -> (Arc<super::super::FileSystemTrustRegistryStore>, TrustRegistry, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            super::super::FileSystemTrustRegistryStore::new(dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let mut registry = TrustRegistry::new(
            "Operator registry".into(),
            String::new(),
            "https://example.com/oob".into(),
            DidMethod::default(),
        );
        registry.tenant_id = tenant_id.map(str::to_string);
        store
            .create(&registry)
            .await
            .unwrap();
        (store, registry, dir)
    }

    async fn events_of_a_save(deleted_first: bool) -> (bool, Vec<(String, String)>) {
        let (store, mut registry, _dir) = stored_registry(None).await;
        registry.our_did = Some("did:peer:2.new".into());
        registry.mediator_did = Some("did:web:mediator.example".into());
        if deleted_first {
            store
                .delete(&registry.id)
                .await
                .unwrap();
        }

        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let hook = crate::event_hook::EventHook::new(crate::event_hook::EventHookSettings {
            hook_url: Some(url),
            ..crate::event_hook::EventHookSettings::default()
        })
        .unwrap();
        let announcement = crate::event_hook::CreationGuard::start(
            Some(hook),
            super::super::communication::trust_registry_payload(
                &registry.id,
                "did:web:mediator.example",
                "did:peer:2.new",
            ),
        );

        let saved = save_announced(&store, &registry, announcement)
            .await
            .is_ok();

        for _ in 0..100 {
            if captured.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut events: Vec<(u64, String, String)> = captured
            .lock()
            .unwrap()
            .iter()
            .map(|call| {
                let body: serde_json::Value = serde_json::from_str(&call.body).unwrap();
                (
                    body["sequence"]
                        .as_u64()
                        .unwrap(),
                    body["event"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    body["connection_point"]["did"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                )
            })
            .collect();
        events.sort();
        (
            saved,
            events
                .into_iter()
                .map(|(_, event, did)| (event, did))
                .collect(),
        )
    }

    #[tokio::test]
    async fn a_saved_did_is_reported_created() {
        assert_eq!(
            events_of_a_save(false).await,
            (
                true,
                vec![
                    ("connection_point.creation_started".to_string(), "did:peer:2.new".to_string()),
                    ("connection_point.created".to_string(), "did:peer:2.new".to_string()),
                ]
            )
        );
    }

    #[tokio::test]
    async fn saving_a_deleted_registry_writes_nothing_and_reports_creation_failed() {
        assert_eq!(
            events_of_a_save(true).await,
            (
                false,
                vec![
                    ("connection_point.creation_started".to_string(), "did:peer:2.new".to_string()),
                    ("connection_point.creation_failed".to_string(), "did:peer:2.new".to_string()),
                ]
            )
        );
    }

    fn tenant_a() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    fn bootstrap(dir: &tempfile::TempDir) -> Arc<crate::config::BootstrapConfig> {
        Arc::new(
            toml::from_str(&format!(
                "backup_encryption_key = \"env://UNUSED\"\n[tls]\ncert_path = \"cert.pem\"\nkey_path = \"key.pem\"\n[storage_paths]\ntrust_registries = \"{}\"\n",
                dir.path()
                    .join("keys")
                    .display()
            ))
            .unwrap(),
        )
    }

    async fn delete_as_tenant_a(
        store: &Arc<super::super::FileSystemTrustRegistryStore>,
        dir: &tempfile::TempDir,
        id: &str,
    ) -> StatusCode {
        match delete_trust_registry(
            Extension(store.clone()),
            None,
            None,
            Extension(None),
            Extension(bootstrap(dir)),
            Path(id.to_string()),
            tenant_a(),
            None,
        )
        .await
        {
            Ok(status) => status,
            Err((status, _)) => status,
        }
    }

    fn rename() -> Json<UpdateTrustRegistryRequest> {
        Json(UpdateTrustRegistryRequest {
            name: Some("Tenant registry".into()),
            description: None,
            status: None,
            main_did: None,
        })
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_update_reconnect_or_delete_an_appliance_wide_registry() {
        let (store, registry, dir) = stored_registry(None).await;

        let Json(read) = get_trust_registry(Extension(store.clone()), Path(registry.id.clone()), tenant_a(), None)
            .await
            .unwrap();
        assert_eq!(read.name, "Operator registry");

        let update = update_trust_registry(
            Extension(store.clone()),
            Extension(None),
            Path(registry.id.clone()),
            tenant_a(),
            None,
            rename(),
        )
        .await;
        assert_eq!(
            update
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::FORBIDDEN)
        );

        let reconnect =
            reconnect_trust_registry(Extension(store.clone()), None, Path(registry.id.clone()), tenant_a(), None).await;
        assert_eq!(
            reconnect
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(delete_as_tenant_a(&store, &dir, &registry.id).await, StatusCode::FORBIDDEN);

        let after = store
            .get(&registry.id)
            .await
            .unwrap()
            .expect("appliance-wide registry must survive");
        assert_eq!(after.name, "Operator registry");
        assert_eq!(after.updated_at, registry.updated_at);
    }

    #[tokio::test]
    async fn another_tenants_registry_is_not_found_on_update_reconnect_or_delete() {
        let (store, registry, dir) = stored_registry(Some("tenant-b")).await;

        let update = update_trust_registry(
            Extension(store.clone()),
            Extension(None),
            Path(registry.id.clone()),
            tenant_a(),
            None,
            rename(),
        )
        .await;
        assert_eq!(
            update
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::NOT_FOUND)
        );

        let reconnect =
            reconnect_trust_registry(Extension(store.clone()), None, Path(registry.id.clone()), tenant_a(), None).await;
        assert_eq!(
            reconnect
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::NOT_FOUND)
        );
        assert_eq!(delete_as_tenant_a(&store, &dir, &registry.id).await, StatusCode::NOT_FOUND);

        let after = store
            .get(&registry.id)
            .await
            .unwrap()
            .expect("another tenant's registry must survive");
        assert_eq!(after.name, "Operator registry");
        assert_eq!(after.updated_at, registry.updated_at);
    }

    #[tokio::test]
    async fn a_tenant_token_can_update_and_delete_its_own_registry() {
        let (store, registry, dir) = stored_registry(Some("tenant-a")).await;

        let Json(updated) = update_trust_registry(
            Extension(store.clone()),
            Extension(None),
            Path(registry.id.clone()),
            tenant_a(),
            None,
            rename(),
        )
        .await
        .unwrap();
        assert_eq!(updated.name, "Tenant registry");
        assert_eq!(
            store
                .get(&registry.id)
                .await
                .unwrap()
                .map(|r| r.name),
            Some("Tenant registry".to_string())
        );
        assert_eq!(delete_as_tenant_a(&store, &dir, &registry.id).await, StatusCode::NO_CONTENT);
        assert!(
            store
                .get(&registry.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    fn standby_manager(dir: &tempfile::TempDir) -> Arc<TrustRegistryListenerManager> {
        let manager = TrustRegistryListenerManager::with_retry_policy(
            "example.com".into(),
            dir.path().join("keys"),
            None,
            crate::comm::connection_health::ReconnectPolicy::default(),
        );
        manager.deactivate();
        manager
    }

    #[tokio::test]
    async fn a_standby_node_refuses_to_create_a_registry_and_stores_nothing() {
        let (store, _registry, dir) = stored_registry(None).await;
        let before = store
            .list_all()
            .await
            .unwrap()
            .len();

        let result = create_trust_registry(
            Extension(store.clone()),
            Some(Extension(standby_manager(&dir))),
            None,
            Extension(None),
            Extension(None),
            None,
            None,
            None,
            Json(CreateTrustRegistryRequest {
                tenant_id: None,
                name: "New registry".into(),
                description: String::new(),
                oob_url: "https://example.com/oob".into(),
                did_method: None,
            }),
        )
        .await;

        assert_eq!(
            result
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(
            store
                .list_all()
                .await
                .unwrap()
                .len(),
            before,
            "no record is stored"
        );
    }

    #[tokio::test]
    async fn a_standby_node_refuses_to_reconnect_and_writes_nothing() {
        let (store, mut registry, dir) = stored_registry(None).await;
        registry.connection_status = TrustRegistryConnectionStatus::Failed;
        assert!(
            store
                .update_if_exists(&registry)
                .await
                .unwrap()
        );

        let result = reconnect_trust_registry(
            Extension(store.clone()),
            Some(Extension(standby_manager(&dir))),
            Path(registry.id.clone()),
            None,
            None,
        )
        .await;

        assert_eq!(
            result
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(
            store
                .get(&registry.id)
                .await
                .unwrap()
                .unwrap()
                .connection_status,
            TrustRegistryConnectionStatus::Failed
        );
    }

    #[tokio::test]
    async fn a_failed_reconnect_keeps_the_status_and_identity() {
        let (store, mut registry, dir) = stored_registry(None).await;
        registry.our_did = Some("did:example:gateway".into());
        registry.registry_did = Some(format!("did:example:registry-{}", registry.id));
        registry.mediator_did = Some("did:example:mediator".into());
        registry.connection_status = TrustRegistryConnectionStatus::Connected;
        assert!(
            store
                .update_if_exists(&registry)
                .await
                .unwrap()
        );
        let manager = TrustRegistryListenerManager::with_retry_policy(
            "example.com".into(),
            dir.path().join("keys"),
            None,
            crate::comm::connection_health::ReconnectPolicy::default(),
        );
        manager
            .set_store(store.clone())
            .await;
        crate::trust_registries::test_builds::install(
            &registry.id,
            vec![crate::trust_registries::test_builds::Outcome::Fail("mediator unreachable".into())],
        );

        let result = reconnect_trust_registry(
            Extension(store.clone()),
            Some(Extension(manager)),
            Path(registry.id.clone()),
            None,
            None,
        )
        .await;

        let (status, message) = result.expect_err("the rebuild fails");
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(message.contains("mediator unreachable"), "the cause is reported: {message}");
        let stored = store
            .get(&registry.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.connection_status, TrustRegistryConnectionStatus::Connected);
        assert_eq!(stored.our_did, registry.our_did);
        assert_eq!(stored.registry_did, registry.registry_did);
    }

    #[test]
    fn a_successful_reconnect_moves_only_a_failed_registry_to_connected() {
        for (before, after) in [
            (TrustRegistryConnectionStatus::Failed, Some(TrustRegistryConnectionStatus::Connected)),
            (TrustRegistryConnectionStatus::Connected, None),
            (TrustRegistryConnectionStatus::AwaitingApproval, None),
            (TrustRegistryConnectionStatus::Connecting, None),
        ] {
            assert_eq!(status_after_reconnect(&before), after, "for {before:?}");
        }
    }

    #[tokio::test]
    async fn updating_a_deleted_registry_returns_not_found_and_writes_nothing() {
        let (store, registry, _dir) = stored_registry(None).await;
        store
            .delete(&registry.id)
            .await
            .unwrap();

        let result = update_trust_registry(
            Extension(store.clone()),
            Extension(None),
            Path(registry.id.clone()),
            None,
            None,
            rename(),
        )
        .await;

        assert_eq!(
            result
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::NOT_FOUND)
        );
        assert!(
            store
                .get(&registry.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    async fn never_connected_registry() -> (
        Arc<super::super::FileSystemTrustRegistryStore>,
        TrustRegistry,
        Arc<TrustRegistryListenerManager>,
        tempfile::TempDir,
    ) {
        let (store, mut registry, dir) = stored_registry(None).await;
        registry.connection_status = TrustRegistryConnectionStatus::Failed;
        assert!(
            store
                .update_if_exists(&registry)
                .await
                .unwrap()
        );
        let manager = TrustRegistryListenerManager::with_retry_policy(
            "example.com".into(),
            dir.path().join("keys"),
            None,
            crate::comm::connection_health::ReconnectPolicy::default(),
        );
        manager
            .set_store(store.clone())
            .await;
        (store, registry, manager, dir)
    }

    /// A store whose deletes fail, so a delete leaves the record in place.
    struct UndeletableStore(Arc<super::super::FileSystemTrustRegistryStore>);

    #[async_trait::async_trait]
    impl TrustRegistryStore for UndeletableStore {
        async fn create(
            &self,
            trust_registry: &TrustRegistry,
        ) -> anyhow::Result<()> {
            self.0
                .create(trust_registry)
                .await
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<TrustRegistry>> {
            self.0.get(id).await
        }

        async fn get_by_did(
            &self,
            did: &str,
        ) -> anyhow::Result<Option<TrustRegistry>> {
            self.0.get_by_did(did).await
        }

        async fn list_all(&self) -> anyhow::Result<Vec<TrustRegistry>> {
            self.0.list_all().await
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("the disk is read-only"))
        }

        async fn update_if_exists(
            &self,
            trust_registry: &TrustRegistry,
        ) -> anyhow::Result<bool> {
            self.0
                .update_if_exists(trust_registry)
                .await
        }
    }

    #[tokio::test]
    async fn a_failed_delete_keeps_the_keys_and_the_registry_can_still_connect() {
        let (store, registry, manager, dir) = never_connected_registry().await;
        let keys = dir
            .path()
            .join("keys")
            .join(&registry.id);
        std::fs::create_dir_all(&keys).unwrap();

        let deleted = delete_trust_registry(
            Extension(Arc::new(UndeletableStore(store.clone()))),
            Some(Extension(manager.clone())),
            None,
            Extension(None),
            Extension(bootstrap(&dir)),
            Path(registry.id.clone()),
            None,
            None,
        )
        .await;

        assert_eq!(
            deleted
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert!(keys.exists(), "the surviving record keeps its keys");
        crate::trust_registries::test_builds::install(
            &registry.id,
            vec![crate::trust_registries::test_builds::Outcome::Connect],
        );
        let Json(reconnected) = reconnect_trust_registry(
            Extension(store.clone()),
            Some(Extension(manager)),
            Path(registry.id.clone()),
            None,
            None,
        )
        .await
        .expect("the registry is owned again");
        assert_eq!(reconnected.connection_status, TrustRegistryConnectionStatus::Connecting);
    }

    #[tokio::test]
    async fn reconnect_completes_the_setup_of_a_registry_that_never_connected() {
        let (store, registry, manager, _dir) = never_connected_registry().await;
        crate::trust_registries::test_builds::install(
            &registry.id,
            vec![crate::trust_registries::test_builds::Outcome::Connect],
        );

        let Json(reconnected) = reconnect_trust_registry(
            Extension(store.clone()),
            Some(Extension(manager)),
            Path(registry.id.clone()),
            None,
            None,
        )
        .await
        .expect("the setup completes");

        let expected_did = Some(format!("did:example:gateway-{}", registry.id));
        assert_eq!(reconnected.connection_status, TrustRegistryConnectionStatus::Connecting);
        assert_eq!(reconnected.our_did, expected_did);
        let stored = store
            .get(&registry.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.connection_status, TrustRegistryConnectionStatus::Connecting);
        assert_eq!(stored.our_did, expected_did);
        assert_eq!(stored.mediator_url.as_deref(), Some("https://mediator.example"));
    }

    #[tokio::test]
    async fn a_failed_setup_retry_leaves_the_record_unchanged() {
        let (store, registry, manager, _dir) = never_connected_registry().await;
        crate::trust_registries::test_builds::install(
            &registry.id,
            vec![crate::trust_registries::test_builds::Outcome::Fail("registry unreachable".into())],
        );

        let (status, message) = reconnect_trust_registry(
            Extension(store.clone()),
            Some(Extension(manager)),
            Path(registry.id.clone()),
            None,
            None,
        )
        .await
        .expect_err("the setup fails");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(message.contains("OOB connection failed"), "the OOB invitation was retried: {message}");
        let stored = store
            .get(&registry.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.connection_status, TrustRegistryConnectionStatus::Failed);
        assert_eq!(stored.our_did, None);
    }
}
