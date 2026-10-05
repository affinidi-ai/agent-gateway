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
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

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
    if !registry_allowed(&trust_registry, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Trust registry is outside this token's permitted scope".into()));
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

                // Update store with connection info
                store
                    .update(&trust_registry)
                    .await
                    .map_err(|e| {
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update trust registry: {}", e))
                    })?;

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
                    .update(&trust_registry)
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
            .update(&trust_registry)
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

    store
        .update(&trust_registry)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update trust registry: {}", e)))?;

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
        return Err((StatusCode::FORBIDDEN, "Trust registry is outside this token's permitted scope".into()));
    }

    // Stop background worker listener
    if let Some(Extension(ref w)) = worker {
        w.stop_listener(&id).await;
    }

    // Stop connection and clean up listener
    if let Some(Extension(listener_mgr)) = listener_manager {
        listener_mgr
            .remove_connection(&id)
            .await;
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

    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete trust registry: {}", e)))?;

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

pub async fn reconnect_trust_registry<S: TrustRegistryStore + 'static>(
    Extension(store): Extension<Arc<S>>,
    listener_manager: Option<Extension<Arc<TrustRegistryListenerManager>>>,
    worker: Option<Extension<Arc<super::TrustRegistryWorker>>>,
    Extension(ws_state): Extension<Option<Arc<crate::server::websocket::WsState>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<TrustRegistry>, (StatusCode, String)> {
    let mut tr = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get trust registry: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Trust registry not found".to_string()))?;
    if !registry_allowed(&tr, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Trust registry is outside this token's permitted scope".to_string()));
    }

    let Extension(listener_mgr) = listener_manager
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()))?;

    // If we have stored connection details, try reconnect from persisted state
    if let (Some(our_did), Some(registry_did), Some(mediator_did)) =
        (tr.our_did.as_deref(), tr.registry_did.as_deref(), tr.mediator_did.as_deref())
    {
        match listener_mgr
            .reconnect(&id, our_did, registry_did, mediator_did, tr.main_did.clone())
            .await
        {
            Ok(()) => {
                // enable_websocket() may return before the WS is fully ready.
                let conn_ready = if let Some(conn) = listener_mgr
                    .get_connection_clone(&id)
                    .await
                {
                    super::communication::await_websocket_ready(&conn.client).await;
                    conn.client
                        .preflight_check(RECONNECT_READINESS_CHECK_TIMEOUT)
                        .await
                        .is_ok()
                } else {
                    false
                };

                if !conn_ready {
                    tracing::error!("Persisted-state reconnect transport not ready for '{}'; failing reconnect", id);
                    tr.connection_status = TrustRegistryConnectionStatus::Failed;
                    let _ = store.update(&tr).await;
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        "Reconnection failed: WebSocket not ready after retries".to_string(),
                    ));
                }

                tr.connection_status = TrustRegistryConnectionStatus::Connected;
                tr.updated_at = chrono::Utc::now();
                store
                    .update(&tr)
                    .await
                    .map_err(|e| {
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update trust registry: {}", e))
                    })?;

                if let (Some(Extension(w)), Some(ws)) = (&worker, &ws_state) {
                    w.start_listener(&tr, store.clone(), (**ws).clone())
                        .await;
                }

                return Ok(Json(tr));
            }
            Err(e) => {
                tracing::warn!("Reconnect from persisted state failed for '{}': {}, retrying via OOB", id, e);
            }
        }
    }

    // Fall back to full OOB re-connection
    match listener_mgr
        .accept_oob_and_connect(&id, &tr.oob_url, &tr.did_method)
        .await
    {
        Ok(connection_info) => {
            tr.our_did = Some(connection_info.our_did);
            tr.registry_did = Some(
                connection_info
                    .registry_did
                    .clone(),
            );
            tr.did = Some(connection_info.registry_did);
            tr.main_did = connection_info.main_did;
            tr.mediator_url = Some(connection_info.mediator_url);
            tr.mediator_did = Some(connection_info.mediator_did);
            tr.updated_at = chrono::Utc::now();

            // Wait for WS readiness; fail rather than persisting a terminal Connecting state
            // that the reader will never promote (already-approved TR won't re-send setup/approved).
            let conn_ready = if let Some(conn) = listener_mgr
                .get_connection_clone(&id)
                .await
            {
                super::communication::await_websocket_ready(&conn.client).await;
                conn.client
                    .preflight_check(RECONNECT_READINESS_CHECK_TIMEOUT)
                    .await
                    .is_ok()
            } else {
                false
            };

            if !conn_ready {
                tracing::error!("OOB reconnection transport not ready for '{}'; failing reconnect", id);
                tr.connection_status = TrustRegistryConnectionStatus::Failed;
                let _ = store.update(&tr).await;
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "Reconnection failed: WebSocket not ready after retries".to_string(),
                ));
            }

            tr.connection_status = TrustRegistryConnectionStatus::Connected;

            store
                .update(&tr)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update trust registry: {}", e)))?;

            if let (Some(Extension(w)), Some(ws)) = (&worker, &ws_state) {
                w.start_listener(&tr, store.clone(), (**ws).clone())
                    .await;
            }

            Ok(Json(tr))
        }
        Err(e) => {
            tracing::error!("OOB reconnection failed for trust registry '{}': {}", id, e);
            tr.connection_status = TrustRegistryConnectionStatus::Failed;
            tr.updated_at = chrono::Utc::now();
            let _ = store.update(&tr).await;
            Err((StatusCode::BAD_GATEWAY, format!("Reconnection failed: {}", e)))
        }
    }
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
}
