use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::comm::client::CommClient;
use crate::gateways::connection_points::ConnectionPointStore;
use crate::mediators::utils::extract_mediator_info;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

use super::MediatorStore;
use super::types::{Mediator, MediatorResponse, MediatorStatus};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OnceCell, RwLock};

struct GlobalCommClientCache {
    clients: RwLock<HashMap<String, Arc<CommClient>>>,
}

static COMM_CLIENT_CACHE: OnceCell<GlobalCommClientCache> = OnceCell::const_new();

async fn get_comm_client_cache() -> &'static GlobalCommClientCache {
    COMM_CLIENT_CACHE
        .get_or_init(|| async {
            GlobalCommClientCache {
                clients: RwLock::new(HashMap::new()),
            }
        })
        .await
}

async fn get_or_create_comm_client(
    cache_key: &str,
    did: String,
    secrets: Vec<affinidi_tdk_common::secrets_resolver::secrets::Secret>,
    alias: Option<String>,
) -> Result<Arc<CommClient>, String> {
    let cache = get_comm_client_cache().await;
    {
        let read = cache.clients.read().await;
        if let Some(client) = read.get(cache_key) {
            tracing::info!("Client for did = {} found in cache", did);
            return Ok(client.clone());
        }
    }

    let new_client = Arc::new(CommClient::new_with_didcomm(did, secrets, None, alias).await?);

    let mut write = cache.clients.write().await;
    if let Some(existing) = write.get(cache_key) {
        return Ok(existing.clone());
    }
    write.insert(cache_key.to_string(), new_client.clone());

    Ok(new_client)
}

async fn remove_cached_clients_for_mediator(mediator_did: &str) -> usize {
    let cache = get_comm_client_cache().await;
    let mut write = cache.clients.write().await;
    remove_cached_client_entries(&mut write, mediator_did)
}

/// Best-effort classification of a mediator error string as a stale/dropped
/// connection (the cached client's socket was reset because the mediator
/// restarted or its store was wiped). Used to decide whether to evict the
/// cached comm client and retry with a fresh, re-authenticated connection.
fn is_stale_connection_error(error: &str) -> bool {
    let lower = error.to_lowercase();
    lower.contains("disconnect")
        || lower.contains("connection reset")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
        || lower.contains("websocket")
        || lower.contains("reset while awaiting")
        || lower.contains("closed")
}

fn remove_cached_client_entries<T>(
    clients: &mut HashMap<String, T>,
    mediator_did: &str,
) -> usize {
    let before = clients.len();
    let key_prefix = format!("{}:", mediator_did);
    clients.retain(|k, _| !k.starts_with(&key_prefix));
    before.saturating_sub(clients.len())
}

/// Request body for creating a mediator
#[derive(Debug, Deserialize)]
pub struct CreateMediatorRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
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

fn mediator_allowed(
    mediator: &Mediator,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(mediator.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Mediators, &mediator.id)
}

/// Request body for updating a mediator
#[derive(Debug, Deserialize)]
pub struct UpdateMediatorRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub did: Option<String>,
    pub status: Option<MediatorStatus>,
}

/// Request body for checking authentication compatibility
#[derive(Debug, Deserialize)]
pub struct CheckAuthRequest {
    pub did_document: serde_json::Value,
}

/// Response body for authentication compatibility check
#[derive(Debug, Serialize)]
pub struct CheckAuthResponse {
    pub compatible: bool,
    pub error: Option<String>,
    pub endpoint_url: Option<String>,
}

/// List all mediators
pub async fn list_mediators<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<MediatorResponse>>, (StatusCode, String)> {
    let mut mediators = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list mediators: {}", e)))?;
    mediators.retain(|mediator| mediator_allowed(mediator, &context, &scope));

    Ok(Json(
        mediators
            .into_iter()
            .map(MediatorResponse::from)
            .collect(),
    ))
}

/// List mediators compatible with OOB invitation creation
/// All stored mediators are compatible (validated during addition)
pub async fn list_compatible_mediators<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<MediatorResponse>>, (StatusCode, String)> {
    let mut mediators = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list mediators: {}", e)))?;
    mediators.retain(|mediator| mediator_allowed(mediator, &context, &scope));

    tracing::info!("Returning {} mediators (all are compatible)", mediators.len());

    Ok(Json(
        mediators
            .into_iter()
            .map(MediatorResponse::from)
            .collect(),
    ))
}

/// Get a mediator by ID
pub async fn get_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Mediator not found".to_string()));
    }

    Ok(Json(mediator.into()))
}

/// Create a new mediator
pub async fn create_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateMediatorRequest>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    crate::config::enforce_add("connections.mediators")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;
    use affinidi_tdk_common::secrets_resolver::secrets::Secret;
    use did_peer::{DIDPeer, DIDPeerCreateKeys, DIDPeerKeys};

    // Generate did:peer for this mediator connection
    let mut ed25519_secret = Secret::generate_ed25519(None, None);
    let mut x25519_secret = Secret::generate_x25519(None, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate X25519 key: {}", e)))?;

    // Extract public key multibase from secrets
    let ed25519_multibase = ed25519_secret
        .get_public_keymultibase()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get Ed25519 multibase: {:?}", e)))?;
    let x25519_multibase = x25519_secret
        .get_public_keymultibase()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get X25519 multibase: {:?}", e)))?;

    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(ed25519_multibase),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: None,
            public_key_multibase: Some(x25519_multibase),
        },
    ];

    let (our_did, _) = DIDPeer::create_peer_did(&keys, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create did:peer: {}", e)))?;

    tracing::info!("Generated did:peer {} for mediator connection", our_did);

    // Update secret IDs to match the did:peer
    ed25519_secret.id = format!("{}#key-1", our_did);
    x25519_secret.id = format!("{}#key-2", our_did);

    let secrets = vec![ed25519_secret, x25519_secret];
    let secrets_json = serde_json::to_value(&secrets)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize secrets: {}", e)))?;

    // Fix malformed service endpoints in the DID document
    // Some mediators incorrectly use colons instead of slashes in URLs
    let fixed_did_document = req
        .did_document
        .map(|doc| fix_malformed_service_endpoints(doc, &req.did));

    let mut mediator = Mediator::new(req.name, req.description, req.did, fixed_did_document);
    mediator.tenant_id = req.tenant_id;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }
    mediator.our_did = Some(our_did);
    mediator.our_secrets = Some(secrets_json);

    store
        .create(&mediator)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store mediator: {}", e)))?;

    // Trigger mediator created event
    if let Some(ref notif_store) = notification_store {
        let mediator_clone = mediator.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let status_str = match mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: mediator_clone.id.clone(),
                name: mediator_clone.name.clone(),
                description: mediator_clone
                    .description
                    .clone(),
                did: mediator_clone.did.clone(),
                status: status_str,
                our_did: mediator_clone.our_did.clone(),
                created_at: Some(
                    mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mediator_integration_triggers::trigger_mediator_created(&notif, &mediator_trigger)
                .await;
        });
    }

    Ok(Json(mediator.into()))
}

/// Fix malformed service endpoints in DID documents
/// Some mediators incorrectly generate serviceEndpoint URLs with colons instead of slashes
/// Example: https://domain:path:to -> https://domain/path/to
fn fix_malformed_service_endpoints(
    mut did_document: serde_json::Value,
    did: &str,
) -> serde_json::Value {
    // Extract the domain from the DID
    // did:web:domain:path:segments -> domain
    // did:webvh:scid:domain:path:segments -> domain
    let domain = if let Some(domain_part) = did.strip_prefix("did:web:") {
        domain_part
            .split(':')
            .next()
            .unwrap_or("")
    } else if let Some(domain_part) = did.strip_prefix("did:webvh:") {
        let parts: Vec<&str> = domain_part
            .split(':')
            .collect();
        if parts.is_empty() {
            return did_document;
        }
        let has_scid = parts.len() >= 2 && !parts[0].contains('.') && !parts[0].contains('%');
        let domain_idx = if has_scid { 1 } else { 0 };
        parts
            .get(domain_idx)
            .copied()
            .unwrap_or("")
    } else {
        return did_document; // Not a did:web, return as-is
    };

    // Process services array
    if let Some(services) = did_document
        .get_mut("service")
        .and_then(|v| v.as_array_mut())
    {
        for service in services.iter_mut() {
            if let Some(endpoint) = service.get_mut("serviceEndpoint")
                && let Some(url_str) = endpoint.as_str()
            {
                // Check if URL has malformed colons after the domain
                // Pattern: https://domain:something -> https://domain/something
                if let Some(fixed_url) = fix_malformed_url(url_str, domain) {
                    tracing::warn!("Fixed malformed service endpoint: {} -> {}", url_str, fixed_url);
                    *endpoint = serde_json::Value::String(fixed_url);
                }
            }
        }
    }

    did_document
}

/// Fix a malformed URL by replacing colons with slashes after the domain
fn fix_malformed_url(
    url: &str,
    domain: &str,
) -> Option<String> {
    // Check if URL contains the domain followed by colons
    if let Some(after_https) = url.strip_prefix("https://")
        && after_https.starts_with(domain)
        && after_https.len() > domain.len()
    {
        let rest = &after_https[domain.len()..];
        // If the character after domain is a colon (not part of port), it's malformed
        if rest.starts_with(':')
            && !rest[1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        {
            // Replace colons with slashes in the path portion
            let fixed_path = rest.replace(':', "/");
            return Some(format!("https://{}{}", domain, fixed_path));
        }
    }
    None
}

/// Update a mediator
pub async fn update_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateMediatorRequest>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    let mut mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }

    let old_mediator = mediator.clone();

    if let Some(name) = req.name {
        mediator.name = name;
    }
    if let Some(description) = req.description {
        mediator.description = description;
    }
    if let Some(did) = req.did {
        mediator.did = did;
    }
    if let Some(status) = req.status {
        mediator.status = status;
    }

    mediator.updated_at = chrono::Utc::now();

    store
        .update(&mediator)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update mediator: {}", e)))?;

    // Trigger mediator updated event
    if let Some(ref notif_store) = notification_store {
        let old_mediator_clone = old_mediator.clone();
        let new_mediator_clone = mediator.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let old_status_str = match old_mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let new_status_str = match new_mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let old_mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: old_mediator_clone.id.clone(),
                name: old_mediator_clone
                    .name
                    .clone(),
                description: old_mediator_clone
                    .description
                    .clone(),
                did: old_mediator_clone.did.clone(),
                status: old_status_str,
                our_did: old_mediator_clone
                    .our_did
                    .clone(),
                created_at: Some(
                    old_mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    old_mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            let new_mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: new_mediator_clone.id.clone(),
                name: new_mediator_clone
                    .name
                    .clone(),
                description: new_mediator_clone
                    .description
                    .clone(),
                did: new_mediator_clone.did.clone(),
                status: new_status_str,
                our_did: new_mediator_clone
                    .our_did
                    .clone(),
                created_at: Some(
                    new_mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    new_mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mediator_integration_triggers::trigger_mediator_updated(
                &notif,
                &old_mediator_trigger,
                &new_mediator_trigger,
            )
            .await;
        });
    }

    Ok(Json(mediator.into()))
}

/// Delete a mediator
pub async fn delete_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(cp_store): Extension<Option<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>>,
    Extension(listener_manager): Extension<
        Option<std::sync::Arc<crate::gateways::connection_points::ws_listener::ConnectionPointListenerManager>>,
    >,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::info!("Deleting mediator: {}", id);

    // Get mediator before deletion for trigger
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }

    // Stop all connection point listeners using this mediator
    if let (Some(cp_store_ref), Some(listener_mgr)) = (cp_store.as_ref(), listener_manager.as_ref()) {
        tracing::info!("Finding connection points using mediator '{}'...", id);

        // Get all connection points
        match cp_store_ref.list_all().await {
            Ok(connection_points) => {
                // Filter to those using this mediator
                let affected_cps: Vec<_> = connection_points
                    .into_iter()
                    .filter(|cp| cp.mediator_id == id)
                    .collect();

                if !affected_cps.is_empty() {
                    tracing::info!("Found {} connection point(s) using this mediator", affected_cps.len());

                    // Stop listener for each affected connection point
                    for cp in affected_cps {
                        tracing::info!("  Stopping listener for connection point '{}'...", cp.id);
                        if let Err(e) = listener_mgr
                            .stop_listener(&cp.id)
                            .await
                        {
                            tracing::warn!("    Failed to stop listener for connection point '{}': {}", cp.id, e);
                        } else {
                            tracing::info!("    ✓ Listener stopped for connection point '{}'", cp.id);
                        }
                    }
                } else {
                    tracing::info!("No connection points using this mediator");
                }
            }
            Err(e) => {
                tracing::error!("Failed to list connection points: {}", e);
                // Continue with mediator deletion even if we can't clean up listeners
            }
        }
    } else {
        tracing::warn!("Cannot stop connection point listeners: store or listener manager not available");
    }
    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete mediator: {}", e)))?;

    let removed_clients = remove_cached_clients_for_mediator(&mediator.did).await;
    tracing::info!("Removed {} cached comm client(s) for mediator DID {}", removed_clients, mediator.did);

    // Trigger mediator deleted event
    if let Some(ref notif_store) = notification_store {
        let mediator_clone = mediator.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let status_str = match mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: mediator_clone.id.clone(),
                name: mediator_clone.name.clone(),
                description: mediator_clone
                    .description
                    .clone(),
                did: mediator_clone.did.clone(),
                status: status_str,
                our_did: mediator_clone.our_did.clone(),
                created_at: Some(
                    mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mediator_integration_triggers::trigger_mediator_deleted(&notif, &mediator_trigger)
                .await;
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Check if a mediator's authentication endpoints are accessible
/// Uses the actual SDK authentication flow to verify compatibility
pub async fn check_auth_compatibility(
    Extension(vc_issuer): Extension<std::sync::Arc<crate::identity::vc_issuer::VCIssuer>>,
    Json(req): Json<CheckAuthRequest>,
) -> Result<Json<CheckAuthResponse>, (StatusCode, String)> {
    // Extract the mediator DID from the DID document's id field
    let mediator_did = req
        .did_document
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "DID document missing 'id' field".to_string()))?
        .to_string();

    tracing::info!("Extracting mediator info from DID: {}", mediator_did);

    // Extract DIDCommMessaging service endpoint (could be URL or DID)
    let (mediator_url, final_did_document) = extract_mediator_info(&req.did_document)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    tracing::info!("Testing authentication with mediator: {} (DID: {})", mediator_url, mediator_did);

    // Get gateway DID and secrets from VC issuer
    let gateway_did_doc = vc_issuer
        .get_did_document()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway DID: {}", e)))?;

    let gateway_did = gateway_did_doc
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Gateway DID not found".to_string()))?
        .to_string();

    let secrets = vc_issuer
        .get_signing_secrets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway secrets: {}", e)))?;

    tracing::info!("Testing authentication: {} -> {}", gateway_did, mediator_did);

    let comm_client = CommClient::new_with_didcomm(
        gateway_did.clone(),
        secrets,
        None,
        Some(format!("auth-test-{}", uuid::Uuid::new_v4())),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to initialize Comm client: {}", e)))?;

    comm_client
        .didcomm()
        .cache_did_document(&gateway_did, gateway_did_doc)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to cache gateway DID document: {}", e)))?;

    comm_client
        .didcomm()
        .cache_did_document(&mediator_did, final_did_document)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to cache mediator DID document: {}", e)))?;

    let auth_result = comm_client
        .didcomm()
        .test_mediator_authentication(&mediator_did, Duration::from_secs(5))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to test mediator authentication: {}", e)))?;

    match auth_result.compatible {
        true => {
            tracing::info!("✓ Authentication successful with mediator: {}", mediator_url);
            Ok(Json(CheckAuthResponse {
                compatible: true,
                error: None,
                endpoint_url: Some(mediator_url),
            }))
        }
        false => {
            let error = auth_result
                .error
                .unwrap_or_else(|| "Authentication failed".to_string());
            tracing::warn!("✗ Authentication failed with mediator {}: {}", mediator_url, error);
            Ok(Json(CheckAuthResponse {
                compatible: false,
                error: Some(error),
                endpoint_url: Some(mediator_url),
            }))
        }
    }
}

/// Extract the base URL from a DIDCommMessaging service endpoint
fn extract_didcomm_service_endpoint(did_document: &serde_json::Value) -> Option<String> {
    tracing::debug!(
        "Extracting DIDComm service endpoint from DID document: {}",
        serde_json::to_string_pretty(did_document).unwrap_or_default()
    );

    let services = did_document
        .get("service")?
        .as_array()?;
    tracing::debug!("Found {} services in DID document", services.len());

    // Find DIDCommMessaging service
    let didcomm_service = services
        .iter()
        .find(|service| {
            if let Some(service_type) = service.get("type") {
                tracing::debug!("Checking service type: {:?}", service_type);
                if let Some(type_str) = service_type.as_str() {
                    return type_str == "DIDCommMessaging";
                }
                if let Some(type_array) = service_type.as_array() {
                    return type_array
                        .iter()
                        .any(|t| t.as_str() == Some("DIDCommMessaging"));
                }
            }
            false
        })?;

    tracing::debug!(
        "Found DIDCommMessaging service: {}",
        serde_json::to_string_pretty(didcomm_service).unwrap_or_default()
    );

    // Extract serviceEndpoint
    let service_endpoint = didcomm_service.get("serviceEndpoint")?;

    let base_url = if let Some(url_str) = service_endpoint.as_str() {
        // Simple string endpoint
        // support for port:
        // url_str.replace("%3A", ":").to_string()
        url_str.to_string()
    } else if let Some(uri) = service_endpoint
        .get("uri")
        .and_then(|v| v.as_str())
    {
        // Object with uri field
        uri.to_string()
    } else if let Some(url) = service_endpoint
        .get("url")
        .and_then(|v| v.as_str())
    {
        // Object with url field
        url.to_string()
    } else if let Some(endpoint_array) = service_endpoint.as_array() {
        // Array of endpoint objects - find the first HTTPS endpoint
        endpoint_array
            .iter()
            .find_map(|ep| {
                if let Some(uri) = ep
                    .get("uri")
                    .and_then(|v| v.as_str())
                    && uri.starts_with("https://")
                {
                    return Some(uri.to_string());
                }
                None
            })
            .or_else(|| {
                // If no HTTPS found, try any URI
                endpoint_array
                    .first()
                    .and_then(|ep| ep.get("uri"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })?
    } else {
        tracing::warn!("Could not extract URL from serviceEndpoint: {:?}", service_endpoint);
        return None;
    };

    // Extract base URL (protocol + host)
    if let Ok(parsed_url) = url::Url::parse(&base_url) {
        Some(format!("{}://{}", parsed_url.scheme(), parsed_url.host_str()?))
    } else {
        // Try to extract with regex
        let re = regex::Regex::new(r"^(https?://[^/]+)").ok()?;
        re.captures(&base_url)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
    }
}

/// Response body for trust ping
#[derive(Debug, Serialize)]
pub struct TrustPingResponse {
    pub success: bool,
    pub message: String,
    pub round_trip_ms: Option<u64>,
}

/// Send a trust ping to `mediator`, evicting the cached comm client and
/// retrying once if the first attempt fails with a stale/dropped connection.
///
/// A cached comm client whose mediator was restarted or had its store wiped
/// surfaces as a disconnect / connection reset. On that failure the stale
/// cached client is dropped and the ping retried with a fresh one, which
/// re-authenticates from scratch — the mediator re-creates the account on the
/// auth challenge, so the ping recovers.
async fn trust_ping_with_reconnect(
    request_id: &str,
    cache_key: &str,
    mediator: &Mediator,
    our_did: &str,
    secrets: &[affinidi_tdk_common::secrets_resolver::secrets::Secret],
) -> Result<crate::comm::didcomm::mediator::MediatorTrustPingResult, (StatusCode, String)> {
    let mut attempt = 0;
    loop {
        attempt += 1;

        let comm_client = get_or_create_comm_client(
            cache_key,
            our_did.to_string(),
            secrets.to_vec(),
            Some("trust-ping-global".to_string()),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to initialize comm client: {}", e)))?;

        if let Some(ref mediator_did_doc) = mediator.did_document {
            comm_client
                .didcomm()
                .cache_did_document(&mediator.did, mediator_did_doc.clone())
                .await
                .map_err(|e| {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to cache mediator DID document: {}", e))
                })?;
        } else {
            tracing::warn!("⚠ Mediator has no cached DID document - authentication may fail!");
            tracing::warn!("  This mediator may need to be re-added to cache its DID document");
        }

        let result = comm_client
            .didcomm()
            .trust_ping_mediator(&mediator.did, Duration::from_secs(5))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to execute trust ping: {}", e)))?;

        if !result.success
            && attempt < 2
            && result
                .error
                .as_deref()
                .map(is_stale_connection_error)
                .unwrap_or(false)
        {
            tracing::warn!(
                "🔄 [{request_id}] Trust ping to {} failed with a stale connection ({}); evicting cached client and reconnecting...",
                mediator.name,
                result
                    .error
                    .as_deref()
                    .unwrap_or("")
            );
            remove_cached_clients_for_mediator(&mediator.did).await;
            continue;
        }

        return Ok(result);
    }
}

/// Send a trust ping to a mediator to test connectivity
pub async fn trust_ping_mediator<S: MediatorStore>(
    Path(id): Path<String>,
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(_vc_issuer): Extension<std::sync::Arc<crate::identity::vc_issuer::VCIssuer>>,
    _listener_manager: Option<Extension<std::sync::Arc<crate::gateways::ConnectionPointListenerManager>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<TrustPingResponse>, (StatusCode, String)> {
    use std::time::Instant;

    let total_start = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string()[..8].to_string();

    tracing::info!("[{request_id}] Trust ping requested for mediator: {}", id);

    // Get mediator from store
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".to_string()));
    }

    tracing::warn!("🆕 [{request_id}] Mediator: {} ({})", mediator.name, mediator.did);

    // Trust ping uses the gateway DID (did:web) which is separate from connection point DIDs (did:key)
    // Each connection point has its own unique DID, so no conflicts occur

    // Extract mediator URL from DID
    let mediator_url = if let Some(ref did_doc) = mediator.did_document {
        extract_didcomm_service_endpoint(did_doc)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "No DIDComm service endpoint found".to_string()))?
    } else {
        // Fallback: try to extract from DID
        crate::gateways::connection_points::extract_mediator_url(&mediator.did)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to extract mediator URL: {}", e)))?
    };

    tracing::info!("Mediator URL: {}", mediator_url);

    // Get our stored did:peer and secrets for this mediator
    let (our_did, secrets) = if let (Some(did), Some(secrets_json)) = (&mediator.our_did, &mediator.our_secrets) {
        use affinidi_tdk_common::secrets_resolver::secrets::Secret;

        let secrets: Vec<Secret> = serde_json::from_value(secrets_json.clone())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to deserialize secrets: {}", e)))?;

        tracing::info!("Using stored did:peer {} for trust ping", did);
        (did.clone(), secrets)
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Mediator missing did:peer configuration. Please recreate the mediator.".to_string(),
        ));
    };

    let cache_key = format!("{}:{}", mediator.did, our_did);

    tracing::info!("🔵 [{request_id}] Sending trust ping...");

    let ping_result = trust_ping_with_reconnect(&request_id, &cache_key, &mediator, &our_did, &secrets).await?;

    let total_elapsed = total_start.elapsed();
    tracing::warn!("🏁 [{request_id}] Trust ping operation COMPLETE - total time: {}ms", total_elapsed.as_millis());

    if ping_result.success {
        tracing::info!("✓ Received pong response from {}", mediator.name);
        tracing::info!(
            "✓ Trust ping successful: {}ms RTT, {}ms total",
            ping_result
                .round_trip_ms
                .unwrap_or_default(),
            total_elapsed.as_millis()
        );
        Ok(Json(TrustPingResponse {
            success: true,
            message: format!(
                "Trust ping successful ({}ms)",
                ping_result
                    .round_trip_ms
                    .unwrap_or_default()
            ),
            round_trip_ms: ping_result.round_trip_ms,
        }))
    } else {
        let error = ping_result
            .error
            .unwrap_or_else(|| "No pong response received".to_string());
        tracing::warn!("✗ Trust ping failed for {}: {}", mediator.name, error);
        Ok(Json(TrustPingResponse {
            success: false,
            message: error,
            round_trip_ms: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fix_malformed_service_endpoints, is_stale_connection_error, mediator_allowed, remove_cached_client_entries,
    };
    use crate::auth_manager::pat::PatResourceScope;
    use crate::mediators::types::Mediator;
    use crate::tenancy::PatTenantContext;
    use regex::Regex;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn mediator_actions_require_tenant_and_scope_access() {
        let mut mediator = Mediator::new("Mediator".into(), String::new(), "did:example:mediator".into(), None);
        mediator.id = "mediator-a".into();
        mediator.tenant_id = Some("tenant-a".into());
        let context = PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(Regex::new(r"\ATENANT:tenant-a:mediators:mediator-a\z").unwrap()));

        assert!(mediator_allowed(
            &mediator,
            &Some(axum::Extension(context.clone())),
            &Some(axum::Extension(scope.clone()))
        ));
        mediator.tenant_id = Some("tenant-b".into());
        assert!(!mediator_allowed(&mediator, &Some(axum::Extension(context)), &Some(axum::Extension(scope))));
    }

    #[test]
    fn stale_connection_error_matches_dropped_sockets() {
        assert!(is_stale_connection_error(
            "Trust ping error: Disconnected(\"Connection reset while awaiting response for abc\")"
        ));
        assert!(is_stale_connection_error("websocket closed"));
        assert!(is_stale_connection_error("broken pipe"));
    }

    #[test]
    fn stale_connection_error_ignores_semantic_failures() {
        assert!(!is_stale_connection_error("No pong response received"));
        assert!(!is_stale_connection_error("Trust ping timed out"));
        assert!(!is_stale_connection_error("DID is blocked"));
    }

    #[test]
    fn fix_malformed_service_endpoints_supports_didwebvh() {
        let doc = json!({
            "service": [{
                "serviceEndpoint": "https://mediator.example.com:mediator:v1"
            }]
        });

        let fixed = fix_malformed_service_endpoints(doc, "did:webvh:z6MkScid123:mediator.example.com:mediator:v1");

        assert_eq!(fixed["service"][0]["serviceEndpoint"], json!("https://mediator.example.com/mediator/v1"));
    }

    #[test]
    fn remove_cached_client_entries_removes_matching_mediator_prefix() {
        let mut cache = HashMap::new();
        cache.insert("did:example:mediator-a:did:peer:one".to_string(), 1u8);
        cache.insert("did:example:mediator-a:did:peer:two".to_string(), 2u8);
        cache.insert("did:example:mediator-b:did:peer:three".to_string(), 3u8);

        let removed = remove_cached_client_entries(&mut cache, "did:example:mediator-a");

        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("did:example:mediator-b:did:peer:three"));
    }
}
