use axum::{
    Extension, Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::config::BootstrapConfig;
use crate::identity::AgentIdentityResponse;
use crate::identity::state::{IdentityApiState, IssueCredentialRequest};
use crate::identity::vc_issuer::VCIssuer;

/// Application error type for credential handlers
#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::BadRequest(msg) => {
                warn!("API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            AppError::InternalError(msg) => {
                error!("API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
            }
        };

        let body = Json(ErrorResponse {
            error: message.to_string(),
            details,
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// Issue or retrieve an agent credential
///
/// POST /api/v1/identity/issue-credential
///
/// Request body:
/// ```json
/// {
///   "agent_identity": {
///     "llmInfo": { ... },
///     "softwareInfo": { ... },
///     "provisioningInfo": { ... },
///     "region": "us-east-1"
///   }
/// }
/// ```
///
/// Response:
/// ```json
/// {
///   "did": "did:web:proxy.example.com:surface:550e8400-e29b-41d4-a716-446655440000",
///   "credential": "eyJ...",
///   "is_new": true
/// }
/// ```
pub async fn issue_credential(
    State(state): State<IdentityApiState>,
    Json(req): Json<IssueCredentialRequest>,
) -> Result<Json<AgentIdentityResponse>, AppError> {
    info!("Received credential issuance request");

    // Issue or retrieve existing credential
    // For backward compatibility, wrap the entire payload in a simple map
    let mut identity_fields = std::collections::HashMap::new();
    identity_fields.insert("agentIdentity".to_string(), req.agent_identity.clone());

    let response = state
        .vc_issuer
        .issue_or_get_credential(identity_fields, None, None, None)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to issue credential");
            AppError::InternalError(format!("Failed to issue credential: {}", e))
        })?;

    info!(
        did = %response.did,
        is_new = response.is_new,
        "Issued credential"
    );

    // If this is a new identity, broadcast the update via WebSocket
    if response.is_new {
        let identity_info = serde_json::json!({
            "did": response.did,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "agent_identity": req.agent_identity,
        });

        state
            .ws_state
            .broadcast(crate::server::WsUpdate::IdentityCreated { identity: identity_info });

        // Trigger identity.created integration event
        if let Some(ref notif_store) = state.notification_store {
            let did_clone = response.did.clone();
            let agent_id_clone = req.agent_identity.clone();
            let notif = notif_store.clone();
            tokio::spawn(async move {
                crate::integrations::async_triggers::trigger_identity_created(Some(notif), &did_clone, &agent_id_clone)
                    .await;
            });
        }
    }

    Ok(Json(response))
}

/// Get the proxy's DID document
///
/// GET /api/v1/identity/did-document
///
/// Returns the canonical DID document: `did:webvh` state when the gateway has
/// been migrated (so callers like the UI get the real `did:webvh` identifier
/// in `doc.id`), falling back to the `did:web` document otherwise.
pub async fn get_did_document(State(state): State<IdentityApiState>) -> Result<Json<serde_json::Value>, AppError> {
    let proxy_did = state
        .vc_issuer
        .get_issuer_did()
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get issuer DID");
            AppError::InternalError(format!("Failed to get issuer DID: {}", e))
        })?;

    #[cfg(feature = "didwebvh")]
    if proxy_did.starts_with("did:webvh:") {
        let log_path = state
            .vc_issuer
            .get_storage_path()
            .await
            .join("did.jsonl");
        if let Some(did_doc) = load_latest_log_state_as_json(&log_path).await {
            return Ok(Json(did_doc));
        }
    }

    let did_doc = state
        .vc_issuer
        .get_did_document()
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get DID document");
            AppError::InternalError(format!("Failed to get DID document: {}", e))
        })?;

    Ok(Json(did_doc))
}

/// Resolve a DID document from any DID using the Affinidi DID resolver
///
/// GET /api/v1/identity/resolve-did?did=did:web:...
///
/// Response: The resolved DID document in JSON format
pub async fn resolve_did_document(
    State(state): State<IdentityApiState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let did = params
        .get("did")
        .ok_or_else(|| AppError::BadRequest("Missing 'did' parameter".to_string()))?;

    // Validate DID format
    if !did.starts_with("did:") {
        return Err(AppError::BadRequest("Invalid DID format - must start with 'did:'".to_string()));
    }

    // Additional DID validation to prevent panics in the resolver
    // DIDs should only contain valid characters (alphanumeric, hyphens, underscores, dots, colons, percent-encoded)
    // and should not contain quotes, backslashes, or other problematic characters
    if did.contains('"') || did.contains('\\') || did.contains('\n') || did.contains('\r') {
        return Err(AppError::BadRequest("Invalid DID format - contains illegal characters".to_string()));
    }

    // Validate basic DID structure: did:method:method-specific-id
    let parts: Vec<&str> = did.splitn(3, ':').collect();
    if parts.len() < 3 || parts[0] != "did" || parts[1].is_empty() || parts[2].is_empty() {
        return Err(AppError::BadRequest("Invalid DID format - must be 'did:method:method-specific-id'".to_string()));
    }

    info!("Resolving DID document for: {}", did);

    // For did:webvh DIDs, try local resolution first.  This handles identities that are
    // hosted on this gateway instance without making outbound HTTP calls (which would
    // fail for localhost DIDs or for old-format DIDs that lack a SCID prefix).
    #[cfg(feature = "didwebvh")]
    if did.starts_with("did:webvh:")
        && let Some(ref log_storage) = state.didwebvh_log_storage
    {
        use crate::identity::didwebvh::resolver::DidWebvhResolver;
        let local_resolver = DidWebvhResolver::new(log_storage.clone());
        match local_resolver
            .resolve(did)
            .await
        {
            Ok(doc) => {
                let did_doc_json = serde_json::to_value(&doc).map_err(|e| {
                    error!(error = %e, "Failed to serialize local did:webvh document");
                    AppError::InternalError(format!("Failed to serialize DID document: {}", e))
                })?;
                info!(did = %did, "Successfully resolved did:webvh DID from local storage");
                if let Some(ref notif_store) = state.notification_store {
                    let did_clone = did.to_string();
                    let notif = notif_store.clone();
                    tokio::spawn(async move {
                        crate::integrations::async_triggers::trigger_identity_accessed(Some(notif), &did_clone).await;
                    });
                }
                return Ok(Json(did_doc_json));
            }
            Err(e) => {
                debug!(
                    did = %did,
                    error = %e,
                    "Local did:webvh resolution found no entries, falling back to external resolver"
                );
            }
        }
    }

    // Some locally managed did:webvh identities are persisted under the identity store's
    // per-identity directories instead of the generic did:webvh log storage backend.
    // Check that layout before falling back to outbound HTTP resolution.
    #[cfg(feature = "didwebvh")]
    if did.starts_with("did:webvh:")
        && let Some(did_doc_json) = try_resolve_local_identity_store_didwebvh(
            state
                .vc_issuer
                .get_identity_store(),
            did,
        )
        .await?
    {
        if let Some(ref notif_store) = state.notification_store {
            let did_clone = did.to_string();
            let notif = notif_store.clone();
            tokio::spawn(async move {
                crate::integrations::async_triggers::trigger_identity_accessed(Some(notif), &did_clone).await;
            });
        }
        return Ok(Json(did_doc_json));
    }

    if let Err(reason) = vet_did_resolution_egress(did).await {
        warn!(did = %did, reason = %reason, "Refused outbound DID resolution: egress target blocked");
        return Err(AppError::BadRequest("DID resolution blocked by egress policy".to_string()));
    }

    // Use the shared DID resolver (single TLS context + connection pool)
    let client = crate::gateways::did_cache::shared_resolver();

    // Resolve the DID document
    let resolution_result = client
        .resolve(did)
        .await
        .map_err(|e| {
            error!(error = %e, did = %did, "Failed to resolve DID");
            AppError::BadRequest("Failed to resolve DID".to_string())
        })?;

    // Convert the DID document to JSON
    let did_doc_json = serde_json::to_value(&resolution_result.doc).map_err(|e| {
        error!(error = %e, "Failed to serialize DID document");
        AppError::InternalError(format!("Failed to serialize DID document: {}", e))
    })?;

    info!(
        did = %did,
        method = ?resolution_result.method,
        cache_hit = resolution_result.cache_hit,
        "Successfully resolved DID document"
    );

    // Trigger identity.accessed integration event
    if let Some(ref notif_store) = state.notification_store {
        let did_clone = did.to_string();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            crate::integrations::async_triggers::trigger_identity_accessed(Some(notif), &did_clone).await;
        });
    }

    Ok(Json(did_doc_json))
}

/// Spec-compliant DID resolution per did:webvh v1.0 §3.6.2 — Read (Resolve)
///
/// GET /api/v1/identity/resolve-did-document?did=did:webvh:...&versionId=...&versionTime=...
///
/// Returns the W3C DID Resolution result:
/// ```json
/// {
///   "didDocument": { ... },
///   "didDocumentMetadata": { "versionId": "...", ... },
///   "didResolutionMetadata": { "contentType": "application/did+ld+json" }
/// }
/// ```
pub async fn resolve_did_document_spec(
    State(state): State<IdentityApiState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let did = match params.get("did") {
        Some(d) => d.clone(),
        None => {
            return axum::response::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "didDocument": null,
                        "didDocumentMetadata": {},
                        "didResolutionMetadata": {
                            "error": "invalidDid",
                            "contentType": "application/did+ld+json",
                            "problemDetails": {
                                "type": "https://www.w3.org/TR/did-core/#did-resolution",
                                "title": "Missing DID parameter",
                                "detail": "The 'did' query parameter is required"
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap();
        }
    };

    // Validate DID format
    if !did.starts_with("did:") || did.contains('"') || did.contains('\\') || did.contains('\n') {
        return did_resolution_error(StatusCode::BAD_REQUEST, "invalidDid", "Invalid DID format");
    }

    let parts: Vec<&str> = did.splitn(3, ':').collect();
    if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
        return did_resolution_error(
            StatusCode::BAD_REQUEST,
            "invalidDid",
            "DID must follow format 'did:method:method-specific-id'",
        );
    }

    let version_id = params
        .get("versionId")
        .cloned();
    let version_time = params
        .get("versionTime")
        .cloned();

    info!(did = %did, ?version_id, ?version_time, "Resolving DID document (spec-compliant)");

    // For did:webvh DIDs, use the local resolver with full metadata
    #[cfg(feature = "didwebvh")]
    if did.starts_with("did:webvh:")
        && let Some(ref log_storage) = state.didwebvh_log_storage
    {
        use crate::identity::didwebvh::resolver::DidWebvhResolver;
        let resolver = DidWebvhResolver::new(log_storage.clone());

        // Version-specific resolution
        if let Some(ref vid) = version_id {
            return match resolver
                .resolve_version_id(&did, vid)
                .await
            {
                Ok(doc) => did_resolution_success_no_metadata(doc),
                Err(e) => did_resolution_error(StatusCode::NOT_FOUND, "notFound", &format!("Version not found: {}", e)),
            };
        }

        if let Some(ref vt) = version_time {
            return match resolver
                .resolve_version_time(&did, vt)
                .await
            {
                Ok(doc) => did_resolution_success_no_metadata(doc),
                Err(e) => {
                    did_resolution_error(StatusCode::BAD_REQUEST, "invalidDid", &format!("Invalid versionTime: {}", e))
                }
            };
        }

        // Full resolution with metadata
        return match resolve_didwebvh_with_deactivation_support(log_storage.clone(), &did).await {
            Ok((doc, metadata)) => {
                let metadata_json = serde_json::to_value(&metadata).unwrap_or_default();
                let body = if metadata.deactivated {
                    // Spec §3.6.2 step 11: deactivated DID → null document, metadata with deactivated: true
                    serde_json::json!({
                        "didDocument": null,
                        "didDocumentMetadata": metadata_json,
                        "didResolutionMetadata": {
                            "contentType": "application/did+ld+json"
                        }
                    })
                } else {
                    let doc_json = serde_json::to_value(&doc).unwrap_or_default();
                    serde_json::json!({
                        "didDocument": doc_json,
                        "didDocumentMetadata": metadata_json,
                        "didResolutionMetadata": {
                            "contentType": "application/did+ld+json"
                        }
                    })
                };
                axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap()
            }
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("did log empty") || err_msg.contains("not found") {
                    did_resolution_error(StatusCode::NOT_FOUND, "notFound", &err_msg)
                } else {
                    did_resolution_error(StatusCode::BAD_REQUEST, "invalidDid", &err_msg)
                }
            }
        };
    }

    if let Err(reason) = vet_did_resolution_egress(&did).await {
        warn!(did = %did, reason = %reason, "Refused outbound DID resolution: egress target blocked");
        return did_resolution_error(StatusCode::BAD_REQUEST, "invalidDid", "DID resolution blocked by egress policy");
    }

    // Fallback for non-didwebvh DIDs: use the shared DID resolver, wrap in spec format
    let client = crate::gateways::did_cache::shared_resolver();
    match client.resolve(&did).await {
        Ok(resolution_result) => {
            let doc_json = serde_json::to_value(&resolution_result.doc).unwrap_or_default();
            let body = serde_json::json!({
                "didDocument": doc_json,
                "didDocumentMetadata": {},
                "didResolutionMetadata": {
                    "contentType": "application/did+ld+json"
                }
            });
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        }
        Err(e) => {
            error!(error = %e, did = %did, "Failed to resolve DID");
            did_resolution_error(StatusCode::NOT_FOUND, "notFound", "DID resolution failed")
        }
    }
}

/// Authority (`host[:port]`) the shared resolver would fetch for a network-backed
/// DID method, mirroring the `did:web`, `did:webvh` and `did:scid` URL mappings.
/// `Ok(None)` for methods that resolve offline.
fn did_resolution_authority(did: &str) -> Result<Option<String>, String> {
    let authority = if let Some(id) = did.strip_prefix("did:web:") {
        id.split(':').next()
    } else if let Some(id) = did.strip_prefix("did:webvh:") {
        id.split(':').nth(1)
    } else if let Some(id) = did.strip_prefix("did:scid:") {
        id.split_once("?src=")
            .map(|(_, src)| {
                src.strip_prefix("https://")
                    .or_else(|| src.strip_prefix("http://"))
                    .unwrap_or(src)
            })
            .and_then(|src| src.split('/').next())
    } else {
        return Ok(None);
    };

    match authority.filter(|authority| !authority.is_empty()) {
        Some(authority) => Ok(Some(
            authority
                .replace("%3A", ":")
                .replace("%3a", ":"),
        )),
        None => Err("DID names no resolvable host".to_string()),
    }
}

/// Runs the strict egress validator against the host an outbound DID resolution
/// would dial, failing closed on any parse, DNS or policy error.
async fn vet_did_resolution_egress(did: &str) -> Result<(), String> {
    let Some(authority) = did_resolution_authority(did)? else {
        return Ok(());
    };
    let url = format!("https://{authority}/");
    tokio::task::spawn_blocking(move || crate::url_validation::validate_resolved_webhook_url(&url))
        .await
        .map_err(|e| format!("egress validation task failed: {e}"))?
        .map(|_| ())
}

/// Build a spec-compliant DID resolution error response
fn did_resolution_error(
    status: StatusCode,
    error_code: &str,
    detail: &str,
) -> axum::response::Response {
    let body = serde_json::json!({
        "didDocument": null,
        "didDocumentMetadata": {},
        "didResolutionMetadata": {
            "error": error_code,
            "contentType": "application/did+ld+json",
            "problemDetails": {
                "type": "https://www.w3.org/TR/did-core/#did-resolution",
                "title": error_code,
                "detail": detail
            }
        }
    });
    axum::response::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// Build a success response for version-specific resolution (no full metadata available)
fn did_resolution_success_no_metadata(doc: crate::identity::didwebvh::types::DidDocument) -> axum::response::Response {
    let doc_json = serde_json::to_value(&doc).unwrap_or_default();
    let body = serde_json::json!({
        "didDocument": doc_json,
        "didDocumentMetadata": {},
        "didResolutionMetadata": {
            "contentType": "application/did+ld+json"
        }
    });
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// Resolve a did:webvh DID with support for deactivated DIDs.
///
/// Unlike `DidWebvhResolver::resolve_with_metadata()` which rejects deactivated DIDs,
/// this function returns metadata with `deactivated: true` per spec §3.6.2 step 11.
#[cfg(feature = "didwebvh")]
async fn resolve_didwebvh_with_deactivation_support(
    log_storage: Arc<dyn crate::storage::DidLogStorage>,
    did: &str,
) -> Result<
    (crate::identity::didwebvh::types::DidDocument, crate::identity::didwebvh::types::DidResolutionMetadata),
    anyhow::Error,
> {
    use crate::identity::didwebvh::types::{DidResolutionMetadata, LogEntry};
    use crate::identity::didwebvh::verifier::DidWebvhVerifier;

    let entries: Vec<LogEntry> = log_storage
        .load_all(did)
        .await?;
    let verifier = DidWebvhVerifier::new();
    verifier.verify(&entries)?;

    let birth = entries
        .first()
        .ok_or_else(|| anyhow::anyhow!("did log empty"))?;
    let latest = entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("did log empty"))?;

    let metadata = DidResolutionMetadata {
        version_id: latest.version_id.clone(),
        version_time: latest.version_time.clone(),
        created: birth.version_time.clone(),
        updated: latest.version_time.clone(),
        scid: latest.parameters.scid.clone(),
        portable: latest.parameters.portable,
        deactivated: latest.parameters.deactivated,
        ttl: latest
            .parameters
            .ttl
            .unwrap_or(3600),
        witness: latest
            .parameters
            .witness
            .clone(),
        watchers: latest
            .parameters
            .watchers
            .clone(),
    };

    Ok((latest.state.clone(), metadata))
}

#[cfg(feature = "didwebvh")]
async fn try_resolve_local_identity_store_didwebvh(
    identity_store: Arc<dyn crate::identity::IdentityStore>,
    did: &str,
) -> Result<Option<serde_json::Value>, AppError> {
    let Some(record) = identity_store
        .find_by_did(did)
        .await
        .map_err(|e| {
            error!(error = %e, did = %did, "Failed to look up local identity for did:webvh resolution");
            AppError::InternalError(format!("Failed to look up local identity: {}", e))
        })?
    else {
        return Ok(None);
    };

    let Some(base_path) = identity_store.base_path() else {
        debug!(did = %did, "Identity store has no filesystem base path for local did:webvh resolution");
        return Ok(None);
    };

    let Some(identity_id) = did
        .rsplit(':')
        .next()
        .filter(|segment| !segment.is_empty())
    else {
        debug!(did = %did, "Unable to derive local identity ID from did:webvh");
        return Ok(None);
    };

    let log_path = base_path
        .join(identity_id)
        .join("did.jsonl");
    let did_doc_json = load_latest_log_state_as_json(&log_path).await;

    if did_doc_json.is_some() {
        info!(
            did = %did,
            identity_hash = %record.identity_hash,
            path = %log_path.display(),
            "Successfully resolved did:webvh DID from identity store log"
        );
    } else {
        debug!(
            did = %did,
            identity_hash = %record.identity_hash,
            path = %log_path.display(),
            "Local identity record found but did.jsonl was missing from identity store path"
        );
    }

    Ok(did_doc_json)
}

async fn find_local_channel_identity_record_by_tail(
    identity_store: Arc<dyn crate::identity::IdentityStore>,
    channel_id: &str,
) -> Result<Option<crate::identity::AgentIdentityRecord>, AppError> {
    let records = identity_store
        .list_all()
        .await
        .map_err(|e| {
            error!(error = %e, channel_id = %channel_id, "Failed to list local identities for channel DID lookup");
            AppError::InternalError(format!("Failed to list local identities: {}", e))
        })?;

    Ok(records
        .into_iter()
        .find(|record| {
            let mut parts = record.did.rsplit(':');
            matches!((parts.next(), parts.next()), (Some(tail), Some("surface")) if tail == channel_id)
        }))
}

fn channel_did_log_path(
    base_path: &std::path::Path,
    channel_id: &str,
) -> Result<std::path::PathBuf, AppError> {
    crate::storage::validate_storage_id(channel_id)
        .and_then(|()| {
            let identity_dir = base_path.join(channel_id);
            crate::storage::assert_within_storage_dir(base_path, &identity_dir)?;
            Ok(identity_dir.join("did.jsonl"))
        })
        .map_err(|e| {
            warn!(error = %e, surface_id = %channel_id, "Rejected surface DID log path");
            AppError::BadRequest("Invalid surface id".to_string())
        })
}

async fn resolve_channel_did_log_path(
    identity_store: Arc<dyn crate::identity::IdentityStore>,
    fallback_base_path: &std::path::Path,
    channel_id: &str,
) -> Result<std::path::PathBuf, AppError> {
    if let Some(base_path) = identity_store.base_path() {
        let direct_path = channel_did_log_path(&base_path, channel_id)?;
        if direct_path.exists() {
            return Ok(direct_path);
        }

        if let Some(record) = find_local_channel_identity_record_by_tail(identity_store, channel_id).await?
            && let Some(actual_tail) = record.did.rsplit(':').next()
        {
            return channel_did_log_path(&base_path, actual_tail);
        }
    }

    channel_did_log_path(fallback_base_path, channel_id)
}

/// Handler for serving the gateway's DID document at /.well-known/did.json
/// This is required for did:web resolution
/// Dynamically injects channel services for channels marked with publish_to_did_document=true
/// When proxy_did is `did:webvh`, returns a parallel did:web document with `alsoKnownAs`.
pub async fn serve_gateway_did_document(
    State(state): State<IdentityApiState>
) -> Result<Json<serde_json::Value>, AppError> {
    info!("Serving gateway DID document at /.well-known/did.json");

    // Determine which proxy DID form to serve.
    let proxy_did = state
        .vc_issuer
        .get_issuer_did()
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get issuer DID");
            AppError::InternalError(format!("Failed to get issuer DID: {}", e))
        })?;

    // When proxy_did is did:webvh, build the parallel did:web document from the latest log entry.
    // When the log file doesn't exist yet (pre-migration), fall through to legacy did:web document.
    let mut did_doc = if proxy_did.starts_with("did:webvh:") {
        #[cfg(feature = "didwebvh")]
        {
            let log_path = state
                .vc_issuer
                .get_storage_path()
                .await
                .join("did.jsonl");
            let scid = extract_scid_from_webvh_did(&proxy_did);
            match load_latest_log_state_as_json(&log_path).await {
                Some(state_doc) => crate::identity::didwebvh::generate_parallel_did_web(&state_doc, &proxy_did, &scid),
                None => {
                    // Log not yet written (pre-migration); serve the legacy did:web document
                    state
                        .vc_issuer
                        .get_did_document()
                        .await
                        .map_err(|e| {
                            error!(error = %e, "Failed to get gateway DID document");
                            AppError::InternalError(format!("Failed to get DID document: {}", e))
                        })?
                }
            }
        }
        #[cfg(not(feature = "didwebvh"))]
        {
            state
                .vc_issuer
                .get_did_document()
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to get gateway DID document (non-didwebvh)");
                    AppError::InternalError(format!("Failed to get DID document: {}", e))
                })?
        }
    } else {
        // Legacy did:web path — get the document from VCIssuer
        state
            .vc_issuer
            .get_did_document()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get gateway DID document");
                AppError::InternalError(format!("Failed to get DID document: {}", e))
            })?
    };

    // Inject channel services for channels marked as publish_to_did_document
    let config = state
        .channel_manager
        .get_config()
        .await;
    let gateway_did = proxy_did;

    // Ensure the `service` array exists before injecting channel services
    if let Some(obj) = did_doc.as_object_mut() {
        obj.entry("service")
            .or_insert_with(|| serde_json::Value::Array(vec![]));
    }

    let services = did_doc
        .get_mut("service")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| {
            error!("DID document missing 'service' array");
            AppError::InternalError("Invalid DID document structure".to_string())
        })?;

    // Add channel services
    for surface in &config.surfaces {
        if surface
            .access_point
            .publish_to_did_document
            && surface.status == crate::config::agent_surface::SurfaceStatus::Active
        {
            let channel_id = surface
                .config_id()
                .unwrap_or(&surface.name);
            let listen_address = surface.listen_address();
            let route = surface.route();

            let listener_http = if let Some(port) = state
                .network_config
                .map_url_to_port(listen_address)
            {
                state
                    .network_config
                    .listeners
                    .iter()
                    .find(|l| l.port == port)
                    .and_then(|l| l.external_urls.first())
                    .map(|url| {
                        if route == "/" {
                            url.clone()
                        } else {
                            format!("{}{}", url, route)
                        }
                    })
            } else {
                None
            };

            let listener_http = listener_http.unwrap_or_else(|| {
                format!(
                    "https://{}{}",
                    listen_address,
                    if route == "/" {
                        ""
                    } else {
                        route
                    }
                )
            });

            let channel_service = serde_json::json!({
                "id": format!("{}/channel#{}", gateway_did, channel_id),
                "serviceEndpoint": [{
                    "accept": ["application/json"],
                    "uri": listener_http
                }],
                "type": "AffinidiFabricAgentGatewayChannel"
            });

            services.push(channel_service);
            info!("Injected channel service for '{}' into DID document", surface.name);
        }
    }

    info!("Successfully served gateway DID document with {} service(s)", services.len());
    Ok(Json(did_doc))
}

/// Handler for serving agent DID documents at /channel/{channel_id}/did.json
/// This enables did:web resolution for channel identities
pub async fn serve_agent_did_document(
    Extension(vc_issuer): Extension<Arc<VCIssuer>>,
    Extension(_bootstrap_config): Extension<Arc<BootstrapConfig>>,
    Extension(network_config): Extension<Arc<crate::config::NetworkConfig>>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    use crate::identity::ssi::did_utils::jwk_to_multibase_ed25519;
    use serde_json::json;

    info!("Serving channel DID document for channel ID: {}", channel_id);

    // Construct the expected DID from the channel_id
    // URL-encode the colon in the domain for did:web spec compliance
    let proxy_domain = network_config
        .did
        .domain
        .replace(":", "%3A");
    let agent_did = format!("did:web:{}:surface:{}", proxy_domain, channel_id);

    // Get the agent's identity record by DID
    let identity_store = vc_issuer.get_identity_store();
    let agent_record = identity_store
        .find_by_did(&agent_did)
        .await
        .map_err(|e| {
            error!(error = %e, agent_did = %agent_did, "Failed to find agent identity");
            AppError::InternalError(format!("Failed to find agent identity: {}", e))
        })?;

    let agent_record = match agent_record {
        Some(record) => record,
        None => {
            let fallback_record =
                find_local_channel_identity_record_by_tail(identity_store.clone(), &channel_id).await?;
            let record = fallback_record.ok_or_else(|| {
                warn!(agent_did = %agent_did, channel_id = %channel_id, "Agent identity not found for channel DID route");
                AppError::BadRequest(format!("Agent identity not found: {}", agent_did))
            })?;

            info!(
                requested_did = %agent_did,
                stored_did = %record.did,
                surface_id = %channel_id,
                "Resolved channel DID document via local tail fallback"
            );
            record
        }
    };

    // Use the DID from the stored record to ensure consistent encoding
    let agent_did = agent_record.did.clone();

    // Extract the public key from the agent's private key
    let private_key_json = agent_record
        .private_key
        .ok_or_else(|| {
            error!("Agent identity has no private key: {}", agent_did);
            AppError::InternalError("Agent identity has no private key".to_string())
        })?;

    let jwk: ssi::jwk::JWK = serde_json::from_value(private_key_json).map_err(|e| {
        error!(error = %e, "Failed to deserialize agent JWK");
        AppError::InternalError("Failed to deserialize agent JWK".to_string())
    })?;

    // Convert JWK to public key only (remove private key component)
    let mut public_jwk = serde_json::to_value(&jwk).map_err(|e| {
        error!(error = %e, "Failed to serialize JWK");
        AppError::InternalError("Failed to serialize JWK".to_string())
    })?;

    // Remove private key component 'd' to make it public
    if let Some(obj) = public_jwk.as_object_mut() {
        obj.remove("d");
    }

    // Convert JWK to multibase format for Multikey verification method
    // This is needed because VP signatures use EdDsaRdfc2022 which references #key-2 (Multikey format)
    let public_key_multibase = jwk_to_multibase_ed25519(&jwk).map_err(|e| {
        error!(error = %e, "Failed to convert JWK to multibase");
        AppError::InternalError("Failed to convert JWK to multibase".to_string())
    })?;

    // Build DID document following W3C DID Core specification
    // Include both JsonWebKey2020 (#key-1) and Multikey (#key-2) formats
    // VP signatures use EdDsaRdfc2022 cryptosuite which expects Multikey format
    let did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": agent_did,
        "verificationMethod": [
            {
                "id": format!("{}#key-1", agent_did),
                "type": "JsonWebKey2020",
                "controller": agent_did,
                "publicKeyJwk": public_jwk
            },
            {
                "id": format!("{}#key-2", agent_did),
                "type": "Multikey",
                "controller": agent_did,
                "publicKeyMultibase": public_key_multibase
            }
        ],
        "authentication": [
            format!("{}#key-1", agent_did)
        ],
        "assertionMethod": [
            format!("{}#key-1", agent_did),
            format!("{}#key-2", agent_did)
        ]
    });

    info!("Successfully generated DID document for agent: {}", agent_did);
    Ok(Json(did_document))
}

// ─── did.jsonl serving helpers ────────────────────────────────────────────────

/// Extract the SCID segment from a `did:webvh:<SCID>:<domain>...` string.
/// Returns an empty string if the DID is not well-formed.
fn extract_scid_from_webvh_did(did: &str) -> String {
    // did:webvh:<SCID>:<domain>... — split on ':' → ["did", "webvh", "<SCID>", ...]
    let parts: Vec<&str> = did.splitn(4, ':').collect();
    if parts.len() >= 3 {
        parts[2].to_string()
    } else {
        String::new()
    }
}

/// Read a `did.jsonl` file, parse each line as a log entry, and return the
/// `state` field (DID document) from the **latest** entry as a `serde_json::Value`.
/// Returns `None` when the file is absent or contains no valid entries.
#[cfg(feature = "didwebvh")]
async fn load_latest_log_state_as_json(path: &std::path::Path) -> Option<serde_json::Value> {
    use crate::identity::didwebvh::types::LogEntry;

    let dir = path.parent()?;
    let content = crate::storage::did_artifacts::read_did_log_raw(dir)
        .await
        .ok()
        .flatten()?;
    let latest: LogEntry = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .next_back()?;
    serde_json::to_value(&latest.state).ok()
}

/// Read a `did.jsonl` file and return an HTTP response with the appropriate
/// Content-Type and CORS headers, or a RFC 9457 problem-details body on error.
async fn serve_did_jsonl_file(path: &std::path::Path) -> Response {
    let dir = path.parent().unwrap_or(path);
    match crate::storage::did_artifacts::read_did_log_raw(dir).await {
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
                "detail": "DID log not found for the requested path"
            });
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/problem+json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                problem.to_string(),
            )
                .into_response()
        }
        Err(e) => {
            error!(error = %e, path = %path.display(), "Failed to read did.jsonl");
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

/// Handler for `GET /.well-known/did.jsonl`
///
/// Serves the gateway's verifiable DID log for did:webvh resolution.
/// Returns 404 (RFC 9457 problem-details) when the log has not been
/// created yet (e.g. before the proxy_did migration to did:webvh).
///
pub async fn serve_gateway_did_jsonl(State(state): State<crate::identity::state::IdentityApiState>) -> Response {
    let log_path = state
        .vc_issuer
        .get_storage_path()
        .await
        .join("did.jsonl");
    serve_did_jsonl_file(&log_path).await
}

/// Handler for `GET /channel/{channel_id}/did.jsonl`
///
/// Serves the per-agent verifiable DID log for the given channel UUID.
/// Returns 404 (RFC 9457 problem-details) when the log has not been
/// created yet (e.g. before the agent identity migration to did:webvh).
///
pub async fn serve_surface_did_jsonl(
    State(state): State<crate::identity::state::IdentityApiState>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
) -> Response {
    let fallback_base_path = std::path::Path::new(
        &state
            .bootstrap_config
            .storage_paths
            .identities,
    );
    let log_path = match resolve_channel_did_log_path(
        state
            .vc_issuer
            .get_identity_store(),
        fallback_base_path,
        &channel_id,
    )
    .await
    {
        Ok(path) => path,
        Err(e) => return e.into_response(),
    };
    serve_did_jsonl_file(&log_path).await
}

/// Return an empty did:webvh witness-proofs document (`[]`).
///
/// Gateway and surface identities do not use witnessing, but the did:webvh
/// resolver fetches `did-witness.json` alongside `did.jsonl`. Without a route
/// the request falls through to the SPA static handler and returns HTML, which
/// fails resolution with a witness-proof deserialization error.
fn empty_did_witness_response() -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], "[]")
        .into_response()
}

/// Handler for `GET /.well-known/did-witness.json`
///
/// Serves an empty witness-proofs array for the gateway's did:webvh identity.
pub async fn serve_gateway_did_witness() -> Response {
    empty_did_witness_response()
}

/// Handler for `GET /surface/{surface_id}/did-witness.json`
///
/// Serves an empty witness-proofs array for a surface's did:webvh identity.
pub async fn serve_surface_did_witness(axum::extract::Path(_surface_id): axum::extract::Path<String>) -> Response {
    empty_did_witness_response()
}

#[cfg(test)]
mod tests {
    use crate::identity::FilesystemIdentityStore;
    use crate::identity::didwebvh::types::{LogEntry, LogParameters};
    use crate::identity::{
        IdentityStore, VpChallengeStore, vc_issuer::VCIssuer, vp_challenge_store::FilesystemVpChallengeStore,
    };
    use std::sync::Arc;

    /// Build a VCIssuer with real filesystem stores in `base_dir`.
    async fn make_issuer(base_dir: &std::path::Path) -> VCIssuer {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let id_store = Arc::new(
            FilesystemIdentityStore::new(base_dir.join("identity"))
                .await
                .unwrap(),
        ) as Arc<dyn IdentityStore>;
        let vp_store = Arc::new(
            FilesystemVpChallengeStore::new(base_dir.join("vp_challenges"))
                .await
                .unwrap(),
        ) as Arc<dyn VpChallengeStore>;
        VCIssuer::new(base_dir.join("issuer"), "proxy.example.com", id_store, vp_store, None, None)
            .await
            .unwrap()
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn resolves_local_didwebvh_from_identity_store_log_path() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FilesystemIdentityStore::new(tmp.path())
                .await
                .unwrap(),
        ) as Arc<dyn IdentityStore>;

        let did = "did:webvh:zQmTestScid:example.com:surface:123e4567-e89b-12d3-a456-426614174000";
        let identity_id = "123e4567-e89b-12d3-a456-426614174000";

        store
            .create(crate::identity::AgentIdentityRecord {
                did: did.to_string(),
                identity_hash: "hash-123".to_string(),
                created_at: chrono::Utc::now(),
                identity_fields: std::collections::HashMap::new(),
                usage_count: 0,
                last_used_at: None,
                channel_usage: vec![],
                private_key: None,
                channel_config_id: None,
                is_local: true,
                verified: true,
            })
            .await
            .unwrap();

        let entry = LogEntry {
            version_id: "1-hash".to_string(),
            version_time: "2026-04-16T00:00:00Z".to_string(),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "zQmTestScid".to_string(),
                update_keys: vec![],
                next_key_hashes: None,
                portable: false,
                ttl: None,
                witness: None,
                watchers: None,
                deactivated: false,
            },
            state: affinidi_did_common::Document::new(did).unwrap(),
            proof: vec![],
        };

        let log_dir = tmp.path().join(identity_id);
        tokio::fs::create_dir_all(&log_dir)
            .await
            .unwrap();
        tokio::fs::write(log_dir.join("did.jsonl"), format!("{}\n", serde_json::to_string(&entry).unwrap()))
            .await
            .unwrap();

        let resolved = super::try_resolve_local_identity_store_didwebvh(store, did)
            .await
            .unwrap()
            .expect("local identity-store did.jsonl should resolve");

        assert_eq!(
            resolved
                .get("id")
                .and_then(|value| value.as_str()),
            Some(did)
        );
    }

    #[tokio::test]
    async fn finds_local_channel_identity_by_tail_when_domain_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FilesystemIdentityStore::new(tmp.path())
                .await
                .unwrap(),
        ) as Arc<dyn IdentityStore>;

        let channel_id = "123e4567-e89b-12d3-a456-426614174000";
        let did = format!("did:webvh:zQmStoredScid:stored.example.com:surface:{}", channel_id);

        store
            .create(crate::identity::AgentIdentityRecord {
                did: did.clone(),
                identity_hash: "hash-456".to_string(),
                created_at: chrono::Utc::now(),
                identity_fields: std::collections::HashMap::new(),
                usage_count: 0,
                last_used_at: None,
                channel_usage: vec![],
                private_key: None,
                channel_config_id: None,
                is_local: true,
                verified: true,
            })
            .await
            .unwrap();

        let record = super::find_local_channel_identity_record_by_tail(store, channel_id)
            .await
            .unwrap()
            .expect("channel-tail fallback should find the local identity record");

        assert_eq!(record.did, did);
    }

    #[tokio::test]
    async fn channel_did_log_path_prefers_identity_store_base_path() {
        let tmp = tempfile::tempdir().unwrap();
        let identity_base = tmp
            .path()
            .join("identity-store");
        let fallback_base = tmp
            .path()
            .join("bootstrap-identities");
        let store = Arc::new(
            FilesystemIdentityStore::new(&identity_base)
                .await
                .unwrap(),
        ) as Arc<dyn IdentityStore>;

        let channel_id = "123e4567-e89b-12d3-a456-426614174000";
        let did = format!("did:webvh:zQmStoredScid:stored.example.com:surface:{}", channel_id);

        store
            .create(crate::identity::AgentIdentityRecord {
                did,
                identity_hash: "hash-789".to_string(),
                created_at: chrono::Utc::now(),
                identity_fields: std::collections::HashMap::new(),
                usage_count: 0,
                last_used_at: None,
                channel_usage: vec![],
                private_key: None,
                channel_config_id: None,
                is_local: true,
                verified: true,
            })
            .await
            .unwrap();

        let expected_path = identity_base
            .join(channel_id)
            .join("did.jsonl");
        tokio::fs::create_dir_all(
            expected_path
                .parent()
                .unwrap(),
        )
        .await
        .unwrap();
        tokio::fs::write(&expected_path, "{}\n")
            .await
            .unwrap();

        let resolved_path = super::resolve_channel_did_log_path(store, &fallback_base, channel_id)
            .await
            .unwrap();

        assert_eq!(resolved_path, expected_path);
    }

    // === did.jsonl HTTP Infrastructure Tests ===
    /// `serve_did_jsonl_file` returns 200, `Content-Type: text/jsonl`, and valid JSON Lines.
    #[tokio::test]
    async fn did_jsonl_returns_200_with_correct_content_type() {
        use axum::http::StatusCode;

        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("did.jsonl");
        let content = r#"{"versionId":"1-abc","versionTime":"2024-01-01T00:00:00Z"}"#;
        tokio::fs::write(&log_path, content)
            .await
            .unwrap();

        let response = super::serve_did_jsonl_file(&log_path).await;
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("must have Content-Type header");
        assert_eq!(ct, "text/jsonl");
    }

    /// `serve_did_jsonl_file` returns 404 with an RFC 9457 body when the file is absent.
    #[tokio::test]
    async fn did_jsonl_returns_404_for_nonexistent_file() {
        use axum::http::StatusCode;

        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp
            .path()
            .join("nonexistent.jsonl");

        let response = super::serve_did_jsonl_file(&log_path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let ct = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("must have Content-Type header");
        assert_eq!(ct, "application/problem+json");
    }

    /// `serve_did_jsonl_file` includes `Access-Control-Allow-Origin: *` on 200 responses.
    #[tokio::test]
    async fn did_jsonl_includes_cors_header() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("did.jsonl");
        tokio::fs::write(&log_path, "{}")
            .await
            .unwrap();

        let response = super::serve_did_jsonl_file(&log_path).await;
        let cors = response
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("must have Access-Control-Allow-Origin header");
        assert_eq!(cors, "*");
    }

    /// The same CORS header is also present on 404 responses.
    #[tokio::test]
    async fn did_jsonl_404_includes_cors_header() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp
            .path()
            .join("does_not_exist.jsonl");

        let response = super::serve_did_jsonl_file(&log_path).await;
        let cors = response
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("must have Access-Control-Allow-Origin header on 404");
        assert_eq!(cors, "*");
    }

    // === Per-Agent Credential DID Tests ===
    /// Same metadata produces the same DID on repeated calls.
    #[tokio::test]
    async fn agent_did_deterministic_from_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let mut fields = std::collections::HashMap::new();
        fields.insert("agentIdentity".to_string(), serde_json::json!({"model": "gpt-4", "provider": "openai"}));

        let r1 = issuer
            .issue_or_get_credential(fields.clone(), None, None, None)
            .await
            .unwrap();
        let r2 = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();

        assert_eq!(r1.did, r2.did, "Same metadata must yield the same DID on repeated calls");
    }

    /// Agent DID follows format did:web:<domain>:surface:<UUID>.
    #[tokio::test]
    async fn agent_did_format_includes_surface_segment() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let mut fields = std::collections::HashMap::new();
        fields.insert("agentIdentity".to_string(), serde_json::json!({"model": "test-model"}));

        let response = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();

        let parts: Vec<&str> = response
            .did
            .split(':')
            .collect();
        assert!(parts.len() >= 5, "Agent DID must have at least 5 colon-delimited parts, got: {}", response.did);
        let surface_idx = parts.len() - 2;
        assert_eq!(
            parts[surface_idx], "surface",
            "Second-to-last segment of agent DID must be 'surface', got: {}",
            response.did
        );
    }

    /// Different metadata produces different DIDs.
    #[tokio::test]
    async fn different_metadata_different_dids() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let mut fields_a = std::collections::HashMap::new();
        fields_a.insert("agentIdentity".to_string(), serde_json::json!({"model": "gpt-4"}));

        let mut fields_b = std::collections::HashMap::new();
        fields_b.insert("agentIdentity".to_string(), serde_json::json!({"model": "claude-3"}));

        let r_a = issuer
            .issue_or_get_credential(fields_a, None, None, None)
            .await
            .unwrap();
        let r_b = issuer
            .issue_or_get_credential(fields_b, None, None, None)
            .await
            .unwrap();

        assert_ne!(r_a.did, r_b.did, "Different metadata must produce different DIDs");
    }

    /// First issuance must return is_new = true.
    #[tokio::test]
    async fn first_issuance_returns_is_new_true() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let mut fields = std::collections::HashMap::new();
        fields.insert("agentIdentity".to_string(), serde_json::json!({"model": "brand-new-agent"}));

        let response = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();
        assert!(response.is_new, "First issuance must set is_new = true");
    }

    /// Second issuance for the same metadata must return is_new = false.
    #[tokio::test]
    async fn second_issuance_returns_is_new_false() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let mut fields = std::collections::HashMap::new();
        fields.insert("agentIdentity".to_string(), serde_json::json!({"model": "returning-agent"}));

        let _first = issuer
            .issue_or_get_credential(fields.clone(), None, None, None)
            .await
            .unwrap();
        let second = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();

        assert!(!second.is_new, "Second issuance for the same metadata must set is_new = false");
    }

    #[test]
    fn did_resolution_authority_mirrors_resolver_host_selection() {
        let authority = |did: &str| super::did_resolution_authority(did).unwrap();
        assert_eq!(authority("did:web:example.com"), Some("example.com".to_string()));
        assert_eq!(authority("did:web:example.com%3A8443:surface:abc"), Some("example.com:8443".to_string()));
        assert_eq!(
            authority("did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:example.com:agents:alpha"),
            Some("example.com".to_string())
        );
        assert_eq!(
            authority("did:scid:vh:1:abcde?src=https://example.com:3000/path"),
            Some("example.com:3000".to_string())
        );
        assert_eq!(authority("did:key:z6Mkexample"), None);
        assert!(super::did_resolution_authority("did:webvh:onlyscid").is_err());
        assert!(super::did_resolution_authority("did:scid:vh:1:abcde").is_err());
        assert!(super::did_resolution_authority("did:web::surface:abc").is_err());
    }

    /// Every case is rejected statically (IP literal, `localhost`, metadata
    /// hostname or embedded credentials), so no DNS lookup and no connection
    /// attempt happens.
    #[tokio::test]
    async fn did_resolution_egress_blocks_loopback_private_link_local_and_metadata() {
        for did in [
            "did:web:127.0.0.1",
            "did:web:[::1]",
            "did:web:2130706433",
            "did:web:localhost%3A8443:surface:abc",
            "did:web:10.0.0.1",
            "did:web:172.16.0.1",
            "did:web:192.168.1.1%3A8080",
            "did:web:169.254.1.1",
            "did:web:169.254.169.254",
            "did:web:metadata.google.internal",
            "did:web:127.0.0.1@example.com",
            "did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:localhost",
            "did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:169.254.169.254",
            "did:scid:vh:1:abcde?src=localhost:3000/path",
            "did:scid:vh:1:abcde?src=http://10.0.0.1/path",
        ] {
            assert!(
                super::vet_did_resolution_egress(did)
                    .await
                    .is_err(),
                "{did} must be refused before any outbound attempt"
            );
        }
    }

    #[tokio::test]
    async fn did_resolution_egress_allows_public_hosts_and_offline_methods() {
        for did in [
            "did:web:8.8.8.8",
            "did:web:example.com:surface:abc",
            "did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:example.com%3A8443:agents:alpha",
            "did:key:z6Mkexample",
        ] {
            assert!(
                super::vet_did_resolution_egress(did)
                    .await
                    .is_ok(),
                "{did} must pass egress validation"
            );
        }
    }

    #[test]
    fn channel_did_log_path_rejects_traversal_and_stays_within_base() {
        let tmp = tempfile::tempdir().unwrap();
        for channel_id in ["../../etc", "../did.jsonl", "..", ".", "", "/etc/passwd", "a/b", "./x"] {
            assert!(
                matches!(super::channel_did_log_path(tmp.path(), channel_id), Err(super::AppError::BadRequest(_))),
                "{channel_id:?} must be rejected"
            );
        }

        let channel_id = "123e4567-e89b-12d3-a456-426614174000";
        let path = super::channel_did_log_path(tmp.path(), channel_id).unwrap();
        assert_eq!(
            path,
            tmp.path()
                .join(channel_id)
                .join("did.jsonl")
        );

        let still_encoded = super::channel_did_log_path(tmp.path(), "..%2F..%2Fetc").unwrap();
        assert_eq!(
            still_encoded
                .parent()
                .and_then(|p| p.parent()),
            Some(tmp.path())
        );
    }

    #[tokio::test]
    async fn channel_did_log_path_lookup_rejects_traversal_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FilesystemIdentityStore::new(
                tmp.path()
                    .join("identity-store"),
            )
            .await
            .unwrap(),
        ) as Arc<dyn IdentityStore>;

        let result = super::resolve_channel_did_log_path(
            store,
            &tmp.path()
                .join("bootstrap-identities"),
            "../../etc",
        )
        .await;

        assert!(matches!(result, Err(super::AppError::BadRequest(_))), "got {result:?}");
    }
}
