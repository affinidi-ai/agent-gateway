use axum::{
    Extension, Json,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::identity::state::IdentityApiState;
use crate::rbac::{Feature, RbacConfig};

/// Request body for the debug export endpoint.
#[derive(Debug, Deserialize)]
pub struct ExportStorageRequest {
    /// Ed25519 public key in PEM format
    pub public_key_pem: String,
}

/// RBAC guard for the full-storage export endpoint.
///
/// Returns `Some(response)` (403 or 500) when the caller is NOT permitted, and
/// `None` when the caller holds the administrator-only `storage.admin` permission.
async fn deny_unless_storage_admin(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
) -> Option<Response> {
    match storage
        .load_user_by_id(user_id)
        .await
    {
        Ok(Some(user)) if rbac_config.has_permission(&user.role, &Feature::StorageAdmin) => None,
        Ok(_) => {
            warn!(user_id = %user_id, feature = "storage.admin", "Storage export rejected — insufficient permissions");
            Some(
                (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response(),
            )
        }
        Err(e) => {
            error!(user_id = %user_id, "RBAC check failed loading user: {}", e);
            Some(
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Authorization check failed"})))
                    .into_response(),
            )
        }
    }
}

/// Export storage with PII redaction, encrypted with the provided Ed25519 public key.
///
/// Returns the encrypted ATGX file as a binary download.
pub async fn export_storage(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<IdentityApiState>,
    Json(req): Json<ExportStorageRequest>,
) -> Response {
    if let Some(resp) = deny_unless_storage_admin(&user_id, &passkey_storage, &rbac_config).await {
        return resp;
    }

    info!("Storage export requested via API");

    if req
        .public_key_pem
        .trim()
        .is_empty()
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "public_key_pem is required"})))
            .into_response();
    }

    // Resolve storage root from bootstrap config
    let storage_root = crate::export::resolve_storage_root(
        &state
            .bootstrap_config
            .storage_paths
            .agent_surfaces,
        "",
    );

    // Build encrypted export (blocking I/O — run in spawn_blocking)
    let pubkey_pem = req.public_key_pem.clone();
    let result =
        tokio::task::spawn_blocking(move || crate::export::build_encrypted_export(&storage_root, &pubkey_pem)).await;

    match result {
        Ok(Ok(encrypted_bytes)) => {
            let size = encrypted_bytes.len();
            info!("Storage export complete: {} bytes", size);

            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"storage-export.agx\""),
            );

            (StatusCode::OK, headers, Body::from(encrypted_bytes)).into_response()
        }
        Ok(Err(e)) => {
            error!("Storage export failed: {:#}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Export failed: {}", e)})))
                .into_response()
        }
        Err(e) => {
            error!("Storage export task panicked: {:#}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Export task failed"})))
                .into_response()
        }
    }
}
