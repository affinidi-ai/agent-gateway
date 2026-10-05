use axum::{Extension, http::StatusCode, response::Json};
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::{error, info};

use crate::config::BootstrapConfig;
use crate::integrations::identity_integrations_storage::{IdentityIntegrationsConfig, IdentityIntegrationsStorage};

/// GET /api/v1/identities/integrations
/// Get the current identity integrations configuration
pub async fn get_identity_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let storage_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    )
    .join("identities");

    let storage = IdentityIntegrationsStorage::new(storage_path)
        .await
        .map_err(|e| {
            error!("Failed to create identity integrations storage: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to initialize storage"
                })),
            )
        })?;

    let config = storage
        .load()
        .await
        .map_err(|e| {
            error!("Failed to load identity integrations: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to load identity integrations"
                })),
            )
        })?;

    Ok(Json(json!(config)))
}

/// PUT /api/v1/identities/integrations
/// Update the identity integrations configuration
pub async fn update_identity_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>,
    Json(payload): Json<IdentityIntegrationsConfig>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    info!(
        "Updating identity integrations with {} integrations",
        payload
            .integration_integrations
            .len()
    );

    // Log each integration's event_types for debugging
    for (idx, integration) in payload
        .integration_integrations
        .iter()
        .enumerate()
    {
        info!(
            "Integration {}: integration_id={}, event_types={:?}, variables={:?}",
            idx,
            integration.integration_id,
            integration.event_types,
            integration.variables.keys()
        );
    }

    let storage_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    )
    .join("identities");

    let storage = IdentityIntegrationsStorage::new(storage_path)
        .await
        .map_err(|e| {
            error!("Failed to create identity integrations storage: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to initialize storage"
                })),
            )
        })?;

    storage
        .save(&payload)
        .await
        .map_err(|e| {
            error!("Failed to save identity integrations: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to save identity integrations"
                })),
            )
        })?;

    info!("Successfully saved identity integrations");
    Ok(Json(json!({
        "message": "Identity integrations updated successfully",
        "integration_integrations": payload.integration_integrations
    })))
}
