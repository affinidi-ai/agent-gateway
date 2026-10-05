use axum::{Extension, http::StatusCode, response::Json};
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::{error, info};

use crate::config::BootstrapConfig;
use crate::integrations::user_integrations_storage::{UserIntegrationsConfig, UserIntegrationsStorage};

/// GET /api/v1/users/integrations
/// Get the current user integrations configuration
pub async fn get_user_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let storage_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    )
    .join("users");

    let storage = UserIntegrationsStorage::new(storage_path)
        .await
        .map_err(|e| {
            error!("Failed to create user integrations storage: {}", e);
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
            error!("Failed to load user integrations: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to load user integrations"
                })),
            )
        })?;

    Ok(Json(json!(config)))
}

/// PUT /api/v1/users/integrations
/// Update the user integrations configuration
pub async fn update_user_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>,
    Json(payload): Json<UserIntegrationsConfig>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    info!(
        "Updating user integrations with {} integrations",
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
    .join("users");

    let storage = UserIntegrationsStorage::new(storage_path)
        .await
        .map_err(|e| {
            error!("Failed to create user integrations storage: {}", e);
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
            error!("Failed to save user integrations: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to save user integrations"
                })),
            )
        })?;

    info!("Successfully saved user integrations");
    Ok(Json(json!({
        "message": "User integrations updated successfully",
        "integration_integrations": payload.integration_integrations
    })))
}
