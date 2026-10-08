use axum::{Extension, http::StatusCode, response::Json};
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::error;

use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::PatResourceScope;
use crate::config::BootstrapConfig;
use crate::integrations::identity_integration_triggers::IDENTITY_MAPPING_RULES;
use crate::integrations::identity_integrations_storage::IdentityIntegrationsStorage;
use crate::integrations::trigger_mappings::{Caller, MappingsRequest, replace_mappings};
use crate::storage::IntegrationStorage;
use crate::tenancy::PatTenantContext;

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
/// Replace the integrations attached to identity events
pub async fn update_identity_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>,
    Extension(integration_store): Extension<Arc<IntegrationStorage>>,
    caller: Option<Extension<AuthGuardOk>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(payload): Json<MappingsRequest>,
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

    let mappings = replace_mappings(
        &storage,
        payload,
        &IDENTITY_MAPPING_RULES,
        &integration_store,
        Caller {
            actor: caller
                .as_ref()
                .map(|Extension(AuthGuardOk(id))| id.as_str()),
            context: context
                .as_ref()
                .map(|Extension(context)| context),
            scope: scope
                .as_ref()
                .map(|Extension(scope)| scope),
        },
    )
    .await?;

    Ok(Json(json!({
        "message": "Identity integrations updated successfully",
        "integration_integrations": mappings
    })))
}
