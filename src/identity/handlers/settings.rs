use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::identity::state::IdentityApiState;
use crate::rbac::{Feature, RbacConfig};
use crate::storage::settings_store::DashboardSettings;

/// Application error type for settings handlers
#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Forbidden(String),
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::BadRequest(msg) => {
                warn!("API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            AppError::Forbidden(msg) => {
                warn!("API Forbidden: {}", msg);
                (StatusCode::FORBIDDEN, "Forbidden", Some(msg.clone()))
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

/// Get current settings
pub async fn get_settings(State(state): State<IdentityApiState>) -> Result<Json<DashboardSettings>, AppError> {
    let mut settings = state.settings_store.get();

    // Never expose the password hash to API consumers
    settings.prometheus_auth_password_hash = String::new();
    settings
        .feature_flags
        .insert("terms".to_string(), state.network_config.terms);

    Ok(Json(settings))
}

/// Helper to check if the calling user has the required RBAC permission.
/// Returns `Ok(())` if the user is authorised, or an `AppError` otherwise.
async fn require_settings_edit(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
) -> Result<(), AppError> {
    let user = storage
        .load_user_by_id(user_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to load user for RBAC check: {}", e)))?
        .ok_or_else(|| AppError::BadRequest("User not found".to_string()))?;

    if !rbac_config.has_permission(&user.role, &Feature::SettingsEdit) {
        warn!(
            user_id = %user_id,
            feature = "settings.edit",
            "System settings modification rejected — insufficient permissions"
        );
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }
    Ok(())
}

/// Update settings request
#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub badge_threshold_minutes: Option<u64>,
    pub metrics_retention_minutes: Option<u64>,
    pub task_activity_window_seconds: Option<u64>,
    pub connections_window_minutes: Option<u64>,
    pub latency_window_minutes: Option<u64>,
    pub onboarding_channel_ttl_seconds: Option<u64>,
    pub refresh_interval_seconds: Option<u64>,
    pub log_timestamp_format: Option<String>,
    pub bucket_seconds: Option<u64>,
    pub feature_flags: Option<HashMap<String, bool>>,
    pub prometheus_auth_enabled: Option<bool>,
    pub prometheus_auth_username: Option<String>,
    /// Plaintext password — hashed with bcrypt before storing.
    pub prometheus_auth_password: Option<String>,
    pub audit_enabled: Option<bool>,
    pub audit_categories: Option<crate::storage::settings_store::AuditCategories>,
    /// Id that fills `${APPLIANCE_ID}`; empty leaves the variable unfilled.
    pub appliance_id: Option<String>,
}

/// Update settings
pub async fn update_settings(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<IdentityApiState>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<DashboardSettings>, AppError> {
    // RBAC: require settings.edit permission
    require_settings_edit(&user_id, &passkey_storage, &rbac_config).await?;

    // Get current settings
    let mut settings = state.settings_store.get();

    // Update provided fields
    if let Some(threshold) = req.badge_threshold_minutes {
        settings.badge_threshold_minutes = threshold;
    }
    if let Some(retention) = req.metrics_retention_minutes {
        settings.metrics_retention_minutes = retention;
    }
    if let Some(window) = req.task_activity_window_seconds {
        settings.task_activity_window_seconds = window;
    }
    if let Some(window) = req.connections_window_minutes {
        settings.connections_window_minutes = window;
    }
    if let Some(window) = req.latency_window_minutes {
        settings.latency_window_minutes = window;
    }
    if let Some(ttl) = req.onboarding_channel_ttl_seconds {
        settings.onboarding_channel_ttl_seconds = ttl;
    }
    if let Some(refresh) = req.refresh_interval_seconds {
        settings.refresh_interval_seconds = refresh;
    }
    if let Some(format) = req.log_timestamp_format {
        settings.log_timestamp_format = format;
    }
    if let Some(bucket) = req.bucket_seconds {
        settings.bucket_seconds = bucket;
    }
    if let Some(flags) = req.feature_flags {
        settings.feature_flags = flags;
    }
    if let Some(enabled) = req.prometheus_auth_enabled {
        if enabled
            && settings
                .prometheus_auth_password_hash
                .is_empty()
            && req
                .prometheus_auth_password
                .is_none()
        {
            return Err(AppError::BadRequest(
                "Password is required when enabling Prometheus authentication for the first time".to_string(),
            ));
        }
        if enabled {
            if let Some(ref username) = req.prometheus_auth_username {
                if username.is_empty() {
                    return Err(AppError::BadRequest("Prometheus auth username cannot be empty".to_string()));
                }
            } else if settings
                .prometheus_auth_username
                .is_empty()
            {
                return Err(AppError::BadRequest(
                    "Username is required when enabling Prometheus authentication for the first time".to_string(),
                ));
            }
        }
        settings.prometheus_auth_enabled = enabled;
    }
    if let Some(username) = req.prometheus_auth_username {
        settings.prometheus_auth_username = username;
    }
    if let Some(password) = req.prometheus_auth_password {
        if password.is_empty() {
            return Err(AppError::BadRequest("Prometheus auth password cannot be empty".to_string()));
        }
        settings.prometheus_auth_password_hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)
            .map_err(|e| AppError::InternalError(format!("Failed to hash password: {e}")))?;
    }
    if let Some(v) = req.audit_enabled {
        settings.audit_enabled = v;
    }
    if let Some(v) = req.audit_categories {
        settings.audit_categories = v;
    }
    if let Some(appliance_id) = req.appliance_id {
        settings.appliance_id = appliance_id
            .trim()
            .to_string();
    }

    // Validate and update settings
    state
        .settings_store
        .update(settings.clone())
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Save to disk
    state
        .settings_store
        .save()
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to save settings: {}", e)))?;

    info!(
        "Settings updated: badge_threshold={} minutes, metrics_retention={} minutes, task_activity_window={} seconds, connections_window={} minutes, latency_window={} minutes, temp_channel_ttl={} seconds",
        settings.badge_threshold_minutes,
        settings.metrics_retention_minutes,
        settings.task_activity_window_seconds,
        settings.connections_window_minutes,
        settings.latency_window_minutes,
        settings.onboarding_channel_ttl_seconds
    );

    // Broadcast dashboard refresh to update UI with new window settings
    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    // Never expose the password hash to API consumers
    settings.prometheus_auth_password_hash = String::new();

    Ok(Json(settings))
}

/// Reset settings to defaults
pub async fn reset_settings(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<IdentityApiState>,
) -> Result<Json<DashboardSettings>, AppError> {
    // RBAC: require settings.edit permission
    require_settings_edit(&user_id, &passkey_storage, &rbac_config).await?;

    // Reset to default settings
    let default_settings = DashboardSettings::default();

    // Update and save
    state
        .settings_store
        .update(default_settings.clone())
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    state
        .settings_store
        .save()
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to save settings: {}", e)))?;

    info!("Settings reset to defaults");

    Ok(Json(default_settings))
}
