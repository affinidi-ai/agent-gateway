use axum::{Extension, Json, extract::State};
use serde::Deserialize;
use tracing::info;

use crate::identity::state::IdentityApiState;
use crate::storage::settings_store::{DashboardSettings, UserSettings};
use std::collections::HashMap;

use super::settings::AppError;

fn with_runtime_feature_flags(
    mut settings: DashboardSettings,
    state: &IdentityApiState,
) -> DashboardSettings {
    settings
        .feature_flags
        .insert("terms".to_string(), state.network_config.terms);
    settings
}

/// Get effective settings for the current user (user overrides merged with system defaults)
pub async fn get_user_settings(
    State(state): State<IdentityApiState>,
    Extension(user_id): Extension<String>,
) -> Result<Json<DashboardSettings>, AppError> {
    let user_settings = state
        .user_settings_store
        .get(&user_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to load user settings: {}", e)))?;

    let system_settings = state.settings_store.get();
    let effective = state
        .user_settings_store
        .merge_with_system(&user_settings, &system_settings);

    Ok(Json(with_runtime_feature_flags(effective, &state)))
}

/// Get only the user's personal overrides (without system defaults merged in)
pub async fn get_user_settings_overrides(
    State(state): State<IdentityApiState>,
    Extension(user_id): Extension<String>,
) -> Result<Json<UserSettings>, AppError> {
    let user_settings = state
        .user_settings_store
        .get(&user_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to load user settings: {}", e)))?;

    Ok(Json(user_settings))
}

/// Update user settings request (all fields optional)
#[derive(Debug, Deserialize)]
pub struct UpdateUserSettingsRequest {
    pub refresh_interval_seconds: Option<u64>,
    pub log_timestamp_format: Option<String>,
    pub bucket_seconds: Option<u64>,
    pub badge_threshold_minutes: Option<u64>,
    pub payments_min_display: Option<u64>,
    pub feature_flags: Option<HashMap<String, bool>>,
}

/// Update the current user's personal settings
pub async fn update_user_settings(
    State(state): State<IdentityApiState>,
    Extension(user_id): Extension<String>,
    Json(req): Json<UpdateUserSettingsRequest>,
) -> Result<Json<DashboardSettings>, AppError> {
    // Load existing user settings and merge in the updates
    let mut user_settings = state
        .user_settings_store
        .get(&user_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to load user settings: {}", e)))?;

    if req
        .refresh_interval_seconds
        .is_some()
    {
        user_settings.refresh_interval_seconds = req.refresh_interval_seconds;
    }
    if req
        .log_timestamp_format
        .is_some()
    {
        user_settings.log_timestamp_format = req.log_timestamp_format;
    }
    if req.bucket_seconds.is_some() {
        user_settings.bucket_seconds = req.bucket_seconds;
    }
    if req
        .badge_threshold_minutes
        .is_some()
    {
        user_settings.badge_threshold_minutes = req.badge_threshold_minutes;
    }
    if req
        .payments_min_display
        .is_some()
    {
        user_settings.payments_min_display = req.payments_min_display;
    }
    if req.feature_flags.is_some() {
        user_settings.feature_flags = req.feature_flags;
    }

    // Save
    state
        .user_settings_store
        .update(&user_id, user_settings.clone())
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    info!("User settings updated for user {}", user_id);

    // Return effective settings (merged with system)
    let system_settings = state.settings_store.get();
    let effective = state
        .user_settings_store
        .merge_with_system(&user_settings, &system_settings);

    Ok(Json(with_runtime_feature_flags(effective, &state)))
}

/// Reset the current user's settings to system defaults
pub async fn reset_user_settings(
    State(state): State<IdentityApiState>,
    Extension(user_id): Extension<String>,
) -> Result<Json<DashboardSettings>, AppError> {
    state
        .user_settings_store
        .delete(&user_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to reset user settings: {}", e)))?;

    info!("User settings reset for user {}", user_id);

    // Return system defaults
    let system_settings = state.settings_store.get();
    Ok(Json(with_runtime_feature_flags(system_settings, &state)))
}
