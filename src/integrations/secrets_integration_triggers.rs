//! Secrets Vault Integration Event Triggers
//!
//! Triggers integration events when secrets vault operations occur.

use super::filesystem::FileSystemNotificationStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// Secret entity structure for triggers (without sensitive value)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Trigger when a secret is created
pub async fn trigger_secret_created(
    integration_store: &FileSystemNotificationStore,
    secret: &Secret,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&secret).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "secret.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("SECRET_ID".to_string(), secret.id.clone());
    runtime_values.insert("SECRET_NAME".to_string(), secret.name.clone());
    runtime_values.insert("SECRET_DESCRIPTION".to_string(), secret.description.clone());
    runtime_values.insert("SECRET_TAGS".to_string(), secret.tags.join(", "));

    trigger_secret_integrations(integration_store, &runtime_values, "secret.created").await;
}

/// Trigger when a secret is updated
pub async fn trigger_secret_updated(
    integration_store: &FileSystemNotificationStore,
    old_secret: &Secret,
    new_secret: &Secret,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_secret).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_secret).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "secret.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("SECRET_ID".to_string(), new_secret.id.clone());
    runtime_values.insert("SECRET_NAME".to_string(), new_secret.name.clone());
    runtime_values.insert("SECRET_DESCRIPTION".to_string(), new_secret.description.clone());
    runtime_values.insert("SECRET_TAGS".to_string(), new_secret.tags.join(", "));

    trigger_secret_integrations(integration_store, &runtime_values, "secret.updated").await;
}

/// Trigger when a secret is deleted
pub async fn trigger_secret_deleted(
    integration_store: &FileSystemNotificationStore,
    secret: &Secret,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&secret).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "secret.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("SECRET_ID".to_string(), secret.id.clone());
    runtime_values.insert("SECRET_NAME".to_string(), secret.name.clone());
    runtime_values.insert("SECRET_DESCRIPTION".to_string(), secret.description.clone());
    runtime_values.insert("SECRET_TAGS".to_string(), secret.tags.join(", "));

    trigger_secret_integrations(integration_store, &runtime_values, "secret.deleted").await;
}

/// Internal helper to trigger all integrations (uses global/general integrations)
async fn trigger_secret_integrations(
    _integration_store: &FileSystemNotificationStore,
    _runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    // Placeholder: Secret integrations would be loaded and triggered here
    // This will be fully implemented when global integration filtering is added
    info!("Secret integration trigger: {} (placeholder - not yet fully implemented)", event_type);
}
