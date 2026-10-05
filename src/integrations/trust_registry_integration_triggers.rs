//! Trust Registry Integration Event Triggers
//!
//! Triggers integration events when trust registry operations occur.

use super::filesystem::FileSystemNotificationStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// Trust registry entity structure for triggers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRegistry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub did: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Trigger when a trust registry is created
pub async fn trigger_trust_registry_created(
    integration_store: &FileSystemNotificationStore,
    trust_registry: &TrustRegistry,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&trust_registry).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "trust_registry.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("TRUST_REGISTRY_ID".to_string(), trust_registry.id.clone());
    runtime_values.insert("TRUST_REGISTRY_NAME".to_string(), trust_registry.name.clone());
    runtime_values.insert(
        "TRUST_REGISTRY_DESCRIPTION".to_string(),
        trust_registry
            .description
            .clone(),
    );
    runtime_values.insert("TRUST_REGISTRY_DID".to_string(), trust_registry.did.clone());
    runtime_values.insert("TRUST_REGISTRY_STATUS".to_string(), trust_registry.status.clone());

    trigger_trust_registry_integrations(integration_store, &runtime_values, "trust_registry.created").await;
}

/// Trigger when a trust registry is updated
pub async fn trigger_trust_registry_updated(
    integration_store: &FileSystemNotificationStore,
    old_trust_registry: &TrustRegistry,
    new_trust_registry: &TrustRegistry,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_trust_registry).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_trust_registry).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "trust_registry.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("TRUST_REGISTRY_ID".to_string(), new_trust_registry.id.clone());
    runtime_values.insert(
        "TRUST_REGISTRY_NAME".to_string(),
        new_trust_registry
            .name
            .clone(),
    );
    runtime_values.insert(
        "TRUST_REGISTRY_DESCRIPTION".to_string(),
        new_trust_registry
            .description
            .clone(),
    );
    runtime_values.insert("TRUST_REGISTRY_DID".to_string(), new_trust_registry.did.clone());
    runtime_values.insert(
        "TRUST_REGISTRY_STATUS".to_string(),
        new_trust_registry
            .status
            .clone(),
    );

    trigger_trust_registry_integrations(integration_store, &runtime_values, "trust_registry.updated").await;
}

/// Trigger when a trust registry is deleted
pub async fn trigger_trust_registry_deleted(
    integration_store: &FileSystemNotificationStore,
    trust_registry: &TrustRegistry,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&trust_registry).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "trust_registry.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("TRUST_REGISTRY_ID".to_string(), trust_registry.id.clone());
    runtime_values.insert("TRUST_REGISTRY_NAME".to_string(), trust_registry.name.clone());
    runtime_values.insert(
        "TRUST_REGISTRY_DESCRIPTION".to_string(),
        trust_registry
            .description
            .clone(),
    );
    runtime_values.insert("TRUST_REGISTRY_DID".to_string(), trust_registry.did.clone());
    runtime_values.insert("TRUST_REGISTRY_STATUS".to_string(), trust_registry.status.clone());

    trigger_trust_registry_integrations(integration_store, &runtime_values, "trust_registry.deleted").await;
}

/// Trigger when a trust registry status changes
pub async fn trigger_trust_registry_status_changed(
    integration_store: &FileSystemNotificationStore,
    old_trust_registry: &TrustRegistry,
    new_trust_registry: &TrustRegistry,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_trust_registry).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_trust_registry).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "trust_registry.status_changed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("TRUST_REGISTRY_ID".to_string(), new_trust_registry.id.clone());
    runtime_values.insert(
        "TRUST_REGISTRY_NAME".to_string(),
        new_trust_registry
            .name
            .clone(),
    );
    runtime_values.insert(
        "TRUST_REGISTRY_DESCRIPTION".to_string(),
        new_trust_registry
            .description
            .clone(),
    );
    runtime_values.insert("TRUST_REGISTRY_DID".to_string(), new_trust_registry.did.clone());
    runtime_values.insert(
        "TRUST_REGISTRY_STATUS".to_string(),
        new_trust_registry
            .status
            .clone(),
    );

    trigger_trust_registry_integrations(integration_store, &runtime_values, "trust_registry.status_changed").await;
}

/// Internal helper to trigger all integrations (uses global/general integrations)
async fn trigger_trust_registry_integrations(
    _integration_store: &FileSystemNotificationStore,
    _runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    // Placeholder: Trust registry integrations would be loaded and triggered here
    // This will be fully implemented when global integration filtering is added
    info!("Trust registry integration trigger: {} (placeholder - not yet fully implemented)", event_type);
}
