use super::filesystem::FileSystemNotificationStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mediator {
    pub id: String,
    pub name: String,
    pub description: String,
    pub did: String,
    pub status: String,
    pub our_did: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Trigger integrations when a mediator is created
pub async fn trigger_mediator_created(
    integration_store: &FileSystemNotificationStore,
    mediator: &Mediator,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&mediator).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "mediator.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("MEDIATOR_ID".to_string(), mediator.id.clone());
    runtime_values.insert("MEDIATOR_NAME".to_string(), mediator.name.clone());
    runtime_values.insert("MEDIATOR_DID".to_string(), mediator.did.clone());

    trigger_mediator_integrations(integration_store, &runtime_values, "mediator.created").await;
}

/// Trigger integrations when a mediator is updated
pub async fn trigger_mediator_updated(
    integration_store: &FileSystemNotificationStore,
    old_mediator: &Mediator,
    new_mediator: &Mediator,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_mediator).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_mediator).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "mediator.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("MEDIATOR_ID".to_string(), new_mediator.id.clone());
    runtime_values.insert("MEDIATOR_NAME".to_string(), new_mediator.name.clone());
    runtime_values.insert("MEDIATOR_DID".to_string(), new_mediator.did.clone());

    trigger_mediator_integrations(integration_store, &runtime_values, "mediator.updated").await;
}

/// Trigger integrations when a mediator is deleted
pub async fn trigger_mediator_deleted(
    integration_store: &FileSystemNotificationStore,
    mediator: &Mediator,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&mediator).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "mediator.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("MEDIATOR_ID".to_string(), mediator.id.clone());
    runtime_values.insert("MEDIATOR_NAME".to_string(), mediator.name.clone());
    runtime_values.insert("MEDIATOR_DID".to_string(), mediator.did.clone());

    trigger_mediator_integrations(integration_store, &runtime_values, "mediator.deleted").await;
}

/// Trigger integrations when a mediator status changes
#[allow(dead_code)]
pub async fn trigger_mediator_status_changed(
    integration_store: &FileSystemNotificationStore,
    mediator: &Mediator,
    old_status: &str,
    new_status: &str,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&mediator).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "mediator.status_changed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("MEDIATOR_ID".to_string(), mediator.id.clone());
    runtime_values.insert("MEDIATOR_NAME".to_string(), mediator.name.clone());
    runtime_values.insert("MEDIATOR_DID".to_string(), mediator.did.clone());
    runtime_values.insert("OLD_STATUS".to_string(), old_status.to_string());
    runtime_values.insert("NEW_STATUS".to_string(), new_status.to_string());

    trigger_mediator_integrations(integration_store, &runtime_values, "mediator.status_changed").await;
}

async fn trigger_mediator_integrations(
    _integration_store: &FileSystemNotificationStore,
    _runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    info!("Mediator integration trigger: {}", event_type);
    // Integration logic will be implemented here
    // This will follow the same pattern as other entity triggers
}
