use super::filesystem::FileSystemNotificationStore;
use crate::integrations::trigger_mappings::MappingRules;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// What an identity integration mapping may name: the events this module raises.
pub const IDENTITY_MAPPING_RULES: MappingRules = MappingRules {
    category: "identity",
    event_types: &[
        "identity.created",
        "identity.updated",
        "identity.deleted",
        "identity.appeared",
        "identity.accessed",
    ],
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub did: String,
    pub identity_type: String,
    pub controller: Option<String>,
    pub public_keys: Option<Vec<String>>,
    pub services: Option<Vec<String>>,
}

/// Trigger integrations when an identity/DID is created
pub async fn trigger_identity_created(
    integration_store: &FileSystemNotificationStore,
    identity: &Identity,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&identity).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "identity.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_identity_integrations(integration_store, &runtime_values, "identity.created").await;
}

/// Trigger integrations when an identity/DID is updated
#[allow(dead_code)]
pub async fn trigger_identity_updated(
    integration_store: &FileSystemNotificationStore,
    old_identity: &Identity,
    new_identity: &Identity,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_identity).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_identity).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "identity.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_identity_integrations(integration_store, &runtime_values, "identity.updated").await;
}

/// Trigger integrations when an identity/DID is deleted
#[allow(dead_code)]
pub async fn trigger_identity_deleted(
    integration_store: &FileSystemNotificationStore,
    identity: &Identity,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&identity).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "identity.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_identity_integrations(integration_store, &runtime_values, "identity.deleted").await;
}

/// Trigger integrations when an identity appears on an Agent Surface
pub async fn trigger_identity_appeared(
    integration_store: &FileSystemNotificationStore,
    identity: &Identity,
    surface_id: &str,
) {
    let mut runtime_values = HashMap::new();

    // Include surface_id in the runtime values
    let mut identity_with_surface = serde_json::to_value(identity).unwrap_or_default();
    if let Some(obj) = identity_with_surface.as_object_mut() {
        obj.insert("surface_id".to_string(), serde_json::Value::String(surface_id.to_string()));
    }

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&identity_with_surface).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "identity.appeared".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_identity_integrations(integration_store, &runtime_values, "identity.appeared").await;
}

/// Trigger integrations when an identity is accessed
pub async fn trigger_identity_accessed(
    integration_store: &FileSystemNotificationStore,
    identity: &Identity,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&identity).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "identity.accessed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_identity_integrations(integration_store, &runtime_values, "identity.accessed").await;
}

async fn trigger_identity_integrations(
    _integration_store: &FileSystemNotificationStore,
    _runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    // Placeholder: Identity integrations would be loaded and triggered here
    // This will be implemented when identity handlers are integrated
    info!("Identity integration trigger: {} (not yet implemented)", event_type);
}
