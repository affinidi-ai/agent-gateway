use super::filesystem::FileSystemNotificationStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoint {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub gateway_id: String,
    pub did: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub status: Option<String>,
    pub connection_count: Option<u32>,
}

/// Trigger integrations when a connection point is created
/// Trigger connection point integrations for connection_point.created event
pub async fn trigger_connection_point_created(
    integration_store: &FileSystemNotificationStore,
    connection_point: &ConnectionPoint,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&connection_point).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "connection_point.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_connection_point_integrations(integration_store, &runtime_values, "connection_point.created").await;
}

/// Trigger integrations when a connection point is updated
pub async fn trigger_connection_point_updated(
    integration_store: &FileSystemNotificationStore,
    old_connection_point: &ConnectionPoint,
    new_connection_point: &ConnectionPoint,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_connection_point).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_connection_point).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "connection_point.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_connection_point_integrations(integration_store, &runtime_values, "connection_point.updated").await;
}

/// Trigger integrations when a connection point is deleted
pub async fn trigger_connection_point_deleted(
    integration_store: &FileSystemNotificationStore,
    connection_point: &ConnectionPoint,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&connection_point).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "connection_point.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_connection_point_integrations(integration_store, &runtime_values, "connection_point.deleted").await;
}

/// Trigger integrations when someone connects to a connection point
#[allow(dead_code)]
pub async fn trigger_connection_point_connected(
    integration_store: &FileSystemNotificationStore,
    connection_point: &ConnectionPoint,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&connection_point).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "connection_point.connected".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_connection_point_integrations(integration_store, &runtime_values, "connection_point.connected").await;
}

/// Trigger integrations when an error occurs at a connection point
#[allow(dead_code)]
pub async fn trigger_connection_point_error(
    integration_store: &FileSystemNotificationStore,
    connection_point: &ConnectionPoint,
    error_message: &str,
) {
    let mut runtime_values = HashMap::new();

    // Include error in the NEW_STATE
    let mut state_map = serde_json::to_value(connection_point).unwrap_or_default();
    if let Some(obj) = state_map.as_object_mut() {
        obj.insert("error".to_string(), serde_json::Value::String(error_message.to_string()));
    }

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&connection_point).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&state_map).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "connection_point.error".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    trigger_connection_point_integrations(integration_store, &runtime_values, "connection_point.error").await;
}

async fn trigger_connection_point_integrations(
    _integration_store: &FileSystemNotificationStore,
    _runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    // Placeholder: Connection point integrations would be loaded and triggered here
    // This will be implemented when connection point handlers are integrated
    info!("Connection point integration trigger: {} (not yet implemented)", event_type);
}
