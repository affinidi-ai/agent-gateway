use super::filesystem::FileSystemNotificationStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpProxy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub base_url: String,
    pub channel_prefix: String,
    pub endpoint_path: String,
    pub status: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Trigger integrations when an MCP proxy is created
pub async fn trigger_mcp_proxy_created(
    integration_store: &FileSystemNotificationStore,
    mcp_proxy: &McpProxy,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&mcp_proxy).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "mcp_proxy.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("MCP_PROXY_ID".to_string(), mcp_proxy.id.clone());
    runtime_values.insert("MCP_PROXY_NAME".to_string(), mcp_proxy.name.clone());

    trigger_mcp_proxy_integrations(integration_store, &runtime_values, "mcp_proxy.created").await;
}

/// Trigger integrations when an MCP proxy is updated
pub async fn trigger_mcp_proxy_updated(
    integration_store: &FileSystemNotificationStore,
    old_mcp_proxy: &McpProxy,
    new_mcp_proxy: &McpProxy,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_mcp_proxy).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_mcp_proxy).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "mcp_proxy.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("MCP_PROXY_ID".to_string(), new_mcp_proxy.id.clone());
    runtime_values.insert("MCP_PROXY_NAME".to_string(), new_mcp_proxy.name.clone());

    trigger_mcp_proxy_integrations(integration_store, &runtime_values, "mcp_proxy.updated").await;
}

/// Trigger integrations when an MCP proxy is deleted
pub async fn trigger_mcp_proxy_deleted(
    integration_store: &FileSystemNotificationStore,
    mcp_proxy: &McpProxy,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&mcp_proxy).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "mcp_proxy.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("MCP_PROXY_ID".to_string(), mcp_proxy.id.clone());
    runtime_values.insert("MCP_PROXY_NAME".to_string(), mcp_proxy.name.clone());

    trigger_mcp_proxy_integrations(integration_store, &runtime_values, "mcp_proxy.deleted").await;
}

/// Trigger integrations when an MCP proxy status changes
#[allow(dead_code)]
pub async fn trigger_mcp_proxy_status_changed(
    integration_store: &FileSystemNotificationStore,
    mcp_proxy: &McpProxy,
    old_status: &str,
    new_status: &str,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&mcp_proxy).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "mcp_proxy.status_changed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("MCP_PROXY_ID".to_string(), mcp_proxy.id.clone());
    runtime_values.insert("MCP_PROXY_NAME".to_string(), mcp_proxy.name.clone());
    runtime_values.insert("OLD_STATUS".to_string(), old_status.to_string());
    runtime_values.insert("NEW_STATUS".to_string(), new_status.to_string());

    trigger_mcp_proxy_integrations(integration_store, &runtime_values, "mcp_proxy.status_changed").await;
}

async fn trigger_mcp_proxy_integrations(
    _integration_store: &FileSystemNotificationStore,
    _runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    info!("MCP Proxy integration trigger: {}", event_type);
    // Integration logic will be implemented here
    // This will follow the same pattern as other entity triggers
}
