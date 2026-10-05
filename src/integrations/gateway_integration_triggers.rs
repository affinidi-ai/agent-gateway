use std::collections::HashMap;
use tracing::{error, info};

use super::filesystem::FileSystemNotificationStore;
use crate::gateways::types::Gateway;

/// Trigger gateway integrations for gateway.created event
pub async fn trigger_gateway_created(
    integration_store: &FileSystemNotificationStore,
    gateway: &Gateway,
) {
    info!("Triggering gateway.created integrations for gateway: {}", gateway.name);

    let mut runtime_values = HashMap::new();
    // For CREATE events, only NEW_STATE is populated
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&gateway).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "gateway.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add gateway-specific variables
    runtime_values.insert("GATEWAY_ID".to_string(), gateway.id.clone());
    runtime_values.insert("GATEWAY_NAME".to_string(), gateway.name.clone());
    runtime_values.insert("GATEWAY_DESCRIPTION".to_string(), gateway.description.clone());
    runtime_values.insert("GATEWAY_DID".to_string(), gateway.did.clone());
    runtime_values.insert("GATEWAY_TYPE".to_string(), format!("{:?}", gateway.gateway_type));
    runtime_values.insert("GATEWAY_STATUS".to_string(), format!("{:?}", gateway.status));

    trigger_gateway_integrations(integration_store, &runtime_values, "gateway.created").await;
}

/// Trigger gateway integrations for gateway.updated event
pub async fn trigger_gateway_updated(
    integration_store: &FileSystemNotificationStore,
    old_gateway: &Gateway,
    new_gateway: &Gateway,
) {
    info!("Triggering gateway.updated integrations for gateway: {}", new_gateway.name);

    let mut runtime_values = HashMap::new();
    // For UPDATE events, both OLD_STATE and NEW_STATE are populated
    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_gateway).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_gateway).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "gateway.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add gateway-specific variables (use new_gateway for current values)
    runtime_values.insert("GATEWAY_ID".to_string(), new_gateway.id.clone());
    runtime_values.insert("GATEWAY_NAME".to_string(), new_gateway.name.clone());
    runtime_values.insert(
        "GATEWAY_DESCRIPTION".to_string(),
        new_gateway
            .description
            .clone(),
    );
    runtime_values.insert("GATEWAY_DID".to_string(), new_gateway.did.clone());
    runtime_values.insert("GATEWAY_TYPE".to_string(), format!("{:?}", new_gateway.gateway_type));
    runtime_values.insert("GATEWAY_STATUS".to_string(), format!("{:?}", new_gateway.status));

    trigger_gateway_integrations(integration_store, &runtime_values, "gateway.updated").await;

    // If status changed, also trigger gateway.status_changed event
    let old_status = format!("{:?}", old_gateway.status);
    let new_status = format!("{:?}", new_gateway.status);
    if old_status != new_status {
        trigger_gateway_status_changed(integration_store, old_gateway, new_gateway).await;
    }
}

/// Trigger gateway integrations for gateway.deleted event
pub async fn trigger_gateway_deleted(
    integration_store: &FileSystemNotificationStore,
    gateway: &Gateway,
) {
    info!("Triggering gateway.deleted integrations for gateway: {}", gateway.name);

    let mut runtime_values = HashMap::new();
    // For DELETE events, only OLD_STATE is populated (pre-deletion state)
    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&gateway).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "gateway.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add gateway-specific variables
    runtime_values.insert("GATEWAY_ID".to_string(), gateway.id.clone());
    runtime_values.insert("GATEWAY_NAME".to_string(), gateway.name.clone());
    runtime_values.insert("GATEWAY_DESCRIPTION".to_string(), gateway.description.clone());
    runtime_values.insert("GATEWAY_DID".to_string(), gateway.did.clone());
    runtime_values.insert("GATEWAY_TYPE".to_string(), format!("{:?}", gateway.gateway_type));
    runtime_values.insert("GATEWAY_STATUS".to_string(), format!("{:?}", gateway.status));

    trigger_gateway_integrations(integration_store, &runtime_values, "gateway.deleted").await;
}

/// Trigger gateway integrations for gateway.status_changed event
pub async fn trigger_gateway_status_changed(
    integration_store: &FileSystemNotificationStore,
    old_gateway: &Gateway,
    new_gateway: &Gateway,
) {
    let old_status = format!("{:?}", old_gateway.status);
    let new_status = format!("{:?}", new_gateway.status);

    info!(
        "Triggering gateway.status_changed integrations for gateway: {} (from {} to {})",
        new_gateway.name, old_status, new_status
    );

    let mut runtime_values = HashMap::new();
    // For STATUS_CHANGED events, both OLD_STATE and NEW_STATE are populated
    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_gateway).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_gateway).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "gateway.status_changed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add gateway-specific variables (use new_gateway for current values)
    runtime_values.insert("GATEWAY_ID".to_string(), new_gateway.id.clone());
    runtime_values.insert("GATEWAY_NAME".to_string(), new_gateway.name.clone());
    runtime_values.insert(
        "GATEWAY_DESCRIPTION".to_string(),
        new_gateway
            .description
            .clone(),
    );
    runtime_values.insert("GATEWAY_DID".to_string(), new_gateway.did.clone());
    runtime_values.insert("GATEWAY_TYPE".to_string(), format!("{:?}", new_gateway.gateway_type));
    runtime_values.insert("GATEWAY_STATUS".to_string(), format!("{:?}", new_gateway.status));
    runtime_values.insert("GATEWAY_OLD_STATUS".to_string(), format!("{:?}", old_gateway.status));

    trigger_gateway_integrations(integration_store, &runtime_values, "gateway.status_changed").await;
}

/// Trigger gateway integrations for gateway.accessed event
pub async fn trigger_gateway_accessed(
    integration_store: &FileSystemNotificationStore,
    gateway: &Gateway,
) {
    info!("Triggering gateway.accessed integrations for gateway: {}", gateway.name);

    let mut runtime_values = HashMap::new();
    // For ACCESS events, only NEW_STATE is populated
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&gateway).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "gateway.accessed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add gateway-specific variables
    runtime_values.insert("GATEWAY_ID".to_string(), gateway.id.clone());
    runtime_values.insert("GATEWAY_NAME".to_string(), gateway.name.clone());
    runtime_values.insert("GATEWAY_DESCRIPTION".to_string(), gateway.description.clone());
    runtime_values.insert("GATEWAY_DID".to_string(), gateway.did.clone());
    runtime_values.insert("GATEWAY_TYPE".to_string(), format!("{:?}", gateway.gateway_type));
    runtime_values.insert("GATEWAY_STATUS".to_string(), format!("{:?}", gateway.status));

    trigger_gateway_integrations(integration_store, &runtime_values, "gateway.accessed").await;
}

/// Internal helper to trigger integrations with the 'gateway' category
async fn trigger_gateway_integrations(
    _integration_store: &FileSystemNotificationStore,
    runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    // Get integration storage to list all integrations
    let storage = match crate::storage::get_integration_storage() {
        Some(storage) => storage,
        None => {
            error!("Integration storage not initialized for {}", event_type);
            return;
        }
    };

    // Get all integrations
    let integrations = match storage.list().await {
        Ok(integrations) => integrations,
        Err(e) => {
            error!("Failed to list integrations for {}: {}", event_type, e);
            return;
        }
    };

    // Filter to gateway and general category integrations that are active
    let gateway_integrations: Vec<_> = integrations
        .into_iter()
        .filter(|n| {
            let matches_category = n.category.as_deref() == Some("gateway") || n.category.as_deref() == Some("general");
            let is_active = n.status == "active";
            matches_category && is_active
        })
        .collect();

    if gateway_integrations.is_empty() {
        info!("No active gateway integrations configured for {}", event_type);
        return;
    }

    info!("Found {} active gateway integrations to trigger for {}", gateway_integrations.len(), event_type);

    // Extract gateway_id from runtime_values
    let gateway_id = match runtime_values.get("GATEWAY_ID") {
        Some(id) => id,
        None => {
            error!("GATEWAY_ID not found in runtime values for {}", event_type);
            return;
        }
    };

    // Load gateway integrations configuration to get custom variable values and event types
    let triggers_path = match crate::storage::get_integration_triggers_storage_path() {
        Some(path) => path,
        None => {
            error!("Integration triggers storage path not initialized for {}", event_type);
            return;
        }
    };

    let gateway_integrations_storage = match crate::integrations::GatewayIntegrationsStorage::new(
        std::path::PathBuf::from(&triggers_path)
            .join("gateways")
            .join(gateway_id),
    )
    .await
    {
        Ok(storage) => storage,
        Err(e) => {
            error!("Failed to create gateway integrations storage: {}", e);
            return;
        }
    };

    // Load configured integrations from trigger mappings
    let configured_integrations = match gateway_integrations_storage
        .load()
        .await
    {
        Ok(config) => config.integration_integrations,
        Err(e) => {
            error!("Failed to load gateway integrations config: {}", e);
            return;
        }
    };

    // Trigger each integration
    for integration in gateway_integrations {
        // Check if this integration is configured in the trigger mappings
        let integration_config = configured_integrations
            .iter()
            .find(|c| c.integration_id == integration.id);

        if integration_config.is_none() {
            info!(
                "Skipping integration {} for event {} - not configured in gateway trigger mappings",
                integration.name, event_type
            );
            continue;
        }

        let integration_config = integration_config.unwrap();

        // Check if this event type should trigger this integration
        // If event_types is empty, the integration is connected but will trigger for all events
        if !integration_config
            .event_types
            .is_empty()
            && !integration_config
                .event_types
                .contains(&event_type.to_string())
        {
            info!(
                "Skipping integration {} for event {} - not in allowed event types: {:?}",
                integration.name, event_type, integration_config.event_types
            );
            continue;
        }

        info!(
            "Triggering gateway integration: {} (type: {}) for {}",
            integration.name, integration.integration_type, event_type
        );

        // Build subject and message from event
        let subject = format!("Gateway Event: {}", event_type);
        let message = format!("Gateway event '{}' occurred", event_type);

        // Use custom variables from the integration config
        let mut merged_variables = integration_config
            .variables
            .clone();
        merged_variables.extend(runtime_values.clone());

        // Use the integration trigger service with merged variables
        if let Err(e) = crate::integrations::integration_service::trigger_integration_with_variables(
            &integration.id,
            &subject,
            &message,
            &merged_variables,
        )
        .await
        {
            error!("Failed to trigger integration {} for {}: {}", integration.name, event_type, e);
        } else {
            info!("Successfully triggered gateway integration: {}", integration.name);
        }
    }
}
