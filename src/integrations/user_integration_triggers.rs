use std::collections::HashMap;
use tracing::{error, info};

use super::filesystem::FileSystemNotificationStore;
use crate::auth::storage::UserData;

/// Trigger user integrations for user.created event
pub async fn trigger_user_created(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.created integrations for user: {}", user.username);

    let mut runtime_values = HashMap::new();
    // For CREATE events, only NEW_STATE is populated
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&user).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "user.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add user-specific variables
    runtime_values.insert("USER_ID".to_string(), user.user_id.clone());
    runtime_values.insert("USERNAME".to_string(), user.username.clone());
    runtime_values.insert(
        "USER_EMAIL".to_string(),
        user.email
            .clone()
            .unwrap_or_default(),
    );
    runtime_values.insert("USER_ROLE".to_string(), format!("{}", user.role));
    runtime_values.insert("USER_STATUS".to_string(), format!("{}", user.status));

    trigger_user_integrations(integration_store, &runtime_values, "user.created").await;
}

/// Trigger user integrations for user.approved event
pub async fn trigger_user_approved(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.approved integrations for user: {}", user.username);

    let mut runtime_values = HashMap::new();
    // For APPROVED events, we show the newly approved state in NEW_STATE
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&user).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "user.approved".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add user-specific variables
    runtime_values.insert("USER_ID".to_string(), user.user_id.clone());
    runtime_values.insert("USERNAME".to_string(), user.username.clone());
    runtime_values.insert(
        "USER_EMAIL".to_string(),
        user.email
            .clone()
            .unwrap_or_default(),
    );
    runtime_values.insert("USER_ROLE".to_string(), format!("{}", user.role));
    runtime_values.insert("USER_STATUS".to_string(), format!("{}", user.status));

    trigger_user_integrations(integration_store, &runtime_values, "user.approved").await;
}

/// Trigger user integrations for user.updated event
pub async fn trigger_user_updated(
    integration_store: &FileSystemNotificationStore,
    old_user: &UserData,
    new_user: &UserData,
) {
    info!("Triggering user.updated integrations for user: {}", new_user.username);

    let mut runtime_values = HashMap::new();
    // For UPDATE events, both OLD_STATE and NEW_STATE are populated
    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_user).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_user).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "user.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add user-specific variables (use new_user for current values)
    runtime_values.insert("USER_ID".to_string(), new_user.user_id.clone());
    runtime_values.insert("USERNAME".to_string(), new_user.username.clone());
    runtime_values.insert(
        "USER_EMAIL".to_string(),
        new_user
            .email
            .clone()
            .unwrap_or_default(),
    );
    runtime_values.insert("USER_ROLE".to_string(), format!("{}", new_user.role));
    runtime_values.insert("USER_STATUS".to_string(), format!("{}", new_user.status));

    trigger_user_integrations(integration_store, &runtime_values, "user.updated").await;
}

/// Trigger user integrations for user.deleted event
pub async fn trigger_user_deleted(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.deleted integrations for user: {}", user.username);

    let mut runtime_values = HashMap::new();
    // For DELETE events, only OLD_STATE is populated (pre-deletion state)
    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&user).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "user.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add user-specific variables
    runtime_values.insert("USER_ID".to_string(), user.user_id.clone());
    runtime_values.insert("USERNAME".to_string(), user.username.clone());
    runtime_values.insert(
        "USER_EMAIL".to_string(),
        user.email
            .clone()
            .unwrap_or_default(),
    );
    runtime_values.insert("USER_ROLE".to_string(), format!("{}", user.role));
    runtime_values.insert("USER_STATUS".to_string(), format!("{}", user.status));

    trigger_user_integrations(integration_store, &runtime_values, "user.deleted").await;
}

/// Trigger user integrations for user.login event
pub async fn trigger_user_login(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.login integrations for user: {}", user.username);

    let mut runtime_values = HashMap::new();
    // For LOGIN events, we show current user state at login time in NEW_STATE
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&user).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "user.login".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add user-specific variables
    runtime_values.insert("USER_ID".to_string(), user.user_id.clone());
    runtime_values.insert("USERNAME".to_string(), user.username.clone());
    runtime_values.insert(
        "USER_EMAIL".to_string(),
        user.email
            .clone()
            .unwrap_or_default(),
    );
    runtime_values.insert("USER_ROLE".to_string(), format!("{}", user.role));
    runtime_values.insert("USER_STATUS".to_string(), format!("{}", user.status));

    trigger_user_integrations(integration_store, &runtime_values, "user.login").await;
}

/// Trigger user integrations for user.accessed event
pub async fn trigger_user_accessed(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.accessed integrations for user: {}", user.username);

    let mut runtime_values = HashMap::new();
    // For ACCESS events, only NEW_STATE is populated
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&user).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "user.accessed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add user-specific variables
    runtime_values.insert("USER_ID".to_string(), user.user_id.clone());
    runtime_values.insert("USERNAME".to_string(), user.username.clone());
    runtime_values.insert(
        "USER_EMAIL".to_string(),
        user.email
            .clone()
            .unwrap_or_default(),
    );
    runtime_values.insert("USER_ROLE".to_string(), format!("{}", user.role));
    runtime_values.insert("USER_STATUS".to_string(), format!("{}", user.status));

    trigger_user_integrations(integration_store, &runtime_values, "user.accessed").await;
}

/// Internal helper to trigger integrations with the 'user' category
async fn trigger_user_integrations(
    _integration_store: &FileSystemNotificationStore,
    runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    // Get integration storage to list all integrations
    let storage = match crate::storage::get_integration_storage() {
        Some(storage) => storage,
        None => {
            error!("Notifier storage not initialized for {}", event_type);
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

    // Filter to user and general category integrations that are active
    let user_integrations: Vec<_> = integrations
        .into_iter()
        .filter(|n| {
            let matches_category = n.category.as_deref() == Some("user") || n.category.as_deref() == Some("general");
            let is_active = n.status == "active";
            matches_category && is_active
        })
        .collect();

    if user_integrations.is_empty() {
        info!("No active user integrations configured for {}", event_type);
        return;
    }

    info!("Found {} active user integrations to trigger for {}", user_integrations.len(), event_type);

    // Load user integrations configuration to get custom variable values
    // Get integration triggers storage path from global config
    let triggers_path = match crate::storage::get_integration_triggers_storage_path() {
        Some(path) => path,
        None => {
            error!("Integration triggers storage path not initialized for {}", event_type);
            return;
        }
    };

    let user_integrations_storage =
        match crate::integrations::UserIntegrationsStorage::new(std::path::PathBuf::from(&triggers_path).join("users"))
            .await
        {
            Ok(storage) => storage,
            Err(e) => {
                error!("Failed to create user integrations storage: {}", e);
                return;
            }
        };

    // Load configured integrations from trigger mappings
    let configured_integrations = match user_integrations_storage
        .load()
        .await
    {
        Ok(config) => config.integration_integrations,
        Err(e) => {
            error!("Failed to load user integrations config: {}", e);
            return;
        }
    };

    // Trigger each integration
    for integration in user_integrations {
        // Check if this integration is configured in the trigger mappings
        let integration_config = configured_integrations
            .iter()
            .find(|c| c.integration_id == integration.id);

        if integration_config.is_none() {
            info!(
                "Skipping integration {} for event {} - not configured in user trigger mappings",
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
            "Triggering user integration: {} (type: {}) for {}",
            integration.name, integration.integration_type, event_type
        );

        // Build subject and message from event
        let subject = format!("User Event: {}", event_type);
        let message = format!("User event '{}' occurred", event_type);

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
            info!("Successfully triggered user integration: {}", integration.name);
        }
    }
}
