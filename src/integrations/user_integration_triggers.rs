use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use tracing::{error, info};

use super::filesystem::FileSystemNotificationStore;
use crate::auth::storage::UserData;
use crate::auth::types::{UserRole, UserStatus};
use crate::integrations::trigger_mappings::MappingRules;

/// What a user integration mapping may name: the events this module raises.
pub const USER_MAPPING_RULES: MappingRules = MappingRules {
    category: "user",
    event_types: &["user.created", "user.approved", "user.updated", "user.deleted", "user.login", "user.accessed"],
};

/// Trigger user integrations for user.created event
pub async fn trigger_user_created(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.created integrations for user: {}", user.user_id);
    let runtime_values = user_runtime_values("user.created", None, Some(user));
    trigger_user_integrations(integration_store, &runtime_values, "user.created").await;
}

/// Trigger user integrations for user.approved event
pub async fn trigger_user_approved(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.approved integrations for user: {}", user.user_id);
    let runtime_values = user_runtime_values("user.approved", None, Some(user));
    trigger_user_integrations(integration_store, &runtime_values, "user.approved").await;
}

/// Trigger user integrations for user.updated event
pub async fn trigger_user_updated(
    integration_store: &FileSystemNotificationStore,
    old_user: &UserData,
    new_user: &UserData,
) {
    info!("Triggering user.updated integrations for user: {}", new_user.user_id);
    let runtime_values = user_runtime_values("user.updated", Some(old_user), Some(new_user));
    trigger_user_integrations(integration_store, &runtime_values, "user.updated").await;
}

/// Trigger user integrations for user.deleted event
pub async fn trigger_user_deleted(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.deleted integrations for user: {}", user.user_id);
    let runtime_values = user_runtime_values("user.deleted", Some(user), None);
    trigger_user_integrations(integration_store, &runtime_values, "user.deleted").await;
}

/// Trigger user integrations for user.login event
pub async fn trigger_user_login(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.login integrations for user: {}", user.user_id);
    let runtime_values = user_runtime_values("user.login", None, Some(user));
    trigger_user_integrations(integration_store, &runtime_values, "user.login").await;
}

/// Trigger user integrations for user.accessed event
pub async fn trigger_user_accessed(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.accessed integrations for user: {}", user.user_id);
    let runtime_values = user_runtime_values("user.accessed", None, Some(user));
    trigger_user_integrations(integration_store, &runtime_values, "user.accessed").await;
}

/// The user fields an integration may receive in `OLD_STATE` and `NEW_STATE`. Passkeys, the
/// SAML subject and profile details stay on the appliance.
#[derive(Serialize)]
struct UserEventState<'a> {
    user_id: &'a str,
    role: &'a UserRole,
    status: &'a UserStatus,
    is_primary: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl<'a> From<&'a UserData> for UserEventState<'a> {
    fn from(user: &'a UserData) -> Self {
        Self {
            user_id: &user.user_id,
            role: &user.role,
            status: &user.status,
            is_primary: user.is_primary,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

/// Active `user` and `general` integrations without a tenant owner receive user events, which
/// describe users across the whole appliance.
fn receives_user_events(integration: &crate::storage::Integration) -> bool {
    let matches_category = matches!(
        integration
            .category
            .as_deref(),
        Some("user" | "general")
    );
    matches_category
        && integration.status == "active"
        && integration
            .tenant_id
            .is_none()
}

/// Runtime variables for one user event: `old` is the user before it and `new` after it.
/// The `USER_*` variables describe `new`, or `old` when the user was deleted.
fn user_runtime_values(
    event_type: &str,
    old: Option<&UserData>,
    new: Option<&UserData>,
) -> HashMap<String, String> {
    let state = |user: Option<&UserData>| {
        user.map(|user| serde_json::to_string(&UserEventState::from(user)).unwrap_or_default())
            .unwrap_or_default()
    };
    let mut values = HashMap::from([
        ("OLD_STATE".to_string(), state(old)),
        ("NEW_STATE".to_string(), state(new)),
        ("EVENT_TYPE".to_string(), event_type.to_string()),
        ("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339()),
    ]);
    if let Some(user) = new.or(old) {
        values.extend([
            ("USER_ID".to_string(), user.user_id.clone()),
            ("USERNAME".to_string(), user.username.clone()),
            (
                "USER_EMAIL".to_string(),
                user.email
                    .clone()
                    .unwrap_or_default(),
            ),
            ("USER_ROLE".to_string(), user.role.to_string()),
            ("USER_STATUS".to_string(), user.status.to_string()),
        ]);
    }
    values
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

    let user_integrations: Vec<_> = integrations
        .into_iter()
        .filter(receives_user_events)
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

#[cfg(test)]
mod tests {
    use super::{receives_user_events, user_runtime_values};
    use crate::storage::Integration;

    fn integration(
        category: &str,
        status: &str,
        tenant_id: Option<&str>,
    ) -> Integration {
        let mut integration = Integration::new(
            "Sink".to_string(),
            String::new(),
            "webhook".to_string(),
            serde_json::json!({}),
            serde_json::json!({}),
            status.to_string(),
            Some(category.to_string()),
        );
        integration.tenant_id = tenant_id.map(str::to_string);
        integration
    }

    #[test]
    fn active_user_and_general_integrations_receive_user_events() {
        assert!(receives_user_events(&integration("user", "active", None)));
        assert!(receives_user_events(&integration("general", "active", None)));
    }

    #[test]
    fn inactive_or_other_category_integrations_receive_no_user_events() {
        assert!(!receives_user_events(&integration("user", "inactive", None)));
        assert!(!receives_user_events(&integration("gateway", "active", None)));
        assert!(!receives_user_events(&integration("audit", "active", None)));
    }

    #[test]
    fn a_tenant_owned_integration_receives_no_appliance_wide_user_events() {
        assert!(!receives_user_events(&integration("general", "active", Some("tenant-a"))));
        assert!(!receives_user_events(&integration("user", "active", Some("tenant-a"))));
    }
    use crate::auth::storage::UserData;
    use crate::auth::types::{UserRole, UserStatus};
    use std::collections::BTreeSet;

    fn user() -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: "u-1".to_string(),
            username: "jane.doe".to_string(),
            passkeys: Vec::new(),
            role: UserRole::PowerUser,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: Some("Janet".to_string()),
            last_name: Some("Doe".to_string()),
            email: Some("jane@example.test".to_string()),
            department: Some("Finance".to_string()),
            job_title: Some("Analyst".to_string()),
            avatar_path: Some("avatars/u-1.png".to_string()),
            created_at: now,
            updated_at: now,
            last_logged_in: Some(now),
            saml_id: Some("saml-subject-123".to_string()),
        }
    }

    fn keys(state: &str) -> BTreeSet<String> {
        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(state)
            .expect("state is a JSON object")
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    }

    #[test]
    fn user_state_carries_only_the_allow_listed_fields() {
        let values = user_runtime_values("user.created", None, Some(&user()));

        let expected: BTreeSet<String> = ["user_id", "role", "status", "is_primary", "created_at", "updated_at"]
            .map(String::from)
            .into();
        assert_eq!(keys(&values["NEW_STATE"]), expected);
    }

    #[test]
    fn user_state_never_carries_passkeys_saml_ids_or_profile_details() {
        let user = user();
        let values = user_runtime_values("user.updated", Some(&user), Some(&user));

        for state in [&values["OLD_STATE"], &values["NEW_STATE"]] {
            for leaked in [
                "passkeys",
                "saml-subject-123",
                "jane@example.test",
                "jane.doe",
                "Janet",
                "Finance",
                "Analyst",
                "avatars/",
            ] {
                assert!(!state.contains(leaked), "state leaks {leaked}: {state}");
            }
        }
    }

    #[test]
    fn user_state_keeps_role_and_status_names() {
        let values = user_runtime_values("user.created", None, Some(&user()));

        let state: serde_json::Value = serde_json::from_str(&values["NEW_STATE"]).unwrap();
        assert_eq!(state["user_id"], "u-1");
        assert_eq!(state["role"], "poweruser");
        assert_eq!(state["status"], "approved");
        assert_eq!(state["is_primary"], false);
    }

    #[test]
    fn a_created_user_fills_only_the_new_state() {
        let values = user_runtime_values("user.created", None, Some(&user()));

        assert!(!values["NEW_STATE"].is_empty());
        assert_eq!(values["OLD_STATE"], "");
    }

    #[test]
    fn a_deleted_user_fills_only_the_old_state_and_names_the_deleted_user() {
        let values = user_runtime_values("user.deleted", Some(&user()), None);

        assert!(!values["OLD_STATE"].is_empty());
        assert_eq!(values["NEW_STATE"], "");
        assert_eq!(values["USER_ID"], "u-1");
    }

    #[test]
    fn an_updated_user_fills_both_states_and_names_the_user_after_the_change() {
        let before = user();
        let mut after = user();
        after.role = UserRole::Administrator;

        let values = user_runtime_values("user.updated", Some(&before), Some(&after));

        assert_eq!(serde_json::from_str::<serde_json::Value>(&values["OLD_STATE"]).unwrap()["role"], "poweruser");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&values["NEW_STATE"]).unwrap()["role"], "administrator");
        assert_eq!(values["USER_ROLE"], "administrator");
    }

    #[test]
    fn user_variables_name_the_event_and_the_user() {
        let values = user_runtime_values("user.login", None, Some(&user()));

        assert_eq!(values["EVENT_TYPE"], "user.login");
        assert_eq!(values["USER_ID"], "u-1");
        assert_eq!(values["USERNAME"], "jane.doe");
        assert_eq!(values["USER_EMAIL"], "jane@example.test");
        assert_eq!(values["USER_ROLE"], "poweruser");
        assert_eq!(values["USER_STATUS"], "approved");
        assert!(chrono::DateTime::parse_from_rfc3339(&values["TIMESTAMP"]).is_ok());
    }
}
