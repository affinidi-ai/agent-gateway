use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

use super::delivery::dispatch::dispatch;
use super::filesystem::FileSystemNotificationStore;
use crate::auth::storage::UserData;
use crate::auth::types::{UserRole, UserStatus};

pub async fn trigger_user_created(
    _notifications: &FileSystemNotificationStore,
    user: &UserData,
) {
    dispatch("user.created", user_runtime_values("user.created", None, Some(user)));
}

pub async fn trigger_user_approved(
    _notifications: &FileSystemNotificationStore,
    user: &UserData,
) {
    dispatch("user.approved", user_runtime_values("user.approved", None, Some(user)));
}

pub async fn trigger_user_updated(
    _notifications: &FileSystemNotificationStore,
    old_user: &UserData,
    new_user: &UserData,
) {
    dispatch("user.updated", user_runtime_values("user.updated", Some(old_user), Some(new_user)));
}

pub async fn trigger_user_deleted(
    _notifications: &FileSystemNotificationStore,
    user: &UserData,
) {
    dispatch("user.deleted", user_runtime_values("user.deleted", Some(user), None));
}

pub async fn trigger_user_login(
    _notifications: &FileSystemNotificationStore,
    user: &UserData,
) {
    dispatch("user.login", user_runtime_values("user.login", None, Some(user)));
}

pub async fn trigger_user_accessed(
    _notifications: &FileSystemNotificationStore,
    user: &UserData,
) {
    dispatch("user.accessed", user_runtime_values("user.accessed", None, Some(user)));
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

#[cfg(test)]
mod tests {
    use super::user_runtime_values;
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
