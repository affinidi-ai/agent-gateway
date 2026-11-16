use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::HashMap;

use super::background_tasks::TaskShare;
use super::delivery::dispatch::{dispatch, dispatch_within};
use crate::auth::storage::UserData;
use crate::auth::types::{UserRole, UserStatus};

/// How a console user signed in, or tried to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMethod {
    Passkey,
    Saml,
}

impl LoginMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passkey => "passkey",
            Self::Saml => "saml",
        }
    }
}

/// Why a console sign-in failed. Only the variants for an existing account carry it, as stored,
/// so the event never repeats what the caller typed.
#[derive(Debug, Clone, Copy)]
pub enum LoginFailure<'a> {
    InvalidCredential(&'a UserData),
    NotApproved(&'a UserData),
    UnknownUser,
    SamlRejected,
}

impl<'a> LoginFailure<'a> {
    /// The failure of a passkey sign-in whose credential did not verify, by the account the
    /// sign-in named: none, one that is not approved, or one whose passkey was not presented.
    pub fn of_passkey_account(account: Option<&'a UserData>) -> Self {
        match account {
            None => Self::UnknownUser,
            Some(user) if user.status != UserStatus::Approved => Self::NotApproved(user),
            Some(user) => Self::InvalidCredential(user),
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            Self::InvalidCredential(_) => "invalid_credential",
            Self::NotApproved(_) => "not_approved",
            Self::UnknownUser => "unknown_user",
            Self::SamlRejected => "saml_rejected",
        }
    }

    fn account(&self) -> Option<&'a UserData> {
        match self {
            Self::InvalidCredential(user) | Self::NotApproved(user) => Some(user),
            Self::UnknownUser | Self::SamlRejected => None,
        }
    }
}

/// At most this many background tasks, a tenth of the limit, deliver failed sign-ins at once.
/// Anyone can fail a sign-in, so a flood of them is skipped beyond this share and never starves
/// the deliveries of other events.
const MAX_FAILED_SIGN_IN_TASKS: usize = 10;

static FAILED_SIGN_INS: Lazy<TaskShare> = Lazy::new(|| TaskShare::new("failed sign-ins", MAX_FAILED_SIGN_IN_TASKS));

pub fn trigger_user_created(user: &UserData) {
    dispatch("user.created", user_runtime_values("user.created", None, Some(user)));
}

pub fn trigger_user_approved(user: &UserData) {
    dispatch("user.approved", user_runtime_values("user.approved", None, Some(user)));
}

pub fn trigger_user_updated(
    old_user: &UserData,
    new_user: &UserData,
) {
    dispatch("user.updated", user_runtime_values("user.updated", Some(old_user), Some(new_user)));
}

pub fn trigger_user_deleted(user: &UserData) {
    dispatch("user.deleted", user_runtime_values("user.deleted", Some(user), None));
}

pub fn trigger_user_login(
    user: &UserData,
    method: LoginMethod,
) {
    dispatch("user.login", login_values(user, method));
}

pub fn trigger_user_login_failed(
    method: LoginMethod,
    failure: LoginFailure<'_>,
) {
    dispatch_within(&FAILED_SIGN_INS, "user.login_failed", login_failed_values(method, failure));
}

fn login_values(
    user: &UserData,
    method: LoginMethod,
) -> HashMap<String, String> {
    let mut values = user_runtime_values("user.login", None, Some(user));
    values.insert("LOGIN_METHOD".to_string(), method.as_str().to_string());
    values
}

fn login_failed_values(
    method: LoginMethod,
    failure: LoginFailure<'_>,
) -> HashMap<String, String> {
    let mut values = user_runtime_values("user.login_failed", None, failure.account());
    values.insert("LOGIN_METHOD".to_string(), method.as_str().to_string());
    values.insert("FAILURE_REASON".to_string(), failure.reason().to_string());
    values
}

pub fn trigger_user_accessed(user: &UserData) {
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
    use super::{LoginFailure, LoginMethod, login_failed_values, login_values, user_runtime_values};
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

    fn value<'a>(
        values: &'a std::collections::HashMap<String, String>,
        name: &str,
    ) -> Option<&'a str> {
        values
            .get(name)
            .map(String::as_str)
    }

    #[test]
    fn a_sign_in_names_its_method_and_the_user() {
        let values = login_values(&user(), LoginMethod::Saml);

        assert_eq!(value(&values, "EVENT_TYPE"), Some("user.login"));
        assert_eq!(value(&values, "LOGIN_METHOD"), Some("saml"));
        assert_eq!(value(&values, "USER_ID"), Some("u-1"));
    }

    #[test]
    fn a_failed_sign_in_of_an_existing_account_names_the_stored_account_its_method_and_reason() {
        let user = user();
        for (failure, reason) in [
            (LoginFailure::InvalidCredential(&user), "invalid_credential"),
            (LoginFailure::NotApproved(&user), "not_approved"),
        ] {
            let values = login_failed_values(LoginMethod::Passkey, failure);

            assert_eq!(value(&values, "EVENT_TYPE"), Some("user.login_failed"));
            assert_eq!(value(&values, "LOGIN_METHOD"), Some("passkey"));
            assert_eq!(value(&values, "FAILURE_REASON"), Some(reason));
            assert_eq!(value(&values, "USER_ID"), Some("u-1"));
            assert_eq!(value(&values, "USERNAME"), Some("jane.doe"));
            assert_eq!(value(&values, "USER_EMAIL"), Some("jane@example.test"));
            assert_eq!(value(&values, "USER_ROLE"), Some("poweruser"));
            assert_eq!(value(&values, "USER_STATUS"), Some("approved"));
            assert_eq!(keys(&values["NEW_STATE"]).len(), 6);
        }
    }

    #[test]
    fn a_failed_sign_in_without_an_account_names_no_user() {
        for (method, failure, method_name, reason) in [
            (LoginMethod::Passkey, LoginFailure::UnknownUser, "passkey", "unknown_user"),
            (LoginMethod::Saml, LoginFailure::SamlRejected, "saml", "saml_rejected"),
        ] {
            let values = login_failed_values(method, failure);

            assert_eq!(value(&values, "LOGIN_METHOD"), Some(method_name));
            assert_eq!(value(&values, "FAILURE_REASON"), Some(reason));
            for name in ["USER_ID", "USERNAME", "USER_EMAIL", "USER_ROLE", "USER_STATUS"] {
                assert_eq!(value(&values, name), None, "{reason} fills {name}");
            }
            assert_eq!(value(&values, "OLD_STATE"), Some(""));
            assert_eq!(value(&values, "NEW_STATE"), Some(""));
        }
    }

    #[test]
    fn a_failed_passkey_sign_in_is_classified_by_the_account_it_named() {
        let approved = user();
        let mut pending = user();
        pending.status = UserStatus::New;

        assert!(matches!(LoginFailure::of_passkey_account(None), LoginFailure::UnknownUser));
        assert!(matches!(LoginFailure::of_passkey_account(Some(&pending)), LoginFailure::NotApproved(_)));
        assert!(matches!(LoginFailure::of_passkey_account(Some(&approved)), LoginFailure::InvalidCredential(_)));
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
