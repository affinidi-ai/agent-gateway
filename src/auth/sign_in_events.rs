//! What a sign-in through an identity provider (SAML or OpenID Connect) did to the stored user,
//! and the user events and metrics it raises.

use std::sync::Arc;

use crate::auth::storage::UserData;
use crate::integrations::LoginMethod;
use crate::metrics::MetricsStore;

/// What a sign-in did to the stored user.
#[derive(Debug)]
pub enum SignInChange {
    Created,
    Updated { previous: Box<UserData> },
}

/// The signed-in user and what the sign-in changed.
#[derive(Debug)]
pub struct Provisioned {
    pub user: UserData,
    pub change: SignInChange,
}

impl Provisioned {
    /// Whether the sign-in changed an existing user's role.
    pub fn role_changed(&self) -> bool {
        matches!(&self.change, SignInChange::Updated { previous } if previous.role != self.user.role)
    }
}

/// A user event a sign-in raises, in the order it is raised.
#[derive(Debug)]
pub enum SignInEvent<'a> {
    Created(&'a UserData),
    Updated { old: &'a UserData, new: &'a UserData },
    Login(&'a UserData),
}

/// The user events a sign-in raises: `user.created` for a new user, `user.updated` when the
/// sign-in changed what user events report, then `user.login`.
pub fn sign_in_events(provisioned: &Provisioned) -> Vec<SignInEvent<'_>> {
    let user = &provisioned.user;
    let mut events = match &provisioned.change {
        SignInChange::Created => vec![SignInEvent::Created(user)],
        SignInChange::Updated { previous } if changes_reported_state(previous, user) => {
            vec![SignInEvent::Updated {
                old: previous.as_ref(),
                new: user,
            }]
        }
        SignInChange::Updated { .. } => Vec::new(),
    };
    events.push(SignInEvent::Login(user));
    events
}

/// Whether the role, status or primary flag changed: the parts of a user that user events
/// report and that a sign-in can change.
fn changes_reported_state(
    old: &UserData,
    new: &UserData,
) -> bool {
    old.role != new.role || old.status != new.status || old.is_primary != new.is_primary
}

/// Raise a completed sign-in's user events in order, each delivered in the background, and
/// count it (and a created user) in the metrics.
pub(crate) fn raise_sign_in_events(
    provisioned: &Provisioned,
    method: LoginMethod,
    metric_store: Option<Arc<MetricsStore>>,
) {
    if let Some(metrics) = metric_store {
        let user_role = provisioned
            .user
            .role
            .to_string();
        let created = matches!(provisioned.change, SignInChange::Created);
        tokio::spawn(async move {
            if created {
                metrics
                    .record_user_event("created", &user_role)
                    .await;
            }
            metrics
                .record_user_login(&user_role)
                .await;
        });
    }
    for event in sign_in_events(provisioned) {
        match event {
            SignInEvent::Created(user) => crate::integrations::trigger_user_created(user),
            SignInEvent::Updated { old, new } => crate::integrations::trigger_user_updated(old, new),
            SignInEvent::Login(user) => crate::integrations::trigger_user_login(user, method),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::{UserRole, UserStatus};

    fn user(role: UserRole) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: "u-1".to_string(),
            username: "jane".to_string(),
            passkeys: Vec::new(),
            role,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: Some("Jane".to_string()),
            last_name: None,
            email: Some("jane@example.test".to_string()),
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: Some(now),
            saml_id: Some("saml-1".to_string()),
            oidc: None,
            deleted_at: None,
        }
    }

    #[test]
    fn a_created_user_raises_created_then_login() {
        let provisioned = Provisioned {
            user: user(UserRole::User),
            change: SignInChange::Created,
        };

        let events = sign_in_events(&provisioned);

        assert!(matches!(events.as_slice(), [SignInEvent::Created(_), SignInEvent::Login(_)]));
        assert!(!provisioned.role_changed(), "a new user had no role to change");
    }

    #[test]
    fn a_role_change_raises_updated_then_login() {
        let previous = user(UserRole::User);
        let mut current = previous.clone();
        current.role = UserRole::PowerUser;
        let provisioned = Provisioned {
            user: current,
            change: SignInChange::Updated { previous: Box::new(previous) },
        };

        let events = sign_in_events(&provisioned);

        match events.as_slice() {
            [SignInEvent::Updated { old, new }, SignInEvent::Login(_)] => {
                assert_eq!(old.role, UserRole::User);
                assert_eq!(new.role, UserRole::PowerUser);
            }
            other => panic!("expected updated then login, got {other:?}"),
        }
        assert!(provisioned.role_changed());
    }

    #[test]
    fn a_sign_in_that_changes_only_profile_details_raises_only_login() {
        let previous = user(UserRole::User);
        let mut current = previous.clone();
        current.first_name = Some("Janet".to_string());
        current.updated_at = previous.updated_at + chrono::Duration::minutes(5);
        current.last_logged_in = Some(current.updated_at);
        let provisioned = Provisioned {
            user: current,
            change: SignInChange::Updated { previous: Box::new(previous) },
        };

        let events = sign_in_events(&provisioned);

        assert!(matches!(events.as_slice(), [SignInEvent::Login(_)]));
        assert!(!provisioned.role_changed());
    }
}
