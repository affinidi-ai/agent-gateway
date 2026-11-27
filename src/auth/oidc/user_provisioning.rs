//! Just-in-time users for OIDC sign-in. A user is found by their OpenID provider account (issuer
//! and `sub`), never by email or username, and their role and profile are refreshed from the ID
//! token at every sign-in.

use serde_json::{Map, Value};
use tracing::info;

use super::config::ClaimNames;
use crate::auth::sign_in_events::{Provisioned, SignInChange};
use crate::auth::storage::{OidcIdentity, PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};

/// The longest username taken from a claim.
const MAX_USERNAME_LEN: usize = 255;

/// Why an OIDC sign-in cannot sign the account in.
#[derive(Debug)]
pub enum ProvisionRefusal {
    /// The user exists and is not approved (an administrator disabled them, or set them back to
    /// awaiting approval). Carries the user as stored.
    NotApproved(Box<UserData>),
    /// A new user would exceed the appliance user limit.
    UserLimit(crate::config::LimitExceeded),
    /// Every username the account could have belongs to another user.
    UsernameTaken,
    Storage(anyhow::Error),
}

impl From<anyhow::Error> for ProvisionRefusal {
    fn from(error: anyhow::Error) -> Self {
        Self::Storage(error)
    }
}

fn claim_string(
    claims: &Map<String, Value>,
    name: &str,
) -> Option<String> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Create or update the user for `identity`, with `role`, from the ID token's claims. A user that
/// exists and is not approved is refused and left unchanged, and a new user is created approved,
/// never primary, within the appliance user limit.
pub async fn provision_user_from_oidc(
    storage: &PasskeyStorage,
    identity: OidcIdentity,
    claims: &Map<String, Value>,
    names: &ClaimNames,
    role: UserRole,
) -> Result<Provisioned, ProvisionRefusal> {
    let email = claim_string(claims, &names.email);
    let first_name = claim_string(claims, &names.first_name);
    let last_name = claim_string(claims, &names.last_name);
    let preferred_username = [claim_string(claims, &names.username), email.clone()]
        .into_iter()
        .flatten()
        .find(|username| username.len() <= MAX_USERNAME_LEN)
        .unwrap_or_else(|| identity.subject.clone());

    let _user_write_guard = storage
        .user_write_guard()
        .await;
    let existing = storage
        .load_user_by_oidc_identity(&identity)
        .await?;
    if let Some(user) = &existing
        && user.status != UserStatus::Approved
    {
        return Err(ProvisionRefusal::NotApproved(Box::new(user.clone())));
    }
    let own_user_id = existing
        .as_ref()
        .map(|user| user.user_id.as_str());
    let username = free_username(storage, [&preferred_username, &identity.subject], own_user_id)
        .await?
        .ok_or(ProvisionRefusal::UsernameTaken)?;
    let now = chrono::Utc::now();

    let provisioned = match existing {
        Some(previous) => {
            let mut user = previous.clone();
            user.username = username;
            user.email = email;
            user.first_name = first_name;
            user.last_name = last_name;
            user.role = role;
            user.updated_at = now;
            user.last_logged_in = Some(now);
            Provisioned {
                user,
                change: SignInChange::Updated { previous: Box::new(previous) },
            }
        }
        None => {
            let user_count = storage
                .list_users()
                .await?
                .len();
            crate::config::global_limits()
                .check_can_add("users", user_count)
                .map_err(ProvisionRefusal::UserLimit)?;
            let user_id = uuid::Uuid::new_v4().to_string();
            info!(user_id = %user_id, role = %role, "Creating a user for a new OIDC account");
            Provisioned {
                user: UserData {
                    user_id,
                    username,
                    passkeys: Vec::new(),
                    role,
                    status: UserStatus::Approved,
                    is_primary: false,
                    first_name,
                    last_name,
                    email,
                    department: None,
                    job_title: None,
                    avatar_path: None,
                    created_at: now,
                    updated_at: now,
                    last_logged_in: Some(now),
                    saml_id: None,
                    oidc: Some(identity),
                },
                change: SignInChange::Created,
            }
        }
    };
    storage
        .save_user(&provisioned.user)
        .await?;
    Ok(provisioned)
}

/// The first of `candidates` that no other user has as their username. The admin handlers find
/// users by username, so two users must never share one.
async fn free_username<const N: usize>(
    storage: &PasskeyStorage,
    candidates: [&String; N],
    own_user_id: Option<&str>,
) -> anyhow::Result<Option<String>> {
    for candidate in candidates {
        match storage
            .load_user(candidate)
            .await?
        {
            Some(holder) if Some(holder.user_id.as_str()) != own_user_id => continue,
            _ => return Ok(Some(candidate.clone())),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn storage() -> (tempfile::TempDir, PasskeyStorage) {
        let dir = tempfile::tempdir().unwrap();
        let storage = PasskeyStorage::new(
            dir.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            dir.path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        (dir, storage)
    }

    fn identity(subject: &str) -> OidcIdentity {
        OidcIdentity {
            issuer: "https://idp.example.com".to_string(),
            subject: subject.to_string(),
        }
    }

    fn claims(value: Value) -> Map<String, Value> {
        value
            .as_object()
            .unwrap()
            .clone()
    }

    async fn provision(
        storage: &PasskeyStorage,
        subject: &str,
        token: Value,
        role: UserRole,
    ) -> Result<Provisioned, ProvisionRefusal> {
        provision_user_from_oidc(storage, identity(subject), &claims(token), &ClaimNames::default(), role).await
    }

    #[tokio::test]
    async fn a_new_account_becomes_an_approved_user_who_is_never_primary() {
        let (_dir, storage) = storage().await;

        let created = provision(
            &storage,
            "sub-1",
            json!({ "preferred_username": "alice", "email": "alice@example.com", "given_name": "Alice" }),
            UserRole::Administrator,
        )
        .await
        .unwrap();

        assert!(matches!(created.change, SignInChange::Created));
        let user = created.user;
        assert_eq!(user.username, "alice");
        assert_eq!(user.role, UserRole::Administrator);
        assert_eq!(user.status, UserStatus::Approved);
        assert!(!user.is_primary, "the first OIDC user is not the primary administrator");
        assert_eq!(user.oidc, Some(identity("sub-1")));
        assert_eq!(user.saml_id, None);
        assert_eq!(user.email.as_deref(), Some("alice@example.com"));
        assert_eq!(user.first_name.as_deref(), Some("Alice"));
        assert_eq!(
            storage
                .load_user_by_id(&user.user_id)
                .await
                .unwrap()
                .unwrap()
                .username,
            "alice"
        );
    }

    #[tokio::test]
    async fn the_same_subject_with_a_new_email_updates_the_same_user() {
        let (_dir, storage) = storage().await;
        let first = provision(&storage, "sub-1", json!({ "email": "a@example.com" }), UserRole::User)
            .await
            .unwrap()
            .user;

        let again = provision(&storage, "sub-1", json!({ "email": "b@example.com" }), UserRole::User)
            .await
            .unwrap();

        assert_eq!(again.user.user_id, first.user_id);
        assert_eq!(again.user.email.as_deref(), Some("b@example.com"));
        assert_eq!(again.user.username, "b@example.com", "the username follows the email claim when it is the source");
        match &again.change {
            SignInChange::Updated { previous } => assert_eq!(previous.email.as_deref(), Some("a@example.com")),
            other => panic!("expected an update, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn another_subject_with_the_same_email_is_another_user() {
        let (_dir, storage) = storage().await;
        let first = provision(&storage, "sub-1", json!({ "email": "a@example.com" }), UserRole::Administrator)
            .await
            .unwrap()
            .user;

        let other = provision(&storage, "sub-2", json!({ "email": "a@example.com" }), UserRole::User)
            .await
            .unwrap()
            .user;

        assert_ne!(other.user_id, first.user_id, "email never links accounts");
        assert_eq!(other.role, UserRole::User);
        assert_eq!(other.username, "sub-2", "the taken username falls back to the subject");
    }

    #[tokio::test]
    async fn an_account_never_takes_over_a_user_with_the_same_username() {
        let (_dir, storage) = storage().await;
        let mut passkey_user = provision(&storage, "sub-0", json!({ "preferred_username": "alice" }), UserRole::User)
            .await
            .unwrap()
            .user;
        passkey_user.oidc = None;
        storage
            .save_user(&passkey_user)
            .await
            .unwrap();

        let newcomer = provision(&storage, "sub-1", json!({ "preferred_username": "alice" }), UserRole::Administrator)
            .await
            .unwrap()
            .user;

        assert_ne!(newcomer.user_id, passkey_user.user_id);
        assert_eq!(newcomer.username, "sub-1");
        assert_eq!(
            storage
                .load_user_by_id(&passkey_user.user_id)
                .await
                .unwrap()
                .unwrap()
                .role,
            UserRole::User,
            "the existing user is untouched"
        );
    }

    #[tokio::test]
    async fn a_sign_in_that_cannot_find_a_free_username_is_refused() {
        let (_dir, storage) = storage().await;
        provision(&storage, "sub-1", json!({ "preferred_username": "sub-2" }), UserRole::User)
            .await
            .unwrap();

        let refused = provision(&storage, "sub-2", json!({ "preferred_username": "sub-2" }), UserRole::User)
            .await
            .unwrap_err();

        assert!(matches!(refused, ProvisionRefusal::UsernameTaken), "{refused:?}");
    }

    #[tokio::test]
    async fn the_role_follows_the_token_in_both_directions() {
        let (_dir, storage) = storage().await;
        provision(&storage, "sub-1", json!({}), UserRole::Administrator)
            .await
            .unwrap();

        let demoted = provision(&storage, "sub-1", json!({}), UserRole::User)
            .await
            .unwrap();
        assert_eq!(demoted.user.role, UserRole::User);
        assert!(demoted.role_changed());

        let unchanged = provision(&storage, "sub-1", json!({}), UserRole::User)
            .await
            .unwrap();
        assert!(!unchanged.role_changed());

        let promoted = provision(&storage, "sub-1", json!({}), UserRole::PowerUser)
            .await
            .unwrap();
        assert_eq!(promoted.user.role, UserRole::PowerUser);
        assert!(promoted.role_changed());
    }

    #[tokio::test]
    async fn a_user_who_is_not_approved_is_refused_and_left_unchanged() {
        let (_dir, storage) = storage().await;
        let mut user = provision(&storage, "sub-1", json!({ "email": "a@example.com" }), UserRole::User)
            .await
            .unwrap()
            .user;
        for status in [UserStatus::Disabled, UserStatus::New] {
            user.status = status.clone();
            storage
                .save_user(&user)
                .await
                .unwrap();

            let refused = provision(&storage, "sub-1", json!({ "email": "b@example.com" }), UserRole::Administrator)
                .await
                .unwrap_err();

            match refused {
                ProvisionRefusal::NotApproved(stored) => assert_eq!(stored.user_id, user.user_id),
                other => panic!("{status}: expected NotApproved, got {other:?}"),
            }
            let stored = storage
                .load_user_by_id(&user.user_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.role, UserRole::User, "{status}: the refused sign-in changed nothing");
            assert_eq!(stored.email.as_deref(), Some("a@example.com"), "{status}");
        }
    }

    #[tokio::test]
    async fn an_overlong_username_claim_is_not_used() {
        let (_dir, storage) = storage().await;

        let user = provision(&storage, "sub-1", json!({ "preferred_username": "x".repeat(300) }), UserRole::User)
            .await
            .unwrap()
            .user;
        assert_eq!(user.username, "sub-1");

        let user = provision(
            &storage,
            "sub-2",
            json!({ "preferred_username": "x".repeat(300), "email": "b@example.com" }),
            UserRole::User,
        )
        .await
        .unwrap()
        .user;
        assert_eq!(user.username, "b@example.com", "the email claim is next");
    }
}
