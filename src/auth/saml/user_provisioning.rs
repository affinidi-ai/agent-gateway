use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::auth::auth_config::SamlConfig;
use crate::auth::saml::graph_api::GraphApiClient;
use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};

/// What a SAML sign-in did to the stored user.
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

/// Provision or update a user from SAML attributes
pub async fn provision_user_from_saml(
    storage: &PasskeyStorage,
    attributes: &HashMap<String, String>,
    config: &SamlConfig,
    avatars_storage_path: &str,
) -> Result<Provisioned> {
    // Extract user attributes using configured mappings
    let user_id_attr = attributes
        .get(
            &config
                .attribute_mapping
                .user_id,
        )
        .or_else(|| attributes.get("NameID"))
        .context("User ID not found in SAML attributes")?;

    let username = attributes
        .get(
            &config
                .attribute_mapping
                .username,
        )
        .or_else(|| attributes.get(&config.attribute_mapping.email))
        .context("Username not found in SAML attributes")?;

    let email = attributes
        .get(&config.attribute_mapping.email)
        .map(|s| s.to_string());

    let first_name = attributes
        .get(
            &config
                .attribute_mapping
                .first_name,
        )
        .map(|s| s.to_string());

    let last_name = attributes
        .get(
            &config
                .attribute_mapping
                .last_name,
        )
        .map(|s| s.to_string());

    let department = attributes
        .get(
            &config
                .attribute_mapping
                .department,
        )
        .map(|s| s.to_string());

    let job_title = attributes
        .get(
            &config
                .attribute_mapping
                .job_title,
        )
        .map(|s| s.to_string());

    // Determine role from SAML attributes
    let role = determine_role(attributes, config);

    let user_write_guard = storage
        .user_write_guard()
        .await;

    // Check if user already exists
    let existing_user = storage
        .load_user_by_saml_id(user_id_attr)
        .await?;

    let (user, change) = if let Some(mut user) = existing_user {
        let previous = user.clone();
        user.username = username.clone();
        user.email = email.clone();
        user.first_name = first_name;
        user.last_name = last_name;
        user.department = department;
        user.job_title = job_title;
        user.role = role;
        user.updated_at = chrono::Utc::now();
        user.last_logged_in = Some(chrono::Utc::now());
        info!(user_id = %user.user_id, "Updated SAML user");

        (user, SignInChange::Updated { previous: Box::new(previous) })
    } else {
        // Check if this is the first user (should be admin)
        let is_first_user = storage
            .list_users()
            .await?
            .is_empty();

        // Enforce the appliance user limit for JIT-provisioned users. The first
        // user always bootstraps admin access regardless of the configured cap.
        if !is_first_user {
            let user_count = storage
                .list_users()
                .await?
                .len();
            if let Err(e) = crate::config::global_limits().check_can_add("users", user_count) {
                crate::config::log_limit_reached("users", &e);
                return Err(anyhow::Error::new(e));
            }
        }

        let final_role = if is_first_user {
            UserRole::Administrator
        } else {
            role
        };
        let status = UserStatus::Approved; // SAML users auto-approved (including first user)

        let now = chrono::Utc::now();
        let user = UserData {
            user_id: uuid::Uuid::new_v4().to_string(),
            username: username.clone(),
            passkeys: Vec::new(),     // SAML users don't have passkeys
            role: final_role.clone(), // Clone so we can use it in logging
            status,
            is_primary: is_first_user,
            created_at: now,
            updated_at: now,
            first_name,
            last_name,
            email: email.clone(),
            department,
            job_title,
            avatar_path: None,
            last_logged_in: Some(now),
            saml_id: Some(user_id_attr.clone()),
        };

        info!(user_id = %user.user_id, role = %final_role, "Created SAML user");

        (user, SignInChange::Created)
    };

    // Save user first (don't block login on avatar fetch)
    storage
        .save_user(&user)
        .await?;

    drop(user_write_guard);

    // Fetch avatar synchronously before returning
    if let Some(graph_config) = &config.graph_api
        && graph_config.fetch_avatar
    {
        if let Some(user_email) = email.clone() {
            let user_id = user.user_id.clone();
            let graph_config = graph_config.clone();
            let avatars_storage_path = avatars_storage_path.to_string();
            if let Some(avatar_filename) =
                fetch_and_save_avatar(&graph_config, &user_email, &user_id, &avatars_storage_path).await
            {
                // Update user with avatar path (relative path: avatars/filename)
                let relative_avatar_path = format!("avatars/{}", avatar_filename);
                if let Ok(Some(mut user)) = storage
                    .load_user_by_id(&user_id)
                    .await
                {
                    user.avatar_path = Some(relative_avatar_path.clone());
                    if let Err(e) = storage.save_user(&user).await {
                        warn!("Failed to update user with avatar path: {}", e);
                    } else {
                        info!("Successfully updated user {} with avatar: {}", user_id, relative_avatar_path);
                    }
                }
            }
        } else {
            warn!("Cannot fetch avatar: user has no email address");
        }
    }

    Ok(Provisioned { user, change })
}

/// Determine user role from SAML attributes and role mapping
fn determine_role(
    attributes: &HashMap<String, String>,
    config: &SamlConfig,
) -> UserRole {
    let role_attr = &config.attribute_mapping.role;
    info!(
        "determine_role: role attribute key='{}', role_mapping keys={:?}, available SAML attributes={:?}",
        role_attr,
        config
            .role_mapping
            .keys()
            .collect::<Vec<_>>(),
        attributes
            .keys()
            .collect::<Vec<_>>()
    );

    // Get role attribute value
    if let Some(saml_role) = attributes.get(role_attr) {
        info!("determine_role: SAML role value received = '{}'", saml_role);

        // Check role mapping
        if let Some(mapped_role) = config
            .role_mapping
            .get(saml_role)
        {
            let resolved = match mapped_role.as_str() {
                "administrator" => UserRole::Administrator,
                "poweruser" => UserRole::PowerUser,
                "user" => UserRole::User,
                _ => UserRole::User,
            };
            info!(
                "determine_role: matched explicit role_mapping '{}' -> '{}' -> {:?}",
                saml_role, mapped_role, resolved
            );
            return resolved;
        }

        // If no explicit mapping, try direct match
        let resolved = match saml_role
            .to_lowercase()
            .as_str()
        {
            "administrator" | "admin" => UserRole::Administrator,
            "poweruser" | "power_user" | "power-user" => UserRole::PowerUser,
            _ => UserRole::User,
        };
        info!("determine_role: no role_mapping hit for '{}', fallback direct-match -> {:?}", saml_role, resolved);
        return resolved;
    }

    info!("determine_role: role attribute '{}' not present in SAML attributes, defaulting to User", role_attr);
    // Default to User role
    UserRole::User
}

/// Fetch avatar from Microsoft Graph API and save to disk
async fn fetch_and_save_avatar(
    graph_config: &crate::auth::auth_config::GraphApiConfig,
    user_email: &str,
    user_id: &str,
    avatars_storage_path: &str,
) -> Option<String> {
    let graph_client = GraphApiClient::new(graph_config.clone());

    match graph_client
        .fetch_user_avatar(user_email)
        .await
    {
        Ok(Some(avatar_bytes)) => {
            // Save avatar to disk using user_id (not email) for filename
            match GraphApiClient::save_avatar(&avatar_bytes, user_id, avatars_storage_path).await {
                Ok(filename) => {
                    info!(%user_id, %filename, "Avatar saved");
                    Some(filename)
                }
                Err(e) => {
                    warn!(%user_id, error = %e, "Failed to save avatar");
                    None
                }
            }
        }
        Ok(None) => {
            // User has no avatar in Azure AD
            None
        }
        Err(e) => {
            warn!(%user_id, error = %e, "Failed to fetch avatar");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::auth_config::SamlAttributeMapping;
    use tempfile::tempdir;

    fn test_saml_config() -> SamlConfig {
        SamlConfig {
            idp_entity_id: "test-idp".to_string(),
            idp_sso_url: "https://idp.example.test/sso".to_string(),
            idp_slo_url: None,
            sp_entity_id: "test-sp".to_string(),
            sp_acs_url: "https://sp.example.test/saml/acs".to_string(),
            idp_cert_path: "idp.crt".to_string(),
            attribute_mapping: SamlAttributeMapping::default(),
            role_mapping: HashMap::new(),
            require_encrypted_assertions: false,
            sign_requests: false,
            sp_key_path: None,
            sp_cert_path: None,
            graph_api: None,
            login_throttle: Default::default(),
        }
    }

    fn saml_attributes(
        user_id: &str,
        username: &str,
    ) -> HashMap<String, String> {
        let mapping = SamlAttributeMapping::default();
        HashMap::from([
            (mapping.user_id, user_id.to_string()),
            (mapping.username, username.to_string()),
            (mapping.email, format!("{username}@example.test")),
        ])
    }

    #[tokio::test]
    async fn concurrent_saml_bootstrap_creates_one_primary_administrator() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("users");
        let avatars_path = temp_dir
            .path()
            .join("avatars");
        let storage = PasskeyStorage::new(
            storage_path
                .to_string_lossy()
                .into_owned(),
            avatars_path
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let config = test_saml_config();
        let first_attributes = saml_attributes("saml-user-1", "first-user");
        let second_attributes = saml_attributes("saml-user-2", "second-user");
        let avatars_storage_path = avatars_path
            .to_string_lossy()
            .into_owned();

        let (first_result, second_result) = tokio::join!(
            provision_user_from_saml(&storage, &first_attributes, &config, &avatars_storage_path),
            provision_user_from_saml(&storage, &second_attributes, &config, &avatars_storage_path),
        );

        first_result.unwrap();
        second_result.unwrap();

        let stored_user_ids = storage
            .list_users()
            .await
            .unwrap();
        let mut stored_users = Vec::new();
        for user_id in stored_user_ids {
            stored_users.push(
                storage
                    .load_user_by_id(&user_id)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(stored_users.len(), 2);
        assert_eq!(
            stored_users
                .iter()
                .filter(|user| user.is_primary)
                .count(),
            1
        );
        assert_eq!(
            stored_users
                .iter()
                .filter(|user| user.role == UserRole::Administrator)
                .count(),
            1
        );
    }

    async fn user_storage(dir: &tempfile::TempDir) -> (PasskeyStorage, String) {
        let avatars = dir
            .path()
            .join("avatars")
            .to_string_lossy()
            .into_owned();
        let storage = PasskeyStorage::new(
            dir.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            avatars.clone(),
        )
        .await
        .unwrap();
        (storage, avatars)
    }

    fn with_role(
        mut attributes: HashMap<String, String>,
        role: &str,
    ) -> HashMap<String, String> {
        attributes.insert(SamlAttributeMapping::default().role, role.to_string());
        attributes
    }

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
        }
    }

    #[tokio::test]
    async fn the_first_sign_in_creates_the_user() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;

        let provisioned =
            provision_user_from_saml(&storage, &saml_attributes("saml-1", "jane"), &test_saml_config(), &avatars)
                .await
                .unwrap();

        assert!(matches!(provisioned.change, SignInChange::Created));
    }

    #[tokio::test]
    async fn a_later_sign_in_reports_the_user_as_it_was_before() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let config = test_saml_config();
        provision_user_from_saml(&storage, &saml_attributes("saml-admin", "admin"), &config, &avatars)
            .await
            .unwrap();
        provision_user_from_saml(&storage, &saml_attributes("saml-1", "jane"), &config, &avatars)
            .await
            .unwrap();

        let second = provision_user_from_saml(
            &storage,
            &with_role(saml_attributes("saml-1", "jane"), "poweruser"),
            &config,
            &avatars,
        )
        .await
        .unwrap();

        match &second.change {
            SignInChange::Updated { previous } => {
                assert_eq!(previous.user_id, second.user.user_id);
                assert_eq!(previous.role, UserRole::User);
            }
            other => panic!("expected an update, got {other:?}"),
        }
        assert_eq!(second.user.role, UserRole::PowerUser);
    }

    #[test]
    fn a_created_user_raises_created_then_login() {
        let provisioned = Provisioned {
            user: user(UserRole::User),
            change: SignInChange::Created,
        };

        let events = sign_in_events(&provisioned);

        assert!(matches!(events.as_slice(), [SignInEvent::Created(_), SignInEvent::Login(_)]));
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
    }
}
