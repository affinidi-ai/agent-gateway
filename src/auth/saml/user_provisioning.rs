use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::auth::auth_config::SamlConfig;
use crate::auth::saml::graph_api::GraphApiClient;
use crate::auth::saml::service::SamlAttributes;
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

/// Refuse an assertion whose user-id attribute carries more than one distinct value, since which
/// one identifies the user would depend on the identity provider's ordering.
fn ensure_single_user_id(
    all_attributes: &SamlAttributes,
    config: &SamlConfig,
) -> Result<()> {
    let user_id_attribute = if all_attributes.contains_key(
        &config
            .attribute_mapping
            .user_id,
    ) {
        &config
            .attribute_mapping
            .user_id
    } else {
        "NameID"
    };
    let distinct: std::collections::HashSet<&String> = all_attributes
        .get(user_id_attribute)
        .into_iter()
        .flatten()
        .collect();
    anyhow::ensure!(distinct.len() <= 1, "The SAML user ID attribute carries more than one value");
    Ok(())
}

/// Provision or update a user from SAML attributes
pub async fn provision_user_from_saml(
    storage: &PasskeyStorage,
    all_attributes: &SamlAttributes,
    config: &SamlConfig,
    avatars_storage_path: &str,
) -> Result<Provisioned> {
    let attributes: HashMap<String, String> = all_attributes
        .iter()
        .filter_map(|(name, values)| {
            values
                .first()
                .map(|value| (name.clone(), value.clone()))
        })
        .collect();
    // Extract user attributes using configured mappings
    let user_id_attr = attributes
        .get(
            &config
                .attribute_mapping
                .user_id,
        )
        .or_else(|| attributes.get("NameID"))
        .context("User ID not found in SAML attributes")?;
    ensure_single_user_id(all_attributes, config)?;

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
    let role = determine_role(all_attributes, config).map_err(|refused| refused.for_subject(user_id_attr));

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
        if !user.is_primary {
            user.role = role?;
        } else {
            match &role {
                Ok(role) if *role != UserRole::Administrator => {
                    warn!(user_id = %user.user_id, idp_role = %role, "Kept the primary administrator's role over the IdP role");
                }
                Ok(_) => {}
                Err(refused) => {
                    warn!(user_id = %user.user_id, idp_role = ?refused.idp_role, "Kept the primary administrator's role; the IdP role maps to no gateway role");
                }
            }
        }
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

        let final_role = if is_first_user {
            if let Err(refused) = &role {
                warn!(idp_role = ?refused.idp_role, "Created the first user as administrator; the IdP role maps to no gateway role");
            }
            UserRole::Administrator
        } else {
            role?
        };

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

/// The longest identity-provider role value kept for a refusal's log line.
const MAX_LOGGED_ROLE_CHARS: usize = 200;

/// A sign-in whose identity-provider role values map to no gateway role while no `default_role`
/// is set. `idp_role` is the values received, joined, capped and `None` when the claim was absent;
/// it is identity-provider input, so log it only with `?`.
#[derive(Debug, thiserror::Error)]
#[error("identity-provider role is not mapped to a gateway role")]
pub struct RoleRefused {
    pub subject: Option<String>,
    pub idp_role: Option<String>,
}

impl RoleRefused {
    fn for_subject(
        self,
        subject: &str,
    ) -> Self {
        Self {
            subject: Some(subject.to_string()),
            ..self
        }
    }
}

fn privilege(role: &UserRole) -> u8 {
    match role {
        UserRole::Administrator => 2,
        UserRole::PowerUser => 1,
        UserRole::User => 0,
    }
}

/// Resolve the gateway role from the identity provider's role values: the highest role an
/// explicit `role_mapping` entry gives any value, else `default_role`, else refused.
fn determine_role(
    attributes: &SamlAttributes,
    config: &SamlConfig,
) -> Result<UserRole, RoleRefused> {
    let values = attributes
        .get(&config.attribute_mapping.role)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mapped = values
        .iter()
        .filter_map(|value| config.role_mapping.get(value))
        .filter_map(|name| UserRole::from_config_name(name))
        .max_by_key(privilege);
    let role = mapped.or_else(|| {
        config
            .default_role
            .as_deref()
            .and_then(UserRole::from_config_name)
    });
    role.ok_or_else(|| RoleRefused {
        subject: None,
        idp_role: (!values.is_empty()).then(|| {
            values
                .join(",")
                .chars()
                .take(MAX_LOGGED_ROLE_CHARS)
                .collect()
        }),
    })
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
            default_role: None,
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
    ) -> SamlAttributes {
        let mapping = SamlAttributeMapping::default();
        HashMap::from([
            (mapping.user_id, vec![user_id.to_string()]),
            (mapping.username, vec![username.to_string()]),
            (mapping.email, vec![format!("{username}@example.test")]),
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
        let mut config = test_saml_config();
        config.default_role = Some("user".to_string());
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
        mut attributes: SamlAttributes,
        role: &str,
    ) -> SamlAttributes {
        attributes.insert(SamlAttributeMapping::default().role, vec![role.to_string()]);
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
        let mut config = test_saml_config();
        config.default_role = Some("user".to_string());
        config
            .role_mapping
            .insert("gw-power".to_string(), "poweruser".to_string());
        provision_user_from_saml(&storage, &saml_attributes("saml-admin", "admin"), &config, &avatars)
            .await
            .unwrap();
        provision_user_from_saml(&storage, &saml_attributes("saml-1", "jane"), &config, &avatars)
            .await
            .unwrap();

        let second = provision_user_from_saml(
            &storage,
            &with_role(saml_attributes("saml-1", "jane"), "gw-power"),
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

    #[tokio::test]
    async fn the_primary_administrator_keeps_the_role_whatever_the_idp_sends() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mut config = test_saml_config();
        config
            .role_mapping
            .insert("gw-all".to_string(), "user".to_string());
        let first = provision_user_from_saml(&storage, &saml_attributes("saml-admin", "admin"), &config, &avatars)
            .await
            .unwrap();
        assert!(first.user.is_primary);
        assert_eq!(first.user.role, UserRole::Administrator);

        for attributes in
            [saml_attributes("saml-admin", "admin"), with_role(saml_attributes("saml-admin", "admin"), "gw-all")]
        {
            let again = provision_user_from_saml(&storage, &attributes, &config, &avatars)
                .await
                .unwrap();

            assert_eq!(again.user.role, UserRole::Administrator);
            assert!(again.user.is_primary);
        }
    }

    #[tokio::test]
    async fn the_user_id_username_and_email_take_the_first_value_of_their_attribute() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mapping = SamlAttributeMapping::default();
        let attributes: SamlAttributes = HashMap::from([
            (mapping.user_id, vec!["saml-1".to_string()]),
            (mapping.username, vec!["first-name".to_string(), "second-name".to_string()]),
            (mapping.email, vec!["first@example.test".to_string(), "second@example.test".to_string()]),
        ]);

        let provisioned = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();

        assert_eq!(
            provisioned
                .user
                .saml_id
                .as_deref(),
            Some("saml-1")
        );
        assert_eq!(provisioned.user.username, "first-name");
        assert_eq!(
            provisioned
                .user
                .email
                .as_deref(),
            Some("first@example.test")
        );
    }

    #[tokio::test]
    async fn an_assertion_whose_user_id_attribute_has_two_distinct_values_is_refused() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes
            .get_mut(&SamlAttributeMapping::default().user_id)
            .unwrap()
            .push("saml-2".to_string());

        let err = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("more than one value")
        );
        assert!(
            storage
                .list_users()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_user_id_attribute_repeating_one_value_is_accepted() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes
            .get_mut(&SamlAttributeMapping::default().user_id)
            .unwrap()
            .push("saml-1".to_string());

        let provisioned = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();

        assert_eq!(
            provisioned
                .user
                .saml_id
                .as_deref(),
            Some("saml-1")
        );
    }

    fn mapped_config() -> SamlConfig {
        let mut config = test_saml_config();
        config
            .role_mapping
            .insert("gw-admins".to_string(), "administrator".to_string());
        config
    }

    #[test]
    fn an_unmapped_role_named_like_a_gateway_role_is_refused() {
        let config = mapped_config();
        for name in ["admin", "administrator", "Administrator", "ADMIN", "poweruser", "power_user", "power-user"] {
            let attributes = with_role(HashMap::new(), name);
            assert!(determine_role(&attributes, &config).is_err(), "{name} must not grant a role");
        }
    }

    #[test]
    fn an_explicit_mapping_grants_its_role() {
        let attributes = with_role(HashMap::new(), "gw-admins");
        assert_eq!(determine_role(&attributes, &mapped_config()).unwrap(), UserRole::Administrator);
    }

    #[test]
    fn an_unmapped_role_gets_the_default_role_never_a_name_match() {
        let mut config = mapped_config();
        config.default_role = Some("user".to_string());
        let attributes = with_role(HashMap::new(), "admin");
        assert_eq!(determine_role(&attributes, &config).unwrap(), UserRole::User);
    }

    #[test]
    fn a_missing_role_attribute_is_refused_without_a_default_role_and_defaulted_with_one() {
        let mut config = mapped_config();
        assert!(determine_role(&HashMap::new(), &config).is_err());
        config.default_role = Some("poweruser".to_string());
        assert_eq!(determine_role(&HashMap::new(), &config).unwrap(), UserRole::PowerUser);
    }

    #[tokio::test]
    async fn an_unmapped_role_refuses_a_new_user_and_stores_nothing() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let config = mapped_config();
        provision_user_from_saml(&storage, &saml_attributes("saml-first", "first"), &config, &avatars)
            .await
            .unwrap();

        let err = provision_user_from_saml(
            &storage,
            &with_role(saml_attributes("saml-2", "mallory"), "admin"),
            &config,
            &avatars,
        )
        .await
        .unwrap_err();

        assert!(
            err.downcast_ref::<RoleRefused>()
                .is_some()
        );
        assert_eq!(
            storage
                .list_users()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn an_existing_user_whose_role_becomes_unmapped_is_refused_and_keeps_the_stored_role() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let config = mapped_config();
        provision_user_from_saml(&storage, &saml_attributes("saml-first", "first"), &config, &avatars)
            .await
            .unwrap();
        let second = provision_user_from_saml(
            &storage,
            &with_role(saml_attributes("saml-2", "jane"), "gw-admins"),
            &config,
            &avatars,
        )
        .await
        .unwrap();
        assert_eq!(second.user.role, UserRole::Administrator);

        let err = provision_user_from_saml(
            &storage,
            &with_role(saml_attributes("saml-2", "jane"), "contractors"),
            &config,
            &avatars,
        )
        .await
        .unwrap_err();

        assert!(
            err.downcast_ref::<RoleRefused>()
                .is_some()
        );
        let stored = storage
            .load_user_by_saml_id("saml-2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.role, UserRole::Administrator);
    }

    fn with_roles(
        mut attributes: SamlAttributes,
        roles: &[&str],
    ) -> SamlAttributes {
        attributes.insert(
            SamlAttributeMapping::default().role,
            roles
                .iter()
                .map(|role| role.to_string())
                .collect(),
        );
        attributes
    }

    #[test]
    fn the_highest_mapped_role_among_several_values_wins_whatever_their_order() {
        let mut config = mapped_config();
        config
            .role_mapping
            .insert("gw-all".to_string(), "user".to_string());
        config
            .role_mapping
            .insert("gw-power".to_string(), "poweruser".to_string());
        for roles in [["contractors", "gw-admins"], ["gw-admins", "contractors"]] {
            let resolved = determine_role(&with_roles(HashMap::new(), &roles), &config).unwrap();
            assert_eq!(resolved, UserRole::Administrator, "{roles:?}");
        }
        let resolved = determine_role(&with_roles(HashMap::new(), &["gw-all", "gw-power"]), &config).unwrap();
        assert_eq!(resolved, UserRole::PowerUser);
    }

    #[test]
    fn several_unmapped_values_are_refused_and_an_unmapped_admin_name_among_them_grants_nothing() {
        let config = mapped_config();
        let refused = determine_role(&with_roles(HashMap::new(), &["contractors", "admin"]), &config).unwrap_err();
        assert_eq!(refused.idp_role.as_deref(), Some("contractors,admin"));
    }

    #[test]
    fn a_refusal_names_the_values_received_or_none_for_an_absent_claim_and_caps_them() {
        let config = mapped_config();
        let absent = determine_role(&HashMap::new(), &config).unwrap_err();
        assert_eq!(absent.idp_role, None);

        let long = "x".repeat(MAX_LOGGED_ROLE_CHARS + 50);
        let capped = determine_role(&with_role(HashMap::new(), &long), &config).unwrap_err();
        assert_eq!(
            capped
                .idp_role
                .unwrap()
                .chars()
                .count(),
            MAX_LOGGED_ROLE_CHARS
        );
    }

    #[tokio::test]
    async fn a_refused_new_user_is_named_by_the_saml_subject() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let config = mapped_config();
        provision_user_from_saml(&storage, &saml_attributes("saml-first", "first"), &config, &avatars)
            .await
            .unwrap();

        let err = provision_user_from_saml(
            &storage,
            &with_role(saml_attributes("saml-2", "jane"), "contractors"),
            &config,
            &avatars,
        )
        .await
        .unwrap_err();

        let refused = err
            .downcast_ref::<RoleRefused>()
            .unwrap();
        assert_eq!(refused.subject.as_deref(), Some("saml-2"));
        assert_eq!(refused.idp_role.as_deref(), Some("contractors"));
    }
}
