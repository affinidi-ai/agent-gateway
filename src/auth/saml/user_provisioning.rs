use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::auth::auth_config::SamlConfig;
use crate::auth::saml::graph_api::GraphApiClient;
use crate::auth::saml::service::{ROLE_VALUES_KEY, SamlAttributes};
use crate::auth::sign_in_events::{Provisioned, SignInChange};
use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};

/// Whether `attribute` carries more than one distinct value.
fn carries_several_values(
    all_attributes: &SamlAttributes,
    attribute: &str,
) -> bool {
    all_attributes
        .get(attribute)
        .into_iter()
        .flatten()
        .collect::<std::collections::HashSet<_>>()
        .len()
        > 1
}

/// An assertion whose user-id or username attribute carries more than one distinct value, so
/// which one names the user would depend on the identity provider's ordering.
#[derive(Debug, thiserror::Error)]
#[error("The SAML {attribute} attribute carries more than one value")]
pub struct AmbiguousAttribute {
    pub attribute: &'static str,
}

fn ensure_single_valued_identity(
    all_attributes: &SamlAttributes,
    config: &SamlConfig,
) -> Result<(), AmbiguousAttribute> {
    let mapping = &config.attribute_mapping;
    if carries_several_values(all_attributes, &mapping.user_id) {
        return Err(AmbiguousAttribute { attribute: "user ID" });
    }
    if mapping.username != mapping.email && carries_several_values(all_attributes, &mapping.username) {
        return Err(AmbiguousAttribute { attribute: "username" });
    }
    Ok(())
}

/// The value a profile attribute gives the user: the stored one when the identity provider still
/// sends it, else the first sent. Several distinct values are logged by attribute name only.
fn profile_value(
    all_attributes: &SamlAttributes,
    attribute: &str,
    stored: Option<&String>,
) -> Option<String> {
    let values = all_attributes.get(attribute)?;
    if values
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len()
        > 1
    {
        warn!(%attribute, "The SAML attribute carries several values; keeping the stored one if sent, else the first");
    }
    stored
        .filter(|stored| values.contains(stored))
        .or_else(|| values.first())
        .cloned()
}

/// The SAML account has a user who is not approved: an administrator disabled or deleted them.
/// Carries the user as stored, so the ACS refuses the sign-in naming that account and creates
/// nothing.
#[derive(Debug, thiserror::Error)]
#[error("the user is not approved")]
pub struct UserNotApproved(pub Box<UserData>);

/// The username the identity provider asserted and the SAML user ID are both held by other users,
/// so nothing is created or updated.
#[derive(Debug, thiserror::Error)]
#[error("the username is held by another user")]
pub struct UsernameTaken;

/// Provision or update a user from SAML attributes. A user that exists and is not approved is
/// refused with [`UserNotApproved`]. When another user holds the asserted username the SAML user
/// ID is used instead, and only when that is held too is the sign-in refused with
/// [`UsernameTaken`].
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
    ensure_single_valued_identity(all_attributes, config)?;

    // Determine role from SAML attributes
    let role = determine_role(all_attributes, config).map_err(|refused| {
        refused.for_subject(
            attributes
                .get("NameID")
                .map(String::as_str),
        )
    });

    let user_write_guard = storage
        .user_write_guard()
        .await;

    // Check if user already exists
    let existing_user = storage
        .load_user_by_saml_id(user_id_attr)
        .await?;
    if let Some(user) = &existing_user
        && user.status != UserStatus::Approved
    {
        return Err(anyhow::Error::new(UserNotApproved(Box::new(user.clone()))));
    }
    let mapping = &config.attribute_mapping;
    let email = profile_value(
        all_attributes,
        &mapping.email,
        existing_user
            .as_ref()
            .and_then(|user| user.email.as_ref()),
    );
    let username = (mapping.username != mapping.email)
        .then(|| {
            attributes
                .get(&mapping.username)
                .cloned()
        })
        .flatten()
        .or_else(|| email.clone())
        .context("Username not found in SAML attributes")?;
    let first_name = profile_value(
        all_attributes,
        &mapping.first_name,
        existing_user
            .as_ref()
            .and_then(|user| user.first_name.as_ref()),
    );
    let last_name = profile_value(
        all_attributes,
        &mapping.last_name,
        existing_user
            .as_ref()
            .and_then(|user| user.last_name.as_ref()),
    );
    let department = profile_value(
        all_attributes,
        &mapping.department,
        existing_user
            .as_ref()
            .and_then(|user| user.department.as_ref()),
    );
    let job_title = profile_value(
        all_attributes,
        &mapping.job_title,
        existing_user
            .as_ref()
            .and_then(|user| user.job_title.as_ref()),
    );

    let (user, change) = if let Some(mut user) = existing_user {
        let previous = user.clone();
        if user.username != username || username == user.user_id {
            user.username = resolve_username(storage, &username, user_id_attr, Some(&user.user_id)).await?;
        }
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
        let username = resolve_username(storage, &username, user_id_attr, None).await?;
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
                .count_toward_user_limit()
                .await?;
            if let Err(e) = crate::config::global_limits().check_can_add("users", user_count) {
                crate::config::log_limit_reached("users", &e);
                return Err(anyhow::Error::new(e));
            }
        }
        let status = UserStatus::Approved; // SAML users auto-approved (including first user)

        let now = chrono::Utc::now();
        let user = UserData {
            user_id: uuid::Uuid::new_v4().to_string(),
            username,
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
            oidc: None,
            deleted_at: None,
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
                let relative_avatar_path = format!("avatars/{}", avatar_filename);
                match storage
                    .set_avatar_if_approved(&user_id, relative_avatar_path.clone())
                    .await
                {
                    Ok(true) => info!("Successfully updated user {} with avatar: {}", user_id, relative_avatar_path),
                    Ok(false) => {
                        storage
                            .remove_uploaded_avatar(&user_id, &relative_avatar_path)
                            .await
                    }
                    Err(e) => warn!("Failed to update user with avatar path: {}", e),
                }
            }
        } else {
            warn!("Cannot fetch avatar: user has no email address");
        }
    }

    Ok(Provisioned { user, change })
}

/// The username a SAML user gets: the asserted one, or the SAML user ID when another user holds
/// it or it is a user id. A user whose stored username already is the asserted one, and not their
/// user id, keeps it without this check, so users that already share a username keep signing in.
async fn resolve_username(
    storage: &PasskeyStorage,
    asserted: &str,
    saml_user_id: &str,
    own_user_id: Option<&str>,
) -> Result<String> {
    storage
        .free_username(&[asserted, saml_user_id], own_user_id)
        .await?
        .ok_or_else(|| anyhow::Error::new(UsernameTaken))
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
        subject: Option<&str>,
    ) -> Self {
        Self {
            subject: subject.map(str::to_string),
            ..self
        }
    }
}

/// Resolve the gateway role from the identity provider's role values: the highest role an
/// explicit `role_mapping` entry gives any value, else `default_role`, else refused.
fn determine_role(
    attributes: &SamlAttributes,
    config: &SamlConfig,
) -> Result<UserRole, RoleRefused> {
    let values = attributes
        .get(ROLE_VALUES_KEY)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mapped = values
        .iter()
        .filter_map(|value| config.role_mapping.get(value))
        .filter_map(|name| UserRole::from_config_name(name))
        .max_by_key(UserRole::rank);
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
        attributes.insert(ROLE_VALUES_KEY.to_string(), vec![role.to_string()]);
        attributes
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
    async fn a_profile_attribute_with_two_values_takes_the_first_for_a_new_user() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mapping = SamlAttributeMapping::default();
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes.insert(mapping.email, vec!["first@example.test".to_string(), "second@example.test".to_string()]);
        attributes.insert(mapping.department, vec!["Platform".to_string(), "Sales".to_string()]);
        attributes.insert(mapping.job_title, vec!["Engineer".to_string(), "Manager".to_string()]);

        let user = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap()
            .user;

        assert_eq!(user.email.as_deref(), Some("first@example.test"));
        assert_eq!(user.department.as_deref(), Some("Platform"));
        assert_eq!(user.job_title.as_deref(), Some("Engineer"));
    }

    #[tokio::test]
    async fn a_profile_attribute_keeps_the_stored_value_while_the_idp_still_sends_it() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mapping = SamlAttributeMapping::default();
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes.insert(mapping.department.clone(), vec!["Sales".to_string()]);
        let first = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();
        assert!(first.user.is_primary);

        attributes.insert(mapping.department.clone(), vec!["Platform".to_string(), "Sales".to_string()]);
        let kept = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();
        assert_eq!(
            kept.user
                .department
                .as_deref(),
            Some("Sales")
        );
        assert_eq!(kept.user.user_id, first.user.user_id);

        attributes.insert(mapping.department, vec!["Platform".to_string(), "Legal".to_string()]);
        let replaced = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();
        assert_eq!(
            replaced
                .user
                .department
                .as_deref(),
            Some("Platform")
        );
    }

    #[tokio::test]
    async fn the_primary_administrator_signs_in_whatever_profile_values_are_sent() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mapping = SamlAttributeMapping::default();
        let mut attributes = saml_attributes("saml-admin", "admin");
        attributes.insert(mapping.email, vec!["a@example.test".to_string(), "b@example.test".to_string()]);

        let provisioned = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();

        assert!(provisioned.user.is_primary);
        assert_eq!(
            provisioned
                .user
                .email
                .as_deref(),
            Some("a@example.test")
        );
    }

    #[tokio::test]
    async fn a_name_id_equal_to_another_users_stored_key_does_not_land_on_that_account() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let config = mapped_config();
        let owner = provision_user_from_saml(&storage, &saml_attributes("shared-key", "owner"), &config, &avatars)
            .await
            .unwrap();
        let mut attributes = with_role(saml_attributes("newcomer-id", "newcomer"), "gw-admins");
        attributes.insert("NameID".to_string(), vec!["shared-key".to_string()]);

        let newcomer = provision_user_from_saml(&storage, &attributes, &config, &avatars)
            .await
            .unwrap();

        assert!(matches!(newcomer.change, SignInChange::Created));
        assert_ne!(newcomer.user.user_id, owner.user.user_id);
        assert_eq!(
            newcomer
                .user
                .saml_id
                .as_deref(),
            Some("newcomer-id")
        );
        let owner_now = storage
            .load_user_by_saml_id("shared-key")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner_now.user_id, owner.user.user_id);
        assert_eq!(owner_now.username, "owner");
    }

    #[tokio::test]
    async fn two_emails_with_no_username_attribute_sign_in_and_the_username_follows_the_stored_email() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mapping = SamlAttributeMapping::default();
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes.remove(&mapping.username);
        attributes.insert(mapping.email.clone(), vec!["old@example.test".to_string()]);
        let first = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();
        assert_eq!(first.user.username, "old@example.test");

        attributes.insert(mapping.email, vec!["new@example.test".to_string(), "old@example.test".to_string()]);
        let again = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();

        assert_eq!(again.user.email.as_deref(), Some("old@example.test"));
        assert_eq!(again.user.username, "old@example.test");
    }

    #[tokio::test]
    async fn a_username_mapped_to_the_email_claim_follows_the_kept_email_whatever_addresses_are_sent() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mut config = test_saml_config();
        config
            .attribute_mapping
            .username = config
            .attribute_mapping
            .email
            .clone();
        let email = config
            .attribute_mapping
            .email
            .clone();
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes.insert(email.clone(), vec!["primary@example.test".to_string()]);
        let first = provision_user_from_saml(&storage, &attributes, &config, &avatars)
            .await
            .unwrap();
        assert_eq!(first.user.username, "primary@example.test");

        attributes.insert(email, vec!["alias@example.test".to_string(), "primary@example.test".to_string()]);
        let again = provision_user_from_saml(&storage, &attributes, &config, &avatars)
            .await
            .unwrap();

        assert_eq!(again.user.username, "primary@example.test");
        assert_eq!(again.user.email.as_deref(), Some("primary@example.test"));
    }

    #[tokio::test]
    async fn an_assertion_with_neither_a_username_nor_an_email_is_refused() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mapping = SamlAttributeMapping::default();
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes.remove(&mapping.username);
        attributes.remove(&mapping.email);

        let err = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("Username not found")
        );
    }

    #[tokio::test]
    async fn a_sign_in_whose_name_id_matches_nobody_creates_a_new_user() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let config = mapped_config();
        provision_user_from_saml(&storage, &saml_attributes("saml-first", "first"), &config, &avatars)
            .await
            .unwrap();
        let mut attributes = with_role(saml_attributes("attribute-id-2", "second"), "gw-admins");
        attributes.insert("NameID".to_string(), vec!["unknown-name-id".to_string()]);

        let provisioned = provision_user_from_saml(&storage, &attributes, &config, &avatars)
            .await
            .unwrap();

        assert!(matches!(provisioned.change, SignInChange::Created));
        assert_eq!(
            storage
                .list_users()
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn a_profile_attribute_repeating_one_value_is_accepted() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mapping = SamlAttributeMapping::default();
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes.insert(mapping.email, vec!["jane@example.test".to_string(); 2]);
        attributes.insert(mapping.department, vec!["Platform".to_string(); 2]);

        let provisioned = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap();

        assert_eq!(
            provisioned
                .user
                .email
                .as_deref(),
            Some("jane@example.test")
        );
        assert_eq!(
            provisioned
                .user
                .department
                .as_deref(),
            Some("Platform")
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
    async fn an_assertion_whose_username_attribute_has_two_distinct_values_is_refused() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let mut attributes = saml_attributes("saml-1", "jane");
        attributes
            .get_mut(&SamlAttributeMapping::default().username)
            .unwrap()
            .push("sam".to_string());

        let err = provision_user_from_saml(&storage, &attributes, &test_saml_config(), &avatars)
            .await
            .unwrap_err();

        assert_eq!(
            err.downcast_ref::<AmbiguousAttribute>()
                .map(|ambiguous| ambiguous.attribute),
            Some("username")
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
    async fn a_refusal_names_the_assertion_subject_not_the_mapped_user_id() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let config = mapped_config();
        provision_user_from_saml(&storage, &saml_attributes("saml-first", "first"), &config, &avatars)
            .await
            .unwrap();
        let mut attributes = with_role(saml_attributes("mapped-id", "mallory"), "admin");
        attributes.insert("NameID".to_string(), vec!["name-id-subject".to_string()]);

        let err = provision_user_from_saml(&storage, &attributes, &config, &avatars)
            .await
            .unwrap_err();

        let refused = err
            .downcast_ref::<RoleRefused>()
            .unwrap();
        assert_eq!(refused.subject.as_deref(), Some("name-id-subject"));
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
            ROLE_VALUES_KEY.to_string(),
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

        let mut attributes = with_role(saml_attributes("saml-2", "jane"), "contractors");
        attributes.insert("NameID".to_string(), vec!["saml-2".to_string()]);

        let err = provision_user_from_saml(&storage, &attributes, &config, &avatars)
            .await
            .unwrap_err();

        let refused = err
            .downcast_ref::<RoleRefused>()
            .unwrap();
        assert_eq!(refused.subject.as_deref(), Some("saml-2"));
        assert_eq!(refused.idp_role.as_deref(), Some("contractors"));
    }

    fn any_role_config() -> SamlConfig {
        let mut config = test_saml_config();
        config.default_role = Some("user".to_string());
        config
    }

    async fn sign_in(
        storage: &PasskeyStorage,
        avatars: &str,
        saml_user_id: &str,
        username: &str,
    ) -> Result<Provisioned> {
        provision_user_from_saml(storage, &saml_attributes(saml_user_id, username), &any_role_config(), avatars).await
    }

    async fn alice_and_bob(
        storage: &PasskeyStorage,
        avatars: &str,
    ) -> (UserData, UserData) {
        let alice = sign_in(storage, avatars, "alice", "alice")
            .await
            .unwrap()
            .user;
        let bob = sign_in(storage, avatars, "bob", "bob")
            .await
            .unwrap()
            .user;
        (alice, bob)
    }

    async fn user_count(storage: &PasskeyStorage) -> usize {
        storage
            .list_users()
            .await
            .unwrap()
            .len()
    }

    #[tokio::test]
    async fn a_new_account_asserting_a_username_another_user_holds_gets_its_saml_user_id_as_username() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let (_, bob) = alice_and_bob(&storage, &avatars).await;

        let second_bob = sign_in(&storage, &avatars, "name-id-2", "bob")
            .await
            .unwrap()
            .user;

        assert_eq!(second_bob.username, "name-id-2");
        assert_ne!(second_bob.user_id, bob.user_id);
        let holder = storage
            .load_user_by_id(&bob.user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((holder.username.as_str(), holder.saml_id.as_deref()), ("bob", Some("bob")));
    }

    #[tokio::test]
    async fn a_sign_in_whose_asserted_username_and_saml_user_id_are_both_held_is_refused_and_nothing_is_created() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        alice_and_bob(&storage, &avatars).await;
        sign_in(&storage, &avatars, "someone", "name-id-3")
            .await
            .unwrap();

        let refused = sign_in(&storage, &avatars, "name-id-3", "bob")
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<UsernameTaken>()
                .is_some(),
            "{refused:?}"
        );
        assert_eq!(user_count(&storage).await, 3);
    }

    #[tokio::test]
    async fn an_existing_account_whose_asserted_username_another_user_holds_keeps_its_own() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let (alice, _) = alice_and_bob(&storage, &avatars).await;

        let signed_in = sign_in(&storage, &avatars, "alice", "bob")
            .await
            .unwrap()
            .user;

        assert_eq!(signed_in.user_id, alice.user_id);
        assert_eq!(signed_in.username, "alice", "the SAML user ID, which alice already holds");
    }

    #[tokio::test]
    async fn two_existing_users_that_share_a_username_both_keep_signing_in() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let (_, bob) = alice_and_bob(&storage, &avatars).await;
        let mut duplicate = sign_in(&storage, &avatars, "dup", "dup")
            .await
            .unwrap()
            .user;
        duplicate.username = "bob".to_string();
        storage
            .save_user(&duplicate)
            .await
            .unwrap();

        let first = sign_in(&storage, &avatars, "bob", "bob")
            .await
            .unwrap()
            .user;
        let second = sign_in(&storage, &avatars, "dup", "bob")
            .await
            .unwrap()
            .user;

        assert_eq!((first.user_id.as_str(), first.username.as_str()), (bob.user_id.as_str(), "bob"));
        assert_eq!((second.user_id.as_str(), second.username.as_str()), (duplicate.user_id.as_str(), "bob"));
    }

    #[tokio::test]
    async fn a_user_who_is_not_approved_is_refused_and_left_unchanged() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let (_, bob) = alice_and_bob(&storage, &avatars).await;
        for status in [UserStatus::Disabled, UserStatus::New] {
            storage
                .update_user(&bob.user_id, None, Some(status.clone()), &crate::config::LimitsConfig::default())
                .await
                .unwrap();

            let refused = sign_in(&storage, &avatars, "bob", "alice")
                .await
                .unwrap_err();

            let UserNotApproved(stored) = refused
                .downcast_ref::<UserNotApproved>()
                .unwrap_or_else(|| panic!("{status}: {refused:?}"));
            assert_eq!(stored.user_id, bob.user_id);
            let stored = storage
                .load_user_by_id(&bob.user_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!((stored.status, stored.username.as_str()), (status, "bob"));
        }
    }

    #[tokio::test]
    async fn a_deleted_user_is_refused_at_the_next_sign_in_and_not_created_again() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let (_, bob) = alice_and_bob(&storage, &avatars).await;
        storage
            .delete_user(&bob.user_id)
            .await
            .unwrap();

        let refused = sign_in(&storage, &avatars, "bob", "bob")
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<UserNotApproved>()
                .is_some(),
            "{refused:?}"
        );
        assert_eq!(user_count(&storage).await, 2, "no second user for the SAML account");
    }

    #[tokio::test]
    async fn a_deleted_user_signs_in_as_the_same_user_once_approved_again() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let (_, bob) = alice_and_bob(&storage, &avatars).await;
        storage
            .delete_user(&bob.user_id)
            .await
            .unwrap();
        storage
            .update_user(&bob.user_id, None, Some(UserStatus::Approved), &crate::config::LimitsConfig::default())
            .await
            .unwrap();

        let again = sign_in(&storage, &avatars, "bob", "bob")
            .await
            .unwrap()
            .user;

        assert_eq!(again.user_id, bob.user_id);
        assert_eq!(again.username, "bob");
        assert_eq!(again.status, UserStatus::Approved);
        assert!(again.deleted_at.is_none());
    }

    #[tokio::test]
    async fn an_asserted_username_equal_to_the_users_own_id_gives_them_their_saml_user_id() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let (_, bob) = alice_and_bob(&storage, &avatars).await;

        let signed_in = sign_in(&storage, &avatars, "bob", &bob.user_id)
            .await
            .unwrap()
            .user;
        assert_eq!((signed_in.user_id.as_str(), signed_in.username.as_str()), (bob.user_id.as_str(), "bob"));

        storage
            .delete_user(&bob.user_id)
            .await
            .unwrap();
        storage
            .update_user(&bob.user_id, None, Some(UserStatus::Approved), &crate::config::LimitsConfig::default())
            .await
            .unwrap();
        let approved_again = sign_in(&storage, &avatars, "bob", &bob.user_id)
            .await
            .unwrap()
            .user;
        assert_eq!(approved_again.username, "bob", "a kept record approved again never keeps its user id as username");
    }

    #[tokio::test]
    async fn an_asserted_username_equal_to_another_users_id_gives_the_saml_user_id() {
        let dir = tempdir().unwrap();
        let (storage, avatars) = user_storage(&dir).await;
        let (alice, _) = alice_and_bob(&storage, &avatars).await;

        let newcomer = sign_in(&storage, &avatars, "carol", &alice.user_id)
            .await
            .unwrap()
            .user;

        assert_ne!(newcomer.user_id, alice.user_id);
        assert_eq!(newcomer.username, "carol");
    }
}
