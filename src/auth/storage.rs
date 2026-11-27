use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::sync::{Mutex, MutexGuard};
use webauthn_rs::prelude::*;

use super::types::{UserRole, UserStatus};
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};

/// Storage for passkey user data, backed by CachedFilesystemStorage
///
/// Uses in-memory cache (DashMap-based) for fast reads with automatic
/// disk persistence. Ideal for user data which is read on every
/// authentication request but written infrequently.
pub struct PasskeyStorage {
    storage: Box<dyn StorageBackend<UserData>>,
    avatars_path: String,
    user_write_lock: Mutex<()>,
}

/// The avatar file every new passkey user shares; never removed with a user.
const DEFAULT_AVATAR_FILE: &str = "default.png";

/// User data stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub user_id: String, // UUID for the user
    pub username: String,
    pub passkeys: Vec<Passkey>,
    pub role: UserRole,
    pub status: UserStatus,

    /// Primary user flag - first user registered, cannot be deleted or demoted
    #[serde(default)]
    pub is_primary: bool,

    // Profile information
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub job_title: Option<String>,
    #[serde(default)]
    pub avatar_path: Option<String>,

    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub last_logged_in: Option<chrono::DateTime<chrono::Utc>>,

    /// SAML user ID (for SAML-authenticated users)
    #[serde(default)]
    pub saml_id: Option<String>,

    /// The OpenID provider account this user signs in with (OIDC mode)
    #[serde(default)]
    pub oidc: Option<OidcIdentity>,

    /// When an administrator deleted this user. Set only on a record that is kept, disabled, so
    /// the user's provider account stays refused. Such a record does not count toward the user
    /// limit.
    #[serde(default)]
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// What deleting a user did to the record: `Removed` when it is gone, `Disabled` when it is
/// kept, scrubbed and refused at sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeleteOutcome {
    Removed,
    Disabled,
}

/// How a user signs in to the dashboard. A user with an OpenID provider or SAML account is kept,
/// not removed, when deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignInMethod {
    Passkey,
    Oidc,
    Saml,
}

/// The result of a delete: the outcome, and whether this call changed the record. A delete of a
/// record that is already kept changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteResult {
    pub outcome: DeleteOutcome,
    pub changed: bool,
}

/// An account at an OpenID provider: its issuer and the subject (`sub`) it gave the account.
/// Together they identify the person; email never does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
}

/// The single plain file name an `avatars/<name>` path stores, or `None` for any other path.
fn avatar_file_name(avatar_path: Option<&str>) -> Option<std::ffi::OsString> {
    let relative = avatar_path?.strip_prefix("avatars/")?;
    let mut components = Path::new(relative).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(file)), None) => Some(file.to_os_string()),
        _ => None,
    }
}

impl StorableEntity for UserData {
    fn id(&self) -> &str {
        &self.user_id
    }
}

impl UserData {
    pub fn sign_in_method(&self) -> SignInMethod {
        if self.oidc.is_some() {
            SignInMethod::Oidc
        } else if self.saml_id.is_some() {
            SignInMethod::Saml
        } else {
            SignInMethod::Passkey
        }
    }
}

impl PasskeyStorage {
    /// Create a new passkey storage instance backed by CachedFilesystemStorage
    pub async fn new(
        storage_path: String,
        avatars_path: String,
    ) -> Result<Self> {
        // Create avatars directory if it doesn't exist
        std::fs::create_dir_all(&avatars_path)
            .with_context(|| format!("Failed to create avatars directory: {}", avatars_path))?;

        // Copy default avatar if it doesn't exist
        let default_avatar_dest = format!("{avatars_path}/{DEFAULT_AVATAR_FILE}");
        if !Path::new(&default_avatar_dest).exists() {
            let default_avatar_src = include_bytes!("../auth_manager/default_avatar.png");
            std::fs::write(&default_avatar_dest, default_avatar_src)
                .with_context(|| format!("Failed to write default avatar: {}", default_avatar_dest))?;
            tracing::info!("Copied default avatar to: {}", default_avatar_dest);
        }

        let storage = cached_storage(PathBuf::from(&storage_path), "passkey_user").await?;

        Ok(Self {
            storage,
            avatars_path,
            user_write_lock: Mutex::new(()),
        })
    }

    pub async fn user_write_guard(&self) -> MutexGuard<'_, ()> {
        self.user_write_lock
            .lock()
            .await
    }

    /// Get the avatars storage path
    pub fn avatars_path(&self) -> &str {
        &self.avatars_path
    }

    /// Load user data by username (scans in-memory cache)
    pub async fn load_user(
        &self,
        username: &str,
    ) -> Result<Option<UserData>> {
        let users = self
            .storage
            .list_all()
            .await?;
        Ok(users
            .into_iter()
            .find(|u| u.username == username))
    }

    /// Load user by user_id (direct cache lookup)
    pub async fn load_user_by_id(
        &self,
        user_id: &str,
    ) -> Result<Option<UserData>> {
        self.storage
            .get(user_id)
            .await
    }

    /// Save user data to disk and cache
    pub async fn save_user(
        &self,
        user_data: &UserData,
    ) -> Result<()> {
        self.storage
            .save(user_data)
            .await
    }

    /// A new user holding their initial passkey, to be stored once consent succeeds. The first
    /// user is the Primary Administrator; any other awaits approval. The caller checks that the
    /// username is free and the user limit allows another user.
    pub(crate) fn prepare_user_with_passkey(
        &self,
        username: &str,
        passkey: Passkey,
        is_first_user: bool,
    ) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            passkeys: vec![passkey],
            role: if is_first_user {
                UserRole::Administrator
            } else {
                UserRole::User
            },
            status: if is_first_user {
                UserStatus::Approved
            } else {
                UserStatus::New
            },
            is_primary: is_first_user,
            created_at: now,
            updated_at: now,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
            avatar_path: Some(format!("avatars/{DEFAULT_AVATAR_FILE}")),
            last_logged_in: None,
            saml_id: None,
            oidc: None,
            deleted_at: None,
        }
    }

    /// Update a user's role and status by id. Approving a kept record gives it a seat back, so the
    /// user limit is checked against the count taken under the same guard every creator holds.
    pub async fn update_user(
        &self,
        user_id: &str,
        role: Option<UserRole>,
        status: Option<UserStatus>,
        limits: &crate::config::LimitsConfig,
    ) -> Result<()> {
        let _user_write_guard = self.user_write_guard().await;
        let mut user_data = self
            .load_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        if let Some(new_status) = status {
            if new_status == UserStatus::Approved && user_data.deleted_at.is_some() {
                limits
                    .check_can_add(
                        "users",
                        self.count_toward_user_limit()
                            .await?,
                    )
                    .map_err(anyhow::Error::new)?;
                user_data.deleted_at = None;
            }
            user_data.status = new_status;
        }
        if let Some(new_role) = role {
            user_data.role = new_role;
        }
        user_data.updated_at = chrono::Utc::now();

        self.save_user(&user_data)
            .await
    }

    /// Record a sign-in on the stored record of an approved user. Returns `None` when the record
    /// is gone or no longer approved, so a delete that lands during the sign-in is not undone by
    /// this write.
    pub async fn record_login(
        &self,
        user_id: &str,
    ) -> Result<Option<UserData>> {
        let _user_write_guard = self.user_write_guard().await;
        let Some(mut user_data) = self
            .load_user_by_id(user_id)
            .await?
            .filter(|user| user.status == UserStatus::Approved)
        else {
            return Ok(None);
        };
        user_data.last_logged_in = Some(chrono::Utc::now());
        self.save_user(&user_data)
            .await?;
        Ok(Some(user_data))
    }

    /// Link an uploaded avatar to a user who is still approved. Returns whether the link was
    /// written; when it was not, the caller removes the file it uploaded.
    pub async fn set_avatar_if_approved(
        &self,
        user_id: &str,
        avatar_path: String,
    ) -> Result<bool> {
        let _user_write_guard = self.user_write_guard().await;
        let Some(mut user_data) = self
            .load_user_by_id(user_id)
            .await?
            .filter(|user| user.status == UserStatus::Approved && user.deleted_at.is_none())
        else {
            return Ok(false);
        };
        user_data.avatar_path = Some(avatar_path);
        user_data.updated_at = chrono::Utc::now();
        self.save_user(&user_data)
            .await?;
        Ok(true)
    }

    /// Whether another user already holds `username`. Call it while holding
    /// [`Self::user_write_guard`], as the creators of users do, so the answer still holds when the
    /// record is written.
    pub async fn username_held_by_other(
        &self,
        username: &str,
        own_user_id: Option<&str>,
    ) -> Result<bool> {
        Ok(self
            .storage
            .list_all()
            .await?
            .iter()
            .any(|holder| holder.username == username && Some(holder.user_id.as_str()) != own_user_id))
    }

    /// The first of `candidates` that no other user has as their username, so no two users share
    /// one. Call it under the same guard as [`Self::username_held_by_other`].
    pub async fn free_username(
        &self,
        candidates: &[&str],
        own_user_id: Option<&str>,
    ) -> Result<Option<String>> {
        for candidate in candidates {
            if !self
                .username_held_by_other(candidate, own_user_id)
                .await?
            {
                return Ok(Some((*candidate).to_string()));
            }
        }
        Ok(None)
    }

    /// Update user profile information and return whether it was written. A missing user and a
    /// deleted user's kept record are left unchanged, so an update that waited for the guard
    /// behind a delete does not write profile data back onto the scrubbed record.
    pub async fn update_profile(
        &self,
        user_id: &str,
        first_name: Option<String>,
        last_name: Option<String>,
        email: Option<String>,
        department: Option<String>,
        job_title: Option<String>,
        avatar_path: Option<String>,
    ) -> Result<bool> {
        let _user_write_guard = self.user_write_guard().await;
        let Some(mut user_data) = self
            .load_user_by_id(user_id)
            .await?
            .filter(|user| user.deleted_at.is_none())
        else {
            return Ok(false);
        };

        if let Some(fn_val) = first_name {
            user_data.first_name = Some(fn_val);
        }
        if let Some(ln_val) = last_name {
            user_data.last_name = Some(ln_val);
        }
        if let Some(email_val) = email {
            user_data.email = Some(email_val);
        }
        if let Some(dept_val) = department {
            user_data.department = Some(dept_val);
        }
        if let Some(job_val) = job_title {
            user_data.job_title = Some(job_val);
        }
        if let Some(avatar_val) = avatar_path {
            user_data.avatar_path = Some(avatar_val);
        }
        user_data.updated_at = chrono::Utc::now();

        self.save_user(&user_data)
            .await?;
        Ok(true)
    }

    /// List all user_ids from cache
    #[allow(dead_code)]
    pub async fn list_users(&self) -> Result<Vec<String>> {
        let users = self
            .storage
            .list_all()
            .await?;
        Ok(users
            .into_iter()
            .map(|u| u.user_id)
            .collect())
    }

    /// Number of stored users that count toward the appliance user limit: every user except the
    /// kept record of a deleted user.
    pub async fn count_toward_user_limit(&self) -> Result<usize> {
        Ok(self
            .storage
            .list_all()
            .await?
            .iter()
            .filter(|user| user.deleted_at.is_none())
            .count())
    }

    /// Delete a user by id and report what happened to the record. A user who signs in through an
    /// OpenID provider or SAML is not removed: the record is scrubbed of profile data and kept
    /// `Disabled` under the provider account, so the next sign-in is refused instead of creating a
    /// new approved user. Deleting a kept record again changes nothing. The uploaded avatar files
    /// are removed after the record changed, and a failure to remove one is logged, never returned.
    pub async fn delete_user(
        &self,
        user_id: &str,
    ) -> Result<DeleteResult> {
        let _user_write_guard = self.user_write_guard().await;
        let mut user_data = self
            .load_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        if user_data.deleted_at.is_some() {
            return Ok(DeleteResult {
                outcome: DeleteOutcome::Disabled,
                changed: false,
            });
        }

        let avatar_path = user_data.avatar_path.clone();
        let outcome = if user_data.sign_in_method() == SignInMethod::Passkey {
            self.storage
                .delete(&user_data.user_id)
                .await?;
            tracing::info!("Permanently deleted user_id: {}", user_data.user_id);
            DeleteOutcome::Removed
        } else {
            let now = chrono::Utc::now();
            user_data.username = user_data.user_id.clone();
            user_data.status = UserStatus::Disabled;
            user_data.role = UserRole::User;
            user_data.passkeys = Vec::new();
            user_data.first_name = None;
            user_data.last_name = None;
            user_data.email = None;
            user_data.department = None;
            user_data.job_title = None;
            user_data.avatar_path = None;
            user_data.updated_at = now;
            user_data.deleted_at = Some(now);
            self.save_user(&user_data)
                .await?;
            tracing::info!("Kept the disabled record of deleted user_id: {}", user_data.user_id);
            DeleteOutcome::Disabled
        };

        self.remove_avatar_files(&user_data.user_id, avatar_path.as_deref())
            .await;
        Ok(DeleteResult { outcome, changed: true })
    }

    /// Remove the uploaded avatar files of a user: the file the stored path names and any
    /// `<user_id>.<extension>` left by an earlier upload. The directory listing is only compared
    /// with those names, so a removed path never comes from the record. The shared default is never
    /// removed, and a file that cannot be removed is logged, not returned.
    async fn remove_avatar_files(
        &self,
        user_id: &str,
        avatar_path: Option<&str>,
    ) {
        self.remove_avatar_matching(user_id, avatar_file_name(avatar_path), Some(user_id))
            .await;
    }

    /// Remove only the file `avatar_path` names, for an upload whose link to the user was refused.
    /// The user's other avatar files stay.
    pub async fn remove_uploaded_avatar(
        &self,
        user_id: &str,
        avatar_path: &str,
    ) {
        self.remove_avatar_matching(user_id, avatar_file_name(Some(avatar_path)), None)
            .await;
    }

    async fn remove_avatar_matching(
        &self,
        user_id: &str,
        stored: Option<std::ffi::OsString>,
        stem: Option<&str>,
    ) {
        let mut entries = match tokio::fs::read_dir(&self.avatars_path).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                tracing::warn!(user_id = %user_id, %error, "Could not list the avatars directory to remove an avatar");
                return;
            }
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => return,
                Err(error) => {
                    tracing::warn!(user_id = %user_id, %error, "Could not read the avatars directory to remove an avatar");
                    return;
                }
            };
            let name = entry.file_name();
            if name == DEFAULT_AVATAR_FILE {
                continue;
            }
            let is_wanted = stored.as_deref() == Some(name.as_os_str())
                || stem.is_some_and(|stem| Path::new(&name).file_stem() == Some(std::ffi::OsStr::new(stem)));
            if !is_wanted {
                continue;
            }
            match tokio::fs::remove_file(entry.path()).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(user_id = %user_id, file = ?name, %error, "Could not remove an avatar file of a deleted user");
                }
            }
        }
    }

    /// Load user by SAML ID (scans in-memory cache)
    pub async fn load_user_by_saml_id(
        &self,
        saml_id: &str,
    ) -> Result<Option<UserData>> {
        let users = self
            .storage
            .list_all()
            .await?;
        Ok(users
            .into_iter()
            .find(|u| u.saml_id.as_deref() == Some(saml_id)))
    }

    /// Load the user who signs in with this OpenID provider account (scans in-memory cache)
    pub async fn load_user_by_oidc_identity(
        &self,
        identity: &OidcIdentity,
    ) -> Result<Option<UserData>> {
        let users = self
            .storage
            .list_all()
            .await?;
        Ok(users
            .into_iter()
            .find(|u| u.oidc.as_ref() == Some(identity)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DeleteOutcome, DeleteResult, OidcIdentity, PasskeyStorage, SignInMethod, UserData, UserRole, UserStatus,
    };
    use crate::config::{LimitDefinition, LimitExceeded, LimitsConfig};
    use tempfile::tempdir;

    async fn storage(dir: &std::path::Path) -> PasskeyStorage {
        PasskeyStorage::new(
            dir.join("users")
                .to_string_lossy()
                .into_owned(),
            dir.join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap()
    }

    fn user(
        user_id: &str,
        oidc: Option<OidcIdentity>,
    ) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: user_id.to_string(),
            username: user_id.to_string(),
            passkeys: vec![],
            role: UserRole::User,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: None,
            last_name: None,
            email: Some("shared@example.com".to_string()),
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: None,
            oidc,
            deleted_at: None,
        }
    }

    fn identity(
        issuer: &str,
        subject: &str,
    ) -> OidcIdentity {
        OidcIdentity {
            issuer: issuer.to_string(),
            subject: subject.to_string(),
        }
    }

    #[tokio::test]
    async fn a_user_is_found_by_the_issuer_and_subject_together() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        for stored in [
            user("u1", Some(identity("https://idp.example", "sub-1"))),
            user("u2", Some(identity("https://other.example", "sub-1"))),
            user("u3", None),
        ] {
            storage
                .save_user(&stored)
                .await
                .unwrap();
        }

        let found = storage
            .load_user_by_oidc_identity(&identity("https://other.example", "sub-1"))
            .await
            .unwrap();
        assert_eq!(
            found
                .map(|user| user.user_id)
                .as_deref(),
            Some("u2")
        );
        for missing in [identity("https://idp.example", "sub-2"), identity("https://idp.example/", "sub-1")] {
            assert!(
                storage
                    .load_user_by_oidc_identity(&missing)
                    .await
                    .unwrap()
                    .is_none(),
                "{missing:?}"
            );
        }
    }

    #[test]
    fn a_user_stored_before_oidc_sign_in_still_loads() {
        let mut stored = serde_json::to_value(user("u1", None)).unwrap();
        for field in ["oidc", "deleted_at"] {
            stored
                .as_object_mut()
                .unwrap()
                .remove(field);
        }

        let loaded: UserData = serde_json::from_value(stored).unwrap();

        assert_eq!(loaded.user_id, "u1");
        assert!(loaded.oidc.is_none());
        assert!(loaded.deleted_at.is_none());
    }

    #[tokio::test]
    async fn deleting_a_user_logs_its_user_id_but_not_its_username() {
        const USERNAME: &str = "alice.marker@example.com";
        let temp_dir = tempdir().unwrap();
        let storage = PasskeyStorage::new(
            temp_dir
                .path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            temp_dir
                .path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let now = chrono::Utc::now();
        let user = UserData {
            user_id: uuid::Uuid::new_v4().to_string(),
            username: USERNAME.to_string(),
            passkeys: vec![],
            role: UserRole::User,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: None,
            last_name: None,
            email: Some(USERNAME.to_string()),
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: None,
            oidc: None,
            deleted_at: None,
        };
        storage
            .save_user(&user)
            .await
            .unwrap();
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

        storage
            .delete_user(&user.user_id)
            .await
            .unwrap();
        let missing = storage
            .delete_user(&user.user_id)
            .await
            .unwrap_err();

        let text = logs.text();
        assert!(text.contains(&format!("Permanently deleted user_id: {}", user.user_id)), "{text}");
        assert!(!text.contains(USERNAME), "{text}");
        assert_eq!(missing.to_string(), "User not found");
    }

    fn oidc_user(user_id: &str) -> UserData {
        let mut data = user(user_id, Some(identity("https://idp.example.com", "sub-1")));
        data.username = "ada".to_string();
        data.email = Some("ada@example.com".to_string());
        data.first_name = Some("Ada".to_string());
        data.department = Some("Ops".to_string());
        data
    }

    fn saml_user(user_id: &str) -> UserData {
        let mut data = user(user_id, None);
        data.role = UserRole::PowerUser;
        data.email = Some("sam@example.com".to_string());
        data.saml_id = Some("saml-1".to_string());
        data
    }

    async fn stored(
        storage: &PasskeyStorage,
        user_id: &str,
    ) -> Option<UserData> {
        storage
            .load_user_by_id(user_id)
            .await
            .unwrap()
    }

    async fn write_avatar(
        dir: &std::path::Path,
        name: &str,
    ) -> std::path::PathBuf {
        let path = dir.join("avatars").join(name);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, b"image")
            .await
            .unwrap();
        path
    }

    fn users_limit(limit: u64) -> LimitsConfig {
        LimitsConfig {
            limits: std::collections::HashMap::from([(
                "users".to_string(),
                LimitDefinition {
                    name: "Users".to_string(),
                    description: String::new(),
                    limit,
                },
            )]),
        }
    }

    async fn storage_with_a_kept_record_and_one_other_user(dir: &std::path::Path) -> PasskeyStorage {
        let storage = storage(dir).await;
        storage
            .save_user(&user("plain", None))
            .await
            .unwrap();
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();
        storage
    }

    #[tokio::test]
    async fn deleting_a_user_without_a_provider_account_removes_the_record() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        storage
            .save_user(&user("plain", None))
            .await
            .unwrap();

        let deleted = storage
            .delete_user("plain")
            .await
            .unwrap();

        assert_eq!(
            deleted,
            DeleteResult {
                outcome: DeleteOutcome::Removed,
                changed: true
            }
        );
        assert_eq!(serde_json::to_string(&deleted.outcome).unwrap(), "\"removed\"");
        assert!(
            stored(&storage, "plain")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_an_oidc_user_keeps_a_disabled_record_for_the_provider_account() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();

        let deleted = storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert_eq!(
            deleted,
            DeleteResult {
                outcome: DeleteOutcome::Disabled,
                changed: true
            }
        );
        assert_eq!(serde_json::to_string(&deleted.outcome).unwrap(), "\"disabled\"");
        let kept = storage
            .load_user_by_oidc_identity(&identity("https://idp.example.com", "sub-1"))
            .await
            .unwrap()
            .expect("the provider account keeps a record");
        assert_eq!(kept.user_id, "oidc-1");
        assert_eq!(kept.status, UserStatus::Disabled);
        assert_eq!(kept.username, "oidc-1", "the username is released for other users");
        assert!(kept.email.is_none() && kept.first_name.is_none() && kept.department.is_none());
        assert!(
            storage
                .load_user("ada")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_a_saml_user_keeps_a_disabled_record_for_the_saml_account() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        storage
            .save_user(&saml_user("saml-user"))
            .await
            .unwrap();

        let deleted = storage
            .delete_user("saml-user")
            .await
            .unwrap();

        assert_eq!(deleted.outcome, DeleteOutcome::Disabled);
        let kept = storage
            .load_user_by_saml_id("saml-1")
            .await
            .unwrap()
            .expect("the SAML account keeps a record");
        assert_eq!(kept.user_id, "saml-user");
        assert_eq!(kept.status, UserStatus::Disabled);
        assert!(kept.deleted_at.is_some());
        assert!(kept.email.is_none());
    }

    #[tokio::test]
    async fn a_user_is_deleted_by_id_and_a_username_is_not_an_id() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let mut data = user("id-1", None);
        data.username = "alice".to_string();
        storage
            .save_user(&data)
            .await
            .unwrap();

        assert!(
            storage
                .delete_user("alice")
                .await
                .is_err()
        );
        storage
            .delete_user("id-1")
            .await
            .unwrap();

        assert!(
            stored(&storage, "id-1")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_kept_record_is_scrubbed_disabled_marked_deleted_and_back_to_the_lowest_role() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let mut data = oidc_user("oidc-1");
        data.role = UserRole::PowerUser;
        data.last_name = Some("Lovelace".to_string());
        data.job_title = Some("Engineer".to_string());
        data.avatar_path = Some("avatars/oidc-1.png".to_string());
        storage
            .save_user(&data)
            .await
            .unwrap();

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        let kept = stored(&storage, "oidc-1")
            .await
            .unwrap();
        assert!(kept.last_name.is_none() && kept.job_title.is_none() && kept.avatar_path.is_none());
        assert!(kept.passkeys.is_empty());
        assert_eq!(kept.role, UserRole::User);
        assert!(kept.deleted_at.is_some());
        assert_eq!(kept.oidc, data.oidc, "the provider account stays so the next sign-in finds it");
    }

    #[tokio::test]
    async fn deleting_a_kept_record_again_changes_nothing_and_reports_it_disabled() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();
        let first = stored(&storage, "oidc-1")
            .await
            .unwrap();

        let repeat = storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert_eq!(
            repeat,
            DeleteResult {
                outcome: DeleteOutcome::Disabled,
                changed: false
            }
        );
        let second = stored(&storage, "oidc-1")
            .await
            .unwrap();
        assert_eq!(second.deleted_at, first.deleted_at);
        assert_eq!(second.updated_at, first.updated_at);
    }

    #[tokio::test]
    async fn only_one_of_two_concurrent_deletes_changes_the_record() {
        let dir = tempdir().unwrap();
        let storage = std::sync::Arc::new(storage(dir.path()).await);
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();

        let delete = |storage: std::sync::Arc<PasskeyStorage>| async move {
            storage
                .delete_user("oidc-1")
                .await
                .unwrap()
        };
        let (a, b) = tokio::join!(delete(storage.clone()), delete(storage.clone()));

        assert_eq!(
            [a.changed, b.changed]
                .iter()
                .filter(|changed| **changed)
                .count(),
            1
        );
        assert_eq!((a.outcome, b.outcome), (DeleteOutcome::Disabled, DeleteOutcome::Disabled));
    }

    #[tokio::test]
    async fn deleting_a_user_removes_their_uploaded_avatar_file_in_both_branches() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let plain_file = write_avatar(dir.path(), "plain.png").await;
        let oidc_file = write_avatar(dir.path(), "oidc-1.png").await;
        let mut plain = user("plain", None);
        plain.avatar_path = Some("avatars/plain.png".to_string());
        let mut federated = oidc_user("oidc-1");
        federated.avatar_path = Some("avatars/oidc-1.png".to_string());
        for data in [&plain, &federated] {
            storage
                .save_user(data)
                .await
                .unwrap();
        }

        for id in ["plain", "oidc-1"] {
            storage
                .delete_user(id)
                .await
                .unwrap();
        }

        assert!(!plain_file.exists());
        assert!(!oidc_file.exists());
    }

    #[tokio::test]
    async fn deleting_a_user_leaves_the_shared_default_avatar_and_files_outside_the_avatars_directory() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let default_file = write_avatar(dir.path(), "default.png").await;
        let outside = dir.path().join("outside.png");
        tokio::fs::write(&outside, b"image")
            .await
            .unwrap();
        for (id, avatar) in
            [("first", "avatars/default.png"), ("second", "avatars/../outside.png"), ("third", "elsewhere/default.png")]
        {
            let mut data = user(id, None);
            data.avatar_path = Some(avatar.to_string());
            storage
                .save_user(&data)
                .await
                .unwrap();
        }

        for id in ["first", "second", "third"] {
            storage
                .delete_user(id)
                .await
                .unwrap();
        }

        assert!(default_file.exists(), "the default avatar is shared");
        assert!(outside.exists(), "a path that leaves the avatars directory is never followed");
    }

    #[tokio::test]
    async fn deleting_a_user_removes_avatar_files_left_by_an_earlier_extension_and_no_one_elses() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let current = write_avatar(dir.path(), "oidc-1.png").await;
        let earlier = write_avatar(dir.path(), "oidc-1.jpg").await;
        let someone_else = write_avatar(dir.path(), "oidc-10.png").await;
        let mut data = oidc_user("oidc-1");
        data.avatar_path = Some("avatars/oidc-1.png".to_string());
        storage
            .save_user(&data)
            .await
            .unwrap();

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert!(!current.exists());
        assert!(!earlier.exists());
        assert!(someone_else.exists(), "another user's file is never matched");
    }

    #[tokio::test]
    async fn deleting_a_user_whose_avatar_file_or_directory_is_gone_succeeds() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let mut plain = user("plain", None);
        plain.avatar_path = Some("avatars/missing.png".to_string());
        let mut federated = oidc_user("oidc-1");
        federated.avatar_path = Some("avatars/oidc-1.png".to_string());
        for data in [&plain, &federated] {
            storage
                .save_user(data)
                .await
                .unwrap();
        }

        storage
            .delete_user("plain")
            .await
            .unwrap();
        tokio::fs::remove_dir_all(dir.path().join("avatars"))
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert!(
            stored(&storage, "plain")
                .await
                .is_none()
        );
        assert!(
            stored(&storage, "oidc-1")
                .await
                .unwrap()
                .deleted_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_file_that_cannot_be_removed_does_not_stop_the_delete() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        tokio::fs::create_dir_all(
            dir.path()
                .join("avatars")
                .join("oidc-1.png"),
        )
        .await
        .unwrap();
        let mut data = oidc_user("oidc-1");
        data.avatar_path = Some("avatars/oidc-1.png".to_string());
        storage
            .save_user(&data)
            .await
            .unwrap();

        let deleted = storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert_eq!(deleted.outcome, DeleteOutcome::Disabled);
        assert!(
            stored(&storage, "oidc-1")
                .await
                .unwrap()
                .deleted_at
                .is_some()
        );
    }

    #[test]
    fn the_sign_in_method_follows_the_provider_account_the_user_has() {
        let mut both = oidc_user("both");
        both.saml_id = Some("saml-1".to_string());

        assert_eq!(user("plain", None).sign_in_method(), SignInMethod::Passkey);
        assert_eq!(saml_user("saml-1").sign_in_method(), SignInMethod::Saml);
        assert_eq!(oidc_user("oidc-1").sign_in_method(), SignInMethod::Oidc);
        assert_eq!(both.sign_in_method(), SignInMethod::Oidc);
        for (method, text) in
            [(SignInMethod::Passkey, "passkey"), (SignInMethod::Oidc, "oidc"), (SignInMethod::Saml, "saml")]
        {
            assert_eq!(serde_json::to_value(method).unwrap(), text);
        }
    }

    #[tokio::test]
    async fn every_write_of_a_user_waits_for_the_user_write_guard() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        let wait = std::time::Duration::from_millis(50);

        let guard = storage
            .user_write_guard()
            .await;
        let role_update = tokio::time::timeout(
            wait,
            storage.update_user("oidc-1", None, Some(UserStatus::Disabled), &LimitsConfig::default()),
        )
        .await;
        let profile_update = tokio::time::timeout(
            wait,
            storage.update_profile("oidc-1", Some("X".to_string()), None, None, None, None, None),
        )
        .await;
        let delete = tokio::time::timeout(wait, storage.delete_user("oidc-1")).await;
        drop(guard);

        assert!(role_update.is_err(), "update_user waits for the guard");
        assert!(profile_update.is_err(), "update_profile waits for the guard");
        assert!(delete.is_err(), "delete_user waits for the guard");
        assert!(
            storage
                .update_profile("oidc-1", Some("X".to_string()), None, None, None, None, None)
                .await
                .unwrap()
        );
        assert_eq!(
            stored(&storage, "oidc-1")
                .await
                .unwrap()
                .first_name
                .as_deref(),
            Some("X")
        );
    }

    #[tokio::test]
    async fn a_profile_update_that_lands_after_a_delete_leaves_the_kept_record_scrubbed() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        let written = storage
            .update_profile(
                "oidc-1",
                Some("Ada".to_string()),
                Some("Lovelace".to_string()),
                Some("ada@example.com".to_string()),
                Some("Ops".to_string()),
                Some("Engineer".to_string()),
                Some("avatars/oidc-1.png".to_string()),
            )
            .await
            .unwrap();

        assert!(!written);
        let kept = stored(&storage, "oidc-1")
            .await
            .unwrap();
        assert!(kept.deleted_at.is_some());
        assert_eq!(
            (kept.first_name, kept.last_name, kept.email, kept.department, kept.job_title, kept.avatar_path),
            (None, None, None, None, None, None)
        );
    }

    #[tokio::test]
    async fn a_profile_update_of_a_missing_user_writes_nothing() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;

        let written = storage
            .update_profile("missing", Some("X".to_string()), None, None, None, None, None)
            .await
            .unwrap();

        assert!(!written);
        assert!(
            stored(&storage, "missing")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn approving_a_kept_record_clears_the_deleted_marker() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        storage
            .update_user("oidc-1", None, Some(UserStatus::Approved), &LimitsConfig::default())
            .await
            .unwrap();

        let approved = stored(&storage, "oidc-1")
            .await
            .unwrap();
        assert_eq!(approved.status, UserStatus::Approved);
        assert!(approved.deleted_at.is_none());
    }

    #[tokio::test]
    async fn kept_records_do_not_count_toward_the_user_limit() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        storage
            .save_user(&user("plain", None))
            .await
            .unwrap();
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        assert_eq!(
            storage
                .count_toward_user_limit()
                .await
                .unwrap(),
            2
        );

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert_eq!(
            storage
                .count_toward_user_limit()
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .list_users()
                .await
                .unwrap()
                .len(),
            2,
            "the record itself is still stored"
        );
    }

    #[tokio::test]
    async fn approving_a_kept_record_at_the_user_limit_is_refused_and_changes_nothing() {
        let dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(dir.path()).await;

        let refused = storage
            .update_user("oidc-1", None, Some(UserStatus::Approved), &users_limit(1))
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<LimitExceeded>()
                .is_some(),
            "{refused:?}"
        );
        let kept = stored(&storage, "oidc-1")
            .await
            .unwrap();
        assert_eq!(kept.status, UserStatus::Disabled);
        assert!(kept.deleted_at.is_some());
    }

    #[tokio::test]
    async fn approving_a_kept_record_below_the_user_limit_is_allowed() {
        let dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(dir.path()).await;

        storage
            .update_user("oidc-1", None, Some(UserStatus::Approved), &users_limit(2))
            .await
            .unwrap();

        let approved = stored(&storage, "oidc-1")
            .await
            .unwrap();
        assert_eq!(approved.status, UserStatus::Approved);
        assert!(approved.deleted_at.is_none());
    }

    #[tokio::test]
    async fn changes_that_do_not_return_a_deleted_user_to_a_seat_ignore_the_user_limit() {
        let dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(dir.path()).await;

        storage
            .update_user("oidc-1", Some(UserRole::PowerUser), Some(UserStatus::Disabled), &users_limit(1))
            .await
            .unwrap();
        storage
            .update_user("plain", None, Some(UserStatus::Approved), &users_limit(1))
            .await
            .unwrap();

        let kept = stored(&storage, "oidc-1")
            .await
            .unwrap();
        assert_eq!(kept.role, UserRole::PowerUser);
        assert!(kept.deleted_at.is_some(), "only an approval returns the record to a seat");
    }

    #[tokio::test]
    async fn an_update_by_id_changes_only_that_record_when_two_share_a_username() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        for id in ["first", "second"] {
            let mut data = user(id, None);
            data.username = "bob".to_string();
            data.status = UserStatus::New;
            storage
                .save_user(&data)
                .await
                .unwrap();
        }

        storage
            .update_user("second", Some(UserRole::PowerUser), Some(UserStatus::Approved), &LimitsConfig::default())
            .await
            .unwrap();

        let first = stored(&storage, "first")
            .await
            .unwrap();
        let second = stored(&storage, "second")
            .await
            .unwrap();
        assert_eq!((first.status, first.role), (UserStatus::New, UserRole::User));
        assert_eq!((second.status, second.role), (UserStatus::Approved, UserRole::PowerUser));
    }

    #[tokio::test]
    async fn a_username_is_free_unless_another_user_holds_it() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let mut data = user("first", None);
        data.username = "bob".to_string();
        storage
            .save_user(&data)
            .await
            .unwrap();

        assert!(
            storage
                .username_held_by_other("bob", None)
                .await
                .unwrap()
        );
        assert!(
            storage
                .username_held_by_other("bob", Some("second"))
                .await
                .unwrap()
        );
        assert!(
            !storage
                .username_held_by_other("bob", Some("first"))
                .await
                .unwrap()
        );
        assert_eq!(
            storage
                .free_username(&["bob", "alice"], Some("second"))
                .await
                .unwrap()
                .as_deref(),
            Some("alice")
        );
        assert_eq!(
            storage
                .free_username(&["bob"], None)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn recording_a_login_updates_an_approved_user_and_refuses_anyone_else() {
        let dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(dir.path()).await;

        let signed_in = storage
            .record_login("plain")
            .await
            .unwrap()
            .expect("an approved user signs in");

        assert!(
            signed_in
                .last_logged_in
                .is_some()
        );
        assert!(
            stored(&storage, "plain")
                .await
                .unwrap()
                .last_logged_in
                .is_some()
        );
        assert!(
            storage
                .record_login("oidc-1")
                .await
                .unwrap()
                .is_none(),
            "a kept record is not signed in"
        );
        storage
            .delete_user("plain")
            .await
            .unwrap();
        assert!(
            storage
                .record_login("plain")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            stored(&storage, "plain")
                .await
                .is_none(),
            "a sign-in that a delete overtook brings no removed record back"
        );
        assert!(
            stored(&storage, "oidc-1")
                .await
                .unwrap()
                .last_logged_in
                .is_none(),
            "a refused sign-in writes nothing"
        );
    }

    #[tokio::test]
    async fn an_avatar_is_linked_only_to_a_user_who_is_still_approved() {
        let dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(dir.path()).await;

        assert!(
            storage
                .set_avatar_if_approved("plain", "avatars/plain.png".to_string())
                .await
                .unwrap()
        );
        assert!(
            !storage
                .set_avatar_if_approved("oidc-1", "avatars/oidc-1.png".to_string())
                .await
                .unwrap()
        );
        assert!(
            !storage
                .set_avatar_if_approved("nobody", "avatars/nobody.png".to_string())
                .await
                .unwrap()
        );
        assert_eq!(
            stored(&storage, "plain")
                .await
                .unwrap()
                .avatar_path
                .as_deref(),
            Some("avatars/plain.png")
        );
        assert!(
            stored(&storage, "oidc-1")
                .await
                .unwrap()
                .avatar_path
                .is_none()
        );
    }

    #[tokio::test]
    async fn removing_an_uploaded_avatar_keeps_the_users_other_avatar_files() {
        let dir = tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let current = write_avatar(dir.path(), "plain.jpg").await;
        let uploaded = write_avatar(dir.path(), "plain.png").await;
        let default_file = write_avatar(dir.path(), "default.png").await;

        storage
            .remove_uploaded_avatar("plain", "avatars/plain.png")
            .await;
        storage
            .remove_uploaded_avatar("plain", "avatars/default.png")
            .await;

        assert!(!uploaded.exists());
        assert!(current.exists(), "the avatar the record still points at stays");
        assert!(default_file.exists());
    }
}
