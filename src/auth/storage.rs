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
}

impl StorableEntity for UserData {
    fn id(&self) -> &str {
        &self.user_id
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
        let default_avatar_dest = format!("{}/default.png", avatars_path);
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

    /// Prepare a user with their initial passkey for persistence after consent succeeds.
    pub(crate) async fn prepare_user_with_passkey(
        &self,
        username: &str,
        passkey: Passkey,
    ) -> Result<UserData> {
        // Check if this is the first user
        let users = self.list_users().await?;
        let is_first_user = users.is_empty();

        if self
            .load_user(username)
            .await?
            .is_some()
        {
            anyhow::bail!("User already exists: {}", username);
        }

        if !is_first_user && let Err(e) = crate::config::global_limits().check_can_add("users", users.len()) {
            crate::config::log_limit_reached("users", &e);
            return Err(anyhow::Error::new(e));
        }

        let now = chrono::Utc::now();
        let user_data = UserData {
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
            avatar_path: Some("avatars/default.png".to_string()),
            last_logged_in: None,
            saml_id: None,
        };
        Ok(user_data)
    }

    /// Update user role and status
    pub async fn update_user(
        &self,
        username: &str,
        role: Option<UserRole>,
        status: Option<UserStatus>,
    ) -> Result<()> {
        let mut user_data = self
            .load_user(username)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found: {}", username))?;

        if let Some(new_role) = role {
            user_data.role = new_role;
        }
        if let Some(new_status) = status {
            user_data.status = new_status;
        }
        user_data.updated_at = chrono::Utc::now();

        self.save_user(&user_data)
            .await
    }

    /// Update user profile information
    pub async fn update_profile(
        &self,
        user_id: &str,
        first_name: Option<String>,
        last_name: Option<String>,
        email: Option<String>,
        department: Option<String>,
        job_title: Option<String>,
        avatar_path: Option<String>,
    ) -> Result<()> {
        let mut user_data = self
            .load_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found: {}", user_id))?;

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
            .await
    }

    /// Check if user is approved to sign in
    pub async fn is_user_approved(
        &self,
        username: &str,
    ) -> Result<bool> {
        Ok(self
            .load_user(username)
            .await?
            .is_some_and(|user_data| user_data.status == UserStatus::Approved))
    }

    /// Get all passkeys for a user
    pub async fn get_passkeys(
        &self,
        username: &str,
    ) -> Result<Vec<Passkey>> {
        Ok(self
            .load_user(username)
            .await?
            .map(|data| data.passkeys)
            .unwrap_or_default())
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

    /// Delete a user permanently by username
    pub async fn delete_user(
        &self,
        username: &str,
    ) -> Result<()> {
        let user_data = self
            .load_user(username)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found: {}", username))?;

        self.storage
            .delete(&user_data.user_id)
            .await?;

        tracing::info!("Permanently deleted user: {} (user_id: {})", username, user_data.user_id);

        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::PasskeyStorage;
    use tempfile::tempdir;

    #[tokio::test]
    async fn missing_user_is_not_approved() {
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

        assert!(
            !storage
                .is_user_approved("missing-user")
                .await
                .unwrap()
        );
    }
}
