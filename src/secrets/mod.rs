//! Secrets module for secure secret storage
//!
//! Provides a unified interface for storing and retrieving secrets,
//! with support for multiple storage backends:
//! - Filesystem-based storage (encrypted JSON files)
//! - AWS Secrets Manager

mod aws;
mod filesystem;
pub mod handlers;
pub mod router;
pub mod store;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use aws::AwsSecretsStore;
pub use filesystem::FilesystemSecretsStore;
pub use store::SecretsStore;

use crate::storage::filesystem::StorableEntity;

/// Secret metadata and value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Unique identifier for the secret
    pub id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Human-readable name for the secret
    pub name: String,

    /// Machine-readable identifier derived from name (used in $SECRET:xxx syntax)
    pub secret_id: String,

    /// Optional description of what this secret is for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The actual secret value
    pub value: String,

    /// Type of secret (ApiKey, General, etc.) - configured in gateway.json
    #[serde(default = "default_secret_type")]
    pub secret_type: String,

    /// Tags for categorization and filtering
    #[serde(default)]
    pub tags: Vec<String>,

    /// When the secret was created
    pub created_at: DateTime<Utc>,

    /// When the secret was last updated
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    pub secret_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The actual secret value (encrypted at rest)
    // Filesystem is currently the only storage backend and encrypts the whole file at rest.
    // Per-field encryption may be enabled when another storage backend is added.
    pub value: String,

    #[serde(default = "default_secret_type")]
    pub secret_type: String,

    #[serde(default)]
    pub tags: Vec<String>,

    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,
}

fn default_secret_type() -> String {
    "General".to_string()
}

// Implement StorableEntity for EncryptedSecret to use with UncachedFilesystemStorage
impl StorableEntity for EncryptedSecret {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Secret creation request (without sensitive fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSecretRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    pub secret_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub value: String,
    #[serde(default = "default_secret_type")]
    pub secret_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Secret update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSecretRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Flag indicating whether the value field should be updated.
    /// If false or not provided, the value field will be ignored even if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_value: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Secret API response (never carries the value)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretListItem {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    pub secret_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_secret_type")]
    pub secret_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Secret> for EncryptedSecret {
    fn from(secret: Secret) -> Self {
        Self {
            id: secret.id,
            tenant_id: secret.tenant_id,
            name: secret.name,
            secret_id: secret.secret_id,
            description: secret.description,
            secret_type: secret.secret_type,
            value: secret.value,
            tags: secret.tags,
            created_at: secret.created_at,
            updated_at: secret.updated_at,
        }
    }
}

impl From<EncryptedSecret> for Secret {
    fn from(encrypted_secret: EncryptedSecret) -> Self {
        Self {
            id: encrypted_secret.id,
            tenant_id: encrypted_secret.tenant_id,
            name: encrypted_secret.name,
            secret_id: encrypted_secret.secret_id,
            description: encrypted_secret.description,
            secret_type: encrypted_secret.secret_type,
            value: encrypted_secret.value,
            tags: encrypted_secret.tags,
            created_at: encrypted_secret.created_at,
            updated_at: encrypted_secret.updated_at,
        }
    }
}

impl From<Secret> for SecretListItem {
    fn from(secret: Secret) -> Self {
        Self {
            id: secret.id,
            tenant_id: secret.tenant_id,
            name: secret.name,
            secret_id: secret.secret_id,
            description: secret.description,
            secret_type: secret.secret_type,
            tags: secret.tags,
            created_at: secret.created_at,
            updated_at: secret.updated_at,
        }
    }
}

/// Generate a secret ID from a name
/// Converts to lowercase and allows only A-Z, a-z, 0-9, underscore, and hyphen
#[allow(dead_code)]
pub fn generate_secret_id(name: &str) -> String {
    name.to_lowercase()
        .trim()
        // Replace whitespace and common separators with underscore
        .replace(|c: char| c.is_whitespace() || c == '.' || c == '/', "_")
        // Remove any characters that aren't alphanumeric, underscore, or hyphen
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>()
        // Replace multiple consecutive underscores with single underscore
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
        // Remove leading/trailing underscores or hyphens
        .trim_matches(|c| c == '_' || c == '-')
        .to_string()
}

/// Secrets store type enum for configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecretsBackend {
    Filesystem,
    Aws,
}

/// Create a secrets store based on configuration
pub async fn create_secrets_store(
    backend: SecretsBackend,
    storage_path: Option<String>,
) -> Result<Arc<dyn SecretsStore>> {
    match backend {
        SecretsBackend::Filesystem => {
            let path = storage_path.unwrap_or_else(|| "_storage/secrets".to_string());
            let store = FilesystemSecretsStore::new_async(&path).await?;
            Ok(Arc::new(store) as Arc<dyn SecretsStore>)
        }
        SecretsBackend::Aws => {
            let store = AwsSecretsStore::new().await?;
            Ok(Arc::new(store) as Arc<dyn SecretsStore>)
        }
    }
}
