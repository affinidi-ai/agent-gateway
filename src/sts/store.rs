//! Managed-connection store for the STS.
//!
//! An [`StsClient`] is the persisted "managed connection" — which OAuth client
//! may request which tokens for which audiences/scopes, how it authenticates,
//! and whether it may obtain an ID-JAG. The [`StoreBackedClientRegistry`]
//! authenticates a client at the token endpoint against this store, resolving
//! the client secret from the secrets store (never storing it inline).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::secrets::SecretsStore;
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};
use crate::sts::errors::StsError;
use crate::sts::handlers::{StsClientRecord, StsClientRegistry, constant_time_eq};

/// A persisted STS managed connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StsClient {
    /// Internal UUID (storage key / filename).
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// OAuth `client_id` presented at the token endpoint (unique).
    pub client_id: String,
    /// Operator-facing display name.
    pub name: String,
    /// Reference (`secret_id`) into the secrets store holding the client secret.
    /// Required: the token endpoint has no alternative client-authentication, so
    /// a connection with no secret reference is rejected at authentication
    /// (fail-closed) rather than treated as a public client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_ref: Option<String>,
    /// Allowed `audience`/`resource` targets. Empty ⇒ unrestricted.
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    /// Allowed scopes. Empty ⇒ unrestricted.
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    /// Allowed subject-token type URNs. Empty ⇒ any supported subject type.
    #[serde(default)]
    pub allowed_subject_token_types: Vec<String>,
    /// Optional allowlist of accepted subject-token audiences. Empty ⇒ no `aud`
    /// check (default). When set, a JWT-shaped subject token's `aud` must include
    /// one of these — an opt-in hardening for connections that require subject
    /// tokens minted for this STS.
    #[serde(default)]
    pub allowed_subject_audiences: Vec<String>,
    /// When true, an exchange without an `actor_token` mints an impersonation
    /// token (no `act`). Default false ⇒ delegation by default.
    #[serde(default)]
    pub allow_impersonation: bool,
    /// Per-connection TTL cap (further capped by the STS max TTL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_secs: Option<u64>,
    /// Whether this client may obtain an ID-JAG (`requested_token_type=id-jag`).
    #[serde(default)]
    pub issue_id_jag: bool,
    /// Caller-leg Trust Check list evaluated on issuance; its results surface to
    /// the gateway policy at `input.trust_check_results.caller[]`. The stage
    /// never denies — the policy decides.
    #[serde(default)]
    pub trust_check_list: Vec<crate::trust_registry_verification::TrustCheckElement>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl StsClient {
    /// Project the runtime record the token endpoint enforces against.
    pub fn to_record(&self) -> StsClientRecord {
        StsClientRecord {
            client_id: self.client_id.clone(),
            tenant_id: self.tenant_id.clone(),
            allowed_audiences: self.allowed_audiences.clone(),
            allowed_scopes: self.allowed_scopes.clone(),
            allow_impersonation: self.allow_impersonation,
            max_ttl_secs: self.max_ttl_secs,
            issue_id_jag: self.issue_id_jag,
            allowed_subject_token_types: self
                .allowed_subject_token_types
                .clone(),
            allowed_subject_audiences: self
                .allowed_subject_audiences
                .clone(),
            trust_check_list: self.trust_check_list.clone(),
        }
    }
}

impl StorableEntity for StsClient {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Storage backend for STS managed connections.
#[async_trait]
pub trait StsClientStorage: Send + Sync {
    async fn create(
        &self,
        client: StsClient,
    ) -> Result<StsClient>;
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<StsClient>>;
    async fn get_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<StsClient>>;
    async fn list(&self) -> Result<Vec<StsClient>>;
    async fn update(
        &self,
        client: StsClient,
    ) -> Result<StsClient>;
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}

/// Filesystem-backed STS client store (`{storage_dir}/{id}.json`), inheriting
/// encryption at rest and atomic writes from the generic storage backend.
pub struct FileSystemStsClientStore {
    storage: Box<dyn StorageBackend<StsClient>>,
}

impl FileSystemStsClientStore {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "sts_client")
            .await
            .context("Failed to open STS client storage")?;
        let store = Self { storage };
        info!(
            "Initialised FileSystemStsClientStore with {} client(s)",
            store
                .storage
                .list_all()
                .await?
                .len()
        );
        Ok(store)
    }
}

#[async_trait]
impl StsClientStorage for FileSystemStsClientStore {
    async fn create(
        &self,
        mut client: StsClient,
    ) -> Result<StsClient> {
        let now = Utc::now();
        if client.id.is_empty() {
            client.id = Uuid::new_v4().to_string();
        } else if self
            .storage
            .get(&client.id)
            .await?
            .is_some()
        {
            anyhow::bail!("STS client {} already exists", client.id);
        }
        client.created_at = now;
        client.updated_at = now;
        self.storage
            .save(&client)
            .await?;
        info!("Created STS client {} ({})", client.client_id, client.id);
        Ok(client)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<StsClient>> {
        self.storage.get(id).await
    }

    async fn get_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<StsClient>> {
        Ok(self
            .storage
            .list_all()
            .await?
            .into_iter()
            .find(|c| c.client_id == client_id))
    }

    async fn list(&self) -> Result<Vec<StsClient>> {
        self.storage.list_all().await
    }

    async fn update(
        &self,
        mut client: StsClient,
    ) -> Result<StsClient> {
        let existing = self
            .storage
            .get(&client.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("STS client {} not found", client.id))?;
        client.created_at = existing.created_at;
        client.updated_at = Utc::now();
        self.storage
            .save(&client)
            .await?;
        info!("Updated STS client {} ({})", client.client_id, client.id);
        Ok(client)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }
}

/// [`StsClientRegistry`] backed by an [`StsClientStorage`] plus the secrets
/// store for client-secret resolution.
pub struct StoreBackedClientRegistry {
    store: Arc<dyn StsClientStorage>,
    secrets: Arc<dyn SecretsStore>,
}

impl StoreBackedClientRegistry {
    pub fn new(
        store: Arc<dyn StsClientStorage>,
        secrets: Arc<dyn SecretsStore>,
    ) -> Self {
        Self { store, secrets }
    }
}

#[async_trait]
impl StsClientRegistry for StoreBackedClientRegistry {
    async fn authenticate(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<StsClientRecord, StsError> {
        let client = self
            .store
            .get_by_client_id(client_id)
            .await
            .map_err(|e| StsError::ServerError(format!("client lookup failed: {e}")))?
            .ok_or_else(|| StsError::InvalidClient("unknown client".to_string()))?;

        // Fail-closed: the token endpoint has no alternative client-auth, so a
        // connection without a configured secret cannot be authenticated.
        let secret_ref = client
            .client_secret_ref
            .as_ref()
            .ok_or_else(|| {
                StsError::InvalidClient("client authentication is not configured for this connection".to_string())
            })?;
        let expected = self
            .secrets
            .get_by_secret_id(secret_ref)
            .await
            .map_err(|e| StsError::ServerError(format!("secret lookup failed: {e}")))?
            .ok_or_else(|| StsError::ServerError(format!("configured client secret '{secret_ref}' not found")))?;
        let ok = client_secret
            .map(|s| constant_time_eq(s, &expected.value))
            .unwrap_or(false);
        if !ok {
            return Err(StsError::InvalidClient("invalid client credentials".to_string()));
        }

        Ok(client.to_record())
    }
}
