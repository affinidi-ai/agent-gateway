//! A2A authentication utilities — shared caching and comparison helpers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use dashmap::DashMap;
use tracing::debug;

use crate::secrets::SecretsStore;

/// Cached secret value with TTL
#[derive(Debug, Clone)]
pub struct CachedSecret {
    pub value: String,
    pub cached_at: Instant,
    pub ttl: Duration,
}

impl CachedSecret {
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    pub fn get_credentials(&self) -> Vec<String> {
        self.value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// Shared cache for secrets keyed by secret_id
pub type SecretsCache = Arc<DashMap<String, CachedSecret>>;

/// Retrieve a secret value, honoring a short-lived cache to avoid hitting the backend on every request
pub async fn get_cached_secret(
    secret_id: &str,
    secrets_store: &Option<Arc<dyn SecretsStore>>,
    secrets_cache: &SecretsCache,
) -> anyhow::Result<Vec<String>> {
    if let Some(entry) = secrets_cache.get(secret_id)
        && !entry.is_expired()
    {
        debug!(secret_id = secret_id, "Secrets cache hit");
        return Ok(entry.get_credentials());
    }

    let store = secrets_store
        .as_ref()
        .ok_or_else(|| anyhow!("Secrets store not configured"))?;

    let secret = store
        .get_by_secret_id(secret_id)
        .await?
        .ok_or_else(|| anyhow!("Secret '{}' not found", secret_id))?;

    let cached = CachedSecret {
        value: secret.value.clone(),
        cached_at: Instant::now(),
        ttl: Duration::from_secs(60),
    };

    secrets_cache.insert(secret_id.to_string(), cached);

    Ok(secret
        .value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

/// Remove a cached secret entry after rotation
pub fn clear_secret_cache(
    secret_id: &str,
    secrets_cache: &SecretsCache,
) {
    secrets_cache.remove(secret_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::Utc;

    use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, UpdateSecretRequest};

    struct TestSecretsStore {
        secret: Secret,
    }

    #[async_trait]
    impl SecretsStore for TestSecretsStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> Result<Secret> {
            anyhow::bail!("not needed in test")
        }

        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<Secret>> {
            Ok(None)
        }

        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> Result<Option<Secret>> {
            Ok((self.secret.secret_id == secret_id).then(|| self.secret.clone()))
        }

        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            Ok(vec![self.secret.clone().into()])
        }

        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> Result<Secret> {
            anyhow::bail!("not needed in test")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            anyhow::bail!("not needed in test")
        }

        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> Result<Vec<SecretListItem>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_get_cached_secret_uses_public_secret_id_lookup() {
        let secret = Secret {
            id: "internal-id".to_string(),
            tenant_id: None,
            name: "API Key Secret".to_string(),
            secret_id: "public-secret-id".to_string(),
            description: None,
            value: "key-a, key-b".to_string(),
            secret_type: "General".to_string(),
            tags: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let store: Arc<dyn SecretsStore> = Arc::new(TestSecretsStore { secret });
        let cache = Arc::new(DashMap::new());

        let credentials = get_cached_secret("public-secret-id", &Some(store), &cache)
            .await
            .unwrap();

        assert_eq!(credentials, vec!["key-a".to_string(), "key-b".to_string()]);
    }
}
