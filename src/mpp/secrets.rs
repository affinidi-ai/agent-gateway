//! Resolves `$SECRET:<secret_id>` references in an `MppConfig` against the
//! secrets store, mirroring the `$SECRET:` idiom used elsewhere in the
//! gateway (see `x402::proxy_config::WalletBinding::get_private_key_value`).
//!
//! `$ENV_VAR` and literal values are left untouched here; they continue to be
//! resolved downstream by `verification::resolve_secret_key` /
//! `challenge::resolve_secret_key`.

use std::sync::Arc;

use super::types::MppConfig;
use crate::secrets::SecretsStore;

const SECRET_STORE_PREFIX: &str = "$SECRET:";

async fn resolve_value(
    value: &str,
    secrets_store: &Option<Arc<dyn SecretsStore>>,
) -> Result<String, String> {
    let Some(secret_id) = value.strip_prefix(SECRET_STORE_PREFIX) else {
        return Ok(value.to_string());
    };

    let store = secrets_store
        .as_ref()
        .ok_or_else(|| format!("Secret reference '{}' found but no secrets store is configured", value))?;

    let secret = store
        .get_by_secret_id(secret_id)
        .await
        .map_err(|e| format!("Failed to resolve secret '{}': {}", secret_id, e))?
        .ok_or_else(|| format!("Secret with secret_id '{}' not found", secret_id))?;

    Ok(secret.value)
}

/// Resolve any `$SECRET:` references in `config.secret_key` / `config.stripe_secret_key`.
///
/// Returns a config clone with the resolved values; `$ENV_VAR` and literal
/// values pass through unchanged.
pub async fn resolve_config_secrets(
    config: &MppConfig,
    secrets_store: &Option<Arc<dyn SecretsStore>>,
) -> Result<MppConfig, String> {
    let mut resolved = config.clone();

    resolved.secret_key = resolve_value(&config.secret_key, secrets_store).await?;

    if let Some(ref stripe_key) = config.stripe_secret_key {
        resolved.stripe_secret_key = Some(resolve_value(stripe_key, secrets_store).await?);
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, UpdateSecretRequest};

    struct StubStore {
        secret_id: String,
        value: String,
    }

    #[async_trait]
    impl SecretsStore for StubStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!()
        }

        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            unimplemented!()
        }

        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            if secret_id == self.secret_id {
                let now = chrono::Utc::now();
                Ok(Some(Secret {
                    id: "internal-id".to_string(),
                    tenant_id: None,
                    name: "test".to_string(),
                    secret_id: self.secret_id.clone(),
                    description: None,
                    value: self.value.clone(),
                    secret_type: "General".to_string(),
                    tags: vec![],
                    created_at: now,
                    updated_at: now,
                }))
            } else {
                Ok(None)
            }
        }

        async fn list_all(&self) -> anyhow::Result<Vec<SecretListItem>> {
            unimplemented!()
        }

        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!()
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> anyhow::Result<Vec<SecretListItem>> {
            unimplemented!()
        }
    }

    fn base_config() -> MppConfig {
        MppConfig {
            enabled: true,
            realm: "api.example.com".to_string(),
            secret_key: "literal-key".to_string(),
            stripe_secret_key: None,
            payment_methods: vec![],
            challenge_ttl_seconds: 300,
            mcp_payment_triggers: None,
            a2a_method_filters: None,
            verification_timeout_ms: 10000,
            crypto_verification_mode: crate::mpp::types::MppVerificationMode::default(),
            rpc_endpoints: std::collections::HashMap::new(),
            min_confirmations: 0,
        }
    }

    #[tokio::test]
    async fn literal_and_env_values_pass_through() {
        let config = base_config();
        let resolved = resolve_config_secrets(&config, &None)
            .await
            .unwrap();
        assert_eq!(resolved.secret_key, "literal-key");
    }

    #[tokio::test]
    async fn resolves_secret_reference_from_store() {
        let mut config = base_config();
        config.secret_key = "$SECRET:hmac-key".to_string();
        config.stripe_secret_key = Some("$SECRET:stripe-key".to_string());

        let store: Arc<dyn SecretsStore> = Arc::new(StubStore {
            secret_id: "hmac-key".to_string(),
            value: "resolved-hmac".to_string(),
        });

        // Only the hmac-key secret exists; stripe-key resolution should fail closed.
        let err = resolve_config_secrets(&config, &Some(store.clone()))
            .await
            .unwrap_err();
        assert!(err.contains("stripe-key"));

        config.stripe_secret_key = None;
        let resolved = resolve_config_secrets(&config, &Some(store))
            .await
            .unwrap();
        assert_eq!(resolved.secret_key, "resolved-hmac");
    }

    #[tokio::test]
    async fn missing_store_fails_closed_for_secret_reference() {
        let mut config = base_config();
        config.secret_key = "$SECRET:hmac-key".to_string();

        let err = resolve_config_secrets(&config, &None)
            .await
            .unwrap_err();
        assert!(err.contains("no secrets store is configured"));
    }
}
