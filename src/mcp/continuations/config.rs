use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

use super::dynamodb::DynamoContinuations;
use super::embedded::EmbeddedContinuations;
use super::protected::{ContinuationCipher, ContinuationKey};
use super::service::ContinuationService;
use super::{ContinuationError, ContinuationStore, MAX_TTL_SECS};
use crate::secrets::SecretsStore;

static RUNTIME: OnceLock<ContinuationRuntime> = OnceLock::new();

#[derive(Clone)]
pub struct ContinuationRuntime {
    pub config: ContinuationConfig,
    pub service: Arc<ContinuationService>,
}

impl ContinuationRuntime {
    pub async fn load(
        config: ContinuationConfig,
        secrets: &dyn SecretsStore,
        dynamodb: Option<aws_sdk_dynamodb::Client>,
        now: u64,
    ) -> Result<Self, ContinuationError> {
        config.validate()?;
        let cipher = config
            .load_cipher(secrets, now)
            .await?;
        let store: Arc<dyn ContinuationStore> = match &config.storage {
            ContinuationStorageConfig::Embedded { capacity } => Arc::new(EmbeddedContinuations::new(*capacity)?),
            ContinuationStorageConfig::Dynamodb { table } => {
                let store = DynamoContinuations::new(
                    dynamodb.ok_or(ContinuationError::Unavailable)?,
                    table.clone(),
                    config.deployment.clone(),
                )?;
                let probe = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    store.get(uuid::Uuid::new_v4(), [1; 32], now),
                )
                .await
                .map_err(|_| ContinuationError::Unavailable)?;
                if !matches!(probe, Err(ContinuationError::NotFound)) {
                    return Err(ContinuationError::Unavailable);
                }
                Arc::new(store)
            }
        };
        let service =
            ContinuationService::new(cipher, store).with_max_pending_per_principal(config.max_pending_per_principal);
        Ok(Self {
            config,
            service: Arc::new(service),
        })
    }

    pub fn install(self) -> Result<(), ContinuationError> {
        RUNTIME
            .set(self)
            .map_err(|_| ContinuationError::Conflict)
    }
}

pub fn global() -> Option<&'static ContinuationRuntime> {
    RUNTIME.get()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationConfig {
    pub deployment: String,
    pub ttl_secs: u64,
    pub active_key: String,
    pub keys: Vec<ContinuationKeyConfig>,
    pub storage: ContinuationStorageConfig,
    /// Continuations one caller may have pending at once, so one caller
    /// cannot use up the store's capacity.
    #[serde(default = "default_max_pending_per_principal")]
    pub max_pending_per_principal: usize,
}

fn default_max_pending_per_principal() -> usize {
    super::service::DEFAULT_MAX_PENDING_PER_PRINCIPAL
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationKeyConfig {
    pub id: String,
    pub secret_id: String,
    pub not_before: u64,
    pub seal_until: u64,
    pub open_until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContinuationStorageConfig {
    Embedded { capacity: usize },
    Dynamodb { table: String },
}

impl ContinuationConfig {
    async fn load_cipher(
        &self,
        secrets: &dyn SecretsStore,
        now: u64,
    ) -> Result<ContinuationCipher, ContinuationError> {
        let mut keys = Vec::with_capacity(self.keys.len());
        for config in &self.keys {
            if config.id == self.active_key
                && (now < config.not_before
                    || now >= config.seal_until
                    || now
                        .checked_add(self.ttl_secs)
                        .is_none_or(|expiry| expiry > config.open_until))
            {
                return Err(ContinuationError::KeyUnavailable);
            }
            let mut secret = secrets
                .get(&config.secret_id)
                .await
                .map_err(|_| ContinuationError::KeyUnavailable)?
                .ok_or(ContinuationError::KeyUnavailable)?;
            let encoded = Zeroizing::new(std::mem::take(&mut secret.value));
            if encoded.trim().len() != 64 {
                return Err(ContinuationError::KeyUnavailable);
            }
            let mut material = Zeroizing::new([0; 32]);
            hex::decode_to_slice(encoded.trim(), material.as_mut()).map_err(|_| ContinuationError::KeyUnavailable)?;
            keys.push(ContinuationKey::new(
                config.id.clone(),
                *material,
                config.not_before,
                config.seal_until,
                config.open_until,
            )?);
        }
        ContinuationCipher::new(self.deployment.clone(), self.active_key.clone(), keys)
    }

    pub fn validate(&self) -> Result<(), ContinuationError> {
        let identifier = |value: &str, limit| {
            !value.is_empty()
                && value.len() <= limit
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        };
        if !identifier(&self.deployment, 128)
            || self.max_pending_per_principal == 0
            || matches!(self.storage, ContinuationStorageConfig::Embedded { capacity } if self.max_pending_per_principal > capacity)
            || self.ttl_secs == 0
            || self.ttl_secs > MAX_TTL_SECS
            || self.keys.is_empty()
            || self.keys.len() > 4
            || self
                .keys
                .iter()
                .filter(|key| key.id == self.active_key)
                .count()
                != 1
        {
            return Err(ContinuationError::InvalidRecord);
        }
        let mut ids = std::collections::HashSet::new();
        for key in &self.keys {
            if !identifier(&key.id, 64)
                || key.secret_id.is_empty()
                || key.secret_id.len() > 256
                || key
                    .secret_id
                    .chars()
                    .any(char::is_control)
                || !ids.insert(&key.id)
                || key.seal_until <= key.not_before
                || key
                    .open_until
                    .checked_sub(key.seal_until)
                    .is_none_or(|overlap| overlap > MAX_TTL_SECS)
            {
                return Err(ContinuationError::InvalidRecord);
            }
        }
        match &self.storage {
            ContinuationStorageConfig::Embedded { capacity } if *capacity == 0 || *capacity > 65_536 => {
                return Err(ContinuationError::InvalidRecord);
            }
            ContinuationStorageConfig::Dynamodb { table }
                if table.len() < 3
                    || table.len() > 255
                    || !table
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')) =>
            {
                return Err(ContinuationError::InvalidRecord);
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    pub(super) fn config() -> ContinuationConfig {
        serde_json::from_value(json!({
            "deployment": "gateway-test",
            "ttl_secs": 300,
            "active_key": "current",
            "keys": [{"id": "current", "secret_id": "key-secret", "not_before": 10, "seal_until": 1000, "open_until": 1900}],
            "storage": {"backend": "embedded", "capacity": 128}
        })).unwrap()
    }

    #[test]
    fn the_per_principal_limit_defaults_and_cannot_exceed_the_embedded_capacity() {
        let mut config = config();
        assert_eq!(config.max_pending_per_principal, super::super::service::DEFAULT_MAX_PENDING_PER_PRINCIPAL);
        assert!(config.validate().is_ok());
        config.max_pending_per_principal = 0;
        assert!(config.validate().is_err());
        config.max_pending_per_principal = 129;
        assert!(config.validate().is_err());
        config.max_pending_per_principal = 128;
        assert!(config.validate().is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn continuation_runtime_requires_real_keys_and_the_selected_backend() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = crate::secrets::FilesystemSecretsStore::new(
            directory
                .path()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let mut config = config();
        assert!(matches!(
            ContinuationRuntime::load(config.clone(), &secrets, None, 20).await,
            Err(ContinuationError::KeyUnavailable)
        ));
        let key = secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "Continuation test key".into(),
                secret_id: "continuation-test".into(),
                description: None,
                value: "01".repeat(32),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        config.keys[0].secret_id = key.id;
        let runtime = ContinuationRuntime::load(config.clone(), &secrets, None, 20)
            .await
            .unwrap();
        assert_eq!(runtime.config.deployment, config.deployment);
        assert!(matches!(runtime.config.storage, ContinuationStorageConfig::Embedded { capacity: 128 }));
        assert!(matches!(
            ContinuationRuntime::load(config.clone(), &secrets, None, 1000).await,
            Err(ContinuationError::KeyUnavailable)
        ));
        config.storage = ContinuationStorageConfig::Dynamodb { table: "continuations".into() };
        assert!(matches!(
            ContinuationRuntime::load(config, &secrets, None, 20).await,
            Err(ContinuationError::Unavailable)
        ));
    }

    #[test]
    fn continuation_config_is_explicit_bounded_and_has_no_backend_fallback() {
        let config = config();
        assert_eq!(config.validate(), Ok(()));
        let base = serde_json::to_value(&config).unwrap();
        for storage in [
            json!({"backend": "unknown"}),
            json!({"backend": "embedded", "capacity": 0}),
            json!({"backend": "dynamodb", "table": "../other"}),
        ] {
            let mut value = base.clone();
            value["storage"] = storage;
            let invalid = serde_json::from_value::<ContinuationConfig>(value);
            assert!(
                invalid.is_err()
                    || invalid
                        .unwrap()
                        .validate()
                        .is_err()
            );
        }
        for (field, value) in [
            ("ttl_secs", json!(901)),
            ("active_key", json!("absent")),
            ("deployment", json!("a/b")),
            ("keys", json!([])),
        ] {
            let mut changed = base.clone();
            changed[field] = value;
            assert!(
                serde_json::from_value::<ContinuationConfig>(changed)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut changed = config.clone();
        changed
            .keys
            .push(changed.keys[0].clone());
        assert!(changed.validate().is_err());
        let mut changed = config;
        changed.keys[0].open_until = 1901;
        assert!(changed.validate().is_err());
        let legacy: crate::config::McpConfig = serde_json::from_value(json!({})).unwrap();
        assert!(legacy.continuations.is_none());
        assert!(
            serde_json::to_value(legacy)
                .unwrap()
                .get("continuations")
                .is_none()
        );
    }
}
