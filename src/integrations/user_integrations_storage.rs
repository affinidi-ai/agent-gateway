use crate::integrations::trigger_mappings::{MappingRequest, MappingStore};
use crate::storage::StorageBackend;
use crate::storage::filesystem::{StorableEntity, cached_storage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::info;

const CONFIG_ID: &str = "config";

/// User integration configuration with integration and variable values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationIntegration {
    pub integration_id: String,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    /// Event types that should trigger this integration (e.g., ["user.created", "user.login"])
    /// If empty, all events will trigger the integration (backward compatibility)
    #[serde(default)]
    pub event_types: Vec<String>,
}

/// User integrations configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserIntegrationsConfig {
    #[serde(skip)]
    _id: String,
    #[serde(default)]
    pub integration_integrations: Vec<IntegrationIntegration>,
}

impl StorableEntity for UserIntegrationsConfig {
    fn id(&self) -> &str {
        CONFIG_ID
    }
}

impl From<MappingRequest> for IntegrationIntegration {
    fn from(mapping: MappingRequest) -> Self {
        Self {
            integration_id: mapping.integration_id,
            variables: mapping.variables,
            event_types: mapping.event_types,
        }
    }
}

impl MappingStore for UserIntegrationsStorage {
    async fn unfiltered_integration_ids(&self) -> Result<HashSet<String>> {
        Ok(self
            .load()
            .await?
            .integration_integrations
            .into_iter()
            .filter(|mapping| mapping.event_types.is_empty())
            .map(|mapping| mapping.integration_id)
            .collect())
    }

    async fn replace(
        &self,
        mappings: Vec<MappingRequest>,
    ) -> Result<Vec<MappingRequest>> {
        let config = UserIntegrationsConfig {
            integration_integrations: mappings
                .into_iter()
                .map(IntegrationIntegration::from)
                .collect(),
            ..Default::default()
        };
        self.save(&config).await?;
        Ok(config
            .integration_integrations
            .into_iter()
            .map(MappingRequest::from)
            .collect())
    }
}

impl From<IntegrationIntegration> for MappingRequest {
    fn from(mapping: IntegrationIntegration) -> Self {
        Self {
            integration_id: mapping.integration_id,
            variables: mapping.variables,
            event_types: mapping.event_types,
        }
    }
}

/// Storage for user integrations configuration
pub struct UserIntegrationsStorage {
    storage: Box<dyn StorageBackend<UserIntegrationsConfig>>,
}

impl UserIntegrationsStorage {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "user_integrations").await?;
        Ok(Self { storage })
    }

    /// Load user integrations configuration
    pub async fn load(&self) -> Result<UserIntegrationsConfig> {
        Ok(self
            .storage
            .get(CONFIG_ID)
            .await?
            .unwrap_or_default())
    }

    /// Save user integrations configuration
    pub async fn save(
        &self,
        config: &UserIntegrationsConfig,
    ) -> Result<()> {
        self.storage
            .save(config)
            .await?;
        info!(
            "Saved user integrations config with {} integrations",
            config
                .integration_integrations
                .len()
        );
        Ok(())
    }

    /// Get custom variables for a specific integration
    #[allow(dead_code)]
    pub async fn get_integration_variables(
        &self,
        integration_id: &str,
    ) -> Result<HashMap<String, String>> {
        let config = self.load().await?;
        for integration in &config.integration_integrations {
            if integration.integration_id == integration_id {
                return Ok(integration.variables.clone());
            }
        }
        Ok(HashMap::new())
    }

    /// Get event types for a specific integration
    #[allow(dead_code)]
    pub async fn get_integration_event_types(
        &self,
        integration_id: &str,
    ) -> Result<Vec<String>> {
        let config = self.load().await?;
        for integration in &config.integration_integrations {
            if integration.integration_id == integration_id {
                return Ok(integration
                    .event_types
                    .clone());
            }
        }
        Ok(Vec::new())
    }

    /// Remove an integration from the configuration
    pub async fn remove_integration(
        &self,
        integration_id: &str,
    ) -> Result<bool> {
        let mut config = self.load().await?;
        let initial_len = config
            .integration_integrations
            .len();

        config
            .integration_integrations
            .retain(|i| i.integration_id != integration_id);

        let removed = config
            .integration_integrations
            .len()
            < initial_len;
        if removed {
            self.save(&config).await?;
            info!("Removed integration {} from user integrations", integration_id);
        }

        Ok(removed)
    }
}
