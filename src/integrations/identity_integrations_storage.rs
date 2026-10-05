use crate::storage::StorageBackend;
use crate::storage::filesystem::{StorableEntity, cached_storage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::info;

const CONFIG_ID: &str = "config";

/// Identity integration configuration with integration and variable values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationIntegration {
    pub integration_id: String,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    /// Event types that should trigger this integration (e.g., ["identity.created", "identity.used"])
    /// If empty, all events will trigger the integration (backward compatibility)
    #[serde(default)]
    pub event_types: Vec<String>,
}

/// Identity integrations configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityIntegrationsConfig {
    #[serde(skip)]
    _id: String,
    #[serde(default)]
    pub integration_integrations: Vec<IntegrationIntegration>,
}

impl StorableEntity for IdentityIntegrationsConfig {
    fn id(&self) -> &str {
        CONFIG_ID
    }
}

/// Storage for identity integrations configuration
pub struct IdentityIntegrationsStorage {
    storage: Box<dyn StorageBackend<IdentityIntegrationsConfig>>,
}

impl IdentityIntegrationsStorage {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "identity_integrations").await?;
        Ok(Self { storage })
    }

    /// Load identity integrations configuration
    pub async fn load(&self) -> Result<IdentityIntegrationsConfig> {
        Ok(self
            .storage
            .get(CONFIG_ID)
            .await?
            .unwrap_or_default())
    }

    /// Save identity integrations configuration
    pub async fn save(
        &self,
        config: &IdentityIntegrationsConfig,
    ) -> Result<()> {
        self.storage
            .save(config)
            .await?;
        info!(
            "Saved identity integrations config with {} integrations",
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
            info!("Removed integration {} from identity integrations", integration_id);
        }

        Ok(removed)
    }
}
