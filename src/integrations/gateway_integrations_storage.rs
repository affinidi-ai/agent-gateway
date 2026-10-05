use crate::storage::StorageBackend;
use crate::storage::filesystem::{StorableEntity, cached_storage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::info;

const CONFIG_ID: &str = "config";

/// Gateway integration configuration with integration and variable values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayIntegrationIntegration {
    pub integration_id: String,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    /// Event types that should trigger this integration (e.g., ["gateway.created", "gateway.updated"])
    /// If empty, all events will trigger the integration (backward compatibility)
    #[serde(default)]
    pub event_types: Vec<String>,
}

/// Gateway integrations configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayIntegrationsConfig {
    #[serde(skip)]
    _id: String,
    #[serde(default)]
    pub integration_integrations: Vec<GatewayIntegrationIntegration>,
}

impl StorableEntity for GatewayIntegrationsConfig {
    fn id(&self) -> &str {
        CONFIG_ID
    }
}

/// Storage for gateway integrations configuration
pub struct GatewayIntegrationsStorage {
    storage: Box<dyn StorageBackend<GatewayIntegrationsConfig>>,
}

impl GatewayIntegrationsStorage {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "gateway_integrations").await?;
        Ok(Self { storage })
    }

    /// Load gateway integrations configuration
    pub async fn load(&self) -> Result<GatewayIntegrationsConfig> {
        Ok(self
            .storage
            .get(CONFIG_ID)
            .await?
            .unwrap_or_default())
    }

    /// Save gateway integrations configuration
    pub async fn save(
        &self,
        config: &GatewayIntegrationsConfig,
    ) -> Result<()> {
        self.storage
            .save(config)
            .await?;
        info!(
            "Saved gateway integrations config with {} integrations",
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
            info!("Removed integration {} from gateway integrations", integration_id);
        }

        Ok(removed)
    }
}
