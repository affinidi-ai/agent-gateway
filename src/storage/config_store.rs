use crate::config::GatewayConfig;
use anyhow::Result;
use async_trait::async_trait;

/// Trait for loading configuration from various sources
#[async_trait]
pub trait ConfigurationStore: Send + Sync {
    /// Load the complete configuration
    async fn load_config(&self) -> Result<GatewayConfig>;

    /// Reload configuration (useful for dynamic updates)
    #[allow(dead_code)]
    async fn reload_config(&self) -> Result<GatewayConfig> {
        self.load_config().await
    }
}
