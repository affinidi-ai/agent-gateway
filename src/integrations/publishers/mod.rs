use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::storage::Integration;

mod email;
mod slack;
mod stream;
mod webhook;

pub use email::EmailPublisher;
pub use slack::SlackPublisher;
pub use stream::StreamPublisher;
pub use webhook::WebhookPublisher;

/// Trait for integration publishing implementations
#[async_trait]
pub trait IntegrationPublisher: Send + Sync {
    /// Get the name of this publisher
    #[allow(dead_code)]
    fn name(&self) -> &str;

    /// Get supported features for this publisher
    #[allow(dead_code)]
    fn supported_features(&self) -> Vec<&str> {
        vec![]
    }

    /// Get required configuration fields
    #[allow(dead_code)]
    fn required_config_fields(&self) -> Vec<&str> {
        vec![]
    }

    /// Validate configuration
    fn validate_config(
        &self,
        _config: &Value,
    ) -> Result<()> {
        Ok(())
    }

    /// Validate content template
    fn validate_content(
        &self,
        _content: &Value,
    ) -> Result<()> {
        Ok(())
    }

    /// Publish a notification through the integration
    async fn publish(
        &self,
        integration: &Integration,
        subject: &str,
        message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()>;

    /// Publish multiple notifications in batch (default: sequential)
    #[allow(dead_code)]
    async fn publish_batch(
        &self,
        integration: &Integration,
        items: Vec<(&str, &str, &HashMap<String, String>)>,
    ) -> Result<Vec<Result<()>>> {
        let mut results = Vec::new();
        for (subject, message, variables) in items {
            results.push(
                self.publish(integration, subject, message, variables)
                    .await,
            );
        }
        Ok(results)
    }

    /// Test the integration configuration
    #[allow(dead_code)]
    async fn test(
        &self,
        config: &Value,
        content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String>;
}

/// Registry for managing integration publishers
pub struct PublisherRegistry {
    publishers: HashMap<String, Arc<dyn IntegrationPublisher>>,
}

impl PublisherRegistry {
    /// Create a new registry with all available publishers
    pub fn new() -> Self {
        let mut publishers: HashMap<String, Arc<dyn IntegrationPublisher>> = HashMap::new();

        publishers.insert("email".to_string(), Arc::new(EmailPublisher));
        publishers.insert("slack".to_string(), Arc::new(SlackPublisher));
        publishers.insert("webhook".to_string(), Arc::new(WebhookPublisher));
        publishers.insert("stream".to_string(), Arc::new(StreamPublisher));

        Self { publishers }
    }

    /// Get a publisher by integration type
    pub fn get(
        &self,
        integration_type: &str,
    ) -> Option<Arc<dyn IntegrationPublisher>> {
        self.publishers
            .get(integration_type)
            .cloned()
    }

    /// Register a custom publisher (for extensibility)
    #[allow(dead_code)]
    pub fn register(
        &mut self,
        integration_type: String,
        publisher: Arc<dyn IntegrationPublisher>,
    ) {
        self.publishers
            .insert(integration_type, publisher);
    }

    /// List all registered integration types
    #[allow(dead_code)]
    pub fn available_types(&self) -> Vec<String> {
        self.publishers
            .keys()
            .cloned()
            .collect()
    }
}

impl Default for PublisherRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Global registry instance
lazy_static::lazy_static! {
    pub static ref INTEGRATION_REGISTRY: PublisherRegistry = PublisherRegistry::new();
}
