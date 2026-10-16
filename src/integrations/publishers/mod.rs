use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

mod email;
mod slack;
mod stream;
mod webhook;

pub use email::EmailPublisher;
pub use slack::SlackPublisher;
pub use stream::StreamPublisher;
pub use webhook::WebhookPublisher;

use crate::integrations::delivery::render::Escaping;

/// One integration's message, rendered and ready to send.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub integration_id: String,
    pub integration_name: String,
    /// The endpoint it is sent through, which owns connections kept between messages.
    pub endpoint_id: String,
    pub content: Value,
}

/// Whether an integration left its template empty.
fn is_empty_template(template: &Value) -> bool {
    template
        .as_object()
        .is_none_or(|fields| fields.is_empty())
}

/// What a webhook or stream integration sends when its template is empty.
fn event_envelope() -> Value {
    serde_json::json!({
        "event_type": "${EVENT_TYPE}",
        "event_name": "${EVENT_NAME}",
        "timestamp": "${TIMESTAMP}",
        "appliance_id": "${APPLIANCE_ID}",
        "summary": "${EVENT_SUMMARY}",
        "data": "${EVENT_DATA}"
    })
}

/// `template` with each field of `defaults` it leaves out.
fn with_defaults(
    template: &Value,
    defaults: Value,
) -> Value {
    let mut completed = defaults;
    if let (Some(completed), Some(fields)) = (completed.as_object_mut(), template.as_object()) {
        for (name, value) in fields {
            completed.insert(name.clone(), value.clone());
        }
    }
    completed
}

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

    /// The template an integration sends with: its own, completed with whatever the
    /// transport needs that it leaves out.
    fn complete_template(
        &self,
        template: &Value,
    ) -> Value;

    /// How values are escaped when `template` is rendered.
    fn escaping(
        &self,
        _template: &Value,
    ) -> Escaping {
        Escaping::None
    }

    /// Sends a rendered message with an endpoint's configuration.
    async fn send(
        &self,
        configuration: &Value,
        message: &Message,
    ) -> Result<()>;
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
