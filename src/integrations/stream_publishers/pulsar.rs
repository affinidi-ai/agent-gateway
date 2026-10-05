use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tracing::info;

use super::StreamPublisher;

pub struct PulsarPublisher;

#[async_trait]
impl StreamPublisher for PulsarPublisher {
    async fn publish(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
        _integration_id: &str,
    ) -> Result<()> {
        let brokers = config
            .get("brokers")
            .and_then(|v| v.as_str())
            .context("Pulsar brokers are required")?;

        info!("Publishing to Pulsar topic '{}' on brokers '{}'", topic, brokers);

        use pulsar::{Pulsar, TokioExecutor, producer::ProducerOptions};

        let pulsar_builder = Pulsar::builder(brokers, TokioExecutor);

        // Add authentication if configured
        if let Some(auth_type) = config
            .get("auth_type")
            .and_then(|v| v.as_str())
            && auth_type == "token"
            && let Some(_token) = config
                .get("auth_token")
                .and_then(|v| v.as_str())
        {
            // For simple token auth, you'd configure proper OAuth2 params
            // In production, this would use OAuth2Authentication
            tracing::warn!("Pulsar token authentication configuration may need OAuth2 parameters");
            // Skip authentication for now as it requires OAuth2 setup
        }

        let pulsar = pulsar_builder
            .build()
            .await
            .context("Failed to create Pulsar client")?;

        let mut producer = pulsar
            .producer()
            .with_topic(topic)
            .with_options(ProducerOptions::default())
            .build()
            .await
            .context("Failed to create Pulsar producer")?;

        let event_json = serde_json::to_string(event).context("Failed to serialize event payload")?;

        let send_future = producer
            .send_non_blocking(event_json)
            .await
            .context("Failed to send event to Pulsar")?;
        send_future
            .await
            .context("Failed to get send confirmation from Pulsar")?;

        info!("Successfully published event to Pulsar topic '{}'", topic);
        Ok(())
    }

    async fn test_connection(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
    ) -> Result<String> {
        let brokers = config
            .get("brokers")
            .and_then(|v| v.as_str())
            .context("Pulsar brokers are required")?;

        info!("Testing Pulsar connection to brokers: {}", brokers);

        use pulsar::{Pulsar, TokioExecutor, producer::ProducerOptions};

        let pulsar_builder = Pulsar::builder(brokers, TokioExecutor);

        // Add authentication if configured
        if let Some(auth_type) = config
            .get("auth_type")
            .and_then(|v| v.as_str())
            && auth_type == "token"
            && let Some(_token) = config
                .get("auth_token")
                .and_then(|v| v.as_str())
        {
            tracing::warn!("Pulsar token authentication configuration may need OAuth2 parameters");
            // Skip authentication for now as it requires OAuth2 setup
        }

        let pulsar = pulsar_builder
            .build()
            .await
            .context("Failed to create Pulsar client")?;

        let mut producer = pulsar
            .producer()
            .with_topic(topic)
            .with_options(ProducerOptions::default())
            .build()
            .await
            .context("Failed to create Pulsar producer")?;

        let event_json = serde_json::to_string(event).context("Failed to serialize event")?;

        let send_future = producer
            .send_non_blocking(event_json)
            .await
            .context("Failed to send test event to Pulsar")?;
        send_future
            .await
            .context("Failed to get confirmation from Pulsar")?;

        info!("Test event sent to Pulsar topic '{}' successfully", topic);
        Ok(format!("Test event sent to Pulsar topic '{}' successfully", topic))
    }
}
