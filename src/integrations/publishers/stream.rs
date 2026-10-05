use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info};

use super::IntegrationPublisher;
use crate::integrations::runtime_variables::substitute_variables_in_json;
use crate::integrations::stream_publishers::PUBLISHER_REGISTRY as STREAM_PUBLISHER_REGISTRY;
use crate::storage::Integration;

pub struct StreamPublisher;

#[async_trait]
impl IntegrationPublisher for StreamPublisher {
    fn name(&self) -> &str {
        "stream"
    }

    fn supported_features(&self) -> Vec<&str> {
        vec!["kafka", "kinesis", "pulsar", "redis", "templates", "variables"]
    }

    fn required_config_fields(&self) -> Vec<&str> {
        vec!["platform", "topic"]
    }

    fn validate_config(
        &self,
        config: &Value,
    ) -> Result<()> {
        let platform = config
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("kafka");

        config
            .get("topic")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing topic in stream configuration"))?;

        // Validate platform is supported
        STREAM_PUBLISHER_REGISTRY
            .get(platform)
            .ok_or_else(|| anyhow::anyhow!("Unsupported streaming platform: {}", platform))?;

        Ok(())
    }

    async fn publish(
        &self,
        integration: &Integration,
        subject: &str,
        message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()> {
        debug!("Triggering stream integration: {}", integration.name);

        // Get streaming platform configuration
        let config = &integration.configuration;

        let platform = config
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("kafka");

        let topic = config
            .get("topic")
            .and_then(|v| v.as_str())
            .context("Stream topic/stream name is required")?;

        // Build event payload from content template with variable substitution
        let event_payload = if !integration.content.is_null()
            && integration
                .content
                .is_object()
        {
            // Use JSON-safe variable substitution to preserve JSON structure
            substitute_variables_in_json(
                &integration.content,
                integration
                    .category
                    .as_deref(),
                variables,
            )
        } else {
            // Default payload with standard fields
            serde_json::json!({
                "subject": subject,
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "integration_id": integration.id,
                "integration_name": integration.name,
            })
        };

        debug!("Stream event payload: {:?}", event_payload);

        // Get the stream publisher from the registry
        let publisher = STREAM_PUBLISHER_REGISTRY
            .get(platform)
            .ok_or_else(|| anyhow::anyhow!("Unsupported streaming platform: {}", platform))?;

        // Use the publisher to send the event
        publisher
            .publish(topic, &event_payload, config, &integration.id)
            .await
    }

    async fn test(
        &self,
        config: &Value,
        content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String> {
        let platform = config
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("kafka");

        let topic = config
            .get("topic")
            .and_then(|v| v.as_str())
            .context("Stream topic/stream name is required")?;

        // Build test event
        let event = if !content.is_null() && content.is_object() {
            substitute_variables_in_json(content, None, variables)
        } else {
            serde_json::json!({
                "test": true,
                "message": "This is a test stream event",
                "timestamp": chrono::Utc::now().to_rfc3339(),
            })
        };

        // Get the stream publisher from the registry
        let publisher = STREAM_PUBLISHER_REGISTRY
            .get(platform)
            .ok_or_else(|| anyhow::anyhow!("Unsupported streaming platform: {}", platform))?;

        // Use the publisher to test the connection
        publisher
            .test_connection(topic, &event, config)
            .await
    }

    async fn publish_batch(
        &self,
        integration: &Integration,
        items: Vec<(&str, &str, &HashMap<String, String>)>,
    ) -> Result<Vec<Result<()>>> {
        info!("Triggering stream batch integration: {} with {} items", integration.name, items.len());

        let config = &integration.configuration;

        let platform = config
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("kafka");

        let topic = config
            .get("topic")
            .and_then(|v| v.as_str())
            .context("Stream topic/stream name is required")?;

        // Get the stream publisher from the registry
        let publisher = STREAM_PUBLISHER_REGISTRY
            .get(platform)
            .ok_or_else(|| anyhow::anyhow!("Unsupported streaming platform: {}", platform))?;

        // Build all event payloads
        let mut events = Vec::new();
        for (subject, message, variables) in items {
            let event_payload = if !integration.content.is_null()
                && integration
                    .content
                    .is_object()
            {
                substitute_variables_in_json(
                    &integration.content,
                    integration
                        .category
                        .as_deref(),
                    variables,
                )
            } else {
                serde_json::json!({
                    "subject": subject,
                    "message": message,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "integration_id": integration.id,
                    "integration_name": integration.name,
                })
            };
            events.push(event_payload);
        }

        debug!("Stream batch contains {} events", events.len());

        // Use the native batch API if available
        if let Ok(results) = publisher
            .publish_batch(topic, &events, config, &integration.id)
            .await
        {
            Ok(results)
        } else {
            // Fallback to sequential publishing if batch not supported
            let mut results = Vec::new();
            for event in events {
                let result = publisher
                    .publish(topic, &event, config, &integration.id)
                    .await;
                results.push(result);
            }
            Ok(results)
        }
    }
}
