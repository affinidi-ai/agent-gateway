use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;

use super::{IntegrationPublisher, Message, event_envelope, is_empty_template};
use crate::integrations::stream_publishers::PUBLISHER_REGISTRY as STREAM_PUBLISHER_REGISTRY;

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

    fn complete_template(
        &self,
        template: &Value,
    ) -> Value {
        if is_empty_template(template) {
            event_envelope()
        } else {
            template.clone()
        }
    }

    async fn send(
        &self,
        configuration: &Value,
        message: &Message,
    ) -> Result<()> {
        let platform = configuration
            .get("platform")
            .and_then(Value::as_str)
            .unwrap_or("kafka");
        let topic = configuration
            .get("topic")
            .and_then(Value::as_str)
            .context("Stream topic/stream name is required")?;
        STREAM_PUBLISHER_REGISTRY
            .get(platform)
            .ok_or_else(|| anyhow::anyhow!("Unsupported streaming platform: {}", platform))?
            .publish(topic, &message.content, configuration, &message.integration_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_empty_template_streams_the_event_envelope_and_its_own_is_kept() {
        assert_eq!(StreamPublisher.complete_template(&json!({}))["data"], "${EVENT_DATA}");
        assert_eq!(StreamPublisher.complete_template(&json!({}))["event_type"], "${EVENT_TYPE}");
        assert_eq!(
            StreamPublisher.complete_template(&json!({"record": "${AUDIT_RECORD}"})),
            json!({"record": "${AUDIT_RECORD}"})
        );
    }
}
