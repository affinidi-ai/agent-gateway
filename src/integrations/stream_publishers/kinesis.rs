use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tracing::info;

use super::StreamPublisher;

pub struct KinesisPublisher;

#[async_trait]
impl StreamPublisher for KinesisPublisher {
    async fn publish(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
        integration_id: &str,
    ) -> Result<()> {
        let region = config
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1");

        let partition_key = config
            .get("partition_key")
            .and_then(|v| v.as_str())
            .unwrap_or(integration_id);

        info!("Publishing to Kinesis stream '{}' in region '{}' with partition key '{}'", topic, region, partition_key);

        use aws_config::BehaviorVersion;
        use aws_sdk_kinesis::primitives::Blob;

        // Build AWS config for the specified region
        let aws_config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_kinesis::config::Region::new(region.to_string()))
            .load()
            .await;

        let kinesis_client = aws_sdk_kinesis::Client::new(&aws_config);

        let event_json = serde_json::to_string(event).context("Failed to serialize event payload")?;

        kinesis_client
            .put_record()
            .stream_name(topic)
            .partition_key(partition_key)
            .data(Blob::new(event_json.as_bytes()))
            .send()
            .await
            .context("Failed to send event to Kinesis")?;

        info!("Successfully published event to Kinesis stream '{}'", topic);
        Ok(())
    }

    async fn test_connection(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
    ) -> Result<String> {
        let region = config
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1");

        info!("Testing Kinesis connection to stream '{}' in region '{}'", topic, region);

        use aws_config::BehaviorVersion;
        use aws_sdk_kinesis::primitives::Blob;

        // Build AWS config for the specified region
        let aws_config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_kinesis::config::Region::new(region.to_string()))
            .load()
            .await;

        let kinesis_client = aws_sdk_kinesis::Client::new(&aws_config);

        let event_json = serde_json::to_string(event).context("Failed to serialize event")?;

        kinesis_client
            .put_record()
            .stream_name(topic)
            .partition_key("test-partition-key")
            .data(Blob::new(event_json.as_bytes()))
            .send()
            .await
            .context("Failed to send test event to Kinesis")?;

        info!("Test event sent to Kinesis stream '{}' successfully", topic);
        Ok(format!("Test event sent to Kinesis stream '{}' in region '{}' successfully", topic, region))
    }
}
