use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tracing::info;

use super::StreamPublisher;

pub struct RedisPublisher;

#[async_trait]
impl StreamPublisher for RedisPublisher {
    async fn publish(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
        _integration_id: &str,
    ) -> Result<()> {
        let redis_url = config
            .get("redis_url")
            .and_then(|v| v.as_str())
            .context("Redis URL is required for Redis Streams")?;

        info!("Publishing to Redis Stream '{}' at '{}'", topic, redis_url);

        use redis::AsyncCommands;

        let client = redis::Client::open(redis_url).context("Failed to create Redis client")?;

        let mut con = client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        // Convert event payload to Redis Stream items (field-value pairs)
        let event_json = serde_json::to_string(event).context("Failed to serialize event payload")?;

        // Use XADD to add entry to Redis Stream
        // Redis Streams store entries as field-value pairs, we'll use a single "data" field
        let _stream_id: String = con
            .xadd(topic, "*", &[("data", event_json.as_str())])
            .await
            .context("Failed to add event to Redis Stream")?;

        info!("Successfully published event to Redis Stream '{}'", topic);
        Ok(())
    }

    async fn test_connection(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
    ) -> Result<String> {
        let redis_url = config
            .get("redis_url")
            .and_then(|v| v.as_str())
            .context("Redis URL is required")?;

        info!("Testing Redis Streams connection to: {}", redis_url);

        use redis::AsyncCommands;

        let client = redis::Client::open(redis_url).context("Failed to create Redis client")?;

        let mut con = client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let event_json = serde_json::to_string(event).context("Failed to serialize event")?;

        let _stream_id: String = con
            .xadd(topic, "*", &[("data", event_json.as_str())])
            .await
            .context("Failed to add test event to Redis Stream")?;

        info!("Test event sent to Redis Stream '{}' successfully", topic);
        Ok(format!("Test event sent to Redis Stream '{}' successfully", topic))
    }
}
