use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

mod kafka;
mod kinesis;
mod pulsar;
mod redis_streams;

pub use kafka::{KafkaPublisher, invalidate_producer as invalidate_kafka_producer};
pub use kinesis::KinesisPublisher;
pub use pulsar::PulsarPublisher;
pub use redis_streams::RedisPublisher;

/// Trait for stream publishing implementations
#[async_trait]
pub trait StreamPublisher: Send + Sync {
    /// Publish an event to the stream
    async fn publish(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
        integration_id: &str,
    ) -> Result<()>;

    /// Publish multiple events as a batch (optional optimization)
    #[allow(dead_code)]
    async fn publish_batch(
        &self,
        topic: &str,
        events: &[Value],
        config: &Value,
        integration_id: &str,
    ) -> Result<Vec<Result<()>>> {
        // Default implementation: publish sequentially
        let mut results = Vec::new();
        for event in events {
            let result = self
                .publish(topic, event, config, integration_id)
                .await;
            results.push(result);
        }
        Ok(results)
    }

    /// Test the connection and configuration
    async fn test_connection(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
    ) -> Result<String>;
}

/// Registry for managing stream publishers
pub struct PublisherRegistry {
    publishers: HashMap<String, Arc<dyn StreamPublisher>>,
}

impl PublisherRegistry {
    /// Create a new registry with all available publishers
    pub fn new() -> Self {
        let mut publishers: HashMap<String, Arc<dyn StreamPublisher>> = HashMap::new();

        publishers.insert("kafka".to_string(), Arc::new(KafkaPublisher));
        publishers.insert("kinesis".to_string(), Arc::new(KinesisPublisher));
        publishers.insert("pulsar".to_string(), Arc::new(PulsarPublisher));
        publishers.insert("redis".to_string(), Arc::new(RedisPublisher));

        Self { publishers }
    }

    /// Get a publisher by platform name
    pub fn get(
        &self,
        platform: &str,
    ) -> Option<Arc<dyn StreamPublisher>> {
        self.publishers
            .get(platform)
            .cloned()
    }

    /// Register a custom publisher (for extensibility)
    #[allow(dead_code)]
    pub fn register(
        &mut self,
        platform: String,
        publisher: Arc<dyn StreamPublisher>,
    ) {
        self.publishers
            .insert(platform, publisher);
    }

    /// List all registered platforms
    #[allow(dead_code)]
    pub fn available_platforms(&self) -> Vec<String> {
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
    pub static ref PUBLISHER_REGISTRY: PublisherRegistry = PublisherRegistry::new();
}
