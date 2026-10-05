use anyhow::{Context, Result};
use async_trait::async_trait;
use moka::future::Cache;
use once_cell::sync::Lazy;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, info};

use super::StreamPublisher;

pub struct KafkaPublisher;

/// A producer keeps its broker connections open between events; it is rebuilt
/// when the integration's connection settings change and evicted once idle.
#[derive(Clone)]
struct CachedProducer {
    settings: String,
    producer: FutureProducer,
}

static PRODUCERS: Lazy<Cache<String, CachedProducer>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(256)
        .time_to_idle(Duration::from_secs(600))
        .build()
});

/// Drop the integration's cached producer, and with it its broker connections
/// and SASL credentials, when the integration is saved or deleted.
pub async fn invalidate_producer(integration_id: &str) {
    PRODUCERS
        .invalidate(integration_id)
        .await;
}

fn client_config(
    brokers: &str,
    config: &Value,
) -> ClientConfig {
    let mut kafka_config = ClientConfig::new();
    kafka_config.set("bootstrap.servers", brokers);
    kafka_config.set("message.timeout.ms", "30000");

    // Configure connection retry behavior with exponential backoff
    kafka_config.set("reconnect.backoff.ms", "1000"); // Start with 1 second
    kafka_config.set("reconnect.backoff.max.ms", "60000"); // Max 60 seconds
    kafka_config.set("socket.connection.setup.timeout.ms", "10000"); // 10s connection timeout
    kafka_config.set("socket.timeout.ms", "60000"); // 60s socket timeout
    kafka_config.set("metadata.max.age.ms", "180000"); // Refresh metadata every 3 min
    kafka_config.set("log_level", "3"); // Reduce log verbosity (warn level)

    // Add authentication if configured
    if let Some(auth_type) = config
        .get("auth_type")
        .and_then(|v| v.as_str())
        && auth_type == "sasl"
        && let Some(username) = config
            .get("sasl_username")
            .and_then(|v| v.as_str())
    {
        kafka_config.set("security.protocol", "SASL_PLAINTEXT");
        kafka_config.set("sasl.mechanism", "PLAIN");
        kafka_config.set("sasl.username", username);
        if let Some(password) = config
            .get("sasl_password")
            .and_then(|v| v.as_str())
        {
            kafka_config.set("sasl.password", password);
        }
    }

    kafka_config
}

/// Every configuration input that shapes the producer's connection.
fn connection_settings(
    brokers: &str,
    config: &Value,
) -> String {
    serde_json::json!([brokers, config.get("auth_type"), config.get("sasl_username"), config.get("sasl_password")])
        .to_string()
}

async fn producer_for(
    integration_id: &str,
    brokers: &str,
    config: &Value,
) -> Result<FutureProducer> {
    let settings = connection_settings(brokers, config);
    if let Some(cached) = PRODUCERS
        .get(integration_id)
        .await
        && cached.settings == settings
    {
        return Ok(cached.producer);
    }
    let producer: FutureProducer = client_config(brokers, config)
        .create()
        .context("Failed to create Kafka producer")?;
    PRODUCERS
        .insert(
            integration_id.to_string(),
            CachedProducer {
                settings,
                producer: producer.clone(),
            },
        )
        .await;
    Ok(producer)
}

#[async_trait]
impl StreamPublisher for KafkaPublisher {
    async fn publish(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
        integration_id: &str,
    ) -> Result<()> {
        let brokers = config
            .get("brokers")
            .and_then(|v| v.as_str())
            .context("Kafka brokers are required")?;

        debug!("Publishing to Kafka topic '{}' on brokers '{}'", topic, brokers);

        let producer = producer_for(integration_id, brokers, config).await?;

        let event_json = serde_json::to_string(event).context("Failed to serialize event payload")?;

        let record = FutureRecord::to(topic)
            .payload(&event_json)
            .key(integration_id);

        producer
            .send(record, Duration::from_secs(30))
            .await
            .map_err(|(e, _)| anyhow::anyhow!("Failed to send event to Kafka: {:?}", e))?;

        debug!("Successfully published event to Kafka topic '{}'", topic);
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
            .context("Kafka brokers are required")?;

        info!("Testing Kafka connection to brokers: {}", brokers);

        let producer: FutureProducer = client_config(brokers, config)
            .create()
            .context("Failed to create Kafka producer")?;

        let event_json = serde_json::to_string(event).context("Failed to serialize event")?;

        let record = FutureRecord::to(topic)
            .payload(&event_json)
            .key("test-key");

        producer
            .send(record, Duration::from_secs(30))
            .await
            .map_err(|(e, _)| anyhow::anyhow!("Failed to send test event to Kafka: {:?}", e))?;

        info!("Test event sent to Kafka topic '{}' successfully", topic);
        Ok(format!("Test event sent to Kafka topic '{}' successfully", topic))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdkafka::producer::Producer;
    use serde_json::json;

    fn native(producer: &FutureProducer) -> usize {
        producer.client().native_ptr() as usize
    }

    #[test]
    fn client_config_sets_sasl_only_when_configured() {
        let plain = client_config("broker:9092", &json!({}));
        assert_eq!(plain.get("bootstrap.servers"), Some("broker:9092"));
        assert_eq!(plain.get("security.protocol"), None);

        let sasl =
            client_config("broker:9092", &json!({"auth_type": "sasl", "sasl_username": "svc", "sasl_password": "pw"}));
        assert_eq!(sasl.get("security.protocol"), Some("SASL_PLAINTEXT"));
        assert_eq!(sasl.get("sasl.mechanism"), Some("PLAIN"));
        assert_eq!(sasl.get("sasl.username"), Some("svc"));
        assert_eq!(sasl.get("sasl.password"), Some("pw"));

        let sasl_without_user = client_config("broker:9092", &json!({"auth_type": "sasl"}));
        assert_eq!(sasl_without_user.get("security.protocol"), None);
    }

    #[tokio::test]
    async fn producer_is_reused_until_connection_settings_change() {
        let integration_id = format!("kafka-cache-{}", uuid::Uuid::new_v4());
        let config = json!({"auth_type": "none"});

        let first = producer_for(&integration_id, "127.0.0.1:1", &config)
            .await
            .unwrap();
        let again = producer_for(&integration_id, "127.0.0.1:1", &config)
            .await
            .unwrap();
        assert_eq!(native(&first), native(&again), "same settings reuse the cached producer");

        let moved = producer_for(&integration_id, "127.0.0.1:2", &config)
            .await
            .unwrap();
        assert_ne!(native(&first), native(&moved), "a broker change builds a new producer");

        let reauthed = producer_for(
            &integration_id,
            "127.0.0.1:2",
            &json!({"auth_type": "sasl", "sasl_username": "svc", "sasl_password": "pw"}),
        )
        .await
        .unwrap();
        assert_ne!(native(&moved), native(&reauthed), "an auth change builds a new producer");

        let other = producer_for(&format!("{integration_id}-other"), "127.0.0.1:2", &config)
            .await
            .unwrap();
        assert_ne!(native(&moved), native(&other), "producers are never shared across integrations");
    }
}
