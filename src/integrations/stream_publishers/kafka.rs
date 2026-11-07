use anyhow::{Context, Result};
use async_trait::async_trait;
use moka::future::Cache;
use once_cell::sync::Lazy;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration;
use tracing::debug;

use super::StreamPublisher;

pub struct KafkaPublisher;

/// A producer keeps its broker connections open between events. It belongs to the endpoint,
/// which holds the brokers and credentials, so every integration and test send on one
/// endpoint shares it; it is rebuilt when the connection settings change and evicted once
/// idle.
#[derive(Clone)]
struct CachedProducer {
    settings: String,
    producer: FutureProducer,
}

/// Producers by endpoint id.
static PRODUCERS: Lazy<Cache<String, CachedProducer>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(256)
        .time_to_idle(Duration::from_secs(600))
        .build()
});

/// Drop the endpoint's cached producer, and with it its broker connections and SASL
/// credentials, when the endpoint is changed or deleted.
pub async fn invalidate_producer(endpoint_id: &str) {
    PRODUCERS
        .invalidate(endpoint_id)
        .await;
}

#[cfg(test)]
pub(crate) async fn has_cached_producer(endpoint_id: &str) -> bool {
    PRODUCERS
        .get(endpoint_id)
        .await
        .is_some()
}

/// Caches a producer for `endpoint_id` without sending anything.
#[cfg(test)]
pub(crate) async fn warm_producer(endpoint_id: &str) {
    let _cached = producer_for(endpoint_id, "127.0.0.1:1", &serde_json::json!({}))
        .await
        .expect("producer");
}

/// The Kafka `security.protocol` an endpoint connects with, as its `security_protocol` field
/// names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SecurityProtocol {
    Plaintext,
    Ssl,
    SaslPlaintext,
    SaslSsl,
}

impl SecurityProtocol {
    fn librdkafka_name(self) -> &'static str {
        match self {
            Self::Plaintext => "PLAINTEXT",
            Self::Ssl => "SSL",
            Self::SaslPlaintext => "SASL_PLAINTEXT",
            Self::SaslSsl => "SASL_SSL",
        }
    }

    fn uses_sasl(self) -> bool {
        matches!(self, Self::SaslPlaintext | Self::SaslSsl)
    }
}

/// The Kafka `sasl.mechanism` an endpoint authenticates with, as its `sasl_mechanism` field
/// names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum SaslMechanism {
    #[serde(rename = "PLAIN")]
    Plain,
    #[serde(rename = "SCRAM-SHA-256")]
    ScramSha256,
    #[serde(rename = "SCRAM-SHA-512")]
    ScramSha512,
}

impl SaslMechanism {
    fn librdkafka_name(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

/// Why a Kafka endpoint's connection settings cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KafkaConfigError {
    #[error("security_protocol must be one of plaintext, ssl, sasl_plaintext or sasl_ssl")]
    UnknownSecurityProtocol,
    #[error("sasl_mechanism must be one of PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512")]
    UnknownSaslMechanism,
    #[error("A SASL security_protocol needs a sasl_mechanism")]
    MissingSaslMechanism,
    #[error("A SASL security_protocol needs a sasl_username")]
    MissingSaslUsername,
    #[error("A SASL security_protocol needs a sasl_password")]
    MissingSaslPassword,
}

/// Checks the connection settings a Kafka endpoint's producer would be built with.
pub fn validate_config(config: &Value) -> Result<(), KafkaConfigError> {
    KafkaSecurity::from_config(config).map(drop)
}

struct SaslCredentials<'a> {
    mechanism: SaslMechanism,
    username: &'a str,
    password: &'a str,
}

/// How the producer connects and authenticates. An endpoint without `security_protocol` keeps
/// the older `auth_type`: `sasl` with a `sasl_username` is SASL_PLAINTEXT with PLAIN unless
/// `sasl_mechanism` says otherwise, anything else plaintext. A SASL protocol needs a mechanism,
/// a username and a password.
struct KafkaSecurity<'a> {
    protocol: SecurityProtocol,
    sasl: Option<SaslCredentials<'a>>,
}

impl<'a> KafkaSecurity<'a> {
    fn from_config(config: &'a Value) -> Result<Self, KafkaConfigError> {
        let protocol: Option<SecurityProtocol> =
            optional_field(config, "security_protocol", KafkaConfigError::UnknownSecurityProtocol)?;
        let mechanism: Option<SaslMechanism> =
            optional_field(config, "sasl_mechanism", KafkaConfigError::UnknownSaslMechanism)?;
        let username = text_field(config, "sasl_username");
        let legacy_sasl =
            protocol.is_none() && text_field(config, "auth_type") == Some("sasl") && username.is_some();
        let protocol = protocol.unwrap_or(if legacy_sasl {
            SecurityProtocol::SaslPlaintext
        } else {
            SecurityProtocol::Plaintext
        });
        if !protocol.uses_sasl() {
            return Ok(Self { protocol, sasl: None });
        }
        let sasl = SaslCredentials {
            mechanism: mechanism
                .or(legacy_sasl.then_some(SaslMechanism::Plain))
                .ok_or(KafkaConfigError::MissingSaslMechanism)?,
            username: username
                .filter(|username| !username.is_empty())
                .ok_or(KafkaConfigError::MissingSaslUsername)?,
            password: text_field(config, "sasl_password")
                .filter(|password| !password.is_empty())
                .ok_or(KafkaConfigError::MissingSaslPassword)?,
        };
        Ok(Self {
            protocol,
            sasl: Some(sasl),
        })
    }

    fn apply(
        &self,
        kafka_config: &mut ClientConfig,
    ) {
        if self.protocol != SecurityProtocol::Plaintext {
            kafka_config.set("security.protocol", self.protocol.librdkafka_name());
        }
        if let Some(sasl) = &self.sasl {
            kafka_config.set("sasl.mechanism", sasl.mechanism.librdkafka_name());
            kafka_config.set("sasl.username", sasl.username);
            kafka_config.set("sasl.password", sasl.password);
        }
    }
}

fn text_field<'a>(
    config: &'a Value,
    field: &str,
) -> Option<&'a str> {
    config
        .get(field)
        .and_then(Value::as_str)
}

/// `field` parsed as `T`, or `None` when absent or null.
fn optional_field<T: DeserializeOwned>(
    config: &Value,
    field: &str,
    unknown: KafkaConfigError,
) -> Result<Option<T>, KafkaConfigError> {
    config
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| T::deserialize(value).map_err(|_| unknown))
        .transpose()
}

fn client_config(
    brokers: &str,
    config: &Value,
) -> Result<ClientConfig, KafkaConfigError> {
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

    KafkaSecurity::from_config(config)?.apply(&mut kafka_config);
    Ok(kafka_config)
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
    endpoint_id: &str,
    brokers: &str,
    config: &Value,
) -> Result<FutureProducer> {
    let settings = connection_settings(brokers, config);
    if let Some(cached) = PRODUCERS
        .get(endpoint_id)
        .await
        && cached.settings == settings
    {
        return Ok(cached.producer);
    }
    let producer: FutureProducer = client_config(brokers, config)?
        .create()
        .context("Failed to create Kafka producer")?;
    PRODUCERS
        .insert(
            endpoint_id.to_string(),
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
        endpoint_id: &str,
    ) -> Result<()> {
        let brokers = config
            .get("brokers")
            .and_then(|v| v.as_str())
            .context("Kafka brokers are required")?;

        debug!("Publishing to Kafka topic '{}' on brokers '{}'", topic, brokers);

        let producer = producer_for(endpoint_id, brokers, config).await?;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdkafka::producer::Producer;
    use serde_json::json;

    fn native(producer: &FutureProducer) -> usize {
        producer.client().native_ptr() as usize
    }

    fn configured(config: Value) -> ClientConfig {
        client_config("broker:9092", &config).expect("valid configuration")
    }

    #[test]
    fn client_config_sets_sasl_only_when_configured() {
        let plain = configured(json!({}));
        assert_eq!(plain.get("bootstrap.servers"), Some("broker:9092"));
        assert_eq!(plain.get("security.protocol"), None);

        let sasl = configured(json!({"auth_type": "sasl", "sasl_username": "svc", "sasl_password": "pw"}));
        assert_eq!(sasl.get("security.protocol"), Some("SASL_PLAINTEXT"));
        assert_eq!(sasl.get("sasl.mechanism"), Some("PLAIN"));
        assert_eq!(sasl.get("sasl.username"), Some("svc"));
        assert_eq!(sasl.get("sasl.password"), Some("pw"));

        let sasl_without_user = configured(json!({"auth_type": "sasl"}));
        assert_eq!(sasl_without_user.get("security.protocol"), None);
    }

    #[test]
    fn client_config_sets_the_configured_security_protocol_and_sasl_mechanism() {
        let scram = configured(json!({
            "security_protocol": "sasl_ssl",
            "sasl_mechanism": "SCRAM-SHA-512",
            "sasl_username": "gw1",
            "sasl_password": "pw"
        }));
        assert_eq!(scram.get("security.protocol"), Some("SASL_SSL"));
        assert_eq!(scram.get("sasl.mechanism"), Some("SCRAM-SHA-512"));
        assert_eq!(scram.get("sasl.username"), Some("gw1"));
        assert_eq!(scram.get("sasl.password"), Some("pw"));

        let tls = configured(json!({"security_protocol": "ssl", "auth_type": "sasl", "sasl_username": "svc"}));
        assert_eq!(tls.get("security.protocol"), Some("SSL"));
        assert_eq!(tls.get("sasl.mechanism"), None);
        assert_eq!(tls.get("sasl.username"), None);

        let explicit_plaintext = configured(json!({"security_protocol": "plaintext"}));
        assert_eq!(explicit_plaintext.get("security.protocol"), None);
    }

    #[test]
    fn a_sasl_protocol_needs_a_mechanism_a_username_and_a_password() {
        let msk = json!({
            "security_protocol": "sasl_ssl",
            "sasl_mechanism": "SCRAM-SHA-512",
            "sasl_username": "gw1",
            "sasl_password": "pw"
        });
        let without = |field: &str| {
            let mut config = msk.clone();
            config
                .as_object_mut()
                .expect("object")
                .remove(field);
            validate_config(&config)
        };

        assert_eq!(validate_config(&msk), Ok(()));
        assert_eq!(without("sasl_mechanism"), Err(KafkaConfigError::MissingSaslMechanism));
        assert_eq!(without("sasl_username"), Err(KafkaConfigError::MissingSaslUsername));
        assert_eq!(without("sasl_password"), Err(KafkaConfigError::MissingSaslPassword));
        assert_eq!(
            validate_config(&json!({"security_protocol": "sasl_plaintext", "sasl_mechanism": "PLAIN", "sasl_username": "", "sasl_password": "pw"})),
            Err(KafkaConfigError::MissingSaslUsername)
        );
    }

    #[test]
    fn an_endpoint_without_security_protocol_keeps_its_auth_type() {
        assert_eq!(validate_config(&json!({})), Ok(()));
        assert_eq!(validate_config(&json!({"auth_type": "none", "sasl_username": "svc"})), Ok(()));
        assert_eq!(
            validate_config(&json!({"auth_type": "sasl", "sasl_username": "svc", "sasl_password": "pw"})),
            Ok(())
        );
        assert_eq!(
            validate_config(&json!({"auth_type": "sasl", "sasl_username": "svc"})),
            Err(KafkaConfigError::MissingSaslPassword)
        );
    }

    #[test]
    fn unknown_protocols_and_mechanisms_are_refused() {
        for protocol in [json!("SASL_SSL"), json!("tls"), json!(1)] {
            assert_eq!(
                validate_config(&json!({"security_protocol": protocol})),
                Err(KafkaConfigError::UnknownSecurityProtocol),
                "{protocol}"
            );
        }
        assert_eq!(
            validate_config(&json!({"security_protocol": "sasl_ssl", "sasl_mechanism": "OAUTHBEARER", "sasl_username": "gw1", "sasl_password": "pw"})),
            Err(KafkaConfigError::UnknownSaslMechanism)
        );
        assert_eq!(
            validate_config(&json!({"security_protocol": "ssl", "sasl_mechanism": "scram-sha-512"})),
            Err(KafkaConfigError::UnknownSaslMechanism)
        );
    }

    #[tokio::test]
    async fn an_endpoints_producer_is_reused_until_its_connection_settings_change() {
        let endpoint_id = format!("kafka-cache-{}", uuid::Uuid::new_v4());
        let config = json!({"auth_type": "none"});

        // Every integration and test send on the endpoint asks for the same producer.
        let first = producer_for(&endpoint_id, "127.0.0.1:1", &config)
            .await
            .unwrap();
        let again = producer_for(&endpoint_id, "127.0.0.1:1", &config)
            .await
            .unwrap();
        assert_eq!(native(&first), native(&again), "same settings reuse the cached producer");

        let moved = producer_for(&endpoint_id, "127.0.0.1:2", &config)
            .await
            .unwrap();
        assert_ne!(native(&first), native(&moved), "a broker change builds a new producer");

        let reauthed = producer_for(
            &endpoint_id,
            "127.0.0.1:2",
            &json!({"auth_type": "sasl", "sasl_username": "svc", "sasl_password": "pw"}),
        )
        .await
        .unwrap();
        assert_ne!(native(&moved), native(&reauthed), "an auth change builds a new producer");

        let other = producer_for(&format!("{endpoint_id}-other"), "127.0.0.1:2", &config)
            .await
            .unwrap();
        assert_ne!(native(&moved), native(&other), "producers are never shared across endpoints");
    }

    #[tokio::test]
    async fn invalidating_an_endpoint_drops_its_producer() {
        let endpoint_id = format!("kafka-cache-{}", uuid::Uuid::new_v4());
        let config = json!({"auth_type": "none"});
        let _cached = producer_for(&endpoint_id, "127.0.0.1:1", &config)
            .await
            .unwrap();
        assert!(has_cached_producer(&endpoint_id).await);

        invalidate_producer(&endpoint_id).await;

        assert!(!has_cached_producer(&endpoint_id).await);
    }
}
