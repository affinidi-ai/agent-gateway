use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{Definition, Status, now};
use crate::integrations::publishers::INTEGRATION_REGISTRY;
use crate::storage::filesystem::StorableEntity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointType {
    Email,
    Slack,
    Webhook,
    Stream,
}

impl EndpointType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Slack => "slack",
            Self::Webhook => "webhook",
            Self::Stream => "stream",
        }
    }

    /// Configuration fields holding credentials. They are written but never read back.
    pub fn secret_fields(self) -> &'static [&'static str] {
        match self {
            Self::Email => &["smtp_password"],
            Self::Slack => &["webhook_url"],
            Self::Webhook => &["signing_secret", "headers"],
            Self::Stream => &["sasl_password", "redis_url"],
        }
    }
}

/// Where an integration delivers: the transport, its destination and its credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "type")]
    pub endpoint_type: EndpointType,
    pub configuration: JsonValue,
    pub status: Status,
    pub created_at: String,
    pub updated_at: String,
}

impl Endpoint {
    pub fn new(
        name: String,
        description: String,
        endpoint_type: EndpointType,
        configuration: JsonValue,
    ) -> Self {
        let created_at = now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description,
            endpoint_type,
            configuration,
            status: Status::Active,
            updated_at: created_at.clone(),
            created_at,
        }
    }

    /// The endpoint without its secret values, and the names of the secrets it holds.
    pub fn redacted(&self) -> (Self, Vec<&'static str>) {
        let mut redacted = self.clone();
        let mut set = Vec::new();
        if let Some(configuration) = redacted
            .configuration
            .as_object_mut()
        {
            for field in self
                .endpoint_type
                .secret_fields()
            {
                if configuration
                    .remove(*field)
                    .is_some_and(|value| !value.is_null())
                {
                    set.push(*field);
                }
            }
        }
        (redacted, set)
    }

    /// Checks the configuration the endpoint's publisher would send with.
    pub fn validate_configuration(&self) -> Result<(), String> {
        if !self.configuration.is_object() {
            return Err("The configuration must be an object".to_string());
        }
        let publisher = INTEGRATION_REGISTRY
            .get(self.endpoint_type.as_str())
            .ok_or_else(|| format!("No publisher for {}", self.endpoint_type.as_str()))?;
        publisher
            .validate_config(&self.configuration)
            .map_err(|error| error.to_string())
    }
}

/// `incoming` with each secret it leaves out kept from `existing`. A secret sent as `null`
/// is cleared.
pub fn keep_unsent_secrets(
    endpoint_type: EndpointType,
    mut incoming: JsonValue,
    existing: &JsonValue,
) -> JsonValue {
    if let Some(configuration) = incoming.as_object_mut() {
        for field in endpoint_type.secret_fields() {
            match configuration.get(*field) {
                Some(JsonValue::Null) => {
                    configuration.remove(*field);
                }
                Some(_) => {}
                None => {
                    if let Some(kept) = existing
                        .get(*field)
                        .filter(|value| !value.is_null())
                    {
                        configuration.insert(field.to_string(), kept.clone());
                    }
                }
            }
        }
    }
    incoming
}

impl StorableEntity for Endpoint {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Definition for Endpoint {
    fn created_at(&self) -> &str {
        &self.created_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn webhook() -> Endpoint {
        Endpoint::new(
            "Ops webhook".to_string(),
            "Posts to ops".to_string(),
            EndpointType::Webhook,
            json!({"url": "https://ops.example.com/hook"}),
        )
    }

    #[test]
    fn a_new_endpoint_is_active_with_its_own_id() {
        let first = webhook();
        let second = webhook();

        assert_eq!(first.status, Status::Active);
        assert_eq!(first.name, "Ops webhook");
        assert_eq!(first.configuration["url"], "https://ops.example.com/hook");
        assert!(uuid::Uuid::parse_str(&first.id).is_ok());
        assert_ne!(first.id, second.id);
        assert_eq!(first.created_at, first.updated_at);
    }

    #[test]
    fn serializes_its_type_and_status_by_name() {
        let value = serde_json::to_value(webhook()).expect("serializes");

        assert_eq!(value["type"], "webhook");
        assert_eq!(value["status"], "active");
        assert!(
            value
                .get("endpoint_type")
                .is_none()
        );
    }

    #[test]
    fn refuses_an_unknown_type() {
        let mut value = serde_json::to_value(webhook()).expect("serializes");
        value["type"] = json!("sms");

        assert!(serde_json::from_value::<Endpoint>(value).is_err());
    }

    #[test]
    fn names_each_type_as_it_is_serialized() {
        for endpoint_type in [EndpointType::Email, EndpointType::Slack, EndpointType::Webhook, EndpointType::Stream] {
            assert_eq!(serde_json::to_value(endpoint_type).expect("serializes"), endpoint_type.as_str());
        }
    }

    #[test]
    fn treats_credentials_and_credential_bearing_urls_as_secrets() {
        assert_eq!(EndpointType::Email.secret_fields(), ["smtp_password"]);
        assert_eq!(EndpointType::Slack.secret_fields(), ["webhook_url"]);
        assert_eq!(EndpointType::Webhook.secret_fields(), ["signing_secret", "headers"]);
        assert_eq!(EndpointType::Stream.secret_fields(), ["sasl_password", "redis_url"]);
    }

    #[test]
    fn redaction_drops_secret_values_and_names_the_ones_set() {
        let mut endpoint = webhook();
        endpoint.configuration = json!({
            "url": "https://ops.example.com/hook",
            "method": "POST",
            "signing_secret": "s3cr3t",
            "headers": {"Authorization": "Bearer token"}
        });

        let (redacted, secrets) = endpoint.redacted();

        assert_eq!(redacted.configuration, json!({"url": "https://ops.example.com/hook", "method": "POST"}));
        assert_eq!(secrets, ["signing_secret", "headers"]);
        assert_eq!(redacted.id, endpoint.id);
        assert_eq!(endpoint.configuration["signing_secret"], "s3cr3t");
    }

    #[test]
    fn redaction_names_no_secret_that_is_unset_or_null() {
        let mut endpoint = webhook();
        endpoint.configuration = json!({"url": "https://ops.example.com/hook", "signing_secret": null});

        let (redacted, secrets) = endpoint.redacted();

        assert_eq!(redacted.configuration, json!({"url": "https://ops.example.com/hook"}));
        assert!(secrets.is_empty());
    }

    #[test]
    fn an_update_keeps_secrets_it_leaves_out_and_clears_those_sent_as_null() {
        let existing = json!({
            "smtp_host": "old.example.com",
            "smtp_password": "kept"
        });

        let kept = keep_unsent_secrets(EndpointType::Email, json!({"smtp_host": "new.example.com"}), &existing);
        assert_eq!(kept, json!({"smtp_host": "new.example.com", "smtp_password": "kept"}));

        let replaced = keep_unsent_secrets(
            EndpointType::Email,
            json!({"smtp_host": "new.example.com", "smtp_password": "rotated"}),
            &existing,
        );
        assert_eq!(replaced["smtp_password"], "rotated");

        let cleared = keep_unsent_secrets(
            EndpointType::Email,
            json!({"smtp_host": "new.example.com", "smtp_password": null}),
            &existing,
        );
        assert_eq!(cleared, json!({"smtp_host": "new.example.com"}));
    }

    #[test]
    fn an_update_never_keeps_a_field_that_is_not_secret() {
        let kept = keep_unsent_secrets(
            EndpointType::Webhook,
            json!({"url": "https://new.example.com/hook"}),
            &json!({"url": "https://old.example.com/hook", "method": "PUT"}),
        );

        assert_eq!(kept, json!({"url": "https://new.example.com/hook"}));
    }

    #[test]
    fn validates_the_configuration_its_publisher_needs() {
        let mut public = webhook();
        public.configuration = json!({"url": "https://93.184.215.14/hook"});
        assert_eq!(public.validate_configuration(), Ok(()));

        let mut internal = webhook();
        internal.configuration = json!({"url": "http://169.254.169.254/latest"});
        assert!(
            internal
                .validate_configuration()
                .is_err()
        );

        let mut not_an_object = webhook();
        not_an_object.configuration = json!("https://ops.example.com/hook");
        assert_eq!(not_an_object.validate_configuration(), Err("The configuration must be an object".to_string()));

        let topicless = Endpoint::new(
            "Kafka".to_string(),
            String::new(),
            EndpointType::Stream,
            json!({"platform": "kafka", "brokers": "kafka:9092"}),
        );
        assert!(
            topicless
                .validate_configuration()
                .is_err()
        );
    }
}
