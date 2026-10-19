use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{Definition, Status, now};
use crate::integrations::publishers::INTEGRATION_REGISTRY;
use crate::secrets::SecretsStore;
use crate::storage::filesystem::StorableEntity;
use crate::tenancy::can_reference;

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
            Self::Stream => &["sasl_password", "redis_url", "auth_token"],
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
                let is_reference = configuration
                    .get(*field)
                    .and_then(JsonValue::as_str)
                    .is_some_and(|value| value.starts_with(SECRET_REFERENCE_PREFIX));
                if is_reference {
                    continue;
                }
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

    /// The secret ids its secret fields and webhook header values reference, in the form
    /// `resolve_secret_references` resolves: the whole value is `$SECRET:<secret_id>`.
    pub fn secret_references(&self) -> Vec<&str> {
        self.referencing_fields()
            .into_iter()
            .map(|(_, secret_id)| secret_id)
            .collect()
    }

    /// Each secret field and webhook header whose value references a secret, named as an
    /// error may show it, with the secret id.
    fn referencing_fields(&self) -> Vec<(String, &str)> {
        let mut references = Vec::new();
        for field in self
            .endpoint_type
            .secret_fields()
        {
            match self.configuration.get(*field) {
                Some(JsonValue::String(value)) => references.extend(
                    value
                        .strip_prefix(SECRET_REFERENCE_PREFIX)
                        .map(|secret_id| (field.to_string(), secret_id)),
                ),
                Some(JsonValue::Object(headers)) => references.extend(headers.iter().filter_map(|(name, value)| {
                    let secret_id = value
                        .as_str()?
                        .strip_prefix(SECRET_REFERENCE_PREFIX)?;
                    Some((format!("the header {name}"), secret_id))
                })),
                _ => {}
            }
        }
        references
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

    /// Checks the configuration the endpoint would send with, its secret references resolved,
    /// as saving it does. The publisher's reason is returned only when the referenced values
    /// blanked give the same one, so it can neither hold nor depend on a secret; otherwise the
    /// reason names the fields and secret ids alone.
    pub async fn validate_resolved(
        &self,
        secrets: Option<&dyn SecretsStore>,
    ) -> Result<(), String> {
        let mut resolved = self.clone();
        resolved.configuration = resolve_secret_references(self.endpoint_type, &self.configuration, secrets).await?;
        let Err(reason) = resolved.validate_configuration() else {
            return Ok(());
        };
        let references = self.referencing_fields();
        if references.is_empty() {
            return Err(reason);
        }
        let mut blanked = self.clone();
        for value in secret_values_mut(self.endpoint_type, &mut blanked.configuration) {
            if value.starts_with(SECRET_REFERENCE_PREFIX) {
                value.clear();
            }
        }
        if blanked
            .validate_configuration()
            .err()
            .as_ref()
            == Some(&reason)
        {
            return Err(reason);
        }
        let named: Vec<String> = references
            .iter()
            .map(|(field, secret_id)| format!("{field} from secret {secret_id}"))
            .collect();
        Err(match named.as_slice() {
            [one] => format!("The value of {one} fails the endpoint checks"),
            many => format!("The values of {} fail the endpoint checks", many.join(", ")),
        })
    }
}

/// Marks a secret field value, or a webhook header value, that names a secret in the secrets
/// store instead of holding it.
pub const SECRET_REFERENCE_PREFIX: &str = "$SECRET:";

/// `configuration` with every `$SECRET:<secret_id>` secret field and webhook header value
/// replaced by the stored secret. Fails when a named secret, or the store, is missing.
pub async fn resolve_secret_references(
    endpoint_type: EndpointType,
    configuration: &JsonValue,
    store: Option<&dyn SecretsStore>,
) -> Result<JsonValue, String> {
    let mut resolved = configuration.clone();
    for value in secret_values_mut(endpoint_type, &mut resolved) {
        resolve_reference(value, store).await?;
    }
    Ok(resolved)
}

/// The text values of `configuration`'s secret fields and webhook headers.
fn secret_values_mut(
    endpoint_type: EndpointType,
    configuration: &mut JsonValue,
) -> Vec<&mut String> {
    let Some(fields) = configuration.as_object_mut() else {
        return Vec::new();
    };
    let secret_fields = endpoint_type.secret_fields();
    fields
        .iter_mut()
        .filter(|(name, _)| secret_fields.contains(&name.as_str()))
        .flat_map(|(_, value)| match value {
            JsonValue::String(value) => vec![value],
            JsonValue::Object(headers) => headers
                .values_mut()
                .filter_map(|header| match header {
                    JsonValue::String(value) => Some(value),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// Replaces a `$SECRET:<secret_id>` `value` with the appliance-wide secret it names.
async fn resolve_reference(
    value: &mut String,
    store: Option<&dyn SecretsStore>,
) -> Result<(), String> {
    let Some(secret_id) = value.strip_prefix(SECRET_REFERENCE_PREFIX) else {
        return Ok(());
    };
    let store =
        store.ok_or_else(|| format!("Secret '{secret_id}' is referenced but no secrets store is configured"))?;
    let secret = store
        .get_by_secret_id(secret_id)
        .await
        .map_err(|error| format!("Failed to read secret '{secret_id}': {error}"))?
        .filter(|secret| can_reference(None, secret.tenant_id.as_deref()))
        .ok_or_else(|| format!("Secret '{secret_id}' not found"))?;
    *value = secret.value;
    Ok(())
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
    use super::super::test_secrets::Secrets;
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
        assert_eq!(EndpointType::Stream.secret_fields(), ["sasl_password", "redis_url", "auth_token"]);
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

    #[tokio::test]
    async fn resolves_secret_references_in_secret_fields_and_headers() {
        let store = Secrets(vec![("hook-signing", None, "s3cr3t"), ("ops-token", None, "Bearer abc")]);
        let configuration = json!({
            "url": "https://93.184.215.14/hook",
            "signing_secret": "$SECRET:hook-signing",
            "headers": {"Authorization": "$SECRET:ops-token", "X-Team": "ops"}
        });

        let resolved = resolve_secret_references(EndpointType::Webhook, &configuration, Some(&store))
            .await
            .expect("resolves");

        assert_eq!(
            resolved,
            json!({
                "url": "https://93.184.215.14/hook",
                "signing_secret": "s3cr3t",
                "headers": {"Authorization": "Bearer abc", "X-Team": "ops"}
            })
        );
    }

    #[tokio::test]
    async fn resolves_only_secret_fields_and_leaves_literals_alone() {
        let store = Secrets(vec![("smtp", None, "pw")]);
        let configuration = json!({"smtp_host": "$SECRET:smtp", "smtp_password": "literal"});

        let resolved = resolve_secret_references(EndpointType::Email, &configuration, Some(&store))
            .await
            .expect("resolves");

        assert_eq!(resolved, configuration);
    }

    #[tokio::test]
    async fn fails_closed_without_the_secret_the_store_or_an_appliance_wide_owner() {
        let configuration = json!({"smtp_password": "$SECRET:smtp"});
        let missing = Secrets(Vec::new());
        let tenant_owned = Secrets(vec![("smtp", Some("team-a"), "pw")]);

        for (store, reason) in [
            (Some(&missing as &dyn SecretsStore), "not found"),
            (Some(&tenant_owned as &dyn SecretsStore), "not found"),
            (None, "no secrets store"),
        ] {
            let error = resolve_secret_references(EndpointType::Email, &configuration, store)
                .await
                .expect_err("fails");
            assert!(error.contains(reason), "{error}");
        }
    }

    const SECRET_VALUE: &str = "s3cr3t-value";

    fn slack(webhook_url: &str) -> Endpoint {
        Endpoint::new("Ops Slack".to_string(), String::new(), EndpointType::Slack, json!({"webhook_url": webhook_url}))
    }

    #[tokio::test]
    async fn a_referenced_secret_failing_the_checks_is_named_but_never_shown() {
        for value in ["not a url s3cr3t-value", "http://10.0.0.1/services/s3cr3t-value"] {
            let store = Secrets(vec![("slack-hook", None, value)]);

            let error = slack("$SECRET:slack-hook")
                .validate_resolved(Some(&store))
                .await
                .expect_err("refused");

            assert_eq!(error, "The value of webhook_url from secret slack-hook fails the endpoint checks");
        }
    }

    #[tokio::test]
    async fn a_problem_the_secret_values_do_not_cause_is_reported_as_it_is() {
        let store = Secrets(vec![("ops-token", None, SECRET_VALUE)]);
        let mut endpoint = webhook();
        endpoint.configuration = json!({
            "url": "http://169.254.169.254/latest",
            "headers": {"Authorization": "$SECRET:ops-token"}
        });

        let error = endpoint
            .validate_resolved(Some(&store))
            .await
            .expect_err("refused");

        assert!(error.contains("169.254.169.254"), "{error}");
        assert!(!error.contains(SECRET_VALUE), "{error}");
    }

    #[tokio::test]
    async fn a_plain_slack_url_failing_the_checks_is_never_shown() {
        let error = slack(&format!("hooks.slack.com/services/T0/B0/{SECRET_VALUE}"))
            .validate_resolved(None)
            .await
            .expect_err("refused");

        assert!(error.starts_with("webhook_url rejected: Invalid URL: "), "{error}");
        assert!(!error.contains(SECRET_VALUE), "{error}");
    }

    #[tokio::test]
    async fn an_unknown_secret_is_named() {
        let error = slack("$SECRET:slack-hook")
            .validate_resolved(Some(&Secrets(Vec::new())))
            .await
            .expect_err("refused");

        assert_eq!(error, "Secret 'slack-hook' not found");
    }

    #[test]
    fn names_the_secrets_its_secret_fields_and_headers_reference() {
        let mut endpoint = webhook();
        endpoint.configuration = json!({
            "url": "$SECRET:not-a-secret-field",
            "signing_secret": "$SECRET:hook-signing",
            "headers": {
                "Authorization": "$SECRET:ops-token",
                "X-Note": "Bearer $SECRET:inside-a-longer-value",
                "X-Team": "ops"
            }
        });

        assert_eq!(endpoint.secret_references(), ["hook-signing", "ops-token"]);
        assert!(
            webhook()
                .secret_references()
                .is_empty()
        );
    }

    #[test]
    fn redaction_shows_secret_references_but_not_secrets() {
        let mut endpoint = webhook();
        endpoint.configuration = json!({
            "url": "https://ops.example.com/hook",
            "signing_secret": "$SECRET:hook-signing"
        });

        let (redacted, secrets) = endpoint.redacted();

        assert_eq!(redacted.configuration["signing_secret"], "$SECRET:hook-signing");
        assert!(secrets.is_empty());
    }
}
