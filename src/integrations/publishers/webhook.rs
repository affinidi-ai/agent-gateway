use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use tracing::info;

use super::{IntegrationPublisher, Message, event_envelope, is_empty_template};

pub struct WebhookPublisher;

#[async_trait]
impl IntegrationPublisher for WebhookPublisher {
    fn name(&self) -> &str {
        "webhook"
    }

    fn supported_features(&self) -> Vec<&str> {
        vec!["hmac_signing", "custom_headers", "templates", "variables"]
    }

    fn required_config_fields(&self) -> Vec<&str> {
        vec!["url"]
    }

    fn validate_config(
        &self,
        config: &Value,
    ) -> Result<()> {
        let url = config
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing url in webhook configuration"))?;
        crate::url_validation::validate_resolved_webhook_url(url)
            .map_err(|e| anyhow::anyhow!("Invalid webhook URL: {}", e))?;
        if let Some(method) = config
            .get("method")
            .and_then(Value::as_str)
            && !SUPPORTED_METHODS.contains(&method.to_uppercase().as_str())
        {
            anyhow::bail!("Unsupported HTTP method: {method}; use POST, PUT or PATCH");
        }
        if let Some(headers) = config.get("headers")
            && !headers
                .as_object()
                .is_some_and(|headers| {
                    headers
                        .values()
                        .all(Value::is_string)
                })
        {
            anyhow::bail!(
                "The headers must be an object of header names to string values; a value may be $SECRET:<secret_id>"
            );
        }
        if let Some(name) = config
            .get("headers")
            .and_then(Value::as_object)
            .and_then(|headers| {
                headers
                    .keys()
                    .find(|name| reserved_header(name))
            })
        {
            anyhow::bail!("The header {name} is set by the gateway on every delivery; remove it from the headers");
        }
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

    fn embeds_json(&self) -> bool {
        true
    }

    async fn send(
        &self,
        configuration: &Value,
        message: &Message,
    ) -> Result<()> {
        let url = configuration
            .get("url")
            .and_then(Value::as_str)
            .context("Missing url in webhook configuration")?;
        crate::url_validation::validate_resolved_webhook_url(url).map_err(|e| anyhow::anyhow!("{}", e))?;
        let client = crate::http_client::external()?;
        let mut request = match configuration
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("POST")
            .to_uppercase()
            .as_str()
        {
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "PATCH" => client.patch(url),
            method => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
        };
        let body = serde_json::to_string(&message.content).context("Failed to serialize payload")?;
        let timestamp = chrono::Utc::now()
            .timestamp()
            .to_string();
        request = request.headers(request_headers(configuration, &timestamp, &body)?);
        let response = request
            .body(body)
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("Failed to send webhook")?;
        if response.status().is_success() {
            info!(integration_id = %message.integration_id, "Webhook delivered");
            return Ok(());
        }
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_default();
        Err(anyhow::anyhow!("Webhook failed: {} - {}", status, body))
    }
}

const SUPPORTED_METHODS: &[&str] = &["POST", "PUT", "PATCH"];

const TIMESTAMP_HEADER: &str = "x-webhook-timestamp";
const SIGNATURE_HEADER: &str = "x-webhook-signature-256";

/// Headers the gateway sets on every delivery, so an endpoint cannot configure them.
const RESERVED_HEADERS: &[&str] = &["content-type", TIMESTAMP_HEADER, SIGNATURE_HEADER];

pub(crate) fn reserved_header(name: &str) -> bool {
    RESERVED_HEADERS.contains(
        &name
            .to_ascii_lowercase()
            .as_str(),
    )
}

/// The headers of one delivery: the configured ones first, then the reserved ones, each set
/// once with replace semantics. A stored endpoint that predates the reserved-header check
/// therefore still sends one `Content-Type`, one timestamp and at most one signature.
fn request_headers(
    configuration: &Value,
    timestamp: &str,
    body: &str,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    if let Some(configured) = configuration
        .get("headers")
        .and_then(Value::as_object)
    {
        for (name, value) in configured {
            let Some(value) = value.as_str() else { continue };
            if reserved_header(name) {
                continue;
            }
            let name =
                HeaderName::from_bytes(name.as_bytes()).with_context(|| format!("Invalid header name {name}"))?;
            let value = HeaderValue::from_str(value).with_context(|| format!("Invalid value for header {name}"))?;
            headers.insert(name, value);
        }
    }
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(TIMESTAMP_HEADER, HeaderValue::from_str(timestamp).context("Invalid timestamp")?);
    if let Some(secret) = configuration
        .get("signing_secret")
        .and_then(Value::as_str)
    {
        headers.insert(
            SIGNATURE_HEADER,
            HeaderValue::from_str(&signature(secret, timestamp, body)?).context("Invalid signature")?,
        );
    }
    Ok(headers)
}

/// The `X-Webhook-Signature-256` value: `sha256=` and the hex HMAC-SHA256 of
/// `timestamp.body` keyed with the signing secret.
fn signature(
    secret: &str,
    timestamp: &str,
    body: &str,
) -> Result<String> {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).context("Invalid HMAC key")?;
    mac.update(format!("{timestamp}.{body}").as_bytes());
    Ok(format!("sha256={}", hex::encode(mac.finalize().into_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::delivery::render::Escaping;
    use serde_json::json;

    #[test]
    fn an_empty_template_sends_the_event_envelope() {
        for empty in [json!({}), json!(null)] {
            assert_eq!(
                WebhookPublisher.complete_template(&empty),
                json!({
                    "event_type": "${EVENT_TYPE}",
                    "event_name": "${EVENT_NAME}",
                    "timestamp": "${TIMESTAMP}",
                    "appliance_id": "${APPLIANCE_ID}",
                    "summary": "${EVENT_SUMMARY}",
                    "data": "${EVENT_DATA}"
                })
            );
        }
    }

    #[test]
    fn a_template_of_its_own_is_sent_as_written() {
        let template = json!({"alert": "${EVENT_SUMMARY}"});

        assert_eq!(WebhookPublisher.complete_template(&template), template);
        assert_eq!(WebhookPublisher.escaping(&template), Escaping::None);
    }

    /// A public address as an IP literal, so validation needs no DNS.
    const URL: &str = "https://93.184.215.14/hook";

    #[test]
    fn headers_are_an_object_of_strings_whose_values_may_reference_secrets() {
        let valid = json!({"url": URL, "headers": {"Authorization": "$SECRET:hook-token", "X-Team": "ops"}});

        assert!(
            WebhookPublisher
                .validate_config(&valid)
                .is_ok()
        );
    }

    #[test]
    fn refuses_headers_that_would_not_be_sent() {
        // A reference resolves to a string, and only an object's string values are sent.
        for headers in [json!("$SECRET:hook-headers"), json!(["Authorization"]), json!({"X-Count": 3})] {
            let error = WebhookPublisher
                .validate_config(&json!({"url": URL, "headers": headers}))
                .expect_err("refused");

            assert!(
                error
                    .to_string()
                    .contains("headers"),
                "{error}"
            );
        }
    }

    #[test]
    fn refuses_configured_headers_the_gateway_sets_itself() {
        for name in ["content-type", "X-WEBHOOK-TIMESTAMP", "X-Webhook-Signature-256"] {
            let error = WebhookPublisher
                .validate_config(&json!({"url": URL, "headers": {name: "value"}}))
                .expect_err("refused");

            assert!(
                error
                    .to_string()
                    .contains(name),
                "{error}"
            );
        }
        assert!(
            WebhookPublisher
                .validate_config(&json!({"url": URL, "headers": {"Authorization": "Bearer x"}}))
                .is_ok()
        );
    }

    fn values<'a>(
        headers: &'a reqwest::header::HeaderMap,
        name: &str,
    ) -> Vec<&'a str> {
        headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect()
    }

    #[test]
    fn a_stored_endpoint_with_reserved_headers_still_sends_each_once() {
        let configuration = json!({
            "signing_secret": "s3cr3t",
            "headers": {
                "Content-Type": "text/plain",
                "x-webhook-signature-256": "sha256=stale",
                "X-Webhook-Timestamp": "0",
                "Authorization": "Bearer x"
            }
        });

        let headers = request_headers(&configuration, "1700000000", r#"{"a":1}"#).expect("headers");

        assert_eq!(values(&headers, "content-type"), ["application/json"]);
        assert_eq!(values(&headers, "x-webhook-timestamp"), ["1700000000"]);
        assert_eq!(
            values(&headers, "x-webhook-signature-256"),
            [signature("s3cr3t", "1700000000", r#"{"a":1}"#)
                .unwrap()
                .as_str()]
        );
        assert_eq!(values(&headers, "authorization"), ["Bearer x"]);
    }

    #[test]
    fn without_a_signing_secret_no_signature_is_sent() {
        let configuration = json!({"headers": {"X-Webhook-Signature-256": "sha256=stale"}});

        let headers = request_headers(&configuration, "1700000000", "{}").expect("headers");

        assert!(values(&headers, "x-webhook-signature-256").is_empty());
    }

    #[test]
    fn refuses_a_method_it_cannot_send_with() {
        let error = WebhookPublisher
            .validate_config(&json!({"url": URL, "method": "DELETE"}))
            .expect_err("refused");

        assert!(
            error
                .to_string()
                .contains("DELETE"),
            "{error}"
        );
        assert!(
            WebhookPublisher
                .validate_config(&json!({"url": URL, "method": "patch"}))
                .is_ok()
        );
    }

    #[test]
    fn signs_the_timestamp_and_body_with_hmac_sha256() {
        assert_eq!(
            signature("s3cr3t", "1700000000", r#"{"a":1}"#).expect("signs"),
            "sha256=8dbbbbf4523b10bbb793e74d854144c45acccc2d233667b1c06b805b6ded8a84"
        );
    }
}
