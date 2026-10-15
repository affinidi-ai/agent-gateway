use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, error, info};

use super::{IntegrationPublisher, Message, event_envelope, is_empty_template};
use crate::integrations::runtime_variables::{substitute_variables, substitute_variables_in_json};
use crate::storage::Integration;

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
        request = request.header("X-Webhook-Timestamp", &timestamp);
        if let Some(secret) = configuration
            .get("signing_secret")
            .and_then(Value::as_str)
        {
            request = request.header("X-Webhook-Signature-256", signature(secret, &timestamp, &body)?);
        }
        if let Some(headers) = configuration
            .get("headers")
            .and_then(Value::as_object)
        {
            for (name, value) in headers {
                if let Some(value) = value.as_str() {
                    request = request.header(name, value);
                }
            }
        }
        let response = request
            .header("Content-Type", "application/json")
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

    async fn publish(
        &self,
        integration: &Integration,
        subject: &str,
        message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()> {
        info!("Triggering webhook integration: {}", integration.name);

        let webhook_url = integration.configuration["url"]
            .as_str()
            .context("Missing url in webhook configuration")?;
        crate::url_validation::validate_resolved_webhook_url(webhook_url).map_err(|e| anyhow::anyhow!("{}", e))?;

        let method = integration
            .configuration
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST")
            .to_uppercase();

        // Get signing secret if provided (for HMAC authentication)
        let signing_secret = integration
            .configuration
            .get("signing_secret")
            .and_then(|v| v.as_str());

        // Build webhook payload from content template with variable substitution
        let payload = if !integration.content.is_null()
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

        debug!("Webhook payload: {:?}", payload);

        // Convert payload to JSON string for body and signing
        let payload_json = serde_json::to_string(&payload).context("Failed to serialize payload")?;

        // Send HTTP request
        let client = crate::http_client::external()?;

        let mut request = match method.as_str() {
            "POST" => client.post(webhook_url),
            "PUT" => client.put(webhook_url),
            "PATCH" => client.patch(webhook_url),
            _ => {
                return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method));
            }
        };

        // Add timestamp for replay attack prevention
        let timestamp = chrono::Utc::now()
            .timestamp()
            .to_string();
        request = request.header("X-Webhook-Timestamp", &timestamp);

        // Add HMAC signature if signing secret is provided
        if let Some(secret) = signing_secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            // Create HMAC signature: HMAC-SHA256(secret, timestamp + "." + payload)
            let signed_content = format!("{}.{}", timestamp, payload_json);

            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).context("Invalid HMAC key")?;
            mac.update(signed_content.as_bytes());
            let signature = mac.finalize();
            let signature_hex = hex::encode(signature.into_bytes());

            // Send signature in header (following GitHub/Stripe webhook pattern)
            request = request.header("X-Webhook-Signature-256", format!("sha256={}", signature_hex));

            info!("Added HMAC-SHA256 signature to webhook request");
        }

        // Add custom headers if provided in configuration (after built-in headers)
        if let Some(headers) = integration
            .configuration
            .get("headers")
            .and_then(|v| v.as_object())
        {
            for (key, value) in headers {
                if let Some(value_str) = value.as_str() {
                    // Substitute variables in header values
                    let substituted_value = substitute_variables(
                        value_str,
                        integration
                            .category
                            .as_deref(),
                        variables,
                    );
                    request = request.header(key, substituted_value);
                }
            }
        }

        let response = request
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await
            .map_err(|e| {
                let e = e.without_url();
                error!("Failed to send webhook: {} (timeout: {}, connect: {})", e, e.is_timeout(), e.is_connect());
                e
            })
            .context("Failed to send webhook")?;

        if response.status().is_success() {
            info!("Webhook notification sent successfully via integration: {}", integration.name);
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            error!("Webhook failed with status {}: {}", status, body);
            Err(anyhow::anyhow!("Webhook failed: {} - {}", status, body))
        }
    }
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

    #[test]
    fn signs_the_timestamp_and_body_with_hmac_sha256() {
        assert_eq!(
            signature("s3cr3t", "1700000000", r#"{"a":1}"#).expect("signs"),
            "sha256=8dbbbbf4523b10bbb793e74d854144c45acccc2d233667b1c06b805b6ded8a84"
        );
    }
}
