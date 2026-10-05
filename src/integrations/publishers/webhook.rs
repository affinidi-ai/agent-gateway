use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, error, info};

use super::IntegrationPublisher;
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

    async fn test(
        &self,
        config: &Value,
        content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String> {
        let webhook_url = config
            .get("url")
            .and_then(|v| v.as_str())
            .context("Missing url in configuration")?;
        crate::url_validation::validate_resolved_webhook_url(webhook_url).map_err(|e| anyhow::anyhow!("{}", e))?;

        let method = config
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST")
            .to_uppercase();

        let signing_secret = config
            .get("signing_secret")
            .and_then(|v| v.as_str());

        // Build test payload
        let payload = if !content.is_null() && content.is_object() {
            substitute_variables_in_json(content, None, variables)
        } else {
            serde_json::json!({
                "test": true,
                "message": "This is a test webhook",
                "timestamp": chrono::Utc::now().to_rfc3339(),
            })
        };

        let payload_json = serde_json::to_string(&payload).context("Failed to serialize payload")?;

        let client = crate::http_client::external()?;

        let mut request = match method.as_str() {
            "POST" => client.post(webhook_url),
            "PUT" => client.put(webhook_url),
            "PATCH" => client.patch(webhook_url),
            _ => {
                return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method));
            }
        };

        let timestamp = chrono::Utc::now()
            .timestamp()
            .to_string();
        request = request.header("X-Webhook-Timestamp", &timestamp);

        if let Some(secret) = signing_secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            let signed_content = format!("{}.{}", timestamp, payload_json);

            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).context("Invalid HMAC key")?;
            mac.update(signed_content.as_bytes());
            let signature = mac.finalize();
            let signature_hex = hex::encode(signature.into_bytes());

            request = request.header("X-Webhook-Signature-256", format!("sha256={}", signature_hex));
        }

        if let Some(headers) = config
            .get("headers")
            .and_then(|v| v.as_object())
        {
            for (key, value) in headers {
                if let Some(value_str) = value.as_str() {
                    let substituted_value = substitute_variables(value_str, None, variables);
                    request = request.header(key, substituted_value);
                }
            }
        }

        let response = request
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await
            .context("Failed to send test webhook")?;

        if response.status().is_success() {
            Ok(format!("Test webhook sent successfully to {} ({})", webhook_url, response.status()))
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            Err(anyhow::anyhow!("Webhook test failed: {} - {}", status, body))
        }
    }
}
