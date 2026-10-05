use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info};

use super::IntegrationPublisher;
use crate::integrations::runtime_variables::substitute_variables;
use crate::storage::Integration;

pub struct SlackPublisher;

#[async_trait]
impl IntegrationPublisher for SlackPublisher {
    fn name(&self) -> &str {
        "slack"
    }

    fn supported_features(&self) -> Vec<&str> {
        vec!["templates", "variables", "custom_bot"]
    }

    fn required_config_fields(&self) -> Vec<&str> {
        vec!["webhook_url"]
    }

    fn validate_config(
        &self,
        config: &Value,
    ) -> Result<()> {
        let url = config
            .get("webhook_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing webhook_url in Slack configuration"))?;
        crate::url_validation::validate_webhook_url(url).map_err(|e| anyhow::anyhow!("webhook_url rejected: {}", e))?;
        Ok(())
    }

    async fn publish(
        &self,
        integration: &Integration,
        subject: &str,
        message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()> {
        info!("Triggering Slack integration: {}", integration.name);

        let webhook_url = integration.configuration["webhook_url"]
            .as_str()
            .context("Missing webhook_url in Slack configuration")?;

        crate::url_validation::validate_resolved_webhook_url(webhook_url)
            .map_err(|e| anyhow::anyhow!("webhook_url rejected: {}", e))?;

        // Use content template if provided
        let text_template = if let Some(template_text) = integration
            .content
            .get("text")
            .and_then(|v| v.as_str())
        {
            template_text.to_string()
        } else {
            format!("*{}*\n{}", subject, message)
        };

        // Perform template variable substitution
        let text = substitute_variables(
            &text_template,
            integration
                .category
                .as_deref(),
            variables,
        );

        let bot_name = integration
            .content
            .get("bot_name")
            .and_then(|v| v.as_str())
            .or_else(|| {
                integration
                    .configuration
                    .get("bot_name")
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("Agent Gateway");

        let icon_emoji = integration
            .content
            .get("icon_emoji")
            .and_then(|v| v.as_str())
            .or_else(|| {
                integration
                    .configuration
                    .get("icon_emoji")
                    .and_then(|v| v.as_str())
            })
            .unwrap_or(":robot_face:");

        // Build Slack message payload
        let mut payload = serde_json::json!({
            "text": text,
            "username": bot_name,
            "icon_emoji": icon_emoji
        });

        // Add channel if specified in content
        if let Some(channel) = integration
            .content
            .get("channel")
            .and_then(|v| v.as_str())
        {
            payload["channel"] = serde_json::json!(channel);
        }

        debug!("Slack payload: {:?}", payload);
        info!("Sending Slack notification to webhook: {}", webhook_url);

        // Send HTTP POST to Slack webhook with timeout
        let client = crate::http_client::external()?;

        let response = client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Slack webhook")?;

        if response.status().is_success() {
            info!("Slack notification sent successfully via integration: {}", integration.name);
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            Err(anyhow::anyhow!("Slack webhook failed: {} - {}", status, body))
        }
    }

    async fn test(
        &self,
        config: &Value,
        content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String> {
        let webhook_url = config
            .get("webhook_url")
            .and_then(|v| v.as_str())
            .context("Missing webhook_url in configuration")?;

        crate::url_validation::validate_resolved_webhook_url(webhook_url)
            .map_err(|e| anyhow::anyhow!("webhook_url rejected: {}", e))?;

        let text_template = content
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("This is a test message from the integration system.");

        let text = substitute_variables(text_template, None, variables);

        let bot_name = content
            .get("bot_name")
            .and_then(|v| v.as_str())
            .or_else(|| {
                config
                    .get("bot_name")
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("Agent Gateway");

        let icon_emoji = content
            .get("icon_emoji")
            .and_then(|v| v.as_str())
            .or_else(|| {
                config
                    .get("icon_emoji")
                    .and_then(|v| v.as_str())
            })
            .unwrap_or(":robot_face:");

        let mut payload = serde_json::json!({
            "text": text,
            "username": bot_name,
            "icon_emoji": icon_emoji
        });

        if let Some(channel) = content
            .get("channel")
            .and_then(|v| v.as_str())
        {
            payload["channel"] = serde_json::json!(channel);
        }

        let client = crate::http_client::external()?;

        let response = client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send test Slack webhook")?;

        if response.status().is_success() {
            Ok("Test Slack message sent successfully".to_string())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            Err(anyhow::anyhow!("Slack webhook failed: {} - {}", status, body))
        }
    }
}

// ── SSRF guard tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(url: &str) -> Value {
        serde_json::json!({ "webhook_url": url })
    }

    fn publisher() -> SlackPublisher {
        SlackPublisher
    }

    // ── validate_config SSRF checks ───────────────────────────────────────

    #[test]
    fn validate_config_rejects_aws_metadata_ip() {
        let result = publisher().validate_config(&make_config("http://169.254.169.254/hook"));
        assert!(result.is_err(), "should reject AWS metadata IP");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("rejected")
        );
    }

    #[test]
    fn validate_config_rejects_loopback() {
        let result = publisher().validate_config(&make_config("http://127.0.0.1/hook"));
        assert!(result.is_err(), "should reject loopback");
    }

    #[test]
    fn validate_config_rejects_localhost() {
        let result = publisher().validate_config(&make_config("http://localhost/hook"));
        assert!(result.is_err(), "should reject localhost");
    }

    #[test]
    fn validate_config_rejects_rfc1918_10() {
        let result = publisher().validate_config(&make_config("http://10.0.0.1/hook"));
        assert!(result.is_err(), "should reject RFC1918 10.x address");
    }

    #[test]
    fn validate_config_rejects_rfc1918_172() {
        let result = publisher().validate_config(&make_config("http://172.16.0.1/hook"));
        assert!(result.is_err(), "should reject RFC1918 172.16.x address");
    }

    #[test]
    fn validate_config_rejects_rfc1918_192_168() {
        let result = publisher().validate_config(&make_config("http://192.168.1.1/hook"));
        assert!(result.is_err(), "should reject RFC1918 192.168.x address");
    }

    #[test]
    fn validate_config_rejects_ipv6_loopback() {
        let result = publisher().validate_config(&make_config("http://[::1]/hook"));
        assert!(result.is_err(), "should reject IPv6 loopback");
    }

    #[test]
    fn validate_config_rejects_embedded_credentials() {
        let result = publisher().validate_config(&make_config("http://user:pass@hooks.slack.com/hook"));
        assert!(result.is_err(), "should reject embedded credentials");
    }

    #[test]
    fn validate_config_rejects_non_http_scheme() {
        let result = publisher().validate_config(&make_config("file:///etc/passwd"));
        assert!(result.is_err(), "should reject non-http scheme");
    }

    #[test]
    fn validate_config_rejects_missing_url() {
        let result = publisher().validate_config(&serde_json::json!({}));
        assert!(result.is_err(), "should reject missing webhook_url");
    }

    #[test]
    fn validate_config_accepts_public_https_url() {
        let result = publisher().validate_config(&make_config("https://hooks.slack.com/services/T00/B00/xxx"));
        assert!(result.is_ok(), "should accept public https Slack webhook URL: {:?}", result.err());
    }

    #[test]
    fn validate_config_accepts_public_http_url() {
        // Use an IP literal so the test does not depend on DNS resolution.
        // 198.51.100.1 is in the TEST-NET-2 documentation range (RFC 5737) —
        // public, not private/link-local/metadata, passes the webhook validator.
        let result = publisher().validate_config(&make_config("http://198.51.100.1/webhook"));
        assert!(result.is_ok(), "should accept public http webhook URL: {:?}", result.err());
    }
}
