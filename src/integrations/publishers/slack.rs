use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tracing::info;

use super::{IntegrationPublisher, Message, with_defaults};
use crate::integrations::delivery::render::Escaping;

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

    fn complete_template(
        &self,
        template: &Value,
    ) -> Value {
        with_defaults(template, serde_json::json!({"text": "*${EVENT_NAME}*\n${EVENT_SUMMARY}"}))
    }

    /// Values are escaped so caller-supplied text cannot form mentions such as `<!channel>`
    /// or disguised links.
    fn escaping(
        &self,
        _template: &Value,
    ) -> Escaping {
        Escaping::SlackMrkdwn
    }

    async fn send(
        &self,
        configuration: &Value,
        message: &Message,
    ) -> Result<()> {
        let webhook_url = configuration
            .get("webhook_url")
            .and_then(Value::as_str)
            .context("Missing webhook_url in Slack configuration")?;
        crate::url_validation::validate_resolved_webhook_url(webhook_url)
            .map_err(|e| anyhow::anyhow!("webhook_url rejected: {}", e))?;
        let setting = |name: &str, default: &'static str| {
            configuration
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or(default)
                .to_string()
        };
        let payload = serde_json::json!({
            "text": message.content.get("text").and_then(Value::as_str).unwrap_or_default(),
            "username": setting("bot_name", "Agent Gateway"),
            "icon_emoji": setting("icon_emoji", ":robot_face:"),
        });
        let response = crate::http_client::external()?
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("Failed to send Slack webhook")?;
        if response.status().is_success() {
            info!(integration_id = %message.integration_id, "Slack message delivered");
            return Ok(());
        }
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_default();
        Err(anyhow::anyhow!("Slack webhook failed: {} - {}", status, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(url: &str) -> Value {
        serde_json::json!({ "webhook_url": url })
    }

    fn publisher() -> SlackPublisher {
        SlackPublisher
    }

    #[test]
    fn an_empty_template_posts_the_event_name_and_summary() {
        assert_eq!(
            publisher().complete_template(&serde_json::json!({})),
            serde_json::json!({"text": "*${EVENT_NAME}*\n${EVENT_SUMMARY}"})
        );
        assert_eq!(
            publisher().complete_template(&serde_json::json!({"text": "${GATEWAY_NAME} changed"})),
            serde_json::json!({"text": "${GATEWAY_NAME} changed"})
        );
    }

    #[test]
    fn values_are_escaped_for_mrkdwn() {
        assert_eq!(publisher().escaping(&serde_json::json!({})), Escaping::SlackMrkdwn);
    }

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
