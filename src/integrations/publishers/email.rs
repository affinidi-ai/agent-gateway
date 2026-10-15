use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tracing::info;

use super::{IntegrationPublisher, Message, with_defaults};
use crate::integrations::delivery::render::Escaping;
use crate::integrations::email_service::{SmtpConfig, send_email};

pub struct EmailPublisher;

/// Whether to send the body as HTML: the integration's `format`, or HTML tags
/// the admin wrote in the template itself. Never the substituted body, whose
/// variable values can come from a caller and must not switch the email to
/// HTML.
fn is_html_template(
    content: &Value,
    body_template: &str,
) -> bool {
    content
        .get("format")
        .and_then(Value::as_str)
        == Some("html")
        || body_template.contains("<html")
        || body_template.contains("<body")
}

#[async_trait]
impl IntegrationPublisher for EmailPublisher {
    fn name(&self) -> &str {
        "email"
    }

    fn supported_features(&self) -> Vec<&str> {
        vec!["html", "templates", "variables"]
    }

    fn required_config_fields(&self) -> Vec<&str> {
        vec!["smtp_host", "smtp_port", "smtp_username", "from", "to"]
    }

    fn validate_config(
        &self,
        config: &Value,
    ) -> Result<()> {
        SmtpConfig::from_json(config)
            .map(|_| ())
            .context("Invalid SMTP configuration")
    }

    /// Also sets `format` from the template, so a value can never switch the email to HTML.
    fn complete_template(
        &self,
        template: &Value,
    ) -> Value {
        let mut completed =
            with_defaults(template, serde_json::json!({"subject": "${EVENT_NAME}", "body": "${EVENT_SUMMARY}"}));
        let format = match self.escaping(template) {
            Escaping::Html => "html",
            _ => "plain",
        };
        completed["format"] = Value::String(format.to_string());
        completed
    }

    fn escaping(
        &self,
        template: &Value,
    ) -> Escaping {
        let body = template
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if is_html_template(template, body) {
            Escaping::Html
        } else {
            Escaping::None
        }
    }

    async fn send(
        &self,
        configuration: &Value,
        message: &Message,
    ) -> Result<()> {
        let smtp_config = SmtpConfig::from_json(configuration).context("Failed to parse SMTP configuration")?;
        let field = |name: &str| {
            message
                .content
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
        };
        let is_html = field("format") == "html";
        send_email(&smtp_config, field("subject"), field("body"), is_html)
            .await
            .context("Failed to send email")?;
        info!(integration_id = %message.integration_id, "Email delivered");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn html_comes_from_the_format_or_the_template() {
        assert!(is_html_template(&json!({ "format": "html" }), "Hello ${NAME}"));
        assert!(is_html_template(&json!({}), "<html><body>${NAME}</body></html>"));
        assert!(!is_html_template(&json!({ "format": "plain" }), "Hello ${NAME}"));
        assert!(!is_html_template(&json!({}), "Hello ${NAME}"));
    }

    #[test]
    fn a_substituted_value_cannot_switch_the_email_to_html() {
        let template = "Caller: ${AUDIT_PRINCIPAL_NAME}";
        let substituted = template.replace("${AUDIT_PRINCIPAL_NAME}", "<html><a href=\"https://evil\">x</a>");
        assert!(substituted.contains("<html"));
        assert!(!is_html_template(&json!({ "format": "plain" }), template));
    }

    #[test]
    fn an_empty_template_mails_the_event_name_and_summary_as_plain_text() {
        let completed = EmailPublisher.complete_template(&json!({}));

        assert_eq!(completed, json!({"subject": "${EVENT_NAME}", "body": "${EVENT_SUMMARY}", "format": "plain"}));
        assert_eq!(EmailPublisher.escaping(&json!({})), Escaping::None);
    }

    #[test]
    fn a_template_keeps_its_fields_and_borrows_the_ones_it_leaves_out() {
        assert_eq!(
            EmailPublisher.complete_template(&json!({"subject": "${GATEWAY_NAME} changed"})),
            json!({"subject": "${GATEWAY_NAME} changed", "body": "${EVENT_SUMMARY}", "format": "plain"})
        );
    }

    #[test]
    fn an_html_template_is_sent_as_html_with_escaped_values() {
        let tagged = json!({"body": "<html><body>${USERNAME}</body></html>"});
        let declared = json!({"body": "${USERNAME}", "format": "html"});

        assert_eq!(EmailPublisher.complete_template(&tagged)["format"], "html");
        assert_eq!(EmailPublisher.escaping(&tagged), Escaping::Html);
        assert_eq!(EmailPublisher.complete_template(&declared)["format"], "html");
        assert_eq!(EmailPublisher.escaping(&declared), Escaping::Html);
    }
}
