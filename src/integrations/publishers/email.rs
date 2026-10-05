use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::info;

use super::IntegrationPublisher;
use crate::integrations::email_service::{SmtpConfig, send_email, send_email_batch};
use crate::integrations::runtime_variables::substitute_variables;
use crate::storage::Integration;

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

    async fn publish(
        &self,
        integration: &Integration,
        subject: &str,
        message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()> {
        info!("Triggering email integration: {}", integration.name);

        // Parse SMTP config from integration configuration
        let smtp_config =
            SmtpConfig::from_json(&integration.configuration).context("Failed to parse SMTP configuration")?;

        // Use content template if provided, otherwise use passed message
        let subject_template = integration
            .content
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or(subject);

        let body_template = integration
            .content
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or(message);

        // Perform template variable substitution
        let actual_subject = substitute_variables(
            subject_template,
            integration
                .category
                .as_deref(),
            variables,
        );
        let actual_body = substitute_variables(
            body_template,
            integration
                .category
                .as_deref(),
            variables,
        );

        let is_html = is_html_template(&integration.content, body_template);

        // Send the email
        send_email(&smtp_config, &actual_subject, &actual_body, is_html)
            .await
            .context("Failed to send email")?;

        info!("Email notification sent successfully via integration: {}", integration.name);
        Ok(())
    }

    async fn test(
        &self,
        config: &Value,
        content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String> {
        use crate::integrations::email_service::{SmtpConfig, send_email};

        let smtp_config = SmtpConfig::from_json(config).context("Failed to parse SMTP configuration")?;

        let subject = content
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("Test Email");

        let body = content
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("This is a test email from the integration system.");

        // Perform template variable substitution
        let actual_subject = substitute_variables(subject, None, variables);
        let actual_body = substitute_variables(body, None, variables);

        let is_html = is_html_template(content, body);

        send_email(&smtp_config, &actual_subject, &actual_body, is_html)
            .await
            .context("Failed to send test email")?;

        Ok(format!("Test email sent successfully to {}", smtp_config.to.join(", ")))
    }
    async fn publish_batch(
        &self,
        integration: &Integration,
        items: Vec<(&str, &str, &HashMap<String, String>)>,
    ) -> Result<Vec<Result<()>>> {
        info!("Triggering email batch integration: {} with {} items", integration.name, items.len());

        // Parse SMTP config once for the batch
        let smtp_config =
            SmtpConfig::from_json(&integration.configuration).context("Failed to parse SMTP configuration")?;

        // Prepare all email messages
        let mut messages = Vec::new();
        for (subject, message, variables) in items {
            let subject_template = integration
                .content
                .get("subject")
                .and_then(|v| v.as_str())
                .unwrap_or(subject);

            let body_template = integration
                .content
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or(message);

            let actual_subject = substitute_variables(
                subject_template,
                integration
                    .category
                    .as_deref(),
                variables,
            );
            let actual_body = substitute_variables(
                body_template,
                integration
                    .category
                    .as_deref(),
                variables,
            );

            let is_html = is_html_template(&integration.content, body_template);

            messages.push((actual_subject, actual_body, is_html));
        }

        // Send all emails using a single SMTP connection
        let results = send_email_batch(&smtp_config, messages).await?;

        info!("Email batch notification sent successfully via integration: {}", integration.name);
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::is_html_template;

    #[test]
    fn html_comes_from_the_format_or_the_template() {
        assert!(is_html_template(&serde_json::json!({ "format": "html" }), "Hello ${NAME}"));
        assert!(is_html_template(&serde_json::json!({}), "<html><body>${NAME}</body></html>"));
        assert!(!is_html_template(&serde_json::json!({ "format": "plain" }), "Hello ${NAME}"));
        assert!(!is_html_template(&serde_json::json!({}), "Hello ${NAME}"));
    }

    #[test]
    fn a_substituted_value_cannot_switch_the_email_to_html() {
        let template = "Caller: ${AUDIT_PRINCIPAL_NAME}";
        let substituted = template.replace("${AUDIT_PRINCIPAL_NAME}", "<html><a href=\"https://evil\">x</a>");
        assert!(substituted.contains("<html"));
        assert!(!is_html_template(&serde_json::json!({ "format": "plain" }), template));
    }
}
