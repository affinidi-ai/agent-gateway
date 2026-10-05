use anyhow::Context;
use std::time::Duration;
use std::time::Instant;
use tokio_retry::RetryIf;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tracing::{debug, instrument, warn};

use super::cache::get_cached_integration;
use super::errors::{IntegrationError, Result};
use super::publishers::INTEGRATION_REGISTRY;
use crate::storage::get_integration_storage;

/// Trigger a integration by ID with the given event data and optional template variables
#[allow(dead_code)]
pub async fn trigger_integration(
    integration_id: &str,
    subject: &str,
    message: &str,
) -> Result<()> {
    trigger_integration_with_variables(integration_id, subject, message, &std::collections::HashMap::new()).await
}

/// Trigger a integration by ID with template variable substitution.
///
/// Refuses governance audit integrations: they receive only the records the
/// VP Audit Log dispatcher forwards, so an event trigger or a connection
/// point cannot push its own, possibly caller-supplied, values into the
/// audit stream.
#[instrument(skip(variables), fields(integration_id = %integration_id))]
pub async fn trigger_integration_with_variables(
    integration_id: &str,
    subject: &str,
    message: &str,
    variables: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let integration = load_integration(integration_id).await?;
    refuse_audit_integration(&integration)?;
    publish_to_integration(&integration, subject, message, variables).await
}

/// Delays before the retries of a transient publish failure, before jitter:
/// 1 s, 2 s, 4 s, 8 s and 16 s. tokio-retry's `ExponentialBackoff` raises its
/// base to successive powers, so the base is 2 and the factor scales it to
/// seconds (`from_millis(1000)` would wait 1 s and then the 16 s cap four times).
fn retry_delays() -> impl Iterator<Item = Duration> {
    ExponentialBackoff::from_millis(2)
        .factor(500)
        .max_delay(Duration::from_secs(16))
        .take(5)
}

/// Whether a publish failure may succeed on retry: a connect, timeout or send
/// error, or an HTTP 429 / 5xx. Any other HTTP status (a 401, a 404) fails
/// the same way every time, so retrying only delays the next delivery.
fn is_transient_publish_error(error: &anyhow::Error) -> bool {
    let send_failed = error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|e| e.is_timeout() || e.is_connect() || e.is_request())
    });
    if send_failed {
        return true;
    }
    let text = format!("{error:#}").to_lowercase();
    if let Some(status) = http_failure_status(&text) {
        return status == 429 || status >= 500;
    }
    ["timeout", "timed out", "connection", "network"]
        .iter()
        .any(|marker| text.contains(marker))
}

/// The status in a publisher's `... failed: <status> - <body>` error.
fn http_failure_status(text: &str) -> Option<u16> {
    let (_, rest) = text.split_once("failed: ")?;
    rest.get(..3)?.parse().ok()
}

fn refuse_audit_integration(integration: &crate::storage::Integration) -> Result<()> {
    if super::audit_integration_triggers::is_audit_integration(integration) {
        return Err(IntegrationError::AuditOnly(integration.id.clone()));
    }
    Ok(())
}

/// Trigger any integration by ID, governance audit ones included. Only for
/// callers that already required `audit.view` for an audit integration, such
/// as the manual trigger endpoints.
#[instrument(skip(variables), fields(integration_id = %integration_id))]
pub async fn trigger_authorized_integration(
    integration_id: &str,
    subject: &str,
    message: &str,
    variables: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let integration = load_integration(integration_id).await?;
    publish_to_integration(&integration, subject, message, variables).await
}

/// Load an integration from the cache, falling back to storage.
pub async fn load_integration(integration_id: &str) -> Result<crate::storage::Integration> {
    match get_cached_integration(integration_id).await {
        Ok(cached) => Ok((*cached).clone()),
        Err(_) => {
            let storage = get_integration_storage()
                .context("Notifier storage not initialized")
                .map_err(|e| IntegrationError::StorageError(e.to_string()))?;

            storage
                .load(integration_id)
                .await
                .map_err(|_| IntegrationError::NotFound(integration_id.to_string()))
        }
    }
}

/// Publish an event through an already-loaded integration, retrying transient failures.
#[instrument(skip_all, fields(integration_id = %integration.id))]
pub async fn publish_to_integration(
    integration: &crate::storage::Integration,
    subject: &str,
    message: &str,
    variables: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let integration_id = integration.id.as_str();
    let start = Instant::now();

    // Log integration details (removed span recording to avoid registry lookups)
    debug!(integration_type = %integration.integration_type, integration_name = %integration.name, "Publishing event to integration");

    if integration.status != "active" {
        warn!("Integration {} is not active, skipping", integration_id);
        return Err(IntegrationError::Inactive(integration_id.to_string(), integration.status.clone()));
    }

    // Get the publisher from the registry
    let publisher = INTEGRATION_REGISTRY
        .get(&integration.integration_type)
        .ok_or_else(|| {
            IntegrationError::UnknownType(
                integration
                    .integration_type
                    .clone(),
            )
        })?;

    let retry_strategy = retry_delays().map(jitter);

    // Use the publisher to send with retry logic
    let integration_clone = integration.clone();
    let subject_clone = subject.to_string();
    let message_clone = message.to_string();
    let variables_clone = variables.clone();
    let publisher_clone = publisher.clone();

    RetryIf::start(
        retry_strategy,
        || {
            let integration = integration_clone.clone();
            let subject = subject_clone.clone();
            let message = message_clone.clone();
            let variables = variables_clone.clone();
            let publisher = publisher_clone.clone();

            async move {
                publisher
                    .publish(&integration, &subject, &message, &variables)
                    .await
            }
        },
        |e: &anyhow::Error| {
            let transient = is_transient_publish_error(e);
            if transient {
                tracing::warn!("Retryable error: {}", e);
            } else {
                tracing::error!("Non-retryable error: {}", e);
            }
            transient
        },
    )
    .await
    .map_err(IntegrationError::PublisherError)?;

    // Record metrics
    let duration = start.elapsed();

    debug!(
        integration_id = %integration_id,
        integration_type = %integration.integration_type,
        duration_ms = duration.as_millis(),
        status = "success",
        "Integration triggered successfully"
    );

    Ok(())
}

/// Trigger multiple integrations by their IDs (executed in parallel)
#[instrument(skip(integration_ids))]
pub async fn trigger_integrations(
    integration_ids: &[String],
    subject: &str,
    message: &str,
) -> anyhow::Result<Vec<(String, Result<()>)>> {
    use futures::future::join_all;

    let subject = subject.to_string();
    let message = message.to_string();
    let variables = std::collections::HashMap::new();

    // Execute all integrations in parallel
    let tasks: Vec<_> = integration_ids
        .iter()
        .map(|id| {
            let id = id.clone();
            let subject = subject.clone();
            let message = message.clone();
            let variables = variables.clone();

            tokio::spawn(async move {
                let result = trigger_authorized_integration(&id, &subject, &message, &variables).await;
                (id, result)
            })
        })
        .collect();

    // Wait for all tasks to complete
    let results = join_all(tasks).await;

    Ok(results
        .into_iter()
        .map(|r| {
            r.unwrap_or_else(|e| {
                ("unknown".to_string(), Err(IntegrationError::PublisherError(anyhow::anyhow!("Task panicked: {}", e))))
            })
        })
        .collect())
}

/// Trigger all integrations of a specific type (executed in parallel)
#[allow(dead_code)]
#[instrument]
pub async fn trigger_integrations_by_type(
    integration_type: &str,
    subject: &str,
    message: &str,
) -> anyhow::Result<Vec<(String, Result<()>)>> {
    use futures::future::join_all;

    let storage = get_integration_storage().context("Notifier storage not initialized")?;

    let all_notifiers = storage
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list integrations: {}", e))?;

    let filtered: Vec<_> = all_notifiers
        .into_iter()
        .filter(|n| {
            n.integration_type == integration_type
                && n.status == "active"
                && !super::audit_integration_triggers::is_audit_integration(n)
        })
        .collect();

    let variables = std::collections::HashMap::new(); // Empty variables for this API

    // Get the publisher from the registry
    let publisher = INTEGRATION_REGISTRY
        .get(integration_type)
        .ok_or_else(|| anyhow::anyhow!("Unknown integration type: {}", integration_type))?;

    let subject = subject.to_string();
    let message = message.to_string();

    // Execute all integrations in parallel
    let tasks: Vec<_> = filtered
        .into_iter()
        .map(|integration| {
            let publisher = publisher.clone();
            let subject = subject.clone();
            let message = message.to_string();
            let variables = variables.clone();
            let integration_id = integration.id.clone();

            tokio::spawn(async move {
                let result = publisher
                    .publish(&integration, &subject, &message, &variables)
                    .await;
                (integration_id, result.map_err(IntegrationError::PublisherError))
            })
        })
        .collect();

    // Wait for all tasks to complete
    let results = join_all(tasks).await;

    Ok(results
        .into_iter()
        .map(|r| {
            r.unwrap_or_else(|e| {
                ("unknown".to_string(), Err(IntegrationError::PublisherError(anyhow::anyhow!("Task panicked: {}", e))))
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{IntegrationError, is_transient_publish_error, refuse_audit_integration, retry_delays};

    #[test]
    fn transient_failures_back_off_one_two_four_eight_sixteen_seconds() {
        let seconds: Vec<u64> = retry_delays()
            .map(|delay| delay.as_secs())
            .collect();
        assert_eq!(seconds, vec![1, 2, 4, 8, 16]);
    }

    #[test]
    fn only_transient_publish_errors_are_retried() {
        for (message, transient) in [
            ("Webhook failed: 503 Service Unavailable - down", true),
            ("Slack webhook failed: 429 Too Many Requests - slow down", true),
            ("Webhook failed: 500 Internal Server Error - {\"error\":\"x\"}", true),
            ("Webhook failed: 401 Unauthorized - {\"error\":\"connection refused\"}", false),
            ("Webhook failed: 404 Not Found - missing", false),
            ("Kafka produce timed out", true),
            ("SMTP connection reset", true),
            ("Missing url in webhook configuration", false),
        ] {
            assert_eq!(is_transient_publish_error(&anyhow::anyhow!("{message}")), transient, "{message}");
        }
    }
    use crate::storage::Integration;

    fn integration(category: Option<&str>) -> Integration {
        Integration::new(
            "Sink".to_string(),
            String::new(),
            "webhook".to_string(),
            serde_json::json!({}),
            serde_json::json!({}),
            "active".to_string(),
            category.map(str::to_string),
        )
    }

    #[test]
    fn event_triggers_cannot_publish_to_an_audit_integration() {
        let audit = integration(Some("audit"));
        assert!(matches!(refuse_audit_integration(&audit), Err(IntegrationError::AuditOnly(id)) if id == audit.id));
    }

    #[test]
    fn event_triggers_publish_to_other_integrations() {
        for category in [None, Some("general"), Some("connection_point"), Some("surface")] {
            assert!(refuse_audit_integration(&integration(category)).is_ok(), "{category:?}");
        }
    }
}
