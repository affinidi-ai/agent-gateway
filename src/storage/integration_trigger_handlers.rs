use axum::{Extension, Json, extract::Path, http::StatusCode, response::IntoResponse};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::integrations::audit_integration_triggers::is_audit_integration;
use crate::integrations::integration_service::trigger_authorized_integration;
use crate::integrations::stream_publishers::PUBLISHER_REGISTRY;
use crate::integrations::trigger_integrations;
use crate::storage::integration_handlers::AuditCaller;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

/// Global storage for variable pattern from config
static VARIABLE_PATTERN: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(r"\$\{([^:}]+)(?::[^}]+)?\}".to_string()));

/// Update the variable pattern from config (called during startup)
pub fn set_variable_pattern(pattern: String) {
    if let Ok(mut p) = VARIABLE_PATTERN.write() {
        *p = pattern;
    }
}

/// Substitute template variables in a string
fn substitute_variables(
    template: &str,
    variables: &std::collections::HashMap<String, String>,
) -> String {
    let mut result = template.to_string();

    // Get pattern from global config
    let pattern = VARIABLE_PATTERN
        .read()
        .unwrap()
        .clone();
    let re = regex::Regex::new(&pattern).unwrap();
    for cap in re.captures_iter(template) {
        let var_name = cap[1].trim();
        let placeholder = &cap[0];

        if let Some(value) = crate::integrations::runtime_variables::variable_value(var_name, variables) {
            result = result.replace(placeholder, &value);
        }
    }

    result
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TriggerNotifierRequest {
    pub subject: String,
    pub message: String,
    #[serde(default)]
    pub variables: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TriggerNotifiersRequest {
    pub integration_ids: Vec<String>,
    pub subject: String,
    pub message: String,
    #[serde(default)]
    pub variables: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct TriggerResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct TriggerMultipleResponse {
    pub results: Vec<IntegrationResult>,
}

#[derive(Debug, Serialize)]
pub struct IntegrationResult {
    pub integration_id: String,
    pub success: bool,
    pub error: Option<String>,
}

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

async fn require_integration_access(
    storage: &crate::storage::IntegrationStorage,
    integration_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    audit_caller: &AuditCaller<'_>,
) -> Result<(), (StatusCode, String)> {
    let integration = storage
        .load(integration_id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Integration not found".to_string()))?;
    if !can_access(
        integration
            .tenant_id
            .as_deref(),
        tenant_context(context),
    ) || !scope_allows_resource(
        resource_scope(scope),
        tenant_context(context),
        ResourceKind::Integrations,
        &integration.id,
    ) {
        return Err((StatusCode::FORBIDDEN, "Integration is outside this token's permitted scope".to_string()));
    }
    if is_audit_integration(&integration) {
        audit_caller
            .require_audit_access()
            .await?;
    }
    Ok(())
}

/// Trigger a single integration by ID
pub async fn trigger_integration_handler(
    Extension(storage): Extension<Arc<crate::storage::IntegrationStorage>>,
    Path(integration_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
    Json(payload): Json<TriggerNotifierRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let audit_caller = AuditCaller::new(&guard, &caller, &pat);
    require_integration_access(storage.as_ref(), &integration_id, &context, &scope, &audit_caller).await?;
    match trigger_authorized_integration(&integration_id, &payload.subject, &payload.message, &payload.variables).await
    {
        Ok(_) => Ok((
            StatusCode::OK,
            Json(TriggerResponse {
                success: true,
                message: format!("Notifier {} triggered successfully", integration_id),
            }),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to trigger integration: {}", e))),
    }
}

/// Trigger multiple integrations
pub async fn trigger_multiple_notifiers_handler(
    Extension(storage): Extension<Arc<crate::storage::IntegrationStorage>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
    Json(payload): Json<TriggerNotifiersRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let audit_caller = AuditCaller::new(&guard, &caller, &pat);
    for integration_id in &payload.integration_ids {
        require_integration_access(storage.as_ref(), integration_id, &context, &scope, &audit_caller).await?;
    }
    let results = trigger_integrations(&payload.integration_ids, &payload.subject, &payload.message)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to trigger integrations: {}", e)))?;

    let integration_results: Vec<IntegrationResult> = results
        .into_iter()
        .map(|(integration_id, result)| IntegrationResult {
            integration_id,
            success: result.is_ok(),
            error: result
                .err()
                .map(|e| e.to_string()),
        })
        .collect();

    Ok((StatusCode::OK, Json(TriggerMultipleResponse { results: integration_results })))
}

/// Test a integration configuration without saving it
#[derive(Debug, Deserialize)]
pub struct TestNotifierRequest {
    #[serde(rename = "type")]
    pub integration_type: String,
    pub configuration: serde_json::Value,
    pub content: serde_json::Value,
    #[serde(default)]
    pub variables: std::collections::HashMap<String, String>,
}

pub async fn test_notifier_handler(
    Json(payload): Json<TestNotifierRequest>
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use crate::integrations::email_service::{SmtpConfig, send_email};

    tracing::info!("Test integration handler called for type: {}", payload.integration_type);
    tracing::debug!("Test integration configuration: {:?}", payload.configuration);
    tracing::debug!("Test integration content: {:?}", payload.content);

    match payload
        .integration_type
        .as_str()
    {
        "email" => {
            tracing::info!("Testing email integration");

            let smtp_config = SmtpConfig::from_json(&payload.configuration).map_err(|e| {
                tracing::error!("Invalid SMTP configuration: {}", e);
                (StatusCode::BAD_REQUEST, format!("Invalid SMTP configuration: {}", e))
            })?;

            tracing::info!("SMTP config parsed, sending test email...");

            // Use content template if provided
            let subject_template = payload
                .content
                .get("subject")
                .and_then(|v| v.as_str())
                .unwrap_or("Test Notification from Agent Gateway");

            let body_template = payload
                .content
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("This is a test email to verify your SMTP configuration is working correctly.");

            // Perform template variable substitution
            let subject = substitute_variables(subject_template, &payload.variables);
            let body = substitute_variables(body_template, &payload.variables);

            // Check format from content, default to plain text
            let format = payload
                .content
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("plain");

            let is_html = format == "html" || body.contains("<html") || body.contains("<body");

            send_email(&smtp_config, &subject, &body, is_html)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to send test email: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send test email: {}", e))
                })?;

            tracing::info!("Test email sent successfully");

            Ok((
                StatusCode::OK,
                Json(TriggerResponse {
                    success: true,
                    message: "Test email sent successfully".to_string(),
                }),
            ))
        }
        "slack" => {
            tracing::info!("Testing Slack integration");

            let webhook_url = payload.configuration["webhook_url"]
                .as_str()
                .ok_or_else(|| {
                    tracing::error!("Missing webhook_url in Slack configuration");
                    (StatusCode::BAD_REQUEST, "Missing webhook_url in Slack configuration".to_string())
                })?;

            tracing::info!("Webhook URL found: {}", webhook_url);

            // Use content template if provided
            let text_template = if let Some(template_text) = payload
                .content
                .get("text")
                .and_then(|v| v.as_str())
            {
                template_text.to_string()
            } else {
                "*Test Notification from Agent Gateway*\nYour Slack integration is configured correctly! 🎉".to_string()
            };

            // Perform template variable substitution
            let text = substitute_variables(&text_template, &payload.variables);

            let bot_name = payload
                .content
                .get("bot_name")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    payload
                        .configuration
                        .get("bot_name")
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("Agent Gateway");

            let icon_emoji = payload
                .content
                .get("icon_emoji")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    payload
                        .configuration
                        .get("icon_emoji")
                        .and_then(|v| v.as_str())
                })
                .unwrap_or(":robot_face:");

            // Build test Slack message payload
            let mut slack_payload = serde_json::json!({
                "text": text,
                "username": bot_name,
                "icon_emoji": icon_emoji
            });

            // Add channel if specified in content
            if let Some(channel) = payload
                .content
                .get("channel")
                .and_then(|v| v.as_str())
            {
                slack_payload["channel"] = serde_json::json!(channel);
            }

            tracing::debug!("Slack payload: {:?}", slack_payload);
            tracing::info!("Sending HTTP POST to Slack webhook URL: {}", webhook_url);

            // Send HTTP POST to Slack webhook with timeout
            let client = crate::http_client::external().map_err(|e| {
                tracing::error!("Failed to build HTTP client: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build HTTP client: {}", e))
            })?;

            let response = client
                .post(webhook_url)
                .json(&slack_payload)
                .send()
                .await
                .map_err(|e| {
                    tracing::error!(
                        "Failed to send Slack webhook: {} (is_timeout: {}, is_connect: {}, is_request: {})",
                        e,
                        e.is_timeout(),
                        e.is_connect(),
                        e.is_request()
                    );
                    if let Some(url_error) = e.url() {
                        tracing::error!("URL that failed: {}", url_error);
                    }
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "Failed to send Slack webhook: {} (timeout: {}, connect: {})",
                            e,
                            e.is_timeout(),
                            e.is_connect()
                        ),
                    )
                })?;

            tracing::info!("Slack webhook response status: {}", response.status());

            if response.status().is_success() {
                tracing::info!("Test Slack notification sent successfully");
                Ok((
                    StatusCode::OK,
                    Json(TriggerResponse {
                        success: true,
                        message: "Test Slack notification sent successfully".to_string(),
                    }),
                ))
            } else {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_default();
                tracing::error!("Slack webhook failed with status {}: {}", status, body);
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Slack webhook failed with status {}: {}", status, body),
                ))
            }
        }
        "webhook" => {
            tracing::info!("Testing webhook integration");

            // Get webhook URL from configuration
            let webhook_url = payload.configuration["url"]
                .as_str()
                .ok_or_else(|| {
                    tracing::error!("Missing url in webhook configuration");
                    (StatusCode::BAD_REQUEST, "Missing url in webhook configuration".to_string())
                })?;

            let method = payload
                .configuration
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("POST")
                .to_uppercase();

            let signing_secret = payload
                .configuration
                .get("signing_secret")
                .and_then(|v| v.as_str());

            // Build test payload from content template with test variables
            let test_payload = if !payload.content.is_null() && payload.content.is_object() {
                payload.content.clone()
            } else {
                // Default test payload
                serde_json::json!({
                    "subject": "Test Notification",
                    "message": "*Test Notification from Agent Gateway*\nYour webhook integration is configured correctly! 🎉",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "test": true
                })
            };

            // Substitute variables in the test payload
            let payload_str = serde_json::to_string(&test_payload)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize payload: {}", e)))?;

            // Perform variable substitution
            let substituted_payload_str = substitute_variables(&payload_str, &payload.variables);

            let final_payload: serde_json::Value = serde_json::from_str(&substituted_payload_str).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse substituted payload: {}", e))
            })?;

            let payload_json = serde_json::to_string(&final_payload).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize final payload: {}", e))
            })?;

            tracing::debug!("Webhook payload: {:?}", final_payload);
            tracing::info!("Sending HTTP {} to webhook URL: {}", method, webhook_url);

            // Send HTTP request to webhook with timeout
            let client = crate::http_client::external()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build HTTP client: {}", e)))?;

            let mut request = match method.as_str() {
                "POST" => client.post(webhook_url),
                "PUT" => client.put(webhook_url),
                "PATCH" => client.patch(webhook_url),
                _ => {
                    return Err((StatusCode::BAD_REQUEST, format!("Unsupported HTTP method: {}", method)));
                }
            };

            // Add timestamp header
            let timestamp = chrono::Utc::now()
                .timestamp()
                .to_string();
            request = request.header("X-Webhook-Timestamp", &timestamp);

            // Add HMAC signature if signing secret is provided
            if let Some(secret) = signing_secret {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;

                let signed_content = format!("{}.{}", timestamp, payload_json);

                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid HMAC key: {}", e)))?;
                mac.update(signed_content.as_bytes());
                let signature = mac.finalize();
                let signature_hex = hex::encode(signature.into_bytes());

                request = request.header("X-Webhook-Signature-256", format!("sha256={}", signature_hex));

                tracing::info!("Added HMAC-SHA256 signature to test webhook request");
            }

            // Add custom headers if provided
            if let Some(headers) = payload
                .configuration
                .get("headers")
                .and_then(|v| v.as_object())
            {
                for (key, value) in headers {
                    if let Some(value_str) = value.as_str() {
                        // Substitute variables in header values
                        let substituted_value = substitute_variables(value_str, &payload.variables);
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
                    tracing::error!(
                        "Failed to send webhook: {} (is_timeout: {}, is_connect: {}, is_request: {})",
                        e,
                        e.is_timeout(),
                        e.is_connect(),
                        e.is_request()
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "Failed to send webhook: {} (timeout: {}, connect: {})",
                            e,
                            e.is_timeout(),
                            e.is_connect()
                        ),
                    )
                })?;

            tracing::info!("Webhook response status: {}", response.status());

            if response.status().is_success() {
                tracing::info!("Test webhook notification sent successfully");
                Ok((
                    StatusCode::OK,
                    Json(TriggerResponse {
                        success: true,
                        message: "Test webhook notification sent successfully".to_string(),
                    }),
                ))
            } else {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_default();
                tracing::error!("Webhook failed with status {}: {}", status, body);
                Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Webhook failed with status {}: {}", status, body)))
            }
        }
        "stream" => {
            tracing::info!("Testing stream integration");

            let platform = payload.configuration["platform"]
                .as_str()
                .ok_or_else(|| {
                    tracing::error!("Missing platform in stream configuration");
                    (StatusCode::BAD_REQUEST, "Missing platform in stream configuration".to_string())
                })?;

            let topic = payload.configuration["topic"]
                .as_str()
                .ok_or_else(|| {
                    tracing::error!("Missing topic in stream configuration");
                    (StatusCode::BAD_REQUEST, "Missing topic in stream configuration".to_string())
                })?;

            // Build test event payload from content template
            let test_event = if !payload.content.is_null() && payload.content.is_object() {
                payload.content.clone()
            } else {
                serde_json::json!({
                    "event_type": "test.notification",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "message": "Test event from Agent Gateway",
                    "test": true
                })
            };

            // Substitute variables in the test event
            let event_str = serde_json::to_string(&test_event)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize event: {}", e)))?;

            let substituted_event_str = substitute_variables(&event_str, &payload.variables);

            let final_event: serde_json::Value = serde_json::from_str(&substituted_event_str).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse substituted event: {}", e))
            })?;

            tracing::info!("Stream platform: {}, topic: {}", platform, topic);
            tracing::debug!("Test event payload: {:?}", final_event);

            // Get the publisher from the registry
            let publisher = PUBLISHER_REGISTRY
                .get(platform)
                .ok_or_else(|| {
                    tracing::error!("Unknown stream platform: {}", platform);
                    (StatusCode::BAD_REQUEST, format!("Unknown stream platform: {}", platform))
                })?;

            // Use the publisher to test the connection
            let message = publisher
                .test_connection(topic, &final_event, &payload.configuration)
                .await
                .map_err(|e| {
                    tracing::error!("Stream test failed: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Stream test failed: {}", e))
                })?;

            Ok((StatusCode::OK, Json(TriggerResponse { success: true, message })))
        }
        _ => {
            tracing::error!("Unknown integration type: {}", payload.integration_type);
            Err((StatusCode::BAD_REQUEST, format!("Unknown integration type: {}", payload.integration_type)))
        }
    }
}
