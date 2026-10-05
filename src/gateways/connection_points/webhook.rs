//! Webhook delivery for connection point messages

use serde_json::json;
use tracing::{debug, info, warn};

use super::messages::ReceivedMessage;
use super::types::GatewayConnectionPoint;

/// Webhook delivery client
#[derive(Clone)]
pub struct WebhookClient {}

impl WebhookClient {
    /// Create a new webhook client
    pub fn new() -> Self {
        Self {}
    }

    /// Trigger integration for a received message
    /// Supports integrations array (preferred) and single integration_id (fallback)
    pub async fn trigger_integration(
        &self,
        connection_point: &GatewayConnectionPoint,
        message: &ReceivedMessage,
    ) -> Result<(), String> {
        // Try integrations array first (preferred method - supports multiple)
        if !connection_point
            .integrations
            .is_empty()
        {
            return self
                .trigger_all_notifiers(connection_point, message)
                .await;
        }

        // Fall back to single integration_id (legacy)
        if let Some(integration_id) = &connection_point.integration_id {
            return self
                .trigger_integration_by_id(
                    integration_id,
                    connection_point,
                    message,
                    &connection_point.integration_variables,
                )
                .await;
        }

        // No integration configured
        debug!("No integration configured for connection point '{}'", connection_point.name);
        Ok(())
    }

    /// Trigger all integrations configured for this connection point
    /// integrations are triggered in parallel as background tasks (fire-and-forget)
    async fn trigger_all_notifiers(
        &self,
        connection_point: &GatewayConnectionPoint,
        message: &ReceivedMessage,
    ) -> Result<(), String> {
        info!(
            "Triggering {} integration(s) for connection point '{}'",
            connection_point
                .integrations
                .len(),
            connection_point.name
        );

        // Spawn integration tasks in parallel (fire-and-forget)
        for integration_integration in &connection_point.integrations {
            let integration_id = integration_integration
                .integration_id
                .clone();
            let cp_name = connection_point.name.clone();
            let variables =
                self.build_template_variables(connection_point, message, &integration_integration.variables);

            let subject = format!("Message on {}", connection_point.name);
            let message_body = format!(
                "Connection Point: {}\nFrom: {}\nType: {}\nMessage ID: {}\nReceived: {}\n\nMessage Body:\n{}",
                connection_point.name,
                message
                    .from_did
                    .as_deref()
                    .unwrap_or("Unknown"),
                message.message_type,
                message.id,
                message
                    .received_at
                    .to_rfc3339(),
                serde_json::to_string_pretty(&message.message_body).unwrap_or_default()
            );

            // Spawn async task to trigger integration without blocking
            crate::observability::spawn_traced_task(&format!("integration.webhook.{}", integration_id), async move {
                use crate::integrations::integration_service;

                match integration_service::trigger_integration_with_variables(
                    &integration_id,
                    &subject,
                    &message_body,
                    &variables,
                )
                .await
                {
                    Ok(_) => {
                        info!("✓ integration '{}' for CP '{}' triggered successfully", integration_id, cp_name);
                    }
                    Err(e) => {
                        warn!("✗ integration '{}' for CP '{}' failed: {}", integration_id, cp_name, e);
                    }
                }
            });
        }

        info!(
            "Spawned {} integration task(s) in background",
            connection_point
                .integrations
                .len()
        );
        Ok(())
    }

    /// Trigger a integration by ID (legacy single integration support)
    /// Spawned as background task (fire-and-forget) for runtime triggers
    async fn trigger_integration_by_id(
        &self,
        integration_id: &str,
        connection_point: &GatewayConnectionPoint,
        message: &ReceivedMessage,
        integration_variables: &serde_json::Value,
    ) -> Result<(), String> {
        use crate::integrations::integration_service;

        info!("Triggering integration '{}' for connection point '{}'", integration_id, connection_point.name);

        // Build template variables for substitution
        let variables = self.build_template_variables(connection_point, message, integration_variables);

        // Subject and message body are fallbacks if the integration doesn't have content templates
        let subject = format!("Message on {}", connection_point.name);
        let message_body = format!(
            "Connection Point: {}\nFrom: {}\nType: {}\nMessage ID: {}\nReceived: {}\n\nMessage Body:\n{}",
            connection_point.name,
            message
                .from_did
                .as_deref()
                .unwrap_or("Unknown"),
            message.message_type,
            message.id,
            message
                .received_at
                .to_rfc3339(),
            serde_json::to_string_pretty(&message.message_body).unwrap_or_default()
        );

        let integration_id = integration_id.to_string();
        let cp_name = connection_point.name.clone();

        // Spawn async task to trigger integration without blocking
        crate::observability::spawn_traced_task(&format!("integration.webhook.{}", integration_id), async move {
            match integration_service::trigger_integration_with_variables(
                &integration_id,
                &subject,
                &message_body,
                &variables,
            )
            .await
            {
                Ok(_) => {
                    info!("✓ integration '{}' for CP '{}' triggered successfully", integration_id, cp_name);
                }
                Err(e) => {
                    warn!("✗ integration '{}' for CP '{}' failed: {}", integration_id, cp_name, e);
                }
            }
        });

        info!("Spawned integration task in background");
        Ok(())
    }

    /// Build template variables map from connection point and message data
    fn build_template_variables(
        &self,
        connection_point: &GatewayConnectionPoint,
        message: &ReceivedMessage,
        integration_variables: &serde_json::Value,
    ) -> std::collections::HashMap<String, String> {
        let runtime_vars = self.build_runtime_variables(connection_point, message);

        let mut variables = std::collections::HashMap::new();

        // Add runtime variables
        for (key, value) in runtime_vars.iter() {
            if let Some(val_str) = value.as_str() {
                variables.insert(key.clone(), val_str.to_string());
            } else {
                variables.insert(key.clone(), value.to_string());
            }
        }

        // Add user-provided variables (can override runtime variables)
        // Resolve any runtime variable references in user variable values
        // Compile regex once outside the loop
        let re = regex::Regex::new(r"^\$\{([^:}]+)(?::[^}]*)?\}$").unwrap();
        if let Some(obj) = integration_variables.as_object() {
            for (key, value) in obj.iter() {
                let resolved_value = if let Some(val_str) = value.as_str() {
                    // Check if the value is a runtime variable reference like ${CP_NAME} or ${CP_NAME:Connection Point Name}
                    // The part after the colon is just a human-readable label and should be removed
                    // Use flexible pattern to match any variable name
                    if let Some(cap) = re.captures(val_str) {
                        let var_name = cap[1].trim();
                        // Try to resolve from runtime variables
                        if let Some(runtime_val) = runtime_vars.get(var_name) {
                            if let Some(runtime_str) = runtime_val.as_str() {
                                runtime_str.to_string()
                            } else {
                                runtime_val.to_string()
                            }
                        } else {
                            // Runtime variable not found, keep original value
                            val_str.to_string()
                        }
                    } else {
                        val_str.to_string()
                    }
                } else {
                    value.to_string()
                };

                variables.insert(key.clone(), resolved_value);
            }
        }

        variables
    }

    /// Substitute template variables in a string
    #[allow(dead_code)]
    fn substitute_string(
        &self,
        template: &str,
        connection_point: &GatewayConnectionPoint,
        message: &ReceivedMessage,
    ) -> String {
        let runtime_vars = self.build_runtime_variables(connection_point, message);
        let user_vars = &connection_point.integration_variables;

        let mut result = template.to_string();

        // Find all $VARIABLE patterns (legacy format)
        // Allow alphanumeric and underscores for legacy $VAR format (already updated to be permissive)
        let re = regex::Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").unwrap();
        for cap in re.captures_iter(template) {
            let var_name = cap[1].trim();
            let placeholder = &cap[0];

            // Try runtime variables first, then user-provided variables
            if let Some(var_value) = runtime_vars.get(var_name) {
                if let Some(val_str) = var_value.as_str() {
                    result = result.replace(placeholder, val_str);
                } else {
                    result = result.replace(placeholder, &var_value.to_string());
                }
            } else if let Some(var_value) = user_vars.get(var_name) {
                if let Some(val_str) = var_value.as_str() {
                    result = result.replace(placeholder, val_str);
                } else {
                    result = result.replace(placeholder, &var_value.to_string());
                }
            }
        }

        result
    }

    /// Build map of runtime variables from connection point and message data
    fn build_runtime_variables(
        &self,
        connection_point: &GatewayConnectionPoint,
        message: &ReceivedMessage,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut vars = serde_json::Map::new();

        // Connection point variables
        vars.insert("CP_NAME".to_string(), json!(connection_point.name));
        vars.insert("CP_ID".to_string(), json!(connection_point.id));
        vars.insert("CP_DESCRIPTION".to_string(), json!(connection_point.description));
        vars.insert("GATEWAY_ID".to_string(), json!(connection_point.gateway_id));
        // GATEWAY defaults to GATEWAY_ID if not provided (can be overridden by user variables)
        vars.insert("GATEWAY".to_string(), json!(connection_point.gateway_id));
        vars.insert("MEDIATOR_ID".to_string(), json!(connection_point.mediator_id));

        // Message variables
        vars.insert("MESSAGE_ID".to_string(), json!(message.id));
        vars.insert("MESSAGE_TYPE".to_string(), json!(message.message_type));
        vars.insert("FROM_DID".to_string(), json!(message.from_did));
        vars.insert("MESSAGE_BODY".to_string(), message.message_body.clone());
        vars.insert(
            "RECEIVED_AT".to_string(),
            json!(
                message
                    .received_at
                    .to_rfc3339()
            ),
        );

        // Timestamp variables
        let now = chrono::Utc::now();
        vars.insert("TIMESTAMP".to_string(), json!(now.to_rfc3339()));
        vars.insert(
            "DATE".to_string(),
            json!(
                now.format("%Y-%m-%d")
                    .to_string()
            ),
        );
        vars.insert(
            "TIME".to_string(),
            json!(
                now.format("%H:%M:%S")
                    .to_string()
            ),
        );
        vars.insert(
            "DATETIME".to_string(),
            json!(
                now.format("%Y-%m-%d %H:%M:%S")
                    .to_string()
            ),
        );

        vars
    }
}

impl Default for WebhookClient {
    fn default() -> Self {
        Self::new()
    }
}
