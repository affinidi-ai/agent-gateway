use std::collections::HashMap;
use tracing::{error, info};

/// Trigger integrations when an MPP payment verification fails
pub async fn trigger_mpp_verification_failed(
    surface_id: &str,
    surface_name: &str,
    payment_method: &str,
    resource_url: &str,
    error_message: &str,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("EVENT_TYPE".to_string(), "mpp.verification.failed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("SURFACE_ID".to_string(), surface_id.to_string());
    runtime_values.insert("SURFACE_NAME".to_string(), surface_name.to_string());
    runtime_values.insert("PAYMENT_METHOD".to_string(), payment_method.to_string());
    runtime_values.insert("RESOURCE_URL".to_string(), resource_url.to_string());
    runtime_values.insert("ERROR_MESSAGE".to_string(), error_message.to_string());
    runtime_values.insert("SEVERITY".to_string(), "error".to_string());

    trigger_mpp_integrations(&runtime_values, "mpp.verification.failed").await;
}

/// Trigger integrations when an MPP payment is verified successfully
pub async fn trigger_mpp_payment_verified(
    surface_id: &str,
    surface_name: &str,
    payment_method: &str,
    resource_url: &str,
    reference: &str,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("EVENT_TYPE".to_string(), "mpp.payment.verified".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("SURFACE_ID".to_string(), surface_id.to_string());
    runtime_values.insert("SURFACE_NAME".to_string(), surface_name.to_string());
    runtime_values.insert("PAYMENT_METHOD".to_string(), payment_method.to_string());
    runtime_values.insert("RESOURCE_URL".to_string(), resource_url.to_string());
    runtime_values.insert("REFERENCE".to_string(), reference.to_string());
    runtime_values.insert("SEVERITY".to_string(), "info".to_string());

    trigger_mpp_integrations(&runtime_values, "mpp.payment.verified").await;
}

/// Trigger integrations when an MPP 402 challenge is issued
pub async fn trigger_mpp_challenge_issued(
    surface_id: &str,
    surface_name: &str,
    resource_url: &str,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("EVENT_TYPE".to_string(), "mpp.challenge.issued".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("SURFACE_ID".to_string(), surface_id.to_string());
    runtime_values.insert("SURFACE_NAME".to_string(), surface_name.to_string());
    runtime_values.insert("RESOURCE_URL".to_string(), resource_url.to_string());
    runtime_values.insert("SEVERITY".to_string(), "info".to_string());

    trigger_mpp_integrations(&runtime_values, "mpp.challenge.issued").await;
}

/// Internal helper to trigger integrations with the 'mpp' category
async fn trigger_mpp_integrations(
    runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    // Get integration storage to list all integrations
    let storage = match crate::storage::get_integration_storage() {
        Some(storage) => storage,
        None => {
            error!("Integration storage not initialized for {}", event_type);
            return;
        }
    };

    // Get all integrations
    let integrations = match storage.list().await {
        Ok(integrations) => integrations,
        Err(e) => {
            error!("Failed to list integrations for {}: {}", event_type, e);
            return;
        }
    };

    // Filter for 'mpp' category integrations
    let mpp_integrations: Vec<_> = integrations
        .into_iter()
        .filter(|i| i.status == "active" && i.category.as_deref() == Some("mpp"))
        .collect();

    if mpp_integrations.is_empty() {
        info!("No active mpp integrations configured for {}", event_type);
        return;
    }

    info!("Triggering {} mpp integrations for event: {}", mpp_integrations.len(), event_type);

    // Execute each integration
    for integration in mpp_integrations {
        let subject = format!("MPP Event: {}", event_type);
        let message = format!("MPP payment event '{}' occurred", event_type);

        if let Err(e) = crate::integrations::integration_service::trigger_integration_with_variables(
            &integration.id,
            &subject,
            &message,
            runtime_values,
        )
        .await
        {
            error!("Failed to execute integration {} for {}: {}", integration.id, event_type, e);
        } else {
            info!("Successfully executed integration {} ({}) for {}", integration.id, integration.name, event_type);
        }
    }
}
