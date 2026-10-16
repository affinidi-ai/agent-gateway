use std::collections::HashMap;

use super::delivery::dispatch::dispatch;

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

    dispatch("mpp.verification.failed", runtime_values);
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

    dispatch("mpp.payment.verified", runtime_values);
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

    dispatch("mpp.challenge.issued", runtime_values);
}
