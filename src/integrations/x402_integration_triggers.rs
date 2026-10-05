use std::collections::HashMap;
use tracing::{error, info};

/// Trigger integrations when a transaction fails verification
pub async fn trigger_transaction_verification_failed(
    correlation_id: &str,
    surface_id: &str,
    tx_hash: &str,
    error_message: &str,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("EVENT_TYPE".to_string(), "x402.verification.failed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("CORRELATION_ID".to_string(), correlation_id.to_string());
    runtime_values.insert("SURFACE_ID".to_string(), surface_id.to_string());
    runtime_values.insert("TX_HASH".to_string(), tx_hash.to_string());
    runtime_values.insert("ERROR_MESSAGE".to_string(), error_message.to_string());
    runtime_values.insert("SEVERITY".to_string(), "error".to_string());

    trigger_x402_integrations(&runtime_values, "x402.verification.failed").await;
}

/// Trigger integrations when a transaction fails settlement
pub async fn trigger_transaction_settlement_failed(
    correlation_id: &str,
    surface_id: &str,
    tx_hash: &str,
    settlement_method: &str,
    error_message: &str,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("EVENT_TYPE".to_string(), "x402.settlement.failed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("CORRELATION_ID".to_string(), correlation_id.to_string());
    runtime_values.insert("SURFACE_ID".to_string(), surface_id.to_string());
    runtime_values.insert("TX_HASH".to_string(), tx_hash.to_string());
    runtime_values.insert("SETTLEMENT_METHOD".to_string(), settlement_method.to_string());
    runtime_values.insert("ERROR_MESSAGE".to_string(), error_message.to_string());
    runtime_values.insert("SEVERITY".to_string(), "error".to_string());

    trigger_x402_integrations(&runtime_values, "x402.settlement.failed").await;
}

/// Trigger integrations when transaction cleanup completes
pub async fn trigger_cleanup_completed(
    transactions_deleted: usize,
    retention_days: i64,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("EVENT_TYPE".to_string(), "x402.cleanup.completed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("TRANSACTIONS_DELETED".to_string(), transactions_deleted.to_string());
    runtime_values.insert("RETENTION_DAYS".to_string(), retention_days.to_string());
    runtime_values.insert("SEVERITY".to_string(), "info".to_string());

    trigger_x402_integrations(&runtime_values, "x402.cleanup.completed").await;
}

/// Trigger integrations when a transaction completes successfully
pub async fn trigger_transaction_completed(
    correlation_id: &str,
    surface_id: &str,
    tx_hash: &str,
    amount: &str,
    network: &str,
    settlement_method: &str,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("EVENT_TYPE".to_string(), "x402.transaction.completed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("CORRELATION_ID".to_string(), correlation_id.to_string());
    runtime_values.insert("SURFACE_ID".to_string(), surface_id.to_string());
    runtime_values.insert("TX_HASH".to_string(), tx_hash.to_string());
    runtime_values.insert("AMOUNT".to_string(), amount.to_string());
    runtime_values.insert("NETWORK".to_string(), network.to_string());
    runtime_values.insert("SETTLEMENT_METHOD".to_string(), settlement_method.to_string());
    runtime_values.insert("SEVERITY".to_string(), "info".to_string());

    trigger_x402_integrations(&runtime_values, "x402.transaction.completed").await;
}

/// Internal helper to trigger integrations with the 'x402' category
async fn trigger_x402_integrations(
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

    // Filter for 'x402' category integrations
    let x402_integrations: Vec<_> = integrations
        .into_iter()
        .filter(|i| i.status == "active" && i.category.as_deref() == Some("x402"))
        .collect();

    if x402_integrations.is_empty() {
        info!("No active x402 integrations configured for {}", event_type);
        return;
    }

    info!("Triggering {} x402 integrations for event: {}", x402_integrations.len(), event_type);

    // Execute each integration
    for integration in x402_integrations {
        // Build subject and message from event
        let subject = format!("X402 Event: {}", event_type);
        let message = format!("X402 payment event '{}' occurred", event_type);

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
