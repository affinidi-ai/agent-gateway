use std::collections::HashMap;

use super::delivery::dispatch::dispatch;

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

    dispatch("x402.verification.failed", runtime_values);
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

    dispatch("x402.settlement.failed", runtime_values);
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

    dispatch("x402.cleanup.completed", runtime_values);
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

    dispatch("x402.transaction.completed", runtime_values);
}
