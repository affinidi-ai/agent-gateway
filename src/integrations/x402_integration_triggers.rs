use std::collections::HashMap;

use super::delivery::dispatch::dispatch;

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
