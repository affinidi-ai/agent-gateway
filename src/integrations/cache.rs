use crate::storage::Integration;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

lazy_static::lazy_static! {
    /// Cache for parsed integrations with 5-minute TTL
    pub static ref INTEGRATION_CACHE: Cache<String, Arc<Integration>> =
        Cache::builder()
            .max_capacity(1000)
            .time_to_live(Duration::from_secs(300))
            .build();
}

/// Get integration from cache or load from storage
pub async fn get_cached_integration(integration_id: &str) -> Result<Arc<Integration>, String> {
    use crate::storage::get_integration_storage;

    // Try cache first
    if let Some(integration) = INTEGRATION_CACHE
        .get(integration_id)
        .await
    {
        return Ok(integration);
    }

    // Load from storage
    let storage = get_integration_storage().ok_or_else(|| "Integration storage not initialized".to_string())?;

    let integration = storage
        .load(integration_id)
        .await
        .map_err(|e| e.to_string())?;
    let arc_integration = Arc::new(integration);

    // Store in cache
    INTEGRATION_CACHE
        .insert(integration_id.to_string(), arc_integration.clone())
        .await;

    Ok(arc_integration)
}

/// Invalidate cache entry for an integration
pub async fn invalidate_integration_cache(integration_id: &str) {
    INTEGRATION_CACHE
        .invalidate(integration_id)
        .await;
    crate::integrations::stream_publishers::invalidate_kafka_producer(integration_id).await;
    crate::integrations::audit_integration_triggers::invalidate_subscribers();
}

/// Clear all cached integrations
#[allow(dead_code)]
pub async fn clear_integration_cache() {
    INTEGRATION_CACHE.invalidate_all();
}
