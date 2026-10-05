use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::handlers::SurfaceInfo;

/// Cached channel information for a gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedGatewayChannels {
    pub gateway_id: String,
    pub channels: Vec<SurfaceInfo>,
    pub cached_at: chrono::DateTime<chrono::Utc>,
    pub last_error: Option<String>,
}

/// Global cache for gateway channels
pub struct GatewaySurfaceCache {
    cache: Arc<RwLock<HashMap<String, CachedGatewayChannels>>>,
    refresh_in_progress: Arc<AtomicBool>,
    last_refresh_time: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl GatewaySurfaceCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            refresh_in_progress: Arc::new(AtomicBool::new(false)),
            last_refresh_time: Arc::new(RwLock::new(None)),
        }
    }

    /// Try to acquire the refresh lock
    /// Returns true if lock was acquired, false if refresh is already in progress
    pub fn try_acquire_refresh_lock(&self) -> bool {
        self.refresh_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Release the refresh lock and update last refresh time
    pub async fn release_refresh_lock(&self) {
        let mut last_refresh = self
            .last_refresh_time
            .write()
            .await;
        *last_refresh = Some(Utc::now());
        self.refresh_in_progress
            .store(false, Ordering::SeqCst);
    }

    /// Check if enough time has passed since last refresh (cooldown mechanism)
    /// Returns true if refresh is allowed, false if still in cooldown period
    pub async fn can_refresh(
        &self,
        cooldown_secs: i64,
    ) -> bool {
        let last_refresh = self
            .last_refresh_time
            .read()
            .await;
        match *last_refresh {
            None => true, // Never refreshed before
            Some(last_time) => {
                let elapsed = Utc::now() - last_time;
                elapsed.num_seconds() >= cooldown_secs
            }
        }
    }

    /// Get cached channels for a gateway
    pub async fn get(
        &self,
        gateway_id: &str,
    ) -> Option<CachedGatewayChannels> {
        let cache = self.cache.read().await;
        cache.get(gateway_id).cloned()
    }

    /// Store channels in cache
    pub async fn set(
        &self,
        gateway_id: String,
        channels: Vec<SurfaceInfo>,
    ) {
        let mut cache = self.cache.write().await;
        cache.insert(
            gateway_id.clone(),
            CachedGatewayChannels {
                gateway_id,
                channels,
                cached_at: chrono::Utc::now(),
                last_error: None,
            },
        );
    }

    /// Store error in cache
    pub async fn set_error(
        &self,
        gateway_id: String,
        error: String,
    ) {
        let mut cache = self.cache.write().await;
        cache.insert(
            gateway_id.clone(),
            CachedGatewayChannels {
                gateway_id,
                channels: Vec::new(),
                cached_at: chrono::Utc::now(),
                last_error: Some(error),
            },
        );
    }

    /// Check if cache entry is fresh (less than 5 minutes old)
    pub async fn is_fresh(
        &self,
        gateway_id: &str,
        max_age_secs: i64,
    ) -> bool {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(gateway_id) {
            let age = chrono::Utc::now() - cached.cached_at;
            age.num_seconds() < max_age_secs
        } else {
            false
        }
    }

    /// Clear cache for a specific gateway
    pub async fn clear(
        &self,
        gateway_id: &str,
    ) {
        let mut cache = self.cache.write().await;
        cache.remove(gateway_id);
        debug!("Cleared cache for gateway {}", gateway_id);
    }

    /// Clear all cached entries
    #[allow(dead_code)]
    pub async fn clear_all(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Cleared all gateway channel cache");
    }

    /// Get all cached gateway IDs
    #[allow(dead_code)]
    pub async fn get_cached_gateway_ids(&self) -> Vec<String> {
        let cache = self.cache.read().await;
        cache
            .keys()
            .cloned()
            .collect()
    }
}

impl Default for GatewaySurfaceCache {
    fn default() -> Self {
        Self::new()
    }
}
