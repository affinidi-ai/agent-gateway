//! Cache for x402 global configuration
//!
//! This module provides a global cache for the x402.json configuration file,
//! preventing repeated disk I/O on every payment verification.
//!
//! Security Note: This cache contains sensitive data (facilitator private keys).
//! The cache is loaded at startup from the main configuration object and
//! stored here for fast access during payment verification.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::config::types::X402Config;
use crate::identity::handlers::config::X402ConfigResponse;

lazy_static::lazy_static! {
    /// Global cache for x402 configuration
    /// Contains the full X402Config including facilitator_private_keys
    static ref X402_CONFIG_CACHE: Arc<RwLock<Option<Arc<X402Config>>>> =
        Arc::new(RwLock::new(None));

    /// Global cache for x402 network/token metadata
    /// Contains X402ConfigResponse with network definitions, token symbols, decimals
    static ref X402_METADATA_CACHE: Arc<RwLock<Option<Arc<X402ConfigResponse>>>> =
        Arc::new(RwLock::new(None));
}

/// Store x402 configuration in cache
/// Should be called during application startup with the already-loaded config
pub async fn set_x402_config(config: X402Config) {
    info!("Storing x402 configuration in cache");

    // Wrap in Arc for efficient sharing
    let config_arc = Arc::new(config);

    // Store in cache
    {
        let mut cache = X402_CONFIG_CACHE
            .write()
            .await;
        *cache = Some(config_arc);
    }

    info!("x402 configuration cached successfully");
}

/// Get cached x402 configuration
/// Returns None if cache is not initialized
pub async fn get_x402_config() -> Option<Arc<X402Config>> {
    let cache = X402_CONFIG_CACHE.read().await;
    cache.clone()
}

/// Get cached x402 configuration, returning error if not cached
/// Use this during payment verification to ensure config is available
pub async fn get_or_load_x402_config() -> anyhow::Result<Arc<X402Config>> {
    let cache = X402_CONFIG_CACHE.read().await;
    if let Some(config) = cache.as_ref() {
        debug!("Using cached x402 configuration");
        return Ok(Arc::clone(config));
    }

    // Not cached - this is an error, config should have been loaded at startup
    anyhow::bail!("x402 configuration not in cache - should have been loaded at startup")
}

/// Clear the x402 configuration cache. Test-only helper for isolating cached
/// config state between tests.
#[cfg(test)]
pub async fn clear_x402_config_cache() {
    let mut cache = X402_CONFIG_CACHE
        .write()
        .await;
    *cache = None;
    info!("x402 configuration cache cleared");
}

/// Store x402 metadata (network/token info) in cache
/// Should be called during application startup with the parsed X402ConfigResponse
pub async fn set_x402_metadata(metadata: X402ConfigResponse) {
    info!("Storing x402 metadata in cache ({} networks)", metadata.networks.len());

    let metadata_arc = Arc::new(metadata);

    {
        let mut cache = X402_METADATA_CACHE
            .write()
            .await;
        *cache = Some(metadata_arc);
    }

    info!("x402 metadata cached successfully");
}

/// Get cached x402 metadata
/// Returns None if cache is not initialized
pub async fn get_x402_metadata() -> Option<Arc<X402ConfigResponse>> {
    let cache = X402_METADATA_CACHE
        .read()
        .await;
    cache.clone()
}
