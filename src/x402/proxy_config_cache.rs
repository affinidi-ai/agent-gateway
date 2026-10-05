//! Cache for the X402 Proxy wallet/network configuration.
//!
//! Provides a global cache for the `x402-proxy.json` wallet/network config so it
//! is loaded once at startup and shared across every consumer (the core
//! `fabric://` MPP auto-pay path in particular).
//!
//! Security Note: this cache contains sensitive data (wallet private keys). It
//! is populated once at startup from the already-loaded configuration object.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use super::proxy_config::X402ProxyConfig;

lazy_static::lazy_static! {
    /// Global cache for X402 Proxy configuration (shared across all consumers).
    static ref X402_PROXY_CONFIG_CACHE: Arc<RwLock<Option<Arc<X402ProxyConfig>>>> =
        Arc::new(RwLock::new(None));
}

/// Store X402 Proxy configuration in cache.
/// Should be called during application startup with the already-loaded config.
pub async fn set_x402_proxy_config(config: X402ProxyConfig) {
    info!("Storing X402 Proxy configuration in cache");

    let config_arc = Arc::new(config);

    {
        let mut cache = X402_PROXY_CONFIG_CACHE
            .write()
            .await;
        *cache = Some(config_arc);
    }

    info!("X402 Proxy configuration cached successfully");
}

/// Get cached X402 Proxy configuration.
/// Returns `None` if the cache is not initialized.
pub async fn get_x402_proxy_config() -> Option<Arc<X402ProxyConfig>> {
    let cache = X402_PROXY_CONFIG_CACHE
        .read()
        .await;
    cache.clone()
}
