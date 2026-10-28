//! Configuration cache for persisting last-known good configuration
//!
//! This module provides functionality to cache channel configurations to disk,
//! allowing fallback to the last successful configuration if DynamoDB fails.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::info;

use crate::config::GatewayConfig;

/// Cached configuration with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedConfig {
    /// The cached configuration
    pub config: GatewayConfig,
    /// Timestamp when this configuration was cached
    pub cached_at: String,
    /// Source of the configuration (e.g., "dynamodb")
    pub source: String,
}

/// Configuration cache manager
pub struct ConfigCache {
    cache_path: PathBuf,
}

impl ConfigCache {
    /// Create a new configuration cache manager
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        let cache_path = cache_dir
            .as_ref()
            .join("last_known_good_config.json");
        Self { cache_path }
    }

    /// Save configuration to cache
    pub async fn save(
        &self,
        config: &GatewayConfig,
        source: &str,
    ) -> Result<()> {
        // Ensure cache directory exists
        if let Some(parent) = self.cache_path.parent() {
            fs::create_dir_all(parent)
                .await
                .context("Failed to create cache directory")?;
        }

        let cached = CachedConfig {
            config: config.clone(),
            cached_at: chrono::Utc::now().to_rfc3339(),
            source: source.to_string(),
        };

        let json = serde_json::to_string_pretty(&cached).context("Failed to serialize configuration")?;

        fs::write(&self.cache_path, json)
            .await
            .context("Failed to write configuration cache")?;

        info!(
            cache_path = %self.cache_path.display(),
            channels = config.surfaces.len(),
            "Saved configuration to cache"
        );

        Ok(())
    }

    /// Load configuration from cache
    pub async fn load(&self) -> Result<CachedConfig> {
        let contents = fs::read_to_string(&self.cache_path)
            .await
            .context("Failed to read configuration cache")?;

        let cached: CachedConfig = serde_json::from_str(&contents).context("Failed to parse cached configuration")?;

        info!(
            cache_path = %self.cache_path.display(),
            cached_at = %cached.cached_at,
            channels = cached.config.surfaces.len(),
            "Loaded configuration from cache"
        );

        Ok(cached)
    }

    /// Check if cache exists
    pub async fn exists(&self) -> bool {
        self.cache_path.exists()
    }

    /// Get cache path
    #[allow(dead_code)]
    pub fn cache_path(&self) -> &Path {
        &self.cache_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_cache_never_carries_surfaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = ConfigCache::new(dir.path());
        let config = GatewayConfig::default_config();
        assert!(!config.surfaces.is_empty());

        cache
            .save(&config, "dynamodb")
            .await
            .expect("save");
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(cache.cache_path()).expect("read cache")).expect("parse");
        assert!(
            raw["config"]
                .get("surfaces")
                .is_none(),
            "surfaces must not be cached"
        );
        let loaded = cache
            .load()
            .await
            .expect("load");
        assert!(
            loaded
                .config
                .surfaces
                .is_empty()
        );
        assert_eq!(loaded.source, "dynamodb");

        raw["config"]["surfaces"] = serde_json::json!([{
            "surface_id": "legacy",
            "name": "legacy",
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/legacy", "protocol": "a2a"},
            "target": {
                "endpoint": "https://managed.example/a2a",
                "trust_check_list": [{
                    "id": "legacy-target",
                    "trust_registry_id": "tr-1",
                    "query_type": "recognition",
                    "query": {"authority_id": "did:example:authority", "entity_id": "{{ target.did }}"}
                }]
            },
            "transit": {"points": [{"alias": "partner-a", "target_endpoint": "https://partner.example/a2a"}]}
        }]);
        std::fs::write(cache.cache_path(), raw.to_string()).expect("write cache");
        let loaded = cache
            .load()
            .await
            .expect("a cache file carrying surfaces still loads");
        assert!(
            loaded
                .config
                .surfaces
                .is_empty(),
            "surfaces come only from the surface store"
        );
    }
}
