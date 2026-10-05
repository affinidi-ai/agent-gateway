//! File-based metrics backend implementation

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

use super::types::{MetricsBackend, MetricsSnapshot};
use crate::metrics::{ConnectionMetric, RuleMetric, RuleValidationEvent};

/// File-based metrics backend (detailed history for local debugging)
pub struct FileMetricsBackend {
    path: PathBuf,
}

impl FileMetricsBackend {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait::async_trait]
impl MetricsBackend for FileMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        // Create directory if it doesn't exist
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Convert to hierarchical format (reuse existing logic)
        let metrics_data =
            crate::metrics::build_hierarchical_metrics(connections, rule_metrics, rule_validation_events);

        // Serialize to compact JSON to reduce transient memory and disk usage
        let json = serde_json::to_string(&metrics_data)?;

        // Write to temporary file first, then atomically rename
        let temp_path = self
            .path
            .with_extension("json.tmp");
        let mut file = tokio::fs::File::create(&temp_path).await?;
        file.write_all(json.as_bytes())
            .await?;
        file.flush().await?;
        drop(file); // Close file before rename

        // Atomic rename
        tokio::fs::rename(&temp_path, &self.path).await?;

        Ok(())
    }

    async fn load(&self) -> Result<MetricsSnapshot> {
        if !self.path.exists() {
            return Ok(MetricsSnapshot {
                connections: vec![],
                rule_validation_events: vec![],
            });
        }

        let contents = tokio::fs::read_to_string(&self.path).await?;
        let metrics_data: crate::metrics::MetricsData = serde_json::from_str(&contents)?;

        // Flatten hierarchical format back to flat metrics
        let (connections, rule_validation_events) = crate::metrics::flatten_hierarchical_metrics(&metrics_data);

        Ok(MetricsSnapshot {
            connections,
            rule_validation_events,
        })
    }

    fn name(&self) -> &str {
        "file"
    }
}
