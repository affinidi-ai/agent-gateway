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

/// The file beside the metrics file that holds the payment gate totals.
const PAYMENT_GATE_FILE: &str = "payment_gate_metrics.json";

impl FileMetricsBackend {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn payment_gate_path(&self) -> PathBuf {
        self.path
            .with_file_name(PAYMENT_GATE_FILE)
    }
}

/// Writes `json` to `path` through a temporary file renamed into place.
async fn write_atomically(
    path: &std::path::Path,
    json: &str,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let temp_path = path.with_extension("json.tmp");
    let mut file = tokio::fs::File::create(&temp_path).await?;
    file.write_all(json.as_bytes())
        .await?;
    file.flush().await?;
    drop(file);
    tokio::fs::rename(&temp_path, path).await?;
    Ok(())
}

#[async_trait::async_trait]
impl MetricsBackend for FileMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        // Create directory if it doesn't exist
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let metrics_data =
            crate::metrics::build_hierarchical_metrics(connections, rule_metrics, rule_validation_events);
        write_atomically(&self.path, &serde_json::to_string(&metrics_data)?).await?;
        write_atomically(&self.payment_gate_path(), &serde_json::to_string(&super::prometheus::payment_gate_totals())?)
            .await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn persisting_writes_the_payment_gate_totals_beside_the_metrics() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileMetricsBackend::new(
            dir.path()
                .join("metrics.json"),
        );
        crate::metrics::backends::prometheus::track_payment_gate("file-backend-surface", "rejected", 7);

        backend
            .persist(&[], &HashMap::new(), &[])
            .await
            .unwrap();

        let written: crate::metrics::backends::prometheus::PaymentGateTotals = serde_json::from_str(
            &std::fs::read_to_string(
                dir.path()
                    .join(PAYMENT_GATE_FILE),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(written.requests_by_outcome["rejected"] >= 1, "{written:?}");
        assert!(written.latency_count >= 1);
        assert!(
            dir.path()
                .join("metrics.json")
                .exists()
        );
        assert!(
            !dir.path()
                .join("payment_gate_metrics.json.tmp")
                .exists()
        );
        assert_eq!(
            backend
                .load()
                .await
                .unwrap()
                .connections
                .len(),
            0,
            "the metrics file still loads"
        );
    }
}
