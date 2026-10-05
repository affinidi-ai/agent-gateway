//! Multi-backend wrapper implementation

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use super::types::{MetricsBackend, MetricsSnapshot};
use crate::metrics::{ConnectionMetric, RuleMetric, RuleValidationEvent};

/// Multi-backend wrapper that broadcasts to all configured backends
pub struct MultiBackend {
    backends: Vec<Arc<dyn MetricsBackend>>,
}

impl MultiBackend {
    pub fn new() -> Self {
        Self { backends: Vec::new() }
    }

    pub fn add_backend(
        mut self,
        backend: Arc<dyn MetricsBackend>,
    ) -> Self {
        self.backends.push(backend);
        self
    }
}

#[async_trait::async_trait]
impl MetricsBackend for MultiBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        // Broadcast to all backends in parallel
        let futures: Vec<_> = self
            .backends
            .iter()
            .map(|backend| {
                let backend = backend.clone();
                let connections = connections.to_vec();
                let rule_metrics = rule_metrics.clone();
                let rule_validation_events = rule_validation_events.to_vec();
                async move {
                    if let Err(e) = backend
                        .persist(&connections, &rule_metrics, &rule_validation_events)
                        .await
                    {
                        eprintln!("Warning: {} backend failed to persist metrics: {}", backend.name(), e);
                    }
                }
            })
            .collect();

        futures::future::join_all(futures).await;

        Ok(())
    }

    async fn load(&self) -> Result<MetricsSnapshot> {
        // Load from the first backend that supports it (typically file backend)
        for backend in &self.backends {
            if let Ok(snapshot) = backend.load().await
                && (!snapshot
                    .connections
                    .is_empty()
                    || !snapshot
                        .rule_validation_events
                        .is_empty())
            {
                return Ok(snapshot);
            }
        }

        Ok(MetricsSnapshot {
            connections: vec![],
            rule_validation_events: vec![],
        })
    }

    fn name(&self) -> &str {
        "multi"
    }
}
