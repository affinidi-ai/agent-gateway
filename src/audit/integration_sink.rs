//! Governance Audit integrations as sinks, and the factory that builds every
//! production sink.

use std::sync::Arc;

use futures::future::BoxFuture;

use crate::audit::audit_log_sink::AuditLogSink;
use crate::audit::dispatch::{Deliver, SinkFactory};
use crate::audit::journal::JournalEntry;
use crate::audit::registry::SinkId;
use crate::integrations::audit_integration_triggers::AuditDelivery;

/// Publishes one rendered record to the integration with the given id.
pub type Publish = Arc<dyn Fn(String, AuditDelivery) -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync>;

#[derive(Clone)]
pub struct IntegrationSink {
    integration_id: String,
    publish: Publish,
}

impl IntegrationSink {
    pub fn new(
        integration_id: String,
        publish: Publish,
    ) -> Self {
        Self { integration_id, publish }
    }
}

impl Deliver for IntegrationSink {
    /// Renders the record as the integration's template expects and
    /// publishes it. An error makes the reader retry.
    async fn deliver(
        &self,
        entry: &JournalEntry,
    ) -> anyhow::Result<()> {
        (self.publish)(self.integration_id.clone(), AuditDelivery::from_event(&entry.record)).await
    }
}

/// Any production sink.
#[derive(Clone)]
pub enum AnySink {
    AuditLog(AuditLogSink),
    Integration(IntegrationSink),
}

impl Deliver for AnySink {
    async fn deliver(
        &self,
        entry: &JournalEntry,
    ) -> anyhow::Result<()> {
        match self {
            AnySink::AuditLog(sink) => sink.deliver(entry).await,
            AnySink::Integration(sink) => sink.deliver(entry).await,
        }
    }

    async fn commit(&self) -> anyhow::Result<()> {
        match self {
            AnySink::AuditLog(sink) => sink.commit().await,
            AnySink::Integration(sink) => sink.commit().await,
        }
    }
}

/// Builds the VP Audit Log sink and one sink per integration.
pub struct ProductionSinks {
    pub audit_log: AuditLogSink,
    pub publish: Publish,
}

impl SinkFactory for ProductionSinks {
    type Deliverer = AnySink;

    fn deliverer(
        &self,
        sink: &SinkId,
    ) -> AnySink {
        match sink {
            SinkId::AuditLog => AnySink::AuditLog(self.audit_log.clone()),
            SinkId::Integration(id) => AnySink::Integration(IntegrationSink::new(id.clone(), self.publish.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::audit::{DelegationAuditAction, audit_event};
    use parking_lot::Mutex;
    use tempfile::TempDir;

    #[derive(Default)]
    struct Published {
        calls: Mutex<Vec<(String, String, Option<String>)>>,
    }

    fn recording(
        published: Arc<Published>,
        fail: bool,
    ) -> Publish {
        Arc::new(move |integration_id, delivery: AuditDelivery| {
            let published = published.clone();
            Box::pin(async move {
                published.calls.lock().push((
                    integration_id,
                    delivery.values()["EVENT_NAME"].clone(),
                    delivery
                        .values()
                        .get("EVENT_TYPE")
                        .cloned(),
                ));
                if fail {
                    anyhow::bail!("broker unreachable")
                } else {
                    Ok(())
                }
            })
        })
    }

    fn entry(sink: SinkId) -> JournalEntry {
        JournalEntry {
            seq: 1,
            recipients: vec![sink],
            record: audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None),
        }
    }

    fn siem() -> SinkId {
        SinkId::Integration("siem".to_string())
    }

    #[tokio::test]
    async fn a_record_is_published_with_its_event_values() {
        let published = Arc::new(Published::default());
        let sink = IntegrationSink::new("siem".to_string(), recording(published.clone(), false));

        sink.deliver(&entry(siem()))
            .await
            .unwrap();

        assert_eq!(
            *published.calls.lock(),
            vec![("siem".to_string(), "Consent Granted".to_string(), Some("audit.consent_granted".to_string()))]
        );
    }

    #[tokio::test]
    async fn a_failed_publish_is_reported_so_the_record_is_retried() {
        let published = Arc::new(Published::default());
        let sink = IntegrationSink::new("siem".to_string(), recording(published, true));
        assert!(
            sink.deliver(&entry(siem()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_factory_builds_the_audit_log_and_integration_sinks() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let published = Arc::new(Published::default());
        let factory = ProductionSinks {
            audit_log: AuditLogSink::open(&path, 16).unwrap(),
            publish: recording(published.clone(), false),
        };

        let audit_log = factory.deliverer(&SinkId::AuditLog);
        audit_log
            .deliver(&entry(SinkId::AuditLog))
            .await
            .unwrap();
        audit_log
            .commit()
            .await
            .unwrap();
        factory
            .deliverer(&siem())
            .deliver(&entry(siem()))
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert_eq!(published.calls.lock().len(), 1);
        assert_eq!(published.calls.lock()[0].0, "siem");
    }
}
