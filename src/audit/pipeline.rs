//! Starts the audit pipeline: journal writer, producer, cursors and the
//! dispatcher that delivers to every sink.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;

use tokio::sync::watch;

use crate::audit::audit_log_sink::AuditLogSink;
use crate::audit::cursors::CursorStore;
use crate::audit::dispatch::{DispatcherConfig, JournalSource, run_dispatcher};
use crate::audit::integration_sink::ProductionSinks;
use crate::audit::journal::{JournalWriter, WriterConfig, spawn_writer};
use crate::audit::producer::{Producer, producer};
use crate::audit::registry::{Sinks, sinks};
use crate::integrations::audit_integration_triggers::publish_audit_delivery;

const SEGMENT_MAX_BYTES: u64 = 16 * 1024 * 1024;
const REMEMBERED_IDS: usize = 1024;

/// Starts the process-wide pipeline. The journal lives in `audit_dir/journal`.
pub fn start(
    audit_dir: &Path,
    audit_log: &Path,
) -> io::Result<()> {
    start_with(producer(), sinks(), audit_dir, audit_log)
}

/// Starts the pipeline for `producer` and `sinks`, keeping the journal under
/// `audit_dir/journal` and the VP Audit Log at `audit_log`.
pub fn start_with(
    producer: &'static Producer,
    sinks: &'static Sinks,
    audit_dir: &Path,
    audit_log: &Path,
) -> io::Result<()> {
    let journal_dir = audit_dir.join("journal");
    let writer = JournalWriter::open(&journal_dir, SEGMENT_MAX_BYTES)?;
    let (durable_tx, durable) = watch::channel(
        writer
            .next_seq()
            .saturating_sub(1),
    );
    let (journal, pending) = mpsc::channel();
    spawn_writer(writer, pending, durable_tx, WriterConfig::default())?;
    producer.connect(journal);

    let source = JournalSource {
        cursors: Arc::new(CursorStore::open(&journal_dir)?),
        dir: journal_dir,
        durable,
    };
    let factory = ProductionSinks {
        audit_log: AuditLogSink::open(audit_log, REMEMBERED_IDS)?,
        publish: Arc::new(publish_audit_delivery),
    };
    tokio::spawn(run_dispatcher(factory, sinks, source, DispatcherConfig::default()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::registry::{EventMask, Sink, SinkId};
    use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent, audit_event};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn stored(path: &Path) -> Vec<DelegationAuditEvent> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    async fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < deadline, "condition not met in time");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn a_produced_record_reaches_the_vp_audit_log() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let sinks: &'static Sinks = Box::leak(Box::default());
        sinks.replace(vec![Sink::new(SinkId::AuditLog, EventMask::from_categories(["consent_granted"]))]);
        let producer: &'static Producer = Box::leak(Box::new(Producer::new(sinks)));

        start_with(producer, sinks, dir.path(), &log).unwrap();
        let record = audit_event(DelegationAuditAction::ConsentGranted, None, None, Some("github"), None);
        let event_id = record.event_id.clone();
        producer.submit(record);
        producer.submit(audit_event(DelegationAuditAction::TokenInjected, None, None, None, None));

        wait_until(|| stored(&log).len() == 1).await;
        assert_eq!(stored(&log)[0].event_id, event_id);
        assert!(
            dir.path()
                .join("journal")
                .is_dir()
        );
    }

    #[tokio::test]
    async fn a_record_for_another_sink_is_journalled_but_not_written_to_the_log() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let sinks: &'static Sinks = Box::leak(Box::default());
        let producer: &'static Producer = Box::leak(Box::new(Producer::new(sinks)));
        sinks.replace(vec![
            Sink::new(SinkId::AuditLog, EventMask::default()),
            Sink::new(SinkId::Integration("siem".to_string()), EventMask::from_categories(["consent_granted"])),
        ]);
        start_with(producer, sinks, dir.path(), &log).unwrap();

        producer.submit(audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None));
        let journal = dir.path().join("journal");
        wait_until(|| crate::audit::cursors::journal_bytes(&journal).unwrap() > 0).await;

        assert!(stored(&log).is_empty());
    }
}
