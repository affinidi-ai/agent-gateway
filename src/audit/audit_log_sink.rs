//! The VP Audit Log as a sink: appends records to the JSONL file the Audit
//! page reads, and rotates it once it reaches its size cap.

use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use tracing::warn;

use crate::audit::dispatch::Deliver;
use crate::audit::journal::JournalEntry;
use crate::audit::log_files::{self, Rotation};

/// The event ids most recently written, so a record delivered again after a
/// restart or a failed commit is not written twice.
struct RecentIds {
    order: VecDeque<String>,
    ids: HashSet<String>,
    capacity: usize,
}

impl RecentIds {
    fn new(capacity: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(capacity),
            ids: HashSet::with_capacity(capacity),
            capacity,
        }
    }

    fn contains(
        &self,
        id: &str,
    ) -> bool {
        self.ids.contains(id)
    }

    fn remember(
        &mut self,
        id: String,
    ) {
        if self.capacity == 0 || self.ids.contains(&id) {
            return;
        }
        if self.order.len() == self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.ids.remove(&oldest);
        }
        self.ids.insert(id.clone());
        self.order.push_back(id);
    }
}

/// How much of the end of an existing log is read for event ids on open.
const TAIL_BYTES: u64 = 4 * 1024 * 1024;

#[derive(serde::Deserialize)]
struct StoredId {
    #[serde(default)]
    event_id: Option<String>,
}

/// Event ids of up to `count` records at the end of the log, oldest first.
/// Reads back into the rotated files, so a log rotated just before a restart
/// still recognises the records a redelivery would write again.
fn tail_event_ids(
    path: &Path,
    count: usize,
) -> io::Result<Vec<String>> {
    let window = log_files::read_window(path, TAIL_BYTES)?;
    let lines: Vec<&str> = window.text.lines().collect();
    let skip = lines
        .len()
        .saturating_sub(count);
    Ok(lines[skip..]
        .iter()
        .filter_map(|line| serde_json::from_str::<StoredId>(line).ok())
        .filter_map(|stored| stored.event_id)
        .collect())
}

struct Inner {
    path: PathBuf,
    file: Mutex<Option<File>>,
    /// Set under the `file` lock once the log is closed; later appends are refused.
    closed: AtomicBool,
    recent: Mutex<RecentIds>,
    /// How the live log is rotated once it reaches its size cap.
    rotation: Rotation,
}

impl Inner {
    fn append(
        &self,
        record: &crate::delegation_vault::audit::DelegationAuditEvent,
    ) -> io::Result<()> {
        if record
            .event_id
            .as_deref()
            .is_some_and(|id| {
                self.recent
                    .lock()
                    .contains(id)
            })
        {
            return Ok(());
        }
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        let mut file = self.file.lock();
        if self
            .closed
            .load(Ordering::Acquire)
        {
            return Err(io::Error::other("the VP Audit Log is closed"));
        }
        if file.is_none() {
            *file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)?,
            );
        }
        if let Some(open) = file.as_mut()
            && let Err(e) = open.write_all(&line)
        {
            *file = None;
            return Err(e);
        }
        if let Some(id) = &record.event_id {
            self.recent
                .lock()
                .remember(id.clone());
        }
        self.rotate_if_full(&mut file);
        Ok(())
    }

    /// Rotates the live log once it has reached its cap, so the file the Audit
    /// page reads stays bounded however long the gateway runs. The record is
    /// already written, so a failed rotation is logged and left for the next
    /// append rather than failing the delivery.
    fn rotate_if_full(
        &self,
        file: &mut Option<File>,
    ) {
        if self.rotation.max_bytes == 0 {
            return;
        }
        let full = file
            .as_ref()
            .and_then(|open| open.metadata().ok())
            .is_some_and(|data| data.len() >= self.rotation.max_bytes);
        if !full {
            return;
        }
        if let Some(open) = file.as_ref() {
            let _ = open.sync_data();
        }
        *file = None;
        if let Err(e) = log_files::rotate(&self.path, self.rotation.keep) {
            warn!(
                target: "credential_delegation",
                error = %e,
                path = %self.path.display(),
                "Failed to rotate the VP Audit Log"
            );
        }
    }

    fn sync(&self) -> io::Result<()> {
        match self.file.lock().as_ref() {
            Some(file) => file.sync_data(),
            None => Ok(()),
        }
    }

    fn close(&self) -> io::Result<()> {
        let mut file = self.file.lock();
        self.closed
            .store(true, Ordering::Release);
        match file.take() {
            Some(open) => open.sync_data(),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct AuditLogSink(Arc<Inner>);

impl AuditLogSink {
    /// Opens the log at `path`, remembering the event ids of up to `remember`
    /// records at its end, and rotating it as `rotation` says.
    pub fn open(
        path: &Path,
        remember: usize,
        rotation: Rotation,
    ) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut recent = RecentIds::new(remember);
        for id in tail_event_ids(path, remember)? {
            recent.remember(id);
        }
        Ok(Self(Arc::new(Inner {
            path: path.to_path_buf(),
            file: Mutex::new(None),
            closed: AtomicBool::new(false),
            recent: Mutex::new(recent),
            rotation,
        })))
    }

    /// Waits for a write in progress, syncs the log and refuses every later write. A delivery
    /// cancelled mid-write still finishes on a blocking thread; closing makes sure it lands
    /// before another pipeline opens the log and reads the ids at its end, or not at all.
    pub fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}

impl Deliver for AuditLogSink {
    /// Appends the record, unless it is one of the most recently written.
    async fn deliver(
        &self,
        entry: &JournalEntry,
    ) -> anyhow::Result<()> {
        let (inner, record) = (self.0.clone(), entry.record.clone());
        tokio::task::spawn_blocking(move || inner.append(&record)).await??;
        Ok(())
    }

    /// Syncs the appended records to disk.
    async fn commit(&self) -> anyhow::Result<()> {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || inner.sync()).await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::registry::SinkId;
    use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent, audit_event};
    use tempfile::TempDir;

    fn entry(seq: u64) -> JournalEntry {
        JournalEntry {
            seq,
            recipients: vec![SinkId::AuditLog],
            record: audit_event(DelegationAuditAction::ConsentGranted, None, None, Some("github"), None),
        }
    }

    fn lines(path: &Path) -> Vec<DelegationAuditEvent> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn ids(path: &Path) -> Vec<Option<String>> {
        lines(path)
            .into_iter()
            .map(|record| record.event_id)
            .collect()
    }

    #[tokio::test]
    async fn delivered_records_are_appended_in_the_stored_format() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let sink = AuditLogSink::open(&path, 16, Rotation::default()).unwrap();
        let (first, second) = (entry(1), entry(2));

        sink.deliver(&first)
            .await
            .unwrap();
        sink.deliver(&second)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        let stored = lines(&path);
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].event_id, first.record.event_id);
        assert_eq!(stored[1].event_id, second.record.event_id);
        assert_eq!(
            stored[0]
                .provider_id
                .as_deref(),
            Some("github")
        );
    }

    #[tokio::test]
    async fn a_record_already_at_the_end_of_the_log_is_not_written_again() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let earlier = entry(1);
        {
            let sink = AuditLogSink::open(&path, 16, Rotation::default()).unwrap();
            sink.deliver(&earlier)
                .await
                .unwrap();
            sink.commit().await.unwrap();
        }

        let sink = AuditLogSink::open(&path, 16, Rotation::default()).unwrap();
        let later = entry(2);
        sink.deliver(&earlier)
            .await
            .unwrap();
        sink.deliver(&later)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(ids(&path), vec![earlier.record.event_id, later.record.event_id]);
    }

    #[tokio::test]
    async fn a_closed_log_takes_no_more_records() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let sink = AuditLogSink::open(&path, 16, Rotation::default()).unwrap();
        let (kept, refused) = (entry(1), entry(2));
        sink.deliver(&kept)
            .await
            .unwrap();

        sink.close().unwrap();

        assert!(
            sink.deliver(&refused)
                .await
                .is_err()
        );
        assert_eq!(ids(&path), vec![kept.record.event_id]);
    }

    #[test]
    fn closing_waits_for_a_write_in_progress() {
        let dir = TempDir::new().unwrap();
        let sink = AuditLogSink::open(
            &dir.path()
                .join("delegation-audit.jsonl"),
            16,
            Rotation::default(),
        )
        .unwrap();
        // A write in progress holds the file while it appends.
        let writing = sink.0.file.lock();

        let closing = std::thread::spawn({
            let sink = sink.clone();
            move || sink.close()
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!closing.is_finished(), "close returned while a write was still in progress");

        drop(writing);
        closing
            .join()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_record_delivered_twice_in_a_run_is_written_once() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let sink = AuditLogSink::open(&path, 16, Rotation::default()).unwrap();
        let record = entry(1);

        sink.deliver(&record)
            .await
            .unwrap();
        sink.deliver(&record)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(ids(&path), vec![record.record.event_id]);
    }

    #[tokio::test]
    async fn only_the_most_recent_ids_are_remembered() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let sink = AuditLogSink::open(&path, 1, Rotation::default()).unwrap();
        let (first, second) = (entry(1), entry(2));

        sink.deliver(&first)
            .await
            .unwrap();
        sink.deliver(&second)
            .await
            .unwrap();
        sink.deliver(&first)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(lines(&path).len(), 3);
    }

    #[tokio::test]
    async fn records_without_an_event_id_are_always_written() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let sink = AuditLogSink::open(&path, 16, Rotation::default()).unwrap();
        let mut record = entry(1);
        record.record.event_id = None;

        sink.deliver(&record)
            .await
            .unwrap();
        sink.deliver(&record)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(ids(&path), vec![None, None]);
    }

    #[tokio::test]
    async fn opening_reads_ids_from_the_end_of_an_existing_log_written_elsewhere() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let earlier = entry(1);
        std::fs::write(&path, format!("{}\n", serde_json::to_string(&earlier.record).unwrap())).unwrap();

        let sink = AuditLogSink::open(&path, 16, Rotation::default()).unwrap();
        sink.deliver(&earlier)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(lines(&path).len(), 1);
    }

    fn rotated(
        path: &Path,
        index: usize,
    ) -> PathBuf {
        PathBuf::from(format!("{}.{index}", path.display()))
    }

    #[tokio::test]
    async fn the_live_log_is_rotated_once_it_reaches_its_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let sink = AuditLogSink::open(&path, 16, Rotation { max_bytes: 1, keep: 2 }).unwrap();
        let (first, second) = (entry(1), entry(2));

        sink.deliver(&first)
            .await
            .unwrap();
        sink.deliver(&second)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(ids(&path), Vec::<Option<String>>::new(), "the live log starts again empty");
        assert_eq!(ids(&rotated(&path, 1)), vec![second.record.event_id]);
        assert_eq!(ids(&rotated(&path, 2)), vec![first.record.event_id]);
    }

    #[tokio::test]
    async fn a_record_rotated_out_of_the_live_log_is_not_written_again() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let record = entry(1);
        {
            let sink = AuditLogSink::open(&path, 16, Rotation { max_bytes: 1, keep: 2 }).unwrap();
            sink.deliver(&record)
                .await
                .unwrap();
            sink.commit().await.unwrap();
        }

        let sink = AuditLogSink::open(&path, 16, Rotation { max_bytes: 1, keep: 2 }).unwrap();
        sink.deliver(&record)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(ids(&path), Vec::<Option<String>>::new(), "the redelivered record is skipped");
        assert_eq!(ids(&rotated(&path, 1)), vec![record.record.event_id]);
    }
}
