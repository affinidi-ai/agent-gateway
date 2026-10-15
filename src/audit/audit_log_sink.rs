//! The VP Audit Log as a sink: appends records to the JSONL file the Audit
//! page reads.

use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::audit::dispatch::Deliver;
use crate::audit::journal::JournalEntry;

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
fn tail_event_ids(
    path: &Path,
    count: usize,
) -> io::Result<Vec<String>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let start = file
        .metadata()?
        .len()
        .saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
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
    recent: Mutex<RecentIds>,
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
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        match self.file.lock().as_ref() {
            Some(file) => file.sync_data(),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct AuditLogSink(Arc<Inner>);

impl AuditLogSink {
    /// Opens the log at `path`, remembering the event ids of up to `remember`
    /// records at its end.
    pub fn open(
        path: &Path,
        remember: usize,
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
            recent: Mutex::new(recent),
        })))
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
        let sink = AuditLogSink::open(&path, 16).unwrap();
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
            let sink = AuditLogSink::open(&path, 16).unwrap();
            sink.deliver(&earlier)
                .await
                .unwrap();
            sink.commit().await.unwrap();
        }

        let sink = AuditLogSink::open(&path, 16).unwrap();
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
    async fn a_record_delivered_twice_in_a_run_is_written_once() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let sink = AuditLogSink::open(&path, 16).unwrap();
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
        let sink = AuditLogSink::open(&path, 1).unwrap();
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
        let sink = AuditLogSink::open(&path, 16).unwrap();
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

        let sink = AuditLogSink::open(&path, 16).unwrap();
        sink.deliver(&earlier)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(lines(&path).len(), 1);
    }
}
