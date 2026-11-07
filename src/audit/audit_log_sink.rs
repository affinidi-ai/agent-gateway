//! The VP Audit Log as a sink: appends records to the JSONL file the Audit
//! page reads, and rotates it once it reaches its size cap.

use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{info, warn};

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
/// Walks back into the rotated files, so a log rotated just before a restart
/// still recognises the records a redelivery would write again, and stops at
/// [`TAIL_BYTES`] so a history of any size costs the same to open.
fn tail_event_ids(
    path: &Path,
    count: usize,
) -> io::Result<Vec<String>> {
    let mut lines = log_files::HistoryLines::open(path);
    let mut ids = Vec::new();
    let mut read: u64 = 0;
    while ids.len() < count && read < TAIL_BYTES {
        let Some(line) = lines.next_line()? else {
            break;
        };
        read += line.len() as u64 + 1;
        if let Ok(stored) = serde_json::from_str::<StoredId>(&line)
            && let Some(id) = stored.event_id
        {
            ids.push(id);
        }
    }
    ids.reverse();
    Ok(ids)
}

struct Inner {
    path: PathBuf,
    /// Bytes the history takes on disk: measured once when the log is opened,
    /// then kept as records are appended and as retention deletes. Measuring
    /// it again would mean listing a directory and `stat`ing every file in it,
    /// and `vp_audit_log_keep = 0` leaves the number of those files unbounded.
    /// An operator who deletes a rotated file beside the gateway makes it read
    /// high until the next start-up; it is reported as what the appliance is
    /// using, never enforced.
    history_bytes: AtomicU64,
    file: Mutex<Option<File>>,
    /// Set under the `file` lock once the log is closed; later appends are refused.
    closed: AtomicBool,
    recent: Mutex<RecentIds>,
    /// How the live log is rotated once it reaches its size cap.
    rotation: Rotation,
    /// When the current run of rotation failures was last reported. `None`
    /// while rotation is working.
    rotation_warned_at: Mutex<Option<Instant>>,
    /// When the next rotation may be tried, while a run of failures holds it
    /// back. `None` while rotation is working.
    rotation_retry_at: Mutex<Option<Instant>>,
}

/// How long a run of rotation failures goes unreported after one is logged.
/// A failure the gateway cannot act on is reported once per appended record if
/// nothing holds it back, and never again after the first if it is held back
/// for good — while the live log grows past the cap this sink exists to keep.
const ROTATION_WARN_INTERVAL: Duration = Duration::from_secs(3600);

/// How long a failed rotation is left alone before it is tried again. The live
/// log stays over its cap while a rotation keeps failing, so without this every
/// appended record would pay a sync, a reopen and a directory scan for a
/// rename that is going to fail again — backing the audit dispatcher up behind
/// a broken disk and growing the journal toward the size at which it skips
/// records.
const ROTATION_RETRY_INTERVAL: Duration = Duration::from_secs(60);

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
        self.grew_by(line.len() as u64);
        if let Some(id) = &record.event_id {
            self.recent
                .lock()
                .remember(id.clone());
        }
        self.rotate_if_full(&mut file, Instant::now());
        Ok(())
    }

    /// Rotates the live log once it has reached its cap, so the file the Audit
    /// page reads stays bounded however long the gateway runs. The record is
    /// already written, so a failed rotation is logged and left for a later
    /// append rather than failing the delivery; while a run of failures lasts,
    /// rotation is tried once per [`ROTATION_RETRY_INTERVAL`] and only the
    /// first failure of the run, and then one per [`ROTATION_WARN_INTERVAL`],
    /// is logged.
    ///
    /// The records appended since the last commit are made durable before the
    /// file is let go of, because nothing else will sync that handle. A sync
    /// that fails holds the rotation back and keeps the handle, so the error
    /// reaches the dispatcher through [`Inner::sync`] instead of being lost
    /// with the file it belonged to.
    fn rotate_if_full(
        &self,
        file: &mut Option<File>,
        now: Instant,
    ) {
        if self.rotation.max_bytes == 0 {
            return;
        }
        let full = file
            .as_ref()
            .and_then(|open| open.metadata().ok())
            .is_some_and(|data| data.len() >= self.rotation.max_bytes);
        if !full || !self.retry_due(now) {
            return;
        }
        if let Some(open) = file.as_ref()
            && let Err(e) = open.sync_data()
        {
            self.hold_back_until(now + ROTATION_RETRY_INTERVAL);
            if self.report_failure_at(now) {
                warn!(
                    target: "credential_delegation",
                    error = %e,
                    path = %self.path.display(),
                    "Could not make the VP Audit Log durable before rotating it; the rotation is held back and the \
                     records are reported as not committed"
                );
            }
            return;
        }
        *file = None;
        match log_files::rotate(&self.path, self.rotation.keep) {
            Ok(freed) => {
                self.shrank_by(freed);
                *self.rotation_retry_at.lock() = None;
                if self.report_recovery() {
                    info!(
                        target: "credential_delegation",
                        path = %self.path.display(),
                        "The VP Audit Log rotated again"
                    );
                }
            }
            Err(e) => {
                self.hold_back_until(now + ROTATION_RETRY_INTERVAL);
                if self.report_failure_at(now) {
                    warn!(
                        target: "credential_delegation",
                        error = %e,
                        path = %self.path.display(),
                        "Failed to rotate the VP Audit Log; the live log grows past its cap until this clears"
                    );
                }
            }
        }
    }

    /// Takes the bytes of an appended record into the size of the history, and
    /// publishes it for the Audit page.
    fn grew_by(
        &self,
        bytes: u64,
    ) {
        let total = self
            .history_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        crate::delegation_vault::audit::publish_history_bytes(total);
    }

    /// Takes the bytes retention deleted out of the size of the history.
    fn shrank_by(
        &self,
        bytes: u64,
    ) {
        if bytes == 0 {
            return;
        }
        let total = self
            .history_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| Some(held.saturating_sub(bytes)))
            .map_or(0, |held| held.saturating_sub(bytes));
        crate::delegation_vault::audit::publish_history_bytes(total);
    }

    /// Whether a rotation may be tried now: always, unless a failed one holds
    /// it back until a later time.
    fn retry_due(
        &self,
        now: Instant,
    ) -> bool {
        self.rotation_retry_at
            .lock()
            .is_none_or(|at| now >= at)
    }

    /// Holds the next rotation back until `at`, so a run of failures costs one
    /// attempt per interval rather than one per appended record.
    fn hold_back_until(
        &self,
        at: Instant,
    ) {
        *self.rotation_retry_at.lock() = Some(at);
    }

    /// Whether this failure is reported: the first of a run, and then once per
    /// [`ROTATION_WARN_INTERVAL`] for as long as rotation keeps failing, so the
    /// operator hears about it again instead of once at the start.
    fn report_failure_at(
        &self,
        now: Instant,
    ) -> bool {
        let mut warned = self.rotation_warned_at.lock();
        if let Some(at) = *warned
            && now.duration_since(at) < ROTATION_WARN_INTERVAL
        {
            return false;
        }
        *warned = Some(now);
        true
    }

    /// Whether this success ends a run of failures, so the recovery is
    /// reported once.
    fn report_recovery(&self) -> bool {
        self.rotation_warned_at
            .lock()
            .take()
            .is_some()
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
        // The one directory listing of the history's life: from here the size
        // follows what this sink writes and deletes.
        let history_bytes = log_files::history_bytes(path);
        crate::delegation_vault::audit::publish_history_bytes(history_bytes);
        Ok(Self(Arc::new(Inner {
            path: path.to_path_buf(),
            history_bytes: AtomicU64::new(history_bytes),
            file: Mutex::new(None),
            closed: AtomicBool::new(false),
            recent: Mutex::new(recent),
            rotation,
            rotation_warned_at: Mutex::new(None),
            rotation_retry_at: Mutex::new(None),
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
        assert_eq!(ids(&rotated(&path, 1)), vec![first.record.event_id], "the first rotation takes the first position");
        assert_eq!(ids(&rotated(&path, 2)), vec![second.record.event_id], "each rotation takes the next one");
    }

    #[tokio::test]
    async fn a_size_cap_of_zero_never_rotates_the_live_log() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let sink = AuditLogSink::open(&path, 16, Rotation { max_bytes: 0, keep: 2 }).unwrap();
        let (first, second) = (entry(1), entry(2));

        sink.deliver(&first)
            .await
            .unwrap();
        sink.deliver(&second)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(ids(&path), vec![first.record.event_id, second.record.event_id]);
        assert!(!rotated(&path, 1).exists(), "nothing was rotated away");
    }

    #[tokio::test]
    async fn a_record_behind_a_missing_rotated_file_is_not_written_again() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let record = entry(1);
        let stored = format!("{}\n", serde_json::to_string(&record.record).unwrap());
        // A history whose older positions are gone, as retention or a crash
        // during a rotation leaves it.
        std::fs::write(rotated(&path, 2), stored).unwrap();

        let sink = AuditLogSink::open(&path, 16, Rotation::default()).unwrap();
        sink.deliver(&record)
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert_eq!(
            ids(&path),
            Vec::<Option<String>>::new(),
            "the record is recognised behind the missing file, so it is not written twice"
        );
    }

    #[tokio::test]
    async fn a_failing_rotation_is_reported_once_and_once_more_when_it_recovers() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        let path = logs.join("delegation-audit.jsonl");
        std::fs::write(&path, "").unwrap();
        // A directory nothing may be renamed in, as a permission change on the
        // log directory leaves it: the live log cannot be moved aside.
        let mode = |bits| std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(bits)).unwrap();
        mode(0o500);
        if std::fs::File::create(logs.join("probe")).is_ok() {
            // A user the mode does not apply to, such as root in a container.
            mode(0o700);
            return;
        }
        let sink = AuditLogSink::open(&path, 16, Rotation { max_bytes: 1, keep: 1 }).unwrap();
        let failing = || {
            sink.0
                .rotation_warned_at
                .lock()
                .is_some()
        };

        sink.deliver(&entry(1))
            .await
            .unwrap();
        assert!(failing(), "the first failed rotation is reported");
        sink.deliver(&entry(2))
            .await
            .unwrap();
        assert!(failing(), "a rotation that is still failing is not reported again");

        mode(0o700);
        // The next retry is due a minute after the failure; a record appended
        // before then pays nothing for the rotation that is still held back.
        sink.0
            .rotation_retry_at
            .lock()
            .take();
        sink.deliver(&entry(3))
            .await
            .unwrap();
        sink.commit().await.unwrap();

        assert!(!failing(), "rotating again is reported as the recovery");
        assert_eq!(lines(&rotated(&path, 1)).len(), 3, "the records held back rotate once it works");
    }

    #[tokio::test]
    async fn a_rotation_that_keeps_failing_is_not_retried_on_every_record() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        let path = logs.join("delegation-audit.jsonl");
        std::fs::write(&path, "").unwrap();
        let mode = |bits| std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(bits)).unwrap();
        mode(0o500);
        if std::fs::File::create(logs.join("probe")).is_ok() {
            mode(0o700);
            return;
        }
        let sink = AuditLogSink::open(&path, 16, Rotation { max_bytes: 1, keep: 1 }).unwrap();

        sink.deliver(&entry(1))
            .await
            .unwrap();
        let held_back = *sink
            .0
            .rotation_retry_at
            .lock();
        sink.deliver(&entry(2))
            .await
            .unwrap();

        assert!(held_back.is_some(), "the failure holds the next rotation back");
        assert_eq!(
            *sink
                .0
                .rotation_retry_at
                .lock(),
            held_back,
            "the next record does not try the rotation again, so it pays no sync, reopen or directory scan"
        );
        assert!(
            !sink
                .0
                .retry_due(held_back.unwrap() - Duration::from_secs(1)),
            "nothing is retried before the interval is up"
        );
        assert!(
            sink.0
                .retry_due(held_back.unwrap()),
            "the rotation is tried again once it is"
        );
        mode(0o700);
    }

    #[test]
    fn a_rotation_that_keeps_failing_is_reported_again_each_hour() {
        let dir = TempDir::new().unwrap();
        let sink = AuditLogSink::open(
            &dir.path()
                .join("delegation-audit.jsonl"),
            16,
            Rotation::default(),
        )
        .unwrap();
        let start = Instant::now();

        assert!(
            sink.0
                .report_failure_at(start),
            "the first failure of a run is reported"
        );
        assert!(
            !sink
                .0
                .report_failure_at(start + ROTATION_WARN_INTERVAL - Duration::from_secs(1)),
            "a failure within the hour is not reported again"
        );
        assert!(
            sink.0
                .report_failure_at(start + ROTATION_WARN_INTERVAL),
            "a rotation still failing an hour later is reported again"
        );
        assert!(sink.0.report_recovery(), "the first success after a run reports the recovery");
        assert!(!sink.0.report_recovery(), "a later success reports nothing");
        assert!(
            sink.0
                .report_failure_at(start + ROTATION_WARN_INTERVAL),
            "the next run is reported from its own first failure"
        );
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
