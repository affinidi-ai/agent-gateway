//! Delivers journalled records to each sink, in order, from its own cursor.
//!
//! A journal line that does not parse never holds a sink back: the reader
//! moves past it as it would past a delivered entry, counts it in
//! `agent_gateway_audit_sink_skipped_total{reason="corrupt"}` and logs one
//! warning per batch naming the segments. Entries with a seq at or below the
//! cursor are ignored, and entries are delivered in file order.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, warn};

use crate::audit::cursors::{CursorStore, JournalRead, journal_bytes, plan_backlog_skip, prune_segments, read_entries};
use crate::audit::journal::{JournalEntry, segment_first_seq, segment_paths};
use crate::audit::registry::{SinkId, Sinks};
use crate::metrics::backends::prometheus::{set_audit_journal_bytes, track_audit_sink_skipped};

/// Hands one journalled record to a sink.
pub trait Deliver: Send + Sync + 'static {
    fn deliver(
        &self,
        entry: &JournalEntry,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Makes every record delivered so far durable. Called once per batch
    /// before the cursor is saved; on failure the batch is read again.
    fn commit(&self) -> impl Future<Output = anyhow::Result<()>> + Send {
        std::future::ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub struct ReaderConfig {
    pub batch: usize,
    pub retry_initial: Duration,
    pub retry_max: Duration,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            batch: 256,
            retry_initial: Duration::from_secs(1),
            retry_max: Duration::from_secs(300),
        }
    }
}

/// The sink's current drop policy: records older than this are skipped.
pub type MaxAge = Arc<dyn Fn() -> Option<Duration> + Send + Sync>;

/// Where a sink reads from: the journal, its cursors and the last durable seq.
#[derive(Clone)]
pub struct JournalSource {
    pub dir: PathBuf,
    pub cursors: Arc<CursorStore>,
    pub durable: watch::Receiver<u64>,
}

/// Delivers every durable entry addressed to `sink`, in order, starting after
/// its saved cursor. A sink without a cursor starts at the current durable
/// seq and saves it at once. A failed delivery is retried with backoff and
/// the cursor does not move past it. Runs until the journal writer is gone.
pub async fn run_reader<D: Deliver>(
    sink: SinkId,
    deliver: D,
    source: JournalSource,
    config: ReaderConfig,
    max_age: MaxAge,
) {
    let JournalSource { dir, cursors, mut durable } = source;
    let (store, owned) = (cursors.clone(), sink.clone());
    let mut cursor = match blocking(move || store.start(&owned)).await {
        Ok(cursor) => cursor,
        Err(e) => {
            warn!(?sink, error = %e, "Failed to save an audit sink's first cursor");
            0
        }
    };
    loop {
        cursor = cursor.max(stored_cursor(&cursors, &sink));
        let upto = *durable.borrow_and_update();
        if cursor >= upto {
            if durable
                .changed()
                .await
                .is_err()
            {
                return;
            }
            continue;
        }
        let read = match read(dir.clone(), cursor, upto, config.batch).await {
            Ok(read) if !read.entries.is_empty() || read.through > cursor => read,
            Ok(_) => {
                warn!(?sink, cursor, upto, "Audit journal has no entries after the sink's cursor");
                tokio::time::sleep(config.retry_initial).await;
                continue;
            }
            Err(e) => {
                warn!(?sink, error = %e, "Failed to read the audit journal");
                tokio::time::sleep(config.retry_initial).await;
                continue;
            }
        };
        let batch_start = cursor;
        for entry in &read.entries {
            let moved_past = || stored_cursor(&cursors, &sink) >= entry.seq;
            let expired = || is_older_than(entry, max_age());
            let addressed = entry
                .recipients
                .contains(&sink);
            if addressed && !moved_past() {
                let delivered = !expired()
                    && deliver_until_accepted(&deliver, entry, &sink, &config, || moved_past() || expired()).await;
                if !delivered && !moved_past() {
                    track_audit_sink_skipped(sink.label(), "expired", 1);
                    warn!(?sink, seq = entry.seq, "Audit record skipped: older than the sink's drop policy");
                }
            }
            cursor = entry
                .seq
                .max(stored_cursor(&cursors, &sink));
        }
        cursor = cursor.max(read.through);
        if let Err(e) = deliver.commit().await {
            warn!(?sink, error = %e, "Audit sink could not commit a batch; reading it again");
            cursor = batch_start;
            tokio::time::sleep(config.retry_initial).await;
            continue;
        }
        if read.corrupt > 0 {
            track_audit_sink_skipped(sink.label(), "corrupt", read.corrupt);
            warn!(
                ?sink,
                lines = read.corrupt,
                segments = ?read.corrupt_segments,
                "Audit journal lines could not be read; the sink moved past them"
            );
        }
        save_cursor(&cursors, &sink, cursor).await;
    }
}

/// Whether the record is older than `max_age`. A record whose timestamp does
/// not parse is never treated as old.
fn is_older_than(
    entry: &JournalEntry,
    max_age: Option<Duration>,
) -> bool {
    let Some(max_age) = max_age else {
        return false;
    };
    chrono::DateTime::parse_from_rfc3339(&entry.record.timestamp).is_ok_and(|timestamp| {
        (chrono::Utc::now() - timestamp.with_timezone(&chrono::Utc))
            .to_std()
            .is_ok_and(|age| age > max_age)
    })
}

/// The sink's saved cursor, which the dispatcher may have moved forward.
fn stored_cursor(
    cursors: &CursorStore,
    sink: &SinkId,
) -> u64 {
    cursors.get(sink).unwrap_or(0)
}

/// Builds the deliverer for a sink.
pub trait SinkFactory: Send + Sync + 'static {
    type Deliverer: Deliver;
    fn deliverer(
        &self,
        sink: &SinkId,
    ) -> Self::Deliverer;
}

#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    pub reader: ReaderConfig,
    pub prune_interval: Duration,
    /// Journal size that raises a warning.
    pub journal_warn_bytes: u64,
    /// Journal size above which the sinks holding back the oldest segment
    /// are moved past it.
    pub journal_max_bytes: u64,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            reader: ReaderConfig::default(),
            prune_interval: Duration::from_secs(60),
            journal_warn_bytes: 256 * 1024 * 1024,
            journal_max_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Keeps one reader running per sink in `sinks`: starts readers for new
/// sinks, stops removed sinks' readers and drops their cursors, drops cursors
/// of sinks that no longer exist, and deletes segments every cursor has
/// passed. Start it after the sinks have been built; it runs until aborted.
pub async fn run_dispatcher<F: SinkFactory>(
    factory: F,
    sinks: &'static Sinks,
    source: JournalSource,
    config: DispatcherConfig,
) {
    let mut changes = sinks.subscribe();
    let mut readers: HashMap<SinkId, JoinHandle<()>> = HashMap::new();
    let mut prune = tokio::time::interval(config.prune_interval);
    prune.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut over_warning = false;

    let current = sinks.snapshot();
    park_unknown_cursors(&source.cursors, current.ids(), &readers).await;
    reconcile(&factory, sinks, &mut readers, &source, &config.reader).await;
    loop {
        tokio::select! {
            changed = changes.changed() => {
                if changed.is_err() {
                    break;
                }
                reconcile(&factory, sinks, &mut readers, &source, &config.reader).await;
            }
            _ = prune.tick() => {
                let current = sinks.snapshot();
                park_unknown_cursors(&source.cursors, current.ids(), &readers).await;
                prune_passed_segments(&source).await;
                enforce_journal_limits(&source, &config, &mut over_warning).await;
            }
        }
    }
    readers
        .values()
        .for_each(JoinHandle::abort);
}

async fn reconcile<F: SinkFactory>(
    factory: &F,
    sinks: &'static Sinks,
    readers: &mut HashMap<SinkId, JoinHandle<()>>,
    source: &JournalSource,
    config: &ReaderConfig,
) {
    let current = sinks.snapshot();
    let ids = current.ids();
    let removed: Vec<SinkId> = readers
        .keys()
        .filter(|id| !ids.contains(id))
        .cloned()
        .collect();
    for id in removed {
        if let Some(reader) = readers.remove(&id) {
            reader.abort();
            let _ = reader.await;
        }
        park_cursor(&source.cursors, &id).await;
    }
    for id in ids {
        if !readers.contains_key(id) {
            let (sinks, owned) = (sinks, id.clone());
            let max_age: MaxAge = Arc::new(move || {
                sinks
                    .snapshot()
                    .drop_older_than(&owned)
            });
            let reader =
                tokio::spawn(run_reader(id.clone(), factory.deliverer(id), source.clone(), config.clone(), max_age));
            readers.insert(id.clone(), reader);
        }
    }
}

/// Parks cursors of sinks that are neither configured nor being read. A sink
/// that still has a reader is left to [`reconcile`], which stops the reader
/// before parking, so a parked sink is never delivered to.
async fn park_unknown_cursors(
    cursors: &Arc<CursorStore>,
    ids: &[SinkId],
    readers: &HashMap<SinkId, JoinHandle<()>>,
) {
    for sink in cursors.sinks() {
        if !ids.contains(&sink) && !readers.contains_key(&sink) {
            park_cursor(cursors, &sink).await;
        }
    }
}

async fn park_cursor(
    cursors: &Arc<CursorStore>,
    sink: &SinkId,
) {
    let (cursors, owned) = (cursors.clone(), sink.clone());
    if let Err(e) = blocking(move || cursors.park(&owned)).await {
        warn!(?sink, error = %e, "Failed to park an audit sink cursor");
    }
}

/// Deletes segments every active cursor has passed and forgets parked
/// cursors whose entries are gone. Returns how many segments were deleted.
async fn prune_passed_segments(source: &JournalSource) -> usize {
    let Some(passed) = source.cursors.min() else {
        return 0;
    };
    let (dir, cursors) = (source.dir.clone(), source.cursors.clone());
    let pruned = blocking(move || {
        let deleted = prune_segments(&dir, passed)?;
        if let Some(oldest) = segment_paths(&dir)?
            .first()
            .and_then(|path| segment_first_seq(path))
        {
            cursors.drop_parked_before(oldest.saturating_sub(1))?;
        }
        Ok(deleted)
    })
    .await;
    match pruned {
        Ok(deleted) => deleted,
        Err(e) => {
            warn!(error = %e, "Failed to delete passed audit journal segments");
            0
        }
    }
}

/// Reports the journal size, warns once it passes the warning size, and while
/// it is over the cap moves the sinks holding back the oldest segment past it
/// so it can be deleted. Every record a moved sink skips is counted.
async fn enforce_journal_limits(
    source: &JournalSource,
    config: &DispatcherConfig,
    over_warning: &mut bool,
) {
    loop {
        let dir = source.dir.clone();
        let bytes = match blocking(move || journal_bytes(&dir)).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(error = %e, "Failed to measure the audit journal");
                return;
            }
        };
        set_audit_journal_bytes(bytes);
        let over = bytes > config.journal_warn_bytes;
        if over && !*over_warning {
            warn!(bytes, warn_bytes = config.journal_warn_bytes, "Audit journal is growing: a sink is falling behind");
        }
        *over_warning = over;
        if bytes <= config.journal_max_bytes {
            return;
        }

        let (dir, cursors) = (source.dir.clone(), source.cursors.snapshot());
        let skip = match blocking(move || plan_backlog_skip(&dir, &cursors)).await {
            Ok(Some(skip)) => skip,
            Ok(None) => return,
            Err(e) => {
                warn!(error = %e, "Failed to plan an audit journal backlog skip");
                return;
            }
        };
        for moved in &skip.sinks {
            save_cursor(&source.cursors, &moved.sink, skip.to).await;
            track_audit_sink_skipped(moved.sink.label(), "backlog_cap", moved.skipped);
            if moved.corrupt > 0 {
                track_audit_sink_skipped(moved.sink.label(), "corrupt", moved.corrupt);
            }
            error!(
                sink = ?moved.sink,
                skipped = moved.skipped,
                unreadable = moved.corrupt,
                to = skip.to,
                max_bytes = config.journal_max_bytes,
                "Audit journal over its cap: sink moved past records it had not received"
            );
        }
        if prune_passed_segments(source).await == 0 {
            return;
        }
    }
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> std::io::Result<T> + Send + 'static) -> std::io::Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(std::io::Error::other)?
}

/// Retries until the sink accepts the record (true) or `give_up` says to stop
/// (false).
async fn deliver_until_accepted<D: Deliver>(
    deliver: &D,
    entry: &JournalEntry,
    sink: &SinkId,
    config: &ReaderConfig,
    give_up: impl Fn() -> bool,
) -> bool {
    let mut backoff = config.retry_initial;
    while let Err(e) = deliver.deliver(entry).await {
        warn!(
            ?sink,
            seq = entry.seq,
            error = format!("{e:#}"),
            retry_in_ms = backoff.as_millis() as u64,
            "Audit sink did not accept a record; retrying"
        );
        tokio::time::sleep(backoff).await;
        if give_up() {
            return false;
        }
        backoff = (backoff * 2).min(config.retry_max);
    }
    true
}

async fn read(
    dir: PathBuf,
    after: u64,
    upto: u64,
    limit: usize,
) -> std::io::Result<JournalRead> {
    tokio::task::spawn_blocking(move || read_entries(&dir, after, upto, limit))
        .await
        .map_err(std::io::Error::other)?
}

async fn save_cursor(
    cursors: &Arc<CursorStore>,
    sink: &SinkId,
    seq: u64,
) {
    let (cursors, owned) = (cursors.clone(), sink.clone());
    let saved = tokio::task::spawn_blocking(move || cursors.set(&owned, seq))
        .await
        .map_err(std::io::Error::other)
        .and_then(|result| result);
    if let Err(e) = saved {
        warn!(?sink, seq, error = %e, "Failed to save an audit sink cursor");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::journal::{JournalWriter, Pending};
    use crate::delegation_vault::audit::{DelegationAuditAction, audit_event};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;
    use tempfile::TempDir;

    #[derive(Clone, Default)]
    struct RecordingSink {
        delivered: Arc<parking_lot::Mutex<Vec<u64>>>,
        failures_left: Arc<AtomicUsize>,
        attempts: Arc<AtomicUsize>,
        commit_failures_left: Arc<AtomicUsize>,
        commits: Arc<AtomicUsize>,
        /// Refuses every entry from this seq on, like an integration that
        /// stopped receiving audit records; 0 refuses nothing.
        refuse_from: Arc<std::sync::atomic::AtomicU64>,
    }

    impl Deliver for RecordingSink {
        async fn deliver(
            &self,
            entry: &JournalEntry,
        ) -> anyhow::Result<()> {
            self.attempts
                .fetch_add(1, Ordering::SeqCst);
            let refuse_from = self
                .refuse_from
                .load(Ordering::SeqCst);
            if refuse_from > 0 && entry.seq >= refuse_from {
                anyhow::bail!("not receiving audit records");
            }
            if self
                .failures_left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
                .is_ok()
            {
                anyhow::bail!("destination unreachable");
            }
            self.delivered
                .lock()
                .push(entry.seq);
            Ok(())
        }

        async fn commit(&self) -> anyhow::Result<()> {
            self.commits
                .fetch_add(1, Ordering::SeqCst);
            if self
                .commit_failures_left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
                .is_ok()
            {
                anyhow::bail!("disk full");
            }
            Ok(())
        }
    }

    struct Fixture {
        dir: TempDir,
        writer: JournalWriter,
        durable: watch::Sender<u64>,
        cursors: Arc<CursorStore>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_segment_bytes(1 << 20)
        }

        fn with_segment_bytes(segment_max_bytes: u64) -> Self {
            let dir = TempDir::new().unwrap();
            let writer = JournalWriter::open(dir.path(), segment_max_bytes).unwrap();
            let cursors = Arc::new(CursorStore::open(dir.path()).unwrap());
            let (durable, _) = watch::channel(0);
            Self { dir, writer, durable, cursors }
        }

        fn append(
            &mut self,
            recipients: &[&[SinkId]],
        ) {
            self.append_aged(recipients, Duration::ZERO);
        }

        /// Appends records whose timestamp is `age` in the past.
        fn append_aged(
            &mut self,
            recipients: &[&[SinkId]],
            age: Duration,
        ) {
            let timestamp = (chrono::Utc::now() - chrono::Duration::from_std(age).unwrap()).to_rfc3339();
            let batch: Vec<Pending> = recipients
                .iter()
                .map(|sinks| {
                    let mut record = audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None);
                    record.timestamp = timestamp.clone();
                    Pending {
                        recipients: sinks.to_vec(),
                        record,
                    }
                })
                .collect();
            let last = self
                .writer
                .append(&batch)
                .unwrap()
                .unwrap();
            self.durable
                .send_replace(last);
        }

        fn source(&self) -> JournalSource {
            JournalSource {
                dir: self.dir.path().to_path_buf(),
                cursors: self.cursors.clone(),
                durable: self.durable.subscribe(),
            }
        }

        fn spawn(
            &self,
            sink: SinkId,
            deliver: RecordingSink,
        ) -> tokio::task::JoinHandle<()> {
            self.spawn_dropping(sink, deliver, None)
        }

        fn spawn_dropping(
            &self,
            sink: SinkId,
            deliver: RecordingSink,
            max_age: Option<Duration>,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(run_reader(sink, deliver, self.source(), fast_retry(), Arc::new(move || max_age)))
        }
    }

    fn fast_retry() -> ReaderConfig {
        ReaderConfig {
            batch: 2,
            retry_initial: Duration::from_millis(1),
            retry_max: Duration::from_millis(2),
        }
    }

    fn siem() -> SinkId {
        SinkId::Integration("siem".to_string())
    }

    async fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "condition not met in time");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test]
    async fn delivers_only_entries_addressed_to_the_sink_in_order() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let sink = RecordingSink::default();
        let reader = f.spawn(siem(), sink.clone());

        f.append(&[&[siem()], &[SinkId::AuditLog], &[SinkId::AuditLog, siem()], &[siem()], &[SinkId::AuditLog]]);
        wait_until(|| f.cursors.get(&siem()) == Some(5)).await;

        assert_eq!(*sink.delivered.lock(), vec![1, 3, 4]);
        reader.abort();
    }

    #[tokio::test]
    async fn a_failed_delivery_is_retried_and_holds_back_later_entries() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let sink = RecordingSink::default();
        sink.failures_left
            .store(3, Ordering::SeqCst);
        let reader = f.spawn(siem(), sink.clone());

        f.append(&[&[siem()], &[siem()]]);
        wait_until(|| sink.delivered.lock().len() == 2).await;

        assert_eq!(*sink.delivered.lock(), vec![1, 2]);
        assert_eq!(
            sink.attempts
                .load(Ordering::SeqCst),
            5
        );
        wait_until(|| f.cursors.get(&siem()) == Some(2)).await;
        reader.abort();
    }

    #[tokio::test]
    async fn the_cursor_stays_put_while_delivery_fails_and_a_new_reader_resumes_there() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let sink = RecordingSink::default();
        sink.failures_left
            .store(usize::MAX, Ordering::SeqCst);
        let reader = f.spawn(siem(), sink.clone());

        f.append(&[&[siem()], &[siem()]]);
        wait_until(|| {
            sink.attempts
                .load(Ordering::SeqCst)
                >= 3
        })
        .await;

        assert_eq!(f.cursors.get(&siem()), Some(0));
        assert!(
            sink.delivered
                .lock()
                .is_empty()
        );
        reader.abort();
        let _ = reader.await;

        let resumed = RecordingSink::default();
        let reader = f.spawn(siem(), resumed.clone());
        wait_until(|| f.cursors.get(&siem()) == Some(2)).await;
        assert_eq!(*resumed.delivered.lock(), vec![1, 2]);
        reader.abort();
    }

    #[tokio::test]
    async fn a_restarted_reader_resumes_after_its_saved_cursor() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let first = RecordingSink::default();
        let reader = f.spawn(siem(), first.clone());
        f.append(&[&[siem()], &[siem()]]);
        wait_until(|| f.cursors.get(&siem()) == Some(2)).await;
        reader.abort();
        let _ = reader.await;

        f.append(&[&[siem()]]);
        let second = RecordingSink::default();
        let reader = f.spawn(siem(), second.clone());
        wait_until(|| f.cursors.get(&siem()) == Some(3)).await;

        assert_eq!(*first.delivered.lock(), vec![1, 2]);
        assert_eq!(*second.delivered.lock(), vec![3]);
        reader.abort();
    }

    fn corrupt_skips(sink: &SinkId) -> u64 {
        crate::metrics::backends::prometheus::AUDIT_SINK_SKIPPED
            .with_label_values(&[sink.label(), "corrupt"])
            .get()
    }

    #[tokio::test]
    async fn a_garbled_line_is_skipped_counted_and_the_reader_carries_on() {
        let sink_id = SinkId::Integration("garbled-mid-batch".to_string());
        let mut f = Fixture::new();
        f.cursors
            .set(&sink_id, 0)
            .unwrap();
        f.append(&[&[sink_id.clone()], &[sink_id.clone()], &[sink_id.clone()]]);
        crate::audit::cursors::garble(f.dir.path(), 2);
        let before = corrupt_skips(&sink_id);

        let sink = RecordingSink::default();
        let reader = f.spawn(sink_id.clone(), sink.clone());
        wait_until(|| f.cursors.get(&sink_id) == Some(3)).await;

        assert_eq!(*sink.delivered.lock(), vec![1, 3]);
        assert_eq!(corrupt_skips(&sink_id), before + 1);
        reader.abort();
    }

    #[tokio::test]
    async fn a_garbled_line_in_the_newest_segment_does_not_stall_the_reader() {
        let sink_id = SinkId::Integration("garbled-newest".to_string());
        let mut f = Fixture::with_segment_bytes(1);
        f.cursors
            .set(&sink_id, 0)
            .unwrap();
        for _ in 0..3 {
            f.append(&[&[sink_id.clone()]]);
        }
        assert_eq!(
            segment_paths(f.dir.path())
                .unwrap()
                .len(),
            3
        );
        crate::audit::cursors::garble(f.dir.path(), 3);
        let before = corrupt_skips(&sink_id);

        let sink = RecordingSink::default();
        let reader = f.spawn(sink_id.clone(), sink.clone());
        wait_until(|| f.cursors.get(&sink_id) == Some(3)).await;
        f.append(&[&[sink_id.clone()]]);
        wait_until(|| f.cursors.get(&sink_id) == Some(4)).await;

        assert_eq!(*sink.delivered.lock(), vec![1, 2, 4]);
        assert_eq!(corrupt_skips(&sink_id), before + 1);
        reader.abort();
    }

    #[tokio::test]
    async fn a_new_sink_reads_from_the_start_of_the_journal() {
        let mut f = Fixture::new();
        f.append(&[&[SinkId::AuditLog], &[siem()]]);
        let sink = RecordingSink::default();
        let reader = f.spawn(siem(), sink.clone());
        wait_until(|| f.cursors.get(&siem()) == Some(2)).await;

        f.append(&[&[siem()]]);
        wait_until(|| f.cursors.get(&siem()) == Some(3)).await;

        assert_eq!(*sink.delivered.lock(), vec![2, 3]);
        reader.abort();
    }

    #[derive(Clone, Default)]
    struct RecordingFactory {
        sinks: Arc<parking_lot::Mutex<std::collections::HashMap<SinkId, RecordingSink>>>,
    }

    impl RecordingFactory {
        fn delivered(
            &self,
            sink: &SinkId,
        ) -> Vec<u64> {
            self.sinks
                .lock()
                .get(sink)
                .map(|recording| {
                    recording
                        .delivered
                        .lock()
                        .clone()
                })
                .unwrap_or_default()
        }
    }

    impl SinkFactory for RecordingFactory {
        type Deliverer = RecordingSink;
        fn deliverer(
            &self,
            sink: &SinkId,
        ) -> RecordingSink {
            self.sinks
                .lock()
                .entry(sink.clone())
                .or_default()
                .clone()
        }
    }

    fn registry(ids: &[SinkId]) -> &'static Sinks {
        let sinks: &'static Sinks = Box::leak(Box::default());
        sinks.replace(selecting_everything(ids));
        sinks
    }

    fn selecting_everything(ids: &[SinkId]) -> Vec<crate::audit::registry::Sink> {
        ids.iter()
            .map(|id| {
                crate::audit::registry::Sink::new(
                    id.clone(),
                    crate::audit::registry::EventMask::from_categories(["consent_granted"]),
                )
            })
            .collect()
    }

    fn manager_config(prune_interval: Duration) -> DispatcherConfig {
        DispatcherConfig {
            reader: fast_retry(),
            prune_interval,
            ..DispatcherConfig::default()
        }
    }

    #[tokio::test]
    async fn every_sink_gets_its_own_entries() {
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        let sinks = registry(&[SinkId::AuditLog, siem()]);
        let manager =
            tokio::spawn(run_dispatcher(factory.clone(), sinks, f.source(), manager_config(Duration::from_secs(60))));
        wait_until(|| {
            f.cursors
                .get(&SinkId::AuditLog)
                .is_some()
                && f.cursors
                    .get(&siem())
                    .is_some()
        })
        .await;

        f.append(&[&[SinkId::AuditLog], &[siem()], &[SinkId::AuditLog, siem()]]);
        wait_until(|| {
            f.cursors
                .get(&SinkId::AuditLog)
                == Some(3)
                && f.cursors.get(&siem()) == Some(3)
        })
        .await;

        assert_eq!(factory.delivered(&SinkId::AuditLog), vec![1, 3]);
        assert_eq!(factory.delivered(&siem()), vec![2, 3]);
        manager.abort();
    }

    #[tokio::test]
    async fn a_sink_added_later_receives_what_is_addressed_to_it() {
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        let sinks = registry(&[SinkId::AuditLog]);
        let manager =
            tokio::spawn(run_dispatcher(factory.clone(), sinks, f.source(), manager_config(Duration::from_secs(60))));
        f.append(&[&[SinkId::AuditLog]]);
        wait_until(|| {
            f.cursors
                .get(&SinkId::AuditLog)
                == Some(1)
        })
        .await;

        sinks.replace(selecting_everything(&[SinkId::AuditLog, siem()]));
        f.append(&[&[SinkId::AuditLog, siem()]]);
        wait_until(|| f.cursors.get(&siem()) == Some(2)).await;

        assert_eq!(factory.delivered(&siem()), vec![2]);
        manager.abort();
    }

    #[tokio::test]
    async fn a_re_enabled_sink_resumes_where_it_stopped() {
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        let sinks = registry(&[SinkId::AuditLog, siem()]);
        let manager =
            tokio::spawn(run_dispatcher(factory.clone(), sinks, f.source(), manager_config(Duration::from_secs(60))));
        f.append(&[&[SinkId::AuditLog, siem()]]);
        wait_until(|| f.cursors.get(&siem()) == Some(1)).await;

        sinks.replace(selecting_everything(&[SinkId::AuditLog]));
        wait_until(|| {
            f.cursors
                .get(&siem())
                .is_none()
        })
        .await;
        f.append(&[&[SinkId::AuditLog]]);
        sinks.replace(selecting_everything(&[SinkId::AuditLog, siem()]));
        f.append(&[&[SinkId::AuditLog, siem()]]);
        wait_until(|| f.cursors.get(&siem()) == Some(3)).await;

        assert_eq!(factory.delivered(&siem()), vec![1, 3]);
        manager.abort();
    }

    #[tokio::test]
    async fn a_sink_disabled_mid_batch_keeps_every_record_it_refused() {
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        factory
            .deliverer(&siem())
            .refuse_from
            .store(2, Ordering::SeqCst);
        let sinks = registry(&[SinkId::AuditLog, siem()]);
        let manager =
            tokio::spawn(run_dispatcher(factory.clone(), sinks, f.source(), manager_config(Duration::from_secs(60))));
        wait_until(|| {
            f.cursors
                .get(&siem())
                .is_some()
        })
        .await;

        f.append(&[&[siem()], &[siem()], &[siem()]]);
        wait_until(|| {
            factory
                .deliverer(&siem())
                .attempts
                .load(Ordering::SeqCst)
                >= 3
        })
        .await;
        assert!(f.cursors.get(&siem()) < Some(2));

        sinks.replace(selecting_everything(&[SinkId::AuditLog]));
        wait_until(|| {
            f.cursors
                .get(&siem())
                .is_none()
        })
        .await;
        factory
            .deliverer(&siem())
            .refuse_from
            .store(0, Ordering::SeqCst);
        sinks.replace(selecting_everything(&[SinkId::AuditLog, siem()]));
        wait_until(|| f.cursors.get(&siem()) == Some(3)).await;

        let delivered = factory.delivered(&siem());
        assert_eq!(delivered.first(), Some(&1));
        assert_eq!(delivered[delivered.len() - 2..], [2, 3]);
        manager.abort();
    }

    #[tokio::test]
    async fn a_removed_sink_stops_and_parks_its_cursor() {
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        let sinks = registry(&[SinkId::AuditLog, siem()]);
        let manager =
            tokio::spawn(run_dispatcher(factory.clone(), sinks, f.source(), manager_config(Duration::from_secs(60))));
        wait_until(|| {
            f.cursors
                .get(&siem())
                .is_some()
        })
        .await;

        sinks.replace(selecting_everything(&[SinkId::AuditLog]));
        wait_until(|| {
            f.cursors
                .get(&siem())
                .is_none()
        })
        .await;
        f.append(&[&[SinkId::AuditLog, siem()]]);
        wait_until(|| {
            f.cursors
                .get(&SinkId::AuditLog)
                == Some(1)
        })
        .await;

        assert!(
            factory
                .delivered(&siem())
                .is_empty()
        );
        assert_eq!(f.cursors.get(&siem()), None);
        manager.abort();
    }

    #[tokio::test]
    async fn cursors_of_sinks_that_no_longer_exist_are_parked_at_start() {
        let f = Fixture::new();
        f.cursors
            .set(&SinkId::Integration("deleted".to_string()), 0)
            .unwrap();
        let sinks = registry(&[SinkId::AuditLog]);
        let manager = tokio::spawn(run_dispatcher(
            RecordingFactory::default(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
        ));

        wait_until(|| {
            f.cursors
                .get(&SinkId::Integration("deleted".to_string()))
                .is_none()
        })
        .await;
        manager.abort();
    }

    #[tokio::test]
    async fn segments_every_sink_has_passed_are_deleted() {
        let dir = TempDir::new().unwrap();
        let mut writer = JournalWriter::open(dir.path(), 1).unwrap();
        let cursors = Arc::new(CursorStore::open(dir.path()).unwrap());
        let (durable, _) = watch::channel(0);
        let source = JournalSource {
            dir: dir.path().to_path_buf(),
            cursors: cursors.clone(),
            durable: durable.subscribe(),
        };
        cursors
            .set(&SinkId::AuditLog, 0)
            .unwrap();
        for _ in 0..3 {
            let last = writer
                .append(&[Pending {
                    recipients: vec![SinkId::AuditLog],
                    record: audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None),
                }])
                .unwrap()
                .unwrap();
            durable.send_replace(last);
        }
        assert_eq!(
            crate::audit::journal::segment_paths(dir.path())
                .unwrap()
                .len(),
            3
        );

        let manager = tokio::spawn(run_dispatcher(
            RecordingFactory::default(),
            registry(&[SinkId::AuditLog]),
            source,
            manager_config(Duration::from_millis(5)),
        ));
        wait_until(|| {
            crate::audit::journal::segment_paths(dir.path())
                .unwrap()
                .len()
                == 1
        })
        .await;
        manager.abort();
    }

    #[tokio::test]
    async fn a_stuck_delivery_is_abandoned_once_its_cursor_is_moved_past_it() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let sink = RecordingSink::default();
        sink.failures_left
            .store(usize::MAX, Ordering::SeqCst);
        let reader = f.spawn(siem(), sink.clone());
        f.append(&[&[siem()], &[siem()], &[siem()]]);
        wait_until(|| {
            sink.attempts
                .load(Ordering::SeqCst)
                >= 2
        })
        .await;

        f.cursors
            .set(&siem(), 2)
            .unwrap();
        sink.failures_left
            .store(0, Ordering::SeqCst);
        wait_until(|| f.cursors.get(&siem()) == Some(3)).await;

        assert_eq!(*sink.delivered.lock(), vec![3]);
        reader.abort();
    }

    #[tokio::test]
    async fn a_journal_over_its_cap_moves_the_sinks_holding_it_back() {
        let dir = TempDir::new().unwrap();
        let mut writer = JournalWriter::open(dir.path(), 1).unwrap();
        let cursors = Arc::new(CursorStore::open(dir.path()).unwrap());
        let (durable, _) = watch::channel(0);
        let source = JournalSource {
            dir: dir.path().to_path_buf(),
            cursors: cursors.clone(),
            durable: durable.subscribe(),
        };
        cursors
            .set(&siem(), 0)
            .unwrap();
        cursors
            .set(&SinkId::AuditLog, 0)
            .unwrap();
        let factory = RecordingFactory::default();
        factory
            .deliverer(&siem())
            .failures_left
            .store(usize::MAX, Ordering::SeqCst);

        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            registry(&[SinkId::AuditLog, siem()]),
            source,
            DispatcherConfig {
                reader: fast_retry(),
                prune_interval: Duration::from_millis(5),
                journal_warn_bytes: 1,
                journal_max_bytes: 1,
            },
        ));
        for _ in 0..4 {
            let last = writer
                .append(&[Pending {
                    recipients: vec![SinkId::AuditLog, siem()],
                    record: audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None),
                }])
                .unwrap()
                .unwrap();
            durable.send_replace(last);
        }

        wait_until(|| {
            crate::audit::journal::segment_paths(dir.path())
                .unwrap()
                .len()
                == 1
        })
        .await;
        wait_until(|| {
            factory
                .delivered(&SinkId::AuditLog)
                .len()
                == 4
        })
        .await;
        assert_eq!(factory.delivered(&SinkId::AuditLog), vec![1, 2, 3, 4]);
        assert!(
            factory
                .delivered(&siem())
                .is_empty()
        );
        assert!(cursors.get(&siem()).unwrap() >= 3);
        manager.abort();
    }

    #[tokio::test]
    async fn records_older_than_the_sinks_limit_are_skipped() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let sink = RecordingSink::default();
        let reader = f.spawn_dropping(siem(), sink.clone(), Some(Duration::from_secs(3600)));

        f.append_aged(&[&[siem()]], Duration::from_secs(7200));
        f.append(&[&[siem()]]);
        wait_until(|| f.cursors.get(&siem()) == Some(2)).await;

        assert_eq!(*sink.delivered.lock(), vec![2]);
        reader.abort();
    }

    #[tokio::test]
    async fn a_stuck_record_is_abandoned_once_it_is_older_than_the_limit() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let sink = RecordingSink::default();
        sink.failures_left
            .store(usize::MAX, Ordering::SeqCst);
        let reader = f.spawn_dropping(siem(), sink.clone(), Some(Duration::from_millis(500)));

        f.append(&[&[siem()]]);
        wait_until(|| {
            sink.attempts
                .load(Ordering::SeqCst)
                >= 1
        })
        .await;
        assert_eq!(f.cursors.get(&siem()), Some(0));
        wait_until(|| f.cursors.get(&siem()) == Some(1)).await;

        assert!(
            sink.delivered
                .lock()
                .is_empty()
        );
        assert!(
            sink.attempts
                .load(Ordering::SeqCst)
                >= 1
        );
        reader.abort();
    }

    #[tokio::test]
    async fn a_failed_commit_keeps_the_cursor_and_reads_the_batch_again() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let sink = RecordingSink::default();
        sink.commit_failures_left
            .store(1, Ordering::SeqCst);
        let reader = f.spawn(siem(), sink.clone());

        f.append(&[&[siem()], &[siem()]]);
        wait_until(|| f.cursors.get(&siem()) == Some(2)).await;

        assert_eq!(*sink.delivered.lock(), vec![1, 2, 1, 2]);
        assert_eq!(
            sink.commits
                .load(Ordering::SeqCst),
            2
        );
        reader.abort();
    }

    #[tokio::test]
    async fn the_reader_ends_when_the_journal_writer_is_gone() {
        let f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let reader = f.spawn(siem(), RecordingSink::default());
        drop(f.durable);
        tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("reader ended")
            .unwrap();
    }
}
