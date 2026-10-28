//! Delivers journalled records to each sink, in order, from its own cursor.
//!
//! A journal line that does not parse never holds a sink back: the reader
//! moves past it as it would past a delivered entry, counts it in
//! `agent_gateway_audit_sink_skipped_total{reason="corrupt"}` and logs one
//! warning per batch naming the segments. Entries with a seq at or below the
//! cursor are ignored, and entries are delivered in file order.
//!
//! A sink with an attempt limit skips a record that has failed that many
//! delivery attempts, counts it with `reason="rejected"` and logs one warning
//! with the last error; without a limit the record is retried until delivered.
//!
//! A sink that leaves the registry (a Governance Audit integration disabled,
//! given a tenant, moved to another category or deleted) is paused: its
//! cursor moves to the durable seq and is parked there, letting go of the
//! records it had not received, counted in
//! `agent_gateway_audit_sink_skipped_total{reason="paused"}`. A sink that
//! resumes continues from its parked cursor. Records produced while the
//! registry change takes effect may still be delivered after the sink resumes,
//! or be counted as paused. The VP Audit Log is never paused.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{error, warn};

use crate::audit::cursors::{
    CursorStore, JournalRead, journal_bytes, plan_backlog_skip, prune_segments, read_entries, skipped_between,
};
use crate::audit::journal::{JournalEntry, segment_first_seq, segment_paths};
use crate::audit::registry::{SinkId, SinkRegistry, Sinks};
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

/// The sink's current attempt limit: a record it has failed to accept this
/// many times is skipped.
pub type MaxAttempts = Arc<dyn Fn() -> Option<u32> + Send + Sync>;

/// Where a sink reads from: the journal, its cursors and the last durable seq.
#[derive(Clone)]
pub struct JournalSource {
    pub dir: PathBuf,
    pub cursors: Arc<CursorStore>,
    pub durable: watch::Receiver<u64>,
}

/// Delivers every durable entry addressed to `sink`, in order, starting after
/// its saved cursor, or after its parked one when it resumes from a pause. A
/// sink with neither starts at the start of the journal and saves that at
/// once (see [`CursorStore::start`]). A failed delivery is retried with
/// backoff and the cursor does not move past it, until the record is older
/// than `max_age` or has failed `max_attempts` times. Runs until the journal
/// writer is gone or `cancel` fires; cancelling drops a delivery in flight,
/// and its cursor stays before it.
pub async fn run_reader<D: Deliver>(
    sink: SinkId,
    deliver: D,
    source: JournalSource,
    config: ReaderConfig,
    max_age: MaxAge,
    max_attempts: MaxAttempts,
    cancel: CancellationToken,
) {
    cancel
        .run_until_cancelled(deliver_from_cursor(sink, deliver, source, config, max_age, max_attempts))
        .await;
}

async fn deliver_from_cursor<D: Deliver>(
    sink: SinkId,
    deliver: D,
    source: JournalSource,
    config: ReaderConfig,
    max_age: MaxAge,
    max_attempts: MaxAttempts,
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
                let delivery = if expired() {
                    Delivery::Abandoned
                } else {
                    deliver_until_accepted(
                        &deliver,
                        entry,
                        &sink,
                        &config,
                        || max_attempts(),
                        || moved_past() || expired(),
                    )
                    .await
                };
                match delivery {
                    Delivery::Accepted => {}
                    _ if moved_past() => {}
                    Delivery::Abandoned => {
                        track_audit_sink_skipped(sink.label(), "expired", 1);
                        warn!(?sink, seq = entry.seq, "Audit record skipped: older than the sink's drop policy");
                    }
                    Delivery::Rejected { attempts, error } => {
                        track_audit_sink_skipped(sink.label(), "rejected", 1);
                        warn!(
                            ?sink,
                            seq = entry.seq,
                            attempts,
                            error = format!("{error:#}"),
                            "Audit record skipped: the sink did not accept it within its attempt limit"
                        );
                    }
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
/// sinks, pauses removed sinks and sinks with a cursor that are not in
/// `sinks`, and deletes segments every active cursor has passed. Start it
/// after the sinks have been built: a sink missing from them is paused. It runs until the
/// journal writer is gone (`source.durable` closes) or `cancel` fires, then
/// stops its readers and closes the cursor store, so nothing is delivered or
/// saved after it returns. Each reader runs under a child of `cancel`, and a
/// dispatcher dropped before it returns cancels its readers too.
pub async fn run_dispatcher<F: SinkFactory>(
    factory: F,
    sinks: &'static Sinks,
    source: JournalSource,
    config: DispatcherConfig,
    cancel: CancellationToken,
) {
    let mut readers = Readers::new();
    cancel
        .run_until_cancelled(dispatch(&factory, sinks, &source, &config, &cancel, &mut readers))
        .await;
    cancel.cancel();
    for reader in readers.into_values() {
        reader.stop().await;
    }
    source.cursors.close();
}

/// A running reader. Dropping it cancels the reader, so no reader outlives the
/// dispatcher that started it.
struct Reader {
    cancel: DropGuard,
    task: JoinHandle<()>,
}

impl Reader {
    /// Cancels the reader and waits for it to end.
    async fn stop(self) {
        let Self { cancel, task } = self;
        drop(cancel);
        if let Err(e) = task.await {
            warn!(error = %e, "An audit sink reader ended abnormally");
        }
    }
}

type Readers = HashMap<SinkId, Reader>;

async fn dispatch<F: SinkFactory>(
    factory: &F,
    sinks: &'static Sinks,
    source: &JournalSource,
    config: &DispatcherConfig,
    cancel: &CancellationToken,
    readers: &mut Readers,
) {
    let mut changes = sinks.subscribe();
    let mut written = source.durable.clone();
    let mut prune = tokio::time::interval(config.prune_interval);
    prune.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut over_warning = false;

    let current = sinks.snapshot();
    park_unknown_cursors(source, current.ids(), readers).await;
    reconcile(factory, sinks, readers, source, &config.reader, cancel).await;
    loop {
        tokio::select! {
            changed = changes.changed() => {
                if changed.is_err() {
                    return;
                }
                reconcile(factory, sinks, readers, source, &config.reader, cancel).await;
            }
            writer = written.changed() => {
                if writer.is_err() {
                    return;
                }
            }
            _ = prune.tick() => {
                let current = sinks.snapshot();
                park_unknown_cursors(source, current.ids(), readers).await;
                prune_passed_segments(source).await;
                enforce_journal_limits(source, config, &mut over_warning).await;
            }
        }
    }
}

/// Starts readers for new sinks and pauses removed ones: a removed sink's
/// reader is stopped, then the sink is paused (see [`pause`]). Then drops the
/// parked cursors of deleted integrations: those neither a sink nor paused.
async fn reconcile<F: SinkFactory>(
    factory: &F,
    sinks: &'static Sinks,
    readers: &mut Readers,
    source: &JournalSource,
    config: &ReaderConfig,
    cancel: &CancellationToken,
) {
    let current = sinks.snapshot();
    let ids = current.ids();
    let removed: Vec<SinkId> = readers
        .keys()
        .filter(|id| !ids.contains(id) && **id != SinkId::AuditLog)
        .cloned()
        .collect();
    for id in removed {
        if let Some(reader) = readers.remove(&id) {
            reader.stop().await;
        }
        pause(source, &id).await;
    }
    drop_deleted_cursors(&source.cursors, &current).await;
    for id in ids {
        if !readers.contains_key(id) {
            let (sinks, owned) = (sinks, id.clone());
            let max_age: MaxAge = Arc::new(move || {
                sinks
                    .snapshot()
                    .drop_older_than(&owned)
            });
            let owned = id.clone();
            let max_attempts: MaxAttempts = Arc::new(move || {
                sinks
                    .snapshot()
                    .max_attempts(&owned)
            });
            let reader_cancel = cancel.child_token();
            let task = tokio::spawn(run_reader(
                id.clone(),
                factory.deliverer(id),
                source.clone(),
                config.clone(),
                max_age,
                max_attempts,
                reader_cancel.clone(),
            ));
            readers.insert(
                id.clone(),
                Reader {
                    cancel: reader_cancel.drop_guard(),
                    task,
                },
            );
        }
    }
}

/// Forgets the parked cursors of sinks that are neither in `registry` nor
/// paused in it. The VP Audit Log's cursor is never dropped.
async fn drop_deleted_cursors(
    cursors: &Arc<CursorStore>,
    registry: &SinkRegistry,
) {
    let known: Vec<SinkId> = registry
        .ids()
        .iter()
        .chain(registry.paused())
        .cloned()
        .collect();
    let cursors = cursors.clone();
    let dropped = blocking(move || cursors.retain_parked(|sink| *sink == SinkId::AuditLog || known.contains(sink)));
    if let Err(e) = dropped.await {
        warn!(error = %e, "Failed to drop the cursors of deleted audit integrations");
    }
}

/// Pauses sinks with an active cursor that are neither configured nor being
/// read, such as an integration paused while the gateway was stopped. A sink
/// that still has a reader is left to [`reconcile`], which stops the reader
/// before pausing, so a paused sink is never delivered to. The VP Audit Log
/// is never paused.
async fn park_unknown_cursors(
    source: &JournalSource,
    ids: &[SinkId],
    readers: &Readers,
) {
    for sink in source.cursors.sinks() {
        if !ids.contains(&sink) && !readers.contains_key(&sink) && sink != SinkId::AuditLog {
            pause(source, &sink).await;
        }
    }
}

/// Pauses a sink with an active cursor: its cursor moves to the durable seq
/// and is parked there, so the sink lets go of the records it had not
/// received and, if it resumes, receives only records written after the
/// pause. The entries addressed to it that it lets go are counted with
/// `reason="paused"`, the unreadable lines with `reason="corrupt"`, and one
/// warning gives both counts.
async fn pause(
    source: &JournalSource,
    sink: &SinkId,
) {
    let Some(cursor) = source.cursors.get(sink) else {
        return;
    };
    let upto = *source.durable.borrow();
    let (dir, owned) = (source.dir.clone(), sink.clone());
    match blocking(move || skipped_between(&dir, &owned, cursor, upto)).await {
        Ok(moved) => {
            track_audit_sink_skipped(sink.label(), "paused", moved.skipped);
            if moved.corrupt > 0 {
                track_audit_sink_skipped(sink.label(), "corrupt", moved.corrupt);
            }
            warn!(
                ?sink,
                skipped = moved.skipped,
                unreadable = moved.corrupt,
                from = cursor,
                to = upto,
                "Audit sink paused: it lets go of the records it had not received"
            );
        }
        Err(e) => {
            warn!(
                ?sink,
                from = cursor,
                to = upto,
                error = %e,
                "Audit sink paused: it lets go of the records it had not received, which could not be counted"
            );
        }
    }
    let (cursors, owned) = (source.cursors.clone(), sink.clone());
    if let Err(e) = blocking(move || cursors.park_at(&owned, upto)).await {
        warn!(?sink, error = %e, "Failed to park an audit sink cursor");
    }
}

/// Deletes segments every active cursor has passed and forgets parked
/// cursors whose entries are gone; a paused sink without a cursor that
/// resumes reads what is left, all of it written after its pause. Returns how
/// many segments were deleted.
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

/// How a record's delivery ended.
enum Delivery {
    Accepted,
    /// `give_up` said to stop.
    Abandoned,
    /// It failed as many times as the sink's attempt limit; `error` is the
    /// last failure.
    Rejected {
        attempts: u32,
        error: anyhow::Error,
    },
}

/// Retries until the sink accepts the record, it has failed `max_attempts`
/// times (read after each failure), or `give_up` says to stop.
async fn deliver_until_accepted<D: Deliver>(
    deliver: &D,
    entry: &JournalEntry,
    sink: &SinkId,
    config: &ReaderConfig,
    max_attempts: impl Fn() -> Option<u32>,
    give_up: impl Fn() -> bool,
) -> Delivery {
    let mut backoff = config.retry_initial;
    let mut attempts: u32 = 0;
    while let Err(error) = deliver.deliver(entry).await {
        attempts = attempts.saturating_add(1);
        if max_attempts().is_some_and(|limit| attempts >= limit) {
            return Delivery::Rejected { attempts, error };
        }
        warn!(
            ?sink,
            seq = entry.seq,
            error = format!("{error:#}"),
            retry_in_ms = backoff.as_millis() as u64,
            "Audit sink did not accept a record; retrying"
        );
        tokio::time::sleep(backoff).await;
        if give_up() {
            return Delivery::Abandoned;
        }
        backoff = (backoff * 2).min(config.retry_max);
    }
    Delivery::Accepted
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
        /// Refuses the entry with this seq every time, like a destination
        /// that never accepts one record; 0 refuses nothing.
        refuse_seq: Arc<std::sync::atomic::AtomicU64>,
        /// Never completes a delivery, like a destination that never answers.
        stalled: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Deliver for RecordingSink {
        async fn deliver(
            &self,
            entry: &JournalEntry,
        ) -> anyhow::Result<()> {
            self.attempts
                .fetch_add(1, Ordering::SeqCst);
            if self
                .stalled
                .load(Ordering::SeqCst)
            {
                std::future::pending::<()>().await;
            }
            let refuse_from = self
                .refuse_from
                .load(Ordering::SeqCst);
            if refuse_from > 0 && entry.seq >= refuse_from {
                anyhow::bail!("not receiving audit records");
            }
            if self
                .refuse_seq
                .load(Ordering::SeqCst)
                == entry.seq
            {
                anyhow::bail!("record rejected");
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
            self.spawn_cancellable(sink, deliver, max_age, CancellationToken::new())
        }

        fn spawn_cancellable(
            &self,
            sink: SinkId,
            deliver: RecordingSink,
            max_age: Option<Duration>,
            cancel: CancellationToken,
        ) -> tokio::task::JoinHandle<()> {
            self.spawn_with(sink, deliver, max_age, None, cancel)
        }

        fn spawn_giving_up(
            &self,
            sink: SinkId,
            deliver: RecordingSink,
            max_attempts: u32,
        ) -> tokio::task::JoinHandle<()> {
            self.spawn_with(sink, deliver, None, Some(max_attempts), CancellationToken::new())
        }

        fn spawn_with(
            &self,
            sink: SinkId,
            deliver: RecordingSink,
            max_age: Option<Duration>,
            max_attempts: Option<u32>,
            cancel: CancellationToken,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(run_reader(
                sink,
                deliver,
                self.source(),
                fast_retry(),
                Arc::new(move || max_age),
                Arc::new(move || max_attempts),
                cancel,
            ))
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
        let addressed = std::slice::from_ref(&sink_id);
        f.append(&[addressed, addressed, addressed]);
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
            f.append(&[std::slice::from_ref(&sink_id)]);
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
        f.append(&[std::slice::from_ref(&sink_id)]);
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
        sinks.replace(selecting_everything(ids), Vec::new());
        sinks
    }

    /// Replaces the sinks with `ids`, `paused` being integrations that exist
    /// but do not receive audit records.
    fn rebuild(
        sinks: &Sinks,
        ids: &[SinkId],
        paused: &[SinkId],
    ) {
        sinks.replace(selecting_everything(ids), paused.to_vec());
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
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
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
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        f.append(&[&[SinkId::AuditLog]]);
        wait_until(|| {
            f.cursors
                .get(&SinkId::AuditLog)
                == Some(1)
        })
        .await;

        rebuild(sinks, &[SinkId::AuditLog, siem()], &[]);
        f.append(&[&[SinkId::AuditLog, siem()]]);
        wait_until(|| f.cursors.get(&siem()) == Some(2)).await;

        assert_eq!(factory.delivered(&siem()), vec![2]);
        manager.abort();
    }

    fn paused_skips(sink: &SinkId) -> u64 {
        crate::metrics::backends::prometheus::AUDIT_SINK_SKIPPED
            .with_label_values(&[sink.label(), "paused"])
            .get()
    }

    #[tokio::test]
    async fn a_paused_sink_skips_to_the_durable_seq_and_counts_its_backlog() {
        let paused = SinkId::Integration("paused-with-backlog".to_string());
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        factory
            .deliverer(&paused)
            .failures_left
            .store(usize::MAX, Ordering::SeqCst);
        let sinks = registry(&[SinkId::AuditLog, paused.clone()]);
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        let addressed = std::slice::from_ref(&paused);
        f.append(&[addressed, &[SinkId::AuditLog], addressed, &[SinkId::AuditLog, paused.clone()]]);
        wait_until(|| {
            factory
                .deliverer(&paused)
                .attempts
                .load(Ordering::SeqCst)
                >= 2
        })
        .await;
        let before = paused_skips(&paused);

        rebuild(sinks, &[SinkId::AuditLog], std::slice::from_ref(&paused));
        wait_until(|| f.cursors.parked(&paused) == Some(4)).await;
        manager.abort();
        let _ = manager.await;

        assert_eq!(f.cursors.get(&paused), None);
        assert_eq!(paused_skips(&paused), before + 3);
        assert!(
            factory
                .delivered(&paused)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_resumed_sink_receives_only_records_produced_after_the_pause() {
        let sink = SinkId::Integration("resumed-after-pause".to_string());
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        let sinks = registry(&[SinkId::AuditLog, sink.clone()]);
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        f.append(&[&[SinkId::AuditLog, sink.clone()]]);
        wait_until(|| f.cursors.get(&sink) == Some(1)).await;
        factory
            .deliverer(&sink)
            .refuse_from
            .store(2, Ordering::SeqCst);
        f.append(&[std::slice::from_ref(&sink), std::slice::from_ref(&sink)]);
        wait_until(|| {
            factory
                .deliverer(&sink)
                .attempts
                .load(Ordering::SeqCst)
                >= 2
        })
        .await;
        let before = paused_skips(&sink);

        rebuild(sinks, &[SinkId::AuditLog], std::slice::from_ref(&sink));
        wait_until(|| f.cursors.parked(&sink) == Some(3)).await;
        f.append(&[&[SinkId::AuditLog]]);
        factory
            .deliverer(&sink)
            .refuse_from
            .store(0, Ordering::SeqCst);
        rebuild(sinks, &[SinkId::AuditLog, sink.clone()], &[]);
        f.append(&[&[SinkId::AuditLog, sink.clone()]]);
        wait_until(|| f.cursors.get(&sink) == Some(5)).await;

        assert_eq!(factory.delivered(&sink), vec![1, 5]);
        assert_eq!(paused_skips(&sink), before + 2);
        manager.abort();
    }

    #[tokio::test]
    async fn a_resumed_sink_whose_parked_cursor_was_pruned_receives_only_newer_records() {
        let sink = SinkId::Integration("resumed-after-prune".to_string());
        let mut f = Fixture::with_segment_bytes(1);
        let factory = RecordingFactory::default();
        let sinks = registry(&[SinkId::AuditLog, sink.clone()]);
        f.cursors
            .set(&sink, 0)
            .unwrap();
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_millis(5)),
            CancellationToken::new(),
        ));
        f.append(&[std::slice::from_ref(&sink)]);
        f.append(&[std::slice::from_ref(&sink)]);
        wait_until(|| f.cursors.get(&sink) == Some(2)).await;

        rebuild(sinks, &[SinkId::AuditLog], std::slice::from_ref(&sink));
        wait_until(|| f.cursors.parked(&sink) == Some(2)).await;
        for _ in 0..3 {
            f.append(&[&[SinkId::AuditLog]]);
        }
        wait_until(|| {
            f.cursors
                .parked(&sink)
                .is_none()
        })
        .await;
        assert_eq!(
            segment_paths(f.dir.path())
                .unwrap()
                .len(),
            1
        );

        rebuild(sinks, &[SinkId::AuditLog, sink.clone()], &[]);
        f.append(&[&[SinkId::AuditLog, sink.clone()]]);
        wait_until(|| f.cursors.get(&sink) == Some(6)).await;

        assert_eq!(factory.delivered(&sink), vec![1, 2, 6]);
        manager.abort();
    }

    #[tokio::test]
    async fn a_removed_sink_stops_and_parks_its_cursor() {
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        let sinks = registry(&[SinkId::AuditLog, siem()]);
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        wait_until(|| {
            f.cursors
                .get(&siem())
                .is_some()
        })
        .await;

        rebuild(sinks, &[SinkId::AuditLog], &[siem()]);
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
    async fn a_sink_paused_when_the_dispatcher_starts_skips_to_the_durable_seq() {
        let paused = SinkId::Integration("paused-at-start".to_string());
        let active = SinkId::Integration("active-at-start".to_string());
        let mut f = Fixture::new();
        let only_paused = std::slice::from_ref(&paused);
        f.append(&[&[SinkId::AuditLog, active.clone(), paused.clone()], only_paused, only_paused]);
        for sink in [&SinkId::AuditLog, &active, &paused] {
            f.cursors
                .set(sink, 0)
                .unwrap();
        }
        let factory = RecordingFactory::default();
        for sink in [&SinkId::AuditLog, &active] {
            factory
                .deliverer(sink)
                .failures_left
                .store(usize::MAX, Ordering::SeqCst);
        }
        let before = paused_skips(&paused);
        let sinks = registry(&[]);
        rebuild(sinks, &[SinkId::AuditLog, active.clone()], std::slice::from_ref(&paused));

        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        wait_until(|| f.cursors.parked(&paused) == Some(3)).await;
        wait_until(|| {
            factory
                .deliverer(&active)
                .attempts
                .load(Ordering::SeqCst)
                >= 1
        })
        .await;

        assert_eq!(paused_skips(&paused), before + 3);
        assert_eq!(
            f.cursors
                .get(&SinkId::AuditLog),
            Some(0)
        );
        assert_eq!(f.cursors.get(&active), Some(0));
        assert_eq!(
            f.cursors
                .parked(&SinkId::AuditLog),
            None
        );
        manager.abort();
    }

    #[tokio::test]
    async fn a_deleted_integrations_parked_cursor_is_dropped_on_rebuild() {
        let deleted = SinkId::Integration("deleted-on-rebuild".to_string());
        let kept = SinkId::Integration("still-paused-on-rebuild".to_string());
        let f = Fixture::new();
        for sink in [&deleted, &kept] {
            f.cursors
                .set(sink, 0)
                .unwrap();
            f.cursors
                .park_at(sink, 0)
                .unwrap();
        }
        let sinks = registry(&[]);
        rebuild(sinks, &[SinkId::AuditLog, siem()], &[deleted.clone(), kept.clone()]);
        let manager = tokio::spawn(run_dispatcher(
            RecordingFactory::default(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        wait_until(|| f.cursors.get(&siem()) == Some(0)).await;
        assert_eq!(f.cursors.parked(&deleted), Some(0));

        rebuild(sinks, &[SinkId::AuditLog, siem()], std::slice::from_ref(&kept));
        wait_until(|| {
            f.cursors
                .parked(&deleted)
                .is_none()
        })
        .await;

        assert_eq!(f.cursors.parked(&kept), Some(0));
        assert_eq!(
            f.cursors
                .get(&SinkId::AuditLog),
            Some(0)
        );
        manager.abort();
    }

    #[tokio::test]
    async fn the_vp_audit_logs_cursor_is_never_dropped() {
        let f = Fixture::new();
        f.cursors
            .set(&SinkId::AuditLog, 0)
            .unwrap();
        f.cursors
            .park_at(&SinkId::AuditLog, 0)
            .unwrap();
        let sinks = registry(&[siem()]);
        let manager = tokio::spawn(run_dispatcher(
            RecordingFactory::default(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        wait_until(|| f.cursors.get(&siem()) == Some(0)).await;

        rebuild(sinks, &[siem()], &[]);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(
            f.cursors
                .parked(&SinkId::AuditLog),
            Some(0)
        );
        manager.abort();
    }

    #[tokio::test]
    async fn the_dispatcher_ends_and_saves_no_more_cursors_once_the_journal_writer_is_gone() {
        let mut f = Fixture::new();
        let sinks = registry(&[SinkId::AuditLog]);
        let manager = tokio::spawn(run_dispatcher(
            RecordingFactory::default(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        f.append(&[&[SinkId::AuditLog]]);
        wait_until(|| {
            f.cursors
                .get(&SinkId::AuditLog)
                == Some(1)
        })
        .await;

        let Fixture { dir, cursors, durable, .. } = f;
        drop(durable);
        tokio::time::timeout(Duration::from_secs(5), manager)
            .await
            .expect("the dispatcher ends once the writer is gone")
            .unwrap();

        cursors
            .set(&SinkId::AuditLog, 9)
            .unwrap();
        assert_eq!(
            CursorStore::open(dir.path())
                .unwrap()
                .get(&SinkId::AuditLog),
            Some(1)
        );
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
            CancellationToken::new(),
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
            CancellationToken::new(),
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

    fn rejected_skips(sink: &SinkId) -> u64 {
        crate::metrics::backends::prometheus::AUDIT_SINK_SKIPPED
            .with_label_values(&[sink.label(), "rejected"])
            .get()
    }

    #[tokio::test]
    async fn a_record_refused_as_often_as_the_attempt_limit_is_skipped_and_counted() {
        let sink_id = SinkId::Integration("rejected-after-limit".to_string());
        let mut f = Fixture::new();
        f.cursors
            .set(&sink_id, 0)
            .unwrap();
        let sink = RecordingSink::default();
        sink.refuse_seq
            .store(1, Ordering::SeqCst);
        let before = rejected_skips(&sink_id);
        let reader = f.spawn_giving_up(sink_id.clone(), sink.clone(), 3);

        let addressed = std::slice::from_ref(&sink_id);
        f.append(&[addressed, addressed]);
        wait_until(|| f.cursors.get(&sink_id) == Some(2)).await;

        assert_eq!(*sink.delivered.lock(), vec![2]);
        assert_eq!(
            sink.attempts
                .load(Ordering::SeqCst),
            4
        );
        assert_eq!(rejected_skips(&sink_id), before + 1);
        reader.abort();
    }

    #[tokio::test]
    async fn without_an_attempt_limit_a_refused_record_is_retried_and_never_skipped() {
        let sink_id = SinkId::Integration("rejected-without-limit".to_string());
        let mut f = Fixture::new();
        f.cursors
            .set(&sink_id, 0)
            .unwrap();
        let sink = RecordingSink::default();
        sink.refuse_seq
            .store(1, Ordering::SeqCst);
        let reader = f.spawn(sink_id.clone(), sink.clone());

        let addressed = std::slice::from_ref(&sink_id);
        f.append(&[addressed, addressed]);
        wait_until(|| {
            sink.attempts
                .load(Ordering::SeqCst)
                >= 10
        })
        .await;

        assert_eq!(f.cursors.get(&sink_id), Some(0));
        assert!(
            sink.delivered
                .lock()
                .is_empty()
        );
        assert_eq!(rejected_skips(&sink_id), 0);
        reader.abort();
    }

    #[tokio::test]
    async fn an_attempt_limit_set_in_the_registry_reaches_a_running_reader() {
        let sink_id = SinkId::Integration("limit-set-while-retrying".to_string());
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        factory
            .deliverer(&sink_id)
            .refuse_seq
            .store(1, Ordering::SeqCst);
        let sinks = registry(std::slice::from_ref(&sink_id));
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        let addressed = std::slice::from_ref(&sink_id);
        f.append(&[addressed, addressed]);
        wait_until(|| {
            factory
                .deliverer(&sink_id)
                .attempts
                .load(Ordering::SeqCst)
                >= 3
        })
        .await;
        assert_eq!(f.cursors.get(&sink_id), Some(0));
        let before = rejected_skips(&sink_id);

        sinks.replace(
            selecting_everything(addressed)
                .into_iter()
                .map(|sink| sink.giving_up_after(Some(2)))
                .collect(),
            Vec::new(),
        );
        wait_until(|| f.cursors.get(&sink_id) == Some(2)).await;

        assert_eq!(factory.delivered(&sink_id), vec![2]);
        assert_eq!(rejected_skips(&sink_id), before + 1);
        manager.abort();
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

    fn saved_cursor(
        dir: &std::path::Path,
        sink: &SinkId,
    ) -> Option<u64> {
        CursorStore::open(dir)
            .unwrap()
            .get(sink)
    }

    #[tokio::test]
    async fn a_cancelled_reader_ends_and_drops_the_delivery_in_flight() {
        let mut f = Fixture::new();
        f.cursors
            .set(&siem(), 0)
            .unwrap();
        let sink = RecordingSink::default();
        sink.stalled
            .store(true, Ordering::SeqCst);
        let cancel = CancellationToken::new();
        let reader = f.spawn_cancellable(siem(), sink.clone(), None, cancel.clone());
        f.append(&[&[siem()]]);
        wait_until(|| {
            sink.attempts
                .load(Ordering::SeqCst)
                == 1
        })
        .await;

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("the reader ends once cancelled")
            .unwrap();

        assert!(
            sink.delivered
                .lock()
                .is_empty()
        );
        assert_eq!(saved_cursor(f.dir.path(), &siem()), Some(0));
    }

    #[tokio::test]
    async fn cancelling_the_dispatcher_stops_every_reader_before_it_returns() {
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        factory
            .deliverer(&siem())
            .stalled
            .store(true, Ordering::SeqCst);
        let sinks = registry(&[SinkId::AuditLog, siem()]);
        let cancel = CancellationToken::new();
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            cancel.clone(),
        ));
        f.append(&[&[SinkId::AuditLog, siem()]]);
        wait_until(|| {
            f.cursors
                .get(&SinkId::AuditLog)
                == Some(1)
                && factory
                    .deliverer(&siem())
                    .attempts
                    .load(Ordering::SeqCst)
                    == 1
        })
        .await;

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), manager)
            .await
            .expect("the dispatcher ends once cancelled")
            .unwrap();
        f.append(&[&[SinkId::AuditLog, siem()]]);
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(factory.delivered(&SinkId::AuditLog), vec![1]);
        assert!(
            factory
                .delivered(&siem())
                .is_empty()
        );
        assert_eq!(saved_cursor(f.dir.path(), &SinkId::AuditLog), Some(1));
        assert_eq!(saved_cursor(f.dir.path(), &siem()), Some(0));
        f.cursors
            .set(&SinkId::AuditLog, 9)
            .unwrap();
        assert_eq!(saved_cursor(f.dir.path(), &SinkId::AuditLog), Some(1));
    }

    #[tokio::test]
    async fn dropping_the_dispatcher_stops_every_reader() {
        let mut f = Fixture::new();
        let factory = RecordingFactory::default();
        let sinks = registry(&[SinkId::AuditLog, siem()]);
        let manager = tokio::spawn(run_dispatcher(
            factory.clone(),
            sinks,
            f.source(),
            manager_config(Duration::from_secs(60)),
            CancellationToken::new(),
        ));
        f.append(&[&[SinkId::AuditLog, siem()]]);
        wait_until(|| {
            f.cursors
                .get(&SinkId::AuditLog)
                == Some(1)
                && f.cursors.get(&siem()) == Some(1)
        })
        .await;

        manager.abort();
        let _ = manager.await;
        tokio::task::yield_now().await;
        f.append(&[&[SinkId::AuditLog, siem()]]);
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(factory.delivered(&SinkId::AuditLog), vec![1]);
        assert_eq!(factory.delivered(&siem()), vec![1]);
        assert_eq!(saved_cursor(f.dir.path(), &SinkId::AuditLog), Some(1));
        assert_eq!(saved_cursor(f.dir.path(), &siem()), Some(1));
    }
}
