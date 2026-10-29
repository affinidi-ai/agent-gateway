//! The store behind the payments ledger: a bounded in-memory window of the
//! newest rows, which serves the API, and append-only hourly segment files,
//! which keep every row for the retention period.
//!
//! Recording a row is an in-memory append: it never waits for the disk. A
//! worker writes the rows recorded since its last pass to their segment in one
//! buffered write and syncs it once per pass. A row that records money is
//! instead written and synced before [`DelegatedPaymentStore::record_durable`]
//! returns, and a change to a row is a new line for the same id, written the
//! same way: the last line for an id is the row. A row id is a time-ordered UUID
//! (version 7), so the hour of its segment follows from the id: a row that has
//! left the window is read back from that one segment, never from the whole
//! ledger.
//!
//! A row with a review case id is also named in an append-only case index
//! (`case_id` to row id), synced with the row, so a caller's poll finds its case
//! after the row has left the window. A missing index is rebuilt at startup
//! from the segments that may still hold a case under review.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use anyhow::{Context, bail};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn};

use super::{LedgerFilter, PaymentLedgerRow, StoredLedgerRow};
use crate::audit::journal::{OWNER_ONLY_FILE, create_owner_only_dir};

const SEGMENT_PREFIX: &str = "ledger-";
const SEGMENT_EXTENSION: &str = "jsonl";
const SEGMENT_HOUR_FORMAT: &str = "%Y-%m-%dT%H";
const SECONDS_PER_HOUR: i64 = 3600;
/// The longest line read from a segment; a longer one is damage and is skipped.
const MAX_LINE_BYTES: usize = 64 * 1024;
/// How many rows a lookup of a row outside the window may read at once.
const CONCURRENT_SEGMENT_READS: usize = 2;
const SEGMENT_READ_BUFFER_BYTES: usize = 256 * 1024;
const CASE_INDEX_FILE: &str = "case-index.jsonl";

#[derive(serde::Serialize, serde::Deserialize)]
struct CaseEntry {
    case_id: String,
    row_id: String,
}

/// The bounds that keep the ledger's memory and disk use finite.
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    /// Newest rows held in memory and served by `list`.
    pub window_rows: usize,
    /// Rows recorded but not yet written; past this, a row is kept in memory only.
    pub pending_rows: usize,
    /// A segment stops taking rows at this size, so one hour cannot fill the disk.
    pub segment_bytes: u64,
    /// The oldest segments are deleted while the ledger is larger than this.
    pub ledger_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            window_rows: 50_000,
            pending_rows: 20_000,
            segment_bytes: 256 * 1024 * 1024,
            ledger_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// One hour of the ledger, as whole hours since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Segment(i64);

impl Segment {
    pub(super) fn at(time: DateTime<Utc>) -> Self {
        Self(
            time.timestamp()
                .div_euclid(SECONDS_PER_HOUR),
        )
    }

    /// The segment a row id belongs to: the hour of its version 7 timestamp.
    /// `None` for an id that is not a canonical version 7 UUID.
    pub(super) fn of_row_id(id: &str) -> Option<Self> {
        let uuid = uuid::Uuid::parse_str(id).ok()?;
        if uuid.get_version() != Some(uuid::Version::SortRand) || uuid.hyphenated().to_string() != id {
            return None;
        }
        let (seconds, _) = uuid
            .get_timestamp()?
            .to_unix();
        Some(Self(i64::try_from(seconds).ok()? / SECONDS_PER_HOUR))
    }

    fn start(self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(self.0 * SECONDS_PER_HOUR, 0)
    }

    pub(super) fn file_name(self) -> String {
        let hour = self
            .start()
            .map(|start| {
                start
                    .format(SEGMENT_HOUR_FORMAT)
                    .to_string()
            })
            .unwrap_or_default();
        format!("{SEGMENT_PREFIX}{hour}.{SEGMENT_EXTENSION}")
    }

    fn parse_file_name(name: &str) -> Option<Self> {
        let hour = name
            .strip_prefix(SEGMENT_PREFIX)?
            .strip_suffix(&format!(".{SEGMENT_EXTENSION}"))?;
        let start = NaiveDateTime::parse_from_str(&format!("{hour}:00:00"), "%Y-%m-%dT%H:%M:%S").ok()?;
        let segment = Self::at(start.and_utc());
        (segment.file_name() == name).then_some(segment)
    }
}

/// Whether a row's payment is still held or unconfirmed, so the reconciler
/// needs it: the window keeps it past its capacity and a restart loads it from
/// whichever segment holds it.
pub(super) fn awaits_settlement(row: &PaymentLedgerRow) -> bool {
    matches!(row.outcome, super::LedgerOutcome::Authorized | super::LedgerOutcome::Unconfirmed)
        && !row.reconcile_failed
        && row.superseded_by.is_none()
}

/// How far back a restart looks for rows that still await settlement: past the
/// longest capture deadline agent-pay grants.
const OPEN_ROWS_LOOKBACK: Duration = Duration::days(8);

/// The newest rows, oldest first, with an index by id.
#[derive(Default)]
struct Window {
    rows: VecDeque<Arc<StoredLedgerRow>>,
    by_id: HashMap<String, Arc<StoredLedgerRow>>,
}

impl Window {
    /// Adds `stored` in `created_at` order and drops the oldest rows beyond
    /// `capacity`. A row is nearly always the newest, so the walk back is short.
    fn insert(
        &mut self,
        stored: Arc<StoredLedgerRow>,
        capacity: usize,
    ) {
        let mut at = self.rows.len();
        while at > 0
            && self.rows[at - 1]
                .row
                .created_at
                > stored.row.created_at
        {
            at -= 1;
        }
        self.by_id
            .insert(stored.row.id.clone(), stored.clone());
        self.rows.insert(at, stored);
        while self.rows.len() > capacity {
            let Some(oldest) = self
                .rows
                .iter()
                .position(|held| !awaits_settlement(&held.row))
                .and_then(|at| self.rows.remove(at))
            else {
                break;
            };
            self.by_id
                .remove(&oldest.row.id);
        }
    }

    /// Puts `stored` in place of the row with its id, when the window holds it.
    fn replace(
        &mut self,
        stored: Arc<StoredLedgerRow>,
    ) -> bool {
        if !self
            .by_id
            .contains_key(&stored.row.id)
        {
            return false;
        }
        if let Some(position) = self
            .rows
            .iter()
            .rposition(|held| held.row.id == stored.row.id)
        {
            self.rows[position] = stored.clone();
        }
        self.by_id
            .insert(stored.row.id.clone(), stored);
        true
    }

    fn drop_older_than(
        &mut self,
        cutoff: DateTime<Utc>,
    ) {
        while let Some(oldest) = self
            .rows
            .front()
            .filter(|oldest| oldest.row.created_at < cutoff)
        {
            self.by_id
                .remove(&oldest.row.id);
            self.rows.pop_front();
        }
    }
}

#[derive(Default)]
struct Inner {
    window: Window,
    /// Rows recorded and not yet written to a segment, oldest first.
    pending: VecDeque<Arc<StoredLedgerRow>>,
    /// Rows kept out of `pending` because the writer was behind, since the last write.
    unwritten: u64,
    /// Every segment file and its size.
    segments: BTreeMap<Segment, u64>,
    /// The row each review case id was last recorded on.
    cases: HashMap<String, String>,
}

pub struct DelegatedPaymentStore {
    dir: PathBuf,
    limits: Limits,
    inner: Mutex<Inner>,
    /// One write, cleanup or reload at a time.
    writing: tokio::sync::Mutex<()>,
    /// One read-modify-write of a row at a time.
    updating: tokio::sync::Mutex<()>,
    reads: tokio::sync::Semaphore,
}

impl DelegatedPaymentStore {
    #[cfg(test)]
    pub async fn new(base_path: PathBuf) -> anyhow::Result<Self> {
        Self::with_limits(base_path, Limits::default()).await
    }

    /// A store whose oldest segments are deleted while it is larger than `max_bytes`.
    pub async fn with_max_bytes(
        base_path: PathBuf,
        max_bytes: u64,
    ) -> anyhow::Result<Self> {
        Self::with_limits(
            base_path,
            Limits {
                ledger_bytes: max_bytes,
                ..Limits::default()
            },
        )
        .await
    }

    pub(super) async fn with_limits(
        base_path: PathBuf,
        limits: Limits,
    ) -> anyhow::Result<Self> {
        create_owner_only_dir(&base_path).with_context(|| format!("failed to create {}", base_path.display()))?;
        let (segments, window, cases) = load(&base_path, &limits)
            .await
            .context("failed to load the payments ledger")?;
        info!(
            "[payments-ledger] Initialized at {:?}: {} segment(s), {} row(s) in memory",
            base_path,
            segments.len(),
            window.rows.len()
        );
        Ok(Self {
            dir: base_path,
            limits,
            inner: Mutex::new(Inner {
                window,
                segments,
                cases,
                ..Inner::default()
            }),
            writing: tokio::sync::Mutex::new(()),
            updating: tokio::sync::Mutex::new(()),
            reads: tokio::sync::Semaphore::new(CONCURRENT_SEGMENT_READS),
        })
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Appends one row in memory; [`Self::flush`] writes it to its segment. A
    /// row id must be a version 7 UUID and is never recorded twice.
    pub fn record(
        &self,
        row: PaymentLedgerRow,
        tenant_id: Option<String>,
    ) -> anyhow::Result<()> {
        if Segment::of_row_id(&row.id).is_none() {
            bail!("ledger row id is not a time-ordered (version 7) UUID");
        }
        let stored = Arc::new(StoredLedgerRow { row, tenant_id });
        let mut inner = self.inner();
        if inner
            .window
            .by_id
            .contains_key(&stored.row.id)
        {
            bail!("ledger row {} is already recorded", stored.row.id);
        }
        inner
            .window
            .insert(stored.clone(), self.limits.window_rows);
        if inner.pending.len() < self.limits.pending_rows {
            inner
                .pending
                .push_back(stored);
        } else {
            inner.unwritten += 1;
            crate::metrics::backends::prometheus::track_payment_ledger_unwritten_row();
        }
        Ok(())
    }

    /// Records one row and writes it to its segment before returning. When the
    /// write fails the row is queued for the next flush and the error returned.
    pub async fn record_durable(
        &self,
        row: PaymentLedgerRow,
        tenant_id: Option<String>,
    ) -> anyhow::Result<()> {
        if Segment::of_row_id(&row.id).is_none() {
            bail!("ledger row id is not a time-ordered (version 7) UUID");
        }
        let stored = Arc::new(StoredLedgerRow { row, tenant_id });
        {
            let mut inner = self.inner();
            if inner
                .window
                .by_id
                .contains_key(&stored.row.id)
            {
                bail!("ledger row {} is already recorded", stored.row.id);
            }
            inner
                .window
                .insert(stored.clone(), self.limits.window_rows);
        }
        self.write_now(stored, self.limits.segment_bytes)
            .await
    }

    /// Applies `change` to the row with `id`, stamps `updated_at` and writes the
    /// new version to the row's segment before returning it.
    pub async fn update(
        &self,
        id: &str,
        change: impl FnOnce(&mut PaymentLedgerRow),
    ) -> anyhow::Result<PaymentLedgerRow> {
        let _updating = self.updating.lock().await;
        let Some((mut row, tenant_id)) = self.get(id).await else {
            bail!("ledger row {id} is not recorded");
        };
        change(&mut row);
        row.id = id.to_string();
        row.updated_at = Some(Utc::now());
        let stored = Arc::new(StoredLedgerRow { row: row.clone(), tenant_id });
        self.inner()
            .window
            .replace(stored.clone());
        self.write_now(stored, u64::MAX)
            .await?;
        Ok(row)
    }

    /// The rows in the window that `keep` admits, with their tenants, oldest first.
    pub fn rows_where(
        &self,
        keep: impl Fn(&PaymentLedgerRow) -> bool,
    ) -> Vec<(PaymentLedgerRow, Option<String>)> {
        self.inner()
            .window
            .rows
            .iter()
            .filter(|stored| keep(&stored.row))
            .map(|stored| (stored.row.clone(), stored.tenant_id.clone()))
            .collect()
    }

    /// Writes one row version to the segment its id names. A new row is held to
    /// `max_bytes`; a change to a recorded row passes `u64::MAX`, so a full
    /// segment never loses the outcome of a payment.
    async fn write_now(
        &self,
        stored: Arc<StoredLedgerRow>,
        max_bytes: u64,
    ) -> anyhow::Result<()> {
        let Some(segment) = Segment::of_row_id(&stored.row.id) else {
            bail!("ledger row id is not a time-ordered (version 7) UUID");
        };
        let _writing = self.writing.lock().await;
        if !self.dir.is_dir() {
            create_owner_only_dir(&self.dir).with_context(|| format!("failed to create {}", self.dir.display()))?;
        }
        let size = self
            .inner()
            .segments
            .get(&segment)
            .copied()
            .unwrap_or(0);
        let written = append_rows(
            &self
                .dir
                .join(segment.file_name()),
            std::slice::from_ref(&stored),
            size,
            max_bytes,
        )
        .await
        .and_then(|appended| {
            if appended.skipped > 0 {
                bail!("segment {} is full", segment.file_name());
            }
            Ok(appended)
        });
        match written {
            Ok(appended) => {
                *self
                    .inner()
                    .segments
                    .entry(segment)
                    .or_default() += appended.bytes;
                self.index_cases(std::slice::from_ref(&stored))
                    .await;
                Ok(())
            }
            Err(e) => {
                crate::metrics::backends::prometheus::track_payment_ledger_unwritten_row();
                let mut inner = self.inner();
                if inner.pending.len() < self.limits.pending_rows {
                    inner
                        .pending
                        .push_back(stored);
                } else {
                    inner.unwritten += 1;
                }
                Err(e.context("failed to write a payment row to the disk; it is queued for the next flush"))
            }
        }
    }

    /// Rows in the window that match `filter` and that `visible(tenant_id,
    /// surface_id)` admits, newest first and capped at `filter.limit`, with the
    /// count of matching rows before the cap. Only the window is searched and
    /// only the returned rows are copied.
    pub fn list(
        &self,
        filter: &LedgerFilter,
        visible: impl Fn(Option<&str>, &str) -> bool,
    ) -> (Vec<PaymentLedgerRow>, usize) {
        let newest_first: Vec<Arc<StoredLedgerRow>> = self
            .inner()
            .window
            .rows
            .iter()
            .rev()
            .cloned()
            .collect();
        let mut rows = Vec::new();
        let mut total = 0;
        for stored in newest_first {
            if filter.matches(&stored.row) && visible(stored.tenant_id.as_deref(), &stored.row.surface_id) {
                total += 1;
                if rows.len() < filter.limit {
                    rows.push(stored.row.clone());
                }
            }
        }
        (rows, total)
    }

    /// How many rows in the window `keep(row, tenant_id)` admits, by outcome.
    pub fn count_by_outcome(
        &self,
        keep: impl Fn(&PaymentLedgerRow, Option<&str>) -> bool,
    ) -> std::collections::BTreeMap<super::LedgerOutcome, usize> {
        let mut counts = std::collections::BTreeMap::new();
        for stored in self
            .inner()
            .window
            .rows
            .iter()
        {
            if keep(&stored.row, stored.tenant_id.as_deref()) {
                *counts
                    .entry(stored.row.outcome)
                    .or_insert(0) += 1;
            }
        }
        counts
    }

    /// Whether any row in the window satisfies `keep(row, tenant_id)`.
    pub fn any_row(
        &self,
        keep: impl Fn(&PaymentLedgerRow, Option<&str>) -> bool,
    ) -> bool {
        self.inner()
            .window
            .rows
            .iter()
            .any(|stored| keep(&stored.row, stored.tenant_id.as_deref()))
    }

    /// The tenant of every surface with a row in the window.
    pub fn surface_tenants(&self) -> HashMap<String, Option<String>> {
        self.inner()
            .window
            .rows
            .iter()
            .map(|stored| (stored.row.surface_id.clone(), stored.tenant_id.clone()))
            .collect()
    }

    /// The row with `id` and its tenant: from the window, or else from the one
    /// segment its id names.
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<(PaymentLedgerRow, Option<String>)> {
        let segment = Segment::of_row_id(id)?;
        {
            let inner = self.inner();
            if let Some(stored) = inner.window.by_id.get(id) {
                return Some((stored.row.clone(), stored.tenant_id.clone()));
            }
            if !inner
                .segments
                .contains_key(&segment)
            {
                return None;
            }
        }
        let _permit = self
            .reads
            .acquire()
            .await
            .ok()?;
        read_row(
            &self
                .dir
                .join(segment.file_name()),
            id,
        )
        .await
    }

    /// The row last recorded for review case `case_id`, wherever it is: the
    /// window, or the segment the case index names.
    pub async fn row_for_case(
        &self,
        case_id: &str,
    ) -> Option<(PaymentLedgerRow, Option<String>)> {
        let row_id = self
            .inner()
            .cases
            .get(case_id)?
            .clone();
        self.get(&row_id)
            .await
            .filter(|(row, _)| row.case_id.as_deref() == Some(case_id))
    }

    /// Names the rows of `written` that carry a case id in the case index. A
    /// failed write is logged and retried with the next version of the row.
    async fn index_cases(
        &self,
        written: &[Arc<StoredLedgerRow>],
    ) {
        let entries: Vec<CaseEntry> = {
            let inner = self.inner();
            written
                .iter()
                .filter_map(|stored| {
                    let case_id = stored.row.case_id.as_ref()?;
                    (inner.cases.get(case_id) != Some(&stored.row.id)).then(|| CaseEntry {
                        case_id: case_id.clone(),
                        row_id: stored.row.id.clone(),
                    })
                })
                .collect()
        };
        if entries.is_empty() {
            return;
        }
        match append_case_entries(&self.dir.join(CASE_INDEX_FILE), &entries, true).await {
            Ok(()) => {
                let mut inner = self.inner();
                for entry in entries {
                    inner
                        .cases
                        .insert(entry.case_id, entry.row_id);
                }
            }
            Err(e) => warn!(error = %e, "[payments-ledger] Failed to write the case index"),
        }
    }

    /// Writes the rows recorded since the last write to their segments, one
    /// buffered write and one sync per segment, then keeps the ledger within its
    /// size bound.
    pub async fn flush(&self) {
        let _writing = self.writing.lock().await;
        self.write_pending().await;
    }

    async fn write_pending(&self) {
        let (batch, unwritten) = {
            let mut inner = self.inner();
            (std::mem::take(&mut inner.pending), std::mem::take(&mut inner.unwritten))
        };
        if unwritten > 0 {
            warn!(
                "[payments-ledger] {unwritten} row(s) were not queued for the disk because the writer was behind; \
                 they are served from memory until restart"
            );
        }
        let mut by_segment: BTreeMap<Segment, Vec<Arc<StoredLedgerRow>>> = BTreeMap::new();
        for stored in batch {
            if let Some(segment) = Segment::of_row_id(&stored.row.id) {
                by_segment
                    .entry(segment)
                    .or_default()
                    .push(stored);
            }
        }
        let mut failed = Vec::new();
        for (segment, rows) in by_segment {
            let size = self
                .inner()
                .segments
                .get(&segment)
                .copied()
                .unwrap_or(0);
            match append_rows(
                &self
                    .dir
                    .join(segment.file_name()),
                &rows,
                size,
                self.limits.segment_bytes,
            )
            .await
            {
                Ok(appended) => {
                    if appended.skipped > 0 {
                        warn!(
                            "[payments-ledger] Segment {} is full: {} row(s) are served from memory only",
                            segment.file_name(),
                            appended.skipped
                        );
                    }
                    if appended.bytes > 0 {
                        *self
                            .inner()
                            .segments
                            .entry(segment)
                            .or_default() += appended.bytes;
                        self.index_cases(&rows).await;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "[payments-ledger] Failed to write {} row(s); retrying on the next pass", rows.len());
                    failed.extend(rows);
                }
            }
        }
        if !failed.is_empty() {
            let mut inner = self.inner();
            for stored in failed.into_iter().rev() {
                inner
                    .pending
                    .push_front(stored);
            }
            while inner.pending.len() > self.limits.pending_rows {
                inner.pending.pop_back();
                inner.unwritten += 1;
            }
        }
        self.enforce_size().await;
    }

    /// Deletes the oldest segments while the ledger is over its size bound,
    /// keeping the newest.
    async fn enforce_size(&self) {
        loop {
            let oldest = {
                let inner = self.inner();
                let total: u64 = inner.segments.values().sum();
                match inner.segments.keys().next() {
                    Some(oldest) if total > self.limits.ledger_bytes && inner.segments.len() > 1 => *oldest,
                    _ => return,
                }
            };
            warn!(
                "[payments-ledger] The ledger is over {} bytes; removing the oldest segment {}",
                self.limits.ledger_bytes,
                oldest.file_name()
            );
            if !self
                .remove_segment(oldest)
                .await
            {
                return;
            }
        }
    }

    async fn remove_segment(
        &self,
        segment: Segment,
    ) -> bool {
        match tokio::fs::remove_file(
            self.dir
                .join(segment.file_name()),
        )
        .await
        {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(error = %e, segment = %segment.file_name(), "[payments-ledger] Failed to remove a segment");
                return false;
            }
        }
        self.inner()
            .segments
            .remove(&segment);
        true
    }

    /// Deletes the segments that end before `now - max_age` and drops older
    /// rows from the window; returns how many segments were deleted. A segment
    /// that still holds rows inside `max_age` is kept whole.
    pub async fn cleanup_older_than(
        &self,
        max_age: Duration,
    ) -> usize {
        let _writing = self.writing.lock().await;
        let cutoff = Utc::now() - max_age;
        let first_kept = Segment::at(cutoff);
        let expired: Vec<Segment> = self
            .inner()
            .segments
            .keys()
            .copied()
            .take_while(|segment| *segment < first_kept)
            .collect();
        let mut removed = 0;
        for segment in expired {
            if self
                .remove_segment(segment)
                .await
            {
                removed += 1;
            }
        }
        self.inner()
            .window
            .drop_older_than(cutoff);
        removed
    }

    /// Rebuilds the window from the segments on disk, after writing what this
    /// node still holds, so a node that has just become Active serves the rows
    /// its predecessor wrote.
    pub async fn reload_from_disk(&self) {
        let _writing = self.writing.lock().await;
        self.write_pending().await;
        match load(&self.dir, &self.limits).await {
            Ok((segments, window, cases)) => {
                let mut inner = self.inner();
                inner.segments = segments;
                inner.cases = cases;
                inner.window = window;
                let pending: Vec<_> = inner
                    .pending
                    .iter()
                    .cloned()
                    .collect();
                for stored in pending {
                    inner
                        .window
                        .insert(stored, self.limits.window_rows);
                }
            }
            Err(e) => {
                warn!(error = %e, "[payments-ledger] Failed to reload the ledger from disk; keeping what is in memory")
            }
        }
    }
}

enum Line {
    End,
    Row,
    Skipped,
}

/// Reads the next line of a segment into `line` (without its newline). A line
/// longer than [`MAX_LINE_BYTES`] is discarded through its newline, so a damaged
/// file cannot make a reader allocate without bound.
async fn next_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> std::io::Result<Line> {
    line.clear();
    let read = (&mut *reader)
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', line)
        .await?;
    if read == 0 {
        return Ok(Line::End);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(Line::Row);
    }
    if line.len() <= MAX_LINE_BYTES {
        return Ok(Line::Row);
    }
    line.clear();
    let mut discarded = Vec::new();
    loop {
        discarded.clear();
        let read = (&mut *reader)
            .take(MAX_LINE_BYTES as u64)
            .read_until(b'\n', &mut discarded)
            .await?;
        if read == 0 || discarded.last() == Some(&b'\n') {
            return Ok(Line::Skipped);
        }
    }
}

async fn read_row(
    path: &Path,
    id: &str,
) -> Option<(PaymentLedgerRow, Option<String>)> {
    let mut reader = BufReader::with_capacity(
        SEGMENT_READ_BUFFER_BYTES,
        tokio::fs::File::open(path)
            .await
            .ok()?,
    );
    let mut line = Vec::new();
    let mut found = None;
    loop {
        match next_line(&mut reader, &mut line)
            .await
            .ok()?
        {
            Line::End => return found,
            Line::Skipped => continue,
            Line::Row => {}
        }
        if !line
            .windows(id.len())
            .any(|window| window == id.as_bytes())
        {
            continue;
        }
        if let Ok(stored) = serde_json::from_slice::<StoredLedgerRow>(&line)
            && stored.row.id == id
        {
            found = Some((stored.row, stored.tenant_id));
        }
    }
}

/// The last `keep` rows of a segment that parse; damaged lines are skipped.
async fn read_tail(
    path: &Path,
    keep: usize,
) -> std::io::Result<Vec<StoredLedgerRow>> {
    let mut reader = BufReader::with_capacity(SEGMENT_READ_BUFFER_BYTES, tokio::fs::File::open(path).await?);
    let mut line = Vec::new();
    let mut tail = VecDeque::new();
    let mut damaged = 0u64;
    loop {
        match next_line(&mut reader, &mut line).await? {
            Line::End => break,
            Line::Skipped => damaged += 1,
            Line::Row => match serde_json::from_slice::<StoredLedgerRow>(&line) {
                Ok(stored) if Segment::of_row_id(&stored.row.id).is_some() => {
                    if tail.len() == keep {
                        tail.pop_front();
                    }
                    tail.push_back(stored);
                }
                _ => damaged += 1,
            },
        }
    }
    if damaged > 0 {
        warn!("[payments-ledger] Skipped {damaged} unreadable line(s) in {}", path.display());
    }
    Ok(tail.into())
}

/// The rows of the segment at `path` whose last version still awaits settlement.
async fn read_open(path: &Path) -> std::io::Result<Vec<StoredLedgerRow>> {
    let mut reader = BufReader::with_capacity(SEGMENT_READ_BUFFER_BYTES, tokio::fs::File::open(path).await?);
    let mut line = Vec::new();
    let mut open: HashMap<String, StoredLedgerRow> = HashMap::new();
    loop {
        match next_line(&mut reader, &mut line).await? {
            Line::End => break,
            Line::Skipped => {}
            Line::Row => {
                if let Ok(stored) = serde_json::from_slice::<StoredLedgerRow>(&line) {
                    if awaits_settlement(&stored.row) {
                        open.insert(stored.row.id.clone(), stored);
                    } else {
                        open.remove(&stored.row.id);
                    }
                }
            }
        }
    }
    Ok(open.into_values().collect())
}

/// The case ids and row ids of the segment at `path`, in write order.
async fn read_cases(path: &Path) -> std::io::Result<Vec<CaseEntry>> {
    let mut reader = BufReader::with_capacity(SEGMENT_READ_BUFFER_BYTES, tokio::fs::File::open(path).await?);
    let mut line = Vec::new();
    let mut entries = Vec::new();
    loop {
        match next_line(&mut reader, &mut line).await? {
            Line::End => return Ok(entries),
            Line::Skipped => {}
            Line::Row => {
                if let Ok(stored) = serde_json::from_slice::<StoredLedgerRow>(&line)
                    && let Some(case_id) = stored.row.case_id
                {
                    entries.push(CaseEntry { case_id, row_id: stored.row.id });
                }
            }
        }
    }
}

/// Appends `entries` to the case index at `path` with one write and one sync,
/// or replaces the file with them when `append` is false.
async fn append_case_entries(
    path: &Path,
    entries: &[CaseEntry],
    append: bool,
) -> anyhow::Result<()> {
    let mut buffer = Vec::new();
    for entry in entries {
        serde_json::to_writer(&mut buffer, entry).context("failed to serialise a case index entry")?;
        buffer.push(b'\n');
    }
    let target = if append {
        path.to_path_buf()
    } else {
        path.with_extension("jsonl.tmp")
    };
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(append)
        .write(true)
        .truncate(!append)
        .mode(OWNER_ONLY_FILE)
        .open(&target)
        .await
        .with_context(|| format!("failed to open {}", target.display()))?;
    file.write_all(&buffer)
        .await?;
    file.flush().await?;
    file.sync_data().await?;
    if !append {
        tokio::fs::rename(&target, path)
            .await
            .with_context(|| format!("failed to replace {}", path.display()))?;
    }
    Ok(())
}

/// The case index in `dir`, without entries whose segment is gone. A missing
/// index is rebuilt from the segments of the last [`OPEN_ROWS_LOOKBACK`], and a
/// rebuilt or pruned one is written back.
async fn load_case_index(
    dir: &Path,
    segments: &BTreeMap<Segment, u64>,
) -> std::io::Result<HashMap<String, String>> {
    let path = dir.join(CASE_INDEX_FILE);
    let mut entries = Vec::new();
    let mut rewrite = false;
    match tokio::fs::File::open(&path).await {
        Ok(file) => {
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            loop {
                match next_line(&mut reader, &mut line).await? {
                    Line::End => break,
                    Line::Skipped => rewrite = true,
                    Line::Row => match serde_json::from_slice::<CaseEntry>(&line) {
                        Ok(entry) => entries.push(entry),
                        Err(_) => rewrite = true,
                    },
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let lookback = Segment::at(Utc::now() - OPEN_ROWS_LOOKBACK);
            for segment in segments
                .keys()
                .filter(|segment| **segment >= lookback)
            {
                match read_cases(&dir.join(segment.file_name())).await {
                    Ok(found) => entries.extend(found),
                    Err(e) => {
                        warn!(error = %e, segment = %segment.file_name(), "[payments-ledger] Failed to read a segment")
                    }
                }
            }
            if !entries.is_empty() {
                rewrite = true;
                info!("[payments-ledger] Rebuilt the case index from the segments: {} entr(y/ies)", entries.len());
            }
        }
        Err(e) => return Err(e),
    }
    let mut cases = HashMap::new();
    for entry in entries {
        if Segment::of_row_id(&entry.row_id).is_some_and(|segment| segments.contains_key(&segment)) {
            cases.insert(entry.case_id, entry.row_id);
        } else {
            rewrite = true;
        }
    }
    if rewrite {
        let kept: Vec<CaseEntry> = cases
            .iter()
            .map(|(case_id, row_id)| CaseEntry {
                case_id: case_id.clone(),
                row_id: row_id.clone(),
            })
            .collect();
        if let Err(e) = append_case_entries(&path, &kept, false).await {
            warn!(error = %e, "[payments-ledger] Failed to write the case index");
        }
    }
    Ok(cases)
}

struct Appended {
    bytes: u64,
    skipped: usize,
}

/// Appends `rows` to the segment at `path` with one write and one sync, leaving
/// out the rows that would take it past `max_bytes`.
async fn append_rows(
    path: &Path,
    rows: &[Arc<StoredLedgerRow>],
    size: u64,
    max_bytes: u64,
) -> anyhow::Result<Appended> {
    let mut buffer = Vec::new();
    let mut skipped = 0;
    for stored in rows {
        let mut line = serde_json::to_vec(stored.as_ref()).context("failed to serialise a ledger row")?;
        line.push(b'\n');
        if size.saturating_add((buffer.len() + line.len()) as u64) > max_bytes {
            skipped += 1;
        } else {
            buffer.extend_from_slice(&line);
        }
    }
    if buffer.is_empty() {
        return Ok(Appended { bytes: 0, skipped });
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(OWNER_ONLY_FILE)
        .open(path)
        .await
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(&buffer)
        .await?;
    file.flush().await?;
    file.sync_data().await?;
    Ok(Appended {
        bytes: buffer.len() as u64,
        skipped,
    })
}

/// The segments in `dir`, a window of the newest rows they hold and the case index.
async fn load(
    dir: &Path,
    limits: &Limits,
) -> std::io::Result<(BTreeMap<Segment, u64>, Window, HashMap<String, String>)> {
    let mut segments = BTreeMap::new();
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        if let Some(segment) = name
            .to_str()
            .and_then(Segment::parse_file_name)
        {
            segments.insert(segment, entry.metadata().await?.len());
        }
    }
    let mut chunks = Vec::new();
    let mut held = 0;
    for segment in segments.keys().rev() {
        if held >= limits.window_rows {
            break;
        }
        match read_tail(&dir.join(segment.file_name()), limits.window_rows - held).await {
            Ok(rows) => {
                held += rows.len();
                chunks.push(rows);
            }
            Err(e) => warn!(error = %e, segment = %segment.file_name(), "[payments-ledger] Failed to read a segment"),
        }
    }
    let lookback = Segment::at(Utc::now() - OPEN_ROWS_LOOKBACK);
    let mut open = Vec::new();
    for segment in segments
        .keys()
        .filter(|segment| **segment >= lookback)
    {
        match read_open(&dir.join(segment.file_name())).await {
            Ok(rows) => open.extend(rows),
            Err(e) => warn!(error = %e, segment = %segment.file_name(), "[payments-ledger] Failed to read a segment"),
        }
    }
    let mut rows: Vec<StoredLedgerRow> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for stored in open.into_iter().chain(
        chunks
            .into_iter()
            .rev()
            .flatten(),
    ) {
        match at.get(&stored.row.id) {
            Some(&position) => rows[position] = stored,
            None => {
                at.insert(stored.row.id.clone(), rows.len());
                rows.push(stored);
            }
        }
    }
    rows.sort_by_key(|stored| stored.row.created_at);
    let mut window = Window::default();
    for stored in rows {
        window.insert(Arc::new(stored), limits.window_rows);
    }
    let cases = load_case_index(dir, &segments).await?;
    Ok((segments, window, cases))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments_ledger::LedgerOutcome;
    use crate::payments_ledger::tests::{all, ids, row, row_in_one_segment};

    async fn store_in(dir: &Path) -> DelegatedPaymentStore {
        DelegatedPaymentStore::new(dir.to_path_buf())
            .await
            .unwrap()
    }

    fn small(limits: impl FnOnce(&mut Limits)) -> Limits {
        let mut small = Limits::default();
        limits(&mut small);
        small
    }

    async fn store_with(
        dir: &Path,
        limits: Limits,
    ) -> DelegatedPaymentStore {
        DelegatedPaymentStore::with_limits(dir.to_path_buf(), limits)
            .await
            .unwrap()
    }

    fn segment_files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with(SEGMENT_PREFIX))
            .collect();
        names.sort();
        names
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn recording_writes_nothing_until_the_flush_and_then_one_segment_holds_every_row() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let rows: Vec<_> = (0..5)
            .map(|second| row_in_one_segment("s-1", LedgerOutcome::Paid, second))
            .collect();
        for r in &rows {
            store
                .record(r.clone(), None)
                .unwrap();
        }
        assert!(segment_files(dir.path()).is_empty(), "recording is an in-memory append");

        store.flush().await;
        let files = segment_files(dir.path());
        assert_eq!(files.len(), 1, "{files:?}");
        let written = lines(&dir.path().join(&files[0]));
        assert_eq!(written.len(), 5, "one line per row in one file, not one file per row");
        for (line, r) in written
            .iter()
            .zip(rows.iter())
        {
            assert!(line.starts_with(&format!("{{\"id\":\"{}\"", r.id)), "{line}");
        }
        store.flush().await;
        assert_eq!(lines(&dir.path().join(&files[0])).len(), 5, "a second flush has nothing to write");
    }

    #[tokio::test]
    async fn the_directory_and_segments_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp();
        let ledger = dir.path().join("ledger");
        let store = store_in(&ledger).await;
        store
            .record(row("s-1", LedgerOutcome::Paid, Duration::zero()), None)
            .unwrap();
        store.flush().await;

        let mode = |path: &Path| {
            std::fs::metadata(path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&ledger), 0o700);
        assert_eq!(mode(&ledger.join(&segment_files(&ledger)[0])), 0o600);
    }

    #[tokio::test]
    async fn rows_recorded_in_different_hours_go_to_different_segments() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let now = row("s-1", LedgerOutcome::Paid, Duration::zero());
        let earlier = row("s-1", LedgerOutcome::Paid, Duration::hours(3));
        store
            .record(now.clone(), None)
            .unwrap();
        store
            .record(earlier.clone(), None)
            .unwrap();
        store.flush().await;

        let files = segment_files(dir.path());
        assert_eq!(files.len(), 2, "{files:?}");
        assert_eq!(
            files[0],
            Segment::of_row_id(&earlier.id)
                .unwrap()
                .file_name()
        );
        assert_eq!(
            files[1],
            Segment::of_row_id(&now.id)
                .unwrap()
                .file_name()
        );
        assert_eq!(lines(&dir.path().join(&files[0])).len(), 1);
    }

    #[tokio::test]
    async fn a_row_is_never_recorded_twice_and_needs_a_time_ordered_id() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let first = row("s-1", LedgerOutcome::Challenge, Duration::zero());
        store
            .record(first.clone(), None)
            .unwrap();
        let mut replay = first.clone();
        replay.outcome = LedgerOutcome::Paid;
        assert!(
            store
                .record(replay, None)
                .is_err()
        );
        assert_eq!(
            store
                .get(&first.id)
                .await
                .map(|(r, _)| r.outcome),
            Some(LedgerOutcome::Challenge)
        );

        for bad in [
            "../escape".to_string(),
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::now_v7()
                .to_string()
                .to_uppercase(),
            uuid::Uuid::now_v7()
                .simple()
                .to_string(),
        ] {
            let mut bad_id = row("s-1", LedgerOutcome::Paid, Duration::zero());
            bad_id.id = bad.clone();
            assert!(
                store
                    .record(bad_id, None)
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn rows_list_newest_first_with_filters_limit_and_total() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let oldest = row("s-1", LedgerOutcome::Paid, Duration::minutes(3));
        let middle = row("s-2", LedgerOutcome::Rejected, Duration::minutes(2));
        let newest = row("s-1", LedgerOutcome::Rejected, Duration::minutes(1));
        for r in [&middle, &newest, &oldest] {
            store
                .record(r.clone(), None)
                .unwrap();
        }

        let (rows, total) = store.list(&LedgerFilter::default(), all);
        assert_eq!((ids(&rows), total), (vec![newest.id.as_str(), middle.id.as_str(), oldest.id.as_str()], 3));

        let by_surface = LedgerFilter {
            surface_id: Some("s-1".to_string()),
            ..LedgerFilter::default()
        };
        let (rows, total) = store.list(&by_surface, all);
        assert_eq!((ids(&rows), total), (vec![newest.id.as_str(), oldest.id.as_str()], 2));

        let by_outcome = LedgerFilter {
            outcome: Some(LedgerOutcome::Rejected),
            ..LedgerFilter::default()
        };
        let (rows, total) = store.list(&by_outcome, all);
        assert_eq!((ids(&rows), total), (vec![newest.id.as_str(), middle.id.as_str()], 2));

        let none = LedgerFilter {
            surface_id: Some("s-2".to_string()),
            outcome: Some(LedgerOutcome::Paid),
            ..LedgerFilter::default()
        };
        assert_eq!(store.list(&none, all), (vec![], 0));

        let limited = LedgerFilter {
            limit: 1,
            ..LedgerFilter::default()
        };
        let (rows, total) = store.list(&limited, all);
        assert_eq!((ids(&rows), total), (vec![newest.id.as_str()], 3));
    }

    #[tokio::test]
    async fn rows_recorded_out_of_order_still_list_newest_first_and_load_that_way() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let newer = row_in_one_segment("s-1", LedgerOutcome::Paid, 5);
        let older = row_in_one_segment("s-1", LedgerOutcome::Paid, 1);
        store
            .record(newer.clone(), None)
            .unwrap();
        store
            .record(older.clone(), None)
            .unwrap();
        let (rows, _) = store.list(&LedgerFilter::default(), all);
        assert_eq!(ids(&rows), vec![newer.id.as_str(), older.id.as_str()]);

        store.flush().await;
        let written = lines(
            &dir.path()
                .join(&segment_files(dir.path())[0]),
        );
        assert!(written[0].contains(&newer.id), "the file keeps the order the rows were recorded in");
        drop(store);
        let (reloaded, _) = store_in(dir.path())
            .await
            .list(&LedgerFilter::default(), all);
        assert_eq!(ids(&reloaded), vec![newer.id.as_str(), older.id.as_str()]);
    }

    #[tokio::test]
    async fn the_visibility_predicate_excludes_rows_from_list_and_total() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let own = row("s-1", LedgerOutcome::Paid, Duration::zero());
        let other = row("s-2", LedgerOutcome::Paid, Duration::zero());
        store
            .record(own.clone(), Some("tenant-a".to_string()))
            .unwrap();
        store
            .record(other, Some("tenant-b".to_string()))
            .unwrap();

        let (rows, total) = store.list(&LedgerFilter::default(), |tenant, _| tenant == Some("tenant-a"));
        assert_eq!((rows, total), (vec![own], 1));
    }

    #[tokio::test]
    async fn a_recorded_row_round_trips_with_its_tenant() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let mut paid = row("s-1", LedgerOutcome::Paid, Duration::zero());
        paid.rail = Some(crate::payments_ledger::LedgerRail::Mpp);
        paid.amount = Some("0.25".to_string());
        store
            .record(paid.clone(), Some("tenant-a".to_string()))
            .unwrap();

        assert_eq!(store.get(&paid.id).await, Some((paid.clone(), Some("tenant-a".to_string()))));
        assert_eq!(
            store
                .get(&uuid::Uuid::now_v7().to_string())
                .await,
            None
        );
        assert_eq!(
            store
                .get(&uuid::Uuid::new_v4().to_string())
                .await,
            None
        );
        assert_eq!(store.get("not-an-id").await, None);
    }

    #[tokio::test]
    async fn rows_persist_across_a_reload_from_disk() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let held = row("s-1", LedgerOutcome::Held, Duration::zero());
        let paid = row("s-2", LedgerOutcome::Paid, Duration::minutes(1));
        store
            .record(held.clone(), Some("tenant-a".to_string()))
            .unwrap();
        store
            .record(paid.clone(), None)
            .unwrap();
        store.flush().await;
        drop(store);

        let reloaded = store_in(dir.path()).await;
        assert_eq!(reloaded.get(&held.id).await, Some((held.clone(), Some("tenant-a".to_string()))));
        let (rows, total) = reloaded.list(&LedgerFilter::default(), all);
        assert_eq!((ids(&rows), total), (vec![held.id.as_str(), paid.id.as_str()], 2));
    }

    #[tokio::test]
    async fn a_row_that_left_the_window_is_still_read_from_its_segment() {
        let dir = temp();
        let store = store_with(dir.path(), small(|l| l.window_rows = 3)).await;
        let rows: Vec<_> = (0..6)
            .map(|minute| row("s-1", LedgerOutcome::Paid, Duration::minutes(minute)))
            .collect();
        for r in &rows {
            store
                .record(r.clone(), None)
                .unwrap();
        }
        store.flush().await;

        let (listed, total) = store.list(&LedgerFilter::default(), all);
        assert_eq!(listed.len(), 3, "the window holds the newest rows only");
        assert_eq!(total, 3);
        let oldest = &rows[5];
        assert!(
            !listed
                .iter()
                .any(|r| r.id == oldest.id)
        );
        assert_eq!(store.get(&oldest.id).await, Some((oldest.clone(), None)));
        assert_eq!(
            store
                .get(&uuid::Uuid::now_v7().to_string())
                .await,
            None,
            "an id the segment does not hold is not found"
        );
    }

    #[tokio::test]
    async fn the_window_a_restart_loads_is_the_newest_rows() {
        let dir = temp();
        let writer = store_in(dir.path()).await;
        let rows: Vec<_> = (0..5)
            .map(|hour| row("s-1", LedgerOutcome::Paid, Duration::hours(hour * 2)))
            .collect();
        for r in &rows {
            writer
                .record(r.clone(), None)
                .unwrap();
        }
        writer.flush().await;
        drop(writer);

        let reloaded = store_with(dir.path(), small(|l| l.window_rows = 2)).await;
        let (listed, _) = reloaded.list(&LedgerFilter::default(), all);
        assert_eq!(ids(&listed), vec![rows[0].id.as_str(), rows[1].id.as_str()]);
        assert_eq!(
            reloaded
                .get(&rows[4].id)
                .await,
            Some((rows[4].clone(), None))
        );
    }

    #[tokio::test]
    async fn a_held_row_stays_in_the_window_and_a_restart_loads_it_past_the_window() {
        let dir = temp();
        let writer = store_with(dir.path(), small(|l| l.window_rows = 2)).await;
        let held = row("s-1", LedgerOutcome::Authorized, Duration::hours(6));
        let paid: Vec<_> = (0..3)
            .map(|hour| row("s-1", LedgerOutcome::Paid, Duration::hours(hour)))
            .collect();
        writer
            .record_durable(held.clone(), None)
            .await
            .unwrap();
        for r in &paid {
            writer
                .record_durable(r.clone(), None)
                .await
                .unwrap();
        }
        let (listed, _) = writer.list(&LedgerFilter::default(), all);
        assert!(ids(&listed).contains(&held.id.as_str()), "a held row is not evicted");
        assert!(!ids(&listed).contains(&paid[2].id.as_str()), "the oldest settled row is");
        drop(writer);

        let reloaded = store_with(dir.path(), small(|l| l.window_rows = 2)).await;
        let open = reloaded.rows_where(awaits_settlement);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].0.id, held.id);

        reloaded
            .update(&held.id, |row| row.outcome = LedgerOutcome::Voided)
            .await
            .unwrap();
        drop(reloaded);
        let settled = store_with(dir.path(), small(|l| l.window_rows = 2)).await;
        assert!(
            settled
                .rows_where(awaits_settlement)
                .is_empty(),
            "a settled row is not reloaded as open"
        );
    }

    #[tokio::test]
    async fn an_update_to_a_full_segment_is_still_written_and_concurrent_updates_both_apply() {
        let dir = temp();
        let store = store_with(dir.path(), small(|l| l.segment_bytes = 700)).await;
        let held = row_in_one_segment("s-1", LedgerOutcome::Authorized, 0);
        store
            .record_durable(held.clone(), None)
            .await
            .unwrap();
        let filler = row_in_one_segment("s-1", LedgerOutcome::Paid, 1);
        let _ = store
            .record_durable(filler, None)
            .await;

        let (first, second) = tokio::join!(
            store.update(&held.id, |row| row.settle_attempts += 1),
            store.update(&held.id, |row| row.settle_attempts += 1),
        );
        first.unwrap();
        second.unwrap();
        drop(store);
        let reloaded = store_in(dir.path()).await;
        assert_eq!(
            reloaded
                .get(&held.id)
                .await
                .unwrap()
                .0
                .settle_attempts,
            2
        );
    }

    #[tokio::test]
    async fn a_torn_or_damaged_line_costs_only_that_line() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let first = row_in_one_segment("s-1", LedgerOutcome::Paid, 1);
        let second = row_in_one_segment("s-1", LedgerOutcome::Paid, 2);
        store
            .record(first.clone(), None)
            .unwrap();
        store
            .record(second.clone(), None)
            .unwrap();
        store.flush().await;
        let path = dir
            .path()
            .join(&segment_files(dir.path())[0]);
        let mut content = std::fs::read(&path).unwrap();
        content.extend_from_slice(b"not json\n");
        content.extend_from_slice(&vec![b'x'; MAX_LINE_BYTES * 3]);
        content.extend_from_slice(b"\n{\"id\":\"cut off by a crash");
        std::fs::write(&path, content).unwrap();
        drop(store);

        let reloaded = store_in(dir.path()).await;
        let (listed, total) = reloaded.list(&LedgerFilter::default(), all);
        assert_eq!((ids(&listed), total), (vec![second.id.as_str(), first.id.as_str()], 2));
        let unknown = uuid::Uuid::now_v7().to_string();
        assert_eq!(read_row(&path, &unknown).await, None, "a damaged file is read to its end without failing");
    }

    #[tokio::test]
    async fn cleanup_deletes_whole_expired_segments_and_drops_expired_rows_from_the_window() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let expired = row("s-1", LedgerOutcome::Paid, Duration::days(8));
        let kept = row("s-1", LedgerOutcome::Paid, Duration::days(6));
        let fresh = row("s-1", LedgerOutcome::Paid, Duration::zero());
        for r in [&expired, &kept, &fresh] {
            store
                .record(r.clone(), None)
                .unwrap();
        }
        store.flush().await;
        assert_eq!(segment_files(dir.path()).len(), 3);

        assert_eq!(
            store
                .cleanup_older_than(Duration::days(7))
                .await,
            1
        );
        assert_eq!(
            segment_files(dir.path()),
            vec![
                Segment::of_row_id(&kept.id)
                    .unwrap()
                    .file_name(),
                Segment::of_row_id(&fresh.id)
                    .unwrap()
                    .file_name()
            ]
        );
        assert_eq!(store.get(&expired.id).await, None);
        assert_eq!(store.get(&kept.id).await, Some((kept, None)));
        assert_eq!(
            store
                .cleanup_older_than(Duration::days(7))
                .await,
            0
        );
        let (listed, _) = store.list(&LedgerFilter::default(), all);
        assert_eq!(listed.len(), 2, "the expired row is no longer served");
    }

    #[tokio::test]
    async fn the_oldest_segments_go_first_when_the_ledger_outgrows_its_bound() {
        let dir = temp();
        let store = store_with(dir.path(), small(|l| l.ledger_bytes = 1)).await;
        let old = row("s-1", LedgerOutcome::Paid, Duration::hours(5));
        let middle = row("s-1", LedgerOutcome::Paid, Duration::hours(3));
        let newest = row("s-1", LedgerOutcome::Paid, Duration::zero());
        for r in [&old, &middle, &newest] {
            store
                .record(r.clone(), None)
                .unwrap();
        }
        store.flush().await;

        assert_eq!(
            segment_files(dir.path()),
            vec![
                Segment::of_row_id(&newest.id)
                    .unwrap()
                    .file_name()
            ],
            "only the newest segment is kept, whatever its size"
        );
        assert_eq!(
            store
                .get(&old.id)
                .await
                .map(|(r, _)| r.id),
            Some(old.id.clone()),
            "still served from memory"
        );
    }

    #[tokio::test]
    async fn a_full_segment_takes_no_more_rows_but_the_window_still_serves_them() {
        let dir = temp();
        let store = store_with(dir.path(), small(|l| l.segment_bytes = 700)).await;
        let rows: Vec<_> = (0..5)
            .map(|second| row_in_one_segment("s-1", LedgerOutcome::Paid, second))
            .collect();
        for r in &rows {
            store
                .record(r.clone(), None)
                .unwrap();
        }
        store.flush().await;

        let path = dir
            .path()
            .join(&segment_files(dir.path())[0]);
        let written = lines(&path).len();
        assert!((1..5).contains(&written), "{written}");
        assert!(
            std::fs::metadata(&path)
                .unwrap()
                .len()
                <= 700
        );
        let (listed, total) = store.list(&LedgerFilter::default(), all);
        assert_eq!((listed.len(), total), (5, 5));
    }

    #[tokio::test]
    async fn rows_past_the_pending_bound_are_served_from_memory_only() {
        let dir = temp();
        let store = store_with(dir.path(), small(|l| l.pending_rows = 2)).await;
        for second in 0..4 {
            store
                .record(row_in_one_segment("s-1", LedgerOutcome::Paid, second), None)
                .unwrap();
        }
        store.flush().await;
        assert_eq!(
            lines(
                &dir.path()
                    .join(&segment_files(dir.path())[0])
            )
            .len(),
            2
        );
        assert_eq!(
            store
                .list(&LedgerFilter::default(), all)
                .1,
            4
        );
    }

    #[tokio::test]
    async fn a_failed_write_is_retried_on_the_next_flush() {
        let dir = temp();
        let store = store_in(dir.path()).await;
        let paid = row("s-1", LedgerOutcome::Paid, Duration::zero());
        store
            .record(paid.clone(), None)
            .unwrap();
        let blocker = dir.path().join(
            Segment::of_row_id(&paid.id)
                .unwrap()
                .file_name(),
        );
        std::fs::create_dir(&blocker).unwrap();

        store.flush().await;
        assert!(blocker.is_dir(), "the write could not happen");
        assert_eq!(store.get(&paid.id).await, Some((paid.clone(), None)), "the row is still served");

        std::fs::remove_dir(&blocker).unwrap();
        store.flush().await;
        assert_eq!(lines(&blocker).len(), 1, "the retried write lands in the segment");
    }

    #[tokio::test]
    async fn concurrent_recording_loses_and_duplicates_nothing() {
        let dir = temp();
        let store = Arc::new(store_in(dir.path()).await);
        let mut tasks = Vec::new();
        for task in 0..8 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                (0..50)
                    .map(|i| {
                        let r = row(&format!("s-{task}"), LedgerOutcome::Challenge, Duration::milliseconds(i));
                        store
                            .record(r.clone(), None)
                            .unwrap();
                        r.id
                    })
                    .collect::<Vec<_>>()
            }));
        }
        let mut expected = Vec::new();
        for task in tasks {
            expected.extend(task.await.unwrap());
        }
        store.flush().await;

        let mut written: Vec<String> = Vec::new();
        for file in segment_files(dir.path()) {
            written.extend(lines(&dir.path().join(file)));
        }
        assert_eq!(written.len(), 400);
        let mut found: Vec<String> = written
            .iter()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        found.sort();
        expected.sort();
        assert_eq!(found, expected);
    }

    #[tokio::test]
    async fn a_reload_serves_rows_another_writer_added_and_keeps_unwritten_ones() {
        let dir = temp();
        let promoted = store_in(dir.path()).await;
        let before = row_in_one_segment("s-1", LedgerOutcome::Paid, 0);
        promoted
            .record(before.clone(), None)
            .unwrap();
        promoted.flush().await;

        let predecessor = store_in(dir.path()).await;
        let written_by_predecessor = row_in_one_segment("s-1", LedgerOutcome::Held, 60);
        predecessor
            .record(written_by_predecessor.clone(), None)
            .unwrap();
        predecessor.flush().await;
        let unwritten = row_in_one_segment("s-1", LedgerOutcome::Challenge, 120);
        promoted
            .record(unwritten.clone(), None)
            .unwrap();
        let (before_reload, _) = promoted.list(&LedgerFilter::default(), all);
        assert_eq!(ids(&before_reload), vec![unwritten.id.as_str(), before.id.as_str()]);
        assert_eq!(
            promoted
                .get(&written_by_predecessor.id)
                .await,
            Some((written_by_predecessor.clone(), None)),
            "a row outside the window is read from its segment"
        );

        promoted
            .reload_from_disk()
            .await;
        let (listed, _) = promoted.list(&LedgerFilter::default(), all);
        assert_eq!(
            ids(&listed),
            vec![
                unwritten.id.as_str(),
                written_by_predecessor
                    .id
                    .as_str(),
                before.id.as_str()
            ]
        );
    }

    #[test]
    fn segment_names_round_trip_and_reject_anything_else() {
        let segment = Segment::at(Utc::now());
        assert_eq!(Segment::parse_file_name(&segment.file_name()), Some(segment));
        assert_eq!(
            Segment::at(DateTime::from_timestamp(1_700_000_000, 0).unwrap()).file_name(),
            "ledger-2023-11-14T22.jsonl"
        );
        for other in [
            "ledger-2023-11-14T22.json",
            "ledger-2023-11-14.jsonl",
            "ledger-2023-11-14T22:00.jsonl",
            "ledger-2023-13-14T22.jsonl",
            "ledger-2023-11-14T25.jsonl",
            "x-2023-11-14T22.jsonl",
            "ledger-2023-11-14T22.jsonl.tmp",
        ] {
            assert_eq!(Segment::parse_file_name(other), None, "{other}");
        }
    }

    #[test]
    fn a_row_id_names_the_hour_of_its_segment() {
        let id = uuid::Uuid::new_v7(uuid::Timestamp::from_unix(uuid::NoContext, 1_700_000_000, 0)).to_string();
        assert_eq!(Segment::of_row_id(&id).map(Segment::file_name), Some("ledger-2023-11-14T22.jsonl".to_string()));
        assert_eq!(Segment::of_row_id(&uuid::Uuid::new_v4().to_string()), None);
        assert_eq!(Segment::of_row_id("nope"), None);
    }
}
