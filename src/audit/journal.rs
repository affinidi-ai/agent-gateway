//! The durable journal every produced audit record is appended to before any
//! sink reads it.
//!
//! Damage to the journal never stops it. On open, the writer continues after
//! the last line of the newest segment that parses: a partial line left by a
//! crash, and any unreadable lines after the last good one, are cut off and
//! logged, and a segment with no readable line is emptied and keeps its first
//! seq. Files in the journal directory that are not segments are logged and
//! ignored. Readers skip unreadable lines anywhere else (see
//! [`crate::audit::cursors::read_entries`]).

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::metrics::backends::prometheus::track_audit_records_lost;

use crate::audit::registry::SinkId;
use crate::delegation_vault::audit::DelegationAuditEvent;

/// One journalled record and the sinks it is addressed to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub seq: u64,
    pub recipients: Vec<SinkId>,
    pub record: DelegationAuditEvent,
}

impl JournalEntry {
    /// The entry on one journal line (without its newline), or `None` when
    /// the line is not a whole entry.
    pub fn parse(line: &[u8]) -> Option<JournalEntry> {
        serde_json::from_slice(line).ok()
    }
}

/// A produced record waiting to be journalled.
#[derive(Debug)]
pub struct Pending {
    pub recipients: Vec<SinkId>,
    pub record: DelegationAuditEvent,
}

#[derive(Serialize)]
struct EntryRef<'a> {
    seq: u64,
    recipients: &'a [SinkId],
    record: &'a DelegationAuditEvent,
}

const SEGMENT_EXTENSION: &str = "jsonl";

fn segment_name(first_seq: u64) -> String {
    format!("{first_seq:020}.{SEGMENT_EXTENSION}")
}

pub fn segment_first_seq(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let digits = name.strip_suffix(&format!(".{SEGMENT_EXTENSION}"))?;
    (digits.len() == 20
        && digits
            .bytes()
            .all(|b| b.is_ascii_digit()))
    .then(|| digits.parse().ok())
    .flatten()
}

/// Journal segment files in `dir`, oldest first.
pub fn segment_paths(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if segment_first_seq(&path).is_some() {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// The newest whole line of `content` that parses, and the length of
/// `content` up to the end of that line (0 when no line parses).
fn last_readable_entry(content: &[u8]) -> (usize, Option<JournalEntry>) {
    let mut end = content
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |newline| newline + 1);
    while end > 0 {
        let start = content[..end - 1]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |newline| newline + 1);
        if let Some(entry) = JournalEntry::parse(&content[start..end - 1]) {
            return (end, Some(entry));
        }
        end = start;
    }
    (0, None)
}

/// Logs files in the journal directory that are neither segments nor the
/// cursors file, so a stray or misnamed file is noticed rather than read.
fn warn_about_foreign_files(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let cursors = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("cursors.json"));
        if segment_first_seq(&path).is_none() && !cursors {
            tracing::warn!(path = %path.display(), "Ignoring a file in the audit journal directory that is not a segment");
        }
    }
    Ok(())
}

/// Appends records to the journal segments in `dir`, one writer per journal.
pub struct JournalWriter {
    dir: PathBuf,
    segment_max_bytes: u64,
    next_seq: u64,
    segment: Option<(File, u64)>,
}

impl JournalWriter {
    /// Opens the journal and continues after the last readable entry of the
    /// newest segment. Whatever follows that entry, a partial line left by a
    /// crash or lines that do not parse, is cut off and logged. Files in `dir`
    /// that are not segments are left in place and ignored.
    pub fn open(
        dir: &Path,
        segment_max_bytes: u64,
    ) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut writer = Self {
            dir: dir.to_path_buf(),
            segment_max_bytes,
            next_seq: 1,
            segment: None,
        };
        warn_about_foreign_files(dir)?;
        if let Some(last) = segment_paths(dir)?.pop() {
            writer.resume(&last)?;
        }
        Ok(writer)
    }

    fn resume(
        &mut self,
        path: &Path,
    ) -> io::Result<()> {
        let content = fs::read(path)?;
        let (keep, last) = last_readable_entry(&content);
        let file = OpenOptions::new()
            .append(true)
            .open(path)?;
        if keep < content.len() {
            file.set_len(keep as u64)?;
            file.sync_data()?;
            tracing::warn!(
                segment = %path.display(),
                discarded_bytes = content.len() - keep,
                "Cut unreadable lines off the end of the audit journal"
            );
        }
        self.next_seq = match last {
            Some(entry) => entry.seq + 1,
            None => segment_first_seq(path).unwrap_or(1),
        };
        self.segment = Some((file, keep as u64));
        Ok(())
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    fn current_segment(&mut self) -> io::Result<&mut (File, u64)> {
        let full = self
            .segment
            .as_ref()
            .is_none_or(|(_, size)| *size >= self.segment_max_bytes);
        if full {
            let file = OpenOptions::new()
                .create_new(true)
                .append(true)
                .open(
                    self.dir
                        .join(segment_name(self.next_seq)),
                )?;
            File::open(&self.dir)?.sync_all()?;
            self.segment = Some((file, 0));
        }
        self.segment
            .as_mut()
            .ok_or_else(|| io::Error::other("no journal segment"))
    }

    /// Appends the batch and syncs it to disk. Returns the last `seq` written.
    /// On failure nothing from the batch is left in the journal.
    pub fn append(
        &mut self,
        batch: &[Pending],
    ) -> io::Result<Option<u64>> {
        if batch.is_empty() {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        for (seq, pending) in (self.next_seq..).zip(batch) {
            serde_json::to_writer(
                &mut bytes,
                &EntryRef {
                    seq,
                    recipients: &pending.recipients,
                    record: &pending.record,
                },
            )
            .map_err(io::Error::other)?;
            bytes.push(b'\n');
        }
        let (file, size) = self.current_segment()?;
        let written = io::Write::write_all(file, &bytes).and_then(|()| file.sync_data());
        if let Err(e) = written {
            let _ = file.set_len(*size);
            return Err(e);
        }
        *size += bytes.len() as u64;
        let count = batch.len() as u64;
        self.next_seq += count;
        Ok(Some(self.next_seq - 1))
    }
}

pub trait JournalAppend {
    fn append(
        &mut self,
        batch: &[Pending],
    ) -> io::Result<Option<u64>>;
}

impl JournalAppend for JournalWriter {
    fn append(
        &mut self,
        batch: &[Pending],
    ) -> io::Result<Option<u64>> {
        JournalWriter::append(self, batch)
    }
}

#[derive(Debug, Clone)]
pub struct WriterConfig {
    pub batch_max: usize,
    pub batch_window: Duration,
    pub pending_cap: usize,
    pub retry_initial: Duration,
    pub retry_max: Duration,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            batch_max: 256,
            batch_window: Duration::from_millis(5),
            pending_cap: 10_000,
            retry_initial: Duration::from_millis(50),
            retry_max: Duration::from_secs(5),
        }
    }
}

/// Runs the writer on its own thread: batches records from `rx`, appends them,
/// and publishes the last durable `seq` on `durable`. A failed append is
/// retried with backoff while records keep arriving; beyond
/// `config.pending_cap` the oldest waiting records are discarded and counted.
/// Ends once every sender is gone and nothing is waiting, returning how many
/// records were discarded.
pub fn spawn_writer<W: JournalAppend + Send + 'static>(
    mut writer: W,
    rx: Receiver<Pending>,
    durable: tokio::sync::watch::Sender<u64>,
    config: WriterConfig,
) -> io::Result<std::thread::JoinHandle<u64>> {
    std::thread::Builder::new()
        .name("audit-journal".to_string())
        .spawn(move || {
            let mut waiting: VecDeque<Pending> = VecDeque::new();
            let mut open = true;
            let mut lost = 0u64;
            let mut backoff = config.retry_initial;
            loop {
                if waiting.is_empty() {
                    match open
                        .then(|| collect_batch(&rx, config.batch_max, config.batch_window))
                        .flatten()
                    {
                        Some(batch) => waiting.extend(batch),
                        None => return lost,
                    }
                } else if open {
                    open = drain_ready(&rx, &mut waiting);
                }

                let overflow = waiting
                    .len()
                    .saturating_sub(config.pending_cap);
                if overflow > 0 {
                    waiting.drain(..overflow);
                    lost += overflow as u64;
                    track_audit_records_lost("journal_write", overflow as u64);
                    tracing::error!(records = overflow, "Discarded audit records the journal could not write");
                }

                let count = waiting
                    .len()
                    .min(config.batch_max);
                match writer.append(&waiting.make_contiguous()[..count]) {
                    Ok(last) => {
                        waiting.drain(..count);
                        if let Some(last) = last {
                            durable.send_replace(last);
                        }
                        backoff = config.retry_initial;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, waiting = waiting.len(), "Failed to append audit records to the journal; retrying");
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(config.retry_max);
                    }
                }
            }
        })
}

/// Moves every record already sent into `waiting`. False once every sender is gone.
fn drain_ready(
    rx: &Receiver<Pending>,
    waiting: &mut VecDeque<Pending>,
) -> bool {
    loop {
        match rx.try_recv() {
            Ok(pending) => waiting.push_back(pending),
            Err(TryRecvError::Empty) => return true,
            Err(TryRecvError::Disconnected) => return false,
        }
    }
}

/// Waits for one record, then gathers more until `max` records or `window`
/// has passed. `None` once every sender is gone and nothing is left.
pub fn collect_batch(
    rx: &Receiver<Pending>,
    max: usize,
    window: Duration,
) -> Option<Vec<Pending>> {
    let mut batch = vec![rx.recv().ok()?];
    let deadline = Instant::now() + window;
    while batch.len() < max {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(pending) => batch.push(pending),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
        }
    }
    Some(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::audit::{DelegationAuditAction, audit_event};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use tempfile::TempDir;

    fn pending(sink: &str) -> Pending {
        Pending {
            recipients: vec![SinkId::Integration(sink.to_string())],
            record: audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None),
        }
    }

    fn read_all(dir: &Path) -> Vec<JournalEntry> {
        segment_paths(dir)
            .unwrap()
            .into_iter()
            .flat_map(|path| {
                fs::read_to_string(path)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<JournalEntry>(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn appended_records_get_increasing_seqs_in_order() {
        let dir = TempDir::new().unwrap();
        let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
        assert_eq!(writer.next_seq(), 1);

        let last = writer
            .append(&[pending("a"), pending("b")])
            .unwrap();
        assert_eq!(last, Some(2));
        let last = writer
            .append(&[pending("c")])
            .unwrap();
        assert_eq!(last, Some(3));

        let entries = read_all(dir.path());
        let seqs: Vec<u64> = entries
            .iter()
            .map(|entry| entry.seq)
            .collect();
        assert_eq!(seqs, vec![1, 2, 3]);
        assert_eq!(entries[1].recipients, vec![SinkId::Integration("b".to_string())]);
    }

    #[test]
    fn empty_batch_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
        assert_eq!(writer.append(&[]).unwrap(), None);
        assert_eq!(writer.next_seq(), 1);
        assert!(read_all(dir.path()).is_empty());
    }

    #[test]
    fn a_full_segment_rolls_to_a_new_file_named_by_its_first_seq() {
        let dir = TempDir::new().unwrap();
        let mut writer = JournalWriter::open(dir.path(), 1).unwrap();
        writer
            .append(&[pending("a")])
            .unwrap();
        writer
            .append(&[pending("b")])
            .unwrap();

        let names: Vec<String> = segment_paths(dir.path())
            .unwrap()
            .iter()
            .map(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, vec!["00000000000000000001.jsonl", "00000000000000000002.jsonl"]);
        assert_eq!(read_all(dir.path()).len(), 2);
    }

    #[test]
    fn reopening_continues_after_the_last_seq() {
        let dir = TempDir::new().unwrap();
        {
            let mut writer = JournalWriter::open(dir.path(), 1).unwrap();
            writer
                .append(&[pending("a"), pending("b")])
                .unwrap();
            writer
                .append(&[pending("c")])
                .unwrap();
        }
        let mut writer = JournalWriter::open(dir.path(), 1).unwrap();
        assert_eq!(writer.next_seq(), 4);
        assert_eq!(
            writer
                .append(&[pending("d")])
                .unwrap(),
            Some(4)
        );
    }

    #[test]
    fn a_partial_last_line_is_cut_off_on_open() {
        let dir = TempDir::new().unwrap();
        {
            let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
            writer
                .append(&[pending("a")])
                .unwrap();
        }
        let segment = segment_paths(dir.path()).unwrap()[0].clone();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap();
        io::Write::write_all(&mut file, b"{\"seq\":2,\"recip").unwrap();

        let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
        assert_eq!(writer.next_seq(), 2);
        writer
            .append(&[pending("b")])
            .unwrap();
        let seqs: Vec<u64> = read_all(dir.path())
            .iter()
            .map(|entry| entry.seq)
            .collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    fn append_raw(
        path: &Path,
        bytes: &[u8],
    ) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap();
        io::Write::write_all(&mut file, bytes).unwrap();
    }

    fn seqs_in(dir: &Path) -> Vec<u64> {
        read_all(dir)
            .iter()
            .map(|entry| entry.seq)
            .collect()
    }

    #[test]
    fn a_garbled_last_line_is_cut_off_on_open_and_the_next_append_takes_its_place() {
        let dir = TempDir::new().unwrap();
        {
            let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
            writer
                .append(&[pending("a"), pending("b")])
                .unwrap();
        }
        let segment = segment_paths(dir.path()).unwrap()[0].clone();
        let good_len = fs::metadata(&segment)
            .unwrap()
            .len();
        append_raw(&segment, b"{\"seq\":3,garbled}\n");

        let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
        assert_eq!(writer.next_seq(), 3);
        assert_eq!(
            fs::metadata(&segment)
                .unwrap()
                .len(),
            good_len
        );
        assert_eq!(
            writer
                .append(&[pending("c")])
                .unwrap(),
            Some(3)
        );
        assert_eq!(seqs_in(dir.path()), vec![1, 2, 3]);
    }

    #[test]
    fn a_segment_with_no_readable_line_is_emptied_and_keeps_its_first_seq() {
        let dir = TempDir::new().unwrap();
        let segment = dir
            .path()
            .join(segment_name(5));
        fs::write(&segment, b"garbage\nmore garbage\n").unwrap();

        let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
        assert_eq!(writer.next_seq(), 5);
        assert_eq!(
            fs::metadata(&segment)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            writer
                .append(&[pending("a")])
                .unwrap(),
            Some(5)
        );
        assert_eq!(seqs_in(dir.path()), vec![5]);
    }

    #[test]
    fn a_partial_line_after_a_garbled_line_are_both_cut_off_on_open() {
        let dir = TempDir::new().unwrap();
        {
            let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
            writer
                .append(&[pending("a")])
                .unwrap();
        }
        let segment = segment_paths(dir.path()).unwrap()[0].clone();
        let good_len = fs::metadata(&segment)
            .unwrap()
            .len();
        append_raw(&segment, b"not json\n{\"seq\":3,\"recip");

        let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
        assert_eq!(writer.next_seq(), 2);
        assert_eq!(
            fs::metadata(&segment)
                .unwrap()
                .len(),
            good_len
        );
        writer
            .append(&[pending("b")])
            .unwrap();
        assert_eq!(seqs_in(dir.path()), vec![1, 2]);
    }

    #[test]
    fn files_that_are_not_segments_do_not_stop_the_journal_opening() {
        let dir = TempDir::new().unwrap();
        {
            let mut writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
            writer
                .append(&[pending("a")])
                .unwrap();
        }
        fs::write(
            dir.path()
                .join("00000000000000000001.jsonl.bak"),
            "garbage",
        )
        .unwrap();
        fs::write(dir.path().join("notes.jsonl"), "garbage").unwrap();
        // Twenty digits, but beyond u64: not a segment name.
        fs::write(
            dir.path()
                .join("99999999999999999999.jsonl"),
            "garbage\n",
        )
        .unwrap();
        fs::create_dir(
            dir.path()
                .join("00000000000000000009.jsonl.d"),
        )
        .unwrap();

        let writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
        assert_eq!(writer.next_seq(), 2);
        assert_eq!(seqs_in(dir.path()), vec![1]);
    }

    #[test]
    fn a_journal_line_parses_only_when_it_is_a_whole_entry() {
        let mut line = serde_json::to_vec(&EntryRef {
            seq: 7,
            recipients: &[SinkId::AuditLog],
            record: &pending("a").record,
        })
        .unwrap();
        assert_eq!(JournalEntry::parse(&line).map(|entry| entry.seq), Some(7));
        line.truncate(line.len() / 2);
        assert!(JournalEntry::parse(&line).is_none());
        assert!(JournalEntry::parse(b"").is_none());
    }

    #[test]
    fn segment_paths_lists_only_journal_segments_in_seq_order() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path()
                .join("00000000000000000010.jsonl"),
            "",
        )
        .unwrap();
        fs::write(
            dir.path()
                .join("00000000000000000002.jsonl"),
            "",
        )
        .unwrap();
        fs::write(
            dir.path()
                .join("cursors.json"),
            "{}",
        )
        .unwrap();
        fs::write(dir.path().join("notes.txt"), "").unwrap();
        let names: Vec<String> = segment_paths(dir.path())
            .unwrap()
            .iter()
            .map(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, vec!["00000000000000000002.jsonl", "00000000000000000010.jsonl"]);
    }

    #[test]
    fn a_batch_closes_at_its_size_limit() {
        let (tx, rx) = mpsc::channel();
        for sink in ["a", "b", "c"] {
            tx.send(pending(sink))
                .unwrap();
        }
        let batch = collect_batch(&rx, 2, Duration::from_secs(5)).unwrap();
        assert_eq!(batch.len(), 2);
        let batch = collect_batch(&rx, 2, Duration::from_millis(10)).unwrap();
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn a_batch_closes_when_its_window_passes() {
        let (tx, rx) = mpsc::channel();
        tx.send(pending("a")).unwrap();
        let started = Instant::now();
        let batch = collect_batch(&rx, 256, Duration::from_millis(20)).unwrap();
        assert_eq!(batch.len(), 1);
        assert!(started.elapsed() >= Duration::from_millis(20));
        drop(tx);
    }

    #[test]
    fn the_writer_thread_publishes_a_seq_once_its_record_is_on_disk() {
        let dir = TempDir::new().unwrap();
        let writer = JournalWriter::open(dir.path(), 1 << 20).unwrap();
        let (tx, rx) = mpsc::channel();
        let (durable_tx, mut durable_rx) = tokio::sync::watch::channel(0);
        let handle = spawn_writer(writer, rx, durable_tx, WriterConfig::default()).unwrap();

        for sink in ["a", "b", "c"] {
            tx.send(pending(sink))
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while *durable_rx.borrow_and_update() < 3 {
            assert!(Instant::now() < deadline, "seq 3 was never published");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(read_all(dir.path()).len(), 3);

        drop(tx);
        assert_eq!(handle.join().unwrap(), 0);
    }

    /// Records what it is asked to append and fails while `failing` is set.
    #[derive(Clone, Default)]
    struct FlakyJournal {
        failing: Arc<AtomicBool>,
        failures: Arc<AtomicUsize>,
        written: Arc<Mutex<Vec<String>>>,
    }

    impl JournalAppend for FlakyJournal {
        fn append(
            &mut self,
            batch: &[Pending],
        ) -> io::Result<Option<u64>> {
            if self
                .failing
                .load(Ordering::SeqCst)
            {
                self.failures
                    .fetch_add(1, Ordering::SeqCst);
                return Err(io::Error::other("disk full"));
            }
            let mut written = self.written.lock().unwrap();
            for pending in batch {
                match &pending.recipients[0] {
                    SinkId::Integration(name) => written.push(name.clone()),
                    SinkId::AuditLog => written.push("audit_log".to_string()),
                }
            }
            Ok((!batch.is_empty()).then_some(written.len() as u64))
        }
    }

    fn fast_retry(pending_cap: usize) -> WriterConfig {
        WriterConfig {
            pending_cap,
            retry_initial: Duration::from_millis(1),
            retry_max: Duration::from_millis(2),
            ..WriterConfig::default()
        }
    }

    fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "condition not met in time");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn records_are_written_once_a_failing_journal_recovers() {
        let journal = FlakyJournal::default();
        journal
            .failing
            .store(true, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        let (durable_tx, durable_rx) = tokio::sync::watch::channel(0);
        let handle = spawn_writer(journal.clone(), rx, durable_tx, fast_retry(100)).unwrap();

        tx.send(pending("a")).unwrap();
        tx.send(pending("b")).unwrap();
        wait_until(|| {
            journal
                .failures
                .load(Ordering::SeqCst)
                >= 3
        });
        assert_eq!(*durable_rx.borrow(), 0);

        journal
            .failing
            .store(false, Ordering::SeqCst);
        drop(tx);
        assert_eq!(handle.join().unwrap(), 0);
        assert_eq!(
            *journal
                .written
                .lock()
                .unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(*durable_rx.borrow(), 2);
    }

    #[test]
    fn records_beyond_the_pending_cap_are_discarded_oldest_first_and_counted() {
        let journal = FlakyJournal::default();
        journal
            .failing
            .store(true, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        let (durable_tx, _durable_rx) = tokio::sync::watch::channel(0);
        let handle = spawn_writer(journal.clone(), rx, durable_tx, fast_retry(5)).unwrap();

        let names: Vec<String> = (0..8)
            .map(|n| n.to_string())
            .collect();
        for name in &names {
            tx.send(pending(name))
                .unwrap();
        }
        let failures = journal
            .failures
            .load(Ordering::SeqCst);
        wait_until(|| {
            journal
                .failures
                .load(Ordering::SeqCst)
                >= failures + 3
        });

        journal
            .failing
            .store(false, Ordering::SeqCst);
        drop(tx);
        assert_eq!(handle.join().unwrap(), 3);
        assert_eq!(
            *journal
                .written
                .lock()
                .unwrap(),
            names[3..].to_vec()
        );
    }

    #[test]
    fn handing_off_records_never_waits_on_a_failing_journal() {
        let journal = FlakyJournal::default();
        journal
            .failing
            .store(true, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        let (durable_tx, _durable_rx) = tokio::sync::watch::channel(0);
        let handle = spawn_writer(journal.clone(), rx, durable_tx, fast_retry(100)).unwrap();

        let started = Instant::now();
        for _ in 0..20_000 {
            tx.send(pending("a")).unwrap();
        }
        assert!(started.elapsed() < Duration::from_secs(1));

        journal
            .failing
            .store(false, Ordering::SeqCst);
        drop(tx);
        let lost = handle.join().unwrap();
        let written = journal
            .written
            .lock()
            .unwrap()
            .len() as u64;
        assert!(lost > 0);
        assert_eq!(lost + written, 20_000);
    }

    #[test]
    fn collecting_ends_once_every_sender_is_gone() {
        let (tx, rx) = mpsc::channel::<Pending>();
        tx.send(pending("a")).unwrap();
        drop(tx);
        assert_eq!(
            collect_batch(&rx, 256, Duration::from_millis(5))
                .unwrap()
                .len(),
            1
        );
        assert!(collect_batch(&rx, 256, Duration::from_millis(5)).is_none());
    }
}
