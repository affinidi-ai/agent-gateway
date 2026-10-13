//! Where each sink has got to in the journal, and removal of segments every
//! sink has passed.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::audit::journal::{JournalEntry, segment_first_seq, segment_paths};
use crate::audit::registry::SinkId;

/// Durable entries after `after`, up to and including `upto`, oldest first,
/// at most `limit` of them. Lines past `upto` are never parsed, so a batch
/// still being written is not read.
pub fn read_entries(
    dir: &Path,
    after: u64,
    upto: u64,
    limit: usize,
) -> io::Result<Vec<JournalEntry>> {
    let mut entries = Vec::new();
    if after >= upto || limit == 0 {
        return Ok(entries);
    }
    let segments = segment_paths(dir)?;
    let start = segments
        .iter()
        .rposition(|path| segment_first_seq(path).is_some_and(|first| first <= after + 1))
        .unwrap_or(0);
    for path in &segments[start..] {
        for line in BufReader::new(File::open(path)?).lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let entry: JournalEntry =
                serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if entry.seq <= after {
                continue;
            }
            if entry.seq > upto {
                return Ok(entries);
            }
            let reached = entry.seq == upto;
            entries.push(entry);
            if reached || entries.len() >= limit {
                return Ok(entries);
            }
        }
    }
    Ok(entries)
}

/// Deletes every segment whose entries all have a `seq` at or below
/// `passed`. The newest segment is always kept. Returns how many were deleted.
pub fn prune_segments(
    dir: &Path,
    passed: u64,
) -> io::Result<usize> {
    let segments = segment_paths(dir)?;
    let mut deleted = 0;
    for pair in segments.windows(2) {
        let next_first = segment_first_seq(&pair[1]).unwrap_or(0);
        if next_first.saturating_sub(1) > passed {
            break;
        }
        fs::remove_file(&pair[0])?;
        deleted += 1;
    }
    Ok(deleted)
}

/// Total size of the journal segments on disk.
pub fn journal_bytes(dir: &Path) -> io::Result<u64> {
    segment_paths(dir)?
        .iter()
        .try_fold(0u64, |total, path| Ok(total.saturating_add(fs::metadata(path)?.len())))
}

/// Sinks moved past the oldest segment so it can be deleted.
#[derive(Debug, PartialEq, Eq)]
pub struct BacklogSkip {
    /// The last `seq` of the oldest segment; each moved sink's new cursor.
    pub to: u64,
    /// Each moved sink and how many entries addressed to it it skips.
    pub sinks: Vec<(SinkId, u64)>,
}

/// Which sinks must move past the oldest segment so it can be deleted, and
/// how many entries addressed to each they skip. `None` while the journal
/// has a single segment, which is never deleted.
pub fn plan_backlog_skip(
    dir: &Path,
    cursors: &HashMap<SinkId, u64>,
) -> io::Result<Option<BacklogSkip>> {
    let segments = segment_paths(dir)?;
    let (Some(oldest), Some(next)) = (segments.first(), segments.get(1)) else {
        return Ok(None);
    };
    let to = segment_first_seq(next)
        .unwrap_or(1)
        .saturating_sub(1);
    let behind: Vec<(&SinkId, u64)> = cursors
        .iter()
        .filter(|(_, cursor)| **cursor < to)
        .map(|(sink, cursor)| (sink, *cursor))
        .collect();
    let mut sinks: Vec<(SinkId, u64)> = behind
        .iter()
        .map(|(sink, _)| ((*sink).clone(), 0))
        .collect();
    for line in BufReader::new(File::open(oldest)?).lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let entry: JournalEntry =
            serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        for ((sink, cursor), (_, skipped)) in behind
            .iter()
            .zip(sinks.iter_mut())
        {
            if entry.seq > *cursor
                && entry
                    .recipients
                    .contains(sink)
            {
                *skipped += 1;
            }
        }
    }
    Ok(Some(BacklogSkip { to, sinks }))
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredCursor {
    sink: SinkId,
    seq: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    parked: bool,
}

#[derive(Default)]
struct Cursors {
    /// Sinks being delivered to.
    active: HashMap<SinkId, u64>,
    /// Removed sinks, kept so one that comes back resumes where it stopped.
    /// They do not hold back pruning, and writes to them are ignored.
    parked: HashMap<SinkId, u64>,
}

/// Each sink's cursor: the `seq` of the last entry it has finished with.
pub struct CursorStore {
    path: PathBuf,
    cursors: Mutex<Cursors>,
}

const CURSORS_FILE: &str = "cursors.json";

impl CursorStore {
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join(CURSORS_FILE);
        let mut cursors = Cursors::default();
        match fs::read(&path) {
            Ok(bytes) => {
                let stored: Vec<StoredCursor> =
                    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                for cursor in stored {
                    let map = if cursor.parked {
                        &mut cursors.parked
                    } else {
                        &mut cursors.active
                    };
                    map.insert(cursor.sink, cursor.seq);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self {
            path,
            cursors: Mutex::new(cursors),
        })
    }

    pub fn get(
        &self,
        sink: &SinkId,
    ) -> Option<u64> {
        self.cursors
            .lock()
            .active
            .get(sink)
            .copied()
    }

    /// Moves the sink's cursor forward to `seq`. A cursor never moves back,
    /// and a parked sink's cursor does not move.
    pub fn set(
        &self,
        sink: &SinkId,
        seq: u64,
    ) -> io::Result<()> {
        let mut cursors = self.cursors.lock();
        if cursors
            .parked
            .contains_key(sink)
        {
            return Ok(());
        }
        let cursor = cursors
            .active
            .entry(sink.clone())
            .or_insert(seq);
        if seq < *cursor {
            return Ok(());
        }
        *cursor = seq;
        self.persist(&cursors)
    }

    /// Stops delivering to the sink, keeping its cursor for when it returns.
    pub fn park(
        &self,
        sink: &SinkId,
    ) -> io::Result<()> {
        let mut cursors = self.cursors.lock();
        let Some(seq) = cursors.active.remove(sink) else {
            return Ok(());
        };
        cursors
            .parked
            .insert(sink.clone(), seq);
        self.persist(&cursors)
    }

    /// The sink's cursor: its active one, its parked one when it returns, or
    /// the start of the journal for a sink never seen. No entry is addressed
    /// to a sink before it exists, so a new sink misses nothing.
    pub fn start(
        &self,
        sink: &SinkId,
    ) -> io::Result<u64> {
        let mut cursors = self.cursors.lock();
        if let Some(seq) = cursors.active.get(sink) {
            return Ok(*seq);
        }
        let seq = cursors
            .parked
            .remove(sink)
            .unwrap_or(0);
        cursors
            .active
            .insert(sink.clone(), seq);
        self.persist(&cursors)?;
        Ok(seq)
    }

    /// Forgets parked cursors before `seq`: what they point at is gone.
    pub fn drop_parked_before(
        &self,
        seq: u64,
    ) -> io::Result<()> {
        let mut cursors = self.cursors.lock();
        let before = cursors.parked.len();
        cursors
            .parked
            .retain(|_, parked| *parked >= seq);
        if cursors.parked.len() == before {
            return Ok(());
        }
        self.persist(&cursors)
    }

    pub fn snapshot(&self) -> HashMap<SinkId, u64> {
        self.cursors
            .lock()
            .active
            .clone()
    }

    /// Every sink being delivered to.
    pub fn sinks(&self) -> Vec<SinkId> {
        self.cursors
            .lock()
            .active
            .keys()
            .cloned()
            .collect()
    }

    /// The lowest active cursor, or `None` when there are no active sinks.
    pub fn min(&self) -> Option<u64> {
        self.cursors
            .lock()
            .active
            .values()
            .min()
            .copied()
    }

    /// Writes a temporary file, syncs it and renames it over the cursors file,
    /// so a crash leaves either the old or the new cursors.
    fn persist(
        &self,
        cursors: &Cursors,
    ) -> io::Result<()> {
        let stored: Vec<StoredCursor> = cursors
            .active
            .iter()
            .map(|(sink, seq)| (sink, seq, false))
            .chain(
                cursors
                    .parked
                    .iter()
                    .map(|(sink, seq)| (sink, seq, true)),
            )
            .map(|(sink, seq, parked)| StoredCursor {
                sink: sink.clone(),
                seq: *seq,
                parked,
            })
            .collect();
        let bytes = serde_json::to_vec(&stored).map_err(io::Error::other)?;
        let temp = self
            .path
            .with_extension("json.tmp");
        {
            let mut file = File::create(&temp)?;
            io::Write::write_all(&mut file, &bytes)?;
            file.sync_all()?;
        }
        fs::rename(&temp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::journal::{JournalWriter, Pending};
    use crate::delegation_vault::audit::{DelegationAuditAction, audit_event};
    use tempfile::TempDir;

    fn pending() -> Pending {
        Pending {
            recipients: vec![SinkId::AuditLog],
            record: audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None),
        }
    }

    fn journal(
        segment_max_bytes: u64,
        batches: &[usize],
    ) -> TempDir {
        let dir = TempDir::new().unwrap();
        let mut writer = JournalWriter::open(dir.path(), segment_max_bytes).unwrap();
        for size in batches {
            let batch: Vec<Pending> = (0..*size)
                .map(|_| pending())
                .collect();
            writer.append(&batch).unwrap();
        }
        dir
    }

    fn seqs(entries: &[JournalEntry]) -> Vec<u64> {
        entries
            .iter()
            .map(|entry| entry.seq)
            .collect()
    }

    fn integration(id: &str) -> SinkId {
        SinkId::Integration(id.to_string())
    }

    #[test]
    fn reads_entries_after_the_cursor_up_to_the_durable_seq() {
        let dir = journal(1 << 20, &[5]);
        assert_eq!(seqs(&read_entries(dir.path(), 0, 5, 100).unwrap()), vec![1, 2, 3, 4, 5]);
        assert_eq!(seqs(&read_entries(dir.path(), 2, 4, 100).unwrap()), vec![3, 4]);
        assert!(
            read_entries(dir.path(), 5, 5, 100)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn reads_at_most_the_limit() {
        let dir = journal(1 << 20, &[5]);
        assert_eq!(seqs(&read_entries(dir.path(), 1, 5, 2).unwrap()), vec![2, 3]);
    }

    #[test]
    fn reads_across_segments() {
        let dir = journal(1, &[2, 2, 2]);
        assert_eq!(
            segment_paths(dir.path())
                .unwrap()
                .len(),
            3
        );
        assert_eq!(seqs(&read_entries(dir.path(), 1, 6, 100).unwrap()), vec![2, 3, 4, 5, 6]);
        assert_eq!(seqs(&read_entries(dir.path(), 4, 6, 100).unwrap()), vec![5, 6]);
    }

    #[test]
    fn ignores_a_partial_line_beyond_the_durable_seq() {
        let dir = journal(1 << 20, &[2]);
        let segment = segment_paths(dir.path()).unwrap()[0].clone();
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(segment)
            .unwrap();
        io::Write::write_all(&mut file, b"{\"seq\":3,\"rec").unwrap();
        assert_eq!(seqs(&read_entries(dir.path(), 0, 2, 100).unwrap()), vec![1, 2]);
    }

    #[test]
    fn prunes_only_segments_every_sink_has_passed() {
        let dir = journal(1, &[2, 2, 2]);
        assert_eq!(prune_segments(dir.path(), 3).unwrap(), 1);
        assert_eq!(seqs(&read_entries(dir.path(), 2, 6, 100).unwrap()), vec![3, 4, 5, 6]);
        assert_eq!(prune_segments(dir.path(), 3).unwrap(), 0);
    }

    #[test]
    fn never_prunes_the_newest_segment() {
        let dir = journal(1, &[2, 2]);
        assert_eq!(prune_segments(dir.path(), 100).unwrap(), 1);
        assert_eq!(
            segment_paths(dir.path())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn cursors_survive_reopening() {
        let dir = TempDir::new().unwrap();
        {
            let store = CursorStore::open(dir.path()).unwrap();
            assert_eq!(store.get(&SinkId::AuditLog), None);
            store
                .set(&SinkId::AuditLog, 7)
                .unwrap();
            store
                .set(&integration("siem"), 3)
                .unwrap();
        }
        let store = CursorStore::open(dir.path()).unwrap();
        assert_eq!(store.get(&SinkId::AuditLog), Some(7));
        assert_eq!(store.get(&integration("siem")), Some(3));
        assert_eq!(store.min(), Some(3));
    }

    #[test]
    fn a_parked_cursor_no_longer_holds_back_the_minimum() {
        let dir = TempDir::new().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        assert_eq!(store.min(), None);
        store
            .set(&SinkId::AuditLog, 7)
            .unwrap();
        store
            .set(&integration("siem"), 3)
            .unwrap();
        store
            .park(&integration("siem"))
            .unwrap();
        assert_eq!(store.min(), Some(7));
        assert_eq!(store.get(&integration("siem")), None);
        assert_eq!(store.sinks(), vec![SinkId::AuditLog]);
    }

    #[test]
    fn a_parked_sink_ignores_late_cursor_writes_and_resumes_where_it_stopped() {
        let dir = TempDir::new().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        store
            .set(&integration("siem"), 3)
            .unwrap();
        store
            .park(&integration("siem"))
            .unwrap();
        store
            .set(&integration("siem"), 5)
            .unwrap();
        assert_eq!(store.get(&integration("siem")), None);

        assert_eq!(
            store
                .start(&integration("siem"))
                .unwrap(),
            3
        );
        store
            .set(&integration("siem"), 10)
            .unwrap();
        assert_eq!(store.get(&integration("siem")), Some(10));
    }

    #[test]
    fn a_parked_cursor_survives_reopening() {
        let dir = TempDir::new().unwrap();
        {
            let store = CursorStore::open(dir.path()).unwrap();
            store
                .set(&integration("siem"), 3)
                .unwrap();
            store
                .park(&integration("siem"))
                .unwrap();
        }
        let store = CursorStore::open(dir.path()).unwrap();
        assert_eq!(store.get(&integration("siem")), None);
        assert_eq!(store.min(), None);
        assert_eq!(
            store
                .start(&integration("siem"))
                .unwrap(),
            3
        );
    }

    #[test]
    fn a_new_sink_starts_at_the_beginning_of_the_journal() {
        let dir = TempDir::new().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        assert_eq!(
            store
                .start(&integration("siem"))
                .unwrap(),
            0
        );
        assert_eq!(store.get(&integration("siem")), Some(0));
    }

    #[test]
    fn starting_a_sink_that_has_a_cursor_keeps_it() {
        let dir = TempDir::new().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        store
            .set(&SinkId::AuditLog, 4)
            .unwrap();
        assert_eq!(
            store
                .start(&SinkId::AuditLog)
                .unwrap(),
            4
        );
        assert_eq!(store.get(&SinkId::AuditLog), Some(4));
    }

    #[test]
    fn parked_cursors_behind_the_oldest_entry_are_dropped() {
        let dir = TempDir::new().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        for (sink, seq) in [("old", 2), ("recent", 9)] {
            store
                .set(&integration(sink), seq)
                .unwrap();
            store
                .park(&integration(sink))
                .unwrap();
        }
        store
            .drop_parked_before(5)
            .unwrap();
        assert_eq!(
            store
                .start(&integration("old"))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .start(&integration("recent"))
                .unwrap(),
            9
        );
    }

    #[test]
    fn a_cursor_never_moves_backward() {
        let dir = TempDir::new().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        store
            .set(&SinkId::AuditLog, 7)
            .unwrap();
        store
            .set(&SinkId::AuditLog, 4)
            .unwrap();
        assert_eq!(store.get(&SinkId::AuditLog), Some(7));
    }

    #[test]
    fn journal_bytes_counts_every_segment() {
        let dir = journal(1, &[1, 1]);
        let expected: u64 = segment_paths(dir.path())
            .unwrap()
            .iter()
            .map(|path| {
                fs::metadata(path)
                    .unwrap()
                    .len()
            })
            .sum();
        assert!(expected > 0);
        assert_eq!(journal_bytes(dir.path()).unwrap(), expected);
    }

    fn journal_for(segments: &[&[&[SinkId]]]) -> TempDir {
        let dir = TempDir::new().unwrap();
        let mut writer = JournalWriter::open(dir.path(), 1).unwrap();
        for segment in segments {
            let batch: Vec<Pending> = segment
                .iter()
                .map(|recipients| Pending {
                    recipients: recipients.to_vec(),
                    record: audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None),
                })
                .collect();
            writer.append(&batch).unwrap();
        }
        dir
    }

    #[test]
    fn a_backlog_skip_moves_every_sink_still_in_the_oldest_segment() {
        let siem = integration("siem");
        let slack = integration("slack");
        let dir = journal_for(&[
            &[std::slice::from_ref(&siem), &[siem.clone(), slack.clone()], &[SinkId::AuditLog]],
            &[std::slice::from_ref(&siem)],
        ]);
        let cursors = HashMap::from([(siem.clone(), 0), (slack.clone(), 2), (SinkId::AuditLog, 3)]);

        let skip = plan_backlog_skip(dir.path(), &cursors)
            .unwrap()
            .unwrap();
        assert_eq!(skip.to, 3);
        let mut moved = skip.sinks;
        moved.sort_by_key(|(sink, _)| format!("{sink:?}"));
        assert_eq!(moved, vec![(siem, 2), (slack, 0)]);
    }

    #[test]
    fn no_backlog_skip_with_a_single_segment() {
        let dir = journal_for(&[&[&[SinkId::AuditLog]]]);
        let cursors = HashMap::from([(SinkId::AuditLog, 0)]);
        assert!(
            plan_backlog_skip(dir.path(), &cursors)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cursors_are_written_atomically() {
        let dir = TempDir::new().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        store
            .set(&SinkId::AuditLog, 7)
            .unwrap();
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, vec!["cursors.json".to_string()]);
    }
}
