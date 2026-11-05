//! The VP Audit Log on disk: rotation of the live file, the rotated history
//! beside it, and bounded walks back through that history.
//!
//! The file the Audit page reads grows with every proxied call, so both the
//! writer ([`crate::audit::audit_log_sink`]) and the reader
//! ([`crate::delegation_vault::audit::read_audit_log`]) work in bounded steps:
//! the writer rotates the live file once it reaches [`Rotation::max_bytes`] and
//! keeps [`Rotation::keep`] rotated files, and a reader takes the history one
//! line at a time through [`HistoryLines`], which never holds more than one
//! chunk of a file in memory however large the file is.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Bytes the live log may reach before it is rotated. The default of
/// `[audit] vp_audit_log_max_bytes`.
pub const LIVE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Rotated files kept beside the live log. The oldest is deleted on rotation.
/// The default of `[audit] vp_audit_log_keep`.
pub const KEEP_ROTATED: usize = 8;

/// Smallest live log size an operator may configure, one read chunk. Below it
/// a rotation costs more than the records it moves: the writer rotates under
/// the append lock on the request path, and the history becomes many tiny
/// files that a read has to open one after another.
pub const MIN_LIVE_MAX_BYTES: u64 = 64 * 1024;

/// Most bytes of the audit history one read examines, however the rotation is
/// configured. A history kept by the default rotation is well inside it, so
/// only a rotation that keeps more — a raised `vp_audit_log_max_bytes`, or a
/// `vp_audit_log_keep` of `0`, which keeps every rotated file — reaches it and
/// has its reads report the page as truncated.
pub const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

/// Bytes of a file held in memory at a time while walking it backwards.
const CHUNK_BYTES: usize = 64 * 1024;

/// Buffer a walk assembles one line in. A line that does not fit is dropped
/// rather than held — and only that line, never the records read beside it — so
/// a file damaged or edited outside the gateway cannot cost a read more memory
/// than this plus one chunk; records the gateway writes are orders of magnitude
/// smaller.
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// How the live log is rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// Bytes the live log may reach before it is rotated. `0` never rotates.
    /// Default: 8 MiB.
    pub max_bytes: u64,
    /// Rotated files kept beside the live log, oldest deleted first. `0` keeps
    /// every rotated file, so no audit record is deleted and the history grows
    /// with the appliance's request rate. Default: 8.
    pub keep: usize,
}

impl Default for Rotation {
    fn default() -> Self {
        Self {
            max_bytes: LIVE_MAX_BYTES,
            keep: KEEP_ROTATED,
        }
    }
}

/// Set once at start-up from `[audit]` in `config.toml`.
static CONFIGURED: OnceLock<Rotation> = OnceLock::new();

impl Rotation {
    /// Sets the rotation the gateway's own pipeline runs with. The first call
    /// wins, so a second start-up in one process does not change it.
    pub fn configure(rotation: Rotation) {
        let _ = CONFIGURED.set(rotation);
    }

    /// The configured rotation, or the defaults while none has been set.
    pub fn configured() -> Self {
        CONFIGURED
            .get()
            .copied()
            .unwrap_or_default()
    }

    /// Bytes of the history one read examines: the whole history this rotation
    /// keeps, so an audit page counts and searches every retained record,
    /// capped at [`MAX_SCAN_BYTES`] for a rotation that keeps everything.
    pub fn scan_budget(&self) -> u64 {
        if self.max_bytes == 0 || self.keep == 0 {
            return MAX_SCAN_BYTES;
        }
        self.max_bytes
            .saturating_mul(self.keep as u64 + 2)
            .min(MAX_SCAN_BYTES)
    }
}

/// Path of the rotated file `index` positions behind the live log; `1` is the
/// most recently rotated.
fn rotated_path(
    live: &Path,
    index: usize,
) -> PathBuf {
    let mut name = live
        .as_os_str()
        .to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

/// The positions of the rotated files beside `live`, oldest last. Taken from
/// the directory rather than by probing each position in turn, so a position
/// missing from the middle hides nothing behind it.
fn rotated_indices(live: &Path) -> Vec<usize> {
    let mut indices: Vec<usize> = Vec::new();
    let (Some(parent), Some(name)) = (live.parent(), live.file_name()) else {
        return indices;
    };
    let dir = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return indices;
    };
    let prefix = format!("{}.", name.to_string_lossy());
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(suffix) = file_name
            .to_string_lossy()
            .strip_prefix(&prefix)
            .map(str::to_string)
        else {
            continue;
        };
        // Only the name rotation itself writes is a position. `.01` and `.+1`
        // parse as 1 but are not the file `.1`, and treating them as one would
        // walk a position twice and rotate a file that is not there.
        if !is_canonical_index(&suffix) {
            continue;
        }
        if let Ok(index) = suffix.parse::<usize>() {
            indices.push(index);
        }
    }
    indices.sort_unstable();
    indices
}

/// Whether `suffix` is a position as rotation writes it: decimal digits, no
/// leading zero, no sign, at least `1`.
fn is_canonical_index(suffix: &str) -> bool {
    !suffix.is_empty()
        && !suffix.starts_with('0')
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit())
}

/// Whether a rotated file is missing from the middle of the history — a crash
/// or an I/O error during a rotation. The files behind the gap are still read;
/// a read that meets one reports partial counts, because the records of the
/// missing file are in none of them.
fn has_gap(indices: &[usize]) -> bool {
    indices
        .iter()
        .enumerate()
        .any(|(position, index)| *index != position + 1)
}

/// One file read backwards, a chunk at a time.
struct BackwardFile {
    file: fs::File,
    /// Bytes of the file before [`BackwardFile::buf`], not yet read.
    remaining: u64,
    /// Bytes read but not yet handed back, in the order they were written.
    buf: Vec<u8>,
    /// Whether the bytes still in `buf` belong to a line too long to hand back,
    /// so the rest of that line is dropped as it is reached.
    discarding: bool,
}

impl BackwardFile {
    fn new(
        file: fs::File,
        len: u64,
    ) -> Self {
        Self {
            file,
            remaining: len,
            buf: Vec::new(),
            discarding: false,
        }
    }

    /// Reads the chunk before the bytes already held.
    fn fill(&mut self) -> io::Result<()> {
        let want = self
            .remaining
            .min(CHUNK_BYTES as u64);
        let from = self.remaining - want;
        self.file
            .seek(SeekFrom::Start(from))?;
        let mut chunk = vec![0u8; want as usize];
        self.file
            .read_exact(&mut chunk)?;
        self.remaining = from;
        chunk.extend_from_slice(&self.buf);
        self.buf = chunk;
        Ok(())
    }

    /// The next line back, or `None` at the start of the file.
    fn next_line(&mut self) -> io::Result<Option<String>> {
        loop {
            if self.buf.last() == Some(&b'\n') {
                self.buf.pop();
            }
            if let Some(end) = self
                .buf
                .iter()
                .rposition(|byte| *byte == b'\n')
            {
                let line = self.buf.split_off(end + 1);
                if self.discarding {
                    self.discarding = false;
                    continue;
                }
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if self.remaining == 0 {
                let line = std::mem::take(&mut self.buf);
                if self.discarding || line.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            self.fill()?;
            if self.buf.len() > MAX_LINE_BYTES {
                // The line being assembled is everything after the last
                // newline held, so only that is dropped: the records the same
                // chunk brought in are before it and are kept.
                match self
                    .buf
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                {
                    Some(end) => {
                        self.buf.truncate(end + 1);
                        self.discarding = false;
                    }
                    None => {
                        self.buf.clear();
                        self.discarding = true;
                    }
                }
            }
        }
    }
}

/// The lines of the audit history, newest first: the live log, then back
/// through the rotated files. Only one chunk of one file is in memory at a
/// time, so a walk costs the same whatever the history has grown to.
///
/// A rotation during a walk moves the file being read to the next position
/// back. The walk looks each next file up when it reaches it, rather than from
/// a list taken at the start, and passes over a file it has already read under
/// another name, so a rotation mid-walk neither hands the same records back
/// twice nor skips the file that moved past it. It takes no lock against the
/// writer to achieve that: a walk lasts as long as the history is large, and
/// the writer's lock is taken on the request path by every record appended, so
/// holding it for a walk would stall proxy traffic.
pub struct HistoryLines {
    live: PathBuf,
    /// Position of the rotated file being read; `0` while the live log is, and
    /// before the walk starts.
    index: usize,
    started: bool,
    current: Option<BackwardFile>,
    /// `(device, inode)` of the files read so far.
    seen: std::collections::HashSet<(u64, u64)>,
    gap: bool,
}

impl HistoryLines {
    /// Walks the history of the live log at `live`.
    pub fn open(live: &Path) -> Self {
        Self {
            live: live.to_path_buf(),
            index: 0,
            started: false,
            current: None,
            seen: std::collections::HashSet::new(),
            gap: has_gap(&rotated_indices(live)),
        }
    }

    /// Whether a rotated file is missing from the middle of the history, so
    /// what the walk returns is not all of it.
    pub fn gap(&self) -> bool {
        self.gap
    }

    /// The next file back: the live log, then the rotated file at the next
    /// position that exists when the walk gets there.
    fn next_file(&mut self) -> Option<PathBuf> {
        if !self.started {
            self.started = true;
            return Some(self.live.clone());
        }
        let next = rotated_indices(&self.live)
            .into_iter()
            .find(|index| *index > self.index)?;
        self.index = next;
        Some(rotated_path(&self.live, next))
    }

    /// Opens the next file of the history, unless it is gone, is not a regular
    /// file, or is one already read under another name.
    fn open_file(
        &mut self,
        path: &Path,
    ) -> io::Result<Option<BackwardFile>> {
        // Checked before opening, not after: opening a FIFO blocks until a
        // writer appears, which would hold this walk — and the one permit
        // audit reads share — for as long as nobody writes to it.
        match fs::metadata(path) {
            Ok(data) if data.is_file() => {}
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let data = file.metadata()?;
        if !data.is_file() {
            return Ok(None);
        }
        if !self
            .seen
            .insert((data.dev(), data.ino()))
        {
            return Ok(None);
        }
        Ok(Some(BackwardFile::new(file, data.len())))
    }

    /// The next non-empty line back, or `None` at the end of the history.
    pub fn next_line(&mut self) -> io::Result<Option<String>> {
        loop {
            while self.current.is_none() {
                let Some(path) = self.next_file() else {
                    return Ok(None);
                };
                self.current = self.open_file(&path)?;
            }
            let line = self
                .current
                .as_mut()
                .map(|file| file.next_line())
                .transpose()?
                .flatten();
            match line {
                Some(line) if line.trim().is_empty() => continue,
                Some(line) => return Ok(Some(line)),
                None => self.current = None,
            }
        }
    }
}

/// Rotates the live log: each rotated file moves one position back, the live
/// log becomes `.1`, and everything past `keep` is deleted. A `keep` of `0`
/// deletes nothing, so the whole history is kept. A live log that is not there
/// is left alone, and the live log itself is never deleted.
pub fn rotate(
    live: &Path,
    keep: usize,
) -> io::Result<()> {
    if !live.exists() {
        return Ok(());
    }
    let mut indices = rotated_indices(live);
    if keep > 0 {
        for index in indices
            .iter()
            .filter(|index| **index >= keep)
        {
            fs::remove_file(rotated_path(live, *index))?;
        }
        indices.retain(|index| *index < keep);
    }
    for index in indices.into_iter().rev() {
        fs::rename(rotated_path(live, index), rotated_path(live, index + 1))?;
    }
    match fs::rename(live, rotated_path(live, 1)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn lines(count: usize) -> String {
        (0..count)
            .map(|n| format!("line-{n}\n"))
            .collect()
    }

    fn walk(live: &Path) -> Vec<String> {
        let mut lines = HistoryLines::open(live);
        let mut walked = Vec::new();
        while let Some(line) = lines.next_line().unwrap() {
            walked.push(line);
        }
        walked
    }

    #[test]
    fn a_file_is_walked_backwards_line_by_line() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, lines(3)).unwrap();

        assert_eq!(walk(&path), vec!["line-2", "line-1", "line-0"]);
    }

    #[test]
    fn a_file_longer_than_one_chunk_is_walked_whole() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let count = (CHUNK_BYTES / 8) + 100;
        fs::write(&path, lines(count)).unwrap();

        let walked = walk(&path);

        assert_eq!(walked.len(), count, "every line is handed back across the chunks");
        assert_eq!(walked[0], format!("line-{}", count - 1), "the newest line comes first");
        assert_eq!(walked[count - 1], "line-0", "the oldest line comes last");
    }

    #[test]
    fn a_line_longer_than_the_cap_is_dropped_and_the_walk_goes_on() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let huge = "x".repeat(MAX_LINE_BYTES + 1024);
        fs::write(&path, format!("line-0\n{huge}\nline-2\n")).unwrap();

        assert_eq!(walk(&path), vec!["line-2", "line-0"], "only the oversized line is left out");
    }

    #[test]
    fn the_records_beside_an_oversized_line_are_all_kept() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        // More than one chunk of records before the line, and a line long
        // enough that several fills hold nothing else, so both the "drop the
        // tail of the line" and the "keep looking for its start" steps run.
        let count = (CHUNK_BYTES / 8) * 3;
        let huge = "x".repeat(MAX_LINE_BYTES * 2 + 1024);
        fs::write(&path, format!("{}{huge}\nlast\n", lines(count))).unwrap();

        let walked = walk(&path);

        assert_eq!(walked.len(), count + 1, "every record beside the oversized line is handed back");
        assert_eq!(walked[0], "last", "the record after the oversized line");
        assert_eq!(walked[1], format!("line-{}", count - 1), "the record before it");
        assert_eq!(walked[count], "line-0", "back to the start of the file");
        assert!(
            !walked
                .iter()
                .any(|line| line.starts_with('x')),
            "no fragment of the oversized line is handed back"
        );
    }

    #[test]
    fn only_a_position_rotation_writes_is_part_of_the_history() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::write(rotated_path(&path, 1), "rotated\n").unwrap();
        for odd in ["01", "+1", "1x", "", "0"] {
            fs::write(PathBuf::from(format!("{}.{odd}", path.display())), "ignored\n").unwrap();
        }

        assert_eq!(rotated_indices(&path), vec![1], "only the canonical position counts");
        assert_eq!(walk(&path), vec!["live", "rotated"], "the odd names are not read");
    }

    #[test]
    fn a_rotated_position_that_is_not_a_regular_file_is_passed_over() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::create_dir(rotated_path(&path, 1)).unwrap();
        fs::write(rotated_path(&path, 2), "rotated\n").unwrap();

        assert_eq!(walk(&path), vec!["live", "rotated"], "the walk reads past it instead of failing");
    }

    #[test]
    fn a_log_that_is_not_there_walks_as_empty() {
        let dir = TempDir::new().unwrap();
        let walked = walk(
            &dir.path()
                .join("delegation-audit.jsonl"),
        );

        assert_eq!(walked, Vec::<String>::new());
    }

    #[test]
    fn blank_lines_are_not_handed_back() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "line-0\n\n\nline-1\n").unwrap();

        assert_eq!(walk(&path), vec!["line-1", "line-0"]);
    }

    #[test]
    fn a_walk_reads_back_through_the_rotated_files() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "newest\n").unwrap();
        fs::write(rotated_path(&path, 1), "middle\n").unwrap();
        fs::write(rotated_path(&path, 2), "oldest\n").unwrap();

        assert_eq!(walk(&path), vec!["newest", "middle", "oldest"]);
        assert!(!HistoryLines::open(&path).gap(), "the history is complete");
    }

    #[test]
    fn a_walk_reads_past_a_missing_rotated_file_and_reports_the_gap() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "newest\n").unwrap();
        fs::write(rotated_path(&path, 2), "oldest\n").unwrap();

        assert_eq!(walk(&path), vec!["newest", "oldest"], "the file behind the gap is still read");
        assert!(HistoryLines::open(&path).gap(), "the missing file is reported");
    }

    #[test]
    fn a_rotation_during_a_walk_hands_no_record_back_twice() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "older\nnewer\n").unwrap();
        fs::write(rotated_path(&path, 1), "rotated\n").unwrap();

        let mut lines = HistoryLines::open(&path);
        let mut walked = vec![
            lines
                .next_line()
                .unwrap()
                .unwrap(),
        ];
        rotate(&path, 2).unwrap();
        while let Some(line) = lines.next_line().unwrap() {
            walked.push(line);
        }

        assert_eq!(walked, vec!["newer", "older", "rotated"], "the rotated live log is recognised at its new name");
    }

    #[test]
    fn rotating_moves_each_file_back_and_drops_the_oldest() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::write(rotated_path(&path, 1), "first\n").unwrap();
        fs::write(rotated_path(&path, 2), "dropped\n").unwrap();

        rotate(&path, 2).unwrap();

        assert!(!path.exists(), "the live log is moved aside");
        assert_eq!(fs::read_to_string(rotated_path(&path, 1)).unwrap(), "live\n");
        assert_eq!(fs::read_to_string(rotated_path(&path, 2)).unwrap(), "first\n");
        assert!(!rotated_path(&path, 3).exists(), "nothing is kept past the retained count");
    }

    #[test]
    fn rotating_keeps_the_built_in_count_of_rotated_files() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        for round in 0..=KEEP_ROTATED + 2 {
            fs::write(&path, format!("round-{round}\n")).unwrap();
            rotate(&path, KEEP_ROTATED).unwrap();
        }

        let kept = rotated_indices(&path);
        assert_eq!(kept, (1..=KEEP_ROTATED).collect::<Vec<_>>(), "exactly the retained count is kept");
        let newest = KEEP_ROTATED + 2;
        assert_eq!(fs::read_to_string(rotated_path(&path, 1)).unwrap(), format!("round-{newest}\n"));
        assert_eq!(
            fs::read_to_string(rotated_path(&path, KEEP_ROTATED)).unwrap(),
            format!("round-{}\n", newest + 1 - KEEP_ROTATED),
            "the oldest retained file is the newest one minus the retained count"
        );
    }

    #[test]
    fn rotating_keeps_nothing_past_a_lowered_retained_count() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::write(rotated_path(&path, 1), "first\n").unwrap();
        fs::write(rotated_path(&path, 2), "second\n").unwrap();
        fs::write(rotated_path(&path, 3), "third\n").unwrap();

        rotate(&path, 1).unwrap();

        assert_eq!(fs::read_to_string(rotated_path(&path, 1)).unwrap(), "live\n");
        assert!(!rotated_path(&path, 2).exists());
        assert!(!rotated_path(&path, 3).exists());
    }

    #[test]
    fn rotating_deletes_the_files_past_the_retained_count_behind_a_gap() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::write(rotated_path(&path, 1), "first\n").unwrap();
        fs::write(rotated_path(&path, 4), "behind the gap\n").unwrap();

        rotate(&path, 2).unwrap();

        assert_eq!(fs::read_to_string(rotated_path(&path, 1)).unwrap(), "live\n");
        assert_eq!(fs::read_to_string(rotated_path(&path, 2)).unwrap(), "first\n");
        assert!(!rotated_path(&path, 4).exists(), "a file past the retained count is deleted even behind a gap");
    }

    #[test]
    fn rotating_with_no_retained_count_keeps_every_rotated_file() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::write(rotated_path(&path, 1), "first\n").unwrap();
        fs::write(rotated_path(&path, 2), "second\n").unwrap();

        rotate(&path, 0).unwrap();

        assert!(!path.exists(), "the live log is moved aside, never deleted");
        assert_eq!(fs::read_to_string(rotated_path(&path, 1)).unwrap(), "live\n");
        assert_eq!(fs::read_to_string(rotated_path(&path, 2)).unwrap(), "first\n");
        assert_eq!(
            fs::read_to_string(rotated_path(&path, 3)).unwrap(),
            "second\n",
            "the oldest file is moved back instead of deleted"
        );
    }

    #[test]
    fn rotating_a_log_that_is_not_there_does_nothing() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(rotated_path(&path, 1), "first\n").unwrap();

        rotate(&path, 2).unwrap();

        assert!(!path.exists());
        assert_eq!(
            fs::read_to_string(rotated_path(&path, 1)).unwrap(),
            "first\n",
            "the rotated files stay where they are, so no gap is opened"
        );
        assert!(!rotated_path(&path, 2).exists());
    }

    #[test]
    fn the_scan_budget_covers_the_whole_history_a_rotation_keeps() {
        let rotation = Rotation { max_bytes: 1024, keep: 4 };
        let keeps_everything = Rotation {
            max_bytes: LIVE_MAX_BYTES,
            keep: 0,
        };
        let never_rotates = Rotation {
            max_bytes: 0,
            keep: KEEP_ROTATED,
        };
        let larger_than_the_cap = Rotation {
            max_bytes: u64::MAX,
            keep: KEEP_ROTATED,
        };

        assert!(
            rotation.scan_budget() > rotation.max_bytes * (rotation.keep as u64 + 1),
            "a read examines every retained file"
        );
        assert_eq!(
            keeps_everything.scan_budget(),
            MAX_SCAN_BYTES,
            "a history that keeps every file is examined up to the cap"
        );
        assert_eq!(
            never_rotates.scan_budget(),
            MAX_SCAN_BYTES,
            "a live log that never rotates is examined up to the cap"
        );
        assert_eq!(
            larger_than_the_cap.scan_budget(),
            MAX_SCAN_BYTES,
            "the cap holds however large the configured history is"
        );
    }
}
