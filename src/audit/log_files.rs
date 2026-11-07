//! The VP Audit Log on disk: rotation of the live file, the rotated history
//! beside it, and bounded walks back through that history.
//!
//! The file the Audit page reads grows with every proxied call, so both the
//! writer ([`crate::audit::audit_log_sink`]) and the reader
//! ([`crate::delegation_vault::audit::read_audit_log`]) work in bounded steps:
//! the writer rotates the live file once it reaches [`Rotation::max_bytes`],
//! keeping every rotated file beside it unless [`Rotation::keep`] bounds them,
//! and a reader takes the history one line at a time through [`HistoryLines`],
//! which holds one chunk of one file plus the line it is assembling — at most
//! [`MAX_LINE_BYTES`] and two chunks — however large the file is. A read stops
//! once it has examined [`Rotation::scan_budget`] bytes of the history, so a
//! history kept in full still costs a bounded read.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use tracing::warn;

/// Bytes the live log may reach before it is rotated. The default of
/// `[audit] vp_audit_log_max_bytes`.
pub const LIVE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Rotated files kept beside the live log. `0`, the default, deletes nothing,
/// so the appliance keeps every audit record it has ever written, as it did
/// before the live log was rotated at all. A positive value deletes the oldest
/// rotated file once that many are kept. The default of
/// `[audit] vp_audit_log_keep`.
pub const KEEP_ROTATED: usize = 0;

/// Smallest live log size an operator may configure, one read chunk. Below it
/// a rotation costs more than the records it moves: the writer rotates under
/// the append lock in the audit dispatcher, so every later record waits for
/// it, and the history becomes many tiny files that a read has to open one
/// after another.
pub const MIN_LIVE_MAX_BYTES: u64 = 64 * 1024;

/// Most bytes of the audit history one read examines, however the rotation is
/// configured. The default rotation keeps every rotated file, so an appliance
/// whose history has grown past this reads only its newest 256 MiB and reports
/// the page as truncated. So does a `vp_audit_log_keep` whose retained history
/// is larger than this, a `vp_audit_log_max_bytes` of `0`, a live log that a
/// run of failed rotations has grown past it, and a log that was already
/// larger than this when rotation was first switched on.
pub const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

/// Size of the audit history an operator is told about by default, through
/// `[audit] vp_audit_log_soft_cap_bytes`. Advisory: nothing is enforced at it.
pub const HISTORY_SOFT_CAP_BYTES: u64 = 1024 * 1024 * 1024;

/// Bytes of a file held in memory at a time while walking it backwards.
const CHUNK_BYTES: usize = 64 * 1024;

/// Longest line a walk assembles. A line that does not fit is dropped rather
/// than held — and only that line, never the records read beside it — so a
/// file damaged or edited outside the gateway cannot cost a read more memory
/// than this plus the two chunks the line is measured across; records the
/// gateway writes are orders of magnitude smaller.
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// How the live log is rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// Bytes the live log may reach before it is rotated. `0` never rotates.
    /// Default: 8 MiB.
    pub max_bytes: u64,
    /// Rotated files kept beside the live log, oldest deleted first. `0`, the
    /// default, keeps every rotated file, so no audit record is deleted and the
    /// history grows with the appliance's request rate.
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

impl Rotation {
    /// Bytes of the history one read examines: everything a bounded rotation
    /// keeps, so an audit page counts and searches every retained record, and
    /// [`MAX_SCAN_BYTES`] when that is more — which the default, keeping every
    /// rotated file, becomes once the history passes the cap. A read that stops
    /// there reports the page as truncated.
    pub fn scan_budget(&self) -> u64 {
        if self.max_bytes == 0 || self.keep == 0 {
            return MAX_SCAN_BYTES;
        }
        self.max_bytes
            .saturating_mul(self.keep as u64 + 2)
            .min(MAX_SCAN_BYTES)
    }
}

/// Path of the rotated file at position `index`. Positions count up from `1`
/// as the log is rotated, so the highest is the most recently rotated.
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

/// The positions of the rotated files beside `live`, oldest first. Taken from
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
/// or an I/O error during a rotation, or a file deleted beside the gateway.
/// The files behind the gap are still read; a read that meets one reports
/// partial counts, because the records of the missing file are in none of
/// them. Positions run consecutively while the history is whole: retention
/// deletes the oldest, which raises the first position without opening a gap.
fn has_gap(indices: &[usize]) -> bool {
    match (indices.first(), indices.last()) {
        (Some(first), Some(last)) => last - first + 1 != indices.len(),
        _ => false,
    }
}

/// Bytes the audit history takes on disk: the live log and every rotated file
/// beside it, by listing the directory and `stat`ing each file. A file that
/// has gone since the directory was listed counts as nothing rather than
/// failing the caller.
///
/// This walks the whole directory, and the number of files in it is bounded by
/// nothing when `vp_audit_log_keep` is `0` — a terabyte of 8 MiB files is
/// 131,000 of them, and none of that is covered by [`Rotation::scan_budget`].
/// It is therefore the way the size is **seeded**, once, when
/// [`crate::audit::audit_log_sink::AuditLogSink`] opens the log; from then on
/// the sink keeps the size as it writes and reports it with no syscall at all.
/// A read falls back to this only while no sink has published one — a Standby
/// node, or before the pipeline starts.
pub fn history_bytes(live: &Path) -> u64 {
    let len = |path: PathBuf| {
        fs::metadata(path)
            .ok()
            .filter(fs::Metadata::is_file)
            .map_or(0, |data| data.len())
    };
    rotated_indices(live)
        .into_iter()
        .map(|index| len(rotated_path(live, index)))
        .fold(len(live.to_path_buf()), u64::saturating_add)
}

/// One file read backwards, a chunk at a time.
struct BackwardFile {
    file: fs::File,
    /// Bytes of the file, as it was when the walk opened it.
    len: u64,
    /// Bytes of the file before [`BackwardFile::buf`], not yet read.
    remaining: u64,
    /// Bytes read but not yet handed back, in the order they were written.
    buf: Vec<u8>,
    /// Whether the bytes still in `buf` belong to a line too long to hand back,
    /// so the rest of that line is dropped as it is reached.
    discarding: bool,
    /// Lines too long to hand back that this file has dropped, so the caller
    /// can say that what it returned is not everything the file holds.
    dropped: usize,
}

impl BackwardFile {
    fn new(
        file: fs::File,
        len: u64,
    ) -> Self {
        Self {
            file,
            len,
            remaining: len,
            buf: Vec::new(),
            discarding: false,
            dropped: 0,
        }
    }

    /// Bytes of the file the walk has taken off it: everything read, less what
    /// is still buffered. This is the file's own bytes — what a read charges
    /// against its budget — and not the length of the lines handed back, which
    /// differs where a line was dropped, was blank, or held bytes that are not
    /// UTF-8.
    fn consumed(&self) -> u64 {
        self.len
            .saturating_sub(self.remaining)
            .saturating_sub(self.buf.len() as u64)
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

    /// Bytes of the line being assembled: everything after the last newline
    /// held, or the whole buffer while it holds none. The rest of the buffer
    /// is the records before that line, which a fill brought in with it.
    fn assembling(&self) -> usize {
        match self.last_newline() {
            Some(end) => self.buf.len() - (end + 1),
            None => self.buf.len(),
        }
    }

    fn last_newline(&self) -> Option<usize> {
        self.buf
            .iter()
            .rposition(|byte| *byte == b'\n')
    }

    /// The next line back, or `None` at the start of the file.
    fn next_line(&mut self) -> io::Result<Option<String>> {
        loop {
            // The newline at the end of the buffer closes the line already
            // handed back, except while a line is being discarded: there it
            // closes the record before the oversized line, and dropping it
            // would make that record the next thing discarded.
            if !self.discarding && self.buf.last() == Some(&b'\n') {
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
            // Measured on the line being assembled, not on the buffer: the
            // buffer also holds the records the same chunk brought in, and
            // counting those would drop a line well inside the cap.
            if self.assembling() > MAX_LINE_BYTES {
                // Only the oversized line is dropped: the records before it
                // are kept.
                self.dropped += 1;
                match self.last_newline() {
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
/// A rotation during a walk gives the live log the next position, leaving the
/// rotated files where they are. The walk looks each next file up when it
/// reaches it, rather than from a list taken at the start, and passes over a
/// file it has already read under another name, so a rotation mid-walk neither
/// hands the same records back twice nor skips the file that moved past it. It
/// takes no lock against the writer to achieve that: a walk lasts as long as
/// the history is large, and the writer's lock is held by every record the
/// audit dispatcher appends, so holding it for a walk would back the dispatcher
/// up behind the Audit page.
pub struct HistoryLines {
    live: PathBuf,
    /// The rotated positions left to read, lowest first, taken once when the
    /// walk leaves the live log. `None` until then.
    rotated: Option<Vec<usize>>,
    /// Whether the walk has reached a rotated file, so a failure to open one
    /// is a gap rather than the live log being unreadable.
    on_rotated: bool,
    started: bool,
    current: Option<BackwardFile>,
    /// `(device, inode)` of the files read so far.
    seen: std::collections::HashSet<(u64, u64)>,
    gap: bool,
    dropped: usize,
    /// Bytes of the files the walk has finished with.
    consumed: u64,
    /// Whether this walk has already reported a rotated file it could not read.
    reported_unreadable: bool,
}

impl HistoryLines {
    /// Walks the history of the live log at `live`.
    pub fn open(live: &Path) -> Self {
        Self {
            live: live.to_path_buf(),
            rotated: None,
            on_rotated: false,
            started: false,
            current: None,
            seen: std::collections::HashSet::new(),
            gap: false,
            dropped: 0,
            consumed: 0,
            reported_unreadable: false,
        }
    }

    /// Whether the walk did not reach the end of the history: a rotated file
    /// missing from the middle of it, or one that could not be read. Read it
    /// after the walk, not before: both are only met as the walk reaches them.
    pub fn gap(&self) -> bool {
        self.gap
    }

    /// Lines the walk met and could not hand back, because no line that long —
    /// longer than [`MAX_LINE_BYTES`] — can be assembled. The history holds
    /// records here that the walk did not return; it reached the end of it all
    /// the same, which is why this is counted apart from
    /// [`HistoryLines::gap`].
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    /// Bytes of the history the walk has taken off disk, which is what a read
    /// charges against its budget: the files it has finished with, plus the
    /// part of the current file it has read.
    pub fn consumed(&self) -> u64 {
        self.current
            .as_ref()
            .map_or(self.consumed, |file| {
                self.consumed
                    .saturating_add(file.consumed())
            })
    }

    /// The next file back: the live log, then the rotated files from the
    /// highest position down.
    ///
    /// The rotated positions are listed once, as the walk leaves the live log,
    /// rather than per file: one `read_dir` for a walk instead of one for every
    /// file of a history that `vp_audit_log_keep = 0` leaves unbounded. Listing
    /// them at that moment is also what makes a rotation mid-walk safe — a
    /// rotation only gives the live log the next position, above everything in
    /// the list, and the walk has already read that file under its old name.
    fn next_file(&mut self) -> Option<PathBuf> {
        if !self.started {
            self.started = true;
            return Some(self.live.clone());
        }
        if self.rotated.is_none() {
            let indices = rotated_indices(&self.live);
            self.gap = has_gap(&indices);
            self.rotated = Some(indices);
        }
        let next = self.rotated.as_mut()?.pop()?;
        self.on_rotated = true;
        Some(rotated_path(&self.live, next))
    }

    /// Opens the next file of the history, unless it is gone, is not a regular
    /// file, is one already read under another name, or is a rotated file this
    /// walk cannot read.
    fn open_file(
        &mut self,
        path: &Path,
    ) -> io::Result<Option<BackwardFile>> {
        let rotated = self.on_rotated;
        // Checked before opening, not after: opening a FIFO blocks until a
        // writer appears, which would hold this walk — and the one permit
        // audit reads share — for as long as nobody writes to it.
        match fs::metadata(path) {
            Ok(data) if data.is_file() => {}
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return self.unreadable(path, e, rotated),
        }
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return self.unreadable(path, e, rotated),
        };
        let data = match file.metadata() {
            Ok(data) => data,
            Err(e) => return self.unreadable(path, e, rotated),
        };
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

    /// A rotated file the walk cannot read is treated as one missing from the
    /// middle of the history: the walk goes on to the older files and reports
    /// the history as incomplete, so a `.1` a backup tool left unreadable
    /// cannot turn every audit read into a `500` and hide a live log that
    /// reads perfectly well. The live log itself is still an error, because a
    /// read that cannot open it has seen none of the evidence.
    fn unreadable(
        &mut self,
        path: &Path,
        error: io::Error,
        rotated: bool,
    ) -> io::Result<Option<BackwardFile>> {
        if !rotated {
            return Err(error);
        }
        self.gap = true;
        if !self.reported_unreadable {
            self.reported_unreadable = true;
            warn!(
                target: "credential_delegation",
                error = %error,
                path = %path.display(),
                "A rotated VP Audit Log file could not be read; the history is read past it and reported as incomplete"
            );
        }
        Ok(None)
    }

    /// Takes the lines the current file could not hand back into this walk's
    /// count. The records read beside such a line are still returned, and the
    /// caller reports the count once for the whole read.
    fn note_dropped_lines(&mut self) {
        let dropped = self
            .current
            .as_mut()
            .map_or(0, |file| std::mem::take(&mut file.dropped));
        self.dropped = self
            .dropped
            .saturating_add(dropped);
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
            self.note_dropped_lines();
            match line {
                Some(line) if line.trim().is_empty() => continue,
                Some(line) => return Ok(Some(line)),
                None => {
                    // The file is done with: all of it has been read, so its
                    // whole length is what the walk took off it.
                    if let Some(file) = self.current.take() {
                        self.consumed = self
                            .consumed
                            .saturating_add(file.len);
                    }
                }
            }
        }
    }
}

/// Rotates the live log: it takes the position after the highest the history
/// holds, and everything older than the newest `keep` rotated files is
/// deleted. Returns the bytes retention deleted, so the writer can keep the
/// size of the history without measuring it again.
///
/// One rename moves the live log however long the history has grown, and the
/// files already rotated are never touched. The directory is listed once to
/// find the next position — the position is taken from the directory rather
/// than counted in memory so that a rename can never land on a file that is
/// already there and destroy the records in it. A `keep` of `0` deletes
/// nothing. Lowering `keep` from `0` deletes everything past the new bound in
/// the next rotation, which is one bulk unlink under the writer's lock.
///
/// A live log that is not there is left alone, the live log itself is never
/// deleted, and a position holding something that is not a regular file is
/// left where it is rather than failing the rotation: the walk passes such a
/// name over too.
pub fn rotate(
    live: &Path,
    keep: usize,
) -> io::Result<u64> {
    if !live.exists() {
        return Ok(0);
    }
    let indices = rotated_indices(live);
    let next = indices
        .last()
        .copied()
        .unwrap_or(0)
        + 1;
    match fs::rename(live, rotated_path(live, next)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
        Ok(()) => {}
    }
    if keep == 0 {
        return Ok(0);
    }
    // The live log just took a position, so it is the newest of the `keep`.
    let oldest_kept = next.saturating_sub(keep - 1);
    let mut freed = 0u64;
    let mut failed = None;
    for index in indices
        .iter()
        .filter(|index| **index < oldest_kept)
    {
        let path = rotated_path(live, *index);
        let Ok(data) = fs::metadata(&path) else {
            continue;
        };
        if !data.is_file() {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => freed = freed.saturating_add(data.len()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => failed = Some(e),
        }
    }
    match failed {
        Some(e) => Err(e),
        None => Ok(freed),
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
        walk_with_gap(live).0
    }

    /// The lines of the history, and whether the walk found part of it missing.
    /// The gap is read after the walk: a position missing from the middle, a
    /// file that cannot be read and a line that cannot be returned are each met
    /// as the walk reaches them.
    fn walk_with_gap(live: &Path) -> (Vec<String>, bool) {
        let (walked, gap, _) = walk_fully(live);
        (walked, gap)
    }

    /// The lines of the history, whether the walk found part of it missing,
    /// and how many lines it could not hand back.
    fn walk_fully(live: &Path) -> (Vec<String>, bool, usize) {
        let mut lines = HistoryLines::open(live);
        let mut walked = Vec::new();
        while let Some(line) = lines.next_line().unwrap() {
            walked.push(line);
        }
        (walked, lines.gap(), lines.dropped())
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
    fn an_oversized_line_starting_on_a_chunk_boundary_keeps_the_record_before_it() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        assert_eq!(MAX_LINE_BYTES % CHUNK_BYTES, 0, "the walk drops an oversized line a whole chunk at a time");
        // A walk fills from the end of the file, so this is the length that
        // leaves the start of the oversized line exactly where a fill stops:
        // the chunk read next ends with the newline closing `rec-2`.
        let trailer = "\nlast\n";
        let huge = "x".repeat(MAX_LINE_BYTES + CHUNK_BYTES - trailer.len());
        fs::write(&path, format!("rec-1\nrec-2\n{huge}{trailer}")).unwrap();

        assert_eq!(
            walk(&path),
            vec!["last", "rec-2", "rec-1"],
            "the record whose newline ends the chunk is not discarded with the oversized line"
        );
    }

    #[test]
    fn a_line_inside_the_cap_is_kept_however_the_chunks_fall_around_it() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        // Inside the cap, but long enough that the fill reaching its start
        // also brings in most of a chunk of the records before it: the two
        // together are over the cap, the line itself is not.
        let last = "z".repeat(1000);
        let long = "y".repeat(MAX_LINE_BYTES - 500);
        fs::write(&path, format!("{}{long}\n{last}\n", lines(CHUNK_BYTES / 8))).unwrap();

        let walked = walk(&path);

        assert_eq!(walked[0], last, "the record after it");
        assert_eq!(walked[1], long, "a line inside the 1 MiB cap is handed back, not dropped");
        assert_eq!(walked[2], format!("line-{}", CHUNK_BYTES / 8 - 1), "the record before it");
    }

    #[test]
    fn a_line_the_walk_could_not_return_is_counted_apart_from_a_gap() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let huge = "x".repeat(MAX_LINE_BYTES + 1024);
        fs::write(&path, format!("line-0\n{huge}\nline-2\n")).unwrap();

        let (walked, gap, dropped) = walk_fully(&path);

        assert_eq!(walked, vec!["line-2", "line-0"], "the records beside it are still returned");
        assert_eq!(dropped, 1, "the line that could not be returned is counted, not passed over in silence");
        assert!(!gap, "the walk did reach the end of the history");
    }

    #[test]
    fn a_whole_history_walked_reports_nothing_missing_and_nothing_dropped() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, lines(3)).unwrap();
        fs::write(rotated_path(&path, 1), lines(2)).unwrap();

        let (walked, gap, dropped) = walk_fully(&path);

        assert_eq!(walked.len(), 5);
        assert!(!gap, "nothing was missing or unreadable");
        assert_eq!(dropped, 0, "and every line was handed back");
    }

    #[test]
    fn a_walk_charges_the_bytes_it_took_off_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        // A blank line and a line that is not UTF-8 both cost the budget what
        // they take on disk, which is not the length of what is handed back.
        let mut stored = b"line-0\n\n".to_vec();
        stored.extend_from_slice(&[0xff, 0xfe, b'\n']);
        stored.extend_from_slice(b"line-2\n");
        fs::write(&path, &stored).unwrap();

        let mut lines = HistoryLines::open(&path);
        assert_eq!(lines.consumed(), 0, "nothing is charged before the walk starts");
        let mut walked = Vec::new();
        while let Some(line) = lines.next_line().unwrap() {
            walked.push(line);
        }

        assert_eq!(walked.len(), 3, "the blank line is not a record; the other three are");
        assert_eq!(
            lines.consumed(),
            stored.len() as u64,
            "the whole file is charged, including the blank line and the bytes that are not UTF-8"
        );
    }

    #[test]
    fn a_walk_lists_the_rotated_files_once() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        for index in 1..=3 {
            fs::write(rotated_path(&path, index), format!("rotated-{index}\n")).unwrap();
        }

        let mut lines = HistoryLines::open(&path);
        lines
            .next_line()
            .unwrap()
            .unwrap();
        // Taken as the walk leaves the live log, so a rotation after that point
        // adds a position the walk has already read under its old name.
        rotate(&path, 0).unwrap();
        let mut walked = Vec::new();
        while let Some(line) = lines.next_line().unwrap() {
            walked.push(line);
        }

        assert_eq!(
            walked,
            vec!["rotated-3", "rotated-2", "rotated-1"],
            "the live log is not handed back a second time under its new name"
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
        fs::write(rotated_path(&path, 2), "middle\n").unwrap();
        fs::write(rotated_path(&path, 1), "oldest\n").unwrap();

        let (walked, gap) = walk_with_gap(&path);

        assert_eq!(walked, vec!["newest", "middle", "oldest"], "the highest position is the newest");
        assert!(!gap, "the history is complete");
    }

    #[test]
    fn the_oldest_positions_being_gone_is_not_a_gap() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "newest\n").unwrap();
        fs::write(rotated_path(&path, 8), "kept\n").unwrap();
        fs::write(rotated_path(&path, 9), "kept too\n").unwrap();

        let (walked, gap) = walk_with_gap(&path);

        assert_eq!(walked, vec!["newest", "kept too", "kept"]);
        assert!(!gap, "retention deleting the oldest leaves the history whole");
    }

    #[test]
    fn a_walk_reads_past_a_missing_rotated_file_and_reports_the_gap() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "newest\n").unwrap();
        fs::write(rotated_path(&path, 3), "middle\n").unwrap();
        fs::write(rotated_path(&path, 1), "oldest\n").unwrap();

        let (walked, gap) = walk_with_gap(&path);

        assert_eq!(walked, vec!["newest", "middle", "oldest"], "the file behind the gap is still read");
        assert!(gap, "the missing file is reported");
    }

    #[test]
    fn a_rotated_file_that_cannot_be_read_is_read_past_as_a_gap() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::write(rotated_path(&path, 1), "oldest\n").unwrap();
        let unreadable = rotated_path(&path, 2);
        fs::write(&unreadable, "taken by a backup tool\n").unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&unreadable).is_ok() {
            // A user the mode does not apply to, such as root in a container.
            return;
        }

        let mut lines = HistoryLines::open(&path);
        let mut walked = Vec::new();
        while let Some(line) = lines.next_line().unwrap() {
            walked.push(line);
        }

        assert_eq!(walked, vec!["live", "oldest"], "the live log and the files behind it are still read");
        assert!(lines.gap(), "the file that could not be read is reported as missing history");
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
    fn rotating_gives_the_live_log_the_next_position_and_drops_the_oldest() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::write(rotated_path(&path, 1), "dropped\n").unwrap();
        fs::write(rotated_path(&path, 2), "first\n").unwrap();

        rotate(&path, 2).unwrap();

        assert!(!path.exists(), "the live log is moved aside");
        assert_eq!(fs::read_to_string(rotated_path(&path, 3)).unwrap(), "live\n");
        assert_eq!(
            fs::read_to_string(rotated_path(&path, 2)).unwrap(),
            "first\n",
            "a file already rotated is left where it is"
        );
        assert!(!rotated_path(&path, 1).exists(), "nothing is kept past the retained count");
    }

    #[test]
    fn rotating_renames_only_the_live_log_however_long_the_history_is() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        for index in 1..=50 {
            fs::write(rotated_path(&path, index), format!("rotated-{index}\n")).unwrap();
        }

        rotate(&path, 0).unwrap();

        for index in 1..=50 {
            assert_eq!(
                fs::read_to_string(rotated_path(&path, index)).unwrap(),
                format!("rotated-{index}\n"),
                "the rotated history is not touched"
            );
        }
        assert_eq!(fs::read_to_string(rotated_path(&path, 51)).unwrap(), "live\n");
    }

    #[test]
    fn rotating_keeps_the_newest_of_the_retained_count() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        let keep = 3;
        for round in 0..=keep + 2 {
            fs::write(&path, format!("round-{round}\n")).unwrap();
            rotate(&path, keep).unwrap();
        }

        let rounds = keep + 2;
        assert_eq!(
            rotated_indices(&path),
            ((rounds + 1 - keep + 1)..=(rounds + 1)).collect::<Vec<_>>(),
            "exactly the retained count is kept, at the newest positions"
        );
        assert_eq!(
            fs::read_to_string(rotated_path(&path, rounds + 1)).unwrap(),
            format!("round-{rounds}\n"),
            "the newest position holds the last log rotated"
        );
        assert_eq!(
            fs::read_to_string(rotated_path(&path, rounds + 1 - keep + 1)).unwrap(),
            format!("round-{}\n", rounds + 1 - keep),
            "the oldest retained file is the newest one minus the retained count"
        );
    }

    #[test]
    fn the_built_in_retained_count_deletes_nothing() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        for round in 0..5 {
            fs::write(&path, format!("round-{round}\n")).unwrap();
            rotate(&path, KEEP_ROTATED).unwrap();
        }

        assert_eq!(KEEP_ROTATED, 0, "the default keeps every rotated file");
        assert_eq!(rotated_indices(&path), vec![1, 2, 3, 4, 5], "every rotated file is still there");
        assert_eq!(fs::read_to_string(rotated_path(&path, 1)).unwrap(), "round-0\n");
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

        assert_eq!(fs::read_to_string(rotated_path(&path, 4)).unwrap(), "live\n");
        assert!(!rotated_path(&path, 1).exists());
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
        fs::write(rotated_path(&path, 1), "behind the gap\n").unwrap();
        fs::write(rotated_path(&path, 4), "newest\n").unwrap();

        rotate(&path, 2).unwrap();

        assert_eq!(fs::read_to_string(rotated_path(&path, 5)).unwrap(), "live\n");
        assert_eq!(fs::read_to_string(rotated_path(&path, 4)).unwrap(), "newest\n");
        assert!(!rotated_path(&path, 1).exists(), "a file past the retained count is deleted even behind a gap");
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
        assert_eq!(fs::read_to_string(rotated_path(&path, 3)).unwrap(), "live\n");
        assert_eq!(fs::read_to_string(rotated_path(&path, 1)).unwrap(), "first\n");
        assert_eq!(
            fs::read_to_string(rotated_path(&path, 2)).unwrap(),
            "second\n",
            "the oldest file stays where it is instead of being deleted"
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
    fn the_size_of_the_history_is_the_live_log_and_every_rotated_file() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "live\n").unwrap();
        fs::write(rotated_path(&path, 1), "first\n").unwrap();
        fs::write(rotated_path(&path, 2), "second\n").unwrap();
        // Neither a rotated position nor part of the history.
        fs::write(PathBuf::from(format!("{}.01", path.display())), "ignored\n").unwrap();
        fs::create_dir(rotated_path(&path, 3)).unwrap();

        assert_eq!(history_bytes(&path), "live\nfirst\nsecond\n".len() as u64);
    }

    #[test]
    fn the_size_of_a_history_that_is_not_there_is_nothing() {
        let dir = TempDir::new().unwrap();
        assert_eq!(
            history_bytes(
                &dir.path()
                    .join("delegation-audit.jsonl")
            ),
            0
        );
    }

    #[test]
    fn the_scan_budget_covers_the_whole_history_a_rotation_keeps() {
        let rotation = Rotation { max_bytes: 1024, keep: 4 };
        let keeps_everything = Rotation {
            max_bytes: LIVE_MAX_BYTES,
            keep: 0,
        };
        let never_rotates = Rotation { max_bytes: 0, keep: 8 };
        let larger_than_the_cap = Rotation { max_bytes: u64::MAX, keep: 8 };
        let bounded_above_the_cap = Rotation {
            max_bytes: 32 * 1024 * 1024,
            keep: 8,
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
        assert_eq!(
            bounded_above_the_cap.scan_budget(),
            MAX_SCAN_BYTES,
            "a bounded history larger than the cap is read up to it, not past it"
        );
    }
}
