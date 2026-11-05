//! The VP Audit Log on disk: rotation of the live file, the rotated history
//! beside it, and bounded reads that take only the end of that history.
//!
//! The file the Audit page reads grows with every proxied call, so both the
//! writer ([`crate::audit::audit_log_sink`]) and the reader
//! ([`crate::delegation_vault::audit::read_audit_log`]) work in bounded steps:
//! the writer rotates the live file once it reaches [`Rotation::max_bytes`] and
//! keeps [`Rotation::keep`] rotated files, and a read never holds more than
//! [`READ_WINDOW_BYTES`] of it in memory.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Bytes the live log may reach before it is rotated.
pub const LIVE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Rotated files kept beside the live log. The oldest is deleted on rotation.
pub const KEEP_ROTATED: usize = 8;

/// Most bytes one read takes from the end of the audit history. A read holds
/// this much of the log, and the records parsed from it, in memory.
pub const READ_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// How the live log is rotated.
#[derive(Debug, Clone, Copy)]
pub struct Rotation {
    /// Bytes the live log may reach before it is rotated. `0` never rotates.
    /// Default: 8 MiB.
    pub max_bytes: u64,
    /// Rotated files kept beside the live log, oldest deleted first.
    /// Default: 8.
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

/// The end of one file, cut to a whole line.
pub struct Tail {
    /// The lines read, in the order they were written.
    pub text: String,
    /// Whether the file held more than was read.
    pub truncated: bool,
}

/// The end of the audit history, cut to a whole line.
pub struct Window {
    /// The lines read, oldest first, across the rotated files and the live one.
    pub text: String,
    /// Whether the history held more than was read, so counts taken from
    /// [`Window::text`] describe the window and not the whole history.
    pub truncated: bool,
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

/// The live log and the rotated files beside it, newest first.
pub fn history(live: &Path) -> Vec<PathBuf> {
    let mut paths = vec![live.to_path_buf()];
    let mut index = 1;
    loop {
        let path = rotated_path(live, index);
        if !path.exists() {
            return paths;
        }
        paths.push(path);
        index += 1;
    }
}

/// Up to `max_bytes` from the end of `path`, starting at a line boundary so a
/// record cut by the window is dropped rather than returned half-read. A file
/// that is not there reads as empty.
pub fn read_tail(
    path: &Path,
    max_bytes: u64,
) -> io::Result<Tail> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(Tail {
                text: String::new(),
                truncated: false,
            });
        }
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    // From one byte earlier, so the newline that ends the record before the
    // window is read too and a window that already starts at a line boundary
    // keeps its first record.
    let from = start.saturating_sub(1);
    file.seek(SeekFrom::Start(from))?;
    let mut bytes = Vec::with_capacity(len.saturating_sub(from) as usize);
    file.read_to_end(&mut bytes)?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if start > 0 {
        match text.find('\n') {
            Some(end) => text = text.split_off(end + 1),
            None => text.clear(),
        }
    }
    Ok(Tail { text, truncated: start > 0 })
}

/// The newest `max_bytes` of the audit history, oldest line first: the live log
/// first, then back through the rotated files until the budget runs out.
pub fn read_window(
    live: &Path,
    max_bytes: u64,
) -> io::Result<Window> {
    let paths = history(live);
    let mut parts: Vec<String> = Vec::with_capacity(paths.len());
    let mut budget = max_bytes;
    let mut truncated = false;
    for path in &paths {
        if budget == 0 {
            truncated = true;
            break;
        }
        let tail = read_tail(path, budget)?;
        let cut = tail.truncated;
        budget = budget.saturating_sub(tail.text.len() as u64);
        truncated |= cut;
        parts.push(tail.text);
        if cut {
            break;
        }
    }
    parts.reverse();
    Ok(Window {
        text: parts.concat(),
        truncated,
    })
}

/// Rotates the live log: each rotated file moves one position back, the live
/// log becomes `.1`, and everything past `keep` is deleted. A live log that is
/// not there is left alone. With `keep` of `0` the live log is deleted instead.
pub fn rotate(
    live: &Path,
    keep: usize,
) -> io::Result<()> {
    let mut index = keep.max(1);
    while rotated_path(live, index).exists() {
        fs::remove_file(rotated_path(live, index))?;
        index += 1;
    }
    if keep == 0 {
        return match fs::remove_file(live) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        };
    }
    for index in (1..keep).rev() {
        let from = rotated_path(live, index);
        if from.exists() {
            fs::rename(&from, rotated_path(live, index + 1))?;
        }
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

    #[test]
    fn a_file_shorter_than_the_window_is_read_whole() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, lines(3)).unwrap();

        let tail = read_tail(&path, 1024).unwrap();

        assert_eq!(tail.text, "line-0\nline-1\nline-2\n");
        assert!(!tail.truncated, "nothing was left out");
    }

    #[test]
    fn a_window_smaller_than_the_file_starts_at_a_whole_line() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, lines(3)).unwrap();

        let tail = read_tail(&path, 10).unwrap();

        assert_eq!(tail.text, "line-2\n", "the record cut by the window is dropped");
        assert!(tail.truncated);
    }

    #[test]
    fn a_log_that_is_not_there_reads_as_empty() {
        let dir = TempDir::new().unwrap();
        let tail = read_tail(
            &dir.path()
                .join("delegation-audit.jsonl"),
            1024,
        )
        .unwrap();

        assert_eq!(tail.text, "");
        assert!(!tail.truncated);
    }

    #[test]
    fn a_window_reads_back_through_the_rotated_files_oldest_line_first() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "newest\n").unwrap();
        fs::write(rotated_path(&path, 1), "middle\n").unwrap();
        fs::write(rotated_path(&path, 2), "oldest\n").unwrap();

        let window = read_window(&path, 1024).unwrap();

        assert_eq!(window.text, "oldest\nmiddle\nnewest\n");
        assert!(!window.truncated, "the whole history fit in the window");
    }

    #[test]
    fn a_window_stops_at_its_budget_and_says_so() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        fs::write(&path, "newest\n").unwrap();
        fs::write(rotated_path(&path, 1), "older\nmiddle\n").unwrap();

        let window = read_window(&path, 14).unwrap();

        assert_eq!(window.text, "middle\nnewest\n", "only the newest records fit");
        assert!(window.truncated, "the history held more than the window");
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
    fn rotating_a_log_that_is_not_there_does_nothing() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("delegation-audit.jsonl");

        rotate(&path, 2).unwrap();

        assert!(!path.exists());
        assert!(!rotated_path(&path, 1).exists());
    }
}
