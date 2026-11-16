//! Mediated filesystem access for per-entity `did:webvh` artifacts.
//!
//! Every webvh entity (department, trust registry, connection point, gateway
//! issuer, …) keeps two artifacts inside its own key directory:
//!
//! - `did.jsonl` — the signed `LogEntry` log. This is the local source of
//!   truth that is served directly and synced into the central DID-keyed
//!   resolver index at startup.
//! - `did.json`  — the parallel `did:web` current-document snapshot.
//!
//! These helpers are the single choke point for reading and writing those two
//! files, so no call site touches `tokio::fs` directly. Raw JSON is written and
//! read **verbatim** (byte-preserving) so the DataIntegrity proofs on log
//! entries survive untouched.
//!
//! This is a mediation layer only: it keeps every file in its existing
//! per-entity location. The central `DidLogStorage` resolver index is a
//! separate concern and is not affected.

use std::path::Path;

use anyhow::{Context, Result};

use crate::storage::filesystem::{AtomicWriteError, atomic_write_file_with_mode};

/// Replaces `path` with `bytes` by an atomic rename. Once the rename has replaced the file,
/// readers see the new content, so a directory sync that fails after it is logged and the write
/// counts as done.
pub(crate) async fn replace_file(
    path: &Path,
    bytes: &[u8],
) -> Result<()> {
    match atomic_write_file_with_mode(path, bytes, None).await {
        Ok(()) => Ok(()),
        Err(AtomicWriteError::ReplacedButUnsynced(error)) => {
            tracing::warn!("Replaced {} but could not sync its directory: {error:#}", path.display());
            Ok(())
        }
        Err(AtomicWriteError::NotReplaced(error)) => Err(error),
    }
}

/// Filename of the per-entity signed log.
const DID_LOG_FILE: &str = "did.jsonl";

/// Filename of the per-entity `did:web` current document.
const DID_DOCUMENT_FILE: &str = "did.json";

/// Write the DID log to `{dir}/did.jsonl`, replacing any existing content atomically and
/// appending a single trailing newline. Used for the one-shot birth log.
///
/// `raw_json` is written verbatim so the entry's signature is preserved.
///
/// Gated on `didwebvh`: the only writers are the did:webvh identity generators,
/// which are themselves `#[cfg(feature = "didwebvh")]`.
#[cfg(feature = "didwebvh")]
pub async fn write_did_log_raw(
    dir: &Path,
    raw_json: &str,
) -> Result<()> {
    let path = dir.join(DID_LOG_FILE);
    replace_file(&path, format!("{}\n", raw_json).as_bytes())
        .await
        .with_context(|| format!("writing DID log {}", path.display()))
}

/// Append one entry to `{dir}/did.jsonl`, whose content the caller read as `current`.
///
/// Refuses when the log no longer holds `current`, so a version is never appended to a log
/// that changed after the caller built that version from it. The new log is written to a
/// temporary file of its own and renamed into place, so a reader never sees a partial entry
/// and two writers sharing the directory never write the same temporary file. The check
/// and the rename are not one step, so writers on several nodes hold a shared lock.
#[cfg(feature = "didwebvh")]
pub async fn append_did_log_raw(
    dir: &Path,
    current: &str,
    raw_json: &str,
) -> Result<()> {
    let path = dir.join(DID_LOG_FILE);
    let on_disk = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("reading DID log {}", path.display()))?;
    anyhow::ensure!(on_disk == current, "DID log {} changed while a version was added", path.display());

    replace_file(&path, format!("{}\n{}\n", current.trim_end(), raw_json).as_bytes())
        .await
        .with_context(|| format!("replacing DID log {}", path.display()))
}

/// Write the `did:web` current document to `{dir}/did.json`, replacing any
/// existing content atomically, so a reader sees the previous document or the new one.
pub async fn write_did_document(
    dir: &Path,
    json: &str,
) -> Result<()> {
    let path = dir.join(DID_DOCUMENT_FILE);
    replace_file(&path, json.as_bytes())
        .await
        .with_context(|| format!("writing DID document {}", path.display()))
}

/// Read the raw contents of `{dir}/did.jsonl` verbatim.
///
/// Returns `Ok(None)` when the log does not exist yet, so callers can map that
/// to a 404 without treating it as a transport error.
///
/// Ungated (unlike [`write_did_log_raw`]): serving a `.jsonl` log is
/// feature-agnostic and several serving handlers (e.g. `serve_department_did_jsonl`,
/// `serve_did_jsonl_file`) are not behind `didwebvh`, so this must compile in a
/// `--no-default-features` build.
pub async fn read_did_log_raw(dir: &Path) -> Result<Option<String>> {
    let path = dir.join(DID_LOG_FILE);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading DID log {}", path.display())),
    }
}

/// Read `{dir}/did.json` verbatim. Returns `Ok(None)` when it does not exist.
pub async fn read_did_document(dir: &Path) -> Result<Option<String>> {
    let path = dir.join(DID_DOCUMENT_FILE);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading DID document {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn write_did_log_appends_single_newline_and_preserves_bytes() {
        let dir = tempdir().unwrap();
        let raw = r#"{"versionId":"1-abc","proof":[{"proofValue":"zSIG"}]}"#;

        write_did_log_raw(dir.path(), raw)
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(dir.path().join("did.jsonl")).unwrap();
        assert_eq!(on_disk, format!("{}\n", raw));
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn write_did_log_replaces_existing_content() {
        let dir = tempdir().unwrap();
        write_did_log_raw(dir.path(), "first")
            .await
            .unwrap();
        write_did_log_raw(dir.path(), "second")
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(dir.path().join("did.jsonl")).unwrap();
        assert_eq!(on_disk, "second\n");
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn append_did_log_adds_one_entry_after_the_existing_ones() {
        let dir = tempdir().unwrap();
        write_did_log_raw(dir.path(), "first")
            .await
            .unwrap();

        append_did_log_raw(dir.path(), "first\n", "second")
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(dir.path().join("did.jsonl")).unwrap();
        assert_eq!(on_disk, "first\nsecond\n");
        let files: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(files, vec!["did.jsonl"], "the temporary log must be renamed into place");
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn append_did_log_never_writes_another_writers_temporary_file() {
        let dir = tempdir().unwrap();
        write_did_log_raw(dir.path(), "first")
            .await
            .unwrap();
        let other_writer = dir
            .path()
            .join("did.jsonl.tmp");
        std::fs::write(&other_writer, "first\nhalf-written").unwrap();

        append_did_log_raw(dir.path(), "first\n", "second")
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(dir.path().join("did.jsonl")).unwrap();
        assert_eq!(on_disk, "first\nsecond\n");
        assert_eq!(std::fs::read_to_string(&other_writer).unwrap(), "first\nhalf-written");
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn append_did_log_refuses_a_log_that_changed() {
        let dir = tempdir().unwrap();
        write_did_log_raw(dir.path(), "first")
            .await
            .unwrap();
        append_did_log_raw(dir.path(), "first\n", "second")
            .await
            .unwrap();

        let err = append_did_log_raw(dir.path(), "first\n", "other")
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("changed while a version was added"),
            "unexpected error: {err}"
        );
        let on_disk = std::fs::read_to_string(dir.path().join("did.jsonl")).unwrap();
        assert_eq!(on_disk, "first\nsecond\n");
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn append_did_log_requires_an_existing_log() {
        let dir = tempdir().unwrap();

        assert!(
            append_did_log_raw(dir.path(), "", "entry")
                .await
                .is_err()
        );
        assert!(
            !dir.path()
                .join("did.jsonl")
                .exists()
        );
    }

    #[tokio::test]
    async fn write_did_document_writes_verbatim() {
        let dir = tempdir().unwrap();
        let doc = r#"{"id":"did:web:example.com"}"#;

        write_did_document(dir.path(), doc)
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(dir.path().join("did.json")).unwrap();
        assert_eq!(on_disk, doc);
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        files.sort();
        files
    }

    /// A reader on another node sees the previous file or the new one, never an empty or
    /// partly written one.
    async fn assert_readers_never_see_a_partial_file(
        file_name: &'static str,
        write: impl Fn(std::path::PathBuf, String) -> tokio::task::JoinHandle<()>,
    ) {
        let dir = tempdir().unwrap();
        let path = dir.path().join(file_name);
        let versions: Vec<String> = ["a", "b"]
            .iter()
            .map(|fill| fill.repeat(256 * 1024))
            .collect();
        write(dir.path().to_path_buf(), versions[0].clone())
            .await
            .unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            let path = path.clone();
            let versions = versions.clone();
            std::thread::spawn(move || {
                let mut partial = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let content = std::fs::read_to_string(&path).unwrap();
                    let content = content.trim_end_matches('\n');
                    if !versions
                        .iter()
                        .any(|version| version == content)
                    {
                        partial += 1;
                    }
                }
                partial
            })
        };

        for round in 0..200 {
            write(dir.path().to_path_buf(), versions[round % 2].clone())
                .await
                .unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(reader.join().unwrap(), 0, "a reader saw an empty or partly written {file_name}");
        assert_eq!(files_in(dir.path()), vec![file_name.to_string()], "no temporary file may be left behind");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn did_document_readers_never_see_a_partial_document() {
        assert_readers_never_see_a_partial_file("did.json", |dir, content| {
            tokio::spawn(async move {
                write_did_document(&dir, &content)
                    .await
                    .unwrap()
            })
        })
        .await;
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test(flavor = "multi_thread")]
    async fn did_log_readers_never_see_a_partial_log() {
        assert_readers_never_see_a_partial_file("did.jsonl", |dir, content| {
            tokio::spawn(async move {
                write_did_log_raw(&dir, &content)
                    .await
                    .unwrap()
            })
        })
        .await;
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn read_did_log_round_trips_and_reports_absent() {
        let dir = tempdir().unwrap();
        assert!(
            read_did_log_raw(dir.path())
                .await
                .unwrap()
                .is_none()
        );

        write_did_log_raw(dir.path(), "entry")
            .await
            .unwrap();
        assert_eq!(
            read_did_log_raw(dir.path())
                .await
                .unwrap()
                .as_deref(),
            Some("entry\n")
        );
    }

    #[tokio::test]
    async fn read_did_document_round_trips_and_reports_absent() {
        let dir = tempdir().unwrap();
        assert!(
            read_did_document(dir.path())
                .await
                .unwrap()
                .is_none()
        );

        write_did_document(dir.path(), "doc")
            .await
            .unwrap();
        assert_eq!(
            read_did_document(dir.path())
                .await
                .unwrap()
                .as_deref(),
            Some("doc")
        );
    }
}
