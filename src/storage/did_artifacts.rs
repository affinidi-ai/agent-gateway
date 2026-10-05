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

/// Filename of the per-entity signed log.
const DID_LOG_FILE: &str = "did.jsonl";

/// Filename of the per-entity `did:web` current document.
const DID_DOCUMENT_FILE: &str = "did.json";

/// Write the DID log to `{dir}/did.jsonl`, replacing any existing content and
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
    tokio::fs::write(&path, format!("{}\n", raw_json))
        .await
        .with_context(|| format!("writing DID log {}", path.display()))
}

/// Write the `did:web` current document to `{dir}/did.json`, replacing any
/// existing content.
pub async fn write_did_document(
    dir: &Path,
    json: &str,
) -> Result<()> {
    let path = dir.join(DID_DOCUMENT_FILE);
    tokio::fs::write(&path, json)
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
