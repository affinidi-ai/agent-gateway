use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{error, info, warn};

use crate::delegation_vault::read_scope::VaultReader;
use crate::identity::state::IdentityApiState;
use crate::observability::loggable;

/// Result of truncating old log files
#[derive(Debug, Serialize)]
pub struct TruncateLogsResult {
    pub files_removed: usize,
    pub bytes_freed: u64,
    /// The current log file is always kept
    pub current_log_kept: bool,
}

/// Truncate old / rotated log files from the logs directory.
///
/// Keeps the current `agent-gateway.log` file intact and removes any
/// rotated or archived log files (e.g. `.log.1`, `.log.gz`, etc.).
pub async fn truncate_old_logs(State(state): State<IdentityApiState>) -> Response {
    let log_dir = match &state
        .bootstrap_config
        .logging
        .log_directory
    {
        Some(dir) => dir.clone(),
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "No log directory configured"})))
                .into_response();
        }
    };

    let result = tokio::task::spawn_blocking(move || truncate_old_log_files(&log_dir)).await;

    match result {
        Ok(Ok(result)) => {
            info!("Old logs truncated: {} files removed, {} bytes freed", result.files_removed, result.bytes_freed);
            (StatusCode::OK, Json(result)).into_response()
        }
        Ok(Err(e)) => {
            error!("Failed to truncate old logs: {:#}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to truncate logs: {}", e)})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Log truncation task panicked: {:#}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Log truncation task failed"})))
                .into_response()
        }
    }
}

/// Remove old / rotated log files, keeping only the current log.
fn truncate_old_log_files(log_dir: &str) -> anyhow::Result<TruncateLogsResult> {
    use std::fs;
    use std::path::Path;

    let dir = Path::new(log_dir);
    if !dir.is_dir() {
        anyhow::bail!("Log directory does not exist: {}", log_dir);
    }

    let current_log = "agent-gateway.log";
    let mut files_removed: usize = 0;
    let mut bytes_freed: u64 = 0;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let file_name = match path
            .file_name()
            .and_then(|n| n.to_str())
        {
            Some(name) => name.to_string(),
            None => continue,
        };

        // Keep the current active log file
        if file_name == current_log {
            continue;
        }

        // Remove rotated / archived log files (e.g. .log.1, .log.gz, .log.old, etc.)
        if file_name.starts_with("agent-gateway") && file_name.contains(".log") {
            let size = path
                .metadata()
                .map(|m| m.len())
                .unwrap_or(0);
            if let Err(e) = fs::remove_file(&path) {
                warn!("Failed to remove old log file {}: {}", file_name, e);
                continue;
            }
            files_removed += 1;
            bytes_freed += size;
        }
    }

    Ok(TruncateLogsResult {
        files_removed,
        bytes_freed,
        current_log_kept: true,
    })
}

/// Download all log files as a streaming response.
///
/// For large log files (multi-GB), this streams the content directly from disk
/// without loading it entirely into memory.
pub async fn download_logs(
    State(state): State<IdentityApiState>,
    reader: VaultReader,
) -> Response {
    log_archive(
        state
            .bootstrap_config
            .logging
            .log_directory
            .clone(),
        &reader,
    )
    .await
}

/// The server logs in `log_dir`, as a ZIP archive for `reader`. They hold
/// every tenant's request and delegation detail, so only an appliance-wide
/// caller downloads them; any other gets a bare 403, as from the middleware.
async fn log_archive(
    log_dir: Option<String>,
    reader: &VaultReader,
) -> Response {
    if !reader.is_appliance_wide() {
        warn!("Log download refused: only an appliance-wide caller downloads the server logs");
        return StatusCode::FORBIDDEN.into_response();
    }
    let log_dir = match log_dir {
        Some(dir) => dir,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "No log directory configured"})))
                .into_response();
        }
    };

    let result = tokio::task::spawn_blocking(move || build_log_zip_streamed(&log_dir)).await;

    match result {
        Ok(Ok(zip_bytes)) => {
            let size = zip_bytes.len();
            info!("Log download complete: {} bytes", size);

            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zip"));
            headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=\"logs.zip\""));

            (StatusCode::OK, headers, Body::from(zip_bytes)).into_response()
        }
        Ok(Err(e)) => {
            error!(error = %loggable::untrusted(&format!("{e:#}")), "Failed to build log archive");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to download logs"})))
                .into_response()
        }
        Err(e) => {
            error!(error = %loggable::untrusted(&e.to_string()), "Log download task panicked");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Log download task failed"})))
                .into_response()
        }
    }
}

/// Build a ZIP of all log files using streaming reads to handle large files.
///
/// Each log file is read in chunks (1 MB) and fed into the ZIP writer
/// to keep memory usage bounded even for multi-GB log files.
fn build_log_zip_streamed(log_dir: &str) -> anyhow::Result<Vec<u8>> {
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::path::Path;
    use zip::write::{FileOptions, SimpleFileOptions, ZipWriter};

    let dir = Path::new(log_dir);
    if !dir.is_dir() {
        anyhow::bail!("Log directory does not exist: {}", log_dir);
    }

    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    let options: SimpleFileOptions = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Collect and sort log files for deterministic ordering
    let mut log_files: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().is_file()
                && e.file_name()
                    .to_string_lossy()
                    .contains(".log")
        })
        .collect();
    log_files.sort_by_key(|e| e.file_name());

    if log_files.is_empty() {
        anyhow::bail!("No log files found in {}", log_dir);
    }

    const CHUNK_SIZE: usize = 1_048_576; // 1 MB chunks
    let mut buf = vec![0u8; CHUNK_SIZE];

    for entry in &log_files {
        let path = entry.path();
        let file_name = path
            .file_name()
            .map(|n| {
                n.to_string_lossy()
                    .to_string()
            })
            .unwrap_or_default();

        let mut file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Skipping unreadable log file {}: {}", file_name, e);
                continue;
            }
        };

        zip.start_file(&file_name, options)?;

        // Stream in chunks to avoid loading entire large files into memory
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            zip.write_all(&buf[..n])?;
        }
    }

    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::test_support::{delegation, pattern, reader, tenant};

    async fn body_of(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    /// The logs hold every tenant's request and delegation detail, so a
    /// resource-scoped token gets a bare 403 and only a session or an
    /// appliance-wide token downloads them.
    #[tokio::test]
    async fn only_an_appliance_wide_caller_downloads_the_server_logs() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory
                .path()
                .join("agent-gateway.log"),
            "a log line\n",
        )
        .unwrap();
        let log_dir = Some(
            directory
                .path()
                .to_string_lossy()
                .into_owned(),
        );
        for (caller, scoped) in [
            ("a tenant token", reader(Some(tenant("tenant-a")), Some(pattern("tenant-a")), Some(delegation(true)))),
            ("a token scoped by a resource pattern", reader(None, Some(pattern("tenant-a")), Some(delegation(true)))),
            ("a token scoped by required headers alone", reader(None, None, Some(delegation(true)))),
        ] {
            let response = log_archive(log_dir.clone(), &scoped).await;
            let status = response.status();
            assert_eq!((status, body_of(response).await), (StatusCode::FORBIDDEN, Vec::new()), "{caller}");
        }
        for (caller, appliance_wide) in [
            ("a session", reader(None, None, None)),
            ("an appliance-wide token", reader(None, None, Some(delegation(false)))),
        ] {
            let response = log_archive(log_dir.clone(), &appliance_wide).await;
            assert_eq!(response.status(), StatusCode::OK, "{caller}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip", "{caller}");
            assert!(
                body_of(response)
                    .await
                    .starts_with(b"PK"),
                "{caller}: not a ZIP archive"
            );
        }
    }

    /// A failed download answers a fixed body; the error, which names the log
    /// directory, goes to the log only.
    #[tokio::test]
    async fn a_failed_log_download_answers_without_its_detail() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory
            .path()
            .join("no-such-logs")
            .to_string_lossy()
            .into_owned();
        let response = log_archive(Some(missing), &reader(None, None, None)).await;
        let status = response.status();
        let body = String::from_utf8(body_of(response).await).unwrap();
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"Failed to download logs"}"#)
        );
    }
}
