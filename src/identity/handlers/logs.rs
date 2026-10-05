use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{error, info, warn};

use crate::identity::state::IdentityApiState;

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
pub async fn download_logs(State(state): State<IdentityApiState>) -> Response {
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
            error!("Failed to build log archive: {:#}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to download logs: {}", e)})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Log download task panicked: {:#}", e);
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
