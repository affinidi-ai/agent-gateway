use axum::{
    Extension, Json,
    body::Body,
    extract::{Multipart, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::identity::state::IdentityApiState;
use crate::rbac::{Feature, RbacConfig};

use super::audit::{StorageAuditEvent, StorageOperation, record_storage_audit};
use super::encryption::{
    BackupKeySource, decrypt_backup_with_keys, encrypt_backup, is_encrypted_backup, resolve_backup_key,
    resolve_legacy_backup_keys,
};

static RESTORE_STAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn append_backup_chunk_with_limit(
    data: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> bool {
    let Some(new_len) = data
        .len()
        .checked_add(chunk.len())
    else {
        return false;
    };
    if new_len > limit {
        return false;
    }
    data.extend_from_slice(chunk);
    true
}

fn append_backup_chunk(
    data: &mut Vec<u8>,
    chunk: &[u8],
) -> bool {
    append_backup_chunk_with_limit(data, chunk, super::MAX_ENCRYPTED_ARCHIVE_BYTES)
}

fn stage_backup_atomically(
    backup_restore_dir: &std::path::Path,
    data: &[u8],
) -> anyhow::Result<std::path::PathBuf> {
    use std::io::Write;

    let _guard = RESTORE_STAGE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("restore staging lock is poisoned"))?;
    let target = backup_restore_dir.join(super::BACKUP_STAGING_FILENAME);
    let temporary = backup_restore_dir.join(format!(".{}.{}.tmp", super::BACKUP_STAGING_FILENAME, std::process::id()));
    if temporary.exists() {
        std::fs::remove_file(&temporary)?;
    }
    let result = (|| -> anyhow::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &target)?;
        std::fs::File::open(backup_restore_dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    Ok(target)
}

fn record_api_restore_failure(
    user_id: &str,
    target_domain: &str,
    category: &str,
    archive_size_bytes: Option<usize>,
) {
    record_api_restore_failure_with_context(user_id, target_domain, category, archive_size_bytes, None, None);
}

fn record_api_restore_failure_with_context(
    user_id: &str,
    target_domain: &str,
    category: &str,
    archive_size_bytes: Option<usize>,
    key_source: Option<&str>,
    source_domain: Option<&str>,
) {
    record_storage_audit(StorageAuditEvent {
        operation: StorageOperation::Restore,
        actor_id: user_id,
        actor_type: "user",
        restore_path: Some("api"),
        key_source,
        source_domain,
        target_domain: Some(target_domain),
        outcome: "failure",
        failure_category: Some(category),
        archive_size_bytes,
    });
}

#[derive(Debug)]
struct PreparedRestore {
    zip_data: Vec<u8>,
    key_source: BackupKeySource,
    manifest: super::manifest::BackupManifest,
}

#[derive(Debug)]
struct RestorePreparationError {
    cause: anyhow::Error,
    category: &'static str,
    key_source: Option<BackupKeySource>,
    source_domain: Option<String>,
}

impl std::fmt::Display for RestorePreparationError {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        self.cause.fmt(formatter)
    }
}

fn preparation_error(
    cause: impl Into<anyhow::Error>,
    category: &'static str,
    key_source: Option<BackupKeySource>,
    source_domain: Option<String>,
) -> RestorePreparationError {
    RestorePreparationError {
        cause: cause.into(),
        category,
        key_source,
        source_domain,
    }
}

fn prepare_restore_upload(
    backup_data: &[u8],
    key: &[u8; 32],
    legacy_backup_encryption_keys: Option<&str>,
    target_domain: &str,
) -> Result<PreparedRestore, RestorePreparationError> {
    let legacy_keys = resolve_legacy_backup_keys(legacy_backup_encryption_keys)
        .map_err(|error| preparation_error(error, "legacy_key_configuration_invalid", None, None))?;
    prepare_restore_upload_with_keys(backup_data, key, &legacy_keys, target_domain)
}

fn prepare_restore_upload_with_keys(
    backup_data: &[u8],
    key: &[u8; 32],
    legacy_keys: &[[u8; 32]],
    target_domain: &str,
) -> Result<PreparedRestore, RestorePreparationError> {
    if !is_encrypted_backup(backup_data) {
        return Err(preparation_error(anyhow::anyhow!("backup is not encrypted"), "encryption_required", None, None));
    }

    let decrypted = decrypt_backup_with_keys(key, legacy_keys, backup_data)
        .map_err(|error| preparation_error(error, "authentication_failed", None, None))?;
    let key_source = decrypted.key_source;
    super::validate_zip_entries(&decrypted.bytes)
        .map_err(|error| preparation_error(error, "zip_invalid", Some(key_source), None))?;
    let parsed_manifest = super::manifest::read_optional_backup_manifest(&decrypted.bytes)
        .map_err(|error| preparation_error(error, "manifest_invalid", Some(key_source), None))?;
    let source_domain = parsed_manifest
        .as_ref()
        .and_then(|manifest| super::manifest::canonicalize_domain(&manifest.source_domain).ok());
    let (zip_data, manifest) = match parsed_manifest {
        Some(manifest) => {
            let manifest =
                super::manifest::validate_parsed_backup_manifest(manifest, target_domain).map_err(|error| {
                    preparation_error(error, "manifest_invalid", Some(key_source), source_domain.clone())
                })?;
            (decrypted.bytes, manifest)
        }
        None if key_source == BackupKeySource::Legacy => {
            let zip_data = super::manifest::add_backup_manifest(&decrypted.bytes, target_domain, true)
                .map_err(|error| preparation_error(error, "manifest_migration_failed", Some(key_source), None))?;
            let manifest = super::manifest::validate_backup_manifest(&zip_data, target_domain)
                .map_err(|error| preparation_error(error, "manifest_migration_failed", Some(key_source), None))?;
            (zip_data, manifest)
        }
        None => {
            return Err(preparation_error(
                anyhow::anyhow!("backup manifest is missing"),
                "manifest_missing",
                Some(key_source),
                None,
            ));
        }
    };

    Ok(PreparedRestore { zip_data, key_source, manifest })
}

/// RBAC guard shared by the storage backup/restore endpoints.
///
/// Returns `Some(response)` (403 or 500) when the caller is NOT permitted to
/// perform full-storage operations, and `None` when the caller is authorised.
async fn deny_unless_storage_admin(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
    operation: StorageOperation,
) -> Option<Response> {
    match storage
        .load_user_by_id(user_id)
        .await
    {
        Ok(Some(user)) if rbac_config.has_permission(&user.role, &Feature::StorageAdmin) => None,
        Ok(_) => {
            record_storage_audit(StorageAuditEvent {
                operation,
                actor_id: user_id,
                actor_type: "user",
                restore_path: (operation == StorageOperation::Restore).then_some("api"),
                key_source: None,
                source_domain: None,
                target_domain: None,
                outcome: "denied",
                failure_category: Some("insufficient_permissions"),
                archive_size_bytes: None,
            });
            warn!(user_id = %user_id, feature = "storage.admin", "Storage admin operation rejected — insufficient permissions");
            Some(
                (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response(),
            )
        }
        Err(e) => {
            record_storage_audit(StorageAuditEvent {
                operation,
                actor_id: user_id,
                actor_type: "user",
                restore_path: (operation == StorageOperation::Restore).then_some("api"),
                key_source: None,
                source_domain: None,
                target_domain: None,
                outcome: "failure",
                failure_category: Some("authorization_check_failed"),
                archive_size_bytes: None,
            });
            error!(user_id = %user_id, "RBAC check failed loading user: {}", e);
            Some(
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Authorization check failed"})))
                    .into_response(),
            )
        }
    }
}

/// Backup storage: zip the entire `_storage` folder (including PIIs), encrypt, and return as `backup.agbak`.
pub async fn backup_storage(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<IdentityApiState>,
) -> Response {
    if let Some(resp) =
        deny_unless_storage_admin(&user_id, &passkey_storage, &rbac_config, StorageOperation::Backup).await
    {
        return resp;
    }

    record_storage_audit(StorageAuditEvent {
        operation: StorageOperation::Backup,
        actor_id: &user_id,
        actor_type: "user",
        restore_path: None,
        key_source: None,
        source_domain: Some(
            &state
                .network_config
                .did
                .domain,
        ),
        target_domain: None,
        outcome: "attempt",
        failure_category: None,
        archive_size_bytes: None,
    });
    info!("Portable storage backup requested via API (skipped directories: {:?})", super::BACKUP_SKIP_DIRS);

    let storage_root = crate::export::resolve_storage_root(
        &state
            .bootstrap_config
            .storage_paths
            .agent_surfaces,
        "",
    );

    // Resolve the required backup key before the blocking task (resolution is async).
    let key = match resolve_backup_key(
        &state
            .bootstrap_config
            .backup_encryption_key,
    )
    .await
    {
        Ok(key) => key,
        Err(e) => {
            error!("Backup key not available: {:#}", e);
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Backup,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: None,
                key_source: None,
                source_domain: Some(
                    &state
                        .network_config
                        .did
                        .domain,
                ),
                target_domain: None,
                outcome: "failure",
                failure_category: Some("key_unavailable"),
                archive_size_bytes: None,
            });
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Backup encryption is unavailable"})),
            )
                .into_response();
        }
    };

    let source_domain = state
        .network_config
        .did
        .domain
        .clone();
    let audit_source_domain = source_domain.clone();
    let result = tokio::task::spawn_blocking(move || {
        let zip_bytes = super::build_portable_zip(&storage_root, &source_domain)?;
        let encrypted = encrypt_backup(&key, &zip_bytes)?;
        if encrypted.len() > super::MAX_ENCRYPTED_ARCHIVE_BYTES {
            anyhow::bail!("generated backup exceeds the 64 MiB archive limit");
        }
        Ok(encrypted)
    })
    .await;

    match result {
        Ok(Ok(encrypted_bytes)) => {
            let size = encrypted_bytes.len();
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Backup,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: None,
                key_source: Some("current"),
                source_domain: Some(&audit_source_domain),
                target_domain: None,
                outcome: "success",
                failure_category: None,
                archive_size_bytes: Some(size),
            });
            info!("Encrypted storage backup complete: {} bytes", size);

            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            headers
                .insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=\"backup.agbak\""));

            (StatusCode::OK, headers, Body::from(encrypted_bytes)).into_response()
        }
        Ok(Err(e)) => {
            error!("Storage backup failed: {:#}", e);
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Backup,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: None,
                key_source: Some("current"),
                source_domain: Some(&audit_source_domain),
                target_domain: None,
                outcome: "failure",
                failure_category: Some("backup_failed"),
                archive_size_bytes: None,
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Backup failed"}))).into_response()
        }
        Err(e) => {
            error!("Storage backup task panicked: {:#}", e);
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Backup,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: None,
                key_source: Some("current"),
                source_domain: Some(&audit_source_domain),
                target_domain: None,
                outcome: "failure",
                failure_category: Some("task_failed"),
                archive_size_bytes: None,
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Backup task failed"})))
                .into_response()
        }
    }
}

/// Restore storage: accept a `backup.agbak` (or legacy `backup.tgwbak`) upload, write it next to `_storage`, then exit.
pub async fn restore_storage(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<IdentityApiState>,
    mut multipart: Multipart,
) -> Response {
    if let Some(resp) =
        deny_unless_storage_admin(&user_id, &passkey_storage, &rbac_config, StorageOperation::Restore).await
    {
        return resp;
    }

    record_storage_audit(StorageAuditEvent {
        operation: StorageOperation::Restore,
        actor_id: &user_id,
        actor_type: "user",
        restore_path: Some("api"),
        key_source: None,
        source_domain: None,
        target_domain: Some(
            &state
                .network_config
                .did
                .domain,
        ),
        outcome: "attempt",
        failure_category: None,
        archive_size_bytes: None,
    });
    info!("Storage restore requested via API");

    // Read the uploaded file without buffering beyond the encrypted archive limit.
    let mut backup_data: Option<Vec<u8>> = None;

    while let Some(mut field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to read restore multipart field: {e}");
            record_api_restore_failure(
                &user_id,
                &state
                    .network_config
                    .did
                    .domain,
                "multipart_invalid",
                None,
            );
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Failed to read backup upload"})))
                .into_response();
        }
    } {
        if field.name() == Some("backup") {
            let mut data = Vec::new();
            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) => {
                        let attempted_size = data
                            .len()
                            .saturating_add(chunk.len());
                        if !append_backup_chunk(&mut data, &chunk) {
                            record_api_restore_failure(
                                &user_id,
                                &state
                                    .network_config
                                    .did
                                    .domain,
                                "archive_too_large",
                                Some(attempted_size),
                            );
                            return (
                                StatusCode::PAYLOAD_TOO_LARGE,
                                Json(serde_json::json!({"error": "Backup archive exceeds the 64 MiB limit"})),
                            )
                                .into_response();
                        }
                    }
                    Ok(None) => {
                        backup_data = Some(data);
                        break;
                    }
                    Err(e) => {
                        warn!("Failed to read restore file data: {e}");
                        record_api_restore_failure(
                            &user_id,
                            &state
                                .network_config
                                .did
                                .domain,
                            "upload_read_failed",
                            Some(data.len()),
                        );
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "Failed to read backup upload"})),
                        )
                            .into_response();
                    }
                }
            }
            break;
        }
    }

    let backup_data = match backup_data {
        Some(d) => d,
        None => {
            record_api_restore_failure(
                &user_id,
                &state
                    .network_config
                    .did
                    .domain,
                "backup_missing",
                None,
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "No backup file provided. Upload a field named 'backup'."})),
            )
                .into_response();
        }
    };

    // Decrypt and validate the uploaded backup
    let key = match resolve_backup_key(
        &state
            .bootstrap_config
            .backup_encryption_key,
    )
    .await
    {
        Ok(key) => key,
        Err(e) => {
            error!("Backup key not available: {:#}", e);
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Restore,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: Some("api"),
                key_source: None,
                source_domain: None,
                target_domain: Some(
                    &state
                        .network_config
                        .did
                        .domain,
                ),
                outcome: "failure",
                failure_category: Some("key_unavailable"),
                archive_size_bytes: Some(backup_data.len()),
            });
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Backup encryption is unavailable"})),
            )
                .into_response();
        }
    };

    let prepared = match prepare_restore_upload(
        &backup_data,
        &key,
        state
            .bootstrap_config
            .legacy_backup_encryption_keys
            .as_deref(),
        &state
            .network_config
            .did
            .domain,
    ) {
        Ok(prepared) => prepared,
        Err(e) => {
            let key_source = e
                .key_source
                .map(|source| match source {
                    BackupKeySource::Current => "current",
                    BackupKeySource::Legacy => "legacy",
                });
            record_api_restore_failure_with_context(
                &user_id,
                &state
                    .network_config
                    .did
                    .domain,
                e.category,
                Some(backup_data.len()),
                key_source,
                e.source_domain.as_deref(),
            );
            warn!("Backup validation failed: {e}");
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Backup validation failed"})))
                .into_response();
        }
    };
    let key_source = match prepared.key_source {
        BackupKeySource::Current => "current",
        BackupKeySource::Legacy => "legacy",
    };
    let source_domain = prepared
        .manifest
        .source_domain
        .clone();
    let zip_data = prepared.zip_data;
    let staged_data = match encrypt_backup(&key, &zip_data) {
        Ok(staged_data) => staged_data,
        Err(e) => {
            error!("Failed to encrypt staged restore: {e}");
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Restore,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: Some("api"),
                key_source: Some(key_source),
                source_domain: Some(&source_domain),
                target_domain: Some(
                    &state
                        .network_config
                        .did
                        .domain,
                ),
                outcome: "failure",
                failure_category: Some("staging_encryption_failed"),
                archive_size_bytes: Some(zip_data.len()),
            });
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to stage backup restore"})),
            )
                .into_response();
        }
    };

    // Resolve backups directory from dedicated storage path
    let backup_restore_dir = std::path::PathBuf::from(
        &state
            .bootstrap_config
            .storage_paths
            .backup_restore,
    );

    if let Err(e) = std::fs::create_dir_all(&backup_restore_dir) {
        error!("Failed to create backups directory: {}", e);
        record_api_restore_failure_with_context(
            &user_id,
            &state
                .network_config
                .did
                .domain,
            "staging_directory_failed",
            Some(staged_data.len()),
            Some(key_source),
            Some(&source_domain),
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to stage backup restore"})),
        )
            .into_response();
    }

    let backup_zip_path = match stage_backup_atomically(&backup_restore_dir, &staged_data) {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to write staged backup: {e}");
            record_api_restore_failure_with_context(
                &user_id,
                &state
                    .network_config
                    .did
                    .domain,
                "staging_write_failed",
                Some(staged_data.len()),
                Some(key_source),
                Some(&source_domain),
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to stage backup restore"})),
            )
                .into_response();
        }
    };

    record_storage_audit(StorageAuditEvent {
        operation: StorageOperation::Restore,
        actor_id: &user_id,
        actor_type: "user",
        restore_path: Some("api"),
        key_source: Some(key_source),
        source_domain: Some(&source_domain),
        target_domain: Some(
            &state
                .network_config
                .did
                .domain,
        ),
        outcome: "success",
        failure_category: None,
        archive_size_bytes: Some(staged_data.len()),
    });
    info!(
        "Staged backup written to {} ({} bytes, encrypted). Exiting for restart... Note: backup does not include directories {:?}",
        backup_zip_path.display(),
        staged_data.len(),
        super::BACKUP_SKIP_DIRS
    );

    // Schedule exit after a short delay so the response can be sent
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        warn!("Exiting with code 1 to trigger restart for backup restore");
        std::process::exit(1);
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": "Backup saved. The service will restart to complete the restore."
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::UserData;
    use crate::auth::types::{UserRole, UserStatus};

    #[test]
    fn backup_upload_chunks_are_bounded_before_append() {
        let mut data = b"1234".to_vec();
        assert!(append_backup_chunk_with_limit(&mut data, b"56", 6));
        assert_eq!(data, b"123456");
        assert!(!append_backup_chunk_with_limit(&mut data, b"7", 6));
        assert_eq!(data, b"123456");
    }

    /// Build an in-memory PasskeyStorage seeded with a single Approved user of the given role.
    async fn storage_with_user(
        user_id: &str,
        role: UserRole,
    ) -> (Arc<PasskeyStorage>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = PasskeyStorage::new(
            tmp.path()
                .join("passkeys")
                .to_string_lossy()
                .to_string(),
            tmp.path()
                .join("avatars")
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("storage init");
        let now = chrono::Utc::now();
        let user = UserData {
            user_id: user_id.to_string(),
            username: format!("user-{user_id}"),
            passkeys: Vec::new(),
            role,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: None,
        };
        storage
            .save_user(&user)
            .await
            .expect("save user");
        (Arc::new(storage), tmp)
    }

    #[test]
    fn restore_staging_atomically_replaces_the_published_archive() {
        let directory = tempfile::tempdir().unwrap();
        let target = stage_backup_atomically(directory.path(), b"first").unwrap();
        stage_backup_atomically(directory.path(), b"second").unwrap();

        assert_eq!(std::fs::read(target).unwrap(), b"second");
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .count(),
            1,
        );
    }

    #[test]
    fn concurrent_restore_staging_publishes_one_complete_archive() {
        let directory = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();
        for value in 0u8..8 {
            let path = directory.path().to_path_buf();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                stage_backup_atomically(&path, &[value; 128]).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let published = std::fs::read(
            directory
                .path()
                .join(crate::backup_restore::BACKUP_STAGING_FILENAME),
        )
        .unwrap();
        assert_eq!(published.len(), 128);
        assert!(
            published
                .iter()
                .all(|byte| *byte == published[0])
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .count(),
            1,
        );
    }

    #[test]
    fn uploaded_backup_rejects_mismatched_domain() {
        let temp = tempfile::tempdir().unwrap();
        let storage_root = temp.path().join("_storage");
        std::fs::create_dir_all(&storage_root).unwrap();
        std::fs::write(storage_root.join("record.json"), b"{}").unwrap();
        let key = [0x44; 32];
        let zip = super::super::build_portable_zip(&storage_root, "source.example.com").unwrap();
        let encrypted = encrypt_backup(&key, &zip).unwrap();

        let error = prepare_restore_upload(&encrypted, &key, None, "target.example.com").unwrap_err();

        assert_eq!(error.key_source, Some(BackupKeySource::Current));
        assert_eq!(error.source_domain.as_deref(), Some("source.example.com"));
        assert_eq!(error.category, "manifest_invalid");
    }

    #[test]
    fn uploaded_current_key_backup_requires_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let storage_root = temp.path().join("_storage");
        std::fs::create_dir_all(&storage_root).unwrap();
        std::fs::write(storage_root.join("record.json"), b"{}").unwrap();
        let current = [0x44; 32];
        let zip = super::super::build_full_zip(&storage_root).unwrap();
        let encrypted = encrypt_backup(&current, &zip).unwrap();

        let result = prepare_restore_upload_with_keys(&encrypted, &current, &[], "gateway.example.com");

        assert!(result.is_err());
    }

    #[test]
    fn uploaded_legacy_backup_is_rebound_to_current_domain() {
        let temp = tempfile::tempdir().unwrap();
        let storage_root = temp.path().join("_storage");
        std::fs::create_dir_all(&storage_root).unwrap();
        std::fs::write(storage_root.join("record.json"), b"{}").unwrap();
        let current = [0x44; 32];
        let legacy = [0x55; 32];
        let zip = super::super::build_full_zip(&storage_root).unwrap();
        let encrypted = encrypt_backup(&legacy, &zip).unwrap();

        let prepared =
            prepare_restore_upload_with_keys(&encrypted, &current, &[legacy], "gateway.example.com").unwrap();

        assert_eq!(prepared.key_source, BackupKeySource::Legacy);
        assert!(
            prepared
                .manifest
                .legacy_import
        );
        assert_eq!(
            prepared
                .manifest
                .source_domain,
            "gateway.example.com"
        );
        super::super::manifest::validate_backup_manifest(&prepared.zip_data, "gateway.example.com").unwrap();
    }

    #[tokio::test]
    async fn storage_admin_allows_administrator() {
        let (storage, _tmp) = storage_with_user("admin-1", UserRole::Administrator).await;
        let rbac = RbacConfig::default();
        assert!(
            deny_unless_storage_admin("admin-1", &storage, &rbac, StorageOperation::Backup)
                .await
                .is_none(),
            "administrator must be allowed"
        );
    }

    #[tokio::test]
    async fn storage_admin_denies_regular_user() {
        let (storage, _tmp) = storage_with_user("user-1", UserRole::User).await;
        let rbac = RbacConfig::default();
        let resp = deny_unless_storage_admin("user-1", &storage, &rbac, StorageOperation::Backup)
            .await
            .expect("regular user must be denied");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn storage_admin_denies_poweruser() {
        let (storage, _tmp) = storage_with_user("pu-1", UserRole::PowerUser).await;
        let rbac = RbacConfig::default();
        let resp = deny_unless_storage_admin("pu-1", &storage, &rbac, StorageOperation::Backup)
            .await
            .expect("poweruser must be denied");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn storage_admin_denies_unknown_user() {
        // Session valid but the user record is gone — fail closed (403).
        let (storage, _tmp) = storage_with_user("admin-1", UserRole::Administrator).await;
        let rbac = RbacConfig::default();
        let resp = deny_unless_storage_admin("ghost", &storage, &rbac, StorageOperation::Backup)
            .await
            .expect("unknown user must be denied");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
