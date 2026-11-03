//! Encryption-aware whole-file read/write for standalone secret files.
//!
//! DID private-key material (connection points, trust registries, departments,
//! did:webvh identities), VC issuer keys and the transit token signing key are persisted as individual JSON
//! files *outside* the generic `StorageBackend` layer. These helpers give those
//! files the same whole-file encryption-at-rest the generic layer provides:
//!
//! - When encryption at rest is active, the `{path}.enc` ciphertext blob is
//!   authoritative and any plaintext sibling is removed, so key material never
//!   lingers in plaintext.
//! - When it is disabled, the plaintext file is authoritative and any stale
//!   `.enc` sibling is removed.
//! - Reads transparently decrypt the `.enc` sibling, and — when encryption is
//!   active — converge on-disk state by migrating a plaintext-only file to
//!   `.enc` and dropping the plaintext, mirroring the generic storage layer.
//!
//! Only private-key files should be routed through these helpers. Public
//! artefacts that must stay resolvable as plaintext (e.g. a `did.json` served
//! over HTTP) must continue to use plain filesystem writes.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::{error, warn};

use crate::encryption::EncryptionService;
use crate::storage::filesystem::{AtomicWriteError, atomic_write_file_with_mode};

/// Path of the whole-file-encrypted sibling for a plaintext secret file.
pub fn secret_enc_path(path: &Path) -> PathBuf {
    let mut os = path
        .as_os_str()
        .to_os_string();
    os.push(".enc");
    PathBuf::from(os)
}

/// The active whole-file encryption service, or `None` when encryption at rest
/// is disabled (a disabled service is a pass-through and must not be used to
/// write a `.enc` blob).
fn active_encryption() -> Option<EncryptionService> {
    match crate::encryption::global::get_encryption_service() {
        Some(service) if service.is_enabled() => Some(service),
        _ => None,
    }
}

/// Best-effort removal of a plaintext secret file once its `.enc` sibling is
/// authoritative. A failure is logged at `error` and metered, not propagated:
/// the record is already durably encrypted, but a lingering plaintext file is a
/// key-material exposure operators must be able to alert on.
///
/// The deletion is guarded by the encrypt-then-delete invariant: the plaintext is
/// removed only when its ciphertext sibling actually exists on disk. If the `.enc`
/// is missing the plaintext is the only readable copy of the key material, so the
/// removal is refused (and metered) rather than destroying it.
async fn remove_plaintext_sibling(path: &Path) {
    if !path.exists() {
        return;
    }
    let enc_path = secret_enc_path(path);
    if !enc_path.exists() {
        crate::metrics::backends::prometheus::track_storage_plaintext_removal_failed("secret_file");
        error!(
            "Refusing to delete plaintext secret file {}: its encrypted sibling {} is missing, so this \
             is the only readable copy of the key material",
            path.display(),
            enc_path.display()
        );
        return;
    }
    if let Err(e) = tokio::fs::remove_file(path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        crate::metrics::backends::prometheus::track_storage_plaintext_removal_failed("secret_file");
        error!(
            "Failed to delete plaintext secret file {} after encryption; key material may remain on disk: {}",
            path.display(),
            e
        );
    }
}

/// Write `bytes` to `path`, readable by its owner only, replacing any previous
/// file atomically, so a reader sharing the directory sees the previous file or
/// the new one, never a partly written one.
async fn write_owner_only(
    path: &Path,
    bytes: &[u8],
) -> Result<()> {
    atomic_write_file_with_mode(path, bytes, Some(0o600))
        .await
        .map_err(|(AtomicWriteError::NotReplaced(error) | AtomicWriteError::ReplacedButUnsynced(error))| error)
}

/// Write a secret file, readable by its owner only and replaced atomically.
/// When encryption at rest is active the content is written as a whole-file
/// `.enc` blob and any plaintext sibling is removed, so key material never
/// lingers in plaintext. Otherwise it is written as plaintext and any stale
/// `.enc` sibling is removed.
pub async fn write_secret_file(
    path: &Path,
    contents: &str,
) -> Result<()> {
    let enc_path = secret_enc_path(path);
    match active_encryption() {
        Some(service) => {
            let ciphertext = service
                .encrypt_string(contents.to_string())
                .context("Failed to encrypt secret file")?;
            write_owner_only(&enc_path, ciphertext.as_bytes())
                .await
                .with_context(|| format!("Failed to write encrypted secret file {}", enc_path.display()))?;
            remove_plaintext_sibling(path).await;
        }
        None => {
            write_owner_only(path, contents.as_bytes())
                .await
                .with_context(|| format!("Failed to write secret file {}", path.display()))?;
            if enc_path.exists()
                && let Err(e) = tokio::fs::remove_file(&enc_path).await
            {
                warn!("Failed to remove stale encrypted secret file {}: {}", enc_path.display(), e);
            }
        }
    }
    Ok(())
}

/// Create a secret file, in the form [`write_secret_file`] would write, only when
/// neither form exists yet. The file is readable by its owner only. Returns
/// `false`, leaving the existing file untouched, when the file already exists,
/// including when another process sharing the directory creates it at the same
/// moment: the content is written in full to a temporary file and then
/// hard-linked into place, which fails rather than replacing a file, so exactly
/// one creator wins and no reader sees a partly written file. The directory must
/// therefore support hard links; one that does not fails the creation with an
/// error saying so. Creators that disagree on encryption at rest can each create
/// a different form at once; a creator that then finds the other form beside its
/// own removes its own and fails, so no two keys stay in use.
pub async fn create_secret_file(
    path: &Path,
    contents: &str,
) -> Result<bool> {
    let enc_path = secret_enc_path(path);
    if path.exists() || enc_path.exists() {
        return Ok(false);
    }
    let (target, other_form, bytes) = match active_encryption() {
        Some(service) => (
            enc_path,
            path.to_path_buf(),
            service
                .encrypt_string(contents.to_string())
                .context("Failed to encrypt secret file")?,
        ),
        None => (path.to_path_buf(), enc_path, contents.to_string()),
    };
    let mut staged = target
        .as_os_str()
        .to_os_string();
    staged.push(format!(".{}.new", uuid::Uuid::new_v4()));
    let staged = PathBuf::from(staged);
    if let Err(error) = write_owner_only(&staged, bytes.as_bytes()).await {
        let _ = tokio::fs::remove_file(&staged).await;
        return Err(error).with_context(|| format!("Failed to write secret file {}", target.display()));
    }
    let linked = tokio::fs::hard_link(&staged, &target).await;
    if let Err(error) = tokio::fs::remove_file(&staged).await {
        warn!("Failed to remove staged secret file {}: {}", staged.display(), error);
    }
    match linked {
        Ok(()) => settle_created_secret_file(&target, &other_form).await,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "Failed to create secret file {} by hard-linking a complete copy into place; its directory must be on \
                 a filesystem that supports hard links",
                target.display()
            )
        }),
    }
}

/// Make a just-linked secret file durable, and give it up again when the other
/// form of the same secret now exists beside it. Every creator checks after
/// linking, so of two creators of different forms at least one sees the other.
async fn settle_created_secret_file(
    target: &Path,
    other_form: &Path,
) -> Result<bool> {
    #[cfg(unix)]
    if let Some(parent) = target.parent() {
        crate::storage::filesystem::sync_directory(parent)
            .await
            .with_context(|| format!("Failed to sync the directory of secret file {}", target.display()))?;
    }
    if !other_form.exists() {
        return Ok(true);
    }
    if let Err(error) = tokio::fs::remove_file(target).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        error!("Failed to remove secret file {} created beside {}: {}", target.display(), other_form.display(), error);
    }
    anyhow::bail!(
        "Secret file {} was created at the same time as {}: processes sharing this directory disagree on encryption \
         at rest",
        target.display(),
        other_form.display()
    )
}

/// Restrict a secret file, in whichever form exists, to its owner, when it was
/// written with the process default mode, as a restore writes every file. A
/// failure is logged and does not stop the caller.
pub async fn restrict_secret_file_to_owner(path: &Path) {
    #[cfg(unix)]
    for path in [path.to_path_buf(), secret_enc_path(path)] {
        use std::os::unix::fs::PermissionsExt;

        let Ok(metadata) = tokio::fs::metadata(&path).await else {
            continue;
        };
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 == 0 {
            continue;
        }
        match tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await {
            Ok(()) => tracing::info!(
                path = %path.display(),
                previous_mode = format!("{mode:o}"),
                "Restricted secret file to its owner"
            ),
            Err(error) => warn!("Failed to restrict secret file {} to its owner: {}", path.display(), error),
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The content of `path`, or `None` when it does not exist.
async fn read_if_present(path: &Path) -> std::io::Result<Option<String>> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The decrypted `.enc` sibling of `path`, removing any plaintext beside it, or
/// `None` when there is no `.enc` sibling.
async fn read_encrypted_secret_file(
    service: &EncryptionService,
    path: &Path,
) -> Result<Option<String>> {
    let enc_path = secret_enc_path(path);
    let Some(ciphertext) = read_if_present(&enc_path)
        .await
        .with_context(|| format!("Failed to read encrypted secret file {}", enc_path.display()))?
    else {
        return Ok(None);
    };
    let plaintext = service
        .decrypt_string(ciphertext)
        .with_context(|| format!("Failed to decrypt secret file {}", enc_path.display()))?;
    remove_plaintext_sibling(path).await;
    Ok(Some(plaintext))
}

/// Read a secret file, transparently decrypting the whole-file `.enc` sibling
/// when encryption at rest is active. Returns `None` when neither the encrypted
/// nor the plaintext form exists.
///
/// When encryption is active this also converges the on-disk state: a plaintext
/// file sitting beside an authoritative `.enc` is removed (ciphertext wins), and
/// a plaintext-only file is migrated to `.enc` and its plaintext deleted — so
/// enabling encryption removes lingering plaintext on the next read.
///
/// When encryption is disabled but an encrypted-only `.enc` sibling exists (no
/// readable plaintext), this fails loudly instead of reporting the secret as
/// missing — mirroring the generic storage loader's
/// `encrypted_but_encryption_disabled` behaviour. Reporting `None` would let
/// callers (VC issuer / DID stores) treat the key as absent and regenerate it,
/// persisting fresh plaintext key material beside the unreadable ciphertext.
pub async fn read_secret_file(path: &Path) -> Result<Option<String>> {
    let enc_path = secret_enc_path(path);
    match active_encryption() {
        Some(service) => {
            if let Some(plaintext) = read_encrypted_secret_file(&service, path).await? {
                return Ok(Some(plaintext));
            }
            let Some(content) = read_if_present(path)
                .await
                .with_context(|| format!("Failed to read secret file {}", path.display()))?
            else {
                // Another instance sharing the directory may have migrated the file
                // between the two reads, removing the plaintext once its `.enc` was
                // in place.
                return read_encrypted_secret_file(&service, path).await;
            };
            // Migrate plaintext-only to whole-file encryption, then drop the plaintext.
            write_secret_file(path, &content).await?;
            Ok(Some(content))
        }
        None => {
            if path.exists() {
                let content = tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("Failed to read secret file {}", path.display()))?;
                Ok(Some(content))
            } else if enc_path.exists() {
                // Encrypted-only secret with encryption at rest disabled: it cannot be
                // decrypted. Fail loudly rather than reporting it missing, so callers do
                // not regenerate the key and persist new plaintext beside the ciphertext.
                crate::metrics::backends::prometheus::track_storage_load_error(
                    "secret_file",
                    "encrypted_but_encryption_disabled",
                );
                anyhow::bail!(
                    "Secret file {} exists only as an encrypted sibling ({}) but encryption at rest \
                     is disabled; refusing to treat it as missing. Re-enable encryption or migrate \
                     this file to plaintext.",
                    path.display(),
                    enc_path.display()
                );
            } else {
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EncryptionConfig;
    use crate::config::KeySourceConfig;
    use crate::encryption::EncryptionService;

    fn enabled_local_service() -> EncryptionService {
        // Raw-key local MEK service — deterministic, no env/KMS needed.
        EncryptionService::new(crate::encryption::KeySource::Raw { key: [7u8; 32] }).unwrap()
    }

    fn install_enabled_encryption() {
        let config = EncryptionConfig {
            enabled: true,
            key_source: KeySourceConfig::Environment,
            ..EncryptionConfig::default()
        };
        crate::encryption::global::set_test_encryption(config, enabled_local_service());
    }

    #[tokio::test]
    async fn round_trips_plaintext_when_encryption_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");

        write_secret_file(&path, "{\"secret\":\"material\"}")
            .await
            .unwrap();

        // Plaintext file exists and is readable as-is; no .enc sibling.
        assert!(path.exists());
        assert!(!secret_enc_path(&path).exists());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, "{\"secret\":\"material\"}");

        let read = read_secret_file(&path)
            .await
            .unwrap();
        assert_eq!(read.as_deref(), Some("{\"secret\":\"material\"}"));
    }

    #[tokio::test]
    async fn write_encrypts_and_removes_plaintext_when_enabled() {
        install_enabled_encryption();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");

        write_secret_file(&path, "{\"secret\":\"material\"}")
            .await
            .unwrap();

        // The ciphertext sibling is authoritative; no plaintext lingers.
        let enc_path = secret_enc_path(&path);
        assert!(enc_path.exists(), "encrypted sibling must exist");
        assert!(!path.exists(), "plaintext must be removed");

        // On-disk bytes are not readable as the original JSON.
        let on_disk = std::fs::read_to_string(&enc_path).unwrap();
        assert!(on_disk.starts_with("ENC["), "on-disk value must be an envelope, got: {on_disk}");
        assert!(!on_disk.contains("material"), "plaintext secret must not appear on disk");

        // Round-trips back to the original plaintext.
        let read = read_secret_file(&path)
            .await
            .unwrap();
        assert_eq!(read.as_deref(), Some("{\"secret\":\"material\"}"));
    }

    #[tokio::test]
    async fn read_migrates_plaintext_only_to_encrypted_when_enabled() {
        install_enabled_encryption();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");

        // Simulate a legacy plaintext-only file written before encryption was on.
        std::fs::write(&path, "{\"secret\":\"legacy\"}").unwrap();

        let read = read_secret_file(&path)
            .await
            .unwrap();
        assert_eq!(read.as_deref(), Some("{\"secret\":\"legacy\"}"));

        // After the read the plaintext is migrated to .enc and removed.
        assert!(secret_enc_path(&path).exists(), "should have migrated to .enc");
        assert!(!path.exists(), "plaintext should be gone after migration");
    }

    #[cfg(unix)]
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn written_and_migrated_secret_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let written = dir
            .path()
            .join("written.json");
        write_secret_file(&written, "{\"secret\":\"written\"}")
            .await
            .unwrap();
        assert_eq!(file_mode(&written), 0o600);

        install_enabled_encryption();
        let legacy = dir.path().join("legacy.json");
        std::fs::write(&legacy, "{\"secret\":\"legacy\"}").unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o644)).unwrap();

        read_secret_file(&legacy)
            .await
            .unwrap();

        assert_eq!(file_mode(&secret_enc_path(&legacy)), 0o600, "the migrated ciphertext is owner-only");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_restored_secret_file_is_restricted_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        std::fs::write(&path, "{\"secret\":\"restored\"}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        restrict_secret_file_to_owner(&path).await;

        assert_eq!(file_mode(&path), 0o600);
    }

    #[tokio::test]
    async fn read_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("missing.json");
        let read = read_secret_file(&path)
            .await
            .unwrap();
        assert!(read.is_none());
    }

    #[tokio::test]
    async fn read_errors_on_encrypted_only_when_encryption_disabled() {
        // Encryption at rest is disabled (no service installed), but only a `.enc`
        // sibling exists on disk — the plaintext is gone. The read must fail loudly
        // rather than report the secret as missing, so callers do not regenerate the
        // key and persist fresh plaintext beside the unreadable ciphertext.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");
        std::fs::write(secret_enc_path(&path), "ENC[whatever]").unwrap();

        let err = read_secret_file(&path)
            .await
            .expect_err("must fail when only an encrypted sibling exists and encryption is disabled");
        let msg = err.to_string();
        assert!(msg.contains("encryption at rest"), "error must explain the encryption-disabled cause, got: {msg}");
        // The unreadable ciphertext is left intact for recovery.
        assert!(secret_enc_path(&path).exists(), "encrypted sibling must not be deleted");
    }

    #[tokio::test]
    async fn create_writes_an_owner_only_file_once_and_never_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");

        assert!(
            create_secret_file(&path, "first")
                .await
                .unwrap()
        );
        assert!(
            !create_secret_file(&path, "second")
                .await
                .unwrap()
        );

        assert_eq!(
            read_secret_file(&path)
                .await
                .unwrap()
                .as_deref(),
            Some("first")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("key.json")], "no staged file may be left behind");
    }

    #[tokio::test]
    async fn create_lets_exactly_one_of_two_concurrent_creators_win() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");

        let (first, second) = tokio::join!(create_secret_file(&path, "first"), create_secret_file(&path, "second"));
        let (first, second) = (first.unwrap(), second.unwrap());

        assert!(first ^ second, "exactly one creator must win, got {first} and {second}");
        let winner = if first {
            "first"
        } else {
            "second"
        };
        assert_eq!(
            read_secret_file(&path)
                .await
                .unwrap()
                .as_deref(),
            Some(winner)
        );
    }

    #[tokio::test]
    async fn a_created_secret_file_is_given_up_when_the_other_form_appeared_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("transit_token_key.json");
        let enc_path = secret_enc_path(&path);
        std::fs::write(&path, "plaintext key").unwrap();
        std::fs::write(&enc_path, "ENC[other key]").unwrap();

        let error = settle_created_secret_file(&enc_path, &path)
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("disagree on encryption at rest"), "{error}");
        assert!(!enc_path.exists(), "the losing form is removed");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "plaintext key", "the other form is left intact");
    }

    #[tokio::test]
    async fn a_created_secret_file_without_the_other_form_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("transit_token_key.json");
        std::fs::write(&path, "plaintext key").unwrap();

        assert!(
            settle_created_secret_file(&path, &secret_enc_path(&path))
                .await
                .unwrap()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "plaintext key");
    }

    #[tokio::test]
    async fn create_writes_only_ciphertext_when_encryption_is_enabled() {
        install_enabled_encryption();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");

        assert!(
            create_secret_file(&path, "{\"secret\":\"material\"}")
                .await
                .unwrap()
        );

        assert!(!path.exists(), "plaintext must never be written");
        let on_disk = std::fs::read_to_string(secret_enc_path(&path)).unwrap();
        assert!(on_disk.starts_with("ENC["), "on-disk value must be an envelope, got: {on_disk}");
        assert!(!on_disk.contains("material"));
        assert!(
            !create_secret_file(&path, "other")
                .await
                .unwrap(),
            "an encrypted file counts as existing"
        );
        assert_eq!(
            read_secret_file(&path)
                .await
                .unwrap()
                .as_deref(),
            Some("{\"secret\":\"material\"}")
        );
    }

    #[tokio::test]
    async fn remove_plaintext_sibling_keeps_plaintext_when_enc_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");
        std::fs::write(&path, "{\"secret\":\"only-copy\"}").unwrap();

        // No ciphertext sibling exists: the plaintext is the only readable copy of the
        // key material and must survive.
        remove_plaintext_sibling(&path).await;
        assert!(path.exists(), "plaintext must be kept when its .enc sibling is missing");

        // Once a ciphertext sibling exists, the plaintext may be removed.
        std::fs::write(secret_enc_path(&path), b"ENC[whatever]").unwrap();
        remove_plaintext_sibling(&path).await;
        assert!(!path.exists(), "plaintext must be removed once its .enc sibling exists");
    }
}
