//! Encryption-aware whole-file read/write for standalone secret files.
//!
//! DID private-key material (connection points, trust registries, departments,
//! did:webvh identities) and VC issuer keys are persisted as individual JSON
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
    if let Err(e) = tokio::fs::remove_file(path).await {
        crate::metrics::backends::prometheus::track_storage_plaintext_removal_failed("secret_file");
        error!(
            "Failed to delete plaintext secret file {} after encryption; key material may remain on disk: {}",
            path.display(),
            e
        );
    }
}

/// Write a secret file. When encryption at rest is active the content is written
/// as a whole-file `.enc` blob and any plaintext sibling is removed, so key
/// material never lingers in plaintext. Otherwise it is written as plaintext and
/// any stale `.enc` sibling is removed.
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
            tokio::fs::write(&enc_path, ciphertext)
                .await
                .with_context(|| format!("Failed to write encrypted secret file {}", enc_path.display()))?;
            remove_plaintext_sibling(path).await;
        }
        None => {
            tokio::fs::write(path, contents)
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
            if enc_path.exists() {
                let ciphertext = tokio::fs::read_to_string(&enc_path)
                    .await
                    .with_context(|| format!("Failed to read encrypted secret file {}", enc_path.display()))?;
                let plaintext = service
                    .decrypt_string(ciphertext)
                    .with_context(|| format!("Failed to decrypt secret file {}", enc_path.display()))?;
                remove_plaintext_sibling(path).await;
                Ok(Some(plaintext))
            } else if path.exists() {
                let content = tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("Failed to read secret file {}", path.display()))?;
                // Migrate plaintext-only to whole-file encryption, then drop the plaintext.
                write_secret_file(path, &content).await?;
                Ok(Some(content))
            } else {
                Ok(None)
            }
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
