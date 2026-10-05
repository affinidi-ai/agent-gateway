//! Post-restore re-encryption marker.
//!
//! A portable backup stores records as plaintext `.json` files (see
//! [`super::normalize`]). After such a backup is restored onto a node, those
//! records sit on disk as plaintext until the next boot, when the whole-file
//! storage encryption layer loads them, rewrites each as `.json.enc`, and deletes
//! the plaintext original (see `storage::filesystem` startup migration).
//!
//! Flow: [`mark_reencrypt_pending`] drops a durable marker at the end of a restore
//! (before the process exits to restart); [`maybe_run_post_restore_reencrypt`]
//! observes the marker on the following boot, once the encryption service is
//! initialised, and clears it.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::config::EncryptionConfig;

/// Marker file name written in the backup-restore directory to request a sweep.
const REENCRYPT_MARKER: &str = "pending_reencrypt";

fn marker_path(backup_restore_dir: &Path) -> PathBuf {
    backup_restore_dir.join(REENCRYPT_MARKER)
}

/// Record that a restore just happened, so the next boot re-encrypts field values
/// under the local KEK. Best-effort: a failure to write the marker is logged, not
/// fatal (records remain readable as plaintext; the storage layer encrypts them on
/// the next boot when it loads them).
pub fn mark_reencrypt_pending(backup_restore_dir: &Path) {
    let path = marker_path(backup_restore_dir);
    match std::fs::write(&path, b"1") {
        Ok(()) => info!("Marked post-restore re-encryption pending at {}", path.display()),
        Err(e) => warn!("Failed to write re-encryption marker {}: {}", path.display(), e),
    }
}

fn is_reencrypt_pending(backup_restore_dir: &Path) -> bool {
    marker_path(backup_restore_dir).exists()
}

fn clear_marker(backup_restore_dir: &Path) {
    let path = marker_path(backup_restore_dir);
    if path.exists()
        && let Err(e) = std::fs::remove_file(&path)
    {
        warn!("Failed to clear re-encryption marker {}: {}", path.display(), e);
    }
}

/// Re-save every `.json` file under `dir` (recursively) as type `T`.
///
/// Deserializing reads plaintext values (the encrypted-field serde deserializer is
/// backward-compatible with plaintext); re-serializing writes them back as
/// Observe the post-restore re-encryption marker if present.
///
/// Under whole-file storage encryption, restored records are plaintext `.json`
/// files that the storage layer encrypts to `.json.enc` (and deletes the plaintext
/// original) on this boot as it loads each store. There is no separate in-place
/// field sweep to run here, so this clears the marker and logs the eager-migration
/// behaviour. When encryption at rest is off, restored plaintext is the intended
/// on-disk state and the marker is simply cleared.
pub fn maybe_run_post_restore_reencrypt(
    backup_restore_dir: &Path,
    encryption: &EncryptionConfig,
) {
    if !is_reencrypt_pending(backup_restore_dir) {
        return;
    }

    if encryption.enabled {
        info!(
            "Post-restore records are plaintext on disk; the storage layer encrypts them to .json.enc \
             under this node's KEK and deletes the plaintext as it loads each store on this boot"
        );
    } else {
        info!("Post-restore re-encryption not required (encryption at rest disabled)");
    }
    clear_marker(backup_restore_dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_lifecycle() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!is_reencrypt_pending(dir.path()));
        mark_reencrypt_pending(dir.path());
        assert!(is_reencrypt_pending(dir.path()));
        clear_marker(dir.path());
        assert!(!is_reencrypt_pending(dir.path()));
    }

    #[test]
    fn maybe_run_clears_marker_when_encryption_enabled() {
        let dir = tempfile::TempDir::new().unwrap();
        mark_reencrypt_pending(dir.path());
        let encryption = EncryptionConfig {
            enabled: true,
            ..Default::default()
        };
        maybe_run_post_restore_reencrypt(dir.path(), &encryption);
        assert!(!is_reencrypt_pending(dir.path()), "marker must be cleared after observation");
    }

    #[test]
    fn maybe_run_clears_marker_when_encryption_disabled() {
        let dir = tempfile::TempDir::new().unwrap();
        mark_reencrypt_pending(dir.path());
        let encryption = EncryptionConfig {
            enabled: false,
            ..Default::default()
        };
        maybe_run_post_restore_reencrypt(dir.path(), &encryption);
        assert!(!is_reencrypt_pending(dir.path()), "marker must be cleared even when encryption is off");
    }

    #[test]
    fn maybe_run_is_noop_without_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let encryption = EncryptionConfig {
            enabled: true,
            ..Default::default()
        };
        maybe_run_post_restore_reencrypt(dir.path(), &encryption);
        assert!(!is_reencrypt_pending(dir.path()));
    }
}
