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
/// one creator wins and no reader sees a partly written file. A link that fails
/// for any reason other than the file already existing, as every link does on a
/// filesystem without hard links such as an SMB share, falls back to creating
/// the file exclusively and filling it in place (see
/// [`create_secret_file_in_place`]), which still lets exactly one creator win but
/// can leave a reader seeing it empty for a moment. Any existing form refuses
/// this creation, an empty one included: an empty file is what a creator killed
/// in that window leaves behind, but this creation cannot tell such a leftover
/// from a file another creator is filling right now, so removing one is the job
/// of a reader that has watched it stay the same empty file for as long as it is
/// willing to wait (see [`empty_secret_files`] and
/// [`remove_unchanged_empty_secret_files`]). Creators that disagree on
/// encryption at rest can each create a different form at once; a creator that
/// then finds the other form beside its own removes its own and fails, so no two
/// keys stay in use.
pub async fn create_secret_file(
    path: &Path,
    contents: &str,
) -> Result<bool> {
    let enc_path = secret_enc_path(path);
    for existing in [path, enc_path.as_path()] {
        if tokio::fs::metadata(existing)
            .await
            .is_ok()
        {
            return Ok(false);
        }
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
    let linked = hard_link_into_place(&staged, &target).await;
    if let Err(error) = tokio::fs::remove_file(&staged).await {
        warn!("Failed to remove staged secret file {}: {}", staged.display(), error);
    }
    match linked {
        Ok(()) => settle_created_secret_file(&target, &other_form).await,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => {
            warn!(
                "Creating secret file {} in place: linking a complete copy into place failed ({}), as it does on a \
                 filesystem without hard links, such as an SMB share. Exactly one creator still wins, but a reader \
                 may briefly see the new file empty",
                target.display(),
                error
            );
            create_secret_file_in_place(&target, &other_form, bytes.as_bytes()).await
        }
    }
}

/// An empty form of a secret file, identified closely enough that only this file
/// is removed later: on unix by its device and inode, so a form another creator
/// removed and created again is usually not mistaken for it, though a filesystem
/// that reuses the inode can hide the difference. Elsewhere only its path and
/// emptiness are compared, which is as much as the platform offers. The removal
/// renames the file aside before it unlinks it, so a creator that finishes
/// filling the captured file after this check cannot have its finished work
/// deleted; see [`EmptySecretFile::remove_if_still_empty`].
pub struct EmptySecretFile {
    path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl EmptySecretFile {
    #[cfg(unix)]
    fn of(
        path: &Path,
        metadata: &std::fs::Metadata,
    ) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(not(unix))]
    fn of(
        path: &Path,
        _metadata: &std::fs::Metadata,
    ) -> Self {
        Self { path: path.to_path_buf() }
    }

    /// Whether the path still holds the same empty file this captured.
    async fn is_unchanged(&self) -> bool {
        let Ok(metadata) = tokio::fs::metadata(&self.path).await else {
            return false;
        };
        metadata.len() == 0 && self.is_same_file(&metadata)
    }

    #[cfg(unix)]
    fn is_same_file(
        &self,
        metadata: &std::fs::Metadata,
    ) -> bool {
        use std::os::unix::fs::MetadataExt;

        metadata.dev() == self.device && metadata.ino() == self.inode
    }

    #[cfg(not(unix))]
    fn is_same_file(
        &self,
        _metadata: &std::fs::Metadata,
    ) -> bool {
        true
    }

    /// Rename this file aside, confirm it is still the empty file that was
    /// captured, and unlink it. Returns whether the path was freed.
    ///
    /// The rename is what makes this safe against a creator that is still
    /// filling the captured file. It moves the inode that creator holds open out
    /// of the path, so the creator's own read-back finds a path that no longer
    /// holds its bytes and it gives up its creation. A file that turns out to
    /// have gained content is put straight back and `false` returned: that
    /// creator finished first and owns it. Checking the file without renaming it
    /// could not give this, because the creator could finish in the moment
    /// between the check and the unlink and still pass its own read-back.
    async fn remove_if_still_empty(&self) -> bool {
        let mut aside = self
            .path
            .as_os_str()
            .to_os_string();
        aside.push(format!(".{}.removed", uuid::Uuid::new_v4()));
        let aside = PathBuf::from(aside);
        if let Err(error) = tokio::fs::rename(&self.path, &aside).await {
            warn!(
                "Not removing the empty secret file {}: it could not be renamed aside ({})",
                self.path.display(),
                error
            );
            return false;
        }
        match tokio::fs::metadata(&aside).await {
            Ok(metadata) if metadata.len() == 0 && self.is_same_file(&metadata) => {}
            _ => {
                if let Err(error) = tokio::fs::rename(&aside, &self.path).await {
                    error!(
                        "Failed to put the secret file {} back after it gained content while it was removed: {}",
                        self.path.display(),
                        error
                    );
                }
                return false;
            }
        }
        warn!(
            "Secret file {} stayed empty, as a creation interrupted while filling it leaves it: removing it and \
             creating the secret again",
            self.path.display()
        );
        if let Err(error) = tokio::fs::remove_file(&aside).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            // The path is free either way, which is what the caller needs.
            error!("Failed to remove the empty secret file {}: {}", aside.display(), error);
        }
        true
    }
}

/// The forms of the secret in `path` when every one that exists is empty, as a
/// creation interrupted while filling it leaves them. `None` when any form holds
/// content, when no form exists, or when a form's metadata cannot be read, so a
/// file that cannot be judged is never taken for a leftover. This removes
/// nothing: the caller waits as long as it is willing to, then calls
/// [`remove_unchanged_empty_secret_files`].
pub async fn empty_secret_files(path: &Path) -> Option<Vec<EmptySecretFile>> {
    let enc_path = secret_enc_path(path);
    let mut empty = Vec::new();
    for form in [path, enc_path.as_path()] {
        match tokio::fs::metadata(form).await {
            Ok(metadata) if metadata.len() == 0 => empty.push(EmptySecretFile::of(form, &metadata)),
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    (!empty.is_empty()).then_some(empty)
}

/// Remove the empty files [`empty_secret_files`] captured, but only while every
/// one of them is still that same empty file, so a creator that has since made
/// its own file, or finished filling this one, does not lose it. Returns whether
/// the paths were freed; a refusal is logged and leaves the file where it was,
/// so the creation that follows refuses it as an existing file.
///
/// Each file is renamed aside before it is unlinked, which is what closes the
/// race against a creator that completes inside this call; see
/// [`EmptySecretFile::remove_if_still_empty`].
pub async fn remove_unchanged_empty_secret_files(empty: &[EmptySecretFile]) -> bool {
    for form in empty {
        if !form
            .is_unchanged()
            .await
        {
            return false;
        }
    }
    let mut removed = false;
    for form in empty {
        if !form
            .remove_if_still_empty()
            .await
        {
            return false;
        }
        removed = true;
    }
    removed
}

/// Hard-link `staged` to `target`, or, under test, fail the way a filesystem
/// without hard links does when [`simulate_link_failure`] asked for it.
async fn hard_link_into_place(
    staged: &Path,
    target: &Path,
) -> std::io::Result<()> {
    #[cfg(test)]
    if SIMULATED_LINK_FAILURE.get() {
        return Err(simulated_link_failure());
    }
    tokio::fs::hard_link(staged, target).await
}

#[cfg(test)]
thread_local! {
    /// Whether [`simulate_link_failure`] made this thread's links fail.
    static SIMULATED_LINK_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Fail every link [`create_secret_file`] makes on the calling thread, as a
/// filesystem without hard links does. Each test runs on its own thread.
#[cfg(test)]
pub(crate) fn simulate_link_failure(simulated: bool) {
    SIMULATED_LINK_FAILURE.set(simulated);
}

/// The failure an SMB share answers `link` with.
#[cfg(test)]
fn simulated_link_failure() -> std::io::Error {
    #[cfg(unix)]
    return std::io::Error::from_raw_os_error(libc::EOPNOTSUPP);
    #[cfg(not(unix))]
    return std::io::Error::from(std::io::ErrorKind::Unsupported);
}

/// Create a secret file without a hard link: the file is created exclusively
/// (`O_CREAT | O_EXCL`), so exactly one creator still wins and an existing file
/// is never replaced, and is then filled and synced in place. Returns `false`
/// when another creator already made it. A directory that genuinely cannot be
/// written fails here as it did on the link.
///
/// Unlike the hard-link path this leaves a window in which a reader sharing the
/// directory sees the file empty or half written, so readers of a file created
/// this way retry one that does not parse yet instead of failing at once. A
/// creation that fails while filling the file removes it again, so the window
/// does not outlive the creator. The file is read back once it is filled: a
/// creator whose file another one removed as an empty leftover and replaced in
/// that window returns `false`, so it adopts the secret now in place instead of
/// running on one that is on no disk.
async fn create_secret_file_in_place(
    target: &Path,
    other_form: &Path,
    bytes: &[u8],
) -> Result<bool> {
    let mut options = tokio::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut created = match options.open(target).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to create secret file {}", target.display()));
        }
    };
    if let Err(error) = fill_created_secret_file(&mut created, bytes).await {
        if created_file_is_still_at(&created, target).await {
            if let Err(error) = tokio::fs::remove_file(target).await
                && error.kind() != std::io::ErrorKind::NotFound
            {
                error!("Failed to remove the unwritten secret file {}: {}", target.display(), error);
            }
        } else {
            warn!(
                "Not removing the secret file {} this creation could not fill: the path holds another creator's \
                 file now, which this one must not delete",
                target.display()
            );
        }
        return Err(error).with_context(|| format!("Failed to write secret file {}", target.display()));
    }
    if !created_secret_file_is_still_ours(target, bytes).await? {
        warn!(
            "Secret file {} was replaced by another creator while it was filled: giving up this creation and \
             adopting the secret now in place",
            target.display()
        );
        return Ok(false);
    }
    settle_created_secret_file(target, other_form).await
}

/// Whether `target` still names the file this creator opened, so a creation that
/// could not fill its file removes only its own. A creator stalled long enough
/// for a reader to take the path, and for another creator to fill it, would
/// otherwise delete a complete secret here. Only the inode decides: on a platform
/// that cannot compare inodes this keeps the older behaviour and removes by path.
#[cfg(unix)]
async fn created_file_is_still_at(
    opened: &tokio::fs::File,
    target: &Path,
) -> bool {
    use std::os::unix::fs::MetadataExt;

    let (Ok(opened), Ok(current)) = (opened.metadata().await, tokio::fs::metadata(target).await) else {
        return false;
    };
    opened.dev() == current.dev() && opened.ino() == current.ino()
}

#[cfg(not(unix))]
async fn created_file_is_still_at(
    _opened: &tokio::fs::File,
    _target: &Path,
) -> bool {
    true
}

/// Whether the file just filled still holds what this creator wrote. Another
/// creator can remove it as an empty leftover and create its own between the
/// exclusive create and the fill, so the content on disk decides who won: a
/// creator that finds anything else, or nothing, lost its file and must adopt
/// the secret now in place. A removal renames the file aside before unlinking
/// it, so a creator whose file is taken while it fills it always reads back a
/// path that no longer holds its bytes, even if it finishes in that moment.
async fn created_secret_file_is_still_ours(
    target: &Path,
    bytes: &[u8],
) -> Result<bool> {
    match tokio::fs::read(target).await {
        Ok(written) => Ok(written.as_slice() == bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("Failed to read back the created secret file {}", target.display()))
        }
    }
}

/// Write `bytes` to a just-created secret file and make them durable. The handle
/// stays with the caller, which needs it to tell whether the path still names
/// the file it created before it removes anything.
async fn fill_created_secret_file(
    created: &mut tokio::fs::File,
    bytes: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    created
        .write_all(bytes)
        .await?;
    created.flush().await?;
    created
        .sync_all()
        .await
}

/// Make a just-created secret file durable, and give it up again when the other
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
/// written with the process default mode, as a restore writes every file. The
/// mode is read back, so a volume that accepts the change without applying it,
/// as an SMB share mounted without `file_mode=0600` does, is warned about
/// instead of reported as restricted. A failure is logged and does not stop the
/// caller.
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
        if let Err(error) = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await {
            warn!("Failed to restrict secret file {} to its owner: {}", path.display(), error);
            continue;
        }
        match tokio::fs::metadata(&path)
            .await
            .map(|metadata| metadata.permissions().mode() & 0o777)
        {
            Ok(applied) if applied & 0o077 == 0 => tracing::info!(
                path = %path.display(),
                previous_mode = format!("{mode:o}"),
                "Restricted secret file to its owner"
            ),
            Ok(applied) => warn!(
                "Secret file {} is still readable beyond its owner (mode {:o}) after restricting it: the volume it \
                 sits on applies its own mode, as an SMB share mounted without file_mode=0600 does",
                path.display(),
                applied
            ),
            Err(error) => warn!(
                "Failed to read the mode of secret file {} back after restricting it to its owner: {}",
                path.display(),
                error
            ),
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
/// enabling encryption removes lingering plaintext on the next read. An empty
/// file is returned as it is and never migrated: it holds nothing, and is what a
/// creator sharing the directory leaves while it fills the file in place.
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
            // An empty file is one a creator sharing the directory is still filling:
            // return it as it is, so in-flight content is never promoted to the
            // authoritative encrypted form, which nothing would replace.
            if content.is_empty() {
                return Ok(Some(content));
            }
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

    /// Azure Files and other SMB shares answer `link` with `EOPNOTSUPP`. The
    /// file is then created exclusively and filled in place: it is still created
    /// once, readable by its owner only, never replaced, and no staged file is
    /// left behind.
    #[tokio::test]
    async fn create_falls_back_to_an_exclusive_create_when_the_link_fails() {
        simulate_link_failure(true);
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
        assert_eq!(file_mode(&path), 0o600);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("key.json")], "no staged file may be left behind");
    }

    /// Exclusive creation keeps the one-winner guarantee the hard link gives.
    #[tokio::test]
    async fn create_lets_exactly_one_concurrent_creator_win_without_a_hard_link() {
        simulate_link_failure(true);
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

    /// A directory the file cannot be made in fails the creation loudly. Falling
    /// back whatever the link failure was never turns a real failure into a
    /// silent success: the same directory refuses the exclusive create too.
    #[tokio::test]
    async fn create_fails_when_the_file_cannot_be_made_at_all() {
        simulate_link_failure(true);
        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("occupied");
        std::fs::write(&not_a_directory, "in the way").unwrap();
        let path = not_a_directory.join("key.json");

        let error = create_secret_file(&path, "first")
            .await
            .expect_err("a file that cannot be made must fail the creation");

        assert!(
            error
                .to_string()
                .contains("secret file"),
            "{error:#}"
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read_to_string(&not_a_directory).unwrap(), "in the way");
    }

    /// The content on disk decides who won when another creator removed this
    /// file as an empty leftover and made its own while it was being filled:
    /// only a creator that still finds its own bytes keeps its creation.
    #[tokio::test]
    async fn a_creator_keeps_its_creation_only_while_the_file_holds_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");

        std::fs::write(&path, "ours").unwrap();
        assert!(
            created_secret_file_is_still_ours(&path, b"ours")
                .await
                .unwrap()
        );

        std::fs::write(&path, "theirs").unwrap();
        assert!(
            !created_secret_file_is_still_ours(&path, b"ours")
                .await
                .unwrap(),
            "a creator whose file was replaced must report that it lost"
        );

        std::fs::remove_file(&path).unwrap();
        assert!(
            !created_secret_file_is_still_ours(&path, b"ours")
                .await
                .unwrap(),
            "a creator whose file was removed must report that it lost"
        );
    }

    /// A creator killed between creating the file and filling it leaves it
    /// empty. The creation itself never removes it, in either form: the reader
    /// that watched it stay the same empty file does, and only then is the
    /// secret created again.
    #[tokio::test]
    async fn an_empty_leftover_is_removed_only_by_the_reader_that_waited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        std::fs::write(&path, "").unwrap();

        assert!(
            !create_secret_file(&path, "first")
                .await
                .unwrap(),
            "the creation refuses an empty file rather than removing it"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");

        let empty = empty_secret_files(&path)
            .await
            .expect("an empty file must be captured");
        assert!(remove_unchanged_empty_secret_files(&empty).await);
        assert!(!path.exists());
        assert!(
            create_secret_file(&path, "first")
                .await
                .unwrap()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        assert!(
            empty_secret_files(&path)
                .await
                .is_none(),
            "a file with content is never taken for a leftover"
        );

        // The empty leftover of the other form is captured and removed the same
        // way, so the creation is not refused by a file that holds nothing.
        let other = dir.path().join("other.json");
        std::fs::write(secret_enc_path(&other), "").unwrap();
        let empty = empty_secret_files(&other)
            .await
            .expect("the empty encrypted form must be captured");

        assert!(remove_unchanged_empty_secret_files(&empty).await);
        assert!(!secret_enc_path(&other).exists(), "the empty leftover must be removed");
        assert!(
            create_secret_file(&other, "first")
                .await
                .unwrap()
        );
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "first");
    }

    /// The removal is refused once the file is no longer the empty one that was
    /// captured, so a creator that filled it in the meantime does not lose it.
    #[tokio::test]
    async fn an_empty_leftover_that_gained_content_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        std::fs::write(&path, "").unwrap();
        let empty = empty_secret_files(&path)
            .await
            .expect("an empty file must be captured");

        std::fs::write(&path, "another creator's secret").unwrap();

        assert!(!remove_unchanged_empty_secret_files(&empty).await, "a file that gained content must be kept");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "another creator's secret");
    }

    /// The check and the removal are not one operation, so a creator can finish
    /// filling the captured file between them and pass its own read-back. The
    /// removal renames the file aside first and puts it back when it finds
    /// content, so that creator keeps its secret. Calling the removal directly
    /// is what puts the content there after the check, as a stalled creator
    /// does.
    #[tokio::test]
    async fn a_leftover_filled_after_the_check_is_put_back_rather_than_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        std::fs::write(&path, "").unwrap();
        let empty = empty_secret_files(&path)
            .await
            .expect("an empty file must be captured");
        let form = &empty[0];
        assert!(form.is_unchanged().await, "the check passes while the file is still empty");

        std::fs::write(&path, "the stalled creator's secret").unwrap();

        assert!(
            !form
                .remove_if_still_empty()
                .await,
            "a file filled after the check must not be removed"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "the stalled creator's secret");
        let left_behind: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
            })
            .collect();
        assert_eq!(left_behind, vec![std::ffi::OsString::from("key.json")], "nothing may be left renamed aside");
    }

    /// A file another instance is still filling in place is empty. Reading it
    /// must not promote that emptiness to the authoritative encrypted form,
    /// which nothing would replace.
    #[tokio::test]
    async fn read_leaves_an_empty_plaintext_file_unmigrated_when_enabled() {
        install_enabled_encryption();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");
        std::fs::write(&path, "").unwrap();

        let read = read_secret_file(&path)
            .await
            .unwrap();

        assert_eq!(read.as_deref(), Some(""));
        assert!(!secret_enc_path(&path).exists(), "an in-flight file must not be promoted to .enc");
        assert!(path.exists(), "the file another instance is filling must be left alone");
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
