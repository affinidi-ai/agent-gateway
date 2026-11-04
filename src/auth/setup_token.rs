//! The single-use setup token the first passkey administrator presents while no user exists.
//!
//! The token is kept in `setup-token` in the passkey user directory, readable by its owner only,
//! so only someone who can read the gateway's storage can register the Primary Administrator.
//! Gateways sharing that directory share the token, and moving the file aside claims it, so only
//! one of them can create the Primary Administrator with it; a gateway that finds the file moved
//! aside by another's claim keeps its token, and a gateway whose token was used cannot claim a
//! token file holding another token, such as one generated after that. Long-lived state holds only
//! the token's SHA-256 digest.

use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::config::types::SecretValue;

/// Environment variable naming the setup token, as a value or a configuration loader reference,
/// in place of a generated one.
pub const SETUP_TOKEN_ENV: &str = "AG_SETUP_TOKEN";

const FILE_NAME: &str = "setup-token";

const TOKEN_LENGTH: RangeInclusive<usize> = 43..=256;

/// How old a copy of the token file left beside it must be before it is removed, since another
/// gateway sharing the directory may still be claiming or creating the file through a younger one.
const LEFTOVER_COPY_AGE: Duration = Duration::from_secs(5 * 60);

type TokenDigest = Zeroizing<[u8; 32]>;

pub struct SetupToken {
    path: PathBuf,
    digest: Mutex<Option<TokenDigest>>,
}

impl std::fmt::Debug for SetupToken {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("SetupToken")
            .field("path", &self.path)
            .field("pending", &self.is_pending())
            .finish()
    }
}

impl SetupToken {
    /// The setup token for a passkey user directory. Copies of the token file that an interrupted
    /// claim or creation left in the directory are removed first, once they are five minutes old.
    /// Once a user exists no token is needed and a leftover token file is removed. Otherwise the
    /// token in the directory's token file is used, or the file is created, once, with
    /// `operator_token` or a random token. A token file that cannot be read as a token, or that
    /// differs from `operator_token`, is an error and is kept.
    pub async fn prepare(
        passkeys_dir: &Path,
        has_users: bool,
        operator_token: Option<SecretValue>,
    ) -> Result<Self> {
        Self::prepare_at(passkeys_dir, has_users, operator_token, SystemTime::now()).await
    }

    async fn prepare_at(
        passkeys_dir: &Path,
        has_users: bool,
        operator_token: Option<SecretValue>,
        now: SystemTime,
    ) -> Result<Self> {
        remove_leftover_copies(passkeys_dir, now).await;
        let path = passkeys_dir.join(FILE_NAME);
        if has_users {
            if operator_token.is_some() {
                warn!(
                    "{SETUP_TOKEN_ENV} is set but a user already exists; unset it, so that emptying the user store \
                     does not bring the token back"
                );
            }
            remove_leftover_token_file(&path).await?;
            return Ok(Self { path, digest: Mutex::new(None) });
        }
        let token = match read_token_file(&path).await? {
            Some(token) => token,
            None => create_token_file(&path, operator_token.as_deref()).await?,
        };
        #[cfg(unix)]
        restrict_token_file(&path).await?;
        let digest = digest_of(&token);
        if let Some(operator_token) = operator_token.as_deref()
            && !same_digest(&digest_of(operator_token), &digest)
        {
            bail!(
                "The setup token file {} holds a different token from {SETUP_TOKEN_ENV}; delete the file or unset \
                 {SETUP_TOKEN_ENV}",
                path.display()
            );
        }
        warn!("No user exists yet: register the first administrator with the setup token in {}", path.display());
        Ok(Self {
            path,
            digest: Mutex::new(Some(digest)),
        })
    }

    /// Whether the token can still register the first administrator.
    pub fn is_pending(&self) -> bool {
        self.digest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Whether `presented` is the pending token. A missing token is compared like a wrong one, and
    /// the comparison takes the same time whatever the presented token's length or content.
    pub fn matches(
        &self,
        presented: Option<&str>,
    ) -> bool {
        let presented = digest_of(presented.unwrap_or(""));
        self.digest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|expected| same_digest(expected, &presented))
    }

    /// Uses the token up. The token file is moved aside under a name of its own, which only one of
    /// the gateways sharing the directory can do, and is removed only when it holds this gateway's
    /// token; a file holding another token, such as one a restarted gateway created after this
    /// gateway's token was used, is put back unless a newer file took its place. Only the caller
    /// that used the token up gets `true`. When there is no token file, as while another gateway's
    /// claim has it moved aside, the claim gives `false` and keeps the token, so a later claim can
    /// still use it if the file comes back holding it; any other `false` means the token can no
    /// longer be used here. A file that cannot be moved, read or put back is an error and keeps the
    /// token.
    pub async fn claim(&self) -> Result<bool> {
        if !self.is_pending() {
            return Ok(false);
        }
        let taken = self
            .path
            .with_file_name(format!("{FILE_NAME}.{}.claim", uuid::Uuid::new_v4()));
        match tokio::fs::rename(&self.path, &taken).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to claim the setup token file {}", self.path.display()));
            }
        }
        let held = match read_regular_file(&taken).await {
            Ok(held) => held,
            Err(error) => {
                self.put_back(&taken).await?;
                return Err(error)
                    .with_context(|| format!("Failed to claim the setup token file {}", self.path.display()));
            }
        };
        if held
            .as_deref()
            .and_then(|contents| token_in(contents))
            .is_some_and(|token| self.matches(Some(token)))
        {
            remove_taken_token_file(&taken).await;
            self.forget();
            return Ok(true);
        }
        if held.is_some() {
            self.put_back(&taken).await?;
        }
        self.forget();
        Ok(false)
    }

    /// Puts the token file moved aside to `taken` back, unless a token file was created in its
    /// place meanwhile, which is kept.
    async fn put_back(
        &self,
        taken: &Path,
    ) -> Result<()> {
        crate::encryption::secret_file::link_if_absent(taken, &self.path)
            .await
            .with_context(|| format!("Failed to put the setup token file {} back", self.path.display()))?;
        remove_taken_token_file(taken).await;
        Ok(())
    }

    fn forget(&self) {
        *self
            .digest
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}

async fn remove_taken_token_file(taken: &Path) {
    if let Err(error) = tokio::fs::remove_file(taken).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!("Failed to remove the setup token file {}; delete it: {}", taken.display(), error);
    }
}

/// The operator's setup token from `AG_SETUP_TOKEN`, resolved through the configuration loaders
/// (`string://`, `file://`, `env://`, `aws_secrets://`, `aws_parameter_store://` or a plain
/// token) and trimmed, or `None` when it is not set or holds only whitespace.
pub async fn operator_token_from_env() -> Result<Option<SecretValue>> {
    operator_token_from(crate::config::loaders::environment::optional_env).await
}

async fn operator_token_from(lookup: impl FnOnce(&str) -> Option<String>) -> Result<Option<SecretValue>> {
    let Some(reference) = lookup(SETUP_TOKEN_ENV)
        .map(Zeroizing::new)
        .filter(|reference| !reference.trim().is_empty())
    else {
        return Ok(None);
    };
    let resolved = Zeroizing::new(
        crate::config::loaders::load(&reference)
            .await
            .map_err(|error| anyhow!("{SETUP_TOKEN_ENV} could not be resolved: {error}"))?,
    );
    let token = resolved.trim();
    if !is_valid_token(token) {
        bail!(
            "{SETUP_TOKEN_ENV} must be {} to {} printable ASCII characters without spaces; generate one with \
             `openssl rand -base64 32`",
            TOKEN_LENGTH.start(),
            TOKEN_LENGTH.end()
        );
    }
    Ok(Some(SecretValue::from(token)))
}

fn is_valid_token(token: &str) -> bool {
    TOKEN_LENGTH.contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
}

fn digest_of(token: &str) -> TokenDigest {
    Zeroizing::new(Sha256::digest(token.as_bytes()).into())
}

fn same_digest(
    expected: &[u8; 32],
    presented: &[u8; 32],
) -> bool {
    expected
        .as_slice()
        .ct_eq(presented.as_slice())
        .into()
}

fn generate() -> Result<Zeroizing<String>> {
    use rand::TryRngCore;

    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(bytes.as_mut())
        .context("the operating system random number generator is unavailable")?;
    Ok(Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

async fn read_token_file(path: &Path) -> Result<Option<Zeroizing<String>>> {
    let Some(contents) = read_regular_file(path).await? else {
        return Ok(None);
    };
    let Some(token) = token_in(&contents) else {
        bail!(
            "The setup token file {} does not hold a setup token; it is left as it is. Delete it and restart the \
             gateway to generate a new token",
            path.display()
        );
    };
    Ok(Some(Zeroizing::new(token.to_string())))
}

/// The token a token file's contents hold, without the whitespace around it.
fn token_in(contents: &[u8]) -> Option<&str> {
    std::str::from_utf8(contents)
        .ok()
        .map(str::trim)
        .filter(|token| is_valid_token(token))
}

/// The first bytes of the file at `path`, enough to hold any token, or `None` when there is no
/// file, read through [`open_regular_file`].
async fn read_regular_file(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    use tokio::io::AsyncReadExt;

    const READ_LIMIT: usize = 1024;
    let Some(file) = open_regular_file(path).await? else {
        return Ok(None);
    };
    let mut contents = Zeroizing::new(Vec::with_capacity(READ_LIMIT));
    file.take(READ_LIMIT as u64)
        .read_to_end(&mut contents)
        .await
        .with_context(|| format!("Failed to read the setup token file {}", path.display()))?;
    Ok(Some(contents))
}

/// The file at `path`, opened for reading, or `None` when there is no file. Only a regular file is
/// opened: a symbolic link or any other kind of file is refused and left as it is, never followed.
async fn open_regular_file(path: &Path) -> Result<Option<tokio::fs::File>> {
    let not_regular = || {
        anyhow!(
            "The setup token file {} is not a regular file; it is left as it is. Replace it with the token file or \
             delete it",
            path.display()
        )
    };
    let read_error = || format!("Failed to read the setup token file {}", path.display());
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if !metadata.is_file() => return Err(not_regular()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(read_error),
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    // A symbolic link, or a FIFO that would block the open, swapped in after the check above is
    // refused all the same.
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = match options.open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(read_error),
    };
    if !file
        .metadata()
        .await
        .with_context(read_error)?
        .is_file()
    {
        return Err(not_regular());
    }
    Ok(Some(file))
}

/// Creates the token file with `operator_token` or a random token. When another gateway sharing
/// the directory creates it first, its token is used.
async fn create_token_file(
    path: &Path,
    operator_token: Option<&str>,
) -> Result<Zeroizing<String>> {
    let candidate = match operator_token {
        Some(token) => Zeroizing::new(token.to_string()),
        None => generate()?,
    };
    let contents = Zeroizing::new(format!("{}\n", candidate.as_str()));
    if crate::encryption::secret_file::create_owner_only_file(path, contents.as_bytes()).await? {
        return Ok(candidate);
    }
    read_token_file(path)
        .await?
        .with_context(|| format!("The setup token file {} disappeared while it was created", path.display()))
}

/// Restricts the token file to its owner through a handle opened by [`open_regular_file`], so the
/// mode is changed and read again on the file itself, never through a link, and stops startup
/// while users other than its owner can still read or write it. A file that is gone, because
/// another gateway sharing the directory claimed it meanwhile, needs nothing.
#[cfg(unix)]
async fn restrict_token_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Some(file) = open_regular_file(path).await? else {
        return Ok(());
    };
    let mode_error = || format!("Failed to read the mode of the setup token file {}", path.display());
    let mode = file
        .metadata()
        .await
        .with_context(mode_error)?
        .permissions()
        .mode();
    if is_owner_only(mode) {
        return Ok(());
    }
    match file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .await
    {
        Ok(()) => info!(
            path = %path.display(),
            previous_mode = format!("{mode:o}"),
            "Restricted the setup token file to its owner"
        ),
        Err(error) => warn!("Failed to restrict the setup token file {} to its owner: {}", path.display(), error),
    }
    let mode = file
        .metadata()
        .await
        .with_context(mode_error)?
        .permissions()
        .mode();
    refuse_unless_owner_only(path, mode)
}

/// Stops startup while `mode` lets users other than the token file's owner read or write it. Only
/// the mode is checked, never the owner, since shares commonly give files an owner other than the
/// gateway's user.
#[cfg(unix)]
fn refuse_unless_owner_only(
    path: &Path,
    mode: u32,
) -> Result<()> {
    if !is_owner_only(mode) {
        bail!(
            "The setup token file {} can be read or written by users other than its owner. Make it readable by its \
             owner only or delete it; on a mount that ignores chmod, give files an owner-only mode through mount \
             options (for example CIFS file_mode=0600,dir_mode=0700) or put the passkeys directory on a volume \
             that honours chmod",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn is_owner_only(mode: u32) -> bool {
    mode & 0o077 == 0
}

async fn remove_leftover_token_file(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!("Failed to remove the setup token file {}, which a user no longer needs", path.display())
        }),
    }
}

/// Removes the copies of the token file that an interrupted claim (`setup-token.<uuid>.claim`) or
/// creation (`setup-token.<uuid>.new`, written through `.setup-token.<uuid>.new.<uuid>.tmp`) left
/// in `passkeys_dir`, once they are [`LEFTOVER_COPY_AGE`] old. A symbolic link by such a name is
/// removed itself, never followed, and nothing else is touched.
async fn remove_leftover_copies(
    passkeys_dir: &Path,
    now: SystemTime,
) {
    let Ok(mut entries) = tokio::fs::read_dir(passkeys_dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(is_leftover_copy_name)
        {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = tokio::fs::symlink_metadata(&path).await else {
            continue;
        };
        if !(metadata.is_file() || metadata.is_symlink()) || !is_stale(&metadata, now) {
            continue;
        }
        if let Err(error) = tokio::fs::remove_file(&path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!("Failed to remove the leftover setup token copy {}; delete it: {}", path.display(), error);
        }
    }
}

fn is_leftover_copy_name(name: &str) -> bool {
    let copy = |name: &str, kind: &str| {
        name.strip_prefix(FILE_NAME)
            .and_then(|rest| rest.strip_prefix('.'))
            .and_then(|rest| rest.strip_suffix(kind))
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(is_uuid)
    };
    let staged_write = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .and_then(|rest| rest.rsplit_once('.'))
        .is_some_and(|(staged, id)| is_uuid(id) && copy(staged, "new"));
    copy(name, "claim") || copy(name, "new") || staged_write
}

fn is_uuid(text: &str) -> bool {
    uuid::Uuid::try_parse(text).is_ok_and(|id| id.hyphenated().to_string() == text)
}

/// Whether the entry was last modified, or last had its status changed, more than
/// [`LEFTOVER_COPY_AGE`] before `now`. A rename keeps the modification time, so on filesystems that
/// mark the status change time on rename a token file a claim has just moved aside counts as fresh
/// however long ago it was created. Elsewhere a sweep can remove it while the claim runs, and the
/// claim then fails closed.
fn is_stale(
    metadata: &std::fs::Metadata,
    now: SystemTime,
) -> bool {
    let Ok(changed) = metadata.modified() else {
        return false;
    };
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        let Ok(status_changed) = u64::try_from(metadata.ctime()) else {
            return false;
        };
        changed.max(SystemTime::UNIX_EPOCH + Duration::from_secs(status_changed))
    };
    now.duration_since(changed)
        .is_ok_and(|age| age > LEFTOVER_COPY_AGE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::formatted_logs::FormattedLogs;

    const OPERATOR_TOKEN: &str = "operator-chosen-setup-token-0123456789-abcdefghij";

    fn token_file(dir: &Path) -> PathBuf {
        dir.join(FILE_NAME)
    }

    fn token_in_file(dir: &Path) -> String {
        std::fs::read_to_string(token_file(dir))
            .unwrap()
            .trim()
            .to_string()
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

    async fn prepare_empty(dir: &Path) -> SetupToken {
        SetupToken::prepare(dir, false, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_store_without_users_gets_a_generated_token_file_readable_only_by_its_owner() {
        let dir = tempfile::tempdir().unwrap();

        let setup_token = prepare_empty(dir.path()).await;

        assert!(setup_token.is_pending());
        let contents = std::fs::read_to_string(token_file(dir.path())).unwrap();
        assert!(contents.ends_with('\n'));
        assert!(setup_token.matches(Some(contents.trim())));
        #[cfg(unix)]
        assert_eq!(file_mode(&token_file(dir.path())), 0o600);
    }

    #[tokio::test]
    async fn the_generated_token_is_43_url_safe_characters() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        prepare_empty(first.path()).await;
        prepare_empty(second.path()).await;

        let token = token_in_file(first.path());

        assert_eq!(token.len(), 43);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "the token is base64url without padding"
        );
        assert_ne!(token, token_in_file(second.path()), "each store gets its own random token");
    }

    #[tokio::test]
    async fn a_restart_before_setup_reuses_the_token_file() {
        let dir = tempfile::tempdir().unwrap();
        prepare_empty(dir.path()).await;
        let token = token_in_file(dir.path());

        let restarted = prepare_empty(dir.path()).await;

        assert_eq!(token_in_file(dir.path()), token);
        assert!(restarted.matches(Some(&token)));
    }

    #[tokio::test]
    async fn a_store_with_users_removes_a_leftover_token_file_and_needs_no_token() {
        let dir = tempfile::tempdir().unwrap();
        prepare_empty(dir.path()).await;
        let token = token_in_file(dir.path());

        let with_users = SetupToken::prepare(dir.path(), true, None)
            .await
            .unwrap();
        let again = SetupToken::prepare(dir.path(), true, None)
            .await
            .unwrap();

        assert!(!token_file(dir.path()).exists());
        assert!(!with_users.is_pending());
        assert!(!with_users.matches(Some(&token)));
        assert!(!again.is_pending(), "a missing token file is fine once a user exists");
    }

    #[tokio::test]
    async fn two_nodes_preparing_at_once_on_shared_storage_agree_on_one_token() {
        let dir = tempfile::tempdir().unwrap();

        let (first, second) =
            tokio::join!(SetupToken::prepare(dir.path(), false, None), SetupToken::prepare(dir.path(), false, None));
        let (first, second) = (first.unwrap(), second.unwrap());

        let token = token_in_file(dir.path());
        assert!(first.matches(Some(&token)));
        assert!(second.matches(Some(&token)));
    }

    #[tokio::test]
    async fn an_operator_token_is_written_to_the_token_file() {
        let dir = tempfile::tempdir().unwrap();

        let setup_token = SetupToken::prepare(dir.path(), false, Some(SecretValue::from(OPERATOR_TOKEN)))
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(token_file(dir.path())).unwrap(), format!("{OPERATOR_TOKEN}\n"));
        assert!(setup_token.matches(Some(OPERATOR_TOKEN)));
    }

    #[tokio::test]
    async fn an_operator_token_that_differs_from_the_token_file_stops_startup() {
        let dir = tempfile::tempdir().unwrap();
        prepare_empty(dir.path()).await;
        let token = token_in_file(dir.path());

        let error = SetupToken::prepare(dir.path(), false, Some(SecretValue::from(OPERATOR_TOKEN)))
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains(SETUP_TOKEN_ENV), "{error}");
        assert!(
            error.contains(
                &token_file(dir.path())
                    .display()
                    .to_string()
            ),
            "{error}"
        );
        assert!(!error.contains(OPERATOR_TOKEN));
        assert!(!error.contains(&token));
        assert_eq!(token_in_file(dir.path()), token, "the token file is kept");
    }

    async fn operator_token(value: &str) -> Result<Option<SecretValue>> {
        operator_token_from(|name| (name == SETUP_TOKEN_ENV).then(|| value.to_string())).await
    }

    fn assert_refused_without_echo(
        result: Result<Option<SecretValue>>,
        value: &str,
    ) {
        let error = result
            .expect_err("the operator token must be refused")
            .to_string();
        assert!(error.contains(SETUP_TOKEN_ENV), "{error}");
        assert!(!error.contains(value), "the error must not repeat the token");
    }

    #[tokio::test]
    async fn an_operator_token_shorter_than_43_characters_stops_startup() {
        let short = "a".repeat(42);
        assert_refused_without_echo(operator_token(&short).await, &short);
        assert_refused_without_echo(operator_token(&"a".repeat(257)).await, &"a".repeat(257));

        for length in [43, 256] {
            let token = "a".repeat(length);
            assert_eq!(
                operator_token(&token)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(token.as_str())
            );
        }
    }

    #[tokio::test]
    async fn an_operator_token_with_whitespace_or_control_characters_stops_startup() {
        let base = "b".repeat(43);
        for token in [
            format!("{base} inner"),
            format!("{base}\tinner"),
            format!("{base}\u{7f}"),
            format!("{base}\u{1b}"),
            format!("{base}é"),
        ] {
            assert_refused_without_echo(operator_token(&token).await, &token);
        }

        assert_eq!(
            operator_token(&format!("  {base}\n"))
                .await
                .unwrap()
                .as_deref(),
            Some(base.as_str()),
            "surrounding whitespace is trimmed"
        );
    }

    #[tokio::test]
    async fn an_operator_token_from_a_loader_reference_is_resolved() {
        assert_eq!(
            operator_token(&format!("string://{OPERATOR_TOKEN}"))
                .await
                .unwrap()
                .as_deref(),
            Some(OPERATOR_TOKEN)
        );

        let error = operator_token("env://AG_TEST_PRESENT_VAR")
            .await
            .expect_err("the resolved token is too short")
            .to_string();
        assert!(error.contains(SETUP_TOKEN_ENV), "{error}");
        assert!(!error.contains("value"), "the error must not repeat the resolved token: {error}");

        assert!(
            operator_token_from(|_| None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_empty_or_blank_ag_setup_token_counts_as_unset() {
        for value in ["", " ", "\t\n "] {
            assert!(
                operator_token(value)
                    .await
                    .unwrap()
                    .is_none(),
                "{value:?}"
            );
        }

        for reference in ["string://", "string://   "] {
            assert_refused_without_echo(operator_token(reference).await, reference);
        }
    }

    #[tokio::test]
    async fn a_malformed_token_file_stops_startup_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        for contents in ["short\n", "", "a token with spaces that is long enough to pass the length check\n"] {
            std::fs::write(token_file(dir.path()), contents).unwrap();

            let error = SetupToken::prepare(dir.path(), false, None)
                .await
                .unwrap_err()
                .to_string();

            assert!(error.contains("does not hold a setup token"), "{error}");
            assert_eq!(std::fs::read_to_string(token_file(dir.path())).unwrap(), contents, "the file is kept");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_reused_token_file_is_restricted_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(token_file(dir.path()), format!("{OPERATOR_TOKEN}\n")).unwrap();
        std::fs::set_permissions(token_file(dir.path()), std::fs::Permissions::from_mode(0o644)).unwrap();

        let setup_token = prepare_empty(dir.path()).await;

        assert_eq!(file_mode(&token_file(dir.path())), 0o600);
        assert!(setup_token.matches(Some(OPERATOR_TOKEN)));
    }

    #[cfg(unix)]
    #[test]
    fn only_a_mode_that_gives_other_users_no_access_is_owner_only() {
        for mode in [0o600, 0o400, 0o200, 0o700, 0o000, 0o100600] {
            assert!(is_owner_only(mode), "{mode:o}");
        }
        for mode in [0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o644, 0o666, 0o100604] {
            assert!(!is_owner_only(mode), "{mode:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_owner_only_check_refuses_a_mode_other_users_can_use_and_names_the_file() {
        let path = Path::new("/srv/gateway/_storage/passkeys/setup-token");

        let error = refuse_unless_owner_only(path, 0o100640)
            .unwrap_err()
            .to_string();

        assert!(error.contains("/srv/gateway/_storage/passkeys/setup-token"), "{error}");
        assert!(error.contains("readable by its owner only"), "{error}");
        assert!(error.contains("or delete it"), "{error}");
        assert!(error.contains("mount options (for example CIFS file_mode=0600,dir_mode=0700)"), "{error}");
        assert!(error.contains("a volume that honours chmod"), "{error}");
        refuse_unless_owner_only(path, 0o100600).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restricting_a_token_file_another_gateway_claimed_meanwhile_needs_nothing() {
        let dir = tempfile::tempdir().unwrap();

        restrict_token_file(&token_file(dir.path()))
            .await
            .unwrap();

        assert!(file_names(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restricting_the_token_file_refuses_a_link_and_leaves_the_file_it_points_to_alone() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, format!("{OPERATOR_TOKEN}\n")).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, token_file(dir.path())).unwrap();

        let error = restrict_token_file(&token_file(dir.path()))
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("is not a regular file"), "{error}");
        assert_eq!(file_mode(&elsewhere), 0o644, "the file the link points to is left alone");
    }

    #[tokio::test]
    async fn matches_accepts_only_the_exact_token() {
        let dir = tempfile::tempdir().unwrap();
        let setup_token = SetupToken::prepare(dir.path(), false, Some(SecretValue::from(OPERATOR_TOKEN)))
            .await
            .unwrap();
        let mut same_length = OPERATOR_TOKEN.to_string();
        same_length.replace_range(0..1, "X");

        assert!(setup_token.matches(Some(OPERATOR_TOKEN)));
        for wrong in [
            Some(same_length.as_str()),
            Some(&OPERATOR_TOKEN[..OPERATOR_TOKEN.len() - 1]),
            Some(&format!("{OPERATOR_TOKEN}x")),
            Some(&format!(" {OPERATOR_TOKEN}")),
            Some(""),
            None,
        ] {
            assert!(!setup_token.matches(wrong), "{wrong:?} must not match");
        }
    }

    #[tokio::test]
    async fn a_claim_removes_the_token_file_once() {
        let dir = tempfile::tempdir().unwrap();
        let setup_token = prepare_empty(dir.path()).await;
        let token = token_in_file(dir.path());

        let first = setup_token
            .claim()
            .await
            .unwrap();
        let second = setup_token
            .claim()
            .await
            .unwrap();

        assert!(first);
        assert!(!second);
        assert!(!token_file(dir.path()).exists());
        assert!(file_names(dir.path()).is_empty(), "the claimed file is removed too");
        assert!(!setup_token.is_pending());
        assert!(!setup_token.matches(Some(&token)));
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn a_gateway_whose_token_was_used_cannot_claim_a_token_file_created_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let stale_node = prepare_empty(dir.path()).await;
        let used_token = token_in_file(dir.path());
        std::fs::remove_file(token_file(dir.path())).unwrap();
        let restarted_node = prepare_empty(dir.path()).await;
        let new_contents = std::fs::read(token_file(dir.path())).unwrap();

        let stale_claimed = stale_node
            .claim()
            .await
            .unwrap();

        assert!(!stale_claimed);
        assert!(!stale_node.is_pending());
        assert_ne!(token_in_file(dir.path()), used_token);
        assert_eq!(std::fs::read(token_file(dir.path())).unwrap(), new_contents, "the new token file is kept intact");
        #[cfg(unix)]
        assert_eq!(file_mode(&token_file(dir.path())), 0o600);
        assert_eq!(file_names(dir.path()), vec![FILE_NAME.to_string()]);
        assert!(
            restarted_node
                .claim()
                .await
                .unwrap(),
            "the gateway that created the new file can still use its token"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_claim_refuses_a_token_path_that_is_a_symbolic_link_and_keeps_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let setup_token = prepare_empty(dir.path()).await;
        let token = token_in_file(dir.path());
        let elsewhere = dir.path().join("elsewhere");
        std::fs::rename(token_file(dir.path()), &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, token_file(dir.path())).unwrap();

        let error = format!(
            "{:#}",
            setup_token
                .claim()
                .await
                .unwrap_err()
        );

        assert!(error.contains("is not a regular file"), "{error}");
        assert!(!error.contains(&token), "{error}");
        assert!(setup_token.matches(Some(&token)));
        assert!(
            std::fs::symlink_metadata(token_file(dir.path()))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link is put back as it was"
        );
        assert_eq!(file_names(dir.path()), vec!["elsewhere".to_string(), FILE_NAME.to_string()]);
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), format!("{token}\n"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_token_path_that_is_not_a_regular_file_stops_startup_and_is_kept() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, format!("{OPERATOR_TOKEN}\n")).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, token_file(dir.path())).unwrap();

        let through_a_link = SetupToken::prepare(dir.path(), false, None)
            .await
            .unwrap_err()
            .to_string();

        assert!(through_a_link.contains("is not a regular file"), "{through_a_link}");
        assert!(!through_a_link.contains(OPERATOR_TOKEN), "{through_a_link}");
        assert!(
            std::fs::symlink_metadata(token_file(dir.path()))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(file_mode(&elsewhere), 0o644, "the file the link points to is left alone");

        std::fs::remove_file(token_file(dir.path())).unwrap();
        std::fs::create_dir(token_file(dir.path())).unwrap();
        let a_directory = SetupToken::prepare(dir.path(), false, None)
            .await
            .unwrap_err()
            .to_string();

        assert!(a_directory.contains("is not a regular file"), "{a_directory}");
        assert!(token_file(dir.path()).is_dir());
    }

    #[tokio::test]
    async fn a_claim_after_another_node_removed_the_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let this_node = prepare_empty(dir.path()).await;
        let other_node = prepare_empty(dir.path()).await;
        let token = token_in_file(dir.path());

        let other_claimed = other_node
            .claim()
            .await
            .unwrap();
        let this_claimed = this_node
            .claim()
            .await
            .unwrap();

        assert!(other_claimed);
        assert!(!this_claimed);
        assert!(this_node.is_pending(), "a claim that finds no token file keeps the token");
        assert!(this_node.matches(Some(&token)));
        assert!(!token_file(dir.path()).exists());
    }

    #[tokio::test]
    async fn a_claim_while_another_node_has_the_file_moved_aside_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let setup_token = prepare_empty(dir.path()).await;
        let token = token_in_file(dir.path());
        let moved_aside = dir
            .path()
            .join(format!("{FILE_NAME}.{}.claim", uuid::Uuid::new_v4()));
        std::fs::rename(token_file(dir.path()), &moved_aside).unwrap();

        let while_moved_aside = setup_token
            .claim()
            .await
            .unwrap();
        std::fs::rename(&moved_aside, token_file(dir.path())).unwrap();
        let retried = setup_token
            .claim()
            .await
            .unwrap();

        assert!(!while_moved_aside);
        assert!(retried, "the token is kept while the file is moved aside, so the retry uses it up");
        assert!(file_names(dir.path()).is_empty());
        assert!(!setup_token.matches(Some(&token)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_claim_that_cannot_move_the_token_file_keeps_the_token() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let passkeys = dir.path().join("passkeys");
        std::fs::create_dir(&passkeys).unwrap();
        let setup_token = prepare_empty(&passkeys).await;
        let token = token_in_file(&passkeys);
        std::fs::set_permissions(&passkeys, std::fs::Permissions::from_mode(0o500)).unwrap();

        let claimed = setup_token.claim().await;
        std::fs::set_permissions(&passkeys, std::fs::Permissions::from_mode(0o700)).unwrap();

        let error = claimed
            .unwrap_err()
            .to_string();
        assert!(error.contains("Failed to claim the setup token file"), "{error}");
        assert!(setup_token.matches(Some(&token)));
        assert!(token_file(&passkeys).exists());
    }

    fn leftover_copy_names() -> Vec<String> {
        let id = uuid::Uuid::new_v4();
        vec![
            format!("{FILE_NAME}.{id}.claim"),
            format!("{FILE_NAME}.{id}.new"),
            format!(".{FILE_NAME}.{id}.new.{}.tmp", uuid::Uuid::new_v4()),
        ]
    }

    fn write_copies(
        dir: &Path,
        names: &[String],
    ) {
        for name in names {
            std::fs::write(dir.join(name), format!("{OPERATOR_TOKEN}\n")).unwrap();
        }
    }

    fn past_leftover_age() -> SystemTime {
        SystemTime::now() + LEFTOVER_COPY_AGE + Duration::from_secs(60)
    }

    #[tokio::test]
    async fn old_leftover_copies_of_the_token_file_are_removed_with_or_without_users() {
        for (has_users, remaining) in [(false, vec![FILE_NAME.to_string()]), (true, Vec::new())] {
            let dir = tempfile::tempdir().unwrap();
            write_copies(dir.path(), &leftover_copy_names());

            SetupToken::prepare_at(dir.path(), has_users, None, past_leftover_age())
                .await
                .unwrap();

            assert_eq!(file_names(dir.path()), remaining, "has_users: {has_users}");
        }
    }

    #[tokio::test]
    async fn fresh_leftover_copies_of_the_token_file_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mut copies = leftover_copy_names();
        write_copies(dir.path(), &copies);

        remove_leftover_copies(dir.path(), SystemTime::now()).await;

        copies.sort();
        assert_eq!(file_names(dir.path()), copies);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_token_file_a_claim_has_just_moved_aside_is_kept_however_old_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let left_in_place = format!("{FILE_NAME}.{}.new", uuid::Uuid::new_v4());
        for name in [FILE_NAME, left_in_place.as_str()] {
            std::fs::write(dir.path().join(name), format!("{OPERATOR_TOKEN}\n")).unwrap();
            std::fs::File::options()
                .write(true)
                .open(dir.path().join(name))
                .unwrap()
                .set_modified(SystemTime::now() - Duration::from_secs(3600))
                .unwrap();
        }
        let set_back = SystemTime::now();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let claimed = format!("{FILE_NAME}.{}.claim", uuid::Uuid::new_v4());
        std::fs::rename(token_file(dir.path()), dir.path().join(&claimed)).unwrap();

        remove_leftover_copies(dir.path(), set_back + LEFTOVER_COPY_AGE + Duration::from_secs(1)).await;

        assert!(
            dir.path()
                .join(&claimed)
                .exists(),
            "the rename two seconds later keeps the moved-aside file fresh"
        );
        assert!(
            !dir.path()
                .join(&left_in_place)
                .exists(),
            "a file changed only before then is old by now"
        );
    }

    #[tokio::test]
    async fn only_leftover_copies_of_the_token_file_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::new_v4();
        let mut kept = vec![
            FILE_NAME.to_string(),
            format!("{FILE_NAME}.backup"),
            format!("{FILE_NAME}.{id}"),
            format!("{FILE_NAME}.{id}.old"),
            format!("{FILE_NAME}.{id}.claim.bak"),
            format!("{FILE_NAME}.not-a-uuid.claim"),
            format!("{FILE_NAME}.{}.claim", id.simple()),
            format!(
                "{FILE_NAME}.{}.claim",
                id.hyphenated()
                    .to_string()
                    .to_uppercase()
            ),
            format!("other-{FILE_NAME}.{id}.claim"),
            format!(".{FILE_NAME}.{id}.claim.{id}.tmp"),
            format!(".{FILE_NAME}.{id}.new.tmp"),
            format!("{id}.json"),
        ];
        write_copies(dir.path(), &kept);
        let directory = format!("{FILE_NAME}.{}.claim", uuid::Uuid::new_v4());
        std::fs::create_dir(dir.path().join(&directory)).unwrap();
        write_copies(dir.path(), &leftover_copy_names());

        remove_leftover_copies(dir.path(), past_leftover_age()).await;

        kept.push(directory);
        kept.sort();
        assert_eq!(file_names(dir.path()), kept);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_leftover_copy_that_is_a_symbolic_link_is_removed_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = elsewhere
            .path()
            .join("target");
        std::fs::write(&target, "kept").unwrap();
        let link = dir
            .path()
            .join(format!("{FILE_NAME}.{}.claim", uuid::Uuid::new_v4()));
        std::os::unix::fs::symlink(&target, &link).unwrap();

        remove_leftover_copies(dir.path(), past_leftover_age()).await;

        assert!(file_names(dir.path()).is_empty(), "the link is removed");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept", "the file it points to is left alone");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_leftover_copy_that_cannot_be_removed_is_named_in_a_warning() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let passkeys = dir.path().join("passkeys");
        std::fs::create_dir(&passkeys).unwrap();
        let name = format!("{FILE_NAME}.{}.claim", uuid::Uuid::new_v4());
        write_copies(&passkeys, std::slice::from_ref(&name));
        std::fs::set_permissions(&passkeys, std::fs::Permissions::from_mode(0o500)).unwrap();
        let logs = FormattedLogs::capture();

        remove_leftover_copies(&passkeys, past_leftover_age()).await;
        std::fs::set_permissions(&passkeys, std::fs::Permissions::from_mode(0o700)).unwrap();

        let text = logs.text();
        assert!(
            text.contains(&format!(
                "Failed to remove the leftover setup token copy {}",
                passkeys.join(&name).display()
            )),
            "{text}"
        );
        assert!(!text.contains(OPERATOR_TOKEN), "{text}");
        assert_eq!(file_names(&passkeys), vec![name]);
    }

    #[tokio::test]
    async fn the_startup_warning_names_the_file_and_never_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let logs = FormattedLogs::capture();

        prepare_empty(dir.path()).await;
        let token = token_in_file(dir.path());
        SetupToken::prepare(dir.path(), true, Some(SecretValue::from(OPERATOR_TOKEN)))
            .await
            .unwrap();

        let text = logs.text();
        assert!(
            text.contains(&format!(
                "No user exists yet: register the first administrator with the setup token in {}",
                token_file(dir.path()).display()
            )),
            "{text}"
        );
        assert!(text.contains("AG_SETUP_TOKEN is set but a user already exists; unset it"), "{text}");
        assert!(!text.contains(&token), "the log must not contain the generated token");
        assert!(!text.contains(OPERATOR_TOKEN), "the log must not contain the operator token");
    }

    #[tokio::test]
    async fn debug_output_never_contains_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let setup_token = SetupToken::prepare(dir.path(), false, Some(SecretValue::from(OPERATOR_TOKEN)))
            .await
            .unwrap();
        let operator = operator_token(OPERATOR_TOKEN)
            .await
            .unwrap();

        let rendered = format!("{setup_token:?} {operator:?}");

        assert!(rendered.contains("pending: true"), "{rendered}");
        assert!(!rendered.contains(OPERATOR_TOKEN), "{rendered}");
        assert!(!rendered.contains(&hex::encode(digest_of(OPERATOR_TOKEN).as_slice())), "{rendered}");
    }
}
