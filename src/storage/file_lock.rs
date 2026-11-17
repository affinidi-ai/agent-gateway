//! Exclusive advisory file locks shared by every process that opens the same lock file,
//! including gateways on other hosts sharing the volume when it supports cross-client locks
//! (local disks, EFS, NFSv4).

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// The outcome of [`lock_exclusive`].
#[derive(Debug)]
pub(crate) enum LockOutcome {
    /// The lock is held until the returned file is closed.
    Acquired(File),
    /// The lock file could not be opened or the volume refused the lock.
    Unavailable(anyhow::Error),
    /// Another holder kept the lock for the whole timeout.
    TimedOut,
}

/// Opens the lock file at `path`, creating it owner-only when it is missing. The file holds
/// nothing and is never truncated or removed, so every holder locks the same file.
pub(crate) async fn open_lock_file(path: &Path) -> anyhow::Result<File> {
    use anyhow::Context;

    let path: PathBuf = path.to_path_buf();
    tokio::task::spawn_blocking(move || open_lock_file_blocking(&path))
        .await
        .context("Lock file open task failed")?
}

fn open_lock_file_blocking(path: &Path) -> anyhow::Result<File> {
    use anyhow::Context;

    let mut options = OpenOptions::new();
    options
        .create(true)
        .truncate(false)
        .read(true)
        .write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .with_context(|| format!("Failed to open lock file {}", path.display()))
}

/// Takes the exclusive lock on the file at `path`, retrying while another holder has it, for
/// up to `timeout`. The lock is tried at least once, so a zero timeout takes a free lock.
/// Opening and each attempt run on a blocking thread, since each can be a round trip to a
/// network file server; the wait between attempts does not hold one.
pub(crate) async fn lock_exclusive(
    path: &Path,
    timeout: Duration,
) -> LockOutcome {
    let mut file = match open_lock_file(path).await {
        Ok(file) => file,
        Err(error) => return LockOutcome::Unavailable(error),
    };
    let give_up_at = tokio::time::Instant::now() + timeout;
    loop {
        let attempt = tokio::task::spawn_blocking(move || {
            let result = file.try_lock();
            (file, result)
        })
        .await;
        let result;
        (file, result) = match attempt {
            Ok(attempted) => attempted,
            Err(error) => return LockOutcome::Unavailable(anyhow::Error::new(error).context("Lock task failed")),
        };
        match result {
            Ok(()) => return LockOutcome::Acquired(file),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(error)) => {
                return LockOutcome::Unavailable(
                    anyhow::Error::new(error).context(format!("Failed to lock {}", path.display())),
                );
            }
        }
        if tokio::time::Instant::now() >= give_up_at {
            return LockOutcome::TimedOut;
        }
        tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lock_exclusive_times_out_while_held_and_succeeds_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".test.lock");
        let LockOutcome::Acquired(held) = lock_exclusive(&path, Duration::ZERO).await else {
            panic!("a free lock must be taken");
        };

        let waited = lock_exclusive(&path, Duration::from_millis(50)).await;

        assert!(matches!(waited, LockOutcome::TimedOut), "a held lock must time out: {waited:?}");
        drop(held);
        let after_release = lock_exclusive(&path, Duration::from_millis(50)).await;
        assert!(matches!(after_release, LockOutcome::Acquired(_)), "a released lock must be taken: {after_release:?}");
    }

    #[tokio::test]
    async fn lock_exclusive_waits_for_a_holder_that_releases_within_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".test.lock");
        let LockOutcome::Acquired(held) = lock_exclusive(&path, Duration::ZERO).await else {
            panic!("a free lock must be taken");
        };
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(held);
        });

        let waited = lock_exclusive(&path, Duration::from_secs(5)).await;

        release.await.unwrap();
        assert!(matches!(waited, LockOutcome::Acquired(_)), "the lock must be taken once released: {waited:?}");
    }

    #[tokio::test]
    async fn lock_exclusive_is_unavailable_when_the_lock_file_cannot_be_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".test.lock");
        std::fs::create_dir(&path).unwrap();

        let outcome = lock_exclusive(&path, Duration::from_secs(5)).await;

        assert!(matches!(outcome, LockOutcome::Unavailable(_)), "a directory is not a lock file: {outcome:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lock_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".test.lock");

        let outcome = lock_exclusive(&path, Duration::ZERO).await;

        assert!(matches!(outcome, LockOutcome::Acquired(_)), "a free lock must be taken: {outcome:?}");
        let mode = std::fs::metadata(&path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
