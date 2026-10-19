//! Deletes the live directories the migration renamed, once they are old enough. They
//! may hold plain-text credentials, so they are not kept longer than a restore needs them.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use tracing::{info, warn};

use super::legacy::LegacyPaths;
use super::run::MIGRATED_RETENTION_DAYS;
use crate::config::StoragePaths;

/// How often the Active node looks for directories to delete.
const CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);

/// Deletes each `<dir>.migrated-<unix seconds>` beside one of `dirs` that was renamed at least
/// `MIGRATED_RETENTION_DAYS` before `now`, and returns what it deleted. Other entries are never
/// touched, whatever they are called.
pub async fn remove_expired(
    dirs: &[PathBuf],
    now: u64,
) -> Result<Vec<PathBuf>> {
    let retention = MIGRATED_RETENTION_DAYS * 86_400;
    let mut removed = Vec::new();
    for (path, renamed_at) in renamed_dirs(dirs).await? {
        if renamed_at.saturating_add(retention) <= now {
            tokio::fs::remove_dir_all(&path).await?;
            removed.push(path);
        }
    }
    Ok(removed)
}

/// Each `<dir>.migrated-<unix seconds>` directory beside one of `dirs`, with its timestamp.
async fn renamed_dirs(dirs: &[PathBuf]) -> Result<Vec<(PathBuf, u64)>> {
    let mut found = Vec::new();
    for dir in dirs {
        let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
            continue;
        };
        if !parent.is_dir() {
            continue;
        }
        let prefix = format!("{}.migrated-", name.to_string_lossy());
        let mut entries = tokio::fs::read_dir(parent).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry
                .file_name()
                .to_string_lossy()
                .into_owned();
            let Some(renamed_at) = file_name
                .strip_prefix(&prefix)
                .and_then(|stamp| stamp.parse::<u64>().ok())
            else {
                continue;
            };
            if entry
                .file_type()
                .await?
                .is_dir()
            {
                found.push((entry.path(), renamed_at));
            }
        }
    }
    Ok(found)
}

/// Whether a renamed live directory is waiting to be deleted. A directory that cannot be
/// listed counts as pending, so the job starts and reports the failure.
pub async fn cleanup_pending(dirs: &[PathBuf]) -> bool {
    renamed_dirs(dirs)
        .await
        .map_or(true, |found| !found.is_empty())
}

/// Deletes what has expired, and returns whether any renamed directory is still waiting.
pub async fn cleanup_round(
    dirs: &[PathBuf],
    now: u64,
) -> Result<bool> {
    for dir in remove_expired(dirs, now).await? {
        info!(
            event = "integrations.migration.cleaned",
            dir = %dir.display(),
            "Deleted a live integration directory the migration renamed {MIGRATED_RETENTION_DAYS} days ago"
        );
    }
    Ok(!renamed_dirs(dirs)
        .await?
        .is_empty())
}

/// Set while a cleanup job runs, so a promotion that migrates does not start a second one.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Starts the cleanup job when a renamed live directory is waiting, unless one already runs,
/// and returns whether it started one. Called at startup, after the sweep, and after a sweep
/// on promotion; a node with nothing to delete runs no job. The job checks every few hours,
/// deletes only on the Active node, and ends once nothing is left.
pub async fn start_cleanup_if_pending(storage_paths: &StoragePaths) -> bool {
    let paths = LegacyPaths::configured(storage_paths);
    let dirs = vec![paths.definitions, paths.triggers];
    if !cleanup_pending(&dirs).await
        || RUNNING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return false;
    }
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(CHECK_EVERY);
        loop {
            ticks.tick().await;
            if crate::server::mode::is_standby() {
                continue;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or_default();
            match cleanup_round(&dirs, now).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => warn!(error = %error, "Failed to delete the old integration directories"),
            }
        }
        RUNNING.store(false, Ordering::SeqCst);
        info!(event = "integrations.migration.cleanup_done", "No migrated integration directories are left to delete");
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_792_000_000;

    fn make(
        parent: &Path,
        name: &str,
    ) -> PathBuf {
        let dir = parent.join(name);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("record.json"), b"{}").expect("write");
        dir
    }

    #[tokio::test]
    async fn deletes_renamed_directories_older_than_the_retention_and_keeps_the_rest() {
        let root = tempfile::tempdir().expect("temp dir");
        let parent = root
            .path()
            .join("integrations");
        let definitions = parent.join("definitions");
        let triggers = parent.join("triggers");
        let expired = MIGRATED_RETENTION_DAYS * DAY + 1;
        let old_definitions = make(&parent, &format!("definitions.migrated-{}", NOW - expired));
        let old_triggers = make(&parent, &format!("triggers.migrated-{}", NOW - MIGRATED_RETENTION_DAYS * DAY));
        let recent = make(&parent, &format!("definitions.migrated-{}", NOW - DAY));
        let unrelated = make(&parent, &format!("endpoints.migrated-{}", NOW - expired));
        let not_a_timestamp = make(&parent, "definitions.migrated-soon");
        let live = make(&parent, "definitions");
        std::fs::write(parent.join(format!("triggers.migrated-{}", NOW - expired)), b"a file").expect("write");

        let mut removed = remove_expired(&[definitions, triggers], NOW)
            .await
            .expect("cleans");

        removed.sort();
        assert_eq!(removed, [old_definitions.clone(), old_triggers.clone()]);
        assert!(!old_definitions.exists());
        assert!(!old_triggers.exists());
        for kept in [recent, unrelated, not_a_timestamp, live] {
            assert!(kept.exists(), "{} was deleted", kept.display());
        }
        assert!(
            parent
                .join(format!("triggers.migrated-{}", NOW - expired))
                .is_file(),
            "only directories are deleted"
        );
    }

    #[tokio::test]
    async fn cleanup_is_pending_only_while_a_renamed_live_directory_is_left() {
        let root = tempfile::tempdir().expect("temp dir");
        let parent = root
            .path()
            .join("integrations");
        let dirs = [parent.join("definitions"), parent.join("triggers")];
        assert!(!cleanup_pending(&dirs).await, "nothing there");

        make(&parent, "definitions");
        make(&parent, &format!("endpoints.migrated-{NOW}"));
        assert!(!cleanup_pending(&dirs).await, "neither the live directory nor another one counts");

        make(&parent, &format!("triggers.migrated-{NOW}"));
        assert!(cleanup_pending(&dirs).await);
    }

    #[tokio::test]
    async fn a_round_says_whether_anything_is_left_to_wait_for() {
        let root = tempfile::tempdir().expect("temp dir");
        let parent = root
            .path()
            .join("integrations");
        let dirs = [parent.join("definitions"), parent.join("triggers")];
        let expired = MIGRATED_RETENTION_DAYS * DAY + 1;
        make(&parent, &format!("definitions.migrated-{}", NOW - expired));
        let recent = make(&parent, &format!("triggers.migrated-{}", NOW - DAY));

        assert!(
            cleanup_round(&dirs, NOW)
                .await
                .expect("round"),
            "the recent one is still waiting"
        );

        std::fs::remove_dir_all(recent).expect("remove");
        make(&parent, &format!("triggers.migrated-{}", NOW - expired));
        assert!(
            !cleanup_round(&dirs, NOW)
                .await
                .expect("round"),
            "everything was deleted, so the job can stop"
        );
    }

    #[tokio::test]
    async fn the_job_starts_only_when_cleanup_is_pending() {
        let root = tempfile::tempdir().expect("temp dir");
        let base = root
            .path()
            .join("integrations");
        let paths = StoragePaths {
            legacy_integrations: base
                .join("definitions")
                .to_string_lossy()
                .into_owned(),
            legacy_integration_triggers: base
                .join("triggers")
                .to_string_lossy()
                .into_owned(),
            ..StoragePaths::default()
        };

        assert!(!start_cleanup_if_pending(&paths).await, "a fresh install starts no job");

        make(&base, &format!("definitions.migrated-{NOW}"));
        assert!(start_cleanup_if_pending(&paths).await, "a renamed directory starts it");
        assert!(!start_cleanup_if_pending(&paths).await, "one job at a time");
    }

    #[tokio::test]
    async fn finds_the_renamed_directories_beside_the_live_paths_resolved_from_the_config_file() {
        let root = tempfile::tempdir().expect("temp dir");
        let expired = NOW - MIGRATED_RETENTION_DAYS * DAY - 1;
        let cases = [
            (
                "defaults",
                "",
                root.path()
                    .join("defaults/config/_storage/integrations"),
            ),
            (
                "keys",
                "integrations = \"../_storage/integrations/definitions\"\nintegration_triggers = \"../_storage/integrations/triggers\"",
                root.path()
                    .join("keys/_storage/integrations"),
            ),
        ];
        for (name, storage_paths, parent) in cases {
            let config = super::super::config_in(
                &root
                    .path()
                    .join(name)
                    .join("config"),
                storage_paths,
            );
            let renamed = [
                make(&parent, &format!("definitions.migrated-{expired}")),
                make(&parent, &format!("triggers.migrated-{expired}")),
            ];
            let live = LegacyPaths::configured(&config.storage_paths);

            let removed = remove_expired(&[live.definitions, live.triggers], NOW)
                .await
                .expect("cleans");

            assert_eq!(removed.len(), 2, "{name}: {removed:?}");
            for dir in renamed {
                assert!(!dir.exists(), "{name}: {} was kept", dir.display());
            }
        }
    }

    #[tokio::test]
    async fn a_missing_parent_deletes_nothing() {
        let root = tempfile::tempdir().expect("temp dir");

        let removed = remove_expired(
            &[root
                .path()
                .join("gone/definitions")],
            NOW,
        )
        .await
        .expect("cleans");

        assert!(removed.is_empty());
    }
}
