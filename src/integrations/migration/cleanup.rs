//! Deletes the live directories the migration renamed, once they are old enough (Q6). They
//! may hold plain-text credentials, so they are not kept longer than a restore needs them.

use std::path::PathBuf;
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
            if renamed_at.saturating_add(retention) > now
                || !entry
                    .file_type()
                    .await?
                    .is_dir()
            {
                continue;
            }
            tokio::fs::remove_dir_all(entry.path()).await?;
            removed.push(entry.path());
        }
    }
    Ok(removed)
}

/// Checks every few hours, on the Active node only, for renamed live directories to delete.
pub fn spawn_cleanup(storage_paths: &StoragePaths) {
    let paths = LegacyPaths::configured(storage_paths);
    let dirs = vec![paths.definitions, paths.triggers];
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
            match remove_expired(&dirs, now).await {
                Ok(removed) => {
                    for dir in removed {
                        info!(
                            event = "integrations.migration.cleaned",
                            dir = %dir.display(),
                            "Deleted a live integration directory the migration renamed {MIGRATED_RETENTION_DAYS} days ago"
                        );
                    }
                }
                Err(error) => warn!(error = %error, "Failed to delete the old integration directories"),
            }
        }
    });
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
