//! The one-time sweep: reads the live records, writes their definitions, renames the live
//! directories so it does not run again, and writes the report.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use super::apply::{MigrationReport, apply, write_report};
use super::legacy::{LegacyPaths, read_legacy};
use super::plan::plan;
use super::received::AuditForwarding;
use crate::config::StoragePaths;
use crate::integrations::definitions::DefinitionStores;
use crate::secrets::SecretsStore;

/// Old directories are deleted this long after the migration renamed them (Q6).
pub const MIGRATED_RETENTION_DAYS: u64 = 30;

/// Migrates the live records under `paths`, if there are any. `now` (unix seconds) names the
/// renamed directories and the report in `report_dir`. Fails, writing and renaming nothing,
/// when any live record cannot be read.
pub async fn migrate_from_live(
    paths: &LegacyPaths,
    report_dir: &Path,
    stores: &DefinitionStores,
    secrets: Option<&dyn SecretsStore>,
    audit: &AuditForwarding,
    now: u64,
) -> Result<Option<MigrationReport>> {
    let Some(records) = read_legacy(paths).await? else {
        return Ok(None);
    };
    let mut report = apply(plan(&records, audit), stores, secrets).await?;

    // The triggers go first: the definitions directory is what makes the sweep run again, so
    // it is renamed last, once everything else is done.
    for dir in [&paths.triggers, &paths.definitions] {
        if !dir.is_dir() {
            continue;
        }
        let target = migrated_path(dir, now);
        tokio::fs::rename(dir, &target)
            .await
            .with_context(|| format!("Failed to rename {} to {}", dir.display(), target.display()))?;
        report
            .notes
            .push(format!(
                "Renamed {} to {}; it may hold plain-text credentials and is deleted {MIGRATED_RETENTION_DAYS} days after the migration",
                dir.display(),
                target.display()
            ));
    }

    let report_path = report_dir.join(format!("migration-report-{now}.json"));
    if let Err(error) = write_report(&report_path, &report).await {
        error!(error = %error, "Failed to write the integration migration report");
    } else {
        info!(
            event = "integrations.migration.done",
            report = %report_path.display(),
            integrations = report.integrations.len(),
            skipped = report.skipped.len(),
            "Migrated the live version's integrations"
        );
    }
    Ok(Some(report))
}

/// `<dir>.migrated-<now>`.
pub fn migrated_path(
    dir: &Path,
    now: u64,
) -> PathBuf {
    let mut name = dir
        .file_name()
        .unwrap_or_default()
        .to_os_string();
    name.push(format!(".migrated-{now}"));
    dir.with_file_name(name)
}

/// The sweep at startup and on promotion to Active: migrates when live's directories are
/// still there, warns about the deprecated path keys, and never fails the caller. Returns
/// whether it wrote definitions, so the caller refreshes routes and sinks.
pub async fn migrate_on_activation(
    storage_paths: &StoragePaths,
    stores: &DefinitionStores,
    secrets: Option<&dyn SecretsStore>,
) -> bool {
    for (key, value) in
        [("integrations", &storage_paths.integrations), ("integration_triggers", &storage_paths.integration_triggers)]
    {
        if value.is_some() {
            warn!(
                key = %format!("storage_paths.{key}"),
                "Deprecated: used only to migrate integrations from the previous version; remove it once migrated"
            );
        }
    }
    let settings = crate::storage::settings_store::global_settings();
    let audit = settings
        .as_ref()
        .map(|settings| AuditForwarding::from_settings(settings.audit_enabled, &settings.audit_events))
        .unwrap_or_else(|| AuditForwarding::from_settings(false, &[]));
    let definitions = Path::new(&storage_paths.integration_definitions);
    let report_dir = definitions
        .parent()
        .unwrap_or(definitions);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    match migrate_from_live(&LegacyPaths::configured(storage_paths), report_dir, stores, secrets, &audit, now).await {
        Ok(report) => report.is_some(),
        Err(error) => {
            error!(
                event = "integrations.migration.failed",
                error = %format!("{error:#}"),
                "Failed to migrate the previous version's integrations; nothing was renamed, the next start tries again"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "6f1c2a7e-3b9d-4c55-9a51-0d7e8f2b4c11";
    const NOW: u64 = 1_792_000_000;

    fn write(
        dir: &Path,
        id: &str,
        value: &serde_json::Value,
    ) {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{id}.json")), serde_json::to_vec(value).expect("json")).expect("write");
    }

    struct Fixture {
        root: tempfile::TempDir,
        paths: LegacyPaths,
        stores: DefinitionStores,
    }

    async fn fixture() -> Fixture {
        let root = tempfile::tempdir().expect("temp dir");
        let base = root
            .path()
            .join("integrations");
        let paths = LegacyPaths {
            definitions: base.join("definitions"),
            triggers: base.join("triggers"),
            connection_points: root
                .path()
                .join("connection_points"),
        };
        let stores =
            DefinitionStores::open(&base.join("endpoints"), &base.join("event_sets"), &base.join("integrations"))
                .await
                .expect("stores");
        Fixture { root, paths, stores }
    }

    fn report_dir(f: &Fixture) -> PathBuf {
        f.root
            .path()
            .join("integrations")
    }

    fn seed_live(f: &Fixture) {
        write(
            &f.paths.definitions,
            ID,
            &json!({
                "id": ID, "name": "Ops webhook", "description": "", "type": "webhook", "category": "gateway",
                "configuration": {"url": "https://93.184.215.14/hook", "signing_secret": "s3cr3t"},
                "content": {"gateway": "${GATEWAY_NAME}"}, "status": "active",
                "created_at": "2026-09-01T10:00:00+00:00", "updated_at": "2026-09-01T10:00:00+00:00"
            }),
        );
        write(
            &f.paths
                .triggers
                .join("gateways/gw-1"),
            "config",
            &json!({"integration_integrations": [{"integration_id": ID, "event_types": ["gateway.created"]}]}),
        );
    }

    async fn run(f: &Fixture) -> Result<Option<MigrationReport>> {
        migrate_from_live(&f.paths, &report_dir(f), &f.stores, None, &AuditForwarding::from_settings(false, &[]), NOW)
            .await
    }

    fn renamed(dir: &Path) -> PathBuf {
        PathBuf::from(format!("{}.migrated-{NOW}", dir.display()))
    }

    #[tokio::test]
    async fn migrates_the_live_records_renames_their_directories_and_writes_the_report() {
        let f = fixture().await;
        seed_live(&f);

        let report = run(&f)
            .await
            .expect("migrates")
            .expect("a report");

        assert_eq!(report.integrations.len(), 1);
        let integration = f
            .stores
            .integrations
            .find(ID)
            .await
            .expect("reads")
            .expect("integration");
        assert_eq!(integration.endpoint_id, ID);
        assert!(!f.paths.definitions.exists());
        assert!(!f.paths.triggers.exists());
        assert!(
            renamed(&f.paths.definitions)
                .join(format!("{ID}.json"))
                .exists()
        );
        assert!(
            renamed(&f.paths.triggers)
                .join("gateways/gw-1/config.json")
                .exists()
        );
        let written =
            std::fs::read_to_string(report_dir(&f).join(format!("migration-report-{NOW}.json"))).expect("report");
        assert!(!written.contains("s3cr3t"), "{written}");
        assert!(written.contains(&format!("definitions.migrated-{NOW}")), "the report names the renamed directories");
    }

    #[tokio::test]
    async fn a_second_start_finds_nothing_to_migrate() {
        let f = fixture().await;
        seed_live(&f);
        run(&f)
            .await
            .expect("first start");

        assert_eq!(
            run(&f)
                .await
                .expect("second start"),
            None
        );
    }

    #[tokio::test]
    async fn without_live_records_nothing_happens() {
        let f = fixture().await;

        assert_eq!(run(&f).await.expect("runs"), None);
        assert!(!f.paths.triggers.exists());
        assert!(
            std::fs::read_dir(report_dir(&f))
                .expect("dir")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("migration-report"))
        );
    }

    #[tokio::test]
    async fn an_unreadable_live_record_migrates_and_renames_nothing() {
        let f = fixture().await;
        seed_live(&f);
        std::fs::write(
            f.paths
                .definitions
                .join("0b6c9d6e-0000-4000-8000-000000000000.json"),
            b"{broken",
        )
        .expect("write");

        assert!(run(&f).await.is_err());

        assert!(f.paths.definitions.exists());
        assert!(f.paths.triggers.exists());
        assert!(
            f.stores
                .endpoints
                .list()
                .await
                .expect("lists")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn live_records_without_attachments_still_rename_only_what_exists() {
        let f = fixture().await;
        write(
            &f.paths.definitions,
            ID,
            &json!({"id": ID, "name": "Mail", "type": "email", "category": "surface", "configuration": {}, "content": {}, "status": "active"}),
        );

        let report = run(&f)
            .await
            .expect("migrates")
            .expect("a report");

        assert_eq!(report.integrations.len(), 1);
        assert!(renamed(&f.paths.definitions).exists());
        assert!(!renamed(&f.paths.triggers).exists());
    }
}
