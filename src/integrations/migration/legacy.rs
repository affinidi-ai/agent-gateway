//! The integration records of the live version (`2470747`), read only so they can be migrated.
//!
//! Each struct keeps only the fields the migration needs and never overrides
//! `migrate_raw_json`, so reading a record never rewrites it: the storage layer re-saves a
//! record through its struct only when that hook reports a change, and this struct would drop
//! every field it leaves out.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::storage::filesystem::{StorableEntity, uncached_storage};

/// An integration as live stored it: its transport, credentials and template in one record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyIntegration {
    pub id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub configuration: JsonValue,
    #[serde(default)]
    pub content: JsonValue,
    pub status: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    /// Written only by a `main` after the live version (PR #43); live never has them.
    #[serde(default)]
    pub audit_events: Vec<String>,
    #[serde(default)]
    pub audit_drop_after_secs: Option<u64>,
    #[serde(default)]
    pub audit_max_attempts: Option<u32>,
}

impl StorableEntity for LegacyIntegration {
    fn id(&self) -> &str {
        &self.id
    }
}

/// One integration attached to a gateway, the users or the identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyAttachment {
    pub integration_id: String,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    /// Empty means every event of the attachment's kind.
    #[serde(default)]
    pub event_types: Vec<String>,
}

const ATTACHMENTS_ID: &str = "config";

/// The `config.json` holding one gateway's, the users' or the identities' attachments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LegacyAttachments {
    #[serde(default)]
    integration_integrations: Vec<LegacyAttachment>,
}

impl StorableEntity for LegacyAttachments {
    fn id(&self) -> &str {
        ATTACHMENTS_ID
    }
}

/// An integration a connection point names, from its `integrations` list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyConnectionPointIntegration {
    pub integration_id: String,
    #[serde(default)]
    pub variables: JsonValue,
}

/// The integration fields of a connection point record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyConnectionPoint {
    pub id: String,
    #[serde(default)]
    pub gateway_id: String,
    #[serde(default)]
    pub integrations: Vec<LegacyConnectionPointIntegration>,
    /// The single integration of older records, used when `integrations` is empty.
    #[serde(default)]
    pub integration_id: Option<String>,
}

impl LegacyConnectionPoint {
    /// The integrations live delivered this connection point's events to: the list, or the
    /// older single field when the list is empty.
    pub fn integration_ids(&self) -> Vec<&str> {
        if self.integrations.is_empty() {
            return self
                .integration_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .into_iter()
                .collect();
        }
        self.integrations
            .iter()
            .map(|integration| {
                integration
                    .integration_id
                    .as_str()
            })
            .collect()
    }
}

impl StorableEntity for LegacyConnectionPoint {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Where live kept its integration records.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyPaths {
    /// `storage_paths.integrations`: one record per integration.
    pub definitions: PathBuf,
    /// `storage_paths.integration_triggers`: `gateways/<id>/`, `users/` and `identities/`.
    pub triggers: PathBuf,
    /// `storage_paths.connection_points`, which the current version still uses.
    pub connection_points: PathBuf,
}

const LIVE_DEFINITIONS: &str = "_storage/integrations/definitions";
const LIVE_TRIGGERS: &str = "_storage/integrations/triggers";

impl LegacyPaths {
    /// The deprecated `storage_paths.integrations` and `integration_triggers` when set,
    /// otherwise live's defaults, and the connection points where they still are.
    pub fn configured(paths: &crate::config::StoragePaths) -> Self {
        Self {
            definitions: PathBuf::from(
                paths
                    .integrations
                    .as_deref()
                    .unwrap_or(LIVE_DEFINITIONS),
            ),
            triggers: PathBuf::from(
                paths
                    .integration_triggers
                    .as_deref()
                    .unwrap_or(LIVE_TRIGGERS),
            ),
            connection_points: PathBuf::from(&paths.connection_points),
        }
    }
}

/// Every live record the migration reads.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LegacyRecords {
    pub integrations: Vec<LegacyIntegration>,
    /// Attachments by gateway id.
    pub gateway_attachments: Vec<(String, Vec<LegacyAttachment>)>,
    pub user_attachments: Vec<LegacyAttachment>,
    pub identity_attachments: Vec<LegacyAttachment>,
    pub connection_points: Vec<LegacyConnectionPoint>,
}

/// The live records, or `None` when there is no live integration directory to migrate. Fails
/// when any record cannot be read, decrypted or parsed, so nothing is migrated from a partial
/// read.
pub async fn read_legacy(paths: &LegacyPaths) -> Result<Option<LegacyRecords>> {
    // Opening a store creates its directory, so only directories that exist are opened.
    if !paths.definitions.is_dir() {
        return Ok(None);
    }
    let integrations = records_in::<LegacyIntegration>(&paths.definitions, "live integration").await?;
    let mut gateway_attachments = Vec::new();
    let gateways = paths
        .triggers
        .join("gateways");
    for (gateway_id, dir) in subdirectories(&gateways).await? {
        let attachments = attachments_in(&dir).await?;
        if !attachments.is_empty() {
            gateway_attachments.push((gateway_id, attachments));
        }
    }
    let connection_points = if paths
        .connection_points
        .is_dir()
    {
        records_in::<LegacyConnectionPoint>(&paths.connection_points, "live connection point").await?
    } else {
        Vec::new()
    };
    Ok(Some(LegacyRecords {
        integrations,
        gateway_attachments,
        user_attachments: attachments_in(&paths.triggers.join("users")).await?,
        identity_attachments: attachments_in(
            &paths
                .triggers
                .join("identities"),
        )
        .await?,
        connection_points,
    }))
}

async fn records_in<T: StorableEntity>(
    dir: &Path,
    entity_name: &'static str,
) -> Result<Vec<T>> {
    uncached_storage::<T>(dir.to_path_buf(), entity_name)
        .await?
        .list_all()
        .await
        .with_context(|| format!("Failed to read the {entity_name} records in {}", dir.display()))
}

async fn attachments_in(dir: &Path) -> Result<Vec<LegacyAttachment>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let attachments = uncached_storage::<LegacyAttachments>(dir.to_path_buf(), "live integration attachments")
        .await?
        .get(ATTACHMENTS_ID)
        .await
        .with_context(|| format!("Failed to read the integration attachments in {}", dir.display()))?;
    Ok(attachments
        .unwrap_or_default()
        .integration_integrations)
}

/// The directories in `dir` with their names, sorted; none when `dir` does not exist.
async fn subdirectories(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("Failed to list {}", dir.display()))?;
    while let Some(entry) = entries.next_entry().await? {
        if entry
            .file_type()
            .await?
            .is_dir()
        {
            found.push((
                entry
                    .file_name()
                    .to_string_lossy()
                    .into_owned(),
                entry.path(),
            ));
        }
    }
    found.sort();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Writes `value` as `<dir>/<id>.json`, as live did with encryption at rest off.
    fn write(
        dir: &Path,
        id: &str,
        value: &JsonValue,
    ) {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{id}.json")), serde_json::to_vec_pretty(value).expect("json")).expect("write");
    }

    fn paths(root: &Path) -> LegacyPaths {
        LegacyPaths {
            definitions: root.join("integrations/definitions"),
            triggers: root.join("integrations/triggers"),
            connection_points: root.join("connection_points"),
        }
    }

    /// An integration in the 2470747 shape, as its dashboard saved it.
    fn live_integration(
        id: &str,
        category: &str,
    ) -> JsonValue {
        json!({
            "id": id,
            "tenant_id": "team-a",
            "name": "Ops Slack",
            "description": "Gateway changes to ops",
            "type": "slack",
            "category": category,
            "configuration": {"webhook_url": "https://hooks.slack.com/services/T/B/x", "channel": "#ops"},
            "content": {"text": "${GATEWAY_NAME} ${_TEAM}"},
            "status": "active",
            "created_at": "2026-09-01T10:00:00+00:00",
            "updated_at": "2026-09-02T10:00:00+00:00"
        })
    }

    #[test]
    fn the_live_paths_are_the_deprecated_keys_resolved_against_the_config_files_directory() {
        let root = tempfile::tempdir().expect("temp dir");

        let custom = super::super::config_in(
            &root
                .path()
                .join("custom/config"),
            "integrations = \"../old/definitions\"\nintegration_triggers = \"/data/triggers\"\nconnection_points = \"../cp\"",
        );

        assert_eq!(
            LegacyPaths::configured(&custom.storage_paths),
            LegacyPaths {
                definitions: root
                    .path()
                    .join("custom/old/definitions"),
                triggers: PathBuf::from("/data/triggers"),
                connection_points: root
                    .path()
                    .join("custom/cp"),
            }
        );
        assert!(
            custom
                .storage_paths
                .integrations
                .is_some()
                && custom
                    .storage_paths
                    .integration_triggers
                    .is_some(),
            "the deprecation warning still knows the keys were set"
        );
    }

    #[test]
    fn without_the_deprecated_keys_the_live_defaults_resolve_against_the_config_files_directory() {
        let root = tempfile::tempdir().expect("temp dir");
        let config_dir = root
            .path()
            .join("config");

        let defaults = super::super::config_in(&config_dir, "");

        assert_eq!(
            LegacyPaths::configured(&defaults.storage_paths),
            LegacyPaths {
                definitions: config_dir.join("_storage/integrations/definitions"),
                triggers: config_dir.join("_storage/integrations/triggers"),
                connection_points: config_dir.join("_storage/connection_points"),
            }
        );
        assert_eq!(
            (
                defaults
                    .storage_paths
                    .integrations,
                defaults
                    .storage_paths
                    .integration_triggers
            ),
            (None, None)
        );
    }

    #[tokio::test]
    async fn there_is_nothing_to_read_without_the_live_definitions_directory() {
        let root = tempfile::tempdir().expect("temp dir");
        let paths = paths(root.path());

        assert_eq!(
            read_legacy(&paths)
                .await
                .expect("reads"),
            None
        );
        assert!(!paths.definitions.exists(), "reading must not create the live directory");
        assert!(!paths.triggers.exists());
    }

    #[tokio::test]
    async fn reads_integrations_attachments_and_connection_points_in_the_live_layout() {
        let root = tempfile::tempdir().expect("temp dir");
        let paths = paths(root.path());
        let id = "6f1c2a7e-3b9d-4c55-9a51-0d7e8f2b4c11";
        write(&paths.definitions, id, &live_integration(id, "gateway"));
        let attachment = json!({"integration_integrations": [
            {"integration_id": id, "variables": {"_TEAM": "edge"}, "event_types": ["gateway.created"]}
        ]});
        write(
            &paths
                .triggers
                .join("gateways/gw-1"),
            "config",
            &attachment,
        );
        write(&paths.triggers.join("users"), "config", &json!({"integration_integrations": [{"integration_id": id}]}));
        write(
            &paths
                .triggers
                .join("identities"),
            "config",
            &json!({}),
        );
        write(
            &paths.connection_points,
            "cp-1",
            &json!({"id": "cp-1", "gateway_id": "gw-1", "name": "Partner", "integrations": [{"integration_id": id}]}),
        );
        write(
            &paths.connection_points,
            "cp-2",
            &json!({"id": "cp-2", "gateway_id": "gw-1", "integration_id": id, "integration_variables": {}}),
        );

        let records = read_legacy(&paths)
            .await
            .expect("reads")
            .expect("live records");

        assert_eq!(records.integrations.len(), 1);
        let integration = &records.integrations[0];
        assert_eq!(
            integration
                .tenant_id
                .as_deref(),
            Some("team-a")
        );
        assert_eq!(
            integration
                .category
                .as_deref(),
            Some("gateway")
        );
        assert_eq!(integration.integration_type, "slack");
        assert_eq!(integration.content, json!({"text": "${GATEWAY_NAME} ${_TEAM}"}));
        assert!(
            integration
                .audit_events
                .is_empty()
        );
        assert_eq!(
            records.gateway_attachments,
            [(
                "gw-1".to_string(),
                vec![LegacyAttachment {
                    integration_id: id.to_string(),
                    variables: HashMap::from([("_TEAM".to_string(), "edge".to_string())]),
                    event_types: vec!["gateway.created".to_string()],
                }]
            )]
        );
        assert_eq!(records.user_attachments[0].event_types, Vec::<String>::new());
        assert!(
            records
                .identity_attachments
                .is_empty()
        );
        let mut named: Vec<(&str, Vec<&str>)> = records
            .connection_points
            .iter()
            .map(|point| (point.id.as_str(), point.integration_ids()))
            .collect();
        named.sort();
        assert_eq!(named, [("cp-1", vec![id]), ("cp-2", vec![id])]);
    }

    #[tokio::test]
    async fn reading_leaves_the_live_records_as_they_were() {
        let root = tempfile::tempdir().expect("temp dir");
        let paths = paths(root.path());
        let id = "6f1c2a7e-3b9d-4c55-9a51-0d7e8f2b4c11";
        write(&paths.definitions, id, &live_integration(id, "channel"));
        let point = json!({"id": "cp-1", "gateway_id": "gw-1", "name": "Partner", "oob_id": "o", "integrations": []});
        write(&paths.connection_points, "cp-1", &point);
        let before = |dir: &Path, id: &str| std::fs::read(dir.join(format!("{id}.json"))).expect("read");
        let (integration, connection_point) =
            (before(&paths.definitions, id), before(&paths.connection_points, "cp-1"));

        read_legacy(&paths)
            .await
            .expect("reads");

        assert_eq!(before(&paths.definitions, id), integration);
        assert_eq!(before(&paths.connection_points, "cp-1"), connection_point);
    }

    #[tokio::test]
    async fn an_unreadable_record_fails_the_read() {
        let root = tempfile::tempdir().expect("temp dir");
        let paths = paths(root.path());
        std::fs::create_dir_all(&paths.definitions).expect("dir");
        std::fs::write(
            paths
                .definitions
                .join("6f1c2a7e-3b9d-4c55-9a51-0d7e8f2b4c11.json"),
            b"{not json",
        )
        .expect("write");

        assert!(
            read_legacy(&paths)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn reads_audit_fields_a_later_main_wrote() {
        let root = tempfile::tempdir().expect("temp dir");
        let paths = paths(root.path());
        let id = "6f1c2a7e-3b9d-4c55-9a51-0d7e8f2b4c11";
        let mut record = live_integration(id, "audit");
        record["audit_events"] = json!(["policy_decision"]);
        record["audit_max_attempts"] = json!(5);
        write(&paths.definitions, id, &record);

        let records = read_legacy(&paths)
            .await
            .expect("reads")
            .expect("live records");

        assert_eq!(records.integrations[0].audit_events, ["policy_decision"]);
        assert_eq!(records.integrations[0].audit_max_attempts, Some(5));
        assert_eq!(records.integrations[0].audit_drop_after_secs, None);
    }
}
