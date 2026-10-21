//! Writes a migration plan to the definition stores and reports what it did.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{info, warn};

use super::plan::{MigrationPlan, Planned, Skipped};
use crate::integrations::definitions::{DefinitionStores, Status};
use crate::secrets::SecretsStore;

/// What happened to one definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Created,
    /// A definition with its id exists, from an earlier run or written since; left as it is.
    AlreadyPresent,
    /// Live delivered it nothing, so there is no event set or integration.
    None,
}

/// One live integration in the report. Never holds a secret, header or attachment value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReportEntry {
    pub id: String,
    pub name: String,
    pub endpoint: Outcome,
    /// Why the endpoint was written disabled: its configuration fails the current checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_disabled: Option<String>,
    pub event_set: Outcome,
    pub events: HashSet<String>,
    pub integration: Outcome,
    /// Why the integration was written disabled whatever its live status: it belonged to a tenant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration_disabled: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MigrationReport {
    pub integrations: Vec<ReportEntry>,
    pub skipped: Vec<SkippedEntry>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SkippedEntry {
    pub id: String,
    pub name: String,
    pub reason: String,
}

impl From<Skipped> for SkippedEntry {
    fn from(skipped: Skipped) -> Self {
        Self {
            id: skipped.id,
            name: skipped.name,
            reason: skipped.reason,
        }
    }
}

/// Saves each planned definition whose id is not stored yet. An endpoint whose configuration
/// fails the checks a save through the API runs is written disabled, so its destination and
/// credentials are kept but nothing is sent.
pub async fn apply(
    plan: MigrationPlan,
    stores: &DefinitionStores,
    secrets: Option<&dyn SecretsStore>,
) -> Result<MigrationReport> {
    let mut report = MigrationReport {
        notes: plan.notes,
        skipped: plan
            .skipped
            .into_iter()
            .map(SkippedEntry::from)
            .collect(),
        ..MigrationReport::default()
    };
    for skipped in &report.skipped {
        warn!(
            event = "integrations.migration.skipped",
            integration_id = %skipped.id,
            name = %skipped.name,
            reason = %skipped.reason,
            "A live integration was not migrated"
        );
    }
    for planned in plan.planned {
        let entry = apply_one(planned, stores, secrets).await?;
        info!(
            event = "integrations.migration.integration",
            integration_id = %entry.id,
            name = %entry.name,
            endpoint = ?entry.endpoint,
            event_set = ?entry.event_set,
            integration = ?entry.integration,
            notes = entry.notes.len(),
            "Migrated a live integration"
        );
        if let Some(reason) = &entry.endpoint_disabled {
            warn!(
                event = "integrations.migration.endpoint_disabled",
                endpoint_id = %entry.id,
                name = %entry.name,
                reason = %reason,
                "A migrated endpoint fails the current checks and was written disabled"
            );
        }
        if let Some(reason) = &entry.integration_disabled {
            warn!(
                event = "integrations.migration.integration_disabled",
                integration_id = %entry.id,
                name = %entry.name,
                reason = %reason,
                "A migrated integration of a tenant was written disabled"
            );
        }
        report
            .integrations
            .push(entry);
    }
    Ok(report)
}

async fn apply_one(
    planned: Planned,
    stores: &DefinitionStores,
    secrets: Option<&dyn SecretsStore>,
) -> Result<ReportEntry> {
    let Planned {
        id,
        name,
        mut endpoint,
        event_set,
        integration,
        integration_disabled,
        notes,
    } = planned;
    let mut endpoint_disabled = None;
    let endpoint_outcome = if stores
        .endpoints
        .find(&endpoint.id)
        .await?
        .is_some()
    {
        Outcome::AlreadyPresent
    } else {
        if let Err(reason) = endpoint
            .validate_resolved(secrets)
            .await
        {
            endpoint.status = Status::Disabled;
            endpoint_disabled = Some(reason);
        }
        stores
            .endpoints
            .save(&endpoint)
            .await
            .with_context(|| format!("Failed to save the migrated endpoint {id}"))?;
        Outcome::Created
    };
    let events = event_set
        .as_ref()
        .map(|event_set| event_set.events.clone())
        .unwrap_or_default();
    let event_set_outcome = match event_set {
        None => Outcome::None,
        Some(event_set) => {
            if stores
                .event_sets
                .find(&event_set.id)
                .await?
                .is_some()
            {
                Outcome::AlreadyPresent
            } else {
                stores
                    .event_sets
                    .save(&event_set)
                    .await
                    .with_context(|| format!("Failed to save the migrated event set {id}"))?;
                Outcome::Created
            }
        }
    };
    let integration_outcome = match integration {
        None => Outcome::None,
        Some(integration) => {
            if stores
                .integrations
                .find(&integration.id)
                .await?
                .is_some()
            {
                Outcome::AlreadyPresent
            } else {
                stores
                    .integrations
                    .save(&integration)
                    .await
                    .with_context(|| format!("Failed to save the migrated integration {id}"))?;
                Outcome::Created
            }
        }
    };
    Ok(ReportEntry {
        id,
        name,
        endpoint: endpoint_outcome,
        endpoint_disabled,
        event_set: event_set_outcome,
        events,
        integration_disabled: integration_disabled.filter(|_| integration_outcome == Outcome::Created),
        integration: integration_outcome,
        notes,
    })
}

/// Writes `report` as JSON to `path`.
pub async fn write_report(
    path: &Path,
    report: &MigrationReport,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let json = serde_json::to_vec_pretty(report)?;
    tokio::fs::write(path, json)
        .await
        .with_context(|| format!("Failed to write the migration report {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::definitions::{Endpoint, EndpointType, EventSet, Integration};
    use serde_json::json;

    const ID: &str = "6f1c2a7e-3b9d-4c55-9a51-0d7e8f2b4c11";

    async fn stores(dir: &Path) -> DefinitionStores {
        DefinitionStores::open(&dir.join("endpoints"), &dir.join("event_sets"), &dir.join("integrations"))
            .await
            .expect("stores")
    }

    fn planned(
        url: &str,
        with_integration: bool,
    ) -> Planned {
        let mut endpoint = Endpoint::new(
            "Ops webhook".to_string(),
            String::new(),
            EndpointType::Webhook,
            json!({"url": url, "signing_secret": "s3cr3t"}),
        );
        endpoint.id = ID.to_string();
        let (event_set, integration) = if with_integration {
            let mut event_set = EventSet::new(
                "Ops webhook events (migrated)".to_string(),
                String::new(),
                vec!["gateway.created".into()],
            )
            .expect("set");
            event_set.id = ID.to_string();
            let mut integration =
                Integration::new("Ops webhook".to_string(), String::new(), ID.to_string(), ID.to_string(), json!({}));
            integration.id = ID.to_string();
            (Some(event_set), Some(integration))
        } else {
            (None, None)
        };
        Planned {
            id: ID.to_string(),
            name: "Ops webhook".to_string(),
            endpoint,
            event_set,
            integration,
            integration_disabled: None,
            notes: vec!["Received gateway events only from gw-1".to_string()],
        }
    }

    fn one(planned: Planned) -> MigrationPlan {
        MigrationPlan {
            planned: vec![planned],
            ..MigrationPlan::default()
        }
    }

    #[tokio::test]
    async fn writes_the_endpoint_event_set_and_integration_and_reports_them() {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = stores(dir.path()).await;

        let report = apply(one(planned("https://93.184.215.14/hook", true)), &stores, None)
            .await
            .expect("applies");

        let endpoint = stores
            .endpoints
            .find(ID)
            .await
            .expect("reads")
            .expect("endpoint");
        assert_eq!(endpoint.status, Status::Active);
        assert_eq!(endpoint.configuration["signing_secret"], "s3cr3t", "stored as a value, as live had it");
        assert!(
            stores
                .event_sets
                .find(ID)
                .await
                .expect("reads")
                .is_some()
        );
        assert!(
            stores
                .integrations
                .find(ID)
                .await
                .expect("reads")
                .is_some()
        );
        assert_eq!(
            report.integrations,
            [ReportEntry {
                id: ID.to_string(),
                name: "Ops webhook".to_string(),
                endpoint: Outcome::Created,
                endpoint_disabled: None,
                event_set: Outcome::Created,
                events: HashSet::from(["gateway.created".to_string()]),
                integration: Outcome::Created,
                integration_disabled: None,
                notes: vec!["Received gateway events only from gw-1".to_string()],
            }]
        );
    }

    #[tokio::test]
    async fn an_endpoint_failing_the_checks_is_written_disabled_with_the_reason() {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = stores(dir.path()).await;

        let report = apply(one(planned("http://169.254.169.254/latest", true)), &stores, None)
            .await
            .expect("applies");

        let endpoint = stores
            .endpoints
            .find(ID)
            .await
            .expect("reads")
            .expect("endpoint");
        assert_eq!(endpoint.status, Status::Disabled);
        let reason = report.integrations[0]
            .endpoint_disabled
            .clone()
            .expect("reason");
        assert!(reason.contains("169.254.169.254"), "{reason}");
        assert_eq!(report.integrations[0].integration, Outcome::Created, "the integration is kept");
    }

    #[tokio::test]
    async fn an_integration_planned_disabled_is_reported_with_the_reason_when_written() {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = stores(dir.path()).await;
        let disabled = || {
            let mut planned = planned("https://93.184.215.14/hook", true);
            if let Some(integration) = planned.integration.as_mut() {
                integration.status = Status::Disabled;
            }
            planned.integration_disabled = Some("It belonged to the tenant team-a".to_string());
            planned
        };

        let report = apply(one(disabled()), &stores, None)
            .await
            .expect("applies");

        let integration = stores
            .integrations
            .find(ID)
            .await
            .expect("reads")
            .expect("integration");
        assert_eq!(integration.status, Status::Disabled);
        assert_eq!(
            report.integrations[0]
                .integration_disabled
                .as_deref(),
            Some("It belonged to the tenant team-a")
        );

        let again = apply(one(disabled()), &stores, None)
            .await
            .expect("applies again");
        assert_eq!(again.integrations[0].integration, Outcome::AlreadyPresent);
        assert_eq!(again.integrations[0].integration_disabled, None, "nothing was written this time");
    }

    #[tokio::test]
    async fn the_report_never_shows_a_slack_webhook_url_that_fails_the_checks() {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = stores(dir.path()).await;
        let mut planned = planned("https://93.184.215.14/hook", false);
        planned.endpoint = Endpoint::new(
            "Ops Slack".to_string(),
            String::new(),
            EndpointType::Slack,
            json!({"webhook_url": "hooks.slack.com/services/T0/B0/s3cr3t-plain"}),
        );
        planned.endpoint.id = ID.to_string();

        let report = apply(one(planned), &stores, None)
            .await
            .expect("applies");

        let reason = report.integrations[0]
            .endpoint_disabled
            .clone()
            .expect("reason");
        assert!(reason.starts_with("webhook_url rejected: Invalid URL"), "{reason}");
        let written = serde_json::to_string(&report).expect("serializes");
        assert!(!written.contains("s3cr3t-plain"), "{written}");
    }

    #[tokio::test]
    async fn running_again_changes_nothing_already_written() {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = stores(dir.path()).await;
        apply(one(planned("https://93.184.215.14/hook", true)), &stores, None)
            .await
            .expect("first run");
        let mut edited = stores
            .endpoints
            .find(ID)
            .await
            .expect("reads")
            .expect("endpoint");
        edited.name = "Renamed since".to_string();
        stores
            .endpoints
            .save(&edited)
            .await
            .expect("save");

        let report = apply(one(planned("https://93.184.215.14/hook", true)), &stores, None)
            .await
            .expect("second run");

        let entry = &report.integrations[0];
        assert_eq!(
            (entry.endpoint, entry.event_set, entry.integration),
            (Outcome::AlreadyPresent, Outcome::AlreadyPresent, Outcome::AlreadyPresent)
        );
        assert_eq!(
            stores
                .endpoints
                .find(ID)
                .await
                .expect("reads")
                .expect("endpoint")
                .name,
            "Renamed since"
        );
    }

    #[tokio::test]
    async fn an_endpoint_only_entry_writes_just_the_endpoint() {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = stores(dir.path()).await;

        let report = apply(one(planned("https://93.184.215.14/hook", false)), &stores, None)
            .await
            .expect("applies");

        assert_eq!(
            (report.integrations[0].event_set, report.integrations[0].integration),
            (Outcome::None, Outcome::None)
        );
        assert!(
            stores
                .integrations
                .list()
                .await
                .expect("lists")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_report_file_holds_no_secret_value() {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = stores(dir.path()).await;
        let mut plan = one(planned("https://93.184.215.14/hook", true));
        plan.skipped.push(Skipped {
            id: "other".to_string(),
            name: "Teams".to_string(),
            reason: "Its type teams is not one an endpoint can have".to_string(),
        });
        plan.notes
            .push("The users were attached to the missing integration x; not migrated".to_string());
        let report = apply(plan, &stores, None)
            .await
            .expect("applies");
        let path = dir.path().join("report.json");

        write_report(&path, &report)
            .await
            .expect("writes");

        let written = std::fs::read_to_string(&path).expect("report");
        assert!(!written.contains("s3cr3t"), "{written}");
        let value: serde_json::Value = serde_json::from_str(&written).expect("json");
        assert_eq!(value["integrations"][0]["endpoint"], "created");
        assert_eq!(value["skipped"][0]["name"], "Teams");
        assert_eq!(value["notes"][0], "The users were attached to the missing integration x; not migrated");
    }
}
