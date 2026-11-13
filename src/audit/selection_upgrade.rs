//! Adds new audit events to the stored selections once: the VP Audit Log's
//! `audit_events` and every integration event set that selects the event each
//! new one extends. The settings directory's marker file names the events
//! added, so an event an operator removes afterwards stays removed.

use std::path::Path;

use anyhow::{Context, Result};
use tracing::{error, info};

use crate::integrations::definitions::{DefinitionStore, EventSet};
use crate::storage::settings_store::SettingsStore;

/// Each new event, with the event a stored selection must hold to get it.
const ADDED_EVENTS: [(&str, &str); 1] = [("delegation_failed", "consent_granted")];

/// The marker file in the settings directory: the events already added.
pub const MARKER_FILE_NAME: &str = "audit_events_added.json";

/// The integration event id of the audit event `event`.
fn integration_event(event: &str) -> String {
    format!("audit.{event}")
}

/// Runs [`add_once`] at startup and on promotion to Active, and never fails
/// the caller: an error is logged and the next start tries again. Returns
/// whether a selection changed, so the caller refreshes routes and sinks.
pub async fn add_on_activation(
    settings: Option<&SettingsStore>,
    settings_dir: &Path,
    event_sets: &DefinitionStore<EventSet>,
) -> bool {
    let Some(settings) = settings else {
        return false;
    };
    match add_once(settings, settings_dir, event_sets).await {
        Ok(changed) => changed,
        Err(e) => {
            error!(
                event = "audit.selection_upgrade.failed",
                error = %format!("{e:#}"),
                "Failed to add new audit events to the stored selections; the next start tries again"
            );
            false
        }
    }
}

/// Adds each event of [`ADDED_EVENTS`] the marker does not name to the
/// selections that hold the event it extends and lack it, then writes the
/// marker. Each selection is read and saved under its store's write guard,
/// and the settings are read from disk under it, so a change saved on this
/// process meanwhile is kept and a deleted event set stays deleted. The marker
/// is written last: a failure leaves it unwritten and the next run adds what
/// is still missing. Returns whether a selection changed.
pub async fn add_once(
    settings: &SettingsStore,
    settings_dir: &Path,
    event_sets: &DefinitionStore<EventSet>,
) -> Result<bool> {
    let marker_path = settings_dir.join(MARKER_FILE_NAME);
    let added: Vec<String> = match tokio::fs::read_to_string(&marker_path).await {
        Ok(content) => serde_json::from_str(&content)
            .with_context(|| format!("The marker {} is not a JSON list of events", marker_path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("Failed to read the marker {}", marker_path.display())),
    };
    let pending: Vec<(&str, &str)> = ADDED_EVENTS
        .into_iter()
        .filter(|(event, _)| {
            !added
                .iter()
                .any(|done| done == event)
        })
        .collect();
    if pending.is_empty() {
        return Ok(false);
    }

    let mut changed_sets = 0;
    for listed in event_sets
        .list()
        .await
        .context("Failed to list the integration event sets")?
    {
        let _writing = event_sets.lock_writes().await;
        let Some(mut event_set) = event_sets
            .find(&listed.id)
            .await
            .with_context(|| format!("Failed to read the event set {}", listed.id))?
        else {
            continue;
        };
        let mut changed = false;
        for (event, extends) in &pending {
            if event_set.contains(&integration_event(extends)) {
                changed |= event_set
                    .events
                    .insert(integration_event(event));
            }
        }
        if changed {
            event_set.updated_at = chrono::Utc::now().to_rfc3339();
            event_sets
                .save(&event_set)
                .await
                .with_context(|| format!("Failed to save the event set {}", event_set.id))?;
            changed_sets += 1;
        }
    }

    let audit_log_changed = {
        let _writing = settings.lock_writes().await;
        settings
            .load()
            .await
            .context("Failed to reload the dashboard settings")?;
        let mut current = settings.get();
        let mut changed = false;
        for (event, extends) in &pending {
            if current
                .audit_events
                .iter()
                .any(|selected| selected == extends)
                && !current
                    .audit_events
                    .iter()
                    .any(|selected| selected == event)
            {
                current
                    .audit_events
                    .push((*event).to_string());
                changed = true;
            }
        }
        if changed {
            settings
                .update(current)
                .context("Failed to change the dashboard settings")?;
            settings
                .save()
                .await
                .context("Failed to save the dashboard settings")?;
        }
        changed
    };

    let marker: Vec<&str> = ADDED_EVENTS
        .iter()
        .map(|(event, _)| *event)
        .collect();
    let temporary = settings_dir.join(format!("{MARKER_FILE_NAME}.tmp"));
    tokio::fs::write(&temporary, serde_json::to_vec(&marker)?)
        .await
        .with_context(|| format!("Failed to write {}", temporary.display()))?;
    tokio::fs::rename(&temporary, &marker_path)
        .await
        .with_context(|| format!("Failed to write the marker {}", marker_path.display()))?;

    let changed = changed_sets > 0 || audit_log_changed;
    if changed {
        info!(
            event = "audit.selection_upgrade.done",
            event_sets = changed_sets,
            audit_log = audit_log_changed,
            "Added new audit events to the stored selections that hold the events they extend"
        );
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::settings_store::DashboardSettings;

    struct Stores {
        _dir: tempfile::TempDir,
        settings_dir: std::path::PathBuf,
        settings: SettingsStore,
        event_sets: DefinitionStore<EventSet>,
    }

    async fn stores(audit_events: &[&str]) -> Stores {
        let dir = tempfile::TempDir::new().unwrap();
        let settings_dir = dir.path().join("settings");
        let settings = SettingsStore::new(&settings_dir);
        settings.load().await.unwrap();
        settings
            .update(DashboardSettings {
                audit_enabled: true,
                audit_events: audit_events
                    .iter()
                    .map(|event| event.to_string())
                    .collect(),
                ..DashboardSettings::default()
            })
            .unwrap();
        settings.save().await.unwrap();
        let event_sets = DefinitionStore::new(dir.path().join("event_sets"), "integration event set")
            .await
            .unwrap();
        Stores {
            _dir: dir,
            settings_dir,
            settings,
            event_sets,
        }
    }

    async fn event_set(
        stores: &Stores,
        events: &[&str],
    ) -> EventSet {
        let mut event_set = EventSet::new(
            "Set".to_string(),
            String::new(),
            events
                .iter()
                .map(|event| integration_event(event))
                .collect(),
        )
        .unwrap();
        event_set.updated_at = "2026-01-01T00:00:00+00:00".to_string();
        stores
            .event_sets
            .save(&event_set)
            .await
            .unwrap();
        event_set
    }

    async fn stored(
        stores: &Stores,
        event_set: &EventSet,
    ) -> EventSet {
        stores
            .event_sets
            .find(&event_set.id)
            .await
            .unwrap()
            .unwrap()
    }

    fn sorted(events: &std::collections::HashSet<String>) -> Vec<&str> {
        let mut events: Vec<&str> = events
            .iter()
            .map(String::as_str)
            .collect();
        events.sort_unstable();
        events
    }

    #[test]
    fn each_added_event_is_one_the_vp_audit_log_and_integrations_can_select() {
        for (event, extends) in ADDED_EVENTS {
            assert!(crate::audit::catalog::event_bit(event).is_some(), "{event}");
            assert!(crate::audit::catalog::event_bit(extends).is_some(), "{extends}");
            assert!(crate::integrations::events::find_event(&integration_event(event)).is_some(), "{event}");
            assert!(crate::integrations::events::find_event(&integration_event(extends)).is_some(), "{extends}");
        }
    }

    /// A selection holding `consent_granted` gets `delegation_failed`; one
    /// without it is left alone, and one with both is not saved again.
    #[tokio::test]
    async fn delegation_failed_is_added_where_consent_granted_is_selected() {
        let stores = stores(&["consent_granted", "auth_failed"]).await;
        let consent = event_set(&stores, &["consent_granted"]).await;
        let other = event_set(&stores, &["auth_failed"]).await;
        let both = event_set(&stores, &["consent_granted", "delegation_failed"]).await;

        let changed = add_once(&stores.settings, &stores.settings_dir, &stores.event_sets)
            .await
            .unwrap();

        assert!(changed);
        let consent = stored(&stores, &consent).await;
        assert_eq!(sorted(&consent.events), ["audit.consent_granted", "audit.delegation_failed"]);
        assert_ne!(consent.updated_at, "2026-01-01T00:00:00+00:00");
        assert_eq!(stored(&stores, &other).await, other);
        assert_eq!(stored(&stores, &both).await, both);
        let reread = SettingsStore::new(&stores.settings_dir);
        reread.load().await.unwrap();
        assert_eq!(reread.get().audit_events, ["consent_granted", "auth_failed", "delegation_failed"]);
    }

    #[tokio::test]
    async fn a_vp_audit_log_selection_without_consent_granted_is_left_alone() {
        let stores = stores(&["auth_failed"]).await;

        let changed = add_once(&stores.settings, &stores.settings_dir, &stores.event_sets)
            .await
            .unwrap();

        assert!(!changed);
        assert_eq!(
            stores
                .settings
                .get()
                .audit_events,
            ["auth_failed"]
        );
        assert!(
            stores
                .settings_dir
                .join(MARKER_FILE_NAME)
                .exists(),
            "the marker is written anyway"
        );
    }

    /// Once added, an event the operator removes stays removed.
    #[tokio::test]
    async fn an_event_removed_after_it_was_added_is_not_added_again() {
        let stores = stores(&["consent_granted"]).await;
        let consent = event_set(&stores, &["consent_granted"]).await;
        add_once(&stores.settings, &stores.settings_dir, &stores.event_sets)
            .await
            .unwrap();
        let mut removed = stored(&stores, &consent).await;
        removed
            .events
            .remove("audit.delegation_failed");
        stores
            .event_sets
            .save(&removed)
            .await
            .unwrap();
        let mut settings = stores.settings.get();
        settings.audit_events = vec!["consent_granted".to_string()];
        stores
            .settings
            .update(settings)
            .unwrap();
        stores
            .settings
            .save()
            .await
            .unwrap();

        let changed = add_once(&stores.settings, &stores.settings_dir, &stores.event_sets)
            .await
            .unwrap();

        assert!(!changed);
        assert_eq!(stored(&stores, &consent).await, removed);
        assert_eq!(
            stores
                .settings
                .get()
                .audit_events,
            ["consent_granted"]
        );
    }

    /// A marker that cannot be read changes nothing and fails, so the next
    /// start reports it again.
    #[tokio::test]
    async fn an_unreadable_marker_changes_nothing() {
        let stores = stores(&["consent_granted"]).await;
        let consent = event_set(&stores, &["consent_granted"]).await;
        tokio::fs::write(
            stores
                .settings_dir
                .join(MARKER_FILE_NAME),
            "not json",
        )
        .await
        .unwrap();

        assert!(
            add_once(&stores.settings, &stores.settings_dir, &stores.event_sets)
                .await
                .is_err()
        );
        assert!(!add_on_activation(Some(&stores.settings), &stores.settings_dir, &stores.event_sets).await);

        assert_eq!(stored(&stores, &consent).await, consent);
        assert_eq!(
            stores
                .settings
                .get()
                .audit_events,
            ["consent_granted"]
        );
    }

    /// The settings on disk are read before they are changed, so a newer copy
    /// another node saved is kept.
    #[tokio::test]
    async fn the_settings_on_disk_are_the_ones_changed() {
        let stores = stores(&[]).await;
        let other_node = SettingsStore::new(&stores.settings_dir);
        other_node
            .load()
            .await
            .unwrap();
        other_node
            .update(DashboardSettings {
                audit_enabled: true,
                audit_events: vec!["consent_granted".to_string()],
                badge_threshold_minutes: 9,
                ..DashboardSettings::default()
            })
            .unwrap();
        other_node
            .save()
            .await
            .unwrap();

        assert!(
            add_once(&stores.settings, &stores.settings_dir, &stores.event_sets)
                .await
                .unwrap()
        );

        let settings = stores.settings.get();
        assert_eq!(settings.badge_threshold_minutes, 9);
        assert_eq!(settings.audit_events, ["consent_granted", "delegation_failed"]);
    }

    /// A settings change in progress when the upgrade runs is kept, and so is
    /// the event the upgrade adds.
    #[tokio::test]
    async fn a_settings_change_in_progress_is_kept_beside_the_added_event() {
        let stores = stores(&["consent_granted"]).await;

        let ((), changed) = tokio::join!(
            async {
                let _writing = stores
                    .settings
                    .lock_writes()
                    .await;
                let mut settings = stores.settings.get();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                settings.badge_threshold_minutes = 9;
                stores
                    .settings
                    .update(settings)
                    .unwrap();
                stores
                    .settings
                    .save()
                    .await
                    .unwrap();
            },
            add_once(&stores.settings, &stores.settings_dir, &stores.event_sets)
        );

        assert!(changed.unwrap());
        let reread = SettingsStore::new(&stores.settings_dir);
        reread.load().await.unwrap();
        assert_eq!(
            reread
                .get()
                .badge_threshold_minutes,
            9
        );
        assert_eq!(reread.get().audit_events, ["consent_granted", "delegation_failed"]);
    }

    /// An event set change in progress when the upgrade runs is kept, and so
    /// is the event the upgrade adds.
    #[tokio::test]
    async fn an_event_set_change_in_progress_is_kept_beside_the_added_event() {
        let stores = stores(&[]).await;
        let consent = event_set(&stores, &["consent_granted"]).await;

        let ((), changed) = tokio::join!(
            async {
                let _writing = stores
                    .event_sets
                    .lock_writes()
                    .await;
                let mut edited = stored(&stores, &consent).await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                edited
                    .events
                    .insert(integration_event("auth_failed"));
                stores
                    .event_sets
                    .save(&edited)
                    .await
                    .unwrap();
            },
            add_once(&stores.settings, &stores.settings_dir, &stores.event_sets)
        );

        assert!(changed.unwrap());
        assert_eq!(
            sorted(
                &stored(&stores, &consent)
                    .await
                    .events
            ),
            ["audit.auth_failed", "audit.consent_granted", "audit.delegation_failed"]
        );
    }

    /// An event set deleted while the upgrade waits for it stays deleted.
    #[tokio::test]
    async fn an_event_set_deleted_meanwhile_stays_deleted() {
        let stores = stores(&[]).await;
        let consent = event_set(&stores, &["consent_granted"]).await;
        let writing = stores
            .event_sets
            .lock_writes()
            .await;

        let upgrade = add_once(&stores.settings, &stores.settings_dir, &stores.event_sets);
        tokio::pin!(upgrade);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut upgrade)
                .await
                .is_err(),
            "the upgrade waits for the event set's write guard"
        );
        assert!(
            stores
                .event_sets
                .delete(&consent.id)
                .await
                .unwrap()
        );
        drop(writing);

        assert!(!upgrade.await.unwrap());
        assert_eq!(
            stores
                .event_sets
                .find(&consent.id)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn without_a_settings_store_nothing_runs() {
        let stores = stores(&["consent_granted"]).await;

        assert!(!add_on_activation(None, &stores.settings_dir, &stores.event_sets).await);
        assert!(
            !stores
                .settings_dir
                .join(MARKER_FILE_NAME)
                .exists()
        );
    }
}
