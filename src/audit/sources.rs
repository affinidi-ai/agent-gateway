//! Builds the audit sinks from where each one is configured.

use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::audit::registry::{EventMask, Sink, SinkId, Sinks, sinks};
use crate::integrations::audit_integration_triggers::receives_audit_records;
use crate::integrations::cache::INTEGRATION_CACHE;
use crate::metrics::backends::prometheus::track_audit_sink_rebuild_failed;
use crate::storage::settings_store::{DashboardSettings, SettingsStore, global_settings, global_settings_store};
use crate::storage::{Integration, IntegrationStorage, get_integration_storage};

/// Held for a whole rebuild, so rebuilds apply in the order they start.
static REBUILDING: Mutex<()> = Mutex::const_new(());
/// The rebuild retry scheduled after a failed rebuild.
static RETRY: parking_lot::Mutex<Option<CancellationToken>> = parking_lot::const_mutex(None);
/// The token rebuild retries run under (see [`rebuild_sinks_within`]).
static RETRY_SCOPE: LazyLock<parking_lot::Mutex<CancellationToken>> = LazyLock::new(Default::default);
const REBUILD_RETRY: Duration = Duration::from_secs(5);

/// Each active, appliance-wide Governance Audit integration as a sink.
pub fn integration_sinks(integrations: &[Integration]) -> Vec<Sink> {
    integrations
        .iter()
        .filter(|integration| receives_audit_records(integration))
        .map(|integration| {
            Sink::new(
                SinkId::Integration(integration.id.clone()),
                EventMask::from_categories(
                    integration
                        .audit_events
                        .iter()
                        .map(String::as_str),
                ),
            )
            .dropping_older_than(
                integration
                    .audit_drop_after_secs
                    .map(Duration::from_secs),
            )
            .giving_up_after(integration.audit_max_attempts)
        })
        .collect()
}

/// Each integration that exists but does not receive audit records: a
/// Governance Audit integration disabled, given a tenant or moved to another
/// category, or one never in that category.
fn paused_integrations(integrations: &[Integration]) -> Vec<SinkId> {
    integrations
        .iter()
        .filter(|integration| !receives_audit_records(integration))
        .map(|integration| SinkId::Integration(integration.id.clone()))
        .collect()
}

pub fn build_sinks(
    settings: &DashboardSettings,
    integrations: &[Integration],
) -> Vec<Sink> {
    std::iter::once(audit_log_sink(settings))
        .chain(integration_sinks(integrations))
        .collect()
}

/// Rebuilds the sinks from the current settings and integrations, one rebuild
/// at a time. When the integrations cannot be listed the current sinks are
/// kept, so no record addressed to an integration is lost, the failure is
/// counted, and the rebuild is retried every [`REBUILD_RETRY`] until it
/// succeeds or the scope set by [`rebuild_sinks_within`] is cancelled.
/// Returns whether this rebuild replaced the sinks.
pub async fn rebuild_sinks() -> bool {
    if rebuild_current().await {
        return true;
    }
    schedule_retry();
    false
}

/// [`rebuild_sinks`] for the audit pipeline: rebuild retries from now on run
/// under `scope` and end once it is cancelled, and a retry scheduled under an
/// earlier scope is stopped.
pub async fn rebuild_sinks_within(scope: CancellationToken) -> bool {
    *RETRY_SCOPE.lock() = scope;
    if let Some(retry) = RETRY.lock().take() {
        retry.cancel();
    }
    rebuild_sinks().await
}

/// Schedules a rebuild retry under the current scope unless one is running.
/// A retry that ends is cancelled, so the next failure schedules another.
fn schedule_retry() {
    let mut scheduled = RETRY.lock();
    if scheduled
        .as_ref()
        .is_some_and(|retry| !retry.is_cancelled())
    {
        return;
    }
    let retry = RETRY_SCOPE
        .lock()
        .child_token();
    *scheduled = Some(retry.clone());
    tokio::spawn(async move {
        retry_until_rebuilt(REBUILD_RETRY, rebuild_current, &retry).await;
        retry.cancel();
    });
}

async fn rebuild_current() -> bool {
    rebuild(&REBUILDING, sinks(), || global_settings().unwrap_or_default(), list_integrations).await
}

async fn list_integrations() -> anyhow::Result<Vec<Integration>> {
    list_from(get_integration_storage()).await
}

/// The integrations in `storage`. Without storage they cannot be listed: an
/// empty list would read as every integration deleted.
async fn list_from(storage: Option<Arc<IntegrationStorage>>) -> anyhow::Result<Vec<Integration>> {
    match storage {
        Some(storage) => storage.list().await,
        None => anyhow::bail!("integration storage is not set up yet"),
    }
}

/// Builds the sinks and the paused integrations from `settings` and `list`
/// and replaces `registry`'s, under
/// `serial` for the whole rebuild so a slower rebuild never replaces newer
/// sinks. Keeps the current sinks and returns false when `list` fails.
async fn rebuild<L, F>(
    serial: &Mutex<()>,
    registry: &Sinks,
    settings: impl FnOnce() -> DashboardSettings,
    list: L,
) -> bool
where
    L: FnOnce() -> F,
    F: Future<Output = anyhow::Result<Vec<Integration>>>,
{
    let _serial = serial.lock().await;
    let settings = settings();
    match list().await {
        Ok(integrations) => {
            registry.replace(build_sinks(&settings, &integrations), paused_integrations(&integrations));
            true
        }
        Err(e) => {
            warn!(error = %e, "Failed to list integrations; keeping the current audit sinks and retrying");
            track_audit_sink_rebuild_failed();
            false
        }
    }
}

/// The integrations deliveries load, by id.
type IntegrationCache = moka::future::Cache<String, Arc<Integration>>;

/// Re-reads the dashboard settings from disk and forgets every cached
/// integration, so the sinks built next, and the deliveries to them, follow
/// what is stored now rather than what this node loaded before. A node
/// becoming Active calls it before the audit pipeline starts: the node that
/// was Active may have changed both.
pub async fn reload_sources() {
    reload(global_settings_store(), &INTEGRATION_CACHE).await;
}

/// Reloads `settings` from disk, keeping the settings already loaded when
/// that fails, and empties `integrations`.
async fn reload(
    settings: Option<&SettingsStore>,
    integrations: &IntegrationCache,
) {
    if let Some(settings) = settings
        && let Err(e) = settings.load().await
    {
        warn!(error = %e, "Failed to reload the dashboard settings; building the audit sinks from those already loaded");
    }
    integrations.invalidate_all();
}

/// Attempts the rebuild every `delay` until an attempt succeeds or `cancel`
/// fires, which also drops an attempt in flight.
async fn retry_until_rebuilt<A, F>(
    delay: Duration,
    mut attempt: A,
    cancel: &CancellationToken,
) where
    A: FnMut() -> F,
    F: Future<Output = bool>,
{
    loop {
        if cancel
            .run_until_cancelled(tokio::time::sleep(delay))
            .await
            .is_none()
        {
            return;
        }
        if cancel
            .run_until_cancelled(attempt())
            .await
            .is_none_or(|rebuilt| rebuilt)
        {
            return;
        }
    }
}

/// The VP Audit Log as a sink: the selected events while auditing is on,
/// nothing while it is off.
pub fn audit_log_sink(settings: &DashboardSettings) -> Sink {
    let events = if settings.audit_enabled {
        EventMask::from_categories(
            settings
                .audit_events
                .iter()
                .map(String::as_str),
        )
    } else {
        EventMask::default()
    };
    Sink::new(SinkId::AuditLog, events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::catalog::event_bit;
    use crate::audit::registry::SinkRegistry;

    #[test]
    fn default_settings_give_an_audit_log_sink_that_selects_nothing() {
        let sink = audit_log_sink(&DashboardSettings::default());
        assert_eq!(sink.id, SinkId::AuditLog);
        assert_eq!(sink.events, EventMask::default());
    }

    #[test]
    fn audit_log_sink_selects_the_stored_events_when_enabled() {
        let settings = DashboardSettings {
            audit_enabled: true,
            audit_events: vec!["policy_decision".to_string(), "no_such_event".to_string()],
            ..DashboardSettings::default()
        };
        let events = audit_log_sink(&settings).events;
        assert!(events.contains(event_bit("policy_decision").unwrap()));
        assert_eq!(events.categories(), vec!["policy_decision"]);
    }

    fn audit_integration(
        status: &str,
        tenant_id: Option<&str>,
        events: &[&str],
    ) -> Integration {
        let mut integration = Integration::new(
            "siem".to_string(),
            String::new(),
            "stream".to_string(),
            serde_json::json!({}),
            serde_json::json!({}),
            status.to_string(),
            Some("audit".to_string()),
        );
        integration.tenant_id = tenant_id.map(str::to_string);
        integration.audit_events = events
            .iter()
            .map(|event| event.to_string())
            .collect();
        integration
    }

    #[test]
    fn active_appliance_wide_audit_integrations_are_sinks() {
        let integration = audit_integration("active", None, &["auth_failed"]);
        let sinks = integration_sinks(std::slice::from_ref(&integration));
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].id, SinkId::Integration(integration.id.clone()));
        assert_eq!(sinks[0].events.categories(), vec!["auth_failed"]);
    }

    #[test]
    fn an_integrations_drop_policy_carries_into_its_sink() {
        let mut integration = audit_integration("active", None, &["auth_failed"]);
        integration.audit_drop_after_secs = Some(3600);
        let without = audit_integration("active", None, &["auth_failed"]);
        let sinks = integration_sinks(&[integration, without]);
        assert_eq!(sinks[0].drop_older_than, Some(std::time::Duration::from_secs(3600)));
        assert_eq!(sinks[1].drop_older_than, None);
    }

    #[test]
    fn an_integrations_attempt_limit_carries_into_its_sink() {
        let mut integration = audit_integration("active", None, &["auth_failed"]);
        integration.audit_max_attempts = Some(10);
        let without = audit_integration("active", None, &["auth_failed"]);
        let sinks = integration_sinks(&[integration, without]);
        assert_eq!(sinks[0].max_attempts, Some(10));
        assert_eq!(sinks[1].max_attempts, None);
    }

    #[test]
    fn disabled_tenant_owned_and_other_integrations_are_not_sinks() {
        let mut general = audit_integration("active", None, &["auth_failed"]);
        general.category = Some("general".to_string());
        let integrations = [
            audit_integration("disabled", None, &["auth_failed"]),
            audit_integration("active", Some("tenant-a"), &["auth_failed"]),
            general,
        ];
        assert!(integration_sinks(&integrations).is_empty());
    }

    #[test]
    fn integrations_that_do_not_receive_audit_records_are_paused() {
        let receiving = audit_integration("active", None, &["auth_failed"]);
        let disabled = audit_integration("disabled", None, &["auth_failed"]);
        let tenant_owned = audit_integration("active", Some("tenant-a"), &["auth_failed"]);
        let mut general = audit_integration("active", None, &["auth_failed"]);
        general.category = Some("general".to_string());

        let paused = paused_integrations(&[receiving, disabled.clone(), tenant_owned.clone(), general.clone()]);

        assert_eq!(
            paused,
            vec![
                SinkId::Integration(disabled.id),
                SinkId::Integration(tenant_owned.id),
                SinkId::Integration(general.id)
            ]
        );
    }

    #[tokio::test]
    async fn a_rebuild_keeps_the_paused_integrations() {
        let serial = Mutex::new(());
        let registry: &'static Sinks = Box::leak(Box::default());
        let receiving = audit_integration("active", None, &["auth_failed"]);
        let disabled = audit_integration("disabled", None, &["auth_failed"]);
        let listed = vec![receiving.clone(), disabled.clone()];

        let rebuilt = rebuild(&serial, registry, || selecting("policy_decision"), || async move { Ok(listed) }).await;

        assert!(rebuilt);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.ids(), &[SinkId::AuditLog, SinkId::Integration(receiving.id)]);
        assert_eq!(snapshot.paused(), &[SinkId::Integration(disabled.id)]);
    }

    #[test]
    fn build_lists_the_audit_log_then_each_integration() {
        let settings = DashboardSettings {
            audit_enabled: true,
            audit_events: vec!["policy_decision".to_string()],
            ..DashboardSettings::default()
        };
        let integration = audit_integration("active", None, &["policy_decision", "trust_check"]);
        let registry = SinkRegistry::new(build_sinks(&settings, std::slice::from_ref(&integration)));

        let policy = event_bit("policy_decision").unwrap();
        let trust = event_bit("trust_check").unwrap();
        assert_eq!(registry.recipients(policy), &[SinkId::AuditLog, SinkId::Integration(integration.id.clone())]);
        assert_eq!(registry.recipients(trust), &[SinkId::Integration(integration.id.clone())]);
    }

    #[test]
    fn integrations_receive_events_the_audit_log_does_not_keep() {
        let settings = DashboardSettings::default();
        let integration = audit_integration("active", None, &["auth_failed"]);
        let registry = SinkRegistry::new(build_sinks(&settings, std::slice::from_ref(&integration)));
        assert!(registry.wants(event_bit("auth_failed").unwrap()));
    }

    #[test]
    fn inactive_audit_log_sink_selects_nothing_and_keeps_the_selection() {
        let settings = DashboardSettings {
            audit_enabled: false,
            audit_events: vec!["policy_decision".to_string()],
            ..DashboardSettings::default()
        };
        assert_eq!(audit_log_sink(&settings).events, EventMask::default());
        assert_eq!(settings.audit_events, vec!["policy_decision".to_string()]);
    }

    fn selecting(event: &str) -> DashboardSettings {
        DashboardSettings {
            audit_enabled: true,
            audit_events: vec![event.to_string()],
            ..DashboardSettings::default()
        }
    }

    fn log_selects(
        registry: &Sinks,
        event: &str,
    ) -> bool {
        registry
            .snapshot()
            .recipients(event_bit(event).unwrap())
            .contains(&SinkId::AuditLog)
    }

    #[tokio::test]
    async fn a_rebuild_replaces_the_sinks() {
        let serial = Mutex::new(());
        let registry: &'static Sinks = Box::leak(Box::default());
        let integration = audit_integration("active", None, &["auth_failed"]);

        let rebuilt =
            rebuild(&serial, registry, || selecting("policy_decision"), || async move { Ok(vec![integration]) }).await;

        assert!(rebuilt);
        assert!(log_selects(registry, "policy_decision"));
        assert_eq!(
            registry
                .snapshot()
                .ids()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn a_failed_listing_keeps_the_current_sinks_and_reports_the_failure() {
        let serial = Mutex::new(());
        let registry: &'static Sinks = Box::leak(Box::default());
        registry.replace(build_sinks(&selecting("policy_decision"), &[]), Vec::new());

        let rebuilt = rebuild(
            &serial,
            registry,
            || selecting("trust_check"),
            || async { Err::<Vec<Integration>, _>(anyhow::anyhow!("storage unavailable")) },
        )
        .await;

        assert!(!rebuilt);
        assert!(log_selects(registry, "policy_decision"));
        assert!(!log_selects(registry, "trust_check"));
    }

    #[tokio::test]
    async fn overlapping_rebuilds_apply_in_the_order_they_start() {
        let serial = Mutex::new(());
        let registry: &'static Sinks = Box::leak(Box::default());
        let (release, held) = tokio::sync::oneshot::channel::<()>();

        let older = rebuild(
            &serial,
            registry,
            || selecting("policy_decision"),
            || async move {
                let _ = held.await;
                Ok(Vec::new())
            },
        );
        let newer = rebuild(&serial, registry, || selecting("trust_check"), || async { Ok(Vec::new()) });
        let (older, newer, ()) = tokio::join!(older, newer, async {
            tokio::task::yield_now().await;
            let _ = release.send(());
        });

        assert!(older && newer);
        assert!(log_selects(registry, "trust_check"));
        assert!(!log_selects(registry, "policy_decision"));
    }

    #[tokio::test]
    async fn listing_without_integration_storage_fails_so_the_sinks_are_kept() {
        let serial = Mutex::new(());
        let registry: &'static Sinks = Box::leak(Box::default());
        registry.replace(build_sinks(&selecting("policy_decision"), &[]), Vec::new());

        let rebuilt = rebuild(&serial, registry, || selecting("trust_check"), || list_from(None)).await;

        assert!(!rebuilt);
        assert!(list_from(None).await.is_err());
        assert!(log_selects(registry, "policy_decision"));
    }

    #[tokio::test]
    async fn a_reload_rebuilds_from_the_settings_and_integrations_stored_now() {
        let dir = tempfile::TempDir::new().unwrap();
        let settings_dir = dir.path().join("settings");
        let settings = SettingsStore::new(&settings_dir);
        settings.load().await.unwrap();
        let storage = IntegrationStorage::new(
            dir.path()
                .join("integrations"),
        )
        .await
        .unwrap();
        let integration = audit_integration("active", None, &["auth_failed"]);
        storage
            .save(&integration)
            .await
            .unwrap();
        let cache = IntegrationCache::builder().build();
        cache
            .insert(integration.id.clone(), Arc::new(integration.clone()))
            .await;
        let serial = Mutex::new(());
        let registry: &'static Sinks = Box::leak(Box::default());
        assert!(rebuild(&serial, registry, || settings.get(), || storage.list()).await);

        let other_node = SettingsStore::new(&settings_dir);
        other_node
            .update(selecting("policy_decision"))
            .unwrap();
        other_node
            .save()
            .await
            .unwrap();
        let mut changed = integration.clone();
        changed.audit_events = vec!["trust_check".to_string()];
        storage
            .save(&changed)
            .await
            .unwrap();
        assert!(!settings.get().audit_enabled);

        reload(Some(&settings), &cache).await;
        assert!(rebuild(&serial, registry, || settings.get(), || storage.list()).await);

        let siem = SinkId::Integration(integration.id.clone());
        let snapshot = registry.snapshot();
        assert!(log_selects(registry, "policy_decision"));
        assert_eq!(snapshot.recipients(event_bit("trust_check").unwrap()), std::slice::from_ref(&siem));
        assert!(
            snapshot
                .recipients(event_bit("auth_failed").unwrap())
                .is_empty()
        );
        assert!(
            cache
                .get(&integration.id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_reload_without_a_settings_store_still_forgets_the_cached_integrations() {
        let cache = IntegrationCache::builder().build();
        let integration = audit_integration("active", None, &["auth_failed"]);
        cache
            .insert(integration.id.clone(), Arc::new(integration.clone()))
            .await;

        reload(None, &cache).await;

        assert!(
            cache
                .get(&integration.id)
                .await
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_rebuild_is_retried_until_it_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        retry_until_rebuilt(
            Duration::from_secs(5),
            || {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                async move { attempt == 3 }
            },
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_rebuild_retry_ends_once_cancelled() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        let cancel = CancellationToken::new();
        retry_until_rebuilt(
            Duration::from_secs(5),
            || {
                if attempts.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                    cancel.cancel();
                }
                async { false }
            },
            &cancel,
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_rebuild_retry_cancelled_while_waiting_makes_no_attempt() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        let cancel = CancellationToken::new();
        let (_, ()) = tokio::join!(
            retry_until_rebuilt(
                Duration::from_secs(5),
                || {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    async { false }
                },
                &cancel,
            ),
            async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                cancel.cancel();
            }
        );

        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }
}
