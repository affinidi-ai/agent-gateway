//! Builds the audit sinks from where each one is configured.

use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::audit::registry::{EventMask, Sink, SinkId, Sinks, sinks};
use crate::integrations::definitions::{DefinitionStores, definition_stores};
use crate::integrations::delivery::dispatch::{Routes, invalidate_routes};
use crate::metrics::backends::prometheus::track_audit_sink_rebuild_failed;
use crate::storage::settings_store::{DashboardSettings, SettingsStore, global_settings, global_settings_store};

/// Held for a whole rebuild, so rebuilds apply in the order they start.
static REBUILDING: Mutex<()> = Mutex::const_new(());
/// The rebuild retry scheduled after a failed rebuild.
static RETRY: parking_lot::Mutex<Option<CancellationToken>> = parking_lot::const_mutex(None);
/// The token rebuild retries run under (see [`rebuild_sinks_within`]).
static RETRY_SCOPE: LazyLock<parking_lot::Mutex<CancellationToken>> = LazyLock::new(Default::default);
const REBUILD_RETRY: Duration = Duration::from_secs(5);

/// Each integration that receives audit records as a sink selecting its event set's audit
/// events.
pub fn integration_sinks(routes: &Routes) -> Vec<Sink> {
    routes
        .audit_receivers()
        .into_iter()
        .map(|receiver| {
            let integration = &receiver.route.integration;
            Sink::new(
                SinkId::Integration(integration.id.clone()),
                EventMask::from_categories(
                    receiver
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

/// Each integration that exists but does not receive audit records: disabled, its endpoint
/// disabled, or its event set holding no audit events.
fn paused_integrations(routes: &Routes) -> Vec<SinkId> {
    routes
        .integration_ids()
        .filter(|id| {
            routes
                .audit_receiver(id)
                .is_none()
        })
        .map(|id| SinkId::Integration(id.to_string()))
        .collect()
}

pub fn build_sinks(
    settings: &DashboardSettings,
    routes: &Routes,
) -> Vec<Sink> {
    std::iter::once(audit_log_sink(settings))
        .chain(integration_sinks(routes))
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

async fn list_integrations() -> anyhow::Result<Routes> {
    list_from(definition_stores()).await
}

/// The definitions in `stores`. Without stores they cannot be listed: an empty list would
/// read as every integration deleted.
async fn list_from(stores: Option<Arc<DefinitionStores>>) -> anyhow::Result<Routes> {
    match stores {
        Some(stores) => Routes::load(&stores).await,
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
    F: Future<Output = anyhow::Result<Routes>>,
{
    let _serial = serial.lock().await;
    let settings = settings();
    match list().await {
        Ok(routes) => {
            registry.replace(build_sinks(&settings, &routes), paused_integrations(&routes));
            true
        }
        Err(e) => {
            warn!(error = %e, "Failed to list integrations; keeping the current audit sinks and retrying");
            track_audit_sink_rebuild_failed();
            false
        }
    }
}

/// Re-reads the dashboard settings from disk and forgets the cached
/// integration definitions, so the sinks built next, and the deliveries to
/// them, follow what is stored now rather than what this node loaded before.
/// A node becoming Active calls it before the audit pipeline starts: the node
/// that was Active may have changed both.
pub async fn reload_sources() {
    reload(global_settings_store()).await;
    invalidate_routes().await;
}

/// Reloads `settings` from disk, keeping the settings already loaded when
/// that fails.
async fn reload(settings: Option<&SettingsStore>) {
    if let Some(settings) = settings
        && let Err(e) = settings.load().await
    {
        warn!(error = %e, "Failed to reload the dashboard settings; building the audit sinks from those already loaded");
    }
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

    use crate::integrations::definitions::{Endpoint, EndpointType, EventSet, Integration, Status};

    fn endpoint() -> Endpoint {
        let mut endpoint =
            Endpoint::new("SIEM".to_string(), String::new(), EndpointType::Stream, serde_json::json!({}));
        endpoint.id = "siem-endpoint".to_string();
        endpoint
    }

    /// An integration whose event set holds `events`, audit events named without their
    /// `audit.` prefix.
    fn integration(
        status: Status,
        events: &[&str],
    ) -> (Integration, EventSet) {
        let event_set = EventSet::new(
            "Set".to_string(),
            String::new(),
            events
                .iter()
                .map(|event| match *event {
                    "gateway.created" => event.to_string(),
                    audit => format!("audit.{audit}"),
                })
                .collect(),
        )
        .expect("event set");
        let mut integration = Integration::new(
            "siem".to_string(),
            String::new(),
            endpoint().id,
            event_set.id.clone(),
            serde_json::json!({}),
        );
        integration.status = status;
        (integration, event_set)
    }

    fn routes(definitions: Vec<(Integration, EventSet)>) -> Routes {
        let (integrations, event_sets) = definitions
            .into_iter()
            .unzip();
        Routes::new(integrations, event_sets, vec![endpoint()])
    }

    #[test]
    fn integrations_receiving_audit_records_are_sinks() {
        let (siem, events) = integration(Status::Active, &["gateway.created", "auth_failed"]);
        let sinks = integration_sinks(&routes(vec![(siem.clone(), events)]));
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].id, SinkId::Integration(siem.id));
        assert_eq!(sinks[0].events.categories(), vec!["auth_failed"]);
    }

    #[test]
    fn an_integrations_drop_policy_and_attempt_limit_carry_into_its_sink() {
        let (mut limited, limited_events) = integration(Status::Active, &["auth_failed"]);
        limited.audit_drop_after_secs = Some(3600);
        limited.audit_max_attempts = Some(10);
        let (without, without_events) = integration(Status::Active, &["auth_failed"]);

        let sinks = integration_sinks(&routes(vec![(limited.clone(), limited_events), (without, without_events)]));

        let sink = |id: &str| {
            sinks
                .iter()
                .find(|sink| sink.id == SinkId::Integration(id.to_string()))
                .expect("sink")
        };
        assert_eq!(sink(&limited.id).drop_older_than, Some(std::time::Duration::from_secs(3600)));
        assert_eq!(sink(&limited.id).max_attempts, Some(10));
        assert_eq!(
            sinks
                .iter()
                .filter(|sink| sink.drop_older_than.is_none() && sink.max_attempts.is_none())
                .count(),
            1
        );
    }

    #[test]
    fn integrations_that_do_not_receive_audit_records_are_paused_not_sinks() {
        let (receiving, receiving_events) = integration(Status::Active, &["auth_failed"]);
        let (disabled, disabled_events) = integration(Status::Disabled, &["auth_failed"]);
        let (gateways, gateway_events) = integration(Status::Active, &["gateway.created"]);
        let routes = routes(vec![
            (receiving.clone(), receiving_events),
            (disabled.clone(), disabled_events),
            (gateways.clone(), gateway_events),
        ]);

        let mut paused = paused_integrations(&routes);
        paused.sort_by_key(|sink| format!("{sink:?}"));
        let mut expected = vec![SinkId::Integration(disabled.id), SinkId::Integration(gateways.id)];
        expected.sort_by_key(|sink| format!("{sink:?}"));

        assert_eq!(
            integration_sinks(&routes)
                .iter()
                .map(|sink| sink.id.clone())
                .collect::<Vec<_>>(),
            vec![SinkId::Integration(receiving.id)]
        );
        assert_eq!(paused, expected);
    }

    #[tokio::test]
    async fn a_rebuild_keeps_the_paused_integrations() {
        let serial = Mutex::new(());
        let registry: &'static Sinks = Box::leak(Box::default());
        let (receiving, receiving_events) = integration(Status::Active, &["auth_failed"]);
        let (disabled, disabled_events) = integration(Status::Disabled, &["auth_failed"]);
        let listed = routes(vec![(receiving.clone(), receiving_events), (disabled.clone(), disabled_events)]);

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
        let (siem, events) = integration(Status::Active, &["policy_decision", "trust_check"]);
        let registry = SinkRegistry::new(build_sinks(&settings, &routes(vec![(siem.clone(), events)])));

        let policy = event_bit("policy_decision").unwrap();
        let trust = event_bit("trust_check").unwrap();
        assert_eq!(registry.recipients(policy), &[SinkId::AuditLog, SinkId::Integration(siem.id.clone())]);
        assert_eq!(registry.recipients(trust), &[SinkId::Integration(siem.id.clone())]);
    }

    #[test]
    fn integrations_receive_events_the_audit_log_does_not_keep() {
        let (siem, events) = integration(Status::Active, &["auth_failed"]);
        let registry = SinkRegistry::new(build_sinks(&DashboardSettings::default(), &routes(vec![(siem, events)])));
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
        let listed = routes(vec![integration(Status::Active, &["auth_failed"])]);

        let rebuilt = rebuild(&serial, registry, || selecting("policy_decision"), || async move { Ok(listed) }).await;

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
        registry.replace(build_sinks(&selecting("policy_decision"), &routes(Vec::new())), Vec::new());

        let rebuilt = rebuild(
            &serial,
            registry,
            || selecting("trust_check"),
            || async { Err::<Routes, _>(anyhow::anyhow!("storage unavailable")) },
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
                Ok(routes(Vec::new()))
            },
        );
        let newer = rebuild(&serial, registry, || selecting("trust_check"), || async { Ok(routes(Vec::new())) });
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
        registry.replace(build_sinks(&selecting("policy_decision"), &routes(Vec::new())), Vec::new());

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
        let stores = Arc::new(
            DefinitionStores::open(
                &dir.path().join("endpoints"),
                &dir.path().join("event_sets"),
                &dir.path()
                    .join("integrations"),
            )
            .await
            .unwrap(),
        );
        let (siem, mut events) = integration(Status::Active, &["auth_failed"]);
        stores
            .endpoints
            .save(&endpoint())
            .await
            .unwrap();
        stores
            .event_sets
            .save(&events)
            .await
            .unwrap();
        stores
            .integrations
            .save(&siem)
            .await
            .unwrap();
        let serial = Mutex::new(());
        let registry: &'static Sinks = Box::leak(Box::default());
        assert!(rebuild(&serial, registry, || settings.get(), || list_from(Some(stores.clone()))).await);

        let other_node = SettingsStore::new(&settings_dir);
        other_node
            .update(selecting("policy_decision"))
            .unwrap();
        other_node
            .save()
            .await
            .unwrap();
        events.events = std::collections::HashSet::from(["audit.trust_check".to_string()]);
        stores
            .event_sets
            .save(&events)
            .await
            .unwrap();
        assert!(!settings.get().audit_enabled);

        reload(Some(&settings)).await;
        assert!(rebuild(&serial, registry, || settings.get(), || list_from(Some(stores.clone()))).await);

        let sink = SinkId::Integration(siem.id.clone());
        let snapshot = registry.snapshot();
        assert!(log_selects(registry, "policy_decision"));
        assert_eq!(snapshot.recipients(event_bit("trust_check").unwrap()), std::slice::from_ref(&sink));
        assert!(
            snapshot
                .recipients(event_bit("auth_failed").unwrap())
                .is_empty()
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
