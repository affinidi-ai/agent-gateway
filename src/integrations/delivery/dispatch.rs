//! Sends a catalog event to every active integration whose event set holds it.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde_json::Value as JsonValue;
use tokio::sync::RwLock;
use tokio_retry::RetryIf;
use tokio_retry::strategy::jitter;
use tracing::{error, warn};

use super::render::render;
use super::retry::{is_transient_publish_error, retry_delays};
use super::values::event_values;
use crate::integrations::background_tasks::spawn_background_task;
use crate::integrations::definitions::endpoint::resolve_secret_references;
use crate::integrations::definitions::{DefinitionStores, Endpoint, EventSet, Integration, Status, definition_stores};
use crate::integrations::events::{IntegrationEvent, find_event};
use crate::integrations::publishers::{INTEGRATION_REGISTRY, Message};
use crate::secrets::SecretsStore;
use crate::storage::filesystem::StorableEntity;

/// An integration and the endpoint it delivers to.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub integration: Integration,
    pub endpoint: Endpoint,
}

/// An integration that receives audit records, and the audit events (catalog names without
/// the `audit.` prefix) its event set selects.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditReceiver {
    pub route: Route,
    pub audit_events: Vec<String>,
}

/// A snapshot of the definitions, for routing events without reading them from disk.
pub struct Routes {
    integrations: Vec<Integration>,
    event_sets: HashMap<String, EventSet>,
    endpoints: HashMap<String, Endpoint>,
}

impl Routes {
    pub fn new(
        integrations: Vec<Integration>,
        event_sets: Vec<EventSet>,
        endpoints: Vec<Endpoint>,
    ) -> Self {
        Self {
            integrations,
            event_sets: by_id(event_sets),
            endpoints: by_id(endpoints),
        }
    }

    pub async fn load(stores: &DefinitionStores) -> Result<Self> {
        Ok(Self::new(
            stores
                .integrations
                .list()
                .await?,
            stores
                .event_sets
                .list()
                .await?,
            stores
                .endpoints
                .list()
                .await?,
        ))
    }

    pub fn integration_ids(&self) -> impl Iterator<Item = &str> {
        self.integrations
            .iter()
            .map(|integration| integration.id.as_str())
    }

    /// Each active integration with an active endpoint whose event set holds audit events.
    pub fn audit_receivers(&self) -> Vec<AuditReceiver> {
        self.integrations
            .iter()
            .filter_map(|integration| self.receiver(integration))
            .collect()
    }

    pub fn audit_receiver(
        &self,
        integration_id: &str,
    ) -> Option<AuditReceiver> {
        self.integrations
            .iter()
            .find(|integration| integration.id == integration_id)
            .and_then(|integration| self.receiver(integration))
    }

    fn receiver(
        &self,
        integration: &Integration,
    ) -> Option<AuditReceiver> {
        let audit_events: Vec<String> = self
            .event_sets
            .get(&integration.event_set_id)?
            .events
            .iter()
            .filter_map(|event| event.strip_prefix("audit."))
            .map(str::to_string)
            .collect();
        if audit_events.is_empty() {
            return None;
        }
        Some(AuditReceiver {
            route: self.active_route(integration)?,
            audit_events,
        })
    }

    /// `integration` and its endpoint, when both are active.
    fn active_route(
        &self,
        integration: &Integration,
    ) -> Option<Route> {
        if integration.status != Status::Active {
            return None;
        }
        let endpoint = self
            .endpoints
            .get(&integration.endpoint_id)
            .filter(|endpoint| endpoint.status == Status::Active)?;
        Some(Route {
            integration: integration.clone(),
            endpoint: endpoint.clone(),
        })
    }

    /// The active integrations whose event set holds `event_id`, with their active endpoint.
    pub fn for_event(
        &self,
        event_id: &str,
    ) -> Vec<Route> {
        self.integrations
            .iter()
            .filter(|integration| {
                self.event_sets
                    .get(&integration.event_set_id)
                    .is_some_and(|event_set| event_set.contains(event_id))
            })
            .filter_map(|integration| self.active_route(integration))
            .collect()
    }
}

fn by_id<T: StorableEntity>(definitions: Vec<T>) -> HashMap<String, T> {
    definitions
        .into_iter()
        .map(|definition| (definition.id().to_string(), definition))
        .collect()
}

/// The routes, reloaded once they are older than the cache's lifetime or after a change.
pub struct RoutesCache {
    lifetime: Duration,
    cached: RwLock<Option<(Instant, Arc<Routes>)>>,
}

impl RoutesCache {
    pub fn new(lifetime: Duration) -> Self {
        Self {
            lifetime,
            cached: RwLock::new(None),
        }
    }

    pub async fn get(
        &self,
        stores: &DefinitionStores,
    ) -> Result<Arc<Routes>> {
        if let Some((loaded_at, routes)) = self
            .cached
            .read()
            .await
            .as_ref()
            && loaded_at.elapsed() < self.lifetime
        {
            return Ok(routes.clone());
        }
        let routes = Arc::new(Routes::load(stores).await?);
        *self.cached.write().await = Some((Instant::now(), routes.clone()));
        Ok(routes)
    }

    pub async fn invalidate(&self) {
        *self.cached.write().await = None;
    }
}

/// Definitions written outside the API, such as on a node that just became Active, are picked
/// up within this time.
const ROUTES_LIFETIME: Duration = Duration::from_secs(5);

static ROUTES: Lazy<RoutesCache> = Lazy::new(|| RoutesCache::new(ROUTES_LIFETIME));

/// The definitions as delivery sees them now: the cached snapshot of the shared stores.
pub async fn current_routes() -> Result<Arc<Routes>> {
    let stores = definition_stores().context("integration storage is not set up yet")?;
    ROUTES.get(&stores).await
}

/// Makes the next event read the definitions again, after the API changed one.
pub async fn invalidate_routes() {
    ROUTES.invalidate().await;
}

/// The catalog event `event_id` when this dispatcher delivers it. Audit events reach their
/// integrations through the audit journal instead.
fn dispatched_event(event_id: &str) -> Option<&'static IntegrationEvent> {
    find_event(event_id).filter(|event| event.family != "audit")
}

/// The configuration to send with, its secret references resolved, and the rendered message.
pub async fn prepare(
    route: &Route,
    values: &HashMap<String, String>,
    secrets: Option<&dyn SecretsStore>,
) -> Result<(JsonValue, Message)> {
    let publisher = INTEGRATION_REGISTRY
        .get(
            route
                .endpoint
                .endpoint_type
                .as_str(),
        )
        .context("No publisher for the endpoint type")?;
    let template = publisher.complete_template(&route.integration.content);
    let content = render(&template, values, publisher.escaping(&template));
    let configuration = resolve_secret_references(route.endpoint.endpoint_type, &route.endpoint.configuration, secrets)
        .await
        .map_err(|reason| anyhow::anyhow!(reason))?;
    Ok((
        configuration,
        Message {
            integration_id: route.integration.id.clone(),
            integration_name: route.integration.name.clone(),
            endpoint_id: route.endpoint.id.clone(),
            content,
        },
    ))
}

/// Sends `route` its message for `values` once, as a test message is.
pub async fn send_once(
    route: &Route,
    values: &HashMap<String, String>,
) -> Result<()> {
    let secrets = crate::gateways::connection_points::message_processor::get_secrets_store();
    let (configuration, message) = prepare(route, values, secrets.as_deref()).await?;
    INTEGRATION_REGISTRY
        .get(
            route
                .endpoint
                .endpoint_type
                .as_str(),
        )
        .context("No publisher for the endpoint type")?
        .send(&configuration, &message)
        .await
}

/// Sends `route` its message for `values`, retrying transient failures.
pub async fn deliver(
    route: &Route,
    values: &HashMap<String, String>,
) -> Result<()> {
    let secrets = crate::gateways::connection_points::message_processor::get_secrets_store();
    let (configuration, message) = prepare(route, values, secrets.as_deref()).await?;
    let publisher = INTEGRATION_REGISTRY
        .get(
            route
                .endpoint
                .endpoint_type
                .as_str(),
        )
        .context("No publisher for the endpoint type")?;
    RetryIf::start(
        retry_delays().map(jitter),
        || publisher.send(&configuration, &message),
        |error: &anyhow::Error| {
            let transient = is_transient_publish_error(error);
            if transient {
                warn!(integration_id = %message.integration_id, error = %error, "Retrying integration delivery");
            }
            transient
        },
    )
    .await
}

/// Delivers `event_id` with its trigger's values to every integration whose event set holds it,
/// in the background so the operation that raised it never waits or fails.
pub fn dispatch(
    event_id: &str,
    trigger: HashMap<String, String>,
) {
    let Some(event) = dispatched_event(event_id) else {
        warn!(event_id, "Not dispatching an event outside the integration catalog");
        return;
    };
    let values = Arc::new(event_values(event, trigger, crate::storage::settings_store::global_appliance_id_override()));
    spawn_background_task(event_id, async move {
        let routes = match current_routes().await {
            Ok(routes) => routes,
            Err(error) => {
                error!(event_id = %event.id, error = %error, "Failed to load integrations");
                return;
            }
        };
        deliver_each(&event.id, routes.for_event(&event.id), values, |route, values| async move {
            deliver(&route, &values).await
        });
    });
}

/// Delivers each route in a background task of its own, so a slow or failing endpoint never
/// holds up the other integrations of the event, and the task limit counts deliveries.
fn deliver_each<D, F>(
    event_id: &str,
    routes: Vec<Route>,
    values: Arc<HashMap<String, String>>,
    deliver: D,
) where
    D: Fn(Route, Arc<HashMap<String, String>>) -> F,
    F: Future<Output = Result<()>> + Send + 'static,
{
    for route in routes {
        let event_id = event_id.to_string();
        let integration_id = route.integration.id.clone();
        let delivery = deliver(route, values.clone());
        spawn_background_task(&format!("{event_id} to {integration_id}"), async move {
            if let Err(error) = delivery.await {
                error!(
                    event_id = %event_id,
                    integration_id = %integration_id,
                    error = %error,
                    "Integration delivery failed"
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::definitions::EndpointType;
    use serde_json::json;

    struct Seeded {
        stores: DefinitionStores,
        endpoint: Endpoint,
        gateway_events: EventSet,
        _dir: tempfile::TempDir,
    }

    async fn seeded() -> Seeded {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = DefinitionStores::open(
            &dir.path().join("endpoints"),
            &dir.path().join("event_sets"),
            &dir.path()
                .join("integrations"),
        )
        .await
        .expect("stores");
        let endpoint = Endpoint::new(
            "Ops Slack".to_string(),
            String::new(),
            EndpointType::Slack,
            json!({"webhook_url": "https://hooks.slack.com/services/T/B/x"}),
        );
        let gateway_events = EventSet::new(
            "Gateways".to_string(),
            String::new(),
            vec!["gateway.created".to_string(), "gateway.deleted".to_string()],
        )
        .expect("set");
        stores
            .endpoints
            .save(&endpoint)
            .await
            .expect("save endpoint");
        stores
            .event_sets
            .save(&gateway_events)
            .await
            .expect("save set");
        Seeded {
            stores,
            endpoint,
            gateway_events,
            _dir: dir,
        }
    }

    async fn integration(
        s: &Seeded,
        name: &str,
        endpoint_id: &str,
        event_set_id: &str,
        status: Status,
    ) -> Integration {
        let mut integration = Integration::new(
            name.to_string(),
            String::new(),
            endpoint_id.to_string(),
            event_set_id.to_string(),
            json!({}),
        );
        integration.status = status;
        s.stores
            .integrations
            .save(&integration)
            .await
            .expect("save integration");
        integration
    }

    fn names(routes: &[Route]) -> Vec<&str> {
        let mut names: Vec<&str> = routes
            .iter()
            .map(|route| {
                route
                    .integration
                    .name
                    .as_str()
            })
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn an_event_reaches_active_integrations_whose_event_set_holds_it() {
        let s = seeded().await;
        let missing = uuid::Uuid::new_v4().to_string();
        integration(&s, "delivers", &s.endpoint.id, &s.gateway_events.id, Status::Active).await;
        integration(&s, "disabled", &s.endpoint.id, &s.gateway_events.id, Status::Disabled).await;
        integration(&s, "no endpoint", &missing, &s.gateway_events.id, Status::Active).await;
        integration(&s, "no event set", &s.endpoint.id, &missing, Status::Active).await;

        let routes = Routes::load(&s.stores)
            .await
            .expect("routes");

        assert_eq!(names(&routes.for_event("gateway.created")), ["delivers"]);
        assert!(
            routes
                .for_event("user.login")
                .is_empty()
        );
        let route = &routes.for_event("gateway.deleted")[0];
        assert_eq!(route.endpoint, s.endpoint);
    }

    #[tokio::test]
    async fn a_disabled_endpoint_receives_nothing() {
        let s = seeded().await;
        let mut disabled = s.endpoint.clone();
        disabled.status = Status::Disabled;
        s.stores
            .endpoints
            .save(&disabled)
            .await
            .expect("save endpoint");
        integration(&s, "delivers", &s.endpoint.id, &s.gateway_events.id, Status::Active).await;

        let routes = Routes::load(&s.stores)
            .await
            .expect("routes");

        assert!(
            routes
                .for_event("gateway.created")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_cache_keeps_its_snapshot_until_invalidated() {
        let s = seeded().await;
        let cache = RoutesCache::new(Duration::from_secs(3600));
        integration(&s, "first", &s.endpoint.id, &s.gateway_events.id, Status::Active).await;
        assert_eq!(
            names(
                &cache
                    .get(&s.stores)
                    .await
                    .expect("routes")
                    .for_event("gateway.created")
            ),
            ["first"]
        );

        integration(&s, "second", &s.endpoint.id, &s.gateway_events.id, Status::Active).await;
        let cached = cache
            .get(&s.stores)
            .await
            .expect("routes");
        cache.invalidate().await;
        let reloaded = cache
            .get(&s.stores)
            .await
            .expect("routes");

        assert_eq!(names(&cached.for_event("gateway.created")), ["first"]);
        assert_eq!(names(&reloaded.for_event("gateway.created")), ["first", "second"]);
    }

    #[tokio::test]
    async fn an_expired_snapshot_is_reloaded() {
        let s = seeded().await;
        let cache = RoutesCache::new(Duration::ZERO);
        cache
            .get(&s.stores)
            .await
            .expect("routes");
        integration(&s, "later", &s.endpoint.id, &s.gateway_events.id, Status::Active).await;

        let routes = cache
            .get(&s.stores)
            .await
            .expect("routes");

        assert_eq!(names(&routes.for_event("gateway.created")), ["later"]);
    }

    #[test]
    fn only_non_audit_catalog_events_are_dispatched() {
        assert_eq!(dispatched_event("gateway.created").map(|event| event.id.as_str()), Some("gateway.created"));
        assert!(dispatched_event("audit.policy_decision").is_none());
        assert!(dispatched_event("identity.created").is_none());
    }

    #[tokio::test]
    async fn a_message_is_the_completed_template_rendered_for_the_transport() {
        let s = seeded().await;
        let mut slack = integration(&s, "alerts", &s.endpoint.id, &s.gateway_events.id, Status::Active).await;
        slack.content = json!({"text": "${GATEWAY_NAME} by ${EVENT_SUMMARY}"});
        let route = Route {
            integration: slack.clone(),
            endpoint: s.endpoint.clone(),
        };
        let values = HashMap::from([
            ("GATEWAY_NAME".to_string(), "<!channel>".to_string()),
            ("EVENT_SUMMARY".to_string(), "Gateway created".to_string()),
        ]);

        let (configuration, message) = prepare(&route, &values, None)
            .await
            .expect("prepares");

        assert_eq!(configuration, s.endpoint.configuration);
        assert_eq!(
            message,
            Message {
                integration_id: slack.id,
                integration_name: "alerts".to_string(),
                endpoint_id: s.endpoint.id.clone(),
                content: json!({"text": "&lt;!channel&gt; by Gateway created"}),
            }
        );
    }

    #[tokio::test]
    async fn an_empty_template_sends_the_transport_default() {
        let s = seeded().await;
        let route = Route {
            integration: integration(&s, "alerts", &s.endpoint.id, &s.gateway_events.id, Status::Active).await,
            endpoint: s.endpoint.clone(),
        };
        let values = HashMap::from([
            ("EVENT_NAME".to_string(), "Gateway Created".to_string()),
            ("EVENT_SUMMARY".to_string(), "Gateway edge was created".to_string()),
        ]);

        let (_, message) = prepare(&route, &values, None)
            .await
            .expect("prepares");

        assert_eq!(message.content, json!({"text": "*Gateway Created*\nGateway edge was created"}));
    }

    #[tokio::test]
    async fn an_unresolvable_secret_reference_fails_the_delivery() {
        let s = seeded().await;
        let mut endpoint = s.endpoint.clone();
        endpoint.configuration = json!({"webhook_url": "$SECRET:slack-hook"});
        let route = Route {
            integration: integration(&s, "alerts", &endpoint.id, &s.gateway_events.id, Status::Active).await,
            endpoint,
        };

        let error = prepare(&route, &HashMap::new(), None)
            .await
            .expect_err("fails");

        assert!(
            error
                .to_string()
                .contains("slack-hook"),
            "{error}"
        );
    }

    fn integration_for(
        name: &str,
        endpoint: &Endpoint,
        event_set: &EventSet,
    ) -> Integration {
        Integration::new(name.to_string(), String::new(), endpoint.id.clone(), event_set.id.clone(), json!({}))
    }

    fn set(events: &[&str]) -> EventSet {
        EventSet::new(
            "Set".to_string(),
            String::new(),
            events
                .iter()
                .map(|event| event.to_string())
                .collect(),
        )
        .expect("set")
    }

    #[tokio::test]
    async fn each_route_of_an_event_is_delivered_without_waiting_for_the_others() {
        let endpoint = Endpoint::new("Ops".to_string(), String::new(), EndpointType::Stream, json!({}));
        let gateways = set(&["gateway.created"]);
        // The slow route comes first and the failing one before the last, so delivering them
        // one after another would hold the others up.
        let routes: Vec<Route> = ["slow", "failing", "fast"]
            .iter()
            .map(|name| Route {
                integration: integration_for(name, &endpoint, &gateways),
                endpoint: endpoint.clone(),
            })
            .collect();
        let release = Arc::new(tokio::sync::Notify::new());
        let (delivered, mut deliveries) = tokio::sync::mpsc::unbounded_channel::<String>();

        deliver_each("gateway.created", routes, Arc::new(HashMap::new()), {
            let release = release.clone();
            move |route: Route, _values| {
                let release = release.clone();
                let delivered = delivered.clone();
                async move {
                    match route
                        .integration
                        .name
                        .as_str()
                    {
                        "slow" => release.notified().await,
                        "failing" => anyhow::bail!("endpoint refused"),
                        _ => {}
                    }
                    delivered
                        .send(route.integration.name)
                        .expect("receiver");
                    Ok(())
                }
            }
        });

        let wait = Duration::from_secs(5);
        let first = tokio::time::timeout(wait, deliveries.recv())
            .await
            .expect("the fast route is not held up by the slow or the failing one");
        assert_eq!(first.as_deref(), Some("fast"));
        release.notify_one();
        let second = tokio::time::timeout(wait, deliveries.recv())
            .await
            .expect("the slow route still completes");
        assert_eq!(second.as_deref(), Some("slow"));
    }

    #[test]
    fn integrations_whose_event_set_holds_audit_events_receive_audit_records() {
        let endpoint = Endpoint::new("SIEM".to_string(), String::new(), EndpointType::Stream, json!({}));
        let mut disabled_endpoint = endpoint.clone();
        disabled_endpoint.id = "disabled-endpoint".to_string();
        disabled_endpoint.status = Status::Disabled;
        let mixed = set(&["gateway.created", "audit.policy_decision", "audit.trust_check"]);
        let gateways = set(&["gateway.created"]);
        let siem = integration_for("siem", &endpoint, &mixed);
        let mut disabled = integration_for("disabled", &endpoint, &mixed);
        disabled.status = Status::Disabled;
        let no_audit = integration_for("no audit", &endpoint, &gateways);
        let endpoint_off = integration_for("endpoint off", &disabled_endpoint, &mixed);
        let routes = Routes::new(
            vec![siem.clone(), disabled.clone(), no_audit, endpoint_off],
            vec![mixed, gateways],
            vec![endpoint.clone(), disabled_endpoint],
        );

        let receivers = routes.audit_receivers();

        assert_eq!(
            receivers,
            vec![AuditReceiver {
                route: Route {
                    integration: siem.clone(),
                    endpoint,
                },
                audit_events: vec!["policy_decision".to_string(), "trust_check".to_string()],
            }]
        );
        assert_eq!(routes.audit_receiver(&siem.id), Some(receivers[0].clone()));
        assert_eq!(routes.audit_receiver(&disabled.id), None);
        assert_eq!(
            routes
                .integration_ids()
                .count(),
            4
        );
    }
}
