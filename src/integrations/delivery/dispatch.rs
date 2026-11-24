//! Sends a catalog event to every active integration whose event set holds it.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde_json::Value as JsonValue;
use tokio::sync::RwLock;
use tokio_retry::RetryIf;
use tokio_retry::strategy::jitter;
use tracing::{error, warn};

use super::render::render;
use super::retry::{is_transient_publish_error, retry_delays};
use super::values::{Occurrence, delivered_form, event_values};
use crate::integrations::background_tasks::{TaskShare, spawn_background_task, spawn_background_task_in};
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
    pub audit_events: HashSet<String>,
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
        let audit_events: HashSet<String> = self
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
    let mut content = render(&template, values, publisher.escaping(&template), publisher.embeds_json());
    if publisher.embeds_json() {
        content = delivered_form(content, values);
    }
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
    send_with_retries(&message, |message| publisher.send(&configuration, message)).await
}

/// Sends the one rendered `message`, and the same message again on each retry of a transient
/// failure.
async fn send_with_retries<'m, S, F>(
    message: &'m Message,
    send: S,
) -> Result<()>
where
    S: Fn(&'m Message) -> F,
    F: Future<Output = Result<()>> + 'm,
{
    RetryIf::start(
        retry_delays().map(jitter),
        || send(message),
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
/// in the background so the operation that raised it never waits or fails. The event happens
/// now.
pub fn dispatch(
    event_id: &str,
    trigger: HashMap<String, String>,
) {
    dispatch_in(None, event_id, None, trigger);
}

/// Like [`dispatch`], for an event that happened at `occurred_at`.
pub fn dispatch_at(
    event_id: &str,
    occurred_at: DateTime<Utc>,
    trigger: HashMap<String, String>,
) {
    dispatch_in(None, event_id, Some(occurred_at), trigger);
}

/// Like [`dispatch`], but the event's background tasks, its routing and each of its deliveries,
/// hold a permit of `share`, so a burst of the event cannot take the task limit from others.
pub fn dispatch_within(
    share: &'static TaskShare,
    event_id: &str,
    trigger: HashMap<String, String>,
) {
    dispatch_in(Some(share), event_id, None, trigger);
}

fn spawn_task<F>(
    share: Option<&'static TaskShare>,
    name: &str,
    task: F,
) where
    F: Future<Output = ()> + Send + 'static,
{
    match share {
        Some(share) => spawn_background_task_in(share, name, task),
        None => spawn_background_task(name, task),
    }
}

/// Creates the event, at `occurred_at` or now, and delivers it.
fn dispatch_in(
    share: Option<&'static TaskShare>,
    event_id: &str,
    occurred_at: Option<DateTime<Utc>>,
    trigger: HashMap<String, String>,
) {
    let Some(event) = dispatched_event(event_id) else {
        warn!(event_id, "Not dispatching an event outside the integration catalog");
        return;
    };
    let occurrence = Occurrence::at(occurred_at.unwrap_or_else(Utc::now));
    let values = Arc::new(event_values(
        event,
        &occurrence,
        trigger,
        crate::storage::settings_store::global_appliance_id_override(),
    ));
    #[cfg(test)]
    dispatched::record(&event.id, &values);
    spawn_task(share, event_id, async move {
        let routes = match current_routes().await {
            Ok(routes) => routes,
            Err(error) => {
                error!(event_id = %event.id, error = %error, "Failed to load integrations");
                return;
            }
        };
        deliver_each(share, &event.id, routes.for_event(&event.id), values, |route, values| async move {
            deliver(&route, &values).await
        });
    });
}

/// Every event dispatched in this test process, so a test can tell which events an operation
/// raised without integrations or endpoints.
#[cfg(test)]
pub mod dispatched {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static EVENTS: Mutex<Vec<(String, HashMap<String, String>)>> = Mutex::new(Vec::new());

    pub(super) fn record(
        event_id: &str,
        values: &HashMap<String, String>,
    ) {
        EVENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((event_id.to_string(), values.clone()));
    }

    /// The ids of the dispatched events whose `variable` was `value`, in dispatch order.
    pub fn with(
        variable: &str,
        value: &str,
    ) -> Vec<String> {
        EVENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|(_, values)| {
                values
                    .get(variable)
                    .map(String::as_str)
                    == Some(value)
            })
            .map(|(event_id, _)| event_id.clone())
            .collect()
    }

    /// The values of the dispatched `event_id` events whose `variable` was `value`, in dispatch
    /// order.
    pub fn values_of(
        event_id: &str,
        variable: &str,
        value: &str,
    ) -> Vec<HashMap<String, String>> {
        EVENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|(id, values)| {
                id == event_id
                    && values
                        .get(variable)
                        .map(String::as_str)
                        == Some(value)
            })
            .map(|(_, values)| values.clone())
            .collect()
    }
}

/// Delivers each route in a background task of its own, so a slow or failing endpoint never
/// holds up the other integrations of the event, and the task limit counts deliveries.
fn deliver_each<D, F>(
    share: Option<&'static TaskShare>,
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
        spawn_task(share, &format!("{event_id} to {integration_id}"), async move {
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

    const EVENT_DATA: &str = r#"{"gateway_name":"<b>edge</b>","old_state":null}"#;

    async fn sole_event_data_field(
        endpoint_type: EndpointType,
        content: JsonValue,
    ) -> JsonValue {
        let s = seeded().await;
        let mut endpoint = s.endpoint.clone();
        endpoint.endpoint_type = endpoint_type;
        endpoint.configuration = json!({});
        let mut integration = integration_for("data", &endpoint, &s.gateway_events);
        integration.content = content;
        let values = HashMap::from([("EVENT_DATA".to_string(), EVENT_DATA.to_string())]);

        prepare(&Route { integration, endpoint }, &values, None)
            .await
            .expect("prepares")
            .1
            .content
    }

    #[tokio::test]
    async fn slack_sends_a_sole_event_data_field_as_escaped_text() {
        let content = sole_event_data_field(EndpointType::Slack, json!({"text": "${EVENT_DATA}"})).await;

        assert_eq!(content, json!({"text": r#"{"gateway_name":"&lt;b&gt;edge&lt;/b&gt;","old_state":null}"#}));
    }

    #[tokio::test]
    async fn email_sends_a_sole_event_data_body_as_text() {
        let plain = sole_event_data_field(EndpointType::Email, json!({"body": "${EVENT_DATA}"})).await;
        let html = sole_event_data_field(EndpointType::Email, json!({"body": "${EVENT_DATA}", "format": "html"})).await;

        assert_eq!(plain["body"], json!(EVENT_DATA));
        assert_eq!(
            html["body"],
            json!(r#"{&quot;gateway_name&quot;:&quot;&lt;b&gt;edge&lt;/b&gt;&quot;,&quot;old_state&quot;:null}"#)
        );
    }

    #[tokio::test]
    async fn webhook_and_stream_still_embed_a_sole_event_data_field_as_json() {
        let embedded = json!({"data": {"gateway_name": "<b>edge</b>", "old_state": null}});

        assert_eq!(sole_event_data_field(EndpointType::Webhook, json!({"data": "${EVENT_DATA}"})).await, embedded);
        assert_eq!(sole_event_data_field(EndpointType::Stream, json!({"data": "${EVENT_DATA}"})).await, embedded);
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

        deliver_each(None, "gateway.created", routes, Arc::new(HashMap::new()), {
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

    #[tokio::test]
    async fn a_delivery_beyond_the_events_share_is_not_made() {
        static SHARE: Lazy<TaskShare> = Lazy::new(|| TaskShare::new("one delivery", 1));
        let endpoint = Endpoint::new("Ops".to_string(), String::new(), EndpointType::Stream, json!({}));
        let gateways = set(&["gateway.created"]);
        let routes: Vec<Route> = ["slow", "beyond the share"]
            .iter()
            .map(|name| Route {
                integration: integration_for(name, &endpoint, &gateways),
                endpoint: endpoint.clone(),
            })
            .collect();
        let release = Arc::new(tokio::sync::Notify::new());
        let (delivered, mut deliveries) = tokio::sync::mpsc::unbounded_channel::<String>();
        let _open = delivered.clone();

        deliver_each(Some(&SHARE), "gateway.created", routes, Arc::new(HashMap::new()), {
            let release = release.clone();
            move |route: Route, _values| {
                let release = release.clone();
                let delivered = delivered.clone();
                async move {
                    if route.integration.name == "slow" {
                        release.notified().await;
                    }
                    delivered
                        .send(route.integration.name)
                        .expect("receiver");
                    Ok(())
                }
            }
        });
        release.notify_one();

        let first = tokio::time::timeout(Duration::from_secs(5), deliveries.recv())
            .await
            .expect("the delivery within the share is made");
        assert_eq!(first.as_deref(), Some("slow"));
        let more = tokio::time::timeout(Duration::from_millis(200), deliveries.recv()).await;
        assert!(more.is_err(), "a delivery beyond the share ran: {more:?}");
    }

    const OCCURRED_AT: &str = "2026-11-24T10:00:00+00:00";

    fn created_gateway_values(occurrence: &Occurrence) -> Arc<HashMap<String, String>> {
        let event = find_event("gateway.created").expect("catalog event");
        Arc::new(event_values(
            event,
            occurrence,
            HashMap::from([("GATEWAY_NAME".to_string(), "edge".to_string())]),
            None,
        ))
    }

    #[tokio::test]
    async fn each_dispatch_of_an_event_is_a_new_event_with_its_own_id() {
        let marker = uuid::Uuid::new_v4().to_string();
        for _ in 0..2 {
            dispatch("gateway.created", HashMap::from([("GATEWAY_ID".to_string(), marker.clone())]));
        }

        let ids: Vec<Option<String>> = dispatched::values_of("gateway.created", "GATEWAY_ID", &marker)
            .iter()
            .map(|values| {
                values
                    .get("EVENT_ID")
                    .cloned()
            })
            .collect();

        assert_eq!(ids.len(), 2, "{ids:?}");
        assert!(
            ids.iter()
                .all(Option::is_some)
                && ids[0] != ids[1],
            "two dispatches, two event ids: {ids:?}"
        );
    }

    #[tokio::test]
    async fn every_route_of_a_dispatch_receives_the_same_event_id_and_time() {
        let endpoint = Endpoint::new("Ops".to_string(), String::new(), EndpointType::Stream, json!({}));
        let gateways = set(&["gateway.created"]);
        let routes: Vec<Route> = ["first", "second", "third"]
            .iter()
            .map(|name| Route {
                integration: integration_for(name, &endpoint, &gateways),
                endpoint: endpoint.clone(),
            })
            .collect();
        let values = created_gateway_values(&Occurrence::recorded(Some("evt-7".to_string()), OCCURRED_AT.to_string()));
        let (delivered, mut deliveries) = tokio::sync::mpsc::unbounded_channel();

        deliver_each(None, "gateway.created", routes, values, move |_route: Route, values| {
            let delivered = delivered.clone();
            async move {
                delivered
                    .send((
                        values
                            .get("EVENT_ID")
                            .cloned(),
                        values
                            .get("OCCURRED_AT")
                            .cloned(),
                    ))
                    .expect("receiver");
                Ok(())
            }
        });

        let mut received = Vec::new();
        for _ in 0..3 {
            received.push(
                tokio::time::timeout(Duration::from_secs(5), deliveries.recv())
                    .await
                    .expect("each route is delivered")
                    .expect("a delivery"),
            );
        }
        assert_eq!(received, vec![(Some("evt-7".to_string()), Some(OCCURRED_AT.to_string())); 3]);
    }

    fn evt_7() -> Occurrence {
        Occurrence::recorded(Some("evt-7".to_string()), OCCURRED_AT.to_string())
    }

    /// The content `prepare` gives a `gateway.created` event of `occurrence` through an
    /// endpoint of `endpoint_type` with `template`.
    async fn delivered(
        endpoint_type: EndpointType,
        template: JsonValue,
        occurrence: &Occurrence,
    ) -> JsonValue {
        delivered_with(endpoint_type, template, &created_gateway_values(occurrence)).await
    }

    /// The content `prepare` gives `values` through an endpoint of `endpoint_type` with
    /// `template`.
    async fn delivered_with(
        endpoint_type: EndpointType,
        template: JsonValue,
        values: &HashMap<String, String>,
    ) -> JsonValue {
        let endpoint = Endpoint::new("Ops".to_string(), String::new(), endpoint_type, json!({}));
        let mut integration = integration_for("ops", &endpoint, &set(&["gateway.created"]));
        integration.content = template;
        prepare(&Route { integration, endpoint }, values, None)
            .await
            .expect("prepares")
            .1
            .content
    }

    const JSON_ENDPOINTS: [EndpointType; 2] = [EndpointType::Webhook, EndpointType::Stream];

    #[tokio::test]
    async fn the_default_envelope_carries_the_events_id_and_occurrence_time_and_no_timestamp() {
        for endpoint_type in JSON_ENDPOINTS {
            let content = delivered(endpoint_type, json!({}), &evt_7()).await;

            assert_eq!(
                content,
                json!({
                    "event_type": "gateway.created",
                    "event_name": "Gateway Created",
                    "event_id": "evt-7",
                    "occurred_at": OCCURRED_AT,
                    "appliance_id": "",
                    "summary": "Gateway edge was created",
                    "data": {"gateway_name": "edge"}
                }),
                "{endpoint_type:?}"
            );
            let keys: Vec<&String> = content
                .as_object()
                .expect("an object")
                .keys()
                .collect();
            assert_eq!(
                keys,
                ["event_type", "event_name", "event_id", "occurred_at", "appliance_id", "summary", "data"],
                "{endpoint_type:?}"
            );
        }
    }

    #[tokio::test]
    async fn agent_watchs_saved_template_is_delivered_with_its_event_id_and_occurrence_time_and_no_timestamp() {
        let saved = json!({
            "event_type": "${EVENT_TYPE}",
            "timestamp": "${TIMESTAMP}",
            "appliance_id": "${APPLIANCE_ID}",
            "record": "${EVENT_DATA}"
        });
        for endpoint_type in JSON_ENDPOINTS {
            assert_eq!(
                delivered(endpoint_type, saved.clone(), &evt_7()).await,
                json!({
                    "event_type": "gateway.created",
                    "appliance_id": "",
                    "record": {"gateway_name": "edge"},
                    "event_id": "evt-7",
                    "occurred_at": OCCURRED_AT
                }),
                "{endpoint_type:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_delivered_audit_records_event_id_and_occurrence_time_are_the_deliverys_and_it_has_no_timestamp() {
        use crate::delegation_vault::audit::{DelegationAuditAction, audit_event};
        use crate::integrations::audit_integration_triggers::AuditDelivery;
        let record = audit_event(DelegationAuditAction::ConsentGranted, None, None, Some("cp-1"), Some("surface-1"));
        let values = AuditDelivery::from_event(&record)
            .values()
            .clone();
        let templates = [
            ("data", json!({})),
            (
                "record",
                json!({"event_type": "${EVENT_TYPE}", "appliance_id": "${APPLIANCE_ID}", "record": "${EVENT_DATA}"}),
            ),
            ("audit_record", json!({"audit_record": "${AUDIT_RECORD}"})),
        ];
        for endpoint_type in JSON_ENDPOINTS {
            for (key, template) in &templates {
                let content = delivered_with(endpoint_type, template.clone(), &values).await;

                let embedded = &content[key];
                assert_eq!(
                    (&embedded["event_id"], &embedded["occurred_at"], embedded.get("timestamp")),
                    (&content["event_id"], &content["occurred_at"], None),
                    "{endpoint_type:?} {key}: {content}"
                );
                assert_eq!(
                    (&content["event_id"], &content["occurred_at"]),
                    (&json!(record.event_id), &json!(record.occurred_at)),
                    "{endpoint_type:?} {key}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_template_cannot_write_the_top_level_event_id_or_occurrence_time() {
        let forging = json!({
            "event_id": "forged",
            "occurred_at": "${EVENT_DATA}",
            "${EVENT_ID}": "${OCCURRED_AT}",
            "note": "${EVENT_SUMMARY}"
        });
        for endpoint_type in JSON_ENDPOINTS {
            assert_eq!(
                delivered(endpoint_type, forging.clone(), &evt_7()).await,
                json!({
                    "event_id": "evt-7",
                    "occurred_at": OCCURRED_AT,
                    "${EVENT_ID}": OCCURRED_AT,
                    "note": "Gateway edge was created"
                }),
                "{endpoint_type:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_nested_timestamp_is_left_alone_and_renders_the_occurrence_time() {
        let nested = json!({"meta": {"timestamp": "${TIMESTAMP}", "event_id": "theirs"}});
        for endpoint_type in JSON_ENDPOINTS {
            assert_eq!(
                delivered(endpoint_type, nested.clone(), &evt_7()).await,
                json!({
                    "meta": {"timestamp": OCCURRED_AT, "event_id": "theirs"},
                    "event_id": "evt-7",
                    "occurred_at": OCCURRED_AT
                }),
                "{endpoint_type:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_event_without_an_id_is_delivered_without_an_event_id() {
        let without_id = Occurrence::recorded(None, OCCURRED_AT.to_string());
        for endpoint_type in JSON_ENDPOINTS {
            assert_eq!(
                delivered(endpoint_type, json!({"event_id": "forged", "type": "${EVENT_TYPE}"}), &without_id).await,
                json!({"type": "gateway.created", "occurred_at": OCCURRED_AT}),
                "{endpoint_type:?}"
            );
        }
    }

    #[tokio::test]
    async fn slack_and_email_messages_are_sent_as_rendered() {
        let slack = json!({"text": "${EVENT_SUMMARY}", "timestamp": "${TIMESTAMP}"});
        let email = json!({"subject": "${EVENT_NAME}", "body": "at ${TIMESTAMP}"});

        assert_eq!(
            delivered(EndpointType::Slack, slack, &evt_7()).await,
            json!({"text": "Gateway edge was created", "timestamp": OCCURRED_AT})
        );
        assert_eq!(
            delivered(EndpointType::Email, email, &evt_7()).await,
            json!({"subject": "Gateway Created", "body": format!("at {OCCURRED_AT}"), "format": "plain"})
        );
    }

    #[tokio::test(start_paused = true)]
    async fn every_retry_sends_the_message_rendered_once_with_its_event_id_and_time() {
        let endpoint = Endpoint::new("Ops".to_string(), String::new(), EndpointType::Stream, json!({}));
        let mut integration = integration_for("ops", &endpoint, &set(&["gateway.created"]));
        integration.content = json!({"id": "${EVENT_ID}", "at": "${OCCURRED_AT}"});
        let values = created_gateway_values(&Occurrence::recorded(Some("evt-7".to_string()), OCCURRED_AT.to_string()));
        let (_, message) = prepare(&Route { integration, endpoint }, &values, None)
            .await
            .expect("prepares");
        let sent = std::sync::Mutex::new(Vec::new());

        send_with_retries(&message, |message: &Message| {
            let mut sent = sent.lock().expect("sent");
            sent.push(message.content.clone());
            let attempt = sent.len();
            async move {
                if attempt < 3 {
                    anyhow::bail!("Webhook failed: 503 Service Unavailable - down")
                }
                Ok(())
            }
        })
        .await
        .expect("the third attempt is accepted");

        let sent = sent
            .into_inner()
            .expect("sent");
        assert_eq!(
            sent,
            vec![json!({"id": "evt-7", "at": OCCURRED_AT, "event_id": "evt-7", "occurred_at": OCCURRED_AT}); 3]
        );
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
                audit_events: HashSet::from(["policy_decision".to_string(), "trust_check".to_string()]),
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
