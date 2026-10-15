//! Sends a catalog event to every active integration whose event set holds it.

use std::collections::HashMap;
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

/// A snapshot of the definitions, for routing events without reading them from disk.
pub struct Routes {
    integrations: Vec<Integration>,
    event_sets: HashMap<String, EventSet>,
    endpoints: HashMap<String, Endpoint>,
}

impl Routes {
    pub async fn load(stores: &DefinitionStores) -> Result<Self> {
        Ok(Self {
            integrations: stores
                .integrations
                .list()
                .await?,
            event_sets: by_id(
                stores
                    .event_sets
                    .list()
                    .await?,
            ),
            endpoints: by_id(
                stores
                    .endpoints
                    .list()
                    .await?,
            ),
        })
    }

    /// The active integrations whose event set holds `event_id`, with their active endpoint.
    pub fn for_event(
        &self,
        event_id: &str,
    ) -> Vec<Route> {
        self.integrations
            .iter()
            .filter(|integration| integration.status == Status::Active)
            .filter(|integration| {
                self.event_sets
                    .get(&integration.event_set_id)
                    .is_some_and(|event_set| event_set.contains(event_id))
            })
            .filter_map(|integration| {
                let endpoint = self
                    .endpoints
                    .get(&integration.endpoint_id)
                    .filter(|endpoint| endpoint.status == Status::Active)?;
                Some(Route {
                    integration: integration.clone(),
                    endpoint: endpoint.clone(),
                })
            })
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
            content,
        },
    ))
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
    let values = event_values(event, trigger, crate::storage::settings_store::global_appliance_id_override());
    crate::integrations::background_tasks::spawn_background_task(event_id, async move {
        let Some(stores) = definition_stores() else {
            return;
        };
        let routes = match ROUTES.get(&stores).await {
            Ok(routes) => routes,
            Err(error) => {
                error!(event_id = %event.id, error = %error, "Failed to load integrations");
                return;
            }
        };
        for route in routes.for_event(&event.id) {
            if let Err(error) = deliver(&route, &values).await {
                error!(
                    event_id = %event.id,
                    integration_id = %route.integration.id,
                    error = %error,
                    "Integration delivery failed"
                );
            }
        }
    });
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
}
