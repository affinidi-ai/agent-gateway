//! The `/v1/integrations` management API: integrations, the endpoints they deliver to, the
//! event sets they deliver, and the catalog to build them from. Integrations belong to the
//! whole appliance, so tenant and resource-scoped tokens are refused.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json, Router};
use serde::Serialize;

use crate::auth_manager::middleware::RbacGuard;
use crate::auth_manager::pat::PatResourceScope;
use crate::integrations::definitions::{DefinitionStore, Endpoint, EndpointType, EventSet, Integration};
use crate::integrations::events::{IntegrationEvent, VariableSpec, catalog, variables};
use crate::tenancy::PatTenantContext;

pub struct DefinitionStores {
    pub endpoints: DefinitionStore<Endpoint>,
    pub event_sets: DefinitionStore<EventSet>,
    pub integrations: DefinitionStore<Integration>,
}

impl DefinitionStores {
    pub async fn open(
        endpoints: &Path,
        event_sets: &Path,
        integrations: &Path,
    ) -> Result<Self> {
        Ok(Self {
            endpoints: DefinitionStore::new(endpoints.to_path_buf(), "integration endpoint").await?,
            event_sets: DefinitionStore::new(event_sets.to_path_buf(), "integration event set").await?,
            integrations: DefinitionStore::new(integrations.to_path_buf(), "integration").await?,
        })
    }
}

pub fn router(
    stores: Arc<DefinitionStores>,
    guard: Option<RbacGuard>,
) -> Router {
    use crate::auth_manager::middleware::maybe_gate;
    use crate::rbac::Feature;
    use axum::routing::{MethodRouter, get};

    let gate = |route: MethodRouter, feature: Feature| -> MethodRouter { maybe_gate(guard.as_ref(), route, feature) };
    Router::new()
        .route("/v1/integrations/catalog", gate(get(get_catalog), Feature::IntegrationsView))
        .layer(axum::middleware::from_fn(appliance_wide_only))
        .layer(Extension(stores))
}

async fn appliance_wide_only(
    request: Request,
    next: Next,
) -> Response {
    let extensions = request.extensions();
    if extensions
        .get::<PatTenantContext>()
        .is_some()
        || extensions
            .get::<PatResourceScope>()
            .is_some()
    {
        return (StatusCode::FORBIDDEN, "Integrations are appliance-wide and need an appliance-wide caller")
            .into_response();
    }
    next.run(request).await
}

#[derive(Serialize)]
struct EndpointTypeInfo {
    #[serde(rename = "type")]
    endpoint_type: EndpointType,
    secret_fields: &'static [&'static str],
}

#[derive(Serialize)]
struct Catalog {
    events: &'static [IntegrationEvent],
    variables: &'static [VariableSpec],
    endpoint_types: Vec<EndpointTypeInfo>,
}

async fn get_catalog() -> Json<Catalog> {
    Json(Catalog {
        events: catalog(),
        variables: variables(),
        endpoint_types: [EndpointType::Email, EndpointType::Slack, EndpointType::Webhook, EndpointType::Stream]
            .into_iter()
            .map(|endpoint_type| EndpointTypeInfo {
                endpoint_type,
                secret_fields: endpoint_type.secret_fields(),
            })
            .collect(),
    })
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[tokio::test]
    async fn the_catalog_lists_events_variables_and_endpoint_types() {
        let f = Fixture::new().await;

        let (status, catalog) = f
            .call(VIEWER, "GET", "/v1/integrations/catalog", None)
            .await;

        assert_eq!(status, StatusCode::OK);
        let events = catalog["events"]
            .as_array()
            .expect("events");
        assert!(
            events
                .iter()
                .any(|event| event["id"] == "gateway.created" && event["family"] == "gateway")
        );
        assert!(
            catalog["variables"]
                .as_array()
                .expect("variables")
                .iter()
                .any(|variable| variable["name"] == "EVENT_SUMMARY")
        );
        let webhook = catalog["endpoint_types"]
            .as_array()
            .expect("endpoint types")
            .iter()
            .find(|info| info["type"] == "webhook")
            .expect("webhook");
        assert_eq!(webhook["secret_fields"], serde_json::json!(["signing_secret", "headers"]));
    }

    #[tokio::test]
    async fn tenant_and_resource_scoped_tokens_are_refused() {
        let f = Fixture::new().await;

        let (tenant, _) = f
            .call_as(Caller::admin().tenant("team-a"), "GET", "/v1/integrations/catalog", None)
            .await;
        let (scoped, _) = f
            .call_as(Caller::admin().resource_scope("^gw-1$"), "GET", "/v1/integrations/catalog", None)
            .await;

        assert_eq!(tenant, StatusCode::FORBIDDEN);
        assert_eq!(scoped, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn every_route_is_refused_without_an_rbac_guard() {
        let f = Fixture::new().await;

        let (status, _) = f
            .call_unguarded(ADMIN, "GET", "/v1/integrations/catalog", None)
            .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
