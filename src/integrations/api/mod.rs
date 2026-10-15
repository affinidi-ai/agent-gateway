//! The `/v1/integrations` management API: integrations, the endpoints they deliver to, the
//! event sets they deliver, and the catalog to build them from. Integrations belong to the
//! whole appliance, so tenant and resource-scoped tokens are refused.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json, Router};
use serde::Serialize;

use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard};
use crate::auth_manager::pat::PatResourceScope;
use crate::integrations::definitions::{DefinitionStores, EndpointType, Integration};
use crate::integrations::events::{IntegrationEvent, VariableSpec, catalog, variables};
use crate::tenancy::PatTenantContext;

pub fn router(
    stores: Arc<DefinitionStores>,
    guard: Option<RbacGuard>,
) -> Router {
    use crate::auth_manager::middleware::maybe_gate;
    use crate::rbac::Feature;
    use axum::routing::{MethodRouter, delete, get, post, put};
    use endpoints::{create_endpoint, delete_endpoint, get_endpoint, list_endpoints, update_endpoint};
    use event_sets::{create_event_set, delete_event_set, get_event_set, list_event_sets, update_event_set};
    use integrations::{
        create_integration, delete_integration, get_integration, list_integrations, update_integration,
    };

    let gate = |route: MethodRouter, feature: Feature| -> MethodRouter { maybe_gate(guard.as_ref(), route, feature) };
    Router::new()
        .route("/v1/integrations", gate(get(list_integrations), Feature::IntegrationsView))
        .route("/v1/integrations", gate(post(create_integration), Feature::IntegrationsEdit))
        .route("/v1/integrations/{id}", gate(get(get_integration), Feature::IntegrationsView))
        .route("/v1/integrations/{id}", gate(put(update_integration), Feature::IntegrationsEdit))
        .route("/v1/integrations/{id}", gate(delete(delete_integration), Feature::IntegrationsDelete))
        .route("/v1/integrations/catalog", gate(get(get_catalog), Feature::IntegrationsView))
        .route("/v1/integrations/endpoints", gate(get(list_endpoints), Feature::IntegrationsView))
        .route("/v1/integrations/endpoints", gate(post(create_endpoint), Feature::IntegrationsEdit))
        .route("/v1/integrations/endpoints/{id}", gate(get(get_endpoint), Feature::IntegrationsView))
        .route("/v1/integrations/endpoints/{id}", gate(put(update_endpoint), Feature::IntegrationsEdit))
        .route("/v1/integrations/endpoints/{id}", gate(delete(delete_endpoint), Feature::IntegrationsDelete))
        .route("/v1/integrations/event-sets", gate(get(list_event_sets), Feature::IntegrationsView))
        .route("/v1/integrations/event-sets", gate(post(create_event_set), Feature::IntegrationsEdit))
        .route("/v1/integrations/event-sets/{id}", gate(get(get_event_set), Feature::IntegrationsView))
        .route("/v1/integrations/event-sets/{id}", gate(put(update_event_set), Feature::IntegrationsEdit))
        .route("/v1/integrations/event-sets/{id}", gate(delete(delete_event_set), Feature::IntegrationsDelete))
        .layer(axum::middleware::from_fn(appliance_wide_only))
        .layer(Extension(stores))
}

pub type ApiError = (StatusCode, String);

const MAX_NAME_LEN: usize = 200;
const MAX_DESCRIPTION_LEN: usize = 2000;

/// The trimmed name and description, when the name is set and both fit their limits.
fn validate_text(
    name: &str,
    description: &str,
) -> Result<(String, String), ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err((StatusCode::BAD_REQUEST, format!("The name must be 1 to {MAX_NAME_LEN} characters")));
    }
    if description.len() > MAX_DESCRIPTION_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("The description must be at most {MAX_DESCRIPTION_LEN} characters"),
        ));
    }
    Ok((name.to_string(), description.trim().to_string()))
}

/// Definitions are named by UUID, so anything else names none.
fn require_known_id(id: &str) -> Result<(), ApiError> {
    uuid::Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| not_found())
}

fn not_found() -> ApiError {
    (StatusCode::NOT_FOUND, "Not found".to_string())
}

fn internal_error(
    action: &str,
    error: anyhow::Error,
) -> ApiError {
    tracing::error!(action, error = %error, "integrations API storage failure");
    (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to {action}"))
}

async fn integrations_using(
    stores: &DefinitionStores,
    uses: impl Fn(&Integration) -> bool,
) -> Result<Vec<Integration>, ApiError> {
    Ok(stores
        .integrations
        .list()
        .await
        .map_err(|error| internal_error("list integrations", error))?
        .into_iter()
        .filter(|integration| uses(integration))
        .collect())
}

/// Refuses with 409, naming them, while integrations use a definition.
async fn refuse_while_used(
    stores: &DefinitionStores,
    definition: &str,
    uses: impl Fn(&Integration) -> bool,
) -> Result<(), ApiError> {
    let names: Vec<String> = integrations_using(stores, uses)
        .await?
        .into_iter()
        .map(|integration| integration.name)
        .collect();
    if names.is_empty() {
        return Ok(());
    }
    Err((StatusCode::CONFLICT, format!("The {definition} is used by these integrations: {}", names.join(", "))))
}

/// Makes event delivery use the definitions as they are now.
async fn definitions_changed() {
    crate::integrations::delivery::dispatch::invalidate_routes().await;
}

fn caller_id(caller: &Option<Extension<AuthGuardOk>>) -> &str {
    caller
        .as_ref()
        .map_or("unknown", |Extension(AuthGuardOk(id))| id.as_str())
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

pub mod endpoints;
pub mod event_sets;
pub mod integrations;

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
