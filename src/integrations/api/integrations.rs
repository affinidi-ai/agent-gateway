use std::sync::Arc;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tracing::info;

use super::{
    ApiError, DefinitionStores, caller_id, definitions_changed, internal_error, not_found, require_known_id,
    validate_text,
};
use crate::auth_manager::middleware::AuthGuardOk;
use crate::integrations::definitions::{Integration, Status};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRequest {
    name: String,
    #[serde(default)]
    description: String,
    endpoint_id: String,
    event_set_id: String,
    content: JsonValue,
    #[serde(default)]
    status: Status,
    #[serde(default)]
    audit_drop_after_secs: Option<u64>,
    #[serde(default)]
    audit_max_attempts: Option<u32>,
}

pub async fn list_integrations(
    Extension(stores): Extension<Arc<DefinitionStores>>
) -> Result<Json<Vec<Integration>>, ApiError> {
    stores
        .integrations
        .list()
        .await
        .map(Json)
        .map_err(|error| internal_error("list integrations", error))
}

pub async fn get_integration(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    Path(id): Path<String>,
) -> Result<Json<Integration>, ApiError> {
    load(&stores, &id)
        .await
        .map(Json)
}

pub async fn create_integration(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Json(request): Json<IntegrationRequest>,
) -> Result<(StatusCode, Json<Integration>), ApiError> {
    let mut integration = Integration::new(String::new(), String::new(), String::new(), String::new(), JsonValue::Null);
    apply(&stores, &mut integration, request).await?;
    save(&stores, &integration).await?;
    info!(
        event = "integrations.integration.created",
        integration_id = %integration.id,
        endpoint_id = %integration.endpoint_id,
        event_set_id = %integration.event_set_id,
        caller = caller_id(&caller),
    );
    Ok((StatusCode::CREATED, Json(integration)))
}

pub async fn update_integration(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Path(id): Path<String>,
    Json(request): Json<IntegrationRequest>,
) -> Result<Json<Integration>, ApiError> {
    let mut integration = load(&stores, &id).await?;
    apply(&stores, &mut integration, request).await?;
    integration.updated_at = chrono::Utc::now().to_rfc3339();
    save(&stores, &integration).await?;
    info!(
        event = "integrations.integration.updated",
        integration_id = %integration.id,
        endpoint_id = %integration.endpoint_id,
        event_set_id = %integration.event_set_id,
        caller = caller_id(&caller),
    );
    Ok(Json(integration))
}

pub async fn delete_integration(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_known_id(&id)?;
    let deleted = stores
        .integrations
        .delete(&id)
        .await
        .map_err(|error| internal_error("delete the integration", error))?;
    if !deleted {
        return Err(not_found());
    }
    definitions_changed().await;
    info!(event = "integrations.integration.deleted", integration_id = %id, caller = caller_id(&caller));
    Ok(StatusCode::NO_CONTENT)
}

/// Sets `integration` from `request` once its endpoint and event set exist and it fits the set.
async fn apply(
    stores: &DefinitionStores,
    integration: &mut Integration,
    request: IntegrationRequest,
) -> Result<(), ApiError> {
    let (name, description) = validate_text(&request.name, &request.description)?;
    let unknown = |what: &str| (StatusCode::BAD_REQUEST, format!("Unknown {what}"));
    if require_known_id(&request.endpoint_id).is_err()
        || stores
            .endpoints
            .find(&request.endpoint_id)
            .await
            .map_err(|error| internal_error("load the endpoint", error))?
            .is_none()
    {
        return Err(unknown("endpoint"));
    }
    let event_set = match require_known_id(&request.event_set_id) {
        Ok(()) => stores
            .event_sets
            .find(&request.event_set_id)
            .await
            .map_err(|error| internal_error("load the event set", error))?,
        Err(_) => None,
    }
    .ok_or_else(|| unknown("event set"))?;
    integration.name = name;
    integration.description = description;
    integration.endpoint_id = request.endpoint_id;
    integration.event_set_id = request.event_set_id;
    integration.content = request.content;
    integration.status = request.status;
    integration.audit_drop_after_secs = request.audit_drop_after_secs;
    integration.audit_max_attempts = request.audit_max_attempts;
    integration
        .check_against(&event_set)
        .map_err(|reason| (StatusCode::BAD_REQUEST, reason))
}

async fn load(
    stores: &DefinitionStores,
    id: &str,
) -> Result<Integration, ApiError> {
    require_known_id(id)?;
    stores
        .integrations
        .find(id)
        .await
        .map_err(|error| internal_error("load the integration", error))?
        .ok_or_else(not_found)
}

async fn save(
    stores: &DefinitionStores,
    integration: &Integration,
) -> Result<(), ApiError> {
    stores
        .integrations
        .save(integration)
        .await
        .map_err(|error| internal_error("save the integration", error))?;
    definitions_changed().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::integrations::definitions::{Endpoint, EndpointType, EventSet};
    use serde_json::json;

    struct Seeded {
        endpoint: Endpoint,
        gateway_events: EventSet,
        audit_events: EventSet,
    }

    async fn seed(f: &Fixture) -> Seeded {
        let endpoint = Endpoint::new(
            "Ops webhook".to_string(),
            String::new(),
            EndpointType::Webhook,
            json!({"url": "https://93.184.215.14/hook"}),
        );
        let gateway_events = EventSet::new("Gateways".to_string(), String::new(), vec!["gateway.created".to_string()])
            .expect("gateway set");
        let audit_events = EventSet::new("Audit".to_string(), String::new(), vec!["audit.policy_decision".to_string()])
            .expect("audit set");
        f.stores
            .endpoints
            .save(&endpoint)
            .await
            .expect("save endpoint");
        for event_set in [&gateway_events, &audit_events] {
            f.stores
                .event_sets
                .save(event_set)
                .await
                .expect("save event set");
        }
        Seeded {
            endpoint,
            gateway_events,
            audit_events,
        }
    }

    fn body(
        endpoint: &Endpoint,
        event_set: &EventSet,
        text: &str,
    ) -> JsonValue {
        json!({
            "name": "Gateway alerts",
            "endpoint_id": endpoint.id,
            "event_set_id": event_set.id,
            "content": {"text": text}
        })
    }

    async fn create(
        f: &Fixture,
        body: JsonValue,
    ) -> (StatusCode, JsonValue) {
        f.call(ADMIN, "POST", "/v1/integrations", Some(body))
            .await
    }

    #[tokio::test]
    async fn an_integration_joins_an_endpoint_and_an_event_set() {
        let f = Fixture::new().await;
        let s = seed(&f).await;

        let (status, created) = create(&f, body(&s.endpoint, &s.gateway_events, "${GATEWAY_NAME} created")).await;

        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["endpoint_id"], s.endpoint.id);
        assert_eq!(created["event_set_id"], s.gateway_events.id);
        assert_eq!(created["content"], json!({"text": "${GATEWAY_NAME} created"}));
        assert_eq!(created["status"], "active");
        let id = created["id"]
            .as_str()
            .expect("id");
        let (_, read) = f
            .call(VIEWER, "GET", &format!("/v1/integrations/{id}"), None)
            .await;
        assert_eq!(read, created);
        let (_, listed) = f
            .call(VIEWER, "GET", "/v1/integrations", None)
            .await;
        assert_eq!(listed, json!([created]));
    }

    #[tokio::test]
    async fn refuses_an_unknown_endpoint_or_event_set() {
        let f = Fixture::new().await;
        let s = seed(&f).await;
        let mut no_endpoint = body(&s.endpoint, &s.gateway_events, "x");
        no_endpoint["endpoint_id"] = json!(uuid::Uuid::new_v4().to_string());
        let mut no_event_set = body(&s.endpoint, &s.gateway_events, "x");
        no_event_set["event_set_id"] = json!("../event_sets/x");

        let (endpoint_status, endpoint_body) = create(&f, no_endpoint).await;
        let (event_set_status, event_set_body) = create(&f, no_event_set).await;

        assert_eq!(endpoint_status, StatusCode::BAD_REQUEST);
        assert_eq!(endpoint_body, json!("Unknown endpoint"));
        assert_eq!(event_set_status, StatusCode::BAD_REQUEST);
        assert_eq!(event_set_body, json!("Unknown event set"));
    }

    #[tokio::test]
    async fn refuses_a_template_its_event_set_does_not_fill_and_misplaced_audit_limits() {
        let f = Fixture::new().await;
        let s = seed(&f).await;
        let mut drop_age = body(&s.endpoint, &s.gateway_events, "${GATEWAY_NAME}");
        drop_age["audit_drop_after_secs"] = json!(600);

        let (unfilled, unfilled_body) = create(&f, body(&s.endpoint, &s.gateway_events, "${USERNAME}")).await;
        let (misplaced, _) = create(&f, drop_age).await;

        assert_eq!(unfilled, StatusCode::BAD_REQUEST);
        assert_eq!(unfilled_body, json!("No event of the event set fills these template variables: USERNAME"));
        assert_eq!(misplaced, StatusCode::BAD_REQUEST);
        assert!(
            f.stores
                .integrations
                .list()
                .await
                .expect("list")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn refuses_categories_tenants_and_other_unknown_fields() {
        let f = Fixture::new().await;
        let s = seed(&f).await;

        for field in ["category", "tenant_id", "audit_events"] {
            let mut extra = body(&s.endpoint, &s.gateway_events, "x");
            extra[field] = json!("audit");
            let (status, _) = create(&f, extra).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{field}");
        }
    }

    #[tokio::test]
    async fn an_update_can_move_the_integration_to_another_event_set() {
        let f = Fixture::new().await;
        let s = seed(&f).await;
        let (_, created) = create(&f, body(&s.endpoint, &s.gateway_events, "${GATEWAY_NAME}")).await;
        let item = format!(
            "/v1/integrations/{}",
            created["id"]
                .as_str()
                .expect("id")
        );
        let mut moved = body(&s.endpoint, &s.audit_events, "${AUDIT_DECISION}");
        moved["audit_max_attempts"] = json!(5);
        moved["status"] = json!("disabled");

        let (status, updated) = f
            .call(ADMIN, "PUT", &item, Some(moved))
            .await;

        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["event_set_id"], s.audit_events.id);
        assert_eq!(updated["audit_max_attempts"], 5);
        assert_eq!(updated["status"], "disabled");
        assert_eq!(updated["created_at"], created["created_at"]);

        let (refused, _) = f
            .call(ADMIN, "PUT", &item, Some(body(&s.endpoint, &s.gateway_events, "${AUDIT_DECISION}")))
            .await;
        assert_eq!(refused, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn only_deleters_delete_an_integration() {
        let f = Fixture::new().await;
        let s = seed(&f).await;
        let (_, created) = create(&f, body(&s.endpoint, &s.gateway_events, "x")).await;
        let item = format!(
            "/v1/integrations/{}",
            created["id"]
                .as_str()
                .expect("id")
        );

        let (viewer, _) = f
            .call(VIEWER, "DELETE", &item, None)
            .await;
        let (deleted, _) = f
            .call(ADMIN, "DELETE", &item, None)
            .await;
        let (again, _) = f
            .call(ADMIN, "DELETE", &item, None)
            .await;

        assert_eq!((viewer, deleted, again), (StatusCode::FORBIDDEN, StatusCode::NO_CONTENT, StatusCode::NOT_FOUND));
    }
}
