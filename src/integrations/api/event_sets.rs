use std::sync::Arc;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use tracing::info;

use super::audit_access::{AuditAccess, event_set_holds_audit, holds_audit_events};
use super::{
    ApiError, DefinitionStores, caller_id, definitions_changed, integrations_using, internal_error, not_found,
    refuse_while_used, require_known_id, validate_text,
};
use crate::auth_manager::middleware::AuthGuardOk;
use crate::integrations::definitions::event_set::validate_events;
use crate::integrations::definitions::{EventSet, EventSetError};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSetRequest {
    name: String,
    #[serde(default)]
    description: String,
    events: Vec<String>,
}

pub async fn list_event_sets(
    Extension(stores): Extension<Arc<DefinitionStores>>
) -> Result<Json<Vec<EventSet>>, ApiError> {
    stores
        .event_sets
        .list()
        .await
        .map(Json)
        .map_err(|error| internal_error("list event sets", error))
}

pub async fn get_event_set(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    Path(id): Path<String>,
) -> Result<Json<EventSet>, ApiError> {
    load(&stores, &id)
        .await
        .map(Json)
}

pub async fn create_event_set(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    access: AuditAccess,
    Json(request): Json<EventSetRequest>,
) -> Result<(StatusCode, Json<EventSet>), ApiError> {
    access
        .require_if(holds_audit_events(&request.events))
        .await?;
    let (name, description) = validate_text(&request.name, &request.description)?;
    let event_set = EventSet::new(name, description, request.events).map_err(bad_events)?;
    save(&stores, &event_set).await?;
    info!(
        event = "integrations.event_set.created",
        event_set_id = %event_set.id,
        events = ?event_set.events,
        caller = caller_id(&caller),
    );
    Ok((StatusCode::CREATED, Json(event_set)))
}

/// Refused while an integration of the set would no longer fit it. Needs `audit.view` when the
/// set holds audit events before or after the change.
pub async fn update_event_set(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    access: AuditAccess,
    Path(id): Path<String>,
    Json(request): Json<EventSetRequest>,
) -> Result<Json<EventSet>, ApiError> {
    let mut event_set = load(&stores, &id).await?;
    access
        .require_if(holds_audit_events(&event_set.events) || holds_audit_events(&request.events))
        .await?;
    let (name, description) = validate_text(&request.name, &request.description)?;
    event_set.events = validate_events(request.events).map_err(bad_events)?;
    event_set.name = name;
    event_set.description = description;
    event_set.updated_at = chrono::Utc::now().to_rfc3339();
    let misfits: Vec<String> = integrations_using(&stores, |integration| integration.event_set_id == id)
        .await?
        .into_iter()
        .filter_map(|integration| {
            integration
                .check_against(&event_set)
                .err()
                .map(|reason| format!("{} ({reason})", integration.name))
        })
        .collect();
    if !misfits.is_empty() {
        return Err((
            StatusCode::CONFLICT,
            format!("These integrations would no longer fit the event set: {}", misfits.join("; ")),
        ));
    }
    save(&stores, &event_set).await?;
    info!(
        event = "integrations.event_set.updated",
        event_set_id = %event_set.id,
        events = ?event_set.events,
        caller = caller_id(&caller),
    );
    Ok(Json(event_set))
}

pub async fn delete_event_set(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    access: AuditAccess,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_known_id(&id)?;
    access
        .require_if(event_set_holds_audit(&stores, &id).await?)
        .await?;
    refuse_while_used(&stores, "event set", |integration| integration.event_set_id == id).await?;
    let deleted = stores
        .event_sets
        .delete(&id)
        .await
        .map_err(|error| internal_error("delete the event set", error))?;
    if !deleted {
        return Err(not_found());
    }
    definitions_changed().await;
    info!(event = "integrations.event_set.deleted", event_set_id = %id, caller = caller_id(&caller));
    Ok(StatusCode::NO_CONTENT)
}

fn bad_events(error: EventSetError) -> ApiError {
    (StatusCode::BAD_REQUEST, error.to_string())
}

async fn load(
    stores: &DefinitionStores,
    id: &str,
) -> Result<EventSet, ApiError> {
    require_known_id(id)?;
    stores
        .event_sets
        .find(id)
        .await
        .map_err(|error| internal_error("load the event set", error))?
        .ok_or_else(not_found)
}

async fn save(
    stores: &DefinitionStores,
    event_set: &EventSet,
) -> Result<(), ApiError> {
    stores
        .event_sets
        .save(event_set)
        .await
        .map_err(|error| internal_error("save the event set", error))?;
    definitions_changed().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::integrations::definitions::Integration;
    use serde_json::{Value as JsonValue, json};

    async fn create(
        f: &Fixture,
        events: &[&str],
    ) -> JsonValue {
        let (status, created) = f
            .call(ADMIN, "POST", "/v1/integrations/event-sets", Some(json!({"name": "Ops events", "events": events})))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        created
    }

    fn id(event_set: &JsonValue) -> String {
        event_set["id"]
            .as_str()
            .expect("id")
            .to_string()
    }

    async fn seed_integration(
        f: &Fixture,
        event_set_id: String,
        content: JsonValue,
    ) -> Integration {
        let integration = Integration::new(
            "Gateway alerts".to_string(),
            String::new(),
            uuid::Uuid::new_v4().to_string(),
            event_set_id,
            content,
        );
        f.stores
            .integrations
            .save(&integration)
            .await
            .expect("save integration");
        integration
    }

    #[tokio::test]
    async fn creating_an_event_set_keeps_each_event_once() {
        let f = Fixture::new().await;

        let created = create(&f, &["gateway.created", "audit.policy_decision", "gateway.created"]).await;

        assert_eq!(created["name"], "Ops events");
        assert_eq!(created["events"], json!(["gateway.created", "audit.policy_decision"]));
        let (_, read) = f
            .call(VIEWER, "GET", &format!("/v1/integrations/event-sets/{}", id(&created)), None)
            .await;
        assert_eq!(read, created);
        let (_, listed) = f
            .call(VIEWER, "GET", "/v1/integrations/event-sets", None)
            .await;
        assert_eq!(listed, json!([created]));
    }

    #[tokio::test]
    async fn refuses_an_empty_set_and_events_outside_the_catalog() {
        let f = Fixture::new().await;

        for events in [json!([]), json!(["gateway.created", "identity.created"])] {
            let (status, body) = f
                .call(ADMIN, "POST", "/v1/integrations/event-sets", Some(json!({"name": "Bad", "events": events})))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }
        let (viewer, _) = f
            .call(
                VIEWER,
                "POST",
                "/v1/integrations/event-sets",
                Some(json!({"name": "Viewer", "events": ["gateway.created"]})),
            )
            .await;
        assert_eq!(viewer, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_update_that_an_integration_still_fits_is_saved() {
        let f = Fixture::new().await;
        let created = create(&f, &["gateway.created"]).await;
        seed_integration(&f, id(&created), json!({"text": "${GATEWAY_NAME}"})).await;

        let (status, updated) = f
            .call(
                ADMIN,
                "PUT",
                &format!("/v1/integrations/event-sets/{}", id(&created)),
                Some(json!({"name": "Gateways", "events": ["gateway.created", "gateway.deleted"]})),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["name"], "Gateways");
        assert_eq!(updated["events"], json!(["gateway.created", "gateway.deleted"]));
        assert_eq!(updated["created_at"], created["created_at"]);
    }

    #[tokio::test]
    async fn an_update_an_integration_would_no_longer_fit_is_refused() {
        let f = Fixture::new().await;
        let created = create(&f, &["gateway.created"]).await;
        seed_integration(&f, id(&created), json!({"text": "${GATEWAY_NAME}"})).await;

        let (status, body) = f
            .call(
                ADMIN,
                "PUT",
                &format!("/v1/integrations/event-sets/{}", id(&created)),
                Some(json!({"name": "Users", "events": ["user.created"]})),
            )
            .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body.as_str()
                .is_some_and(|message| message.contains("Gateway alerts") && message.contains("GATEWAY_NAME")),
            "{body}"
        );
        let stored = f
            .stores
            .event_sets
            .find(&id(&created))
            .await
            .expect("find")
            .expect("stored");
        assert_eq!(stored.events, ["gateway.created"]);
    }

    #[tokio::test]
    async fn an_event_set_in_use_is_not_deleted() {
        let f = Fixture::new().await;
        let created = create(&f, &["gateway.created"]).await;
        let item = format!("/v1/integrations/event-sets/{}", id(&created));
        let integration = seed_integration(&f, id(&created), json!({})).await;

        let (in_use, _) = f
            .call(ADMIN, "DELETE", &item, None)
            .await;
        assert_eq!(in_use, StatusCode::CONFLICT);

        f.stores
            .integrations
            .delete(&integration.id)
            .await
            .expect("delete integration");
        let (deleted, _) = f
            .call(ADMIN, "DELETE", &item, None)
            .await;
        let (gone, _) = f
            .call(VIEWER, "GET", &item, None)
            .await;
        let (malformed, _) = f
            .call(VIEWER, "GET", "/v1/integrations/event-sets/not-a-uuid", None)
            .await;
        assert_eq!((deleted, gone, malformed), (StatusCode::NO_CONTENT, StatusCode::NOT_FOUND, StatusCode::NOT_FOUND));
    }
}
