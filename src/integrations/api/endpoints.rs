use std::sync::Arc;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;

use super::{
    ApiError, DefinitionStores, caller_id, internal_error, not_found, refuse_while_used, require_known_id,
    validate_text,
};
use crate::auth_manager::middleware::AuthGuardOk;
use crate::gateways::connection_points::message_processor::get_secrets_store;
use crate::integrations::definitions::endpoint::{keep_unsent_secrets, resolve_secret_references};
use crate::integrations::definitions::{Endpoint, EndpointType, Status};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEndpointRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(rename = "type")]
    endpoint_type: EndpointType,
    configuration: JsonValue,
    #[serde(default)]
    status: Status,
}

/// An endpoint's type is fixed: integrations' templates are written for it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEndpointRequest {
    name: String,
    #[serde(default)]
    description: String,
    configuration: JsonValue,
    status: Status,
}

#[derive(Debug, Serialize)]
pub struct EndpointResponse {
    #[serde(flatten)]
    endpoint: Endpoint,
    secrets: Vec<&'static str>,
}

impl From<&Endpoint> for EndpointResponse {
    fn from(endpoint: &Endpoint) -> Self {
        let (endpoint, secrets) = endpoint.redacted();
        Self { endpoint, secrets }
    }
}

pub async fn list_endpoints(
    Extension(stores): Extension<Arc<DefinitionStores>>
) -> Result<Json<Vec<EndpointResponse>>, ApiError> {
    let endpoints = stores
        .endpoints
        .list()
        .await
        .map_err(|error| internal_error("list endpoints", error))?;
    Ok(Json(
        endpoints
            .iter()
            .map(EndpointResponse::from)
            .collect(),
    ))
}

pub async fn get_endpoint(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    Path(id): Path<String>,
) -> Result<Json<EndpointResponse>, ApiError> {
    let endpoint = load(&stores, &id).await?;
    Ok(Json(EndpointResponse::from(&endpoint)))
}

pub async fn create_endpoint(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Json(request): Json<CreateEndpointRequest>,
) -> Result<(StatusCode, Json<EndpointResponse>), ApiError> {
    let (name, description) = validate_text(&request.name, &request.description)?;
    let mut endpoint = Endpoint::new(name, description, request.endpoint_type, request.configuration);
    endpoint.status = request.status;
    validate(&endpoint).await?;
    save(&stores, &endpoint).await?;
    info!(
        event = "integrations.endpoint.created",
        endpoint_id = %endpoint.id,
        endpoint_type = endpoint.endpoint_type.as_str(),
        caller = caller_id(&caller),
    );
    Ok((StatusCode::CREATED, Json(EndpointResponse::from(&endpoint))))
}

pub async fn update_endpoint(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Path(id): Path<String>,
    Json(request): Json<UpdateEndpointRequest>,
) -> Result<Json<EndpointResponse>, ApiError> {
    let mut endpoint = load(&stores, &id).await?;
    let (name, description) = validate_text(&request.name, &request.description)?;
    endpoint.configuration =
        keep_unsent_secrets(endpoint.endpoint_type, request.configuration, &endpoint.configuration);
    endpoint.name = name;
    endpoint.description = description;
    endpoint.status = request.status;
    endpoint.updated_at = chrono::Utc::now().to_rfc3339();
    validate(&endpoint).await?;
    save(&stores, &endpoint).await?;
    info!(
        event = "integrations.endpoint.updated",
        endpoint_id = %endpoint.id,
        caller = caller_id(&caller),
    );
    Ok(Json(EndpointResponse::from(&endpoint)))
}

pub async fn delete_endpoint(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_known_id(&id)?;
    refuse_while_used(&stores, "endpoint", |integration| integration.endpoint_id == id).await?;
    let deleted = stores
        .endpoints
        .delete(&id)
        .await
        .map_err(|error| internal_error("delete the endpoint", error))?;
    if !deleted {
        return Err(not_found());
    }
    info!(event = "integrations.endpoint.deleted", endpoint_id = %id, caller = caller_id(&caller));
    Ok(StatusCode::NO_CONTENT)
}

async fn load(
    stores: &DefinitionStores,
    id: &str,
) -> Result<Endpoint, ApiError> {
    require_known_id(id)?;
    stores
        .endpoints
        .find(id)
        .await
        .map_err(|error| internal_error("load the endpoint", error))?
        .ok_or_else(not_found)
}

/// Checks the configuration the endpoint would send with, its secret references resolved.
async fn validate(endpoint: &Endpoint) -> Result<(), ApiError> {
    let store = get_secrets_store();
    let mut resolved = endpoint.clone();
    resolved.configuration =
        resolve_secret_references(endpoint.endpoint_type, &endpoint.configuration, store.as_deref())
            .await
            .map_err(|reason| (StatusCode::BAD_REQUEST, reason))?;
    resolved
        .validate_configuration()
        .map_err(|reason| (StatusCode::BAD_REQUEST, reason))
}

async fn save(
    stores: &DefinitionStores,
    endpoint: &Endpoint,
) -> Result<(), ApiError> {
    stores
        .endpoints
        .save(endpoint)
        .await
        .map_err(|error| internal_error("save the endpoint", error))
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::integrations::definitions::Integration;
    use serde_json::json;

    const PUBLIC_HOOK: &str = "https://93.184.215.14/hook";

    fn webhook_body() -> JsonValue {
        json!({
            "name": "Ops webhook",
            "description": "Posts to ops",
            "type": "webhook",
            "configuration": {"url": PUBLIC_HOOK, "method": "POST", "signing_secret": "s3cr3t"}
        })
    }

    async fn create(f: &Fixture) -> JsonValue {
        let (status, created) = f
            .call(ADMIN, "POST", "/v1/integrations/endpoints", Some(webhook_body()))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        created
    }

    fn id(endpoint: &JsonValue) -> String {
        endpoint["id"]
            .as_str()
            .expect("id")
            .to_string()
    }

    #[tokio::test]
    async fn creating_an_endpoint_stores_its_secret_but_never_returns_it() {
        let f = Fixture::new().await;

        let created = create(&f).await;

        assert_eq!(created["name"], "Ops webhook");
        assert_eq!(created["type"], "webhook");
        assert_eq!(created["status"], "active");
        assert_eq!(created["configuration"], json!({"url": PUBLIC_HOOK, "method": "POST"}));
        assert_eq!(created["secrets"], json!(["signing_secret"]));
        let stored = f
            .stores
            .endpoints
            .find(&id(&created))
            .await
            .expect("find")
            .expect("stored");
        assert_eq!(stored.configuration["signing_secret"], "s3cr3t");

        let (_, read) = f
            .call(VIEWER, "GET", &format!("/v1/integrations/endpoints/{}", id(&created)), None)
            .await;
        assert_eq!(read, created);
        let (_, listed) = f
            .call(VIEWER, "GET", "/v1/integrations/endpoints", None)
            .await;
        assert_eq!(listed, json!([created]));
    }

    #[tokio::test]
    async fn only_editors_create_endpoints() {
        let f = Fixture::new().await;

        let (status, _) = f
            .call(VIEWER, "POST", "/v1/integrations/endpoints", Some(webhook_body()))
            .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            f.stores
                .endpoints
                .list()
                .await
                .expect("list")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn refuses_a_configuration_its_publisher_would_not_send_with() {
        let f = Fixture::new().await;
        let mut internal = webhook_body();
        internal["configuration"]["url"] = json!("http://169.254.169.254/latest");

        let (status, body) = f
            .call(ADMIN, "POST", "/v1/integrations/endpoints", Some(internal))
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }

    #[tokio::test]
    async fn refuses_a_secret_reference_it_cannot_resolve() {
        let f = Fixture::new().await;
        let mut unresolved = webhook_body();
        unresolved["configuration"]["signing_secret"] = json!("$SECRET:never-stored");

        let (status, body) = f
            .call(ADMIN, "POST", "/v1/integrations/endpoints", Some(unresolved))
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.as_str()
                .is_some_and(|message| message.contains("never-stored")),
            "{body}"
        );
    }

    #[tokio::test]
    async fn refuses_unknown_fields_and_blank_names() {
        let f = Fixture::new().await;
        let mut extra = webhook_body();
        extra["tenant_id"] = json!("team-a");
        let mut blank = webhook_body();
        blank["name"] = json!("   ");

        let (extra_status, _) = f
            .call(ADMIN, "POST", "/v1/integrations/endpoints", Some(extra))
            .await;
        let (blank_status, _) = f
            .call(ADMIN, "POST", "/v1/integrations/endpoints", Some(blank))
            .await;

        assert_eq!(extra_status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(blank_status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_update_keeps_the_secret_it_leaves_out_and_cannot_change_the_type() {
        let f = Fixture::new().await;
        let created = create(&f).await;
        let item = format!("/v1/integrations/endpoints/{}", id(&created));

        let (status, updated) = f
            .call(
                ADMIN,
                "PUT",
                &item,
                Some(json!({
                    "name": "Renamed",
                    "configuration": {"url": PUBLIC_HOOK, "method": "PUT"},
                    "status": "disabled"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["name"], "Renamed");
        assert_eq!(updated["status"], "disabled");
        assert_eq!(updated["secrets"], json!(["signing_secret"]));
        assert_eq!(updated["created_at"], created["created_at"]);
        let stored = f
            .stores
            .endpoints
            .find(&id(&created))
            .await
            .expect("find")
            .expect("stored");
        assert_eq!(stored.configuration["signing_secret"], "s3cr3t");
        assert_eq!(stored.configuration["method"], "PUT");

        let (retype, _) = f
            .call(
                ADMIN,
                "PUT",
                &item,
                Some(json!({"name": "x", "type": "slack", "configuration": {}, "status": "active"})),
            )
            .await;
        assert_eq!(retype, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn unknown_and_malformed_ids_are_not_found() {
        let f = Fixture::new().await;
        let unknown = format!("/v1/integrations/endpoints/{}", uuid::Uuid::new_v4());

        for uri in [unknown.as_str(), "/v1/integrations/endpoints/..%2Fsecrets"] {
            let (get, _) = f
                .call(VIEWER, "GET", uri, None)
                .await;
            let (delete, _) = f
                .call(ADMIN, "DELETE", uri, None)
                .await;
            assert_eq!((get, delete), (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND), "{uri}");
        }
    }

    #[tokio::test]
    async fn an_endpoint_in_use_is_not_deleted() {
        let f = Fixture::new().await;
        let created = create(&f).await;
        let item = format!("/v1/integrations/endpoints/{}", id(&created));
        let integration = Integration::new(
            "Uses it".to_string(),
            String::new(),
            id(&created),
            uuid::Uuid::new_v4().to_string(),
            json!({}),
        );
        f.stores
            .integrations
            .save(&integration)
            .await
            .expect("save integration");

        let (in_use, body) = f
            .call(ADMIN, "DELETE", &item, None)
            .await;
        assert_eq!(in_use, StatusCode::CONFLICT);
        assert!(
            body.as_str()
                .is_some_and(|message| message.contains("Uses it")),
            "{body}"
        );

        f.stores
            .integrations
            .delete(&integration.id)
            .await
            .expect("delete integration");
        let (deleted, _) = f
            .call(ADMIN, "DELETE", &item, None)
            .await;
        assert_eq!(deleted, StatusCode::NO_CONTENT);
        let (gone, _) = f
            .call(VIEWER, "GET", &item, None)
            .await;
        assert_eq!(gone, StatusCode::NOT_FOUND);
    }
}
