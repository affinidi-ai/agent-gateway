//! Sends one test message through an endpoint or an integration, saved or not.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Serialize;
use tracing::info;

use super::integrations::{IntegrationRequest, apply};
use super::{ApiError, DefinitionStores, caller_id, internal_error, not_found, require_known_id};
use crate::auth_manager::middleware::AuthGuardOk;
use crate::integrations::definitions::{Definition, DefinitionStore, EventSet, Integration};
use crate::integrations::delivery::dispatch::{Route, send_once};
use crate::integrations::delivery::values::{event_values, sample_trigger_values};
use crate::integrations::events::find_event;

#[derive(Debug, Serialize)]
pub struct TestResult {
    delivered: bool,
    event_type: String,
}

/// Sends the endpoint's default message for a test event.
pub async fn test_endpoint(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Path(id): Path<String>,
) -> Result<Json<TestResult>, ApiError> {
    let endpoint = load(&stores.endpoints, &id, "endpoint").await?;
    let values = HashMap::from([
        ("EVENT_TYPE".to_string(), TEST_EVENT.to_string()),
        ("EVENT_NAME".to_string(), "Test message".to_string()),
        ("EVENT_SUMMARY".to_string(), format!("Test message for endpoint {}", endpoint.name)),
        ("EVENT_DATA".to_string(), "{}".to_string()),
        ("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339()),
        (
            "APPLIANCE_ID".to_string(),
            crate::storage::settings_store::global_appliance_id_override().unwrap_or_default(),
        ),
    ]);
    let route = Route {
        integration: Integration::new(
            "Endpoint test".to_string(),
            String::new(),
            endpoint.id.clone(),
            String::new(),
            serde_json::json!({}),
        ),
        endpoint,
    };
    send(&route, &values, TEST_EVENT, &caller).await
}

/// Sends the integration's message for the first event of its event set, with sample values.
pub async fn test_integration(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Path(id): Path<String>,
) -> Result<Json<TestResult>, ApiError> {
    let integration = load(&stores.integrations, &id, "integration").await?;
    send_sample(&stores, integration, &caller).await
}

/// [`test_integration`] for an integration not saved yet, checked as a save would be.
pub async fn test_draft(
    Extension(stores): Extension<Arc<DefinitionStores>>,
    caller: Option<Extension<AuthGuardOk>>,
    Json(request): Json<IntegrationRequest>,
) -> Result<Json<TestResult>, ApiError> {
    let mut draft =
        Integration::new(String::new(), String::new(), String::new(), String::new(), serde_json::Value::Null);
    apply(&stores, &mut draft, request).await?;
    send_sample(&stores, draft, &caller).await
}

/// The event a test of an endpoint alone stands for.
const TEST_EVENT: &str = "integration.test";

async fn send_sample(
    stores: &DefinitionStores,
    integration: Integration,
    caller: &Option<Extension<AuthGuardOk>>,
) -> Result<Json<TestResult>, ApiError> {
    let endpoint = load(&stores.endpoints, &integration.endpoint_id, "endpoint").await?;
    let event_set: EventSet = load(&stores.event_sets, &integration.event_set_id, "event set").await?;
    let event = event_set
        .events
        .first()
        .and_then(|id| find_event(id))
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "The event set holds no known event".to_string()))?;
    let values = event_values(
        event,
        sample_trigger_values(event),
        crate::storage::settings_store::global_appliance_id_override(),
    );
    let route = Route { integration, endpoint };
    send(&route, &values, &event.id, caller).await
}

async fn send(
    route: &Route,
    values: &HashMap<String, String>,
    event_type: &str,
    caller: &Option<Extension<AuthGuardOk>>,
) -> Result<Json<TestResult>, ApiError> {
    let result = send_once(route, values).await;
    info!(
        event = "integrations.test_sent",
        endpoint_id = %route.endpoint.id,
        event_type,
        delivered = result.is_ok(),
        caller = caller_id(caller),
    );
    result.map_err(|error| (StatusCode::BAD_GATEWAY, format!("{error:#}")))?;
    Ok(Json(TestResult {
        delivered: true,
        event_type: event_type.to_string(),
    }))
}

async fn load<T: Definition>(
    store: &DefinitionStore<T>,
    id: &str,
    what: &str,
) -> Result<T, ApiError> {
    require_known_id(id)?;
    store
        .find(id)
        .await
        .map_err(|error| internal_error(&format!("load the {what}"), error))?
        .ok_or_else(not_found)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::integrations::definitions::{Endpoint, EndpointType};
    use serde_json::{Value as JsonValue, json};

    struct Seeded {
        endpoint: Endpoint,
        event_set: EventSet,
        integration: Integration,
    }

    /// An integration whose endpoint names a secret that does not exist, so a test send
    /// fails before anything leaves the gateway.
    async fn seeded(f: &Fixture) -> Seeded {
        let endpoint = Endpoint::new(
            "Ops Slack".to_string(),
            String::new(),
            EndpointType::Slack,
            json!({"webhook_url": "$SECRET:never-stored"}),
        );
        let event_set =
            EventSet::new("Gateways".to_string(), String::new(), vec!["gateway.created".to_string()]).expect("set");
        let integration = Integration::new(
            "Alerts".to_string(),
            String::new(),
            endpoint.id.clone(),
            event_set.id.clone(),
            json!({"text": "${GATEWAY_NAME}"}),
        );
        f.stores
            .endpoints
            .save(&endpoint)
            .await
            .expect("endpoint");
        f.stores
            .event_sets
            .save(&event_set)
            .await
            .expect("event set");
        f.stores
            .integrations
            .save(&integration)
            .await
            .expect("integration");
        Seeded {
            endpoint,
            event_set,
            integration,
        }
    }

    fn failed_on_the_secret(
        status: StatusCode,
        body: &JsonValue,
    ) -> bool {
        status == StatusCode::BAD_GATEWAY
            && body
                .as_str()
                .is_some_and(|message| message.contains("never-stored"))
    }

    #[tokio::test]
    async fn a_test_send_that_fails_reports_why() {
        let f = Fixture::new().await;
        let s = seeded(&f).await;

        let (endpoint_status, endpoint_body) = f
            .call(ADMIN, "POST", &format!("/v1/integrations/endpoints/{}/test", s.endpoint.id), None)
            .await;
        let (integration_status, integration_body) = f
            .call(ADMIN, "POST", &format!("/v1/integrations/{}/test", s.integration.id), None)
            .await;
        let (draft_status, draft_body) = f
            .call(
                ADMIN,
                "POST",
                "/v1/integrations/test",
                Some(json!({
                    "name": "Draft",
                    "endpoint_id": s.endpoint.id,
                    "event_set_id": s.event_set.id,
                    "content": {"text": "${GATEWAY_NAME}"}
                })),
            )
            .await;

        assert!(failed_on_the_secret(endpoint_status, &endpoint_body), "{endpoint_status} {endpoint_body}");
        assert!(failed_on_the_secret(integration_status, &integration_body), "{integration_status} {integration_body}");
        assert!(failed_on_the_secret(draft_status, &draft_body), "{draft_status} {draft_body}");
    }

    #[tokio::test]
    async fn a_test_send_that_fails_never_shows_a_secret_or_a_slack_webhook_url() {
        let f = Fixture::new()
            .await
            .with_secrets(Secrets(vec![("slack-hook", None, "not a url s3cr3t-stored")]));
        for webhook_url in ["$SECRET:slack-hook", "hooks.slack.com/services/T0/B0/s3cr3t-plain"] {
            let endpoint = Endpoint::new(
                "Ops Slack".to_string(),
                String::new(),
                EndpointType::Slack,
                json!({"webhook_url": webhook_url}),
            );
            f.stores
                .endpoints
                .save(&endpoint)
                .await
                .expect("endpoint");

            let (status, body) = f
                .call(ADMIN, "POST", &format!("/v1/integrations/endpoints/{}/test", endpoint.id), None)
                .await;

            assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
            let message = body
                .as_str()
                .expect("message");
            assert!(message.contains("webhook_url rejected"), "{message}");
            assert!(!message.contains("s3cr3t"), "{message}");
        }
    }

    #[tokio::test]
    async fn a_draft_is_checked_as_a_save_would_be() {
        let f = Fixture::new().await;
        let s = seeded(&f).await;

        let (status, body) = f
            .call(
                ADMIN,
                "POST",
                "/v1/integrations/test",
                Some(json!({
                    "name": "Draft",
                    "endpoint_id": s.endpoint.id,
                    "event_set_id": s.event_set.id,
                    "content": {"text": "${USERNAME}"}
                })),
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!("No event of the event set fills these template variables: USERNAME"));
    }

    #[tokio::test]
    async fn only_editors_send_tests_and_unknown_definitions_are_not_found() {
        let f = Fixture::new().await;
        let s = seeded(&f).await;
        let unknown = uuid::Uuid::new_v4();

        let (viewer, _) = f
            .call(VIEWER, "POST", &format!("/v1/integrations/{}/test", s.integration.id), None)
            .await;
        let (missing_integration, _) = f
            .call(ADMIN, "POST", &format!("/v1/integrations/{unknown}/test"), None)
            .await;
        let (missing_endpoint, _) = f
            .call(ADMIN, "POST", &format!("/v1/integrations/endpoints/{unknown}/test"), None)
            .await;

        assert_eq!(
            (viewer, missing_integration, missing_endpoint),
            (StatusCode::FORBIDDEN, StatusCode::NOT_FOUND, StatusCode::NOT_FOUND)
        );
    }
}
