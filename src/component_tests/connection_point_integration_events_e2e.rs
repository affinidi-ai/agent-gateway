//! Connection point integration events raised by the Management API, read from the events
//! dispatched in this test process rather than from a receiving endpoint.

use serde_json::{Value, json};

use super::event_hook_e2e::{Api, FakeMediator, fake_invitation};
use crate::integrations::delivery::dispatch::dispatched;

async fn send(request: reqwest::RequestBuilder) -> u16 {
    request
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn put(
    api: &Api,
    path: &str,
    body: Value,
) -> u16 {
    send(
        api.client
            .put(api.url(path))
            .json(&body),
    )
    .await
}

async fn delete(
    api: &Api,
    path: &str,
) -> u16 {
    send(
        api.client
            .delete(api.url(path)),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn creating_changing_and_deleting_a_connection_point_raises_its_events() {
    let api = Api::start(None).await;
    let mediator = FakeMediator::start_resolvable().await;
    Api::install_fake_mediator(&mediator, fake_invitation());
    let (status, created) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 200, "{created}");
    let id = created["connection_point"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/connection-points/{id}");
    let raised = || dispatched::with("CP_ID", &id);
    assert_eq!(raised(), ["connection_point.created"]);

    assert_eq!(put(&api, &path, json!({})).await, 200);
    assert_eq!(put(&api, &path, json!({"name": "cp", "description": "cp", "enabled": true})).await, 200);
    assert_eq!(put(&api, &format!("{path}/exposed-surfaces"), json!({"exposed_channels": []})).await, 200);
    assert_eq!(raised(), ["connection_point.created"], "a save that changes nothing raises nothing");

    assert_eq!(put(&api, &path, json!({"name": "renamed"})).await, 200);
    assert_eq!(raised(), ["connection_point.created", "connection_point.updated"]);

    let (status, surface) = api
        .post(
            "/surfaces",
            &json!({
                "name": "exposed", "status": "disabled",
                "access_point": {"listen_address": api.harness.gateway_base, "route": "/exposed", "protocol": "a2a", "public": true},
                "target": {"endpoint": "http://127.0.0.1:9"}
            }),
        )
        .await;
    assert_eq!(status, 201, "{surface}");
    let surface_id = surface["surface_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(put(&api, &format!("{path}/exposed-surfaces"), json!({"exposed_channels": [surface_id]})).await, 200);
    assert_eq!(raised(), ["connection_point.created", "connection_point.updated", "connection_point.updated"]);

    assert_eq!(delete(&api, &path).await, 204);
    assert_eq!(
        raised(),
        [
            "connection_point.created",
            "connection_point.updated",
            "connection_point.updated",
            "connection_point.deleted"
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_or_deleting_an_unknown_connection_point_raises_nothing() {
    let api = Api::start(None).await;
    let unknown = uuid::Uuid::new_v4().to_string();
    let path = format!("/connection-points/{unknown}");

    assert_eq!(put(&api, &path, json!({"name": "renamed"})).await, 404);
    assert_eq!(put(&api, &format!("{path}/exposed-surfaces"), json!({"exposed_channels": []})).await, 404);
    assert_eq!(delete(&api, &path).await, 404);

    assert!(dispatched::with("CP_ID", &unknown).is_empty());
}
