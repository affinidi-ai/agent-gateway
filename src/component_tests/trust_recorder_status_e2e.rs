//! `GET /v1/surfaces/{id}/trust-recorder-status` — end-to-end over the admin API.

use serde_json::{Value, json};

use super::helpers::{GatewayHarness, configure_admin_api};

async fn unconnected_registry_id(
    client: &reqwest::Client,
    base: &str,
) -> String {
    let name = "recorder-status-registry";
    client
        .post(format!("{base}/api/v1/trust-registries"))
        .json(&json!({
            "name": name,
            "description": "",
            "oob_url": "http://127.0.0.1:1/unreachable",
            "did_method": "peer"
        }))
        .send()
        .await
        .unwrap();
    let registries: Vec<Value> = client
        .get(format!("{base}/api/v1/trust-registries"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    registries
        .iter()
        .find(|registry| registry["name"] == name)
        .and_then(|registry| registry["id"].as_str())
        .expect("the unconnected trust registry stays stored")
        .to_string()
}

async fn status_of(
    client: &reqwest::Client,
    url: &str,
) -> Value {
    let response = client
        .get(url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response
        .json::<Value>()
        .await
        .unwrap()["status"]
        .clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn surface_trust_recorder_status_is_null_until_attempted_and_follows_the_surface() {
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let client = client.unwrap();
    let registry_id = unconnected_registry_id(&client, &harness.gateway_base).await;
    let collection = format!("{}/api/v1/surfaces", harness.gateway_base);
    let created = client
        .post(&collection)
        .json(&json!({
            "name": "recorder-status",
            "status": "disabled",
            "access_point": {
                "listen_address": harness.gateway_base,
                "route": "/recorder-status",
                "protocol": "mcp",
                "trust_recorder": {"entries": [{
                    "trust_registry_id": registry_id,
                    "issuer_did": "did:web:example.com:issuer",
                    "authority_did": "did:web:example.com:authority",
                    "include_owned_agent": true,
                    "custom_resources": []
                }]}
            },
            "target": {"endpoint": harness.mock.url()}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let surface: Value = created.json().await.unwrap();
    let surface_id = surface["surface_id"]
        .as_str()
        .unwrap()
        .to_string();
    let surface_url = format!("{collection}/{surface_id}");
    let status_url = format!("{surface_url}/trust-recorder-status");

    assert_eq!(status_of(&client, &status_url).await, Value::Null);

    let patched = client
        .patch(&surface_url)
        .header("Content-Type", "application/merge-patch+json")
        .json(&json!({"access_point": {"trust_recorder": null}}))
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), 200);
    assert_eq!(
        status_of(&client, &status_url).await,
        Value::Null,
        "a surface without a Trust Recorder reports no status"
    );

    let unknown = client
        .get(format!("{collection}/no-such-surface/trust-recorder-status"))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);

    let anonymous = reqwest::Client::new()
        .get(&status_url)
        .send()
        .await
        .unwrap();
    assert!(
        matches!(anonymous.status().as_u16(), 401 | 403),
        "an unauthenticated caller must not read the status, got {}",
        anonymous.status()
    );

    let deleted = client
        .delete(&surface_url)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 200);
    assert_eq!(
        client
            .get(&status_url)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}
