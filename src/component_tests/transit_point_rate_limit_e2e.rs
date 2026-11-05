//! A Transit Point's per-caller rate limit through the admin API: it is stored
//! and read back as sent, left out of a point that sets none, and refused when
//! it cannot be enforced.

use super::helpers::{GatewayHarness, configure_admin_api};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread")]
async fn a_per_caller_rate_limit_round_trips_through_the_admin_api_and_an_unenforceable_one_is_refused() {
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let client = client.unwrap();
    let collection = format!("{}/api/v1/surfaces", harness.gateway_base);
    let point = |alias: &str, limit: Option<Value>| {
        let mut point = json!({ "alias": alias, "protocol": "mcp", "target_endpoint": harness.mock.url(),
                                "require_transit_token": true });
        if let Some(limit) = limit {
            point["per_caller_rate_limit"] = limit;
        }
        point
    };
    let surface = |route: &str, points: Value| {
        json!({
            "name": route.trim_start_matches('/'), "status": "disabled",
            "access_point": { "listen_address": harness.gateway_base, "route": route, "protocol": "mcp", "public": true },
            "target": { "endpoint": harness.mock.url() },
            "transit": { "points": points }
        })
    };
    let limit = json!({ "requests": 60, "window_secs": 60, "burst": 10 });

    let created = client
        .post(&collection)
        .json(&surface("/per-caller-limit", json!([point("limited", Some(limit.clone())), point("open", None)])))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: Value = created.json().await.unwrap();
    let surface_id = created["surface_id"]
        .as_str()
        .unwrap();
    let fetched: Value = client
        .get(format!("{collection}/{surface_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    for (answer, body) in [("create", &created), ("get", &fetched)] {
        assert_eq!(body.pointer("/transit/points/0/per_caller_rate_limit"), Some(&limit), "{answer}: {body}");
        assert!(
            body.pointer("/transit/points/1/per_caller_rate_limit")
                .is_none(),
            "{answer}: a point without a per-caller limit has none: {body}"
        );
    }

    let refused = client
        .post(&collection)
        .json(&surface(
            "/per-caller-unenforceable",
            json!([point("limited", Some(json!({ "requests": 1, "window_secs": 20_000_000_000_u64 })))]),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
    let refused = refused.text().await.unwrap();
    assert!(refused.contains("per_caller_rate_limit cannot be enforced"), "{refused}");
}
