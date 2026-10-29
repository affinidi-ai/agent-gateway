//! `transit.source_auth` E2E: the gateway does not enforce it, so the admin API
//! refuses it, and a surface that already carries it still loads but has every
//! request to its Transit Points refused.

use super::helpers::{self, GatewayHarness, configure_admin_api};
use serde_json::json;
use std::sync::atomic::Ordering;

fn transit_source_auth() -> serde_json::Value {
    json!({
        "type": "api_key",
        "extraction": { "source": "http_header", "field": "X-API-Key" },
        "secret_id": "transit-caller-key"
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn transit_source_auth_is_refused_by_the_api_and_closes_a_loaded_surfaces_transit_points() {
    let mut admin = None;
    let h = GatewayHarness::start_with_outbound(|_, gw_config, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
        let mut surface = helpers::build_minimal_outbound_channel();
        surface.surface_id = "loaded-with-transit-source-auth".to_string();
        surface
            .transit
            .as_mut()
            .unwrap()
            .shared
            .source_auth = Some(serde_json::from_value(transit_source_auth()).unwrap());
        gw_config.surfaces = vec![surface];
    })
    .await;
    let admin = admin.unwrap();
    let outbound = h
        .outbound_url
        .clone()
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    for (method, path) in [
        (reqwest::Method::POST, "/outbound/smoke/target"),
        (reqwest::Method::GET, "/outbound/smoke/target/.well-known/agent-card.json"),
    ] {
        let response = client
            .request(method.clone(), format!("{outbound}{path}"))
            .header("content-type", "application/json")
            .header("x-api-key", "any-key")
            .body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503, "{method} {path}");
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["detail"], "This Transit Point is unavailable", "{method} {path}: {body}");
        assert!(
            !body
                .to_string()
                .contains("source_auth"),
            "the caller is not told why: {body}"
        );
    }
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        0,
        "a refused Transit Point request must not reach the target"
    );

    let collection = format!("{}/api/v1/surfaces", h.gateway_base);
    let payload = json!({
        "name": "without-transit-source-auth",
        "access_point": { "listen_address": h.gateway_base, "route": "/smoke", "protocol": "a2a" },
        "target": { "endpoint": h.mock.url() },
        "transit": { "points": [{ "alias": "partner", "target_endpoint": h.mock.url() }] }
    });
    let created = admin
        .post(&collection)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let stored: serde_json::Value = created.json().await.unwrap();
    let surface_url = format!(
        "{collection}/{}",
        stored["surface_id"]
            .as_str()
            .unwrap()
    );

    let mut on_the_surface = payload.clone();
    on_the_surface["transit"]["source_auth"] = transit_source_auth();
    let mut in_a_disabled_variant = payload.clone();
    in_a_disabled_variant["variants"] = json!([{
        "id": "with-source-auth", "alias": "candidate", "name": "Candidate", "enabled": false,
        "overrides": { "transit": { "shared": { "source_auth": transit_source_auth() } } }
    }]);
    let mut updated = stored.clone();
    updated["transit"]["source_auth"] = transit_source_auth();
    for (case, request) in [
        (
            "create",
            admin
                .post(&collection)
                .json(&on_the_surface),
        ),
        (
            "create with a variant",
            admin
                .post(&collection)
                .json(&in_a_disabled_variant),
        ),
        (
            "update",
            admin
                .put(&surface_url)
                .json(&updated),
        ),
        (
            "merge patch",
            admin
                .patch(&surface_url)
                .header("content-type", "application/merge-patch+json")
                .body(json!({ "transit": { "source_auth": transit_source_auth() } }).to_string()),
        ),
    ] {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 400, "{case}");
        let body = response.text().await.unwrap();
        assert!(body.contains(crate::config::agent_surface::TRANSIT_SOURCE_AUTH_REFUSED), "{case}: {body}");
    }
    let unchanged: serde_json::Value = admin
        .get(&surface_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        unchanged["transit"]
            .get("source_auth")
            .is_none(),
        "{unchanged}"
    );
}
