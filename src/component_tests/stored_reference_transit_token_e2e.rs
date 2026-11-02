//! A surface stored with `transit_token_mode: reference` is rewritten to
//! `embedded` when the gateway loads it, so the admin API accepts every later
//! write to it, on the surface and on its variants.

use super::helpers::{GatewayHarness, configure_admin_api};
use serde_json::json;

const SURFACE_ID: &str = "stored-reference";

fn stored_surface() -> serde_json::Value {
    json!({
        "surface_id": SURFACE_ID, "name": SURFACE_ID, "status": "disabled",
        "access_point": { "listen_address": "0.0.0.0:8443", "route": "/stored-reference", "protocol": "a2a" },
        "target": { "endpoint": "https://managed.example/a2a" },
        "transit": { "transit_token_mode": "reference", "points": [] },
        "variants": [{ "id": "variant-dev", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": { "transit": { "shared": { "transit_token_mode": "reference" } } } }]
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_stored_with_reference_transit_tokens_accepts_every_admin_write() {
    let mut admin = None;
    let mut surface_file = None;
    let h = GatewayHarness::start(|_, _, bootstrap| {
        let directory = std::path::PathBuf::from(
            &bootstrap
                .storage_paths
                .agent_surfaces,
        );
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{SURFACE_ID}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&stored_surface()).unwrap()).unwrap();
        surface_file = Some(path);
        admin = Some(configure_admin_api(bootstrap));
    })
    .await;
    let (admin, surface_file) = (admin.unwrap(), surface_file.unwrap());
    let url = format!("{}/api/v1/surfaces/{SURFACE_ID}", h.gateway_base);

    let read = admin
        .get(&url)
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), 200);
    let surface: serde_json::Value = read.json().await.unwrap();
    assert_eq!(surface["transit"]["transit_token_mode"], "embedded");
    assert_eq!(surface["variants"][0]["overrides"]["transit"]["shared"]["transit_token_mode"], "embedded");
    let on_disk: serde_json::Value = serde_json::from_slice(&std::fs::read(&surface_file).unwrap()).unwrap();
    assert_eq!(on_disk["transit"]["transit_token_mode"], "embedded", "the rewrite is persisted");
    assert_eq!(on_disk["variants"][0]["overrides"]["transit"]["shared"]["transit_token_mode"], "embedded");

    let patched = admin
        .patch(&url)
        .header("content-type", "application/merge-patch+json")
        .body(json!({ "name": "renamed" }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), 200, "PATCH: {}", patched.text().await.unwrap());

    let mut put_body = surface.clone();
    put_body["name"] = json!("renamed again");
    let put = admin
        .put(&url)
        .json(&put_body)
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200, "PUT: {}", put.text().await.unwrap());

    let variant_put = admin
        .put(format!("{url}/variants/variant-dev"))
        .json(&json!({ "id": "variant-dev", "alias": "dev", "name": "dev again", "enabled": true,
            "overrides": { "transit": { "shared": { "transit_token_mode": "embedded" } } } }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        variant_put.status(),
        200,
        "variant PUT: {}",
        variant_put
            .text()
            .await
            .unwrap()
    );

    let created = admin
        .post(format!("{url}/variants"))
        .json(&json!({ "alias": "qa", "name": "qa", "enabled": true, "overrides": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "variant create: {}", created.text().await.unwrap());

    let refused = admin
        .put(&url)
        .json(&{
            let mut body = put_body.clone();
            body["transit"]["transit_token_mode"] = json!("reference");
            body
        })
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400, "a write that sets reference is still refused");
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("transit.transit_token_mode 'reference' is not supported")
    );
}
