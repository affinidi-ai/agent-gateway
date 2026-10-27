//! RFC 9728 discovery for MCP Access Points whose JWT Bearer caller
//! authentication accepts tokens from an external authorization server.

use serde_json::json;

use super::helpers::jwt::{JwksFixture, setup_jwt_bearer_auth_rejects_missing_then_accepts_valid};
use super::helpers::{GatewayHarness, configure_admin_api};

const PUBLIC_ORIGIN: &str = "https://gateway.example";
const AUTHORIZATION_SERVER: &str = "https://idp.example/realms/agents";

fn protected_resource(route: &str) -> serde_json::Value {
    json!({
        "resource": format!("{PUBLIC_ORIGIN}{route}"),
        "authorization_servers": [AUTHORIZATION_SERVER],
        "scopes": ["tools"]
    })
}

async fn start_discovery_gateway(fixture: &JwksFixture) -> (GatewayHarness, reqwest::Client) {
    let mut admin = None;
    let harness = GatewayHarness::start(|directory, config, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
        let mut network: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
        network["listeners"][0]["external_urls"]
            .as_array_mut()
            .unwrap()
            .push(json!(PUBLIC_ORIGIN));
        std::fs::write(&bootstrap.config_files.gateway, serde_json::to_vec(&network).unwrap()).unwrap();
        setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(fixture, directory, config);
        let surface = &mut config.surfaces[0];
        surface.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
        surface
            .access_point
            .caller_authentication
            .as_mut()
            .unwrap()
            .protected_resource = Some(serde_json::from_value(protected_resource("/smoke")).unwrap());
    })
    .await;
    (harness, admin.unwrap())
}

fn metadata_url(
    harness: &GatewayHarness,
    route: &str,
) -> String {
    format!("{}/.well-known/oauth-protected-resource{route}", harness.gateway_base)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_mcp_access_point_publishes_the_protected_resource_its_caller_authentication_names() {
    let fixture = JwksFixture::start().await;
    let (harness, admin) = start_discovery_gateway(&fixture).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();

    let published = client
        .get(metadata_url(&harness, "/smoke"))
        .header("x-forwarded-host", "untrusted.example")
        .send()
        .await
        .unwrap();
    assert_eq!(published.status(), 200);
    assert_eq!(published.headers()["cache-control"], "no-store");
    assert_eq!(
        published
            .json::<serde_json::Value>()
            .await
            .unwrap(),
        json!({
            "resource": "https://gateway.example/smoke",
            "authorization_servers": [AUTHORIZATION_SERVER],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["tools"]
        })
    );
    for unpublished in ["", "/elsewhere", "/smoke/tools"] {
        assert_eq!(
            client
                .get(metadata_url(&harness, unpublished))
                .send()
                .await
                .unwrap()
                .status(),
            404,
            "{unpublished}"
        );
    }

    let surfaces = format!("{}/api/v1/surfaces", harness.gateway_base);
    let listen_address = harness
        .gateway_base
        .replace("127.0.0.1", "localhost");
    let surface = |route: &str, protected: serde_json::Value| {
        json!({
            "name": route.trim_start_matches('/'),
            "access_point": {"listen_address": listen_address, "route": route, "protocol": "mcp",
                "caller_authentication": {
                    "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": "e2e-jwt-strategy", "audiences": []}],
                    "protected_resource": protected
                }},
            "target": {"endpoint": harness.mock.url()}
        })
    };
    let added = admin
        .post(&surfaces)
        .json(&surface("/added", protected_resource("/added")))
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 201, "{}", added.text().await.unwrap());
    let published = client
        .get(metadata_url(&harness, "/added"))
        .send()
        .await
        .unwrap();
    assert_eq!(published.status(), 200);
    assert_eq!(
        published
            .json::<serde_json::Value>()
            .await
            .unwrap()["resource"],
        "https://gateway.example/added"
    );

    let mut elsewhere = protected_resource("/other");
    elsewhere["resource"] = json!("https://elsewhere.example/other");
    let refused = admin
        .post(&surfaces)
        .json(&surface("/other", elsewhere))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("MCP resource 'https://elsewhere.example/other' must be this endpoint's own public URL")
    );
    let mut http_issuer = protected_resource("/other");
    http_issuer["authorization_servers"] = json!(["http://idp.example"]);
    let refused = admin
        .post(&surfaces)
        .json(&surface("/other", http_issuer))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("authorization_servers")
    );
}
