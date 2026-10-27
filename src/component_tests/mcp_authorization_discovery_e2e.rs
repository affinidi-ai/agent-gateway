//! RFC 9728 discovery for MCP Access Points whose JWT Bearer caller
//! authentication accepts tokens from an external authorization server.

use std::sync::atomic::Ordering;

use serde_json::json;

use super::helpers::jwt::{JwksFixture, now_secs, setup_jwt_bearer_auth_rejects_missing_then_accepts_valid, sign_jwt};
use super::helpers::{GatewayHarness, MockServer, configure_admin_api};

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
    start_discovery_gateway_with(fixture, false, Vec::new()).await
}

/// `forward_header` is set in storage, where the API cannot refuse it, and
/// `listeners` are added to the gateway's network configuration.
async fn start_discovery_gateway_with(
    fixture: &JwksFixture,
    forward_header: bool,
    listeners: Vec<serde_json::Value>,
) -> (GatewayHarness, reqwest::Client) {
    let mut admin = None;
    let tools =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}).to_string()).await;
    let harness = GatewayHarness::start_with_mock(tools, |directory, config, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
        let mut network: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
        network["listeners"][0]["external_urls"]
            .as_array_mut()
            .unwrap()
            .push(json!(PUBLIC_ORIGIN));
        network["listeners"]
            .as_array_mut()
            .unwrap()
            .extend(listeners);
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
        if let Some(crate::source_auth::SourceAuthConfig::JwtBearer(jwt)) = surface
            .access_point
            .caller_authentication
            .as_mut()
            .and_then(|caller| caller.methods.first_mut())
        {
            jwt.forward_header = forward_header;
        }
        surface.variants = vec![
            serde_json::from_value(
                json!({"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {}}),
            )
            .unwrap(),
        ];
    })
    .await;
    (harness, admin.unwrap())
}

/// A token `fixture` issued for `audience`, valid for five minutes.
fn token_for(
    fixture: &JwksFixture,
    audience: serde_json::Value,
) -> String {
    sign_jwt(json!({"iss": fixture.issuer, "sub": "user-123", "aud": audience, "exp": now_secs() + 300}), &fixture.kid)
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
    let variant = client
        .get(metadata_url(&harness, "/smoke$beta"))
        .send()
        .await
        .unwrap();
    assert_eq!(variant.status(), 200);
    assert_eq!(
        variant
            .json::<serde_json::Value>()
            .await
            .unwrap()["resource"],
        "https://gateway.example/smoke$beta"
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
    let mut audience = surface("/other", protected_resource("/other"));
    audience["access_point"]["caller_authentication"]["methods"][0]["audiences"] =
        json!(["https://gateway.example/other"]);
    let refused = admin
        .post(&surfaces)
        .json(&audience)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("requires empty JWT Bearer audiences")
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

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_client_reads_the_metadata_from_any_origin() {
    let fixture = JwksFixture::start().await;
    let (harness, _admin) = start_discovery_gateway(&fixture).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let origin = "https://mcp-client.example";

    let read = client
        .get(metadata_url(&harness, "/smoke"))
        .header("origin", origin)
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), 200);
    assert_eq!(read.headers()["access-control-allow-origin"], origin);

    let preflight = |method: &'static str| {
        client
            .request(reqwest::Method::OPTIONS, metadata_url(&harness, "/smoke"))
            .header("origin", origin)
            .header("access-control-request-method", method)
            .send()
    };
    let allowed = preflight("GET")
        .await
        .unwrap();
    assert!(allowed.status().is_success(), "{}", allowed.status());
    assert_eq!(allowed.headers()["access-control-allow-origin"], origin);
    let refused = preflight("POST")
        .await
        .unwrap();
    assert!(
        !refused
            .headers()
            .contains_key("access-control-allow-origin")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_without_a_valid_token_is_challenged_to_fetch_one() {
    let fixture = JwksFixture::start().await;
    let (harness, _admin) = start_discovery_gateway(&fixture).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let tools_list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let call = |path: &str, token: Option<String>| {
        let mut request = client
            .post(format!("{}{path}", harness.gateway_base))
            .json(&tools_list);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send()
    };
    let challenge = |route: &str, error: &str| {
        format!(
            "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource{route}\"{error}, scope=\"tools\""
        )
    };

    let missing = call("/smoke/rpc", None)
        .await
        .unwrap();
    assert_eq!(missing.status(), 401);
    assert_eq!(missing.headers()["www-authenticate"], challenge("/smoke", "").as_str());
    assert_eq!(missing.headers()["content-type"], "application/problem+json");
    assert_eq!(missing.headers()["cache-control"], "no-store");
    let body: serde_json::Value = missing.json().await.unwrap();
    assert_eq!(body["status"], 401);
    assert_eq!(body["title"], "Unauthorized");

    let variant = call("/smoke$beta/rpc", None)
        .await
        .unwrap();
    assert_eq!(variant.status(), 401);
    assert_eq!(variant.headers()["www-authenticate"], challenge("/smoke$beta", "").as_str());

    let expired = sign_jwt(
        json!({"iss": fixture.issuer, "sub": "user-123", "aud": "https://gateway.example/smoke", "exp": now_secs() - 600}),
        &fixture.kid,
    );
    let unbound = sign_jwt(json!({"iss": fixture.issuer, "sub": "user-123", "exp": now_secs() + 300}), &fixture.kid);
    // Tokens the same authorization server issued for another resource,
    // including the variant's and the base's, are not accepted.
    for (path, route, invalid) in [
        ("/smoke/rpc", "/smoke", expired),
        ("/smoke/rpc", "/smoke", "not-a-jwt".to_string()),
        ("/smoke/rpc", "/smoke", unbound),
        ("/smoke/rpc", "/smoke", token_for(&fixture, json!("https://gateway.example/elsewhere"))),
        ("/smoke/rpc", "/smoke", token_for(&fixture, json!("https://gateway.example/smoke$beta"))),
        ("/smoke$beta/rpc", "/smoke$beta", token_for(&fixture, json!("https://gateway.example/smoke"))),
    ] {
        let response = call(path, Some(invalid))
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "{path}");
        assert_eq!(response.headers()["www-authenticate"], challenge(route, ", error=\"invalid_token\"").as_str());
    }
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let valid = token_for(&fixture, json!(["https://gateway.example/smoke", "https://other.example"]));
    let accepted = call("/smoke/rpc", Some(valid))
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200, "{}", accepted.text().await.unwrap());
    let variant = call("/smoke$beta/rpc", Some(token_for(&fixture, json!("https://gateway.example/smoke$beta"))))
        .await
        .unwrap();
    assert_eq!(variant.status(), 200, "{}", variant.text().await.unwrap());
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        2
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_callers_token_never_reaches_the_target() {
    let fixture = JwksFixture::start().await;
    let (harness, admin) = start_discovery_gateway(&fixture).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let tools_list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let token = token_for(&fixture, json!("https://gateway.example/smoke"));
    let accepted = client
        .post(&harness.gateway_url)
        .bearer_auth(&token)
        .json(&tools_list)
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200);
    let forwarded = harness
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("the target received the request");
    assert!(
        !forwarded
            .headers
            .contains_key("authorization"),
        "{:?}",
        forwarded.headers
    );

    let refused = admin
        .post(format!("{}/api/v1/surfaces", harness.gateway_base))
        .json(&json!({
            "name": "forwarding",
            "access_point": {"listen_address": harness.gateway_base.replace("127.0.0.1", "localhost"),
                "route": "/forwarding", "protocol": "mcp",
                "caller_authentication": {
                    "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": "e2e-jwt-strategy",
                        "audiences": [], "forward_header": true}],
                    "protected_resource": protected_resource("/forwarding")
                }},
            "target": {"endpoint": harness.mock.url()}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("forward_header")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_surface_that_would_forward_the_callers_token_fails_closed() {
    let fixture = JwksFixture::start().await;
    let (harness, _admin) = start_discovery_gateway_with(&fixture, true, Vec::new()).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let token = token_for(&fixture, json!("https://gateway.example/smoke"));
    let refused = client
        .post(&harness.gateway_url)
        .bearer_auth(&token)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 503);
    assert_eq!(
        client
            .get(metadata_url(&harness, "/smoke"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_route_on_two_listeners_publishes_each_listeners_own_resource() {
    let fixture = JwksFixture::start().await;
    let (second_port, mut second_port_guard) = super::helpers::free_port();
    second_port_guard.release_listener();
    let second_address = format!("http://localhost:{second_port}");
    let (harness, admin) = start_discovery_gateway_with(
        &fixture,
        false,
        vec![json!({
            "id": "second", "name": "Second", "bind_address": "0.0.0.0", "port": second_port, "protocol": "http",
            "external_urls": [second_address, "https://other.example"]
        })],
    )
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let second_base = format!("http://127.0.0.1:{second_port}");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while client
        .get(format!("{second_base}/v1/health"))
        .send()
        .await
        .is_err()
    {
        assert!(tokio::time::Instant::now() < deadline, "the second listener did not start");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let added = admin
        .post(format!("{}/api/v1/surfaces", harness.gateway_base))
        .json(&json!({
            "name": "second",
            "access_point": {"listen_address": second_address, "route": "/smoke", "protocol": "mcp",
                "caller_authentication": {
                    "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": "e2e-jwt-strategy", "audiences": []}],
                    "protected_resource": {"resource": "https://other.example/smoke", "authorization_servers": [AUTHORIZATION_SERVER]}
                }},
            "target": {"endpoint": harness.mock.url()}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 201, "{}", added.text().await.unwrap());

    for (base, resource) in [
        (harness.gateway_base.as_str(), "https://gateway.example/smoke"),
        (second_base.as_str(), "https://other.example/smoke"),
    ] {
        let published = client
            .get(format!("{base}/.well-known/oauth-protected-resource/smoke"))
            .send()
            .await
            .unwrap();
        assert_eq!(published.status(), 200, "{base}");
        assert_eq!(
            published
                .json::<serde_json::Value>()
                .await
                .unwrap()["resource"],
            resource
        );
    }
}
