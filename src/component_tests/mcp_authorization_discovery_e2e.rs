//! RFC 9728 discovery for MCP Access Points whose JWT Bearer caller
//! authentication accepts tokens from an external authorization server.

use std::sync::atomic::Ordering;

use serde_json::json;

use super::helpers::jwt::{JwksFixture, now_secs, setup_jwt_bearer_auth_rejects_missing_then_accepts_valid, sign_jwt};
use super::helpers::{GatewayHarness, MockServer, configure_admin_api};

const PUBLIC_ORIGIN: &str = "https://gateway.example";
const AUTHORIZATION_SERVER: &str = "https://idp.example/realms/agents";
/// A strategy trusting `AUTHORIZATION_SERVER`, whose keys the fixture serves, for the
/// harness surface and for surfaces saved through the API.
const IDP_STRATEGY: &str = "discovery-idp-strategy";

fn protected_resource(route: &str) -> serde_json::Value {
    json!({
        "resource": format!("{PUBLIC_ORIGIN}{route}"),
        "scopes": ["tools"]
    })
}

async fn start_discovery_gateway(fixture: &JwksFixture) -> (GatewayHarness, reqwest::Client) {
    start_discovery_gateway_with(fixture, |_| {}, Vec::new()).await
}

/// `edit` changes the surface in storage, where the API cannot refuse it, and
/// `listeners` are added to the gateway's network configuration.
async fn start_discovery_gateway_with(
    fixture: &JwksFixture,
    edit: impl FnOnce(&mut crate::config::agent_surface::AgentSurface),
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
        let strategy = json!({
            "id": IDP_STRATEGY,
            "name": "Discovery IdP",
            "expected_issuer": AUTHORIZATION_SERVER,
            "jwks_source": {"type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer)},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        });
        std::fs::write(
            directory
                .join("jwt_verification_strategies")
                .join(format!("{IDP_STRATEGY}.json")),
            serde_json::to_vec(&strategy).unwrap(),
        )
        .unwrap();
        let surface = &mut config.surfaces[0];
        surface.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
        surface
            .access_point
            .caller_authentication = Some(
            serde_json::from_value(json!({
                "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": IDP_STRATEGY, "audiences": []}],
                "protected_resource": protected_resource("/smoke")
            }))
            .unwrap(),
        );
        surface.variants = vec![
            serde_json::from_value(
                json!({"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {}}),
            )
            .unwrap(),
        ];
        edit(surface);
    })
    .await;
    (harness, admin.unwrap())
}

/// A token `fixture` issued for `audience`, valid for five minutes.
fn token_for(
    fixture: &JwksFixture,
    audience: serde_json::Value,
) -> String {
    sign_jwt(
        json!({"iss": AUTHORIZATION_SERVER, "sub": "user-123", "aud": audience, "exp": now_secs() + 300}),
        &fixture.kid,
    )
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
    let head = client
        .head(metadata_url(&harness, "/smoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["cache-control"], "no-store");
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
    // Without the gateway STS profile, a path nothing publishes is a plain 404:
    // never proxied, and not answered as a request without a route.
    let before = harness
        .mock
        .request_count
        .load(Ordering::SeqCst);
    for unpublished in ["", "/elsewhere", "/smoke/tools"] {
        let response = client
            .get(metadata_url(&harness, unpublished))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{unpublished}");
        assert_eq!(response.text().await.unwrap(), "", "{unpublished}");
    }
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        before
    );

    let surfaces = format!("{}/api/v1/surfaces", harness.gateway_base);
    let listen_address = harness
        .gateway_base
        .replace("127.0.0.1", "localhost");
    let surface = |route: &str, protected: serde_json::Value| {
        json!({
            "name": route.trim_start_matches('/'),
            "access_point": {"listen_address": listen_address, "route": route, "protocol": "mcp",
                "caller_authentication": {
                    "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": IDP_STRATEGY, "audiences": []}],
                    "protected_resource": protected
                }},
            "target": {"endpoint": harness.mock.url()}
        })
    };
    let mut with_server = protected_resource("/added");
    with_server["authorization_servers"] = json!([AUTHORIZATION_SERVER]);
    let added = admin
        .post(&surfaces)
        .json(&surface("/added", with_server))
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
    let published: serde_json::Value = published
        .json()
        .await
        .unwrap();
    assert_eq!(published["resource"], "https://gateway.example/added");
    assert_eq!(published["authorization_servers"], json!([AUTHORIZATION_SERVER]));

    let omitted = admin
        .post(&surfaces)
        .json(&surface("/omitted", protected_resource("/omitted")))
        .send()
        .await
        .unwrap();
    assert_eq!(omitted.status(), 201, "{}", omitted.text().await.unwrap());
    let published: serde_json::Value = client
        .get(metadata_url(&harness, "/omitted"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        published["authorization_servers"],
        json!([AUTHORIZATION_SERVER]),
        "an omitted list advertises the issuer the strategy trusts"
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
    // The operator's strategy the fixture trusts names an http issuer, which
    // its protected resource metadata advertises as configured.
    let mut operator_http = surface("/operator", protected_resource("/operator"));
    operator_http["access_point"]["caller_authentication"]["methods"][0]["jwt_verification_strategy_id"] =
        json!("e2e-jwt-strategy");
    let accepted = admin
        .post(&surfaces)
        .json(&operator_http)
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 201, "{}", accepted.text().await.unwrap());
    let published: serde_json::Value = client
        .get(metadata_url(&harness, "/operator"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(published["authorization_servers"], json!([fixture.issuer.as_str()]));
    // Another server listed beside the trusted one, first or last, would be
    // refused too: its tokens never pass the strategy.
    for servers in [
        json!(["https://other-idp.example", AUTHORIZATION_SERVER]),
        json!([AUTHORIZATION_SERVER, "https://other-idp.example"]),
    ] {
        let mut listed = protected_resource("/other");
        listed["authorization_servers"] = servers.clone();
        let refused = admin
            .post(&surfaces)
            .json(&surface("/other", listed))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 400, "{servers}");
        assert!(
            refused
                .text()
                .await
                .unwrap()
                .contains("authorization_servers must be exactly"),
            "{servers}"
        );
    }
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
async fn a_put_removes_discovery_only_where_it_sends_null() {
    let fixture = JwksFixture::start().await;
    let (harness, admin) = start_discovery_gateway(&fixture).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let surfaces = format!("{}/api/v1/surfaces", harness.gateway_base);
    let created = admin
        .post(&surfaces)
        .json(&json!({
            "name": "edited",
            "access_point": {"listen_address": harness.gateway_base.replace("127.0.0.1", "localhost"),
                "route": "/edited", "protocol": "mcp",
                "caller_authentication": {
                    "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": IDP_STRATEGY, "audiences": []}],
                    "protected_resource": protected_resource("/edited")
                }},
            "target": {"endpoint": harness.mock.url()}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let mut surface: serde_json::Value = created.json().await.unwrap();
    let url = format!(
        "{surfaces}/{}",
        surface["surface_id"]
            .as_str()
            .unwrap()
    );

    // A PUT that leaves the setting out keeps it.
    surface["description"] = json!("edited without the setting");
    surface["access_point"]["caller_authentication"]
        .as_object_mut()
        .unwrap()
        .remove("protected_resource");
    let kept = admin
        .put(&url)
        .json(&surface)
        .send()
        .await
        .unwrap();
    assert_eq!(kept.status(), 200, "{}", kept.text().await.unwrap());
    let published = client
        .get(metadata_url(&harness, "/edited"))
        .send()
        .await
        .unwrap();
    assert_eq!(published.status(), 200);

    // The body is still read as JSON only.
    let refused = admin
        .put(&url)
        .header("content-type", "text/plain")
        .body(surface.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 415);

    // A null removes it in the same request as the rest of the edit, a route
    // change the stored setting would no longer fit included.
    surface["description"] = json!("edited without discovery");
    surface["access_point"]["route"] = json!("/edited-moved");
    surface["access_point"]["caller_authentication"]["protected_resource"] = json!(null);
    let removed = admin
        .put(&url)
        .json(&surface)
        .send()
        .await
        .unwrap();
    let status = removed.status();
    let saved: serde_json::Value = removed.json().await.unwrap();
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["description"], "edited without discovery");
    assert_eq!(saved["access_point"]["route"], "/edited-moved");
    assert!(
        saved["access_point"]["caller_authentication"]
            .get("protected_resource")
            .is_none(),
        "{saved}"
    );
    let unpublished = client
        .get(metadata_url(&harness, "/edited"))
        .send()
        .await
        .unwrap();
    assert_eq!(unpublished.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_variant_put_keeps_its_discovery_unless_it_sends_null() {
    let fixture = JwksFixture::start().await;
    let (harness, admin) = start_discovery_gateway(&fixture).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let methods = json!([{"type": "jwt_bearer", "jwt_verification_strategy_id": IDP_STRATEGY, "audiences": []}]);
    let mut own = protected_resource("/varied");
    own["scopes"] = json!(["beta"]);
    let surfaces = format!("{}/api/v1/surfaces", harness.gateway_base);
    let created = admin
        .post(&surfaces)
        .json(&json!({
            "name": "varied",
            "access_point": {"listen_address": harness.gateway_base.replace("127.0.0.1", "localhost"),
                "route": "/varied", "protocol": "mcp",
                "caller_authentication": {"methods": methods, "protected_resource": protected_resource("/varied")}},
            "target": {"endpoint": harness.mock.url()},
            "variants": [{"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {
                "access_point": {"caller_authentication": {"methods": methods, "protected_resource": own}}
            }}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "{}", created.text().await.unwrap());
    let created: serde_json::Value = created.json().await.unwrap();
    let url = format!(
        "{surfaces}/{}/variants/beta",
        created["surface_id"]
            .as_str()
            .unwrap()
    );
    let variant_metadata = || {
        client
            .get(metadata_url(&harness, "/varied$beta"))
            .send()
    };

    // Overrides that leave the setting out keep the variant's own.
    let kept = admin
        .put(&url)
        .json(&json!({"overrides": {"access_point": {"caller_authentication": {"methods": methods}}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(kept.status(), 200, "{}", kept.text().await.unwrap());
    let published = variant_metadata()
        .await
        .unwrap();
    assert_eq!(published.status(), 200);
    assert_eq!(
        published
            .json::<serde_json::Value>()
            .await
            .unwrap()["scopes_supported"],
        json!(["beta"])
    );

    // A null removes it.
    let removed = admin
        .put(&url)
        .json(&json!({"overrides": {"access_point": {"caller_authentication": {
            "methods": methods, "protected_resource": null
        }}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 200, "{}", removed.text().await.unwrap());
    assert_eq!(
        variant_metadata()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_catch_all_route_still_receives_metadata_paths_no_surface_publishes() {
    let upstream =
        json!({"resource": "https://upstream.example/mcp", "authorization_servers": ["https://idp.example"]});
    let target = MockServer::start_with_response(upstream.to_string()).await;
    let harness = GatewayHarness::start_with_mock(target, |_directory, config, bootstrap| {
        let mut network: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
        network["routes"]["root"] = json!({"type": "proxy", "prefix": ""});
        std::fs::write(&bootstrap.config_files.gateway, serde_json::to_vec(&network).unwrap()).unwrap();
        config.surfaces = vec![
            serde_json::from_value(json!({
                "name": "pass-through",
                "access_point": {"listen_address": "inbound_port_placeholder", "route": "/", "protocol": "mcp"},
                "target": {"endpoint": "inbound_target_placeholder"}
            }))
            .unwrap(),
        ];
    })
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();

    // A pass-through surface at / still gets the path: the answer is its Target's.
    let response = client
        .get(metadata_url(&harness, "/mcp"))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap(), upstream);

    // The Target's answers keep the cors allowlist: no origin outside it may read them.
    let preflight = client
        .request(reqwest::Method::OPTIONS, metadata_url(&harness, "/mcp"))
        .header("origin", "https://client.example")
        .header("access-control-request-method", "GET")
        .send()
        .await
        .unwrap();
    assert!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_surface_on_the_metadata_path_is_logged_and_left_unmounted() {
    let target = MockServer::start_with_response(json!({"from": "pass-through"}).to_string()).await;
    let squatter_target = MockServer::start_with_response(json!({"from": "squatter"}).to_string()).await;
    let squatter_url = squatter_target.url();
    let harness = GatewayHarness::start_with_mock_and_logs(target, |_directory, config, bootstrap| {
        let mut network: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
        network["routes"]["root"] = json!({"type": "proxy", "prefix": ""});
        std::fs::write(&bootstrap.config_files.gateway, serde_json::to_vec(&network).unwrap()).unwrap();
        config.surfaces = vec![
            serde_json::from_value(json!({
                "name": "pass-through",
                "access_point": {"listen_address": "inbound_port_placeholder", "route": "/", "protocol": "mcp"},
                "target": {"endpoint": "inbound_target_placeholder"}
            }))
            .unwrap(),
            serde_json::from_value(json!({
                "surface_id": "squatter",
                "name": "squatter",
                "access_point": {
                    "listen_address": "inbound_port_placeholder",
                    "route": "/.well-known/oauth-protected-resource/agent",
                    "protocol": "mcp"
                },
                "target": {"endpoint": squatter_url}
            }))
            .unwrap(),
        ];
    })
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();

    let response = client
        .get(metadata_url(&harness, "/agent"))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap(), json!({"from": "pass-through"}));
    assert_eq!(
        squatter_target
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let logs = harness.logs();
    let unmounted = logs
        .lines()
        .filter(|line| line.contains("so the surface is not mounted"))
        .collect::<Vec<_>>();
    assert!(!unmounted.is_empty(), "no unmounted surface logged: {logs}");
    for line in unmounted {
        assert!(line.contains("ERROR"), "{line}");
        assert!(line.contains("surface_id=squatter"), "only the squatter is left unmounted: {line}");
    }
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
            "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource{route}\"{error}"
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
        json!({"iss": AUTHORIZATION_SERVER, "sub": "user-123", "aud": "https://gateway.example/smoke", "exp": now_secs() - 600}),
        &fixture.kid,
    );
    let unbound =
        sign_jwt(json!({"iss": AUTHORIZATION_SERVER, "sub": "user-123", "exp": now_secs() + 300}), &fixture.kid);
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
async fn a_token_whose_aud_array_names_the_resource_among_others_is_accepted() {
    let fixture = JwksFixture::start().await;
    let (harness, _admin) = start_discovery_gateway(&fixture).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let token = token_for(&fixture, json!(["https://gateway.example/smoke", "https://idp.example/userinfo"]));
    let accepted = client
        .post(format!("{}/smoke/rpc", harness.gateway_base))
        .bearer_auth(token)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200, "{}", accepted.text().await.unwrap());
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_for_another_variants_resource_is_refused_even_in_an_aud_array() {
    let fixture = JwksFixture::start().await;
    let (harness, _admin) = start_discovery_gateway(&fixture).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let token = token_for(&fixture, json!(["https://gateway.example/smoke$beta", "x"]));
    let refused = client
        .post(format!("{}/smoke/rpc", harness.gateway_base))
        .bearer_auth(token)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 401);
    assert_eq!(
        refused.headers()["www-authenticate"],
        "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/smoke\", \
         error=\"invalid_token\""
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
async fn a_token_short_of_a_required_scope_is_refused_with_insufficient_scope_before_policy() {
    let fixture = JwksFixture::start().await;
    let (harness, _admin) = start_discovery_gateway_with(
        &fixture,
        |surface| {
            if let Some(crate::source_auth::SourceAuthConfig::JwtBearer(jwt)) = surface
                .access_point
                .caller_authentication
                .as_mut()
                .and_then(|caller| caller.methods.first_mut())
            {
                jwt.required_scopes = vec!["tools.call".to_string()];
            }
        },
        Vec::new(),
    )
    .await;
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
    let scoped = |audience: &str, scope: &str| {
        sign_jwt(
            json!({"iss": AUTHORIZATION_SERVER, "sub": "user-123", "aud": audience, "scope": scope, "exp": now_secs() + 300}),
            &fixture.kid,
        )
    };
    let target_requests = || {
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst)
    };

    let published = client
        .get(metadata_url(&harness, "/smoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(published.status(), 200);
    let mut supported: Vec<String> = serde_json::from_value(
        published
            .json::<serde_json::Value>()
            .await
            .unwrap()["scopes_supported"]
            .clone(),
    )
    .unwrap();
    supported.sort();
    assert_eq!(supported, vec!["tools", "tools.call"]);

    let scope_denied = || {
        crate::metrics::backends::prometheus::SCOPE_DENIED
            .with_label_values(&["jwt"])
            .get()
    };
    let denied_before = scope_denied();
    let short = call("/smoke/rpc", Some(scoped("https://gateway.example/smoke", "tools")))
        .await
        .unwrap();
    assert_eq!(short.status(), 403);
    assert_eq!(
        short.headers()["www-authenticate"],
        "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/smoke\", \
         error=\"insufficient_scope\", scope=\"tools.call\""
    );
    assert_eq!(short.headers()["content-type"], "application/problem+json");
    assert_eq!(short.headers()["cache-control"], "no-store");
    let body: serde_json::Value = short.json().await.unwrap();
    assert_eq!(body["status"], 403);
    assert_eq!(body["title"], "Forbidden");
    assert!(scope_denied() > denied_before, "a scope shortfall through the proxy is counted under jwt");

    let variant = call("/smoke$beta/rpc", Some(scoped("https://gateway.example/smoke$beta", "tools")))
        .await
        .unwrap();
    assert_eq!(variant.status(), 403);
    assert_eq!(
        variant.headers()["www-authenticate"],
        "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/smoke$beta\", \
         error=\"insufficient_scope\", scope=\"tools.call\""
    );

    let missing = call("/smoke/rpc", None)
        .await
        .unwrap();
    assert_eq!(missing.status(), 401);
    assert_eq!(
        missing.headers()["www-authenticate"],
        "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/smoke\", \
         scope=\"tools.call\""
    );
    let elsewhere = call("/smoke/rpc", Some(scoped("https://gateway.example/elsewhere", "tools.call")))
        .await
        .unwrap();
    assert_eq!(elsewhere.status(), 401);
    assert_eq!(
        elsewhere.headers()["www-authenticate"],
        "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/smoke\", \
         error=\"invalid_token\", scope=\"tools.call\""
    );
    let id_token = sign_jwt(
        json!({"iss": AUTHORIZATION_SERVER, "sub": "user-123", "aud": "https://gateway.example/smoke",
            "scope": "tools.call", "nonce": "n-1", "exp": now_secs() + 300}),
        &fixture.kid,
    );
    let refused = call("/smoke/rpc", Some(id_token))
        .await
        .unwrap();
    assert_eq!(refused.status(), 401);
    assert_eq!(target_requests(), 0);

    let granted = call("/smoke/rpc", Some(scoped("https://gateway.example/smoke", "tools tools.call")))
        .await
        .unwrap();
    assert_eq!(granted.status(), 200, "{}", granted.text().await.unwrap());
    assert_eq!(target_requests(), 1);
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
                    "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": IDP_STRATEGY,
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
async fn a_default_variant_answers_on_the_route_with_the_resource_as_written() {
    let fixture = JwksFixture::start().await;
    let (harness, _admin) = start_discovery_gateway_with(
        &fixture,
        |surface| surface.default_variant_id = Some("beta".to_string()),
        Vec::new(),
    )
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();

    let published = client
        .get(metadata_url(&harness, "/smoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(published.status(), 200);
    assert_eq!(
        published
            .json::<serde_json::Value>()
            .await
            .unwrap()["resource"],
        "https://gateway.example/smoke"
    );
    let call = |audience: &str| {
        client
            .post(&harness.gateway_url)
            .bearer_auth(token_for(&fixture, json!(audience)))
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}))
            .send()
    };
    assert_eq!(
        call("https://gateway.example/smoke")
            .await
            .unwrap()
            .status(),
        200
    );
    let refused = call("https://gateway.example/smoke$beta")
        .await
        .unwrap();
    assert_eq!(refused.status(), 401);
    assert!(
        refused.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("/.well-known/oauth-protected-resource/smoke\"")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_surface_that_would_forward_the_callers_token_fails_closed() {
    let fixture = JwksFixture::start().await;
    let (harness, _admin) = start_discovery_gateway_with(
        &fixture,
        |surface| {
            if let Some(crate::source_auth::SourceAuthConfig::JwtBearer(jwt)) = surface
                .access_point
                .caller_authentication
                .as_mut()
                .and_then(|caller| caller.methods.first_mut())
            {
                jwt.forward_header = true;
            }
        },
        Vec::new(),
    )
    .await;
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
    assert!(
        !refused
            .headers()
            .contains_key("www-authenticate")
    );
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
        |_| {},
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
                    "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": IDP_STRATEGY, "audiences": []}],
                    "protected_resource": {"resource": "https://other.example/smoke"}
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

#[tokio::test(flavor = "multi_thread")]
async fn a_post_is_refused_for_unsafe_required_scopes_or_a_route_at_the_metadata_path() {
    let fixture = JwksFixture::start().await;
    let (harness, admin) = start_discovery_gateway(&fixture).await;
    let listen_address = harness
        .gateway_base
        .replace("127.0.0.1", "localhost");
    let post = |name: &str, route: &str, required_scopes: serde_json::Value| {
        admin
            .post(format!("{}/api/v1/surfaces", harness.gateway_base))
            .json(&json!({
                "name": name,
                "access_point": {"listen_address": listen_address, "route": route, "protocol": "mcp",
                    "caller_authentication": {"methods": [{"type": "jwt_bearer",
                        "jwt_verification_strategy_id": IDP_STRATEGY, "audiences": [],
                        "required_scopes": required_scopes}]}},
                "target": {"endpoint": harness.mock.url()}
            }))
            .send()
    };

    for (name, route, required_scopes, names) in [
        ("spaced", "/spaced", json!(["tools read"]), "required_scopes"),
        ("quoted", "/quoted", json!(["tools\""]), "required_scopes"),
        ("metadata", "/.well-known/oauth-protected-resource/agent", json!(["tools"]), "protected resource metadata"),
    ] {
        let refused = post(name, route, required_scopes)
            .await
            .unwrap();
        assert_eq!(refused.status(), 400, "{name}");
        let body = refused.text().await.unwrap();
        assert!(body.contains(names), "{name}: {body}");
    }

    let accepted = post("scoped", "/scoped", json!(["tools", "tools.read"]))
        .await
        .unwrap();
    assert_eq!(accepted.status(), 201, "{}", accepted.text().await.unwrap());
}
