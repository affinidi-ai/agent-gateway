//! MCP `tools/call` channel-OPA enforcement — end-to-end.
//!
//! Regression guard for OPA Policy check: when the general channel OPA gate denies
//! an MCP `tools/call` request, the response must be a JSON-RPC `-32001`
//! envelope (HTTP 200) — not a bare HTTP 403 — so MCP clients see a
//! protocol-shaped failure.

use super::helpers::{GatewayHarness, configure_admin_api};
use serde_json::json;

const DENY_ALL_POLICY_ID: &str = "deny-all-channel";

#[tokio::test(flavor = "multi_thread")]
async fn mcp_http_survives_older_put_and_patch_null_while_protocol_mode_is_dropped() {
    use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

    let mut storage_path = std::path::PathBuf::new();
    let mut client = None;
    let harness = GatewayHarness::start(|directory, _, bootstrap| {
        storage_path = directory.join("agent_surfaces");
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let client = client.unwrap();
    let point = json!({
        "id": "mode-point", "alias": "service", "protocol": "mcp",
        "target_endpoint": harness.mock.url(), "mcp_protocol_mode": "dual",
        "mcp_http": {"allowed_origins": ["https://agent.example"]}
    });
    let collection = format!("{}/api/v1/surfaces", harness.gateway_base);
    let created = client
        .post(&collection)
        .json(&json!({
            "name": "protocol-mode", "status": "disabled", "mcp_protocol_mode": "dual",
            "mcp_http": {"allowed_origins": ["https://console.example"], "max_request_bytes": 4096},
            "access_point": {"listen_address": harness.gateway_base, "route": "/protocol-mode", "protocol": "mcp"},
            "target": {"endpoint": harness.mock.url()},
            "transit": {"points": [point.clone()]},
            "variants": [{"id": "mode-variant", "alias": "test", "name": "test", "enabled": true,
                "overrides": {"transit": {"points": [point]}}}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let mut original: serde_json::Value = created.json().await.unwrap();
    let surface_id = original["surface_id"]
        .as_str()
        .unwrap()
        .to_string();
    let endpoint = format!("{collection}/{surface_id}");
    let mode_paths = [
        "/mcp_protocol_mode",
        "/transit/points/0/mcp_protocol_mode",
        "/variants/0/overrides/transit/points/0/mcp_protocol_mode",
    ];
    for path in mode_paths {
        assert!(
            original
                .pointer(path)
                .is_none(),
            "{path} was stored"
        );
    }
    original
        .as_object_mut()
        .unwrap()
        .remove("mcp_http");
    for path in ["/transit/points/0", "/variants/0/overrides/transit/points/0"] {
        original
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("mcp_http");
    }
    original["description"] = json!("saved by older client");
    let updated = client
        .put(&endpoint)
        .json(&original)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    let mut stored: serde_json::Value = updated.json().await.unwrap();
    assert_eq!(stored["mcp_http"]["max_request_bytes"], 4096);
    assert_eq!(stored["mcp_http"]["allowed_origins"], json!(["https://console.example"]));
    for path in [
        "/transit/points/0/mcp_http/allowed_origins",
        "/variants/0/overrides/transit/points/0/mcp_http/allowed_origins",
    ] {
        assert_eq!(stored.pointer(path), Some(&json!(["https://agent.example"])), "{path}");
    }
    stored["mcp_protocol_mode"] = json!("legacy");
    stored["transit"]["points"][0]["mcp_protocol_mode"] = json!("legacy");
    let updated = client
        .put(&endpoint)
        .json(&stored)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    let stored: serde_json::Value = updated.json().await.unwrap();
    for path in mode_paths {
        assert!(stored.pointer(path).is_none(), "{path} was stored");
    }

    let ignored = client
        .patch(&endpoint)
        .header("content-type", "application/merge-patch+json")
        .json(&json!({"mcp_protocol_mode": "modern"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ignored.status(), 200);
    let ignored: serde_json::Value = ignored.json().await.unwrap();
    assert!(
        ignored
            .get("mcp_protocol_mode")
            .is_none()
    );
    assert_eq!(ignored["mcp_http"], stored["mcp_http"]);
    let readback: serde_json::Value = client
        .get(&endpoint)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(readback, ignored);
    let response = client.patch(&endpoint).header("content-type", "application/merge-patch+json")
        .json(&json!({"mcp_protocol_mode": null, "mcp_http": null, "transit": original["transit"], "variants": original["variants"]}))
        .send().await.unwrap();
    assert_eq!(response.status(), 200);
    let removed: serde_json::Value = response.json().await.unwrap();
    for path in mode_paths {
        assert!(
            removed
                .pointer(path)
                .is_none(),
            "{path}"
        );
    }
    for path in ["/mcp_http", "/transit/points/0/mcp_http", "/variants/0/overrides/transit/points/0/mcp_http"] {
        assert!(
            removed
                .pointer(path)
                .is_none(),
            "{path}"
        );
    }
    let reloaded = FileSystemAgentSurfaceStore::new(storage_path)
        .await
        .unwrap();
    let restored = reloaded
        .get(&surface_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), removed);
}

#[tokio::test(flavor = "multi_thread")]
async fn modern_mcp_follows_the_direct_access_point_policy() {
    let harness = GatewayHarness::start(|_, config, _| {
        let mut surface = surface_with_deny_all_channel_policy();
        surface.target.policy = None;
        config.surfaces = vec![surface];
    })
    .await;
    reqwest::Client::new()
        .post(&harness.gateway_url)
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "echo")
        .header("accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0", "id": "mode", "method": "tools/call",
            "params": {"name": "echo", "arguments": {}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        }))
        .send()
        .await
        .unwrap();
    let forwarded = harness
        .mock
        .request_count
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(forwarded, 1, "an admitted modern request must reach the Target");
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_resource_authorization_requires_scoped_tokens_and_strips_target_credentials() {
    use super::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
    use std::sync::atomic::Ordering;

    let fixture = JwksFixture::start().await;
    let public_origin = "https://gateway.example";
    let issuer = format!("{public_origin}/api/oauth2/mcp");
    let resource = format!("{public_origin}/smoke");
    let transit_resource = "https://outbound.example/outbound/smoke/target";
    let owned_resource = "https://gateway.example/mcp/owned";
    let mock = super::helpers::MockServer::start_with_response(
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}).to_string(),
    )
    .await;
    let harness = GatewayHarness::start_with_outbound_mock(mock, |directory, config, bootstrap| {
        let _admin = configure_admin_api(bootstrap);
        let mut network: serde_json::Value = serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
        network["listeners"][0]["external_urls"].as_array_mut().unwrap().push(json!(public_origin));
        network["listeners"][1]["external_urls"].as_array_mut().unwrap().push(json!("https://outbound.example"));
        network["mcp_proxies"] = json!([{"id": "mcp", "name": "mcp", "prefix": "/mcp"}]);
        network["sts"] = json!({"mcp_issuer": {"issuer": issuer}});
        std::fs::write(&bootstrap.config_files.gateway, serde_json::to_vec(&network).unwrap()).unwrap();
        super::helpers::jwt::setup_jwt_bearer_auth_rejects_missing_then_accepts_valid(&fixture, directory, config);
        config.surfaces[0] = surface_with_deny_all_channel_policy();
        config.surfaces[0].target.policy = None;
        config.surfaces[0].mcp_http = Some(serde_json::from_value(json!({
            "authorization": {"resource": resource, "scopes": ["read"]}
        })).unwrap());
        config.surfaces[0].transit = Some(serde_json::from_value(json!({
            "outbound_listen_address": "outbound_port_placeholder",
            "sign_requests": false,
            "points": [{"alias": "target", "target_endpoint": "outbound_target_placeholder", "protocol": "mcp", "require_transit_token": false,
                "mcp_http": {"authorization": {"resource": transit_resource, "scopes": ["read"]}}}]
        })).unwrap());
        let now = chrono::Utc::now();
        for (kind, id, value) in [
            ("secrets", "mcp-client-secret", json!({
                "id": "mcp-client-secret", "name": "MCP test client", "secret_id": "mcp-client-secret",
                "value": "test-only-client-secret", "secret_type": "General", "tags": [], "created_at": now, "updated_at": now
            })),
            ("sts_clients", "mcp-client", json!({
                "id": "mcp-client", "client_id": "mcp-client", "name": "MCP test client", "client_secret_ref": "mcp-client-secret",
                "allowed_audiences": [resource, transit_resource, owned_resource], "allowed_scopes": ["read"], "allowed_subject_audiences": ["identity-client"],
                "created_at": now, "updated_at": now
            })),
            ("mcp_proxies", "owned", json!({
                "id": "owned", "name": "Owned MCP", "description": "", "base_url": "https://example.com",
                "openapi_spec": "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0.0\npaths: {}\n",
                "status": "active", "channel_prefix": "/mcp", "endpoint_path": "/owned",
                "mcp_http": {"authorization": {"resource": owned_resource, "scopes": ["read"]}},
                "created_at": now, "updated_at": now
            }))
        ] {
            std::fs::create_dir_all(directory.join(kind)).unwrap();
            std::fs::write(directory.join(kind).join(format!("{id}.json")), serde_json::to_vec(&value).unwrap()).unwrap();
        }
    }).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let discovery = client
        .get(format!("{}/.well-known/oauth-authorization-server/api/oauth2/mcp", harness.gateway_base))
        .send()
        .await
        .unwrap();
    assert_eq!(discovery.status(), 200);
    assert_eq!(
        discovery
            .json::<serde_json::Value>()
            .await
            .unwrap()["issuer"],
        issuer
    );
    let metadata = client
        .get(format!("{}/.well-known/oauth-protected-resource/smoke", harness.gateway_base))
        .header("x-forwarded-host", "untrusted.example")
        .send()
        .await
        .unwrap();
    assert_eq!(metadata.status(), 200);
    let metadata: serde_json::Value = metadata.json().await.unwrap();
    assert_eq!(metadata["resource"], resource);
    assert_eq!(metadata["authorization_servers"], json!([issuer]));
    for path in ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/unknown"] {
        assert_eq!(
            client
                .get(format!("{}{path}", harness.gateway_base))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let missing = client
        .post(&harness.gateway_url)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 401);
    assert!(
        missing.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("https://gateway.example/.well-known/oauth-protected-resource/smoke")
    );
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );
    let assertion = sign_jwt(
        json!({"iss": fixture.issuer, "sub": "user-123", "aud": "identity-client", "exp": now_secs() + 300}),
        &fixture.kid,
    );
    for (scope, expected) in [("", 403), ("read", 200)] {
        let exchange = client
            .post(format!("{}/api/oauth2/mcp/token", harness.gateway_base))
            .basic_auth("mcp-client", Some("test-only-client-secret"))
            .form(&[
                ("grant_type", crate::sts::types::GRANT_TYPE_TOKEN_EXCHANGE),
                ("subject_token", assertion.as_str()),
                ("subject_token_type", crate::sts::types::TOKEN_TYPE_JWT),
                ("resource", resource.as_str()),
                ("scope", scope),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(exchange.status(), 200, "{}", exchange.text().await.unwrap());
        let token = exchange
            .json::<crate::sts::types::TokenExchangeResponse>()
            .await
            .unwrap()
            .access_token;
        let response = client
            .post(&harness.gateway_url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == 403 {
            assert!(
                response.headers()["www-authenticate"]
                    .to_str()
                    .unwrap()
                    .contains("insufficient_scope")
            );
            assert_eq!(
                harness
                    .mock
                    .request_count
                    .load(Ordering::SeqCst),
                0
            );
        }
    }
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        1
    );
    let received = harness
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .unwrap();
    assert!(
        !received
            .headers
            .contains_key("authorization")
    );
    assert_eq!(serde_json::from_str::<serde_json::Value>(&received.body).unwrap()["method"], "tools/list");
    let endpoints = [
        (
            transit_resource,
            harness
                .outbound_url
                .as_ref()
                .unwrap()
                .as_str(),
            "/outbound/smoke/target",
            2,
        ),
        (owned_resource, harness.gateway_base.as_str(), "/mcp/owned", 2),
    ];
    for (target_resource, base, path, expected_calls) in endpoints {
        let metadata = client
            .get(format!("{base}/.well-known/oauth-protected-resource{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(metadata.status(), 200, "{path}");
        assert_eq!(
            metadata
                .json::<serde_json::Value>()
                .await
                .unwrap()["resource"],
            target_resource
        );
        let missing = client
            .post(format!("{base}{path}"))
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 401, "{path}");
        let exchange = client
            .post(format!("{}/api/oauth2/mcp/token", harness.gateway_base))
            .basic_auth("mcp-client", Some("test-only-client-secret"))
            .form(&[
                ("grant_type", crate::sts::types::GRANT_TYPE_TOKEN_EXCHANGE),
                ("subject_token", assertion.as_str()),
                ("subject_token_type", crate::sts::types::TOKEN_TYPE_JWT),
                ("resource", target_resource),
                ("scope", "read"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(exchange.status(), 200);
        let token = exchange
            .json::<crate::sts::types::TokenExchangeResponse>()
            .await
            .unwrap()
            .access_token;
        let wrong_resource = client
            .post(&harness.gateway_url)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_resource.status(), 401);
        let response = client
            .post(format!("{base}{path}"))
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
        assert_eq!(
            harness
                .mock
                .request_count
                .load(Ordering::SeqCst),
            expected_calls
        );
        assert!(
            !harness
                .mock
                .last_request_rx
                .borrow()
                .as_ref()
                .unwrap()
                .headers
                .contains_key("authorization")
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_http_direct_guards_opt_in_before_target_dispatch() {
    let harness = GatewayHarness::start(|_, config, _| {
        let mut surface = surface_with_deny_all_channel_policy();
        surface.target.policy = None;
        surface.mcp_http = Some(
            serde_json::from_value(json!({
                "allowed_origins": ["https://console.example"], "max_request_bytes": 1024, "max_header_bytes": 512
            }))
            .unwrap(),
        );
        config.surfaces = vec![surface];
    })
    .await;
    let body = json!({"jsonrpc": "2.0", "id": "http-guard", "method": "server/discover", "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2025-11-25", "io.modelcontextprotocol/clientCapabilities": {}
    }}});
    let client = reqwest::Client::new();
    for (origin, expected_status) in [
        (None, 400),
        (Some("https://console.example"), 400),
        (Some("https://untrusted.example"), 403),
        (Some("null"), 403),
    ] {
        let mut request = client
            .post(&harness.gateway_url)
            .header("mcp-protocol-version", "2025-11-25")
            .header("mcp-method", "server/discover")
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), expected_status, "{origin:?}");
        let response: serde_json::Value = response.json().await.unwrap();
        if expected_status == 400 {
            assert_eq!(response["id"], "http-guard");
            assert_eq!(response["error"]["code"], -32022);
        }
    }
    let duplicate = client
        .post(&harness.gateway_url)
        .header("origin", "https://console.example")
        .header("origin", "https://console.example")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 403);
    let oversized = client
        .post(&harness.gateway_url)
        .header("content-type", "application/json")
        .body(" ".repeat(1025))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
    let headers = client
        .post(&harness.gateway_url)
        .header("x-extra", "x".repeat(513))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(headers.status(), 431);
    let legacy = client
        .post(&harness.gateway_url)
        .header("origin", "https://untrusted.example")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(legacy.status(), 403);
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let response = client
            .request(method, &harness.gateway_url)
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-session-id", "attached-legacy-session")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 405);
        assert_eq!(response.headers()["allow"], "POST");
        assert!(
            response
                .bytes()
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        harness
            .mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_metadata_patch_null_removes_persisted_preference() {
    use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

    let mut storage_path = std::path::PathBuf::new();
    let mut client = None;
    let harness = GatewayHarness::start(|directory, _, bootstrap| {
        storage_path = directory.join("agent_surfaces");
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let client = client.unwrap();
    let collection = format!("{}/api/v1/surfaces", harness.gateway_base);
    let created = client.post(&collection).json(&json!({
        "name": "metadata-rollback", "status": "disabled",
        "mcp_legacy_metadata_output": "canonical",
        "access_point": { "listen_address": harness.gateway_base, "route": "/metadata-rollback", "protocol": "mcp" },
        "target": { "endpoint": harness.mock.url() }
    })).send().await.unwrap();
    assert_eq!(created.status(), 201);
    let original: serde_json::Value = created.json().await.unwrap();
    let surface_id = original["surface_id"]
        .as_str()
        .unwrap();
    let endpoint = format!("{collection}/{surface_id}");
    for (patch, status, expected) in [
        (json!({"description": "preserve preference"}), 200, Some("canonical")),
        (json!({"mcp_legacy_metadata_output": "invalid"}), 400, Some("canonical")),
        (json!({"mcp_legacy_metadata_output": null}), 200, None),
    ] {
        let response = client
            .patch(&endpoint)
            .header("content-type", "application/merge-patch+json")
            .json(&patch)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let readback = client
            .get(&endpoint)
            .send()
            .await
            .unwrap();
        assert_eq!(readback.status(), 200);
        let body: serde_json::Value = readback.json().await.unwrap();
        assert_eq!(
            body.get("mcp_legacy_metadata_output")
                .and_then(serde_json::Value::as_str),
            expected
        );
    }
    let reloaded = FileSystemAgentSurfaceStore::new(storage_path)
        .await
        .unwrap();
    let stored = reloaded
        .get(surface_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.mcp_legacy_metadata_output, None);
    assert_eq!(stored.description, "preserve preference");
    assert!(
        serde_json::to_value(stored)
            .unwrap()
            .get("mcp_legacy_metadata_output")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_metadata_response_keeps_snapshot_during_reload() {
    let upstream = json!({
        "jsonrpc": "2.0", "id": 1, "result": { "tools": [], "_meta": {
            crate::config::TRUST_REGISTRY_EXTENSION: { "marker": "upstream" }
        }}
    });
    let (mock, release) = super::helpers::MockServer::start_paused(upstream.to_string()).await;
    let mut client = None;
    let harness = GatewayHarness::start_with_mock(mock, |_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let client = client.unwrap();
    let collection = format!("{}/api/v1/surfaces", harness.gateway_base);
    let mut listener = url::Url::parse(&harness.gateway_base).unwrap();
    listener
        .set_host(Some("localhost"))
        .unwrap();
    let response = client.post(&collection).json(&json!({
        "name": "metadata-snapshot", "mcp_legacy_metadata_output": "canonical",
        "access_point": { "listen_address": listener.origin().ascii_serialization(), "route": "/smoke/metadata-snapshot", "protocol": "mcp" },
        "target": { "endpoint": harness.mock.url() }
    })).send().await.unwrap();
    assert_eq!(response.status(), 201);
    let surface: serde_json::Value = response.json().await.unwrap();
    let endpoint = format!(
        "{collection}/{}",
        surface["surface_id"]
            .as_str()
            .unwrap()
    );
    let request_url = format!("{}/smoke/metadata-snapshot", harness.gateway_base);
    let mut requests = harness
        .mock
        .last_request_rx
        .clone();
    for (current, updated) in [("canonical", "compatibility"), ("compatibility", "canonical")] {
        requests.borrow_and_update();
        let send = reqwest::Client::new()
            .post(&request_url)
            .json(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/list", "_meta": {"tenant": "caller"}
            }))
            .send();
        let pending = tokio::spawn(send);
        tokio::time::timeout(std::time::Duration::from_secs(10), requests.changed())
            .await
            .unwrap()
            .unwrap();
        let received = requests
            .borrow()
            .clone()
            .unwrap();
        let forwarded: serde_json::Value = serde_json::from_str(&received.body).unwrap();
        if current == "canonical" {
            assert_eq!(forwarded["params"]["_meta"]["tenant"], "caller");
            assert!(
                forwarded
                    .get("_meta")
                    .is_none()
            );
        } else {
            assert_eq!(forwarded["_meta"]["tenant"], "caller");
        }
        let patch = client
            .patch(&endpoint)
            .header("content-type", "application/merge-patch+json")
            .json(&json!({"mcp_legacy_metadata_output": updated}))
            .send();
        let patch = tokio::spawn(patch);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let readback = client
                    .get(&endpoint)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(readback.status(), 200);
                let saved: serde_json::Value = readback.json().await.unwrap();
                if saved["mcp_legacy_metadata_output"] == updated {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!pending.is_finished());
        release.notify_one();
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), 200);
        let response: serde_json::Value = response.json().await.unwrap();
        let mut expected = upstream.clone();
        if current == "canonical" {
            expected["result"]["_meta"] = json!({"io.affinidi.fabric/trust-registry": {"marker": "upstream"}});
        }
        assert_eq!(response, expected, "in-flight response must keep {current} after reload to {updated}");
        let patched = patch.await.unwrap().unwrap();
        assert_eq!(patched.status(), 200);
        let saved: serde_json::Value = patched.json().await.unwrap();
        assert_eq!(saved["mcp_legacy_metadata_output"], updated);
    }
    release.notify_one();
    let response = reqwest::Client::new()
        .post(&request_url)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response["result"]["_meta"], json!({"io.affinidi.fabric/trust-registry": {"marker": "upstream"}}));
    assert_eq!(
        harness
            .mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        3
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_metadata_helper_failure_blocks_each_leg() {
    for output in
        [crate::config::McpLegacyMetadataOutput::Compatibility, crate::config::McpLegacyMetadataOutput::Canonical]
    {
        for response_leg in [false, true] {
            let mock = super::helpers::MockServer::start_with_response(
                json!({
                    "jsonrpc": "2.0", "id": "helper", "result": { "tools": [] }
                })
                .to_string(),
            )
            .await;
            let harness = GatewayHarness::start_with_mock(mock, |_, config, _| {
                let mut surface = surface_with_deny_all_channel_policy();
                surface.target.policy = None;
                surface.mcp_legacy_metadata_output = Some(output);
                let metadata = Some(crate::config::CustomMetadata {
                    enabled: true,
                    payload: Some(json!({"tenant": "$SECRET:missing-metadata-test-secret"})),
                    injection_target: Some(crate::config::MetadataInjectionTarget::Meta),
                });
                if response_leg {
                    surface
                        .target
                        .response_custom_metadata = metadata;
                } else {
                    surface.target.custom_metadata = metadata;
                }
                config.surfaces = vec![surface];
            })
            .await;
            let response = reqwest::Client::new()
                .post(&harness.gateway_url)
                .json(&json!({"jsonrpc": "2.0", "id": "helper", "method": "tools/list"}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status().as_u16(),
                if response_leg {
                    502
                } else {
                    500
                }
            );
            assert_eq!(
                harness
                    .mock
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                usize::from(response_leg)
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_unverified_identity_aliases_never_reach_the_target() {
    let harness = GatewayHarness::start(|_, config, _| {
        let mut surface = surface_with_deny_all_channel_policy();
        surface.target.policy = None;
        config.surfaces = vec![surface];
    })
    .await;
    for key in [
        crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
        crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY,
        crate::config::MCP_AGENT_IDENTITY_BINDING_KEY,
    ] {
        let response = reqwest::Client::new().post(&harness.gateway_url).json(&json!({"jsonrpc": "2.0", "id": "spoof", "method": "tools/call", "params": {"name": "echo", "_meta": {key: {"did": "did:example:unverified"}}}})).send().await.unwrap();
        assert_eq!(response.status(), 422);
        assert_eq!(
            harness
                .mock
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
}

fn write_deny_all_policy_definition(temp_dir: &std::path::Path) {
    let definition = json!({
        "id": DENY_ALL_POLICY_ID,
        "name": "Deny All (surface)",
        "description": "Surface-scoped policy that denies every request.",
        "policy_type": "agent_surface",
        "policy": "package surface.policy\n\ndefault allow := false\n",
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z"
    });
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{}.json", DENY_ALL_POLICY_ID)),
        serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
    )
    .expect("write deny-all policy definition fixture");
}

fn surface_with_deny_all_channel_policy() -> crate::config::agent_surface::AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "mcp-deny-all",
        "name": "mcp-deny-all",
        "description": "MCP tools/call -32001 regression",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "mcp"
        },
        "target": {
            "endpoint": "inbound_target_placeholder",
            "policy": { "policy_definition_id": DENY_ALL_POLICY_ID }
        }
    }))
    .expect("build mcp-deny-all surface")
}

/// MCP `tools/call` blocked by a deny-all surface policy comes back as a
/// JSON-RPC `-32001` envelope (HTTP 200), preserving the request `id` and
/// surfacing the tool name in the error message.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_tools_call_denied_returns_jsonrpc_error_envelope() {
    let h = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        write_deny_all_policy_definition(temp_dir);
        gw_config.surfaces = vec![surface_with_deny_all_channel_policy()];
    })
    .await;

    let client = reqwest::Client::new();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": { "name": "echo", "arguments": {} }
    })
    .to_string();

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("POST tools/call failed");

    assert_eq!(
        resp.status(),
        200,
        "denied MCP tools/call must return HTTP 200 with a JSON-RPC error envelope, got {}",
        resp.status()
    );

    let envelope: serde_json::Value = resp
        .json()
        .await
        .expect("parse JSON-RPC envelope");
    assert_eq!(envelope["jsonrpc"], "2.0");
    assert_eq!(envelope["id"], 7);
    assert_eq!(envelope["error"]["code"], -32001);
    let message = envelope["error"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(message.contains("echo"), "error message should mention the denied tool, got: {message:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_wire_validation_precedes_policy_without_rejecting_legacy_headers() {
    let harness = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        write_deny_all_policy_definition(temp_dir);
        gw_config.surfaces = vec![surface_with_deny_all_channel_policy()];
    })
    .await;
    let client = reqwest::Client::new();
    let modern_body = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let mut list_body = modern_body.clone();
    list_body["method"] = json!("tools/list");
    list_body["params"]
        .as_object_mut()
        .unwrap()
        .remove("name");
    let mut unmodelled_body = modern_body.clone();
    unmodelled_body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2025-11-25");
    let mut mixed_era_body = list_body.clone();
    mixed_era_body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
        json!(crate::mcp::MCP_LEGACY_VERSION);
    for (body, method, version, name, expected_code, expected_id) in [
        (String::new(), "tools/call", crate::mcp::MCP_MODERN_VERSION, "echo", -32700, None),
        (modern_body.to_string(), "tools/call", crate::mcp::MCP_MODERN_VERSION, "=?base64?=", -32020, Some(json!(8))),
        (unmodelled_body.to_string(), "tools/call", "2025-11-25", "echo", -32022, Some(json!(8))),
        (list_body.to_string(), "tools/list", crate::mcp::MCP_MODERN_VERSION, "=?base64?=", -32020, Some(json!(8))),
        (
            mixed_era_body.to_string(),
            "tools/list",
            crate::mcp::MCP_LEGACY_VERSION,
            "extra-name",
            -32602,
            Some(json!(8)),
        ),
    ] {
        let response = client
            .post(&harness.gateway_url)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", version)
            .header("mcp-method", method)
            .header("mcp-name", name)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        let envelope: serde_json::Value = response.json().await.unwrap();
        assert_eq!(envelope["error"]["code"], expected_code);
        assert_eq!(envelope.get("id").cloned(), expected_id);
        if expected_code == -32602 {
            assert!(
                envelope["error"]
                    .get("data")
                    .is_none()
            );
            assert_eq!(
                envelope["error"]["message"],
                "MCP 2024-11-05 cannot use modern per-request metadata or mirrored headers"
            );
        }
    }
    let response = client
        .post(&harness.gateway_url)
        .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
        .json(&json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "echo"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let envelope: serde_json::Value = response.json().await.unwrap();
    assert_eq!(envelope["id"], 9);
    assert_eq!(envelope["error"]["code"], -32001);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_wire_validation_precedes_protocol_family_detection() {
    let harness = GatewayHarness::start(|temp_dir, gw_config, _bootstrap| {
        write_deny_all_policy_definition(temp_dir);
        gw_config.surfaces = vec![surface_with_deny_all_channel_policy()];
    })
    .await;
    let client = reqwest::Client::new();
    let response = client
        .post(&harness.gateway_url)
        .header("mcp-protocol-version", "2025-11-25")
        .header("mcp-method", "tasks/get")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "modern-task",
            "method": "tasks/get",
            "params": {
                "taskId": "task-1",
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                    "io.modelcontextprotocol/clientCapabilities": {
                        "extensions": { "io.modelcontextprotocol/tasks": {} }
                    }
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let envelope: serde_json::Value = response.json().await.unwrap();
    assert_eq!(envelope["jsonrpc"], "2.0");
    assert_eq!(envelope["id"], "modern-task");
    assert_eq!(envelope["error"]["code"], -32022);
    assert_eq!(
        envelope["error"]["data"],
        json!({
            "requested": "2025-11-25",
            "supported": [crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION]
        })
    );

    for protocol_version in [None, Some(crate::mcp::MCP_LEGACY_VERSION)] {
        let mut request = client
            .post(&harness.gateway_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": "legacy-task",
                "method": "tasks/get",
                "params": { "id": "task-1" }
            }));
        if let Some(protocol_version) = protocol_version {
            request = request.header("mcp-protocol-version", protocol_version);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 422);
    }
}
