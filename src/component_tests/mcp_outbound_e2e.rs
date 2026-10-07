//! MCP outbound (transit) custom metadata injection E2E tests
//!
//! Exercises `step_inject_custom_metadata` in `outbound_handler.rs` for the MCP
//! protocol — the path that is **not** covered by `mcp_custom_metadata.feature`,
//! which only tests the direct inbound proxy path.
//!
//! Setup: a surface with `protocol = "mcp"` and a `transit` block that carries
//! `custom_metadata`.  The simulated managed agent sends MCP `tools/list`
//! requests through the gateway's outbound listener; the mock external MCP
//! server records what it received.

use super::helpers;
use crate::config::agent_surface::AgentSurface;
use helpers::{GatewayHarness, MockServer};
use serde_json::json;

fn mcp_tools_list_request() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    })
}

fn mcp_ok_response() -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "tools": [] }
    }))
    .unwrap()
}

fn build_mcp_outbound_surface(custom_metadata: serde_json::Value) -> AgentSurface {
    serde_json::from_value(json!({
        "name": "smoke-mcp-outbound",
        "description": "MCP outbound custom metadata test surface",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "mcp"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "sign_requests": false,
            "custom_metadata": custom_metadata,
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "protocol": "mcp",
                "require_transit_token": false
            }]
        }
    }))
    .expect("build_mcp_outbound_surface: AgentSurface JSON")
}

async fn send_mcp_outbound(h: &GatewayHarness) -> reqwest::Response {
    let outbound_url = h
        .outbound_url
        .as_ref()
        .expect("outbound_url must be set");
    reqwest::Client::new()
        .post(format!("{}/outbound/smoke/target", outbound_url))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&mcp_tools_list_request()).unwrap())
        .send()
        .await
        .expect("outbound MCP request failed")
}

#[tokio::test(flavor = "multi_thread")]
async fn outbound_mcp_listener_preserves_variant_catalog_and_custom_routes() {
    let base = MockServer::start_with_response(
        json!({"jsonrpc": "2.0", "id": 1, "result": {
            "tools": [], "marker": "base"
        }})
        .to_string(),
    )
    .await;
    let candidate = MockServer::start_with_response(
        json!({"jsonrpc": "2.0", "id": 1, "result": {
            "tools": [], "marker": "candidate"
        }})
        .to_string(),
    )
    .await;
    let base_url = base.url();
    let candidate_url = candidate.url();
    let harness = GatewayHarness::start_with_outbound_mock(base, |_, config, _| {
        let mut surface = build_mcp_outbound_surface(json!({"enabled": false}));
        surface.surface_id = "outbound-route-variants".into();
        let transit = surface
            .transit
            .as_mut()
            .unwrap();
        transit.points[0].listen_path = Some("/custom/mcp".into());
        let mut default_point = transit.points[0].clone();
        default_point.target_endpoint = base_url.clone();
        let mut candidate_point = default_point.clone();
        candidate_point.target_endpoint = candidate_url.clone();
        surface.variants = serde_json::from_value(json!([
            {"id": "default", "alias": "default", "name": "Default", "overrides": {
                "transit": {"points": [default_point]}
            }},
            {"id": "candidate", "alias": "candidate", "name": "Candidate", "overrides": {
                "transit": {"points": [candidate_point]}
            }}
        ]))
        .unwrap();
        surface.default_variant_id = Some("default".into());
        config.surfaces = vec![surface];
    })
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    for (path, marker) in [
        ("/outbound/smoke/target", "base"),
        ("/outbound/smoke$candidate/target", "candidate"),
        ("/outbound/smoke%24candidate/target", "candidate"),
        ("/custom/mcp", "base"),
        ("/custom/mcp$candidate", "candidate"),
        ("/custom/mcp%24candidate", "candidate"),
    ] {
        for suffix in ["", "/rpc/orders/42"] {
            let url = format!(
                "{}{path}{suffix}",
                harness
                    .outbound_url
                    .as_ref()
                    .unwrap()
            );
            let response = client
                .post(&url)
                .json(&mcp_tools_list_request())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "legacy route {path}");
            let response: serde_json::Value = response.json().await.unwrap();
            assert_eq!(response["result"]["marker"], marker, "{path}");
            let observed = if marker == "candidate" {
                candidate
                    .last_request_rx
                    .borrow()
                    .clone()
            } else {
                harness
                    .mock
                    .last_request_rx
                    .borrow()
                    .clone()
            }
            .unwrap();
            assert_eq!(
                observed.path,
                if suffix.is_empty() {
                    "/"
                } else {
                    suffix
                },
                "forwarded {path}{suffix}"
            );
            let before = harness
                .mock
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst)
                + candidate
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst);
            let response = client
                .post(&url)
                .header("mcp-protocol-version", "2025-11-25")
                .header("mcp-method", "tools/list")
                .header("accept", "application/json, text/event-stream")
                .json(
                    &json!({"jsonrpc": "2.0", "id": "variant-admission", "method": "tools/list", "params": {"_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }}}),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 400, "unmodelled revision on route {path}");
            let error: serde_json::Value = response.json().await.unwrap();
            assert_eq!(error["id"], "variant-admission");
            assert_eq!(error["error"]["code"], -32022);
            assert_eq!(
                before,
                harness
                    .mock
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst)
                    + candidate
                        .request_count
                        .load(std::sync::atomic::Ordering::SeqCst)
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn outbound_mcp_canonical_metadata_and_modern_rejection() {
    let mock = MockServer::start_with_response(mcp_ok_response()).await;
    let harness = GatewayHarness::start_with_outbound_mock(mock, |_, config, _| {
        let mut surface = build_mcp_outbound_surface(
            json!({"enabled": true, "payload": {"tenant": "acme"}, "injection_target": "meta"}),
        );
        surface.mcp_legacy_metadata_output = Some(crate::config::McpLegacyMetadataOutput::Canonical);
        config.surfaces = vec![surface];
    })
    .await;
    assert_eq!(
        send_mcp_outbound(&harness)
            .await
            .status(),
        200
    );
    let received = harness
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .unwrap();
    let forwarded: serde_json::Value = serde_json::from_str(&received.body).unwrap();
    assert_eq!(forwarded["params"]["_meta"]["tenant"], "acme");
    assert!(
        forwarded
            .get("_meta")
            .is_none()
    );
    let calls = harness
        .mock
        .request_count
        .load(std::sync::atomic::Ordering::SeqCst);
    let response = reqwest::Client::new().post(format!("{}/outbound/smoke/target", harness.outbound_url.as_ref().unwrap()))
        .header("MCP-Protocol-Version", "2025-11-25").header("Mcp-Method", "tasks/get")
        .json(&json!({"jsonrpc": "2.0", "id": "modern-transit", "method": "tasks/get", "params": {"taskId": "one", "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2025-11-25",
            "io.modelcontextprotocol/clientCapabilities": {}
        }}})).send().await.unwrap();
    assert_eq!(response.status(), 400);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["id"], "modern-transit");
    assert_eq!(error["error"]["code"], -32022);
    assert_eq!(
        error["error"]["data"],
        json!({"requested": "2025-11-25", "supported": [crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION]})
    );
    assert_eq!(
        harness
            .mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        calls
    );

    for metadata in
        [json!({"io.affinidi.fabric/agent-identity-credential": {"did": "did:example:unverified"}}), json!(null)]
    {
        let expected = if metadata.is_null() {
            400
        } else {
            422
        };
        let response = reqwest::Client::new()
            .post(format!(
                "{}/outbound/smoke/target",
                harness
                    .outbound_url
                    .as_ref()
                    .unwrap()
            ))
            .json(
                &json!({"jsonrpc": "2.0", "id": "bad-transit", "method": "tools/list", "params": {"_meta": metadata}}),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            harness
                .mock
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            calls
        );
    }
}

// ── meta target ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn outbound_mcp_custom_metadata_meta_target_injects_meta_only() {
    let mock = MockServer::start_with_response(mcp_ok_response()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![build_mcp_outbound_surface(json!({
            "enabled": true,
            "payload": { "tenant": "acme" },
            "injection_target": "meta"
        }))];
    })
    .await;

    let resp = send_mcp_outbound(&h).await;
    assert_eq!(resp.status(), 200);

    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock received no request");
    let body: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body must be valid JSON");

    assert_eq!(body["_meta"]["tenant"], "acme", "_meta.tenant must be injected");
    assert!(
        !received
            .headers
            .contains_key("x-gateway-tenant"),
        "x-gateway-tenant header must NOT be present for meta target"
    );
}

// ── headers target ────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn outbound_mcp_custom_metadata_headers_target_injects_headers_only() {
    let mock = MockServer::start_with_response(mcp_ok_response()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![build_mcp_outbound_surface(json!({
            "enabled": true,
            "payload": { "tenant": "acme" },
            "injection_target": "headers"
        }))];
    })
    .await;

    let resp = send_mcp_outbound(&h).await;
    assert_eq!(resp.status(), 200);

    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock received no request");
    let body: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body must be valid JSON");

    assert_eq!(
        received
            .headers
            .get("x-gateway-tenant")
            .map(String::as_str),
        Some("acme"),
        "x-gateway-tenant header must be injected"
    );
    assert!(body.get("_meta").is_none() || body["_meta"].is_null(), "_meta must NOT be injected for headers target");
}

// ── both target (injection_target absent → defaults to Both) ─────────────────

#[tokio::test(flavor = "multi_thread")]
async fn outbound_mcp_custom_metadata_default_target_injects_meta_and_headers() {
    let mock = MockServer::start_with_response(mcp_ok_response()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![build_mcp_outbound_surface(json!({
            "enabled": true,
            "payload": { "tenant": "acme" }
        }))];
    })
    .await;

    let resp = send_mcp_outbound(&h).await;
    assert_eq!(resp.status(), 200);

    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock received no request");
    let body: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body must be valid JSON");

    assert_eq!(body["_meta"]["tenant"], "acme", "_meta.tenant must be injected");
    assert_eq!(
        received
            .headers
            .get("x-gateway-tenant")
            .map(String::as_str),
        Some("acme"),
        "x-gateway-tenant header must be injected"
    );
}

// ── disabled flag ─────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn outbound_mcp_custom_metadata_disabled_passes_body_unchanged() {
    let mock = MockServer::start_with_response(mcp_ok_response()).await;

    let h = GatewayHarness::start_with_outbound_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![build_mcp_outbound_surface(json!({
            "enabled": false,
            "payload": { "tenant": "acme" }
        }))];
    })
    .await;

    let resp = send_mcp_outbound(&h).await;
    assert_eq!(resp.status(), 200);

    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock received no request");
    let body: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body must be valid JSON");

    assert!(
        body.get("_meta").is_none() || body["_meta"].is_null(),
        "_meta must NOT be injected when custom_metadata is disabled"
    );
    assert!(
        !received
            .headers
            .contains_key("x-gateway-tenant"),
        "x-gateway-tenant header must NOT be present when custom_metadata is disabled"
    );
}
