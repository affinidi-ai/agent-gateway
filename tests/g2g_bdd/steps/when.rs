//! When steps — caller actions against a surface. The first action boots the
//! topology (`G2gWorld::start`) before sending.

use cucumber::when;
use futures::future::join_all;
use reqwest::Client;
use serde_json::Value;
use tokio::time::{Duration, timeout};

use crate::bdd_support::caller::post_json;
use crate::bdd_support::http::{collect_headers, parse_json_or_sse_body};
use crate::bdd_support::json_rpc::{
    attach_agent_identity_payload, attach_identity_proof, build_a2a_request_body, build_mcp_echo_request_bodies,
    build_mcp_initialize_body, build_mcp_initialized_notification_body, build_mcp_list_tools_body,
    build_mcp_request_without_method_body, build_mcp_tool_call_body, build_modern_mcp_list_tools_body,
    modern_mcp_request_headers,
};
use crate::world::{ConcurrentResponse, ConformanceRun, G2gWorld};

const CONCURRENT_MCP_TIMEOUT: Duration = Duration::from_secs(90);

/// The managed agent calls its gateway's outbound listener. What it presents
/// follows from its state: the `agent-identity/v1` payload when its surface
/// derives the managed identity from the payload, and any identity proof it
/// obtained earlier in the scenario.
pub(crate) async fn send_a2a_request_through_transit_point(
    world: &mut G2gWorld,
    agent_name: &str,
    transit_point: &str,
    headers: Vec<(String, String)>,
) {
    world
        .topology
        .actors
        .expect_target_kind(agent_name, crate::bdd_support::actors::TargetActorKind::ManagedAgent);
    world.start().await;
    world
        .remember_fabric_forward_baseline()
        .await;

    let link = world
        .transit_point_link(transit_point)
        .clone();
    let gw_index = link.from_gw;
    let gateway = world.harness().gw(gw_index);
    let outbound_port = gateway
        .outbound_port
        .unwrap_or_else(|| panic!("gateway {gw_index} has no outbound listener for Transit Point '{transit_point}'"));
    let url = format!("http://127.0.0.1:{outbound_port}/transit/{transit_point}");
    let mut body = build_a2a_request_body();
    if world
        .surface_spec(gw_index, &link.from_surface)
        .managed_identity
    {
        attach_agent_identity_payload(&mut body);
    }
    if let Some(proof) = world
        .obtained_identity_proofs
        .get(agent_name)
    {
        attach_identity_proof(&mut body, proof);
    }
    world.sent_body = Some(body.clone());

    let client = Client::new();
    let response = post_json(&client, &url, &body, &headers)
        .await
        .expect("managed agent Transit Point request must succeed at the transport layer");
    world.response_status = Some(response.status);
    world.response_content_type = response.content_type;
    world.response_body = Some(response.body);
}

#[when(
    regex = r#"^managed agent \"([^\"]+)\" sends an A2A message/send request through Transit Point \"([^\"]+)\" with header \"([^\"]+)\" set to \"([^\"]+)\" and header \"([^\"]+)\" set to \"([^\"]+)\"$"#
)]
pub async fn managed_agent_sends_a2a_request_through_transit_point_with_two_headers(
    world: &mut G2gWorld,
    agent_name: String,
    transit_point: String,
    first_header: String,
    first_value: String,
    second_header: String,
    second_value: String,
) {
    send_a2a_request_through_transit_point(
        world,
        &agent_name,
        &transit_point,
        vec![(first_header, first_value), (second_header, second_value)],
    )
    .await;
}

#[when(regex = r#"^managed agent "([^"]+)" sends an A2A message/send request through Transit Point "([^"]+)"$"#)]
pub async fn managed_agent_sends_a2a_request_through_transit_point(
    world: &mut G2gWorld,
    agent_name: String,
    transit_point: String,
) {
    send_a2a_request_through_transit_point(world, &agent_name, &transit_point, Vec::new()).await;
}

#[when(expr = "the caller sends a Fabric A2A request through gateway {int} surface {string}")]
pub async fn a2a_request_sent_to_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(world, gw_index, &surface_name, build_a2a_request_body(), &[]).await;
}

/// Send a Fabric A2A request carrying a specific JSON-RPC method name.
///
/// Proves a v1.0 method survives the DIDComm hop between gateways unchanged: the
/// gateway forwards the method as-sent and never translates between protocol eras,
/// so whatever the caller wrote must arrive at the remote managed agent verbatim.
#[when(expr = "the caller sends Fabric A2A method {string} through gateway {int} surface {string}")]
pub async fn a2a_method_request_sent_to_surface(
    world: &mut G2gWorld,
    method: String,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    let mut body = build_a2a_request_body();
    body["method"] = serde_json::json!(method);
    send_rpc(world, gw_index, &surface_name, body, &[]).await;
}

#[when(regex = r#"^the caller asks gateway (\d+) surface "([^"]+)" for available MCP tools$"#)]
pub async fn mcp_list_tools_sent_to_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(world, gw_index, &surface_name, build_mcp_list_tools_body(), &[]).await;
}

/// The caller's own `Authorization` is for the gateway it calls, never for
/// the remote Target.
#[when(expr = "the caller asks gateway {int} surface {string} for available MCP tools with bearer token {string}")]
pub async fn mcp_list_tools_sent_with_caller_bearer(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
    token: String,
) {
    world.start().await;
    let headers = [("authorization".to_string(), format!("Bearer {token}"))];
    send_rpc(world, gw_index, &surface_name, build_mcp_list_tools_body(), &headers).await;
}

#[when(expr = "the caller asks gateway {int} surface {string} for available MCP tools using protocol version {string}")]
pub async fn modern_mcp_list_tools_sent_to_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
    protocol_version: String,
) {
    world.start().await;
    let body = build_modern_mcp_list_tools_body(serde_json::json!("modern-mcp-tools-list"), &protocol_version, true);
    let headers = modern_mcp_request_headers(&protocol_version, "tools/list");
    send_rpc(world, gw_index, &surface_name, body, &headers).await;
}

#[when(
    expr = "the caller asks gateway {int} surface {string} for available MCP tools with top-level metadata key {string} value {string}"
)]
async fn caller_sends_historical_metadata_over_fabric(
    world: &mut G2gWorld,
    gateway: usize,
    surface: String,
    key: String,
    value: String,
) {
    world.start().await;
    let mut body = build_mcp_list_tools_body();
    body["_meta"] = serde_json::json!({key: value});
    send_rpc(world, gateway, &surface, body, &[]).await;
}

#[when(expr = "the operator reads the Remote gateway records on both gateways")]
pub async fn operator_reads_remote_gateway_records_on_both_gateways(world: &mut G2gWorld) {
    world.start().await;
    let count = world
        .topology
        .gateway_count
        .max(1);
    assert_eq!(count, 2, "this step reads the records of a two-gateway fabric, got {count} gateways");
    for gw_index in 1..=count {
        let records = world
            .harness()
            .gw(gw_index)
            .admin
            .remote_gateways()
            .await
            .unwrap_or_else(|error| panic!("read Remote gateway records on gateway {gw_index}: {error:#}"));
        world
            .remote_gateway_records
            .insert(gw_index, records);
    }
}

#[when(expr = "gateway {int} requests the issuer DID of gateway {int}")]
pub async fn gateway_requests_issuer_did_of_peer(
    world: &mut G2gWorld,
    gw_index: usize,
    peer_gw: usize,
) {
    world.start().await;
    let harness = world.harness();
    let remote_id = harness
        .remote_id(gw_index, peer_gw)
        .unwrap_or_else(|| panic!("gateway {gw_index} holds no Remote record for gateway {peer_gw}"))
        .to_string();
    let response = harness
        .gw(gw_index)
        .admin
        .request_gateway_issuer(&remote_id)
        .await
        .unwrap_or_else(|error| panic!("gateway {gw_index} issuer request for gateway {peer_gw}: {error:#}"));
    assert_eq!(response.gateway_id, remote_id, "issuer response should name the requested Remote gateway record");
    world.issuer_request_result = Some((peer_gw, response.issuer_did));
}

#[when(expr = "gateway {int} restarts")]
pub async fn gateway_restarts(
    world: &mut G2gWorld,
    gw_index: usize,
) {
    world.start().await;
    world
        .harness_mut()
        .restart_gateway(gw_index)
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
}

#[when(regex = r"^gateway (\d+) pings gateway (\d+)$")]
pub async fn gateway_pings_gateway(
    world: &mut G2gWorld,
    from_gw: usize,
    to_gw: usize,
) {
    world.start().await;
    let success = world
        .harness()
        .ping(from_gw, to_gw)
        .await
        .expect("gateway ping request should complete");
    world
        .ping_results
        .insert((from_gw, to_gw), success);
}

#[when(regex = r#"^the caller asks gateway (\d+) surface "([^"]+)" for available MCP tools with a valid API key$"#)]
pub async fn mcp_list_tools_sent_with_api_key(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    let api_key = "bdd-source-api-key".to_string();
    let header = "x-api-key".to_string();
    world.start().await;
    send_rpc(world, gw_index, &surface_name, build_mcp_list_tools_body(), &[(header, api_key)]).await;
}

#[when(regex = r#"^the caller asks gateway (\d+) surface "([^"]+)" for available MCP tools without an API key$"#)]
pub async fn mcp_list_tools_sent_without_credentials(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(world, gw_index, &surface_name, build_mcp_list_tools_body(), &[]).await;
}

/// MCP Streamable HTTP: caller advertises `Accept: text/event-stream`, so the
/// gateway wraps the JSON-RPC response as a single SSE `message` event.
#[when(regex = r#"^the caller asks gateway (\d+) surface "([^"]+)" for available MCP tools over SSE$"#)]
pub async fn mcp_list_tools_sent_over_sse(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(
        world,
        gw_index,
        &surface_name,
        build_mcp_list_tools_body(),
        &[("accept".to_string(), "text/event-stream".to_string())],
    )
    .await;
}

/// Two `tools/list` calls, with distinct ids, over one session of the deprecated HTTP+SSE
/// transport (`GET {route}/sse`, then POSTs to the announced session URL).
/// Each POST must be accepted with `202` and answered by an SSE `message`
/// event. Each request is recorded with its reply.
#[when(
    expr = "the caller asks gateway {int} surface {string} for available MCP tools twice over one Legacy SSE session"
)]
pub async fn mcp_list_tools_twice_over_legacy_sse(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    world
        .remember_fabric_forward_baseline()
        .await;
    let (_, surface_id) = world.surface(&surface_name);
    let route = world
        .surface_spec(gw_index, &surface_id)
        .route
        .clone();
    let port = world
        .harness()
        .gw(gw_index)
        .port;
    // Distinct ids, as a real client sends, so the target sees two requests.
    let bodies = ["legacy-sse-1", "legacy-sse-2"].map(|id| {
        let mut body = build_mcp_list_tools_body();
        body["id"] = Value::from(id);
        body
    });
    world.sent_body = bodies.last().cloned();
    let replies =
        crate::bdd_support::sse_client::legacy_sse_session_calls(&format!("http://127.0.0.1:{port}"), &route, &bodies)
            .await
            .unwrap_or_else(|error| {
                panic!("Legacy SSE session on gateway {gw_index} surface {surface_name}: {error:#}")
            });
    world.response_body = replies.last().cloned();
    world.legacy_sse_exchange = bodies
        .into_iter()
        .zip(replies)
        .collect();
}

#[when(regex = r#"^the caller sends an MCP initialize request to gateway (\d+) surface "([^"]+)"$"#)]
pub async fn mcp_initialize_sent_to_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(world, gw_index, &surface_name, build_mcp_initialize_body(serde_json::json!(4242)), &[]).await;
}

#[when(
    regex = r#"^the caller sends an MCP initialize request with content type "([^"]+)" to gateway (\d+) surface "([^"]+)"$"#
)]
pub async fn mcp_initialize_sent_with_content_type(
    world: &mut G2gWorld,
    content_type: String,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_raw_rpc_body(
        world,
        gw_index,
        &surface_name,
        Some(build_mcp_initialize_body(serde_json::json!(4242))),
        content_type,
    )
    .await;
}

#[when(
    regex = r#"^the caller invokes MCP tool "([^"]+)" with a result limit of (\d+) through gateway (\d+) surface "([^"]+)"$"#
)]
pub async fn mcp_tool_call_sent_to_surface_with_limit(
    world: &mut G2gWorld,
    tool_name: String,
    limit: i64,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(
        world,
        gw_index,
        &surface_name,
        build_mcp_tool_call_body(&tool_name, serde_json::json!({ "limit": limit })),
        &[],
    )
    .await;
}

#[when(regex = r#"^the caller invokes MCP tool "([^"]+)" through gateway (\d+) surface "([^"]+)"$"#)]
pub async fn mcp_tool_call_sent_to_surface(
    world: &mut G2gWorld,
    tool_name: String,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(world, gw_index, &surface_name, build_mcp_tool_call_body(&tool_name, serde_json::json!({})), &[]).await;
}

#[when(regex = r#"^the caller sends a malformed MCP request to gateway (\d+) surface "([^"]+)"$"#)]
pub async fn malformed_mcp_request_sent_to_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_raw_string(world, gw_index, &surface_name, "{\"jsonrpc\":", "application/json").await;
}

#[when(regex = r#"^the caller sends an MCP request without a method to gateway (\d+) surface "([^"]+)"$"#)]
pub async fn mcp_request_without_method_sent_to_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(
        world,
        gw_index,
        &surface_name,
        build_mcp_request_without_method_body(serde_json::json!("mcp-missing-method")),
        &[],
    )
    .await;
}

#[when(regex = r#"^the caller sends an MCP notification to gateway (\d+) surface "([^"]+)"$"#)]
pub async fn mcp_notification_sent_to_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    send_rpc(world, gw_index, &surface_name, build_mcp_initialized_notification_body(), &[]).await;
}

#[when(regex = r#"^the caller sends (\d+) concurrent MCP Echo calls to gateway (\d+) surface "([^"]+)"$"#)]
pub async fn concurrent_mcp_echo_calls_sent_to_surface(
    world: &mut G2gWorld,
    count: usize,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;

    let (_gw, surface_id) = world.surface(&surface_name);
    let port = world
        .harness()
        .gw(gw_index)
        .port;
    let url = format!("http://127.0.0.1:{port}/{surface_id}/rpc");
    let client = Client::new();
    let bodies = build_mcp_echo_request_bodies(count);

    world.concurrent_requests = bodies.clone();
    world
        .concurrent_responses
        .clear();
    world
        .remember_fabric_forward_baseline()
        .await;

    let calls = bodies
        .into_iter()
        .map(|body| {
            let client = client.clone();
            let url = url.clone();
            async move { send_concurrent_rpc(client, url, body).await }
        });
    let responses = timeout(CONCURRENT_MCP_TIMEOUT, join_all(calls))
        .await
        .expect("concurrent MCP calls should complete before timeout");

    world.concurrent_responses = responses;
}

async fn send_concurrent_rpc(
    client: Client,
    url: String,
    body: Value,
) -> ConcurrentResponse {
    let request_id = body
        .get("id")
        .cloned()
        .expect("concurrent MCP request must include JSON-RPC id");
    let response = post_json(&client, &url, &body, &[])
        .await
        .expect("caller request must succeed at the transport layer");

    ConcurrentResponse {
        request_id,
        status: response.status,
        body: response.body,
        content_type: response.content_type,
    }
}

/// POST a JSON-RPC body to `{gw_port}{route}/rpc` with optional extra headers
/// and record the response. An SSE-framed body (`text/event-stream`) is decoded
/// to its inner JSON-RPC payload so the standard Then steps still apply.
pub(crate) async fn send_rpc(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: &str,
    body: serde_json::Value,
    extra_headers: &[(String, String)],
) {
    let (_gw, surface_id) = world.surface(surface_name);
    let retry_transient_timeout = world.expects_allow_only_denial(gw_index, &surface_id);
    world
        .remember_fabric_forward_baseline()
        .await;
    let port = world
        .harness()
        .gw(gw_index)
        .port;
    let url = format!("http://127.0.0.1:{port}/{surface_id}/rpc");

    world.sent_body = Some(body.clone());

    let client = Client::new();
    let response = if retry_transient_timeout {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let response = post_json(&client, &url, &body, extra_headers)
                .await
                .expect("caller request must succeed at the transport layer");
            if response.status != 504 || tokio::time::Instant::now() >= deadline {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    } else {
        post_json(&client, &url, &body, extra_headers)
            .await
            .expect("caller request must succeed at the transport layer")
    };

    world.response_status = Some(response.status);
    world.response_content_type = response.content_type;
    world.response_body = Some(response.body);
}

async fn send_raw_rpc_body(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: &str,
    body: Option<Value>,
    content_type: String,
) {
    let raw_body = body
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .expect("serialize raw JSON-RPC body")
        .unwrap_or_default();
    world.sent_body = body;
    send_raw_string(world, gw_index, surface_name, &raw_body, &content_type).await;
}

async fn send_raw_string(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: &str,
    raw_body: &str,
    content_type: &str,
) {
    let (_gw, surface_id) = world.surface(surface_name);
    world
        .remember_fabric_forward_baseline()
        .await;
    let port = world
        .harness()
        .gw(gw_index)
        .port;
    let url = format!("http://127.0.0.1:{port}/{surface_id}/rpc");

    let response = Client::new()
        .post(&url)
        .header("content-type", content_type)
        .body(raw_body.to_string())
        .send()
        .await
        .expect("caller request must succeed at the transport layer");

    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let content_type = headers
        .get("content-type")
        .cloned();
    let raw = response
        .text()
        .await
        .unwrap_or_default();
    let body = parse_json_or_sse_body(&raw, content_type.as_deref());

    world.response_status = Some(status);
    world.response_content_type = content_type;
    world.response_body = Some(body);
}

fn conformance_setting(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set; run this feature through scripts/mcp-conformance/run.sh"))
}

/// Runs the MCP conformance suite against a surface. `run.sh` names the suite
/// CLI, the requirement set, the baseline, and where results and the log go.
#[when(expr = "the MCP conformance suite runs against gateway {int} surface {string}")]
pub async fn mcp_conformance_suite_runs_against_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    let (_, surface_id) = world.surface(&surface_name);
    let port = world
        .harness()
        .gw(gw_index)
        .port;
    // The exact route: the Access Point forwards a sub-path, and the
    // conformance upstream serves only its own path.
    let url = format!("http://127.0.0.1:{port}/{surface_id}");
    let output = tokio::process::Command::new(conformance_setting("MCP_CONFORMANCE_CLI"))
        .args([
            "server",
            "--url",
            &url,
            "--requirements",
            &conformance_setting("MCP_CONFORMANCE_REQUIREMENTS"),
            "--expected-failures",
            &conformance_setting("MCP_CONFORMANCE_EXPECTED_FAILURES"),
            "-o",
            &conformance_setting("MCP_CONFORMANCE_OUTPUT"),
        ])
        .output()
        .await
        .expect("start the MCP conformance suite");
    let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
    log.push_str(&String::from_utf8_lossy(&output.stderr));
    std::fs::write(conformance_setting("MCP_CONFORMANCE_LOG"), &log).expect("write the MCP conformance suite log");
    world.conformance_run = Some(ConformanceRun {
        passed: output.status.success(),
        output: log,
    });
}
