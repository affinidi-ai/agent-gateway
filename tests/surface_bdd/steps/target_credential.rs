use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::assertions::assert_json_body_mentions;
use crate::bdd_support::caller::post_raw_path;
use crate::bdd_support::json_rpc::build_mcp_list_tools_body_with_id;
use crate::bdd_support::mock_server::MockResponse;
use crate::steps::given::transit_point_config_mut;
use crate::steps::when::{
    build_request_body, ensure_admin_session, ensure_gateway_running, record_mock_observation,
    record_replacement_mock_observation, send_mcp_request_through_transit_point, send_request_and_record,
};
use crate::world::{RecordedResponse, SurfaceSourceAuthConfig, SurfaceTargetAuthConfig, SurfaceWorld};

fn before_the_gateway_starts(
    world: &SurfaceWorld,
    what: &str,
) {
    assert!(world.infra.is_none(), "{what} must be set before the gateway starts");
}

async fn redirect_every_request(
    world: &mut SurfaceWorld,
    name: &str,
    kind: TargetActorKind,
    path: &str,
) {
    world
        .actors
        .expect_target_kind(name, kind);
    ensure_gateway_running(world).await;
    let mock = world.mock_for_target(name);
    let mut redirect = MockResponse::json(json!({}));
    redirect.status = 302;
    redirect
        .headers
        .insert("location".to_string(), format!("{}{path}", mock.url()));
    mock.set_response(redirect)
        .await;
}

async fn send_raw_and_record(
    world: &mut SurfaceWorld,
    port: u16,
    path: &str,
    body: Value,
) {
    let response = post_raw_path(port, path, &body.to_string(), &[])
        .await
        .unwrap_or_else(|error| panic!("POST {path} exactly as written: {error:#}"));
    world.sent_body = Some(body);
    world.caller_response = Some(RecordedResponse {
        status: response.status,
        headers: response.headers,
        body: response.body,
    });
    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

fn is_target_credential_refusal(event: &Value) -> bool {
    event["event"]["request_rejected"]["reason"] == "target_auth_failed"
}

async fn target_credential_refusals(world: &mut SurfaceWorld) -> (bool, Vec<Value>) {
    ensure_admin_session(world).await;
    world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .wait_for_audit_event(is_target_credential_refusal)
        .await
        .unwrap_or_else(|error| panic!("the VP Audit Log must be readable: {error:#}"))
}

/// Expects a `target_auth_failed` refusal with `outcome` and `oauth_error`, recorded for the
/// credential of `transit_point`, or for the Target's own credential when that is `None`.
async fn expect_target_credential_refusal(
    world: &mut SurfaceWorld,
    outcome: &str,
    oauth_error: Option<&str>,
    transit_point: Option<&str>,
) {
    let (_, events) = target_credential_refusals(world).await;
    let refusals: Vec<&Value> = events
        .iter()
        .filter(|event| is_target_credential_refusal(event))
        .collect();
    let expected_error = oauth_error.map_or(Value::Null, |code| json!(code));
    let expected_transit_point = transit_point.map_or(Value::Null, |alias| json!(alias));
    assert!(
        refusals.iter().any(|event| {
            let detail = &event["event"]["request_rejected"]["target_auth"];
            detail["outcome"] == outcome
                && detail["oauth_error"] == expected_error
                && detail["transit_point"] == expected_transit_point
        }),
        "expected a target_auth_failed refusal with outcome {outcome}, OAuth error {oauth_error:?} and Transit Point \
         {transit_point:?}, got {refusals:?}"
    );
}

/// The harness serves every collaborator from a mock on a plain http loopback address, so this
/// names that default rather than changing it; the gateway start checks the URL it writes.
fn reached_over_plain_http(
    world: &mut SurfaceWorld,
    name: &str,
    kind: TargetActorKind,
) {
    before_the_gateway_starts(world, "how a collaborator is reached");
    world
        .actors
        .expect_target_kind(name, kind);
    let collaborator_key = world
        .actors
        .target_collaborator_key(name)
        .to_string();
    world
        .plain_http_collaborators
        .push(collaborator_key);
}

#[given(expr = "managed agent {string} is reached over plain http")]
fn managed_agent_is_reached_over_plain_http(
    world: &mut SurfaceWorld,
    name: String,
) {
    reached_over_plain_http(world, &name, TargetActorKind::ManagedAgent);
}

#[given(expr = "MCP server {string} is reached over plain http")]
fn mcp_server_is_reached_over_plain_http(
    world: &mut SurfaceWorld,
    name: String,
) {
    reached_over_plain_http(world, &name, TargetActorKind::McpServer);
}

#[given("the surface's Access Point does not check its callers")]
fn access_point_checks_no_caller(world: &mut SurfaceWorld) {
    before_the_gateway_starts(world, "the Access Point's source authentication");
    world
        .surface_config
        .source_auth = None;
}

#[given(
    expr = "the surface's Access Point forwards the token of a caller its JWT Bearer method verifies to managed agent {string}"
)]
fn access_point_forwards_verified_jwt_bearer_token(
    world: &mut SurfaceWorld,
    name: String,
) {
    world
        .actors
        .expect_target_kind(&name, TargetActorKind::ManagedAgent);
    before_the_gateway_starts(world, "forwarding the caller's JWT Bearer token");
    let surface = &mut world.surface_config;
    let jwt_bearer = surface
        .source_auth
        .iter_mut()
        .chain(
            surface
                .additional_source_auth
                .iter_mut(),
        )
        .find_map(|auth| match auth {
            SurfaceSourceAuthConfig::JwtBearer(config) => Some(config),
            SurfaceSourceAuthConfig::ApiKey(_) | SurfaceSourceAuthConfig::ApiKeyProvider(_) => None,
        })
        .expect("the surface must accept JWT Bearer source authentication first");
    jwt_bearer.forward_header = true;
}

#[given(expr = "Transit Point {string} is an Open Transit Point")]
fn transit_point_is_open(
    world: &mut SurfaceWorld,
    transit_point: String,
) {
    before_the_gateway_starts(world, "how a Transit Point checks its callers");
    let point = transit_point_config_mut(world, &transit_point);
    point.require_transit_token = false;
    point.source_auth = None;
    point.allow_unauthenticated_callers = true;
}

#[given(
    expr = "the gateway authenticates to the destination of Transit Point {string} with missing secret {string} in header {string}, falling back to {string}"
)]
fn transit_point_authenticates_with_missing_secret(
    world: &mut SurfaceWorld,
    transit_point: String,
    secret_id: String,
    header_name: String,
    fallback: String,
) {
    before_the_gateway_starts(world, "the Transit Point's Target authentication");
    transit_point_config_mut(world, &transit_point).target_auth_secret = Some(SurfaceTargetAuthConfig {
        secret_id,
        header_name,
        header_format: "{value}".to_string(),
        fallback,
        secret_value: None,
    });
}

#[given(expr = "the gateway's authentication to the destination of Transit Point {string} falls back to {string}")]
fn transit_point_target_auth_fallback(
    world: &mut SurfaceWorld,
    transit_point: String,
    fallback: String,
) {
    before_the_gateway_starts(world, "the Transit Point's Target authentication");
    let point = transit_point_config_mut(world, &transit_point);
    assert!(
        point.target_auth_provider,
        "the gateway must authenticate to the destination of Transit Point {transit_point} with a credential provider first"
    );
    point.target_auth_fallback = fallback;
}

#[given(expr = "the surface's Target endpoint has the base path {string}")]
fn target_endpoint_has_base_path(
    world: &mut SurfaceWorld,
    path: String,
) {
    before_the_gateway_starts(world, "the Target endpoint");
    world
        .surface_config
        .target_base_path = Some(path);
}

#[given(expr = "the MCP proxy's base URL has the base path {string}")]
fn mcp_proxy_base_url_has_base_path(
    world: &mut SurfaceWorld,
    path: String,
) {
    before_the_gateway_starts(world, "the MCP proxy base URL");
    world
        .surface_config
        .target_base_path = Some(path);
}

#[given("the MCP proxy's base URL is an https URL")]
fn mcp_proxy_base_url_is_https(world: &mut SurfaceWorld) {
    before_the_gateway_starts(world, "the MCP proxy base URL");
    world
        .surface_config
        .mcp_proxy_target
        .as_mut()
        .expect("background must register an MCP proxy target before its base URL is set")
        .https_base_url = true;
}

#[given(expr = "the target endpoint of Transit Point {string} has the base path {string}")]
fn transit_point_target_endpoint_has_base_path(
    world: &mut SurfaceWorld,
    transit_point: String,
    path: String,
) {
    before_the_gateway_starts(world, "the Transit Point target endpoint");
    transit_point_config_mut(world, &transit_point).target_base_path = Some(path);
}

#[given(expr = "managed agent {string} answers every request with a redirect to its path {string}")]
async fn managed_agent_redirects_every_request(
    world: &mut SurfaceWorld,
    name: String,
    path: String,
) {
    redirect_every_request(world, &name, TargetActorKind::ManagedAgent, &path).await;
}

#[given(expr = "MCP server {string} answers every request with a redirect to its path {string}")]
async fn mcp_server_redirects_every_request(
    world: &mut SurfaceWorld,
    name: String,
    path: String,
) {
    redirect_every_request(world, &name, TargetActorKind::McpServer, &path).await;
}

#[given(expr = "REST API {string} answers every request with a redirect to its path {string}")]
async fn rest_api_redirects_every_request(
    world: &mut SurfaceWorld,
    name: String,
    path: String,
) {
    redirect_every_request(world, &name, TargetActorKind::RestApi, &path).await;
}

#[given(expr = "MCP server {string} refuses every request with status 401 and the challenge {string}")]
async fn mcp_server_refuses_every_request(
    world: &mut SurfaceWorld,
    name: String,
    challenge: String,
) {
    world
        .actors
        .expect_target_kind(&name, TargetActorKind::McpServer);
    ensure_gateway_running(world).await;
    let mut refusal = MockResponse::json(json!({"error": "unauthorized"}));
    refusal.status = 401;
    refusal
        .headers
        .insert("www-authenticate".to_string(), challenge);
    world
        .mock_for_target(&name)
        .set_response(refusal)
        .await;
}

#[given(
    expr = "managed agent {string} has asked for available tools through Transit Point {string} and received status {int}"
)]
async fn managed_agent_has_asked_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    transit_point: String,
    expected: u16,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let body = build_mcp_list_tools_body_with_id(json!("mcp-tools-list-alpha"));
    send_mcp_request_through_transit_point(world, &agent_name, &transit_point, body).await;
    let status = world
        .caller_response
        .as_ref()
        .map(|response| response.status);
    assert_eq!(
        status,
        Some(expected),
        "the first request through Transit Point {transit_point} must answer {expected}"
    );
}

#[when(expr = "the caller sends a request to the surface path {string} exactly as written")]
async fn caller_sends_raw_request(
    world: &mut SurfaceWorld,
    path: String,
) {
    ensure_gateway_running(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway is running")
        .gateway_port;
    let body = build_request_body(&world.surface_config.protocol);
    send_raw_and_record(world, port, &path, body).await;
}

#[when(
    expr = "managed agent {string} asks for available tools through the Transit Point path {string} exactly as written"
)]
async fn managed_agent_sends_raw_transit_request(
    world: &mut SurfaceWorld,
    agent_name: String,
    path: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    ensure_gateway_running(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway is running")
        .outbound_port;
    let body = build_mcp_list_tools_body_with_id(json!("mcp-tools-list-alpha"));
    send_raw_and_record(world, port, &path, body).await;
}

#[when(expr = "the caller sends a request to the surface with header {string} set to {string}")]
async fn caller_sends_request_with_header(
    world: &mut SurfaceWorld,
    name: String,
    value: String,
) {
    send_request_and_record(world, vec![(name, value)]).await;
}

#[then(expr = "the response mentions {string}")]
fn response_mentions(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("the caller must have received a response");
    assert_json_body_mentions(&response.body, &expected, "caller response");
}

#[then(expr = "the response header {string} points at path {string} of managed agent {string}")]
fn response_header_points_at_managed_agent(
    world: &mut SurfaceWorld,
    header: String,
    path: String,
    agent_name: String,
) {
    let expected = format!(
        "{}{path}",
        world
            .mock_for_target(&agent_name)
            .url()
    );
    let response = world
        .caller_response
        .as_ref()
        .expect("the caller must have received a response");
    let actual = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&header))
        .map(|(_, value)| value.as_str());
    assert_eq!(actual, Some(expected.as_str()), "response headers: {:?}", response.headers);
}

#[then(expr = "MCP server {string} received the forwarded path {string}")]
async fn mcp_server_received_path(
    world: &mut SurfaceWorld,
    name: String,
    expected: String,
) {
    let request = world
        .mock_for_target(&name)
        .last_request()
        .await
        .unwrap_or_else(|| panic!("MCP server {name} received no request"));
    assert_eq!(request.path_and_query, expected);
}

#[then(
    expr = "the VP Audit Log records a Target credential that was not sent, with outcome {string} and OAuth error {string}"
)]
async fn vp_audit_log_records_refusal_with_oauth_error(
    world: &mut SurfaceWorld,
    outcome: String,
    oauth_error: String,
) {
    expect_target_credential_refusal(world, &outcome, Some(&oauth_error), None).await;
}

#[then(
    expr = "the VP Audit Log records a Target credential that was not sent, with outcome {string} and no OAuth error"
)]
async fn vp_audit_log_records_refusal_without_oauth_error(
    world: &mut SurfaceWorld,
    outcome: String,
) {
    expect_target_credential_refusal(world, &outcome, None, None).await;
}

#[then(
    expr = "the VP Audit Log records a Target credential of Transit Point {string} that was not sent, with outcome {string}"
)]
async fn vp_audit_log_records_transit_point_refusal(
    world: &mut SurfaceWorld,
    transit_point: String,
    outcome: String,
) {
    expect_target_credential_refusal(world, &outcome, None, Some(&transit_point)).await;
}

fn is_invalid_envelope_marker(event: &Value) -> bool {
    event["event"]["request_rejected"]["reason"] == "invalid_envelope"
}

/// Sends the surface a body that is no JSON-RPC envelope, which is refused before any Target
/// credential is resolved, and waits for its `invalid_envelope` record. Records reach the VP
/// Audit Log in the order they are made, so a refusal made by an earlier request is in the log
/// by the time this marker is.
#[then("the VP Audit Log records no Target credential that was not sent")]
async fn vp_audit_log_records_no_refusal(world: &mut SurfaceWorld) {
    let port = world
        .infra
        .as_ref()
        .expect("the gateway is running")
        .gateway_port;
    let route = world
        .surface_config
        .route
        .clone();
    let marker = post_raw_path(port, &route, "{}", &[])
        .await
        .unwrap_or_else(|error| panic!("POST a body that is no JSON-RPC envelope: {error:#}"));
    assert_eq!(marker.status, 400, "the marker request must be refused before the Target");
    ensure_admin_session(world).await;
    let (marked, events) = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .wait_for_audit_event(is_invalid_envelope_marker)
        .await
        .unwrap_or_else(|error| panic!("the VP Audit Log must be readable: {error:#}"));
    assert!(marked, "expected the marker's invalid_envelope record, got {events:?}");
    let refusals: Vec<&Value> = events
        .iter()
        .filter(|event| is_target_credential_refusal(event))
        .collect();
    assert!(refusals.is_empty(), "expected no target_auth_failed refusal, got {refusals:?}");
}
