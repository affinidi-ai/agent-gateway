//! Caller challenge E2E tests
//!
//! A declaring Access Point answers a caller whose token is missing or invalid with an
//! RFC 6750 challenge naming its protected resource metadata, before policy and before
//! the Target, whichever policy plane refuses failed callers; an MCP `tools/call` gets
//! that HTTP challenge, not the JSON-RPC denial. Target challenges other than `Payment`
//! never reach the caller of a declaring Access Point, because the gateway is the
//! resource server there: the dropped schemes are logged, and a Target 401 left without
//! a challenge becomes a 502. An Access Point that does not declare relays every Target
//! challenge unchanged.

use std::path::Path;
use std::sync::atomic::Ordering;

use axum::http::HeaderValue;
use serde_json::{Value, json};

use super::helpers;
use crate::config::{BootstrapConfig, GatewayConfig};
use helpers::jwt::{JwksFixture, now_secs, sign_jwt};
use helpers::{GatewayHarness, MockServer};

const PUBLIC_ORIGIN: &str = "https://gw.example";
const SMOKE_RESOURCE: &str = "https://gw.example/smoke";
const METADATA_URL: &str = "https://gw.example/.well-known/oauth-protected-resource/smoke";
const AUTHORIZATION_SERVER: &str = "https://as.example/";
const STRATEGY_ID: &str = "challenge-strategy";
const DENY_FAILED_POLICY_ID: &str = "deny-failed-callers";
const DENY_FAILED: &str =
    "package surface.policy\ndefault allow := true\nallow := false if input.source_auth.method == \"failed\"\n";
const TOOLS_CALL_ID: i64 = 9;

/// Put [`PUBLIC_ORIGIN`] first in the inbound listener's `external_urls`, keeping the
/// local URL so the listener still matches the surface's `listen_address`.
fn advertise_public_origin(bootstrap: &BootstrapConfig) {
    let path = Path::new(&bootstrap.config_files.gateway);
    let mut network: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read gateway.json")).expect("gateway.json");
    network["listeners"][0]["external_urls"]
        .as_array_mut()
        .expect("external_urls")
        .insert(0, json!(PUBLIC_ORIGIN));
    std::fs::write(path, serde_json::to_string_pretty(&network).expect("serialize gateway.json"))
        .expect("write gateway.json");
}

fn write_strategy(
    temp_dir: &Path,
    fixture: &JwksFixture,
) {
    let strategy = json!({
        "id": STRATEGY_ID,
        "name": "Challenge",
        "expected_issuer": fixture.issuer,
        "jwks_source": { "type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer) },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    let dir = temp_dir.join("jwt_verification_strategies");
    std::fs::create_dir_all(&dir).expect("create strategy dir");
    std::fs::write(dir.join(format!("{STRATEGY_ID}.json")), strategy.to_string()).expect("write strategy");
}

fn write_deny_failed_definition(temp_dir: &Path) {
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{DENY_FAILED_POLICY_ID}.json")),
        json!({
            "id": DENY_FAILED_POLICY_ID, "name": "Deny failed callers", "description": "",
            "policy_type": "agent_surface", "policy": DENY_FAILED, "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        })
        .to_string(),
    )
    .expect("write policy definition");
}

/// Make the local gateway record enforce `rego` as its gateway policy.
fn write_gateway_policy(
    gateways_dir: &str,
    rego: &str,
) {
    let mut gateway = crate::gateways::types::Gateway::new(
        "This Gateway (Local)".to_string(),
        "Local".to_string(),
        "did:web:localhost:8443".to_string(),
        crate::gateways::types::GatewayType::SelfGateway,
    );
    gateway.opa_policy_config = Some(crate::gateways::types::GatewayOpaPolicyConfig {
        enabled: true,
        policy: rego.to_string(),
        ..Default::default()
    });
    std::fs::create_dir_all(gateways_dir).expect("create gateways dir");
    std::fs::write(
        Path::new(gateways_dir).join(format!("{}.json", gateway.id)),
        serde_json::to_string(&gateway).expect("serialize gateway"),
    )
    .expect("write gateway");
}

/// The policy plane that refuses callers whose source authentication failed.
#[derive(Clone, Copy, Debug)]
enum Plane {
    Surface,
    Gateway,
}

/// How the Access Point authenticates its callers.
#[derive(Clone, Copy, Debug)]
enum CallerAuth {
    None,
    ApiKey,
    /// JWT Bearer without a declaration.
    Jwt {
        forward_header: bool,
    },
    /// JWT Bearer with an explicit `protected_resource` (MCP only).
    Declaring,
}

impl CallerAuth {
    fn config(self) -> Option<Value> {
        match self {
            Self::None => None,
            Self::ApiKey => Some(json!({ "methods": [{
                "type": "api_key", "extraction": { "source": "http_header", "field": "X-Caller-Key" },
                "secret_id": "CALLER_KEYS"
            }] })),
            Self::Jwt { forward_header } => Some(json!({ "methods": [{
                "type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID,
                "audiences": [SMOKE_RESOURCE], "forward_header": forward_header
            }] })),
            Self::Declaring => Some(json!({
                "methods": [{ "type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID, "audiences": [] }],
                "protected_resource": { "resource": SMOKE_RESOURCE, "authorization_servers": [AUTHORIZATION_SERVER] }
            })),
        }
    }

    /// The token an admitted caller presents, when the Access Point reads one.
    fn bearer(
        self,
        fixture: &JwksFixture,
    ) -> Option<String> {
        matches!(self, Self::Jwt { .. } | Self::Declaring).then(|| token(fixture))
    }
}

struct Setup {
    caller: CallerAuth,
    mcp: bool,
    deny_in: Option<Plane>,
}

impl Setup {
    /// A surface with no policy, on the protocol `caller` can serve.
    fn relaying(caller: CallerAuth) -> Self {
        Self {
            caller,
            mcp: matches!(caller, CallerAuth::Declaring),
            deny_in: None,
        }
    }

    fn request(&self) -> Value {
        if self.mcp {
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} })
        } else {
            a2a_message()
        }
    }
}

fn surface(setup: &Setup) -> crate::config::agent_surface::AgentSurface {
    let mut access_point = json!({
        "listen_address": "inbound_port_placeholder",
        "route": "/smoke",
        "protocol": if setup.mcp { "mcp" } else { "a2a" }
    });
    if let Some(caller_authentication) = setup.caller.config() {
        access_point["caller_authentication"] = caller_authentication;
    }
    if matches!(setup.deny_in, Some(Plane::Surface)) {
        access_point["inbound_policy"] = json!({ "policy_definition_id": DENY_FAILED_POLICY_ID });
    }
    serde_json::from_value(json!({
        "name": "challenge",
        "access_point": access_point,
        "target": { "endpoint": "inbound_target_placeholder" }
    }))
    .expect("challenge surface")
}

fn configure(
    fixture: &JwksFixture,
    setup: &Setup,
    target: Option<String>,
    temp_dir: &Path,
    gw_config: &mut GatewayConfig,
    bootstrap: &mut BootstrapConfig,
) {
    advertise_public_origin(bootstrap);
    write_strategy(temp_dir, fixture);
    match setup.deny_in {
        Some(Plane::Surface) => write_deny_failed_definition(temp_dir),
        Some(Plane::Gateway) => write_gateway_policy(
            &bootstrap
                .storage_paths
                .gateways,
            &DENY_FAILED.replace("surface.policy", "gateway.policy"),
        ),
        None => {}
    }
    let mut surface = surface(setup);
    if let Some(target) = target {
        surface.target.endpoint = target;
    }
    gw_config.surfaces = vec![surface];
}

async fn start(
    fixture: &JwksFixture,
    mock: MockServer,
    setup: &Setup,
) -> GatewayHarness {
    GatewayHarness::start_with_mock(mock, |temp_dir, gw_config, bootstrap| {
        configure(fixture, setup, None, temp_dir, gw_config, bootstrap)
    })
    .await
}

fn token(fixture: &JwksFixture) -> String {
    token_with(fixture, None)
}

fn token_with(
    fixture: &JwksFixture,
    scope: Option<&str>,
) -> String {
    let mut claims = json!({
        "iss": fixture.issuer, "sub": "client", "aud": SMOKE_RESOURCE,
        "exp": now_secs() + 300, "iat": now_secs(),
    });
    if let Some(scope) = scope {
        claims["scope"] = json!(scope);
    }
    sign_jwt(claims, &fixture.kid)
}

async fn tools_mock() -> MockServer {
    MockServer::start_with_response(json!({ "jsonrpc": "2.0", "id": 1, "result": { "tools": [] } }).to_string()).await
}

fn target_calls(h: &GatewayHarness) -> usize {
    h.mock
        .request_count
        .load(Ordering::SeqCst)
}

struct Answer {
    status: u16,
    challenges: Vec<String>,
    headers: reqwest::header::HeaderMap,
}

fn a2a_message() -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": { "message": { "role": "user", "kind": "message", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] } }
    })
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client")
}

async fn send(
    h: &GatewayHarness,
    setup: &Setup,
    bearer: Option<&str>,
) -> (Answer, Value) {
    send_body(h, bearer, setup.request(), None).await
}

async fn call_tool(
    h: &GatewayHarness,
    bearer: Option<&str>,
) -> (Answer, Value) {
    let body = json!({
        "jsonrpc": "2.0", "id": TOOLS_CALL_ID, "method": "tools/call", "params": { "name": "echo", "arguments": {} }
    });
    send_body(h, bearer, body, Some("application/json, text/event-stream")).await
}

async fn send_body(
    h: &GatewayHarness,
    bearer: Option<&str>,
    body: Value,
    accept: Option<&str>,
) -> (Answer, Value) {
    let mut request = client()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(body.to_string());
    if let Some(accept) = accept {
        request = request.header("accept", accept);
    }
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let response = request
        .send()
        .await
        .expect("request");
    let answer = Answer {
        status: response.status().as_u16(),
        challenges: response
            .headers()
            .get_all("www-authenticate")
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .expect("ascii challenge")
                    .to_string()
            })
            .collect(),
        headers: response.headers().clone(),
    };
    let text = response
        .text()
        .await
        .expect("response body");
    (answer, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

fn challenge(error: Option<&str>) -> Vec<String> {
    let error = error
        .map(|error| format!(", error=\"{error}\""))
        .unwrap_or_default();
    vec![format!("Bearer resource_metadata=\"{METADATA_URL}\"{error}")]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_mcp_access_point_without_policy_challenges_a_failed_caller_before_the_target() {
    let fixture = JwksFixture::start().await;
    let setup = Setup {
        caller: CallerAuth::Declaring,
        mcp: true,
        deny_in: None,
    };
    let h = start(&fixture, tools_mock().await, &setup).await;

    let (missing, body) = send(&h, &setup, None).await;
    assert_eq!((missing.status, missing.challenges), (401, challenge(None)), "{body}");
    assert_eq!(missing.headers["content-type"], "application/problem+json");
    assert_eq!(missing.headers["cache-control"], "no-store");
    assert_eq!(body["status"], 401);
    let (invalid, body) = send(&h, &setup, Some("not-a-jwt")).await;
    assert_eq!((invalid.status, invalid.challenges), (401, challenge(Some("invalid_token"))), "{body}");
    assert_eq!(target_calls(&h), 0, "no refused caller reached the target");

    let (admitted, body) = send(&h, &setup, Some(&token(&fixture))).await;
    assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);

    let metadata: Value = client()
        .get(format!("{}/.well-known/oauth-protected-resource/smoke", h.gateway_base))
        .send()
        .await
        .expect("metadata request")
        .json()
        .await
        .expect("metadata JSON");
    assert_eq!(metadata["resource"], SMOKE_RESOURCE, "the challenge points at the metadata the gateway serves");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_challenged_mcp_tools_call_gets_the_http_challenge_whichever_plane_refuses_failed_callers() {
    let fixture = JwksFixture::start().await;
    for deny_in in [None, Some(Plane::Surface), Some(Plane::Gateway)] {
        let setup = Setup {
            caller: CallerAuth::Declaring,
            mcp: true,
            deny_in,
        };
        let h = start(&fixture, MockServer::start().await, &setup).await;
        let (missing, _) = call_tool(&h, None).await;
        assert_eq!((missing.status, missing.challenges), (401, challenge(None)), "{deny_in:?}");
        let (invalid, _) = call_tool(&h, Some("not-a-jwt")).await;
        assert_eq!((invalid.status, invalid.challenges), (401, challenge(Some("invalid_token"))), "{deny_in:?}");
        assert_eq!(target_calls(&h), 0, "{deny_in:?}: no refused caller reached the target");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_mcp_tools_call_without_a_declaration_keeps_the_jsonrpc_denial() {
    let fixture = JwksFixture::start().await;
    let setup = Setup {
        caller: CallerAuth::Jwt { forward_header: false },
        mcp: true,
        deny_in: Some(Plane::Surface),
    };
    let h = start(&fixture, MockServer::start().await, &setup).await;
    let (answer, body) = call_tool(&h, None).await;
    assert_eq!((answer.status, answer.challenges), (200, vec![]), "{body}");
    assert_eq!(body["id"], TOOLS_CALL_ID, "{body}");
    assert_eq!(body["error"]["code"], -32001, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("Tool 'echo' is not allowed by policy")),
        "{body}"
    );
    assert_eq!(target_calls(&h), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_caller_on_an_access_point_that_does_not_declare_keeps_the_403() {
    let fixture = JwksFixture::start().await;
    let setup = Setup {
        caller: CallerAuth::Jwt { forward_header: false },
        mcp: false,
        deny_in: Some(Plane::Surface),
    };
    let h = start(&fixture, MockServer::start().await, &setup).await;
    for bearer in [None, Some("not-a-jwt")] {
        let (answer, body) = send(&h, &setup, bearer).await;
        assert_eq!((answer.status, answer.challenges), (403, vec![]), "{bearer:?}: {body}");
    }
    assert_eq!(target_calls(&h), 0);

    let (admitted, body) = send(&h, &setup, Some(&token(&fixture))).await;
    assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);
}

/// A target that answers every request with `status` and the given challenges.
async fn challenging_target(
    status: u16,
    challenges: &'static [&'static str],
) -> String {
    let app = axum::Router::new().fallback(move || async move {
        let mut response = axum::response::Response::new(axum::body::Body::from(r#"{"error":"upstream"}"#));
        *response.status_mut() = axum::http::StatusCode::from_u16(status).expect("status");
        for challenge in challenges {
            response
                .headers_mut()
                .append("www-authenticate", HeaderValue::from_static(challenge));
        }
        response
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind target");
    let url = format!(
        "http://{}",
        listener
            .local_addr()
            .expect("target addr")
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .ok();
    });
    url
}

const UPSTREAM_CHALLENGES: &[&str] = &[
    "Bearer realm=\"agent\", resource_metadata=\"https://idp.internal/prm\"",
    "DPoP algs=\"ES256\"",
    "Payment id=\"p1\", realm=\"agent\", method=\"tempo\"",
];

async fn start_against_challenging_target(
    fixture: &JwksFixture,
    status: u16,
    challenges: &'static [&'static str],
    setup: &Setup,
) -> GatewayHarness {
    let target = challenging_target(status, challenges).await;
    GatewayHarness::start_with_mock_and_logs(MockServer::start().await, |temp_dir, gw_config, bootstrap| {
        configure(fixture, setup, Some(target), temp_dir, gw_config, bootstrap)
    })
    .await
}

/// The gateway log lines that name the `DPoP` scheme, which only the record of
/// dropped Target challenges does.
fn dropped_challenge_lines(h: &GatewayHarness) -> Vec<String> {
    h.logs()
        .lines()
        .filter(|line| line.contains("DPoP"))
        .map(str::to_string)
        .collect()
}

fn assert_logs_dropped_bearer_and_dpop(
    h: &GatewayHarness,
    became_bad_gateway: bool,
) {
    let lines = dropped_challenge_lines(h);
    assert_eq!(lines.len(), 1, "one record of the dropped challenges: {lines:?}");
    assert!(lines[0].contains("WARN"), "{}", lines[0]);
    assert!(lines[0].contains("schemes=Bearer,DPoP,"), "Payment is kept, not dropped: {}", lines[0]);
    assert!(lines[0].contains(&format!("became_bad_gateway={became_bad_gateway}")), "{}", lines[0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn target_challenges_reach_the_caller_of_an_access_point_that_does_not_declare() {
    let fixture = JwksFixture::start().await;
    for caller in [
        CallerAuth::None,
        CallerAuth::ApiKey,
        CallerAuth::Jwt { forward_header: false },
        CallerAuth::Jwt { forward_header: true },
    ] {
        for status in [401, 402] {
            let setup = Setup::relaying(caller);
            let h = start_against_challenging_target(&fixture, status, UPSTREAM_CHALLENGES, &setup).await;
            let (answer, body) = send(
                &h,
                &setup,
                caller
                    .bearer(&fixture)
                    .as_deref(),
            )
            .await;
            assert_eq!(answer.status, status, "{caller:?}: {body}");
            assert_eq!(answer.challenges, UPSTREAM_CHALLENGES, "{caller:?} {status}");
            assert_eq!(dropped_challenge_lines(&h), Vec::<String>::new(), "{caller:?} {status}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_payment_challenges_from_the_target_reach_the_caller_of_a_declaring_access_point() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::relaying(CallerAuth::Declaring);
    for status in [401, 402] {
        let h = start_against_challenging_target(&fixture, status, UPSTREAM_CHALLENGES, &setup).await;
        let (answer, body) = send(&h, &setup, Some(&token(&fixture))).await;
        assert_eq!(answer.status, status, "{body}");
        assert_eq!(answer.challenges, vec![UPSTREAM_CHALLENGES[2].to_string()], "status {status}");
        assert_logs_dropped_bearer_and_dpop(&h, false);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_target_401_left_without_a_challenge_becomes_a_502_on_a_declaring_access_point() {
    let fixture = JwksFixture::start().await;
    let declaring = Setup::relaying(CallerAuth::Declaring);
    let h = start_against_challenging_target(&fixture, 401, &UPSTREAM_CHALLENGES[..2], &declaring).await;
    let (answer, body) = send(&h, &declaring, Some(&token(&fixture))).await;
    assert_eq!((answer.status, answer.challenges), (502, vec![]), "{body}");
    assert_eq!(body["detail"], "The target refused the gateway's authorization", "{body}");
    assert_logs_dropped_bearer_and_dpop(&h, true);

    let undeclared = Setup::relaying(CallerAuth::ApiKey);
    let h = start_against_challenging_target(&fixture, 401, &UPSTREAM_CHALLENGES[..2], &undeclared).await;
    let (answer, body) = send(&h, &undeclared, None).await;
    assert_eq!(answer.status, 401, "{body}");
    assert_eq!(answer.challenges, &UPSTREAM_CHALLENGES[..2]);
    assert_eq!(dropped_challenge_lines(&h), Vec::<String>::new());
}

const SCOPE_DENY_REASON: &str = "scope-order-probe-denied";
const DENY_ALL_GATEWAY_POLICY: &str =
    "package gateway.policy\ndefault allow := false\ndeny_reason := \"scope-order-probe-denied\" if true\n";
const ALLOW_ALL_GATEWAY_POLICY: &str = "package gateway.policy\ndefault allow := true\n";

async fn start_requiring_scope(
    fixture: &JwksFixture,
    gateway_policy: &'static str,
) -> GatewayHarness {
    let setup = Setup::relaying(CallerAuth::Declaring);
    GatewayHarness::start_with_mock_and_logs(tools_mock().await, |temp_dir, gw_config, bootstrap| {
        configure(fixture, &setup, None, temp_dir, gw_config, bootstrap);
        write_gateway_policy(
            &bootstrap
                .storage_paths
                .gateways,
            gateway_policy,
        );
        let mut surface = serde_json::to_value(&gw_config.surfaces[0]).expect("serialize surface");
        surface["access_point"]["caller_authentication"]["methods"][0]["required_scopes"] = json!(["tools.call"]);
        gw_config.surfaces = vec![serde_json::from_value(surface).expect("scoped surface")];
    })
    .await
}

fn policy_decision_lines(h: &GatewayHarness) -> Vec<String> {
    h.logs()
        .lines()
        .filter(|line| line.contains("policy decision"))
        .map(str::to_string)
        .collect()
}

fn insufficient_scope_challenge() -> Vec<String> {
    vec![format!("Bearer resource_metadata=\"{METADATA_URL}\", error=\"insufficient_scope\", scope=\"tools.call\"")]
}

fn gateway_policy_evaluations(h: &GatewayHarness) -> usize {
    h.logs()
        .lines()
        .filter(|line| line.contains("[OPA-INPUT] Gateway policy input before eval"))
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scope_shortfall_is_refused_before_a_gateway_policy_that_denies_and_a_granted_token_reaches_it() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::relaying(CallerAuth::Declaring);
    let h = start_requiring_scope(&fixture, DENY_ALL_GATEWAY_POLICY).await;

    let (short, body) = send(&h, &setup, Some(&token_with(&fixture, Some("tools")))).await;
    assert_eq!(short.status, 403, "{body}");
    assert_eq!(short.challenges, insufficient_scope_challenge(), "{body}");
    assert_eq!(body["status"], 403, "{body}");
    assert_eq!(target_calls(&h), 0);
    assert_eq!(gateway_policy_evaluations(&h), 0, "gateway policy never evaluated for the shortfall");
    assert!(
        !h.logs()
            .contains(SCOPE_DENY_REASON),
        "policy never ran for the shortfall"
    );

    let (granted, body) = send(&h, &setup, Some(&token_with(&fixture, Some("tools tools.call")))).await;
    assert_eq!((granted.status, granted.challenges), (403, vec![]), "{body}");
    assert_eq!(body["detail"], "Request blocked by gateway policy", "{body}");
    assert_eq!(target_calls(&h), 0);
    assert_eq!(gateway_policy_evaluations(&h), 1);
    let decisions = policy_decision_lines(&h);
    assert_eq!(decisions.len(), 1, "{decisions:?}");
    assert!(decisions[0].contains("policy decision: deny"), "{}", decisions[0]);
    assert!(decisions[0].contains(SCOPE_DENY_REASON), "{}", decisions[0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scope_shortfall_is_refused_before_a_gateway_policy_that_allows_and_a_granted_token_reaches_the_target() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::relaying(CallerAuth::Declaring);
    let h = start_requiring_scope(&fixture, ALLOW_ALL_GATEWAY_POLICY).await;

    let (short, body) = send(&h, &setup, Some(&token_with(&fixture, Some("tools")))).await;
    assert_eq!(short.status, 403, "{body}");
    assert_eq!(short.challenges, insufficient_scope_challenge(), "{body}");
    assert_eq!(target_calls(&h), 0, "an allowing policy does not admit a scope shortfall");
    assert_eq!(gateway_policy_evaluations(&h), 0, "gateway policy never evaluated for the shortfall");

    let (granted, body) = send(&h, &setup, Some(&token_with(&fixture, Some("tools.call")))).await;
    assert_eq!((granted.status, granted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);
    assert_eq!(gateway_policy_evaluations(&h), 1);
}
