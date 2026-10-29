//! Caller challenge E2E tests
//!
//! A declaring Access Point answers a caller whose token is missing, invalid or short of
//! the required scopes with an RFC 6750 challenge naming its protected resource
//! metadata, before policy, payment and the Target, whichever policy plane refuses
//! failed callers and whether or not any does. It declares through an explicit
//! `protected_resource` (MCP only) or through one pinned `jwt_bearer` method with
//! `required_scopes` (the derived declaration), and never forwards the caller's token.
//! An MCP `tools/call` gets that HTTP challenge, not the JSON-RPC denial. Target
//! challenges other than `Payment` never reach the caller of a declaring Access Point,
//! because the gateway is the resource server there: the dropped schemes are logged, and
//! a Target 401 left without a challenge becomes a 502. An Access Point that does not
//! declare, including one that forwards the caller's token, relays every Target
//! challenge unchanged and leaves failed callers to policy.

use std::path::Path;
use std::sync::atomic::Ordering;

use axum::http::HeaderValue;
use serde_json::{Value, json};

use super::helpers;
use crate::config::{BootstrapConfig, GatewayConfig};
use helpers::card_security::{REQUIRED_SCOPE, SMOKE_RESOURCE, advertise_public_origin};
use helpers::jwt::{JwksFixture, now_secs, sign_jwt};
use helpers::{GatewayHarness, MockServer};

const METADATA_URL: &str = "https://gw.example/.well-known/oauth-protected-resource/smoke";
const AUTHORIZATION_SERVER: &str = "https://as.example/";
const STRATEGY_ID: &str = "challenge-strategy";
const DENY_FAILED_POLICY_ID: &str = "deny-failed-callers";
const DENY_FAILED: &str =
    "package surface.policy\ndefault allow := true\nallow := false if input.source_auth.method == \"failed\"\n";
const TOOLS_CALL_ID: i64 = 9;
const SAVED_ROUTE: &str = "/smoke/saved";
const SAVED_RESOURCE: &str = "https://gw.example/smoke/saved";
const SAVED_METADATA_URL: &str = "https://gw.example/.well-known/oauth-protected-resource/smoke/saved";

/// Write the strategy the Access Point names, trusting the fixture's issuer. `pinned`
/// decides whether it carries discovered authorization server metadata.
fn write_strategy(
    temp_dir: &Path,
    fixture: &JwksFixture,
    pinned: bool,
) {
    let jwks_uri = format!("{}/.well-known/jwks.json", fixture.issuer);
    let mut strategy = json!({
        "id": STRATEGY_ID,
        "name": "Challenge",
        "expected_issuer": fixture.issuer,
        "jwks_source": { "type": "remote", "jwks_uri": jwks_uri },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    if pinned {
        strategy["authorization_server"] = json!({
            "issuer": fixture.issuer,
            "metadata_url": format!("{}/.well-known/oauth-authorization-server", fixture.issuer),
            "token_endpoint": format!("{}/token", fixture.issuer),
            "jwks_uri": jwks_uri,
        });
    }
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

/// An MPP payment policy that charges every A2A `message/send`.
fn mpp_payment_policy() -> Value {
    json!({
        "type": "mpp",
        "realm": "gw.example",
        "secret_key": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]),
        "payment_methods": [{
            "method": "tempo", "intent": "charge", "currency": "USD", "recipient": "acct_1", "amount": "0.01"
        }],
        "a2a_method_filters": [{ "method": "message/send" }]
    })
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
    /// JWT Bearer without `required_scopes`, which never declares.
    Jwt {
        forward_header: bool,
        pinned: bool,
    },
    /// One JWT Bearer method with `required_scopes`: the derived declaration when its
    /// strategy is pinned and it does not forward the caller's token.
    Scoped {
        forward_header: bool,
        pinned: bool,
    },
    /// JWT Bearer with an explicit `protected_resource` (MCP only).
    Declaring,
}

/// The derived declaration.
const DERIVED: CallerAuth = CallerAuth::Scoped {
    forward_header: false,
    pinned: true,
};

impl CallerAuth {
    fn config(self) -> Option<Value> {
        match self {
            Self::None => None,
            Self::ApiKey => Some(json!({ "methods": [{
                "type": "api_key", "extraction": { "source": "http_header", "field": "X-Caller-Key" },
                "secret_id": "CALLER_KEYS"
            }] })),
            Self::Jwt { forward_header, .. } => Some(json!({ "methods": [{
                "type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID,
                "audiences": [SMOKE_RESOURCE], "forward_header": forward_header
            }] })),
            Self::Scoped { forward_header, .. } => Some(json!({ "methods": [{
                "type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID,
                "audiences": [SMOKE_RESOURCE], "required_scopes": [REQUIRED_SCOPE], "forward_header": forward_header
            }] })),
            Self::Declaring => Some(json!({
                "methods": [{ "type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID, "audiences": [] }],
                "protected_resource": { "resource": SMOKE_RESOURCE, "authorization_servers": [AUTHORIZATION_SERVER] }
            })),
        }
    }

    fn pinned(self) -> bool {
        matches!(self, Self::Jwt { pinned: true, .. } | Self::Scoped { pinned: true, .. })
    }

    /// The token an admitted caller presents, when the Access Point reads one.
    fn bearer(
        self,
        fixture: &JwksFixture,
    ) -> Option<String> {
        matches!(self, Self::Jwt { .. } | Self::Scoped { .. } | Self::Declaring).then(|| token(fixture))
    }
}

struct Setup {
    caller: CallerAuth,
    mcp: bool,
    deny_in: Option<Plane>,
    paid: bool,
}

impl Setup {
    /// A surface with no policy, on the protocol `caller` can serve.
    fn relaying(caller: CallerAuth) -> Self {
        Self {
            caller,
            mcp: matches!(caller, CallerAuth::Declaring),
            deny_in: None,
            paid: false,
        }
    }

    /// An A2A surface without payment.
    fn a2a(
        caller: CallerAuth,
        deny_in: Option<Plane>,
    ) -> Self {
        Self {
            caller,
            mcp: false,
            deny_in,
            paid: false,
        }
    }

    /// An MCP surface.
    fn mcp(
        caller: CallerAuth,
        deny_in: Option<Plane>,
    ) -> Self {
        Self {
            caller,
            mcp: true,
            deny_in,
            paid: false,
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
    let mut target = json!({ "endpoint": "inbound_target_placeholder" });
    if setup.paid {
        target["payment_policy"] = mpp_payment_policy();
    }
    serde_json::from_value(json!({
        "name": "challenge",
        "access_point": access_point,
        "target": target
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
    write_strategy(temp_dir, fixture, setup.caller.pinned());
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

fn signed(
    fixture: &JwksFixture,
    audience: &str,
    scope: &str,
) -> String {
    sign_jwt(
        json!({
            "iss": fixture.issuer, "sub": "client", "aud": audience, "scope": scope,
            "exp": now_secs() + 300, "iat": now_secs(),
        }),
        &fixture.kid,
    )
}

/// A token for the `/smoke` Access Point granting the required scope.
fn token(fixture: &JwksFixture) -> String {
    signed(fixture, SMOKE_RESOURCE, REQUIRED_SCOPE)
}

/// A token for the `/smoke` Access Point that lacks the required scope.
fn short_token(fixture: &JwksFixture) -> String {
    signed(fixture, SMOKE_RESOURCE, "read")
}

/// A token the same authorization server issued for another resource.
fn other_resource_token(fixture: &JwksFixture) -> String {
    signed(fixture, "https://gw.example/other", REQUIRED_SCOPE)
}

async fn tools_mock() -> MockServer {
    MockServer::start_with_response(json!({ "jsonrpc": "2.0", "id": 1, "result": { "tools": [] } }).to_string()).await
}

fn target_calls(h: &GatewayHarness) -> usize {
    h.mock
        .request_count
        .load(Ordering::SeqCst)
}

/// The `Authorization` header the Target received with the last request.
fn forwarded_authorization(h: &GatewayHarness) -> Option<String> {
    h.mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("the target received a request")
        .headers
        .get("authorization")
        .cloned()
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
    send_to(&h.gateway_url, bearer, body, accept).await
}

async fn send_to(
    url: &str,
    bearer: Option<&str>,
    body: Value,
    accept: Option<&str>,
) -> (Answer, Value) {
    let mut request = client()
        .post(url)
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

/// The status and document the gateway serves at the protected resource metadata path
/// of `route`.
async fn fetch_metadata(
    h: &GatewayHarness,
    route: &str,
) -> (u16, Value) {
    let response = client()
        .get(format!("{}/.well-known/oauth-protected-resource{route}", h.gateway_base))
        .send()
        .await
        .expect("metadata request");
    let status = response.status().as_u16();
    let text = response
        .text()
        .await
        .expect("metadata body");
    (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

fn bearer_challenge(
    metadata_url: &str,
    error: Option<&str>,
    scope: Option<&str>,
) -> Vec<String> {
    let error = error
        .map(|error| format!(", error=\"{error}\""))
        .unwrap_or_default();
    let scope = scope
        .map(|scope| format!(", scope=\"{scope}\""))
        .unwrap_or_default();
    vec![format!("Bearer resource_metadata=\"{metadata_url}\"{error}{scope}")]
}

/// The challenge of the explicit declaration, which names no required scope.
fn challenge(error: Option<&str>) -> Vec<String> {
    bearer_challenge(METADATA_URL, error, None)
}

/// The challenge of the derived declaration, which names its required scope.
fn derived_challenge(error: Option<&str>) -> Vec<String> {
    bearer_challenge(METADATA_URL, error, Some(REQUIRED_SCOPE))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_mcp_access_point_without_policy_challenges_a_failed_caller_before_the_target() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::mcp(CallerAuth::Declaring, None);
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

    let (status, metadata) = fetch_metadata(&h, "/smoke").await;
    assert_eq!(status, 200, "{metadata}");
    assert_eq!(metadata["resource"], SMOKE_RESOURCE, "the challenge points at the metadata the gateway serves");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_challenged_mcp_tools_call_gets_the_http_challenge_whichever_plane_refuses_failed_callers() {
    let fixture = JwksFixture::start().await;
    for deny_in in [None, Some(Plane::Surface), Some(Plane::Gateway)] {
        let setup = Setup::mcp(CallerAuth::Declaring, deny_in);
        let h = start(&fixture, MockServer::start().await, &setup).await;
        let (missing, _) = call_tool(&h, None).await;
        assert_eq!((missing.status, missing.challenges), (401, challenge(None)), "{deny_in:?}");
        let (invalid, _) = call_tool(&h, Some("not-a-jwt")).await;
        assert_eq!((invalid.status, invalid.challenges), (401, challenge(Some("invalid_token"))), "{deny_in:?}");
        assert_eq!(target_calls(&h), 0, "{deny_in:?}: no refused caller reached the target");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_derived_mcp_declaration_challenges_with_its_required_scope_before_policy() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::mcp(DERIVED, None);
    let h = start(&fixture, tools_mock().await, &setup).await;

    let (missing, body) = send(&h, &setup, None).await;
    assert_eq!((missing.status, missing.challenges), (401, derived_challenge(None)), "{body}");
    assert_eq!(missing.headers["content-type"], "application/problem+json");
    let (invalid, body) = send(&h, &setup, Some("not-a-jwt")).await;
    assert_eq!((invalid.status, invalid.challenges), (401, derived_challenge(Some("invalid_token"))), "{body}");
    let (short, body) = send(&h, &setup, Some(&short_token(&fixture))).await;
    assert_eq!((short.status, short.challenges), (403, derived_challenge(Some("insufficient_scope"))), "{body}");
    let (short_call, body) = call_tool(&h, Some(&short_token(&fixture))).await;
    assert_eq!(
        (short_call.status, short_call.challenges),
        (403, derived_challenge(Some("insufficient_scope"))),
        "{body}"
    );
    assert_eq!(target_calls(&h), 0, "no refused caller reached the target");

    let (admitted, body) = send(&h, &setup, Some(&token(&fixture))).await;
    assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);
    assert_eq!(forwarded_authorization(&h), None, "a declaring Access Point never forwards the caller's token");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_mcp_tools_call_without_a_declaration_keeps_the_jsonrpc_denial() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::mcp(
        CallerAuth::Jwt {
            forward_header: false,
            pinned: false,
        },
        Some(Plane::Surface),
    );
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

/// A declaring A2A Access Point refuses a failed caller with its challenge by default,
/// with no policy configured.
#[tokio::test(flavor = "multi_thread")]
async fn a_derived_a2a_declaration_without_policy_challenges_a_failed_caller_before_the_target() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::a2a(DERIVED, None);
    let h = start(&fixture, MockServer::start().await, &setup).await;

    let (missing, body) = send(&h, &setup, None).await;
    assert_eq!((missing.status, missing.challenges), (401, derived_challenge(None)), "{body}");
    assert_eq!(missing.headers["cache-control"], "no-store");
    let (invalid, body) = send(&h, &setup, Some("not-a-jwt")).await;
    assert_eq!((invalid.status, invalid.challenges), (401, derived_challenge(Some("invalid_token"))), "{body}");
    let (other, body) = send(&h, &setup, Some(&other_resource_token(&fixture))).await;
    assert_eq!(
        (other.status, other.challenges),
        (401, derived_challenge(Some("invalid_token"))),
        "a token for another resource is refused: {body}"
    );
    let (short, body) = send(&h, &setup, Some(&short_token(&fixture))).await;
    assert_eq!((short.status, short.challenges), (403, derived_challenge(Some("insufficient_scope"))), "{body}");
    assert_eq!(target_calls(&h), 0, "no refused caller reached the target");

    let (admitted, body) = send(&h, &setup, Some(&token(&fixture))).await;
    assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);
    assert_eq!(forwarded_authorization(&h), None, "a declaring Access Point never forwards the caller's token");

    let (status, metadata) = fetch_metadata(&h, "/smoke").await;
    assert_eq!(status, 200, "{metadata}");
    assert_eq!(
        metadata,
        json!({
            "resource": SMOKE_RESOURCE,
            "authorization_servers": [fixture.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [REQUIRED_SCOPE]
        }),
        "the challenge points at the metadata the gateway serves"
    );
}

/// Start a gateway serving `setup` once `edit` has changed the surface's configuration.
async fn start_edited(
    fixture: &JwksFixture,
    mock: MockServer,
    setup: &Setup,
    edit: impl FnOnce(&mut Value),
) -> GatewayHarness {
    GatewayHarness::start_with_mock_and_logs(mock, |temp_dir, gw_config, bootstrap| {
        configure(fixture, setup, None, temp_dir, gw_config, bootstrap);
        let mut surface = serde_json::to_value(&gw_config.surfaces[0]).expect("serialize surface");
        edit(&mut surface);
        gw_config.surfaces = vec![serde_json::from_value(surface).expect("edited surface")];
    })
    .await
}

const OTHER_AUDIENCE: &str = "api://agent";

/// A derived declaration narrows the accepted audiences to the Access Point URL, so a
/// token for another audience the method lists is refused; without the declaration the
/// same token is accepted.
#[tokio::test(flavor = "multi_thread")]
async fn a_derived_declaration_refuses_a_token_for_another_audience_its_method_lists() {
    let fixture = JwksFixture::start().await;
    let both_audiences = |surface: &mut Value| {
        surface["access_point"]["caller_authentication"]["methods"][0]["audiences"] =
            json!([SMOKE_RESOURCE, OTHER_AUDIENCE]);
    };
    let other_audience = signed(&fixture, OTHER_AUDIENCE, REQUIRED_SCOPE);

    let declaring = Setup::a2a(DERIVED, None);
    let h = start_edited(&fixture, MockServer::start().await, &declaring, both_audiences).await;
    let (other, body) = send(&h, &declaring, Some(&other_audience)).await;
    assert_eq!((other.status, other.challenges), (401, derived_challenge(Some("invalid_token"))), "{body}");
    assert_eq!(target_calls(&h), 0, "a token for another audience never reached the target");
    let (admitted, body) = send(&h, &declaring, Some(&token(&fixture))).await;
    assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);

    let undeclared = Setup::a2a(
        CallerAuth::Scoped {
            forward_header: false,
            pinned: false,
        },
        None,
    );
    let h = start_edited(&fixture, MockServer::start().await, &undeclared, both_audiences).await;
    let (other, body) = send(&h, &undeclared, Some(&other_audience)).await;
    assert_eq!((other.status, other.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);
}

/// An alias on a surface without variants selects nothing and the base route answers,
/// so the request is refused as the base route refuses it, with the base route's
/// challenge, and never reaches the Target. A catch-all route on the listener is what
/// carries such a path to the surface.
#[tokio::test(flavor = "multi_thread")]
async fn an_alias_that_selects_no_variant_is_challenged_as_the_base_route() {
    let fixture = JwksFixture::start().await;
    for setup in [Setup::a2a(DERIVED, None), Setup::mcp(DERIVED, None)] {
        let mock = if setup.mcp {
            tools_mock().await
        } else {
            MockServer::start().await
        };
        let h = GatewayHarness::start_with_mock(mock, |temp_dir, gw_config, bootstrap| {
            let mut network: Value =
                serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).expect("network config"))
                    .expect("network json");
            network["routes"]["root"] = json!({ "type": "proxy", "prefix": "" });
            std::fs::write(&bootstrap.config_files.gateway, serde_json::to_vec(&network).expect("network bytes"))
                .expect("write network config");
            configure(&fixture, &setup, None, temp_dir, gw_config, bootstrap);
        })
        .await;
        for suffix in ["$x", "%24x", "$X"] {
            let url = format!("{}/smoke{suffix}", h.gateway_base);
            let (missing, body) = send_to(&url, None, setup.request(), None).await;
            assert_eq!(
                (missing.status, missing.challenges),
                (401, derived_challenge(None)),
                "mcp={} {suffix}: {body}",
                setup.mcp
            );
            let (invalid, body) = send_to(&url, Some("not-a-jwt"), setup.request(), None).await;
            assert_eq!(
                (invalid.status, invalid.challenges),
                (401, derived_challenge(Some("invalid_token"))),
                "mcp={} {suffix}: {body}",
                setup.mcp
            );
        }
        assert_eq!(target_calls(&h), 0, "mcp={}: no refused caller reached the target", setup.mcp);

        let url = format!("{}/smoke$x", h.gateway_base);
        let (admitted, body) = send_to(&url, Some(&token(&fixture)), setup.request(), None).await;
        assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "mcp={}: {body}", setup.mcp);
        assert_eq!(target_calls(&h), 1, "mcp={}", setup.mcp);
    }
}

/// The built-in refusal follows gateway policy: a gateway policy admitting every caller
/// still evaluates a failed caller once, and the Access Point then refuses it.
#[tokio::test(flavor = "multi_thread")]
async fn a_derived_a2a_declaration_refuses_a_failed_caller_after_a_gateway_policy_admits_it() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::a2a(DERIVED, None);
    let h = GatewayHarness::start_with_mock_and_logs(MockServer::start().await, |temp_dir, gw_config, bootstrap| {
        configure(&fixture, &setup, None, temp_dir, gw_config, bootstrap);
        write_gateway_policy(
            &bootstrap
                .storage_paths
                .gateways,
            ALLOW_ALL_GATEWAY_POLICY,
        );
    })
    .await;

    let (missing, body) = send(&h, &setup, None).await;
    assert_eq!((missing.status, missing.challenges), (401, derived_challenge(None)), "{body}");
    assert_eq!(target_calls(&h), 0, "an admitting gateway policy does not let a failed caller through");
    assert_eq!(gateway_policy_evaluations(&h), 1, "gateway policy saw the failed caller first");

    let (admitted, body) = send(&h, &setup, Some(&token(&fixture))).await;
    assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);
    assert_eq!(gateway_policy_evaluations(&h), 2);
}

/// The built-in refusal runs before the AP2 inbound gate, so a failed caller on a
/// declaring AP2 Access Point is challenged rather than told AP2 is disabled, and an
/// admitted caller still meets the gate.
#[tokio::test(flavor = "multi_thread")]
async fn a_derived_ap2_declaration_challenges_a_failed_caller_before_the_ap2_gate() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::a2a(DERIVED, None);
    let h = start_edited(&fixture, MockServer::start().await, &setup, |surface| {
        surface["access_point"]["protocol"] = json!("ap2");
    })
    .await;

    let (missing, body) = send(&h, &setup, None).await;
    assert_eq!((missing.status, missing.challenges), (401, derived_challenge(None)), "{body}");
    let (admitted, body) = send(&h, &setup, Some(&token(&fixture))).await;
    assert_eq!(admitted.status, 501, "{body}");
    assert_eq!(body["detail"], "AP2 is experimental and not enabled on this gateway", "{body}");
    assert_eq!(target_calls(&h), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_derived_a2a_declaration_challenges_a_failed_caller_whichever_plane_refuses_it() {
    let fixture = JwksFixture::start().await;
    for deny_in in [Plane::Surface, Plane::Gateway] {
        let setup = Setup::a2a(DERIVED, Some(deny_in));
        let h = start(&fixture, MockServer::start().await, &setup).await;
        let (missing, _) = send(&h, &setup, None).await;
        assert_eq!((missing.status, missing.challenges), (401, derived_challenge(None)), "{deny_in:?}");
        let (invalid, _) = send(&h, &setup, Some("not-a-jwt")).await;
        assert_eq!(
            (invalid.status, invalid.challenges),
            (401, derived_challenge(Some("invalid_token"))),
            "{deny_in:?}"
        );
        let (short, _) = send(&h, &setup, Some(&short_token(&fixture))).await;
        assert_eq!(
            (short.status, short.challenges),
            (403, derived_challenge(Some("insufficient_scope"))),
            "{deny_in:?}"
        );
        assert_eq!(target_calls(&h), 0, "{deny_in:?}: no refused caller reached the target");

        let (admitted, body) = send(&h, &setup, Some(&token(&fixture))).await;
        assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{deny_in:?}: {body}");
    }
}

/// The built-in refusal of a declaring Access Point runs before payment, so a failed
/// caller is never asked to pay, whichever plane, if any, would refuse it.
#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_access_point_challenges_a_failed_caller_before_payment() {
    let fixture = JwksFixture::start().await;
    for deny_in in [None, Some(Plane::Surface), Some(Plane::Gateway)] {
        let setup = Setup {
            paid: true,
            ..Setup::a2a(DERIVED, deny_in)
        };
        let h = start(&fixture, MockServer::start().await, &setup).await;
        let (missing, body) = send(&h, &setup, None).await;
        assert_eq!(
            (missing.status, missing.challenges),
            (401, derived_challenge(None)),
            "{deny_in:?}: no Payment challenge before the Bearer one: {body}"
        );
        let (short, body) = send(&h, &setup, Some(&short_token(&fixture))).await;
        assert_eq!(
            (short.status, short.challenges),
            (403, derived_challenge(Some("insufficient_scope"))),
            "{deny_in:?}: {body}"
        );
        assert_eq!(target_calls(&h), 0, "{deny_in:?}: no refused caller reached the target");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn surface_policy_runs_after_payment_on_an_access_point_that_does_not_declare() {
    let fixture = JwksFixture::start().await;
    let setup = Setup {
        paid: true,
        ..Setup::a2a(
            CallerAuth::Scoped {
                forward_header: false,
                pinned: false,
            },
            Some(Plane::Surface),
        )
    };
    let h = start(&fixture, MockServer::start().await, &setup).await;
    let (answer, body) = send(&h, &setup, None).await;
    assert_eq!(answer.status, 402, "{body}");
    assert!(!answer.challenges.is_empty(), "the 402 carries its Payment challenge");
    assert!(
        answer
            .challenges
            .iter()
            .all(|challenge| challenge.starts_with("Payment ")),
        "a 402 never carries a Bearer challenge: {:?}",
        answer.challenges
    );
    assert_eq!(target_calls(&h), 0);
}

/// Access Points that authenticate callers with JWT Bearer but do not declare: no
/// `required_scopes`, a strategy without a pinned authorization server, or a method that
/// forwards the caller's token.
const UNDECLARED_JWT: [CallerAuth; 4] = [
    CallerAuth::Jwt {
        forward_header: false,
        pinned: false,
    },
    CallerAuth::Jwt {
        forward_header: false,
        pinned: true,
    },
    CallerAuth::Scoped {
        forward_header: false,
        pinned: false,
    },
    CallerAuth::Scoped {
        forward_header: true,
        pinned: true,
    },
];

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_caller_on_an_access_point_that_does_not_declare_keeps_the_403() {
    let fixture = JwksFixture::start().await;
    for caller in UNDECLARED_JWT {
        let setup = Setup::a2a(caller, Some(Plane::Surface));
        let h = start(&fixture, MockServer::start().await, &setup).await;
        for bearer in [None, Some("not-a-jwt")] {
            let (answer, body) = send(&h, &setup, bearer).await;
            assert_eq!((answer.status, answer.challenges), (403, vec![]), "{caller:?} {bearer:?}: {body}");
        }
        assert_eq!(target_calls(&h), 0, "{caller:?}");

        let (admitted, body) = send(&h, &setup, Some(&token(&fixture))).await;
        assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{caller:?}: {body}");
        assert_eq!(target_calls(&h), 1, "{caller:?}");
    }
}

/// A method that forwards the caller's token cannot declare, so the Access Point
/// publishes no metadata, challenges no one, leaves failed callers to policy and
/// forwards the token as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_scoped_access_point_that_forwards_the_callers_token_does_not_declare() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::a2a(
        CallerAuth::Scoped {
            forward_header: true,
            pinned: true,
        },
        None,
    );
    let h = start(&fixture, MockServer::start().await, &setup).await;

    let (status, metadata) = fetch_metadata(&h, "/smoke").await;
    assert_eq!(status, 404, "{metadata}");

    let (missing, body) = send(&h, &setup, None).await;
    assert_eq!(
        (missing.status, missing.challenges),
        (200, vec![]),
        "without a policy a failed caller reaches the target: {body}"
    );
    assert_eq!(target_calls(&h), 1);

    let bearer = token(&fixture);
    let (admitted, body) = send(&h, &setup, Some(&bearer)).await;
    assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{body}");
    assert_eq!(forwarded_authorization(&h), Some(format!("Bearer {bearer}")));
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

/// The Access Points that declare: the explicit MCP setting and the derived declaration.
const DECLARING: [CallerAuth; 2] = [CallerAuth::Declaring, DERIVED];

#[tokio::test(flavor = "multi_thread")]
async fn target_challenges_reach_the_caller_of_an_access_point_that_does_not_declare() {
    let fixture = JwksFixture::start().await;
    let callers = [
        CallerAuth::None,
        CallerAuth::ApiKey,
        CallerAuth::Jwt {
            forward_header: true,
            pinned: false,
        },
    ]
    .into_iter()
    .chain(UNDECLARED_JWT);
    for caller in callers {
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
    for caller in DECLARING {
        let setup = Setup::relaying(caller);
        for status in [401, 402] {
            let h = start_against_challenging_target(&fixture, status, UPSTREAM_CHALLENGES, &setup).await;
            let (answer, body) = send(&h, &setup, Some(&token(&fixture))).await;
            assert_eq!(answer.status, status, "{caller:?}: {body}");
            assert_eq!(answer.challenges, vec![UPSTREAM_CHALLENGES[2].to_string()], "{caller:?} {status}");
            assert_logs_dropped_bearer_and_dpop(&h, false);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_target_401_left_without_a_challenge_becomes_a_502_on_a_declaring_access_point() {
    let fixture = JwksFixture::start().await;
    for caller in DECLARING {
        let declaring = Setup::relaying(caller);
        let h = start_against_challenging_target(&fixture, 401, &UPSTREAM_CHALLENGES[..2], &declaring).await;
        let (answer, body) = send(&h, &declaring, Some(&token(&fixture))).await;
        assert_eq!((answer.status, answer.challenges), (502, vec![]), "{caller:?}: {body}");
        assert_eq!(body["detail"], "The target refused the gateway's authorization", "{caller:?}: {body}");
        assert_logs_dropped_bearer_and_dpop(&h, true);
    }

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
    policy_decision_lines(h)
        .iter()
        .filter(|line| line.contains("policy_scope=\"gateway\"") || line.contains("policy_scope=gateway "))
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scope_shortfall_is_refused_before_a_gateway_policy_that_denies_and_a_granted_token_reaches_it() {
    let fixture = JwksFixture::start().await;
    let setup = Setup::relaying(CallerAuth::Declaring);
    let h = start_requiring_scope(&fixture, DENY_ALL_GATEWAY_POLICY).await;

    let (short, body) = send(&h, &setup, Some(&signed(&fixture, SMOKE_RESOURCE, "tools"))).await;
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

    let (granted, body) = send(&h, &setup, Some(&signed(&fixture, SMOKE_RESOURCE, "tools tools.call"))).await;
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

    let (short, body) = send(&h, &setup, Some(&signed(&fixture, SMOKE_RESOURCE, "tools"))).await;
    assert_eq!(short.status, 403, "{body}");
    assert_eq!(short.challenges, insufficient_scope_challenge(), "{body}");
    assert_eq!(target_calls(&h), 0, "an allowing policy does not admit a scope shortfall");
    assert_eq!(gateway_policy_evaluations(&h), 0, "gateway policy never evaluated for the shortfall");

    let (granted, body) = send(&h, &setup, Some(&signed(&fixture, SMOKE_RESOURCE, "tools.call"))).await;
    assert_eq!((granted.status, granted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);
    assert_eq!(gateway_policy_evaluations(&h), 1);
}

/// A gateway with the admin API and a pinned strategy, serving no surface yet.
async fn start_with_admin_api(fixture: &JwksFixture) -> (GatewayHarness, reqwest::Client) {
    let mut admin = None;
    let h = GatewayHarness::start_with_mock(MockServer::start().await, |temp_dir, _, bootstrap| {
        advertise_public_origin(bootstrap);
        write_strategy(temp_dir, fixture, true);
        admin = Some(helpers::configure_admin_api(bootstrap));
    })
    .await;
    (h, admin.expect("admin API client"))
}

/// Save an A2A surface with the derived declaration on `route` through the admin API,
/// with no policy. Returns the status and the response body.
async fn save_derived_surface(
    h: &GatewayHarness,
    admin: &reqwest::Client,
    name: &str,
    route: &str,
) -> (u16, String) {
    let listen_address = h
        .gateway_base
        .replace("127.0.0.1", "localhost");
    let response = admin
        .post(format!("{}/api/v1/surfaces", h.gateway_base))
        .json(&json!({
            "name": name, "status": "active",
            "access_point": {"listen_address": listen_address, "route": route, "protocol": "a2a",
                "caller_authentication": {"methods": [{"type": "jwt_bearer",
                    "jwt_verification_strategy_id": STRATEGY_ID, "audiences": [SAVED_RESOURCE],
                    "required_scopes": [REQUIRED_SCOPE]}]}},
            "target": {"endpoint": h.mock.url()}
        }))
        .send()
        .await
        .expect("save the surface");
    let status = response.status().as_u16();
    (
        status,
        response
            .text()
            .await
            .expect("save response body"),
    )
}

/// The built-in refusal protects a declaring surface saved through the API, which
/// carries no deny policy, exactly as one written to the configuration.
#[tokio::test(flavor = "multi_thread")]
async fn a_declaring_a2a_surface_saved_through_the_api_refuses_a_failed_caller_without_a_policy() {
    let fixture = JwksFixture::start().await;
    let (h, admin) = start_with_admin_api(&fixture).await;
    let (status, body) = save_derived_surface(&h, &admin, "saved", SAVED_ROUTE).await;
    assert_eq!(status, 201, "{body}");

    let url = format!("{}{SAVED_ROUTE}", h.gateway_base);
    let (missing, body) = send_to(&url, None, a2a_message(), None).await;
    assert_eq!(
        (missing.status, missing.challenges),
        (401, bearer_challenge(SAVED_METADATA_URL, None, Some(REQUIRED_SCOPE))),
        "{body}"
    );
    let (invalid, body) = send_to(&url, Some("not-a-jwt"), a2a_message(), None).await;
    assert_eq!(
        (invalid.status, invalid.challenges),
        (401, bearer_challenge(SAVED_METADATA_URL, Some("invalid_token"), Some(REQUIRED_SCOPE))),
        "{body}"
    );
    let short = signed(&fixture, SAVED_RESOURCE, "read");
    let (short, body) = send_to(&url, Some(&short), a2a_message(), None).await;
    assert_eq!(
        (short.status, short.challenges),
        (403, bearer_challenge(SAVED_METADATA_URL, Some("insufficient_scope"), Some(REQUIRED_SCOPE))),
        "{body}"
    );
    assert_eq!(target_calls(&h), 0, "no refused caller reached the target");

    let admitted = signed(&fixture, SAVED_RESOURCE, REQUIRED_SCOPE);
    let (admitted, body) = send_to(&url, Some(&admitted), a2a_message(), None).await;
    assert_eq!((admitted.status, admitted.challenges), (200, vec![]), "{body}");
    assert_eq!(target_calls(&h), 1);

    let (status, metadata) = fetch_metadata(&h, SAVED_ROUTE).await;
    assert_eq!(status, 200, "{metadata}");
    assert_eq!(metadata["resource"], SAVED_RESOURCE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_route_holding_the_variant_separator_is_refused_on_save() {
    let fixture = JwksFixture::start().await;
    let (h, admin) = start_with_admin_api(&fixture).await;
    for (name, route) in [("dollar", "/smoke/a$b"), ("encoded", "/smoke/a%24b")] {
        let (status, body) = save_derived_surface(&h, &admin, name, route).await;
        assert_eq!(status, 400, "{route}: {body}");
    }
    let (status, body) = save_derived_surface(&h, &admin, "plain", "/smoke/ab").await;
    assert_eq!(status, 201, "{body}");
}
