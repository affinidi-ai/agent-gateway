use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{Router, extract::Request, response::Response, routing::any};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::helpers::{self, GatewayHarness, ReceivedRequest};

const PROXY_ID: &str = "worker-proxy";
const SECRET_ID: &str = "direct-line-secret";
const SECRET_VALUE: &str = "test-direct-line-secret";
const GENERATED_DIRECT_LINE_TOKEN: &str = "test-generated-direct-line-token";
const TARGET_TRUST_CHECK_POLICY_ID: &str = "a2a-proxy-target-trust-check-deny";
const AGENT_IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
const TRUST_REGISTRY_EXTENSION_URI: &str = "https://fabric.affinidi.io/extensions/trust-registry";
const TARGET_TRUST_CHECK_DENY_REGO: &str = r#"package channel.policy

default allow := false

allow if {
    not input.trust_check_results
}

allow if {
    input.trust_check_results
    count([r | r := input.trust_check_results.target[_]; r.error.code == "TRUST_REGISTRY_UNREACHABLE"]) == 0
}
"#;

fn enable_local_a2a_dial_for_tests() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // SAFETY: set exactly once, before any A2A dial runs; only the A2A-proxy
        // egress path reads this var and every test in this module wants it on.
        unsafe { std::env::set_var("AG_ALLOW_LOCAL_A2A_PROXY", "1") };
    });
}

struct FakeDirectLine {
    base_url: String,
    requests: Arc<Mutex<Vec<ReceivedRequest>>>,
    request_count: Arc<AtomicUsize>,
    _handle: tokio::task::JoinHandle<()>,
}

impl FakeDirectLine {
    async fn start(reply_text: &'static str) -> Self {
        Self::start_with_reply(Some(reply_text)).await
    }

    async fn start_without_reply() -> Self {
        Self::start_with_reply(None).await
    }

    async fn start_with_reply(reply_text: Option<&'static str>) -> Self {
        // The A2A-proxy dial now goes through the strict SSRF egress guard, which
        // blocks loopback by default. These component tests point `base_url` at a
        // loopback mock, so enable the dev/test hatch that allow-lists the exact
        // dialed URL (cloud metadata stays blocked). Set once for the test process;
        // only the A2A dial reads it and every A2A test wants it on.
        enable_local_a2a_dial_for_tests();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Direct Line");
        let addr = listener
            .local_addr()
            .expect("fake Direct Line addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_count = Arc::new(AtomicUsize::new(0));

        let app = Router::new()
            .route("/", any(Self::handler(reply_text, requests.clone(), request_count.clone())))
            .route("/{*path}", any(Self::handler(reply_text, requests.clone(), request_count.clone())));

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            base_url: format!("http://{addr}/v3/directline"),
            requests,
            request_count,
            _handle: handle,
        }
    }

    fn handler(
        reply_text: Option<&'static str>,
        requests: Arc<Mutex<Vec<ReceivedRequest>>>,
        request_count: Arc<AtomicUsize>,
    ) -> impl Clone + Send + 'static + Fn(Request) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
    {
        move |req: Request| {
            let requests = requests.clone();
            let request_count = request_count.clone();
            Box::pin(async move {
                request_count.fetch_add(1, Ordering::SeqCst);
                let method = req.method().to_string();
                let path = req.uri().path().to_string();
                let headers: HashMap<String, String> = req
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|v| (k.as_str().to_string(), v.to_string()))
                    })
                    .collect();
                let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                    .await
                    .unwrap_or_default();
                let body = String::from_utf8_lossy(&body).to_string();
                requests
                    .lock()
                    .expect("record fake Direct Line request")
                    .push(ReceivedRequest {
                        method: method.clone(),
                        path: path.clone(),
                        headers,
                        body,
                    });

                let response = if method == "POST" && path == "/v3/directline/tokens/generate" {
                    json!({ "token": GENERATED_DIRECT_LINE_TOKEN, "expires_in": 1800 })
                } else if method == "POST" && path == "/v3/directline/conversations" {
                    json!({ "conversationId": "conv-1" })
                } else if method == "POST" && path == "/v3/directline/conversations/conv-1/activities" {
                    json!({ "id": "activity-1" })
                } else if method == "GET" && path == "/v3/directline/conversations/conv-1/activities" {
                    match reply_text {
                        Some(reply_text) => json!({
                            "activities": [{
                                "type": "message",
                                "from": { "id": "copilot-worker" },
                                "text": reply_text
                            }],
                            "watermark": "1"
                        }),
                        None => json!({
                            "activities": [],
                            "watermark": "1"
                        }),
                    }
                } else {
                    json!({ "error": format!("unexpected {method} {path}") })
                };

                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(response.to_string()))
                    .unwrap()
            })
        }
    }

    fn requests(&self) -> Vec<ReceivedRequest> {
        self.requests
            .lock()
            .expect("read fake Direct Line requests")
            .clone()
    }
}

fn a2a_text_request(parts: Vec<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "kind": "message",
                "messageId": "msg-001",
                "contextId": "ctx-001",
                "parts": parts
            }
        }
    })
}

async fn start_a2a_proxy_harness(fake_direct_line: &FakeDirectLine) -> GatewayHarness {
    start_a2a_proxy_harness_with_options(fake_direct_line, "active", true).await
}

async fn start_a2a_proxy_harness_with_target_trust_check(fake_direct_line: &FakeDirectLine) -> GatewayHarness {
    let direct_line_base_url = fake_direct_line
        .base_url
        .clone();
    GatewayHarness::start(move |temp_dir, gw_config, _| {
        write_target_trust_check_policy_definition(temp_dir);
        let mut surface_json = serde_json::to_value(helpers::build_minimal_channel()).expect("surface JSON");
        surface_json["target"]["endpoint"] = json!(format!("a2a-proxy://{PROXY_ID}"));
        surface_json["target"]["a2a_proxy_id"] = json!(PROXY_ID);
        surface_json["target"]["policy"] = json!({ "policy_definition_id": TARGET_TRUST_CHECK_POLICY_ID });
        surface_json["target"]["trust_check_list"] = json!([{
            "id": "target-recognition",
            "trust_registry_id": "tr-unreachable",
            "query_type": "recognition",
            "query": {
                "authority_id": "did:example:provider",
                "entity_id": "did:example:agent"
            }
        }]);
        gw_config.surfaces = vec![serde_json::from_value(surface_json).expect("A2A proxy trust-check surface")];
        write_a2a_proxy_fixtures(temp_dir, &direct_line_base_url, "active", true, 5, 100, 3);
    })
    .await
}

fn write_target_trust_check_policy_definition(temp_dir: &std::path::Path) {
    let definition = json!({
        "id": TARGET_TRUST_CHECK_POLICY_ID,
        "name": "A2A Proxy target Trust Check deny",
        "description": "Denies when target Trust Check cannot reach the configured registry.",
        "policy_type": "agent_surface",
        "policy": TARGET_TRUST_CHECK_DENY_REGO,
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z"
    });
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{TARGET_TRUST_CHECK_POLICY_ID}.json")),
        serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
    )
    .expect("write target trust-check policy definition fixture");
}

fn write_a2a_proxy_fixtures(
    temp_dir: &std::path::Path,
    direct_line_base_url: &str,
    status: &'static str,
    write_proxy: bool,
    timeout_secs: u32,
    poll_interval_ms: u32,
    max_poll_attempts: u32,
) {
    write_a2a_proxy_fixtures_with_credential_mode(
        temp_dir,
        direct_line_base_url,
        status,
        write_proxy,
        "secret",
        timeout_secs,
        poll_interval_ms,
        max_poll_attempts,
    );
}

fn write_a2a_proxy_fixtures_with_credential_mode(
    temp_dir: &std::path::Path,
    direct_line_base_url: &str,
    status: &'static str,
    write_proxy: bool,
    credential_mode: &'static str,
    timeout_secs: u32,
    poll_interval_ms: u32,
    max_poll_attempts: u32,
) {
    let now = chrono::Utc::now().to_rfc3339();
    let secret_dir = temp_dir.join("secrets");
    std::fs::create_dir_all(&secret_dir).expect("create secrets dir");
    std::fs::write(
        secret_dir.join("secret-1.json"),
        json!({
            "id": "secret-1",
            "name": "Direct Line Secret",
            "secret_id": SECRET_ID,
            "description": null,
            "value": SECRET_VALUE,
            "secret_type": "General",
            "tags": [],
            "created_at": now,
            "updated_at": now
        })
        .to_string(),
    )
    .expect("write Direct Line secret fixture");

    if write_proxy {
        let proxy_dir = temp_dir.join("a2a_proxies");
        std::fs::create_dir_all(&proxy_dir).expect("create A2A proxy dir");
        std::fs::write(
            proxy_dir.join(format!("{PROXY_ID}.json")),
            json!({
                "id": PROXY_ID,
                "name": "Copilot Worker",
                "description": "Fake Direct Line worker",
                "status": status,
                "backend": {
                    "kind": "copilot_direct_line",
                    "secret_id": SECRET_ID,
                    "credential_mode": credential_mode,
                    "base_url": direct_line_base_url,
                    "timeout_secs": timeout_secs,
                    "poll_interval_ms": poll_interval_ms,
                    "max_poll_attempts": max_poll_attempts
                },
                "agent_card": {
                    "name": PROXY_ID,
                    "description": format!("BDD A2A proxy {PROXY_ID}")
                },
                "agent_identity": {
                    "type": "entra_agent",
                    "entra_agent_id": "00000000-0000-0000-0000-000000000000",
                    "client_tenant_id": "11111111-1111-1111-1111-111111111111"
                },
                "created_at": now,
                "updated_at": now
            })
            .to_string(),
        )
        .expect("write A2A proxy fixture");
    }
}

async fn start_a2a_proxy_harness_with_options(
    fake_direct_line: &FakeDirectLine,
    status: &'static str,
    write_proxy: bool,
) -> GatewayHarness {
    start_a2a_proxy_harness_with_backend_options(fake_direct_line, status, write_proxy, 5, 100, 3).await
}

async fn start_a2a_proxy_harness_with_credential_mode(
    fake_direct_line: &FakeDirectLine,
    credential_mode: &'static str,
) -> GatewayHarness {
    let direct_line_base_url = fake_direct_line
        .base_url
        .clone();
    GatewayHarness::start(move |temp_dir, gw_config, _| {
        let mut surface = helpers::build_minimal_channel();
        surface.target.endpoint = format!("a2a-proxy://{PROXY_ID}");
        surface.target.a2a_proxy_id = Some(PROXY_ID.to_string());
        gw_config.surfaces = vec![surface];

        write_a2a_proxy_fixtures_with_credential_mode(
            temp_dir,
            &direct_line_base_url,
            "active",
            true,
            credential_mode,
            5,
            100,
            3,
        );
    })
    .await
}

async fn start_a2a_proxy_harness_with_backend_options(
    fake_direct_line: &FakeDirectLine,
    status: &'static str,
    write_proxy: bool,
    timeout_secs: u32,
    poll_interval_ms: u32,
    max_poll_attempts: u32,
) -> GatewayHarness {
    let direct_line_base_url = fake_direct_line
        .base_url
        .clone();
    GatewayHarness::start(move |temp_dir, gw_config, _| {
        let mut surface_json = serde_json::to_value(helpers::build_minimal_channel()).expect("surface JSON");
        surface_json["target"]["endpoint"] = json!(format!("a2a-proxy://{PROXY_ID}"));
        surface_json["target"]["a2a_proxy_id"] = json!(PROXY_ID);
        gw_config.surfaces = vec![serde_json::from_value(surface_json).expect("A2A proxy surface")];

        write_a2a_proxy_fixtures(
            temp_dir,
            &direct_line_base_url,
            status,
            write_proxy,
            timeout_secs,
            poll_interval_ms,
            max_poll_attempts,
        );
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_text_message_send_reaches_direct_line_and_returns_a2a_text_response() {
    let fake_direct_line = FakeDirectLine::start("Hello from Copilot").await;
    let h = start_a2a_proxy_harness(&fake_direct_line).await;
    let client = reqwest::Client::new();
    let request = a2a_text_request(vec![json!({ "kind": "text", "text": "Hello, worker!" })]);

    let response = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-from-caller", "do-not-forward")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200);
    let body: Value = response
        .json()
        .await
        .expect("A2A proxy response JSON");
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 7);
    assert_eq!(body["result"]["kind"], "message");
    assert_eq!(body["result"]["role"], "agent");
    assert_eq!(body["result"]["contextId"], "ctx-001");
    assert_eq!(body["result"]["parts"][0]["kind"], "text");
    assert_eq!(body["result"]["parts"][0]["text"], "Hello from Copilot");

    let requests = fake_direct_line.requests();
    assert_eq!(requests.len(), 3, "create conversation, post activity, poll activities");
    let activity_post = requests
        .iter()
        .find(|request| {
            request.method == "POST"
                && request
                    .path
                    .ends_with("/activities")
        })
        .expect("Direct Line activity post");
    let activity_body: Value = serde_json::from_str(&activity_post.body).expect("activity JSON");
    assert_eq!(activity_body["type"], "message");
    assert_eq!(activity_body["text"], "Hello, worker!");
    assert_eq!(
        activity_post
            .headers
            .get("authorization")
            .map(String::as_str),
        Some("Bearer test-direct-line-secret")
    );
    assert!(
        !activity_post
            .headers
            .contains_key("x-from-caller")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_generate_token_mode_exchanges_direct_line_secret_for_token() {
    let fake_direct_line = FakeDirectLine::start("Hello with token").await;
    let h = start_a2a_proxy_harness_with_credential_mode(&fake_direct_line, "generate_token").await;
    let request = a2a_text_request(vec![json!({ "kind": "text", "text": "Hello, token mode!" })]);

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200);
    let body: Value = response
        .json()
        .await
        .expect("A2A proxy response JSON");
    assert_eq!(body["result"]["parts"][0]["text"], "Hello with token");

    let requests = fake_direct_line.requests();
    let token_request = requests
        .iter()
        .find(|request| request.method == "POST" && request.path == "/v3/directline/tokens/generate")
        .expect("Direct Line token generation request");
    assert_eq!(
        token_request
            .headers
            .get("authorization")
            .map(String::as_str),
        Some("Bearer test-direct-line-secret")
    );

    let activity_post = requests
        .iter()
        .find(|request| {
            request.method == "POST"
                && request
                    .path
                    .ends_with("/activities")
        })
        .expect("Direct Line activity post");
    assert_eq!(
        activity_post
            .headers
            .get("authorization")
            .map(String::as_str),
        Some("Bearer test-generated-direct-line-token")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_target_synthesizes_public_agent_card_without_calling_direct_line() {
    let fake_direct_line = FakeDirectLine::start("should not be called").await;
    let h = start_a2a_proxy_harness(&fake_direct_line).await;
    let agent_card_url = h
        .gateway_url
        .replace("/rpc", "/.well-known/agent-card.json");

    let response = reqwest::Client::new()
        .get(&agent_card_url)
        .send()
        .await
        .expect("fetch synthesized agent card");

    assert_eq!(response.status(), 200);
    assert!(
        response
            .headers()
            .get_all(reqwest::header::VARY)
            .iter()
            .any(|value| value == "A2A-Version, Accept"),
        "agent card response must vary on the negotiation headers: {:?}",
        response.headers()
    );
    let card: Value = response
        .json()
        .await
        .expect("agent card JSON");
    assert_eq!(card["name"], "worker-proxy");
    assert_eq!(card["description"], "BDD A2A proxy worker-proxy");
    let expected_url = h
        .gateway_base
        .replace("127.0.0.1", "localhost");
    assert_eq!(card["url"], format!("{expected_url}/smoke/rpc"));
    assert_eq!(card["capabilities"]["streaming"], false);
    assert_eq!(card["defaultInputModes"][0], "text/plain");
    assert_eq!(card["skills"][0]["id"], "message-send-text");

    let extensions = card["capabilities"]["extensions"]
        .as_array()
        .expect("capabilities.extensions");
    let credential_ext = extensions
        .iter()
        .find(|ext| {
            ext.get("uri")
                .and_then(Value::as_str)
                == Some(AGENT_IDENTITY_CREDENTIAL_URI)
        })
        .expect("credential extension");
    let credential_did = credential_ext["params"]["did"]
        .as_str()
        .expect("credential did");
    assert!(credential_did.starts_with("did:"));
    assert!(
        credential_ext["params"]["verifiablePresentation"]
            .as_str()
            .is_some_and(|vp| vp.matches('.').count() >= 2),
        "credential extension should carry a compact VP"
    );

    assert!(
        extensions
            .iter()
            .all(|ext| ext
                .get("uri")
                .and_then(Value::as_str)
                != Some(TRUST_REGISTRY_EXTENSION_URI)),
        "trust-registry extension is no longer injected into agent cards"
    );
    assert_eq!(
        fake_direct_line
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_target_trust_check_uses_synthesized_agent_card_before_dispatch() {
    let fake_direct_line = FakeDirectLine::start("should not be called").await;
    let h = start_a2a_proxy_harness_with_target_trust_check(&fake_direct_line).await;
    let request = a2a_text_request(vec![json!({ "kind": "text", "text": "hello" })]);

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 403);
    let body: Value = response
        .json()
        .await
        .expect("policy denial body");
    assert_eq!(body["error"], "Forbidden");
    assert_eq!(body["message"], "Agent trust policy denied the request");
    assert_eq!(
        fake_direct_line
            .request_count
            .load(Ordering::SeqCst),
        0,
        "target Trust Check denial must happen before Direct Line dispatch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_multiple_text_parts_are_joined_deterministically() {
    let fake_direct_line = FakeDirectLine::start("Joined").await;
    let h = start_a2a_proxy_harness(&fake_direct_line).await;
    let request =
        a2a_text_request(vec![json!({ "kind": "text", "text": "hello" }), json!({ "kind": "text", "text": "worker" })]);

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200);
    let requests = fake_direct_line.requests();
    let activity_post = requests
        .iter()
        .find(|request| {
            request.method == "POST"
                && request
                    .path
                    .ends_with("/activities")
        })
        .expect("Direct Line activity post");
    let activity_body: Value = serde_json::from_str(&activity_post.body).expect("activity JSON");
    assert_eq!(activity_body["text"], "hello\nworker");
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_missing_record_returns_target_unavailable_before_backend_call() {
    let fake_direct_line = FakeDirectLine::start("should not be called").await;
    let h = start_a2a_proxy_harness_with_options(&fake_direct_line, "active", false).await;
    let request = a2a_text_request(vec![json!({ "kind": "text", "text": "hello" })]);

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200);
    let body: Value = response
        .json()
        .await
        .expect("JSON-RPC error JSON");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], -32020);
    assert_eq!(body["error"]["message"], "A2A proxy not found");
    assert_eq!(
        fake_direct_line
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_disabled_record_returns_target_unavailable_before_backend_call() {
    let fake_direct_line = FakeDirectLine::start("should not be called").await;
    let h = start_a2a_proxy_harness_with_options(&fake_direct_line, "disabled", true).await;
    let request = a2a_text_request(vec![json!({ "kind": "text", "text": "hello" })]);

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200);
    let body: Value = response
        .json()
        .await
        .expect("JSON-RPC error JSON");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], -32020);
    assert_eq!(body["error"]["message"], "A2A proxy is disabled");
    assert_eq!(
        fake_direct_line
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_direct_line_without_bot_reply_returns_target_timeout() {
    let fake_direct_line = FakeDirectLine::start_without_reply().await;
    let h = start_a2a_proxy_harness_with_backend_options(&fake_direct_line, "active", true, 1, 100, 2).await;
    let request = a2a_text_request(vec![json!({ "kind": "text", "text": "hello" })]);

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200);
    let body: Value = response
        .json()
        .await
        .expect("JSON-RPC error JSON");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], -32021);
    assert_eq!(body["error"]["message"], "A2A proxy target timed out");

    let requests = fake_direct_line.requests();
    assert!(
        requests
            .iter()
            .any(|request| request.method == "POST"
                && request
                    .path
                    .ends_with("/activities")),
        "Direct Line activity should be posted before polling times out; requests: {requests:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_non_text_parts_are_rejected_before_backend_call() {
    let fake_direct_line = FakeDirectLine::start("should not be called").await;
    let h = start_a2a_proxy_harness(&fake_direct_line).await;
    let request = a2a_text_request(vec![json!({ "kind": "file", "file": { "name": "a.txt" } })]);

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200);
    let body: Value = response
        .json()
        .await
        .expect("JSON-RPC error JSON");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], -32602);
    assert_eq!(
        fake_direct_line
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_unsupported_methods_are_rejected_before_backend_call() {
    let fake_direct_line = FakeDirectLine::start("should not be called").await;
    let h = start_a2a_proxy_harness(&fake_direct_line).await;
    let mut request = a2a_text_request(vec![json!({ "kind": "text", "text": "hello" })]);
    // A well-formed tasks/get, so the proxy's method gate is what refuses it
    // rather than request-shape validation upstream of it.
    request["method"] = json!("tasks/get");
    request["params"] = json!({ "id": "task-1" });

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200);
    let body: Value = response
        .json()
        .await
        .expect("JSON-RPC error JSON");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], -32601);
    assert_eq!(
        fake_direct_line
            .request_count
            .load(Ordering::SeqCst),
        0
    );
}

/// Request-shape validation applies to **managed agents only**, never to an
/// A2A-proxy target.
///
/// A managed agent validates its own payloads, so checking at the gateway fails
/// a bad request sooner and names the field. An A2A proxy is different: it is
/// not a pass-through to an A2A agent, it is the implementation. It translates
/// the message into a non-A2A backend and needs only `params.message` and text
/// parts, so there is no downstream agent that would have refused a message
/// missing `messageId` or `role`. Validating here would not fail a request
/// sooner, it would fail one that works today, and the callers affected are the
/// ones least able to change what their tooling emits.
#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_accepts_a_message_a_managed_agent_would_refuse() {
    let fake_direct_line = FakeDirectLine::start("hello from the bot").await;
    let h = start_a2a_proxy_harness(&fake_direct_line).await;

    // No `messageId` and no `role`: both required by A2A, and both refused on a
    // managed-agent surface.
    let request = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "message/send",
        "params": { "message": { "parts": [{ "kind": "text", "text": "hello" }] } }
    });

    let response = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("send request through gateway");

    assert_eq!(response.status(), 200, "an A2A proxy must not refuse a message its backend can serve");

    let body: Value = response
        .json()
        .await
        .expect("JSON response");
    assert!(body.get("error").is_none(), "expected the proxy to serve the request, got {body}");
}
