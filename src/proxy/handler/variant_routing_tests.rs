//! How the Access Point serves and refuses a request by the surface variant it
//! selects.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::audit::events::AuthScheme;
use crate::audit::request_events::{RejectionReason, RejectionStage};
use crate::component_tests::helpers::MockServer;
use crate::component_tests::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
use crate::config::agent_surface::AgentSurface;
use crate::config::agent_surface_variants::SurfaceVariant;
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};

pub(super) fn surface(
    endpoint: &str,
    variants: Value,
    default_variant_id: Option<&str>,
) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "orders", "name": "Orders",
        "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
        "target": {"endpoint": endpoint},
        "variants": variants,
        "default_variant_id": default_variant_id
    }))
    .unwrap()
}

/// `prod` and `beta` serve traffic, `off` is disabled.
pub(super) fn catalog() -> Value {
    json!([
        {"id": "v-prod", "alias": "prod", "name": "Prod"},
        {"id": "v-beta", "alias": "beta", "name": "Beta"},
        {"id": "v-off", "alias": "off", "name": "Off", "enabled": false}
    ])
}

pub(super) fn router(surface: AgentSurface) -> crate::state::MultiSurfaceProxyState {
    let config = serde_json::from_value(json!({
        "tls": {"cert_path": "unused.pem", "key_path": "unused-key.pem"},
        "integration": {"variable_pattern": "\\$\\{([^}]+)\\}", "custom_variable_prefix": "_", "types": [], "categories": []},
        "extension_inspection": {"enabled": false}
    }))
    .unwrap();
    let network = serde_json::from_value(json!({
        "did": {"domain": "gateway.example"},
        "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
        "integration": {"types": [], "categories": []},
        "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080,
            "protocol": "http", "external_urls": ["https://gateway.example"]}],
        "routes": {"identity": {"type": "identity_api", "prefix": "/api"}}
    }))
    .unwrap();
    let variant_engines = surface
        .variants
        .iter()
        .map(|variant| {
            (
                variant.id.clone(),
                crate::state::proxy::VariantEngines {
                    identity_rules_engine: None,
                    identity_selector: None,
                    protected_rules_engine: None,
                    protected_selector: None,
                    external_rules_engine: None,
                    external_selector: None,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    crate::state::MultiSurfaceProxyState {
        config: Arc::new(config),
        network_config: Arc::new(network),
        client: reqwest::Client::new(),
        channels: Arc::new(tokio::sync::RwLock::new(vec![crate::state::SurfaceInfo {
            surface: Arc::new(surface),
            identity_rules_engine: None,
            identity_selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
            task_id: "variant-routing".into(),
            variant_engines,
        }])),
        metrics_store: None,
        task_monitor: None,
        ws_state: None,
        listener_manager: Arc::new(tokio::sync::RwLock::new(None)),
        secrets_store: None,
        certificates_store: None,
        vc_issuer: None,
        policy_manager: None,
        gateway_policy_manager: None,
        didauth_session_store: Arc::new(crate::didauth::DidAuthSessionStore::new()),
        transaction_store: None,
        mpp_transaction_store: None,
        trust_registry_listener_manager: None,
        source_auth_middleware: None,
        #[cfg(feature = "didwebvh")]
        didwebvh_identity_store: None,
        #[cfg(feature = "didwebvh")]
        didwebvh_log_manager: None,
        credential_provider_store: None,
        delegation_vault_store: None,
        gateway_base_url: Some("https://gateway.example".into()),
        transit_token_issuer: None,
        mcp_proxy_store: None,
        a2a_proxy_store: None,
        resolved_surface_cache: Arc::new(crate::surfaces::ResolvedSurfaceCache::new()),
    }
}

/// [`router`] with an allow-all response policy on the surface, so a served
/// request writes a policy decision. Returns the directory holding the
/// policy, which the caller keeps alive.
pub(super) async fn router_with_decisions(
    mut surface: AgentSurface
) -> (crate::state::MultiSurfaceProxyState, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let policies = Arc::new(
        crate::policies::policy_definitions::FileSystemPolicyDefinitionStore::new(
            directory
                .path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap(),
    );
    policies
        .save(
            serde_json::from_value(json!({
                "id": "allow-responses", "name": "Allow responses", "policy_type": "agent_surface",
                "policy": "package surface.policy\ndefault allow = true", "created_at": "2026-10-28T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    surface.target.response_policy =
        serde_json::from_value(json!({"policy_definition_id": "allow-responses"})).unwrap();
    let manager = Arc::new(crate::policies::SurfacePolicyManager::new());
    manager.set_policy_definition_store(policies);
    manager
        .update_channel_policy(&surface)
        .await
        .unwrap();
    let mut router = router(surface);
    router.policy_manager = Some(manager);
    (router, directory)
}

/// The `surface_variant` of every record, and how many records there were.
pub(super) fn variants(events: &[DelegationAuditEvent]) -> std::collections::BTreeSet<Option<String>> {
    events
        .iter()
        .map(|event| event.surface_variant.clone())
        .collect()
}

fn decisions(events: &[DelegationAuditEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event.event, DelegationAuditAction::PolicyDecision { .. }))
        .count()
}

/// Sends one A2A message through the Access Point and returns the status with
/// every audit record the request wrote.
pub(super) async fn send(
    router: crate::state::MultiSurfaceProxyState,
    path: &str,
) -> (axum::http::StatusCode, Vec<DelegationAuditEvent>) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
                "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hello"}]
            }}})
            .to_string(),
        ))
        .unwrap();
    let (response, events) =
        crate::audit::producer::capture(Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            router,
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        )))
        .await;
    (response.status(), events)
}

type Refusal = (RejectionStage, RejectionReason, Option<u16>, Option<String>);

pub(super) fn refusals(events: &[DelegationAuditEvent]) -> Vec<Refusal> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected {
                stage,
                reason,
                http_status,
                requested_variant,
                ..
            } => Some((*stage, *reason, *http_status, requested_variant.clone())),
            _ => None,
        })
        .collect()
}

fn refused(
    reason: RejectionReason,
    status: u16,
    requested_variant: Option<&str>,
) -> Vec<Refusal> {
    vec![(RejectionStage::Routing, reason, Some(status), requested_variant.map(str::to_string))]
}

#[tokio::test]
async fn a_variant_that_cannot_be_resolved_is_refused_with_one_status_per_reason() {
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string())
            .await;
    let endpoint = target.url();
    let cases = [
        (
            "unknown alias",
            surface(&endpoint, catalog(), Some("v-prod")),
            "/a2a$missing/rpc",
            refused(RejectionReason::UnknownVariant, 404, Some("missing")),
        ),
        (
            "alias on a surface with no variants",
            surface(&endpoint, json!([]), None),
            "/a2a$beta/rpc",
            refused(RejectionReason::UnknownVariant, 404, Some("beta")),
        ),
        (
            "disabled alias",
            surface(&endpoint, catalog(), Some("v-prod")),
            "/a2a$off/rpc",
            refused(RejectionReason::VariantDisabled, 404, None),
        ),
        (
            "disabled default with no alias",
            surface(&endpoint, catalog(), Some("v-off")),
            "/a2a/rpc",
            refused(RejectionReason::VariantDisabled, 404, None),
        ),
        (
            "misconfigured default with variants",
            surface(&endpoint, catalog(), Some("removed")),
            "/a2a/rpc",
            refused(RejectionReason::MisconfiguredDefault, 500, None),
        ),
        (
            "misconfigured default with no variants",
            surface(&endpoint, json!([]), Some("removed")),
            "/a2a/rpc",
            refused(RejectionReason::MisconfiguredDefault, 500, None),
        ),
    ];
    for (case, surface, path, expected) in cases {
        let (status, events) = send(router(surface), path).await;
        assert_eq!(Some(status.as_u16()), expected[0].2, "{case}: status");
        assert_eq!(refusals(&events), expected, "{case}: recorded refusal");
    }
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        0,
        "no refused request reaches the Target"
    );
}

fn one(variant: &str) -> std::collections::BTreeSet<Option<String>> {
    std::collections::BTreeSet::from([Some(variant.to_string())])
}

/// The future `build` returns, built and kept on the heap. A served request
/// runs deep, so a test that drives one keeps its surfaces and helper futures
/// off its own frame, which stays on the stack for the whole request.
fn on_heap<F: std::future::Future>(build: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(build())
}

#[tokio::test]
async fn every_record_of_a_served_request_names_the_variant_that_served_it() {
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string())
            .await;
    let endpoint = target.url();
    for (case, catalog_json, default_variant_id, path, expected) in [
        ("named variant", catalog(), Some("v-prod"), "/a2a$beta/rpc", "beta"),
        ("default variant", catalog(), Some("v-prod"), "/a2a/rpc", "prod"),
        ("no variants", json!([]), None, "/a2a/rpc", "_base_"),
        ("variants but no default", catalog(), None, "/a2a/rpc", "_base_"),
    ] {
        let (router, _policies) =
            on_heap(|| router_with_decisions(surface(&endpoint, catalog_json, default_variant_id))).await;
        let (status, events) = on_heap(|| send(router, path)).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{case}: {events:?}");
        assert!(decisions(&events) > 0, "{case}: a decision is recorded");
        assert_eq!(variants(&events), one(expected), "{case}");
    }
}

#[tokio::test]
async fn a_request_served_from_the_last_good_snapshot_records_that_snapshots_variant() {
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string())
            .await;
    let endpoint = target.url();
    // The surface list already holds a default the snapshot cache never took,
    // as after a save whose snapshots failed to build.
    let (router, _policies) = on_heap(|| router_with_decisions(surface(&endpoint, catalog(), Some("v-prod")))).await;
    router
        .resolved_surface_cache
        .upsert(&surface(&endpoint, catalog(), Some("v-beta")))
        .unwrap();

    let (status, events) = on_heap(|| send(router, "/a2a/rpc")).await;

    assert_eq!(status, axum::http::StatusCode::OK, "{events:?}");
    assert_eq!(variants(&events), one("beta"), "the snapshot that served the request is beta's");
}

#[tokio::test]
async fn a_refusal_names_the_variant_it_refused_and_never_the_callers_text() {
    let endpoint = "http://127.0.0.1:9";
    let long = "a".repeat(40);
    let long_path = format!("/a2a${long}/rpc");
    let cases = [
        ("unknown alias", surface(endpoint, catalog(), None), "/a2a$typo/rpc", Some("_unknown_"), Some("typo")),
        (
            "alias outside the alias grammar",
            surface(endpoint, catalog(), None),
            "/a2a$Bad_Alias/rpc",
            Some("_unknown_"),
            Some("Bad_Alias"),
        ),
        ("long alias", surface(endpoint, catalog(), None), long_path.as_str(), Some("_unknown_"), Some(&long[..32])),
        ("disabled alias", surface(endpoint, catalog(), None), "/a2a$off/rpc", Some("off"), None),
        ("disabled default", surface(endpoint, catalog(), Some("v-off")), "/a2a/rpc", Some("off"), None),
        ("misconfigured default", surface(endpoint, catalog(), Some("removed")), "/a2a/rpc", None, None),
    ];
    for (case, surface, path, variant, requested) in cases {
        let (_, events) = send(router(surface), path).await;
        assert_eq!(events.len(), 1, "{case}: {events:?}");
        assert_eq!(
            events[0]
                .surface_variant
                .as_deref(),
            variant,
            "{case}"
        );
        assert_eq!(
            refusals(&events)[0]
                .3
                .as_deref(),
            requested,
            "{case}"
        );
    }
}

#[tokio::test]
async fn the_refusal_warning_names_the_requested_variant_cut_never_the_callers_full_alias() {
    let long = "a".repeat(40);
    let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

    send(router(surface("http://127.0.0.1:9", catalog(), None)), &format!("/a2a${long}/rpc")).await;

    let text = logs.text();
    let warnings: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("Surface variant cannot be resolved"))
        .collect();
    assert_eq!(warnings.len(), 1, "{text}");
    assert!(warnings[0].contains("WARN"), "{}", warnings[0]);
    assert!(
        warnings[0].contains("[CHANNEL:orders] Surface variant cannot be resolved"),
        "the dashboard's log filter keys on the channel prefix: {}",
        warnings[0]
    );
    assert!(warnings[0].contains("config_id=\"orders\""), "{}", warnings[0]);
    assert!(warnings[0].contains("UnknownVariant"), "{}", warnings[0]);
    assert!(warnings[0].contains(&long[..32]), "{}", warnings[0]);
    assert!(!warnings[0].contains(&long), "the caller's full alias is logged: {}", warnings[0]);
}

#[tokio::test]
async fn the_refusal_warning_names_a_disabled_variant_in_full() {
    let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

    send(router(surface("http://127.0.0.1:9", catalog(), Some("v-off"))), "/a2a/rpc").await;

    let text = logs.text();
    let warnings: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("Surface variant cannot be resolved"))
        .collect();
    assert_eq!(warnings.len(), 1, "{text}");
    assert!(warnings[0].contains("VariantDisabled"), "{}", warnings[0]);
    assert!(
        warnings[0].contains("disabled_variant=Some(\"off\")"),
        "a configured alias, logged in full: {}",
        warnings[0]
    );
}

#[tokio::test]
async fn an_access_point_request_exports_its_span_with_the_variant() {
    use crate::observability::http_trace::span_capture::{capture_spans, span_attr};
    use tower::ServiceExt;

    crate::observability::register_channel_prefix("/a2a".to_string(), "Orders".to_string());
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string())
            .await;
    let app = axum::Router::new()
        .fallback(super::multi_channel_proxy_handler)
        .with_state(router(surface(&target.url(), catalog(), Some("v-prod"))))
        .layer(axum::middleware::from_fn(crate::observability::http_trace::trace_http_request));
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/a2a$beta/rpc")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
                "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hello"}]
            }}})
            .to_string(),
        ))
        .unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 12345))));

    let (status, spans) = capture_spans(async {
        app.oneshot(request)
            .await
            .unwrap()
            .status()
    })
    .await;

    assert_eq!(status, axum::http::StatusCode::OK);
    let request_span = spans
        .iter()
        .find(|span| span_attr(span, "http.path").is_some())
        .expect("the request span was exported");
    assert_eq!(span_attr(request_span, "surface.variant").as_deref(), Some("beta"));
}

fn mcp_surface(default_variant_id: Option<&str>) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "tools", "name": "Tools",
        "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": "http://127.0.0.1:9"},
        "variants": catalog(),
        "default_variant_id": default_variant_id
    }))
    .unwrap()
}

/// Sends a `tools/list` with the id `variant` to the MCP Access Point, with the
/// modern MCP headers or the legacy version header, and returns the status,
/// the content type, the body and every audit record the request wrote.
async fn send_mcp(
    surface: AgentSurface,
    path: &str,
    modern: bool,
) -> (axum::http::StatusCode, String, Value, Vec<DelegationAuditEvent>) {
    let body = json!({"jsonrpc": "2.0", "id": "variant", "method": "tools/list"}).to_string();
    send_mcp_request(surface, "POST", path, modern, body).await
}

async fn send_mcp_request(
    surface: AgentSurface,
    method: &str,
    path: &str,
    modern: bool,
    body: String,
) -> (axum::http::StatusCode, String, Value, Vec<DelegationAuditEvent>) {
    send_mcp_body(router(surface), method, path, modern, axum::body::Body::from(body)).await
}

async fn send_mcp_body(
    router: crate::state::MultiSurfaceProxyState,
    method: &str,
    path: &str,
    modern: bool,
    body: axum::body::Body,
) -> (axum::http::StatusCode, String, Value, Vec<DelegationAuditEvent>) {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    request = if modern {
        request
            .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
            .header("mcp-method", "tools/list")
    } else {
        request.header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
    };
    let request = request.body(body).unwrap();
    let (response, events) =
        crate::audit::producer::capture(Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            router,
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        )))
        .await;
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    (status, content_type, serde_json::from_slice(&body).unwrap(), events)
}

fn mcp_refusals(events: &[DelegationAuditEvent]) -> Vec<(RejectionReason, Option<u16>, Option<i64>)> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected {
                reason,
                http_status,
                rpc_error_code,
                ..
            } => Some((*reason, *http_status, *rpc_error_code)),
            _ => None,
        })
        .collect()
}

fn mcp_refusal_cases() -> [(&'static str, AgentSurface, &'static str, RejectionReason, u16); 3] {
    [
        ("unknown alias", mcp_surface(Some("v-prod")), "/mcp$missing", RejectionReason::UnknownVariant, 404),
        ("disabled alias", mcp_surface(Some("v-prod")), "/mcp$off", RejectionReason::VariantDisabled, 404),
        ("misconfigured default", mcp_surface(Some("removed")), "/mcp", RejectionReason::MisconfiguredDefault, 500),
    ]
}

/// Asserts a modern MCP refusal: a JSON-RPC error with `-32603`, the given
/// `id` (the key absent when `None`), and exactly one routing record.
fn assert_json_rpc_refusal(
    case: &str,
    (answered, content_type, body, events): (axum::http::StatusCode, String, Value, Vec<DelegationAuditEvent>),
    reason: RejectionReason,
    status: u16,
    id: Option<&str>,
) {
    let code = i64::from(crate::mcp::error_codes::INTERNAL_ERROR);
    assert_eq!(answered.as_u16(), status, "{case}");
    assert_eq!(content_type, "application/json", "{case}");
    assert_eq!(body["jsonrpc"], "2.0", "{case}: {body}");
    assert_eq!(
        body.get("id")
            .and_then(Value::as_str),
        id,
        "{case}: {body}"
    );
    assert_eq!(body.get("id").is_some(), id.is_some(), "{case}: no null id: {body}");
    assert_eq!(body["error"]["code"], code, "{case}: {body}");
    assert!(body.get("result").is_none(), "{case}: {body}");
    assert_eq!(mcp_refusals(&events), vec![(reason, Some(status), Some(code))], "{case}: one record");
}

#[tokio::test]
async fn a_modern_mcp_variant_refusal_echoes_the_request_id() {
    for (case, surface, path, reason, status) in mcp_refusal_cases() {
        let answer = send_mcp(surface, path, true).await;

        assert_json_rpc_refusal(case, answer, reason, status, Some("variant"));
    }
}

#[tokio::test]
async fn a_modern_mcp_variant_refusal_without_a_readable_id_answers_without_one() {
    let bodies = [
        ("not JSON", "not json".to_string()),
        ("notification", json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string()),
    ];
    for (body_case, body) in bodies {
        for (case, surface, path, reason, status) in mcp_refusal_cases() {
            let answer = send_mcp_request(surface, "POST", path, true, body.clone()).await;

            assert_json_rpc_refusal(&format!("{body_case}, {case}"), answer, reason, status, None);
        }
    }
}

#[tokio::test]
async fn an_oversized_modern_mcp_body_is_refused_for_its_variant_without_an_id() {
    let mut surface = mcp_surface(Some("v-prod"));
    surface.mcp_http = Some(crate::config::McpHttpConfig {
        max_request_bytes: std::num::NonZeroUsize::new(64).unwrap(),
        ..Default::default()
    });
    let body =
        json!({"jsonrpc": "2.0", "id": "variant", "method": "tools/list", "params": {"padding": "x".repeat(128)}})
            .to_string();

    let answer = send_mcp_request(surface, "POST", "/mcp$missing", true, body).await;

    assert_json_rpc_refusal("oversized", answer, RejectionReason::UnknownVariant, 404, None);
}

#[tokio::test]
async fn a_modern_mcp_body_over_sixteen_kib_is_refused_for_its_variant_without_an_id() {
    let body = json!({"jsonrpc": "2.0", "id": "variant", "method": "tools/list",
        "params": {"padding": "x".repeat(20 * 1024)}})
    .to_string();

    let answer = send_mcp_request(mcp_surface(Some("v-prod")), "POST", "/mcp$missing", true, body).await;

    assert_json_rpc_refusal("20 KiB under the default limit", answer, RejectionReason::UnknownVariant, 404, None);
}

/// A body that sends the start of an envelope with an id, then nothing more.
/// `stalled` is told once the reader waits for the rest.
fn stalled_body(stalled: tokio::sync::oneshot::Sender<()>) -> axum::body::Body {
    let mut stalled = Some(stalled);
    let prefix = futures::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":"variant","#,
    ))]);
    let stall = futures::stream::poll_fn(move |_| {
        if let Some(stalled) = stalled.take() {
            stalled
                .send(())
                .expect("the test waits for the stall");
        }
        std::task::Poll::<Option<Result<bytes::Bytes, std::io::Error>>>::Pending
    });
    axum::body::Body::from_stream(futures::StreamExt::chain(prefix, stall))
}

#[tokio::test(start_paused = true)]
async fn a_modern_mcp_body_that_stalls_is_refused_at_the_id_read_deadline_without_an_id() {
    let (stalled, _waiting) = tokio::sync::oneshot::channel();
    let started = tokio::time::Instant::now();

    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        send_mcp_body(router(mcp_surface(Some("v-prod"))), "POST", "/mcp$missing", true, stalled_body(stalled)),
    )
    .await
    .expect("a stalled body is answered at the id-read deadline");

    assert_eq!(started.elapsed(), std::time::Duration::from_secs(2), "the id-read deadline");
    assert_json_rpc_refusal("stalled body", answer, RejectionReason::UnknownVariant, 404, None);
}

#[tokio::test(start_paused = true)]
async fn a_surface_update_does_not_wait_for_a_refusal_reading_its_body() {
    let router = router(mcp_surface(Some("v-prod")));
    let channels = Arc::clone(&router.channels);
    let (stalled, waiting) = tokio::sync::oneshot::channel();
    let refusal = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        send_mcp_body(router, "POST", "/mcp$missing", true, stalled_body(stalled)),
    );
    let update = async {
        waiting
            .await
            .expect("the refusal reads its body");
        let surfaces = tokio::time::timeout(std::time::Duration::from_millis(1), channels.write())
            .await
            .expect("a surface update waits for a refusal reading its body");
        drop(surfaces);
    };

    let (answer, ()) = tokio::join!(refusal, update);

    let answer = answer.expect("a stalled body is answered at the id-read deadline");
    assert_json_rpc_refusal("stalled body", answer, RejectionReason::UnknownVariant, 404, None);
}

#[tokio::test]
async fn a_modern_mcp_variant_refusal_of_any_method_echoes_the_id_its_body_carries() {
    let body = json!({"jsonrpc": "2.0", "id": "variant", "method": "tools/list"}).to_string();
    for (case, surface, path, reason, status) in mcp_refusal_cases() {
        let answer = send_mcp_request(surface, "DELETE", path, true, body.clone()).await;

        assert_json_rpc_refusal(&format!("DELETE, {case}"), answer, reason, status, Some("variant"));
    }
}

#[tokio::test]
async fn a_modern_mcp_get_variant_refusal_answers_without_an_id() {
    for (case, surface, path, reason, status) in mcp_refusal_cases() {
        let answer = send_mcp_request(surface, "GET", path, true, String::new()).await;

        assert_json_rpc_refusal(case, answer, reason, status, None);
    }
}

#[tokio::test]
async fn a_legacy_mcp_variant_refusal_keeps_its_plain_error() {
    for (case, surface, path, reason, status) in mcp_refusal_cases() {
        let (answered, _, body, events) = send_mcp(surface, path, false).await;

        assert_eq!(answered.as_u16(), status, "{case}");
        assert!(body.get("jsonrpc").is_none(), "{case}: {body}");
        assert_eq!(body["status"], status, "{case}: {body}");
        assert_eq!(mcp_refusals(&events), vec![(reason, Some(status), None)], "{case}: one record");
    }
}

/// A surface on a `fabric://gw2/orders` Target whose variant `beta` keeps that
/// Target and whose variant `pinned` overrides it with `fabric://gw2/orders$v`.
fn fabric_surface() -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "orders", "name": "Orders",
        "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
        "target": {"endpoint": "fabric://gw2/orders"},
        "variants": [
            {"id": "v-beta", "alias": "beta", "name": "Beta"},
            {"id": "v-pinned", "alias": "pinned", "name": "Pinned", "overrides": {
                "target": {"endpoint": "fabric://gw2/orders$v"}
            }}
        ]
    }))
    .unwrap()
}

#[test]
fn a_fabric_target_is_sent_only_the_alias_it_pins_never_the_callers() {
    let route = |endpoint: &str| super::fabric_send_route(&surface(endpoint, catalog(), None)).unwrap();
    let cases = [
        ("no pinned alias", "fabric://gw2/orders", "orders", None),
        ("a pinned alias", "fabric://gw2/orders$v", "orders", Some("v")),
    ];
    for (case, endpoint, channel_id, variant_alias) in cases {
        let sent = route(endpoint);

        assert_eq!(sent.gateway_id, "gw2", "{case}");
        assert_eq!(sent.channel_id, channel_id, "{case}: the ForwardRequest's channel_id");
        assert_eq!(sent.variant_alias.as_deref(), variant_alias, "{case}: the ForwardRequest's alias");
        assert_eq!(sent.stream_target, endpoint, "{case}: the stream's target");
    }
}

#[test]
fn a_variant_whose_fabric_target_pins_an_alias_sends_it() {
    let cases = [
        ("/a2a$beta: the Target pins nothing", "beta", None, "fabric://gw2/orders"),
        ("/a2a$pinned: the variant's Target pins v", "pinned", Some("v"), "fabric://gw2/orders$v"),
    ];
    for (case, alias, variant_alias, stream_target) in cases {
        let served = fabric_surface()
            .serve_variant(Some(alias))
            .unwrap()
            .surface;

        let sent = super::fabric_send_route(&served).unwrap();

        assert_eq!(sent.channel_id, "orders", "{case}");
        assert_eq!(sent.variant_alias.as_deref(), variant_alias, "{case}");
        assert_eq!(sent.stream_target, stream_target, "{case}");
    }
}

#[test]
fn an_mpp_auto_pay_retry_asks_the_peer_for_the_alias_its_target_pins() {
    let headers = std::collections::HashMap::from([("AUTHORIZATION".to_string(), "Payment proof".to_string())]);
    let cases =
        [("/a2a$beta: the Target pins nothing", "beta", None), ("/a2a$pinned: the Target pins v", "pinned", Some("v"))];
    for (case, alias, pinned) in cases {
        let served = fabric_surface()
            .serve_variant(Some(alias))
            .unwrap()
            .surface;
        let route = super::fabric_send_route(&served).unwrap();

        let body = super::mpp_retry_forward_request_body(
            &route,
            &axum::http::Method::POST,
            "/rpc",
            &headers,
            &json!({"jsonrpc": "2.0"}),
            "trace",
            0,
        );

        assert_eq!(body["channel_id"], "orders", "{case}: {body}");
        assert_eq!(body["virtual_channel_alias"], json!(pinned), "{case}: {body}");
        assert_eq!(body["active_variant_alias"], json!(pinned), "{case}: {body}");
    }
}

#[tokio::test]
async fn a_surface_with_variants_but_no_default_serves_an_alias_less_request_from_the_base() {
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string())
            .await;
    let (status, events) = send(router(surface(&target.url(), catalog(), None)), "/a2a/rpc").await;

    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(refusals(&events).is_empty(), "{events:?}");
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        1
    );
}

/// JWT Bearer caller authentication declaring the protected resource at `/mcp`.
fn declaring_caller_authentication() -> Value {
    json!({
        "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []}],
        "protected_resource": {"resource": "https://gateway.example/mcp", "authorization_servers": ["https://idp.example"]}
    })
}

/// An MCP surface at `/mcp` whose base does not authenticate callers and whose
/// variants `prod` and `beta` declare; `off` is disabled.
fn surface_declaring_through_variants(default_variant_id: Option<&str>) -> AgentSurface {
    let mut surface = mcp_surface(default_variant_id);
    for variant in surface
        .variants
        .iter_mut()
        .filter(|variant| variant.alias != "off")
    {
        variant.overrides = serde_json::from_value(
            json!({"access_point": {"caller_authentication": declaring_caller_authentication()}}),
        )
        .unwrap();
    }
    surface
}

/// [`mcp_surface`] whose base declares.
fn surface_declaring_on_its_base(default_variant_id: Option<&str>) -> AgentSurface {
    let mut surface = mcp_surface(default_variant_id);
    surface
        .access_point
        .caller_authentication = Some(serde_json::from_value(declaring_caller_authentication()).unwrap());
    surface
}

/// [`router`] with source authentication, and the directory its strategies are
/// stored in, which the caller keeps alive.
async fn authenticating_router(surface: AgentSurface) -> (crate::state::MultiSurfaceProxyState, tempfile::TempDir) {
    authenticating_router_trusting(surface, None).await
}

/// [`authenticating_router`] whose strategy `idp` trusts the tokens `fixture`
/// signs, when one is given.
async fn authenticating_router_trusting(
    surface: AgentSurface,
    fixture: Option<&JwksFixture>,
) -> (crate::state::MultiSurfaceProxyState, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    if let Some(fixture) = fixture {
        let strategies = directory
            .path()
            .join("strategies");
        std::fs::create_dir_all(&strategies).unwrap();
        std::fs::write(
            strategies.join("idp.json"),
            json!({
                "id": "idp", "name": "IdP", "expected_issuer": fixture.issuer,
                "jwks_source": {"type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer)},
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
            })
            .to_string(),
        )
        .unwrap();
    }
    let strategies = Arc::new(
        crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(
            directory
                .path()
                .join("strategies"),
        )
        .await
        .unwrap(),
    );
    let mut router = router(surface);
    router.source_auth_middleware = Some(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
        Arc::clone(&router.didauth_session_store),
        strategies,
        Arc::new(crate::jwt_bearer::JwksClient::new()),
        None,
        Arc::new(dashmap::DashMap::new()),
        None,
        None,
    )));
    (router, directory)
}

/// Sends a legacy MCP `tools/list` without credentials and returns the status,
/// the `WWW-Authenticate` challenge and every audit record the request wrote.
async fn send_without_credentials(
    router: crate::state::MultiSurfaceProxyState,
    path: &str,
) -> (u16, Option<String>, Vec<DelegationAuditEvent>) {
    send_with_bearer(router, path, None).await
}

/// [`send_without_credentials`] presenting `bearer`, when one is given.
async fn send_with_bearer(
    router: crate::state::MultiSurfaceProxyState,
    path: &str,
    bearer: Option<&str>,
) -> (u16, Option<String>, Vec<DelegationAuditEvent>) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION);
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let request = request
        .body(axum::body::Body::from(json!({"jsonrpc": "2.0", "id": "variant", "method": "tools/list"}).to_string()))
        .unwrap();
    let (response, events) =
        crate::audit::producer::capture(Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            router,
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        )))
        .await;
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    (response.status().as_u16(), challenge, events)
}

/// The `surface_variant` of each `auth_failed` record.
fn auth_failures(events: &[DelegationAuditEvent]) -> Vec<Option<String>> {
    events
        .iter()
        .filter(|event| matches!(event.event, DelegationAuditAction::AuthFailed { .. }))
        .map(|event| event.surface_variant.clone())
        .collect()
}

const BARE_ROUTE_CHALLENGE: &str =
    "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/mcp\"";

/// A caller without credentials whose variant cannot be resolved gets the
/// challenge the route answers when its URL names no variant, built from the
/// surface that route serves, and the refusal is not recorded.
#[tokio::test]
async fn a_failed_caller_whose_variant_cannot_be_resolved_gets_the_bare_routes_challenge() {
    let cases = [
        (
            "default variant declares, unknown alias",
            surface_declaring_through_variants(Some("v-prod")),
            "/mcp$missing",
            Some("_unknown_"),
        ),
        (
            "default variant declares, disabled alias",
            surface_declaring_through_variants(Some("v-prod")),
            "/mcp$off",
            Some("off"),
        ),
        ("base declares, misconfigured default", surface_declaring_on_its_base(Some("removed")), "/mcp", None),
        ("base declares, disabled default", surface_declaring_on_its_base(Some("v-off")), "/mcp", Some("off")),
    ];
    for (case, surface, path, variant) in cases {
        let (router, _strategies) = authenticating_router(surface).await;

        let (status, challenge, events) = send_without_credentials(router, path).await;

        assert_eq!(status, 401, "{case}");
        assert_eq!(challenge.as_deref(), Some(BARE_ROUTE_CHALLENGE), "{case}");
        assert_eq!(auth_failures(&events), vec![variant.map(str::to_string)], "{case}: one auth_failed record");
        assert!(refusals(&events).is_empty(), "{case}: no routing refusal: {events:?}");
    }
}

/// The bare route's challenge is the one the bare route itself answers.
#[tokio::test]
async fn the_bare_route_answers_the_challenge_an_unresolved_variant_is_given() {
    let (router, _strategies) = authenticating_router(surface_declaring_through_variants(Some("v-prod"))).await;

    let (status, challenge, events) = send_without_credentials(router, "/mcp").await;

    assert_eq!(status, 401);
    assert_eq!(challenge.as_deref(), Some(BARE_ROUTE_CHALLENGE));
    assert_eq!(auth_failures(&events), vec![Some("prod".to_string())]);
}

/// Where only variants declare and no default is set, the bare route does not
/// declare, so a caller without credentials gets the routing refusal for an
/// unknown alias, while a known declaring variant answers with its own challenge.
#[tokio::test]
async fn without_a_declaring_bare_route_an_unresolved_variant_is_refused_and_a_known_one_challenges() {
    let (router, _strategies) = authenticating_router(surface_declaring_through_variants(None)).await;
    let (status, challenge, events) = send_without_credentials(router, "/mcp$missing").await;
    assert_eq!((status, challenge), (404, None));
    assert_eq!(refusals(&events).len(), 1, "{events:?}");
    assert!(auth_failures(&events).is_empty(), "{events:?}");

    let (router, _strategies) = authenticating_router(surface_declaring_through_variants(None)).await;
    let (status, challenge, _) = send_without_credentials(router, "/mcp$beta").await;
    assert_eq!(status, 401);
    assert_eq!(
        challenge.as_deref(),
        Some("Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/mcp$beta\""),
        "a known variant names its own resource"
    );
}

/// The surface variant, scheme, reason and blocking flag of each `auth_failed` record.
fn auth_failure_records(events: &[DelegationAuditEvent]) -> Vec<(Option<String>, AuthScheme, String, bool)> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::AuthFailed { scheme, reason, blocking, .. } => {
                Some((event.surface_variant.clone(), *scheme, reason.clone(), *blocking))
            }
            _ => None,
        })
        .collect()
}

/// The surface variant of each `request_rejected` record.
fn refusal_variants(events: &[DelegationAuditEvent]) -> Vec<Option<String>> {
    events
        .iter()
        .filter(|event| matches!(event.event, DelegationAuditAction::RequestRejected { .. }))
        .map(|event| event.surface_variant.clone())
        .collect()
}

/// A token the trusted IdP signs for the declared resource.
fn resource_token(fixture: &JwksFixture) -> String {
    sign_jwt(
        json!({
            "iss": fixture.issuer, "sub": "client", "aud": "https://gateway.example/mcp",
            "exp": now_secs() + 300, "iat": now_secs(),
        }),
        &fixture.kid,
    )
}

/// A caller that fails authentication on a declaring Access Point and names a
/// variant that cannot be resolved is recorded once, as a blocking `auth_failed`
/// naming the variant the refusal would have named, with the reason the
/// declaration reports, and never as a routing refusal.
#[tokio::test]
async fn a_failed_caller_whose_variant_cannot_be_resolved_is_recorded_as_one_blocking_auth_failure() {
    let fixture = JwksFixture::start().await;
    let cases = [
        ("unknown alias, no token", "/mcp$missing", None, SurfaceVariant::UNKNOWN, "missing_credential"),
        (
            "unknown alias, invalid token",
            "/mcp$missing",
            Some("not-a-jwt"),
            SurfaceVariant::UNKNOWN,
            "invalid_credential",
        ),
        ("disabled alias, no token", "/mcp$off", None, "off", "missing_credential"),
        ("disabled alias, invalid token", "/mcp$off", Some("not-a-jwt"), "off", "invalid_credential"),
    ];
    for (case, path, bearer, variant, reason) in cases {
        let (router, _strategies) =
            authenticating_router_trusting(surface_declaring_through_variants(Some("v-prod")), Some(&fixture)).await;

        let (status, _, events) = send_with_bearer(router, path, bearer).await;

        assert_eq!(status, 401, "{case}");
        assert_eq!(
            auth_failure_records(&events),
            vec![(Some(variant.to_string()), AuthScheme::Jwt, reason.to_string(), true)],
            "{case}"
        );
        assert!(refusal_variants(&events).is_empty(), "{case}: no request_rejected record: {events:?}");
    }
}

/// An authenticated caller naming a variant that cannot be resolved is refused
/// at routing, recorded as a `request_rejected` naming the same variant a failed
/// caller's `auth_failed` names, and never as an authentication failure.
#[tokio::test]
async fn an_authenticated_caller_whose_variant_cannot_be_resolved_is_recorded_as_a_routing_refusal() {
    let fixture = JwksFixture::start().await;
    let cases = [
        (
            "unknown alias",
            "/mcp$missing",
            SurfaceVariant::UNKNOWN,
            refused(RejectionReason::UnknownVariant, 404, Some("missing")),
        ),
        ("disabled alias", "/mcp$off", "off", refused(RejectionReason::VariantDisabled, 404, None)),
    ];
    for (case, path, variant, expected) in cases {
        let (router, _strategies) =
            authenticating_router_trusting(surface_declaring_through_variants(Some("v-prod")), Some(&fixture)).await;

        let (status, challenge, events) = send_with_bearer(router, path, Some(&resource_token(&fixture))).await;

        assert_eq!((status, challenge), (404, None), "{case}");
        assert_eq!(refusals(&events), expected, "{case}");
        assert_eq!(refusal_variants(&events), vec![Some(variant.to_string())], "{case}");
        assert!(auth_failure_records(&events).is_empty(), "{case}: no auth_failed record: {events:?}");
    }
}
