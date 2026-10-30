//! Where a declaring Access Point answers a caller that fails source
//! authentication: before its body is read, before any admission refusal, and
//! never on the well-known card path.

use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

use super::variant_routing_tests::{
    auth_failure_records, authenticating_router, authenticating_router_trusting, catalog,
    declaring_caller_authentication, idp_token, refusals, stalled_body, surface, surface_declaring_on_its_base,
};
use crate::audit::events::AuthScheme;
use crate::audit::request_events::RejectionStage;
use crate::component_tests::helpers::MockServer;
use crate::component_tests::helpers::jwt::JwksFixture;
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::DelegationAuditEvent;

const MISSING_TOKEN_DETAIL: &str =
    "A bearer token from an authorization server in the protected resource metadata is required";

#[derive(Debug, Clone, Copy)]
enum Protocol {
    Mcp,
    A2a,
}

impl Protocol {
    fn route(self) -> &'static str {
        match self {
            Self::Mcp => "/mcp",
            Self::A2a => "/a2a",
        }
    }

    /// A surface on [`Self::route`] whose base declares, served by its default
    /// variant `prod`, with a Target nothing listens on.
    fn declaring_surface(self) -> AgentSurface {
        match self {
            Self::Mcp => surface_declaring_on_its_base(Some("v-prod")),
            Self::A2a => a2a_surface_declaring_on_its_base("http://127.0.0.1:9"),
        }
    }

    fn challenge(self) -> String {
        format!(
            "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource{}\"",
            self.route()
        )
    }
}

/// The A2A surface at `/a2a` on `endpoint` whose base declares, served by its
/// default variant `prod`.
fn a2a_surface_declaring_on_its_base(endpoint: &str) -> AgentSurface {
    let mut surface = surface(endpoint, catalog(), Some("v-prod"));
    surface
        .access_point
        .caller_authentication = Some(serde_json::from_value(declaring_caller_authentication("/a2a")).unwrap());
    surface
}

fn message(protocol: Protocol) -> String {
    match protocol {
        Protocol::Mcp => json!({"jsonrpc": "2.0", "id": "order", "method": "tools/list"}),
        Protocol::A2a => json!({"jsonrpc": "2.0", "id": "order", "method": "message/send", "params": {"message": {
            "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hello"}]
        }}}),
    }
    .to_string()
}

fn request(
    protocol: Protocol,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: axum::body::Body,
) -> axum::http::Request<axum::body::Body> {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Protocol::Mcp = protocol {
        request = request
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION);
    }
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    request.body(body).unwrap()
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    events: Vec<DelegationAuditEvent>,
}

impl Answer {
    fn header(
        &self,
        name: &str,
    ) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&self.body)))
    }
}

async fn answer(
    router: crate::state::MultiSurfaceProxyState,
    request: axum::http::Request<axum::body::Body>,
) -> Answer {
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
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1 << 20)
        .await
        .unwrap()
        .to_vec();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body,
        events,
    }
}

/// One blocking `auth_failed` for a missing token, served by the variant `prod`.
fn one_blocking_missing_credential() -> Vec<(Option<String>, AuthScheme, String, bool)> {
    vec![(Some("prod".to_string()), AuthScheme::Jwt, "missing_credential".to_string(), true)]
}

fn assert_missing_token_challenge(
    case: &str,
    protocol: Protocol,
    answer: &Answer,
) {
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{case}: {}", String::from_utf8_lossy(&answer.body));
    assert_eq!(answer.header("www-authenticate"), Some(protocol.challenge().as_str()), "{case}");
    assert_eq!(answer.header("content-type"), Some("application/problem+json"), "{case}");
    assert_eq!(answer.header("cache-control"), Some("no-store"), "{case}");
    assert_eq!(
        answer.json(),
        json!({"type": "about:blank", "title": "Unauthorized", "status": 401, "detail": MISSING_TOKEN_DETAIL}),
        "{case}"
    );
    assert_eq!(auth_failure_records(&answer.events), one_blocking_missing_credential(), "{case}");
    assert!(refusals(&answer.events).is_empty(), "{case}: no refusal after the challenge: {:?}", answer.events);
}

/// A failed caller is answered without the gateway waiting on its body, on MCP
/// and A2A alike, while an authenticated caller's body is read.
#[tokio::test]
async fn a_failed_caller_of_a_declaring_access_point_is_challenged_before_its_body_is_read() {
    let fixture = JwksFixture::start().await;
    for protocol in [Protocol::Mcp, Protocol::A2a] {
        let case = format!("{protocol:?}");
        let (router, _strategies) = authenticating_router_trusting(protocol.declaring_surface(), Some(&fixture)).await;
        let (stalled, mut waiting) = tokio::sync::oneshot::channel();

        let failed = tokio::time::timeout(
            Duration::from_secs(2),
            answer(router, request(protocol, "POST", protocol.route(), None, stalled_body(stalled))),
        )
        .await
        .unwrap_or_else(|_| panic!("{case}: a failed caller waits on its body"));

        assert_missing_token_challenge(&case, protocol, &failed);
        assert!(waiting.try_recv().is_err(), "{case}: the body was read past its first chunk");

        let (router, _strategies) = authenticating_router_trusting(protocol.declaring_surface(), Some(&fixture)).await;
        let (stalled, waiting) = tokio::sync::oneshot::channel();
        let token = idp_token(&fixture, &format!("https://gateway.example{}", protocol.route()));
        let reached = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                answered = answer(router, request(protocol, "POST", protocol.route(), Some(&token), stalled_body(stalled))) => {
                    panic!("{case}: an authenticated caller was answered {} before its body was read", answered.status)
                }
                stall = waiting => stall.expect("the body is read"),
            }
        })
        .await;
        assert!(reached.is_ok(), "{case}: an authenticated caller's body is read");
    }
}

/// A failed caller's oversized body never reaches the body limit, so it is
/// challenged rather than refused with `413`; an authenticated caller sending the
/// same body to the MCP Access Point, whose limit is 64 bytes, is refused at
/// admission.
#[tokio::test]
async fn an_oversized_body_from_a_failed_caller_of_a_declaring_access_point_is_challenged_not_413() {
    let oversized = json!({"jsonrpc": "2.0", "id": "order", "method": "tools/list",
        "params": {"padding": "x".repeat(128)}})
    .to_string();
    let limited = |protocol: Protocol| {
        let mut surface = protocol.declaring_surface();
        if let Protocol::Mcp = protocol {
            surface.mcp_http = Some(crate::config::McpHttpConfig {
                max_request_bytes: std::num::NonZeroUsize::new(64).unwrap(),
                ..Default::default()
            });
        }
        surface
    };
    for protocol in [Protocol::Mcp, Protocol::A2a] {
        let case = format!("{protocol:?}");
        let (router, _strategies) = authenticating_router(limited(protocol)).await;

        let failed = answer(
            router,
            request(protocol, "POST", protocol.route(), None, axum::body::Body::from(oversized.clone())),
        )
        .await;

        assert_missing_token_challenge(&case, protocol, &failed);
    }

    let fixture = JwksFixture::start().await;
    let (router, _strategies) = authenticating_router_trusting(limited(Protocol::Mcp), Some(&fixture)).await;
    let token = idp_token(&fixture, "https://gateway.example/mcp");
    let authenticated =
        answer(router, request(Protocol::Mcp, "POST", "/mcp", Some(&token), axum::body::Body::from(oversized))).await;
    assert_eq!(authenticated.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", String::from_utf8_lossy(&authenticated.body));
    assert!(auth_failure_records(&authenticated.events).is_empty(), "{:?}", authenticated.events);
    assert_eq!(
        refusals(&authenticated.events)
            .iter()
            .map(|(stage, _, status, _)| (*stage, *status))
            .collect::<Vec<_>>(),
        vec![(RejectionStage::Admission, Some(413))]
    );
}

/// An A2A caller without a token naming a variant that cannot be resolved gets
/// the problem body and challenge the bare route answers, byte for byte.
#[tokio::test]
async fn an_unresolvable_variant_of_a_declaring_a2a_route_gets_the_problem_body_of_the_bare_route() {
    let send = |path: &'static str| async move {
        let (router, _strategies) = authenticating_router(Protocol::A2a.declaring_surface()).await;
        answer(router, request(Protocol::A2a, "POST", path, None, axum::body::Body::from(message(Protocol::A2a)))).await
    };

    let unresolved = send("/a2a$nope").await;
    let bare = send("/a2a").await;

    assert_eq!(unresolved.status, StatusCode::UNAUTHORIZED, "{}", String::from_utf8_lossy(&unresolved.body));
    assert_eq!(unresolved.header("content-type"), Some("application/problem+json"));
    assert_eq!(
        unresolved.header("www-authenticate"),
        Some(
            Protocol::A2a
                .challenge()
                .as_str()
        )
    );
    assert_eq!(unresolved.json()["detail"], MISSING_TOKEN_DETAIL);
    assert!(refusals(&unresolved.events).is_empty(), "no routing refusal: {:?}", unresolved.events);
    assert_missing_token_challenge("bare route", Protocol::A2a, &bare);
    assert_eq!(unresolved.body, bare.body, "the same problem body");
    assert_eq!(unresolved.header("www-authenticate"), bare.header("www-authenticate"));
}

/// On a declaring Access Point only a GET or HEAD of its well-known card skips
/// source authentication; a path that only ends like a discovery document, and
/// the card path with any other method, is challenged before the Target is asked.
#[tokio::test]
async fn only_the_well_known_card_of_a_declaring_access_point_is_never_challenged() {
    let target =
        MockServer::start_with_response(json!({"name": "orders", "supportedInterfaces": []}).to_string()).await;
    for method in ["GET", "HEAD"] {
        let (router, _strategies) = authenticating_router(a2a_surface_declaring_on_its_base(&target.url())).await;

        let public = answer(
            router,
            request(Protocol::A2a, method, "/a2a/.well-known/agent-card.json", None, axum::body::Body::empty()),
        )
        .await;

        assert_ne!(public.status, StatusCode::UNAUTHORIZED, "{method}: {}", String::from_utf8_lossy(&public.body));
        assert_eq!(public.header("www-authenticate"), None, "{method}");
        assert!(auth_failure_records(&public.events).is_empty(), "{method}: {:?}", public.events);
    }

    let asked = target
        .request_count
        .load(std::sync::atomic::Ordering::SeqCst);
    for (method, path) in [
        ("POST", "/a2a/.well-known/agent-card.json"),
        ("PUT", "/a2a/.well-known/agent.json"),
        ("GET", "/a2a/x/.well-known/agent-card.json"),
    ] {
        let (router, _strategies) = authenticating_router(a2a_surface_declaring_on_its_base(&target.url())).await;

        let challenged = answer(router, request(Protocol::A2a, method, path, None, axum::body::Body::empty())).await;

        assert_missing_token_challenge(&format!("{method} {path}"), Protocol::A2a, &challenged);
    }
    for path in ["/a2a/agent.json", "/a2a/tasks/discovery", "/a2a/x/.well-known/ucp"] {
        let (router, _strategies) = authenticating_router(a2a_surface_declaring_on_its_base(&target.url())).await;

        let challenged = answer(router, request(Protocol::A2a, "GET", path, None, axum::body::Body::empty())).await;

        assert_missing_token_challenge(&format!("GET {path}"), Protocol::A2a, &challenged);
    }
    assert_eq!(
        target
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        asked,
        "a challenged discovery-suffix path never reaches the Target"
    );

    let (router, _strategies) = authenticating_router(a2a_surface_declaring_on_its_base(&target.url())).await;
    let posted = answer(
        router,
        request(Protocol::A2a, "POST", "/a2a/agent-card.json", None, axum::body::Body::from(message(Protocol::A2a))),
    )
    .await;
    assert_missing_token_challenge("POST of a public path", Protocol::A2a, &posted);
}

/// An authenticated GET of a discovery-suffix path on a declaring Access Point is
/// an ordinary request: surface policy decides it.
#[tokio::test]
async fn an_authenticated_discovery_suffix_path_of_a_declaring_access_point_meets_surface_policy() {
    let fixture = JwksFixture::start().await;
    let target =
        MockServer::start_with_response(json!({"name": "orders", "supportedInterfaces": []}).to_string()).await;
    let policies_directory = tempfile::tempdir().unwrap();
    let policies = std::sync::Arc::new(
        crate::policies::policy_definitions::FileSystemPolicyDefinitionStore::new(
            policies_directory
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
                "id": "deny-all", "name": "Deny all", "policy_type": "agent_surface",
                "policy": "package surface.policy\ndefault allow = false", "created_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let mut surface = a2a_surface_declaring_on_its_base(&target.url());
    surface.target.policy = serde_json::from_value(json!({"policy_definition_id": "deny-all"})).unwrap();
    let manager = std::sync::Arc::new(crate::policies::SurfacePolicyManager::new());
    manager.set_policy_definition_store(policies);
    manager
        .update_channel_policy(&surface)
        .await
        .unwrap();
    let (mut router, _strategies) = authenticating_router_trusting(surface, Some(&fixture)).await;
    router.policy_manager = Some(manager);
    let token = idp_token(&fixture, "https://gateway.example/a2a");

    let denied =
        answer(router, request(Protocol::A2a, "GET", "/a2a/tasks/discovery", Some(&token), axum::body::Body::empty()))
            .await;

    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&denied.body));
    assert!(auth_failure_records(&denied.events).is_empty(), "{:?}", denied.events);
    assert_eq!(
        target
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a denied request never reaches the Target"
    );
}

/// A declaring Access Point without required scopes refuses an ID-shaped token
/// with the invalid-token challenge, on MCP and A2A alike, before surface policy,
/// while an access token for the same resource is served.
#[tokio::test]
async fn a_declaring_access_point_without_scopes_challenges_an_id_token_as_invalid() {
    let fixture = JwksFixture::start().await;
    for protocol in [Protocol::Mcp, Protocol::A2a] {
        let case = format!("{protocol:?}");
        let resource = format!("https://gateway.example{}", protocol.route());
        let id_token = crate::component_tests::helpers::jwt::sign_jwt(
            json!({
                "iss": "https://idp.example", "sub": "client", "aud": resource, "nonce": "n-1",
                "exp": crate::component_tests::helpers::jwt::now_secs() + 300,
                "iat": crate::component_tests::helpers::jwt::now_secs(),
            }),
            &fixture.kid,
        );
        let (router, _strategies) = authenticating_router_trusting(protocol.declaring_surface(), Some(&fixture)).await;

        let refused = answer(
            router,
            request(protocol, "POST", protocol.route(), Some(&id_token), axum::body::Body::from(message(protocol))),
        )
        .await;

        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{case}: {}", String::from_utf8_lossy(&refused.body));
        let challenge = refused
            .header("www-authenticate")
            .unwrap_or_default();
        assert!(challenge.contains("error=\"invalid_token\""), "{case}: {challenge}");
        assert_eq!(
            auth_failure_records(&refused.events),
            vec![(Some("prod".to_string()), AuthScheme::Jwt, "invalid_credential".to_string(), true)],
            "{case}"
        );
        assert!(refusals(&refused.events).is_empty(), "{case}: {:?}", refused.events);

        let (router, _strategies) = authenticating_router_trusting(protocol.declaring_surface(), Some(&fixture)).await;
        let served = answer(
            router,
            request(
                protocol,
                "POST",
                protocol.route(),
                Some(&idp_token(&fixture, &resource)),
                axum::body::Body::from(message(protocol)),
            ),
        )
        .await;
        assert!(auth_failure_records(&served.events).is_empty(), "{case}: {:?}", served.events);
    }
}

/// On a declaring Access Point that terminates traces, an authenticated GET of a
/// discovery-suffix path reaches the Target and records one trace bridge, while
/// the well-known card records none.
#[tokio::test]
async fn only_an_authenticated_discovery_suffix_path_of_a_declaring_access_point_records_a_trace_bridge() {
    let fixture = JwksFixture::start().await;
    let target =
        MockServer::start_with_response(json!({"name": "orders", "supportedInterfaces": []}).to_string()).await;
    let terminating = || {
        let mut surface = a2a_surface_declaring_on_its_base(&target.url());
        surface
            .access_point
            .terminate_trace_id = true;
        surface
    };
    let bridges = |answer: &Answer| {
        answer
            .events
            .iter()
            .filter(|event| {
                matches!(event.event, crate::delegation_vault::audit::DelegationAuditAction::TraceTerminated { .. })
            })
            .count()
    };
    let token = idp_token(&fixture, "https://gateway.example/a2a");

    let (router, _strategies) = authenticating_router_trusting(terminating(), Some(&fixture)).await;
    let discovery =
        answer(router, request(Protocol::A2a, "GET", "/a2a/tasks/discovery", Some(&token), axum::body::Body::empty()))
            .await;

    assert_eq!(discovery.status, StatusCode::OK, "{}", String::from_utf8_lossy(&discovery.body));
    assert_eq!(
        target
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(bridges(&discovery), 1, "{:?}", discovery.events);

    let (router, _strategies) = authenticating_router_trusting(terminating(), Some(&fixture)).await;
    let card = answer(
        router,
        request(Protocol::A2a, "GET", "/a2a/.well-known/agent-card.json", None, axum::body::Body::empty()),
    )
    .await;

    assert_ne!(card.status, StatusCode::UNAUTHORIZED, "{}", String::from_utf8_lossy(&card.body));
    assert_eq!(bridges(&card), 0, "{:?}", card.events);
}
