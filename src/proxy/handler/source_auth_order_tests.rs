//! Where a declaring Access Point answers a caller that fails source
//! authentication: before its body is read, before any admission refusal, and
//! never on a public path.

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

/// A GET or HEAD of a public path skips source authentication on a declaring
/// Access Point; the same path with any other method is challenged.
#[tokio::test]
async fn a_public_path_of_a_declaring_access_point_is_never_challenged() {
    let target =
        MockServer::start_with_response(json!({"name": "orders", "supportedInterfaces": []}).to_string()).await;
    for path in ["/a2a/.well-known/agent-card.json", "/a2a/agent.json"] {
        let (router, _strategies) = authenticating_router(a2a_surface_declaring_on_its_base(&target.url())).await;

        let public = answer(router, request(Protocol::A2a, "GET", path, None, axum::body::Body::empty())).await;

        assert_ne!(public.status, StatusCode::UNAUTHORIZED, "{path}: {}", String::from_utf8_lossy(&public.body));
        assert_eq!(public.header("www-authenticate"), None, "{path}");
        assert!(auth_failure_records(&public.events).is_empty(), "{path}: {:?}", public.events);
    }

    let (router, _strategies) = authenticating_router(a2a_surface_declaring_on_its_base(&target.url())).await;
    let posted = answer(
        router,
        request(Protocol::A2a, "POST", "/a2a/agent-card.json", None, axum::body::Body::from(message(Protocol::A2a))),
    )
    .await;
    assert_missing_token_challenge("POST of a public path", Protocol::A2a, &posted);
}
