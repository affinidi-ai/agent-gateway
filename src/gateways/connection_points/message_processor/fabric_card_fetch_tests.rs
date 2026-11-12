//! An agent card fetch a Fabric peer sends reaches a protected Target as the
//! receiving gateway's own credentialed request, with only the headers that
//! describe the card relayed back and a redirect refused, and no other public
//! path carries the Target credential. The card read for the receiving
//! surface's policy input presents the same credential.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::fabric_transit_tests::{
    CALLER_KEY, SURFACE_ID, forward_request, forward_response, header_values, ran_in_child, receiver, surface,
};
use crate::audit::request_events::RejectionReason;
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::DelegationAuditAction;
use crate::gateways::connection_points::messages::ReceivedMessage;

const TARGET_KEY_HEADER: &str = "x-target-key";
const TARGET_KEY: &str = "target-key-value";
const PROVIDER_TOKEN: &str = "provider-issued-token";

/// One request the protected Target received.
#[derive(Clone, Debug)]
struct TargetRequest {
    method: axum::http::Method,
    path: String,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
}

/// A Target that records every request and serves an agent card, with a
/// session cookie and an internal header, only to a request carrying its key
/// or the credential provider's token; any other request gets `401`.
struct ProtectedTarget {
    url: String,
    received: Arc<std::sync::Mutex<Vec<TargetRequest>>>,
    _server: tokio::task::JoinHandle<()>,
}

impl ProtectedTarget {
    async fn start() -> Self {
        Self::serving(|headers| {
            headers
                .get(TARGET_KEY_HEADER)
                .is_some_and(|value| value == TARGET_KEY)
                || headers
                    .get("authorization")
                    .is_some_and(|value| value == format!("Bearer {PROVIDER_TOKEN}").as_str())
        })
        .await
    }

    /// A Target that serves its card to every request.
    async fn open() -> Self {
        Self::serving(|_| true).await
    }

    async fn serving(accepts: fn(&axum::http::HeaderMap) -> bool) -> Self {
        use axum::response::IntoResponse;
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = received.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let recorded = recorded.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .unwrap();
                let keyed = accepts(&parts.headers);
                recorded
                    .lock()
                    .unwrap()
                    .push(TargetRequest {
                        method: parts.method,
                        path: parts.uri.path().to_string(),
                        headers: parts.headers,
                        body,
                    });
                if keyed {
                    (
                        axum::http::StatusCode::OK,
                        [
                            ("content-type", "application/json"),
                            ("cache-control", "max-age=60"),
                            ("set-cookie", "target-session=gateway"),
                            ("x-internal", "target-only"),
                        ],
                        r#"{"name":"protected-agent"}"#,
                    )
                        .into_response()
                } else {
                    (axum::http::StatusCode::UNAUTHORIZED, "key rejected for account acme").into_response()
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });
        Self { url, received, _server: server }
    }

    fn received(&self) -> Vec<TargetRequest> {
        self.received
            .lock()
            .unwrap()
            .clone()
    }
}

/// [`surface`] for an A2A Target that requires the key in `secret_id`, served
/// with its card at `card_location` when one is configured.
fn protected_surface(
    target: &str,
    secret_id: &str,
    card_location: Option<&str>,
) -> AgentSurface {
    let mut value = serde_json::to_value(surface("a2a", target, &[])).unwrap();
    value["access_point"]["public"] = json!(true);
    value["target"]["auth"] =
        json!({ "method": { "static_secret": { "secret_id": secret_id, "header_name": TARGET_KEY_HEADER } } });
    if let Some(location) = card_location {
        value["access_point"]["agent_card_path"] = json!(location);
    }
    serde_json::from_value(value).unwrap()
}

async fn store_target_key(secrets: &std::path::Path) {
    use crate::secrets::SecretsStore;
    crate::secrets::FilesystemSecretsStore::new_async(secrets.to_str().unwrap())
        .await
        .unwrap()
        .create(crate::secrets::CreateSecretRequest {
            tenant_id: None,
            name: "Target key".to_string(),
            secret_id: "target-key".to_string(),
            description: None,
            value: TARGET_KEY.to_string(),
            secret_type: "ApiKey".to_string(),
            tags: vec![],
        })
        .await
        .unwrap();
}

/// A peer's `method` request for `path`, carrying credentials, a cookie, content
/// negotiation and a body of its own.
fn peer_request(
    root: &std::path::Path,
    method: &str,
    path: &str,
) -> ReceivedMessage {
    let mut message = forward_request(
        root,
        json!({ "Authorization": "Bearer peer-token", "Cookie": "session=peer", "Accept": "application/json",
            "Accept-Language": "en-GB", "User-Agent": "peer-agent", "X-Custom": "peer", "Content-Type": "application/json" }),
        json!({ "peer": "body" }),
    )
    .with_context("secrets_storage_path", json!(root.join("secrets")));
    message.message_body["method"] = json!(method);
    message.message_body["path"] = json!(path);
    message
}

/// A peer's agent card fetch reaches a protected Target as the gateway's own
/// request, as on the direct path: a bodiless `GET` of the card path with the
/// Target credential and only the peer's `Accept`, `Accept-Language` and
/// `User-Agent`.
#[tokio::test]
async fn an_agent_card_fetch_over_fabric_is_a_credentialed_get_of_the_exact_card_path() {
    if ran_in_child("ATG_FABRIC_CREDENTIALED_CARD_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &protected_surface(&target.url, "target-key", None)).await;
    store_target_key(&root.path().join("secrets")).await;

    let response = forward_response(&peer_request(root.path(), "GET", "/.well-known/agent-card.json")).await;
    assert_eq!(response["status"], 200, "{response}");
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(request.method, axum::http::Method::GET);
    assert_eq!(request.path, "/.well-known/agent-card.json");
    assert!(request.body.is_empty(), "the peer's body was forwarded");
    assert_eq!(header_values(&request.headers, TARGET_KEY_HEADER), [TARGET_KEY]);
    assert_eq!(header_values(&request.headers, "accept"), ["application/json"]);
    assert_eq!(header_values(&request.headers, "accept-language"), ["en-GB"]);
    assert_eq!(header_values(&request.headers, "user-agent"), ["peer-agent"]);
    for withheld in ["authorization", "cookie", "x-custom", "content-type"] {
        assert!(
            request
                .headers
                .get(withheld)
                .is_none(),
            "{withheld} was forwarded"
        );
    }
}

/// The surface's configured card location is a card fetch too, and a well-known
/// card request is fetched from it.
#[tokio::test]
async fn an_agent_card_fetch_over_fabric_uses_the_configured_card_location() {
    if ran_in_child("ATG_FABRIC_CARD_LOCATION_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &protected_surface(&target.url, "target-key", Some("/cards/me"))).await;
    store_target_key(&root.path().join("secrets")).await;

    for path in ["/cards/me", "/.well-known/agent-card.json"] {
        let response = forward_response(&peer_request(root.path(), "GET", path)).await;
        assert_eq!(response["status"], 200, "{path}: {response}");
        let request = target
            .received()
            .pop()
            .unwrap();
        assert_eq!(request.path, "/cards/me", "{path}");
        assert_eq!(header_values(&request.headers, TARGET_KEY_HEADER), [TARGET_KEY], "{path}");
        assert!(
            request
                .headers
                .get("authorization")
                .is_none(),
            "{path}"
        );
    }
}

/// The gateway's own card fetch at a configured card location is not a caller's
/// request, so the managed agent gets no transit token with it, even on a
/// surface with a Transit Point; a caller's request still gets one.
#[tokio::test]
async fn a_card_fetch_at_a_configured_location_carries_no_transit_token() {
    if ran_in_child("ATG_FABRIC_CARD_TRANSIT_TOKEN_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let mut value = serde_json::to_value(protected_surface(&target.url, "target-key", Some("/cards/me"))).unwrap();
    value["transit"] = json!({ "outbound_listen_address": "http://127.0.0.1:9111",
        "points": [{ "alias": "crm", "target_endpoint": "https://crm.example" }] });
    let _receiver = receiver(root.path(), &serde_json::from_value(value).unwrap()).await;
    store_target_key(&root.path().join("secrets")).await;

    let response = forward_response(&peer_request(root.path(), "GET", "/cards/me")).await;
    assert_eq!(response["status"], 200, "{response}");
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(header_values(&request.headers, TARGET_KEY_HEADER), [TARGET_KEY]);
    assert!(
        request
            .headers
            .get("x-transit-token")
            .is_none(),
        "the card fetch carried a transit token"
    );

    let mut authenticated = peer_request(root.path(), "POST", "/rpc");
    authenticated.message_body["headers"]["x-api-key"] = json!(CALLER_KEY);
    let response = forward_response(&authenticated).await;
    assert_eq!(response["status"], 200, "{response}");
    let request = target
        .received()
        .pop()
        .unwrap();
    assert!(
        request
            .headers
            .get("x-transit-token")
            .is_some(),
        "a caller's request carries a transit token"
    );
}

/// Other public reads skip caller authentication and so reach the Target without
/// its credential, as they were sent: another discovery path, a `HEAD` of the
/// card path, the legacy `agent.json`, and a card path spelled with a query or
/// dot segments. So does a `POST` to the card path from a caller who failed
/// source authentication. A request from an authenticated caller still carries it.
#[tokio::test]
async fn a_public_path_over_fabric_other_than_the_card_reaches_the_target_without_its_credential() {
    if ran_in_child("ATG_FABRIC_PUBLIC_PATH_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &protected_surface(&target.url, "target-key", None)).await;
    store_target_key(&root.path().join("secrets")).await;

    for (method, path) in [
        ("GET", "/discovery"),
        ("GET", "/.well-known/ucp"),
        ("GET", "/x/%2e%2e/discovery"),
        ("GET", "/agent/agent-card.json"),
        ("HEAD", "/.well-known/agent-card.json"),
        ("GET", "/.well-known/agent.json"),
        ("GET", "/.well-known/agent-card.json?view=full"),
        ("GET", "/x/../.well-known/agent-card.json"),
        ("POST", "/.well-known/agent-card.json"),
    ] {
        let response = forward_response(&peer_request(root.path(), method, path)).await;
        assert_eq!(response["status"], 401, "{method} {path}: {response}");
        let request = target
            .received()
            .pop()
            .unwrap();
        assert_eq!(request.method.as_str(), method, "{method} {path}");
        assert!(
            request
                .headers
                .get(TARGET_KEY_HEADER)
                .is_none(),
            "{method} {path}: the Target credential was sent"
        );
    }

    let mut authenticated = peer_request(root.path(), "POST", "/rpc");
    authenticated.message_body["headers"]["x-api-key"] = json!(CALLER_KEY);
    let response = forward_response(&authenticated).await;
    assert_eq!(response["status"], 200, "{response}");
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(header_values(&request.headers, TARGET_KEY_HEADER), [TARGET_KEY]);
}

/// The outcome of each `target_auth_failed` record in `events`, with its HTTP status.
fn target_auth_outcomes(
    events: &[crate::delegation_vault::audit::DelegationAuditEvent]
) -> Vec<(Option<u16>, Option<crate::audit::request_events::TargetAuthOutcome>)> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected {
                reason: RejectionReason::TargetAuthFailed,
                http_status,
                target_auth,
                ..
            } => Some((
                *http_status,
                target_auth
                    .as_ref()
                    .map(|rejection| rejection.outcome),
            )),
            _ => None,
        })
        .collect()
}

/// A Target credential that cannot be resolved fails the card fetch, at the
/// well-known path or the configured card location, and any other request with
/// the direct path's `502` text, before the Target is called, and each is
/// recorded once as a rejected `target_auth_failed`.
#[tokio::test]
async fn an_unresolvable_target_credential_over_fabric_answers_target_authentication_failed() {
    if ran_in_child("ATG_FABRIC_TARGET_AUTH_FAILED_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &protected_surface(&target.url, "absent-key", None)).await;
    let located = tempfile::tempdir().unwrap();
    let _located_receiver =
        receiver(located.path(), &protected_surface(&target.url, "absent-key", Some("/cards/me"))).await;

    for (stores, method, path) in [
        (root.path(), "GET", "/.well-known/agent-card.json"),
        (root.path(), "POST", "/rpc"),
        (located.path(), "GET", "/cards/me"),
    ] {
        let mut message = peer_request(stores, method, path);
        message.message_body["headers"]["x-api-key"] = json!(CALLER_KEY);
        let (response, events) = crate::audit::producer::capture(forward_response(&message)).await;
        assert_eq!(
            target_auth_outcomes(&events),
            [(None, Some(crate::audit::request_events::TargetAuthOutcome::Rejected))],
            "{method} {path}"
        );
        assert_eq!(response["status"], 502, "{method} {path}: {response}");
        assert_eq!(response["error"], "Target authentication failed", "{method} {path}");
        let body: Value = serde_json::from_str(
            response["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["detail"], "Target authentication failed", "{method} {path}");
    }
    assert!(target.received().is_empty(), "the Target was called");
}

/// Under `fallback: passthrough` a Target credential that cannot be resolved
/// leaves the card fetch the gateway's own bodiless `GET` with only the peer's
/// `Accept`, `Accept-Language` and `User-Agent`, sent without the credential,
/// and the card the Target serves reaches the peer; the failure is recorded once
/// as a passthrough `target_auth_failed`.
#[tokio::test]
async fn a_passthrough_card_fetch_over_fabric_without_its_credential_returns_the_card() {
    if ran_in_child("ATG_FABRIC_PASSTHROUGH_CARD_CHILD").await {
        return;
    }
    let target = ProtectedTarget::open().await;
    let root = tempfile::tempdir().unwrap();
    let mut value = serde_json::to_value(protected_surface(&target.url, "absent-key", None)).unwrap();
    value["target"]["auth"]["fallback"] = json!("passthrough");
    let _receiver = receiver(root.path(), &serde_json::from_value(value).unwrap()).await;

    let (response, events) = crate::audit::producer::capture(forward_response(&peer_request(
        root.path(),
        "GET",
        "/.well-known/agent-card.json",
    )))
    .await;

    assert_eq!(response["status"], 200, "{response}");
    let card: Value = serde_json::from_str(
        response["body"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(card["name"], "protected-agent");
    assert_eq!(
        target_auth_outcomes(&events),
        [(None, Some(crate::audit::request_events::TargetAuthOutcome::Passthrough))]
    );
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(request.method, axum::http::Method::GET);
    assert_eq!(request.path, "/.well-known/agent-card.json");
    assert!(request.body.is_empty(), "the peer's body was forwarded");
    let mut names: Vec<&str> = request
        .headers
        .keys()
        .map(axum::http::HeaderName::as_str)
        .filter(|name| *name != "host")
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["accept", "accept-encoding", "accept-language", "user-agent"]);
    assert_eq!(header_values(&request.headers, "accept-encoding"), ["identity"]);
    assert_eq!(header_values(&request.headers, "accept"), ["application/json"]);
    assert_eq!(header_values(&request.headers, "accept-language"), ["en-GB"]);
    assert_eq!(header_values(&request.headers, "user-agent"), ["peer-agent"]);
}

/// The card read for the policy input authenticates to the Target as the
/// gateway, with a credential from the gateway's secrets store, so a protected
/// Target's card reaches policy; a credential that cannot be resolved leaves the
/// policy input without a card, or under `fallback: passthrough` reads it
/// without the credential. Each surface's outcome is cached, so a second read
/// neither calls the Target nor resolves the credential.
#[tokio::test]
async fn the_policy_card_read_uses_the_target_credential_and_yields_no_card_without_it() {
    if ran_in_child("ATG_FABRIC_POLICY_CARD_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let secrets = root.path().join("secrets");
    store_target_key(&secrets).await;
    let store: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
        crate::secrets::FilesystemSecretsStore::new_async(secrets.to_str().unwrap())
            .await
            .unwrap(),
    );
    let card = |surface: crate::config::agent_surface::AgentSurface| {
        super::TEST_SECRETS_STORE
            .scope(store.clone(), async move { super::policy_agent_card(&surface, SURFACE_ID).await })
    };
    let named = |surface: AgentSurface, surface_id: &str, fallback: Option<&str>| {
        let mut value = serde_json::to_value(surface).unwrap();
        value["surface_id"] = json!(surface_id);
        if let Some(fallback) = fallback {
            value["target"]["auth"]["fallback"] = json!(fallback);
        }
        serde_json::from_value::<AgentSurface>(value).unwrap()
    };

    let protected = named(protected_surface(&target.url, "target-key", None), "protected", None);
    assert_eq!(card(protected.clone()).await, Some(json!({ "name": "protected-agent" })));
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(request.path, "/.well-known/agent.json");
    assert_eq!(header_values(&request.headers, TARGET_KEY_HEADER), [TARGET_KEY]);
    let called = target.received().len();
    assert_eq!(card(protected).await, Some(json!({ "name": "protected-agent" })), "cached");
    assert_eq!(target.received().len(), called, "a cached card calls the Target again");

    let unresolvable = named(protected_surface(&target.url, "absent-key", None), "unresolvable", None);
    assert_eq!(card(unresolvable).await, None, "absent secret");
    assert_eq!(target.received().len(), called, "the Target was asked without the credential");

    let passthrough = named(protected_surface(&target.url, "absent-key", None), "passthrough", Some("passthrough"));
    assert_eq!(card(passthrough).await, None, "a 401 is no card");
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(request.path, "/.well-known/agent.json");
    assert!(
        request
            .headers
            .get(TARGET_KEY_HEADER)
            .is_none(),
        "passthrough reads the card without the credential"
    );

    let unprotected = named(surface("a2a", &target.url, &[]), "unprotected", None);
    assert_eq!(card(unprotected).await, None, "a 401 is no card");

    let variant_without_auth = named(surface("a2a", &target.url, &[]), "protected", None);
    assert_eq!(card(variant_without_auth).await, None, "a variant without the credential reads its own card");
}

/// The gateway's own card fetch carries no trace id from the peer's request,
/// even where the surface would forward a fresh one; a caller's request still
/// carries one.
#[tokio::test]
async fn a_card_fetch_over_fabric_carries_no_onward_trace_id() {
    if ran_in_child("ATG_FABRIC_CARD_TRACE_ID_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let mut value = serde_json::to_value(protected_surface(&target.url, "target-key", None)).unwrap();
    value["access_point"]["terminate_trace_id"] = json!(true);
    let _receiver = receiver(root.path(), &serde_json::from_value(value).unwrap()).await;
    store_target_key(&root.path().join("secrets")).await;

    let response = forward_response(&peer_request(root.path(), "GET", "/.well-known/agent-card.json")).await;
    assert_eq!(response["status"], 200, "{response}");
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(header_values(&request.headers, TARGET_KEY_HEADER), [TARGET_KEY]);
    assert!(
        request
            .headers
            .get("x-gateway-trace-id")
            .is_none(),
        "the card fetch carried a trace id"
    );

    let mut authenticated = peer_request(root.path(), "POST", "/rpc");
    authenticated.message_body["headers"]["x-api-key"] = json!(CALLER_KEY);
    let response = forward_response(&authenticated).await;
    assert_eq!(response["status"], 200, "{response}");
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(header_values(&request.headers, "x-gateway-trace-id").len(), 1, "a caller's request carries a trace id");
}

fn response_header_names(response: &Value) -> Vec<String> {
    response["headers"]
        .as_object()
        .map(|headers| {
            headers
                .keys()
                .map(|name| name.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

/// The Target answered the gateway's own card fetch, which carried its
/// credential, so only the headers that describe the card reach the peer; a
/// caller's request still gets every response header.
#[tokio::test]
async fn a_card_fetch_over_fabric_relays_only_the_headers_that_describe_the_card() {
    if ran_in_child("ATG_FABRIC_CARD_RESPONSE_HEADERS_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &protected_surface(&target.url, "target-key", None)).await;
    store_target_key(&root.path().join("secrets")).await;

    let response = forward_response(&peer_request(root.path(), "GET", "/.well-known/agent-card.json")).await;
    assert_eq!(response["status"], 200, "{response}");
    let relayed = response_header_names(&response);
    for kept in ["content-type", "cache-control"] {
        assert!(relayed.contains(&kept.to_string()), "{kept} missing from {relayed:?}");
    }
    for withheld in ["set-cookie", "x-internal"] {
        assert!(!relayed.contains(&withheld.to_string()), "{withheld} relayed in {relayed:?}");
    }

    let mut authenticated = peer_request(root.path(), "POST", "/rpc");
    authenticated.message_body["headers"]["x-api-key"] = json!(CALLER_KEY);
    let response = forward_response(&authenticated).await;
    assert_eq!(response["status"], 200, "{response}");
    let relayed = response_header_names(&response);
    assert!(relayed.contains(&"set-cookie".to_string()), "a caller's request relays {relayed:?}");
}

/// A Target that refuses the gateway's own card fetch answers the peer with only
/// its status, as on the direct path, so nothing the Target says about the
/// gateway's credential reaches the peer.
#[tokio::test]
async fn a_refused_card_fetch_over_fabric_answers_only_the_status() {
    if ran_in_child("ATG_FABRIC_REFUSED_CARD_CHILD").await {
        return;
    }
    use crate::secrets::SecretsStore;
    let target = ProtectedTarget::start().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &protected_surface(&target.url, "stale-key", None)).await;
    crate::secrets::FilesystemSecretsStore::new_async(
        root.path()
            .join("secrets")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap()
    .create(crate::secrets::CreateSecretRequest {
        tenant_id: None,
        name: "Stale key".to_string(),
        secret_id: "stale-key".to_string(),
        description: None,
        value: "stale".to_string(),
        secret_type: "ApiKey".to_string(),
        tags: vec![],
    })
    .await
    .unwrap();

    let response = forward_response(&peer_request(root.path(), "GET", "/.well-known/agent-card.json")).await;
    assert_eq!(response["status"], 401, "{response}");
    assert_eq!(
        header_values(
            &target
                .received()
                .pop()
                .unwrap()
                .headers,
            TARGET_KEY_HEADER
        ),
        ["stale"]
    );
    let body = response["body"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(!body.contains("acme"), "the Target's answer reached the peer: {body}");
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["detail"], "Upstream error: 401");

    let mut value = serde_json::to_value(protected_surface(&target.url, "stale-key", None)).unwrap();
    value["target"]
        .as_object_mut()
        .unwrap()
        .remove("auth");
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &serde_json::from_value(value).unwrap()).await;
    let response = forward_response(&peer_request(root.path(), "GET", "/.well-known/agent-card.json")).await;
    assert_eq!(response["status"], 401, "{response}");
    assert!(
        response["body"]
            .as_str()
            .unwrap_or_default()
            .contains("acme"),
        "without Target authentication the answer is relayed as before: {response}"
    );
}

/// A Target that redirects the gateway's own card fetch answers the peer `502`
/// "Upstream redirected", as on the direct path: the gateway never follows the
/// redirect, and neither its `Location` nor its body reaches the peer. Without
/// Target authentication the redirect is relayed as before.
#[tokio::test]
async fn a_redirected_card_fetch_over_fabric_answers_upstream_redirected() {
    use axum::response::IntoResponse;
    use std::sync::atomic::Ordering::SeqCst;
    if ran_in_child("ATG_FABRIC_REDIRECTED_CARD_CHILD").await {
        return;
    }
    let status = Arc::new(std::sync::atomic::AtomicU16::new(302));
    let keyed_fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (answer, keyed) = (status.clone(), keyed_fetches.clone());
    let app = axum::Router::new().fallback(move |headers: axum::http::HeaderMap| {
        let (answer, keyed) = (answer.clone(), keyed.clone());
        async move {
            if headers
                .get(TARGET_KEY_HEADER)
                .is_some_and(|value| value == TARGET_KEY)
            {
                keyed.fetch_add(1, SeqCst);
            }
            (
                axum::http::StatusCode::from_u16(answer.load(SeqCst)).unwrap(),
                [("location", "https://idp.example/login?state=redirect-state")],
                "sign in for account acme-7731",
            )
                .into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let target_url = format!("http://{}", listener.local_addr().unwrap());
    let _server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .ok();
    });
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &protected_surface(&target_url, "target-key", None)).await;
    store_target_key(&root.path().join("secrets")).await;

    let redirects = [301, 302, 303, 307, 308];
    for redirect in redirects {
        status.store(redirect, SeqCst);
        let response = forward_response(&peer_request(root.path(), "GET", "/.well-known/agent-card.json")).await;
        assert_eq!(response["status"], 502, "{redirect}: {response}");
        assert!(!response_header_names(&response).contains(&"location".to_string()), "{redirect}: {response}");
        let body = response["body"]
            .as_str()
            .unwrap_or_default();
        assert!(
            !body.contains("idp.example") && !body.contains("acme"),
            "{redirect}: the Target's answer reached the peer: {body}"
        );
        let body: Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["detail"], crate::proxy::handler::UPSTREAM_REDIRECTED, "{redirect}");
        assert_eq!(body["status"], 502, "{redirect}");
    }
    assert_eq!(keyed_fetches.load(SeqCst), redirects.len(), "every fetch carried the Target credential");

    let mut value = serde_json::to_value(protected_surface(&target_url, "target-key", None)).unwrap();
    value["target"]
        .as_object_mut()
        .unwrap()
        .remove("auth");
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &serde_json::from_value(value).unwrap()).await;
    status.store(302, SeqCst);
    let response = forward_response(&peer_request(root.path(), "GET", "/.well-known/agent-card.json")).await;
    assert_eq!(response["status"], 302, "without Target authentication the redirect is relayed as before: {response}");
}

/// A client credentials token endpoint that issues [`PROVIDER_TOKEN`] and counts
/// the token requests it answered.
struct TokenEndpoint {
    url: String,
    requests: Arc<std::sync::atomic::AtomicUsize>,
    _server: tokio::task::JoinHandle<()>,
}

/// The client secret of [`TARGET_PROVIDER`], which never leaves the gateway but in a token request.
const PROVIDER_CLIENT_SECRET: &str = "fabric-provider-client-secret";
/// The `error_description` a refusing token endpoint answers with, which the gateway never relays,
/// records or logs.
const REFUSED_TOKEN_DESCRIPTION: &str = "fabric-token-endpoint-description";

impl TokenEndpoint {
    async fn start() -> Self {
        Self::answering(200, json!({ "access_token": PROVIDER_TOKEN, "token_type": "Bearer", "expires_in": 3600 }))
            .await
    }

    /// A token endpoint that refuses the client with an OAuth `invalid_client` error whose
    /// description names the client secret.
    async fn refusing() -> Self {
        Self::answering(
            401,
            json!({ "error": "invalid_client",
                "error_description": format!("{REFUSED_TOKEN_DESCRIPTION}: {PROVIDER_CLIENT_SECRET} rejected") }),
        )
        .await
    }

    async fn answering(
        status: u16,
        body: Value,
    ) -> Self {
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = requests.clone();
        let app = axum::Router::new().fallback(axum::routing::post(move || {
            let counted = counted.clone();
            let body = body.clone();
            async move {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                (axum::http::StatusCode::from_u16(status).unwrap(), axum::Json(body))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });
        Self { url, requests, _server: server }
    }

    fn requests(&self) -> usize {
        self.requests
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn egress(&self) -> crate::delegation_vault::oauth::TokenEgress {
        crate::delegation_vault::oauth::TokenEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(self.url.clone()),
            policy: Default::default(),
        }
    }
}

const TARGET_PROVIDER: &str = "target-provider";

/// [`surface`] for an A2A Target that requires a token from the client
/// credentials provider [`TARGET_PROVIDER`].
fn provider_surface(target: &str) -> AgentSurface {
    let mut value = serde_json::to_value(surface("a2a", target, &[])).unwrap();
    value["target"]["auth"] = json!({ "method": { "credential_provider": { "provider_id": TARGET_PROVIDER } } });
    serde_json::from_value(value).unwrap()
}

/// Installs the client credentials provider [`TARGET_PROVIDER`] of `token_endpoint`
/// and a delegation vault as the gateway's stores, with the provider's client
/// credentials in `root/secrets`.
async fn install_target_provider(
    root: &std::path::Path,
    token_endpoint: &str,
) {
    use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
    use crate::secrets::SecretsStore;
    let secrets = crate::secrets::FilesystemSecretsStore::new_async(
        root.join("secrets")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    for (secret_id, value) in [("CLIENT_ID", "client"), ("CLIENT_SECRET", PROVIDER_CLIENT_SECRET)] {
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: value.into(),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .unwrap();
    }
    let providers = FileSystemCredentialProviderStore::new(root.join("providers"))
        .await
        .unwrap();
    providers
        .create(
            serde_json::from_value(json!({
                "id": TARGET_PROVIDER, "name": TARGET_PROVIDER, "provider_id": TARGET_PROVIDER,
                "provider_type": "oauth2_client_credentials", "token_endpoint": token_endpoint,
                "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET",
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    super::init_credential_provider_store(Arc::new(providers) as Arc<dyn CredentialProviderStorage>).await;
    super::init_delegation_vault_store(Arc::new(
        crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(root.join("vault"))
            .await
            .unwrap(),
    ))
    .await;
}

/// A peer's agent card fetch reaches a Target protected by a client credentials
/// provider with the provider's token as a bearer token, obtained with one token
/// request, and never with the peer's own `Authorization`.
#[tokio::test]
async fn an_agent_card_fetch_over_fabric_presents_the_credential_providers_token() {
    if ran_in_child("ATG_FABRIC_PROVIDER_CARD_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let token_endpoint = TokenEndpoint::start().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &provider_surface(&target.url)).await;
    install_target_provider(root.path(), &token_endpoint.url).await;

    let response = token_endpoint
        .egress()
        .scope(forward_response(&peer_request(root.path(), "GET", "/.well-known/agent-card.json")))
        .await;

    assert_eq!(response["status"], 200, "{response}");
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(request.method, axum::http::Method::GET);
    assert_eq!(request.path, "/.well-known/agent-card.json");
    assert_eq!(header_values(&request.headers, "authorization"), [format!("Bearer {PROVIDER_TOKEN}")]);
    assert_eq!(token_endpoint.requests(), 1, "token requests");
}

/// A credential provider that refuses its token request fails a peer's agent
/// card fetch with the direct path's `502` "Target authentication failed"
/// before the Target is called, and records one rejected `target_auth_failed`
/// naming the provider and the OAuth `error` code. Neither the token endpoint's
/// `error_description` nor the client secret reaches the peer, the audit record
/// or the logs.
#[tokio::test]
async fn a_refused_provider_token_fails_a_card_fetch_over_fabric_with_target_authentication_failed() {
    use tracing::instrument::WithSubscriber;
    if ran_in_child("ATG_FABRIC_REFUSED_PROVIDER_CARD_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let token_endpoint = TokenEndpoint::refusing().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &provider_surface(&target.url)).await;
    install_target_provider(root.path(), &token_endpoint.url).await;
    let logs = super::mcp_receive_tests::CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();

    let (response, events) = token_endpoint
        .egress()
        .scope(crate::audit::producer::capture(forward_response(&peer_request(
            root.path(),
            "GET",
            "/.well-known/agent-card.json",
        ))))
        .with_subscriber(subscriber)
        .await;

    assert_eq!(response["status"], 502, "{response}");
    let body: Value = serde_json::from_str(
        response["body"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["detail"], crate::proxy::handler::TARGET_AUTH_FAILED);
    assert_eq!(token_endpoint.requests(), 1, "token requests");
    assert!(target.received().is_empty(), "the Target was called");
    let rejections: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected {
                reason: RejectionReason::TargetAuthFailed,
                target_auth: Some(rejection),
                ..
            } => Some((
                event.provider_id.as_deref(),
                rejection.outcome,
                rejection
                    .oauth_error
                    .as_deref(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        rejections,
        [(Some(TARGET_PROVIDER), crate::audit::request_events::TargetAuthOutcome::Rejected, Some("invalid_client"))]
    );
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("invalid_client"), "the OAuth error code was not logged:\n{logs}");
    for (sink, text) in
        [("response", response.to_string()), ("audit record", serde_json::to_string(&events).unwrap()), ("logs", logs)]
    {
        for (what, value) in [
            ("the token endpoint's description", REFUSED_TOKEN_DESCRIPTION),
            ("the client secret", PROVIDER_CLIENT_SECRET),
        ] {
            assert!(!text.contains(value), "{what} reached the {sink}");
        }
    }
}

/// Under `fallback: passthrough` a credential provider that refuses its token
/// request leaves the card fetch over Fabric without the credential, and the
/// Target's card reaches the peer; the failure is recorded once as a passthrough
/// `target_auth_failed`.
#[tokio::test]
async fn a_refused_provider_token_under_passthrough_fetches_the_card_over_fabric_without_it() {
    if ran_in_child("ATG_FABRIC_PASSTHROUGH_PROVIDER_CARD_CHILD").await {
        return;
    }
    let target = ProtectedTarget::open().await;
    let token_endpoint = TokenEndpoint::refusing().await;
    let root = tempfile::tempdir().unwrap();
    let mut value = serde_json::to_value(provider_surface(&target.url)).unwrap();
    value["target"]["auth"]["fallback"] = json!("passthrough");
    let _receiver = receiver(root.path(), &serde_json::from_value(value).unwrap()).await;
    install_target_provider(root.path(), &token_endpoint.url).await;

    let (response, events) = token_endpoint
        .egress()
        .scope(crate::audit::producer::capture(forward_response(&peer_request(
            root.path(),
            "GET",
            "/.well-known/agent-card.json",
        ))))
        .await;

    assert_eq!(response["status"], 200, "{response}");
    let card: Value = serde_json::from_str(
        response["body"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(card["name"], "protected-agent");
    assert_eq!(token_endpoint.requests(), 1, "token requests");
    assert_eq!(
        target_auth_outcomes(&events),
        [(None, Some(crate::audit::request_events::TargetAuthOutcome::Passthrough))]
    );
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(request.path, "/.well-known/agent-card.json");
    assert!(
        request
            .headers
            .get("authorization")
            .is_none(),
        "an Authorization header reached the Target: {:?}",
        request.headers
    );
}

/// The card read for the policy input presents the client credentials
/// provider's token too, obtained with one token request.
#[tokio::test]
async fn the_policy_card_read_presents_the_credential_providers_token() {
    if ran_in_child("ATG_FABRIC_PROVIDER_POLICY_CARD_CHILD").await {
        return;
    }
    let target = ProtectedTarget::start().await;
    let token_endpoint = TokenEndpoint::start().await;
    let root = tempfile::tempdir().unwrap();
    install_target_provider(root.path(), &token_endpoint.url).await;
    let store: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
        crate::secrets::FilesystemSecretsStore::new_async(
            root.path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap(),
    );
    let surface = provider_surface(&target.url);

    let card = token_endpoint
        .egress()
        .scope(super::TEST_SECRETS_STORE.scope(store, async { super::policy_agent_card(&surface, SURFACE_ID).await }))
        .await;

    assert_eq!(card, Some(json!({ "name": "protected-agent" })));
    let request = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(request.path, "/.well-known/agent.json");
    assert_eq!(header_values(&request.headers, "authorization"), [format!("Bearer {PROVIDER_TOKEN}")]);
    assert_eq!(token_endpoint.requests(), 1, "token requests");
}

/// The card read for the policy input drops a provider token the Target refuses
/// as `invalid_token`, as the forward does, so a refused token does not leave a
/// policy that needs the card without one until the token expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_policy_card_read_drops_a_token_its_target_refuses_as_invalid() {
    use crate::proxy::handler::target_auth_tests::{
        BackendAnswer, Fixture, assert_a_refused_token_is_dropped, backend_answering, provider_auth,
    };
    if ran_in_child("ATG_FABRIC_POLICY_CARD_REFUSED_TOKEN_CHILD").await {
        return;
    }
    let fixture = Fixture::new(200).await;
    let answer = BackendAnswer::new(std::sync::Mutex::new((200, None)));
    let (target_url, _target) = backend_answering(answer.clone(), json!({ "name": "protected-agent" })).await;
    let mut surface = surface("a2a", &target_url, &[]);
    surface.target.auth = Some(provider_auth("machine"));
    super::init_credential_provider_store(fixture.providers.clone()).await;
    super::init_delegation_vault_store(fixture.vault.clone()).await;
    let card_url = format!("{target_url}/.well-known/agent.json");
    let call = || {
        let read = fixture.egress.clone().scope(
            super::TEST_SECRETS_STORE
                .scope(fixture.secrets.clone(), super::read_policy_agent_card(&surface, &card_url, SURFACE_ID)),
        );
        async move { json!({ "isError": read.await.is_none() }) }
    };

    assert_a_refused_token_is_dropped(&fixture, &answer, "policy card read", call).await;
}

/// A Target that is not an `http(s)` URL, such as a `proxy://` MCP proxy or a
/// further `fabric://` hop, has no card to read for the policy input, so no
/// credential is resolved and no provider token requested for it.
#[tokio::test]
async fn the_policy_card_read_resolves_no_credential_for_a_target_that_is_not_http() {
    if ran_in_child("ATG_FABRIC_POLICY_CARD_NOT_HTTP_CHILD").await {
        return;
    }
    let token_endpoint = TokenEndpoint::start().await;
    let root = tempfile::tempdir().unwrap();
    install_target_provider(root.path(), &token_endpoint.url).await;
    let store: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
        crate::secrets::FilesystemSecretsStore::new_async(
            root.path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap(),
    );

    for endpoint in ["proxy://tools", "fabric://did:web:peer.example/orders"] {
        let surface = provider_surface(endpoint);
        let card = token_endpoint
            .egress()
            .scope(super::TEST_SECRETS_STORE.scope(store.clone(), super::policy_agent_card(&surface, SURFACE_ID)))
            .await;
        assert_eq!(card, None, "{endpoint}");
    }
    assert_eq!(token_endpoint.requests(), 0, "no provider token is requested for a card that cannot be read");
}

/// The card read for the policy input logs the card location it fetches without
/// its query values, and the card's `url` without its userinfo or query values.
#[tokio::test]
async fn the_policy_card_read_logs_the_card_location_and_the_cards_url_redacted() {
    use axum::response::IntoResponse;
    use tracing::instrument::WithSubscriber;
    let app = axum::Router::new().fallback(|| async {
        (
            [("content-type", "application/json")],
            r#"{"name":"agent","url":"https://user:card-password@agent.example/a2a?token=card-query-secret"}"#,
        )
            .into_response()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let card_url =
        format!("http://{}/.well-known/agent.json?token=location-query-secret", listener.local_addr().unwrap());
    let _server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .ok();
    });
    let logs = super::mcp_receive_tests::CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();

    let card = super::read_policy_agent_card(&surface("a2a", "http://127.0.0.1", &[]), &card_url, SURFACE_ID)
        .with_subscriber(subscriber)
        .await;

    assert_eq!(card.unwrap()["name"], "agent");
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("/.well-known/agent.json?token="), "the card location was not logged:\n{logs}");
    assert!(logs.contains("agent.example/a2a"), "the card url was not logged:\n{logs}");
    for (what, value) in [
        ("the card location's query value", "location-query-secret"),
        ("the card url's password", "card-password"),
        ("the card url's query value", "card-query-secret"),
    ] {
        assert!(!logs.contains(value), "{what} was logged");
    }
}
