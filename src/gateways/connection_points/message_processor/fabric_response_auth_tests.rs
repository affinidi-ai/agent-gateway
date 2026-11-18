//! A request a Fabric peer sends reaches the receiving surface's managed agent, and its answer
//! is used only when it passes the surface's Response authentication; one that fails is
//! refused with `502` and recorded as a Fabric request refusal. The agent card read for the
//! surface's policy input yields no card from an answer that fails it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::fabric_transit_tests::{
    CALLER_KEY, SURFACE_ID, forward_request, forward_response, ran_in_child, receiver, surface,
};
use crate::audit::request_events::RejectionReason;
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};
use crate::proxy::response_auth::{BRAVO_KEY, BRAVO_KEY_HEADER, REFUSAL_MESSAGE, api_key_bravo, bravo_key_store};

/// A managed agent that answers every request with a JSON-RPC result, or with an agent card
/// at a card path, carrying its key while `keyed` holds, and counts the requests it answered.
struct ManagedAgent {
    url: String,
    keyed: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    _server: tokio::task::JoinHandle<()>,
}

impl ManagedAgent {
    async fn start() -> Self {
        let keyed = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let (answer_keyed, counted) = (keyed.clone(), calls.clone());
        let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
            let (keyed, counted) = (answer_keyed.clone(), counted.clone());
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                let body = if uri
                    .path()
                    .contains(".well-known/agent")
                {
                    json!({ "name": "bravo" })
                } else {
                    json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } })
                };
                let mut response = axum::response::Response::builder().header("content-type", "application/json");
                if keyed.load(Ordering::SeqCst) {
                    response = response.header(BRAVO_KEY_HEADER, BRAVO_KEY);
                }
                response
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap()
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
        Self {
            url,
            keyed,
            calls,
            _server: server,
        }
    }
}

/// [`surface`] on `target` whose Target's responses are authenticated by `response_auth`.
fn authenticated_surface(
    target: &str,
    response_auth: Value,
) -> AgentSurface {
    let mut value = serde_json::to_value(surface("a2a", target, &[])).unwrap();
    value["target"]["response_auth"] = response_auth;
    serde_json::from_value(value).unwrap()
}

/// An authenticated caller's A2A message, sent by the peer.
fn peer_message(root: &std::path::Path) -> crate::gateways::connection_points::messages::ReceivedMessage {
    forward_request(
        root,
        json!({ "x-api-key": CALLER_KEY, "Content-Type": "application/json" }),
        json!({ "jsonrpc": "2.0", "id": 7, "method": "message/send",
            "params": { "message": { "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] } } }),
    )
}

/// The Fabric request refusals for a Target response that failed Response authentication.
fn fabric_response_auth_refusals(events: &[DelegationAuditEvent]) -> Vec<bool> {
    events
        .iter()
        .filter(|event| {
            matches!(
                event.event,
                DelegationAuditAction::RequestRejected {
                    reason: RejectionReason::TargetResponseAuthFailed,
                    ..
                }
            )
        })
        .map(|event| event.via_fabric)
        .collect()
}

fn body_of(response: &Value) -> Value {
    serde_json::from_str(
        response["body"]
            .as_str()
            .unwrap_or_default(),
    )
    .unwrap_or_else(|error| panic!("the body is not JSON ({error}): {response}"))
}

/// The managed agent's answer without its key is refused with a JSON-RPC `502` naming no
/// reason and recorded as a refused Fabric request; with its key it reaches the peer without it.
#[tokio::test]
async fn a_fabric_request_is_served_only_when_the_managed_agents_answer_carries_its_key() {
    if ran_in_child("ATG_FABRIC_RESPONSE_AUTH_KEY_CHILD").await {
        return;
    }
    let agent = ManagedAgent::start().await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &authenticated_surface(&agent.url, api_key_bravo())).await;
    let (_dir, secrets) = bravo_key_store().await;
    super::init_secrets_store(secrets).await;

    let (response, events) = crate::audit::producer::capture(forward_response(&peer_message(root.path()))).await;
    assert_eq!(response["status"], 502, "{response}");
    let body = body_of(&response);
    assert_eq!(body["id"], 7, "{body}");
    assert_eq!(body["error"]["code"], -32603, "{body}");
    assert_eq!(body["error"]["message"], REFUSAL_MESSAGE, "{body}");
    assert_eq!(fabric_response_auth_refusals(&events), [true], "{events:?}");

    agent
        .keyed
        .store(true, Ordering::SeqCst);
    let response = forward_response(&peer_message(root.path())).await;
    assert_eq!(response["status"], 200, "{response}");
    assert_eq!(body_of(&response)["result"]["ok"], true, "{response}");
    let relayed: Vec<String> = response["headers"]
        .as_object()
        .map(|headers| {
            headers
                .keys()
                .map(|name| name.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !relayed.contains(&BRAVO_KEY_HEADER.to_ascii_lowercase()),
        "the managed agent's key reached the peer: {relayed:?}"
    );
}

/// A managed agent that fails the mTLS server trust ends the connection in the handshake,
/// and the peer's request is refused and recorded as a Fabric request refusal.
#[tokio::test]
async fn a_fabric_request_to_a_server_that_fails_the_mtls_trust_is_refused() {
    if ran_in_child("ATG_FABRIC_RESPONSE_AUTH_MTLS_CHILD").await {
        return;
    }
    let (port, _dir, certificates) = crate::proxy::response_auth::untrusted_target().await;
    crate::proxy::server::init_certificates_store(certificates);
    let root = tempfile::tempdir().unwrap();
    let target = format!("https://127.0.0.1:{port}");
    let _receiver =
        receiver(root.path(), &authenticated_surface(&target, crate::proxy::response_auth::pinned_bravo())).await;

    let (response, events) = crate::audit::producer::capture(forward_response(&peer_message(root.path()))).await;

    assert_eq!(response["status"], 502, "{response}");
    assert_eq!(body_of(&response)["error"]["message"], REFUSAL_MESSAGE, "{response}");
    assert_eq!(fabric_response_auth_refusals(&events), [true], "{events:?}");
}

/// Without the certificate store the mTLS settings cannot be built, so the peer's request is
/// refused before the managed agent is asked.
#[tokio::test]
async fn a_fabric_request_whose_mtls_settings_cannot_be_built_is_refused_unsent() {
    if ran_in_child("ATG_FABRIC_RESPONSE_AUTH_UNVERIFIABLE_CHILD").await {
        return;
    }
    let agent = ManagedAgent::start().await;
    let root = tempfile::tempdir().unwrap();
    let target = agent
        .url
        .replacen("http://", "https://", 1);
    let _receiver =
        receiver(root.path(), &authenticated_surface(&target, crate::proxy::response_auth::pinned_bravo())).await;

    let (response, events) = crate::audit::producer::capture(forward_response(&peer_message(root.path()))).await;

    assert_eq!(response["status"], 502, "{response}");
    assert_eq!(fabric_response_auth_refusals(&events), [true], "{events:?}");
    assert_eq!(
        agent
            .calls
            .load(Ordering::SeqCst),
        0,
        "the managed agent was asked"
    );
}

/// The card read for the policy input yields no card from an answer without the managed
/// agent's key, and the card from one with it.
#[tokio::test]
async fn the_policy_card_read_yields_a_card_only_from_an_answer_carrying_the_key() {
    let agent = ManagedAgent::start().await;
    let (_dir, secrets) = bravo_key_store().await;
    let surface = authenticated_surface(&agent.url, api_key_bravo());
    let card_url = format!("{}/.well-known/agent.json", agent.url);
    let read = || {
        super::TEST_SECRETS_STORE.scope(secrets.clone(), super::read_policy_agent_card(&surface, &card_url, SURFACE_ID))
    };

    assert_eq!(read().await, None, "an answer without the key");
    agent
        .keyed
        .store(true, Ordering::SeqCst);
    assert_eq!(read().await, Some(json!({ "name": "bravo" })), "an answer with the key");
}

/// The card read for the policy input yields no card from a server that fails the mTLS trust.
#[tokio::test]
async fn the_policy_card_read_yields_no_card_from_a_server_that_fails_the_mtls_trust() {
    if ran_in_child("ATG_FABRIC_RESPONSE_AUTH_POLICY_CARD_MTLS_CHILD").await {
        return;
    }
    let (port, _dir, certificates) = crate::proxy::response_auth::untrusted_target().await;
    crate::proxy::server::init_certificates_store(certificates);
    let target = format!("https://127.0.0.1:{port}");
    let surface = authenticated_surface(&target, crate::proxy::response_auth::pinned_bravo());

    assert_eq!(
        super::read_policy_agent_card(&surface, &format!("{target}/.well-known/agent.json"), SURFACE_ID).await,
        None
    );
}
