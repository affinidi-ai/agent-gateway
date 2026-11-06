//! A request a Fabric peer sends reaches the managed agent with a transit token
//! this gateway issued for it, naming the peer and the Fabric crossings, never
//! with a token the peer sent; a request past the hop limit is refused before
//! anything is forwarded. An agent card fetch reaches a protected Target as the
//! gateway's own credentialed request, and no other public path carries the
//! Target credential.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::{
    FabricDelegationRefusal, FabricReceiveCaller, ProcessingResult, fabric_caller_did_and_source,
    fabric_delegation_refusal, fabric_receive_transit_token, fabric_response_workload_binding,
    transit_token_unavailable_refusal,
};
use crate::audit::request_events::{RejectionReason, RejectionStage};
use crate::component_tests::helpers::RecordingTarget;
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::DelegationAuditAction;
use crate::gateways::GatewayStore;
use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
use crate::gateways::types::{ExposureMode, Gateway, GatewayStatus, GatewayType};
use crate::messages::MessageType;
use crate::proxy::caller_identity::IdentitySource;
use crate::proxy::transit_token::{FabricTransitClaims, TransitTokenClaims, TransitTokenIssuer, TransitTokenKey};
use crate::surface_context::IdentityVerification;
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

pub(super) const PEER_CONNECTION_POINT_DID: &str = "did:web:peer.example";
pub(super) const PEER_ISSUER_DID: &str = "did:web:partner.example";
pub(super) const SURFACE_ID: &str = "fabric-transit";
pub(super) const CALLER_KEY: &str = "peer-target-auth-key";

/// Runs the calling test again in a child process, where the process-wide
/// stores this path reads are unset until the test sets them. Returns `true`
/// in the parent, which then has nothing more to do.
pub(super) async fn ran_in_child(variable: &str) -> bool {
    if std::env::var_os(variable).is_some() {
        return false;
    }
    let test_name = std::thread::current()
        .name()
        .unwrap()
        .to_string();
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(variable, "1")
        .env("RUST_MIN_STACK", "8388608")
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "isolated {test_name} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

pub(super) fn test_issuer() -> TransitTokenIssuer {
    TransitTokenIssuer::new(TransitTokenKey::from_parts("fabric-test-kid", [9; 32]), "receiver.example".to_string())
}

fn network() -> crate::config::NetworkConfig {
    serde_json::from_value(json!({
        "did": {"domain": "receiver.example"},
        "webauthn": {"rp_id": "receiver.example", "external_origin": "https://receiver.example"},
        "integration": {"types": [], "categories": []},
        "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080,
            "protocol": "http", "external_urls": ["https://receiver.example"]}],
        "routes": {"identity": {"type": "identity_api", "prefix": "/api"}}
    }))
    .unwrap()
}

fn peer() -> Gateway {
    let mut peer =
        Gateway::new("Partner".to_string(), String::new(), PEER_CONNECTION_POINT_DID.to_string(), GatewayType::Remote);
    peer.status = GatewayStatus::Active;
    peer.exposure_mode = Some(ExposureMode::All);
    peer.issuer_did = Some(PEER_ISSUER_DID.to_string());
    peer
}

/// A surface whose Target is `target` and whose Transit Points are `aliases`,
/// authenticating its callers with an API key header the peer's
/// `target_auth` sends.
pub(super) fn surface(
    protocol: &str,
    target: &str,
    aliases: &[&str],
) -> AgentSurface {
    let points: Vec<Value> = aliases
        .iter()
        .map(|alias| json!({ "alias": alias, "target_endpoint": format!("https://{alias}.example") }))
        .collect();
    let mut surface = json!({
        "surface_id": SURFACE_ID, "name": SURFACE_ID,
        "access_point": { "listen_address": "127.0.0.1:8080", "route": "/agent", "protocol": protocol,
            "caller_authentication": { "methods": [{ "type": "api_key", "secret_id": "peer-callers",
                "extraction": { "source": "http_header", "field": "x-api-key" } }] } },
        "target": { "endpoint": target }
    });
    if !points.is_empty() {
        surface["transit"] = json!({ "outbound_listen_address": "http://127.0.0.1:9111", "points": points });
    }
    serde_json::from_value(surface).unwrap()
}

/// The receiving gateway's stores under `root`, the peer paired, the caller
/// key the surface checks stored, and `surface` saved.
async fn receiver(
    root: &std::path::Path,
    surface: &AgentSurface,
) -> (Gateway, tempfile::TempDir) {
    let strategies = Arc::new(
        crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(root.join("strategies"))
            .await
            .unwrap(),
    );
    receiver_with_strategies(root, surface, strategies).await
}

/// [`receiver`], whose source authentication reads JWT verification
/// strategies from `strategies`.
pub(super) async fn receiver_with_strategies(
    root: &std::path::Path,
    surface: &AgentSurface,
    strategies: Arc<crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore>,
) -> (Gateway, tempfile::TempDir) {
    receiver_trusting(root, surface, strategies, Vec::new()).await
}

/// [`receiver_with_strategies`], whose connection to the peer also trusts
/// identity presentations from `trusted_issuers`.
pub(super) async fn receiver_trusting(
    root: &std::path::Path,
    surface: &AgentSurface,
    strategies: Arc<crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore>,
    trusted_issuers: Vec<String>,
) -> (Gateway, tempfile::TempDir) {
    use crate::secrets::SecretsStore;
    let secrets = crate::secrets::FilesystemSecretsStore::new_async(
        root.join("secrets")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    secrets
        .create(crate::secrets::CreateSecretRequest {
            tenant_id: None,
            name: "Peer callers".to_string(),
            secret_id: "peer-callers".to_string(),
            description: None,
            value: CALLER_KEY.to_string(),
            secret_type: "ApiKey".to_string(),
            tags: vec![],
        })
        .await
        .unwrap();
    super::init_source_auth_middleware(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
        Arc::new(crate::didauth::DidAuthSessionStore::new()),
        strategies,
        Arc::new(crate::jwt_bearer::JwksClient::new()),
        Some(Arc::new(secrets)),
        Arc::new(dashmap::DashMap::new()),
        None,
        None,
    )))
    .await;
    super::init_mcp_auth_network(Arc::new(network()));
    crate::proxy::server::init_transit_token_issuer(Arc::new(test_issuer()));
    FileSystemAgentSurfaceStore::new(root.join("agent_surfaces"))
        .await
        .unwrap()
        .save(surface)
        .await
        .unwrap();
    let mut paired = peer();
    paired.trusted_issuer_dids = trusted_issuers;
    let issuer_dir = crate::gateways::test_helpers::install_listener_manager_with_peers(root, &[paired]).await;
    let peer = crate::gateways::FileSystemGatewayStore::new(root.join("gateways"), None)
        .await
        .unwrap()
        .get_by_did(PEER_CONNECTION_POINT_DID)
        .await
        .unwrap()
        .unwrap();
    (peer, issuer_dir)
}

pub(super) fn forward_request(
    root: &std::path::Path,
    headers: Value,
    body: Value,
) -> ReceivedMessage {
    ReceivedMessage::new(
        "cp-test".to_string(),
        "gw-test".to_string(),
        MessageType::ForwardRequest.to_string(),
        uuid::Uuid::new_v4().to_string(),
        None,
        Some(PEER_CONNECTION_POINT_DID.to_string()),
        vec!["did:web:receiver.example".to_string()],
        None,
        Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
        json!({ "channel_id": SURFACE_ID, "method": "POST", "path": "/rpc", "headers": headers, "body": body,
            "trace_id": "trace-from-the-peer" }),
        MessageMetadata {
            encrypted: true,
            authenticated: true,
            from_key: None,
            extra: Value::Null,
        },
    )
    .with_context("agent_surface_storage_path", json!(root.join("agent_surfaces")))
}

/// The forward-response for `message`, served as the listener serves a
/// forward-request: in the trace the peer named.
pub(super) async fn forward_response(message: &ReceivedMessage) -> Value {
    let trace_id = message.message_body["trace_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        crate::observability::policy_audit::REQUEST_TRACE_ID
            .scope(trace_id, Box::pin(super::process_forward_request(message))),
    )
    .await
    .expect("Fabric receive timed out");
    match result {
        ProcessingResult::RequiresResponse { response_type, response_body } => {
            assert_eq!(response_type, MessageType::ForwardResponse.to_string());
            response_body
        }
        other => panic!("expected a ForwardResponse, got {other:?}"),
    }
}

pub(super) fn header_values<'headers>(
    headers: &'headers axum::http::HeaderMap,
    name: &str,
) -> Vec<&'headers str> {
    headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect()
}

fn a2a_body() -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": { "message": { "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] } } })
}

/// The agent behind a surface with Transit Points gets one transit token per
/// request a peer sends, whatever tokens the peer sent: valid for each of the
/// surface's Transit Points and no other, naming the peer's record and issuer
/// DID and the Fabric crossings the request made, continuing the request's
/// trace. The surface's API key names every key in its secret as one caller,
/// so the token carries no principal for it, and never a top-level
/// `user_identity_hash`. The hop count header never reaches the agent.
#[tokio::test]
async fn a_fabric_request_reaches_the_agent_with_one_transit_token_issued_for_it() {
    if ran_in_child("ATG_FABRIC_TRANSIT_TOKEN_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let (peer, _issuer_dir) = receiver(root.path(), &surface("a2a", &target.url, &["crm", "billing"])).await;
    let issuer = test_issuer();
    let auth_failures = |events: &[crate::delegation_vault::audit::DelegationAuditEvent]| {
        events
            .iter()
            .filter(|event| matches!(event.event, DelegationAuditAction::AuthFailed { .. }))
            .count()
    };
    let (response, events) = crate::audit::producer::capture(forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "x-api-key": "a-key-the-surface-refuses" }),
        a2a_body(),
    )))
    .await;
    assert_eq!(auth_failures(&events), 1, "the surface checks the peer's key");
    assert_eq!(response["status"], 401, "the surface refuses the unverified request: {response}");
    assert!(target.received().is_empty(), "a refused request never reaches the agent");
    for (case, hops_header, expected_hops) in [("an older peer", None, 1), ("three crossings", Some("3"), 3)] {
        let mut headers = json!({ "content-type": "application/json", "x-api-key": CALLER_KEY,
            "X-Transit-Token": "token-the-peer-sent", "x-transit-token": "another-token-the-peer-sent" });
        if let Some(hops) = hops_header {
            headers["X-Gateway-Fabric-Hops"] = json!(hops);
        }
        let (response, events) =
            crate::audit::producer::capture(forward_response(&forward_request(root.path(), headers, a2a_body()))).await;
        assert_eq!(response["status"], 200, "{case}: {response}");
        assert_eq!(auth_failures(&events), 0, "{case}: the surface's source_auth verified the peer's key");

        let received = target
            .received()
            .pop()
            .unwrap();
        let tokens = header_values(&received, "x-transit-token");
        assert_eq!(tokens.len(), 1, "{case}: {received:?}");
        assert!(
            received
                .get("x-gateway-fabric-hops")
                .is_none(),
            "{case}: {received:?}"
        );
        for alias in ["crm", "billing"] {
            issuer
                .validate_for_transit_point(tokens[0], SURFACE_ID, alias, 300)
                .unwrap_or_else(|error| panic!("{case}: {alias}: {error}"));
        }
        assert!(
            issuer
                .validate_for_transit_point(tokens[0], SURFACE_ID, "other", 300)
                .is_err()
        );
        let claims: TransitTokenClaims = issuer
            .validate(tokens[0], 300)
            .unwrap();
        assert_eq!(
            claims.fabric,
            Some(FabricTransitClaims {
                peer_gateway_id: peer.id.clone(),
                peer_issuer_did: Some(PEER_ISSUER_DID.to_string()),
                hops: expected_hops,
                caller_did: None,
                principal_hash: None,
            }),
            "{case}"
        );
        assert_eq!(claims.user_identity_hash, None, "{case}: never the principal an Access Point verified");
        assert_eq!(claims.sub, None, "{case}");
        assert_eq!(
            claims
                .identity_source
                .as_deref(),
            Some("fabric-asserted"),
            "{case}"
        );
        assert_eq!(claims.trace_id.as_deref(), Some("trace-from-the-peer"), "{case}");
        assert_eq!(header_values(&received, "x-gateway-trace-id"), ["trace-from-the-peer"], "{case}");
        assert_eq!(claims.exp - claims.iat, 300, "{case}: the surface's lifetime");
    }

    // A payload pseudonym is not an identity: the token carries no `sub`.
    let mut body = a2a_body();
    body["params"]["message"]["extensions"] = json!([crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION]);
    body["params"]["message"]["metadata"] =
        json!({ crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION: { "agentId": "agent-7" } });
    let response = forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "x-api-key": CALLER_KEY }),
        body,
    ))
    .await;
    assert_eq!(response["status"], 200, "{response}");
    let received = target
        .received()
        .pop()
        .unwrap();
    let claims = issuer
        .validate(header_values(&received, "x-transit-token")[0], 300)
        .unwrap();
    assert_eq!(claims.sub, None);
    assert_eq!(
        claims
            .identity_source
            .as_deref(),
        Some("fabric-asserted")
    );
    assert_eq!(claims.user_identity_hash, None);
    assert_eq!(
        claims
            .fabric
            .and_then(|fabric| fabric.principal_hash),
        None,
        "a key the surface verified names no user, and the identity the payload names is never the principal"
    );
}

/// A request past the hop limit is refused with `508`, and one whose hop
/// count is not an integer from 1 to 255 with `400`, before the Target is
/// called; each refusal is audited.
#[tokio::test]
async fn a_fabric_request_past_the_hop_limit_or_with_a_malformed_count_is_refused() {
    if ran_in_child("ATG_FABRIC_HOP_LIMIT_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &surface("a2a", &target.url, &["crm"])).await;

    for (hops, status, reason, said) in [
        (json!("9"), 508, RejectionReason::FabricChainTooLong, "The request passed through too many gateways"),
        (json!("255"), 508, RejectionReason::FabricChainTooLong, "The request passed through too many gateways"),
        (json!("many"), 400, RejectionReason::FabricHopsInvalid, "Invalid X-Gateway-Fabric-Hops header"),
        (json!("0"), 400, RejectionReason::FabricHopsInvalid, "Invalid X-Gateway-Fabric-Hops header"),
        (json!(["2", "2"]), 400, RejectionReason::FabricHopsInvalid, "Invalid X-Gateway-Fabric-Hops header"),
    ] {
        let message = forward_request(
            root.path(),
            json!({ "content-type": "application/json", "x-api-key": CALLER_KEY, "x-gateway-fabric-hops": hops }),
            a2a_body(),
        );
        let (response, events) = crate::audit::producer::capture(forward_response(&message)).await;
        assert_eq!(response["status"], status, "{hops}: {response}");
        let body: Value = serde_json::from_str(
            response["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["message"], said, "{hops}");
        let rejected: Vec<_> = events
            .iter()
            .filter_map(|event| match &event.event {
                DelegationAuditAction::RequestRejected { stage, reason, http_status, .. } => {
                    Some((*stage, *reason, *http_status))
                }
                _ => None,
            })
            .collect();
        assert_eq!(rejected, [(RejectionStage::Routing, reason, None)], "{hops}");
        assert!(
            events
                .iter()
                .all(|event| event.via_fabric && event.trace_id.as_deref() == Some("trace-from-the-peer")),
            "{hops}"
        );
        assert!(
            events
                .iter()
                .all(|event| event
                    .surface_variant
                    .is_none()),
            "{hops}: refused before a variant is resolved: {events:?}"
        );
    }
    assert!(target.received().is_empty(), "a refused request never reaches the Target");

    let response = forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "x-api-key": CALLER_KEY, "x-gateway-fabric-hops": "8" }),
        a2a_body(),
    ))
    .await;
    assert_eq!(response["status"], 200, "the eighth crossing is within the limit: {response}");
}

/// The agent of a surface without Transit Points gets no transit token, and
/// never the one the peer sent.
#[tokio::test]
async fn a_surface_without_transit_points_passes_its_agent_no_transit_token() {
    if ran_in_child("ATG_FABRIC_NO_TRANSIT_POINTS_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &surface("a2a", &target.url, &[])).await;

    let response = forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "x-api-key": CALLER_KEY, "X-Transit-Token": "token-the-peer-sent" }),
        a2a_body(),
    ))
    .await;
    assert_eq!(response["status"], 200, "{response}");
    let received = target.received();
    assert_eq!(received.len(), 1);
    assert!(
        received[0]
            .get("x-transit-token")
            .is_none(),
        "{:?}",
        received[0]
    );
}

/// A peer fetching the agent card makes no request of the agent's own, so the
/// agent gets no transit token with it, as with a card fetched directly, and
/// no delegated credential: a binding that applies to every request neither
/// refuses the card nor releases a grant for it.
#[tokio::test]
async fn an_agent_card_fetch_over_fabric_passes_the_agent_no_transit_token() {
    if ran_in_child("ATG_FABRIC_AGENT_CARD_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let mut delegating = surface("a2a", &target.url, &["crm"]);
    delegating.outbound_credentials =
        vec![serde_json::from_value(json!({ "credential_provider_id": "provider", "scopes": ["read"] })).unwrap()];
    let _receiver = receiver(root.path(), &delegating).await;

    let mut message = forward_request(
        root.path(),
        json!({ "x-api-key": CALLER_KEY, "X-Transit-Token": "token-the-peer-sent" }),
        Value::Null,
    );
    message.message_body["method"] = json!("GET");
    message.message_body["path"] = json!("/.well-known/agent-card.json");
    let response = forward_response(&message).await;
    assert_eq!(response["status"], 200, "{response}");
    let received = target.received();
    assert_eq!(received.len(), 1, "the card request reaches the agent");
    for header in ["x-transit-token", "authorization"] {
        assert!(
            received[0]
                .get(header)
                .is_none(),
            "{header}: {:?}",
            received[0]
        );
    }
}

/// A framed stream whose Open carries a hop count past the limit, or one that
/// is not a count, is refused as a buffered request is, before the agent is
/// called, and recorded with the stream's trace.
#[tokio::test]
async fn a_framed_stream_past_the_hop_limit_or_with_a_malformed_count_is_refused() {
    if ran_in_child("ATG_FABRIC_STREAM_HOP_LIMIT_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let surface = surface("mcp", &target.url, &["crm"]);
    let _receiver = receiver(root.path(), &surface).await;
    let body = json!({ "jsonrpc": "2.0", "id": "stream", "method": "tools/list", "params": { "_meta": {
        "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {}
    } } });

    for (hops, status, reason, said) in [
        ("9", 508, RejectionReason::FabricChainTooLong, "The request passed through too many gateways"),
        ("many", 400, RejectionReason::FabricHopsInvalid, "Invalid X-Gateway-Fabric-Hops header"),
    ] {
        let headers = json!({ "content-type": "application/json", "accept": "application/json, text/event-stream",
            "mcp-protocol-version": crate::mcp::MCP_MODERN_VERSION, "mcp-method": "tools/list",
            "x-api-key": CALLER_KEY, "x-gateway-fabric-hops": hops });
        let stream_headers = crate::proxy::fabric_stream::wire::headers_from_json(Some(&headers)).unwrap();
        let message = forward_request(root.path(), headers, Value::Null);
        let (result, events) = crate::audit::producer::capture(tokio::time::timeout(
            Duration::from_secs(10),
            crate::observability::policy_audit::REQUEST_TRACE_ID.scope(
                "trace-from-the-peer".to_string(),
                Box::pin(super::process_forward_request_with_mcp_runtime(
                    &message,
                    Some(super::FabricStreamRequest {
                        headers: stream_headers,
                        body: serde_json::to_vec(&body)
                            .unwrap()
                            .into(),
                        surface: surface.clone(),
                        variant: crate::config::agent_surface_variants::ForwardedVariant {
                            id: None,
                            recorded: "_base_".into(),
                        },
                        capabilities: crate::proxy::fabric_stream::peer::StreamCapabilities::local(true, true),
                        scope: crate::observability::policy_audit::RequestScope::fresh(),
                    }),
                    crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
                    None,
                )),
            ),
        ))
        .await;
        let response = match result.expect("Fabric stream receive timed out") {
            ProcessingResult::RequiresResponse { response_body, .. } => response_body,
            other => panic!("{hops}: expected a refusal, got {other:?}"),
        };
        assert_eq!(response["status"], status, "{hops}: {response}");
        let refusal: Value = serde_json::from_str(
            response["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(refusal["message"], said, "{hops}");
        let rejected: Vec<_> = events
            .iter()
            .filter_map(|event| match &event.event {
                DelegationAuditAction::RequestRejected { stage, reason, http_status, .. } => {
                    Some((*stage, *reason, *http_status, event.trace_id.clone(), event.surface_variant.clone()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            rejected,
            [(RejectionStage::Routing, reason, None, Some("trace-from-the-peer".to_string()), None)],
            "{hops}: no HTTP status on Fabric, and no variant before one is resolved"
        );
    }
    assert!(target.received().is_empty(), "a refused stream never reaches the agent");
}

/// A `2026-07-28` MCP request crossing as a framed stream reaches the agent
/// with one transit token, the one this gateway issued, and the hop count the
/// stream's Open carried.
#[tokio::test]
async fn a_modern_mcp_stream_reaches_the_agent_with_one_transit_token() {
    if ran_in_child("ATG_FABRIC_STREAM_TRANSIT_TOKEN_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let surface = surface("mcp", &target.url, &["crm"]);
    let _receiver = receiver(root.path(), &surface).await;

    let headers = json!({ "content-type": "application/json", "accept": "application/json, text/event-stream",
        "mcp-protocol-version": crate::mcp::MCP_MODERN_VERSION, "mcp-method": "tools/list",
        "x-api-key": CALLER_KEY, "X-Transit-Token": "token-the-peer-sent", "x-gateway-fabric-hops": "2" });
    let mut stream_headers = crate::proxy::fabric_stream::wire::headers_from_json(Some(&headers)).unwrap();
    stream_headers.append("x-transit-token", axum::http::HeaderValue::from_static("another-token-the-peer-sent"));
    let body = json!({ "jsonrpc": "2.0", "id": "stream", "method": "tools/list", "params": { "_meta": {
        "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {}
    } } });
    let message = forward_request(root.path(), headers, Value::Null);
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(super::FabricStreamRequest {
                headers: stream_headers,
                body: serde_json::to_vec(&body)
                    .unwrap()
                    .into(),
                surface,
                variant: crate::config::agent_surface_variants::ForwardedVariant {
                    id: None,
                    recorded: "_base_".into(),
                },
                capabilities: crate::proxy::fabric_stream::peer::StreamCapabilities::local(true, true),
                scope: crate::observability::policy_audit::RequestScope::fresh(),
            }),
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        )),
    )
    .await
    .expect("Fabric stream receive timed out");
    let received = target.received();
    assert_eq!(received.len(), 1, "the request reaches the agent: {result:?}");
    let tokens = header_values(&received[0], "x-transit-token");
    assert_eq!(tokens.len(), 1, "{:?}", received[0]);
    let claims = test_issuer()
        .validate_for_transit_point(tokens[0], SURFACE_ID, "crm", 300)
        .unwrap();
    assert_eq!(
        claims
            .fabric
            .map(|fabric| fabric.hops),
        Some(2)
    );
    assert!(
        received[0]
            .get("x-gateway-fabric-hops")
            .is_none()
    );
}

fn caller(
    caller_identity: Option<&str>,
    verification: IdentityVerification,
) -> FabricReceiveCaller<'_> {
    FabricReceiveCaller {
        peer_gateway_id: "peer-record",
        peer_issuer_did: Some(PEER_ISSUER_DID),
        hops: 1,
        caller_identity,
        verification,
        verified_identity: None,
    }
}

/// The token's principal and caller context fields come only from the caller
/// the receiving surface verified, namespaced by the surface's tenant: a DID a
/// connection issuer's presentation carried is never one.
#[test]
fn a_fabric_tokens_principal_is_only_the_caller_the_receiving_surface_verified() {
    let issuer = test_issuer();
    let mut surface = surface("a2a", "https://agent.example", &["crm", "billing"]);
    surface.tenant_id = Some("tenant-a".to_string());
    let shared_key_surface = surface.clone();
    surface
        .access_point
        .caller_authentication = Some(
        serde_json::from_value(json!({ "methods": [{ "type": "jwt_bearer",
            "jwt_verification_strategy_id": "idp", "audiences": [JWT_AUDIENCE] }] }))
        .unwrap(),
    );
    let transit = surface
        .transit
        .as_mut()
        .unwrap();
    for (point, fields) in transit
        .points
        .iter_mut()
        .zip([json!(["email"]), json!(["name"])])
    {
        point.workload_binding = Some(
            serde_json::from_value(
                json!({ "enabled": true, "caller_source": "transit_token", "caller_context_fields": fields }),
            )
            .unwrap(),
        );
    }
    let claims = |caller: &FabricReceiveCaller<'_>| {
        let (token, _) = fabric_receive_transit_token(
            Some(&issuer),
            Some(30),
            &surface,
            "https://agent.example/rpc",
            false,
            caller,
            Some("trace"),
        )
        .unwrap()
        .unwrap();
        issuer
            .validate(&token, 300)
            .unwrap()
    };

    let presented = claims(&caller(Some("did:web:agent.example"), IdentityVerification::Vp));
    let presented_fabric = presented
        .fabric
        .clone()
        .unwrap();
    assert_eq!(
        presented_fabric
            .caller_did
            .as_deref(),
        Some("did:web:agent.example")
    );
    assert_eq!(presented_fabric.principal_hash, None, "a presentation names the caller, it does not verify it");
    assert!(
        presented
            .caller_context_fields
            .is_empty()
    );

    let alice = crate::source_auth::AuthenticatedIdentity::JwtBearer {
        principal_claim: "sub".to_string(),
        subject: "alice".to_string(),
        claims: json!({ "iss": "https://idp.example", "sub": "alice", "email": "alice@example.com",
            "name": "Alice", "phone": "+15550100" }),
        verification: Default::default(),
    };
    let mut verified = caller(Some("did:web:agent.example"), IdentityVerification::Vp);
    verified.verified_identity = Some(&alice);
    let verified = claims(&verified);
    assert_eq!(verified.user_identity_hash, None);
    assert_eq!(
        verified
            .fabric
            .and_then(|fabric| fabric.principal_hash),
        alice.principal_hash(Some("tenant-a"))
    );
    assert_ne!(alice.principal_hash(Some("tenant-a")), alice.principal_hash(None));
    assert_eq!(
        Value::Object(verified.caller_context_fields),
        json!({ "email": "alice@example.com", "name": "Alice" }),
        "the claims some Transit Point of the surface allowlists"
    );

    let key = crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: "peer-callers".to_string(),
        provider_agent_id: None,
    };
    let mut keyed = caller(None, IdentityVerification::Unverified);
    keyed.verified_identity = Some(&key);
    let (token, _) = fabric_receive_transit_token(
        Some(&issuer),
        Some(30),
        &shared_key_surface,
        "https://agent.example/rpc",
        false,
        &keyed,
        Some("trace"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        issuer
            .validate(&token, 300)
            .unwrap()
            .fabric
            .and_then(|fabric| fabric.principal_hash),
        None,
        "an API key the surface verified names every key in its secret as one caller, so no principal"
    );
}

pub(super) const PER_USER_PROVIDER: &str = "per-user";
const SERVICE_PROVIDER: &str = "service";
const SERVICE_KEY: &str = "service-key-value";
pub(super) const JWT_AUDIENCE: &str = "https://receiver.example/agent";

/// A binding of the receiving surface's Target to `provider`. The key of
/// [`SERVICE_PROVIDER`] travels in `x-service-key`, a per-user grant as the
/// `Authorization` bearer.
pub(super) fn binding(provider: &str) -> crate::config::types::OutboundCredentialBinding {
    let mut binding = json!({ "credential_provider_id": provider, "scopes": ["read"] });
    if provider == SERVICE_PROVIDER {
        binding["inject_as"] = json!({ "type": "custom_header", "name": "x-service-key", "format": "{value}" });
    }
    serde_json::from_value(binding).unwrap()
}

/// The stores the receiving gateway resolves its Target's delegated
/// credentials from, under `root`: an authorization code provider
/// [`PER_USER_PROVIDER`], a grant of it for the Target at `target_url` to each
/// `(user identity hash, access token)` in `grants`, and an API key provider
/// [`SERVICE_PROVIDER`] whose key is [`SERVICE_KEY`].
async fn install_delegation_stores(
    root: &std::path::Path,
    target_url: &str,
    grants: &[(&str, &str)],
) {
    use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
    use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
    use crate::secrets::SecretsStore;

    let providers = Arc::new(
        FileSystemCredentialProviderStore::new(root.join("providers"))
            .await
            .unwrap(),
    );
    for provider in [
        json!({ "id": PER_USER_PROVIDER, "name": "Per user", "provider_id": PER_USER_PROVIDER,
            "resource": "https://provider.example/api",
            "authorization_endpoint": "https://provider.example/authorize", "client_id_secret_ref": "client-id" }),
        json!({ "id": SERVICE_PROVIDER, "name": "Service", "provider_id": SERVICE_PROVIDER,
            "provider_type": "api_key", "api_key_secret_ref": "service-key" }),
    ] {
        let mut provider = provider;
        provider["created_at"] = json!("2026-09-01T00:00:00Z");
        provider["updated_at"] = json!("2026-09-01T00:00:00Z");
        providers
            .create(serde_json::from_value(provider).unwrap())
            .await
            .unwrap();
    }
    let vault = Arc::new(
        FileSystemDelegationVaultStore::new(root.join("vault"))
            .await
            .unwrap(),
    );
    for (index, (user_identity_hash, access_token)) in grants.iter().enumerate() {
        vault
            .store(
                serde_json::from_value(json!({
                    "id": format!("grant-{index}"), "agent_did": target_url, "user_identity_hash": user_identity_hash,
                    "credential_provider_id": PER_USER_PROVIDER, "provider_id": PER_USER_PROVIDER,
                    "access_token": access_token, "refresh_token": format!("{access_token}-refresh"),
                    "scopes": ["read"], "expires_at": chrono::Utc::now() + chrono::Duration::hours(1),
                    "consent_granted_at": "2026-09-01T00:00:00Z",
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
    }
    let secrets = crate::secrets::FilesystemSecretsStore::new_async(
        root.join("delegation-secrets")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    for (secret_id, value) in [("client-id", "receiver-client"), ("service-key", SERVICE_KEY)] {
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: secret_id.to_string(),
                secret_id: secret_id.to_string(),
                description: None,
                value: value.to_string(),
                secret_type: "ApiKey".to_string(),
                tags: vec![],
            })
            .await
            .unwrap();
    }
    super::init_credential_provider_store(providers).await;
    super::init_delegation_vault_store(vault).await;
    super::init_secrets_store(Arc::new(secrets)).await;
    super::init_gateway_base_url("https://receiver.example".to_string()).await;
}

/// An A2A request whose agent identity extension names `metadata`.
pub(super) fn naming(metadata: Value) -> Value {
    let mut body = a2a_body();
    body["params"]["message"]["extensions"] = json!([crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION]);
    body["params"]["message"]["metadata"] = json!({ crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION: metadata });
    body
}

/// The forward-response for `message` with the reason its body names, and the
/// `request_rejected` records it wrote.
pub(super) async fn refused(message: &ReceivedMessage) -> (Value, Value, Vec<(RejectionStage, RejectionReason, bool)>) {
    let (response, events) = crate::audit::producer::capture(forward_response(message)).await;
    let body: Value = response["body"]
        .as_str()
        .and_then(|body| serde_json::from_str(body).ok())
        .unwrap_or(Value::Null);
    let rejected = events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected { stage, reason, .. } => Some((*stage, *reason, event.via_fabric)),
            _ => None,
        })
        .collect();
    (response, body, rejected)
}

/// While the Target does not set `delegated_credentials_for_fabric_callers`,
/// a partner's request never reaches a per-user credential of the Target. A
/// request a per-user binding applies to is refused with `403` and a fixed
/// reason before the Target is called, and recorded as a `request_rejected`,
/// even when a grant is stored for the caller the surface verified or for the
/// one the peer names.
#[tokio::test]
async fn a_partner_request_gets_no_per_user_credential_on_fabric_receive() {
    if ran_in_child("ATG_FABRIC_RECEIVE_NOT_OPTED_IN_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let mut delegating = surface("a2a", &target.url, &[]);
    delegating.outbound_credentials = vec![binding(PER_USER_PROVIDER)];
    let _receiver = receiver(root.path(), &delegating).await;
    let partner = crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: "peer-callers".to_string(),
        provider_agent_id: None,
    }
    .principal_hash(None)
    .unwrap();
    install_delegation_stores(
        root.path(),
        &target.url,
        &[(partner.as_str(), "partner-access"), ("did:web:alice.example", "alice-did-access")],
    )
    .await;

    for named in [json!({ "agentId": "alice" }), json!({ "agentId": "bob", "did": "did:web:alice.example" })] {
        let (response, body, rejected) = refused(&forward_request(
            root.path(),
            json!({ "content-type": "application/json", "x-api-key": CALLER_KEY }),
            naming(named.clone()),
        ))
        .await;
        assert_eq!(response["status"], 403, "{named}: {response}");
        assert_eq!(body["reason"], "delegation_not_enabled_for_partners", "{named}: {body}");
        assert_eq!(
            rejected,
            [(RejectionStage::Admission, RejectionReason::DelegationNotEnabledForPartners, true)],
            "{named}"
        );
    }
    assert!(target.received().is_empty(), "the Target is never called");
}

/// A service-level binding, such as an API key provider, keys no caller's
/// grant, so it reaches a partner's request without the opt-in, as long as the
/// receiving surface verified a caller of the request; without one the closed
/// Access Point refuses the request with `401` before the Target is called,
/// even when the peer names a caller in the identity extension.
#[tokio::test]
async fn a_service_level_credential_reaches_a_partner_request_without_the_opt_in() {
    if ran_in_child("ATG_FABRIC_RECEIVE_SERVICE_CREDENTIAL_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let mut delegating = surface("a2a", &target.url, &[]);
    delegating.outbound_credentials = vec![binding(SERVICE_PROVIDER)];
    let _receiver = receiver(root.path(), &delegating).await;
    install_delegation_stores(root.path(), &target.url, &[]).await;
    let send = |key: &str, body: Value| {
        forward_request(root.path(), json!({ "content-type": "application/json", "x-api-key": key }), body)
    };

    for (case, request) in
        [("no caller named", a2a_body()), ("peer names a caller", naming(json!({ "agentId": "alice" })))]
    {
        let before = target.received().len();
        let response = forward_response(&send(CALLER_KEY, request.clone())).await;
        assert_eq!(response["status"], 200, "{case}: {response}");
        let received = target.received();
        assert_eq!(received.len(), before + 1, "{case}: the Target is called once");
        assert_eq!(header_values(&received[before], "x-service-key"), [SERVICE_KEY], "{case}");

        let reached = received.len();
        let response = forward_response(&send("not-the-key", request)).await;
        assert_eq!(response["status"], 401, "{case}: {response}");
        assert_eq!(target.received().len(), reached, "{case}: the Target is not called");
    }
}

/// A public Access Point hands a partner's request whose caller it did not
/// verify on, but a service-level binding still is not released to it: the
/// request is refused with `403` before the Target is called, even when the
/// peer names a caller in the identity extension.
#[tokio::test]
async fn a_public_surface_releases_no_service_credential_to_a_partner_whose_caller_it_did_not_verify() {
    if ran_in_child("ATG_FABRIC_RECEIVE_PUBLIC_SERVICE_CREDENTIAL_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let mut delegating = surface("a2a", &target.url, &[]);
    delegating.access_point.public = Some(true);
    delegating.outbound_credentials = vec![binding(SERVICE_PROVIDER)];
    let _receiver = receiver(root.path(), &delegating).await;
    install_delegation_stores(root.path(), &target.url, &[]).await;

    for (case, request) in
        [("no caller named", a2a_body()), ("peer names a caller", naming(json!({ "agentId": "alice" })))]
    {
        let (response, body, rejected) = refused(&forward_request(
            root.path(),
            json!({ "content-type": "application/json", "x-api-key": "not-the-key" }),
            request,
        ))
        .await;
        assert_eq!(response["status"], 403, "{case}: {response}");
        assert_eq!(body["reason"], "partner_caller_not_verified", "{case}: {body}");
        assert_eq!(rejected, [(RejectionStage::Admission, RejectionReason::ConsentIdentityRequired, true)], "{case}");
        assert!(target.received().is_empty(), "{case}: the Target is not called");
    }
}

/// Each receive-side refusal of delegated credentials answers `403`: an MCP
/// request with a JSON-RPC error carrying its id, `-32001` and the fixed
/// reason, any other request with a problem JSON naming the reason. Each is
/// recorded once as a `request_rejected` at the `admission` stage.
#[tokio::test]
async fn a_refused_partner_delegation_is_recorded_and_answers_mcp_with_a_json_rpc_error() {
    let surface = surface("mcp", "https://agent.example", &[]);
    let facts = crate::audit::request_events::RequestFacts {
        surface_id: &surface.surface_id,
        channel_name: &surface.name,
        trace_id: Some("trace-from-the-peer"),
        via_fabric: true,
    };
    let request = serde_json::to_vec(
        &json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": { "name": "lookup" } }),
    )
    .unwrap();
    for (refusal, reason, recorded) in [
        (
            FabricDelegationRefusal::CallerNotVerified,
            "partner_caller_not_verified",
            RejectionReason::ConsentIdentityRequired,
        ),
        (
            FabricDelegationRefusal::NotEnabledForPartners,
            "delegation_not_enabled_for_partners",
            RejectionReason::DelegationNotEnabledForPartners,
        ),
        (
            FabricDelegationRefusal::ConsentNotAvailable,
            "consent_not_available_for_partners",
            RejectionReason::ConsentNotAvailableForPartners,
        ),
    ] {
        for mcp in [true, false] {
            let (result, events) =
                crate::audit::producer::capture(async { fabric_delegation_refusal(&facts, mcp, &request, refusal) })
                    .await;
            let ProcessingResult::RequiresResponse { response_body, .. } = result else {
                panic!("expected a refusal, got {result:?}");
            };
            assert_eq!(response_body["status"], 403);
            let body: Value = serde_json::from_str(
                response_body["body"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            if mcp {
                assert_eq!(body["id"], 7, "{body}");
                assert_eq!(body["error"]["code"], -32001, "{body}");
                assert_eq!(body["error"]["data"]["reason"], reason, "{body}");
            } else {
                assert_eq!(body["status"], 403, "{body}");
                assert_eq!(body["reason"], reason, "{body}");
            }
            let rejected: Vec<_> = events
                .iter()
                .filter_map(|event| match &event.event {
                    DelegationAuditAction::RequestRejected { stage, reason, .. } => {
                        Some((*stage, *reason, event.via_fabric, event.trace_id.clone()))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                rejected,
                [(RejectionStage::Admission, recorded, true, Some("trace-from-the-peer".to_string()))],
                "{reason} mcp={mcp}"
            );
        }
    }
}

/// A surface that verifies no caller of its own gives its agent a token with
/// no principal, whatever identity the peer's request names.
#[tokio::test]
async fn a_surface_that_verifies_no_caller_issues_a_fabric_token_without_a_principal() {
    if ran_in_child("ATG_FABRIC_UNVERIFIED_CALLER_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let mut open = surface("a2a", &target.url, &["crm"]);
    open.access_point
        .caller_authentication = None;
    let _receiver = receiver(root.path(), &open).await;

    let mut body = a2a_body();
    body["params"]["message"]["extensions"] = json!([crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION]);
    body["params"]["message"]["metadata"] = json!({ crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION: {
        "agentId": "agent-7", "did": "did:web:asserted.example" } });
    let response = forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "x-api-key": CALLER_KEY }),
        body,
    ))
    .await;
    assert_eq!(response["status"], 200, "{response}");
    let received = target
        .received()
        .pop()
        .unwrap();
    let claims = test_issuer()
        .validate(header_values(&received, "x-transit-token")[0], 300)
        .unwrap();
    assert_eq!(claims.user_identity_hash, None);
    assert_eq!(
        claims
            .fabric
            .and_then(|fabric| fabric.principal_hash),
        None
    );
    assert!(
        claims
            .caller_context_fields
            .is_empty()
    );
}

/// A JWT the receiving surface verified on a Fabric request is the token's
/// principal, and the claims the surface's Transit Points allowlist ride with
/// it; claims no Transit Point allowlists stay behind.
#[tokio::test]
async fn a_jwt_the_receiving_surface_verified_is_the_fabric_tokens_principal_with_its_allowlisted_claims() {
    if ran_in_child("ATG_FABRIC_JWT_CALLER_CHILD").await {
        return;
    }
    use crate::component_tests::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
    use crate::jwt_bearer::storage::JwtVerificationStrategyStorage;

    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let strategies = Arc::new(
        crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(root.path().join("strategies"))
            .await
            .unwrap(),
    );
    let strategy = strategies
        .create(
            serde_json::from_value(json!({
                "id": "partner-idp", "name": "Partner IdP", "expected_issuer": fixture.issuer,
                "jwks_source": {"type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer)},
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let mut surface = surface("a2a", &target.url, &["crm"]);
    surface
        .access_point
        .caller_authentication = Some(
        serde_json::from_value(json!({ "methods": [{ "type": "jwt_bearer",
            "jwt_verification_strategy_id": strategy.id, "audiences": ["https://receiver.example/agent"] }] }))
        .unwrap(),
    );
    surface
        .transit
        .as_mut()
        .unwrap()
        .points[0]
        .workload_binding = Some(
        serde_json::from_value(
            json!({ "enabled": true, "caller_source": "transit_token", "caller_context_fields": ["email"] }),
        )
        .unwrap(),
    );
    let _receiver = receiver_with_strategies(root.path(), &surface, strategies).await;
    let claims = json!({ "iss": fixture.issuer, "sub": "user-123", "aud": "https://receiver.example/agent",
        "exp": now_secs() + 300, "email": "user-123@partner.example", "phone": "+15550100" });
    let jwt = sign_jwt(claims.clone(), &fixture.kid);

    let response = forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "authorization": format!("Bearer {jwt}") }),
        a2a_body(),
    ))
    .await;
    assert_eq!(response["status"], 200, "{response}");
    let received = target
        .received()
        .pop()
        .unwrap();
    let token = test_issuer()
        .validate(header_values(&received, "x-transit-token")[0], 300)
        .unwrap();
    let verified = crate::source_auth::AuthenticatedIdentity::JwtBearer {
        principal_claim: "sub".to_string(),
        subject: "user-123".to_string(),
        claims,
        verification: Default::default(),
    };
    assert_eq!(token.user_identity_hash, None);
    assert_eq!(
        token
            .fabric
            .and_then(|fabric| fabric.principal_hash),
        verified.principal_hash(None)
    );
    assert!(
        verified
            .principal_hash(None)
            .is_some()
    );
    assert_eq!(Value::Object(token.caller_context_fields), json!({ "email": "user-123@partner.example" }));
}

/// A token issued on Fabric receive carries a caller DID only when a
/// presentation from one of the peer's connection issuers carried it
/// (`fabric-presentation`): never one the peer only named, one this gateway
/// computed from fields the peer sent, or a payload pseudonym.
#[test]
fn a_fabric_token_carries_only_a_did_the_peers_presentation_proved() {
    for (identity, verification, expected) in [
        (
            Some("did:web:agent.example"),
            IdentityVerification::Vp,
            (Some("did:web:agent.example"), IdentitySource::FabricPresentation),
        ),
        (Some("did:web:agent.example"), IdentityVerification::Unverified, (None, IdentitySource::FabricAsserted)),
        (
            Some("did:web:this-gateway.example:computed:0f3a"),
            IdentityVerification::Unverified,
            (None, IdentitySource::FabricAsserted),
        ),
        (Some("did:web:agent.example"), IdentityVerification::VpUnanchored, (None, IdentitySource::FabricAsserted)),
        (Some("sha256:0f3a"), IdentityVerification::Vp, (None, IdentitySource::FabricAsserted)),
        (None, IdentityVerification::Unverified, (None, IdentitySource::FabricAsserted)),
    ] {
        assert_eq!(fabric_caller_did_and_source(identity, verification), expected, "{identity:?} {verification:?}");
    }
}

/// The presentation this gateway signs for its agent's response names the
/// caller as the user the agent acted for only when a presentation from one of
/// the connection's issuers proved the caller's DID, the same caller a transit
/// token carries: never a pseudonym, a DID this gateway computed from fields
/// the peer sent, or one the peer only named.
#[test]
fn a_fabric_response_presentation_names_only_a_caller_the_peers_presentation_proved() {
    let identity_fields = std::collections::HashMap::from([("model".to_string(), json!("gpt-4"))]);
    let proved = fabric_response_workload_binding(
        &identity_fields,
        Some("did:web:agent.example"),
        IdentityVerification::Vp,
        Some("trace-1".to_string()),
    );
    assert_eq!(
        proved,
        json!({
            "agentIdentity": { "model": "gpt-4" },
            "userIdentity": { "id": "did:web:agent.example" },
            "delegated": true,
            "traceId": "trace-1"
        })
    );
    for (identity, verification) in [
        ("did:web:victim.example", IdentityVerification::Unverified),
        ("did:web:this-gateway.example:computed:0f3a", IdentityVerification::Unverified),
        ("did:web:victim.example", IdentityVerification::VpUnanchored),
        ("sha256:0f3a", IdentityVerification::Vp),
        ("0f3a-victim-pseudonym", IdentityVerification::Unverified),
    ] {
        let binding = fabric_response_workload_binding(&identity_fields, Some(identity), verification, None);
        assert_eq!(binding, json!({ "agentIdentity": { "model": "gpt-4" } }), "{identity} {verification:?}");
    }
}

/// A token is issued only for a surface with Transit Points whose Target is
/// the agent itself, by HTTP or HTTPS, never for a Target the gateway runs;
/// one that should be issued without an issuer is an error, so the request is
/// refused.
#[test]
fn a_fabric_token_is_issued_only_for_an_agent_behind_an_http_target() {
    let issuer = test_issuer();
    let with_points = surface("a2a", "https://agent.example", &["crm"]);
    let issue = |issuer: Option<&TransitTokenIssuer>, surface: &AgentSurface, target_url: &str, card: bool| {
        fabric_receive_transit_token(
            issuer,
            Some(30),
            surface,
            target_url,
            card,
            &caller(None, IdentityVerification::Unverified),
            Some("trace"),
        )
    };
    let issued = |issuer: Option<&TransitTokenIssuer>, surface: &AgentSurface, target_url: &str| {
        issue(issuer, surface, target_url, false)
    };
    for target_url in ["https://agent.example/rpc", "http://agent.example/rpc", "HTTPS://agent.example/rpc"] {
        assert!(matches!(issued(Some(&issuer), &with_points, target_url), Ok(Some(_))), "{target_url}");
    }
    assert!(
        matches!(
            issue(Some(&issuer), &with_points, "https://agent.example/.well-known/agent-card.json", true),
            Ok(None)
        ),
        "an agent card fetch is no request of the agent's own"
    );
    for target_url in ["proxy://tools", "a2a-proxy://direct-line", "fabric://peer/surface"] {
        assert!(matches!(issued(Some(&issuer), &with_points, target_url), Ok(None)), "{target_url}");
    }
    assert_eq!(issued(None, &with_points, "https://agent.example/rpc"), Err(()));
    assert!(matches!(
        issued(Some(&issuer), &surface("a2a", "https://agent.example", &[]), "https://agent.example/rpc"),
        Ok(None)
    ));
}

/// The token names every Transit Point of the surface, as the Access Point's
/// token does, whether or not it requires the token, and none is issued for a
/// surface without Transit Points.
#[test]
fn a_fabric_token_names_every_transit_point_of_the_surface() {
    let issuer = test_issuer();
    let issue = |surface: &AgentSurface| {
        fabric_receive_transit_token(
            Some(&issuer),
            Some(300),
            surface,
            "https://agent.example/rpc",
            false,
            &caller(None, IdentityVerification::Unverified),
            Some("trace"),
        )
    };
    let mut mixed = surface("a2a", "https://agent.example", &["crm", "billing"]);
    mixed
        .transit
        .as_mut()
        .unwrap()
        .points[1]
        .require_transit_token = false;
    let (token, _) = issue(&mixed)
        .unwrap()
        .expect("a token for a surface with Transit Points");
    let claims = issuer
        .validate(&token, 300)
        .unwrap();
    assert_eq!(claims.allowed_transit_points, vec!["crm".to_string(), "billing".to_string()]);

    let without_points = surface("a2a", "https://agent.example", &[]);
    assert_eq!(issue(&without_points), Ok(None), "a surface without Transit Points gets no token");
}

/// A Fabric request whose managed agent should get a transit token that cannot
/// be issued is refused with `503`, never forwarded, and recorded once as a
/// `request_rejected` at the `forward` stage.
#[tokio::test]
async fn a_fabric_request_is_refused_when_its_transit_token_cannot_be_issued() {
    let surface = surface("a2a", "https://agent.example", &["crm"]);
    let (result, events) = crate::audit::producer::capture(async {
        transit_token_unavailable_refusal(&surface, Some("trace-from-the-peer"))
    })
    .await;
    let ProcessingResult::RequiresResponse { response_body, .. } = result else {
        panic!("expected a refusal, got {result:?}");
    };
    assert_eq!(response_body["status"], 503);
    let rejected: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected { stage, reason, .. } => {
                Some((*stage, *reason, event.via_fabric, event.trace_id.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        rejected,
        [(
            RejectionStage::Forward,
            RejectionReason::TransitTokenUnavailable,
            true,
            Some("trace-from-the-peer".to_string())
        )]
    );
}

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
/// dot segments. A request from an authenticated caller still carries it.
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
    assert_eq!(names, ["accept", "accept-language", "user-agent"]);
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
        for secret in [REFUSED_TOKEN_DESCRIPTION, PROVIDER_CLIENT_SECRET] {
            assert!(!text.contains(secret), "{secret} reached the {sink}:\n{text}");
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

/// The card read for the policy input logs the card's `url` without its
/// userinfo or query values, as it logs the card location.
#[tokio::test]
async fn the_policy_card_read_logs_the_cards_url_redacted() {
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
    let card_url = format!("http://{}/.well-known/agent.json", listener.local_addr().unwrap());
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

    let card = super::fetch_agent_card(
        &card_url,
        None,
        Duration::from_secs(5),
        super::fabric_body_limits(&surface("a2a", "http://127.0.0.1", &[])),
        SURFACE_ID,
    )
    .with_subscriber(subscriber)
    .await;

    assert_eq!(card.unwrap()["name"], "agent");
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("agent.example/a2a"), "the card url was not logged:\n{logs}");
    for secret in ["card-password", "card-query-secret"] {
        assert!(!logs.contains(secret), "{secret} was logged:\n{logs}");
    }
}
