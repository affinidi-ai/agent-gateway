//! A request a Fabric peer sends reaches the managed agent with a transit token
//! this gateway issued for it, naming the peer and the Fabric crossings, never
//! with a token the peer sent; a request past the hop limit is refused before
//! anything is forwarded.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::{
    FabricReceiveCaller, ProcessingResult, fabric_caller_did_and_source, fabric_receive_transit_token,
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

const PEER_CONNECTION_POINT_DID: &str = "did:web:peer.example";
const PEER_ISSUER_DID: &str = "did:web:partner.example";
const SURFACE_ID: &str = "fabric-transit";
const CALLER_KEY: &str = "peer-target-auth-key";

/// Runs the calling test again in a child process, where the process-wide
/// stores this path reads are unset until the test sets them. Returns `true`
/// in the parent, which then has nothing more to do.
async fn ran_in_child(variable: &str) -> bool {
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

fn test_issuer() -> TransitTokenIssuer {
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
fn surface(
    protocol: &str,
    target: &str,
    aliases: &[&str],
) -> AgentSurface {
    let points: Vec<Value> = aliases
        .iter()
        .map(|alias| {
            json!({ "alias": alias, "target_endpoint": format!("https://{alias}.example"), "allow_fabric_callers": true })
        })
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
        Arc::new(
            crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(root.join("strategies"))
                .await
                .unwrap(),
        ),
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
    let issuer_dir = crate::gateways::test_helpers::install_listener_manager_with_peers(root, &[peer()]).await;
    let peer = crate::gateways::FileSystemGatewayStore::new(root.join("gateways"), None)
        .await
        .unwrap()
        .get_by_did(PEER_CONNECTION_POINT_DID)
        .await
        .unwrap()
        .unwrap();
    (peer, issuer_dir)
}

fn forward_request(
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
async fn forward_response(message: &ReceivedMessage) -> Value {
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

fn header_values<'headers>(
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
/// trace, and carrying no principal even though the surface's `source_auth`
/// verified one. The hop count header never reaches the agent.
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
    let (_, events) = crate::audit::producer::capture(forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "x-api-key": "a-key-the-surface-refuses" }),
        a2a_body(),
    )))
    .await;
    assert_eq!(auth_failures(&events), 1, "the surface checks the peer's key");

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
            }),
            "{case}"
        );
        assert_eq!(claims.user_identity_hash, None, "{case}: the peer's principal is never the caller's");
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
/// agent gets no transit token with it, as with a card fetched directly.
#[tokio::test]
async fn an_agent_card_fetch_over_fabric_passes_the_agent_no_transit_token() {
    if ran_in_child("ATG_FABRIC_AGENT_CARD_CHILD").await {
        return;
    }
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let _receiver = receiver(root.path(), &surface("a2a", &target.url, &["crm"])).await;

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
    assert!(
        received[0]
            .get("x-transit-token")
            .is_none(),
        "{:?}",
        received[0]
    );
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
    }
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

/// The token opens only the Transit Points that set `allow_fabric_callers`,
/// and none is issued when no Transit Point sets it.
#[test]
fn a_fabric_token_opens_only_the_transit_points_that_allow_fabric_callers() {
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
        .allow_fabric_callers = false;
    let (token, _) = issue(&mixed)
        .unwrap()
        .expect("a token for the Transit Point that allows Fabric callers");
    let claims = issuer
        .validate(&token, 300)
        .unwrap();
    assert_eq!(claims.allowed_transit_points, vec!["crm".to_string()]);

    let mut none = mixed.clone();
    none.transit
        .as_mut()
        .unwrap()
        .points[0]
        .allow_fabric_callers = false;
    assert_eq!(issue(&none), Ok(None), "no Transit Point allows Fabric callers");
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
