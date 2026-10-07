use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};

use super::{ProcessingResult, build_fabric_gating_input, process_forward_request};
use crate::component_tests::helpers::MockServer;
use crate::config::agent_surface::AgentSurface;
use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
use crate::gateways::test_helpers::install_listener_manager_with_peers;
use crate::gateways::types::{Gateway, GatewayType};
use crate::gateways::{FileSystemGatewayStore, GatewayStore};
use crate::mcp::{MCP_LEGACY_VERSION, MCP_MODERN_VERSION};
use crate::messages::MessageType;
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

const SENDER_CONNECTION_POINT_DID: &str = "did:web:sender.example";
const SENDER_GATEWAY_DID: &str = "did:web:sender-gateway.example";
const OTHER_SENDER_DID: &str = "did:example:other-sender";

fn remote_peer(
    connection_point_did: &str,
    issuer_did: Option<&str>,
    trusted_issuer_dids: &[&str],
) -> Gateway {
    let mut peer = Gateway::new(
        connection_point_did.to_string(),
        String::new(),
        connection_point_did.to_string(),
        GatewayType::Remote,
    );
    peer.issuer_did = issuer_did.map(str::to_string);
    peer.trusted_issuer_dids = trusted_issuer_dids
        .iter()
        .map(|did| did.to_string())
        .collect();
    peer
}

/// Pairs the sending Connection Point with a verified issuer DID.
async fn install_listener_manager_with_sender(root: &std::path::Path) -> tempfile::TempDir {
    install_listener_manager_with_peers(
        root,
        &[remote_peer(SENDER_CONNECTION_POINT_DID, Some(SENDER_GATEWAY_DID), &[])],
    )
    .await
}

async fn receive(message: &ReceivedMessage) -> (Value, Value) {
    let result = tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(message)))
        .await
        .expect("Fabric receive handler timed out");
    let ProcessingResult::RequiresResponse { response_type, response_body } = result else {
        panic!("expected ForwardResponse, got {result:?}");
    };
    assert_eq!(response_type, MessageType::ForwardResponse.to_string());
    assert_eq!(
        response_body["headers"]["content-type"],
        if response_body["status"] == 422 {
            "application/problem+json"
        } else {
            "application/json"
        }
    );
    assert!(
        response_body
            .get("error")
            .is_none()
    );
    let envelope = serde_json::from_str(
        response_body["body"]
            .as_str()
            .expect("ForwardResponse body string"),
    )
    .expect("ForwardResponse JSON-RPC envelope");
    (response_body, envelope)
}

#[test]
fn fabric_policy_context_matches_direct_admission_without_changing_legacy_shape() {
    use crate::mcp::request_validation::{LegacySessionEvidence, McpVersionPolicy, validate_mcp_post};
    let surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "context", "name": "context",
        "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": "http://127.0.0.1:8081"}
    }))
    .unwrap();
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {
        "cursor": "page-2", "_meta": {
            "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {"extensions": {"com.example/feature": [1, true]}}
        }
    }});
    let headers = json!({"MCP-Protocol-Version": MCP_MODERN_VERSION, "Mcp-Method": "tools/list"});
    let headers = headers.as_object().unwrap();
    let wire_headers = super::fabric_mcp_headers(Some(headers)).unwrap();
    let bytes = serde_json::to_vec(&body).unwrap();
    let classification = validate_mcp_post(
        &wire_headers,
        &bytes,
        LegacySessionEvidence::Absent,
        McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]),
    )
    .unwrap();
    let direct = crate::mcp::build_validated_mcp_context(&bytes, &classification).unwrap();
    let reduced = crate::surface_context::McpContext {
        method: "tools/list".to_string(),
        ..Default::default()
    };

    let fabric = build_fabric_gating_input(
        &surface,
        "context",
        Some("variant"),
        Some(headers),
        "POST",
        "/mcp",
        None,
        None,
        reduced.clone(),
        Some(&direct),
    );
    assert_eq!(fabric["mcp"], serde_json::to_value(&direct).unwrap());
    assert_eq!(fabric["channel"]["variant_alias"], "variant");
    let legacy = build_fabric_gating_input(&surface, "context", None, None, "POST", "/mcp", None, None, reduced, None);
    assert_eq!(legacy["mcp"], json!({"method": "tools/list"}));
}

#[tokio::test]
async fn modern_fabric_response_reuses_final_processing_in_json_and_sse() {
    use crate::mcp::request_validation::{
        LegacySessionEvidence, McpRequestClassification, McpVersionPolicy, validate_mcp_post,
    };
    use std::sync::{Arc, atomic::AtomicUsize};

    let request_headers = super::fabric_mcp_headers(
        json!({
            "mcp-protocol-version": MCP_MODERN_VERSION, "mcp-method": "tools/list",
        })
        .as_object(),
    )
    .unwrap();
    let request_body = json!({"jsonrpc": "2.0", "id": "stream", "method": "tools/list", "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {}
    }}});
    let classification = validate_mcp_post(
        &request_headers,
        &serde_json::to_vec(&request_body).unwrap(),
        LegacySessionEvidence::Absent,
        McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]),
    )
    .unwrap();
    let metadata = crate::mcp::meta::McpMetadataContext::from_classification(&classification, None);
    let McpRequestClassification::Modern(request) = classification else { panic!("expected modern fixture") };
    let message = json!({"jsonrpc": "2.0", "id": "stream", "result": {
        "resultType": "complete", "tools": [{"name": "kept", "inputSchema": {"type": "object"}}],
        "ttlMs": 0, "cacheScope": "private",
        "_meta": {crate::config::TRUST_REGISTRY_EXTENSION: {"marker": [1, true, null]}}
    }});
    for sse in [false, true] {
        for reject in [false, true] {
            let content_type = if sse {
                "text/event-stream"
            } else {
                "application/json"
            };
            let wire_body = if sse {
                format!("data: {message}\n\n")
            } else {
                message.to_string()
            };
            let upstream = reqwest::Response::from(
                axum::http::Response::builder()
                    .header("content-type", content_type)
                    .header("x-repeated", "first")
                    .header("x-repeated", "second")
                    .body(reqwest::Body::from(wire_body))
                    .unwrap(),
            );
            let headers = upstream.headers().clone();
            let processing_headers = std::collections::HashMap::from([
                ("content-type".to_string(), vec!["application/json".to_string()]),
                ("x-repeated".to_string(), vec!["first".to_string(), "second".to_string()]),
            ]);
            let called = Arc::new(AtomicUsize::new(0));
            let count = called.clone();
            let response = super::process_modern_fabric_response(upstream, headers, (*request).clone(),
                crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default()),
                processing_headers, crate::mcp::modern::ForwardingSupport::for_endpoint(false, crate::mcp::request_validation::McpPathKind::FabricReceive), None, move |body, headers| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let body = crate::mcp::meta::normalize_text(&body, metadata).unwrap();
                    ProcessingResult::RequiresResponse {
                        response_type: MessageType::ForwardResponse.to_string(),
                        response_body: json!({"status": if reject { 403 } else { 200 }, "body": body, "headers": headers}),
                    }
                }).await;
            if reject {
                if sse {
                    assert!(
                        axum::body::to_bytes(response.unwrap().into_body(), 8192)
                            .await
                            .is_err()
                    );
                } else {
                    assert!(response.is_err());
                }
            } else {
                let response = response.unwrap();
                assert_eq!(
                    response
                        .headers()
                        .get_all("x-repeated")
                        .iter()
                        .count(),
                    2
                );
                let bytes = axum::body::to_bytes(response.into_body(), 8192)
                    .await
                    .unwrap();
                let body: Value = if sse {
                    use eventsource_stream::Eventsource;
                    use futures::StreamExt;
                    let events = futures::stream::iter([Ok::<_, std::io::Error>(bytes)]).eventsource();
                    futures::pin_mut!(events);
                    let event = events
                        .next()
                        .await
                        .unwrap()
                        .unwrap();
                    serde_json::from_str(&event.data).unwrap()
                } else {
                    serde_json::from_slice(&bytes).unwrap()
                };
                assert_eq!(body["result"]["tools"], message["result"]["tools"]);
                assert_eq!(
                    body["result"]["_meta"]["io.affinidi.fabric/trust-registry"]["marker"],
                    json!([1, true, null])
                );
                assert_eq!(body["id"], "stream");
            }
            assert_eq!(called.load(Ordering::SeqCst), 1);
        }
    }
}

/// An upstream result carrying every preservation field
/// leaves the receiving gateway's modern response adapter intact, in JSON and
/// SSE. The final processing here is the metadata normalization; identity
/// injection is not configured.
#[tokio::test]
async fn modern_fabric_response_preserves_every_result_field() {
    use crate::mcp::request_validation::{
        LegacySessionEvidence, McpRequestClassification, McpVersionPolicy, validate_mcp_post,
    };

    for fixture in crate::mcp::result_fixtures::result_fixtures() {
        let (request_body, request_headers) = fixture.request("stream");
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in &request_headers {
            headers.insert(*name, value.parse().unwrap());
        }
        let classification = validate_mcp_post(
            &headers,
            &serde_json::to_vec(&request_body).unwrap(),
            LegacySessionEvidence::Absent,
            McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]),
        )
        .unwrap();
        let metadata = crate::mcp::meta::McpMetadataContext::from_classification(&classification, None);
        let McpRequestClassification::Modern(request) = classification else { panic!("expected a modern request") };
        let message = fixture.response("stream");
        for sse in [false, true] {
            let (content_type, wire_body) = if sse {
                ("text/event-stream", format!("data: {message}\n\n"))
            } else {
                ("application/json", message.to_string())
            };
            let upstream = reqwest::Response::from(
                axum::http::Response::builder()
                    .header("content-type", content_type)
                    .body(reqwest::Body::from(wire_body))
                    .unwrap(),
            );
            let upstream_headers = upstream.headers().clone();
            let processing_headers =
                std::collections::HashMap::from([("content-type".to_string(), vec!["application/json".to_string()])]);
            let response = super::process_modern_fabric_response(
                upstream,
                upstream_headers,
                (*request).clone(),
                crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default()),
                processing_headers,
                crate::mcp::modern::ForwardingSupport::for_endpoint(
                    false,
                    crate::mcp::request_validation::McpPathKind::FabricReceive,
                ),
                None,
                move |body, headers| async move {
                    let body = crate::mcp::meta::normalize_text(&body, metadata).unwrap();
                    ProcessingResult::RequiresResponse {
                        response_type: MessageType::ForwardResponse.to_string(),
                        response_body: json!({"status": 200, "body": body, "headers": headers}),
                    }
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{} ({content_type}): {error}", fixture.method));
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let body: Value = if sse {
                use eventsource_stream::Eventsource;
                use futures::StreamExt;
                let events: Vec<_> = futures::stream::iter([Ok::<_, std::io::Error>(bytes)])
                    .eventsource()
                    .collect()
                    .await;
                serde_json::from_str(
                    &events
                        .last()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .data,
                )
                .unwrap()
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            assert_eq!(body["id"], "stream");
            fixture.assert_preserved(&body["result"], &format!("Fabric receive ({content_type})"));
        }
    }
}

#[tokio::test]
async fn fabric_mcp_requests_are_validated_on_receive() {
    if std::env::var_os("AG_MCP_RECEIVE_REGRESSION_CHILD").is_none() {
        let test_name = std::thread::current()
            .name()
            .expect("test thread name")
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env("AG_MCP_RECEIVE_REGRESSION_CHILD", "1")
            .output()
            .expect("run receiver regression with isolated globals");
        assert!(
            output.status.success(),
            "isolated receiver regression failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let target_response = json!({
        "jsonrpc": "2.0",
        "id": "legacy-control",
        "result": {
            "tools": [],
            "_meta": { crate::config::TRUST_REGISTRY_EXTENSION: { "marker": [1, true, null] } }
        }
    });
    let target = MockServer::start_with_response(target_response.to_string()).await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap();
    let gateway_store = FileSystemGatewayStore::new(
        temp_dir
            .path()
            .join("gateways"),
        None,
    )
    .await
    .unwrap();
    gateway_store
        .create(&Gateway::new(
            "Sender".to_string(),
            String::new(),
            "did:web:sender.example".to_string(),
            GatewayType::Remote,
        ))
        .await
        .unwrap();
    let surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "fabric-mcp-validation",
        "name": "Fabric MCP validation",
        "access_point": {
            "listen_address": "127.0.0.1:8080",
            "route": "/mcp",
            "protocol": "mcp"
        },
        "target": { "endpoint": format!("http://{}", target.addr) }
    }))
    .unwrap();
    store
        .save(&surface)
        .await
        .unwrap();

    let now_secs = super::super::envelope_replay::now_secs();
    let forward_message = |body: Value, headers: Value| {
        ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(now_secs + 60),
            json!({
                "channel_id": surface.surface_id,
                "method": "POST",
                "path": "/mcp",
                "headers": headers,
                "body": body
            }),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path))
    };
    let modern_body = json!({
        "jsonrpc": "2.0",
        "id": "fabric-modern",
        "method": "tasks/get",
        "params": {
            "taskId": "task-1",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": { "io.modelcontextprotocol/tasks": {} }
                }
            }
        }
    });
    let modern_headers = json!({
        "MCP-Protocol-Version": MCP_MODERN_VERSION,
        "Mcp-Method": "tasks/get"
    });
    let mut duplicate_headers = modern_headers.clone();
    duplicate_headers["mcp-method"] = json!("tasks/get");
    let mut malformed_headers = modern_headers.clone();
    malformed_headers["Mcp-Method"] = json!(["tasks/get"]);
    let mut invalid_name_headers = modern_headers.clone();
    invalid_name_headers["Mcp-Name"] = json!("=?base64?=");
    let mut mixed_era_headers = modern_headers.clone();
    mixed_era_headers["MCP-Protocol-Version"] = json!(MCP_LEGACY_VERSION);
    let mut mixed_era_body = modern_body.clone();
    mixed_era_body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!(MCP_LEGACY_VERSION);

    for (case, body, headers, code, expected_id) in [
        (
            "malformed canonical metadata cannot fall back",
            json!({"jsonrpc": "2.0", "id": "bad-meta", "method": "tools/list", "params": {"_meta": null}, "_meta": {"tenant": "fallback"}}),
            json!({}),
            -32602,
            Some(json!("bad-meta")),
        ),
        (
            "identity alias conflict",
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {"_meta": {
                "io.affinidi.fabric/agent-identity-credential": {"did": "did:example:one"},
                "https://fabric.affinidi.io/extensions/agent-identity-credential/v1": {"did": "did:example:two"}
            }}}),
            json!({}),
            -32602,
            Some(json!(7)),
        ),
        (
            "modern request on the buffered Fabric leg",
            modern_body.clone(),
            modern_headers.clone(),
            -32022,
            Some(json!("fabric-modern")),
        ),
        ("empty modern body", json!(""), modern_headers, -32700, None),
        ("duplicate standard header", modern_body.clone(), duplicate_headers, -32020, Some(json!("fabric-modern"))),
        ("malformed optional name", modern_body.clone(), invalid_name_headers, -32020, Some(json!("fabric-modern"))),
        ("mixed-era version", mixed_era_body, mixed_era_headers, -32602, Some(json!("fabric-modern"))),
        ("malformed standard header", modern_body, malformed_headers, -32020, Some(json!("fabric-modern"))),
    ] {
        let message = forward_message(body, headers);
        let (forward_response, envelope) = receive(&message).await;
        assert_eq!(forward_response["status"], 400, "{case}");
        assert_eq!(envelope["jsonrpc"], "2.0", "{case}");
        assert_eq!(envelope["error"]["code"], code, "{case}");
        assert_eq!(envelope.get("id").cloned(), expected_id, "{case}");
        if code == -32022 {
            assert_eq!(
                envelope["error"]["data"],
                json!({"requested": MCP_MODERN_VERSION, "supported": [MCP_LEGACY_VERSION]})
            );
        } else {
            assert!(
                envelope["error"]
                    .get("data")
                    .is_none(),
                "{case}"
            );
        }
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            0,
            "{case} reached the Target"
        );
    }

    let unverified = forward_message(
        json!({"jsonrpc": "2.0", "id": "unverified", "method": "tools/list", "params": {"_meta": {"io.affinidi.fabric/agent-identity-credential": {"did": "did:example:unverified"}}}}),
        json!({}),
    );
    let (denied, _) = receive(&unverified).await;
    assert_eq!(denied["status"], 422);
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let legacy_body = json!({"jsonrpc": "2.0", "id": "legacy-control", "method": "tools/list"});
    let message = forward_message(legacy_body.clone(), json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION}));
    let (forward_response, envelope) = receive(&message).await;
    assert_eq!(forward_response["status"], 200);
    assert_eq!(envelope, target_response);
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        1
    );
    let forwarded = target
        .last_request_rx
        .borrow()
        .clone()
        .expect("legacy request reached the Target");
    assert_eq!(forwarded.method, "POST");
    assert_eq!(serde_json::from_str::<Value>(&forwarded.body).unwrap(), legacy_body);

    // An initialize for a revision this receiver does not serve reaches the
    // Target asking for one it does, so the session it opens stays usable.
    let initialize = json!({"jsonrpc": "2.0", "id": "legacy-initialize", "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "client", "version": "1"}
    }});
    let (forward_response, _) = receive(&forward_message(initialize.clone(), json!({}))).await;
    assert_eq!(forward_response["status"], 200);
    let forwarded = target
        .last_request_rx
        .borrow()
        .clone()
        .expect("initialize reached the Target");
    let mut expected = initialize;
    expected["params"]["protocolVersion"] = json!(MCP_LEGACY_VERSION);
    assert_eq!(serde_json::from_str::<Value>(&forwarded.body).unwrap(), expected);

    let caller_body = json!({
        "jsonrpc": "2.0", "id": "legacy-control", "method": "tools/list",
        "params": { "cursor": "opaque", "_meta": { "progressToken": 7 } },
        "_meta": {
            "tenant": "acme",
            crate::config::TRUST_REGISTRY_EXTENSION: { "marker": [1, true, null] }
        }
    });
    for (index, output) in
        [crate::config::McpLegacyMetadataOutput::Compatibility, crate::config::McpLegacyMetadataOutput::Canonical]
            .into_iter()
            .enumerate()
    {
        let mut configured = surface.clone();
        configured.mcp_legacy_metadata_output = Some(output);
        store
            .save(&configured)
            .await
            .unwrap();
        let message = forward_message(caller_body.clone(), json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION}));
        let (forward_response, envelope) = receive(&message).await;
        assert_eq!(forward_response["status"], 200);
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            index + 3
        );
        let received = target
            .last_request_rx
            .borrow()
            .clone()
            .unwrap();
        let forwarded: Value = serde_json::from_str(&received.body).unwrap();
        let mut expected_request = caller_body.clone();
        let mut expected_response = target_response.clone();
        if output == crate::config::McpLegacyMetadataOutput::Canonical {
            expected_request
                .as_object_mut()
                .unwrap()
                .remove("_meta");
            expected_request["params"]["_meta"]["tenant"] = json!("acme");
            expected_request["params"]["_meta"]["io.affinidi.fabric/trust-registry"] =
                json!({"marker": [1, true, null]});
            expected_response["result"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove(crate::config::TRUST_REGISTRY_EXTENSION);
            expected_response["result"]["_meta"]["io.affinidi.fabric/trust-registry"] =
                json!({"marker": [1, true, null]});
        }
        assert_eq!(forwarded, expected_request, "Fabric request output: {output:?}");
        assert_eq!(envelope, expected_response, "Fabric response output: {output:?}");
    }

    async fn refused(message: &ReceivedMessage) -> Value {
        match tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(message)))
            .await
            .expect("Fabric receive handler timed out")
        {
            ProcessingResult::RequiresResponse { response_body, .. } => response_body,
            other => panic!("expected ForwardResponse, got {other:?}"),
        }
    }

    let delivered = target
        .request_count
        .load(Ordering::SeqCst);
    let replayed = forward_message(legacy_body.clone(), json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION}));
    let (first, _) = receive(&replayed).await;
    assert_eq!(first["status"], 200);
    let second = tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(&replayed)))
        .await
        .expect("Fabric receive handler timed out");
    assert!(
        matches!(second, ProcessingResult::ProcessedNoResponse),
        "a verbatim re-delivery is dropped without a ForwardResponse: {second:?}"
    );

    let mut without_expiry = forward_message(legacy_body.clone(), json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION}));
    without_expiry.expires_time = None;
    let response = refused(&without_expiry).await;
    assert_eq!(response["status"], 403, "an envelope without expires_time is refused: {response}");

    let mut expired = forward_message(legacy_body.clone(), json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION}));
    expired.expires_time = Some(now_secs - 1);
    let response = refused(&expired).await;
    assert_eq!(response["status"], 504, "an expired envelope is refused: {response}");

    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        delivered + 1,
        "only the first delivery reached the Target"
    );

    let mut configured = surface.clone();
    configured
        .access_point
        .listen_address = "https://receiver.example".to_string();
    configured.mcp_http = Some(
        serde_json::from_value(json!({
            "allowed_origins": ["https://console.example"], "max_request_bytes": 1024, "max_header_bytes": 512
        }))
        .unwrap(),
    );
    store
        .save(&configured)
        .await
        .unwrap();
    let modern_body = json!({"jsonrpc": "2.0", "id": "http-receive", "method": "server/discover", "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {}
    }}});
    // The sending gateway owns the browser Origin check, so no Origin value
    // changes the buffered receive outcome.
    for origin in [
        json!("https://console.example"),
        json!("https://receiver.example"),
        json!("https://untrusted.example"),
        json!("null"),
        Value::Null,
        json!(["https://console.example"]),
    ] {
        let message = forward_message(
            modern_body.clone(),
            json!({
                "origin": origin, "mcp-protocol-version": MCP_MODERN_VERSION,
                "mcp-method": "server/discover", "accept": "application/json, text/event-stream", "content-type": "application/json"
            }),
        );
        let (response, envelope) = receive(&message).await;
        assert_eq!(response["status"], 400, "{origin}");
        assert_eq!(envelope["id"], "http-receive");
        assert_eq!(envelope["error"]["code"], -32022);
    }
    for (body, headers, expected_status) in [
        (
            legacy_body.clone(),
            json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION, "origin": "https://untrusted.example", "Origin": "https://untrusted.example"}),
            200,
        ),
        (json!(" ".repeat(1025)), json!({}), 413),
        (legacy_body, json!({"x-extra": "x".repeat(513)}), 431),
    ] {
        let (response, _) = receive(&forward_message(body, headers)).await;
        assert_eq!(response["status"], expected_status);
    }
    for method in ["GET", "DELETE"] {
        let mut message = forward_message(
            Value::Null,
            json!({
                "mcp-protocol-version": MCP_MODERN_VERSION, "mcp-session-id": "legacy-session"
            }),
        );
        message.message_body["method"] = json!(method);
        let ProcessingResult::RequiresResponse { response_body, .. } = process_forward_request(&message).await else {
            panic!("expected a Fabric method rejection");
        };
        assert_eq!(response_body["status"], 405);
        assert_eq!(response_body["headers"]["allow"], "POST");
        assert_eq!(response_body["body"], "");
    }
    // The shared negative admission cases, through the
    // ForwardRequest path. Envelope headers are JSON: a repeated header is an
    // array, and a value that is not UTF-8 cannot be carried at all.
    let before = target
        .request_count
        .load(Ordering::SeqCst);
    for case in crate::mcp::admission_cases::admission_cases()
        .into_iter()
        .filter(|case| {
            !case.http_only
                && !case
                    .headers
                    .iter()
                    .any(|(name, _)| *name == "origin")
        })
    {
        let mut headers = serde_json::Map::new();
        for (name, value) in &case.headers {
            let value = json!(value.to_str().unwrap());
            match headers.remove(*name) {
                None => headers.insert(name.to_string(), value),
                Some(Value::Array(mut values)) => {
                    values.push(value);
                    headers.insert(name.to_string(), Value::Array(values))
                }
                Some(first) => headers.insert(name.to_string(), json!([first, value])),
            };
        }
        let body: Value = serde_json::from_slice(&case.body).unwrap();
        let (response, envelope) = receive(&forward_message(body, Value::Object(headers))).await;
        let status = axum::http::StatusCode::from_u16(
            response["status"]
                .as_u64()
                .unwrap() as u16,
        )
        .unwrap();
        crate::mcp::admission_cases::assert_rejected(&case, status, &envelope, "Fabric receive");
    }
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        before,
        "no negative admission case reaches the Target"
    );
    let mut protected = configured.clone();
    protected
        .mcp_http
        .as_mut()
        .unwrap()
        .authorization = Some(crate::mcp::resource_server::McpResourceServerConfig {
        resource: "https://receiver.example/mcp".into(),
        scopes: vec!["read".into()],
    });
    store
        .save(&protected)
        .await
        .unwrap();
    let before = target
        .request_count
        .load(Ordering::SeqCst);
    let denied = process_forward_request(&forward_message(
        json!({"jsonrpc": "2.0", "id": "protected", "method": "tools/list"}),
        json!({"Authorization": "Bearer cannot-establish-receiver-authority"}),
    ))
    .await;
    let ProcessingResult::RequiresResponse { response_body, .. } = denied else {
        panic!("protected Fabric request must fail closed without resource authorization context");
    };
    assert_eq!(response_body["status"], 503);
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        before
    );
    store
        .save(&configured)
        .await
        .unwrap();

    // A legacy-only receiver rejects the modern revision; a duplicate mirrored
    // header is rejected first.
    for duplicate in [false, true] {
        let mut headers = axum::http::HeaderMap::new();
        headers.append(
            "mcp-protocol-version",
            MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.append(
            "mcp-method",
            "server/discover"
                .parse()
                .unwrap(),
        );
        headers.append(
            "accept",
            "application/json, text/event-stream"
                .parse()
                .unwrap(),
        );
        headers.append(
            "content-type",
            "application/json"
                .parse()
                .unwrap(),
        );
        if duplicate {
            headers.append(
                "mcp-method",
                "server/discover"
                    .parse()
                    .unwrap(),
            );
        }
        let body = bytes::Bytes::from(serde_json::to_vec(&modern_body).unwrap());
        let message = forward_message(Value::Null, json!({}));
        let result = super::process_stream_forward_request(
            &message,
            super::FabricStreamRequest {
                headers,
                body,
                surface: configured.clone(),
                variant_id: None,
                capabilities: crate::proxy::fabric_stream::peer::StreamCapabilities::local(true, true),
            },
            crate::mcp::request_validation::LEGACY_ONLY_POLICY,
            None,
        )
        .await;
        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected framed request rejection")
        };
        let envelope: Value = serde_json::from_str(
            response_body["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response_body["status"], 400);
        assert_eq!(envelope["id"], "http-receive");
        assert_eq!(
            envelope["error"]["code"],
            if duplicate {
                -32020
            } else {
                -32022
            }
        );
    }
    // Includes the capped initialize, the one envelope-replay delivery and the
    // legacy request whose forwarded Origin is not rechecked.
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        6
    );
}

#[test]
fn fabric_consent_uses_receiver_authority_and_rejects_cross_peer_retries() {
    if std::env::var_os("ATG_MCP_CONSENT_RECEIVE_CHILD").is_none() {
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env("ATG_MCP_CONSENT_RECEIVE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated Fabric consent test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(fabric_consent_flow()));
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn fabric_consent_flow() {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::{extract::State, http::HeaderMap, response::IntoResponse};
    use futures::TryStreamExt;
    use sha2::{Digest, Sha256};

    use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
    use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
    use crate::identity::ssi::vc_issuer::{AgentIdentity, IssueVcPayload, LocalVcIssuer, LocalVcSigner, VcIssuer};
    use crate::identity::ssi::vp_issuer::{Credentials, LocalVpIssuer, LocalVpSigner, VpIssuer, VpIssuerPayload};
    use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
    use crate::mcp::continuations::{
        config::ContinuationRuntime,
        embedded::EmbeddedContinuations,
        protected::{ContinuationCipher, ContinuationKey, ContinuationRoute},
        service::ContinuationService,
    };

    fn peer(key: &ssi::jwk::JWK) -> String {
        let public_key = crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(key).unwrap();
        let keys = (0..2)
            .map(|_| did_peer::DIDPeerCreateKeys {
                purpose: did_peer::DIDPeerKeys::Verification,
                type_: None,
                public_key_multibase: Some(public_key.clone()),
            })
            .collect::<Vec<_>>();
        did_peer::DIDPeer::create_peer_did(&keys, None)
            .unwrap()
            .0
    }

    async fn decode(result: ProcessingResult) -> (u16, Value) {
        match result {
            ProcessingResult::RequiresResponse { response_body, .. } => {
                let text = response_body["body"]
                    .as_str()
                    .unwrap_or("");
                (
                    response_body["status"]
                        .as_u64()
                        .unwrap() as u16,
                    if text.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_str(text).unwrap()
                    },
                )
            }
            ProcessingResult::StreamingResponse { response } => {
                let status = response.status().as_u16();
                let sse = response
                    .headers()
                    .get("content-type")
                    .is_some_and(|value| value == "text/event-stream");
                let bytes = axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap();
                let body = if sse {
                    let events: Vec<_> = crate::mcp::modern_sse::decode_events(
                        futures::stream::iter([Ok::<_, std::io::Error>(bytes)]),
                        crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default()),
                    )
                    .try_collect()
                    .await
                    .unwrap();
                    serde_json::from_str(&events.last().unwrap().data).unwrap()
                } else {
                    serde_json::from_slice(&bytes).unwrap()
                };
                (status, body)
            }
            other => panic!("unexpected Fabric result: {other:?}"),
        }
    }

    type ObservedCalls = Arc<tokio::sync::Mutex<Vec<(HeaderMap, Value)>>>;
    let calls: ObservedCalls = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let target = axum::Router::new()
        .fallback(axum::routing::post(
            |State(calls): State<ObservedCalls>,
             uri: axum::http::Uri,
             headers: HeaderMap,
             axum::Json(body): axum::Json<Value>| async move {
                if body.get("id").is_none() {
                    calls
                        .lock()
                        .await
                        .push((headers, body));
                    return if uri.path().contains("reject") {
                        (
                            axum::http::StatusCode::NOT_FOUND,
                            axum::Json(json!({
                                "jsonrpc": "2.0", "error": {"code": -32601, "message": "Unknown notification"}
                            })),
                        )
                            .into_response()
                    } else {
                        axum::http::StatusCode::ACCEPTED.into_response()
                    };
                }
                let result = if body["params"]
                    .get("requestState")
                    .is_some()
                {
                    json!({"resultType": "complete", "content": []})
                } else {
                    json!({"resultType": "input_required", "requestState": "remote opaque state",
                    "inputRequests": {"remote-input": {"method": "elicitation/create", "params": {
                        "mode": "url", "url": "https://target.example/consent", "message": "Authorize"
                    }}}})
                };
                let response = json!({"jsonrpc": "2.0", "id": body["id"], "result": result});
                calls
                    .lock()
                    .await
                    .push((headers, body));
                if uri.path().contains("sse") {
                    ([("content-type", "text/event-stream")], format!("data: {response}\n\n")).into_response()
                } else {
                    axum::Json(response).into_response()
                }
            },
        ))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let target_address = listener.local_addr().unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        axum::serve(listener, target)
            .await
            .unwrap();
    });

    let (receiver, directory) = crate::identity::test_helpers::test_vc_issuer().await;
    let receiver = Arc::new(receiver);
    let sender_key = ssi::jwk::JWK::generate_ed25519().unwrap();
    let sender_did = peer(&sender_key);
    // The other sender also trusts the sender's issuer, so a retry it replays
    // is refused by the continuation's peer binding, not by the issuer check.
    let _paired_dir = install_listener_manager_with_peers(
        directory.path(),
        &[
            remote_peer(&sender_did, Some(&sender_did), &[]),
            remote_peer(OTHER_SENDER_DID, Some("did:example:other-sender-gateway"), &[&sender_did]),
        ],
    )
    .await;
    let holder_key = ssi::jwk::JWK::generate_ed25519().unwrap();
    let holder_did = peer(&holder_key);
    let signing_config = Arc::new(tokio::sync::RwLock::new(crate::identity::VCIssuerConfig {
        storage_path: Default::default(),
        proxy_did: sender_did.clone(),
        signing_key: sender_key,
        is_vp_challenge_required: false,
    }));
    let credential = LocalVcIssuer::new(signing_config.clone(), Arc::new(LocalVcSigner::new(signing_config)))
        .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
            did: Cow::Borrowed(&holder_did),
            identity_fields: Cow::Owned(HashMap::new()),
            workload_binding: None,
        }))
        .await
        .unwrap();
    let presentation = LocalVpIssuer::new(Arc::new(LocalVpSigner::new()))
        .issue(VpIssuerPayload::Credentials(Credentials {
            holder_key: Cow::Owned(holder_key),
            holder_did: Cow::Borrowed(&holder_did),
            verifiable_credentials: Cow::Owned(vec![credential]),
            challenge: None,
            domain: None,
        }))
        .await
        .unwrap();
    let strategies = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            directory
                .path()
                .join("strategies"),
        )
        .await
        .unwrap(),
    );
    let strategy = strategies
        .create(
            crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &json!({"keys": []}))
                .unwrap(),
        )
        .await
        .unwrap();
    let providers = Arc::new(
        FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap(),
    );
    let provider = providers.create(serde_json::from_value(json!({
        "id": "provider", "name": "Provider", "provider_id": "provider", "resource": "https://target.example/api",
        "consent_identity_strategy_id": strategy.id, "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
    })).unwrap()).await.unwrap();
    let vault = Arc::new(
        FileSystemDelegationVaultStore::new(directory.path().join("vault"))
            .await
            .unwrap(),
    );
    let network = serde_json::from_value(json!({
        "did": {"domain": "receiver.example"}, "webauthn": {"rp_id": "receiver.example", "external_origin": "https://receiver.example"},
        "integration": {"types": [], "categories": []},
        "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080,
            "protocol": "http", "external_urls": ["https://receiver.example"]}],
        "routes": {"identity": {"type": "identity_api", "prefix": "/api"}},
        "sts": {"mcp_issuer": {"issuer": "https://receiver.example/api/oauth2/mcp"}}
    })).unwrap();
    super::init_mcp_auth_network(Arc::new(network));
    super::init_vc_issuer(receiver.clone(), None).await;
    super::init_source_auth_middleware(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
        Arc::new(crate::didauth::DidAuthSessionStore::new()),
        strategies,
        Arc::new(crate::jwt_bearer::JwksClient::new()),
        None,
        Arc::new(dashmap::DashMap::new()),
        None,
        None,
    )))
    .await;
    super::init_credential_provider_store(providers).await;
    super::init_delegation_vault_store(vault.clone()).await;
    let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
    let runtime = Arc::new(ContinuationRuntime {
        config: serde_json::from_value(json!({"deployment": "receiver", "ttl_secs": 300, "active_key": "key",
            "keys": [{"id": "key", "secret_id": "key-secret", "not_before": now - 1, "seal_until": now + 3600, "open_until": now + 4500}],
            "storage": {"backend": "embedded", "capacity": 32}})).unwrap(),
        service: Arc::new(ContinuationService::new(ContinuationCipher::new("receiver".into(), "key".into(), vec![
            ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap(),
        ]).unwrap(), Arc::new(EmbeddedContinuations::new(32).unwrap()))),
    });
    let claims = json!({"iss": "https://receiver.example/api/oauth2/mcp", "sub": "user", "scope": "read",
        "aud": "https://receiver.example/mcp", "exp": now + 300});
    let bearer = receiver
        .sign_jwt_with_gateway_key_typ(&claims, "at+jwt")
        .await
        .unwrap();
    let mut surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "fabric-consent", "name": "Fabric consent",
        "access_point": {"listen_address": "https://receiver.example", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": format!("http://{target_address}/json")},
        "mcp_http": {"authorization": {"resource": "https://receiver.example/mcp", "scopes": ["read"]}},
        "outbound_credentials": [{"credential_provider_id": "provider", "scopes": ["read"]}]
    }))
    .unwrap();
    let mut body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "echo", "arguments": {"value": 1}, "_meta": {
            "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"url": {}}},
            "io.affinidi.fabric/agent-identity-credential": {"did": holder_did, "verifiablePresentation": presentation.to_string()}
        }
    }});
    let make_request = |body: &Value, surface: &AgentSurface, sender: &str, token: &str| {
        let headers = json!({"authorization": format!("Bearer {token}"), "content-type": "application/json",
            "accept": "application/json, text/event-stream", "mcp-protocol-version": MCP_MODERN_VERSION,
            "mcp-method": "tools/call", "mcp-name": "echo"});
        let typed_headers = crate::proxy::fabric_stream::wire::headers_from_json(Some(&headers)).unwrap();
        let message = ReceivedMessage::new(
            "connection".into(),
            "receiver".into(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(sender.into()),
            vec!["did:example:receiver".into()],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            json!({"channel_id": surface.surface_id, "method": "POST", "path": "/mcp", "headers": headers}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        // Fabric receive resolves the sender under the parent of this path,
        // where the paired peers were installed.
        .with_context(
            "agent_surface_storage_path",
            json!(
                directory
                    .path()
                    .join("surfaces")
            ),
        );
        (
            message,
            super::FabricStreamRequest {
                headers: typed_headers,
                body: serde_json::to_vec(body)
                    .unwrap()
                    .into(),
                surface: surface.clone(),
                variant_id: None,
                capabilities: crate::proxy::fabric_stream::peer::StreamCapabilities::local(true, true),
            },
        )
    };
    let versions = crate::mcp::request_validation::McpVersionPolicy::new(
        &[MCP_MODERN_VERSION],
        &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION],
    );
    {
        let (message, stream) = make_request(&body, &surface, &sender_did, &bearer);
        let rejected = decode(
            super::process_stream_forward_request(
                &message,
                stream,
                crate::mcp::request_validation::LEGACY_ONLY_POLICY,
                None,
            )
            .await,
        )
        .await;
        assert_eq!(rejected.0, 400);
        assert_eq!(rejected.1["error"]["code"], -32022);
    }
    let mut wrong_claims = claims;
    wrong_claims["aud"] = json!("https://ingress.example/mcp");
    let wrong_token = receiver
        .sign_jwt_with_gateway_key_typ(&wrong_claims, "at+jwt")
        .await
        .unwrap();
    let (message, stream) = make_request(&body, &surface, &sender_did, &wrong_token);
    let rejected = decode(
        Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(stream),
            versions,
            Some(runtime.clone()),
        ))
        .await,
    )
    .await;
    assert_eq!(rejected.0, 401);
    let (message, stream) = make_request(&body, &surface, &sender_did, &bearer);
    let pending = decode(
        Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(stream),
            versions,
            Some(runtime.clone()),
        ))
        .await,
    )
    .await;
    assert_eq!(pending.0, 200, "{:?}", pending.1);
    assert_eq!(pending.1["result"]["resultType"], "input_required");
    assert!(calls.lock().await.is_empty());
    // Tampered, expired, cross-user and incapable MRTR retries, on a continuation of their own
    // so the flow below keeps its state.
    {
        let send = |body: Value, token: String, runtime: Arc<ContinuationRuntime>| {
            let (message, stream) = make_request(&body, &surface, &sender_did, &token);
            async move {
                decode(
                    Box::pin(super::process_forward_request_with_mcp_runtime(
                        &message,
                        Some(stream),
                        versions,
                        Some(runtime),
                    ))
                    .await,
                )
                .await
            }
        };
        let pending = |id: &str, request_state: Option<&str>| {
            let mut pending = body.clone();
            pending["id"] = json!(id);
            if let Some(request_state) = request_state {
                pending["params"]["requestState"] = json!(request_state);
            }
            pending
        };
        let (_, issued) = send(pending("negatives", None), bearer.clone(), runtime.clone()).await;
        let issued_state = issued["result"]["requestState"]
            .as_str()
            .expect("a continuation to replay")
            .to_string();

        // A tampered state does not open.
        let mut bytes = issued_state
            .clone()
            .into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered = String::from_utf8(bytes).unwrap();
        let (status, response) = send(pending("tampered", Some(&tampered)), bearer.clone(), runtime.clone()).await;
        assert_eq!(status, 400, "tampered: {response}");
        assert_eq!(response["error"]["code"], crate::mcp::error_codes::INVALID_PARAMS, "tampered: {response}");

        // Another principal cannot resume it.
        let other = receiver
            .sign_jwt_with_gateway_key_typ(
                &json!({"iss": "https://receiver.example/api/oauth2/mcp", "sub": "other-user", "scope": "read",
                    "aud": "https://receiver.example/mcp", "exp": now + 300}),
                "at+jwt",
            )
            .await
            .unwrap();
        let (status, response) = send(pending("cross-user", Some(&issued_state)), other, runtime.clone()).await;
        assert_eq!(status, 403, "cross-user: {response}");
        assert_eq!(response["error"]["code"], -32001, "cross-user: {response}");

        // A client that did not declare URL elicitation is not sent a consent request.
        let mut incapable = pending("incapable", None);
        incapable["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
        let (status, response) = send(incapable, bearer.clone(), runtime.clone()).await;
        assert_eq!(
            response["error"]["code"],
            crate::mcp::error_codes::MISSING_REQUIRED_CLIENT_CAPABILITY,
            "incapable: {status} {response}"
        );

        // An expired state does not open.
        let short = Arc::new(ContinuationRuntime {
            config: serde_json::from_value(json!({"deployment": "deployment", "ttl_secs": 1, "active_key": "key",
                "keys": [{"id": "key", "secret_id": "key-secret", "not_before": now - 1, "seal_until": now + 3600, "open_until": now + 4500}],
                "storage": {"backend": "embedded", "capacity": 32}})).unwrap(),
            service: Arc::new(ContinuationService::new(ContinuationCipher::new("deployment".into(), "key".into(), vec![
                ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap(),
            ]).unwrap(), Arc::new(EmbeddedContinuations::new(32).unwrap()))),
        });
        let (_, short_issued) = send(pending("short", None), bearer.clone(), short.clone()).await;
        tokio::time::sleep(Duration::from_millis(2100)).await;
        let short_state = short_issued["result"]["requestState"]
            .as_str()
            .unwrap()
            .to_string();
        let (status, response) = send(pending("expired", Some(&short_state)), bearer.clone(), short).await;
        assert_eq!(status, 400, "expired: {response}");
        assert_eq!(response["error"]["code"], crate::mcp::error_codes::INVALID_PARAMS, "expired: {response}");
        assert!(calls.lock().await.is_empty(), "no negative case reaches the upstream");
    }

    vault.store(serde_json::from_value(json!({
        "id": "verified-token", "agent_did": holder_did, "user_identity_hash": hex::encode(Sha256::digest(b"user")),
        "credential_provider_id": "provider", "provider_id": "provider", "access_token": "verified-remote-credential", "scopes": ["read"],
        "consent_granted_at": "2026-09-01T00:00:00Z", "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z",
        "consent_identity": {"principal": hex::encode(Sha256::digest(serde_json_canonicalizer::to_vec(&("https://receiver.example/api/oauth2/mcp", "user")).unwrap())),
            "provider_digest": crate::mcp::continuations::delegation::provider_digest(&provider).unwrap(),
            "strategy_digest": crate::mcp::continuations::delegation::identity_strategy_digest(&strategy).unwrap()}
    })).unwrap()).await.unwrap();
    for format in ["json", "sse"] {
        surface.target.endpoint = format!("http://{target_address}/{format}");
        body["id"] = json!(10);
        body["params"]
            .as_object_mut()
            .unwrap()
            .remove("requestState");
        body["params"]
            .as_object_mut()
            .unwrap()
            .remove("inputResponses");
        let before = calls.lock().await.len();
        let (message, stream) = make_request(&body, &surface, &sender_did, &bearer);
        let response = decode(
            Box::pin(super::process_forward_request_with_mcp_runtime(
                &message,
                Some(stream),
                versions,
                Some(runtime.clone()),
            ))
            .await,
        )
        .await;
        assert_eq!(response.0, 200, "{:?}", response.1);
        assert_eq!(response.1["result"]["resultType"], "input_required");
        assert_ne!(response.1["result"]["requestState"], "remote opaque state");
        body["id"] = json!(11);
        body["params"]["requestState"] = response.1["result"]["requestState"].clone();
        body["params"]["inputResponses"] =
            json!({"remote-input": {"action": "accept"}, "ignored": {"action": "cancel"}});
        let (message, stream) = make_request(&body, &surface, OTHER_SENDER_DID, &bearer);
        let response = decode(
            Box::pin(super::process_forward_request_with_mcp_runtime(
                &message,
                Some(stream),
                versions,
                Some(runtime.clone()),
            ))
            .await,
        )
        .await;
        assert_eq!(response.0, 403, "{:?}", response.1);
        assert_eq!(response.1["error"]["code"], -32001, "{:?}", response.1);
        let (first_message, first_stream) = make_request(&body, &surface, &sender_did, &bearer);
        let (second_message, second_stream) = make_request(&body, &surface, &sender_did, &bearer);
        let (first, second) = tokio::join!(
            Box::pin(super::process_forward_request_with_mcp_runtime(
                &first_message,
                Some(first_stream),
                versions,
                Some(runtime.clone())
            )),
            Box::pin(super::process_forward_request_with_mcp_runtime(
                &second_message,
                Some(second_stream),
                versions,
                Some(runtime.clone())
            )),
        );
        let first = decode(first).await;
        let second = decode(second).await;
        assert_eq!(
            [first.0, second.0]
                .iter()
                .filter(|status| **status == 200)
                .count(),
            1,
            "{first:?}; {second:?}"
        );
        assert_eq!(
            [first.0, second.0]
                .iter()
                .filter(|status| **status == 409)
                .count(),
            1,
            "{first:?}; {second:?}"
        );
        let observed = calls.lock().await;
        assert_eq!(observed.len(), before + 2);
        for (headers, _) in &observed[before..] {
            assert_eq!(
                headers
                    .get_all("authorization")
                    .iter()
                    .count(),
                1
            );
            assert_eq!(headers["authorization"], "Bearer verified-remote-credential");
        }
        assert_eq!(observed[before + 1].1["params"]["requestState"], "remote opaque state");
        assert_eq!(observed[before + 1].1["params"]["inputResponses"], json!({"remote-input": {"action": "accept"}}));
    }
    let bound_request = crate::mcp::request_validation::ValidatedModernMessage {
        protocol_version: MCP_MODERN_VERSION.into(),
        client_capabilities: None,
        client_info: None,
        method: "tools/call".into(),
        params: Some(body["params"].clone()),
        id: Some(json!(12)),
        kind: crate::mcp::request_validation::McpMessageKind::Request,
    };
    let binding = runtime
        .service
        .request_binding(
            body["params"]["requestState"]
                .as_str()
                .unwrap(),
            &bound_request,
            crate::proxy::credential_delegation::modern::now_secs().unwrap(),
        )
        .unwrap();
    assert!(binding.route == ContinuationRoute::Fabric { peer_did: sender_did.clone() });
    assert_eq!(binding.resource, "https://receiver.example/mcp");
    for format in ["json", "sse"] {
        surface.target.endpoint = format!("http://{target_address}/{format}");
        surface.target.payment_policy = Some(
            serde_json::from_value(json!({
                "type": "x402", "enabled": true, "verification_mode": "mock", "settlement_mode": "none",
                "mcp_payment_triggers": {"mode": "all"}
            }))
            .unwrap(),
        );
        body["id"] = json!(20);
        body["params"]
            .as_object_mut()
            .unwrap()
            .remove("requestState");
        body["params"]
            .as_object_mut()
            .unwrap()
            .remove("inputResponses");
        let original = crate::mcp::request_validation::ValidatedModernMessage {
            protocol_version: MCP_MODERN_VERSION.into(),
            client_capabilities: Some(json!({"elicitation": {"url": {}}})),
            client_info: None,
            method: "tools/call".into(),
            params: Some(body["params"].clone()),
            id: Some(body["id"].clone()),
            kind: crate::mcp::request_validation::McpMessageKind::Request,
        };
        let identity = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "user".into(),
            claims: json!({"iss": "https://receiver.example/api/oauth2/mcp", "sub": "user", "scope": "read"}),
        };
        let binding = crate::mcp::continuations::delegation::make_binding(
            "receiver",
            &surface,
            None,
            ContinuationRoute::Fabric { peer_did: sender_did.clone() },
            surface
                .mcp_http
                .as_ref()
                .unwrap()
                .authorization
                .as_ref()
                .unwrap(),
            &provider,
            vec!["read".into()],
            &holder_did,
            &identity,
            &original,
        )
        .unwrap();
        let response = runtime
            .service
            .wrap_upstream_response(
                &original,
                binding,
                json!({"jsonrpc": "2.0", "id": 20, "result": {
                    "resultType": "input_required", "requestState": "remote opaque state",
                    "inputRequests": {"remote-input": {"method": "elicitation/create", "params": {
                        "mode": "url", "url": "https://target.example/consent", "message": "Authorize"
                    }}}
                }}),
                300,
                now,
            )
            .await
            .unwrap();
        body["id"] = json!(21);
        body["params"]["requestState"] = response["result"]["requestState"].clone();
        body["params"]["inputResponses"] = json!({"remote-input": {"action": "accept"}});
        let before = calls.lock().await.len();
        for _attempt in 0..2 {
            let (message, stream) = make_request(&body, &surface, &sender_did, &bearer);
            let response = decode(
                Box::pin(super::process_forward_request_with_mcp_runtime(
                    &message,
                    Some(stream),
                    versions,
                    Some(runtime.clone()),
                ))
                .await,
            )
            .await;
            assert_eq!(response.0, 402, "{:?}", response.1);
            assert_eq!(calls.lock().await.len(), before);
        }
        body["id"] = json!(22);
        let signature = base64::Engine::encode(&base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&json!({
                "x402Version": 2,
                "resource": {"url": "https://receiver.example/mcp", "description": "test", "mimeType": "application/json"},
                "accepted": {"scheme": "exact", "network": "eip155:1", "amount": "1000",
                    "asset": "0x123", "payTo": "0x456", "maxTimeoutSeconds": 300},
                "payload": {"signature": "fixture-payment"}
            })).unwrap());
        let paid_request = || {
            let mut paid_body = body.clone();
            if format == "sse" {
                paid_body["params"]["arguments"]["payment_signature"] = json!(signature);
            }
            let (mut message, mut stream) = make_request(&paid_body, &surface, &sender_did, &bearer);
            if format == "json" {
                stream
                    .headers
                    .insert("payment-signature", signature.parse().unwrap());
                message.message_body["headers"]["pAyMeNt-SiGnAtUrE"] = json!(signature);
            }
            (message, stream)
        };
        let (first_message, first_stream) = paid_request();
        let (second_message, second_stream) = paid_request();
        let (first, second) = tokio::join!(
            Box::pin(super::process_forward_request_with_mcp_runtime(
                &first_message,
                Some(first_stream),
                versions,
                Some(runtime.clone()),
            )),
            Box::pin(super::process_forward_request_with_mcp_runtime(
                &second_message,
                Some(second_stream),
                versions,
                Some(runtime.clone()),
            )),
        );
        for result in [&first, &second] {
            if let ProcessingResult::StreamingResponse { response } = result {
                let receipt = response
                    .headers()
                    .get("payment-response")
                    .expect("receiver receipt");
                let receipt =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, receipt.as_bytes()).unwrap();
                let receipt: Value = serde_json::from_slice(&receipt).unwrap();
                assert_eq!(receipt["verified"], true);
                assert_eq!(receipt["settled"], false);
            }
        }
        let first = decode(first).await;
        let second = decode(second).await;
        assert!(matches!((first.0, second.0), (200, 409) | (409, 200)), "{first:?}; {second:?}");
        let observed = calls.lock().await;
        assert_eq!(observed.len(), before + 1);
        assert_eq!(observed[before].0["authorization"], "Bearer verified-remote-credential");
        assert!(
            !observed[before]
                .0
                .contains_key("payment-signature")
        );
        assert!(
            observed[before].1["params"]["arguments"]
                .get("payment_signature")
                .is_none()
        );
        assert_eq!(observed[before].1["params"]["requestState"], "remote opaque state");
    }
    let transactions = Arc::new(
        crate::x402::TransactionStore::new(
            directory
                .path()
                .join("payments"),
        )
        .await
        .unwrap(),
    );
    super::init_transaction_store(transactions.clone()).await;
    for format in ["json", "sse"] {
        surface.target.endpoint = format!("http://{target_address}/{format}");
        body["id"] = json!(30);
        body["params"]
            .as_object_mut()
            .unwrap()
            .remove("requestState");
        body["params"]
            .as_object_mut()
            .unwrap()
            .remove("inputResponses");
        let signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&json!({
                "x402Version": 2,
                "accepted": {"scheme": "exact", "network": "eip155:1", "amount": "1000",
                    "asset": "0x123", "payTo": "0x456", "maxTimeoutSeconds": 300},
                "payload": {"signature": format!("receiver-round-{format}")}
            }))
            .unwrap(),
        );
        let (message, mut stream) = make_request(&body, &surface, &sender_did, &bearer);
        stream
            .headers
            .insert("payment-signature", signature.parse().unwrap());
        let calls_before = calls.lock().await.len();
        let payments_before = transactions
            .list_all()
            .await
            .len();
        let response = Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(stream),
            versions,
            Some(runtime.clone()),
        ))
        .await;
        let receipt = match &response {
            ProcessingResult::StreamingResponse { response } => response
                .headers()
                .get("payment-response")
                .unwrap()
                .clone(),
            other => panic!("expected paid streaming response: {other:?}"),
        };
        let (status, response) = decode(response).await;
        assert_eq!(status, 200, "{response}");
        assert_eq!(response["result"]["resultType"], "input_required");
        assert_eq!(
            transactions
                .list_all()
                .await
                .len(),
            payments_before + 1
        );
        body["id"] = json!(31);
        body["params"]["requestState"] = response["result"]["requestState"].clone();
        body["params"]["inputResponses"] = json!({"remote-input": {"action": "accept"}});
        let (message, stream) = make_request(&body, &surface, &sender_did, &bearer);
        let response = Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(stream),
            versions,
            Some(runtime.clone()),
        ))
        .await;
        match &response {
            ProcessingResult::StreamingResponse { response } => assert_eq!(
                response
                    .headers()
                    .get("payment-response"),
                Some(&receipt)
            ),
            other => panic!("expected paid continuation response: {other:?}"),
        }
        let (status, response) = decode(response).await;
        assert_eq!(status, 200, "{response}");
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(
            transactions
                .list_all()
                .await
                .len(),
            payments_before + 1
        );
        assert_eq!(calls.lock().await.len(), calls_before + 2);
        body["id"] = json!(32);
        let (message, stream) = make_request(&body, &surface, &sender_did, &bearer);
        let response = decode(
            Box::pin(super::process_forward_request_with_mcp_runtime(
                &message,
                Some(stream),
                versions,
                Some(runtime.clone()),
            ))
            .await,
        )
        .await;
        assert_eq!(response.0, 409, "{:?}", response.1);
        assert_eq!(
            transactions
                .list_all()
                .await
                .len(),
            payments_before + 1
        );
        assert_eq!(calls.lock().await.len(), calls_before + 2);
    }
    surface.target.payment_policy = None;
    for reject in [false, true] {
        surface.target.endpoint = format!(
            "http://{target_address}/{}",
            if reject {
                "notification-reject"
            } else {
                "notification-accept"
            }
        );
        let mut notification = json!({"jsonrpc": "2.0", "method": "notifications/com.example/changed", "params": {
            "revision": 1, "_meta": body["params"]["_meta"]
        }});
        notification["params"]["_meta"]
            .as_object_mut()
            .unwrap()
            .remove("io.modelcontextprotocol/clientCapabilities");
        let (mut message, mut stream) = make_request(&notification, &surface, &sender_did, &bearer);
        stream.headers.insert(
            "mcp-method",
            "notifications/com.example/changed"
                .parse()
                .unwrap(),
        );
        stream
            .headers
            .remove("mcp-name");
        stream.headers.insert(
            "mcp-session-id",
            "unused-session"
                .parse()
                .unwrap(),
        );
        stream
            .headers
            .insert("last-event-id", "7".parse().unwrap());
        message.message_body["headers"]["mcp-method"] = json!("notifications/com.example/changed");
        message.message_body["headers"]
            .as_object_mut()
            .unwrap()
            .remove("mcp-name");
        let before = calls.lock().await.len();
        let result = Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(stream),
            versions,
            Some(runtime.clone()),
        ))
        .await;
        let ProcessingResult::StreamingResponse { response } = result else {
            panic!("expected receiver notification response: {result:?}");
        };
        let status = response.status();
        let headers = response.headers().clone();
        let response_body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            status,
            if reject {
                axum::http::StatusCode::NOT_FOUND
            } else {
                axum::http::StatusCode::ACCEPTED
            },
            "{}",
            String::from_utf8_lossy(&response_body)
        );
        assert!(!headers.contains_key("mcp-session-id"));
        if reject {
            let error: Value = serde_json::from_slice(&response_body).unwrap();
            assert_eq!(error["error"]["code"], -32601);
            assert!(error.get("id").is_none());
        } else {
            assert!(response_body.is_empty());
            assert!(!headers.contains_key("content-type"));
        }
        let observed = calls.lock().await;
        assert_eq!(observed.len(), before + 1);
        assert!(
            observed[before]
                .1
                .get("id")
                .is_none()
        );
        assert_eq!(observed[before].1["method"], notification["method"]);
        assert_eq!(observed[before].1["params"]["revision"], 1);
        assert_eq!(observed[before].0["authorization"], "Bearer verified-remote-credential");
        for name in ["mcp-session-id", "last-event-id"] {
            assert!(
                !observed[before]
                    .0
                    .contains_key(name),
                "{name} does not reach the upstream"
            );
        }
    }
    let mut variant_catalog = surface.clone();
    variant_catalog.variants.push(
        serde_json::from_value(json!({
            "id": "credential-variant", "alias": "candidate", "name": "Candidate",
            "overrides": {"target": {"endpoint": format!("http://{target_address}/json")}}
        }))
        .unwrap(),
    );
    variant_catalog.default_variant_id = Some("credential-variant".into());
    for alias in [Some("candidate"), None] {
        let resolved = variant_catalog
            .resolve_variant(alias)
            .unwrap();
        assert!(resolved.variants.is_empty());
        assert!(
            resolved
                .default_variant_id
                .is_none()
        );
        let resource = if alias.is_some() {
            "https://receiver.example/mcp$candidate"
        } else {
            "https://receiver.example/mcp"
        };
        let variant_bearer = receiver
            .sign_jwt_with_gateway_key_typ(
                &json!({
                    "iss": "https://receiver.example/api/oauth2/mcp", "sub": "user", "scope": "read",
                    "aud": resource, "exp": now + 300
                }),
                "at+jwt",
            )
            .await
            .unwrap();
        let mut variant_body = body.clone();
        variant_body["id"] = json!(40);
        variant_body["params"]
            .as_object_mut()
            .unwrap()
            .remove("requestState");
        variant_body["params"]
            .as_object_mut()
            .unwrap()
            .remove("inputResponses");
        let build_variant = |body: &Value, bearer: &str| {
            let (mut message, mut stream) = make_request(body, &resolved, &sender_did, bearer);
            if let Some(alias) = alias {
                message.message_body["virtual_channel_alias"] = json!(alias);
            }
            stream.variant_id = Some("credential-variant".into());
            (message, stream)
        };
        let before = calls.lock().await.len();
        if alias.is_some() {
            let (message, stream) = build_variant(&variant_body, &bearer);
            let response = Box::pin(super::process_forward_request_with_mcp_runtime(
                &message,
                Some(stream),
                versions,
                Some(runtime.clone()),
            ))
            .await;
            assert_eq!(decode(response).await.0, 401);
            assert_eq!(calls.lock().await.len(), before);
        }
        let (message, stream) = build_variant(&variant_body, &variant_bearer);
        let crate::mcp::request_validation::McpRequestClassification::Modern(mut original) =
            crate::mcp::request_validation::validate_mcp_post(
                &stream.headers,
                &stream.body,
                crate::mcp::request_validation::LegacySessionEvidence::Absent,
                versions,
            )
            .unwrap()
        else {
            panic!("expected admitted receiver variant fixture");
        };
        let response = Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(stream),
            versions,
            Some(runtime.clone()),
        ))
        .await;
        let (status, pending) = decode(response).await;
        assert_eq!(status, 200, "{pending}");
        assert_eq!(pending["result"]["resultType"], "input_required");
        original.id = Some(json!(41));
        let binding = runtime
            .service
            .request_binding(
                pending["result"]["requestState"]
                    .as_str()
                    .unwrap(),
                &original,
                crate::proxy::credential_delegation::modern::now_secs().unwrap(),
            )
            .unwrap();
        assert_eq!(binding.variant_id.as_deref(), Some("credential-variant"));
        assert_eq!(binding.resource, resource);
        variant_body["id"] = json!(41);
        variant_body["params"]["requestState"] = pending["result"]["requestState"].clone();
        variant_body["params"]["inputResponses"] = json!({"remote-input": {"action": "accept"}});
        let (message, stream) = build_variant(&variant_body, &variant_bearer);
        let response = Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(stream),
            versions,
            Some(runtime.clone()),
        ))
        .await;
        let (status, complete) = decode(response).await;
        assert_eq!(status, 200, "{complete}");
        assert_eq!(complete["result"]["resultType"], "complete");
        assert_eq!(calls.lock().await.len(), before + 2);
    }
    use futures::StreamExt;
    let (subscriptions_tx, mut subscriptions_rx) = tokio::sync::mpsc::channel(2);
    let subscription_target = axum::Router::new().fallback(axum::routing::post(
        move |headers: HeaderMap, axum::Json(request): axum::Json<Value>| {
            let subscriptions = subscriptions_tx.clone();
            async move {
                let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(2);
                let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
                let ack = json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": {
                    "_meta": {"io.modelcontextprotocol/subscriptionId": request["id"]},
                    "notifications": request["params"]["notifications"]
                }});
                sender
                    .send(Ok(bytes::Bytes::from(format!("data: {ack}\n\n"))))
                    .await
                    .unwrap();
                subscriptions
                    .send((headers, request, sender, outcome_rx))
                    .await
                    .unwrap();
                let response = axum::response::Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver)))
                    .unwrap();
                crate::mcp::modern_sse::observe_response(response, move |outcome| {
                    let _ = outcome_tx.send(outcome);
                })
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let subscription_address = listener.local_addr().unwrap();
    tasks.spawn(async move {
        axum::serve(listener, subscription_target)
            .await
            .unwrap();
    });
    surface.target.endpoint = format!("http://{subscription_address}/mcp");
    let subscription = json!({"jsonrpc": "2.0", "id": "receiver-subscription", "method": "subscriptions/listen", "params": {
        "notifications": {"toolsListChanged": true}, "_meta": body["params"]["_meta"]
    }});
    let make_subscription = |token: &str| {
        let (mut message, mut stream) = make_request(&subscription, &surface, &sender_did, token);
        stream.headers.insert(
            "mcp-method",
            "subscriptions/listen"
                .parse()
                .unwrap(),
        );
        stream
            .headers
            .remove("mcp-name");
        stream.headers.insert(
            "mcp-session-id",
            "unused-subscription-session"
                .parse()
                .unwrap(),
        );
        message.message_body["headers"]["mcp-method"] = json!("subscriptions/listen");
        message.message_body["headers"]
            .as_object_mut()
            .unwrap()
            .remove("mcp-name");
        (message, stream)
    };
    for invalid in ["missing", "audience", "scope", "expired"] {
        let claims = json!({"iss": "https://receiver.example/api/oauth2/mcp", "sub": "user",
            "aud": if invalid == "audience" { "https://ingress.example/mcp" } else { "https://receiver.example/mcp" },
            "scope": if invalid == "scope" { "write" } else { "read" },
            "exp": if invalid == "expired" { now - 1 } else { now + 300 }
        });
        let token = receiver
            .sign_jwt_with_gateway_key_typ(&claims, "at+jwt")
            .await
            .unwrap();
        let (mut message, mut stream) = make_subscription(&token);
        if invalid == "missing" {
            stream
                .headers
                .remove("authorization");
            message.message_body["headers"]
                .as_object_mut()
                .unwrap()
                .remove("authorization");
        }
        let response = Box::pin(super::process_forward_request_with_mcp_runtime(
            &message,
            Some(stream),
            versions,
            Some(runtime.clone()),
        ))
        .await;
        let (status, _) = decode(response).await;
        assert_eq!(
            status,
            if invalid == "scope" {
                403
            } else {
                401
            },
            "{invalid}"
        );
        assert!(
            subscriptions_rx
                .try_recv()
                .is_err(),
            "invalid {invalid} reached the receiver Target"
        );
    }
    let (message, stream) = make_subscription(&bearer);
    let result = Box::pin(super::process_forward_request_with_mcp_runtime(
        &message,
        Some(stream),
        versions,
        Some(runtime.clone()),
    ))
    .await;
    let ProcessingResult::StreamingResponse { response } = result else {
        panic!("expected authorized receiver subscription: {result:?}");
    };
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        !response
            .headers()
            .contains_key("mcp-session-id")
    );
    let (headers, request, sender, outcome) = subscriptions_rx
        .recv()
        .await
        .unwrap();
    assert_eq!(headers["authorization"], "Bearer verified-remote-credential");
    assert!(!headers.contains_key("mcp-session-id"));
    assert_eq!(request["id"], subscription["id"]);
    assert_eq!(request["method"], "subscriptions/listen");
    let limits = crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
    let mut events = Box::pin(crate::mcp::modern_sse::decode_events(
        response
            .into_body()
            .into_data_stream(),
        limits,
    ));
    let ack = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ack: Value = serde_json::from_str(&ack.data).unwrap();
    assert_eq!(ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], subscription["id"]);
    assert_eq!(ack["params"]["notifications"], json!({"toolsListChanged": true}));
    let active = vault
        .list_all()
        .await
        .unwrap()
        .into_iter()
        .find(|token| token.provider_id == "provider")
        .unwrap();
    assert!(futures::poll!(events.next()).is_pending());
    assert!(!sender.is_closed());
    assert!(
        vault
            .delete(&active.id)
            .await
            .unwrap()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), events.next())
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    drop(events);
    assert!(
        !tokio::time::timeout(Duration::from_secs(2), outcome)
            .await
            .unwrap()
            .unwrap()
            .completed
    );
    assert!(sender.is_closed());
    let (message, stream) = make_subscription(&bearer);
    let response = Box::pin(super::process_forward_request_with_mcp_runtime(
        &message,
        Some(stream),
        versions,
        Some(runtime.clone()),
    ))
    .await;
    assert_eq!(decode(response).await.0, 403);
    assert!(
        subscriptions_rx
            .try_recv()
            .is_err(),
        "revoked consent reached the receiver Target"
    );
    tasks.shutdown().await;
}

#[test]
fn fabric_policies_see_the_same_mcp_input_as_direct() {
    if std::env::var_os("ATG_FABRIC_POLICY_INPUT_CHILD").is_none() {
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env("ATG_FABRIC_POLICY_INPUT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated Fabric policy input test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(Box::pin(fabric_policy_input_flow()));
}

/// A legacy request on Fabric receive gives the gateway and surface policies
/// the same `input.mcp` the direct path builds from the same body.
async fn fabric_policy_input_flow() {
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": "call", "result": {"content": []}}).to_string())
            .await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap();
    let surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "fabric-policy-input", "name": "Fabric policy input",
        "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": format!("http://{}", target.addr), "policy": {"policy_definition_id": "mcp-input"}}
    }))
    .unwrap();
    store
        .save(&surface)
        .await
        .unwrap();
    let policies = std::sync::Arc::new(crate::policies::SurfacePolicyManager::new());
    policies
        .load_policy_text(
            &surface.surface_id,
            r#"package surface.policy

default allow := false

allow if {
    input.mcp.method == "tools/call"
    input.mcp.tool_name == "echo"
    input.mcp.params.arguments.value == 1
}
"#,
        )
        .unwrap();
    super::init_policy_manager(policies).await;
    // The appliance-wide gateway policy reads `input.mcp` too, so the allowed
    // request passes only if the gateway policy seam also sees it.
    let definitions = std::sync::Arc::new(
        crate::policies::FileSystemPolicyDefinitionStore::new(
            temp_dir
                .path()
                .join("policy_definitions")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap(),
    );
    definitions
        .save(crate::policies::policy_definitions::PolicyDefinition {
            id: "gateway-mcp-input".into(),
            tenant_id: None,
            name: "gateway-mcp-input".into(),
            description: String::new(),
            policy_type: crate::policies::policy_definitions::PolicyType::Gateway,
            policy: r#"package gateway.policy

default allow := false

allow if {
    input.mcp.method == "tools/call"
    input.mcp.tool_name == "echo"
}
"#
            .into(),
            enabled: true,
            created_at: "2026-09-29T00:00:00Z".into(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
        })
        .await
        .unwrap();
    let appliance = std::sync::Arc::new(crate::policies::GlobalPolicyManager::new());
    appliance.set_policy_definition_store(definitions);
    let mut assignments = crate::policies::GlobalPolicyAssignments::default();
    assignments
        .assignments
        .insert(
            crate::policies::global_policy::PLANE_GATEWAY.to_string(),
            vec![crate::policies::global_policy::GlobalAssignment {
                policy_id: "gateway-mcp-input".into(),
                monitor_only: false,
            }],
        );
    appliance
        .refresh(&assignments)
        .await;
    assert!(appliance.has_global(crate::policies::global_policy::PLANE_GATEWAY));
    super::init_appliance_policy_manager(appliance).await;

    let now_secs = super::super::envelope_replay::now_secs();
    let message = |body: &Value| {
        ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(now_secs + 60),
            json!({"channel_id": surface.surface_id, "method": "POST", "path": "/mcp", "headers": {}, "body": body}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path))
    };

    let allowed = json!({"jsonrpc": "2.0", "id": "call", "method": "tools/call",
        "params": {"name": "echo", "arguments": {"value": 1}}});
    let direct = crate::mcp::build_mcp_context(&serde_json::to_vec(&allowed).unwrap()).expect("direct input.mcp");
    assert_eq!(direct.tool_name.as_deref(), Some("echo"));
    let (response, _) = receive(&message(&allowed)).await;
    assert_eq!(response["status"], 200, "the policy saw input.mcp: {response}");
    // Surface OPA also fetches the Target's agent card, so compare the last
    // request rather than counting them.
    let last_body = || {
        target
            .last_request_rx
            .borrow()
            .clone()
            .and_then(|request| serde_json::from_str::<Value>(&request.body).ok())
    };
    assert_eq!(last_body(), Some(allowed.clone()), "the allowed call reached the Target");

    let denied = json!({"jsonrpc": "2.0", "id": "call", "method": "tools/call",
        "params": {"name": "echo", "arguments": {"value": 2}}});
    let result = tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(&message(&denied))))
        .await
        .expect("Fabric receive handler timed out");
    let ProcessingResult::RequiresResponse { response_body, .. } = result else {
        panic!("expected a ForwardResponse, got {result:?}");
    };
    assert!(
        response_body["body"]
            .as_str()
            .is_some_and(|body| body.contains("error")),
        "a request the policy rejects is refused: {response_body}"
    );
    assert_ne!(last_body(), Some(denied), "a request the policy rejects never reaches the Target");
}
