use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};

use super::{ProcessingResult, build_fabric_gating_input, process_forward_request};
use crate::component_tests::helpers::MockServer;
use crate::config::agent_surface::AgentSurface;
use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
use crate::gateways::test_helpers::install_listener_manager_with_peers;
use crate::gateways::types::{ExposureMode, Gateway, GatewayType};
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
    peer.exposure_mode = Some(ExposureMode::All);
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

/// A child process started to isolate globals runs one test; one that matched
/// no test would also exit successfully.
fn assert_ran_exactly_one_test(output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test result: ok. 1 passed;"),
        "the isolated child did not run exactly one test:\n{stdout}"
    );
}

#[test]
fn fabric_policy_context_matches_direct_admission_without_changing_legacy_shape() {
    use crate::mcp::request_validation::{LegacySessionEvidence, validate_mcp_post};
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
        crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
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
    use crate::mcp::request_validation::{LegacySessionEvidence, McpRequestClassification, validate_mcp_post};
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
        crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
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
    use crate::mcp::request_validation::{LegacySessionEvidence, McpRequestClassification, validate_mcp_post};

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
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
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
        assert_ran_exactly_one_test(&output);
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
    let mut sender =
        Gateway::new("Sender".to_string(), String::new(), "did:web:sender.example".to_string(), GatewayType::Remote);
    sender.exposure_mode = Some(ExposureMode::All);
    gateway_store
        .create(&sender)
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
                json!({"requested": MCP_MODERN_VERSION, "supported": crate::mcp::request_validation::SESSION_VERSIONS})
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
        "protocolVersion": "2099-01-01", "capabilities": {}, "clientInfo": {"name": "client", "version": "1"}
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

    // A session revision the receiver serves reaches the Target unchanged, so
    // the Target negotiates it.
    let session_initialize = json!({"jsonrpc": "2.0", "id": "session-initialize", "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "client", "version": "1"}
    }});
    let (forward_response, _) = receive(&forward_message(
        session_initialize.clone(),
        json!({"MCP-Protocol-Version": "2025-06-18", "Mcp-Method": "initialize"}),
    ))
    .await;
    assert_eq!(forward_response["status"], 200);
    let forwarded = target
        .last_request_rx
        .borrow()
        .clone()
        .expect("initialize reached the Target");
    assert_eq!(serde_json::from_str::<Value>(&forwarded.body).unwrap(), session_initialize);
    assert_eq!(
        forwarded
            .headers
            .get("mcp-protocol-version")
            .map(String::as_str),
        Some("2025-06-18")
    );

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
            index + 4
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
    use crate::audit::request_events::RejectionReason;
    for (body, headers, expected_status, expected_refusal) in [
        (
            legacy_body.clone(),
            json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION, "origin": "https://untrusted.example", "Origin": "https://untrusted.example"}),
            200,
            None,
        ),
        (json!(" ".repeat(1025)), json!({}), 413, Some(RejectionReason::BodyTooLarge)),
        (legacy_body.clone(), json!({"x-extra": "x".repeat(513)}), 431, Some(RejectionReason::McpAdmission)),
        (
            legacy_body.clone(),
            json!({"Origin": format!("https://{}.example", "a".repeat(500))}),
            431,
            Some(RejectionReason::McpAdmission),
        ),
    ] {
        let ((response, _), audit) = crate::audit::producer::capture(receive(&forward_message(body, headers))).await;
        assert_eq!(response["status"], expected_status);
        let refusals: Vec<_> = audit
            .iter()
            .filter_map(|event| match event.event {
                crate::delegation_vault::audit::DelegationAuditAction::RequestRejected {
                    reason, http_status, ..
                } => {
                    assert!(event.via_fabric, "a Fabric receive refusal is marked as such");
                    Some((reason, http_status))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            refusals,
            expected_refusal
                .map(|reason| (reason, None))
                .into_iter()
                .collect::<Vec<_>>(),
            "recorded refusals for a {expected_status}, with no HTTP status on Fabric"
        );
    }
    let mut unknown_surface = forward_message(legacy_body, json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION}));
    unknown_surface.message_body["channel_id"] = json!("no-such-surface");
    let (response, audit) = crate::audit::producer::capture(refused(&unknown_surface)).await;
    assert_eq!(response["status"], 404);
    let unroutable = audit
        .iter()
        .find(|event| {
            matches!(
                event.event,
                crate::delegation_vault::audit::DelegationAuditAction::RequestRejected {
                    reason: RejectionReason::NoRoute,
                    ..
                }
            )
        })
        .unwrap_or_else(|| panic!("an unknown surface is recorded as unroutable: {audit:?}"));
    assert_eq!(
        unroutable
            .surface_id
            .as_deref(),
        Some(crate::audit::request_events::UNKNOWN_SURFACE)
    );
    assert!(unroutable.via_fabric);
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
    // Fabric carries the method as a string: it is uppercased, and one that is
    // not an HTTP token is an extension method. PUT, PATCH and extension
    // methods get 405 with `Allow`, and a body on any other method gets 400.
    let forwarded_before = target
        .request_count
        .load(Ordering::SeqCst);
    for (method, body, status) in [
        ("PUT", Value::Null, 405),
        ("put", Value::Null, 405),
        ("PATCH", Value::Null, 405),
        ("BAD METHOD", Value::Null, 405),
        ("GET", json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), 400),
        ("delete", json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), 400),
    ] {
        let mut message = forward_message(body, json!({}));
        message.message_body["method"] = json!(method);
        let ProcessingResult::RequiresResponse { response_body, .. } = process_forward_request(&message).await else {
            panic!("expected a Fabric method rejection for {method}");
        };
        assert_eq!(response_body["status"], status, "{method}: {response_body}");
        if status == 405 {
            assert_eq!(response_body["headers"]["allow"], "POST, GET, DELETE, HEAD, OPTIONS", "{method}");
        } else {
            let envelope: Value = serde_json::from_str(
                response_body["body"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(envelope["error"]["code"], -32600, "{method}");
        }
    }
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        forwarded_before,
        "no refused method reaches the Target"
    );
    for (forwarded, method) in [(1, "GET"), (2, "delete")] {
        let mut message = forward_message(Value::Null, json!({}));
        message.message_body["method"] = json!(method);
        process_forward_request(&message).await;
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            forwarded_before + forwarded,
            "an unmarked {method} without a body is forwarded"
        );
    }
    let mut oversized_origin =
        forward_message(Value::Null, json!({"Origin": format!("https://{}.example", "a".repeat(500))}));
    oversized_origin.message_body["method"] = json!("GET");
    let (response, _) = receive(&oversized_origin).await;
    assert_eq!(response["status"], 431);
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
    let (denied, audit) = crate::audit::producer::capture(process_forward_request(&forward_message(
        json!({"jsonrpc": "2.0", "id": "protected", "method": "tools/list"}),
        json!({"Authorization": "Bearer cannot-establish-receiver-authority"}),
    )))
    .await;
    let ProcessingResult::RequiresResponse { response_body, .. } = denied else {
        panic!("protected Fabric request must fail closed without resource authorization context");
    };
    assert_eq!(response_body["status"], 503);
    assert!(
        audit
            .iter()
            .any(|event| event.via_fabric
                && matches!(
                    &event.event,
                    crate::delegation_vault::audit::DelegationAuditAction::AuthFailed {
                        scheme: crate::audit::events::AuthScheme::McpResourceToken,
                        reason,
                        blocking: true,
                        client_ip: None,
                    } if reason == "unavailable"
                )),
        "the refused resource token is audited: {audit:?}"
    );
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
                variant: crate::config::agent_surface_variants::ForwardedVariant {
                    id: None,
                    recorded: "_base_".into(),
                },
                capabilities: crate::proxy::fabric_stream::peer::StreamCapabilities::local(true, true),
                scope: crate::observability::policy_audit::RequestScope::fresh(),
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
    // Includes the capped and the session-revision initialize, the one
    // envelope-replay delivery, the legacy request whose forwarded Origin is
    // not rechecked, and the unmarked GET and DELETE without a body.
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        9
    );

    let mut guarded = surface.clone();
    guarded
        .access_point
        .caller_authentication = Some(
        serde_json::from_value(json!({"methods": [{
            "type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": []
        }]}))
        .unwrap(),
    );
    store
        .save(&guarded)
        .await
        .unwrap();
    let before = target
        .request_count
        .load(Ordering::SeqCst);
    let unauthenticated = forward_message(
        json!({"jsonrpc": "2.0", "id": "unauthenticated", "method": "tools/list"}),
        json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION}),
    );
    let response = refused(&unauthenticated).await;
    assert_eq!(response["status"], 500, "source auth unavailable must block: {response}");
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        before,
        "a request blocked by source auth must not reach the Target"
    );
}

/// The status and JSON-RPC body of a Fabric receive's answer, buffered or streamed.
async fn decode(result: ProcessingResult) -> (u16, Value) {
    use futures::TryStreamExt;

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
        assert_ran_exactly_one_test(&output);
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
            display_name: None,
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
                variant: crate::config::agent_surface_variants::ForwardedVariant {
                    id: None,
                    recorded: "_base_".into(),
                },
                capabilities: crate::proxy::fabric_stream::peer::StreamCapabilities::local(true, true),
                scope: crate::observability::policy_audit::RequestScope::fresh(),
            },
        )
    };
    let versions = crate::mcp::request_validation::MODERN_CAPABLE_POLICY;
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
    {
        let send = |body: Value, token: Option<String>, runtime: Arc<ContinuationRuntime>| {
            let token = token.unwrap_or_else(|| bearer.clone());
            let (message, stream) = make_request(&body, &surface, &sender_did, &token);
            async move {
                let (status, body) = decode(
                    Box::pin(super::process_forward_request_with_mcp_runtime(
                        &message,
                        Some(stream),
                        versions,
                        Some(runtime),
                    ))
                    .await,
                )
                .await;
                (axum::http::StatusCode::from_u16(status).unwrap(), body)
            }
        };
        let other = receiver
            .sign_jwt_with_gateway_key_typ(
                &json!({"iss": "https://receiver.example/api/oauth2/mcp", "sub": "other-user", "scope": "read",
                    "aud": "https://receiver.example/mcp", "exp": now + 300}),
                "at+jwt",
            )
            .await
            .unwrap();
        crate::mcp::continuations::negative_cases::assert_rejected_retries(&body, runtime.clone(), other, now, send)
            .await;
        assert!(calls.lock().await.is_empty(), "no negative case reaches the upstream");
    }

    vault.store(serde_json::from_value(json!({
        "id": "verified-token", "agent_did": holder_did,
        "user_identity_hash": crate::source_auth::models::caller_identity_hash(
            "jwt_bearer", "https://receiver.example/api/oauth2/mcp", surface.tenant_id.as_deref(), "user"),
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
    surface.target.endpoint = format!("http://{target_address}/json");
    surface.target.payment_policy =
        Some(serde_json::from_value(json!({"type": "x402", "mcp_payment_triggers": {"mode": "all"}})).unwrap());
    body["id"] = json!(20);
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
    assert_eq!(response, (503, json!({"error": "payment_unavailable"})));
    assert_eq!(calls.lock().await.len(), before, "a local payment surface never reaches the Target");
    {
        use crate::proxy::handler::agent_pay_gate::{install_test_transport, tests::MockGate};

        fn receipt_header(result: &ProcessingResult) -> Option<String> {
            match result {
                ProcessingResult::StreamingResponse { response } => response
                    .headers()
                    .get("payment-response")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                ProcessingResult::RequiresResponse { response_body, .. } => {
                    response_body["headers"]["payment-response"]
                        .as_str()
                        .map(str::to_string)
                }
                _ => None,
            }
        }

        let gate = MockGate::answering(200, &[("Payment-Receipt", "consent-flow-receipt")], json!({}))
            .challenging(&[("payment-required", "eyJ4IjoxfQ==")], json!({"accepts": []}));
        install_test_transport("consent-flow-gate", gate.clone());
        surface.target.payment_policy = Some(
            serde_json::from_value(json!({
                "type": "agent_pay", "payment_gateway_id": "consent-flow-gate", "payment_surface_id": "pay-1",
                "mcp_payment_triggers": {"mode": "all"}
            }))
            .unwrap(),
        );
        let request = |body: &Value, surface: &AgentSurface, signature: Option<&str>| {
            let (mut message, mut stream) = make_request(body, surface, &sender_did, &bearer);
            if let Some(signature) = signature {
                stream
                    .headers
                    .insert("payment-signature", signature.parse().unwrap());
                message.message_body["headers"]["PAYMENT-SIGNATURE"] = json!(signature);
            }
            (message, stream)
        };
        let fresh = |body: &mut Value, id: u64| {
            body["id"] = json!(id);
            for field in ["requestState", "inputResponses"] {
                body["params"]
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
            }
        };

        for format in ["json", "sse"] {
            surface.target.endpoint = format!("http://{target_address}/{format}");
            fresh(&mut body, 30);
            let signature = format!("consent-flow-{format}");
            let (hops, forwarded) = (gate.calls(), calls.lock().await.len());
            let (message, stream) = request(&body, &surface, Some(&signature));
            let paid = Box::pin(super::process_forward_request_with_mcp_runtime(
                &message,
                Some(stream),
                versions,
                Some(runtime.clone()),
            ))
            .await;
            assert_eq!(receipt_header(&paid).as_deref(), Some("consent-flow-receipt"), "{format}");
            let (status, paid) = decode(paid).await;
            assert_eq!(status, 200, "{format}: {paid}");
            assert_eq!(paid["result"]["resultType"], "input_required", "{format}");
            assert_ne!(paid["result"]["requestState"], "remote opaque state", "{format}");
            assert_eq!(gate.calls(), hops + 1, "{format}: the first round is charged once");
            assert_eq!(gate.last().headers["PAYMENT-SIGNATURE"], signature);

            body["id"] = json!(31);
            body["params"]["requestState"] = paid["result"]["requestState"].clone();
            body["params"]["inputResponses"] = json!({"remote-input": {"action": "accept"}});
            let (message, stream) = request(&body, &surface, None);
            let continued = Box::pin(super::process_forward_request_with_mcp_runtime(
                &message,
                Some(stream),
                versions,
                Some(runtime.clone()),
            ))
            .await;
            assert_eq!(
                receipt_header(&continued).as_deref(),
                Some("consent-flow-receipt"),
                "{format}: the continuation carries the receipt it already holds"
            );
            let (status, continued) = decode(continued).await;
            assert_eq!(status, 200, "{format}: {continued}");
            assert_eq!(continued["result"]["resultType"], "complete", "{format}");
            assert_eq!(continued["result"]["_meta"]["org.paymentauth/receipt"], "consent-flow-receipt", "{format}");
            assert_eq!(gate.calls(), hops + 1, "{format}: a continuation round is not charged again");
            {
                let observed = calls.lock().await;
                assert_eq!(observed.len(), forwarded + 2, "{format}");
                for (headers, upstream) in &observed[forwarded..] {
                    assert_eq!(headers["authorization"], "Bearer verified-remote-credential");
                    assert!(!headers.contains_key("payment-signature"), "{format}: {headers:?}");
                    assert!(
                        upstream["params"]["arguments"]
                            .get("payment_signature")
                            .is_none()
                    );
                }
                assert_eq!(observed[forwarded + 1].1["params"]["requestState"], "remote opaque state");
            }

            body["id"] = json!(32);
            let (message, stream) = request(&body, &surface, None);
            let replayed = decode(
                Box::pin(super::process_forward_request_with_mcp_runtime(
                    &message,
                    Some(stream),
                    versions,
                    Some(runtime.clone()),
                ))
                .await,
            )
            .await;
            assert_eq!(replayed.0, 409, "{format}: {:?}", replayed.1);
            assert_eq!(gate.calls(), hops + 1, "{format}: a replayed continuation is not charged");
            assert_eq!(calls.lock().await.len(), forwarded + 2, "{format}: nor forwarded");
        }

        surface.target.endpoint = format!("http://{target_address}/json");
        fresh(&mut body, 40);
        let (hops, forwarded) = (gate.calls(), calls.lock().await.len());
        let (first_message, first_stream) = request(&body, &surface, Some("racing-consent-flow"));
        let (second_message, second_stream) = request(&body, &surface, Some("racing-consent-flow"));
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
        let (first, second) = (decode(first).await, decode(second).await);
        let (paid, refused) = match (first.0, second.0) {
            (200, 402) => (first, second),
            (402, 200) => (second, first),
            other => panic!("one payment pays for one call: {other:?}; {first:?}; {second:?}"),
        };
        assert_eq!(paid.1["result"]["resultType"], "input_required");
        assert_eq!(refused.1["error"]["code"], 1002, "{:?}", refused.1);
        assert_eq!(refused.1["error"]["data"]["failure"]["reason"], "payment_already_used");
        assert_eq!(calls.lock().await.len(), forwarded + 1, "the credential reaches the Target once");
        assert_eq!(gate.calls(), hops + 3, "two payments, and the fresh challenge for the replayed one");

        let (message, stream) = request(&body, &surface, Some("continuation-consent-flow"));
        let paid = decode(
            Box::pin(super::process_forward_request_with_mcp_runtime(
                &message,
                Some(stream),
                versions,
                Some(runtime.clone()),
            ))
            .await,
        )
        .await;
        assert_eq!(paid.0, 200, "{:?}", paid.1);
        body["id"] = json!(41);
        body["params"]["requestState"] = paid.1["result"]["requestState"].clone();
        body["params"]["inputResponses"] = json!({"remote-input": {"action": "accept"}});
        let (hops, forwarded) = (gate.calls(), calls.lock().await.len());
        let (first_message, first_stream) = request(&body, &surface, None);
        let (second_message, second_stream) = request(&body, &surface, None);
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
        let (first, second) = (decode(first).await, decode(second).await);
        assert!(matches!((first.0, second.0), (200, 409) | (409, 200)), "{first:?}; {second:?}");
        assert_eq!(gate.calls(), hops, "neither continuation round reaches agent-pay");
        assert_eq!(calls.lock().await.len(), forwarded + 1, "the continuation is forwarded once");
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
            stream.variant = crate::config::agent_surface_variants::ForwardedVariant {
                id: Some("credential-variant".into()),
                recorded: "candidate".into(),
            };
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
        assert_ran_exactly_one_test(&output);
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
    let credential_policies = policies.clone();
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

    // A payment credential in a tool argument or `_meta` is not in what the
    // gateway and surface policies read.
    use crate::proxy::handler::agent_pay_gate::{install_test_transport, tests::MockGate};
    let gate = MockGate::answering(200, &[("Payment-Receipt", "policy-receipt")], json!({}));
    install_test_transport("fabric-credential-gate", gate.clone());
    let paying: AgentSurface = serde_json::from_value(json!({
        "surface_id": "fabric-credential-policy", "name": "Fabric credential policy",
        "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": format!("http://{}", target.addr), "policy": {"policy_definition_id": "mcp-input"},
            "payment_policy": {"type": "agent_pay", "payment_gateway_id": "fabric-credential-gate",
                "payment_surface_id": "pay-1", "mcp_payment_triggers": {"mode": "all"}}}
    }))
    .unwrap();
    store
        .save(&paying)
        .await
        .unwrap();
    credential_policies
        .load_policy_text(
            &paying.surface_id,
            r#"package surface.policy

default allow := false

allow if {
    input.mcp.tool_name == "echo"
    not contains(json.marshal(input), "FABRIC-SECRET")
}
"#,
        )
        .unwrap();
    let with_credential = json!({"jsonrpc": "2.0", "id": "call", "method": "tools/call",
        "params": {"name": "echo", "arguments": {"value": 1, "payment_signature": "FABRIC-SECRET"},
            "_meta": {"org.paymentauth/credential": "FABRIC-SECRET"}}});
    let mut paying_message = message(&with_credential);
    paying_message.message_body["channel_id"] = json!(paying.surface_id);
    let result = tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(&paying_message)))
        .await
        .expect("Fabric receive handler timed out");
    let ProcessingResult::RequiresResponse { response_body, .. } = result else {
        panic!("expected a ForwardResponse, got {result:?}");
    };
    assert_eq!(response_body["status"], 200, "the policies read the call without its credential: {response_body}");
    assert_eq!(gate.calls(), 1, "the credential was still the one paid with");
    assert_eq!(gate.last().headers["PAYMENT-SIGNATURE"], "FABRIC-SECRET");
    let received = target
        .last_request_rx
        .borrow()
        .clone()
        .unwrap();
    assert!(
        !received
            .body
            .contains("FABRIC-SECRET"),
        "the Target received a credential: {}",
        received.body
    );
}

/// Runs `flow` in a test process of its own. Fabric receive reads process-wide
/// stores (surfaces, source auth) that the first gateway booted in a process
/// owns, so a flow that installs its own would otherwise see another test's.
fn run_in_own_process<F: std::future::Future<Output = ()>>(flow: impl FnOnce() -> F) {
    if std::env::var_os("ATG_FABRIC_ISOLATED_CHILD").is_none() {
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env("ATG_FABRIC_ISOLATED_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated Fabric test {test_name} failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(Box::pin(flow()));
}

#[test]
fn fabric_receive_binds_tokens_to_the_routes_protected_resource() {
    run_in_own_process(fabric_discovery_flow);
}

/// An MCP Access Point that publishes protected resource metadata binds a
/// Fabric request's token to the resource of the route called, as on the
/// direct path. The sending gateway strips the caller's own token, so the
/// `Authorization` here stands for a credential the sender injects: a missing
/// one, or one issued for another resource or variant, gets a 401 before
/// policy without `resource_metadata`, and only one for the route's resource
/// reaches the Target. A named alias that does not resolve is refused before
/// any token is read, never served by the default.
async fn fabric_discovery_flow() {
    use std::sync::Arc;

    use crate::component_tests::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
    use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};

    let fixture = JwksFixture::start().await;
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": "call", "result": {"tools": []}}).to_string())
            .await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let strategies = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            temp_dir
                .path()
                .join("strategies"),
        )
        .await
        .unwrap(),
    );
    let strategy = strategies
        .create(
            serde_json::from_value(json!({
                "id": "idp", "name": "IdP", "expected_issuer": fixture.issuer,
                "jwks_source": {"type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer)},
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "fabric-discovery", "name": "Fabric discovery",
        "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp",
            "caller_authentication": {
                "methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": strategy.id, "audiences": []}],
                "protected_resource": {"resource": "https://gateway.example/mcp",
                    "authorization_servers": [crate::protocols::protected_resource::fixtures::ISSUER]}
            }},
        "target": {"endpoint": format!("http://{}", target.addr)},
        "variants": [{"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {}}]
    }))
    .unwrap();
    FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap()
        .save(&surface)
        .await
        .unwrap();
    super::init_mcp_auth_network(Arc::new(crate::protocols::protected_resource::fixtures::discovery_network()));
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

    let token_for = |audience: &str| {
        sign_jwt(
            json!({"iss": fixture.issuer, "sub": "user-123", "aud": audience, "exp": now_secs() + 300}),
            &fixture.kid,
        )
    };
    let now = super::super::envelope_replay::now_secs();
    let send = |alias: Option<&str>, token: Option<String>| {
        let mut headers = json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION});
        if let Some(token) = token {
            headers["authorization"] = json!(format!("Bearer {token}"));
        }
        let mut body = json!({"channel_id": surface.surface_id, "method": "POST", "path": "/mcp", "headers": headers,
            "body": {"jsonrpc": "2.0", "id": "call", "method": "tools/list"}});
        if let Some(alias) = alias {
            body["virtual_channel_alias"] = json!(alias);
        }
        let message = ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(now + 60),
            body,
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path));
        async move {
            let result = tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(&message)))
                .await
                .expect("Fabric receive handler timed out");
            let ProcessingResult::RequiresResponse { response_body, .. } = result else {
                panic!("expected a ForwardResponse, got {result:?}");
            };
            response_body
        }
    };
    let reached = || {
        target
            .request_count
            .load(Ordering::SeqCst)
    };

    for (alias, token, invalid_token) in [
        (None, None, false),
        (None, Some(token_for("https://gateway.example/other")), true),
        (None, Some(token_for("https://gateway.example/mcp$beta")), true),
        (Some("beta"), Some(token_for("https://gateway.example/mcp")), true),
    ] {
        let response = send(alias, token).await;
        assert_eq!(response["status"], 401, "{response}");
        let challenge = response["headers"]["www-authenticate"]
            .as_str()
            .unwrap_or_default();
        assert!(challenge.starts_with("Bearer realm=\"agent-gateway\""), "{response}");
        assert!(!challenge.contains("resource_metadata"), "{response}");
        assert_eq!(challenge.contains("error=\"invalid_token\""), invalid_token, "{response}");
        assert_eq!(reached(), 0, "a refused token never reaches the Target");
    }

    for (alias, audience) in [(None, "https://gateway.example/mcp"), (Some("beta"), "https://gateway.example/mcp$beta")]
    {
        let before = reached();
        let response = send(alias, Some(token_for(audience))).await;
        assert_eq!(response["status"], 200, "{response}");
        assert_eq!(reached(), before + 1, "a token for the route's own resource reaches the Target");
        let forwarded = target
            .last_request_rx
            .borrow()
            .clone()
            .unwrap();
        assert!(
            !forwarded
                .headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("authorization")),
            "the caller's token never reaches the Target"
        );
    }

    // A named alias that does not resolve is refused, whatever the token
    // names, and never reaches the Target.
    for audience in ["https://gateway.example/mcp", "https://gateway.example/mcp$ghost"] {
        let before = reached();
        let response = send(Some("ghost"), Some(token_for(audience))).await;
        assert_eq!(response["status"], 404, "{response}");
        assert_eq!(reached(), before, "an unresolved alias never reaches the Target");
    }
}

#[test]
fn fabric_receive_refuses_a_failed_caller_on_a_closed_access_point() {
    run_in_own_process(closed_access_point_fabric_flow);
}

/// A closed Access Point refuses a Fabric caller without a valid credential
/// before policy and the Target, in the caller's protocol shape, while a
/// surface stored without `on_failure` still forwards it. A closed Access
/// Point stored without caller authentication is not ready and refuses every
/// caller with `503`.
async fn closed_access_point_fabric_flow() {
    use std::sync::Arc;

    use crate::component_tests::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
    use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};

    let fixture = JwksFixture::start().await;
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": "call", "result": {"tools": []}}).to_string())
            .await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let strategies = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            temp_dir
                .path()
                .join("strategies"),
        )
        .await
        .unwrap(),
    );
    let strategy = strategies
        .create(
            serde_json::from_value(json!({
                "id": "closed-idp", "name": "IdP", "expected_issuer": fixture.issuer,
                "jwks_source": {"type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer)},
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap();
    let surface = |id: &str, protocol: &str, on_failure: Option<&str>| {
        let mut caller_authentication =
            json!({"methods": [{"type": "jwt_bearer", "jwt_verification_strategy_id": strategy.id, "audiences": []}]});
        if let Some(on_failure) = on_failure {
            caller_authentication["on_failure"] = json!(on_failure);
        }
        serde_json::from_value::<AgentSurface>(json!({
            "surface_id": id, "name": id,
            "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"), "protocol": protocol,
                "caller_authentication": caller_authentication},
            "target": {"endpoint": format!("http://{}", target.addr)}
        }))
        .unwrap()
    };
    let not_ready = |id: &str, protocol: &str| {
        serde_json::from_value::<AgentSurface>(json!({
            "surface_id": id, "name": id,
            "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"), "protocol": protocol,
                "public": false},
            "target": {"endpoint": format!("http://{}", target.addr)}
        }))
        .unwrap()
    };
    for stored in [
        surface("closed-mcp", "mcp", Some("reject")),
        surface("closed-a2a", "a2a", Some("reject")),
        surface("legacy-mcp", "mcp", None),
        not_ready("unready-mcp", "mcp"),
        not_ready("unready-a2a", "a2a"),
    ] {
        store
            .save(&stored)
            .await
            .unwrap();
    }
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

    let now = super::super::envelope_replay::now_secs();
    let send = |channel_id: &str, token: Option<String>| {
        let mut headers = json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION});
        if let Some(token) = token {
            headers["authorization"] = json!(format!("Bearer {token}"));
        }
        let message = ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(now + 60),
            json!({"channel_id": channel_id, "method": "POST", "path": format!("/{channel_id}"), "headers": headers,
                "body": {"jsonrpc": "2.0", "id": "call", "method": "tools/list"}}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path));
        async move {
            let result = tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(&message)))
                .await
                .expect("Fabric receive handler timed out");
            let ProcessingResult::RequiresResponse { response_body, .. } = result else {
                panic!("expected a ForwardResponse, got {result:?}");
            };
            response_body
        }
    };
    let reached = || {
        target
            .request_count
            .load(Ordering::SeqCst)
    };
    let foreign_token =
        sign_jwt(json!({"iss": "https://other.example", "sub": "user-1", "exp": now_secs() + 300}), &fixture.kid);
    let body = |response: &Value| -> Value {
        serde_json::from_str(
            response["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    };

    for token in [None, Some(foreign_token.clone())] {
        let refused = send("closed-mcp", token.clone()).await;
        assert_eq!(refused["status"], 401, "{refused}");
        assert_eq!(refused["headers"]["www-authenticate"], "Bearer realm=\"agent-gateway\"", "{refused}");
        assert_eq!(
            body(&refused),
            json!({"jsonrpc": "2.0", "id": "call", "error": {
                "code": crate::mcp::errors::error_codes::INTERNAL_ERROR,
                "message": crate::source_auth::errors::CALLER_CREDENTIAL_REFUSED
            }})
        );

        let refused = send("closed-a2a", token).await;
        assert_eq!(refused["status"], 401, "{refused}");
        assert_eq!(refused["headers"]["content-type"], "application/problem+json", "{refused}");
        assert_eq!(body(&refused)["detail"], crate::source_auth::errors::CALLER_CREDENTIAL_REFUSED);
        assert_eq!(reached(), 0, "a refused caller never reaches the Target");
    }

    let valid = sign_jwt(json!({"iss": fixture.issuer, "sub": "user-1", "exp": now_secs() + 300}), &fixture.kid);
    let admitted = send("closed-mcp", Some(valid)).await;
    assert_eq!(admitted["status"], 200, "{admitted}");
    assert_eq!(reached(), 1, "a valid caller reaches the Target");

    let forwarded = send("legacy-mcp", Some(foreign_token)).await;
    assert_eq!(forwarded["status"], 200, "{forwarded}");
    assert_eq!(reached(), 2, "a surface stored without on_failure forwards a failed caller to policy");

    let valid = sign_jwt(json!({"iss": fixture.issuer, "sub": "user-1", "exp": now_secs() + 300}), &fixture.kid);
    for token in [None, Some(valid)] {
        let refused = send("unready-mcp", token.clone()).await;
        assert_eq!(refused["status"], 503, "{refused}");
        assert_eq!(
            body(&refused),
            json!({"jsonrpc": "2.0", "id": "call", "error": {
                "code": crate::mcp::errors::error_codes::INTERNAL_ERROR,
                "message": crate::source_auth::errors::ACCESS_POINT_UNAVAILABLE
            }})
        );

        let refused = send("unready-a2a", token).await;
        assert_eq!(refused["status"], 503, "{refused}");
        assert_eq!(refused["headers"]["content-type"], "application/problem+json", "{refused}");
        assert_eq!(body(&refused)["detail"], crate::source_auth::errors::ACCESS_POINT_UNAVAILABLE);
        assert_eq!(reached(), 2, "a not-ready Access Point never reaches the Target");
    }
}

#[derive(Clone, Default)]
struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(
        &mut self,
        buf: &[u8],
    ) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn fabric_receive_logs_forwarded_header_names_without_values() {
    use tracing::instrument::WithSubscriber;

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
        assert_ran_exactly_one_test(&output);
        return;
    }

    let target_response = json!({"jsonrpc": "2.0", "id": "header-logs", "result": {"tools": []}});
    let target = MockServer::start_with_response(target_response.to_string()).await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap();
    let surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "fabric-header-logs",
        "name": "Fabric header logs",
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

    let credentials = [
        ("authorization", "Bearer delegated-access-token"),
        ("proxy-authorization", "Basic proxy-credential"),
        ("x-api-key", "api-key-credential"),
        ("x-upstream-auth", "custom-header-credential"),
    ];
    let mut headers = json!({
        "MCP-Protocol-Version": MCP_LEGACY_VERSION,
        "x-transit-token": "transit-credential",
        "cookie": "session=cookie-credential"
    });
    for (name, value) in credentials {
        headers[name] = json!(value);
    }
    let message = ReceivedMessage::new(
        "receiver-connection".to_string(),
        "receiver-gateway".to_string(),
        MessageType::ForwardRequest.to_string(),
        uuid::Uuid::new_v4().to_string(),
        None,
        Some(SENDER_CONNECTION_POINT_DID.to_string()),
        vec!["did:web:receiver.example".to_string()],
        None,
        Some(super::super::envelope_replay::now_secs() + 60),
        json!({
            "channel_id": surface.surface_id,
            "method": "POST",
            "path": "/mcp",
            "headers": headers,
            "body": {"jsonrpc": "2.0", "id": "header-logs", "method": "tools/list"}
        }),
        MessageMetadata {
            encrypted: true,
            authenticated: true,
            from_key: None,
            extra: Value::Null,
        },
    )
    .with_context("agent_surface_storage_path", json!(storage_path));

    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();
    let (forward_response, envelope) = receive(&message)
        .with_subscriber(subscriber)
        .await;
    assert_eq!(forward_response["status"], 200);
    assert_eq!(envelope, target_response);

    let forwarded = target
        .last_request_rx
        .borrow()
        .clone()
        .expect("request reached the Target");
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for (name, value) in credentials {
        assert_eq!(forwarded.headers[name], value, "{name} was not forwarded");
        assert!(logs.contains(&format!("Header: {name}\n")), "header name {name} was not logged:\n{logs}");
        assert!(!logs.contains(value), "credential value for {name} was logged:\n{logs}");
    }
    assert!(
        !forwarded
            .headers
            .contains_key("x-transit-token"),
        "a transit token the peer sent never reaches the Target"
    );
    assert!(!logs.contains("transit-credential"), "the peer's transit token was logged:\n{logs}");
    assert!(
        !forwarded
            .headers
            .contains_key("cookie"),
        "a cookie the peer sent never reaches the Target"
    );
    assert!(!logs.contains("cookie-credential"), "the peer's cookie was logged:\n{logs}");
}

#[test]
fn fabric_tool_call_batches_are_refused_before_tool_level_controls() {
    if std::env::var_os("ATG_FABRIC_TOOL_CALL_BATCH_CHILD").is_none() {
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env("ATG_FABRIC_TOOL_CALL_BATCH_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated Fabric tool-call batch test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_ran_exactly_one_test(&output);
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(Box::pin(fabric_tool_call_batch_flow()));
}

async fn fabric_tool_call_batch_flow() {
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 2, "result": {"content": []}}).to_string())
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
        "surface_id": "fabric-batch", "name": "fabric-batch",
        "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": format!("http://{}", target.addr), "mcp_tool_gating": {"gates": [{"id": "g1",
            "name": "no admin", "action": {"effect": "deny", "patterns": ["^admin_"]}}]}},
        "outbound_credentials": [{"credential_provider_id": "provider", "required_for": {"tools": ["scoped_tool"]}}]
    }))
    .unwrap();
    store
        .save(&surface)
        .await
        .unwrap();
    let policies = std::sync::Arc::new(crate::policies::SurfacePolicyManager::new());
    policies
        .update_channel_policy(&surface)
        .await
        .unwrap();
    super::init_policy_manager(policies).await;

    let now_secs = super::super::envelope_replay::now_secs();
    for tool in ["admin_reset", "scoped_tool"] {
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": {}}}
        ]);
        let message = ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(now_secs + 60),
            json!({"channel_id": surface.surface_id, "method": "POST", "path": "/mcp", "headers": {}, "body": batch}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path));

        let (response, body) = receive(&message).await;

        assert_eq!(response["status"], 422, "{tool}: {response}");
        assert_eq!(response["headers"]["content-type"], "application/problem+json", "{tool}");
        assert_eq!(
            body,
            json!({"type": "https://a2a-protocol.org/errors/proxy-error", "title": "Unprocessable Entity", "status": 422, "detail": "JSON-RPC batches are not supported"}),
            "{tool}"
        );
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            0,
            "{tool}"
        );
    }

    // A field the gateway reads, spelled in another case, is refused at
    // admission: a case-folding Target would read it as the method or tool.
    // A `tools/call` with no readable tool name is denied by the gate.
    for (body, code) in [
        (json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"Name": "admin_reset"}}), -32600),
        (json!({"jsonrpc": "2.0", "id": 4, "Method": "tools/call", "params": {"name": "admin_reset"}}), -32600),
        // A string body reaches admission byte for byte, so its duplicate key survives.
        (
            json!(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","name":"admin_reset"}}"#),
            -32600,
        ),
        (json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {}}), -32001),
        (json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": 42}}), -32001),
    ] {
        let message = ReceivedMessage::new(
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
        .with_context("agent_surface_storage_path", json!(storage_path));

        let (response, envelope) = receive(&message).await;

        assert_eq!(envelope["error"]["code"], code, "{body}: {response} {envelope}");
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            0,
            "{body}"
        );
    }
}

#[tokio::test]
async fn a_paid_surface_reached_over_the_fabric_is_charged() {
    use crate::proxy::handler::agent_pay_gate::{install_test_transport, tests::MockGate};

    if std::env::var_os("AG_FABRIC_PAYMENT_CHILD").is_none() {
        let test_name = std::thread::current()
            .name()
            .expect("test thread name")
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env("AG_FABRIC_PAYMENT_CHILD", "1")
            .output()
            .expect("run the fabric payment test with isolated globals");
        assert!(
            output.status.success(),
            "isolated fabric payment test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_ran_exactly_one_test(&output);
        return;
    }

    let target_response = json!({"jsonrpc": "2.0", "id": "paid", "result": {"content": []}});
    let target = MockServer::start_with_response(target_response.to_string()).await;
    let failing = MockServer::start_with_status(500, "application/json", r#"{"error":"boom"}"#).await;
    let unreachable = crate::component_tests::helpers::closing_endpoint();
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap();
    for (surface_id, address) in
        [("fabric-paid", target.addr), ("fabric-paid-failing", failing.addr), ("fabric-paid-unreachable", unreachable)]
    {
        let surface: AgentSurface = serde_json::from_value(json!({
            "surface_id": surface_id, "name": surface_id,
            "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": format!("http://{address}"), "payment_policy": {
                "type": "agent_pay", "payment_gateway_id": "fabric-receive-gate", "payment_surface_id": "pay-1",
                "mcp_payment_triggers": {"mode": "match", "patterns": ["^paid_"]}
            }}
        }))
        .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
    }
    let gate =
        MockGate::answering(200, &[("Payment-Receipt", "fabric-receipt"), ("Cache-Control", "no-store")], json!({}))
            .challenging(
                &[("payment-required", "eyJ4IjoxfQ=="), ("content-type", "application/json")],
                json!({"accepts": []}),
            );
    install_test_transport("fabric-receive-gate", gate.clone());
    let now_secs = super::super::envelope_replay::now_secs();
    let forward_message = |surface_id: &str, path: &str, body: Value, headers: Value| {
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
            json!({"channel_id": surface_id, "method": "POST", "path": path, "headers": headers, "body": body}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path))
    };
    let call = |tool: &str| json!({"jsonrpc": "2.0", "id": "paid", "method": "tools/call", "params": {"name": tool}});
    let refusal = |result: ProcessingResult| {
        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected a ForwardResponse, got {result:?}");
        };
        let envelope: Value = serde_json::from_str(
            response_body["body"]
                .as_str()
                .unwrap_or("null"),
        )
        .unwrap_or(Value::Null);
        (response_body, envelope)
    };
    let forwarded = |target: &MockServer| {
        target
            .request_count
            .load(Ordering::SeqCst)
    };
    let legacy = json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION});

    let (response, envelope) =
        receive(&forward_message("fabric-paid", "/mcp", call("free_tool"), legacy.clone())).await;
    assert_eq!(response["status"], 200);
    assert_eq!(envelope, target_response);
    assert_eq!(gate.calls(), 0, "a free call makes no payment hop");

    let (response, envelope) = refusal(
        Box::pin(process_forward_request(&forward_message("fabric-paid", "/mcp", call("paid_tool"), legacy.clone())))
            .await,
    );
    assert_eq!(response["status"], 402, "{response}");
    assert_eq!(response["headers"]["payment-required"], "eyJ4IjoxfQ==");
    assert_eq!(
        envelope["error"]["code"], -32042,
        "a legacy caller is answered with the MPP MCP transport's payment-required code"
    );
    assert_eq!(envelope["error"]["data"]["x402"], json!({"accepts": []}));
    assert_eq!(gate.calls(), 1);
    assert_eq!(forwarded(&target), 1, "an unpaid call never reaches the Target");

    let modern_call = json!({"jsonrpc": "2.0", "id": "paid", "method": "tools/call", "params": {
        "name": "paid_tool", "_meta": {
            "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    }});
    let modern = json!({
        "MCP-Protocol-Version": MCP_MODERN_VERSION, "Mcp-Method": "tools/call", "Mcp-Name": "paid_tool",
        "content-type": "application/json", "accept": "application/json, text/event-stream"
    });
    let (response, envelope) = refusal(
        Box::pin(super::process_forward_request_with_mcp_runtime(
            &forward_message("fabric-paid", "/mcp", modern_call, modern),
            None,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        ))
        .await,
    );
    assert_eq!(response["status"], 402, "{response}");
    assert_eq!(envelope["error"]["code"], 1001, "a modern caller gets the application code");
    assert_eq!(forwarded(&target), 1);

    // A header that cannot be read, whether its name or its value, does not cost the
    // request its credential or its forward, and the query string is not sent to
    // agent-pay.
    let mut paid_headers = legacy.clone();
    paid_headers["PAYMENT-SIGNATURE"] = json!("proof");
    paid_headers["bad header"] = json!("a name with a space");
    paid_headers["x-count"] = json!(5);
    let path = "/mcp?api_key=query-secret";
    let (response, envelope) =
        receive(&forward_message("fabric-paid", path, call("paid_tool"), paid_headers.clone())).await;
    assert_eq!(response["status"], 200, "{response}");
    assert_eq!(response["headers"]["payment-response"], "fabric-receipt");
    assert_eq!(response["headers"]["cache-control"], "no-store");
    assert_eq!(envelope["result"]["_meta"]["org.paymentauth/receipt"], "fabric-receipt");
    let sent = gate.last();
    assert_eq!(sent.headers["PAYMENT-SIGNATURE"], "proof");
    let wire = format!("{} {:?} {} {}", sent.path, sent.headers, sent.body, sent.payment_context);
    assert!(!wire.contains("query-secret"), "the query string never reaches agent-pay: {wire}");
    let upstream = target
        .last_request_rx
        .borrow()
        .clone()
        .unwrap();
    assert!(
        !upstream
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("payment-signature")),
        "the consumed credential is stripped: {:?}",
        upstream.headers
    );
    let (hops, reached) = (gate.calls(), forwarded(&target));

    // The same payment on the same request is used up: refused with a fresh
    // challenge, and never forwarded a second time.
    let (response, envelope) = refusal(
        Box::pin(process_forward_request(&forward_message(
            "fabric-paid",
            path,
            call("paid_tool"),
            paid_headers.clone(),
        )))
        .await,
    );
    assert_eq!(response["status"], 402, "{response}");
    assert_eq!(response["headers"]["payment-required"], "eyJ4IjoxfQ==");
    assert!(
        response["headers"]
            .get("payment-response")
            .is_none()
    );
    assert_eq!(envelope["error"]["code"], -32043);
    assert_eq!(envelope["error"]["data"]["failure"]["reason"], "payment_already_used");
    assert_eq!(gate.calls(), hops + 2, "the replayed payment, then a request for a fresh challenge");
    assert_eq!(forwarded(&target), reached, "a used payment is not forwarded again");

    // The same credential on another tool is another request, so it is another key.
    let (response, _) = receive(&forward_message("fabric-paid", path, call("paid_other"), paid_headers)).await;
    assert_eq!(response["status"], 200, "{response}");
    let keys: Vec<String> = gate
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter_map(|request| {
            request.payment_context["correlation"]["idempotency_key"]
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert_eq!(keys.len(), 3, "{keys:?}");
    assert_eq!(keys[0], keys[1], "the replay is the same request");
    assert_ne!(keys[0], keys[2], "another tool is another request");

    // A paid call that then fails still carries its receipt, whether the Target
    // answers with an error or cannot be reached.
    for (surface_id, status) in [("fabric-paid-failing", 500), ("fabric-paid-unreachable", 502)] {
        let mut headers = legacy.clone();
        headers["PAYMENT-SIGNATURE"] = json!(format!("proof-{surface_id}"));
        let hops = gate.calls();
        let (response, _) = refusal(
            Box::pin(process_forward_request(&forward_message(surface_id, "/mcp", call("paid_tool"), headers))).await,
        );
        assert_eq!(response["status"], status, "{surface_id}: {response}");
        assert_eq!(response["headers"]["payment-response"], "fabric-receipt", "{surface_id}");
        assert_eq!(gate.calls(), hops + 1, "{surface_id}");
    }

    // An MCP proxy Target is charged only once the proxy is found, its request is
    // known to be servable and its breaker is closed, and what reaches the REST
    // backend carries no credential.
    use crate::mcp_proxies::filesystem::McpProxyStore;
    let backend = MockServer::start_with_response(r#"{"ok": true}"#).await;
    let proxy_directory = tempfile::tempdir().unwrap();
    let proxy_store = std::sync::Arc::new(
        crate::mcp_proxies::FileSystemMcpProxyStore::new(
            proxy_directory
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap(),
    );
    let spec = json!({"openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {
        "/echo": {"post": {"operationId": "paid_echo", "summary": "Echo",
            "requestBody": {"required": true, "content": {"application/json": {"schema": {
                "type": "object", "properties": {"payment_signature": {"type": "string"}, "q": {"type": "string"}}
            }}}},
            "responses": {"200": {"description": "OK"}}}}
    }});
    let mut proxy = crate::mcp_proxies::types::McpProxy::new(
        "Echo".into(),
        String::new(),
        backend.url(),
        spec.to_string(),
        "/mcp".into(),
        "/echo-proxy".into(),
    );
    proxy.flatten_post_params = true;
    proxy_store
        .create(&proxy)
        .await
        .unwrap();
    super::super::init_mcp_proxy_store(proxy_store).await;
    let policies = std::sync::Arc::new(crate::policies::SurfacePolicyManager::new());
    super::super::init_policy_manager(policies.clone()).await;
    let proxy_surface = |surface_id: &str, proxy_id: &str, breaker: bool| -> AgentSurface {
        let mut target = json!({"endpoint": format!("proxy://{proxy_id}"), "payment_policy": {
            "type": "agent_pay", "payment_gateway_id": "fabric-receive-gate", "payment_surface_id": "pay-1",
            "mcp_payment_triggers": {"mode": "match", "patterns": ["^paid_"]}
        }});
        if breaker {
            target["networking"] = json!({
                "circuit_breaker": {"failure_threshold": 1, "success_threshold": 1, "timeout_secs": 60, "window_secs": 60}
            });
        }
        serde_json::from_value(json!({
            "surface_id": surface_id, "name": surface_id,
            "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
            "target": target
        }))
        .unwrap()
    };
    for (surface_id, proxy_id, breaker) in [
        ("fabric-proxy", proxy.id.as_str(), false),
        ("fabric-proxy-missing", "no-such-proxy", false),
        ("fabric-proxy-breaker", proxy.id.as_str(), true),
    ] {
        let surface = proxy_surface(surface_id, proxy_id, breaker);
        policies
            .update_channel_policy(&surface)
            .await
            .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
    }
    // The status and headers (as `{"status", "headers"}`) and the JSON body of any answer.
    let flat = |result: ProcessingResult| async move {
        match result {
            ProcessingResult::RequiresResponse { response_body, .. } => {
                let envelope = serde_json::from_str::<Value>(
                    response_body["body"]
                        .as_str()
                        .unwrap_or("null"),
                )
                .unwrap_or(Value::Null);
                (response_body, envelope)
            }
            ProcessingResult::StreamingResponse { response } => {
                let headers: serde_json::Map<String, Value> = response
                    .headers()
                    .iter()
                    .map(|(name, value)| (name.to_string(), json!(value.to_str().unwrap())))
                    .collect();
                let status = response.status().as_u16();
                let bytes = axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap();
                (json!({"status": status, "headers": headers}), serde_json::from_slice(&bytes).unwrap_or(Value::Null))
            }
            other => panic!("expected a response, got {other:?}"),
        }
    };
    let with_credential = |tool: &str| {
        json!({"jsonrpc": "2.0", "id": "paid", "method": "tools/call", "params": {
            "name": tool, "arguments": {"q": "1", "payment_signature": "proxy-secret"}
        }})
    };
    let hops = gate.calls();
    let (response, envelope) = flat(
        Box::pin(process_forward_request(&forward_message(
            "fabric-proxy",
            "/mcp",
            with_credential("paid_unknown"),
            legacy.clone(),
        )))
        .await,
    )
    .await;
    assert_eq!(response["status"], 200, "{response}");
    assert!(
        envelope
            .get("error")
            .is_some(),
        "{envelope}"
    );
    assert_eq!(gate.calls(), hops, "a tool the proxy does not have is refused before it is charged");

    let (response, envelope) = flat(
        Box::pin(process_forward_request(&forward_message(
            "fabric-proxy",
            "/mcp",
            with_credential("paid_echo"),
            legacy.clone(),
        )))
        .await,
    )
    .await;
    assert_eq!(response["status"], 200, "{response}");
    assert_eq!(response["headers"]["payment-response"], "fabric-receipt", "{envelope}");
    assert_eq!(gate.calls(), hops + 1);
    assert_eq!(gate.last().headers["PAYMENT-SIGNATURE"], "proxy-secret");
    let reached = backend
        .last_request_rx
        .borrow()
        .clone()
        .expect("the backend was called");
    assert!(reached.body.contains("\"q\""), "{reached:?}");
    assert!(
        !reached
            .body
            .contains("proxy-secret"),
        "a legacy call reached the backend with its credential: {reached:?}"
    );

    let modern_call = |tool: &str| {
        json!({"jsonrpc": "2.0", "id": "paid", "method": "tools/call", "params": {
            "name": tool, "arguments": {"q": "2", "payment_signature": "modern-proxy-secret"}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }})
    };
    let modern_headers = |tool: &str| {
        json!({
            "MCP-Protocol-Version": MCP_MODERN_VERSION, "Mcp-Method": "tools/call", "Mcp-Name": tool,
            "content-type": "application/json", "accept": "application/json, text/event-stream"
        })
    };
    let hops = gate.calls();
    let modern_receive = |surface_id: &str| {
        let message = forward_message(surface_id, "/mcp", modern_call("paid_echo"), modern_headers("paid_echo"));
        Box::pin(super::process_forward_request_with_mcp_runtime(
            Box::leak(Box::new(message)),
            None,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        ))
    };
    let (response, _) = flat(modern_receive("fabric-proxy-missing").await).await;
    assert_eq!(response["status"], 404, "{response}");
    assert_eq!(gate.calls(), hops, "a proxy that is not there is refused before it is charged");

    let (response, envelope) = flat(modern_receive("fabric-proxy").await).await;
    assert_eq!(response["status"], 200, "{response} {envelope}");
    assert_eq!(gate.calls(), hops + 1);
    let reached = backend
        .last_request_rx
        .borrow()
        .clone()
        .unwrap();
    assert!(reached.body.contains("\"q\""), "{reached:?}");
    assert!(
        !reached
            .body
            .contains("modern-proxy-secret"),
        "a modern call reached the backend with its credential: {reached:?}"
    );

    let breaker = policies
        .get_circuit_breaker("fabric-proxy-breaker")
        .await
        .expect("the surface has a circuit breaker");
    let _ = breaker
        .call(async { Err::<(), &str>("backend down") })
        .await;
    assert!(
        breaker
            .refusing_for()
            .await
            .is_some()
    );
    let hops = gate.calls();
    let (response, envelope) = flat(
        Box::pin(process_forward_request(&forward_message(
            "fabric-proxy-breaker",
            "/mcp",
            with_credential("paid_echo"),
            legacy.clone(),
        )))
        .await,
    )
    .await;
    assert!(
        response["headers"]
            .get("payment-response")
            .is_none(),
        "{response} {envelope}"
    );
    assert!(
        envelope
            .get("error")
            .is_some(),
        "{envelope}"
    );
    assert_eq!(gate.calls(), hops, "a Target whose circuit is open is refused before it is charged");
}

#[test]
fn a_hold_a_retry_or_a_refusal_reaches_a_fabric_caller_as_the_gate_answered() {
    run_in_own_process(gate_answers_over_fabric_flow);
}

async fn gate_answers_over_fabric_flow() {
    use crate::mcp::errors::{application_error_codes, error_codes, payment_transport_error_codes};
    use crate::proxy::handler::agent_pay_gate::{install_test_transport, tests::MockGate};

    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": "paid", "result": {"content": []}}).to_string())
            .await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap();
    let cases = [
        (
            "fabric-held-gate",
            None,
            MockGate::answering(
                202,
                &[],
                json!({"status": "held_for_oversight", "case_id": "case-7", "reason": "limit"}),
            ),
            200,
            None,
            json!({"code": application_error_codes::PAYMENT_PENDING, "message": "Payment pending review",
                "data": {"httpStatus": 202, "case_id": "case-7", "reason": "limit"}}),
        ),
        (
            "fabric-rate-limited-gate",
            None,
            MockGate::answering(429, &[("retry-after", "9")], json!({"error": "rate_limited"})),
            429,
            Some("9"),
            json!({"code": error_codes::INTERNAL_ERROR, "message": "Payment gateway rate limit reached",
                "data": {"httpStatus": 429, "retryAfter": "9"}}),
        ),
        (
            "fabric-in-progress-gate",
            None,
            MockGate::answering(409, &[], json!({"error": "idempotency_key_in_use"})),
            409,
            Some("1"),
            json!({"code": error_codes::INTERNAL_ERROR, "message": "Payment in progress",
                "data": {"httpStatus": 409, "error": "payment_in_progress", "retryAfter": "1"}}),
        ),
        (
            "fabric-unconfirmed-gate",
            Some("unconfirmed-proof"),
            MockGate::answering(500, &[], json!({})),
            502,
            Some("2"),
            json!({"code": error_codes::INTERNAL_ERROR, "message": "Payment not confirmed",
                "data": {"httpStatus": 502, "error": "payment_unconfirmed",
                    "detail": "payment gateway returned unexpected status 500",
                    "retryAfter": 2, "replayWindowSecs": 120}}),
        ),
        (
            "fabric-rejected-gate",
            Some("rejected-proof"),
            MockGate::answering(403, &[], json!({"status": "rejected_by_oversight"})),
            403,
            None,
            json!({"code": payment_transport_error_codes::PAYMENT_VERIFICATION_FAILED,
                "message": "Payment Verification Failed",
                "data": {"httpStatus": 403, "failure": {"reason": "rejected_by_oversight"}}}),
        ),
    ];
    for (gate_id, _, gate, ..) in &cases {
        let surface: AgentSurface = serde_json::from_value(json!({
            "surface_id": gate_id, "name": gate_id,
            "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": target.url(), "payment_policy": {
                "type": "agent_pay", "payment_gateway_id": gate_id, "payment_surface_id": "pay-1",
                "mcp_payment_triggers": {"mode": "all"}
            }}
        }))
        .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
        install_test_transport(gate_id, gate.clone());
    }
    let now_secs = super::super::envelope_replay::now_secs();

    for (gate_id, credential, gate, expected_status, retry_after, error) in cases {
        let mut headers = json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION});
        if let Some(credential) = credential {
            headers["PAYMENT-SIGNATURE"] = json!(credential);
        }
        let message = ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(now_secs + 60),
            json!({"channel_id": gate_id, "method": "POST", "path": "/mcp",
                "headers": headers,
                "body": {"jsonrpc": "2.0", "id": "paid", "method": "tools/call", "params": {"name": "paid_tool"}}}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path));

        let (response, envelope) = receive(&message).await;
        assert_eq!(response["status"], expected_status, "{gate_id}: {response}");
        assert_eq!(response["headers"]["retry-after"].as_str(), retry_after, "{gate_id}: {response}");
        assert_eq!(response["headers"]["cache-control"], "no-store", "{gate_id}: {response}");
        assert_eq!(envelope, json!({"jsonrpc": "2.0", "id": "paid", "error": error}), "{gate_id}");
        assert_eq!(gate.calls(), 1, "{gate_id}");
    }
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        0,
        "an unpaid call never reaches the Target"
    );
}

#[test]
fn lenient_headers_keep_every_header_that_decodes() {
    let headers = json!({
        "PAYMENT-SIGNATURE": "proof", "x-big": "a".repeat(40_000), "bad header": "name", "x-count": 5,
        "x-nested": {"a": 1}, "x-bad-value": "line\nbreak"
    });
    let decoded = super::lenient_headers(headers.as_object());
    assert_eq!(decoded["payment-signature"], "proof");
    assert_eq!(decoded["x-big"].len(), 40_000, "there is no size cliff");
    let mut names: Vec<_> = decoded
        .keys()
        .map(|name| name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["payment-signature", "x-big"]);
    assert!(super::lenient_headers(None).is_empty());
}

#[test]
fn the_payment_variant_is_the_resolved_alias_and_never_the_peers_text() {
    let surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "variants", "name": "variants",
        "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": "http://127.0.0.1:9"},
        "variants": [
            {"id": "vc-gold", "alias": "gold", "name": "Gold", "description": "", "enabled": true, "overrides": {}},
            {"id": "vc-off", "alias": "off", "name": "Off", "description": "", "enabled": false, "overrides": {}}
        ],
        "default_variant_id": "vc-gold"
    }))
    .unwrap();

    assert_eq!(super::resolved_variant_alias(&surface, Some("vc-gold"), None).as_deref(), Some("gold"));
    assert_eq!(
        super::resolved_variant_alias(&surface, Some("vc-off"), None),
        None,
        "a disabled variant selects nothing"
    );
    assert_eq!(super::resolved_variant_alias(&surface, Some("vc-unknown"), None), None);
    assert_eq!(super::resolved_variant_alias(&surface, None, None), None);
    assert_eq!(
        super::resolved_variant_alias(&surface, None, Some("gold")).as_deref(),
        Some("gold"),
        "a stream carries the alias its open request named"
    );
}

#[test]
fn fabric_receive_selects_the_method_each_credential_belongs_to() {
    run_in_own_process(fabric_multi_method_flow);
}

/// Fabric receive selects the caller authentication method as the direct path
/// does. On a JWT + API key Access Point each credential alone is verified by
/// its own method, a request carrying both fails as ambiguous, and an
/// `Authorization` value in another scheme is not the JWT. Beside protected
/// resource metadata a missing credential gets the discovery refusal and a
/// failed API key a plain one, both before policy.
async fn fabric_multi_method_flow() {
    use std::sync::Arc;

    use crate::component_tests::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
    use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore, SecretsStore};

    const PARTNER_KEY: &str = "partner-key";

    let fixture = JwksFixture::start().await;
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": "call", "result": {"tools": []}}).to_string())
            .await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let strategies = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            temp_dir
                .path()
                .join("strategies"),
        )
        .await
        .unwrap(),
    );
    let strategy = strategies
        .create(
            serde_json::from_value(json!({
                "id": "idp", "name": "IdP", "expected_issuer": fixture.issuer,
                "jwks_source": {"type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer)},
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let secrets: Arc<dyn SecretsStore> = Arc::new(
        FilesystemSecretsStore::new_async(
            temp_dir
                .path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap(),
    );
    secrets
        .create(CreateSecretRequest {
            tenant_id: None,
            name: "partners".into(),
            secret_id: "partners".into(),
            description: None,
            value: PARTNER_KEY.into(),
            secret_type: "ApiKey".into(),
            tags: vec![],
        })
        .await
        .unwrap();
    let methods = json!([
        {"type": "jwt_bearer", "jwt_verification_strategy_id": strategy.id, "audiences": []},
        {"type": "api_key", "secret_id": "partners", "extraction": {"source": "http_header", "field": "x-api-key"}}
    ]);
    let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap();
    for surface in [
        json!({
            "surface_id": "multi", "name": "multi",
            "access_point": {"listen_address": "https://gateway.example", "route": "/multi", "protocol": "mcp",
                "caller_authentication": {"methods": methods, "on_failure": "reject"}},
            "target": {"endpoint": format!("http://{}", target.addr)}
        }),
        json!({
            "surface_id": "multi-discovery", "name": "multi-discovery",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp",
                "caller_authentication": {"methods": methods,
                    "protected_resource": {"resource": "https://gateway.example/mcp",
                        "authorization_servers": [crate::protocols::protected_resource::fixtures::ISSUER]}}},
            "target": {"endpoint": format!("http://{}", target.addr)}
        }),
    ] {
        store
            .save(&serde_json::from_value::<AgentSurface>(surface).unwrap())
            .await
            .unwrap();
    }
    super::init_mcp_auth_network(Arc::new(crate::protocols::protected_resource::fixtures::discovery_network()));
    super::init_source_auth_middleware(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
        Arc::new(crate::didauth::DidAuthSessionStore::new()),
        strategies,
        Arc::new(crate::jwt_bearer::JwksClient::new()),
        Some(secrets),
        Arc::new(dashmap::DashMap::new()),
        None,
        None,
    )))
    .await;

    let now = super::super::envelope_replay::now_secs();
    let send = |channel_id: &str, path: &str, credentials: &[(&str, String)]| {
        let mut headers = json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION});
        for (name, value) in credentials {
            headers[*name] = json!(value);
        }
        let message = ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(now + 60),
            json!({"channel_id": channel_id, "method": "POST", "path": path, "headers": headers,
                "body": {"jsonrpc": "2.0", "id": "call", "method": "tools/list"}}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path));
        async move {
            let result = tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(&message)))
                .await
                .expect("Fabric receive handler timed out");
            let ProcessingResult::RequiresResponse { response_body, .. } = result else {
                panic!("expected a ForwardResponse, got {result:?}");
            };
            response_body
        }
    };
    let reached = || {
        target
            .request_count
            .load(Ordering::SeqCst)
    };
    let body = |response: &Value| -> Value {
        serde_json::from_str(
            response["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    };
    let token = |audience: &str| {
        format!(
            "Bearer {}",
            sign_jwt(
                json!({"iss": fixture.issuer, "sub": "user-1", "aud": audience, "exp": now_secs() + 300}),
                &fixture.kid
            )
        )
    };
    let key = || ("x-api-key", PARTNER_KEY.to_string());

    let jwt = send("multi", "/multi", &[("authorization", token("any"))]).await;
    assert_eq!(jwt["status"], 200, "a JWT caller is verified by the JWT method: {jwt}");
    let partner = send("multi", "/multi", &[key()]).await;
    assert_eq!(partner["status"], 200, "an API key caller is verified by the API key method: {partner}");
    let payment = send("multi", "/multi", &[key(), ("authorization", "Payment cred".to_string())]).await;
    assert_eq!(payment["status"], 200, "an Authorization value in another scheme is not the JWT: {payment}");
    assert_eq!(reached(), 3);

    let both = send("multi", "/multi", &[key(), ("authorization", token("any"))]).await;
    assert_eq!(both["status"], 401, "a caller carrying two credentials fails as ambiguous: {both}");
    assert_eq!(body(&both)["error"]["message"], crate::source_auth::errors::CALLER_CREDENTIAL_REFUSED, "{both}");
    assert_eq!(reached(), 3, "an ambiguous caller never reaches the Target");

    let missing = send("multi-discovery", "/mcp", &[]).await;
    assert_eq!(missing["status"], 401, "{missing}");
    assert!(
        missing["headers"]["www-authenticate"]
            .as_str()
            .unwrap_or_default()
            .starts_with("Bearer realm=\"agent-gateway\""),
        "a missing credential gets the discovery refusal: {missing}"
    );
    assert_ne!(body(&missing)["error"]["message"], crate::source_auth::errors::CALLER_CREDENTIAL_REFUSED, "{missing}");
    let wrong_key = send("multi-discovery", "/mcp", &[("x-api-key", "wrong".to_string())]).await;
    assert_eq!(wrong_key["status"], 401, "a failed API key is refused before policy: {wrong_key}");
    assert_eq!(
        body(&wrong_key)["error"]["message"],
        crate::source_auth::errors::CALLER_CREDENTIAL_REFUSED,
        "a failed API key gets the plain refusal, not the challenge: {wrong_key}"
    );
    assert_eq!(reached(), 3, "a refused caller never reaches the Target");

    let discovery_key = send("multi-discovery", "/mcp", &[key()]).await;
    assert_eq!(discovery_key["status"], 200, "{discovery_key}");
    let discovery_jwt =
        send("multi-discovery", "/mcp", &[("authorization", token("https://gateway.example/mcp"))]).await;
    assert_eq!(discovery_jwt["status"], 200, "{discovery_jwt}");
    assert_eq!(reached(), 5);
}

#[test]
fn fabric_receive_sends_the_target_credential_only_for_a_caller_one_method_verified() {
    run_in_own_process(multi_method_target_credential_flow);
}

/// On an Access Point with two API key methods, under `target_source_auth` `enforce`, a caller
/// verified by either method gets the Target credential over Fabric receive, and its API key
/// is not forwarded. A caller carrying both keys fails as ambiguous: it reaches the Target
/// without the credential when failed callers go on to policy, and is refused when the Access
/// Point rejects them.
async fn multi_method_target_credential_flow() {
    use std::sync::Arc;

    use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode, init_credential_policy};
    use crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore;
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore, SecretsStore};

    const PARTNER_KEY: &str = "partner-key";
    const AGENT_KEY: &str = "agent-key";

    init_credential_policy(CredentialPolicyConfig {
        target_source_auth: RuleMode::Enforce,
        ..Default::default()
    });
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": "call", "result": {"tools": []}}).to_string())
            .await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let secrets_path = temp_dir
        .path()
        .join("secrets");
    let secrets: Arc<dyn SecretsStore> = Arc::new(
        FilesystemSecretsStore::new_async(secrets_path.to_str().unwrap())
            .await
            .unwrap(),
    );
    for (secret_id, value) in [("partners", PARTNER_KEY), ("agents", AGENT_KEY), ("target-key", "target-secret")] {
        secrets
            .create(CreateSecretRequest {
                tenant_id: None,
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: value.into(),
                secret_type: "ApiKey".into(),
                tags: vec![],
            })
            .await
            .unwrap();
    }
    let surface = |id: &str, on_failure: &str| -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": id, "name": id,
            "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"), "protocol": "mcp",
                "public": true,
                "caller_authentication": {"on_failure": on_failure, "methods": [
                    {"type": "api_key", "secret_id": "partners",
                     "extraction": {"source": "http_header", "field": "x-partner-key"}},
                    {"type": "api_key", "secret_id": "agents",
                     "extraction": {"source": "http_header", "field": "x-agent-key"}}
                ]}},
            "target": {"endpoint": format!("http://{}", target.addr), "auth": {"method": {"static_secret": {
                "secret_id": "target-key", "header_name": "X-Target-Key", "header_format": "{value}"
            }}}}
        }))
        .unwrap()
    };
    let (forwarding, rejecting) = (surface("forwarding", "continue"), surface("rejecting", "reject"));
    let storage_path = saved_surfaces(temp_dir.path(), &[&forwarding, &rejecting]).await;
    super::init_source_auth_middleware(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
        Arc::new(crate::didauth::DidAuthSessionStore::new()),
        Arc::new(
            FileSystemJwtVerificationStrategyStore::new(
                temp_dir
                    .path()
                    .join("strategies"),
            )
            .await
            .unwrap(),
        ),
        Arc::new(crate::jwt_bearer::JwksClient::new()),
        Some(secrets),
        Arc::new(dashmap::DashMap::new()),
        None,
        None,
    )))
    .await;

    let send = |surface: &AgentSurface, credentials: &[(&str, &str)]| {
        let mut headers = json!({"MCP-Protocol-Version": MCP_LEGACY_VERSION});
        for (name, value) in credentials {
            headers[*name] = json!(value);
        }
        let mut message = forwarded_post(
            surface,
            &format!("/{}", surface.surface_id),
            json!({"jsonrpc": "2.0", "id": "call", "method": "tools/list"}),
            &storage_path,
        )
        .with_context("secrets_storage_path", json!(secrets_path));
        message.message_body["headers"] = headers;
        async move { decode(super::process_forward_request(&message).await).await }
    };
    let reached = || {
        target
            .request_count
            .load(Ordering::SeqCst)
    };
    let last_headers = || {
        target
            .last_request_rx
            .borrow()
            .clone()
            .expect("the Target was called")
            .headers
    };

    for (caller, credential) in [("x-partner-key", PARTNER_KEY), ("x-agent-key", AGENT_KEY)] {
        let (status, answered) = send(&forwarding, &[(caller, credential)]).await;
        assert_eq!(status, 200, "{caller}: {answered}");
        let headers = last_headers();
        assert_eq!(
            headers
                .get("x-target-key")
                .map(String::as_str),
            Some("target-secret"),
            "{caller}: {headers:?}"
        );
        assert!(!headers.contains_key(caller), "the caller's API key is not forwarded: {headers:?}");
    }
    assert_eq!(reached(), 2);

    let both = [("x-partner-key", PARTNER_KEY), ("x-agent-key", AGENT_KEY)];
    let (status, answered) = send(&forwarding, &both).await;
    assert_eq!(status, 200, "an ambiguous caller goes on to policy: {answered}");
    assert_eq!(reached(), 3);
    let headers = last_headers();
    assert!(!headers.contains_key("x-target-key"), "an ambiguous caller gets no Target credential: {headers:?}");
    assert!(!headers.contains_key("x-partner-key") && !headers.contains_key("x-agent-key"), "{headers:?}");

    let (status, answered) = send(&rejecting, &both).await;
    assert_eq!(status, 401, "{answered}");
    assert_eq!(reached(), 3, "a refused caller never reaches the Target");
}

#[test]
fn a_legacy_mcp_proxy_tool_call_received_over_fabric_drops_a_token_its_backend_refuses_as_invalid() {
    run_in_own_process(|| refused_mcp_proxy_token_flow(false));
}

#[test]
fn a_modern_mcp_proxy_tool_call_received_over_fabric_drops_a_token_its_backend_refuses_as_invalid() {
    run_in_own_process(|| refused_mcp_proxy_token_flow(true));
}

/// A `proxy://` surface reached over Fabric sends the Target credential from its client
/// credentials provider, and drops the token the MCP proxy's backend refuses as
/// `invalid_token` under the same limits as the direct path.
async fn refused_mcp_proxy_token_flow(modern: bool) {
    use std::sync::Arc;

    use crate::mcp_proxies::filesystem::McpProxyStore;
    use crate::proxy::handler::target_auth_tests::{
        BackendAnswer, Fixture, assert_a_refused_token_is_dropped, echo_tool_call, mcp_proxy_answering, provider_auth,
    };

    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let fixture = Fixture::new(200).await;
    let answer = BackendAnswer::new(std::sync::Mutex::new((200, None)));
    let (proxy, mut surface, _backend) = mcp_proxy_answering(answer.clone()).await;
    surface.target.auth = Some(provider_auth("machine"));
    let proxies = Arc::new(
        crate::mcp_proxies::FileSystemMcpProxyStore::new(
            temp_dir
                .path()
                .join("proxies"),
        )
        .await
        .unwrap(),
    );
    proxies
        .create(&proxy)
        .await
        .unwrap();
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap()
        .save(&surface)
        .await
        .unwrap();
    super::init_mcp_proxy_store(proxies).await;
    super::init_credential_provider_store(fixture.providers.clone()).await;
    super::init_delegation_vault_store(fixture.vault.clone()).await;

    let call = || {
        let (headers, body) = echo_tool_call(modern);
        let headers = Value::Object(
            headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), json!(value)))
                .collect(),
        );
        let mut forwarded =
            json!({"channel_id": surface.surface_id, "method": "POST", "path": "/mcp", "headers": headers});
        if !modern {
            forwarded["body"] = body.clone();
        }
        let message = ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(super::super::envelope_replay::now_secs() + 60),
            forwarded,
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path))
        .with_context("secrets_storage_path", json!(fixture.secrets_path()));
        let stream = modern.then(|| super::FabricStreamRequest {
            headers: crate::proxy::fabric_stream::wire::headers_from_json(Some(&headers)).unwrap(),
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
        });
        let egress = fixture.egress.clone();
        async move {
            let received = egress
                .scope(Box::pin(super::process_forward_request_with_mcp_runtime(
                    &message,
                    stream,
                    crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
                    None,
                )))
                .await;
            let (status, answered) = decode(received).await;
            assert_eq!(status, 200, "modern: {modern}: {answered}");
            answered["result"].clone()
        }
    };
    assert_a_refused_token_is_dropped(&fixture, &answer, &format!("Fabric receive, modern: {modern}"), call).await;
}

#[test]
fn an_mcp_proxy_tool_call_received_over_fabric_answers_an_unresolvable_target_credential_with_a_problem() {
    run_in_own_process(unresolvable_mcp_proxy_credential_flow);
}

/// A `proxy://` surface reached over Fabric whose Target credential names a missing secret,
/// with `fallback: reject`, is answered with the same problem as the forward path.
async fn unresolvable_mcp_proxy_credential_flow() {
    use std::sync::Arc;

    use crate::mcp_proxies::filesystem::McpProxyStore;
    use crate::proxy::handler::target_auth_tests::{BackendAnswer, echo_tool_call, mcp_proxy_answering};

    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let (proxy, mut surface, _backend) =
        mcp_proxy_answering(BackendAnswer::new(std::sync::Mutex::new((200, None)))).await;
    surface.target.auth = Some(
        serde_json::from_value(
            json!({"method": {"static_secret": {"secret_id": "missing", "header_name": "x-target-key"}},
            "fallback": "reject"}),
        )
        .unwrap(),
    );
    let proxies = Arc::new(
        crate::mcp_proxies::FileSystemMcpProxyStore::new(
            temp_dir
                .path()
                .join("proxies"),
        )
        .await
        .unwrap(),
    );
    proxies
        .create(&proxy)
        .await
        .unwrap();
    super::init_mcp_proxy_store(proxies).await;
    let secrets_path = temp_dir
        .path()
        .join("secrets");
    crate::secrets::FilesystemSecretsStore::new_async(secrets_path.to_str().unwrap())
        .await
        .unwrap();
    let storage_path = saved_surfaces(temp_dir.path(), &[&surface]).await;
    let message = forwarded_post(&surface, "/mcp", echo_tool_call(false).1, &storage_path)
        .with_context("secrets_storage_path", json!(secrets_path));

    let ProcessingResult::RequiresResponse { response_body, .. } = process_forward_request(&message).await else {
        panic!("expected a buffered answer");
    };

    assert_eq!(response_body["status"], 502, "{response_body}");
    assert_eq!(response_body["headers"]["content-type"], "application/problem+json", "{response_body}");
    let problem: Value = serde_json::from_str(
        response_body["body"]
            .as_str()
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    assert_eq!(
        problem,
        json!({"type": "about:blank", "title": "Bad Gateway", "status": 502,
            "detail": "Target authentication configuration error"}),
        "{response_body}"
    );
}

/// Saves `surfaces` to a surface store under `root` and returns its storage path.
async fn saved_surfaces(
    root: &std::path::Path,
    surfaces: &[&AgentSurface],
) -> std::path::PathBuf {
    let storage_path = root.join("surfaces");
    let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
        .await
        .unwrap();
    for surface in surfaces {
        store
            .save(surface)
            .await
            .unwrap();
    }
    storage_path
}

/// A `POST` of `body` to `surface` as the sending Connection Point forwards it over Fabric.
fn forwarded_post(
    surface: &AgentSurface,
    path: &str,
    body: Value,
    storage_path: &std::path::Path,
) -> ReceivedMessage {
    ReceivedMessage::new(
        "receiver-connection".to_string(),
        "receiver-gateway".to_string(),
        MessageType::ForwardRequest.to_string(),
        uuid::Uuid::new_v4().to_string(),
        None,
        Some(SENDER_CONNECTION_POINT_DID.to_string()),
        vec!["did:web:receiver.example".to_string()],
        None,
        Some(super::super::envelope_replay::now_secs() + 60),
        json!({"channel_id": surface.surface_id, "method": "POST", "path": path,
            "headers": {"content-type": "application/json"}, "body": body}),
        MessageMetadata {
            encrypted: true,
            authenticated: true,
            from_key: None,
            extra: Value::Null,
        },
    )
    .with_context("agent_surface_storage_path", json!(storage_path))
}

#[test]
fn a_request_received_over_fabric_drops_a_token_its_http_target_refuses_as_invalid() {
    run_in_own_process(refused_http_target_token_flow);
}

/// A surface whose Target is an http URL, reached over Fabric, sends the Target credential from
/// its client credentials provider and drops the token the Target refuses as `invalid_token`
/// under the same limits as the direct path.
async fn refused_http_target_token_flow() {
    use crate::proxy::handler::target_auth_tests::{
        BackendAnswer, Fixture, assert_a_refused_token_is_dropped, backend_answering, provider_auth,
    };

    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let fixture = Fixture::new(200).await;
    let answer = BackendAnswer::new(std::sync::Mutex::new((200, None)));
    let (target_url, _target) =
        backend_answering(answer.clone(), json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})).await;
    let mut surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "http-target", "name": "HTTP Target",
        "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
        "target": {"endpoint": target_url}
    }))
    .unwrap();
    surface.target.auth = Some(provider_auth("machine"));
    let storage_path = saved_surfaces(temp_dir.path(), &[&surface]).await;
    super::init_credential_provider_store(fixture.providers.clone()).await;
    super::init_delegation_vault_store(fixture.vault.clone()).await;

    let call = || {
        let message =
            forwarded_post(&surface, "/mcp", json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), &storage_path)
                .with_context("secrets_storage_path", json!(fixture.secrets_path()));
        let egress = fixture.egress.clone();
        async move {
            let received = egress
                .scope(Box::pin(super::process_forward_request(&message)))
                .await;
            let (status, answered) = decode(received).await;
            json!({"isError": status != 200, "status": status, "answered": answered})
        }
    };
    assert_a_refused_token_is_dropped(&fixture, &answer, "Fabric receive HTTP forward", call).await;
}

#[test]
fn only_an_a2a_or_ap2_surface_received_over_fabric_reaches_its_a2a_proxy() {
    run_in_own_process(a2a_proxy_dispatch_flow);
}

/// No A2A proxy store is installed, so a request that reaches the A2A proxy is answered that its
/// storage is unavailable. An MCP surface whose Target names an A2A proxy is not dispatched to
/// it, as on the direct path, so its Direct Line credential is never sent for that surface.
async fn a2a_proxy_dispatch_flow() {
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let surface = |id: &str, protocol: &str| -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": id, "name": id,
            "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"), "protocol": protocol},
            "target": {"endpoint": "a2a-proxy://proxy-1"}
        }))
        .unwrap()
    };
    let (a2a, ap2, mcp) = (surface("a2a", "a2a"), surface("ap2", "ap2"), surface("mcp", "mcp"));
    let storage_path = saved_surfaces(temp_dir.path(), &[&a2a, &ap2, &mcp]).await;
    let send = |surface: &AgentSurface, body: Value| {
        let message = forwarded_post(surface, "/", body, &storage_path);
        async move { decode(super::process_forward_request(&message).await).await }
    };
    let message_send = json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
        "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hi"}]
    }}});

    for dispatched in [&a2a, &ap2] {
        let (status, answered) = send(dispatched, message_send.clone()).await;
        assert_eq!(
            (status, answered["error"]["message"].as_str()),
            (200, Some("Failed to access A2A proxy storage")),
            "{}: {answered}",
            dispatched.surface_id
        );
    }
    let (status, answered) = send(&mcp, json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).await;
    assert_ne!(status, 200, "{answered}");
    assert!(
        !answered
            .to_string()
            .contains("A2A proxy"),
        "{status}: {answered}"
    );
}

#[test]
fn fabric_receive_refuses_a_surface_naming_another_tenants_provider_key_when_enforced() {
    run_in_own_process(provider_key_fabric_flow);
}

/// Over Fabric, a surface stored naming another tenant's API Key Provider key is not ready
/// under `tenant_credential_isolation: enforce` and refuses with `503` before the Target; one
/// naming its own tenant's key is served. The verdict is taken on the first request, as no
/// apply ran for the surfaces.
async fn provider_key_fabric_flow() {
    use std::sync::Arc;

    use crate::api_keys::store::ApiKeyStore as _;
    use crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore;

    crate::config::credential_policy::init_credential_policy(
        crate::config::credential_policy::CredentialPolicyConfig {
            tenant_credential_isolation: crate::config::credential_policy::RuleMode::Enforce,
            ..Default::default()
        },
    );
    let target =
        MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": "call", "result": {"tools": []}}).to_string())
            .await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let storage_path = temp_dir
        .path()
        .join("surfaces");
    let store = Arc::new(
        FileSystemAgentSurfaceStore::new(storage_path.clone())
            .await
            .unwrap(),
    );
    let api_keys = Arc::new(
        crate::api_keys::FileSystemApiKeyStore::new(
            &temp_dir
                .path()
                .join("api_keys")
                .to_string_lossy(),
        )
        .await
        .unwrap(),
    );
    let surface = |id: &str, tenant: &str, key_id: Option<&str>| {
        let mut surface = json!({
            "surface_id": id, "name": id, "tenant_id": tenant,
            "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"), "protocol": "mcp"},
            "target": {"endpoint": format!("http://{}", target.addr)}
        });
        if let Some(key_id) = key_id {
            surface["identity_slots"] = json!({"external": {"type": "from_api_key", "api_key_id": key_id}});
        }
        serde_json::from_value::<AgentSurface>(surface).unwrap()
    };
    for stored in [
        surface("owner-a", "tenant-a", None),
        surface("owner-b", "tenant-b", None),
        surface("names-cross", "tenant-a", Some("atgk_fabric_b")),
        surface("names-own", "tenant-a", Some("atgk_fabric_a")),
    ] {
        store
            .save(&stored)
            .await
            .unwrap();
    }
    for (owner, key_id) in [("owner-a", "atgk_fabric_a"), ("owner-b", "atgk_fabric_b")] {
        api_keys
            .create_with_material(owner, key_id.to_string(), format!("atgs_{key_id}"), "client", None, "test")
            .await
            .unwrap();
    }
    crate::identity::provider_key_gate::gate().set_sources(Some(api_keys), Some(store));
    super::init_source_auth_middleware(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
        Arc::new(crate::didauth::DidAuthSessionStore::new()),
        Arc::new(
            FileSystemJwtVerificationStrategyStore::new(
                temp_dir
                    .path()
                    .join("strategies"),
            )
            .await
            .unwrap(),
        ),
        Arc::new(crate::jwt_bearer::JwksClient::new()),
        None,
        Arc::new(dashmap::DashMap::new()),
        None,
        None,
    )))
    .await;

    let now = super::super::envelope_replay::now_secs();
    let send = |channel_id: &str| {
        let message = ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_CONNECTION_POINT_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(now + 60),
            json!({"channel_id": channel_id, "method": "POST", "path": format!("/{channel_id}"),
                "headers": {"MCP-Protocol-Version": MCP_LEGACY_VERSION},
                "body": {"jsonrpc": "2.0", "id": "call", "method": "tools/list"}}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(storage_path));
        async move { receive(&message).await.0 }
    };
    let reached = || {
        target
            .request_count
            .load(Ordering::SeqCst)
    };

    let refused = send("names-cross").await;
    assert_eq!(refused["status"], 503, "{refused}");
    assert_eq!(
        serde_json::from_str::<Value>(
            refused["body"]
                .as_str()
                .unwrap()
        )
        .unwrap()["error"]["message"],
        crate::source_auth::errors::ACCESS_POINT_UNAVAILABLE
    );
    assert_eq!(reached(), 0, "a not-ready Access Point never reaches the Target");

    let served = send("names-own").await;
    assert_eq!(served["status"], 200, "{served}");
    assert_eq!(reached(), 1);
}

#[test]
fn fabric_receive_sends_the_target_credential_only_for_a_get_of_the_surfaces_card_location() {
    run_in_own_process(card_location_target_credential_flow);
}

/// A surface that checks no caller, reached over Fabric, sends its Target credential only for a
/// `GET` of exactly its card location, the sending gateway's own card fetch, in `warn` and under
/// `target_source_auth` `enforce`. A `HEAD` of it, a query on it, and any other discovery read
/// reach the Target without the credential.
async fn card_location_target_credential_flow() {
    use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode, TEST_CREDENTIAL_POLICY};
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore, SecretsStore};

    let target = MockServer::start_with_response(json!({"name": "card"}).to_string()).await;
    let temp_dir = tempfile::tempdir().unwrap();
    let _issuer_dir = install_listener_manager_with_sender(temp_dir.path()).await;
    let secrets_path = temp_dir
        .path()
        .join("secrets");
    FilesystemSecretsStore::new_async(secrets_path.to_str().unwrap())
        .await
        .unwrap()
        .create(CreateSecretRequest {
            tenant_id: None,
            name: "target-key".into(),
            secret_id: "target-key".into(),
            description: None,
            value: "target-secret".into(),
            secret_type: "ApiKey".into(),
            tags: vec![],
        })
        .await
        .unwrap();
    let surface = |id: &str, card_path: Option<&str>| -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": id, "name": id,
            "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"),
                "protocol": "a2a", "public": true, "agent_card_path": card_path},
            "target": {"endpoint": format!("http://{}", target.addr), "auth": {"method": {"static_secret": {
                "secret_id": "target-key", "header_name": "X-Target-Key", "header_format": "{value}"
            }}}}
        }))
        .unwrap()
    };
    let (default, custom) = (surface("default-card", None), surface("custom-card", Some("custom/card.json")));
    let storage_path = saved_surfaces(temp_dir.path(), &[&default, &custom]).await;

    let send = |surface: &AgentSurface, method: &str, path: &str| {
        let mut message = forwarded_post(surface, path, Value::Null, &storage_path)
            .with_context("secrets_storage_path", json!(secrets_path));
        message.message_body["method"] = json!(method);
        message.message_body["headers"] = json!({});
        message
            .message_body
            .as_object_mut()
            .unwrap()
            .remove("body");
        async move { decode(super::process_forward_request(&message).await).await }
    };
    let reached = || {
        target
            .request_count
            .load(Ordering::SeqCst)
    };
    let last = || {
        target
            .last_request_rx
            .borrow()
            .clone()
            .expect("the Target was called")
    };

    let enforced: &'static CredentialPolicyConfig = Box::leak(Box::new(CredentialPolicyConfig {
        target_source_auth: RuleMode::Enforce,
        ..Default::default()
    }));
    let warned: &'static CredentialPolicyConfig = Box::leak(Box::default());
    for policy in [warned, enforced] {
        TEST_CREDENTIAL_POLICY
            .scope(policy, async {
                let cases = [
                    (&default, "GET", "/.well-known/agent-card.json", "/.well-known/agent-card.json", true),
                    (&custom, "GET", "/custom/card.json", "/custom/card.json", true),
                    (&custom, "GET", "/.well-known/agent-card.json", "/custom/card.json", true),
                    (&default, "GET", "/discovery", "/discovery", false),
                    (&default, "GET", "/.well-known/agent.json", "/.well-known/agent.json", false),
                    (&default, "GET", "/a/.well-known/agent-card.json", "/a/.well-known/agent-card.json", false),
                    (&default, "GET", "/.well-known/agent-card.json?x=1", "/.well-known/agent-card.json", false),
                    (&default, "HEAD", "/.well-known/agent-card.json", "/.well-known/agent-card.json", false),
                    (&custom, "GET", "/discovery", "/custom/card.json", false),
                ];
                for (surface, method, path, reached_path, credential) in cases {
                    let before = reached();
                    let (status, answered) = send(surface, method, path).await;
                    let case = format!(
                        "{:?} {} {method} {path}: {status} {answered}",
                        policy.target_source_auth, surface.surface_id
                    );
                    assert_eq!(reached(), before + 1, "{case}");
                    let request = last();
                    assert_eq!((request.method.as_str(), request.path.as_str()), (method, reached_path), "{case}");
                    assert_eq!(
                        request
                            .headers
                            .get("x-target-key")
                            .map(String::as_str),
                        credential.then_some("target-secret"),
                        "{case}: {:?}",
                        request.headers
                    );
                }
            })
            .await;
    }
}
