use super::helpers;
use helpers::{GatewayHarness, MockServer};
use serde_json::json;

const AGENT_IDENTITY_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";
const AGENT_IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
const HEADER_METADATA_URI: &str = "https://fabric.affinidi.io/extensions/header-metadata/v1";
const IDENTITY_BINDING_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-binding/v1";
const A2A_PROXY_PARITY_ID: &str = "entra-parity-proxy";
const PARITY_ENTRA_AGENT_ID: &str = "agent-123";
const PARITY_CLIENT_TENANT_ID: &str = "tenant-456";

/// Returns true if `v` is a valid Verifiable Presentation — either a compact
/// JWT string (three base64url segments), a JSON string containing a VP object,
/// or a direct JSON-LD VP object with a `proof`.
fn write_api_key_secret(
    storage_path: &str,
    secret_id: &str,
    value: &str,
) {
    use crate::secrets::SecretsStore;

    let store = crate::secrets::FilesystemSecretsStore::new(storage_path).expect("create secrets store");
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            store
                .create(crate::secrets::CreateSecretRequest {
                    tenant_id: None,
                    name: "Slice 10 source API key".to_string(),
                    secret_id: secret_id.to_string(),
                    description: Some("component-test source auth secret".to_string()),
                    value: value.to_string(),
                    secret_type: "ApiKey".to_string(),
                    tags: vec!["component-test".to_string()],
                })
                .await
                .expect("create source auth secret");
        })
    });
}

fn write_entra_a2a_proxy_fixture(temp_dir: &std::path::Path) {
    let proxy_dir = temp_dir.join("a2a_proxies");
    std::fs::create_dir_all(&proxy_dir).expect("create A2A proxy fixture dir");
    let now = chrono::Utc::now().to_rfc3339();
    std::fs::write(
        proxy_dir.join(format!("{A2A_PROXY_PARITY_ID}.json")),
        json!({
            "id": A2A_PROXY_PARITY_ID,
            "name": "Entra parity proxy",
            "description": "A2A Proxy identity parity fixture",
            "status": "active",
            "backend": {
                "kind": "copilot_direct_line",
                "secret_id": "unused-direct-line-secret",
                "credential_mode": "secret",
                "base_url": "http://127.0.0.1/directline",
                "timeout_secs": 5,
                "poll_interval_ms": 100,
                "max_poll_attempts": 3
            },
            "agent_card": {
                "name": "Entra parity proxy",
                "description": "A2A Proxy identity parity fixture"
            },
            "agent_identity": {
                "type": "entra_agent",
                "entra_agent_id": PARITY_ENTRA_AGENT_ID,
                "client_tenant_id": PARITY_CLIENT_TENANT_ID
            },
            "created_at": now,
            "updated_at": now
        })
        .to_string(),
    )
    .expect("write A2A proxy fixture");
}

fn configure_header_metadata_inbound_identity_surface(
    surface: &mut crate::config::agent_surface::AgentSurface,
    require_source_auth: bool,
) {
    surface
        .access_point
        .header_metadata_mapping = Some(crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
        headers: vec![
            crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                header: "x-ms-entra-agent-id".to_string(),
                field: "entra_agent_id".to_string(),
            },
            crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                header: "x-ms-client-tenant-id".to_string(),
                field: "client_tenant_id".to_string(),
            },
            crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                header: "x-ms-client-session-id".to_string(),
                field: "session_id".to_string(),
            },
        ],
        ..Default::default()
    });
    surface.identity_slots.inbound = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
        crate::source_auth::models::PayloadExtractionConfig {
            extension_uri: Some(HEADER_METADATA_URI.to_string()),
            meta_field: "agentIdentity".to_string(),
            fields: vec!["entra_agent_id".to_string(), "client_tenant_id".to_string()],
            json_schema: Some(crate::config::header_metadata_mapping::copilot_header_metadata_identity_schema()),
            extension_rules: None,
            strip_raw_meta: false,
        },
    ));
    surface
        .target
        .identity_injection
        .inject_vp = true;
    if require_source_auth {
        surface
            .access_point
            .caller_authentication = Some(crate::config::agent_surface::CallerAuthentication {
            methods: vec![crate::source_auth::SourceAuthConfig::ApiKey(crate::source_auth::models::ApiKeyAuthConfig {
                extraction: crate::source_auth::models::CredentialExtraction::HttpHeader {
                    field: "x-api-key".to_string(),
                },
                secret_id: "slice10-source-key".to_string(),
            })],
        });
    }
}

fn a2a_request() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": {
            "message": {
                "role": "user",
                "messageId": "msg-fixture",
                "parts": [{ "kind": "text", "text": "hi" }]
            }
        }
    })
}

fn find_did(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if s.starts_with("did:") => Some(s.clone()),
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(find_did),
        serde_json::Value::Object(map) => map
            .get("holder")
            .and_then(|value| value.as_str())
            .filter(|value| value.starts_with("did:"))
            .map(ToString::to_string)
            .or_else(|| {
                map.get("id")
                    .and_then(|value| value.as_str())
                    .filter(|value| value.starts_with("did:"))
                    .map(ToString::to_string)
            })
            .or_else(|| {
                map.values()
                    .find_map(find_did)
            }),
        _ => None,
    }
}

fn decode_jwt_payload(jwt: &str) -> Option<serde_json::Value> {
    use base64::Engine as _;

    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn agent_card_credential_did(card: &serde_json::Value) -> String {
    let extensions = card["capabilities"]["extensions"]
        .as_array()
        .expect("agent card capabilities.extensions should be an array");
    let credential = extensions
        .iter()
        .find(|ext| {
            ext.get("uri")
                .and_then(|uri| uri.as_str())
                == Some(AGENT_IDENTITY_CREDENTIAL_URI)
        })
        .expect("agent card should contain credential extension");
    let params = credential["params"]
        .as_object()
        .expect("credential extension should contain params");
    assert!(
        is_valid_vp(&params["verifiablePresentation"]),
        "agent-card credential should contain a valid VP, got {params:?}"
    );
    params["did"]
        .as_str()
        .filter(|did| did.starts_with("did:"))
        .expect("agent-card credential should expose did")
        .to_string()
}

fn forwarded_binding_did(h: &GatewayHarness) -> String {
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");
    let forwarded: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body is not valid JSON");
    let message = &forwarded["params"]["message"];
    let extensions = message["extensions"]
        .as_array()
        .expect("forwarded message should have an extensions array");
    assert!(
        extensions
            .iter()
            .any(|ext| ext.as_str() == Some(IDENTITY_BINDING_URI)),
        "forwarded extensions should contain identity binding URI, got {extensions:?}"
    );
    let credential = message["metadata"][IDENTITY_BINDING_URI]
        .as_object()
        .expect("forwarded metadata should contain identity-binding object");
    assert!(
        is_valid_vp(&credential["verifiablePresentation"]),
        "forwarded binding should contain a valid VP, got {credential:?}"
    );
    let vp = &credential["verifiablePresentation"];
    if let Some(did) = find_did(vp) {
        return did;
    }
    if let Some(vp_str) = vp.as_str() {
        if let Ok(json_vp) = serde_json::from_str::<serde_json::Value>(vp_str)
            && let Some(did) = find_did(&json_vp)
        {
            return did;
        }
        if let Some(payload) = decode_jwt_payload(vp_str)
            && let Some(did) = find_did(&payload)
        {
            return did;
        }
    }
    panic!("forwarded binding VP should expose a DID, got {credential:?}")
}

fn is_valid_vp(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => {
            // Compact JWT
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() == 3
                && parts
                    .iter()
                    .all(|p| !p.is_empty())
            {
                return true;
            }
            // JSON-serialized VP object
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(s) {
                return obj.is_object() && obj.get("proof").is_some() && obj.get("type").is_some();
            }
            false
        }
        serde_json::Value::Object(obj) => obj.contains_key("proof") && obj.contains_key("type"),
        _ => false,
    }
}

// ── Outbound ─────────────────────────────────────────────────────────────────

/// Outbound A2A: when `managed_identity` is enabled the gateway should
/// replace `agent-identity/v1` with `agent-identity-credential/v1` carrying
/// a signed VP before forwarding the request to the external agent.
#[tokio::test(flavor = "multi_thread")]
async fn outbound_a2a_identity_credential_injected() {
    //
    // Given — a channel with managed_identity enabled
    //
    let h = GatewayHarness::start_with_outbound(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let outbound_url = h
        .outbound_url
        .as_ref()
        .expect("outbound_url must be set");

    // A2A JSON-RPC request carrying agent-identity/v1
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "extensions": [AGENT_IDENTITY_URI],
                "metadata": {
                    AGENT_IDENTITY_URI: {
                        "softwareInfo": { "name": "test-agent", "version": "1.0" },
                        "cloudProvider": "local"
                    }
                }
            }
        }
    });

    //
    // When — the request is sent through the outbound pipeline
    //
    let resp = client
        .post(format!("{}/outbound/smoke/target/rpc", outbound_url))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await
        .expect("outbound request failed");

    assert_eq!(resp.status(), 200, "expected 200 from gateway, got {}", resp.status());

    //
    // Then — the forwarded body has agent-identity-credential/v1 instead of agent-identity/v1
    //
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");

    let forwarded: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body is not valid JSON");

    let message = &forwarded["params"]["message"];

    // extensions array: credential URI present, raw identity URI removed
    let extensions = message["extensions"]
        .as_array()
        .expect("extensions should be an array");
    let ext_strings: Vec<&str> = extensions
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    assert!(
        ext_strings.contains(&AGENT_IDENTITY_CREDENTIAL_URI),
        "extensions should contain credential URI, got: {ext_strings:?}"
    );
    assert!(
        !ext_strings.contains(&AGENT_IDENTITY_URI),
        "extensions should NOT contain raw identity URI, got: {ext_strings:?}"
    );

    // metadata: credential object present with VP JWT
    let metadata = message["metadata"]
        .as_object()
        .expect("metadata should be an object");
    assert!(!metadata.contains_key(AGENT_IDENTITY_URI), "metadata should NOT contain raw identity key");
    let credential = metadata
        .get(AGENT_IDENTITY_CREDENTIAL_URI)
        .expect("metadata should contain credential key");
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "verifiablePresentation should be a valid VP, got: {vp}");

    let did = credential["did"]
        .as_str()
        .expect("credential should have did");
    assert!(did.starts_with("did:"), "did should start with 'did:', got: {did}");
}

// ── Inbound ──────────────────────────────────────────────────────────────────

/// Inbound A2A: when `managed_identity` is enabled, the protected agent's
/// response carrying `agent-identity/v1` should be transformed — the gateway
/// replaces it with `agent-identity-credential/v1` before returning to the
/// external caller.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_identity_credential_injected_in_response() {
    //
    // Given — mock "protected agent" returns a response with agent-identity/v1
    //
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "backend-agent", "version": "2.0" },
                    "cloudProvider": "local"
                }
            }
        }
    });

    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let client = reqwest::Client::new();

    // The inbound request from the external agent carries NO identity extension.
    // Step 7 (extension inspection) is purely observability — managed_identity
    // only governs the response path (Step 12), so callers are not required to
    // include extensions.
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": {
            "message": {
                "role": "user",
                "messageId": "msg-fixture",
                "parts": [
                    { "kind": "text", "text": "Hello from external agent" }
                ]
            }
        }
    });

    //
    // When — an external agent sends a request through the inbound pipeline
    //
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());

    //
    // Then — the request was forwarded to the protected agent with the body intact,
    // and the response has agent-identity-credential/v1Response Message from responder:
    //
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");
    let forwarded: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body is not valid JSON");
    let forwarded_parts = forwarded["params"]["message"]["parts"]
        .as_array()
        .expect("forwarded message should have parts");
    assert_eq!(forwarded_parts.len(), 1, "should forward exactly one part");
    assert_eq!(
        forwarded_parts[0]["text"]
            .as_str()
            .unwrap(),
        "Hello from external agent",
        "forwarded text should match the original request"
    );

    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("response body is not JSON");

    // The mock returns a Message response (kind: "message"), so extensions
    // and metadata live directly on result.
    let result = &resp_body["result"];

    // extensions array: credential URI present, raw identity URI removed
    let extensions = result["extensions"]
        .as_array()
        .expect("extensions should be an array in response");
    let ext_strings: Vec<&str> = extensions
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    assert!(
        ext_strings.contains(&AGENT_IDENTITY_CREDENTIAL_URI),
        "response extensions should contain credential URI, got: {ext_strings:?}"
    );
    assert!(
        !ext_strings.contains(&AGENT_IDENTITY_URI),
        "response extensions should NOT contain raw identity URI, got: {ext_strings:?}"
    );

    // metadata: credential with signed VP JWT
    let metadata = result["metadata"]
        .as_object()
        .expect("metadata should be an object in response");
    assert!(!metadata.contains_key(AGENT_IDENTITY_URI), "response metadata should NOT contain raw identity key");
    let credential = metadata
        .get(AGENT_IDENTITY_CREDENTIAL_URI)
        .expect("response metadata should contain credential key");
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "verifiablePresentation should be a valid VP, got: {vp}");

    let did = credential["did"]
        .as_str()
        .expect("credential should have did");
    assert!(did.starts_with("did:"), "did should start with 'did:', got: {did}");
}

/// Sends one inbound A2A request to an identity surface whose protected agent
/// answers with `agent_response`, and returns the gateway's response body.
async fn inbound_response_through_identity_surface(
    agent_response: serde_json::Value,
    method: &str,
    request_message: serde_json::Value,
    a2a_version: Option<&str>,
) -> serde_json::Value {
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;
    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;
    let mut request = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json");
    if let Some(version) = a2a_version {
        request = request.header("A2A-Version", version);
    }
    let body = json!({ "jsonrpc": "2.0", "method": method, "id": 1, "params": { "message": request_message } });
    let resp = request
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await
        .expect("inbound request failed");
    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());
    resp.json()
        .await
        .expect("response body is not JSON")
}

fn identity_credential_on(message: &serde_json::Value) -> &serde_json::Value {
    let extensions: Vec<&str> = message["extensions"]
        .as_array()
        .expect("extensions should be an array")
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    assert!(
        extensions.contains(&AGENT_IDENTITY_CREDENTIAL_URI) && !extensions.contains(&AGENT_IDENTITY_URI),
        "the raw identity extension should be replaced by the credential, got: {extensions:?}"
    );
    assert!(
        message["metadata"]
            .get(AGENT_IDENTITY_URI)
            .is_none(),
        "raw identity metadata should be removed"
    );
    let credential = &message["metadata"][AGENT_IDENTITY_CREDENTIAL_URI];
    assert!(
        is_valid_vp(&credential["verifiablePresentation"]),
        "credential should carry a valid VP, got: {credential}"
    );
    credential
}

/// Inbound A2A: a v1.0 `SendMessage` result wraps its Task in `result.task`
/// (`SendMessageResponse`). The protected agent's identity on that task's status
/// message is resolved and replaced by the credential exactly as for the bare
/// v0.3 Task a `message/send` returns.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_v1_task_reply_gets_the_same_credential_as_v03_task_reply() {
    let identity = json!({
        "softwareInfo": { "name": "backend-agent", "version": "2.0" },
        "cloudProvider": "local"
    });

    let v03_reply = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "task",
            "id": "task-1",
            "contextId": "ctx-1",
            "status": {
                "state": "completed",
                "message": {
                    "kind": "message",
                    "messageId": "msg-001",
                    "role": "agent",
                    "parts": [{ "kind": "text", "text": "response" }],
                    "extensions": [AGENT_IDENTITY_URI],
                    "metadata": { AGENT_IDENTITY_URI: identity.clone() }
                }
            }
        }
    });
    let v1_reply = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "task": {
                "id": "task-1",
                "contextId": "ctx-1",
                "status": {
                    "state": "TASK_STATE_COMPLETED",
                    "message": {
                        "messageId": "msg-001",
                        "role": "ROLE_AGENT",
                        "parts": [{ "text": "response" }],
                        "extensions": [AGENT_IDENTITY_URI],
                        "metadata": { AGENT_IDENTITY_URI: identity }
                    }
                }
            }
        }
    });

    let v03_body = inbound_response_through_identity_surface(
        v03_reply,
        "message/send",
        json!({ "kind": "message", "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] }),
        None,
    )
    .await;
    let v1_body = inbound_response_through_identity_surface(
        v1_reply,
        "SendMessage",
        json!({ "role": "ROLE_USER", "messageId": "m-1", "parts": [{ "text": "hi" }] }),
        Some("1.0"),
    )
    .await;

    for credential in [
        identity_credential_on(&v03_body["result"]["status"]["message"]),
        identity_credential_on(&v1_body["result"]["task"]["status"]["message"]),
    ] {
        let did = credential["did"]
            .as_str()
            .expect("credential should have a did");
        assert!(did.starts_with("did:"), "did should start with 'did:', got: {did}");
    }
    assert!(
        v1_body["result"]
            .get("status")
            .is_none(),
        "the v1.0 task wrapper should be kept as sent"
    );
}

/// Inbound A2A: when a wrapped v1.0 task carries the protected agent's identity
/// only on an artifact, the identity still resolves (so the reply is not refused),
/// but there is no message to sign it into: the artifact keeps its raw extension
/// and no credential is added.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_v1_task_reply_with_artifact_identity_is_served_unsigned() {
    let artifact = json!({
        "artifactId": "answer",
        "parts": [{ "text": "response" }],
        "extensions": [AGENT_IDENTITY_URI],
        "metadata": { AGENT_IDENTITY_URI: { "softwareInfo": { "name": "backend-agent", "version": "2.0" }, "cloudProvider": "local" } }
    });
    let v1_reply = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "task": { "id": "task-1", "status": { "state": "TASK_STATE_COMPLETED" }, "artifacts": [artifact.clone()] } }
    });

    let body = inbound_response_through_identity_surface(
        v1_reply,
        "SendMessage",
        json!({ "role": "ROLE_USER", "messageId": "m-1", "parts": [{ "text": "hi" }] }),
        Some("1.0"),
    )
    .await;

    assert_eq!(body["result"]["task"]["artifacts"], json!([artifact]));
    assert!(
        !body
            .to_string()
            .contains(AGENT_IDENTITY_CREDENTIAL_URI),
        "no credential should be added, got: {body}"
    );
}

// ── Agent Card ───────────────────────────────────────────────────────────────

/// Inbound agent card: when `managed_identity` is enabled, the agent card
/// served by the gateway should have `agent-identity-credential/v1` (with a
/// signed VP) instead of the raw `agent-identity/v1` that the protected
/// agent publishes.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_agent_card_has_credential_extension() {
    //
    // Given — mock "protected agent" publishes an agent card with agent-identity/v1
    //
    let agent_card = json!({
        "name": "test-agent",
        "url": "http://example.com/a2a",
        "version": "1.0.0",
        "capabilities": {
            "extensions": [
                {
                    "uri": AGENT_IDENTITY_URI,
                    "params": {
                        "softwareInfo": { "name": "backend-agent", "version": "2.0" },
                        "cloudProvider": "local"
                    }
                }
            ]
        }
    });

    let mock = MockServer::start_with_response(serde_json::to_string(&agent_card).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let client = reqwest::Client::new();

    // Derive the agent card URL from the gateway URL (replace /rpc with /.well-known/agent-card.json)
    let agent_card_url = h
        .gateway_url
        .replace("/rpc", "/.well-known/agent-card.json");

    //
    // When — an external agent fetches the agent card through the gateway
    //
    let resp = client
        .get(&agent_card_url)
        .send()
        .await
        .expect("agent card request failed");

    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());

    //
    // Then — the agent card has agent-identity-credential/v1 instead of agent-identity/v1
    //
    let card: serde_json::Value = resp
        .json()
        .await
        .expect("agent card response is not JSON");

    let extensions = card["capabilities"]["extensions"]
        .as_array()
        .expect("capabilities.extensions should be an array");

    // Collect URIs
    let uris: Vec<&str> = extensions
        .iter()
        .filter_map(|ext| {
            ext.get("uri")
                .and_then(|u| u.as_str())
        })
        .collect();

    assert!(
        uris.contains(&AGENT_IDENTITY_CREDENTIAL_URI),
        "agent card extensions should contain credential URI, got: {uris:?}"
    );
    assert!(
        !uris.contains(&AGENT_IDENTITY_URI),
        "agent card extensions should NOT contain raw identity URI, got: {uris:?}"
    );

    // Find the credential extension and verify it has a valid VP
    let credential_ext = extensions
        .iter()
        .find(|ext| {
            ext.get("uri")
                .and_then(|u| u.as_str())
                == Some(AGENT_IDENTITY_CREDENTIAL_URI)
        })
        .expect("credential extension should exist");

    let params = credential_ext
        .get("params")
        .expect("credential extension should have params");

    let vp = &params["verifiablePresentation"];
    assert!(is_valid_vp(vp), "verifiablePresentation should be a valid VP, got: {vp}");

    let did = params["did"]
        .as_str()
        .expect("credential params should have did");
    assert!(did.starts_with("did:"), "did should start with 'did:', got: {did}");
}

// ── Extra fields filtering ───────────────────────────────────────────────────

/// Inbound A2A: fields NOT marked with `x-identity: true` in the schema must
/// be ignored when computing the identity hash. Changing only a non-schema
/// field between two responses (while keeping the x-identity fields constant)
/// must produce the **same** DID.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_extra_identity_fields_do_not_affect_did() {
    //
    // Given — two responses from the protected agent that share the same
    // x-identity fields but differ in a non-schema field ("region").
    //
    let response_with_extra_a = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "backend-agent", "version": "2.0" },
                    "cloudProvider": "local",
                    "region": "eu-west-1"
                }
            }
        }
    });

    let response_with_extra_b = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-002",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "backend-agent", "version": "2.0" },
                    "cloudProvider": "local",
                    "region": "us-east-1"
                }
            }
        }
    });

    let (mock, resp_tx) =
        helpers::MockServer::start_with_response_channel(serde_json::to_string(&response_with_extra_a).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": {
            "message": {
                "role": "user",
                "messageId": "msg-fixture",
                "parts": [{ "kind": "text", "text": "Hello" }]
            }
        }
    });

    //
    // When — first request: response has region=eu-west-1
    //
    let resp1 = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("first request failed");
    assert_eq!(resp1.status(), 200, "first request should succeed");

    let body1: serde_json::Value = resp1
        .json()
        .await
        .expect("body1 not JSON");
    let did1 = body1["result"]["metadata"][AGENT_IDENTITY_CREDENTIAL_URI]["did"]
        .as_str()
        .expect("did1 should be present")
        .to_string();
    assert!(did1.starts_with("did:"), "did1 should be a DID: {did1}");

    // Update mock to return a different value for the extra field
    resp_tx
        .send(serde_json::to_string(&response_with_extra_b).unwrap())
        .expect("failed to update mock response");

    //
    // When — second request: response has region=us-east-1 (different extra field)
    //
    let resp2 = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("second request failed");
    assert_eq!(resp2.status(), 200, "second request should succeed");

    let body2: serde_json::Value = resp2
        .json()
        .await
        .expect("body2 not JSON");
    let did2 = body2["result"]["metadata"][AGENT_IDENTITY_CREDENTIAL_URI]["did"]
        .as_str()
        .expect("did2 should be present")
        .to_string();

    //
    // Then — both DIDs must be identical: the non-schema "region" field
    // must have been ignored by the identity hash computation.
    //
    assert_eq!(
        did1, did2,
        "Extra fields not in schema should not affect identity. \
         DID1={did1} (region=eu-west-1), DID2={did2} (region=us-east-1)"
    );
}

// ── Inbound identity validation hard-fail ────────────────────────────────────

/// Inbound A2A: when the request carries the `agent-identity/v1` extension
/// but the payload is missing a field marked `x-identity: true` in the
/// channel schema, the gateway MUST reject the request with HTTP 422 and an
/// `application/problem+json` body identifying the `inbound_identity` slot.
///
/// Regression guard for the bug where this failure was downgraded to a
/// `warn!` log and the request was forwarded without a resolved DID.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_a2a_identity_schema_violation_returns_422() {
    //
    // Given — a mock protected agent that should NEVER be called, and a
    // channel with identity extraction enabled (build_identity_channel marks
    // `softwareInfo.name`, `softwareInfo.version`, and `cloudProvider` as
    // x-identity fields).
    //
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "kind": "message", "messageId": "msg-001", "role": "agent", "parts": [] }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        let mut surface = helpers::build_identity_channel();
        // Add inbound slot so the gateway validates the caller's identity extension.
        let inbound_slot = serde_json::json!({
            "type": "payload_extraction",
            "meta_field": "agentIdentity",
            "extension_rules": {
                "json_schema": {
                    "type": "object",
                    "properties": {
                        "softwareInfo": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string", "x-identity": true },
                                "version": { "type": "string", "x-identity": true }
                            }
                        },
                        "cloudProvider": { "type": "string", "x-identity": true }
                    }
                }
            }
        });
        let inbound: crate::source_auth::ManagedIdentityConfig = serde_json::from_value(inbound_slot).unwrap();
        surface.identity_slots.inbound = Some(inbound);
        gw_config.surfaces = vec![surface];
    })
    .await;

    let client = reqwest::Client::new();

    //
    // When — the external caller sends a request carrying the identity
    // extension with a payload missing the `cloudProvider` x-identity field
    // (simulating a typo such as `cloudPrvider`).
    //
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": {
            "message": {
                "role": "user",
                "messageId": "msg-fixture",
                "parts": [{ "kind": "text", "text": "hi" }],
                "extensions": [AGENT_IDENTITY_URI],
                "metadata": {
                    AGENT_IDENTITY_URI: {
                        "softwareInfo": { "name": "caller-agent", "version": "1.0" },
                        "cloudPrvider": "local"
                    }
                }
            }
        }
    });

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    //
    // Then — the gateway responds 422 with problem+json identifying the
    // inbound_identity slot, and the protected agent was never contacted.
    //
    assert_eq!(resp.status(), 422, "expected 422 Unprocessable Entity, got {}", resp.status());
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(content_type.contains("application/problem+json"), "expected application/problem+json, got {content_type}");

    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response body is not JSON");
    assert_eq!(body["status"], 422, "problem.status mismatch: {body}");
    assert_eq!(body["code"], "identity_validation_failed", "problem.code mismatch: {body}");
    assert_eq!(body["slot"], "inbound_identity", "problem.slot mismatch: {body}");
    let detail = body["detail"]
        .as_str()
        .expect("problem.detail should be a string");
    assert!(
        detail.contains("cloudProvider"),
        "problem.detail should mention the missing x-identity field, got: {detail}"
    );

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "protected agent must not be called when inbound identity validation fails"
    );
}

/// Inbound A2A: a surface that configures ONLY a protected (MA→AP) Server
/// Identity and NO inbound (CA→AP) identity MUST NOT validate a
/// caller-supplied `agent-identity/v1` extension against the protected schema.
///
/// Regression guard: because `ctx.identity_selector` is compiled
/// from the first available slot (inbound → protected → external), a
/// protected-only surface carries the protected schema in that selector. Before
/// the fix, when a caller happened to include an identity extension whose
/// payload did not match the protected schema, the request path validated it
/// and returned 422 `identity_validation_failed` / `slot=inbound_identity` —
/// even though there is no identity element on the CA→AP leg. The caller must
/// be allowed through (the protected leg is validated on the response only).
#[tokio::test(flavor = "multi_thread")]
async fn inbound_caller_identity_not_validated_without_inbound_slot() {
    //
    // Given — a protected-only surface (build_identity_channel has a protected
    // slot and NO inbound slot) and a mock protected agent whose response
    // carries an agent-identity/v1 payload that DOES satisfy the protected
    // schema (so the response path resolves cleanly).
    //
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "backend-agent", "version": "2.0" },
                    "cloudProvider": "local"
                }
            }
        }
    });

    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        // build_identity_channel configures ONLY identity_slots.protected — no inbound slot.
        gw_config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let client = reqwest::Client::new();

    //
    // When — the caller sends a request that DOES carry an agent-identity/v1
    // extension whose payload does NOT match the protected schema (missing the
    // required `cloudProvider` x-identity field). This is the exact payload the
    // inbound-slot test rejects; here there is no inbound slot, so it must pass.
    //
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": {
            "message": {
                "role": "user",
                "messageId": "msg-fixture",
                "parts": [{ "kind": "text", "text": "hi" }],
                "extensions": [AGENT_IDENTITY_URI],
                "metadata": {
                    AGENT_IDENTITY_URI: {
                        "softwareInfo": { "name": "caller-agent", "version": "1.0" },
                        "cloudPrvider": "local"
                    }
                }
            }
        }
    });

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    //
    // Then — the caller identity is NOT enforced: the gateway forwards to the
    // protected agent and returns 200 (not 422).
    //
    assert_eq!(resp.status(), 200, "protected-only surface must not validate caller identity; got {}", resp.status());

    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_some(),
        "protected agent must be contacted — the caller's mismatched identity must not short-circuit the request"
    );

    // And the response carries the protected agent's identity credential,
    // proving the response path still resolved the protected Server Identity.
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("response body is not JSON");
    let metadata = resp_body["result"]["metadata"]
        .as_object()
        .expect("metadata should be an object in response");
    assert!(
        metadata.contains_key(AGENT_IDENTITY_CREDENTIAL_URI),
        "response should carry the protected agent-identity credential, got: {metadata:?}"
    );
}

// ── Per-TP outbound identity validation ──────────────────────────────────────

/// Outbound MA→TP: when the **per-TP** `managed_identity` declares a required
/// `x-identity` field and the MA's outbound request body does not contain it,
/// the gateway MUST reject the outbound request (it must NOT silently forward
/// it to the TP target). Regression guard for the bug where the outbound
/// identity step only consulted the channel-level `managed_identity` and
/// skipped per-TP rules entirely.
#[tokio::test(flavor = "multi_thread")]
async fn outbound_per_tp_identity_missing_field_is_rejected() {
    //
    // Given — a channel whose **per-TP** managed_identity requires the
    // x-identity field `agentIdentity.fish`. The channel itself has no
    // managed_identity.
    //
    let h = GatewayHarness::start_with_outbound(|_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_per_tp_identity_channel()];
    })
    .await;

    let client = reqwest::Client::new();
    let outbound_url = h
        .outbound_url
        .as_ref()
        .expect("outbound_url must be set");

    //
    // When — the MA sends an outbound A2A request that does NOT include
    // any `agentIdentity` payload at all.
    //
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": "msg-fixture",
                "parts": [{ "kind": "text", "text": "ping" }]
            }
        }
    });

    let resp = client
        .post(format!("{}/outbound/smoke/target/rpc", outbound_url))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await
        .expect("outbound request failed");

    //
    // Then — the gateway MUST NOT return success, and the TP target must
    // not have been called.
    //
    let status = resp.status();
    assert!(
        status.is_client_error() || status.is_server_error(),
        "expected a 4xx/5xx rejection when per-TP identity rule is violated, got {status}"
    );
    assert!(
        h.mock
            .last_request_rx
            .borrow()
            .is_none(),
        "TP target must not be called when per-TP identity validation fails"
    );
}

// ── Inbound from_jwt_claim (Entra Agent ID) ──────────────────────────────────

/// Inbound A2A with `identity_slots.protected = from_jwt_claim`: the gateway
/// derives the protected agent DID from the validated `oid` claim of the
/// caller's JWT (not from the response body), then injects the credential
/// extension into the response.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_from_jwt_claim_derives_did_from_oid() {
    use helpers::jwt::{JwksFixture, now_secs, setup_jwt_claim_managed_identity, sign_jwt};

    let fixture = JwksFixture::start().await;

    // Mock protected agent returns an A2A message response declaring the raw
    // identity extension; the gateway swaps it for the credential extension.
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "backend-agent", "version": "2.0" },
                    "cloudProvider": "local"
                }
            }
        }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let issuer = fixture.issuer.clone();
    let h = GatewayHarness::start_with_outbound_mock(mock, |temp_dir, gw_config, _| {
        setup_jwt_claim_managed_identity(&fixture, temp_dir, gw_config);
    })
    .await;

    let token = sign_jwt(
        json!({
            "iss": issuer,
            "sub": "app-registration-123",
            "oid": "11111111-2222-3333-4444-555555555555",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        "e2e-test-key",
    );

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": { "message": {
                "role": "user",
                "messageId": "msg-fixture", "parts": [{ "kind": "text", "text": "hi" }] } }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());

    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("response body is not JSON");
    let metadata = resp_body["result"]["metadata"]
        .as_object()
        .expect("metadata should be an object in response");
    let credential = metadata
        .get(AGENT_IDENTITY_CREDENTIAL_URI)
        .expect("response metadata should contain credential key");
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "verifiablePresentation should be a valid VP, got: {vp}");
    let did = credential["did"]
        .as_str()
        .expect("credential should have did");
    assert!(did.starts_with("did:"), "did should start with 'did:', got: {did}");
}

/// Inbound A2A with `from_jwt_claim`: a JWT that passes signature/issuer
/// verification but lacks the configured `oid` claim must be rejected with
/// HTTP 422 (identity validation failed) — the DID cannot be derived.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_from_jwt_claim_missing_oid_rejected() {
    use helpers::jwt::{JwksFixture, now_secs, setup_jwt_claim_managed_identity, sign_jwt};

    let fixture = JwksFixture::start().await;

    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "kind": "message", "messageId": "msg-001", "role": "agent", "parts": [] }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let issuer = fixture.issuer.clone();
    let h = GatewayHarness::start_with_outbound_mock(mock, |temp_dir, gw_config, _| {
        setup_jwt_claim_managed_identity(&fixture, temp_dir, gw_config);
    })
    .await;

    // Valid token (good signature, issuer, exp) but WITHOUT the `oid` claim.
    let token = sign_jwt(
        json!({
            "iss": issuer,
            "sub": "app-registration-123",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        "e2e-test-key",
    );

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": { "message": {
                "role": "user",
                "messageId": "msg-fixture", "parts": [{ "kind": "text", "text": "hi" }] } }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 422, "expected 422 for missing oid claim, got {}", resp.status());
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response body is not JSON");
    assert_eq!(body["code"], "identity_validation_failed", "problem.code mismatch: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a2a_proxy_entra_identity_matches_header_metadata_did() {
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "kind": "message", "messageId": "msg-001", "role": "agent", "parts": [] }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |temp_dir, gw_config, bootstrap| {
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            "slice10-source-key",
            "valid",
        );
        write_entra_a2a_proxy_fixture(temp_dir);
        helpers::configure_gateway_route_prefixes(
            bootstrap,
            &[("headers", "headers", "/headers"), ("proxy", "proxy", "/proxy")],
        );

        let mut header_surface = helpers::build_minimal_channel();
        header_surface.surface_id = "header-metadata-parity".to_string();
        header_surface.name = "header metadata parity".to_string();
        header_surface
            .access_point
            .route = "/headers".to_string();
        configure_header_metadata_inbound_identity_surface(&mut header_surface, true);

        let mut proxy_surface = helpers::build_minimal_channel();
        proxy_surface.surface_id = "a2a-proxy-entra-parity".to_string();
        proxy_surface.name = "A2A Proxy Entra parity".to_string();
        proxy_surface
            .access_point
            .route = "/proxy".to_string();
        proxy_surface.target.endpoint = format!("a2a-proxy://{A2A_PROXY_PARITY_ID}");
        proxy_surface
            .target
            .a2a_proxy_id = Some(A2A_PROXY_PARITY_ID.to_string());

        gw_config.surfaces = vec![header_surface, proxy_surface];
    })
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/headers/rpc", h.gateway_base))
        .header("content-type", "application/json")
        .header("x-api-key", "valid")
        .header("x-ms-entra-agent-id", PARITY_ENTRA_AGENT_ID)
        .header("x-ms-client-tenant-id", PARITY_CLIENT_TENANT_ID)
        .header("x-ms-client-session-id", "session-a")
        .body(serde_json::to_string(&a2a_request()).unwrap())
        .send()
        .await
        .expect("inbound header metadata request failed");
    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());
    let header_metadata_did = forwarded_binding_did(&h);

    let resp = client
        .get(format!("{}/proxy/.well-known/agent-card.json", h.gateway_base))
        .send()
        .await
        .expect("A2A Proxy agent-card request failed");
    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());
    let card: serde_json::Value = resp
        .json()
        .await
        .expect("agent-card response should be JSON");
    let a2a_proxy_did = agent_card_credential_did(&card);

    assert_eq!(
        a2a_proxy_did, header_metadata_did,
        "matching Entra Agent ID and Client Tenant ID must resolve to the same DID"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_header_metadata_identity_derives_did_after_source_auth() {
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "kind": "message", "messageId": "msg-001", "role": "agent", "parts": [] }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, bootstrap| {
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            "slice10-source-key",
            "valid",
        );
        let mut surface = helpers::build_minimal_channel();
        configure_header_metadata_inbound_identity_surface(&mut surface, true);
        gw_config.surfaces = vec![surface];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-api-key", "valid")
        .header("x-ms-entra-agent-id", "agent-123")
        .header("x-ms-client-tenant-id", "tenant-456")
        .header("x-ms-client-session-id", "session-a")
        .body(serde_json::to_string(&a2a_request()).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());
    let did = forwarded_binding_did(&h);
    assert!(did.starts_with("did:"), "expected DID from forwarded binding, got {did}");
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_header_metadata_identity_requires_source_auth() {
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "kind": "message", "messageId": "msg-001", "role": "agent", "parts": [] }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        let mut surface = helpers::build_minimal_channel();
        configure_header_metadata_inbound_identity_surface(&mut surface, false);
        gw_config.surfaces = vec![surface];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-ms-entra-agent-id", "agent-123")
        .header("x-ms-client-tenant-id", "tenant-456")
        .body(serde_json::to_string(&a2a_request()).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 422, "expected 422, got {}", resp.status());
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "unauthenticated header-derived identity must not reach target"
    );
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response body should be JSON");
    assert_eq!(body["code"], "identity_validation_failed", "problem body mismatch: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_header_metadata_identity_missing_required_field_returns_422() {
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "kind": "message", "messageId": "msg-001", "role": "agent", "parts": [] }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, bootstrap| {
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            "slice10-source-key",
            "valid",
        );
        let mut surface = helpers::build_minimal_channel();
        configure_header_metadata_inbound_identity_surface(&mut surface, true);
        gw_config.surfaces = vec![surface];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-api-key", "valid")
        .header("x-ms-entra-agent-id", "agent-123")
        .body(serde_json::to_string(&a2a_request()).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 422, "expected 422, got {}", resp.status());
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "schema-invalid header-derived identity must not reach target"
    );
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("response body should be JSON");
    assert_eq!(body["code"], "identity_validation_failed", "problem body mismatch: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_header_metadata_identity_ignores_session_for_stable_did() {
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "kind": "message", "messageId": "msg-001", "role": "agent", "parts": [] }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, bootstrap| {
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            "slice10-source-key",
            "valid",
        );
        let mut surface = helpers::build_minimal_channel();
        configure_header_metadata_inbound_identity_surface(&mut surface, true);
        gw_config.surfaces = vec![surface];
    })
    .await;

    let client = reqwest::Client::new();
    for session in ["session-a", "session-b"] {
        let resp = client
            .post(&h.gateway_url)
            .header("content-type", "application/json")
            .header("x-api-key", "valid")
            .header("x-ms-entra-agent-id", "agent-123")
            .header("x-ms-client-tenant-id", "tenant-456")
            .header("x-ms-client-session-id", session)
            .body(serde_json::to_string(&a2a_request()).unwrap())
            .send()
            .await
            .expect("inbound request failed");
        assert_eq!(resp.status(), 200, "expected 200 for {session}, got {}", resp.status());
    }

    let did_after_second_request = forwarded_binding_did(&h);

    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-api-key", "valid")
        .header("x-ms-entra-agent-id", "agent-123")
        .header("x-ms-client-tenant-id", "tenant-456")
        .header("x-ms-client-session-id", "session-c")
        .body(serde_json::to_string(&a2a_request()).unwrap())
        .send()
        .await
        .expect("inbound request failed");
    assert_eq!(resp.status(), 200, "expected 200 for session-c, got {}", resp.status());
    let did_after_third_request = forwarded_binding_did(&h);

    assert_eq!(
        did_after_second_request, did_after_third_request,
        "session-only metadata changes must not change the derived DID"
    );
}

/// Inbound A2A with `identity_slots.inbound = from_jwt_claim` and `inject_vp`:
/// the gateway derives the *caller* agent's DID from the validated `oid` claim
/// on the **request** leg and injects the identity-binding VP into the request
/// **forwarded upstream** to the target (not the response back to the caller).
/// This is the request-leg counterpart to the protected-slot test above.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_from_jwt_claim_injects_vp_into_forwarded_request() {
    use helpers::jwt::{JwksFixture, now_secs, setup_jwt_claim_inbound_identity, sign_jwt};

    let fixture = JwksFixture::start().await;

    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "kind": "message", "messageId": "msg-001", "role": "agent", "parts": [] }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let issuer = fixture.issuer.clone();
    let h = GatewayHarness::start_with_outbound_mock(mock, |temp_dir, gw_config, _| {
        setup_jwt_claim_inbound_identity(&fixture, temp_dir, gw_config);
    })
    .await;

    let token = sign_jwt(
        json!({
            "iss": issuer,
            "sub": "app-registration-123",
            "oid": "11111111-2222-3333-4444-555555555555",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        "e2e-test-key",
    );

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": { "message": {
                "role": "user",
                "messageId": "msg-fixture", "parts": [{ "kind": "text", "text": "hi" }] } }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());

    // The forwarded request to the target must carry the caller's identity
    // binding VP in `params.message.metadata[binding_uri]`.
    let binding_uri = "https://fabric.affinidi.io/extensions/agent-identity-binding/v1";
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive a request");
    let forwarded: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body is not valid JSON");

    let message = &forwarded["params"]["message"];
    let extensions = message["extensions"]
        .as_array()
        .expect("forwarded message should have an extensions array");
    let ext_strings: Vec<&str> = extensions
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    assert!(
        ext_strings.contains(&binding_uri),
        "forwarded extensions should contain the identity-binding URI, got: {ext_strings:?}"
    );

    let credential = message["metadata"][binding_uri]
        .as_object()
        .expect("forwarded metadata should contain the identity-binding object");
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "forwarded binding should contain a valid VP, got: {vp:?}");
}

/// selector built by `compile_identity_engines_from_managed_identity`.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_from_api_key_derives_did() {
    // `atgk_`-prefixed key derives directly without any store lookup.
    let api_key_id = "atgk_e2e0000000000000000000000000001";

    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "backend-agent", "version": "2.0" },
                    "cloudProvider": "local"
                }
            }
        }
    });
    let mock = MockServer::start_with_response(serde_json::to_string(&agent_response).unwrap()).await;

    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, _| {
        gw_config.surfaces = vec![helpers::build_api_key_identity_channel(api_key_id)];
    })
    .await;

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": { "message": {
                "role": "user",
                "messageId": "msg-fixture", "parts": [{ "kind": "text", "text": "hi" }] } }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 200, "expected 200, got {}", resp.status());

    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("response body is not JSON");
    let metadata = resp_body["result"]["metadata"]
        .as_object()
        .expect("metadata should be an object in response");
    let credential = metadata
        .get(AGENT_IDENTITY_CREDENTIAL_URI)
        .expect("response metadata should contain credential key");
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "verifiablePresentation should be a valid VP, got: {vp}");
    let did = credential["did"]
        .as_str()
        .expect("credential should have did");
    assert!(did.starts_with("did:"), "did should start with 'did:', got: {did}");
}

fn stored_identity_origins(dir: &std::path::Path) -> Vec<(String, Option<String>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    entries
        .filter_map(Result::ok)
        .flat_map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                return stored_identity_origins(&path);
            }
            std::fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .filter(|record| {
                    record
                        .get("identity_hash")
                        .is_some()
                })
                .and_then(|record| {
                    let did = record["did"]
                        .as_str()?
                        .to_string();
                    Some((
                        did,
                        record["origin"]
                            .as_str()
                            .map(String::from),
                    ))
                })
                .into_iter()
                .collect()
        })
        .collect()
}

fn stored_identity_origin(
    dir: &std::path::Path,
    did: &str,
) -> Option<String> {
    stored_identity_origins(dir)
        .into_iter()
        .find(|(stored, _)| stored == did)
        .and_then(|(_, origin)| origin)
}

/// A protected `from_api_key` slot with no inbound slot falls back to the managed slot on
/// inbound requests, so an inbound request reaching the surface first must still record its
/// DID as the managed agent, and the outbound leg must keep using that DID.
#[tokio::test(flavor = "multi_thread")]
async fn managed_api_key_identity_reached_inbound_first_stays_managed() {
    let api_key_id = "atgk_e2e0000000000000000000000000003";
    let agent_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": { AGENT_IDENTITY_URI: { "softwareInfo": { "name": "backend-agent", "version": "2.0" } } }
        }
    });
    let mock = MockServer::start_with_response(agent_response.to_string()).await;
    let mut base_dir = std::path::PathBuf::new();
    let h = GatewayHarness::start_with_outbound_mock(mock, |dir, gw_config, _| {
        base_dir = dir.to_path_buf();
        let mut surface = helpers::build_api_key_identity_channel(api_key_id);
        surface
            .transit
            .as_mut()
            .expect("transit")
            .points[0]
            .identity_injection
            .inject_vp = true;
        gw_config.surfaces = vec![surface];
    })
    .await;
    let client = reqwest::Client::new();
    let message = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": { "message": { "role": "user", "messageId": "msg-1", "parts": [{ "kind": "text", "text": "hi" }] } }
    });

    let inbound = client
        .post(&h.gateway_url)
        .json(&message)
        .send()
        .await
        .expect("inbound request failed");
    assert_eq!(inbound.status(), 200);
    let inbound_body: serde_json::Value = inbound
        .json()
        .await
        .expect("inbound response body is not JSON");
    let did = inbound_body["result"]["metadata"][AGENT_IDENTITY_CREDENTIAL_URI]["did"]
        .as_str()
        .expect("response should carry the managed agent's DID")
        .to_string();
    assert_eq!(stored_identity_origin(&base_dir, &did).as_deref(), Some("managed"));

    let outbound_url = h
        .outbound_url
        .as_ref()
        .expect("outbound_url must be set");
    let outbound = client
        .post(format!("{outbound_url}/outbound/smoke/target/rpc"))
        .json(&message)
        .send()
        .await
        .expect("outbound request failed");
    assert_eq!(outbound.status(), 200);
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock did not receive the outbound request");
    let forwarded: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body is not JSON");
    let metadata = &forwarded["params"]["message"]["metadata"];
    let outbound_credential = [AGENT_IDENTITY_CREDENTIAL_URI, IDENTITY_BINDING_URI]
        .iter()
        .map(|uri| &metadata[*uri])
        .find(|credential| !credential.is_null())
        .unwrap_or_else(|| panic!("forwarded request should carry an identity credential, got {metadata}"));
    assert_eq!(outbound_credential["did"], did.as_str());
    assert_eq!(stored_identity_origin(&base_dir, &did).as_deref(), Some("managed"));
}

/// A DID derived from the inbound slot belongs to the caller, so it is recorded as an
/// external caller even though the same credential mode backs managed identities.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_slot_api_key_identity_is_recorded_as_external_caller() {
    let inbound = json!({ "type": "from_api_key", "api_key_id": "atgk_e2e0000000000000000000000000004" });
    let mut base_dir = std::path::PathBuf::new();
    let h = GatewayHarness::start(|dir, gw_config, _| {
        base_dir = dir.to_path_buf();
        write_caller_verification_policies(dir);
        gw_config.surfaces = vec![inbound_identity_surface(inbound, UNVERIFIED_CALLER_POLICY_ID)];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .json(&a2a_request())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 200);
    let origins: Vec<_> = stored_identity_origins(&base_dir)
        .into_iter()
        .map(|(_, origin)| origin)
        .collect();
    assert_eq!(origins, vec![Some("external_caller".to_string())]);
}

const STATIC_CALLER_DID: &str = "did:web:static-caller.example";
const UNVERIFIED_CALLER_POLICY_ID: &str = "unverified-caller-policy";
const VERIFIED_CALLER_POLICY_ID: &str = "verified-caller-policy";
const SOURCE_AUTH_CALLER_POLICY_ID: &str = "source-auth-caller-policy";

fn write_caller_verification_policies(temp_dir: &std::path::Path) {
    let policies = [
        (
            UNVERIFIED_CALLER_POLICY_ID,
            r#"package surface.policy

default allow := false

allow if {
    startswith(input.agent.did, "did:")
    input.agent.did_verified == false
    input.agent.did_verification == "unverified"
    input.extension_identity.did == input.agent.did
    input.extension_identity.verified == false
    input.extension_identity.verification == "unverified"
}
"#,
        ),
        (
            VERIFIED_CALLER_POLICY_ID,
            r#"package surface.policy

default allow := false

allow if input.agent.did_verified == true
"#,
        ),
        (
            SOURCE_AUTH_CALLER_POLICY_ID,
            r#"package surface.policy

default allow := false

allow if {
    startswith(input.agent.did, "did:")
    input.agent.did_verified == true
    input.agent.did_verification == "source_auth"
    input.extension_identity.verification == "source_auth"
}
"#,
        ),
    ];
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    for (id, rego) in policies {
        let definition = json!({
            "id": id,
            "name": id,
            "description": "Caller identity verification policy",
            "policy_type": "agent_surface",
            "policy": rego,
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        });
        std::fs::write(
            dir.join(format!("{id}.json")),
            serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
        )
        .expect("write policy definition fixture");
    }
}

fn inbound_identity_surface(
    inbound: serde_json::Value,
    policy_id: &str,
) -> crate::config::agent_surface::AgentSurface {
    let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
        "name": "configured-inbound-identity",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a"
        },
        "target": { "endpoint": "inbound_target_placeholder" },
        "identity_slots": { "inbound": inbound }
    }))
    .expect("configured inbound identity surface JSON");
    surface.target.policy = Some(crate::config::agent_surface::PolicyRef {
        policy_definition_id: policy_id.to_string(),
        require_agent_context: false,
    });
    surface
}

async fn send_configured_identity_request(
    inbound: serde_json::Value,
    policy_id: &'static str,
) -> (reqwest::StatusCode, usize) {
    let h = GatewayHarness::start(move |temp_dir, gw_config, _| {
        write_caller_verification_policies(temp_dir);
        gw_config.surfaces = vec![inbound_identity_surface(inbound, policy_id)];
    })
    .await;
    let status = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&a2a_request())
        .send()
        .await
        .expect("inbound request failed")
        .status();
    let forwarded = h
        .mock
        .request_count
        .load(std::sync::atomic::Ordering::SeqCst);
    (status, forwarded)
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_static_identity_reaches_policy_as_unverified() {
    let (status, forwarded) = send_configured_identity_request(
        json!({ "type": "static", "did": STATIC_CALLER_DID }),
        UNVERIFIED_CALLER_POLICY_ID,
    )
    .await;
    assert_eq!(status, 200, "policy must see the static DID as unverified");
    assert_eq!(forwarded, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_static_identity_does_not_satisfy_a_verified_caller_policy() {
    let (status, forwarded) = send_configured_identity_request(
        json!({ "type": "static", "did": STATIC_CALLER_DID }),
        VERIFIED_CALLER_POLICY_ID,
    )
    .await;
    assert_eq!(status, 403, "a configured DID must not count as verified");
    assert_eq!(forwarded, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_from_api_key_identity_reaches_policy_as_unverified() {
    let inbound = json!({ "type": "from_api_key", "api_key_id": "atgk_e2e0000000000000000000000000002" });
    let (status, forwarded) = send_configured_identity_request(inbound.clone(), UNVERIFIED_CALLER_POLICY_ID).await;
    assert_eq!(status, 200, "policy must see the API-key-derived DID as unverified");
    assert_eq!(forwarded, 1);

    let (status, forwarded) = send_configured_identity_request(inbound, VERIFIED_CALLER_POLICY_ID).await;
    assert_eq!(status, 403, "an API-key-derived DID must not count as verified");
    assert_eq!(forwarded, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_from_jwt_claim_identity_reaches_policy_as_source_auth() {
    use helpers::jwt::{JwksFixture, now_secs, setup_jwt_claim_inbound_identity, sign_jwt};

    let fixture = JwksFixture::start().await;
    let issuer = fixture.issuer.clone();
    let h = GatewayHarness::start_with_outbound(|temp_dir, gw_config, _| {
        setup_jwt_claim_inbound_identity(&fixture, temp_dir, gw_config);
        write_caller_verification_policies(temp_dir);
        gw_config.surfaces[0]
            .target
            .policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: SOURCE_AUTH_CALLER_POLICY_ID.to_string(),
            require_agent_context: false,
        });
    })
    .await;
    let token = sign_jwt(
        json!({
            "iss": issuer,
            "sub": "app-registration-123",
            "oid": "11111111-2222-3333-4444-555555555555",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        "e2e-test-key",
    );

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&a2a_request())
        .send()
        .await
        .expect("inbound request failed");

    assert_eq!(resp.status(), 200, "policy must see the JWT-claim DID as source-auth verified");
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_credential_identity_is_not_resolved_on_discovery_paths() {
    let inbound = json!({ "type": "from_api_key", "api_key_id": "missing-secret-id" });
    let h = GatewayHarness::start(move |temp_dir, gw_config, _| {
        write_caller_verification_policies(temp_dir);
        gw_config.surfaces = vec![inbound_identity_surface(inbound, UNVERIFIED_CALLER_POLICY_ID)];
    })
    .await;
    let client = reqwest::Client::new();

    let rpc_status = client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .json(&a2a_request())
        .send()
        .await
        .expect("inbound request failed")
        .status();
    assert_eq!(rpc_status, 502, "an unresolvable credential identity must fail the request");

    let discovery_status = client
        .get(
            h.gateway_url
                .replace("/rpc", "/.well-known/ucp"),
        )
        .send()
        .await
        .expect("discovery request failed")
        .status();
    assert_eq!(discovery_status, 200, "discovery must not resolve the caller identity");
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}
