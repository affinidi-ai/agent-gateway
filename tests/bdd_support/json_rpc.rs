pub const MODERN_MCP_PROTOCOL_VERSION: &str = "2026-07-28";

pub fn build_a2a_request_body() -> serde_json::Value {
    build_a2a_message_send_body("g2g-bdd")
}

pub const AGENT_IDENTITY_EXTENSION_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";
pub const AGENT_IDENTITY_CREDENTIAL_EXTENSION_URI: &str =
    "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
pub const AGENT_IDENTITY_BINDING_EXTENSION_URI: &str =
    "https://fabric.affinidi.io/extensions/agent-identity-binding/v1";

/// An identity proof a gateway injected into a forwarded A2A message: the
/// extension URI it was filed under and the `metadata[uri]` object.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityBindingProof {
    pub uri: String,
    pub proof: serde_json::Value,
}

impl IdentityBindingProof {
    /// Read the proof from an A2A `message/send` body as a target received it.
    /// The fabric hop files it under the binding extension; the Transit Point
    /// hop files it under the credential extension.
    pub fn from_forwarded_a2a_body(body: &serde_json::Value) -> Option<Self> {
        let metadata = body.pointer("/params/message/metadata")?;
        [AGENT_IDENTITY_BINDING_EXTENSION_URI, AGENT_IDENTITY_CREDENTIAL_EXTENSION_URI]
            .into_iter()
            .find_map(|uri| {
                metadata
                    .get(uri)
                    .map(|proof| Self {
                        uri: uri.to_string(),
                        proof: proof.clone(),
                    })
            })
    }
}

/// Present a previously captured identity proof in an A2A message, declaring
/// the extension the way the issuing gateway did.
pub fn attach_identity_proof(
    body: &mut serde_json::Value,
    proof: &IdentityBindingProof,
) {
    declare_a2a_message_extension(body, &proof.uri, proof.proof.clone());
}

/// Present the managed agent's own identity payload (`agent-identity/v1`) in
/// an A2A message, the way a managed agent does when its surface derives its
/// identity from the payload.
pub fn attach_agent_identity_payload(body: &mut serde_json::Value) {
    declare_a2a_message_extension(body, AGENT_IDENTITY_EXTENSION_URI, build_mcp_agent_identity_payload());
}

fn declare_a2a_message_extension(
    body: &mut serde_json::Value,
    uri: &str,
    payload: serde_json::Value,
) {
    let message = &mut body["params"]["message"];
    if !message["extensions"].is_array() {
        message["extensions"] = serde_json::json!([]);
    }
    message["extensions"]
        .as_array_mut()
        .expect("extensions array")
        .push(serde_json::json!(uri));
    if !message["metadata"].is_object() {
        message["metadata"] = serde_json::json!({});
    }
    message["metadata"][uri] = payload;
}

pub fn build_a2a_message_send_body(text: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": "bdd-message",
                "parts": [{ "kind": "text", "text": text }]
            }
        }
    })
}

pub fn build_mcp_list_tools_body() -> serde_json::Value {
    build_mcp_list_tools_body_with_id(serde_json::json!(1))
}

pub fn build_mcp_list_tools_body_with_id(id: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list",
        "params": {}
    })
}

pub fn build_modern_mcp_list_tools_body(
    id: serde_json::Value,
    protocol_version: &str,
    include_capabilities: bool,
) -> serde_json::Value {
    let mut meta = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": protocol_version,
        "io.modelcontextprotocol/clientInfo": {
            "name": "bdd-test-client",
            "version": "0.1.0"
        }
    });
    if include_capabilities {
        meta["io.modelcontextprotocol/clientCapabilities"] = serde_json::json!({});
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list",
        "params": { "_meta": meta }
    })
}

pub fn modern_mcp_request_headers(
    protocol_version: &str,
    method: &str,
) -> Vec<(String, String)> {
    vec![
        ("accept".to_string(), "application/json, text/event-stream".to_string()),
        ("MCP-Protocol-Version".to_string(), protocol_version.to_string()),
        ("Mcp-Method".to_string(), method.to_string()),
    ]
}

pub fn build_mcp_initialize_body(id: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "bdd-test-client", "version": "0.1.0" }
        }
    })
}

pub fn build_mcp_tool_call_body(
    tool_name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    })
}

pub fn build_mcp_tool_call_with_meta(
    tool_name: &str,
    meta: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": {},
            "_meta": meta
        }
    })
}

pub fn build_mcp_tool_call_without_meta(tool_name: &str) -> serde_json::Value {
    build_mcp_tool_call_body(tool_name, serde_json::json!({}))
}

pub fn build_mcp_request_without_method_body(id: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id
    })
}

pub fn build_mcp_initialized_notification_body() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })
}

pub fn build_mcp_agent_identity_payload() -> serde_json::Value {
    serde_json::json!({
        "softwareInfo": { "name": "caller-agent", "version": "1.0" },
        "cloudProvider": "local"
    })
}

pub fn build_mcp_schema_invalid_agent_identity_tool_call_body(tool_name: &str) -> serde_json::Value {
    build_mcp_tool_call_with_meta(
        tool_name,
        serde_json::json!({
            "agentIdentity": {
                "softwareInfo": { "name": 42, "version": true },
                "cloudProvider": 999
            }
        }),
    )
}

pub fn build_mcp_echo_request_bodies(count: usize) -> Vec<serde_json::Value> {
    (1..=count)
        .map(|index| {
            let marker = format!("mcp-concurrent-{index:03}");
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": marker,
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {
                        "marker": marker,
                    }
                }
            })
        })
        .collect()
}

pub fn build_mcp_echo_response_body() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "result": { "ok": true, "marker": "g2g-echo" }
    })
}

pub fn build_target_ok_response() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "ok": true, "marker": "g2g-target" }
    })
}

/// A managed-agent body that doubles as an agent card declaring the
/// `agent-identity/v1` extension. A minting target surface serves this so the
/// receiving gateway can inject the agent-identity-credential VP into the card
/// (injection requires the card to declare the base `agent-identity/v1`
/// extension); message-send forwards still return 200 with this body.
pub fn build_target_agent_card_with_identity() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "ok": true, "marker": "g2g-target" },
        "name": "g2g-target-agent",
        "url": "http://mock.local",
        "version": "1.0.0",
        "capabilities": {
            "extensions": [
                {
                    "uri": "https://fabric.affinidi.io/extensions/agent-identity/v1",
                    "params": {
                        "softwareInfo": { "name": "g2g-target", "version": "1.0" },
                        "cloudProvider": "local"
                    }
                }
            ]
        }
    })
}

/// A modern `tools/call` that declares its revision, capabilities and a
/// progress token in `params._meta`, as a `2026-07-28` client sends it.
pub fn build_modern_mcp_tool_call_body(
    id: serde_json::Value,
    tool_name: &str,
    protocol_version: &str,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": {"value": "bdd"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": protocol_version,
                "io.modelcontextprotocol/clientInfo": {"name": "bdd-test-client", "version": "0.1.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
                "progressToken": "bdd-progress"
            }
        }
    })
}

/// A complete modern tool catalog, as an MCP server answering `2026-07-28`
/// `tools/list`: a list result carries `resultType` and cache hints.
pub fn build_modern_mcp_tool_catalog_fixture(id: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "resultType": "complete",
            "ttlMs": 0,
            "cacheScope": "public",
            "tools": [{
                "name": "echo",
                "description": "Echo the given text",
                "inputSchema": {"type": "object"}
            }]
        }
    })
}

/// A complete modern tool result, as an MCP server answering `2026-07-28`.
pub fn build_modern_mcp_tool_result_fixture(id: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "resultType": "complete",
            "content": [{"type": "text", "text": "bdd"}]
        }
    })
}

#[cfg(test)]
mod tests {
    // `super::` paths rather than imports: the `#[test]` fns are compiled out
    // of the `harness = false` BDD binaries, which would leave imports unused.
    fn forwarded_body_with_proof(
        uri: &str,
        proof: serde_json::Value,
    ) -> serde_json::Value {
        let mut body = super::build_a2a_request_body();
        body["params"]["message"]["extensions"] = serde_json::json!([uri]);
        body["params"]["message"]["metadata"] = serde_json::json!({ uri: proof });
        body
    }

    #[test]
    fn identity_proof_is_read_from_binding_or_credential_metadata() {
        let proof = serde_json::json!({ "verifiablePresentation": "a.b.c" });

        for uri in [super::AGENT_IDENTITY_BINDING_EXTENSION_URI, super::AGENT_IDENTITY_CREDENTIAL_EXTENSION_URI] {
            let captured =
                super::IdentityBindingProof::from_forwarded_a2a_body(&forwarded_body_with_proof(uri, proof.clone()));
            assert_eq!(
                captured,
                Some(super::IdentityBindingProof {
                    uri: uri.to_string(),
                    proof: proof.clone()
                })
            );
        }
    }

    #[test]
    fn identity_proof_is_absent_without_proof_metadata() {
        assert_eq!(super::IdentityBindingProof::from_forwarded_a2a_body(&super::build_a2a_request_body()), None);
    }

    #[test]
    fn attached_identity_proof_round_trips_and_keeps_other_extensions() {
        let proof = super::IdentityBindingProof {
            uri: super::AGENT_IDENTITY_CREDENTIAL_EXTENSION_URI.to_string(),
            proof: serde_json::json!({ "verifiablePresentation": "a.b.c" }),
        };
        let mut body = super::build_a2a_request_body();

        super::attach_agent_identity_payload(&mut body);
        super::attach_identity_proof(&mut body, &proof);

        assert_eq!(body["method"], "message/send");
        assert_eq!(
            body["params"]["message"]["extensions"],
            serde_json::json!([super::AGENT_IDENTITY_EXTENSION_URI, super::AGENT_IDENTITY_CREDENTIAL_EXTENSION_URI])
        );
        assert_eq!(
            body["params"]["message"]["metadata"][super::AGENT_IDENTITY_EXTENSION_URI]["cloudProvider"],
            "local"
        );
        assert_eq!(super::IdentityBindingProof::from_forwarded_a2a_body(&body), Some(proof));
    }

    #[test]
    fn build_mcp_tool_call_with_meta_preserves_identity_metadata() {
        let body = super::build_mcp_tool_call_with_meta(
            "search",
            serde_json::json!({ "agentIdentity": super::build_mcp_agent_identity_payload() }),
        );

        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["name"], "search");
        assert_eq!(body["params"]["_meta"]["agentIdentity"]["cloudProvider"], "local");
    }

    #[test]
    fn build_mcp_initialize_body_uses_given_id() {
        let body = super::build_mcp_initialize_body(serde_json::json!(4242));

        assert_eq!(body["id"], 4242);
        assert_eq!(body["method"], "initialize");
        assert_eq!(body["params"]["protocolVersion"], "2025-03-26");
    }

    #[test]
    fn modern_list_tools_fixture_can_omit_capabilities() {
        let complete = super::build_modern_mcp_list_tools_body(serde_json::json!(1), "2026-07-28", true);
        let incomplete = super::build_modern_mcp_list_tools_body(serde_json::json!(1), "2026-07-28", false);

        assert_eq!(complete["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"], serde_json::json!({}));
        assert!(
            incomplete["params"]["_meta"]
                .get("io.modelcontextprotocol/clientCapabilities")
                .is_none()
        );
    }

    #[test]
    fn modern_request_headers_include_both_response_media_types() {
        let headers = super::modern_mcp_request_headers("2026-07-28", "tools/list");
        assert!(headers.contains(&("accept".to_string(), "application/json, text/event-stream".to_string())));
        assert!(headers.contains(&("MCP-Protocol-Version".to_string(), "2026-07-28".to_string())));
        assert!(headers.contains(&("Mcp-Method".to_string(), "tools/list".to_string())));
    }
}
