//! MCP (Model Context Protocol) handling
//!
//! This module contains functions for handling MCP protocol features including
//! initialization, capability negotiation, tools, resources, prompts, sampling,
//! logging, validation, and identity injection.

#[cfg(test)]
pub(crate) mod admission_cases;
pub mod capabilities;
pub mod continuations;
pub mod elicitation;
pub mod errors;
pub mod handler;
pub mod identity;
pub mod initialize;
pub mod logging;
pub mod meta;
pub mod metadata;
pub mod modern;
pub mod modern_http;
pub mod modern_sse;
pub mod policy;
pub mod prompts;
pub mod request_validation;
pub mod resource_server;
pub mod resources;
#[cfg(test)]
pub(crate) mod result_fixtures;
pub mod sampling;
pub mod sse_server;
pub mod sse_transport;
pub mod streamable_sse;
pub mod subscriptions;
pub mod tool_analyzer;
pub mod tool_headers;
pub mod tools;
pub mod upstream_versions;
pub mod validation;

pub use errors::create_mcp_error_response;
pub use errors::error_codes;
pub use handler::{
    build_tools_call_policy_denied_envelope, build_tools_call_policy_denied_response, fail_closed_tools_list,
    handle_mcp_request, inject_mcp_metadata, is_mcp_request, is_tools_call_request, is_tools_list_request,
};
// inject_identity_credential_mcp is currently unused but retained for future
// outbound MCP identity signing support.
#[allow(unused_imports)]
pub use identity::inject_identity_credential_mcp;

#[cfg(feature = "didwebvh")]
pub use identity::inject_didwebvh_identity_mcp;

pub use initialize::inject_server_metadata;
pub use logging::handle_logging_message;
pub use policy::McpPolicyContext;
pub use tool_analyzer::McpToolRequest;
pub use validation::{inject_vp_into_mcp_request, inject_vp_into_mcp_response, is_notification, validate_mcp_message};

/// Legacy MCP protocol version implemented by the gateway.
pub const MCP_LEGACY_VERSION: &str = "2024-11-05";

/// Modern MCP protocol version recognized by the wire validator.
pub const MCP_MODERN_VERSION: &str = "2026-07-28";

/// Backward-compatible alias used by legacy initialize and client paths.
pub const MCP_PROTOCOL_VERSION: &str = MCP_LEGACY_VERSION;

/// Build the `McpContext` used for OPA input and Trust Check template
/// resolution (`input.mcp.*`) from a raw JSON-RPC request body.
///
/// Returns `None` when the body is not a parseable MCP request. Shared by the
/// direct-inbound and fabric-receive pipelines so `input.mcp` is populated
/// identically on both paths.
pub fn build_mcp_context(body_bytes: &[u8]) -> Option<crate::surface_context::McpContext> {
    McpToolRequest::from_json_rpc(body_bytes)
        .ok()
        .map(|req| {
            let tool_name = req
                .params
                .as_ref()
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .map(|s| s.to_string());
            crate::surface_context::McpContext {
                method: req.method.clone(),
                tool_name,
                resource_uri: None,
                prompt_name: None,
                params: req.params.clone(),
                ..Default::default()
            }
        })
}

pub fn modern_mcp_context(
    classification: &request_validation::McpRequestClassification
) -> Option<crate::surface_context::McpContext> {
    let request_validation::McpRequestClassification::Modern(message) = classification else {
        return None;
    };
    let named_param = |method: &str, field: &str| {
        (message.method == method)
            .then(|| {
                message
                    .params
                    .as_ref()?
                    .get(field)?
                    .as_str()
                    .map(str::to_string)
            })
            .flatten()
    };
    Some(crate::surface_context::McpContext {
        method: message.method.clone(),
        tool_name: named_param("tools/call", "name"),
        resource_uri: named_param("resources/read", "uri"),
        prompt_name: named_param("prompts/get", "name"),
        params: message.params.clone(),
        protocol_version: Some(
            message
                .protocol_version
                .clone(),
        ),
        client_capabilities: message
            .client_capabilities
            .clone(),
        client_info: message.client_info.clone(),
    })
}

pub fn build_validated_mcp_context(
    body_bytes: &[u8],
    classification: &request_validation::McpRequestClassification,
) -> Option<crate::surface_context::McpContext> {
    modern_mcp_context(classification).or_else(|| build_mcp_context(body_bytes))
}

#[cfg(test)]
mod tests {
    use super::request_validation::{
        LEGACY_ONLY_POLICY, LegacySessionEvidence, McpRequestClassification, McpVersionPolicy, validate_mcp_post,
    };
    use super::{MCP_LEGACY_VERSION, MCP_MODERN_VERSION, build_mcp_context, build_validated_mcp_context};
    use axum::http::HeaderMap;
    use serde_json::json;

    fn modern_request(method: &str) -> serde_json::Value {
        json!({"jsonrpc": "2.0", "id": "request", "method": method, "params": {
            "name": "echo", "uri": "https://example.org/resource", "arguments": {"nested": [1, false, null]},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {"extensions": {"com.example/extension": {"custom": [1, true]}}},
                "io.modelcontextprotocol/clientInfo": {"name": "declared-client", "version": "1.0"},
                "progressToken": 7
            }
        }})
    }

    fn classify_modern(body: &serde_json::Value) -> McpRequestClassification {
        let mut headers = HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        let method = body["method"]
            .as_str()
            .unwrap();
        headers.insert("mcp-method", method.parse().unwrap());
        let name = match method {
            "tools/call" | "prompts/get" => body["params"]["name"].as_str(),
            "resources/read" => body["params"]["uri"].as_str(),
            _ => None,
        };
        if let Some(name) = name {
            headers.insert("mcp-name", name.parse().unwrap());
        }
        let bytes = serde_json::to_vec(body).unwrap();
        let rejection =
            validate_mcp_post(&headers, &bytes, LegacySessionEvidence::Absent, LEGACY_ONLY_POLICY).unwrap_err();
        assert_eq!(rejection.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(rejection.code, -32022);
        assert_eq!(rejection.data, Some(json!({"requested": MCP_MODERN_VERSION, "supported": [MCP_LEGACY_VERSION]})));
        validate_mcp_post(
            &headers,
            &bytes,
            LegacySessionEvidence::Absent,
            McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]),
        )
        .unwrap()
    }

    #[test]
    fn modern_policy_context_uses_validated_declarations_not_rewritten_body() {
        let body = modern_request("tools/call");
        let classification = classify_modern(&body);
        let context =
            build_validated_mcp_context(br#"{"method":"other","id":9,"params":{}}"#, &classification).unwrap();

        assert_eq!(
            serde_json::to_value(context).unwrap(),
            json!({
                "method": "tools/call", "tool_name": "echo", "params": body["params"],
                "protocol_version": MCP_MODERN_VERSION,
                "client_capabilities": body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
                "client_info": body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]
            })
        );
    }

    #[test]
    fn modern_policy_context_preserves_extension_methods_and_raw_params() {
        for method in [
            "server/discover",
            "subscriptions/listen",
            "tasks/get",
            "tasks/update",
            "tasks/cancel",
            "com.example/operation",
        ] {
            let body = modern_request(method);
            let context = build_validated_mcp_context(b"", &classify_modern(&body)).unwrap();

            assert_eq!(context.method, method);
            assert_eq!(context.params, Some(body["params"].clone()));
            assert_eq!(context.tool_name, None);
            assert_eq!(context.resource_uri, None);
            assert_eq!(context.prompt_name, None);
        }
        for (method, expected_resource, expected_prompt) in
            [("resources/read", Some("https://example.org/resource"), None), ("prompts/get", None, Some("echo"))]
        {
            let body = modern_request(method);
            let context = build_validated_mcp_context(b"", &classify_modern(&body)).unwrap();
            assert_eq!(
                context
                    .resource_uri
                    .as_deref(),
                expected_resource
            );
            assert_eq!(context.prompt_name.as_deref(), expected_prompt);
            assert_eq!(context.tool_name, None);
        }
    }

    #[test]
    fn modern_policy_context_never_inherits_previous_capabilities_or_info() {
        let mut body = modern_request("tools/list");
        let first = build_validated_mcp_context(b"", &classify_modern(&body)).unwrap();
        body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
        body["params"]["_meta"]
            .as_object_mut()
            .unwrap()
            .remove("io.modelcontextprotocol/clientInfo");
        let second = build_validated_mcp_context(b"", &classify_modern(&body)).unwrap();

        assert!(first.client_info.is_some());
        assert_eq!(second.client_capabilities, Some(json!({})));
        assert!(
            serde_json::to_value(second)
                .unwrap()
                .get("client_info")
                .is_none()
        );
    }

    #[test]
    fn modern_notification_context_does_not_require_request_only_fields() {
        let body = json!({"jsonrpc": "2.0", "method": "notifications/tasks", "params": {
            "taskId": "task", "status": "working",
            "_meta": {"io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION}
        }});
        let context = build_validated_mcp_context(b"", &classify_modern(&body)).unwrap();
        assert_eq!(
            serde_json::to_value(context).unwrap(),
            json!({
                "method": "notifications/tasks", "params": body["params"], "protocol_version": MCP_MODERN_VERSION
            })
        );
    }

    #[test]
    fn legacy_policy_context_preserves_its_serialized_shape() {
        for method in ["tools/call", "prompts/get", "com.example/operation"] {
            let params = json!({"name": "echo", "arguments": {"value": [1, true]}, "_meta": {"tenant": "example"}});
            let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
            let bytes = serde_json::to_vec(&body).unwrap();
            let classification =
                validate_mcp_post(&HeaderMap::new(), &bytes, LegacySessionEvidence::Absent, LEGACY_ONLY_POLICY)
                    .unwrap();
            let context = build_validated_mcp_context(&bytes, &classification).unwrap();

            assert_eq!(
                serde_json::to_value(context).unwrap(),
                json!({"method": method, "tool_name": "echo", "params": params})
            );
        }
    }

    #[test]
    fn legacy_policy_context_omits_absent_params() {
        let context = build_mcp_context(br#"{"jsonrpc":"2.0","id":"list","method":"tools/list"}"#).unwrap();

        assert_eq!(serde_json::to_value(context).unwrap(), json!({"method": "tools/list"}));
    }

    #[test]
    fn legacy_policy_context_does_not_invent_requests_from_notifications_or_replies() {
        for body in [
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"result":{}}"#.as_slice(),
            b"invalid JSON".as_slice(),
        ] {
            assert!(build_mcp_context(body).is_none());
        }
    }
}
