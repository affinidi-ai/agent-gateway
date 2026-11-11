//! Protocol-agnostic utilities for handling multiple protocols (A2A, MCP, UCP, ACP, etc.)
//!
//! This module contains functions that work across different messaging protocols,
//! including extension inspection, metadata injection, and utility functions.

pub mod extensions;
pub mod protected_resource;

pub use extensions::{
    ExtensionInspectionContext, MetadataRuntimeContext, inspect_message_extensions, is_hop_by_hop_header,
    resolve_metadata_references, should_forward_request_header,
};

use crate::config::ChannelProtocol;
use axum::{body::Body, http::StatusCode, response::Response};

/// An RFC 9457 `application/problem+json` response that names no protocol:
/// type `about:blank`, the status's reason phrase as title, and a stable
/// `code` callers can branch on instead of parsing `detail`.
pub fn problem_response(
    status: StatusCode,
    code: &str,
    detail: &str,
) -> Response {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "code": code,
        "detail": detail,
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/problem+json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// The `404` a caller gets when nothing is served where it asked: same
/// `about:blank` body whatever the protocol and whichever way the target is
/// missing, so it never says whether the target is disabled, deleted or unknown.
pub fn no_route_response(detail: &str) -> Response {
    problem_response(StatusCode::NOT_FOUND, "no_route", detail)
}

/// [`no_route_response`] for a Transit Point path that no enabled Transit Point serves.
pub fn no_transit_point_response() -> Response {
    no_route_response(
        "No Transit Point is served at this path. Check the Transit Point URL, and that the Transit Point is saved and enabled.",
    )
}

/// [`no_route_response`] for an entry point whose MCP Proxy is missing.
pub fn no_mcp_proxy_response() -> Response {
    no_route_response("No MCP Proxy is served at this entry point. Check that the MCP Proxy is saved and enabled.")
}

/// Detect the wire "protocol family" of a JSON-RPC request body from its
/// `method` prefix. Returns `Some("a2a")` or `Some("mcp")` only when the body
/// is positively identifiable; `None` for non-JSON bodies, bodies without a
/// string `method` (e.g. JSON-RPC responses, MCP `initialize`), or unrecognised
/// methods — so ambiguous payloads are never misclassified.
///
/// Shared by the inbound access-point and outbound transit-point protocol
/// guards so both legs classify bodies identically.
pub fn detect_request_protocol_family(body: &[u8]) -> Option<&'static str> {
    let json = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let method = json
        .get("method")
        .and_then(|m| m.as_str())?;
    // A2A is recognised across both eras: v0.3 slash-form (`message/*`, `tasks/*`)
    // by prefix, plus the v1.0 PascalCase names (`SendMessage`, `GetTask`, …) and
    // the `agent/getAuthenticatedExtendedCard` method by exact match.
    if method.starts_with("message/") || method.starts_with("tasks/") || crate::a2a::is_a2a_method(method) {
        Some("a2a")
    } else if method.starts_with("tools/") || method.starts_with("prompts/") || method.starts_with("resources/") {
        Some("mcp")
    } else {
        None
    }
}

/// The protocol family a configured [`ChannelProtocol`] expects on the wire, or
/// `None` when the protocol has no JSON-RPC method-based detector
/// (`didcomm`) and therefore cannot be shape-validated. A2A and
/// AP2 share the same method shapes (`message/*`, `tasks/*`), so they collapse
/// to one family.
pub fn channel_protocol_family(protocol: &ChannelProtocol) -> Option<&'static str> {
    match protocol {
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => Some("a2a"),
        ChannelProtocol::Mcp => Some("mcp"),
        ChannelProtocol::DIDComm => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_problem_response_is_about_blank_problem_json_with_a_code() {
        let response = problem_response(StatusCode::UNPROCESSABLE_ENTITY, "batch_not_supported", "why");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .unwrap(),
            "application/problem+json"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "type": "about:blank",
                "title": "Unprocessable Entity",
                "status": 422,
                "code": "batch_not_supported",
                "detail": "why",
            })
        );
    }

    #[test]
    fn detects_a2a_from_message_method() {
        let body = br#"{"jsonrpc":"2.0","method":"message/send","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("a2a"));
    }

    #[test]
    fn detects_a2a_from_tasks_method() {
        let body = br#"{"jsonrpc":"2.0","method":"tasks/get","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("a2a"));
    }

    #[test]
    fn detects_a2a_from_v1_pascalcase_method() {
        // v1.0 renamed the JSON-RPC methods to PascalCase; they must classify as A2A.
        let body = br#"{"jsonrpc":"2.0","method":"SendMessage","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("a2a"));
        let body = br#"{"jsonrpc":"2.0","method":"ListTasks","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("a2a"));
    }

    #[test]
    fn detects_a2a_from_extended_card_method() {
        // `agent/getAuthenticatedExtendedCard` matches neither the message/ nor tasks/
        // prefix but is a recognised A2A method.
        let body = br#"{"jsonrpc":"2.0","method":"agent/getAuthenticatedExtendedCard","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("a2a"));
    }

    #[test]
    fn detects_mcp_from_tools_method() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/call","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("mcp"));
    }

    #[test]
    fn returns_none_for_mcp_initialize() {
        // `initialize` is a real MCP method but shares no prefix with the
        // detectable families; it must not be misclassified or rejected.
        let body = br#"{"jsonrpc":"2.0","method":"initialize","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), None);
    }

    #[test]
    fn returns_none_for_jsonrpc_response() {
        // JSON-RPC responses (id + result, no method) carry no protocol marker.
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert_eq!(detect_request_protocol_family(body), None);
    }

    #[test]
    fn returns_none_for_non_json() {
        assert_eq!(detect_request_protocol_family(b"not json"), None);
    }

    #[test]
    fn channel_families_collapse_a2a_and_ap2() {
        assert_eq!(channel_protocol_family(&ChannelProtocol::A2a), Some("a2a"));
        assert_eq!(channel_protocol_family(&ChannelProtocol::Ap2), Some("a2a"));
        assert_eq!(channel_protocol_family(&ChannelProtocol::Mcp), Some("mcp"));
        assert_eq!(channel_protocol_family(&ChannelProtocol::DIDComm), None);
    }
}
