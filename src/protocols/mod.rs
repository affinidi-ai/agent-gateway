//! Protocol-agnostic utilities for handling multiple protocols (A2A, MCP, UCP, ACP, etc.)
//!
//! This module contains functions that work across different messaging protocols,
//! including extension inspection, metadata injection, and utility functions.

pub mod extensions;

pub use extensions::{
    ExtensionInspectionContext, MetadataRuntimeContext, inspect_message_extensions, is_hop_by_hop_header,
    resolve_metadata_references, should_forward_request_header,
};

use crate::config::ChannelProtocol;

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
