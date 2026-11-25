//! MCP error response handling

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value as JsonValue, json};

pub fn create_mcp_error_envelope(
    id: Option<JsonValue>,
    code: i32,
    message: &str,
    data: Option<JsonValue>,
) -> JsonValue {
    let mut error = json!({
        "code": code,
        "message": message,
    });

    if let Some(data) = data {
        error["data"] = data;
    }

    let mut body = json!({
        "jsonrpc": "2.0",
        "error": error,
    });
    if let Some(id) = id {
        body["id"] = id;
    }
    body
}

pub fn create_mcp_error_response_with_status(
    status: StatusCode,
    id: Option<JsonValue>,
    code: i32,
    message: &str,
    data: Option<JsonValue>,
) -> Response {
    (status, axum::Json(create_mcp_error_envelope(id, code, message, data))).into_response()
}

/// Create a JSON-RPC error response for MCP
pub fn create_mcp_error_response(
    id: Option<serde_json::Value>,
    code: i32,
    message: &str,
    data: Option<serde_json::Value>,
) -> Response {
    let mut error = json!({
        "code": code,
        "message": message,
    });

    if let Some(data_val) = data {
        error["data"] = data_val;
    }

    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": error,
    });

    (StatusCode::OK, axum::Json(body)).into_response()
}

/// The answer to an MCP request the gateway could not carry to its Target: a JSON-RPC `-32603`
/// error that echoes the request `id` with `data.reason` set to `reason`, under HTTP `status`.
/// A JSON-RPC notification (an object without an `id`) gets `status` and no body, and a body
/// whose `id` cannot be read is answered with a `null` one.
pub fn target_failure_response(
    status: StatusCode,
    request_body: &[u8],
    reason: &str,
    message: &str,
) -> Response {
    let id = match serde_json::from_slice::<JsonValue>(request_body) {
        Ok(JsonValue::Object(message)) => message.get("id").cloned(),
        _ => Some(JsonValue::Null),
    };
    target_failure_response_with_id(status, id, reason, message)
}

/// [`target_failure_response`] for a request whose `id` was already read: `None` for a
/// notification, which gets `status` and no body.
pub fn target_failure_response_with_id(
    status: StatusCode,
    id: Option<JsonValue>,
    reason: &str,
    message: &str,
) -> Response {
    match id {
        Some(id) => create_mcp_error_response_with_status(
            status,
            Some(id),
            error_codes::INTERNAL_ERROR,
            message,
            Some(json!({"reason": reason})),
        ),
        None => status.into_response(),
    }
}

/// Standard JSON-RPC error codes
pub mod error_codes {
    /// Invalid JSON was received by the server
    pub const PARSE_ERROR: i32 = -32700;
    /// The JSON sent is not a valid Request object
    pub const INVALID_REQUEST: i32 = -32600;
    /// The method does not exist / is not available
    #[allow(dead_code)]
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid method parameter(s)
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal JSON-RPC error
    pub const INTERNAL_ERROR: i32 = -32603;
    /// HTTP request metadata does not match the JSON-RPC body
    pub const HEADER_MISMATCH: i32 = -32020;
    pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i32 = -32021;
    /// The requested modern MCP protocol version is not active
    pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;
}

pub mod application_error_codes {
    pub const PAYMENT_REQUIRED: i32 = 1001;
    pub const PAYMENT_REJECTED: i32 = 1002;
    /// The payment is held for human review; `data.case_id` names the case.
    pub const PAYMENT_PENDING: i32 = 1003;
}

/// The payment errors of the MPP MCP transport (`draft-payment-transport-mcp-00`
/// §10), which a caller on the legacy MCP revision is answered with in place of
/// [`application_error_codes`].
pub mod payment_transport_error_codes {
    pub const PAYMENT_REQUIRED: i32 = -32042;
    pub const PAYMENT_VERIFICATION_FAILED: i32 = -32043;
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;
    use crate::mcp::{MCP_LEGACY_VERSION, MCP_MODERN_VERSION};

    async fn response_json(response: Response) -> JsonValue {
        let (_, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn legacy_error_response_keeps_http_ok_and_null_id() {
        let response = create_mcp_error_response(None, error_codes::INVALID_REQUEST, "Invalid request", None);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["id"], JsonValue::Null);
    }

    #[tokio::test]
    async fn target_failure_echoes_the_request_id_under_the_given_status() {
        for (body, id) in [
            (r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#, json!(7)),
            (r#"{"jsonrpc":"2.0","id":"abc","method":"tools/list"}"#, json!("abc")),
            (r#"not json"#, JsonValue::Null),
            (r#"[{"jsonrpc":"2.0","id":1,"method":"x"}]"#, JsonValue::Null),
        ] {
            let response = target_failure_response(
                StatusCode::BAD_GATEWAY,
                body.as_bytes(),
                "target_unreachable",
                "Target unavailable",
            );
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{body}");
            assert_eq!(response.headers()["content-type"], "application/json");
            let json = response_json(response).await;
            assert_eq!(
                json,
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32603, "message": "Target unavailable", "data": {"reason": "target_unreachable"}},
                }),
                "{body}"
            );
        }
    }

    #[tokio::test]
    async fn target_failure_for_a_notification_has_a_status_and_no_body() {
        let response = target_failure_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "target_auth_misconfigured",
            "Target authentication failed",
        );
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn modern_error_response_preserves_status_id_and_data() {
        let response = create_mcp_error_response_with_status(
            StatusCode::BAD_REQUEST,
            Some(json!("request-1")),
            error_codes::UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            Some(json!({"requested": MCP_MODERN_VERSION, "supported": [MCP_LEGACY_VERSION]})),
        );
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["content-type"], "application/json");
        let body = response_json(response).await;
        assert_eq!(body["id"], "request-1");
        assert_eq!(body["error"]["code"], error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(body["error"]["data"]["supported"], json!([MCP_LEGACY_VERSION]));
    }

    #[tokio::test]
    async fn modern_error_response_omits_unreadable_id() {
        let response = create_mcp_error_response_with_status(
            StatusCode::BAD_REQUEST,
            None,
            error_codes::PARSE_ERROR,
            "Invalid JSON",
            None,
        );
        assert!(
            response_json(response)
                .await
                .get("id")
                .is_none()
        );
    }
}
