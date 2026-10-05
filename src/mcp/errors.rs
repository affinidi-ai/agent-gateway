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
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

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
    async fn modern_error_response_preserves_status_id_and_data() {
        let response = create_mcp_error_response_with_status(
            StatusCode::BAD_REQUEST,
            Some(json!("request-1")),
            error_codes::UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            Some(json!({"requested": "2026-07-28", "supported": ["2024-11-05"]})),
        );
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["content-type"], "application/json");
        let body = response_json(response).await;
        assert_eq!(body["id"], "request-1");
        assert_eq!(body["error"]["code"], error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(body["error"]["data"]["supported"], json!(["2024-11-05"]));
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
