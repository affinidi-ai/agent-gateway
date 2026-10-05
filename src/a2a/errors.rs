//! A2A protocol error response builders

use axum::{body::Body, http::StatusCode, response::Response};

/// Create generic error response
pub fn create_error_response(
    status: StatusCode,
    message: &str,
) -> Response {
    let error_body = serde_json::json!({
        "type": "https://a2a-protocol.org/errors/proxy-error",
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "detail": message,
    });

    Response::builder()
        .status(status)
        .header("content-type", "application/problem+json")
        .body(Body::from(serde_json::to_string(&error_body).unwrap()))
        .unwrap()
}

/// Stable error code identifying a class of identity resolution failure.
/// Embedded in the problem+json body as `code` so callers can branch on it
/// without parsing the human-readable `detail` string.
pub const ERR_IDENTITY_EXTENSION_MISSING: &str = "identity_extension_missing";
pub const ERR_IDENTITY_INVALID_RESPONSE: &str = "identity_invalid_response";
pub const ERR_IDENTITY_VALIDATION_FAILED: &str = "identity_validation_failed";
pub const ERR_IDENTITY_DID_FAILED: &str = "identity_did_failed";

/// Build an RFC 7807 problem+json response for an identity-slot failure.
///
/// Includes the identity `slot` name (e.g. `protected_identity`, `inbound_identity`,
/// `external_identity`) and a stable `code` so demo UIs and downstream callers can
/// surface the precise reason rather than just the bare HTTP status.
pub fn create_identity_error_response(
    status: StatusCode,
    code: &str,
    slot: &str,
    channel: &str,
    detail: &str,
) -> Response {
    let error_body = serde_json::json!({
        "type": format!("https://errors.affinidi.io/{}", code),
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "code": code,
        "slot": slot,
        "channel": channel,
        "detail": detail,
    });

    Response::builder()
        .status(status)
        .header("content-type", "application/problem+json")
        .body(Body::from(serde_json::to_string(&error_body).unwrap()))
        .unwrap()
}

/// Validate that `body` is a well-formed JSON-RPC 2.0 request envelope.
///
/// Returns `Ok(())` when the body parses as JSON and contains both a
/// `"jsonrpc": "2.0"` field and a string `"method"` field.  On failure
/// returns `(error_code, message)` suitable for [`create_jsonrpc_error_response`].
pub fn validate_jsonrpc_envelope(body: &[u8]) -> Result<(), (i32, &'static str)> {
    let json_body: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| (-32700, "Parse error: invalid JSON"))?;

    validate_jsonrpc_value(&json_body)
}

/// Validate an already-parsed JSON value as a JSON-RPC 2.0 request envelope.
///
/// Use this variant when the request body has already been parsed (e.g. by
/// [`crate::proxy::handler::extract_ucp_operation_from_body`]) to avoid a
/// redundant deserialization pass on large payloads.
pub fn validate_jsonrpc_value(json_body: &serde_json::Value) -> Result<(), (i32, &'static str)> {
    json_body
        .get("jsonrpc")
        .and_then(|v| v.as_str())
        .filter(|&v| v == "2.0")
        .ok_or((-32600, "Invalid JSON-RPC: missing or invalid 'jsonrpc' field"))?;

    json_body
        .get("method")
        .filter(|m| m.is_string())
        .ok_or((-32600, "Invalid JSON-RPC: missing or invalid 'method' field"))?;

    Ok(())
}

/// Create a JSON-RPC 2.0 error response.
///
/// Returns a standard JSON-RPC error envelope with the given error `code` and
/// human-readable `message`.  The HTTP status is set to `status` so that
/// intermediaries (load balancers, monitoring) can distinguish client errors
/// from successful responses.
///
/// Standard JSON-RPC error codes:
/// * `-32700` — Parse error (invalid JSON)
/// * `-32600` — Invalid Request (missing required fields)
pub fn create_jsonrpc_error_response(
    status: StatusCode,
    code: i32,
    message: &str,
) -> Response {
    let error_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": code,
            "message": message,
        }
    });

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&error_body).unwrap()))
        .unwrap()
}

/// Create a JSON-RPC `Invalid params` (`-32602`) response carrying field-level
/// detail, so a caller can see which fields were wrong rather than guessing.
///
/// `data.errors` is an array of `{ field, message }`, where `field` is a dotted
/// path such as `params.message.messageId`. It holds at most
/// [`crate::a2a::validation::MAX_FIELD_ERRORS`] entries; `data.truncated` is
/// `true` when more problems were found, and absent otherwise.
pub fn create_invalid_params_response(errors: &crate::a2a::validation::FieldErrors) -> Response {
    let detail: Vec<serde_json::Value> = errors
        .errors
        .iter()
        .map(|e| {
            serde_json::json!({
                "field": e.field,
                "message": e.message,
            })
        })
        .collect();

    let mut data = serde_json::json!({ "errors": detail });
    if errors.truncated {
        data["truncated"] = serde_json::Value::Bool(true);
    }

    let error_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": crate::a2a::validation::ERR_INVALID_PARAMS,
            "message": "Invalid params",
            "data": data
        }
    });

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&error_body).unwrap()))
        .unwrap()
}

/// Build the A2A `VersionNotSupportedError` response (`-32009`) for a request whose
/// resolved protocol version is not one this gateway accepts.
///
/// `data.supported` lists the versions actually accepted right now, which narrows
/// to v1.0 alone when legacy A2A 0.3 compatibility is off, so a caller can
/// renegotiate without guessing.
pub fn create_version_not_supported_response(requested: &str) -> Response {
    let error_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": crate::a2a::version::ERR_VERSION_NOT_SUPPORTED,
            "message": format!("Unsupported A2A protocol version '{}'", requested),
            "data": {
                "requested": requested,
                "supported": crate::a2a::version::accepted_versions(),
            }
        }
    });

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&error_body).unwrap()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn version_not_supported_reports_supported_versions() {
        let response = create_version_not_supported_response("2.0");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["code"], -32009);
        assert_eq!(body["error"]["data"]["requested"], "2.0");
        assert_eq!(body["error"]["data"]["supported"], serde_json::json!(crate::a2a::version::accepted_versions()));
        assert!(
            body["error"]["data"]["supported"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("1.0"))
        );
    }

    #[test]
    fn valid_envelope() {
        let body = br#"{"jsonrpc":"2.0","method":"message/send","id":1}"#;
        assert!(validate_jsonrpc_envelope(body).is_ok());
    }

    #[test]
    fn valid_envelope_without_id() {
        let body = br#"{"jsonrpc":"2.0","method":"notifications/list"}"#;
        assert!(validate_jsonrpc_envelope(body).is_ok());
    }

    #[test]
    fn wrong_jsonrpc_version() {
        let body = br#"{"jsonrpc":"1.0","method":"foo","id":1}"#;
        assert_eq!(
            validate_jsonrpc_envelope(body),
            Err((-32600, "Invalid JSON-RPC: missing or invalid 'jsonrpc' field"))
        );
    }

    #[test]
    fn missing_jsonrpc_field() {
        let body = br#"{"method":"foo","id":1}"#;
        assert_eq!(
            validate_jsonrpc_envelope(body),
            Err((-32600, "Invalid JSON-RPC: missing or invalid 'jsonrpc' field"))
        );
    }

    #[test]
    fn method_is_number() {
        let body = br#"{"jsonrpc":"2.0","method":42,"id":1}"#;
        assert_eq!(
            validate_jsonrpc_envelope(body),
            Err((-32600, "Invalid JSON-RPC: missing or invalid 'method' field"))
        );
    }

    #[test]
    fn missing_method_field() {
        let body = br#"{"jsonrpc":"2.0","id":1}"#;
        assert_eq!(
            validate_jsonrpc_envelope(body),
            Err((-32600, "Invalid JSON-RPC: missing or invalid 'method' field"))
        );
    }

    #[test]
    fn invalid_json() {
        let body = b"not json at all";
        assert_eq!(validate_jsonrpc_envelope(body), Err((-32700, "Parse error: invalid JSON")));
    }

    #[test]
    fn empty_object() {
        let body = b"{}";
        assert_eq!(
            validate_jsonrpc_envelope(body),
            Err((-32600, "Invalid JSON-RPC: missing or invalid 'jsonrpc' field"))
        );
    }

    #[test]
    fn root_is_array() {
        let body = b"[1, 2, 3]";
        assert_eq!(
            validate_jsonrpc_envelope(body),
            Err((-32600, "Invalid JSON-RPC: missing or invalid 'jsonrpc' field"))
        );
    }

    #[test]
    fn validate_value_variant_matches_envelope() {
        let body = br#"{"jsonrpc":"2.0","method":"test"}"#;
        let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(validate_jsonrpc_envelope(body), validate_jsonrpc_value(&parsed));
    }

    async fn invalid_params_body(parts: usize) -> serde_json::Value {
        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": { "message": { "role": "user", "messageId": "m-1", "parts": vec![serde_json::json!(0); parts] } }
        });
        let errors = crate::a2a::validation::validate_request_shape(&request).unwrap_err();
        let response = create_invalid_params_response(&errors);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn invalid_params_response_marks_a_capped_list_as_truncated() {
        let body = invalid_params_body(10_000).await;
        let data = &body["error"]["data"];
        assert_eq!(body["error"]["code"], crate::a2a::validation::ERR_INVALID_PARAMS);
        assert_eq!(
            data["errors"]
                .as_array()
                .unwrap()
                .len(),
            crate::a2a::validation::MAX_FIELD_ERRORS
        );
        assert_eq!(data["truncated"], true);
    }

    #[tokio::test]
    async fn invalid_params_response_omits_truncated_for_a_complete_list() {
        let body = invalid_params_body(2).await;
        let data = &body["error"]["data"];
        assert_eq!(
            data["errors"],
            serde_json::json!([
                { "field": "params.message.parts[0]", "message": "must be an object" },
                { "field": "params.message.parts[1]", "message": "must be an object" }
            ])
        );
        assert!(
            data.get("truncated")
                .is_none(),
            "{data}"
        );
    }
}
