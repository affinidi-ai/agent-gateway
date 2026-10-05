use axum::http::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use super::ContinuationError;
use super::service::IssuedContinuation;
use crate::mcp::errors::error_codes;
use crate::mcp::modern::{RequiredClientCapability, ResultSource, require_client_capability, validate_response};
use crate::mcp::request_validation::{McpRequestValidationError, ValidatedModernMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConsentResponse {
    Missing,
    Accept,
    Decline,
    Cancel,
}

pub fn input_required_response(
    request: &ValidatedModernMessage,
    continuation: &IssuedContinuation,
    consent_url: &url::Url,
    message: &str,
) -> Result<Value, Box<McpRequestValidationError>> {
    require_client_capability(request, RequiredClientCapability::ElicitationUrl)?;
    let local_http = consent_url.scheme() == "http"
        && consent_url
            .host_str()
            .is_some_and(|host| {
                host == "localhost"
                    || host
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
    let invalid = || {
        Box::new(McpRequestValidationError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            id: request.id.clone(),
            code: error_codes::INTERNAL_ERROR,
            message: "Unable to construct consent request".into(),
            data: None,
        })
    };
    if request.protocol_version != crate::mcp::MCP_MODERN_VERSION
        || continuation.id.is_nil()
        || continuation.state.is_empty()
        || continuation.state.len() > 64 * 1024
        || consent_url.host().is_none()
        || consent_url.scheme() != "https" && !local_http
        || !consent_url
            .username()
            .is_empty()
        || consent_url
            .password()
            .is_some()
        || consent_url
            .fragment()
            .is_some()
        || consent_url.as_str().len() > 8192
        || message.is_empty()
        || message.len() > 2048
        || message
            .chars()
            .any(char::is_control)
    {
        return Err(invalid());
    }
    let response = json!({
        "jsonrpc": "2.0",
        "id": request.id,
        "result": {
            "resultType": "input_required",
            "requestState": continuation.state,
            "inputRequests": {
                input_key(continuation.id): {
                    "method": "elicitation/create",
                    "params": {"mode": "url", "url": consent_url.as_str(), "message": message}
                }
            }
        }
    });
    validate_response(request, &response, ResultSource::ModernServer).map_err(|_| invalid())?;
    Ok(response)
}

pub(super) fn input_key(id: Uuid) -> String {
    format!("gateway-consent-{id}")
}

pub(super) fn parse_response(
    request: &ValidatedModernMessage,
    id: Uuid,
) -> Result<ConsentResponse, ContinuationError> {
    let Some(responses) = request
        .params
        .as_ref()
        .and_then(|params| params.get("inputResponses"))
    else {
        return Ok(ConsentResponse::Missing);
    };
    let responses = responses
        .as_object()
        .ok_or(ContinuationError::InvalidInputResponse)?;
    let Some(response) = responses.get(&input_key(id)) else {
        return Ok(ConsentResponse::Missing);
    };
    let response = response
        .as_object()
        .ok_or(ContinuationError::InvalidInputResponse)?;
    if response.contains_key("content") {
        return Err(ContinuationError::InvalidInputResponse);
    }
    match response
        .get("action")
        .and_then(Value::as_str)
    {
        Some("accept") => Ok(ConsentResponse::Accept),
        Some("decline") => Ok(ConsentResponse::Decline),
        Some("cancel") => Ok(ConsentResponse::Cancel),
        _ => Err(ContinuationError::InvalidInputResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::request_validation::McpMessageKind;

    #[test]
    fn consent_result_is_request_local_and_requires_url_capability() {
        let mut request = ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: Some(json!({"elicitation": {"url": {}}})),
            client_info: None,
            method: "tools/call".into(),
            id: Some(json!(7)),
            kind: McpMessageKind::Request,
            params: Some(json!({"name": "write"})),
        };
        let issued = IssuedContinuation {
            id: Uuid::new_v4(),
            state: "protected-state".into(),
            expires_at: 100,
        };
        let url = url::Url::parse("https://gateway.example/connect?state=opaque").unwrap();
        let response = input_required_response(&request, &issued, &url, "Authorize provider access").unwrap();
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["resultType"], "input_required");
        assert_eq!(response["result"]["requestState"], issued.state);
        let input = &response["result"]["inputRequests"][input_key(issued.id)];
        assert_eq!(input["method"], "elicitation/create");
        assert_eq!(input["params"]["mode"], "url");
        assert_eq!(input["params"]["url"], url.as_str());
        for field in ["jsonrpc", "id"] {
            assert!(input.get(field).is_none());
        }
        for field in ["_meta", "cacheScope", "ttlMs"] {
            assert!(
                response["result"]
                    .get(field)
                    .is_none()
            );
        }
        request.client_capabilities = Some(json!({"elicitation": {}}));
        let error = input_required_response(&request, &issued, &url, "Authorize provider access").unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, error_codes::MISSING_REQUIRED_CLIENT_CAPABILITY);
        assert_eq!(error.data.unwrap()["requiredCapabilities"], json!({"elicitation": {"url": {}}}));
        request.client_capabilities = Some(json!({"elicitation": {"url": {}}}));
        for invalid_url in
            ["http://provider.example/connect", "https://user:password@gateway.example/connect", "file:///tmp/consent"]
        {
            assert!(
                input_required_response(&request, &issued, &url::Url::parse(invalid_url).unwrap(), "Authorize")
                    .is_err()
            );
        }
        request.method = "tools/list".into();
        assert!(input_required_response(&request, &issued, &url, "Authorize").is_err());
    }

    #[test]
    fn consent_responses_use_exact_keys_and_never_accept_inline_credentials() {
        let id = Uuid::new_v4();
        let mut request = ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: None,
            client_info: None,
            method: "tools/call".into(),
            id: Some(json!(2)),
            kind: McpMessageKind::Request,
            params: Some(json!({"inputResponses": {"unknown": {"action": "accept"}}})),
        };
        assert_eq!(parse_response(&request, id), Ok(ConsentResponse::Missing));
        for (action, expected) in [
            ("accept", ConsentResponse::Accept),
            ("decline", ConsentResponse::Decline),
            ("cancel", ConsentResponse::Cancel),
        ] {
            request
                .params
                .as_mut()
                .unwrap()["inputResponses"][input_key(id)] = json!({"action": action});
            assert_eq!(parse_response(&request, id), Ok(expected));
        }
        for response in [
            json!({"result": {"action": "accept"}}),
            json!({"action": "unknown"}),
            json!({"action": "accept", "content": {"token": "secret"}}),
        ] {
            request
                .params
                .as_mut()
                .unwrap()["inputResponses"][input_key(id)] = response;
            assert_eq!(parse_response(&request, id), Err(ContinuationError::InvalidInputResponse));
        }
        request
            .params
            .as_mut()
            .unwrap()["inputResponses"] = json!([]);
        assert_eq!(parse_response(&request, id), Err(ContinuationError::InvalidInputResponse));
    }
}
