use std::collections::HashMap;

pub fn assert_response_status(
    actual: Option<u16>,
    expected: u16,
) {
    let actual = actual.expect("a When must record the response status before this Then");
    assert_eq!(actual, expected, "unexpected response status");
}

pub fn assert_status_with_body(
    actual: u16,
    expected: u16,
    body: &serde_json::Value,
    context: &str,
) {
    assert_eq!(actual, expected, "expected {context} status {expected}, got {actual}. Body: {body}");
}

pub fn assert_json_field_absent(
    body: &serde_json::Value,
    field: &str,
    context: &str,
) {
    assert!(body.get(field).is_none(), "expected {context} not to include '{field}', got {body}");
}

pub fn assert_json_string_field_equals(
    body: &serde_json::Value,
    field: &str,
    expected: &str,
    context: &str,
) {
    let actual = body
        .get(field)
        .and_then(|value| value.as_str());
    assert_eq!(actual, Some(expected), "expected {context} field '{field}' to equal '{expected}', got {body}");
}

pub fn assert_json_bodies_equal(
    actual: &serde_json::Value,
    expected: &serde_json::Value,
    context: &str,
) {
    assert_eq!(actual, expected, "{context} body mismatch. Expected: {expected} Actual: {actual}");
}

pub fn json_body_mentions(
    body: &serde_json::Value,
    expected: &str,
) -> bool {
    ["detail", "details", "title", "error"]
        .into_iter()
        .any(|field| {
            body.get(field)
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.contains(expected))
        })
        || body
            .to_string()
            .contains(expected)
}

pub fn assert_json_body_mentions(
    body: &serde_json::Value,
    expected: &str,
    context: &str,
) {
    assert!(json_body_mentions(body, expected), "expected {context} body to mention '{expected}', got {body}");
}

pub fn assert_json_body_does_not_mention(
    body: &serde_json::Value,
    unexpected: &str,
    context: &str,
) {
    assert!(!json_body_mentions(body, unexpected), "expected {context} body not to mention '{unexpected}', got {body}");
}

pub fn assert_content_type_starts_with(
    actual: Option<&str>,
    expected: &str,
) {
    let actual = actual.unwrap_or_default();
    assert!(actual.starts_with(expected), "unexpected response content type: expected '{expected}', got '{actual}'");
}

pub fn get_header_value<'a>(
    headers: &'a HashMap<String, String>,
    header_name: &str,
    context: &str,
) -> &'a str {
    headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case(header_name)
                .then_some(value.as_str())
        })
        .unwrap_or_else(|| panic!("{} header '{}' not found", context, header_name))
}

pub fn assert_header_contains(
    headers: &HashMap<String, String>,
    header_name: &str,
    expected: &str,
    context: &str,
) {
    let actual = get_header_value(headers, header_name, context);
    assert!(
        actual.contains(expected),
        "expected {context} header '{header_name}' to mention '{expected}', got '{actual}'"
    );
}

pub fn assert_content_type_contains(
    headers: &HashMap<String, String>,
    expected: &str,
    context: &str,
) {
    assert_header_contains(headers, "content-type", expected, context);
}

pub fn assert_json_rpc_id_matches_request_body(
    response_body: &serde_json::Value,
    request_body: &serde_json::Value,
    context: &str,
) {
    let request_id = request_body
        .get("id")
        .unwrap_or_else(|| panic!("expected {context} request to include JSON-RPC id, got {request_body}"));
    let response_id = response_body
        .get("id")
        .unwrap_or_else(|| panic!("expected MCP response to include JSON-RPC id, got {response_body}"));
    assert_eq!(
        response_id, request_id,
        "expected MCP response id to match {context} request id. Response: {response_body} Request: {request_body}"
    );
}

pub fn assert_json_object(
    value: &serde_json::Value,
    context: &str,
) {
    assert!(value.is_object(), "{context} must be a JSON object, got {value}");
}

pub fn assert_mcp_method(
    request_body: &serde_json::Value,
    expected: &str,
    context: &str,
) {
    let actual = request_body
        .get("method")
        .and_then(|value| value.as_str());
    assert_eq!(actual, Some(expected), "expected {context} MCP method '{expected}', got {request_body}");
}

pub fn assert_json_rpc_error_code(
    response_body: &serde_json::Value,
    expected_code: i64,
) {
    assert!(
        response_body
            .get("result")
            .is_none(),
        "JSON-RPC error response must not carry a 'result', got: {response_body}"
    );
    let code = response_body
        .pointer("/error/code")
        .and_then(|value| value.as_i64())
        .unwrap_or_else(|| panic!("MCP response must have an integer 'error.code', got: {response_body}"));
    assert_eq!(code, expected_code, "expected JSON-RPC error code {expected_code}, got {code}");
}

pub fn assert_mcp_unsupported_version_error(
    response_body: &serde_json::Value,
    requested: &str,
    supported: &str,
) {
    assert_json_rpc_error_code(response_body, -32022);
    assert_eq!(
        response_body
            .pointer("/error/data/requested")
            .and_then(serde_json::Value::as_str),
        Some(requested),
        "unsupported-version error must identify the requested MCP version: {response_body}"
    );
    assert_eq!(
        response_body.pointer("/error/data/supported"),
        Some(&serde_json::json!(
            supported
                .split(", ")
                .collect::<Vec<_>>()
        )),
        "unsupported-version error must list exactly the active MCP versions: {response_body}"
    );
}

pub fn assert_json_field_matches(
    actual_body: &serde_json::Value,
    expected_body: &serde_json::Value,
    dotted_field: &str,
    context: &str,
) {
    let pointer = json_pointer_from_dotted(dotted_field);
    let expected_value = expected_body
        .pointer(&pointer)
        .unwrap_or_else(|| panic!("field '{dotted_field}' not found in expected body for {context}"));
    let actual_value = actual_body
        .pointer(&pointer)
        .unwrap_or_else(|| panic!("field '{dotted_field}' not found in actual body for {context}"));
    assert_eq!(
        actual_value, expected_value,
        "{context} field '{dotted_field}' mismatch. Expected: {expected_value} Actual: {actual_value}"
    );
}

pub fn json_pointer_from_dotted(field: &str) -> String {
    let mut out = String::new();
    for part in field.split('.') {
        out.push('/');
        out.push_str(
            &part
                .replace('~', "~0")
                .replace('/', "~1"),
        );
    }
    out
}

pub fn json_rpc_id_key(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

pub fn mcp_tool_catalog(body: &serde_json::Value) -> &Vec<serde_json::Value> {
    body.pointer("/result/tools")
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("MCP response must have a 'result.tools' array: {body}"))
}

pub fn assert_mcp_tool_catalog_count(
    body: &serde_json::Value,
    expected: usize,
) {
    let actual = mcp_tool_catalog(body).len();
    assert_eq!(actual, expected, "expected {expected} tools in catalog, got {actual}");
}

pub fn assert_mcp_tool_catalog_includes(
    body: &serde_json::Value,
    expected_name: &str,
) {
    let names: Vec<&str> = mcp_tool_catalog(body)
        .iter()
        .filter_map(|tool| {
            tool.get("name")
                .and_then(|name| name.as_str())
        })
        .collect();
    assert!(names.contains(&expected_name), "expected tool catalog to include '{expected_name}', got {names:?}");
}

pub fn assert_mcp_tool_catalog_excludes(
    body: &serde_json::Value,
    unexpected_name: &str,
) {
    let names: Vec<&str> = mcp_tool_catalog(body)
        .iter()
        .filter_map(|tool| {
            tool.get("name")
                .and_then(|name| name.as_str())
        })
        .collect();
    assert!(!names.contains(&unexpected_name), "expected tool catalog to exclude '{unexpected_name}', got {names:?}");
}

pub fn assert_json_rpc_result_matches_response(
    actual: &serde_json::Value,
    expected: &serde_json::Value,
    actor_name: &str,
) {
    assert_eq!(
        actual.get("jsonrpc"),
        expected.get("jsonrpc"),
        "caller response JSON-RPC version did not match target response for '{actor_name}'"
    );

    let actual_result = actual
        .get("result")
        .cloned()
        .map(|mut r| {
            if let Some(obj) = r.as_object_mut() {
                obj.remove("_meta");
            }
            r
        });
    let expected_result = expected
        .get("result")
        .cloned()
        .map(|mut r| {
            if let Some(obj) = r.as_object_mut() {
                obj.remove("_meta");
            }
            r
        });
    assert_eq!(
        actual_result, expected_result,
        "caller response result did not match target response for '{actor_name}'"
    );
}

pub fn assert_mcp_response_preserves_field(
    response: &serde_json::Value,
    expected_body: &serde_json::Value,
    field: &str,
    context: &str,
) {
    let pointer = json_pointer_from_dotted(field);
    let expected_value = expected_body
        .pointer(&pointer)
        .unwrap_or_else(|| panic!("field '{field}' not found in {context} response"));
    let response_value = response
        .pointer(&pointer)
        .unwrap_or_else(|| panic!("field '{field}' not found in MCP response"));
    assert_eq!(
        response_value, expected_value,
        "MCP response field '{field}' differs from {context}.\nExpected: {expected_value}\nResponse: {response_value}"
    );
}

pub fn assert_mcp_response_result_matches_body(
    response: &serde_json::Value,
    expected_body: &serde_json::Value,
    context: &str,
) {
    let actual = response
        .get("result")
        .expect("MCP response must have 'result'");
    let expected = expected_body
        .get("result")
        .unwrap_or_else(|| panic!("{context} response must have 'result'"));
    assert_eq!(
        actual, expected,
        "MCP response result differs from {context} response result.\nExpected: {expected}\nActual: {actual}"
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_body_mentions_checks_common_error_fields_and_fallback_text() {
        let body = serde_json::json!({ "details": "surface alpha failed" });

        assert!(super::json_body_mentions(&body, "alpha"));
        assert!(super::json_body_mentions(&body, "surface"));
        assert!(!super::json_body_mentions(&body, "bravo"));
    }

    #[test]
    fn json_field_assertions_cover_absence_and_string_value() {
        let body = serde_json::json!({ "status": "disabled" });

        super::assert_json_string_field_equals(&body, "status", "disabled", "stored surface");
        super::assert_json_field_absent(&body, "surface_id", "admin response");
    }

    #[test]
    fn header_match_is_case_insensitive() {
        let headers = std::collections::HashMap::from([("Content-Type".to_string(), "application/json".to_string())]);

        let actual = super::get_header_value(&headers, "content-type", "response");

        assert_eq!(actual, "application/json");
    }

    #[test]
    fn content_type_contains_accepts_parameters() {
        let headers = std::collections::HashMap::from([(
            "content-type".to_string(),
            "application/problem+json; charset=utf-8".to_string(),
        )]);

        super::assert_content_type_contains(&headers, "application/problem+json", "response");
    }

    #[test]
    fn mcp_tool_catalog_assertions_find_named_tools() {
        let body = serde_json::json!({
            "result": {
                "tools": [{ "name": "search" }, { "name": "echo" }]
            }
        });

        super::assert_mcp_tool_catalog_count(&body, 2);
        super::assert_mcp_tool_catalog_includes(&body, "echo");
    }

    #[test]
    fn json_rpc_result_matcher_accepts_matching_protocol_fields() {
        let actual = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}, "extra": true});
        let expected = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}});

        super::assert_json_rpc_result_matches_response(&actual, &expected, "bravo");
    }

    #[test]
    #[should_panic(expected = "caller response result did not match target response for 'bravo'")]
    fn json_rpc_result_matcher_rejects_different_results() {
        let actual = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": false}});
        let expected = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}});

        super::assert_json_rpc_result_matches_response(&actual, &expected, "bravo");
    }

    #[test]
    fn json_rpc_id_matcher_accepts_request_correlation() {
        let request = serde_json::json!({"jsonrpc": "2.0", "id": "req-1", "method": "tools/list"});
        let response = serde_json::json!({"jsonrpc": "2.0", "id": "req-1", "result": {}});

        super::assert_json_rpc_id_matches_request_body(&response, &request, "MCP server 'bravo' forwarded");
    }

    #[test]
    fn mcp_method_matcher_accepts_expected_method() {
        let request = serde_json::json!({"jsonrpc": "2.0", "id": "req-1", "method": "tools/list"});

        super::assert_mcp_method(&request, "tools/list", "MCP server 'bravo'");
    }

    #[test]
    fn mcp_response_matchers_accept_matching_result_and_fields() {
        let response = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"marker": "ok"}});
        let expected = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"marker": "ok"}});

        super::assert_mcp_response_result_matches_body(&response, &expected, "MCP server 'bravo'");
        super::assert_mcp_response_preserves_field(&response, &expected, "result.marker", "MCP server 'bravo'");
    }

    #[test]
    fn unsupported_version_matcher_requires_exact_request_and_support_list() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32022,
                "message": "Unsupported protocol version",
                "data": {
                    "requested": "2026-07-28",
                    "supported": ["2024-11-05"]
                }
            }
        });
        super::assert_mcp_unsupported_version_error(&response, "2026-07-28", "2024-11-05");
    }

    #[test]
    fn json_rpc_error_matcher_accepts_expected_error_code() {
        let response = serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600}});

        super::assert_json_rpc_error_code(&response, -32600);
    }

    #[test]
    fn dotted_json_field_matcher_accepts_nested_match() {
        let actual = serde_json::json!({"params": {"name": "get_news"}});
        let expected = serde_json::json!({"params": {"name": "get_news"}});

        super::assert_json_field_matches(&actual, &expected, "params.name", "forwarded MCP request");
    }
}
