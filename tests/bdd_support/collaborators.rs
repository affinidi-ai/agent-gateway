use std::collections::{BTreeSet, HashMap};

use crate::bdd_support::mock_server::ReceivedRequest;

pub fn assert_no_requests(
    requests: &[ReceivedRequest],
    context: &str,
) {
    assert!(requests.is_empty(), "{context} unexpectedly received {} request(s): {requests:?}", requests.len());
}

pub fn assert_request_count(
    requests: &[ReceivedRequest],
    expected_count: usize,
    context: &str,
) {
    assert_eq!(
        requests.len(),
        expected_count,
        "{context} should receive {expected_count} request(s), got {}",
        requests.len()
    );
}

pub fn assert_called_exactly_once<'a>(
    requests: &'a [ReceivedRequest],
    context: &str,
) -> &'a ReceivedRequest {
    assert_request_count(requests, 1, context);
    requests
        .last()
        .expect("exactly one request must include a last request")
}

pub fn assert_header_value(
    headers: &HashMap<String, String>,
    header: &str,
    expected_value: &str,
    context: &str,
) {
    let actual = header_value(headers, header)
        .unwrap_or_else(|| panic!("{context} missing header '{header}'; headers: {headers:?}"));
    assert_eq!(actual, expected_value, "{context} header '{header}' value mismatch");
}

pub fn assert_header_absent(
    headers: &HashMap<String, String>,
    header: &str,
    context: &str,
) {
    assert!(
        header_value(headers, header).is_none(),
        "{context} unexpectedly carried header '{header}'; headers: {headers:?}"
    );
}

pub fn assert_request_content_type_starts_with(
    request: &ReceivedRequest,
    expected: &str,
    context: &str,
) {
    let actual = request
        .content_type
        .as_deref()
        .unwrap_or_default();
    assert!(actual.starts_with(expected), "{context} content type mismatch: expected '{expected}', got '{actual}'");
}

pub fn assert_json_request_body(
    request: &ReceivedRequest,
    context: &str,
) {
    let body = request.json_body();
    assert!(body.is_object(), "{context} did not receive a JSON request: {body}");
}

pub fn assert_unique_json_rpc_request_ids(
    requests: &[ReceivedRequest],
    expected_count: usize,
    context: &str,
) {
    let request_ids: BTreeSet<String> = requests
        .iter()
        .map(|request| {
            let body = request.json_body();
            json_rpc_id_key(
                body.get("id")
                    .unwrap_or(&serde_json::Value::Null),
            )
        })
        .collect();
    assert_eq!(request_ids.len(), expected_count, "{context} received duplicate JSON-RPC ids: {request_ids:?}");
}

fn header_value<'a>(
    headers: &'a HashMap<String, String>,
    header: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case(header)
                .then_some(value.as_str())
        })
}

fn json_rpc_id_key(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::bdd_support::mock_server::ReceivedRequest;

    fn request() -> ReceivedRequest {
        ReceivedRequest {
            method: "POST".to_string(),
            headers: HashMap::from([("content-type".to_string(), "application/json; charset=utf-8".to_string())]),
            raw_body: r#"{"ok":true}"#.to_string(),
            content_type: Some("application/json; charset=utf-8".to_string()),
            path_and_query: "/example".to_string(),
        }
    }

    #[test]
    fn called_once_returns_last_request() {
        let requests = vec![request()];
        let observed = super::assert_called_exactly_once(&requests, "managed agent 'alpha'");

        assert_eq!(observed.path_and_query, "/example");
    }

    #[test]
    fn header_match_is_case_insensitive() {
        let request = request();

        super::assert_header_value(&request.headers, "Content-Type", "application/json; charset=utf-8", "request");
    }

    #[test]
    fn content_type_prefix_accepts_parameters() {
        let request = request();

        super::assert_request_content_type_starts_with(&request, "application/json", "request");
    }

    #[test]
    fn json_request_body_accepts_object_body() {
        let request = request();

        super::assert_json_request_body(&request, "MCP server 'bravo'");
    }

    #[test]
    fn unique_json_rpc_request_ids_accepts_distinct_ids() {
        let requests = vec![
            ReceivedRequest {
                raw_body: r#"{"id":1}"#.to_string(),
                ..request()
            },
            ReceivedRequest {
                raw_body: r#"{"id":"two"}"#.to_string(),
                ..request()
            },
        ];

        super::assert_unique_json_rpc_request_ids(&requests, 2, "MCP server 'bravo'");
    }
}
