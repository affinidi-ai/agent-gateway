use axum::http::{HeaderValue, StatusCode};
use serde_json::{Value, json};

use super::error_codes;
use super::{MCP_LEGACY_VERSION, MCP_MODERN_VERSION};

const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";

/// The one caller Origin the endpoint under test allowlists.
pub(crate) const ALLOWED_ORIGIN: &str = "https://console.example";

pub(crate) struct AdmissionCase {
    pub name: &'static str,
    pub body: Vec<u8>,
    /// Sent in order, so a repeated name produces a duplicate header.
    pub headers: Vec<(&'static str, HeaderValue)>,
    pub status: StatusCode,
    pub code: i32,
    /// The error echoes the request id. Origin is checked before the body is
    /// read, so those errors carry no id.
    pub echoes_id: bool,
    /// `data.requested` of an unsupported-version error.
    pub requested: Option<&'static str>,
    /// The header value is not valid UTF-8, which only raw HTTP can carry.
    pub http_only: bool,
}

impl AdmissionCase {
    pub fn id(&self) -> Value {
        json!(format!("neg-{}", self.name))
    }

    /// The headers as a map, with repeated names kept.
    pub fn header_map(&self) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in &self.headers {
            headers.append(*name, value.clone());
        }
        headers
    }
}

fn request(
    name: &str,
    method: &str,
    params: Value,
) -> Value {
    json!({"jsonrpc": "2.0", "id": format!("neg-{name}"), "method": method, "params": params})
}

fn modern_meta() -> Value {
    json!({PROTOCOL_VERSION_META: MCP_MODERN_VERSION, CLIENT_CAPABILITIES_META: {}})
}

fn modern_headers(method: &'static str) -> Vec<(&'static str, HeaderValue)> {
    vec![
        ("content-type", HeaderValue::from_static("application/json")),
        ("accept", HeaderValue::from_static("application/json, text/event-stream")),
        ("mcp-protocol-version", HeaderValue::from_static(MCP_MODERN_VERSION)),
        ("mcp-method", HeaderValue::from_static(method)),
    ]
}

fn without(
    mut headers: Vec<(&'static str, HeaderValue)>,
    name: &str,
) -> Vec<(&'static str, HeaderValue)> {
    headers.retain(|(header, _)| *header != name);
    headers
}

fn replaced(
    headers: Vec<(&'static str, HeaderValue)>,
    name: &'static str,
    value: HeaderValue,
) -> Vec<(&'static str, HeaderValue)> {
    let mut headers = without(headers, name);
    headers.push((name, value));
    headers
}

fn case(
    name: &'static str,
    body: Value,
    headers: Vec<(&'static str, HeaderValue)>,
    code: i32,
) -> AdmissionCase {
    AdmissionCase {
        name,
        body: serde_json::to_vec(&body).unwrap(),
        headers,
        status: StatusCode::BAD_REQUEST,
        code,
        echoes_id: true,
        requested: None,
        http_only: false,
    }
}

fn origin_case(
    name: &'static str,
    origins: &[&'static str],
) -> AdmissionCase {
    let mut headers = modern_headers("tools/list");
    for origin in origins {
        headers.push(("origin", HeaderValue::from_static(origin)));
    }
    AdmissionCase {
        status: StatusCode::FORBIDDEN,
        echoes_id: false,
        ..case(
            name,
            request(name, "tools/list", json!({"_meta": modern_meta()})),
            headers,
            error_codes::INVALID_REQUEST,
        )
    }
}

pub(crate) fn admission_cases() -> Vec<AdmissionCase> {
    let list = |name| request(name, "tools/list", json!({"_meta": modern_meta()}));
    let mut missing_version = modern_meta();
    missing_version
        .as_object_mut()
        .unwrap()
        .remove(PROTOCOL_VERSION_META);
    let mut missing_capabilities = modern_meta();
    missing_capabilities
        .as_object_mut()
        .unwrap()
        .remove(CLIENT_CAPABILITIES_META);
    const UNSUPPORTED: &str = "2099-01-01";

    vec![
        case(
            "missing-protocol-version-meta",
            request("missing-protocol-version-meta", "tools/list", json!({"_meta": missing_version})),
            modern_headers("tools/list"),
            error_codes::INVALID_PARAMS,
        ),
        case(
            "missing-client-capabilities",
            request("missing-client-capabilities", "tools/list", json!({"_meta": missing_capabilities})),
            modern_headers("tools/list"),
            error_codes::INVALID_PARAMS,
        ),
        case(
            "missing-protocol-version-header",
            list("missing-protocol-version-header"),
            without(modern_headers("tools/list"), "mcp-protocol-version"),
            error_codes::HEADER_MISMATCH,
        ),
        case(
            "missing-method-header",
            list("missing-method-header"),
            without(modern_headers("tools/list"), "mcp-method"),
            error_codes::HEADER_MISMATCH,
        ),
        case(
            "duplicate-method-header",
            list("duplicate-method-header"),
            [modern_headers("tools/list"), vec![("mcp-method", HeaderValue::from_static("tools/list"))]].concat(),
            error_codes::HEADER_MISMATCH,
        ),
        AdmissionCase {
            http_only: true,
            ..case(
                "malformed-method-header",
                list("malformed-method-header"),
                replaced(modern_headers("tools/list"), "mcp-method", HeaderValue::from_bytes(&[0xff]).unwrap()),
                error_codes::HEADER_MISMATCH,
            )
        },
        case(
            "base64-invalid-name-header",
            request("base64-invalid-name-header", "tools/call", json!({"name": "search", "_meta": modern_meta()})),
            [modern_headers("tools/call"), vec![("mcp-name", HeaderValue::from_static("=?base64?%%%?="))]].concat(),
            error_codes::HEADER_MISMATCH,
        ),
        case(
            "protocol-version-header-mismatch",
            list("protocol-version-header-mismatch"),
            replaced(
                modern_headers("tools/list"),
                "mcp-protocol-version",
                HeaderValue::from_static(MCP_LEGACY_VERSION),
            ),
            error_codes::HEADER_MISMATCH,
        ),
        case(
            "method-header-mismatch",
            list("method-header-mismatch"),
            modern_headers("tools/call"),
            error_codes::HEADER_MISMATCH,
        ),
        case(
            "name-header-mismatch",
            request(
                "name-header-mismatch",
                "resources/read",
                json!({"uri": "file:///expected", "_meta": modern_meta()}),
            ),
            [modern_headers("resources/read"), vec![("mcp-name", HeaderValue::from_static("file:///other"))]].concat(),
            error_codes::HEADER_MISMATCH,
        ),
        AdmissionCase {
            requested: Some(UNSUPPORTED),
            ..case(
                "unsupported-version",
                request(
                    "unsupported-version",
                    "tools/list",
                    json!({"_meta": {PROTOCOL_VERSION_META: UNSUPPORTED, CLIENT_CAPABILITIES_META: {}}}),
                ),
                replaced(modern_headers("tools/list"), "mcp-protocol-version", HeaderValue::from_static(UNSUPPORTED)),
                error_codes::UNSUPPORTED_PROTOCOL_VERSION,
            )
        },
        case("batch", json!([list("batch")]), modern_headers("tools/list"), error_codes::INVALID_REQUEST),
        origin_case("untrusted-origin", &["https://untrusted.example"]),
        origin_case("null-origin", &["null"]),
        origin_case("duplicate-origin", &[ALLOWED_ORIGIN, ALLOWED_ORIGIN]),
        origin_case("malformed-origin", &["https://console.example/path"]),
    ]
}

/// Asserts a rejection against its case, from the status and the JSON-RPC body.
pub(crate) fn assert_rejected(
    case: &AdmissionCase,
    status: StatusCode,
    body: &Value,
    path: &str,
) {
    let name = case.name;
    assert_eq!(status, case.status, "{path} {name}: {body}");
    assert_eq!(body["error"]["code"], case.code, "{path} {name}: {body}");
    if case.echoes_id {
        // A batch has no single request id to echo.
        let expected = if name == "batch" {
            Value::Null
        } else {
            case.id()
        };
        assert_eq!(body["id"], expected, "{path} {name}: {body}");
    }
    if let Some(requested) = case.requested {
        assert_eq!(body["error"]["data"]["requested"], requested, "{path} {name}: {body}");
        assert!(
            body["error"]["data"]["supported"]
                .as_array()
                .is_some_and(|supported| supported.contains(&json!(MCP_LEGACY_VERSION))),
            "{path} {name}: {body}"
        );
    }
}
