use std::collections::HashSet;
use std::num::NonZeroUsize;

use axum::http::{HeaderMap, StatusCode, header};

use super::request_validation::{
    LegacySessionEvidence, McpMessageKind, McpRequestClassification, McpRequestValidationError, McpVersionPolicy,
    recover_request_id, validate_mcp_post,
};

#[derive(Debug, Clone, Copy)]
pub struct HttpLimits {
    pub max_request_bytes: NonZeroUsize,
    pub max_header_bytes: NonZeroUsize,
    pub max_accept_ranges: NonZeroUsize,
}

impl From<&crate::config::McpHttpConfig> for HttpLimits {
    fn from(config: &crate::config::McpHttpConfig) -> Self {
        Self {
            max_request_bytes: config.max_request_bytes,
            max_header_bytes: config.max_header_bytes,
            max_accept_ranges: config.max_accept_ranges,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EndpointHttpPolicy {
    origins: Option<OriginPolicy>,
    limits: HttpLimits,
    versions: McpVersionPolicy<'static>,
}

impl EndpointHttpPolicy {
    pub fn new(
        mode: Option<crate::config::McpProtocolMode>,
        config: Option<&crate::config::McpHttpConfig>,
        public_endpoints: &[String],
        path: super::request_validation::McpPathKind,
    ) -> Result<Self, String> {
        Self::with_versions(
            mode,
            config,
            public_endpoints,
            super::request_validation::endpoint_version_policy(mode, path),
        )
    }

    pub(crate) fn with_versions(
        mode: Option<crate::config::McpProtocolMode>,
        config: Option<&crate::config::McpHttpConfig>,
        public_endpoints: &[String],
        versions: McpVersionPolicy<'static>,
    ) -> Result<Self, String> {
        let defaults = crate::config::McpHttpConfig::default();
        let config = config.unwrap_or(&defaults);
        let origins = if mode == Some(crate::config::McpProtocolMode::Dual) {
            Some(OriginPolicy::new(public_endpoints, &config.allowed_origins)?)
        } else {
            None
        };
        Ok(Self {
            origins,
            limits: config.into(),
            versions: if mode == Some(crate::config::McpProtocolMode::Dual) {
                versions
            } else {
                super::request_validation::LEGACY_ONLY_POLICY
            },
        })
    }

    pub fn body_limit(&self) -> usize {
        self.origins
            .as_ref()
            .map_or(usize::MAX, |_| {
                self.limits
                    .max_request_bytes
                    .get()
            })
    }

    pub fn validate_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<(), HttpAdmissionError> {
        if let Some(origins) = &self.origins {
            validate_header_budget(headers, self.limits)?;
            origins.validate(headers)?;
        }
        Ok(())
    }

    pub fn admit_post(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        session: LegacySessionEvidence,
    ) -> Result<McpRequestClassification, Box<McpRequestValidationError>> {
        admit_post(headers, body, session, self.versions, self.origins.as_ref(), self.limits)
    }

    /// Caps an admitted legacy `initialize` to a revision this endpoint serves;
    /// see [`super::request_validation::cap_legacy_initialize`].
    pub fn cap_legacy_initialize(
        &self,
        body: &[u8],
        classification: &McpRequestClassification,
    ) -> Option<super::request_validation::CappedInitialize> {
        super::request_validation::cap_legacy_initialize(body, classification, self.versions)
    }

    pub fn non_post_response(
        &self,
        method: &axum::http::Method,
        headers: &HeaderMap,
    ) -> Option<axum::response::Response> {
        if self.origins.is_none() || !matches!(*method, axum::http::Method::GET | axum::http::Method::DELETE) {
            return None;
        }
        let mut versions = headers
            .get_all("mcp-protocol-version")
            .iter();
        let version = versions.next()?;
        if versions.next().is_some() || version.to_str().is_err() {
            return Some(
                (*super::request_validation::malformed_transport_header(
                    &[],
                    "MCP-Protocol-Version requires one valid header value",
                ))
                .into_response(),
            );
        }
        if version != super::MCP_MODERN_VERSION {
            return None;
        }
        let mut response = axum::response::Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response
            .headers_mut()
            .insert(header::ALLOW, axum::http::HeaderValue::from_static("POST"));
        Some(response)
    }

    pub fn body_read_error(
        &self,
        error: axum::Error,
    ) -> Box<McpRequestValidationError> {
        if std::error::Error::source(&error).is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) {
            BODY_TOO_LARGE.into_validation_error(None)
        } else {
            HttpAdmissionError {
                status: StatusCode::BAD_REQUEST,
                message: "Failed to read MCP request body",
            }
            .into_validation_error(None)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpAdmissionError {
    pub status: StatusCode,
    pub message: &'static str,
}

impl HttpAdmissionError {
    pub fn into_validation_error(
        self,
        id: Option<serde_json::Value>,
    ) -> Box<McpRequestValidationError> {
        Box::new(McpRequestValidationError {
            status: self.status,
            id,
            code: super::error_codes::INVALID_REQUEST,
            message: self.message.to_string(),
            data: None,
        })
    }

    pub fn into_response(
        self,
        id: Option<serde_json::Value>,
    ) -> axum::response::Response {
        (*self.into_validation_error(id)).into_response()
    }
}

const INVALID_ORIGIN: HttpAdmissionError = HttpAdmissionError {
    status: StatusCode::FORBIDDEN,
    message: "Origin is not permitted on this MCP endpoint",
};
const INVALID_ACCEPT: HttpAdmissionError = HttpAdmissionError {
    status: StatusCode::BAD_REQUEST,
    message: "Invalid Accept media ranges or quality values",
};
const NOT_ACCEPTABLE: HttpAdmissionError = HttpAdmissionError {
    status: StatusCode::NOT_ACCEPTABLE,
    message: "Accept must explicitly permit application/json and text/event-stream",
};
const UNSUPPORTED_CONTENT_TYPE: HttpAdmissionError = HttpAdmissionError {
    status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
    message: "MCP POST requires one application/json Content-Type with UTF-8 encoding",
};
const HEADERS_TOO_LARGE: HttpAdmissionError = HttpAdmissionError {
    status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
    message: "MCP request headers exceed the configured limit",
};
const BODY_TOO_LARGE: HttpAdmissionError = HttpAdmissionError {
    status: StatusCode::PAYLOAD_TOO_LARGE,
    message: "MCP request body exceeds the configured limit",
};

pub fn strip_protocol_session_headers(headers: &mut HeaderMap) {
    headers.remove("mcp-session-id");
    headers.remove("last-event-id");
}

pub fn admit_post(
    headers: &HeaderMap,
    body: &[u8],
    session: LegacySessionEvidence,
    versions: McpVersionPolicy<'_>,
    origins: Option<&OriginPolicy>,
    limits: HttpLimits,
) -> Result<McpRequestClassification, Box<McpRequestValidationError>> {
    let transport_error = |error: HttpAdmissionError| {
        let id = (body.len() <= limits.max_request_bytes.get())
            .then(|| serde_json::from_slice::<serde_json::Value>(body).ok())
            .flatten()
            .and_then(|value| {
                value
                    .as_object()
                    .and_then(recover_request_id)
            });
        error.into_validation_error(id)
    };
    if let Some(origins) = origins {
        validate_header_budget(headers, limits).map_err(transport_error)?;
        origins
            .validate(headers)
            .map_err(transport_error)?;
        if body.len() > limits.max_request_bytes.get() {
            return Err(transport_error(BODY_TOO_LARGE));
        }
    }
    let classification = validate_mcp_post(headers, body, session, versions)?;
    if let McpRequestClassification::Modern(message) = &classification {
        if origins.is_none() {
            return Err(transport_error(HttpAdmissionError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Modern MCP endpoint has no configured Origin policy",
            }));
        }
        if message.kind == McpMessageKind::Request {
            validate_modern_post(headers, limits).map_err(transport_error)?;
            if message.method == "subscriptions/listen" {
                super::subscriptions::SubscriptionFilter::from_request(message)?;
            }
        } else {
            validate_content_type(headers).map_err(transport_error)?;
        }
    }
    Ok(classification)
}

#[derive(Debug, Clone)]
pub struct OriginPolicy {
    allowed: HashSet<String>,
}

fn parsed_origin(value: &str) -> Option<String> {
    let endpoint = url::Url::parse(value).ok()?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return None;
    }
    Some(
        endpoint
            .origin()
            .ascii_serialization(),
    )
}

impl OriginPolicy {
    pub fn new(
        public_endpoints: &[String],
        allowed_origins: &[String],
    ) -> Result<Self, String> {
        let mut allowed = HashSet::new();
        for endpoint in public_endpoints {
            let origin = parsed_origin(endpoint).ok_or("MCP public endpoints must have an HTTP(S) origin")?;
            allowed.insert(origin);
        }
        for origin in allowed_origins {
            if parsed_origin(origin).as_deref() != Some(origin.as_str()) {
                return Err("MCP allowed origins must be exact serialized HTTP(S) origins".to_string());
            }
            allowed.insert(origin.clone());
        }
        Ok(Self { allowed })
    }

    pub fn validate(
        &self,
        headers: &HeaderMap,
    ) -> Result<(), HttpAdmissionError> {
        let mut values = headers
            .get_all(header::ORIGIN)
            .iter();
        let Some(value) = values.next() else {
            return Ok(());
        };
        let origin = value
            .to_str()
            .map_err(|_| INVALID_ORIGIN)?;
        if values.next().is_some() || parsed_origin(origin).as_deref() != Some(origin) || !self.allowed.contains(origin)
        {
            return Err(INVALID_ORIGIN);
        }
        Ok(())
    }
}

pub fn validate_header_budget(
    headers: &HeaderMap,
    limits: HttpLimits,
) -> Result<(), HttpAdmissionError> {
    let bytes = headers
        .iter()
        .fold(0_usize, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
                .saturating_add(4)
        });
    if bytes > limits.max_header_bytes.get() {
        return Err(HEADERS_TOO_LARGE);
    }
    Ok(())
}

pub fn validate_modern_post(
    headers: &HeaderMap,
    limits: HttpLimits,
) -> Result<(), HttpAdmissionError> {
    validate_header_budget(headers, limits)?;
    validate_content_type(headers)?;
    validate_accept(headers, limits.max_accept_ranges)
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), HttpAdmissionError> {
    let mut content_types = headers
        .get_all(header::CONTENT_TYPE)
        .iter();
    let content_type: mime::Mime = content_types
        .next()
        .ok_or(UNSUPPORTED_CONTENT_TYPE)?
        .to_str()
        .map_err(|_| UNSUPPORTED_CONTENT_TYPE)?
        .parse()
        .map_err(|_| UNSUPPORTED_CONTENT_TYPE)?;
    if content_types.next().is_some()
        || content_type.essence_str() != "application/json"
        || content_type
            .params()
            .any(|(name, value)| name == mime::CHARSET && value != mime::UTF_8)
    {
        return Err(UNSUPPORTED_CONTENT_TYPE);
    }
    Ok(())
}

fn quality_value(value: &str) -> Result<u16, HttpAdmissionError> {
    let (whole, fraction) = value
        .split_once('.')
        .unwrap_or((value, ""));
    if fraction.len() > 3
        || !fraction
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(INVALID_ACCEPT);
    }
    match whole {
        "1" if fraction
            .bytes()
            .all(|byte| byte == b'0') =>
        {
            Ok(1000)
        }
        "0" => Ok(fraction
            .parse::<u16>()
            .unwrap_or(0)
            * 10_u16.pow(3 - fraction.len() as u32)),
        _ => Err(INVALID_ACCEPT),
    }
}

fn media_ranges(
    value: &str,
    remaining: usize,
) -> Result<Vec<mime::Mime>, HttpAdmissionError> {
    let mut ranges = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    for (index, byte) in value
        .bytes()
        .chain(std::iter::once(b','))
        .enumerate()
    {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b',' && !quoted {
            let item = value[start..index].trim();
            if !item.is_empty() {
                if ranges.len() >= remaining {
                    return Err(HEADERS_TOO_LARGE);
                }
                ranges.push(
                    item.parse::<mime::Mime>()
                        .map_err(|_| INVALID_ACCEPT)?,
                );
            }
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(INVALID_ACCEPT);
    }
    Ok(ranges)
}

fn validate_accept(
    headers: &HeaderMap,
    max_ranges: NonZeroUsize,
) -> Result<(), HttpAdmissionError> {
    let mut json_quality: Option<u16> = None;
    let mut sse_quality: Option<u16> = None;
    let mut range_count = 0;
    for value in headers.get_all(header::ACCEPT) {
        for range in media_ranges(
            value
                .to_str()
                .map_err(|_| INVALID_ACCEPT)?,
            max_ranges.get() - range_count,
        )? {
            range_count += 1;
            if range.type_() == mime::STAR && range.subtype() != mime::STAR {
                return Err(INVALID_ACCEPT);
            }
            let mut quality = None;
            let mut parameters_match = true;
            for (name, value) in range.params() {
                if name == "q" {
                    if quality.is_some() {
                        return Err(INVALID_ACCEPT);
                    }
                    quality = Some(quality_value(value.as_str())?);
                } else if quality.is_none() && !(name == mime::CHARSET && value == mime::UTF_8) {
                    parameters_match = false;
                }
            }
            if parameters_match {
                let accepted = match range.essence_str() {
                    "application/json" => &mut json_quality,
                    "text/event-stream" => &mut sse_quality,
                    _ => continue,
                };
                let quality = quality.unwrap_or(1000);
                *accepted = Some(accepted.map_or(quality, |previous| previous.min(quality)));
            }
        }
    }
    if json_quality.unwrap_or(0) == 0 || sse_quality.unwrap_or(0) == 0 {
        return Err(NOT_ACCEPTABLE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_admission_checks_filters_after_wire_and_media_validation() {
        let origins = OriginPolicy::new(&["https://gateway.example".to_string()], &[]).unwrap();
        let limits = HttpLimits::from(&crate::config::McpHttpConfig::default());
        let versions = McpVersionPolicy::new(&[crate::mcp::MCP_MODERN_VERSION], &[crate::mcp::MCP_MODERN_VERSION]);
        let headers = HeaderMap::from_iter([
            (
                header::CONTENT_TYPE,
                "application/json"
                    .parse()
                    .unwrap(),
            ),
            (
                header::ACCEPT,
                "application/json, text/event-stream"
                    .parse()
                    .unwrap(),
            ),
            (
                axum::http::HeaderName::from_static("mcp-method"),
                "subscriptions/listen"
                    .parse()
                    .unwrap(),
            ),
            (
                axum::http::HeaderName::from_static("mcp-protocol-version"),
                crate::mcp::MCP_MODERN_VERSION
                    .parse()
                    .unwrap(),
            ),
        ]);
        for notifications in
            [serde_json::json!({}), serde_json::json!({"toolsListChanged": true}), serde_json::json!([])]
        {
            let body = serde_json::to_vec(&serde_json::json!({"jsonrpc": "2.0", "id": "listen", "method": "subscriptions/listen", "params": {
                "notifications": notifications, "_meta": {"io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}}
            }})).unwrap();
            let result = admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, Some(&origins), limits);
            if notifications.is_object() {
                assert!(matches!(result, Ok(McpRequestClassification::Modern(_))));
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.code, crate::mcp::error_codes::INVALID_PARAMS);
                assert_eq!(error.id, Some(serde_json::json!("listen")));
            }
            let error = admit_post(
                &headers,
                &body,
                LegacySessionEvidence::Absent,
                super::super::request_validation::LEGACY_ONLY_POLICY,
                Some(&origins),
                limits,
            )
            .unwrap_err();
            assert_eq!(error.code, crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        }
    }

    #[test]
    fn modern_forwarding_removes_only_session_and_resumption_state() {
        let mut headers = modern_headers();
        headers.append("mcp-session-id", "first".parse().unwrap());
        headers.append("mcp-session-id", "second".parse().unwrap());
        headers.insert("last-event-id", "resume".parse().unwrap());
        headers.append("mcp-param-custom", "one".parse().unwrap());
        headers.append("mcp-param-custom", "two".parse().unwrap());
        let mut expected = headers.clone();
        expected.remove("mcp-session-id");
        expected.remove("last-event-id");
        strip_protocol_session_headers(&mut headers);
        assert_eq!(headers, expected);
        assert_eq!(
            headers
                .get_all("mcp-param-custom")
                .iter()
                .count(),
            2
        );
    }

    #[test]
    fn explicit_modern_get_and_delete_are_post_only_without_affecting_legacy_routes() {
        let dual = EndpointHttpPolicy::new(
            Some(crate::config::McpProtocolMode::Dual),
            None,
            &[],
            crate::mcp::request_validation::McpPathKind::DirectAccessPoint,
        )
        .unwrap();
        let legacy =
            EndpointHttpPolicy::new(None, None, &[], crate::mcp::request_validation::McpPathKind::DirectAccessPoint)
                .unwrap();
        let mut headers = modern_headers();
        headers.insert(
            "mcp-session-id",
            "attached-legacy-session"
                .parse()
                .unwrap(),
        );
        for method in [axum::http::Method::GET, axum::http::Method::DELETE] {
            let response = dual
                .non_post_response(&method, &headers)
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()[header::ALLOW], "POST");
            assert!(
                legacy
                    .non_post_response(&method, &headers)
                    .is_none()
            );
            assert!(
                dual.non_post_response(&method, &HeaderMap::new())
                    .is_none()
            );
        }
        assert!(
            dual.non_post_response(&axum::http::Method::POST, &headers)
                .is_none()
        );
        assert!(
            dual.non_post_response(&axum::http::Method::OPTIONS, &headers)
                .is_none()
        );
        headers.insert(
            "mcp-protocol-version",
            super::super::MCP_LEGACY_VERSION
                .parse()
                .unwrap(),
        );
        assert!(
            dual.non_post_response(&axum::http::Method::GET, &headers)
                .is_none()
        );
        headers.append(
            "mcp-protocol-version",
            super::super::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        assert_eq!(
            dual.non_post_response(&axum::http::Method::GET, &headers)
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn mcp_http_config_defaults_round_trips_and_rejects_invalid_settings() {
        let defaults: crate::config::McpHttpConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults, crate::config::McpHttpConfig::default());
        assert_eq!(defaults.validate(), Ok(()));
        let configured: crate::config::McpHttpConfig = serde_json::from_value(serde_json::json!({
            "allowed_origins": ["https://console.example"], "max_request_bytes": 4096,
            "max_header_bytes": 512, "max_accept_ranges": 2
        }))
        .unwrap();
        assert_eq!(configured.validate(), Ok(()));
        let limits = HttpLimits::from(&configured);
        assert_eq!(limits.max_request_bytes.get(), 4096);
        assert_eq!(limits.max_header_bytes.get(), 512);
        assert_eq!(limits.max_accept_ranges.get(), 2);
        let restored: crate::config::McpHttpConfig =
            serde_json::from_value(serde_json::to_value(&configured).unwrap()).unwrap();
        assert_eq!(restored, configured);
        for value in [
            serde_json::json!({"max_request_bytes": 0}),
            serde_json::json!({"max_header_bytes": -1}),
            serde_json::json!({"max_accept_ranges": 0}),
            serde_json::json!({"allow_all_origins": true}),
        ] {
            assert!(serde_json::from_value::<crate::config::McpHttpConfig>(value).is_err());
        }
        let invalid: crate::config::McpHttpConfig =
            serde_json::from_value(serde_json::json!({"allowed_origins": ["*"]})).unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn mcp_http_endpoint_policy_applies_limits_only_to_opted_in_endpoints() {
        let config = crate::config::McpHttpConfig::default();
        let mut headers = modern_headers();
        headers.insert(
            header::ORIGIN,
            "https://untrusted.example"
                .parse()
                .unwrap(),
        );
        for mode in [None, Some(crate::config::McpProtocolMode::Legacy)] {
            let policy = EndpointHttpPolicy::new(
                mode,
                Some(&config),
                &[],
                crate::mcp::request_validation::McpPathKind::DirectAccessPoint,
            )
            .unwrap();
            assert_eq!(policy.body_limit(), usize::MAX);
            assert_eq!(policy.validate_headers(&headers), Ok(()));
            assert_eq!(
                policy
                    .admit_post(&headers, &modern_body(), LegacySessionEvidence::Absent)
                    .unwrap_err()
                    .code,
                super::super::error_codes::UNSUPPORTED_PROTOCOL_VERSION
            );
        }
        let policy = EndpointHttpPolicy::new(
            Some(crate::config::McpProtocolMode::Dual),
            Some(&config),
            &[],
            crate::mcp::request_validation::McpPathKind::DirectAccessPoint,
        )
        .unwrap();
        assert_eq!(policy.body_limit(), config.max_request_bytes.get());
        assert_eq!(policy.validate_headers(&headers), Err(INVALID_ORIGIN));
        assert!(
            policy
                .versions
                .supports_modern(super::super::MCP_MODERN_VERSION),
            "a dual endpoint admits modern requests"
        );
    }

    fn limits() -> HttpLimits {
        HttpLimits {
            max_request_bytes: NonZeroUsize::new(1048576).unwrap(),
            max_header_bytes: NonZeroUsize::new(16384).unwrap(),
            max_accept_ranges: NonZeroUsize::new(32).unwrap(),
        }
    }

    fn headers(accept: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, accept.parse().unwrap());
        headers.insert(
            header::CONTENT_TYPE,
            "application/json"
                .parse()
                .unwrap(),
        );
        headers
    }

    #[test]
    fn origin_allows_missing_and_exact_trusted_origins_only() {
        let policy =
            OriginPolicy::new(&["https://gateway.example:8443/mcp".into()], &["https://console.example".into()])
                .unwrap();
        assert_eq!(policy.validate(&HeaderMap::new()), Ok(()));
        for origin in ["https://gateway.example:8443", "https://console.example"] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert_eq!(policy.validate(&headers), Ok(()));
        }
        for origin in [
            "null",
            "*",
            "",
            "https://console.example/",
            "https://console.example/path",
            "https://console.example?query",
            "https://console.example#fragment",
            "https://user@console.example",
            "https://console.example.attacker.test",
            "http://console.example",
            "https://console.example, https://gateway.example:8443",
            "https://console.example https://gateway.example:8443",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            headers.insert(
                "x-forwarded-host",
                "console.example"
                    .parse()
                    .unwrap(),
            );
            assert_eq!(policy.validate(&headers), Err(INVALID_ORIGIN), "{origin}");
        }
    }

    #[test]
    fn origin_rejects_duplicate_fields_and_invalid_allowlist_configuration() {
        let policy = OriginPolicy::new(&[], &["https://console.example".into()]).unwrap();
        let mut headers = HeaderMap::new();
        headers.append(
            header::ORIGIN,
            "https://console.example"
                .parse()
                .unwrap(),
        );
        headers.append(
            header::ORIGIN,
            "https://console.example"
                .parse()
                .unwrap(),
        );
        assert_eq!(policy.validate(&headers), Err(INVALID_ORIGIN));
        for origin in [
            "null",
            "*",
            "https://console.example/",
            "https://console.example/path",
            "file:///tmp",
            "https://user@console.example",
        ] {
            assert!(OriginPolicy::new(&[], &[origin.into()]).is_err(), "{origin}");
        }
    }

    #[test]
    fn accept_parses_repeated_fields_quotes_parameters_and_quality() {
        for accept in [
            "application/json, text/event-stream",
            "APPLICATION/JSON; q=0.001, TEXT/EVENT-STREAM; charset=utf-8; q=1.000",
            "application/json;q=0.9;note=\"comma,here\", text/event-stream",
            ", application/json, , text/event-stream,",
            "*/*;q=0, application/json, text/event-stream",
        ] {
            assert_eq!(validate_modern_post(&headers(accept), limits()), Ok(()), "{accept}");
        }
        let mut repeated = headers("application/json;q=0.1");
        repeated.append(
            header::ACCEPT,
            "text/event-stream;q=0.2"
                .parse()
                .unwrap(),
        );
        assert_eq!(validate_modern_post(&repeated, limits()), Ok(()));
    }

    #[test]
    fn accept_requires_both_explicit_media_types_without_zero_quality() {
        for accept in [
            "",
            "*/*",
            "application/json",
            "text/event-stream",
            "application/*, text/*",
            "application/json;q=0, text/event-stream, */*;q=1",
            "application/json, text/event-stream;q=0.000",
            "application/json, text/event-stream;q=1, text/event-stream;q=0",
            "application/json;profile=other, text/event-stream",
        ] {
            assert_eq!(validate_modern_post(&headers(accept), limits()), Err(NOT_ACCEPTABLE), "{accept}");
        }
        let mut missing = headers("application/json, text/event-stream");
        missing.remove(header::ACCEPT);
        assert_eq!(validate_modern_post(&missing, limits()), Err(NOT_ACCEPTABLE));
    }

    #[test]
    fn malformed_media_ranges_and_quality_are_rejected() {
        for value in ["1.001", "0.0001", "1.0000", "-1", "+1", "NaN", "01", ".5"] {
            let accept = format!("application/json;q={value}, text/event-stream");
            assert_eq!(validate_modern_post(&headers(&accept), limits()), Err(INVALID_ACCEPT), "{value}");
        }
        for accept in [
            "application/json;q=1;q=0, text/event-stream",
            "application/json;q=1;note=\"unfinished, text/event-stream",
            "application/json, */event-stream",
            "application/json, invalid",
        ] {
            assert_eq!(validate_modern_post(&headers(accept), limits()), Err(INVALID_ACCEPT), "{accept}");
        }
    }

    #[test]
    fn content_type_requires_one_json_field_and_utf8() {
        let mut headers = headers("application/json, text/event-stream");
        headers.insert(
            header::CONTENT_TYPE,
            "application/json; charset=utf-8"
                .parse()
                .unwrap(),
        );
        assert_eq!(validate_modern_post(&headers, limits()), Ok(()));
        for content_type in [
            "text/plain",
            "application/problem+json",
            "application/json+vendor",
            "application/json; charset=iso-8859-1",
            "application/json, application/json",
        ] {
            headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
            assert_eq!(validate_modern_post(&headers, limits()), Err(UNSUPPORTED_CONTENT_TYPE), "{content_type}");
        }
        headers.insert(
            header::CONTENT_TYPE,
            "application/json"
                .parse()
                .unwrap(),
        );
        headers.append(
            header::CONTENT_TYPE,
            "application/json"
                .parse()
                .unwrap(),
        );
        assert_eq!(validate_modern_post(&headers, limits()), Err(UNSUPPORTED_CONTENT_TYPE));
        headers.remove(header::CONTENT_TYPE);
        assert_eq!(validate_modern_post(&headers, limits()), Err(UNSUPPORTED_CONTENT_TYPE));
    }

    #[test]
    fn header_and_media_range_budgets_have_exact_boundaries() {
        let headers = headers("application/json, text/event-stream");
        let total = headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
            .sum();
        let mut limits = HttpLimits {
            max_header_bytes: NonZeroUsize::new(total).unwrap(),
            max_accept_ranges: NonZeroUsize::new(2).unwrap(),
            ..limits()
        };
        assert_eq!(validate_modern_post(&headers, limits), Ok(()));
        limits.max_header_bytes = NonZeroUsize::new(total - 1).unwrap();
        assert_eq!(validate_modern_post(&headers, limits), Err(HEADERS_TOO_LARGE));
        limits.max_header_bytes = NonZeroUsize::new(total + 1).unwrap();
        limits.max_accept_ranges = NonZeroUsize::new(1).unwrap();
        assert_eq!(validate_modern_post(&headers, limits), Err(HEADERS_TOO_LARGE));
    }

    fn modern_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0", "id": "admission", "method": "server/discover", "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": super::super::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        }))
        .unwrap()
    }

    fn modern_headers() -> HeaderMap {
        let mut headers = headers("application/json, text/event-stream");
        headers.insert(
            "mcp-protocol-version",
            super::super::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert(
            "mcp-method",
            "server/discover"
                .parse()
                .unwrap(),
        );
        headers
    }

    #[test]
    fn admission_preserves_legacy_paths_and_requires_modern_origin_configuration() {
        let versions = McpVersionPolicy::new(&[super::super::MCP_MODERN_VERSION], &[super::super::MCP_MODERN_VERSION]);
        let mut legacy_headers = HeaderMap::new();
        legacy_headers.insert(
            header::ORIGIN,
            "https://untrusted.example"
                .parse()
                .unwrap(),
        );
        let legacy = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        assert_eq!(
            admit_post(&legacy_headers, legacy, LegacySessionEvidence::Absent, versions, None, limits()),
            validate_mcp_post(&legacy_headers, legacy, LegacySessionEvidence::Absent, versions)
        );
        let body = modern_body();
        let headers = modern_headers();
        assert_eq!(
            admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, None, limits())
                .unwrap_err()
                .status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let origins = OriginPolicy::new(&[], &[]).unwrap();
        assert!(matches!(
            admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, Some(&origins), limits()),
            Ok(McpRequestClassification::Modern(_))
        ));
        let error = admit_post(
            &headers,
            &body,
            LegacySessionEvidence::Absent,
            super::super::request_validation::LEGACY_ONLY_POLICY,
            Some(&origins),
            limits(),
        )
        .unwrap_err();
        assert_eq!(error.code, super::super::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(
            error.data,
            Some(
                serde_json::json!({"requested": super::super::MCP_MODERN_VERSION, "supported": [super::super::MCP_LEGACY_VERSION]})
            )
        );
    }

    #[test]
    fn admission_prioritizes_origin_then_wire_validation_then_media_types() {
        let origins = OriginPolicy::new(&[], &[]).unwrap();
        let versions = McpVersionPolicy::new(&[super::super::MCP_MODERN_VERSION], &[super::super::MCP_MODERN_VERSION]);
        let mut headers = modern_headers();
        headers.insert(
            header::ORIGIN,
            "https://untrusted.example"
                .parse()
                .unwrap(),
        );
        headers.remove("mcp-method");
        headers.remove(header::CONTENT_TYPE);
        headers.remove(header::ACCEPT);
        let body = modern_body();
        let error =
            admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, Some(&origins), limits()).unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.id, Some(serde_json::json!("admission")));
        headers.remove(header::ORIGIN);
        let error =
            admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, Some(&origins), limits()).unwrap_err();
        assert_eq!(error.code, super::super::error_codes::HEADER_MISMATCH);
        headers.insert(
            "mcp-method",
            "server/discover"
                .parse()
                .unwrap(),
        );
        let error =
            admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, Some(&origins), limits()).unwrap_err();
        assert_eq!(error.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        headers.insert(
            header::CONTENT_TYPE,
            "application/json"
                .parse()
                .unwrap(),
        );
        let error =
            admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, Some(&origins), limits()).unwrap_err();
        assert_eq!(error.status, StatusCode::NOT_ACCEPTABLE);
        assert_eq!(error.id, Some(serde_json::json!("admission")));
    }

    #[test]
    fn admission_enforces_request_body_limits_without_parsing_oversized_content() {
        let origins = OriginPolicy::new(&[], &[]).unwrap();
        let versions = McpVersionPolicy::new(&[super::super::MCP_MODERN_VERSION], &[super::super::MCP_MODERN_VERSION]);
        let body = modern_body();
        let headers = modern_headers();
        let mut limits = limits();
        limits.max_request_bytes = NonZeroUsize::new(body.len()).unwrap();
        assert!(admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, Some(&origins), limits).is_ok());
        limits.max_request_bytes = NonZeroUsize::new(body.len() - 1).unwrap();
        let error =
            admit_post(&headers, &body, LegacySessionEvidence::Absent, versions, Some(&origins), limits).unwrap_err();
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.id, None);
    }
}
