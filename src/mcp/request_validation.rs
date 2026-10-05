use axum::http::{HeaderMap, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value as JsonValue, json};

use super::{MCP_LEGACY_VERSION, error_codes};

const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";
const CLIENT_INFO_META: &str = "io.modelcontextprotocol/clientInfo";
const LOG_LEVEL_META: &str = "io.modelcontextprotocol/logLevel";
const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const METHOD_HEADER: &str = "mcp-method";
const NAME_HEADER: &str = "mcp-name";
const BASE64_PREFIX: &str = "=?base64?";
const BASE64_SUFFIX: &str = "?=";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacySessionEvidence {
    Absent,
    Known,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub struct McpVersionPolicy<'a> {
    active_modern_versions: &'a [&'a str],
    supported_versions: &'a [&'a str],
}

impl<'a> McpVersionPolicy<'a> {
    pub const fn new(
        active_modern_versions: &'a [&'a str],
        supported_versions: &'a [&'a str],
    ) -> Self {
        Self {
            active_modern_versions,
            supported_versions,
        }
    }

    pub(crate) fn supports_modern(
        &self,
        version: &str,
    ) -> bool {
        self.active_modern_versions
            .contains(&version)
    }

    pub(crate) fn supported_versions(&self) -> &[&str] {
        self.supported_versions
    }

    /// Returns whichever of two nested policies admits and advertises less.
    pub(crate) fn within(
        self,
        limit: Self,
    ) -> Self {
        if self.includes(&limit) {
            limit
        } else {
            self
        }
    }

    fn includes(
        &self,
        other: &Self,
    ) -> bool {
        let covers = |outer: &[&str], inner: &[&str]| {
            inner
                .iter()
                .all(|version| outer.contains(version))
        };
        covers(self.active_modern_versions, other.active_modern_versions)
            && covers(self.supported_versions, other.supported_versions)
    }
}

/// Transport path a request is admitted on.
///
/// Modern activation is scoped per path, so a path whose conformance matrix
/// passes can accept modern requests while an unproven path stays legacy-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpPathKind {
    DirectAccessPoint,
    OwnedProxy,
    TransitPoint,
    FabricReceive,
    FabricSend,
}

impl McpPathKind {
    #[cfg(test)]
    pub const ALL: [Self; 5] =
        [Self::DirectAccessPoint, Self::OwnedProxy, Self::TransitPoint, Self::FabricReceive, Self::FabricSend];
}

const LEGACY_SUPPORTED_VERSIONS: &[&str] = &[MCP_LEGACY_VERSION];
pub const LEGACY_ONLY_POLICY: McpVersionPolicy<'static> = McpVersionPolicy::new(&[], LEGACY_SUPPORTED_VERSIONS);

/// Admits `2026-07-28` alongside `2024-11-05`. A path uses it only for endpoints
/// set to `dual`; `legacy` endpoints use [`LEGACY_ONLY_POLICY`].
const MODERN_CAPABLE_POLICY: McpVersionPolicy<'static> =
    McpVersionPolicy::new(&[super::MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, super::MCP_MODERN_VERSION]);

// One policy per path, so a path can be returned to legacy-only without
// affecting the others. The Fabric legs carry modern MCP only as framed streams.
const DIRECT_ACCESS_POINT_POLICY: McpVersionPolicy<'static> = MODERN_CAPABLE_POLICY;
const OWNED_PROXY_POLICY: McpVersionPolicy<'static> = MODERN_CAPABLE_POLICY;
const TRANSIT_POINT_POLICY: McpVersionPolicy<'static> = MODERN_CAPABLE_POLICY;
const FABRIC_RECEIVE_POLICY: McpVersionPolicy<'static> = MODERN_CAPABLE_POLICY;
const FABRIC_SEND_POLICY: McpVersionPolicy<'static> = MODERN_CAPABLE_POLICY;

pub const fn runtime_policy_for(path: McpPathKind) -> McpVersionPolicy<'static> {
    match path {
        McpPathKind::DirectAccessPoint => DIRECT_ACCESS_POINT_POLICY,
        McpPathKind::OwnedProxy => OWNED_PROXY_POLICY,
        McpPathKind::TransitPoint => TRANSIT_POINT_POLICY,
        McpPathKind::FabricReceive => FABRIC_RECEIVE_POLICY,
        McpPathKind::FabricSend => FABRIC_SEND_POLICY,
    }
}

pub fn endpoint_version_policy(
    mode: Option<crate::config::McpProtocolMode>,
    path: McpPathKind,
) -> McpVersionPolicy<'static> {
    match mode.unwrap_or_default() {
        crate::config::McpProtocolMode::Legacy => LEGACY_ONLY_POLICY,
        crate::config::McpProtocolMode::Dual => runtime_policy_for(path),
    }
}

/// Narrows an entry point's policy to the Fabric send policy when its Target
/// is `fabric://`, so the request is rejected at admission rather than after
/// payment, policy and consent work for a leg that cannot carry it.
pub fn admission_policy_for_target<'a>(
    policy: McpVersionPolicy<'a>,
    mode: Option<crate::config::McpProtocolMode>,
    target_endpoint: &str,
) -> McpVersionPolicy<'a> {
    if target_endpoint.starts_with("fabric://") {
        policy.within(endpoint_version_policy(mode, McpPathKind::FabricSend))
    } else {
        policy
    }
}

/// A legacy `initialize` rewritten to request a revision the endpoint serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CappedInitialize {
    pub body: bytes::Bytes,
    pub requested: String,
    pub offered: String,
}

impl CappedInitialize {
    /// The requested revision as it is safe to log: a well-formed date
    /// revision as is, anything else (caller-controlled, up to the body size)
    /// only by its length.
    pub fn requested_for_log(&self) -> String {
        let is_revision = self.requested.len() == 10
            && self
                .requested
                .bytes()
                .enumerate()
                .all(|(index, byte)| {
                    if matches!(index, 4 | 7) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit()
                    }
                });
        if is_revision {
            self.requested.clone()
        } else {
            format!("<{} bytes, not a date revision>", self.requested.len())
        }
    }
}

/// Rewrites a legacy `initialize` whose requested revision the endpoint does
/// not serve to request the newest legacy revision it does, or returns `None`
/// to forward the request unchanged.
///
/// A server answers `initialize` with a revision it supports and the client
/// decides whether to continue. The upstream cannot see which revisions this
/// endpoint serves, so forwarding a request for `2025-11-25` lets it settle a
/// session whose every later request is rejected with `-32022`. Modern
/// revisions are never offered: they have no `initialize` handshake.
/// Supported versions are listed oldest first, so no date strings are compared.
pub fn cap_legacy_initialize(
    body: &[u8],
    classification: &McpRequestClassification,
    policy: McpVersionPolicy<'_>,
) -> Option<CappedInitialize> {
    if !matches!(classification, McpRequestClassification::Legacy(LegacyRequestKind::Opening)) {
        return None;
    }
    let serves = |version: &str| {
        policy
            .supported_versions
            .contains(&version)
            && !policy.supports_modern(version)
    };
    let offered = policy
        .supported_versions
        .iter()
        .rev()
        .copied()
        .find(|version| serves(version))?;
    let mut request: JsonValue = serde_json::from_slice(body).ok()?;
    let version = request
        .get_mut("params")?
        .get_mut("protocolVersion")?;
    let requested = version.as_str()?.to_string();
    if serves(&requested) {
        return None;
    }
    *version = JsonValue::String(offered.to_string());
    Some(CappedInitialize {
        body: serde_json::to_vec(&request)
            .ok()?
            .into(),
        requested,
        offered: offered.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyRequestKind {
    Opening,
    Session,
    Compatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpMessageKind {
    Request,
    Notification,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedModernMessage {
    pub protocol_version: String,
    pub client_capabilities: Option<JsonValue>,
    pub client_info: Option<JsonValue>,
    pub method: String,
    pub params: Option<JsonValue>,
    pub id: Option<JsonValue>,
    pub kind: McpMessageKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpRequestClassification {
    Legacy(LegacyRequestKind),
    UnversionedNotification,
    Modern(Box<ValidatedModernMessage>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpRequestValidationError {
    pub status: StatusCode,
    pub id: Option<JsonValue>,
    pub code: i32,
    pub message: String,
    pub data: Option<JsonValue>,
}

impl McpRequestValidationError {
    fn new(
        id: Option<JsonValue>,
        code: i32,
        message: impl Into<String>,
    ) -> Box<Self> {
        Box::new(Self {
            status: StatusCode::BAD_REQUEST,
            id,
            code,
            message: message.into(),
            data: None,
        })
    }

    pub(super) fn unsupported(
        id: Option<JsonValue>,
        requested: &str,
        policy: McpVersionPolicy<'_>,
    ) -> Box<Self> {
        let supported = policy
            .supported_versions
            .iter()
            .map(|version| JsonValue::String((*version).to_string()))
            .collect();
        Box::new(Self {
            status: StatusCode::BAD_REQUEST,
            id,
            code: error_codes::UNSUPPORTED_PROTOCOL_VERSION,
            message: "Unsupported protocol version".to_string(),
            data: Some(json!({
                "requested": requested,
                "supported": JsonValue::Array(supported),
            })),
        })
    }

    /// The answer to a modern request whose endpoint serves legacy MCP only,
    /// as a `legacy` endpoint gives it: `400` / `-32022` listing `2024-11-05`.
    /// A Fabric peer whose surface is not `dual` is answered the same way.
    pub fn legacy_only(id: Option<JsonValue>) -> Box<Self> {
        Self::unsupported(id, super::MCP_MODERN_VERSION, LEGACY_ONLY_POLICY)
    }

    pub fn into_response(self) -> axum::response::Response {
        super::errors::create_mcp_error_response_with_status(self.status, self.id, self.code, &self.message, self.data)
    }
}

pub fn malformed_transport_header(
    body_bytes: &[u8],
    message: impl Into<String>,
) -> Box<McpRequestValidationError> {
    let id = serde_json::from_slice::<JsonValue>(body_bytes)
        .ok()
        .and_then(|body| {
            body.as_object()
                .and_then(recover_request_id)
        });
    header_mismatch(id, message)
}

pub fn validate_mcp_post(
    headers: &HeaderMap,
    body_bytes: &[u8],
    session_evidence: LegacySessionEvidence,
    policy: McpVersionPolicy<'_>,
) -> Result<McpRequestClassification, Box<McpRequestValidationError>> {
    let header_intent = has_modern_header(headers);
    let body: JsonValue = match serde_json::from_slice(body_bytes) {
        Ok(body) => body,
        Err(error) if header_intent => {
            return Err(McpRequestValidationError::new(
                None,
                error_codes::PARSE_ERROR,
                format!("Invalid JSON: {error}"),
            ));
        }
        Err(_) => return Ok(McpRequestClassification::Legacy(LegacyRequestKind::Compatibility)),
    };

    let body_intent = value_has_modern_meta(&body);
    let Some(object) = body.as_object() else {
        if header_intent || body_intent {
            return Err(McpRequestValidationError::new(
                None,
                error_codes::INVALID_REQUEST,
                "Modern MCP POST body must be one JSON-RPC object",
            ));
        }
        return Ok(McpRequestClassification::Legacy(LegacyRequestKind::Compatibility));
    };

    let id = recover_request_id(object);
    if !header_intent && !body_intent {
        let method = object
            .get("method")
            .and_then(JsonValue::as_str);
        if method == Some("initialize") {
            return Ok(McpRequestClassification::Legacy(LegacyRequestKind::Opening));
        }
        if method.is_some() && !object.contains_key("id") {
            return Ok(McpRequestClassification::UnversionedNotification);
        }
        return Ok(McpRequestClassification::Legacy(match session_evidence {
            LegacySessionEvidence::Known => LegacyRequestKind::Session,
            LegacySessionEvidence::Absent | LegacySessionEvidence::Unknown => LegacyRequestKind::Compatibility,
        }));
    }

    validate_modern_message(headers, object, id, policy)
}

fn validate_modern_message(
    headers: &HeaderMap,
    object: &Map<String, JsonValue>,
    id: Option<JsonValue>,
    policy: McpVersionPolicy<'_>,
) -> Result<McpRequestClassification, Box<McpRequestValidationError>> {
    if object
        .get("jsonrpc")
        .and_then(JsonValue::as_str)
        != Some("2.0")
    {
        return Err(McpRequestValidationError::new(
            id,
            error_codes::INVALID_REQUEST,
            "Invalid or missing JSON-RPC version",
        ));
    }

    let method = object
        .get("method")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            McpRequestValidationError::new(id.clone(), error_codes::INVALID_REQUEST, "Missing or invalid method")
        })?;

    let kind = match object.get("id") {
        Some(value) if is_valid_request_id(value) => McpMessageKind::Request,
        Some(_) => {
            return Err(McpRequestValidationError::new(
                None,
                error_codes::INVALID_REQUEST,
                "MCP request id must be a string or integer",
            ));
        }
        None => McpMessageKind::Notification,
    };

    let header_version = single_header(headers, PROTOCOL_VERSION_HEADER, id.clone())?;
    let header_name = single_header(headers, NAME_HEADER, id.clone())?
        .map(decode_mirrored_value)
        .transpose()
        .map_err(|message| header_mismatch(id.clone(), message))?;
    if let Some(requested) =
        header_version.filter(|version| *version != super::MCP_MODERN_VERSION && *version != MCP_LEGACY_VERSION)
        && kind == McpMessageKind::Request
    {
        if let Some(body_version) = canonical_body_version(object)
            && body_version != requested
        {
            return Err(header_mismatch(id, "MCP-Protocol-Version header does not match params._meta"));
        }
        return Err(McpRequestValidationError::unsupported(id, requested, policy));
    }

    if top_level_has_modern_meta(object) {
        return Err(McpRequestValidationError::new(
            id,
            error_codes::INVALID_PARAMS,
            "Modern MCP metadata must be in params._meta",
        ));
    }

    let params = match object.get("params") {
        Some(JsonValue::Object(params)) => Some(params),
        Some(_) => {
            return Err(McpRequestValidationError::new(
                id,
                error_codes::INVALID_PARAMS,
                "MCP params must be an object",
            ));
        }
        None if kind == McpMessageKind::Request => {
            return Err(McpRequestValidationError::new(
                id,
                error_codes::INVALID_PARAMS,
                "Modern MCP requests require params._meta",
            ));
        }
        None => None,
    };

    let meta = match params.and_then(|params| params.get("_meta")) {
        Some(JsonValue::Object(meta)) => Some(meta),
        Some(_) => {
            return Err(McpRequestValidationError::new(
                id,
                error_codes::INVALID_PARAMS,
                "MCP params._meta must be an object",
            ));
        }
        None if kind == McpMessageKind::Request => {
            return Err(McpRequestValidationError::new(
                id,
                error_codes::INVALID_PARAMS,
                "Modern MCP requests require params._meta",
            ));
        }
        None => None,
    };

    let body_version = meta
        .and_then(|meta| meta.get(PROTOCOL_VERSION_META))
        .map(|value| {
            value
                .as_str()
                .filter(|version| !version.is_empty())
                .ok_or_else(|| {
                    McpRequestValidationError::new(
                        id.clone(),
                        error_codes::INVALID_PARAMS,
                        format!("{PROTOCOL_VERSION_META} must be a non-empty string"),
                    )
                })
        })
        .transpose()?;

    let client_capabilities = meta
        .and_then(|meta| meta.get(CLIENT_CAPABILITIES_META))
        .map(|value| {
            if value.is_object() {
                Ok(value.clone())
            } else {
                Err(McpRequestValidationError::new(
                    id.clone(),
                    error_codes::INVALID_PARAMS,
                    format!("{CLIENT_CAPABILITIES_META} must be an object"),
                ))
            }
        })
        .transpose()?;

    if kind == McpMessageKind::Request && body_version.is_none() {
        return Err(McpRequestValidationError::new(
            id,
            error_codes::INVALID_PARAMS,
            format!("Missing {PROTOCOL_VERSION_META}"),
        ));
    }
    if kind == McpMessageKind::Request && client_capabilities.is_none() {
        return Err(McpRequestValidationError::new(
            id,
            error_codes::INVALID_PARAMS,
            format!("Missing {CLIENT_CAPABILITIES_META}"),
        ));
    }

    let client_info = meta
        .and_then(|meta| meta.get(CLIENT_INFO_META))
        .map(|value| validate_client_info(value, id.clone()))
        .transpose()?;

    if kind == McpMessageKind::Request {
        if meta
            .and_then(|meta| meta.get(LOG_LEVEL_META))
            .is_some_and(|value| !is_logging_level(value))
        {
            return Err(McpRequestValidationError::new(
                id,
                error_codes::INVALID_PARAMS,
                format!("{LOG_LEVEL_META} must be a defined logging level"),
            ));
        }
        if meta
            .and_then(|meta| meta.get("progressToken"))
            .is_some_and(|value| !value.is_string() && !value.is_number())
        {
            return Err(McpRequestValidationError::new(
                id,
                error_codes::INVALID_PARAMS,
                "progressToken must be a string or number",
            ));
        }
    }

    let header_method = single_header(headers, METHOD_HEADER, id.clone())?;

    if kind == McpMessageKind::Request {
        let header_version = header_version
            .ok_or_else(|| header_mismatch(id.clone(), "Missing required MCP-Protocol-Version header"))?;
        let header_method =
            header_method.ok_or_else(|| header_mismatch(id.clone(), "Missing required Mcp-Method header"))?;
        if Some(header_version) != body_version {
            return Err(header_mismatch(id, "MCP-Protocol-Version header does not match params._meta"));
        }
        if header_method != method {
            return Err(header_mismatch(id, "Mcp-Method header does not match method"));
        }
    } else {
        if let (Some(header_version), Some(body_version)) = (header_version, body_version)
            && header_version != body_version
        {
            return Err(header_mismatch(id, "MCP-Protocol-Version header does not match params._meta"));
        }
        if let Some(header_method) = header_method
            && header_method != method
        {
            return Err(header_mismatch(id, "Mcp-Method header does not match method"));
        }
    }

    let expected_name = mirrored_name_source(method, params, id.clone())?;
    match (expected_name, header_name.as_deref()) {
        (Some(expected), Some(decoded)) => {
            if decoded != expected {
                return Err(header_mismatch(id, "Mcp-Name header does not match request params"));
            }
        }
        (Some(_), None) if kind == McpMessageKind::Request => {
            return Err(header_mismatch(id, "Missing required Mcp-Name header"));
        }
        (None, Some(_)) => {}
        (Some(_), None) | (None, None) => {}
    }

    let protocol_version = match kind {
        McpMessageKind::Request => body_version.expect("request version checked above"),
        McpMessageKind::Notification => match (body_version, header_version) {
            (Some(version), _) => version,
            (None, Some(version)) => version,
            (None, None) => return Ok(McpRequestClassification::UnversionedNotification),
        },
    };

    if protocol_version == MCP_LEGACY_VERSION {
        return Err(McpRequestValidationError::new(
            id,
            error_codes::INVALID_PARAMS,
            format!("MCP {MCP_LEGACY_VERSION} cannot use modern per-request metadata or mirrored headers"),
        ));
    }

    if !policy.supports_modern(protocol_version) {
        return Err(McpRequestValidationError::unsupported(id, protocol_version, policy));
    }

    Ok(McpRequestClassification::Modern(Box::new(ValidatedModernMessage {
        protocol_version: protocol_version.to_string(),
        client_capabilities,
        client_info,
        method: method.to_string(),
        params: params
            .cloned()
            .map(JsonValue::Object),
        id,
        kind,
    })))
}

pub(super) fn recover_request_id(object: &Map<String, JsonValue>) -> Option<JsonValue> {
    object
        .get("id")
        .filter(|value| is_valid_request_id(value))
        .cloned()
}

fn is_valid_request_id(value: &JsonValue) -> bool {
    value.is_string() || value.as_i64().is_some() || value.as_u64().is_some()
}

fn has_modern_header(headers: &HeaderMap) -> bool {
    let mut versions = headers
        .get_all(PROTOCOL_VERSION_HEADER)
        .iter();
    let legacy_version = versions
        .next()
        .and_then(|value| value.to_str().ok())
        == Some(MCP_LEGACY_VERSION)
        && versions.next().is_none();
    (headers.contains_key(PROTOCOL_VERSION_HEADER) && !legacy_version)
        || headers.contains_key(METHOD_HEADER)
        || headers.contains_key(NAME_HEADER)
}

fn has_modern_meta(object: &Map<String, JsonValue>) -> bool {
    top_level_has_modern_meta(object)
        || object
            .get("params")
            .and_then(JsonValue::as_object)
            .and_then(|params| params.get("_meta"))
            .is_some_and(meta_has_modern_key)
}

fn value_has_modern_meta(value: &JsonValue) -> bool {
    match value {
        JsonValue::Object(object) => has_modern_meta(object),
        JsonValue::Array(messages) => messages
            .iter()
            .any(value_has_modern_meta),
        _ => false,
    }
}

fn top_level_has_modern_meta(object: &Map<String, JsonValue>) -> bool {
    object
        .get("_meta")
        .is_some_and(meta_has_modern_key)
}

fn canonical_body_version(object: &Map<String, JsonValue>) -> Option<&str> {
    object
        .get("params")
        .and_then(JsonValue::as_object)
        .and_then(|params| params.get("_meta"))
        .and_then(JsonValue::as_object)
        .and_then(|meta| meta.get(PROTOCOL_VERSION_META))
        .and_then(JsonValue::as_str)
}

fn meta_has_modern_key(meta: &JsonValue) -> bool {
    meta.as_object()
        .is_some_and(|meta| {
            [PROTOCOL_VERSION_META, CLIENT_CAPABILITIES_META, CLIENT_INFO_META, LOG_LEVEL_META]
                .iter()
                .any(|key| meta.contains_key(*key))
        })
}

pub(super) fn is_logging_level(value: &JsonValue) -> bool {
    matches!(
        value.as_str(),
        Some("debug" | "info" | "notice" | "warning" | "error" | "critical" | "alert" | "emergency")
    )
}

fn validate_client_info(
    value: &JsonValue,
    id: Option<JsonValue>,
) -> Result<JsonValue, Box<McpRequestValidationError>> {
    let valid = value
        .as_object()
        .is_some_and(|info| {
            info.get("name")
                .and_then(JsonValue::as_str)
                .is_some()
                && info
                    .get("version")
                    .and_then(JsonValue::as_str)
                    .is_some()
        });
    if valid {
        Ok(value.clone())
    } else {
        Err(McpRequestValidationError::new(
            id,
            error_codes::INVALID_PARAMS,
            format!("{CLIENT_INFO_META} must contain string name and version fields"),
        ))
    }
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
    id: Option<JsonValue>,
) -> Result<Option<&'a str>, Box<McpRequestValidationError>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(header_mismatch(id, format!("Header {name} must appear exactly once")));
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| header_mismatch(id, format!("Header {name} contains invalid characters")))
}

fn mirrored_name_source<'a>(
    method: &str,
    params: Option<&'a Map<String, JsonValue>>,
    id: Option<JsonValue>,
) -> Result<Option<&'a str>, Box<McpRequestValidationError>> {
    let field = match method {
        "tools/call" | "prompts/get" => "name",
        "resources/read" => "uri",
        _ => return Ok(None),
    };
    let value = params
        .and_then(|params| params.get(field))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            McpRequestValidationError::new(
                id,
                error_codes::INVALID_PARAMS,
                format!("{method} requires string params.{field}"),
            )
        })?;
    Ok(Some(value))
}

pub(super) fn decode_mirrored_value(value: &str) -> Result<String, String> {
    let starts_with_sentinel = value.starts_with(BASE64_PREFIX);
    let ends_with_sentinel = value.ends_with(BASE64_SUFFIX);
    if starts_with_sentinel && ends_with_sentinel {
        let encoded = value
            .strip_prefix(BASE64_PREFIX)
            .and_then(|value| value.strip_suffix(BASE64_SUFFIX))
            .ok_or_else(|| "Mcp-Name header uses a malformed Base64 sentinel".to_string())?;
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| "Mcp-Name header contains invalid Base64".to_string())?;
        return String::from_utf8(decoded).map_err(|_| "Mcp-Name header Base64 payload is not UTF-8".to_string());
    }
    if value
        .as_bytes()
        .iter()
        .any(|byte| !matches!(*byte, 0x20..=0x7e | b'\t'))
        || value.trim() != value
    {
        return Err("Mcp-Name header contains invalid characters".to_string());
    }
    Ok(value.to_string())
}

pub(super) fn header_mismatch(
    id: Option<JsonValue>,
    message: impl Into<String>,
) -> Box<McpRequestValidationError> {
    McpRequestValidationError::new(id, error_codes::HEADER_MISMATCH, message)
}

#[cfg(test)]
pub fn encode_mirrored_value(value: &str) -> String {
    if value.trim() != value
        || value
            .bytes()
            .any(|byte| !matches!(byte, 0x20..=0x7e | b'\t'))
        || (value.starts_with(BASE64_PREFIX) && value.ends_with(BASE64_SUFFIX))
    {
        format!("{BASE64_PREFIX}{}{BASE64_SUFFIX}", STANDARD.encode(value.as_bytes()))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_capped_initialize_logs_only_a_well_formed_requested_revision() {
        let capped = |requested: &str| super::CappedInitialize {
            body: bytes::Bytes::new(),
            requested: requested.into(),
            offered: "2025-06-18".into(),
        };
        assert_eq!(capped("2025-11-25").requested_for_log(), "2025-11-25");
        assert_eq!(capped("2025-11-25\nforged").requested_for_log(), "<17 bytes, not a date revision>");
        assert_eq!(capped(&"9".repeat(4096)).requested_for_log(), "<4096 bytes, not a date revision>");
        assert_eq!(capped("2025/11/25").requested_for_log(), "<10 bytes, not a date revision>");
    }

    use axum::http::{HeaderMap, HeaderValue};
    use serde_json::json;

    use super::*;
    use crate::mcp::MCP_MODERN_VERSION;

    const TEST_POLICY: McpVersionPolicy<'static> =
        McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]);

    #[test]
    fn every_transport_path_admits_modern_only_on_dual_endpoints() {
        use crate::config::McpProtocolMode;

        for path in McpPathKind::ALL {
            for (endpoint, policy, admits) in [
                ("runtime", runtime_policy_for(path), true),
                ("dual", endpoint_version_policy(Some(McpProtocolMode::Dual), path), true),
                ("legacy", endpoint_version_policy(Some(McpProtocolMode::Legacy), path), false),
                ("unset", endpoint_version_policy(None, path), false),
            ] {
                let supported: &[&str] = if admits {
                    &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]
                } else {
                    &[MCP_LEGACY_VERSION]
                };
                assert_eq!(policy.supports_modern(MCP_MODERN_VERSION), admits, "{path:?} {endpoint} admission");
                assert_eq!(policy.supported_versions(), supported, "{path:?} {endpoint} advertisement");
            }
        }
    }

    #[test]
    fn a_path_never_advertises_a_version_it_does_not_admit() {
        for path in McpPathKind::ALL {
            let policy = runtime_policy_for(path);
            for active in policy.active_modern_versions {
                assert!(
                    policy
                        .supported_versions()
                        .contains(active),
                    "{path:?} admits {active} without advertising it"
                );
            }
        }
    }

    #[test]
    fn no_mcp_surface_scenario_is_a_draft_while_modern_mcp_is_admitted() {
        let mut inspected = 0usize;
        let mut drafts = Vec::new();
        for entry in std::fs::read_dir("tests/features/surface").expect("surface feature directory") {
            let path = entry
                .expect("feature directory entry")
                .path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string();
            if !name.starts_with("mcp_") || !name.ends_with(".feature") {
                continue;
            }
            inspected += 1;
            if std::fs::read_to_string(&path)
                .expect("feature file")
                .contains("@wip")
            {
                drafts.push(name);
            }
        }
        assert!(inspected > 0, "no MCP feature files were inspected; the guard would pass vacuously");
        let activated: Vec<_> = McpPathKind::ALL
            .into_iter()
            .filter(|path| {
                !runtime_policy_for(*path)
                    .active_modern_versions
                    .is_empty()
            })
            .collect();
        assert!(
            activated.is_empty() || drafts.is_empty(),
            "{activated:?} admit modern requests while {drafts:?} still contain draft scenarios"
        );
    }

    #[test]
    fn returning_one_path_to_legacy_leaves_the_others_admitting_modern() {
        let rolled_back = |path| {
            if path == McpPathKind::FabricSend {
                LEGACY_ONLY_POLICY
            } else {
                runtime_policy_for(path)
            }
        };
        assert!(!rolled_back(McpPathKind::FabricSend).supports_modern(MCP_MODERN_VERSION));
        for path in McpPathKind::ALL
            .into_iter()
            .filter(|path| *path != McpPathKind::FabricSend)
        {
            assert!(rolled_back(path).supports_modern(MCP_MODERN_VERSION), "{path:?} lost modern admission");
        }
    }

    fn version_sets(policy: McpVersionPolicy<'_>) -> (&[&str], &[&str]) {
        (policy.active_modern_versions, policy.supported_versions)
    }

    #[test]
    fn within_keeps_the_narrower_of_two_nested_policies() {
        const ADVERTISED_ONLY: McpVersionPolicy<'static> =
            McpVersionPolicy::new(&[], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]);
        for (policy, limit, expected) in [
            (TEST_POLICY, LEGACY_ONLY_POLICY, LEGACY_ONLY_POLICY),
            (LEGACY_ONLY_POLICY, TEST_POLICY, LEGACY_ONLY_POLICY),
            (LEGACY_ONLY_POLICY, LEGACY_ONLY_POLICY, LEGACY_ONLY_POLICY),
            (TEST_POLICY, TEST_POLICY, TEST_POLICY),
            (TEST_POLICY, ADVERTISED_ONLY, ADVERTISED_ONLY),
            (ADVERTISED_ONLY, TEST_POLICY, ADVERTISED_ONLY),
            (ADVERTISED_ONLY, LEGACY_ONLY_POLICY, LEGACY_ONLY_POLICY),
        ] {
            assert_eq!(version_sets(policy.within(limit)), version_sets(expected), "{policy:?} within {limit:?}");
        }
    }

    #[test]
    fn admission_narrows_only_fabric_targets_to_the_fabric_send_policy() {
        use crate::config::McpProtocolMode;

        for mode in [None, Some(McpProtocolMode::Legacy), Some(McpProtocolMode::Dual)] {
            let fabric_send = endpoint_version_policy(mode, McpPathKind::FabricSend);
            for target in ["fabric://gateway/channel", "fabric://gateway/channel$variant"] {
                assert_eq!(
                    version_sets(admission_policy_for_target(TEST_POLICY, mode, target)),
                    version_sets(fabric_send),
                    "{mode:?} {target}"
                );
                assert_eq!(
                    version_sets(admission_policy_for_target(LEGACY_ONLY_POLICY, mode, target)),
                    version_sets(LEGACY_ONLY_POLICY),
                    "{mode:?} {target} widened a legacy-only entry point"
                );
            }
            for target in ["https://agent.example/mcp", "http://127.0.0.1:9/mcp", "proxy://owned-tools"] {
                for policy in [TEST_POLICY, LEGACY_ONLY_POLICY] {
                    assert_eq!(
                        version_sets(admission_policy_for_target(policy, mode, target)),
                        version_sets(policy),
                        "{mode:?} {target}"
                    );
                }
            }
        }
    }

    fn modern_body() -> JsonValue {
        json!({
            "jsonrpc": "2.0",
            "id": "request-1",
            "method": "tools/list",
            "params": {
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {},
                    CLIENT_INFO_META: { "name": "test-client", "version": "1.0.0" }
                }
            }
        })
    }

    fn modern_headers(method: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(MCP_MODERN_VERSION));
        headers.insert(METHOD_HEADER, HeaderValue::from_str(method).unwrap());
        headers
    }

    fn validate(
        body: &JsonValue,
        headers: &HeaderMap,
        policy: McpVersionPolicy<'_>,
    ) -> Result<McpRequestClassification, Box<McpRequestValidationError>> {
        validate_mcp_post(headers, &serde_json::to_vec(body).unwrap(), LegacySessionEvidence::Absent, policy)
    }

    #[test]
    fn initialize_without_modern_signal_is_legacy_opening() {
        let result = validate(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            &HeaderMap::new(),
            LEGACY_ONLY_POLICY,
        );
        assert_eq!(result, Ok(McpRequestClassification::Legacy(LegacyRequestKind::Opening)));
    }

    fn initialize_body(protocol_version: JsonValue) -> JsonValue {
        json!({"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {
            "protocolVersion": protocol_version,
            "capabilities": {"roots": {"listChanged": true}},
            "clientInfo": {"name": "client", "version": "1.0"}
        }})
    }

    fn cap(
        body: &JsonValue,
        policy: McpVersionPolicy<'_>,
    ) -> Option<CappedInitialize> {
        let classification = validate(body, &HeaderMap::new(), policy).expect("legacy initialize is admitted");
        cap_legacy_initialize(&serde_json::to_vec(body).unwrap(), &classification, policy)
    }

    #[test]
    fn initialize_for_an_unserved_revision_requests_the_newest_served_legacy_revision() {
        for requested in ["2025-03-26", "2025-06-18", "2025-11-25", "1999-01-01"] {
            let body = initialize_body(json!(requested));
            let capped = cap(&body, LEGACY_ONLY_POLICY).expect("an unserved revision is capped");
            assert_eq!(capped.requested, requested);
            assert_eq!(capped.offered, MCP_LEGACY_VERSION);
            let mut expected = body.clone();
            expected["params"]["protocolVersion"] = json!(MCP_LEGACY_VERSION);
            assert_eq!(serde_json::from_slice::<JsonValue>(&capped.body).unwrap(), expected, "{requested}");
        }
    }

    #[test]
    fn initialize_for_a_served_revision_is_forwarded_unchanged() {
        assert_eq!(cap(&initialize_body(json!(MCP_LEGACY_VERSION)), LEGACY_ONLY_POLICY), None);
    }

    #[test]
    fn initialize_never_settles_on_a_modern_revision() {
        let dual = McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]);
        for requested in [MCP_MODERN_VERSION, "2025-11-25"] {
            let capped = cap(&initialize_body(json!(requested)), dual).expect("capped");
            assert_eq!(capped.offered, MCP_LEGACY_VERSION, "{requested}");
        }
        assert_eq!(cap(&initialize_body(json!(MCP_LEGACY_VERSION)), dual), None);
    }

    #[test]
    fn only_a_legacy_opening_with_a_string_revision_is_capped() {
        let body = serde_json::to_vec(&initialize_body(json!("2025-11-25"))).unwrap();
        for classification in [
            McpRequestClassification::Legacy(LegacyRequestKind::Session),
            McpRequestClassification::Legacy(LegacyRequestKind::Compatibility),
            McpRequestClassification::UnversionedNotification,
        ] {
            assert_eq!(cap_legacy_initialize(&body, &classification, LEGACY_ONLY_POLICY), None);
        }
        for version in [json!(null), json!(20251125)] {
            assert_eq!(cap(&initialize_body(version), LEGACY_ONLY_POLICY), None);
        }
        let without_version = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        assert_eq!(cap(&without_version, LEGACY_ONLY_POLICY), None);
    }

    #[test]
    fn no_signal_request_preserves_legacy_compatibility() {
        let result = validate(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
            &HeaderMap::new(),
            LEGACY_ONLY_POLICY,
        );
        assert_eq!(result, Ok(McpRequestClassification::Legacy(LegacyRequestKind::Compatibility)));
    }

    #[test]
    fn known_session_is_legacy_session() {
        let body = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).unwrap();
        let result = validate_mcp_post(&HeaderMap::new(), &body, LegacySessionEvidence::Known, LEGACY_ONLY_POLICY);
        assert_eq!(result, Ok(McpRequestClassification::Legacy(LegacyRequestKind::Session)));
    }

    #[test]
    fn notification_without_modern_version_is_unversioned() {
        let result = validate(
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            &HeaderMap::new(),
            LEGACY_ONLY_POLICY,
        );
        assert_eq!(result, Ok(McpRequestClassification::UnversionedNotification));
    }

    #[test]
    fn complete_modern_request_is_accepted_by_test_policy() {
        let mut body = modern_body();
        body["params"]["extensionField"] = json!({"nested": [1, true, null]});
        body["params"]["_meta"]["com.example/opaque"] = json!({"preserve": true});
        let expected_params = body["params"].clone();

        let result = validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap();
        let McpRequestClassification::Modern(message) = result else {
            panic!("expected modern request");
        };
        assert_eq!(message.protocol_version, MCP_MODERN_VERSION);
        assert_eq!(message.method, "tools/list");
        assert_eq!(message.kind, McpMessageKind::Request);
        assert_eq!(message.client_capabilities, Some(json!({})));
        assert_eq!(message.client_info, Some(json!({"name": "test-client", "version": "1.0.0"})));
        assert_eq!(message.params, Some(expected_params));
    }

    #[test]
    fn a_legacy_only_refusal_answers_as_a_legacy_endpoint_does() {
        let error = McpRequestValidationError::legacy_only(Some(json!(7)));
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.id, Some(json!(7)));
        assert_eq!(error.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(
            error.data,
            Some(json!({"requested": crate::mcp::MCP_MODERN_VERSION, "supported": [MCP_LEGACY_VERSION]}))
        );
    }

    #[test]
    fn complete_modern_request_is_rejected_by_legacy_only_policy() {
        let error = validate(&modern_body(), &modern_headers("tools/list"), LEGACY_ONLY_POLICY).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(error.id, Some(json!("request-1")));
        assert_eq!(
            error.data,
            Some(json!({
                "requested": MCP_MODERN_VERSION,
                "supported": [MCP_LEGACY_VERSION]
            }))
        );
    }

    #[test]
    fn intermediate_header_only_version_is_unsupported_without_modern_metadata() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "intermediate-request",
            "method": "tools/list",
            "params": {}
        });
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static("2025-11-25"));

        let error = validate(&body, &headers, LEGACY_ONLY_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(error.id, Some(json!("intermediate-request")));
        assert_eq!(error.data, Some(json!({"requested": "2025-11-25", "supported": [MCP_LEGACY_VERSION]})));
    }

    #[test]
    fn intermediate_header_and_modern_body_version_mismatch_is_header_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static("2025-11-25"));
        let error = validate(&modern_body(), &headers, LEGACY_ONLY_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn missing_client_capabilities_is_invalid_params() {
        let mut body = modern_body();
        body["params"]["_meta"]
            .as_object_mut()
            .unwrap()
            .remove(CLIENT_CAPABILITIES_META);
        let error = validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::INVALID_PARAMS);
        assert_eq!(error.id, Some(json!("request-1")));
    }

    #[test]
    fn missing_params_or_meta_is_invalid_params() {
        for body in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        ] {
            let error = validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap_err();
            assert_eq!(error.code, error_codes::INVALID_PARAMS);
            assert_eq!(error.id, Some(json!(1)));
        }
    }

    #[test]
    fn required_modern_metadata_must_have_the_declared_types() {
        let mut invalid_version = modern_body();
        invalid_version["params"]["_meta"][PROTOCOL_VERSION_META] = json!(20260728);
        let mut invalid_capabilities = modern_body();
        invalid_capabilities["params"]["_meta"][CLIENT_CAPABILITIES_META] = json!([]);

        for body in [invalid_version, invalid_capabilities] {
            let error = validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap_err();
            assert_eq!(error.code, error_codes::INVALID_PARAMS);
        }
    }

    #[test]
    fn optional_request_notification_controls_have_declared_types() {
        for (field, values) in [
            (LOG_LEVEL_META, vec![json!(null), json!(false), json!("verbose"), json!("INFO")]),
            ("progressToken", vec![json!(null), json!(false), json!([]), json!({"token": "work"})]),
        ] {
            for value in values {
                let mut body = modern_body();
                body["params"]["_meta"][field] = value;
                for policy in [TEST_POLICY, LEGACY_ONLY_POLICY] {
                    let error = validate(&body, &modern_headers("tools/list"), policy).unwrap_err();
                    assert_eq!(error.code, error_codes::INVALID_PARAMS, "{body}");
                    assert_eq!(error.status, StatusCode::BAD_REQUEST);
                    assert_eq!(error.id, Some(json!("request-1")));
                }
            }
        }
        for level in ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"] {
            for token in [json!(""), json!("work"), json!(1), json!(1.5)] {
                let mut body = modern_body();
                body["params"]["_meta"][LOG_LEVEL_META] = json!(level);
                body["params"]["_meta"]["progressToken"] = token;
                let McpRequestClassification::Modern(message) =
                    validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap()
                else {
                    panic!("expected modern classification");
                };
                assert_eq!(message.params, Some(body["params"].clone()));
            }
        }
        let legacy =
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {"progressToken": false}}});
        assert_eq!(
            validate(&legacy, &HeaderMap::new(), LEGACY_ONLY_POLICY).unwrap(),
            McpRequestClassification::Legacy(LegacyRequestKind::Compatibility)
        );
    }

    #[test]
    fn mismatched_method_header_is_header_mismatch() {
        let error = validate(&modern_body(), &modern_headers("tools/call"), TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
        assert_eq!(error.id, Some(json!("request-1")));
    }

    #[test]
    fn modern_metadata_takes_precedence_over_known_session() {
        let body = serde_json::to_vec(&modern_body()).unwrap();
        let error =
            validate_mcp_post(&modern_headers("tools/list"), &body, LegacySessionEvidence::Known, LEGACY_ONLY_POLICY)
                .unwrap_err();
        assert_eq!(error.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
    }

    #[test]
    fn unknown_session_is_not_exposed_as_known_legacy_state() {
        let body = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).unwrap();
        let result = validate_mcp_post(&HeaderMap::new(), &body, LegacySessionEvidence::Unknown, LEGACY_ONLY_POLICY);
        assert_eq!(result, Ok(McpRequestClassification::Legacy(LegacyRequestKind::Compatibility)));
    }

    #[test]
    fn mcp_param_header_alone_does_not_select_modern_validation() {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-param-region", HeaderValue::from_static("eu-west-1"));
        let result = validate(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "search"}}),
            &headers,
            LEGACY_ONLY_POLICY,
        );
        assert_eq!(result, Ok(McpRequestClassification::Legacy(LegacyRequestKind::Compatibility)));
    }

    #[test]
    fn top_level_modern_metadata_is_invalid_params() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
            "_meta": {
                PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                CLIENT_CAPABILITIES_META: {}
            }
        });
        let error = validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::INVALID_PARAMS);
    }

    #[test]
    fn missing_protocol_version_is_invalid_params_before_header_checks() {
        let mut body = modern_body();
        body["params"]["_meta"]
            .as_object_mut()
            .unwrap()
            .remove(PROTOCOL_VERSION_META);
        let error = validate(&body, &HeaderMap::new(), TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::INVALID_PARAMS);
    }

    #[test]
    fn invalid_client_info_is_invalid_params() {
        let mut body = modern_body();
        body["params"]["_meta"][CLIENT_INFO_META] = json!({"name": "client"});
        let error = validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::INVALID_PARAMS);
    }

    #[test]
    fn missing_method_header_is_header_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(MCP_MODERN_VERSION));
        let error = validate(&modern_body(), &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn missing_protocol_version_header_is_header_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, HeaderValue::from_static("tools/list"));
        let error = validate(&modern_body(), &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn duplicate_method_header_is_header_mismatch() {
        let mut headers = modern_headers("tools/list");
        headers.append(METHOD_HEADER, HeaderValue::from_static("tools/list"));
        let error = validate(&modern_body(), &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn duplicate_protocol_version_header_is_header_mismatch() {
        let mut headers = modern_headers("tools/list");
        headers.append(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(MCP_MODERN_VERSION));
        let error = validate(&modern_body(), &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn malformed_standard_header_is_header_mismatch() {
        let mut headers = modern_headers("tools/list");
        headers.insert(METHOD_HEADER, HeaderValue::from_bytes(&[0xff]).unwrap());
        let error = validate(&modern_body(), &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn header_names_are_case_insensitive_and_values_are_case_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(b"MCP-PROTOCOL-VERSION").unwrap(),
            HeaderValue::from_static(MCP_MODERN_VERSION),
        );
        headers
            .insert(axum::http::HeaderName::from_bytes(b"MCP-METHOD").unwrap(), HeaderValue::from_static("tools/list"));
        assert!(matches!(validate(&modern_body(), &headers, TEST_POLICY), Ok(McpRequestClassification::Modern(_))));

        headers.insert(METHOD_HEADER, HeaderValue::from_static("TOOLS/LIST"));
        let error = validate(&modern_body(), &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn mismatch_precedes_unsupported_version() {
        let mut headers = modern_headers("tools/call");
        headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static("2025-11-25"));
        let error = validate(&modern_body(), &headers, LEGACY_ONLY_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn intermediate_and_unknown_per_request_versions_are_unsupported() {
        for version in ["2025-11-25", "2099-01-01"] {
            let mut body = modern_body();
            body["params"]["_meta"][PROTOCOL_VERSION_META] = json!(version);
            let mut headers = modern_headers("tools/list");
            headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(version));
            let error = validate(&body, &headers, LEGACY_ONLY_POLICY).unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
            assert_eq!(error.data, Some(json!({"requested": version, "supported": [MCP_LEGACY_VERSION]})));
        }
    }

    #[test]
    fn legacy_version_in_modern_metadata_is_invalid_params() {
        for (method, notification) in [("tools/list", false), ("notifications/example", true)] {
            let mut body = modern_body();
            body["method"] = json!(method);
            body["params"]["_meta"][PROTOCOL_VERSION_META] = json!(MCP_LEGACY_VERSION);
            if notification {
                body.as_object_mut()
                    .unwrap()
                    .remove("id");
            }
            let mut headers = modern_headers(method);
            headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(MCP_LEGACY_VERSION));
            for policy in [LEGACY_ONLY_POLICY, TEST_POLICY] {
                let error = validate(&body, &headers, policy).unwrap_err();
                assert_eq!(error.status, StatusCode::BAD_REQUEST);
                assert_eq!(error.code, error_codes::INVALID_PARAMS);
                assert_eq!(error.id, body.get("id").cloned());
                assert_eq!(error.data, None);
                assert_eq!(error.message, "MCP 2024-11-05 cannot use modern per-request metadata or mirrored headers");
            }
            headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(MCP_MODERN_VERSION));
            let error = validate(&body, &headers, LEGACY_ONLY_POLICY).unwrap_err();
            assert_eq!(error.code, error_codes::HEADER_MISMATCH);
        }
    }

    #[test]
    fn unknown_extension_method_is_preserved_without_name_header() {
        let mut body = modern_body();
        body["method"] = json!("example.vendor/do-work");
        let result = validate(&body, &modern_headers("example.vendor/do-work"), TEST_POLICY).unwrap();
        let McpRequestClassification::Modern(message) = result else {
            panic!("expected modern request");
        };
        assert_eq!(message.method, "example.vendor/do-work");
    }

    #[test]
    fn unknown_extension_method_preserves_optional_name_header() {
        let mut body = modern_body();
        body["method"] = json!("example.vendor/do-work");
        body["params"]["name"] = json!("extension-operation");
        let mut headers = modern_headers("example.vendor/do-work");
        headers.insert(NAME_HEADER, HeaderValue::from_static("extension-operation"));

        let result = validate(&body, &headers, TEST_POLICY).unwrap();
        let McpRequestClassification::Modern(message) = result else {
            panic!("expected modern request");
        };
        assert_eq!(message.method, "example.vendor/do-work");
    }

    #[test]
    fn malformed_optional_name_header_is_header_mismatch() {
        for (method, notification) in
            [("tools/list", false), ("example.vendor/do-work", false), ("notifications/example", true)]
        {
            let mut body = modern_body();
            body["method"] = json!(method);
            if notification {
                body.as_object_mut()
                    .unwrap()
                    .remove("id");
            }
            for name in ["=?base64?=", "=?base64?%%%?=", "=?base64?/w==?=", " padded "] {
                let mut headers = modern_headers(method);
                headers.insert(NAME_HEADER, HeaderValue::from_static(name));
                for policy in [LEGACY_ONLY_POLICY, TEST_POLICY] {
                    let error = validate(&body, &headers, policy).unwrap_err();
                    assert_eq!(error.status, StatusCode::BAD_REQUEST, "{method}: {name}");
                    assert_eq!(error.code, error_codes::HEADER_MISMATCH, "{method}: {name}");
                    assert_eq!(error.id, body.get("id").cloned());
                }
            }
        }
    }

    #[test]
    fn valid_optional_name_header_does_not_require_a_body_source() {
        let body = modern_body();
        for name in ["extra-name", "=?base64?prefix-only", "suffix?=", "=?base64?c2VhcmNo?="] {
            let mut headers = modern_headers("tools/list");
            headers.insert(NAME_HEADER, HeaderValue::from_static(name));
            let result = validate(&body, &headers, TEST_POLICY).unwrap();
            let McpRequestClassification::Modern(message) = result else {
                panic!("expected modern request");
            };
            assert_eq!(message.method, "tools/list");
            assert_eq!(message.params, Some(body["params"].clone()));
            let error = validate(&body, &headers, LEGACY_ONLY_POLICY).unwrap_err();
            assert_eq!(error.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        }
    }

    #[test]
    fn optional_name_is_validated_before_unsupported_header_only_version() {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        for version in ["2025-11-25", "2099-01-01"] {
            let mut headers = HeaderMap::new();
            headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(version));
            headers.insert(NAME_HEADER, HeaderValue::from_static("=?base64?="));
            let error = validate(&body, &headers, LEGACY_ONLY_POLICY).unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.code, error_codes::HEADER_MISMATCH);
            assert_eq!(error.id, Some(json!(1)));

            headers.insert(NAME_HEADER, HeaderValue::from_static("extra-name"));
            let error = validate(&body, &headers, LEGACY_ONLY_POLICY).unwrap_err();
            assert_eq!(error.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
            assert_eq!(error.data, Some(json!({"requested": version, "supported": [MCP_LEGACY_VERSION]})));
        }
    }

    #[test]
    fn notification_headers_are_optional_but_present_values_must_match() {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "notifications/example",
            "params": {"_meta": {PROTOCOL_VERSION_META: MCP_MODERN_VERSION}}
        });
        let result = validate(&body, &HeaderMap::new(), TEST_POLICY);
        assert!(matches!(result, Ok(McpRequestClassification::Modern(_))));

        let mut headers = HeaderMap::new();
        headers.insert(METHOD_HEADER, HeaderValue::from_static("notifications/other"));
        let error = validate(&body, &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn base64_encoded_name_is_decoded_before_comparison() {
        let name = "søk";
        let body = json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": {},
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {}
                }
            }
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());
        let mut headers = modern_headers("tools/call");
        headers
            .insert(NAME_HEADER, HeaderValue::from_str(&format!("{BASE64_PREFIX}{encoded}{BASE64_SUFFIX}")).unwrap());
        let result = validate(&body, &headers, TEST_POLICY);
        assert!(matches!(result, Ok(McpRequestClassification::Modern(_))));
    }

    #[test]
    fn all_conditional_name_sources_are_validated() {
        for (method, field, value) in [
            ("tools/call", "name", "search"),
            ("prompts/get", "name", "review"),
            ("resources/read", "uri", "file:///tmp/example"),
        ] {
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": {
                    field: value,
                    "_meta": {
                        PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                        CLIENT_CAPABILITIES_META: {}
                    }
                }
            });
            let mut headers = modern_headers(method);
            headers.insert(NAME_HEADER, HeaderValue::from_str(value).unwrap());
            assert!(matches!(validate(&body, &headers, TEST_POLICY), Ok(McpRequestClassification::Modern(_))));
        }
    }

    #[test]
    fn missing_conditional_name_header_is_header_mismatch() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search",
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {}
                }
            }
        });
        let error = validate(&body, &modern_headers("tools/call"), TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn mismatched_conditional_name_header_is_header_mismatch() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {
                "uri": "file:///expected",
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {}
                }
            }
        });
        let mut headers = modern_headers("resources/read");
        headers.insert(NAME_HEADER, HeaderValue::from_static("file:///other"));
        let error = validate(&body, &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn malformed_base64_name_is_header_mismatch() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search",
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {}
                }
            }
        });
        let mut headers = modern_headers("tools/call");
        headers.insert(NAME_HEADER, HeaderValue::from_static("=?base64?%%%?="));
        let error = validate(&body, &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn non_utf8_base64_name_is_header_mismatch() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search",
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {}
                }
            }
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode([0xff]);
        let mut headers = modern_headers("tools/call");
        headers
            .insert(NAME_HEADER, HeaderValue::from_str(&format!("{BASE64_PREFIX}{encoded}{BASE64_SUFFIX}")).unwrap());
        let error = validate(&body, &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn partial_base64_markers_are_plain_ascii_names() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search",
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {}
                }
            }
        });
        let mut headers = modern_headers("tools/call");
        for name in ["=?base64?c2VhcmNo", "lookup?="] {
            let mut body = body.clone();
            body["params"]["name"] = json!(name);
            headers.insert(NAME_HEADER, HeaderValue::from_str(name).unwrap());
            assert!(matches!(validate(&body, &headers, TEST_POLICY), Ok(McpRequestClassification::Modern(_))));
        }
    }

    #[test]
    fn duplicate_conditional_name_header_is_header_mismatch() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search",
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {}
                }
            }
        });
        let mut headers = modern_headers("tools/call");
        headers.append(NAME_HEADER, HeaderValue::from_static("search"));
        headers.append(NAME_HEADER, HeaderValue::from_static("search"));
        let error = validate(&body, &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn overlapping_base64_markers_are_rejected_without_panicking() {
        let mut body = modern_body();
        body["method"] = json!("tools/call");
        body["params"]["name"] = json!("search");
        let mut headers = modern_headers("tools/call");
        headers.insert(NAME_HEADER, HeaderValue::from_static("=?base64?="));
        let error = validate(&body, &headers, LEGACY_ONLY_POLICY).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
        assert_eq!(error.id, Some(json!("request-1")));
    }

    #[test]
    fn advertised_legacy_header_preserves_legacy_messages() {
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(MCP_LEGACY_VERSION));
        for (body, expected) in [
            (
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
                McpRequestClassification::Legacy(LegacyRequestKind::Opening),
            ),
            (
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                McpRequestClassification::Legacy(LegacyRequestKind::Session),
            ),
            (
                json!({"jsonrpc": "2.0", "id": "consent", "result": {"action": "accept"}}),
                McpRequestClassification::Legacy(LegacyRequestKind::Session),
            ),
            (
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                McpRequestClassification::UnversionedNotification,
            ),
        ] {
            let result = validate_mcp_post(
                &headers,
                &serde_json::to_vec(&body).unwrap(),
                LegacySessionEvidence::Known,
                LEGACY_ONLY_POLICY,
            );
            assert_eq!(result, Ok(expected));
        }
        let error = validate(&modern_body(), &headers, LEGACY_ONLY_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
        headers.append(PROTOCOL_VERSION_HEADER, HeaderValue::from_static(MCP_LEGACY_VERSION));
        let error = validate(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), &headers, LEGACY_ONLY_POLICY)
            .unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn empty_post_with_modern_headers_is_parse_error() {
        let error =
            validate_mcp_post(&modern_headers("tools/list"), b"", LegacySessionEvidence::Absent, LEGACY_ONLY_POLICY)
                .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, error_codes::PARSE_ERROR);
        assert_eq!(error.id, None);
        assert_eq!(
            validate_mcp_post(&HeaderMap::new(), b"", LegacySessionEvidence::Absent, LEGACY_ONLY_POLICY),
            Ok(McpRequestClassification::Legacy(LegacyRequestKind::Compatibility))
        );
    }

    #[test]
    fn unencoded_padded_name_is_header_mismatch() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": " padded ",
                "_meta": {
                    PROTOCOL_VERSION_META: MCP_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META: {}
                }
            }
        });
        let mut headers = modern_headers("tools/call");
        headers.insert(NAME_HEADER, HeaderValue::from_static(" padded "));
        let error = validate(&body, &headers, TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::HEADER_MISMATCH);
    }

    #[test]
    fn modern_client_response_post_is_invalid_request() {
        let body = json!({"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete"}});
        let error = validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap_err();
        assert_eq!(error.code, error_codes::INVALID_REQUEST);
        assert_eq!(error.id, Some(json!(1)));
    }

    #[test]
    fn modern_request_id_must_be_a_string_or_integer() {
        for invalid_id in [JsonValue::Null, json!(true), json!({"nested": "id"})] {
            let mut body = modern_body();
            body["id"] = invalid_id;
            let error = validate(&body, &modern_headers("tools/list"), TEST_POLICY).unwrap_err();
            assert_eq!(error.code, error_codes::INVALID_REQUEST);
            assert_eq!(error.id, None);
        }
    }

    #[test]
    fn malformed_modern_json_is_parse_error_without_id() {
        let error = validate_mcp_post(
            &modern_headers("tools/list"),
            br#"{"jsonrpc":"#,
            LegacySessionEvidence::Absent,
            TEST_POLICY,
        )
        .unwrap_err();
        assert_eq!(error.code, error_codes::PARSE_ERROR);
        assert_eq!(error.id, None);
    }

    #[test]
    fn malformed_legacy_json_stays_on_the_legacy_path() {
        let result =
            validate_mcp_post(&HeaderMap::new(), br#"{"jsonrpc":"#, LegacySessionEvidence::Absent, LEGACY_ONLY_POLICY);
        assert_eq!(result, Ok(McpRequestClassification::Legacy(LegacyRequestKind::Compatibility)));
    }

    #[test]
    fn modern_batch_is_invalid_request() {
        let body = serde_json::to_vec(&json!([modern_body()])).unwrap();
        let error = validate_mcp_post(&modern_headers("tools/list"), &body, LegacySessionEvidence::Absent, TEST_POLICY)
            .unwrap_err();
        assert_eq!(error.code, error_codes::INVALID_REQUEST);
    }

    #[test]
    fn body_signaled_modern_batch_is_invalid_without_headers() {
        let body = serde_json::to_vec(&json!([modern_body()])).unwrap();
        let error =
            validate_mcp_post(&HeaderMap::new(), &body, LegacySessionEvidence::Absent, TEST_POLICY).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, error_codes::INVALID_REQUEST);
    }

    #[test]
    fn legacy_batch_stays_on_the_legacy_compatibility_path() {
        let body = serde_json::to_vec(&json!([{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }]))
        .unwrap();
        let result = validate_mcp_post(&HeaderMap::new(), &body, LegacySessionEvidence::Absent, LEGACY_ONLY_POLICY);
        assert_eq!(result, Ok(McpRequestClassification::Legacy(LegacyRequestKind::Compatibility)));
    }
}
