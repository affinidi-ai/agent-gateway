use axum::http::StatusCode;
use serde_json::{Map, Value, json};

use super::errors::error_codes;
use super::request_validation::{McpMessageKind, McpRequestValidationError, ValidatedModernMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Outside tests only `ElicitationUrl` is required; the other variants are
// constructed by the capability declaration tests.
#[cfg_attr(not(test), allow(dead_code))]
pub enum RequiredClientCapability {
    ElicitationForm,
    ElicitationUrl,
    Roots,
    Sampling,
    SamplingContext,
    SamplingTools,
}

impl RequiredClientCapability {
    pub fn declaration(self) -> Value {
        match self {
            Self::ElicitationForm => json!({"elicitation": {"form": {}}}),
            Self::ElicitationUrl => json!({"elicitation": {"url": {}}}),
            Self::Roots => json!({"roots": {}}),
            Self::Sampling => json!({"sampling": {}}),
            Self::SamplingContext => json!({"sampling": {"context": {}}}),
            Self::SamplingTools => json!({"sampling": {"tools": {}}}),
        }
    }

    fn is_declared(
        self,
        capabilities: Option<&Value>,
    ) -> bool {
        let Some(capabilities) = capabilities.and_then(Value::as_object) else {
            return false;
        };
        let capability_object = |name: &str| {
            capabilities
                .get(name)
                .and_then(Value::as_object)
        };
        match self {
            Self::ElicitationForm => capability_object("elicitation").is_some_and(|elicitation| {
                elicitation.is_empty()
                    || elicitation
                        .get("form")
                        .is_some_and(Value::is_object)
            }),
            Self::ElicitationUrl => capability_object("elicitation")
                .and_then(|elicitation| elicitation.get("url"))
                .is_some_and(Value::is_object),
            Self::Roots => capability_object("roots").is_some(),
            Self::Sampling => capability_object("sampling").is_some(),
            Self::SamplingContext => capability_object("sampling")
                .and_then(|sampling| sampling.get("context"))
                .is_some_and(Value::is_object),
            Self::SamplingTools => capability_object("sampling")
                .and_then(|sampling| sampling.get("tools"))
                .is_some_and(Value::is_object),
        }
    }
}

pub fn require_client_capability(
    request: &ValidatedModernMessage,
    required: RequiredClientCapability,
) -> Result<(), Box<McpRequestValidationError>> {
    if required.is_declared(
        request
            .client_capabilities
            .as_ref(),
    ) {
        return Ok(());
    }
    Err(Box::new(McpRequestValidationError {
        status: StatusCode::BAD_REQUEST,
        id: request.id.clone(),
        code: error_codes::MISSING_REQUIRED_CLIENT_CAPABILITY,
        message: "Missing required client capability".to_string(),
        data: Some(json!({"requiredCapabilities": required.declaration()})),
    }))
}

#[cfg(test)]
pub fn supports_extension(
    client: Option<&Value>,
    server: &Value,
    identifier: &str,
) -> bool {
    if !identifier.contains('/') || !super::meta::is_valid_key(identifier) {
        return false;
    }
    let declared = |capabilities: &Value| {
        capabilities
            .get("extensions")
            .and_then(|extensions| extensions.get(identifier))
            .is_some_and(Value::is_object)
    };
    client.is_some_and(declared) && declared(server)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultSource {
    ModernServer,
    CompatiblePeer,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModernResponseError {
    #[error("A response requires a request with a string or integer id")]
    InvalidRequest,
    #[error("Expected one JSON-RPC response with either result or error")]
    InvalidEnvelope,
    #[error("Response id does not match the request")]
    IdMismatch,
    #[error("Result must be an object")]
    InvalidResult,
    #[error("A modern server result requires resultType")]
    MissingResultType,
    #[error("resultType must be a string")]
    InvalidResultType,
    #[error("A complete response cannot replace another result type")]
    NotComplete,
    #[error("Cache hints require a nonnegative finite ttlMs and public or private cacheScope")]
    InvalidCacheHints,
    #[error("Input-required results need an eligible method and inputRequests or requestState")]
    InvalidContinuation,
    #[error("An error requires an integer code and string message")]
    InvalidError,
    #[error("Discovery requires supported versions and well-formed server capabilities")]
    InvalidDiscovery,
    #[error("Discovery does not establish support for the requested version on this path")]
    DiscoveryUnavailable,
}

fn request_id(request: &ValidatedModernMessage) -> Result<&Value, ModernResponseError> {
    request
        .id
        .as_ref()
        .filter(|id| {
            request.kind == McpMessageKind::Request
                && (id.is_string() || id.as_i64().is_some() || id.as_u64().is_some())
        })
        .ok_or(ModernResponseError::InvalidRequest)
}

pub fn is_cacheable_method(method: &str) -> bool {
    matches!(
        method,
        "server/discover"
            | "tools/list"
            | "prompts/list"
            | "resources/list"
            | "resources/templates/list"
            | "resources/read"
    )
}

pub fn validate_result<'result>(
    method: &str,
    result: &'result Value,
    source: ResultSource,
) -> Result<&'result str, ModernResponseError> {
    let object = result
        .as_object()
        .ok_or(ModernResponseError::InvalidResult)?;
    let result_type = match object.get("resultType") {
        Some(Value::String(result_type)) => result_type.as_str(),
        Some(_) => return Err(ModernResponseError::InvalidResultType),
        None if source == ResultSource::CompatiblePeer => "complete",
        None => return Err(ModernResponseError::MissingResultType),
    };
    if result_type == "input_required" {
        if !matches!(method, "tools/call" | "prompts/get" | "resources/read")
            || (!object.contains_key("inputRequests") && !object.contains_key("requestState"))
            || object
                .get("inputRequests")
                .is_some_and(|requests| !requests.is_object())
            || object
                .get("requestState")
                .is_some_and(|state| !state.is_string())
        {
            return Err(ModernResponseError::InvalidContinuation);
        }
    } else if result_type == "complete" && is_cacheable_method(method) {
        let required = source == ResultSource::ModernServer;
        let ttl = object.get("ttlMs");
        let scope = object.get("cacheScope");
        if (required || ttl.is_some())
            && !ttl
                .and_then(Value::as_f64)
                .is_some_and(|ttl| ttl.is_finite() && ttl >= 0.0)
            || (required || scope.is_some()) && !matches!(scope.and_then(Value::as_str), Some("public" | "private"))
        {
            return Err(ModernResponseError::InvalidCacheHints);
        }
    }
    Ok(result_type)
}

pub fn validate_response<'response>(
    request: &ValidatedModernMessage,
    response: &'response Value,
    source: ResultSource,
) -> Result<Option<&'response str>, ModernResponseError> {
    let expected_id = request_id(request)?;
    let envelope = response
        .as_object()
        .ok_or(ModernResponseError::InvalidEnvelope)?;
    if envelope
        .get("jsonrpc")
        .and_then(Value::as_str)
        != Some("2.0")
        || envelope.contains_key("method")
        || envelope.contains_key("result") == envelope.contains_key("error")
    {
        return Err(ModernResponseError::InvalidEnvelope);
    }
    if let Some(result) = envelope.get("result") {
        if envelope.get("id") != Some(expected_id) {
            return Err(ModernResponseError::IdMismatch);
        }
        return validate_result(&request.method, result, source).map(Some);
    }
    if envelope
        .get("id")
        .is_some_and(|id| id != expected_id)
    {
        return Err(ModernResponseError::IdMismatch);
    }
    let error = envelope
        .get("error")
        .and_then(Value::as_object)
        .ok_or(ModernResponseError::InvalidError)?;
    if !error
        .get("code")
        .is_some_and(|code| code.as_i64().is_some() || code.as_u64().is_some())
        || !error
            .get("message")
            .is_some_and(Value::is_string)
    {
        return Err(ModernResponseError::InvalidError);
    }
    Ok(None)
}

pub fn complete_response(
    request: &ValidatedModernMessage,
    mut fields: Map<String, Value>,
) -> Result<Value, ModernResponseError> {
    let id = request_id(request)?;
    if fields
        .get("resultType")
        .is_some_and(|kind| kind.as_str() != Some("complete"))
    {
        return Err(ModernResponseError::NotComplete);
    }
    fields.insert("resultType".to_string(), json!("complete"));
    if is_cacheable_method(&request.method) {
        fields
            .entry("ttlMs")
            .or_insert(json!(0));
        fields
            .entry("cacheScope")
            .or_insert(json!("private"));
    }
    let result = Value::Object(fields);
    validate_result(&request.method, &result, ResultSource::ModernServer)?;
    Ok(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

pub fn require_active_version(
    request: &ValidatedModernMessage,
    versions: super::request_validation::McpVersionPolicy<'_>,
) -> Result<(), Box<McpRequestValidationError>> {
    if versions.supports_modern(&request.protocol_version) {
        Ok(())
    } else {
        Err(McpRequestValidationError::unsupported(request.id.clone(), &request.protocol_version, versions))
    }
}

pub fn owned_discovery_response(
    request: &ValidatedModernMessage,
    versions: super::request_validation::McpVersionPolicy<'_>,
    name: &str,
    version: &str,
) -> Result<Value, Box<McpRequestValidationError>> {
    require_active_version(request, versions)?;
    if request.method != "server/discover" || request.kind != McpMessageKind::Request {
        return Err(Box::new(McpRequestValidationError {
            status: StatusCode::BAD_REQUEST,
            id: request.id.clone(),
            code: error_codes::INVALID_REQUEST,
            message: "Discovery requires a server/discover request".to_string(),
            data: None,
        }));
    }
    let fields = json!({
        "supportedVersions": versions.supported_versions(),
        "capabilities": {"tools": {"listChanged": true}},
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": {"io.modelcontextprotocol/serverInfo": {"name": name, "version": version}}
    });
    complete_response(
        request,
        fields
            .as_object()
            .unwrap()
            .clone(),
    )
    .map_err(|error| {
        Box::new(McpRequestValidationError {
            status: StatusCode::BAD_REQUEST,
            id: request.id.clone(),
            code: error_codes::INVALID_REQUEST,
            message: error.to_string(),
            data: None,
        })
    })
}

pub struct ForwardingSupport<'support> {
    pub versions: super::request_validation::McpVersionPolicy<'support>,
    pub request_streams: bool,
    pub subscriptions: bool,
    pub capabilities: &'support [&'support str],
    pub extensions: &'support [&'support str],
    /// Endpoint whose forwarded discovery result updates the learned upstream versions.
    pub learned_versions: Option<super::upstream_versions::UpstreamKey>,
}

impl ForwardingSupport<'static> {
    pub fn for_endpoint(
        fabric: bool,
        path: super::request_validation::McpPathKind,
    ) -> Self {
        let transport = !fabric
            || crate::proxy::fabric_stream::global()
                .ok()
                .is_some_and(|runtime| runtime.supports_request_streams());
        let subscriptions = !fabric
            || crate::proxy::fabric_stream::global()
                .ok()
                .is_some_and(|runtime| runtime.supports_subscriptions());
        Self {
            versions: super::request_validation::runtime_policy_for(path),
            request_streams: transport,
            subscriptions: transport && subscriptions,
            capabilities: &["tools", "prompts", "resources", "completions", "logging"],
            extensions: &[],
            learned_versions: None,
        }
    }

    pub fn recording_versions(
        mut self,
        key: super::upstream_versions::UpstreamKey,
    ) -> Self {
        self.learned_versions = Some(key);
        self
    }

    pub fn restrict_to_fabric_peer(
        mut self,
        peer: Option<&crate::proxy::fabric_stream::peer::StreamCapabilities>,
    ) -> Self {
        self.request_streams &= peer.is_some_and(|peer| peer.request_streams);
        self.subscriptions &= peer.is_some_and(|peer| peer.request_streams && peer.subscriptions);
        self
    }
}

pub fn constrain_forwarded_discovery(
    request: &ValidatedModernMessage,
    response: &mut Value,
    support: &ForwardingSupport<'_>,
) -> Result<bool, ModernResponseError> {
    if request.method != "server/discover"
        || validate_response(request, response, ResultSource::ModernServer)? != Some("complete")
    {
        return Ok(false);
    }
    if !support.request_streams
        || !support
            .versions
            .supports_modern(&request.protocol_version)
    {
        return Err(ModernResponseError::DiscoveryUnavailable);
    }
    let result = response
        .get_mut("result")
        .and_then(Value::as_object_mut)
        .ok_or(ModernResponseError::InvalidDiscovery)?;
    let versions = result
        .get("supportedVersions")
        .and_then(Value::as_array)
        .ok_or(ModernResponseError::InvalidDiscovery)?;
    if versions.is_empty()
        || versions.len() > 32
        || versions
            .iter()
            .any(|version| !version.is_string())
    {
        return Err(ModernResponseError::InvalidDiscovery);
    }
    if !versions
        .iter()
        .any(|version| version.as_str() == Some(&request.protocol_version))
    {
        return Err(ModernResponseError::DiscoveryUnavailable);
    }
    let effective_versions: Vec<Value> = versions
        .iter()
        .filter(|version| {
            version
                .as_str()
                .is_some_and(|version| {
                    support
                        .versions
                        .supported_versions()
                        .contains(&version)
                })
        })
        .cloned()
        .collect();
    let upstream = result
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or(ModernResponseError::InvalidDiscovery)?;
    if upstream.len() > 128
        || upstream
            .values()
            .any(|capability| !capability.is_object())
    {
        return Err(ModernResponseError::InvalidDiscovery);
    }
    let mut capabilities = Map::new();
    for (name, settings) in upstream {
        if name == "extensions" {
            let settings = settings
                .as_object()
                .ok_or(ModernResponseError::InvalidDiscovery)?;
            if settings.len() > 128
                || settings
                    .iter()
                    .any(|(identifier, settings)| {
                        !identifier.contains('/') || !super::meta::is_valid_key(identifier) || !settings.is_object()
                    })
            {
                return Err(ModernResponseError::InvalidDiscovery);
            }
            let extensions: Map<String, Value> = settings
                .iter()
                .filter(|(identifier, _)| {
                    support
                        .extensions
                        .contains(&identifier.as_str())
                })
                .map(|(identifier, settings)| (identifier.clone(), settings.clone()))
                .collect();
            if !extensions.is_empty() || settings.is_empty() {
                capabilities.insert(name.clone(), Value::Object(extensions));
            }
            continue;
        }
        if matches!(name.as_str(), "tools" | "prompts" | "resources") {
            for flag in ["listChanged", "subscribe"] {
                if settings
                    .get(flag)
                    .is_some_and(|value| !value.is_boolean())
                {
                    return Err(ModernResponseError::InvalidDiscovery);
                }
            }
        }
        if !support
            .capabilities
            .contains(&name.as_str())
        {
            continue;
        }
        let mut settings = settings.clone();
        if !support.subscriptions && matches!(name.as_str(), "tools" | "prompts" | "resources") {
            let settings = settings
                .as_object_mut()
                .ok_or(ModernResponseError::InvalidDiscovery)?;
            settings.remove("listChanged");
            if name == "resources" {
                settings.remove("subscribe");
            }
        }
        capabilities.insert(name.clone(), settings);
    }
    let changed = effective_versions != *versions || capabilities != *upstream;
    if changed {
        result.insert("supportedVersions".to_string(), Value::Array(effective_versions));
        result.insert("capabilities".to_string(), Value::Object(capabilities));
        result.insert("ttlMs".to_string(), json!(0));
        result.insert("cacheScope".to_string(), json!("private"));
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::request_validation::{
        LegacySessionEvidence, McpRequestClassification, McpVersionPolicy, validate_mcp_post,
    };

    #[test]
    fn forwarded_discovery_intersects_path_support_without_replacing_server_metadata() {
        let request = request("server/discover", json!({}));
        let support = ForwardingSupport {
            versions: McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
            ),
            request_streams: true,
            subscriptions: false,
            capabilities: &["tools", "resources", "prompts", "completions"],
            extensions: &["com.example/reviewed"],
            learned_versions: None,
        };
        let mut response = json!({"jsonrpc": "2.0", "id": "request", "result": {
            "resultType": "complete", "supportedVersions": [crate::mcp::MCP_MODERN_VERSION, "2025-11-25", crate::mcp::MCP_LEGACY_VERSION],
            "capabilities": {"tools": {"listChanged": true, "vendorField": [1, null]}, "resources": {"subscribe": true, "listChanged": true},
                "prompts": {}, "logging": {}, "experimental": {"feature": {}},
                "extensions": {"com.example/reviewed": {"opaque": [false, 5]}, "com.example/unavailable": {}}},
            "ttlMs": 60000, "cacheScope": "public", "instructions": "Upstream instructions",
            "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "Upstream", "version": "2", "icons": [{"src": "https://upstream.example/icon.png"}]}},
            "vendorField": {"kept": true}
        }});
        let metadata = response["result"]["_meta"].clone();
        assert_eq!(constrain_forwarded_discovery(&request, &mut response, &support), Ok(true));
        assert_eq!(
            response["result"]["supportedVersions"],
            json!([crate::mcp::MCP_MODERN_VERSION, crate::mcp::MCP_LEGACY_VERSION])
        );
        assert_eq!(
            response["result"]["capabilities"],
            json!({"tools": {"vendorField": [1, null]}, "resources": {}, "prompts": {},
            "extensions": {"com.example/reviewed": {"opaque": [false, 5]}}})
        );
        assert_eq!(response["result"]["_meta"], metadata);
        assert_eq!(response["result"]["instructions"], "Upstream instructions");
        assert_eq!(response["result"]["vendorField"], json!({"kept": true}));
        assert_eq!(response["result"]["ttlMs"], 0);
        assert_eq!(response["result"]["cacheScope"], "private");
        assert_eq!(constrain_forwarded_discovery(&request, &mut response, &support), Ok(false));
    }

    #[test]
    fn forwarded_discovery_never_infers_modern_support_from_a_legacy_result() {
        let request = request("server/discover", json!({}));
        let support = ForwardingSupport {
            versions: McpVersionPolicy::new(&[crate::mcp::MCP_MODERN_VERSION], &[crate::mcp::MCP_MODERN_VERSION]),
            request_streams: true,
            subscriptions: true,
            capabilities: &["tools"],
            extensions: &[],
            learned_versions: None,
        };
        let response = json!({"jsonrpc": "2.0", "id": "request", "result": {
            "resultType": "complete", "supportedVersions": [crate::mcp::MCP_MODERN_VERSION],
            "capabilities": {"tools": {"listChanged": true}}, "ttlMs": 1000, "cacheScope": "public"
        }});
        let mut unchanged = response.clone();
        assert_eq!(constrain_forwarded_discovery(&request, &mut unchanged, &support), Ok(false));
        assert_eq!(unchanged, response);
        for (field, value) in [
            ("supportedVersions", json!([crate::mcp::MCP_LEGACY_VERSION])),
            ("capabilities", json!({"tools": null})),
            ("capabilities", json!({"tools": {"listChanged": 1}})),
            ("supportedVersions", json!([null])),
        ] {
            let mut invalid = response.clone();
            invalid["result"][field] = value;
            assert!(constrain_forwarded_discovery(&request, &mut invalid, &support).is_err(), "{field}");
        }
        let mut legacy = response.clone();
        legacy["result"]
            .as_object_mut()
            .unwrap()
            .remove("resultType");
        assert_eq!(
            constrain_forwarded_discovery(&request, &mut legacy, &support),
            Err(ModernResponseError::MissingResultType)
        );
        assert!(
            legacy["result"]
                .get("resultType")
                .is_none()
        );
        let unavailable = ForwardingSupport {
            request_streams: false,
            ..support
        };
        assert_eq!(
            constrain_forwarded_discovery(&request, &mut response.clone(), &unavailable),
            Err(ModernResponseError::DiscoveryUnavailable)
        );
        let disabled = ForwardingSupport {
            versions: crate::mcp::request_validation::LEGACY_ONLY_POLICY,
            request_streams: true,
            ..unavailable
        };
        assert_eq!(
            constrain_forwarded_discovery(&request, &mut response.clone(), &disabled),
            Err(ModernResponseError::DiscoveryUnavailable)
        );
    }

    #[test]
    fn owned_discovery_is_truthful_and_does_not_activate_modern_runtime() {
        let wrong_method = request("tools/list", json!({}));
        let request = request("server/discover", json!({}));
        let versions = McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let response = owned_discovery_response(&request, versions, "Owned tools", "1.0").unwrap();
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(
            response["result"]["supportedVersions"],
            json!([crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION])
        );
        assert_eq!(response["result"]["capabilities"], json!({"tools": {"listChanged": true}}));
        assert_eq!(response["result"]["ttlMs"], 0);
        assert_eq!(response["result"]["cacheScope"], "private");
        assert_eq!(
            response["result"]["_meta"]["io.modelcontextprotocol/serverInfo"],
            json!({"name": "Owned tools", "version": "1.0"})
        );
        assert_eq!(validate_response(&request, &response, ResultSource::ModernServer), Ok(Some("complete")));
        let error = owned_discovery_response(
            &request,
            crate::mcp::request_validation::LEGACY_ONLY_POLICY,
            "Owned tools",
            "1.0",
        )
        .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(
            error.data,
            Some(json!({"requested": crate::mcp::MCP_MODERN_VERSION, "supported": [crate::mcp::MCP_LEGACY_VERSION]}))
        );
        assert_eq!(
            owned_discovery_response(&wrong_method, versions, "Owned tools", "1.0")
                .unwrap_err()
                .code,
            error_codes::INVALID_REQUEST
        );
    }

    #[test]
    fn forwarded_discovery_never_exceeds_the_selected_peer_subscription_support() {
        let support =
            || ForwardingSupport::for_endpoint(false, crate::mcp::request_validation::McpPathKind::DirectAccessPoint);
        assert!(support().subscriptions);
        assert!(
            !support()
                .restrict_to_fabric_peer(None)
                .request_streams
        );
        let requests_only = crate::proxy::fabric_stream::peer::StreamCapabilities::local(true, false);
        let constrained = support().restrict_to_fabric_peer(Some(&requests_only));
        assert!(constrained.request_streams);
        assert!(!constrained.subscriptions);
        let subscriptions = crate::proxy::fabric_stream::peer::StreamCapabilities::local(true, true);
        assert!(
            support()
                .restrict_to_fabric_peer(Some(&subscriptions))
                .subscriptions
        );
        // The installed Fabric stream runtime advertises subscriptions.
        assert!(
            ForwardingSupport::for_endpoint(true, crate::mcp::request_validation::McpPathKind::FabricSend,)
                .subscriptions
        );
    }

    fn request(
        method: &str,
        capabilities: Value,
    ) -> ValidatedModernMessage {
        let body = json!({"jsonrpc": "2.0", "id": "request", "method": method, "params": {
            "name": "echo", "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": capabilities
            }
        }});
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("mcp-method", method.parse().unwrap());
        if method == "tools/call" {
            headers.insert("mcp-name", "echo".parse().unwrap());
        }
        let classification = validate_mcp_post(
            &headers,
            &serde_json::to_vec(&body).unwrap(),
            LegacySessionEvidence::Absent,
            McpVersionPolicy::new(&[crate::mcp::MCP_MODERN_VERSION], &[crate::mcp::MCP_MODERN_VERSION]),
        )
        .unwrap();
        let McpRequestClassification::Modern(message) = classification else { panic!("modern fixture required") };
        *message
    }

    #[tokio::test]
    async fn capability_errors_keep_the_required_shape_and_request_id() {
        for required in [
            RequiredClientCapability::ElicitationForm,
            RequiredClientCapability::ElicitationUrl,
            RequiredClientCapability::Roots,
            RequiredClientCapability::Sampling,
            RequiredClientCapability::SamplingContext,
            RequiredClientCapability::SamplingTools,
        ] {
            let request = request("tools/call", json!({}));
            let error = require_client_capability(&request, required).unwrap_err();
            let response = (*error).into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let envelope: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                envelope,
                json!({"jsonrpc": "2.0", "id": "request", "error": {
                    "code": -32021, "message": "Missing required client capability",
                    "data": {"requiredCapabilities": required.declaration()}
                }})
            );
            let mut declared = request.clone();
            declared.client_capabilities = Some(required.declaration());
            assert_eq!(require_client_capability(&declared, required), Ok(()));
            assert!(require_client_capability(&request, required).is_err());
        }
    }

    #[test]
    fn elicitation_form_implicit_support_never_implies_url_support() {
        let implicit = request("tools/call", json!({"elicitation": {}}));
        assert!(require_client_capability(&implicit, RequiredClientCapability::ElicitationForm).is_ok());
        assert!(require_client_capability(&implicit, RequiredClientCapability::ElicitationUrl).is_err());
        let url_only = request("tools/call", json!({"elicitation": {"url": {}}}));
        assert!(require_client_capability(&url_only, RequiredClientCapability::ElicitationForm).is_err());
        for capabilities in [json!(null), json!({"elicitation": true}), json!({"elicitation": {"url": false}})] {
            let mut invalid = implicit.clone();
            invalid.client_capabilities = Some(capabilities);
            assert!(require_client_capability(&invalid, RequiredClientCapability::ElicitationUrl).is_err());
        }
    }

    #[test]
    fn extensions_require_both_peers_and_a_legal_identifier_without_merging_settings() {
        let client = json!({"extensions": {"com.example/tools": {"custom": [1, false]}}});
        let server = json!({"extensions": {"com.example/tools": {"other": {"value": null}}}});
        let original = client.clone();
        assert!(supports_extension(Some(&client), &server, "com.example/tools"));
        assert!(!supports_extension(None, &server, "com.example/tools"));
        assert!(!supports_extension(Some(&client), &json!({}), "com.example/tools"));
        for identifier in ["tools", "https://example.com/tools", "com.example/a/b"] {
            let declaration = json!({"extensions": {identifier: {}}});
            assert!(!supports_extension(Some(&declaration), &declaration, identifier));
        }
        assert_eq!(client, original);
    }

    #[test]
    fn pinned_common_result_fixtures_are_preserved() {
        let fixtures: Value = serde_json::from_str(include_str!("../../tests/fixtures/mcp/2026-07-28.json")).unwrap();
        assert_eq!(fixtures["source"]["commit"], "271ecc9accafdd9b83a3c869fa67c22953b2af80");
        assert_eq!(fixtures["source"]["sha256"], "742750af0bb8c716e7030c4977c992b55d1adc4407e9e66997db5846baedc2cd");
        for fixture in fixtures["results"]
            .as_array()
            .unwrap()
        {
            let method = fixture["method"]
                .as_str()
                .unwrap();
            let result = &fixture["result"];
            let original = serde_json::to_vec(result).unwrap();
            assert_eq!(
                validate_result(method, result, ResultSource::ModernServer).unwrap(),
                result["resultType"]
                    .as_str()
                    .unwrap()
            );
            assert_eq!(serde_json::to_vec(result).unwrap(), original);
        }
    }

    #[test]
    fn owned_complete_responses_add_only_common_fields_and_conservative_cache_defaults() {
        let request = request("tools/list", json!({}));
        let fields = json!({"tools": [], "nextCursor": "opaque", "vendor": [true, null]});
        let response = complete_response(
            &request,
            fields
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        assert_eq!(
            response,
            json!({"jsonrpc": "2.0", "id": "request", "result": {
                "tools": [], "nextCursor": "opaque", "vendor": [true, null],
                "resultType": "complete", "ttlMs": 0, "cacheScope": "private"
            }})
        );
        assert_eq!(validate_response(&request, &response, ResultSource::ModernServer), Ok(Some("complete")));
        assert_eq!(
            complete_response(
                &request,
                json!({"resultType": "task"})
                    .as_object()
                    .unwrap()
                    .clone()
            ),
            Err(ModernResponseError::NotComplete)
        );
        let empty = complete_response(&self::request("com.example/empty", json!({})), Map::new()).unwrap();
        assert_eq!(empty["result"], json!({"resultType": "complete"}));
    }

    #[test]
    fn backward_compatible_reads_do_not_fabricate_modern_results() {
        let legacy = json!({"tools": [], "vendor": true});
        assert_eq!(validate_result("tools/list", &legacy, ResultSource::CompatiblePeer), Ok("complete"));
        assert_eq!(
            validate_result("tools/list", &legacy, ResultSource::ModernServer),
            Err(ModernResponseError::MissingResultType)
        );
        assert!(
            legacy
                .get("resultType")
                .is_none()
        );
        for invalid in [json!(false), json!({"resultType": null}), json!({"resultType": 1})] {
            assert!(validate_result("tools/call", &invalid, ResultSource::CompatiblePeer).is_err());
        }
    }

    #[test]
    fn result_cache_and_continuation_rules_do_not_close_extension_types() {
        for result in [
            json!({"resultType": "complete"}),
            json!({"resultType": "complete", "ttlMs": -1, "cacheScope": "private"}),
            json!({"resultType": "complete", "ttlMs": 0, "cacheScope": "user"}),
        ] {
            assert_eq!(
                validate_result("resources/read", &result, ResultSource::ModernServer),
                Err(ModernResponseError::InvalidCacheHints)
            );
        }
        let pending = json!({"resultType": "input_required", "requestState": "opaque"});
        for method in ["tools/call", "prompts/get", "resources/read"] {
            assert_eq!(validate_result(method, &pending, ResultSource::ModernServer), Ok("input_required"));
        }
        assert_eq!(
            validate_result("tools/list", &pending, ResultSource::ModernServer),
            Err(ModernResponseError::InvalidContinuation)
        );
        for result in [
            json!({"resultType": "input_required"}),
            json!({"resultType": "input_required", "requestState": null}),
            json!({"resultType": "input_required", "inputRequests": []}),
        ] {
            assert_eq!(
                validate_result("tools/call", &result, ResultSource::ModernServer),
                Err(ModernResponseError::InvalidContinuation)
            );
        }
        assert_eq!(
            validate_result(
                "com.example/work",
                &json!({"resultType": "com.example/pending", "opaque": [1]}),
                ResultSource::ModernServer
            ),
            Ok("com.example/pending")
        );
    }

    #[test]
    fn response_validation_preserves_tool_errors_and_checks_correlation() {
        let mut request = request("tools/call", json!({}));
        let response = complete_response(
            &request,
            json!({"content": [], "isError": true})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        assert_eq!(validate_response(&request, &response, ResultSource::ModernServer), Ok(Some("complete")));
        let error = json!({"jsonrpc": "2.0", "error": {"code": -32602, "message": "invalid", "data": [1, true]}});
        assert_eq!(validate_response(&request, &error, ResultSource::ModernServer), Ok(None));
        let mut mismatched = response.clone();
        mismatched["id"] = json!(7);
        assert_eq!(
            validate_response(&request, &mismatched, ResultSource::ModernServer),
            Err(ModernResponseError::IdMismatch)
        );
        for malformed in [
            json!({"jsonrpc": "2.0", "id": "request"}),
            json!({"jsonrpc": "2.0", "result": {}, "error": {}}),
            json!({"jsonrpc": "2.0", "id": "request", "method": "roots/list"}),
        ] {
            assert_eq!(
                validate_response(&request, &malformed, ResultSource::ModernServer),
                Err(ModernResponseError::InvalidEnvelope)
            );
        }
        request.kind = McpMessageKind::Notification;
        request.id = None;
        assert_eq!(complete_response(&request, Map::new()), Err(ModernResponseError::InvalidRequest));
    }
}
