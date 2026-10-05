use serde_json::{Map, Value};

use crate::config::{MCP_METADATA_ALIASES, McpLegacyMetadataOutput};

use super::request_validation::McpRequestClassification;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpMetadataError {
    #[error("MCP {0} must be a JSON object")]
    InvalidObject(&'static str),
    #[error("Conflicting MCP metadata aliases for '{0}'")]
    ConflictingAlias(String),
    #[error("Invalid MCP metadata key '{0}'")]
    InvalidKey(String),
    #[error("MCP metadata key '{0}' is reserved and cannot be configured for injection or removal")]
    ProtectedKey(String),
    #[error("Modern MCP metadata cannot use the top-level compatibility envelope")]
    TopLevelModernMetadata,
    #[error("MCP message has no successful result object for metadata injection")]
    MissingResult,
}

impl McpMetadataError {
    pub fn into_response(
        self,
        body_bytes: &[u8],
        status: axum::http::StatusCode,
    ) -> axum::response::Response {
        let id = serde_json::from_slice::<Value>(body_bytes)
            .ok()
            .and_then(|body| {
                body.get("id")
                    .filter(|id| id.is_string() || id.is_i64() || id.is_u64())
                    .cloned()
            });
        super::errors::create_mcp_error_response_with_status(
            status,
            id,
            if status == axum::http::StatusCode::BAD_REQUEST {
                super::error_codes::INVALID_PARAMS
            } else {
                super::error_codes::INTERNAL_ERROR
            },
            &self.to_string(),
            None,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum McpMetaTarget {
    Params,
    Result,
    TopLevel,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct McpMetadataContext {
    output: McpLegacyMetadataOutput,
    modern: bool,
    cacheable_result: bool,
}

impl McpMetadataContext {
    pub fn legacy(output: Option<McpLegacyMetadataOutput>) -> Self {
        Self {
            output: output.unwrap_or_default(),
            modern: false,
            cacheable_result: false,
        }
    }

    pub fn from_classification(
        classification: &McpRequestClassification,
        output: Option<McpLegacyMetadataOutput>,
    ) -> Self {
        if let McpRequestClassification::Modern(message) = classification {
            Self {
                output: McpLegacyMetadataOutput::Canonical,
                modern: true,
                cacheable_result: super::modern::is_cacheable_method(&message.method),
            }
        } else {
            Self::legacy(output)
        }
    }

    pub fn is_canonical(self) -> bool {
        self.output == McpLegacyMetadataOutput::Canonical
    }

    pub fn is_modern(self) -> bool {
        self.modern
    }

    pub fn requires_private_result_cache(self) -> bool {
        self.modern && self.cacheable_result
    }

    pub fn extension_key(
        self,
        key: &str,
    ) -> &str {
        if self.is_canonical() {
            canonical_key(key)
        } else {
            MCP_METADATA_ALIASES
                .iter()
                .find(|(_, canonical)| *canonical == key)
                .map_or(key, |(historical, _)| historical)
        }
    }
}

pub fn canonical_key(key: &str) -> &str {
    MCP_METADATA_ALIASES
        .iter()
        .find(|(historical, _)| *historical == key)
        .map_or(key, |(_, canonical)| canonical)
}

pub fn is_valid_key(key: &str) -> bool {
    let name = if let Some((prefix, name)) = key.split_once('/') {
        if !prefix
            .split('.')
            .all(|label| {
                let bytes = label.as_bytes();
                bytes
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
                    && bytes
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && bytes
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            })
        {
            return false;
        }
        name
    } else {
        key
    };
    let bytes = name.as_bytes();
    bytes.is_empty()
        || (bytes
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
}

pub fn is_protocol_key(key: &str) -> bool {
    matches!(key, "progressToken" | "traceparent" | "tracestate" | "baggage")
        || key
            .split_once('/')
            .is_some_and(|(prefix, _)| matches!(prefix.split('.').nth(1), Some("mcp" | "modelcontextprotocol")))
}

pub fn is_gateway_key(key: &str) -> bool {
    MCP_METADATA_ALIASES
        .iter()
        .any(|(historical, canonical)| key == *historical || key == *canonical)
        || matches!(key, "agentIdentity" | "serverIdentity" | "didwebvhIdentity" | "x-affinidi-fabric-gateway-did")
}

pub fn validate_operator_key(
    key: &str,
    context: McpMetadataContext,
) -> Result<(), McpMetadataError> {
    if is_protocol_key(key) || is_gateway_key(key) {
        return Err(McpMetadataError::ProtectedKey(key.to_string()));
    }
    if context.is_canonical() && !is_valid_key(key) {
        return Err(McpMetadataError::InvalidKey(key.to_string()));
    }
    Ok(())
}

fn canonical_container(body: &Map<String, Value>) -> Result<Option<&Map<String, Value>>, McpMetadataError> {
    if body.contains_key("error") {
        return Ok(None);
    }
    let (key, path) = if body.contains_key("method") || body.contains_key("params") {
        ("params", "params")
    } else {
        ("result", "result")
    };
    body.get(key)
        .map(|value| {
            value
                .as_object()
                .ok_or(McpMetadataError::InvalidObject(path))
        })
        .transpose()
}

fn meta_object<'a>(
    container: &'a Map<String, Value>,
    path: &'static str,
) -> Result<Option<&'a Map<String, Value>>, McpMetadataError> {
    container
        .get("_meta")
        .map(|value| {
            value
                .as_object()
                .ok_or(McpMetadataError::InvalidObject(path))
        })
        .transpose()
}

pub fn read_metadata(body: &Value) -> Result<Option<Map<String, Value>>, McpMetadataError> {
    let body = body
        .as_object()
        .ok_or(McpMetadataError::InvalidObject("body"))?;
    if body.contains_key("error") {
        return Ok(None);
    }
    let canonical = canonical_container(body)?
        .map(|container| meta_object(container, "canonical _meta"))
        .transpose()?
        .flatten();
    let historical = meta_object(body, "top-level _meta")?;
    if canonical.is_none() && historical.is_none() {
        return Ok(None);
    }

    let mut metadata = Map::new();
    for source in [historical, canonical]
        .into_iter()
        .flatten()
    {
        for (key, value) in source {
            let key = canonical_key(key);
            if is_gateway_key(key)
                && metadata
                    .get(key)
                    .is_some_and(|existing| existing != value)
            {
                return Err(McpMetadataError::ConflictingAlias(key.to_string()));
            }
            metadata.insert(key.to_string(), value.clone());
        }
    }
    Ok(Some(metadata))
}

pub fn normalize_metadata(
    body: &mut Value,
    context: McpMetadataContext,
) -> Result<(), McpMetadataError> {
    if body.get("_meta").is_none()
        && body
            .get("params")
            .and_then(|params| params.get("_meta"))
            .is_none()
        && body
            .get("result")
            .and_then(|result| result.get("_meta"))
            .is_none()
    {
        return Ok(());
    }
    if context.is_modern() && body.get("_meta").is_some() {
        return Err(McpMetadataError::TopLevelModernMetadata);
    }
    let Some(metadata) = read_metadata(body)? else {
        return Ok(());
    };
    if !context.is_canonical() {
        return Ok(());
    }
    for key in metadata.keys() {
        if !is_valid_key(key) {
            return Err(McpMetadataError::InvalidKey(key.clone()));
        }
    }
    let body = body
        .as_object_mut()
        .ok_or(McpMetadataError::InvalidObject("body"))?;
    let key = if body.contains_key("method") || body.contains_key("params") {
        "params"
    } else {
        "result"
    };
    let container = body
        .entry(key)
        .or_insert_with(|| Value::Object(Map::new()));
    let container = container
        .as_object_mut()
        .ok_or(McpMetadataError::InvalidObject(key))?;
    container.insert("_meta".to_string(), Value::Object(metadata));
    body.remove("_meta");
    Ok(())
}

pub fn normalize_bytes(
    body: &bytes::Bytes,
    context: McpMetadataContext,
) -> Result<bytes::Bytes, McpMetadataError> {
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return Ok(body.clone());
    };
    if !value.is_object() {
        return Ok(body.clone());
    }
    let original = value.clone();
    normalize_metadata(&mut value, context)?;
    if original == value {
        Ok(body.clone())
    } else {
        Ok(bytes::Bytes::from(value.to_string()))
    }
}

pub fn normalize_text(
    body: &str,
    context: McpMetadataContext,
) -> Result<String, McpMetadataError> {
    let normalized = normalize_bytes(&bytes::Bytes::copy_from_slice(body.as_bytes()), context)?;
    String::from_utf8(normalized.to_vec()).map_err(|_| McpMetadataError::InvalidObject("UTF-8 body"))
}

pub fn metadata_mut(
    body: &mut Value,
    context: McpMetadataContext,
    target: McpMetaTarget,
) -> Result<&mut Map<String, Value>, McpMetadataError> {
    normalize_metadata(body, context)?;
    let body = body
        .as_object_mut()
        .ok_or(McpMetadataError::InvalidObject("body"))?;
    let target = if context.is_canonical() && matches!(target, McpMetaTarget::TopLevel) {
        McpMetaTarget::Params
    } else {
        target
    };
    let container = match target {
        McpMetaTarget::Params => body
            .entry("params")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(McpMetadataError::InvalidObject("params"))?,
        McpMetaTarget::Result => body
            .get_mut("result")
            .and_then(Value::as_object_mut)
            .ok_or(McpMetadataError::MissingResult)?,
        McpMetaTarget::TopLevel => body,
    };
    container
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or(McpMetadataError::InvalidObject("_meta"))
}

pub fn remove_metadata_key(
    body: &mut Value,
    key: &str,
) {
    for path in ["/_meta", "/params/_meta", "/result/_meta"] {
        if let Some(metadata) = body
            .pointer_mut(path)
            .and_then(Value::as_object_mut)
        {
            metadata.remove(key);
            for (historical, canonical) in MCP_METADATA_ALIASES {
                if key == *historical || key == *canonical {
                    metadata.remove(*historical);
                    metadata.remove(*canonical);
                }
            }
        }
    }
}

pub fn validate_raw_identity_key(
    key: &str,
    context: McpMetadataContext,
) -> Result<(), McpMetadataError> {
    if is_protocol_key(key)
        || MCP_METADATA_ALIASES
            .iter()
            .any(|(old, new)| key == *old || key == *new)
    {
        return Err(McpMetadataError::ProtectedKey(key.to_string()));
    }
    if context.is_canonical() && !is_valid_key(key) {
        return Err(McpMetadataError::InvalidKey(key.to_string()));
    }
    Ok(())
}

pub fn insert_gateway_metadata(
    body: &mut Value,
    context: McpMetadataContext,
    target: McpMetaTarget,
    key: &str,
    value: Value,
) -> Result<(), McpMetadataError> {
    normalize_metadata(body, context)?;
    remove_metadata_key(body, key);
    metadata_mut(body, context, target)?.insert(
        context
            .extension_key(key)
            .to_string(),
        value,
    );
    if matches!(target, McpMetaTarget::Result) {
        protect_enriched_result_cache(body, context);
    }
    Ok(())
}

pub fn permits_result_enrichment(body: &Value) -> bool {
    body.get("result")
        .and_then(Value::as_object)
        .is_some_and(|result| {
            result
                .get("resultType")
                .is_none_or(|kind| kind.as_str() == Some("complete"))
        })
}

pub fn protect_enriched_result_cache(
    body: &mut Value,
    context: McpMetadataContext,
) {
    if context.requires_private_result_cache()
        && permits_result_enrichment(body)
        && let Some(result) = body
            .get_mut("result")
            .and_then(Value::as_object_mut)
    {
        result.insert("cacheScope".to_string(), Value::String("private".to_string()));
        result.insert("ttlMs".to_string(), Value::from(0));
    }
}

pub fn validate_custom_metadata(
    custom: &crate::config::CustomMetadata,
    context: McpMetadataContext,
) -> Result<(), String> {
    use crate::config::MetadataInjectionTarget;
    use axum::http::header::HeaderName;

    if !custom.enabled {
        return Ok(());
    }
    let Some(payload) = custom.payload.as_ref() else { return Ok(()) };
    let payload = payload
        .as_object()
        .ok_or("Custom metadata payload must be a JSON object")?;
    let target = custom
        .injection_target
        .as_ref()
        .unwrap_or(&MetadataInjectionTarget::Both);
    for (key, value) in payload {
        if matches!(target, MetadataInjectionTarget::Meta | MetadataInjectionTarget::Both) {
            validate_operator_key(key, context).map_err(|error| error.to_string())?;
        }
        if matches!(target, MetadataInjectionTarget::Headers | MetadataInjectionTarget::Both) {
            HeaderName::from_bytes(format!("X-Gateway-{}", key.replace('_', "-")).as_bytes())
                .map_err(|_| format!("Invalid MCP custom metadata header name '{key}'"))?;
            if !value.is_string() {
                return Err(format!("MCP custom metadata header '{key}' must be a string"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn metadata_free_legacy_payloads_remain_byte_for_byte_unchanged() {
        for raw in [r#"{ "jsonrpc": "2.0", "id": 1, "result": "ok" }"#, r#"{"method":"tools/list"}"#] {
            let body = bytes::Bytes::copy_from_slice(raw.as_bytes());
            for output in [McpLegacyMetadataOutput::Compatibility, McpLegacyMetadataOutput::Canonical] {
                assert_eq!(normalize_bytes(&body, McpMetadataContext::legacy(Some(output))).unwrap(), body);
            }
        }
    }

    #[test]
    fn modern_top_level_metadata_without_protocol_keys_is_rejected() {
        use crate::mcp::request_validation::{LegacySessionEvidence, McpVersionPolicy, validate_mcp_post};
        use axum::http::HeaderMap;
        let admitted = serde_json::json!({"jsonrpc": "2.0", "id": "modern", "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        let mut headers = HeaderMap::new();
        headers.insert(
            "MCP-Protocol-Version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("Mcp-Method", "tools/list".parse().unwrap());
        let classification = validate_mcp_post(
            &headers,
            admitted
                .to_string()
                .as_bytes(),
            LegacySessionEvidence::Absent,
            McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
            ),
        )
        .unwrap();
        let context = super::McpMetadataContext::from_classification(&classification, None);
        // A request and a response envelope carrying only non-protocol keys at
        // the top level, as an upstream that attaches identity there sends.
        for mut body in [
            serde_json::json!({"jsonrpc": "2.0", "id": "modern", "method": "tools/list",
                "params": {}, "_meta": {"tenant": "acme"}}),
            serde_json::json!({"jsonrpc": "2.0", "id": "modern", "result": {"resultType": "complete", "tools": []},
                "_meta": {"serverIdentity": {"name": "upstream"}}}),
        ] {
            assert_eq!(normalize_metadata(&mut body, context), Err(McpMetadataError::TopLevelModernMetadata), "{body}");
        }
        let mut in_result = serde_json::json!({"jsonrpc": "2.0", "id": "modern", "result": {
            "resultType": "complete", "tools": [], "_meta": {"serverIdentity": {"name": "upstream"}}
        }});
        assert_eq!(normalize_metadata(&mut in_result, context), Ok(()), "result._meta is accepted");
    }

    #[test]
    fn modern_context_forces_canonical_without_changing_runtime_admission() {
        use crate::mcp::request_validation::{
            LEGACY_ONLY_POLICY, LegacySessionEvidence, McpVersionPolicy, validate_mcp_post,
        };
        use axum::http::HeaderMap;
        let body = serde_json::json!({"jsonrpc": "2.0", "id": "modern", "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {"extensions": {"com.example/extension": {"arbitrary": [true]}}},
            "traceparent": "preserve-only", "progressToken": "progress"
        }}});
        let mut headers = HeaderMap::new();
        headers.insert(
            "MCP-Protocol-Version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("Mcp-Method", "tools/list".parse().unwrap());
        let classification = validate_mcp_post(
            &headers,
            body.to_string().as_bytes(),
            LegacySessionEvidence::Absent,
            McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
            ),
        )
        .unwrap();
        let context = super::McpMetadataContext::from_classification(
            &classification,
            Some(crate::config::McpLegacyMetadataOutput::Compatibility),
        );
        assert!(context.is_canonical());
        assert!(context.is_modern());
        let mut rewritten = body.clone();
        super::insert_gateway_metadata(
            &mut rewritten,
            context,
            super::McpMetaTarget::TopLevel,
            crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
            serde_json::json!({"verifiablePresentation": "unchanged"}),
        )
        .unwrap();
        for (key, value) in body["params"]["_meta"]
            .as_object()
            .unwrap()
        {
            assert_eq!(&rewritten["params"]["_meta"][key], value);
        }
        assert!(
            rewritten
                .get("_meta")
                .is_none()
        );
        let error =
            validate_mcp_post(&headers, body.to_string().as_bytes(), LegacySessionEvidence::Absent, LEGACY_ONLY_POLICY)
                .unwrap_err();
        assert_eq!(error.code, -32022);
        assert_eq!(
            error.data,
            Some(
                serde_json::json!({"requested": crate::mcp::MCP_MODERN_VERSION, "supported": [crate::mcp::MCP_LEGACY_VERSION]})
            )
        );

        let mut result = serde_json::json!({"result": {"resultType": "complete", "tools": [], "ttlMs": 60000, "cacheScope": "public"}});
        super::protect_enriched_result_cache(&mut result, context);
        assert_eq!(result["result"]["ttlMs"], 0);
        assert_eq!(result["result"]["cacheScope"], "private");
        result["result"]["resultType"] = serde_json::json!("input_required");
        let original = result.clone();
        super::protect_enriched_result_cache(&mut result, context);
        assert_eq!(result, original);
    }

    use super::*;
    use crate::config::{AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION, MCP_AGENT_IDENTITY_CREDENTIAL_KEY};
    use serde_json::json;

    #[test]
    fn canonical_normalization_preserves_params_and_migrates_only_envelope_keys() {
        let credential = json!({"did": "did:example:agent", "verifiablePresentation": "signed.unchanged.token"});
        let mut body = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"_meta": {"https://example.org/key": 1}}, "_meta": {"tenant": "canonical", "progressToken": 9}},
            "_meta": {"tenant": "historical", "traceId": "trace", AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: credential}
        });
        let original_params = body["params"].clone();
        normalize_metadata(&mut body, McpMetadataContext::legacy(Some(McpLegacyMetadataOutput::Canonical))).unwrap();
        assert_eq!(body["params"]["name"], original_params["name"]);
        assert_eq!(body["params"]["arguments"], original_params["arguments"]);
        assert_eq!(body["params"]["_meta"]["tenant"], "canonical");
        assert_eq!(body["params"]["_meta"]["progressToken"], 9);
        assert_eq!(body["params"]["_meta"][MCP_AGENT_IDENTITY_CREDENTIAL_KEY], credential);
        assert_eq!(body["params"]["_meta"]["traceId"], "trace");
        assert!(body.get("_meta").is_none());
        assert_eq!(body["id"], 7);
    }

    #[test]
    fn compatibility_normalization_does_not_change_wire_shape() {
        let mut body =
            json!({"method": "tools/list", "_meta": {AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: {"did": "old"}}});
        let original = body.clone();
        normalize_metadata(&mut body, McpMetadataContext::default()).unwrap();
        assert_eq!(body, original);

        // A legacy request carrying top-level `_meta` and its URL key reaches
        // the Target byte for byte, including its whitespace and key order.
        let wire = bytes::Bytes::from_static(
            br#"{ "jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"echo"}, "_meta":{"https://fabric.affinidi.io/extensions/agent-identity-credential/v1":{"did":"old"}} }"#,
        );
        assert_eq!(normalize_bytes(&wire, McpMetadataContext::default()).unwrap(), wire);
    }

    #[test]
    fn malformed_canonical_metadata_never_uses_historical_fallback() {
        for invalid in [Value::Null, json!("bad"), json!([]), json!(1)] {
            let body = json!({"method": "tools/list", "params": {"_meta": invalid}, "_meta": {"tenant": "fallback"}});
            assert!(matches!(read_metadata(&body), Err(McpMetadataError::InvalidObject(_))));
            let body = json!({"method": "tools/list", "params": invalid, "_meta": {"tenant": "fallback"}});
            assert!(matches!(read_metadata(&body), Err(McpMetadataError::InvalidObject(_))));
        }
    }

    #[test]
    fn aliases_must_agree_across_spellings_and_locations() {
        let mut body = json!({
            "method": "tools/call", "params": {"_meta": {MCP_AGENT_IDENTITY_CREDENTIAL_KEY: {"did": "new"}}},
            "_meta": {AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: {"did": "old"}}
        });
        assert!(matches!(read_metadata(&body), Err(McpMetadataError::ConflictingAlias(_))));
        body["_meta"][AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION] = json!({"did": "new"});
        let metadata = read_metadata(&body)
            .unwrap()
            .unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[MCP_AGENT_IDENTITY_CREDENTIAL_KEY]["did"], "new");
    }

    #[test]
    fn metadata_key_grammar_accepts_optional_prefix_and_empty_name() {
        for key in ["progressToken", "tenant", "", "io.affinidi.fabric/", "com.example/name_1.value", "a/name"] {
            assert!(is_valid_key(key), "{key}");
        }
        for key in [
            "https://fabric.affinidi.io/key",
            "io.example/a/b",
            "1example/key",
            "io.-example/key",
            "io.example-/key",
            "/name",
            "io..example/key",
            "io.example/_name",
        ] {
            assert!(!is_valid_key(key), "{key}");
        }
    }

    #[test]
    fn operator_keys_cannot_overwrite_reserved_or_owned_values() {
        for key in [
            "io.modelcontextprotocol/version",
            "dev.mcp/name",
            "org.modelcontextprotocol.api/name",
            "progressToken",
            "traceparent",
            "tracestate",
            "baggage",
            MCP_AGENT_IDENTITY_CREDENTIAL_KEY,
            AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
        ] {
            assert!(
                matches!(
                    validate_operator_key(key, McpMetadataContext::default()),
                    Err(McpMetadataError::ProtectedKey(_))
                ),
                "{key}"
            );
        }
        for key in [
            "mcp/name",
            "modelcontextprotocol/tools",
            "mcp.example/name",
            "modelcontextprotocol.example/name",
            "com.example.mcp/name",
        ] {
            assert!(!is_protocol_key(key), "{key}");
            for output in [McpLegacyMetadataOutput::Compatibility, McpLegacyMetadataOutput::Canonical] {
                assert!(validate_operator_key(key, McpMetadataContext::legacy(Some(output))).is_ok(), "{key}");
            }
        }
    }

    #[test]
    fn result_metadata_preserves_open_result_types_and_continuation_state() {
        for result_type in ["complete", "input_required", "task", "vendor_result"] {
            let mut body = json!({"id": "reply", "result": {
                "resultType": result_type, "inputRequests": {"one": {"method": "roots/list"}},
                "requestState": "opaque", "structuredContent": [1, false],
                "_meta": {"com.example/key": {"arbitrary": true}}
            }});
            let original = body.clone();
            normalize_metadata(&mut body, McpMetadataContext::legacy(Some(McpLegacyMetadataOutput::Canonical)))
                .unwrap();
            assert_eq!(body, original);
        }
        let mut error = json!({"id": 1, "error": {"code": -32602, "message": "invalid"}});
        let original = error.clone();
        normalize_metadata(&mut error, McpMetadataContext::legacy(Some(McpLegacyMetadataOutput::Canonical))).unwrap();
        assert_eq!(error, original);
    }

    #[test]
    fn canonical_result_round_trip_preserves_extensible_schema_and_content() {
        let credential = json!({"verifiablePresentation": "signed-content-unchanged"});
        let mut body = json!({"jsonrpc": "2.0", "id": "preserve", "result": {
            "resultType": "complete", "structuredContent": [false, 1, null, {"free": "shape"}],
            "content": [{"type": "audio", "data": "YXVkaW8=", "mimeType": "audio/wav"}, {"type": "resource_link", "uri": "https://example.org/resource", "name": "reference"}],
            "tools": [{"name": "echo", "title": "Echo", "annotations": {"readOnlyHint": true}, "icons": [{"src": "https://example.org/icon.png"}],
                "inputSchema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "$defs": {"input": {"type": "string"}}, "allOf": [{"$ref": "#/$defs/input"}], "if": {"type": "object"}, "then": {"unevaluatedProperties": false}},
                "outputSchema": {"oneOf": [{"type": "null"}, {"type": "array"}]}, "com.example/unknown": [1, 2]}],
            "ttlMs": 321, "cacheScope": "public", "nextCursor": "opaque-cursor", "isError": false,
            "_meta": {AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: credential, "com.example/key": {"anything": true}}, "unknown": {"value": 1}
        }});
        let mut expected = body.clone();
        expected["result"]["_meta"]
            .as_object_mut()
            .unwrap()
            .remove(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION);
        expected["result"]["_meta"][MCP_AGENT_IDENTITY_CREDENTIAL_KEY] = credential;
        normalize_metadata(&mut body, McpMetadataContext::legacy(Some(McpLegacyMetadataOutput::Canonical))).unwrap();
        assert_eq!(body, expected);
        normalize_metadata(&mut body, McpMetadataContext::legacy(Some(McpLegacyMetadataOutput::Canonical))).unwrap();
        assert_eq!(body, expected);
    }
}
