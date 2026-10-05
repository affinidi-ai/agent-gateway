//! MCP custom metadata injection

use std::sync::Arc;

use axum::http::header::{HeaderName, HeaderValue};

use super::meta::{McpMetaTarget, McpMetadataContext};
use crate::config::MetadataInjectionTarget;

/// Output of [`inject_custom_metadata_with_context`].
///
/// `body` is the (possibly modified) request body.
/// `extra_headers` lists `X-Gateway-*` name/value pairs to merge into the
/// outbound request's HTTP headers.
#[derive(Debug)]
pub struct McpCustomMetadataResult {
    pub body: bytes::Bytes,
    pub extra_headers: Vec<(HeaderName, HeaderValue)>,
}

/// Inject operator-configured custom metadata into an outbound MCP request.
///
/// Behaviour is governed by `custom_metadata.injection_target`:
/// * `Meta`    → merges key/value pairs into the JSON-RPC `_meta` object.
/// * `Headers` → emits `X-Gateway-<key>` header pairs in `extra_headers`.
/// * `Both`    → does both (default when `injection_target` is absent).
///
/// Returns the (possibly rewritten) body and the headers to inject.
/// Returns an unmodified body and empty headers when `payload` is absent.
#[cfg(test)]
pub async fn inject_custom_metadata_mcp(
    body_bytes: &bytes::Bytes,
    custom_metadata: &crate::config::CustomMetadata,
    channel_name: &str,
    secrets_store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
    runtime: crate::protocols::MetadataRuntimeContext<'_>,
) -> anyhow::Result<McpCustomMetadataResult> {
    inject_custom_metadata_with_context(
        body_bytes,
        custom_metadata,
        channel_name,
        secrets_store,
        runtime,
        McpMetadataContext::default(),
        McpMetaTarget::TopLevel,
    )
    .await
}

pub async fn inject_custom_metadata_with_context(
    body_bytes: &bytes::Bytes,
    custom_metadata: &crate::config::CustomMetadata,
    channel_name: &str,
    secrets_store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
    runtime: crate::protocols::MetadataRuntimeContext<'_>,
    context: McpMetadataContext,
    target: McpMetaTarget,
) -> anyhow::Result<McpCustomMetadataResult> {
    if !custom_metadata.enabled {
        return Ok(McpCustomMetadataResult {
            body: body_bytes.clone(),
            extra_headers: Vec::new(),
        });
    }
    if matches!(target, McpMetaTarget::Result) {
        let body: serde_json::Value = serde_json::from_slice(body_bytes)?;
        if !super::meta::permits_result_enrichment(&body) {
            return Ok(McpCustomMetadataResult {
                body: super::meta::normalize_bytes(body_bytes, context)?,
                extra_headers: Vec::new(),
            });
        }
    }
    super::meta::validate_custom_metadata(custom_metadata, context).map_err(anyhow::Error::msg)?;
    let Some(ref payload) = custom_metadata.payload else {
        return Ok(McpCustomMetadataResult {
            body: body_bytes.clone(),
            extra_headers: Vec::new(),
        });
    };

    let injection_target = custom_metadata
        .injection_target
        .as_ref()
        .unwrap_or(&MetadataInjectionTarget::Both);

    let resolved_payload = crate::protocols::resolve_metadata_references(payload, secrets_store, channel_name, runtime)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to resolve custom metadata value helpers: {}", e))?;

    let payload_obj = resolved_payload
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Custom metadata payload must be a JSON object"))?;

    let mut extra_headers = Vec::new();
    let mut body = body_bytes.clone();

    if matches!(injection_target, MetadataInjectionTarget::Headers | MetadataInjectionTarget::Both) {
        for (key, value) in payload_obj {
            let value_str = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("MCP custom metadata header '{}' must be a string", key))?;
            let header_name = HeaderName::from_bytes(format!("X-Gateway-{}", key.replace('_', "-")).as_bytes())
                .map_err(|e| anyhow::anyhow!("Invalid MCP custom metadata header name '{}': {}", key, e))?;
            let header_value = HeaderValue::from_str(value_str)
                .map_err(|e| anyhow::anyhow!("Invalid MCP custom metadata header value for '{}': {}", key, e))?;
            extra_headers.push((header_name, header_value));
        }
    }

    if matches!(injection_target, MetadataInjectionTarget::Meta | MetadataInjectionTarget::Both) {
        let mut json_body: serde_json::Value = serde_json::from_slice(body_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse MCP body as JSON: {}", e))?;

        if !json_body.is_object() {
            anyhow::bail!("MCP request body root must be a JSON object")
        }
        let meta_obj = super::meta::metadata_mut(&mut json_body, context, target)?;

        for (key, value) in payload_obj {
            super::meta::validate_operator_key(key, context)?;
            meta_obj.insert(key.clone(), value.clone());
        }
        if matches!(target, McpMetaTarget::Result) {
            super::meta::protect_enriched_result_cache(&mut json_body, context);
            if context.requires_private_result_cache() {
                extra_headers.push((axum::http::header::CACHE_CONTROL, HeaderValue::from_static("private, no-store")));
            }
        }

        body = bytes::Bytes::from(
            serde_json::to_vec(&json_body)
                .map_err(|e| anyhow::anyhow!("Failed to serialize modified MCP body: {}", e))?,
        );
    }

    Ok(McpCustomMetadataResult { body, extra_headers })
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn canonical_metadata_has_one_location_and_preserves_caller_values() {
        let body = Bytes::from(serde_json::json!({"method": "tools/call", "params": {"name": "echo", "_meta": {"progressToken": 3}}, "_meta": {"traceId": "keep"}}).to_string());
        let output = inject_custom_metadata_with_context(
            &body,
            &metadata(Some(MetadataInjectionTarget::Meta)),
            "test",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
            McpMetadataContext::legacy(Some(crate::config::McpLegacyMetadataOutput::Canonical)),
            McpMetaTarget::TopLevel,
        )
        .await
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&output.body).unwrap();
        assert_eq!(
            parsed["params"]["_meta"],
            serde_json::json!({"progressToken": 3, "traceId": "keep", "tenant": "acme", "region": "eu-west"})
        );
        assert!(parsed.get("_meta").is_none());
    }

    #[tokio::test]
    async fn custom_metadata_rejects_reserved_collisions_and_ambiguous_header_names() {
        for key in [
            "progressToken",
            "dev.mcp/version",
            "org.modelcontextprotocol.api/name",
            "traceparent",
            crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY,
        ] {
            let mut config = metadata(Some(MetadataInjectionTarget::Meta));
            config.payload = Some(serde_json::json!({key: "overwrite"}));
            assert!(
                inject_custom_metadata_mcp(
                    &body_with_params(),
                    &config,
                    "test",
                    &None,
                    crate::protocols::MetadataRuntimeContext::default()
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("reserved")
            );
        }
        let mut config = metadata(Some(MetadataInjectionTarget::Both));
        config.payload = Some(serde_json::json!({"com.example/tenant": "one"}));
        assert!(
            inject_custom_metadata_mcp(
                &body_with_params(),
                &config,
                "test",
                &None,
                crate::protocols::MetadataRuntimeContext::default()
            )
            .await
            .is_err()
        );
        config.injection_target = Some(MetadataInjectionTarget::Meta);
        assert!(
            inject_custom_metadata_mcp(
                &body_with_params(),
                &config,
                "test",
                &None,
                crate::protocols::MetadataRuntimeContext::default()
            )
            .await
            .is_ok()
        );
    }

    use super::*;
    use crate::config::{CustomMetadata, MetadataInjectionTarget};
    use bytes::Bytes;
    use serde_json::json;

    fn body_with_params() -> Bytes {
        Bytes::from(
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "my_tool" }
            })
            .to_string(),
        )
    }

    fn metadata(target: Option<MetadataInjectionTarget>) -> CustomMetadata {
        CustomMetadata {
            enabled: true,
            payload: Some(json!({ "tenant": "acme", "region": "eu-west" })),
            injection_target: target,
        }
    }

    #[tokio::test]
    async fn runtime_helpers_resolve_for_meta_and_headers() {
        let body = body_with_params();
        let cfg = CustomMetadata {
            enabled: true,
            payload: Some(json!({
                "request_id": "$REQUEST_ID",
                "surface_id": "$SURFACE_ID",
            })),
            injection_target: Some(MetadataInjectionTarget::Both),
        };

        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext {
                request_id: Some("trace-123"),
                surface_id: Some("surface-456"),
            },
        )
        .await
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&result.body).unwrap();
        assert_eq!(parsed["_meta"]["request_id"].as_str(), Some("trace-123"));
        assert_eq!(parsed["_meta"]["surface_id"].as_str(), Some("surface-456"));
        let headers = result
            .extra_headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value
                        .to_str()
                        .unwrap()
                        .to_string(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(headers.get("x-gateway-request-id"), Some(&"trace-123".to_string()));
        assert_eq!(headers.get("x-gateway-surface-id"), Some(&"surface-456".to_string()));
    }

    #[tokio::test]
    async fn unresolved_helpers_fail_closed_in_both_output_modes() {
        for output in
            [crate::config::McpLegacyMetadataOutput::Compatibility, crate::config::McpLegacyMetadataOutput::Canonical]
        {
            for injection in
                [MetadataInjectionTarget::Meta, MetadataInjectionTarget::Headers, MetadataInjectionTarget::Both]
            {
                let config = CustomMetadata {
                    enabled: true,
                    payload: Some(json!({"tenant": "$SECRET:missing"})),
                    injection_target: Some(injection),
                };
                for (target, body) in [
                    (McpMetaTarget::Params, json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})),
                    (McpMetaTarget::Result, json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})),
                ] {
                    let bytes = Bytes::from(body.to_string());
                    let error = inject_custom_metadata_with_context(
                        &bytes,
                        &config,
                        "test",
                        &None,
                        crate::protocols::MetadataRuntimeContext::default(),
                        McpMetadataContext::legacy(Some(output)),
                        target,
                    )
                    .await
                    .unwrap_err();
                    assert!(
                        error
                            .to_string()
                            .contains("Failed to resolve custom metadata value helpers")
                    );
                    assert!(
                        error
                            .to_string()
                            .contains("secrets store is not configured")
                    );
                    assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(), body);
                }
            }
        }
    }

    #[tokio::test]
    async fn no_payload_returns_body_unchanged_and_no_headers() {
        let body = body_with_params();
        let cfg = CustomMetadata {
            enabled: true,
            payload: None,
            injection_target: None,
        };
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.body, body);
        assert!(
            result
                .extra_headers
                .is_empty()
        );
    }

    #[tokio::test]
    async fn meta_target_injects_meta_only() {
        let body = body_with_params();
        let cfg = metadata(Some(MetadataInjectionTarget::Meta));
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await
        .unwrap();

        assert!(
            result
                .extra_headers
                .is_empty(),
            "no headers for Meta target"
        );

        let parsed: serde_json::Value = serde_json::from_slice(&result.body).unwrap();
        assert_eq!(parsed["_meta"]["tenant"].as_str(), Some("acme"));
        assert_eq!(parsed["_meta"]["region"].as_str(), Some("eu-west"));
    }

    #[tokio::test]
    async fn headers_target_injects_headers_only() {
        let body = body_with_params();
        let original_body = body.clone();
        let cfg = metadata(Some(MetadataInjectionTarget::Headers));
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await
        .unwrap();

        assert_eq!(result.body, original_body, "body unchanged for Headers target");
        let header_names: Vec<&str> = result
            .extra_headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(header_names.contains(&"x-gateway-tenant"), "X-Gateway-tenant missing");
        assert!(header_names.contains(&"x-gateway-region"), "X-Gateway-region missing");

        let tenant_val = result
            .extra_headers
            .iter()
            .find(|(k, _)| k.as_str() == "x-gateway-tenant")
            .and_then(|(_, v)| v.to_str().ok());
        assert_eq!(tenant_val, Some("acme"));
    }

    #[tokio::test]
    async fn both_target_injects_meta_and_headers() {
        let body = body_with_params();
        let cfg = metadata(Some(MetadataInjectionTarget::Both));
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&result.body).unwrap();
        assert_eq!(parsed["_meta"]["tenant"].as_str(), Some("acme"), "_meta.tenant");
        assert!(
            !result
                .extra_headers
                .is_empty(),
            "headers present"
        );
    }

    #[tokio::test]
    async fn default_target_behaves_like_both() {
        let body = body_with_params();
        let cfg = metadata(None);
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&result.body).unwrap();
        assert_eq!(parsed["_meta"]["tenant"].as_str(), Some("acme"), "_meta.tenant");
        assert!(
            !result
                .extra_headers
                .is_empty(),
            "headers present"
        );
    }

    #[tokio::test]
    async fn underscore_in_key_becomes_hyphen_in_header_name() {
        let body = body_with_params();
        let cfg = CustomMetadata {
            enabled: true,
            payload: Some(json!({ "my_key": "value" })),
            injection_target: Some(MetadataInjectionTarget::Headers),
        };
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await
        .unwrap();
        let names: Vec<&str> = result
            .extra_headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(names.contains(&"x-gateway-my-key"), "underscore → hyphen: got {names:?}");
    }

    #[tokio::test]
    async fn non_string_payload_value_errors_for_headers() {
        let body = body_with_params();
        let cfg = CustomMetadata {
            enabled: true,
            payload: Some(json!({ "count": 42, "flag": true, "name": "ok" })),
            injection_target: Some(MetadataInjectionTarget::Headers),
        };
        let err = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("must be a string"),
            "expected string header value error, got: {err}"
        );
    }

    #[tokio::test]
    async fn existing_meta_is_merged_not_replaced() {
        let body = Bytes::from(
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "_meta": { "existing": "keep-me" }
            })
            .to_string(),
        );
        let cfg = metadata(Some(MetadataInjectionTarget::Meta));
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&result.body).unwrap();
        assert_eq!(parsed["_meta"]["existing"].as_str(), Some("keep-me"), "existing key preserved");
        assert_eq!(parsed["_meta"]["tenant"].as_str(), Some("acme"), "new key injected");
    }

    #[tokio::test]
    async fn non_object_payload_returns_error() {
        let body = body_with_params();
        let cfg = CustomMetadata {
            enabled: true,
            payload: Some(json!("not-an-object")),
            injection_target: None,
        };
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("JSON object")
        );
    }

    #[tokio::test]
    async fn non_json_body_returns_error_for_meta_target() {
        let body = Bytes::from(b"not json".to_vec());
        let cfg = metadata(Some(MetadataInjectionTarget::Meta));
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("parse MCP body")
        );
    }

    #[tokio::test]
    async fn non_object_body_root_returns_error_for_meta_target() {
        let body = Bytes::from(json!(["array", "not", "object"]).to_string());
        let cfg = metadata(Some(MetadataInjectionTarget::Meta));
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("root must be a JSON object")
        );
    }

    #[tokio::test]
    async fn non_object_meta_field_returns_error() {
        let body = Bytes::from(
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "_meta": "unexpected-string"
            })
            .to_string(),
        );
        let cfg = metadata(Some(MetadataInjectionTarget::Meta));
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("top-level _meta must be a JSON object")
        );
    }

    #[tokio::test]
    async fn header_target_errors_when_header_name_is_invalid() {
        let body = body_with_params();
        let cfg = CustomMetadata {
            enabled: true,
            payload: Some(json!({ "bad key": "value" })),
            injection_target: Some(MetadataInjectionTarget::Headers),
        };
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid MCP custom metadata header name")
        );
    }

    #[tokio::test]
    async fn header_target_errors_when_header_value_is_invalid() {
        let body = body_with_params();
        let cfg = CustomMetadata {
            enabled: true,
            payload: Some(json!({ "tenant": "bad\nvalue" })),
            injection_target: Some(MetadataInjectionTarget::Headers),
        };
        let result = inject_custom_metadata_mcp(
            &body,
            &cfg,
            "test-surface",
            &None,
            crate::protocols::MetadataRuntimeContext::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid MCP custom metadata header value")
        );
    }

    #[tokio::test]
    async fn modern_result_metadata_marks_the_result_private() {
        use crate::mcp::request_validation::{LegacySessionEvidence, McpVersionPolicy, validate_mcp_post};

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("mcp-method", "tools/list".parse().unwrap());
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        let classification = validate_mcp_post(
            &headers,
            request.to_string().as_bytes(),
            LegacySessionEvidence::Absent,
            McpVersionPolicy::new(&[crate::mcp::MCP_MODERN_VERSION], &[crate::mcp::MCP_MODERN_VERSION]),
        )
        .unwrap();
        let upstream = Bytes::from(
            json!({"jsonrpc": "2.0", "id": 1, "result": {
                "resultType": "complete", "tools": [], "ttlMs": 60000, "cacheScope": "public"
            }})
            .to_string(),
        );
        for (context, ttl, scope, cache_control) in [
            (McpMetadataContext::from_classification(&classification, None), 0, "private", Some("private, no-store")),
            (McpMetadataContext::legacy(None), 60000, "public", None),
        ] {
            let injected = inject_custom_metadata_with_context(
                &upstream,
                &metadata(Some(MetadataInjectionTarget::Meta)),
                "test",
                &None,
                crate::protocols::MetadataRuntimeContext::default(),
                context,
                McpMetaTarget::Result,
            )
            .await
            .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&injected.body).unwrap();
            assert_eq!(parsed["result"]["_meta"]["tenant"], "acme");
            assert_eq!(parsed["result"]["ttlMs"], ttl);
            assert_eq!(parsed["result"]["cacheScope"], scope);
            assert_eq!(
                injected
                    .extra_headers
                    .iter()
                    .find(|(name, _)| name == axum::http::header::CACHE_CONTROL)
                    .map(|(_, value)| value.to_str().unwrap()),
                cache_control
            );
        }
    }
}
