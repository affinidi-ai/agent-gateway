//! MCP message validation

use axum::body::Body;
use axum::http::{Response, StatusCode};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tracing::{debug, error, info};

use super::meta::{McpMetaTarget, McpMetadataContext};

/// Validate that a message is a valid JSON-RPC 2.0 request
pub fn validate_mcp_message(body: &JsonValue) -> Result<(), String> {
    // Check for jsonrpc field
    if body
        .get("jsonrpc")
        .and_then(|v| v.as_str())
        != Some("2.0")
    {
        return Err("Invalid or missing 'jsonrpc' field - must be '2.0'".to_string());
    }

    // Check for method field (required for requests, not for responses)
    if body.get("method").is_none() && body.get("result").is_none() && body.get("error").is_none() {
        return Err("Missing 'method' field in JSON-RPC request".to_string());
    }

    Ok(())
}

/// Check if this is an MCP notification (no id field)
pub fn is_notification(body: &JsonValue) -> bool {
    body.get("id").is_none()
}

/// Check if this is an MCP request (has id field)
#[allow(dead_code)]
pub fn is_request(body: &JsonValue) -> bool {
    body.get("id").is_some() && body.get("method").is_some()
}

/// Check if this is an MCP response (has id and result/error)
#[allow(dead_code)]
pub fn is_response(body: &JsonValue) -> bool {
    body.get("id").is_some() && (body.get("result").is_some() || body.get("error").is_some())
}

/// Validate MCP response for required identity fields
///
/// MCP responses use _meta.serverIdentity instead of A2A-style extensions arrays.
/// This function checks for the presence and validity of server identity in MCP responses.
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn validate_mcp_response(
    response_body: &[u8],
    channel_name: &str,
    surface: &crate::config::agent_surface::AgentSurface,
    response_rules_engine: &Option<Arc<crate::proxy::RulesEngine>>,
    metrics_store: &Option<Arc<crate::metrics::MetricsStore>>,
) -> Result<(), Response<Body>> {
    debug!(channel = channel_name, "Starting MCP response validation");

    // Try to parse response as JSON
    let response_json: JsonValue = match serde_json::from_slice(response_body) {
        Ok(json) => {
            debug!(channel = channel_name, "Successfully parsed MCP response as JSON");
            json
        }
        Err(e) => {
            debug!(channel = channel_name, error = %e, "MCP response is not JSON, skipping validation");
            return Ok(());
        }
    };

    // The `_meta` field name for server identity — taken from the surface's
    // protected identity slot when configured, otherwise falls back to "serverIdentity".
    let response_meta_field = surface
        .protected_identity()
        .and_then(|c| {
            if let crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) = c {
                Some(cfg.meta_field.as_str())
            } else {
                None
            }
        })
        .unwrap_or("serverIdentity");

    debug!(channel = channel_name, response_meta_field = response_meta_field, "Looking for MCP response identity");

    // Check if result._meta field exists (MCP spec places _meta inside result)
    if let Some(result) = response_json.get("result")
        && let Some(meta) = result.get("_meta")
    {
        // Check if the configured response_meta_field exists in _meta
        if let Some(server_identity) = meta.get(response_meta_field) {
            debug!(
                channel = channel_name,
                response_meta_field = response_meta_field,
                "Found response identity in _meta"
            );

            // Wrap the identity in an object with the field name to match the schema structure
            // Schema expects: { "serverIdentity": { ... } }
            // We extracted: { ... } from _meta.serverIdentity
            // So we need to re-wrap it for validation
            let wrapped_identity = serde_json::json!({
                response_meta_field: server_identity
            });

            // Validate against identity rules engine if configured
            if let Some(engine) = response_rules_engine {
                match engine.validate(&wrapped_identity, channel_name) {
                    Ok(()) => {
                        debug!(channel = channel_name, "✓ MCP response identity validation passed");
                        if let Some(metrics) = metrics_store {
                            metrics
                                .record_rule_validation(surface.surface_id.clone(), true)
                                .await;
                        }
                        Ok(())
                    }
                    Err(e) => {
                        error!(channel = channel_name, error = %e, "✗ MCP response identity validation failed");
                        if let Some(metrics) = metrics_store {
                            metrics
                                .record_rule_validation(surface.surface_id.clone(), false)
                                .await;
                        }
                        Err(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .header("content-type", "application/json")
                            .body(Body::from(format!(
                                r#"{{"error":"MCP response identity validation failed: {}"}}"#,
                                e
                            )))
                            .unwrap())
                    }
                }
            } else {
                // No validation engine configured, just check existence
                debug!(channel = channel_name, "No response validation engine configured, accepting MCP response");
                Ok(())
            }
        } else {
            debug!(
                channel = channel_name,
                response_meta_field = response_meta_field,
                "MCP _meta found but {} not present, enforcement disabled",
                response_meta_field
            );
            Ok(())
        }
    } else {
        debug!(channel = channel_name, "MCP response has no _meta field, enforcement disabled");
        Ok(())
    }
}

async fn inject_vp_into_mcp(
    message_bytes: &bytes::Bytes,
    agent_did: &str,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    workload_binding: Option<serde_json::Value>,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
    inbound_chained_vcs: Vec<serde_json::Value>,
    meta_field: &str,
    strip_raw_meta: bool,
    target: McpMetaTarget,
    context: McpMetadataContext,
) -> anyhow::Result<(bytes::Bytes, Option<String>)> {
    let mut message_json: JsonValue = serde_json::from_slice(message_bytes)?;
    super::meta::normalize_metadata(&mut message_json, context)?;
    if matches!(target, McpMetaTarget::Result) {
        if message_json
            .get("result")
            .and_then(JsonValue::as_object)
            .is_none()
        {
            anyhow::bail!("MCP response has no 'result' object for VP injection");
        }
        if !super::meta::permits_result_enrichment(&message_json) {
            return Ok((super::meta::normalize_bytes(message_bytes, context)?, None));
        }
    }
    super::meta::validate_raw_identity_key(meta_field, context)?;
    if strip_raw_meta {
        super::meta::remove_metadata_key(&mut message_json, meta_field);
    }
    super::meta::metadata_mut(&mut message_json, context, target)?;
    // Create VP containing the serverIdentity VC signed by the backend agent's
    // DID. When a workload_binding is supplied (from the channel's transit
    // config + authenticated caller) the VC uses structured `workloadBinding`
    // (agentIdentity + userIdentity), otherwise it falls back to the legacy
    // flat `identityFields` shape. Any VCs from the verified inbound
    // agentIdentity binding VP are flattened in so the receiver sees the
    // request-side provenance alongside the response-side serverIdentity.
    let chain_len = inbound_chained_vcs.len();
    let vp_jwt = vc_issuer
        .create_agent_identity_presentation_chained(
            agent_did,
            identity_fields,
            workload_binding,
            None,
            None,
            inbound_chained_vcs,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create identity presentation: {}", e))?;
    info!(
        channel = channel_name,
        did = agent_did,
        chained_vcs = chain_len,
        "Created identity credential VP for backend agent MCP message"
    );

    let extension_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    super::meta::insert_gateway_metadata(
        &mut message_json,
        context,
        target,
        extension_uri,
        serde_json::json!({
            "verifiablePresentation": vp_jwt,
            "did": agent_did,
        }),
    )?;

    info!(channel = channel_name, "Injected backend agent identity credential VP into MCP _meta field");

    // Serialize back to bytes
    let modified_json = serde_json::to_vec(&message_json)
        .map_err(|e| anyhow::anyhow!("Failed to serialize modified MCP message JSON: {}", e))?;

    Ok((bytes::Bytes::from(modified_json), Some(vp_jwt)))
}

/// Inject the backend agent identity credential VP into an MCP **response**
/// (`result._meta`, per the MCP spec).
pub async fn inject_vp_into_mcp_response(
    response_bytes: &bytes::Bytes,
    agent_did: &str,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    workload_binding: Option<serde_json::Value>,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
    inbound_chained_vcs: Vec<serde_json::Value>,
    meta_field: &str,
    strip_raw_meta: bool,
    context: McpMetadataContext,
) -> anyhow::Result<(bytes::Bytes, Option<String>)> {
    inject_vp_into_mcp(
        response_bytes,
        agent_did,
        identity_fields,
        workload_binding,
        vc_issuer,
        channel_name,
        inbound_chained_vcs,
        meta_field,
        strip_raw_meta,
        McpMetaTarget::Result,
        context,
    )
    .await
}

pub async fn inject_vp_into_mcp_request(
    request_bytes: &bytes::Bytes,
    agent_did: &str,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    workload_binding: Option<serde_json::Value>,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
    inbound_chained_vcs: Vec<serde_json::Value>,
    meta_field: &str,
    strip_raw_meta: bool,
    context: McpMetadataContext,
) -> anyhow::Result<(bytes::Bytes, Option<String>)> {
    inject_vp_into_mcp(
        request_bytes,
        agent_did,
        identity_fields,
        workload_binding,
        vc_issuer,
        channel_name,
        inbound_chained_vcs,
        meta_field,
        strip_raw_meta,
        McpMetaTarget::TopLevel,
        context,
    )
    .await
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn canonical_request_injection_preserves_metadata_and_proof() {
        let (issuer, _temporary, did) = issuer_with_did().await;
        let request = serde_json::json!({"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {
            "name": "echo", "arguments": {"data": [true, 1]}, "_meta": {"progressToken": 7, "traceparent": "unchanged"}
        }});
        let context = McpMetadataContext::legacy(Some(crate::config::McpLegacyMetadataOutput::Canonical));
        let (bytes, proof) = inject_vp_into_mcp_request(
            &bytes::Bytes::from(request.to_string()),
            &did,
            &identity_fields(),
            None,
            &issuer,
            "test",
            vec![],
            "agentIdentity",
            true,
            context,
        )
        .await
        .unwrap();
        let result: JsonValue = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["params"]["name"], request["params"]["name"]);
        assert_eq!(result["params"]["arguments"], request["params"]["arguments"]);
        assert_eq!(result["params"]["_meta"]["progressToken"], 7);
        assert_eq!(result["params"]["_meta"]["traceparent"], "unchanged");
        assert!(result.get("_meta").is_none());
        assert!(
            result["params"]["_meta"]
                .get(CREDENTIAL_EXT)
                .is_none()
        );
        assert_eq!(result["params"]["_meta"][crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY]["did"], did);
        assert_eq!(
            result["params"]["_meta"][crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY]["verifiablePresentation"],
            proof.unwrap()
        );
    }

    fn modern_context(request: &JsonValue) -> McpMetadataContext {
        use crate::mcp::request_validation::{
            LegacySessionEvidence, McpRequestClassification, McpVersionPolicy, validate_mcp_post,
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("mcp-method", "tools/call".parse().unwrap());
        headers.insert("mcp-name", "echo".parse().unwrap());
        let classification = validate_mcp_post(
            &headers,
            &serde_json::to_vec(request).unwrap(),
            LegacySessionEvidence::Absent,
            McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
            ),
        )
        .unwrap();
        assert!(matches!(classification, McpRequestClassification::Modern(_)));
        McpMetadataContext::from_classification(&classification, None)
    }

    fn modern_tools_call() -> JsonValue {
        serde_json::json!({"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {
            "name": "echo", "arguments": {"value": 1}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
                "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
            }
        }})
    }

    #[tokio::test]
    async fn modern_tools_call_injection_keeps_protocol_metadata() {
        let (issuer, _temporary, did) = issuer_with_did().await;
        let request = modern_tools_call();
        let (bytes, proof) = inject_vp_into_mcp_request(
            &bytes::Bytes::from(request.to_string()),
            &did,
            &identity_fields(),
            None,
            &issuer,
            "test",
            vec![],
            "agentIdentity",
            true,
            modern_context(&request),
        )
        .await
        .unwrap();
        let result: JsonValue = serde_json::from_slice(&bytes).unwrap();
        let meta = &result["params"]["_meta"];
        for key in
            ["io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientCapabilities", "traceparent"]
        {
            assert_eq!(meta[key], request["params"]["_meta"][key], "{key} survives injection");
        }
        assert_eq!(meta[crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY]["did"], did);
        assert_eq!(meta[crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY]["verifiablePresentation"], proof.unwrap());
        assert!(
            meta.get(CREDENTIAL_EXT)
                .is_none(),
            "no URL key on a modern request"
        );
        assert!(result.get("_meta").is_none(), "no top-level _meta on a modern request");
        assert_eq!(result["params"]["arguments"], request["params"]["arguments"]);
    }

    #[tokio::test]
    async fn complete_result_injection_keeps_its_result_type() {
        let (issuer, _temporary, did) = issuer_with_did().await;
        let response = serde_json::json!({"jsonrpc": "2.0", "id": 13, "result": {
            "resultType": "complete", "content": [{"type": "text", "text": "ok"}]
        }});
        let (bytes, proof) = inject_vp_into_mcp_response(
            &bytes::Bytes::from(response.to_string()),
            &did,
            &identity_fields(),
            None,
            &issuer,
            "test",
            vec![],
            "serverIdentity",
            false,
            modern_context(&modern_tools_call()),
        )
        .await
        .unwrap();
        assert!(proof.is_some(), "a complete result is enriched");
        let result: JsonValue = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["result"]["resultType"], "complete");
        assert_eq!(result["result"]["content"], response["result"]["content"]);
        assert!(
            result["result"]["_meta"]
                .as_object()
                .is_some_and(|meta| !meta.is_empty()),
            "identity lands in result._meta: {result}"
        );
        assert!(result.get("_meta").is_none());
    }

    #[tokio::test]
    async fn interim_results_do_not_mint_identity_proofs() {
        let (issuer, _temporary, _) = issuer_with_did().await;
        for kind in ["input_required", "task", "custom"] {
            let response = bytes::Bytes::from(serde_json::json!({"id": 1, "result": {
                "resultType": kind, "inputRequests": {"input": {"method": "roots/list"}}, "requestState": "opaque", "_meta": {"vendor": 3}
            }}).to_string());
            let (output, proof) = inject_vp_into_mcp_response(
                &response,
                "did:example:not-stored",
                &identity_fields(),
                None,
                &issuer,
                "test",
                vec![],
                "serverIdentity",
                false,
                McpMetadataContext::default(),
            )
            .await
            .unwrap();
            assert_eq!(output, response);
            assert!(proof.is_none());
        }
    }

    use super::*;
    use std::collections::HashMap;

    const CREDENTIAL_EXT: &str = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;

    fn identity_fields() -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert(
            "agentIdentity".to_string(),
            serde_json::json!({
                "llmInfo": { "provider": "anthropic", "model": "claude-3-5-sonnet" }
            }),
        );
        m
    }

    /// Build an issuer and mint a real agent DID so VP creation (which looks the
    /// DID up in the issuer's store) succeeds and the JSON-navigation logic under
    /// test is actually reached.
    async fn issuer_with_did() -> (Arc<crate::identity::VCIssuer>, tempfile::TempDir, String) {
        let (issuer, tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let did = issuer
            .issue_or_get_credential(identity_fields(), None, None, None)
            .await
            .expect("mint agent DID")
            .did;
        (Arc::new(issuer), tmp, did)
    }

    #[tokio::test]
    async fn request_injection_targets_top_level_meta_on_params_only_body() {
        let (issuer, _tmp, did) = issuer_with_did().await;

        // Outgoing MCP request: has `params`, no `result`.
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": { "name": "echo", "arguments": { "text": "hi" } }
        });
        let bytes = bytes::Bytes::from(serde_json::to_vec(&request).unwrap());

        let (signed, vp_jwt) = inject_vp_into_mcp_request(
            &bytes,
            &did,
            &identity_fields(),
            None,
            &issuer,
            "test-surface",
            Vec::new(),
            "agentIdentity",
            false,
            McpMetadataContext::default(),
        )
        .await
        .expect("request injection must succeed on a params-only body");

        assert!(vp_jwt.is_some_and(|jwt| !jwt.is_empty()), "a VP JWT must be produced");

        let out: JsonValue = serde_json::from_slice(&signed).unwrap();
        // Credential lands in the top-level `_meta`, not under `result`.
        let cred = out
            .get("_meta")
            .and_then(|m| m.get(CREDENTIAL_EXT))
            .expect("credential extension must be in top-level _meta");
        assert_eq!(
            cred.get("did")
                .and_then(|d| d.as_str()),
            Some(did.as_str())
        );
        assert!(
            cred.get("verifiablePresentation")
                .is_some()
        );
        assert!(out.get("result").is_none(), "no result object should be created on a request");
        // Existing request fields are preserved.
        assert_eq!(
            out.get("method")
                .and_then(|m| m.as_str()),
            Some("tools/call")
        );
        assert!(
            out.get("params")
                .and_then(|p| p.get("name"))
                .is_some()
        );
    }

    #[tokio::test]
    async fn response_injection_still_requires_result_object() {
        let (issuer, _tmp, did) = issuer_with_did().await;

        // A response without a `result` object (e.g. an error envelope).
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "error": { "code": -32000, "message": "boom" }
        });
        let bytes = bytes::Bytes::from(serde_json::to_vec(&response).unwrap());

        let err = inject_vp_into_mcp_response(
            &bytes,
            &did,
            &identity_fields(),
            None,
            &issuer,
            "test-surface",
            Vec::new(),
            "serverIdentity",
            false,
            McpMetadataContext::default(),
        )
        .await
        .expect_err("response injection must fail without a result object");
        assert!(
            err.to_string()
                .contains("no 'result' object"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn response_injection_targets_result_meta() {
        let (issuer, _tmp, did) = issuer_with_did().await;

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": { "content": [ { "type": "text", "text": "ok" } ] }
        });
        let bytes = bytes::Bytes::from(serde_json::to_vec(&response).unwrap());

        let (signed, _vp) = inject_vp_into_mcp_response(
            &bytes,
            &did,
            &identity_fields(),
            None,
            &issuer,
            "test-surface",
            Vec::new(),
            "serverIdentity",
            false,
            McpMetadataContext::default(),
        )
        .await
        .expect("response injection must succeed with a result object");

        let out: JsonValue = serde_json::from_slice(&signed).unwrap();
        let cred = out
            .get("result")
            .and_then(|r| r.get("_meta"))
            .and_then(|m| m.get(CREDENTIAL_EXT))
            .expect("credential extension must be in result._meta");
        assert_eq!(
            cred.get("did")
                .and_then(|d| d.as_str()),
            Some(did.as_str())
        );
        assert!(out.get("_meta").is_none(), "top-level _meta must not be created on a response");
    }
}
