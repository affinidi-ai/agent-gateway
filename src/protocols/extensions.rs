//! Protocol-agnostic extension inspection and utility functions
//!
//! This module contains functions that work across multiple messaging protocols
//! (A2A, MCP, UCP, ACP, etc.) for inspecting extensions, validating messages,
//! and resolving secret references.

use crate::{channel_debug, channel_error};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::config::GatewayConfig;

/// Context for extension inspection operations
///
/// Step 7 (extension inspection) is inspection/logging only — it does not
/// validate payloads against the identity rules engine.  Validation of
/// `agent-identity/v1` happens later in Step 12
/// (`resolve_protected_agent_identity`).
pub struct ExtensionInspectionContext<'a> {
    pub config: &'a GatewayConfig,
    pub channel_name: &'a str,
    pub surface: &'a crate::config::agent_surface::AgentSurface,
    pub rules_engine: &'a Option<Arc<crate::proxy::RulesEngine>>,
    /// Identity selector — used to compute agent identity (hash + DID) on the
    /// inbound request path when identity extraction is enabled.
    pub identity_selector: &'a Option<Arc<crate::identity::IdentitySelector>>,
    /// True only after configured source authentication has successfully resolved.
    pub source_authenticated: bool,
    pub metrics_store: &'a Option<Arc<crate::metrics::MetricsStore>>,
    pub ws_state: &'a Option<Arc<crate::server::WsState>>,
    /// Active surface variant alias. Threaded into payload-capture
    /// broadcasts so dashboard consumers can attribute traffic to the
    /// variant.
    pub variant_alias: Option<&'a str>,
}

/// Context for response extension inspection operations
pub struct ResponseExtensionInspectionContext<'a> {
    pub config: &'a GatewayConfig,
    pub channel_name: &'a str,
    pub surface: &'a crate::config::agent_surface::AgentSurface,
    pub response_rules_engine: &'a Option<Arc<crate::proxy::RulesEngine>>,
    pub metrics_store: &'a Option<Arc<crate::metrics::MetricsStore>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MetadataRuntimeContext<'a> {
    pub request_id: Option<&'a str>,
    pub surface_id: Option<&'a str>,
}

/// Recursively resolve custom-metadata value helpers in a JSON value.
///
/// Supported whole-string helpers:
/// * `$SECRET:secret_id` — resolved via the secrets store.
/// * `$TIMESTAMP` — UTC RFC3339 timestamp at injection time.
/// * `$REQUEST_ID` — request/trace id for this injection seam.
/// * `$SURFACE_ID` — Agent Surface config id.
pub fn resolve_metadata_references<'a>(
    value: &'a JsonValue,
    secrets_store: &'a Option<Arc<dyn crate::secrets::SecretsStore>>,
    channel_name: &'a str,
    runtime: MetadataRuntimeContext<'a>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<JsonValue>> + Send + 'a>> {
    Box::pin(async move {
        match value {
            JsonValue::String(s) => {
                if s.starts_with("$SECRET:") {
                    let secret_id_ref = s
                        .strip_prefix("$SECRET:")
                        .unwrap();

                    let store = secrets_store
                        .as_ref()
                        .ok_or_else(|| {
                            anyhow::anyhow!("Secret reference {} found but secrets store is not configured", s)
                        })?;

                    let secrets = store.list_all().await?;
                    let secret_uuid = secrets
                        .iter()
                        .find(|sec| sec.secret_id == secret_id_ref)
                        .map(|sec| sec.id.clone())
                        .ok_or_else(|| anyhow::anyhow!("Secret with secret_id '{}' not found", secret_id_ref))?;

                    let secret = store
                        .get(&secret_uuid)
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Secret with secret_id '{}' (UUID: {}) was deleted",
                                secret_id_ref,
                                secret_uuid
                            )
                        })?;

                    debug!(channel = channel_name, secret_id = secret_id_ref, "Resolved secret reference");

                    Ok(JsonValue::String(secret.value))
                } else if s == "$TIMESTAMP" {
                    Ok(JsonValue::String(chrono::Utc::now().to_rfc3339()))
                } else if s == "$REQUEST_ID" {
                    Ok(runtime
                        .request_id
                        .map(|v| JsonValue::String(v.to_string()))
                        .unwrap_or_else(|| value.clone()))
                } else if s == "$SURFACE_ID" {
                    Ok(runtime
                        .surface_id
                        .map(|v| JsonValue::String(v.to_string()))
                        .unwrap_or_else(|| value.clone()))
                } else {
                    Ok(value.clone())
                }
            }
            JsonValue::Array(arr) => {
                let mut resolved_arr = Vec::new();
                for item in arr {
                    resolved_arr.push(resolve_metadata_references(item, secrets_store, channel_name, runtime).await?);
                }
                Ok(JsonValue::Array(resolved_arr))
            }
            JsonValue::Object(obj) => {
                let mut resolved_obj = serde_json::Map::new();
                for (key, val) in obj {
                    resolved_obj.insert(
                        key.clone(),
                        resolve_metadata_references(val, secrets_store, channel_name, runtime).await?,
                    );
                }
                Ok(JsonValue::Object(resolved_obj))
            }
            _ => Ok(value.clone()),
        }
    })
}

/// Backwards-compatible resolver for callers that only need secret references.
#[allow(dead_code)]
pub fn resolve_secret_references<'a>(
    value: &'a JsonValue,
    secrets_store: &'a Option<Arc<dyn crate::secrets::SecretsStore>>,
    channel_name: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<JsonValue>> + Send + 'a>> {
    resolve_metadata_references(value, secrets_store, channel_name, MetadataRuntimeContext::default())
}

/// Inspect extensions in message body for multiple protocols (A2A, MCP, UCP, ACP, etc.)
/// Returns Ok(Some(IdentityResult)) if validation passes and agent identity is resolved (hash + DID),
/// Ok(None) if validation passes without identity,
/// or Err(Response) with error if validation fails
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn inspect_message_extensions(
    body_bytes: &[u8],
    ctx: &ExtensionInspectionContext<'_>,
) -> Result<Option<crate::identity::IdentityResult>, Response> {
    use crate::observability::broadcast_payload_capture_async;

    debug!(channel = ctx.channel_name, "Starting extension inspection");

    // Try to parse as JSON
    let body_json: JsonValue = match serde_json::from_slice::<JsonValue>(body_bytes) {
        Ok(json) => {
            debug!(channel = ctx.channel_name, "Successfully parsed body as JSON");
            // Log first 500 chars of JSON for debugging
            let json_str = serde_json::to_string(&json).unwrap_or_default();
            let preview = if json_str.len() > 500 {
                format!("{}...", &json_str[..500])
            } else {
                json_str.clone()
            };
            debug!(channel = ctx.channel_name, body_preview = %preview, "JSON body preview");

            json
        }
        Err(e) => {
            debug!(channel = ctx.channel_name, error = %e, "Body is not JSON, skipping inspection");
            // Still broadcast non-JSON payloads for capture
            if let Ok(text) = String::from_utf8(body_bytes.to_vec()) {
                let text_json = serde_json::json!({ "raw_text": text });
                let config_id = ctx
                    .surface
                    .config_id()
                    .unwrap_or("unknown");
                broadcast_payload_capture_async(
                    ctx.ws_state,
                    ctx.metrics_store,
                    ctx.channel_name,
                    config_id,
                    &text_json,
                    None,
                    "Non-JSON Body",
                    None,
                    None,
                    ctx.variant_alias,
                )
                .await;
            }
            return Ok(None);
        }
    };

    // Handle API Key authentication mode (applies to all protocols)
    // NOTE: API Key auth is now handled by SourceAuthMiddleware before reaching this function.

    // Handle mTLS authentication mode (applies to all protocols)
    // NOTE: mTLS auth is now handled by SourceAuthMiddleware before reaching this function.

    // Handle DID Auth authentication mode (applies to all protocols)
    // NOTE: DID Auth is now handled by SourceAuthMiddleware before reaching this function.

    // Check protocol type - handle MCP differently from A2A
    if ctx.surface.channel_protocol() == crate::config::ChannelProtocol::Mcp {
        let metadata = crate::mcp::meta::read_metadata(&body_json)
            .map_err(|error| error.into_response(body_bytes, StatusCode::BAD_REQUEST))?;
        let config_id = ctx
            .surface
            .config_id()
            .unwrap_or("unknown");
        channel_debug!(config_id, "MCP protocol detected, checking for identity extraction");

        // Log the channel config for debugging
        // Slot 1 (CA→AP request): prefer the dedicated inbound_identity slot,
        // fall back to the legacy `managed_identity` alias for unmigrated channels.
        let managed_identity = ctx
            .surface
            .inbound_identity()
            .cloned()
            .or_else(|| ctx.surface.managed_identity());
        channel_debug!(config_id, "MCP channel configuration inbound_identity={:?}", managed_identity,);

        // Determine the meta_field from managed_identity
        let managed_identity_meta_field = match &managed_identity {
            Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg)) => Some(cfg.meta_field.as_str()),
            _ => None,
        };
        let identity_enabled = managed_identity_meta_field.is_some();
        let meta_field_str = managed_identity_meta_field.unwrap_or("agentIdentity");

        if !identity_enabled {
            channel_debug!(config_id, "Identity extraction disabled");

            // Check if extension_rules are configured - this would be a configuration error
            if let Some(extension_rules) = ctx.surface.extension_rules()
                && (extension_rules
                    .json_schema
                    .is_some()
                    || !extension_rules
                        .rules
                        .is_empty())
            {
                let error_msg = format!(
                    "Configuration Error: Channel '{}' has extension_rules configured but identity extraction is disabled. \
                        Either enable identity extraction or remove extension_rules.",
                    ctx.channel_name
                );
                channel_error!(config_id, "Configuration mismatch detected");
                broadcast_payload_capture_async(
                    ctx.ws_state,
                    ctx.metrics_store,
                    ctx.channel_name,
                    config_id,
                    &body_json,
                    None,
                    "Failed Validation",
                    Some(error_msg.clone()),
                    None,
                    ctx.variant_alias,
                )
                .await;
                return Err(crate::a2a::errors::create_error_response(StatusCode::FORBIDDEN, &error_msg));
            }

            // Inspect _meta if present — purely for observability/capture.
            // managed_identity is a response-path config (Step 12) and does not
            // gate inbound request acceptance.
            if metadata.is_some() {
                debug!(channel = ctx.channel_name, "_meta field found in MCP request (inspection only)");
                broadcast_payload_capture_async(
                    ctx.ws_state,
                    ctx.metrics_store,
                    ctx.channel_name,
                    config_id,
                    &body_json,
                    None,
                    "MCP Inspection",
                    None,
                    None,
                    ctx.variant_alias,
                )
                .await;
            } else {
                debug!(channel = ctx.channel_name, "No _meta field in MCP request body");
                broadcast_payload_capture_async(
                    ctx.ws_state,
                    ctx.metrics_store,
                    ctx.channel_name,
                    config_id,
                    &body_json,
                    None,
                    "MCP No Meta",
                    None,
                    None,
                    ctx.variant_alias,
                )
                .await;
            }
            return Ok(None);
        }

        let meta_field = meta_field_str;
        info!(channel = ctx.channel_name, meta_field = %meta_field, "Identity extraction enabled, looking for identity in _meta field");

        let meta = metadata.as_ref();
        if let Some(meta) = meta {
            info!(channel = ctx.channel_name, meta_field = %meta_field, "_meta field found in request");
            if let Some(agent_identity) = meta.get(crate::mcp::meta::canonical_key(meta_field)) {
                info!(channel = ctx.channel_name, meta_field = %meta_field, "Found identity in MCP request");

                // Wrap the identity in an object with the field name to match the schema structure
                // Schema expects: { "agentIdentity": { ... } }
                // We extracted: { ... } from _meta.agentIdentity
                // So we need to re-wrap it
                let wrapped_identity = serde_json::json!({
                    meta_field: agent_identity
                });

                // Validate against rules engine if configured
                if let Some(engine) = ctx.rules_engine {
                    match engine.validate(&wrapped_identity, ctx.channel_name) {
                        Ok(()) => {
                            info!(channel = ctx.channel_name, "✓ MCP identity validation passed");
                            if let Some(metrics) = ctx.metrics_store {
                                let channel_config_id = ctx.surface.config_id_string();
                                metrics
                                    .record_rule_validation(channel_config_id, true)
                                    .await;
                            }
                        }
                        Err(e) => {
                            error!(channel = ctx.channel_name, error = %e, "✗ MCP identity validation failed");
                            if let Some(metrics) = ctx.metrics_store {
                                metrics
                                    .record_rule_validation(ctx.channel_name.to_string(), false)
                                    .await;
                            }
                            // For MCP, if managed_identity is set we always require the identity
                            let error_msg = format!("MCP identity validation failed: {}", e);
                            let config_id = ctx
                                .surface
                                .config_id()
                                .unwrap_or("unknown");
                            broadcast_payload_capture_async(
                                ctx.ws_state,
                                ctx.metrics_store,
                                ctx.channel_name,
                                config_id,
                                &body_json,
                                None,
                                "Failed Validation",
                                Some(error_msg.clone()),
                                None,
                                ctx.variant_alias,
                            )
                            .await;
                            return Err(crate::a2a::errors::create_error_response(StatusCode::FORBIDDEN, &error_msg));
                        }
                    }
                } else {
                    // No rules engine configured but identity was found - log warning
                    warn!(channel = ctx.channel_name, meta_field = %meta_field, "Identity extraction enabled but no rules engine configured for validation");
                }

                // Extension validation passed — compute agent identity (hash + DID) from the
                // validated payload so it is available BEFORE credential delegation.
                //
                // When the schema declares no `x-identity` fields, schema validation
                // still runs (so malformed payloads are rejected) but DID computation
                // is skipped — the flatten-based fallback on the response path will
                // produce the identity fields instead.
                if let Some(selector) = ctx.identity_selector.as_ref()
                    && !selector.has_identity_fields()
                {
                    if let Err(e) = selector.validate(&wrapped_identity) {
                        error!(channel = ctx.channel_name, error = %e, "✗ MCP inbound identity schema validation failed");
                        let error_msg = format!("Inbound identity validation failed: {}", e);
                        let config_id = ctx
                            .surface
                            .config_id()
                            .unwrap_or("unknown");
                        broadcast_payload_capture_async(
                            ctx.ws_state,
                            ctx.metrics_store,
                            ctx.channel_name,
                            config_id,
                            &body_json,
                            None,
                            "Failed Validation",
                            Some(error_msg.clone()),
                            None,
                            ctx.variant_alias,
                        )
                        .await;
                        return Err(crate::a2a::create_identity_error_response(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            crate::a2a::errors::ERR_IDENTITY_VALIDATION_FAILED,
                            "inbound_identity",
                            ctx.channel_name,
                            &error_msg,
                        ));
                    }
                    info!(
                        channel = ctx.channel_name,
                        "✓ MCP inbound identity schema validation passed (no x-identity fields, skipping DID)"
                    );
                }

                if let Some(selector) = ctx.identity_selector.as_ref()
                    && selector.has_identity_fields()
                {
                    let config_id = ctx
                        .surface
                        .config_id()
                        .map(|s| s.to_string());
                    let issuer_id = ctx.surface.issuer_id.clone();
                    match selector
                        .compute_identity(&wrapped_identity, ctx.channel_name, config_id, issuer_id)
                        .await
                    {
                        Ok(result) => {
                            info!(channel = ctx.channel_name, did = %result.did, hash = %result.hash, "✓ MCP agent identity resolved on request path");
                            let config_id = ctx
                                .surface
                                .config_id()
                                .unwrap_or("unknown");
                            broadcast_payload_capture_async(
                                ctx.ws_state,
                                ctx.metrics_store,
                                ctx.channel_name,
                                config_id,
                                &body_json,
                                None,
                                "success",
                                None,
                                Some(result.hash.clone()),
                                ctx.variant_alias,
                            )
                            .await;
                            return Ok(Some(result));
                        }
                        Err(e) => {
                            error!(channel = ctx.channel_name, error = %e, "✗ MCP agent identity computation failed (schema or x-identity field violation)");
                            let error_msg = format!("Inbound identity validation failed: {}", e);
                            let config_id = ctx
                                .surface
                                .config_id()
                                .unwrap_or("unknown");
                            broadcast_payload_capture_async(
                                ctx.ws_state,
                                ctx.metrics_store,
                                ctx.channel_name,
                                config_id,
                                &body_json,
                                None,
                                "Failed Validation",
                                Some(error_msg.clone()),
                                None,
                                ctx.variant_alias,
                            )
                            .await;
                            return Err(crate::a2a::create_identity_error_response(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                crate::a2a::errors::ERR_IDENTITY_VALIDATION_FAILED,
                                "inbound_identity",
                                ctx.channel_name,
                                &error_msg,
                            ));
                        }
                    }
                }

                info!(channel = ctx.channel_name, "✓ MCP extension validation passed (no identity selector)");
                let config_id = ctx
                    .surface
                    .config_id()
                    .unwrap_or("unknown");
                broadcast_payload_capture_async(
                    ctx.ws_state,
                    ctx.metrics_store,
                    ctx.channel_name,
                    config_id,
                    &body_json,
                    None,
                    "success",
                    None,
                    None,
                    ctx.variant_alias,
                )
                .await;
                return Ok(None);
            } else {
                warn!(channel = ctx.channel_name, meta_field = %meta_field, "_meta found but identity field missing");
            }
        } else {
            debug!(channel = ctx.channel_name, "No _meta field in MCP request body");
            broadcast_payload_capture_async(
                ctx.ws_state,
                ctx.metrics_store,
                ctx.channel_name,
                config_id,
                &body_json,
                None,
                "MCP No Meta",
                None,
                None,
                ctx.variant_alias,
            )
            .await;
        }

        // Slot 1 (`inbound_identity`) is configured with `payload_extraction`
        // ⇒ the caller identity must be carried in the request body. If we got
        // here the request either lacked `_meta` entirely or its `_meta` did
        // not contain the configured `meta_field`. Reject with 422 so
        // misbehaving callers fail loudly instead of silently passing through.
        // Credential-derived modes (`from_jwt_claim`, `from_api_key`, …) source
        // the identity from the validated credential, not the body, so they do
        // NOT require an inbound extension here. The legacy `managed_identity`
        // field is overloaded as a response-path config in many surfaces, so
        // only the explicit slot triggers enforcement.
        if ctx
            .surface
            .inbound_identity_requires_payload()
        {
            let error_msg = format!("Inbound identity required: missing `{}` in MCP `_meta`", meta_field);
            error!(channel = ctx.channel_name, "✗ {}", error_msg);
            broadcast_payload_capture_async(
                ctx.ws_state,
                ctx.metrics_store,
                ctx.channel_name,
                config_id,
                &body_json,
                None,
                "Failed Validation",
                Some(error_msg.clone()),
                None,
                ctx.variant_alias,
            )
            .await;
            return Err(crate::a2a::create_identity_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                crate::a2a::errors::ERR_IDENTITY_VALIDATION_FAILED,
                "inbound_identity",
                ctx.channel_name,
                &error_msg,
            ));
        }

        // Legacy `managed_identity`-only surfaces (no slot 1) keep the prior
        // pass-through semantics — `managed_identity` governs the response
        // path; the inbound request is not required to carry identity.
        info!(
            channel = ctx.channel_name,
            "MCP inbound request has no extractable identity \
             (legacy managed_identity, no inbound_identity slot) — passing through"
        );
        return Ok(None);
    }

    // A2A protocol handling follows below
    let payload_identity_config = ctx
        .surface
        .inbound_identity()
        .and_then(|identity| match identity {
            crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => Some(cfg),
            _ => None,
        });
    let identity_extension_uri = payload_identity_config
        .map(crate::source_auth::models::PayloadExtractionConfig::identity_extension_uri)
        .unwrap_or(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION);
    let identity_required = ctx
        .surface
        .inbound_identity_requires_payload();
    let identity_uses_non_default_extension =
        identity_extension_uri != crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
    if identity_required && identity_uses_non_default_extension && !ctx.source_authenticated {
        let error_msg = format!(
            "Inbound identity from extension '{}' requires configured source authentication to resolve first",
            identity_extension_uri
        );
        error!(channel = ctx.channel_name, "✗ {}", error_msg);
        let config_id = ctx
            .surface
            .config_id()
            .unwrap_or("unknown");
        broadcast_payload_capture_async(
            ctx.ws_state,
            ctx.metrics_store,
            ctx.channel_name,
            config_id,
            &body_json,
            None,
            "Failed Validation",
            Some(error_msg.clone()),
            None,
            ctx.variant_alias,
        )
        .await;
        return Err(crate::a2a::create_identity_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            crate::a2a::errors::ERR_IDENTITY_VALIDATION_FAILED,
            "inbound_identity",
            ctx.channel_name,
            &error_msg,
        ));
    }

    // Navigate to message.extensions array
    // For JSON-RPC, check params.message.extensions first, then fall back to message.extensions
    let extensions_array = body_json
        .get("params")
        .and_then(|params| params.get("message"))
        .and_then(|msg| msg.get("extensions"))
        .and_then(|ext| ext.as_array())
        .or_else(|| {
            body_json
                .get("message")
                .and_then(|msg| msg.get("extensions"))
                .and_then(|ext| ext.as_array())
        });

    // Track resolved identity — computed on the inbound request path when
    // identity extraction is enabled and identity_selector is available.
    let mut identity_result: Option<crate::identity::IdentityResult> = None;

    let extensions_array = match extensions_array {
        Some(arr) => {
            debug!(channel = ctx.channel_name, count = arr.len(), "Found extensions array");
            arr
        }
        None => {
            debug!(channel = ctx.channel_name, "No extensions array found in message or params.message");
            // Slot 1 (inbound_identity) governs caller identity extraction
            // from the request body, but only in `payload_extraction` mode.
            // When that mode is configured, an inbound request without an
            // extensions array cannot satisfy it — reject with 422 so
            // misbehaving callers fail loudly. Credential-derived modes
            // (`from_jwt_claim`, `from_api_key`, …) derive the identity from
            // the validated credential, not the body, so they pass through
            // here. The legacy `managed_identity` field is overloaded as a
            // response-path config in many surfaces (see `build_identity_channel`
            // in component tests), so it does NOT trigger inbound enforcement.
            let config_id = ctx
                .surface
                .config_id()
                .unwrap_or("unknown");
            if identity_required {
                let error_msg = format!(
                    "Inbound identity required: A2A request has no `extensions` array carrying `{}`",
                    identity_extension_uri
                );
                error!(channel = ctx.channel_name, "✗ {}", error_msg);
                broadcast_payload_capture_async(
                    ctx.ws_state,
                    ctx.metrics_store,
                    ctx.channel_name,
                    config_id,
                    &body_json,
                    None,
                    "Failed Validation",
                    Some(error_msg.clone()),
                    None,
                    ctx.variant_alias,
                )
                .await;
                return Err(crate::a2a::create_identity_error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    crate::a2a::errors::ERR_IDENTITY_VALIDATION_FAILED,
                    "inbound_identity",
                    ctx.channel_name,
                    &error_msg,
                ));
            }
            // No extensions and identity not required — broadcast for capture and pass through.
            broadcast_payload_capture_async(
                ctx.ws_state,
                ctx.metrics_store,
                ctx.channel_name,
                config_id,
                &body_json,
                None,
                "No Extensions",
                None,
                None,
                ctx.variant_alias,
            )
            .await;
            return Ok(None);
        }
    };

    // Get metadata object (try params.message.metadata first, then message.metadata)
    let metadata = body_json
        .get("params")
        .and_then(|params| params.get("message"))
        .and_then(|msg| msg.get("metadata"))
        .or_else(|| {
            body_json
                .get("message")
                .and_then(|msg| msg.get("metadata"))
        });

    // Check for watched extensions
    debug!(
        channel = ctx.channel_name,
        watch_list = ?ctx.config.extension_inspection.watch_extensions,
        "Checking for watched extensions"
    );

    let mut found_identity_extension = false;
    // Once a presented VP has been rejected, no identity is computed from the
    // other extensions of this request, whatever order they arrive in.
    let mut presentation_rejected = false;

    for extension in extensions_array {
        if let Some(extension_uri) = extension.as_str() {
            debug!(channel = ctx.channel_name, extension = extension_uri, "Checking extension");

            if ctx
                .config
                .extension_inspection
                .watch_extensions
                .contains(&extension_uri.to_string())
            {
                info!(channel = ctx.channel_name, extension = extension_uri, "🎯 A2A Extension Detected");

                // Extension detected, no need to print the details
                if let Some(meta) = metadata {
                    if meta
                        .get(extension_uri)
                        .is_none()
                    {
                        debug!(
                            channel = ctx.channel_name,
                            extension = extension_uri,
                            "No metadata found for extension"
                        );
                    }
                } else {
                    debug!(channel = ctx.channel_name, "No metadata object found in message");
                }
            }

            // Identity enforcement: always runs regardless of watch_extensions.
            // Accept the configured raw identity extension. Existing surfaces using
            // the default Affinidi identity URI also continue accepting the signed VP
            // credential extension from an upstream gateway.
            let is_configured_identity_ext = extension_uri == identity_extension_uri;
            let is_credential_ext = identity_extension_uri == crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION
                && extension_uri == crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
            if (is_configured_identity_ext || is_credential_ext)
                && let Some(meta) = metadata
                && let Some(extension_payload) = meta.get(extension_uri)
            {
                found_identity_extension = true;

                // Validate extension payload against rules engine if configured
                if let Some(engine) = ctx.rules_engine {
                    match engine.validate(extension_payload, ctx.channel_name) {
                        Ok(()) => {
                            info!(
                                channel = ctx.channel_name,
                                extension = extension_uri,
                                "✓ Extension validation passed"
                            );
                            if let Some(metrics) = ctx.metrics_store {
                                let channel_config_id = ctx.surface.config_id_string();
                                metrics
                                    .record_rule_validation(channel_config_id, true)
                                    .await;
                            }
                        }
                        Err(e) => {
                            error!(
                                channel = ctx.channel_name,
                                extension = extension_uri,
                                error = %e,
                                "✗ Extension validation failed"
                            );
                            if let Some(metrics) = ctx.metrics_store {
                                metrics
                                    .record_rule_validation(ctx.channel_name.to_string(), false)
                                    .await;
                            }
                            let error_msg = format!("Extension validation failed: {}", e);
                            let config_id = ctx
                                .surface
                                .config_id()
                                .unwrap_or("unknown");
                            broadcast_payload_capture_async(
                                ctx.ws_state,
                                ctx.metrics_store,
                                ctx.channel_name,
                                config_id,
                                &body_json,
                                None,
                                "Failed Validation",
                                Some(error_msg.clone()),
                                identity_result
                                    .as_ref()
                                    .map(|r| r.hash.clone()),
                                ctx.variant_alias,
                            )
                            .await;
                            return Err(crate::a2a::errors::create_error_response(StatusCode::FORBIDDEN, &error_msg));
                        }
                    }
                }

                // A signed VP credential (`agent-identity-credential/v1`) from an
                // upstream hop carries a `verifiablePresentation` / `did`, not the
                // origin agent's raw x-identity fields. Verify the presentation and
                // derive the caller DID from it, instead of running the payload
                // x-identity schema (which would fail on the absent x-identity fields).
                let is_credential_ext = extension_uri == crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
                if is_credential_ext {
                    match resolve_inbound_credential_identity(
                        extension_payload,
                        ctx.identity_selector,
                        ctx.channel_name,
                    )
                    .await
                    {
                        CredentialResolution::Verified(result) => identity_result = Some(result),
                        CredentialResolution::Rejected => {
                            presentation_rejected = true;
                            identity_result = None;
                        }
                        CredentialResolution::Absent => {}
                    }
                }

                // Extension validation passed — compute agent identity from the validated
                // payload so it is available before credential delegation.
                //
                // When the schema declares no `x-identity` fields, schema validation still
                // runs (so malformed payloads are rejected) but DID computation is skipped —
                // the flatten-based fallback on the response path will produce the identity
                // fields instead.
                //
                // Both blocks below are additionally gated on an **inbound identity** element
                // actually being configured (`payload_identity_config.is_some()`). Without
                // this gate, a surface that configures ONLY a protected (MA→AP) Server
                // Identity — and no inbound (CA→AP) identity — would still validate a
                // caller-supplied `agent-identity/v1` extension against the protected
                // schema. That happens because `ctx.identity_selector` is compiled from the
                // first available slot (`compile_identity_engines_from_surface` falls back
                // inbound → protected → external), so it carries the protected schema when
                // no inbound slot exists. The caller must not be judged against the MA→AP
                // schema when there is no identity element on the CA→AP leg, so we skip
                // inbound validation entirely and let the extension pass through.
                if let Some(selector) = ctx.identity_selector.as_ref()
                    && payload_identity_config.is_some()
                    && !selector.has_identity_fields()
                    && !is_credential_ext
                {
                    if let Err(e) = selector.validate(extension_payload) {
                        error!(
                            channel = ctx.channel_name,
                            extension = extension_uri,
                            error = %e,
                            "✗ A2A inbound identity schema validation failed"
                        );
                        let error_msg = format!("Inbound identity validation failed: {}", e);
                        let config_id = ctx
                            .surface
                            .config_id()
                            .unwrap_or("unknown");
                        broadcast_payload_capture_async(
                            ctx.ws_state,
                            ctx.metrics_store,
                            ctx.channel_name,
                            config_id,
                            &body_json,
                            None,
                            "Failed Validation",
                            Some(error_msg.clone()),
                            None,
                            ctx.variant_alias,
                        )
                        .await;
                        return Err(crate::a2a::create_identity_error_response(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            crate::a2a::errors::ERR_IDENTITY_VALIDATION_FAILED,
                            "inbound_identity",
                            ctx.channel_name,
                            &error_msg,
                        ));
                    }
                    info!(
                        channel = ctx.channel_name,
                        extension = extension_uri,
                        "✓ A2A inbound identity schema validation passed (no x-identity fields, skipping DID)"
                    );
                }

                if let Some(selector) = ctx.identity_selector.as_ref()
                    && payload_identity_config.is_some()
                    && selector.has_identity_fields()
                    && !is_credential_ext
                    && !presentation_rejected
                {
                    let config_id = ctx
                        .surface
                        .config_id()
                        .map(|s| s.to_string());
                    let issuer_id = ctx.surface.issuer_id.clone();
                    match selector
                        .compute_identity(extension_payload, ctx.channel_name, config_id, issuer_id)
                        .await
                    {
                        Ok(result) => {
                            info!(
                                channel = ctx.channel_name,
                                did = %result.did,
                                hash = %result.hash,
                                extension = extension_uri,
                                "✓ A2A agent identity resolved on request path"
                            );
                            identity_result = Some(result);
                        }
                        Err(e) => {
                            error!(
                                channel = ctx.channel_name,
                                extension = extension_uri,
                                error = %e,
                                "✗ A2A agent identity computation failed (schema or x-identity field violation)"
                            );
                            let error_msg = format!("Inbound identity validation failed: {}", e);
                            let config_id = ctx
                                .surface
                                .config_id()
                                .unwrap_or("unknown");
                            broadcast_payload_capture_async(
                                ctx.ws_state,
                                ctx.metrics_store,
                                ctx.channel_name,
                                config_id,
                                &body_json,
                                None,
                                "Failed Validation",
                                Some(error_msg.clone()),
                                None,
                                ctx.variant_alias,
                            )
                            .await;
                            return Err(crate::a2a::create_identity_error_response(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                crate::a2a::errors::ERR_IDENTITY_VALIDATION_FAILED,
                                "inbound_identity",
                                ctx.channel_name,
                                &error_msg,
                            ));
                        }
                    }
                } else if ctx
                    .identity_selector
                    .is_none()
                {
                    debug!(
                        channel = ctx.channel_name,
                        extension = extension_uri,
                        "Extension validation passed (no identity selector available)"
                    );
                }
            }
        }
    }

    // After checking all extensions, if slot 1 (inbound_identity) is
    // configured with `payload_extraction` and the Affinidi extension wasn't
    // found, reject. Credential-derived modes derive identity from the
    // validated credential, not the body, so they do not require the
    // extension. The legacy `managed_identity` field is overloaded as a
    // response-path config (see component tests' `build_identity_channel`)
    // and does NOT imply inbound enforcement.
    if identity_required && !found_identity_extension {
        error!(
            channel = ctx.channel_name,
            "Identity extraction enabled but required extension '{}' not found", identity_extension_uri
        );
        if let Some(metrics) = ctx.metrics_store {
            let channel_config_id = ctx.surface.config_id_string();
            metrics
                .record_rule_validation(channel_config_id, false)
                .await;
        }
        // Missing required extension
        let error_msg =
            format!("Inbound identity required: extension '{}' not present in A2A request", identity_extension_uri);
        let config_id = ctx
            .surface
            .config_id()
            .unwrap_or("unknown");
        broadcast_payload_capture_async(
            ctx.ws_state,
            ctx.metrics_store,
            ctx.channel_name,
            config_id,
            &body_json,
            None,
            "Failed Validation",
            Some(error_msg.clone()),
            identity_result
                .as_ref()
                .map(|r| r.hash.clone()),
            ctx.variant_alias,
        )
        .await;
        return Err(crate::a2a::create_identity_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            crate::a2a::errors::ERR_IDENTITY_VALIDATION_FAILED,
            "inbound_identity",
            ctx.channel_name,
            &error_msg,
        ));
    }

    // All validations passed
    Ok(identity_result)
}

/// Outcome of resolving the caller identity from a signed
/// `agent-identity-credential/v1` (VP) extension.
#[derive(Debug)]
enum CredentialResolution {
    /// The presentation verified; its holder is the caller.
    Verified(crate::identity::IdentityResult),
    /// A presentation was present and was not accepted: it failed
    /// verification, or no verifier is available. No payload-derived identity
    /// may be computed for this request.
    Rejected,
    /// The extension carries no presentation.
    Absent,
}

/// Resolve the caller identity from a signed `agent-identity-credential/v1`
/// (VP) extension carried by an upstream hop.
///
/// Unlike the raw `agent-identity/v1` extension — whose payload is the origin
/// agent's `x-identity` fields — the credential extension carries a
/// `verifiablePresentation` JWT (and a `did` claim). Only a presentation that
/// verifies yields an identity; the `did` claim is never used on its own.
/// There is no authenticated sender on this path, so nothing vouches for the
/// issuer: the identity is reported as `vp_unanchored`.
async fn resolve_inbound_credential_identity(
    credential_ext: &JsonValue,
    identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    channel_name: &str,
) -> CredentialResolution {
    let Some(vp_jwt) = credential_ext
        .get("verifiablePresentation")
        .and_then(|v| v.as_str())
    else {
        return CredentialResolution::Absent;
    };
    let Some(selector) = identity_selector.as_ref() else {
        warn!(
            channel = channel_name,
            "A2A inbound VP credential present but no identity selector/VC issuer available to verify it; request carries no caller identity"
        );
        return CredentialResolution::Rejected;
    };
    match selector
        .get_vc_issuer()
        .verify_agent_presentation_full(vp_jwt)
        .await
    {
        Ok(verified) => {
            let did = verified.holder_did;
            let identity_fields = verified.identity_fields;
            let hash = crate::identity::compute_canonical_identity_hash(&identity_fields);
            info!(
                channel = channel_name,
                did = %did,
                issuer = ?verified.issuer_did,
                "✓ A2A inbound VP credential verified (issuer unanchored on the direct path)"
            );
            CredentialResolution::Verified(crate::identity::IdentityResult {
                hash,
                did,
                is_new: false,
                verification: crate::surface_context::IdentityVerification::VpUnanchored,
                identity_fields,
                issuer_did: verified.issuer_did,
            })
        }
        Err(e) => {
            warn!(
                channel = channel_name,
                error = %e,
                "✗ A2A inbound VP verification failed; request carries no caller identity"
            );
            CredentialResolution::Rejected
        }
    }
}

/// Outcome of issuer trust evaluation for a signature-verified binding VP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingIssuerDecision {
    /// Issuer is vouched for by the sending connection's issuers (its attested
    /// issuer DID plus the issuer DIDs an operator trusts for that connection).
    Trusted,
    /// No trust anchor exists at all (direct path: no authenticated sending
    /// gateway and no configured issuers), so nothing vouches for the issuer.
    /// The binding is surfaced to OPA with `verified: false`, never as trusted.
    Unanchored,
    /// A trust anchor exists and the issuer is not one of that connection's
    /// issuers → hard reject.
    Reject,
}

/// Evaluate issuer trust for an inbound Workload Binding VP. On the fabric
/// receive path the anchor is the sending connection's issuers (its attested
/// issuer DID plus the issuer DIDs an operator trusts for that connection)
/// and the primary VC issuer must be one of them. On the direct path there is
/// no authenticated sender, so there is no anchor: the issuer is reported as
/// unanchored and exposed to OPA as unverified, never as trusted.
pub(crate) fn evaluate_binding_issuer_trust(
    issuer: &str,
    issuer_anchor: Option<&crate::gateways::types::PeerIssuers>,
) -> BindingIssuerDecision {
    match issuer_anchor {
        Some(anchor) if anchor.accepts(issuer) => BindingIssuerDecision::Trusted,
        Some(_) => BindingIssuerDecision::Reject,
        None => BindingIssuerDecision::Unanchored,
    }
}

/// Extract and verify an identity binding VP from an inbound request.
///
/// Returns `Some(IdentityBindingContext)` if a binding VP was found and verified,
/// `None` if no binding VP is present.
/// Returns `Err` if a binding VP is present but verification fails.
/// Extract the raw identity-binding VP string from an inbound request body
/// **without verifying it**. Returns the `verifiablePresentation` from the
/// `agent-identity-binding/v1` extension (preferred) or the
/// `agent-identity-credential/v1` extension, for the given protocol. Used to
/// attach the received presentation to audit events on the fabric-receive path;
/// signature/issuer verification is done separately by
/// [`extract_identity_binding_vp`].
pub fn extract_identity_binding_vp_jwt(
    body_bytes: &[u8],
    protocol: &crate::config::ChannelProtocol,
) -> Option<String> {
    let body_json: JsonValue = serde_json::from_slice(body_bytes).ok()?;

    // The workload binding is embedded in the agent-identity-credential VP —
    // the Workload Binding feature reuses that VP ("no second VP"). A dedicated
    // agent-identity-binding VP may also be present. Check the binding
    // extension first, then fall back to the credential extension.
    let binding_uri = crate::config::AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION;
    let credential_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;

    let vp_jwt = match protocol {
        crate::config::ChannelProtocol::Mcp => {
            let meta = crate::mcp::meta::read_metadata(&body_json).ok()??;
            return meta
                .get(crate::config::MCP_AGENT_IDENTITY_BINDING_KEY)
                .or_else(|| meta.get(crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY))
                .and_then(|extension| extension.get("verifiablePresentation"))
                .and_then(JsonValue::as_str)
                .map(String::from);
        }
        crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2 => {
            // Check message.metadata or params.message.metadata
            let message = body_json
                .get("params")
                .and_then(|p| p.get("message"))
                .or_else(|| body_json.get("message"));
            message
                .and_then(|m| m.get("metadata"))
                .and_then(|meta| {
                    meta.get(binding_uri)
                        .or_else(|| meta.get(credential_uri))
                })
                .and_then(|ext| ext.get("verifiablePresentation"))
                .and_then(|v| v.as_str())
        }
        _ => None,
    };

    vp_jwt.map(String::from)
}

pub async fn extract_identity_binding_vp(
    body_bytes: &[u8],
    protocol: &crate::config::ChannelProtocol,
    identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    channel_name: &str,
    issuer_anchor: Option<&crate::gateways::types::PeerIssuers>,
) -> Result<Option<crate::surface_context::IdentityBindingContext>, String> {
    if *protocol == crate::config::ChannelProtocol::Mcp {
        let Ok(body) = serde_json::from_slice::<JsonValue>(body_bytes) else { return Ok(None) };
        let Some(metadata) = crate::mcp::meta::read_metadata(&body).map_err(|error| error.to_string())? else {
            return Ok(None);
        };
        let mut primary = None;
        for key in [crate::config::MCP_AGENT_IDENTITY_BINDING_KEY, crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY] {
            let Some(extension) = metadata.get(key) else { continue };
            let vp_jwt = extension
                .get("verifiablePresentation")
                .and_then(JsonValue::as_str)
                .filter(|jwt| !jwt.is_empty())
                .ok_or_else(|| format!("MCP identity extension '{key}' requires a presentation"))?;
            let claimed_did = extension
                .get("did")
                .map(|did| {
                    did.as_str()
                        .filter(|did| !did.is_empty())
                        .ok_or_else(|| format!("MCP identity extension '{key}' has an invalid DID"))
                })
                .transpose()?;
            let verified = verify_identity_binding_presentation(
                vp_jwt,
                claimed_did,
                identity_selector,
                channel_name,
                issuer_anchor,
            )
            .await?;
            if primary.is_none() {
                primary = verified;
            }
        }
        return Ok(primary);
    }
    let Some(vp_jwt) = extract_identity_binding_vp_jwt(body_bytes, protocol) else {
        return Ok(None);
    };
    verify_identity_binding_presentation(&vp_jwt, None, identity_selector, channel_name, issuer_anchor).await
}

pub async fn verify_mcp_metadata_identity(
    body: &[u8],
    issuer: Option<&Arc<crate::identity::VCIssuer>>,
    surface_id: &str,
    issuer_anchor: Option<&crate::gateways::types::PeerIssuers>,
) -> Result<Option<crate::surface_context::IdentityBindingContext>, String> {
    let selector = issuer
        .map(|issuer| crate::identity::IdentitySelector::new(&serde_json::json!({}), issuer.clone()).map(Arc::new))
        .transpose()
        .map_err(|error| error.to_string())?;
    let result =
        extract_identity_binding_vp(body, &crate::config::ChannelProtocol::Mcp, &selector, surface_id, issuer_anchor)
            .await;
    crate::observability::identity_binding_audit::audit_extraction(
        surface_id,
        issuer_anchor.and_then(|anchor| anchor.attested.as_deref()),
        &result,
    );
    result
}

async fn verify_identity_binding_presentation(
    vp_jwt: &str,
    claimed_did: Option<&str>,
    identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    channel_name: &str,
    issuer_anchor: Option<&crate::gateways::types::PeerIssuers>,
) -> Result<Option<crate::surface_context::IdentityBindingContext>, String> {
    info!(channel = channel_name, "Found identity binding VP in inbound request, verifying...");

    // Verify the VP signature
    let selector = match identity_selector.as_ref() {
        Some(s) => s,
        None => {
            warn!(channel = channel_name, "No identity selector available to verify binding VP");
            return Err("No identity selector available to verify binding VP".to_string());
        }
    };

    let vc_issuer = selector.get_vc_issuer();
    match vc_issuer
        .verify_agent_presentation_full(vp_jwt)
        .await
    {
        Ok(verified) => {
            let crate::identity::vc_issuer::VerifiedAgentPresentation {
                holder_did: agent_did,
                subject_id,
                issuer_did,
                identity_fields,
                raw_credentials: inbound_credentials,
            } = verified;

            if claimed_did.is_some_and(|did| did != agent_did) {
                return Err("MCP identity extension DID does not match the verified presentation holder".to_string());
            }

            // Holder / subject binding: the VP holder must be the same DID as
            // the primary VC subject (`credentialSubject.id`). A mismatch means
            // the presentation was assembled from someone else's credential.
            if let Some(subject) = &subject_id
                && subject != &agent_did
            {
                warn!(
                    channel = channel_name,
                    holder = %agent_did,
                    subject = %subject,
                    "Identity binding VP holder does not match credential subject"
                );
                return Err(format!(
                    "identity binding VP holder '{}' does not match credential subject '{}'",
                    agent_did, subject
                ));
            }

            // Issuer trust. The primary VC issuer must be the fabric-authenticated
            // sending gateway or one of the surface's configured trusted issuers.
            // With neither anchor present — the direct, unconfigured path — nothing
            // vouches for the issuer, so the binding reaches OPA with
            // `verified: false` and the issuer as `issuer_gateway` for policy to
            // decide; it is never reported as verified.
            let issuer = issuer_did
                .clone()
                .unwrap_or_default();
            let issuer_trusted = match evaluate_binding_issuer_trust(&issuer, issuer_anchor) {
                BindingIssuerDecision::Trusted => true,
                BindingIssuerDecision::Unanchored => {
                    warn!(
                        channel = channel_name,
                        issuer = %issuer,
                        "Identity binding VP issuer has no trust anchor; binding surfaced as unverified"
                    );
                    false
                }
                BindingIssuerDecision::Reject => {
                    warn!(
                        channel = channel_name,
                        issuer = %issuer,
                        "Identity binding VP issuer is not a trusted gateway"
                    );
                    return Err(format!("identity binding VP issuer '{}' is not a trusted gateway", issuer));
                }
            };

            // The gateway DID exposed to OPA/audit is the real VC issuer. Fall
            // back to the local issuer only for a degenerate VP with no VC.
            let gateway_did = match issuer_did {
                Some(did) => did,
                None => vc_issuer
                    .get_issuer_did()
                    .await
                    .unwrap_or_default(),
            };
            info!(
                channel = channel_name,
                agent_did = %agent_did,
                issuer = %gateway_did,
                issuer_trusted = issuer_trusted,
                chained_vcs = inbound_credentials.len(),
                "Identity binding VP signature verified"
            );
            Ok(Some(crate::surface_context::IdentityBindingContext::from_verified_parts(
                agent_did,
                gateway_did,
                identity_fields,
                inbound_credentials,
                issuer_trusted,
            )))
        }
        Err(e) => {
            warn!(
                channel = channel_name,
                error = %e,
                "Identity binding VP verification FAILED"
            );
            Err(format!("Identity binding VP verification failed: {}", e))
        }
    }
}

/// Inspect response message extensions for validation
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn inspect_response_extensions(
    response_body: &[u8],
    ctx: &ResponseExtensionInspectionContext<'_>,
) -> Result<(), Response> {
    debug!(channel = ctx.channel_name, "Starting response extension inspection");

    // Try to parse response as JSON
    let response_json: JsonValue = match serde_json::from_slice(response_body) {
        Ok(json) => {
            debug!(channel = ctx.channel_name, "Successfully parsed response as JSON");
            json
        }
        Err(e) => {
            debug!(channel = ctx.channel_name, error = %e, "Response is not JSON, skipping inspection");
            return Ok(());
        }
    };

    // Navigate to extensions arrays in multiple possible locations
    let extensions_array = response_json
        .get("result")
        .and_then(|result| result.get("message"))
        .and_then(|msg| msg.get("extensions"))
        .and_then(|ext| ext.as_array())
        .or_else(|| {
            // Check status message extensions (for Task response)
            response_json
                .get("result")
                .and_then(|result| result.get("status"))
                .and_then(|status| status.get("message"))
                .and_then(|msg| msg.get("extensions"))
                .and_then(|ext| ext.as_array())
        })
        .or_else(|| {
            // Check result.extensions (for direct Message response)
            // A2A spec allows SendMessage to return either Task or Message
            response_json
                .get("result")
                .and_then(|result| result.get("extensions"))
                .and_then(|ext| ext.as_array())
        })
        .or_else(|| {
            // Fallback to direct message.extensions
            response_json
                .get("message")
                .and_then(|msg| msg.get("extensions"))
                .and_then(|ext| ext.as_array())
        });

    let extensions_array = match extensions_array {
        Some(arr) => {
            debug!(channel = ctx.channel_name, count = arr.len(), "Found response extensions array");
            arr
        }
        None => {
            debug!(channel = ctx.channel_name, "No extensions array found in response");
            // Response extensions are optional - no enforcement
            return Ok(());
        }
    };

    // Get response metadata objects from specific locations
    let metadata_locations = [
        response_json
            .get("result")
            .and_then(|result| result.get("metadata")),
        response_json
            .get("result")
            .and_then(|result| result.get("status"))
            .and_then(|status| status.get("message"))
            .and_then(|msg| msg.get("metadata")),
        response_json
            .get("message")
            .and_then(|msg| msg.get("metadata")),
    ];

    // Track if we found the Affinidi agent identity extension
    let mut _found_affinidi_extension = false;

    for extension in extensions_array {
        if let Some(extension_uri) = extension.as_str() {
            debug!(channel = ctx.channel_name, extension = extension_uri, "Checking response extension");

            if ctx
                .config
                .extension_inspection
                .watch_extensions
                .contains(&extension_uri.to_string())
            {
                debug!(channel = ctx.channel_name, extension = extension_uri, "🔍 Response Extension Detected");

                // Validate if Affinidi agent identity extension is present (accept both raw identity and VP credential)
                if extension_uri == crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION
                    || extension_uri == crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION
                {
                    _found_affinidi_extension = true;

                    // Check all metadata locations for this extension
                    for (idx, metadata_opt) in metadata_locations
                        .iter()
                        .enumerate()
                    {
                        if let Some(meta) = metadata_opt
                            && let Some(extension_payload) = meta.get(extension_uri)
                        {
                            debug!(
                                channel = ctx.channel_name,
                                extension = extension_uri,
                                location = idx,
                                "Found extension payload at metadata location {}",
                                idx
                            );

                            // Validate extension payload against response rules engine if configured
                            if let Some(engine) = ctx.response_rules_engine {
                                match engine.validate(extension_payload, ctx.channel_name) {
                                    Ok(()) => {
                                        debug!(
                                            channel = ctx.channel_name,
                                            extension = extension_uri,
                                            location = idx,
                                            "✓ Response extension validation passed at location {}",
                                            idx
                                        );
                                        // Record successful validation
                                        if let Some(metrics) = ctx.metrics_store {
                                            let channel_config_id = ctx.surface.config_id_string();
                                            metrics
                                                .record_rule_validation(channel_config_id, true)
                                                .await;
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            channel = ctx.channel_name,
                                            extension = extension_uri,
                                            location = idx,
                                            error = %e,
                                            "✗ Response extension validation failed at location {}", idx
                                        );
                                        // Record denied validation
                                        if let Some(metrics) = ctx.metrics_store {
                                            let channel_config_id = ctx.surface.config_id_string();
                                            metrics
                                                .record_rule_validation(channel_config_id, false)
                                                .await;
                                        }
                                        return Err(crate::a2a::errors::create_error_response(
                                            StatusCode::BAD_GATEWAY,
                                            &format!("Response extension validation failed: {}", e),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // All response validations passed  - response extensions are optional
    Ok(())
}

/// Check if header is hop-by-hop
pub fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Returns `true` if a header should be forwarded to an upstream request.
///
/// Excludes:
/// - Hop-by-hop headers (see [`is_hop_by_hop_header`])
/// - `content-length` — reqwest sets this automatically from the body
/// - `host` — must be derived from the target URL so TLS SNI matches the upstream
///   certificate; forwarding the inbound `Host` causes TLS handshake failures when
///   the gateway domain differs from the upstream domain (e.g. ngrok vs Google APIs)
/// - `x-transit-token` — a GW1-local continuity proof between the Access Point request
///   and the later Transit Point call. It authorizes the outbound hop on the issuing
///   gateway only and must never be forwarded to the upstream or to a remote gateway
///   (GW2); the cross-gateway trust artifact is the signed workload-binding VP.
pub fn should_forward_request_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    !is_hop_by_hop_header(&lower) && lower != "content-length" && lower != "host" && lower != "x-transit-token"
}

#[cfg(test)]
mod tests {
    use crate::identity::test_helpers::{SignedAgentPresentation, signed_agent_presentation};

    #[tokio::test]
    async fn mcp_signed_aliases_preserve_verification_and_reject_spoofing() {
        use crate::identity::ssi::verifier::{LocalVerifier, Verifier};
        use serde_json::json;

        let SignedAgentPresentation {
            issuer_did,
            holder_did,
            presentation,
            issuer,
            _temporary,
        } = signed_agent_presentation().await;
        let verifier = LocalVerifier::new(crate::gateways::did_cache::shared_resolver().clone());
        assert_eq!(
            verifier
                .verify_vp(&presentation)
                .await
                .unwrap()
                .holder_did,
            holder_did
        );

        for key in [
            crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
            crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY,
            crate::config::AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION,
            crate::config::MCP_AGENT_IDENTITY_BINDING_KEY,
        ] {
            let mut body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"_meta": {key: {"verifiablePresentation": presentation.to_string(), "did": holder_did}}}});
            let verified = super::verify_mcp_metadata_identity(
                body.to_string().as_bytes(),
                Some(&issuer),
                "test",
                Some(&peer_issuers(&issuer_did)),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(verified.verified);
            assert_eq!(verified.agent_did, holder_did);
            assert_eq!(verified.gateway_did, issuer_did);
            crate::mcp::meta::normalize_metadata(
                &mut body,
                crate::mcp::meta::McpMetadataContext::legacy(Some(crate::config::McpLegacyMetadataOutput::Canonical)),
            )
            .unwrap();
            let canonical = crate::mcp::meta::canonical_key(key);
            assert_eq!(body["params"]["_meta"][canonical]["verifiablePresentation"], presentation.to_string());
            assert!(
                super::verify_mcp_metadata_identity(
                    body.to_string().as_bytes(),
                    Some(&issuer),
                    "test",
                    Some(&peer_issuers("did:example:untrusted")),
                )
                .await
                .is_err()
            );
            body["params"]["_meta"][canonical]["did"] = json!("did:example:spoofed");
            assert!(
                super::verify_mcp_metadata_identity(
                    body.to_string().as_bytes(),
                    Some(&issuer),
                    "test",
                    Some(&peer_issuers(&issuer_did)),
                )
                .await
                .is_err()
            );
        }
        let mut tampered = presentation.clone();
        tampered["proof"]["proofValue"] =
            json!("z11111111111111111111111111111111111111111111111111111111111111111111");
        assert!(
            verifier
                .verify_vp(&tampered)
                .await
                .is_err()
        );
        let mut expired = presentation;
        if expired["verifiableCredential"].is_array() {
            expired["verifiableCredential"][0]["validUntil"] = json!("2000-01-01T00:00:00Z");
        } else {
            expired["verifiableCredential"]["validUntil"] = json!("2000-01-01T00:00:00Z");
        }
        assert!(
            verifier
                .verify_vp(&expired)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn mcp_binding_aliases_do_not_bypass_validation() {
        use crate::config::{ChannelProtocol, MCP_AGENT_IDENTITY_BINDING_KEY, MCP_AGENT_IDENTITY_CREDENTIAL_KEY};
        use serde_json::json;
        for key in [
            MCP_AGENT_IDENTITY_BINDING_KEY,
            MCP_AGENT_IDENTITY_CREDENTIAL_KEY,
            crate::config::AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION,
            crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
        ] {
            let body = json!({"method": "tools/call", "params": {"_meta": {key: {"did": "did:example:unverified"}}}});
            let error = super::extract_identity_binding_vp(
                body.to_string().as_bytes(),
                &ChannelProtocol::Mcp,
                &None,
                "test",
                None,
            )
            .await
            .unwrap_err();
            assert!(error.contains("requires a presentation"), "{error}");
            let body = json!({"method": "tools/call", "params": {"_meta": {key: {"verifiablePresentation": "signed.proof.value"}}}});
            assert_eq!(
                super::extract_identity_binding_vp_jwt(body.to_string().as_bytes(), &ChannelProtocol::Mcp).as_deref(),
                Some("signed.proof.value")
            );
            assert!(
                super::extract_identity_binding_vp(
                    body.to_string().as_bytes(),
                    &ChannelProtocol::Mcp,
                    &None,
                    "test",
                    None
                )
                .await
                .is_err()
            );
        }
    }

    /// The issuers of a fabric connection whose peer attested `attested`.
    fn peer_issuers(attested: &str) -> crate::gateways::types::PeerIssuers {
        crate::gateways::types::PeerIssuers {
            attested: Some(attested.to_string()),
            trusted: Vec::new(),
        }
    }

    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn metadata_runtime_helpers_resolve_supported_values() {
        let input = json!({
            "request": "$REQUEST_ID",
            "surface": "$SURFACE_ID",
            "time": "$TIMESTAMP",
            "literal": "$CALLER_DID"
        });
        let resolved = resolve_metadata_references(
            &input,
            &None,
            "test-surface",
            MetadataRuntimeContext {
                request_id: Some("trace-123"),
                surface_id: Some("surface-456"),
            },
        )
        .await
        .expect("metadata helpers resolve");

        assert_eq!(resolved["request"], "trace-123");
        assert_eq!(resolved["surface"], "surface-456");
        assert!(
            resolved["time"]
                .as_str()
                .unwrap()
                .contains('T')
        );
        assert_eq!(resolved["literal"], "$CALLER_DID");
    }

    #[test]
    fn transit_token_and_authorization_are_never_forwarded() {
        // GW1-local headers must not cross to the upstream or to GW2.
        assert!(!should_forward_request_header("X-Transit-Token"));
        assert!(!should_forward_request_header("x-transit-token"));
        assert!(should_forward_request_header("Authorization"));
        // Ordinary headers still forward.
        assert!(should_forward_request_header("Content-Type"));
        assert!(should_forward_request_header("X-Custom-Trace"));
    }

    // ── Identity binding issuer trust ────────────────────────────────────────

    #[test]
    fn binding_issuer_trust_accepts_the_sending_connections_attested_issuer() {
        assert_eq!(
            evaluate_binding_issuer_trust("did:web:gw1", Some(&peer_issuers("did:web:gw1"))),
            BindingIssuerDecision::Trusted
        );
    }

    #[test]
    fn binding_issuer_trust_accepts_allowlisted_issuer() {
        let anchor = crate::gateways::types::PeerIssuers {
            attested: None,
            trusted: vec!["did:web:relay".to_string(), "did:web:gw1".to_string()],
        };
        assert_eq!(evaluate_binding_issuer_trust("did:web:gw1", Some(&anchor)), BindingIssuerDecision::Trusted);
    }

    #[test]
    fn binding_issuer_trust_rejects_an_issuer_the_connection_does_not_know() {
        let anchor = crate::gateways::types::PeerIssuers {
            attested: Some("did:web:gw1".to_string()),
            trusted: vec!["did:web:relay".to_string()],
        };
        assert_eq!(evaluate_binding_issuer_trust("did:web:attacker", Some(&anchor)), BindingIssuerDecision::Reject);
    }

    #[test]
    fn binding_issuer_trust_rejects_everything_for_a_connection_without_issuers() {
        let anchor = crate::gateways::types::PeerIssuers {
            attested: None,
            trusted: Vec::new(),
        };
        assert_eq!(evaluate_binding_issuer_trust("did:web:gw1", Some(&anchor)), BindingIssuerDecision::Reject);
    }

    #[test]
    fn binding_issuer_trust_is_unanchored_when_no_anchor() {
        assert_eq!(evaluate_binding_issuer_trust("did:web:anyone", None), BindingIssuerDecision::Unanchored);
    }

    #[test]
    fn binding_issuer_trust_never_trusts_a_missing_issuer() {
        assert_eq!(evaluate_binding_issuer_trust("", None), BindingIssuerDecision::Unanchored);
        assert_eq!(
            evaluate_binding_issuer_trust("", Some(&peer_issuers("did:web:gw1"))),
            BindingIssuerDecision::Reject
        );
    }

    #[tokio::test]
    async fn a2a_binding_without_trust_anchor_is_surfaced_unverified() {
        use crate::config::{AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION, ChannelProtocol};

        let SignedAgentPresentation {
            issuer_did,
            holder_did,
            presentation,
            issuer,
            _temporary,
        } = signed_agent_presentation().await;
        let selector = Some(std::sync::Arc::new(crate::identity::IdentitySelector::new(&json!({}), issuer).unwrap()));
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {"message": {"metadata": {
                AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION: {"verifiablePresentation": presentation.to_string()}
            }}}
        })
        .to_string();
        let body = body.as_bytes();
        let protocol = ChannelProtocol::A2a;

        let unanchored = extract_identity_binding_vp(body, &protocol, &selector, "test", None)
            .await
            .unwrap()
            .expect("binding is surfaced to OPA");
        assert!(!unanchored.verified, "a binding with no trust anchor must not report verified");
        assert_eq!(unanchored.agent_did, holder_did);
        assert_eq!(unanchored.gateway_did, issuer_did);

        let attested = crate::gateways::types::PeerIssuers {
            attested: Some(issuer_did.clone()),
            trusted: Vec::new(),
        };
        let anchored = extract_identity_binding_vp(body, &protocol, &selector, "test", Some(&attested))
            .await
            .unwrap()
            .unwrap();
        assert!(anchored.verified);

        let allowed = crate::gateways::types::PeerIssuers {
            attested: None,
            trusted: vec![issuer_did.clone()],
        };
        let allowlisted = extract_identity_binding_vp(body, &protocol, &selector, "test", Some(&allowed))
            .await
            .unwrap()
            .unwrap();
        assert!(allowlisted.verified);

        let other = crate::gateways::types::PeerIssuers {
            attested: Some("did:example:other".to_string()),
            trusted: Vec::new(),
        };
        assert!(
            extract_identity_binding_vp(body, &protocol, &selector, "test", Some(&other))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn credential_identity_did_only_yields_no_identity() {
        let ext = json!({ "did": "did:web:agent.example" });
        assert!(
            matches!(
                resolve_inbound_credential_identity(&ext, &None, "test-channel").await,
                CredentialResolution::Absent
            ),
            "a bare did claim must not become the caller identity"
        );
    }

    #[tokio::test]
    async fn credential_identity_none_when_neither_vp_nor_did() {
        let ext = json!({ "unrelated": "value" });
        assert!(matches!(
            resolve_inbound_credential_identity(&ext, &None, "test-channel").await,
            CredentialResolution::Absent
        ));
    }

    #[tokio::test]
    async fn credential_identity_vp_without_verifier_is_rejected() {
        let ext = json!({
            "verifiablePresentation": "not-a-real-jwt",
            "did": "did:web:agent.example"
        });
        assert!(
            matches!(
                resolve_inbound_credential_identity(&ext, &None, "test-channel").await,
                CredentialResolution::Rejected
            ),
            "an unverifiable presentation must not fall back to the did claim"
        );
    }

    #[tokio::test]
    async fn credential_identity_unverifiable_vp_is_rejected() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let selector =
            Arc::new(crate::identity::IdentitySelector::new(&json!({ "type": "object" }), Arc::new(issuer)).unwrap());
        let ext = json!({ "verifiablePresentation": "not-a-real-jwt", "did": "did:web:agent.example" });
        assert!(matches!(
            resolve_inbound_credential_identity(&ext, &Some(selector), "test-channel").await,
            CredentialResolution::Rejected
        ));
    }

    // The direct path has no authenticated sender, so a presentation from any
    // issuer verifies; the result must say so.
    #[tokio::test]
    async fn credential_identity_verified_on_the_direct_path_is_unanchored() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = Arc::new(
            crate::identity::IdentitySelector::new(&json!({ "type": "object" }), signed.issuer.clone()).unwrap(),
        );
        let ext = json!({ "did": signed.holder_did, "verifiablePresentation": signed.presentation.to_string() });
        match resolve_inbound_credential_identity(&ext, &Some(selector), "test-channel").await {
            CredentialResolution::Verified(result) => {
                assert_eq!(result.did, signed.holder_did);
                assert_eq!(result.issuer_did.as_deref(), Some(signed.issuer_did.as_str()));
                assert_eq!(
                    result.verification,
                    crate::surface_context::IdentityVerification::VpUnanchored,
                    "no sender vouches for the issuer on the direct path"
                );
            }
            other => panic!("expected a verified presentation, got {other:?}"),
        }
    }
}
