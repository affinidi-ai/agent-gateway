#![allow(clippy::result_large_err)] // FIXME: Response is not an error

//! Handler functions for proxy requests

use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{Instrument, debug, error, info, warn};

use crate::a2a::{
    build_target_url, create_error_response, create_jsonrpc_error_response, inject_custom_metadata_extension,
    inspect_message_extensions, is_hop_by_hop_header, rewrite_agent_card_urls, should_forward_request_header,
    validate_jsonrpc_envelope,
};
use crate::observability::broadcast_payload_capture_async;
use crate::proxy::backend_identity::ProtectedAgentIdentity;
use crate::server::ConnectionGuard;
use crate::state::{MultiSurfaceProxyState, ProxyState};
use crate::{channel_debug, channel_error, channel_info, channel_warn};

pub(crate) mod surface_payment;

/// Lazy-initialized SSE session manager for MCP proxy:// channels.
/// Shared across all channel proxy handlers.
static CHANNEL_SSE_SESSION_MGR: std::sync::LazyLock<crate::mcp::sse_server::SseSessionManager> =
    std::sync::LazyLock::new(|| crate::mcp::sse_server::SseSessionManager::new(None));

async fn resolve_legacy_mcp_session(
    headers: &HeaderMap
) -> (crate::mcp::request_validation::LegacySessionEvidence, Option<String>) {
    use crate::mcp::request_validation::LegacySessionEvidence;

    let Some(session_id) = headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
    else {
        return if headers.contains_key("mcp-session-id") {
            (LegacySessionEvidence::Unknown, None)
        } else {
            (LegacySessionEvidence::Absent, None)
        };
    };

    let (legacy_sse, streamable_sse, capabilities) = tokio::join!(
        CHANNEL_SSE_SESSION_MGR.session_exists(session_id),
        crate::mcp::streamable_sse::global_streamable_session_registry().has_session(session_id),
        crate::mcp::elicitation::global_capability_registry().get(session_id),
    );
    if legacy_sse || streamable_sse || capabilities.is_some() {
        (LegacySessionEvidence::Known, Some(session_id.to_string()))
    } else {
        (LegacySessionEvidence::Unknown, None)
    }
}

/// Returns `true` if the header should be forwarded upstream, additionally
/// stripping the source-auth credential header unless JWT bearer auth
/// explicitly opts into forwarding it to the direct target.
fn should_forward_header(
    name: &str,
    source_auth_header: Option<&str>,
) -> bool {
    should_forward_ap_request_header_with_mapping(name, source_auth_header, None, false)
}

fn should_forward_ap_request_header_with_mapping(
    name: &str,
    source_auth_header: Option<&str>,
    header_metadata_mapping: Option<&crate::config::header_metadata_mapping::HeaderMetadataMappingConfig>,
    forward_source_auth_header: bool,
) -> bool {
    if !should_forward_request_header(name) {
        return false;
    }

    if let Some(auth_header_name) = source_auth_header
        && name.eq_ignore_ascii_case(auth_header_name)
    {
        return forward_source_auth_header;
    } else if name.eq_ignore_ascii_case("authorization") {
        return false;
    }

    if header_metadata_mapping.is_some_and(|mapping| {
        mapping.strip_mapped_headers
            && mapping
                .headers
                .iter()
                .any(|mapped| name.eq_ignore_ascii_case(mapped.header.trim()))
    }) {
        return false;
    }

    true
}

/// Extract UCP operation type from request path and method
/// Supports UCP REST, MCP, and A2A transport bindings per spec
pub(crate) fn extract_ucp_operation(
    path: &str,
    method: &Method,
) -> Option<String> {
    // UCP Discovery endpoint (common to all transports)
    // Includes the standard A2A agent card path used by the UCP A2A binding
    // Also includes /.well-known/agent.json (A2A agent descriptor) — both are metadata-only
    if crate::proxy::paths::is_public_request(method.as_str(), path) {
        return Some("discovery".to_string());
    }

    // UCP REST Transport - Official UCP paths per https://ucp.dev/specification/checkout-rest/
    // POST /checkout-sessions -> create_checkout
    if method == Method::POST && (path.ends_with("/checkout-sessions") || path.contains("/checkout-sessions?")) {
        return Some("create_checkout".to_string());
    }

    // GET /checkout-sessions/{id} -> get_checkout
    if method == Method::GET
        && path.contains("/checkout-sessions/")
        && !path.contains("/complete")
        && !path.contains("/cancel")
    {
        return Some("get_checkout".to_string());
    }

    // PUT /checkout-sessions/{id} -> update_checkout
    if method == Method::PUT && path.contains("/checkout-sessions/") {
        return Some("update_checkout".to_string());
    }

    // POST /checkout-sessions/{id}/complete -> complete_checkout
    if method == Method::POST && path.contains("/checkout-sessions/") && path.contains("/complete") {
        return Some("complete_checkout".to_string());
    }

    // POST /checkout-sessions/{id}/cancel -> cancel_checkout
    if method == Method::POST && path.contains("/checkout-sessions/") && path.contains("/cancel") {
        return Some("cancel_checkout".to_string());
    }

    // Additional UCP REST endpoints for commerce operations
    // GET /products -> products_list
    if method == Method::GET && (path.ends_with("/products") || path.contains("/products?")) {
        return Some("products_list".to_string());
    }

    // POST /carts -> cart_create
    if method == Method::POST && (path.ends_with("/carts") || path.contains("/carts?")) {
        return Some("cart_create".to_string());
    }

    // GET /carts -> carts_list
    if method == Method::GET && (path.ends_with("/carts") || path.contains("/carts?")) {
        return Some("carts_list".to_string());
    }

    // POST /carts/{id}/items -> cart_add_item
    if method == Method::POST && path.contains("/carts/") && path.contains("/items") {
        return Some("cart_add_item".to_string());
    }

    // GET /carts/{id} -> cart_get
    if method == Method::GET && path.contains("/carts/") && !path.contains("/items") {
        return Some("cart_get".to_string());
    }

    // GET /orders -> orders_list
    if method == Method::GET && (path.ends_with("/orders") || path.contains("/orders?")) {
        return Some("orders_list".to_string());
    }

    // GET /orders/{id} -> order_get
    if method == Method::GET && path.contains("/orders/") {
        return Some("order_get".to_string());
    }

    // Legacy/generic UCP REST patterns (for backward compatibility)
    if method == Method::POST && path.contains("/checkout") && !path.contains("/complete") && !path.contains("/cancel")
    {
        return Some("checkout_create".to_string());
    }

    if method == Method::POST && path.contains("/payment") {
        return Some("payment".to_string());
    }

    if method == Method::GET && path.contains("/order/") {
        return Some("order_query".to_string());
    }

    if method == Method::GET && path.contains("/discount/") {
        return Some("discount_query".to_string());
    }

    None
}

/// Extract UCP operation type from request body JSON.
/// This handles MCP and A2A transports where the operation type is embedded in the body
/// rather than in the URL path.
///
/// This is a standalone helper so it can be called from both the direct proxy path
/// (handler.rs) and the fabric forwarding path (message_processor.rs).
pub(crate) fn extract_ucp_operation_from_body(
    body_bytes: &[u8],
    config_id: &str,
) -> Option<String> {
    if body_bytes.is_empty() {
        return None;
    }
    let mut ucp_operation: Option<String> = None;
    // Try to parse body as JSON and scan for UCP operation signals.
    // No channel-type gate: a2a.ucp.* and a2a.product* keys are specific enough to avoid false positives.
    if let Ok(body_json) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
        // Priority 1: Check A2A Transport with UCP data in nested message parts first
        // This handles params.message.parts[].data.action or parts[].text (JSON-encoded) or UCP-specific keys
        // Also handles JSON-RPC response format: result.parts[] (push notifications / webhooks)
        // Two-pass approach: first collect action + all UCP keys from both data and text fields, then decide
        let parts_from_params = body_json
            .get("params")
            .and_then(|p| p.get("message"))
            .and_then(|m| m.get("parts"))
            .and_then(|p| p.as_array());
        let parts_from_result = body_json
            .get("result")
            .and_then(|r| r.get("parts"))
            .and_then(|p| p.as_array());
        if let Some(parts) = parts_from_params.or(parts_from_result) {
            let mut found_action: Option<String> = None;
            let mut found_ucp_keys: Vec<String> = Vec::new();
            let mut found_product_keys: Vec<String> = Vec::new();

            for part in parts {
                // Process data field if present
                if let Some(data) = part
                    .get("data")
                    .and_then(|d| d.as_object())
                {
                    // Collect explicit action field — first found wins across all parts
                    if found_action.is_none()
                        && let Some(action) = data
                            .get("action")
                            .and_then(|a| a.as_str())
                    {
                        found_action = Some(action.to_string());
                    }
                    // Collect all a2a.ucp.* keys
                    for key in data.keys() {
                        if key.starts_with("a2a.ucp.") {
                            found_ucp_keys.push(key.clone());
                        } else if key.starts_with("a2a.product") {
                            found_product_keys.push(key.clone());
                        }
                    }
                }

                // Also check text field for JSON-encoded UCP operations
                if let Some(text) = part
                    .get("text")
                    .and_then(|t| t.as_str())
                {
                    // Try to parse text as JSON
                    if let Ok(text_json) = serde_json::from_str::<serde_json::Value>(text)
                        && let Some(text_obj) = text_json.as_object()
                    {
                        // Collect action field from parsed text — first found wins across all parts
                        if found_action.is_none()
                            && let Some(action) = text_obj
                                .get("action")
                                .and_then(|a| a.as_str())
                        {
                            found_action = Some(action.to_string());
                        }
                        // Collect all a2a.ucp.* keys from parsed text
                        for key in text_obj.keys() {
                            if key.starts_with("a2a.ucp.") {
                                found_ucp_keys.push(key.clone());
                            } else if key.starts_with("a2a.product") {
                                found_product_keys.push(key.clone());
                            }
                        }
                    }
                }
            }

            // Sort keys for deterministic operation inference across multi-part messages
            found_ucp_keys.sort();
            // Determine operation: UCP key evidence takes priority for specificity,
            // then action field, then generic inference from UCP key prefixes.
            // Use exact key matches for payment detection to avoid false positives
            // (e.g. prevent a2a.ucp.cart.payment_data from triggering complete_checkout).
            let has_payment_keys = found_ucp_keys
                .iter()
                .any(|k| k == "a2a.ucp.checkout.payment_data" || k == "a2a.ucp.checkout.ap2_checkout_mandate");
            let has_cart_keys = found_ucp_keys
                .iter()
                .any(|k| k.starts_with("a2a.ucp.cart"));

            if has_payment_keys {
                // Exact payment/mandate key present → complete_checkout (most specific)
                ucp_operation = Some("complete_checkout".to_string());
                channel_info!(config_id, "🛒 UCP (request): complete_checkout");
            } else if let Some(ref action) = found_action {
                // Explicit action field from parts — accept as-is.
                // Unknown actions are forwarded but warned for observability.
                ucp_operation = Some(action.clone());
                let known_ucp_actions = [
                    "create_checkout",
                    "get_checkout",
                    "update_checkout",
                    "complete_checkout",
                    "cancel_checkout",
                    "cart_create",
                    "cart_add_item",
                    "cart_get",
                    "cart_update",
                    "cart_remove_item",
                    "add_to_checkout",
                    "start_payment",
                    "checkout",
                    "payment",
                    "discovery",
                ];
                if known_ucp_actions.contains(&action.as_str()) {
                    channel_info!(config_id, "🛒 UCP (request): {}", action);
                } else {
                    channel_warn!(config_id, "🛒 UCP (request): unrecognized action '{}'", action);
                }
            } else if !found_ucp_keys.is_empty() {
                // Infer operation from the first (sorted) a2a.ucp.* key.
                // Key format: a2a.ucp.{operation}[.subfield] → extract first segment.
                // e.g. "a2a.ucp.checkout" → "checkout", "a2a.ucp.cart" → "cart_create"
                let first_key = &found_ucp_keys[0];
                let op = first_key
                    .strip_prefix("a2a.ucp.")
                    .unwrap_or(first_key.as_str());
                let op = op
                    .split('.')
                    .next()
                    .unwrap_or(op);
                // Map bare "cart" key to "cart_create" to align with REST operation names
                let op = if op == "cart" && has_cart_keys {
                    "cart_create"
                } else {
                    op
                };
                ucp_operation = Some(op.to_string());
                channel_info!(config_id, "🛒 UCP (request): {} (from key '{}')", op, first_key);
            } else if !found_product_keys.is_empty() {
                // a2a.product_results or similar → product discovery response
                ucp_operation = Some("discovery".to_string());
                channel_info!(config_id, "🛒 UCP (request): discovery (from '{}')", found_product_keys[0]);
            }
        }

        if ucp_operation.is_none()
            && body_json
                .get("jsonrpc")
                .and_then(|v| v.as_str())
                == Some("2.0")
            && let Some(method) = body_json
                .get("method")
                .and_then(|v| v.as_str())
        {
            // Map MCP methods to UCP operation names
            match method {
                // UCP MCP Transport - direct UCP operations
                "create_checkout" | "get_checkout" | "update_checkout" | "complete_checkout" | "cancel_checkout" => {
                    ucp_operation = Some(method.to_string());
                    channel_debug!(config_id, "Extracted UCP MCP method: {}", method);
                }
                // A2A Transport envelope methods on UCP channels (both eras — v0.3
                // slash-form and v1.0 PascalCase — via the shared recogniser):
                // These are A2A/JSON-RPC wrappers — the actual UCP operation is inside
                // the message parts (handled by Priority 1 above). If Priority 1 found
                // nothing, this is a non-UCP A2A message. Track as A2A method, not UCP.
                _ if crate::a2a::is_a2a_method(method) => {
                    // These are A2A envelope methods, NOT UCP operations.
                    // Priority 1 already tried to extract UCP operation from parts.
                    // If we're here, there was no UCP data in parts → skip.
                    channel_debug!(
                        config_id,
                        "A2A envelope method '{}' on UCP channel, no UCP operation in parts — skipping",
                        method
                    );
                }
                _ => {
                    // Unknown method on UCP channel — could be a UCP extension or custom op
                    ucp_operation = Some(method.to_string());
                    channel_debug!(config_id, "Extracted unknown method as UCP operation: {}", method);
                }
            }
        }

        // Priority 3: UCP A2A Transport or custom implementations - operation in body
        // { "operation": "cart.create", ... } or { "params": { "operation": "..." } }
        if ucp_operation.is_none() {
            if let Some(operation) = body_json
                .get("operation")
                .and_then(|v| v.as_str())
            {
                ucp_operation = Some(operation.to_string());
                channel_debug!(config_id, "Extracted UCP operation from body: {}", operation);
            }
            // Also check params.operation for wrapped requests
            else if let Some(operation) = body_json
                .get("params")
                .and_then(|p| p.get("operation"))
                .and_then(|v| v.as_str())
            {
                ucp_operation = Some(operation.to_string());
                channel_debug!(config_id, "Extracted UCP operation from params.operation: {}", operation);
            }
        }
    }
    ucp_operation
}

/// Extract JWT claims from the `Authorization` header of an incoming request.
fn extract_jwt_claims_from_headers(headers: &HeaderMap) -> Option<HashMap<String, serde_json::Value>> {
    let auth_header = headers
        .get("authorization")?
        .to_str()
        .ok()?;
    decode_bearer_jwt_claims(auth_header)
}

/// Decode the (unverified) claims of a `Bearer <jwt>` Authorization header value.
///
/// Populates `input.jwt` for MCP tool policy evaluation on both the direct path
/// and the GW2 fabric path, where the caller's forwarded Authorization header is
/// rebuilt into the same policy context. The signature is NOT verified here —
/// authenticity is established by source authentication; this only surfaces the
/// claims for policy input.
pub(crate) fn decode_bearer_jwt_claims(auth_header: &str) -> Option<HashMap<String, serde_json::Value>> {
    let token = auth_header.strip_prefix("Bearer ")?;

    // Split JWT into parts (header.payload.signature)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode the payload (second part) from base64url and parse the claims JSON.
    let payload_bytes = base64_url_decode_helper(parts[1]).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

/// Decode base64url string (JWT uses base64url encoding)
fn base64_url_decode_helper(input: &str) -> Result<Vec<u8>, String> {
    // Replace base64url chars with standard base64
    let standard_b64 = input
        .replace('-', "+")
        .replace('_', "/");

    // Add padding if needed
    let padding_len = (4 - (standard_b64.len() % 4)) % 4;
    let padded = if padding_len > 0 {
        format!("{}{}", standard_b64, "=".repeat(padding_len))
    } else {
        standard_b64
    };

    // Decode using standard base64
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| e.to_string())
}

/// Inject target authentication credentials into an outbound request header.
/// Returns the header name and value to inject, or None if method is not implemented.
/// Whether the inbound request that triggered this forward had its caller
/// identity asserted by the gateway.
///
/// `target.auth` exists so a backend can trust that the gateway vetted the
/// caller. On a request that skipped caller authentication the gateway has
/// vetted nobody, so attaching the backend credential would vouch for an
/// unauthenticated stranger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallerAssertion {
    Authenticated,
    Unauthenticated,
    /// The gateway's own request to its target, not a forwarded caller request:
    /// the agent-card fetch behind `/.well-known/agent-card.json` and
    /// `/.well-known/agent.json`. The credential vouches for the gateway reaching
    /// its configured backend, and the caller controls neither the path, the
    /// method nor the body.
    GatewayOriginated,
}

impl CallerAssertion {
    /// Whether the target credential may be attached. Exhaustive on purpose: a
    /// new variant does not compile until it states whether it carries the
    /// credential.
    pub(crate) fn permits_target_credential(self) -> bool {
        match self {
            Self::Authenticated | Self::GatewayOriginated => true,
            Self::Unauthenticated => false,
        }
    }

    /// A public discovery read skipped caller authentication, so the gateway has
    /// no caller to vouch for. Any other request, including a POST to a path
    /// that only ends like a discovery document, was authenticated.
    pub(crate) fn for_request(
        method: &str,
        path: &str,
    ) -> Self {
        if crate::proxy::paths::is_public_request(method, path) {
            Self::Unauthenticated
        } else {
            Self::Authenticated
        }
    }
}

pub(crate) async fn inject_target_auth_header(
    target_auth: &crate::config::TargetAuthConfig,
    secrets_store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
    channel_name: &str,
    caller: CallerAssertion,
) -> anyhow::Result<Option<(String, String)>> {
    use crate::config::TargetAuthMethod;

    if !caller.permits_target_credential() {
        warn!(
            channel = %channel_name,
            "Refusing to inject target credentials: the inbound request skipped caller authentication"
        );
        return Ok(None);
    }

    match &target_auth.method {
        TargetAuthMethod::StaticSecret {
            secret_id,
            header_name,
            header_format,
        } => {
            let store = secrets_store
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Secrets store not available"))?;

            let secret = store
                .get_by_secret_id(secret_id)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to load secret '{}': {}", secret_id, e))?
                .ok_or_else(|| anyhow::anyhow!("Secret with secret_id '{}' not found", secret_id))?;

            // Format the header value
            let header_value = header_format.replace("{value}", &secret.value);

            debug!(channel = channel_name, secret_id = %secret_id, header = %header_name, "Resolved target auth secret");

            Ok(Some((header_name.clone(), header_value)))
        }
        TargetAuthMethod::CredentialLookup => {
            // CredentialLookup method not yet implemented - using Secrets approach instead
            warn!(channel = channel_name, "CredentialLookup method not implemented, skipping target auth injection");
            Ok(None)
        }
    }
}

/// Load and prepare DID:webvh identity context for a channel request
#[cfg(feature = "didwebvh")]
async fn load_did_identity_context(state: &ProxyState) -> Option<crate::identity::didwebvh::SurfaceDidContext> {
    use crate::identity::didwebvh::load_surface_identity;

    // Check if channel has DID:webvh configuration
    let did_config = state
        .surface
        .didwebvh_identity_legacy()?;

    // Get stores from state
    let identity_store = state
        .didwebvh_identity_store
        .as_ref()?;
    let log_manager = state
        .didwebvh_log_manager
        .as_ref()?;

    // Load the identity context
    match load_surface_identity(&did_config, identity_store.clone(), log_manager.clone()).await {
        Ok(Some(context)) => {
            debug!(
                surface = %state.surface.name,
                identity_id = %context.identity_id,
                did = %context.did,
                "Loaded DID:webvh identity for channel"
            );
            Some(context)
        }
        Ok(None) => {
            warn!(
                surface = %state.surface.name,
                identity_id = %did_config.identity_id,
                "DID:webvh identity not found"
            );
            None
        }
        Err(e) => {
            error!(
                surface = %state.surface.name,
                identity_id = %did_config.identity_id,
                error = %e,
                "Failed to load DID:webvh identity"
            );
            None
        }
    }
}

/// Inject DID:webvh identity into HTTP headers based on injection mode
#[cfg(feature = "didwebvh")]
fn inject_did_headers(
    context: &crate::identity::didwebvh::SurfaceDidContext,
    headers: &mut Vec<(&str, String)>,
) {
    use crate::config::DidInjectionMode;

    match context.injection_mode() {
        DidInjectionMode::Header => {
            // Simple DID in X-DID-Identity header
            headers.push(("X-DID-Identity", context.did().to_string()));
            debug!(did = %context.did(), "Injected DID identity in header");
        }
        DidInjectionMode::SignedHeader => {
            // DID document in X-DID-Signed-Identity header
            headers.push((
                "X-DID-Signed-Identity",
                context
                    .did_document()
                    .to_string(),
            ));
            debug!(did = %context.did(), "Injected signed DID document in header");
        }
        DidInjectionMode::ProtocolNative => {
            // Will be handled by protocol-specific code (A2A, MCP)
            debug!(did = %context.did(), "Protocol-native injection mode - handled by protocol layer");
        }
    }
}

/// Handle agent card requests - intercept and potentially modify
#[allow(dead_code)]
pub async fn handle_agent_card(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<ProxyState>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let channel_name = state.surface.name.clone();

    // Extract source address (client IP) - prefer x-forwarded-for if present, otherwise use socket address
    let addr_string = addr.ip().to_string();
    let source_addr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .next()
                .unwrap_or("")
                .trim()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or(&addr_string)
        .to_string();

    info!(
        surface = %channel_name,
        "Intercepting /.well-known/agent-card.json request"
    );

    // Handle payment verification (x402, MPP, or both)
    // When both protocols are enabled, the client can satisfy either one.
    // If no credential is provided, a combined 402 is returned with both
    // x402 JSON body and MPP WWW-Authenticate headers.
    {
        let config_id = state
            .surface
            .surface_id
            .as_str();
        let resource_url = "/.well-known/agent-card.json";
        let empty_body: &[u8] = b""; // Agent card is a GET request

        // A delegated (Model B) x402 policy has no local price/verify config to
        // check here and is never routed through the delegation relay on this
        // endpoint — skip it so an agent-card fetch isn't paywalled against an
        // empty local challenge.
        let x402_required = state
            .surface
            .x402_config()
            .is_some_and(|p| p.enabled && p.provider != crate::config::types::X402Provider::AgentPay);
        let mpp_required = state
            .surface
            .mpp_config()
            .is_some_and(|p| {
                crate::mpp::should_require_payment(
                    p,
                    &state
                        .surface
                        .channel_protocol(),
                    empty_body,
                    None,
                )
            });

        if x402_required || mpp_required {
            let payment_signature = crate::x402::extract_payment_signature(
                &headers,
                &state
                    .config
                    .x402_headers
                    .payment_signature,
            );
            let mpp_credential = crate::mpp::extract_mpp_credential(&headers);

            if x402_required && payment_signature.is_some() {
                // Client sent x402 credential → verify via x402
                match crate::x402::process_payment(
                    payment_signature,
                    state
                        .surface
                        .x402_config()
                        .unwrap(),
                    &channel_name,
                    config_id,
                    &state.config.x402_headers,
                    resource_url,
                    state
                        .listener_manager
                        .read()
                        .await
                        .clone(),
                    state
                        .transaction_store
                        .clone(),
                )
                .await
                {
                    Ok(_) => {}
                    Err(err_response) => return Err(err_response),
                }
            } else if mpp_required && mpp_credential.is_some() {
                // Client sent MPP credential → verify via MPP
                match crate::mpp::process_payment(
                    mpp_credential,
                    state
                        .surface
                        .mpp_config()
                        .unwrap(),
                    &channel_name,
                    config_id,
                    resource_url,
                    state
                        .mpp_transaction_store
                        .clone(),
                    &state.secrets_store,
                )
                .await
                {
                    Ok(_) => {}
                    Err(err_response) => return Err(err_response),
                }
            } else {
                // No credential → return 402 (combined if both protocols enabled)
                let err_response = if x402_required {
                    // Build x402 402 (includes payment requirements normalization)
                    let x402_resp = crate::x402::process_payment(
                        None,
                        state
                            .surface
                            .x402_config()
                            .unwrap(),
                        &channel_name,
                        config_id,
                        &state.config.x402_headers,
                        resource_url,
                        state
                            .listener_manager
                            .read()
                            .await
                            .clone(),
                        state
                            .transaction_store
                            .clone(),
                    )
                    .await
                    .unwrap_err();
                    if mpp_required {
                        // Both enabled → add MPP challenge headers to x402 response
                        crate::mpp::fire_challenge_issued_events(
                            config_id,
                            &channel_name,
                            resource_url,
                            state
                                .mpp_transaction_store
                                .clone(),
                        );
                        crate::mpp::errors::add_mpp_challenges_to_response_resolved(
                            x402_resp,
                            state
                                .surface
                                .mpp_config()
                                .unwrap(),
                            resource_url,
                            &state.secrets_store,
                        )
                        .await
                    } else {
                        x402_resp
                    }
                } else {
                    // Only MPP → standard MPP 402
                    crate::mpp::process_payment(
                        None,
                        state
                            .surface
                            .mpp_config()
                            .unwrap(),
                        &channel_name,
                        config_id,
                        resource_url,
                        state
                            .mpp_transaction_store
                            .clone(),
                        &state.secrets_store,
                    )
                    .await
                    .unwrap_err()
                };
                return Err(err_response);
            }
        }
    }

    let prepared_a2a_proxy_agent_card = prepare_a2a_proxy_agent_card(&state, &channel_name).await?;
    let agent_card_was_synthesized = prepared_a2a_proxy_agent_card.is_some();

    // Build target URL, respecting override_agent_card_location if configured
    let target_url = if prepared_a2a_proxy_agent_card.is_none()
        && state
            .surface
            .override_agent_card_location()
        && state
            .surface
            .agent_card_location_path()
            .is_some()
    {
        let custom_path = state
            .surface
            .agent_card_location_path()
            .unwrap();
        let endpoint = &state.surface.target.endpoint;
        let origin = if let Some(scheme_end) = endpoint.find("://") {
            let after_scheme = &endpoint[scheme_end + 3..];
            let authority_end = after_scheme
                .find('/')
                .unwrap_or(after_scheme.len());
            &endpoint[..scheme_end + 3 + authority_end]
        } else {
            endpoint.as_str()
        };
        if custom_path.starts_with('/') {
            format!("{}{}", origin, custom_path)
        } else {
            format!("{}/{}", origin, custom_path)
        }
    } else {
        crate::proxy::protocol_router::join_endpoint_path(
            &state.surface.target.endpoint,
            "/.well-known/agent-card.json",
        )
    };

    let (mut agent_card, prepared_identity) = if let Some(prepared) = prepared_a2a_proxy_agent_card {
        (prepared.card, prepared.identity)
    } else {
        (fetch_agent_card_from_surface_target(&state, &headers, &source_addr, &channel_name, &target_url).await?, None)
    };

    let card_bytes = serde_json::to_vec(&agent_card).unwrap_or_default();
    let resolved_identity = if let Some(identity) = prepared_identity {
        identity
    } else {
        let card_identity_selector = state
            .protected_selector
            .as_ref()
            .or(state
                .identity_selector
                .as_ref());
        let card_identity_rules = state
            .protected_rules_engine
            .as_ref()
            .or(state
                .identity_rules_engine
                .as_ref());
        match crate::proxy::backend_identity::resolve_protected_agent_identity(
            &card_bytes,
            &state.surface,
            card_identity_selector,
            card_identity_rules,
            &channel_name,
            true,
            None,
        )
        .await
        {
            Ok(identity) => identity,
            Err(e) => {
                warn!(
                    channel = channel_name,
                    error = %e,
                    code = %e.code(),
                    "Protected agent identity resolution failed for agent card intercept"
                );
                return Err(crate::a2a::create_identity_error_response(
                    e.http_status(),
                    e.code(),
                    "protected_identity",
                    &channel_name,
                    &e.to_string(),
                ));
            }
        }
    };

    // External slot resolution (Surface Builder external identity node).
    // Side-effect: issues DID for the external counterparty via vc_issuer.
    if state
        .external_selector
        .is_some()
        && let Err(e) = crate::proxy::backend_identity::resolve_external_agent_identity(
            &card_bytes,
            &state.surface,
            state
                .external_selector
                .as_ref(),
            state
                .external_rules_engine
                .as_ref(),
            &channel_name,
            true,
            None, // agent-card fetch has no inbound caller token
        )
        .await
    {
        warn!(
            channel = channel_name,
            error = %e,
            code = %e.code(),
            "External agent identity resolution failed for agent card intercept"
        );
        return Err(crate::a2a::create_identity_error_response(
            e.http_status(),
            e.code(),
            "external_identity",
            &channel_name,
            &e.to_string(),
        ));
    }

    // Rewrite upstream cards to point back to the proxy; synthesized A2A Proxy
    // cards already derive their URL from the exposing Access Point.
    if !agent_card_was_synthesized {
        let card_bytes = serde_json::to_vec(&agent_card).unwrap_or_default();
        let rewritten = rewrite_agent_card_urls(
            &card_bytes,
            &state.surface,
            &state.config,
            &state.network_config,
            &resolved_identity,
        )
        .await
        .map_err(|e| {
            warn!(channel = channel_name, error = %e, "Failed to rewrite agent card URLs");
            create_error_response(StatusCode::BAD_GATEWAY, "Failed to rewrite agent card URLs")
        })?;
        agent_card = serde_json::from_slice(rewritten.as_ref()).map_err(|e| {
            warn!(channel = channel_name, error = %e, "Failed to parse rewritten agent card JSON");
            create_error_response(StatusCode::BAD_GATEWAY, "Invalid rewritten agent card JSON")
        })?;
    }

    // Replace agent-identity/v1 with agent-identity-credential/v1 (signed VP)
    if let Some(selector) = state
        .identity_selector
        .as_ref()
    {
        let vc_issuer = selector.get_vc_issuer();
        if let Err(e) = crate::a2a::inject_credential_into_agent_card(
            &mut agent_card,
            &resolved_identity,
            &vc_issuer,
            &channel_name,
        )
        .await
        {
            error!(channel = channel_name, error = %e, "Failed to inject identity credential into agent card");
            return Err(create_error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Agent card identity credential injection failed: {}", e),
            ));
        }
    }

    // Inject Agent DNA + DID from the channel's did:webvh identity into the agent card.
    // Per the February demo design: DNA is randomly generated at identity creation time
    // and surfaced here so callers (other agents, UI clients) can observe the UAI / DNA
    // without needing to resolve the did.jsonl separately.
    #[cfg(feature = "didwebvh")]
    if let (Some(did_config), Some(identity_store)) = (
        state
            .surface
            .didwebvh_identity_legacy(),
        state
            .didwebvh_identity_store
            .as_ref(),
    ) {
        match identity_store
            .get(&did_config.identity_id)
            .await
        {
            Ok(Some(identity)) => {
                if let Some(obj) = agent_card.as_object_mut() {
                    obj.insert("agentDid".to_string(), JsonValue::String(identity.did.clone()));
                    if let Some(dna_value) = identity
                        .metadata
                        .get("agentDNA")
                    {
                        obj.insert("agentDNA".to_string(), dna_value.clone());
                        info!(
                            channel = channel_name,
                            did = %identity.did,
                            "Injected agentDNA into agent card"
                        );
                    }
                }
            }
            Ok(None) => {
                warn!(
                    channel = channel_name,
                    identity_id = %did_config.identity_id,
                    "Configured did:webvh identity not found — skipping DNA injection"
                );
            }
            Err(e) => {
                warn!(
                    channel = channel_name,
                    identity_id = %did_config.identity_id,
                    error = %e,
                    "Failed to load did:webvh identity for agent card — skipping DNA injection"
                );
            }
        }
    }

    info!(channel = channel_name, "Successfully fetched and parsed agent card");

    // Trust Recorder — writes TrAdmin records to configured TRs on the
    // discovery (agent-card) fetch, so a fresh surface populates its trust
    // registry on the first `.well-known/agent-card.json` request instead of
    // waiting for the first real message. Fire-and-forget; idempotent —
    // duplicate records log at DEBUG (`apply_trust_recorder`), so firing on
    // every discovery is safe.
    if let ProtectedAgentIdentity::Managed { did, .. } = &resolved_identity {
        crate::trust_registry_verification::spawn_trust_recorder(
            &state.surface,
            did,
            state
                .trust_registry_listener_manager
                .clone(),
        );
    }

    // Record successful connection in metrics
    // Only tag as UCP "discovery" when the channel is actually a UCP channel
    if let Some(ref metrics) = state.metrics_store {
        let metrics = Arc::clone(metrics);
        let channel_config_id = state
            .surface
            .surface_id
            .clone();
        let source = source_addr.clone();
        let dest = state
            .surface
            .target
            .endpoint
            .clone();
        let ucp_operation = if state.surface.is_ucp() {
            Some("discovery".to_string())
        } else {
            None
        };
        let variant_alias = state
            .active_variant_alias
            .clone();
        tokio::spawn(async move {
            metrics
                .record_connection_with_ucp(
                    channel_config_id,
                    source,
                    dest,
                    crate::metrics::ConnectionStatus::Success,
                    None,
                    None,
                    crate::metrics::ConnectionDirection::Request,
                    uuid::Uuid::new_v4().to_string(),
                    ucp_operation,
                    None,
                    None,
                    0,
                    variant_alias,
                )
                .await;
        });
    }

    // Negotiate the agent-card media type: A2A 1.0.1 prefers
    // `application/a2a+json`, but it is only served to callers that signalled 1.0
    // (via `A2A-Version` or `Accept`) so 0.3 clients and tools that strict-check
    // `application/json` are unaffected.
    Ok(agent_card_response(agent_card, &headers))
}

/// Serialize an agent card with the media type negotiated from the request's
/// `A2A-Version` / `Accept` headers, and a `Vary` naming those headers so a
/// shared cache keys each variant separately.
fn agent_card_response(
    agent_card: JsonValue,
    headers: &HeaderMap,
) -> Response {
    use axum::http::{HeaderValue, header};

    let content_type = crate::a2a::version::agent_card_content_type(headers);
    let mut response = Json(agent_card).into_response();
    let response_headers = response.headers_mut();
    response_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response_headers.append(header::VARY, HeaderValue::from_static("A2A-Version, Accept"));
    response
}

/// Process AP2 VDC transformation pipeline
///
/// This function handles the complete AP2 credential transformation:
/// 1. Parse message body as JSON
/// 2. Extract VDC mandate from message
/// 3. Validate VDC signature
/// 4. Transform VDC to W3C Verifiable Credential (using agent DID if available)
/// 5. Create Verifiable Presentation (signed with agent key if available)
/// 6. Inject VP JWT into message metadata
async fn process_ap2_vdc_transformation(
    body_bytes: &[u8],
    state: &ProxyState,
    agent_identity: Option<(String, std::collections::HashMap<String, serde_json::Value>)>,
) -> anyhow::Result<Vec<u8>> {
    use serde_json::Value as JsonValue;

    // Parse message body
    let mut message: JsonValue =
        serde_json::from_slice(body_bytes).map_err(|e| anyhow::anyhow!("Failed to parse AP2 message: {}", e))?;

    // Get gateway DID as fallback
    let gateway_did = if let Some(ref selector) = state.identity_selector {
        selector
            .get_vc_issuer()
            .get_issuer_did()
            .await
            .ok()
            .unwrap_or_else(|| "did:example:gateway".to_string())
    } else {
        "did:example:gateway".to_string()
    };

    // Get VC issuer for signing operations
    let vc_issuer_opt = state
        .identity_selector
        .as_ref()
        .map(|selector| selector.get_vc_issuer());

    // Process AP2 message (VDC→VC→VP transformation)
    // Uses agent identity if available, otherwise falls back to gateway identity
    crate::ap2::process_ap2_message(&mut message, &gateway_did, &vc_issuer_opt, &agent_identity)
        .await
        .map_err(|e| anyhow::anyhow!("AP2 VDC transformation failed: {}", e))?;

    // Serialize modified message back to bytes
    let modified_bytes =
        serde_json::to_vec(&message).map_err(|e| anyhow::anyhow!("Failed to serialize AP2 message: {}", e))?;

    Ok(modified_bytes)
}

fn ap2_experimental_enabled_from_flags(feature_flags: Option<&std::collections::HashMap<String, bool>>) -> bool {
    feature_flags
        .and_then(|flags| {
            flags
                .get("ap2_experimental")
                .copied()
        })
        .unwrap_or(false)
}

fn ap2_experimental_enabled() -> bool {
    crate::storage::settings_store::global_settings()
        .map(|s| ap2_experimental_enabled_from_flags(Some(&s.feature_flags)))
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ap2InboundDecision {
    ForwardOriginal,
    RejectFeatureDisabled,
    Transform,
    RejectTransformationFailed,
    ForwardTransformed,
}

fn evaluate_ap2_inbound_decision(
    is_ap2_post_with_body: bool,
    ap2_enabled: bool,
    transformation_succeeded: Option<bool>,
) -> Ap2InboundDecision {
    if !is_ap2_post_with_body {
        return Ap2InboundDecision::ForwardOriginal;
    }

    if !ap2_enabled {
        return Ap2InboundDecision::RejectFeatureDisabled;
    }

    match transformation_succeeded {
        Some(true) => Ap2InboundDecision::ForwardTransformed,
        Some(false) => Ap2InboundDecision::RejectTransformationFailed,
        None => Ap2InboundDecision::Transform,
    }
}

async fn resolve_direct_surface_auth_config(
    auth_config: &crate::source_auth::SourceAuthConfig,
    vc_issuer: Option<&crate::identity::VCIssuer>,
    surface_id: &str,
) -> crate::source_auth::errors::SourceAuthResult<crate::source_auth::SourceAuthConfig> {
    crate::source_auth::middleware::resolve_surface_audience(auth_config, vc_issuer, surface_id).await
}

/// Maps the config-level delegated-rail marker onto the audit `PaymentRail`.
fn map_delegated_rail(
    rail: &crate::config::types::DelegatedPaymentRail
) -> crate::delegation_vault::audit::PaymentRail {
    if rail.is_x402() {
        crate::delegation_vault::audit::PaymentRail::X402
    } else {
        crate::delegation_vault::audit::PaymentRail::Mpp
    }
}

/// Records one payment-lifecycle audit event for the Model B fabric relay, using
/// the same protocol-independent `PaymentEvent` action the local x402/MPP stores
/// emit. The delegate leg owns no local transaction, so the request `trace_id`
/// doubles as the correlation id and `delegated` / remote-id / remote-status
/// fields carry the relay context. `extra_detail` is folded into the failure
/// `error` for a denied/misconfigured outcome. On `proceed` this also issues a
/// `PaymentAccessGrantCredential` ( agent-gateway attests to granting access on
/// a payment it relayed, not to settlement — that is the remote payment
/// gateway's own responsibility to attest to); on a denial it issues a
/// `PaymentRejectionCredential` instead.
async fn audit_payment_delegation(
    config_id: &str,
    channel_name: &str,
    trace_id: &str,
    rail: crate::delegation_vault::audit::PaymentRail,
    payment_gateway_id: &str,
    payment_surface_id: &str,
    outcome: &str,
    status_code: u16,
    extra_detail: Option<&str>,
) {
    use crate::delegation_vault::audit::{PaymentEventDetails, PaymentStage, record_payment_event};
    let stage = match outcome {
        "proceed" => PaymentStage::Verified,
        "challenge" => PaymentStage::ChallengeIssued,
        _ => PaymentStage::Failed,
    };
    let error = (stage == PaymentStage::Failed).then(|| match extra_detail {
        Some(msg) => format!("{outcome}: {msg}"),
        None => outcome.to_string(),
    });
    let rail_tag = if rail == crate::delegation_vault::audit::PaymentRail::X402 {
        "x402"
    } else {
        "mpp"
    };
    let vc = match stage {
        PaymentStage::Verified => {
            crate::payment_credentials::issue_access_grant(crate::payment_credentials::AccessGrantInput {
                rail: rail_tag,
                trace_id: Some(trace_id.to_string()),
                payment_gateway_id: (!payment_gateway_id.is_empty()).then(|| payment_gateway_id.to_string()),
                payment_surface_id: (!payment_surface_id.is_empty()).then(|| payment_surface_id.to_string()),
                remote_status: status_code,
            })
            .await
        }
        PaymentStage::Failed => {
            crate::payment_credentials::issue_payment_rejection(crate::payment_credentials::PaymentRejectionInput {
                rail: rail_tag,
                payment_id: trace_id.to_string(),
                trace_id: Some(trace_id.to_string()),
                method: None,
                payer: None,
                reason: error
                    .clone()
                    .unwrap_or_else(|| outcome.to_string()),
            })
            .await
        }
        _ => None,
    };
    record_payment_event(
        PaymentEventDetails {
            rail,
            stage,
            transaction_id: trace_id.to_string(),
            amount: None,
            currency: None,
            method: None,
            payer: None,
            error,
            delegated: true,
            payment_gateway_id: (!payment_gateway_id.is_empty()).then(|| payment_gateway_id.to_string()),
            payment_surface_id: (!payment_surface_id.is_empty()).then(|| payment_surface_id.to_string()),
            remote_status: Some(status_code),
        },
        Some(config_id),
        Some(channel_name),
        Some(trace_id),
        true,
        vc.as_ref()
            .map(|c| c.jwt.as_str()),
    );
}

fn access_point_upstream_key(state: &ProxyState) -> crate::mcp::upstream_versions::UpstreamKey {
    crate::mcp::upstream_versions::UpstreamKey {
        surface_id: state
            .surface
            .surface_id
            .clone(),
        route: crate::mcp::upstream_versions::UpstreamRoute::AccessPoint(
            state
                .active_variant_id
                .clone(),
        ),
        target: state
            .surface
            .target
            .endpoint
            .clone(),
    }
}

/// True when the surface authorizes or filters MCP results per caller: a
/// surface or variant OPA policy (which also filters `tools/list`), MCP tool
/// gating, or a response policy. Gateway-level OPA only admits requests, so it
/// leaves upstream cache hints intact, as on Transit Points.
fn caller_scoped_mcp_result(
    surface: &crate::config::agent_surface::AgentSurface,
    policy_manager: Option<&crate::policies::SurfacePolicyManager>,
    variant_alias: Option<&str>,
) -> bool {
    surface
        .response_policy_definition_id()
        .is_some()
        || policy_manager.is_some_and(|manager| {
            manager.has_policy_for_variant(&surface.surface_id, variant_alias)
                || manager
                    .compiled_mcp_tool_gating(&surface.surface_id, variant_alias)
                    .is_some_and(|gating| !gating.is_empty())
        })
}

/// The key a local surface's open listens are counted under, shared by its
/// Access Point and Fabric receive paths.
pub(crate) fn listen_surface_key(surface: &crate::config::agent_surface::AgentSurface) -> String {
    let id = if surface.surface_id.is_empty() {
        &surface.name
    } else {
        &surface.surface_id
    };
    format!("surface:{id}")
}

async fn proxy_handler_with_mcp_runtime(
    addr: SocketAddr,
    state: ProxyState,
    req: Request,
    mcp_versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
    mcp_continuations: Option<Arc<crate::mcp::continuations::config::ContinuationRuntime>>,
) -> Result<Response, Response> {
    let mut subscription_access = crate::mcp::subscriptions::SubscriptionLifetime::new(
        std::time::Duration::from_secs(
            state
                .surface
                .mcp_http
                .clone()
                .unwrap_or_default()
                .stream_max_lifetime_secs
                .get(),
        ),
        None,
    );
    let channel_name = state.surface.name.clone();
    let config_id = state
        .surface
        .surface_id
        .as_str();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Start timing the request
    let start_time = std::time::Instant::now();

    // Trace id for this request. A trusted internal forward (fabric G2G / Transit
    // Point) carries the originating request's id in `X-Gateway-Trace-Id`; reusing
    // it keeps ONE correlatable trace id across every hop — metrics, audit, the
    // "This request" filter, and the injected VP `workloadBinding.traceId` — so a
    // caller → GW1 → TP → GW2 chain shares a single trace end-to-end instead of a
    // fresh per-hop id. The header is only honoured when it parses as a UUID: an
    // external caller could set it, but a spoofed value can at worst pollute
    // correlation (never an authorization decision), and the UUID check blocks
    // log/field injection. A missing or malformed value mints a fresh id, so the
    // external entry hop (where callers don't send the header) always starts a new
    // trace.
    let trace_id = crate::proxy::trace::continue_or_mint_trace_id(
        headers
            .get("X-Gateway-Trace-Id")
            .and_then(|v| v.to_str().ok()),
    );

    // Trace-id termination is an EGRESS firewall: this gateway keeps the incoming
    // `trace_id` for its own VP + audit (so the caller → … → here chain stays
    // traceable) and forwards a FRESH id downstream, so the trace never crosses
    // this boundary. `egress_trace_id` is what gets stamped on the onward hop
    // (`X-Gateway-Trace-Id`, the transit token, the fabric message); it equals
    // `trace_id` unless the surface opts into termination.
    let egress_trace_id = crate::proxy::trace::egress_trace_id(
        state
            .surface
            .access_point
            .terminate_trace_id,
        &trace_id,
    );

    // Bridge for this gateway's operator on the non-fabric (direct / transit-point)
    // egress: record the own → downstream mapping locally so a terminated trace can
    // still be followed past the boundary. The fabric path emits its own bridge from
    // `handle_fabric_request`, so skip fabric targets here to avoid a double record.
    // Public/discovery paths are skipped too (no caller identity, bypass OPA/VP), so
    // a discovery fetch doesn't add a noise bridge record.
    if egress_trace_id != trace_id
        && !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && !state
            .surface
            .target
            .endpoint
            .starts_with("fabric://")
    {
        let flow = if state
            .surface
            .transit_points()
            .is_empty()
        {
            "access_point"
        } else {
            "transit_point"
        };
        channel_info!(
            config_id,
            "🔀 Trace terminated at egress: own trace {} continues downstream as {}",
            trace_id,
            egress_trace_id
        );
        crate::delegation_vault::audit::audit_trace_terminated(
            Some(config_id),
            &trace_id,
            &egress_trace_id,
            flow,
            false,
        );
    }

    // Extract UCP operation type from request path and method (if this is a UCP channel).
    let mut ucp_operation = extract_ucp_operation(uri.path(), &method);

    if let Some(ref op) = ucp_operation {
        channel_info!(
            config_id,
            "🟢 INNER HANDLER ENTRY: trace_id={} method={} path={} ucp_op={}",
            trace_id,
            method,
            uri.path(),
            op
        );
    } else {
        channel_info!(config_id, "🟢 INNER HANDLER ENTRY: trace_id={} method={} path={}", trace_id, method, uri.path());
    }

    // Track active connection for this task and create guard for cleanup
    let mut connection_guard = ConnectionGuard::new(state.task_monitor.clone(), state.task_id.clone());
    if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
        task_monitor
            .increment_connections(task_id)
            .await;
    }

    // Extract source address (client IP) - prefer x-forwarded-for if present, otherwise use socket address
    let addr_string = addr.ip().to_string();
    let source_addr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .next()
                .unwrap_or("")
                .trim()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or(&addr_string)
        .to_string();

    channel_info!(config_id, "Proxying request: method={} path={}", method, uri.path());

    if uri
        .path()
        .ends_with("/.well-known/agent-card.json")
        || uri
            .path()
            .ends_with("/.well-known/agent.json")
    {
        let response = match handle_agent_card(ConnectInfo(addr), State(state.clone()), headers.clone()).await {
            Ok(response) | Err(response) => response,
        };
        connection_guard
            .decrement()
            .await;
        return Ok(response);
    }

    // Special handling for DID Auth challenge and authenticate endpoints
    // Check if this is a DID Auth request to /authenticate/challenge or /authenticate
    let path = uri.path();
    if path.ends_with("/authenticate/challenge") || path.ends_with("/authenticate") {
        // Check if this is a DID Auth request to /authenticate/challenge or /authenticate
        let didauth_cfg = match state.surface.source_auth() {
            Some(crate::source_auth::SourceAuthConfig::DidAuth(cfg)) => Some(cfg.clone()),
            _ => None,
        };

        if let Some(cfg) = didauth_cfg {
            channel_info!(config_id, "DID Auth request detected: {}", path);

            // Read the request body
            let (_parts, body) = req.into_parts();
            let body_bytes = axum::body::to_bytes(body, usize::MAX)
                .await
                .map_err(|e| {
                    create_error_response(StatusCode::BAD_REQUEST, &format!("Failed to read request body: {}", e))
                })?;

            let handler_state = crate::didauth::handlers::DidAuthHandlerState {
                session_store: state
                    .didauth_session_store
                    .clone(),
                config: std::sync::Arc::new(cfg),
                surface_id: state
                    .surface
                    .surface_id
                    .clone(),
            };

            // Route to appropriate handler based on path
            let response = if path.ends_with("/authenticate/challenge") {
                use crate::didauth::handlers::{ChallengeRequest, challenge_handler};

                let challenge_req: ChallengeRequest = serde_json::from_slice(&body_bytes)
                    .map_err(|e| create_error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)))?;

                challenge_handler(State(handler_state), Json(challenge_req)).await
            } else {
                use crate::didauth::handlers::{AuthenticateRequest, authenticate_handler};

                let auth_req: AuthenticateRequest = serde_json::from_slice(&body_bytes)
                    .map_err(|e| create_error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)))?;

                authenticate_handler(State(handler_state), Json(auth_req)).await
            };

            return Ok(response);
        }
    }

    // Special handling for temporary onboarding channels - capture payload and return mock response
    if state.surface.is_onboarding() {
        return handle_onboarding_request(
            state,
            &channel_name,
            method,
            uri,
            headers,
            source_addr,
            start_time,
            connection_guard,
            req,
        )
        .await;
    }

    // ── Unified source authentication ──────────────────────────────────────
    // Must run before rate limiting so unauthenticated requests are rejected
    // before consuming any rate-limit budget.
    // Public paths (e.g. agent-card) bypass all authentication gates.
    // Caller-attributable source-auth failures are non-blocking: the outcome is
    // handed to the policy layer via `source_auth_context` below, which decides
    // whether to allow or deny. Only server-side failures (setup/config
    // resolution, internal errors) still block here (now with a 500).
    let resource_authorization = state
        .surface
        .mcp_http
        .as_ref()
        .and_then(|http| http.authorization.as_ref())
        .map(|authorization| {
            authorization.for_variant(
                state
                    .active_variant_alias
                    .as_deref(),
            )
        })
        .transpose()
        .map_err(|_| create_error_response(StatusCode::SERVICE_UNAVAILABLE, "Invalid MCP resource authorization"))?;
    let mut source_auth_failure: Option<crate::surface_context::SourceAuthContext> = None;
    let authenticated_identity: Option<crate::source_auth::AuthenticatedIdentity> = if let Some(authorization) =
        &resource_authorization
    {
        let Some((profile, issuer, middleware)) = state
            .network_config
            .sts
            .mcp_issuer
            .as_ref()
            .zip(state.vc_issuer.as_deref())
            .zip(
                state
                    .source_auth_middleware
                    .as_ref(),
            )
            .map(|((profile, issuer), middleware)| (profile, issuer, middleware))
        else {
            return Ok(authorization.challenge(crate::mcp::resource_server::ResourceTokenError::Unavailable));
        };
        let public_origins = state
            .network_config
            .map_url_to_port(
                &state
                    .surface
                    .access_point
                    .listen_address,
            )
            .and_then(|port| {
                state
                    .network_config
                    .get_listener_by_port(port)
            })
            .map(|listener| listener.external_urls.clone())
            .unwrap_or_default();
        let expected_path = match state
            .active_variant_alias
            .as_deref()
        {
            Some(alias) => format!(
                "{}${alias}",
                state
                    .surface
                    .access_point
                    .route
            ),
            None => state
                .surface
                .access_point
                .route
                .clone(),
        };
        if state
            .surface
            .access_point
            .protocol
            != crate::config::agent_surface::SurfaceProtocol::Mcp
            || state
                .surface
                .source_auth()
                .is_some()
            || authorization
                .validate_endpoint(&public_origins, &expected_path)
                .is_err()
            || profile
                .validate_network(&state.network_config)
                .is_err()
        {
            return Ok(authorization.challenge(crate::mcp::resource_server::ResourceTokenError::Unavailable));
        }
        match authorization
            .authenticate(&headers, profile, issuer, middleware.jwks_client())
            .await
        {
            Ok(identity) => Some(identity),
            Err(error) => return Ok(authorization.challenge(error)),
        }
    } else if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && let (Some(auth_config), Some(sa_middleware)) = (state.surface.source_auth(), &state.source_auth_middleware)
    {
        let resolved_auth_config = match resolve_direct_surface_auth_config(
            auth_config,
            state.vc_issuer.as_deref(),
            &state.surface.surface_id,
        )
        .await
        {
            Ok(config) => config,
            Err(e) => {
                // Setup/config-resolution failure is a server-side problem,
                // not a caller decision — keep blocking.
                channel_warn!(config_id, "Source authentication setup failed (reason={}) — blocking", e);
                connection_guard
                    .decrement()
                    .await;
                return Err(crate::source_auth::errors::deny_response(
                    &state
                        .surface
                        .access_point
                        .protocol,
                    auth_config,
                    &e,
                ));
            }
        };
        let peer_cert = req
            .extensions()
            .get::<crate::source_auth::models::PeerCertInfo>();
        match sa_middleware
            .authenticate(&resolved_auth_config, &headers, &channel_name, &state.surface.surface_id, peer_cert)
            .await
        {
            Ok(identity) => Some(identity),
            // Caller-attributable failure (missing/invalid credential):
            // record the outcome for the policy layer and continue with no
            // asserted caller identity — do not block here.
            Err(e) if e.is_caller_attributable() => {
                channel_warn!(config_id, "Source authentication failed (reason={}) — deferring to policy", e);
                source_auth_failure = Some(crate::surface_context::SourceAuthContext::Failed {
                    attempted_method: resolved_auth_config
                        .method_tag()
                        .to_string(),
                    reason: e.to_string(),
                });
                None
            }
            // Server-side failure (config not found, internal) — keep
            // blocking (500).
            Err(e) => {
                channel_warn!(config_id, "Source authentication error (reason={}) — blocking", e);
                connection_guard
                    .decrement()
                    .await;
                return Err(crate::source_auth::errors::deny_response(
                    &state
                        .surface
                        .access_point
                        .protocol,
                    &resolved_auth_config,
                    &e,
                ));
            }
        }
    } else {
        None
    };

    // Merged source-auth context for policy inputs: the verified identity on
    // success, or a `Failed` marker on a non-blocking caller-attributable
    // failure. `None` when no source auth is configured.
    let source_auth_failed = source_auth_failure.is_some();

    let source_auth_context: Option<crate::surface_context::SourceAuthContext> = authenticated_identity
        .as_ref()
        .map(crate::surface_context::SourceAuthContext::from)
        .or(source_auth_failure);

    // Stamp the authenticated caller's identity onto the root HTTP span so
    // operators can attribute the trace (and any later policy-deny) to a
    // caller. No-op unless opted in via `traces.record_caller_identity`.
    if let Some(identity) = authenticated_identity.as_ref() {
        crate::observability::record_caller_identity_on_current_span(identity);
    }

    // Check rate limit for this channel (applies to both A2A and MCP protocols, including fabric:// connections)
    // This check must happen BEFORE fabric routing to ensure fabric connections are rate limited
    if let Some(ref policy_manager) = state.policy_manager
        && let Some(rate_limit_config_id) = state.surface.config_id()
    {
        match policy_manager
            .check_rate_limit(rate_limit_config_id)
            .await
        {
            Ok(_) => {
                channel_debug!(config_id, "Rate limit check passed");
            }
            Err(e) => {
                warn!(channel = channel_name, error = %e, "Rate limit exceeded");

                // For MCP protocol, return JSON-RPC error with HTTP 429 status
                if state
                    .surface
                    .channel_protocol()
                    == crate::config::ChannelProtocol::Mcp
                {
                    let error_response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32000,
                            "message": "Rate limit exceeded",
                            "data": {
                                "retry_after": e.to_string()
                            }
                        },
                        "id": null
                    });

                    // Return with HTTP 429 status code
                    let mut response = axum::response::Json(error_response).into_response();
                    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;

                    // Add Retry-After header
                    if let Ok(retry_secs) = e.to_string().parse::<u64>() {
                        response.headers_mut().insert(
                            axum::http::header::RETRY_AFTER,
                            axum::http::HeaderValue::from_str(&retry_secs.to_string())
                                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("60")),
                        );
                    }

                    connection_guard
                        .decrement()
                        .await;
                    return Ok(response);
                } else {
                    // For A2A protocol, return HTTP 429 Too Many Requests
                    let mut response = create_error_response(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded");

                    // Add Retry-After header (extract seconds from error string)
                    if let Ok(retry_secs) = e.to_string().parse::<u64>() {
                        response.headers_mut().insert(
                            axum::http::header::RETRY_AFTER,
                            axum::http::HeaderValue::from_str(&retry_secs.to_string())
                                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("60")),
                        );
                    }

                    connection_guard
                        .decrement()
                        .await;
                    return Err(response);
                }
            }
        }
    }

    let mcp_versions =
        crate::mcp::request_validation::admission_policy_for_target(mcp_versions, &state.surface.target.endpoint);
    let mcp_http = if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
    {
        Some(
            crate::mcp::modern_http::EndpointHttpPolicy::with_versions(
                state
                    .surface
                    .mcp_http
                    .as_ref(),
                &state
                    .network_config
                    .get_inbound_external_urls(),
                mcp_versions,
            )
            .map_err(|error| {
                channel_warn!(config_id, "Invalid MCP HTTP configuration: {}", error);
                create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid MCP HTTP configuration")
            })?,
        )
    } else {
        None
    };
    if let Some(policy) = &mcp_http
        && let Err(error) = policy.validate_headers(&headers)
    {
        connection_guard
            .decrement()
            .await;
        return Ok(error.into_response(None));
    }
    if let Some(policy) = &mcp_http
        && let Some(response) = policy.non_post_response(&method, &headers)
    {
        connection_guard
            .decrement()
            .await;
        return Ok(response);
    }

    // Extract body early for payment verification and fabric forwarding
    // Body is needed to check payment requirements based on request content
    let mut body_bytes = axum::body::to_bytes(
        req.into_body(),
        mcp_http
            .as_ref()
            .map_or(usize::MAX, |policy| policy.body_limit()),
    )
    .await
    .map_err(|e| {
        error!(channel = channel_name, error = %e, "Failed to read request body");
        // Track error (connection guard will be dropped automatically)
        if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
            let task_id = task_id.clone();
            let monitor = task_monitor.clone();
            tokio::spawn(async move {
                info!(task_id = %task_id, "Recording error: Failed to read request body");
                monitor
                    .increment_errors(&task_id)
                    .await;
            });
        }
        // Connection guard will automatically decrement when dropped
        if let Some(policy) = &mcp_http {
            return (*policy.body_read_error(e)).into_response();
        }
        create_error_response(StatusCode::BAD_REQUEST, "Failed to read request body")
    })?;

    let (mcp_metadata_context, validated_mcp_session_id, mcp_verified_binding, mcp_classification) = if let Some(policy) =
        &mcp_http
        && method == Method::POST
    {
        let (session_evidence, known_session_id) = resolve_legacy_mcp_session(&headers).await;
        let classification = match policy.admit_post(&headers, &body_bytes, session_evidence) {
            Ok(classification) => classification,
            Err(validation_error) => {
                channel_warn!(
                    config_id,
                    "Rejecting MCP request at protocol boundary: code={} message={}",
                    validation_error.code,
                    validation_error.message
                );
                connection_guard
                    .decrement()
                    .await;
                return Ok((*crate::mcp::upstream_versions::restrict_unsupported(
                    validation_error,
                    &access_point_upstream_key(&state),
                ))
                .into_response());
            }
        };
        let mcp_metadata_context = crate::mcp::meta::McpMetadataContext::from_classification(
            &classification,
            state
                .surface
                .mcp_legacy_metadata_output,
        );
        if let Err(error) = state
            .surface
            .validate_mcp_metadata_base()
        {
            channel_warn!(config_id, "Invalid MCP metadata configuration: {}", error);
            connection_guard
                .decrement()
                .await;
            return Err(create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid MCP metadata configuration"));
        }
        body_bytes = match crate::mcp::meta::normalize_bytes(&body_bytes, mcp_metadata_context) {
            Ok(body) => body,
            Err(error) => {
                connection_guard
                    .decrement()
                    .await;
                return Ok(error.into_response(&body_bytes, StatusCode::BAD_REQUEST));
            }
        };
        if let Some(capped) = policy.cap_legacy_initialize(&body_bytes, &classification) {
            channel_info!(
                config_id,
                "Forwarding MCP initialize with protocolVersion {} in place of unsupported {}",
                capped.offered,
                capped.requested_for_log()
            );
            body_bytes = capped.body;
        }
        let binding = crate::protocols::extensions::verify_mcp_metadata_identity(
            &body_bytes,
            state.vc_issuer.as_ref(),
            config_id,
            None,
        )
        .await
        .map_err(|error| {
            warn!(channel = channel_name, error = %error, "Invalid MCP identity presentation");
            create_error_response(StatusCode::UNPROCESSABLE_ENTITY, "Invalid MCP identity presentation")
        })?;
        let session_id = if matches!(
            classification,
            crate::mcp::request_validation::McpRequestClassification::Legacy(
                crate::mcp::request_validation::LegacyRequestKind::Session
            )
        ) {
            known_session_id
        } else {
            None
        };
        (mcp_metadata_context, session_id, binding, Some(classification))
    } else {
        (
            crate::mcp::meta::McpMetadataContext::legacy(
                state
                    .surface
                    .mcp_legacy_metadata_output,
            ),
            None,
            None,
            None,
        )
    };

    let mut modern_request = match mcp_classification.as_ref() {
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) => Some((**request).clone()),
        _ => None,
    };
    if let Some(request) = modern_request.as_ref()
        && let Some(error) = state
            .variant_resolution_error
            .as_ref()
    {
        connection_guard
            .decrement()
            .await;
        let status = match error {
            crate::config::agent_surface_variants::VariantResolveError::UnknownAlias(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        return Ok(crate::mcp::request_validation::McpRequestValidationError {
            status,
            id: request.id.clone(),
            code: crate::mcp::error_codes::INTERNAL_ERROR,
            message: "MCP surface variant is unavailable".into(),
            data: None,
        }
        .into_response());
    }
    let subscription_lifetime = if let Some(request) = modern_request
        .as_ref()
        .filter(|request| request.method == "subscriptions/listen")
    {
        let caller = crate::mcp::subscriptions::listen_caller(authenticated_identity.as_ref(), &addr.ip().to_string());
        let Some(slot) =
            crate::mcp::subscriptions::ListenSlots::global().acquire(&listen_surface_key(&state.surface), &caller)
        else {
            connection_guard
                .decrement()
                .await;
            return Ok(crate::mcp::subscriptions::listen_limit_error(request).into_response());
        };
        subscription_access.hold(slot);
        if let Some(vault) = &state.delegation_vault_store
            && subscription_access
                .watch_vault(vault.clone())
                .await
                .is_err()
        {
            connection_guard
                .decrement()
                .await;
            return Ok(crate::mcp::request_validation::McpRequestValidationError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                id: request.id.clone(),
                code: crate::mcp::error_codes::INTERNAL_ERROR,
                message: "MCP subscription authorization unavailable".into(),
                data: None,
            }
            .into_response());
        }
        subscription_access.restrict_to_identity(authenticated_identity.as_ref());
        Some(subscription_access)
    } else {
        None
    };
    let mut headers = if modern_request.is_some() {
        let mut headers = headers;
        crate::mcp::modern_http::strip_protocol_session_headers(&mut headers);
        headers
    } else {
        headers
    };
    if resource_authorization.is_some() {
        headers.remove(axum::http::header::AUTHORIZATION);
    }

    // ── Inbound access-point protocol enforcement ──────────────────────────
    // Symmetric to the outbound transit-point guard: if the request body is
    // positively identifiable as a *different* protocol family than the one
    // this access point is configured for, reject it before any further
    // processing. Negative detection only — ambiguous bodies (non-JSON,
    // JSON-RPC responses, MCP `initialize`, discovery GETs, unrecognised
    // methods) and protocols without a clean detector (`didcomm`)
    // pass through untouched.
    if method == "POST"
        && !body_bytes.is_empty()
        && !matches!(
            mcp_classification.as_ref(),
            Some(crate::mcp::request_validation::McpRequestClassification::Modern(_))
        )
        && let Some(expected) = crate::protocols::channel_protocol_family(
            &state
                .surface
                .channel_protocol(),
        )
        && let Some(detected) = crate::protocols::detect_request_protocol_family(&body_bytes)
        && expected != detected
    {
        warn!(
            channel = channel_name,
            expected, detected, "Rejecting inbound request: body protocol does not match access point protocol"
        );
        if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
            let task_id = task_id.clone();
            let monitor = task_monitor.clone();
            tokio::spawn(async move {
                monitor
                    .increment_errors(&task_id)
                    .await;
            });
        }
        // Connection guard will automatically decrement when dropped.
        return Err(create_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("Request protocol '{detected}' does not match access point protocol '{expected}'"),
        ));
    }

    // ── Header Metadata Mapping (A2A/AP2 Access Point boundary) ───────────
    // Runs after source authentication and body read, before agent context,
    // identity extraction, Trust Check, OPA, and forwarding. It normalizes
    // selected transport headers into protocol-native A2A message metadata;
    // the original filtered HTTP headers remain visible to OPA via
    // `input.http.headers` because `headers` itself is not mutated.
    if method == Method::POST
        && !body_bytes.is_empty()
        && matches!(
            state
                .surface
                .channel_protocol(),
            crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2
        )
        && let Some(mapping) = state
            .surface
            .access_point
            .header_metadata_mapping
            .as_ref()
    {
        let diagnostics = mapping.diagnostics(&headers);
        let identity_extraction_reads_mapped_extension = matches!(
            state.surface.inbound_identity(),
            Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg))
                if cfg.identity_extension_uri() == mapping.extension_uri.as_str()
        );
        match crate::a2a::inject_header_metadata_extension(&body_bytes, mapping, &headers, &channel_name) {
            Ok((modified_body, mapped_count)) => {
                info!(
                    channel = channel_name,
                    surface_id = %config_id,
                    extension_uri = %diagnostics.extension_uri,
                    mapped_count,
                    configured_fields = ?diagnostics.configured_fields,
                    mapped_fields = ?diagnostics.mapped_fields,
                    missing_headers = ?diagnostics.missing_headers,
                    strip_mapped_headers = diagnostics.strip_mapped_headers,
                    identity_extraction_reads_mapped_extension,
                    result = if mapped_count > 0 { "applied" } else { "skipped" },
                    "Header Metadata Mapping evaluated"
                );
                if mapped_count > 0 {
                    body_bytes = modified_body;
                }
            }
            Err(e) => {
                warn!(
                    channel = channel_name,
                    surface_id = %config_id,
                    extension_uri = %diagnostics.extension_uri,
                    configured_fields = ?diagnostics.configured_fields,
                    mapped_fields = ?diagnostics.mapped_fields,
                    missing_headers = ?diagnostics.missing_headers,
                    strip_mapped_headers = diagnostics.strip_mapped_headers,
                    identity_extraction_reads_mapped_extension,
                    error = %e,
                    "Header Metadata Mapping failed"
                );
                connection_guard
                    .decrement()
                    .await;
                return Err(create_error_response(StatusCode::BAD_REQUEST, "Header Metadata Mapping failed"));
            }
        }
    }

    // Try to extract UCP operation from request body if not already detected from path
    // This handles MCP and A2A transports where operation is in the body
    if ucp_operation.is_none() {
        ucp_operation = extract_ucp_operation_from_body(&body_bytes, config_id);
    }

    // ── MCP `initialize` capability sniff ──────────────────────────────────
    // Per MCP spec, the client advertises its supported capabilities
    // (`elicitation`, `sampling`, `roots`) on `initialize`. We capture them
    // here so that — once the upstream responds and we mint an
    // `Mcp-Session-Id` — we can record `client_capabilities[session_id]` in
    // the process-global registry for later use by the credential
    // delegation pipeline (Elicit consent mode).
    let mcp_initialize_caps: Option<crate::mcp::elicitation::McpClientCapabilities> = if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && modern_request.is_none()
    {
        serde_json::from_slice::<serde_json::Value>(&body_bytes)
            .ok()
            .filter(|v| {
                v.get("method")
                    .and_then(|m| m.as_str())
                    == Some("initialize")
            })
            .and_then(|v| v.get("params").cloned())
            .map(|params| crate::mcp::elicitation::McpClientCapabilities::from_initialize_params(&params))
    } else {
        None
    };

    // ── MCP server→client request RESPONSE routing ─────────────────────────
    // Per MCP Streamable HTTP, the client POSTs JSON-RPC *responses* to
    // server-initiated requests (e.g. our `elicitation/create`) over the
    // same POST endpoint. Per spec, the server MUST respond 202 Accepted
    // with no body. We detect responses (have `id` + `result`/`error`,
    // no `method`) and route them to the pending-elicitation registry.
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && method == "POST"
        && let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
        && envelope
            .get("method")
            .is_none()
        && envelope.get("id").is_some()
        && (envelope
            .get("result")
            .is_some()
            || envelope
                .get("error")
                .is_some())
    {
        if let Some(session_id) = validated_mcp_session_id.as_deref()
            && let Some((elicit_id, result)) = crate::mcp::elicitation::try_parse_elicitation_response(&envelope)
        {
            let resolved = crate::mcp::elicitation::global_pending_elicitation_registry()
                .resolve(session_id, &elicit_id, result)
                .await;
            channel_info!(
                config_id,
                "📩 MCP elicitation response routed session={} elicit_id={} resolved={}",
                session_id,
                elicit_id,
                resolved
            );
        }
        connection_guard
            .decrement()
            .await;
        return Ok(axum::http::StatusCode::ACCEPTED.into_response());
    }

    // ── Capture MCP context for OPA input (early, before gateway OPA) ──────
    let mcp_context: Option<crate::surface_context::McpContext> = if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
    {
        match mcp_classification.as_ref() {
            Some(classification) => crate::mcp::build_validated_mcp_context(&body_bytes, classification),
            None => crate::mcp::build_mcp_context(&body_bytes),
        }
    } else {
        None
    };

    // Parse the A2A/AP2 message payload so policies can inspect the actual
    // agent content (`input.a2a`). Built after boundary Header Metadata
    // Mapping but before gateway-side trust registry, DID, and custom metadata
    // injection, so policies see normalized caller transport context as
    // protocol metadata without seeing later gateway assertions.
    let a2a_context: Option<crate::surface_context::A2aContext> = if matches!(
        state
            .surface
            .channel_protocol(),
        crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2
    ) {
        serde_json::from_slice::<serde_json::Value>(&body_bytes)
            .ok()
            .map(|body| {
                // `method` reaches policy exactly as the caller sent it (v0.3
                // `message/send` or v1.0 `SendMessage`); `A2aContext::new` adds the
                // slash-form `method_canonical` sibling so one deny rule covers both.
                let method = body
                    .get("method")
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string());
                let message = body
                    .get("params")
                    .and_then(|p| p.get("message"))
                    .or_else(|| body.get("message"))
                    .cloned();
                crate::surface_context::A2aContext::new(method, message)
            })
    } else {
        None
    };

    // For MCP `tools/call`, qualify the operation with the actual tool
    // name so the monitoring "Tool/Operation Distribution" table shows a
    // row per tool instead of collapsing every tool invocation into a
    // single `tools/call` bucket. Reuses the already-parsed `mcp_context`
    // — no extra body parse.
    if let Some(ref ctx) = mcp_context
        && ctx.method == "tools/call"
        && let Some(ref tool) = ctx.tool_name
    {
        ucp_operation = Some(format!("tools/call:{}", tool));
    }

    // ── Trust Registry Fetch (early, before gateway OPA) ────────────────────
    // Fetches agent trust context (DID, trust verification, agent DNA) from the
    // ORIGINAL request body (before any gateway-side injection) and makes it
    // available as `input.agent` for ALL OPA evaluations (gateway + channel)
    // AND for the Trust Check stage's `{{ input.agent.* }}` template
    // resolution. Built when surface OPA is configured or any caller-leg
    // Trust Check element is present — the Trust Check branch is required
    // even when surface OPA is absent, because its template resolver reads
    // `input.agent.*` directly. Skipped only for discovery requests.
    let mut agent_context: Option<crate::surface_context::AgentContext> =
        if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
            && ucp_operation.as_deref() != Some("discovery")
            && (state.surface.opa_enabled()
                || !state
                    .surface
                    .access_point
                    .trust_check_list
                    .is_empty())
        {
            let config_id_str = state
                .surface
                .surface_id
                .as_str();
            let body_json: Option<serde_json::Value> = serde_json::from_slice(&body_bytes).ok();
            let body_ref = body_json.as_ref();

            info!(channel = config_id_str, "GW1: Building agent context from inbound message body");
            let agent_ctx = crate::policies::build_agent_context_for_protocol(
                state
                    .surface
                    .channel_protocol(),
                body_ref,
                None,
                state
                    .trust_registry_listener_manager
                    .as_deref(),
                // Caller leg: skip the TR-extension / identity-credential cross-check
                // so a payload that carries a TR extension without a matching identity
                // credential still surfaces its TR fields to OPA / Trust Check.
                false,
            )
            .await;
            info!(
                channel = config_id_str,
                "GW1: Agent context built: trust_verification={:?}", agent_ctx.trust_verification
            );
            Some(agent_ctx)
        } else {
            None
        };

    // ── Trust Check stage placeholder ───────────────────────────────────────
    // The caller-leg Trust Check stage runs at the single post-identity seam
    // further down (after the managed-identity resolver populates
    // `extension_identity`), so this declaration starts empty and is filled
    // in by that seam. Gateway OPA — evaluated next, before identity
    // resolution — therefore never sees trust check results on the caller
    // leg; only surface OPA does.
    let mut trust_check_results: Option<crate::trust_registry_verification::TrustCheckResultsContext> = None;

    // ── Appliance-wide (global) gateway policy ───────────────────────────────
    // Enforced deny-overrides ahead of the per-gateway policy on every direct
    // inbound request, regardless of this gateway's own OPA configuration and
    // regardless of whether the path is a public discovery endpoint — a
    // deny-override the caller can switch off by choosing a path is not a control.
    if let Some(global_pm) = crate::gateways::get_appliance_policy_manager()
        && global_pm.has_global(crate::policies::global_policy::PLANE_GATEWAY)
    {
        let mut g_input = crate::surface_context::PolicyInput::new(
            method.as_ref(),
            uri.path(),
            crate::surface_context::filter_sensitive_headers(&headers),
            "inbound",
            None,
            None,
            state
                .surface
                .config_id()
                .map(|s| s.to_string()),
            &state.surface.name,
        );
        g_input.source_auth = source_auth_context.clone();
        g_input.agent = agent_context.clone();
        g_input.mcp = mcp_context.clone();
        g_input.a2a = a2a_context.clone();
        g_input.trust_check_results = trust_check_results.clone();
        let g_input_value = serde_json::to_value(&g_input).unwrap_or_default();
        let gd = global_pm.evaluate_global(crate::policies::global_policy::PLANE_GATEWAY, &g_input_value);
        let global_policy_name = gd.policy_name.as_deref();
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::Gateway,
            allow: gd.allow,
            reason: gd.reason.as_deref(),
            policy_id: Some(crate::policies::GATEWAY_POLICY_PACKAGE),
            policy_definition_id: gd.policy_id.as_deref(),
            policy_name: global_policy_name,
            surface_id: state.surface.config_id(),
            trace_id: Some(&trace_id),
            http_method: Some(method.as_ref()),
            path: Some(uri.path()),
            identity: authenticated_identity.as_ref(),
            policy_version: gd.version,
            policy_content_hash: gd.content_hash.as_deref(),
            ..Default::default()
        });
        if !gd.allow {
            connection_guard
                .decrement()
                .await;
            return Err(create_error_response(StatusCode::FORBIDDEN, "Request blocked by appliance-wide policy"));
        }
    }

    // ── Gateway-level OPA policy enforcement ─────────────────────────────────
    // Evaluated AFTER trust registry fetch so that `input.agent` is available.
    // A gateway deny cannot be overridden by a channel allow (no privilege escalation).
    if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && let Some(ref gw_policy_manager) = state.gateway_policy_manager
        && let Some(self_gateway_id) = gw_policy_manager.get_self_gateway_id()
        && gw_policy_manager.is_enforced(&self_gateway_id)
    {
        let mut gw_input = crate::surface_context::PolicyInput::new(
            method.as_ref(),
            uri.path(),
            crate::surface_context::filter_sensitive_headers(&headers),
            "inbound",
            None,
            None,
            state
                .surface
                .config_id()
                .map(|s| s.to_string()),
            &state.surface.name,
        );
        gw_input.source_auth = source_auth_context.clone();
        // [OPA-INPUT] Gateway policy input BEFORE agent/TR data
        info!(
            channel = state.surface.name,
            "[OPA-INPUT] Gateway policy input before TR: {}",
            serde_json::to_string(&gw_input).unwrap_or_default()
        );
        gw_input.agent = agent_context.clone();
        gw_input.mcp = mcp_context.clone();
        gw_input.a2a = a2a_context.clone();
        gw_input.trust_check_results = trust_check_results.clone();
        let gw_input_value = serde_json::to_value(&gw_input).unwrap_or_default();
        info!(channel = state.surface.name, "[OPA-INPUT] Gateway policy input before eval: {}", gw_input_value);
        let (gw_policy_def_id, gw_policy_version, gw_policy_hash) =
            match gw_policy_manager.policy_evidence(&self_gateway_id) {
                Some((id, v, h)) => (id, v, Some(h)),
                None => (None, None, None),
            };
        let gw_policy_name = gw_policy_manager
            .resolve_policy_name_or_default(gw_policy_def_id.as_deref())
            .await;

        match gw_policy_manager.evaluate_policy_decision(&self_gateway_id, gw_input_value) {
            Ok(decision) if decision.allow => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Gateway,
                    allow: true,
                    policy_id: Some(crate::policies::GATEWAY_POLICY_PACKAGE),
                    policy_definition_id: gw_policy_def_id.as_deref(),
                    policy_name: Some(gw_policy_name.as_str()),
                    surface_id: state.surface.config_id(),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    gateway_did: Some(&self_gateway_id),
                    policy_version: gw_policy_version,
                    policy_content_hash: gw_policy_hash.as_deref(),
                    ..Default::default()
                });
            }
            Ok(decision) => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Gateway,
                    allow: false,
                    reason: decision.reason.as_deref(),
                    policy_id: Some(crate::policies::GATEWAY_POLICY_PACKAGE),
                    policy_definition_id: gw_policy_def_id.as_deref(),
                    policy_name: Some(gw_policy_name.as_str()),
                    surface_id: state.surface.config_id(),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    gateway_did: Some(&self_gateway_id),
                    policy_version: gw_policy_version,
                    policy_content_hash: gw_policy_hash.as_deref(),
                    ..Default::default()
                });
                connection_guard
                    .decrement()
                    .await;
                return Err(create_error_response(StatusCode::FORBIDDEN, "Request blocked by gateway policy"));
            }
            Err(e) => {
                channel_warn!(config_id, "Gateway policy evaluation error (denying request): {}", e);
                connection_guard
                    .decrement()
                    .await;
                return Err(create_error_response(StatusCode::FORBIDDEN, "Request blocked by gateway policy"));
            }
        }
    }

    // ── AP2 experimental inbound gate (fail-closed, pre-payment) ────────────
    // Admission + VDC transformation for AP2 runs here — after gateway OPA but
    // BEFORE any payment settlement (delegated payment, fabric or direct
    // paywall) and before fabric/direct dispatch — so a disabled or
    // unverifiable AP2 request can never settle a payment or be forwarded.
    // Gateway OPA above still sees the original body. Every stage below —
    // payment settlement, MCP tool policies, surface OPA, custom metadata and
    // forwarding — now evaluates the transformed body; that is intended (the
    // transformed body is what is forwarded), and it is inert today because a
    // transform always fails closed (no production signing) and 501s here
    // before those stages run. Both direct and `fabric://` dispatch are
    // downstream of this point, so the gate covers them uniformly.
    let is_ap2_post_with_body = state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Ap2
        && method == "POST"
        && !body_bytes.is_empty();
    let ap2_enabled = ap2_experimental_enabled();
    match evaluate_ap2_inbound_decision(is_ap2_post_with_body, ap2_enabled, None) {
        Ap2InboundDecision::RejectFeatureDisabled => {
            warn!(channel = channel_name, "AP2 request rejected: experimental feature gate is disabled");
            connection_guard
                .decrement()
                .await;
            return Err(create_error_response(
                StatusCode::NOT_IMPLEMENTED,
                "AP2 is experimental and not enabled on this gateway",
            ));
        }
        Ap2InboundDecision::Transform => {
            let agent_identity: Option<(String, std::collections::HashMap<String, serde_json::Value>)> = None;
            let transform_result = process_ap2_vdc_transformation(&body_bytes, &state, agent_identity).await;
            let transform_decision =
                evaluate_ap2_inbound_decision(is_ap2_post_with_body, ap2_enabled, Some(transform_result.is_ok()));

            match (transform_decision, transform_result) {
                (Ap2InboundDecision::ForwardTransformed, Ok(transformed_bytes)) => {
                    info!(channel = channel_name, "AP2 VDC transformation completed");
                    body_bytes = transformed_bytes.into();
                }
                (_, Ok(transformed_bytes)) => {
                    body_bytes = transformed_bytes.into();
                }
                (_, Err(e)) => {
                    warn!(channel = channel_name, error = %e, "AP2 VDC transformation failed; rejecting request");
                    connection_guard
                        .decrement()
                        .await;
                    return Err(create_error_response(
                        StatusCode::NOT_IMPLEMENTED,
                        "AP2 experimental processing failed and request was rejected",
                    ));
                }
            }
        }
        Ap2InboundDecision::ForwardOriginal
        | Ap2InboundDecision::ForwardTransformed
        | Ap2InboundDecision::RejectTransformationFailed => {}
    }

    let is_a2a_surface = matches!(
        state
            .surface
            .access_point
            .protocol,
        crate::config::agent_surface::SurfaceProtocol::A2a | crate::config::agent_surface::SurfaceProtocol::Ap2
    );
    let is_a2a_proxy_target = is_a2a_surface
        && state
            .surface
            .target
            .endpoint
            .starts_with("a2a-proxy://");
    // Version negotiation, JSON-RPC envelope validation and A2A request-shape
    // validation are decided from the headers and the body shape alone, so they
    // run here, before any payment is taken, and a request they refuse is never
    // charged. `fabric://` targets are neither negotiated nor validated.
    let checks_a2a_request = is_a2a_surface
        && !state
            .surface
            .target
            .endpoint
            .starts_with("fabric://");

    // ── A2A protocol version negotiation (A2A / AP2 only) ────────────────
    // A2A 1.0 added the `A2A-Version` request header. Per spec an absent or
    // empty value means `0.3`; a version outside the set the gateway accepts is
    // rejected with `VersionNotSupportedError` (-32009) plus the supported list.
    // The gateway recognises both eras but never translates between them — a
    // caller and its managed agent must be version-compatible.
    //
    // This runs BEFORE the two validation layers below. Negotiation reads only
    // the headers, so it can. A caller sending an unsupported version and a
    // malformed body should learn about the version first: fixing the fields
    // named by -32602 and resending would only surface the -32009 on the second
    // attempt, and the version is the more fundamental rejection since the
    // gateway cannot serve that caller whatever the body contains.
    if checks_a2a_request {
        // The gateway accepts either method era regardless of the negotiated
        // version, so record both: the skew between them is the signal that
        // tells us when v0.3 traffic has faded enough to drop it. Refused
        // requests are recorded too, so callers turned away after legacy
        // compatibility is switched off stay visible.
        // Reuses the already-parsed `a2a_context` — no extra body parse.
        let negotiation = crate::a2a::negotiate_from_headers(&headers);
        let method_era = a2a_context
            .as_ref()
            .and_then(|ctx| ctx.method.as_deref())
            .map_or("none", crate::a2a::methods::method_era);
        crate::metrics::backends::prometheus::track_a2a_protocol_version(
            &channel_name,
            crate::a2a::version::negotiated_version_label(&negotiation),
            method_era,
        );
        match negotiation {
            Ok(version) => {
                channel_debug!(config_id, "A2A protocol version negotiated: {} (method era: {})", version, method_era);
            }
            Err(requested) => {
                channel_warn!(config_id, "Unsupported A2A protocol version requested: {}", requested);
                connection_guard
                    .decrement()
                    .await;
                return Err(crate::a2a::create_version_not_supported_response(&requested));
            }
        }
    }

    // ── JSON-RPC envelope validation (A2A / AP2 only) ────────────────────
    // When `validate_messages` is enabled, reject requests that are not valid
    // JSON or that lack the required JSON-RPC 2.0 envelope fields (`jsonrpc`
    // and `method`).  This catches malformed requests early, before they reach
    // the upstream agent.
    if state
        .config
        .a2a
        .validate_messages
        && checks_a2a_request
        && !body_bytes.is_empty()
        && let Err((code, message)) = validate_jsonrpc_envelope(&body_bytes)
    {
        channel_warn!(config_id, "JSON-RPC validation failed: {}", message);
        connection_guard
            .decrement()
            .await;
        return Err(create_jsonrpc_error_response(StatusCode::BAD_REQUEST, code, message));
    }

    // ── A2A request-shape validation ─────────────────────────────────────
    // Beyond the JSON-RPC envelope, check the fields A2A itself requires on a
    // request, under the same `validate_messages` setting. A request that fails
    // here was already going to fail: a conformant agent refuses a message with
    // no `messageId` too, one hop later and with a vaguer error. Only fields
    // both protocol eras spell the same way are checked, so it favours neither.
    if state
        .config
        .a2a
        .validate_messages
        && checks_a2a_request
        // Managed agents only. An A2A-proxy target is not a pass-through to an
        // A2A agent, it IS the implementation: it translates the message into a
        // non-A2A backend and needs only `params.message` and text parts. There
        // is no downstream agent to refuse a malformed request, so checking here
        // would not fail a request sooner, it would fail one that works today.
        && !is_a2a_proxy_target
        && !body_bytes.is_empty()
        && let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
        && let Err(field_errors) = crate::a2a::validation::validate_request_shape(&parsed)
    {
        channel_warn!(
            config_id,
            "A2A request shape validation failed: {} error(s), truncated={}, first fields: {}",
            field_errors.errors.len(),
            field_errors.truncated,
            field_errors
                .errors
                .iter()
                .take(3)
                .map(|e| e.field.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        connection_guard
            .decrement()
            .await;
        return Err(crate::a2a::errors::create_invalid_params_response(&field_errors));
    }

    // ── Track payment context for OPA input ────────────────────────────────
    let mut payment_context: Option<crate::surface_context::PaymentContext> = None;

    // Handle payment verification for fabric:// protocol BEFORE forwarding
    // When both x402 and MPP are enabled, the client can satisfy either one.
    // If no credential is provided, a combined 402 is returned.
    let mut mpp_receipt_header: Option<String> = None;

    // Settlement receipt headers relayed from a delegate payment gateway
    // (Model B) on a `Proceed` decision, injected onto the caller's response.
    let mut delegation_receipt_headers: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    let defer_surface_payment = modern_request.is_some();
    if !defer_surface_payment {
        match surface_payment::delegate(
            &state,
            &headers,
            body_bytes.clone(),
            &method,
            &uri,
            &trace_id,
            &channel_name,
            None,
        )
        .await
        {
            surface_payment::DelegatedPayment::Proceed(receipts) => delegation_receipt_headers.extend(receipts),
            surface_payment::DelegatedPayment::Challenge(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Ok(response);
            }
            surface_payment::DelegatedPayment::Denied(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
    }

    if !defer_surface_payment
        && state
            .surface
            .target
            .endpoint
            .starts_with("fabric://")
    {
        // A delegated (Model B) x402 policy was already fully adjudicated by
        // the delegation block above (Proceed/Challenge/Deny) — never run the
        // local paywall a second time against its (empty) local price config.
        let x402_required = state
            .surface
            .x402_config()
            .is_some_and(|p| {
                p.provider != crate::config::types::X402Provider::AgentPay
                    && crate::x402::should_require_payment(
                        p,
                        &state
                            .surface
                            .channel_protocol(),
                        &body_bytes,
                        mcp_context.as_ref(),
                    )
            });
        let mpp_required = state
            .surface
            .mpp_config()
            .is_some_and(|p| {
                crate::mpp::should_require_payment(
                    p,
                    &state
                        .surface
                        .channel_protocol(),
                    &body_bytes,
                    mcp_context.as_ref(),
                )
            });

        if x402_required || mpp_required {
            let resource_url = uri.to_string();

            // Extract credentials for both protocols (with MCP body extraction)
            let (payment_signature, mpp_credential, modified_body) = if state
                .surface
                .channel_protocol()
                == crate::config::ChannelProtocol::Mcp
            {
                let (sig, body1) = crate::x402::extract_payment_signature_with_mcp(
                    &headers,
                    &state
                        .config
                        .x402_headers
                        .payment_signature,
                    &body_bytes,
                );
                let (cred, body2) = crate::mpp::extract_mpp_credential_with_mcp(&headers, &body1);
                (sig, cred, body2)
            } else {
                let sig = crate::x402::extract_payment_signature(
                    &headers,
                    &state
                        .config
                        .x402_headers
                        .payment_signature,
                );
                let cred = crate::mpp::extract_mpp_credential(&headers);
                (sig, cred, body_bytes.to_vec())
            };

            if x402_required && payment_signature.is_some() {
                // Client sent x402 credential → verify via x402
                match crate::x402::process_payment(
                    payment_signature,
                    state
                        .surface
                        .x402_config()
                        .unwrap(),
                    &channel_name,
                    config_id,
                    &state.config.x402_headers,
                    &resource_url,
                    state
                        .listener_manager
                        .read()
                        .await
                        .clone(),
                    state
                        .transaction_store
                        .clone(),
                )
                .await
                {
                    Ok(response_header) => {
                        body_bytes = modified_body.into();
                        if let Some(hdr) = response_header {
                            payment_context = Some(crate::surface_context::PaymentContext {
                                verified: true,
                                response_header: Some(hdr),
                            });
                        }
                    }
                    Err(err_response) => {
                        channel_warn!(config_id, "❌ Payment verification failed for fabric request");

                        if let Some(ref metrics) = state.metrics_store {
                            let latency_ms = start_time
                                .elapsed()
                                .as_millis() as u64;
                            let channel_config_id = state
                                .surface
                                .surface_id
                                .clone();
                            let source = source_addr.clone();
                            let dest = state
                                .surface
                                .target
                                .endpoint
                                .clone();
                            let metrics_clone = Arc::clone(metrics);
                            let trace_id_clone = trace_id.clone();
                            tokio::spawn(async move {
                                metrics_clone
                                    .record_connection(
                                        channel_config_id,
                                        source,
                                        dest,
                                        crate::metrics::ConnectionStatus::Success,
                                        Some(latency_ms),
                                        None,
                                        crate::metrics::ConnectionDirection::Request,
                                        trace_id_clone,
                                        None,
                                        None,
                                        latency_ms,
                                        None,
                                    )
                                    .await;
                            });
                        }

                        connection_guard
                            .decrement()
                            .await;
                        return Err(err_response);
                    }
                }
            } else if mpp_required && mpp_credential.is_some() {
                // Client sent MPP credential → verify via MPP
                match crate::mpp::process_payment(
                    mpp_credential,
                    state
                        .surface
                        .mpp_config()
                        .unwrap(),
                    &channel_name,
                    config_id,
                    &resource_url,
                    state
                        .mpp_transaction_store
                        .clone(),
                    &state.secrets_store,
                )
                .await
                {
                    Ok(receipt_header) => {
                        mpp_receipt_header = receipt_header;
                        body_bytes = modified_body.into();
                    }
                    Err(err_response) => {
                        channel_warn!(config_id, "❌ MPP payment verification failed for fabric request");
                        connection_guard
                            .decrement()
                            .await;
                        return Err(err_response);
                    }
                }
            } else {
                // No credential → return 402 (combined if both protocols enabled)
                channel_warn!(config_id, "❌ Payment required for fabric request");

                let err_response = if x402_required {
                    let x402_resp = crate::x402::process_payment(
                        None,
                        state
                            .surface
                            .x402_config()
                            .unwrap(),
                        &channel_name,
                        config_id,
                        &state.config.x402_headers,
                        &resource_url,
                        state
                            .listener_manager
                            .read()
                            .await
                            .clone(),
                        state
                            .transaction_store
                            .clone(),
                    )
                    .await
                    .unwrap_err();
                    if mpp_required {
                        crate::mpp::fire_challenge_issued_events(
                            config_id,
                            &channel_name,
                            &resource_url,
                            state
                                .mpp_transaction_store
                                .clone(),
                        );
                        crate::mpp::errors::add_mpp_challenges_to_response_resolved(
                            x402_resp,
                            state
                                .surface
                                .mpp_config()
                                .unwrap(),
                            &resource_url,
                            &state.secrets_store,
                        )
                        .await
                    } else {
                        x402_resp
                    }
                } else {
                    crate::mpp::process_payment(
                        None,
                        state
                            .surface
                            .mpp_config()
                            .unwrap(),
                        &channel_name,
                        config_id,
                        &resource_url,
                        state
                            .mpp_transaction_store
                            .clone(),
                        &state.secrets_store,
                    )
                    .await
                    .unwrap_err()
                };

                if let Some(ref metrics) = state.metrics_store {
                    let latency_ms = start_time
                        .elapsed()
                        .as_millis() as u64;
                    let channel_config_id = state
                        .surface
                        .surface_id
                        .clone();
                    let source = source_addr.clone();
                    let dest = state
                        .surface
                        .target
                        .endpoint
                        .clone();
                    let metrics_clone = Arc::clone(metrics);
                    let trace_id_clone = trace_id.clone();
                    tokio::spawn(async move {
                        metrics_clone
                            .record_connection(
                                channel_config_id,
                                source,
                                dest,
                                crate::metrics::ConnectionStatus::Success,
                                Some(latency_ms),
                                None,
                                crate::metrics::ConnectionDirection::Request,
                                trace_id_clone,
                                None,
                                None,
                                latency_ms,
                                None,
                            )
                            .await;
                    });
                }

                connection_guard
                    .decrement()
                    .await;
                return Err(err_response);
            }
        }
    }

    // ── MCP fabric:// SSE transport (GET /sse and POST /mcp/messages/) ─────
    // For MCP channels with fabric:// targets, SSE transport must be handled
    // at GW1 level — long-lived SSE streams cannot traverse DIDComm.
    // GET /sse → local session; POST /mcp/messages/ → forward through Fabric,
    // then push the response to the SSE session stream.
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && state
            .surface
            .target
            .endpoint
            .starts_with("fabric://")
    {
        let path_str = uri.path();

        // GET /sse → Legacy SSE: create local session, return SSE stream
        if method == "GET" && path_str.ends_with("/sse") {
            channel_info!(config_id, "🔌 SSE connect for fabric:// MCP channel (handled locally at GW1)");

            let (session_id, rx_stream) = CHANNEL_SSE_SESSION_MGR
                .create_session()
                .await;

            // The `endpoint` event must advertise a path the client can POST to
            // through the gateway's public-facing router — i.e. the channel
            // route prefix, not the already-stripped per-channel tail. Without
            // the prefix, the client POSTs to a path no channel matches and
            // axum returns 404 before `proxy_handler_with_mcp_runtime` ever sees it.
            // Mirrors the proxy:// SSE fix in the block below.
            let surface_route = state
                .surface
                .route()
                .trim_end_matches('/');
            let response = crate::mcp::sse_server::build_legacy_sse_response(session_id, rx_stream, surface_route);

            connection_guard
                .decrement()
                .await;
            return Ok(response);
        }

        // POST /mcp/messages/?session_id=X → Forward JSON-RPC through Fabric,
        // then push the response to the SSE session.
        if method == "POST"
            && path_str.contains("/mcp/messages")
            && let Some(session_id) = crate::mcp::sse_server::extract_session_id(uri.query())
        {
            if !CHANNEL_SSE_SESSION_MGR
                .session_exists(&session_id)
                .await
            {
                connection_guard
                    .decrement()
                    .await;
                return Err(create_error_response(StatusCode::NOT_FOUND, "SSE session not found or expired"));
            }

            channel_info!(config_id, "📨 SSE session POST for fabric:// MCP channel session={}", session_id);

            // Parse the JSON-RPC request
            let json_request: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
                error!(channel = %channel_name, error = %e, "Failed to parse JSON-RPC request");
                create_error_response(StatusCode::BAD_REQUEST, "Invalid JSON-RPC request")
            })?;

            let is_notification = json_request
                .get("id")
                .is_none();

            // The /mcp/messages/ path is a GW1-local Legacy SSE construct.
            // Forward just "/" to GW2 — it will append this to its target
            // endpoint to POST the JSON-RPC body to the upstream's root.
            let rewritten_uri: axum::http::Uri = "/".parse().unwrap();

            channel_info!(
                config_id,
                "📨 Fabric SSE: forwarding through Fabric — rewritten_uri={}, body_len={}, method=POST, target={}",
                rewritten_uri,
                body_bytes.len(),
                state.surface.target.endpoint
            );

            // Forward through Fabric
            let fabric_result = Box::pin(handle_fabric_request(
                state.clone(),
                &channel_name,
                Method::POST,
                rewritten_uri,
                headers.clone(),
                source_addr.clone(),
                start_time,
                ConnectionGuard::new(None, None),
                body_bytes.clone(),
                trace_id.clone(),
                ucp_operation.clone(),
                authenticated_identity.clone(),
                source_auth_context.clone(),
                payment_context.clone(),
                mcp_metadata_context,
                mcp_verified_binding.clone(),
                mcp_classification.as_ref(),
                None,
                mcp_continuations.clone(),
            ))
            .await;

            match &fabric_result {
                Ok(resp) => {
                    channel_info!(
                        config_id,
                        "📨 Fabric SSE: handle_fabric_request returned Ok — status={}",
                        resp.status()
                    );
                }
                Err(resp) => {
                    // Extract the error response body for logging
                    channel_error!(
                        config_id,
                        "📨 Fabric SSE: handle_fabric_request returned Err — status={}",
                        resp.status()
                    );
                }
            }

            match fabric_result {
                Ok(resp) if !is_notification => {
                    let (parts, body) = resp.into_parts();
                    let body_bytes_resp = axum::body::to_bytes(body, 10 * 1024 * 1024)
                        .await
                        .unwrap_or_default();
                    let json_str = String::from_utf8_lossy(&body_bytes_resp);

                    channel_info!(
                        config_id,
                        "📨 Fabric SSE: response status={}, body_len={}, body_preview={}",
                        parts.status,
                        json_str.len(),
                        &json_str[..json_str.len().min(500)]
                    );

                    if parts.status.is_success() && !json_str.is_empty() {
                        CHANNEL_SSE_SESSION_MGR
                            .send_response(&session_id, &json_str)
                            .await;
                    } else {
                        // Non-success from Fabric path — send error via SSE
                        let error_json = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": json_request.get("id"),
                            "error": {
                                "code": -32603,
                                "message": format!("Upstream returned status {}", parts.status)
                            }
                        });
                        let error_str = serde_json::to_string(&error_json).unwrap_or_default();
                        CHANNEL_SSE_SESSION_MGR
                            .send_response(&session_id, &error_str)
                            .await;
                    }
                }
                Err(err_resp) => {
                    // Extract error details for debugging
                    let err_status = err_resp.status();
                    let (err_parts, err_body) = err_resp.into_parts();
                    let err_body_bytes = axum::body::to_bytes(err_body, 1024 * 1024)
                        .await
                        .unwrap_or_default();
                    let err_body_str = String::from_utf8_lossy(&err_body_bytes);
                    channel_error!(
                        config_id,
                        "📨 Fabric SSE: forwarding FAILED — status={}, headers={:?}, body={}",
                        err_status,
                        err_parts.headers,
                        &err_body_str[..err_body_str.len().min(1000)]
                    );

                    let error_json = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": json_request.get("id"),
                        "error": { "code": -32603, "message": format!("Fabric forwarding failed: {} {}", err_status, err_body_str.chars().take(200).collect::<String>()) }
                    });
                    let error_str = serde_json::to_string(&error_json).unwrap_or_default();
                    CHANNEL_SSE_SESSION_MGR
                        .send_response(&session_id, &error_str)
                        .await;
                }
                _ => {} // Notification — no response
            }

            connection_guard
                .decrement()
                .await;
            return Ok(StatusCode::ACCEPTED.into_response());
        }
    }

    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && state
            .surface
            .target
            .endpoint
            .starts_with("fabric://")
    {
        let should_validate_mcp_body = method == axum::http::Method::POST && !body_bytes.is_empty();
        if should_validate_mcp_body && !crate::mcp::is_mcp_request(&headers, &body_bytes) {
            warn!(
                channel = channel_name,
                "Malformed MCP body on MCP fabric surface — returning JSON-RPC error envelope"
            );
            let err_response = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                Ok(json) => crate::mcp::create_mcp_error_response(
                    json.get("id").cloned(),
                    crate::mcp::error_codes::INVALID_REQUEST,
                    "Invalid JSON-RPC request",
                    None,
                ),
                Err(e) => crate::mcp::create_mcp_error_response(
                    None,
                    crate::mcp::error_codes::PARSE_ERROR,
                    "Invalid JSON",
                    Some(serde_json::json!({ "details": e.to_string() })),
                ),
            };
            connection_guard
                .decrement()
                .await;
            return Ok(err_response);
        }

        if !state
            .surface
            .target
            .mcp_tool_policies
            .is_empty()
            && should_validate_mcp_body
        {
            match evaluate_mcp_tool_policies(
                &state,
                &headers,
                &body_bytes,
                &channel_name,
                &source_addr,
                &uri,
                mcp_context.as_ref(),
            )
            .await
            {
                Ok(outcome) => {
                    let (allow, reason) = if outcome.allow {
                        (true, None)
                    } else {
                        (false, outcome.reason.as_deref())
                    };

                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::McpTool,
                        allow,
                        reason,
                        policy_id: outcome
                            .policy_id
                            .as_deref()
                            .or(outcome.tool_name.as_deref()),
                        policy_name: outcome.policy.name.as_deref(),
                        policy_version: outcome.policy.version,
                        policy_content_hash: outcome
                            .policy
                            .content_hash
                            .as_deref(),
                        policy_definition_id: outcome.policy_id.as_deref(),
                        surface_id: Some(channel_name.as_str()),
                        trace_id: Some(&trace_id),
                        http_method: Some(method.as_ref()),
                        path: Some(uri.path()),
                        identity: authenticated_identity.as_ref(),
                        ..Default::default()
                    });

                    if allow {
                        info!(channel = channel_name, "MCP tool policy check passed before fabric forwarding");
                    } else {
                        warn!(channel = channel_name, "MCP tool policy check failed before fabric forwarding");
                        let request_id = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                            .ok()
                            .and_then(|json| json.get("id").cloned());
                        let error_response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "error": {
                                "code": -32000,
                                "message": "Access denied: insufficient permissions for this tool"
                            }
                        });
                        connection_guard
                            .decrement()
                            .await;
                        return Ok(axum::response::Json(error_response).into_response());
                    }
                }
                Err(e) => {
                    error!(channel = channel_name, error = %e, "Failed to evaluate MCP tool policy before fabric forwarding");
                    let request_id = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                        .ok()
                        .and_then(|json| json.get("id").cloned());
                    let error_response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32603,
                            "message": "Internal error: policy evaluation failed"
                        }
                    });
                    connection_guard
                        .decrement()
                        .await;
                    return Ok(axum::response::Json(error_response).into_response());
                }
            }
        }

        match crate::mcp::handle_mcp_request(&state, &body_bytes, &channel_name).await {
            Ok(_) => {}
            Err(response) => {
                let should_forward = response
                    .headers()
                    .get("X-MCP-Forward")
                    .and_then(|v| v.to_str().ok())
                    == Some("true");
                if !should_forward {
                    connection_guard
                        .decrement()
                        .await;
                    return Ok(response);
                }
            }
        }
    }

    // Special handling for fabric:// protocol - forward through gateway
    if state
        .surface
        .target
        .endpoint
        .starts_with("fabric://")
    {
        return Box::pin(handle_fabric_request(
            state,
            &channel_name,
            method,
            uri,
            headers,
            source_addr,
            start_time,
            connection_guard,
            body_bytes, // Pass body_bytes instead of req
            trace_id,
            ucp_operation,
            authenticated_identity,
            source_auth_context.clone(),
            payment_context,
            mcp_metadata_context,
            mcp_verified_binding,
            mcp_classification.as_ref(),
            subscription_lifetime,
            mcp_continuations,
        ))
        .await;
    }

    // Build target URL (or get direct response for special protocols like DID).
    // A2A Proxy targets are internal adapter references, not network URLs; keep
    // them in the normal policy/trust pipeline, then dispatch after OPA.
    let target_url = if is_a2a_proxy_target {
        String::new()
    } else {
        match build_target_url(
            &state.surface.target.endpoint,
            &uri,
            &method,
            &headers,
            state
                .surface
                .override_agent_card_location(),
            state
                .surface
                .agent_card_location_path(),
        ) {
            Ok(url) => url,
            Err(direct_response) => {
                // Special protocol handling (e.g., DID) - return direct response
                debug!(channel = channel_name, "Returning direct response from protocol handler");

                // Record successful connection in metrics (using special case for direct responses)
                if let Some(ref metrics) = state.metrics_store {
                    let latency_ms = start_time
                        .elapsed()
                        .as_millis() as u64;
                    let metrics = Arc::clone(metrics);
                    let channel_config_id = state
                        .surface
                        .surface_id
                        .clone();
                    let source = source_addr.clone();
                    let dest = state
                        .surface
                        .target
                        .endpoint
                        .clone();
                    let trace_id = uuid::Uuid::new_v4().to_string();
                    tokio::spawn(async move {
                        metrics
                            .record_connection(
                                channel_config_id,
                                source,
                                dest,
                                crate::metrics::ConnectionStatus::Success,
                                Some(latency_ms),
                                None,
                                crate::metrics::ConnectionDirection::Request,
                                trace_id,
                                None,
                                None,
                                latency_ms,
                                None,
                            )
                            .await;
                    });
                }

                // Track task metrics: decrement active connections
                if let (Some(_task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
                    info!(channel = channel_name, task_id = task_id, "Recording direct response connection metrics");
                    connection_guard
                        .decrement()
                        .await;
                }

                return Ok(direct_response);
            }
        }
    };

    // Defense-in-depth SSRF guard at the forwarding layer. `pinned_forward_client`
    // fails closed on an unparseable URL, resolves DNS once to block any host that
    // *resolves* to a cloud-metadata endpoint (not just static metadata
    // hostnames), and returns a redirect-disabled client pinned to that exact
    // resolved address — so the connection cannot be re-resolved to an internal
    // address between vetting and connect (DNS rebinding) and an upstream 3xx is
    // returned to the caller rather than followed to an unvetted `Location`.
    // Loopback and RFC 1918 stay allowed on purpose — an operator-configured
    // surface legitimately forwards to a localhost sidecar or same-VPC upstream.
    // A2A-proxy targets carry an empty `target_url` here; their real `base_url`
    // egress is vetted at dial time (strict egress guard) and at config-set time,
    // so they are skipped at this sink. MCP `proxy://` targets are a virtual
    // identifier here too, not a network address (the gateway resolves the real
    // REST backend and dispatches it further down this function); that backend's
    // `base_url` is already vetted with `validate_resolved_url` when the MCP proxy
    // is created/updated, so it is also skipped at this sink rather than
    // DNS-resolving the placeholder host and failing closed on every request.
    let is_mcp_proxy_target = target_url.starts_with("proxy://");
    let mut forward_client: Option<reqwest::Client> = None;
    if !is_a2a_proxy_target && !is_mcp_proxy_target {
        match pinned_target_client(&state, &channel_name, &target_url).await {
            Ok(client) => forward_client = Some(client),
            Err(blocked) => return Ok(blocked),
        }
    }

    if !is_a2a_proxy_target {
        debug!(channel = channel_name, target = %target_url, "Forwarding to upstream");
    }

    let _prep_span = tracing::info_span!(
        "channel.request_preparation",
        otel.name = "Request Preparation",
        surface = %channel_name
    );
    // Use drop(enter()) for sync context marking
    drop(_prep_span.enter());

    // Body already extracted earlier for payment verification
    // Check body size
    if body_bytes.len() > state.config.a2a.max_body_size {
        warn!(
            channel = channel_name,
            size = body_bytes.len(),
            max = state.config.a2a.max_body_size,
            "Request body too large"
        );
        connection_guard
            .decrement()
            .await;
        return Err(create_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("Request body too large: {} bytes (max: {})", body_bytes.len(), state.config.a2a.max_body_size),
        ));
    }

    if !defer_surface_payment {
        match surface_payment::process(
            &state,
            &headers,
            body_bytes.clone(),
            mcp_context.as_ref(),
            &uri.to_string(),
            None,
        )
        .await
        {
            Ok(payment) => {
                body_bytes = payment.body;
                if payment.context.is_some() {
                    payment_context = payment.context;
                }
                if payment.mpp_receipt.is_some() {
                    mpp_receipt_header = payment.mpp_receipt;
                }
            }
            Err(response) => {
                channel_warn!(config_id, "Payment did not authorize the request");
                if let Some(metrics) = state.metrics_store.as_ref() {
                    let latency_ms = start_time
                        .elapsed()
                        .as_millis() as u64;
                    let channel_config_id = state
                        .surface
                        .surface_id
                        .clone();
                    let source = source_addr.clone();
                    let dest = state
                        .surface
                        .target
                        .endpoint
                        .clone();
                    let metrics = Arc::clone(metrics);
                    let trace = trace_id.clone();
                    tokio::spawn(async move {
                        metrics
                            .record_connection(
                                channel_config_id,
                                source,
                                dest,
                                crate::metrics::ConnectionStatus::Success,
                                Some(latency_ms),
                                None,
                                crate::metrics::ConnectionDirection::Request,
                                trace,
                                None,
                                None,
                                latency_ms,
                                None,
                            )
                            .await;
                    });
                }
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
    }

    // ── MCP Streamable HTTP transport: GET (notification stream) + DELETE ────
    // Per MCP spec rev 2025-03-26, a Streamable HTTP server must accept:
    //   - POST /<route> with Accept: text/event-stream  (request → SSE response)
    //   - GET  /<route> with Accept: text/event-stream  (server → client notifications)
    //   - DELETE /<route>                                (terminate session)
    //
    // POST is wrapped at response build time below. GET and DELETE short-circuit
    // here so external clients (e.g. Microsoft Copilot Studio) can establish the
    // server→client SSE channel for any MCP channel (proxy:// or http://).
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
    {
        let path_str = uri.path();

        // GET + Accept: text/event-stream → notification stream.
        // Skip if path ends in /sse — that's the legacy SSE transport handled below.
        if method == "GET" && crate::mcp::sse_server::client_wants_sse(&headers) && !path_str.ends_with("/sse") {
            // Per MCP Streamable HTTP, the client SHOULD include the
            // `Mcp-Session-Id` header it received on `initialize`. We use it
            // to register an SSE writer so server-initiated requests
            // (`elicitation/create`) can be pushed onto this stream.
            let session_id_opt = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            channel_info!(
                config_id,
                "🔌 MCP Streamable HTTP GET: opening notification stream session_id={:?}",
                session_id_opt
            );
            connection_guard
                .decrement()
                .await;

            let stream: std::pin::Pin<
                Box<dyn futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>> + Send>,
            > = match session_id_opt {
                Some(sid) => {
                    let rx = match crate::mcp::streamable_sse::global_streamable_session_registry()
                        .register(&sid)
                        .await
                    {
                        Some(rx) => rx,
                        None => {
                            return Ok((axum::http::StatusCode::TOO_MANY_REQUESTS, "Too many active SSE sessions")
                                .into_response());
                        }
                    };
                    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
                }
                None => {
                    Box::pin(futures::stream::pending::<Result<axum::response::sse::Event, std::convert::Infallible>>())
                }
            };
            let sse = axum::response::Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default());
            return Ok(axum::response::IntoResponse::into_response(sse));
        }

        // DELETE → terminate session.
        if method == "DELETE" {
            let session_id_opt = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            channel_info!(
                config_id,
                "🔌 MCP Streamable HTTP DELETE: terminating session session_id={:?}",
                session_id_opt
            );
            if let Some(sid) = session_id_opt {
                crate::mcp::streamable_sse::global_streamable_session_registry()
                    .drop_session(&sid)
                    .await;
                crate::mcp::elicitation::global_capability_registry()
                    .drop_session(&sid)
                    .await;
                crate::mcp::elicitation::global_pending_elicitation_registry()
                    .drop_session(&sid)
                    .await;
            }
            connection_guard
                .decrement()
                .await;
            return Ok(axum::http::StatusCode::NO_CONTENT.into_response());
        }
    }

    // ── MCP proxy:// SSE transport (GET /sse and POST /mcp/messages/) ────────
    // For channels with proxy:// targets, the gateway IS the MCP server.
    // Handle Legacy SSE and Streamable HTTP transports before the regular proxy path.
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && modern_request.is_none()
        && state
            .surface
            .target
            .endpoint
            .starts_with("proxy://")
    {
        let path_str = uri.path();

        // GET /sse → Legacy SSE: create session, return SSE stream
        if method == "GET" && path_str.ends_with("/sse") {
            // Enforce inbound + surface OPA policies before establishing SSE session
            if let Err(deny) = evaluate_mcp_proxy_opa_policies(
                &state,
                method.as_ref(),
                &uri,
                &headers,
                &body_bytes,
                authenticated_identity.as_ref(),
                source_auth_context.as_ref(),
                mcp_context.as_ref(),
                payment_context.as_ref(),
                &trace_id,
            )
            .await
            {
                connection_guard
                    .decrement()
                    .await;
                return Err(deny);
            }

            let proxy_id = &state.surface.target.endpoint[8..];
            channel_info!(config_id, "🔌 SSE connect for proxy:// channel proxy_id={}", proxy_id);

            let (session_id, rx_stream) = CHANNEL_SSE_SESSION_MGR
                .create_session()
                .await;

            // The `endpoint` event must advertise a path the client can POST to
            // through the gateway's public-facing router — i.e. the channel
            // route prefix, not the already-stripped per-channel tail. Without
            // the prefix, the client POSTs to a path no channel matches and
            // axum returns 404 before `proxy_handler_with_mcp_runtime` ever sees it.
            let surface_route = state
                .surface
                .route()
                .trim_end_matches('/');
            let response = crate::mcp::sse_server::build_legacy_sse_response(session_id, rx_stream, surface_route);

            connection_guard
                .decrement()
                .await;
            return Ok(response);
        }

        // POST /mcp/messages/?session_id=X → Legacy SSE session message
        if method == "POST"
            && path_str.contains("/mcp/messages")
            && let Some(session_id) = crate::mcp::sse_server::extract_session_id(uri.query())
        {
            if !CHANNEL_SSE_SESSION_MGR
                .session_exists(&session_id)
                .await
            {
                connection_guard
                    .decrement()
                    .await;
                return Err(create_error_response(StatusCode::NOT_FOUND, "SSE session not found or expired"));
            }

            // Enforce inbound + surface OPA policies
            let policy_input = match evaluate_mcp_proxy_opa_policies(
                &state,
                method.as_ref(),
                &uri,
                &headers,
                &body_bytes,
                authenticated_identity.as_ref(),
                source_auth_context.as_ref(),
                mcp_context.as_ref(),
                payment_context.as_ref(),
                &trace_id,
            )
            .await
            {
                Ok(policy_input) => policy_input,
                Err(deny) => {
                    connection_guard
                        .decrement()
                        .await;
                    return Err(deny);
                }
            };

            let proxy_id = &state.surface.target.endpoint[8..];
            channel_info!(
                config_id,
                "📨 SSE session POST for proxy:// channel proxy_id={} session={}",
                proxy_id,
                session_id
            );

            // Parse JSON-RPC request
            let json_request: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
                error!(channel = %channel_name, error = %e, "Failed to parse JSON-RPC request");
                create_error_response(StatusCode::BAD_REQUEST, "Invalid JSON-RPC request")
            })?;

            let is_notification = json_request
                .get("id")
                .is_none();

            // Process through the proxy handler (reuses existing handle_mcp_proxy_request flow)
            let response = handle_mcp_proxy_request(
                &state,
                proxy_id,
                &body_bytes,
                &headers,
                &method,
                &uri,
                &channel_name,
                &source_addr,
                start_time,
                trace_id.clone(),
                authenticated_identity.as_ref(),
                &policy_input,
                mcp_context.as_ref(),
            )
            .await;

            match response {
                Ok(resp) if !is_notification => {
                    let (parts, body) = resp.into_parts();
                    let body_bytes_resp = axum::body::to_bytes(body, 10 * 1024 * 1024)
                        .await
                        .unwrap_or_default();
                    let json_str = String::from_utf8_lossy(&body_bytes_resp);

                    if parts.status.is_success() && !json_str.is_empty() {
                        CHANNEL_SSE_SESSION_MGR
                            .send_response(&session_id, &json_str)
                            .await;
                    }
                }
                Err(resp) => {
                    // `handle_mcp_proxy_request` returns Err with HTTP 200 +
                    // JSON-RPC error envelope for in-protocol failures (e.g.
                    // disabled proxy, unknown tool). For those, forward the
                    // body verbatim so the caller sees the actual error
                    // shape rather than a generic "Internal error". For
                    // out-of-band HTTP errors (non-200, non-JSON), fall back
                    // to a synthesized JSON-RPC envelope so the SSE message
                    // stays parseable.
                    let (parts, body) = resp.into_parts();
                    let body_bytes_resp = axum::body::to_bytes(body, 10 * 1024 * 1024)
                        .await
                        .unwrap_or_default();
                    let body_str = String::from_utf8_lossy(&body_bytes_resp);
                    let forwardable = parts.status == StatusCode::OK
                        && !body_str.is_empty()
                        && serde_json::from_str::<serde_json::Value>(&body_str).is_ok();
                    let to_send = if forwardable {
                        body_str.into_owned()
                    } else {
                        serde_json::to_string(&serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": json_request.get("id"),
                            "error": { "code": -32603, "message": "Internal error" }
                        }))
                        .unwrap_or_default()
                    };
                    CHANNEL_SSE_SESSION_MGR
                        .send_response(&session_id, &to_send)
                        .await;
                }
                _ => {} // Notification — no response needed
            }

            // Legacy SSE: return 202 Accepted
            connection_guard
                .decrement()
                .await;
            return Ok(StatusCode::ACCEPTED.into_response());
        }

        // POST with Accept: text/event-stream → Streamable HTTP
        if method == "POST" && crate::mcp::sse_server::client_wants_sse(&headers) && !body_bytes.is_empty() {
            // Enforce inbound + surface OPA policies
            let policy_input = match evaluate_mcp_proxy_opa_policies(
                &state,
                method.as_ref(),
                &uri,
                &headers,
                &body_bytes,
                authenticated_identity.as_ref(),
                source_auth_context.as_ref(),
                mcp_context.as_ref(),
                payment_context.as_ref(),
                &trace_id,
            )
            .await
            {
                Ok(policy_input) => policy_input,
                Err(deny) => {
                    connection_guard
                        .decrement()
                        .await;
                    return Err(deny);
                }
            };

            let proxy_id = &state.surface.target.endpoint[8..];
            channel_info!(config_id, "🔌 Streamable HTTP for proxy:// channel proxy_id={}", proxy_id);

            let response = handle_mcp_proxy_request(
                &state,
                proxy_id,
                &body_bytes,
                &headers,
                &method,
                &uri,
                &channel_name,
                &source_addr,
                start_time,
                trace_id.clone(),
                authenticated_identity.as_ref(),
                &policy_input,
                mcp_context.as_ref(),
            )
            .await;

            // Treat in-protocol Err responses (HTTP 200 + JSON-RPC envelope,
            // e.g. disabled proxy / unknown tool) the same as Ok responses
            // for transport framing — wrap their body as a single SSE
            // `message` event so the client still gets a `text/event-stream`
            // response. Genuine HTTP errors (non-200) are propagated as-is.
            let resp = match response {
                Ok(r) => r,
                Err(r) if r.status() == StatusCode::OK => r,
                Err(r) => {
                    connection_guard
                        .decrement()
                        .await;
                    return Err(r);
                }
            };
            let (_, body) = resp.into_parts();
            let body_bytes_resp = axum::body::to_bytes(body, 10 * 1024 * 1024)
                .await
                .unwrap_or_default();
            let json_str = String::from_utf8_lossy(&body_bytes_resp);

            connection_guard
                .decrement()
                .await;
            return Ok(crate::mcp::sse_server::build_streamable_http_response(&json_str));
        }
    }

    // Handle MCP protocol if channel is configured for MCP
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && method == "POST"
        && !body_bytes.is_empty()
    {
        // Reject non-JSON-RPC-2.0 bodies on an MCP-protocol surface up front:
        // never leak a malformed request to the upstream target — fail fast with
        // the proper JSON-RPC error envelope (PARSE_ERROR / INVALID_REQUEST).
        //
        // The envelope is built directly here rather than routing through
        // `handle_mcp_request`: that dispatcher returns an internal forward
        // signal (HTTP 200 + `X-MCP-Forward`) for any well-formed method, and a
        // body that fails `is_mcp_request` only on the Content-Type check would
        // otherwise leak that signal to the caller instead of an error.
        if modern_request.is_none() && !crate::mcp::is_mcp_request(&headers, &body_bytes) {
            warn!(channel = channel_name, "Malformed MCP body on MCP surface — returning JSON-RPC error envelope");
            let err_response = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                Ok(json) => crate::mcp::create_mcp_error_response(
                    json.get("id").cloned(),
                    crate::mcp::error_codes::INVALID_REQUEST,
                    "Invalid JSON-RPC request",
                    None,
                ),
                Err(e) => crate::mcp::create_mcp_error_response(
                    None,
                    crate::mcp::error_codes::PARSE_ERROR,
                    "Invalid JSON",
                    Some(serde_json::json!({ "details": e.to_string() })),
                ),
            };
            connection_guard
                .decrement()
                .await;
            return Ok(err_response);
        }

        channel_info!(config_id, "Detected MCP request");

        // Check if this channel uses a proxy:// backend (MCP proxy)
        if state
            .surface
            .target
            .endpoint
            .starts_with("proxy://")
            && modern_request.is_none()
        {
            // Enforce inbound + surface OPA policies
            let policy_input = match evaluate_mcp_proxy_opa_policies(
                &state,
                method.as_ref(),
                &uri,
                &headers,
                &body_bytes,
                authenticated_identity.as_ref(),
                source_auth_context.as_ref(),
                mcp_context.as_ref(),
                payment_context.as_ref(),
                &trace_id,
            )
            .await
            {
                Ok(policy_input) => policy_input,
                Err(deny) => {
                    connection_guard
                        .decrement()
                        .await;
                    return Err(deny);
                }
            };

            let proxy_id = &state.surface.target.endpoint[8..]; // Extract ID after "proxy://"
            channel_info!(config_id, "🔌 Routing MCP request through proxy backend proxy_id={}", proxy_id);

            match handle_mcp_proxy_request(
                &state,
                proxy_id,
                &body_bytes,
                &headers,
                &method,
                &uri,
                &channel_name,
                &source_addr,
                start_time,
                trace_id.clone(),
                authenticated_identity.as_ref(),
                &policy_input,
                mcp_context.as_ref(),
            )
            .await
            {
                Ok(response) => {
                    // Decrement connection counter
                    connection_guard
                        .decrement()
                        .await;
                    return Ok(response);
                }
                Err(error_response) => {
                    // Decrement connection counter
                    connection_guard
                        .decrement()
                        .await;
                    return Err(error_response);
                }
            }
        }

        // Evaluate MCP tool-level policies (if any are configured).
        // Policy entries are stored on the surface as `policy_definition_id`
        // references; the evaluator resolves Rego text via the channel
        // policy manager's policy_definition_store at request time.
        if !state
            .surface
            .target
            .mcp_tool_policies
            .is_empty()
        {
            match evaluate_mcp_tool_policies(
                &state,
                &headers,
                &body_bytes,
                &channel_name,
                &source_addr,
                &uri,
                mcp_context.as_ref(),
            )
            .await
            {
                Ok(outcome) if outcome.allow => {
                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::McpTool,
                        allow: true,
                        surface_id: Some(channel_name.as_str()),
                        trace_id: Some(&trace_id),
                        http_method: Some(method.as_ref()),
                        path: Some(uri.path()),
                        identity: authenticated_identity.as_ref(),
                        ..Default::default()
                    });
                }
                Ok(outcome) => {
                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::McpTool,
                        allow: false,
                        reason: outcome.reason.as_deref(),
                        policy_id: outcome
                            .policy_id
                            .as_deref()
                            .or(outcome.tool_name.as_deref()),
                        policy_name: outcome.policy.name.as_deref(),
                        policy_version: outcome.policy.version,
                        policy_content_hash: outcome
                            .policy
                            .content_hash
                            .as_deref(),
                        policy_definition_id: outcome.policy_id.as_deref(),
                        surface_id: Some(channel_name.as_str()),
                        trace_id: Some(&trace_id),
                        http_method: Some(method.as_ref()),
                        path: Some(uri.path()),
                        identity: authenticated_identity.as_ref(),
                        ..Default::default()
                    });

                    // Record failed connection
                    if let Some(ref metrics) = state.metrics_store {
                        let latency_ms = start_time
                            .elapsed()
                            .as_millis() as u64;
                        let metrics = Arc::clone(metrics);
                        let channel_config_id = state
                            .surface
                            .surface_id
                            .clone();
                        let source = source_addr.clone();
                        let dest = state
                            .surface
                            .target
                            .endpoint
                            .clone();
                        tokio::spawn(async move {
                            metrics
                                .record_connection(
                                    channel_config_id,
                                    source,
                                    dest,
                                    crate::metrics::ConnectionStatus::Failed,
                                    Some(latency_ms),
                                    None,
                                    crate::metrics::ConnectionDirection::Request,
                                    trace_id.clone(),
                                    None,
                                    None,
                                    latency_ms,
                                    None,
                                )
                                .await;
                        });
                    }

                    // Return JSON-RPC error response
                    let request_id = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                        .ok()
                        .and_then(|json| json.get("id").cloned());
                    let error_response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32000,
                            "message": "Access denied: insufficient permissions for this tool"
                        }
                    });
                    connection_guard
                        .decrement()
                        .await;
                    return Ok(axum::response::Json(error_response).into_response());
                }
                Err(e) => {
                    error!(channel = channel_name, error = %e, "Failed to evaluate MCP tool policy");

                    // Return JSON-RPC error response
                    let request_id = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                        .ok()
                        .and_then(|json| json.get("id").cloned());
                    let error_response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32603,
                            "message": "Internal error: policy evaluation failed"
                        }
                    });
                    connection_guard
                        .decrement()
                        .await;
                    return Ok(axum::response::Json(error_response).into_response());
                }
            }
        }

        // Check if this request should be handled locally or forwarded
        if modern_request.is_none() {
            match crate::mcp::handle_mcp_request(&state, &body_bytes, &channel_name).await {
                Ok(json_rpc_response) => {
                    // Successfully handled MCP request locally (shouldn't happen in current design)
                    // Record the successful connection with metrics
                    if let Some(ref metrics) = state.metrics_store {
                        let latency_ms = start_time
                            .elapsed()
                            .as_millis() as u64;
                        let metrics = Arc::clone(metrics);
                        let channel_config_id = state
                            .surface
                            .surface_id
                            .clone();
                        let source = source_addr.clone();
                        let dest = state
                            .surface
                            .target
                            .endpoint
                            .clone();
                        tokio::spawn(async move {
                            metrics
                                .record_connection(
                                    channel_config_id,
                                    source,
                                    dest,
                                    crate::metrics::ConnectionStatus::Success,
                                    Some(latency_ms),
                                    None,
                                    crate::metrics::ConnectionDirection::Request,
                                    trace_id,
                                    None,
                                    None,
                                    latency_ms,
                                    None,
                                )
                                .await;
                        });
                    }

                    // Return JSON-RPC response
                    connection_guard
                        .decrement()
                        .await;
                    return Ok(axum::response::Json(json_rpc_response).into_response());
                }
                Err(err_response) => {
                    // Check if this is a forward signal (has X-MCP-Forward header)
                    if err_response
                        .headers()
                        .get("X-MCP-Forward")
                        .is_some()
                    {
                        // This should be forwarded to upstream
                        info!(channel = channel_name, "MCP request will be forwarded to upstream");
                        // Fall through to normal forwarding logic below
                    } else {
                        // Actual error, return it
                        connection_guard
                            .decrement()
                            .await;
                        return Ok(err_response);
                    }
                }
            }
        }
    }

    // x402 payment has already been verified earlier in the handler (line ~395)
    // Use MPP receipt if available, otherwise None
    let payment_response_header: Option<String> = mpp_receipt_header;
    let mut modern_local_receipt = None;

    // Inspect extensions if enabled and this is a POST with JSON body (A2A or MCP protocol)
    // Also capture if client supports credential extension for response VP injection
    let (mut identity_result, client_supports_vp) = if state
        .config
        .extension_inspection
        .enabled
        && method == "POST"
        && !body_bytes.is_empty()
        && (state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::A2a
            || state
                .surface
                .channel_protocol()
                == crate::config::ChannelProtocol::Ap2
            || state
                .surface
                .channel_protocol()
                == crate::config::ChannelProtocol::Mcp)
    {
        let inspection_span = tracing::info_span!(
            "channel.extension_inspection",
            otel.name = "Extension Inspection",
            surface = %channel_name
        );

        let inspection_ctx = crate::a2a::ExtensionInspectionContext {
            config: &state.config,
            channel_name: &channel_name,
            surface: &state.surface,
            rules_engine: &state.identity_rules_engine,
            identity_selector: &state.identity_selector,
            source_authenticated: authenticated_identity.is_some(),
            metrics_store: &state.metrics_store,
            ws_state: &state.ws_state,
            variant_alias: state
                .active_variant_alias
                .as_deref(),
        };

        let identity_result = match async { inspect_message_extensions(&body_bytes, &inspection_ctx).await }
            .instrument(inspection_span)
            .await
        {
            Ok(result) => result,
            Err(response) => {
                // Record failed connection due to validation rejection
                if let Some(ref metrics) = state.metrics_store {
                    let latency_ms = start_time
                        .elapsed()
                        .as_millis() as u64;
                    let metrics = Arc::clone(metrics);
                    let channel_config_id = state
                        .surface
                        .surface_id
                        .clone();
                    let source = source_addr.clone();
                    let dest = state
                        .surface
                        .target
                        .endpoint
                        .clone();
                    let trace_id = uuid::Uuid::new_v4().to_string();
                    tokio::spawn(async move {
                        metrics
                            .record_connection(
                                channel_config_id,
                                source,
                                dest,
                                crate::metrics::ConnectionStatus::Failed,
                                Some(latency_ms),
                                None,
                                crate::metrics::ConnectionDirection::Request,
                                trace_id,
                                None,
                                None,
                                latency_ms,
                                None,
                            )
                            .await;
                    });
                }

                // Track error (connection guard will handle decrement)
                if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
                    let task_id = task_id.clone();
                    let monitor = task_monitor.clone();
                    tokio::spawn(async move {
                        info!(task_id = %task_id, "Recording error: Extension validation failed");
                        monitor
                            .increment_errors(&task_id)
                            .await;
                    });
                }

                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        };

        // Check if client supports credential extension (for response VP injection)
        let supports_vp = does_client_support_vp_extension(
            &state
                .surface
                .channel_protocol(),
            &body_bytes,
            &channel_name,
        );

        (identity_result, supports_vp)
    } else {
        debug!(channel = channel_name, protocol = ?state.surface.channel_protocol(), "Skipping extension inspection - conditions not met");
        (None, false)
    };

    // ── Configured caller identity (FromMtls / FromApiKey / Static) ─────────
    if identity_result.is_none() {
        match resolve_configured_caller_identity(&state, method.as_str(), uri.path(), &channel_name, "direct").await {
            Ok(resolved) => identity_result = resolved,
            Err(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
    }

    // ── Request-bound identity resolution (FromJwtClaim) ──────────────────
    //
    // `from_jwt_claim` on the inbound slot derives the *caller* agent's DID
    // from a validated JWT claim (e.g. the Entra Agent ID `oid`) produced by
    // `jwt_bearer` source auth, then feeds the same `identity_result` /
    // VP-inject path so the caller's identity VP is forwarded upstream to the
    // target. This is the request leg — distinct from the protected slot,
    // which stamps the managed agent's DID on the response back to the caller.
    //
    // Skipped on public/discovery paths (`is_public_path`): source auth is
    // bypassed there, so no JWT claims exist and there is no caller identity to
    // resolve — mirrors the Trust Check and surface OPA discovery bypasses.
    if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && identity_result.is_none()
        && let Some(crate::source_auth::ManagedIdentityConfig::FromJwtClaim { claim, namespace_claims }) = state
            .surface
            .inbound_identity()
    {
        let mode_label = "from_jwt_claim";
        let started = std::time::Instant::now();
        let Some(claims) = authenticated_identity
            .as_ref()
            .and_then(|i| i.jwt_claims())
        else {
            crate::metrics::backends::prometheus::track_managed_identity_resolve(
                &channel_name,
                mode_label,
                "jwt_claims_unavailable",
                started
                    .elapsed()
                    .as_secs_f64(),
            );
            connection_guard
                .decrement()
                .await;
            return Err(create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "from_jwt_claim requires jwt_bearer source auth on this surface",
            ));
        };
        match crate::identity::credential_identity::resolve_jwt_claim_identity(claim, namespace_claims, claims) {
            Ok(crate::identity::credential_identity::CredentialIdentity::Derived {
                identity_fields,
                identity_hash,
            }) => {
                let vc_issuer_opt = state
                    .identity_selector
                    .as_ref()
                    .map(|s| s.get_vc_issuer())
                    .or_else(|| state.vc_issuer.clone());
                let Some(issuer) = vc_issuer_opt else {
                    crate::metrics::backends::prometheus::track_managed_identity_resolve(
                        &channel_name,
                        mode_label,
                        "vc_issuer_missing",
                        started
                            .elapsed()
                            .as_secs_f64(),
                    );
                    connection_guard
                        .decrement()
                        .await;
                    return Err(create_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "from_jwt_claim requires a configured VC issuer",
                    ));
                };
                match issuer
                    .issue_or_get_caller_credential(
                        identity_fields.clone(),
                        Some(identity_hash.clone()),
                        state
                            .surface
                            .config_id()
                            .map(String::from),
                        state
                            .surface
                            .issuer_id
                            .clone(),
                    )
                    .await
                {
                    Ok(response) => {
                        crate::metrics::backends::prometheus::track_managed_identity_resolve(
                            &channel_name,
                            mode_label,
                            if response.is_new {
                                "ok_new"
                            } else {
                                "ok_cached"
                            },
                            started
                                .elapsed()
                                .as_secs_f64(),
                        );
                        info!(
                            channel = channel_name,
                            did = %response.did,
                            is_new = response.is_new,
                            "Resolved inbound agent DID from JWT claim"
                        );
                        identity_result = Some(crate::identity::IdentityResult {
                            verification: crate::surface_context::IdentityVerification::SourceAuth,
                            hash: identity_hash,
                            did: response.did,
                            is_new: response.is_new,
                            identity_fields,
                            issuer_did: None,
                        });
                    }
                    Err(e) => {
                        crate::metrics::backends::prometheus::track_managed_identity_resolve(
                            &channel_name,
                            mode_label,
                            "vc_issuer_error",
                            started
                                .elapsed()
                                .as_secs_f64(),
                        );
                        connection_guard
                            .decrement()
                            .await;
                        return Err(create_error_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("VCIssuer failure during from_jwt_claim resolution: {e}"),
                        ));
                    }
                }
            }
            Ok(_) => unreachable!("resolve_jwt_claim_identity only returns Derived"),
            Err(e) => {
                let result_label = match &e {
                    crate::identity::credential_identity::CredentialIdentityError::JwtClaimMissing(_) => {
                        "jwt_claim_missing"
                    }
                    _ => "jwt_claim_error",
                };
                crate::metrics::backends::prometheus::track_managed_identity_resolve(
                    &channel_name,
                    mode_label,
                    result_label,
                    started
                        .elapsed()
                        .as_secs_f64(),
                );
                connection_guard
                    .decrement()
                    .await;
                return Err(create_error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("from_jwt_claim could not derive identity: {e}"),
                ));
            }
        }
    }

    // Destructure identity result into separate hash and DID
    let identity_hash = identity_result
        .as_ref()
        .map(|r| r.hash.clone());
    let request_agent_did = identity_result
        .as_ref()
        .map(|r| r.did.clone());
    let request_user_id = source_auth_user_id(authenticated_identity.as_ref());
    let request_user_hash = source_auth_user_hash(authenticated_identity.as_ref());

    // Stamp the derived agent DID onto the root HTTP span as `caller.did`.
    // For credential-derived managed identity (e.g. `from_jwt_claim`) the DID
    // is only known here, after the request pipeline resolves it — unlike
    // `did_auth`, where it is already recorded at authentication time.
    if let Some(did) = request_agent_did.as_deref() {
        crate::observability::record_caller_did_on_current_span(did);
    }

    // ── Build ExtensionIdentityContext from identity result ─────────────────
    let extension_identity = identity_result
        .as_ref()
        .map(|result| crate::surface_context::ExtensionIdentityContext {
            verification: result.verification,
            did: Some(result.did.clone()),
            identity_hash: Some(result.hash.clone()),
        });

    // Surface the cryptographically-verified issuer DID of the caller's
    // `agent-identity-credential/v1` VP as `input.agent.identity_issuer_did`,
    // so a caller-leg Trust Check authority can default to the *proven* issuer
    // rather than a self-asserted metadata field. Only set when a VP was
    // actually verified (never for raw/credential-derived identity), so a
    // non-VP caller leaves it `None` and any template defaulting to it
    // resolves empty → deny (fail-safe).
    if let Some(issuer_did) = identity_result
        .as_ref()
        .and_then(|r| r.issuer_did.clone())
        && let Some(agent) = agent_context.as_mut()
    {
        agent.identity_issuer_did = Some(issuer_did);
    }

    // Agent identity is now resolved on the request path (above) when identity
    // extraction is enabled. The response path still handles VP credential injection.

    // ── Extract and verify inbound identity binding VP (from upstream gateway) ──
    let binding_result = if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
    {
        Ok(mcp_verified_binding)
    } else {
        let result = crate::protocols::extensions::extract_identity_binding_vp(
            &body_bytes,
            &state
                .surface
                .channel_protocol(),
            &state.identity_selector,
            &channel_name,
            None,
        )
        .await;
        crate::observability::identity_binding_audit::audit_extraction(&state.surface.surface_id, None, &result);
        result
    };
    let identity_binding = match binding_result {
        Ok(binding) => binding,
        Err(e) => {
            warn!(channel = channel_name, error = %e, "Identity binding VP present but invalid");
            None // Continue without binding context — OPA can decide
        }
    };

    // Persist the verified external agent DID so it appears on the local
    // Identities page (mirrors `fabric_identity.rs` response-path handling).
    if let (Some(binding), Some(selector)) = (
        identity_binding.as_ref(),
        state
            .identity_selector
            .as_ref(),
    ) && binding.verified
    {
        let identity_store = selector
            .get_vc_issuer()
            .get_identity_store();
        if let Err(e) = identity_store
            .store_external_did(
                &binding.agent_did,
                binding
                    .identity_fields
                    .clone(),
                Some(
                    state
                        .surface
                        .surface_id
                        .clone(),
                ),
                true,
            )
            .await
        {
            warn!(
                channel = channel_name,
                did = %binding.agent_did,
                error = %e,
                "Failed to persist verified inbound agent DID from identity binding VP"
            );
        } else {
            info!(
                channel = channel_name,
                did = %binding.agent_did,
                "Persisted verified inbound agent DID from identity binding VP"
            );
        }
    }

    // ── Identity binding VP: minted later ────────────────────────────────
    //
    // The user→agent identity VP used to be created here, but its
    // `workloadBinding.delegationAction` would always be empty because
    // credential delegation hasn't run yet. It is now minted at the
    // "deferred request VP injection" site below, after the resolver has
    // produced the per-binding `delegationAction` summary.

    // ── Capture buffer for delegation audit events ─────────────────────
    //
    // The per-binding audit events (TokenInjected/Refreshed/ConsentRequired/
    // elicitation_*) are emitted by `resolve_delegation_credentials` *before*
    // we know the final `delegationAction` summary. We buffer them via a
    // tokio task-local queue, then re-stamp each with the canonical identity
    // VP after the deferred mint below. When workload-binding attestation is
    // explicitly configured, that VP carries `workloadBinding.delegationAction`;
    // otherwise it stays in the legacy `identityFields` shape.
    let deferred_audit_queue: std::sync::Arc<
        std::sync::Mutex<Vec<crate::delegation_vault::audit::DelegationAuditEvent>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    // Note: outbound request body VP injection is deferred to after credential
    // delegation resolves (see "deferred request VP injection" below) so an
    // explicitly configured workload-binding VP can carry the full
    // `workloadBinding.delegationAction` summary. Injection fires when the
    // `inject_identity_vp()` toggle is on OR the primary target has an enabled
    // Workload Binding element; both are re-checked at the deferred site.

    // Inject custom metadata extension if enabled for this channel
    let body_bytes = if let Some(custom_metadata) = state
        .surface
        .custom_metadata()
    {
        if custom_metadata.enabled && method == "POST" && !body_bytes.is_empty() {
            // For A2A and AP2 protocols, inject A2A-style metadata
            if state
                .surface
                .channel_protocol()
                == crate::config::ChannelProtocol::A2a
                || state
                    .surface
                    .channel_protocol()
                    == crate::config::ChannelProtocol::Ap2
            {
                match inject_custom_metadata_extension(
                    &body_bytes,
                    custom_metadata,
                    &channel_name,
                    &state.secrets_store,
                    crate::protocols::MetadataRuntimeContext {
                        request_id: Some(egress_trace_id.as_str()),
                        surface_id: Some(config_id),
                    },
                )
                .await
                {
                    Ok(modified_bytes) => {
                        info!(channel = channel_name, "Custom metadata extension injected (A2A)");
                        modified_bytes
                    }
                    Err(e) => {
                        warn!(channel = channel_name, error = %e, "Failed to inject custom metadata extension, using original body");
                        body_bytes
                    }
                }
            } else {
                // For MCP and other protocols, metadata injection happens in response handling
                body_bytes
            }
        } else {
            body_bytes
        }
    } else {
        body_bytes
    };

    // Enbindification
    // ── Request-path VP injection is deferred ───────────────────────────────
    //
    // Historically the identity-binding VP was minted and injected into the
    // outbound body here, BEFORE credential delegation had run. That meant the
    // VP — both the one wrapped into the upstream body AND the one written to
    // the audit log — carried no `workloadBinding.delegationAction`, because
    // the delegation outcomes did not yet exist.
    //
    // To give the upstream and the audit trail an action-aware cryptographic
    // record when workload binding is enabled, the VP is now built and injected
    // AFTER the delegation block resolves. Search for `deferred request VP
    // injection` below for the actual mint + inject + audit site.
    //
    // `body_bytes` flows through unchanged at this point; subsequent
    // protocol-specific body mutations (AP2 VDC, DID:webvh, custom metadata,
    // etc.) still happen here so that the late VP wraps the final body.

    // Load DID:webvh identity context if configured (used for injection below)
    #[cfg(feature = "didwebvh")]
    let did_context = load_did_identity_context(&state).await;

    // Inject DID:webvh identity into A2A protocol body (protocol-native mode)
    #[cfg(feature = "didwebvh")]
    let body_bytes = {
        if let Some(ref context) = did_context {
            use crate::config::DidInjectionMode;
            if *context.injection_mode() == DidInjectionMode::ProtocolNative
                && state
                    .surface
                    .channel_protocol()
                    == crate::config::ChannelProtocol::A2a
                && method == "POST"
                && !body_bytes.is_empty()
            {
                match crate::a2a::inject_didwebvh_identity_extension(&body_bytes, context, &channel_name).await {
                    Ok(modified_bytes) => {
                        info!(channel = channel_name, did = %context.did(), "DID:webvh identity injected into A2A extensions");
                        modified_bytes
                    }
                    Err(e) => {
                        warn!(channel = channel_name, error = %e, "Failed to inject DID:webvh identity into A2A extensions, using original body");
                        body_bytes
                    }
                }
            } else {
                body_bytes
            }
        } else {
            body_bytes
        }
    };
    #[cfg(not(feature = "didwebvh"))]
    let mut body_bytes = body_bytes;
    #[cfg(feature = "didwebvh")]
    #[allow(unused_mut)]
    let mut body_bytes = body_bytes;

    // ── Trust Check stage (caller leg) ──────────────────────────────────────
    // Runs after the managed-identity resolver populates `extension_identity`
    // and before the inbound/surface OPA gates read `trust_check_results`, so
    // templates that reference `{{ input.extension_identity.did }}` resolve
    // against the gateway-derived agent DID across every identity mode.
    // Gateway OPA already ran above and never sees these results.
    // Caller-only by construction: target-leg entries are unaffected. No-op
    // when the caller-leg list is empty.
    //
    // Skipped on discovery requests (`.well-known/agent-card.json` etc., per
    // `is_public_path`) — surface OPA bypasses the same requests. Discovery is
    // unauthenticated by design so the caller-leg check has no caller to
    // verify; running it would only emit a spurious `TEMPLATE_RESOLUTION_FAILED`
    // and burn a trust-registry round-trip whose result nobody reads.
    {
        let caller_elements = &state
            .surface
            .access_point
            .trust_check_list;
        if !caller_elements.is_empty()
            && !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
            && let Some(manager) = state
                .trust_registry_listener_manager
                .clone()
        {
            let client = crate::trust_registry_verification::TrqpListenerClient::new(manager);
            let mut probe_input = crate::surface_context::PolicyInput::new(
                method.as_ref(),
                uri.path(),
                crate::surface_context::filter_sensitive_headers(&headers),
                "inbound",
                None,
                None,
                state
                    .surface
                    .config_id()
                    .map(|s| s.to_string()),
                &state.surface.name,
            );
            probe_input.source_auth = source_auth_context.clone();
            probe_input.agent = agent_context.clone();
            probe_input.mcp = mcp_context.clone();
            probe_input.a2a = a2a_context.clone();
            probe_input.extension_identity = extension_identity.clone();
            probe_input.payment = payment_context.clone();
            probe_input.identity_binding = identity_binding.clone();
            probe_input.normalize_caller_did();
            trust_check_results = crate::trust_registry_verification::run_caller_trust_check(
                state
                    .surface
                    .surface_id
                    .as_str(),
                caller_elements,
                &probe_input,
                &client,
            )
            .await;
        }
    }

    // ── Trust Check stage (target leg, A2A Proxy target) ───────────────────
    // A2A Proxy targets do not have an upstream A2A endpoint to fetch an
    // agent card from. Build the same synthesized card used by public
    // discovery and use it as target context before surface OPA evaluates
    // `input.trust_check_results.target`.
    {
        let target_elements = &state
            .surface
            .target
            .trust_check_list;
        if !target_elements.is_empty()
            && state
                .surface
                .target
                .endpoint
                .starts_with("a2a-proxy://")
        {
            let prepared_card = prepare_a2a_proxy_agent_card_for_target_context(&state, &channel_name).await;
            if let Some(card_json) = prepared_card {
                if let Some(manager) = state
                    .trust_registry_listener_manager
                    .clone()
                {
                    let body_json: Option<serde_json::Value> = serde_json::from_slice(&body_bytes).ok();
                    let agent_ctx = crate::policies::build_agent_context(
                        body_json.as_ref(),
                        Some(&card_json),
                        state
                            .trust_registry_listener_manager
                            .as_deref(),
                        true,
                    )
                    .await;
                    let mut probe_input = crate::surface_context::PolicyInput::new(
                        method.as_ref(),
                        uri.path(),
                        crate::surface_context::filter_sensitive_headers(&headers),
                        "inbound",
                        None,
                        None,
                        state
                            .surface
                            .config_id()
                            .map(|s| s.to_string()),
                        &state.surface.name,
                    );
                    probe_input.source_auth = source_auth_context.clone();
                    probe_input.agent = Some(agent_ctx);
                    probe_input.mcp = mcp_context.clone();
                    probe_input.a2a = a2a_context.clone();
                    probe_input.extension_identity = extension_identity.clone();
                    probe_input.payment = payment_context.clone();
                    probe_input.identity_binding = identity_binding.clone();
                    let probe_value = serde_json::to_value(&probe_input).unwrap_or_default();
                    if let Some(target_results) = crate::trust_registry_verification::run_trust_check_stage(
                        state
                            .surface
                            .surface_id
                            .as_str(),
                        crate::trust_registry_verification::TrustCheckLeg::Target,
                        target_elements,
                        &probe_value,
                        &crate::trust_registry_verification::TrqpListenerClient::new(manager),
                    )
                    .await
                    {
                        let mut merged = trust_check_results
                            .take()
                            .unwrap_or_default();
                        merged.target = target_results.target;
                        trust_check_results = Some(merged);
                    }
                }
            } else {
                let mut merged = trust_check_results
                    .take()
                    .unwrap_or_default();
                merged.target = target_elements
                    .iter()
                    .map(|elem| {
                        crate::trust_registry_verification::synthesize_failure(
                            elem,
                            crate::trust_registry_verification::AGENT_CARD_UNAVAILABLE,
                            "A2A proxy target agent card could not be synthesized".to_string(),
                        )
                    })
                    .collect();
                trust_check_results = Some(merged);
            }
        }
    }

    // Access-Point Inbound OPA Policy check.
    //
    // Runs BEFORE the target-side surface OPA gate so a variant override of
    // `access_point.inbound_policy` can deny the request before any
    // target-side processing. Independent of `state.surface.opa_enabled()`
    // (which gates `target.policy`) — both can fire on the same request.
    // Sees the caller-leg `trust_check_results` populated above.
    if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && state
            .surface
            .inbound_opa_enabled()
        && let Some(config_id_str) = state.surface.config_id()
    {
        let mut policy_input = crate::surface_context::PolicyInput::new(
            method.as_ref(),
            uri.path(),
            crate::surface_context::filter_sensitive_headers(&headers),
            "inbound",
            None,
            None,
            state
                .surface
                .config_id()
                .map(|s| s.to_string()),
            &state.surface.name,
        );
        policy_input.source_auth = source_auth_context.clone();
        policy_input.agent = agent_context.clone();
        policy_input.mcp = mcp_context.clone();
        policy_input.a2a = a2a_context.clone();
        policy_input.extension_identity = extension_identity.clone();
        policy_input.payment = payment_context.clone();
        policy_input.identity_binding = identity_binding.clone();
        policy_input.trust_check_results = trust_check_results.clone();
        let input_value = serde_json::to_value(&policy_input).unwrap_or_default();

        let Some(policy_manager) = state.policy_manager.as_ref() else {
            channel_warn!(
                config_id_str,
                "Access-point inbound OPA policy is configured but policy manager is not available — denying request"
            );
            connection_guard
                .decrement()
                .await;
            return Err(axum::response::Response::builder()
                .status(axum::http::StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                ))
                .unwrap());
        };
        let inbound_policy_def_id = state
            .surface
            .inbound_opa_policy_definition_id();
        let (inbound_policy_name, inbound_policy_version, inbound_policy_hash) = policy_manager
            .resolve_policy_decision_evidence(inbound_policy_def_id)
            .await;
        match policy_manager.evaluate_inbound_policy_decision_for_variant(
            config_id_str,
            state
                .active_variant_alias
                .as_deref(),
            input_value,
        ) {
            Ok(decision) if decision.allow => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: true,
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: inbound_policy_def_id,
                    policy_name: Some(inbound_policy_name.as_str()),
                    policy_version: inbound_policy_version,
                    policy_content_hash: inbound_policy_hash.as_deref(),
                    surface_id: Some(config_id_str),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    actor_did: request_agent_did.as_deref(),
                    ..Default::default()
                });
            }
            Ok(decision) => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: false,
                    reason: decision.reason.as_deref(),
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: inbound_policy_def_id,
                    policy_name: Some(inbound_policy_name.as_str()),
                    policy_version: inbound_policy_version,
                    policy_content_hash: inbound_policy_hash.as_deref(),
                    surface_id: Some(config_id_str),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    actor_did: request_agent_did.as_deref(),
                    ..Default::default()
                });
                connection_guard
                    .decrement()
                    .await;
                if crate::mcp::is_tools_call_request(&body_bytes) {
                    return Err(crate::mcp::build_tools_call_policy_denied_response(
                        &body_bytes,
                        decision.reason.as_deref(),
                    ));
                }
                return Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                    ))
                    .unwrap());
            }
            Err(e) => {
                channel_warn!(
                    config_id_str,
                    "Access-point inbound OPA policy evaluation error (denying request): {}",
                    e
                );
                connection_guard
                    .decrement()
                    .await;
                if crate::mcp::is_tools_call_request(&body_bytes) {
                    return Err(crate::mcp::build_tools_call_policy_denied_response(
                        &body_bytes,
                        Some("policy evaluation error"),
                    ));
                }
                return Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                    ))
                    .unwrap());
            }
        }
    }

    // ── Appliance-wide (global) surface policy ───────────────────────────────
    // Enforced deny-overrides ahead of the per-surface policy on every direct
    // inbound request, regardless of the surface's own OPA configuration and
    // regardless of whether the path is a public discovery endpoint — a
    // deny-override the caller can switch off by choosing a path is not a
    // control. Mirrors the gateway-plane gate above.
    if let Some(global_pm) = crate::gateways::get_appliance_policy_manager()
        && global_pm.has_global(crate::policies::global_policy::PLANE_AGENT_SURFACE)
    {
        let mut g_input = crate::surface_context::PolicyInput::new(
            method.as_ref(),
            uri.path(),
            crate::surface_context::filter_sensitive_headers(&headers),
            "inbound",
            None,
            None,
            state
                .surface
                .config_id()
                .map(|s| s.to_string()),
            &state.surface.name,
        );
        g_input.source_auth = source_auth_context.clone();
        g_input.agent = agent_context.clone();
        g_input.mcp = mcp_context.clone();
        g_input.a2a = a2a_context.clone();
        g_input.extension_identity = extension_identity.clone();
        g_input.payment = payment_context.clone();
        g_input.identity_binding = identity_binding.clone();
        g_input.trust_check_results = trust_check_results.clone();
        g_input.normalize_caller_did();
        let g_input_value = serde_json::to_value(&g_input).unwrap_or_default();
        let gd = global_pm.evaluate_global(crate::policies::global_policy::PLANE_AGENT_SURFACE, &g_input_value);
        let global_policy_name = gd.policy_name.as_deref();
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::Surface,
            allow: gd.allow,
            reason: gd.reason.as_deref(),
            policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
            policy_definition_id: gd.policy_id.as_deref(),
            policy_name: global_policy_name,
            surface_id: state.surface.config_id(),
            trace_id: Some(&trace_id),
            http_method: Some(method.as_ref()),
            path: Some(uri.path()),
            identity: authenticated_identity.as_ref(),
            policy_version: gd.version,
            policy_content_hash: gd.content_hash.as_deref(),
            ..Default::default()
        });
        if !gd.allow {
            connection_guard
                .decrement()
                .await;
            if crate::mcp::is_tools_call_request(&body_bytes) {
                return Err(crate::mcp::build_tools_call_policy_denied_response(&body_bytes, gd.reason.as_deref()));
            }
            return Err(create_error_response(StatusCode::FORBIDDEN, "Request blocked by appliance-wide policy"));
        }
    }

    // Surface-Level OPA Policy check (evaluated against resolved AgentContext)
    // Skip for discovery requests (agent-card, /.well-known/ucp, etc.) — no trust check needed
    if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && state.surface.opa_enabled()
        && let Some(config_id_str) = state.surface.config_id()
    {
        let mut policy_input = crate::surface_context::PolicyInput::new(
            method.as_ref(),
            uri.path(),
            crate::surface_context::filter_sensitive_headers(&headers),
            "inbound",
            None,
            None,
            state
                .surface
                .config_id()
                .map(|s| s.to_string()),
            &state.surface.name,
        );
        policy_input.source_auth = source_auth_context.clone();
        // [OPA-INPUT] Surface policy input BEFORE agent/TR data
        info!(
            channel = config_id_str,
            "[OPA-INPUT] Surface policy input before TR: {}",
            serde_json::to_string(&policy_input).unwrap_or_default()
        );
        policy_input.agent = agent_context.clone();
        policy_input.mcp = mcp_context.clone();
        policy_input.a2a = a2a_context.clone();
        policy_input.extension_identity = extension_identity.clone();
        policy_input.payment = payment_context.clone();
        policy_input.identity_binding = identity_binding.clone();
        policy_input.trust_check_results = trust_check_results.clone();
        policy_input.normalize_caller_did();
        let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
        // [OPA-INPUT] Surface policy input fully populated
        info!(channel = config_id_str, "[OPA-INPUT] Surface policy input before eval: {}", input_value);

        let Some(policy_manager) = state
            .policy_manager
            .as_ref()
            .filter(|pm| {
                pm.has_policy_for_variant(
                    config_id_str,
                    state
                        .active_variant_alias
                        .as_deref(),
                )
            })
        else {
            channel_warn!(config_id_str, "OPA is enabled but no compiled policy found for channel — denying request");
            connection_guard
                .decrement()
                .await;
            if crate::mcp::is_tools_call_request(&body_bytes) {
                return Err(crate::mcp::build_tools_call_policy_denied_response(
                    &body_bytes,
                    Some("no policy is loaded for this channel"),
                ));
            }
            return Err(axum::response::Response::builder()
                .status(axum::http::StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"Forbidden","message":"OPA policy enforcement is enabled but no policy is loaded for this channel"}"#,
                ))
                .unwrap());
        };
        let channel_opa_def_id = state
            .surface
            .opa_policy_definition_id();
        let (channel_opa_name, channel_opa_version, channel_opa_hash) = policy_manager
            .resolve_policy_decision_evidence(channel_opa_def_id)
            .await;
        match policy_manager.evaluate_policy_decision_for_variant(
            config_id_str,
            state
                .active_variant_alias
                .as_deref(),
            input_value,
        ) {
            Ok(decision) if decision.allow => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: true,
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: channel_opa_def_id,
                    policy_name: Some(channel_opa_name.as_str()),
                    surface_id: Some(config_id_str),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    actor_did: request_agent_did.as_deref(),
                    policy_version: channel_opa_version,
                    policy_content_hash: channel_opa_hash.as_deref(),
                    ..Default::default()
                });
            }
            Ok(decision) => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: false,
                    reason: decision.reason.as_deref(),
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: channel_opa_def_id,
                    policy_name: Some(channel_opa_name.as_str()),
                    surface_id: Some(config_id_str),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    actor_did: request_agent_did.as_deref(),
                    policy_version: channel_opa_version,
                    policy_content_hash: channel_opa_hash.as_deref(),
                    ..Default::default()
                });
                connection_guard
                    .decrement()
                    .await;
                if crate::mcp::is_tools_call_request(&body_bytes) {
                    return Err(crate::mcp::build_tools_call_policy_denied_response(
                        &body_bytes,
                        decision.reason.as_deref(),
                    ));
                }
                return Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                    ))
                    .unwrap());
            }
            Err(e) => {
                channel_warn!(config_id_str, "Surface-level OPA policy evaluation error (denying request): {}", e);
                connection_guard
                    .decrement()
                    .await;
                if crate::mcp::is_tools_call_request(&body_bytes) {
                    return Err(crate::mcp::build_tools_call_policy_denied_response(
                        &body_bytes,
                        Some("policy evaluation error"),
                    ));
                }
                return Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                    ))
                    .unwrap());
            }
        }
    }
    // ▲▲▲ development

    // MCP Tool Gating — runtime `tools/call` enforcement. A tool the gating
    // firewall hides from `tools/list` must also be uncallable. Runs
    // independently of the surface OPA gate above (which may be disabled) and
    // only for MCP `tools/call` requests on surfaces that have gating
    // installed. The gate condition is evaluated against the same `PolicyInput`
    // the surface OPA gate and the tools/list filter see, so a gate that hides
    // a tool from the list decides identically here.
    if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::Mcp
        && crate::mcp::is_tools_call_request(&body_bytes)
        && let Some(config_id_str) = state.surface.config_id()
        && let Some(policy_manager) = state.policy_manager.as_ref()
        && let Some(gating) = policy_manager
            .compiled_mcp_tool_gating(
                config_id_str,
                state
                    .active_variant_alias
                    .as_deref(),
            )
            .filter(|g| !g.is_empty())
        && let Some(tool_name) = mcp_context
            .as_ref()
            .and_then(|m| m.tool_name.as_deref())
    {
        // Only build + serialize the request context when a gate carries an OPA
        // condition; pure-regex gating decides on the tool name alone.
        let input_value = if gating.has_policy_conditions() {
            let mut policy_input = crate::surface_context::PolicyInput::new(
                method.as_ref(),
                uri.path(),
                crate::surface_context::filter_sensitive_headers(&headers),
                "inbound",
                None,
                None,
                Some(config_id_str.to_string()),
                &state.surface.name,
            );
            policy_input.source_auth = source_auth_context.clone();
            policy_input.agent = agent_context.clone();
            policy_input.mcp = mcp_context.clone();
            policy_input.a2a = a2a_context.clone();
            policy_input.extension_identity = extension_identity.clone();
            policy_input.payment = payment_context.clone();
            policy_input.identity_binding = identity_binding.clone();
            policy_input.trust_check_results = trust_check_results.clone();
            policy_input.normalize_caller_did();
            serde_json::to_value(&policy_input).unwrap_or_default()
        } else {
            serde_json::Value::Null
        };

        let allowed = gating.is_tool_call_allowed(tool_name, &input_value);

        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::McpTool,
            allow: allowed,
            reason: if allowed {
                None
            } else {
                Some("blocked by MCP tool gating")
            },
            policy_id: Some("mcp_tool_gating"),
            surface_id: Some(config_id_str),
            trace_id: Some(&trace_id),
            http_method: Some(method.as_ref()),
            path: Some(uri.path()),
            identity: authenticated_identity.as_ref(),
            actor_did: request_agent_did.as_deref(),
            ..Default::default()
        });

        if !allowed {
            channel_warn!(config_id_str, "MCP tool gating blocked tools/call for tool '{}'", tool_name);
            connection_guard
                .decrement()
                .await;
            return Err(crate::mcp::build_tools_call_policy_denied_response(
                &body_bytes,
                Some("Tool is not available"),
            ));
        }
    }

    // A2A Proxy target adapter: the surface remains the public A2A/AP2 endpoint,
    // while the target endpoint dispatches to an internal configured adapter.
    // Dispatch happens after the normal gateway/source-auth/body/trust/OPA
    // controls above, but before any network upstream request is built.
    if is_a2a_proxy_target {
        let Some(proxy_id) =
            crate::a2a_proxies::A2aProxyTargetAdapter::proxy_id_from_endpoint(&state.surface.target.endpoint)
        else {
            let response = crate::a2a_proxies::target_adapter::json_rpc_target_error(
                &body_bytes,
                crate::a2a_proxies::target_adapter::A2aProxyTargetError::InvalidEndpoint,
            );
            connection_guard
                .decrement()
                .await;
            return Ok(response);
        };
        channel_info!(config_id, "🔌 Routing A2A request through A2A proxy backend proxy_id={}", proxy_id);
        let response = handle_a2a_proxy_target_request(&state, proxy_id, &body_bytes, &channel_name).await;
        let response = record_a2a_proxy_connection_metric(
            &state,
            proxy_id,
            response,
            &source_addr,
            start_time,
            &trace_id,
            body_bytes.len() as u64,
        )
        .await;
        connection_guard
            .decrement()
            .await;
        return Ok(response);
    }

    let mut modern_delegation = None;
    if let Some(request) = modern_request.as_ref()
        && !state
            .surface
            .outbound_credentials
            .is_empty()
    {
        use crate::proxy::credential_delegation::modern::{
            ModernDelegationError, ModernDelegationResult, prepare_direct,
        };
        let Some(runtime) = mcp_continuations.as_deref() else {
            connection_guard
                .decrement()
                .await;
            return Err(ModernDelegationError::from(crate::mcp::continuations::ContinuationError::Unavailable)
                .response(request));
        };
        match prepare_direct(
            &state,
            runtime,
            request,
            resource_authorization.as_ref(),
            authenticated_identity.as_ref(),
            request_agent_did.as_deref(),
            crate::mcp::continuations::protected::ContinuationRoute::AccessPoint,
            surface_payment::is_unpaid(&state, &headers, &body_bytes),
        )
        .await
        {
            Ok(ModernDelegationResult::InputRequired(response)) => {
                connection_guard
                    .decrement()
                    .await;
                return Ok(([("cache-control", "no-store")], Json(response)).into_response());
            }
            Ok(ModernDelegationResult::Prepared(prepared)) => {
                body_bytes = prepared
                    .rewrite_body(&body_bytes)
                    .map_err(|error| ModernDelegationError::from(error).response(request))?;
                modern_request = Some(prepared.request.clone());
                modern_delegation = Some(prepared);
            }
            Err(ModernDelegationError::Unpaid) => {
                connection_guard
                    .decrement()
                    .await;
                return match surface_payment::process(
                    &state,
                    &headers,
                    body_bytes,
                    mcp_context.as_ref(),
                    &uri.to_string(),
                    None,
                )
                .await
                {
                    Err(response) => Ok(response),
                    Ok(_) => Err(ModernDelegationError::Unpaid.response(request)),
                };
            }
            Err(error) => {
                connection_guard
                    .decrement()
                    .await;
                return Err(error.response(request));
            }
        }
    }
    if defer_surface_payment {
        match surface_payment::delegate(
            &state,
            &headers,
            body_bytes.clone(),
            &method,
            &uri,
            &trace_id,
            &channel_name,
            modern_request.as_ref(),
        )
        .await
        {
            surface_payment::DelegatedPayment::Proceed(receipts) => delegation_receipt_headers.extend(receipts),
            surface_payment::DelegatedPayment::Challenge(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Ok(response);
            }
            surface_payment::DelegatedPayment::Denied(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
        match surface_payment::process(
            &state,
            &headers,
            body_bytes.clone(),
            mcp_context.as_ref(),
            &uri.to_string(),
            modern_delegation
                .as_ref()
                .and_then(|prepared| prepared.payment()),
        )
        .await
        {
            Ok(mut payment) => {
                if let Some(prepared) = modern_delegation.as_mut() {
                    let now = crate::proxy::credential_delegation::modern::now_secs().map_err(|_| {
                        create_error_response(StatusCode::SERVICE_UNAVAILABLE, "Payment continuation unavailable")
                    })?;
                    prepared
                        .record_local_payment(
                            &payment,
                            mcp_continuations
                                .as_ref()
                                .map_or(300, |runtime| runtime.config.ttl_secs),
                            now,
                        )
                        .map_err(|_| {
                            create_error_response(StatusCode::SERVICE_UNAVAILABLE, "Payment continuation unavailable")
                        })?;
                }
                payment
                    .strip_consumed_mcp_argument()
                    .map_err(|_| {
                        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid paid MCP request")
                    })?;
                payment.strip_consumed_headers(
                    &mut headers,
                    &state
                        .config
                        .x402_headers
                        .payment_signature,
                );
                modern_local_receipt = payment
                    .receipt_header(&state.config.x402_headers)
                    .map_err(|_| {
                        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid payment receipt header")
                    })?;
                body_bytes = payment.body;
                payment_context = payment.context;
            }
            Err(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
    }

    // Determine source-auth credential header to strip from upstream requests.
    let source_cred_header = state
        .surface
        .source_auth()
        .and_then(|sa| sa.credential_header_name())
        .or(resource_authorization
            .as_ref()
            .map(|_| "authorization"));
    let header_metadata_mapping = state
        .surface
        .access_point
        .header_metadata_mapping_if_supported();
    let forward_source_auth_header = state
        .surface
        .source_auth()
        .is_some_and(
            |auth| matches!(auth, crate::source_auth::SourceAuthConfig::JwtBearer(config) if config.forward_header),
        )
        && resource_authorization.is_none();

    // Build upstream request. The forward send uses the per-request pinned,
    // redirect-disabled client built at the SSRF vetting sink above; only the
    // MCP `proxy://` skip (never DNS-resolved here) falls back to the pooled
    // client, and A2A-proxy targets returned earlier.
    let forward_client = forward_client
        .as_ref()
        .unwrap_or(&state.client);
    let mut upstream_req = forward_client
        .request(method.clone(), &target_url)
        .body(body_bytes.clone());

    // Copy headers (excluding hop-by-hop headers, content-length, host,
    // and the source-auth credential header which must not leak upstream)
    for (key, value) in headers.iter() {
        if should_forward_ap_request_header_with_mapping(
            key.as_str(),
            source_cred_header,
            header_metadata_mapping,
            forward_source_auth_header,
        ) {
            upstream_req = upstream_req.header(key.as_str(), value.as_bytes());
        }
    }

    // For MCP channels, advertise SSE support upstream ONLY if the client
    // itself asked for it. Forwarding `Accept: text/event-stream` to upstream
    // when the client sent `Accept: application/json` would cause the upstream
    // to return SSE-wrapped responses that the client cannot parse.
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && method == "POST"
        && modern_request.is_none()
        && crate::mcp::sse_server::client_wants_sse(&headers)
    {
        upstream_req = upstream_req.header(reqwest::header::ACCEPT, "text/event-stream, application/json");
    }

    // Inject trace ID as standard header for correlation
    upstream_req = upstream_req.header("X-Gateway-Trace-Id", egress_trace_id.clone());

    // Inject DID:webvh identity into HTTP headers (Header and SignedHeader modes)
    #[cfg(feature = "didwebvh")]
    if let Some(ref context) = did_context {
        use crate::config::DidInjectionMode;
        if *context.injection_mode() != DidInjectionMode::ProtocolNative {
            let mut did_headers = Vec::new();
            inject_did_headers(context, &mut did_headers);
            for (key, value) in did_headers {
                upstream_req = upstream_req.header(key, value);
            }
        }
    }

    // Inject unified caller-info headers so every managed agent knows who is calling
    // and how the gateway verified that claim.  Both the HTTP identity-extraction path
    // (gateway-computed DID) and the DID-aware path (self-presented / verified DID)
    // contribute a DID through `agent_context.did`; the source discriminator tells the
    // agent which trust level to apply.
    let caller_identity_source: Option<String>;
    {
        use crate::proxy::caller_identity::{CallerHeaders, CallerIdentity};

        let caller_did = agent_context
            .as_ref()
            .and_then(|ctx| ctx.did.as_deref())
            .unwrap_or("anonymous")
            .to_string();

        // Determine identity source from caller-presented metadata, not from the
        // channel's own DID:webvh identity. The channel DID context represents the
        // managed agent/gateway identity, while `extension_identity`/`agent_context`
        // reflect the caller.
        #[cfg(feature = "didwebvh")]
        let caller_presented_did = extension_identity
            .as_ref()
            .and_then(|ctx| ctx.did.as_ref())
            .is_some();
        #[cfg(feature = "didwebvh")]
        let caller_agent_dna = agent_context
            .as_ref()
            .and_then(|ctx| ctx.agent_dna.clone());
        #[cfg(feature = "didwebvh")]
        let caller = if caller_presented_did || caller_agent_dna.is_some() {
            CallerIdentity::from_self_presented(caller_did, None, caller_agent_dna)
        } else {
            CallerIdentity::from_gateway_computed(caller_did, std::collections::HashMap::new())
        };
        #[cfg(not(feature = "didwebvh"))]
        let caller = CallerIdentity::from_gateway_computed(caller_did, std::collections::HashMap::new());

        // Preserve identity_source for transit token enrichment (used after this block).
        caller_identity_source = Some(
            caller
                .identity_source
                .to_string(),
        );

        // Pass the gateway/managed agent DID when it is configured, so downstream
        // services can verify which DID:webvh identity the gateway used for routing.
        #[cfg(feature = "didwebvh")]
        let gateway_did = did_context
            .as_ref()
            .map(|context| context.did().to_string());
        #[cfg(not(feature = "didwebvh"))]
        let gateway_did: Option<String> = None;

        for (key, value) in CallerHeaders::build(&caller, gateway_did.as_deref()) {
            upstream_req = upstream_req.header(&key, &value);
        }
    }

    // ── Step 18: Transit token generation (§6.1) ───────────────────────────
    // When the channel has transit points (outbound virtual channels), generate
    // a transit token encoding the caller context and inject it so the managed
    // agent can echo it back on transit calls.
    if !state
        .surface
        .transit_points()
        .is_empty()
        && let Some(ref issuer) = state.transit_token_issuer
    {
        let surface_id = state
            .surface
            .surface_id
            .as_str();

        let caller_did_for_token = request_agent_did
            .as_deref()
            .or_else(|| {
                agent_context
                    .as_ref()
                    .and_then(|ctx| ctx.did.as_deref())
            });

        let caller_dna_uai = agent_context
            .as_ref()
            .and_then(|ctx| ctx.agent_dna.as_ref())
            .map(|dna| dna.uai.as_str());

        // Compute user identity hash from authenticated identity for credential
        // vault lookups on the transit side.
        let transit_user_hash = authenticated_identity
            .as_ref()
            .map(|id| {
                use sha2::{Digest, Sha256};
                let raw = match id {
                    crate::source_auth::AuthenticatedIdentity::JwtBearer { subject, .. } => subject.clone(),
                    crate::source_auth::AuthenticatedIdentity::ApiKey { key_name } => key_name.clone(),
                    crate::source_auth::AuthenticatedIdentity::DidAuth { did } => did.clone(),
                    crate::source_auth::AuthenticatedIdentity::Mtls { principal, .. } => principal.clone(),
                };
                format!("{:x}", Sha256::digest(raw.as_bytes()))
            });

        let allowed_points: Vec<String> = state
            .surface
            .transit_points()
            .iter()
            .map(|ovc| ovc.alias.clone())
            .collect();

        let caller_context_fields =
            compute_transit_token_caller_context(&state.surface, authenticated_identity.as_ref());

        match issuer.issue_with_caller_context(
            surface_id,
            caller_did_for_token,
            caller_identity_source.as_deref(),
            caller_dna_uai,
            transit_user_hash.as_deref(),
            Some(egress_trace_id.as_str()),
            allowed_points,
            caller_context_fields,
        ) {
            Ok(token) => {
                upstream_req = upstream_req.header("X-Transit-Token", &token);
                debug!(channel = channel_name, "Injected transit token into upstream request");
            }
            Err(e) => {
                warn!(channel = channel_name, error = %e, "Failed to generate transit token");
            }
        }
    }

    // Inject custom metadata for MCP protocol
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && let Some(custom_metadata) = state
            .surface
            .custom_metadata()
        && custom_metadata.enabled
        && method == Method::POST
        && !body_bytes.is_empty()
    {
        let injected = crate::mcp::metadata::inject_custom_metadata_with_context(
            &body_bytes,
            custom_metadata,
            &channel_name,
            &state.secrets_store,
            crate::protocols::MetadataRuntimeContext {
                request_id: Some(egress_trace_id.as_str()),
                surface_id: Some(config_id),
            },
            mcp_metadata_context,
            crate::mcp::meta::McpMetaTarget::Params,
        )
        .await
        .map_err(|error| {
            warn!(channel = channel_name, error = %error, "MCP metadata injection failed");
            create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "MCP metadata injection failed")
        })?;
        body_bytes = injected.body;
        upstream_req = upstream_req.body(body_bytes.clone());
        for (name, value) in injected.extra_headers {
            upstream_req = upstream_req.header(name, value);
        }
    }

    // Inject DID:webvh identity into MCP _meta (protocol-native mode for MCP)
    #[cfg(feature = "didwebvh")]
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && let Some(ref context) = did_context
    {
        use crate::config::DidInjectionMode;
        if *context.injection_mode() == DidInjectionMode::ProtocolNative && method == "POST" && !body_bytes.is_empty() {
            match crate::mcp::inject_didwebvh_identity_mcp(&body_bytes, context, &channel_name, mcp_metadata_context)
                .await
            {
                Ok(modified_bytes) => {
                    info!(channel = channel_name, did = %context.did(), "DID:webvh identity injected into MCP _meta");
                    body_bytes = modified_bytes;
                    upstream_req = forward_client
                        .request(method.clone(), &target_url)
                        .body(body_bytes.clone());
                    for (key, value) in headers.iter() {
                        if should_forward_ap_request_header_with_mapping(
                            key.as_str(),
                            source_cred_header,
                            header_metadata_mapping,
                            forward_source_auth_header,
                        ) {
                            upstream_req = upstream_req.header(key.as_str(), value.as_bytes());
                        }
                    }
                    upstream_req = upstream_req.header("X-Gateway-Trace-Id", egress_trace_id.clone());
                }
                Err(e) => {
                    warn!(channel = channel_name, error = %e, "Failed to inject DID:webvh identity into MCP _meta, using original body");
                }
            }
        }
    }

    // Inject target authentication credentials (if configured)
    if let Some(target_auth) = state.surface.target_auth() {
        let caller_assertion = if source_auth_failed {
            CallerAssertion::Unauthenticated
        } else {
            CallerAssertion::for_request(method.as_str(), uri.path())
        };
        match inject_target_auth_header(target_auth, &state.secrets_store, &channel_name, caller_assertion).await {
            Ok(Some((header_name, header_value))) => {
                upstream_req = upstream_req.header(&header_name, &header_value);
                debug!(channel = channel_name, header = %header_name, "Injected target authentication header");
            }
            Ok(None) => {
                // CredentialLookup method not implemented, skip
            }
            Err(e) => {
                error!(channel = channel_name, error = %e, "Failed to resolve target authentication");
                // Check fallback behavior
                match target_auth.fallback {
                    crate::config::TargetAuthFallback::Reject => {
                        return Ok(create_error_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Target authentication failed: {}", e),
                        ));
                    }
                    crate::config::TargetAuthFallback::Passthrough => {
                        warn!(
                            channel = channel_name,
                            "Target auth failed but passthrough enabled, continuing without credentials"
                        );
                    }
                }
            }
        }
    }

    // ── Credential delegation: inject delegated OAuth tokens or signal consent ──
    let mut delegation_actions_for_vp: Option<serde_json::Value> = None;
    let mut outbound_credentials = state
        .surface
        .outbound_credentials();
    if let Some(prepared) = modern_delegation.as_ref() {
        outbound_credentials.retain(|binding| {
            !prepared
                .handled_provider_ids
                .contains(&binding.credential_provider_id)
        });
    }
    if !outbound_credentials.is_empty() {
        // Credential delegation requires a verified identity — both source_auth
        // (to know *who* the caller is) and managed_identity / extension inspection
        // (to know *which agent* is acting). Anonymous callers must be rejected.
        // Enbindification
        // Derive the user hash from source authentication only.
        // This identifies the HUMAN user who is delegating — separate from the
        // agent identity (which comes from extension extraction via request_agent_did).
        let delegation_user_hash = authenticated_identity
            .as_ref()
            .map(|id| {
                use sha2::{Digest, Sha256};
                let raw = match id {
                    crate::source_auth::AuthenticatedIdentity::JwtBearer { subject, .. } => subject.clone(),
                    crate::source_auth::AuthenticatedIdentity::ApiKey { key_name } => key_name.clone(),
                    crate::source_auth::AuthenticatedIdentity::DidAuth { did } => did.clone(),
                    crate::source_auth::AuthenticatedIdentity::Mtls { principal, .. } => principal.clone(),
                };
                format!("{:x}", Sha256::digest(raw.as_bytes()))
            });

        // Reject anonymous callers: credential delegation requires a verified identity
        if delegation_user_hash.is_none() {
            warn!(
                target: "credential_delegation",
                surface = %channel_name,
                "Credential delegation requires source authentication — rejecting anonymous request"
            );
            let body = serde_json::json!({
                "type": "https://affinidi.com/atg/errors/identity-required",
                "title": "Identity Required for Credential Delegation",
                "status": 403,
                "detail": "This channel requires credential delegation which needs authenticated source identity. \
                           Configure source authentication and agent identity management on this channel.",
            });
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-type", "application/problem+json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap());
        }

        if let (Some(user_hash), Some(vault_store), Some(provider_store), Some(secrets_store), Some(base_url)) = (
            &delegation_user_hash,
            &state.delegation_vault_store,
            &state.credential_provider_store,
            &state.secrets_store,
            &state.gateway_base_url,
        ) {
            let mcp_tool = mcp_context
                .as_ref()
                .and_then(|ctx| ctx.tool_name.as_deref());

            // Use the agent DID from request-path identity extraction.
            // Fall back to channel_id as the workload identity when no
            // managed identity is configured.
            let agent_did_for_vault = request_agent_did
                .as_deref()
                .unwrap_or(config_id);

            // Only a verified JWT establishes who consented; every other source
            // auth mode leaves this None and so cannot unlock a consent record.
            let delegation_consent_principal = state
                .network_config
                .sts
                .mcp_issuer
                .as_ref()
                .zip(
                    authenticated_identity
                        .as_ref()
                        .and_then(crate::source_auth::AuthenticatedIdentity::jwt_claims),
                )
                .and_then(|(profile, claims)| {
                    crate::delegation_vault::modern_consent::identity::principal_for_claims(profile, claims)
                });

            let delegation_audit_ctx = crate::proxy::credential_delegation::DelegationAuditContext {
                caller: authenticated_identity
                    .as_ref()
                    .map(crate::delegation_vault::audit::build_caller_context),
                channel_name: Some(channel_name.clone()),
                target_endpoint: Some(
                    state
                        .surface
                        .target
                        .endpoint
                        .clone(),
                ),
                protocol: Some(format!("{:?}", state.surface.channel_protocol()).to_lowercase()),
                mcp_tool_name: mcp_tool.map(String::from),
                agent_identity_did: request_agent_did.clone(),
                // The canonical VP is minted at the deferred site below and
                // stamped onto every per-binding event when the audit defer
                // queue is drained. Set None here so the resolver doesn't copy
                // a stale pre-delegation VP.
                vp_jwt: None,
                mcp_session_id: validated_mcp_session_id.clone(),
            };

            let delegation_results = crate::delegation_vault::audit::AUDIT_DEFER_QUEUE
                .scope(
                    deferred_audit_queue.clone(),
                    crate::proxy::credential_delegation::resolve_delegation_credentials(
                        &outbound_credentials,
                        user_hash,
                        agent_did_for_vault,
                        config_id,
                        mcp_tool,
                        vault_store,
                        provider_store,
                        secrets_store,
                        base_url,
                        false, // via_fabric = false (direct HTTP path)
                        Some(&delegation_audit_ctx),
                        delegation_consent_principal.as_deref(),
                    ),
                )
                .await;

            // Compute the delegation-action summary for the workload-binding VP.
            delegation_actions_for_vp =
                crate::proxy::credential_delegation::delegation_actions_value(&delegation_results);

            if delegation_results
                .iter()
                .any(|resolution| {
                    matches!(
                        &resolution.result,
                        crate::proxy::credential_delegation::DelegationLookupResult::Unavailable
                    )
                })
            {
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("content-type", "text/plain")
                    .header("cache-control", "no-store")
                    .body(Body::from("Delegated credentials unavailable"))
                    .unwrap());
            }

            // Check for consent_required — if any binding needs consent, return immediately
            let mut consent_entries = Vec::new();
            for resolution in &delegation_results {
                if let crate::proxy::credential_delegation::DelegationLookupResult::ConsentRequired {
                    authorization_url,
                    provider_name,
                    scopes,
                } = &resolution.result
                {
                    consent_entries.push(serde_json::json!({
                        "provider_name": provider_name,
                        "authorization_url": authorization_url,
                        "scopes": scopes,
                    }));
                }
            }

            if !consent_entries.is_empty() {
                info!(
                    target: "credential_delegation",
                    surface = %channel_name,
                    providers = %consent_entries.len(),
                    user_hash = %user_hash,
                    agent_did = %agent_did_for_vault,
                    "Credential delegation requires user consent — returning 401"
                );

                // Mint a signed identity VP for the dedicated audit event. When
                // workload-binding attestation is explicitly configured, it
                // captures the consent_required outcome inside
                // `workloadBinding.delegationAction`; otherwise it uses the
                // legacy `identityFields` shape. The VP itself is NEVER returned
                // to the caller — it lives only in the audit trail.
                if let (Some(selector), Some(result)) = (
                    state
                        .identity_selector
                        .as_ref(),
                    identity_result.as_ref(),
                ) {
                    let wb: Option<serde_json::Value> = None;
                    let vc_issuer = selector.get_vc_issuer();
                    match vc_issuer
                        .create_agent_identity_presentation_with_binding(
                            &result.did,
                            &result.identity_fields,
                            wb,
                            None,
                            None,
                        )
                        .await
                    {
                        Ok(jwt) => {
                            // Drain the deferred queue and stamp every
                            // per-binding event with the consent_required VP.
                            {
                                let pending = match deferred_audit_queue.lock() {
                                    Ok(mut g) => std::mem::take(&mut *g),
                                    Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
                                };
                                for mut evt in pending {
                                    evt.vp_jwt = Some(jwt.clone());
                                    crate::delegation_vault::audit::audit(evt);
                                }
                            }

                            let mut evt = crate::delegation_vault::audit::audit_event(
                                crate::delegation_vault::audit::DelegationAuditAction::ConsentRequired,
                                Some(agent_did_for_vault),
                                Some(user_hash),
                                None,
                                Some(config_id),
                            );
                            evt.channel_name = Some(channel_name.to_string());
                            evt.agent_identity_did = request_agent_did.clone();
                            evt.protocol = Some(format!("{:?}", state.surface.channel_protocol()).to_lowercase());
                            evt.mcp_tool_name = mcp_context
                                .as_ref()
                                .and_then(|c| c.tool_name.clone());
                            evt.caller = authenticated_identity
                                .as_ref()
                                .map(crate::delegation_vault::audit::build_caller_context);
                            evt.vp_jwt = Some(jwt);

                            // Surface provider info for single-provider cases
                            // so the dashboard renders something useful in
                            // the provider column instead of a dash. For
                            // multi-provider rejections we leave provider_id
                            // unset and rely on the VP's `delegationAction`
                            // array (rendered in the row detail panel) to
                            // show the per-binding outcomes.
                            let consent_providers: Vec<&crate::proxy::credential_delegation::DelegationResolution> =
                                delegation_results
                                    .iter()
                                    .filter(|r| {
                                        matches!(
                                            r.action.outcome,
                                            crate::proxy::credential_delegation::DelegationActionOutcome::ConsentRequired
                                        )
                                    })
                                    .collect();
                            if let [only] = consent_providers.as_slice() {
                                evt.provider_id = Some(
                                    only.action
                                        .provider_id
                                        .clone(),
                                );
                                evt.provider_name = only
                                    .action
                                    .provider_name
                                    .clone();
                            }
                            evt.detail = Some(format!("consent_required summary; providers={}", consent_entries.len()));
                            crate::delegation_vault::audit::audit(evt);
                        }
                        Err(e) => {
                            warn!(
                                target: "credential_delegation",
                                surface = %channel_name,
                                error = %e,
                                "Failed to mint consent_required identity VP for audit log"
                            );
                        }
                    }
                } else {
                    debug!(
                        target: "credential_delegation",
                        surface = %channel_name,
                        has_identity_selector = %state.identity_selector.is_some(),
                        has_identity_result = %identity_result.is_some(),
                        "Skipping consent_required VP audit — missing identity selector or resolved agent identity"
                    );
                }

                // Flush any per-binding events that were still queued because
                // the consent_required VP could not be minted (or no identity
                // selector). They have no VP attached but at least preserve
                // the audit trail.
                {
                    let pending = match deferred_audit_queue.lock() {
                        Ok(mut g) => std::mem::take(&mut *g),
                        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
                    };
                    for evt in pending {
                        crate::delegation_vault::audit::audit(evt);
                    }
                }

                let body = serde_json::json!({
                    "type": "https://affinidi.com/atg/errors/consent-required",
                    "title": "Credential Delegation Consent Required",
                    "status": 401,
                    "detail": "This channel requires delegated credentials. The user must authorize access via the provided URLs.",
                    "consent_required": consent_entries,
                    "_debug_user_hash": user_hash,
                    "_debug_agent_did": agent_did_for_vault,
                });
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/problem+json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap());
            }

            for resolution in &delegation_results {
                if let crate::proxy::credential_delegation::DelegationLookupResult::Inject(injections) =
                    &resolution.result
                {
                    for injection in injections {
                        match injection {
                            crate::proxy::credential_delegation::ResolvedCredentialInjection::McpMeta {
                                field,
                                value,
                            } => {
                                match crate::proxy::credential_delegation::inject_delegated_credential_into_mcp_meta(
                                    &body_bytes,
                                    field,
                                    value,
                                ) {
                                    Ok(modified) => {
                                        body_bytes = modified.into();
                                        upstream_req = upstream_req.body(body_bytes.clone());
                                        debug!(
                                            target: "credential_delegation",
                                            surface = %channel_name,
                                            meta_field = %field,
                                            "Injected delegated credential into MCP metadata"
                                        );
                                    }
                                    Err(error) => {
                                        warn!(
                                            target: "credential_delegation",
                                            surface = %channel_name,
                                            meta_field = %field,
                                            error = %error,
                                            "Failed to inject delegated credential into MCP metadata"
                                        );
                                        return Err(create_error_response(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            "Failed to inject delegated credential into MCP metadata",
                                        ));
                                    }
                                }
                            }
                            crate::proxy::credential_delegation::ResolvedCredentialInjection::Header {
                                name,
                                value,
                            } => {
                                upstream_req = upstream_req.header(name, value);
                                debug!(
                                    target: "credential_delegation",
                                    surface = %channel_name,
                                    header = %name,
                                    "Injected delegated credential header"
                                );
                            }
                        }
                    }
                }
            }
        } else {
            warn!(
                target: "credential_delegation",
                surface = %channel_name,
                has_user_hash = %delegation_user_hash.is_some(),
                "Credential delegation configured but stores not available — skipping"
            );
        }
    }

    if let Some(prepared) = modern_delegation.as_ref() {
        let mut injection_headers = HeaderMap::new();
        for injection in &prepared.injections {
            match injection {
                crate::proxy::credential_delegation::ResolvedCredentialInjection::Header { name, value } => {
                    let name = axum::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid delegated credential header")
                    })?;
                    let value = axum::http::HeaderValue::from_str(value).map_err(|_| {
                        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid delegated credential value")
                    })?;
                    injection_headers.insert(name, value);
                }
                crate::proxy::credential_delegation::ResolvedCredentialInjection::McpMeta { field, value } => {
                    body_bytes = crate::proxy::credential_delegation::inject_delegated_credential_into_mcp_meta(
                        &body_bytes,
                        field,
                        value,
                    )
                    .map(bytes::Bytes::from)
                    .map_err(|_| {
                        create_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Invalid delegated credential metadata",
                        )
                    })?;
                }
            }
        }
        upstream_req = upstream_req
            .headers(injection_headers)
            .body(body_bytes.clone());
        delegation_actions_for_vp = Some(serde_json::Value::Array(
            prepared
                .handled_provider_ids
                .iter()
                .map(|id| serde_json::json!({"providerId": id, "outcome": "token_injected"}))
                .collect(),
        ));
    }

    // ── deferred request VP injection ───────────────────────────────────────
    //
    // Mint the request-path identity binding VP *after* credential delegation
    // has resolved. When workload-binding attestation is enabled, the workload
    // binding's `delegationAction` array reflects what actually happened
    // (TokenInjected / TokenRefreshed / NotApplicable / ConsentRequired /
    // elicitation_*). The resulting VP is:
    //   1. injected into the outbound body (replacing any earlier VP slot), and
    //   2. recorded in the delegation audit log as a single `VpInjected` event
    //      that operators can verify cryptographically.
    //
    // Skipped silently when there's no identity selector or no resolved agent
    // identity — those are configuration gaps surfaced elsewhere.
    if state
        .surface
        .inject_identity_vp()
        && identity_result.is_none()
    {
        info!(
            channel = channel_name,
            "inject_vp is enabled but no identity binding VP was produced on the protected path — no inbound agent identity was resolved (configure managed_identity / protected_identity, or have the caller send an identity VP); toggle has no effect for this request"
        );
    }
    let vc_issuer_for_vp = state
        .identity_selector
        .as_ref()
        .map(|s| s.get_vc_issuer())
        .or_else(|| state.vc_issuer.clone());
    if let (Some(vc_issuer), Some(result)) = (vc_issuer_for_vp, identity_result.as_ref()) {
        let wb = build_target_request_workload_binding(
            &state.surface,
            &headers,
            &result.identity_fields,
            &trace_id,
            delegation_actions_for_vp.clone(),
            authenticated_identity.as_ref(),
        );
        match vc_issuer
            .create_agent_identity_presentation_with_binding(&result.did, &result.identity_fields, wb, None, None)
            .await
        {
            Ok(final_vp_jwt) => {
                // 1. inject into outbound body (replaces the slot if any existed)
                if (state
                    .surface
                    .inject_identity_vp()
                    || state
                        .surface
                        .target_workload_binding()
                        .is_some())
                    && method == "POST"
                    && !body_bytes.is_empty()
                {
                    let inbound_meta_field_to_strip: Option<String> = state
                        .surface
                        .inbound_identity()
                        .and_then(|c| {
                            if let crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) = c {
                                cfg.strip_raw_meta
                                    .then(|| cfg.meta_field.clone())
                            } else {
                                None
                            }
                        });
                    match inject_identity_binding_vp_into_request(
                        &body_bytes,
                        &final_vp_jwt,
                        &state
                            .surface
                            .channel_protocol(),
                        &channel_name,
                        inbound_meta_field_to_strip.as_deref(),
                        mcp_metadata_context,
                    ) {
                        Ok(modified) => {
                            info!(channel = channel_name, "Identity binding VP injected into outbound request");
                            body_bytes = modified;
                            upstream_req = upstream_req.body(body_bytes.clone());
                        }
                        Err(e) => {
                            warn!(
                                channel = channel_name,
                                error = %e,
                                "Failed to inject identity binding VP into request"
                            );
                            if state
                                .surface
                                .channel_protocol()
                                == crate::config::ChannelProtocol::Mcp
                            {
                                return Err(create_error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "MCP identity binding injection failed",
                                ));
                            }
                        }
                    }
                }

                // 2. drain the deferred audit queue and re-stamp every
                //    per-binding event with the canonical VP so each row in
                //    the audit log carries the same signed identity binding as
                //    the request-level event.
                {
                    let pending = match deferred_audit_queue.lock() {
                        Ok(mut g) => std::mem::take(&mut *g),
                        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
                    };
                    for mut evt in pending {
                        evt.vp_jwt = Some(final_vp_jwt.clone());
                        crate::delegation_vault::audit::audit(evt);
                    }
                }

                // 3. audit the request-path VP injection itself
                if crate::delegation_vault::audit::identity_binding_vp_audit_enabled() {
                    let mut evt = crate::delegation_vault::audit::audit_event(
                        crate::delegation_vault::audit::DelegationAuditAction::VpInjected,
                        request_agent_did.as_deref(),
                        request_user_hash.as_deref(),
                        None,
                        Some(
                            state
                                .surface
                                .surface_id
                                .as_str(),
                        ),
                    );
                    evt.agent_identity_did = request_agent_did.clone();
                    evt.channel_name = Some(channel_name.clone());
                    evt.target_endpoint = Some(
                        state
                            .surface
                            .target
                            .endpoint
                            .clone(),
                    );
                    evt.protocol = Some(format!("{:?}", state.surface.channel_protocol()).to_lowercase());
                    evt.mcp_tool_name = mcp_context
                        .as_ref()
                        .and_then(|c| c.tool_name.clone());
                    evt.vp_jwt = Some(final_vp_jwt.clone());
                    evt.vp_fingerprint = Some(crate::delegation_vault::audit::vp_fingerprint(&final_vp_jwt));
                    evt.trace_id = Some(trace_id.clone());
                    evt.detail = Some(if egress_trace_id != trace_id {
                        format!("request_path; downstream_trace_id={egress_trace_id}")
                    } else {
                        "request_path".to_string()
                    });
                    evt.caller = authenticated_identity
                        .as_ref()
                        .map(crate::delegation_vault::audit::build_caller_context);
                    crate::delegation_vault::audit::audit(evt);
                }
            }
            Err(e) => {
                warn!(
                    channel = channel_name,
                    error = %e,
                    "Failed to mint deferred request-path identity VP"
                );
                // Flush any queued per-binding events without a VP so we
                // don't lose audit trail on VP minting failure.
                let pending = match deferred_audit_queue.lock() {
                    Ok(mut g) => std::mem::take(&mut *g),
                    Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
                };
                for evt in pending {
                    crate::delegation_vault::audit::audit(evt);
                }
            }
        }
    } else {
        // No identity selector / resolved identity — flush any queued events
        // unchanged so we don't silently drop audit rows.
        let pending = match deferred_audit_queue.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for evt in pending {
            crate::delegation_vault::audit::audit(evt);
        }
    }

    debug!("🟢 OUTBOUND REQUEST: trace_id={} target={}", trace_id, target_url);

    // Traffic mirroring - send duplicate request to mirror endpoint (if configured)
    if let Some(mirror_config) = state.surface.mirror() {
        // Check if we should mirror this request based on percentage
        let should_mirror = if mirror_config.percentage >= 100 {
            true
        } else if mirror_config.percentage == 0 {
            false
        } else {
            use rand::Rng;
            let mut rng = rand::rng();
            rng.random_range(0..100) < mirror_config.percentage
        };

        if should_mirror {
            let mirror_endpoint = mirror_config.endpoint.clone();
            let mirror_endpoint_for_log = mirror_endpoint.clone(); // Clone for later use
            let mirror_timeout = std::time::Duration::from_secs(mirror_config.timeout_secs);
            let wait_for_response = mirror_config.wait_for_response;
            let channel_name_clone = channel_name.to_string();
            let client_clone = state.client.clone();
            let trace_id_clone = trace_id.clone();

            // Clone the request for mirroring
            if let Some(_mirror_req) = upstream_req.try_clone() {
                // Build mirror URL (replace target with mirror endpoint)
                let mirror_url = mirror_endpoint.clone();
                let mirror_req = client_clone
                    .request(method.clone(), &mirror_url)
                    .body(body_bytes.clone())
                    .timeout(mirror_timeout);

                // Copy headers
                let mut mirror_req_with_headers = mirror_req;
                for (key, value) in headers.iter() {
                    if should_forward_ap_request_header_with_mapping(
                        key.as_str(),
                        source_cred_header,
                        header_metadata_mapping,
                        false,
                    ) {
                        mirror_req_with_headers = mirror_req_with_headers.header(key.as_str(), value.as_bytes());
                    }
                }
                mirror_req_with_headers =
                    mirror_req_with_headers.header("X-Gateway-Trace-Id", format!("{}-mirror", trace_id_clone));
                mirror_req_with_headers = mirror_req_with_headers.header("X-Mirrored-Request", "true");

                if wait_for_response {
                    // Wait for mirror response (blocking)
                    match mirror_req_with_headers
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            info!(
                                channel = channel_name_clone,
                                mirror_endpoint = mirror_endpoint,
                                status = resp.status().as_u16(),
                                trace_id = trace_id_clone,
                                "Mirror request completed"
                            );
                        }
                        Err(e) => {
                            warn!(
                                channel = channel_name_clone,
                                mirror_endpoint = mirror_endpoint,
                                error = %e,
                                trace_id = trace_id_clone,
                                "Mirror request failed"
                            );
                        }
                    }
                } else {
                    // Fire-and-forget mirror request
                    let config_id_clone = config_id.to_string();
                    tokio::spawn(async move {
                        match mirror_req_with_headers
                            .send()
                            .await
                        {
                            Ok(resp) => {
                                channel_info!(
                                    config_id_clone,
                                    "Mirror request completed (async): endpoint={}, status={}",
                                    mirror_endpoint,
                                    resp.status().as_u16()
                                );
                            }
                            Err(e) => {
                                channel_warn!(
                                    config_id_clone,
                                    "Mirror request failed (async): endpoint={}, error={}",
                                    mirror_endpoint,
                                    e
                                );
                            }
                        }
                    });
                    debug!(
                        channel = channel_name,
                        mirror_endpoint = mirror_endpoint_for_log,
                        "Mirror request sent (fire-and-forget)"
                    );
                }
            } else {
                warn!(channel = channel_name, "Failed to clone request for mirroring");
            }
        }
    }

    // Apply timeout configuration if available
    if let Some(timeout_config) = state.surface.timeout() {
        upstream_req = upstream_req.timeout(std::time::Duration::from_secs(timeout_config.request_secs));
        debug!(channel = channel_name, timeout_secs = timeout_config.request_secs, "Applied request timeout");
    }

    // For MCP channels, SSE connections are long-lived streams that must not
    // be killed by the configured request timeout. Override only when the
    // request is likely to produce an SSE response:
    //  - GET requests (legacy SSE GET /sse — always long-lived)
    //  - POST requests with `Accept: text/event-stream` (Streamable HTTP)
    // Plain JSON-RPC POSTs (e.g. tools/list) keep the configured
    // `target.networking.timeout.request_secs` so per-variant timeout
    // overrides take effect.
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
    {
        let caller_wants_sse = method == "POST" && crate::mcp::sse_server::client_wants_sse(&headers);
        if modern_request.is_some() {
            let config = state
                .surface
                .mcp_http
                .clone()
                .unwrap_or_default();
            let header_timeout = state
                .surface
                .timeout()
                .map_or(30, |timeout| timeout.request_secs);
            upstream_req = upstream_req.timeout(std::time::Duration::from_secs(
                config
                    .stream_max_lifetime_secs
                    .get()
                    .saturating_add(header_timeout),
            ));
        } else if method == "GET" || caller_wants_sse {
            // 24 hours — effectively no timeout; the connection will be closed
            // when either side drops or the channel is torn down.
            upstream_req = upstream_req.timeout(std::time::Duration::from_secs(86400));
            debug!(channel = channel_name, "MCP channel: SSE-shaped request, overriding timeout to 24h");
        }
    }

    // Get circuit breaker if configured
    let circuit_breaker = if state
        .surface
        .circuit_breaker()
        .is_some()
    {
        if let Some(ref pm) = state.policy_manager {
            // Use config_id for circuit breaker lookup, not channel name
            let channel_id = &state.surface.surface_id;
            pm.get_circuit_breaker(channel_id.as_str())
                .await
        } else {
            None
        }
    } else {
        None
    };

    // Send request and measure request latency (time to get response from upstream)
    let request_latency_start = std::time::Instant::now();

    let _send_span = tracing::info_span!(
        "http.client.send",
        otel.name = "Send Request & Await Response",
        http.method = %method,
        http.url = %target_url,
        surface = %channel_name
    );

    let owned_modern_response = if let Some(request) = modern_request.as_ref()
        && let Some(proxy_id) = state
            .surface
            .target
            .endpoint
            .strip_prefix("proxy://")
    {
        use crate::mcp_proxies::McpProxyStore;
        let store = state
            .mcp_proxy_store
            .as_ref()
            .ok_or_else(|| {
                create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "MCP proxy storage is unavailable")
            })?;
        let proxy = store
            .get(proxy_id)
            .await
            .map_err(|_| create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load MCP proxy"))?
            .ok_or_else(|| create_error_response(StatusCode::NOT_FOUND, "MCP proxy was not found"))?;
        let prepared = upstream_req
            .try_clone()
            .ok_or_else(|| {
                create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to prepare MCP proxy request")
            })?
            .build()
            .map_err(|_| {
                create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to prepare MCP proxy request")
            })?;
        let execute = crate::mcp_proxies::handlers::handle_modern_surface_http_request(
            &proxy,
            &state.surface,
            request,
            prepared,
            &state.client,
            mcp_versions,
        );
        let execute = async {
            let deadline = std::time::Duration::from_secs(
                state
                    .surface
                    .timeout()
                    .map_or(30, |timeout| timeout.request_secs),
            );
            tokio::time::timeout(deadline, execute)
                .await
                .map_err(|_| create_error_response(StatusCode::GATEWAY_TIMEOUT, "MCP proxy execution timed out"))?
                .map_err(|error| (*error).into_response())
        };
        let response = if let Some(breaker) = circuit_breaker.clone() {
            breaker
                .call(execute)
                .await
                .map_err(|error| match error {
                    crate::policies::CircuitBreakerError::Open { .. } => {
                        create_error_response(StatusCode::SERVICE_UNAVAILABLE, "MCP proxy circuit breaker is open")
                    }
                    crate::policies::CircuitBreakerError::Inner(response) => response,
                })?
        } else {
            execute.await?
        };
        let (parts, body) = response.into_parts();
        let response = axum::http::Response::from_parts(parts, reqwest::Body::wrap_stream(body.into_data_stream()));
        Some(reqwest::Response::from(response))
    } else {
        None
    };

    // Implement retry logic if configured
    let send_with_retry = || async {
        if let Some(retry_config) = state
            .surface
            .retry()
            .filter(|_| modern_request.is_none())
        {
            let mut attempt = 0;
            let mut _last_error = None;

            loop {
                attempt += 1;
                debug!(
                    channel = channel_name,
                    attempt = attempt,
                    max_attempts = retry_config.max_attempts + 1,
                    "Sending request"
                );

                // Clone the request for retry
                let req_to_send = if let Some(cloned) = upstream_req.try_clone() {
                    cloned
                } else {
                    warn!(channel = channel_name, "Failed to clone request for retry, sending original request");
                    // If we can't clone, send the original and break the retry loop
                    let result = upstream_req.send().await;
                    break result;
                };

                match req_to_send.send().await {
                    Ok(resp) => {
                        let status = resp.status();

                        // Check if we should retry based on status code
                        if attempt <= retry_config.max_attempts
                            && retry_config
                                .retryable_status_codes
                                .contains(&status.as_u16())
                        {
                            warn!(
                                channel = channel_name,
                                attempt = attempt,
                                status = status.as_u16(),
                                "Request failed with retryable status"
                            );

                            // Calculate backoff delay
                            let backoff_ms = std::cmp::min(
                                (retry_config.initial_backoff_ms as f64
                                    * retry_config
                                        .backoff_multiplier
                                        .powi((attempt - 1) as i32)) as u64,
                                retry_config.max_backoff_ms,
                            );

                            info!(channel = channel_name, backoff_ms = backoff_ms, "Retrying after backoff");
                            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                            _last_error = Some(format!("HTTP {}", status.as_u16()));
                            continue;
                        }

                        // Success or non-retryable status
                        break Ok(resp);
                    }
                    Err(e) => {
                        if attempt <= retry_config.max_attempts {
                            warn!(channel = channel_name, attempt = attempt, error = %e, "Request failed, will retry");

                            // Calculate backoff delay
                            let backoff_ms = std::cmp::min(
                                (retry_config.initial_backoff_ms as f64
                                    * retry_config
                                        .backoff_multiplier
                                        .powi((attempt - 1) as i32)) as u64,
                                retry_config.max_backoff_ms,
                            );

                            info!(channel = channel_name, backoff_ms = backoff_ms, "Retrying after backoff");
                            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                            _last_error = Some(e.to_string());
                            continue;
                        } else {
                            break Err(e);
                        }
                    }
                }
            }
        } else {
            // No retry configured, send once
            upstream_req.send().await
        }
    };

    // Wrap in circuit breaker if configured
    let send_response = async {
        let upstream_response = if let Some(cb) = circuit_breaker {
            match cb
                .call(send_with_retry().instrument(_send_span.clone()))
                .await
            {
                Ok(response) => {
                    // Successfully got response through circuit breaker
                    response
                }
                Err(crate::policies::CircuitBreakerError::Open { retry_after }) => {
                    error!(
                        channel = channel_name,
                        retry_after = ?retry_after,
                        "Circuit breaker is open"
                    );
                    return Err(create_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("Service temporarily unavailable. Retry after {:?}", retry_after),
                    ));
                }
                Err(crate::policies::CircuitBreakerError::Inner(e)) => {
                    return Err(handle_upstream_error(
                        e,
                        &state,
                        &source_addr,
                        &identity_hash,
                        &channel_name,
                        &ucp_operation,
                    ));
                }
            }
        } else {
            send_with_retry()
                .instrument(_send_span.clone())
                .await
                .map_err(|e| {
                    handle_upstream_error(e, &state, &source_addr, &identity_hash, &channel_name, &ucp_operation)
                })?
        };
        Ok::<_, Response>(upstream_response)
    };
    let upstream_response = if let Some(response) = owned_modern_response {
        drop(send_response);
        response
    } else if modern_request.is_some() {
        let header_timeout = std::time::Duration::from_secs(
            state
                .surface
                .timeout()
                .map_or(30, |timeout| timeout.request_secs),
        );
        tokio::time::timeout(header_timeout, send_response)
            .await
            .map_err(|_| {
                create_error_response(StatusCode::GATEWAY_TIMEOUT, "Modern MCP upstream response headers timed out")
            })??
    } else {
        send_response.await?
    };

    // Process response
    let _process_span = tracing::info_span!(
        "http.client.process_response",
        otel.name = "Process Response",
        surface = %channel_name,
        http.status_code = upstream_response.status().as_u16()
    );
    // Process span - just mark context, actual work happens inline
    drop(_process_span.enter());

    // ── SSE fallback for MCP channels (Legacy SSE upstreams) ───────────────
    // Legacy SSE servers reject direct POST to '/' with 400/404/405.
    // When that happens, retry the JSON-RPC body through a persistent SSE
    // session (GET /sse → session → POST /mcp/messages).
    // Only trigger for the channel root path — NOT for /sse or /messages
    // paths which are part of Legacy SSE transport itself.
    let request_path = uri.path();
    let is_sse_transport_path =
        request_path.ends_with("/sse") || request_path.contains("/messages") || request_path.contains("/mcp/messages");
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && method == "POST"
        && modern_request.is_none()
        && !is_sse_transport_path
        && !state
            .surface
            .target
            .endpoint
            .starts_with("fabric://")
        && !state
            .surface
            .target
            .endpoint
            .starts_with("proxy://")
        && matches!(
            upstream_response
                .status()
                .as_u16(),
            400 | 404 | 405
        )
    {
        let sse_status = upstream_response.status();
        info!(
            surface = %channel_name,
            status = %sse_status,
            body = %String::from_utf8_lossy(&body_bytes),
            "Upstream rejected direct POST ({}), falling back to Legacy SSE transport",
            sse_status
        );

        match crate::mcp::sse_transport::send_via_persistent_sse(
            &state.client,
            &state.surface.target.endpoint,
            &body_bytes,
            &channel_name,
            state.config.a2a.max_body_size,
        )
        .await
        {
            Ok(json_response) => {
                info!(channel = %channel_name, response = %json_response, "SSE fallback succeeded, returning JSON response");
                connection_guard
                    .decrement()
                    .await;
                return Ok(axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(json_response))
                    .unwrap());
            }
            Err(e) => {
                warn!(
                    surface = %channel_name,
                    error = %e,
                    "SSE fallback also failed, returning original {} response",
                    sse_status
                );
                // Fall through to return the original upstream response
            }
        }
    }

    // ── SSE handling for MCP channels ──────────────────────────────────────
    // If the upstream responded with text/event-stream, stream the SSE events
    // directly back to the client — EXCEPT for `tools/list`, which we buffer
    // into its JSON-RPC payload so the tool filter + MCP tool gating below can
    // run on it (it is re-wrapped as SSE for Streamable-HTTP clients further
    // down). Without this a Streamable-HTTP/SSE MCP server bypasses gating.
    let modern_limits = crate::mcp::modern_sse::SseLimits::from(
        &state
            .surface
            .mcp_http
            .clone()
            .unwrap_or_default(),
    );
    let (modern_upstream, legacy_upstream) = if modern_request.is_some() {
        (Some(upstream_response), None)
    } else {
        (None, Some(upstream_response))
    };
    // Every buffered body, whatever the protocol, is bounded by size and idle
    // time. A non-SSE MCP body, or a `tools/list` answered as SSE, is buffered
    // even under the SSE-shaped 24h request timeout above, so it gets the
    // request timeout it would otherwise have had.
    let body_limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(
        state.config.a2a.max_body_size,
        state.surface.timeout(),
        state
            .config
            .a2a
            .timeout_seconds,
    );
    let (status, response_headers, response_body) = 'acquire_body: {
        let Some(upstream_response) = legacy_upstream else {
            break 'acquire_body (StatusCode::OK, HeaderMap::new(), bytes::Bytes::new());
        };
        if state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::Mcp
        {
            let upstream_ct = upstream_response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if crate::mcp::sse_transport::is_sse_content_type(upstream_ct) {
                if crate::mcp::is_tools_list_request(&body_bytes) {
                    info!(
                        channel = channel_name,
                        "Upstream MCP tools/list arrived as SSE — buffering to apply tool gating/policies"
                    );
                    let sse_status = upstream_response.status();
                    let mut sse_headers = upstream_response
                        .headers()
                        .clone();
                    // Re-label as JSON so the tool filter + Streamable-HTTP SSE
                    // re-wrap below treat the buffered body as a normal JSON-RPC
                    // response.
                    sse_headers.remove(reqwest::header::CONTENT_TYPE);
                    sse_headers.insert(
                        reqwest::header::CONTENT_TYPE,
                        reqwest::header::HeaderValue::from_static("application/json"),
                    );
                    match crate::mcp::sse_transport::consume_sse_response(upstream_response, &body_bytes, body_limits)
                        .await
                    {
                        Ok(json) => break 'acquire_body (sse_status, sse_headers, bytes::Bytes::from(json)),
                        Err(e) => {
                            warn!(channel = channel_name, error = %e, "Failed to buffer SSE tools/list response");
                            connection_guard
                                .decrement()
                                .await;
                            let (status, message) = match &e {
                                crate::mcp::sse_transport::SseConsumeError::Body(body_error) => {
                                    body_error.status_and_message()
                                }
                                crate::mcp::sse_transport::SseConsumeError::NoResponse => {
                                    (StatusCode::BAD_GATEWAY, "Failed to read MCP tools/list response")
                                }
                            };
                            return Err(create_error_response(status, message));
                        }
                    }
                } else {
                    info!(channel = channel_name, "Upstream MCP agent responded with SSE — streaming to client");

                    let resp_headers = upstream_response
                        .headers()
                        .clone();

                    // Record metrics for the SSE connection start
                    if let Some(ref metrics) = state.metrics_store {
                        let latency_ms = request_latency_start
                            .elapsed()
                            .as_millis() as u64;
                        let metrics = Arc::clone(metrics);
                        let channel_config_id = state
                            .surface
                            .surface_id
                            .clone();
                        let source = source_addr.clone();
                        let dest = state
                            .surface
                            .target
                            .endpoint
                            .clone();
                        let trace = trace_id.clone();
                        tokio::spawn(async move {
                            metrics
                                .record_connection(
                                    channel_config_id,
                                    source,
                                    dest,
                                    crate::metrics::ConnectionStatus::Success,
                                    Some(latency_ms),
                                    None,
                                    crate::metrics::ConnectionDirection::Request,
                                    trace,
                                    None,
                                    None,
                                    latency_ms,
                                    None,
                                )
                                .await;
                        });
                    }

                    connection_guard
                        .decrement()
                        .await;

                    let sse_response = crate::mcp::sse_transport::create_sse_passthrough_response(
                        upstream_response,
                        resp_headers,
                        channel_name.to_string(),
                        state.config.a2a.max_body_size,
                    );

                    return Ok(sse_response);
                }
            }
        }

        let status = upstream_response.status();
        let response_headers = upstream_response
            .headers()
            .clone();
        let response_body = crate::proxy::upstream_body::read_bounded(upstream_response, body_limits)
            .await
            .map_err(|e| {
                error!(channel = channel_name, error = %e, "Failed to read upstream response");

                // Track error (connection guard will handle decrement)
                if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
                    let task_id = task_id.clone();
                    let monitor = task_monitor.clone();
                    tokio::spawn(async move {
                        monitor
                            .increment_errors(&task_id)
                            .await;
                    });
                }

                let (status, message) = e.status_and_message();
                create_error_response(status, message)
            })?;
        (status, response_headers, response_body)
    };

    let mut modern_receipt_headers = HeaderMap::new();
    if modern_request.is_some() {
        if let Some((name, value)) = modern_local_receipt {
            modern_receipt_headers.append(name, value);
        }
        for (name, values) in &delegation_receipt_headers {
            let name = axum::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid delegated receipt header name")
            })?;
            for value in values {
                let value = axum::http::HeaderValue::from_str(value).map_err(|_| {
                    create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid delegated receipt header value")
                })?;
                modern_receipt_headers.append(name.clone(), value);
            }
        }
    }
    let modern_completion = modern_upstream
        .as_ref()
        .map(|upstream| {
            let status = upstream.status();
            let mut guard = std::mem::replace(&mut connection_guard, ConnectionGuard::new(None, None));
            let metrics = state.metrics_store.clone();
            let monitor = state.task_monitor.clone();
            let task_id = state.task_id.clone();
            let surface_id = state
                .surface
                .surface_id
                .clone();
            let target = state
                .surface
                .target
                .endpoint
                .clone();
            let source = source_addr.clone();
            let identity = identity_hash.clone();
            let trace = trace_id.clone();
            let variant = state
                .active_variant_alias
                .clone();
            let request_bytes = body_bytes.len() as u64;
            move |outcome: crate::mcp::modern_sse::ResponseOutcome| {
                let latency = start_time
                    .elapsed()
                    .as_millis() as u64;
                tokio::spawn(async move {
                    guard.decrement().await;
                    if let (Some(monitor), Some(task_id)) = (monitor, task_id) {
                        monitor
                            .record_bytes(&task_id, outcome.bytes, request_bytes)
                            .await;
                        if !outcome.completed || outcome.failed {
                            monitor
                                .increment_errors(&task_id)
                                .await;
                        }
                    }
                    if let Some(metrics) = metrics {
                        let result = if outcome.completed && !outcome.failed && status.is_success() {
                            crate::metrics::ConnectionStatus::Success
                        } else {
                            crate::metrics::ConnectionStatus::Failed
                        };
                        metrics
                            .record_connection_with_ucp(
                                surface_id,
                                source,
                                target,
                                result,
                                Some(latency),
                                identity,
                                crate::metrics::ConnectionDirection::Request,
                                trace,
                                None,
                                None,
                                None,
                                latency,
                                variant,
                            )
                            .await;
                    }
                });
            }
        });
    let discovery_support = crate::mcp::modern::ForwardingSupport {
        versions: mcp_versions,
        ..crate::mcp::modern::ForwardingSupport::for_endpoint(
            false,
            crate::mcp::request_validation::McpPathKind::DirectAccessPoint,
        )
    }
    .recording_versions(access_point_upstream_key(&state));
    let is_modern_response = modern_request.is_some();
    let process_response = async move |status: StatusCode, response_headers: HeaderMap, response_body: bytes::Bytes| {
        let config_id = state
            .surface
            .surface_id
            .as_str();

        // Calculate request latency (time to receive response from upstream)
        let request_latency_ms = request_latency_start
            .elapsed()
            .as_millis() as u64;

        // Start timer for response processing latency
        let response_processing_start = std::time::Instant::now();

        let log_execution_id = uuid::Uuid::new_v4();
        debug!(
            channel = channel_name,
            status = %status,
            trace_id = %trace_id,
            log_exec_id = %log_execution_id,
            "Request completed"
        );

        // Determine if this is an agent card response (used by multiple steps below)
        let is_agent_card_request = (uri
            .path()
            .ends_with("/.well-known/agent-card.json")
            || uri
                .path()
                .ends_with("/.well-known/agent.json"))
            && status.is_success();

        // ── Step 12: Resolve Protected Agent Identity ───────────────────────────
        // Must happen FIRST, before any injection or rewriting.
        // All subsequent response steps consume the resolved identity.
        let response_identity_selector = state
            .protected_selector
            .as_ref()
            .or(state
                .identity_selector
                .as_ref());
        let response_identity_rules = state
            .protected_rules_engine
            .as_ref()
            .or(state
                .identity_rules_engine
                .as_ref());
        let response_body = if state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::Mcp
        {
            crate::mcp::meta::normalize_bytes(&response_body, mcp_metadata_context)
                .map_err(|error| error.into_response(&response_body, StatusCode::BAD_GATEWAY))?
        } else {
            response_body
        };
        let resolved_identity = if status.is_success() && !response_body.is_empty() {
            match crate::proxy::backend_identity::resolve_protected_agent_identity(
                &response_body,
                &state.surface,
                response_identity_selector,
                response_identity_rules,
                &channel_name,
                is_agent_card_request,
                authenticated_identity.as_ref(),
            )
            .await
            {
                Ok(identity) => identity,
                Err(e) => {
                    // Enbindification
                    // If identity was already resolved on the request path, use it
                    // instead of failing. The upstream may not echo identity in every response.
                    if let Some(ref result) = identity_result {
                        info!(
                            channel = channel_name,
                            did = %result.did,
                            "Response-path identity missing, using request-path identity"
                        );
                        ProtectedAgentIdentity::Managed {
                            did: result.did.clone(),
                            identity_fields: result.identity_fields.clone(),
                        }
                    } else {
                        warn!(
                            channel = channel_name,
                            error = %e,
                            code = %e.code(),
                            "Protected agent identity resolution failed"
                        );
                        return Err(crate::a2a::create_identity_error_response(
                            e.http_status(),
                            e.code(),
                            "protected_identity",
                            &channel_name,
                            &e.to_string(),
                        ));
                    }
                }
            }
        } else {
            ProtectedAgentIdentity::Anonymous
        };

        // External slot resolution (Surface Builder external identity node).
        // Side-effect: issues DID for the external counterparty via vc_issuer.
        if state
            .external_selector
            .is_some()
            && status.is_success()
            && !response_body.is_empty()
            && let Err(e) = crate::proxy::backend_identity::resolve_external_agent_identity(
                &response_body,
                &state.surface,
                state
                    .external_selector
                    .as_ref(),
                state
                    .external_rules_engine
                    .as_ref(),
                &channel_name,
                is_agent_card_request,
                authenticated_identity.as_ref(),
            )
            .await
        {
            warn!(
                channel = channel_name,
                error = %e,
                code = %e.code(),
                "External agent identity resolution failed"
            );
            return Err(crate::a2a::create_identity_error_response(
                e.http_status(),
                e.code(),
                "external_identity",
                &channel_name,
                &e.to_string(),
            ));
        }

        // Rewrite agent card URLs if this is an agent card response
        let response_body = if is_agent_card_request {
            match rewrite_agent_card_urls(
                &response_body,
                &state.surface,
                &state.config,
                &state.network_config,
                &resolved_identity,
            )
            .await
            {
                Ok(rewritten) => {
                    info!(channel = channel_name, "Rewrote agent card URLs to point to proxy");
                    rewritten
                }
                Err(e) => {
                    warn!(channel = channel_name, error = %e, "Failed to rewrite agent card URLs, returning original");
                    response_body
                }
            }
        } else {
            response_body
        };

        // Replace agent-identity/v1 with agent-identity-credential/v1 (signed VP) in agent card
        let response_body = if is_agent_card_request {
            if let Some(selector) = state
                .identity_selector
                .as_ref()
            {
                let vc_issuer = selector.get_vc_issuer();
                let mut card: serde_json::Value = serde_json::from_slice(&response_body).map_err(|e| {
                    create_error_response(
                        StatusCode::BAD_GATEWAY,
                        &format!("Failed to parse agent card for credential injection: {}", e),
                    )
                })?;
                crate::a2a::inject_credential_into_agent_card(&mut card, &resolved_identity, &vc_issuer, &channel_name)
                .await
                .map_err(|e| {
                    error!(channel = channel_name, error = %e, "Failed to inject identity credential into agent card");
                    create_error_response(
                        StatusCode::BAD_GATEWAY,
                        &format!("Agent card identity credential injection failed: {}", e),
                    )
                })?;
                bytes::Bytes::from(serde_json::to_vec(&card).map_err(|e| {
                    create_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("Failed to serialize agent card after credential injection: {}", e),
                    )
                })?)
            } else {
                response_body
            }
        } else {
            response_body
        };

        // Inject did:webvh-derived agentDid/agentDNA top-level fields onto the agent card.
        let response_body = if is_agent_card_request {
            match serde_json::from_slice::<serde_json::Value>(&response_body) {
                Ok(mut card) => {
                    #[cfg(feature = "didwebvh")]
                    crate::a2a::inject_didwebvh_identity_into_agent_card(
                        &mut card,
                        &state.surface,
                        state
                            .didwebvh_identity_store
                            .as_ref(),
                    )
                    .await;
                    #[cfg(not(feature = "didwebvh"))]
                    let _ = &card;
                    match serde_json::to_vec(&card) {
                        Ok(bytes) => bytes::Bytes::from(bytes),
                        Err(e) => {
                            warn!(channel = channel_name, error = %e, "Failed to re-serialize agent card after agentDNA injection; returning previous body");
                            response_body
                        }
                    }
                }
                Err(e) => {
                    warn!(channel = channel_name, error = %e, "Failed to parse agent card for agentDNA injection; returning previous body");
                    response_body
                }
            }
        } else {
            response_body
        };

        // Inject custom metadata into MCP initialize responses
        let response_body = if state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::Mcp
            && status.is_success()
            && !response_body.is_empty()
        {
            // Try to parse as JSON-RPC response
            if let Ok(mut json_response) = serde_json::from_slice::<serde_json::Value>(&response_body) {
                // Check if this is an initialize response
                if !is_modern_response
                    && let Some(result) = json_response.get("result")
                    && (result
                        .get("protocolVersion")
                        .is_some()
                        || result
                            .get("serverInfo")
                            .is_some())
                {
                    // This looks like an initialize response
                    if let Some(custom_metadata) = state
                        .surface
                        .custom_metadata()
                        && custom_metadata.enabled
                    {
                        info!(channel = channel_name, "Injecting custom metadata into MCP initialize response");
                        crate::mcp::inject_mcp_metadata(&mut json_response, &custom_metadata.payload);
                    }
                }

                // Filter tools/list responses based on OPA policy
                if let (Some(policy_manager), Some(config_id)) = (&state.policy_manager, state.surface.config_id())
                    && let Some(result) = json_response.get_mut("result")
                    && let Some(tools) = result.get_mut("tools")
                    && let Some(tools_array_mut) = tools.as_array_mut()
                {
                    // Extract tool names
                    let tool_names: Vec<String> = tools_array_mut
                        .iter()
                        .filter_map(|t| {
                            t.get("name")
                                .and_then(|n| n.as_str())
                                .map(|s| s.to_string())
                        })
                        .collect();

                    let original_count = tools_array_mut.len();

                    if !tool_names.is_empty() {
                        // Build a full PolicyInput template so per-tool decisions
                        // see the same context as the inbound channel OPA gate
                        // (source_auth, agent, extension_identity, payment,
                        // identity_binding, a2a). `filter_mcp_tools` clones the
                        // template per tool and overrides `mcp` with the
                        // synthesized tools/call probe.
                        let mut template = crate::surface_context::PolicyInput::new(
                            method.as_ref(),
                            uri.path(),
                            crate::surface_context::filter_sensitive_headers(&headers),
                            "inbound",
                            None,
                            None,
                            state
                                .surface
                                .config_id()
                                .map(|s| s.to_string()),
                            &state.surface.name,
                        );
                        template.source_auth = source_auth_context.clone();
                        template.mcp = mcp_classification
                            .as_ref()
                            .and_then(crate::mcp::modern_mcp_context);
                        template.agent = agent_context.clone();
                        template.a2a = a2a_context.clone();
                        template.extension_identity = extension_identity.clone();
                        template.payment = payment_context.clone();
                        template.identity_binding = identity_binding.clone();
                        template.normalize_caller_did();

                        // Filter tools based on policy
                        let filtered_names = policy_manager.filter_mcp_tools_for_variant(
                            config_id,
                            state
                                .active_variant_alias
                                .as_deref(),
                            tool_names,
                            &template,
                        );

                        // Update tools array to only include filtered tools
                        tools_array_mut.retain(|t| {
                            if let Some(name) = t
                                .get("name")
                                .and_then(|n| n.as_str())
                            {
                                filtered_names.contains(&name.to_string())
                            } else {
                                false
                            }
                        });
                        channel_info!(
                            config_id,
                            "Filtered tools based on OPA policy original_count={} filtered_count={}",
                            original_count,
                            tools_array_mut.len()
                        );

                        // MCP Tool Gating — apply the surface's condition-gated
                        // allow/deny firewall on top of the per-tool OPA filter.
                        // The gate condition sees the request `PolicyInput` (with
                        // `mcp.method = tools/list`), so a tool hidden here is the
                        // same one the tools/call gate blocks.
                        if let Some(gating) = policy_manager
                            .compiled_mcp_tool_gating(
                                config_id,
                                state
                                    .active_variant_alias
                                    .as_deref(),
                            )
                            .filter(|g| !g.is_empty())
                        {
                            let gating_input_value = if gating.has_policy_conditions() {
                                let mut gating_input = template.clone();
                                gating_input.mcp = mcp_classification
                                    .as_ref()
                                    .and_then(crate::mcp::modern_mcp_context)
                                    .or_else(|| {
                                        Some(crate::surface_context::McpContext {
                                            method: "tools/list".to_string(),
                                            tool_name: None,
                                            resource_uri: None,
                                            prompt_name: None,
                                            params: None,
                                            ..Default::default()
                                        })
                                    });
                                serde_json::to_value(&gating_input).unwrap_or_default()
                            } else {
                                serde_json::Value::Null
                            };
                            let current_names: Vec<String> = tools_array_mut
                                .iter()
                                .filter_map(|t| {
                                    t.get("name")
                                        .and_then(|n| n.as_str())
                                        .map(|s| s.to_string())
                                })
                                .collect();
                            let gated_count_before = tools_array_mut.len();
                            let allowed_names = gating.filter_tools(current_names, &gating_input_value);
                            tools_array_mut.retain(|t| {
                                t.get("name")
                                    .and_then(|n| n.as_str())
                                    .map(|name| allowed_names.contains(&name.to_string()))
                                    .unwrap_or(false)
                            });
                            if tools_array_mut.len() < gated_count_before {
                                channel_info!(
                                    config_id,
                                    "MCP tool gating filtered tools/list before={} after={}",
                                    gated_count_before,
                                    tools_array_mut.len()
                                );
                            }
                        }
                    }
                }

                if is_modern_response
                    && caller_scoped_mcp_result(
                        &state.surface,
                        state
                            .policy_manager
                            .as_deref(),
                        state
                            .active_variant_alias
                            .as_deref(),
                    )
                {
                    crate::mcp::meta::protect_enriched_result_cache(&mut json_response, mcp_metadata_context);
                }

                // Serialize back to bytes
                match serde_json::to_vec(&json_response) {
                    Ok(modified_bytes) => bytes::Bytes::from(modified_bytes),
                    Err(e) => {
                        warn!(channel = channel_name, error = %e, "Failed to serialize modified MCP response");
                        response_body
                    }
                }
            } else {
                response_body
            }
        } else {
            response_body
        };

        // Inject response custom metadata if enabled (separate from request metadata)
        // Custom metadata HTTP headers are collected here and applied on the response builder below.
        let mut response_metadata_headers: Vec<(String, String)> = Vec::new();
        let response_body = if status.is_success() && !response_body.is_empty() {
            if let Some(response_custom_metadata) = state
                .surface
                .response_custom_metadata()
            {
                if response_custom_metadata.enabled {
                    match state
                        .surface
                        .channel_protocol()
                    {
                        crate::config::ChannelProtocol::A2a
                        | crate::config::ChannelProtocol::Ap2
                        | crate::config::ChannelProtocol::DIDComm => {
                            // For A2A protocol, inject into message.metadata
                            info!(channel = channel_name, "Injecting response custom metadata (A2A)");
                            match inject_custom_metadata_extension(
                                &response_body,
                                response_custom_metadata,
                                &channel_name,
                                &state.secrets_store,
                                crate::protocols::MetadataRuntimeContext {
                                    request_id: Some(trace_id.as_str()),
                                    surface_id: Some(config_id),
                                },
                            )
                            .await
                            {
                                Ok(modified_body) => {
                                    info!(channel = channel_name, "Response custom metadata extension injected (A2A)");
                                    modified_body
                                }
                                Err(e) => {
                                    warn!(channel = channel_name, error = %e, "Failed to inject response custom metadata extension, using original body");
                                    response_body
                                }
                            }
                        }
                        crate::config::ChannelProtocol::Mcp => {
                            let injected = crate::mcp::metadata::inject_custom_metadata_with_context(
                                &response_body,
                                response_custom_metadata,
                                &channel_name,
                                &state.secrets_store,
                                crate::protocols::MetadataRuntimeContext {
                                    request_id: Some(trace_id.as_str()),
                                    surface_id: Some(config_id),
                                },
                                mcp_metadata_context,
                                crate::mcp::meta::McpMetaTarget::Result,
                            )
                            .await
                            .map_err(|error| {
                                warn!(channel = channel_name, error = %error, "MCP response metadata injection failed");
                                create_error_response(StatusCode::BAD_GATEWAY, "MCP response metadata injection failed")
                            })?;
                            for (name, value) in injected.extra_headers {
                                response_metadata_headers.push((
                                    name.to_string(),
                                    value
                                        .to_str()
                                        .unwrap_or_default()
                                        .to_string(),
                                ));
                            }
                            injected.body
                        }
                    }
                } else {
                    response_body
                }
            } else {
                response_body
            }
        } else {
            response_body
        };

        // Inject identity credential (VP) into outbound responses for A2A/AP2 protocols
        // This replaces agent-identity/v1 with agent-identity-credential/v1 containing a signed VP
        // Uses the pre-resolved protected agent identity from Step 12
        // NOTE: This must happen BEFORE trust registry injection so the credential extension is available
        let response_body = if let ProtectedAgentIdentity::Managed { ref did, ref identity_fields } = resolved_identity
        {
            if (state
                .surface
                .channel_protocol()
                == crate::config::ChannelProtocol::A2a
                || state
                    .surface
                    .channel_protocol()
                    == crate::config::ChannelProtocol::Ap2)
                && status.is_success()
                && !response_body.is_empty()
            {
                let selector = state
                    .identity_selector
                    .as_ref();
                if let Some(selector) = selector {
                    let vc_issuer = selector.get_vc_issuer();
                    let response_wb =
                        build_response_workload_binding(identity_fields, request_agent_did.as_deref(), &trace_id);
                    match crate::a2a::inject_identity_credential_into_response(
                        &response_body,
                        did,
                        identity_fields,
                        response_wb,
                        &vc_issuer,
                        &channel_name,
                    )
                    .await
                    {
                        Ok(None) => response_body,
                        Ok(Some((modified_bytes, vp_jwt))) => {
                            info!(channel = channel_name, did = %did, "Identity credential VP injected into outbound response");
                            if crate::delegation_vault::audit::identity_binding_vp_audit_enabled() {
                                let mut evt = crate::delegation_vault::audit::audit_event(
                                    crate::delegation_vault::audit::DelegationAuditAction::VpInjected,
                                    None,
                                    request_user_hash.as_deref(),
                                    None,
                                    Some(
                                        state
                                            .surface
                                            .surface_id
                                            .as_str(),
                                    ),
                                );
                                evt.agent_identity_did = Some(did.clone());
                                evt.channel_name = Some(channel_name.clone());
                                evt.target_endpoint = Some(
                                    state
                                        .surface
                                        .target
                                        .endpoint
                                        .clone(),
                                );
                                evt.protocol = Some(format!("{:?}", state.surface.channel_protocol()).to_lowercase());
                                evt.vp_jwt = Some(vp_jwt);
                                evt.trace_id = Some(trace_id.clone());
                                evt.detail = Some("response_path".to_string());
                                evt.caller = authenticated_identity
                                    .as_ref()
                                    .map(crate::delegation_vault::audit::build_caller_context);
                                crate::delegation_vault::audit::audit(evt);
                            }
                            modified_bytes
                        }
                        Err(e) => {
                            warn!(channel = channel_name, error = %e, "Failed to inject identity credential VP into response, using original body");
                            response_body
                        }
                    }
                } else {
                    debug!(channel = channel_name, "No identity selector available, skipping response VP injection");
                    response_body
                }
            } else {
                response_body
            }
        } else {
            response_body
        };

        // Validate response extensions if enabled and response validation rules are configured
        // Skip validation for agent card requests (they're JSON config, not A2A messages)
        if is_agent_card_request {
            debug!(channel = channel_name, "Skipping extension validation for agent card request");
        }

        if state
            .config
            .extension_inspection
            .enabled
            && !response_body.is_empty()
            && state
                .identity_rules_engine
                .is_some()
            && !is_agent_card_request
        {
            // Dispatch to protocol-specific validator
            let validation_result = if matches!(
                state
                    .surface
                    .channel_protocol(),
                crate::config::ChannelProtocol::Mcp
            ) {
                // MCP protocol - validate _meta.serverIdentity
                crate::mcp::validation::validate_mcp_response(
                    &response_body,
                    &channel_name,
                    &state.surface,
                    &state.identity_rules_engine,
                    &state.metrics_store,
                )
                .await
            } else {
                // A2A/UCP protocols - validate extensions arrays
                let response_ctx = crate::protocols::extensions::ResponseExtensionInspectionContext {
                    config: &state.config,
                    channel_name: &channel_name,
                    surface: &state.surface,
                    response_rules_engine: &state.identity_rules_engine,
                    metrics_store: &state.metrics_store,
                };
                crate::protocols::extensions::inspect_response_extensions(&response_body, &response_ctx).await
            };

            match validation_result {
                Ok(_) => {
                    debug!(channel = channel_name, "Response extension validation passed");
                }
                Err(response) => {
                    warn!(channel = channel_name, "Response extension validation failed");

                    // Record failed connection due to response validation rejection
                    if let Some(ref metrics) = state.metrics_store
                        && !is_modern_response
                    {
                        let latency_ms = start_time
                            .elapsed()
                            .as_millis() as u64;
                        let metrics = Arc::clone(metrics);
                        let channel_config_id = state
                            .surface
                            .surface_id
                            .clone();
                        let source = source_addr.clone();
                        let dest = state
                            .surface
                            .target
                            .endpoint
                            .clone();
                        let trace_id = uuid::Uuid::new_v4().to_string();
                        tokio::spawn(async move {
                            metrics
                                .record_connection(
                                    channel_config_id,
                                    source,
                                    dest,
                                    crate::metrics::ConnectionStatus::Failed,
                                    Some(latency_ms),
                                    identity_hash,
                                    crate::metrics::ConnectionDirection::Request,
                                    trace_id,
                                    None,
                                    None,
                                    latency_ms,
                                    None,
                                )
                                .await;
                        });
                    }

                    // Track error (connection guard will handle decrement)
                    if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id)
                        && !is_modern_response
                    {
                        let task_id = task_id.clone();
                        let monitor = task_monitor.clone();
                        tokio::spawn(async move {
                            info!(task_id = %task_id, "Recording error: Response extension validation failed");
                            monitor
                                .increment_errors(&task_id)
                                .await;
                        });
                    }

                    return Err(response);
                }
            }
        }

        // ── Step 23: Response policy evaluation (§4.11 / §6.1) ─────────────────
        // If a response_policy_definition_id is configured, evaluate the OPA policy
        // on the upstream response before returning it to the caller.
        if let Some(response_policy_id) = state
            .surface
            .response_policy_definition_id()
            && let Some(ref pm) = state.policy_manager
        {
            use crate::proxy::response_policy::{
                CallerContext as RpCallerContext, ResponseContext, ResponsePolicyInput, SurfaceContext,
                evaluate_response_policy,
            };

            let response_json: Option<serde_json::Value> = serde_json::from_slice(&response_body).ok();

            let content_type_str = response_headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let policy_key = format!("response:{}", response_policy_id);
            let input = ResponsePolicyInput {
                response: ResponseContext {
                    status_code: status.as_u16(),
                    body: response_json,
                    content_type: content_type_str,
                    is_error: status.is_server_error() || status.is_client_error(),
                    method: None,
                },
                caller: RpCallerContext {
                    did: agent_context
                        .as_ref()
                        .and_then(|ctx| ctx.did.clone()),
                    identity_source: caller_identity_source.clone(),
                    dna_uai: agent_context
                        .as_ref()
                        .and_then(|ctx| ctx.agent_dna.as_ref())
                        .map(|dna| dna.uai.clone()),
                },
                surface: SurfaceContext {
                    id: state
                        .surface
                        .surface_id
                        .clone(),
                    name: channel_name.clone(),
                    protocol: format!(
                        "{:?}",
                        state
                            .surface
                            .channel_protocol()
                    )
                    .to_lowercase(),
                },
                metadata: None,
            };

            let response_policy = pm
                .resolve_policy_attestation(Some(response_policy_id))
                .await;
            let decision = evaluate_response_policy(pm.as_ref(), &policy_key, input);
            if !decision.allow {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Response,
                    allow: false,
                    reason: decision.reason.as_deref(),
                    policy_id: Some(response_policy_id),
                    policy_definition_id: Some(response_policy_id),
                    policy_name: response_policy
                        .name
                        .as_deref(),
                    policy_version: response_policy.version,
                    policy_content_hash: response_policy
                        .content_hash
                        .as_deref(),
                    surface_id: Some(channel_name.as_str()),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    actor_did: request_agent_did.as_deref(),
                    ..Default::default()
                });
                connection_guard
                    .decrement()
                    .await;
                return Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(r#"{"error":"Response blocked","code":"response_policy_denied"}"#))
                    .unwrap());
            }
            crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                scope: crate::observability::PolicyScope::Response,
                allow: true,
                policy_id: Some(response_policy_id),
                policy_definition_id: Some(response_policy_id),
                policy_name: response_policy
                    .name
                    .as_deref(),
                policy_version: response_policy.version,
                policy_content_hash: response_policy
                    .content_hash
                    .as_deref(),
                surface_id: Some(channel_name.as_str()),
                trace_id: Some(&trace_id),
                http_method: Some(method.as_ref()),
                path: Some(uri.path()),
                identity: authenticated_identity.as_ref(),
                actor_did: request_agent_did.as_deref(),
                ..Default::default()
            });
        }

        // Inject VP into response if client supports credential extension and backend agent has DID
        // Uses the pre-resolved protected agent identity from Step 12. When an
        // inbound binding VP from an upstream gateway has been verified, its raw
        // VCs are flattened into the outgoing serverIdentity VP so the receiver
        // sees the full request → response provenance chain.
        let inbound_chained_vcs = identity_binding
            .as_ref()
            .map(|b| b.inbound_credentials.clone())
            .unwrap_or_default();
        let (response_body, injected_vp_jwt) = inject_backend_agent_vp(
            response_body,
            client_supports_vp,
            &resolved_identity,
            &state,
            &channel_name,
            request_user_id.as_deref(),
            inbound_chained_vcs,
            &trace_id,
            mcp_metadata_context,
        )
        .await?;

        // Emit delegation audit event if a VP was injected
        if let Some(ref vp_jwt) = injected_vp_jwt
            && crate::delegation_vault::audit::identity_binding_vp_audit_enabled()
        {
            let mut evt = crate::delegation_vault::audit::audit_event(
                crate::delegation_vault::audit::DelegationAuditAction::VpInjected,
                None,
                request_user_hash.as_deref(),
                None,
                Some(
                    state
                        .surface
                        .surface_id
                        .as_str(),
                ),
            );
            evt.agent_identity_did = match &resolved_identity {
                ProtectedAgentIdentity::Managed { did, .. } => Some(did.clone()),
                ProtectedAgentIdentity::Anonymous => None,
            };
            evt.channel_name = Some(channel_name.clone());
            evt.target_endpoint = Some(
                state
                    .surface
                    .target
                    .endpoint
                    .clone(),
            );
            evt.protocol = Some(format!("{:?}", state.surface.channel_protocol()).to_lowercase());
            evt.vp_jwt = Some(vp_jwt.clone());
            evt.caller = authenticated_identity
                .as_ref()
                .map(crate::delegation_vault::audit::build_caller_context);
            crate::delegation_vault::audit::audit(evt);
        }

        // Trust Recorder — writes TrAdmin records to configured TRs on the
        // response leg for HTTP-managed agents. Fire-and-forget; idempotent —
        // duplicate records log at DEBUG (`apply_trust_recorder`).
        if let ProtectedAgentIdentity::Managed { did, .. } = &resolved_identity {
            crate::trust_registry_verification::spawn_trust_recorder(
                &state.surface,
                did,
                state
                    .trust_registry_listener_manager
                    .clone(),
            );
        }

        // Broadcast complete payload capture with response (for successful requests)
        // Capture payloads for all requests when extension inspection is enabled
        if state
            .config
            .extension_inspection
            .enabled
        {
            let config_id = state
                .surface
                .surface_id
                .as_str();

            // Try to parse request body as JSON, or use empty object if not available/parseable
            let request_json = if !body_bytes.is_empty() {
                serde_json::from_slice::<JsonValue>(&body_bytes).unwrap_or_else(|_| {
                    serde_json::json!({
                        "_raw_body": String::from_utf8_lossy(&body_bytes).to_string(),
                        "method": method.as_str()
                    })
                })
            } else {
                serde_json::json!({
                    "method": method.as_str(),
                    "_no_body": true
                })
            };

            // Try to parse response as JSON
            let response_json = if !response_body.is_empty() {
                serde_json::from_slice::<JsonValue>(&response_body).ok()
            } else {
                None
            };

            broadcast_payload_capture_async(
                &state.ws_state,
                &state.metrics_store,
                &channel_name,
                config_id,
                &request_json,
                response_json,
                "success",
                None,
                identity_hash.clone(),
                state
                    .active_variant_alias
                    .as_deref(),
            )
            .await;
        }

        // Fallback: if the inbound request body had no UCP data, inspect the upstream response body.
        // This handles the common A2A pattern where the client sends a plain text message/send
        // and the upstream returns UCP-structured data (e.g. a2a.ucp.checkout, a2a.product_results).
        if ucp_operation.is_none()
            && !response_body.is_empty()
            && let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&response_body)
        {
            // Responses from upstream agents use result.parts[] (A2A response envelope)
            let resp_parts = resp_json
                .get("result")
                .and_then(|r| r.get("parts"))
                .and_then(|p| p.as_array());
            if let Some(parts) = resp_parts {
                let mut found_action: Option<String> = None;
                let mut found_ucp_keys: Vec<String> = Vec::new();
                let mut found_product_keys: Vec<String> = Vec::new();
                for part in parts {
                    if let Some(data) = part
                        .get("data")
                        .and_then(|d| d.as_object())
                    {
                        if found_action.is_none()
                            && let Some(action) = data
                                .get("action")
                                .and_then(|a| a.as_str())
                        {
                            found_action = Some(action.to_string());
                        }
                        for key in data.keys() {
                            if key.starts_with("a2a.ucp.") {
                                found_ucp_keys.push(key.clone());
                            } else if key.starts_with("a2a.product") {
                                found_product_keys.push(key.clone());
                            }
                        }
                    }
                }
                found_ucp_keys.sort();
                let has_payment_keys = found_ucp_keys
                    .iter()
                    .any(|k| k == "a2a.ucp.checkout.payment_data" || k == "a2a.ucp.checkout.ap2_checkout_mandate");
                let has_cart_keys = found_ucp_keys
                    .iter()
                    .any(|k| k.starts_with("a2a.ucp.cart"));
                if has_payment_keys {
                    ucp_operation = Some("complete_checkout".to_string());
                    channel_info!(config_id, "🛒 UCP (response): complete_checkout");
                } else if let Some(ref action) = found_action {
                    ucp_operation = Some(action.clone());
                    channel_info!(config_id, "🛒 UCP (response): {}", action);
                } else if !found_ucp_keys.is_empty() {
                    let first_key = &found_ucp_keys[0];
                    let op = first_key
                        .strip_prefix("a2a.ucp.")
                        .unwrap_or(first_key.as_str());
                    let op = op
                        .split('.')
                        .next()
                        .unwrap_or(op);
                    let op = if op == "cart" && has_cart_keys {
                        "cart_create"
                    } else {
                        op
                    };
                    ucp_operation = Some(op.to_string());
                    channel_info!(config_id, "🛒 UCP (response): {} (from key '{}')", op, first_key);
                } else if !found_product_keys.is_empty() {
                    ucp_operation = Some("discovery".to_string());
                    channel_info!(config_id, "🛒 UCP (response): discovery (from '{}')", found_product_keys[0]);
                }
            }
        }

        // Record successful connection in metrics - single record per request
        if let Some(ref metrics) = state.metrics_store
            && !is_modern_response
        {
            let metrics = Arc::clone(metrics);
            let channel_config_id = state
                .surface
                .surface_id
                .clone();
            let source = source_addr.clone();
            let dest = state
                .surface
                .target
                .endpoint
                .clone();
            let identity = identity_hash.clone();

            // Use the trace_id generated at the start of the request handler
            // Calculate response processing latency (time to rewrite URLs, validate, etc.)
            let channel_response_latency_ms = response_processing_start
                .elapsed()
                .as_millis() as u64;
            let total_latency_ms = start_time
                .elapsed()
                .as_millis() as u64;

            // Debug log identity tracking
            if identity.is_some() {
                channel_info!(
                    config_id,
                    "📊 Recording metrics: channel_config_id={} identity={:?}",
                    channel_config_id,
                    identity
                );
            }

            // Record single metric with all latency breakdowns
            let variant_alias = state
                .active_variant_alias
                .clone();
            tokio::spawn(async move {
                metrics
                    .record_connection_with_ucp(
                        channel_config_id,
                        source,
                        dest,
                        crate::metrics::ConnectionStatus::Success,
                        Some(request_latency_ms),
                        identity,
                        crate::metrics::ConnectionDirection::Request,
                        trace_id,
                        ucp_operation,
                        Some(request_latency_ms),
                        Some(channel_response_latency_ms),
                        total_latency_ms,
                        variant_alias,
                    )
                    .await;
            });
        }

        // Final cleanup and response building
        let _cleanup_span = tracing::info_span!(
            "channel.cleanup",
            otel.name = "Cleanup & Build Response",
            surface = %channel_name
        );
        // Don't hold guard across awaits - just enter/exit to mark context
        drop(_cleanup_span.enter());

        // Track task metrics: decrement active connections and record bytes transferred
        if !is_modern_response {
            if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
                let bytes_received = body_bytes.len() as u64;
                let bytes_sent = response_body.len() as u64;
                debug!(
                    channel = channel_name,
                    task_id = task_id,
                    bytes_sent = bytes_sent,
                    bytes_received = bytes_received,
                    status = %status,
                    "Recording successful connection metrics"
                );
                let decrement_start = std::time::Instant::now();
                connection_guard
                    .decrement()
                    .await;
                let decrement_duration = decrement_start.elapsed();
                if decrement_duration.as_millis() > 10 {
                    warn!(
                        channel = channel_name,
                        duration_ms = decrement_duration.as_millis(),
                        "connection_guard.decrement() took longer than expected"
                    );
                }
                task_monitor
                    .record_bytes(task_id, bytes_sent, bytes_received)
                    .await;
            } else {
                // No task monitor, but still need to decrement
                let decrement_start = std::time::Instant::now();
                connection_guard
                    .decrement()
                    .await;
                let decrement_duration = decrement_start.elapsed();
                if decrement_duration.as_millis() > 10 {
                    warn!(
                        channel = channel_name,
                        duration_ms = decrement_duration.as_millis(),
                        "connection_guard.decrement() took longer than expected"
                    );
                }
            }

            // ── MCP Streamable HTTP: wrap JSON-RPC response as SSE event ────────────
        }

        // If this is an MCP channel, the request was a POST that advertised
        // `Accept: text/event-stream`, and the upstream returned application/json,
        // wrap the body as a single SSE `message` event so Streamable-HTTP clients
        // (e.g. Microsoft Copilot Studio) get the response shape they expect.
        //
        // Also synthesize an `Mcp-Session-Id` header on `initialize` responses —
        // the gateway runs in stateless session mode, so the ID is not validated
        // on subsequent requests, but Copilot Studio requires the header to be
        // present on the initial response.
        let client_wants_streamable_sse = state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::Mcp
            && !is_modern_response
            && method == "POST"
            && crate::mcp::sse_server::client_wants_sse(&headers);

        let upstream_is_json = response_headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("application/json"));

        let (response_body, sse_override_content_type, mcp_session_id) =
            if client_wants_streamable_sse && status.is_success() && upstream_is_json && !response_body.is_empty() {
                // Detect MCP `initialize` response so we can mint a session id.
                let parsed = serde_json::from_slice::<serde_json::Value>(&response_body).ok();

                let compact_body = match &parsed {
                    Some(v) => serde_json::to_string(v)
                        .unwrap_or_else(|_| String::from_utf8_lossy(&response_body).into_owned()),
                    None => String::from_utf8_lossy(&response_body).into_owned(),
                };

                let is_initialize = parsed
                    .as_ref()
                    .and_then(|v| {
                        v.get("result").map(|r| {
                            r.get("protocolVersion")
                                .is_some()
                                || r.get("serverInfo").is_some()
                                || r.get("capabilities")
                                    .is_some()
                        })
                    })
                    .unwrap_or(false);

                let session_id = if is_initialize {
                    let sid = uuid::Uuid::new_v4()
                        .to_string()
                        .replace('-', "");
                    // Associate the client capabilities captured from the
                    // inbound `initialize` request with the freshly-minted
                    // session id, so downstream code (credential delegation,
                    // Elicit mode) can check `capabilities.elicitation`.
                    if let Some(caps) = mcp_initialize_caps.clone() {
                        let registry = crate::mcp::elicitation::global_capability_registry().clone();
                        registry
                            .record(&sid, caps)
                            .await;
                    }
                    Some(sid)
                } else {
                    None
                };

                let sse_body = crate::mcp::sse_server::wrap_json_as_sse_event(&compact_body);
                channel_info!(
                    config_id,
                    "📦 MCP Streamable HTTP: wrapping JSON-RPC response as SSE (initialize={}, body_len={})",
                    is_initialize,
                    sse_body.len()
                );
                (bytes::Bytes::from(sse_body), Some("text/event-stream"), session_id)
            } else {
                (response_body, None, None)
            };

        // Build response
        let mut response = Response::builder().status(status);

        // Copy response headers (excluding hop-by-hop headers and content-length)
        // content-length will be set automatically by axum based on the actual body
        // Skip Content-Type if we are overriding it for SSE.
        for (key, value) in response_headers.iter() {
            let key_str = key.as_str();
            if is_hop_by_hop_header(key_str) || key_str.to_lowercase() == "content-length" {
                continue;
            }
            if sse_override_content_type.is_some() && key_str.eq_ignore_ascii_case("content-type") {
                continue;
            }
            response = response.header(key_str, value.as_bytes());
        }

        if let Some(ct) = sse_override_content_type {
            response = response
                .header("Content-Type", ct)
                .header("Cache-Control", "no-cache");
        }

        if let Some(sid) = mcp_session_id {
            response = response.header("Mcp-Session-Id", sid);
        }

        // Add x402 payment response header if present
        if let Some(payment_header) = payment_response_header
            && !is_modern_response
        {
            response = response.header(
                &state
                    .config
                    .x402_headers
                    .payment_response,
                payment_header,
            );
        }

        // Relay allow-listed settlement receipt headers from a delegate payment
        // gateway (Model B `Proceed`) onto the caller-facing response.
        if !is_modern_response {
            for (name, values) in &delegation_receipt_headers {
                for value in values {
                    response = response.header(name.as_str(), value.as_str());
                }
            }
        }

        // Apply Custom Metadata HTTP headers (when injection_target is Headers or Both).
        for (name, value) in &response_metadata_headers {
            response = response.header(name.as_str(), value.as_str());
        }

        let response_body = if state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::Mcp
        {
            crate::mcp::meta::normalize_bytes(&response_body, mcp_metadata_context)
                .map_err(|error| error.into_response(&response_body, StatusCode::BAD_GATEWAY))?
        } else {
            response_body
        };
        response
            .body(Body::from(response_body))
            .map_err(|e| {
                error!(channel = channel_name, error = %e, "Failed to build response");
                create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response")
            })
    };
    if let (Some(upstream), Some(request), Some(complete)) = (modern_upstream, modern_request, modern_completion) {
        let status = upstream.status();
        let mut upstream_headers = upstream.headers().clone();
        for name in modern_receipt_headers.keys() {
            upstream_headers.remove(name);
            for value in modern_receipt_headers.get_all(name) {
                upstream_headers.append(name, value.clone());
            }
        }
        let mut processing_headers = upstream_headers.clone();
        processing_headers.insert("content-type", axum::http::HeaderValue::from_static("application/json"));
        let result = crate::mcp::modern_sse::forwarding_response_with_finalizer(
            upstream.bytes_stream(),
            status,
            &upstream_headers,
            request,
            modern_limits,
            discovery_support,
            move |message| async move {
                use crate::mcp::modern_sse::SseReadError;
                let body = bytes::Bytes::from(serde_json::to_vec(&message).map_err(|_| SseReadError::InvalidMessage)?);
                let processed = process_response(status, processing_headers, body)
                    .await
                    .map_err(|_| SseReadError::ResponseRejected)?;
                let headers = processed.headers().clone();
                let body = axum::body::to_bytes(
                    processed.into_body(),
                    modern_limits
                        .max_event_bytes
                        .get(),
                )
                .await
                .map_err(|_| SseReadError::EventTooLarge)?;
                Ok(crate::mcp::modern_sse::ProcessedResponse {
                    message: serde_json::from_slice(&body).map_err(|_| SseReadError::InvalidMessage)?,
                    headers: Some(headers),
                })
            },
            move |message| async move {
                let Some(prepared) = modern_delegation else {
                    return Ok(message);
                };
                let runtime = mcp_continuations
                    .as_deref()
                    .ok_or(crate::mcp::modern_sse::SseReadError::ResponseRejected)?;
                let now = crate::proxy::credential_delegation::modern::now_secs()
                    .map_err(|_| crate::mcp::modern_sse::SseReadError::ResponseRejected)?;
                prepared
                    .finish(&runtime.service, message, runtime.config.ttl_secs, now)
                    .await
                    .map_err(|_| crate::mcp::modern_sse::SseReadError::ResponseRejected)
            },
        )
        .await;
        return match result {
            Ok(response) => {
                let response = match subscription_lifetime {
                    Some(lifetime) => lifetime.wrap(response),
                    None => response,
                };
                Ok(crate::mcp::modern_sse::observe_response(response, complete))
            }
            Err(error) => {
                complete(crate::mcp::modern_sse::ResponseOutcome {
                    failed: true,
                    ..Default::default()
                });
                warn!(error = %error, "Modern MCP upstream response rejected");
                Err(create_error_response(StatusCode::BAD_GATEWAY, "Invalid modern MCP upstream response"))
            }
        };
    }
    process_response(status, response_headers, response_body).await
}

fn normalize_route_for_match(route: &str) -> String {
    let with_leading_slash = if route.starts_with('/') {
        route.to_string()
    } else {
        format!("/{route}")
    };
    let trimmed = with_leading_slash.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn route_tail_to_uri_path(tail: &str) -> String {
    if tail.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", tail.trim_start_matches('/'))
    }
}

/// Multi-channel proxy handler that routes based on path prefix
pub async fn multi_channel_proxy_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<MultiSurfaceProxyState>,
    req: Request,
) -> Response {
    let continuations = crate::mcp::continuations::config::global().map(|runtime| Arc::new(runtime.clone()));
    Box::pin(multi_channel_proxy_handler_with_mcp_runtime(
        addr,
        state,
        req,
        crate::mcp::request_validation::runtime_policy_for(
            crate::mcp::request_validation::McpPathKind::DirectAccessPoint,
        ),
        continuations,
    ))
    .await
}

async fn multi_channel_proxy_handler_with_mcp_runtime(
    addr: SocketAddr,
    state: MultiSurfaceProxyState,
    req: Request,
    mcp_versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
    mcp_continuations: Option<Arc<crate::mcp::continuations::config::ContinuationRuntime>>,
) -> Response {
    // Generate unique ID for this handler invocation to track duplicates
    let handler_invocation_id = uuid::Uuid::new_v4();
    info!(
        "🔵 HANDLER ENTRY: invocation_id={} source={} method={} path={}",
        handler_invocation_id,
        addr,
        req.method(),
        req.uri().path()
    );

    // Extract path and query before consuming req
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| q.to_string());

    debug!("Multi-channel handler received request: method={} path={}", req.method(), path);

    // Find the matching channel and parse any `$alias` suffix attached to its route.
    // URL grammar: `/route[$alias][/rest]`.
    // Sort channels by route length (descending) so the most specific route wins.
    let channels = state.channels.read().await;
    let mut sorted_channels: Vec<_> = channels.iter().collect();
    sorted_channels.sort_by(|a, b| {
        let a_route = a.surface.route();
        let b_route = b.surface.route();
        b_route
            .len()
            .cmp(&a_route.len())
    });

    let matched_channel = sorted_channels
        .iter()
        .find_map(|ch| {
            let route = ch.surface.route();
            let normalized_route = normalize_route_for_match(route);
            // The parser treats "/" specially: a route of "/" matches every path.
            // For prefix matching pass an empty string in that case so any leading
            // `$alias` is honoured at the very start of the path.
            let prefix: &str = if normalized_route == "/" {
                ""
            } else {
                normalized_route.as_str()
            };

            crate::proxy::route_variant::parse_route_with_variant(&path, prefix).map(|m| {
                debug!(
                    "Route matched: surface='{}' route='{}' alias={:?} tail='{}'",
                    ch.surface.name, normalized_route, m.alias, m.tail
                );
                (*ch, normalized_route, m.alias.map(|s| s.to_string()), m.tail.to_string())
            })
        });

    // Surface the alias as `virtual_channel_alias` for the downstream resolver
    // (which still operates on `ChannelMapping.virtual_channels` until the
    // SurfaceVariant pipeline migration lands — see plan §3b).
    let (channel_info, virtual_channel_alias, stripped_tail) = match matched_channel {
        Some((ch, _route, alias, tail)) => (Some(ch), alias, tail),
        None => (None, None, String::new()),
    };

    if let Some(ref alias) = virtual_channel_alias {
        debug!("Variant alias detected: alias='{}' tail='{}'", alias, stripped_tail);
    }

    match channel_info {
        Some(ch) => {
            info!("Matched channel '{}' with route '{}' for path '{}'", ch.surface.name, ch.surface.route(), path);

            // Base-mode (no variants): resolve to base surface, use channel-level
            // engines, and forward through the normal pipeline below.
            // Variant-mode (one or more variants): pick by alias or
            // default_variant_id, use per-variant engines.
            // `variant_id` is None in base-mode.
            let mut variant_resolution_error = None;
            let variant_id: Option<String> = if ch.surface.variants.is_empty() {
                if let Some(alias) = virtual_channel_alias.as_deref() {
                    warn!(
                        surface = %ch.surface.name,
                        requested_alias = %alias,
                        "Channel has no variants — alias in path is ignored, routing to base surface"
                    );
                    variant_resolution_error = Some(
                        crate::config::agent_surface_variants::VariantResolveError::UnknownAlias(alias.to_string()),
                    );
                } else if let Some(id) = ch
                    .surface
                    .default_variant_id
                    .as_deref()
                {
                    variant_resolution_error =
                        Some(crate::config::agent_surface_variants::VariantResolveError::MisconfiguredDefault(
                            id.to_string(),
                        ));
                }
                None
            } else {
                let candidate = if let Some(alias) = virtual_channel_alias.as_deref() {
                    ch.surface
                        .variants
                        .iter()
                        .find(|v| v.alias == alias)
                        .map(|v| v.id.clone())
                } else {
                    ch.surface
                        .default_variant_id
                        .clone()
                };

                match candidate {
                    Some(id) => Some(id),
                    None => {
                        if let Some(alias) = virtual_channel_alias.as_deref() {
                            error!(
                                surface = %ch.surface.name,
                                config_id = ?ch.surface.config_id(),
                                requested_alias = %alias,
                                available_variants = ?ch.surface.variants.iter().map(|v| &v.alias).collect::<Vec<_>>(),
                                "❌ ROUTING FAILED: Virtual channel alias not found"
                            );
                            return create_error_response(
                                StatusCode::BAD_REQUEST,
                                &format!("Virtual channel alias '{}' not found for this channel", alias),
                            );
                        } else {
                            // No alias in path and no default_variant_id
                            // configured → route to the bare base surface
                            // (base is the implicit default). variant_id =
                            // None drops into channel-level engine handling
                            // below.
                            debug!(
                                surface = %ch.surface.name,
                                "Alias-less request, no default_variant_id — routing to base surface"
                            );
                            None
                        }
                    }
                }
            };

            // Check if variant exists and is enabled (only in variant-mode)
            if let Some(ref vid) = variant_id {
                let variant = match ch
                    .surface
                    .variants
                    .iter()
                    .find(|v| &v.id == vid)
                {
                    Some(v) => v,
                    None => {
                        error!(
                            surface = %ch.surface.name,
                            config_id = ?ch.surface.config_id(),
                            variant_id = %vid,
                            "❌ ROUTING FAILED: Variant ID not found in channel's variants list"
                        );
                        return create_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Selected variant not found in channel configuration",
                        );
                    }
                };

                if !variant.enabled {
                    warn!(
                        surface = %ch.surface.name,
                        variant_id = %vid,
                        variant_alias = %variant.alias,
                        "❌ Virtual channel variant is DISABLED"
                    );
                    return create_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("Virtual channel variant '{}' is disabled", variant.alias),
                    );
                }

                info!(
                    "✓ Using virtual channel variant '{}' (alias: '{}') for channel '{}'",
                    vid, variant.alias, ch.surface.name
                );
            }

            // Phase D — prefer the pre-resolved snapshot from
            // `MultiSurfaceProxyState.resolved_surface_cache`, which is
            // populated by `apply_surface_change` whenever a surface is
            // saved. Falls back to resolving the variant from the
            // channel's mirror surface when the cache has no entry
            // (e.g. a legacy JSON-config channel that never came from a
            // surface, or a startup race before seeding). The mirror
            // surface is built by `AgentSurface::from_channel_mapping`,
            // whose `variants[]` projection (see
            // `virtual_channel_to_surface_variant`) carries every
            // per-variant field that `apply_variant_overrides` would
            // write, so `resolve_variant` returns an equivalent
            // surface.
            let resolved_surface = {
                let cache_lookup = ch
                    .surface
                    .config_id()
                    .and_then(|sid| {
                        state
                            .resolved_surface_cache
                            .resolve(sid, virtual_channel_alias.as_deref())
                            .ok()
                    });
                if let Some(snap) = cache_lookup {
                    snap
                } else {
                    match ch
                        .surface
                        .resolve_variant(virtual_channel_alias.as_deref())
                    {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            error!(
                                surface = %ch.surface.name,
                                config_id = ?ch.surface.config_id(),
                                requested_alias = ?virtual_channel_alias,
                                error = %e,
                                "❌ VARIANT RESOLVE FAILED on surface mirror"
                            );
                            return create_error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to resolve virtual channel variant",
                            );
                        }
                    }
                }
            };

            // Select the correct engines. In base-mode (variant_id == None) we
            // use channel-level engines and resolve to the base surface.
            // Otherwise we use the pre-compiled per-variant engines.
            let (
                identity_rules_engine,
                identity_selector,
                protected_rules_engine,
                protected_selector,
                external_rules_engine,
                external_selector,
            ) = if let Some(ref vid) = variant_id {
                if let Some(variant_engines) = ch.variant_engines.get(vid) {
                    info!("✓ Using pre-compiled engines for variant '{}' on channel '{}'", vid, ch.surface.name);
                    (
                        variant_engines
                            .identity_rules_engine
                            .clone(),
                        variant_engines
                            .identity_selector
                            .clone(),
                        variant_engines
                            .protected_rules_engine
                            .clone(),
                        variant_engines
                            .protected_selector
                            .clone(),
                        variant_engines
                            .external_rules_engine
                            .clone(),
                        variant_engines
                            .external_selector
                            .clone(),
                    )
                } else {
                    error!(
                        surface = %ch.surface.name,
                        config_id = ?ch.surface.config_id(),
                        variant_id = %vid,
                        compiled_variants = ?ch.variant_engines.keys().collect::<Vec<_>>(),
                        "❌ ENGINE LOOKUP FAILED: Variant selected but not found in pre-compiled variant engines. This should never happen if channel validation passed."
                    );
                    return create_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Selected virtual channel variant has no compiled engines. This is a configuration error.",
                    );
                }
            } else {
                info!("✓ Using channel-level engines (base-mode) for channel '{}'", ch.surface.name);
                (
                    ch.identity_rules_engine
                        .clone(),
                    ch.identity_selector.clone(),
                    ch.protected_rules_engine
                        .clone(),
                    ch.protected_selector.clone(),
                    ch.external_rules_engine
                        .clone(),
                    ch.external_selector.clone(),
                )
            };

            // Create single-channel ProxyState for this request with effective channel and variant engines
            let proxy_state = ProxyState {
                config: state.config.clone(),
                network_config: state.network_config.clone(),
                client: state.client.clone(),
                metrics_store: state.metrics_store.clone(),
                identity_rules_engine,
                identity_selector,
                protected_rules_engine,
                protected_selector,
                external_rules_engine,
                external_selector,
                task_monitor: state.task_monitor.clone(),
                task_id: Some(ch.task_id.clone()),
                ws_state: state.ws_state.clone(),
                listener_manager: state.listener_manager.clone(),
                secrets_store: state.secrets_store.clone(),
                certificates_store: state
                    .certificates_store
                    .clone(),
                policy_manager: state.policy_manager.clone(),
                gateway_policy_manager: state
                    .gateway_policy_manager
                    .clone(),
                didauth_session_store: state
                    .didauth_session_store
                    .clone(),
                transaction_store: state
                    .transaction_store
                    .clone(),
                mpp_transaction_store: state
                    .mpp_transaction_store
                    .clone(),
                trust_registry_listener_manager: state
                    .trust_registry_listener_manager
                    .clone(),
                source_auth_middleware: state
                    .source_auth_middleware
                    .clone(),

                #[cfg(feature = "didwebvh")]
                didwebvh_identity_store: state
                    .didwebvh_identity_store
                    .clone(),

                #[cfg(feature = "didwebvh")]
                didwebvh_log_manager: state
                    .didwebvh_log_manager
                    .clone(),

                credential_provider_store: state
                    .credential_provider_store
                    .clone(),
                delegation_vault_store: state
                    .delegation_vault_store
                    .clone(),
                gateway_base_url: state.gateway_base_url.clone(),
                transit_token_issuer: state
                    .transit_token_issuer
                    .clone(),
                mcp_proxy_store: state.mcp_proxy_store.clone(),
                a2a_proxy_store: state.a2a_proxy_store.clone(),
                vc_issuer: state.vc_issuer.clone(),
                active_variant_alias: virtual_channel_alias.clone(),
                active_variant_id: variant_id,
                variant_resolution_error,
                surface: resolved_surface,
            };

            // The route + optional `$alias` suffix have already been stripped
            // by `parse_route_with_variant` above; `stripped_tail` is the
            // upstream-facing remainder (always either empty or starting with '/').
            let stripped_path = route_tail_to_uri_path(&stripped_tail);

            // Rebuild the request with the stripped path
            let (mut parts, body) = req.into_parts();

            let new_uri = if let Some(q) = query {
                format!("{}?{}", stripped_path, q)
            } else {
                stripped_path.clone()
            };

            debug!(
                "Rewriting URI: original='{}' new='{}' (stripped route '{}' alias={:?})",
                path,
                new_uri,
                ch.surface.route(),
                virtual_channel_alias
            );

            let parsed_uri = match new_uri.parse() {
                Ok(uri) => uri,
                Err(e) => {
                    error!("Failed to parse stripped URI: {}", e);
                    return create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to process request path");
                }
            };
            parts.uri = parsed_uri;

            let new_req = Request::from_parts(parts, body);

            // Forward to the single-channel proxy handler
            let channel_config_id = ch
                .surface
                .config_id()
                .unwrap_or("unknown");
            // Install the per-request policy-decision collector so OPA decisions
            // pushed inside `proxy_handler_with_mcp_runtime` are visible to the VP injectors
            // when they read POLICY_DECISION_COLLECTOR to embed policyDecisions in the VP.
            let policy_collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::<
                crate::observability::policy_audit::PolicyDecisionSummary,
            >::new()));
            let result = Box::pin(crate::observability::policy_audit::POLICY_DECISION_COLLECTOR.scope(
                policy_collector,
                proxy_handler_with_mcp_runtime(addr, proxy_state, new_req, mcp_versions, mcp_continuations),
            ))
            .await;
            match result {
                Ok(response) => {
                    channel_info!(
                        channel_config_id,
                        "✅ MULTI_CHANNEL_HANDLER: Received success response with status {}",
                        response.status()
                    );
                    response
                }
                Err(error_response) => {
                    let status = error_response.status();
                    // The downstream error response is typically `application/problem+json`
                    // (RFC 7807) — for identity-slot failures it carries `code`, `slot`,
                    // `channel`, `detail`. Decompose it so the gateway log mirrors what the
                    // caller actually receives instead of just the bare HTTP status.
                    let (parts, body) = error_response.into_parts();
                    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
                        Ok(b) => b,
                        Err(_) => bytes::Bytes::new(),
                    };
                    let detail = decode_error_body_for_log(&parts.headers, &body_bytes);
                    if status.is_server_error() {
                        channel_error!(
                            channel_config_id,
                            "❌ MULTI_CHANNEL_HANDLER: Received error response with status {}{}",
                            status,
                            detail
                        );
                    } else {
                        channel_warn!(
                            channel_config_id,
                            "⚠️ MULTI_CHANNEL_HANDLER: Received error response with status {}{}",
                            status,
                            detail
                        );
                    }
                    Response::from_parts(parts, axum::body::Body::from(body_bytes))
                }
            }
        }
        None => {
            // No matching channel found for this route
            warn!("No channel found for path: {} (checked {} channels)", path, channels.len());
            for ch in channels.iter() {
                warn!("  Available: surface='{}' route='{}'", ch.surface.name, ch.surface.route());
            }
            create_error_response(StatusCode::NOT_FOUND, &format!("No route configured for path: {}", path))
        }
    }
}

// Helper functions

/// Format an error response body as a human-readable tail for the gateway log
/// (e.g. ` | code=identity_did_failed | slot=protected_identity | channel=MCP Testkit 1 | detail=...`).
/// Recognizes RFC 7807 `application/problem+json` (which our `create_identity_error_response`
/// emits) and JSON-RPC error envelopes. Returns an empty string when the body is
/// not JSON or carries no useful fields, so the caller can append it unconditionally.
fn decode_error_body_for_log(
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> String {
    if body.is_empty() {
        return String::new();
    }
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.contains("json") {
        return String::new();
    }
    let json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    // JSON-RPC envelope: { "error": { "code", "message", "data": {...} } }
    let (root, jsonrpc_code) = if let Some(err) = json.get("error") {
        (
            err,
            json.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_i64()),
        )
    } else {
        (&json, None)
    };

    let mut parts: Vec<String> = Vec::new();
    let pick = |obj: &serde_json::Value, key: &str| -> Option<String> {
        obj.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    if let Some(code) = pick(root, "code") {
        parts.push(format!("code={}", code));
    }
    if let Some(slot) = pick(root, "slot") {
        parts.push(format!("slot={}", slot));
    }
    if let Some(channel) = pick(root, "channel") {
        parts.push(format!("channel={}", channel));
    }
    if let Some(title) = pick(root, "title") {
        parts.push(format!("title={}", title));
    }
    if let Some(detail) = pick(root, "detail") {
        parts.push(format!("detail={}", detail));
    } else if let Some(message) = pick(root, "message") {
        parts.push(format!("message={}", message));
    }
    // JSON-RPC `error.data` may carry the same fields under a sub-object.
    if let Some(data) = root.get("data")
        && data.is_object()
    {
        for k in ["code", "gateway_code", "slot", "channel", "detail"] {
            if !parts
                .iter()
                .any(|p| p.starts_with(&format!("{}=", k)))
                && let Some(v) = pick(data, k)
            {
                parts.push(format!("{}={}", k, v));
            }
        }
    }
    if let Some(c) = jsonrpc_code {
        parts.push(format!("jsonrpc={}", c));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" | {}", parts.join(" | "))
    }
}

fn handle_upstream_error(
    e: reqwest::Error,
    state: &ProxyState,
    source_addr: &str,
    identity_hash: &Option<String>,
    channel_name: &str,
    ucp_operation: &Option<String>,
) -> Response {
    // Check if this is a placeholder/example domain that's expected to fail
    let is_example_domain = state
        .surface
        .target
        .endpoint
        .contains("example.com")
        || state
            .surface
            .target
            .endpoint
            .contains("placeholder.")
        || state
            .surface
            .target
            .endpoint
            .contains("your-domain.com");

    // Provide more specific error messages based on the error type
    let error_message = if e.is_connect() {
        if e.to_string().contains("dns")
            || e.to_string()
                .contains("resolve")
        {
            if is_example_domain {
                format!(
                    "Target endpoint '{}' uses a placeholder domain that doesn't resolve. Please configure a valid endpoint in your channel settings.",
                    state.surface.target.endpoint
                )
            } else {
                format!(
                    "DNS resolution failed for target endpoint '{}'. Please check that the hostname is valid and resolvable.",
                    state.surface.target.endpoint
                )
            }
        } else if e
            .to_string()
            .contains("timeout")
        {
            format!(
                "Connection timeout to target endpoint '{}'. The server may be unavailable or slow to respond.",
                state.surface.target.endpoint
            )
        } else {
            format!("Connection failed to target endpoint '{}': {}", state.surface.target.endpoint, e)
        }
    } else if e.is_timeout() {
        format!(
            "Request timeout to target endpoint '{}'. The server did not respond within the configured timeout period.",
            state.surface.target.endpoint
        )
    } else {
        format!("Failed to forward request to target endpoint '{}': {}", state.surface.target.endpoint, e)
    };

    error!(channel = channel_name, error = %e, target = %state.surface.target.endpoint, "Failed to forward request to upstream - bad gateway");

    // Record gateway fault in metrics
    if let Some(ref metrics) = state.metrics_store {
        let metrics = Arc::clone(metrics);
        let channel_config_id = state
            .surface
            .surface_id
            .clone();
        let source = source_addr.to_string();
        let dest = state
            .surface
            .target
            .endpoint
            .clone();
        let hash = identity_hash.clone();
        let ucp_op = ucp_operation.clone();
        let variant_alias = state
            .active_variant_alias
            .clone();
        tokio::spawn(async move {
            metrics
                .record_connection_with_ucp(
                    channel_config_id,
                    source,
                    dest,
                    crate::metrics::ConnectionStatus::GatewayFault,
                    None,
                    hash,
                    crate::metrics::ConnectionDirection::Request,
                    uuid::Uuid::new_v4().to_string(),
                    ucp_op,
                    None,
                    None,
                    0,
                    variant_alias,
                )
                .await;
        });
    }

    // Track error and mark channel as broken if target endpoint is unreachable
    if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
        let task_id = task_id.clone();
        let monitor = task_monitor.clone();
        let is_connection_error = e.is_connect();
        tokio::spawn(async move {
            monitor
                .increment_errors(&task_id)
                .await;

            // Mark channel as error status if this is a connection failure
            if is_connection_error {
                monitor
                    .update_status(&task_id, crate::observability::TaskStatus::Error)
                    .await;
                info!(task_id = %task_id, "Marking channel as error status due to target endpoint connection failure");
            }
        });
    }

    // Use 503 Service Unavailable for placeholder domains, 502 Bad Gateway for real connection failures
    let status_code = if is_example_domain {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_GATEWAY
    };
    create_error_response(status_code, &error_message)
}

async fn handle_onboarding_request(
    _state: ProxyState,
    channel_name: &str,
    method: Method,
    uri: axum::http::Uri,
    _headers: HeaderMap,
    _source_addr: String,
    _start_time: std::time::Instant,
    mut connection_guard: ConnectionGuard,
    _req: Request,
) -> Result<Response, Response> {
    info!(channel = channel_name, method = %method, path = %uri.path(), "Onboarding channel detected");

    // Onboarding handler implementation would go here - this is a simplified version
    // The full implementation is quite long (lines 1438-1695 in original file)
    // For now, returning a placeholder

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Body::from("Onboarding channel"))
        .unwrap();
    connection_guard
        .decrement()
        .await;
    Ok(response)
}

/// Fetch an agent card from `<base_url>/.well-known/agent-card.json` (then
/// `/.well-known/agent.json` as fallback).
///
/// `base_url` must include the scheme (e.g. `https://gw.example.com/route`).
/// A non-2xx status or a JSON parse error is treated as final — only
/// **transport-level** failures (connection error, TLS handshake) on the
/// first well-known path trigger the fallback to the second path.
///
/// Returns `Some(card)` on success or `None` on failure.
async fn fetch_agent_card(
    client: &reqwest::Client,
    base_url: &str,
    channel_id: &str,
    limits: crate::proxy::upstream_body::UpstreamBodyLimits,
) -> Option<serde_json::Value> {
    let base = base_url.trim_end_matches('/');
    let urls = [format!("{}/.well-known/agent-card.json", base), format!("{}/.well-known/agent.json", base)];

    for url in &urls {
        info!(channel = channel_id, "GW1 fabric: [Target mode] Fetching agent card from: {}", url);
        match client.get(url).send().await {
            Ok(resp) => {
                info!(channel = channel_id, "GW1 fabric: Agent card fetch HTTP status: {}", resp.status());
                if resp.status().is_success() {
                    let body = match crate::proxy::upstream_body::read_bounded(resp, limits).await {
                        Ok(body) => body,
                        Err(e) => {
                            warn!(
                                channel = channel_id,
                                "GW1 fabric: Agent card exceeded its bounds (url={}): {}", url, e
                            );
                            return None;
                        }
                    };
                    match serde_json::from_slice::<serde_json::Value>(&body) {
                        Ok(card) => {
                            info!(
                                channel = channel_id,
                                "GW1 fabric: Agent card fetched successfully (url={}): name={:?} endpoint={:?}",
                                url,
                                card.get("name"),
                                // Reads either era: a pure-1.0 card has no top-level
                                // `url`, only `supportedInterfaces[]`.
                                crate::a2a::url_rewriter::primary_endpoint_url(&card)
                            );
                            return Some(card);
                        }
                        Err(e) => {
                            // JSON parse failure — no value in retrying with http
                            warn!(
                                channel = channel_id,
                                "GW1 fabric: Failed to parse agent card JSON (url={}): {}", url, e
                            );
                            return None;
                        }
                    }
                } else {
                    // HTTP-level error — no value in retrying with http
                    warn!(
                        channel = channel_id,
                        "GW1 fabric: Agent card fetch non-success status (url={}): {}",
                        url,
                        resp.status()
                    );
                    return None;
                }
            }
            Err(e) => {
                warn!(channel = channel_id, "GW1 fabric: Agent card fetch request failed (url={}): {}", url, e);
                // Transport-level failure — try the next well-known path
            }
        }
    }
    None
}

/// Resolves the caller identity configured on the surface's inbound (or
/// managed) identity slot for the modes whose DID comes from a stored
/// credential (cert / API key) or a configured static DID rather than the
/// request body: `static`, `from_mtls` and `from_api_key`.
/// `derive_credential_identity` returns `Bound` for `Static` and pre-bound
/// certs, and `Derived` for `FromMtls` / `FromApiKey`.
///
/// Returns `Ok(None)` for other modes and on public/discovery paths, where
/// source auth, Trust Check and surface OPA are bypassed (mirroring the
/// `from_jwt_claim` resolution). A credential that cannot be derived is a
/// `502` error response.
async fn resolve_configured_caller_identity(
    state: &ProxyState,
    method: &str,
    path: &str,
    channel_name: &str,
    leg: &'static str,
) -> Result<Option<crate::identity::IdentityResult>, Response> {
    use crate::identity::credential_identity::CredentialIdentity;
    use crate::source_auth::ManagedIdentityConfig;

    if crate::proxy::paths::is_public_request(method, path) {
        return Ok(None);
    }
    let Some(mi) = state
        .surface
        .inbound_identity()
        .cloned()
        .or_else(|| {
            state
                .surface
                .managed_identity()
        })
    else {
        return Ok(None);
    };
    if !matches!(
        mi,
        ManagedIdentityConfig::FromMtls { .. }
            | ManagedIdentityConfig::FromApiKey { .. }
            | ManagedIdentityConfig::Static { .. }
    ) {
        return Ok(None);
    }

    let derived = crate::identity::credential_identity::derive_credential_identity(
        &mi,
        state
            .certificates_store
            .as_ref(),
        state.secrets_store.as_ref(),
    )
    .await;
    let identity = match derived {
        Ok(Some(CredentialIdentity::Bound { did, identity_fields })) => {
            info!(channel = channel_name, leg, did = %did, "Inbound credential identity resolved (pre-bound)");
            crate::identity::IdentityResult {
                verification: mi.caller_verification(),
                hash: String::new(),
                did,
                is_new: false,
                identity_fields,
                issuer_did: None,
            }
        }
        Ok(Some(CredentialIdentity::Derived { identity_fields, identity_hash })) => {
            let Some(issuer) = state
                .identity_selector
                .as_ref()
                .map(|s| s.get_vc_issuer())
                .or_else(|| state.vc_issuer.clone())
            else {
                debug!(
                    channel = channel_name,
                    leg, "Inbound credential identity: VCIssuer not configured — DID issuance skipped"
                );
                return Ok(None);
            };
            let issued = issuer
                .issue_or_get_caller_credential(
                    identity_fields.clone(),
                    Some(identity_hash.clone()),
                    state
                        .surface
                        .config_id()
                        .map(String::from),
                    state
                        .surface
                        .issuer_id
                        .clone(),
                )
                .await;
            let response = match issued {
                Ok(response) => response,
                Err(e) => {
                    warn!(channel = channel_name, leg, error = %e, "Failed to issue DID for inbound credential-based identity");
                    return Ok(None);
                }
            };
            if response.is_new {
                info!(channel = channel_name, leg, did = %response.did, "Created new DID for inbound credential-based identity");
            } else {
                debug!(channel = channel_name, leg, did = %response.did, "Resolved existing DID for inbound credential-based identity");
            }
            crate::identity::IdentityResult {
                verification: mi.caller_verification(),
                hash: identity_hash,
                did: response.did,
                is_new: response.is_new,
                identity_fields,
                issuer_did: None,
            }
        }
        Ok(None) => return Ok(None),
        Err(e) => {
            warn!(channel = channel_name, leg, error = %e, "Failed to derive inbound credential-based identity");
            return Err(create_error_response(
                StatusCode::BAD_GATEWAY,
                &format!("VCIssuer failure during identity resolution: {e}"),
            ));
        }
    };
    Ok(Some(identity))
}

/// Handle requests through the fabric:// protocol by forwarding via gateway
async fn handle_fabric_request(
    state: ProxyState,
    channel_name: &str,
    method: Method,
    uri: axum::http::Uri,
    mut headers: HeaderMap,
    source_addr: String,
    start_time: std::time::Instant,
    mut connection_guard: ConnectionGuard,
    body_bytes: axum::body::Bytes,
    trace_id: String,
    ucp_operation: Option<String>,
    authenticated_identity: Option<crate::source_auth::AuthenticatedIdentity>,
    source_auth_context: Option<crate::surface_context::SourceAuthContext>,
    payment_context: Option<crate::surface_context::PaymentContext>,
    mcp_metadata_context: crate::mcp::meta::McpMetadataContext,
    mcp_verified_binding: Option<crate::surface_context::IdentityBindingContext>,
    mcp_classification: Option<&crate::mcp::request_validation::McpRequestClassification>,
    subscription_lifetime: Option<crate::mcp::subscriptions::SubscriptionLifetime>,
    mcp_continuations: Option<Arc<crate::mcp::continuations::config::ContinuationRuntime>>,
) -> Result<Response, Response> {
    let modern_mcp_context = mcp_classification.and_then(crate::mcp::modern_mcp_context);
    let mut modern_request = match mcp_classification {
        Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) => Some((**request).clone()),
        _ => None,
    };
    let config_id = state
        .surface
        .surface_id
        .as_str();

    channel_info!(config_id, "🏭 Handling fabric protocol request");

    // Egress trace id for the fabric hop: keep the incoming `trace_id` for this
    // gateway's own VP + audit, but forward a fresh id in the fabric message +
    // caller binding VP when the surface terminates traces, so the downstream
    // gateway starts a new trace.
    let egress_trace_id = crate::proxy::trace::egress_trace_id(
        state
            .surface
            .access_point
            .terminate_trace_id,
        &trace_id,
    );

    // Bridge for this gateway's operator: when the trace is terminated, record the
    // own → downstream mapping here (stays local; the remote gateway only ever sees
    // the downstream id). Lets the operator follow the request past the boundary
    // without leaking the incoming trace across it. Skipped on public/discovery
    // paths (agent-card fetch, `.well-known/*`) — those carry no caller identity and
    // bypass OPA/VP injection, so a bridge record for them is only noise (matching
    // the discovery bypass every other stage already applies).
    if egress_trace_id != trace_id && !crate::proxy::paths::is_public_request(method.as_str(), uri.path()) {
        channel_info!(
            config_id,
            "🔀 Trace terminated at egress: own trace {} continues downstream as {}",
            trace_id,
            egress_trace_id
        );
        crate::delegation_vault::audit::audit_trace_terminated(
            Some(config_id),
            &trace_id,
            &egress_trace_id,
            "fabric",
            true,
        );
    }

    // Log the incoming URI details
    channel_debug!(config_id, "📍 Incoming URI: {}", uri);
    channel_debug!(config_id, "  ↳ Path: {:?}", uri.path());
    channel_debug!(config_id, "  ↳ Query: {:?}", uri.query());
    channel_debug!(config_id, "  ↳ Path and Query: {:?}", uri.path_and_query());

    // Parse fabric://{gateway_id}/{channel_id}
    let fabric_path = &state.surface.target.endpoint[9..]; // Remove "fabric://"
    let parts: Vec<&str> = fabric_path
        .split('/')
        .collect();

    if parts.len() < 2 {
        channel_error!(config_id, "Invalid fabric URL format: {}", state.surface.target.endpoint);
        connection_guard
            .decrement()
            .await;
        return Err(create_error_response(
            StatusCode::BAD_REQUEST,
            "Invalid fabric URL format. Expected: fabric://{gateway_id}/{channel_id}",
        ));
    }

    let gateway_id = parts[0];
    let channel_id = parts[1];

    channel_info!(config_id, "Fabric - forwarding to gateway {} channel {}", gateway_id, channel_id);

    // Get listener manager from state (read from RwLock)
    let listener_mgr = state
        .listener_manager
        .read()
        .await
        .clone()
        .ok_or_else(|| {
            channel_error!(config_id, "Listener manager not available");
            create_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway forwarding not available - listener manager not initialized",
            )
        })?;

    // Get the gateway listener (WebSocket connection)
    let gateway_listener = listener_mgr
        .get_listener(gateway_id)
        .await
        .ok_or_else(|| {
            channel_warn!(config_id, "No active listener found for gateway {}", gateway_id);
            create_error_response(StatusCode::SERVICE_UNAVAILABLE, "Gateway not connected")
        })?;

    // Get the remote gateway's DID
    let remote_gateway_did = listener_mgr
        .get_gateway_did(gateway_id)
        .await
        .ok_or_else(|| {
            channel_error!(config_id, "Could not find DID for gateway {}", gateway_id);
            create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gateway DID not found")
        })?;

    channel_debug!(config_id, "Remote gateway DID: {}", remote_gateway_did);

    // Body already extracted in caller for payment verification
    let mut body_bytes = body_bytes; // Make mutable for modifications below
    channel_info!(config_id, "📦 FABRIC: Using request body - {} bytes", body_bytes.len());
    if body_bytes.is_empty() {
        channel_warn!(config_id, "⚠️ FABRIC: Request body is EMPTY!");
    }

    let fabric_target_url = uri.path().to_string();

    // ── Extract and verify inbound identity binding VP (from upstream gateway) ──
    // This is the HTTP-facing path: the request has no authenticated fabric
    // sender (`x-affinidi-fabric-gateway-did` is a caller-writable header, not
    // an anchor), so the issuer is exposed to OPA instead of being pinned.
    let binding_result = if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
    {
        Ok(mcp_verified_binding)
    } else {
        let result = crate::protocols::extensions::extract_identity_binding_vp(
            &body_bytes,
            &state
                .surface
                .channel_protocol(),
            &state.identity_selector,
            channel_name,
            None,
        )
        .await;
        crate::observability::identity_binding_audit::audit_extraction(&state.surface.surface_id, None, &result);
        result
    };
    let identity_binding = match binding_result {
        Ok(binding) => binding,
        Err(e) => {
            channel_warn!(config_id, "Identity binding VP present but invalid error={}", e);
            None
        }
    };

    // ── Inbound identity resolution — fabric path ────────────────────────
    //
    // Extension inspection + credential-derived + JWT-claim identity
    // resolution all run HERE (before both surface OPA gates) so the fabric
    // inbound gate below sees the same `PolicyInput` shape as the direct
    // inbound gate (source auth, agent, MCP, A2A, extension identity,
    // payment, identity binding). Mirrors the direct-path order.
    let mut identity_result: Option<crate::identity::IdentityResult> = None;

    if state
        .config
        .extension_inspection
        .enabled
        && method == Method::POST
        && !body_bytes.is_empty()
        && matches!(
            state
                .surface
                .channel_protocol(),
            crate::config::ChannelProtocol::A2a
                | crate::config::ChannelProtocol::Ap2
                | crate::config::ChannelProtocol::Mcp
        )
    {
        let inspection_span = tracing::info_span!(
            "channel.extension_inspection",
            otel.name = "Extension Inspection",
            channel = channel_name
        );
        let inspection_ctx = crate::a2a::ExtensionInspectionContext {
            config: &state.config,
            channel_name,
            surface: &state.surface,
            rules_engine: &state.identity_rules_engine,
            identity_selector: &state.identity_selector,
            source_authenticated: authenticated_identity.is_some(),
            metrics_store: &state.metrics_store,
            ws_state: &state.ws_state,
            variant_alias: state
                .active_variant_alias
                .as_deref(),
        };
        match async { inspect_message_extensions(&body_bytes, &inspection_ctx).await }
            .instrument(inspection_span)
            .await
        {
            Ok(identity) => {
                channel_debug!(config_id, "Extension inspection passed in fabric path");
                identity_result = identity;
            }
            Err(response) => {
                channel_warn!(config_id, "✗ Fabric path inbound identity check rejected request");
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
    }

    // ── Configured caller identity (FromMtls / FromApiKey / Static) ─────────
    if identity_result.is_none() {
        match resolve_configured_caller_identity(&state, method.as_str(), uri.path(), channel_name, "fabric").await {
            Ok(resolved) => identity_result = resolved,
            Err(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
    }

    // ── Request-bound identity resolution (FromJwtClaim) — fabric path ────
    //
    // `from_jwt_claim` on the inbound slot derives the *caller* agent's DID
    // from a validated JWT claim (e.g. the Entra Agent ID `oid`) produced by
    // `jwt_bearer` source auth, then feeds the same `identity_result` so the
    // caller's identity VP is forwarded across the fabric hop to the remote
    // gateway (mirrors the direct path).
    //
    // Skipped on public/discovery paths (`is_public_path`): source auth is
    // bypassed there, so no JWT claims exist and there is no caller identity to
    // resolve — mirrors the Trust Check and surface OPA discovery bypasses.
    if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && identity_result.is_none()
        && let Some(crate::source_auth::ManagedIdentityConfig::FromJwtClaim { claim, namespace_claims }) = state
            .surface
            .inbound_identity()
    {
        let mode_label = "from_jwt_claim";
        let started = std::time::Instant::now();
        let Some(claims) = authenticated_identity
            .as_ref()
            .and_then(|i| i.jwt_claims())
        else {
            crate::metrics::backends::prometheus::track_managed_identity_resolve(
                channel_name,
                mode_label,
                "jwt_claims_unavailable",
                started
                    .elapsed()
                    .as_secs_f64(),
            );
            connection_guard
                .decrement()
                .await;
            return Err(create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "from_jwt_claim requires jwt_bearer source auth on this surface",
            ));
        };
        match crate::identity::credential_identity::resolve_jwt_claim_identity(claim, namespace_claims, claims) {
            Ok(crate::identity::credential_identity::CredentialIdentity::Derived {
                identity_fields,
                identity_hash,
            }) => {
                let vc_issuer_opt = state
                    .identity_selector
                    .as_ref()
                    .map(|s| s.get_vc_issuer())
                    .or_else(|| state.vc_issuer.clone());
                let Some(issuer) = vc_issuer_opt else {
                    crate::metrics::backends::prometheus::track_managed_identity_resolve(
                        channel_name,
                        mode_label,
                        "vc_issuer_missing",
                        started
                            .elapsed()
                            .as_secs_f64(),
                    );
                    connection_guard
                        .decrement()
                        .await;
                    return Err(create_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "from_jwt_claim requires a configured VC issuer",
                    ));
                };
                match issuer
                    .issue_or_get_caller_credential(
                        identity_fields.clone(),
                        Some(identity_hash.clone()),
                        state
                            .surface
                            .config_id()
                            .map(String::from),
                        state
                            .surface
                            .issuer_id
                            .clone(),
                    )
                    .await
                {
                    Ok(response) => {
                        crate::metrics::backends::prometheus::track_managed_identity_resolve(
                            channel_name,
                            mode_label,
                            if response.is_new {
                                "ok_new"
                            } else {
                                "ok_cached"
                            },
                            started
                                .elapsed()
                                .as_secs_f64(),
                        );
                        info!(
                            channel = channel_name,
                            did = %response.did,
                            is_new = response.is_new,
                            "Resolved inbound agent DID from JWT claim on fabric path"
                        );
                        identity_result = Some(crate::identity::IdentityResult {
                            verification: crate::surface_context::IdentityVerification::SourceAuth,
                            hash: identity_hash,
                            did: response.did,
                            is_new: response.is_new,
                            identity_fields,
                            issuer_did: None,
                        });
                    }
                    Err(e) => {
                        crate::metrics::backends::prometheus::track_managed_identity_resolve(
                            channel_name,
                            mode_label,
                            "vc_issuer_error",
                            started
                                .elapsed()
                                .as_secs_f64(),
                        );
                        connection_guard
                            .decrement()
                            .await;
                        return Err(create_error_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("VCIssuer failure during from_jwt_claim resolution: {e}"),
                        ));
                    }
                }
            }
            Ok(_) => unreachable!("resolve_jwt_claim_identity only returns Derived"),
            Err(e) => {
                let result_label = match &e {
                    crate::identity::credential_identity::CredentialIdentityError::JwtClaimMissing(_) => {
                        "jwt_claim_missing"
                    }
                    _ => "jwt_claim_error",
                };
                crate::metrics::backends::prometheus::track_managed_identity_resolve(
                    channel_name,
                    mode_label,
                    result_label,
                    started
                        .elapsed()
                        .as_secs_f64(),
                );
                connection_guard
                    .decrement()
                    .await;
                return Err(create_error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("from_jwt_claim could not derive identity: {e}"),
                ));
            }
        }
    }

    // Build ExtensionIdentityContext from the resolved identity_result so the
    // inbound OPA gate sees the same `input.extension_identity` shape as the
    // direct path.
    let extension_identity = identity_result
        .as_ref()
        .map(|result| crate::surface_context::ExtensionIdentityContext {
            verification: result.verification,
            did: Some(result.did.clone()),
            identity_hash: Some(result.hash.clone()),
        });

    // Access-Point Inbound OPA Policy check (fabric:// path).
    //
    // Mirrors the direct-HTTP inbound gate: runs BEFORE the target-side
    // surface OPA gate, independent of `state.surface.opa_enabled()`, so a
    // variant override of `access_point.inbound_policy` can deny a fabric
    // G2G request before any target-side processing.
    //
    // Fail-closed: the gate enters purely on `inbound_opa_enabled()` — a
    // missing policy manager or a policy that failed to load/compile
    // returns 403 (matches the direct path).
    if !crate::proxy::paths::is_public_request(method.as_str(), uri.path())
        && state
            .surface
            .inbound_opa_enabled()
        && let Some(config_id_str) = state.surface.config_id()
    {
        let body_json: Option<serde_json::Value> = serde_json::from_slice(&body_bytes).ok();
        let body_ref = body_json.as_ref();

        let mcp_context: Option<crate::surface_context::McpContext> = if state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::Mcp
        {
            modern_mcp_context
                .clone()
                .or_else(|| crate::mcp::build_mcp_context(&body_bytes))
        } else {
            None
        };

        let a2a_context: Option<crate::surface_context::A2aContext> = if matches!(
            state
                .surface
                .channel_protocol(),
            crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2
        ) {
            body_ref.map(|body| {
                let a2a_method = body
                    .get("method")
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string());
                let message = body
                    .get("params")
                    .and_then(|p| p.get("message"))
                    .or_else(|| body.get("message"))
                    .cloned();
                crate::surface_context::A2aContext::new(a2a_method, message)
            })
        } else {
            None
        };

        let agent_ctx = if !state
            .surface
            .access_point
            .trust_check_list
            .is_empty()
        {
            Some(
                crate::policies::build_agent_context(
                    body_ref,
                    None,
                    state
                        .trust_registry_listener_manager
                        .as_deref(),
                    // Caller leg (GW2 fabric receive): skip the cross-check.
                    false,
                )
                .await,
            )
        } else {
            None
        };

        let mut policy_input = crate::surface_context::PolicyInput::new(
            method.as_ref(),
            uri.path(),
            crate::surface_context::filter_sensitive_headers(&headers),
            "inbound",
            None,
            None,
            state
                .surface
                .config_id()
                .map(|s| s.to_string()),
            &state.surface.name,
        );
        policy_input.source_auth = source_auth_context.clone();
        policy_input.agent = agent_ctx;
        policy_input.mcp = mcp_context;
        policy_input.a2a = a2a_context;
        policy_input.extension_identity = extension_identity.clone();
        policy_input.payment = payment_context.clone();
        policy_input.identity_binding = identity_binding.clone();
        let input_value = serde_json::to_value(&policy_input).unwrap_or_default();

        let request_agent_did = identity_result
            .as_ref()
            .map(|r| r.did.clone());

        let Some(policy_manager) = state.policy_manager.as_ref() else {
            channel_warn!(
                config_id_str,
                "Access-point inbound OPA policy is configured but policy manager is not available — denying request"
            );
            connection_guard
                .decrement()
                .await;
            return Err(axum::response::Response::builder()
                .status(axum::http::StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                ))
                .unwrap());
        };
        let inbound_policy_def_id = state
            .surface
            .inbound_opa_policy_definition_id();
        let (inbound_policy_name, inbound_policy_version, inbound_policy_hash) = policy_manager
            .resolve_policy_decision_evidence(inbound_policy_def_id)
            .await;
        match policy_manager.evaluate_inbound_policy_decision_for_variant(
            config_id_str,
            state
                .active_variant_alias
                .as_deref(),
            input_value,
        ) {
            Ok(decision) if decision.allow => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: true,
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: inbound_policy_def_id,
                    policy_name: Some(inbound_policy_name.as_str()),
                    policy_version: inbound_policy_version,
                    policy_content_hash: inbound_policy_hash.as_deref(),
                    surface_id: Some(config_id_str),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    actor_did: request_agent_did.as_deref(),
                    ..Default::default()
                });
            }
            Ok(decision) => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: false,
                    reason: decision.reason.as_deref(),
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: inbound_policy_def_id,
                    policy_name: Some(inbound_policy_name.as_str()),
                    policy_version: inbound_policy_version,
                    policy_content_hash: inbound_policy_hash.as_deref(),
                    surface_id: Some(config_id_str),
                    trace_id: Some(&trace_id),
                    http_method: Some(method.as_ref()),
                    path: Some(uri.path()),
                    identity: authenticated_identity.as_ref(),
                    actor_did: request_agent_did.as_deref(),
                    ..Default::default()
                });
                connection_guard
                    .decrement()
                    .await;
                if crate::mcp::is_tools_call_request(&body_bytes) {
                    return Err(crate::mcp::build_tools_call_policy_denied_response(
                        &body_bytes,
                        decision.reason.as_deref(),
                    ));
                }
                return Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                    ))
                    .unwrap());
            }
            Err(e) => {
                channel_warn!(
                    config_id_str,
                    "Fabric access-point inbound OPA policy evaluation error (denying request): {}",
                    e
                );
                connection_guard
                    .decrement()
                    .await;
                if crate::mcp::is_tools_call_request(&body_bytes) {
                    return Err(crate::mcp::build_tools_call_policy_denied_response(
                        &body_bytes,
                        Some("policy evaluation error"),
                    ));
                }
                return Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                    ))
                    .unwrap());
            }
        }
    }

    // Surface-Level OPA Policy check (fabric:// path)
    if state.surface.opa_enabled()
        && !(fabric_target_url.ends_with("/agent.json") || fabric_target_url.ends_with("/agent-card.json"))
        && state
            .policy_manager
            .as_ref()
            .is_some_and(|pm| {
                pm.has_policy_for_variant(
                    &state.surface.surface_id,
                    state
                        .active_variant_alias
                        .as_deref(),
                )
            })
    {
        let config_id_str = state
            .surface
            .surface_id
            .as_str();
        let body_json: Option<serde_json::Value> = serde_json::from_slice(&body_bytes).ok();
        let body_ref = body_json.as_ref();
        info!("GW1 fabric: Surface-level OPA policy, body JSON parse success: {}", body_json.is_some());
        // For fabric:// targets, fetch the agent card via the surface's
        // own access point URL (public path, bypasses auth) instead of
        // the unresolvable fabric:// target endpoint.
        let fabric_card_json = {
            let card_url = format!(
                "{}{}",
                state
                    .surface
                    .access_point
                    .listen_address
                    .trim_end_matches('/'),
                state
                    .surface
                    .access_point
                    .route,
            );
            info!(
                channel = config_id_str,
                fabric_target = %state.surface.target.endpoint,
                resolved_url = %card_url,
                "GW1 fabric: resolving agent card via access point listen address"
            );
            fetch_agent_card(
                &state.client,
                &card_url,
                config_id_str,
                crate::proxy::upstream_body::UpstreamBodyLimits::new(
                    state.config.a2a.max_body_size,
                    state.surface.timeout(),
                    state
                        .config
                        .a2a
                        .timeout_seconds,
                ),
            )
            .await
        };

        let agent_ctx = if fabric_card_json.is_some() {
            let agent_ctx = crate::policies::build_agent_context(
                body_ref,
                fabric_card_json.as_ref(),
                state
                    .trust_registry_listener_manager
                    .as_deref(),
                true,
            )
            .await;
            Some(agent_ctx)
        } else {
            None
        };

        let mut policy_input = crate::surface_context::PolicyInput::new(
            method.as_ref(),
            uri.path(),
            crate::surface_context::filter_sensitive_headers(&headers),
            "outbound",
            None,
            Some(remote_gateway_did.clone()),
            state
                .surface
                .config_id()
                .map(|s| s.to_string()),
            &state.surface.name,
        );
        policy_input.source_auth = source_auth_context.clone();
        policy_input.mcp = modern_mcp_context.clone();
        // [OPA-INPUT] Fabric surface policy input BEFORE agent/TR data
        info!(
            channel = config_id_str,
            "[OPA-INPUT] Fabric surface policy input before TR: {}",
            serde_json::to_string(&policy_input).unwrap_or_default()
        );
        policy_input.agent = agent_ctx;
        if matches!(
            state
                .surface
                .channel_protocol(),
            crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2
        ) && let Some(body) = body_ref
        {
            let method = body
                .get("method")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string());
            let message = body
                .get("params")
                .and_then(|p| p.get("message"))
                .or_else(|| body.get("message"))
                .cloned();
            policy_input.a2a = Some(crate::surface_context::A2aContext::new(method, message));
        }
        // ── Trust Check stage (target leg, fabric send) ──────────────────────
        {
            let target_elements = &state
                .surface
                .target
                .trust_check_list;
            if !target_elements.is_empty()
                && let Some(manager) = state
                    .trust_registry_listener_manager
                    .clone()
            {
                let client = crate::trust_registry_verification::TrqpListenerClient::new(manager);
                let probe_input = serde_json::to_value(&policy_input).unwrap_or_default();
                policy_input.trust_check_results = crate::trust_registry_verification::run_trust_check_stage(
                    state
                        .surface
                        .surface_id
                        .as_str(),
                    crate::trust_registry_verification::TrustCheckLeg::Target,
                    target_elements,
                    &probe_input,
                    &client,
                )
                .await;
            }
        }
        let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
        // [OPA-INPUT] Fabric surface policy input fully populated
        info!(channel = config_id_str, "[OPA-INPUT] Fabric surface policy input before eval: {}", input_value);

        if let Some(ref policy_manager) = state.policy_manager {
            let channel_opa_def_id = state
                .surface
                .opa_policy_definition_id();
            let (channel_opa_name, channel_opa_version, channel_opa_hash) = policy_manager
                .resolve_policy_decision_evidence(channel_opa_def_id)
                .await;
            match policy_manager.evaluate_policy_decision_for_variant(
                config_id_str,
                state
                    .active_variant_alias
                    .as_deref(),
                input_value,
            ) {
                Ok(decision) if decision.allow => {
                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::Surface,
                        allow: true,
                        policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                        policy_definition_id: channel_opa_def_id,
                        policy_name: Some(channel_opa_name.as_str()),
                        surface_id: Some(config_id_str),
                        trace_id: Some(&trace_id),
                        http_method: Some(method.as_ref()),
                        path: Some(uri.path()),
                        identity: authenticated_identity.as_ref(),
                        policy_version: channel_opa_version,
                        policy_content_hash: channel_opa_hash.as_deref(),
                        ..Default::default()
                    });
                }
                Ok(decision) => {
                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::Surface,
                        allow: false,
                        reason: decision.reason.as_deref(),
                        policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                        policy_definition_id: channel_opa_def_id,
                        policy_name: Some(channel_opa_name.as_str()),
                        surface_id: Some(config_id_str),
                        trace_id: Some(&trace_id),
                        http_method: Some(method.as_ref()),
                        path: Some(uri.path()),
                        identity: authenticated_identity.as_ref(),
                        policy_version: channel_opa_version,
                        policy_content_hash: channel_opa_hash.as_deref(),
                        ..Default::default()
                    });
                    connection_guard
                        .decrement()
                        .await;
                    return Err(axum::response::Response::builder()
                        .status(axum::http::StatusCode::FORBIDDEN)
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(
                            r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                        ))
                        .unwrap());
                }
                Err(e) => {
                    channel_warn!(config_id_str, "Surface-level OPA policy evaluation error (denying request): {}", e);
                    connection_guard
                        .decrement()
                        .await;
                    return Err(axum::response::Response::builder()
                        .status(axum::http::StatusCode::FORBIDDEN)
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(
                            r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                        ))
                        .unwrap());
                }
            }
        }
    }
    // ▲▲▲ development

    // MCP Tool Gating — `tools/call` gate on the fabric:// send leg. GW1
    // forwards fabric targets from here, before the direct-path gate would run,
    // so the surface's own firewall must be enforced on this leg too: a tool
    // this surface denies must be uncallable by its clients even when the
    // target is another gateway. Mirrors the direct-path gate in this handler.
    if state
        .surface
        .channel_protocol()
        == crate::config::ChannelProtocol::Mcp
        && crate::mcp::is_tools_call_request(&body_bytes)
        && let Some(config_id_str) = state.surface.config_id()
        && let Some(policy_manager) = state.policy_manager.as_ref()
        && let Some(gating) = policy_manager
            .compiled_mcp_tool_gating(
                config_id_str,
                state
                    .active_variant_alias
                    .as_deref(),
            )
            .filter(|g| !g.is_empty())
        && let Ok(tool_request) = crate::mcp::McpToolRequest::from_json_rpc(&body_bytes)
        && let Some(tool_name) = tool_request.tool_name()
    {
        let input_value = if gating.has_policy_conditions() {
            let mut policy_input = crate::surface_context::PolicyInput::new(
                method.as_ref(),
                uri.path(),
                crate::surface_context::filter_sensitive_headers(&headers),
                "outbound",
                None,
                Some(remote_gateway_did.clone()),
                Some(config_id_str.to_string()),
                &state.surface.name,
            );
            policy_input.source_auth = source_auth_context.clone();
            policy_input.mcp = modern_mcp_context
                .clone()
                .or_else(|| {
                    Some(crate::surface_context::McpContext {
                        method: tool_request.method.clone(),
                        tool_name: Some(tool_name.to_string()),
                        resource_uri: None,
                        prompt_name: None,
                        params: tool_request.params.clone(),
                        ..Default::default()
                    })
                });
            policy_input.identity_binding = identity_binding.clone();
            policy_input.normalize_caller_did();
            serde_json::to_value(&policy_input).unwrap_or_default()
        } else {
            serde_json::Value::Null
        };

        let allowed = gating.is_tool_call_allowed(tool_name, &input_value);
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::McpTool,
            allow: allowed,
            reason: if allowed {
                None
            } else {
                Some("blocked by MCP tool gating")
            },
            policy_id: Some("mcp_tool_gating"),
            surface_id: Some(config_id_str),
            trace_id: Some(&trace_id),
            http_method: Some(method.as_ref()),
            path: Some(uri.path()),
            identity: authenticated_identity.as_ref(),
            ..Default::default()
        });
        if !allowed {
            channel_warn!(
                config_id_str,
                "MCP tool gating blocked tools/call for tool '{}' (fabric send leg)",
                tool_name
            );
            connection_guard
                .decrement()
                .await;
            return Err(crate::mcp::build_tools_call_policy_denied_response(
                &body_bytes,
                Some("Tool is not available"),
            ));
        }
    }

    let mut modern_delegation = None;
    let mut modern_payment_headers = HeaderMap::new();
    if let Some(request) = modern_request.as_ref() {
        use crate::mcp::continuations::{ContinuationError, protected::ContinuationRoute};
        use crate::proxy::credential_delegation::modern::{
            ModernDelegationError, ModernDelegationResult, prepare_direct,
        };
        if state.surface.opa_enabled() && state.policy_manager.is_none() {
            connection_guard
                .decrement()
                .await;
            return Err(ModernDelegationError::from(ContinuationError::Denied).response(request));
        }
        if !state
            .surface
            .outbound_credentials
            .is_empty()
        {
            let Some(runtime) = mcp_continuations.as_deref() else {
                connection_guard
                    .decrement()
                    .await;
                return Err(ModernDelegationError::from(ContinuationError::Unavailable).response(request));
            };
            let authorization = state
                .surface
                .mcp_http
                .as_ref()
                .and_then(|http| http.authorization.as_ref())
                .map(|authorization| {
                    authorization.for_variant(
                        state
                            .active_variant_alias
                            .as_deref(),
                    )
                })
                .transpose()
                .map_err(|_| ModernDelegationError::from(ContinuationError::BindingMismatch).response(request))?;
            match prepare_direct(
                &state,
                runtime,
                request,
                authorization.as_ref(),
                authenticated_identity.as_ref(),
                identity_result
                    .as_ref()
                    .map(|identity| identity.did.as_str()),
                ContinuationRoute::FabricSend {
                    peer_did: remote_gateway_did.clone(),
                },
                surface_payment::is_unpaid(&state, &headers, &body_bytes),
            )
            .await
            {
                Ok(ModernDelegationResult::InputRequired(response)) => {
                    connection_guard
                        .decrement()
                        .await;
                    return Ok(([("cache-control", "no-store")], Json(response)).into_response());
                }
                Ok(ModernDelegationResult::Prepared(prepared)) => {
                    body_bytes = prepared
                        .rewrite_body(&body_bytes)
                        .map_err(|error| ModernDelegationError::from(error).response(request))?;
                    modern_request = Some(prepared.request.clone());
                    modern_delegation = Some(prepared);
                }
                Err(ModernDelegationError::Unpaid) => {
                    connection_guard
                        .decrement()
                        .await;
                    return match surface_payment::process(
                        &state,
                        &headers,
                        body_bytes,
                        modern_mcp_context.as_ref(),
                        &uri.to_string(),
                        None,
                    )
                    .await
                    {
                        Err(response) => Ok(response),
                        Ok(_) => Err(ModernDelegationError::Unpaid.response(request)),
                    };
                }
                Err(error) => {
                    connection_guard
                        .decrement()
                        .await;
                    return Err(error.response(request));
                }
            }
        }
        match surface_payment::delegate(
            &state,
            &headers,
            body_bytes.clone(),
            &method,
            &uri,
            &trace_id,
            channel_name,
            modern_request.as_ref(),
        )
        .await
        {
            surface_payment::DelegatedPayment::Proceed(receipts) => {
                for (name, values) in receipts {
                    let name = axum::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid delegated receipt header")
                    })?;
                    for value in values {
                        let value = axum::http::HeaderValue::from_str(&value).map_err(|_| {
                            create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid delegated receipt value")
                        })?;
                        modern_payment_headers.append(name.clone(), value);
                    }
                }
            }
            surface_payment::DelegatedPayment::Challenge(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Ok(response);
            }
            surface_payment::DelegatedPayment::Denied(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
        match surface_payment::process(
            &state,
            &headers,
            body_bytes.clone(),
            modern_mcp_context.as_ref(),
            &uri.to_string(),
            modern_delegation
                .as_ref()
                .and_then(|prepared| prepared.payment()),
        )
        .await
        {
            Ok(mut payment) => {
                if let Some(prepared) = modern_delegation.as_mut() {
                    let now = crate::proxy::credential_delegation::modern::now_secs().map_err(|_| {
                        create_error_response(StatusCode::SERVICE_UNAVAILABLE, "Payment continuation unavailable")
                    })?;
                    prepared
                        .record_local_payment(
                            &payment,
                            mcp_continuations
                                .as_ref()
                                .map_or(300, |runtime| runtime.config.ttl_secs),
                            now,
                        )
                        .map_err(|_| {
                            create_error_response(StatusCode::SERVICE_UNAVAILABLE, "Payment continuation unavailable")
                        })?;
                }
                payment
                    .strip_consumed_mcp_argument()
                    .map_err(|_| {
                        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid paid MCP request")
                    })?;
                payment.strip_consumed_headers(
                    &mut headers,
                    &state
                        .config
                        .x402_headers
                        .payment_signature,
                );
                if let Some((name, value)) = payment
                    .receipt_header(&state.config.x402_headers)
                    .map_err(|_| {
                        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid payment receipt header")
                    })?
                {
                    modern_payment_headers.insert(name, value);
                }
                body_bytes = payment.body;
            }
            Err(response) => {
                connection_guard
                    .decrement()
                    .await;
                return Err(response);
            }
        }
    }

    // Save original body for capture (before any modifications)
    let original_body_bytes = body_bytes.clone();

    // Traffic mirroring for fabric:// protocol - send duplicate request to mirror endpoint (if configured)
    if let Some(mirror_config) = state.surface.mirror() {
        // Check if we should mirror this request based on percentage
        let should_mirror = if mirror_config.percentage >= 100 {
            true
        } else if mirror_config.percentage == 0 {
            false
        } else {
            use rand::Rng;
            let mut rng = rand::rng();
            rng.random_range(0..100) < mirror_config.percentage
        };

        if should_mirror {
            let mirror_endpoint = mirror_config.endpoint.clone();
            let mirror_timeout = std::time::Duration::from_secs(mirror_config.timeout_secs);
            let wait_for_response = mirror_config.wait_for_response;
            let client = crate::http_client::with_timeout(mirror_timeout).unwrap_or_else(|_| reqwest::Client::new());
            let trace_id_clone = trace_id.clone();

            // Build mirror request
            let mirror_req = client
                .request(method.clone(), &mirror_endpoint)
                .body(body_bytes.to_vec())
                .timeout(mirror_timeout);

            // Copy headers
            let source_cred_header = state
                .surface
                .source_auth()
                .and_then(|sa| sa.credential_header_name());
            let header_metadata_mapping = state
                .surface
                .access_point
                .header_metadata_mapping_if_supported();
            let mut mirror_req_with_headers = mirror_req;
            for (key, value) in headers.iter() {
                if should_forward_ap_request_header_with_mapping(
                    key.as_str(),
                    source_cred_header,
                    header_metadata_mapping,
                    false,
                ) {
                    mirror_req_with_headers = mirror_req_with_headers.header(key.as_str(), value.as_bytes());
                }
            }
            mirror_req_with_headers =
                mirror_req_with_headers.header("X-Gateway-Trace-Id", format!("{}-mirror", trace_id_clone));
            mirror_req_with_headers = mirror_req_with_headers.header("X-Mirrored-Request", "true");
            mirror_req_with_headers = mirror_req_with_headers.header("X-Fabric-Gateway", gateway_id);
            mirror_req_with_headers = mirror_req_with_headers.header("X-Fabric-Channel", channel_id);

            if wait_for_response {
                // Wait for mirror response (blocking) - fabric request will be blocked if mirror fails
                match mirror_req_with_headers
                    .send()
                    .await
                {
                    Ok(resp) => {
                        channel_info!(
                            config_id,
                            "Fabric mirror request completed: endpoint={}, status={}",
                            mirror_endpoint,
                            resp.status().as_u16()
                        );
                    }
                    Err(e) => {
                        let error_type = if e.is_timeout() {
                            "timeout"
                        } else if e.is_connect() {
                            "connection refused"
                        } else if e.is_request() {
                            "invalid request"
                        } else {
                            "network error"
                        };

                        channel_error!(
                            config_id,
                            "Fabric mirror request failed ({}): endpoint={}, error={}",
                            error_type,
                            mirror_endpoint,
                            e
                        );

                        // For synchronous mirroring, return error if mirror fails
                        connection_guard
                            .decrement()
                            .await;
                        return Err(create_error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            &format!(
                                "Traffic mirroring failed ({}): Mirror endpoint '{}' is unreachable. Error: {}",
                                error_type, mirror_endpoint, e
                            ),
                        ));
                    }
                }
            } else {
                // Fire-and-forget mirror request
                let mirror_endpoint_clone = mirror_endpoint.clone();
                let config_id_clone = config_id.to_string();
                tokio::spawn(async move {
                    match mirror_req_with_headers
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            channel_info!(
                                config_id_clone,
                                "Fabric mirror request completed (async): endpoint={}, status={}",
                                mirror_endpoint_clone,
                                resp.status().as_u16()
                            );
                        }
                        Err(e) => {
                            channel_warn!(
                                config_id_clone,
                                "Fabric mirror request failed (async): endpoint={}, error={}",
                                mirror_endpoint_clone,
                                e
                            );
                        }
                    }
                });
            }
        } else {
            channel_debug!(config_id, "Skipping mirror for fabric request (percentage: {}%)", mirror_config.percentage);
        }
    }

    // Destructure identity result into separate hash and DID
    let identity_hash = identity_result
        .as_ref()
        .map(|r| r.hash.clone());
    let _request_agent_did = identity_result
        .as_ref()
        .map(|r| r.did.clone());
    let request_user_hash = source_auth_user_hash(authenticated_identity.as_ref());

    // Mirror the direct path: stamp the derived agent DID onto the root span
    // as `caller.did` so credential-derived identity (e.g. `from_jwt_claim`)
    // is visible on fabric:// G2G hops too.
    if let Some(did) = _request_agent_did.as_deref() {
        crate::observability::record_caller_did_on_current_span(did);
    }

    // Inject custom metadata extension if enabled for this channel (A2A/AP2 protocols)
    if let Some(custom_metadata) = state
        .surface
        .custom_metadata()
    {
        if (state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::A2a
            || state
                .surface
                .channel_protocol()
                == crate::config::ChannelProtocol::Ap2)
            && custom_metadata.enabled
            && method == "POST"
            && !body_bytes.is_empty()
        {
            match inject_custom_metadata_extension(
                &body_bytes,
                custom_metadata,
                channel_name,
                &state.secrets_store,
                crate::protocols::MetadataRuntimeContext {
                    request_id: Some(egress_trace_id.as_str()),
                    surface_id: Some(config_id),
                },
            )
            .await
            {
                Ok(modified_bytes) => {
                    channel_info!(config_id, "Custom metadata extension injected into fabric forward request");
                    body_bytes = modified_bytes;
                }
                Err(e) => {
                    channel_warn!(
                        config_id,
                        "Failed to inject custom metadata extension, using original body error={}",
                        e
                    );
                }
            }
        } else if state
            .surface
            .channel_protocol()
            == crate::config::ChannelProtocol::Mcp
            && custom_metadata.enabled
            && method == "POST"
            && !body_bytes.is_empty()
        {
            // Inject custom metadata for MCP protocol (into _meta field)
            match crate::protocols::resolve_metadata_references(
                custom_metadata
                    .payload
                    .as_ref()
                    .unwrap_or(&serde_json::json!({})),
                &state.secrets_store,
                channel_name,
                crate::protocols::MetadataRuntimeContext {
                    request_id: Some(egress_trace_id.as_str()),
                    surface_id: Some(config_id),
                },
            )
            .await
            {
                Ok(resolved_payload) => {
                    if let Ok(mut json_body) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                        && let Some(obj) = json_body.as_object_mut()
                    {
                        use crate::config::MetadataInjectionTarget;
                        let injection_target = custom_metadata
                            .injection_target
                            .as_ref()
                            .unwrap_or(&MetadataInjectionTarget::Both);

                        // For fabric protocol, only inject into params._meta field (not headers)
                        // Headers are not preserved through fabric forwarding
                        if *injection_target == MetadataInjectionTarget::Meta
                            || *injection_target == MetadataInjectionTarget::Both
                        {
                            // Navigate into "params" object per MCP spec
                            let params = obj
                                .entry("params")
                                .or_insert(serde_json::json!({}));
                            if let Some(params_obj) = params.as_object_mut() {
                                let meta = params_obj
                                    .entry("_meta")
                                    .or_insert(serde_json::json!({}));
                                if let Some(meta_obj) = meta.as_object_mut()
                                    && let Some(payload_obj) = resolved_payload.as_object()
                                {
                                    for (key, value) in payload_obj {
                                        meta_obj.insert(key.clone(), value.clone());
                                        channel_debug!(
                                            config_id,
                                            "Injected custom metadata to params._meta field in fabric forward key={}",
                                            key
                                        );
                                    }
                                }
                            }
                            // Update body_bytes with modified JSON
                            if let Ok(new_body) = serde_json::to_vec(&json_body) {
                                body_bytes = new_body.into();
                                channel_info!(
                                    config_id,
                                    "Custom metadata (with resolved secrets) injected into params._meta field for MCP fabric forward request"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    channel_warn!(
                        config_id,
                        "Failed to resolve secrets in custom metadata for MCP fabric forward, using original body error={}",
                        e
                    );
                }
            }
        }
    }

    // NOTE: Identity hash computation and DID assignment for external agents has been removed
    // from the inbound request path. VP credential injection into fabric forward requests
    // is no longer performed here. Protected agent identity is managed on the response path.

    // ── Build workload binding JSON for fabric forwarding ─────
    // When the primary target configures an enabled Workload Binding, produce the
    // configurable subject for the MA→EXT (fabric) request leg, capturing caller
    // context from the inbound Authorization bearer JWT (no transit token on this
    // leg). Otherwise leave it unset (the flat identityFields shape is used).
    let fabric_workload_binding: Option<serde_json::Value> = identity_result
        .as_ref()
        .and_then(|result| {
            build_target_request_workload_binding(
                &state.surface,
                &headers,
                &result.identity_fields,
                &trace_id,
                None,
                authenticated_identity.as_ref(),
            )
        });

    // ── Create identity binding VP for fabric forwarding (audit + optional injection) ─────
    let fabric_binding_vp_jwt = if let Some(ref result) = identity_result {
        let selector = state
            .identity_selector
            .as_ref();
        if let Some(selector) = selector {
            let vc_issuer = selector.get_vc_issuer();
            let chained_credentials = identity_binding
                .as_ref()
                .map(|b| b.inbound_credentials.clone())
                .unwrap_or_default();
            let chain_len = chained_credentials.len();
            match vc_issuer
                .create_agent_identity_presentation_chained(
                    &result.did,
                    &result.identity_fields,
                    fabric_workload_binding,
                    None,
                    None,
                    chained_credentials,
                )
                .await
            {
                Ok(vp_jwt) => {
                    channel_info!(
                        config_id,
                        "Created identity binding VP for fabric forwarding did={} chained_vcs={}",
                        result.did,
                        chain_len
                    );
                    Some(vp_jwt)
                }
                Err(e) => {
                    channel_warn!(config_id, "Failed to create identity binding VP for fabric forwarding error={}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    if state
        .surface
        .inject_identity_vp()
        && fabric_binding_vp_jwt.is_none()
    {
        channel_info!(
            config_id,
            "inject_vp is enabled but no identity binding VP was produced on the fabric path — no inbound agent identity was resolved (configure managed_identity / protected_identity, or have the caller send an identity VP); toggle has no effect for this request"
        );
    }

    // Inject VP into outbound request body only if channel toggle is enabled
    if (state
        .surface
        .inject_identity_vp()
        || state
            .surface
            .target_workload_binding()
            .is_some())
        && !body_bytes.is_empty()
        && let Some(ref vp_jwt) = fabric_binding_vp_jwt
        && let Some(ref result) = identity_result
    {
        let inbound_meta_field_to_strip: Option<String> = state
            .surface
            .inbound_identity()
            .and_then(|c| {
                if let crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) = c {
                    cfg.strip_raw_meta
                        .then(|| cfg.meta_field.clone())
                } else {
                    None
                }
            });
        match inject_identity_binding_vp_into_request(
            &body_bytes,
            vp_jwt,
            &state
                .surface
                .channel_protocol(),
            channel_name,
            inbound_meta_field_to_strip.as_deref(),
            mcp_metadata_context,
        ) {
            Ok(modified) => {
                body_bytes = modified;
                channel_info!(config_id, "Identity binding VP injected into fabric forward request");

                // Emit delegation audit event for VP injection
                if crate::delegation_vault::audit::identity_binding_vp_audit_enabled() {
                    let mut evt = crate::delegation_vault::audit::audit_event(
                        crate::delegation_vault::audit::DelegationAuditAction::VpInjected,
                        None,
                        request_user_hash.as_deref(),
                        None,
                        Some(
                            state
                                .surface
                                .surface_id
                                .as_str(),
                        ),
                    );
                    evt.agent_identity_did = Some(result.did.clone());
                    evt.channel_name = Some(channel_name.to_string());
                    evt.target_endpoint = Some(
                        state
                            .surface
                            .target
                            .endpoint
                            .clone(),
                    );
                    evt.protocol = Some(format!("{:?}", state.surface.channel_protocol()).to_lowercase());
                    evt.vp_jwt = Some(vp_jwt.clone());
                    // Own trace id (not the egress one on the wire): groups this
                    // injection event with this gateway's policy decisions under one
                    // `trace_id` so the Audit "This request" filter appears (mirrors
                    // the direct path). The VP the caller receives still carries the
                    // egress trace id downstream.
                    evt.trace_id = Some(trace_id.clone());
                    // When the trace was terminated, record the downstream (egress)
                    // trace in this gateway's own audit so the operator can bridge to
                    // the isolated downstream trace — it stays local (the remote
                    // gateway never sees the incoming trace).
                    evt.detail = Some(if egress_trace_id != trace_id {
                        format!("request_path_fabric; downstream_trace_id={egress_trace_id}")
                    } else {
                        "request_path_fabric".to_string()
                    });
                    crate::delegation_vault::audit::audit(evt);
                }
            }
            Err(e) => {
                channel_warn!(
                    config_id,
                    "Failed to inject identity binding VP into fabric forward request error={}",
                    e
                );
            }
        }
    }

    // Inject source gateway DID for fabric-to-fabric connections
    // This allows tracking gateway-to-gateway communication in metrics
    // Use the actual gateway DID (not connection point DID) to avoid information leakage
    if !body_bytes.is_empty() {
        // Get the local gateway DID from the identity selector (if available)
        let local_gateway_did = if let Some(ref selector) = state.identity_selector {
            selector
                .get_vc_issuer()
                .get_issuer_did()
                .await
                .ok()
        } else {
            None
        };

        if let Some(gateway_did) = local_gateway_did
            && let Ok(mut json_body) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
            && let Some(obj) = json_body.as_object_mut()
        {
            let gateway_did_field = "x-affinidi-fabric-gateway-did";

            match state
                .surface
                .channel_protocol()
            {
                crate::config::ChannelProtocol::Mcp => {
                    // For MCP, inject into params._meta field as an array
                    let params = obj
                        .entry("params")
                        .or_insert(serde_json::json!({}));
                    if let Some(params_obj) = params.as_object_mut() {
                        let meta = params_obj
                            .entry("_meta")
                            .or_insert(serde_json::json!({}));
                        if let Some(meta_obj) = meta.as_object_mut() {
                            meta_obj.insert(gateway_did_field.to_string(), serde_json::json!([gateway_did]));
                            channel_debug!(
                                config_id,
                                "Injected source gateway DID into params._meta.{} as array: [{}] gateway_did={}",
                                gateway_did_field,
                                gateway_did,
                                gateway_did
                            );
                        }
                    }
                }
                crate::config::ChannelProtocol::A2a
                | crate::config::ChannelProtocol::Ap2
                | crate::config::ChannelProtocol::DIDComm => {
                    // For A2A/AP2/DIDComm, inject into message.metadata as an array
                    if let Some(message) = obj
                        .get_mut("message")
                        .and_then(|m| m.as_object_mut())
                    {
                        let metadata = message
                            .entry("metadata")
                            .or_insert(serde_json::json!({}));
                        if let Some(metadata_obj) = metadata.as_object_mut() {
                            metadata_obj.insert(gateway_did_field.to_string(), serde_json::json!([gateway_did]));
                            channel_debug!(
                                config_id,
                                "Injected source gateway DID into message.metadata.{} as array: [{}] gateway_did={}",
                                gateway_did_field,
                                gateway_did,
                                gateway_did
                            );
                        }
                    }
                }
            }

            // Update body_bytes with modified JSON
            if let Ok(new_body) = serde_json::to_vec(&json_body) {
                body_bytes = new_body.into();
                channel_info!(
                    config_id,
                    "Source gateway DID injected for fabric forwarding gateway_did={}",
                    gateway_did
                );
            }
        }
    }

    // Convert headers to JSON-serializable format
    // Normalize header names to uppercase for consistency (HTTP headers are case-insensitive)
    // This ensures PAYMENT-SIGNATURE and other x402 headers work correctly through fabric protocol
    // Also strip the source-auth credential header — it was consumed by GW1 and must not leak to GW2/upstream.
    let fabric_source_cred = state
        .surface
        .source_auth()
        .and_then(|sa| sa.credential_header_name());
    let header_metadata_mapping = state
        .surface
        .access_point
        .header_metadata_mapping_if_supported();
    let mut stream_headers = HeaderMap::new();
    let mut headers_map: std::collections::HashMap<String, String> = headers
        .iter()
        .filter_map(|(k, v)| {
            if !should_forward_ap_request_header_with_mapping(
                k.as_str(),
                fabric_source_cred,
                header_metadata_mapping,
                false,
            ) {
                return None;
            }
            stream_headers.append(k.clone(), v.clone());
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_uppercase(), v.to_string()))
        })
        .collect();

    // Inject target authentication credentials into the forwarded headers so
    // GW2 delivers them to the upstream service.
    if let Some(target_auth) = state.surface.target_auth() {
        match inject_target_auth_header(
            target_auth,
            &state.secrets_store,
            channel_name,
            CallerAssertion::for_request(method.as_str(), uri.path()),
        )
        .await
        {
            Ok(Some((header_name, header_value))) => {
                if modern_request.is_some() {
                    let name = axum::http::HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| {
                        create_error_response(StatusCode::BAD_GATEWAY, "Invalid Target authentication header")
                    })?;
                    let value = axum::http::HeaderValue::from_str(&header_value).map_err(|_| {
                        create_error_response(StatusCode::BAD_GATEWAY, "Invalid Target authentication value")
                    })?;
                    stream_headers.insert(name, value);
                }
                headers_map.insert(header_name.to_uppercase(), header_value);
                channel_info!(config_id, "Injected target auth header into fabric ForwardRequest");
            }
            Ok(None) => {}
            Err(e) => {
                error!(channel = channel_name, error = %e, "Failed to resolve target auth for fabric forwarding");
                match target_auth.fallback {
                    crate::config::TargetAuthFallback::Reject => {
                        connection_guard
                            .decrement()
                            .await;
                        return Err(create_error_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Target authentication failed: {}", e),
                        ));
                    }
                    crate::config::TargetAuthFallback::Passthrough => {
                        warn!(
                            channel = channel_name,
                            "Target auth failed but passthrough enabled, continuing without credentials"
                        );
                    }
                }
            }
        }
    }

    if let Some(prepared) = modern_delegation.as_ref() {
        body_bytes = prepared
            .inject_body_credentials(&body_bytes)
            .map_err(|_| {
                create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid delegated credential metadata")
            })?;
        let credentials = prepared
            .credential_headers()
            .map_err(|_| {
                create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid delegated credential header")
            })?;
        for (name, value) in credentials.iter() {
            stream_headers.insert(name.clone(), value.clone());
        }
    }

    // Debug: Log payment-related headers to diagnose propagation
    if let Some(payment_sig) = headers_map.get("PAYMENT-SIGNATURE") {
        channel_info!(
            config_id,
            "Forwarding PAYMENT-SIGNATURE header (first 50 chars): {}",
            if payment_sig.len() > 50 {
                &payment_sig[..50]
            } else {
                payment_sig
            }
        );
    } else {
        channel_info!(config_id, "No PAYMENT-SIGNATURE header to forward");
    }
    channel_info!(
        config_id,
        "Forwarding {} headers to GW2: {:?}",
        headers_map.len(),
        headers_map
            .keys()
            .collect::<Vec<_>>()
    );

    // Build ForwardRequest DIDComm message
    use crate::messages::MessageType;
    use affinidi_messaging_didcomm::Message as DIDCommMessage;

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Convert body to string for DIDComm message
    let body_string = String::from_utf8_lossy(&body_bytes).to_string();

    // Parse the body as JSON so it's not double-escaped in the DIDComm message
    let body_value = if !body_string.is_empty() {
        serde_json::from_str::<serde_json::Value>(&body_string).unwrap_or_else(|_| {
            // If it's not valid JSON, store it as a string value
            serde_json::Value::String(body_string.clone())
        })
    } else {
        serde_json::Value::Null
    };

    info!(
        "📦 Building ForwardRequest: {} {} ({} headers, {} bytes body)",
        method.as_str(),
        path_and_query,
        headers_map.len(),
        body_bytes.len()
    );

    debug!("  ↳ Full path being sent: '{}'", path_and_query);
    debug!("  ↳ Body bytes length: {}", body_bytes.len());

    // Calculate message expiration time (use channel timeout if configured, otherwise global)
    let message_expires_secs = if let Some(timeout_config) = state.surface.timeout() {
        timeout_config.request_secs
    } else {
        state
            .config
            .a2a
            .message_expires_seconds
    };
    let expires_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    // The envelope's own lifetime is capped below the receiver's replay
    // horizon; the caller deadline below keeps the full timeout.
    let message_expires_epoch = expires_time.as_secs()
        + crate::gateways::connection_points::envelope_replay::sent_envelope_lifetime_secs(message_expires_secs);

    // Extract OpenTelemetry trace context for distributed tracing across fabric
    // protocol. Skipped when the surface terminates traces: the egress firewall
    // also covers the OTEL correlation id, so the remote gateway starts a fresh
    // distributed trace instead of inheriting ours.
    let otel_context = if state
        .surface
        .access_point
        .terminate_trace_id
    {
        None
    } else {
        use opentelemetry::trace::TraceContextExt;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let current_span = tracing::Span::current();
        let otel_ctx = current_span.context();
        let span_context = otel_ctx
            .span()
            .span_context()
            .clone();

        if span_context.is_valid() {
            let context = serde_json::json!({
                "trace_id": span_context.trace_id().to_string(),
                "span_id": span_context.span_id().to_string(),
                "trace_flags": span_context.trace_flags().to_u8(),
            });
            info!("📊 GW1: Extracted OTel context for fabric forwarding: {:?}", context);
            Some(context)
        } else {
            warn!("📊 GW1: Current span context is not valid, not propagating OTel context");
            None
        }
    };

    // Extract variant alias from the request path (for fabric routing).
    // This allows GW2 to resolve the same surface variant on its side.
    // URL grammar: `/route$alias/...` (suffix on the route, see plan §2.3).
    let virtual_channel_alias = crate::proxy::route_variant::extract_variant_alias_for_route(
        uri.path(),
        state
            .surface
            .access_point
            .route
            .as_str(),
    )
    .and_then(|a| a);

    let (modern_upstream, forward_result) = if modern_request.is_some() {
        crate::mcp::modern_http::strip_protocol_session_headers(&mut stream_headers);
        let stream_target = match virtual_channel_alias.as_deref() {
            Some(alias)
                if !state
                    .surface
                    .target
                    .endpoint
                    .contains('$') =>
            {
                format!("{}${alias}", state.surface.target.endpoint)
            }
            _ => state
                .surface
                .target
                .endpoint
                .clone(),
        };
        let header_timeout = state
            .surface
            .timeout()
            .map(|timeout| std::time::Duration::from_secs(timeout.request_secs))
            .unwrap_or_else(|| {
                std::time::Duration::from_millis(
                    state
                        .config
                        .a2a
                        .fabric_gateway_timeout_ms,
                )
            });
        let response = crate::proxy::fabric_forward::forward_stream_via_fabric(
            &state.listener_manager,
            crate::proxy::fabric_forward::FabricStreamForwardRequest {
                fabric_target: &stream_target,
                path: path_and_query,
                headers: stream_headers,
                body: body_bytes.clone(),
                header_timeout,
                limits: state
                    .surface
                    .mcp_http
                    .clone()
                    .unwrap_or_default(),
                trace_id: uuid::Uuid::parse_str(&egress_trace_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            },
        )
        .await
        .map_err(|error| {
            warn!(%error, "Modern Access Point Fabric transport failed");
            let status = match error {
                crate::proxy::fabric_forward::FabricForwardError::RemoteLegacyOnly => {
                    return crate::mcp::request_validation::McpRequestValidationError::legacy_only(
                        modern_request
                            .as_ref()
                            .and_then(|request| request.id.clone()),
                    )
                    .into_response();
                }
                crate::proxy::fabric_forward::FabricForwardError::NoResponse(_) => StatusCode::GATEWAY_TIMEOUT,
                _ => StatusCode::BAD_GATEWAY,
            };
            create_error_response(status, "Modern Fabric transport is unavailable")
        })?;
        (Some(response), Ok(None))
    } else {
        // Save data for potential MPP auto-pay retry (before it's consumed by json! macro)
        let mpp_retry_context = if state.surface.mpp_auto_pay() {
            Some((headers_map.clone(), body_value.clone()))
        } else {
            None
        };

        // Compute a wall-clock deadline (epoch milliseconds) for this proxied
        // request. GW2 short-circuits the upstream call with 504 once this
        // passes so we never spend time on work the caller has already given
        // up on (`fabric_gateway_timeout_ms` on the GW1 side guarantees we
        // bail out at the same wall-clock instant).
        let deadline_ms = (expires_time.as_millis() as u64).saturating_add(message_expires_secs.saturating_mul(1000));

        let forward_request_msg = DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            MessageType::ForwardRequest
                .as_str()
                .to_string(),
            serde_json::json!({
                "channel_id": channel_id,
                "method": method.as_str(),
                "path": path_and_query,
                "headers": headers_map,
                "body": body_value,
                "trace_id": egress_trace_id.clone(),
                "otel_context": otel_context,
                "deadline_ms": deadline_ms,
                // `virtual_channel_alias` retained for backward compatibility with
                // older GW2s. `active_variant_alias` is the spec-aligned name
                // (plan §4.4); GW2 prefers it when present.
                "virtual_channel_alias": virtual_channel_alias,
                "active_variant_alias": virtual_channel_alias,
            }),
        )
        .from(
            gateway_listener
                .gateway_did
                .clone(),
        )
        .to(remote_gateway_did.clone())
        .thid(uuid::Uuid::new_v4().to_string())
        .expires_time(message_expires_epoch)
        .finalize();

        debug!(
            "📤 Sending ForwardRequest (ID: {}) to gateway {} (DID: {})",
            forward_request_msg.id, gateway_id, remote_gateway_did
        );

        // Pre-resolve and cache the remote gateway's DID document
        debug!("Pre-resolving remote gateway DID document for encryption: {}", remote_gateway_did);
        let did_cache = listener_mgr.get_did_cache();

        // Get the ATM's TDK state to populate its cache
        let tdk_state = gateway_listener
            .client
            .atm()
            .get_tdk();

        // Resolve and cache the DID (uses fallback to cached version if resolution fails)
        match did_cache
            .resolve_and_cache_for_atm(&remote_gateway_did, tdk_state)
            .await
        {
            Ok((_, was_cached)) => {
                if was_cached {
                    channel_debug!(config_id, "✓ Using cached DID document for remote gateway {}", remote_gateway_did);
                } else {
                    channel_debug!(
                        config_id,
                        "✓ DID document resolved and cached for remote gateway {}",
                        remote_gateway_did
                    );
                }
            }
            Err(e) => {
                channel_warn!(
                    config_id,
                    "Failed to resolve remote gateway DID: {}. Attempting pack_encrypted anyway (may use SDK's cache)",
                    e
                );
                // Don't fail here - let pack_encrypted try with its own resolver
                // This preserves backward compatibility
            }
        }

        let response_rx = crate::proxy::fabric_response_waiter::register_forward_response_waiter(
            &forward_request_msg.id,
            &remote_gateway_did,
        )
        .map_err(|e| {
            channel_error!(config_id, "Failed to register ForwardResponse waiter: {}", e);
            create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to prepare fabric response waiter")
        })?;

        // Pack and send the message
        let _send_span = tracing::info_span!(
            "fabric.client.send",
            otel.name = "Fabric Send Request",
            gateway_id = gateway_id,
            channel_id = channel_id,
            remote_did = remote_gateway_did.as_str()
        );

        async {
        let packed = gateway_listener.client.atm().pack_encrypted(
        &forward_request_msg,
        &remote_gateway_did,
        Some(&gateway_listener.gateway_did),
        Some(&gateway_listener.gateway_did),
    ).await
    .map_err(|e| {
        crate::proxy::fabric_response_waiter::remove_forward_response_waiter(&forward_request_msg.id);
        channel_error!(config_id, "Failed to pack ForwardRequest to gateway {} (DID: {}): {:?}", gateway_id, remote_gateway_did, e);
        channel_warn!(config_id, "If the error mentions DID resolution, the remote gateway may be offline or its DID document unreachable");
        channel_warn!(config_id, "Consider checking if a cached DID document exists but is expired");
        create_error_response(
            StatusCode::BAD_GATEWAY,
            &format!("Failed to pack message for remote gateway '{}': {}. Gateway may be offline if DID resolution failed.", gateway_id, e)
        )
    })?;

    gateway_listener.client.atm().send_message(
        gateway_listener.client.profile(),
        &packed.0,
        &forward_request_msg.id,
        false, // Don't wait for response here
        false, // Don't auto-delete
    ).await
    .map_err(|e| {
        crate::proxy::fabric_response_waiter::remove_forward_response_waiter(&forward_request_msg.id);
        channel_error!(config_id, "Failed to send ForwardRequest: {:?}", e);
        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to send message")
    })?;

        debug!("ForwardRequest sent, waiting for response via WebSocket...");
        Ok::<_, Response>(())
    }.instrument(_send_span).await?;

        // Wait for ForwardResponse via WebSocket (configurable timeout)
        let _wait_span = tracing::info_span!(
            "fabric.client.wait_response",
            otel.name = "Fabric Wait for Response",
            gateway_id = gateway_id,
            channel_id = channel_id,
            timeout_ms = state
                .config
                .a2a
                .fabric_gateway_timeout_ms
        );

        let forward_result = async {
            // Use channel-level timeout if configured, otherwise fall back to global config
            let timeout_duration = if let Some(timeout_config) = state.surface.timeout() {
                std::time::Duration::from_secs(timeout_config.request_secs)
            } else {
                std::time::Duration::from_millis(
                    state
                        .config
                        .a2a
                        .fabric_gateway_timeout_ms,
                )
            };
            info!(
                "⏱️ Waiting for fabric gateway response with timeout: {:?} (channel timeout: {})",
                timeout_duration,
                state
                    .surface
                    .timeout()
                    .is_some()
            );

            Ok::<Option<crate::gateways::connection_points::messages::ReceivedMessage>, String>(
                crate::proxy::fabric_response_waiter::wait_for_forward_response(
                    &forward_request_msg.id,
                    response_rx,
                    timeout_duration,
                )
                .await,
            )
        }
        .instrument(_wait_span)
        .await;

        // ─── MPP Auto-Pay: intercept 402 from downstream gateway ───
        let forward_result = if state.surface.mpp_auto_pay() {
            if let Some((saved_headers, saved_body)) = mpp_retry_context {
                // Check if the response is a 402 ForwardResponse
                let should_retry = match &forward_result {
                    Ok(Some(response_msg)) => {
                        let status = response_msg
                            .message_body
                            .get("status")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u16;
                        if status == 402 {
                            response_msg
                                .message_body
                                .get("headers")
                                .and_then(|v| v.as_object())
                                .map(|m| {
                                    m.iter()
                                        .map(|(k, v)| (k.clone(), v.clone()))
                                        .collect::<std::collections::HashMap<String, serde_json::Value>>()
                                })
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                if let Some(response_headers_map) = should_retry {
                    channel_info!(
                        config_id,
                        "🔄 MPP auto-pay: downstream gateway returned 402, attempting auto-payment"
                    );

                    let secrets_store_ref = state
                        .secrets_store
                        .as_ref()
                        .map(|s| s.as_ref());

                    let auto_pay_result = if let Some(store) = secrets_store_ref {
                        crate::mpp::auto_pay::auto_pay_402(
                            &response_headers_map,
                            state
                                .surface
                                .mpp_auto_pay_max_amount(),
                            store,
                        )
                        .await
                    } else {
                        Err(anyhow::anyhow!("Secrets store not available for MPP auto-pay"))
                    };

                    match auto_pay_result {
                        Ok(result) => {
                            channel_info!(
                                config_id,
                                "🔄 MPP auto-pay succeeded (method='{}'), retrying fabric request",
                                result.method
                            );

                            // Rebuild headers with Authorization
                            let mut retry_headers = saved_headers;
                            retry_headers.insert("AUTHORIZATION".to_string(), result.authorization_header);

                            // Recalculate expiration
                            let retry_expires_secs = if let Some(timeout_config) = state.surface.timeout() {
                                timeout_config.request_secs
                            } else {
                                state
                                    .config
                                    .a2a
                                    .message_expires_seconds
                            };
                            let now_epoch = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap();
                            let retry_expires = now_epoch.as_secs()
                                + crate::gateways::connection_points::envelope_replay::sent_envelope_lifetime_secs(
                                    retry_expires_secs,
                                );
                            let retry_deadline_ms =
                                (now_epoch.as_millis() as u64).saturating_add(retry_expires_secs.saturating_mul(1000));

                            // Build new ForwardRequest with auth header
                            let retry_msg = DIDCommMessage::build(
                                uuid::Uuid::new_v4().to_string(),
                                MessageType::ForwardRequest
                                    .as_str()
                                    .to_string(),
                                serde_json::json!({
                                    "channel_id": channel_id,
                                    "method": method.as_str(),
                                    "path": path_and_query,
                                    "headers": retry_headers,
                                    "body": saved_body,
                                    "trace_id": egress_trace_id.clone(),
                                    "deadline_ms": retry_deadline_ms,
                                }),
                            )
                            .from(
                                gateway_listener
                                    .gateway_did
                                    .clone(),
                            )
                            .to(remote_gateway_did.clone())
                            .thid(uuid::Uuid::new_v4().to_string())
                            .expires_time(retry_expires)
                            .finalize();

                            match crate::proxy::fabric_response_waiter::register_forward_response_waiter(
                                &retry_msg.id,
                                &remote_gateway_did,
                            ) {
                                Ok(retry_response_rx) => {
                                    // Pack + send retry
                                    match gateway_listener
                                        .client
                                        .pack_and_send_message(
                                            &retry_msg,
                                            &remote_gateway_did,
                                            &gateway_listener.gateway_did,
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            // Wait for retry response
                                            let timeout_duration = if let Some(timeout_config) = state.surface.timeout()
                                            {
                                                std::time::Duration::from_secs(timeout_config.request_secs)
                                            } else {
                                                std::time::Duration::from_millis(
                                                    state
                                                        .config
                                                        .a2a
                                                        .fabric_gateway_timeout_ms,
                                                )
                                            };
                                            let retry_result = Ok::<
                                                Option<crate::gateways::connection_points::messages::ReceivedMessage>,
                                                String,
                                            >(
                                                crate::proxy::fabric_response_waiter::wait_for_forward_response(
                                                    &retry_msg.id,
                                                    retry_response_rx,
                                                    timeout_duration,
                                                )
                                                .await,
                                            );
                                            channel_info!(config_id, "🔄 MPP auto-pay: retry response received");
                                            retry_result
                                        }
                                        Err(e) => {
                                            crate::proxy::fabric_response_waiter::remove_forward_response_waiter(
                                                &retry_msg.id,
                                            );
                                            channel_warn!(config_id, "MPP auto-pay: failed to send retry: {}", e);
                                            forward_result
                                        }
                                    }
                                }
                                Err(e) => {
                                    channel_warn!(config_id, "MPP auto-pay: failed to register retry waiter: {}", e);
                                    forward_result
                                }
                            }
                        }
                        Err(e) => {
                            channel_warn!(config_id, "MPP auto-pay failed: {}, propagating 402", e);
                            forward_result
                        }
                    }
                } else {
                    forward_result
                }
            } else {
                forward_result
            }
        } else {
            forward_result
        };
        (None, forward_result)
    };

    // Process the ForwardResponse
    let _process_span = tracing::info_span!(
        "fabric.client.process_response",
        otel.name = "Fabric Process Response",
        gateway_id = gateway_id,
        channel_id = channel_id
    );

    let response_config_id = config_id.to_string();
    let response_gateway_id = gateway_id.to_string();
    let response_channel_name = channel_name.to_string();
    let modern_response_peer_did = remote_gateway_did.clone();
    let discovery_support = crate::mcp::modern::ForwardingSupport::for_endpoint(
        true,
        crate::mcp::request_validation::McpPathKind::FabricSend,
    )
    .restrict_to_fabric_peer(
        modern_upstream
            .as_ref()
            .and_then(|response| {
                response
                    .extensions()
                    .get::<crate::proxy::fabric_stream::peer::StreamCapabilities>()
            }),
    )
    .recording_versions(access_point_upstream_key(&state));
    let modern_limits = crate::mcp::modern_sse::SseLimits::from(
        &state
            .surface
            .mcp_http
            .clone()
            .unwrap_or_default(),
    );
    let is_modern_response = modern_request.is_some();
    let modern_completion = modern_upstream
        .as_ref()
        .map(|upstream| {
            let status = upstream.status();
            let mut guard = std::mem::replace(&mut connection_guard, ConnectionGuard::new(None, None));
            let metrics = state.metrics_store.clone();
            let monitor = state.task_monitor.clone();
            let task_id = state.task_id.clone();
            let surface_id = state
                .surface
                .config_id_string();
            let target = state
                .surface
                .target
                .endpoint
                .clone();
            let source = source_addr.clone();
            let identity = identity_hash.clone();
            let trace = trace_id.clone();
            let variant = state
                .active_variant_alias
                .clone();
            let request_bytes = body_bytes.len() as u64;
            move |outcome: crate::mcp::modern_sse::ResponseOutcome| {
                let latency = start_time
                    .elapsed()
                    .as_millis() as u64;
                tokio::spawn(async move {
                    guard.decrement().await;
                    if let (Some(monitor), Some(task_id)) = (monitor, task_id) {
                        monitor
                            .record_bytes(&task_id, outcome.bytes, request_bytes)
                            .await;
                        if !outcome.completed || outcome.failed {
                            monitor
                                .increment_errors(&task_id)
                                .await;
                        }
                    }
                    if let Some(metrics) = metrics {
                        let result = if outcome.completed && !outcome.failed && status.is_success() {
                            crate::metrics::ConnectionStatus::Success
                        } else {
                            crate::metrics::ConnectionStatus::Failed
                        };
                        metrics
                            .record_connection_with_ucp(
                                surface_id,
                                source,
                                target,
                                result,
                                Some(latency),
                                identity,
                                crate::metrics::ConnectionDirection::Request,
                                trace,
                                None,
                                None,
                                None,
                                latency,
                                variant,
                            )
                            .await;
                    }
                });
            }
        });
    let mut process_response = async move |forward_result: Result<
        Option<crate::gateways::connection_points::messages::ReceivedMessage>,
        String,
    >| {
        let config_id = response_config_id.as_str();
        let gateway_id = response_gateway_id.as_str();
        let channel_name = response_channel_name.as_str();
        // Don't manually decrement - let the Drop impl handle it after response is sent
        // connection_guard will be dropped when this function returns

        match forward_result {
            Ok(Some(response_msg)) => {
                let _extract_span =
                    tracing::info_span!("fabric.extract_response", otel.name = "Extract Response Fields");
                drop(_extract_span.enter());

                // Verify it's a ForwardResponse message
                let is_forward_response = response_msg.message_type == MessageType::ForwardResponse.as_str();

                if !is_forward_response {
                    channel_error!(config_id, "Received unexpected message type: {}", response_msg.message_type);
                    connection_guard
                        .decrement()
                        .await;
                    return Err(create_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Received unexpected message type from gateway",
                    ));
                }

                channel_debug!(config_id, "📨 Received ForwardResponse message body: {:?}", response_msg.message_body);

                // Capture the raw fabric envelope from GW2 (status/headers/body) so the
                // capture UX on GW1 can show what the remote gateway actually returned,
                // separate from the eventual transformed outbound response to the agent.
                let fabric_response_envelope: serde_json::Value = serde_json::json!({
                    "type": response_msg.message_type.clone(),
                    "from": response_msg.from_did.clone(),
                    "to": response_msg.to_dids.clone(),
                    "body": response_msg.message_body.clone(),
                });

                // Extract response fields
                let status = response_msg
                    .message_body
                    .get("status")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(500) as u16;

                let response_headers = response_msg
                    .message_body
                    .get("headers")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();

                let response_body = response_msg
                    .message_body
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                channel_debug!(
                    config_id,
                    "Extracted: status={}, headers_count={}, body_len={}",
                    status,
                    response_headers.len(),
                    response_body.len()
                );

                // Check if there was an error in the response
                if let Some(error) = response_msg
                    .message_body
                    .get("error")
                {
                    // Special handling for 402 Payment Required - propagate it with all headers
                    if status == 402 {
                        channel_warn!(config_id, "⚠️ Downstream gateway requires payment (402), propagating to client");

                        // Build 402 response with all payment headers from downstream
                        let mut response_builder = Response::builder().status(StatusCode::PAYMENT_REQUIRED);

                        for (key, value) in response_headers.iter() {
                            if let Ok(header_name) = axum::http::HeaderName::try_from(key)
                                && let Some(value_str) = value.as_str()
                                && let Ok(header_value) = axum::http::HeaderValue::try_from(value_str)
                            {
                                response_builder = response_builder.header(header_name, header_value);
                            }
                        }

                        // Ensure Content-Type is set
                        if !response_headers.contains_key("content-type") {
                            response_builder = response_builder.header("Content-Type", "application/json");
                        }

                        connection_guard
                            .decrement()
                            .await;
                        return Err(response_builder
                            .body(axum::body::Body::from(response_body))
                            .unwrap());
                    }

                    channel_error!(config_id, "❌ Gateway forwarding error: {}", error);

                    // For MCP requests, return the error as a properly formatted JSON-RPC error response
                    // instead of converting it to an HTTP error (which causes a 500)
                    if state
                        .surface
                        .channel_protocol()
                        == crate::config::ChannelProtocol::Mcp
                    {
                        // Map upstream HTTP status to a JSON-RPC error code.
                        // 403 (policy denial) -> -32001 to match the local MCP handler
                        // (see src/mcp/handler.rs). Everything else falls back to -32603.
                        let jsonrpc_error_code: i32 = if status == 403 {
                            -32001
                        } else {
                            -32603
                        };

                        // Try to parse the response_body as JSON to see if it's already a JSON-RPC error
                        let error_response =
                            if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&response_body) {
                                // If it's already a JSON-RPC response, use it as-is
                                if json_body
                                    .get("jsonrpc")
                                    .is_some()
                                {
                                    response_body
                                } else {
                                    // Create a JSON-RPC error response
                                    let error_msg = error
                                        .as_str()
                                        .unwrap_or("Gateway forwarding failed");
                                    serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "id": null,
                                        "error": {
                                            "code": jsonrpc_error_code,
                                            "message": error_msg
                                        }
                                    })
                                    .to_string()
                                }
                            } else {
                                // Create a JSON-RPC error response
                                let error_msg = error
                                    .as_str()
                                    .unwrap_or("Gateway forwarding failed");
                                serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": null,
                                    "error": {
                                        "code": jsonrpc_error_code,
                                        "message": error_msg
                                    }
                                })
                                .to_string()
                            };

                        // Build response with headers from the forward response.
                        // Preserve the MCP JSON-RPC convention (HTTP 200 + error
                        // body) for application-level errors, but propagate an
                        // explicit transport/authorization error status (>= 400)
                        // from the downstream gateway — e.g. a gateway-policy
                        // denial (403) — so MCP and A2A behave consistently and
                        // the caller can distinguish "blocked" from "answered".
                        let mcp_error_status = if status >= 400 {
                            StatusCode::from_u16(status).unwrap_or(StatusCode::OK)
                        } else {
                            StatusCode::OK
                        };
                        let mut response_builder = Response::builder().status(mcp_error_status);

                        for (key, value) in response_headers.iter() {
                            if let Ok(header_name) = axum::http::HeaderName::try_from(key)
                                && let Some(value_str) = value.as_str()
                                && let Ok(header_value) = axum::http::HeaderValue::try_from(value_str)
                            {
                                response_builder = response_builder.header(header_name, header_value);
                            }
                        }

                        // Ensure Content-Type is set to application/json
                        response_builder = response_builder.header("Content-Type", "application/json");

                        connection_guard
                            .decrement()
                            .await;
                        return Ok(response_builder
                            .body(axum::body::Body::from(error_response))
                            .unwrap());
                    }

                    // For non-MCP requests, return HTTP error as before
                    let error_status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                    connection_guard
                        .decrement()
                        .await;
                    return Err(create_error_response(
                        error_status,
                        error
                            .as_str()
                            .unwrap_or("Gateway forwarding failed"),
                    ));
                }

                // Check if status is 402 Payment Required (even without error field)
                // This handles the case where downstream gateway returns a proper x402 response
                if status == 402 {
                    channel_warn!(config_id, "⚠️ Downstream gateway requires payment (402), propagating to client");

                    // Build 402 response with all payment headers from downstream
                    let mut response_builder = Response::builder().status(StatusCode::PAYMENT_REQUIRED);

                    for (key, value) in response_headers.iter() {
                        if let Ok(header_name) = axum::http::HeaderName::try_from(key)
                            && let Some(value_str) = value.as_str()
                            && let Ok(header_value) = axum::http::HeaderValue::try_from(value_str)
                        {
                            response_builder = response_builder.header(header_name, header_value);
                        }
                    }

                    // Ensure Content-Type is set
                    if !response_headers.contains_key("content-type") && !response_headers.contains_key("Content-Type")
                    {
                        response_builder = response_builder.header("Content-Type", "application/json");
                    }

                    connection_guard
                        .decrement()
                        .await;
                    return Err(response_builder
                        .body(axum::body::Body::from(response_body))
                        .unwrap());
                }

                channel_info!(config_id, "✅ Fabric forward completed with status {}", status);

                let response_body = if state
                    .surface
                    .channel_protocol()
                    == crate::config::ChannelProtocol::Mcp
                {
                    crate::mcp::meta::normalize_text(&response_body, mcp_metadata_context)
                        .map_err(|error| error.into_response(response_body.as_bytes(), StatusCode::BAD_GATEWAY))?
                } else {
                    response_body
                };

                // ── Step 12: Resolve Protected Agent Identity (fabric path) ─────
                let is_agent_card_request = (uri
                    .path()
                    .ends_with("/.well-known/agent-card.json")
                    || uri
                        .path()
                        .ends_with("/.well-known/agent.json"))
                    && status < 400;
                let fabric_response_identity_selector = state
                    .protected_selector
                    .as_ref()
                    .or(state
                        .identity_selector
                        .as_ref());
                let fabric_response_identity_rules = state
                    .protected_rules_engine
                    .as_ref()
                    .or(state
                        .identity_rules_engine
                        .as_ref());
                let resolved_identity = if (200..300).contains(&status) && !response_body.is_empty() {
                    match crate::proxy::backend_identity::resolve_protected_agent_identity(
                        response_body.as_bytes(),
                        &state.surface,
                        fabric_response_identity_selector,
                        fabric_response_identity_rules,
                        channel_name,
                        is_agent_card_request,
                        authenticated_identity.as_ref(),
                    )
                    .await
                    {
                        Ok(identity) => identity,
                        Err(e) => {
                            // If identity was already resolved on the request path, use it
                            if let Some(ref result) = identity_result {
                                info!(
                                    channel = channel_name,
                                    did = %result.did,
                                    "Fabric: Response-path identity missing, using request-path identity"
                                );
                                ProtectedAgentIdentity::Managed {
                                    did: result.did.clone(),
                                    identity_fields: result.identity_fields.clone(),
                                }
                            } else {
                                warn!(
                                    channel = channel_name,
                                    error = %e,
                                    code = %e.code(),
                                    "Fabric: Protected agent identity resolution failed"
                                );
                                connection_guard
                                    .decrement()
                                    .await;
                                return Err(crate::a2a::create_identity_error_response(
                                    e.http_status(),
                                    e.code(),
                                    "protected_identity",
                                    channel_name,
                                    &e.to_string(),
                                ));
                            }
                        }
                    }
                } else {
                    ProtectedAgentIdentity::Anonymous
                };

                // External slot resolution (Surface Builder external identity node).
                if state
                    .external_selector
                    .is_some()
                    && (200..300).contains(&status)
                    && !response_body.is_empty()
                    && let Err(e) = crate::proxy::backend_identity::resolve_external_agent_identity(
                        response_body.as_bytes(),
                        &state.surface,
                        state
                            .external_selector
                            .as_ref(),
                        state
                            .external_rules_engine
                            .as_ref(),
                        channel_name,
                        is_agent_card_request,
                        authenticated_identity.as_ref(),
                    )
                    .await
                {
                    warn!(
                        channel = channel_name,
                        error = %e,
                        code = %e.code(),
                        "Fabric: External agent identity resolution failed"
                    );
                    connection_guard
                        .decrement()
                        .await;
                    return Err(crate::a2a::create_identity_error_response(
                        e.http_status(),
                        e.code(),
                        "external_identity",
                        channel_name,
                        &e.to_string(),
                    ));
                }

                // Rewrite agent card URLs if this is an agent card response
                let _rewrite_span = tracing::info_span!("fabric.rewrite_urls", otel.name = "Rewrite Agent Card URLs");
                drop(_rewrite_span.enter());

                let response_body = if is_agent_card_request {
                    match rewrite_agent_card_urls(
                        response_body.as_bytes(),
                        &state.surface,
                        &state.config,
                        &state.network_config,
                        &resolved_identity,
                    )
                    .await
                    {
                        Ok(rewritten) => {
                            channel_info!(config_id, "Rewrote agent card URLs to point to proxy");
                            String::from_utf8_lossy(&rewritten).to_string()
                        }
                        Err(e) => {
                            channel_warn!(
                                config_id,
                                "Failed to rewrite agent card URLs, returning original error={}",
                                e
                            );
                            response_body
                        }
                    }
                } else {
                    response_body
                };

                // Replace agent-identity/v1 with agent-identity-credential/v1 (signed VP) in agent card (fabric path)
                let response_body = if is_agent_card_request {
                    if let Some(selector) = state
                        .identity_selector
                        .as_ref()
                    {
                        let vc_issuer = selector.get_vc_issuer();
                        let mut card: serde_json::Value = match serde_json::from_str(&response_body) {
                            Ok(v) => v,
                            Err(e) => {
                                connection_guard
                                    .decrement()
                                    .await;
                                return Err(create_error_response(
                                    StatusCode::BAD_GATEWAY,
                                    &format!("Failed to parse agent card for credential injection: {}", e),
                                ));
                            }
                        };
                        if let Err(e) = crate::a2a::inject_credential_into_agent_card(
                            &mut card,
                            &resolved_identity,
                            &vc_issuer,
                            channel_name,
                        )
                        .await
                        {
                            channel_error!(config_id, "Failed to inject identity credential into agent card: {}", e);
                            connection_guard
                                .decrement()
                                .await;
                            return Err(create_error_response(
                                StatusCode::BAD_GATEWAY,
                                &format!("Agent card identity credential injection failed: {}", e),
                            ));
                        }
                        serde_json::to_string(&card).unwrap_or(response_body)
                    } else {
                        response_body
                    }
                } else {
                    response_body
                };

                // Inject did:webvh-derived agentDid/agentDNA top-level fields onto the agent card (fabric path).
                let response_body = if is_agent_card_request {
                    match serde_json::from_str::<serde_json::Value>(&response_body) {
                        Ok(mut card) => {
                            #[cfg(feature = "didwebvh")]
                            crate::a2a::inject_didwebvh_identity_into_agent_card(
                                &mut card,
                                &state.surface,
                                state
                                    .didwebvh_identity_store
                                    .as_ref(),
                            )
                            .await;
                            #[cfg(not(feature = "didwebvh"))]
                            let _ = &card;
                            serde_json::to_string(&card).unwrap_or(response_body)
                        }
                        Err(e) => {
                            channel_warn!(config_id, "Failed to parse agent card for agentDNA injection: {}", e);
                            response_body
                        }
                    }
                } else {
                    response_body
                };

                // Inject response custom metadata if enabled (fabric-to-fabric on GW1 side)
                let _metadata_span =
                    tracing::info_span!("fabric.inject_metadata", otel.name = "Inject Response Metadata");

                // HTTP headers collected from response Custom Metadata when injection_target is
                // Headers or Both. Applied on the response builder below.
                let mut response_metadata_headers: Vec<(String, String)> = Vec::new();

                let response_body = async {
                let rewritten = if (200..300).contains(&status) && !response_body.is_empty() {
                // For fabric-to-fabric responses, ALWAYS inject GW1's DID into the array
                // (GW2 should have already added its DID)
                let local_gateway_did = if let Some(ref selector) = state.identity_selector {
                    selector.get_vc_issuer().get_issuer_did().await.ok()
                } else {
                    None
                };

                let mut response_body = if let Some(local_gateway_did) = local_gateway_did {
                    match state.surface.channel_protocol() {
                        crate::config::ChannelProtocol::Mcp => {
                            if let Ok(mut json_response) = serde_json::from_str::<serde_json::Value>(&response_body)
                                && crate::mcp::meta::permits_result_enrichment(&json_response) {
                                if let Some(obj) = json_response.as_object_mut()
                                    && let Some(result) = obj.get_mut("result").and_then(|r| r.as_object_mut())
                                {
                                    let meta = result.entry("_meta").or_insert_with(|| serde_json::json!({}));
                                    if let Some(meta_obj) = meta.as_object_mut() {
                                        let gateway_did_field = "x-affinidi-fabric-gateway-did";
                                        let did_array = meta_obj.entry(gateway_did_field.to_string())
                                            .or_insert_with(|| serde_json::json!([]));

                                        if let Some(arr) = did_array.as_array_mut() {
                                            arr.push(serde_json::json!(local_gateway_did));
                                            channel_info!(config_id, "✅ GW1: Appended source gateway DID to result._meta.{} array: {}", gateway_did_field, local_gateway_did);
                                        } else {
                                            // If it exists but is not an array, convert it to array
                                            let existing_value = did_array.clone();
                                            *did_array = serde_json::json!([existing_value, local_gateway_did]);
                                            channel_info!(config_id, "✅ GW1: Converted result._meta.{} to array and appended DID: {}", gateway_did_field, local_gateway_did);
                                        }

                                        // Serialize back
                                        match serde_json::to_string(&json_response) {
                                            Ok(modified_str) => modified_str,
                                            Err(e) => {
                                                channel_warn!(config_id, "Failed to serialize response after GW1 DID injection error={}", e);
                                                response_body
                                            }
                                        }
                                    } else {
                                        response_body
                                    }
                                } else {
                                    response_body
                                }
                            } else {
                                response_body
                            }
                        },
                        crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2 | crate::config::ChannelProtocol::DIDComm => {
                            // For A2A/AP2, inject into result.history[0].metadata
                            if let Ok(mut json_response) = serde_json::from_str::<serde_json::Value>(&response_body) {
                                if let Some(obj) = json_response.as_object_mut() {
                                    let gateway_did_field = "x-affinidi-fabric-gateway-did";
                                    let mut modified = false;

                                    // Try to inject into result.history[0].metadata
                                    if let Some(result) = obj.get_mut("result")
                                        && let Some(history) = result.get_mut("history").and_then(|h| h.as_array_mut())
                                            && let Some(first_msg) = history.first_mut()
                                                && let Some(msg_obj) = first_msg.as_object_mut() {
                                                    let metadata = msg_obj.entry("metadata").or_insert(serde_json::json!({}));
                                                    if let Some(metadata_obj) = metadata.as_object_mut() {
                                                        let did_array = metadata_obj.entry(gateway_did_field.to_string())
                                                            .or_insert_with(|| serde_json::json!([]));

                                                        if let Some(arr) = did_array.as_array_mut() {
                                                            arr.push(serde_json::json!(local_gateway_did));
                                                            channel_info!(config_id, "✅ GW1: Appended source gateway DID to result.history[0].metadata.{} array: {}", gateway_did_field, local_gateway_did);
                                                            modified = true;
                                                        } else {
                                                            // If it exists but is not an array, convert it to array
                                                            let existing_value = did_array.clone();
                                                            *did_array = serde_json::json!([existing_value, local_gateway_did]);
                                                            channel_info!(config_id, "✅ GW1: Converted result.history[0].metadata.{} to array and appended DID: {}", gateway_did_field, local_gateway_did);
                                                            modified = true;
                                                        }
                                                    }
                                                }

                                    if modified {
                                        // Serialize back
                                        match serde_json::to_string(&json_response) {
                                            Ok(modified_str) => modified_str,
                                            Err(e) => {
                                                channel_warn!(config_id, "Failed to serialize A2A response after GW1 DID injection error={}", e);
                                                response_body
                                            }
                                        }
                                    } else {
                                        response_body
                                    }
                                } else {
                                    response_body
                                }
                            } else {
                                response_body
                            }
                        }
                    }
                } else {
                    response_body
                };

                // Then inject custom metadata if enabled
                if let Some(response_custom_metadata) = state.surface.response_custom_metadata() {
                    if response_custom_metadata.enabled {
                        channel_info!(config_id, "Response custom metadata is enabled, protocol={:?}", state.surface.channel_protocol());
                        response_body = match state.surface.channel_protocol() {
                            crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2 | crate::config::ChannelProtocol::DIDComm => {
                                // For A2A/AP2 protocol, inject into result.history[0].metadata under extension URI
                                channel_info!(config_id, "Injecting response custom metadata (A2A) for fabric response");
                                if let Some(payload) = &response_custom_metadata.payload {
                                    if let Ok(mut json_response) = serde_json::from_str::<serde_json::Value>(&response_body) {
                                        if let Some(obj) = json_response.as_object_mut() {
                                            let mut modified = false;

                                            // Inject into result.history[0].metadata
                                            if let Some(result) = obj.get_mut("result")
                                                && let Some(history) = result.get_mut("history").and_then(|h| h.as_array_mut())
                                                    && let Some(first_msg) = history.first_mut()
                                                        && let Some(msg_obj) = first_msg.as_object_mut() {
                                                            let metadata = msg_obj.entry("metadata").or_insert(serde_json::json!({}));
                                                            if let Some(metadata_obj) = metadata.as_object_mut() {
                                                                // Inject custom metadata under the extension URI
                                                                let extension_uri = crate::config::AFFINIDI_AGENT_METADATA_EXTENSION;
                                                                let extension_data = metadata_obj.entry(extension_uri)
                                                                    .or_insert_with(|| serde_json::json!({}));

                                                                if let Some(extension_obj) = extension_data.as_object_mut() {
                                                                    if let Some(payload_obj) = payload.as_object() {
                                                                        for (key, value) in payload_obj {
                                                                            channel_info!(config_id, "Injecting A2A response metadata key '{}' = {:?} under {}", key, value, extension_uri);
                                                                            extension_obj.insert(key.clone(), value.clone());
                                                                        }
                                                                        modified = true;
                                                                        channel_info!(config_id, "✅ Response custom metadata injected into result.history[0].metadata.{} for A2A fabric response", extension_uri);
                                                                    }
                                                                } else {
                                                                    channel_warn!(config_id, "Extension data is not an object");
                                                                }
                                                            }
                                                        }

                                            if modified {
                                                match serde_json::to_string(&json_response) {
                                                    Ok(modified_str) => modified_str,
                                                    Err(e) => {
                                                        channel_warn!(config_id, "Failed to serialize A2A response with custom metadata error={}", e);
                                                        response_body
                                                    }
                                                }
                                            } else {
                                                channel_debug!(config_id, "Could not find result.history[0].metadata in A2A response (response may not contain history)");
                                                response_body
                                            }
                                        } else {
                                            response_body
                                        }
                                    } else {
                                        channel_warn!(config_id, "Failed to parse A2A response as JSON for custom metadata injection");
                                        response_body
                                    }
                                } else {
                                    channel_warn!(config_id, "No payload configured for A2A response custom metadata");
                                    response_body
                                }
                            }
                            crate::config::ChannelProtocol::Mcp => {
                                let injected = crate::mcp::metadata::inject_custom_metadata_with_context(
                                    &bytes::Bytes::from(response_body.clone()), response_custom_metadata, channel_name, &state.secrets_store,
                                    crate::protocols::MetadataRuntimeContext { request_id: Some(trace_id.as_str()), surface_id: Some(config_id) },
                                    mcp_metadata_context, crate::mcp::meta::McpMetaTarget::Result,
                                ).await.map_err(|error| {
                                    channel_warn!(config_id, "MCP response metadata injection failed: {}", error);
                                    create_error_response(StatusCode::BAD_GATEWAY, "MCP response metadata injection failed")
                                })?;
                                for (name, value) in injected.extra_headers {
                                    response_metadata_headers.push((name.to_string(), value.to_str().unwrap_or_default().to_string()));
                                }
                                String::from_utf8(injected.body.to_vec()).map_err(|_| create_error_response(StatusCode::BAD_GATEWAY, "Invalid MCP response encoding"))?
                            }
                        };
                    } else {
                        channel_info!(config_id, "Response custom metadata is not enabled");
                    }
                } else {
                    channel_info!(config_id, "No response_custom_metadata configured");
                }

                response_body
            } else {
                channel_info!(config_id, "Skipping response metadata injection: status={}, body_empty={}", status, response_body.is_empty());
                response_body
            };
            Ok::<_, Response>(rewritten)
            }.instrument(_metadata_span).await?;
                let response_body = if state
                    .surface
                    .channel_protocol()
                    == crate::config::ChannelProtocol::Mcp
                {
                    crate::mcp::meta::normalize_text(&response_body, mcp_metadata_context)
                        .map_err(|error| error.into_response(response_body.as_bytes(), StatusCode::BAD_GATEWAY))?
                } else {
                    response_body
                };

                // MCP Tool Gating — `tools/list` filter on the fabric response leg.
                // This surface's firewall also hides tools from its own clients
                // (composing with the receiving gateway's filter), so a tool it
                // denies is neither listed nor callable. The fabric response is
                // already plain JSON here (the receiving gateway de-SSE's it).
                let response_body = if state
                    .surface
                    .channel_protocol()
                    == crate::config::ChannelProtocol::Mcp
                    && crate::mcp::is_tools_list_request(&original_body_bytes)
                    && let Some(policy_manager) = state.policy_manager.as_ref()
                    && let Some(gating) = policy_manager
                        .compiled_mcp_tool_gating(
                            config_id,
                            state
                                .active_variant_alias
                                .as_deref(),
                        )
                        .filter(|g| !g.is_empty())
                {
                    match serde_json::from_str::<serde_json::Value>(&response_body) {
                        Ok(mut json) => {
                            let input_value = if gating.has_policy_conditions() {
                                let mut policy_input = crate::surface_context::PolicyInput::new(
                                    method.as_ref(),
                                    uri.path(),
                                    crate::surface_context::filter_sensitive_headers(&headers),
                                    "outbound",
                                    None,
                                    Some(remote_gateway_did.clone()),
                                    Some(config_id.to_string()),
                                    &state.surface.name,
                                );
                                policy_input.mcp = modern_mcp_context
                                    .clone()
                                    .or_else(|| {
                                        Some(crate::surface_context::McpContext {
                                            method: "tools/list".to_string(),
                                            tool_name: None,
                                            resource_uri: None,
                                            prompt_name: None,
                                            params: None,
                                            ..Default::default()
                                        })
                                    });
                                serde_json::to_value(&policy_input).unwrap_or_default()
                            } else {
                                serde_json::Value::Null
                            };
                            match gating.filter_tools_list_value(&mut json, &input_value) {
                                Some((before, after)) => {
                                    if after < before {
                                        channel_info!(
                                            config_id,
                                            "MCP tool gating filtered tools/list before={} after={} (fabric response leg)",
                                            before,
                                            after
                                        );
                                    }
                                    // A caller-scoped gate makes the list
                                    // authorization-dependent even when it removes nothing.
                                    let privatize = mcp_metadata_context.requires_private_result_cache();
                                    if privatize {
                                        crate::mcp::meta::protect_enriched_result_cache(
                                            &mut json,
                                            mcp_metadata_context,
                                        );
                                    }
                                    match (after < before || privatize)
                                        .then(|| serde_json::to_string(&json).ok())
                                        .flatten()
                                    {
                                        Some(rewritten) => rewritten,
                                        None => response_body,
                                    }
                                }
                                None => response_body,
                            }
                        }
                        // Un-inspectable tools/list response: fail closed once
                        // gating is installed rather than pass it through.
                        Err(_) => {
                            channel_warn!(
                                config_id,
                                "MCP tools/list response unparsable under gating; failing closed (empty tool list) (fabric response leg)"
                            );
                            crate::mcp::fail_closed_tools_list(&body_bytes, mcp_metadata_context)
                        }
                    }
                } else {
                    response_body
                };

                // Broadcast payload capture AFTER all transformations (4-stage pipeline)
                // This ensures Stage 4 shows the actual final response sent to the agent
                if state
                    .config
                    .extension_inspection
                    .enabled
                {
                    let config_id = state
                        .surface
                        .config_id_string();

                    // Stage 1: Inbound request from agent (ORIGINAL, before transformations)
                    let inbound_request: serde_json::Value = if !original_body_bytes.is_empty() {
                        serde_json::from_slice(&original_body_bytes).unwrap_or_else(|_| {
                            serde_json::json!({
                                "_raw_body": String::from_utf8_lossy(&original_body_bytes).to_string(),
                                "method": method.as_str()
                            })
                        })
                    } else {
                        serde_json::json!({
                            "method": method.as_str(),
                            "_no_body": true
                        })
                    };

                    // Stage 2: Outbound to target (TRANSFORMED with VP, custom metadata, etc.)
                    let outbound_request: Option<serde_json::Value> = if !body_bytes.is_empty() {
                        Some(serde_json::from_slice(&body_bytes).unwrap_or_else(|_| {
                            serde_json::json!({
                                "_raw_body": String::from_utf8_lossy(&body_bytes).to_string(),
                                "method": method.as_str()
                            })
                        }))
                    } else {
                        Some(serde_json::json!({
                            "method": method.as_str(),
                            "_no_body": true
                        }))
                    };

                    // Stage 3: Inbound response from target (we don't have the original anymore - it was transformed in place)
                    // For the fabric path, surface the raw ForwardResponse envelope returned by
                    // the remote gateway (GW2) so operators can distinguish it from the eventual
                    // outbound response (Stage 4) which carries this gateway's own transformations.
                    let inbound_response: Option<serde_json::Value> = Some(fabric_response_envelope.clone());

                    // Stage 4: Outbound result to agent (FINAL - after agent card rewriting, custom metadata injection, etc.)
                    let outbound_response: Option<serde_json::Value> = if !response_body.is_empty() {
                        serde_json::from_str(&response_body).ok()
                    } else {
                        Some(serde_json::json!({
                            "status": status,
                            "_no_body": true
                        }))
                    };

                    // Determine validation status
                    let validation_status = if (200..300).contains(&status) {
                        "success"
                    } else if status == 405 {
                        "method_not_allowed" // Don't show as validation failure
                    } else if (400..500).contains(&status) {
                        "client_error"
                    } else if status >= 500 {
                        "server_error"
                    } else {
                        "unknown"
                    };

                    // Broadcast the full 4-stage pipeline
                    crate::observability::payload_capture::broadcast_payload_capture_extended(
                        &state.ws_state,
                        &state.metrics_store,
                        channel_name,
                        &config_id,
                        &inbound_request,
                        outbound_request,
                        inbound_response,
                        outbound_response,
                        validation_status,
                        None, // validation_error
                        identity_hash.clone(),
                        state
                            .active_variant_alias
                            .as_deref(),
                    )
                    .await;

                    info!(
                        "📡 Broadcast 4-stage payload capture for fabric flow (GW1) - channel: {}, config_id: {}",
                        channel_name, config_id
                    );
                }

                // Extract and verify backend agent identity from fabric response (multi-gateway only)
                // This verifies VPs sent by GW2 instead of computing raw identity
                let _agent_identity = if state
                    .surface
                    .managed_identity()
                    .is_some()
                {
                    match crate::proxy::fabric_identity::extract_fabric_backend_agent_identity(
                        &response_body,
                        &state.surface,
                        &state.identity_selector,
                        channel_name,
                    )
                    .await
                    {
                        Ok(identity_opt) => {
                            if let Some(ref agent_did) = identity_opt {
                                info!(
                                    channel = channel_name,
                                    did = agent_did,
                                    "Fabric: Verified backend agent identity from GW2"
                                );
                            }
                            identity_opt
                        }
                        Err(e) => {
                            // VP verification failed - reject the response (Policy: Option C)
                            error!(channel = channel_name, error = %e, "Fabric: Backend agent VP verification failed");
                            connection_guard
                                .decrement()
                                .await;
                            return Err(create_error_response(
                                StatusCode::BAD_GATEWAY,
                                &format!("Backend agent identity verification failed: {}", e),
                            ));
                        }
                    }
                } else {
                    None
                };

                if let Some(ref agent_did) = _agent_identity {
                    // Log for metrics/audit purposes
                    debug!(channel = channel_name, did = agent_did, "Fabric: Backend agent DID extracted and verified");
                }

                // Inspect response extensions if enabled (same as direct path)
                // Skip validation for agent card requests (they're JSON config, not A2A messages)
                let _inspect_span =
                    tracing::info_span!("fabric.inspect_response", otel.name = "Inspect Response Extensions");
                let is_agent_card_request = uri
                    .path()
                    .ends_with("/.well-known/agent-card.json")
                    || uri
                        .path()
                        .ends_with("/.well-known/agent.json");

                if is_agent_card_request {
                    debug!(
                        channel = channel_name,
                        "Skipping extension validation for agent card request in fabric path"
                    );
                }

                let _response_body_bytes = response_body.as_bytes();
                async {
                    if state
                        .config
                        .extension_inspection
                        .enabled
                        && !_response_body_bytes.is_empty()
                        && state
                            .identity_rules_engine
                            .is_some()
                        && !is_agent_card_request
                    {
                        // Dispatch to protocol-specific validator
                        let validation_result = if matches!(
                            state
                                .surface
                                .channel_protocol(),
                            crate::config::ChannelProtocol::Mcp
                        ) {
                            // MCP protocol - validate _meta.serverIdentity
                            crate::mcp::validation::validate_mcp_response(
                                _response_body_bytes,
                                channel_name,
                                &state.surface,
                                &state.identity_rules_engine,
                                &state.metrics_store,
                            )
                            .await
                        } else {
                            // A2A/UCP protocols - validate extensions arrays
                            let response_ctx = crate::protocols::extensions::ResponseExtensionInspectionContext {
                                config: &state.config,
                                channel_name,
                                surface: &state.surface,
                                response_rules_engine: &state.identity_rules_engine,
                                metrics_store: &state.metrics_store,
                            };
                            crate::protocols::extensions::inspect_response_extensions(
                                _response_body_bytes,
                                &response_ctx,
                            )
                            .await
                        };

                        match validation_result {
                            Ok(_) => {
                                channel_debug!(config_id, "Response extension inspection passed in fabric path");
                            }
                            Err(response) => {
                                channel_warn!(config_id, "Response extension inspection failed in fabric path");
                                connection_guard
                                    .decrement()
                                    .await;
                                return Err(response);
                            }
                        }
                    }
                    Ok(())
                }
                .instrument(_inspect_span)
                .await?;

                // Build response using Response::builder() like the test that worked
                let _build_span = tracing::info_span!("fabric.build_response", otel.name = "Build HTTP Response");
                drop(_build_span.enter());

                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let mut response_builder = Response::builder().status(status_code);

                // Add headers, filtering out hop-by-hop headers
                for (key, value) in response_headers {
                    let key_lower = key.to_lowercase();

                    // Skip hop-by-hop headers - these should not be forwarded
                    if key_lower == "transfer-encoding"
                        || key_lower == "connection"
                        || key_lower == "keep-alive"
                        || key_lower == "proxy-authenticate"
                        || key_lower == "proxy-authorization"
                        || key_lower == "te"
                        || key_lower == "trailers"
                        || key_lower == "upgrade"
                    {
                        continue;
                    }

                    // Skip the upstream content-length: this branch may have rewritten the
                    // body (URL rewriter, trust-registry extension, agentDid/agentDNA
                    // injection, GW1 DID array append, response custom metadata), so the
                    // upstream length no longer matches the bytes we are about to write.
                    // axum/hyper will set the correct content-length from the actual body.
                    if key_lower == "content-length" {
                        continue;
                    }

                    // For MCP fabric responses, skip the upstream content-type so we can
                    // override it below. GW2 consumed SSE into plain JSON, so forwarding
                    // text/event-stream would cause clients to treat the response as a
                    // streaming SSE connection and fail with IncompleteRead.
                    if key_lower == "content-type"
                        && state
                            .surface
                            .channel_protocol()
                            == crate::config::ChannelProtocol::Mcp
                    {
                        continue;
                    }

                    let values = if is_modern_response {
                        match value {
                            serde_json::Value::String(value) => vec![value],
                            serde_json::Value::Array(values) => values
                                .into_iter()
                                .filter_map(|value| {
                                    value
                                        .as_str()
                                        .map(str::to_string)
                                })
                                .collect(),
                            _ => Vec::new(),
                        }
                    } else {
                        value
                            .as_str()
                            .map(str::to_string)
                            .into_iter()
                            .collect()
                    };
                    for value_str in values {
                        channel_info!(config_id, "  Header: {}: {}", key, value_str);
                        response_builder = response_builder.header(key.as_str(), value_str);
                    }
                }

                // MCP fabric responses are always plain JSON (GW2 consumed any SSE stream)
                if state
                    .surface
                    .channel_protocol()
                    == crate::config::ChannelProtocol::Mcp
                {
                    response_builder = response_builder.header("Content-Type", "application/json");
                }

                // Apply Custom Metadata HTTP headers (when injection_target is Headers or Both).
                for (name, value) in &response_metadata_headers {
                    response_builder = response_builder.header(name.as_str(), value.as_str());
                }

                channel_debug!(config_id, "📝 Response body length: {} bytes", response_body.len());

                let response = response_builder
                    .body(Body::from(response_body.clone()))
                    .unwrap_or_else(|e| {
                        channel_error!(config_id, "Failed to build response: {}", e);
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from("Failed to build response"))
                            .unwrap()
                    });

                // Record successful connection in metrics (with identity hash from inspection)
                let _metrics_span = tracing::info_span!("fabric.record_metrics", otel.name = "Record Metrics");
                drop(_metrics_span.enter());

                if !is_modern_response && let Some(ref metrics) = state.metrics_store {
                    let latency_ms = start_time
                        .elapsed()
                        .as_millis() as u64;
                    let metrics = Arc::clone(metrics);
                    let channel_config_id = state
                        .surface
                        .config_id_string();
                    let source = source_addr.clone();
                    let dest = state
                        .surface
                        .target
                        .endpoint
                        .clone();
                    let identity = identity_hash.clone();
                    let trace = trace_id.clone();
                    let ucp_op = ucp_operation.clone();
                    let variant_alias = state
                        .active_variant_alias
                        .clone();

                    // Record single metric with total latency
                    tokio::spawn(async move {
                        metrics
                            .record_connection_with_ucp(
                                channel_config_id,
                                source,
                                dest,
                                crate::metrics::ConnectionStatus::Success,
                                Some(latency_ms),
                                identity,
                                crate::metrics::ConnectionDirection::Request,
                                trace,
                                ucp_op,
                                None,
                                None,
                                latency_ms,
                                variant_alias,
                            )
                            .await;
                    });
                }

                // Track task metrics: record bytes transferred for fabric requests
                if !is_modern_response
                    && let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id)
                {
                    let bytes_received = body_bytes.len() as u64;
                    let bytes_sent = response_body.len() as u64;
                    channel_debug!(
                        config_id,
                        "Recording fabric request bytes task_id={} bytes_sent={} bytes_received={} status={}",
                        task_id,
                        bytes_sent,
                        bytes_received,
                        status
                    );
                    task_monitor
                        .record_bytes(task_id, bytes_sent, bytes_received)
                        .await;
                }

                connection_guard
                    .decrement()
                    .await;
                Ok(response)
            }
            Ok(None) => {
                channel_warn!(
                    config_id,
                    "⏱️ Fabric forward timed out - no response received from gateway {}",
                    gateway_id
                );

                // Record timeout in metrics (with identity hash from request inspection)
                if let Some(ref metrics) = state.metrics_store {
                    let latency_ms = start_time
                        .elapsed()
                        .as_millis() as u64;
                    let metrics = Arc::clone(metrics);
                    let channel_config_id = state
                        .surface
                        .config_id_string();
                    let source = source_addr.clone();
                    let dest = state
                        .surface
                        .target
                        .endpoint
                        .clone();
                    let identity = identity_hash.clone();
                    let trace = trace_id.clone();
                    let ucp_op = ucp_operation.clone();
                    let variant_alias = state
                        .active_variant_alias
                        .clone();
                    tokio::spawn(async move {
                        metrics
                            .record_connection_with_ucp(
                                channel_config_id,
                                source,
                                dest,
                                crate::metrics::ConnectionStatus::GatewayFault,
                                Some(latency_ms),
                                identity,
                                crate::metrics::ConnectionDirection::Request,
                                trace,
                                ucp_op,
                                None,
                                None,
                                latency_ms,
                                variant_alias,
                            )
                            .await;
                    });
                }

                // Track task metrics: record bytes received even on timeout (no response bytes)
                if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
                    let bytes_received = body_bytes.len() as u64;
                    channel_debug!(
                        config_id,
                        "Recording fabric timeout bytes task_id={} bytes_received={}",
                        task_id,
                        bytes_received
                    );
                    task_monitor
                        .record_bytes(task_id, 0, bytes_received)
                        .await;
                }

                connection_guard
                    .decrement()
                    .await;
                Err(create_error_response(StatusCode::GATEWAY_TIMEOUT, "Gateway did not respond in time"))
            }
            Err(e) => {
                channel_error!(config_id, "❌ Fabric forward failed: {}", e);

                // Record failed connection in metrics (with identity hash from request inspection)
                if let Some(ref metrics) = state.metrics_store {
                    let latency_ms = start_time
                        .elapsed()
                        .as_millis() as u64;
                    let metrics = Arc::clone(metrics);
                    let channel_config_id = state
                        .surface
                        .config_id_string();
                    let source = source_addr.clone();
                    let dest = state
                        .surface
                        .target
                        .endpoint
                        .clone();
                    let identity = identity_hash.clone();
                    let trace = trace_id.clone();
                    let ucp_op = ucp_operation.clone();
                    let variant_alias = state
                        .active_variant_alias
                        .clone();
                    tokio::spawn(async move {
                        metrics
                            .record_connection_with_ucp(
                                channel_config_id,
                                source,
                                dest,
                                crate::metrics::ConnectionStatus::GatewayFault,
                                Some(latency_ms),
                                identity,
                                crate::metrics::ConnectionDirection::Request,
                                trace,
                                ucp_op,
                                None,
                                None,
                                latency_ms,
                                variant_alias,
                            )
                            .await;
                    });
                }

                // Track task metrics: record bytes received even on failure (no response bytes)
                if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
                    let bytes_received = body_bytes.len() as u64;
                    channel_debug!(
                        config_id,
                        "Recording fabric failure bytes task_id={} bytes_received={}",
                        task_id,
                        bytes_received
                    );
                    task_monitor
                        .record_bytes(task_id, 0, bytes_received)
                        .await;
                }

                connection_guard
                    .decrement()
                    .await;
                Err(create_error_response(StatusCode::BAD_GATEWAY, &format!("Fabric forwarding failed: {}", e)))
            }
        }
    };
    if let (Some(upstream), Some(request), Some(complete)) = (modern_upstream, modern_request, modern_completion) {
        let (mut parts, body) = upstream.into_parts();
        let completion = parts
            .extensions
            .remove::<crate::mcp::modern_sse::TransportCompletion>();
        for name in modern_payment_headers.keys() {
            parts.headers.remove(name);
            for value in modern_payment_headers.get_all(name) {
                parts
                    .headers
                    .append(name.clone(), value.clone());
            }
        }
        let status = parts.status;
        let mut processing_headers = parts.headers.clone();
        processing_headers.insert("content-type", axum::http::HeaderValue::from_static("application/json"));
        let result = crate::mcp::modern_sse::forwarding_response_with_completion(
            body.into_data_stream(),
            status,
            &parts.headers,
            request,
            modern_limits,
            discovery_support,
            move |message| async move {
                use crate::mcp::modern_sse::SseReadError;
                let headers = crate::proxy::fabric_stream::wire::encode_headers(&processing_headers)
                    .map_err(|_| SseReadError::ResponseRejected)?;
                let response_body = serde_json::to_string(&message).map_err(|_| SseReadError::InvalidMessage)?;
                let received = crate::gateways::connection_points::messages::ReceivedMessage::new(
                    "fabric-stream".to_string(),
                    String::new(),
                    MessageType::ForwardResponse.to_string(),
                    uuid::Uuid::new_v4().to_string(),
                    None,
                    Some(modern_response_peer_did),
                    Vec::new(),
                    None,
                    None,
                    serde_json::json!({"status": status.as_u16(), "headers": headers, "body": response_body}),
                    crate::gateways::connection_points::messages::MessageMetadata {
                        encrypted: true,
                        authenticated: true,
                        from_key: None,
                        extra: serde_json::Value::Null,
                    },
                );
                let response = process_response(Ok(Some(received)))
                    .instrument(_process_span)
                    .await
                    .map_err(|_| SseReadError::ResponseRejected)?;
                if response.status() != status {
                    return Err(SseReadError::ResponseRejected);
                }
                let headers = response.headers().clone();
                let bytes = axum::body::to_bytes(
                    response.into_body(),
                    modern_limits
                        .max_event_bytes
                        .get(),
                )
                .await
                .map_err(|_| SseReadError::EventTooLarge)?;
                Ok(crate::mcp::modern_sse::ProcessedResponse {
                    message: serde_json::from_slice(&bytes).map_err(|_| SseReadError::InvalidMessage)?,
                    headers: Some(headers),
                })
            },
            move |message| async move {
                use crate::mcp::modern_sse::SseReadError;
                let Some(prepared) = modern_delegation else {
                    return Ok(message);
                };
                let runtime = mcp_continuations
                    .as_deref()
                    .ok_or(SseReadError::ResponseRejected)?;
                let now = crate::proxy::credential_delegation::modern::now_secs()
                    .map_err(|_| SseReadError::ResponseRejected)?;
                prepared
                    .finish(&runtime.service, message, runtime.config.ttl_secs, now)
                    .await
                    .map_err(|_| SseReadError::ResponseRejected)
            },
            completion,
        )
        .await;
        return match result {
            Ok(response) => {
                let response = match subscription_lifetime {
                    Some(lifetime) => lifetime.wrap(response),
                    None => response,
                };
                Ok(crate::mcp::modern_sse::observe_response(response, complete))
            }
            Err(error) => {
                complete(crate::mcp::modern_sse::ResponseOutcome {
                    failed: true,
                    ..Default::default()
                });
                warn!(%error, "Modern Fabric Access Point response rejected");
                Err(create_error_response(StatusCode::BAD_GATEWAY, "Invalid modern Fabric response"))
            }
        };
    }
    process_response(forward_result)
        .instrument(_process_span)
        .await
}

/// Outcome of evaluating the surface's MCP tool-level policies. Carries the
/// allow flag plus the denying policy's reason / id / tool so the caller can
/// emit a single structured policy-audit event with full request context.
struct McpToolPolicyOutcome {
    allow: bool,
    reason: Option<String>,
    policy_id: Option<String>,
    tool_name: Option<String>,
    /// Name, version and content hash of the policy that denied the call.
    policy: crate::policies::PolicyAttestation,
}

/// Evaluate MCP tool-level policies for a request
/// Returns `allow = true` if allowed, `allow = false` if denied, `Err` if evaluation failed
async fn evaluate_mcp_tool_policies(
    state: &ProxyState,
    headers: &HeaderMap,
    body_bytes: &bytes::Bytes,
    channel_name: &str,
    source_addr: &str,
    uri: &axum::http::Uri,
    mcp_context: Option<&crate::surface_context::McpContext>,
) -> Result<McpToolPolicyOutcome, String> {
    // The tool policy gate is an allowlist scoped to `tools/call`. Everything
    // else — notifications (no `id`), bodies missing `method`, and non-`tools/call`
    // methods — is passed through here so the normal MCP validation/routing
    // produces the correct response (204 / -32600 / forward) instead of being
    // turned into a policy-evaluation error.
    if !crate::mcp::is_tools_call_request(body_bytes) {
        return Ok(McpToolPolicyOutcome {
            allow: true,
            reason: None,
            policy_id: None,
            tool_name: None,
            policy: Default::default(),
        });
    }

    // Parse the now-confirmed `tools/call` request to extract method/tool information.
    let tool_request = crate::mcp::McpToolRequest::from_json_rpc(body_bytes)
        .map_err(|e| format!("Failed to parse MCP request: {}", e))?;

    info!(
        channel = channel_name,
        method = %tool_request.method,
        "Evaluating MCP tool policies for method"
    );

    // Extract JWT claims from headers
    let jwt_claims = extract_jwt_claims_from_headers(headers);

    // Build policy context
    let context = crate::mcp::McpPolicyContext::new(
        tool_request.method.clone(),
        tool_request.params.clone(),
        jwt_claims,
        channel_name.to_string(),
        Some(
            state
                .surface
                .surface_id
                .clone(),
        ),
        "mcp".to_string(),
        source_addr.to_string(),
        "POST".to_string(),
        uri.path().to_string(),
    )
    .with_modern_request(mcp_context);

    let requested_tool_name = tool_request.tool_name();

    if requested_tool_name.is_none() {
        return Ok(McpToolPolicyOutcome {
            allow: false,
            reason: Some("MCP tools/call request is missing params.name".to_string()),
            policy_id: None,
            tool_name: None,
            policy: Default::default(),
        });
    }

    // Resolve the policy definition store from the surface policy
    // manager. Without it we can't look up Rego text for any entry, so
    // a configured `mcp_tool_policies` list with no store wired up is a
    // hard configuration error rather than a silent allow.
    let store = state
        .policy_manager
        .as_ref()
        .and_then(|pm| pm.policy_definition_store())
        .ok_or_else(|| "MCP tool policies configured but no policy_definition_store is wired up".to_string())?;

    let all_entries = state
        .surface
        .target
        .mcp_tool_policies
        .clone();

    let entries: Vec<_> = all_entries
        .iter()
        .filter(|entry| Some(entry.tool_name.as_str()) == requested_tool_name)
        .collect();

    // If no exact match, fall back to the wildcard entry ("*") which acts as the
    // default tool policy applied to any tool without an explicit per-tool entry.
    let entries: Vec<_> = if entries.is_empty() {
        all_entries
            .iter()
            .filter(|entry| entry.tool_name == "*")
            .collect()
    } else {
        entries
    };

    let policies_evaluated = entries.len();

    if entries.is_empty() {
        return Ok(McpToolPolicyOutcome {
            allow: false,
            reason: requested_tool_name.map(|tool| format!("No MCP tool policy configured for tool '{tool}'")),
            policy_id: None,
            tool_name: requested_tool_name.map(str::to_string),
            policy: Default::default(),
        });
    }

    // Evaluate each policy in declaration order. The surface model has
    // no per-entry priority or enforce flag — every listed entry is
    // enforced, and order is preserved from the source surface.
    for entry in entries {
        let policy_id = &entry.policy_definition_id;
        let definition = match store.get(policy_id).await {
            Some(d) => d,
            None => {
                return Err(format!(
                    "MCP tool policy '{}' references unknown policy_definition_id '{}'",
                    entry.tool_name, policy_id
                ));
            }
        };
        if !definition.enabled {
            debug!(
                channel = channel_name,
                tool = %entry.tool_name,
                policy_id = %policy_id,
                "Skipping disabled policy definition"
            );
            continue;
        }
        if definition.policy.is_empty() {
            return Err(format!(
                "MCP tool policy '{}' references policy_definition_id '{}' which has an empty Rego body",
                entry.tool_name, policy_id
            ));
        }

        let engine = crate::policies::OpaEngine::new();
        engine
            .load_policy(policy_id, &definition.policy)
            .map_err(|e| format!("Failed to load policy '{}': {}", policy_id, e))?;

        let decision = engine
            .evaluate_mcp_tool_policy(&context)
            .map_err(|e| format!("Policy '{}' evaluation failed: {}", policy_id, e))?;

        if !decision.allow {
            debug!(
                channel = channel_name,
                tool = %entry.tool_name,
                policy_id = %policy_id,
                method = %tool_request.method,
                reason = ?decision.reason,
                "MCP tool policy denied request"
            );
            return Ok(McpToolPolicyOutcome {
                allow: false,
                reason: decision.reason,
                policy_id: Some(policy_id.clone()),
                tool_name: Some(entry.tool_name.clone()),
                policy: crate::policies::PolicyAttestation::of(&definition),
            });
        }

        debug!(
            channel = channel_name,
            tool = %entry.tool_name,
            policy_id = %policy_id,
            method = %tool_request.method,
            "MCP tool policy allowed request"
        );
    }

    // All policies passed
    info!(
        channel = channel_name,
        method = %tool_request.method,
        policies_evaluated,
        "All MCP tool policies passed"
    );
    Ok(McpToolPolicyOutcome {
        allow: true,
        reason: None,
        policy_id: None,
        tool_name: None,
        policy: Default::default(),
    })
}

fn agent_card_fabric_forward_path(surface: &crate::config::agent_surface::AgentSurface) -> String {
    if surface.override_agent_card_location()
        && let Some(custom_path) = surface.agent_card_location_path()
    {
        if custom_path.starts_with('/') {
            custom_path.to_string()
        } else {
            format!("/{custom_path}")
        }
    } else {
        "/.well-known/agent-card.json".to_string()
    }
}

fn record_agent_card_gateway_fault(
    state: &ProxyState,
    source_addr: &str,
) {
    if let Some(ref metrics) = state.metrics_store {
        let metrics = Arc::clone(metrics);
        let channel_config_id = state
            .surface
            .surface_id
            .clone();
        let source = source_addr.to_string();
        let dest = state
            .surface
            .target
            .endpoint
            .clone();
        let trace_id = uuid::Uuid::new_v4().to_string();
        tokio::spawn(async move {
            metrics
                .record_connection(
                    channel_config_id,
                    source,
                    dest,
                    crate::metrics::ConnectionStatus::GatewayFault,
                    None,
                    Some("Anonymous".to_string()),
                    crate::metrics::ConnectionDirection::Request,
                    trace_id,
                    None,
                    None,
                    0,
                    None,
                )
                .await;
        });
    }
}

async fn fetch_agent_card_from_surface_target(
    state: &ProxyState,
    headers: &HeaderMap,
    source_addr: &str,
    channel_name: &str,
    target_url: &str,
) -> Result<JsonValue, Response> {
    debug!(channel = channel_name, target = %target_url, "Fetching agent card from upstream");

    let source_cred_header = state
        .surface
        .source_auth()
        .and_then(|sa| sa.credential_header_name());

    if state
        .surface
        .target
        .endpoint
        .starts_with("fabric://")
    {
        let forwarded_headers = headers
            .iter()
            .filter(|(key, _)| should_forward_header(key.as_str(), source_cred_header))
            .filter_map(|(key, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (key.as_str().to_string(), value.to_string()))
            })
            .collect::<HashMap<_, _>>();
        let trace_id = uuid::Uuid::new_v4().to_string();
        let path = agent_card_fabric_forward_path(&state.surface);
        let response = crate::proxy::fabric_forward::forward_via_fabric(
            &state.listener_manager,
            crate::proxy::fabric_forward::FabricForwardRequest {
                fabric_target: &state.surface.target.endpoint,
                method: &Method::GET,
                path: &path,
                headers: forwarded_headers,
                body: bytes::Bytes::new(),
                timeout: std::time::Duration::from_secs(30),
                trace_id: &trace_id,
                log_label: channel_name,
            },
        )
        .await
        .map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to fetch agent card from fabric upstream - bad gateway");
            record_agent_card_gateway_fault(state, source_addr);
            create_error_response(StatusCode::BAD_GATEWAY, &format!("Failed to fetch from upstream: {}", e))
        })?;

        let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
        if !status.is_success() {
            error!(channel = channel_name, status = %status, "Fabric upstream returned error for agent card - gateway fault");
            record_agent_card_gateway_fault(state, source_addr);
            return Err(create_error_response(status, &format!("Upstream error: {status}")));
        }

        serde_json::from_slice(&response.body).map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to parse fabric agent card JSON");
            create_error_response(StatusCode::BAD_GATEWAY, "Invalid JSON from upstream")
        })
    } else {
        let credential = agent_card_target_credential(state, source_addr, channel_name).await?;
        let mut req = match credential {
            Some(_) => pinned_target_client(state, channel_name, target_url)
                .await
                .inspect_err(|_| record_agent_card_gateway_fault(state, source_addr))?
                .get(target_url),
            None => state.client.get(target_url),
        };

        for (key, value) in headers.iter() {
            let forward = match credential {
                Some(_) => is_forwarded_on_credentialed_card_fetch(key.as_str()),
                None => should_forward_header(key.as_str(), source_cred_header),
            };
            if forward {
                req = req.header(key.as_str(), value.as_bytes());
            }
        }
        if let Some((header_name, header_value)) = &credential {
            req = req.header(header_name.as_str(), header_value.as_str());
            debug!(channel = channel_name, header = %header_name, "Injected target authentication header on agent card fetch");
        }

        let response = req
            .send()
            .await
            .map_err(|e| {
                error!(channel = channel_name, error = %e, "Failed to fetch agent card from upstream - bad gateway");
                record_agent_card_gateway_fault(state, source_addr);
                create_error_response(StatusCode::BAD_GATEWAY, &format!("Failed to fetch from upstream: {}", e))
            })?;

        if response
            .status()
            .is_redirection()
        {
            error!(channel = channel_name, status = %response.status(), "Upstream redirected the agent card fetch - gateway fault");
            record_agent_card_gateway_fault(state, source_addr);
            return Err(create_error_response(StatusCode::BAD_GATEWAY, "Upstream redirected"));
        }
        if !response.status().is_success() {
            error!(channel = channel_name, status = %response.status(), "Upstream returned error for agent card - gateway fault");
            record_agent_card_gateway_fault(state, source_addr);
            return Err(create_error_response(response.status(), &format!("Upstream error: {}", response.status())));
        }

        let limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(
            state.config.a2a.max_body_size,
            state.surface.timeout(),
            state
                .config
                .a2a
                .timeout_seconds,
        );
        let body = crate::proxy::upstream_body::read_bounded(response, limits)
            .await
            .map_err(|e| {
                error!(channel = channel_name, error = %e, "Failed to read agent card from upstream - gateway fault");
                record_agent_card_gateway_fault(state, source_addr);
                let (status, message) = e.status_and_message();
                create_error_response(status, message)
            })?;
        serde_json::from_slice(&body).map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to parse agent card JSON");
            create_error_response(StatusCode::BAD_GATEWAY, "Invalid JSON from upstream")
        })
    }
}

/// The surface's target credential for the gateway's own agent-card fetch, or
/// `None` when the surface has none. Honours `target.auth.fallback` exactly as
/// the forwarded path does: `reject` fails the card with 502 rather than asking
/// the target without the credential it requires.
async fn agent_card_target_credential(
    state: &ProxyState,
    source_addr: &str,
    channel_name: &str,
) -> Result<Option<(String, String)>, Response> {
    let Some(target_auth) = state.surface.target_auth() else {
        return Ok(None);
    };
    match inject_target_auth_header(target_auth, &state.secrets_store, channel_name, CallerAssertion::GatewayOriginated)
        .await
    {
        Ok(credential) => Ok(credential),
        Err(e) => {
            error!(channel = channel_name, error = %e, "Failed to resolve target authentication for agent card fetch");
            match target_auth.fallback {
                crate::config::TargetAuthFallback::Reject => {
                    record_agent_card_gateway_fault(state, source_addr);
                    Err(create_error_response(StatusCode::BAD_GATEWAY, "Target authentication failed"))
                }
                crate::config::TargetAuthFallback::Passthrough => {
                    warn!(
                        channel = channel_name,
                        "Target auth failed but passthrough enabled, fetching agent card without credentials"
                    );
                    Ok(None)
                }
            }
        }
    }
}

/// A redirect-disabled client pinned to the vetted address of `target_url`, or
/// the 403 to answer when egress policy blocks it. Pinning stops DNS rebinding
/// between vetting and connect; disabling redirects stops a 3xx from sending
/// the request, and any credential on it, to an unvetted host.
async fn pinned_target_client(
    state: &ProxyState,
    channel_name: &str,
    target_url: &str,
) -> Result<reqwest::Client, Response> {
    let candidate = target_url.to_string();
    let timeout = std::time::Duration::from_secs(
        state
            .config
            .a2a
            .timeout_seconds,
    );
    match tokio::task::spawn_blocking(move || crate::egress::pinned_forward_client(&candidate, timeout)).await {
        Ok(Ok((client, _target))) => Ok(client),
        Ok(Err(e)) => {
            warn!(channel = channel_name, target = %target_url, "SSRF blocked by egress policy: {}", e);
            Err(create_error_response(StatusCode::FORBIDDEN, "Request blocked by egress policy"))
        }
        Err(e) => {
            warn!(channel = channel_name, target = %target_url, "SSRF egress validation task failed: {}", e);
            Err(create_error_response(StatusCode::FORBIDDEN, "Request blocked by egress policy"))
        }
    }
}

/// Caller headers forwarded on an agent-card fetch that carries the target
/// credential. The caller is anonymous, so only content negotiation passes;
/// nothing the caller sends can override the credential or ride along on a
/// request the gateway has authenticated.
fn is_forwarded_on_credentialed_card_fetch(name: &str) -> bool {
    ["accept", "accept-language", "user-agent"]
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

async fn prepare_a2a_proxy_agent_card(
    state: &ProxyState,
    channel_name: &str,
) -> Result<Option<crate::a2a_proxies::agent_card::PreparedA2aProxyAgentCard>, Response> {
    crate::a2a_proxies::resolve_prepared_agent_card_for_endpoint(
        state.a2a_proxy_store.clone(),
        &state.surface.target.endpoint,
        &state.surface,
        channel_name,
        state.vc_issuer.as_ref(),
    )
    .await
    .map_err(|err| {
        let status = match err {
            crate::a2a_proxies::A2aProxyTargetError::NotFound | crate::a2a_proxies::A2aProxyTargetError::Disabled => {
                StatusCode::BAD_GATEWAY
            }
            crate::a2a_proxies::A2aProxyTargetError::StoreUnavailable
            | crate::a2a_proxies::A2aProxyTargetError::InvalidEndpoint
            | crate::a2a_proxies::A2aProxyTargetError::LoadFailed
            | crate::a2a_proxies::A2aProxyTargetError::AgentCardPreparationFailed => StatusCode::INTERNAL_SERVER_ERROR,
        };
        create_error_response(status, &err.to_string())
    })
}

async fn prepare_a2a_proxy_agent_card_for_target_context(
    state: &ProxyState,
    channel_name: &str,
) -> Option<JsonValue> {
    crate::a2a_proxies::resolve_prepared_agent_card_for_endpoint(
        state.a2a_proxy_store.clone(),
        &state.surface.target.endpoint,
        &state.surface,
        channel_name,
        state.vc_issuer.as_ref(),
    )
    .await
    .ok()
    .flatten()
    .map(|prepared| prepared.card)
}

async fn handle_a2a_proxy_target_request(
    state: &ProxyState,
    proxy_id: &str,
    body_bytes: &[u8],
    channel_name: &str,
) -> Response {
    let adapter = match crate::a2a_proxies::A2aProxyTargetAdapter::from_optional_store(state.a2a_proxy_store.clone()) {
        Ok(adapter) => adapter,
        Err(err) => return crate::a2a_proxies::target_adapter::json_rpc_target_error(body_bytes, err),
    };

    adapter
        .dispatch_message_send(proxy_id, body_bytes, state.secrets_store.as_ref(), channel_name)
        .await
}

async fn record_a2a_proxy_connection_metric(
    state: &ProxyState,
    proxy_id: &str,
    response: Response,
    source_addr: &str,
    start_time: std::time::Instant,
    trace_id: &str,
    request_bytes: u64,
) -> Response {
    let Some(metrics) = state.metrics_store.as_ref() else {
        return response;
    };

    let latency_ms = start_time
        .elapsed()
        .as_millis() as u64;
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(proxy_id = proxy_id, error = %e, "Failed to read A2A proxy response body for metrics");
            bytes::Bytes::new()
        }
    };
    let status = a2a_proxy_connection_status(parts.status, &body_bytes);
    let response_bytes = body_bytes.len() as u64;

    metrics
        .record_connection_with_bytes(
            state
                .surface
                .surface_id
                .clone(),
            source_addr.to_string(),
            format!("a2a-proxy:{proxy_id}"),
            status,
            Some(latency_ms),
            None,
            crate::metrics::ConnectionDirection::Request,
            trace_id.to_string(),
            request_bytes,
            response_bytes,
            None,
            None,
            latency_ms,
            state
                .active_variant_alias
                .clone(),
        )
        .await;

    Response::from_parts(parts, axum::body::Body::from(body_bytes))
}

pub(crate) fn a2a_proxy_connection_status(
    http_status: StatusCode,
    body_bytes: &[u8],
) -> crate::metrics::ConnectionStatus {
    if !http_status.is_success() {
        return crate::metrics::ConnectionStatus::Failed;
    }

    match serde_json::from_slice::<serde_json::Value>(body_bytes) {
        Ok(body) if body.get("error").is_some() => crate::metrics::ConnectionStatus::Failed,
        _ => crate::metrics::ConnectionStatus::Success,
    }
}

/// Evaluate inbound OPA + surface OPA policies for a `proxy://` MCP request.
/// Returns the evaluated `PolicyInput` when both policies allow, so MCP tool
/// gating decides on the same context, or `Err(Response)` with a 403 deny.
async fn evaluate_mcp_proxy_opa_policies(
    state: &ProxyState,
    method: &str,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body_bytes: &[u8],
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    source_auth_context: Option<&crate::surface_context::SourceAuthContext>,
    mcp_context: Option<&crate::surface_context::McpContext>,
    payment_context: Option<&crate::surface_context::PaymentContext>,
    trace_id: &str,
) -> Result<crate::surface_context::PolicyInput, Response> {
    /// Build a deny response for the MCP proxy OPA gate. For `tools/call`
    /// requests, returns a JSON-RPC error (HTTP 200); for everything else,
    /// returns HTTP 403 with a JSON error body.
    fn mcp_proxy_deny_response(
        body_bytes: &[u8],
        reason: Option<&str>,
        message: &str,
    ) -> Response {
        if crate::mcp::is_tools_call_request(body_bytes) {
            crate::mcp::build_tools_call_policy_denied_response(body_bytes, reason)
        } else {
            axum::response::Response::builder()
                .status(axum::http::StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(format!(r#"{{"error":"Forbidden","message":"{}"}}"#, message)))
                .unwrap()
        }
    }

    let mut policy_input = crate::surface_context::PolicyInput::new(
        method,
        uri.path(),
        crate::surface_context::filter_sensitive_headers(headers),
        "inbound",
        None,
        None,
        state
            .surface
            .config_id()
            .map(|s| s.to_string()),
        &state.surface.name,
    );
    policy_input.source_auth = source_auth_context.cloned();
    policy_input.mcp = mcp_context.cloned();
    policy_input.payment = payment_context.cloned();
    // Build `input.agent` from the caller's `_meta` trust-registry extension so
    // caller-leg Trust Check templates (`{{ input.agent.provider_did }}`) resolve
    // for MCP proxy surfaces, exactly as the direct/plain-MCP path does.
    {
        let body_json: Option<serde_json::Value> = serde_json::from_slice(body_bytes).ok();
        policy_input.agent = Some(
            crate::policies::build_agent_context_for_protocol(
                crate::config::ChannelProtocol::Mcp,
                body_json.as_ref(),
                None,
                state
                    .trust_registry_listener_manager
                    .as_deref(),
                // Caller leg: skip the TR-extension / identity-credential
                // cross-check so a payload carrying a TR extension without a
                // matching identity credential still surfaces `provider_did` to
                // the caller-leg Trust Check template (matches the plain-MCP /
                // A2A direct-inbound caller seam above).
                false,
            )
            .await,
        );
    }
    policy_input.normalize_caller_did();

    // ── Trust Check stage (caller leg) ─────────────────────────────────────
    // MCP `proxy://` surfaces short-circuit before the generic caller-leg seam
    // in `proxy_handler_with_mcp_runtime`, so run the check here and surface the results to
    // the OPA gates below. Skipped on discovery requests (unauthenticated).
    {
        let caller_elements = &state
            .surface
            .access_point
            .trust_check_list;
        if !caller_elements.is_empty()
            && !crate::proxy::paths::is_public_request(method, uri.path())
            && let Some(manager) = state
                .trust_registry_listener_manager
                .clone()
        {
            let client = crate::trust_registry_verification::TrqpListenerClient::new(manager);
            policy_input.trust_check_results = crate::trust_registry_verification::run_caller_trust_check(
                state
                    .surface
                    .surface_id
                    .as_str(),
                caller_elements,
                &policy_input,
                &client,
            )
            .await;
        }
    }

    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();

    // ── Inbound OPA (access_point.inbound_policy) ──────────────────────────
    if state
        .surface
        .inbound_opa_enabled()
        && let Some(config_id_str) = state.surface.config_id()
    {
        let Some(policy_manager) = state.policy_manager.as_ref() else {
            channel_warn!(
                config_id_str,
                "Access-point inbound OPA policy is configured but policy manager is not available — denying request"
            );
            return Err(mcp_proxy_deny_response(body_bytes, None, "Agent trust policy denied the request"));
        };
        let inbound_policy_def_id = state
            .surface
            .inbound_opa_policy_definition_id();
        let (inbound_policy_name, inbound_policy_version, inbound_policy_hash) = policy_manager
            .resolve_policy_decision_evidence(inbound_policy_def_id)
            .await;
        match policy_manager.evaluate_inbound_policy_decision_for_variant(
            config_id_str,
            state
                .active_variant_alias
                .as_deref(),
            input_value.clone(),
        ) {
            Ok(decision) if decision.allow => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: true,
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: inbound_policy_def_id,
                    policy_name: Some(inbound_policy_name.as_str()),
                    policy_version: inbound_policy_version,
                    policy_content_hash: inbound_policy_hash.as_deref(),
                    surface_id: Some(config_id_str),
                    trace_id: Some(trace_id),
                    http_method: Some(method),
                    path: Some(uri.path()),
                    identity: authenticated_identity,
                    ..Default::default()
                });
            }
            Ok(decision) => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: false,
                    reason: decision.reason.as_deref(),
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: inbound_policy_def_id,
                    policy_name: Some(inbound_policy_name.as_str()),
                    policy_version: inbound_policy_version,
                    policy_content_hash: inbound_policy_hash.as_deref(),
                    surface_id: Some(config_id_str),
                    trace_id: Some(trace_id),
                    http_method: Some(method),
                    path: Some(uri.path()),
                    identity: authenticated_identity,
                    ..Default::default()
                });
                return Err(mcp_proxy_deny_response(
                    body_bytes,
                    decision.reason.as_deref(),
                    "Agent trust policy denied the request",
                ));
            }
            Err(e) => {
                channel_warn!(
                    config_id_str,
                    "Access-point inbound OPA policy evaluation error (denying request): {}",
                    e
                );
                return Err(mcp_proxy_deny_response(
                    body_bytes,
                    Some("policy evaluation error"),
                    "Agent trust policy denied the request",
                ));
            }
        }
    }

    // ── Surface OPA (target.policy) ────────────────────────────────────────
    if state.surface.opa_enabled()
        && let Some(config_id_str) = state.surface.config_id()
    {
        let Some(policy_manager) = state
            .policy_manager
            .as_ref()
            .filter(|pm| {
                pm.has_policy_for_variant(
                    config_id_str,
                    state
                        .active_variant_alias
                        .as_deref(),
                )
            })
        else {
            channel_warn!(config_id_str, "OPA is enabled but no compiled policy found for channel — denying request");
            return Err(mcp_proxy_deny_response(
                body_bytes,
                Some("no policy is loaded for this channel"),
                "OPA policy enforcement is enabled but no policy is loaded for this channel",
            ));
        };
        let channel_opa_def_id = state
            .surface
            .opa_policy_definition_id();
        let (channel_opa_name, channel_opa_version, channel_opa_hash) = policy_manager
            .resolve_policy_decision_evidence(channel_opa_def_id)
            .await;
        match policy_manager.evaluate_policy_decision_for_variant(
            config_id_str,
            state
                .active_variant_alias
                .as_deref(),
            input_value,
        ) {
            Ok(decision) if decision.allow => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: true,
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: channel_opa_def_id,
                    policy_name: Some(channel_opa_name.as_str()),
                    surface_id: Some(config_id_str),
                    trace_id: Some(trace_id),
                    http_method: Some(method),
                    path: Some(uri.path()),
                    identity: authenticated_identity,
                    policy_version: channel_opa_version,
                    policy_content_hash: channel_opa_hash.as_deref(),
                    ..Default::default()
                });
            }
            Ok(decision) => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Surface,
                    allow: false,
                    reason: decision.reason.as_deref(),
                    policy_id: Some(crate::policies::SURFACE_POLICY_PACKAGE),
                    policy_definition_id: channel_opa_def_id,
                    policy_name: Some(channel_opa_name.as_str()),
                    policy_version: channel_opa_version,
                    policy_content_hash: channel_opa_hash.as_deref(),
                    surface_id: Some(config_id_str),
                    trace_id: Some(trace_id),
                    http_method: Some(method),
                    path: Some(uri.path()),
                    identity: authenticated_identity,
                    ..Default::default()
                });
                return Err(mcp_proxy_deny_response(
                    body_bytes,
                    decision.reason.as_deref(),
                    "Agent trust policy denied the request",
                ));
            }
            Err(e) => {
                channel_warn!(config_id_str, "Surface-level OPA policy evaluation error (denying request): {}", e);
                return Err(mcp_proxy_deny_response(
                    body_bytes,
                    Some("policy evaluation error"),
                    "Agent trust policy denied the request",
                ));
            }
        }
    }

    Ok(policy_input)
}

/// Handle MCP request through an MCP proxy backend
/// This routes the request through rmcp-openapi Server instead of directly forwarding
async fn handle_mcp_proxy_request(
    state: &ProxyState,
    proxy_id: &str,
    body_bytes: &[u8],
    headers: &HeaderMap,
    method: &Method,
    uri: &axum::http::Uri,
    channel_name: &str,
    source_addr: &str,
    start_time: std::time::Instant,
    trace_id: String,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    policy_input: &crate::surface_context::PolicyInput,
    mcp_context: Option<&crate::surface_context::McpContext>,
) -> Result<Response, Response> {
    use crate::mcp_proxies::filesystem::McpProxyStore;

    let store = state
        .mcp_proxy_store
        .as_ref()
        .ok_or_else(|| {
            error!(
                channel = channel_name,
                proxy_id = proxy_id,
                "MCP proxy store not configured on ProxyState — this is a bug; \
                 the orchestrator must wire bootstrap_config.storage_paths.mcp_proxies \
                 into MultiSurfaceProxyState::mcp_proxy_store at boot"
            );
            create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to access MCP proxy storage")
        })?;

    let proxy = store
        .get(proxy_id)
        .await
        .map_err(|e| {
            error!(channel = channel_name, proxy_id = proxy_id, error = %e, "Failed to load MCP proxy");
            create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load MCP proxy configuration")
        })?
        .ok_or_else(|| {
            error!(channel = channel_name, proxy_id = proxy_id, "MCP proxy not found");
            create_error_response(StatusCode::NOT_FOUND, &format!("MCP proxy '{}' not found", proxy_id))
        })?;

    if matches!(proxy.status, crate::mcp_proxies::types::McpProxyStatus::Disabled) {
        let id = serde_json::from_slice::<serde_json::Value>(body_bytes)
            .ok()
            .and_then(|v| v.get("id").cloned());
        warn!(
            channel = channel_name,
            proxy_id = proxy_id,
            proxy_name = %proxy.name,
            "MCP proxy is disabled; rejecting request"
        );
        return Err(crate::mcp::errors::create_mcp_error_response(
            id,
            crate::mcp::errors::error_codes::INTERNAL_ERROR,
            "MCP proxy is disabled",
            None,
        ));
    }

    info!(
        channel = channel_name,
        proxy_id = proxy_id,
        proxy_name = %proxy.name,
        "Loaded MCP proxy configuration"
    );

    // Parse the JSON-RPC request to route it through rmcp-openapi
    let json_request: serde_json::Value = serde_json::from_slice(body_bytes).map_err(|e| {
        error!(channel = channel_name, error = %e, "Failed to parse JSON-RPC request");
        let error_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": -32700,
                "message": "Parse error"
            }
        });
        axum::response::Json(error_response).into_response()
    })?;

    // Evaluate MCP tool-level policies before forwarding to the proxy
    // backend. The regular http:// path runs this in `proxy_handler_with_mcp_runtime`,
    // but proxy:// targets short-circuit there before the policy gate, so
    // enforcement has to happen here.
    if !state
        .surface
        .target
        .mcp_tool_policies
        .is_empty()
    {
        let body_bytes_owned = bytes::Bytes::copy_from_slice(body_bytes);
        match evaluate_mcp_tool_policies(state, headers, &body_bytes_owned, channel_name, source_addr, uri, mcp_context)
            .await
        {
            Ok(outcome) if outcome.allow => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::McpTool,
                    allow: true,
                    surface_id: Some(channel_name),
                    trace_id: Some(&trace_id),
                    path: Some(uri.path()),
                    identity: authenticated_identity,
                    ..Default::default()
                });
                info!(channel = channel_name, "MCP tool policy check passed");
            }
            Ok(outcome) => {
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::McpTool,
                    allow: false,
                    reason: outcome.reason.as_deref(),
                    policy_id: outcome
                        .policy_id
                        .as_deref()
                        .or(outcome.tool_name.as_deref()),
                    policy_name: outcome.policy.name.as_deref(),
                    policy_version: outcome.policy.version,
                    policy_content_hash: outcome
                        .policy
                        .content_hash
                        .as_deref(),
                    surface_id: Some(channel_name),
                    trace_id: Some(&trace_id),
                    path: Some(uri.path()),
                    identity: authenticated_identity,
                    ..Default::default()
                });
                warn!(
                    channel = channel_name,
                    reason = ?outcome.reason,
                    policy_id = ?outcome.policy_id,
                    tool = ?outcome.tool_name,
                    "MCP tool policy check failed - access denied"
                );
                return Err(crate::mcp::errors::create_mcp_error_response(
                    json_request
                        .get("id")
                        .cloned(),
                    -32000,
                    "Access denied: insufficient permissions for this tool",
                    None,
                ));
            }
            Err(e) => {
                error!(channel = channel_name, error = %e, "Failed to evaluate MCP tool policy");
                return Err(crate::mcp::errors::create_mcp_error_response(
                    json_request
                        .get("id")
                        .cloned(),
                    crate::mcp::errors::error_codes::INTERNAL_ERROR,
                    "Internal error: policy evaluation failed",
                    None,
                ));
            }
        }
    }

    let rpc_method = json_request
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string();
    let tool_gating = surface_mcp_tool_gating(state).map(|gating| {
        let input = mcp_tool_gating_input(&gating, policy_input);
        (gating, input)
    });
    if rpc_method == "tools/call"
        && let Some((gating, input)) = tool_gating.as_ref()
    {
        let tool_name = json_request
            .pointer("/params/name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        let allowed = gating.is_tool_call_allowed(tool_name, input);
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::McpTool,
            allow: allowed,
            reason: if allowed {
                None
            } else {
                Some("blocked by MCP tool gating")
            },
            policy_id: Some("mcp_tool_gating"),
            surface_id: Some(channel_name),
            trace_id: Some(&trace_id),
            http_method: Some("POST"),
            path: Some(uri.path()),
            identity: authenticated_identity,
            ..Default::default()
        });
        if !allowed {
            warn!(channel = channel_name, tool = tool_name, "MCP tool gating blocked tools/call on MCP proxy");
            return Err(crate::mcp::build_tools_call_policy_denied_response(body_bytes, Some("Tool is not available")));
        }
    }

    // Get config_id for payload capture
    let config_id = state
        .surface
        .config_id()
        .unwrap_or("unknown");

    // Resolve target auth header if configured on the channel
    let target_auth_header = if let Some(target_auth) = state.surface.target_auth() {
        match inject_target_auth_header(
            target_auth,
            &state.secrets_store,
            channel_name,
            CallerAssertion::for_request(method.as_str(), uri.path()),
        )
        .await
        {
            Ok(header) => header,
            Err(e) => {
                error!(channel = channel_name, error = %e, "Failed to resolve target auth for MCP proxy");
                match target_auth.fallback {
                    crate::config::TargetAuthFallback::Reject => {
                        return Err(create_error_response(
                            StatusCode::BAD_GATEWAY,
                            "Target authentication configuration error",
                        ));
                    }
                    crate::config::TargetAuthFallback::Passthrough => {
                        warn!(
                            channel = channel_name,
                            "Target auth failed but passthrough enabled, continuing without credentials"
                        );
                        None
                    }
                }
            }
        }
    } else {
        None
    };

    // Use the MCP proxy request handler with full policy support (timeout, retry, circuit breaker, mirroring)
    match crate::mcp_proxies::handlers::handle_mcp_request_with_policies(
        &proxy,
        json_request.clone(),
        &state.surface,
        state.policy_manager.as_ref(),
        &state.client,
        channel_name,
        target_auth_header,
    )
    .await
    {
        Ok(mut response_json) => {
            info!(channel = channel_name, proxy_id = proxy_id, "✅ MCP proxy request successful");

            if rpc_method == "tools/list"
                && let Some((gating, input)) = tool_gating.as_ref()
                && let Some((before, after)) = gating.filter_tools_list_value(&mut response_json, input)
                && after < before
            {
                info!(channel = channel_name, before, after, "MCP tool gating filtered tools/list on MCP proxy");
            }

            // ── Response OPA policy ────────────────────────────────────────
            if let Some(response_policy_id) = state
                .surface
                .response_policy_definition_id()
                && let Some(ref pm) = state.policy_manager
            {
                use crate::proxy::response_policy::{
                    CallerContext as RpCallerContext, ResponseContext, ResponsePolicyInput, SurfaceContext,
                    evaluate_response_policy,
                };

                let policy_key = format!("response:{}", response_policy_id);
                let input = ResponsePolicyInput {
                    response: ResponseContext {
                        status_code: 200,
                        body: Some(response_json.clone()),
                        content_type: Some("application/json".to_string()),
                        is_error: false,
                        method: None,
                    },
                    caller: RpCallerContext {
                        did: None,
                        identity_source: authenticated_identity.map(|id| format!("{:?}", id)),
                        dna_uai: None,
                    },
                    surface: SurfaceContext {
                        id: state
                            .surface
                            .surface_id
                            .clone(),
                        name: channel_name.to_string(),
                        protocol: format!(
                            "{:?}",
                            state
                                .surface
                                .channel_protocol()
                        )
                        .to_lowercase(),
                    },
                    metadata: None,
                };

                let response_policy = pm
                    .resolve_policy_attestation(Some(response_policy_id))
                    .await;
                let decision = evaluate_response_policy(pm.as_ref(), &policy_key, input);
                if !decision.allow {
                    crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                        scope: crate::observability::PolicyScope::Response,
                        allow: false,
                        reason: decision.reason.as_deref(),
                        policy_id: Some(response_policy_id),
                        policy_definition_id: Some(response_policy_id),
                        policy_name: response_policy
                            .name
                            .as_deref(),
                        policy_version: response_policy.version,
                        policy_content_hash: response_policy
                            .content_hash
                            .as_deref(),
                        surface_id: Some(channel_name),
                        trace_id: Some(&trace_id),
                        http_method: Some("POST"),
                        path: Some(uri.path()),
                        identity: authenticated_identity,
                        ..Default::default()
                    });
                    let error_response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": json_request.get("id"),
                        "error": {
                            "code": -32000,
                            "message": decision.reason.unwrap_or_else(|| "Response blocked by policy".to_string())
                        }
                    });
                    return Err(axum::response::Json(error_response).into_response());
                }
                crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                    scope: crate::observability::PolicyScope::Response,
                    allow: true,
                    policy_id: Some(response_policy_id),
                    policy_definition_id: Some(response_policy_id),
                    policy_name: response_policy
                        .name
                        .as_deref(),
                    policy_version: response_policy.version,
                    policy_content_hash: response_policy
                        .content_hash
                        .as_deref(),
                    surface_id: Some(channel_name),
                    trace_id: Some(&trace_id),
                    http_method: Some("POST"),
                    path: Some(uri.path()),
                    identity: authenticated_identity,
                    ..Default::default()
                });
            }

            // Trust Recorder — writes TrAdmin records to configured TRs on the
            // MCP-proxy response leg. This path short-circuits before the
            // generic recorder seam in `proxy_handler_with_mcp_runtime`, so run it here.
            // Fire-and-forget; idempotent — duplicate records log at DEBUG
            // (`apply_trust_recorder`).
            if state
                .surface
                .trust_recorder()
                .is_some_and(|cfg| !cfg.entries.is_empty())
            {
                let response_bytes = serde_json::to_vec(&response_json).unwrap_or_default();
                let recorder_selector = state
                    .protected_selector
                    .as_ref()
                    .or(state
                        .identity_selector
                        .as_ref());
                let recorder_rules = state
                    .protected_rules_engine
                    .as_ref()
                    .or(state
                        .identity_rules_engine
                        .as_ref());
                let resolved = if response_bytes.is_empty() {
                    None
                } else {
                    crate::proxy::backend_identity::resolve_protected_agent_identity(
                        &response_bytes,
                        &state.surface,
                        recorder_selector,
                        recorder_rules,
                        channel_name,
                        false,
                        authenticated_identity,
                    )
                    .await
                    .ok()
                };
                if let Some(ProtectedAgentIdentity::Managed { did, .. }) = resolved {
                    crate::trust_registry_verification::spawn_trust_recorder(
                        &state.surface,
                        &did,
                        state
                            .trust_registry_listener_manager
                            .clone(),
                    );
                }
            }

            // Broadcast payload capture for MCP channels
            // Note: MCP doesn't have A2A-style extension validation, so we always report "success" for completed requests
            crate::observability::payload_capture::broadcast_payload_capture_async(
                &state.ws_state,
                &state.metrics_store,
                channel_name,
                config_id,
                &json_request,
                Some(response_json.clone()),
                "success", // MCP protocol doesn't have A2A extension validation
                None,
                None, // identity_hash - MCP channels might not have identity tracking
                state
                    .active_variant_alias
                    .as_deref(),
            )
            .await;

            // Record successful connection in metrics
            if let Some(ref metrics) = state.metrics_store {
                let latency_ms = start_time
                    .elapsed()
                    .as_millis() as u64;
                let metrics = Arc::clone(metrics);
                let channel_config_id = state
                    .surface
                    .surface_id
                    .clone();
                let source = source_addr.to_string();
                let dest = format!("mcp-proxy:{}", proxy_id);
                let trace = trace_id.clone();

                // Record single metric with total latency
                tokio::spawn(async move {
                    metrics
                        .record_connection(
                            channel_config_id,
                            source,
                            dest,
                            crate::metrics::ConnectionStatus::Success,
                            Some(latency_ms),
                            None,
                            crate::metrics::ConnectionDirection::Request,
                            trace,
                            None,
                            None,
                            latency_ms,
                            None,
                        )
                        .await;
                });
            }

            // Track task metrics: record bytes transferred
            if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
                let bytes_received = body_bytes.len() as u64;
                let bytes_sent = serde_json::to_vec(&response_json)
                    .map(|v| v.len() as u64)
                    .unwrap_or(0);
                debug!(
                    channel = channel_name,
                    task_id = task_id,
                    bytes_sent = bytes_sent,
                    bytes_received = bytes_received,
                    "Recording MCP request bytes"
                );
                task_monitor
                    .record_bytes(task_id, bytes_sent, bytes_received)
                    .await;
            }

            Ok(axum::response::Json(response_json).into_response())
        }
        Err(e) => {
            error!(
                channel = channel_name,
                proxy_id = proxy_id,
                error = %e,
                "❌ MCP proxy request failed"
            );

            // Broadcast payload capture for failed MCP requests
            // Note: This is a JSON-RPC error, not an A2A extension validation failure
            crate::observability::payload_capture::broadcast_payload_capture_async(
                &state.ws_state,
                &state.metrics_store,
                channel_name,
                config_id,
                &json_request,
                None,
                "mcp_error", // Custom status to differentiate MCP errors from A2A validation failures
                Some(format!("MCP Proxy Error: {}", e)),
                None,
                state
                    .active_variant_alias
                    .as_deref(),
            )
            .await;

            // Record failed connection in metrics
            if let Some(ref metrics) = state.metrics_store {
                let latency_ms = start_time
                    .elapsed()
                    .as_millis() as u64;
                let metrics = Arc::clone(metrics);
                let channel_config_id = state
                    .surface
                    .surface_id
                    .clone();
                let source = source_addr.to_string();
                let dest = format!("mcp-proxy:{}", proxy_id);
                let trace = trace_id.clone();

                // Record single metric with total latency
                tokio::spawn(async move {
                    metrics
                        .record_connection(
                            channel_config_id,
                            source,
                            dest,
                            crate::metrics::ConnectionStatus::Failed,
                            Some(latency_ms),
                            None,
                            crate::metrics::ConnectionDirection::Request,
                            trace,
                            None,
                            None,
                            latency_ms,
                            None,
                        )
                        .await;
                });
            }

            let error_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32603,
                    "message": format!("MCP proxy error: {}", e)
                }
            });

            // Track task metrics: record bytes transferred (even for errors)
            if let (Some(task_monitor), Some(task_id)) = (&state.task_monitor, &state.task_id) {
                let bytes_received = body_bytes.len() as u64;
                let bytes_sent = serde_json::to_vec(&error_response)
                    .map(|v| v.len() as u64)
                    .unwrap_or(0);
                debug!(
                    channel = channel_name,
                    task_id = task_id,
                    bytes_sent = bytes_sent,
                    bytes_received = bytes_received,
                    "Recording MCP error response bytes"
                );
                task_monitor
                    .record_bytes(task_id, bytes_sent, bytes_received)
                    .await;
            }
            Err(axum::response::Json(error_response).into_response())
        }
    }
}

/// The surface's MCP tool gating, when it has any gates installed.
fn surface_mcp_tool_gating(state: &ProxyState) -> Option<Arc<crate::policies::mcp_tool_gating::CompiledMcpToolGating>> {
    let config_id = state.surface.config_id()?;
    state
        .policy_manager
        .as_ref()?
        .compiled_mcp_tool_gating(
            config_id,
            state
                .active_variant_alias
                .as_deref(),
        )
        .filter(|g| !g.is_empty())
}

/// The request context a gate condition is evaluated against: the same
/// `PolicyInput` the `proxy://` inbound and surface OPA gates saw. Pure
/// name-based gating needs none, so it is only serialized when a gate carries
/// a condition.
fn mcp_tool_gating_input(
    gating: &crate::policies::mcp_tool_gating::CompiledMcpToolGating,
    policy_input: &crate::surface_context::PolicyInput,
) -> serde_json::Value {
    if !gating.has_policy_conditions() {
        return serde_json::Value::Null;
    }
    serde_json::to_value(policy_input).unwrap_or_default()
}

/// Check if client supports VP credential extension (for response VP injection)
fn does_client_support_vp_extension(
    protocol: &crate::config::ChannelProtocol,
    body_bytes: &bytes::Bytes,
    channel_name: &str,
) -> bool {
    match protocol {
        crate::config::ChannelProtocol::Mcp => {
            debug!(channel = channel_name, "MCP protocol: VP injection enabled by default");
            true
        }
        crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2 => {
            check_a2a_credential_extension_support(body_bytes, channel_name)
        }
        _ => false,
    }
}

/// Check if A2A client supports credential extension
fn check_a2a_credential_extension_support(
    body_bytes: &bytes::Bytes,
    channel_name: &str,
) -> bool {
    let Ok(body_json) = serde_json::from_slice::<JsonValue>(body_bytes) else {
        return false;
    };

    // Navigate to extensions array (try params.message first, then message)
    let extensions = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .and_then(|m| m.get("extensions"))
        .and_then(|e| e.as_array())
        .or_else(|| {
            body_json
                .get("message")
                .and_then(|m| m.get("extensions"))
                .and_then(|e| e.as_array())
        });

    let Some(ext_array) = extensions else {
        return false;
    };

    let has_credential_ext = ext_array
        .iter()
        .any(|e| e.as_str() == Some(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION));

    if has_credential_ext {
        debug!(channel = channel_name, "A2A client supports credential extension (VP)");
    }

    has_credential_ext
}

/// Inject backend agent VP into response if conditions are met
///
/// Uses the pre-resolved protected agent identity from Step 12.
/// Injects the VP into the response using protocol-specific handlers.
async fn inject_backend_agent_vp(
    response_body: bytes::Bytes,
    client_supports_vp: bool,
    resolved_identity: &ProtectedAgentIdentity,
    state: &ProxyState,
    channel_name: &str,
    caller_id: Option<&str>,
    inbound_chained_vcs: Vec<serde_json::Value>,
    trace_id: &str,
    mcp_metadata_context: crate::mcp::meta::McpMetadataContext,
) -> Result<(bytes::Bytes, Option<String>), Response> {
    // Early return: client doesn't support VP
    if !client_supports_vp {
        return Ok((response_body, None));
    }

    // Early return: no resolved identity
    let (did, identity_fields) = match resolved_identity {
        ProtectedAgentIdentity::Managed { did, identity_fields } => (did, identity_fields),
        ProtectedAgentIdentity::Anonymous => return Ok((response_body, None)),
    };

    // Build the fabric-style workload binding for the response-leg VP:
    // agentIdentity (the managed agent) + userIdentity.id (the resolved inbound
    // caller) + delegated + traceId + policyDecisions.
    let workload_binding: Option<serde_json::Value> =
        build_response_workload_binding(identity_fields, caller_id, trace_id);

    info!(
        channel = channel_name,
        did = %did,
        "Client supports VP and backend agent has DID, injecting VP into response"
    );

    // Check prerequisites for VP injection
    if !has_vp_injection_prerequisites(state, channel_name) {
        return Ok((response_body, None));
    }

    // Inject VP using pre-resolved identity fields
    let selector = state
        .identity_selector
        .as_ref();
    let Some(selector) = selector else {
        debug!(channel = channel_name, "No identity selector available for VP injection");
        return Ok((response_body, None));
    };

    let vc_issuer = selector.get_vc_issuer();

    let vp_result = match state
        .surface
        .channel_protocol()
    {
        crate::config::ChannelProtocol::Mcp => {
            let (protected_meta_field, protected_strip_raw) = state
                .surface
                .protected_identity()
                .and_then(|c| {
                    if let crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) = c {
                        Some((cfg.meta_field.clone(), cfg.strip_raw_meta))
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| ("serverIdentity".to_string(), false));
            crate::mcp::inject_vp_into_mcp_response(
                &response_body,
                did,
                identity_fields,
                workload_binding.clone(),
                &vc_issuer,
                channel_name,
                inbound_chained_vcs.clone(),
                &protected_meta_field,
                protected_strip_raw,
                mcp_metadata_context,
            )
            .await
        }
        crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2 => {
            crate::a2a::extensions::inject_vp_into_a2a_response(
                &response_body,
                did,
                identity_fields,
                workload_binding.clone(),
                &vc_issuer,
                channel_name,
                inbound_chained_vcs.clone(),
            )
            .await
            .map(|(body, proof)| (body, Some(proof)))
        }
        _ => {
            debug!(channel = channel_name, protocol = ?state.surface.channel_protocol(), "VP injection not supported for this protocol");
            return Ok((response_body, None));
        }
    };

    match vp_result {
        Ok((modified_body, vp_jwt)) => {
            info!(channel = channel_name, did = %did, "Backend agent VP injected into response");
            Ok((modified_body, vp_jwt))
        }
        Err(e) => {
            if state
                .surface
                .channel_protocol()
                == crate::config::ChannelProtocol::Mcp
            {
                warn!(channel = channel_name, error = %e, "MCP response identity injection failed");
                return Err(create_error_response(StatusCode::BAD_GATEWAY, "MCP response identity injection failed"));
            }
            warn!(channel = channel_name, error = %e, "Failed to inject backend agent VP into response, using original body");
            Ok((response_body, None))
        }
    }
}

/// Check if all prerequisites for VP injection are available
fn has_vp_injection_prerequisites(
    state: &ProxyState,
    channel_name: &str,
) -> bool {
    let has_ext_rules_schema = state
        .surface
        .response_extension_rules()
        .and_then(|rules| rules.json_schema.as_ref())
        .is_some()
        || state
            .surface
            .managed_identity()
            .and_then(|mi| match mi {
                crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg
                    .extension_rules
                    .and_then(|er| er.json_schema)
                    .or(cfg.json_schema),
                _ => None,
            })
            .is_some();

    let has_selector = state
        .identity_selector
        .is_some();

    let has_prerequisites = has_ext_rules_schema && has_selector;

    if !has_prerequisites {
        debug!(
            channel = channel_name,
            "Missing required components for VP injection (managed_identity.extension_rules.json_schema or identity_selector)"
        );
    }

    has_prerequisites
}

/// Inject an identity binding VP into an outbound request body.
///
/// For MCP: adds `_meta[BINDING_EXT_URI].verifiablePresentation = vp_jwt`
/// For A2A/AP2: adds the binding extension URI to `extensions` array and
///              sets `metadata[BINDING_EXT_URI].verifiablePresentation = vp_jwt`
fn inject_identity_binding_vp_into_request(
    body_bytes: &bytes::Bytes,
    vp_jwt: &str,
    protocol: &crate::config::ChannelProtocol,
    channel_name: &str,
    meta_field_to_strip: Option<&str>,
    context: crate::mcp::meta::McpMetadataContext,
) -> anyhow::Result<bytes::Bytes> {
    let mut body_json: serde_json::Value = serde_json::from_slice(body_bytes)?;
    let binding_uri = crate::config::AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION;

    match protocol {
        crate::config::ChannelProtocol::Mcp => {
            crate::mcp::meta::normalize_metadata(&mut body_json, context)?;
            if let Some(field) = meta_field_to_strip {
                crate::mcp::meta::validate_raw_identity_key(field, context)?;
                crate::mcp::meta::remove_metadata_key(&mut body_json, field);
            }
            let target = if body_json
                .get("params")
                .is_some()
            {
                crate::mcp::meta::McpMetaTarget::Params
            } else {
                crate::mcp::meta::McpMetaTarget::TopLevel
            };
            crate::mcp::meta::insert_gateway_metadata(
                &mut body_json,
                context,
                target,
                binding_uri,
                serde_json::json!({"verifiablePresentation": vp_jwt}),
            )?;

            debug!(channel = channel_name, "VP binding injected into MCP _meta");
        }
        crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2 => {
            // Navigate to message object (try params.message, then message)
            let has_params_message = body_json
                .get("params")
                .and_then(|p| p.get("message"))
                .is_some();

            let message = if has_params_message {
                body_json
                    .get_mut("params")
                    .and_then(|p| p.get_mut("message"))
            } else {
                body_json.get_mut("message")
            };

            if let Some(message) = message {
                if let Some(msg_obj) = message.as_object_mut() {
                    // Add binding URI to extensions array
                    let extensions = msg_obj
                        .entry("extensions")
                        .or_insert(serde_json::json!([]));
                    if let Some(ext_arr) = extensions.as_array_mut() {
                        let uri_val = serde_json::Value::String(binding_uri.to_string());
                        if !ext_arr.contains(&uri_val) {
                            ext_arr.push(uri_val);
                        }
                    }

                    // Add VP to metadata
                    let metadata = msg_obj
                        .entry("metadata")
                        .or_insert(serde_json::json!({}));
                    if let Some(meta_obj) = metadata.as_object_mut() {
                        meta_obj.insert(binding_uri.to_string(), serde_json::json!({"verifiablePresentation": vp_jwt}));
                    }
                    debug!(channel = channel_name, "VP binding injected into A2A message extensions/metadata");
                }
            } else {
                debug!(channel = channel_name, "No message object found in A2A body for VP binding injection");
            }
        }
        _ => {
            debug!(channel = channel_name, protocol = ?protocol, "VP binding injection not supported for this protocol");
        }
    }

    Ok(serde_json::to_vec(&body_json)?.into())
}

/// Build the request-leg `workloadBinding` credential-subject for the MA→EXT
/// VP. Only produced when the primary target configures an enabled Workload
/// Binding element: the configurable subject binds the managed-agent identity to
/// caller context captured from the inbound `Authorization` bearer JWT (no
/// transit token on this leg), plus the resolved `delegationAction`. Returns
/// `None` when no WB element is configured, so the VP keeps the flat
/// `identityFields` credential-subject shape. Shared by the direct
/// (`proxy_handler_with_mcp_runtime`) and `fabric://` (`handle_fabric_request`) request
/// legs; the fabric leg passes `delegation_actions = None`.
fn build_target_request_workload_binding(
    surface: &crate::config::agent_surface::AgentSurface,
    headers: &HeaderMap,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    trace_id: &str,
    delegation_actions: Option<serde_json::Value>,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> Option<serde_json::Value> {
    let cfg = surface.target_workload_binding()?;
    let captured = match cfg.caller_source {
        crate::config::types::CallerContextSource::AuthorizationBearerJwt
        | crate::config::types::CallerContextSource::TransitToken => headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|auth| {
                crate::proxy::workload_binding::capture_from_bearer_jwt(auth, &cfg.caller_context_fields).ok()
            }),
        crate::config::types::CallerContextSource::Did => authenticated_identity
            .and_then(|id| crate::proxy::workload_binding::capture_from_did(id, &cfg.caller_context_fields).ok()),
    };
    crate::proxy::workload_binding::maybe_build_workload_binding_subject(
        Some(cfg),
        crate::proxy::workload_binding::WorkloadBindingInputs {
            agent_identity_fields: Some(identity_fields),
            caller: captured.as_ref(),
            trace_id: Some(trace_id),
            target: Some(surface.target_endpoint()),
            policy_decisions: crate::observability::policy_audit::current_policy_decisions(),
            delegation_actions,
            ..Default::default()
        },
    )
}

/// Build the fabric-style `workloadBinding` credential-subject for a response-
/// or outbound-leg VP: `agentIdentity` (the managed agent, raw dot-notation
/// fields) plus, when a caller id is present, `userIdentity.id` + `delegated`,
/// and `traceId` / `policyDecisions` when available for this request. Matches the
/// GW2 fabric response-leg shape (see
/// `gateways::connection_points::message_processor`) so the direct and fabric
/// paths carry the same envelope. Always returns `Some(..)`, so the injected VP
/// uses the `workloadBinding` credential-subject shape rather than the flat
/// `identityFields`.
fn build_response_workload_binding(
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    caller_id: Option<&str>,
    trace_id: &str,
) -> Option<serde_json::Value> {
    let mut binding = serde_json::Map::new();
    binding.insert(
        "agentIdentity".to_string(),
        serde_json::to_value(identity_fields).unwrap_or_else(|_| serde_json::json!({})),
    );
    if let Some(id) = caller_id.filter(|d| !d.is_empty()) {
        binding.insert("userIdentity".to_string(), serde_json::json!({ "id": id }));
        binding.insert("delegated".to_string(), serde_json::Value::Bool(true));
    }
    if !trace_id.is_empty() {
        binding.insert("traceId".to_string(), serde_json::Value::String(trace_id.to_string()));
    }
    if let Some(decisions) = crate::observability::policy_audit::current_policy_decisions() {
        binding.insert("policyDecisions".to_string(), decisions);
    }
    Some(serde_json::Value::Object(binding))
}

fn source_auth_user_id(identity: Option<&crate::source_auth::AuthenticatedIdentity>) -> Option<String> {
    identity.map(|id| match id {
        crate::source_auth::AuthenticatedIdentity::JwtBearer { subject, .. } => subject.clone(),
        crate::source_auth::AuthenticatedIdentity::ApiKey { key_name } => key_name.clone(),
        crate::source_auth::AuthenticatedIdentity::DidAuth { did } => did.clone(),
        crate::source_auth::AuthenticatedIdentity::Mtls { principal, .. } => principal.clone(),
    })
}

fn source_auth_user_hash(identity: Option<&crate::source_auth::AuthenticatedIdentity>) -> Option<String> {
    source_auth_user_id(identity).map(|raw| {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    })
}

/// Compute caller context fields for the transit token.
///
/// Builds the union of all Transit Points' `workload_binding.caller_context_fields`
/// allowlists (only those with `caller_source = transit_token` and `enabled = true`),
/// then populates from the authenticated identity's JWT claims (only `JwtBearer`
/// carries claims today). The TP side re-filters per its own allowlist via
/// `select_allowlisted`, so a superset in the token is safe.
fn compute_transit_token_caller_context(
    surface: &crate::config::agent_surface::AgentSurface,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> serde_json::Map<String, serde_json::Value> {
    use std::collections::HashSet;

    let union_allowlist: HashSet<&str> = surface
        .transit_points()
        .iter()
        .filter_map(|tp| tp.workload_binding.as_ref())
        .filter(|wb| wb.enabled && wb.caller_source == crate::config::types::CallerContextSource::TransitToken)
        .flat_map(|wb| {
            wb.caller_context_fields
                .iter()
                .map(|s| s.as_str())
        })
        .collect();

    if union_allowlist.is_empty() {
        return serde_json::Map::new();
    }

    authenticated_identity
        .and_then(|id| id.jwt_claims())
        .and_then(|v| v.as_object())
        .map(|claims| {
            let mut map = serde_json::Map::new();
            for name in &union_allowlist {
                if let Some(value) = claims.get(*name) {
                    map.insert((*name).to_string(), value.clone());
                }
            }
            map
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod caller_assertion_tests {
    use super::CallerAssertion;

    #[test]
    fn only_a_discovery_read_is_the_ucp_discovery_operation() {
        use axum::http::Method;
        for method in [Method::GET, Method::HEAD] {
            assert_eq!(
                super::extract_ucp_operation("/surface/agent.json", &method).as_deref(),
                Some("discovery"),
                "{method}"
            );
        }
        // A POST that only ends like a discovery document is not discovery, so
        // it still gets the agent context OPA and Trust Check read.
        assert_ne!(super::extract_ucp_operation("/surface/agent.json", &Method::POST).as_deref(), Some("discovery"));
    }

    #[test]
    fn a_discovery_read_is_not_an_asserted_caller() {
        for path in ["/payments/garlic/station/discovery", "/surface/.well-known/agent-card.json"] {
            for method in ["GET", "HEAD"] {
                assert_eq!(
                    CallerAssertion::for_request(method, path),
                    CallerAssertion::Unauthenticated,
                    "{method} {path} skips source authentication, so there is no caller to vouch for"
                );
            }
        }
    }

    #[test]
    fn a_normal_request_carries_an_asserted_caller() {
        for path in ["/payments/garlic/station", "/payments/garlic/not-really/discovery/x"] {
            assert_eq!(CallerAssertion::for_request("GET", path), CallerAssertion::Authenticated, "{path}");
        }
        // A POST to a discovery-like path runs source authentication.
        assert_eq!(CallerAssertion::for_request("POST", "/surface/agent.json"), CallerAssertion::Authenticated);
    }

    #[test]
    fn only_an_asserted_or_gateway_originated_request_carries_the_target_credential() {
        assert!(CallerAssertion::Authenticated.permits_target_credential());
        assert!(CallerAssertion::GatewayOriginated.permits_target_credential());
        assert!(!CallerAssertion::Unauthenticated.permits_target_credential());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Ap2InboundDecision, CHANNEL_SSE_SESSION_MGR, a2a_proxy_connection_status, agent_card_fabric_forward_path,
        agent_card_response, ap2_experimental_enabled_from_flags, decode_bearer_jwt_claims,
        evaluate_ap2_inbound_decision, is_forwarded_on_credentialed_card_fetch, normalize_route_for_match,
        resolve_direct_surface_auth_config, resolve_legacy_mcp_session, route_tail_to_uri_path,
        should_forward_ap_request_header_with_mapping,
    };
    use axum::http::{HeaderMap, HeaderValue};
    use base64::Engine;
    use std::collections::HashMap;

    #[test]
    fn credentialed_card_fetch_forwards_only_content_negotiation_headers() {
        for name in ["Accept", "accept-language", "User-Agent"] {
            assert!(is_forwarded_on_credentialed_card_fetch(name), "{name} must be forwarded");
        }
        for name in
            ["cookie", "authorization", "x-target-api-key", "x-forwarded-for", "x-forwarded-user", "x-remote-user"]
        {
            assert!(!is_forwarded_on_credentialed_card_fetch(name), "{name} must be withheld");
        }
    }

    fn agent_card_response_headers(request_headers: &[(&'static str, &'static str)]) -> (String, Vec<String>) {
        let mut headers = HeaderMap::new();
        for (name, value) in request_headers {
            headers.insert(*name, HeaderValue::from_static(value));
        }
        let response = agent_card_response(serde_json::json!({"name": "card"}), &headers);
        let content_type = response.headers()[axum::http::header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .to_string();
        let vary = response
            .headers()
            .get_all(axum::http::header::VARY)
            .iter()
            .map(|v| {
                v.to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        (content_type, vary)
    }

    #[test]
    fn agent_card_response_varies_on_version_and_accept_for_a2a_json() {
        for request_headers in [[("a2a-version", "1.0")], [("accept", "application/a2a+json")]] {
            let (content_type, vary) = agent_card_response_headers(&request_headers);
            assert_eq!(content_type, "application/a2a+json");
            assert_eq!(vary, vec!["A2A-Version, Accept".to_string()]);
        }
    }

    #[test]
    fn agent_card_response_varies_on_version_and_accept_for_plain_json() {
        for request_headers in [&[][..], &[("a2a-version", "0.3")], &[("accept", "application/json")]] {
            let (content_type, vary) = agent_card_response_headers(request_headers);
            assert_eq!(content_type, "application/json");
            assert_eq!(vary, vec!["A2A-Version, Accept".to_string()]);
        }
    }

    fn direct_router_state(
        state: &crate::state::ProxyState,
        surface: crate::config::agent_surface::AgentSurface,
    ) -> crate::state::MultiSurfaceProxyState {
        use std::sync::Arc;

        crate::state::MultiSurfaceProxyState {
            config: state.config.clone(),
            network_config: state.network_config.clone(),
            client: state.client.clone(),
            channels: Arc::new(tokio::sync::RwLock::new(vec![crate::state::SurfaceInfo {
                surface: Arc::new(surface),
                identity_rules_engine: None,
                identity_selector: None,
                protected_rules_engine: None,
                protected_selector: None,
                external_rules_engine: None,
                external_selector: None,
                task_id: "router-fixture".into(),
                variant_engines: HashMap::new(),
            }])),
            metrics_store: state.metrics_store.clone(),
            task_monitor: state.task_monitor.clone(),
            ws_state: state.ws_state.clone(),
            listener_manager: state.listener_manager.clone(),
            secrets_store: state.secrets_store.clone(),
            certificates_store: state
                .certificates_store
                .clone(),
            vc_issuer: state.vc_issuer.clone(),
            policy_manager: state.policy_manager.clone(),
            gateway_policy_manager: state
                .gateway_policy_manager
                .clone(),
            didauth_session_store: state
                .didauth_session_store
                .clone(),
            transaction_store: state
                .transaction_store
                .clone(),
            mpp_transaction_store: state
                .mpp_transaction_store
                .clone(),
            trust_registry_listener_manager: state
                .trust_registry_listener_manager
                .clone(),
            source_auth_middleware: state
                .source_auth_middleware
                .clone(),
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: state
                .didwebvh_identity_store
                .clone(),
            #[cfg(feature = "didwebvh")]
            didwebvh_log_manager: state
                .didwebvh_log_manager
                .clone(),
            credential_provider_store: state
                .credential_provider_store
                .clone(),
            delegation_vault_store: state
                .delegation_vault_store
                .clone(),
            gateway_base_url: state.gateway_base_url.clone(),
            transit_token_issuer: state
                .transit_token_issuer
                .clone(),
            mcp_proxy_store: state.mcp_proxy_store.clone(),
            a2a_proxy_store: state.a2a_proxy_store.clone(),
            resolved_surface_cache: Arc::new(crate::surfaces::ResolvedSurfaceCache::new()),
        }
    }

    async fn modern_access_point_router_keeps_legacy_variant_fallback(state: &crate::state::ProxyState) {
        use serde_json::json;
        use std::sync::atomic::Ordering;

        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "router-request", "result": {
                "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"
            }})
            .to_string(),
        )
        .await;
        let surface = serde_json::from_value(json!({
            "surface_id": "router-variants", "name": "Router variants",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": target.url()}
        }))
        .unwrap();
        let router = direct_router_state(state, surface);
        let mut broken: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "router-broken-default", "name": "Router broken default",
            "access_point": {"listen_address": "https://gateway.example", "route": "/broken", "protocol": "mcp"},
            "target": {"endpoint": target.url()}
        }))
        .unwrap();
        broken.default_variant_id = Some("removed".into());
        assert!(broken.variants.is_empty());
        let broken = direct_router_state(state, broken);
        let address = "127.0.0.1:12345"
            .parse()
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        for (router, path, modern, expected) in [
            (&router, "/mcp", true, axum::http::StatusCode::OK),
            (&router, "/mcp$missing", false, axum::http::StatusCode::OK),
            (&router, "/mcp$missing", true, axum::http::StatusCode::NOT_FOUND),
            (&broken, "/broken", false, axum::http::StatusCode::OK),
            (&broken, "/broken", true, axum::http::StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let before = target
                .request_count
                .load(Ordering::SeqCst);
            let mut body = json!({"jsonrpc": "2.0", "id": "router-request", "method": "tools/list"});
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream");
            if modern {
                body["params"] = json!({"_meta": {
                    "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }});
                request = request
                    .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                    .header("mcp-method", "tools/list");
            }
            let response = Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                address,
                router.clone(),
                request
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
                versions,
                None,
            ))
            .await;
            let status = response.status();
            let streamed = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/event-stream"));
            let bytes = axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap();
            let text = String::from_utf8_lossy(&bytes).to_string();
            assert_eq!(status, expected, "{path} modern={modern}: {text}");
            let text = if streamed {
                crate::mcp::sse_transport::extract_last_json_rpc_from_sse_bytes(&bytes)
                    .unwrap_or_else(|| panic!("{path} modern={modern} unframed SSE body {text:?}"))
            } else {
                text
            };
            let response: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|error| {
                panic!("{path} modern={modern} body {text:?}: {error}");
            });
            assert_eq!(response["id"], "router-request");
            assert_eq!(
                target
                    .request_count
                    .load(Ordering::SeqCst),
                before + usize::from(expected.is_success())
            );
        }
    }

    fn modern_tools_list_request(
        path: &str,
        id: &str,
    ) -> axum::http::Request<axum::body::Body> {
        let body = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
            .header("mcp-method", "tools/list")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    async fn mounted_access_point_uses_the_direct_access_point_policy(state: &crate::state::ProxyState) {
        use serde_json::json;
        use std::sync::atomic::Ordering;

        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "mounted", "result": {
                "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"
            }})
            .to_string(),
        )
        .await;
        let surface = serde_json::from_value(json!({
            "surface_id": "mounted-policy", "name": "Mounted policy",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mounted", "protocol": "mcp"},
            "target": {"endpoint": target.url()}
        }))
        .unwrap();
        let response = super::multi_channel_proxy_handler(
            axum::extract::ConnectInfo(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
            ),
            axum::extract::State(direct_router_state(state, surface)),
            modern_tools_list_request("/mounted", "mounted"),
        )
        .await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let forwarded = target
            .request_count
            .load(Ordering::SeqCst);
        assert_eq!(status, axum::http::StatusCode::OK, "{text}");
        assert_eq!(forwarded, 1);
    }

    async fn direct_access_point_caps_legacy_initialize(state: &crate::state::ProxyState) {
        use serde_json::json;

        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": 1, "result": {
                "protocolVersion": crate::mcp::MCP_LEGACY_VERSION, "capabilities": {},
                "serverInfo": {"name": "target", "version": "1"}
            }})
            .to_string(),
        )
        .await;
        let surface = json!({
            "surface_id": "initialize-cap", "name": "Initialize cap",
            "access_point": {"listen_address": "https://gateway.example", "route": "/initialize", "protocol": "mcp"},
            "target": {"endpoint": target.url()}
        });
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "client", "version": "1"}
        }});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/initialize")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let response = super::multi_channel_proxy_handler(
            axum::extract::ConnectInfo(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
            ),
            axum::extract::State(direct_router_state(state, serde_json::from_value(surface).unwrap())),
            request,
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let forwarded = target
            .last_request_rx
            .borrow()
            .clone()
            .expect("initialize reached the Target");
        let forwarded: serde_json::Value = serde_json::from_str(&forwarded.body).unwrap();
        assert_eq!(forwarded["method"], "initialize");
        assert_eq!(forwarded["params"]["protocolVersion"], crate::mcp::MCP_LEGACY_VERSION);
        assert_eq!(forwarded["params"]["clientInfo"], body["params"]["clientInfo"]);
    }

    /// The direct Access Point is a transparent proxy for the modern routing
    /// headers: `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` reach the upstream
    /// unchanged, alongside the version header.
    async fn modern_routing_headers_reach_the_upstream(state: &crate::state::ProxyState) {
        use serde_json::json;

        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "routing", "result": {
                "resultType": "complete", "content": [{"type": "text", "text": "ok"}]
            }})
            .to_string(),
        )
        .await;
        let surface = serde_json::from_value(json!({
            "surface_id": "routing-headers", "name": "Routing headers",
            "access_point": {"listen_address": "https://gateway.example", "route": "/routing", "protocol": "mcp"},
            "target": {"endpoint": target.url()}
        }))
        .unwrap();
        let body = json!({"jsonrpc": "2.0", "id": "routing", "method": "tools/call", "params": {
            "name": "echo", "arguments": {"region": "eu"}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/routing")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
            .header("mcp-method", "tools/call")
            .header("mcp-name", "echo")
            .header("mcp-param-region", "eu")
            // Session and resumption state a legacy client might still send.
            .header("mcp-session-id", "legacy-session")
            .header("last-event-id", "7")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let response = Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            direct_router_state(state, surface),
            request,
            versions,
            None,
        ))
        .await;
        let status = response.status();
        let delivered = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        assert_eq!(status, axum::http::StatusCode::OK, "{}", String::from_utf8_lossy(&delivered));
        let forwarded = target
            .last_request_rx
            .borrow()
            .clone()
            .expect("the request reached the upstream");
        for (name, value) in [
            ("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION),
            ("mcp-method", "tools/call"),
            ("mcp-name", "echo"),
            ("mcp-param-region", "eu"),
        ] {
            assert_eq!(
                forwarded
                    .headers
                    .get(name)
                    .map(String::as_str),
                Some(value),
                "{name} reaches the upstream"
            );
        }
        for name in ["mcp-session-id", "last-event-id"] {
            assert!(
                !forwarded
                    .headers
                    .contains_key(name),
                "{name} does not reach the upstream"
            );
        }
    }

    /// An Access Point targeting `proxy://` is backed by a gateway-owned server,
    /// so it answers modern `server/discover` itself with its truthful
    /// versions, capabilities and `serverInfo`.
    async fn proxy_access_point_answers_modern_discovery(state: &crate::state::ProxyState) {
        use crate::mcp_proxies::filesystem::McpProxyStore;
        use serde_json::json;

        let directory = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(
            crate::mcp_proxies::FileSystemMcpProxyStore::new(directory.path().to_path_buf())
                .await
                .unwrap(),
        );
        let spec = json!({"openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {
            "/alpha": {"get": {"operationId": "alpha", "summary": "Alpha tool", "responses": {"200": {"description": "OK"}}}}
        }});
        let proxy = crate::mcp_proxies::types::McpProxy::new(
            "Owned tools".into(),
            String::new(),
            "https://example.com".into(),
            spec.to_string(),
            "/mcp".into(),
            "/owned-discovery".into(),
        );
        store
            .create(&proxy)
            .await
            .unwrap();
        let state = crate::state::ProxyState {
            mcp_proxy_store: Some(store),
            ..state.clone()
        };
        let surface = serde_json::from_value(json!({
            "surface_id": "proxy-discovery", "name": "Proxy discovery",
            "access_point": {"listen_address": "https://gateway.example", "route": "/proxy-discovery", "protocol": "mcp"},
            "target": {"endpoint": format!("proxy://{}", proxy.id)}
        }))
        .unwrap();
        let body = json!({"jsonrpc": "2.0", "id": "discover", "method": "server/discover", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/proxy-discovery")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
            .header("mcp-method", "server/discover")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let response = Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            direct_router_state(&state, surface),
            request,
            crate::mcp::request_validation::McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
            ),
            None,
        ))
        .await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let discovery: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("discovery body: {}", String::from_utf8_lossy(&bytes)));
        assert_eq!(status, axum::http::StatusCode::OK, "{discovery}");
        assert_eq!(discovery["id"], "discover");
        assert_eq!(discovery["result"]["resultType"], "complete", "{discovery}");
        assert!(
            discovery["result"]["supportedVersions"]
                .as_array()
                .is_some_and(|versions| versions.contains(&json!(crate::mcp::MCP_MODERN_VERSION))),
            "{discovery}"
        );
        assert!(discovery["result"]["capabilities"]["tools"].is_object(), "{discovery}");
        assert_eq!(
            discovery["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "Owned tools",
            "{discovery}"
        );
    }

    /// Extensions survive forwarding: the client's
    /// declared extensions reach the upstream, an extension result type
    /// (`task`) reaches the client, and an extension method is relayed.
    async fn modern_extensions_survive_forwarding(state: &crate::state::ProxyState) {
        use serde_json::json;

        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        // Extension negotiation is between the client and the upstream: the
        // gateway originates no extension traffic, so it forwards an extension
        // request whether or not the client declared the extension, and never
        // adds or removes a declaration.
        let declared = json!({"extensions": {"io.modelcontextprotocol/tasks": {}, "com.example/audit": {"level": 2}}});
        let cases = [
            (
                json!({"jsonrpc": "2.0", "id": "task", "method": "tools/call", "params": {"name": "echo", "arguments": {}}}),
                Some("echo"),
                json!({"jsonrpc": "2.0", "id": "task", "result": {"resultType": "task", "taskId": "t-1", "status": "working"}}),
            ),
            (
                json!({"jsonrpc": "2.0", "id": "poll", "method": "tasks/get", "params": {"taskId": "t-1"}}),
                None,
                json!({"jsonrpc": "2.0", "id": "poll", "result": {
                    "resultType": "complete", "taskId": "t-1", "status": "completed"
                }}),
            ),
        ];
        for (capabilities, (mut body, name, upstream)) in [declared, json!({})]
            .into_iter()
            .flat_map(|capabilities| {
                cases
                    .clone()
                    .map(|case| (capabilities.clone(), case))
            })
        {
            body["params"]["_meta"] = json!({
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": capabilities
            });
            let target = crate::component_tests::helpers::MockServer::start_with_response(upstream.to_string()).await;
            let surface = serde_json::from_value(json!({
                "surface_id": "extensions", "name": "Extensions",
                "access_point": {"listen_address": "https://gateway.example", "route": "/extensions", "protocol": "mcp"},
                "target": {"endpoint": target.url()}
            }))
            .unwrap();
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/extensions")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                .header(
                    "mcp-method",
                    body["method"]
                        .as_str()
                        .unwrap(),
                );
            if let Some(name) = name {
                request = request.header("mcp-name", name);
            }
            let response = Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                direct_router_state(state, surface),
                request
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
                versions,
                None,
            ))
            .await;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap();
            let delivered: serde_json::Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| panic!("{}: {}", body["method"], String::from_utf8_lossy(&bytes)));
            assert_eq!(status, axum::http::StatusCode::OK, "{delivered}");
            for field in ["resultType", "taskId", "status"] {
                assert_eq!(delivered["result"][field], upstream["result"][field], "{field}: {delivered}");
            }
            let forwarded = target
                .last_request_rx
                .borrow()
                .clone()
                .expect("the request reached the upstream");
            let forwarded: serde_json::Value = serde_json::from_str(&forwarded.body).unwrap();
            assert_eq!(forwarded["method"], body["method"]);
            assert_eq!(forwarded["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"], capabilities);
            if body["method"] == "tasks/get" {
                assert_eq!(forwarded["params"]["taskId"], "t-1");
            }
        }
    }

    /// A forwarding Access Point never synthesizes resource errors: a modern
    /// resource-not-found (`-32602`) reaches the client with its `data` intact.
    async fn modern_resource_not_found_passes_through(state: &crate::state::ProxyState) {
        use serde_json::json;

        let not_found = json!({"jsonrpc": "2.0", "id": "missing", "error": {
            "code": -32602, "message": "Resource not found", "data": {"uri": "file:///missing.md"}
        }});
        let target = crate::component_tests::helpers::MockServer::start_with_response(not_found.to_string()).await;
        let surface = serde_json::from_value(json!({
            "surface_id": "resource-errors", "name": "Resource errors",
            "access_point": {"listen_address": "https://gateway.example", "route": "/resources", "protocol": "mcp"},
            "target": {"endpoint": target.url()}
        }))
        .unwrap();
        let body = json!({"jsonrpc": "2.0", "id": "missing", "method": "resources/read", "params": {
            "uri": "file:///missing.md", "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/resources")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
            .header("mcp-method", "resources/read")
            .header("mcp-name", "file:///missing.md")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let response = Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            direct_router_state(state, surface),
            request,
            versions,
            None,
        ))
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let delivered: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("JSON-RPC error body: {}", String::from_utf8_lossy(&bytes)));
        assert_eq!(delivered["id"], "missing");
        assert_eq!(delivered["error"], not_found["error"], "{delivered}");
    }

    /// Legacy `resources/subscribe` and `resources/unsubscribe` keep passing
    /// through unchanged; only modern peers use `subscriptions/listen`.
    async fn legacy_resource_subscriptions_are_forwarded_unchanged(state: &crate::state::ProxyState) {
        use serde_json::json;

        for method in ["resources/subscribe", "resources/unsubscribe"] {
            let target = crate::component_tests::helpers::MockServer::start_with_response(
                json!({"jsonrpc": "2.0", "id": 5, "result": {}}).to_string(),
            )
            .await;
            let surface = json!({
                "surface_id": "legacy-subscribe", "name": "Legacy subscribe",
                "access_point": {"listen_address": "https://gateway.example", "route": "/legacy-subscribe", "protocol": "mcp"},
                "target": {"endpoint": target.url()}
            });
            let body =
                json!({"jsonrpc": "2.0", "id": 5, "method": method, "params": {"uri": "file:///docs/readme.md"}});
            let request = axum::http::Request::builder()
                .method("POST")
                .uri("/legacy-subscribe")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            let response = super::multi_channel_proxy_handler(
                axum::extract::ConnectInfo(
                    "127.0.0.1:12345"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::State(direct_router_state(state, serde_json::from_value(surface).unwrap())),
                request,
            )
            .await;
            assert_eq!(response.status(), axum::http::StatusCode::OK, "{method}");
            let forwarded = target
                .last_request_rx
                .borrow()
                .clone()
                .expect("the request reached the upstream");
            let forwarded: serde_json::Value = serde_json::from_str(&forwarded.body).unwrap();
            assert_eq!(forwarded["method"], method);
            assert_eq!(forwarded["params"], body["params"], "{method}");
        }
    }

    /// The shared negative admission cases, and modern GET and
    /// DELETE, on the three paths the Access Point router serves: an HTTP
    /// Target, a `fabric://` Target (Fabric send) and a `proxy://` Target. Each
    /// is rejected by admission, before the Target, the Fabric leg or the MCP
    /// Proxy is reached.
    async fn access_point_admission_rejects_every_negative_case(state: &crate::state::ProxyState) {
        use crate::mcp::admission_cases::{ALLOWED_ORIGIN, admission_cases, assert_rejected};
        use serde_json::json;
        use std::sync::atomic::Ordering;

        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "unexpected", "result": {}}).to_string(),
        )
        .await;
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        for (path, endpoint) in [
            ("direct Access Point", target.url()),
            ("Fabric send", "fabric://gw/ch".to_string()),
            ("proxy:// Access Point", "proxy://negative-cases".to_string()),
        ] {
            let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
                "surface_id": "admission-cases", "name": "Admission cases",
                "mcp_http": {"allowed_origins": [ALLOWED_ORIGIN]},
                "access_point": {"listen_address": "https://gateway.example", "route": "/negative", "protocol": "mcp"},
                "target": {"endpoint": endpoint}
            }))
            .unwrap();
            for case in admission_cases() {
                let mut request = axum::http::Request::builder()
                    .method("POST")
                    .uri("/negative");
                for (name, value) in &case.headers {
                    request = request.header(*name, value.clone());
                }
                let request = request
                    .body(axum::body::Body::from(case.body.clone()))
                    .unwrap();
                // Every Fabric send reads the listener manager, so holding its
                // write lock proves admission answered first.
                let listener = state
                    .listener_manager
                    .write()
                    .await;
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                        "127.0.0.1:12345"
                            .parse()
                            .unwrap(),
                        direct_router_state(state, surface.clone()),
                        request,
                        versions,
                        None,
                    )),
                )
                .await
                .unwrap_or_else(|_| panic!("{path} {} was not answered at admission", case.name));
                drop(listener);
                let status = response.status();
                let body: serde_json::Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 16384)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_rejected(&case, status, &body, path);
            }
            // A modern endpoint is POST-only.
            for method in ["GET", "DELETE"] {
                let request = axum::http::Request::builder()
                    .method(method)
                    .uri("/negative")
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                    .header("mcp-session-id", "legacy-session")
                    .body(axum::body::Body::empty())
                    .unwrap();
                let listener = state
                    .listener_manager
                    .write()
                    .await;
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                        "127.0.0.1:12345"
                            .parse()
                            .unwrap(),
                        direct_router_state(state, surface.clone()),
                        request,
                        versions,
                        None,
                    )),
                )
                .await
                .unwrap_or_else(|_| panic!("{path} modern {method} was not answered at admission"));
                drop(listener);
                assert_eq!(response.status(), axum::http::StatusCode::METHOD_NOT_ALLOWED, "{path} {method}");
                assert_eq!(response.headers()["allow"], "POST", "{path} {method}");
            }
        }
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            0,
            "no negative admission case reaches the Target"
        );
    }

    /// A caller cannot present an Affinidi identity credential the gateway did
    /// not issue. The Access Point refuses it with 422 before the Target or,
    /// for a `fabric://` Target, the Fabric leg.
    async fn access_point_rejects_a_spoofed_identity_credential(state: &crate::state::ProxyState) {
        use serde_json::json;
        use std::sync::atomic::Ordering;

        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "spoofed", "result": {"tools": []}}).to_string(),
        )
        .await;
        for (path, endpoint) in [("direct Access Point", target.url()), ("Fabric send", "fabric://gw/ch".to_string())] {
            let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
                "surface_id": "spoofed-identity", "name": "Spoofed identity",
                "access_point": {"listen_address": "https://gateway.example", "route": "/spoofed", "protocol": "mcp"},
                "target": {"endpoint": endpoint}
            }))
            .unwrap();
            let body = json!({"jsonrpc": "2.0", "id": "spoofed", "method": "tools/list", "params": {"_meta": {
                "io.affinidi.fabric/agent-identity-credential": {"did": "did:example:spoofed"}
            }}});
            let request = axum::http::Request::builder()
                .method("POST")
                .uri("/spoofed")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            let listener = state
                .listener_manager
                .write()
                .await;
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                    "127.0.0.1:12345"
                        .parse()
                        .unwrap(),
                    direct_router_state(state, surface),
                    request,
                    crate::mcp::request_validation::LEGACY_ONLY_POLICY,
                    None,
                )),
            )
            .await
            .unwrap_or_else(|_| panic!("{path} did not refuse the credential before the Fabric leg"));
            drop(listener);
            assert_eq!(response.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY, "{path}");
        }
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            0
        );
    }

    /// An upstream result carrying every preservation field
    /// reaches the caller of a direct Access Point intact, in JSON and SSE.
    async fn direct_access_point_preserves_every_result_field(state: &crate::state::ProxyState) {
        use serde_json::json;

        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        for fixture in crate::mcp::result_fixtures::result_fixtures() {
            let id = "preserved";
            let target = crate::component_tests::helpers::MockServer::start_with_response(
                fixture
                    .response(id)
                    .to_string(),
            )
            .await;
            let surface = serde_json::from_value(json!({
                "surface_id": "preservation", "name": "Preservation",
                "access_point": {"listen_address": "https://gateway.example", "route": "/preserved", "protocol": "mcp"},
                "target": {"endpoint": target.url()}
            }))
            .unwrap();
            let (body, headers) = fixture.request(id);
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/preserved");
            for (name, value) in &headers {
                request = request.header(*name, value);
            }
            let response = Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                direct_router_state(state, surface),
                request
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
                versions,
                None,
            ))
            .await;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let delivered: serde_json::Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| panic!("{}: {}", fixture.method, String::from_utf8_lossy(&bytes)));
            assert_eq!(status, axum::http::StatusCode::OK, "{}: {delivered}", fixture.method);
            assert_eq!(delivered["id"], id);
            fixture.assert_preserved(&delivered["result"], "direct Access Point");
        }

        // Forwarded discovery is narrowed to what the gateway supports, but the
        // upstream's server identity, titles and icons included, is kept.
        let server_info = json!({
            "name": "fixture-server", "title": "Fixture Server", "version": "1.0.0",
            "icons": [{"src": "https://example.org/server.png", "mimeType": "image/png", "sizes": ["48x48"]}],
            "websiteUrl": "https://example.org", "com.example/unknown": [1]
        });
        let target = crate::component_tests::helpers::MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "discover", "result": {
                "resultType": "complete", "supportedVersions": [crate::mcp::MCP_MODERN_VERSION],
                "capabilities": {"tools": {}}, "serverInfo": server_info, "ttlMs": 0, "cacheScope": "private"
            }})
            .to_string(),
        )
        .await;
        let surface = serde_json::from_value(json!({
            "surface_id": "preservation", "name": "Preservation",
            "access_point": {"listen_address": "https://gateway.example", "route": "/preserved", "protocol": "mcp"},
            "target": {"endpoint": target.url()}
        }))
        .unwrap();
        let body = json!({"jsonrpc": "2.0", "id": "discover", "method": "server/discover", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        let response = Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            direct_router_state(state, surface),
            axum::http::Request::builder()
                .method("POST")
                .uri("/preserved")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                .header("mcp-method", "server/discover")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
            versions,
            None,
        ))
        .await;
        let delivered: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(delivered["result"]["serverInfo"], server_info, "{delivered}");
    }

    /// A caller that disconnects from a modern request stream stops the upstream
    /// request: the direct Access Point closes its upstream connection instead
    /// of leaving quiet tool work running.
    async fn direct_access_point_caller_disconnect_cancels_quiet_upstream(state: &crate::state::ProxyState) {
        use serde_json::json;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            while !request
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                let read = socket
                    .read(&mut buffer)
                    .await
                    .unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            // Headers only: the tool is still working and sends nothing more.
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-store\r\n\r\n")
                .await
                .unwrap();
            // Reading reaches EOF once the gateway closes the connection.
            let closed = loop {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break true,
                    Ok(_) => continue,
                }
            };
            let _ = closed_tx.send(closed);
        });
        let surface = serde_json::from_value(json!({
            "surface_id": "disconnect", "name": "Disconnect",
            "access_point": {"listen_address": "https://gateway.example", "route": "/disconnect", "protocol": "mcp"},
            "target": {"endpoint": format!("http://{address}")}
        }))
        .unwrap();
        let body = json!({"jsonrpc": "2.0", "id": "quiet", "method": "tools/call", "params": {
            "name": "slow", "arguments": {}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}, "progressToken": "work"
            }
        }});
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                direct_router_state(state, surface),
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/disconnect")
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                    .header("mcp-method", "tools/call")
                    .header("mcp-name", "slow")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
                versions,
                None,
            )),
        )
        .await
        .expect("the gateway starts streaming once the upstream stream opens");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        // The caller goes away.
        drop(response);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(5), closed_rx)
                .await
                .expect("the upstream connection must close after the caller disconnects")
                .unwrap()
        );
    }

    async fn forwarded_discovery_narrows_unsupported_version_errors(state: &crate::state::ProxyState) {
        use crate::mcp::{MCP_LEGACY_VERSION, MCP_MODERN_VERSION};
        use serde_json::json;
        use std::sync::atomic::Ordering;

        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[MCP_MODERN_VERSION],
            &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION],
        );
        let request = |path: &str, id: &str, method: &str, version: &str| {
            let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientCapabilities": {}
            }}});
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", version)
                .header("mcp-method", method)
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        };
        let read = async |response: axum::response::Response| -> (axum::http::StatusCode, serde_json::Value) {
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap();
            (status, serde_json::from_slice(&bytes).unwrap_or_default())
        };
        let discovered = json!({"jsonrpc": "2.0", "id": "discover", "result": {
            "resultType": "complete", "supportedVersions": [MCP_MODERN_VERSION], "capabilities": {"tools": {}},
            "ttlMs": 0, "cacheScope": "private"
        }});
        let legacy_only = json!({"jsonrpc": "2.0", "id": "discover", "error": {
            "code": crate::mcp::error_codes::METHOD_NOT_FOUND, "message": "Method not found"
        }});
        for (name, discovery, expected) in [
            ("discovered", Some(&discovered), json!([MCP_MODERN_VERSION])),
            ("legacy-only", Some(&legacy_only), json!([MCP_LEGACY_VERSION])),
            ("fresh", None, json!(versions.supported_versions())),
        ] {
            let target = crate::component_tests::helpers::MockServer::start_with_response(
                discovery.map_or_else(String::new, ToString::to_string),
            )
            .await;
            let route = format!("/discovery-{name}");
            let surface = serde_json::from_value(json!({
                "surface_id": format!("discovery-{name}"), "name": name,
                "access_point": {"listen_address": "https://gateway.example", "route": route, "protocol": "mcp"},
                "target": {"endpoint": target.url()}
            }))
            .unwrap();
            let router = direct_router_state(state, surface);
            let send = |request| {
                Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                    "127.0.0.1:12345"
                        .parse()
                        .unwrap(),
                    router.clone(),
                    request,
                    versions,
                    None,
                ))
            };
            if let Some(discovery) = discovery {
                let (status, delivered) =
                    read(send(request(&route, "discover", "server/discover", MCP_MODERN_VERSION)).await).await;
                assert_eq!(status, axum::http::StatusCode::OK, "{name}: {delivered}");
                if discovery
                    .get("result")
                    .is_some()
                {
                    assert_eq!(delivered["result"]["supportedVersions"], expected, "{name}: {delivered}");
                } else {
                    assert_eq!(delivered["error"], discovery["error"], "{name}: {delivered}");
                }
            }
            let forwarded = target
                .request_count
                .load(Ordering::SeqCst);
            let (status, rejected) = read(send(request(&route, "unmodelled", "tools/list", "2025-11-25")).await).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{name}: {rejected}");
            assert_eq!(rejected["id"], "unmodelled");
            assert_eq!(rejected["error"]["code"], crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
            assert_eq!(rejected["error"]["data"]["supported"], expected, "{name}");
            // Learned versions narrow only the advertised list; a modern request is still admitted.
            send(modern_tools_list_request(&route, "admitted")).await;
            assert_eq!(
                target
                    .request_count
                    .load(Ordering::SeqCst),
                forwarded + 1,
                "{name}"
            );
        }
    }

    async fn upstream_cache_hints_survive_unless_results_are_caller_scoped(state: &crate::state::ProxyState) {
        use serde_json::json;

        let manager = std::sync::Arc::new(crate::policies::SurfacePolicyManager::new());
        let state = crate::state::ProxyState {
            policy_manager: Some(manager.clone()),
            ..state.clone()
        };
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let upstream = json!({"jsonrpc": "2.0", "id": "cache", "result": {
            "resultType": "complete", "tools": [{"name": "echo"}, {"name": "admin_delete"}],
            "ttlMs": 60000, "cacheScope": "public"
        }});
        let deny_admin = json!({"gates": [{"id": "g1", "name": "no admin", "action": {
            "effect": "deny", "patterns": ["^admin_"]
        }}]});
        for (name, gating, tools, ttl, scope) in [
            ("open", None, json!(["echo", "admin_delete"]), 60000, "public"),
            ("gated", Some(&deny_admin), json!(["echo"]), 0, "private"),
        ] {
            let target = crate::component_tests::helpers::MockServer::start_with_response(upstream.to_string()).await;
            let route = format!("/cache-{name}");
            let mut surface = json!({
                "surface_id": format!("cache-{name}"), "name": name,
                "access_point": {"listen_address": "https://gateway.example", "route": route, "protocol": "mcp"},
                "target": {"endpoint": target.url()}
            });
            if let Some(gating) = gating {
                surface["target"]["mcp_tool_gating"] = gating.clone();
            }
            let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(surface).unwrap();
            manager
                .update_channel_policy(&surface)
                .await
                .unwrap();
            let response = Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
                direct_router_state(&state, surface),
                modern_tools_list_request(&route, "cache"),
                versions,
                None,
            ))
            .await;
            let status = response.status();
            let delivered: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 16384)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(status, axum::http::StatusCode::OK, "{name}: {delivered}");
            let names: Vec<_> = delivered["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tool| tool["name"].clone())
                .collect();
            assert_eq!(json!(names), tools, "{name}: {delivered}");
            assert_eq!(delivered["result"]["ttlMs"], ttl, "{name}: {delivered}");
            assert_eq!(delivered["result"]["cacheScope"], scope, "{name}: {delivered}");
        }
    }

    #[tokio::test]
    async fn caller_scoped_mcp_results_follow_surface_policies() {
        use super::caller_scoped_mcp_result;
        use crate::policies::SurfacePolicyManager;
        use serde_json::json;

        const ALLOW: &str = "package surface.policy\n\ndefault allow = true\n";
        let surface = |target: serde_json::Value| -> crate::config::agent_surface::AgentSurface {
            serde_json::from_value(json!({
                "surface_id": "cache-scope", "name": "Cache scope",
                "access_point": {"listen_address": "https://gateway.example", "route": "/cache", "protocol": "mcp"},
                "target": target,
                "variants": [{"id": "open", "alias": "open", "name": "Open", "enabled": true,
                    "overrides": {"target": {"mcp_tool_gating": {}}}}]
            }))
            .unwrap()
        };
        let plain = surface(json!({"endpoint": "http://127.0.0.1:9/mcp"}));
        let empty = SurfacePolicyManager::new();
        assert!(!caller_scoped_mcp_result(&plain, None, None));
        assert!(!caller_scoped_mcp_result(&plain, Some(&empty), None));
        assert!(!caller_scoped_mcp_result(&plain, Some(&empty), Some("beta")));

        let surface_engine = SurfacePolicyManager::new();
        surface_engine
            .load_policy_text("cache-scope", ALLOW)
            .unwrap();
        assert!(caller_scoped_mcp_result(&plain, Some(&surface_engine), None));
        assert!(caller_scoped_mcp_result(&plain, Some(&surface_engine), Some("beta")));

        let variant_engine = SurfacePolicyManager::new();
        variant_engine
            .load_policy_text("variant:cache-scope:beta", ALLOW)
            .unwrap();
        assert!(caller_scoped_mcp_result(&plain, Some(&variant_engine), Some("beta")));
        assert!(!caller_scoped_mcp_result(&plain, Some(&variant_engine), Some("gamma")));
        assert!(!caller_scoped_mcp_result(&plain, Some(&variant_engine), None));

        let gated = surface(json!({"endpoint": "http://127.0.0.1:9/mcp", "mcp_tool_gating": {"gates": [{
            "id": "g1", "name": "no admin", "action": {"effect": "deny", "patterns": ["^admin_"]}
        }]}}));
        let gating = SurfacePolicyManager::new();
        gating
            .update_channel_policy(&gated)
            .await
            .unwrap();
        assert!(caller_scoped_mcp_result(&gated, Some(&gating), None));
        assert!(!caller_scoped_mcp_result(&gated, Some(&gating), Some("open")));
        assert!(!caller_scoped_mcp_result(&gated, None, None));

        let responding = surface(json!({"endpoint": "http://127.0.0.1:9/mcp", "response_policy": {
            "policy_definition_id": "response"
        }}));
        assert!(caller_scoped_mcp_result(&responding, None, None));
        assert!(caller_scoped_mcp_result(&responding, Some(&empty), None));
    }

    #[test]
    fn direct_modern_consent_runs_after_authorization_and_before_payment() {
        if std::env::var_os("ATG_MCP_SUBSCRIPTION_DIRECT_CHILD").is_none() {
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env("ATG_MCP_SUBSCRIPTION_DIRECT_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated direct MCP test failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_stack_size(8 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(Box::pin(direct_modern_consent_flow()));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn direct_modern_consent_flow() {
        use std::sync::Arc;

        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
        use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
        use crate::mcp::continuations::{
            config::ContinuationRuntime,
            embedded::EmbeddedContinuations,
            protected::{ContinuationCipher, ContinuationKey},
            service::ContinuationService,
        };
        use futures::TryStreamExt;
        use serde_json::json;
        use sha2::{Digest, Sha256};

        let (issuer, directory) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let strategies = Arc::new(
            FileSystemJwtVerificationStrategyStore::new(
                directory
                    .path()
                    .join("strategies"),
            )
            .await
            .unwrap(),
        );
        let strategy = strategies
            .create(
                crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &json!({"keys": []}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let providers = Arc::new(
            FileSystemCredentialProviderStore::new(
                directory
                    .path()
                    .join("providers"),
            )
            .await
            .unwrap(),
        );
        let provider = providers
            .create(
                serde_json::from_value(json!({
                    "id": "provider", "name": "Provider", "provider_id": "provider",
                    "resource": "https://provider.example/api", "consent_identity_strategy_id": strategy.id,
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let vault = Arc::new(
            FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "consent-surface", "name": "Consent Surface",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "http://127.0.0.1:9/api", "payment_policy": {
                "type": "x402", "enabled": true, "provider": "agent_pay",
                "payment_gateway_id": "payment-gateway", "payment_surface_id": "payment-surface"
            }},
            "identity_slots": {"inbound": {"type": "static", "did": "did:web:agent.example"}},
            "mcp_http": {"authorization": {"resource": "https://gateway.example/mcp", "scopes": ["read"]}},
            "outbound_credentials": [{"credential_provider_id": "provider", "scopes": ["read"]}]
        }))
        .unwrap();
        let network = serde_json::from_value(json!({
            "did": {"domain": "gateway.example"},
            "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []},
            "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080,
                "protocol": "http", "external_urls": ["https://gateway.example"]}],
            "routes": {"identity": {"type": "identity_api", "prefix": "/api"}},
            "sts": {"mcp_issuer": {"issuer": "https://gateway.example/api/oauth2/mcp"}}
        }))
        .unwrap();
        let config = serde_json::from_value(json!({
            "tls": {"cert_path": "unused.pem", "key_path": "unused-key.pem"},
            "integration": {"variable_pattern": "\\$\\{([^}]+)\\}", "custom_variable_prefix": "_", "types": [], "categories": []},
            "extension_inspection": {"enabled": false}
        })).unwrap();
        let sessions = Arc::new(crate::didauth::DidAuthSessionStore::new());
        let middleware = Arc::new(crate::source_auth::SourceAuthMiddleware::new(
            sessions.clone(),
            strategies,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
            None,
            Arc::new(dashmap::DashMap::new()),
            None,
            None,
        ));
        let mut state = crate::state::ProxyState {
            config: Arc::new(config),
            network_config: Arc::new(network),
            client: reqwest::Client::new(),
            metrics_store: None,
            identity_rules_engine: None,
            identity_selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
            task_monitor: None,
            task_id: None,
            ws_state: None,
            listener_manager: Arc::new(tokio::sync::RwLock::new(None)),
            secrets_store: None,
            certificates_store: None,
            vc_issuer: Some(issuer.clone()),
            policy_manager: None,
            gateway_policy_manager: None,
            didauth_session_store: sessions,
            transaction_store: None,
            mpp_transaction_store: None,
            trust_registry_listener_manager: None,
            source_auth_middleware: Some(middleware),
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: None,
            #[cfg(feature = "didwebvh")]
            didwebvh_log_manager: None,
            credential_provider_store: Some(providers),
            delegation_vault_store: Some(vault.clone()),
            gateway_base_url: Some("https://gateway.example".into()),
            transit_token_issuer: None,
            mcp_proxy_store: None,
            a2a_proxy_store: None,
            active_variant_alias: None,
            active_variant_id: None,
            variant_resolution_error: None,
            surface: Arc::new(surface),
        };
        modern_access_point_router_keeps_legacy_variant_fallback(&state).await;
        mounted_access_point_uses_the_direct_access_point_policy(&state).await;
        direct_access_point_caps_legacy_initialize(&state).await;
        access_point_admission_rejects_every_negative_case(&state).await;
        access_point_rejects_a_spoofed_identity_credential(&state).await;
        direct_access_point_preserves_every_result_field(&state).await;
        direct_access_point_caller_disconnect_cancels_quiet_upstream(&state).await;
        forwarded_discovery_narrows_unsupported_version_errors(&state).await;
        upstream_cache_hints_survive_unless_results_are_caller_scoped(&state).await;
        modern_routing_headers_reach_the_upstream(&state).await;
        legacy_resource_subscriptions_are_forwarded_unchanged(&state).await;
        modern_resource_not_found_passes_through(&state).await;
        modern_extensions_survive_forwarding(&state).await;
        proxy_access_point_answers_modern_discovery(&state).await;
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        let runtime = Arc::new(ContinuationRuntime {
            config: serde_json::from_value(json!({"deployment": "deployment", "ttl_secs": 300, "active_key": "key",
                "keys": [{"id": "key", "secret_id": "key-secret", "not_before": now - 1, "seal_until": now + 3600, "open_until": now + 4500}],
                "storage": {"backend": "embedded", "capacity": 32}})).unwrap(),
            service: Arc::new(ContinuationService::new(ContinuationCipher::new("deployment".into(), "key".into(), vec![
                ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap(),
            ]).unwrap(), Arc::new(EmbeddedContinuations::new(32).unwrap()))),
        });
        let bearer = issuer.sign_jwt_with_gateway_key_typ(&json!({
            "iss": "https://gateway.example/api/oauth2/mcp", "sub": "user", "aud": "https://gateway.example/mcp",
            "scope": "read", "exp": now + 300
        }), "at+jwt").await.unwrap();
        let mut message = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "read", "arguments": {"value": 1}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"url": {}}}
            }
        }});
        let build_request = |message: &serde_json::Value| {
            axum::http::Request::builder()
                .method("POST")
                .uri("https://gateway.example/mcp")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                .header("mcp-method", "tools/call")
                .header("mcp-name", "read")
                .body(axum::body::Body::from(serde_json::to_vec(message).unwrap()))
                .unwrap()
        };
        let address = "127.0.0.1:12345"
            .parse()
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let response = Box::pin(super::proxy_handler_with_mcp_runtime(
            address,
            state.clone(),
            build_request(&message),
            versions,
            Some(runtime.clone()),
        ))
        .await
        .unwrap_or_else(|response| response);
        let status = response.status();
        let response: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status, axum::http::StatusCode::OK, "{response}");
        assert_eq!(response["result"]["resultType"], "input_required");
        // Tampered, expired, cross-user and incapable MRTR retries, on a continuation of their
        // own so the flow below keeps its state.
        {
            let send = |message: serde_json::Value, bearer: Option<String>, runtime: Arc<ContinuationRuntime>| {
                let mut request = build_request(&message);
                if let Some(bearer) = bearer {
                    request.headers_mut().insert(
                        "authorization",
                        format!("Bearer {bearer}")
                            .parse()
                            .unwrap(),
                    );
                }
                let state = state.clone();
                async move {
                    let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                        address,
                        state,
                        request,
                        versions,
                        Some(runtime),
                    ))
                    .await
                    .unwrap_or_else(|response| response);
                    let status = response.status();
                    let body: serde_json::Value = serde_json::from_slice(
                        &axum::body::to_bytes(response.into_body(), 16384)
                            .await
                            .unwrap(),
                    )
                    .unwrap();
                    (status, body)
                }
            };
            let pending = |id: &str| {
                let mut pending = message.clone();
                pending["id"] = json!(id);
                pending
            };
            let (_, issued) = send(pending("negatives"), None, runtime.clone()).await;
            let issued_state = issued["result"]["requestState"]
                .as_str()
                .expect("a continuation to replay")
                .to_string();

            // A tampered state does not open.
            let mut tampered = pending("tampered");
            let mut bytes = issued_state
                .clone()
                .into_bytes();
            let last = bytes.len() - 1;
            bytes[last] = if bytes[last] == b'A' {
                b'B'
            } else {
                b'A'
            };
            tampered["params"]["requestState"] = json!(String::from_utf8(bytes).unwrap());
            let (status, body) = send(tampered, None, runtime.clone()).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "tampered: {body}");
            assert_eq!(body["error"]["code"], crate::mcp::error_codes::INVALID_PARAMS, "tampered: {body}");
            assert_eq!(body["id"], "tampered");

            // Another principal cannot resume it.
            let other = issuer
                .sign_jwt_with_gateway_key_typ(
                    &json!({
                        "iss": "https://gateway.example/api/oauth2/mcp", "sub": "other-user",
                        "aud": "https://gateway.example/mcp", "scope": "read", "exp": now + 300
                    }),
                    "at+jwt",
                )
                .await
                .unwrap();
            let mut cross_user = pending("cross-user");
            cross_user["params"]["requestState"] = json!(issued_state);
            let (status, body) = send(cross_user, Some(other), runtime.clone()).await;
            assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "cross-user: {body}");
            assert_eq!(body["error"]["code"], -32001, "cross-user: {body}");

            // A client that did not declare URL elicitation is not sent a consent request.
            let mut incapable = pending("incapable");
            incapable["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
            let (status, body) = send(incapable, None, runtime.clone()).await;
            assert_eq!(
                body["error"]["code"],
                crate::mcp::error_codes::MISSING_REQUIRED_CLIENT_CAPABILITY,
                "incapable: {status} {body}"
            );
            assert!(body.get("result").is_none(), "incapable: {body}");

            // An expired state does not open.
            let short: Arc<ContinuationRuntime> = Arc::new(ContinuationRuntime {
                config: serde_json::from_value(json!({"deployment": "deployment", "ttl_secs": 1, "active_key": "key",
                    "keys": [{"id": "key", "secret_id": "key-secret", "not_before": now - 1, "seal_until": now + 3600, "open_until": now + 4500}],
                    "storage": {"backend": "embedded", "capacity": 32}})).unwrap(),
                service: Arc::new(ContinuationService::new(ContinuationCipher::new("deployment".into(), "key".into(), vec![
                    ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap(),
                ]).unwrap(), Arc::new(EmbeddedContinuations::new(32).unwrap()))),
            });
            let (_, short_issued) = send(pending("short"), None, short.clone()).await;
            tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
            let mut expired = pending("expired");
            expired["params"]["requestState"] = short_issued["result"]["requestState"].clone();
            let (status, body) = send(expired, None, short).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "expired: {body}");
            assert_eq!(body["error"]["code"], crate::mcp::error_codes::INVALID_PARAMS, "expired: {body}");
        }
        message["id"] = json!(2);
        message["params"]["requestState"] = response["result"]["requestState"].clone();
        Arc::make_mut(&mut state.surface)
            .target
            .policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: "missing-policy".into(),
            require_agent_context: false,
        });
        let response = Box::pin(super::proxy_handler_with_mcp_runtime(
            address,
            state.clone(),
            build_request(&message),
            versions,
            Some(runtime.clone()),
        ))
        .await
        .unwrap_or_else(|response| response);
        let status = response.status();
        let response: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            status == axum::http::StatusCode::FORBIDDEN || response["error"]["code"] == -32001,
            "{status}: {response}"
        );
        assert!(
            response
                .get("result")
                .is_none()
        );

        async fn decode_response(response: axum::response::Response) -> (axum::http::StatusCode, serde_json::Value) {
            let status = response.status();
            let sse = response
                .headers()
                .get("content-type")
                .is_some_and(|value| value == "text/event-stream");
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let value = if sse {
                let events: Vec<_> = crate::mcp::modern_sse::decode_events(
                    futures::stream::iter([Ok::<_, std::io::Error>(bytes)]),
                    crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default()),
                )
                .try_collect()
                .await
                .unwrap();
                serde_json::from_str(&events.last().unwrap().data).unwrap()
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            (status, value)
        }

        type ObservedCalls = Arc<tokio::sync::Mutex<Vec<(HeaderMap, serde_json::Value)>>>;
        let calls: ObservedCalls = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let target = axum::Router::new()
            .fallback(axum::routing::post(
                |axum::extract::State(calls): axum::extract::State<ObservedCalls>,
                 uri: axum::http::Uri,
                 headers: HeaderMap,
                 axum::Json(body): axum::Json<serde_json::Value>| async move {
                    use axum::response::IntoResponse;
                    if body.get("id").is_none() {
                        calls
                            .lock()
                            .await
                            .push((headers, body));
                        return if uri.path().contains("reject") {
                            (
                                axum::http::StatusCode::NOT_FOUND,
                                axum::Json(json!({
                                    "jsonrpc": "2.0", "error": {"code": -32601, "message": "Unknown notification"}
                                })),
                            )
                                .into_response()
                        } else {
                            axum::http::StatusCode::ACCEPTED.into_response()
                        };
                    }
                    let result = if body["params"]
                        .get("requestState")
                        .is_some()
                    {
                        json!({"resultType": "complete", "content": [], "structuredContent": {"delivered": true}})
                    } else {
                        json!({"resultType": "input_required", "requestState": "opaque upstream state",
                        "inputRequests": {"upstream-input": {"method": "elicitation/create", "params": {
                            "mode": "url", "url": "https://upstream.example/consent", "message": "Authorize"
                        }}}})
                    };
                    let response = json!({"jsonrpc": "2.0", "id": body["id"], "result": result});
                    calls
                        .lock()
                        .await
                        .push((headers, body));
                    if uri.path().contains("sse") {
                        ([("content-type", "text/event-stream")], format!("data: {response}\n\n")).into_response()
                    } else {
                        axum::Json(response).into_response()
                    }
                },
            ))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let target_address = listener.local_addr().unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, target)
                .await
                .unwrap();
        });
        state.client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let token = serde_json::from_value(json!({
            "id": "verified-token", "agent_did": "did:web:agent.example",
            "user_identity_hash": hex::encode(Sha256::digest(b"user")), "credential_provider_id": "provider",
            "provider_id": "provider", "access_token": "verified-credential", "scopes": ["read"],
            "consent_granted_at": "2026-09-01T00:00:00Z", "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z",
            "consent_identity": {
                "principal": hex::encode(Sha256::digest(serde_json_canonicalizer::to_vec(&("https://gateway.example/api/oauth2/mcp", "user")).unwrap())),
                "provider_digest": crate::mcp::continuations::delegation::provider_digest(&provider).unwrap(),
                "strategy_digest": crate::mcp::continuations::delegation::identity_strategy_digest(&strategy).unwrap()
            }
        })).unwrap();
        vault
            .store(token)
            .await
            .unwrap();
        for format in ["json", "sse"] {
            let surface = Arc::make_mut(&mut state.surface);
            surface.target.policy = None;
            surface.target.payment_policy = None;
            surface.target.endpoint = format!("http://{target_address}/{format}");
            message["id"] = json!(10);
            message["params"]
                .as_object_mut()
                .unwrap()
                .remove("requestState");
            message["params"]
                .as_object_mut()
                .unwrap()
                .remove("inputResponses");
            let before = calls.lock().await.len();
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                build_request(&message),
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            let (status, response) = decode_response(response).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{response}");
            assert_eq!(response["result"]["resultType"], "input_required");
            assert_ne!(response["result"]["requestState"], "opaque upstream state");
            message["id"] = json!(11);
            message["params"]["requestState"] = response["result"]["requestState"].clone();
            message["params"]["inputResponses"] =
                json!({"upstream-input": {"action": "accept"}, "ignored": {"action": "cancel"}});
            let (first, second) = tokio::join!(
                Box::pin(super::proxy_handler_with_mcp_runtime(
                    address,
                    state.clone(),
                    build_request(&message),
                    versions,
                    Some(runtime.clone())
                )),
                Box::pin(super::proxy_handler_with_mcp_runtime(
                    address,
                    state.clone(),
                    build_request(&message),
                    versions,
                    Some(runtime.clone())
                )),
            );
            let first = decode_response(first.unwrap_or_else(|response| response)).await;
            let second = decode_response(second.unwrap_or_else(|response| response)).await;
            let successes = [&first, &second]
                .into_iter()
                .filter(|(status, _)| *status == axum::http::StatusCode::OK)
                .count();
            let conflicts = [&first, &second]
                .into_iter()
                .filter(|(status, _)| *status == axum::http::StatusCode::CONFLICT)
                .count();
            assert_eq!((successes, conflicts), (1, 1), "{first:?}; {second:?}");
            let completed = if first.0 == axum::http::StatusCode::OK {
                first.1
            } else {
                second.1
            };
            assert_eq!(completed["result"]["resultType"], "complete");
            assert_eq!(completed["result"]["structuredContent"]["delivered"], true);
            let observed = calls.lock().await;
            assert_eq!(observed.len(), before + 2);
            for (headers, _) in &observed[before..] {
                assert_eq!(
                    headers
                        .get_all("authorization")
                        .iter()
                        .count(),
                    1
                );
                assert_eq!(headers["authorization"], "Bearer verified-credential");
                assert!(!headers.contains_key("mcp-session-id"));
            }
            assert_eq!(observed[before + 1].1["params"]["requestState"], "opaque upstream state");
            assert_eq!(
                observed[before + 1].1["params"]["inputResponses"],
                json!({"upstream-input": {"action": "accept"}})
            );
        }
        // Gateway consent end to end over HTTP: the gateway's own
        // `input_required`, its connect ticket through the callback steps, then
        // retries carrying the gateway's `requestState` until `complete`.
        {
            Arc::make_mut(&mut state.surface)
                .target
                .endpoint = format!("http://{target_address}/json");
            let credential = vault
                .get("verified-token")
                .await
                .unwrap()
                .unwrap();
            assert!(
                vault
                    .delete("verified-token")
                    .await
                    .unwrap()
            );
            let send = |message: &serde_json::Value| {
                Box::pin(super::proxy_handler_with_mcp_runtime(
                    address,
                    state.clone(),
                    build_request(message),
                    versions,
                    Some(runtime.clone()),
                ))
            };
            message["id"] = json!(30);
            let params = message["params"]
                .as_object_mut()
                .unwrap();
            params.remove("requestState");
            params.remove("inputResponses");
            let (status, consent) = decode_response(
                send(&message)
                    .await
                    .unwrap_or_else(|response| response),
            )
            .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{consent}");
            assert_eq!(consent["result"]["resultType"], "input_required", "{consent}");
            let (input_key, input) = consent["result"]["inputRequests"]
                .as_object()
                .and_then(|requests| requests.iter().next())
                .expect("gateway consent input request");
            assert!(input_key.starts_with("gateway-consent-"), "{consent}");
            let consent_url = url::Url::parse(
                input["params"]["url"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let connect = consent_url
                .query_pairs()
                .find(|(name, _)| name == "state")
                .expect("connect ticket")
                .1
                .into_owned();
            let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
            let ticket = runtime
                .service
                .read_consent_ticket(&connect, false, now)
                .await
                .unwrap();
            let callback = runtime
                .service
                .begin_consent_callback(ticket, "v".repeat(43), vault.as_ref(), now)
                .await
                .unwrap();
            let ticket = runtime
                .service
                .read_consent_ticket(&callback, true, now)
                .await
                .unwrap();
            let claimed = runtime
                .service
                .claim_consent_callback(ticket, now)
                .await
                .unwrap();
            runtime
                .service
                .complete_consent_callback(claimed, vault.as_ref(), credential.clone(), now)
                .await
                .unwrap();
            message["id"] = json!(31);
            message["params"]["requestState"] = consent["result"]["requestState"].clone();
            message["params"]["inputResponses"] = json!({input_key.clone(): {"action": "accept"}});
            let before = calls.lock().await.len();
            let (status, upstream_round) = decode_response(
                send(&message)
                    .await
                    .unwrap_or_else(|response| response),
            )
            .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{upstream_round}");
            assert_eq!(calls.lock().await.len(), before + 1, "consent resumed and reached the Target");
            // The Target asks for its own input; the gateway wraps that round.
            assert_eq!(upstream_round["result"]["resultType"], "input_required", "{upstream_round}");
            message["id"] = json!(32);
            message["params"]["requestState"] = upstream_round["result"]["requestState"].clone();
            message["params"]["inputResponses"] = json!({"upstream-input": {"action": "accept"}});
            let (status, completed) = decode_response(
                send(&message)
                    .await
                    .unwrap_or_else(|response| response),
            )
            .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{completed}");
            assert_eq!(completed["result"]["resultType"], "complete", "{completed}");
            assert_eq!(completed["result"]["structuredContent"]["delivered"], true);
            if vault
                .get("verified-token")
                .await
                .unwrap()
                .is_none()
            {
                vault
                    .store(credential)
                    .await
                    .unwrap();
            }
        }
        let surface = Arc::make_mut(&mut state.surface);
        surface.target.endpoint = format!("http://{target_address}/json");
        surface.target.payment_policy = Some(
            serde_json::from_value(json!({
                "type": "x402", "enabled": true, "verification_mode": "mock", "settlement_mode": "none",
                "mcp_payment_triggers": {"mode": "all"}
            }))
            .unwrap(),
        );
        message["id"] = json!(20);
        message["params"]["requestState"] = json!("opaque upstream state");
        let original = crate::mcp::request_validation::ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: Some(json!({"elicitation": {"url": {}}})),
            client_info: None,
            method: "tools/call".into(),
            params: Some(message["params"].clone()),
            id: Some(message["id"].clone()),
            kind: crate::mcp::request_validation::McpMessageKind::Request,
        };
        let identity = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "user".into(),
            claims: json!({"iss": "https://gateway.example/api/oauth2/mcp", "sub": "user", "scope": "read"}),
        };
        let binding = crate::mcp::continuations::delegation::make_binding(
            "deployment",
            &state.surface,
            None,
            crate::mcp::continuations::protected::ContinuationRoute::AccessPoint,
            state
                .surface
                .mcp_http
                .as_ref()
                .unwrap()
                .authorization
                .as_ref()
                .unwrap(),
            &provider,
            vec!["read".into()],
            "did:web:agent.example",
            &identity,
            &original,
        )
        .unwrap();
        let (issued, connect) = runtime
            .service
            .issue_consent(
                &original,
                binding,
                crate::mcp::continuations::delegation::provider_digest(&provider).unwrap(),
                crate::mcp::continuations::delegation::surface_digest(&state.surface).unwrap(),
                crate::mcp::continuations::delegation::identity_strategy_digest(&strategy).unwrap(),
                "https://gateway.example/mcp-consent/callback/provider".into(),
                300,
                now,
            )
            .await
            .unwrap();
        let ticket = runtime
            .service
            .read_consent_ticket(&connect, false, now)
            .await
            .unwrap();
        let callback = runtime
            .service
            .begin_consent_callback(ticket, "v".repeat(43), vault.as_ref(), now)
            .await
            .unwrap();
        let ticket = runtime
            .service
            .read_consent_ticket(&callback, true, now)
            .await
            .unwrap();
        let callback = runtime
            .service
            .claim_consent_callback(ticket, now)
            .await
            .unwrap();
        let credential = vault
            .get("verified-token")
            .await
            .unwrap()
            .unwrap();
        runtime
            .service
            .complete_consent_callback(callback, vault.as_ref(), credential, now)
            .await
            .unwrap();
        message["id"] = json!(21);
        message["params"]["requestState"] = json!(issued.state);
        message["params"]
            .as_object_mut()
            .unwrap()
            .remove("inputResponses");
        let before = calls.lock().await.len();
        for _attempt in 0..2 {
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                build_request(&message),
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            assert_eq!(response.status(), axum::http::StatusCode::PAYMENT_REQUIRED);
            assert_eq!(calls.lock().await.len(), before);
        }
        message["id"] = json!(22);
        let signature = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&json!({
            "x402Version": 2, "resource": {"url": "https://gateway.example/mcp", "description": "test", "mimeType": "application/json"},
            "accepted": {"scheme": "exact", "network": "eip155:1", "amount": "1000",
                "asset": "0x123", "payTo": "0x456", "maxTimeoutSeconds": 300},
            "payload": {"signature": "fixture-payment"}
        })).unwrap());
        let paid_request = || {
            let mut request = build_request(&message);
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(
                    state
                        .config
                        .x402_headers
                        .payment_signature
                        .as_bytes(),
                )
                .unwrap(),
                HeaderValue::from_str(&signature).unwrap(),
            );
            request
        };
        let (first, second) = tokio::join!(
            Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                paid_request(),
                versions,
                Some(runtime.clone())
            )),
            Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                paid_request(),
                versions,
                Some(runtime.clone())
            )),
        );
        let first = decode_response(first.unwrap_or_else(|response| response)).await;
        let second = decode_response(second.unwrap_or_else(|response| response)).await;
        assert!(matches!((first.0.as_u16(), second.0.as_u16()), (200, 409) | (409, 200)), "{first:?}; {second:?}");
        assert_eq!(calls.lock().await.len(), before + 1);
        assert!(
            !calls.lock().await[before]
                .0
                .contains_key(
                    state
                        .config
                        .x402_headers
                        .payment_signature
                        .as_str()
                )
        );
        let transactions = Arc::new(
            crate::x402::TransactionStore::new(
                directory
                    .path()
                    .join("payments"),
            )
            .await
            .unwrap(),
        );
        state.transaction_store = Some(transactions.clone());
        for format in ["json", "sse"] {
            Arc::make_mut(&mut state.surface)
                .target
                .endpoint = format!("http://{target_address}/{format}");
            message["id"] = json!(30);
            message["params"]
                .as_object_mut()
                .unwrap()
                .remove("requestState");
            message["params"]
                .as_object_mut()
                .unwrap()
                .remove("inputResponses");
            let signature = base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(&json!({
                    "x402Version": 2,
                    "accepted": {"scheme": "exact", "network": "eip155:1", "amount": "1000",
                        "asset": "0x123", "payTo": "0x456", "maxTimeoutSeconds": 300},
                    "payload": {"signature": format!("paid-round-{format}")}
                }))
                .unwrap(),
            );
            let mut paid = build_request(&message);
            paid.headers_mut().insert(
                axum::http::HeaderName::from_bytes(
                    state
                        .config
                        .x402_headers
                        .payment_signature
                        .as_bytes(),
                )
                .unwrap(),
                HeaderValue::from_str(&signature).unwrap(),
            );
            let calls_before = calls.lock().await.len();
            let payments_before = transactions
                .list_all()
                .await
                .len();
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                paid,
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            let receipt = response
                .headers()
                .get(
                    state
                        .config
                        .x402_headers
                        .payment_response
                        .as_str(),
                )
                .unwrap()
                .clone();
            let (status, response) = decode_response(response).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{response}");
            assert_eq!(response["result"]["resultType"], "input_required");
            assert_eq!(
                transactions
                    .list_all()
                    .await
                    .len(),
                payments_before + 1
            );
            message["id"] = json!(31);
            message["params"]["requestState"] = response["result"]["requestState"].clone();
            message["params"]["inputResponses"] = json!({"upstream-input": {"action": "accept"}});
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                build_request(&message),
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            assert_eq!(
                response.headers().get(
                    state
                        .config
                        .x402_headers
                        .payment_response
                        .as_str()
                ),
                Some(&receipt)
            );
            let (status, response) = decode_response(response).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{response}");
            assert_eq!(response["result"]["resultType"], "complete");
            assert_eq!(
                transactions
                    .list_all()
                    .await
                    .len(),
                payments_before + 1
            );
            assert_eq!(calls.lock().await.len(), calls_before + 2);
            message["id"] = json!(32);
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                build_request(&message),
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
            assert_eq!(
                transactions
                    .list_all()
                    .await
                    .len(),
                payments_before + 1
            );
            assert_eq!(calls.lock().await.len(), calls_before + 2);
        }
        Arc::make_mut(&mut state.surface)
            .target
            .payment_policy = None;
        for reject in [false, true] {
            Arc::make_mut(&mut state.surface)
                .target
                .endpoint = format!(
                "http://{target_address}/{}",
                if reject {
                    "notification-reject"
                } else {
                    "notification-accept"
                }
            );
            let notification = json!({"jsonrpc": "2.0", "method": "notifications/com.example/changed", "params": {
                "revision": 1, "_meta": {"io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION}
            }});
            let mut request = build_request(&notification);
            request.headers_mut().insert(
                "mcp-method",
                "notifications/com.example/changed"
                    .parse()
                    .unwrap(),
            );
            request
                .headers_mut()
                .remove("mcp-name");
            request.headers_mut().insert(
                "mcp-session-id",
                "ignored-legacy-session"
                    .parse()
                    .unwrap(),
            );
            let before = calls.lock().await.len();
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                request,
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            let status = response.status();
            let headers = response.headers().clone();
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                status,
                if reject {
                    axum::http::StatusCode::NOT_FOUND
                } else {
                    axum::http::StatusCode::ACCEPTED
                },
                "notification response: {}",
                String::from_utf8_lossy(&body)
            );
            assert!(!headers.contains_key("mcp-session-id"));
            if reject {
                let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(error["error"]["code"], -32601);
                assert!(error.get("id").is_none());
            } else {
                assert!(body.is_empty());
                assert!(!headers.contains_key("content-type"));
            }
            let observed = calls.lock().await;
            assert_eq!(observed.len(), before + 1);
            assert!(
                observed[before]
                    .1
                    .get("id")
                    .is_none()
            );
            assert_eq!(observed[before].1["method"], "notifications/com.example/changed");
            assert_eq!(observed[before].1["params"]["revision"], 1);
            assert_eq!(observed[before].0["authorization"], "Bearer verified-credential");
            assert!(
                !observed[before]
                    .0
                    .contains_key("mcp-session-id")
            );
        }
        let mut variant_catalog = (*state.surface).clone();
        variant_catalog.variants.push(
            serde_json::from_value(json!({
                "id": "credential-variant", "alias": "candidate", "name": "Candidate",
                "overrides": {"target": {"endpoint": format!("http://{target_address}/json")}}
            }))
            .unwrap(),
        );
        variant_catalog.default_variant_id = Some("credential-variant".into());
        for alias in [Some("candidate"), None] {
            let mut variant_state = state.clone();
            variant_state.active_variant_alias = alias.map(str::to_string);
            variant_state.active_variant_id = Some("credential-variant".into());
            variant_state.surface = Arc::new(
                variant_catalog
                    .resolve_variant(alias)
                    .unwrap(),
            );
            assert!(
                variant_state
                    .surface
                    .variants
                    .is_empty()
            );
            assert!(
                variant_state
                    .surface
                    .default_variant_id
                    .is_none()
            );
            let resource = if alias.is_some() {
                "https://gateway.example/mcp$candidate"
            } else {
                "https://gateway.example/mcp"
            };
            let mut variant_message = message.clone();
            variant_message["id"] = json!(40);
            variant_message["params"]
                .as_object_mut()
                .unwrap()
                .remove("requestState");
            variant_message["params"]
                .as_object_mut()
                .unwrap()
                .remove("inputResponses");
            let mut request = build_request(&variant_message);
            *request.uri_mut() = resource.parse().unwrap();
            let before = calls.lock().await.len();
            if alias.is_some() {
                let denied = Box::pin(super::proxy_handler_with_mcp_runtime(
                    address,
                    variant_state.clone(),
                    request,
                    versions,
                    Some(runtime.clone()),
                ))
                .await
                .unwrap_or_else(|response| response);
                assert_eq!(denied.status(), axum::http::StatusCode::UNAUTHORIZED);
                assert_eq!(calls.lock().await.len(), before);
                request = build_request(&variant_message);
                *request.uri_mut() = resource.parse().unwrap();
            }
            let variant_bearer = issuer
                .sign_jwt_with_gateway_key_typ(
                    &json!({
                        "iss": "https://gateway.example/api/oauth2/mcp", "sub": "user", "scope": "read",
                        "aud": resource, "exp": now + 300
                    }),
                    "at+jwt",
                )
                .await
                .unwrap();
            request.headers_mut().insert(
                "authorization",
                format!("Bearer {variant_bearer}")
                    .parse()
                    .unwrap(),
            );
            let crate::mcp::request_validation::McpRequestClassification::Modern(mut original) =
                crate::mcp::request_validation::validate_mcp_post(
                    request.headers(),
                    &serde_json::to_vec(&variant_message).unwrap(),
                    crate::mcp::request_validation::LegacySessionEvidence::Absent,
                    versions,
                )
                .unwrap()
            else {
                panic!("expected admitted variant fixture");
            };
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                variant_state.clone(),
                request,
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            let (status, pending) = decode_response(response).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{pending}");
            assert_eq!(pending["result"]["resultType"], "input_required");
            original.id = Some(json!(41));
            let binding = runtime
                .service
                .request_binding(
                    pending["result"]["requestState"]
                        .as_str()
                        .unwrap(),
                    &original,
                    crate::proxy::credential_delegation::modern::now_secs().unwrap(),
                )
                .unwrap();
            assert_eq!(binding.variant_id.as_deref(), Some("credential-variant"));
            assert_eq!(binding.resource, resource);
            variant_message["id"] = json!(41);
            variant_message["params"]["requestState"] = pending["result"]["requestState"].clone();
            variant_message["params"]["inputResponses"] = json!({"upstream-input": {"action": "accept"}});
            let mut retry = build_request(&variant_message);
            *retry.uri_mut() = resource.parse().unwrap();
            retry.headers_mut().insert(
                "authorization",
                format!("Bearer {variant_bearer}")
                    .parse()
                    .unwrap(),
            );
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                variant_state,
                retry,
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            let (status, complete) = decode_response(response).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{complete}");
            assert_eq!(complete["result"]["resultType"], "complete");
            assert_eq!(calls.lock().await.len(), before + 2);
        }
        use futures::StreamExt;
        let (subscriptions_tx, mut subscriptions_rx) = tokio::sync::mpsc::channel(2);
        let subscription_target = axum::Router::new().fallback(axum::routing::post(
            move |headers: HeaderMap, axum::Json(request): axum::Json<serde_json::Value>| {
                let subscriptions = subscriptions_tx.clone();
                async move {
                    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(2);
                    let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
                    let ack = json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": {
                        "_meta": {"io.modelcontextprotocol/subscriptionId": request["id"]},
                        "notifications": request["params"]["notifications"]
                    }});
                    sender
                        .send(Ok(bytes::Bytes::from(format!("data: {ack}\n\n"))))
                        .await
                        .unwrap();
                    subscriptions
                        .send((headers, request, sender, outcome_rx))
                        .await
                        .unwrap();
                    let response = axum::response::Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver)))
                        .unwrap();
                    crate::mcp::modern_sse::observe_response(response, move |outcome| {
                        let _ = outcome_tx.send(outcome);
                    })
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let subscription_address = listener.local_addr().unwrap();
        tasks.spawn(async move {
            axum::serve(listener, subscription_target)
                .await
                .unwrap();
        });
        Arc::make_mut(&mut state.surface)
            .target
            .endpoint = format!("http://{subscription_address}/mcp");
        let subscription = json!({"jsonrpc": "2.0", "id": "authorized-subscription", "method": "subscriptions/listen", "params": {
            "notifications": {"toolsListChanged": true}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }});
        let subscription_request = || {
            let mut request = build_request(&subscription);
            request.headers_mut().insert(
                "mcp-method",
                "subscriptions/listen"
                    .parse()
                    .unwrap(),
            );
            request
                .headers_mut()
                .remove("mcp-name");
            request.headers_mut().insert(
                "mcp-session-id",
                "ignored-subscription-session"
                    .parse()
                    .unwrap(),
            );
            request
        };
        for invalid in ["missing", "audience", "scope", "expired"] {
            let mut request = subscription_request();
            if invalid == "missing" {
                request
                    .headers_mut()
                    .remove("authorization");
            } else {
                let claims = json!({"iss": "https://gateway.example/api/oauth2/mcp", "sub": "user",
                    "aud": if invalid == "audience" { "https://other.example/mcp" } else { "https://gateway.example/mcp" },
                    "scope": if invalid == "scope" { "write" } else { "read" },
                    "exp": if invalid == "expired" { now - 1 } else { now + 300 }
                });
                let token = issuer
                    .sign_jwt_with_gateway_key_typ(&claims, "at+jwt")
                    .await
                    .unwrap();
                request.headers_mut().insert(
                    "authorization",
                    format!("Bearer {token}")
                        .parse()
                        .unwrap(),
                );
            }
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                request,
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            assert_eq!(
                response.status(),
                if invalid == "scope" {
                    axum::http::StatusCode::FORBIDDEN
                } else {
                    axum::http::StatusCode::UNAUTHORIZED
                },
                "{invalid}"
            );
            assert!(
                response
                    .headers()
                    .contains_key("www-authenticate")
            );
            assert!(
                subscriptions_rx
                    .try_recv()
                    .is_err(),
                "invalid {invalid} reached the subscription Target"
            );
        }
        let policies = Arc::new(
            crate::policies::policy_definitions::FileSystemPolicyDefinitionStore::new(
                directory
                    .path()
                    .join("policies")
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let mut subscription_policy: crate::policies::policy_definitions::PolicyDefinition =
            serde_json::from_value(json!({
                "id": "subscription-policy", "name": "Subscription policy", "policy_type": "agent_surface",
                "policy": "package surface.policy\ndefault allow = true", "created_at": "2026-09-01T00:00:00Z"
            }))
            .unwrap();
        policies
            .save(subscription_policy.clone())
            .await
            .unwrap();
        let policy_manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        policy_manager.set_policy_definition_store(policies.clone());
        Arc::make_mut(&mut state.surface)
            .target
            .policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: subscription_policy.id.clone(),
            require_agent_context: false,
        });
        policy_manager
            .update_channel_policy(&state.surface)
            .await
            .unwrap();
        state.policy_manager = Some(policy_manager.clone());
        for change in ["policy", "vault"] {
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                subscription_request(),
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(
                !response
                    .headers()
                    .contains_key("mcp-session-id")
            );
            let (headers, request, sender, outcome) = subscriptions_rx
                .recv()
                .await
                .unwrap();
            assert_eq!(headers["authorization"], "Bearer verified-credential");
            assert!(!headers.contains_key("mcp-session-id"));
            assert_eq!(request["id"], subscription["id"]);
            assert_eq!(request["method"], "subscriptions/listen");
            let limits = crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
            let mut events = Box::pin(crate::mcp::modern_sse::decode_events(
                response
                    .into_body()
                    .into_data_stream(),
                limits,
            ));
            let ack = tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let ack: serde_json::Value = serde_json::from_str(&ack.data).unwrap();
            assert_eq!(ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], subscription["id"]);
            assert_eq!(ack["params"]["notifications"], json!({"toolsListChanged": true}));
            let active = vault
                .list_all()
                .await
                .unwrap()
                .into_iter()
                .find(|token| token.provider_id == "provider")
                .unwrap();
            assert!(futures::poll!(events.next()).is_pending());
            assert!(!sender.is_closed());
            // A change notification from the upstream reaches the client with
            // its subscription tag.
            let changed = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {
                "_meta": {"io.modelcontextprotocol/subscriptionId": subscription["id"]}
            }});
            sender
                .send(Ok(bytes::Bytes::from(format!("data: {changed}\n\n"))))
                .await
                .unwrap();
            let relayed = tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let relayed: serde_json::Value = serde_json::from_str(&relayed.data).unwrap();
            assert_eq!(relayed["method"], "notifications/tools/list_changed");
            assert_eq!(relayed["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], subscription["id"]);
            if change == "policy" {
                subscription_policy.policy = "package surface.policy\ndefault allow = false".into();
                policies
                    .save(subscription_policy.clone())
                    .await
                    .unwrap();
                policy_manager
                    .update_channel_policy(&state.surface)
                    .await
                    .unwrap();
            } else {
                assert!(
                    vault
                        .delete(&active.id)
                        .await
                        .unwrap()
                );
            }
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            drop(events);
            assert!(
                !tokio::time::timeout(std::time::Duration::from_secs(2), outcome)
                    .await
                    .unwrap()
                    .unwrap()
                    .completed
            );
            assert!(sender.is_closed());
            let response = Box::pin(super::proxy_handler_with_mcp_runtime(
                address,
                state.clone(),
                subscription_request(),
                versions,
                Some(runtime.clone()),
            ))
            .await
            .unwrap_or_else(|response| response);
            assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN, "{change}");
            assert!(
                subscriptions_rx
                    .try_recv()
                    .is_err(),
                "{change} denial reached the subscription Target"
            );
            if change == "policy" {
                subscription_policy.policy = "package surface.policy\ndefault allow = true".into();
                policies
                    .save(subscription_policy.clone())
                    .await
                    .unwrap();
                policy_manager
                    .update_channel_policy(&state.surface)
                    .await
                    .unwrap();
            }
        }
        tasks.shutdown().await;
    }

    fn bearer_with_payload(payload: serde_json::Value) -> String {
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("Bearer header.{payload_b64}.signature")
    }

    #[tokio::test]
    async fn direct_request_resolves_surface_agent_did_audience() {
        let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        vc_issuer
            .get_identity_store()
            .create(crate::identity::test_helpers::test_surface_identity_record(
                "did:webvh:direct-agent",
                "direct-surface",
            ))
            .await
            .expect("store direct surface identity");
        let config = crate::source_auth::SourceAuthConfig::JwtBearer(crate::jwt_bearer::models::JwtBearerAuthConfig {
            audiences: vec![crate::source_auth::middleware::SURFACE_AGENT_DID_AUDIENCE.to_string()],
            ..Default::default()
        });

        let resolved = resolve_direct_surface_auth_config(&config, Some(&vc_issuer), "direct-surface")
            .await
            .expect("resolve direct surface audience");

        let crate::source_auth::SourceAuthConfig::JwtBearer(resolved) = resolved else {
            panic!("expected JWT bearer config");
        };
        assert_eq!(resolved.audiences, vec!["did:webvh:direct-agent"]);
    }

    #[tokio::test]
    async fn legacy_mcp_session_resolution_returns_only_registered_sessions() {
        use crate::mcp::request_validation::LegacySessionEvidence;

        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", HeaderValue::from_static("unknown-session"));
        let unknown = resolve_legacy_mcp_session(&headers).await;
        assert_eq!(unknown, (LegacySessionEvidence::Unknown, None));

        let (session_id, _receiver) = CHANNEL_SSE_SESSION_MGR
            .create_session()
            .await;
        headers.insert("mcp-session-id", HeaderValue::from_str(&session_id).unwrap());
        let known = resolve_legacy_mcp_session(&headers).await;
        assert_eq!(known, (LegacySessionEvidence::Known, Some(session_id.clone())));
        CHANNEL_SSE_SESSION_MGR
            .remove_session(&session_id)
            .await;
    }

    fn surface_with_agent_card_path(path: Option<&str>) -> crate::config::agent_surface::AgentSurface {
        let mut surface = serde_json::json!({
            "name": "Fabric Surface",
            "access_point": {
                "listen_address": "https://gateway.example",
                "route": "/agent",
                "protocol": "a2a"
            },
            "target": {
                "endpoint": "fabric://gw/surface"
            }
        });
        if let Some(path) = path {
            surface["access_point"]["agent_card_path"] = serde_json::json!(path);
        }
        serde_json::from_value(surface).expect("surface fixture")
    }

    #[test]
    fn normalize_route_for_match_trims_trailing_slash() {
        assert_eq!(normalize_route_for_match("a2a/requester/"), "/a2a/requester");
        assert_eq!(normalize_route_for_match("/a2a/requester/"), "/a2a/requester");
        assert_eq!(normalize_route_for_match("/"), "/");
    }

    #[test]
    fn route_tail_to_uri_path_collapses_boundary_slashes() {
        assert_eq!(route_tail_to_uri_path(""), "/");
        assert_eq!(route_tail_to_uri_path("/.well-known/agent-card.json"), "/.well-known/agent-card.json");
        assert_eq!(route_tail_to_uri_path("//.well-known/agent-card.json"), "/.well-known/agent-card.json");
    }

    #[test]
    fn authorization_forwarding_requires_explicit_jwt_opt_in() {
        assert!(!should_forward_ap_request_header_with_mapping("authorization", None, None, false));
        assert!(!should_forward_ap_request_header_with_mapping("authorization", None, None, true));
    }

    #[test]
    fn source_auth_authorization_requires_explicit_jwt_opt_in() {
        assert!(!should_forward_ap_request_header_with_mapping("authorization", Some("authorization"), None, false,));
        assert!(should_forward_ap_request_header_with_mapping("authorization", Some("authorization"), None, true,));
    }

    #[test]
    fn custom_source_auth_header_can_be_forwarded_with_jwt_opt_in() {
        assert!(should_forward_ap_request_header_with_mapping(
            "x-gateway-authorization",
            Some("x-gateway-authorization"),
            None,
            true,
        ));
        assert!(!should_forward_ap_request_header_with_mapping(
            "authorization",
            Some("x-gateway-authorization"),
            None,
            true,
        ));
    }

    #[test]
    fn fabric_agent_card_forward_path_uses_default_well_known_path() {
        let surface = surface_with_agent_card_path(None);

        assert_eq!(agent_card_fabric_forward_path(&surface), "/.well-known/agent-card.json");
    }

    #[test]
    fn fabric_agent_card_forward_path_uses_access_point_override() {
        let surface = surface_with_agent_card_path(Some("custom/card.json"));

        assert_eq!(agent_card_fabric_forward_path(&surface), "/custom/card.json");
    }

    #[test]
    fn a2a_proxy_connection_status_marks_json_rpc_errors_failed() {
        let status = a2a_proxy_connection_status(
            axum::http::StatusCode::OK,
            br#"{"jsonrpc":"2.0","id":"1","error":{"code":-32021,"message":"timeout"}}"#,
        );

        assert_eq!(status, crate::metrics::ConnectionStatus::Failed);
    }

    #[test]
    fn a2a_proxy_connection_status_marks_json_rpc_results_successful() {
        let status = a2a_proxy_connection_status(
            axum::http::StatusCode::OK,
            br#"{"jsonrpc":"2.0","id":"1","result":{"kind":"message"}}"#,
        );

        assert_eq!(status, crate::metrics::ConnectionStatus::Success);
    }

    #[test]
    fn decode_bearer_jwt_claims_extracts_payload_claims() {
        let header = bearer_with_payload(serde_json::json!({ "sub": "agent@example.com", "role": "admin" }));
        let claims = decode_bearer_jwt_claims(&header).expect("claims should decode");
        assert_eq!(
            claims
                .get("sub")
                .and_then(|v| v.as_str()),
            Some("agent@example.com")
        );
        assert_eq!(
            claims
                .get("role")
                .and_then(|v| v.as_str()),
            Some("admin")
        );
    }

    #[test]
    fn decode_bearer_jwt_claims_rejects_invalid_inputs() {
        // Not a Bearer token.
        assert!(decode_bearer_jwt_claims("Basic abc123").is_none());
        // Wrong number of JWT segments.
        assert!(decode_bearer_jwt_claims("Bearer header.payload").is_none());
        // Payload segment is valid base64url but not a JSON object.
        let not_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"hello");
        assert!(decode_bearer_jwt_claims(&format!("Bearer header.{not_json}.sig")).is_none());
    }

    #[test]
    fn ap2_experimental_enabled_defaults_false() {
        let empty_flags = HashMap::new();
        assert!(!ap2_experimental_enabled_from_flags(None));
        assert!(!ap2_experimental_enabled_from_flags(Some(&empty_flags)));
    }

    #[test]
    fn ap2_gate_flag_off_rejects() {
        let decision = evaluate_ap2_inbound_decision(true, false, None);
        assert_eq!(decision, Ap2InboundDecision::RejectFeatureDisabled);
    }

    #[test]
    fn ap2_gate_flag_on_and_transform_error_rejects() {
        let decision = evaluate_ap2_inbound_decision(true, true, Some(false));
        assert_eq!(decision, Ap2InboundDecision::RejectTransformationFailed);
    }

    #[test]
    fn ap2_gate_flag_on_and_transform_success_forwards() {
        let decision = evaluate_ap2_inbound_decision(true, true, Some(true));
        assert_eq!(decision, Ap2InboundDecision::ForwardTransformed);
    }
}
