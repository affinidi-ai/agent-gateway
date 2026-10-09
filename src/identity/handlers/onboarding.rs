use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::identity::state::IdentityApiState;

/// Active onboarding sessions
#[derive(Clone)]
pub struct OnboardingSessionManager {
    sessions: Arc<RwLock<HashMap<String, OnboardingSession>>>,
}

#[derive(Clone)]
pub struct OnboardingSession {
    #[allow(dead_code)]
    pub uuid: String,
    pub protocol: String,
    #[allow(dead_code)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl OnboardingSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_session(
        &self,
        protocol: String,
        ttl_seconds: u64,
    ) -> String {
        let uuid = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let session = OnboardingSession {
            uuid: uuid.clone(),
            protocol,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds as i64),
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(uuid.clone(), session);
        uuid
    }

    pub async fn get_session(
        &self,
        uuid: &str,
    ) -> Option<OnboardingSession> {
        let sessions = self.sessions.read().await;
        sessions.get(uuid).cloned()
    }

    pub async fn is_session_active(
        &self,
        uuid: &str,
    ) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(uuid) {
            chrono::Utc::now() < session.expires_at
        } else {
            false
        }
    }

    pub async fn remove_session(
        &self,
        uuid: &str,
    ) -> bool {
        let mut sessions = self.sessions.write().await;
        sessions
            .remove(uuid)
            .is_some()
    }

    #[allow(dead_code)]
    pub async fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now();
        sessions.retain(|_, session| now < session.expires_at);
    }
}

/// Application error type for onboarding handlers
#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::BadRequest(msg) => {
                warn!("API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            AppError::InternalError(msg) => {
                error!("API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
            }
        };

        let body = Json(ErrorResponse {
            error: message.to_string(),
            details,
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// Request body for creating a temporary onboarding channel
#[derive(Debug, Deserialize)]
pub struct CreateTempOnboardChannelRequest {
    pub protocol: String, // "a2a", "ap2", or "mcp"
}

/// Response for creating a temporary onboarding channel
#[derive(Debug, Serialize)]
pub struct CreateTempOnboardChannelResponse {
    pub config_id: String,
    pub channel_name: String,
    pub endpoint_url: String,
    pub message: String,
    pub ttl_seconds: u64,
}

/// Create a temporary onboarding session
pub async fn create_temp_onboard_surface(
    State(state): State<IdentityApiState>,
    Json(req): Json<CreateTempOnboardChannelRequest>,
) -> Result<Json<CreateTempOnboardChannelResponse>, AppError> {
    // Validate protocol
    if req.protocol != "a2a" && req.protocol != "ap2" && req.protocol != "mcp" {
        return Err(AppError::BadRequest("Protocol must be either 'a2a', 'ap2', or 'mcp'".to_string()));
    }

    let ttl_seconds = state
        .settings_store
        .get_onboarding_channel_ttl_seconds();

    // Use the first available external listen address for the endpoint URL
    let base_url = state
        .network_config
        .get_all_external_urls()
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            format!(
                "https://{}",
                state
                    .network_config
                    .webauthn
                    .rp_id
            )
        });
    let base_url = base_url.trim_end_matches('/');

    // Create onboarding session
    let session_uuid = state
        .onboarding_sessions
        .create_session(req.protocol.clone(), ttl_seconds)
        .await;

    let endpoint_url = match req.protocol.as_str() {
        // MCP clients connect directly to the JSON-RPC POST endpoint; there
        // is no agent-card discovery document in MCP.
        "mcp" => format!("{}/onboard/{}", base_url, session_uuid),
        // A2A / AP2 use the well-known agent card for discovery.
        _ => format!("{}/onboard/{}/.well-known/agent-card.json", base_url, session_uuid),
    };

    info!(
        "Created temporary onboarding session: {} for {} protocol (expires in {}s)",
        session_uuid,
        req.protocol.to_uppercase(),
        ttl_seconds
    );

    // Auto-delete timer
    let session_uuid_clone = session_uuid.clone();
    let onboarding_sessions_clone = state
        .onboarding_sessions
        .clone();
    let ws_state_clone = state.ws_state.clone();

    tokio::spawn(async move {
        info!("Temporary onboarding session '{}' will expire in {} seconds", session_uuid_clone, ttl_seconds);
        tokio::time::sleep(tokio::time::Duration::from_secs(ttl_seconds)).await;

        let removed = onboarding_sessions_clone
            .remove_session(&session_uuid_clone)
            .await;
        if removed {
            info!("Temporary onboarding session '{}' expired and removed", session_uuid_clone);

            ws_state_clone.broadcast(crate::server::WsUpdate::ChannelExpired {
                config_id: session_uuid_clone.clone(),
                channel_name: format!("onboard-{}", session_uuid_clone),
            });
        } else {
            info!("Temporary onboarding session '{}' was already removed", session_uuid_clone);
        }
    });

    Ok(Json(CreateTempOnboardChannelResponse {
        config_id: session_uuid.clone(),
        channel_name: format!("onboard-{}", session_uuid),
        endpoint_url,
        message: format!(
            "Temporary onboarding session created for {} protocol (expires in {}s)",
            req.protocol.to_uppercase(),
            ttl_seconds
        ),
        ttl_seconds,
    }))
}

/// Delete a temporary onboarding session
pub async fn delete_temp_onboard_channel(
    Path(config_id): Path<String>,
    State(state): State<IdentityApiState>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("Deleting temporary onboarding session: {}", config_id);

    let removed = state
        .onboarding_sessions
        .remove_session(&config_id)
        .await;

    if !removed {
        return Err(AppError::BadRequest(format!("Temporary onboarding session '{}' not found", config_id)));
    }

    info!("Temporary onboarding session deleted successfully: {}", config_id);

    Ok(Json(serde_json::json!({
        "message": "Temporary onboarding session deleted successfully",
        "config_id": config_id
    })))
}

/// Serve agent-card.json for onboarding session
pub async fn serve_onboarding_agent_card(
    Path(uuid): Path<String>,
    State(state): State<IdentityApiState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("=== GET ONBOARDING AGENT CARD REQUEST ===");
    info!("Session UUID: {}", uuid);
    info!("Request headers:");
    for (name, value) in headers.iter() {
        if let Ok(val_str) = value.to_str() {
            info!("  {}: {}", name, val_str);
        }
    }

    // Check if session is active
    if !state
        .onboarding_sessions
        .is_session_active(&uuid)
        .await
    {
        warn!("Onboarding request for invalid or expired session: {}", uuid);
        warn!(
            "Available sessions: {:?}",
            state
                .onboarding_sessions
                .sessions
                .read()
                .await
                .keys()
                .collect::<Vec<_>>()
        );
        return Err(AppError::BadRequest("Invalid or expired onboarding session".to_string()));
    }

    // Get session details
    let session = state
        .onboarding_sessions
        .get_session(&uuid)
        .await
        .ok_or_else(|| AppError::InternalError("Session disappeared after validation".to_string()))?;

    info!(
        "Session found - Protocol: {}, Created: {}, Expires: {}",
        session.protocol, session.created_at, session.expires_at
    );

    // Use the first available external listen address for the endpoint URL
    let base_url = state
        .network_config
        .get_all_external_urls()
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            format!(
                "https://{}",
                state
                    .network_config
                    .webauthn
                    .rp_id
            )
        });
    let base_url = base_url.trim_end_matches('/');

    let agent_card = build_onboarding_agent_card(base_url, &uuid);

    info!("Sending agent card response: {}", serde_json::to_string_pretty(&agent_card).unwrap_or_default());
    info!("=== END GET ONBOARDING AGENT CARD REQUEST ===");

    Ok(Json(agent_card))
}

/// Handle POST requests to onboarding endpoint (A2A message exchange)
pub async fn handle_onboarding_message(
    Path(uuid): Path<String>,
    State(state): State<IdentityApiState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("=== POST ONBOARDING MESSAGE REQUEST ===");
    info!("Session UUID: {}", uuid);
    info!("Request headers:");
    for (name, value) in headers.iter() {
        if let Ok(val_str) = value.to_str() {
            info!("  {}: {}", name, val_str);
        }
    }
    info!("Request body (raw): {} bytes", body.len());

    // Parse JSON manually to provide better error messages
    let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        error!("Failed to parse JSON body: {}", e);
        AppError::BadRequest(format!("Invalid JSON: {}", e))
    })?;

    info!("Request body: {}", serde_json::to_string_pretty(&payload).unwrap_or_default());

    // Check if session is active
    if !state
        .onboarding_sessions
        .is_session_active(&uuid)
        .await
    {
        warn!("Onboarding message for invalid or expired session: {}", uuid);
        warn!(
            "Available sessions: {:?}",
            state
                .onboarding_sessions
                .sessions
                .read()
                .await
                .keys()
                .collect::<Vec<_>>()
        );

        // Return JSON-RPC error for expired session
        let error_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "error": {
                "code": -32001,
                "message": "Invalid or expired onboarding session"
            }
        });
        info!("Sending JSON-RPC error response: {}", serde_json::to_string_pretty(&error_response).unwrap_or_default());
        return Ok(Json(error_response));
    }

    info!("Session validated successfully");

    // Branch by session protocol. MCP uses different JSON-RPC methods
    // (`initialize`, `tools/list`, `tools/call`, ...) and stores agent
    // identity under `_meta.<field>` rather than the A2A extension-uri
    // metadata block, so it needs its own minimal responder.
    let session_protocol = state
        .onboarding_sessions
        .get_session(&uuid)
        .await
        .map(|s| s.protocol)
        .unwrap_or_default();
    if session_protocol == "mcp" {
        return handle_mcp_onboarding_message(state, uuid, payload).await;
    }

    // Extract JSON-RPC request ID (required for proper RPC response)
    let rpc_request_id = match payload.get("id") {
        Some(id) => id.clone(),
        None => {
            let error_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: Missing 'id' field"
                }
            });
            return Ok(Json(error_response));
        }
    };

    // Verify this is a JSON-RPC 2.0 request
    let jsonrpc_version = payload
        .get("jsonrpc")
        .and_then(|v| v.as_str());
    if jsonrpc_version != Some("2.0") {
        let error_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": rpc_request_id,
            "error": {
                "code": -32600,
                "message": format!("Invalid Request: Expected jsonrpc '2.0', got {:?}", jsonrpc_version)
            }
        });
        return Ok(Json(error_response));
    }

    let method = payload
        .get("method")
        .and_then(|v| v.as_str());
    if !method.is_some_and(is_onboarding_send_method) {
        let error_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": rpc_request_id,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {:?}", method)
            }
        });
        return Ok(Json(error_response));
    }

    // Extract params from JSON-RPC request
    let params = match payload.get("params") {
        Some(p) => p,
        None => {
            let error_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": rpc_request_id,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: Missing 'params' field"
                }
            });
            return Ok(Json(error_response));
        }
    };

    // Extract agent identity from A2A message metadata
    // According to A2A protocol, the structure should be:
    // { "params": { "message": { "metadata": { "extension-uri": { "agentIdentity": {...} } } } } }
    let agent_identity_ext_uri = "https://fabric.affinidi.io/extensions/agent-identity/v1";

    let mut derived_schema = serde_json::json!({
        "type": "object",
        "properties": {},
        "required": []
    });

    let mut agent_identity_metadata: Option<serde_json::Value> = None;

    // Try to extract agent identity from the params.message
    if let Some(message) = params.get("message")
        && let Some(metadata) = message.get("metadata")
        && let Some(extension_data) = metadata.get(agent_identity_ext_uri)
        && let Some(identity) = extension_data.get("agentIdentity")
    {
        info!("Found agent identity in message metadata");
        agent_identity_metadata = Some(identity.clone());

        // Derive schema from the agent identity
        derived_schema = crate::a2a::schema::derive_schema_from_metadata(identity);
        info!("Derived schema: {}", serde_json::to_string_pretty(&derived_schema).unwrap_or_default());
    }

    // Define channel name for metrics and broadcasting
    let channel_name = format!("onboard-{}", uuid);

    // Store the payload in metrics for later retrieval
    state
        .metrics_store
        .store_latest_channel_payload(channel_name.clone(), payload.clone())
        .await;

    info!("Payload captured - will broadcast with response after processing");

    // Build response message with details about what was captured
    let mut response_text = String::from("Hello! Onboarding connection successful.\n\n");
    response_text.push_str("Your agent is now connected to the Affinidi Fabric Affinidi Trust Fabric Gateway.\n\n");

    if let Some(identity) = &agent_identity_metadata {
        response_text.push_str("✓ Agent identity metadata captured and schema derived\n\n");

        // Add details from the captured identity
        if let Some(llm_info) = identity.get("llmInfo")
            && let Some(provider) = llm_info
                .get("provider")
                .and_then(|v| v.as_str())
            && let Some(model) = llm_info
                .get("model")
                .and_then(|v| v.as_str())
        {
            response_text.push_str(&format!("LLM: {} {}\n", provider, model));
        }
        if let Some(sw_info) = identity.get("softwareInfo")
            && let Some(name) = sw_info
                .get("name")
                .and_then(|v| v.as_str())
            && let Some(version) = sw_info
                .get("version")
                .and_then(|v| v.as_str())
        {
            response_text.push_str(&format!("Software: {} v{}\n", name, version));
        }
    } else {
        response_text.push_str("Note: No agent identity metadata found in request.\n");
        response_text.push_str("To enable schema derivation, include agent identity in message metadata.\n");
    }

    // Create server's agent identity to include in response
    let server_identity = serde_json::json!({
        "llmInfo": {
            "provider": "Affinidi",
            "model": "Affinidi Trust Fabric Gateway",
            "version": "1.0.0"
        },
        "softwareInfo": {
            "name": "Affinidi Fabric Gateway",
            "version": "0.1.0",
            "build": "rust-production"
        },
        "region": "cloud",
        "provisioningInfo": {
            "environment": "production",
            "instanceId": uuid.clone(),
            "deployedAt": chrono::Utc::now().to_rfc3339()
        }
    });

    // Build A2A task response with server identity in metadata
    let task_id = format!("onboard-{}", uuid::Uuid::new_v4());
    let message_id = format!("msg-{}", uuid::Uuid::new_v4());

    // Construct the A2A Task result (this goes inside the JSON-RPC result field)
    let task_result = serde_json::json!({
        "kind": "task",
        "id": task_id.clone(),
        "contextId": uuid.clone(),
        "status": {
            "state": "completed",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "message": {
                "kind": "message",
                "role": "agent",
                "messageId": message_id,
                "parts": [{
                    "kind": "text",
                    "type": "text",
                    "text": response_text
                }],
                "taskId": task_id,
                "contextId": uuid.clone(),
                "extensions": [agent_identity_ext_uri],
                "metadata": {
                    agent_identity_ext_uri: {
                        "agentIdentity": server_identity
                    }
                }
            }
        },
        "history": [],
        "metadata": {},
        "artifacts": []
    });

    // Wrap in JSON-RPC 2.0 response format
    let rpc_response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_request_id,
        "result": task_result
    });

    // Broadcast the successful response with validation success
    let ws_update = crate::server::WsUpdate::PayloadCaptured {
        channel: channel_name.clone(),
        config_id: uuid.clone(),
        payload: payload.clone(),
        response_payload: Some(rpc_response.clone()),
        outbound_request: Box::new(None), // Onboarding doesn't transform outbound
        inbound_response: Box::new(None), // Onboarding doesn't have separate inbound response
        timestamp: chrono::Utc::now().to_rfc3339(),
        validation_status: "success".to_string(),
        validation_error: None,
        derived_schema: Box::new(derived_schema.clone()),
        variant_alias: None,
    };

    // Log the exact WebSocket message being broadcast
    if let Ok(ws_json) = serde_json::to_string_pretty(&ws_update) {
        info!("Broadcasting WebSocket message:\n{}", ws_json);
    }

    info!("Broadcasting payload capture for channel: {}, config_id: {}", channel_name, uuid);
    state
        .ws_state
        .broadcast(ws_update);
    info!("Broadcast complete");

    info!("Sending JSON-RPC response: {}", serde_json::to_string_pretty(&rpc_response).unwrap_or_default());
    info!("=== END ONBOARDING MESSAGE REQUEST ===");

    Ok(Json(rpc_response))
}

/// The onboarding endpoint answers the A2A send operation in either era
/// (`message/send` or `SendMessage`) and its own `agent/send-message` alias.
fn is_onboarding_send_method(method: &str) -> bool {
    method == "agent/send-message" || crate::a2a::canonical_method(method) == "message/send"
}

/// Minimal MCP responder for onboarding sessions. Accepts the discovery
/// methods an MCP client will issue (`initialize`, `tools/list`,
/// `tools/call`, `ping`) and extracts agent identity from
/// `_meta.agentIdentity` (top-level or under `params._meta`) for schema
/// derivation. Notifications without an `id` field receive an empty
/// response.
async fn handle_mcp_onboarding_message(
    state: IdentityApiState,
    uuid: String,
    payload: serde_json::Value,
) -> Result<Json<serde_json::Value>, AppError> {
    let method = payload
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let rpc_request_id = payload.get("id").cloned();
    let params = payload
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    info!("MCP onboarding request — method={} id={:?}", method, rpc_request_id);

    // Identity extraction: prefer params._meta, fall back to top-level _meta
    // (some clients still send identity at the envelope root).
    let meta_field = "agentIdentity";
    let mut derived_schema = serde_json::json!({
        "type": "object",
        "properties": {},
        "required": []
    });
    let mut agent_identity_metadata: Option<serde_json::Value> = None;
    let meta = params
        .get("_meta")
        .or_else(|| payload.get("_meta"));
    if let Some(meta) = meta
        && let Some(identity) = meta.get(meta_field)
    {
        info!("Found agent identity in MCP _meta");
        agent_identity_metadata = Some(identity.clone());
        derived_schema = crate::a2a::schema::derive_schema_from_metadata(identity);
    }

    // Build the method-specific result. We respond to the common
    // discovery surface and treat anything else as a polite echo.
    let result: serde_json::Value = match method {
        "initialize" => serde_json::json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "Affinidi Fabric Onboarding (MCP)",
                "version": "1.0.0"
            },
            "capabilities": {
                "tools": {}
            },
            "_meta": {
                meta_field: {
                    "softwareInfo": {
                        "name": "Affinidi Fabric Gateway",
                        "version": "0.1.0"
                    }
                }
            }
        }),
        "tools/list" => serde_json::json!({
            "tools": [{
                "name": "onboarding.echo",
                "description": "Onboarding probe tool — returns a confirmation message.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }]
        }),
        "tools/call" => {
            let text = if agent_identity_metadata.is_some() {
                "Onboarding connection successful. Agent identity captured and schema derived.".to_string()
            } else {
                "Onboarding connection successful. No agent identity found in _meta — \
                    include it on tools/call to enable schema derivation."
                    .to_string()
            };
            serde_json::json!({
                "content": [{ "type": "text", "text": text }],
                "isError": false
            })
        }
        "ping" => serde_json::json!({}),
        // Notifications (no id) or unknown methods: empty success result.
        _ => serde_json::json!({}),
    };

    // Notifications carry no `id` per JSON-RPC 2.0 and should not receive
    // a response. We still need to return a body for axum, but use a 204
    // empty object so well-behaved clients ignore it.
    let rpc_response = if rpc_request_id.is_none() {
        serde_json::json!({})
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": rpc_request_id,
            "result": result
        })
    };

    let channel_name = format!("onboard-{}", uuid);
    state
        .metrics_store
        .store_latest_channel_payload(channel_name.clone(), payload.clone())
        .await;

    let ws_update = crate::server::WsUpdate::PayloadCaptured {
        channel: channel_name.clone(),
        config_id: uuid.clone(),
        payload: payload.clone(),
        response_payload: Some(rpc_response.clone()),
        outbound_request: Box::new(None),
        inbound_response: Box::new(None),
        timestamp: chrono::Utc::now().to_rfc3339(),
        validation_status: "success".to_string(),
        validation_error: None,
        derived_schema: Box::new(derived_schema),
        variant_alias: None,
    };
    state
        .ws_state
        .broadcast(ws_update);

    info!("MCP onboarding response: {}", serde_json::to_string_pretty(&rpc_response).unwrap_or_default());
    Ok(Json(rpc_response))
}

/// Build the onboarding agent card as a valid **A2A v1.0** document, dual-emitting
/// the legacy v0.3 transport fields.
///
/// Extracted from the handler so the emitted shape is unit-testable: this is one of
/// only two cards the gateway *generates* (the other is the synthesized A2A-proxy
/// card). Cards belonging to a managed agent are passed through at the upstream's
/// own version and are never reshaped here.
fn build_onboarding_agent_card(
    base_url: &str,
    uuid: &str,
) -> serde_json::Value {
    let onboarding_url = format!("{}/onboard/{}/", base_url, uuid);
    let provider = serde_json::json!({ "organization": "Affinidi", "url": "https://affinidi.com" });
    // The onboarding agent serves no extended card.
    let extended_agent_card = false;
    // The onboarding agent belongs to no surface, so it advertises every
    // version the gateway supports.
    let accepted = crate::a2a::version::SUPPORTED_VERSIONS;

    let mut card = serde_json::json!({
        "name": "Affinidi Fabric Onboarding Agent",
        "description": "Temporary onboarding agent for testing agent connectivity and identity exchange",
        // A2A 1.0 renamed `agentProvider` → `provider`.
        "provider": provider.clone(),
        "version": "1.0.0",
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            // A2A 1.0 moved `supportsAuthenticatedExtendedCard` here and removed
            // `stateTransitionHistory` entirely.
            "extendedAgentCard": extended_agent_card,
            "extensions": [{
                "uri": "https://fabric.affinidi.io/extensions/agent-identity/v1",
                "description": "Supports exchanging agent identity information",
                "required": true
            }]
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{
            "id": "onboarding-test",
            "name": "Onboarding Test",
            "description": "Verifies connectivity for agent onboarding",
            "tags": ["onboarding", "connectivity"],
            "examples": ["Test connection", "Verify setup"],
            "inputModes": ["text/plain"],
            "outputModes": ["text/plain"]
        }],
        // A2A 1.0: `url` + `preferredTransport` collapse into one ordered
        // `supportedInterfaces[]`; `transport` became `protocolBinding`.
        "supportedInterfaces": crate::a2a::version::generated_supported_interfaces(&onboarding_url, accepted),

    });

    // Legacy v0.3 fields, including the top-level `protocolVersion`.
    if let Some(legacy) =
        crate::a2a::version::legacy_v0_3_card_fields(&onboarding_url, &provider, extended_agent_card, accepted)
        && let Some(object) = card.as_object_mut()
    {
        object.extend(legacy);
    }

    card
}

#[cfg(test)]
mod onboarding_card_tests {
    use super::*;

    #[test]
    fn onboarding_accepts_the_send_operation_in_either_era() {
        assert!(is_onboarding_send_method("SendMessage"));
        assert!(is_onboarding_send_method("message/send"));
        assert!(is_onboarding_send_method("agent/send-message"));
    }

    #[test]
    fn onboarding_refuses_methods_other_than_send() {
        assert!(!is_onboarding_send_method("SendStreamingMessage"));
        assert!(!is_onboarding_send_method("GetTask"));
        assert!(!is_onboarding_send_method("tasks/send"));
        assert!(!is_onboarding_send_method("sendmessage"));
        assert!(!is_onboarding_send_method(""));
    }

    #[test]
    fn onboarding_card_advertises_1_0_when_no_version_is_configured() {
        let card = build_onboarding_agent_card("https://gw.example", "session-123");

        assert_eq!(card["protocolVersion"], "1.0");
        assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
    }

    #[test]
    fn onboarding_card_advertises_the_configured_version() {
        if !crate::a2a::version::run_isolated_from_other_tests() {
            return;
        }
        crate::a2a::version::init_advertised_version("0.3");

        let card = build_onboarding_agent_card("https://gw.example", "session-123");

        assert_eq!(card["protocolVersion"], "0.3");
        assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "0.3");
        assert_eq!(card["supportedInterfaces"][1]["protocolVersion"], "1.0");
    }

    /// The onboarding agent belongs to no surface and serves both versions, so
    /// its card lists both and carries the v0.3 fields.
    #[test]
    fn onboarding_card_lists_every_supported_version() {
        let card = build_onboarding_agent_card("https://gw.example", "session-123");

        let listed: Vec<&str> = card["supportedInterfaces"]
            .as_array()
            .expect("supportedInterfaces")
            .iter()
            .map(|i| {
                i["protocolVersion"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        assert_eq!(listed, vec!["1.0", "0.3"]);
        assert_eq!(card["protocolVersion"], "1.0");
    }

    #[test]
    fn onboarding_card_is_valid_a2a_1_0() {
        let card = build_onboarding_agent_card("https://gw.example", "session-123");
        let expected_url = "https://gw.example/onboard/session-123/";

        let advertised = crate::a2a::version::effective_advertised_version(crate::a2a::version::SUPPORTED_VERSIONS);
        assert_eq!(card["protocolVersion"], advertised);

        // 1.0 transport shape: one ordered `supportedInterfaces[]` in camelCase with
        // `protocolBinding` (JSONRPC, not HTTP+JSON) and a per-interface version.
        let iface = &card["supportedInterfaces"][0];
        assert_eq!(iface["url"], expected_url);
        assert_eq!(iface["protocolBinding"], crate::a2a::version::PROTOCOL_BINDING_JSONRPC);
        assert_eq!(iface["protocolVersion"], advertised);
        assert!(iface["transport"].is_null(), "`transport` became `protocolBinding` in 1.0");

        // Renamed / relocated / removed fields.
        // The 1.0 spellings are canonical.
        assert_eq!(card["provider"]["organization"], "Affinidi");
        assert_eq!(card["capabilities"]["extendedAgentCard"], false);

        // The onboarding agent accepts v0.3 too, so the v0.3 spellings are emitted
        // as well, and a v0.3 reader gets a card it can act on rather than one it
        // can only partially parse. They track the 1.0 values rather than being
        // hardcoded.
        assert_eq!(card["agentProvider"], card["provider"]);
        assert_eq!(card["supportsAuthenticatedExtendedCard"], card["capabilities"]["extendedAgentCard"]);

        // Removed outright in 1.0 with no successor, so it is not resurrected.
        assert!(
            card["capabilities"]["stateTransitionHistory"].is_null(),
            "`stateTransitionHistory` was removed in 1.0"
        );

        // Skill `tags` are required in 1.0.
        assert!(
            card["skills"][0]["tags"]
                .as_array()
                .is_some_and(|t| !t.is_empty())
        );

        // The identity extension the onboarding flow relies on is still declared.
        assert_eq!(
            card["capabilities"]["extensions"][0]["uri"],
            "https://fabric.affinidi.io/extensions/agent-identity/v1"
        );

        // Legacy v0.3 fields remain dual-emitted for 0.3 clients.
        assert_eq!(card["url"], expected_url);
        assert_eq!(card["preferredTransport"], crate::a2a::version::PROTOCOL_BINDING_JSONRPC);

        // The gateway never signs the cards it generates.
        assert!(card["signatures"].is_null());
    }

    #[test]
    fn onboarding_card_trims_and_builds_the_session_url() {
        // The handler passes a base URL already stripped of a trailing slash; the
        // interface URL and the legacy `url` must agree.
        let card = build_onboarding_agent_card("https://gw.example", "abc");
        assert_eq!(card["url"], card["supportedInterfaces"][0]["url"]);
        assert_eq!(card["url"], "https://gw.example/onboard/abc/");
    }
}
