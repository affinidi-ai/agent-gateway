//! MCP `elicitation/create` — spec-compliant types, builders, parsing, and
//! a per-session pending-request registry.
//!
//! Spec reference: <https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation>
//!
//! Key constraints the spec imposes that this module enforces:
//!
//! - `requestedSchema` is restricted to a flat object whose properties are
//!   primitives only (`string`/`number`/`integer`/`boolean`/enum). No
//!   nested objects, no arrays of objects.
//! - String formats are limited to `email`, `uri`, `date`, `date-time`.
//! - Servers MUST NOT request sensitive information. The OAuth-consent
//!   builder in this module asks only for a `boolean` confirmation, never
//!   the user's password or token.
//! - The response action is one of `accept` / `decline` / `cancel`.
//! - The request must be a JSON-RPC 2.0 request (has an `id`); the client's
//!   response is correlated by that `id`.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;

/// The full JSON-RPC 2.0 envelope for a server→client `elicitation/create`
/// request. Serialize and write straight onto an open MCP Streamable HTTP / SSE
/// stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationCreateRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: ElicitationCreateParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationCreateParams {
    pub message: String,
    #[serde(rename = "requestedSchema")]
    pub requested_schema: RequestedSchema,
}

/// The top-level `requestedSchema` — always `type: "object"` per spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    pub properties: HashMap<String, SchemaProperty>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub required: Vec<String>,
}

impl RequestedSchema {
    pub fn new() -> Self {
        Self {
            schema_type: "object".to_string(),
            properties: HashMap::new(),
            required: Vec::new(),
        }
    }
}

impl Default for RequestedSchema {
    fn default() -> Self {
        Self::new()
    }
}

/// A single property in `requestedSchema.properties`. Restricted to the
/// primitive types the spec allows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SchemaProperty {
    String(StringProperty),
    Number(NumberProperty),
    Integer(NumberProperty),
    Boolean(BooleanProperty),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringProperty {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    /// Spec-restricted: `email`, `uri`, `date`, `date-time`. Validated by
    /// [`StringFormat`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<StringFormat>,
    /// Enum values. When set, the property becomes an enum field. The spec
    /// also allows `enumNames` for display labels.
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "enumNames", skip_serializing_if = "Option::is_none")]
    pub enum_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StringFormat {
    Email,
    Uri,
    Date,
    #[serde(rename = "date-time")]
    DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NumberProperty {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BooleanProperty {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,
}

// ── Response ─────────────────────────────────────────────────────────────

/// The full JSON-RPC 2.0 response from the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ElicitationResponseEnvelope {
    pub jsonrpc: String,
    pub id: Value,
    pub result: ElicitationResult,
}

/// The three-action response model. Only `Accept` carries `content`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum ElicitationResult {
    Accept {
        #[serde(default)]
        content: Value,
    },
    Decline,
    Cancel,
}

// ── Builders ─────────────────────────────────────────────────────────────

/// Build a spec-compliant `elicitation/create` request that asks the user to
/// authorize an OAuth provider so the gateway can call a specific MCP tool on
/// their behalf.
///
/// The authorization URL is embedded in the human-readable `message` and is
/// **not** part of `requestedSchema` (we are not asking the user to type or
/// paste sensitive data — we are asking them to confirm a navigation they will
/// complete in their browser). The `authorize` boolean property exists so the
/// client UI has something to render an Accept button against.
pub fn build_oauth_consent_elicitation(
    request_id: Value,
    provider_name: &str,
    tool_name: Option<&str>,
    scopes: &[String],
    authorization_url: &str,
) -> ElicitationCreateRequest {
    // Strip control characters from provider_name to prevent message
    // manipulation. Allow printable chars (punctuation, unicode letters).
    let safe_provider_name: String = provider_name
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let safe_provider_name = if safe_provider_name.is_empty() {
        "Unknown Provider"
    } else {
        &safe_provider_name
    };

    let scope_blurb = if scopes.is_empty() {
        String::new()
    } else {
        format!(" (scopes: {})", scopes.join(", "))
    };
    let tool_blurb = tool_name
        .map(|t| format!(" to run `{}`", t))
        .unwrap_or_default();

    let message = format!(
        "{safe_provider_name} access is required{tool_blurb}{scope_blurb}.\n\nOpen this URL in your \
         browser, sign in with {safe_provider_name}, then return here and click Accept:\n\n{authorization_url}",
    );

    let mut props = HashMap::new();
    props.insert(
        "authorize".to_string(),
        SchemaProperty::Boolean(BooleanProperty {
            title: Some(format!("Authorize {safe_provider_name}")),
            description: Some(
                "Open the URL above in your browser, complete sign-in, then click Accept to continue.".to_string(),
            ),
            default: Some(false),
        }),
    );

    ElicitationCreateRequest {
        jsonrpc: "2.0".to_string(),
        id: request_id,
        method: "elicitation/create".to_string(),
        params: ElicitationCreateParams {
            message,
            requested_schema: RequestedSchema {
                schema_type: "object".to_string(),
                properties: props,
                required: vec!["authorize".to_string()],
            },
        },
    }
}

// ── Schema validation (defence-in-depth) ─────────────────────────────────

/// Validate that a [`RequestedSchema`] only uses spec-allowed shapes.
/// Returns the first violation it finds. Designed to be called before sending
/// any elicitation onto the wire so a misconfigured caller can't smuggle a
/// non-conformant schema to the client.
#[allow(dead_code)]
pub fn validate_requested_schema(schema: &RequestedSchema) -> Result<(), SchemaViolation> {
    if schema.schema_type != "object" {
        return Err(SchemaViolation::TopLevelNotObject(schema.schema_type.clone()));
    }
    for (name, prop) in &schema.properties {
        match prop {
            SchemaProperty::String(_)
            | SchemaProperty::Number(_)
            | SchemaProperty::Integer(_)
            | SchemaProperty::Boolean(_) => {}
        }
        if name.is_empty() {
            return Err(SchemaViolation::EmptyPropertyName);
        }
    }
    for req in &schema.required {
        if !schema
            .properties
            .contains_key(req)
        {
            return Err(SchemaViolation::RequiredMissing(req.clone()));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SchemaViolation {
    #[error("requestedSchema.type must be \"object\", got {0:?}")]
    TopLevelNotObject(String),
    #[error("requestedSchema.required references property {0:?} which is not declared")]
    RequiredMissing(String),
    #[error("requestedSchema.properties contains an empty property name")]
    EmptyPropertyName,
}

// ── Pending-request registry ─────────────────────────────────────────────

/// Per-MCP-session map: `elicit request id` -> oneshot waker for the eventual
/// response. The tool-call handler `await`s the receiver; the SSE-response
/// dispatcher fires `send(...)` when it sees the matching client reply.
///
/// Keyed on the MCP `Mcp-Session-Id` so two concurrent sessions can each have
/// their own pending elicitations without colliding.
#[derive(Debug, Default)]
pub struct PendingElicitationRegistry {
    inner: Mutex<HashMap<String, HashMap<String, oneshot::Sender<ElicitationResult>>>>,
}

impl PendingElicitationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fresh elicitation for `session_id`. Returns the generated
    /// `request_id` (use it as the JSON-RPC `id`) and the receiver to await.
    pub async fn register(
        &self,
        session_id: &str,
    ) -> (String, oneshot::Receiver<ElicitationResult>) {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let mut guard = self.inner.lock().await;
        guard
            .entry(session_id.to_string())
            .or_default()
            .insert(id.clone(), tx);
        (id, rx)
    }

    /// Called by the SSE dispatcher when it observes a client response whose
    /// `id` matches a pending elicitation. Returns `true` if a waiter was
    /// woken, `false` if the id was unknown (response arrived too late or for
    /// a different request).
    pub async fn resolve(
        &self,
        session_id: &str,
        request_id: &str,
        result: ElicitationResult,
    ) -> bool {
        let mut guard = self.inner.lock().await;
        if let Some(session_map) = guard.get_mut(session_id)
            && let Some(tx) = session_map.remove(request_id)
        {
            return tx.send(result).is_ok();
        }
        false
    }

    /// Cancel and drop any pending elicitations for a session (e.g. on
    /// DELETE / transport close). Receivers will observe the channel closing.
    pub async fn drop_session(
        &self,
        session_id: &str,
    ) {
        let mut guard = self.inner.lock().await;
        guard.remove(session_id);
    }

    /// Remove a single pending elicitation by session + request id. Used to
    /// clean up the registry entry after the waiter has resolved (timeout,
    /// cancel, decline) so stale senders don't leak memory.
    pub async fn remove(
        &self,
        session_id: &str,
        request_id: &str,
    ) {
        let mut guard = self.inner.lock().await;
        if let Some(session_map) = guard.get_mut(session_id) {
            session_map.remove(request_id);
            if session_map.is_empty() {
                guard.remove(session_id);
            }
        }
    }
}

/// Convenience alias so callers can store a shared registry.
pub type SharedPendingElicitationRegistry = Arc<PendingElicitationRegistry>;

// ── Client capability tracking ───────────────────────────────────────────

/// Parses the `capabilities.elicitation` field out of a client's `initialize`
/// request params. Presence of the key (even with an empty object) signals
/// the client supports elicitation, per spec §2.
#[allow(dead_code)]
pub fn client_supports_elicitation(initialize_params: &Value) -> bool {
    initialize_params
        .get("capabilities")
        .and_then(|c| c.get("elicitation"))
        .is_some()
}

/// Per-session capability snapshot recorded from `initialize`. Stored under
/// `Mcp-Session-Id` so subsequent tool calls can consult it.
#[derive(Debug, Clone, Default)]
pub struct McpClientCapabilities {
    pub elicitation: bool,
    #[allow(dead_code)]
    pub sampling: bool,
    #[allow(dead_code)]
    pub roots: bool,
}

impl McpClientCapabilities {
    pub fn from_initialize_params(params: &Value) -> Self {
        let caps = params.get("capabilities");
        Self {
            elicitation: caps
                .and_then(|c| c.get("elicitation"))
                .is_some(),
            sampling: caps
                .and_then(|c| c.get("sampling"))
                .is_some(),
            roots: caps
                .and_then(|c| c.get("roots"))
                .is_some(),
        }
    }
}

#[derive(Debug, Default)]
pub struct McpCapabilityRegistry {
    inner: Mutex<HashMap<String, McpClientCapabilities>>,
}

impl McpCapabilityRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn record(
        &self,
        session_id: &str,
        caps: McpClientCapabilities,
    ) {
        self.inner
            .lock()
            .await
            .insert(session_id.to_string(), caps);
    }
    pub async fn get(
        &self,
        session_id: &str,
    ) -> Option<McpClientCapabilities> {
        self.inner
            .lock()
            .await
            .get(session_id)
            .cloned()
    }
    pub async fn drop_session(
        &self,
        session_id: &str,
    ) {
        self.inner
            .lock()
            .await
            .remove(session_id);
    }
}

pub type SharedMcpCapabilityRegistry = Arc<McpCapabilityRegistry>;

// ── Process-global singletons ────────────────────────────────────────────
//
// These mirror the OnceCell pattern used by `gateways::connection_points::
// message_processor` for the delegation-vault store. They let cross-cutting
// MCP code (proxy handlers, credential delegation, SSE writer) reach the
// registries without threading them through every ProxyState/MultiChannel
// constructor. Tests construct private instances directly.

static GLOBAL_MCP_CAPABILITY_REGISTRY: std::sync::OnceLock<SharedMcpCapabilityRegistry> = std::sync::OnceLock::new();
static GLOBAL_PENDING_ELICITATION_REGISTRY: std::sync::OnceLock<SharedPendingElicitationRegistry> =
    std::sync::OnceLock::new();

/// Process-wide MCP client capability registry, keyed by `Mcp-Session-Id`.
pub fn global_capability_registry() -> &'static SharedMcpCapabilityRegistry {
    GLOBAL_MCP_CAPABILITY_REGISTRY.get_or_init(|| Arc::new(McpCapabilityRegistry::new()))
}

/// Process-wide registry of in-flight `elicitation/create` requests awaiting
/// a client response, keyed by `Mcp-Session-Id` and elicitation id.
pub fn global_pending_elicitation_registry() -> &'static SharedPendingElicitationRegistry {
    GLOBAL_PENDING_ELICITATION_REGISTRY.get_or_init(|| Arc::new(PendingElicitationRegistry::new()))
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Try to parse a JSON-RPC envelope from the client and, if it looks like the
/// response to one of our pending elicitations, return `(request_id, result)`.
/// Returns `None` if the envelope isn't an elicitation response.
pub fn try_parse_elicitation_response(envelope: &Value) -> Option<(String, ElicitationResult)> {
    // Only responses have `result` and an `id`. Server-initiated responses to
    // elicitation/create always carry the original request id.
    let id = envelope.get("id")?;
    let result = envelope.get("result")?;
    let action = result
        .get("action")
        .and_then(|v| v.as_str())?;

    let parsed = match action {
        "accept" => {
            let content = result
                .get("content")
                .cloned()
                .unwrap_or(json!({}));
            ElicitationResult::Accept { content }
        }
        "decline" => ElicitationResult::Decline,
        "cancel" => ElicitationResult::Cancel,
        _ => return None,
    };

    let id_str = match id {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    Some((id_str, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_spec_shape() {
        let req = build_oauth_consent_elicitation(
            json!("req-1"),
            "GitHub",
            Some("create_issue"),
            &["repo".to_string(), "read:user".to_string()],
            "https://github.com/login/oauth/authorize?state=xyz",
        );
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "elicitation/create");
        assert_eq!(
            req.params
                .requested_schema
                .schema_type,
            "object"
        );
        assert!(
            req.params
                .message
                .contains("GitHub")
        );
        assert!(
            req.params
                .message
                .contains("create_issue")
        );
        assert!(
            req.params
                .message
                .contains("https://github.com/login/oauth/authorize?state=xyz")
        );
        assert!(
            req.params
                .requested_schema
                .properties
                .contains_key("authorize")
        );
        assert_eq!(
            req.params
                .requested_schema
                .required,
            vec!["authorize"]
        );
    }

    #[test]
    fn builder_omits_tool_when_none() {
        let req = build_oauth_consent_elicitation(json!(1), "Slack", None, &[], "https://slack/auth");
        assert!(
            !req.params
                .message
                .contains("`"),
            "no tool backticks when tool absent"
        );
    }

    #[test]
    fn schema_validation_rejects_non_object_root() {
        let mut s = RequestedSchema::new();
        s.schema_type = "string".to_string();
        let err = validate_requested_schema(&s).unwrap_err();
        assert!(matches!(err, SchemaViolation::TopLevelNotObject(_)));
    }

    #[test]
    fn schema_validation_rejects_required_missing_property() {
        let mut s = RequestedSchema::new();
        s.required = vec!["ghost".to_string()];
        let err = validate_requested_schema(&s).unwrap_err();
        assert_eq!(err, SchemaViolation::RequiredMissing("ghost".to_string()));
    }

    #[test]
    fn schema_validation_accepts_oauth_consent_builder_output() {
        let req = build_oauth_consent_elicitation(json!(1), "GitHub", None, &[], "https://x");
        assert!(validate_requested_schema(&req.params.requested_schema).is_ok());
    }

    #[test]
    fn round_trip_request_serialization_matches_spec_shape() {
        let req = build_oauth_consent_elicitation(json!(1), "GitHub", None, &[], "https://x");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "elicitation/create");
        assert_eq!(json["params"]["requestedSchema"]["type"], "object");
        assert!(json["params"]["requestedSchema"]["properties"]["authorize"].is_object());
        assert_eq!(json["params"]["requestedSchema"]["properties"]["authorize"]["type"], "boolean");
    }

    #[test]
    fn string_property_serializes_format_kebab_case() {
        let p = SchemaProperty::String(StringProperty {
            format: Some(StringFormat::DateTime),
            ..Default::default()
        });
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["format"], "date-time");
        assert_eq!(json["type"], "string");
    }

    #[test]
    fn parse_accept_response() {
        let env = json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": { "action": "accept", "content": { "authorize": true } }
        });
        let (id, result) = try_parse_elicitation_response(&env).unwrap();
        assert_eq!(id, "req-1");
        match result {
            ElicitationResult::Accept { content } => {
                assert_eq!(content["authorize"], true);
            }
            other => panic!("expected Accept, got {:?}", other),
        }
    }

    #[test]
    fn parse_decline_response() {
        let env = json!({"jsonrpc":"2.0","id":42,"result":{"action":"decline"}});
        let (id, result) = try_parse_elicitation_response(&env).unwrap();
        assert_eq!(id, "42");
        assert!(matches!(result, ElicitationResult::Decline));
    }

    #[test]
    fn parse_cancel_response() {
        let env = json!({"jsonrpc":"2.0","id":"x","result":{"action":"cancel"}});
        let (_id, result) = try_parse_elicitation_response(&env).unwrap();
        assert!(matches!(result, ElicitationResult::Cancel));
    }

    #[test]
    fn parse_rejects_non_response_envelopes() {
        // tools/call request from the client — not an elicitation response.
        let env = json!({"jsonrpc":"2.0","id":"x","method":"tools/call","params":{}});
        assert!(try_parse_elicitation_response(&env).is_none());
        // No id at all → can't correlate.
        let env = json!({"jsonrpc":"2.0","result":{"action":"accept"}});
        assert!(try_parse_elicitation_response(&env).is_none());
    }

    #[test]
    fn client_capabilities_detect_elicitation_flag() {
        let params = json!({ "capabilities": { "elicitation": {} } });
        assert!(client_supports_elicitation(&params));
        let caps = McpClientCapabilities::from_initialize_params(&params);
        assert!(caps.elicitation);
        assert!(!caps.sampling);
        assert!(!caps.roots);
    }

    #[test]
    fn client_capabilities_missing_elicitation() {
        let params = json!({ "capabilities": { "sampling": {} } });
        assert!(!client_supports_elicitation(&params));
        let caps = McpClientCapabilities::from_initialize_params(&params);
        assert!(!caps.elicitation);
        assert!(caps.sampling);
    }

    #[tokio::test]
    async fn global_registries_are_singletons() {
        // Both accessors must return the same Arc instance on repeated calls,
        // otherwise the proxy handler and credential delegation pipeline would
        // be talking to different maps.
        let a = global_capability_registry().clone();
        let b = global_capability_registry().clone();
        assert!(Arc::ptr_eq(&a, &b));
        let p1 = global_pending_elicitation_registry().clone();
        let p2 = global_pending_elicitation_registry().clone();
        assert!(Arc::ptr_eq(&p1, &p2));

        // Round-trip a capability record through the global registry.
        a.record(
            "global-sess-1",
            McpClientCapabilities {
                elicitation: true,
                sampling: false,
                roots: false,
            },
        )
        .await;
        let got = b
            .get("global-sess-1")
            .await
            .expect("recorded");
        assert!(got.elicitation);
    }

    #[tokio::test]
    async fn pending_registry_resolves_waiter() {
        let reg = PendingElicitationRegistry::new();
        let (id, rx) = reg.register("sess-1").await;
        let resolved = reg
            .resolve(
                "sess-1",
                &id,
                ElicitationResult::Accept {
                    content: json!({"authorize": true}),
                },
            )
            .await;
        assert!(resolved);
        let result = rx.await.unwrap();
        assert!(matches!(result, ElicitationResult::Accept { .. }));
    }

    #[tokio::test]
    async fn pending_registry_unknown_id_returns_false() {
        let reg = PendingElicitationRegistry::new();
        let resolved = reg
            .resolve("sess-1", "nope", ElicitationResult::Decline)
            .await;
        assert!(!resolved);
    }

    #[tokio::test]
    async fn pending_registry_drop_session_closes_waiters() {
        let reg = PendingElicitationRegistry::new();
        let (_id, rx) = reg.register("sess-1").await;
        reg.drop_session("sess-1")
            .await;
        // The sender was dropped; receiver should observe a closed channel.
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn capability_registry_round_trip() {
        let reg = McpCapabilityRegistry::new();
        let caps = McpClientCapabilities {
            elicitation: true,
            sampling: false,
            roots: true,
        };
        reg.record("s1", caps.clone())
            .await;
        let got = reg.get("s1").await.unwrap();
        assert!(got.elicitation);
        assert!(!got.sampling);
        assert!(got.roots);
        reg.drop_session("s1").await;
        assert!(reg.get("s1").await.is_none());
    }
}
