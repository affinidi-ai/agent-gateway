//! Managed identity fixture shared by the surface and G2G config writers: the
//! payload schema a managed agent's `agent-identity/v1` metadata must satisfy
//! and the surface-level `target.identity_injection` rule that derives the
//! agent's DID from it.

use serde_json::Value;

/// Identity payload schema matching `json_rpc::build_mcp_agent_identity_payload`.
pub fn default_identity_payload_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "softwareInfo": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "x-identity": true },
                    "version": { "type": "string", "x-identity": true }
                }
            },
            "cloudProvider": { "type": "string", "x-identity": true }
        }
    })
}

/// Surface-level managed identity derived from the `agentIdentity` payload,
/// with VP injection on. Transit Points inherit it as the managed agent's
/// outbound identity when their own `identity_injection.inject_vp` is on.
pub fn target_identity_injection_json(identity_payload_schema: &Value) -> Value {
    serde_json::json!({
        "inject_vp": true,
        "type": "from_payload",
        "meta_field": "agentIdentity",
        "fields": ["agentIdentity.softwareInfo.name", "agentIdentity.softwareInfo.version", "agentIdentity.cloudProvider"],
        "json_schema": identity_payload_schema,
    })
}
