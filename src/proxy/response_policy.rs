//! Response Policy Evaluation
//!
//! Evaluates OPA policies against upstream responses before returning them to callers.
//! This runs after the target responds but before the Gateway forwards the response back.
//!
//! The response policy can:
//! - Block responses containing sensitive data
//! - Redact fields based on caller role
//! - Enforce output contracts (required fields, forbidden patterns)

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Input document passed to the response OPA policy.
/// The Rego policy sees this as `input.*`.
#[derive(Debug, Clone, Serialize)]
pub struct ResponsePolicyInput {
    /// The upstream response body (JSON).
    pub response: ResponseContext,
    /// Caller context (who made the original request).
    pub caller: CallerContext,
    /// Channel/surface context.
    pub surface: SurfaceContext,
    /// Optional metadata carried forward from the request pipeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, Value>>,
}

/// Response body context visible to the policy.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseContext {
    /// HTTP status code from upstream.
    pub status_code: u16,
    /// The response body as JSON (if parseable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    /// Content-Type header from the upstream response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Whether the response is a JSON-RPC error.
    #[serde(default)]
    pub is_error: bool,
    /// JSON-RPC method (if this is an RPC response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// Caller identity context forwarded from the inbound pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct CallerContext {
    /// Caller DID (if resolved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Identity source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_source: Option<String>,
    /// DNA UAI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dna_uai: Option<String>,
}

/// Surface/channel routing context.
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceContext {
    /// Surface ID or channel config_id.
    pub id: String,
    /// Surface/channel name.
    pub name: String,
    /// Protocol (a2a, mcp, ap2).
    pub protocol: String,
}

/// Result of a response policy evaluation.
#[derive(Debug, Clone)]
pub struct ResponsePolicyDecision {
    /// Whether the response is allowed through.
    pub allow: bool,
    /// Reason for denial (if denied).
    pub reason: Option<String>,
}

/// Evaluate a response policy using the policy manager.
///
/// Returns `Ok(decision)` indicating allow/deny.
/// If no policy is configured or the engine is not found, allows by default.
pub fn evaluate_response_policy(
    policy_manager: &crate::policies::surface_manager::SurfacePolicyManager,
    policy_key: &str,
    input: ResponsePolicyInput,
) -> ResponsePolicyDecision {
    let input_value = match serde_json::to_value(&input) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                policy_key = %policy_key,
                error = %e,
                "Failed to serialize response policy input, allowing response"
            );
            return ResponsePolicyDecision { allow: true, reason: None };
        }
    };

    match policy_manager.evaluate_policy_decision(policy_key, input_value) {
        Ok(decision) => {
            if !decision.allow {
                debug!(policy_key = %policy_key, "Response policy denied");
            }
            ResponsePolicyDecision {
                allow: decision.allow,
                reason: if decision.allow {
                    None
                } else {
                    decision
                        .reason
                        .or_else(|| Some("Response blocked by policy".to_string()))
                },
            }
        }
        Err(e) => {
            warn!(
                policy_key = %policy_key,
                error = %e,
                "Response policy evaluation failed, denying response (fail-closed)"
            );
            ResponsePolicyDecision {
                allow: false,
                reason: Some(format!("Policy evaluation error: {}", e)),
            }
        }
    }
}

/// Build the policy engine key for a response policy.
/// Convention: "response:{surface_id}" or "response:{config_id}".
#[allow(dead_code)]
pub fn response_policy_key(surface_or_channel_id: &str) -> String {
    format!("response:{}", surface_or_channel_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_policy_input_serializes() {
        let input = ResponsePolicyInput {
            response: ResponseContext {
                status_code: 200,
                body: Some(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"tools": [{"name": "search"}]}
                })),
                content_type: Some("application/json".to_string()),
                is_error: false,
                method: Some("tools/list".to_string()),
            },
            caller: CallerContext {
                did: Some("did:example:caller".to_string()),
                identity_source: Some("gateway_computed".to_string()),
                dna_uai: None,
            },
            surface: SurfaceContext {
                id: "surf-001".to_string(),
                name: "research-agent".to_string(),
                protocol: "mcp".to_string(),
            },
            metadata: None,
        };

        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["response"]["status_code"], 200);
        assert_eq!(json["caller"]["did"], "did:example:caller");
        assert_eq!(json["surface"]["protocol"], "mcp");
    }

    #[test]
    fn test_response_policy_key() {
        assert_eq!(response_policy_key("surf-001"), "response:surf-001");
        assert_eq!(response_policy_key("abc-123-def"), "response:abc-123-def");
    }
}
