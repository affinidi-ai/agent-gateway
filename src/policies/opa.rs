use regorus::Engine;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use tracing::{debug, error, info};

/// OPA policy engine for evaluating Rego policies.
///
/// ## Performance
///
/// The policy is compiled once via `load_policy()` and stored as a template engine.
/// On each evaluation, the template is **cloned** (cheap with regorus `arc` feature —
/// internal data uses `Arc`) and evaluated on the owned clone. This eliminates all
/// lock contention: concurrent requests evaluate in parallel with zero synchronization.
///
/// Uses `eval_bool_query()` (via `eval_surface_decision`, which queries the single
/// `data.surface.policy.allow` base) and `set_input_json()` (avoids intermediate
/// `serde_json::Value` allocation). Surface policies always declare
/// `package surface.policy`; a legacy `channel.policy` definition is rewritten to
/// the canonical package by the policy store's startup migration pass (see
/// [`super::policy_definitions::FileSystemPolicyDefinitionStore::migrate_legacy_packages`]),
/// so the engine only ever compiles the canonical package.
pub struct OpaEngine {
    engine: RwLock<Engine>,
}

/// Policy evaluation decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the request is allowed
    pub allow: bool,

    /// Reason for the decision (if denied)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Query base for agent-surface policies: `data.surface.policy`. A legacy
/// `package channel.policy` definition is rewritten to `surface.policy` by the
/// policy store's startup migration pass (see
/// [`super::policy_definitions::FileSystemPolicyDefinitionStore::migrate_legacy_packages`]),
/// so the engine only ever declares the canonical package and a single query root
/// suffices — there is no `data.channel.policy` fallback.
const SURFACE_POLICY_BASE: &str = "data.surface.policy";

fn eval_surface_decision(engine: &mut Engine) -> Result<PolicyDecision, String> {
    match engine.eval_bool_query(format!("{SURFACE_POLICY_BASE}.allow"), false) {
        Ok(allow) => {
            let reason = if allow {
                None
            } else {
                engine
                    .eval_rule(format!("{SURFACE_POLICY_BASE}.deny_reason"))
                    .ok()
                    .and_then(|v| {
                        v.as_string()
                            .ok()
                            .map(|s| s.to_string())
                    })
            };
            Ok(PolicyDecision { allow, reason })
        }
        // Undefined `allow` (the query produced no value): the module does not
        // declare `package surface.policy`, or omits a `default allow`. That is a
        // policy misconfiguration, not a system error: fail closed with an
        // actionable reason. Keyed on the Regorus "no value" marker (see
        // `super::REGORUS_QUERY_NO_VALUE_MARKER` for the version-coupling note).
        Err(e)
            if e.to_string()
                .contains(super::REGORUS_QUERY_NO_VALUE_MARKER) =>
        {
            Ok(PolicyDecision {
                allow: false,
                reason: Some(
                    "Surface policy produced no `allow` decision; it must declare `package surface.policy` and define `allow` (e.g. `default allow = false`)"
                        .to_string(),
                ),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

impl OpaEngine {
    /// Create a new OPA engine
    pub fn new() -> Self {
        Self {
            engine: RwLock::new(Engine::new()),
        }
    }

    /// Load a Rego policy from a string.
    /// The policy is compiled and stored as a template for fast clone-per-eval.
    ///
    /// Surface policies are expected to declare the canonical `package
    /// surface.policy`. The legacy `channel.policy` rename is applied once by the
    /// policy store's startup migration pass
    /// ([`super::policy_definitions::FileSystemPolicyDefinitionStore::migrate_legacy_packages`]),
    /// so every stored policy this compiles already carries the canonical package.
    pub fn load_policy(
        &self,
        policy_name: &str,
        policy_content: &str,
    ) -> Result<(), String> {
        let mut engine = self
            .engine
            .write()
            .expect("OpaEngine lock poisoned");

        // Clear previous policies
        *engine = Engine::new();

        // Add the policy (compiles it)
        engine
            .add_policy(policy_name.to_string(), policy_content.to_string())
            .map_err(|e| format!("Policy failed to compile: {}", e.to_string().trim_start()))?;

        info!("Loaded OPA policy: {}", policy_name);
        Ok(())
    }

    /// Clone the internal engine template for evaluation.
    /// The read lock is held only long enough to clone (cheap Arc bump).
    fn clone_engine(&self) -> Engine {
        self.engine
            .read()
            .expect("OpaEngine lock poisoned")
            .clone()
    }

    /// Evaluate an agent-surface policy against input data.
    /// Clones the template and evaluates on the clone — fully concurrent, no lock held.
    ///
    /// Policies declare `package surface.policy` (evaluated at
    /// `data.surface.policy.allow`); a legacy `package channel.policy` is migrated
    /// to the canonical package on load, so no runtime fallback is needed.
    pub fn evaluate(
        &self,
        input: serde_json::Value,
    ) -> Result<PolicyDecision, String> {
        let input_json = serde_json::to_string(&input).map_err(|e| format!("Failed to serialize input: {}", e))?;
        self.evaluate_prepared(&input_json)
    }

    /// Evaluate against an already-serialized input JSON string.
    ///
    /// Lets a caller that evaluates the same input against several engines
    /// (e.g. MCP tool gating conditions) serialize the input **once** and reuse
    /// the string, avoiding a per-engine `serde_json::to_string`.
    pub fn evaluate_prepared(
        &self,
        input_json: &str,
    ) -> Result<PolicyDecision, String> {
        let mut engine = self.clone_engine();

        engine
            .set_input_json(input_json)
            .map_err(|e| format!("Failed to set input: {}", e))?;

        match eval_surface_decision(&mut engine) {
            Ok(mut decision) => {
                if !decision.allow && decision.reason.is_none() {
                    decision.reason = Some("Policy denied request".to_string());
                }
                Ok(decision)
            }
            Err(e) => Err(format!("Failed to evaluate query '{SURFACE_POLICY_BASE}.allow': {e}")),
        }
    }

    /// Evaluate and filter MCP tools based on policy.
    /// Each tool is evaluated on an independent engine clone — no serialization.
    ///
    /// `input_template` carries the request-level `PolicyInput` (http, surface,
    /// source_auth, agent, extension_identity, payment, identity_binding) so
    /// per-tool evaluation sees the same context as the general surface OPA
    /// gate. The function clones the template for each tool and overrides only
    /// `input.mcp` with the per-tool method/name.
    pub fn filter_mcp_tools(
        &self,
        tools: Vec<String>,
        input_template: &crate::surface_context::PolicyInput,
    ) -> Vec<String> {
        let mut allowed_tools = Vec::new();

        for tool_name in tools {
            let mut input = input_template.clone();
            let modern_context = input
                .mcp
                .take()
                .filter(|context| {
                    context
                        .protocol_version
                        .is_some()
                })
                .unwrap_or_default();
            input.mcp = Some(crate::surface_context::McpContext {
                method: "tools/list".to_string(),
                tool_name: Some(tool_name.clone()),
                ..modern_context
            });
            let input_value = serde_json::to_value(&input).unwrap_or_default();

            match self.evaluate(input_value) {
                Ok(decision) if decision.allow => {
                    allowed_tools.push(tool_name);
                }
                Ok(_) => {
                    debug!("Tool {} filtered out by policy", tool_name);
                }
                Err(e) => {
                    error!("Failed to evaluate policy for tool {}: {}", tool_name, e);
                    // On error, deny access to be safe
                }
            }
        }

        allowed_tools
    }

    /// Evaluate MCP tool-level policy.
    /// Clones the template and evaluates on the clone. Also extracts `deny_reason` if present.
    pub fn evaluate_mcp_tool_policy(
        &self,
        context: &crate::mcp::McpPolicyContext,
    ) -> Result<PolicyDecision, String> {
        let mut engine = self.clone_engine();

        let input_json =
            serde_json::to_string(context).map_err(|e| format!("Failed to serialize MCP context: {}", e))?;

        debug!("Evaluating MCP tool policy with context: {}", input_json);

        engine
            .set_input_json(&input_json)
            .map_err(|e| format!("Failed to set MCP input: {}", e))?;

        let decision = eval_surface_decision(&mut engine)
            .map_err(|e| format!("Failed to evaluate query '{SURFACE_POLICY_BASE}.allow': {e}"))?;

        Ok(PolicyDecision {
            allow: decision.allow,
            reason: decision.reason.or_else(|| {
                if !decision.allow {
                    Some("Access denied by MCP tool policy".to_string())
                } else {
                    None
                }
            }),
        })
    }
}

impl Default for OpaEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opa_basic_allow() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "echo"
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(decision.allow);
    }

    #[test]
    fn test_opa_basic_deny() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "restricted"
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason.as_deref(), Some("Policy denied request"));
    }

    #[test]
    fn test_opa_deny_reason_from_policy() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}

deny_reason = sprintf("Tool '%s' is not permitted", [input.mcp.tool_name]) if {
    not allow
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "restricted"
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason.as_deref(), Some("Tool 'restricted' is not permitted"));
    }

    #[test]
    fn mcp_tool_policy_accepts_surface_package() {
        let engine = OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.jwt.role == "admin"
}

deny_reason = "surface tool deny" if {
    not allow
}
"#;
        engine
            .load_policy("test", policy)
            .unwrap();

        let mut jwt_claims = std::collections::HashMap::new();
        jwt_claims.insert("role".to_string(), serde_json::json!("user"));
        let context = crate::mcp::McpPolicyContext::new(
            "tools/call".to_string(),
            None,
            Some(jwt_claims),
            "test-channel".to_string(),
            None,
            "mcp".to_string(),
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/".to_string(),
        );
        let decision = engine
            .evaluate_mcp_tool_policy(&context)
            .unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason.as_deref(), Some("surface tool deny"));
    }

    #[test]
    fn mcp_tool_policy_propagates_real_evaluator_errors() {
        let engine = OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow := input.jwt.role
"#;
        engine
            .load_policy("test", policy)
            .unwrap();

        let mut jwt_claims = std::collections::HashMap::new();
        jwt_claims.insert("role".to_string(), serde_json::json!("admin"));
        let context = crate::mcp::McpPolicyContext::new(
            "tools/call".to_string(),
            None,
            Some(jwt_claims),
            "test-channel".to_string(),
            None,
            "mcp".to_string(),
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/".to_string(),
        );

        let err = engine
            .evaluate_mcp_tool_policy(&context)
            .expect_err("real evaluator errors must propagate to the caller");
        assert!(err.contains("Failed to evaluate query 'data.surface.policy.allow'"), "unexpected error: {err}");
    }

    #[test]
    fn load_policy_does_not_migrate_channel_package() {
        // The `channel.policy` → `surface.policy` rename is a storage-layer
        // concern: the policy store's startup migration pass re-saves any legacy
        // definition (see `FileSystemPolicyDefinitionStore::migrate_legacy_packages`).
        // `load_policy` itself does NOT migrate, so a `channel.policy` module
        // compiled directly declares no `data.surface.policy` rules and therefore
        // fails closed (deny) — the same as any other unknown package. Production
        // never reaches this path because every stored definition is already
        // migrated before it is loaded.
        let engine = OpaEngine::new();
        let policy = r#"
package channel.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}
"#;
        engine
            .load_policy("legacy", policy)
            .unwrap();

        let decision = engine
            .evaluate(serde_json::json!({ "mcp": { "tool_name": "echo" } }))
            .expect("an unmigrated channel.policy must be a clean deny, not an Err");
        assert!(!decision.allow, "load_policy must not migrate — an unmigrated channel.policy denies");
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("surface.policy")),
            "deny reason must point at the surface.policy requirement, got: {:?}",
            decision.reason
        );
    }

    #[test]
    fn unknown_package_policy_is_denied_not_ignored() {
        // A policy that declares neither `surface.policy` nor a legacy
        // `channel.policy` (which the policy store's startup pass migrates)
        // produces no value at the `data.surface.policy.allow` base, so it must
        // fail closed (deny) with an actionable reason — never be silently allowed.
        let engine = OpaEngine::new();
        let policy = r#"
package authz.custom

default allow = true

allow := true
"#;
        engine
            .load_policy("unknown", policy)
            .unwrap();

        let decision = engine
            .evaluate(serde_json::json!({}))
            .expect("an unknown package must be a clean deny, not an Err");
        assert!(!decision.allow, "an unknown-package policy must deny, never be silently allowed");
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("surface.policy")),
            "deny reason must point the operator at the surface.policy requirement, got: {:?}",
            decision.reason
        );
    }

    #[test]
    fn defaultless_surface_policy_denies_when_allow_is_undefined() {
        // A valid `surface.policy` that omits `default allow` and relies on
        // "undefined == deny": when the conditional `allow` matches, it allows;
        // when it does not, the canonical base produces no value and the runtime
        // falls through to a fail-closed deny (never a silent allow, never an
        // opaque engine error).
        let engine = OpaEngine::new();
        let policy = r#"
package surface.policy

allow if {
    input.mcp.tool_name == "echo"
}
"#;
        engine
            .load_policy("defaultless", policy)
            .unwrap();

        let allowed = engine
            .evaluate(serde_json::json!({ "mcp": { "tool_name": "echo" } }))
            .expect("matching conditional allow must evaluate");
        assert!(allowed.allow, "conditional allow must allow when the condition matches");

        let denied = engine
            .evaluate(serde_json::json!({ "mcp": { "tool_name": "restricted" } }))
            .expect("undefined allow must be a clean deny, not an Err");
        assert!(!denied.allow, "a defaultless surface policy must deny when `allow` is undefined");
        assert!(
            denied
                .reason
                .as_deref()
                .is_some_and(|r| !r.is_empty()),
            "a deny must carry a non-empty reason, got: {:?}",
            denied.reason
        );
    }

    #[test]
    fn regorus_no_value_marker_matches_live_error() {
        // Canary for the Regorus-version coupling documented on
        // `crate::policies::REGORUS_QUERY_NO_VALUE_MARKER`. Query a rule the
        // loaded module does not declare and assert the raw Regorus error still
        // contains the marker the fail-closed branches key on. If a Regorus
        // upgrade rewords this error, THIS test fails first and points straight
        // at the constant — update the marker to match the new wording.
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("canary".to_string(), "package surface.policy\n\ndefault allow = false\n".to_string())
            .unwrap();
        engine
            .set_input_json("{}")
            .unwrap();

        let err = engine
            .eval_bool_query("data.gateway.policy.allow".to_string(), false)
            .expect_err("querying an undeclared package must error");
        assert!(
            err.to_string()
                .contains(crate::policies::REGORUS_QUERY_NO_VALUE_MARKER),
            "Regorus 'no value' wording changed — update REGORUS_QUERY_NO_VALUE_MARKER. Got: {err}"
        );
    }

    #[test]
    fn test_opa_mcp_tool_policy_deny_reason() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.jwt.role == "admin"
}

deny_reason = "Only admin users can access MCP tools" if {
    not allow
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let mut jwt_claims = std::collections::HashMap::new();
        jwt_claims.insert("role".to_string(), serde_json::json!("user"));
        let context = crate::mcp::McpPolicyContext::new(
            "tools/call".to_string(),
            None,
            Some(jwt_claims),
            "test-channel".to_string(),
            None,
            "mcp".to_string(),
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/".to_string(),
        );

        let decision = engine
            .evaluate_mcp_tool_policy(&context)
            .unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason.as_deref(), Some("Only admin users can access MCP tools"));
    }

    #[test]
    fn test_opa_source_auth_claims() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.source_auth.method == "jwt_bearer"
    input.source_auth.claims.role == "admin"
    input.mcp.method == "tools/call"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "restricted_tool"
            },
            "source_auth": {
                "method": "jwt_bearer",
                "subject": "admin-user",
                "claims": { "role": "admin" }
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(decision.allow);
    }

    #[test]
    fn test_opa_source_auth_deny_wrong_role() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.source_auth.method == "jwt_bearer"
    input.source_auth.claims.role == "admin"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "source_auth": {
                "method": "jwt_bearer",
                "subject": "user-1",
                "claims": { "role": "viewer" }
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(!decision.allow);
    }

    #[test]
    fn test_filter_tools() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}

allow if {
    input.mcp.tool_name == "add"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let tools = vec!["echo".to_string(), "add".to_string(), "restricted".to_string()];

        let allowed = engine.filter_mcp_tools(tools, &Default::default());
        assert_eq!(allowed, vec!["echo", "add"]);
    }

    #[test]
    fn filter_mcp_tools_propagates_template_fields_to_per_tool_eval() {
        // Regression guard for the audit P3 #17 bug: filter_mcp_tools used to
        // build PolicyInput with only `input.mcp` populated, so policies
        // checking source_auth / extension_identity / agent / payment /
        // identity_binding silently filtered every tool. The template now
        // carries the full inbound context.
        let engine = OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

# Allows ONLY when both the template-carried source_auth AND the per-tool mcp
# context are present — proves both halves of the merged input reach Rego.
allow if {
    input.source_auth.method == "api_key"
    input.extension_identity.did == "did:webvh:test"
    input.mcp.tool_name == "echo"
}
"#;
        engine
            .load_policy("regress", policy)
            .unwrap();

        let template = crate::surface_context::PolicyInput {
            source_auth: Some(crate::surface_context::SourceAuthContext::ApiKey {
                key_name: "key-123".to_string(),
            }),
            extension_identity: Some(crate::surface_context::ExtensionIdentityContext {
                verification: crate::surface_context::IdentityVerification::Unverified,
                did: Some("did:webvh:test".to_string()),
                identity_hash: None,
            }),
            ..Default::default()
        };

        let tools = vec!["echo".to_string(), "blocked".to_string()];
        let allowed = engine.filter_mcp_tools(tools, &template);
        assert_eq!(allowed, vec!["echo"]);
    }

    #[test]
    fn filter_mcp_tools_denies_when_template_lacks_required_field() {
        let engine = OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.source_auth.method == "api_key"
    input.mcp.tool_name == "echo"
}
"#;
        engine
            .load_policy("regress2", policy)
            .unwrap();

        let tools = vec!["echo".to_string()];
        let allowed = engine.filter_mcp_tools(tools, &Default::default());
        assert!(allowed.is_empty(), "policy must deny when source_auth is missing from the template");
    }

    #[test]
    fn filter_mcp_tools_overrides_template_mcp_per_tool() {
        // The template's own `input.mcp` (if any) must be replaced per tool;
        // the per-tool override is what carries the tool_name.
        let engine = OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.mcp == {"method": "tools/list", "tool_name": "echo"}
}
"#;
        engine
            .load_policy("regress3", policy)
            .unwrap();

        let template = crate::surface_context::PolicyInput {
            mcp: Some(crate::surface_context::McpContext {
                method: "tools/call".to_string(),
                tool_name: Some("would-be-stale".to_string()),
                resource_uri: None,
                prompt_name: None,
                params: Some(serde_json::json!({"cursor": "legacy"})),
                ..Default::default()
            }),
            ..Default::default()
        };

        let tools = vec!["echo".to_string()];
        let allowed = engine.filter_mcp_tools(tools, &template);
        assert_eq!(allowed, vec!["echo"], "per-tool override must replace the template's stale mcp.tool_name");
    }

    #[test]
    fn filter_mcp_tools_retains_modern_declarations_without_granting_identity() {
        let engine = OpaEngine::new();
        engine
            .load_policy(
                "modern-context",
                r#"
package surface.policy
default allow = false
allow if {
    input.source_auth.method == "api_key"
    input.mcp.protocol_version == "2026-07-28"
    input.mcp.client_capabilities.extensions["com.example/tools"].enabled == true
    input.mcp.params.cursor == "page-2"
    input.mcp.method == "tools/list"
    input.mcp.tool_name == "echo"
}
"#,
            )
            .unwrap();
        let mut template = crate::surface_context::PolicyInput {
            mcp: Some(crate::surface_context::McpContext {
                method: "tools/list".to_string(),
                params: Some(serde_json::json!({"cursor": "page-2"})),
                protocol_version: Some(crate::mcp::MCP_MODERN_VERSION.to_string()),
                client_capabilities: Some(serde_json::json!({"extensions": {"com.example/tools": {"enabled": true}}})),
                client_info: Some(serde_json::json!({"name": "untrusted", "version": "1"})),
                ..Default::default()
            }),
            ..Default::default()
        };
        let tools = vec!["blocked".to_string(), "echo".to_string()];
        assert!(
            engine
                .filter_mcp_tools(tools.clone(), &template)
                .is_empty()
        );

        template.source_auth = Some(crate::surface_context::SourceAuthContext::ApiKey {
            key_name: "verified-key".to_string(),
        });
        assert_eq!(engine.filter_mcp_tools(tools.clone(), &template), vec!["echo"]);
        assert_eq!(
            template
                .mcp
                .as_ref()
                .unwrap()
                .tool_name,
            None
        );
        template
            .mcp
            .as_mut()
            .unwrap()
            .client_capabilities = Some(serde_json::json!({}));
        assert!(
            engine
                .filter_mcp_tools(tools, &template)
                .is_empty()
        );
    }
}
