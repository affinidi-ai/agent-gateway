//! Compiled, cached representation of a surface's MCP Tool Gating config.
//!
//! [`crate::config::agent_surface::McpToolGatingConfig`] is the operator-facing
//! shape. At surface-load time it is compiled once into a
//! [`CompiledMcpToolGating`]: each gate's regex patterns become a
//! [`RegexSet`] and each gate's optional condition policy becomes a
//! pre-loaded [`OpaEngine`] (gates sharing a condition policy id share one
//! compiled engine). The compiled form is cached per surface/variant by
//! [`super::surface_manager::SurfacePolicyManager`], so a request pays only for
//! one OPA evaluation per **distinct** active condition policy (never per tool),
//! with the request input serialized **once** and reused across engines, plus
//! O(1) regex-set matches per tool. Gating with no OPA condition
//! ([`CompiledMcpToolGating::has_policy_conditions`] is `false`) evaluates with
//! no input at all, so the caller can skip building the `PolicyInput`.
//!
//! ## Firewall semantics
//!
//! A gate is **active** when its condition is met (no condition ⇒ always
//! active; an unevaluable condition fails **closed** ⇒ active). Given the set
//! of active gates, a tool is allowed iff:
//!
//! - no active `Deny` gate matches it, **and**
//! - either at least one active `Allow` gate matches it (the union of
//!   allow-matches is the allow-list), or — when no active `Allow` gate
//!   matches — the config's `default_effect` is `allow`.
//!
//! `default_effect` (default `allow`) is the baseline for a tool that matches
//! no active gate: `allow` = allow-by-default (gates are deny carve-outs),
//! `deny` = deny-by-default (gates are the allow-list). `Deny` always
//! overrides `Allow`.

use std::collections::HashMap;
use std::sync::Arc;

use regex::RegexSet;
use serde_json::Value;
use tracing::warn;

use crate::config::agent_surface::{McpToolGateEffect, McpToolGatingConfig};

use super::OpaEngine;

/// How a compiled gate decides whether it is active for a given request.
enum GateCondition {
    /// No condition policy was configured — the gate is always active.
    AlwaysActive,
    /// A compiled OPA condition. An `allow` result activates the gate.
    Policy(Arc<OpaEngine>),
    /// A condition policy id was configured but could not be resolved or
    /// compiled at build time. Fails closed **toward denial** at runtime: a
    /// `Deny` gate stays active, an `Allow` gate is forced inactive (never
    /// grants on an unknowable condition).
    Unresolved,
}

/// One compiled gate: a matcher plus an activeness condition and an effect.
struct CompiledGate {
    /// Gate id (for diagnostics).
    id: String,
    effect: McpToolGateEffect,
    condition: GateCondition,
    /// Pre-compiled union of the gate's (non-empty) regex patterns.
    matcher: RegexSet,
}

/// Compiled, ready-to-evaluate MCP Tool Gating for one surface (or variant).
pub struct CompiledMcpToolGating {
    gates: Vec<CompiledGate>,
    /// Baseline verdict for a tool matching no active gate.
    default_effect: McpToolGateEffect,
}

fn empty_regex_set() -> RegexSet {
    RegexSet::empty()
}

impl CompiledMcpToolGating {
    /// An empty gating with no gates. Used as a variant "tombstone" so a
    /// variant that clears its parent's gating does not inherit it at lookup.
    pub fn empty() -> Self {
        Self {
            gates: Vec::new(),
            default_effect: McpToolGateEffect::Allow,
        }
    }

    /// Returns `true` when the gating is a no-op: no gates AND an `allow`
    /// default (allow-everything). A `deny` default with no gates still
    /// denies every tool, so it is NOT empty.
    pub fn is_empty(&self) -> bool {
        self.gates.is_empty() && matches!(self.default_effect, McpToolGateEffect::Allow)
    }

    /// Compile a [`McpToolGatingConfig`] into its cached runtime form.
    ///
    /// `resolve_policy` maps a condition policy id to its Rego text, returning
    /// `None` when the definition is missing, empty, or disabled. Regex sets
    /// are compiled here once; a pattern that fails to compile is dropped (the
    /// config-write validation surfaces such errors to operators, so this path
    /// is best-effort and never panics).
    pub fn build(
        config: &McpToolGatingConfig,
        resolve_policy: impl Fn(&str) -> Option<String>,
    ) -> Self {
        let mut gates = Vec::with_capacity(config.gates.len());
        // Share one compiled engine across gates that reference the same
        // condition policy id, so a policy is compiled once, not per gate.
        let mut engine_cache: HashMap<String, Arc<OpaEngine>> = HashMap::new();
        for gate in &config.gates {
            let effective: Vec<&str> = gate
                .action
                .patterns
                .iter()
                .map(|p| p.trim())
                .filter(|p| !p.is_empty())
                .collect();

            let matcher = RegexSet::new(effective.iter().copied()).unwrap_or_else(|_| {
                // One bad pattern must not disable the whole gate: keep only
                // the patterns that individually compile.
                let good: Vec<&str> = effective
                    .iter()
                    .copied()
                    .filter(|p| regex::Regex::new(p).is_ok())
                    .collect();
                RegexSet::new(good.iter().copied()).unwrap_or_else(|_| empty_regex_set())
            });

            let condition = match gate
                .condition_policy_definition_id
                .as_deref()
            {
                None => GateCondition::AlwaysActive,
                Some(policy_id) => {
                    if let Some(shared) = engine_cache.get(policy_id) {
                        GateCondition::Policy(shared.clone())
                    } else {
                        match resolve_policy(policy_id) {
                            Some(text) if !text.is_empty() => {
                                let engine = OpaEngine::new();
                                match engine.load_policy(policy_id, &text) {
                                    Ok(()) => {
                                        let arc = Arc::new(engine);
                                        engine_cache.insert(policy_id.to_string(), arc.clone());
                                        GateCondition::Policy(arc)
                                    }
                                    Err(e) => {
                                        warn!(
                                            gate = %gate.id,
                                            policy_id = %policy_id,
                                            error = %e,
                                            "MCP tool gate condition policy failed to compile; failing closed (deny gate stays active, allow gate forced inactive)"
                                        );
                                        GateCondition::Unresolved
                                    }
                                }
                            }
                            _ => {
                                warn!(
                                    gate = %gate.id,
                                    policy_id = %policy_id,
                                    "MCP tool gate condition policy missing, empty, or disabled; failing closed (deny gate stays active, allow gate forced inactive)"
                                );
                                GateCondition::Unresolved
                            }
                        }
                    }
                }
            };

            gates.push(CompiledGate {
                id: gate.id.clone(),
                effect: gate.action.effect,
                condition,
                matcher,
            });
        }
        Self {
            gates,
            default_effect: config.default_effect,
        }
    }

    /// `true` when at least one gate carries an OPA *condition* policy. When
    /// `false`, activeness needs no request input at all (every gate is an
    /// unconditional or fail-closed filter), so the caller can skip building
    /// and serializing the `PolicyInput` entirely.
    pub fn has_policy_conditions(&self) -> bool {
        self.gates
            .iter()
            .any(|g| matches!(g.condition, GateCondition::Policy(_)))
    }

    /// Evaluate every gate's activeness once for this request. Fail-closed
    /// **toward denial**: a condition that cannot be resolved (build time) or
    /// evaluated (runtime error) keeps a `Deny` gate active (keep hiding) but
    /// forces an `Allow` gate inactive (never grant access on an unknowable
    /// condition). A resolved condition activates the gate iff it returns
    /// `allow`, regardless of the gate's effect.
    ///
    /// The input is serialized **once** (lazily — pure-regex gating never
    /// serializes) and reused across engines, and gates that share a condition
    /// policy (same compiled engine) are evaluated **once**, keyed by engine
    /// identity.
    fn active_flags(
        &self,
        input: &Value,
    ) -> Vec<bool> {
        let mut input_json: Option<String> = None;
        // Memoize the condition OUTCOME per engine: `Some(allow)` when the
        // policy evaluated, `None` when it errored. Kept separate from the
        // final activeness because an errored condition fails closed in an
        // effect-dependent way, so two gates sharing one engine can resolve to
        // different activeness.
        let mut memo: HashMap<*const OpaEngine, Option<bool>> = HashMap::new();
        self.gates
            .iter()
            .map(|gate| match &gate.condition {
                // Unconditional gate: its action always applies.
                GateCondition::AlwaysActive => true,
                // Build-time-unresolved condition: fail closed toward denial —
                // a Deny gate stays active (keep hiding), an Allow gate goes
                // inactive (do NOT grant on an unknowable condition).
                GateCondition::Unresolved => matches!(gate.effect, McpToolGateEffect::Deny),
                GateCondition::Policy(engine) => {
                    let key = Arc::as_ptr(engine);
                    let outcome = if let Some(&cached) = memo.get(&key) {
                        cached
                    } else {
                        let json = input_json
                            .get_or_insert_with(|| serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string()));
                        let outcome = match engine.evaluate_prepared(json) {
                            Ok(decision) => Some(decision.allow),
                            Err(e) => {
                                warn!(
                                    gate = %gate.id,
                                    error = %e,
                                    "MCP tool gate condition evaluation failed; failing closed"
                                );
                                None
                            }
                        };
                        memo.insert(key, outcome);
                        outcome
                    };
                    match outcome {
                        // Condition resolved: active iff it returned allow.
                        Some(allow) => allow,
                        // Condition errored: same effect-dependent fail-closed
                        // as an unresolved gate.
                        None => matches!(gate.effect, McpToolGateEffect::Deny),
                    }
                }
            })
            .collect()
    }

    /// Apply the firewall decision to a single tool using pre-computed active
    /// flags (parallel to `self.gates`).
    fn tool_allowed_with(
        &self,
        tool: &str,
        active: &[bool],
    ) -> bool {
        let mut matched_active_allow = false;
        for (idx, gate) in self.gates.iter().enumerate() {
            if !active
                .get(idx)
                .copied()
                .unwrap_or(false)
            {
                continue;
            }
            let hit = gate.matcher.is_match(tool);
            match gate.effect {
                // Deny overrides everything: a single active deny match hides the tool.
                McpToolGateEffect::Deny => {
                    if hit {
                        return false;
                    }
                }
                McpToolGateEffect::Allow => {
                    if hit {
                        matched_active_allow = true;
                    }
                }
            }
        }
        // No active deny matched. An explicit allow match survives; otherwise
        // the tool falls back to `default_effect`. An allow gate only *adds*
        // allowances over the default — it never restricts under an
        // allow-by-default baseline (that would contradict "allowed unless
        // denied"); allow-lists are expressed with a `deny` default.
        if matched_active_allow {
            true
        } else {
            matches!(self.default_effect, McpToolGateEffect::Allow)
        }
    }

    /// Filter a list of tool names, keeping only those the firewall allows.
    /// Gate conditions are evaluated exactly once regardless of tool count.
    pub fn filter_tools(
        &self,
        tools: Vec<String>,
        input: &Value,
    ) -> Vec<String> {
        if self.is_empty() {
            return tools;
        }
        let active = self.active_flags(input);
        tools
            .into_iter()
            .filter(|tool| self.tool_allowed_with(tool, &active))
            .collect()
    }

    /// Decide whether a single `tools/call` for `tool` is permitted.
    pub fn is_tool_call_allowed(
        &self,
        tool: &str,
        input: &Value,
    ) -> bool {
        if self.is_empty() {
            return true;
        }
        let active = self.active_flags(input);
        self.tool_allowed_with(tool, &active)
    }

    /// Filter a JSON-RPC `tools/list` response's `result.tools[]` array in
    /// place, dropping tools the firewall denies. Returns `(before, after)`
    /// counts, or `None` when the value carries no `result.tools` array.
    pub fn filter_tools_list_value(
        &self,
        json: &mut Value,
        input: &Value,
    ) -> Option<(usize, usize)> {
        let tools = json
            .get_mut("result")?
            .get_mut("tools")?
            .as_array_mut()?;
        let before = tools.len();
        let names: Vec<String> = tools
            .iter()
            .filter_map(|t| {
                t.get("name")
                    .and_then(|n| n.as_str())
                    .map(str::to_string)
            })
            .collect();
        let allowed = self.filter_tools(names, input);
        tools.retain(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .map(|n| allowed.contains(&n.to_string()))
                .unwrap_or(false)
        });
        let after = tools.len();
        Some((before, after))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{McpToolGate, McpToolGateAction};

    fn gate(
        id: &str,
        effect: McpToolGateEffect,
        patterns: &[&str],
        condition: Option<&str>,
    ) -> McpToolGate {
        McpToolGate {
            id: id.to_string(),
            name: String::new(),
            description: String::new(),
            condition_policy_definition_id: condition.map(str::to_string),
            action: McpToolGateAction {
                effect,
                patterns: patterns
                    .iter()
                    .map(|p| p.to_string())
                    .collect(),
            },
        }
    }

    // Rego policy body helpers.
    const ALLOW_POLICY: &str = "package surface.policy\ndefault allow = true\n";
    const DENY_POLICY: &str = "package surface.policy\ndefault allow = false\n";

    fn compile(config: &McpToolGatingConfig) -> CompiledMcpToolGating {
        CompiledMcpToolGating::build(config, |id| match id {
            "always-allow" => Some(ALLOW_POLICY.to_string()),
            "always-deny" => Some(DENY_POLICY.to_string()),
            _ => None,
        })
    }

    fn tools() -> Vec<String> {
        vec!["read_file".to_string(), "write_file".to_string(), "delete_file".to_string(), "admin_reset".to_string()]
    }

    #[test]
    fn no_gates_allows_everything() {
        let compiled = compile(&McpToolGatingConfig::default());
        assert!(compiled.is_empty());
        assert_eq!(compiled.filter_tools(tools(), &Value::Null), tools());
        assert!(compiled.is_tool_call_allowed("admin_reset", &Value::Null));
    }

    #[test]
    fn unconditional_deny_hides_matching_tools() {
        let cfg = McpToolGatingConfig {
            gates: vec![gate("g1", McpToolGateEffect::Deny, &["^delete_", "^admin_"], None)],
            ..Default::default()
        };
        let compiled = compile(&cfg);
        assert_eq!(
            compiled.filter_tools(tools(), &Value::Null),
            vec!["read_file".to_string(), "write_file".to_string()]
        );
        assert!(!compiled.is_tool_call_allowed("delete_file", &Value::Null));
        assert!(compiled.is_tool_call_allowed("read_file", &Value::Null));
    }

    #[test]
    fn allow_gate_under_allow_default_does_not_restrict() {
        // With the default `allow` baseline, an allow gate is redundant: a tool
        // that does NOT match it is still allowed (an allow gate only adds
        // allowances over the default). Allow-lists require a `deny` default.
        let cfg = McpToolGatingConfig {
            gates: vec![gate("g1", McpToolGateEffect::Allow, &["_file$"], None)],
            ..Default::default()
        };
        let compiled = compile(&cfg);
        assert_eq!(compiled.filter_tools(tools(), &Value::Null), tools());
        // admin_reset does not match the allow gate but is allowed by default.
        assert!(compiled.is_tool_call_allowed("admin_reset", &Value::Null));
    }

    #[test]
    fn deny_overrides_allow() {
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: vec![
                gate("allow", McpToolGateEffect::Allow, &["_file$"], None),
                gate("deny", McpToolGateEffect::Deny, &["^delete_"], None),
            ],
        };
        let compiled = compile(&cfg);
        // deny-default allow-list: `_file$` tools survive, but delete_file (also
        // matched by the deny gate) is denied — deny overrides allow.
        assert_eq!(
            compiled.filter_tools(tools(), &Value::Null),
            vec!["read_file".to_string(), "write_file".to_string()]
        );
        assert!(!compiled.is_tool_call_allowed("delete_file", &Value::Null));
    }

    #[test]
    fn allow_gates_union() {
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: vec![
                gate("a1", McpToolGateEffect::Allow, &["^read_"], None),
                gate("a2", McpToolGateEffect::Allow, &["^write_"], None),
            ],
        };
        let compiled = compile(&cfg);
        // Under a deny default, a tool allowed by EITHER allow gate survives (union).
        assert_eq!(
            compiled.filter_tools(tools(), &Value::Null),
            vec!["read_file".to_string(), "write_file".to_string()]
        );
    }

    #[test]
    fn inactive_gate_via_condition_deny_is_skipped() {
        // A deny gate whose condition returns deny is inactive → no effect.
        let cfg = McpToolGatingConfig {
            gates: vec![gate("g1", McpToolGateEffect::Deny, &["^delete_"], Some("always-deny"))],
            ..Default::default()
        };
        let compiled = compile(&cfg);
        assert_eq!(compiled.filter_tools(tools(), &Value::Null), tools());
        assert!(compiled.is_tool_call_allowed("delete_file", &Value::Null));
    }

    #[test]
    fn active_gate_via_condition_allow_is_enforced() {
        let cfg = McpToolGatingConfig {
            gates: vec![gate("g1", McpToolGateEffect::Deny, &["^delete_"], Some("always-allow"))],
            ..Default::default()
        };
        let compiled = compile(&cfg);
        assert!(!compiled.is_tool_call_allowed("delete_file", &Value::Null));
        assert!(compiled.is_tool_call_allowed("read_file", &Value::Null));
    }

    #[test]
    fn unresolved_condition_fails_closed() {
        // Condition references a policy the resolver cannot find → fail closed
        // → gate is active → its deny action is enforced.
        let cfg = McpToolGatingConfig {
            gates: vec![gate("g1", McpToolGateEffect::Deny, &["^delete_"], Some("missing-policy"))],
            ..Default::default()
        };
        let compiled = compile(&cfg);
        assert!(!compiled.is_tool_call_allowed("delete_file", &Value::Null));
    }

    #[test]
    fn unresolved_allow_gate_does_not_grant_under_deny_default() {
        // deny-by-default + a single allow gate whose condition can't be
        // resolved. Failing the allow gate CLOSED must mean "do not grant" —
        // otherwise a broken/missing condition silently opens the allow-list.
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: vec![gate("a1", McpToolGateEffect::Allow, &["^get_"], Some("missing-policy"))],
        };
        let compiled = compile(&cfg);
        assert!(!compiled.is_tool_call_allowed("get_news", &Value::Null));
        assert!(
            compiled
                .filter_tools(tools(), &Value::Null)
                .is_empty()
        );
    }

    #[test]
    fn unresolved_allow_gate_is_inert_under_allow_default() {
        // allow-by-default + an allow gate with an unresolvable condition: the
        // gate is inactive, so tools follow the allow default (still allowed).
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Allow,
            gates: vec![gate("a1", McpToolGateEffect::Allow, &["^get_"], Some("missing-policy"))],
        };
        let compiled = compile(&cfg);
        assert!(compiled.is_tool_call_allowed("get_news", &Value::Null));
        assert!(compiled.is_tool_call_allowed("admin_reset", &Value::Null));
    }

    #[test]
    fn invalid_regex_pattern_is_dropped_not_fatal() {
        // "(" is an invalid regex; the gate compiles with no effective pattern
        // and therefore matches nothing.
        let cfg = McpToolGatingConfig {
            gates: vec![gate("g1", McpToolGateEffect::Deny, &["("], None)],
            ..Default::default()
        };
        let compiled = compile(&cfg);
        assert_eq!(compiled.filter_tools(tools(), &Value::Null), tools());
    }

    #[test]
    fn deny_by_default_with_allow_list_keeps_only_matches() {
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: vec![gate("a1", McpToolGateEffect::Allow, &["_file$"], None)],
        };
        let compiled = compile(&cfg);
        assert!(!compiled.is_empty());
        assert_eq!(
            compiled.filter_tools(tools(), &Value::Null),
            vec!["read_file".to_string(), "write_file".to_string(), "delete_file".to_string()]
        );
        assert!(!compiled.is_tool_call_allowed("admin_reset", &Value::Null));
        assert!(compiled.is_tool_call_allowed("read_file", &Value::Null));
    }

    #[test]
    fn deny_by_default_with_no_gates_denies_all() {
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: vec![],
        };
        let compiled = compile(&cfg);
        // Not empty: the stage must run to deny every tool.
        assert!(!compiled.is_empty());
        assert!(
            compiled
                .filter_tools(tools(), &Value::Null)
                .is_empty()
        );
        assert!(!compiled.is_tool_call_allowed("read_file", &Value::Null));
    }

    #[test]
    fn filter_tools_list_value_strips_denied_tools_from_response() {
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: vec![],
        };
        let compiled = compile(&cfg);
        let mut response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    { "name": "read_file" },
                    { "name": "write_file" }
                ]
            }
        });
        let counts = compiled.filter_tools_list_value(&mut response, &Value::Null);
        assert_eq!(counts, Some((2, 0)));
        assert_eq!(
            response["result"]["tools"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn filter_tools_list_value_returns_none_without_tools_array() {
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: vec![],
        };
        let compiled = compile(&cfg);
        let mut not_a_list = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
        assert_eq!(compiled.filter_tools_list_value(&mut not_a_list, &Value::Null), None);
    }

    #[test]
    fn deny_by_default_with_only_inactive_allow_still_denies() {
        // Robustness case: the sole allow gate is gated behind a condition
        // that returns deny (inactive). With no active allow gate the tool
        // falls back to the deny default — everything denied, no leak.
        let cfg = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: vec![gate("a1", McpToolGateEffect::Allow, &["_file$"], Some("always-deny"))],
        };
        let compiled = compile(&cfg);
        assert!(
            compiled
                .filter_tools(tools(), &Value::Null)
                .is_empty()
        );
        assert!(!compiled.is_tool_call_allowed("read_file", &Value::Null));
    }

    #[test]
    fn has_policy_conditions_reflects_gate_conditions() {
        let unconditional = McpToolGatingConfig {
            gates: vec![gate("g1", McpToolGateEffect::Deny, &["^admin_"], None)],
            ..Default::default()
        };
        assert!(!compile(&unconditional).has_policy_conditions());

        let conditional = McpToolGatingConfig {
            gates: vec![gate("g1", McpToolGateEffect::Deny, &["^admin_"], Some("always-allow"))],
            ..Default::default()
        };
        assert!(compile(&conditional).has_policy_conditions());
    }

    #[test]
    fn gates_sharing_a_condition_policy_evaluate_consistently() {
        // Two gates reference the same (always-allow) condition policy; both
        // are active, so both deny actions apply. Exercises the shared-engine
        // (build-time dedup) + per-request memoization path.
        let cfg = McpToolGatingConfig {
            gates: vec![
                gate("g1", McpToolGateEffect::Deny, &["^admin_"], Some("always-allow")),
                gate("g2", McpToolGateEffect::Deny, &["^delete_"], Some("always-allow")),
            ],
            ..Default::default()
        };
        let compiled = compile(&cfg);
        assert!(compiled.has_policy_conditions());
        assert_eq!(
            compiled.filter_tools(tools(), &Value::Null),
            vec!["read_file".to_string(), "write_file".to_string()]
        );
        assert!(!compiled.is_tool_call_allowed("admin_reset", &Value::Null));
        assert!(!compiled.is_tool_call_allowed("delete_file", &Value::Null));
    }

    /// Exhaustive truth table over `default_effect` × gate set × match ×
    /// condition activeness. Also asserts `tools/call` agrees with `tools/list`
    /// for every tool (they must never diverge). Tools: alpha / beta / gamma.
    #[test]
    fn firewall_truth_table() {
        use McpToolGateEffect::{Allow, Deny};

        // (effect, pattern, condition-policy-id)
        type G = (McpToolGateEffect, &'static str, Option<&'static str>);
        struct Case {
            name: &'static str,
            default: McpToolGateEffect,
            gates: Vec<G>,
            expected: Vec<&'static str>,
        }
        let all = || vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];

        let cases: Vec<Case> = vec![
            // ── default = allow (allowed unless denied) ──────────────────
            Case {
                name: "allow-default / no gates",
                default: Allow,
                gates: vec![],
                expected: vec!["alpha", "beta", "gamma"],
            },
            Case {
                name: "allow-default / allow gate matches (redundant)",
                default: Allow,
                gates: vec![(Allow, "^alpha$", None)],
                expected: vec!["alpha", "beta", "gamma"],
            },
            Case {
                name: "allow-default / allow gate matches nothing",
                default: Allow,
                gates: vec![(Allow, "^zzz$", None)],
                expected: vec!["alpha", "beta", "gamma"],
            },
            Case {
                name: "allow-default / deny gate matches",
                default: Allow,
                gates: vec![(Deny, "^alpha$", None)],
                expected: vec!["beta", "gamma"],
            },
            Case {
                name: "allow-default / deny gate matches nothing",
                default: Allow,
                gates: vec![(Deny, "^zzz$", None)],
                expected: vec!["alpha", "beta", "gamma"],
            },
            Case {
                name: "allow-default / allow+deny overlap (deny wins)",
                default: Allow,
                gates: vec![(Allow, "^alpha$", None), (Deny, "^alpha$", None)],
                expected: vec!["beta", "gamma"],
            },
            Case {
                name: "allow-default / allow one + deny other",
                default: Allow,
                gates: vec![(Allow, "^alpha$", None), (Deny, "^beta$", None)],
                expected: vec!["alpha", "gamma"],
            },
            Case {
                name: "allow-default / deny gate inactive (condition off)",
                default: Allow,
                gates: vec![(Deny, "^alpha$", Some("always-deny"))],
                expected: vec!["alpha", "beta", "gamma"],
            },
            Case {
                name: "allow-default / deny gate active (condition on)",
                default: Allow,
                gates: vec![(Deny, "^alpha$", Some("always-allow"))],
                expected: vec!["beta", "gamma"],
            },
            // ── default = deny (denied unless allowed) ───────────────────
            Case {
                name: "deny-default / no gates (deny all)",
                default: Deny,
                gates: vec![],
                expected: vec![],
            },
            Case {
                name: "deny-default / allow gate matches (allow-list)",
                default: Deny,
                gates: vec![(Allow, "^alpha$", None)],
                expected: vec!["alpha"],
            },
            Case {
                name: "deny-default / allow union",
                default: Deny,
                gates: vec![(Allow, "^alpha$", None), (Allow, "^beta$", None)],
                expected: vec!["alpha", "beta"],
            },
            Case {
                name: "deny-default / allow gate matches nothing (deny all)",
                default: Deny,
                gates: vec![(Allow, "^zzz$", None)],
                expected: vec![],
            },
            Case {
                name: "deny-default / deny gate only (redundant, deny all)",
                default: Deny,
                gates: vec![(Deny, "^alpha$", None)],
                expected: vec![],
            },
            Case {
                name: "deny-default / allow+deny overlap (deny wins)",
                default: Deny,
                gates: vec![(Allow, "^alpha$", None), (Deny, "^alpha$", None)],
                expected: vec![],
            },
            Case {
                name: "deny-default / allow two + deny one",
                default: Deny,
                gates: vec![(Allow, "^alpha$", None), (Allow, "^beta$", None), (Deny, "^beta$", None)],
                expected: vec!["alpha"],
            },
            Case {
                name: "deny-default / allow gate inactive (condition off, deny all)",
                default: Deny,
                gates: vec![(Allow, "^alpha$", Some("always-deny"))],
                expected: vec![],
            },
            Case {
                name: "deny-default / allow gate active (condition on)",
                default: Deny,
                gates: vec![(Allow, "^alpha$", Some("always-allow"))],
                expected: vec!["alpha"],
            },
        ];

        for case in &cases {
            let cfg = McpToolGatingConfig {
                default_effect: case.default,
                gates: case
                    .gates
                    .iter()
                    .enumerate()
                    .map(|(i, (effect, pattern, condition))| gate(&format!("g{i}"), *effect, &[*pattern], *condition))
                    .collect(),
            };
            let compiled = compile(&cfg);

            let got = compiled.filter_tools(all(), &Value::Null);
            let expected: Vec<String> = case
                .expected
                .iter()
                .map(|s| s.to_string())
                .collect();
            assert_eq!(got, expected, "tools/list mismatch for case: {}", case.name);

            // tools/call MUST agree with tools/list for every tool.
            for tool in all() {
                let call_allowed = compiled.is_tool_call_allowed(&tool, &Value::Null);
                let in_list = expected.contains(&tool);
                assert_eq!(
                    call_allowed, in_list,
                    "tools/call vs tools/list disagree for '{}' in case: {}",
                    tool, case.name
                );
            }
        }
    }
}
