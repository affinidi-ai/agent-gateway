//! Trust Check stage entry point.
//!
//! One thin glue function the request pipeline calls on each leg
//! (inbound caller, outbound target) after the legacy
//! `trust_registry_verification` stage and before any OPA evaluation.
//! Returns the populated [`TrustCheckResultsContext`] for the leg, ready
//! to drop straight onto `PolicyInput.trust_check_results`. Returns
//! `None` when no elements are configured for the leg, so the OPA input
//! never carries an empty result block in that case.

use serde_json::{Value, json};

use crate::trust_registry_verification::metadata_gate::synthesize_metadata_gate_failures;
use crate::trust_registry_verification::trust_check_element::{
    TrustCheckElement, TrustCheckLeg, TrustCheckResult, TrustCheckResultsContext,
};
use crate::trust_registry_verification::trust_check_executor::{
    ExecutionContext, NOT_AUTHORIZED, NOT_RECOGNIZED, TrqpClient, execute_list,
};

/// Consolidate all trust check results and log the summary for visibility
fn consolidate_trust_check_results(results: &[TrustCheckResult]) -> (usize, usize, usize) {
    let mut ok_count = 0usize;
    let mut denied_count = 0usize;
    let mut error_count = 0usize;
    for r in results {
        if r.ok {
            ok_count += 1;
        } else if matches!(
            r.error
                .as_ref()
                .map(|e| e.code.as_str()),
            Some(NOT_RECOGNIZED | NOT_AUTHORIZED)
        ) {
            denied_count += 1;
        } else {
            error_count += 1;
        }
    }
    (ok_count, denied_count, error_count)
}

/// Run the Trust Check stage for a single leg.
///
/// `elements` is the configured `trust_check_list` for the leg
/// (`AccessPoint.trust_check_list` on the caller leg,
/// `Target.trust_check_list` on the target leg). Every element fires —
/// the caller leg runs at a single post-identity seam (so templates that
/// reference `{{ input.extension_identity.did }}` resolve against the
/// gateway-derived agent DID), the target leg at the existing single
/// outbound seam. Surface OPA observes the result; gateway OPA no longer
/// sees trust check results on the caller leg.
///
/// `input` is the bare `PolicyInput` JSON (top-level keys: `agent`,
/// `mcp`, `a2a`, `extension_identity`, …). The stage wraps it once under
/// `{ "input": … }` so dashboard templates can use the OPA convention
/// (`{{ input.agent.did }}`) verbatim — the same shape Rego policies see
/// at every other OPA seam.
///
/// Returns `None` when the list is empty so the caller leaves
/// `PolicyInput.trust_check_results` absent. Returns `Some(...)` when at
/// least one element fires; the matching leg of the returned context
/// carries the results, the other leg is an empty list so OPA rules
/// don't need null checks.
pub async fn run_trust_check_stage<C: TrqpClient + ?Sized>(
    surface_id: &str,
    leg: TrustCheckLeg,
    elements: &[TrustCheckElement],
    input: &Value,
    client: &C,
) -> Option<TrustCheckResultsContext> {
    if elements.is_empty() {
        return None;
    }
    let wrapped = json!({ "input": input });
    // Per-element metadata gate — synthesizes TRUST_REGISTRY_METADATA_UNAVAILABLE
    // for elements whose query template references TR-metadata leaves
    // the built `input.agent` doesn't populate. Runs on both legs; each
    // leg has its own allow-list. Runnable elements (gate-clear) go
    // through the TRQP executor; synthesized entries are merged back at
    // their configured index so the result list preserves order.
    let (synthesized_by_index, runnable) = synthesize_metadata_gate_failures(surface_id, leg, elements, &wrapped);
    let executor_results: Vec<TrustCheckResult> = if runnable.is_empty() {
        Vec::new()
    } else {
        execute_list(surface_id, leg, &runnable, &ExecutionContext { input: &wrapped }, client).await
    };
    let mut executor_iter = executor_results.into_iter();
    let mut results: Vec<TrustCheckResult> = Vec::with_capacity(synthesized_by_index.len());
    for slot in synthesized_by_index {
        match slot {
            Some(r) => results.push(r),
            None => {
                if let Some(r) = executor_iter.next() {
                    results.push(r);
                }
            }
        }
    }
    let (ok_count, denied_count, error_count) = consolidate_trust_check_results(&results);
    let leg_label = match leg {
        TrustCheckLeg::Caller => "caller",
        TrustCheckLeg::Target => "target",
    };
    tracing::info!(
        target: "trust_check_audit",
        surface_id = surface_id,
        leg = leg_label,
        total = results.len(),
        ok = ok_count,
        denied = denied_count,
        error = error_count,
        "Trust Check Consolidated Result:"
    );
    let ctx = match leg {
        TrustCheckLeg::Caller => TrustCheckResultsContext {
            caller: results,
            target: Vec::new(),
        },
        TrustCheckLeg::Target => TrustCheckResultsContext {
            caller: Vec::new(),
            target: results,
        },
    };
    Some(ctx)
}

/// Run the caller-leg Trust Check stage from a typed [`PolicyInput`].
///
/// Thin wrapper over [`run_trust_check_stage`] that owns the serialization
/// step so every caller-leg seam (direct A2A/MCP, fabric-receive, MCP proxy)
/// shares one code path. Callers build a single fully-populated `PolicyInput`
/// (with whatever protocol contexts apply — `agent`, `mcp`, `a2a`,
/// `extension_identity`, …) and pass it by reference; the same value is the
/// one surface OPA consumes immediately afterwards, so protocol context can't
/// drift between the check and the policy gate. Returns `None` when no
/// elements are configured, matching [`run_trust_check_stage`].
pub async fn run_caller_trust_check<C: TrqpClient + ?Sized>(
    surface_id: &str,
    elements: &[TrustCheckElement],
    input: &crate::surface_context::PolicyInput,
    client: &C,
) -> Option<TrustCheckResultsContext> {
    if elements.is_empty() {
        return None;
    }
    let input_value = serde_json::to_value(input).unwrap_or_default();
    run_trust_check_stage(surface_id, TrustCheckLeg::Caller, elements, &input_value, client).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_registry_verification::trust_check_element::{TrqpQueryParams, TrqpQueryType, TrustCheckElement};
    use crate::trust_registry_verification::trust_check_executor::{TrqpClient, TrqpClientError, TrqpOutcome};
    use async_trait::async_trait;
    use serde_json::json;

    struct AllowClient;

    #[async_trait]
    impl TrqpClient for AllowClient {
        async fn query(
            &self,
            _registry_id: &str,
            _query_type: TrqpQueryType,
            _params: &TrqpQueryParams,
        ) -> Result<TrqpOutcome, TrqpClientError> {
            Ok(TrqpOutcome::Allowed)
        }
    }

    fn elem(id: &str) -> TrustCheckElement {
        TrustCheckElement {
            id: id.to_string(),
            trust_registry_id: "tr-a".to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams {
                authority_id: "did:a".to_string(),
                entity_id: "did:e".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: None,
        }
    }

    #[tokio::test]
    async fn empty_list_returns_none() {
        let res = run_trust_check_stage("surf", TrustCheckLeg::Caller, &[], &json!({}), &AllowClient).await;
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn caller_leg_populates_caller_and_leaves_target_empty() {
        let elements = vec![elem("tc-1"), elem("tc-2")];
        let ctx = run_trust_check_stage("surf", TrustCheckLeg::Caller, &elements, &json!({}), &AllowClient)
            .await
            .expect("expected Some");
        assert_eq!(ctx.caller.len(), 2);
        assert!(ctx.target.is_empty());
        assert!(
            ctx.caller
                .iter()
                .all(|r| r.ok)
        );
    }

    #[tokio::test]
    async fn target_leg_populates_target_and_leaves_caller_empty() {
        let elements = vec![elem("tc-1")];
        let ctx = run_trust_check_stage("surf", TrustCheckLeg::Target, &elements, &json!({}), &AllowClient)
            .await
            .expect("expected Some");
        assert!(ctx.caller.is_empty());
        assert_eq!(ctx.target.len(), 1);
    }

    #[test]
    fn summarize_results_classifies_ok_denied_and_error() {
        use crate::trust_registry_verification::trust_check_element::TrustCheckError;

        fn result(
            ok: bool,
            code: Option<&str>,
        ) -> TrustCheckResult {
            TrustCheckResult {
                id: "r".to_string(),
                trust_registry_id: "tr".to_string(),
                query_type: TrqpQueryType::Recognition,
                ok,
                error: code.map(|c| TrustCheckError {
                    code: c.to_string(),
                    message: String::new(),
                }),
                name: None,
                authority_id: None,
                entity_id: None,
                action: "is".to_string(),
                resource: "ownedAgent".to_string(),
                query_resolved: true,
            }
        }

        let results = vec![
            result(true, None),
            result(false, Some(NOT_RECOGNIZED)),
            result(false, Some(NOT_AUTHORIZED)),
            result(false, Some("QUERY_TIMEOUT")),
            result(false, None),
        ];
        let (ok_count, denied_count, error_count) = consolidate_trust_check_results(&results);
        assert_eq!(ok_count, 1, "one allowed result");
        assert_eq!(denied_count, 2, "NOT_RECOGNIZED + NOT_AUTHORIZED are clean denials");
        assert_eq!(error_count, 2, "transport error + missing-code result are errors");
    }

    /// Acceptance: chained example — two elements on the same edge with
    /// mixed outcomes (one allowed, one denied) both surface in the
    /// matching leg of the published context, preserving configured order.
    #[tokio::test]
    async fn chained_mixed_outcomes_both_land_in_caller_leg() {
        struct MixedClient;
        #[async_trait]
        impl TrqpClient for MixedClient {
            async fn query(
                &self,
                registry_id: &str,
                _q: TrqpQueryType,
                _p: &TrqpQueryParams,
            ) -> Result<TrqpOutcome, TrqpClientError> {
                if registry_id == "tr-allow" {
                    Ok(TrqpOutcome::Allowed)
                } else {
                    Ok(TrqpOutcome::Denied {
                        detail: "Registry answered `recognized: false`".to_string(),
                    })
                }
            }
        }

        let mut e1 = elem("first");
        e1.trust_registry_id = "tr-allow".into();
        let mut e2 = elem("second");
        e2.trust_registry_id = "tr-deny".into();

        let ctx = run_trust_check_stage("surf", TrustCheckLeg::Caller, &[e1, e2], &json!({}), &MixedClient)
            .await
            .expect("expected Some");

        assert_eq!(ctx.caller.len(), 2);
        assert!(ctx.target.is_empty());
        assert!(ctx.caller[0].ok, "first element allowed");
        assert!(!ctx.caller[1].ok, "second element denied");
        let deny_err = ctx.caller[1]
            .error
            .as_ref()
            .expect("negative recognition verdict now carries an error code");
        assert_eq!(deny_err.code, "NOT_RECOGNIZED");
        assert_eq!(ctx.caller[0].trust_registry_id, "tr-allow", "configured order preserved");
        assert_eq!(ctx.caller[1].trust_registry_id, "tr-deny");
    }

    /// Acceptance: PolicyInput exposes the per-leg result block to OPA at
    /// the documented JSON path `input.trust_check_results.{caller|target}`.
    #[tokio::test]
    async fn policy_input_serialises_trust_check_results_at_documented_opa_path() {
        let ctx = run_trust_check_stage("surf", TrustCheckLeg::Caller, &[elem("tc-1")], &json!({}), &AllowClient)
            .await
            .expect("expected Some");

        let mut policy_input = crate::surface_context::PolicyInput::new(
            "POST",
            "/agents/x/messages",
            std::collections::HashMap::new(),
            "inbound",
            None,
            None,
            Some("surf".into()),
            "surface-name",
        );
        policy_input.trust_check_results = Some(ctx);

        let v = serde_json::to_value(&policy_input).expect("serialise");
        let block = v
            .get("trust_check_results")
            .expect("trust_check_results must serialise on PolicyInput");
        assert!(block.get("caller").is_some(), "caller leg must be present");
        assert!(block.get("target").is_some(), "target leg must be present even when empty");
        let caller = block
            .get("caller")
            .and_then(|c| c.as_array())
            .expect("caller is an array");
        assert_eq!(caller.len(), 1);
        let first = &caller[0];
        assert_eq!(first["trust_registry_id"], "tr-a");
        assert_eq!(first["ok"], true);
        assert!(first.get("error").is_none() || first["error"].is_null());
    }

    /// Acceptance: when no element fires, `trust_check_results` is fully
    /// omitted from the serialised PolicyInput so OPA rules that do not
    /// reference it remain unaffected.
    #[test]
    fn policy_input_omits_trust_check_results_when_none() {
        let policy_input = crate::surface_context::PolicyInput::new(
            "POST",
            "/x",
            std::collections::HashMap::new(),
            "inbound",
            None,
            None,
            Some("surf".into()),
            "surface-name",
        );
        let v = serde_json::to_value(&policy_input).expect("serialise");
        assert!(
            v.get("trust_check_results")
                .is_none(),
            "trust_check_results must be absent when no element fired"
        );
    }

    /// Regression: the stage must wrap the bare `PolicyInput` JSON under
    /// `{ "input": ... }` so dashboard templates that use the OPA
    /// convention (`{{ input.agent.did }}`) resolve against the same
    /// shape Rego sees. The call site passes the un-wrapped serialised
    /// `PolicyInput` (top-level keys: `agent`, `mcp`, …); without the
    /// wrap, every `{{ input.* }}` template would fail with
    /// `TEMPLATE_RESOLUTION_FAILED` even when `agent.did` is populated.
    #[tokio::test]
    async fn stage_wraps_input_so_opa_style_templates_resolve() {
        struct CapturingClient {
            captured: tokio::sync::Mutex<Option<TrqpQueryParams>>,
        }
        #[async_trait]
        impl TrqpClient for CapturingClient {
            async fn query(
                &self,
                _registry_id: &str,
                _q: TrqpQueryType,
                params: &TrqpQueryParams,
            ) -> Result<TrqpOutcome, TrqpClientError> {
                *self.captured.lock().await = Some(params.clone());
                Ok(TrqpOutcome::Allowed)
            }
        }

        let mut e = elem("tc-1");
        e.query.authority_id = "{{ input.agent.provider_did }}".to_string();
        e.query.entity_id = "{{ input.agent.did }}".to_string();

        let bare_policy_input = json!({
            "agent": {
                "did": "did:web:caller-agent",
                "provider_did": "did:web:authority"
            }
        });

        let client = CapturingClient {
            captured: tokio::sync::Mutex::new(None),
        };
        let ctx = run_trust_check_stage("surf", TrustCheckLeg::Caller, &[e], &bare_policy_input, &client)
            .await
            .expect("expected Some");

        assert!(ctx.caller[0].ok, "templates resolved and TRQP allowed");
        let resolved = client
            .captured
            .lock()
            .await
            .clone()
            .expect("client received resolved params");
        assert_eq!(resolved.authority_id, "did:web:authority");
        assert_eq!(resolved.entity_id, "did:web:caller-agent");
    }

    /// Regression: on the GW2 fabric-receive path the
    /// caller-leg Trust Check must populate `input.agent` (built from the
    /// caller's body via `build_agent_context`, source mode) so the default
    /// caller-leg template `{{ input.agent.provider_did }}` resolves. The
    /// pre-fix fabric seam built the trust-check input WITHOUT `agent`, so
    /// every provider_did template failed — while the direct-inbound path
    /// (which sets `probe_input.agent`) worked (the direct URL works fine).
    /// With the metadata gate active the
    /// agent-less path now surfaces the specific
    /// `TRUST_REGISTRY_METADATA_UNAVAILABLE` code instead of the generic
    /// `TEMPLATE_RESOLUTION_FAILED`; either code is a deny — the check is
    /// that the element does not silently pass.
    #[tokio::test]
    async fn affbk_901_caller_provider_did_template_resolves_from_source_mode_agent_context() {
        use crate::trust_registry_verification::trust_check_executor::TRUST_REGISTRY_METADATA_UNAVAILABLE;

        // The caller's original (source-mode) body as it arrives over fabric:
        // the trust-registry extension lives under `metadata`.
        let caller_body = json!({
            "jsonrpc": "2.0",
            "params": {
                "message": {
                    "kind": "message",
                    "metadata": {
                        crate::config::TRUST_REGISTRY_EXTENSION: {
                            "trust_registry_did": "did:web:registry.example",
                            "provider_did": "did:web:provider.example",
                            "authority_did": "did:web:authority.example"
                        }
                    }
                }
            }
        });

        // The dashboard's default caller-leg element templates the authority
        // on `{{ input.agent.provider_did }}` (the field the bug couldn't find).
        let mut element = elem("caller-tc");
        element.query.authority_id = "{{ input.agent.provider_did }}".to_string();

        // ── Fix: input built the way the patched fabric seam builds it ──
        // `build_agent_context(body, None, None)` — source mode, no recognition
        // queries — extracts provider_did synchronously from the caller body.
        let agent_ctx = crate::policies::build_agent_context(Some(&caller_body), None, None, false).await;
        assert_eq!(
            agent_ctx
                .provider_did
                .as_deref(),
            Some("did:web:provider.example"),
            "source-mode build must extract the caller's provider_did"
        );
        let mut policy_input = crate::surface_context::PolicyInput::new(
            "POST",
            "/a2a/tasks/send",
            std::collections::HashMap::new(),
            "inbound",
            Some("did:web:caller-gateway".into()),
            None,
            Some("surf".into()),
            "surface-name",
        );
        policy_input.agent = Some(agent_ctx);
        policy_input.normalize_caller_did();
        let fixed_input = serde_json::to_value(&policy_input).expect("serialise");

        let fixed = run_trust_check_stage(
            "surf",
            TrustCheckLeg::Caller,
            std::slice::from_ref(&element),
            &fixed_input,
            &AllowClient,
        )
        .await
        .expect("expected Some");
        assert!(
            fixed.caller[0].ok,
            "with input.agent populated the provider_did template resolves and TRQP allows; got {:?}",
            fixed.caller[0].error
        );

        // ── Bug reproduction: the pre-fix fabric input carried no `agent` ──
        let buggy = run_trust_check_stage(
            "surf",
            TrustCheckLeg::Caller,
            std::slice::from_ref(&element),
            &json!({}),
            &AllowClient,
        )
        .await
        .expect("expected Some");
        assert!(!buggy.caller[0].ok, "an agent-less input must fail the element, not silently pass");
        assert_eq!(
            buggy.caller[0]
                .error
                .as_ref()
                .map(|e| e.code.as_str()),
            Some(TRUST_REGISTRY_METADATA_UNAVAILABLE),
            "agent-less input must fail with TRUST_REGISTRY_METADATA_UNAVAILABLE (caller-leg metadata gate)"
        );
    }

    /// MCP caller-leg parity: `run_caller_trust_check` fed a `PolicyInput`
    /// built for an MCP surface resolves both the agent provider DID (from the
    /// caller's `_meta` trust-registry extension) and `{{ input.mcp.* }}`, so
    /// MCP surfaces get the same caller-leg Trust Check behaviour as A2A.
    #[tokio::test]
    async fn run_caller_trust_check_resolves_mcp_agent_and_mcp_context() {
        struct CapturingClient {
            captured: tokio::sync::Mutex<Option<TrqpQueryParams>>,
        }
        #[async_trait]
        impl TrqpClient for CapturingClient {
            async fn query(
                &self,
                _registry_id: &str,
                _q: TrqpQueryType,
                params: &TrqpQueryParams,
            ) -> Result<TrqpOutcome, TrqpClientError> {
                *self.captured.lock().await = Some(params.clone());
                Ok(TrqpOutcome::Allowed)
            }
        }

        // MCP request carrying the trust-registry extension under `_meta`.
        let caller_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "search" },
            "_meta": {
                crate::config::TRUST_REGISTRY_EXTENSION: {
                    "trust_registry_did": "did:web:registry.mcp",
                    "provider_did": "did:web:provider.mcp",
                    "authority_did": "did:web:authority.mcp"
                }
            }
        });

        let agent_ctx = crate::policies::build_agent_context_for_protocol(
            crate::config::ChannelProtocol::Mcp,
            Some(&caller_body),
            None,
            None,
            false,
        )
        .await;
        assert_eq!(
            agent_ctx
                .provider_did
                .as_deref(),
            Some("did:web:provider.mcp")
        );

        let mut policy_input = crate::surface_context::PolicyInput::new(
            "POST",
            "/mcp",
            std::collections::HashMap::new(),
            "inbound",
            None,
            None,
            Some("surf".into()),
            "surface-name",
        );
        policy_input.agent = Some(agent_ctx);
        policy_input.mcp = crate::mcp::build_mcp_context(
            serde_json::to_vec(&caller_body)
                .unwrap()
                .as_slice(),
        );
        policy_input.normalize_caller_did();

        let mut element = elem("mcp-caller-tc");
        element.query.authority_id = "{{ input.agent.provider_did }}".to_string();
        element.query.entity_id = "{{ input.mcp.tool_name }}".to_string();

        let client = CapturingClient {
            captured: tokio::sync::Mutex::new(None),
        };
        let ctx = run_caller_trust_check("surf", std::slice::from_ref(&element), &policy_input, &client)
            .await
            .expect("expected Some");

        assert!(ctx.caller[0].ok, "MCP caller-leg templates resolved and TRQP allowed: {:?}", ctx.caller[0].error);
        assert!(ctx.target.is_empty(), "caller leg only");
        let resolved = client
            .captured
            .lock()
            .await
            .clone()
            .expect("client received resolved params");
        assert_eq!(resolved.authority_id, "did:web:provider.mcp");
        assert_eq!(resolved.entity_id, "search");
    }

    #[tokio::test]
    async fn caller_trust_check_resolves_only_admitted_modern_protocol_version() {
        use crate::mcp::request_validation::{LegacySessionEvidence, McpVersionPolicy, validate_mcp_post};
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("mcp-method", "tools/list".parse().unwrap());
        let bytes = serde_json::to_vec(&body).unwrap();
        let classification = validate_mcp_post(
            &headers,
            &bytes,
            LegacySessionEvidence::Absent,
            McpVersionPolicy::new(&[crate::mcp::MCP_MODERN_VERSION], &[crate::mcp::MCP_MODERN_VERSION]),
        )
        .unwrap();
        let mut input = crate::surface_context::PolicyInput {
            mcp: crate::mcp::build_validated_mcp_context(&bytes, &classification),
            ..Default::default()
        };
        let mut element = elem("modern-protocol");
        element.query.action = Some("{{ input.mcp.protocol_version }}".to_string());
        let modern = run_caller_trust_check("surface", std::slice::from_ref(&element), &input, &AllowClient)
            .await
            .unwrap();
        assert!(modern.caller[0].ok);
        assert_eq!(modern.caller[0].action, crate::mcp::MCP_MODERN_VERSION);

        input.mcp = crate::mcp::build_mcp_context(br#"{"id":1,"method":"tools/list"}"#);
        let legacy = run_caller_trust_check("surface", &[element], &input, &AllowClient)
            .await
            .unwrap();
        assert!(!legacy.caller[0].ok);
        assert_eq!(
            legacy.caller[0]
                .error
                .as_ref()
                .unwrap()
                .code,
            "TEMPLATE_RESOLUTION_FAILED"
        );
    }
}
