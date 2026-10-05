//! Shared per-element gate that synthesizes
//! [`TRUST_REGISTRY_METADATA_UNAVAILABLE`] on both Trust Check legs when
//! an element's query template references a TR-metadata field the
//! upstream context does not populate.
//!
//! The **target leg** gates on the fields sourced from the target's
//! agent card (`provider_did`, `trust_registry_did`).
//!
//! The **caller leg** gates on the fields sourced from the caller's
//! request payload — its identity credential extension plus its
//! `trust-registry/v1` extension (`did`, `provider_did`,
//! `trust_registry_did`, `authority_did`).
//!
//! Each leg has its own allow-list of leaf paths so a template
//! referencing a leg-irrelevant field falls through to the executor and
//! produces the element's real answer. Only
//! [`TemplateError::Unresolved`] participates; `NonScalar`/`Malformed`
//! are genuine template-authoring bugs and are left to the executor,
//! which surfaces them as `TEMPLATE_RESOLUTION_FAILED` with the raw
//! template strings preserved.
//!
//! Path matching is exact-leaf under `||` fallback chains: the marker
//! body is split by `||`, each branch trimmed, and each branch
//! exact-compared to the leg's allow-list. So
//! `{{ input.agent.did || input.extension_identity.did }}` only trips
//! the `did` flag when **every** branch would fail — matching the
//! resolver's exhaust-on-all-branches contract.

use serde_json::Value;

use crate::observability::trust_check_audit::{TrustCheckAuditEvent, record_trust_check};
use crate::trust_registry_verification::template::{self, TemplateError};
use crate::trust_registry_verification::trust_check_element::{TrustCheckElement, TrustCheckLeg, TrustCheckResult};
use crate::trust_registry_verification::trust_check_executor::{
    TRUST_REGISTRY_METADATA_UNAVAILABLE, synthesize_failure,
};

const AGENT_DID_PATH: &str = "input.agent.did";
const AGENT_PROVIDER_DID_PATH: &str = "input.agent.provider_did";
const AGENT_TRUST_REGISTRY_DID_PATH: &str = "input.agent.trust_registry_did";
const AGENT_AUTHORITY_DID_PATH: &str = "input.agent.authority_did";

/// Which TR-metadata fields the element's template references AND the
/// upstream context does not populate. Drives both
/// [`element_needs_missing_tr_metadata`] and
/// [`build_missing_metadata_message`].
///
/// The target leg only ever sets `provider_did` / `trust_registry_did`;
/// the caller leg additionally sets `did` / `authority_did`. Callers
/// should not read leg-irrelevant flags — they are always `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MissingTrMetadataFields {
    pub did: bool,
    pub provider_did: bool,
    pub trust_registry_did: bool,
    pub authority_did: bool,
}

impl MissingTrMetadataFields {
    fn any(self) -> bool {
        self.did || self.provider_did || self.trust_registry_did || self.authority_did
    }
}

/// Per-element predicate. Returns `Some(fields)` when the element's
/// query template references one of the leg's TR-metadata leaf paths
/// AND the corresponding field is missing on the built `input.agent`.
/// Returns `None` when the template references only fields the context
/// populates (or references non-metadata paths entirely) — in that case
/// the executor path runs and produces the element's real answer.
pub fn element_needs_missing_tr_metadata(
    elem: &TrustCheckElement,
    leg: TrustCheckLeg,
    wrapped_input: &Value,
) -> Option<MissingTrMetadataFields> {
    let agent = wrapped_input.pointer("/input/agent");
    let did_gated = matches!(leg, TrustCheckLeg::Caller) && !is_populated_field(agent, "did");
    let provider_gated = !is_populated_field(agent, "provider_did");
    let registry_gated = !is_populated_field(agent, "trust_registry_did");
    let authority_gated = matches!(leg, TrustCheckLeg::Caller) && !is_populated_field(agent, "authority_did");

    if !did_gated && !provider_gated && !registry_gated && !authority_gated {
        return None;
    }

    let templates: [&str; 4] = [
        elem.query
            .authority_id
            .as_str(),
        elem.query.entity_id.as_str(),
        elem.query
            .action
            .as_deref()
            .unwrap_or(""),
        elem.query
            .resource
            .as_deref()
            .unwrap_or(""),
    ];

    let mut fields = MissingTrMetadataFields::default();
    for tmpl in templates {
        if tmpl.is_empty() {
            continue;
        }
        let Err(TemplateError::Unresolved { path }) = template::resolve(tmpl, wrapped_input) else {
            // Ok / NonScalar / Malformed → not our concern. NonScalar and
            // Malformed remain executor-side TEMPLATE_RESOLUTION_FAILED.
            continue;
        };
        if did_gated && path_mentions_leaf(&path, AGENT_DID_PATH) {
            fields.did = true;
        }
        if provider_gated && path_mentions_leaf(&path, AGENT_PROVIDER_DID_PATH) {
            fields.provider_did = true;
        }
        if registry_gated && path_mentions_leaf(&path, AGENT_TRUST_REGISTRY_DID_PATH) {
            fields.trust_registry_did = true;
        }
        if authority_gated && path_mentions_leaf(&path, AGENT_AUTHORITY_DID_PATH) {
            fields.authority_did = true;
        }
    }

    fields.any().then_some(fields)
}

/// Partition `elements` into (synthesized, runnable) using
/// [`element_needs_missing_tr_metadata`]. For every element the gate
/// fires on, a `TRUST_REGISTRY_METADATA_UNAVAILABLE` result is
/// synthesized via [`synthesize_failure`] AND a matching audit event is
/// recorded so operators see the deny in the audit trail. `synthesized`
/// is parallel to `elements` (same length; `None` slots correspond to
/// runnable elements). `runnable` is the sublist the caller should send
/// through the TRQP executor.
pub fn synthesize_metadata_gate_failures(
    surface_id: &str,
    leg: TrustCheckLeg,
    elements: &[TrustCheckElement],
    wrapped_input: &Value,
) -> (Vec<Option<TrustCheckResult>>, Vec<TrustCheckElement>) {
    let mut synthesized: Vec<Option<TrustCheckResult>> = Vec::with_capacity(elements.len());
    let mut runnable: Vec<TrustCheckElement> = Vec::new();
    for elem in elements {
        match element_needs_missing_tr_metadata(elem, leg, wrapped_input) {
            Some(fields) => {
                let msg = build_missing_metadata_message(leg, &fields);
                let result = synthesize_failure(elem, TRUST_REGISTRY_METADATA_UNAVAILABLE, msg.clone());
                record_trust_check(TrustCheckAuditEvent {
                    surface_id,
                    leg,
                    element_id: elem.id.as_str(),
                    element_name: elem.name.as_deref(),
                    authority_id: None,
                    entity_id: None,
                    trust_registry_id: elem
                        .trust_registry_id
                        .as_str(),
                    query_type: elem.query_type,
                    ok: false,
                    error_code: Some(TRUST_REGISTRY_METADATA_UNAVAILABLE),
                    error_detail: Some(&msg),
                    latency_ms: 0,
                });
                synthesized.push(Some(result));
            }
            None => {
                synthesized.push(None);
                runnable.push(elem.clone());
            }
        }
    }
    (synthesized, runnable)
}

/// Operator-facing `error.message` naming the specific field(s) the
/// leg's upstream must populate to unblock the element. Wording is
/// leg-specific: the target leg blames the target's agent card, the
/// caller leg blames the caller's request payload.
pub fn build_missing_metadata_message(
    leg: TrustCheckLeg,
    fields: &MissingTrMetadataFields,
) -> String {
    match leg {
        TrustCheckLeg::Target => build_target_message(fields),
        TrustCheckLeg::Caller => build_caller_message(fields),
    }
}

fn build_target_message(fields: &MissingTrMetadataFields) -> String {
    match (fields.provider_did, fields.trust_registry_did) {
        (true, true) => {
            "target agent card does not populate provider_did or trust_registry_did in its trust registry metadata"
                .to_string()
        }
        (true, false) => "target agent card does not populate provider_did in its trust registry metadata".to_string(),
        (false, true) => {
            "target agent card does not populate trust_registry_did in its trust registry metadata".to_string()
        }
        (false, false) => {
            // Defensive; element_needs_missing_tr_metadata returns None in this case.
            "target agent card is missing the trust registry metadata extension".to_string()
        }
    }
}

fn build_caller_message(fields: &MissingTrMetadataFields) -> String {
    let mut tr_fields: Vec<&str> = Vec::new();
    if fields.provider_did {
        tr_fields.push("provider_did");
    }
    if fields.trust_registry_did {
        tr_fields.push("trust_registry_did");
    }
    if fields.authority_did {
        tr_fields.push("authority_did");
    }
    let tr_clause = (!tr_fields.is_empty())
        .then(|| format!("does not populate {} in its trust registry metadata extension", join_english(&tr_fields)));
    let did_clause = fields
        .did
        .then(|| "does not carry an agent identity credential".to_string());
    match (did_clause, tr_clause) {
        (Some(d), Some(t)) => format!("caller's request payload {d} and {t}"),
        (Some(d), None) => format!("caller's request payload {d}"),
        (None, Some(t)) => format!("caller's request payload {t}"),
        (None, None) => "caller's request payload is missing the trust registry metadata extension".to_string(),
    }
}

fn join_english(items: &[&str]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].to_string(),
        2 => format!("{} or {}", items[0], items[1]),
        _ => {
            let (last, head) = items
                .split_last()
                .expect("len > 2");
            format!("{} or {}", head.join(", "), last)
        }
    }
}

fn is_populated_field(
    agent: Option<&Value>,
    key: &str,
) -> bool {
    agent
        .and_then(|a| a.get(key))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .is_some()
}

fn path_mentions_leaf(
    path: &str,
    leaf: &str,
) -> bool {
    path.split("||")
        .map(str::trim)
        .any(|branch| branch == leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_registry_verification::trust_check_element::{TrqpQueryParams, TrqpQueryType};
    use serde_json::json;

    fn elem(entity: &str) -> TrustCheckElement {
        TrustCheckElement {
            id: "e".to_string(),
            trust_registry_id: "tr".to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams {
                authority_id: "did:literal:authority".to_string(),
                entity_id: entity.to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: None,
        }
    }

    fn wrap(agent: Value) -> Value {
        json!({ "input": { "agent": agent } })
    }

    // ── target leg ────────────────────────────────────────────

    #[test]
    fn target_leg_literal_element_does_not_gate() {
        let input = wrap(json!({}));
        let e = elem("did:literal:entity");
        assert!(element_needs_missing_tr_metadata(&e, TrustCheckLeg::Target, &input).is_none());
    }

    #[test]
    fn target_leg_did_reference_never_gates_even_when_did_is_absent() {
        // Target leg's allow-list does NOT include agent.did — a template
        // referencing input.agent.did on the target leg must fall through
        // to the executor (surface as TEMPLATE_RESOLUTION_FAILED there)
        // rather than being reinterpreted as a metadata failure.
        let input = wrap(json!({}));
        let e = elem("{{ input.agent.did }}");
        assert!(element_needs_missing_tr_metadata(&e, TrustCheckLeg::Target, &input).is_none());
    }

    #[test]
    fn target_leg_provider_did_reference_gates_when_missing() {
        let input = wrap(json!({ "did": "did:web:target", "trust_registry_did": "did:web:tr" }));
        let e = elem("{{ input.agent.provider_did }}");
        let f = element_needs_missing_tr_metadata(&e, TrustCheckLeg::Target, &input).expect("gates");
        assert_eq!(
            f,
            MissingTrMetadataFields {
                provider_did: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn target_leg_provider_did_present_does_not_gate() {
        let input = wrap(json!({ "provider_did": "did:web:p" }));
        let e = elem("{{ input.agent.provider_did }}");
        assert!(element_needs_missing_tr_metadata(&e, TrustCheckLeg::Target, &input).is_none());
    }

    #[test]
    fn target_leg_both_missing_and_referenced_sets_both_flags() {
        let input = wrap(json!({}));
        let mut e = elem("{{ input.agent.trust_registry_did }}");
        e.query.authority_id = "{{ input.agent.provider_did }}".to_string();
        let f = element_needs_missing_tr_metadata(&e, TrustCheckLeg::Target, &input).expect("gates");
        assert_eq!(
            f,
            MissingTrMetadataFields {
                provider_did: true,
                trust_registry_did: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn target_leg_fallback_that_resolves_does_not_gate() {
        // `did` populated, so `input.agent.did` branch of the chain
        // resolves and the marker succeeds — gate must not fire.
        let input = wrap(json!({ "did": "did:web:target" }));
        let e = elem("{{ input.agent.provider_did || input.agent.did }}");
        assert!(element_needs_missing_tr_metadata(&e, TrustCheckLeg::Target, &input).is_none());
    }

    #[test]
    fn target_leg_fallback_that_exhausts_gates_only_leaves_in_the_chain() {
        // Both branches fail. `did` is NOT on the target leg's
        // allow-list, so its exhaust must not attribute a `did` flag —
        // only `provider_did` gets flagged.
        let input = wrap(json!({}));
        let e = elem("{{ input.agent.provider_did || input.agent.did }}");
        let f = element_needs_missing_tr_metadata(&e, TrustCheckLeg::Target, &input).expect("gates");
        assert_eq!(
            f,
            MissingTrMetadataFields {
                provider_did: true,
                ..Default::default()
            }
        );
    }

    // ── caller leg ────────────────────────────────────────────

    #[test]
    fn caller_leg_did_reference_gates_when_missing() {
        let input = wrap(json!({}));
        let e = elem("{{ input.agent.did }}");
        let f = element_needs_missing_tr_metadata(&e, TrustCheckLeg::Caller, &input).expect("gates");
        assert_eq!(
            f,
            MissingTrMetadataFields {
                did: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn caller_leg_did_present_does_not_gate() {
        let input = wrap(json!({ "did": "did:web:caller" }));
        let e = elem("{{ input.agent.did }}");
        assert!(element_needs_missing_tr_metadata(&e, TrustCheckLeg::Caller, &input).is_none());
    }

    #[test]
    fn caller_leg_authority_did_reference_gates_when_missing() {
        let input = wrap(json!({ "did": "did:web:caller" }));
        let e = elem("{{ input.agent.authority_did }}");
        let f = element_needs_missing_tr_metadata(&e, TrustCheckLeg::Caller, &input).expect("gates");
        assert_eq!(
            f,
            MissingTrMetadataFields {
                authority_did: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn caller_leg_all_four_missing_and_referenced_sets_all_flags() {
        let input = wrap(json!({}));
        let mut e = elem("{{ input.agent.provider_did }}");
        e.query.authority_id = "{{ input.agent.authority_did }}".to_string();
        e.query.action = Some("{{ input.agent.did }}".to_string());
        e.query.resource = Some("{{ input.agent.trust_registry_did }}".to_string());
        let f = element_needs_missing_tr_metadata(&e, TrustCheckLeg::Caller, &input).expect("gates");
        assert_eq!(
            f,
            MissingTrMetadataFields {
                did: true,
                provider_did: true,
                trust_registry_did: true,
                authority_did: true,
            }
        );
    }

    #[test]
    fn caller_leg_ignores_non_metadata_paths() {
        let input = wrap(json!({}));
        // References `input.mcp.method`, not an agent-metadata path —
        // the gate has nothing to say about it; the executor will
        // resolve it (or fail with TEMPLATE_RESOLUTION_FAILED there).
        let e = elem("{{ input.mcp.method }}");
        assert!(element_needs_missing_tr_metadata(&e, TrustCheckLeg::Caller, &input).is_none());
    }

    // ── message wording ───────────────────────────────────────

    #[test]
    fn target_leg_message_names_missing_fields() {
        assert_eq!(
            build_missing_metadata_message(
                TrustCheckLeg::Target,
                &MissingTrMetadataFields {
                    provider_did: true,
                    ..Default::default()
                }
            ),
            "target agent card does not populate provider_did in its trust registry metadata"
        );
        assert_eq!(
            build_missing_metadata_message(
                TrustCheckLeg::Target,
                &MissingTrMetadataFields {
                    trust_registry_did: true,
                    ..Default::default()
                }
            ),
            "target agent card does not populate trust_registry_did in its trust registry metadata"
        );
        assert_eq!(
            build_missing_metadata_message(
                TrustCheckLeg::Target,
                &MissingTrMetadataFields {
                    provider_did: true,
                    trust_registry_did: true,
                    ..Default::default()
                }
            ),
            "target agent card does not populate provider_did or trust_registry_did in its trust registry metadata"
        );
    }

    #[test]
    fn caller_leg_message_names_only_tr_fields() {
        assert_eq!(
            build_missing_metadata_message(
                TrustCheckLeg::Caller,
                &MissingTrMetadataFields {
                    provider_did: true,
                    ..Default::default()
                }
            ),
            "caller's request payload does not populate provider_did in its trust registry metadata extension"
        );
        assert_eq!(
            build_missing_metadata_message(
                TrustCheckLeg::Caller,
                &MissingTrMetadataFields {
                    authority_did: true,
                    ..Default::default()
                }
            ),
            "caller's request payload does not populate authority_did in its trust registry metadata extension"
        );
        assert_eq!(
            build_missing_metadata_message(
                TrustCheckLeg::Caller,
                &MissingTrMetadataFields {
                    provider_did: true,
                    trust_registry_did: true,
                    authority_did: true,
                    ..Default::default()
                }
            ),
            "caller's request payload does not populate provider_did, trust_registry_did or authority_did in its trust registry metadata extension"
        );
    }

    #[test]
    fn caller_leg_message_only_did_missing() {
        assert_eq!(
            build_missing_metadata_message(
                TrustCheckLeg::Caller,
                &MissingTrMetadataFields {
                    did: true,
                    ..Default::default()
                }
            ),
            "caller's request payload does not carry an agent identity credential"
        );
    }

    #[test]
    fn caller_leg_message_combines_did_and_tr_fields() {
        assert_eq!(
            build_missing_metadata_message(
                TrustCheckLeg::Caller,
                &MissingTrMetadataFields {
                    did: true,
                    provider_did: true,
                    ..Default::default()
                }
            ),
            "caller's request payload does not carry an agent identity credential and does not populate provider_did in its trust registry metadata extension"
        );
    }

    // ── partition helper ──────────────────────────────────────

    #[test]
    fn partition_synthesizes_gated_and_leaves_runnable_intact() {
        let input = wrap(json!({}));
        // e1 gates (references provider_did on missing agent).
        let e1 = elem("{{ input.agent.provider_did }}");
        // e2 doesn't gate (literal only).
        let e2 = elem("did:literal:entity");
        // e3 gates (references authority_did on caller leg).
        let e3 = elem("{{ input.agent.authority_did }}");
        let (syn, runnable) = synthesize_metadata_gate_failures(
            "surf",
            TrustCheckLeg::Caller,
            &[e1.clone(), e2.clone(), e3.clone()],
            &input,
        );
        assert_eq!(syn.len(), 3, "synthesized parallel to elements");
        assert!(syn[0].is_some(), "e1 synthesized");
        assert!(syn[1].is_none(), "e2 runnable");
        assert!(syn[2].is_some(), "e3 synthesized");
        assert_eq!(runnable.len(), 1);
        assert_eq!(runnable[0].id, e2.id);

        let r1 = syn[0].as_ref().unwrap();
        assert!(!r1.ok);
        let err = r1
            .error
            .as_ref()
            .expect("error present");
        assert_eq!(err.code, TRUST_REGISTRY_METADATA_UNAVAILABLE);
        assert!(
            err.message
                .contains("provider_did")
        );
        assert!(r1.authority_id.is_none(), "authority_id omitted per contract");
        assert!(r1.entity_id.is_none(), "entity_id omitted per contract");
    }

    #[test]
    fn partition_all_runnable_when_agent_context_is_complete() {
        let input = wrap(json!({
            "did": "did:web:caller",
            "provider_did": "did:web:p",
            "trust_registry_did": "did:web:tr",
            "authority_did": "did:web:a",
        }));
        let e = elem("{{ input.agent.provider_did }}");
        let (syn, runnable) = synthesize_metadata_gate_failures("surf", TrustCheckLeg::Caller, &[e], &input);
        assert!(
            syn.iter()
                .all(Option::is_none)
        );
        assert_eq!(runnable.len(), 1);
    }
}
