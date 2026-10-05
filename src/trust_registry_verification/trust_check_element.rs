//! Trust Check element — per-leg, per-trust-registry verification declared on
//! an Agent Surface and evaluated against a TRQP endpoint at request time.
//!
//! Persisted on `AccessPoint.trust_check_list` (caller leg, AP→MA) and
//! `Target.trust_check_list` (target leg, MA→TP). Runtime evaluation,
//! observability, and OPA wiring land in subsequent MRs; this module owns the
//! configuration shape and the runtime result shape only.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Structured error surfaced by a Trust Check probe (per-element).
///
/// `code` is machine-readable and used both by OPA (via
/// `input.trust_check_results.<leg>[_].error.code`) and by Prometheus
/// `result` labelling. `message` carries a human-readable description
/// for audit / logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCheckError {
    /// Machine-readable error code
    pub code: String,
    /// Human-readable error message
    pub message: String,
}

/// Per-element `name` cap: max code points (chars), not bytes.
pub const TRUST_CHECK_NAME_MAX_CODE_POINTS: usize = 64;

/// Per-element `id` cap: max code points (chars), not bytes. Kept separate
/// from `TRUST_CHECK_NAME_MAX_CODE_POINTS` because the two fields serve
/// different roles — `id` is Rego-addressable and audit-visible; `name` is
/// a free display label — even though today both caps are the same value.
pub const TRUST_CHECK_ID_MAX_CODE_POINTS: usize = 64;

/// TRQP query family supported in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrqpQueryType {
    /// "Is `entity_id` authorised by `authority_id` to perform `action`
    /// on `resource`?" — requires `action` and `resource` on the query;
    /// sent verbatim on the wire.
    Authorization,
    /// "Does `authority_id` recognise `entity_id`?" — `action` and
    /// `resource` are optional on the element. When absent or blank,
    /// the wire adapter defaults them to `"is"` / `"ownedAgent"` so
    /// 4-tuple-indexed registries still match the recognition record.
    /// A future custom-query mode will let the dashboard set these
    /// explicitly per element.
    Recognition,
}

/// TRQP query parameters. All values are template strings resolved against
/// the request context before dispatch; resolution rules land with the
/// executor in MR-2.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrqpQueryParams {
    /// Authority DID (or template) the query is asked against.
    #[serde(default)]
    pub authority_id: String,

    /// Entity DID (or template). Blank inherits the placement-derived
    /// subject DID at execution time.
    #[serde(default)]
    pub entity_id: String,

    /// Required for `query_type = authorization`; optional for
    /// `query_type = recognition` (the wire adapter defaults to `"is"`
    /// when absent or blank — see `TrqpQueryType::Recognition`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// Required for `query_type = authorization`; optional for
    /// `query_type = recognition` (the wire adapter defaults to
    /// `"ownedAgent"` when absent or blank — see
    /// `TrqpQueryType::Recognition`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// Trust Check configuration element. One per `(trust_registry, query_type)`
/// pair on a leg; duplicates are permitted (an OPA rule iterates with
/// `some r in input.trust_check_results.<leg>`).
///
/// `deny_unknown_fields` is deliberately **not** set: stored surfaces may
/// carry the legacy `phase` field from when the caller leg had two seams
/// (`pre_identity` / `post_identity`). The collapse to a single
/// post-identity caller seam drops the field from the struct; serde simply
/// ignores it on load, so existing on-disk configs keep deserialising
/// without a migration step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCheckElement {
    /// Surface-unique element id. Required on the wire so a Rego rule can
    /// match a specific result on `input.trust_check_results.{caller|target}[]`
    /// (by id, not array index — element order is stored config). The dashboard
    /// generates this as a UUID at element creation and hides the field;
    /// operators editing the surface JSON directly may use any string.
    pub id: String,

    /// Foreign key into the trust-registries store.
    pub trust_registry_id: String,

    pub query_type: TrqpQueryType,

    pub query: TrqpQueryParams,

    /// Optional per-element override of the TRQP request timeout.
    /// `None` (the default — the dashboard never emits this field) defers
    /// to the [`TrustRegistryListenerManager`] default timeout, which is
    /// the only timeout knob the trust-registry transport itself exposes.
    /// Operators editing the surface JSON directly may set a value to
    /// tighten the bound for a specific element; `Some(n)` wraps the TRQP
    /// call in `tokio::time::timeout(Duration::from_secs(n), …)` on top of
    /// the transport's own timeout.
    ///
    /// [`TrustRegistryListenerManager`]: crate::trust_registries::communication::TrustRegistryListenerManager
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,

    /// Operator-visible label, optional, free UTF-8 text. Max
    /// [`TRUST_CHECK_NAME_MAX_CODE_POINTS`] code points; control / DEL /
    /// C1 / bidi-override codepoints are rejected by [`Self::validate`].
    /// Display-only — Rego must address results by `id`, not `name`.
    /// Mirrored onto [`TrustCheckResult::name`] by the executor at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Element-level validation errors raised by [`TrustCheckElement::validate`].
/// List-level errors (duplicate `id`, list too long) live on
/// [`crate::config::agent_surface::TrustCheckValidationError`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TrustCheckElementValidationError {
    #[error("id must not be blank")]
    IdBlank,
    #[error("id exceeds {max} code points (got {got})")]
    IdTooLong { got: usize, max: usize },
    #[error("id contains control or bidi-override codepoints")]
    IdForbiddenChars,
    #[error("query.authority_id must not be blank")]
    AuthorityBlank,
    #[error("name exceeds {max} code points (got {got})")]
    NameTooLong { got: usize, max: usize },
    #[error("name contains control or bidi-override codepoints")]
    NameForbiddenChars,
}

impl TrustCheckElement {
    /// Validate the per-element invariants documented on the field comments.
    /// Called by the list-level walker on every PUT / PATCH and on hot
    /// reload from disk; the executor does not re-validate at request time.
    pub fn validate(&self) -> Result<(), TrustCheckElementValidationError> {
        if self.id.trim().is_empty() {
            return Err(TrustCheckElementValidationError::IdBlank);
        }
        let id_count = self.id.chars().count();
        if id_count > TRUST_CHECK_ID_MAX_CODE_POINTS {
            return Err(TrustCheckElementValidationError::IdTooLong {
                got: id_count,
                max: TRUST_CHECK_ID_MAX_CODE_POINTS,
            });
        }
        if self
            .id
            .chars()
            .any(is_forbidden_name_char)
        {
            return Err(TrustCheckElementValidationError::IdForbiddenChars);
        }
        if self
            .query
            .authority_id
            .trim()
            .is_empty()
        {
            return Err(TrustCheckElementValidationError::AuthorityBlank);
        }
        if let Some(name) = &self.name {
            let count = name.chars().count();
            if count > TRUST_CHECK_NAME_MAX_CODE_POINTS {
                return Err(TrustCheckElementValidationError::NameTooLong {
                    got: count,
                    max: TRUST_CHECK_NAME_MAX_CODE_POINTS,
                });
            }
            if name
                .chars()
                .any(is_forbidden_name_char)
            {
                return Err(TrustCheckElementValidationError::NameForbiddenChars);
            }
        }
        Ok(())
    }
}

/// True for codepoints disallowed in a `TrustCheckElement.name`: every
/// Unicode control character (C0 `U+0000–U+001F`, DEL `U+007F`, C1
/// `U+0080–U+009F`) plus the bidi-override range (`U+202A–U+202E`,
/// `U+2066–U+2069`) which is not classified as control but can rewrite
/// the visual order of an operator-facing label.
fn is_forbidden_name_char(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Runtime result for a single Trust Check element, serialised into
/// `PolicyInput.trust_check_results` for OPA consumption.
/// `ok = false` with `error.code = NOT_RECOGNIZED` / `NOT_AUTHORIZED`
/// is a clean negative TRQP response (the registry answered "no");
/// `ok = false` with any other `error.code` is a stage failure (timeout,
/// transport, template resolution, problem-report, parse error, etc.).
///
/// The `authority_id` / `entity_id` / `action` / `resource` fields carry
/// the **evaluated** TRQP query as it was actually sent to the registry
/// (or would have been, on a pre-dispatch failure). `action` / `resource`
/// are always populated — for recognition queries with no operator-set
/// value the wire defaults (`"is"` / `"ownedAgent"`, see
/// [`crate::trust_registry_verification::trqp_adapter::RECOGNITION_DEFAULT_ACTION`])
/// are filled in so Rego rules see the same tuple the registry saw.
/// `query_resolved = true` means every template placeholder in the
/// source element resolved; `false` means the executor fell back to the
/// raw template strings because resolution failed
/// (`TEMPLATE_RESOLUTION_FAILED`) or the target's agent card was
/// unavailable (`AGENT_CARD_UNAVAILABLE`).
///
/// `authority_id` / `entity_id` are `Option<String>` because the two
/// "unavailable" codes emitted by the outbound target-leg pre-check
/// (`AGENT_CARD_UNAVAILABLE`, `TRUST_REGISTRY_METADATA_UNAVAILABLE`)
/// carry no meaningful value for these fields — the pipeline never got
/// as far as resolving them and the raw template strings would be noise,
/// not signal. Every other path (success, clean deny, transport / parse
/// / timeout / problem-report failures, and `TEMPLATE_RESOLUTION_FAILED`)
/// keeps setting them to `Some(...)` with either the resolved value or
/// the raw template string. Serialized with
/// `#[serde(skip_serializing_if = "Option::is_none")]`, so the wire
/// simply omits the fields on the two "unavailable" paths.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrustCheckResult {
    /// Mirrors [`TrustCheckElement::id`] so a Rego rule can address a
    /// specific result via `input.trust_check_results.{caller|target}[]`
    /// without depending on array index (element order is stored config,
    /// not a stable contract). Always present on the wire.
    pub id: String,
    pub trust_registry_id: String,
    pub query_type: TrqpQueryType,
    pub ok: bool,
    pub error: Option<TrustCheckError>,
    /// Mirrors [`TrustCheckElement::name`] from the element that produced
    /// this result. Display-only — Rego addresses by `id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Evaluated TRQP authority as it was actually sent (or would have
    /// been sent, on a pre-dispatch failure). `Some(post-substitution)`
    /// when `query_resolved = true`; `Some(raw template)` on
    /// `TEMPLATE_RESOLUTION_FAILED`; `None` on `AGENT_CARD_UNAVAILABLE`
    /// / `TRUST_REGISTRY_METADATA_UNAVAILABLE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,

    /// Evaluated TRQP entity; same resolution semantics as
    /// `authority_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,

    /// Evaluated TRQP action, always present. Post template substitution
    /// when `query_resolved = true`; raw template string when
    /// `query_resolved = false`. Recognition queries with no
    /// operator-set value are filled with the wire default (`"is"`).
    pub action: String,

    /// Evaluated TRQP resource, always present. Same semantics as
    /// `action`; recognition default is `"ownedAgent"`.
    pub resource: String,

    /// `true` when every template placeholder resolved. `false` when
    /// the executor fell back to the raw template strings because
    /// resolution failed (`TEMPLATE_RESOLUTION_FAILED`) or the target's
    /// agent card / TR metadata extension was unavailable
    /// (`AGENT_CARD_UNAVAILABLE` / `TRUST_REGISTRY_METADATA_UNAVAILABLE`).
    pub query_resolved: bool,
}

/// `input.trust_check_results` block as seen by OPA: per-leg result lists,
/// each preserving the configured order from the matching `trust_check_list`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TrustCheckResultsContext {
    pub caller: Vec<TrustCheckResult>,
    pub target: Vec<TrustCheckResult>,
}

/// Placement-derived leg label. Threaded from the runtime call site to the
/// audit/observability layer; never persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustCheckLeg {
    /// `AccessPoint.trust_check_list` — caller-side verification.
    Caller,
    /// `Target.trust_check_list` — target-side verification.
    Target,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_query(authority: &str) -> TrqpQueryParams {
        TrqpQueryParams {
            authority_id: authority.to_string(),
            entity_id: "{{input.caller.did}}".to_string(),
            action: None,
            resource: None,
        }
    }

    fn elem_with_name(
        id: &str,
        name: Option<&str>,
    ) -> TrustCheckElement {
        TrustCheckElement {
            id: id.to_string(),
            trust_registry_id: "tr-x".to_string(),
            query_type: TrqpQueryType::Recognition,
            query: base_query("did:a"),
            timeout_secs: None,
            name: name.map(str::to_string),
        }
    }

    #[test]
    fn element_round_trips_with_authorization_query() {
        let elem = TrustCheckElement {
            id: "tc-1".to_string(),
            trust_registry_id: "tr-a".to_string(),
            query_type: TrqpQueryType::Authorization,
            query: TrqpQueryParams {
                authority_id: "{{input.caller.gateway.did}}".to_string(),
                entity_id: "{{input.caller.did}}".to_string(),
                action: Some("invoke".to_string()),
                resource: Some("{{input.http.path}}".to_string()),
            },
            timeout_secs: Some(5),
            name: None,
        };
        let json = serde_json::to_value(&elem).unwrap();
        assert_eq!(json["query_type"], "authorization");
        assert_eq!(json["query"]["action"], "invoke");
        let back: TrustCheckElement = serde_json::from_value(json).unwrap();
        assert_eq!(back, elem);
    }

    #[test]
    fn recognition_query_omits_action_and_resource_on_wire() {
        let elem = TrustCheckElement {
            id: "tc-2".to_string(),
            trust_registry_id: "tr-b".to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams {
                authority_id: "{{input.target.gateway.did}}".to_string(),
                entity_id: "{{input.target.did}}".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: None,
        };
        let json = serde_json::to_value(&elem).unwrap();
        assert!(
            json["query"]
                .get("action")
                .is_none()
        );
        assert!(
            json["query"]
                .get("resource")
                .is_none()
        );
        let back: TrustCheckElement = serde_json::from_value(json).unwrap();
        assert_eq!(back, elem);
    }

    #[test]
    fn timeout_defaults_to_none_when_absent() {
        let v = json!({
            "id": "tc-3",
            "trust_registry_id": "tr-c",
            "query_type": "recognition",
            "query": { "authority_id": "did:a", "entity_id": "did:e" }
        });
        let elem: TrustCheckElement = serde_json::from_value(v).unwrap();
        assert_eq!(elem.timeout_secs, None);
    }

    #[test]
    fn timeout_round_trips_as_some_when_set() {
        let v = json!({
            "id": "tc-3b",
            "trust_registry_id": "tr-c",
            "query_type": "recognition",
            "query": { "authority_id": "did:a", "entity_id": "did:e" },
            "timeout_secs": 7
        });
        let elem: TrustCheckElement = serde_json::from_value(v).unwrap();
        assert_eq!(elem.timeout_secs, Some(7));
        let back = serde_json::to_value(&elem).unwrap();
        assert_eq!(back["timeout_secs"], 7);
    }

    #[test]
    fn timeout_omitted_from_wire_when_none() {
        let elem = TrustCheckElement {
            id: "tc-3c".to_string(),
            trust_registry_id: "tr-c".to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams {
                authority_id: "did:a".to_string(),
                entity_id: "did:e".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: None,
        };
        let v = serde_json::to_value(&elem).unwrap();
        assert!(
            v.get("timeout_secs")
                .is_none(),
            "None must be omitted on the wire so the TR transport default applies"
        );
    }

    #[test]
    fn unknown_query_type_is_rejected() {
        let v = json!({
            "id": "tc-4",
            "trust_registry_id": "tr-c",
            "query_type": "delegation",
            "query": { "authority_id": "did:a", "entity_id": "did:e" }
        });
        assert!(serde_json::from_value::<TrustCheckElement>(v).is_err());
    }

    #[test]
    fn legacy_phase_field_is_ignored_on_load() {
        let v = json!({
            "id": "tc-5",
            "trust_registry_id": "tr-c",
            "query_type": "recognition",
            "query": { "authority_id": "did:a", "entity_id": "did:e" },
            "phase": "pre_identity"
        });
        let elem: TrustCheckElement =
            serde_json::from_value(v).expect("stored configs may carry a legacy `phase` field");
        assert_eq!(elem.id, "tc-5");
        let back = serde_json::to_value(&elem).unwrap();
        assert!(back.get("phase").is_none(), "re-serialised element must not echo the legacy phase field");
    }

    #[test]
    fn results_context_serializes_both_legs_even_when_empty() {
        let ctx = TrustCheckResultsContext::default();
        let v = serde_json::to_value(&ctx).unwrap();
        assert_eq!(v, json!({ "caller": [], "target": [] }));
    }

    #[test]
    fn result_with_clean_denial_keeps_error_null() {
        let r = TrustCheckResult {
            id: "tc-r1".to_string(),
            trust_registry_id: "tr-a".to_string(),
            query_type: TrqpQueryType::Authorization,
            ok: false,
            error: None,
            name: None,
            authority_id: Some("did:example:auth".to_string()),
            entity_id: Some("did:example:agent".to_string()),
            action: "invoke".to_string(),
            resource: "tool:x".to_string(),
            query_resolved: true,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], serde_json::Value::Null);
        assert_eq!(v["id"], "tc-r1");
        assert!(v.get("name").is_none(), "None name must be omitted on the wire");
        assert_eq!(v["authority_id"], "did:example:auth");
        assert_eq!(v["entity_id"], "did:example:agent");
        assert_eq!(v["action"], "invoke");
        assert_eq!(v["resource"], "tool:x");
        assert_eq!(v["query_resolved"], true);
    }

    #[test]
    fn result_always_serialises_action_and_resource() {
        // A recognition result whose element omits action/resource is
        // still serialised with both fields — the wire defaults
        // (`"is"` / `"ownedAgent"`) are filled in by the executor before
        // constructing the result, so Rego rules see the same tuple the
        // registry saw.
        let r = TrustCheckResult {
            id: "tc-r2".to_string(),
            trust_registry_id: "tr-a".to_string(),
            query_type: TrqpQueryType::Recognition,
            ok: true,
            error: None,
            name: Some("primary registry".to_string()),
            authority_id: Some("did:example:auth".to_string()),
            entity_id: Some("did:example:agent".to_string()),
            action: "is".to_string(),
            resource: "ownedAgent".to_string(),
            query_resolved: true,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["id"], "tc-r2");
        assert_eq!(v["name"], "primary registry");
        assert_eq!(v["action"], "is", "action must always be present on the wire");
        assert_eq!(v["resource"], "ownedAgent", "resource must always be present on the wire");
        assert_eq!(v["query_resolved"], true);
    }

    #[test]
    fn serde_default_name_omits_field_on_wire() {
        let elem = elem_with_name("tc-n0", None);
        let v = serde_json::to_value(&elem).unwrap();
        assert!(v.get("name").is_none(), "None must be omitted on the wire so the dashboard never sees a stray field");
    }

    #[test]
    fn serde_round_trips_name() {
        let elem = elem_with_name("tc-n1", Some("internal registry"));
        let v = serde_json::to_value(&elem).unwrap();
        assert_eq!(v["name"], "internal registry");
        let back: TrustCheckElement = serde_json::from_value(v).unwrap();
        assert_eq!(back, elem);
    }

    #[test]
    fn validate_accepts_minimal_element() {
        let elem = elem_with_name("tc-ok", None);
        assert_eq!(elem.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_blank_authority() {
        let mut elem = elem_with_name("tc-bad", None);
        elem.query.authority_id = "   ".to_string();
        assert_eq!(elem.validate(), Err(TrustCheckElementValidationError::AuthorityBlank));
    }

    #[test]
    fn validate_rejects_empty_id() {
        let elem = elem_with_name("", None);
        assert_eq!(elem.validate(), Err(TrustCheckElementValidationError::IdBlank));
    }

    #[test]
    fn validate_rejects_whitespace_only_id() {
        let elem = elem_with_name("   ", None);
        assert_eq!(elem.validate(), Err(TrustCheckElementValidationError::IdBlank));
    }

    #[test]
    fn validate_accepts_64_codepoint_id() {
        let elem = elem_with_name(&"a".repeat(64), None);
        assert_eq!(elem.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_id_over_64_codepoints() {
        let elem = elem_with_name(&"a".repeat(65), None);
        assert_eq!(
            elem.validate(),
            Err(TrustCheckElementValidationError::IdTooLong {
                got: 65,
                max: TRUST_CHECK_ID_MAX_CODE_POINTS,
            })
        );
    }

    #[test]
    fn validate_rejects_id_with_c0_control() {
        let elem = elem_with_name("tc\u{0007}id", None);
        assert_eq!(elem.validate(), Err(TrustCheckElementValidationError::IdForbiddenChars));
    }

    #[test]
    fn validate_rejects_id_with_bidi_override() {
        let elem = elem_with_name("tc\u{202E}id", None);
        assert_eq!(elem.validate(), Err(TrustCheckElementValidationError::IdForbiddenChars));
    }

    #[test]
    fn validate_accepts_64_codepoint_emoji_name() {
        let elem = elem_with_name("tc-emoji", Some(&"\u{1F642}".repeat(64)));
        assert_eq!(elem.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_name_over_64_codepoints() {
        let elem = elem_with_name("tc-long", Some(&"\u{1F642}".repeat(65)));
        assert_eq!(
            elem.validate(),
            Err(TrustCheckElementValidationError::NameTooLong {
                got: 65,
                max: TRUST_CHECK_NAME_MAX_CODE_POINTS,
            })
        );
    }

    #[test]
    fn validate_rejects_name_with_c0_control() {
        let elem = elem_with_name("tc-ctrl", Some("\u{0007}foo"));
        assert_eq!(elem.validate(), Err(TrustCheckElementValidationError::NameForbiddenChars));
    }

    #[test]
    fn validate_rejects_name_with_bidi_override() {
        let elem = elem_with_name("tc-bidi", Some("foo\u{202E}bar"));
        assert_eq!(elem.validate(), Err(TrustCheckElementValidationError::NameForbiddenChars));
    }
}
