//! Predefined Trust Check TRQP queries — the Affinidi-shipped catalogue
//! surfaced to the dashboard's Trust Check editor as selectable
//! "Query Template" presets.
//!
//! The catalogue data lives in the sibling `trust_check_query_presets.json`
//! file, embedded at compile time via `include_str!`. The tuples for
//! `agent-policy-q1|q2|q3` are cross-checked at startup against the
//! `pub const` templates below (see [`validate_catalogue`]) so the shipped
//! JSON cannot silently drift from the constants this module exposes to
//! the wider crate. Any mismatch fails validation and panics the process
//! at boot.

use std::collections::HashSet;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::trust_check_element::{TrqpQueryParams, TrqpQueryType};

// ---------------------------------------------------------------------------
// Shared TRQP templates and literals
//
// These mirror the tuples `agent_context.rs::perform_trust_verification`
// sends at runtime. That verifier is on the retirement path (its queries
// will move behind Trust Check elements), so it deliberately keeps its own
// inline literals rather than importing from here — the constants below
// exist for the catalogue's own drift-check and for the served HTTP
// response. Keep the two in sync by review discipline until the retirement
// slice lands.
// ---------------------------------------------------------------------------

/// TRQP `authority_id` template for the higher-Authority queries (Q2, Q3).
pub const AGENT_POLICY_AUTHORITY_TEMPLATE: &str = "{{ input.agent.authority_did }}";

/// TRQP template for the Provider (issuer) DID — `authority_id` on Q1,
/// `entity_id` on Q2/Q3.
pub const AGENT_POLICY_PROVIDER_TEMPLATE: &str = "{{ input.agent.provider_did }}";

/// TRQP template for the effective caller agent DID — `entity_id` on Q1.
pub const AGENT_POLICY_AGENT_TEMPLATE: &str = "{{ input.agent.did }}";

// ---------------------------------------------------------------------------
// Per-Q ids and literal action/resource values
// ---------------------------------------------------------------------------

pub const AGENT_POLICY_Q1_ID: &str = "agent-policy-q1";
pub const AGENT_POLICY_Q2_ID: &str = "agent-policy-q2";
pub const AGENT_POLICY_Q3_ID: &str = "agent-policy-q3";

pub const AGENT_POLICY_Q1_ACTION: &str = "is";
pub const AGENT_POLICY_Q1_RESOURCE: &str = "ownedAgent";
pub const AGENT_POLICY_Q2_ACTION: &str = "register";
pub const AGENT_POLICY_Q2_RESOURCE: &str = "agents";
pub const AGENT_POLICY_Q3_ACTION: &str = "is";
/// Legacy wire value — the shipped preset JSON hard-codes this string so operators
/// using the built-in preset continue to hit registries indexed against the pre-rename
/// resource. The gateway's runtime issuer-TR-registration + Q3 dispatch reads the
/// active value from `TrustRegistryRuntimeConfig::q3_resource_name`
/// (default `"registeredDepartment"`), so a per-gateway flip to `"registeredIssuer"`
/// does not have to touch this const or the preset JSON.
pub const AGENT_POLICY_Q3_RESOURCE: &str = "registeredDepartment";

/// Sanity cap on catalogue size — a catalogue with hundreds of entries is
/// a bug in the shipped JSON, not a feature.
pub const CATALOGUE_MAX_ENTRIES: usize = 32;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Provenance of a predefined query. v1 ships `Builtin` only; `Operator` is
/// reserved for a future runtime store of user-defined presets so the wire
/// shape doesn't have to change when that lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PredefinedQueryOrigin {
    Builtin,
    #[allow(dead_code)]
    Operator,
}

/// A single predefined Trust Check TRQP query surfaced to the dashboard.
/// Materialised into a `TrustCheckElement.query` tuple verbatim when the
/// operator selects it from the "Query Template" dropdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredefinedTrustCheckQuery {
    pub id: String,
    pub name: String,
    pub description: String,
    pub query_type: TrqpQueryType,
    pub query: TrqpQueryParams,
    pub origin: PredefinedQueryOrigin,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CatalogueValidationError {
    #[error("catalogue is empty")]
    Empty,
    #[error("catalogue exceeds sanity cap of {max} entries (got {got})")]
    TooLarge { got: usize, max: usize },
    #[error("entry {index} has blank {field}")]
    BlankField { index: usize, field: &'static str },
    #[error("entry {index} has invalid id '{id}' (must match /^[a-z0-9][a-z0-9-]{{0,63}}$/)")]
    InvalidIdSlug { index: usize, id: String },
    #[error("duplicate id '{id}' at entry {index}")]
    DuplicateId { index: usize, id: String },
    #[error("entry {index} ('{id}') has origin={origin:?} but only Builtin is allowed in the compile-time catalogue")]
    NonBuiltinOrigin { index: usize, id: String, origin: PredefinedQueryOrigin },
    #[error("entry {index} ('{id}') query failed TR-parity validation: {reason}")]
    QueryValidationFailed { index: usize, id: String, reason: String },
    #[error("entry '{id}' drifted from shared pub const templates: expected {expected}, got {actual}")]
    DriftFromConsts { id: String, expected: String, actual: String },
}

// ---------------------------------------------------------------------------
// Catalogue accessor
// ---------------------------------------------------------------------------

static CATALOGUE: OnceLock<Vec<PredefinedTrustCheckQuery>> = OnceLock::new();

/// Return the compile-time catalogue of Affinidi-shipped predefined Trust
/// Check queries. First call parses the embedded JSON, cross-checks against
/// the shared `pub const` templates, and caches the result. Subsequent calls
/// are lock-free `OnceLock` reads.
///
/// Panics at boot on: malformed JSON, empty catalogue, blank fields,
/// duplicate ids, non-Builtin origin, TR-parity failure, or drift from the
/// shared consts. `main.rs` primes this at startup so a bad edit fails the
/// process immediately rather than on the first HTTP hit.
pub fn builtin_catalogue() -> &'static [PredefinedTrustCheckQuery] {
    CATALOGUE.get_or_init(|| {
        let raw = include_str!("trust_check_query_presets.json");
        let parsed: Vec<PredefinedTrustCheckQuery> =
            serde_json::from_str(raw).expect("predefined queries JSON invalid — compile-time data error");
        validate_catalogue(&parsed).expect("predefined queries failed startup validation");
        parsed
    })
}

/// Full validator run on a parsed catalogue. Extracted so unit tests can
/// exercise drift/error paths without going through the panicking
/// `builtin_catalogue()` accessor.
///
/// Checks, in order:
/// 1. Non-empty; length ≤ [`CATALOGUE_MAX_ENTRIES`].
/// 2. Every entry has a non-blank `id`, `name`, `description`.
/// 3. Every `id` matches `^[a-z0-9][a-z0-9-]{0,63}$` and is unique.
/// 4. Every `origin == Builtin`.
/// 5. Every `query` passes the shared TR-parity shape validator.
/// 6. For `id ∈ {agent-policy-q1|q2|q3}`: tuple equals the shared
///    [`AGENT_POLICY_*`] constants.
pub fn validate_catalogue(catalogue: &[PredefinedTrustCheckQuery]) -> Result<(), CatalogueValidationError> {
    if catalogue.is_empty() {
        return Err(CatalogueValidationError::Empty);
    }
    if catalogue.len() > CATALOGUE_MAX_ENTRIES {
        return Err(CatalogueValidationError::TooLarge {
            got: catalogue.len(),
            max: CATALOGUE_MAX_ENTRIES,
        });
    }

    let mut seen_ids: HashSet<&str> = HashSet::new();

    for (index, entry) in catalogue.iter().enumerate() {
        if entry.id.trim().is_empty() {
            return Err(CatalogueValidationError::BlankField { index, field: "id" });
        }
        if !is_valid_id(&entry.id) {
            return Err(CatalogueValidationError::InvalidIdSlug { index, id: entry.id.clone() });
        }
        if !seen_ids.insert(entry.id.as_str()) {
            return Err(CatalogueValidationError::DuplicateId { index, id: entry.id.clone() });
        }
        if entry.name.trim().is_empty() {
            return Err(CatalogueValidationError::BlankField { index, field: "name" });
        }
        if entry
            .description
            .trim()
            .is_empty()
        {
            return Err(CatalogueValidationError::BlankField { index, field: "description" });
        }
        if !matches!(entry.origin, PredefinedQueryOrigin::Builtin) {
            return Err(CatalogueValidationError::NonBuiltinOrigin {
                index,
                id: entry.id.clone(),
                origin: entry.origin,
            });
        }
        validate_query_shape(&entry.query, entry.query_type).map_err(|reason| {
            CatalogueValidationError::QueryValidationFailed {
                index,
                id: entry.id.clone(),
                reason,
            }
        })?;
        drift_check(entry)?;
    }

    Ok(())
}

/// TR-parity shape validator. Mirrors the rules a trust registry applies
/// when validating an inbound TRQP query, and matches what
/// [`crate::trust_registry_verification::trust_check_element::TrustCheckElement::validate`]
/// enforces on user-authored `TrustCheckElement.query` fields today.
fn validate_query_shape(
    query: &TrqpQueryParams,
    query_type: TrqpQueryType,
) -> Result<(), String> {
    if query
        .authority_id
        .trim()
        .is_empty()
    {
        return Err("authority_id must not be blank".to_string());
    }
    if query
        .entity_id
        .trim()
        .is_empty()
    {
        return Err("entity_id must not be blank".to_string());
    }
    if matches!(query_type, TrqpQueryType::Authorization) {
        let has_action = query
            .action
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !has_action {
            return Err("authorization queries require a non-blank action".to_string());
        }
        let has_resource = query
            .resource
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !has_resource {
            return Err("authorization queries require a non-blank resource".to_string());
        }
    }
    Ok(())
}

fn drift_check(entry: &PredefinedTrustCheckQuery) -> Result<(), CatalogueValidationError> {
    // Per-entry expected shape: (authority, entity, action, resource, query_type).
    // The three Agent Policy entries all share the same authority/entity
    // templates but differ in query_type (Q1 recognition; Q2 authorization
    // — the operator-facing "Provider authorised to register agents"
    // semantics require action+resource on the wire; Q3 recognition).
    let expected: Option<(&str, &str, &str, &str, TrqpQueryType)> = match entry.id.as_str() {
        AGENT_POLICY_Q1_ID => Some((
            AGENT_POLICY_PROVIDER_TEMPLATE,
            AGENT_POLICY_AGENT_TEMPLATE,
            AGENT_POLICY_Q1_ACTION,
            AGENT_POLICY_Q1_RESOURCE,
            TrqpQueryType::Recognition,
        )),
        AGENT_POLICY_Q2_ID => Some((
            AGENT_POLICY_AUTHORITY_TEMPLATE,
            AGENT_POLICY_PROVIDER_TEMPLATE,
            AGENT_POLICY_Q2_ACTION,
            AGENT_POLICY_Q2_RESOURCE,
            TrqpQueryType::Authorization,
        )),
        AGENT_POLICY_Q3_ID => Some((
            AGENT_POLICY_AUTHORITY_TEMPLATE,
            AGENT_POLICY_PROVIDER_TEMPLATE,
            AGENT_POLICY_Q3_ACTION,
            AGENT_POLICY_Q3_RESOURCE,
            TrqpQueryType::Recognition,
        )),
        _ => None,
    };

    let Some((auth, ent, act, res, expected_qt)) = expected else {
        return Ok(());
    };

    check_field(&entry.id, "authority_id", &entry.query.authority_id, auth)?;
    check_field(&entry.id, "entity_id", &entry.query.entity_id, ent)?;
    let got_action = entry
        .query
        .action
        .as_deref()
        .unwrap_or("");
    check_field(&entry.id, "action", got_action, act)?;
    let got_resource = entry
        .query
        .resource
        .as_deref()
        .unwrap_or("");
    check_field(&entry.id, "resource", got_resource, res)?;
    if entry.query_type != expected_qt {
        return Err(CatalogueValidationError::DriftFromConsts {
            id: entry.id.clone(),
            expected: format!("query_type: {:?}", expected_qt),
            actual: format!("query_type: {:?}", entry.query_type),
        });
    }
    Ok(())
}

fn check_field(
    id: &str,
    field: &str,
    actual: &str,
    expected: &str,
) -> Result<(), CatalogueValidationError> {
    if actual != expected {
        return Err(CatalogueValidationError::DriftFromConsts {
            id: id.to_string(),
            expected: format!("{}: {:?}", field, expected),
            actual: format!("{}: {:?}", field, actual),
        });
    }
    Ok(())
}

fn is_valid_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    let mut chars = id.chars();
    let first = chars
        .next()
        .expect("id is non-empty here");
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_parses_without_error() {
        let raw = include_str!("trust_check_query_presets.json");
        let _: Vec<PredefinedTrustCheckQuery> =
            serde_json::from_str(raw).expect("shipped trust_check_query_presets.json must parse");
    }

    #[test]
    fn catalogue_has_three_entries() {
        assert_eq!(builtin_catalogue().len(), 3);
    }

    #[test]
    fn every_entry_is_non_blank_and_builtin() {
        for (i, entry) in builtin_catalogue()
            .iter()
            .enumerate()
        {
            assert!(!entry.id.trim().is_empty(), "entry {i} id blank");
            assert!(!entry.name.trim().is_empty(), "entry {i} name blank");
            assert!(
                !entry
                    .description
                    .trim()
                    .is_empty(),
                "entry {i} description blank"
            );
            assert!(matches!(entry.origin, PredefinedQueryOrigin::Builtin));
        }
    }

    #[test]
    fn ids_are_the_expected_stable_slugs() {
        let ids: Vec<&str> = builtin_catalogue()
            .iter()
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(ids, vec![AGENT_POLICY_Q1_ID, AGENT_POLICY_Q2_ID, AGENT_POLICY_Q3_ID]);
    }

    #[test]
    fn every_entry_passes_tr_parity_shape_validator() {
        for entry in builtin_catalogue() {
            validate_query_shape(&entry.query, entry.query_type)
                .unwrap_or_else(|e| panic!("entry {} failed: {}", entry.id, e));
        }
    }

    #[test]
    fn q_tuples_match_shared_pub_const_templates() {
        for entry in builtin_catalogue() {
            drift_check(entry).unwrap_or_else(|e| panic!("{}", e));
        }
    }

    #[test]
    fn validate_catalogue_rejects_resource_drift() {
        let mut cat: Vec<PredefinedTrustCheckQuery> = builtin_catalogue().to_vec();
        cat[1].query.resource = Some("wrongResource".to_string());
        match validate_catalogue(&cat).unwrap_err() {
            CatalogueValidationError::DriftFromConsts { id, .. } => {
                assert_eq!(id, AGENT_POLICY_Q2_ID);
            }
            other => panic!("expected DriftFromConsts, got {other:?}"),
        }
    }

    #[test]
    fn validate_catalogue_rejects_query_type_drift() {
        let mut cat: Vec<PredefinedTrustCheckQuery> = builtin_catalogue().to_vec();
        cat[0].query_type = TrqpQueryType::Authorization;
        match validate_catalogue(&cat).unwrap_err() {
            CatalogueValidationError::DriftFromConsts { id, .. } => {
                assert_eq!(id, AGENT_POLICY_Q1_ID);
            }
            other => panic!("expected DriftFromConsts, got {other:?}"),
        }
    }

    #[test]
    fn validate_catalogue_rejects_duplicate_ids() {
        let cat_ref = builtin_catalogue();
        let mut cat = cat_ref.to_vec();
        cat.push(cat_ref[0].clone());
        assert!(matches!(validate_catalogue(&cat).unwrap_err(), CatalogueValidationError::DuplicateId { .. }));
    }

    #[test]
    fn validate_catalogue_rejects_operator_origin() {
        let mut cat: Vec<PredefinedTrustCheckQuery> = builtin_catalogue().to_vec();
        cat[0].origin = PredefinedQueryOrigin::Operator;
        assert!(matches!(validate_catalogue(&cat).unwrap_err(), CatalogueValidationError::NonBuiltinOrigin { .. }));
    }

    #[test]
    fn validate_catalogue_rejects_empty() {
        assert!(matches!(validate_catalogue(&[]).unwrap_err(), CatalogueValidationError::Empty));
    }

    #[test]
    fn validate_catalogue_rejects_over_cap() {
        let one = builtin_catalogue()[0].clone();
        let cat: Vec<PredefinedTrustCheckQuery> = (0..=CATALOGUE_MAX_ENTRIES)
            .map(|i| PredefinedTrustCheckQuery {
                id: format!("dummy-{i}"),
                ..one.clone()
            })
            .collect();
        assert!(matches!(validate_catalogue(&cat).unwrap_err(), CatalogueValidationError::TooLarge { .. }));
    }

    #[test]
    fn is_valid_id_accepts_valid_slugs() {
        assert!(is_valid_id("agent-policy-q1"));
        assert!(is_valid_id("q1"));
        assert!(is_valid_id("0abc"));
    }

    #[test]
    fn is_valid_id_rejects_invalid_slugs() {
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("Q1"));
        assert!(!is_valid_id("-abc"));
        assert!(!is_valid_id("a b"));
        assert!(!is_valid_id("a_b"));
    }

    #[test]
    fn tr_parity_validator_requires_action_and_resource_for_authorization() {
        let mut q = TrqpQueryParams {
            authority_id: "a".to_string(),
            entity_id: "b".to_string(),
            action: None,
            resource: None,
        };
        assert!(validate_query_shape(&q, TrqpQueryType::Authorization).is_err());
        q.action = Some("issue".to_string());
        assert!(validate_query_shape(&q, TrqpQueryType::Authorization).is_err());
        q.resource = Some("credential".to_string());
        assert!(validate_query_shape(&q, TrqpQueryType::Authorization).is_ok());
    }

    #[test]
    fn tr_parity_validator_allows_blank_action_resource_for_recognition() {
        let q = TrqpQueryParams {
            authority_id: "a".to_string(),
            entity_id: "b".to_string(),
            action: None,
            resource: None,
        };
        assert!(validate_query_shape(&q, TrqpQueryType::Recognition).is_ok());
    }
}
