//! How an ID token's claims decide whether a person may sign in, and with
//! which role (`required_claims` and `role_mapping` in `oidc.json`).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::config::{RoleMapping, ValueMatcher};
use crate::auth::types::UserRole;

/// The string values of a top-level claim: a string is one value, an array
/// gives its string elements, and anything else, or no claim, gives none.
fn claim_values<'a>(
    claims: &'a Map<String, Value>,
    name: &str,
) -> Vec<&'a str> {
    match claims.get(name) {
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .collect(),
        _ => Vec::new(),
    }
}

/// The first required claim the token does not carry with an allowed value,
/// or `None` when it meets them all. A claim meets its entry when it, or any
/// element of it when it is an array, equals one of the allowed values.
pub fn unmet_required_claim<'a>(
    claims: &Map<String, Value>,
    required: &'a BTreeMap<String, Vec<ValueMatcher>>,
) -> Option<&'a str> {
    required
        .iter()
        .find(|(claim, allowed)| {
            let values: &[Value] = match claims.get(claim.as_str()) {
                Some(Value::Array(values)) => values,
                Some(value) => std::slice::from_ref(value),
                None => &[],
            };
            !values.iter().any(|value| {
                allowed
                    .iter()
                    .any(|allowed| allowed.matches(value))
            })
        })
        .map(|(claim, _)| claim.as_str())
}

/// The role the token's values of `mapping.claim` grant: the highest role any
/// value maps to, or `mapping.unmapped` when none maps. `None` means the
/// account gets no access.
pub fn mapped_role(
    claims: &Map<String, Value>,
    mapping: &RoleMapping,
) -> Option<UserRole> {
    claim_values(claims, &mapping.claim)
        .into_iter()
        .filter_map(|value| role_for_value(value, mapping))
        .max_by_key(UserRole::rank)
        .or_else(|| mapping.unmapped.clone())
}

/// The role one claim value maps to: its exact entry when it has one, so an
/// exact entry can raise or lower a person a pattern also matches; otherwise
/// the highest role among the `regex:` patterns it matches.
fn role_for_value(
    value: &str,
    mapping: &RoleMapping,
) -> Option<UserRole> {
    let exact = mapping
        .values
        .iter()
        .find(|(matcher, _)| matches!(matcher, ValueMatcher::Exact(exact) if exact == value));
    if let Some((_, role)) = exact {
        return Some(role.clone());
    }
    mapping
        .values
        .iter()
        .filter(|(matcher, _)| matches!(matcher, ValueMatcher::Regex(_)) && matcher.matches_str(value))
        .map(|(_, role)| role.clone())
        .max_by_key(UserRole::rank)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(value: Value) -> Map<String, Value> {
        value
            .as_object()
            .unwrap()
            .clone()
    }

    fn matcher(value: &Value) -> ValueMatcher {
        match value {
            Value::Bool(value) => ValueMatcher::Bool(*value),
            Value::String(text) => ValueMatcher::from_text("test", text).unwrap(),
            other => panic!("not a claim value: {other}"),
        }
    }

    fn allowed(values: Value) -> Vec<ValueMatcher> {
        values
            .as_array()
            .unwrap()
            .iter()
            .map(matcher)
            .collect()
    }

    fn mapping_of(
        values: Value,
        unmapped: Option<UserRole>,
    ) -> RoleMapping {
        RoleMapping {
            claim: "email".to_string(),
            values: values
                .as_object()
                .unwrap()
                .iter()
                .map(|(text, role)| (matcher(&json!(text)), serde_json::from_value(role.clone()).unwrap()))
                .collect(),
            unmapped,
        }
    }

    fn mapping(unmapped: Option<UserRole>) -> RoleMapping {
        RoleMapping {
            claim: "roles".to_string(),
            ..mapping_of(json!({ "admin": "administrator", "operator": "poweruser", "member": "user" }), unmapped)
        }
    }

    #[test]
    fn a_string_or_an_array_claim_maps_to_a_role() {
        assert_eq!(mapped_role(&claims(json!({ "roles": "admin" })), &mapping(None)), Some(UserRole::Administrator));
        assert_eq!(mapped_role(&claims(json!({ "roles": ["operator"] })), &mapping(None)), Some(UserRole::PowerUser));
    }

    #[test]
    fn the_highest_mapped_role_wins_whatever_the_order() {
        for values in
            [json!(["member", "admin", "operator"]), json!(["admin", "member"]), json!(["operator", "member"])]
        {
            let expected = if values
                .as_array()
                .unwrap()
                .contains(&json!("admin"))
            {
                UserRole::Administrator
            } else {
                UserRole::PowerUser
            };
            assert_eq!(mapped_role(&claims(json!({ "roles": values })), &mapping(None)), Some(expected));
        }
    }

    #[test]
    fn values_match_exactly_and_never_by_name() {
        for value in [json!("Admin"), json!("administrator"), json!(" admin"), json!(["ADMIN"])] {
            assert_eq!(mapped_role(&claims(json!({ "roles": value })), &mapping(None)), None, "{value}");
        }
    }

    #[test]
    fn an_account_with_no_mapped_value_gets_the_unmapped_setting() {
        for token in [json!({}), json!({ "roles": [] }), json!({ "roles": ["guest"] }), json!({ "roles": 7 })] {
            assert_eq!(mapped_role(&claims(token.clone()), &mapping(None)), None, "deny: {token}");
            assert_eq!(
                mapped_role(&claims(token.clone()), &mapping(Some(UserRole::User))),
                Some(UserRole::User),
                "{token}"
            );
        }
    }

    #[test]
    fn elements_of_an_array_that_are_not_strings_are_ignored() {
        assert_eq!(
            mapped_role(&claims(json!({ "roles": [1, null, {"admin": true}, "member"] })), &mapping(None)),
            Some(UserRole::User)
        );
    }

    #[test]
    fn a_required_claim_needs_one_allowed_value() {
        let required = BTreeMap::from([("org_id".to_string(), allowed(json!(["org_123", "org_456"])))]);

        assert_eq!(unmet_required_claim(&claims(json!({ "org_id": "org_123" })), &required), None);
        assert_eq!(unmet_required_claim(&claims(json!({ "org_id": ["org_9", "org_456"] })), &required), None);
        for token in
            [json!({}), json!({ "org_id": "org_9" }), json!({ "org_id": ["ORG_123"] }), json!({ "org_id": 123 })]
        {
            assert_eq!(unmet_required_claim(&claims(token.clone()), &required), Some("org_id"), "{token}");
        }
    }

    #[test]
    fn every_required_claim_must_be_met() {
        let required = BTreeMap::from([
            ("org_id".to_string(), allowed(json!(["org_123"]))),
            ("tier".to_string(), allowed(json!(["enterprise"]))),
        ]);

        assert_eq!(unmet_required_claim(&claims(json!({ "org_id": "org_123" })), &required), Some("tier"));
        assert_eq!(
            unmet_required_claim(&claims(json!({ "org_id": "org_123", "tier": "enterprise" })), &required),
            None
        );
        assert_eq!(unmet_required_claim(&claims(json!({})), &BTreeMap::new()), None, "nothing required");
    }

    #[test]
    fn a_boolean_claim_matches_only_a_boolean() {
        let required = BTreeMap::from([("email_verified".to_string(), allowed(json!([true])))]);

        assert_eq!(unmet_required_claim(&claims(json!({ "email_verified": true })), &required), None);
        for token in [
            json!({}),
            json!({ "email_verified": false }),
            json!({ "email_verified": "true" }),
            json!({ "email_verified": 1 }),
            json!({ "email_verified": null }),
        ] {
            assert_eq!(unmet_required_claim(&claims(token.clone()), &required), Some("email_verified"), "{token}");
        }

        let either = BTreeMap::from([("email_verified".to_string(), allowed(json!([true, "true"])))]);
        assert_eq!(
            unmet_required_claim(&claims(json!({ "email_verified": "true" })), &either),
            None,
            "a provider that sends the string is met by listing it"
        );
    }

    #[test]
    fn a_string_never_matches_a_boolean_and_arrays_may_mix_them() {
        let required = BTreeMap::from([("flags".to_string(), allowed(json!(["true", true])))]);

        assert_eq!(unmet_required_claim(&claims(json!({ "flags": ["x", true] })), &required), None);
        assert_eq!(unmet_required_claim(&claims(json!({ "flags": [false, "x"] })), &required), Some("flags"));

        let strings_only = BTreeMap::from([("flags".to_string(), allowed(json!(["true"])))]);
        assert_eq!(unmet_required_claim(&claims(json!({ "flags": true })), &strings_only), Some("flags"));
    }

    fn role_of(
        email: &str,
        mapping: &RoleMapping,
    ) -> Option<UserRole> {
        mapped_role(&claims(json!({ "email": email })), mapping)
    }

    #[test]
    fn a_regex_value_maps_everyone_it_matches() {
        let mapping = mapping_of(json!({ "regex:.*@example\\.com": "poweruser" }), None);

        assert_eq!(role_of("someone@example.com", &mapping), Some(UserRole::PowerUser));
        assert_eq!(role_of("a.b+c@example.com", &mapping), Some(UserRole::PowerUser));
        for outside in ["someone@example.co", "someone@example.com.evil.example", "someone@EXAMPLE.COM", "example.com"]
        {
            assert_eq!(role_of(outside, &mapping), None, "{outside}");
        }

        let any_case = mapping_of(json!({ "regex:(?i).*@example\\.com": "poweruser" }), None);
        assert_eq!(role_of("someone@EXAMPLE.COM", &any_case), Some(UserRole::PowerUser), "(?i) ignores case");
    }

    #[test]
    fn an_exact_entry_beats_a_pattern_in_either_direction() {
        let mapping = mapping_of(
            json!({
                "regex:.*@example\\.com": "poweruser",
                "jo.doe@example.com": "administrator",
                "intern@example.com": "user",
            }),
            None,
        );

        assert_eq!(role_of("jo.doe@example.com", &mapping), Some(UserRole::Administrator));
        assert_eq!(role_of("intern@example.com", &mapping), Some(UserRole::User));
        assert_eq!(role_of("someone@example.com", &mapping), Some(UserRole::PowerUser));
    }

    #[test]
    fn the_highest_of_several_matching_patterns_wins() {
        let mapping =
            mapping_of(json!({ "regex:.*@example\\.com": "user", "regex:ops-.*@example\\.com": "poweruser" }), None);

        assert_eq!(role_of("ops-jo@example.com", &mapping), Some(UserRole::PowerUser));
        assert_eq!(role_of("jo@example.com", &mapping), Some(UserRole::User));
    }

    #[test]
    fn values_without_the_prefix_stay_exact_whatever_characters_they_hold() {
        let mapping = mapping_of(json!({ "jo.doe.au+user@mail.example": "user" }), None);

        assert_eq!(role_of("jo.doe.au+user@mail.example", &mapping), Some(UserRole::User));
        assert_eq!(role_of("joXdoe.au+user@mail.example", &mapping), None, "a dot is a dot");
        assert_eq!(role_of("jo.doe.auuser@mail.example", &mapping), None, "a plus is a plus");
    }

    #[test]
    fn a_required_claim_may_be_a_pattern_but_never_matches_a_boolean() {
        let required = BTreeMap::from([("email".to_string(), allowed(json!(["regex:.*@example\\.com"])))]);

        assert_eq!(unmet_required_claim(&claims(json!({ "email": "x@example.com" })), &required), None);
        assert_eq!(unmet_required_claim(&claims(json!({ "email": "x@mail.example" })), &required), Some("email"));

        let anything = BTreeMap::from([("flag".to_string(), allowed(json!(["regex:.*"])))]);
        assert_eq!(unmet_required_claim(&claims(json!({ "flag": true })), &anything), Some("flag"));
    }
}
