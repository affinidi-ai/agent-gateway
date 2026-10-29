//! A policy plane's decision for one input, keeping an undefined or failing
//! evaluation apart from a deny.
//!
//! The request path fails closed and treats both as a deny. A save-time dry run
//! needs to tell them apart: a plane that denies is a control, one that cannot be
//! evaluated is a configuration the operator has to look at.

/// What a policy plane decides for one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneVerdict {
    Allow,
    Deny,
    /// The query produced no value, a non-boolean value or an error, or the plane
    /// has no usable compiled policy.
    Undetermined,
}

impl PlaneVerdict {
    /// Evaluate `query` on a compiled engine; the caller passes a clone it owns.
    pub fn evaluate(
        mut engine: regorus::Engine,
        query: &str,
        input_json: &str,
    ) -> Self {
        if engine
            .set_input_json(input_json)
            .is_err()
        {
            return Self::Undetermined;
        }
        match engine.eval_bool_query(query.to_string(), false) {
            Ok(true) => Self::Allow,
            Ok(false) => Self::Deny,
            Err(_) => Self::Undetermined,
        }
    }

    /// Deny-overrides: a deny wins, then an undetermined member, then allow.
    pub fn and(
        self,
        other: Self,
    ) -> Self {
        match (self, other) {
            (Self::Deny, _) | (_, Self::Deny) => Self::Deny,
            (Self::Undetermined, _) | (_, Self::Undetermined) => Self::Undetermined,
            (Self::Allow, Self::Allow) => Self::Allow,
        }
    }

    /// Combine a deny-overrides set; an empty set allows.
    pub fn all(verdicts: impl IntoIterator<Item = Self>) -> Self {
        verdicts
            .into_iter()
            .fold(Self::Allow, Self::and)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY: &str = "data.surface.policy.allow";

    fn engine(policy: &str) -> regorus::Engine {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("test.rego".to_string(), policy.to_string())
            .expect("policy compiles");
        engine
    }

    #[test]
    fn test_evaluate_reports_allow_and_deny() {
        let policy = engine("package surface.policy\ndefault allow := false\nallow if input.ok\n");
        assert_eq!(PlaneVerdict::evaluate(policy.clone(), QUERY, r#"{"ok": true}"#), PlaneVerdict::Allow);
        assert_eq!(PlaneVerdict::evaluate(policy.clone(), QUERY, r#"{"ok": false}"#), PlaneVerdict::Deny);
    }

    #[test]
    fn test_evaluate_undefined_allow_is_undetermined() {
        let policy = engine("package surface.policy\nallow if input.ok\n");
        assert_eq!(PlaneVerdict::evaluate(policy.clone(), QUERY, r#"{"ok": false}"#), PlaneVerdict::Undetermined);
    }

    #[test]
    fn test_evaluate_wrong_package_is_undetermined() {
        let policy = engine("package other.policy\ndefault allow := false\n");
        assert_eq!(PlaneVerdict::evaluate(policy.clone(), QUERY, "{}"), PlaneVerdict::Undetermined);
    }

    #[test]
    fn test_evaluate_conflicting_rule_values_are_undetermined() {
        let policy = engine("package surface.policy\nallow := true if input.x\nallow := false if input.x\n");
        assert_eq!(PlaneVerdict::evaluate(policy.clone(), QUERY, r#"{"x": true}"#), PlaneVerdict::Undetermined);
    }

    #[test]
    fn test_evaluate_non_boolean_allow_is_undetermined() {
        let policy = engine("package surface.policy\nallow := \"yes\"\n");
        assert_eq!(PlaneVerdict::evaluate(policy.clone(), QUERY, "{}"), PlaneVerdict::Undetermined);
    }

    #[test]
    fn test_all_is_deny_overrides() {
        use PlaneVerdict::{Allow, Deny, Undetermined};
        assert_eq!(PlaneVerdict::all([]), Allow);
        assert_eq!(PlaneVerdict::all([Allow, Allow]), Allow);
        assert_eq!(PlaneVerdict::all([Allow, Undetermined]), Undetermined);
        assert_eq!(PlaneVerdict::all([Undetermined, Deny, Allow]), Deny);
    }
}
