//! Structured audit logging for verified identity bindings (Workload Binding).
//!
//! Mirrors [`crate::observability::trust_check_audit`] and
//! [`crate::observability::policy_audit`]: one structured `tracing` event per
//! inbound request that carried (or should have carried) an identity binding
//! VP. A verified binding and a missing binding log at `DEBUG` (absence is
//! informational); an *invalid* binding logs at `WARN` so it reaches the
//! OpenTelemetry log exporter.
//!
//! The event answers the operator questions the design calls for: which managed
//! agent acted, which caller it acted for (attested field names + the stable
//! user hash), which gateway attested the binding, which target / Transit Point
//! was used, and whether the caller context was only `gateway_attested` or also
//! `caller_credential_chained`.
//!
//! It never carries the signed VP material — [`record_identity_binding`] has no
//! access to the VP JWT by construction, so a verification failure cannot leak
//! the presentation into the logs. Caller-context *values* are likewise never
//! emitted; only the attested field *names* are logged (the values already live
//! in the VP and OPA input, and the log correlates to them via `user_hash`).

/// Outcome of identity-binding extraction on an inbound request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityBindingOutcome {
    /// A binding VP was present and verified.
    Verified,
    /// No binding VP was present on the request.
    Absent,
    /// A binding VP was present but failed verification.
    Invalid,
}

impl IdentityBindingOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Absent => "absent",
            Self::Invalid => "invalid",
        }
    }
}

/// Structured input to [`record_identity_binding`]. Named fields keep the call
/// sites self-documenting and let the audit surface grow without perturbing
/// every caller.
pub struct IdentityBindingAuditEvent<'a> {
    pub surface_id: &'a str,
    pub outcome: IdentityBindingOutcome,
    /// Managed agent DID (VP holder). `None` when absent/invalid.
    pub agent_did: Option<&'a str>,
    /// Attesting gateway DID (VC issuer). `None` when absent/invalid.
    pub issuer_gateway: Option<&'a str>,
    /// Bound target endpoint from `workloadBinding.target`. `None` when absent.
    pub target: Option<&'a str>,
    /// Transit Point alias the request routed through, when known.
    pub transit_point: Option<&'a str>,
    /// Stable caller correlation hash. `None` when there is no caller context.
    pub user_hash: Option<&'a str>,
    /// Assurance level: `gateway_attested` or `caller_credential_chained`.
    pub assurance: Option<&'a str>,
    /// Whether the managed agent acted on behalf of a caller.
    pub delegated: bool,
    /// Names of the attested caller-context fields (keys only — values stay in
    /// the VP / policy input and are never dumped into the audit log).
    pub caller_field_names: &'a [String],
    /// Verification-failure detail for the `Invalid` outcome. Must never carry
    /// signed VP material.
    pub error_detail: Option<&'a str>,
}

/// Record one identity-binding outcome as a structured audit event.
pub fn record_identity_binding(event: IdentityBindingAuditEvent<'_>) {
    let IdentityBindingAuditEvent {
        surface_id,
        outcome,
        agent_did,
        issuer_gateway,
        target,
        transit_point,
        user_hash,
        assurance,
        delegated,
        caller_field_names,
        error_detail,
    } = event;

    let outcome_str = outcome.label();
    let agent_did_str = agent_did.unwrap_or_default();
    let issuer_gateway_str = issuer_gateway.unwrap_or_default();
    let target_str = target.unwrap_or_default();
    let transit_point_str = transit_point.unwrap_or_default();
    let user_hash_str = user_hash.unwrap_or_default();
    let assurance_str = assurance.unwrap_or_default();
    let caller_fields_str = caller_field_names.join(",");
    let error_detail_str = error_detail.unwrap_or_default();

    match outcome {
        IdentityBindingOutcome::Invalid => {
            tracing::warn!(
                target: "identity_binding_audit",
                surface_id = surface_id,
                outcome = outcome_str,
                agent_did = agent_did_str,
                issuer_gateway = issuer_gateway_str,
                target = target_str,
                transit_point = transit_point_str,
                user_hash = user_hash_str,
                assurance = assurance_str,
                delegated = delegated,
                caller_fields = caller_fields_str.as_str(),
                error_detail = error_detail_str,
                "identity binding: invalid"
            );
        }
        IdentityBindingOutcome::Verified | IdentityBindingOutcome::Absent => {
            tracing::debug!(
                target: "identity_binding_audit",
                surface_id = surface_id,
                outcome = outcome_str,
                agent_did = agent_did_str,
                issuer_gateway = issuer_gateway_str,
                target = target_str,
                transit_point = transit_point_str,
                user_hash = user_hash_str,
                assurance = assurance_str,
                delegated = delegated,
                caller_fields = caller_fields_str.as_str(),
                "identity binding: {}",
                outcome_str
            );
        }
    }
}

/// Emit the audit event for an [`crate::protocols::extensions::extract_identity_binding_vp`]
/// result. `Ok(Some)` → verified, `Ok(None)` → absent, `Err` → invalid (the
/// error string is a short diagnostic, never the signed VP).
pub fn audit_extraction(
    surface_id: &str,
    transit_point: Option<&str>,
    result: &Result<Option<crate::surface_context::IdentityBindingContext>, String>,
) {
    match result {
        Ok(Some(binding)) => {
            let caller_field_names: Vec<String> = binding
                .caller
                .as_ref()
                .map(|c| {
                    c.fields
                        .keys()
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            record_identity_binding(IdentityBindingAuditEvent {
                surface_id,
                outcome: IdentityBindingOutcome::Verified,
                agent_did: Some(binding.agent_did.as_str()),
                issuer_gateway: Some(binding.gateway_did.as_str()),
                target: binding.target.as_deref(),
                transit_point,
                user_hash: binding
                    .caller
                    .as_ref()
                    .and_then(|c| c.user_hash.as_deref()),
                assurance: binding
                    .caller
                    .as_ref()
                    .map(|c| c.assurance.as_str()),
                delegated: binding.delegated,
                caller_field_names: &caller_field_names,
                error_detail: None,
            });
        }
        Ok(None) => record_identity_binding(IdentityBindingAuditEvent {
            surface_id,
            outcome: IdentityBindingOutcome::Absent,
            agent_did: None,
            issuer_gateway: None,
            target: None,
            transit_point,
            user_hash: None,
            assurance: None,
            delegated: false,
            caller_field_names: &[],
            error_detail: None,
        }),
        Err(e) => record_identity_binding(IdentityBindingAuditEvent {
            surface_id,
            outcome: IdentityBindingOutcome::Invalid,
            agent_did: None,
            issuer_gateway: None,
            target: None,
            transit_point,
            user_hash: None,
            assurance: None,
            delegated: false,
            caller_field_names: &[],
            error_detail: Some(e.as_str()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    #[test]
    fn outcome_labels_are_stable() {
        assert_eq!(IdentityBindingOutcome::Verified.label(), "verified");
        assert_eq!(IdentityBindingOutcome::Absent.label(), "absent");
        assert_eq!(IdentityBindingOutcome::Invalid.label(), "invalid");
    }

    #[derive(Clone, Default)]
    struct CapturedEvent {
        level: String,
        fields: Vec<(String, String)>,
    }

    struct CapturingLayer {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    struct FieldVisitor {
        fields: Vec<(String, String)>,
    }

    impl Visit for FieldVisitor {
        fn record_debug(
            &mut self,
            field: &Field,
            value: &dyn std::fmt::Debug,
        ) {
            self.fields
                .push((field.name().to_string(), format!("{:?}", value)));
        }

        fn record_str(
            &mut self,
            field: &Field,
            value: &str,
        ) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }

        fn record_bool(
            &mut self,
            field: &Field,
            value: bool,
        ) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    impl<S: tracing::Subscriber> Layer<S> for CapturingLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor { fields: Vec::new() };
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("events lock poisoned")
                .push(CapturedEvent {
                    level: event
                        .metadata()
                        .level()
                        .to_string(),
                    fields: visitor.fields,
                });
        }
    }

    fn field<'a>(
        ev: &'a CapturedEvent,
        name: &str,
    ) -> Option<&'a str> {
        ev.fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CapturingLayer { events: events.clone() });
        tracing::subscriber::with_default(subscriber, f);
        let guard = events
            .lock()
            .expect("events lock poisoned");
        guard.clone()
    }

    #[test]
    fn verified_event_carries_full_context_at_debug() {
        let caller_fields = vec!["sub".to_string(), "email".to_string()];
        let captured = capture(|| {
            record_identity_binding(IdentityBindingAuditEvent {
                surface_id: "surface-a",
                outcome: IdentityBindingOutcome::Verified,
                agent_did: Some("did:web:agent.example"),
                issuer_gateway: Some("did:web:gw1.example"),
                target: Some("fabric://gw2/alpha"),
                transit_point: Some("delta"),
                user_hash: Some("sha256-hash"),
                assurance: Some("gateway_attested"),
                delegated: true,
                caller_field_names: &caller_fields,
                error_detail: None,
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-a"))
            .expect("identity binding audit event not captured");

        assert_eq!(ev.level, "DEBUG");
        assert_eq!(field(ev, "outcome"), Some("verified"));
        assert_eq!(field(ev, "agent_did"), Some("did:web:agent.example"));
        assert_eq!(field(ev, "issuer_gateway"), Some("did:web:gw1.example"));
        assert_eq!(field(ev, "target"), Some("fabric://gw2/alpha"));
        assert_eq!(field(ev, "transit_point"), Some("delta"));
        assert_eq!(field(ev, "user_hash"), Some("sha256-hash"));
        assert_eq!(field(ev, "assurance"), Some("gateway_attested"));
        assert_eq!(field(ev, "delegated"), Some("true"));
        assert_eq!(field(ev, "caller_fields"), Some("sub,email"));
    }

    #[test]
    fn absent_event_records_absence_without_fabricating_caller_fields() {
        let empty: Vec<String> = Vec::new();
        let captured = capture(|| {
            record_identity_binding(IdentityBindingAuditEvent {
                surface_id: "surface-b",
                outcome: IdentityBindingOutcome::Absent,
                agent_did: None,
                issuer_gateway: None,
                target: None,
                transit_point: Some("delta"),
                user_hash: None,
                assurance: None,
                delegated: false,
                caller_field_names: &empty,
                error_detail: None,
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-b"))
            .expect("identity binding audit event not captured");

        assert_eq!(ev.level, "DEBUG");
        assert_eq!(field(ev, "outcome"), Some("absent"));
        assert_eq!(field(ev, "agent_did"), Some(""));
        assert_eq!(field(ev, "user_hash"), Some(""));
        assert_eq!(field(ev, "assurance"), Some(""));
        assert_eq!(field(ev, "delegated"), Some("false"));
        assert_eq!(field(ev, "caller_fields"), Some(""), "must not fabricate caller fields when absent");
    }

    #[test]
    fn invalid_event_at_warn_carries_detail_without_vp_material() {
        let empty: Vec<String> = Vec::new();
        let captured = capture(|| {
            record_identity_binding(IdentityBindingAuditEvent {
                surface_id: "surface-c",
                outcome: IdentityBindingOutcome::Invalid,
                agent_did: None,
                issuer_gateway: None,
                target: None,
                transit_point: Some("delta"),
                user_hash: None,
                assurance: None,
                delegated: false,
                caller_field_names: &empty,
                error_detail: Some("Identity binding VP verification failed: signature invalid"),
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-c"))
            .expect("identity binding audit event not captured");

        assert_eq!(ev.level, "WARN");
        assert_eq!(field(ev, "outcome"), Some("invalid"));
        assert_eq!(field(ev, "error_detail"), Some("Identity binding VP verification failed: signature invalid"));
        // No signed VP material is ever emitted: there is no field carrying a
        // presentation, and the detail is a short diagnostic, not a JWT.
        assert!(
            ev.fields
                .iter()
                .all(|(k, _)| k != "verifiablePresentation" && k != "vp")
        );
        assert!(
            ev.fields
                .iter()
                .all(|(_, v)| !v.contains("eyJ")),
            "no field may contain a JWT segment"
        );
    }

    #[test]
    fn chained_credential_changes_assurance_to_caller_credential_chained() {
        let caller_fields = vec!["sub".to_string()];
        let captured = capture(|| {
            record_identity_binding(IdentityBindingAuditEvent {
                surface_id: "surface-d",
                outcome: IdentityBindingOutcome::Verified,
                agent_did: Some("did:web:agent.example"),
                issuer_gateway: Some("did:web:gw1.example"),
                target: Some("fabric://gw2/alpha"),
                transit_point: Some("delta"),
                user_hash: Some("sha256-hash"),
                assurance: Some("caller_credential_chained"),
                delegated: true,
                caller_field_names: &caller_fields,
                error_detail: None,
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-d"))
            .expect("identity binding audit event not captured");

        assert_eq!(field(ev, "assurance"), Some("caller_credential_chained"));
    }
}
