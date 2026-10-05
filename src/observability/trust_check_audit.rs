//! Structured audit logging for Trust Check element executions.
//!
//! Mirrors [`crate::observability::policy_audit`]: one structured `tracing`
//! event per element evaluation, plus a Prometheus sample. Successes log at
//! `DEBUG` so the success/error ratio is observable when the operator opts
//! into verbose logging; failures (clean denials *and* stage errors) log at
//! `WARN` so they reach the OpenTelemetry log exporter.
//!
//! Events carry the surface id, leg, trust registry id, query type, outcome
//! flag, error code (when applicable), and per-element latency in
//! milliseconds. Because the event fires inside the active request span it
//! auto-correlates to the distributed trace.

use crate::metrics::backends::prometheus::track_trust_check;
use crate::trust_registry_verification::trust_check_element::{TrqpQueryType, TrustCheckLeg};
use crate::trust_registry_verification::trust_check_executor::{NOT_AUTHORIZED, NOT_RECOGNIZED};

const RESULT_OK: &str = "ok";
const RESULT_DENIED: &str = "denied";
const RESULT_ERROR: &str = "error";

fn leg_label(leg: TrustCheckLeg) -> &'static str {
    match leg {
        TrustCheckLeg::Caller => "caller",
        TrustCheckLeg::Target => "target",
    }
}

fn query_type_label(qt: TrqpQueryType) -> &'static str {
    match qt {
        TrqpQueryType::Authorization => "authorization",
        TrqpQueryType::Recognition => "recognition",
    }
}

/// Classify a result into the Prometheus / audit `result` label:
/// `ok` (allowed), `denied` (clean negative TRQP response — the
/// [`NOT_RECOGNIZED`] / [`NOT_AUTHORIZED`] codes), or `error` (system
/// fault carrying any other `error_code`, or the legacy no-code path).
/// Note the label split is independent of the log level: every `!ok`
/// outcome still logs at `WARN` so the audit page keeps every denial
/// in view.
fn result_label(
    ok: bool,
    error_code: Option<&'static str>,
) -> &'static str {
    match (ok, error_code) {
        (true, _) => RESULT_OK,
        (false, Some(NOT_RECOGNIZED | NOT_AUTHORIZED)) => RESULT_DENIED,
        (false, _) => RESULT_ERROR,
    }
}

/// Structured input to [`record_trust_check`]. Named fields keep the
/// call sites self-documenting and let the audit surface grow without
/// perturbing every caller.
///
/// * `element_id` and `element_name` come from the [`crate::trust_registry_verification::trust_check_element::TrustCheckElement`]
///   that produced this result; both are emitted as structured audit
///   fields so an operator can correlate an event with a specific row
///   on the surface. `element_name` is `None` when the element omits
///   the optional label.
/// * `error_code` is `None` for `ok` results and for the (now rare)
///   unclassified negative path where a stage produced `ok = false`
///   without a code. Every network-driven Trust Check now carries a
///   code even on a clean deny — [`NOT_RECOGNIZED`] / [`NOT_AUTHORIZED`]
///   for the negative verdict, or one of the transport / problem-report
///   / parse-error codes for a stage failure.
///   When set, `error_detail` should carry the per-failure detail
///   message (e.g. the serde parse error, the unreachable diagnostic,
///   the problem-report code+message, or the negative-verdict
///   `"Registry answered ..."` / `"Registry returned empty response
///   body"` string) and is emitted as an `error_detail` structured
///   field on the WARN event so operators can diagnose without raising
///   the gateway log level.
/// * `latency_ms = 0` signals "no network call fired" (e.g. template
///   resolution failed before the per-element clock started); the
///   histogram observation is skipped on that path.
pub struct TrustCheckAuditEvent<'a> {
    pub surface_id: &'a str,
    pub leg: TrustCheckLeg,
    pub element_id: &'a str,
    pub element_name: Option<&'a str>,
    /// Resolved (or, on a pre-dispatch failure, templated) TRQP authority id.
    /// `None` on the target-leg "unavailable" pre-check paths
    /// (`AGENT_CARD_UNAVAILABLE`, `TRUST_REGISTRY_METADATA_UNAVAILABLE`)
    /// where the raw template strings would be noise, matching the
    /// wire shape of [`crate::trust_registry_verification::TrustCheckResult`].
    pub authority_id: Option<&'a str>,
    /// Resolved (or, on a pre-dispatch failure, templated) TRQP entity id.
    /// Same `None` semantics as `authority_id`.
    pub entity_id: Option<&'a str>,
    pub trust_registry_id: &'a str,
    pub query_type: TrqpQueryType,
    pub ok: bool,
    pub error_code: Option<&'static str>,
    pub error_detail: Option<&'a str>,
    pub latency_ms: u64,
}

/// Record one Trust Check element execution: emit a structured audit event
/// and a Prometheus sample.
pub fn record_trust_check(event: TrustCheckAuditEvent<'_>) {
    let TrustCheckAuditEvent {
        surface_id,
        leg,
        element_id,
        element_name,
        authority_id,
        entity_id,
        trust_registry_id,
        query_type,
        ok,
        error_code,
        error_detail,
        latency_ms,
    } = event;

    let leg_str = leg_label(leg);
    let query_type_str = query_type_label(query_type);
    let result = result_label(ok, error_code);
    let error_code_str = error_code.unwrap_or_default();
    let error_detail_str = error_detail.unwrap_or_default();
    let element_name_str = element_name.unwrap_or_default();

    let duration_secs = match (result, latency_ms) {
        (RESULT_ERROR, 0) => None,
        _ => Some(latency_ms as f64 / 1000.0),
    };
    track_trust_check(trust_registry_id, query_type_str, result, duration_secs);

    if ok {
        tracing::debug!(
            target: "trust_check_audit",
            surface_id = surface_id,
            leg = leg_str,
            element_id = element_id,
            element_name = element_name_str,
            trust_registry_id = trust_registry_id,
            query_type = query_type_str,
            result = result,
            ok = ok,
            error_code = error_code_str,
            latency_ms = latency_ms,
            "trust check: ok"
        );
    } else {
        tracing::warn!(
            target: "trust_check_audit",
            surface_id = surface_id,
            leg = leg_str,
            element_id = element_id,
            element_name = element_name_str,
            trust_registry_id = trust_registry_id,
            query_type = query_type_str,
            result = result,
            ok = ok,
            error_code = error_code_str,
            error_detail = error_detail_str,
            latency_ms = latency_ms,
            "trust check: {}",
            result
        );
    }

    // Mirror into the VP Audit Log (JSONL) when the operator enabled the
    // `trust_checks` category in Settings › Security. The tracing + Prometheus
    // emission above is always on for operational telemetry; only this durable
    // audit record is gated, so toggling the category never blinds ops.
    //
    // `authority_id` / `entity_id` are truncated to the same shape the
    // dashboard identity page renders (`did:METHOD:FIRST8...LAST8`, with the
    // `did::channel:FIRST8...LAST8` special case for `did:web:host:channel:UUID`)
    // so operators see identical strings in the dashboard and the audit
    // export. Non-`did:` values (including blank strings, a permitted
    // element config) pass through unchanged. `None` (the target-leg
    // "unavailable" pre-check paths) is forwarded verbatim so the JSONL
    // omits the field, matching the wire shape.
    if crate::storage::settings_store::global_settings()
        .map(|s| s.audit_category_enabled("trust_checks"))
        .unwrap_or(false)
    {
        let (authority_display, entity_display) = redacted_ids_for_audit(authority_id, entity_id);
        crate::delegation_vault::audit::audit_trust_check(
            leg_str,
            authority_display.as_deref(),
            entity_display.as_deref(),
            ok,
            error_code,
        );
    }
}

/// Produce the audit-log display forms of `authority_id` / `entity_id`
/// using the shared [`crate::observability::did_display::format_did`]
/// (defaults `first = 8`, `last = 8`). `None` is preserved so the JSONL
/// omits the field on the target-leg "unavailable" pre-check paths.
fn redacted_ids_for_audit(
    authority_id: Option<&str>,
    entity_id: Option<&str>,
) -> (Option<String>, Option<String>) {
    (
        authority_id.map(|id| crate::observability::did_display::format_did(id, 8, 8)),
        entity_id.map(|id| crate::observability::did_display::format_did(id, 8, 8)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leg_labels_are_stable() {
        assert_eq!(leg_label(TrustCheckLeg::Caller), "caller");
        assert_eq!(leg_label(TrustCheckLeg::Target), "target");
    }

    #[test]
    fn query_type_labels_are_stable() {
        assert_eq!(query_type_label(TrqpQueryType::Authorization), "authorization");
        assert_eq!(query_type_label(TrqpQueryType::Recognition), "recognition");
    }

    #[test]
    fn result_label_partitions_outcome_space() {
        assert_eq!(result_label(true, None), RESULT_OK);
        assert_eq!(result_label(true, Some("ignored")), RESULT_OK);
        assert_eq!(result_label(false, None), RESULT_ERROR);
        assert_eq!(result_label(false, Some(NOT_RECOGNIZED)), RESULT_DENIED);
        assert_eq!(result_label(false, Some(NOT_AUTHORIZED)), RESULT_DENIED);
        assert_eq!(result_label(false, Some("TRUST_REGISTRY_UNREACHABLE")), RESULT_ERROR);
        assert_eq!(result_label(false, Some("TRUST_REGISTRY_PARSE_ERROR")), RESULT_ERROR);
    }

    #[test]
    fn record_does_not_panic_on_any_path() {
        record_trust_check(TrustCheckAuditEvent {
            surface_id: "surf-1",
            leg: TrustCheckLeg::Caller,
            element_id: "tc-1",
            element_name: None,
            authority_id: Some("did:authority:a"),
            entity_id: Some("did:entity:a"),
            trust_registry_id: "tr-a",
            query_type: TrqpQueryType::Recognition,
            ok: true,
            error_code: None,
            error_detail: None,
            latency_ms: 12,
        });
        record_trust_check(TrustCheckAuditEvent {
            surface_id: "surf-1",
            leg: TrustCheckLeg::Target,
            element_id: "tc-2",
            element_name: Some("primary"),
            authority_id: Some("did:authority:a"),
            entity_id: Some("did:entity:b"),
            trust_registry_id: "tr-a",
            query_type: TrqpQueryType::Authorization,
            ok: false,
            error_code: None,
            error_detail: None,
            latency_ms: 8,
        });
        record_trust_check(TrustCheckAuditEvent {
            surface_id: "surf-1",
            leg: TrustCheckLeg::Caller,
            element_id: "tc-3",
            element_name: Some("departmental"),
            authority_id: Some("did:authority:b"),
            entity_id: Some("did:entity:c"),
            trust_registry_id: "tr-b",
            query_type: TrqpQueryType::Recognition,
            ok: false,
            error_code: Some("TRUST_REGISTRY_UNREACHABLE"),
            error_detail: Some("no active trust registry connection for id 'tr-b'"),
            latency_ms: 0,
        });
    }

    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

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

        fn record_u64(
            &mut self,
            field: &Field,
            value: u64,
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
    fn ok_event_carries_full_structured_context_at_debug() {
        let captured = capture(|| {
            record_trust_check(TrustCheckAuditEvent {
                surface_id: "surface-a",
                leg: TrustCheckLeg::Caller,
                element_id: "tc-id-a",
                element_name: Some("primary registry"),
                authority_id: Some("did:authority:42"),
                entity_id: Some("did:entity:42"),
                trust_registry_id: "tr-42",
                query_type: TrqpQueryType::Recognition,
                ok: true,
                error_code: None,
                error_detail: None,
                latency_ms: 17,
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-a"))
            .expect("trust check audit event not captured");

        assert_eq!(ev.level, "DEBUG");
        assert_eq!(field(ev, "leg"), Some("caller"));
        assert_eq!(field(ev, "element_id"), Some("tc-id-a"));
        assert_eq!(field(ev, "element_name"), Some("primary registry"));
        assert_eq!(field(ev, "trust_registry_id"), Some("tr-42"));
        assert_eq!(field(ev, "query_type"), Some("recognition"));
        assert_eq!(field(ev, "result"), Some("ok"));
        assert_eq!(field(ev, "ok"), Some("true"));
        assert_eq!(field(ev, "error_code"), Some(""));
        assert_eq!(field(ev, "latency_ms"), Some("17"));
    }

    #[test]
    fn unclassified_negative_event_emits_at_warn_and_maps_to_error() {
        // With the negative-verdict codes, every clean TRQP deny now carries
        // NOT_RECOGNIZED or NOT_AUTHORIZED; `error_code = None` on a `!ok`
        // event is an unclassified anomaly, not a clean deny, so
        // `result_label` routes it to `error` rather than `denied`.
        let captured = capture(|| {
            record_trust_check(TrustCheckAuditEvent {
                surface_id: "surface-b",
                leg: TrustCheckLeg::Target,
                element_id: "tc-id-b",
                element_name: None,
                authority_id: Some("did:authority:99"),
                entity_id: Some("did:entity:99"),
                trust_registry_id: "tr-99",
                query_type: TrqpQueryType::Authorization,
                ok: false,
                error_code: None,
                error_detail: None,
                latency_ms: 23,
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-b"))
            .expect("trust check audit event not captured");

        assert_eq!(ev.level, "WARN");
        assert_eq!(field(ev, "leg"), Some("target"));
        assert_eq!(field(ev, "element_id"), Some("tc-id-b"));
        assert_eq!(field(ev, "element_name"), Some(""));
        assert_eq!(field(ev, "trust_registry_id"), Some("tr-99"));
        assert_eq!(field(ev, "query_type"), Some("authorization"));
        assert_eq!(field(ev, "result"), Some("error"));
        assert_eq!(field(ev, "ok"), Some("false"));
        assert_eq!(field(ev, "error_code"), Some(""));
        assert_eq!(field(ev, "latency_ms"), Some("23"));
    }

    #[test]
    fn not_recognized_event_emits_at_warn_with_result_denied() {
        let captured = capture(|| {
            record_trust_check(TrustCheckAuditEvent {
                surface_id: "surface-nr",
                leg: TrustCheckLeg::Caller,
                element_id: "tc-id-nr",
                element_name: None,
                authority_id: Some("did:authority:nr"),
                entity_id: Some("did:entity:nr"),
                trust_registry_id: "tr-nr",
                query_type: TrqpQueryType::Recognition,
                ok: false,
                error_code: Some(NOT_RECOGNIZED),
                error_detail: Some("Registry answered `recognized: false`"),
                latency_ms: 42,
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-nr"))
            .expect("trust check audit event not captured");

        assert_eq!(ev.level, "WARN", "denials must stay WARN so the audit page still lists them");
        assert_eq!(field(ev, "result"), Some("denied"), "NOT_RECOGNIZED must map to the `denied` Prometheus label");
        assert_eq!(field(ev, "error_code"), Some("NOT_RECOGNIZED"));
        assert_eq!(field(ev, "error_detail"), Some("Registry answered `recognized: false`"));
    }

    #[test]
    fn not_authorized_event_emits_at_warn_with_result_denied() {
        let captured = capture(|| {
            record_trust_check(TrustCheckAuditEvent {
                surface_id: "surface-na",
                leg: TrustCheckLeg::Caller,
                element_id: "tc-id-na",
                element_name: None,
                authority_id: Some("did:authority:na"),
                entity_id: Some("did:entity:na"),
                trust_registry_id: "tr-na",
                query_type: TrqpQueryType::Authorization,
                ok: false,
                error_code: Some(NOT_AUTHORIZED),
                error_detail: Some("Registry returned empty response body \u{2014} no matching trust record"),
                latency_ms: 55,
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-na"))
            .expect("trust check audit event not captured");

        assert_eq!(ev.level, "WARN");
        assert_eq!(field(ev, "result"), Some("denied"));
        assert_eq!(field(ev, "error_code"), Some("NOT_AUTHORIZED"));
    }

    #[test]
    fn error_event_emits_at_warn_with_error_code_and_zero_latency() {
        let captured = capture(|| {
            record_trust_check(TrustCheckAuditEvent {
                surface_id: "surface-c",
                leg: TrustCheckLeg::Caller,
                element_id: "tc-id-c",
                element_name: Some("departmental"),
                authority_id: Some("did:authority:7"),
                entity_id: Some("did:entity:7"),
                trust_registry_id: "tr-7",
                query_type: TrqpQueryType::Recognition,
                ok: false,
                error_code: Some("TRUST_REGISTRY_UNREACHABLE"),
                error_detail: Some("no active trust registry connection for id 'tr-7'"),
                latency_ms: 0,
            });
        });

        let ev = captured
            .iter()
            .find(|e| field(e, "surface_id") == Some("surface-c"))
            .expect("trust check audit event not captured");

        assert_eq!(ev.level, "WARN");
        assert_eq!(field(ev, "result"), Some("error"));
        assert_eq!(field(ev, "ok"), Some("false"));
        assert_eq!(field(ev, "element_id"), Some("tc-id-c"));
        assert_eq!(field(ev, "element_name"), Some("departmental"));
        assert_eq!(field(ev, "error_code"), Some("TRUST_REGISTRY_UNREACHABLE"));
        assert_eq!(
            field(ev, "error_detail"),
            Some("no active trust registry connection for id 'tr-7'"),
            "WARN event must carry the per-failure detail so operators can diagnose without DEBUG"
        );
        assert_eq!(field(ev, "latency_ms"), Some("0"));
    }

    #[test]
    fn audit_truncates_authority_and_entity_ids() {
        let (authority, entity) = redacted_ids_for_audit(
            Some("did:web:agent-gateway-1.example.com:channel:1524042a-2339-4e08-af51-2c5fd43f7b7e"),
            Some("did:key:aaaaaaaabbbbbbbbccccccccdddddddd"),
        );
        assert_eq!(authority.as_deref(), Some("did::channel:1524042a...d43f7b7e"));
        assert_eq!(entity.as_deref(), Some("did:key:aaaaaaaa...dddddddd"));
    }

    #[test]
    fn audit_passthrough_for_non_did_values() {
        // Non-`did:` prefixed values (blank, URI-style, opaque) pass
        // through unchanged. Blank `entity_id` is a permitted element
        // config today; the truncator must not mangle it into anything
        // else so Rego rules keying off `r.entity_id == ""` keep working
        // and audit rows still show a blank cell.
        let (authority, entity) = redacted_ids_for_audit(Some("https://example.com/authority"), Some(""));
        assert_eq!(authority.as_deref(), Some("https://example.com/authority"));
        assert_eq!(entity.as_deref(), Some(""));
    }

    #[test]
    fn audit_omits_ids_when_none() {
        // Target-leg pre-check paths (`AGENT_CARD_UNAVAILABLE`,
        // `TRUST_REGISTRY_METADATA_UNAVAILABLE`) pass `None` so the
        // JSONL audit sink omits the fields, matching the wire shape
        // of `TrustCheckResult`.
        let (authority, entity) = redacted_ids_for_audit(None, None);
        assert!(authority.is_none());
        assert!(entity.is_none());
    }
}
