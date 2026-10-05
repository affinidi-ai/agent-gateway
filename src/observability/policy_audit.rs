//! Structured audit logging for OPA policy decisions.
//!
//! Every policy evaluation point in the request pipeline (gateway-level,
//! surface-level, MCP tool-level, and response-level) emits a single
//! structured event through [`record_policy_decision`]. Denials are emitted
//! at `WARN` so they reach the OpenTelemetry log exporter; allows are emitted
//! at `DEBUG` so the allow/deny ratio is observable when the operator opts
//! into a more verbose level, without flooding default-level logs.
//!
//! The event carries the full decision context — trace id, policy scope and
//! id, caller identity (auth method, principal, derived DID), the resolved
//! actor/gateway DID, HTTP method/path, and the surface identifier — so a
//! single log line (or its OTEL counterpart) fully describes the decision.
//! Because the event fires inside the active request span it is automatically
//! correlated to the distributed trace.
//!
//! This module is logging-only: it never alters the HTTP response returned to
//! a caller.
//!
//! ## Per-request VP embedding
//!
//! When a task-local [`POLICY_DECISION_COLLECTOR`] scope is active (installed
//! by `multi_channel_proxy_handler` around the entire request), every decision is also
//! pushed into a lightweight [`PolicyDecisionSummary`] list. The workload
//! binding builder reads this list from [`POLICY_DECISION_COLLECTOR`] and embeds
//! it as `policyDecisions` in the VP minted for that request — so the signed VP
//! carries a cryptographic proof of every allow/deny decision that governed it.
//! Embedding is gated by the `policies` VP audit category (Settings › Security):
//! the builder skips embedding when it is disabled, so operators
//! can turn off all policy-decision evidence recording.

use std::sync::{Arc, Mutex};

use crate::source_auth::AuthenticatedIdentity;

/// Full policy-decision record embedded in the workload-binding VP.
/// Being inside the signed VP makes every field tamper-evident.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyDecisionSummary {
    /// Stable per-decision identifier: SHA-256(scope|policy|decision|deny_reason|trace_id).
    /// Appears in both this audit entry and the signed VP — match them to prove attestation.
    pub id: String,
    /// "gateway" | "surface" | "mcp_tool" | "response"
    pub scope: &'static str,
    /// "access_point" | "transit_point" | "fabric" — which request flow produced
    /// the decision (ingress vs egress vs fabric-received).
    pub flow: &'static str,
    /// Human-readable policy name. Operator-assigned definition name when set;
    /// falls back to the Rego package name (e.g. "surface.policy").
    pub policy_name: String,
    /// Policy/definition identifier (e.g. the Rego package `gateway.policy` /
    /// `surface.policy`, or the definition id for response/MCP scopes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// The stored policy-definition record id (UUID), when backed by a
    /// definition — lets a verifier link the decision to the policy record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_definition_id: Option<String>,
    /// "allow" | "deny"
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
    /// Monotonic version of the enforced policy revision, when versioned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u32>,
    /// `sha256:<hex>` content hash of the exact Rego enforced — the attestation
    /// primitive that resolves the decision to specific bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_content_hash: Option<String>,
}

fn compute_decision_id(
    scope: &str,
    policy: &str,
    decision: &str,
    deny_reason: Option<&str>,
    trace_id: Option<&str>,
) -> String {
    use sha2::{Digest, Sha256};
    let input = format!("{}|{}|{}|{}|{}", scope, policy, decision, deny_reason.unwrap_or(""), trace_id.unwrap_or(""),);
    format!("sha256:{}", hex::encode(Sha256::digest(input.as_bytes())))
}

tokio::task_local! {
    /// Per-request collector for policy decisions. Installed by `multi_channel_proxy_handler`
    /// around the inner handler call; absent in all other contexts (e.g. tests,
    /// background tasks) where `try_with` silently returns `Err`.
    pub static POLICY_DECISION_COLLECTOR: Arc<Mutex<Vec<PolicyDecisionSummary>>>;

    /// Per-request trace id installed by non-HTTP entry points (e.g. the fabric
    /// `ForwardRequest` dispatch, seeded from the inbound message's `trace_id`)
    /// so a request's audit events + policy decisions share a `trace_id` even
    /// when no OTEL exporter is configured. Absent elsewhere (`try_with` errs).
    pub static REQUEST_TRACE_ID: String;
}

/// Snapshot the current decisions as a JSON array for embedding in a VP.
/// Returns `None` when the collector is empty or inactive.
///
/// Also returns `None` when the operator has not enabled the `policies` VP
/// audit category (Settings › Security): disabling policy-decision auditing
/// stops the signed `policyDecisions` from being embedded in minted VPs, so the
/// switch governs *all* policy-decision evidence recording, not just the JSONL
/// audit log.
pub fn current_policy_decisions() -> Option<serde_json::Value> {
    let policies_audit_enabled = crate::storage::settings_store::global_settings()
        .map(|s| s.audit_category_enabled("policies"))
        .unwrap_or(false);
    if !policies_audit_enabled {
        return None;
    }
    POLICY_DECISION_COLLECTOR
        .try_with(|q| {
            let g = q.lock().ok()?;
            if g.is_empty() {
                return None;
            }
            serde_json::to_value(&*g).ok()
        })
        .ok()
        .flatten()
}

/// Push a decision into the per-request collector (no-op when no scope is active).
pub fn push_policy_decision(summary: PolicyDecisionSummary) {
    let _ = POLICY_DECISION_COLLECTOR.try_with(|q| {
        if let Ok(mut g) = q.lock() {
            g.push(summary);
        }
    });
}

/// Best-effort trace id for the current request, as a lowercase hex string.
/// Prefers the explicit `REQUEST_TRACE_ID` task-local (set by non-HTTP paths
/// from the inbound message), then falls back to the active OTEL span. `None`
/// when neither is available. Lets audit events on non-HTTP paths (e.g. the
/// fabric `process_forward_request`) share a `trace_id` with the request's
/// policy decisions and injected VP without threading it through call sites,
/// and without requiring an OTEL exporter.
pub fn current_span_trace_id() -> Option<String> {
    if let Some(id) = REQUEST_TRACE_ID
        .try_with(|t| (!t.is_empty()).then(|| t.clone()))
        .ok()
        .flatten()
    {
        return Some(id);
    }
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let cx = tracing::Span::current().context();
    let span_context = cx
        .span()
        .span_context()
        .clone();
    span_context
        .is_valid()
        .then(|| {
            span_context
                .trace_id()
                .to_string()
        })
}

/// Which policy evaluation point produced a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyScope {
    /// Gateway-level OPA (evaluated before surface policy; deny is final).
    Gateway,
    /// Surface-level OPA.
    #[default]
    Surface,
    /// MCP tool-level RBAC policy.
    McpTool,
    /// Response-leg policy (outbound payload to the caller).
    Response,
}

impl PolicyScope {
    /// Stable, low-cardinality label used in the structured event.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyScope::Gateway => "gateway",
            PolicyScope::Surface => "surface",
            PolicyScope::McpTool => "mcp_tool",
            PolicyScope::Response => "response",
        }
    }
}

/// Which request flow a policy decision belongs to, so the Audit Log can tell
/// ingress from egress. Defaults to [`PolicyFlow::AccessPoint`] because the
/// direct inbound path is the overwhelmingly common case and its call sites
/// rely on the default; the egress and fabric-receive paths set their flow
/// explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyFlow {
    /// Inbound request at the surface's Access Point — the direct listener, or
    /// the `fabric://` send leg which is still triggered by an inbound request.
    #[default]
    AccessPoint,
    /// Outbound request leaving through a Transit Point (egress).
    TransitPoint,
    /// Inbound request received over Fabric (G2G) at a connection point (GW2).
    Fabric,
}

impl PolicyFlow {
    /// Stable, low-cardinality label used in the structured event.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyFlow::AccessPoint => "access_point",
            PolicyFlow::TransitPoint => "transit_point",
            PolicyFlow::Fabric => "fabric",
        }
    }
}

/// Caller-identity fields lifted off an [`AuthenticatedIdentity`] for the
/// audit event: `(auth_method, principal, did)`. `did` is populated only for
/// `did_auth` (the credential *is* a DID); every other mode carries its
/// derived DID via [`PolicyDecisionEvent::actor_did`].
fn caller_fields(identity: &AuthenticatedIdentity) -> (&'static str, String, Option<String>) {
    match identity {
        AuthenticatedIdentity::JwtBearer { subject, .. } => ("jwt_bearer", subject.clone(), None),
        AuthenticatedIdentity::ApiKey { key_name } => ("api_key", key_name.clone(), None),
        AuthenticatedIdentity::DidAuth { did } => ("did_auth", did.clone(), Some(did.clone())),
        AuthenticatedIdentity::Mtls { principal, .. } => ("mtls", principal.clone(), None),
    }
}

/// The caller a decision is attributed to in the VP Audit Log: the leg's own
/// authenticated identity, else the caller context carried onto it.
fn decision_caller(event: &PolicyDecisionEvent<'_>) -> Option<crate::delegation_vault::audit::AuditCallerContext> {
    event
        .identity
        .map(crate::delegation_vault::audit::build_caller_context)
        .or_else(|| event.caller.cloned())
}

/// A single policy decision to be recorded. Optional fields are tolerated so
/// the same shape works at every evaluation point regardless of how much
/// context has been resolved by the time the decision is made (e.g. the
/// gateway-level check runs before the actor DID is derived).
#[derive(Debug, Default)]
pub struct PolicyDecisionEvent<'a> {
    /// Which evaluation point produced the decision.
    pub scope: PolicyScope,
    /// `true` = allowed, `false` = denied.
    pub allow: bool,
    /// Human-readable deny reason, when the policy supplied one.
    pub reason: Option<&'a str>,
    /// Policy/definition identifier — for gateway/surface scopes this is the
    /// Rego package (`gateway.policy` / `surface.policy`); for response/MCP
    /// scopes it is the stored policy-definition id.
    pub policy_id: Option<&'a str>,
    /// The stored policy-definition record id (UUID), when the evaluated policy
    /// is backed by a definition. Lets the Audit Log link straight to the
    /// policy record. `None` for the built-in allow-all default (no definition).
    pub policy_definition_id: Option<&'a str>,
    /// Human-readable policy name (e.g. the operator-assigned definition name).
    /// When `None`, falls back to `policy_id` in the VP `policyDecisions` array.
    pub policy_name: Option<&'a str>,
    /// Surface/channel identifier the decision applies to.
    pub surface_id: Option<&'a str>,
    /// Per-request trace identifier for log/trace correlation.
    pub trace_id: Option<&'a str>,
    /// HTTP method of the request under evaluation.
    pub http_method: Option<&'a str>,
    /// Request path under evaluation.
    pub path: Option<&'a str>,
    /// Authenticated caller identity, when source auth resolved one.
    pub identity: Option<&'a AuthenticatedIdentity>,
    /// Caller context for a leg with no authenticated identity of its own,
    /// such as the one a transit token carries onto a Transit Point. Used
    /// only when `identity` is `None`.
    pub caller: Option<&'a crate::delegation_vault::audit::AuditCallerContext>,
    /// Resolved/derived agent DID for the request, when available.
    pub actor_did: Option<&'a str>,
    /// Identifier (or DID) of the gateway making the decision.
    pub gateway_did: Option<&'a str>,
    /// Which request flow produced the decision (access point / transit point /
    /// fabric). Defaults to `AccessPoint`.
    pub flow: PolicyFlow,
    /// Monotonic version of the enforced policy revision, when the evaluated
    /// policy is backed by a versioned definition.
    pub policy_version: Option<u32>,
    /// `sha256:<hex>` content hash of the exact Rego enforced (attestation).
    pub policy_content_hash: Option<&'a str>,
}

/// Emit one structured event describing a policy decision.
///
/// Denials are logged at `WARN` (reaching the OTEL log exporter); allows at
/// `DEBUG`. The event is emitted within the active request span, so it is
/// correlated to the distributed trace automatically.
pub fn record_policy_decision(event: PolicyDecisionEvent<'_>) {
    let (auth_method, principal, did_from_identity) = match event.identity {
        Some(id) => caller_fields(id),
        None => ("none", String::new(), None),
    };

    let caller_did = event
        .actor_did
        .map(str::to_string)
        .or(did_from_identity)
        .unwrap_or_default();

    let decision = if event.allow {
        "allow"
    } else {
        "deny"
    };
    let scope = event.scope.as_str();
    let flow = event.flow.as_str();
    let reason = event
        .reason
        .unwrap_or_default();
    let policy_id = event
        .policy_id
        .unwrap_or_default();
    let policy_definition_id = event
        .policy_definition_id
        .unwrap_or_default();
    let surface_id = event
        .surface_id
        .unwrap_or_default();
    // Fall back to the active span's OTEL trace id when the caller didn't set
    // one (e.g. the fabric path), so every decision + the injected VP for a
    // request share a `trace_id` (Audit correlation + the "This request" filter).
    let resolved_trace_id: Option<String> = event
        .trace_id
        .map(str::to_string)
        .or_else(current_span_trace_id);
    let trace_id = resolved_trace_id
        .as_deref()
        .unwrap_or_default();
    let http_method = event
        .http_method
        .unwrap_or_default();
    let path = event.path.unwrap_or_default();
    let gateway_did = event
        .gateway_did
        .unwrap_or_default();
    let policy_version_str = event
        .policy_version
        .map(|v| v.to_string())
        .unwrap_or_default();
    let policy_content_hash = event
        .policy_content_hash
        .unwrap_or_default();

    if event.allow {
        tracing::debug!(
            target: "policy_audit",
            policy_scope = scope,
            policy_flow = flow,
            policy_decision = decision,
            policy_id = policy_id,
            policy_definition_id = policy_definition_id,
            deny_reason = reason,
            surface_id = surface_id,
            gateway_did = gateway_did,
            actor_did = caller_did.as_str(),
            caller_auth_method = auth_method,
            caller_principal = principal.as_str(),
            caller_did = caller_did.as_str(),
            http_method = http_method,
            http_path = path,
            trace_id = trace_id,
            policy_version = policy_version_str.as_str(),
            policy_content_hash = policy_content_hash,
            "policy decision: allow"
        );
    } else {
        tracing::warn!(
            target: "policy_audit",
            policy_scope = scope,
            policy_flow = flow,
            policy_decision = decision,
            policy_id = policy_id,
            policy_definition_id = policy_definition_id,
            deny_reason = reason,
            surface_id = surface_id,
            gateway_did = gateway_did,
            actor_did = caller_did.as_str(),
            caller_auth_method = auth_method,
            caller_principal = principal.as_str(),
            caller_did = caller_did.as_str(),
            http_method = http_method,
            http_path = path,
            trace_id = trace_id,
            policy_version = policy_version_str.as_str(),
            policy_content_hash = policy_content_hash,
            "policy decision: deny"
        );
    }

    // Whether operators enabled recording of policy-decision evidence. This
    // single switch gates BOTH the JSONL VP audit log entry and the signed
    // `policyDecisions` embedded in the minted VP, so disabling the category in
    // Settings › Security stops all policy-decision evidence recording (not just
    // the JSONL log). The structured `policy_audit` tracing events above are
    // always emitted for operational observability and are unaffected.
    let policies_audit_enabled = crate::storage::settings_store::global_settings()
        .map(|s| s.audit_category_enabled("policies"))
        .unwrap_or(false);

    // Write to VP audit log when the policies category is enabled.
    if policies_audit_enabled {
        let is_allow = event.allow;
        crate::delegation_vault::audit::audit_policy_decision(
            scope,
            is_allow,
            policy_id,
            event.policy_name,
            event.policy_definition_id,
            if is_allow {
                None
            } else {
                Some(reason)
            },
            if surface_id.is_empty() {
                None
            } else {
                Some(surface_id)
            },
            if caller_did.is_empty() {
                None
            } else {
                Some(caller_did.as_str())
            },
            if http_method.is_empty() {
                None
            } else {
                Some(http_method)
            },
            if path.is_empty() {
                None
            } else {
                Some(path)
            },
            resolved_trace_id.as_deref(),
            flow,
            event.policy_version,
            event.policy_content_hash,
            decision_caller(&event),
        );
    }

    // Push the full decision into the per-request VP collector so the signed VP
    // carries a tamper-evident record of every decision that governed this
    // request. The collector is always populated; whether these decisions are
    // actually embedded into a minted VP is gated at the embedding site by the
    // same `policies` audit category.
    let is_allow = event.allow;
    let deny_reason_val = if is_allow {
        None
    } else {
        event
            .reason
            .map(str::to_string)
    };
    let decision_str = if is_allow {
        "allow"
    } else {
        "deny"
    };
    let id =
        compute_decision_id(scope, policy_id, decision_str, deny_reason_val.as_deref(), resolved_trace_id.as_deref());
    // Use the operator-assigned definition name when available; fall back to the Rego package name.
    let policy_name_val = event
        .policy_name
        .filter(|n| !n.is_empty())
        .unwrap_or(policy_id)
        .to_string();
    push_policy_decision(PolicyDecisionSummary {
        id,
        scope: event.scope.as_str(),
        flow,
        policy_name: policy_name_val,
        policy_id: if policy_id.is_empty() {
            None
        } else {
            Some(policy_id.to_string())
        },
        policy_definition_id: event
            .policy_definition_id
            .filter(|d| !d.is_empty())
            .map(str::to_string),
        decision: decision_str,
        deny_reason: deny_reason_val,
        surface_id: if surface_id.is_empty() {
            None
        } else {
            Some(surface_id.to_string())
        },
        caller_did: if caller_did.is_empty() {
            None
        } else {
            Some(caller_did.to_string())
        },
        http_method: if http_method.is_empty() {
            None
        } else {
            Some(http_method.to_string())
        },
        http_path: if path.is_empty() {
            None
        } else {
            Some(path.to_string())
        },
        policy_version: event.policy_version,
        policy_content_hash: event
            .policy_content_hash
            .map(str::to_string),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_labels_are_stable() {
        assert_eq!(PolicyScope::Gateway.as_str(), "gateway");
        assert_eq!(PolicyScope::Surface.as_str(), "surface");
        assert_eq!(PolicyScope::McpTool.as_str(), "mcp_tool");
        assert_eq!(PolicyScope::Response.as_str(), "response");
    }

    #[test]
    fn caller_fields_map_each_identity_variant() {
        let jwt = AuthenticatedIdentity::JwtBearer {
            subject: "sub-123".to_string(),
            claims: serde_json::json!({}),
        };
        let (method, principal, did) = caller_fields(&jwt);
        assert_eq!(method, "jwt_bearer");
        assert_eq!(principal, "sub-123");
        assert_eq!(did, None);

        let api = AuthenticatedIdentity::ApiKey { key_name: "key-a".to_string() };
        let (method, principal, did) = caller_fields(&api);
        assert_eq!(method, "api_key");
        assert_eq!(principal, "key-a");
        assert_eq!(did, None);

        let dida = AuthenticatedIdentity::DidAuth {
            did: "did:example:abc".to_string(),
        };
        let (method, principal, did) = caller_fields(&dida);
        assert_eq!(method, "did_auth");
        assert_eq!(principal, "did:example:abc");
        assert_eq!(did.as_deref(), Some("did:example:abc"));
    }

    #[test]
    fn decision_caller_prefers_the_authenticated_identity_over_a_carried_caller() {
        let identity = AuthenticatedIdentity::JwtBearer {
            subject: "user-123".to_string(),
            claims: serde_json::json!({"email": "ada@example.com"}),
        };
        let carried = crate::delegation_vault::audit::AuditCallerContext {
            auth_method: "transit_token".to_string(),
            iss: None,
            aud: None,
            sub: Some("did:web:caller".to_string()),
            token_id: None,
            email: Some("carried@example.com".to_string()),
            name: None,
            email_redacted: None,
            name_redacted: None,
            mtls_fingerprint: None,
            mtls_subject_dn: None,
            mtls_issuer_dn: None,
            mtls_source: None,
        };

        let authenticated = decision_caller(&PolicyDecisionEvent {
            identity: Some(&identity),
            caller: Some(&carried),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(authenticated.auth_method, "jwt_bearer");
        assert_eq!(authenticated.email.as_deref(), Some("ada@example.com"));

        let transit = decision_caller(&PolicyDecisionEvent {
            caller: Some(&carried),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(transit.auth_method, "transit_token");
        assert_eq!(transit.email.as_deref(), Some("carried@example.com"));

        assert!(decision_caller(&PolicyDecisionEvent::default()).is_none(), "no caller context, no principal");
    }

    #[test]
    fn record_decision_does_not_panic_with_minimal_context() {
        record_policy_decision(PolicyDecisionEvent {
            scope: PolicyScope::Gateway,
            allow: false,
            reason: Some("blocked"),
            ..Default::default()
        });
        record_policy_decision(PolicyDecisionEvent {
            scope: PolicyScope::Surface,
            allow: true,
            ..Default::default()
        });
    }

    #[tokio::test]
    async fn summary_carries_both_policy_id_and_name() {
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), async {
                record_policy_decision(PolicyDecisionEvent {
                    scope: PolicyScope::Surface,
                    allow: true,
                    policy_id: Some("surface.policy"),
                    policy_definition_id: Some("def-uuid-42"),
                    policy_name: Some("My Surface Policy"),
                    ..Default::default()
                });
            })
            .await;

        let decisions = collector.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            decisions[0]
                .policy_id
                .as_deref(),
            Some("surface.policy")
        );
        assert_eq!(
            decisions[0]
                .policy_definition_id
                .as_deref(),
            Some("def-uuid-42")
        );
        assert_eq!(decisions[0].policy_name, "My Surface Policy");
    }

    #[tokio::test]
    async fn summary_policy_name_falls_back_to_id_when_unset() {
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        POLICY_DECISION_COLLECTOR
            .scope(collector.clone(), async {
                record_policy_decision(PolicyDecisionEvent {
                    scope: PolicyScope::Gateway,
                    allow: false,
                    reason: Some("blocked"),
                    policy_id: Some("gateway.policy"),
                    policy_name: None,
                    ..Default::default()
                });
            })
            .await;

        let decisions = collector.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            decisions[0]
                .policy_id
                .as_deref(),
            Some("gateway.policy")
        );
        // With no operator name, the summary name falls back to the policy id.
        assert_eq!(decisions[0].policy_name, "gateway.policy");
    }

    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    /// Captures every field of every event into `(name, value)` string pairs,
    /// together with the event's level, so a test can assert the structured
    /// shape of an emitted policy-decision event.
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

    #[test]
    fn deny_event_carries_full_structured_context_at_warn() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CapturingLayer { events: events.clone() });

        tracing::subscriber::with_default(subscriber, || {
            let identity = AuthenticatedIdentity::ApiKey {
                key_name: "alpha-key".to_string(),
            };
            record_policy_decision(PolicyDecisionEvent {
                scope: PolicyScope::Surface,
                allow: false,
                reason: Some("trust check failed"),
                policy_id: Some("pol-7"),
                policy_definition_id: Some("def-uuid-7"),
                policy_name: None,
                surface_id: Some("surface-a"),
                trace_id: Some("trace-xyz"),
                http_method: Some("POST"),
                path: Some("/v1/agent"),
                identity: Some(&identity),
                actor_did: Some("did:example:agent"),
                gateway_did: Some("did:web:gw1"),
                flow: PolicyFlow::TransitPoint,
                policy_version: Some(3),
                policy_content_hash: Some("sha256:abc123"),
                caller: None,
            });
        });

        let captured = events.lock().unwrap();
        let ev = captured
            .iter()
            .find(|e| field(e, "policy_scope") == Some("surface"))
            .expect("policy decision event not captured");

        assert_eq!(ev.level, "WARN");
        assert_eq!(field(ev, "policy_decision"), Some("deny"));
        assert_eq!(field(ev, "policy_flow"), Some("transit_point"));
        assert_eq!(field(ev, "deny_reason"), Some("trust check failed"));
        assert_eq!(field(ev, "policy_id"), Some("pol-7"));
        assert_eq!(field(ev, "surface_id"), Some("surface-a"));
        assert_eq!(field(ev, "trace_id"), Some("trace-xyz"));
        assert_eq!(field(ev, "http_method"), Some("POST"));
        assert_eq!(field(ev, "http_path"), Some("/v1/agent"));
        assert_eq!(field(ev, "caller_auth_method"), Some("api_key"));
        assert_eq!(field(ev, "caller_principal"), Some("alpha-key"));
        assert_eq!(field(ev, "actor_did"), Some("did:example:agent"));
        assert_eq!(field(ev, "caller_did"), Some("did:example:agent"));
        assert_eq!(field(ev, "gateway_did"), Some("did:web:gw1"));
        assert_eq!(field(ev, "policy_version"), Some("3"));
        assert_eq!(field(ev, "policy_content_hash"), Some("sha256:abc123"));
    }

    #[test]
    fn allow_event_is_emitted_at_debug() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CapturingLayer { events: events.clone() });

        tracing::subscriber::with_default(subscriber, || {
            record_policy_decision(PolicyDecisionEvent {
                scope: PolicyScope::Gateway,
                allow: true,
                surface_id: Some("surface-b"),
                ..Default::default()
            });
        });

        let captured = events.lock().unwrap();
        let ev = captured
            .iter()
            .find(|e| field(e, "policy_scope") == Some("gateway"))
            .expect("allow decision event not captured");

        assert_eq!(ev.level, "DEBUG");
        assert_eq!(field(ev, "policy_decision"), Some("allow"));
    }

    #[test]
    fn did_auth_identity_populates_caller_did_without_actor_did() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CapturingLayer { events: events.clone() });

        tracing::subscriber::with_default(subscriber, || {
            let identity = AuthenticatedIdentity::DidAuth {
                did: "did:example:caller".to_string(),
            };
            record_policy_decision(PolicyDecisionEvent {
                scope: PolicyScope::McpTool,
                allow: false,
                identity: Some(&identity),
                ..Default::default()
            });
        });

        let captured = events.lock().unwrap();
        let ev = captured
            .iter()
            .find(|e| field(e, "policy_scope") == Some("mcp_tool"))
            .expect("decision event not captured");

        assert_eq!(field(ev, "caller_auth_method"), Some("did_auth"));
        assert_eq!(field(ev, "caller_did"), Some("did:example:caller"));
    }
}
