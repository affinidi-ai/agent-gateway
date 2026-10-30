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
//! ## Per-request collection
//!
//! When a task-local [`POLICY_DECISION_COLLECTOR`] scope is active (installed
//! by `multi_channel_proxy_handler` and the fabric `ForwardRequest` dispatch
//! around the entire request), every decision is also pushed into a
//! lightweight [`PolicyDecisionSummary`] list for that request. The list is
//! never embedded in a minted VP: what goes on the wire to another gateway
//! does not depend on audit configuration.

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
    /// Human-readable policy name: the operator-assigned definition name, else
    /// the definition id, else a layer label such as "Surface policy".
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

    /// The gateway request being served, installed at each entry point
    /// (Access Point, Transit Point, fabric receive, authenticated management
    /// API request). Its id and variant are stamped on every audit record the
    /// request produces.
    static REQUEST: Arc<RequestScope>;
}

/// One gateway request: its id, minted here and never read from a header or
/// token, and the surface variant routing resolved it to, set once routing
/// knows it.
#[derive(Debug)]
pub struct RequestScope {
    id: String,
    variant: std::sync::OnceLock<String>,
}

impl RequestScope {
    /// A request with id `id` and no variant yet.
    pub fn new(id: String) -> Arc<Self> {
        Arc::new(Self {
            id,
            variant: std::sync::OnceLock::new(),
        })
    }

    /// A request with a fresh id.
    pub fn fresh() -> Arc<Self> {
        Self::new(new_request_id())
    }
}

/// A fresh request id: a W3C span id (16 lowercase hex characters, never all
/// zero).
fn new_request_id() -> String {
    loop {
        let bytes = rand::random::<[u8; 8]>();
        if bytes != [0u8; 8] {
            return hex::encode(bytes);
        }
    }
}

/// The id of the request being served, when an entry point scoped one.
pub fn current_request_id() -> Option<String> {
    REQUEST
        .try_with(|scope| scope.id.clone())
        .ok()
}

/// Records the surface variant the request being served resolved to, and
/// stamps it on the current span as `surface.variant`. Only surface routing
/// calls this, while the request span is current; the first value set is
/// kept. Does nothing outside a request.
pub fn set_request_variant(variant: &str) {
    let first = REQUEST
        .try_with(|scope| {
            scope
                .variant
                .set(variant.to_string())
                .is_ok()
        })
        .unwrap_or(false);
    if first {
        tracing::Span::current().record("surface.variant", variant);
    }
}

/// The surface variant the request being served resolved to, when routing
/// set one.
pub fn current_request_variant() -> Option<String> {
    REQUEST
        .try_with(|scope| scope.variant.get().cloned())
        .ok()
        .flatten()
}

/// Runs `f` as a request that resolved to surface variant `variant`.
#[cfg(test)]
pub fn with_request_variant<R>(
    variant: &str,
    f: impl FnOnce() -> R,
) -> R {
    let scope = RequestScope::fresh();
    let _ = scope
        .variant
        .set(variant.to_string());
    REQUEST.sync_scope(scope, f)
}

/// Runs `future` as request `scope`: every audit record it writes carries
/// the request's id and variant. An entry point serves its request through
/// this and passes the response to [`response_in_request`].
pub async fn in_request<F: std::future::Future>(
    scope: Arc<RequestScope>,
    future: F,
) -> F::Output {
    REQUEST
        .scope(scope, future)
        .await
}

/// `response` with a streamed body read and dropped as request `scope`. A
/// streamed body (an SSE stream) is read after its handler returned, outside
/// the handler's scope, so the records written per event, and those its
/// observers write when a client disconnects and the body is dropped, would
/// otherwise lose the request. A body of known length is left as it is.
pub fn response_in_request(
    scope: Arc<RequestScope>,
    response: axum::response::Response,
) -> axum::response::Response {
    use axum::body::HttpBody;
    use futures::StreamExt;

    if response
        .body()
        .size_hint()
        .exact()
        .is_some()
    {
        return response;
    }
    response.map(|body| {
        let mut guard = DroppedInRequest {
            data: Some(body.into_data_stream()),
            scope,
        };
        axum::body::Body::from_stream(futures::stream::poll_fn(move |cx| {
            let DroppedInRequest { data, scope } = &mut guard;
            REQUEST.sync_scope(Arc::clone(scope), || match data.as_mut() {
                Some(data) => data.poll_next_unpin(cx),
                None => std::task::Poll::Ready(None),
            })
        }))
    })
}

/// A streamed body that is dropped inside its request's scope, wherever the
/// drop happens.
struct DroppedInRequest<S> {
    data: Option<S>,
    scope: Arc<RequestScope>,
}

impl<S> Drop for DroppedInRequest<S> {
    fn drop(&mut self) {
        // Entering the scope can panic, and a panic while unwinding aborts.
        if std::thread::panicking() {
            return;
        }
        let data = self.data.take();
        REQUEST.sync_scope(Arc::clone(&self.scope), move || drop(data));
    }
}

/// Spawns `future` as the request being served, so the audit records it
/// writes carry the request's id and variant, as the task-local does not
/// cross a spawn.
pub fn spawn_in_request<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    match REQUEST.try_with(Arc::clone) {
        Ok(scope) => tokio::spawn(REQUEST.scope(scope, future)),
        Err(_) => tokio::spawn(future),
    }
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
    /// Filtering of an MCP `tools/list` response by tool policy and gating.
    McpToolList,
}

impl PolicyScope {
    /// Stable, low-cardinality label used in the structured event.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyScope::Gateway => "gateway",
            PolicyScope::Surface => "surface",
            PolicyScope::McpTool => "mcp_tool",
            PolicyScope::Response => "response",
            PolicyScope::McpToolList => "mcp_tool_list",
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
        AuthenticatedIdentity::ApiKey { key_name, .. } => ("api_key", key_name.clone(), None),
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

/// Why a policy could not reach a decision. The request is denied (fail
/// closed) and the decision is recorded as `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEvaluationError {
    EvaluationError,
    NoPolicyManager,
    PolicyNotCompiled,
}

impl PolicyEvaluationError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvaluationError => "evaluation_error",
            Self::NoPolicyManager => "no_policy_manager",
            Self::PolicyNotCompiled => "policy_not_compiled",
        }
    }
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
    /// Set when the policy could not decide; the request was denied.
    pub error: Option<PolicyEvaluationError>,
    /// Tools a `tools/list` filter removed (scope `McpToolList`).
    pub removed_tools: Option<&'a [String]>,
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
    /// When `None`, the recorded name falls back to the definition id, then to a
    /// label for the policy layer.
    pub policy_name: Option<&'a str>,
    /// Surface/channel identifier the decision applies to.
    pub surface_id: Option<&'a str>,
    /// Name of the surface the decision applies to, recorded as `channel_name`.
    pub surface_name: Option<&'a str>,
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
/// Records which tools a `tools/list` filter took out of the catalog: an
/// `allow` decision with scope `McpToolList` naming the removed tools. Nothing
/// is recorded when no tool was removed. `context` carries the request fields.
pub fn record_tools_list_filtering(
    listed: &[String],
    kept: &[String],
    context: PolicyDecisionEvent<'_>,
) {
    let removed: Vec<String> = listed
        .iter()
        .filter(|tool| !kept.contains(tool))
        .cloned()
        .collect();
    if removed.is_empty() {
        return;
    }
    record_policy_decision(PolicyDecisionEvent {
        scope: PolicyScope::McpToolList,
        allow: true,
        removed_tools: Some(&removed),
        ..context
    });
}

/// The best name the gateway knows for the policy that decided: the
/// operator's definition name, else the definition id, else a readable label
/// for the layer. A tool policy that matched no definition keeps the tool name.
fn decision_policy_name(event: &PolicyDecisionEvent<'_>) -> String {
    fn known(value: Option<&str>) -> Option<&str> {
        value.filter(|v| !v.is_empty())
    }
    if let Some(name) = known(event.policy_name).or(known(event.policy_definition_id)) {
        return name.to_string();
    }
    match known(event.policy_id) {
        Some(crate::policies::GATEWAY_POLICY_PACKAGE) => "Gateway policy",
        Some(crate::policies::SURFACE_POLICY_PACKAGE) => "Surface policy",
        Some("mcp_tool_gating") => "MCP tool gating",
        Some(other) => other,
        None => match event.scope {
            PolicyScope::Gateway => "Gateway policy",
            PolicyScope::Surface => "Surface policy",
            PolicyScope::McpTool => "MCP tool policy",
            PolicyScope::Response => "Response policy",
            PolicyScope::McpToolList => "MCP tool list filter",
        },
    }
    .to_string()
}

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

    let allowed = event.allow && event.error.is_none();
    let decision = match (event.error, allowed) {
        (Some(_), _) => "error",
        (None, true) => "allow",
        (None, false) => "deny",
    };
    let scope = event.scope.as_str();
    let flow = event.flow.as_str();
    let reason = event
        .error
        .map(PolicyEvaluationError::as_str)
        .or(event.reason)
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
    let policy_name = decision_policy_name(&event);
    let surface_variant = current_request_variant();

    if allowed {
        tracing::debug!(
            target: "policy_audit",
            policy_scope = scope,
            policy_flow = flow,
            policy_decision = decision,
            policy_id = policy_id,
            policy_definition_id = policy_definition_id,
            deny_reason = reason,
            surface_id = surface_id,
            surface_variant = surface_variant.as_deref(),
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
            surface_variant = surface_variant.as_deref(),
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
            "policy decision: {decision}"
        );
    }

    // A record is built only when an audit sink selects `policy_decision`. The
    // `policy_audit` tracing events above are always emitted.
    if crate::audit::producer::producer().wants("policy_decision") {
        crate::delegation_vault::audit::audit_policy_decision(
            scope,
            decision,
            policy_id,
            Some(policy_name.as_str()),
            event.policy_definition_id,
            if allowed {
                None
            } else {
                Some(reason)
            },
            if surface_id.is_empty() {
                None
            } else {
                Some(surface_id)
            },
            event
                .surface_name
                .filter(|name| !name.is_empty()),
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
            event.removed_tools,
        );
    }

    // Push the full decision into the per-request collector. It is always
    // populated when a scope is active and is never embedded in a minted VP.
    let deny_reason_val = (!allowed && !reason.is_empty()).then(|| reason.to_string());
    let id = compute_decision_id(scope, policy_id, decision, deny_reason_val.as_deref(), resolved_trace_id.as_deref());
    push_policy_decision(PolicyDecisionSummary {
        id,
        scope: event.scope.as_str(),
        flow,
        policy_name,
        policy_id: if policy_id.is_empty() {
            None
        } else {
            Some(policy_id.to_string())
        },
        policy_definition_id: event
            .policy_definition_id
            .filter(|d| !d.is_empty())
            .map(str::to_string),
        decision,
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
    fn a_new_request_id_is_a_w3c_span_id() {
        let ids: Vec<String> = (0..64)
            .map(|_| new_request_id())
            .collect();
        for id in &ids {
            assert_eq!(id.len(), 16, "{id}");
            assert!(
                id.chars()
                    .all(|c| matches!(c, '0'..='9' | 'a'..='f')),
                "{id}"
            );
            assert_ne!(id, "0000000000000000");
        }
        let distinct: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len());
        let thirteenth: std::collections::HashSet<char> = ids
            .iter()
            .filter_map(|id| id.chars().nth(12))
            .collect();
        assert!(thirteenth.len() > 1, "every character is random, none fixed by a UUID version");
    }

    fn request(id: &str) -> Arc<RequestScope> {
        RequestScope::new(id.to_string())
    }

    #[tokio::test]
    async fn the_current_request_id_is_the_scoped_one_and_none_outside() {
        assert_eq!(current_request_id(), None);
        in_request(request("0123456789abcdef"), async {
            assert_eq!(current_request_id().as_deref(), Some("0123456789abcdef"));
        })
        .await;
    }

    #[tokio::test]
    async fn a_variant_set_in_a_request_is_read_back() {
        let variant = in_request(request("0123456789abcdef"), async {
            assert_eq!(current_request_variant(), None, "routing has not set it yet");
            set_request_variant("beta");
            current_request_variant()
        })
        .await;

        assert_eq!(variant.as_deref(), Some("beta"));
    }

    #[tokio::test]
    async fn a_second_variant_set_in_a_request_is_ignored() {
        let variant = in_request(request("0123456789abcdef"), async {
            set_request_variant("beta");
            set_request_variant("_base_");
            current_request_variant()
        })
        .await;

        assert_eq!(variant.as_deref(), Some("beta"));
    }

    #[test]
    fn outside_a_request_there_is_no_variant() {
        set_request_variant("beta");
        assert_eq!(current_request_variant(), None);
    }

    #[tokio::test]
    async fn a_streamed_body_is_read_as_its_request() {
        use futures::StreamExt;

        let chunks = futures::stream::repeat_with(|| {
            Ok::<_, std::convert::Infallible>(bytes::Bytes::from(format!(
                "{}:{};",
                current_request_id().unwrap_or_default(),
                current_request_variant().unwrap_or_default()
            )))
        })
        .take(2);
        let response = axum::response::Response::new(axum::body::Body::from_stream(chunks));
        let scope = request("0123456789abcdef");
        in_request(scope.clone(), async { set_request_variant("beta") }).await;

        let response = response_in_request(scope, response);
        let body = axum::body::to_bytes(response.into_body(), 64)
            .await
            .unwrap();

        assert_eq!(body, "0123456789abcdef:beta;0123456789abcdef:beta;");
    }

    #[tokio::test]
    async fn a_streamed_body_dropped_before_its_end_is_dropped_as_its_request() {
        use futures::StreamExt;
        use http_body_util::BodyExt;

        type Seen = Arc<Mutex<Option<(Option<String>, Option<String>)>>>;
        struct RecordOnDrop(Seen);
        impl Drop for RecordOnDrop {
            fn drop(&mut self) {
                *self.0.lock().unwrap() = Some((current_request_id(), current_request_variant()));
            }
        }
        let seen = Seen::default();
        let observer = RecordOnDrop(Arc::clone(&seen));
        let chunks = futures::stream::once(async { Ok::<_, std::convert::Infallible>(bytes::Bytes::from("event")) })
            .chain(futures::stream::pending())
            .map(move |chunk| {
                let _ = &observer;
                chunk
            });
        let response = axum::response::Response::new(axum::body::Body::from_stream(chunks));
        let scope = request("0123456789abcdef");
        in_request(scope.clone(), async { set_request_variant("beta") }).await;
        let mut body = response_in_request(scope, response).into_body();
        let first = body
            .frame()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.into_data().unwrap(), "event");

        drop(body);

        assert_eq!(
            seen.lock().unwrap().clone(),
            Some((Some("0123456789abcdef".to_string()), Some("beta".to_string())))
        );
    }

    #[tokio::test]
    async fn a_streamed_body_dropped_while_panicking_is_dropped_outside_its_request() {
        use futures::StreamExt;

        type Seen = Arc<Mutex<Option<Option<String>>>>;
        struct RecordOnDrop(Seen);
        impl Drop for RecordOnDrop {
            fn drop(&mut self) {
                *self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(current_request_variant());
            }
        }
        let seen = Seen::default();
        let observer = RecordOnDrop(Arc::clone(&seen));
        let chunks = futures::stream::pending::<Result<bytes::Bytes, std::convert::Infallible>>().map(move |chunk| {
            let _ = &observer;
            chunk
        });
        let response = axum::response::Response::new(axum::body::Body::from_stream(chunks));
        let scope = request("0123456789abcdef");
        in_request(scope.clone(), async { set_request_variant("beta") }).await;
        let body = response_in_request(scope, response).into_body();

        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _body = body;
            panic!("the request handler panics while holding its body");
        }));

        assert!(unwound.is_err(), "the panic is caught, not turned into an abort");
        assert_eq!(
            seen.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            Some(None),
            "a body dropped during unwinding never enters the request scope"
        );
    }

    #[test]
    fn a_body_of_known_length_is_left_as_it_is() {
        use axum::body::HttpBody;

        let response = axum::response::Response::new(axum::body::Body::from("{}"));
        let response = response_in_request(request("0123456789abcdef"), response);

        assert_eq!(
            response
                .body()
                .size_hint()
                .exact(),
            Some(2)
        );
    }

    #[tokio::test]
    async fn a_task_spawned_in_a_request_keeps_its_id_and_variant() {
        let spawned = in_request(request("0123456789abcdef"), async {
            set_request_variant("beta");
            spawn_in_request(async { (current_request_id(), current_request_variant()) })
                .await
                .unwrap()
        })
        .await;
        let outside = spawn_in_request(async { (current_request_id(), current_request_variant()) })
            .await
            .unwrap();

        assert_eq!(spawned, (Some("0123456789abcdef".to_string()), Some("beta".to_string())));
        assert_eq!(outside, (None, None));
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

        let api = AuthenticatedIdentity::ApiKey {
            key_name: "key-a".to_string(),
            provider_agent_id: None,
        };
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
            user_identity_hash: None,
            peer_gateway: None,
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
    async fn summary_policy_name_falls_back_to_the_layer_label_when_unset() {
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
        assert_eq!(decisions[0].policy_name, "Gateway policy");
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
                provider_agent_id: None,
            };
            with_request_variant("beta", || {
                record_policy_decision(PolicyDecisionEvent {
                    scope: PolicyScope::Surface,
                    allow: false,
                    reason: Some("trust check failed"),
                    policy_id: Some("pol-7"),
                    policy_definition_id: Some("def-uuid-7"),
                    policy_name: None,
                    surface_id: Some("surface-a"),
                    surface_name: Some("Surface A"),
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
                    error: None,
                    removed_tools: None,
                })
            });
        });

        let captured = events.lock().unwrap();
        let ev = captured
            .iter()
            .find(|e| field(e, "policy_scope") == Some("surface"))
            .expect("policy decision event not captured");

        assert_eq!(ev.level, "WARN");
        assert_eq!(field(ev, "surface_variant"), Some("beta"));
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

    #[tokio::test]
    async fn a_policy_that_could_not_decide_is_recorded_as_an_error() {
        for (error, reason) in [
            (PolicyEvaluationError::EvaluationError, "evaluation_error"),
            (PolicyEvaluationError::NoPolicyManager, "no_policy_manager"),
            (PolicyEvaluationError::PolicyNotCompiled, "policy_not_compiled"),
        ] {
            let ((), events) = crate::audit::producer::capture(async {
                record_policy_decision(PolicyDecisionEvent {
                    scope: PolicyScope::Surface,
                    error: Some(error),
                    policy_id: Some("surface.policy"),
                    surface_id: Some("surface-a"),
                    ..Default::default()
                });
            })
            .await;

            assert_eq!(events.len(), 1, "{reason}");
            match &events[0].event {
                crate::delegation_vault::audit::DelegationAuditAction::PolicyDecision {
                    decision, deny_reason, ..
                } => {
                    assert_eq!(decision, "error");
                    assert_eq!(deny_reason.as_deref(), Some(reason));
                }
                other => panic!("expected a policy decision, got {other:?}"),
            }
        }
    }

    fn names(names: &[&str]) -> Vec<String> {
        names
            .iter()
            .map(|name| name.to_string())
            .collect()
    }

    #[tokio::test]
    async fn tools_removed_from_a_tools_list_are_recorded() {
        let ((), events) = crate::audit::producer::capture(async {
            record_tools_list_filtering(
                &names(&["search", "delete_repo", "read_file", "drop_table"]),
                &names(&["search", "read_file"]),
                PolicyDecisionEvent {
                    surface_id: Some("surface-a"),
                    trace_id: Some("trace-1"),
                    ..Default::default()
                },
            );
        })
        .await;

        assert_eq!(events.len(), 1);
        match &events[0].event {
            crate::delegation_vault::audit::DelegationAuditAction::PolicyDecision {
                scope,
                decision,
                removed_tools,
                surface_id,
                ..
            } => {
                assert_eq!(scope, "mcp_tool_list");
                assert_eq!(decision, "allow");
                assert_eq!(removed_tools.as_deref(), Some(names(&["delete_repo", "drop_table"]).as_slice()));
                assert_eq!(surface_id.as_deref(), Some("surface-a"));
            }
            other => panic!("expected a policy decision, got {other:?}"),
        }
    }

    #[test]
    fn a_decision_names_its_policy_by_the_best_name_known() {
        let name = |scope, policy_name, policy_definition_id, policy_id| {
            decision_policy_name(&PolicyDecisionEvent {
                scope,
                policy_name,
                policy_definition_id,
                policy_id,
                ..Default::default()
            })
        };
        assert_eq!(
            name(
                PolicyScope::Surface,
                Some("Partner policy"),
                Some("def-1"),
                Some(crate::policies::SURFACE_POLICY_PACKAGE)
            ),
            "Partner policy"
        );
        assert_eq!(
            name(PolicyScope::Surface, Some(""), Some("def-1"), Some(crate::policies::SURFACE_POLICY_PACKAGE)),
            "def-1"
        );
        for (scope, policy_id, label) in [
            (PolicyScope::Gateway, Some(crate::policies::GATEWAY_POLICY_PACKAGE), "Gateway policy"),
            (PolicyScope::Surface, Some(crate::policies::SURFACE_POLICY_PACKAGE), "Surface policy"),
            (PolicyScope::McpTool, Some("mcp_tool_gating"), "MCP tool gating"),
            (PolicyScope::McpTool, Some("delete_repo"), "delete_repo"),
            (PolicyScope::McpTool, None, "MCP tool policy"),
            (PolicyScope::McpTool, Some(""), "MCP tool policy"),
            (PolicyScope::Response, None, "Response policy"),
            (PolicyScope::McpToolList, None, "MCP tool list filter"),
            (PolicyScope::Gateway, None, "Gateway policy"),
            (PolicyScope::Surface, None, "Surface policy"),
        ] {
            assert_eq!(name(scope, None, None, policy_id), label, "{scope:?} {policy_id:?}");
        }
    }

    #[tokio::test]
    async fn every_decision_record_carries_a_policy_name() {
        let ((), events) = crate::audit::producer::capture(async {
            record_policy_decision(PolicyDecisionEvent {
                scope: PolicyScope::Gateway,
                allow: false,
                policy_id: Some(crate::policies::GATEWAY_POLICY_PACKAGE),
                ..Default::default()
            });
            record_policy_decision(PolicyDecisionEvent {
                scope: PolicyScope::McpTool,
                allow: true,
                ..Default::default()
            });
        })
        .await;

        let names: Vec<Option<String>> = events
            .iter()
            .map(|event| match &event.event {
                crate::delegation_vault::audit::DelegationAuditAction::PolicyDecision { policy_name, .. } => {
                    policy_name.clone()
                }
                other => panic!("expected a policy decision, got {other:?}"),
            })
            .collect();
        assert_eq!(names, [Some("Gateway policy".to_string()), Some("MCP tool policy".to_string())]);
    }

    #[tokio::test]
    async fn a_decision_record_names_its_surface() {
        let ((), events) = crate::audit::producer::capture(async {
            record_policy_decision(PolicyDecisionEvent {
                scope: PolicyScope::Surface,
                allow: false,
                surface_id: Some("0b6f7a52-surface-uuid"),
                surface_name: Some("Payments"),
                ..Default::default()
            });
            record_policy_decision(PolicyDecisionEvent {
                scope: PolicyScope::Gateway,
                allow: true,
                ..Default::default()
            });
        })
        .await;

        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0]
                .channel_name
                .as_deref(),
            Some("Payments")
        );
        assert_eq!(
            events[0]
                .surface_id
                .as_deref(),
            Some("0b6f7a52-surface-uuid")
        );
        assert_eq!(events[1].channel_name, None, "no surface, no name");
    }

    #[tokio::test]
    async fn a_tools_list_with_nothing_removed_is_not_recorded() {
        let ((), events) = crate::audit::producer::capture(async {
            record_tools_list_filtering(&names(&["search"]), &names(&["search"]), PolicyDecisionEvent::default());
        })
        .await;
        assert!(events.is_empty());
    }

    #[test]
    fn a_decision_without_removed_tools_omits_the_field() {
        let event = crate::delegation_vault::audit::DelegationAuditAction::PolicyDecision {
            scope: "surface".to_string(),
            flow: "access_point".to_string(),
            policy_id: "surface.policy".to_string(),
            policy_name: None,
            policy_definition_id: None,
            decision: "allow".to_string(),
            deny_reason: None,
            surface_id: None,
            caller_did: None,
            http_method: None,
            http_path: None,
            policy_version: None,
            policy_content_hash: None,
            removed_tools: None,
        };
        let stored = serde_json::to_value(event).unwrap();
        assert!(
            stored["policy_decision"]
                .get("removed_tools")
                .is_none()
        );
    }

    #[test]
    fn an_error_decision_is_logged_at_warn() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CapturingLayer { events: events.clone() });
        tracing::subscriber::with_default(subscriber, || {
            record_policy_decision(PolicyDecisionEvent {
                scope: PolicyScope::Gateway,
                error: Some(PolicyEvaluationError::PolicyNotCompiled),
                ..Default::default()
            });
        });
        let captured = events.lock().unwrap();
        let ev = captured
            .iter()
            .find(|e| field(e, "policy_scope") == Some("gateway"))
            .expect("policy decision event not captured");
        assert_eq!(ev.level, "WARN");
        assert_eq!(field(ev, "policy_decision"), Some("error"));
        assert_eq!(field(ev, "deny_reason"), Some("policy_not_compiled"));
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
        assert_eq!(field(ev, "surface_variant"), None, "outside a request there is no variant");
    }

    #[test]
    fn an_allow_line_names_the_request_variant() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CapturingLayer { events: events.clone() });

        tracing::subscriber::with_default(subscriber, || {
            with_request_variant("_base_", || {
                record_policy_decision(PolicyDecisionEvent {
                    scope: PolicyScope::Gateway,
                    allow: true,
                    surface_id: Some("surface-b"),
                    ..Default::default()
                })
            });
        });

        let captured = events.lock().unwrap();
        let ev = captured
            .iter()
            .find(|e| field(e, "policy_scope") == Some("gateway"))
            .expect("allow decision event not captured");
        assert_eq!(field(ev, "surface_variant"), Some("_base_"));
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
