//! Emit helpers for the governance events raised on the request path: the
//! emit site passes the facts it has, and a record is built only when a sink
//! selects the event.

use std::net::IpAddr;
use std::time::Duration;

pub use crate::audit::events::{RejectionReason, RejectionStage, TargetAuthOutcome};

use crate::audit::events::{AuthScheme, RateLimitScope};
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent, audit_event, emit};
use crate::protocols::protected_resource::ResourceTokenError;
use crate::source_auth::errors::SourceAuthError;
use crate::source_auth::models::SourceAuthConfig;

/// What the emit site knows about the request, for the record envelope.
pub struct RequestFacts<'a> {
    pub surface_id: &'a str,
    pub channel_name: &'a str,
    pub trace_id: Option<&'a str>,
    /// The request arrived over the fabric (gateway to gateway).
    pub via_fabric: bool,
}

/// The surface id and name of a record for a request no surface matched.
pub const UNKNOWN_SURFACE: &str = "unknown";

impl RequestFacts<'_> {
    /// A request refused before any surface matched it, and before its trace
    /// id was assigned.
    pub fn unroutable() -> RequestFacts<'static> {
        RequestFacts {
            surface_id: UNKNOWN_SURFACE,
            channel_name: UNKNOWN_SURFACE,
            trace_id: None,
            via_fabric: false,
        }
    }

    fn record(
        &self,
        action: DelegationAuditAction,
    ) -> DelegationAuditEvent {
        let mut event = audit_event(action, None, None, None, Some(self.surface_id));
        event.channel_name = Some(self.channel_name.to_string());
        event.trace_id = self
            .trace_id
            .map(str::to_string);
        event.via_fabric = self.via_fabric;
        event
    }
}

/// A caller failed authentication. `reason` is a fixed code, never the
/// credential or the validator's message. `blocking` is false when the
/// failure is handed to policy instead of refusing the request.
pub fn auth_failed(
    facts: &RequestFacts<'_>,
    scheme: AuthScheme,
    reason: &'static str,
    blocking: bool,
    client_ip: Option<IpAddr>,
) {
    emit("auth_failed", || {
        facts.record(DelegationAuditAction::AuthFailed {
            scheme,
            reason: reason.to_string(),
            blocking,
            client_ip: client_ip.map(|ip| ip.to_string()),
        })
    })
}

/// A request was refused with 429 because a limit was reached.
pub fn rate_limited(
    facts: &RequestFacts<'_>,
    scope: RateLimitScope,
    retry_after: Option<Duration>,
) {
    emit("rate_limited", || {
        facts.record(DelegationAuditAction::RateLimited {
            scope,
            retry_after_ms: retry_after.map(|wait| u64::try_from(wait.as_millis()).unwrap_or(u64::MAX)),
            transit_point: None,
        })
    })
}

/// A Transit Point refused a request with 429 because its per-caller limit
/// was reached. `caller_hash` is the identity hash of the caller the Transit
/// Point identified, absent for a request with no identified caller. A refusal
/// by the bucket callers share while the limit holds as many buckets as it may
/// is recorded with scope `transit_point_overflow` and names no caller, since
/// the caller did not spend an allowance of their own.
pub fn transit_point_caller_rate_limited(
    facts: &RequestFacts<'_>,
    transit_point: &str,
    caller_hash: Option<&str>,
    refusal: crate::policies::CallerRefusal,
) {
    emit("rate_limited", || {
        let mut event = facts.record(DelegationAuditAction::RateLimited {
            scope: if refusal.overflow {
                RateLimitScope::TransitPointOverflow
            } else {
                RateLimitScope::TransitPointCaller
            },
            retry_after_ms: Some(
                u64::try_from(
                    refusal
                        .retry_after
                        .as_millis(),
                )
                .unwrap_or(u64::MAX),
            ),
            transit_point: Some(transit_point.to_string()),
        });
        event.user_identity_hash = caller_hash
            .filter(|_| !refusal.overflow)
            .map(str::to_string);
        event
    })
}

/// What an Access Point knows about a request at the moment it hands it to its
/// target.
pub struct Forwarding<'a> {
    pub surface: &'a crate::config::agent_surface::AgentSurface,
    pub trace_id: &'a str,
    /// The managed agent's own DID, when the surface has one.
    pub agent_identity_did: Option<&'a str>,
    /// The caller source authentication verified; `None` for a caller it did
    /// not authenticate.
    pub identity: Option<&'a crate::source_auth::AuthenticatedIdentity>,
    /// The agent DID derived for the request, as a policy decision records it.
    pub actor_did: Option<&'a str>,
}

/// The Access Point is handing a request to its target. The record names the
/// caller, as a policy decision does, only when source authentication
/// verified one. The target URL is written without its credentials.
pub fn request_forwarded(forwarding: Forwarding<'_>) {
    emit("request_forwarded", || {
        let surface = forwarding.surface;
        let caller = forwarding
            .identity
            .map(|identity| {
                crate::observability::policy_audit::recorded_caller(Some(identity), None, forwarding.actor_did)
            })
            .unwrap_or_default();
        let facts = RequestFacts {
            surface_id: &surface.surface_id,
            channel_name: &surface.name,
            trace_id: Some(forwarding.trace_id),
            via_fabric: surface
                .target
                .endpoint
                .starts_with("fabric://"),
        };
        let mut record = facts.record(DelegationAuditAction::RequestForwarded {
            flow: crate::observability::PolicyFlow::AccessPoint
                .as_str()
                .to_string(),
            caller_did: caller.caller_did,
        });
        record.caller = caller.caller;
        record.tenant_id = surface.tenant_id.clone();
        record.protocol = Some(
            surface
                .channel_protocol()
                .to_string(),
        );
        record.target_endpoint = Some(crate::observability::loggable::url(&surface.target.endpoint));
        record.agent_identity_did = forwarding
            .agent_identity_did
            .map(str::to_string);
        record
    })
}

/// What a Transit Point knows about a request at the moment it hands it to its
/// target.
pub struct TransitForwarding<'a> {
    pub surface: &'a crate::config::agent_surface::AgentSurface,
    pub transit_point: &'a crate::config::agent_surface::TransitPoint,
    pub trace_id: &'a str,
    /// The protected agent's DID, when the Transit Point resolved one.
    pub agent_identity_did: Option<&'a str>,
}

/// The Transit Point is handing a request to its target, over HTTP or the
/// Fabric. The record names no caller. The target URL is written without its
/// credentials.
pub fn transit_request_forwarded(forwarding: TransitForwarding<'_>) {
    emit("transit_request_forwarded", || {
        let (surface, transit_point) = (forwarding.surface, forwarding.transit_point);
        let facts = RequestFacts {
            surface_id: &surface.surface_id,
            channel_name: &surface.name,
            trace_id: Some(forwarding.trace_id),
            via_fabric: transit_point
                .target_endpoint
                .starts_with("fabric://"),
        };
        let mut record = facts.record(DelegationAuditAction::TransitRequestForwarded {
            transit_point: transit_point.alias.clone(),
        });
        record.tenant_id = surface.tenant_id.clone();
        record.protocol = Some(
            transit_point
                .protocol
                .to_string(),
        );
        record.target_endpoint = Some(crate::observability::loggable::url(&transit_point.target_endpoint));
        record.agent_identity_did = forwarding
            .agent_identity_did
            .map(str::to_string);
        record
    })
}

/// The gateway refused the request. `http_status` and `rpc_error_code` are
/// what the caller received; a Fabric refusal records no HTTP status, as no
/// HTTP response is involved.
pub fn request_rejected(
    facts: &RequestFacts<'_>,
    stage: RejectionStage,
    reason: RejectionReason,
    http_status: u16,
    rpc_error_code: Option<i64>,
) {
    record_rejection(facts, stage, reason, http_status, rpc_error_code, None)
}

fn record_rejection(
    facts: &RequestFacts<'_>,
    stage: RejectionStage,
    reason: RejectionReason,
    http_status: u16,
    rpc_error_code: Option<i64>,
    requested_variant: Option<&str>,
) {
    emit("request_rejected", || {
        facts.record(DelegationAuditAction::RequestRejected {
            stage,
            reason,
            http_status: (!facts.via_fabric).then_some(http_status),
            rpc_error_code,
            requested_variant: requested_variant.map(str::to_string),
            target_auth: None,
        })
    })
}

/// The Target credential was not sent: it could not be obtained, or a `[credential_policy]`
/// rule in `enforce` withheld it. Recorded as a `forward` refusal with reason
/// `target_auth_failed` whether `outcome` refused the request (`http_status` is the refusal's
/// `status` on HTTP) or forwarded it without the credential (no `http_status`).
/// `transit_point` names the Transit Point whose credential it was, absent for the Target;
/// `provider_id` names the credential provider; `oauth_error` is the token endpoint's
/// registered OAuth `error` code, or `other`, never its body.
pub fn target_auth_failed(
    facts: &RequestFacts<'_>,
    transit_point: Option<&str>,
    provider_id: Option<&str>,
    outcome: TargetAuthOutcome,
    status: u16,
    oauth_error: Option<crate::delegation_vault::oauth::OAuthErrorCode>,
) {
    emit("request_rejected", || {
        let mut record = facts.record(DelegationAuditAction::RequestRejected {
            stage: RejectionStage::Forward,
            reason: RejectionReason::TargetAuthFailed,
            http_status: (outcome == TargetAuthOutcome::Rejected && !facts.via_fabric).then_some(status),
            rpc_error_code: None,
            requested_variant: None,
            target_auth: Some(crate::audit::events::TargetAuthRejection {
                outcome,
                transit_point: transit_point.map(str::to_string),
                oauth_error: oauth_error.map(|code| code.to_string()),
                upstream_status: None,
            }),
        });
        record.provider_id = provider_id.map(str::to_string);
        record
    })
}

/// The Target credential was sent, and the peer gateway that checked it as its caller
/// credential refused it with `upstream_status`. Recorded as a `forward` refusal with reason
/// `target_auth_failed` and outcome `refused_by_target`; `http_status` is the `status` this
/// gateway answered its caller with.
pub fn target_credential_refused_by_target(
    facts: &RequestFacts<'_>,
    transit_point: Option<&str>,
    provider_id: Option<&str>,
    status: u16,
    upstream_status: u16,
) {
    emit("request_rejected", || {
        let mut record = facts.record(DelegationAuditAction::RequestRejected {
            stage: RejectionStage::Forward,
            reason: RejectionReason::TargetAuthFailed,
            http_status: (!facts.via_fabric).then_some(status),
            rpc_error_code: None,
            requested_variant: None,
            target_auth: Some(crate::audit::events::TargetAuthRejection {
                outcome: TargetAuthOutcome::RefusedByTarget,
                transit_point: transit_point.map(str::to_string),
                oauth_error: None,
                upstream_status: Some(upstream_status),
            }),
        });
        record.provider_id = provider_id.map(str::to_string);
        record
    })
}

/// A request refused at routing because the surface variant it selects can't
/// be resolved. Only [`refuse_routing`] builds one, and it records the refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRefusal {
    reason: RejectionReason,
    status: axum::http::StatusCode,
    requested_variant: Option<String>,
    /// On `variant_disabled`: the disabled variant's configured alias.
    disabled_variant: Option<String>,
}

impl RoutingRefusal {
    pub fn reason(&self) -> RejectionReason {
        self.reason
    }

    pub fn status(&self) -> axum::http::StatusCode {
        self.status
    }

    /// Logs the refusal of a request to `surface` from what was recorded:
    /// the reason, the requested alias as cut for the record, on a disabled
    /// variant its configured alias in full, and on a misconfigured default
    /// the configured `default_variant_id`. The caller's raw alias is never
    /// logged. The message carries the `[CHANNEL:<config_id>]` prefix the
    /// dashboard's channel log filter matches.
    pub fn warn(
        &self,
        surface: &crate::config::agent_surface::AgentSurface,
    ) {
        let default_variant_id = (self.reason() == RejectionReason::MisconfiguredDefault)
            .then_some(
                surface
                    .default_variant_id
                    .as_deref(),
            )
            .flatten();
        let config_id = surface
            .config_id()
            .unwrap_or_default();
        tracing::warn!(
            config_id,
            surface = %surface.name,
            reason = ?self.reason(),
            requested_variant = ?self.requested_variant(),
            disabled_variant = ?self.disabled_variant.as_deref(),
            default_variant_id = ?default_variant_id,
            "[CHANNEL:{config_id}] Surface variant cannot be resolved"
        );
    }

    pub fn requested_variant(&self) -> Option<&str> {
        self.requested_variant
            .as_deref()
    }

    /// What the caller is told. Both 404s say the same thing: nothing is
    /// served at that URL.
    pub fn message(&self) -> &'static str {
        match self.reason {
            RejectionReason::MisconfiguredDefault => "Surface variant configuration error",
            _ => "No surface variant is served at this URL",
        }
    }
}

/// Records a routing refusal for `error` and returns how to answer it. The
/// request's surface variant is set first: `_unknown_` for an unknown alias,
/// the disabled variant's alias, or nothing for a misconfigured default. The
/// alias the caller named goes only to `requested_variant`. `rpc_error_code`
/// is the JSON-RPC error code the caller is answered with, when the refusal
/// is one.
pub fn refuse_routing(
    facts: &RequestFacts<'_>,
    error: &crate::config::agent_surface_variants::VariantResolveError,
    rpc_error_code: Option<i64>,
) -> RoutingRefusal {
    use crate::config::agent_surface_variants::{SurfaceVariant, VariantResolveError};
    use crate::observability::policy_audit::set_request_variant;
    use axum::http::StatusCode;

    match error {
        VariantResolveError::UnknownAlias(_) => set_request_variant(SurfaceVariant::UNKNOWN),
        VariantResolveError::DisabledVariant(alias) => set_request_variant(alias),
        VariantResolveError::MisconfiguredDefault(_) => {}
    }
    let refusal = match error {
        VariantResolveError::UnknownAlias(alias) => RoutingRefusal {
            reason: RejectionReason::UnknownVariant,
            status: StatusCode::NOT_FOUND,
            requested_variant: Some(SurfaceVariant::cut_alias(alias)),
            disabled_variant: None,
        },
        VariantResolveError::DisabledVariant(alias) => RoutingRefusal {
            reason: RejectionReason::VariantDisabled,
            status: StatusCode::NOT_FOUND,
            requested_variant: None,
            disabled_variant: Some(alias.clone()),
        },
        VariantResolveError::MisconfiguredDefault(_) => RoutingRefusal {
            reason: RejectionReason::MisconfiguredDefault,
            status: StatusCode::INTERNAL_SERVER_ERROR,
            requested_variant: None,
            disabled_variant: None,
        },
    };
    record_rejection(
        facts,
        RejectionStage::Routing,
        refusal.reason,
        refusal.status.as_u16(),
        rpc_error_code,
        refusal.requested_variant(),
    );
    refusal
}

/// The reason for an MCP transport refusal, from the HTTP status and JSON-RPC
/// code the caller received. A malformed JSON-RPC envelope is the same reason
/// on every path; an Origin, header, method or capability rule is MCP admission.
pub fn mcp_refusal_reason(
    http_status: u16,
    rpc_error_code: Option<i64>,
) -> RejectionReason {
    match (http_status, rpc_error_code) {
        (413, _) => RejectionReason::BodyTooLarge,
        (_, Some(-32022)) => RejectionReason::VersionUnsupported,
        (200 | 400, Some(-32700 | -32600)) => RejectionReason::InvalidEnvelope,
        _ => RejectionReason::McpAdmission,
    }
}

/// An identity-binding VP verified and a trust anchor vouches for its issuer.
pub fn identity_binding_verified(
    facts: &RequestFacts<'_>,
    agent_did: &str,
    issuer_gateway: Option<&str>,
    assurance: Option<&str>,
) {
    emit("identity_binding_verified", || {
        facts.record(DelegationAuditAction::IdentityBindingVerified {
            agent_did: agent_did.to_string(),
            issuer_gateway: issuer_gateway.map(str::to_string),
            assurance: assurance.map(str::to_string),
        })
    })
}

/// The identity check did not produce a binding to rely on. `error_detail` is
/// a short diagnostic and never carries signed VP material.
pub fn identity_binding_failed(
    facts: &RequestFacts<'_>,
    outcome: crate::audit::events::IdentityBindingFailure,
    agent_did: Option<&str>,
    issuer_gateway: Option<&str>,
    error_detail: Option<&str>,
) {
    emit("identity_binding_failed", || {
        facts.record(DelegationAuditAction::IdentityBindingFailed {
            outcome,
            agent_did: agent_did.map(str::to_string),
            issuer_gateway: issuer_gateway.map(str::to_string),
            error_detail: error_detail.map(str::to_string),
        })
    })
}

/// An MCP transport refusal, recorded from the validation error the caller receives.
pub fn mcp_request_rejected(
    facts: &RequestFacts<'_>,
    error: &crate::mcp::request_validation::McpRequestValidationError,
) {
    let http_status = error.status.as_u16();
    let rpc_error_code = Some(i64::from(error.code));
    request_rejected(
        facts,
        RejectionStage::Admission,
        mcp_refusal_reason(http_status, rpc_error_code),
        http_status,
        rpc_error_code,
    );
}

/// An MCP body that is not one unambiguous JSON-RPC object was refused. Every
/// such body is a malformed envelope, a batch included.
pub fn mcp_body_refused(
    facts: &RequestFacts<'_>,
    refusal: &crate::mcp::tool_analyzer::BodyRefusal,
    modern: bool,
) {
    let (http_status, rpc_error_code) = refusal.caller_status_and_code(modern);
    request_rejected(facts, RejectionStage::Admission, RejectionReason::InvalidEnvelope, http_status, rpc_error_code);
}

/// An MCP resource token was refused; the request gets the OAuth challenge.
pub fn resource_token_failed(
    facts: &RequestFacts<'_>,
    error: ResourceTokenError,
    client_ip: Option<IpAddr>,
) {
    auth_failed(facts, AuthScheme::McpResourceToken, resource_token_reason(error), true, client_ip);
}

pub fn source_auth_scheme(config: &SourceAuthConfig) -> AuthScheme {
    match config {
        SourceAuthConfig::JwtBearer(_) => AuthScheme::Jwt,
        SourceAuthConfig::ApiKey(_) | SourceAuthConfig::ApiKeyProvider(_) => AuthScheme::ApiKey,
        SourceAuthConfig::DidAuth(_) => AuthScheme::DidAuth,
        SourceAuthConfig::Mtls(_) => AuthScheme::Mtls,
    }
}

pub fn source_auth_reason(error: &SourceAuthError) -> &'static str {
    match error {
        SourceAuthError::MissingCredential { .. } => "missing_credential",
        SourceAuthError::InvalidCredential { .. } => "invalid_credential",
        SourceAuthError::AmbiguousCredentials => "ambiguous_credentials",
        SourceAuthError::ConfigNotFound { .. } => "config_not_found",
        SourceAuthError::Internal { .. } => "internal",
    }
}

pub fn resource_token_reason(error: ResourceTokenError) -> &'static str {
    match error {
        ResourceTokenError::Missing => "missing_credential",
        ResourceTokenError::Invalid => "invalid_credential",
        ResourceTokenError::InsufficientScope => "insufficient_scope",
        ResourceTokenError::Unavailable => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::events::AuthScheme;
    use crate::delegation_vault::audit::DelegationAuditAction;

    fn facts() -> RequestFacts<'static> {
        RequestFacts {
            surface_id: "surf-1",
            channel_name: "Alpha",
            trace_id: Some("trace-1"),
            via_fabric: false,
        }
    }

    /// An MCP surface of tenant `tenant-a` whose Target URL holds a user name,
    /// a password, a query value and a fragment.
    fn forwarding_surface() -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "orders", "name": "Orders", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://agent:planted-password@agent.example/mcp?key=planted-query#planted-fragment"}
        }))
        .unwrap()
    }

    /// The caller of a `request_forwarded` vector's `auth_method`. The JWT
    /// carries a claim no record may hold.
    fn vector_caller(auth_method: &serde_json::Value) -> Option<crate::source_auth::AuthenticatedIdentity> {
        use crate::source_auth::AuthenticatedIdentity;
        match auth_method.as_str() {
            Some("jwt_bearer") => Some(AuthenticatedIdentity::JwtBearer {
                strategy_id: None,
                principal_claim: "oid".to_string(),
                subject: "agent-oid".to_string(),
                claims: serde_json::json!({"sub": "user-123", "iss": "https://issuer.example", "aud": "gateway",
                    "oid": "agent-oid", "email": "ada@example.com", "name": "Ada",
                    "planted": "planted-claim-secret"}),
                verification: Default::default(),
            }),
            Some("did_auth") => Some(AuthenticatedIdentity::DidAuth {
                did: "did:web:caller.example".to_string(),
            }),
            None => None,
            Some(other) => panic!("no vector caller for {other}"),
        }
    }

    /// Every record written while `forwarding` is recorded inside a request
    /// that continued the caller's `traceparent` under span `53995c3f42cd8ad8`.
    async fn recorded_forwarding(
        identity: Option<&crate::source_auth::AuthenticatedIdentity>
    ) -> Vec<serde_json::Value> {
        use crate::observability::policy_audit::{RequestScope, in_request};
        use crate::proxy::trace::{RequestTrace, SpanId};
        let surface = forwarding_surface();
        let (trace, _) = RequestTrace::from_headers(
            &["00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"],
            &[],
            SpanId::parse("53995c3f42cd8ad8").unwrap(),
        );
        let trace_id = trace
            .trace_id
            .as_str()
            .to_string();
        let ((), records) = crate::audit::producer::capture(in_request(RequestScope::traced(trace), async {
            request_forwarded(Forwarding {
                surface: &surface,
                trace_id: &trace_id,
                agent_identity_did: Some("did:web:agent.example"),
                identity,
                actor_did: Some("did:web:derived.example"),
            });
        }))
        .await;
        records
            .iter()
            .map(|record| serde_json::to_value(record).unwrap())
            .collect()
    }

    /// The one `request_forwarded` record among `records`.
    fn forwarded(
        records: &[serde_json::Value],
        name: &serde_json::Value,
    ) -> serde_json::Value {
        let forwarded: Vec<&serde_json::Value> = records
            .iter()
            .filter(|record| record["event"]["request_forwarded"].is_object())
            .collect();
        assert_eq!(forwarded.len(), 1, "{name}: one request_forwarded record, got {records:?}");
        forwarded[0].clone()
    }

    /// The field at a vector's dotted `path`, when the record has it.
    fn field<'a>(
        record: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        path.split('.')
            .try_fold(record, |value, key| value.get(key))
            .filter(|value| !value.is_null())
    }

    #[tokio::test]
    async fn request_forwarded_writes_the_vectors_fields() {
        let cases = crate::proxy::trace::vector_cases("request_forwarded");
        for case in cases
            .iter()
            .filter(|case| case["accepted"] == true)
        {
            let (name, expected) = (&case["name"], &case["expected"]);
            let identity = vector_caller(&case["input"]["auth_method"]);
            let record = forwarded(&recorded_forwarding(identity.as_ref()).await, name);
            for path in expected["required"]
                .as_array()
                .unwrap()
            {
                let path = path.as_str().unwrap();
                assert!(field(&record, path).is_some(), "{name}: {path} is missing from {record}");
            }
            for path in expected["absent"]
                .as_array()
                .unwrap()
            {
                let path = path.as_str().unwrap();
                assert!(field(&record, path).is_none(), "{name}: {path} is present in {record}");
            }
            assert_eq!(record["event"]["request_forwarded"]["flow"], expected["flow"], "{name}");
            assert_eq!(record["span_id"], record["request_id"], "{name}");
            assert_eq!(record["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736", "{name}");
        }
        let refused: Vec<&str> = cases
            .iter()
            .filter(|case| case["accepted"] == false)
            .map(|case| case["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            refused,
            ["refused_before_forwarding", "transit_point_request", "fabric_receive"],
            "each refusing case has its own test where the request is served"
        );
    }

    /// A surface whose Transit Point `tools` sends to `endpoint`, a URL with a
    /// planted password, query value and fragment unless it is `fabric://`.
    fn transit_forwarding_surface(endpoint: &str) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "orders", "name": "Orders", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "a2a"},
            "target": {"endpoint": "https://agent.example/a2a"},
            "transit": {"points": [{"alias": "tools", "protocol": "mcp", "target_endpoint": endpoint}]}
        }))
        .unwrap()
    }

    /// Every record written while a Transit Point records a request it
    /// forwards to `endpoint`, inside a request whose trace is `trace`.
    async fn recorded_transit_forwarding(
        trace: crate::proxy::trace::RequestTrace,
        endpoint: &str,
    ) -> Vec<serde_json::Value> {
        use crate::observability::policy_audit::{RequestScope, in_request};
        let surface = transit_forwarding_surface(endpoint);
        let trace_id = trace
            .trace_id
            .as_str()
            .to_string();
        let ((), records) = crate::audit::producer::capture(in_request(RequestScope::traced(trace), async {
            transit_request_forwarded(TransitForwarding {
                surface: &surface,
                transit_point: &surface.transit_points()[0],
                trace_id: &trace_id,
                agent_identity_did: Some("did:web:agent.example"),
            });
        }))
        .await;
        records
            .iter()
            .map(|record| serde_json::to_value(record).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn transit_request_forwarded_writes_the_vectors_fields() {
        use crate::proxy::trace::{RequestTrace, SpanId};
        let cases = crate::proxy::trace::vector_cases("transit_request_forwarded");
        for case in cases
            .iter()
            .filter(|case| case["accepted"] == true)
        {
            let (name, input, expected) = (&case["name"], &case["input"], &case["expected"]);
            let span = SpanId::parse("53995c3f42cd8ad8").unwrap();
            let traceparent = ["00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"];
            let (trace, _) = match input["trace_source"].as_str() {
                Some("transit_token") => {
                    RequestTrace::at_transit_point(Some("4bf92f3577b34da6a3ce929d0e0e4736"), &traceparent, &[], span)
                }
                Some("header") => RequestTrace::at_transit_point(None, &traceparent, &[], span),
                other => panic!("{name}: no trace for {other:?}"),
            };
            let endpoint = if input["via_fabric"] == true {
                "fabric://peer-gateway/peer-surface"
            } else {
                "https://tools:planted-password@tools.example/mcp?key=planted-query#planted-fragment"
            };
            let records = recorded_transit_forwarding(trace, endpoint).await;
            let forwarded: Vec<&serde_json::Value> = records
                .iter()
                .filter(|record| record["event"]["transit_request_forwarded"].is_object())
                .collect();
            assert_eq!(forwarded.len(), 1, "{name}: one transit_request_forwarded record, got {records:?}");
            let record = forwarded[0];
            for path in expected["required"]
                .as_array()
                .unwrap()
                .iter()
                .chain(
                    expected["when_known"]
                        .as_array()
                        .unwrap(),
                )
            {
                let path = path.as_str().unwrap();
                assert!(field(record, path).is_some(), "{name}: {path} is missing from {record}");
            }
            for path in expected["absent"]
                .as_array()
                .unwrap()
            {
                let path = path.as_str().unwrap();
                assert!(field(record, path).is_none(), "{name}: {path} is present in {record}");
            }
            assert_eq!(record["trace_source"], expected["trace_source"], "{name}");
            assert_eq!(record["span_id"], record["request_id"], "{name}");
            assert_eq!(record["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736", "{name}");
            assert_eq!(record["parent_span_id"], "00f067aa0ba902b7", "{name}");
            assert_eq!(record["event"]["transit_request_forwarded"]["transit_point"], "tools", "{name}");
            assert_eq!(record["via_fabric"], input["via_fabric"], "{name}");
            let stored = record.to_string();
            for planted in ["planted-password", "planted-query", "planted-fragment"] {
                assert!(!stored.contains(planted), "{name}: the record holds {planted}: {stored}");
            }
        }
        let refused: Vec<&str> = cases
            .iter()
            .filter(|case| case["accepted"] == false)
            .map(|case| case["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            refused,
            [
                "transit_refused_before_forwarding",
                "transit_record_not_for_an_access_point_request",
                "transit_record_not_for_a_fabric_receive"
            ],
            "each refusing case has its own test where the request is served"
        );
    }

    /// A forwarded request names its caller exactly as a policy decision for
    /// the same caller does, and holds no claim, hash, credential or URL part
    /// beyond that.
    #[tokio::test]
    async fn a_forwarded_request_carries_no_more_of_its_caller_than_a_policy_decision() {
        let identity = vector_caller(&serde_json::json!("jwt_bearer")).unwrap();
        let record = forwarded(&recorded_forwarding(Some(&identity)).await, &serde_json::json!("jwt"));
        let ((), decisions) = crate::audit::producer::capture(async {
            crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
                scope: crate::observability::PolicyScope::Surface,
                allow: true,
                identity: Some(&identity),
                actor_did: Some("did:web:derived.example"),
                ..Default::default()
            });
        })
        .await;
        let decision = serde_json::to_value(&decisions[0]).unwrap();

        assert_eq!(record["caller"], decision["caller"]);
        assert_eq!(
            record["event"]["request_forwarded"]["caller_did"],
            decision["event"]["policy_decision"]["caller_did"]
        );
        assert_eq!(
            record["target_endpoint"], "https://agent.example/mcp?key=<redacted>",
            "the target URL loses its user name, password, query value and fragment"
        );
        let stored = record.to_string();
        for planted in ["planted-claim-secret", "planted-password", "planted-query", "planted-fragment"] {
            assert!(!stored.contains(planted), "the record holds {planted}: {stored}");
        }
        assert!(
            field(&record, "user_identity_hash").is_none() && field(&record, "caller.user_identity_hash").is_none()
        );
    }

    #[tokio::test]
    async fn auth_failed_records_scheme_reason_blocking_and_client_ip() {
        let ((), events) = crate::audit::producer::capture(async {
            auth_failed(&facts(), AuthScheme::Jwt, "invalid_credential", false, Some("203.0.113.7".parse().unwrap()));
        })
        .await;

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.surface_id.as_deref(), Some("surf-1"));
        assert_eq!(event.channel_name.as_deref(), Some("Alpha"));
        assert_eq!(event.trace_id.as_deref(), Some("trace-1"));
        match &event.event {
            DelegationAuditAction::AuthFailed {
                scheme,
                reason,
                blocking,
                client_ip,
            } => {
                assert_eq!(*scheme, AuthScheme::Jwt);
                assert_eq!(reason, "invalid_credential");
                assert!(!blocking);
                assert_eq!(client_ip.as_deref(), Some("203.0.113.7"));
            }
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rate_limited_records_scope_and_retry_after_in_milliseconds() {
        use crate::audit::events::RateLimitScope;
        let ((), events) = crate::audit::producer::capture(async {
            rate_limited(&facts(), RateLimitScope::Surface, Some(std::time::Duration::from_millis(1500)));
            rate_limited(&facts(), RateLimitScope::SseSessions, None);
        })
        .await;

        let recorded: Vec<_> = events
            .iter()
            .map(|event| match &event.event {
                DelegationAuditAction::RateLimited { scope, retry_after_ms, .. } => (*scope, *retry_after_ms),
                other => panic!("expected RateLimited, got {other:?}"),
            })
            .collect();
        assert_eq!(recorded, vec![(RateLimitScope::Surface, Some(1500)), (RateLimitScope::SseSessions, None)]);
        assert_eq!(
            events[0]
                .surface_id
                .as_deref(),
            Some("surf-1")
        );
    }

    #[tokio::test]
    async fn a_transit_point_callers_rate_limit_records_the_point_the_caller_and_the_wait() {
        use crate::audit::events::RateLimitScope;
        let ((), events) = crate::audit::producer::capture(async {
            let refusal = |overflow| crate::policies::CallerRefusal {
                retry_after: std::time::Duration::from_millis(2500),
                overflow,
            };
            transit_point_caller_rate_limited(&facts(), "partner", Some("caller-hash"), refusal(false));
            transit_point_caller_rate_limited(&facts(), "partner", None, refusal(false));
            transit_point_caller_rate_limited(&facts(), "partner", Some("newcomer-hash"), refusal(true));
        })
        .await;

        assert_eq!(events.len(), 3);
        match &events[0].event {
            DelegationAuditAction::RateLimited {
                scope,
                retry_after_ms,
                transit_point,
            } => {
                assert_eq!(*scope, RateLimitScope::TransitPointCaller);
                assert_eq!(*retry_after_ms, Some(2500));
                assert_eq!(transit_point.as_deref(), Some("partner"));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert_eq!(
            events[0]
                .user_identity_hash
                .as_deref(),
            Some("caller-hash")
        );
        assert_eq!(events[1].user_identity_hash, None, "a request with no identified caller names none");
        match &events[2].event {
            DelegationAuditAction::RateLimited { scope, .. } => {
                assert_eq!(*scope, RateLimitScope::TransitPointOverflow)
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert_eq!(
            events[2].user_identity_hash, None,
            "an overflow refusal names no caller, who spent no allowance of their own"
        );
        assert_eq!(
            serde_json::to_value(&events[2]).unwrap()["event"]["rate_limited"]["scope"],
            "transit_point_overflow"
        );

        let recorded = serde_json::to_value(&events[0]).unwrap();
        assert_eq!(recorded["event"]["rate_limited"]["scope"], "transit_point_caller", "{recorded}");
        let read_back: crate::delegation_vault::audit::DelegationAuditEvent = serde_json::from_value(recorded).unwrap();
        assert_eq!(
            read_back
                .user_identity_hash
                .as_deref(),
            Some("caller-hash"),
            "the audit log reads the record back with its caller"
        );
    }

    fn rejected(
        events: &[crate::delegation_vault::audit::DelegationAuditEvent]
    ) -> Vec<(RejectionStage, RejectionReason, Option<u16>, Option<i64>)> {
        events
            .iter()
            .map(|event| match &event.event {
                DelegationAuditAction::RequestRejected {
                    stage,
                    reason,
                    http_status,
                    rpc_error_code,
                    ..
                } => (*stage, *reason, *http_status, *rpc_error_code),
                other => panic!("expected RequestRejected, got {other:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn request_rejected_records_stage_reason_status_and_json_rpc_code() {
        let ((), events) = crate::audit::producer::capture(async {
            request_rejected(&facts(), RejectionStage::Admission, RejectionReason::InvalidEnvelope, 200, Some(-32700));
            request_rejected(&facts(), RejectionStage::Forward, RejectionReason::SsrfBlocked, 403, None);
        })
        .await;

        assert_eq!(
            rejected(&events),
            vec![
                (RejectionStage::Admission, RejectionReason::InvalidEnvelope, Some(200), Some(-32700)),
                (RejectionStage::Forward, RejectionReason::SsrfBlocked, Some(403), None),
            ]
        );
        assert_eq!(events[0].trace_id.as_deref(), Some("trace-1"));
    }

    #[tokio::test]
    async fn a_fabric_refusal_records_no_http_status() {
        use crate::config::agent_surface_variants::VariantResolveError;
        let fabric = RequestFacts { via_fabric: true, ..facts() };
        let ((), events) = crate::audit::producer::capture(async {
            request_rejected(&fabric, RejectionStage::Admission, RejectionReason::BodyTooLarge, 413, None);
            refuse_routing(&fabric, &VariantResolveError::UnknownAlias("typo".into()), None);
            request_rejected(&facts(), RejectionStage::Admission, RejectionReason::BodyTooLarge, 413, None);
        })
        .await;

        assert_eq!(
            rejected(&events),
            vec![
                (RejectionStage::Admission, RejectionReason::BodyTooLarge, None, None),
                (RejectionStage::Routing, RejectionReason::UnknownVariant, None, None),
                (RejectionStage::Admission, RejectionReason::BodyTooLarge, Some(413), None),
            ]
        );
        let stored = serde_json::to_value(&events[0]).unwrap();
        assert!(
            stored["event"]["request_rejected"]
                .get("http_status")
                .is_none(),
            "{stored}"
        );
    }

    #[tokio::test]
    async fn a_target_auth_failure_records_the_provider_outcome_and_oauth_error_code() {
        let fabric = RequestFacts { via_fabric: true, ..facts() };
        let ((), events) = crate::audit::producer::capture(async {
            target_auth_failed(
                &facts(),
                None,
                Some("machine"),
                TargetAuthOutcome::Rejected,
                500,
                Some(crate::delegation_vault::oauth::OAuthErrorCode::new("invalid_client")),
            );
            target_auth_failed(&facts(), Some("partner"), None, TargetAuthOutcome::Passthrough, 503, None);
            target_auth_failed(&fabric, None, Some("machine"), TargetAuthOutcome::Rejected, 503, None);
        })
        .await;

        let recorded: Vec<_> = events
            .iter()
            .map(|event| match &event.event {
                DelegationAuditAction::RequestRejected {
                    stage,
                    reason,
                    http_status,
                    target_auth,
                    ..
                } => (*stage, *reason, *http_status, event.provider_id.clone(), target_auth.clone()),
                other => panic!("expected RequestRejected, got {other:?}"),
            })
            .collect();
        let detail = |outcome, transit_point: Option<&str>, oauth_error: Option<&str>| {
            Some(crate::audit::events::TargetAuthRejection {
                outcome,
                transit_point: transit_point.map(str::to_string),
                oauth_error: oauth_error.map(str::to_string),
                upstream_status: None,
            })
        };
        let forward = (RejectionStage::Forward, RejectionReason::TargetAuthFailed);
        assert_eq!(
            recorded,
            vec![
                (
                    forward.0,
                    forward.1,
                    Some(500),
                    Some("machine".to_string()),
                    detail(TargetAuthOutcome::Rejected, None, Some("invalid_client"))
                ),
                (forward.0, forward.1, None, None, detail(TargetAuthOutcome::Passthrough, Some("partner"), None)),
                (
                    forward.0,
                    forward.1,
                    None,
                    Some("machine".to_string()),
                    detail(TargetAuthOutcome::Rejected, None, None)
                ),
            ]
        );
        assert_eq!(events[0].trace_id.as_deref(), Some("trace-1"));
        let stored = serde_json::to_value(&events[0]).unwrap();
        assert_eq!(
            stored["event"]["request_rejected"],
            serde_json::json!({
                "stage": "forward", "reason": "target_auth_failed", "http_status": 500,
                "target_auth": {"outcome": "rejected", "oauth_error": "invalid_client"}
            })
        );
        assert_eq!(stored["provider_id"], "machine");
    }

    #[tokio::test]
    async fn a_target_auth_failure_records_an_unregistered_oauth_error_as_other() {
        let ((), events) = crate::audit::producer::capture(async {
            target_auth_failed(
                &facts(),
                None,
                Some("machine"),
                TargetAuthOutcome::Rejected,
                500,
                Some(crate::delegation_vault::oauth::OAuthErrorCode::new("echoed client-id-12345")),
            );
        })
        .await;
        let stored = serde_json::to_value(&events[0]).unwrap();
        assert_eq!(stored["event"]["request_rejected"]["target_auth"]["oauth_error"], "other");
        assert!(
            !stored
                .to_string()
                .contains("client-id-12345"),
            "{stored}"
        );
    }

    #[tokio::test]
    async fn a_target_credential_the_peer_gateway_refused_is_recorded_with_both_statuses() {
        let ((), events) = crate::audit::producer::capture(async {
            target_credential_refused_by_target(&facts(), Some("partner"), Some("machine"), 500, 401);
        })
        .await;
        let stored = serde_json::to_value(&events[0]).unwrap();
        assert_eq!(
            stored["event"]["request_rejected"],
            serde_json::json!({
                "stage": "forward", "reason": "target_auth_failed", "http_status": 500,
                "target_auth": {"outcome": "refused_by_target", "transit_point": "partner", "upstream_status": 401}
            })
        );
        assert_eq!(stored["provider_id"], "machine");
    }

    #[test]
    fn a_stored_refusal_with_an_http_status_still_reads() {
        let read: DelegationAuditAction = serde_json::from_value(serde_json::json!({"request_rejected": {
            "stage": "routing", "reason": "unknown_variant", "http_status": 404, "requested_variant": "typo"
        }}))
        .unwrap();
        match read {
            DelegationAuditAction::RequestRejected { http_status, .. } => assert_eq!(http_status, Some(404)),
            other => panic!("expected RequestRejected, got {other:?}"),
        }
    }

    fn requested_variants(events: &[crate::delegation_vault::audit::DelegationAuditEvent]) -> Vec<Option<String>> {
        events
            .iter()
            .map(|event| match &event.event {
                DelegationAuditAction::RequestRejected { requested_variant, .. } => requested_variant.clone(),
                other => panic!("expected RequestRejected, got {other:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn each_routing_refusal_is_recorded_with_one_status_per_reason() {
        use crate::config::agent_surface_variants::VariantResolveError;
        let errors = [
            VariantResolveError::UnknownAlias("typo".into()),
            VariantResolveError::DisabledVariant("beta".into()),
            VariantResolveError::MisconfiguredDefault("removed".into()),
        ];
        let (refusals, events) = crate::audit::producer::capture(async {
            errors
                .iter()
                .map(|error| refuse_routing(&facts(), error, None))
                .collect::<Vec<_>>()
        })
        .await;

        let answered: Vec<_> = refusals
            .iter()
            .map(|refusal| (refusal.status().as_u16(), refusal.requested_variant()))
            .collect();
        assert_eq!(answered, vec![(404, Some("typo")), (404, None), (500, None),]);
        assert_eq!(
            rejected(&events),
            vec![
                (RejectionStage::Routing, RejectionReason::UnknownVariant, Some(404), None),
                (RejectionStage::Routing, RejectionReason::VariantDisabled, Some(404), None),
                (RejectionStage::Routing, RejectionReason::MisconfiguredDefault, Some(500), None),
            ]
        );
        assert_eq!(requested_variants(&events), vec![Some("typo".to_string()), None, None]);
        assert_eq!(refusals[0].message(), refusals[1].message(), "both 404s tell the caller the same");
        assert!(
            !refusals[0]
                .message()
                .contains("typo"),
            "the caller's alias is not echoed back"
        );
    }

    #[tokio::test]
    async fn a_requested_variant_is_cut_to_the_longest_alias() {
        use crate::config::agent_surface_variants::VariantResolveError;
        let long = "a".repeat(40);
        let accented = "é".repeat(40);
        let (_, events) = crate::audit::producer::capture(async {
            refuse_routing(&facts(), &VariantResolveError::UnknownAlias(long.clone()), None);
            refuse_routing(&facts(), &VariantResolveError::UnknownAlias(accented.clone()), None);
        })
        .await;

        assert_eq!(requested_variants(&events), vec![Some("a".repeat(32)), Some("é".repeat(32))]);
    }

    #[test]
    fn a_misconfigured_default_is_stored_in_snake_case() {
        assert_eq!(serde_json::to_value(RejectionReason::MisconfiguredDefault).unwrap(), "misconfigured_default");
    }

    #[tokio::test]
    async fn an_unroutable_request_is_recorded_against_an_unknown_surface() {
        let ((), events) = crate::audit::producer::capture(async {
            request_rejected(&RequestFacts::unroutable(), RejectionStage::Routing, RejectionReason::NoRoute, 404, None);
        })
        .await;

        assert_eq!(rejected(&events), vec![(RejectionStage::Routing, RejectionReason::NoRoute, Some(404), None)]);
        assert_eq!(
            events[0]
                .surface_id
                .as_deref(),
            Some(UNKNOWN_SURFACE)
        );
        assert_eq!(
            events[0]
                .channel_name
                .as_deref(),
            Some(UNKNOWN_SURFACE)
        );
        assert_eq!(events[0].trace_id, None);
    }

    #[tokio::test]
    async fn an_mcp_validation_error_is_recorded_as_the_caller_received_it() {
        let error = crate::mcp::request_validation::McpRequestValidationError {
            status: axum::http::StatusCode::BAD_REQUEST,
            id: None,
            code: crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION,
            message: "unsupported".into(),
            data: None,
        };
        let ((), events) = crate::audit::producer::capture(async {
            mcp_request_rejected(&facts(), &error);
        })
        .await;

        assert_eq!(
            rejected(&events),
            vec![(RejectionStage::Admission, RejectionReason::VersionUnsupported, Some(400), Some(-32022))]
        );
    }

    #[tokio::test]
    async fn a_refused_mcp_body_is_an_invalid_envelope_recorded_as_the_caller_received_it() {
        use crate::mcp::tool_analyzer::BodyRefusal;
        let ((), events) = crate::audit::producer::capture(async {
            mcp_body_refused(&facts(), &BodyRefusal::NotJson("eof".into()), false);
            mcp_body_refused(&facts(), &BodyRefusal::AmbiguousKeys, false);
            mcp_body_refused(&facts(), &BodyRefusal::Batch, false);
            mcp_body_refused(&facts(), &BodyRefusal::Batch, true);
        })
        .await;

        assert_eq!(
            rejected(&events),
            vec![
                (RejectionStage::Admission, RejectionReason::InvalidEnvelope, Some(200), Some(-32700)),
                (RejectionStage::Admission, RejectionReason::InvalidEnvelope, Some(200), Some(-32600)),
                (RejectionStage::Admission, RejectionReason::InvalidEnvelope, Some(422), None),
                (RejectionStage::Admission, RejectionReason::InvalidEnvelope, Some(400), Some(-32600)),
            ]
        );
    }

    #[test]
    fn mcp_refusals_are_classified_by_status_and_json_rpc_code() {
        assert_eq!(mcp_refusal_reason(413, Some(-32600)), RejectionReason::BodyTooLarge);
        assert_eq!(mcp_refusal_reason(400, Some(-32022)), RejectionReason::VersionUnsupported);
        assert_eq!(mcp_refusal_reason(400, Some(-32700)), RejectionReason::InvalidEnvelope);
        assert_eq!(mcp_refusal_reason(400, Some(-32600)), RejectionReason::InvalidEnvelope);
        assert_eq!(mcp_refusal_reason(400, Some(-32020)), RejectionReason::McpAdmission);
        assert_eq!(mcp_refusal_reason(400, Some(-32602)), RejectionReason::McpAdmission);
        // A rejected Origin or oversized headers carry -32600 too, but are
        // transport rules, not a malformed envelope.
        assert_eq!(mcp_refusal_reason(403, Some(-32600)), RejectionReason::McpAdmission);
        assert_eq!(mcp_refusal_reason(431, Some(-32600)), RejectionReason::McpAdmission);
        assert_eq!(mcp_refusal_reason(405, None), RejectionReason::McpAdmission);
    }

    #[tokio::test]
    async fn a_refused_resource_token_is_a_blocking_auth_failure() {
        use crate::protocols::protected_resource::ResourceTokenError;
        let ((), events) = crate::audit::producer::capture(async {
            resource_token_failed(&facts(), ResourceTokenError::InsufficientScope, None);
        })
        .await;

        assert_eq!(events.len(), 1);
        match &events[0].event {
            DelegationAuditAction::AuthFailed {
                scheme,
                reason,
                blocking,
                client_ip,
            } => {
                assert_eq!(*scheme, AuthScheme::McpResourceToken);
                assert_eq!(reason, "insufficient_scope");
                assert!(blocking);
                assert_eq!(*client_ip, None);
            }
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[test]
    fn source_auth_schemes_map_onto_audit_schemes() {
        use crate::source_auth::models::SourceAuthConfig;
        let scheme = |config: &SourceAuthConfig| source_auth_scheme(config);
        let jwt: SourceAuthConfig = serde_json::from_value(serde_json::json!({
            "type": "jwt_bearer", "jwt_verification_strategy_id": "s", "audiences": []
        }))
        .unwrap();
        assert_eq!(scheme(&jwt), AuthScheme::Jwt);
    }

    #[test]
    fn source_auth_errors_have_fixed_reason_codes() {
        use crate::source_auth::errors::SourceAuthError;
        let reason = |e: SourceAuthError| source_auth_reason(&e);
        assert_eq!(
            reason(SourceAuthError::MissingCredential {
                reason: "Missing bearer token".into()
            }),
            "missing_credential"
        );
        assert_eq!(
            reason(SourceAuthError::InvalidCredential {
                reason: "Token has expired".into()
            }),
            "invalid_credential"
        );
        assert_eq!(reason(SourceAuthError::AmbiguousCredentials), "ambiguous_credentials");
        assert_eq!(reason(SourceAuthError::ConfigNotFound { id: "s".into() }), "config_not_found");
        assert_eq!(reason(SourceAuthError::Internal { reason: "x".into() }), "internal");
    }

    #[test]
    fn resource_token_errors_have_fixed_reason_codes() {
        use crate::protocols::protected_resource::ResourceTokenError;
        assert_eq!(resource_token_reason(ResourceTokenError::Missing), "missing_credential");
        assert_eq!(resource_token_reason(ResourceTokenError::Invalid), "invalid_credential");
        assert_eq!(resource_token_reason(ResourceTokenError::InsufficientScope), "insufficient_scope");
        assert_eq!(resource_token_reason(ResourceTokenError::Unavailable), "unavailable");
    }
}
