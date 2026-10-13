//! Emit helpers for the governance events raised on the request path: the
//! emit site passes the facts it has, and a record is built only when a sink
//! selects the event.

use std::net::IpAddr;
use std::time::Duration;

pub use crate::audit::events::{RejectionReason, RejectionStage};

use crate::audit::events::{AuthScheme, RateLimitScope};
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent, audit_event, emit};
use crate::mcp::resource_server::ResourceTokenError;
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
        })
    })
}

/// The Access Point refused the request. `http_status` and `rpc_error_code`
/// are what the caller received.
pub fn request_rejected(
    facts: &RequestFacts<'_>,
    stage: RejectionStage,
    reason: RejectionReason,
    http_status: u16,
    rpc_error_code: Option<i64>,
) {
    emit("request_rejected", || {
        facts.record(DelegationAuditAction::RequestRejected {
            stage,
            reason,
            http_status,
            rpc_error_code,
        })
    })
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
                DelegationAuditAction::RateLimited { scope, retry_after_ms } => (*scope, *retry_after_ms),
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

    fn rejected(
        events: &[crate::delegation_vault::audit::DelegationAuditEvent]
    ) -> Vec<(RejectionStage, RejectionReason, u16, Option<i64>)> {
        events
            .iter()
            .map(|event| match &event.event {
                DelegationAuditAction::RequestRejected {
                    stage,
                    reason,
                    http_status,
                    rpc_error_code,
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
                (RejectionStage::Admission, RejectionReason::InvalidEnvelope, 200, Some(-32700)),
                (RejectionStage::Forward, RejectionReason::SsrfBlocked, 403, None),
            ]
        );
        assert_eq!(events[0].trace_id.as_deref(), Some("trace-1"));
    }

    #[tokio::test]
    async fn an_unroutable_request_is_recorded_against_an_unknown_surface() {
        let ((), events) = crate::audit::producer::capture(async {
            request_rejected(&RequestFacts::unroutable(), RejectionStage::Routing, RejectionReason::NoRoute, 404, None);
        })
        .await;

        assert_eq!(rejected(&events), vec![(RejectionStage::Routing, RejectionReason::NoRoute, 404, None)]);
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
            vec![(RejectionStage::Admission, RejectionReason::VersionUnsupported, 400, Some(-32022))]
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
        use crate::mcp::resource_server::ResourceTokenError;
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
        assert_eq!(reason(SourceAuthError::ConfigNotFound { id: "s".into() }), "config_not_found");
        assert_eq!(reason(SourceAuthError::Internal { reason: "x".into() }), "internal");
    }

    #[test]
    fn resource_token_errors_have_fixed_reason_codes() {
        use crate::mcp::resource_server::ResourceTokenError;
        assert_eq!(resource_token_reason(ResourceTokenError::Missing), "missing_credential");
        assert_eq!(resource_token_reason(ResourceTokenError::Invalid), "invalid_credential");
        assert_eq!(resource_token_reason(ResourceTokenError::InsufficientScope), "insufficient_scope");
        assert_eq!(resource_token_reason(ResourceTokenError::Unavailable), "unavailable");
    }
}
