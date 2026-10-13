//! Emit helpers for the governance events raised on the request path: the
//! emit site passes the facts it has, and a record is built only when a sink
//! selects the event.

use std::net::IpAddr;
use std::time::Duration;

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

impl RequestFacts<'_> {
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
