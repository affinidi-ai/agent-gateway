//! Refusals of a caller at an Access Point, on the direct and Fabric sending paths.
//!
//! Every refusing stage answers through [`deny_caller`], which reads the declaration
//! resolved once for the request. A caller that failed source authentication on a
//! declaring Access Point gets the declaration's challenge; every other refused caller
//! gets the stage's 403. [`refuse_failed_caller_by_default`] is the built-in refusal of
//! such a caller after gateway policy and before AP2 and payment.

use axum::response::Response;

use crate::config::agent_surface::{AgentSurface, SurfaceProtocol};
use crate::source_auth::challenge::{CallerDenial, caller_deny_response};
use crate::source_auth::declaration::{Declaration, DeclarationOutcome, refuses_failed_callers_by_default};
use crate::state::ProxyState;
use crate::surface_context::SourceAuthContext;

/// The response for a caller a stage refused.
pub(crate) fn deny_caller(
    state: &ProxyState,
    denial: CallerDenial,
    source_auth: Option<&SourceAuthContext>,
) -> Response {
    deny(
        denial,
        &state
            .surface
            .access_point
            .protocol,
        state
            .access_point_declaration
            .as_deref(),
        source_auth,
    )
}

/// The refusal of a caller that failed source authentication on an Access Point whose
/// declaration refuses such callers without a policy: the declaration's challenge.
/// `None` lets the request go on.
pub(crate) fn refuse_failed_caller_by_default(
    state: &ProxyState,
    source_auth: Option<&SourceAuthContext>,
) -> Option<Response> {
    default_refusal(
        &state
            .surface
            .access_point
            .protocol,
        state
            .access_point_declaration
            .as_deref(),
        source_auth,
    )
}

/// Whether Target challenges other than `Payment` are dropped from this surface's
/// responses: the Access Point declares, so the gateway is the resource server and never
/// forwards the caller's token, or the Target is another gateway, which is answering the
/// sending gateway's credential.
pub(crate) fn drops_upstream_challenges(
    surface: &AgentSurface,
    declares: bool,
) -> bool {
    declares
        || surface
            .target
            .endpoint
            .starts_with("fabric://")
}

fn default_refusal(
    protocol: &SurfaceProtocol,
    outcome: Option<&DeclarationOutcome>,
    source_auth: Option<&SourceAuthContext>,
) -> Option<Response> {
    let outcome = outcome.filter(|outcome| refuses_failed_callers_by_default(outcome))?;
    matches!(source_auth, Some(SourceAuthContext::Failed { .. }))
        .then(|| deny(CallerDenial::CallerAuthentication, protocol, Some(outcome), source_auth))
}

fn deny(
    denial: CallerDenial,
    protocol: &SurfaceProtocol,
    outcome: Option<&DeclarationOutcome>,
    source_auth: Option<&SourceAuthContext>,
) -> Response {
    caller_deny_response(denial, protocol, declared(outcome), source_auth)
}

fn declared(outcome: Option<&DeclarationOutcome>) -> Option<&Declaration> {
    match outcome {
        Some(DeclarationOutcome::Declare(declaration)) => Some(declaration),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{StatusCode, header};
    use serde_json::json;

    use super::*;
    use crate::protocols::protected_resource::fixtures::{
        ISSUER, discovery_network, discovery_surface, jwt_bearer_method,
    };
    use crate::protocols::protected_resource::is_gateway_challenge;
    use crate::source_auth::declaration::{StripReason, resolve_surface_declaration};
    use crate::source_auth::errors::SourceAuthError;

    const METADATA: &str =
        "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha\"";
    const PROTOCOLS: [SurfaceProtocol; 2] = [SurfaceProtocol::Mcp, SurfaceProtocol::A2a];

    fn declaring_surface() -> AgentSurface {
        discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]})),
        )
    }

    fn surface_with_target(endpoint: &str) -> AgentSurface {
        let mut surface = discovery_surface(jwt_bearer_method(), None);
        surface.target.endpoint = endpoint.into();
        surface
    }

    async fn outcome(surface: &AgentSurface) -> DeclarationOutcome {
        resolve_surface_declaration(surface, None, None, &discovery_network())
            .await
            .expect("an explicit declaration reads no strategy store")
    }

    fn failed(error: SourceAuthError) -> SourceAuthContext {
        SourceAuthContext::failed("jwt_bearer", &error).expect("a caller-attributable failure")
    }

    fn missing() -> SourceAuthContext {
        failed(SourceAuthError::MissingCredential {
            reason: "Missing bearer token".into(),
        })
    }

    fn invalid() -> SourceAuthContext {
        failed(SourceAuthError::InvalidCredential {
            reason: "Invalid audience".into(),
        })
    }

    fn short_of_scope() -> SourceAuthContext {
        failed(SourceAuthError::InsufficientScope {
            missing: vec!["tools.call".into()],
        })
    }

    fn authenticated() -> SourceAuthContext {
        SourceAuthContext::ApiKey { key_name: "k".into() }
    }

    fn challenge(response: &Response) -> Option<String> {
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .map(|value| {
                value
                    .to_str()
                    .expect("ascii challenge")
                    .to_string()
            })
    }

    #[tokio::test]
    async fn only_a_declare_outcome_names_a_declaration() {
        let declare = outcome(&declaring_surface()).await;
        assert_eq!(
            declared(Some(&declare)).map(|declaration| declaration.resource.as_str()),
            Some("https://gateway.example/mcp/alpha")
        );
        for other in [
            None,
            Some(DeclarationOutcome::PassThrough),
            Some(DeclarationOutcome::Strip(StripReason::ForwardsCallerToken)),
            Some(DeclarationOutcome::Unservable(crate::source_auth::declaration::UnservableDeclaration::new(
                crate::source_auth::declaration::UnservableReason::StrategyStoreUnavailable,
                "x",
            ))),
        ] {
            assert_eq!(declared(other.as_ref()), None, "{other:?}");
        }
    }

    #[tokio::test]
    async fn a_failed_caller_on_a_declaring_access_point_gets_the_challenge() {
        let declare = outcome(&declaring_surface()).await;
        for protocol in &PROTOCOLS {
            let refusal = deny(CallerDenial::SurfacePolicy, protocol, Some(&declare), Some(&missing()));
            assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED, "{protocol:?}");
            assert!(is_gateway_challenge(&refusal), "{protocol:?}");
            let header = challenge(&refusal).expect("challenge");
            assert!(header.starts_with(METADATA), "{header}");
            assert!(!header.contains("error="), "{header}");

            let refusal = deny(CallerDenial::GatewayPolicy, protocol, Some(&declare), Some(&invalid()));
            assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED, "{protocol:?}");
            assert!(is_gateway_challenge(&refusal), "{protocol:?}");
            let header = challenge(&refusal).expect("challenge");
            assert!(header.starts_with(&format!("{METADATA}, error=\"invalid_token\"")), "{header}");
        }
    }

    #[tokio::test]
    async fn a_refusal_without_a_failed_caller_on_a_declaration_keeps_the_stage_403() {
        let declare = outcome(&declaring_surface()).await;
        let unservable = DeclarationOutcome::Unservable(crate::source_auth::declaration::UnservableDeclaration::new(
            crate::source_auth::declaration::UnservableReason::NotMcp,
            "requires an MCP Access Point",
        ));
        for protocol in &PROTOCOLS {
            for (outcome, source_auth) in [
                (Some(&declare), Some(authenticated())),
                (Some(&declare), None),
                (Some(&DeclarationOutcome::PassThrough), Some(missing())),
                (Some(&unservable), Some(missing())),
                (None, Some(invalid())),
            ] {
                let refusal = deny(CallerDenial::SurfacePolicy, protocol, outcome, source_auth.as_ref());
                assert_eq!(refusal.status(), StatusCode::FORBIDDEN, "{protocol:?} {outcome:?} {source_auth:?}");
                assert_eq!(challenge(&refusal), None, "{protocol:?} {outcome:?} {source_auth:?}");
                assert!(!is_gateway_challenge(&refusal), "{protocol:?} {outcome:?} {source_auth:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_declaring_access_point_refuses_a_failed_caller_by_default_with_its_challenge() {
        let declare = outcome(&declaring_surface()).await;
        for protocol in &PROTOCOLS {
            let refusal = default_refusal(protocol, Some(&declare), Some(&missing())).expect("refused");
            assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED, "{protocol:?}");
            assert!(is_gateway_challenge(&refusal), "{protocol:?}");
            let header = challenge(&refusal).expect("challenge");
            assert!(header.starts_with(METADATA), "{header}");
            assert!(!header.contains("error="), "{header}");

            let refusal = default_refusal(protocol, Some(&declare), Some(&invalid())).expect("refused");
            assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED, "{protocol:?}");
            let header = challenge(&refusal).expect("challenge");
            assert!(header.starts_with(&format!("{METADATA}, error=\"invalid_token\"")), "{header}");

            let refusal = default_refusal(protocol, Some(&declare), Some(&short_of_scope())).expect("refused");
            assert_eq!(refusal.status(), StatusCode::FORBIDDEN, "{protocol:?}");
            assert!(is_gateway_challenge(&refusal), "{protocol:?}");
            let header = challenge(&refusal).expect("challenge");
            assert!(header.starts_with(&format!("{METADATA}, error=\"insufficient_scope\"")), "{header}");
        }
    }

    #[tokio::test]
    async fn only_a_failed_caller_on_a_declaring_access_point_is_refused_by_default() {
        let declare = outcome(&declaring_surface()).await;
        let stripped = DeclarationOutcome::Strip(StripReason::ForwardsCallerToken);
        let unservable = DeclarationOutcome::Unservable(crate::source_auth::declaration::UnservableDeclaration::new(
            crate::source_auth::declaration::UnservableReason::StrategyStoreUnavailable,
            "strategy store unavailable",
        ));
        for protocol in &PROTOCOLS {
            for (outcome, source_auth) in [
                (Some(&declare), Some(authenticated())),
                (Some(&declare), None),
                (Some(&DeclarationOutcome::PassThrough), Some(missing())),
                (Some(&stripped), Some(invalid())),
                (Some(&unservable), Some(missing())),
                (None, Some(missing())),
            ] {
                assert!(
                    default_refusal(protocol, outcome, source_auth.as_ref()).is_none(),
                    "{protocol:?} {outcome:?} {source_auth:?}"
                );
            }
        }
    }

    #[test]
    fn a_declaring_access_point_or_a_fabric_target_drops_upstream_challenges() {
        assert!(drops_upstream_challenges(&surface_with_target("https://agent.internal"), true));
        assert!(drops_upstream_challenges(&surface_with_target("fabric://gw2/surface"), false));
        assert!(drops_upstream_challenges(&surface_with_target("fabric://gw2/surface"), true));
    }

    #[test]
    fn a_non_declaring_access_point_keeps_upstream_challenges_whatever_it_authenticates() {
        let api_key = json!({"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"});
        let forwarding = json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "forward_header": true});
        for method in [api_key, jwt_bearer_method(), forwarding] {
            let surface = discovery_surface(method.clone(), None);
            assert!(!drops_upstream_challenges(&surface, false), "{method}");
        }
        assert!(!drops_upstream_challenges(&surface_with_target("http://localhost:9000"), false));
    }
}
