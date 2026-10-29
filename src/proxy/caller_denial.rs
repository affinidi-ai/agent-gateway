//! Refusals of a caller at an Access Point, on the direct and Fabric sending paths.
//!
//! Every refusing stage answers through [`deny_caller`], which reads the declaration
//! resolved once for the request. A caller that failed source authentication on a
//! declaring Access Point gets the declaration's challenge; every other refused caller
//! gets the stage's 403.

use axum::response::Response;

use crate::config::agent_surface::AgentSurface;
use crate::source_auth::challenge::{CallerDenial, caller_deny_response};
use crate::source_auth::declaration::{Declaration, DeclarationOutcome};
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

fn deny(
    denial: CallerDenial,
    outcome: Option<&DeclarationOutcome>,
    source_auth: Option<&SourceAuthContext>,
) -> Response {
    caller_deny_response(denial, declared(outcome), source_auth)
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
    use crate::source_auth::declaration::resolve_surface_declaration;
    use crate::source_auth::errors::SourceAuthError;

    const METADATA: &str =
        "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha\"";

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

    fn outcome(surface: &AgentSurface) -> DeclarationOutcome {
        resolve_surface_declaration(surface, None, &discovery_network())
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

    #[test]
    fn only_a_declare_outcome_names_a_declaration() {
        let surface = declaring_surface();
        let declare = outcome(&surface);
        assert_eq!(
            declared(Some(&declare)).map(|declaration| declaration.resource.as_str()),
            Some("https://gateway.example/mcp/alpha")
        );
        for other in [None, Some(DeclarationOutcome::PassThrough), Some(DeclarationOutcome::Unservable("x".into()))] {
            assert_eq!(declared(other.as_ref()), None, "{other:?}");
        }
    }

    #[test]
    fn a_failed_caller_on_a_declaring_access_point_gets_the_challenge() {
        let surface = declaring_surface();
        let declare = outcome(&surface);

        let refusal = deny(CallerDenial::SurfacePolicy, Some(&declare), Some(&missing()));
        assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        assert!(is_gateway_challenge(&refusal));
        let header = challenge(&refusal).expect("challenge");
        assert!(header.starts_with(METADATA), "{header}");
        assert!(!header.contains("error="), "{header}");

        let refusal = deny(CallerDenial::GatewayPolicy, Some(&declare), Some(&invalid()));
        assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        assert!(is_gateway_challenge(&refusal));
        let header = challenge(&refusal).expect("challenge");
        assert!(header.starts_with(&format!("{METADATA}, error=\"invalid_token\"")), "{header}");
    }

    #[test]
    fn a_refusal_without_a_failed_caller_on_a_declaration_keeps_the_stage_403() {
        let surface = declaring_surface();
        let declare = outcome(&surface);
        let unservable = DeclarationOutcome::Unservable("requires an MCP Access Point".into());
        for (outcome, source_auth) in [
            (Some(&declare), Some(authenticated())),
            (Some(&declare), None),
            (Some(&DeclarationOutcome::PassThrough), Some(missing())),
            (Some(&unservable), Some(missing())),
            (None, Some(invalid())),
        ] {
            let refusal = deny(CallerDenial::SurfacePolicy, outcome, source_auth.as_ref());
            assert_eq!(refusal.status(), StatusCode::FORBIDDEN, "{outcome:?} {source_auth:?}");
            assert_eq!(challenge(&refusal), None, "{outcome:?} {source_auth:?}");
            assert!(!is_gateway_challenge(&refusal), "{outcome:?} {source_auth:?}");
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
