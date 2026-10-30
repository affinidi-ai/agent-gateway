//! Refusals of a caller at an Access Point. A caller whose source authentication
//! failed on a declaring Access Point is answered once, at source authentication
//! or at routing, by [`challenge_failed_caller`]; no later stage sees such a
//! caller. Every policy stage refuses with [`CallerDenial::refusal`].

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;

use crate::config::agent_surface::AgentSurface;

/// The stage that refused a caller. It names the body of the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallerDenial {
    AppliancePolicy,
    GatewayPolicy,
    SurfacePolicy,
    SurfacePolicyUnloaded,
    IdentityRequired,
}

impl CallerDenial {
    /// The stage's `403`: a body naming the stage, never a challenge.
    pub(crate) fn refusal(self) -> Response {
        let status = StatusCode::FORBIDDEN;
        let proxy_error = |detail: &str| crate::a2a::errors::proxy_error_body(status, detail);
        let surface_error = |message: &str| serde_json::json!({ "error": "Forbidden", "message": message });
        let (content_type, body) = match self {
            Self::AppliancePolicy => {
                ("application/problem+json", proxy_error("Request blocked by appliance-wide policy"))
            }
            Self::GatewayPolicy => ("application/problem+json", proxy_error("Request blocked by gateway policy")),
            Self::SurfacePolicy => ("application/json", surface_error("Agent trust policy denied the request")),
            Self::SurfacePolicyUnloaded => (
                "application/json",
                surface_error("OPA policy enforcement is enabled but no policy is loaded for this channel"),
            ),
            Self::IdentityRequired => (
                "application/problem+json",
                serde_json::json!({
                    "type": "https://affinidi.com/atg/errors/identity-required",
                    "title": "Identity Required for Credential Delegation",
                    "status": status.as_u16(),
                    "detail": "This channel requires credential delegation which needs authenticated source identity. \
                               Configure source authentication and agent identity management on this channel.",
                }),
            ),
        };
        let mut response = Response::new(Body::from(body.to_string()));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        response
    }
}

/// The one answer to a caller whose source authentication failed on a declaring
/// Access Point, on every protocol: records a blocking `auth_failed` and returns
/// the declaration's challenge, `401` for a missing or invalid token and `403`
/// with `error="insufficient_scope"` for a scope shortfall, as a problem with a
/// fixed detail, `Cache-Control: no-store` and the `GatewayChallenge` marker;
/// `503` without a challenge when the metadata URL cannot be named.
pub(crate) fn challenge_failed_caller(
    facts: &crate::audit::request_events::RequestFacts<'_>,
    declaration: &crate::source_auth::declaration::Declaration,
    scheme: crate::audit::events::AuthScheme,
    error: &crate::source_auth::errors::SourceAuthError,
    client_ip: Option<std::net::IpAddr>,
) -> Response {
    crate::audit::request_events::auth_failed(
        facts,
        scheme,
        crate::audit::request_events::source_auth_reason(error),
        true,
        client_ip,
    );
    declaration.caller_challenge(error)
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

#[cfg(test)]
mod tests {
    use axum::http::header;
    use serde_json::{Value, json};

    use super::*;
    use crate::audit::events::AuthScheme;
    use crate::audit::request_events::RequestFacts;
    use crate::config::agent_surface::SurfaceProtocol;
    use crate::delegation_vault::audit::DelegationAuditAction;
    use crate::protocols::protected_resource::fixtures::{
        FixtureStrategies, ISSUER, STRATEGY_ID, discovery_network, discovery_surface, jwt_bearer_method,
    };
    use crate::protocols::protected_resource::is_gateway_challenge;
    use crate::source_auth::declaration::{Declaration, DeclarationOutcome, resolve_surface_declaration};
    use crate::source_auth::errors::SourceAuthError;

    const TOKEN_REQUIRED: &str =
        "A bearer token from an authorization server in the protected resource metadata is required";
    const SCOPE_REQUIRED: &str = "A bearer token granting the scopes in the challenge is required";
    const CLIENT_IP: &str = "203.0.113.7";

    fn scoped_method() -> Value {
        json!({"type": "jwt_bearer", "jwt_verification_strategy_id": STRATEGY_ID, "audiences": [],
            "required_scopes": ["tools.call"]})
    }

    fn declaring_surface(
        protocol: SurfaceProtocol,
        route: &str,
    ) -> AgentSurface {
        let mut surface =
            discovery_surface(scoped_method(), Some(json!({"resource": format!("https://gateway.example{route}")})));
        surface.access_point.protocol = protocol;
        surface.access_point.route = route.into();
        surface
    }

    async fn declaration_of(surface: &AgentSurface) -> Declaration {
        match resolve_surface_declaration(surface, None, Some(&FixtureStrategies::Pinned), &discovery_network())
            .await
            .expect("a pinned strategy resolves")
        {
            DeclarationOutcome::Declare(declaration) => declaration,
            other => panic!("expected a declaration, got {other:?}"),
        }
    }

    fn declaration_for(resource: &str) -> Declaration {
        Declaration {
            resource: resource.into(),
            authorization_servers: vec![ISSUER.into()],
            pin: None,
            required_scopes: Vec::new(),
            advertised_scopes: Vec::new(),
        }
    }

    fn facts() -> RequestFacts<'static> {
        RequestFacts {
            surface_id: "alpha",
            channel_name: "alpha",
            trace_id: Some("trace-1"),
            via_fabric: false,
        }
    }

    fn surface_with_target(endpoint: &str) -> AgentSurface {
        let mut surface = discovery_surface(jwt_bearer_method(), None);
        surface.target.endpoint = endpoint.into();
        surface
    }

    fn header_of(
        response: &Response,
        name: header::HeaderName,
    ) -> Option<String> {
        response
            .headers()
            .get(name)
            .map(|value| {
                value
                    .to_str()
                    .expect("ascii header")
                    .to_string()
            })
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    #[tokio::test]
    async fn a_failed_caller_of_a_declaring_access_point_gets_one_challenge_whatever_the_protocol() {
        let routes = [(SurfaceProtocol::Mcp, "/mcp/alpha"), (SurfaceProtocol::A2a, "/a2a/buyer")];
        for (protocol, route) in routes {
            let declaration = declaration_of(&declaring_surface(protocol.clone(), route)).await;
            let metadata = format!("https://gateway.example/.well-known/oauth-protected-resource{route}");
            let cases = [
                (
                    SourceAuthError::MissingCredential {
                        reason: "Missing bearer token".into(),
                    },
                    StatusCode::UNAUTHORIZED,
                    format!("Bearer resource_metadata=\"{metadata}\", scope=\"tools.call\""),
                    json!({"type": "about:blank", "title": "Unauthorized", "status": 401, "detail": TOKEN_REQUIRED}),
                    "missing_credential",
                ),
                (
                    SourceAuthError::InvalidCredential {
                        reason: "Invalid audience".into(),
                    },
                    StatusCode::UNAUTHORIZED,
                    format!("Bearer resource_metadata=\"{metadata}\", error=\"invalid_token\", scope=\"tools.call\""),
                    json!({"type": "about:blank", "title": "Unauthorized", "status": 401, "detail": TOKEN_REQUIRED}),
                    "invalid_credential",
                ),
                (
                    SourceAuthError::InsufficientScope {
                        missing: vec!["tools.call".into()],
                    },
                    StatusCode::FORBIDDEN,
                    format!(
                        "Bearer resource_metadata=\"{metadata}\", error=\"insufficient_scope\", scope=\"tools.call\""
                    ),
                    json!({"type": "about:blank", "title": "Forbidden", "status": 403, "detail": SCOPE_REQUIRED}),
                    "insufficient_scope",
                ),
            ];
            for (error, status, challenge, body, reason) in cases {
                let (response, events) = crate::audit::producer::capture(async {
                    challenge_failed_caller(
                        &facts(),
                        &declaration,
                        AuthScheme::Jwt,
                        &error,
                        Some(CLIENT_IP.parse().unwrap()),
                    )
                })
                .await;
                assert_eq!(response.status(), status, "{protocol:?} {error:?}");
                assert_eq!(header_of(&response, header::WWW_AUTHENTICATE), Some(challenge), "{protocol:?} {error:?}");
                assert_eq!(
                    header_of(&response, header::CONTENT_TYPE).as_deref(),
                    Some("application/problem+json"),
                    "{protocol:?} {error:?}"
                );
                assert_eq!(
                    header_of(&response, header::CACHE_CONTROL).as_deref(),
                    Some("no-store"),
                    "{protocol:?} {error:?}"
                );
                assert!(is_gateway_challenge(&response), "{protocol:?} {error:?}");
                let text = body_text(response).await;
                assert!(!text.contains("Missing bearer token") && !text.contains("Invalid audience"), "{text}");
                assert_eq!(serde_json::from_str::<Value>(&text).expect("json body"), body, "{protocol:?}");

                assert_eq!(events.len(), 1, "{protocol:?} {error:?}");
                assert_eq!(
                    events[0]
                        .surface_id
                        .as_deref(),
                    Some("alpha")
                );
                match &events[0].event {
                    DelegationAuditAction::AuthFailed {
                        scheme,
                        reason: recorded,
                        blocking,
                        client_ip,
                    } => {
                        assert_eq!(*scheme, AuthScheme::Jwt);
                        assert_eq!(recorded, reason);
                        assert!(*blocking, "{protocol:?} {error:?}");
                        assert_eq!(client_ip.as_deref(), Some(CLIENT_IP));
                    }
                    other => panic!("expected AuthFailed, got {other:?}"),
                }
            }
        }
    }

    #[tokio::test]
    async fn each_policy_stage_refuses_with_its_403_and_no_challenge() {
        let cases = [
            (
                CallerDenial::AppliancePolicy,
                "application/problem+json",
                "detail",
                "Request blocked by appliance-wide policy",
            ),
            (CallerDenial::GatewayPolicy, "application/problem+json", "detail", "Request blocked by gateway policy"),
            (CallerDenial::SurfacePolicy, "application/json", "message", "Agent trust policy denied the request"),
            (
                CallerDenial::SurfacePolicyUnloaded,
                "application/json",
                "message",
                "OPA policy enforcement is enabled but no policy is loaded for this channel",
            ),
        ];
        for (denial, content_type, field, text) in cases {
            let refusal = denial.refusal();
            assert_eq!(refusal.status(), StatusCode::FORBIDDEN, "{denial:?}");
            assert_eq!(header_of(&refusal, header::WWW_AUTHENTICATE), None, "{denial:?}");
            assert_eq!(header_of(&refusal, header::CACHE_CONTROL), None, "{denial:?}");
            assert_eq!(header_of(&refusal, header::CONTENT_TYPE).as_deref(), Some(content_type), "{denial:?}");
            assert!(!is_gateway_challenge(&refusal), "{denial:?}");
            let body: Value = serde_json::from_str(&body_text(refusal).await).expect("json body");
            assert_eq!(body[field], text, "{denial:?}");
        }

        let proxy_error: Value =
            serde_json::from_str(&body_text(CallerDenial::GatewayPolicy.refusal()).await).expect("json body");
        assert_eq!(
            proxy_error,
            json!({
                "type": "https://a2a-protocol.org/errors/proxy-error",
                "title": "Forbidden",
                "status": 403,
                "detail": "Request blocked by gateway policy",
            })
        );
        let surface_error: Value =
            serde_json::from_str(&body_text(CallerDenial::SurfacePolicy.refusal()).await).expect("json body");
        assert_eq!(surface_error, json!({"error": "Forbidden", "message": "Agent trust policy denied the request"}));

        let identity = CallerDenial::IdentityRequired.refusal();
        assert_eq!(identity.status(), StatusCode::FORBIDDEN);
        assert_eq!(header_of(&identity, header::WWW_AUTHENTICATE), None);
        assert!(!is_gateway_challenge(&identity));
        let body: Value = serde_json::from_str(&body_text(identity).await).expect("json body");
        assert_eq!(body["type"], "https://affinidi.com/atg/errors/identity-required");
        assert_eq!(body["status"], 403);
    }

    #[tokio::test]
    async fn a_declaration_that_cannot_name_its_metadata_answers_503_without_a_challenge() {
        let unnamed = declaration_for("http://gateway.example/mcp/alpha");
        let missing = SourceAuthError::MissingCredential {
            reason: "Missing bearer token".into(),
        };
        let (response, events) = crate::audit::producer::capture(async {
            challenge_failed_caller(&facts(), &unnamed, AuthScheme::Jwt, &missing, None)
        })
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(header_of(&response, header::WWW_AUTHENTICATE), None);
        assert!(!is_gateway_challenge(&response));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn a_root_route_resource_names_the_bare_metadata_path() {
        let root = declaration_for("https://gateway.example/");
        let missing = SourceAuthError::MissingCredential {
            reason: "Missing bearer token".into(),
        };
        let response = challenge_failed_caller(&facts(), &root, AuthScheme::Jwt, &missing, None);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            header_of(&response, header::WWW_AUTHENTICATE).as_deref(),
            Some("Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource\"")
        );
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
