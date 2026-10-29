//! The resource server declaration of an Access Point.
//!
//! For the route called, an Access Point either declares the OAuth protection
//! the gateway enforces, asks for a declaration it cannot serve, or passes
//! through. The protected resource metadata, the audience a caller's token must
//! name and the caller challenge are projections of the declaration, so every
//! consumer reads it from [`resolve_surface_declaration`]. The RFC 6750 and
//! RFC 9728 strings come from [`crate::protocols::protected_resource`].

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::config::NetworkConfig;
use crate::config::agent_surface::AgentSurface;
use crate::jwt_bearer::models::JwtBearerAuthConfig;
use crate::protocols::protected_resource::{self, ProtectedResourceConfig, ResourceTokenError};
use crate::source_auth::SourceAuthConfig;
use crate::source_auth::errors::SourceAuthError;

const TOKEN_REQUIRED: &str =
    "A bearer token from an authorization server in the protected resource metadata is required";
const SCOPE_REQUIRED: &str = "A bearer token granting the scopes in the challenge is required";
const FABRIC_TOKEN_REQUIRED: &str = "A bearer token issued for this resource is required";
const FABRIC_SCOPE_REQUIRED: &str = "A bearer token granting the scopes this resource requires is required";

/// The resource server facts a declaring Access Point publishes for the route
/// called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    /// The resource of the route called, base or `$alias` variant.
    pub resource: String,
    pub authorization_servers: Vec<String>,
    /// The scopes a caller's token must grant, which the challenge names.
    pub required_scopes: Vec<String>,
    /// The scopes the metadata lists as supported: the required scopes, then
    /// any other scope the settings advertise.
    pub advertised_scopes: Vec<String>,
}

impl Declaration {
    /// The RFC 9728 document the Access Point publishes.
    pub fn metadata(&self) -> Value {
        protected_resource::metadata_document(&self.resource, &self.authorization_servers, &self.advertised_scopes)
    }

    pub fn metadata_url(&self) -> Result<url::Url, String> {
        protected_resource::metadata_url(&self.resource)
    }

    /// The caller authentication the Access Point enforces: a JWT Bearer token
    /// must name the resource of the route called as its audience (RFC 8707),
    /// so a token the same authorization server issued for another resource or
    /// variant is refused.
    pub fn bind_audience(
        &self,
        config: &JwtBearerAuthConfig,
    ) -> JwtBearerAuthConfig {
        JwtBearerAuthConfig {
            audiences: vec![self.resource.clone()],
            ..config.clone()
        }
    }

    /// The answer to a caller whose token is missing, invalid or short of the
    /// required scopes: a problem with the challenge naming this resource's
    /// metadata document and the required scopes, `401`, or `403` with
    /// `error="insufficient_scope"`. The detail is fixed, so the response
    /// never says why a token failed. A `503` without a challenge when the
    /// Access Point cannot check tokens.
    pub fn challenge(
        &self,
        error: ResourceTokenError,
    ) -> Response {
        let challenge = match error {
            ResourceTokenError::Unavailable => None,
            _ => self
                .metadata_url()
                .ok()
                .and_then(|metadata| protected_resource::challenge_header(&metadata, error, &self.required_scopes)),
        };
        let Some(challenge) = challenge else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let detail = match error {
            ResourceTokenError::InsufficientScope => SCOPE_REQUIRED,
            _ => TOKEN_REQUIRED,
        };
        protected_resource::refusal(error.status_code(), Some(challenge), detail)
    }

    /// The challenge for a caller authentication failure the caller caused,
    /// by its failure kind: without an error code when no credential was sent.
    pub fn caller_challenge(
        &self,
        error: &SourceAuthError,
    ) -> Response {
        self.challenge(caller_token_error(error))
    }

    /// The answer over Fabric to a caller authentication failure, before
    /// policy but without `resource_metadata`: `401`, or `403` with
    /// `error="insufficient_scope"`. The sending gateway strips the caller's
    /// own token, so only a credential it injects for this resource can pass,
    /// and sending the remote client to fetch a token for this resource would
    /// only loop.
    pub fn fabric_refusal(
        &self,
        error: &SourceAuthError,
    ) -> Response {
        let error = caller_token_error(error);
        let detail = match error {
            ResourceTokenError::InsufficientScope => FABRIC_SCOPE_REQUIRED,
            _ => FABRIC_TOKEN_REQUIRED,
        };
        protected_resource::refusal(
            error.status_code(),
            Some(protected_resource::realm_challenge_header(error)),
            detail,
        )
    }
}

/// The resource token error a caller authentication failure answers with:
/// any failure without a caller failure kind counts as an invalid token.
fn caller_token_error(error: &SourceAuthError) -> ResourceTokenError {
    error
        .failure_kind()
        .map_or(ResourceTokenError::Invalid, ResourceTokenError::from)
}

/// The required scopes, then each advertised scope not already among them.
fn scopes_supported(
    required_scopes: &[String],
    advertised_scopes: &[String],
) -> Vec<String> {
    let mut scopes = required_scopes.to_vec();
    for scope in advertised_scopes {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    scopes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclarationOutcome {
    Declare(Declaration),
    PassThrough,
    /// The settings ask for a declaration the Access Point cannot serve, so
    /// callers fail closed.
    Unservable(String),
}

/// The declaration of a resolved Access Point for the route called, `alias`
/// naming its variant: the `protected_resource` setting of its caller
/// authentication, or a pass-through without one. The direct path, Fabric
/// receive and the metadata route all resolve it here.
pub fn resolve_surface_declaration(
    surface: &AgentSurface,
    alias: Option<&str>,
    network: &NetworkConfig,
) -> DeclarationOutcome {
    match surface.protected_resource() {
        Some(configured) => explicit_declaration(surface, configured, alias, network),
        None => DeclarationOutcome::PassThrough,
    }
}

fn explicit_declaration(
    surface: &AgentSurface,
    configured: &ProtectedResourceConfig,
    alias: Option<&str>,
    network: &NetworkConfig,
) -> DeclarationOutcome {
    match protected_resource::access_point_protected_resource(surface, alias, network) {
        Some(Ok(served)) => {
            let required_scopes = match surface.source_auth() {
                Some(SourceAuthConfig::JwtBearer(config)) => config.required_scopes.clone(),
                _ => Vec::new(),
            };
            DeclarationOutcome::Declare(Declaration {
                resource: served.resource,
                authorization_servers: configured
                    .authorization_servers
                    .clone(),
                advertised_scopes: scopes_supported(&required_scopes, &configured.scopes),
                required_scopes,
            })
        }
        Some(Err(reason)) => DeclarationOutcome::Unservable(reason),
        None => DeclarationOutcome::PassThrough,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::header;
    use serde_json::json;

    use super::*;
    use crate::protocols::protected_resource::fixtures::{
        ISSUER, discovery_network, discovery_surface, jwt_bearer_method,
    };
    use crate::protocols::protected_resource::is_gateway_challenge;

    const RESOURCE: &str = "https://gateway.example/mcp/alpha";
    const METADATA: &str = "https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha";

    fn explicit(resource: &str) -> Value {
        json!({"resource": resource, "authorization_servers": [ISSUER], "scopes": ["tools"]})
    }

    fn declaring_surface() -> AgentSurface {
        discovery_surface(jwt_bearer_method(), Some(explicit(RESOURCE)))
    }

    /// A declaring surface whose callers' tokens must grant `tools.call` and
    /// `tools`, advertising `tools` and `resources`.
    fn scoped_surface() -> AgentSurface {
        let mut method = jwt_bearer_method();
        method["required_scopes"] = json!(["tools.call", "tools"]);
        discovery_surface(
            method,
            Some(json!({"resource": RESOURCE, "authorization_servers": [ISSUER], "scopes": ["tools", "resources"]})),
        )
    }

    fn short_of_scope() -> SourceAuthError {
        SourceAuthError::InsufficientScope {
            missing: vec!["tools.call".into()],
        }
    }

    async fn problem(response: Response) -> Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body"),
        )
        .expect("problem")
    }

    fn root_surface() -> AgentSurface {
        let mut root = discovery_surface(jwt_bearer_method(), Some(explicit("https://gateway.example/")));
        root.access_point.route = "/".into();
        root
    }

    fn resolve(
        surface: &AgentSurface,
        alias: Option<&str>,
    ) -> DeclarationOutcome {
        let view = surface
            .resolve_variant(alias)
            .expect("variant");
        resolve_surface_declaration(&view, alias, &discovery_network())
    }

    fn declaration(
        surface: &AgentSurface,
        alias: Option<&str>,
    ) -> Declaration {
        match resolve(surface, alias) {
            DeclarationOutcome::Declare(declaration) => declaration,
            other => panic!("expected a declaration, got {other:?}"),
        }
    }

    fn missing() -> SourceAuthError {
        SourceAuthError::MissingCredential {
            reason: "Missing bearer token".into(),
        }
    }

    fn invalid() -> SourceAuthError {
        SourceAuthError::InvalidCredential {
            reason: "Invalid audience".into(),
        }
    }

    #[test]
    fn an_explicit_protected_resource_declares_the_resource_of_the_route_called() {
        let surface = declaring_surface();
        assert_eq!(
            resolve(&surface, None),
            DeclarationOutcome::Declare(Declaration {
                resource: RESOURCE.into(),
                authorization_servers: vec![ISSUER.into()],
                required_scopes: Vec::new(),
                advertised_scopes: vec!["tools".into()],
            })
        );
        assert_eq!(declaration(&surface, Some("beta")).resource, "https://gateway.example/mcp/alpha$beta");
        assert_eq!(declaration(&root_surface(), None).resource, "https://gateway.example/");
    }

    #[test]
    fn an_access_point_without_a_protected_resource_passes_through() {
        let mut scoped = jwt_bearer_method();
        scoped["required_scopes"] = json!(["agent.invoke"]);
        for method in [jwt_bearer_method(), scoped] {
            let surface = discovery_surface(method.clone(), None);
            assert_eq!(resolve(&surface, None), DeclarationOutcome::PassThrough, "{method}");
            assert_eq!(resolve(&surface, Some("beta")), DeclarationOutcome::PassThrough, "{method}");
        }
    }

    #[test]
    fn a_protected_resource_the_access_point_cannot_serve_is_unservable() {
        assert!(matches!(resolve(&root_surface(), Some("beta")), DeclarationOutcome::Unservable(_)));

        let mut a2a = declaring_surface();
        a2a.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::A2a;
        assert_eq!(resolve(&a2a, None), DeclarationOutcome::Unservable("requires an MCP Access Point".into()));

        for unserved in [explicit("https://other.example/mcp/alpha"), explicit("https://gateway.example/mcp/other")] {
            let surface = discovery_surface(jwt_bearer_method(), Some(unserved.clone()));
            assert!(matches!(resolve(&surface, None), DeclarationOutcome::Unservable(_)), "{unserved}");
        }
        for method in [
            json!({"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "token_header": "x-token"}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "forward_header": true}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [RESOURCE]}),
        ] {
            let surface = discovery_surface(method.clone(), Some(explicit(RESOURCE)));
            assert!(matches!(resolve(&surface, None), DeclarationOutcome::Unservable(_)), "{method}");
        }
    }

    #[test]
    fn a_declaration_publishes_its_document_at_an_absolute_metadata_url() {
        assert_eq!(
            declaration(&declaring_surface(), None).metadata(),
            json!({
                "resource": RESOURCE,
                "authorization_servers": [ISSUER],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["tools"]
            })
        );
        let unscoped = Declaration {
            advertised_scopes: Vec::new(),
            ..declaration(&declaring_surface(), None)
        };
        assert_eq!(
            unscoped
                .metadata()
                .get("scopes_supported"),
            None
        );

        for (surface, alias, expected) in [
            (declaring_surface(), None, "https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha"),
            (
                declaring_surface(),
                Some("beta"),
                "https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha$beta",
            ),
            (root_surface(), None, "https://gateway.example/.well-known/oauth-protected-resource"),
        ] {
            assert_eq!(
                declaration(&surface, alias)
                    .metadata_url()
                    .expect("metadata URL")
                    .as_str(),
                expected
            );
        }
    }

    #[test]
    fn a_declaration_accepts_only_tokens_for_the_resource_of_the_route_called() {
        let surface = scoped_surface();
        let Some(SourceAuthConfig::JwtBearer(method)) = surface.source_auth().cloned() else {
            panic!("the declaring surface authenticates callers with JWT Bearer");
        };
        let method = JwtBearerAuthConfig {
            audiences: vec!["https://other.example/mcp".into()],
            ..method
        };
        for (alias, audience) in [(None, RESOURCE), (Some("beta"), "https://gateway.example/mcp/alpha$beta")] {
            let bound = declaration(&surface, alias).bind_audience(&method);
            assert_eq!(bound.audiences, [audience]);
            assert_eq!(
                JwtBearerAuthConfig {
                    audiences: method.audiences.clone(),
                    ..bound
                },
                method
            );
        }
    }

    #[test]
    fn a_declaration_requires_the_method_scopes_and_supports_the_advertised_ones_too() {
        for alias in [None, Some("beta")] {
            let declaration = declaration(&scoped_surface(), alias);
            assert_eq!(declaration.required_scopes, ["tools.call", "tools"], "{alias:?}");
            assert_eq!(declaration.advertised_scopes, ["tools.call", "tools", "resources"], "{alias:?}");
            assert_eq!(
                declaration.metadata()["scopes_supported"],
                json!(["tools.call", "tools", "resources"]),
                "{alias:?}"
            );
        }
        let unrequired = declaration(&declaring_surface(), None);
        assert_eq!(unrequired.required_scopes, Vec::<String>::new());
        assert_eq!(unrequired.advertised_scopes, ["tools"]);
    }

    #[tokio::test]
    async fn the_challenge_names_the_metadata_and_never_why_a_token_failed() {
        let declaration = declaration(&declaring_surface(), None);
        let missing = declaration.challenge(ResourceTokenError::Missing);
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            missing.headers()[header::WWW_AUTHENTICATE],
            format!("Bearer resource_metadata=\"{METADATA}\"").as_str()
        );
        assert_eq!(missing.headers()[header::CONTENT_TYPE], "application/problem+json");
        assert!(is_gateway_challenge(&missing));
        assert_eq!(
            problem(declaration.challenge(ResourceTokenError::Invalid)).await,
            json!({
                "type": "about:blank",
                "title": "Unauthorized",
                "status": 401,
                "detail": "A bearer token from an authorization server in the protected resource metadata is required"
            })
        );
        let unavailable = declaration.challenge(ResourceTokenError::Unavailable);
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !unavailable
                .headers()
                .contains_key(header::WWW_AUTHENTICATE)
        );
        assert!(!is_gateway_challenge(&unavailable));
    }

    #[tokio::test]
    async fn a_scope_shortfall_is_403_naming_only_the_required_scopes() {
        let scoped = declaration(&scoped_surface(), None);
        let forbidden = scoped.challenge(ResourceTokenError::InsufficientScope);
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            forbidden.headers()[header::WWW_AUTHENTICATE],
            format!(
                "Bearer resource_metadata=\"{METADATA}\", error=\"insufficient_scope\", scope=\"tools.call tools\""
            )
            .as_str()
        );
        assert_eq!(forbidden.headers()[header::CACHE_CONTROL], "no-store");
        assert!(is_gateway_challenge(&forbidden));
        assert_eq!(
            problem(forbidden).await,
            json!({
                "type": "about:blank",
                "title": "Forbidden",
                "status": 403,
                "detail": "A bearer token granting the scopes in the challenge is required"
            })
        );

        let unscoped = declaration(&declaring_surface(), None).challenge(ResourceTokenError::InsufficientScope);
        assert_eq!(unscoped.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            unscoped.headers()[header::WWW_AUTHENTICATE],
            format!("Bearer resource_metadata=\"{METADATA}\", error=\"insufficient_scope\"").as_str()
        );

        let unavailable = scoped.challenge(ResourceTokenError::Unavailable);
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !unavailable
                .headers()
                .contains_key(header::WWW_AUTHENTICATE)
        );
    }

    #[test]
    fn every_caller_and_fabric_challenge_is_marked_as_the_gateways() {
        let declaration = declaration(&scoped_surface(), None);
        let metadata = format!("Bearer resource_metadata=\"{METADATA}\"");
        let scope = "scope=\"tools.call tools\"";
        for (response, status, challenge) in [
            (declaration.caller_challenge(&missing()), StatusCode::UNAUTHORIZED, format!("{metadata}, {scope}")),
            (
                declaration.caller_challenge(&invalid()),
                StatusCode::UNAUTHORIZED,
                format!("{metadata}, error=\"invalid_token\", {scope}"),
            ),
            (
                declaration.caller_challenge(&short_of_scope()),
                StatusCode::FORBIDDEN,
                format!("{metadata}, error=\"insufficient_scope\", {scope}"),
            ),
            (declaration.fabric_refusal(&missing()), StatusCode::UNAUTHORIZED, "Bearer realm=\"agent-gateway\"".into()),
            (
                declaration.fabric_refusal(&invalid()),
                StatusCode::UNAUTHORIZED,
                "Bearer realm=\"agent-gateway\", error=\"invalid_token\"".into(),
            ),
            (
                declaration.fabric_refusal(&short_of_scope()),
                StatusCode::FORBIDDEN,
                "Bearer realm=\"agent-gateway\", error=\"insufficient_scope\"".into(),
            ),
        ] {
            assert_eq!(response.status(), status, "{challenge}");
            assert_eq!(response.headers()[header::WWW_AUTHENTICATE], challenge.as_str());
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(is_gateway_challenge(&response), "{challenge}");
        }
    }

    #[tokio::test]
    async fn a_fabric_scope_shortfall_names_no_metadata_and_no_scopes() {
        let refusal = declaration(&scoped_surface(), None).fabric_refusal(&short_of_scope());
        assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            refusal.headers()[header::WWW_AUTHENTICATE],
            "Bearer realm=\"agent-gateway\", error=\"insufficient_scope\""
        );
        assert_eq!(
            problem(refusal).await,
            json!({
                "type": "about:blank",
                "title": "Forbidden",
                "status": 403,
                "detail": "A bearer token granting the scopes this resource requires is required"
            })
        );
    }

    #[test]
    fn a_failure_without_a_caller_failure_kind_answers_as_an_invalid_token() {
        for (error, expected) in [
            (missing(), ResourceTokenError::Missing),
            (invalid(), ResourceTokenError::Invalid),
            (short_of_scope(), ResourceTokenError::InsufficientScope),
            (SourceAuthError::Internal { reason: "x".into() }, ResourceTokenError::Invalid),
        ] {
            assert_eq!(caller_token_error(&error), expected, "{error}");
        }
    }

    #[test]
    fn the_supported_scopes_list_the_required_ones_first_without_repeats() {
        let scopes = |values: &[&str]| -> Vec<String> {
            values
                .iter()
                .map(|value| value.to_string())
                .collect()
        };
        assert_eq!(
            scopes_supported(&scopes(&["tools.call", "tools"]), &scopes(&["tools", "resources"])),
            scopes(&["tools.call", "tools", "resources"])
        );
        assert_eq!(scopes_supported(&[], &scopes(&["tools"])), scopes(&["tools"]));
        assert_eq!(scopes_supported(&scopes(&["tools"]), &[]), scopes(&["tools"]));
        assert_eq!(scopes_supported(&[], &[]), Vec::<String>::new());
    }
}
