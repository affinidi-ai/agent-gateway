//! The resource server declaration of an Access Point.
//!
//! For the route called, an Access Point either declares the OAuth protection
//! the gateway enforces, strips every security declaration with a reason, asks
//! for a declaration it cannot serve, or passes through. The protected resource
//! metadata, the audience a caller's token must name and the caller challenge
//! are projections of the declaration, so every consumer reads it from
//! [`resolve_surface_declaration`]. The RFC 6750 and RFC 9728 strings come from
//! [`crate::protocols::protected_resource`].
//!
//! An Access Point declares from one of two sources, chosen by
//! [`declaration_source`]: the explicit `protected_resource` setting of an MCP
//! Access Point, or a declaration derived from its one pinned `jwt_bearer`
//! method with `required_scopes`.

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::config::NetworkConfig;
use crate::config::agent_surface::AgentSurface;
use crate::jwt_bearer::JwtVerificationStrategyStorage;
use crate::jwt_bearer::models::{AuthorizationServerMetadata, JwtBearerAuthConfig, JwtVerificationStrategy};
use crate::protocols::protected_resource::{self, ProtectedResourceConfig, ResourceTokenError};
use crate::source_auth::SourceAuthConfig;
use crate::source_auth::errors::SourceAuthError;

const TOKEN_REQUIRED: &str =
    "A bearer token from an authorization server in the protected resource metadata is required";
const SCOPE_REQUIRED: &str = "A bearer token granting the scopes in the challenge is required";
const FABRIC_TOKEN_REQUIRED: &str = "A bearer token issued for this resource is required";
const FABRIC_SCOPE_REQUIRED: &str = "A bearer token granting the scopes this resource requires is required";

/// Why an Access Point without an explicit `protected_resource` declares
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripReason {
    FabricTarget,
    MultipleMethods,
    MethodNotDeclarable,
    StrategyUnavailable,
    StaticJwks,
    NotPinned,
    PinMismatch,
    CustomTokenHeader,
    ForwardsCallerToken,
    NoAccessPointUrl,
    AudienceMissing,
    NoRequiredScopes,
    RootVariant,
    TransitPoint,
}

impl StripReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::FabricTarget => "fabric_target",
            Self::MultipleMethods => "multiple_methods",
            Self::MethodNotDeclarable => "method_not_declarable",
            Self::StrategyUnavailable => "strategy_unavailable",
            Self::StaticJwks => "static_jwks",
            Self::NotPinned => "not_pinned",
            Self::PinMismatch => "pin_mismatch",
            Self::CustomTokenHeader => "custom_token_header",
            Self::ForwardsCallerToken => "forwards_caller_token",
            Self::NoAccessPointUrl => "no_access_point_url",
            Self::AudienceMissing => "audience_missing",
            Self::NoRequiredScopes => "no_required_scopes",
            Self::RootVariant => "root_variant",
            Self::TransitPoint => "transit_point",
        }
    }
}

/// The resource server facts a declaring Access Point publishes for the route
/// called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    /// The resource of the route called, base or `$alias` variant.
    pub resource: String,
    pub authorization_servers: Vec<String>,
    /// The authorization server metadata a derived declaration was pinned to.
    pub pin: Option<AuthorizationServerMetadata>,
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

    /// The `WWW-Authenticate` value naming this resource's metadata document
    /// and the required scopes. `None` when the Access Point cannot check
    /// tokens.
    pub(crate) fn challenge_header(
        &self,
        error: ResourceTokenError,
    ) -> Option<HeaderValue> {
        match error {
            ResourceTokenError::Unavailable => None,
            _ => self
                .metadata_url()
                .ok()
                .and_then(|metadata| protected_resource::challenge_header(&metadata, error, &self.required_scopes)),
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
        let Some(challenge) = self.challenge_header(error) else {
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
    Strip(StripReason),
    PassThrough,
    /// The settings ask for a declaration the Access Point cannot serve, so
    /// callers fail closed.
    Unservable(String),
}

impl DeclarationOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Declare(_) => "declare",
            Self::Strip(_) => "strip",
            Self::PassThrough => "pass_through",
            Self::Unservable(_) => "unservable",
        }
    }

    pub fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::Strip(reason) => Some(reason.code()),
            Self::Declare(_) | Self::PassThrough | Self::Unservable(_) => None,
        }
    }
}

/// Whether the Access Point refuses a caller that failed source
/// authentication with the declaration's challenge whatever policy allows,
/// before AP2 and payment: it declares, so the gateway is the resource server.
pub fn refuses_failed_callers_by_default(outcome: &DeclarationOutcome) -> bool {
    matches!(outcome, DeclarationOutcome::Declare(_))
}

/// Where the declaration of an Access Point comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationSource<'a> {
    /// The `protected_resource` setting of its caller authentication.
    Explicit(&'a ProtectedResourceConfig),
    /// Its one `jwt_bearer` method with `required_scopes`, which declares once
    /// its strategy is pinned.
    Derived,
    /// Nothing: it never declares, and resolving reads no strategy.
    None,
}

/// The source of the declaration for the route called, `alias` naming its
/// variant. An explicit `protected_resource` takes precedence; without one, a
/// single `jwt_bearer` method with `required_scopes` derives the declaration,
/// except on a variant of an Access Point at `/`, which has no resource of its
/// own.
pub fn declaration_source<'a>(
    surface: &'a AgentSurface,
    alias: Option<&str>,
) -> DeclarationSource<'a> {
    match surface.protected_resource() {
        Some(configured) => DeclarationSource::Explicit(configured),
        None if derived_method(surface, alias).is_ok() => DeclarationSource::Derived,
        None => DeclarationSource::None,
    }
}

/// The declaration of a resolved Access Point for the route called, `alias`
/// naming its variant. The direct path, Fabric receive and the metadata route
/// all resolve it here. Only a derived declaration reads its strategy from
/// `strategies`, and only a store failure is an error; a missing store or
/// strategy strips.
pub async fn resolve_surface_declaration(
    surface: &AgentSurface,
    alias: Option<&str>,
    strategies: Option<&dyn JwtVerificationStrategyStorage>,
    network: &NetworkConfig,
) -> anyhow::Result<DeclarationOutcome> {
    let strategy = match declaration_source(surface, alias) {
        DeclarationSource::Explicit(configured) => {
            return Ok(explicit_declaration(surface, configured, alias, network));
        }
        DeclarationSource::Derived => match (declaration_strategy_id(surface), strategies) {
            (Some(id), Some(store)) => store.get(id).await?,
            _ => None,
        },
        DeclarationSource::None => None,
    };
    Ok(derived_declaration(surface, alias, strategy.as_ref(), network))
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
                pin: None,
                advertised_scopes: scopes_supported(&required_scopes, &configured.scopes),
                required_scopes,
            })
        }
        Some(Err(reason)) => DeclarationOutcome::Unservable(reason),
        None => DeclarationOutcome::PassThrough,
    }
}

/// The Access Point's `jwt_bearer` method when it is its only caller
/// authentication method.
fn single_jwt_bearer(surface: &AgentSurface) -> Result<Option<&JwtBearerAuthConfig>, StripReason> {
    let methods = surface
        .access_point
        .caller_authentication
        .as_ref()
        .map(|auth| auth.methods.as_slice())
        .unwrap_or_default();
    match methods {
        [] => Ok(None),
        [SourceAuthConfig::JwtBearer(config)] => Ok(Some(config)),
        [_] => Err(StripReason::MethodNotDeclarable),
        _ => Err(StripReason::MultipleMethods),
    }
}

/// The method a derived declaration is built from, or, for an Access Point
/// that cannot derive one without reading its strategy, why it strips (`None`
/// when it passes through).
fn derived_method<'a>(
    surface: &'a AgentSurface,
    alias: Option<&str>,
) -> Result<&'a JwtBearerAuthConfig, Option<StripReason>> {
    let config = match single_jwt_bearer(surface) {
        Ok(Some(config)) => config,
        Ok(None)
            if surface
                .target
                .endpoint
                .starts_with("fabric://") =>
        {
            return Err(Some(StripReason::FabricTarget));
        }
        Ok(None) => return Err(None),
        Err(reason) => return Err(Some(reason)),
    };
    if config
        .required_scopes
        .is_empty()
    {
        return Err(Some(StripReason::NoRequiredScopes));
    }
    if alias.is_some()
        && matches!(
            surface
                .access_point
                .route
                .as_str(),
            "" | "/"
        )
    {
        return Err(Some(StripReason::RootVariant));
    }
    Ok(config)
}

/// The strategy a derived declaration reads.
fn declaration_strategy_id(surface: &AgentSurface) -> Option<&str> {
    single_jwt_bearer(surface)
        .ok()
        .flatten()
        .map(|config| {
            config
                .jwt_verification_strategy_id
                .as_str()
        })
}

/// The derived outcome of a resolved Access Point. `strategy` is the stored
/// strategy its method names, if it exists.
fn derived_declaration(
    surface: &AgentSurface,
    alias: Option<&str>,
    strategy: Option<&JwtVerificationStrategy>,
    network: &NetworkConfig,
) -> DeclarationOutcome {
    let config = match derived_method(surface, alias) {
        Ok(config) => config,
        Err(Some(reason)) => return DeclarationOutcome::Strip(reason),
        Err(None) => return DeclarationOutcome::PassThrough,
    };
    match declare(surface, alias, config, strategy, network) {
        Ok(declaration) => DeclarationOutcome::Declare(declaration),
        Err(reason) => DeclarationOutcome::Strip(reason),
    }
}

fn declare(
    surface: &AgentSurface,
    alias: Option<&str>,
    config: &JwtBearerAuthConfig,
    strategy: Option<&JwtVerificationStrategy>,
    network: &NetworkConfig,
) -> Result<Declaration, StripReason> {
    let strategy = strategy
        .filter(|strategy| {
            strategy.id == config.jwt_verification_strategy_id
                && crate::tenancy::can_reference(surface.tenant_id.as_deref(), strategy.tenant_id.as_deref())
        })
        .ok_or(StripReason::StrategyUnavailable)?;
    let jwks_uri = strategy
        .remote_jwks_uri()
        .ok_or(StripReason::StaticJwks)?;
    let pin = strategy
        .authorization_server
        .as_ref()
        .ok_or(StripReason::NotPinned)?;
    if pin.issuer != strategy.expected_issuer || pin.jwks_uri != jwks_uri {
        return Err(StripReason::PinMismatch);
    }
    if !config
        .token_header
        .eq_ignore_ascii_case("authorization")
        || !config
            .token_scheme
            .eq_ignore_ascii_case("bearer")
    {
        return Err(StripReason::CustomTokenHeader);
    }
    if config.forward_header {
        return Err(StripReason::ForwardsCallerToken);
    }
    let resource = derived_resource(surface, alias, network).ok_or(StripReason::NoAccessPointUrl)?;
    if !config
        .audiences
        .contains(&resource)
    {
        return Err(StripReason::AudienceMissing);
    }
    Ok(Declaration {
        resource,
        authorization_servers: vec![pin.issuer.clone()],
        pin: Some(pin.clone()),
        required_scopes: config.required_scopes.clone(),
        advertised_scopes: config.required_scopes.clone(),
    })
}

/// The resource a derived declaration names: the public origin of the Access
/// Point's listener and its route, as a canonical HTTPS URL, with `$alias` for
/// a variant.
fn derived_resource(
    surface: &AgentSurface,
    alias: Option<&str>,
    network: &NetworkConfig,
) -> Option<String> {
    let path = protected_resource::access_point_path(surface, None).filter(|path| path.starts_with('/'))?;
    let resource = format!("{}{path}", protected_resource::access_point_origin(surface, network)?);
    crate::sts::mcp_profile::canonical_https_url(&resource).ok()?;
    match alias {
        Some(alias) => protected_resource::variant_resource(&resource, alias).ok(),
        None => Some(resource),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::header;
    use serde_json::json;

    use super::*;
    use crate::jwt_bearer::models::JwksSource;
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

    async fn resolve(
        surface: &AgentSurface,
        alias: Option<&str>,
    ) -> DeclarationOutcome {
        let view = surface
            .resolve_variant(alias)
            .expect("variant");
        resolve_surface_declaration(&view, alias, None, &discovery_network())
            .await
            .expect("an explicit declaration reads no strategy")
    }

    async fn declaration(
        surface: &AgentSurface,
        alias: Option<&str>,
    ) -> Declaration {
        match resolve(surface, alias).await {
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

    #[tokio::test]
    async fn an_explicit_protected_resource_declares_the_resource_of_the_route_called() {
        let surface = declaring_surface();
        assert_eq!(
            resolve(&surface, None).await,
            DeclarationOutcome::Declare(Declaration {
                resource: RESOURCE.into(),
                authorization_servers: vec![ISSUER.into()],
                pin: None,
                required_scopes: Vec::new(),
                advertised_scopes: vec!["tools".into()],
            })
        );
        assert_eq!(
            declaration(&surface, Some("beta"))
                .await
                .resource,
            "https://gateway.example/mcp/alpha$beta"
        );
        assert_eq!(
            declaration(&root_surface(), None)
                .await
                .resource,
            "https://gateway.example/"
        );
    }

    #[tokio::test]
    async fn an_access_point_without_a_protected_resource_declares_only_from_a_pinned_strategy() {
        let surface = discovery_surface(jwt_bearer_method(), None);
        assert_eq!(resolve(&surface, None).await, DeclarationOutcome::Strip(StripReason::NoRequiredScopes));
        assert_eq!(resolve(&surface, Some("beta")).await, DeclarationOutcome::Strip(StripReason::NoRequiredScopes));
        assert!(!refuses_failed_callers_by_default(&resolve(&surface, None).await));

        let mut scoped = jwt_bearer_method();
        scoped["required_scopes"] = json!(["tools"]);
        let scoped = discovery_surface(scoped, None);
        assert_eq!(resolve(&scoped, None).await, DeclarationOutcome::Strip(StripReason::StrategyUnavailable));
        assert!(!refuses_failed_callers_by_default(&resolve(&scoped, None).await));
    }

    #[tokio::test]
    async fn a_protected_resource_the_access_point_cannot_serve_is_unservable() {
        assert!(matches!(resolve(&root_surface(), Some("beta")).await, DeclarationOutcome::Unservable(_)));

        let mut a2a = declaring_surface();
        a2a.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::A2a;
        assert_eq!(resolve(&a2a, None).await, DeclarationOutcome::Unservable("requires an MCP Access Point".into()));

        for unserved in [explicit("https://other.example/mcp/alpha"), explicit("https://gateway.example/mcp/other")] {
            let surface = discovery_surface(jwt_bearer_method(), Some(unserved.clone()));
            assert!(matches!(resolve(&surface, None).await, DeclarationOutcome::Unservable(_)), "{unserved}");
        }
        for method in [
            json!({"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "token_header": "x-token"}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "forward_header": true}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [RESOURCE]}),
        ] {
            let surface = discovery_surface(method.clone(), Some(explicit(RESOURCE)));
            let outcome = resolve(&surface, None).await;
            assert!(matches!(outcome, DeclarationOutcome::Unservable(_)), "{method}");
            assert!(!refuses_failed_callers_by_default(&outcome), "{method}");
        }
    }

    #[tokio::test]
    async fn a_declaration_publishes_its_document_at_an_absolute_metadata_url() {
        assert_eq!(
            declaration(&declaring_surface(), None)
                .await
                .metadata(),
            json!({
                "resource": RESOURCE,
                "authorization_servers": [ISSUER],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["tools"]
            })
        );
        let unscoped = Declaration {
            advertised_scopes: Vec::new(),
            ..declaration(&declaring_surface(), None).await
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
                    .await
                    .metadata_url()
                    .expect("metadata URL")
                    .as_str(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn a_declaration_accepts_only_tokens_for_the_resource_of_the_route_called() {
        let surface = scoped_surface();
        let Some(SourceAuthConfig::JwtBearer(method)) = surface.source_auth().cloned() else {
            panic!("the declaring surface authenticates callers with JWT Bearer");
        };
        let method = JwtBearerAuthConfig {
            audiences: vec!["https://other.example/mcp".into()],
            ..method
        };
        for (alias, audience) in [(None, RESOURCE), (Some("beta"), "https://gateway.example/mcp/alpha$beta")] {
            let bound = declaration(&surface, alias)
                .await
                .bind_audience(&method);
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

    #[tokio::test]
    async fn a_declaration_requires_the_method_scopes_and_supports_the_advertised_ones_too() {
        for alias in [None, Some("beta")] {
            let declaration = declaration(&scoped_surface(), alias).await;
            assert_eq!(declaration.required_scopes, ["tools.call", "tools"], "{alias:?}");
            assert_eq!(declaration.advertised_scopes, ["tools.call", "tools", "resources"], "{alias:?}");
            assert_eq!(
                declaration.metadata()["scopes_supported"],
                json!(["tools.call", "tools", "resources"]),
                "{alias:?}"
            );
        }
        let unrequired = declaration(&declaring_surface(), None).await;
        assert_eq!(unrequired.required_scopes, Vec::<String>::new());
        assert_eq!(unrequired.advertised_scopes, ["tools"]);
    }

    #[tokio::test]
    async fn the_challenge_names_the_metadata_and_never_why_a_token_failed() {
        let declaration = declaration(&declaring_surface(), None).await;
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
        assert_eq!(declaration.challenge_header(ResourceTokenError::Unavailable), None);
        assert_eq!(
            declaration
                .challenge_header(ResourceTokenError::Invalid)
                .expect("challenge"),
            format!("Bearer resource_metadata=\"{METADATA}\", error=\"invalid_token\"").as_str()
        );
    }

    #[tokio::test]
    async fn a_scope_shortfall_is_403_naming_only_the_required_scopes() {
        let scoped = declaration(&scoped_surface(), None).await;
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

        let unscoped = declaration(&declaring_surface(), None)
            .await
            .challenge(ResourceTokenError::InsufficientScope);
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

    #[tokio::test]
    async fn every_caller_and_fabric_challenge_is_marked_as_the_gateways() {
        let declaration = declaration(&scoped_surface(), None).await;
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
        let refusal = declaration(&scoped_surface(), None)
            .await
            .fabric_refusal(&short_of_scope());
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

    const A2A_RESOURCE: &str = "https://gw.example/a2a/buyer";
    const AS_ISSUER: &str = "https://as.example/";
    const JWKS: &str = "https://as.example/jwks.json";

    fn a2a_network() -> NetworkConfig {
        serde_json::from_value(json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "fallback.example", "external_origin": "https://fallback.example" },
            "integration": { "types": [], "categories": [] },
            "listeners": [{
                "id": "in", "name": "in", "bind_address": "0.0.0.0", "port": 8443,
                "protocol": "https", "external_urls": ["https://gw.example/"], "listener_type": "inbound"
            }],
            "routes": {},
        }))
        .expect("network config")
    }

    fn jwt_method(overrides: Value) -> Value {
        let mut method = json!({
            "type": "jwt_bearer",
            "jwt_verification_strategy_id": "strategy-1",
            "audiences": [A2A_RESOURCE],
            "required_scopes": ["agent.invoke"],
        });
        if let (Some(method), Some(overrides)) = (method.as_object_mut(), overrides.as_object()) {
            method.extend(overrides.clone());
        }
        method
    }

    fn a2a_surface(
        methods: Option<Vec<Value>>,
        target: &str,
    ) -> AgentSurface {
        let mut access_point = json!({
            "listen_address": "0.0.0.0:8443",
            "route": "/a2a/buyer",
            "protocol": "a2a",
        });
        if let Some(methods) = methods {
            access_point["caller_authentication"] = json!({ "methods": methods });
        }
        serde_json::from_value(json!({
            "name": "buyer",
            "access_point": access_point,
            "target": { "endpoint": target },
        }))
        .expect("surface")
    }

    fn api_key_method() -> Value {
        json!({
            "type": "api_key",
            "secret_id": "keys",
            "extraction": { "source": "http_header", "field": "X-API-Key" },
        })
    }

    fn derived_surface() -> AgentSurface {
        a2a_surface(Some(vec![jwt_method(json!({}))]), "https://agent.internal")
    }

    fn pin() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: AS_ISSUER.into(),
            metadata_url: "https://as.example/.well-known/oauth-authorization-server".into(),
            token_endpoint: "https://as.example/oauth2/token".into(),
            jwks_uri: JWKS.into(),
        }
    }

    fn pinned_strategy() -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            id: "strategy-1".into(),
            name: "as".into(),
            expected_issuer: AS_ISSUER.into(),
            jwks_source: JwksSource::Remote { jwks_uri: JWKS.into() },
            authorization_server: Some(pin()),
            ..Default::default()
        }
    }

    fn derived(
        surface: &AgentSurface,
        strategy: Option<&JwtVerificationStrategy>,
    ) -> DeclarationOutcome {
        derived_declaration(surface, None, strategy, &a2a_network())
    }

    fn stripped(reason: StripReason) -> DeclarationOutcome {
        DeclarationOutcome::Strip(reason)
    }

    #[test]
    fn a_single_pinned_jwt_bearer_method_with_required_scopes_declares_the_pinned_server() {
        let outcome = derived(&derived_surface(), Some(&pinned_strategy()));
        assert_eq!(
            outcome,
            DeclarationOutcome::Declare(Declaration {
                resource: A2A_RESOURCE.into(),
                authorization_servers: vec![AS_ISSUER.into()],
                pin: Some(pin()),
                required_scopes: vec!["agent.invoke".into()],
                advertised_scopes: vec!["agent.invoke".into()],
            })
        );
        assert!(refuses_failed_callers_by_default(&outcome));
        let DeclarationOutcome::Declare(declaration) = outcome else { unreachable!() };
        assert_eq!(
            declaration.metadata(),
            json!({
                "resource": A2A_RESOURCE,
                "authorization_servers": [AS_ISSUER],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["agent.invoke"],
            })
        );
        assert_eq!(
            declaration
                .challenge_header(ResourceTokenError::Missing)
                .expect("challenge"),
            "Bearer resource_metadata=\"https://gw.example/.well-known/oauth-protected-resource/a2a/buyer\", \
             scope=\"agent.invoke\""
        );
    }

    #[test]
    fn no_caller_authentication_passes_through_unless_the_target_is_fabric() {
        assert_eq!(derived(&a2a_surface(None, "https://agent.internal"), None), DeclarationOutcome::PassThrough);
        assert_eq!(
            derived(&a2a_surface(Some(vec![]), "https://agent.internal"), None),
            DeclarationOutcome::PassThrough
        );
        assert_eq!(derived(&a2a_surface(None, "fabric://peer/surface"), None), stripped(StripReason::FabricTarget));
        assert!(!refuses_failed_callers_by_default(&DeclarationOutcome::PassThrough));
        assert!(!refuses_failed_callers_by_default(&stripped(StripReason::FabricTarget)));
    }

    #[test]
    fn more_than_one_method_or_another_method_strips() {
        let strategy = pinned_strategy();
        let api_key = api_key_method();
        let two = a2a_surface(Some(vec![jwt_method(json!({})), api_key.clone()]), "https://agent.internal");
        assert_eq!(derived(&two, Some(&strategy)), stripped(StripReason::MultipleMethods));
        let other = a2a_surface(Some(vec![api_key]), "https://agent.internal");
        assert_eq!(derived(&other, Some(&strategy)), stripped(StripReason::MethodNotDeclarable));
        assert_eq!(declaration_strategy_id(&two), None);
        assert_eq!(declaration_strategy_id(&derived_surface()), Some("strategy-1"));
    }

    #[test]
    fn a_missing_foreign_or_mismatched_strategy_strips() {
        let surface = derived_surface();
        assert_eq!(derived(&surface, None), stripped(StripReason::StrategyUnavailable));

        let mut foreign = pinned_strategy();
        foreign.tenant_id = Some("tenant-b".into());
        assert_eq!(derived(&surface, Some(&foreign)), stripped(StripReason::StrategyUnavailable));

        let mut other_id = pinned_strategy();
        other_id.id = "strategy-2".into();
        assert_eq!(derived(&surface, Some(&other_id)), stripped(StripReason::StrategyUnavailable));

        let mut owned = derived_surface();
        owned.tenant_id = Some("tenant-a".into());
        let mut own = pinned_strategy();
        own.tenant_id = Some("tenant-a".into());
        assert_eq!(derived(&owned, Some(&own)).label(), "declare");
        assert_eq!(derived(&owned, Some(&pinned_strategy())).label(), "declare");
    }

    #[test]
    fn a_static_unpinned_or_mismatched_pin_strips() {
        let surface = derived_surface();

        let mut static_keys = pinned_strategy();
        static_keys.jwks_source = JwksSource::Static { jwks: Vec::new() };
        assert_eq!(derived(&surface, Some(&static_keys)), stripped(StripReason::StaticJwks));

        let mut unpinned = pinned_strategy();
        unpinned.authorization_server = None;
        assert_eq!(derived(&surface, Some(&unpinned)), stripped(StripReason::NotPinned));

        let mut other_issuer = pinned_strategy();
        other_issuer.expected_issuer = "https://as.example".into();
        assert_eq!(derived(&surface, Some(&other_issuer)), stripped(StripReason::PinMismatch));

        let mut other_keys = pinned_strategy();
        other_keys.jwks_source = JwksSource::Remote {
            jwks_uri: "https://as.example/other.json".into(),
        };
        assert_eq!(derived(&surface, Some(&other_keys)), stripped(StripReason::PinMismatch));
    }

    #[test]
    fn a_custom_header_or_scheme_strips_and_case_does_not_matter() {
        let strategy = pinned_strategy();
        for overrides in
            [json!({ "token_header": "X-Token" }), json!({ "token_scheme": "" }), json!({ "token_scheme": "DPoP" })]
        {
            let surface = a2a_surface(Some(vec![jwt_method(overrides)]), "https://agent.internal");
            assert_eq!(derived(&surface, Some(&strategy)), stripped(StripReason::CustomTokenHeader));
        }
        let lower = a2a_surface(
            Some(vec![jwt_method(json!({ "token_header": "authorization", "token_scheme": "bearer" }))]),
            "https://agent.internal",
        );
        assert_eq!(derived(&lower, Some(&strategy)).label(), "declare");
    }

    #[test]
    fn forwarding_the_callers_token_strips_without_an_error() {
        let forwarding =
            a2a_surface(Some(vec![jwt_method(json!({ "forward_header": true }))]), "https://agent.internal");
        let outcome = derived(&forwarding, Some(&pinned_strategy()));
        assert_eq!(outcome, stripped(StripReason::ForwardsCallerToken));
        assert_eq!(outcome.reason_code(), Some("forwards_caller_token"));
        assert!(!refuses_failed_callers_by_default(&outcome));

        let custom_and_forwarding = a2a_surface(
            Some(vec![jwt_method(json!({ "forward_header": true, "token_header": "X-Token" }))]),
            "https://agent.internal",
        );
        assert_eq!(derived(&custom_and_forwarding, Some(&pinned_strategy())), stripped(StripReason::CustomTokenHeader));
    }

    #[test]
    fn no_listener_or_a_non_canonical_url_strips() {
        let strategy = pinned_strategy();
        let mut unmatched = derived_surface();
        unmatched
            .access_point
            .listen_address = "0.0.0.0:9999".into();
        assert_eq!(derived(&unmatched, Some(&strategy)), stripped(StripReason::NoAccessPointUrl));

        let mut spaced = derived_surface();
        spaced.access_point.route = "/a2a/bu yer".into();
        assert_eq!(derived(&spaced, Some(&strategy)), stripped(StripReason::NoAccessPointUrl));

        let mut relative = derived_surface();
        relative.access_point.route = "a2a/buyer".into();
        assert_eq!(derived(&relative, Some(&strategy)), stripped(StripReason::NoAccessPointUrl));

        let mut plain_http = a2a_network();
        plain_http.listeners[0].external_urls = vec!["http://gw.example".into()];
        assert_eq!(
            derived_declaration(&derived_surface(), None, Some(&strategy), &plain_http),
            stripped(StripReason::NoAccessPointUrl)
        );
    }

    #[test]
    fn the_access_point_url_must_be_an_exact_audience() {
        let strategy = pinned_strategy();
        for audiences in [
            json!([]),
            json!(["https://gw.example/a2a/buyer/"]),
            json!(["https://GW.example/a2a/buyer"]),
            json!([crate::source_auth::middleware::SURFACE_AGENT_DID_AUDIENCE]),
        ] {
            let surface =
                a2a_surface(Some(vec![jwt_method(json!({ "audiences": audiences }))]), "https://agent.internal");
            assert_eq!(derived(&surface, Some(&strategy)), stripped(StripReason::AudienceMissing));
        }
        let extra = a2a_surface(
            Some(vec![jwt_method(json!({ "audiences": ["api://agent", A2A_RESOURCE] }))]),
            "https://agent.internal",
        );
        assert_eq!(derived(&extra, Some(&strategy)).label(), "declare");
    }

    #[test]
    fn empty_required_scopes_strip_before_the_strategy_is_needed() {
        let surface = a2a_surface(Some(vec![jwt_method(json!({ "required_scopes": [] }))]), "https://agent.internal");
        assert_eq!(derived(&surface, Some(&pinned_strategy())), stripped(StripReason::NoRequiredScopes));
        assert_eq!(derived(&surface, None), stripped(StripReason::NoRequiredScopes));
        assert_eq!(declaration_source(&surface, None), DeclarationSource::None);
    }

    #[test]
    fn a_named_variant_declares_its_aliased_url() {
        let surface = a2a_surface(
            Some(vec![jwt_method(json!({ "audiences": ["https://gw.example/a2a/buyer$dev"] }))]),
            "https://agent.internal",
        );
        let strategy = pinned_strategy();
        let DeclarationOutcome::Declare(declaration) =
            derived_declaration(&surface, Some("dev"), Some(&strategy), &a2a_network())
        else {
            panic!("expected declare");
        };
        assert_eq!(declaration.resource, "https://gw.example/a2a/buyer$dev");
        assert_eq!(
            declaration
                .metadata_url()
                .expect("metadata URL")
                .as_str(),
            "https://gw.example/.well-known/oauth-protected-resource/a2a/buyer$dev"
        );
        assert_eq!(derived(&surface, Some(&strategy)), stripped(StripReason::AudienceMissing));
    }

    #[test]
    fn a_variant_of_an_access_point_at_the_root_does_not_declare() {
        let strategy = pinned_strategy();
        for route in ["/", ""] {
            let mut root = a2a_surface(
                Some(vec![jwt_method(json!({ "audiences": ["https://gw.example/", "https://gw.example/$dev"] }))]),
                "https://agent.internal",
            );
            root.access_point.route = route.into();
            let DeclarationOutcome::Declare(base) = derived_declaration(&root, None, Some(&strategy), &a2a_network())
            else {
                panic!("expected the root Access Point to declare");
            };
            assert_eq!(base.resource, "https://gw.example/", "{route:?}");
            assert_eq!(
                derived_declaration(&root, Some("dev"), Some(&strategy), &a2a_network()),
                stripped(StripReason::RootVariant),
                "{route:?}"
            );
            assert_eq!(declaration_source(&root, Some("dev")), DeclarationSource::None, "{route:?}");
            assert_eq!(declaration_source(&root, None), DeclarationSource::Derived, "{route:?}");
        }
    }

    #[test]
    fn the_source_is_explicit_with_a_protected_resource_and_derived_only_with_required_scopes() {
        let explicit = declaring_surface();
        let DeclarationSource::Explicit(configured) = declaration_source(&explicit, None) else {
            panic!("expected an explicit source");
        };
        assert_eq!(configured.resource, RESOURCE);
        assert!(matches!(declaration_source(&explicit, Some("beta")), DeclarationSource::Explicit(_)));
        assert!(matches!(declaration_source(&scoped_surface(), None), DeclarationSource::Explicit(_)));

        assert_eq!(declaration_source(&derived_surface(), None), DeclarationSource::Derived);
        assert_eq!(declaration_source(&derived_surface(), Some("dev")), DeclarationSource::Derived);
        for undeclared in [
            discovery_surface(jwt_bearer_method(), None),
            a2a_surface(None, "https://agent.internal"),
            a2a_surface(None, "fabric://peer/surface"),
            a2a_surface(Some(vec![jwt_method(json!({})), api_key_method()]), "https://agent.internal"),
        ] {
            assert_eq!(declaration_source(&undeclared, None), DeclarationSource::None, "{}", undeclared.name);
        }
    }

    #[test]
    fn outcomes_report_their_label_and_reason() {
        assert_eq!(stripped(StripReason::NotPinned).label(), "strip");
        assert_eq!(stripped(StripReason::NotPinned).reason_code(), Some("not_pinned"));
        assert_eq!(stripped(StripReason::RootVariant).reason_code(), Some("root_variant"));
        assert_eq!(stripped(StripReason::TransitPoint).reason_code(), Some("transit_point"));
        assert_eq!(DeclarationOutcome::PassThrough.label(), "pass_through");
        assert_eq!(DeclarationOutcome::PassThrough.reason_code(), None);
        assert_eq!(DeclarationOutcome::Unservable("x".into()).label(), "unservable");
        assert_eq!(DeclarationOutcome::Unservable("x".into()).reason_code(), None);
    }

    /// A strategy store whose every read fails.
    struct FailingStore;

    #[async_trait::async_trait]
    impl JwtVerificationStrategyStorage for FailingStore {
        async fn create(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            anyhow::bail!("store unavailable")
        }

        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
            anyhow::bail!("store unavailable")
        }

        async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
            anyhow::bail!("store unavailable")
        }

        async fn update(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            anyhow::bail!("store unavailable")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            anyhow::bail!("store unavailable")
        }
    }

    #[tokio::test]
    async fn the_surface_resolver_reads_the_named_strategy_only_for_a_derived_declaration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(dir.path().to_path_buf())
            .await
            .expect("store");
        let stored = store
            .create(pinned_strategy())
            .await
            .expect("create");
        let surface = a2a_surface(
            Some(vec![jwt_method(json!({ "jwt_verification_strategy_id": stored.id }))]),
            "https://agent.internal",
        );
        let network = a2a_network();
        assert_eq!(
            resolve_surface_declaration(&surface, None, Some(&store), &network)
                .await
                .expect("resolve")
                .label(),
            "declare"
        );
        assert_eq!(
            resolve_surface_declaration(&surface, None, None, &network)
                .await
                .expect("resolve"),
            stripped(StripReason::StrategyUnavailable)
        );
        assert_eq!(
            resolve_surface_declaration(&derived_surface(), None, Some(&store), &network)
                .await
                .expect("resolve"),
            stripped(StripReason::StrategyUnavailable)
        );

        assert!(
            resolve_surface_declaration(&surface, None, Some(&FailingStore), &network)
                .await
                .is_err()
        );
        let unscoped = a2a_surface(Some(vec![jwt_method(json!({ "required_scopes": [] }))]), "https://agent.internal");
        assert_eq!(
            resolve_surface_declaration(&unscoped, None, Some(&FailingStore), &network)
                .await
                .expect("an Access Point without required scopes reads no strategy"),
            stripped(StripReason::NoRequiredScopes)
        );
        assert_eq!(
            resolve_surface_declaration(&declaring_surface(), None, Some(&FailingStore), &discovery_network())
                .await
                .expect("an explicit declaration reads no strategy")
                .label(),
            "declare"
        );
    }
}
