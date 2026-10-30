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
//! An Access Point declares from one source, its
//! `caller_authentication.protected_resource` setting, whose authorization
//! server and scopes come from the method's JWT verification strategy and
//! `required_scopes`.

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::config::NetworkConfig;
use crate::config::agent_surface::AgentSurface;
use crate::jwt_bearer::JwtVerificationStrategyStorage;
use crate::jwt_bearer::models::{AuthorizationServerMetadata, JwtBearerAuthConfig, JwtVerificationStrategy};
use crate::protocols::protected_resource::{self, ResourceTokenError};
use crate::source_auth::SourceAuthConfig;
use crate::source_auth::errors::SourceAuthError;

const TOKEN_REQUIRED: &str =
    "A bearer token from an authorization server in the protected resource metadata is required";
const SCOPE_REQUIRED: &str = "A bearer token granting the scopes in the challenge is required";
const FABRIC_TOKEN_REQUIRED: &str = "A bearer token issued for this resource is required";
const FABRIC_SCOPE_REQUIRED: &str = "A bearer token granting the scopes this resource requires is required";

/// Why nothing is declared: the Access Point sets no `protected_resource`, or
/// the card is an outbound Transit Point's. Only reporting and metrics read
/// it; the card is kept as the Target served it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripReason {
    /// No caller authentication and a `fabric://` Target.
    FabricTarget,
    /// Caller authentication without `protected_resource`.
    NotDeclared,
    /// An outbound Transit Point card.
    TransitPoint,
}

impl StripReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::FabricTarget => "fabric_target",
            Self::NotDeclared => "not_declared",
            Self::TransitPoint => "transit_point",
        }
    }
}

/// Why an Access Point cannot serve the declaration its settings ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnservableReason {
    UnsupportedProtocol,
    InvalidProtectedResource,
    IncompatibleCallerAuthentication,
    RootVariantResource,
    ResourceMismatch,
    StrategyUnavailable,
    IssuerNotAdvertisable,
    StrategyStoreUnavailable,
    NetworkUnavailable,
}

impl UnservableReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::InvalidProtectedResource => "invalid_protected_resource",
            Self::IncompatibleCallerAuthentication => "incompatible_caller_authentication",
            Self::RootVariantResource => "root_variant_resource",
            Self::ResourceMismatch => "resource_mismatch",
            Self::StrategyUnavailable => "strategy_unavailable",
            Self::IssuerNotAdvertisable => "issuer_not_advertisable",
            Self::StrategyStoreUnavailable => "strategy_store_unavailable",
            Self::NetworkUnavailable => "network_unavailable",
        }
    }
}

/// A declaration the Access Point cannot serve: why, and the detail the
/// gateway logs and a refused save quotes. It displays as its detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnservableDeclaration {
    pub reason: UnservableReason,
    pub detail: String,
}

impl UnservableDeclaration {
    pub fn new(
        reason: UnservableReason,
        detail: impl Into<String>,
    ) -> Self {
        Self { reason, detail: detail.into() }
    }
}

impl std::fmt::Display for UnservableDeclaration {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// The resource server facts a declaring Access Point publishes for the route
/// called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    /// The resource of the route called, base or `$alias` variant.
    pub resource: String,
    /// The strategy's `expected_issuer`, the one authorization server advertised.
    pub authorization_servers: Vec<String>,
    /// The strategy's pinned authorization server metadata when its issuer
    /// equals the strategy's `expected_issuer` and, for a remote key set, its
    /// `jwks_uri` equals the strategy's; the A2A card's `agent_gateway` scheme
    /// needs it.
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
    Unservable(UnservableDeclaration),
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
            Self::Unservable(unservable) => Some(unservable.reason.code()),
            Self::Declare(_) | Self::PassThrough => None,
        }
    }
}

/// Whether the Access Point refuses a caller that failed source
/// authentication itself, at the source authentication step and before rate
/// limit, every policy plane, AP2 and payment: it declares, so the gateway is
/// the resource server. The request path, the dry run and the save report
/// agree through this predicate.
pub fn refuses_failed_callers_by_default(outcome: &DeclarationOutcome) -> bool {
    matches!(outcome, DeclarationOutcome::Declare(_))
}

/// Whether the Access Point asks to declare on the route it resolves to: its
/// caller authentication sets `protected_resource`. Such an Access Point fails
/// closed when it cannot serve the declaration.
pub fn requests_declaration(surface: &AgentSurface) -> bool {
    surface
        .protected_resource()
        .is_some()
}

/// The declaration of a resolved Access Point for the route called, `alias`
/// naming its variant. The direct path, Fabric receive and the metadata route
/// all resolve it here. An Access Point without `protected_resource` never
/// declares and never reads `strategies`. One that sets it reads the strategy
/// its JWT Bearer method names: the strategy's `expected_issuer` is the one
/// authorization server advertised, so the stored `authorization_servers` is
/// never read. Only a store failure is an error; a missing store, a missing or
/// foreign strategy and an issuer metadata cannot name leave the declaration
/// unservable.
pub async fn resolve_surface_declaration(
    surface: &AgentSurface,
    alias: Option<&str>,
    strategies: Option<&dyn JwtVerificationStrategyStorage>,
    network: &NetworkConfig,
) -> anyhow::Result<DeclarationOutcome> {
    let Some(configured) = surface.protected_resource() else {
        return Ok(undeclared(surface));
    };
    let served = match protected_resource::access_point_protected_resource(surface, alias, network) {
        Some(Ok(served)) => served,
        Some(Err(unservable)) => return Ok(DeclarationOutcome::Unservable(unservable)),
        None => return Ok(DeclarationOutcome::PassThrough),
    };
    let Some(SourceAuthConfig::JwtBearer(jwt)) = surface.source_auth() else {
        return Ok(DeclarationOutcome::Unservable(UnservableDeclaration::new(
            UnservableReason::IncompatibleCallerAuthentication,
            "requires a first caller authentication method of JWT Bearer reading the Authorization header with \
             the Bearer scheme",
        )));
    };
    let Some(store) = strategies else {
        return Ok(DeclarationOutcome::Unservable(UnservableDeclaration::new(
            UnservableReason::StrategyStoreUnavailable,
            "the JWT verification strategy store is unavailable",
        )));
    };
    let Some(strategy) = store
        .get(&jwt.jwt_verification_strategy_id)
        .await?
        .filter(|strategy| crate::tenancy::can_reference(surface.tenant_id.as_deref(), strategy.tenant_id.as_deref()))
    else {
        return Ok(DeclarationOutcome::Unservable(UnservableDeclaration::new(
            UnservableReason::StrategyUnavailable,
            "the JWT verification strategy is missing or not available to this surface's tenant",
        )));
    };
    if !protected_resource::advertisable_strategy_issuer(&strategy) {
        return Ok(DeclarationOutcome::Unservable(UnservableDeclaration::new(
            UnservableReason::IssuerNotAdvertisable,
            "the JWT verification strategy's expected_issuer is not an issuer URL protected resource metadata \
             can name",
        )));
    }
    Ok(DeclarationOutcome::Declare(Declaration {
        resource: served.resource,
        pin: matching_pin(&strategy),
        authorization_servers: vec![strategy.expected_issuer],
        advertised_scopes: scopes_supported(&jwt.required_scopes, &configured.scopes),
        required_scopes: jwt.required_scopes.clone(),
    }))
}

/// The outcome of an Access Point that sets no `protected_resource`.
fn undeclared(surface: &AgentSurface) -> DeclarationOutcome {
    let has_methods = surface
        .access_point
        .caller_authentication
        .as_ref()
        .is_some_and(|auth| !auth.methods.is_empty());
    if has_methods {
        DeclarationOutcome::Strip(StripReason::NotDeclared)
    } else if surface
        .target
        .endpoint
        .starts_with("fabric://")
    {
        DeclarationOutcome::Strip(StripReason::FabricTarget)
    } else {
        DeclarationOutcome::PassThrough
    }
}

/// The strategy's pin when it names the strategy's own issuer and, for a
/// remote key set, its own `jwks_uri`.
fn matching_pin(strategy: &JwtVerificationStrategy) -> Option<AuthorizationServerMetadata> {
    strategy
        .authorization_server
        .as_ref()
        .filter(|pin| {
            pin.issuer == strategy.expected_issuer
                && strategy
                    .remote_jwks_uri()
                    .is_none_or(|uri| pin.jwks_uri == uri)
        })
        .cloned()
}

/// The URL the save report suggests as the resource of an Access Point that
/// does not declare: the first external URL of its listener and its route,
/// `$alias` for a variant. It is never an audience.
pub fn access_point_resource_url(
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
        FixtureStrategies, ISSUER, discovery_network, discovery_surface, fixture_strategy, jwt_bearer_method,
    };
    use crate::protocols::protected_resource::is_gateway_challenge;

    const RESOURCE: &str = "https://gateway.example/mcp/alpha";
    const METADATA: &str = "https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha";

    fn explicit(resource: &str) -> Value {
        json!({"resource": resource, "scopes": ["tools"]})
    }

    fn declaring_surface() -> AgentSurface {
        discovery_surface(jwt_bearer_method(), Some(explicit(RESOURCE)))
    }

    /// A declaring surface whose callers' tokens must grant `tools.call` and
    /// `tools`, advertising `tools` and `resources`.
    fn scoped_surface() -> AgentSurface {
        let mut method = jwt_bearer_method();
        method["required_scopes"] = json!(["tools.call", "tools"]);
        discovery_surface(method, Some(json!({"resource": RESOURCE, "scopes": ["tools", "resources"]})))
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

    async fn resolve_with(
        surface: &AgentSurface,
        alias: Option<&str>,
        strategies: &FixtureStrategies,
    ) -> DeclarationOutcome {
        let view = surface
            .resolve_variant(alias)
            .expect("variant");
        resolve_surface_declaration(&view, alias, Some(strategies), &discovery_network())
            .await
            .expect("the fixture store answers")
    }

    async fn resolve(
        surface: &AgentSurface,
        alias: Option<&str>,
    ) -> DeclarationOutcome {
        resolve_with(surface, alias, &FixtureStrategies::Pinned).await
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

    fn unservable_reason(outcome: &DeclarationOutcome) -> Option<UnservableReason> {
        match outcome {
            DeclarationOutcome::Unservable(unservable) => Some(unservable.reason),
            _ => None,
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
                pin: fixture_strategy(true).authorization_server,
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
    async fn an_access_point_without_protected_resource_never_declares() {
        let mut scoped = jwt_bearer_method();
        scoped["required_scopes"] = json!(["tools"]);
        for method in [jwt_bearer_method(), scoped] {
            let surface = discovery_surface(method.clone(), None);
            for alias in [None, Some("beta")] {
                let outcome = resolve(&surface, alias).await;
                assert_eq!(outcome, DeclarationOutcome::Strip(StripReason::NotDeclared), "{method} {alias:?}");
                assert!(!refuses_failed_callers_by_default(&outcome), "{method} {alias:?}");
                assert_eq!(
                    resolve_with(&surface, alias, &FixtureStrategies::Failing).await,
                    DeclarationOutcome::Strip(StripReason::NotDeclared),
                    "{method} {alias:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_protected_resource_the_access_point_cannot_serve_is_unservable_with_its_cause() {
        assert_eq!(
            unservable_reason(&resolve(&root_surface(), Some("beta")).await),
            Some(UnservableReason::RootVariantResource)
        );

        let mut didcomm = declaring_surface();
        didcomm.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::DIDComm;
        assert_eq!(
            resolve(&didcomm, None).await,
            DeclarationOutcome::Unservable(UnservableDeclaration::new(
                UnservableReason::UnsupportedProtocol,
                "requires an MCP, A2A or AP2 Access Point"
            ))
        );
        let mut a2a = declaring_surface();
        a2a.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::A2a;
        assert_eq!(
            resolve(&a2a, None)
                .await
                .label(),
            "declare"
        );

        let no_servers = json!({"resource": RESOURCE, "authorization_servers": []});
        let surface = discovery_surface(jwt_bearer_method(), Some(no_servers));
        assert_eq!(unservable_reason(&resolve(&surface, None).await), Some(UnservableReason::InvalidProtectedResource));

        for unserved in [explicit("https://other.example/mcp/alpha"), explicit("https://gateway.example/mcp/other")] {
            let surface = discovery_surface(jwt_bearer_method(), Some(unserved.clone()));
            assert_eq!(
                unservable_reason(&resolve(&surface, None).await),
                Some(UnservableReason::ResourceMismatch),
                "{unserved}"
            );
        }
        for method in [
            json!({"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "token_header": "x-token"}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "forward_header": true}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [RESOURCE]}),
        ] {
            let surface = discovery_surface(method.clone(), Some(explicit(RESOURCE)));
            let outcome = resolve(&surface, None).await;
            assert_eq!(
                unservable_reason(&outcome),
                Some(UnservableReason::IncompatibleCallerAuthentication),
                "{method}"
            );
            assert!(!refuses_failed_callers_by_default(&outcome), "{method}");
        }
        assert_eq!(unservable_reason(&resolve(&declaring_surface(), None).await), None);
    }

    #[tokio::test]
    async fn a_protected_resource_without_required_scopes_still_declares_and_refuses() {
        let surface =
            discovery_surface(jwt_bearer_method(), Some(json!({"resource": RESOURCE, "scopes": ["agent.read"]})));
        let outcome = resolve(&surface, None).await;
        assert!(refuses_failed_callers_by_default(&outcome));
        let DeclarationOutcome::Declare(declaration) = outcome else {
            panic!("expected a declaration");
        };
        assert_eq!(declaration.required_scopes, Vec::<String>::new());
        assert_eq!(declaration.advertised_scopes, ["agent.read"]);
        let challenge = declaration.caller_challenge(&missing());
        assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            challenge.headers()[header::WWW_AUTHENTICATE],
            format!("Bearer resource_metadata=\"{METADATA}\"").as_str()
        );
    }

    #[tokio::test]
    async fn the_stored_authorization_servers_are_never_advertised() {
        let surface = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": RESOURCE, "authorization_servers": ["https://old.example/"]})),
        );
        let declaration = declaration(&surface, None).await;
        assert_eq!(declaration.authorization_servers, [ISSUER]);
        assert_eq!(declaration.metadata()["authorization_servers"], json!([ISSUER]));
        assert_ne!(declaration.authorization_servers, ["https://old.example/"]);
    }

    #[tokio::test]
    async fn the_audience_does_not_depend_on_the_order_of_external_urls() {
        let method = JwtBearerAuthConfig {
            jwt_verification_strategy_id: "idp".into(),
            ..Default::default()
        };
        let mut bound = Vec::new();
        for external_urls in [
            ["https://internal.example", "https://gateway.example"],
            ["https://gateway.example", "https://internal.example"],
        ] {
            let mut network = discovery_network();
            network.listeners[0].external_urls = external_urls
                .iter()
                .map(|url| url.to_string())
                .collect();
            let outcome =
                resolve_surface_declaration(&declaring_surface(), None, Some(&FixtureStrategies::Pinned), &network)
                    .await
                    .expect("resolve");
            let DeclarationOutcome::Declare(declaration) = outcome else {
                panic!("expected a declaration for {external_urls:?}");
            };
            assert_eq!(declaration.resource, RESOURCE, "{external_urls:?}");
            bound.push(
                declaration
                    .bind_audience(&method)
                    .audiences,
            );
        }
        assert_eq!(bound, [vec![RESOURCE.to_string()], vec![RESOURCE.to_string()]]);
    }

    #[test]
    fn requests_declaration_follows_protected_resource_only() {
        assert!(requests_declaration(&declaring_surface()));
        for protocol in [
            crate::config::agent_surface::SurfaceProtocol::A2a,
            crate::config::agent_surface::SurfaceProtocol::Ap2,
            crate::config::agent_surface::SurfaceProtocol::DIDComm,
        ] {
            let mut surface = declaring_surface();
            surface.access_point.protocol = protocol.clone();
            assert!(requests_declaration(&surface), "{protocol:?}");
        }
        let mut scoped = jwt_bearer_method();
        scoped["required_scopes"] = json!(["tools"]);
        assert!(!requests_declaration(&discovery_surface(scoped, None)));
        assert!(!requests_declaration(&discovery_surface(jwt_bearer_method(), None)));
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
            "audiences": [],
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

    /// An A2A Access Point whose one JWT Bearer method, changed by
    /// `overrides`, declares `resource`.
    fn declaring_a2a(
        overrides: Value,
        resource: &str,
    ) -> AgentSurface {
        let mut surface = a2a_surface(Some(vec![jwt_method(overrides)]), "https://agent.internal");
        if let Some(caller_authentication) = surface
            .access_point
            .caller_authentication
            .as_mut()
        {
            caller_authentication.protected_resource =
                Some(serde_json::from_value(json!({ "resource": resource })).expect("protected resource"));
        }
        surface
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

    /// A read-only store holding one strategy under its id.
    struct Holding(JwtVerificationStrategy);

    #[async_trait::async_trait]
    impl JwtVerificationStrategyStorage for Holding {
        async fn create(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            anyhow::bail!("read-only")
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
            Ok((self.0.id == id).then(|| self.0.clone()))
        }

        async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
            Ok(vec![self.0.clone()])
        }

        async fn update(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            anyhow::bail!("read-only")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            anyhow::bail!("read-only")
        }
    }

    async fn resolve_a2a(
        surface: &AgentSurface,
        alias: Option<&str>,
        strategy: JwtVerificationStrategy,
        network: &NetworkConfig,
    ) -> DeclarationOutcome {
        resolve_surface_declaration(surface, alias, Some(&Holding(strategy)), network)
            .await
            .expect("the store answers")
    }

    fn stripped(reason: StripReason) -> DeclarationOutcome {
        DeclarationOutcome::Strip(reason)
    }

    #[tokio::test]
    async fn an_a2a_protected_resource_declares_the_strategy_issuer_and_its_pin() {
        let outcome =
            resolve_a2a(&declaring_a2a(json!({}), A2A_RESOURCE), None, pinned_strategy(), &a2a_network()).await;
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

    #[tokio::test]
    async fn no_caller_authentication_passes_through_unless_the_target_is_fabric() {
        let network = a2a_network();
        for (surface, expected) in [
            (a2a_surface(None, "https://agent.internal"), DeclarationOutcome::PassThrough),
            (a2a_surface(Some(vec![]), "https://agent.internal"), DeclarationOutcome::PassThrough),
            (a2a_surface(None, "fabric://peer/surface"), stripped(StripReason::FabricTarget)),
            (a2a_surface(Some(vec![]), "fabric://peer/surface"), stripped(StripReason::FabricTarget)),
            (
                a2a_surface(Some(vec![jwt_method(json!({}))]), "fabric://peer/surface"),
                stripped(StripReason::NotDeclared),
            ),
        ] {
            let outcome = resolve_surface_declaration(&surface, None, Some(&FixtureStrategies::Failing), &network)
                .await
                .expect("an Access Point without protected_resource reads no strategy");
            assert_eq!(outcome, expected, "{}", surface.target.endpoint);
            assert!(!refuses_failed_callers_by_default(&outcome));
        }
    }

    #[tokio::test]
    async fn a_missing_or_foreign_strategy_leaves_a_declaration_unservable() {
        let network = a2a_network();
        let surface = declaring_a2a(json!({}), A2A_RESOURCE);

        let mut other_id = pinned_strategy();
        other_id.id = "strategy-2".into();
        let outcome = resolve_a2a(&surface, None, other_id, &network).await;
        assert_eq!(
            outcome,
            DeclarationOutcome::Unservable(UnservableDeclaration::new(
                UnservableReason::StrategyUnavailable,
                "the JWT verification strategy is missing or not available to this surface's tenant"
            ))
        );
        assert!(!refuses_failed_callers_by_default(&outcome));

        let mut foreign = pinned_strategy();
        foreign.tenant_id = Some("tenant-b".into());
        assert_eq!(
            unservable_reason(&resolve_a2a(&surface, None, foreign.clone(), &network).await),
            Some(UnservableReason::StrategyUnavailable)
        );

        let mut owned = declaring_a2a(json!({}), A2A_RESOURCE);
        owned.tenant_id = Some("tenant-a".into());
        assert_eq!(
            unservable_reason(&resolve_a2a(&owned, None, foreign, &network).await),
            Some(UnservableReason::StrategyUnavailable)
        );
        let mut own = pinned_strategy();
        own.tenant_id = Some("tenant-a".into());
        assert_eq!(
            resolve_a2a(&owned, None, own, &network)
                .await
                .label(),
            "declare"
        );
        assert_eq!(
            resolve_a2a(&owned, None, pinned_strategy(), &network)
                .await
                .label(),
            "declare"
        );
    }

    #[tokio::test]
    async fn a_static_unpinned_or_mismatched_strategy_still_declares() {
        let surface = declaring_a2a(json!({}), A2A_RESOURCE);

        let mut static_keys = pinned_strategy();
        static_keys.jwks_source = JwksSource::Static { jwks: Vec::new() };
        let outcome = resolve_a2a(&surface, None, static_keys.clone(), &a2a_network()).await;
        assert!(refuses_failed_callers_by_default(&outcome));
        let DeclarationOutcome::Declare(declaration) = outcome else {
            panic!("a static key set declares");
        };
        assert_eq!(declaration.authorization_servers, [AS_ISSUER]);
        assert_eq!(declaration.pin, Some(pin()));
        static_keys.authorization_server = None;

        let mut unpinned = pinned_strategy();
        unpinned.authorization_server = None;
        let mut other_issuer = pinned_strategy();
        other_issuer.authorization_server = Some(AuthorizationServerMetadata {
            issuer: "https://other.example/".into(),
            ..pin()
        });
        let mut other_keys = pinned_strategy();
        other_keys.jwks_source = JwksSource::Remote {
            jwks_uri: "https://as.example/other.json".into(),
        };

        for (case, strategy) in [
            ("static unpinned", static_keys),
            ("unpinned", unpinned),
            ("other issuer", other_issuer),
            ("other keys", other_keys),
        ] {
            let outcome = resolve_a2a(&surface, None, strategy, &a2a_network()).await;
            assert!(refuses_failed_callers_by_default(&outcome), "{case}");
            let DeclarationOutcome::Declare(declaration) = outcome else {
                panic!("{case}: expected a declaration");
            };
            assert_eq!(declaration.authorization_servers, [AS_ISSUER], "{case}");
            assert_eq!(declaration.pin, None, "{case}");
        }
    }

    #[tokio::test]
    async fn an_issuer_metadata_cannot_name_leaves_the_declaration_unservable() {
        let unservable = DeclarationOutcome::Unservable(UnservableDeclaration::new(
            UnservableReason::IssuerNotAdvertisable,
            "the JWT verification strategy's expected_issuer is not an issuer URL protected resource metadata can \
             name",
        ));
        let operators = declaring_a2a(json!({}), A2A_RESOURCE);
        let mut tenants = declaring_a2a(json!({}), A2A_RESOURCE);
        tenants.tenant_id = Some("tenant-a".into());
        let cases = [
            (&operators, None, "did:web:as.example"),
            (&operators, None, "https://as.example/?tenant=a"),
            (&operators, None, "http://user:pw@as.example/"),
            (&tenants, Some("tenant-a"), "http://as.example/"),
            (&tenants, Some("tenant-a"), "did:web:as.example"),
        ];
        for (surface, tenant, issuer) in cases {
            let mut strategy = pinned_strategy();
            strategy.expected_issuer = issuer.into();
            strategy.tenant_id = tenant.map(Into::into);
            let outcome = resolve_a2a(surface, None, strategy, &a2a_network()).await;
            assert_eq!(outcome, unservable, "{issuer} for {tenant:?}");
            assert!(!refuses_failed_callers_by_default(&outcome), "{issuer}");
        }
    }

    #[tokio::test]
    async fn an_operator_strategy_with_an_http_issuer_declares_it() {
        let mut strategy = pinned_strategy();
        strategy.expected_issuer = "http://127.0.0.1:4444/".into();
        let outcome = resolve_a2a(&declaring_a2a(json!({}), A2A_RESOURCE), None, strategy, &a2a_network()).await;
        assert!(refuses_failed_callers_by_default(&outcome));
        let DeclarationOutcome::Declare(declaration) = outcome else {
            panic!("an operator's http issuer declares");
        };
        assert_eq!(declaration.authorization_servers, ["http://127.0.0.1:4444/"]);
    }

    #[tokio::test]
    async fn a_resource_no_listener_serves_is_unservable() {
        let mut unmatched = declaring_a2a(json!({}), A2A_RESOURCE);
        unmatched
            .access_point
            .listen_address = "0.0.0.0:9999".into();
        assert_eq!(
            unservable_reason(&resolve_a2a(&unmatched, None, pinned_strategy(), &a2a_network()).await),
            Some(UnservableReason::ResourceMismatch)
        );

        let mut plain_http = a2a_network();
        plain_http.listeners[0].external_urls = vec!["http://gw.example".into()];
        assert_eq!(
            unservable_reason(
                &resolve_a2a(&declaring_a2a(json!({}), A2A_RESOURCE), None, pinned_strategy(), &plain_http).await
            ),
            Some(UnservableReason::ResourceMismatch)
        );
    }

    #[tokio::test]
    async fn a_named_variant_declares_its_aliased_url() {
        let surface = declaring_a2a(json!({}), A2A_RESOURCE);
        let DeclarationOutcome::Declare(declaration) =
            resolve_a2a(&surface, Some("dev"), pinned_strategy(), &a2a_network()).await
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
    }

    #[tokio::test]
    async fn a_variant_of_an_access_point_at_the_root_is_unservable() {
        for route in ["/", ""] {
            let mut root = declaring_a2a(json!({}), "https://gw.example/");
            root.access_point.route = route.into();
            let DeclarationOutcome::Declare(base) = resolve_a2a(&root, None, pinned_strategy(), &a2a_network()).await
            else {
                panic!("expected the root Access Point to declare");
            };
            assert_eq!(base.resource, "https://gw.example/", "{route:?}");
            assert_eq!(
                unservable_reason(&resolve_a2a(&root, Some("dev"), pinned_strategy(), &a2a_network()).await),
                Some(UnservableReason::RootVariantResource),
                "{route:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_surface_resolver_reads_the_strategy_only_when_protected_resource_is_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(dir.path().to_path_buf())
            .await
            .expect("store");
        let stored = store
            .create(pinned_strategy())
            .await
            .expect("create");
        let surface = declaring_a2a(json!({ "jwt_verification_strategy_id": stored.id }), A2A_RESOURCE);
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
            DeclarationOutcome::Unservable(UnservableDeclaration::new(
                UnservableReason::StrategyStoreUnavailable,
                "the JWT verification strategy store is unavailable"
            ))
        );
        assert!(
            resolve_surface_declaration(&surface, None, Some(&FixtureStrategies::Failing), &network)
                .await
                .is_err()
        );
        let undeclared = a2a_surface(Some(vec![jwt_method(json!({}))]), "https://agent.internal");
        assert_eq!(
            resolve_surface_declaration(&undeclared, None, Some(&FixtureStrategies::Failing), &network)
                .await
                .expect("an Access Point without protected_resource reads no strategy"),
            stripped(StripReason::NotDeclared)
        );
        assert_eq!(
            resolve_surface_declaration(&undeclared, None, None, &network)
                .await
                .expect("resolve"),
            stripped(StripReason::NotDeclared)
        );
    }

    #[test]
    fn the_suggested_resource_is_the_first_external_url_and_the_route() {
        let mut network = a2a_network();
        network.listeners[0].external_urls = vec!["https://gw.example/".into(), "https://other.example".into()];
        let mut surface = a2a_surface(Some(vec![jwt_method(json!({}))]), "https://agent.internal");
        assert_eq!(
            access_point_resource_url(&surface, None, &network).as_deref(),
            Some("https://gw.example/a2a/buyer")
        );
        assert_eq!(
            access_point_resource_url(&surface, Some("dev"), &network).as_deref(),
            Some("https://gw.example/a2a/buyer$dev")
        );
        network.listeners[0].external_urls = vec!["http://gw.example".into()];
        assert_eq!(access_point_resource_url(&surface, None, &network), None);
        surface
            .access_point
            .listen_address = "0.0.0.0:9999".into();
        assert_eq!(access_point_resource_url(&surface, None, &a2a_network()), None);
    }

    #[test]
    fn outcomes_report_their_label_and_reason() {
        for (reason, code) in [
            (StripReason::NotDeclared, "not_declared"),
            (StripReason::FabricTarget, "fabric_target"),
            (StripReason::TransitPoint, "transit_point"),
        ] {
            assert_eq!(stripped(reason).label(), "strip");
            assert_eq!(stripped(reason).reason_code(), Some(code));
        }
        assert_eq!(DeclarationOutcome::PassThrough.label(), "pass_through");
        assert_eq!(DeclarationOutcome::PassThrough.reason_code(), None);
        for (reason, code) in [
            (UnservableReason::UnsupportedProtocol, "unsupported_protocol"),
            (UnservableReason::InvalidProtectedResource, "invalid_protected_resource"),
            (UnservableReason::IncompatibleCallerAuthentication, "incompatible_caller_authentication"),
            (UnservableReason::RootVariantResource, "root_variant_resource"),
            (UnservableReason::ResourceMismatch, "resource_mismatch"),
            (UnservableReason::StrategyUnavailable, "strategy_unavailable"),
            (UnservableReason::IssuerNotAdvertisable, "issuer_not_advertisable"),
            (UnservableReason::StrategyStoreUnavailable, "strategy_store_unavailable"),
            (UnservableReason::NetworkUnavailable, "network_unavailable"),
        ] {
            let unservable = DeclarationOutcome::Unservable(UnservableDeclaration::new(reason, "detail"));
            assert_eq!(unservable.label(), "unservable");
            assert_eq!(unservable.reason_code(), Some(code));
        }
        assert_eq!(
            UnservableDeclaration::new(UnservableReason::UnsupportedProtocol, "the detail").to_string(),
            "the detail"
        );
    }
}
