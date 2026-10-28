//! OAuth 2.0 Protected Resource Metadata (RFC 9728) and bearer token
//! challenges (RFC 6750) for Access Points.
//!
//! An Access Point whose caller authentication accepts tokens from external
//! authorization servers publishes a metadata document naming them, and
//! answers a caller without a valid token with a challenge pointing at it, so
//! a client finds where to get a token. The rules for resource identifiers,
//! variant resources, metadata URLs, documents and challenges live here so
//! every protocol that publishes them shares one implementation; the gateway
//! STS Resource Server (`crate::mcp::resource_server`) uses the same helpers.
//! The authorization server side, fetching an issuer's own metadata (RFC 8414),
//! is [`crate::authz_metadata`], whose issuer rules the advertised
//! authorization servers follow.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::agent_surface::SurfaceProtocol;
use crate::sts::mcp_profile::canonical_https_url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceTokenError {
    Missing,
    Invalid,
    InsufficientScope,
    Unavailable,
}

impl ResourceTokenError {
    pub fn status_code(self) -> StatusCode {
        match self {
            Self::Missing | Self::Invalid => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Access Point protocols whose caller authentication can publish protected
/// resource metadata. Another protocol opts in here.
pub fn supports_protected_resource(protocol: &SurfaceProtocol) -> bool {
    *protocol == SurfaceProtocol::Mcp
}

/// A resource identifier and the scopes advertised for it: a canonical HTTPS
/// URL without credentials, query or fragment, and bounded OAuth scope tokens.
pub fn validate_resource(
    resource: &str,
    scopes: &[String],
) -> Result<(), String> {
    canonical_https_url(resource).map_err(|error| error.to_string())?;
    if scopes.len() > 128
        || scopes.iter().any(|scope| {
            scope.is_empty()
                || scope.len() > 256
                || scope
                    .bytes()
                    .any(|byte| !matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        })
    {
        return Err("MCP authorization scopes must be bounded OAuth scope tokens".into());
    }
    Ok(())
}

/// The resource of an Access Point variant: `<resource>$<alias>`.
pub fn variant_resource(
    resource: &str,
    alias: &str,
) -> Result<String, String> {
    if alias.is_empty()
        || alias.len() > 32
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("Invalid MCP resource variant alias".into());
    }
    let mut resource = canonical_https_url(resource).map_err(|error| error.to_string())?;
    resource.set_path(&format!("{}${alias}", resource.path()));
    Ok(resource.to_string())
}

/// A resource is served only on a public origin of its endpoint's listener,
/// with the endpoint's own path.
pub fn validate_endpoint(
    resource: &str,
    public_origins: &[String],
    path: &str,
) -> Result<(), String> {
    let resource = canonical_https_url(resource).map_err(|error| error.to_string())?;
    if resource.path() != path
        || !public_origins
            .iter()
            .any(|origin| url::Url::parse(origin).is_ok_and(|origin| origin.origin() == resource.origin()))
    {
        return Err("MCP resource must match the configured public origin and endpoint path".into());
    }
    Ok(())
}

/// `/.well-known/oauth-protected-resource` followed by the resource's path,
/// on the resource's origin (RFC 9728 section 3.1).
pub fn metadata_url(resource: &str) -> Result<url::Url, String> {
    let mut resource = canonical_https_url(resource).map_err(|error| error.to_string())?;
    let suffix = if resource.path() == "/" {
        ""
    } else {
        resource.path()
    };
    let path = format!("/.well-known/oauth-protected-resource{suffix}");
    resource.set_path(&path);
    Ok(resource)
}

pub fn metadata_document(
    resource: &str,
    authorization_servers: &[String],
    scopes: &[String],
) -> Value {
    let mut metadata = json!({
        "resource": resource,
        "authorization_servers": authorization_servers,
        "bearer_methods_supported": ["header"]
    });
    if !scopes.is_empty() {
        metadata["scopes_supported"] = json!(scopes);
    }
    metadata
}

/// `Bearer resource_metadata="…"` (RFC 9728), with the RFC 6750 error
/// code once a token was presented and the scopes the resource requires.
pub fn challenge_header(
    metadata: &url::Url,
    error: ResourceTokenError,
    scopes: &[String],
) -> Option<HeaderValue> {
    let mut challenge = format!("Bearer resource_metadata=\"{metadata}\"");
    match error {
        ResourceTokenError::Invalid => challenge.push_str(", error=\"invalid_token\""),
        ResourceTokenError::InsufficientScope => challenge.push_str(", error=\"insufficient_scope\""),
        _ => {}
    }
    if !scopes.is_empty() {
        challenge.push_str(&format!(", scope=\"{}\"", scopes.join(" ")));
    }
    HeaderValue::from_str(&challenge).ok()
}

const MAX_AUTHORIZATION_SERVERS: usize = 8;
const MAX_AUTHORIZATION_SERVER_BYTES: usize = 2048;

/// RFC 9728 discovery for an MCP Access Point whose JWT Bearer caller
/// authentication accepts tokens from external authorization servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResourceConfig {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl ProtectedResourceConfig {
    pub fn validate(&self) -> Result<(), String> {
        validate_resource(&self.resource, &self.scopes)?;
        if self
            .authorization_servers
            .is_empty()
            || self
                .authorization_servers
                .len()
                > MAX_AUTHORIZATION_SERVERS
        {
            return Err(format!("authorization_servers must list 1 to {MAX_AUTHORIZATION_SERVERS} issuers"));
        }
        let mut seen = std::collections::HashSet::new();
        for issuer in &self.authorization_servers {
            validate_authorization_server(issuer)?;
            if !seen.insert(issuer.as_str()) {
                return Err("authorization_servers must not repeat an issuer".into());
            }
        }
        Ok(())
    }

    pub fn for_variant(
        &self,
        alias: Option<&str>,
    ) -> Result<Self, String> {
        validate_resource(&self.resource, &self.scopes)?;
        let Some(alias) = alias else {
            return Ok(self.clone());
        };
        Ok(Self {
            resource: variant_resource(&self.resource, alias)?,
            ..self.clone()
        })
    }

    pub fn metadata(&self) -> Result<Value, String> {
        self.validate()?;
        Ok(metadata_document(&self.resource, &self.authorization_servers, &self.scopes))
    }

    pub fn metadata_url(&self) -> Result<url::Url, String> {
        validate_resource(&self.resource, &self.scopes)?;
        metadata_url(&self.resource)
    }

    pub fn validate_endpoint(
        &self,
        public_origins: &[String],
        path: &str,
    ) -> Result<(), String> {
        validate_resource(&self.resource, &self.scopes)?;
        validate_endpoint(&self.resource, public_origins, path)
    }

    /// The caller authentication the Access Point enforces with this
    /// resource: a JWT Bearer token must name it, the resource advertised for
    /// the route called, as its audience (RFC 8707), so a token the same
    /// authorization server issued for another resource or variant is refused.
    pub fn bind_audience(
        &self,
        config: crate::source_auth::SourceAuthConfig,
    ) -> crate::source_auth::SourceAuthConfig {
        match config {
            crate::source_auth::SourceAuthConfig::JwtBearer(mut jwt) => {
                jwt.audiences = vec![self.resource.clone()];
                crate::source_auth::SourceAuthConfig::JwtBearer(jwt)
            }
            other => other,
        }
    }

    /// The answer to a caller whose token is missing or invalid: a problem
    /// with the RFC 9728 challenge naming this resource's metadata document.
    /// The detail is fixed, so the response never says why a token failed.
    pub fn challenge(
        &self,
        error: ResourceTokenError,
    ) -> Response {
        let challenge = self
            .metadata_url()
            .ok()
            .and_then(|metadata| challenge_header(&metadata, error, &self.scopes));
        let (Some(challenge), ResourceTokenError::Missing | ResourceTokenError::Invalid) = (challenge, error) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let status = error.status_code();
        let body = json!({
            "type": "about:blank",
            "title": status.canonical_reason(),
            "status": status.as_u16(),
            "detail": "A bearer token from an authorization server in the protected resource metadata is required",
        });
        let mut response = (
            status,
            [(header::CONTENT_TYPE, "application/problem+json"), (header::CACHE_CONTROL, "no-store")],
            body.to_string(),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
        response
    }

    /// The challenge for a caller authentication failure the caller caused:
    /// without `error="invalid_token"` when no credential was sent.
    pub fn caller_challenge(
        &self,
        error: &crate::source_auth::errors::SourceAuthError,
    ) -> Response {
        self.challenge(match error {
            crate::source_auth::errors::SourceAuthError::MissingCredential { .. } => ResourceTokenError::Missing,
            _ => ResourceTokenError::Invalid,
        })
    }
}

/// An RFC 8414 issuer identifier, by the rules authorization server metadata
/// discovery applies under the strict posture (`https`, a host, no credentials,
/// query or fragment), and at most 2048 printable ASCII bytes. It is advertised
/// exactly as configured, since clients compare it byte for byte with the
/// issuer in the server's metadata.
fn validate_authorization_server(issuer: &str) -> Result<(), String> {
    if issuer.len() > MAX_AUTHORIZATION_SERVER_BYTES
        || !issuer
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || crate::authz_metadata::validate_issuer(issuer, crate::authz_metadata::EgressPosture::Strict).is_err()
    {
        return Err(
            "authorization_servers entries must be https issuer URLs without credentials, query or fragment".into()
        );
    }
    Ok(())
}

/// The public origins of the listener an Access Point is served on.
fn access_point_origins(
    surface: &crate::config::agent_surface::AgentSurface,
    network: &crate::config::NetworkConfig,
) -> Vec<String> {
    network
        .map_url_to_port(
            &surface
                .access_point
                .listen_address,
        )
        .and_then(|port| network.get_listener_by_port(port))
        .map(|listener| listener.external_urls.clone())
        .unwrap_or_default()
}

/// The request path of an Access Point variant: its route, or `route$alias`.
fn access_point_path(
    surface: &crate::config::agent_surface::AgentSurface,
    alias: Option<&str>,
) -> String {
    match alias {
        Some(alias) => format!("{}${alias}", surface.access_point.route),
        None => surface
            .access_point
            .route
            .clone(),
    }
}

/// The protected resource a resolved MCP Access Point publishes for `alias`:
/// `None` when it has none, and an error when its settings are not ones the
/// Access Point serves, so callers fail closed.
pub fn access_point_protected_resource(
    surface: &crate::config::agent_surface::AgentSurface,
    alias: Option<&str>,
    network: &crate::config::NetworkConfig,
) -> Option<Result<ProtectedResourceConfig, String>> {
    let configured = surface.protected_resource()?;
    Some(
        surface
            .validate_protected_resource()
            .and_then(|()| configured.for_variant(alias))
            .and_then(|derived| {
                derived
                    .validate_endpoint(&access_point_origins(surface, network), &access_point_path(surface, alias))
                    .map(|()| derived)
            }),
    )
}

/// The metadata document an MCP Access Point's caller authentication
/// publishes at `path`. `Ok(None)` when no Access Point claims the path; an
/// error when the claiming settings cannot be served or two claim it.
fn caller_authentication_metadata(
    surfaces: &[std::sync::Arc<crate::config::agent_surface::AgentSurface>],
    network: &crate::config::NetworkConfig,
    path: &str,
) -> Result<Option<Value>, ()> {
    let requested = path.replace("%24", "$");
    let mut found = None;
    for surface in surfaces {
        if surface.status != crate::config::agent_surface::SurfaceStatus::Active
            || !supports_protected_resource(&surface.access_point.protocol)
        {
            continue;
        }
        let aliases = std::iter::once(None).chain(
            surface
                .variants
                .iter()
                .filter(|variant| variant.enabled)
                .map(|variant| Some(variant.alias.as_str())),
        );
        for alias in aliases {
            let Ok(resolved) = surface.resolve_variant(alias) else {
                continue;
            };
            let claims_path = resolved
                .protected_resource()
                .and_then(|configured| {
                    configured
                        .for_variant(alias)
                        .ok()
                })
                .and_then(|derived| derived.metadata_url().ok())
                .is_some_and(|url| url.path() == requested);
            if !claims_path {
                continue;
            }
            let metadata = access_point_protected_resource(&resolved, alias, network)
                .and_then(Result::ok)
                .and_then(|served| served.metadata().ok())
                .ok_or(())?;
            if found
                .replace(metadata)
                .is_some()
            {
                return Err(());
            }
        }
    }
    Ok(found)
}

/// Protected resource metadata on an inbound listener. MCP Access Points
/// whose caller authentication publishes a document are matched first, then
/// the gateway STS Resource Server. Without the gateway STS profile, a path no
/// Access Point publishes is a plain `404`: MCP clients probe these paths
/// during discovery, so they are not proxied, logged or audited as requests
/// without a route.
pub async fn protected_resource_metadata(
    axum::extract::State(state): axum::extract::State<crate::state::MultiSurfaceProxyState>,
    request: axum::extract::Request,
) -> Response {
    let reads = matches!(*request.method(), axum::http::Method::GET | axum::http::Method::HEAD);
    let surfaces = state
        .channels
        .read()
        .await
        .iter()
        .map(|channel| channel.surface.clone())
        .collect::<Vec<_>>();
    let published = if reads {
        caller_authentication_metadata(&surfaces, &state.network_config, request.uri().path())
    } else {
        Ok(None)
    };
    match published {
        Err(()) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Ok(Some(metadata)) => ([(header::CACHE_CONTROL, "no-store")], axum::Json(metadata)).into_response(),
        Ok(None)
            if state
                .network_config
                .sts
                .mcp_issuer
                .is_some() =>
        {
            if !reads {
                return (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "GET,HEAD")]).into_response();
            }
            let uri = request.uri().clone();
            crate::mcp::resource_server::surface_metadata(axum::extract::State(state), axum::extract::OriginalUri(uri))
                .await
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Settings and surfaces the discovery tests share with the gateway STS
/// Resource Server tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use serde_json::{Value, json};

    use super::ProtectedResourceConfig;

    pub(crate) const ISSUER: &str = "https://idp.example/realms/agents";

    pub(crate) fn protected_resource(resource: &str) -> ProtectedResourceConfig {
        ProtectedResourceConfig {
            resource: resource.into(),
            authorization_servers: vec![ISSUER.into()],
            scopes: vec!["tools".into()],
        }
    }

    pub(crate) fn discovery_network() -> crate::config::NetworkConfig {
        serde_json::from_value(json!({
            "did": {"domain": "gateway.example"},
            "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []},
            "listeners": [
                {"id": "in", "name": "in", "bind_address": "0.0.0.0", "port": 8443, "protocol": "https",
                    "external_urls": ["https://gateway.example"]}
            ],
            "routes": {}
        }))
        .unwrap()
    }

    pub(crate) fn jwt_bearer_method() -> Value {
        json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []})
    }

    pub(crate) fn discovery_surface(
        method: Value,
        protected: Option<Value>,
    ) -> crate::config::agent_surface::AgentSurface {
        let mut caller_authentication = json!({"methods": [method]});
        if let Some(protected) = protected {
            caller_authentication["protected_resource"] = protected;
        }
        serde_json::from_value(json!({
            "surface_id": "alpha", "name": "alpha",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp/alpha", "protocol": "mcp",
                "caller_authentication": caller_authentication},
            "target": {"endpoint": "https://tools.example/mcp"},
            "variants": [
                {"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {}},
                {"id": "off", "alias": "off", "name": "Off", "enabled": false, "overrides": {}}
            ]
        }))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn protected_resource_settings_take_only_https_issuers_and_bounded_scopes() {
        assert_eq!(protected_resource("https://gateway.example/mcp/alpha").validate(), Ok(()));
        let trailing_slash = ProtectedResourceConfig {
            authorization_servers: vec!["https://tenant.auth0.example/".into(), "https://accounts.example".into()],
            ..protected_resource("https://gateway.example/mcp/alpha")
        };
        assert_eq!(trailing_slash.validate(), Ok(()));
        for servers in [
            vec![],
            vec!["http://idp.example".to_string()],
            vec!["https://idp.example?tenant=a".to_string()],
            vec!["https://idp.example#issuer".to_string()],
            vec!["https://user:secret@idp.example".to_string()],
            vec!["https://idp.example/realm one".to_string()],
            vec!["idp.example".to_string()],
            vec![ISSUER.to_string(), ISSUER.to_string()],
            (0..9)
                .map(|index| format!("https://idp{index}.example"))
                .collect(),
            vec![format!("https://idp.example/{}", "a".repeat(2048))],
        ] {
            let config = ProtectedResourceConfig {
                authorization_servers: servers.clone(),
                ..protected_resource("https://gateway.example/mcp/alpha")
            };
            assert!(config.validate().is_err(), "{servers:?}");
        }
        assert!(
            protected_resource("http://gateway.example/mcp/alpha")
                .validate()
                .is_err()
        );
        let unbounded_scope = ProtectedResourceConfig {
            scopes: vec!["two words".into()],
            ..protected_resource("https://gateway.example/mcp/alpha")
        };
        assert!(
            unbounded_scope
                .validate()
                .is_err()
        );
    }

    #[test]
    fn protected_resource_metadata_names_the_configured_servers_and_scopes() {
        let config = protected_resource("https://gateway.example/mcp/alpha");
        assert_eq!(
            config.metadata().unwrap(),
            json!({
                "resource": "https://gateway.example/mcp/alpha",
                "authorization_servers": [ISSUER],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["tools"]
            })
        );
        let variant = config
            .for_variant(Some("beta"))
            .unwrap();
        assert_eq!(variant.resource, "https://gateway.example/mcp/alpha$beta");
        assert_eq!(variant.authorization_servers, config.authorization_servers);
        assert_eq!(
            variant
                .metadata_url()
                .unwrap()
                .as_str(),
            "https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha$beta"
        );
        let unscoped = ProtectedResourceConfig { scopes: Vec::new(), ..config };
        assert!(
            unscoped
                .metadata()
                .unwrap()
                .get("scopes_supported")
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_discovery_challenge_names_the_metadata_and_never_why_a_token_failed() {
        let config = protected_resource("https://gateway.example/mcp/alpha");
        let missing = config.challenge(ResourceTokenError::Missing);
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            missing.headers()[header::WWW_AUTHENTICATE],
            "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha\", \
             scope=\"tools\""
        );
        assert_eq!(missing.headers()[header::CONTENT_TYPE], "application/problem+json");
        assert_eq!(missing.headers()[header::CACHE_CONTROL], "no-store");
        let invalid = config.challenge(ResourceTokenError::Invalid);
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert!(
            invalid.headers()[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains(", error=\"invalid_token\", ")
        );
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(invalid.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            body,
            json!({
                "type": "about:blank",
                "title": "Unauthorized",
                "status": 401,
                "detail": "A bearer token from an authorization server in the protected resource metadata is required"
            })
        );
        for error in [ResourceTokenError::InsufficientScope, ResourceTokenError::Unavailable] {
            let response = config.challenge(error);
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                !response
                    .headers()
                    .contains_key(header::WWW_AUTHENTICATE)
            );
        }
    }

    #[test]
    fn a_discovery_access_point_accepts_only_tokens_for_the_resource_of_the_route_called() {
        let network = discovery_network();
        let surface = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]})),
        );
        let method = surface
            .source_auth()
            .cloned()
            .unwrap();
        for (alias, audience) in
            [(None, "https://gateway.example/mcp/alpha"), (Some("beta"), "https://gateway.example/mcp/alpha$beta")]
        {
            let protected = access_point_protected_resource(&surface, alias, &network)
                .unwrap()
                .unwrap();
            let crate::source_auth::SourceAuthConfig::JwtBearer(bound) = protected.bind_audience(method.clone()) else {
                panic!("JWT Bearer caller authentication stays JWT Bearer");
            };
            assert_eq!(bound.audiences, [audience]);
        }
        let api_key: crate::source_auth::SourceAuthConfig = serde_json::from_value(json!(
            {"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}
        ))
        .unwrap();
        assert_eq!(protected_resource("https://gateway.example/mcp/alpha").bind_audience(api_key.clone()), api_key);
    }

    #[test]
    fn an_access_point_serves_its_protected_resource_only_on_its_own_origin_and_route() {
        let network = discovery_network();
        let resource = json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]});
        let surface = discovery_surface(jwt_bearer_method(), Some(resource.clone()));
        assert_eq!(
            access_point_protected_resource(&surface, None, &network)
                .unwrap()
                .unwrap()
                .resource,
            "https://gateway.example/mcp/alpha"
        );
        let beta = surface
            .resolve_variant(Some("beta"))
            .unwrap();
        assert_eq!(
            access_point_protected_resource(&beta, Some("beta"), &network)
                .unwrap()
                .unwrap()
                .resource,
            "https://gateway.example/mcp/alpha$beta"
        );
        assert_eq!(
            access_point_protected_resource(&discovery_surface(jwt_bearer_method(), None), None, &network),
            None
        );
        for unserved in [
            json!({"resource": "https://other.example/mcp/alpha", "authorization_servers": [ISSUER]}),
            json!({"resource": "https://gateway.example/mcp/other", "authorization_servers": [ISSUER]}),
        ] {
            let surface = discovery_surface(jwt_bearer_method(), Some(unserved));
            assert!(matches!(access_point_protected_resource(&surface, None, &network), Some(Err(_))));
        }
        for method in [
            json!({"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "token_header": "x-token"}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "token_scheme": ""}),
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "forward_header": true}),
        ] {
            let surface = discovery_surface(method.clone(), Some(resource.clone()));
            assert!(matches!(access_point_protected_resource(&surface, None, &network), Some(Err(_))), "{method}");
        }
    }

    #[test]
    fn caller_authentication_metadata_matches_the_exact_published_path() {
        let network = discovery_network();
        let surfaces = vec![std::sync::Arc::new(discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]})),
        ))];
        let metadata = |path: &str| caller_authentication_metadata(&surfaces, &network, path);
        assert_eq!(
            metadata("/.well-known/oauth-protected-resource/mcp/alpha").unwrap(),
            Some(json!({
                "resource": "https://gateway.example/mcp/alpha",
                "authorization_servers": [ISSUER],
                "bearer_methods_supported": ["header"]
            }))
        );
        for variant_path in [
            "/.well-known/oauth-protected-resource/mcp/alpha$beta",
            "/.well-known/oauth-protected-resource/mcp/alpha%24beta",
        ] {
            assert_eq!(
                metadata(variant_path)
                    .unwrap()
                    .unwrap()["resource"],
                "https://gateway.example/mcp/alpha$beta"
            );
        }
        for unclaimed in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource/mcp/alpha/tools",
            "/.well-known/oauth-protected-resource/mcp/alpha$off",
        ] {
            assert_eq!(metadata(unclaimed), Ok(None), "{unclaimed}");
        }

        let mut inactive = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]})),
        );
        inactive.status = crate::config::agent_surface::SurfaceStatus::Disabled;
        assert_eq!(
            caller_authentication_metadata(
                &[std::sync::Arc::new(inactive)],
                &network,
                "/.well-known/oauth-protected-resource/mcp/alpha"
            ),
            Ok(None)
        );

        let api_key = json!({"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"});
        let misconfigured = [std::sync::Arc::new(discovery_surface(
            api_key,
            Some(json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]})),
        ))];
        assert_eq!(
            caller_authentication_metadata(&misconfigured, &network, "/.well-known/oauth-protected-resource/mcp/alpha"),
            Err(())
        );
    }
}
