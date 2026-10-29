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
use crate::source_auth::declaration::{UnservableDeclaration, UnservableReason};
use crate::source_auth::errors::SourceAuthFailureKind;
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

impl From<SourceAuthFailureKind> for ResourceTokenError {
    fn from(kind: SourceAuthFailureKind) -> Self {
        match kind {
            SourceAuthFailureKind::Missing => Self::Missing,
            SourceAuthFailureKind::Invalid => Self::Invalid,
            SourceAuthFailureKind::InsufficientScope => Self::InsufficientScope,
        }
    }
}

/// Marks a response whose `WWW-Authenticate` challenge the gateway built
/// itself, so the filter for challenges relayed from a Target keeps it.
#[derive(Clone, Copy, Debug)]
pub struct GatewayChallenge;

/// Sets a challenge the gateway built on `response` and marks the response
/// as carrying it.
pub fn mark_gateway_challenge(
    response: &mut Response,
    challenge: HeaderValue,
) {
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
        .extensions_mut()
        .insert(GatewayChallenge);
}

/// Whether the gateway built the response's challenge itself.
pub fn is_gateway_challenge(response: &Response) -> bool {
    response
        .extensions()
        .get::<GatewayChallenge>()
        .is_some()
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
    if !is_variant_alias(alias) {
        return Err("Invalid MCP resource variant alias".into());
    }
    let mut resource = canonical_https_url(resource).map_err(|error| error.to_string())?;
    resource.set_path(&format!("{}${alias}", resource.path()));
    Ok(resource.to_string())
}

/// A Surface Variant alias a resource can name: 1 to 32 lowercase letters,
/// digits or hyphens.
fn is_variant_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 32
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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
    let path = format!("{}{suffix}", crate::proxy::paths::PROTECTED_RESOURCE_METADATA_PATH);
    resource.set_path(&path);
    Ok(resource)
}

/// The resource path a protected resource metadata request names: the request
/// path after the well-known prefix, `/` when nothing follows it, with `%24`
/// read as the Surface Variant separator `$`. `None` for a path outside the
/// metadata paths.
fn requested_resource_path(path: &str) -> Option<String> {
    let requested = path.replace("%24", "$");
    match requested.strip_prefix(crate::proxy::paths::PROTECTED_RESOURCE_METADATA_PATH)? {
        "" => Some("/".into()),
        suffix if suffix.starts_with('/') => Some(suffix.into()),
        _ => None,
    }
}

pub fn metadata_document(
    resource: &str,
    authorization_servers: &[String],
    scopes_supported: &[String],
) -> Value {
    let mut metadata = json!({
        "resource": resource,
        "authorization_servers": authorization_servers,
        "bearer_methods_supported": ["header"]
    });
    if !scopes_supported.is_empty() {
        metadata["scopes_supported"] = json!(scopes_supported);
    }
    metadata
}

/// The RFC 6750 error code a challenge carries: none when no token was
/// presented.
fn error_code(error: ResourceTokenError) -> Option<&'static str> {
    match error {
        ResourceTokenError::Invalid => Some("invalid_token"),
        ResourceTokenError::InsufficientScope => Some("insufficient_scope"),
        ResourceTokenError::Missing | ResourceTokenError::Unavailable => None,
    }
}

/// `Bearer resource_metadata="…"` (RFC 9728), with the RFC 6750 error
/// code once a token was presented and the scopes the resource requires.
pub fn challenge_header(
    metadata: &url::Url,
    error: ResourceTokenError,
    required_scopes: &[String],
) -> Option<HeaderValue> {
    let mut challenge = format!("Bearer resource_metadata=\"{metadata}\"");
    if let Some(code) = error_code(error) {
        challenge.push_str(&format!(", error=\"{code}\""));
    }
    if !required_scopes.is_empty() {
        challenge.push_str(&format!(", scope=\"{}\"", required_scopes.join(" ")));
    }
    HeaderValue::from_str(&challenge).ok()
}

/// `Bearer realm="agent-gateway"` (RFC 6750) with the error code once a token
/// was presented: a challenge naming no protected resource metadata.
pub fn realm_challenge_header(error: ResourceTokenError) -> HeaderValue {
    HeaderValue::from_static(match error {
        ResourceTokenError::Invalid => "Bearer realm=\"agent-gateway\", error=\"invalid_token\"",
        ResourceTokenError::InsufficientScope => "Bearer realm=\"agent-gateway\", error=\"insufficient_scope\"",
        ResourceTokenError::Missing | ResourceTokenError::Unavailable => "Bearer realm=\"agent-gateway\"",
    })
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

    pub fn validate_endpoint(
        &self,
        public_origins: &[String],
        path: &str,
    ) -> Result<(), String> {
        validate_resource(&self.resource, &self.scopes)?;
        validate_endpoint(&self.resource, public_origins, path)
    }
}

/// A problem with a fixed detail, so the response never says why a token
/// failed, carrying `challenge` as a gateway challenge.
pub(crate) fn refusal(
    status: StatusCode,
    challenge: Option<HeaderValue>,
    detail: &'static str,
) -> Response {
    let body = json!({
        "type": "about:blank",
        "title": status.canonical_reason(),
        "status": status.as_u16(),
        "detail": detail,
    });
    let mut response = (
        status,
        [(header::CONTENT_TYPE, "application/problem+json"), (header::CACHE_CONTROL, "no-store")],
        body.to_string(),
    )
        .into_response();
    if let Some(challenge) = challenge {
        mark_gateway_challenge(&mut response, challenge);
    }
    response
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

/// The public origin a derived declaration names for an Access Point: the
/// first public origin of its listener, without a trailing slash. The listener
/// is the one its `listen_address` names, or for a bind address such as
/// `0.0.0.0:8443`, the one on that port.
pub fn access_point_origin(
    surface: &crate::config::agent_surface::AgentSurface,
    network: &crate::config::NetworkConfig,
) -> Option<String> {
    let listen_address = &surface
        .access_point
        .listen_address;
    let port = network
        .map_url_to_port(listen_address)
        .or_else(|| {
            listen_address
                .rsplit(':')
                .next()
                .and_then(|port| port.parse().ok())
        })?;
    network
        .get_listener_by_port(port)?
        .external_urls
        .first()
        .map(|origin| {
            origin
                .trim_end_matches('/')
                .to_string()
        })
}

/// The request path of an Access Point variant: its route (`/` for an empty
/// route), or `route$alias`. `None` for an alias no resource can name, and for
/// a variant of an Access Point at `/`: a request for `/$alias` reaches the
/// Access Point at `/` itself, so the variant has no path of its own.
pub fn access_point_path(
    surface: &crate::config::agent_surface::AgentSurface,
    alias: Option<&str>,
) -> Option<String> {
    let route = match surface
        .access_point
        .route
        .as_str()
    {
        "" => "/",
        route => route,
    };
    match alias {
        None => Some(route.to_string()),
        Some(alias) if route != "/" && is_variant_alias(alias) => Some(format!("{route}${alias}")),
        Some(_) => None,
    }
}

/// The protected resource a resolved MCP Access Point publishes for `alias`:
/// `None` when it has none, and an error when its settings are not ones the
/// Access Point serves, so callers fail closed.
pub fn access_point_protected_resource(
    surface: &crate::config::agent_surface::AgentSurface,
    alias: Option<&str>,
    network: &crate::config::NetworkConfig,
) -> Option<Result<ProtectedResourceConfig, UnservableDeclaration>> {
    let configured = surface.protected_resource()?;
    let Some(path) = access_point_path(surface, alias) else {
        return Some(Err(UnservableDeclaration::new(
            UnservableReason::RootVariantResource,
            "a variant of an Access Point at / is not reachable at a resource of its own",
        )));
    };
    Some(
        surface
            .validate_protected_resource()
            .and_then(|()| {
                configured
                    .for_variant(alias)
                    .map_err(|detail| UnservableDeclaration::new(UnservableReason::InvalidProtectedResource, detail))
            })
            .and_then(|derived| {
                derived
                    .validate_endpoint(&access_point_origins(surface, network), &path)
                    .map(|()| derived)
                    .map_err(|detail| UnservableDeclaration::new(UnservableReason::ResourceMismatch, detail))
            }),
    )
}

/// Whether a channel or proxy route catch-all on the listener also covers the
/// protected resource metadata paths: one with an empty prefix or at
/// `/.well-known`. A path no Access Point publishes then still reaches it, as
/// it did before these paths were routed here.
pub fn proxies_metadata_paths(network: &crate::config::NetworkConfig) -> bool {
    let metadata_path = crate::proxy::paths::PROTECTED_RESOURCE_METADATA_PATH;
    network
        .channels
        .iter()
        .map(|channel| channel.prefix.as_str())
        .chain(
            network
                .routes
                .values()
                .filter(|route| route.route_type == crate::config::RouteType::Proxy)
                .map(|route| route.prefix.as_str()),
        )
        .any(|prefix| prefix != metadata_path && format!("{metadata_path}/").starts_with(&format!("{prefix}/")))
}

/// Protected resource metadata on an inbound listener: the one document an
/// Access Point declaration, an MCP surface or MCP Proxy of the gateway STS
/// Resource Server publishes at the path, from
/// [`crate::mcp::resource_server::served_metadata`], and `503` when the
/// claiming settings cannot be served or two endpoints claim it. Without the
/// gateway STS profile, a path nothing publishes goes to the proxy handler when
/// a channel or proxy route covers it ([`proxies_metadata_paths`]), and is
/// otherwise a plain `404`: MCP clients probe these paths during discovery, so
/// they are not logged or audited as requests without a route.
pub async fn protected_resource_metadata(
    axum::extract::ConnectInfo(address): axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::State(state): axum::extract::State<crate::state::MultiSurfaceProxyState>,
    request: axum::extract::Request,
) -> Response {
    use crate::mcp::resource_server::{MetadataMatch, served_metadata};

    let reads = matches!(*request.method(), axum::http::Method::GET | axum::http::Method::HEAD);
    let sts = state
        .network_config
        .sts
        .mcp_issuer
        .is_some();
    let requested = requested_resource_path(request.uri().path()).filter(|_| reads);
    let published = match requested {
        Some(requested) => served_metadata(&state, &requested).await,
        None => MetadataMatch::None,
    };
    match published {
        MetadataMatch::Metadata(metadata) => {
            ([(header::CACHE_CONTROL, "no-store")], axum::Json(metadata)).into_response()
        }
        MetadataMatch::Unavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        MetadataMatch::None if sts && !reads => {
            (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "GET,HEAD")]).into_response()
        }
        MetadataMatch::None if !sts && proxies_metadata_paths(&state.network_config) => {
            crate::proxy::handler::multi_channel_proxy_handler(
                axum::extract::ConnectInfo(address),
                axum::extract::State(state),
                request,
            )
            .await
        }
        MetadataMatch::None => StatusCode::NOT_FOUND.into_response(),
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
    fn a_variant_names_its_resource_and_metadata_url_after_the_alias() {
        let config = protected_resource("https://gateway.example/mcp/alpha");
        let variant = config
            .for_variant(Some("beta"))
            .unwrap();
        assert_eq!(variant.resource, "https://gateway.example/mcp/alpha$beta");
        assert_eq!(variant.authorization_servers, config.authorization_servers);
        assert_eq!(
            metadata_url(&variant.resource)
                .unwrap()
                .as_str(),
            "https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha$beta"
        );
        assert_eq!(
            config
                .for_variant(None)
                .unwrap(),
            config
        );
        assert!(
            config
                .for_variant(Some("Beta"))
                .is_err()
        );
    }

    #[test]
    fn a_marked_challenge_is_the_gateways_and_a_header_alone_is_not() {
        let challenge = HeaderValue::from_static("Bearer realm=\"agent-gateway\"");
        let mut relayed = StatusCode::UNAUTHORIZED.into_response();
        relayed
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge.clone());
        assert!(!is_gateway_challenge(&relayed));

        let mut marked = StatusCode::UNAUTHORIZED.into_response();
        mark_gateway_challenge(&mut marked, challenge.clone());
        assert!(is_gateway_challenge(&marked));
        assert_eq!(
            marked
                .headers()
                .get_all(header::WWW_AUTHENTICATE)
                .iter()
                .collect::<Vec<_>>(),
            [&challenge]
        );

        let unchallenged = refusal(StatusCode::FORBIDDEN, None, "A bearer token issued for this resource is required");
        assert_eq!(unchallenged.status(), StatusCode::FORBIDDEN);
        assert!(
            !unchallenged
                .headers()
                .contains_key(header::WWW_AUTHENTICATE)
        );
        assert!(!is_gateway_challenge(&unchallenged));
    }

    #[test]
    fn a_failure_kind_names_the_resource_token_error_and_its_status() {
        for (kind, error, status) in [
            (SourceAuthFailureKind::Missing, ResourceTokenError::Missing, StatusCode::UNAUTHORIZED),
            (SourceAuthFailureKind::Invalid, ResourceTokenError::Invalid, StatusCode::UNAUTHORIZED),
            (SourceAuthFailureKind::InsufficientScope, ResourceTokenError::InsufficientScope, StatusCode::FORBIDDEN),
        ] {
            assert_eq!(ResourceTokenError::from(kind), error);
            assert_eq!(ResourceTokenError::from(kind).status_code(), status);
        }
        assert_ne!(ResourceTokenError::from(SourceAuthFailureKind::InsufficientScope), ResourceTokenError::Invalid);
    }

    #[test]
    fn a_challenge_names_the_error_once_a_token_was_presented_and_only_the_scopes_given() {
        let metadata = metadata_url("https://gateway.example/mcp/alpha").unwrap();
        let named =
            "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha\"";
        let required = ["tools.call".to_string(), "tools.list".to_string()];
        for (error, scopes, expected) in [
            (ResourceTokenError::Missing, &[][..], named.to_string()),
            (ResourceTokenError::Invalid, &[][..], format!("{named}, error=\"invalid_token\"")),
            (
                ResourceTokenError::InsufficientScope,
                &required[..],
                format!("{named}, error=\"insufficient_scope\", scope=\"tools.call tools.list\""),
            ),
            (ResourceTokenError::Missing, &required[..], format!("{named}, scope=\"tools.call tools.list\"")),
        ] {
            assert_eq!(challenge_header(&metadata, error, scopes).unwrap(), expected.as_str(), "{error:?}");
        }
    }

    #[test]
    fn a_realm_challenge_names_no_metadata_and_the_error_once_a_token_was_presented() {
        for (error, expected) in [
            (ResourceTokenError::Missing, "Bearer realm=\"agent-gateway\""),
            (ResourceTokenError::Invalid, "Bearer realm=\"agent-gateway\", error=\"invalid_token\""),
            (ResourceTokenError::InsufficientScope, "Bearer realm=\"agent-gateway\", error=\"insufficient_scope\""),
        ] {
            let challenge = realm_challenge_header(error);
            assert_eq!(challenge, expected, "{error:?}");
            assert!(
                !challenge
                    .to_str()
                    .unwrap()
                    .contains("resource_metadata")
            );
        }
    }

    #[test]
    fn a_document_lists_scopes_supported_only_when_there_are_some() {
        let servers = [ISSUER.to_string()];
        assert_eq!(
            metadata_document(
                "https://gateway.example/mcp/alpha",
                &servers,
                &["tools.call".to_string(), "tools".to_string()]
            ),
            json!({
                "resource": "https://gateway.example/mcp/alpha",
                "authorization_servers": [ISSUER],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["tools.call", "tools"]
            })
        );
        assert_eq!(metadata_document("https://gateway.example/mcp/alpha", &servers, &[]).get("scopes_supported"), None);
    }

    /// Source files that hold only tests.
    fn is_test_source(relative: &str) -> bool {
        let name = relative
            .rsplit('/')
            .next()
            .unwrap_or(relative);
        relative.starts_with("component_tests/")
            || name == "tests.rs"
            || name.ends_with("_tests.rs")
            || name.ends_with(".test.rs")
            || name.starts_with("test_")
    }

    /// The source before its first inline test module.
    fn non_test_code(source: &str) -> &str {
        let mut offset = 0;
        let mut lines = source
            .split_inclusive('\n')
            .peekable();
        while let Some(line) = lines.next() {
            if line.trim_end() == "#[cfg(test)]"
                && lines
                    .peek()
                    .is_some_and(|next| {
                        ["mod ", "pub mod ", "pub(crate) mod "]
                            .iter()
                            .any(|item| next.starts_with(item))
                    })
            {
                return &source[..offset];
            }
            offset += line.len();
        }
        source
    }

    #[test]
    fn only_the_challenge_builders_and_payment_modules_set_www_authenticate() {
        const BUILDERS: [&str; 7] = [
            "protocols/protected_resource.rs",
            "mcp/resource_server.rs",
            "source_auth/errors.rs",
            "source_auth/challenge.rs",
            "identity/handlers/metrics.rs",
            "mpp/",
            "x402/",
        ];
        const SETTERS: [&str; 4] = [".insert(", ".append(", ".header(", "[("];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut pending = vec![root.clone()];
        let mut setters = Vec::new();
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let relative = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if !relative.ends_with(".rs")
                    || is_test_source(&relative)
                    || BUILDERS
                        .iter()
                        .any(|builder| relative.starts_with(builder))
                {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let lines = non_test_code(&source)
                    .lines()
                    .collect::<Vec<_>>();
                for (index, line) in lines.iter().enumerate() {
                    let lower = line.to_ascii_lowercase();
                    let names_header = lower.contains("www-authenticate") || lower.contains("www_authenticate");
                    let sets = [
                        Some(*line),
                        index
                            .checked_sub(1)
                            .map(|previous| lines[previous]),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|text| {
                        SETTERS
                            .iter()
                            .any(|setter| text.contains(setter))
                    });
                    if names_header
                        && sets
                        && !line
                            .trim_start()
                            .starts_with("//")
                    {
                        setters.push(format!("{relative}:{}", index + 1));
                    }
                }
            }
        }
        assert_eq!(setters, Vec::<String>::new());
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
        // A prefix at the metadata path is refused before it is served, so it
        // never turns discovery off.
        let mut owned = network.clone();
        owned.channels = vec![crate::config::network::ChannelPrefix {
            id: "metadata".into(),
            name: "metadata".into(),
            prefix: crate::proxy::paths::PROTECTED_RESOURCE_METADATA_PATH.into(),
        }];
        assert_eq!(
            access_point_protected_resource(&surface, None, &owned),
            access_point_protected_resource(&surface, None, &network)
        );
        // A variant of an Access Point at / has no path of its own.
        let mut root = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/", "authorization_servers": [ISSUER]})),
        );
        root.access_point.route = "/".into();
        assert!(matches!(access_point_protected_resource(&root, None, &network), Some(Ok(_))));
        let root_beta = root
            .resolve_variant(Some("beta"))
            .unwrap();
        assert!(matches!(access_point_protected_resource(&root_beta, Some("beta"), &network), Some(Err(_))));
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

    /// What the listener of [`discovery_network`] answers at a metadata path.
    async fn served(
        surfaces: &[std::sync::Arc<crate::config::agent_surface::AgentSurface>],
        path: &str,
    ) -> Result<Option<Value>, ()> {
        use crate::mcp::resource_server::{MetadataMatch, listener_metadata};
        let Some(requested) = requested_resource_path(path) else {
            return Ok(None);
        };
        match listener_metadata(surfaces, &[], &requested, None, None, &discovery_network()).await {
            MetadataMatch::None => Ok(None),
            MetadataMatch::Metadata(metadata) => Ok(Some(metadata)),
            MetadataMatch::Unavailable => Err(()),
        }
    }

    #[test]
    fn a_metadata_path_names_the_resource_path_after_the_well_known_prefix() {
        for (path, requested) in [
            ("/.well-known/oauth-protected-resource", Some("/")),
            ("/.well-known/oauth-protected-resource/", Some("/")),
            ("/.well-known/oauth-protected-resource/mcp/alpha", Some("/mcp/alpha")),
            ("/.well-known/oauth-protected-resource/mcp/alpha$beta", Some("/mcp/alpha$beta")),
            ("/.well-known/oauth-protected-resource/mcp/alpha%24beta", Some("/mcp/alpha$beta")),
            ("/.well-known/oauth-protected-resourcex", None),
            ("/mcp/alpha", None),
        ] {
            assert_eq!(requested_resource_path(path).as_deref(), requested, "{path}");
        }
    }

    #[test]
    fn an_access_point_origin_is_the_first_public_origin_of_its_listener() {
        let mut network = discovery_network();
        let mut surface = discovery_surface(jwt_bearer_method(), None);
        assert_eq!(access_point_origin(&surface, &network).as_deref(), Some("https://gateway.example"));

        network.listeners[0].external_urls = vec!["https://first.example/".into(), "https://gateway.example".into()];
        surface
            .access_point
            .listen_address = "0.0.0.0:8443".into();
        assert_eq!(access_point_origin(&surface, &network).as_deref(), Some("https://first.example"));

        for unmatched in ["0.0.0.0:9999", "https://other.example", "gateway"] {
            surface
                .access_point
                .listen_address = unmatched.into();
            assert_eq!(access_point_origin(&surface, &network), None, "{unmatched}");
        }

        surface
            .access_point
            .listen_address = "0.0.0.0:8443".into();
        network.listeners[0].external_urls = Vec::new();
        assert_eq!(access_point_origin(&surface, &network), None);
    }

    #[test]
    fn an_access_point_path_names_the_route_called() {
        let mut surface = discovery_surface(jwt_bearer_method(), None);
        assert_eq!(access_point_path(&surface, None).as_deref(), Some("/mcp/alpha"));
        assert_eq!(access_point_path(&surface, Some("beta")).as_deref(), Some("/mcp/alpha$beta"));
        for invalid in ["", "Beta", "be/ta", "b$c"] {
            assert_eq!(access_point_path(&surface, Some(invalid)), None, "{invalid}");
        }
        for route in ["", "/"] {
            surface.access_point.route = route.into();
            assert_eq!(access_point_path(&surface, None).as_deref(), Some("/"), "{route:?}");
            assert_eq!(access_point_path(&surface, Some("beta")), None, "{route:?}");
        }
    }

    #[tokio::test]
    async fn an_access_point_publishes_its_document_at_the_exact_path_of_its_resource() {
        let explicit = json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]});
        let surfaces = vec![std::sync::Arc::new(discovery_surface(jwt_bearer_method(), Some(explicit.clone())))];
        assert_eq!(
            served(&surfaces, "/.well-known/oauth-protected-resource/mcp/alpha").await,
            Ok(Some(json!({
                "resource": "https://gateway.example/mcp/alpha",
                "authorization_servers": [ISSUER],
                "bearer_methods_supported": ["header"]
            })))
        );
        for variant_path in [
            "/.well-known/oauth-protected-resource/mcp/alpha$beta",
            "/.well-known/oauth-protected-resource/mcp/alpha%24beta",
        ] {
            assert_eq!(
                served(&surfaces, variant_path)
                    .await
                    .unwrap()
                    .unwrap()["resource"],
                "https://gateway.example/mcp/alpha$beta",
                "{variant_path}"
            );
        }
        for unclaimed in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource/mcp/alpha/tools",
            "/.well-known/oauth-protected-resource/mcp/alpha$off",
            "/.well-known/oauth-protected-resource/mcp/alpha$unknown",
        ] {
            assert_eq!(served(&surfaces, unclaimed).await, Ok(None), "{unclaimed}");
        }

        // A resource naming another path is not published at the route's path.
        let elsewhere = [std::sync::Arc::new(discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/mcp/other", "authorization_servers": [ISSUER]})),
        ))];
        assert_eq!(served(&elsewhere, "/.well-known/oauth-protected-resource/mcp/alpha").await, Ok(None));

        // An Access Point at / publishes the root form only.
        let mut root = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/", "authorization_servers": [ISSUER]})),
        );
        root.access_point.route = "/".into();
        let root = [std::sync::Arc::new(root)];
        assert_eq!(
            served(&root, "/.well-known/oauth-protected-resource")
                .await
                .unwrap()
                .unwrap()["resource"],
            "https://gateway.example/"
        );
        assert_eq!(served(&root, "/.well-known/oauth-protected-resource/$beta").await, Err(()));
        assert_eq!(served(&root, "/.well-known/oauth-protected-resource/mcp").await, Ok(None));

        let mut inactive = discovery_surface(jwt_bearer_method(), Some(explicit.clone()));
        inactive.status = crate::config::agent_surface::SurfaceStatus::Disabled;
        assert_eq!(
            served(&[std::sync::Arc::new(inactive)], "/.well-known/oauth-protected-resource/mcp/alpha").await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn settings_the_access_point_cannot_serve_make_its_metadata_path_unavailable() {
        let explicit = json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]});
        let path = "/.well-known/oauth-protected-resource/mcp/alpha";

        let api_key = json!({"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"});
        let misconfigured = [std::sync::Arc::new(discovery_surface(api_key, Some(explicit.clone())))];
        assert_eq!(served(&misconfigured, path).await, Err(()));

        let mut a2a = discovery_surface(jwt_bearer_method(), Some(explicit.clone()));
        a2a.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::A2a;
        assert_eq!(served(&[std::sync::Arc::new(a2a)], path).await, Err(()));
    }

    #[tokio::test]
    async fn an_explicit_protected_resource_lists_the_required_scopes_as_supported() {
        let explicit = json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]});
        let unscoped = json!({
            "resource": "https://gateway.example/mcp/alpha",
            "authorization_servers": [ISSUER],
            "bearer_methods_supported": ["header"]
        });
        let mut scoped = jwt_bearer_method();
        scoped["required_scopes"] = json!(["tools"]);
        let mut scoped_document = unscoped.clone();
        scoped_document["scopes_supported"] = json!(["tools"]);
        for (method, document) in [(jwt_bearer_method(), unscoped), (scoped, scoped_document)] {
            let surfaces = [std::sync::Arc::new(discovery_surface(method.clone(), Some(explicit.clone())))];
            assert_eq!(
                served(&surfaces, "/.well-known/oauth-protected-resource/mcp/alpha").await,
                Ok(Some(document)),
                "{method}"
            );
        }
    }

    #[tokio::test]
    async fn a_published_document_supports_the_required_and_the_advertised_scopes() {
        let mut scoped = jwt_bearer_method();
        scoped["required_scopes"] = json!(["tools.call", "tools"]);
        let surfaces = [std::sync::Arc::new(discovery_surface(
            scoped,
            Some(json!({
                "resource": "https://gateway.example/mcp/alpha",
                "authorization_servers": [ISSUER],
                "scopes": ["tools", "resources"]
            })),
        ))];
        assert_eq!(
            served(&surfaces, "/.well-known/oauth-protected-resource/mcp/alpha")
                .await
                .unwrap()
                .unwrap()["scopes_supported"],
            json!(["tools.call", "tools", "resources"])
        );
    }

    #[tokio::test]
    async fn an_access_point_without_a_protected_resource_publishes_no_document() {
        let surfaces = [std::sync::Arc::new(discovery_surface(jwt_bearer_method(), None))];
        for path in
            ["/.well-known/oauth-protected-resource/mcp/alpha", "/.well-known/oauth-protected-resource/mcp/alpha$beta"]
        {
            assert_eq!(served(&surfaces, path).await, Ok(None), "{path}");
        }
    }
}
