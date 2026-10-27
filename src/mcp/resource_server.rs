use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::sts::mcp_profile::{McpIssuerProfile, canonical_https_url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpResourceServerConfig {
    pub resource: String,
    #[serde(default)]
    pub scopes: Vec<String>,
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
    pub fn resource_server(&self) -> McpResourceServerConfig {
        McpResourceServerConfig {
            resource: self.resource.clone(),
            scopes: self.scopes.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.resource_server()
            .validate()?;
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
        let derived = self
            .resource_server()
            .for_variant(alias)?;
        Ok(Self {
            resource: derived.resource,
            ..self.clone()
        })
    }

    pub fn metadata(&self) -> Result<Value, String> {
        self.validate()?;
        Ok(self
            .resource_server()
            .metadata_document(&self.authorization_servers))
    }
}

/// An RFC 8414 issuer identifier: an absolute https URL without credentials,
/// query or fragment. It is advertised exactly as configured, since clients
/// compare it byte for byte with the issuer in the server's metadata.
fn validate_authorization_server(issuer: &str) -> Result<(), String> {
    let invalid = || "authorization_servers entries must be https issuer URLs without credentials, query or fragment";
    let parsed = url::Url::parse(issuer).map_err(|_| invalid())?;
    if issuer.len() > MAX_AUTHORIZATION_SERVER_BYTES
        || !issuer
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid().into());
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
                    .resource_server()
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
            || surface.access_point.protocol != crate::config::agent_surface::SurfaceProtocol::Mcp
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
                .and_then(|derived| {
                    derived
                        .resource_server()
                        .metadata_url()
                        .ok()
                })
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
/// the gateway STS Resource Server. Without the gateway STS profile, a request
/// no Access Point answers is routed like any other request.
pub async fn protected_resource_metadata(
    axum::extract::ConnectInfo(address): axum::extract::ConnectInfo<std::net::SocketAddr>,
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
            surface_metadata(axum::extract::State(state), axum::extract::OriginalUri(uri)).await
        }
        Ok(None) => {
            crate::proxy::handler::multi_channel_proxy_handler(
                axum::extract::ConnectInfo(address),
                axum::extract::State(state),
                request,
            )
            .await
        }
    }
}

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

#[derive(Clone)]
pub struct ResourceServerAuthContext {
    pub issuer: std::sync::Arc<crate::identity::VCIssuer>,
    pub keys: std::sync::Arc<crate::jwt_bearer::JwksClient>,
}

#[derive(Clone)]
pub struct TransitMetadataState {
    pub network: std::sync::Arc<crate::config::NetworkConfig>,
    pub surfaces: Vec<std::sync::Arc<std::sync::RwLock<crate::state::OutboundSurfaceState>>>,
    pub port: u16,
}

pub async fn transit_metadata(
    axum::extract::State(state): axum::extract::State<TransitMetadataState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    let Some(profile) = state
        .network
        .sts
        .mcp_issuer
        .as_ref()
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(suffix) = uri
        .path()
        .strip_prefix("/.well-known/oauth-protected-resource")
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let requested_path = if suffix.is_empty() {
        "/"
    } else {
        suffix
    };
    let origins = state
        .network
        .get_listener_by_port(state.port)
        .map(|listener| listener.external_urls.clone())
        .unwrap_or_default();
    let mut result = None;
    for live in &state.surfaces {
        let Ok(live) = live.read() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let surface = live.surface.clone();
        drop(live);
        if surface.status != crate::config::agent_surface::SurfaceStatus::Active {
            continue;
        }
        for alias in std::iter::once(None).chain(
            surface
                .variants
                .iter()
                .filter(|variant| variant.enabled)
                .map(|variant| Some(variant.alias.as_str())),
        ) {
            let Ok(resolved) = surface.resolve_variant(alias) else {
                continue;
            };
            let Some(transit) = resolved.transit.as_ref() else {
                continue;
            };
            for point in &transit.points {
                let Some(authorization) = point
                    .mcp_http
                    .as_ref()
                    .and_then(|http| http.authorization.as_ref())
                else {
                    continue;
                };
                let listener = point
                    .listen_address
                    .as_deref()
                    .or(transit
                        .outbound_listen_address
                        .as_deref());
                if listener.and_then(|address| {
                    state
                        .network
                        .map_url_to_port_for_type(address, Some("outbound"))
                }) != Some(state.port)
                {
                    continue;
                }
                let base = resolved
                    .access_point
                    .route
                    .trim_end_matches('/');
                let path = point
                    .listen_path
                    .clone()
                    .unwrap_or_else(|| {
                        format!("{}{base}/{}", crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX, point.alias)
                    });
                if authorization
                    .validate_endpoint(&origins, &path)
                    .is_err()
                {
                    continue;
                }
                let Ok(authorization) = authorization.for_transit_variant(base, point, alias) else {
                    continue;
                };
                if url::Url::parse(&authorization.resource).is_ok_and(|resource| resource.path() != requested_path) {
                    continue;
                }
                let Ok(metadata) = authorization.metadata(profile) else {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                };
                if result
                    .replace(metadata)
                    .is_some()
                {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
            }
        }
    }
    match result {
        Some(metadata) => ([(header::CACHE_CONTROL, "no-store")], axum::Json(metadata)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

impl ResourceServerAuthContext {
    pub async fn authenticate_proxy(
        &self,
        proxy: &crate::mcp_proxies::types::McpProxy,
        network: &crate::config::NetworkConfig,
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<crate::source_auth::AuthenticatedIdentity>, ResourceTokenError> {
        let Some(authorization) = proxy
            .mcp_http
            .as_ref()
            .and_then(|http| http.authorization.as_ref())
        else {
            return Ok(None);
        };
        let Some(profile) = network
            .sts
            .mcp_issuer
            .as_ref()
        else {
            return Err(ResourceTokenError::Unavailable);
        };
        authorization
            .validate_endpoint(&network.get_inbound_external_urls(), &proxy.full_path())
            .map_err(|_| ResourceTokenError::Unavailable)?;
        profile
            .validate_network(network)
            .map_err(|_| ResourceTokenError::Unavailable)?;
        authorization
            .authenticate(headers, profile, &self.issuer, self.keys.clone())
            .await
            .map(Some)
    }
}

pub async fn surface_metadata(
    axum::extract::State(state): axum::extract::State<crate::state::MultiSurfaceProxyState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    let Some(profile) = state
        .network_config
        .sts
        .mcp_issuer
        .as_ref()
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(suffix) = uri
        .path()
        .strip_prefix("/.well-known/oauth-protected-resource")
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let requested_path = if suffix.is_empty() {
        "/"
    } else {
        suffix
    };
    let surfaces = state
        .channels
        .read()
        .await
        .iter()
        .map(|channel| channel.surface.clone())
        .collect::<Vec<_>>();
    let mut result = None;
    for surface in surfaces {
        if surface.status != crate::config::agent_surface::SurfaceStatus::Active
            || surface.access_point.protocol != crate::config::agent_surface::SurfaceProtocol::Mcp
        {
            continue;
        }
        let Some(authorization) = surface
            .mcp_http
            .as_ref()
            .and_then(|http| http.authorization.as_ref())
        else {
            continue;
        };
        let Ok(resource) = canonical_https_url(&authorization.resource) else {
            continue;
        };
        let prefix = if resource.path() == "/" {
            ""
        } else {
            resource.path()
        };
        let Some(parsed) = crate::proxy::route_variant::parse_route_with_variant(requested_path, prefix) else {
            continue;
        };
        let exact_resource = parsed.tail.is_empty() || (resource.path() == "/" && parsed.tail == "/");
        if !exact_resource {
            continue;
        }
        if let Some(alias) = parsed.alias {
            if !surface
                .variants
                .iter()
                .any(|variant| variant.alias == alias && variant.enabled)
            {
                continue;
            }
        } else if surface
            .default_variant_id
            .as_ref()
            .is_some_and(|id| {
                !surface
                    .variants
                    .iter()
                    .any(|variant| &variant.id == id && variant.enabled)
            })
        {
            continue;
        }
        let Ok(resolved) = surface.resolve_variant(parsed.alias) else {
            continue;
        };
        let Some(authorization) = resolved
            .mcp_http
            .as_ref()
            .and_then(|http| http.authorization.as_ref())
        else {
            continue;
        };
        let Ok(authorization) = authorization.for_variant(parsed.alias) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let origins = state
            .network_config
            .map_url_to_port(
                &resolved
                    .access_point
                    .listen_address,
            )
            .and_then(|port| {
                state
                    .network_config
                    .get_listener_by_port(port)
            })
            .map(|listener| listener.external_urls.clone())
            .unwrap_or_default();
        let expected_path = match parsed.alias {
            Some(alias) => format!("{}${alias}", resolved.access_point.route),
            None => resolved
                .access_point
                .route
                .clone(),
        };
        if expected_path != requested_path
            || authorization
                .validate_endpoint(&origins, &expected_path)
                .is_err()
            || resolved
                .source_auth()
                .is_some()
            || profile
                .validate_network(&state.network_config)
                .is_err()
        {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let Ok(metadata) = authorization.metadata(profile) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        if result
            .replace(metadata)
            .is_some()
        {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    if let Some(store) = state.mcp_proxy_store.as_ref() {
        use crate::mcp_proxies::McpProxyStore;
        let Ok(proxies) = store.list_all().await else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        for proxy in proxies {
            if proxy.status != crate::mcp_proxies::types::McpProxyStatus::Active || proxy.full_path() != requested_path
            {
                continue;
            }
            let Some(authorization) = proxy
                .mcp_http
                .as_ref()
                .and_then(|http| http.authorization.as_ref())
            else {
                continue;
            };
            if authorization
                .validate_endpoint(
                    &state
                        .network_config
                        .get_inbound_external_urls(),
                    requested_path,
                )
                .is_err()
            {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            let Ok(metadata) = authorization.metadata(profile) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            if result
                .replace(metadata)
                .is_some()
            {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
    }
    match result {
        Some(metadata) => ([(header::CACHE_CONTROL, "no-store")], axum::Json(metadata)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// A resource URI an endpoint declares for Resource Server checks.
///
/// `served` says whether the endpoint's runtime check would accept it: the
/// resource's origin must be a public URL of the endpoint's listener and its
/// path the endpoint's own path. A declaration that is not served fails closed
/// at request time, so it grants nothing and never counts as owning the
/// resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceDeclaration {
    pub resource: String,
    pub served: bool,
}

/// Every resource a surface declares — the base Access Point, each enabled
/// variant, and their Transit Points, including the protected resource an
/// Access Point's caller authentication publishes — checked against the same origins and
/// paths the Access Point (`src/proxy/handler.rs`) and Transit
/// (`src/proxy/outbound_handler.rs`) runtime checks use.
///
/// STS ownership decisions must cover every audience a token could later be
/// accepted under, not just the base one.
pub fn surface_resource_declarations(
    surface: &crate::config::agent_surface::AgentSurface,
    network: &crate::config::NetworkConfig,
) -> Vec<ResourceDeclaration> {
    let listener_origins = |port: Option<u16>| {
        port.and_then(|port| network.get_listener_by_port(port))
            .map(|listener| listener.external_urls.clone())
            .unwrap_or_default()
    };
    let mut declarations = Vec::new();
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
        if let Some(authorization) = resolved
            .mcp_http
            .as_ref()
            .and_then(|http| http.authorization.as_ref())
            && let Ok(derived) = authorization.for_variant(alias)
        {
            let path = match alias {
                Some(alias) => format!("{}${alias}", resolved.access_point.route),
                None => resolved
                    .access_point
                    .route
                    .clone(),
            };
            let origins = listener_origins(
                network.map_url_to_port(
                    &resolved
                        .access_point
                        .listen_address,
                ),
            );
            declarations.push(ResourceDeclaration {
                served: derived
                    .validate_endpoint(&origins, &path)
                    .is_ok(),
                resource: derived.resource,
            });
        }
        if let Some(protected) = resolved.protected_resource()
            && let Ok(derived) = protected.for_variant(alias)
        {
            declarations.push(ResourceDeclaration {
                served: matches!(access_point_protected_resource(&resolved, alias, network), Some(Ok(_))),
                resource: derived.resource,
            });
        }
        let Some(transit) = resolved.transit.as_ref() else {
            continue;
        };
        let base_route = resolved
            .access_point
            .route
            .trim_end_matches('/');
        for point in &transit.points {
            let Some(authorization) = point
                .mcp_http
                .as_ref()
                .and_then(|http| http.authorization.as_ref())
            else {
                continue;
            };
            let Ok(derived) = authorization.for_transit_variant(base_route, point, alias) else {
                continue;
            };
            // The Transit runtime checks the point's own resource against its
            // unaliased path, then derives the variant resource from it.
            let path = point
                .listen_path
                .clone()
                .unwrap_or_else(|| {
                    format!("{}{base_route}/{}", crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX, point.alias)
                });
            let origins = listener_origins(
                point
                    .listen_address
                    .as_deref()
                    .or(transit
                        .outbound_listen_address
                        .as_deref())
                    .and_then(|address| network.map_url_to_port_for_type(address, Some("outbound"))),
            );
            declarations.push(ResourceDeclaration {
                served: authorization
                    .validate_endpoint(&origins, &path)
                    .is_ok(),
                resource: derived.resource,
            });
        }
    }
    declarations
}

/// The resource a standalone MCP Proxy declares, checked the way
/// `ResourceServerAuthContext::authenticate_proxy` checks it.
pub fn proxy_resource_declaration(
    proxy: &crate::mcp_proxies::types::McpProxy,
    network: &crate::config::NetworkConfig,
) -> Option<ResourceDeclaration> {
    let authorization = proxy
        .mcp_http
        .as_ref()?
        .authorization
        .as_ref()?;
    Some(ResourceDeclaration {
        resource: authorization.resource.clone(),
        served: authorization
            .validate_endpoint(&network.get_inbound_external_urls(), &proxy.full_path())
            .is_ok(),
    })
}

impl McpResourceServerConfig {
    pub fn for_transit_variant(
        &self,
        surface_route: &str,
        point: &crate::config::agent_surface::TransitPoint,
        alias: Option<&str>,
    ) -> Result<Self, String> {
        let mut authorization = self.for_variant(alias)?;
        if point.listen_path.is_none()
            && let Some(alias) = alias
        {
            let mut resource = canonical_https_url(&authorization.resource).map_err(|error| error.to_string())?;
            resource.set_path(&format!(
                "{}{}${alias}/{}",
                crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX,
                surface_route.trim_end_matches('/'),
                point.alias
            ));
            authorization.resource = resource.to_string();
        }
        Ok(authorization)
    }

    pub fn for_variant(
        &self,
        alias: Option<&str>,
    ) -> Result<Self, String> {
        self.validate()?;
        let Some(alias) = alias else {
            return Ok(self.clone());
        };
        if alias.is_empty()
            || alias.len() > 32
            || !alias
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("Invalid MCP resource variant alias".into());
        }
        let mut resource = canonical_https_url(&self.resource).map_err(|error| error.to_string())?;
        resource.set_path(&format!("{}${alias}", resource.path()));
        Ok(Self {
            resource: resource.to_string(),
            scopes: self.scopes.clone(),
        })
    }

    pub fn validate_endpoint(
        &self,
        public_origins: &[String],
        path: &str,
    ) -> Result<(), String> {
        self.validate()?;
        let resource = canonical_https_url(&self.resource).map_err(|error| error.to_string())?;
        if resource.path() != path
            || !public_origins
                .iter()
                .any(|origin| url::Url::parse(origin).is_ok_and(|origin| origin.origin() == resource.origin()))
        {
            return Err("MCP resource must match the configured public origin and endpoint path".into());
        }
        Ok(())
    }

    pub async fn authenticate(
        &self,
        headers: &axum::http::HeaderMap,
        profile: &McpIssuerProfile,
        issuer: &crate::identity::VCIssuer,
        keys: std::sync::Arc<crate::jwt_bearer::JwksClient>,
    ) -> Result<crate::source_auth::AuthenticatedIdentity, ResourceTokenError> {
        let jwks = issuer
            .signing_public_jwks()
            .await
            .map_err(|_| ResourceTokenError::Unavailable)?;
        self.verify_token(headers, profile, &jwks, keys)
            .await
    }

    async fn verify_token(
        &self,
        headers: &axum::http::HeaderMap,
        profile: &McpIssuerProfile,
        jwks: &Value,
        keys: std::sync::Arc<crate::jwt_bearer::JwksClient>,
    ) -> Result<crate::source_auth::AuthenticatedIdentity, ResourceTokenError> {
        let mut authorization = headers
            .get_all(header::AUTHORIZATION)
            .iter();
        let first = authorization
            .next()
            .ok_or(ResourceTokenError::Missing)?;
        if authorization.next().is_some() {
            return Err(ResourceTokenError::Invalid);
        }
        let authorization = first
            .to_str()
            .map_err(|_| ResourceTokenError::Invalid)?;
        let (scheme, token) = authorization
            .split_once(' ')
            .ok_or(ResourceTokenError::Invalid)?;
        if !scheme.eq_ignore_ascii_case("Bearer")
            || token.is_empty()
            || token.len() > 16 * 1024
            || token
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ResourceTokenError::Invalid);
        }
        let jose = jsonwebtoken::decode_header(token).map_err(|_| ResourceTokenError::Invalid)?;
        if jose.typ.as_deref() != Some("at+jwt") || jose.alg != jsonwebtoken::Algorithm::EdDSA {
            return Err(ResourceTokenError::Invalid);
        }
        let strategy = crate::sts::handlers::gateway_self_trust_strategy(&profile.issuer, jwks)
            .map_err(|_| ResourceTokenError::Unavailable)?;
        let claims = crate::jwt_bearer::JwtBearerVerifier::new(keys)
            .validate(token, &strategy, std::slice::from_ref(&self.resource))
            .await
            .map_err(|_| ResourceTokenError::Invalid)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ResourceTokenError::Unavailable)?
            .as_secs();
        self.validate_verified_claims(profile, &claims, now)?;
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .ok_or(ResourceTokenError::Invalid)?
            .to_string();
        Ok(crate::source_auth::AuthenticatedIdentity::JwtBearer { subject, claims })
    }

    pub fn validate(&self) -> Result<(), String> {
        canonical_https_url(&self.resource).map_err(|error| error.to_string())?;
        if self.scopes.len() > 128
            || self
                .scopes
                .iter()
                .any(|scope| {
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

    pub fn metadata_url(&self) -> Result<url::Url, String> {
        self.validate()?;
        let mut resource = canonical_https_url(&self.resource).map_err(|error| error.to_string())?;
        let suffix = if resource.path() == "/" {
            ""
        } else {
            resource.path()
        };
        let path = format!("/.well-known/oauth-protected-resource{suffix}");
        resource.set_path(&path);
        Ok(resource)
    }

    pub fn metadata(
        &self,
        profile: &McpIssuerProfile,
    ) -> Result<Value, String> {
        self.validate()?;
        profile
            .validate()
            .map_err(|error| error.to_string())?;
        Ok(self.metadata_document(std::slice::from_ref(&profile.issuer)))
    }

    fn metadata_document(
        &self,
        authorization_servers: &[String],
    ) -> Value {
        let mut metadata = json!({
            "resource": self.resource,
            "authorization_servers": authorization_servers,
            "bearer_methods_supported": ["header"]
        });
        if !self.scopes.is_empty() {
            metadata["scopes_supported"] = json!(self.scopes);
        }
        metadata
    }

    pub fn validate_verified_claims(
        &self,
        profile: &McpIssuerProfile,
        claims: &Value,
        now: u64,
    ) -> Result<(), ResourceTokenError> {
        self.validate()
            .map_err(|_| ResourceTokenError::Unavailable)?;
        profile
            .validate()
            .map_err(|_| ResourceTokenError::Unavailable)?;
        if claims
            .get("iss")
            .and_then(Value::as_str)
            != Some(profile.issuer.as_str())
            || profile
                .validate_subject(claims, now)
                .is_err()
            || !claims
                .get("aud")
                .is_some_and(|audience| match audience {
                    Value::String(audience) => audience == &self.resource,
                    Value::Array(audiences) => {
                        !audiences.is_empty()
                            && audiences
                                .iter()
                                .all(|audience| {
                                    audience
                                        .as_str()
                                        .is_some_and(|value| !value.is_empty())
                                })
                            && audiences
                                .iter()
                                .any(|audience| audience.as_str() == Some(self.resource.as_str()))
                    }
                    _ => false,
                })
        {
            return Err(ResourceTokenError::Invalid);
        }
        let scopes = match claims.get("scope") {
            None => "",
            Some(Value::String(scopes)) => scopes.as_str(),
            _ => return Err(ResourceTokenError::Invalid),
        };
        if self
            .scopes
            .iter()
            .any(|required| {
                !scopes
                    .split(' ')
                    .any(|granted| granted == required)
            })
        {
            return Err(ResourceTokenError::InsufficientScope);
        }
        Ok(())
    }

    pub fn challenge(
        &self,
        error: ResourceTokenError,
    ) -> Response {
        let Ok(metadata) = self.metadata_url() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let mut response = error
            .status_code()
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if error == ResourceTokenError::Unavailable {
            return response;
        }
        let mut challenge = format!("Bearer resource_metadata=\"{metadata}\"");
        match error {
            ResourceTokenError::Invalid => challenge.push_str(", error=\"invalid_token\""),
            ResourceTokenError::InsufficientScope => challenge.push_str(", error=\"insufficient_scope\""),
            _ => {}
        }
        if !self.scopes.is_empty() {
            challenge.push_str(&format!(", scope=\"{}\"", self.scopes.join(" ")));
        }
        let Ok(challenge) = HeaderValue::from_str(&challenge) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declaration_counts_as_served_only_on_its_own_origin_and_path() {
        let network: crate::config::NetworkConfig = serde_json::from_value(json!({
            "did": {"domain": "gateway.example"},
            "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []},
            "listeners": [
                {"id": "in", "name": "in", "bind_address": "0.0.0.0", "port": 8443, "protocol": "https",
                    "external_urls": ["https://gateway.example"]},
                {"id": "out", "name": "out", "bind_address": "0.0.0.0", "port": 8444, "protocol": "https",
                    "external_urls": ["https://outbound.example"], "listener_type": "outbound"}
            ],
            "routes": {}
        }))
        .unwrap();
        let point = |alias: &str, resource: &str| {
            json!({"alias": alias, "protocol": "mcp", "target_endpoint": "https://tools.example/mcp",
                "mcp_http": {"authorization": {"resource": resource, "scopes": []}}})
        };
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "s", "name": "s",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://tools.example/mcp"},
            "mcp_http": {"authorization": {"resource": "https://gateway.example/mcp", "scopes": []}},
            "variants": [{"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {}}],
            "transit": {"outbound_listen_address": "https://outbound.example", "points": [
                point("partner", "https://outbound.example/outbound/mcp/partner"),
                // Another endpoint's path, and an origin no listener has.
                point("squat", "https://outbound.example/other"),
                point("elsewhere", "https://elsewhere.example/outbound/mcp/elsewhere"),
            ]}
        }))
        .unwrap();
        let served = |resource: &str| ResourceDeclaration {
            resource: resource.into(),
            served: true,
        };
        let refused = |resource: &str| ResourceDeclaration {
            resource: resource.into(),
            served: false,
        };
        assert_eq!(
            surface_resource_declarations(&surface, &network),
            vec![
                served("https://gateway.example/mcp"),
                served("https://outbound.example/outbound/mcp/partner"),
                refused("https://outbound.example/other"),
                refused("https://elsewhere.example/outbound/mcp/elsewhere"),
                served("https://gateway.example/mcp$beta"),
                served("https://outbound.example/outbound/mcp$beta/partner"),
                refused("https://outbound.example/outbound/mcp$beta/squat"),
                refused("https://elsewhere.example/outbound/mcp$beta/elsewhere"),
            ]
        );

        let mut surface = surface;
        surface.access_point.route = "/moved".into();
        assert!(
            !surface_resource_declarations(&surface, &network)[0].served,
            "the resource no longer matches the route"
        );

        let mut proxy = crate::mcp_proxies::types::McpProxy::new(
            "api".into(),
            String::new(),
            "https://api.example".into(),
            "openapi: 3.0.0".into(),
            "/mcp".into(),
            "/api".into(),
        );
        assert_eq!(proxy_resource_declaration(&proxy, &network), None);
        proxy.mcp_http = serde_json::from_value(
            json!({"authorization": {"resource": "https://gateway.example/mcp/api", "scopes": []}}),
        )
        .unwrap();
        assert_eq!(proxy_resource_declaration(&proxy, &network), Some(served("https://gateway.example/mcp/api")));
        proxy.endpoint_path = "/moved".into();
        assert_eq!(proxy_resource_declaration(&proxy, &network), Some(refused("https://gateway.example/mcp/api")));
    }

    #[tokio::test]
    async fn resource_tokens_require_valid_signatures_explicit_type_and_one_bearer() {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwks = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "key-1", "x": encoding.encode(signing.verifying_key().as_bytes())}]});
        let keys = std::sync::Arc::new(crate::jwt_bearer::JwksClient::new());
        let config = McpResourceServerConfig {
            resource: "https://gateway.example/mcp/".into(),
            scopes: vec!["read".into()],
        };
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/oauth2/mcp".into(),
        };
        assert_eq!(
            config
                .metadata_url()
                .unwrap()
                .path(),
            "/.well-known/oauth-protected-resource/mcp/"
        );
        let claims = json!({"iss": profile.issuer, "sub": "user", "aud": config.resource, "exp": chrono::Utc::now().timestamp() + 60, "scope": "read"});
        let sign = |typ| {
            let header =
                encoding.encode(serde_json::to_vec(&json!({"alg": "EdDSA", "typ": typ, "kid": "key-1"})).unwrap());
            let payload = encoding.encode(serde_json::to_vec(&claims).unwrap());
            let content = format!("{header}.{payload}");
            let signature = encoding.encode(
                signing
                    .sign(content.as_bytes())
                    .to_bytes(),
            );
            format!("{content}.{signature}")
        };
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(
            config
                .verify_token(&headers, &profile, &jwks, keys.clone())
                .await,
            Err(ResourceTokenError::Missing)
        );
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", sign("at+jwt"))).unwrap());
        let identity = config
            .verify_token(&headers, &profile, &jwks, keys.clone())
            .await
            .unwrap();
        assert_eq!(identity.jwt_claims().unwrap()["sub"], "user");
        headers.append(header::AUTHORIZATION, HeaderValue::from_static("Bearer second"));
        assert_eq!(
            config
                .verify_token(&headers, &profile, &jwks, keys.clone())
                .await,
            Err(ResourceTokenError::Invalid)
        );
        for token in [
            sign("oauth-id-jag+jwt"),
            sign("JWT"),
            format!(
                "{}.bad",
                sign("at+jwt")
                    .rsplit_once('.')
                    .unwrap()
                    .0
            ),
        ] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
            assert_eq!(
                config
                    .verify_token(&headers, &profile, &jwks, keys.clone())
                    .await,
                Err(ResourceTokenError::Invalid)
            );
        }
    }

    #[test]
    fn protected_resource_metadata_and_challenges_use_only_canonical_configuration() {
        let config = McpResourceServerConfig {
            resource: "https://gateway.example/surfaces/alpha".into(),
            scopes: vec!["read".into(), "write".into()],
        };
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        assert!(
            config
                .validate_endpoint(&["https://gateway.example".into()], "/surfaces/alpha")
                .is_ok()
        );
        assert!(
            config
                .validate_endpoint(&["https://other.example".into()], "/surfaces/alpha")
                .is_err()
        );
        assert!(
            config
                .validate_endpoint(&["https://gateway.example".into()], "/surfaces/beta")
                .is_err()
        );
        assert_eq!(
            config
                .for_variant(Some("review"))
                .unwrap()
                .resource,
            "https://gateway.example/surfaces/alpha$review"
        );
        assert_eq!(
            config
                .metadata_url()
                .unwrap()
                .as_str(),
            "https://gateway.example/.well-known/oauth-protected-resource/surfaces/alpha"
        );
        let metadata = config
            .metadata(&profile)
            .unwrap();
        assert_eq!(metadata["resource"], config.resource);
        assert_eq!(metadata["authorization_servers"], json!([profile.issuer]));
        assert_eq!(metadata["bearer_methods_supported"], json!(["header"]));
        let missing = config.challenge(ResourceTokenError::Missing);
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !missing.headers()[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("invalid_token")
        );
        let forbidden = config.challenge(ResourceTokenError::InsufficientScope);
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
        assert!(
            forbidden.headers()[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("scope=\"read write\"")
        );
        let unavailable = config.challenge(ResourceTokenError::Unavailable);
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !unavailable
                .headers()
                .contains_key(header::WWW_AUTHENTICATE)
        );
    }

    #[test]
    fn transit_resource_variants_use_the_registered_endpoint_path() {
        let mut point: crate::config::agent_surface::TransitPoint = serde_json::from_value(json!({
            "alias": "partner-a", "protocol": "mcp", "target_endpoint": "https://target.example/mcp"
        }))
        .unwrap();
        for (path, custom, expected) in [
            ("/outbound/mcp/partner-a", None, "/outbound/mcp$review/partner-a"),
            ("/custom/mcp", Some("/custom/mcp"), "/custom/mcp$review"),
        ] {
            point.listen_path = custom.map(str::to_string);
            let config = McpResourceServerConfig {
                resource: format!("https://outbound.example{path}"),
                scopes: vec!["read".into()],
            };
            assert_eq!(
                config
                    .for_transit_variant("/mcp/", &point, None)
                    .unwrap(),
                config
            );
            let variant = config
                .for_transit_variant("/mcp/", &point, Some("review"))
                .unwrap();
            assert_eq!(variant.resource, format!("https://outbound.example{expected}"));
            assert_eq!(variant.scopes, config.scopes);
            assert_eq!(
                variant
                    .metadata_url()
                    .unwrap()
                    .path(),
                format!("/.well-known/oauth-protected-resource{expected}")
            );
            for invalid in ["", "other/path", "review$other", "UPPERCASE"] {
                assert!(
                    config
                        .for_transit_variant("/mcp/", &point, Some(invalid))
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn resource_gate_rejects_wrong_issuer_audience_expiry_and_scope() {
        let config = McpResourceServerConfig {
            resource: "https://gateway.example/surfaces/alpha".into(),
            scopes: vec!["read".into()],
        };
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        let claims =
            json!({"iss": profile.issuer, "sub": "user", "aud": config.resource, "exp": 100, "scope": "read write"});
        assert_eq!(config.validate_verified_claims(&profile, &claims, 10), Ok(()));
        for (field, value) in [
            ("iss", json!("https://other.example/oauth2/mcp")),
            ("aud", json!("https://other.example/mcp")),
            ("exp", json!(10)),
            ("sub", json!("")),
            ("nbf", json!(11)),
        ] {
            let mut changed = claims.clone();
            changed[field] = value;
            assert_eq!(
                config.validate_verified_claims(&profile, &changed, 10),
                Err(ResourceTokenError::Invalid),
                "{field}"
            );
        }
        let mut changed = claims;
        changed["scope"] = json!("write");
        assert_eq!(config.validate_verified_claims(&profile, &changed, 10), Err(ResourceTokenError::InsufficientScope));
    }

    const ISSUER: &str = "https://idp.example/realms/agents";

    fn protected_resource(resource: &str) -> ProtectedResourceConfig {
        ProtectedResourceConfig {
            resource: resource.into(),
            authorization_servers: vec![ISSUER.into()],
            scopes: vec!["tools".into()],
        }
    }

    fn discovery_network() -> crate::config::NetworkConfig {
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

    fn jwt_bearer_method() -> Value {
        json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []})
    }

    fn discovery_surface(
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
                .resource_server()
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

    #[test]
    fn a_protected_resource_is_declared_like_the_access_point_resource() {
        let network = discovery_network();
        let served = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/mcp/alpha", "authorization_servers": [ISSUER]})),
        );
        assert_eq!(
            surface_resource_declarations(&served, &network),
            vec![
                ResourceDeclaration {
                    resource: "https://gateway.example/mcp/alpha".into(),
                    served: true
                },
                ResourceDeclaration {
                    resource: "https://gateway.example/mcp/alpha$beta".into(),
                    served: true
                },
            ]
        );
        let elsewhere = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://other.example/mcp/alpha", "authorization_servers": [ISSUER]})),
        );
        assert!(
            surface_resource_declarations(&elsewhere, &network)
                .iter()
                .all(|declaration| !declaration.served)
        );
    }
}
