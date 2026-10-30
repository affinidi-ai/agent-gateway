use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocols::protected_resource::{self, ResourceTokenError};
use crate::sts::mcp_profile::{McpIssuerProfile, canonical_https_url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpResourceServerConfig {
    pub resource: String,
    #[serde(default)]
    pub scopes: Vec<String>,
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
        .strip_prefix(crate::proxy::paths::PROTECTED_RESOURCE_METADATA_PATH)
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

/// What the endpoints of one inbound listener answer at a protected resource
/// metadata path.
#[derive(Debug, PartialEq)]
pub(crate) enum MetadataMatch {
    None,
    Metadata(Value),
    Unavailable,
}

impl MetadataMatch {
    /// The answer for a path two endpoints may claim: one claim stands, two
    /// leave the path unavailable.
    fn and(
        self,
        other: Self,
    ) -> Self {
        match (self, other) {
            (Self::None, found) | (found, Self::None) => found,
            _ => Self::Unavailable,
        }
    }
}

/// RFC 9728 metadata a listener's endpoints publish at `requested_path`, the
/// resource path a metadata path names, read from live configuration on every
/// request.
pub(crate) async fn served_metadata(
    state: &crate::state::MultiSurfaceProxyState,
    requested_path: &str,
) -> MetadataMatch {
    let profile = state
        .network_config
        .sts
        .mcp_issuer
        .as_ref();
    let strategies = state
        .source_auth_middleware
        .as_ref()
        .map(|middleware| middleware.provider_store());
    let surfaces = state
        .channels
        .read()
        .await
        .iter()
        .map(|channel| channel.surface.clone())
        .collect::<Vec<_>>();
    let proxies = match (profile, state.mcp_proxy_store.as_ref()) {
        (Some(_), Some(store)) => {
            use crate::mcp_proxies::McpProxyStore;
            let Ok(proxies) = store.list_all().await else {
                return MetadataMatch::Unavailable;
            };
            proxies
        }
        _ => Vec::new(),
    };
    listener_metadata(&surfaces, &proxies, requested_path, profile, strategies.as_deref(), &state.network_config).await
}

/// The one document served at `requested_path` among the surfaces and, when the
/// gateway STS issuer is set, the standalone MCP Proxies. A path more than one
/// endpoint claims is unavailable.
pub(crate) async fn listener_metadata(
    surfaces: &[std::sync::Arc<crate::config::agent_surface::AgentSurface>],
    proxies: &[crate::mcp_proxies::types::McpProxy],
    requested_path: &str,
    profile: Option<&McpIssuerProfile>,
    strategies: Option<&dyn crate::jwt_bearer::JwtVerificationStrategyStorage>,
    network: &crate::config::NetworkConfig,
) -> MetadataMatch {
    let found = surfaces_metadata(surfaces, requested_path, profile, strategies, network).await;
    match profile {
        Some(profile) => found.and(proxies_metadata(proxies, requested_path, profile, network)),
        None => found,
    }
}

/// The one standalone MCP Proxy document served at `requested_path`, naming the
/// gateway's STS issuer. A proxy path holding the Surface Variant separator is
/// never published, so it cannot answer for a surface's variant URL.
fn proxies_metadata(
    proxies: &[crate::mcp_proxies::types::McpProxy],
    requested_path: &str,
    profile: &McpIssuerProfile,
    network: &crate::config::NetworkConfig,
) -> MetadataMatch {
    let mut result = MetadataMatch::None;
    for proxy in proxies {
        let path = proxy.full_path();
        if proxy.status != crate::mcp_proxies::types::McpProxyStatus::Active
            || path != requested_path
            || crate::proxy::paths::route_holds_variant_separator(&path)
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
        let found = match authorization
            .validate_endpoint(&network.get_inbound_external_urls(), requested_path)
            .and_then(|()| authorization.metadata(profile))
        {
            Ok(metadata) => MetadataMatch::Metadata(metadata),
            Err(_) => MetadataMatch::Unavailable,
        };
        result = result.and(found);
    }
    result
}

/// The one surface document served at `requested_path`; a path more than one
/// surface claims is unavailable, whatever their protocols. A route holding the
/// Surface Variant separator is never published, so it cannot answer for
/// another surface's variant URL.
async fn surfaces_metadata(
    surfaces: &[std::sync::Arc<crate::config::agent_surface::AgentSurface>],
    requested_path: &str,
    profile: Option<&McpIssuerProfile>,
    strategies: Option<&dyn crate::jwt_bearer::JwtVerificationStrategyStorage>,
    network: &crate::config::NetworkConfig,
) -> MetadataMatch {
    let mut result = MetadataMatch::None;
    for surface in surfaces {
        if surface.status != crate::config::agent_surface::SurfaceStatus::Active
            || crate::proxy::paths::route_holds_variant_separator(&surface.access_point.route)
        {
            continue;
        }
        let mcp_authorization = surface.access_point.protocol == crate::config::agent_surface::SurfaceProtocol::Mcp
            && surface
                .mcp_http
                .as_ref()
                .is_some_and(|http| http.authorization.is_some());
        let found = match (mcp_authorization, profile) {
            (true, Some(profile)) => mcp_surface_metadata(surface, requested_path, profile, network),
            (true, None) => MetadataMatch::None,
            (false, _) => declared_surface_metadata(surface, requested_path, strategies, network).await,
        };
        result = result.and(found);
        if result == MetadataMatch::Unavailable {
            return result;
        }
    }
    result
}

/// The document an Access Point whose declaration resolves to declare
/// publishes at its own path, for the base route or an enabled Surface
/// Variant's `$alias`. Only an Access Point that sets `protected_resource`
/// claims a path, and only the path of the resource it names, so one without
/// the setting never reads the strategy store. A strategy store failure while
/// resolving leaves the path unavailable.
async fn declared_surface_metadata(
    surface: &crate::config::agent_surface::AgentSurface,
    requested_path: &str,
    strategies: Option<&dyn crate::jwt_bearer::JwtVerificationStrategyStorage>,
    network: &crate::config::NetworkConfig,
) -> MetadataMatch {
    use crate::source_auth::declaration::{DeclarationOutcome, resolve_surface_declaration};

    let route = match surface
        .access_point
        .route
        .as_str()
    {
        "" => "/",
        route => route,
    };
    let alias = match requested_path.strip_prefix(route) {
        Some("") => None,
        Some(rest) => match rest.strip_prefix('$') {
            Some(alias) => Some(alias),
            None => return MetadataMatch::None,
        },
        None => return MetadataMatch::None,
    };
    if let Some(alias) = alias
        && !surface
            .variants
            .iter()
            .any(|variant| variant.enabled && variant.alias == alias)
    {
        return MetadataMatch::None;
    }
    let Ok(resolved) = surface.resolve_variant(alias) else {
        return MetadataMatch::None;
    };
    let Some(configured) = resolved.protected_resource() else {
        return MetadataMatch::None;
    };
    let claims_path = configured
        .for_variant(alias)
        .ok()
        .and_then(|served| url::Url::parse(&served.resource).ok())
        .is_some_and(|resource| resource.path() == requested_path);
    if !claims_path {
        return MetadataMatch::None;
    }
    match resolve_surface_declaration(&resolved, alias, strategies, network).await {
        Ok(DeclarationOutcome::Declare(declaration)) => MetadataMatch::Metadata(declaration.metadata()),
        Ok(DeclarationOutcome::Unservable(_)) => MetadataMatch::Unavailable,
        Ok(DeclarationOutcome::Strip(_) | DeclarationOutcome::PassThrough) => MetadataMatch::None,
        Err(error) => {
            tracing::warn!(
                surface_id = %surface.surface_id,
                error = %error,
                "Strategy lookup failed while serving protected resource metadata"
            );
            MetadataMatch::Unavailable
        }
    }
}

/// The document an MCP surface with `mcp_http.authorization` publishes, naming
/// the gateway's STS issuer.
fn mcp_surface_metadata(
    surface: &crate::config::agent_surface::AgentSurface,
    requested_path: &str,
    profile: &McpIssuerProfile,
    network: &crate::config::NetworkConfig,
) -> MetadataMatch {
    let Some(authorization) = surface
        .mcp_http
        .as_ref()
        .and_then(|http| http.authorization.as_ref())
    else {
        return MetadataMatch::None;
    };
    let Ok(resource) = canonical_https_url(&authorization.resource) else {
        return MetadataMatch::None;
    };
    let prefix = if resource.path() == "/" {
        ""
    } else {
        resource.path()
    };
    let Some(parsed) = crate::proxy::route_variant::parse_route_with_variant(requested_path, prefix) else {
        return MetadataMatch::None;
    };
    let exact_resource = parsed.tail.is_empty() || (resource.path() == "/" && parsed.tail == "/");
    if !exact_resource {
        return MetadataMatch::None;
    }
    if let Some(alias) = parsed.alias {
        if !surface
            .variants
            .iter()
            .any(|variant| variant.alias == alias && variant.enabled)
        {
            return MetadataMatch::None;
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
        return MetadataMatch::None;
    }
    let Ok(resolved) = surface.resolve_variant(parsed.alias) else {
        return MetadataMatch::None;
    };
    let Some(authorization) = resolved
        .mcp_http
        .as_ref()
        .and_then(|http| http.authorization.as_ref())
    else {
        return MetadataMatch::None;
    };
    let Ok(authorization) = authorization.for_variant(parsed.alias) else {
        return MetadataMatch::Unavailable;
    };
    let origins = network
        .map_url_to_port(
            &resolved
                .access_point
                .listen_address,
        )
        .and_then(|port| network.get_listener_by_port(port))
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
            .validate_network(network)
            .is_err()
    {
        return MetadataMatch::Unavailable;
    }
    match authorization.metadata(profile) {
        Ok(metadata) => MetadataMatch::Metadata(metadata),
        Err(_) => MetadataMatch::Unavailable,
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
                served: matches!(
                    protected_resource::access_point_protected_resource(&resolved, alias, network),
                    Some(Ok(_))
                ),
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
        Ok(Self {
            resource: protected_resource::variant_resource(&self.resource, alias)?,
            scopes: self.scopes.clone(),
        })
    }

    pub fn validate_endpoint(
        &self,
        public_origins: &[String],
        path: &str,
    ) -> Result<(), String> {
        self.validate()?;
        protected_resource::validate_endpoint(&self.resource, public_origins, path)
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
        Ok(crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject,
            claims,
            strategy: None,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        protected_resource::validate_resource(&self.resource, &self.scopes)
    }

    pub fn metadata_url(&self) -> Result<url::Url, String> {
        self.validate()?;
        protected_resource::metadata_url(&self.resource)
    }

    pub fn metadata(
        &self,
        profile: &McpIssuerProfile,
    ) -> Result<Value, String> {
        self.validate()?;
        profile
            .validate()
            .map_err(|error| error.to_string())?;
        Ok(protected_resource::metadata_document(&self.resource, std::slice::from_ref(&profile.issuer), &self.scopes))
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
        let Some(challenge) = protected_resource::challenge_header(&metadata, error, &self.scopes) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        protected_resource::mark_gateway_challenge(&mut response, challenge);
        response
    }
}

#[cfg(test)]
mod listener_metadata_tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::config::agent_surface::AgentSurface;
    use crate::protocols::protected_resource::fixtures::{
        FixtureStrategies, ISSUER, discovery_network, discovery_surface, jwt_bearer_method,
    };

    const STS_ISSUER: &str = "https://gateway.example/api/oauth2/mcp";

    fn network() -> crate::config::NetworkConfig {
        let mut network = discovery_network();
        network.routes =
            serde_json::from_value(json!({"identity": {"type": "identity_api", "prefix": "/api"}})).unwrap();
        network
    }

    fn sts() -> McpIssuerProfile {
        McpIssuerProfile { issuer: STS_ISSUER.into() }
    }

    /// An MCP Access Point at `route` whose caller authentication publishes
    /// the resource of its route.
    fn explicit(route: &str) -> Arc<AgentSurface> {
        let mut surface = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": format!("https://gateway.example{route}")})),
        );
        surface.access_point.route = route.into();
        Arc::new(surface)
    }

    /// An MCP surface at `route` whose resource the gateway STS issues tokens for.
    fn sts_resource(route: &str) -> Arc<AgentSurface> {
        Arc::new(
            serde_json::from_value(json!({
                "surface_id": "sts", "name": "sts",
                "access_point": {"listen_address": "https://gateway.example", "route": route, "protocol": "mcp"},
                "target": {"endpoint": "https://tools.example/mcp"},
                "mcp_http": {"authorization": {"resource": format!("https://gateway.example{route}"), "scopes": []}},
                "variants": [{"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {}}]
            }))
            .unwrap(),
        )
    }

    fn declaring_proxy(path: &str) -> crate::mcp_proxies::types::McpProxy {
        let mut proxy = crate::mcp_proxies::types::McpProxy::new(
            "proxy".into(),
            String::new(),
            "https://api.example".into(),
            String::new(),
            String::new(),
            path.into(),
        );
        proxy.mcp_http = serde_json::from_value(
            json!({"authorization": {"resource": format!("https://gateway.example{path}"), "scopes": []}}),
        )
        .unwrap();
        proxy
    }

    const SCOPE: &str = "agent.invoke";

    /// An Access Point at `route` whose one JWT Bearer method requires a scope
    /// and whose `protected_resource` names the route.
    fn declaring(
        protocol: crate::config::agent_surface::SurfaceProtocol,
        route: &str,
        method: impl FnOnce(&mut serde_json::Value),
    ) -> Arc<AgentSurface> {
        let base = match route {
            "/" => "https://gateway.example/".to_string(),
            route => format!("https://gateway.example{route}"),
        };
        let mut jwt_bearer = jwt_bearer_method();
        jwt_bearer["required_scopes"] = json!([SCOPE]);
        method(&mut jwt_bearer);
        let mut surface = discovery_surface(jwt_bearer, Some(json!({"resource": base})));
        surface.access_point.route = route.into();
        surface.access_point.protocol = protocol;
        Arc::new(surface)
    }

    fn declaring_a2a(route: &str) -> Arc<AgentSurface> {
        declaring(crate::config::agent_surface::SurfaceProtocol::A2a, route, |_| ())
    }

    fn declared_document(resource: &str) -> MetadataMatch {
        MetadataMatch::Metadata(json!({
            "resource": resource,
            "authorization_servers": [ISSUER],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SCOPE]
        }))
    }

    async fn served_from(
        surfaces: &[Arc<AgentSurface>],
        proxies: &[crate::mcp_proxies::types::McpProxy],
        path: &str,
        profile: Option<&McpIssuerProfile>,
        strategies: &FixtureStrategies,
    ) -> MetadataMatch {
        listener_metadata(surfaces, proxies, path, profile, Some(strategies), &network()).await
    }

    async fn served(
        surfaces: &[Arc<AgentSurface>],
        proxies: &[crate::mcp_proxies::types::McpProxy],
        path: &str,
        profile: Option<&McpIssuerProfile>,
    ) -> MetadataMatch {
        served_from(surfaces, proxies, path, profile, &FixtureStrategies::Pinned).await
    }

    fn explicit_document(resource: &str) -> MetadataMatch {
        MetadataMatch::Metadata(json!({
            "resource": resource,
            "authorization_servers": [ISSUER],
            "bearer_methods_supported": ["header"]
        }))
    }

    fn sts_document(resource: &str) -> MetadataMatch {
        MetadataMatch::Metadata(json!({
            "resource": resource,
            "authorization_servers": [STS_ISSUER],
            "bearer_methods_supported": ["header"]
        }))
    }

    #[tokio::test]
    async fn an_explicit_access_point_publishes_its_strategy_issuer_with_or_without_the_sts_issuer() {
        let surfaces = [explicit("/smoke")];
        for profile in [None, Some(&sts())] {
            assert_eq!(
                served(&surfaces, &[], "/smoke", profile).await,
                explicit_document("https://gateway.example/smoke")
            );
            assert_eq!(
                served(&surfaces, &[], "/smoke$beta", profile).await,
                explicit_document("https://gateway.example/smoke$beta")
            );
            for path in ["/", "/smoke/tools", "/smok", "/smoke$off", "/other"] {
                assert_eq!(served(&surfaces, &[], path, profile).await, MetadataMatch::None, "{path}");
            }
        }
    }

    #[tokio::test]
    async fn a_stored_authorization_servers_list_is_never_published() {
        let mut surface = discovery_surface(
            jwt_bearer_method(),
            Some(
                json!({"resource": "https://gateway.example/smoke", "authorization_servers": ["https://old.example"]}),
            ),
        );
        surface.access_point.route = "/smoke".into();
        assert_eq!(
            served(&[Arc::new(surface)], &[], "/smoke", None).await,
            explicit_document("https://gateway.example/smoke")
        );
    }

    #[tokio::test]
    async fn an_mcp_resource_server_keeps_the_sts_issuer_and_needs_it() {
        let surfaces = [sts_resource("/smoke")];
        assert_eq!(served(&surfaces, &[], "/smoke", Some(&sts())).await, sts_document("https://gateway.example/smoke"));
        assert_eq!(
            served(&surfaces, &[], "/smoke$beta", Some(&sts())).await,
            sts_document("https://gateway.example/smoke$beta")
        );
        assert_eq!(served(&surfaces, &[], "/smoke", None).await, MetadataMatch::None);
    }

    #[tokio::test]
    async fn a_route_holding_the_variant_separator_cannot_claim_another_surfaces_variant() {
        let claimant = explicit("/smoke$beta");
        assert_eq!(served(std::slice::from_ref(&claimant), &[], "/smoke$beta", None).await, MetadataMatch::None);
        assert_eq!(
            served(&[explicit("/smoke"), claimant], &[], "/smoke$beta", None).await,
            explicit_document("https://gateway.example/smoke$beta")
        );
    }

    #[tokio::test]
    async fn a_path_two_surfaces_claim_is_unavailable_whatever_their_settings() {
        for pair in [[explicit("/smoke"), sts_resource("/smoke")], [explicit("/smoke"), explicit("/smoke")]] {
            assert_eq!(served(&pair, &[], "/smoke", Some(&sts())).await, MetadataMatch::Unavailable);
        }
        assert_eq!(
            served(&[explicit("/smoke"), explicit("/other")], &[], "/smoke", None).await,
            explicit_document("https://gateway.example/smoke")
        );
    }

    #[tokio::test]
    async fn a_declaring_mcp_proxy_names_the_sts_issuer_and_needs_it() {
        let proxies = [declaring_proxy("/tools")];
        assert_eq!(served(&[], &proxies, "/tools", Some(&sts())).await, sts_document("https://gateway.example/tools"));
        assert_eq!(served(&[], &proxies, "/tools", None).await, MetadataMatch::None);
        assert_eq!(served(&[], &proxies, "/other", Some(&sts())).await, MetadataMatch::None);
        let mut disabled = declaring_proxy("/tools");
        disabled.status = crate::mcp_proxies::types::McpProxyStatus::Disabled;
        assert_eq!(served(&[], &[disabled], "/tools", Some(&sts())).await, MetadataMatch::None);
        let mut unserved = declaring_proxy("/tools");
        unserved.endpoint_path = "/moved".into();
        assert_eq!(served(&[], &[unserved], "/moved", Some(&sts())).await, MetadataMatch::Unavailable);
    }

    #[tokio::test]
    async fn a_proxy_path_holding_the_variant_separator_cannot_take_over_a_surface_variant() {
        let squatter = [declaring_proxy("/smoke$beta")];
        assert_eq!(served(&[], &squatter, "/smoke$beta", Some(&sts())).await, MetadataMatch::None);
        assert_eq!(
            served(&[explicit("/smoke")], &squatter, "/smoke$beta", Some(&sts())).await,
            explicit_document("https://gateway.example/smoke$beta")
        );
    }

    #[tokio::test]
    async fn a_path_an_access_point_shares_with_a_declaring_proxy_is_unavailable() {
        let surfaces = [explicit("/smoke")];
        let proxies = [declaring_proxy("/smoke")];
        assert_eq!(served(&surfaces, &proxies, "/smoke", Some(&sts())).await, MetadataMatch::Unavailable);
        assert_eq!(
            served(&surfaces, &proxies, "/smoke", None).await,
            explicit_document("https://gateway.example/smoke"),
            "without the STS issuer no MCP Proxy publishes"
        );
    }

    #[tokio::test]
    async fn a_declaring_mcp_or_a2a_access_point_publishes_the_strategy_issuer_at_each_enabled_path() {
        let mcp = declaring(crate::config::agent_surface::SurfaceProtocol::Mcp, "/smoke", |_| ());
        for surfaces in [[declaring_a2a("/smoke")], [mcp]] {
            for profile in [None, Some(&sts())] {
                assert_eq!(
                    served(&surfaces, &[], "/smoke", profile).await,
                    declared_document("https://gateway.example/smoke")
                );
                assert_eq!(
                    served(&surfaces, &[], "/smoke$beta", profile).await,
                    declared_document("https://gateway.example/smoke$beta")
                );
                for path in ["/", "/smoke/rpc", "/smok", "/smoke$off", "/smoke$unknown", "/other"] {
                    assert_eq!(served(&surfaces, &[], path, profile).await, MetadataMatch::None, "{path}");
                }
            }
        }
    }

    #[tokio::test]
    async fn a_variant_of_a_root_access_point_has_no_metadata_of_its_own() {
        let surfaces = [declaring_a2a("/")];
        assert_eq!(served(&surfaces, &[], "/", None).await, declared_document("https://gateway.example/"));
        assert_eq!(served(&surfaces, &[], "/$beta", None).await, MetadataMatch::Unavailable);
    }

    #[tokio::test]
    async fn an_access_point_whose_declaration_strips_or_passes_through_is_not_published() {
        let mut scoped = jwt_bearer_method();
        scoped["required_scopes"] = json!([SCOPE]);
        let mut without_setting = discovery_surface(scoped, None);
        without_setting
            .access_point
            .route = "/smoke".into();
        let mut without_caller_authentication = without_setting.clone();
        without_caller_authentication
            .access_point
            .caller_authentication = None;
        for surface in [without_setting, without_caller_authentication] {
            assert_eq!(
                served(std::slice::from_ref(&Arc::new(surface.clone())), &[], "/smoke", None).await,
                MetadataMatch::None
            );
            assert_eq!(served(&[Arc::new(surface)], &[], "/smoke$beta", None).await, MetadataMatch::None);
        }
        let mut disabled = (*declaring_a2a("/smoke")).clone();
        disabled.status = crate::config::agent_surface::SurfaceStatus::Disabled;
        assert_eq!(served(&[Arc::new(disabled)], &[], "/smoke", None).await, MetadataMatch::None);
        let forwards = declaring(crate::config::agent_surface::SurfaceProtocol::A2a, "/smoke", |method| {
            method["forward_header"] = json!(true);
        });
        assert_eq!(served(&[forwards], &[], "/smoke", None).await, MetadataMatch::Unavailable);
    }

    #[tokio::test]
    async fn a_strategy_store_failure_leaves_a_declaring_candidate_unavailable() {
        let surfaces = [declaring_a2a("/smoke")];
        for path in ["/smoke", "/smoke$beta"] {
            assert_eq!(
                served_from(&surfaces, &[], path, None, &FixtureStrategies::Failing).await,
                MetadataMatch::Unavailable,
                "{path}"
            );
        }
        assert_eq!(served_from(&surfaces, &[], "/other", None, &FixtureStrategies::Failing).await, MetadataMatch::None);
    }

    #[tokio::test]
    async fn an_access_point_without_protected_resource_never_reads_the_strategy_store() {
        let mut scoped = jwt_bearer_method();
        scoped["required_scopes"] = json!([SCOPE]);
        let mut surface = discovery_surface(scoped, None);
        surface.access_point.route = "/smoke".into();
        for path in ["/smoke", "/smoke$beta"] {
            assert_eq!(
                served_from(&[Arc::new(surface.clone())], &[], path, None, &FixtureStrategies::Failing).await,
                MetadataMatch::None,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn a_path_two_declarations_share_is_unavailable() {
        for other in [explicit("/smoke"), sts_resource("/smoke"), declaring_a2a("/smoke")] {
            assert_eq!(
                served(&[declaring_a2a("/smoke"), other], &[], "/smoke", Some(&sts())).await,
                MetadataMatch::Unavailable
            );
        }
        assert_eq!(
            served(&[declaring_a2a("/smoke")], &[declaring_proxy("/smoke")], "/smoke", Some(&sts())).await,
            MetadataMatch::Unavailable
        );
        assert_eq!(
            served(&[declaring_a2a("/smoke"), explicit("/other")], &[], "/smoke", None).await,
            declared_document("https://gateway.example/smoke")
        );
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::protocols::protected_resource::fixtures::{
        ISSUER, discovery_network, discovery_surface, jwt_bearer_method,
    };

    #[test]
    fn mcp_metadata_keeps_its_exact_serialization() {
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        let scoped = McpResourceServerConfig {
            resource: "https://gateway.example/surfaces/alpha".into(),
            scopes: vec!["read".into(), "write".into()],
        };
        assert_eq!(
            serde_json::to_string(
                &scoped
                    .metadata(&profile)
                    .unwrap()
            )
            .unwrap(),
            r#"{"resource":"https://gateway.example/surfaces/alpha","authorization_servers":["https://gateway.example/api/oauth2/mcp"],"bearer_methods_supported":["header"],"scopes_supported":["read","write"]}"#
        );
        let root = McpResourceServerConfig {
            resource: "https://gateway.example/".into(),
            scopes: Vec::new(),
        };
        assert_eq!(
            serde_json::to_string(
                &root
                    .metadata(&profile)
                    .unwrap()
            )
            .unwrap(),
            r#"{"resource":"https://gateway.example/","authorization_servers":["https://gateway.example/api/oauth2/mcp"],"bearer_methods_supported":["header"]}"#
        );
        assert_eq!(
            root.metadata_url()
                .unwrap()
                .as_str(),
            "https://gateway.example/.well-known/oauth-protected-resource"
        );
    }

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
        assert!(!protected_resource::is_gateway_challenge(&unavailable));
    }

    #[test]
    fn resource_server_challenges_are_marked_as_the_gateways_with_unchanged_values() {
        let config = McpResourceServerConfig {
            resource: "https://gateway.example/surfaces/alpha".into(),
            scopes: vec!["read".into(), "write".into()],
        };
        let metadata =
            "Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource/surfaces/alpha\"";
        for (error, status, challenge) in [
            (ResourceTokenError::Missing, StatusCode::UNAUTHORIZED, format!("{metadata}, scope=\"read write\"")),
            (
                ResourceTokenError::Invalid,
                StatusCode::UNAUTHORIZED,
                format!("{metadata}, error=\"invalid_token\", scope=\"read write\""),
            ),
            (
                ResourceTokenError::InsufficientScope,
                StatusCode::FORBIDDEN,
                format!("{metadata}, error=\"insufficient_scope\", scope=\"read write\""),
            ),
        ] {
            let response = config.challenge(error);
            assert_eq!(response.status(), status, "{error:?}");
            assert_eq!(response.headers()[header::WWW_AUTHENTICATE], challenge.as_str());
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(protected_resource::is_gateway_challenge(&response), "{error:?}");
        }
        let unservable = McpResourceServerConfig {
            resource: "http://gateway.example/surfaces/alpha".into(),
            scopes: Vec::new(),
        };
        let refused = unservable.challenge(ResourceTokenError::Missing);
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!protected_resource::is_gateway_challenge(&refused));
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
